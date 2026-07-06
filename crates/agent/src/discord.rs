use anyhow::{Context, Result};
use innerwarden_core::{entities::EntityType, incident::Incident};
use serde_json::json;
use tracing::warn;

// ---------------------------------------------------------------------------
// Discord Incoming Webhook client (spec 078 Phase 3)
// ---------------------------------------------------------------------------

/// Sends notifications to a Discord channel via an Incoming Webhook URL.
///
/// Uses Discord embeds for structured, colour-coded messages. Failure is logged
/// as a warning and swallowed - a dead webhook must never stop the agent
/// (fail-open policy), matching [`crate::slack::SlackClient`].
///
/// `Clone` is cheap: the only non-trivial field is a `reqwest::Client`, whose
/// clone shares the connection pool. The chat-channel registry clones it into a
/// `Box<dyn ChatChannel>`.
#[derive(Clone)]
pub struct DiscordClient {
    /// Discord Incoming Webhook URL.
    webhook_url: String,
    /// Reused HTTP client (connection pool).
    client: reqwest::Client,
}

impl DiscordClient {
    pub fn new(webhook_url: impl Into<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("failed to build Discord HTTP client")?;
        Ok(Self {
            webhook_url: webhook_url.into(),
            client,
        })
    }

    async fn post(&self, payload: serde_json::Value, what: &str) -> Result<()> {
        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("Discord {what} webhook POST failed"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                status = status.as_u16(),
                what,
                body = body.chars().take(200).collect::<String>(),
                "Discord webhook returned non-2xx"
            );
        }
        Ok(())
    }

    /// Send an incident alert to Discord.
    pub async fn send_incident_alert(
        &self,
        incident: &Incident,
        dashboard_url: Option<&str>,
    ) -> Result<()> {
        self.post(incident_alert_payload(incident, dashboard_url), "alert")
            .await
    }

    /// Send a post-execution action report ("what the agent did") to Discord.
    pub async fn send_action_report(
        &self,
        report: &crate::notification_channels::ActionReport,
        dashboard_url: Option<&str>,
    ) -> Result<()> {
        self.post(
            action_report_payload(report, dashboard_url),
            "action-report",
        )
        .await
    }

    /// Send a pre-rendered summary line (burst/group rollup). The input is
    /// Telegram HTML; Discord has no HTML rendering so the tags are stripped.
    pub async fn send_summary(&self, html: &str) -> Result<()> {
        self.post(json!({ "content": strip_html_tags(html) }), "summary")
            .await
    }
}

/// Discord embed colour (decimal RGB) for a severity.
fn severity_color(severity: &innerwarden_core::event::Severity) -> u32 {
    use innerwarden_core::event::Severity::*;
    match severity {
        Critical => 0xE7_4C_3C,
        High => 0xE6_7E_22,
        Medium => 0xF1_C4_0F,
        Low => 0x34_98_DB,
        _ => 0x95_A5_A6,
    }
}

fn entity_line(incident: &Incident) -> String {
    let ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == EntityType::Ip)
        .map(|e| format!("IP: `{}`", e.value));
    let user = incident
        .entities
        .iter()
        .find(|e| e.r#type == EntityType::User)
        .map(|e| format!("User: `{}`", e.value));
    [ip, user]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("  •  ")
}

fn incident_alert_payload(incident: &Incident, dashboard_url: Option<&str>) -> serde_json::Value {
    let severity_str = format!("{:?}", incident.severity);
    let entities = entity_line(incident);
    let footer = format!(
        "🖥 {host}{ent}  •  🕐 {time}",
        host = incident.host,
        ent = if entities.is_empty() {
            String::new()
        } else {
            format!("  •  {entities}")
        },
        time = incident.ts.format("%H:%M UTC"),
    );

    let mut embed = json!({
        "title": format!("{} — {}", severity_str.to_uppercase(), incident.title),
        "description": incident.summary,
        "color": severity_color(&incident.severity),
        "footer": { "text": footer },
    });

    // Dashboard deep-link (prefer the attacker IP entity).
    if let Some(url) = dashboard_url {
        let link = incident
            .entities
            .iter()
            .find(|e| e.r#type == EntityType::Ip)
            .map(|e| format!("{}/?entity={}", url, e.value))
            .unwrap_or_else(|| url.to_string());
        embed["url"] = json!(link);
    }

    json!({ "embeds": [embed] })
}

fn action_report_payload(
    report: &crate::notification_channels::ActionReport,
    dashboard_url: Option<&str>,
) -> serde_json::Value {
    let pct = (report.confidence * 100.0) as u32;
    let mode = if report.dry_run {
        "🟡 DRY-RUN (simulated)"
    } else {
        "🟢 Executed"
    };
    let mut footer_bits = vec![format!("🖥 {}", report.host), format!("Confidence: {pct}%")];
    if report.cloudflare_pushed {
        footer_bits.push("Cloudflare edge updated".to_string());
    }
    if let Some(rep) = &report.ip_reputation {
        let country = report
            .ip_geo
            .as_ref()
            .map(|g| g.country_code.clone())
            .filter(|c| !c.is_empty())
            .map(|c| format!(" ({c})"))
            .unwrap_or_default();
        footer_bits.push(format!("AbuseIPDB {}%{}", rep.confidence_score, country));
    }

    let mut embed = json!({
        "title": "🛡️ Threat neutralized",
        "description": format!("{} `{}`\n_{}_", report.action_label, report.target, report.incident_title),
        "color": 0x2E_CC_71u32,
        "footer": { "text": format!("{mode}  •  {}", footer_bits.join("  •  ")) },
    });
    if let Some(url) = dashboard_url {
        embed["url"] = json!(url);
    }
    json!({ "embeds": [embed] })
}

/// Strip HTML tags from a Telegram-formatted string for plain-text channels.
fn strip_html_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;

    fn incident() -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "prod-1".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.5:w".to_string(),
            severity: Severity::Critical,
            title: "SSH brute force".to_string(),
            summary: "many failed logins".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.5"), EntityRef::user("root")],
        }
    }

    #[test]
    fn alert_payload_has_embed_colour_title_and_dashboard_url() {
        let p = incident_alert_payload(&incident(), Some("https://dash"));
        let e = &p["embeds"][0];
        assert_eq!(e["color"], 0xE7_4C_3Cu32); // Critical red
        assert!(e["title"].as_str().unwrap().contains("CRITICAL"));
        assert!(e["title"].as_str().unwrap().contains("SSH brute force"));
        assert_eq!(e["url"], "https://dash/?entity=203.0.113.5");
        assert!(e["footer"]["text"]
            .as_str()
            .unwrap()
            .contains("203.0.113.5"));
    }

    #[test]
    fn alert_payload_without_dashboard_has_no_url() {
        let p = incident_alert_payload(&incident(), None);
        assert!(p["embeds"][0]["url"].is_null());
    }

    #[test]
    fn action_report_payload_renders_disposition() {
        let report = crate::notification_channels::ActionReport {
            action_label: "Blocked".to_string(),
            target: "203.0.113.9".to_string(),
            incident_title: "SSH brute force".to_string(),
            confidence: 0.97,
            host: "prod-1".to_string(),
            dry_run: false,
            ip_reputation: None,
            ip_geo: None,
            cloudflare_pushed: true,
        };
        let p = action_report_payload(&report, None);
        let e = &p["embeds"][0];
        assert_eq!(e["color"], 0x2E_CC_71u32);
        assert!(e["title"].as_str().unwrap().contains("Threat neutralized"));
        assert!(e["description"].as_str().unwrap().contains("Blocked"));
        let f = e["footer"]["text"].as_str().unwrap();
        assert!(f.contains("Executed"));
        assert!(f.contains("97%"));
        assert!(f.contains("Cloudflare"));
    }

    #[test]
    fn strip_html_tags_works() {
        assert_eq!(strip_html_tags("<b>3</b> from <code>x</code>"), "3 from x");
    }
}
