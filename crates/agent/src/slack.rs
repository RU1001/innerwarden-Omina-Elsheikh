use anyhow::{Context, Result};
use innerwarden_core::{entities::EntityType, incident::Incident};
use serde_json::json;
use tracing::warn;

// ---------------------------------------------------------------------------
// Slack Incoming Webhook client
// ---------------------------------------------------------------------------

/// Sends incident alerts to a Slack channel via an Incoming Webhook URL.
///
/// Uses Block Kit for a structured, readable message.
/// Failure is logged as a warning and swallowed - a dead Slack webhook must
/// never stop the agent from processing events (fail-open policy).
///
/// `Clone` is cheap: the only non-trivial field is a `reqwest::Client`, whose
/// clone shares the underlying connection pool. The chat-channel registry
/// (spec 078) clones it into a `Box<dyn ChatChannel>`.
#[derive(Clone)]
pub struct SlackClient {
    /// Slack Incoming Webhook URL.
    webhook_url: String,
    /// Reused HTTP client (connection pool).
    client: reqwest::Client,
}

impl SlackClient {
    pub fn new(webhook_url: impl Into<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("failed to build Slack HTTP client")?;
        Ok(Self {
            webhook_url: webhook_url.into(),
            client,
        })
    }

    /// Send an incident alert to Slack.
    ///
    /// The message uses Block Kit: a severity-coloured header section, a brief
    /// summary, entity details, and an optional deep-link to the dashboard.
    pub async fn send_incident_alert(
        &self,
        incident: &Incident,
        dashboard_url: Option<&str>,
    ) -> Result<()> {
        let payload = incident_alert_payload(incident, dashboard_url);

        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("Slack webhook POST to {} failed", self.webhook_url))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                status = status.as_u16(),
                body = body.chars().take(200).collect::<String>(),
                "Slack webhook returned non-2xx"
            );
        }

        Ok(())
    }

    /// Send an agent-guard snitch alert to Slack.
    pub async fn send_agent_guard_alert(
        &self,
        alert: &crate::dashboard::AgentGuardAlert,
    ) -> Result<()> {
        let payload = agent_guard_alert_payload(alert);

        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .context("Slack agent-guard webhook POST failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                status = status.as_u16(),
                body = body.chars().take(200).collect::<String>(),
                "Slack agent-guard webhook returned non-2xx"
            );
        }
        Ok(())
    }

    /// Send a post-execution action report ("what the agent did") to Slack.
    ///
    /// Mirrors the Telegram action report so an operator watching either
    /// channel sees the same disposition (spec 078 Phase 2).
    pub async fn send_action_report(
        &self,
        report: &crate::notification_channels::ActionReport,
        dashboard_url: Option<&str>,
    ) -> Result<()> {
        let payload = action_report_payload(report, dashboard_url);
        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .context("Slack action-report webhook POST failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                status = status.as_u16(),
                body = body.chars().take(200).collect::<String>(),
                "Slack action-report webhook returned non-2xx"
            );
        }
        Ok(())
    }

    /// Send a pre-rendered summary line (burst/group rollup) to Slack.
    ///
    /// The input is Telegram HTML; Slack has no HTML rendering, so the tags are
    /// stripped and the text posted plain.
    pub async fn send_summary(&self, html: &str) -> Result<()> {
        let payload = json!({ "text": strip_html_tags(html) });
        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await
            .context("Slack summary webhook POST failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                status = status.as_u16(),
                body = body.chars().take(200).collect::<String>(),
                "Slack summary webhook returned non-2xx"
            );
        }
        Ok(())
    }
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

    let mut context_bits = vec![
        format!("🖥 `{}`", report.host),
        format!("Confidence: {pct}%"),
    ];
    if report.cloudflare_pushed {
        context_bits.push("Cloudflare edge updated".to_string());
    }
    if let Some(rep) = &report.ip_reputation {
        let country = report
            .ip_geo
            .as_ref()
            .map(|g| g.country_code.clone())
            .filter(|c| !c.is_empty())
            .map(|c| format!(" ({c})"))
            .unwrap_or_default();
        context_bits.push(format!("AbuseIPDB {}%{}", rep.confidence_score, country));
    }

    let mut blocks = vec![
        json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!(
                    "🛡️ *Threat neutralized*\n{label} `{target}`\n_{title}_",
                    label = report.action_label,
                    target = report.target,
                    title = report.incident_title,
                )
            }
        }),
        json!({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": format!("{mode}  |  {}", context_bits.join("  |  "))
            }]
        }),
    ];

    if let Some(url) = dashboard_url {
        blocks.push(json!({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": { "type": "plain_text", "text": "Investigate →", "emoji": true },
                "url": url
            }]
        }));
    }

    json!({
        "attachments": [{
            "color": "#22c55e",
            "blocks": blocks,
            "fallback": format!(
                "[InnerWarden] {} {}: {}",
                report.action_label, report.target, report.incident_title
            ),
        }]
    })
}

fn incident_alert_payload(incident: &Incident, dashboard_url: Option<&str>) -> serde_json::Value {
    let severity_str = format!("{:?}", incident.severity);
    let emoji = severity_emoji(&severity_str);
    let color = severity_color(&severity_str);

    let entity_line = {
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
            .join("  |  ")
    };

    let actions_block = dashboard_url.map(|url| {
        let link_url = incident
            .entities
            .iter()
            .find(|e| e.r#type == EntityType::Ip)
            .map(|e| format!("{}/?entity={}", url, e.value))
            .unwrap_or_else(|| url.to_string());

        json!({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": { "type": "plain_text", "text": "Investigate →", "emoji": true },
                "url": link_url,
                "style": "danger"
            }]
        })
    });

    let mut blocks = vec![
        json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!("{emoji} *{severity_str} - {title}*\n{summary}",
                    emoji = emoji,
                    severity_str = severity_str.to_uppercase(),
                    title = &incident.title,
                    summary = &incident.summary,
                )
            }
        }),
        json!({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": format!("🖥 `{host}`  {entity_part}  🕐 {time}",
                    host = &incident.host,
                    entity_part = if entity_line.is_empty() { String::new() } else { format!(" |  {entity_line}") },
                    time = incident.ts.format("%H:%M UTC"),
                )
            }]
        }),
    ];

    if let Some(block) = actions_block {
        blocks.push(block);
    }

    json!({
        "attachments": [{
            "color": color,
            "blocks": blocks,
            "fallback": format!("[InnerWarden] {}: {}", severity_str, incident.title),
        }]
    })
}

fn agent_guard_alert_payload(alert: &crate::dashboard::AgentGuardAlert) -> serde_json::Value {
    let color = match alert.severity.as_str() {
        "high" => "#f43f5e",
        "medium" => "#f97316",
        _ => "#eab308",
    };
    let sev_emoji = match alert.severity.as_str() {
        "high" => "🔴",
        "medium" => "🟠",
        _ => "🟡",
    };
    // `&alert.command[..120]` panicked on a multi-byte UTF-8 boundary;
    // command_preview backs up to a char boundary and adds an ellipsis only
    // when it actually truncates.
    let cmd_preview = crate::text_util::command_preview(&alert.command, 120);
    let signals_str = alert.signals.join(", ");
    let atr_line = if alert.atr_rule_ids.is_empty() {
        String::new()
    } else {
        format!("  |  ATR: {}", alert.atr_rule_ids.join(", "))
    };

    json!({
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": format!(
                            "🤖 *Agent Guard Alert*\n{sev_emoji} {} — {}\n\n*Agent:* {}\n*Command:* `{}`\n*Risk score:* {}\n*Signals:* {}{}",
                            alert.severity.to_uppercase(),
                            alert.recommendation.to_uppercase(),
                            alert.agent_name,
                            cmd_preview,
                            alert.risk_score,
                            signals_str,
                            atr_line,
                        )
                    }
                }
            ],
            "fallback": format!("[InnerWarden] Agent Guard: {} attempted {}", alert.agent_name, cmd_preview)
        }]
    })
}

fn severity_emoji(severity: &str) -> &'static str {
    match severity {
        "Critical" => "🚨",
        "High" => "🔴",
        "Medium" => "🟠",
        "Low" => "🟡",
        _ => "ℹ️",
    }
}

fn severity_color(severity: &str) -> &'static str {
    match severity {
        "Critical" => "#9b1c1c", // dark red
        "High" => "#f43f5e",     // red
        "Medium" => "#f97316",   // orange
        "Low" => "#eab308",      // yellow
        _ => "#6b7280",          // gray
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_emoji_maps_correctly() {
        // Mapping path: each canonical severity must map to the expected
        // emoji so operator triage can scan Slack alerts quickly.
        assert_eq!(severity_emoji("Critical"), "🚨");
        assert_eq!(severity_emoji("High"), "🔴");
        assert_eq!(severity_emoji("Medium"), "🟠");
        assert_eq!(severity_emoji("Low"), "🟡");
        assert_eq!(severity_emoji("Info"), "ℹ️");
    }

    #[test]
    fn severity_color_maps_correctly() {
        // Color path: attachment color should track severity consistently with
        // dashboard semantics.
        assert_eq!(severity_color("Critical"), "#9b1c1c");
        assert_eq!(severity_color("High"), "#f43f5e");
        assert_eq!(severity_color("Medium"), "#f97316");
        assert_eq!(severity_color("Low"), "#eab308");
        assert_eq!(severity_color("Debug"), "#6b7280");
    }

    #[test]
    fn slack_client_new_succeeds_with_valid_url() {
        // Construction path: a syntactically valid webhook URL should create
        // a Slack client without touching the network.
        let result = SlackClient::new("https://hooks.slack.com/services/T/B/xyz");
        assert!(result.is_ok());
    }

    #[test]
    fn severity_emoji_unknown_returns_info() {
        // Fallback path: unknown severities should degrade to informational
        // markers instead of panicking.
        assert_eq!(severity_emoji("Unknown"), "ℹ️");
    }

    #[test]
    fn severity_color_unknown_returns_gray() {
        // Fallback path: unknown severities should use neutral gray.
        assert_eq!(severity_color("Unknown"), "#6b7280");
    }

    #[test]
    fn severity_helpers_are_case_sensitive_by_design() {
        // Validation path: lowercase severities currently fall back to
        // neutral styling, documenting current behavior explicitly.
        assert_eq!(severity_emoji("critical"), "ℹ️");
        assert_eq!(severity_color("critical"), "#6b7280");
    }

    fn test_incident() -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "edge-1".to_string(),
            incident_id: "inc-1".to_string(),
            severity: innerwarden_core::event::Severity::Critical,
            title: "Credential stuffing".to_string(),
            summary: "Burst from one actor".to_string(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![
                innerwarden_core::entities::EntityRef::ip("1.2.3.4"),
                innerwarden_core::entities::EntityRef::user("root"),
            ],
        }
    }

    fn test_guard_alert(command: String, severity: &str) -> crate::dashboard::AgentGuardAlert {
        crate::dashboard::AgentGuardAlert {
            ts: chrono::Utc::now(),
            agent_name: "codex".to_string(),
            command,
            risk_score: 91,
            severity: severity.to_string(),
            recommendation: "block".to_string(),
            signals: vec!["shell".to_string(), "credential".to_string()],
            atr_rule_ids: vec!["ATR-7".to_string()],
            explanation: "dangerous".to_string(),
            tenant: None,
        }
    }

    #[test]
    fn incident_payload_includes_entity_context_and_dashboard_deeplink() {
        let payload = incident_alert_payload(&test_incident(), Some("https://dash.local"));
        assert_eq!(payload["attachments"][0]["color"], "#9b1c1c");
        let blocks = payload["attachments"][0]["blocks"].as_array().unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(
            blocks[2]["elements"][0]["url"],
            "https://dash.local/?entity=1.2.3.4"
        );
        let context = blocks[1]["elements"][0]["text"].as_str().unwrap();
        assert!(context.contains("IP: `1.2.3.4`"));
        assert!(context.contains("User: `root`"));
    }

    #[test]
    fn incident_payload_omits_actions_without_dashboard_url() {
        let mut incident = test_incident();
        incident.entities.clear();
        let payload = incident_alert_payload(&incident, None);
        let blocks = payload["attachments"][0]["blocks"].as_array().unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(blocks[1]["elements"][0]["text"]
            .as_str()
            .unwrap()
            .contains("edge-1"));
    }

    #[test]
    fn agent_guard_payload_truncates_long_commands_and_renders_atr_context() {
        let payload = agent_guard_alert_payload(&test_guard_alert("x".repeat(140), "high"));
        assert_eq!(payload["attachments"][0]["color"], "#f43f5e");
        let text = payload["attachments"][0]["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains("ATR: ATR-7"));
        assert!(text.contains('…'));
        // Risk is an unbounded weighted sum, not a percentage: render it as a
        // bare score, never the misleading "/100" (prod showed "270/100").
        assert!(text.contains("Risk score:"));
        assert!(text.contains("91"));
        assert!(!text.contains("/100"));
    }

    #[test]
    fn agent_guard_payload_truncates_multibyte_command_without_panic() {
        // 140 multibyte chars: byte index 120 is NOT a char boundary, so a
        // naive `&cmd[..120]` would panic. safe_truncate must back up cleanly.
        let payload = agent_guard_alert_payload(&test_guard_alert("✓".repeat(140), "high"));
        let text = payload["attachments"][0]["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains('…'));
    }

    #[test]
    fn agent_guard_payload_uses_medium_palette_and_handles_empty_atr_ids() {
        let mut alert = test_guard_alert("echo ok".to_string(), "medium");
        alert.atr_rule_ids.clear();
        let payload = agent_guard_alert_payload(&alert);
        assert_eq!(payload["attachments"][0]["color"], "#f97316");
        let text = payload["attachments"][0]["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains("MEDIUM"));
        assert!(!text.contains("ATR:"));
    }

    #[test]
    fn strip_html_tags_removes_markup_keeps_text() {
        assert_eq!(
            strip_html_tags("<b>3 incidents</b> from <code>1.2.3.4</code>"),
            "3 incidents from 1.2.3.4"
        );
        assert_eq!(strip_html_tags("no tags"), "no tags");
        assert_eq!(strip_html_tags("<a href=\"x\">link</a>"), "link");
    }

    fn test_action_report(dry_run: bool) -> crate::notification_channels::ActionReport {
        crate::notification_channels::ActionReport {
            action_label: "Blocked".to_string(),
            target: "203.0.113.9".to_string(),
            incident_title: "SSH brute force".to_string(),
            confidence: 0.97,
            host: "prod-1".to_string(),
            dry_run,
            ip_reputation: None,
            ip_geo: None,
            cloudflare_pushed: true,
        }
    }

    #[test]
    fn action_report_payload_renders_disposition_and_dashboard_button() {
        let payload = action_report_payload(&test_action_report(false), Some("https://dash"));
        assert_eq!(payload["attachments"][0]["color"], "#22c55e");
        let header = payload["attachments"][0]["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap();
        assert!(header.contains("Threat neutralized"));
        assert!(header.contains("Blocked"));
        assert!(header.contains("203.0.113.9"));
        let ctx = payload["attachments"][0]["blocks"][1]["elements"][0]["text"]
            .as_str()
            .unwrap();
        assert!(ctx.contains("Executed"), "non-dry-run shows Executed");
        assert!(ctx.contains("97%"));
        assert!(ctx.contains("Cloudflare"));
        // dashboard_url present -> an actions block with the Investigate button.
        assert_eq!(payload["attachments"][0]["blocks"][2]["type"], "actions");
    }

    #[test]
    fn action_report_payload_dry_run_and_no_dashboard() {
        let payload = action_report_payload(&test_action_report(true), None);
        let ctx = payload["attachments"][0]["blocks"][1]["elements"][0]["text"]
            .as_str()
            .unwrap();
        assert!(ctx.contains("DRY-RUN"));
        // No dashboard_url -> no third (actions) block.
        assert!(payload["attachments"][0]["blocks"][2].is_null());
    }
}
