use std::time::Duration;

use anyhow::{Context, Result};
use innerwarden_core::incident::Incident;
use serde::Serialize;
use tracing::warn;

// ---------------------------------------------------------------------------
// Payload formats
// ---------------------------------------------------------------------------

/// The JSON body posted to the webhook endpoint (default format).
#[derive(Debug, Serialize)]
struct DefaultPayload<'a> {
    ts: &'a str,
    host: &'a str,
    incident_id: &'a str,
    severity: &'a str,
    title: &'a str,
    summary: &'a str,
    tags: &'a [String],
}

/// Build a PagerDuty Events API v2 payload.
fn pagerduty_payload(incident: &Incident, routing_key: &str) -> serde_json::Value {
    let severity = match format!("{:?}", incident.severity).to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "error",
        "medium" => "warning",
        _ => "info",
    };
    serde_json::json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": incident.incident_id,
        "payload": {
            "summary": format!("[{}] {} - {}", incident.host, incident.title, incident.summary),
            "source": incident.host,
            "severity": severity,
            "component": "innerwarden",
            "group": incident.tags.first().unwrap_or(&"security".to_string()),
            "custom_details": {
                "incident_id": incident.incident_id,
                "tags": incident.tags,
            }
        }
    })
}

/// Build an Opsgenie Alert API payload.
fn opsgenie_payload(incident: &Incident) -> serde_json::Value {
    let priority = match format!("{:?}", incident.severity).to_lowercase().as_str() {
        "critical" => "P1",
        "high" => "P2",
        "medium" => "P3",
        _ => "P4",
    };
    serde_json::json!({
        "message": format!("[{}] {}", incident.host, incident.title),
        "alias": incident.incident_id,
        "description": incident.summary,
        "priority": priority,
        "source": "innerwarden",
        "tags": incident.tags,
        "entity": incident.host,
        "details": {
            "incident_id": incident.incident_id,
            "severity": format!("{:?}", incident.severity).to_lowercase(),
        }
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// POST an incident notification to `url`.
///
/// `format` controls the payload shape:
/// - `"default"` - InnerWarden native format
/// - `"pagerduty"` - PagerDuty Events API v2
/// - `"opsgenie"` - Opsgenie Alert API
///
/// For PagerDuty, `url` should be "https://events.pagerduty.com/v2/enqueue"
/// and the routing key goes in the webhook URL or is extracted from it.
///
/// Failures are logged as warnings and swallowed - fail-open policy.
pub async fn send_incident(
    url: &str,
    timeout_secs: u64,
    incident: &Incident,
    format: &str,
) -> Result<()> {
    let severity_str = format!("{:?}", incident.severity).to_lowercase();
    let ts_str = incident.ts.to_rfc3339();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .context("failed to build HTTP client")?;

    let resp = match format {
        "pagerduty" => {
            // Extract routing key from URL query param or use a default
            let routing_key = url
                .split("routing_key=")
                .nth(1)
                .unwrap_or("")
                .split('&')
                .next()
                .unwrap_or("");
            let base_url = if url.contains('?') {
                url.split('?').next().unwrap_or(url)
            } else {
                url
            };
            let payload = pagerduty_payload(incident, routing_key);
            client.post(base_url).json(&payload).send().await
        }
        "opsgenie" => {
            let payload = opsgenie_payload(incident);
            client.post(url).json(&payload).send().await
        }
        _ => {
            // Default InnerWarden format
            let payload = DefaultPayload {
                ts: &ts_str,
                host: &incident.host,
                incident_id: &incident.incident_id,
                severity: &severity_str,
                title: &incident.title,
                summary: &incident.summary,
                tags: &incident.tags,
            };
            client.post(url).json(&payload).send().await
        }
    }
    .with_context(|| format!("webhook POST to {} failed", redact_url(url)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        warn!(
            url = redact_url(url),
            status = status.as_u16(),
            body = body.chars().take(200).collect::<String>(),
            "webhook returned non-2xx"
        );
    }

    Ok(())
}

/// Redact query string from URL to prevent leaking tokens/keys in logs.
/// "https://hooks.slack.com/T123/B456?token=secret" → "https://hooks.slack.com/T123/B456?[REDACTED]"
fn redact_url(url: &str) -> String {
    match url.find('?') {
        Some(pos) => format!("{}?[REDACTED]", &url[..pos]),
        None => url.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Agent Guard alert webhook
// ---------------------------------------------------------------------------

/// Send an agent-guard snitch alert via webhook.
pub async fn send_agent_guard_alert(
    url: &str,
    timeout_secs: u64,
    alert: &crate::dashboard::AgentGuardAlert,
    _format: &str,
) -> Result<()> {
    if url.is_empty() {
        return Ok(());
    }
    let payload = serde_json::json!({
        "type": "agent_guard_alert",
        "ts": alert.ts.to_rfc3339(),
        "agent_name": alert.agent_name,
        "command": alert.command,
        "risk_score": alert.risk_score,
        "severity": alert.severity,
        "recommendation": alert.recommendation,
        "signals": alert.signals,
        "atr_rule_ids": alert.atr_rule_ids,
        "explanation": alert.explanation,
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .context("failed to build webhook client")?;

    let resp = client.post(url).json(&payload).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        warn!(
            status = status.as_u16(),
            body = body.chars().take(200).collect::<String>(),
            "agent-guard webhook returned non-2xx"
        );
    }
    Ok(())
}

// Severity comparison helper (used in main.rs to filter by min_severity)
// ---------------------------------------------------------------------------

/// Returns a numeric rank for a Severity so we can compare thresholds.
pub fn severity_rank(s: &innerwarden_core::event::Severity) -> u8 {
    use innerwarden_core::event::Severity::*;
    match s {
        Debug => 0,
        Info => 1,
        Low => 2,
        Medium => 3,
        High => 4,
        Critical => 5,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::{entities::EntityRef, event::Severity};

    fn test_incident() -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:2026".to_string(),
            severity: Severity::High,
            title: "SSH brute force from 1.2.3.4".to_string(),
            summary: "8 failed attempts".to_string(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec!["ssh".to_string(), "bruteforce".to_string()],
            entities: vec![EntityRef::ip("1.2.3.4")],
        }
    }

    fn test_guard_alert() -> crate::dashboard::AgentGuardAlert {
        crate::dashboard::AgentGuardAlert {
            ts: chrono::Utc::now(),
            agent_name: "agent-a".to_string(),
            command: "rm -rf /tmp/demo".to_string(),
            risk_score: 92,
            severity: "high".to_string(),
            recommendation: "review".to_string(),
            signals: vec!["destructive".to_string()],
            atr_rule_ids: vec!["ATR-1".to_string()],
            explanation: "test alert".to_string(),
            tenant: None,
        }
    }

    #[test]
    fn pagerduty_format_has_required_fields() {
        let inc = test_incident();
        let payload = pagerduty_payload(&inc, "test-routing-key");
        assert_eq!(payload["routing_key"], "test-routing-key");
        assert_eq!(payload["event_action"], "trigger");
        assert_eq!(payload["dedup_key"], inc.incident_id);
        assert_eq!(payload["payload"]["severity"], "error"); // High → error
        assert!(payload["payload"]["summary"]
            .as_str()
            .unwrap()
            .contains("SSH brute force"));
    }

    #[test]
    fn opsgenie_format_has_required_fields() {
        let inc = test_incident();
        let payload = opsgenie_payload(&inc);
        assert_eq!(payload["priority"], "P2"); // High → P2
        assert_eq!(payload["source"], "innerwarden");
        assert!(payload["message"]
            .as_str()
            .unwrap()
            .contains("SSH brute force"));
        assert_eq!(payload["alias"], inc.incident_id);
    }

    #[test]
    fn pagerduty_severity_mapping() {
        let mut inc = test_incident();
        inc.severity = Severity::Critical;
        let p = pagerduty_payload(&inc, "key");
        assert_eq!(p["payload"]["severity"], "critical");

        inc.severity = Severity::Medium;
        let p = pagerduty_payload(&inc, "key");
        assert_eq!(p["payload"]["severity"], "warning");

        inc.severity = Severity::Low;
        let p = pagerduty_payload(&inc, "key");
        assert_eq!(p["payload"]["severity"], "info");
    }

    #[test]
    fn opsgenie_priority_mapping() {
        let mut inc = test_incident();
        inc.severity = Severity::Critical;
        assert_eq!(opsgenie_payload(&inc)["priority"], "P1");

        inc.severity = Severity::Medium;
        assert_eq!(opsgenie_payload(&inc)["priority"], "P3");
    }

    // severity_rank covers all 6 levels
    #[test]
    fn severity_rank_covers_all_levels() {
        assert_eq!(severity_rank(&Severity::Debug), 0);
        assert_eq!(severity_rank(&Severity::Info), 1);
        assert_eq!(severity_rank(&Severity::Low), 2);
        assert_eq!(severity_rank(&Severity::Medium), 3);
        assert_eq!(severity_rank(&Severity::High), 4);
        assert_eq!(severity_rank(&Severity::Critical), 5);
    }

    // redact_url removes query strings (prevents leaking tokens)
    #[test]
    fn redact_url_strips_query_string() {
        assert_eq!(
            redact_url("https://hooks.slack.com/T123/B456?token=secret"),
            "https://hooks.slack.com/T123/B456?[REDACTED]"
        );
    }

    #[test]
    fn redact_url_preserves_no_query() {
        assert_eq!(
            redact_url("https://hooks.slack.com/T123/B456"),
            "https://hooks.slack.com/T123/B456"
        );
    }

    #[tokio::test]
    async fn send_incident_posts_default_payload_and_treats_2xx_as_success() {
        let server = mockito::Server::new_async().await;
        let mut server = server;
        let m = server
            .mock("POST", "/incident")
            .match_header(
                "content-type",
                mockito::Matcher::Regex("application/json.*".to_string()),
            )
            .with_status(204)
            .create_async()
            .await;

        send_incident(
            &format!("{}/incident", server.url()),
            2,
            &test_incident(),
            "default",
        )
        .await
        .expect("default webhook succeeds");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn send_incident_pagerduty_strips_query_from_post_url() {
        let server = mockito::Server::new_async().await;
        let mut server = server;
        let m = server
            .mock("POST", "/v2/enqueue")
            .with_status(202)
            .create_async()
            .await;
        let url = format!(
            "{}/v2/enqueue?routing_key=route-1&token=secret",
            server.url()
        );

        send_incident(&url, 2, &test_incident(), "pagerduty")
            .await
            .expect("pagerduty webhook succeeds");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn send_incident_non_2xx_is_logged_but_not_returned_as_error() {
        let server = mockito::Server::new_async().await;
        let mut server = server;
        let m = server
            .mock("POST", "/opsgenie")
            .with_status(503)
            .with_body("temporarily unavailable")
            .create_async()
            .await;

        send_incident(
            &format!("{}/opsgenie", server.url()),
            2,
            &test_incident(),
            "opsgenie",
        )
        .await
        .expect("non-2xx responses are fail-open");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn agent_guard_alert_empty_url_is_noop() {
        send_agent_guard_alert("", 2, &test_guard_alert(), "default")
            .await
            .expect("empty URL is intentionally ignored");
    }

    #[tokio::test]
    async fn agent_guard_alert_posts_payload_and_treats_non_2xx_as_success() {
        let server = mockito::Server::new_async().await;
        let mut server = server;
        let m = server
            .mock("POST", "/guard")
            .match_header(
                "content-type",
                mockito::Matcher::Regex("application/json.*".to_string()),
            )
            .with_status(429)
            .with_body("rate limited")
            .create_async()
            .await;

        send_agent_guard_alert(
            &format!("{}/guard", server.url()),
            2,
            &test_guard_alert(),
            "default",
        )
        .await
        .expect("agent guard webhook is fail-open on non-2xx");
        m.assert_async().await;
    }
}
