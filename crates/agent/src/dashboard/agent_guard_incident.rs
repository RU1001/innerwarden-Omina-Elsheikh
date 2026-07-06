//! Convert an Agent Guard alert into a dashboard incident.
//!
//! Agent Guard is the AI-agent guardrail: when a co-located AI agent (OpenClaw,
//! aider, a compromised interpreter, …) attempts a risky command, the guard
//! scores it against the ATR ruleset and emits an [`AgentGuardAlert`]. That
//! alert historically flowed ONLY to two sinks — the
//! `agent-guard-events-YYYY-MM-DD.jsonl` audit log and the Telegram/Slack/webhook
//! "snitch" notification — so an operator watching the dashboard never saw that
//! the guard had acted. This module bridges the gap: the alert also becomes a
//! first-class **incident**, which the SQLite-backed live-feed / Cases surfaces
//! read via `Store::incidents_since_ts`. The guardrail is the product's
//! differentiator, so its events belong in the same case UI as host detections.
//!
//! The conversion is pure (no I/O) so it is exhaustively unit-tested; the boot
//! loop performs the `insert_incident` write.

use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;

use super::state::AgentGuardAlert;

/// Map the alert's string severity (already computed by the ATR engine) onto the
/// canonical [`Severity`] enum. Unknown / empty falls back to `Info` — the
/// neutral "we saw it" level — never a silent escalation.
fn severity_from_str(s: &str) -> Severity {
    match s.trim().to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// The detector column in the `incidents` table is derived by the store as
/// `incident_id.split(':').take(2).join(':')`, so the incident_id MUST be
/// `agent_guard:<kind>:<uniquifier>` for the case to group under an
/// `agent_guard:<kind>` detector. `<kind>` comes from the first signal
/// (`atr:privilege-escalation` → `privilege-escalation`); it must not itself
/// contain a colon (would corrupt the detector parse) or whitespace.
fn kind_from_alert(alert: &AgentGuardAlert) -> String {
    let raw = alert
        .signals
        .first()
        .map(|s| s.rsplit(':').next().unwrap_or(s.as_str()).to_string())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "policy_violation".to_string());
    raw.trim()
        .chars()
        .map(|c| {
            if c == ':' || c.is_whitespace() {
                '-'
            } else {
                c
            }
        })
        .collect()
}

/// Human verb for the recommendation, used in the case title.
fn recommendation_verb(recommendation: &str) -> &str {
    match recommendation.trim().to_lowercase().as_str() {
        "deny" => "blocked",
        "review" => "flagged",
        "allow" => "allowed",
        _ => "flagged",
    }
}

/// Convert an [`AgentGuardAlert`] into an [`Incident`] so a blocked/flagged
/// AI-agent action surfaces as a dashboard case. Idempotency is provided by the
/// caller: the `incident_id` carries the alert timestamp and the store inserts
/// with `INSERT OR IGNORE`, so a duplicate dispatch is a no-op.
pub(crate) fn alert_to_incident(alert: &AgentGuardAlert, host: &str) -> Incident {
    let severity = severity_from_str(&alert.severity);
    let kind = kind_from_alert(alert);
    let incident_id = format!("agent_guard:{kind}:{}", alert.ts.to_rfc3339());

    let agent_name = if alert.agent_name.trim().is_empty() {
        "unknown"
    } else {
        alert.agent_name.as_str()
    };
    let verb = recommendation_verb(&alert.recommendation);
    let cmd_short: String = alert.command.chars().take(120).collect();
    let title = format!("AI agent {verb}: {cmd_short}");

    let atr = alert.atr_rule_ids.join(", ");
    let summary = format!(
        "Agent Guard {rec} an AI-agent action (risk {risk}). Agent: {agent}. \
         ATR: {atr}. {explanation}",
        rec = alert.recommendation,
        risk = alert.risk_score,
        agent = agent_name,
        atr = if atr.is_empty() { "-" } else { atr.as_str() },
        explanation = alert.explanation,
    );

    // Tags: always mark the source; carry signals + ATR ids so the case is
    // filterable; a denied action is already contained (the guard refused it),
    // so tag it as such — the operator does not need to act.
    let mut tags = Vec::with_capacity(3 + alert.signals.len() + alert.atr_rule_ids.len());
    tags.push("agent_guard".to_string());
    // Spec 084: carry the tenant as a `tenant:<id>` tag (the same shape the
    // fleet dashboard / SQLite->Loki bridge read) so a blocked/flagged AI-agent
    // action is attributed to the right agent/employee/pod in the per-tenant
    // command review, not just in the /metrics counter. Omitted when absent.
    if let Some(t) = alert
        .tenant
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        tags.push(format!("tenant:{t}"));
    }
    for s in &alert.signals {
        tags.push(s.clone());
    }
    for r in &alert.atr_rule_ids {
        tags.push(r.clone());
    }
    if alert.recommendation.trim().eq_ignore_ascii_case("deny") {
        tags.push("contained".to_string());
    }

    let evidence = serde_json::json!({
        "source": "agent_guard",
        "agent_name": agent_name,
        "tenant": alert.tenant,
        "command": alert.command,
        "risk_score": alert.risk_score,
        "recommendation": alert.recommendation,
        "signals": alert.signals,
        "atr_rule_ids": alert.atr_rule_ids,
        "explanation": alert.explanation,
    });

    Incident {
        ts: alert.ts,
        host: host.to_string(),
        incident_id,
        severity,
        title,
        summary,
        evidence,
        recommended_checks: vec![
            "Review the AI agent's session and its intent for this command".to_string(),
            "Confirm the agent is not compromised or prompt-injected".to_string(),
        ],
        tags,
        entities: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny_alert() -> AgentGuardAlert {
        AgentGuardAlert {
            ts: chrono::Utc::now(),
            agent_name: "unknown".to_string(),
            command: "sudo systemctl start innerwarden-agent".to_string(),
            risk_score: 40,
            severity: "medium".to_string(),
            recommendation: "deny".to_string(),
            signals: vec!["atr:privilege-escalation".to_string()],
            atr_rule_ids: vec!["ATR-2026-064".to_string()],
            explanation: "[ATR-2026-064] ATR-2026-064 match".to_string(),
            tenant: None,
        }
    }

    #[test]
    fn alert_serializes_tenant_only_when_present() {
        // absent tenant → field omitted (single-tenant logs unchanged).
        let json = serde_json::to_string(&deny_alert()).unwrap();
        assert!(!json.contains("tenant"), "tenant must be omitted when None");
        // present tenant → in the JSONL for per-tenant incident investigation.
        let mut a = deny_alert();
        a.tenant = Some("globex-inc".to_string());
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("\"tenant\":\"globex-inc\""));
    }

    #[test]
    fn tenant_becomes_a_tag_and_evidence_field() {
        // no tenant → no tenant tag, evidence tenant is null.
        let inc = alert_to_incident(&deny_alert(), "h");
        assert!(!inc.tags.iter().any(|t| t.starts_with("tenant:")));
        assert!(inc.evidence["tenant"].is_null());
        // tenant present → `tenant:<id>` tag (spec-084 shape) + evidence field.
        let mut a = deny_alert();
        a.tenant = Some("globex-inc".to_string());
        let inc = alert_to_incident(&a, "h");
        assert!(inc.tags.contains(&"tenant:globex-inc".to_string()));
        assert_eq!(inc.evidence["tenant"], "globex-inc");
        // still tagged agent_guard + contained (deny).
        assert!(inc.tags.contains(&"agent_guard".to_string()));
        assert!(inc.tags.contains(&"contained".to_string()));
    }

    #[test]
    fn deny_alert_becomes_contained_medium_case() {
        let alert = deny_alert();
        let inc = alert_to_incident(&alert, "prod-box");

        assert_eq!(inc.severity, Severity::Medium);
        assert_eq!(inc.host, "prod-box");
        // detector column is incident_id.split(':').take(2).join(':')
        let detector = inc
            .incident_id
            .split(':')
            .take(2)
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(detector, "agent_guard:privilege-escalation");
        assert!(inc
            .title
            .starts_with("AI agent blocked: sudo systemctl start"));
        assert!(inc.tags.contains(&"agent_guard".to_string()));
        assert!(inc.tags.contains(&"contained".to_string()));
        assert!(inc.tags.contains(&"ATR-2026-064".to_string()));
        assert_eq!(
            inc.evidence["command"],
            "sudo systemctl start innerwarden-agent"
        );
        assert_eq!(inc.evidence["source"], "agent_guard");
        assert_eq!(inc.evidence["risk_score"], 40);
        assert_eq!(inc.ts, alert.ts);
    }

    #[test]
    fn critical_severity_maps_and_uses_alert_ts_for_idempotency() {
        let mut alert = deny_alert();
        alert.severity = "CRITICAL".to_string();
        let a = alert_to_incident(&alert, "h");
        let b = alert_to_incident(&alert, "h");
        assert_eq!(a.severity, Severity::Critical);
        // Same ts → same incident_id → store INSERT OR IGNORE dedups.
        assert_eq!(a.incident_id, b.incident_id);
    }

    #[test]
    fn review_recommendation_is_flagged_not_contained() {
        let mut alert = deny_alert();
        alert.recommendation = "review".to_string();
        let inc = alert_to_incident(&alert, "h");
        assert!(inc.title.starts_with("AI agent flagged:"));
        assert!(!inc.tags.contains(&"contained".to_string()));
    }

    #[test]
    fn empty_signals_fall_back_to_policy_violation_kind() {
        let mut alert = deny_alert();
        alert.signals.clear();
        let inc = alert_to_incident(&alert, "h");
        let detector = inc
            .incident_id
            .split(':')
            .take(2)
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(detector, "agent_guard:policy_violation");
    }

    #[test]
    fn empty_agent_name_renders_unknown_and_unknown_severity_is_info() {
        let mut alert = deny_alert();
        alert.agent_name = "  ".to_string();
        alert.severity = "weird".to_string();
        let inc = alert_to_incident(&alert, "h");
        assert_eq!(inc.severity, Severity::Info);
        assert_eq!(inc.evidence["agent_name"], "unknown");
        assert!(inc.summary.contains("Agent: unknown"));
    }

    #[test]
    fn kind_with_colon_or_space_is_sanitised() {
        let mut alert = deny_alert();
        alert.signals = vec!["weird sig:name".to_string()];
        let inc = alert_to_incident(&alert, "h");
        // rsplit(':') → "name" (no colon/space), detector stays clean
        let detector = inc
            .incident_id
            .split(':')
            .take(2)
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(detector, "agent_guard:name");
    }
}
