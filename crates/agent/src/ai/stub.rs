//! Deterministic AI provider used by the spec-024 scenario-qa harness.
//!
//! The real providers (OpenAI / Anthropic / Ollama) need an API key and
//! return non-deterministic output that varies across model versions — both
//! are deal-breakers for a scenario harness that has to assert "this input
//! produces N incidents, M telegram messages, K blocks" on every PR.
//!
//! `StubAiProvider` returns a fixed decision for each kind of incident it
//! recognises. The mapping is deliberately narrow — the goal is to make the
//! scenarios that exist today deterministic, not to replicate the richness
//! of a real model. Contract tests on the real providers still run on every
//! PR; nothing here affects production.
//!
//! Activation: `[ai].provider = "stub"` in the agent config. The scenario
//! runner sets this for every scenario under `testdata/scenarios/`.
//!
//! Invariants:
//! - `decide` never mutates external state and is pure in the incident.
//! - Confidence is always `>= 0.9` when an action is chosen so it is never
//!   suppressed by the configured confidence threshold.
//! - Honeypot hits from known-bad IPs (AbuseIPDB score > 50) escalate to
//!   `BlockIp`; unknown IPs stay on `Monitor` so scenario #4 reads "0 blocks".

use anyhow::Result;
use async_trait::async_trait;
use innerwarden_core::entities::EntityType;

use super::{AiAction, AiDecision, AiProvider, DecisionContext};

pub struct StubAiProvider;

impl StubAiProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AiProvider for StubAiProvider {
    fn name(&self) -> &'static str {
        "stub"
    }

    async fn chat(&self, _system_prompt: &str, _user_message: &str) -> Result<String> {
        Ok("[stub] no model".to_string())
    }

    async fn decide(&self, ctx: &DecisionContext<'_>) -> Result<AiDecision> {
        Ok(decide_for_incident(ctx))
    }
}

/// Pure decision logic — factored out so unit tests can call it without an
/// async runtime.
pub(crate) fn decide_for_incident(ctx: &DecisionContext<'_>) -> AiDecision {
    let detector = crate::agent_context::incident_detector(&ctx.incident.incident_id);
    let first_ip = ctx
        .incident
        .entities
        .iter()
        .find(|e| matches!(e.r#type, EntityType::Ip))
        .map(|e| e.value.clone());

    let action = match (detector, first_ip.as_deref()) {
        // Scenarios 1/2 — ssh brute force (single + coordinated). Always block.
        ("ssh_bruteforce", Some(ip)) => AiAction::BlockIp {
            ip: ip.to_string(),
            skill_id: "block-ip-ufw".to_string(),
        },
        // Scenario 5 — port scan. Always block.
        ("port_scan", Some(ip)) => AiAction::BlockIp {
            ip: ip.to_string(),
            skill_id: "block-ip-ufw".to_string(),
        },
        // Scenario 3/4 — honeypot hit. Known-bad IPs escalate; unknown IPs
        // stay on Monitor so the scenario asserts "0 blocks".
        ("honeypot", Some(ip)) => {
            let known_bad = ctx
                .ip_reputation
                .as_ref()
                .map(|r| r.confidence_score > 50)
                .unwrap_or(false);
            if known_bad {
                AiAction::BlockIp {
                    ip: ip.to_string(),
                    skill_id: "block-ip-ufw".to_string(),
                }
            } else {
                AiAction::Monitor { ip: ip.to_string() }
            }
        }
        // Scenario 6 — DDoS / shield. Shield already mitigated; the AI's job
        // is to acknowledge, not to re-block.
        ("shield", _) => AiAction::Ignore {
            reason: "already mitigated by shield".to_string(),
        },
        // Any other detector gets acknowledged without action — the scenario
        // harness only asserts envelopes for the scenarios listed above.
        _ => AiAction::Ignore {
            reason: format!("stub: no rule for detector {detector}"),
        },
    };

    let estimated_threat = match action {
        AiAction::BlockIp { .. } => "high",
        AiAction::Monitor { .. } => "medium",
        _ => "low",
    }
    .to_string();

    AiDecision {
        action,
        confidence: 0.9,
        auto_execute: true,
        reason: "stub provider (spec 024 scenario harness)".to_string(),
        alternatives: vec![],
        estimated_threat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};

    fn ctx_for(incident_id: &str, ip: &str) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "h".into(),
            incident_id: incident_id.into(),
            severity: Severity::High,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    fn decide(incident: &Incident) -> AiDecision {
        let ctx = DecisionContext {
            incident,
            recent_events: vec![],
            related_incidents: vec![],
            already_blocked: vec![],
            available_skills: vec![],
            ip_reputation: None,
            ip_geo: None,
            ip_dshield: None,
            ip_dshield_attacker: false,
            host_posture: None,
            prior_decisions: None,
            graph_context: None,
            graph_subgraph: None,
            playbook_outcome: None,
        };
        decide_for_incident(&ctx)
    }

    #[test]
    fn ssh_bruteforce_is_blocked() {
        let inc = ctx_for("ssh_bruteforce:1.2.3.4:abc", "1.2.3.4");
        let d = decide(&inc);
        assert!(matches!(d.action, AiAction::BlockIp { .. }));
        assert!(d.auto_execute);
        assert!(d.confidence >= 0.9);
    }

    #[test]
    fn port_scan_is_blocked() {
        let inc = ctx_for("port_scan:5.6.7.8:abc", "5.6.7.8");
        let d = decide(&inc);
        assert!(matches!(d.action, AiAction::BlockIp { .. }));
    }

    #[test]
    fn honeypot_unknown_ip_monitors_not_blocks() {
        let inc = ctx_for("honeypot:9.9.9.9:abc", "9.9.9.9");
        let d = decide(&inc);
        assert!(
            matches!(d.action, AiAction::Monitor { .. }),
            "unknown IPs must not be auto-blocked; honeypot lets them in"
        );
    }

    #[test]
    fn honeypot_known_bad_ip_blocks() {
        let inc = ctx_for("honeypot:6.6.6.6:abc", "6.6.6.6");
        let ctx = DecisionContext {
            incident: &inc,
            recent_events: vec![],
            related_incidents: vec![],
            already_blocked: vec![],
            available_skills: vec![],
            ip_reputation: Some(crate::abuseipdb::IpReputation {
                confidence_score: 90,
                total_reports: 100,
                distinct_users: 5,
                country_code: Some("RU".to_string()),
                isp: Some("noisy ASN".to_string()),
                is_tor: false,
            }),
            ip_geo: None,
            ip_dshield: None,
            ip_dshield_attacker: false,
            host_posture: None,
            prior_decisions: None,
            graph_context: None,
            graph_subgraph: None,
            playbook_outcome: None,
        };
        let d = decide_for_incident(&ctx);
        assert!(matches!(d.action, AiAction::BlockIp { .. }));
    }

    #[test]
    fn shield_ddos_is_acknowledged_not_reblocked() {
        let inc = ctx_for("shield:10.11.12.13:abc", "10.11.12.13");
        let d = decide(&inc);
        assert!(matches!(d.action, AiAction::Ignore { .. }));
    }

    #[test]
    fn unknown_detector_ignores() {
        let inc = ctx_for("random_detector:1.1.1.1:abc", "1.1.1.1");
        let d = decide(&inc);
        assert!(matches!(d.action, AiAction::Ignore { .. }));
    }
}
