use crate::{abuseipdb, ai, config, geoip, AgentState};

/// Whether a decided action is worth a post-execution report to the operator.
///
/// `Dismiss` and `Ignore` are non-actions — the agent decided the incident is
/// not a threat, so "🛡️ Threat neutralized — Dismissed" reports are pure noise.
/// Every other action did something the operator should be told about.
fn is_reportable_action(action: &ai::AiAction) -> bool {
    use ai::AiAction;
    !matches!(action, AiAction::Dismiss { .. } | AiAction::Ignore { .. })
}

/// Send a post-execution action report ("what the agent did") to every
/// operator-facing chat channel when an action was executed.
///
/// Spec 078 Phase 2: this used to be Telegram-only; it now fans out through the
/// chat-channel registry so Slack (and future Discord) see the same
/// disposition. Gating is unchanged in spirit — executed action, immediate
/// threat, reportable (non-`Dismiss`/`Ignore`) — except the old
/// `telegram.bot.enabled` gate (the conversational-bot switch) is replaced by
/// "at least one chat channel is configured", so an action report now follows
/// the notification master switch rather than the bot interface.
#[allow(clippy::too_many_arguments)]
pub(crate) fn maybe_send_post_execution_report(
    incident: &innerwarden_core::incident::Incident,
    decision: &ai::AiDecision,
    execution_result: &str,
    cloudflare_pushed: bool,
    cfg: &config::AgentConfig,
    state: &AgentState,
    ip_reputation: Option<&abuseipdb::IpReputation>,
    ip_geo: Option<&geoip::GeoInfo>,
) {
    let was_executed = !execution_result.starts_with("skipped");
    if !was_executed {
        return;
    }

    // Only send action reports for immediate threats — routine blocks
    // (ssh_bruteforce, port_scan, etc.) go to the daily digest silently.
    if !crate::notification_pipeline::is_immediate_threat(incident) {
        return;
    }

    // Dismiss / Ignore are non-actions: the agent decided this incident is NOT a
    // threat. Sending "🛡️ Threat neutralized — Dismissed" for every dismissed
    // false positive floods the operator with reports about things that needed
    // no response. Skip them here (the first-alert and the daily digest still
    // record the incident).
    if !is_reportable_action(&decision.action) {
        return;
    }

    let channels = crate::notification_channels::collect_chat_channels(cfg, state);
    if channels.is_empty() {
        return;
    }

    use ai::AiAction;
    let (action_label, target) = match &decision.action {
        AiAction::BlockIp { ip, .. } => ("Blocked".to_string(), ip.clone()),
        AiAction::Monitor { ip } => ("Monitoring traffic from".to_string(), ip.clone()),
        AiAction::Honeypot { ip } => ("Redirected to honeypot".to_string(), ip.clone()),
        AiAction::SuspendUserSudo { user, .. } => ("Suspended sudo for".to_string(), user.clone()),
        AiAction::KillProcess { user, .. } => ("Killed processes for".to_string(), user.clone()),
        AiAction::BlockContainer { container_id, .. } => {
            ("Paused container".to_string(), container_id.clone())
        }
        AiAction::KillChainResponse { .. } => (
            "Kill chain response".to_string(),
            format!(
                "PID {}",
                incident.incident_id.split(':').nth(2).unwrap_or("-")
            ),
        ),
        AiAction::Ignore { .. } => ("Ignored".to_string(), "-".to_string()),
        AiAction::Dismiss { .. } => ("Dismissed".to_string(), "-".to_string()),
        AiAction::RequestConfirmation { .. } => {
            ("Requested confirmation for".to_string(), "-".to_string())
        }
    };

    let report = crate::notification_channels::ActionReport {
        action_label,
        target,
        incident_title: incident.title.clone(),
        confidence: decision.confidence,
        host: incident.host.clone(),
        dry_run: cfg.responder.dry_run,
        ip_reputation: ip_reputation.cloned(),
        ip_geo: ip_geo.cloned(),
        cloudflare_pushed,
    };
    tokio::spawn(async move {
        crate::notification_channels::fan_out_action_report(&channels, &report).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    #[test]
    fn dismiss_and_ignore_are_not_reportable() {
        // Non-actions must not produce a "Threat neutralized" report — that
        // floods the operator with noise about incidents that needed nothing.
        assert!(!is_reportable_action(&ai::AiAction::Dismiss {
            reason: "false positive".to_string(),
        }));
        assert!(!is_reportable_action(&ai::AiAction::Ignore {
            reason: "benign".to_string(),
        }));

        // Real actions still report.
        assert!(is_reportable_action(&ai::AiAction::BlockIp {
            ip: "203.0.113.7".to_string(),
            skill_id: "block-ip-ufw".to_string(),
        }));
        assert!(is_reportable_action(&ai::AiAction::Monitor {
            ip: "203.0.113.7".to_string(),
        }));
        assert!(is_reportable_action(&ai::AiAction::RequestConfirmation {
            summary: "needs operator".to_string(),
        }));
    }

    fn base_decision(action: ai::AiAction) -> ai::AiDecision {
        ai::AiDecision {
            action,
            confidence: 0.91,
            auto_execute: true,
            reason: "unit test".to_string(),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        }
    }

    fn state_with_telegram(dir: &std::path::Path) -> AgentState {
        let mut state = crate::tests::triage_test_state(dir);
        let tg = crate::telegram::TelegramClient::new("token", "chat-id", None)
            .expect("telegram client");
        state.telegram_client = Some(Arc::new(tg));
        state
    }

    #[tokio::test]
    async fn skips_when_not_executed_or_no_channels_configured() {
        let dir = TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.telegram.enabled = true; // enabled, but state has no client below
        let mut incident = crate::tests::test_incident("203.0.113.30");
        incident.severity = innerwarden_core::event::Severity::Critical;
        let decision = base_decision(ai::AiAction::BlockIp {
            ip: "203.0.113.30".to_string(),
            skill_id: "block-ip-ufw".to_string(),
        });

        maybe_send_post_execution_report(
            &incident,
            &decision,
            "skipped: confidence below threshold",
            false,
            &cfg,
            &state,
            None,
            None,
        );

        cfg.telegram.enabled = true;
        maybe_send_post_execution_report(
            &incident, &decision, "ok", false, &cfg, &state, None, None,
        );
    }

    #[tokio::test]
    async fn skips_non_immediate_threats_even_when_executed() {
        let dir = TempDir::new().expect("tempdir");
        let state = state_with_telegram(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.telegram.enabled = true;
        let incident = crate::tests::test_incident_with_kind("203.0.113.31", "benign_detector");
        let decision = base_decision(ai::AiAction::Monitor {
            ip: "203.0.113.31".to_string(),
        });

        maybe_send_post_execution_report(
            &incident, &decision, "ok", false, &cfg, &state, None, None,
        );
    }

    #[tokio::test]
    async fn maps_all_action_variants_into_report_labels_and_targets() {
        let dir = TempDir::new().expect("tempdir");
        let state = state_with_telegram(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.telegram.enabled = true;
        cfg.responder.dry_run = true;

        let mut incident = crate::tests::test_incident("203.0.113.32");
        incident.severity = innerwarden_core::event::Severity::Critical;
        incident.incident_id = "kill_chain:203.0.113.32:4242".to_string();

        let actions = vec![
            ai::AiAction::BlockIp {
                ip: "203.0.113.32".to_string(),
                skill_id: "block-ip-ufw".to_string(),
            },
            ai::AiAction::Monitor {
                ip: "203.0.113.32".to_string(),
            },
            ai::AiAction::Honeypot {
                ip: "203.0.113.32".to_string(),
            },
            ai::AiAction::SuspendUserSudo {
                user: "root".to_string(),
                duration_secs: 300,
            },
            ai::AiAction::KillProcess {
                user: "root".to_string(),
                duration_secs: 120,
            },
            ai::AiAction::BlockContainer {
                container_id: "abc123".to_string(),
                action: "pause".to_string(),
            },
            ai::AiAction::KillChainResponse {
                reason: "chain complete".to_string(),
            },
            ai::AiAction::Ignore {
                reason: "false positive".to_string(),
            },
            ai::AiAction::Dismiss {
                reason: "below noise floor".to_string(),
            },
            ai::AiAction::RequestConfirmation {
                summary: "needs approval".to_string(),
            },
        ];

        for action in actions {
            let decision = base_decision(action);
            maybe_send_post_execution_report(
                &incident, &decision, "executed", true, &cfg, &state, None, None,
            );
        }
    }
}
