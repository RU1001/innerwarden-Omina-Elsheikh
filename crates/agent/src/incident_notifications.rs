use std::path::Path;

use tracing::{info, warn};

use crate::config::ChannelFilterLevel;
use crate::notification_pipeline::{self, FeedbackEvent, GroupAction, SuppressReason};
use crate::{config, state_store, web_push, webhook, AgentState};

pub(crate) struct NotificationThresholds {
    pub(crate) webhook_min_rank: Option<u8>,
}

pub(crate) fn compute_notification_thresholds(
    cfg: &config::AgentConfig,
    _state: &AgentState,
) -> NotificationThresholds {
    // Telegram + Slack thresholds now live in the chat-channel registry
    // (spec 078, `notification_channels`); only the non-chat webhook sink
    // keeps its threshold here.
    let webhook_min_rank = if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
        Some(webhook::severity_rank(&cfg.webhook.parsed_min_severity()))
    } else {
        None
    };

    NotificationThresholds { webhook_min_rank }
}

/// Check if a first-alert should pass the channel filter.
/// For the first alert, auto_resolved is always false (obvious gate runs after dispatch).
pub(crate) fn passes_channel_filter(
    level: ChannelFilterLevel,
    severity: &innerwarden_core::event::Severity,
) -> bool {
    match level {
        ChannelFilterLevel::All | ChannelFilterLevel::Actionable => true,
        ChannelFilterLevel::None => false,
        ChannelFilterLevel::Critical => {
            matches!(
                severity,
                innerwarden_core::event::Severity::High
                    | innerwarden_core::event::Severity::Critical
            )
        }
    }
}

pub(crate) async fn dispatch_incident_notifications(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    thresholds: &NotificationThresholds,
) {
    // Notification cooldown - suppress duplicate alerts for the same entity
    // within a 10-minute window. Prevents alert spam during sustained attacks.
    let notify_cutoff =
        chrono::Utc::now() - chrono::Duration::seconds(crate::NOTIFICATION_COOLDOWN_SECS);
    let notify_keys = crate::notification_cooldown_keys(incident);
    let notify_suppressed = notify_keys.iter().any(|k| {
        state
            .store
            .get_cooldown(state_store::CooldownTable::Notification, k)
            .is_some_and(|ts| ts > notify_cutoff)
    });

    if notify_suppressed {
        info!(
            incident_id = %incident.incident_id,
            "notification cooldown: suppressing duplicate alert"
        );
        record_suppressed(data_dir, incident, SuppressReason::Cooldown);
        return;
    }

    // Environment-aware suppression: cloud timing anomalies, admin routine.
    if notification_pipeline::should_suppress_for_environment(incident, &state.environment_profile)
    {
        info!(
            incident_id = %incident.incident_id,
            "notification suppressed: environment profile (cloud/timing)"
        );
        record_suppressed(data_dir, incident, SuppressReason::Environment);
        return;
    }

    // Insert into grouping engine — determines if this is first-in-group or suppressed.
    let action = state.grouping_engine.insert(incident);

    let incident_rank = webhook::severity_rank(&incident.severity);

    match action {
        GroupAction::NotifyImmediately => {
            // Spec 005 Phase 7: operator-ignored detectors are demoted to
            // daily briefing before the gate even sees them. Critical
            // severity bypasses the demotion — "Not a threat" taps never
            // silence a real compromise.
            let detector = incident.incident_id.split(':').next().unwrap_or("unknown");
            let primary_entity = incident
                .entities
                .iter()
                .find(|e| {
                    matches!(
                        e.r#type,
                        innerwarden_core::entities::EntityType::Ip
                            | innerwarden_core::entities::EntityType::User
                    )
                })
                .cloned();
            let is_critical = matches!(
                incident.severity,
                innerwarden_core::event::Severity::Critical
            );
            if !is_critical {
                if let Some(entity) = &primary_entity {
                    if state.feedback_tracker.is_demoted(detector, &entity.r#type) {
                        *state
                            .telegram_deferred
                            .entry(detector.to_string())
                            .or_insert(0) += 1;
                        info!(
                            detector = %detector,
                            entity_type = ?entity.r#type,
                            "notification demoted by feedback tracker (spec 005 Phase 7)"
                        );
                        return;
                    }
                }
            }

            // Centralized notification gate: evaluate policy BEFORE any channel dispatch.
            // Only uncontained active intrusions and confirmed compromises get
            // immediate notification on ANY channel. Everything else → daily briefing.
            let gate_ctx = crate::notification_gate::NotificationContext::from_incident(incident);
            let gate_counter = state.telemetry.gate_suppressed_counter();
            let gate_verdict = crate::notification_gate::should_notify_with_counter(
                &gate_ctx,
                gate_counter.as_ref(),
            );

            let should_send_now = matches!(
                gate_verdict,
                crate::notification_gate::NotificationVerdict::SendNow
            );

            if !should_send_now {
                // Track for daily briefing + burst summary
                let detector = incident.incident_id.split(':').next().unwrap_or("unknown");
                *state
                    .telegram_deferred
                    .entry(detector.to_string())
                    .or_insert(0) += 1;

                // Record contained + check if burst threshold hit. The burst
                // summary fans out through the chat-channel registry (spec 078
                // P2) so Slack/Discord get it too, not just Telegram.
                let category = crate::notification_gate::burst_category(detector);
                let source_ip = incident
                    .entities
                    .iter()
                    .find(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Ip))
                    .map(|e| e.value.clone());
                if let Some(mut summary) = state
                    .notification_burst_tracker
                    .record_contained(category, source_ip.as_deref())
                {
                    let host = crate::notification_gate::resolve_host_id(
                        &cfg.agent.tags,
                        &state.knowledge_graph,
                    );
                    summary.host = host.clone();
                    let channels = crate::notification_channels::collect_chat_channels(cfg, state);
                    if !channels.is_empty() {
                        let msg = crate::notification_gate::format_burst_summary(&host, &summary);
                        tokio::spawn(async move {
                            crate::notification_channels::fan_out_summary(&channels, &msg).await;
                        });
                    }
                }
                return;
            }

            // Gate passed — dispatch to all channels.

            // Webhook
            if let Some(min_rank) = thresholds.webhook_min_rank {
                let level = cfg.webhook.channel_notifications.notification_level;
                if incident_rank >= min_rank && passes_channel_filter(level, &incident.severity) {
                    if let Err(e) = webhook::send_incident(
                        &cfg.webhook.url,
                        cfg.webhook.timeout_secs,
                        incident,
                        &cfg.webhook.format,
                    )
                    .await
                    {
                        state.telemetry.observe_error("webhook");
                        warn!(incident_id = %incident.incident_id, "webhook failed: {e:#}");
                    }
                }
            }

            // Telegram + Slack via the unified chat-channel registry (spec 078
            // P1). Each channel applies its own severity-rank + filter-level
            // gate inside `fan_out_alert`; one channel failing never blocks the
            // others. Webhook (machine JSON) and Web Push (browser) are non-chat
            // sinks and keep their own dispatch above/below.
            let chat_channels = crate::notification_channels::collect_chat_channels(cfg, state);
            if !chat_channels.is_empty() {
                let ctx = crate::notification_channels::ChatContext::from_config(cfg);
                crate::notification_channels::fan_out_alert(&chat_channels, incident, &ctx).await;
            }

            // Web Push — respects its own channel filter.
            let wp_level = cfg.web_push.channel_notifications.notification_level;
            if passes_channel_filter(wp_level, &incident.severity) {
                web_push::notify_incident(incident, data_dir, &cfg.web_push).await;
            }

            // Spec 005 Phase 7: record that we notified the operator for this
            // incident so the tracker can observe whether the operator
            // engaged with it in the next 24h.
            if let Some(entity) = &primary_entity {
                let ev = state.feedback_tracker.on_notification_sent(
                    detector,
                    entity.r#type.clone(),
                    &entity.value,
                    &incident.incident_id,
                    chrono::Utc::now(),
                );
                if let Err(e) = notification_pipeline::feedback_store::append(data_dir, &ev) {
                    warn!("feedback persist failed: {e:#}");
                }
            }
        }
        GroupAction::Suppress => {
            // Subsequent incident in group — suppressed. Group summary will be
            // emitted by the periodic tick in the agent loop.
            info!(
                incident_id = %incident.incident_id,
                "notification grouped: suppressing individual alert"
            );
            record_suppressed(data_dir, incident, SuppressReason::Grouped);
        }
    }

    let now = chrono::Utc::now();
    for k in &notify_keys {
        state
            .store
            .set_cooldown(state_store::CooldownTable::Notification, k, now);
    }
}

/// 2026-05-01: persist a `Suppressed` feedback event when the
/// pre-send gate (cooldown / environment / grouped) drops a
/// notification candidate. The previous audit only recorded `sent`
/// / `ignored` / `action` — operator question "auditar o que
/// funciona" had no way to distinguish the three suppression
/// mechanisms beyond mining INFO logs.
///
/// Best-effort: a write failure logs WARN but does not change the
/// caller's behaviour. The notification was already correctly
/// suppressed; the audit gap is recoverable from the journald log.
fn record_suppressed(
    data_dir: &Path,
    incident: &innerwarden_core::incident::Incident,
    reason: SuppressReason,
) {
    use innerwarden_core::entities::EntityType;
    let detector = incident
        .incident_id
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();
    // Pick the primary entity for indexing. Mirrors the on_notification_sent
    // path which keys on (detector, entity_type) — so suppressed events
    // align with sent events when an audit tool joins by that pair.
    let (entity_type, _entity_value) = incident
        .entities
        .first()
        .map(|e| (e.r#type.clone(), e.value.clone()))
        .unwrap_or((EntityType::Ip, String::new()));
    let event = FeedbackEvent::Suppressed {
        ts: chrono::Utc::now(),
        detector,
        entity_type,
        incident_id: incident.incident_id.clone(),
        reason,
    };
    if let Err(e) = notification_pipeline::feedback_store::append(data_dir, &event) {
        warn!("feedback_store append (suppressed) failed: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::{EntityRef, EntityType};
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;

    fn incident(incident_id: &str, entities: Vec<EntityRef>) -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: incident_id.to_string(),
            severity: Severity::High,
            title: "test incident".to_string(),
            summary: "synthetic notification fixture".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities,
        }
    }

    // Test 1: Full permutation of passes_channel_filter
    #[test]
    fn test_passes_channel_filter_all_level() {
        // ChannelFilterLevel::All passes everything including edge severities
        assert!(passes_channel_filter(
            ChannelFilterLevel::All,
            &Severity::Low
        ));
        assert!(passes_channel_filter(
            ChannelFilterLevel::All,
            &Severity::Medium
        ));
        assert!(passes_channel_filter(
            ChannelFilterLevel::All,
            &Severity::High
        ));
        assert!(passes_channel_filter(
            ChannelFilterLevel::All,
            &Severity::Critical
        ));
    }

    // Test 2: Actionable passes everything for first alerts (auto_resolved=false path)
    #[test]
    fn test_passes_channel_filter_actionable_level() {
        assert!(passes_channel_filter(
            ChannelFilterLevel::Actionable,
            &Severity::Low
        ));
        assert!(passes_channel_filter(
            ChannelFilterLevel::Actionable,
            &Severity::Medium
        ));
        assert!(passes_channel_filter(
            ChannelFilterLevel::Actionable,
            &Severity::High
        ));
        assert!(passes_channel_filter(
            ChannelFilterLevel::Actionable,
            &Severity::Critical
        ));
    }

    // Test 3: None blocks everything
    #[test]
    fn test_passes_channel_filter_none_level() {
        assert!(!passes_channel_filter(
            ChannelFilterLevel::None,
            &Severity::Low
        ));
        assert!(!passes_channel_filter(
            ChannelFilterLevel::None,
            &Severity::Medium
        ));
        assert!(!passes_channel_filter(
            ChannelFilterLevel::None,
            &Severity::High
        ));
        assert!(!passes_channel_filter(
            ChannelFilterLevel::None,
            &Severity::Critical
        ));
    }

    // Test 4: Critical level only passes High and Critical
    #[test]
    fn test_passes_channel_filter_critical_level() {
        assert!(!passes_channel_filter(
            ChannelFilterLevel::Critical,
            &Severity::Low
        ));
        assert!(!passes_channel_filter(
            ChannelFilterLevel::Critical,
            &Severity::Medium
        ));
        assert!(passes_channel_filter(
            ChannelFilterLevel::Critical,
            &Severity::High
        ));
        assert!(passes_channel_filter(
            ChannelFilterLevel::Critical,
            &Severity::Critical
        ));
    }

    // Test 5: severity_rank produces monotonically increasing values
    #[test]
    fn test_severity_rank_ordering() {
        use crate::webhook::severity_rank;
        assert!(severity_rank(&Severity::Low) < severity_rank(&Severity::Medium));
        assert!(severity_rank(&Severity::Medium) < severity_rank(&Severity::High));
        assert!(severity_rank(&Severity::High) < severity_rank(&Severity::Critical));
    }

    // Test 6: severity_rank boundary — Low meets min_rank threshold vs Medium
    #[test]
    fn test_severity_rank_threshold_gating() {
        use crate::webhook::severity_rank;
        let min_rank = severity_rank(&Severity::High);
        // High meets its own threshold
        assert!(severity_rank(&Severity::High) >= min_rank);
        // Critical exceeds High threshold
        assert!(severity_rank(&Severity::Critical) >= min_rank);
        // Medium does NOT meet High threshold
        assert!(severity_rank(&Severity::Medium) < min_rank);
    }

    #[test]
    fn record_suppressed_persists_reason_detector_and_primary_entity() {
        let dir = tempfile::tempdir().unwrap();
        let incident = incident(
            "ssh_bruteforce:185.234.1.1:window",
            vec![EntityRef::user("alice"), EntityRef::ip("185.234.1.1")],
        );

        record_suppressed(dir.path(), &incident, SuppressReason::Cooldown);

        let events = notification_pipeline::feedback_store::load(dir.path());
        assert_eq!(events.len(), 1);
        match &events[0] {
            FeedbackEvent::Suppressed {
                detector,
                entity_type,
                incident_id,
                reason,
                ..
            } => {
                assert_eq!(detector, "ssh_bruteforce");
                assert_eq!(entity_type, &EntityType::User);
                assert_eq!(incident_id, "ssh_bruteforce:185.234.1.1:window");
                assert_eq!(*reason, SuppressReason::Cooldown);
            }
            other => panic!("expected suppressed event, got {other:?}"),
        }
    }

    #[test]
    fn record_suppressed_defaults_to_ip_when_incident_has_no_entities() {
        let dir = tempfile::tempdir().unwrap();
        let incident = incident("environment_noise", vec![]);

        record_suppressed(dir.path(), &incident, SuppressReason::Environment);

        let events = notification_pipeline::feedback_store::load(dir.path());
        assert_eq!(events.len(), 1);
        match &events[0] {
            FeedbackEvent::Suppressed {
                detector,
                entity_type,
                reason,
                ..
            } => {
                assert_eq!(detector, "environment_noise");
                assert_eq!(entity_type, &EntityType::Ip);
                assert_eq!(*reason, SuppressReason::Environment);
            }
            other => panic!("expected suppressed event, got {other:?}"),
        }
    }

    #[test]
    fn record_suppressed_uses_empty_detector_for_empty_incident_id() {
        let dir = tempfile::tempdir().unwrap();
        let incident = incident("", vec![EntityRef::ip("185.234.1.1")]);

        record_suppressed(dir.path(), &incident, SuppressReason::Grouped);

        let events = notification_pipeline::feedback_store::load(dir.path());
        assert_eq!(events.len(), 1);
        match &events[0] {
            FeedbackEvent::Suppressed {
                detector, reason, ..
            } => {
                assert!(detector.is_empty());
                assert_eq!(*reason, SuppressReason::Grouped);
            }
            other => panic!("expected suppressed event, got {other:?}"),
        }
    }
}
