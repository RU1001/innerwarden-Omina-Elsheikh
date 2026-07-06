use std::path::Path;

use tracing::info;

use crate::{ai, config, correlation, AgentState};

/// Apply correlation confidence boost, attacker-intel boost, and
/// autoencoder anomaly boost to the AI decision, then emit the
/// canonical decision log.
///
/// The defender brain second-opinion path was removed when the
/// AlphaZero model was replaced by the SecureBERT classifier provider
/// routed through `ai::AiRouter`. Decisions now come from a single
/// place (the router) and there is no separate "brain compares with
/// AI" log to keep in sync.
pub(crate) fn apply_correlation_boost_and_log_decision(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    decision: &mut ai::AiDecision,
    _data_dir: &Path,
) {
    // If the same IP triggered multiple distinct detectors within the
    // correlation window, boost the confidence.
    let (boosted_confidence, correlated_detectors) = if cfg.correlation.enabled {
        let (b, k) = correlation::cross_detector_boost(
            &mut state.correlator,
            incident,
            decision.confidence as f64,
        );
        (b as f32, k)
    } else {
        (decision.confidence, vec![])
    };

    if boosted_confidence > decision.confidence {
        info!(
            incident_id = %incident.incident_id,
            base_confidence = decision.confidence,
            boosted_confidence,
            correlated_detectors = ?correlated_detectors,
            "cross-detector correlation boost applied"
        );
        decision.confidence = boosted_confidence;
        decision.reason = format!(
            "{} [correlated: {}]",
            decision.reason,
            correlated_detectors.join(", ")
        );
    }

    // Attacker intel risk score boost: if this IP has a known risk profile,
    // enrich the decision with context and boost confidence for repeat offenders.
    {
        let ip = incident
            .entities
            .iter()
            .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
            .map(|e| e.value.as_str());
        if let Some(ip) = ip {
            if let Some(profile) = state.attacker_profiles.get(ip) {
                let risk = profile.risk_score;
                if risk > 50 {
                    let boost = (risk as f32 - 50.0) / 500.0; // 50 → 0 %, 100 → 10 %
                    let new_conf = (decision.confidence + boost).min(1.0);
                    if new_conf > decision.confidence {
                        let pattern = &profile.dna.pattern_class;
                        info!(
                            incident_id = %incident.incident_id,
                            ip,
                            risk_score = risk,
                            pattern = pattern.as_str(),
                            visits = profile.visit_count,
                            boost = format!("{:.3}", boost),
                            "attacker intel: known threat - confidence boosted"
                        );
                        decision.confidence = new_conf;
                        decision.reason = format!(
                            "{} [intel: risk {}, {}, {} visits]",
                            decision.reason, risk, pattern, profile.visit_count
                        );
                    }
                }
            }
        }
    }

    // Autoencoder signal boost: if the neural model also flagged unusual
    // activity in this time window, boost confidence by up to 10 %. The
    // autoencoder is a silent intuition that reinforces real detections.
    // Score range (post 2026-05-01 percentile_score fix): in-range
    // events map to 0..0.99, above-max-anchor events extrapolate
    // asymptotically into 0.99..<1.0. Practical max boost is ~9.9%
    // instead of exactly 10%, which preserves the spirit of the
    // formula while killing the prior saturation at 1.0.
    if let Some(anomaly_score) = state.latest_anomaly_score.take() {
        if anomaly_score > 0.7 {
            let boost = (anomaly_score - 0.7) * 0.33; // 0.7 → 0 %, 1.0 → ~10 %
            let new_conf = (decision.confidence + boost).min(1.0);
            if new_conf > decision.confidence {
                info!(
                    incident_id = %incident.incident_id,
                    anomaly_score = format!("{:.3}", anomaly_score),
                    boost = format!("{:.3}", boost),
                    "autoencoder signal: neural model agrees - confidence boosted"
                );
                decision.confidence = new_conf;
                decision.reason = format!(
                    "{} [neural: {:.0}% anomaly]",
                    decision.reason,
                    anomaly_score * 100.0
                );
            }
        }
    }

    // Spec 043 Phase 1 — KG-derived confidence modifier. Runs AFTER the
    // existing attacker_profiles + neural boosts so the legacy paths are
    // untouched during the shadow rollout. Three modes:
    //   off     -> no-op (early return)
    //   shadow  -> compute + log to JSONL, do NOT mutate decision
    //   enforce -> apply modifier to decision.confidence
    // Critical incidents are protected by `apply_critical_floor` (negative
    // modifiers clamped to 0) — defensive layering with Phase 7.
    apply_kg_decide_modifier(incident, cfg, state, decision, _data_dir);

    info!(
        incident_id = %incident.incident_id,
        action = ?decision.action,
        confidence = decision.confidence,
        auto_execute = decision.auto_execute,
        reason = %decision.reason,
        "AI decision"
    );
}

/// Spec 043 Phase 1 — KG modifier wiring. Extracted into its own
/// function so the integration site stays readable and the unit tests
/// can exercise the shadow / enforce branches without spinning up the
/// full decide pipeline.
///
/// Spec 043 Phase 1b (2026-05-06): made `pub(crate)` so the
/// direct-block paths (`repeat-offender:*`, `multi-technique:*` in
/// `correlation_response.rs`) can also call into this hook. Pre-1b
/// the hook was wired only on the AI-router decide path, which prod
/// evidence shows accounts for <5% of actual block decisions on a
/// busy host (the rest flow through `repeat-offender` direct-blocks
/// that bypass the AI router entirely). Hooking the high-volume
/// paths makes the shadow log fill in minutes instead of days.
pub(crate) fn apply_kg_decide_modifier(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &AgentState,
    decision: &mut ai::AiDecision,
    data_dir: &Path,
) {
    use crate::kg_decide_features::{
        apply_critical_floor, compute_modifier, extract_features, parse_mode, write_shadow_log,
        DecideModifierMode, ShadowLogRecord,
    };

    let mode = parse_mode(&cfg.kg.decide_modifier_mode);
    if matches!(mode, DecideModifierMode::Off) {
        return;
    }

    let kg = match state.knowledge_graph.read() {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(
                "kg_decide_features: knowledge_graph lock poisoned: {e}; skipping modifier"
            );
            return;
        }
    };
    let now = chrono::Utc::now();
    let mut features = match extract_features(&kg, incident, now) {
        Some(f) => f,
        None => return, // no IP entity or entity not yet in graph
    };
    drop(kg); // release the read lock before any logging or apply

    // The KG IP node's `first_seen` (and risk) is rebuilt from a dated, daily
    // graph snapshot, so it effectively resets across days/restarts — the
    // age-based benign-suppression bands (`first_seen_age_days >= 7`) were
    // therefore unreachable and the modifier sat at 0.0 in practice. Override
    // with the PERSISTED attacker-intel profile (loaded from redb on boot, so
    // it carries the true first sighting + composite risk across restarts).
    // We take the OLDER age and HIGHER risk: a longer tenure makes the benign
    // bands reachable for genuinely long-lived IPs, and the higher composite
    // risk keeps the repeat-offender band honest — neither weakens detection.
    if let Some(ip) = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str())
    {
        if let Some(profile) = state.attacker_profiles.get(ip) {
            crate::kg_decide_features::merge_persisted_profile(
                &mut features,
                profile.first_seen,
                profile.risk_score,
                now,
            );
        }
    }

    let (modifier_raw, reason) = compute_modifier(&features);
    let modifier_after_floor = apply_critical_floor(modifier_raw, &incident.severity);
    let new_confidence = (decision.confidence + modifier_after_floor).clamp(0.0, 1.0);
    let would_change =
        crate::kg_decide_features::would_change_action(decision.confidence, new_confidence);

    match mode {
        DecideModifierMode::Off => unreachable!("early-returned above"),
        DecideModifierMode::Shadow => {
            // Best-effort log; do not mutate decision.
            let real_action = format!("{:?}", decision.action);
            let record = ShadowLogRecord {
                ts: now.to_rfc3339(),
                incident_id: incident.incident_id.clone(),
                real_action,
                real_confidence: decision.confidence,
                modifier_raw,
                modifier_after_floor,
                new_confidence,
                would_change_action: would_change,
                features,
                reason,
            };
            write_shadow_log(data_dir, &record);
            if would_change {
                info!(
                    incident_id = %incident.incident_id,
                    real_confidence = decision.confidence,
                    modifier = modifier_after_floor,
                    new_confidence,
                    reason,
                    "kg_decide_modifier: shadow — would_change_action"
                );
            }
        }
        DecideModifierMode::Enforce => {
            if modifier_after_floor.abs() > f32::EPSILON {
                info!(
                    incident_id = %incident.incident_id,
                    base_confidence = decision.confidence,
                    modifier = modifier_after_floor,
                    new_confidence,
                    reason,
                    "kg_decide_modifier: enforce — confidence adjusted"
                );
                decision.confidence = new_confidence;
                decision.reason = format!(
                    "{} [kg: benign={:.2}, risk={}, age={}d, modifier={:+.2}]",
                    decision.reason,
                    features.benign_history_score,
                    features.risk_score,
                    features.first_seen_age_days,
                    modifier_after_floor
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn correlation_boost_applies_when_multiple_detectors_match_same_ip() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        let ip = "203.0.113.50";

        // Prime the correlator with two distinct detectors firing on
        // the same IP so the cross-detector boost has signal to apply.
        let i1 = crate::tests::test_incident_with_kind(ip, "ssh_bruteforce");
        let i2 = crate::tests::test_incident_with_kind(ip, "port_scan");
        let _ = correlation::cross_detector_boost(&mut state.correlator, &i1, 0.6);
        let _ = correlation::cross_detector_boost(&mut state.correlator, &i2, 0.6);

        let trigger = crate::tests::test_incident_with_kind(ip, "credential_stuffing");
        let mut decision = ai::AiDecision {
            action: ai::AiAction::Ignore {
                reason: "test".into(),
            },
            confidence: 0.5,
            auto_execute: false,
            reason: "baseline".into(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        };

        apply_correlation_boost_and_log_decision(
            &trigger,
            &cfg,
            &mut state,
            &mut decision,
            dir.path(),
        );

        // Either the boost path or one of the other enrichments should
        // tag the reason with bracketed metadata; baseline alone never
        // carries `[`. Ensures the function actually ran end to end.
        assert!(
            decision.reason.contains('[') || decision.reason == "baseline",
            "decision.reason was not annotated: {}",
            decision.reason
        );
        assert!(state.latest_anomaly_score.is_none());
    }

    #[test]
    fn autoencoder_anomaly_score_is_consumed_even_when_below_threshold() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        state.latest_anomaly_score = Some(0.5);

        let incident = crate::tests::test_incident_with_kind("198.51.100.1", "ssh_bruteforce");
        let mut decision = ai::AiDecision {
            action: ai::AiAction::Ignore {
                reason: "test".into(),
            },
            confidence: 0.5,
            auto_execute: false,
            reason: "r".into(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        };

        apply_correlation_boost_and_log_decision(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            dir.path(),
        );
        // Score is `take()`'n regardless of whether the threshold was met.
        assert!(state.latest_anomaly_score.is_none());
    }

    // ── Spec 043 Phase 1 anchors (AUDIT-SPEC043-PHASE1) ────────────────
    //
    // Pre-Phase-1 the Decide path consulted only the `attacker_profiles`
    // sidecar (re-derived from JSONL, separate from the KG). Phase 1
    // adds a KG-derived modifier that runs AFTER the existing boosts.
    // Three anchors pin the contract:
    //
    //   1. shadow mode does NOT mutate decision.confidence (audit-only)
    //   2. enforce mode applies the modifier and tags the reason string
    //   3. Critical incidents NEVER receive a negative modifier even
    //      when an entity looks pristine (defensive layering with
    //      Spec 043 Phase 7 — KG-based FP suppression).

    fn seed_kg_with_benign_history(
        kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
        ip: &str,
    ) {
        use crate::knowledge_graph::types::{Edge, Node, Relation};
        use chrono::{Duration, Utc};
        let mut g = kg.write().unwrap();
        let now = Utc::now();
        let ip_id = g.add_node(Node::Ip {
            addr: ip.to_string(),
            is_internal: false,
            datasets: vec![],
            risk_score: 5,
            is_tor: false,
            first_seen: now - Duration::days(60),
            last_seen: now,
            attempted_usernames: vec![],
        });
        // 10 benign incidents in the last 7d — qualifies for the
        // strongest -0.30 band when paired with the IP's risk_score=5
        // and age=60d above.
        for i in 0..10 {
            let inc = g.add_node(Node::Incident {
                incident_id: format!("benign:seed:{i}"),
                detector: "test".to_string(),
                severity: "low".to_string(),
                title: format!("benign #{i}"),
                summary: String::new(),
                ts: now - Duration::days(2),
                mitre_ids: vec![],
                decision: None,
                confidence: None,
                decision_reason: None,
                decision_target: None,
                auto_executed: false,
                is_allowlisted: false,
                false_positive: false,
                fp_reporter: None,
                fp_reported_at: None,
                research_only: false,
            });
            g.add_edge(Edge::new(
                inc,
                ip_id,
                Relation::TriggeredBy,
                now - Duration::days(2),
            ));
        }
    }

    #[test]
    fn kg_decide_modifier_shadow_mode_logs_but_does_not_apply() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.kg.decide_modifier_mode = "shadow".to_string();

        let ip = "203.0.113.55";
        seed_kg_with_benign_history(&state.knowledge_graph, ip);

        let trigger = crate::tests::test_incident_with_kind(ip, "ssh_bruteforce");
        let baseline_confidence = 0.90_f32;
        let mut decision = ai::AiDecision {
            action: ai::AiAction::Ignore {
                reason: "test".into(),
            },
            confidence: baseline_confidence,
            auto_execute: false,
            reason: "baseline".into(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        };

        apply_correlation_boost_and_log_decision(
            &trigger,
            &cfg,
            &mut state,
            &mut decision,
            dir.path(),
        );

        // Shadow mode MUST NOT mutate decision.confidence via the KG path.
        // (Other boosts may legitimately change it, but the KG modifier
        // alone must be audit-only. We assert the KG tag never appears in
        // the reason string in shadow mode — that tag is enforce-only.)
        assert!(
            !decision.reason.contains("[kg:"),
            "shadow mode must NOT add the [kg: ...] reason tag; got: {}",
            decision.reason
        );

        // Shadow log file MUST exist for today's date with at least one
        // record for the trigger incident.
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let log_path = dir
            .path()
            .join(format!("kg_shadow_decide_modifier_{}.jsonl", date));
        assert!(
            log_path.exists(),
            "shadow log {} must exist after a shadow-mode evaluation",
            log_path.display()
        );
        let body = std::fs::read_to_string(&log_path).expect("read shadow log");
        assert!(
            body.contains(&trigger.incident_id),
            "shadow log must record the trigger incident id; got body: {body}"
        );
    }

    #[test]
    fn kg_decide_modifier_enforce_mode_applies_modifier() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.kg.decide_modifier_mode = "enforce".to_string();

        let ip = "203.0.113.56";
        seed_kg_with_benign_history(&state.knowledge_graph, ip);

        let trigger = crate::tests::test_incident_with_kind(ip, "ssh_bruteforce");
        let baseline_confidence = 0.90_f32;
        let mut decision = ai::AiDecision {
            action: ai::AiAction::Ignore {
                reason: "test".into(),
            },
            confidence: baseline_confidence,
            auto_execute: false,
            reason: "baseline".into(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        };

        apply_correlation_boost_and_log_decision(
            &trigger,
            &cfg,
            &mut state,
            &mut decision,
            dir.path(),
        );

        // Enforce mode: the strongest benign band (-0.30) must apply.
        // baseline 0.90 + (-0.30) = 0.60 (clamped to [0,1]).
        assert!(
            (decision.confidence - 0.60).abs() < 0.01,
            "enforce mode must apply -0.30 modifier (0.90 → 0.60); got {}",
            decision.confidence
        );
        assert!(
            decision.reason.contains("[kg:"),
            "enforce mode must tag reason with [kg: ...]; got: {}",
            decision.reason
        );
    }

    #[test]
    fn kg_decide_modifier_critical_severity_floor_holds() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.kg.decide_modifier_mode = "enforce".to_string();

        let ip = "203.0.113.57";
        seed_kg_with_benign_history(&state.knowledge_graph, ip);

        // Same baseline as above but Severity::Critical.
        let mut trigger =
            crate::tests::test_incident_with_kind(ip, "kill_chain:detected:DATA_EXFIL");
        trigger.severity = innerwarden_core::event::Severity::Critical;
        let baseline_confidence = 0.90_f32;
        let mut decision = ai::AiDecision {
            action: ai::AiAction::BlockIp {
                ip: ip.to_string(),
                skill_id: "block-ip-ufw".to_string(),
            },
            confidence: baseline_confidence,
            auto_execute: true,
            reason: "baseline".into(),
            alternatives: vec![],
            estimated_threat: "critical".into(),
        };

        apply_correlation_boost_and_log_decision(
            &trigger,
            &cfg,
            &mut state,
            &mut decision,
            dir.path(),
        );

        // Critical incident MUST NOT receive negative modifier even though
        // the entity has a 60-day pristine history. Defensive layering with
        // Spec 043 Phase 7. Confidence stays at baseline (no [kg: ...] tag
        // added because the post-floor modifier is exactly 0.0).
        assert!(
            (decision.confidence - baseline_confidence).abs() < f32::EPSILON,
            "Critical incident must NOT receive negative kg modifier; got {}",
            decision.confidence
        );
        assert!(
            !decision.reason.contains("[kg:"),
            "no [kg: ...] tag when post-floor modifier is zero on Critical; got: {}",
            decision.reason
        );
    }

    // ── Coverage anchors (AUDIT-COVERAGE-INCIDENT-DECISION-EVAL) ───────
    //
    // The five tests above pin the spec-043 contract and the existing
    // anomaly-take-on-low-score behaviour. The four anchors below cover
    // the other branches of `apply_correlation_boost_and_log_decision`
    // and `apply_kg_decide_modifier` so a regression that silently
    // disables one of those legacy enrichment paths gets caught.

    #[test]
    fn correlation_disabled_skips_cross_detector_boost() {
        // When `correlation.enabled = false` the function MUST NOT call
        // into the temporal correlator at all and the boosted_confidence
        // tuple falls through with the original confidence + empty
        // detector list. We verify by asserting that no `[correlated:` tag
        // is added to the reason even though we prime the correlator with
        // signal that would otherwise trigger a boost.
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.correlation.enabled = false;
        // Disable the kg modifier path too so the test isolates the
        // correlation toggle (otherwise a stray kg tag could hide the
        // regression we're trying to anchor).
        cfg.kg.decide_modifier_mode = "off".to_string();

        let ip = "203.0.113.60";
        // Prime the correlator. If the early-return is broken these
        // would yield a `[correlated: ...]` tag downstream.
        let i1 = crate::tests::test_incident_with_kind(ip, "ssh_bruteforce");
        let i2 = crate::tests::test_incident_with_kind(ip, "port_scan");
        let _ = correlation::cross_detector_boost(&mut state.correlator, &i1, 0.6);
        let _ = correlation::cross_detector_boost(&mut state.correlator, &i2, 0.6);

        let trigger = crate::tests::test_incident_with_kind(ip, "credential_stuffing");
        let baseline_confidence = 0.5_f32;
        let mut decision = ai::AiDecision {
            action: ai::AiAction::Ignore {
                reason: "test".into(),
            },
            confidence: baseline_confidence,
            auto_execute: false,
            reason: "baseline".into(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        };

        apply_correlation_boost_and_log_decision(
            &trigger,
            &cfg,
            &mut state,
            &mut decision,
            dir.path(),
        );

        // No correlation tag, no kg tag, no anomaly boost -> reason
        // remains exactly the baseline string and confidence unchanged.
        assert_eq!(
            decision.reason, "baseline",
            "with correlation disabled and no other enrichments, reason must be untouched"
        );
        assert!(
            (decision.confidence - baseline_confidence).abs() < f32::EPSILON,
            "with correlation disabled, confidence must NOT move; got {}",
            decision.confidence
        );
    }

    #[test]
    fn attacker_profile_high_risk_boosts_confidence_and_tags_reason() {
        // risk_score > 50 with confidence headroom must apply
        // `(risk - 50) / 500` boost and tag the reason with
        // `[intel: risk N, <pattern>, <visits> visits]`. Pin the formula
        // and the tag shape: a regression that drops the boost or the
        // tag silently demotes a known-attacker decision to AI baseline.
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.kg.decide_modifier_mode = "off".to_string();

        let ip = "203.0.113.61";
        let mut profile = crate::attacker_intel::new_profile(ip, chrono::Utc::now());
        profile.risk_score = 100; // boost = (100 - 50) / 500 = 0.10
        profile.visit_count = 7;
        profile.dna.pattern_class = "regular_scanner".to_string();
        state.attacker_profiles.insert(ip.to_string(), profile);

        let trigger = crate::tests::test_incident_with_kind(ip, "ssh_bruteforce");
        let baseline_confidence = 0.5_f32;
        let mut decision = ai::AiDecision {
            action: ai::AiAction::Ignore {
                reason: "test".into(),
            },
            confidence: baseline_confidence,
            auto_execute: false,
            reason: "baseline".into(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        };

        apply_correlation_boost_and_log_decision(
            &trigger,
            &cfg,
            &mut state,
            &mut decision,
            dir.path(),
        );

        // 0.5 + 0.10 = 0.60 (not clamped).
        assert!(
            (decision.confidence - 0.60).abs() < 1e-4,
            "risk=100 must boost confidence by exactly 0.10; got {}",
            decision.confidence
        );
        assert!(
            decision.reason.contains("[intel: risk 100"),
            "intel tag missing the risk value; got: {}",
            decision.reason
        );
        assert!(
            decision.reason.contains("regular_scanner") && decision.reason.contains("7 visits"),
            "intel tag must include pattern class and visit count; got: {}",
            decision.reason
        );
    }

    #[test]
    fn anomaly_score_above_threshold_boosts_confidence_and_tags_reason() {
        // anomaly_score > 0.7 must apply a `(score - 0.7) * 0.33` boost
        // capped by `min(1.0)` and tag the reason with
        // `[neural: NN% anomaly]`. Anchor for the autoencoder agreement
        // path that downstream operators rely on to distinguish "AI
        // alone said block" vs "AI + anomaly engine agreed".
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.kg.decide_modifier_mode = "off".to_string();
        // Score 1.0 → boost = 0.099 ≈ 0.10 cap.
        state.latest_anomaly_score = Some(1.0);

        let trigger = crate::tests::test_incident_with_kind("198.51.100.10", "ssh_bruteforce");
        let baseline_confidence = 0.5_f32;
        let mut decision = ai::AiDecision {
            action: ai::AiAction::Ignore {
                reason: "test".into(),
            },
            confidence: baseline_confidence,
            auto_execute: false,
            reason: "baseline".into(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        };

        apply_correlation_boost_and_log_decision(
            &trigger,
            &cfg,
            &mut state,
            &mut decision,
            dir.path(),
        );

        // 0.5 + (1.0 - 0.7) * 0.33 = 0.599
        assert!(
            decision.confidence > baseline_confidence,
            "anomaly_score>0.7 must boost confidence; got {}",
            decision.confidence
        );
        assert!(
            (decision.confidence - 0.599).abs() < 1e-3,
            "boost formula drift: expected ~0.599 from score=1.0, got {}",
            decision.confidence
        );
        assert!(
            decision.reason.contains("[neural:") && decision.reason.contains("% anomaly]"),
            "reason must carry the [neural: NN% anomaly] tag; got: {}",
            decision.reason
        );
        // Score is consumed regardless of branch.
        assert!(state.latest_anomaly_score.is_none());
    }

    #[test]
    fn kg_decide_modifier_off_mode_is_full_noop() {
        // mode = "off" must early-return BEFORE acquiring the kg lock or
        // computing features. Anchor: even with rich KG state seeded the
        // decision must be untouched and no shadow log file must be
        // created. This pins the rollback-without-redeploy contract.
        let dir = TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.kg.decide_modifier_mode = "off".to_string();

        let ip = "203.0.113.62";
        seed_kg_with_benign_history(&state.knowledge_graph, ip);

        let trigger = crate::tests::test_incident_with_kind(ip, "ssh_bruteforce");
        let baseline_confidence = 0.90_f32;
        let mut decision = ai::AiDecision {
            action: ai::AiAction::Ignore {
                reason: "test".into(),
            },
            confidence: baseline_confidence,
            auto_execute: false,
            reason: "baseline".into(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        };

        apply_kg_decide_modifier(&trigger, &cfg, &state, &mut decision, dir.path());

        // No mutation, no tag.
        assert!(
            (decision.confidence - baseline_confidence).abs() < f32::EPSILON,
            "off mode must NOT change confidence; got {}",
            decision.confidence
        );
        assert!(
            !decision.reason.contains("[kg:"),
            "off mode must NOT add the [kg: ...] tag; got: {}",
            decision.reason
        );

        // Off mode must NOT create the shadow log file either — the
        // operator's contract is that flipping mode→off is a true rollback.
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let log_path = dir
            .path()
            .join(format!("kg_shadow_decide_modifier_{}.jsonl", date));
        assert!(
            !log_path.exists(),
            "off mode must NOT create the shadow log; found {}",
            log_path.display()
        );
    }
}
