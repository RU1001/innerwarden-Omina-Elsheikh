//! Narrative tick integration for observation verification (spec 021 Phase B).
//!
//! Scans the knowledge graph for undecided (OBSERVING) incidents and runs the
//! behavioural scorer from `observation_verify`.  High scores auto-dismiss,
//! low scores escalate, and ambiguous items are collected for AI verification
//! (Phase C).

use crate::knowledge_graph::types::{Node, NodeType};
use crate::knowledge_graph::KnowledgeGraph;
use crate::observation_verify::{self, ScoreBreakdown, VerificationResult};
use crate::AgentState;

use tracing::{debug, info, warn};

/// Item queued for AI verification (score 40-69). Phase C consumes these.
#[derive(Debug)]
#[allow(dead_code)] // Phase C reads these fields
pub(crate) struct AmbiguousItem {
    pub incident_id: String,
    pub score: u8,
    pub evidence: serde_json::Value,
    pub detector: String,
    pub title: String,
}

/// Run observation verification on all OBSERVING incidents in the knowledge graph.
///
/// Returns the list of ambiguous items that need AI verification (Phase C).
///
/// Spec 028-b: became `async` so the Escalate branch can reach the Fase 4
/// `ai_provider.decide()` path. `data_dir` is threaded through for the
/// decision audit / skill execution helpers. The behaviour shift is gated
/// behind `cfg.incident_flow.escalate_to_decide`; when the flag is false
/// (default) this function still only escalates to the graph + JSONL and
/// the async surface is equivalent to the prior sync one.
pub(crate) async fn verify_observing_incidents(
    cfg: &crate::config::AgentConfig,
    state: &mut AgentState,
    data_dir: &std::path::Path,
) -> Vec<AmbiguousItem> {
    if !cfg.observation.enabled {
        return Vec::new();
    }

    let dismiss_threshold = cfg.observation.auto_dismiss_threshold;
    let escalate_threshold = cfg.observation.auto_escalate_threshold;

    // Determine temporal context from agent state
    let operator_active = !state.operator_ips.is_empty();

    // Check recent package activity — look at event kinds seen this narrative date.
    let recent_package_activity = state.narrative_acc.events_by_kind.keys().any(|k| {
        k.starts_with("package.")
            || k.starts_with("apt.")
            || k.starts_with("dpkg.")
            || k.starts_with("dnf.")
            || k.starts_with("snap.")
    });

    // Check if systemctl restart ran recently
    let recent_service_restart = state
        .narrative_acc
        .events_by_kind
        .keys()
        .any(|k| k.contains("systemd.") || k.contains("service.restart"));

    // Check maintenance window
    let now = chrono::Local::now();
    let in_maintenance = observation_verify::in_maintenance_window(
        &cfg.observation.maintenance_windows,
        now.hour(),
        now.minute(),
    );

    // Collect undecided incident data from the graph (read lock)
    let undecided: Vec<(String, String, String, serde_json::Value, Option<String>)> = {
        let graph = state.knowledge_graph.read().unwrap();
        collect_undecided_incidents(&graph)
    };

    if undecided.is_empty() {
        return Vec::new();
    }

    let mut dismissed = 0u32;
    let mut escalated = 0u32;
    let mut ambiguous_items = Vec::new();

    for (incident_id, detector, title, evidence, primary_ip) in undecided {
        let (result, breakdown) = observation_verify::behaviour_score(
            &evidence,
            operator_active,
            recent_package_activity,
            recent_service_restart,
            in_maintenance,
            dismiss_threshold,
            escalate_threshold,
        );

        match result {
            VerificationResult::Dismiss { score, reason } => {
                let mut graph = state.knowledge_graph.write().unwrap();
                graph.ingest_decision(
                    &incident_id,
                    "dismiss",
                    None,
                    1.0,
                    &format!("obs-verify score {score}/100: {reason}"),
                    true,
                    chrono::Utc::now(),
                );
                dismissed += 1;
                debug!(
                    incident_id,
                    score, reason, "observation-verify: auto-dismissed"
                );
            }
            VerificationResult::Escalate { score, reason } => {
                apply_escalate(
                    &state.knowledge_graph,
                    state.decision_writer.as_mut(),
                    cfg.incident_flow.escalate_to_decide,
                    &incident_id,
                    primary_ip.as_deref(),
                    score,
                    &reason,
                );
                // Spec 028-b: when the operator has flipped the flag, follow
                // the escalate through to the Fase 4 decide() + execute path
                // so the IP actually gets actioned instead of sitting under
                // the "escalate" label forever (the autonomy gap that
                // motivated spec 028).
                if cfg.incident_flow.escalate_to_decide {
                    promote_escalated_to_decision(
                        cfg,
                        state,
                        data_dir,
                        &incident_id,
                        &detector,
                        &title,
                        primary_ip.as_deref(),
                    )
                    .await;
                }
                escalated += 1;
                debug!(
                    incident_id,
                    score, reason, "observation-verify: escalated to Fase 4"
                );
            }
            VerificationResult::NeedsAiVerification { score } => {
                ambiguous_items.push(AmbiguousItem {
                    incident_id,
                    score,
                    evidence,
                    detector,
                    title,
                });
            }
        }

        // Store breakdown for dashboard (Phase D)
        store_breakdown(&breakdown);
    }

    if dismissed > 0 || escalated > 0 || !ambiguous_items.is_empty() {
        info!(
            dismissed,
            escalated,
            ambiguous = ambiguous_items.len(),
            "observation-verify: processed OBSERVING queue"
        );
    }

    ambiguous_items
}

/// Collect undecided incident data from the knowledge graph.
///
/// The last tuple element is the primary IP entity connected to the incident,
/// if any. Spec 028-c uses this so the escalate decision written below can
/// link back to a target IP and the dashboard can bucket the IP as "needs
/// attention" instead of "observing".
fn collect_undecided_incidents(
    graph: &KnowledgeGraph,
) -> Vec<(String, String, String, serde_json::Value, Option<String>)> {
    graph
        .nodes_of_type(NodeType::Incident)
        .iter()
        .filter_map(|&id| {
            if let Some(Node::Incident {
                incident_id,
                decision,
                research_only,
                detector,
                title,
                summary,
                severity,
                ..
            }) = graph.get_node(id)
            {
                if decision.is_some() || *research_only {
                    return None;
                }

                let mut evidence = serde_json::json!({
                    "detector": detector,
                    "severity": severity,
                    "title": title,
                    "summary": summary,
                });

                // Enrich evidence from connected graph nodes.
                // Track the first IP entity we see as the primary attacker IP.
                let mut primary_ip: Option<String> = None;
                for edge in graph.edges_slice() {
                    if edge.from != id && edge.to != id {
                        continue;
                    }
                    let other_id = if edge.from == id { edge.to } else { edge.from };
                    if let Some(node) = graph.get_node(other_id) {
                        if primary_ip.is_none() {
                            if let Node::Ip { addr, .. } = node {
                                primary_ip = Some(addr.clone());
                            }
                        }
                        enrich_evidence_from_node(&mut evidence, node, graph);
                    }
                }

                Some((
                    incident_id.clone(),
                    detector.clone(),
                    title.clone(),
                    evidence,
                    primary_ip,
                ))
            } else {
                None
            }
        })
        .collect()
}

/// Add fields to the evidence JSON from a connected graph node.
fn enrich_evidence_from_node(
    evidence: &mut serde_json::Value,
    node: &Node,
    graph: &KnowledgeGraph,
) {
    let obj = evidence.as_object_mut().unwrap();
    match node {
        Node::Process {
            comm, exe, ppid, ..
        } => {
            obj.insert("comm".into(), serde_json::Value::String(comm.clone()));
            if let Some(exe) = exe {
                obj.insert("binary_path".into(), serde_json::Value::String(exe.clone()));
            }
            if *ppid > 0 {
                if let Some(parent_comm) = find_process_comm_by_pid(graph, *ppid) {
                    obj.insert("ppid_comm".into(), serde_json::Value::String(parent_comm));
                }
            }
        }
        Node::Ip { addr, .. } => {
            obj.insert("dst_ip".into(), serde_json::Value::String(addr.clone()));
        }
        Node::Port {
            number, protocol, ..
        } => {
            obj.insert("dst_port".into(), serde_json::json!(*number));
            obj.insert(
                "protocol".into(),
                serde_json::Value::String(protocol.clone()),
            );
        }
        Node::File { path, .. } => {
            obj.insert("path".into(), serde_json::Value::String(path.clone()));
        }
        _ => {}
    }
}

/// Find a process node by PID and return its comm name.
fn find_process_comm_by_pid(graph: &KnowledgeGraph, pid: u32) -> Option<String> {
    for &nid in &graph.nodes_of_type(NodeType::Process) {
        if let Some(Node::Process {
            pid: p, comm: c, ..
        }) = graph.get_node(nid)
        {
            if *p == pid {
                return Some(c.clone());
            }
        }
    }
    None
}

/// Spec 062 Phase 5 — pure `needs_human` veto predicate for an LLM
/// escalation decision. Returns true when the action is HIGH-IMPACT
/// (block_ip / suspend_user / kill_process / block_container, per
/// [`crate::ai::AiAction::is_high_impact`]) AND the model's confidence is
/// below `min_conf`. Soft / low-blast actions never trip it, and a
/// confident high-impact call passes through. Free of I/O so every branch
/// (action class × confidence boundary) is unit-testable.
fn llm_escalation_needs_human(
    action: &crate::ai::AiAction,
    confidence: f32,
    min_conf: f32,
) -> bool {
    action.is_high_impact() && confidence < min_conf
}

/// Spec 062 Phase 5 — build the `needs_review` decision entry for a
/// high-impact LLM escalation that fell below the confidence floor. Pure
/// (no I/O). Mirrors [`needs_review_entry`] but carries the would-be
/// action + the deciding LLM in the reason so the operator sees exactly
/// what was deferred and why. `auto_executed = false`,
/// `execution_result = "awaiting_human"`, `decision_layer =
/// "observation_verifier"` — the same lifecycle Phase 1 / Phase 2 sweep
/// and the dashboard already understand.
fn escalation_needs_review_entry(
    incident: &innerwarden_core::incident::Incident,
    provider_name: &str,
    decision: &crate::ai::AiDecision,
    min_conf: f32,
    now: chrono::DateTime<chrono::Utc>,
) -> crate::decisions::DecisionEntry {
    // Prefer the action's own target IP (the IP the LLM wanted to act on);
    // fall back to the incident's primary IP entity. AiDecision has no
    // target accessor, so read it off the action variant directly.
    let target_ip = match &decision.action {
        crate::ai::AiAction::BlockIp { ip, .. }
        | crate::ai::AiAction::Monitor { ip }
        | crate::ai::AiAction::Honeypot { ip } => Some(ip.clone()),
        _ => incident
            .entities
            .iter()
            .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
            .map(|e| e.value.clone()),
    };
    crate::decisions::DecisionEntry {
        ts: now,
        incident_id: incident.incident_id.clone(),
        host: incident.host.clone(),
        ai_provider: "needs-review".to_string(),
        action_type: "needs_review".to_string(),
        target_ip,
        target_user: None,
        skill_id: None,
        confidence: decision.confidence,
        auto_executed: false,
        dry_run: false,
        reason: format!(
            "High-impact action '{}' proposed by the escalation LLM ({}) at \
             confidence {:.2}, below the {:.2} floor. Deferred to human review \
             instead of auto-executing (Spec 062 Phase 5 needs_human veto). \
             LLM rationale: {}",
            decision.action.name(),
            provider_name,
            decision.confidence,
            min_conf,
            decision.reason,
        ),
        estimated_threat: decision.estimated_threat.clone(),
        execution_result: "awaiting_human".to_string(),
        prev_hash: None,
        decision_layer: Some("observation_verifier".to_string()),
    }
}

/// Promote an escalated incident into the Fase 4 decide() + execute path
/// (spec 028-b full wiring). Called only when the
/// `incident_flow.escalate_to_decide` feature flag is enabled.
///
/// Reconstructs a minimal `Incident` from the graph + evidence, builds a
/// `DecisionContext`, invokes the production AI provider, runs the decision
/// through the same safeguards / execution gate / audit helpers the fast
/// loop uses, and writes the resulting decision to both the decisions
/// JSONL and the knowledge graph. The graph label written by
/// `apply_escalate` immediately before is overwritten by the real action
/// (`block_ip`, `ignore`, etc.) because `ingest_decision` updates in place.
///
/// Intentionally shallow context (empty `recent_events` /
/// `related_incidents`, graph_subgraph built from the incident's connected
/// nodes) because this path runs in the slow loop where assembling full
/// enrichment is expensive and would duplicate fast-loop work. The primary
/// value is executing on escalates the fast loop would not have reached.
async fn promote_escalated_to_decision(
    cfg: &crate::config::AgentConfig,
    state: &mut AgentState,
    data_dir: &std::path::Path,
    incident_id: &str,
    detector: &str,
    title: &str,
    primary_ip: Option<&str>,
) {
    // 1. Provider must exist. If AI is disabled entirely this path is a
    //    no-op and we stay at the "escalate" label in the graph.
    //
    // Spec 029 PR-C.2: this is the Decide role (the escalate-to-decide
    // wiring from 028-b), so route through the capability router.
    //
    // Spec 062 Phase 5: this path runs ONLY on incidents the fast-path
    // warden could not resolve (they were parked as `escalate`). Prefer
    // the LLM for the second-opinion Decide via `escalation_decider()` —
    // `provider_for(Decide)` would hand it back to the same warden, which
    // is why the configured Azure LLM recorded zero decisions in prod.
    // Gated by `[learning] llm_escalation_enabled` (default true) as a
    // no-redeploy kill switch; when off, keep the legacy Decide routing.
    let provider = if cfg.learning.llm_escalation_enabled {
        state.ai_router.escalation_decider()
    } else {
        state.ai_router.provider_for(crate::ai::Capability::Decide)
    };
    let Some(provider) = provider else {
        tracing::debug!(
            incident_id,
            "028-b: no Decide provider configured, leaving escalated in graph"
        );
        return;
    };
    let provider_name = provider.name();

    // 2. Reconstruct the minimal Incident from the graph node. This loses
    //    fields like `recommended_checks` and full `tags` but preserves
    //    everything the provider and the downstream helpers actually read.
    let Some(incident) = reconstruct_incident_from_graph(state, incident_id) else {
        tracing::warn!(
            incident_id,
            "028-b: incident node missing from graph, skipping promote"
        );
        return;
    };

    // 3. Build a slim DecisionContext. recent_events + related_incidents
    //    stay empty; graph_subgraph carries the structural context the
    //    fast loop would otherwise have included.
    let available_skills: Vec<crate::ai::SkillInfo> = state
        .skill_registry
        .infos()
        .into_iter()
        .map(|s| crate::ai::SkillInfo {
            id: s.id.clone(),
            applicable_to: s.applicable_to.clone(),
        })
        .collect();

    let graph_subgraph = if cfg.ai.use_structured_subgraph {
        let graph = state.knowledge_graph.read().unwrap();
        graph
            .find_by_incident(incident_id)
            .map(|nid| graph.attack_subgraph_json(nid, 3))
    } else {
        None
    };

    let ctx = crate::ai::DecisionContext {
        incident: &incident,
        recent_events: Vec::new(),
        related_incidents: Vec::new(),
        already_blocked: state.blocklist.as_vec(),
        available_skills,
        ip_reputation: None,
        ip_geo: None,
        ip_dshield: None,
        ip_dshield_attacker: false,
        host_posture: None,
        prior_decisions: None,
        graph_context: None,
        graph_subgraph,
        // Narrative-verification Decide path runs outside the incident
        // playbook flow; no playbook outcome to surface.
        playbook_outcome: None,
    };

    tracing::info!(
        incident_id,
        detector,
        target_ip = ?primary_ip,
        "028-b: promoting escalated incident to decide()"
    );
    state.telemetry.observe_ai_sent();

    let decision_start = std::time::Instant::now();
    let mut decision = match provider.decide(&ctx).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                incident_id,
                provider_name,
                error = %e,
                "028-b: provider.decide() failed, leaving escalated in graph"
            );
            state.telemetry.observe_error("observation_verify_decide");
            return;
        }
    };
    let latency_ms = decision_start.elapsed().as_millis();
    state
        .telemetry
        .observe_ai_decision(&decision.action, latency_ms);

    // 3b. Spec 062 Phase 5 — needs_human veto. If the escalation LLM
    //     chose a HIGH-IMPACT action (block_ip / suspend_user /
    //     kill_process / block_container) but is below the configured
    //     confidence floor, do NOT auto-execute: park it in `needs_review`
    //     for the operator (Phase 1 lifecycle). "Com peso, confirma."
    //     Soft / low-blast actions and confident calls fall through to the
    //     normal execute path unchanged. Skipped entirely when the LLM
    //     escalation routing is disabled (then there is no LLM second
    //     opinion to second-guess).
    if cfg.learning.llm_escalation_enabled
        && llm_escalation_needs_human(
            &decision.action,
            decision.confidence,
            cfg.learning.llm_escalation_min_confidence,
        )
    {
        let now = chrono::Utc::now();
        let entry = escalation_needs_review_entry(
            &incident,
            provider_name,
            &decision,
            cfg.learning.llm_escalation_min_confidence,
            now,
        );
        if let Some(writer) = &mut state.decision_writer {
            if let Err(e) = writer.write(&entry) {
                tracing::warn!(
                    incident_id,
                    error = %e,
                    "062-p5: failed to write needs_review veto decision"
                );
            }
        }
        {
            let mut graph = state.knowledge_graph.write().unwrap();
            graph.ingest_decision(
                incident_id,
                "needs_review",
                entry.target_ip.as_deref(),
                decision.confidence,
                &entry.reason,
                false,
                now,
            );
        }
        tracing::info!(
            incident_id,
            provider_name,
            action = decision.action.name(),
            confidence = decision.confidence,
            "062-p5: high-impact LLM escalation below confidence floor — \
             deferred to human (needs_review) instead of auto-executing"
        );
        return;
    }

    // 4. Reuse the existing post-decision safeguards so that
    //    already-blocked IPs, below-threshold confidence, and other fast-
    //    loop guards apply identically here.
    let mut blocked_set = state.blocklist.as_vec().into_iter().collect();
    crate::incident_post_decision::apply_post_decision_safeguards(
        &incident,
        cfg,
        state,
        &mut decision,
        &mut blocked_set,
    );

    // 5. Execute (or skip) the decision via the same gate the fast loop
    //    uses. This is what closes the autonomy gap: previously the
    //    escalated incident would die at the graph label; now it reaches
    //    the skill executor.
    let (execution_result, _cloudflare_pushed) =
        crate::incident_execution_gate::execute_or_skip_decision(
            &incident, &decision, data_dir, cfg, state,
        )
        .await;

    // 6. Audit trail: decision entry in JSONL with the real action, not
    //    the "escalate" placeholder.
    crate::incident_audit_write::write_decision_audit_entry(
        &incident,
        provider_name,
        &decision,
        &execution_result,
        cfg,
        state,
    );

    // 7. Overwrite the graph decision with the real action. ingest_decision
    //    updates the Incident node in place, so the "escalate" label
    //    written moments ago becomes the real action here.
    {
        let (action_type, action_target) = match &decision.action {
            crate::ai::AiAction::BlockIp { ip, .. } => ("block_ip", Some(ip.as_str())),
            crate::ai::AiAction::Monitor { ip } => ("monitor", Some(ip.as_str())),
            crate::ai::AiAction::Honeypot { ip } => ("honeypot", Some(ip.as_str())),
            crate::ai::AiAction::SuspendUserSudo { user, .. } => {
                ("suspend_user_sudo", Some(user.as_str()))
            }
            crate::ai::AiAction::KillProcess { user, .. } => ("kill_process", Some(user.as_str())),
            crate::ai::AiAction::BlockContainer { container_id, .. } => {
                ("block_container", Some(container_id.as_str()))
            }
            crate::ai::AiAction::Ignore { .. } => ("ignore", None),
            crate::ai::AiAction::Dismiss { .. } => ("dismiss", None),
            crate::ai::AiAction::RequestConfirmation { .. } => ("request_confirmation", None),
            crate::ai::AiAction::KillChainResponse { .. } => ("kill_chain_response", None),
        };
        let auto_executed = decision.auto_execute && !execution_result.is_empty();
        let mut graph = state.knowledge_graph.write().unwrap();
        graph.ingest_decision(
            incident_id,
            action_type,
            action_target,
            decision.confidence,
            &decision.reason,
            auto_executed,
            chrono::Utc::now(),
        );
    }

    // Title is available for log context; pass it so operators tailing
    // journalctl see which incident was promoted without having to cross-
    // reference incident_id.
    let _ = title;
}

/// Reconstruct an Incident from the graph node and its connected entities.
/// Used by `promote_escalated_to_decision` because the slow-loop verifier
/// does not have the original `Incident` object in memory (the fast loop
/// consumed it on arrival).
///
/// Fields that are not preserved in the graph (`recommended_checks`, full
/// `tags` list beyond MITRE IDs, arbitrary extra evidence keys) come back
/// as defaults. This is a lossy reconstruction but covers everything the
/// decision pipeline actually reads.
fn reconstruct_incident_from_graph(
    state: &AgentState,
    incident_id: &str,
) -> Option<innerwarden_core::incident::Incident> {
    use innerwarden_core::entities::{EntityRef, EntityType};
    use innerwarden_core::event::Severity;

    let graph = state.knowledge_graph.read().unwrap();
    let inc_node_id = graph.find_by_incident(incident_id)?;
    let Node::Incident {
        severity,
        title,
        summary,
        ts,
        mitre_ids,
        ..
    } = graph.get_node(inc_node_id)?
    else {
        return None;
    };

    let severity = match severity.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    };

    // Collect entities by walking the edges of the incident node.
    let mut entities: Vec<EntityRef> = Vec::new();
    for edge in graph.edges_slice() {
        if edge.from != inc_node_id && edge.to != inc_node_id {
            continue;
        }
        let other_id = if edge.from == inc_node_id {
            edge.to
        } else {
            edge.from
        };
        let Some(node) = graph.get_node(other_id) else {
            continue;
        };
        match node {
            Node::Ip { addr, .. } => entities.push(EntityRef {
                r#type: EntityType::Ip,
                value: addr.clone(),
            }),
            Node::User { name, .. } => entities.push(EntityRef {
                r#type: EntityType::User,
                value: name.clone(),
            }),
            Node::Container { container_id, .. } => entities.push(EntityRef {
                r#type: EntityType::Container,
                value: container_id.clone(),
            }),
            Node::File { path, .. } => entities.push(EntityRef {
                r#type: EntityType::Path,
                value: path.clone(),
            }),
            _ => {}
        }
    }

    Some(innerwarden_core::incident::Incident {
        ts: *ts,
        host: String::new(),
        incident_id: incident_id.to_string(),
        severity,
        title: title.clone(),
        summary: summary.clone(),
        evidence: serde_json::json!({}),
        recommended_checks: Vec::new(),
        tags: mitre_ids.clone(),
        entities,
    })
}

/// Apply the Escalate branch of observation-verify (spec 028-b/c).
///
/// Writes the escalate label to the knowledge graph, writes the escalate
/// decision to the decisions JSONL (if a writer is configured), and reads
/// the 028-b feature flag to log intent for the future decide() call. The
/// extraction keeps the verify_observing_incidents match arm short and
/// makes the whole Escalate side effect unit-testable without constructing
/// a full AgentState.
fn apply_escalate(
    graph: &std::sync::Arc<std::sync::RwLock<KnowledgeGraph>>,
    decision_writer: Option<&mut crate::decisions::DecisionWriter>,
    escalate_to_decide: bool,
    incident_id: &str,
    primary_ip: Option<&str>,
    score: u8,
    reason: &str,
) {
    {
        let mut g = graph.write().unwrap();
        g.ingest_decision(
            incident_id,
            "escalate",
            primary_ip,
            0.8,
            &format!("obs-verify score {score}/100: {reason}"),
            true,
            chrono::Utc::now(),
        );
    }
    if let Some(writer) = decision_writer {
        write_escalate_decision(writer, incident_id, primary_ip, score, reason);
    }
    // Spec 028-b stub: the flag is read here so operators can already
    // toggle it in agent.toml, but the actual forwarding into Fase 4 is a
    // follow-up PR (needs provider + skill_executor threading + async
    // conversion).
    log_escalate_to_decide_intent(escalate_to_decide, incident_id, primary_ip);
}

/// Write an escalate decision to the decisions JSONL (spec 028-c).
///
/// Extracted so the Escalate match arm stays short and so the JSONL-write
/// path can be unit tested without spinning up a full AgentState. Failures
/// are logged at warn! level but never propagated; the knowledge graph
/// already carries the decision, so a JSONL write failure is a visibility
/// regression, not a correctness one.
fn write_escalate_decision(
    writer: &mut crate::decisions::DecisionWriter,
    incident_id: &str,
    primary_ip: Option<&str>,
    score: u8,
    reason: &str,
) {
    let entry = crate::decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: incident_id.to_string(),
        host: String::new(),
        ai_provider: "observation-verify".to_string(),
        action_type: "escalate".to_string(),
        target_ip: primary_ip.map(|s| s.to_string()),
        target_user: None,
        skill_id: None,
        confidence: 0.8,
        auto_executed: true,
        dry_run: false,
        reason: format!("obs-verify score {score}/100: {reason}"),
        estimated_threat: "medium".to_string(),
        execution_result: "pending-fase4".to_string(),
        prev_hash: None,
        decision_layer: Some("observation_verifier".to_string()),
    };
    if let Err(e) = writer.write(&entry) {
        tracing::warn!(
            incident_id = %incident_id,
            error = %e,
            "observation-verify: failed to write escalate decision to JSONL"
        );
    }
}

/// Log intent when the 028-b feature flag is on (spec 028-b stub).
///
/// Extracted from the Escalate match arm both for readability and so the
/// flag-read branch is trivially exercisable by a unit test. The flag
/// default is false, so in production this is a no-op until an operator
/// explicitly flips it in agent.toml.
fn log_escalate_to_decide_intent(
    escalate_to_decide: bool,
    incident_id: &str,
    primary_ip: Option<&str>,
) {
    if escalate_to_decide {
        tracing::info!(
            incident_id = %incident_id,
            target_ip = ?primary_ip,
            "observation-verify: spec 028-b flag on - decide() call pending (follow-up PR threading)"
        );
    }
}

/// AI batch verification for ambiguous items (spec 021 Phase C).
///
/// Takes the ambiguous items collected by `verify_observing_incidents`,
/// builds a prompt, sends to the AI provider, parses verdicts, and
/// applies dismiss/escalate decisions to the knowledge graph.
pub(crate) async fn ai_verify_ambiguous(
    items: Vec<AmbiguousItem>,
    cfg: &crate::config::AgentConfig,
    state: &mut AgentState,
) {
    if items.is_empty() {
        return;
    }

    // Spec 062 Phase 1 (no-orphan-leak): every ambiguous item MUST end with a
    // decision. The pre-062 code returned early here when AI verification was
    // off or no Classify provider existed, leaving the items UNDECIDED — they
    // then sat in the graph until orphan-recovery auto-dismissed them ~1h later
    // (prod 2026-05-30: 1637 such silent dismissals, the LLM never decided).
    // The deterministic fallback is `needs_review`: a visible, audited decision
    // that a human (or a later LLM pass) resolves, instead of a silent orphan.
    //
    // This `resolved` set tracks which incident_ids the LLM actually decided;
    // anything left unresolved at the end falls to `mark_needs_review`. That
    // makes the path correct WITH an LLM (LLM decides, no needs_review) and
    // WITHOUT one (everything → needs_review), per the LLM-optional invariant.
    let mut resolved: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Spec 029 PR-C.2: ai_verify_ambiguous uses the LLM chat() API to
    // group-score N OBSERVING incidents in a single prompt. Maps to
    // the Classify capability (structured input → short structured
    // label per incident). When verification is disabled or no Classify
    // provider is configured (the common no-LLM install), skip straight
    // to the needs_review fallback so nothing leaks.
    let ai_opt = if cfg.observation.ai_verification {
        state
            .ai_router
            .provider_for(crate::ai::Capability::Classify)
    } else {
        None
    };
    let Some(ai) = ai_opt else {
        mark_needs_review(&items, cfg, state, "no AI verifier configured");
        return;
    };

    // Build host profile from environment
    let host_profile = build_host_profile(state);

    // Process in batches
    let batch_size = cfg.observation.ai_batch_size.max(1);
    for chunk in items.chunks(batch_size) {
        let batch_items: Vec<observation_verify::AiBatchItem> = chunk
            .iter()
            .enumerate()
            .map(|(i, item)| observation_verify::AiBatchItem {
                index: i + 1,
                incident_id: item.incident_id.clone(),
                score: item.score,
                process: item
                    .evidence
                    .get("comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                event_summary: item
                    .evidence
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                binary_path: item
                    .evidence
                    .get("binary_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                parent_chain: item
                    .evidence
                    .get("ppid_comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                detector: item.detector.clone(),
            })
            .collect();

        let system_prompt = observation_verify::ai_verify_system_prompt(&host_profile);
        let user_message = observation_verify::ai_verify_user_message(&batch_items);

        let response = match ai.chat(&system_prompt, &user_message).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("observation-verify AI batch failed: {e:#}");
                continue;
            }
        };

        let verdicts = observation_verify::parse_ai_verdicts(&response);

        let mut ai_dismissed = 0u32;
        let mut ai_escalated = 0u32;

        for verdict in &verdicts {
            // Map 1-based index back to the chunk item
            let Some(item) = chunk.get(verdict.item_index.saturating_sub(1)) else {
                continue;
            };

            let mut graph = state.knowledge_graph.write().unwrap();
            match verdict.verdict {
                observation_verify::AiVerdictKind::Normal => {
                    graph.ingest_decision(
                        &item.incident_id,
                        "dismiss",
                        None,
                        0.9,
                        &format!("obs-verify AI: NORMAL — {}", verdict.reason),
                        true,
                        chrono::Utc::now(),
                    );
                    ai_dismissed += 1;
                    resolved.insert(item.incident_id.clone());
                }
                observation_verify::AiVerdictKind::Suspicious => {
                    graph.ingest_decision(
                        &item.incident_id,
                        "escalate",
                        None,
                        0.85,
                        &format!("obs-verify AI: SUSPICIOUS — {}", verdict.reason),
                        true,
                        chrono::Utc::now(),
                    );
                    ai_escalated += 1;
                    resolved.insert(item.incident_id.clone());
                }
            }
        }

        if ai_dismissed > 0 || ai_escalated > 0 {
            info!(
                ai_dismissed,
                ai_escalated,
                batch_size = chunk.len(),
                "observation-verify: AI batch complete"
            );
        }
    }

    // Spec 062 Phase 1: any ambiguous item the LLM did NOT decide (batch error,
    // missing verdict, unparseable response, index out of range) must not be
    // left undecided to leak into orphan-recovery. Fall it to needs_review.
    let unresolved = partition_unresolved(items, &resolved);
    if !unresolved.is_empty() {
        mark_needs_review(&unresolved, cfg, state, "AI verifier returned no verdict");
    }
}

/// Pure: the ambiguous items NOT in `resolved` (i.e. the LLM produced no
/// verdict for them). Extracted from `ai_verify_ambiguous` so the
/// "nothing leaks" partition is unit-testable without a live LLM.
fn partition_unresolved(
    items: Vec<AmbiguousItem>,
    resolved: &std::collections::HashSet<String>,
) -> Vec<AmbiguousItem> {
    items
        .into_iter()
        .filter(|it| !resolved.contains(&it.incident_id))
        .collect()
}

/// Pure: build the `needs_review` decision row for one ambiguous item.
/// Extracted so the row shape (action_type, awaiting_human, layer,
/// target_ip-from-evidence) is unit-testable without an AgentState or
/// a DecisionWriter.
fn needs_review_entry(
    item: &AmbiguousItem,
    why: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> crate::decisions::DecisionEntry {
    crate::decisions::DecisionEntry {
        ts: now,
        incident_id: item.incident_id.clone(),
        host: String::new(),
        ai_provider: "needs-review".to_string(),
        action_type: "needs_review".to_string(),
        target_ip: item
            .evidence
            .get("dst_ip")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        target_user: None,
        skill_id: None,
        confidence: 0.0,
        auto_executed: false,
        dry_run: false,
        reason: format!(
            "Ambiguous incident (behaviour score {}) needs human review: {why}. \
             No automated layer reached a confident decision.",
            item.score
        ),
        estimated_threat: "unknown".to_string(),
        execution_result: "awaiting_human".to_string(),
        prev_hash: None,
        decision_layer: Some("observation_verifier".to_string()),
    }
}

/// Spec 062 Phase 1 — record an explicit `needs_review` decision for ambiguous
/// incidents that no automated layer resolved.
///
/// This is the deterministic floor that makes the pipeline LLM-OPTIONAL: with
/// no LLM (or on any LLM failure) the incident gets a visible, audited
/// `needs_review` decision instead of silently rotting until orphan-recovery
/// dismisses it. Because the row IS a decision, `find_orphan_incidents`
/// (which joins on the absence of any decision) no longer treats it as an
/// orphan — the 1637/3-day silent-dismiss leak is closed at the source.
///
/// `needs_review` is terminal-pending: it carries `auto_executed = false`
/// (no action was taken) and `execution_result = "awaiting_human"`. Phase 2
/// adds the severity-gated timeout + notification clock on top of these rows.
fn mark_needs_review(
    items: &[AmbiguousItem],
    cfg: &crate::config::AgentConfig,
    state: &mut AgentState,
    why: &str,
) {
    let now = chrono::Utc::now();
    for item in items {
        // Graph label so the dashboard's graph-derived views update in place.
        {
            let mut graph = state.knowledge_graph.write().unwrap();
            graph.ingest_decision(
                &item.incident_id,
                "needs_review",
                None,
                0.0,
                &format!("needs human review (score {}): {why}", item.score),
                false,
                now,
            );
        }
        // Audited decision row (JSONL + SQLite mirror) so the incident is no
        // longer decisionless and the operator can see it pending.
        if let Some(writer) = state.decision_writer.as_mut() {
            let entry = needs_review_entry(item, why, now);
            if let Err(e) = writer.write(&entry) {
                warn!(
                    incident_id = %item.incident_id,
                    error = %e,
                    "needs_review: failed to write decision row"
                );
            }
        }

        // Spec 062 Phase 3: notify the operator on Telegram with inline
        // Block / Ignore / Dismiss buttons (gated by [learning]
        // needs_review_notify, default false — nothing auto-enabled in prod).
        // The tap routes back via the `__review__:` sentinel in bot_actions.
        // Fire-and-forget: a notify failure must not block the tick.
        if cfg.learning.needs_review_notify {
            if let (Some(tg), Some(store)) =
                (state.telegram_client.clone(), state.sqlite_store.clone())
            {
                match store.get_incident(&item.incident_id) {
                    Ok(Some(incident)) => {
                        tokio::spawn(async move {
                            if let Err(e) = tg.send_needs_review_request(&incident).await {
                                warn!(error = %e, "needs_review: telegram notify failed");
                            }
                        });
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(
                            incident_id = %item.incident_id,
                            error = %e,
                            "needs_review: could not load incident for telegram notify"
                        );
                    }
                }
            }
        }
    }
    info!(
        count = items.len(),
        why, "observation-verify: marked ambiguous incidents needs_review (no silent orphan)"
    );
}

/// Build a host profile string from the agent's environment profile.
fn build_host_profile(state: &AgentState) -> String {
    build_host_profile_from_env(&state.environment_profile)
}

/// Pure helper: build host profile string from an EnvironmentProfile.
fn build_host_profile_from_env(env: &crate::environment_profile::EnvironmentProfile) -> String {
    let services = if env.services.is_empty() {
        "unknown".to_string()
    } else {
        env.services.join(", ")
    };
    format!(
        "Platform: {} ({})\nServices: {}",
        env.platform, env.provider, services,
    )
}

/// Store the score breakdown for dashboard display (Phase D stub).
fn store_breakdown(_breakdown: &ScoreBreakdown) {
    // Phase D will implement dashboard display of score breakdowns.
    // For now, the breakdown is included in the decision reason string.
}

// ── chrono import for Local time ────────────────────────────────────────
use chrono::Timelike;

#[cfg(test)]
mod tests {
    use super::*;

    // ── Spec 062 Phase 5: needs_human veto ──────────────────────────────

    fn p5_decision(action: crate::ai::AiAction, confidence: f32) -> crate::ai::AiDecision {
        crate::ai::AiDecision {
            action,
            confidence,
            auto_execute: true,
            reason: "test rationale".to_string(),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        }
    }

    #[test]
    fn needs_human_vetoes_low_confidence_high_impact() {
        use crate::ai::AiAction;
        assert!(llm_escalation_needs_human(
            &AiAction::BlockIp {
                ip: "203.0.113.7".into(),
                skill_id: "block-ip-ufw".into(),
            },
            0.60,
            0.75
        ));
        assert!(llm_escalation_needs_human(
            &AiAction::KillProcess {
                user: "mallory".into(),
                duration_secs: 0,
            },
            0.0,
            0.75
        ));
        assert!(llm_escalation_needs_human(
            &AiAction::SuspendUserSudo {
                user: "mallory".into(),
                duration_secs: 3600,
            },
            0.74,
            0.75
        ));
        assert!(llm_escalation_needs_human(
            &AiAction::BlockContainer {
                container_id: "abc".into(),
                action: "pause".into(),
            },
            0.10,
            0.75
        ));
        assert!(llm_escalation_needs_human(
            &AiAction::KillChainResponse {
                reason: "c2".into(),
            },
            0.50,
            0.75
        ));
    }

    #[test]
    fn needs_human_passes_confident_high_impact() {
        use crate::ai::AiAction;
        assert!(!llm_escalation_needs_human(
            &AiAction::BlockIp {
                ip: "203.0.113.7".into(),
                skill_id: "block-ip-ufw".into(),
            },
            0.75,
            0.75
        ));
        assert!(!llm_escalation_needs_human(
            &AiAction::BlockIp {
                ip: "203.0.113.7".into(),
                skill_id: "block-ip-ufw".into(),
            },
            0.99,
            0.75
        ));
    }

    #[test]
    fn needs_human_never_vetoes_soft_or_low_blast_actions() {
        use crate::ai::AiAction;
        let soft = [
            AiAction::Monitor {
                ip: "203.0.113.7".into(),
            },
            AiAction::Dismiss {
                reason: "noise".into(),
            },
            AiAction::Ignore {
                reason: "noise".into(),
            },
            AiAction::Honeypot {
                ip: "203.0.113.7".into(),
            },
            AiAction::RequestConfirmation {
                summary: "?".into(),
            },
        ];
        for action in soft {
            assert!(
                !llm_escalation_needs_human(&action, 0.0, 0.75),
                "{} must never trip the needs_human veto",
                action.name()
            );
        }
    }

    #[test]
    fn escalation_needs_review_entry_has_lifecycle_fields() {
        use crate::ai::AiAction;
        use innerwarden_core::entities::EntityRef;
        let inc = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "host-1".into(),
            incident_id: "imds_ssrf:203.0.113.7:now".into(),
            severity: innerwarden_core::event::Severity::Medium,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.7")],
        };
        let decision = p5_decision(
            AiAction::BlockIp {
                ip: "203.0.113.7".into(),
                skill_id: "block-ip-ufw".into(),
            },
            0.60,
        );
        let entry = escalation_needs_review_entry(
            &inc,
            "azure_openai",
            &decision,
            0.75,
            chrono::Utc::now(),
        );
        assert_eq!(entry.action_type, "needs_review");
        assert_eq!(entry.ai_provider, "needs-review");
        assert!(!entry.auto_executed);
        assert_eq!(entry.execution_result, "awaiting_human");
        assert_eq!(
            entry.decision_layer.as_deref(),
            Some("observation_verifier")
        );
        assert_eq!(entry.target_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(entry.host, "host-1");
        assert!(entry.reason.contains("block_ip"));
        assert!(entry.reason.contains("azure_openai"));
        assert!(entry.reason.contains("0.75"));
    }

    #[test]
    fn escalation_needs_review_entry_falls_back_to_incident_ip_for_non_ip_action() {
        use crate::ai::AiAction;
        use innerwarden_core::entities::EntityRef;
        let inc = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "h".into(),
            incident_id: "x:1".into(),
            severity: innerwarden_core::event::Severity::Medium,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("198.51.100.5")],
        };
        let decision = p5_decision(
            AiAction::KillProcess {
                user: "mallory".into(),
                duration_secs: 0,
            },
            0.40,
        );
        let entry = escalation_needs_review_entry(
            &inc,
            "azure_openai",
            &decision,
            0.75,
            chrono::Utc::now(),
        );
        assert_eq!(entry.target_ip.as_deref(), Some("198.51.100.5"));
        assert!(entry.reason.contains("kill_process"));
    }

    #[test]
    fn ambiguous_item_captures_fields() {
        let item = AmbiguousItem {
            incident_id: "test-123".to_string(),
            score: 55,
            evidence: serde_json::json!({"detector": "data_exfiltration"}),
            detector: "data_exfiltration".to_string(),
            title: "Data Exfiltration Detected".to_string(),
        };
        assert_eq!(item.score, 55);
        assert_eq!(item.incident_id, "test-123");
    }

    #[test]
    fn verification_result_serializes() {
        let r = VerificationResult::Dismiss {
            score: 85,
            reason: "package managed binary, trusted parent chain".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("Dismiss"));
        assert!(json.contains("85"));
    }

    #[test]
    fn score_breakdown_default() {
        let bd = ScoreBreakdown::default();
        assert_eq!(bd.total, 0);
        assert_eq!(bd.installation, 0);
    }

    #[test]
    fn find_process_comm_returns_none_on_empty_graph() {
        let graph = KnowledgeGraph::new();
        assert_eq!(find_process_comm_by_pid(&graph, 1234), None);
    }

    #[test]
    fn collect_undecided_on_empty_graph() {
        let graph = KnowledgeGraph::new();
        let result = collect_undecided_incidents(&graph);
        assert!(result.is_empty());
    }

    // Spec 028-c: write_escalate_decision must land a line in the decisions
    // JSONL shaped so the dashboard's determine_outcome can bucket the IP
    // into "escalated" → "needs_attention".
    #[test]
    fn write_escalate_decision_emits_jsonl_line() {
        let tmp = tempfile::tempdir().unwrap();
        let mut writer = crate::decisions::DecisionWriter::new(tmp.path()).unwrap();

        write_escalate_decision(
            &mut writer,
            "test-incident-1",
            Some("203.0.113.42"),
            55,
            "masscan fingerprint",
        );
        drop(writer); // flush buffer

        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let mut found = false;
        for entry in std::fs::read_dir(tmp.path()).unwrap() {
            let path = entry.unwrap().path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(&today))
            {
                let content = std::fs::read_to_string(&path).unwrap();
                assert!(content.contains("\"action_type\":\"escalate\""));
                assert!(content.contains("\"target_ip\":\"203.0.113.42\""));
                assert!(content.contains("\"ai_provider\":\"observation-verify\""));
                assert!(content.contains("\"execution_result\":\"pending-fase4\""));
                assert!(content.contains("masscan fingerprint"));
                assert!(content.contains("55/100"));
                found = true;
            }
        }
        assert!(found, "decisions JSONL file must exist for today");
    }

    // Spec 028-c: target_ip is optional (incident may lack an IP entity).
    // The writer still produces a valid line with target_ip = null.
    #[test]
    fn write_escalate_decision_handles_missing_ip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut writer = crate::decisions::DecisionWriter::new(tmp.path()).unwrap();

        write_escalate_decision(&mut writer, "test-incident-2", None, 45, "no ip");
        drop(writer);

        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        for entry in std::fs::read_dir(tmp.path()).unwrap() {
            let path = entry.unwrap().path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains(&today))
            {
                let content = std::fs::read_to_string(&path).unwrap();
                assert!(content.contains("\"target_ip\":null"));
                return;
            }
        }
        panic!("decisions JSONL file must exist for today");
    }

    // Spec 028-b stub: the intent-log branch reads the flag without side
    // effects. Flag-off and flag-on are both tested here for coverage; the
    // real assertion is that the helper does not panic and compiles in both
    // shapes.
    #[test]
    fn log_escalate_to_decide_intent_is_side_effect_free() {
        log_escalate_to_decide_intent(false, "id-off", None);
        log_escalate_to_decide_intent(true, "id-on", Some("198.51.100.1"));
        log_escalate_to_decide_intent(true, "id-on-no-ip", None);
    }

    // Spec 028-c: apply_escalate writes to graph + JSONL in one call. The
    // graph must be seeded with the incident node first because
    // ingest_decision silently no-ops when find_by_incident returns None.
    // This test exercises the whole Escalate side effect directly with a
    // seeded graph and DecisionWriter, bypassing the behaviour_score layer
    // that is tested elsewhere.
    #[test]
    fn apply_escalate_writes_graph_and_jsonl() {
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;

        let tmp = tempfile::tempdir().unwrap();
        let graph = std::sync::Arc::new(std::sync::RwLock::new(KnowledgeGraph::new()));
        let incident = Incident {
            ts: chrono::Utc::now(),
            host: "h".into(),
            incident_id: "proto_anomaly:SshVersionAnomaly:198.51.100.77:apply-escalate-test".into(),
            severity: Severity::Medium,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("198.51.100.77".to_string())],
        };
        {
            let mut g = graph.write().unwrap();
            g.ingest_incident(&incident);
        }
        let mut writer = crate::decisions::DecisionWriter::new(tmp.path()).unwrap();

        apply_escalate(
            &graph,
            Some(&mut writer),
            false,
            &incident.incident_id,
            Some("198.51.100.77"),
            35,
            "low confidence signal",
        );
        drop(writer);

        // Graph side: the incident node now carries decision="escalate".
        {
            let g = graph.read().unwrap();
            let mut saw_escalate = false;
            for &id in &g.nodes_of_type(NodeType::Incident) {
                if let Some(Node::Incident {
                    decision: Some(d), ..
                }) = g.get_node(id)
                {
                    if d == "escalate" {
                        saw_escalate = true;
                    }
                }
            }
            assert!(saw_escalate, "incident node must carry decision=escalate");
        }

        // JSONL side: one line shaped like a dashboard-consumable entry.
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let mut saw = false;
        for entry in std::fs::read_dir(tmp.path()).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.contains(&today) && name.ends_with(".jsonl") {
                let content = std::fs::read_to_string(&path).unwrap();
                if content.contains("\"action_type\":\"escalate\"")
                    && content.contains("\"target_ip\":\"198.51.100.77\"")
                    && content.contains("\"ai_provider\":\"observation-verify\"")
                    && content.contains("low confidence signal")
                {
                    saw = true;
                    break;
                }
            }
        }
        assert!(saw, "apply_escalate must write the escalate line to JSONL");
    }

    // Spec 028-c: apply_escalate tolerates a missing writer and a missing
    // incident in the graph (ingest_decision no-ops). Assertion: no panic.
    #[test]
    fn apply_escalate_tolerates_missing_writer_and_node() {
        let graph = std::sync::Arc::new(std::sync::RwLock::new(KnowledgeGraph::new()));
        apply_escalate(&graph, None, false, "id-no-writer", None, 20, "r");
    }

    // Spec 028-b full: promote_escalated_to_decision is a no-op when the
    // agent has no AI provider configured (the graph still carries the
    // "escalate" label from apply_escalate).
    #[tokio::test]
    async fn promote_is_noop_without_provider() {
        use crate::config::AgentConfig;
        use crate::tests::triage_test_state;
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;

        let tmp = tempfile::tempdir().unwrap();
        let mut state = triage_test_state(tmp.path());
        assert!(
            state.ai_router.is_disabled(),
            "triage_test_state baseline has a disabled router"
        );
        let cfg = AgentConfig::default();

        let incident = Incident {
            ts: chrono::Utc::now(),
            host: "h".into(),
            incident_id: "proto_anomaly:SshVersionAnomaly:198.51.100.42:promote-no-provider".into(),
            severity: Severity::Medium,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("198.51.100.42".to_string())],
        };
        {
            let mut g = state.knowledge_graph.write().unwrap();
            g.ingest_incident(&incident);
        }

        promote_escalated_to_decision(
            &cfg,
            &mut state,
            tmp.path(),
            &incident.incident_id,
            "proto_anomaly",
            "t",
            Some("198.51.100.42"),
        )
        .await;

        // No decision should have been written to the graph by the
        // promote path because no provider was available.
        let g = state.knowledge_graph.read().unwrap();
        let node = g.find_by_incident(&incident.incident_id).and_then(|nid| {
            if let Some(Node::Incident { decision, .. }) = g.get_node(nid) {
                decision.clone()
            } else {
                None
            }
        });
        assert!(
            node.is_none(),
            "without provider, promote must not touch the incident decision field"
        );
    }

    // Spec 028-b full: promote_escalated_to_decision calls the stub
    // provider and writes the resulting decision to the graph + JSONL.
    #[tokio::test]
    async fn promote_with_stub_provider_writes_decision() {
        use crate::config::{AgentConfig, AiConfig};
        use crate::tests::triage_test_state;
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let mut state = triage_test_state(tmp.path());
        // Build the stub provider via the public factory (stub module is
        // private) with provider="stub" which bypasses all network setup.
        let ai_cfg = AiConfig {
            enabled: true,
            provider: "stub".into(),
            ..Default::default()
        };
        let provider = crate::ai::build_provider(&ai_cfg, "ufw").expect("stub provider builds");
        let provider_arc: Arc<dyn crate::ai::AiProvider> = Arc::from(provider);
        state.ai_router =
            crate::ai::AiRouter::new(Some(Arc::clone(&provider_arc)), Some(provider_arc))
                .expect("router with stub provider");
        let cfg = AgentConfig::default();

        // ssh_bruteforce + public IP: stub returns BlockIp.
        let incident = Incident {
            ts: chrono::Utc::now(),
            host: "h".into(),
            incident_id: "ssh_bruteforce:198.51.100.77:promote-test".into(),
            severity: Severity::High,
            title: "SSH brute force".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("198.51.100.77".to_string())],
        };
        {
            let mut g = state.knowledge_graph.write().unwrap();
            g.ingest_incident(&incident);
        }

        promote_escalated_to_decision(
            &cfg,
            &mut state,
            tmp.path(),
            &incident.incident_id,
            "ssh_bruteforce",
            "SSH brute force",
            Some("198.51.100.77"),
        )
        .await;

        // Graph should show block_ip decision now (stub returns BlockIp
        // for ssh_bruteforce detector with an IP entity).
        {
            let g = state.knowledge_graph.read().unwrap();
            let nid = g.find_by_incident(&incident.incident_id).unwrap();
            if let Some(Node::Incident {
                decision: Some(d), ..
            }) = g.get_node(nid)
            {
                assert_eq!(d, "block_ip", "stub decides block_ip on ssh_bruteforce");
            } else {
                panic!("incident node missing decision");
            }
        }

        // Drop state so decision_writer flushes.
        drop(state);

        // JSONL should also contain the block_ip decision.
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let mut saw_block = false;
        for entry in std::fs::read_dir(tmp.path()).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.contains(&today) && name.ends_with(".jsonl") {
                let content = std::fs::read_to_string(&path).unwrap();
                if content.contains("\"action_type\":\"block_ip\"")
                    && content.contains("\"target_ip\":\"198.51.100.77\"")
                {
                    saw_block = true;
                    break;
                }
            }
        }
        assert!(
            saw_block,
            "block_ip decision must appear in decisions JSONL"
        );
    }

    // Spec 028-b full: reconstruct_incident_from_graph covers all entity
    // kinds (Ip, User, Container, File) so downstream helpers get back
    // exactly what they would have received from the fast loop.
    #[test]
    fn reconstruct_incident_covers_all_entity_kinds() {
        use crate::tests::triage_test_state;
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;

        let tmp = tempfile::tempdir().unwrap();
        let state = triage_test_state(tmp.path());
        let incident = Incident {
            ts: chrono::Utc::now(),
            host: "h".into(),
            incident_id: "cross_layer_chain:multi-entity:test".into(),
            severity: Severity::High,
            title: "cross layer".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["T1055".into()],
            entities: vec![
                EntityRef::ip("203.0.113.9".to_string()),
                EntityRef {
                    r#type: innerwarden_core::entities::EntityType::User,
                    value: "attacker".into(),
                },
                EntityRef {
                    r#type: innerwarden_core::entities::EntityType::Container,
                    value: "container-xyz".into(),
                },
                EntityRef {
                    r#type: innerwarden_core::entities::EntityType::Path,
                    value: "/etc/passwd".into(),
                },
            ],
        };
        {
            let mut g = state.knowledge_graph.write().unwrap();
            g.ingest_incident(&incident);
        }

        let reconstructed = reconstruct_incident_from_graph(&state, &incident.incident_id).unwrap();

        assert_eq!(reconstructed.incident_id, incident.incident_id);
        assert!(matches!(reconstructed.severity, Severity::High));
        assert!(reconstructed.tags.contains(&"T1055".to_string()));

        let kinds: std::collections::HashSet<_> = reconstructed
            .entities
            .iter()
            .map(|e| format!("{:?}", e.r#type))
            .collect();
        // Ip + User + Container + Path all survive the graph round-trip.
        assert!(kinds.contains("Ip"));
        assert!(kinds.contains("User"));
        assert!(kinds.contains("Container"));
        assert!(kinds.contains("Path"));
    }

    // Spec 028-b full: severity strings in the graph map back to enum
    // variants correctly, with Info as the fallback for unknown strings.
    #[test]
    fn reconstruct_incident_severity_mapping() {
        use crate::tests::triage_test_state;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;

        let tmp = tempfile::tempdir().unwrap();
        let state = triage_test_state(tmp.path());

        for (label, expected) in [
            ("critical-test", Severity::Critical),
            ("high-test", Severity::High),
            ("medium-test", Severity::Medium),
            ("low-test", Severity::Low),
        ] {
            let incident = Incident {
                ts: chrono::Utc::now(),
                host: "h".into(),
                incident_id: format!("detector:{label}"),
                severity: expected.clone(),
                title: "t".into(),
                summary: "s".into(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            };
            {
                let mut g = state.knowledge_graph.write().unwrap();
                g.ingest_incident(&incident);
            }
            let r = reconstruct_incident_from_graph(&state, &incident.incident_id).unwrap();
            assert_eq!(
                format!("{:?}", r.severity),
                format!("{:?}", expected),
                "severity round-trip {label}"
            );
        }
    }

    // Spec 028-b full: reconstruct returns None when the incident id is
    // not in the graph.
    #[test]
    fn reconstruct_incident_missing_returns_none() {
        use crate::tests::triage_test_state;
        let tmp = tempfile::tempdir().unwrap();
        let state = triage_test_state(tmp.path());
        assert!(reconstruct_incident_from_graph(&state, "does-not-exist").is_none());
    }

    // Spec 028-b full: when the provider's decide() errors, promote logs
    // a warning and returns without mutating the graph. The pre-written
    // "escalate" label from apply_escalate is left intact (though this
    // test checks only that promote itself does not write a decision).
    #[tokio::test]
    async fn promote_tolerates_provider_error() {
        use crate::ai::{AiDecision, AiProvider, DecisionContext};
        use crate::config::AgentConfig;
        use crate::tests::triage_test_state;
        use anyhow::Result;
        use async_trait::async_trait;
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;
        use std::sync::Arc;

        struct ErroringProvider;
        #[async_trait]
        impl AiProvider for ErroringProvider {
            fn name(&self) -> &'static str {
                "erroring"
            }
            async fn decide(&self, _ctx: &DecisionContext<'_>) -> Result<AiDecision> {
                anyhow::bail!("forced error for test")
            }
            async fn chat(&self, _s: &str, _u: &str) -> Result<String> {
                anyhow::bail!("unused")
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let mut state = triage_test_state(tmp.path());
        let err_arc: Arc<dyn crate::ai::AiProvider> = Arc::new(ErroringProvider);
        state.ai_router = crate::ai::AiRouter::new(Some(Arc::clone(&err_arc)), Some(err_arc))
            .expect("router with erroring provider");

        let incident = Incident {
            ts: chrono::Utc::now(),
            host: "h".into(),
            incident_id: "proto_anomaly:SshVersionAnomaly:198.51.100.55:error-path".into(),
            severity: Severity::Medium,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("198.51.100.55".to_string())],
        };
        {
            let mut g = state.knowledge_graph.write().unwrap();
            g.ingest_incident(&incident);
        }

        let cfg = AgentConfig::default();
        promote_escalated_to_decision(
            &cfg,
            &mut state,
            tmp.path(),
            &incident.incident_id,
            "proto_anomaly",
            "t",
            Some("198.51.100.55"),
        )
        .await;

        // Graph should not have a decision written by the promote path —
        // it must not panic and must not mask the provider failure.
        let g = state.knowledge_graph.read().unwrap();
        let nid = g.find_by_incident(&incident.incident_id).unwrap();
        if let Some(Node::Incident { decision, .. }) = g.get_node(nid) {
            assert!(
                decision.is_none(),
                "provider error must leave decision field untouched"
            );
        }
    }

    // Spec 028-b full: a detector not recognised by the stub provider
    // (anything outside ssh_bruteforce / port_scan / honeypot / shield)
    // returns Ignore. The promote path must still write the ignore
    // decision so the audit trail shows the AI was consulted.
    #[tokio::test]
    async fn promote_ignore_decision_still_audited() {
        use crate::config::{AgentConfig, AiConfig};
        use crate::tests::triage_test_state;
        use innerwarden_core::entities::EntityRef;
        use innerwarden_core::event::Severity;
        use innerwarden_core::incident::Incident;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let mut state = triage_test_state(tmp.path());
        let ai_cfg = AiConfig {
            enabled: true,
            provider: "stub".into(),
            ..Default::default()
        };
        let provider = crate::ai::build_provider(&ai_cfg, "ufw").expect("stub builds");
        let provider_arc: Arc<dyn crate::ai::AiProvider> = Arc::from(provider);
        state.ai_router =
            crate::ai::AiRouter::new(Some(Arc::clone(&provider_arc)), Some(provider_arc))
                .expect("router with stub");
        let cfg = AgentConfig::default();

        let incident = Incident {
            ts: chrono::Utc::now(),
            host: "h".into(),
            incident_id: "unknown_detector:198.51.100.66:ignore-path".into(),
            severity: Severity::Medium,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("198.51.100.66".to_string())],
        };
        {
            let mut g = state.knowledge_graph.write().unwrap();
            g.ingest_incident(&incident);
        }

        promote_escalated_to_decision(
            &cfg,
            &mut state,
            tmp.path(),
            &incident.incident_id,
            "unknown_detector",
            "t",
            Some("198.51.100.66"),
        )
        .await;

        // Graph decision should now be "ignore".
        {
            let g = state.knowledge_graph.read().unwrap();
            let nid = g.find_by_incident(&incident.incident_id).unwrap();
            if let Some(Node::Incident {
                decision: Some(d), ..
            }) = g.get_node(nid)
            {
                assert_eq!(d, "ignore");
            } else {
                panic!("incident node missing decision");
            }
        }

        drop(state);
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let mut saw = false;
        for entry in std::fs::read_dir(tmp.path()).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.contains(&today) && name.ends_with(".jsonl") {
                let content = std::fs::read_to_string(&path).unwrap();
                if content.contains("\"action_type\":\"ignore\"")
                    && content.contains("198.51.100.66")
                {
                    saw = true;
                    break;
                }
            }
        }
        assert!(saw, "ignore decision must appear in decisions JSONL");
    }

    // Spec 028-b stub: flag on/off must produce the same persistent side
    // effects. Running apply_escalate twice with identical inputs apart
    // from the flag must yield identical JSONL output and graph state.
    #[test]
    fn apply_escalate_flag_toggle_is_observational() {
        let tmp = tempfile::tempdir().unwrap();
        let graph = std::sync::Arc::new(std::sync::RwLock::new(KnowledgeGraph::new()));
        let mut writer = crate::decisions::DecisionWriter::new(tmp.path()).unwrap();

        apply_escalate(
            &graph,
            Some(&mut writer),
            false,
            "flag-test-off",
            Some("198.51.100.88"),
            30,
            "reason",
        );
        apply_escalate(
            &graph,
            Some(&mut writer),
            true,
            "flag-test-on",
            Some("198.51.100.88"),
            30,
            "reason",
        );
        drop(writer);

        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let mut lines_off = 0;
        let mut lines_on = 0;
        for entry in std::fs::read_dir(tmp.path()).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.contains(&today) && name.ends_with(".jsonl") {
                let content = std::fs::read_to_string(&path).unwrap();
                for line in content.lines() {
                    if line.contains("flag-test-off") {
                        lines_off += 1;
                    }
                    if line.contains("flag-test-on") {
                        lines_on += 1;
                    }
                }
            }
        }
        assert_eq!(lines_off, 1, "flag=false path must emit exactly one line");
        assert_eq!(lines_on, 1, "flag=true path must emit exactly one line");
    }

    #[test]
    fn enrich_evidence_from_ip_node() {
        let mut evidence = serde_json::json!({});
        let node = Node::Ip {
            addr: "10.0.0.1".to_string(),
            is_internal: true,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            attempted_usernames: vec![],
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        assert_eq!(evidence["dst_ip"], "10.0.0.1");
    }

    #[test]
    fn enrich_evidence_from_port_node() {
        let mut evidence = serde_json::json!({});
        let node = Node::Port {
            number: 443,
            protocol: "tcp".to_string(),
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        assert_eq!(evidence["dst_port"], 443);
        assert_eq!(evidence["protocol"], "tcp");
    }

    #[test]
    fn enrich_evidence_from_process_node() {
        let mut evidence = serde_json::json!({});
        let node = Node::Process {
            pid: 1234,
            ppid: 1,
            comm: "nginx".to_string(),
            exe: Some("/usr/sbin/nginx".to_string()),
            uid: 0,
            container_id: None,
            start_ts: chrono::Utc::now(),
            exit_ts: None,
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        assert_eq!(evidence["comm"], "nginx");
        assert_eq!(evidence["binary_path"], "/usr/sbin/nginx");
    }

    #[test]
    fn enrich_evidence_from_file_node() {
        let mut evidence = serde_json::json!({});
        let node = Node::File {
            path: "/etc/shadow".to_string(),
            sha256: None,
            size: None,
            entropy: None,
            is_sensitive: true,
            yara_matches: vec![],
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        assert_eq!(evidence["path"], "/etc/shadow");
    }

    // ── find_process_comm_by_pid: 3 tests ───────────────────────────────

    #[test]
    fn find_process_comm_finds_existing_pid() {
        let mut graph = KnowledgeGraph::new();
        graph.add_node(Node::Process {
            pid: 42,
            ppid: 1,
            comm: "systemd".to_string(),
            exe: Some("/usr/lib/systemd/systemd".to_string()),
            uid: 0,
            container_id: None,
            start_ts: chrono::Utc::now(),
            exit_ts: None,
        });
        assert_eq!(
            find_process_comm_by_pid(&graph, 42),
            Some("systemd".to_string())
        );
    }

    #[test]
    fn find_process_comm_returns_none_for_missing_pid() {
        let mut graph = KnowledgeGraph::new();
        graph.add_node(Node::Process {
            pid: 42,
            ppid: 1,
            comm: "systemd".to_string(),
            exe: None,
            uid: 0,
            container_id: None,
            start_ts: chrono::Utc::now(),
            exit_ts: None,
        });
        assert_eq!(find_process_comm_by_pid(&graph, 999), None);
    }

    // ── collect_undecided_incidents: 3 tests ────────────────────────────

    #[test]
    fn collect_undecided_skips_decided_incidents() {
        let mut graph = KnowledgeGraph::new();
        let inc = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            incident_id: "inc-1".to_string(),
            severity: innerwarden_core::event::Severity::Medium,
            title: "Test".to_string(),
            summary: "Test summary".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        };
        graph.ingest_incident(&inc);
        // Mark as decided
        graph.ingest_decision(
            "inc-1",
            "dismiss",
            None,
            1.0,
            "test",
            true,
            chrono::Utc::now(),
        );
        let result = collect_undecided_incidents(&graph);
        assert!(result.is_empty(), "decided incident should be skipped");
    }

    #[test]
    fn collect_undecided_returns_undecided_incidents() {
        let mut graph = KnowledgeGraph::new();
        let inc = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            incident_id: "inc-2".to_string(),
            severity: innerwarden_core::event::Severity::Medium,
            title: "Data Exfil".to_string(),
            summary: "Suspicious outbound".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["data_exfiltration".to_string()],
            entities: vec![],
        };
        graph.ingest_incident(&inc);
        let result = collect_undecided_incidents(&graph);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "inc-2");
    }

    #[test]
    fn collect_undecided_includes_incident_metadata() {
        let mut graph = KnowledgeGraph::new();
        let inc = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            incident_id: "inc-3".to_string(),
            severity: innerwarden_core::event::Severity::High,
            title: "Data Exfiltration".to_string(),
            summary: "Large outbound transfer".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["data_exfiltration".to_string()],
            entities: vec![],
        };
        graph.ingest_incident(&inc);
        let result = collect_undecided_incidents(&graph);
        assert_eq!(result.len(), 1);
        // Check the evidence includes detector and severity from node
        assert_eq!(result[0].2, "Data Exfiltration"); // title
        assert!(result[0].3["severity"].is_string()); // severity present
    }

    // ── enrich_evidence_from_node: edge cases ───────────────────────────

    #[test]
    fn enrich_evidence_process_no_exe() {
        let mut evidence = serde_json::json!({});
        let node = Node::Process {
            pid: 1,
            ppid: 0,
            comm: "init".to_string(),
            exe: None,
            uid: 0,
            container_id: None,
            start_ts: chrono::Utc::now(),
            exit_ts: None,
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        assert_eq!(evidence["comm"], "init");
        assert!(evidence.get("binary_path").is_none());
    }

    #[test]
    fn enrich_evidence_domain_node_ignored() {
        let mut evidence = serde_json::json!({});
        let node = Node::Domain {
            name: "example.com".to_string(),
            datasets: vec![],
            is_dga: None,
            entropy: None,
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        // Domain nodes are not enriched (matched by _ => {})
        assert!(evidence.as_object().unwrap().is_empty());
    }

    #[test]
    fn enrich_evidence_preserves_existing_fields() {
        let mut evidence = serde_json::json!({"existing_key": "existing_value"});
        let node = Node::Ip {
            addr: "1.2.3.4".to_string(),
            is_internal: false,
            datasets: vec![],
            risk_score: 50,
            is_tor: false,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            attempted_usernames: vec![],
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        assert_eq!(evidence["existing_key"], "existing_value");
        assert_eq!(evidence["dst_ip"], "1.2.3.4");
    }

    // ── build_host_profile_from_env: 3 tests ──────────────────────────

    #[test]
    fn host_profile_with_services() {
        use crate::environment_profile::EnvironmentProfile;
        let env = EnvironmentProfile {
            platform: "cloud_vps".into(),
            provider: "oracle".into(),
            services: vec!["nginx".into(), "postgres".into()],
            ..Default::default()
        };
        let profile = build_host_profile_from_env(&env);
        assert!(profile.contains("cloud_vps"));
        assert!(profile.contains("oracle"));
        assert!(profile.contains("nginx"));
        assert!(profile.contains("postgres"));
    }

    #[test]
    fn host_profile_no_services() {
        use crate::environment_profile::EnvironmentProfile;
        let env = EnvironmentProfile::default();
        let profile = build_host_profile_from_env(&env);
        assert!(profile.contains("unknown"));
    }

    #[test]
    fn host_profile_bare_metal() {
        use crate::environment_profile::EnvironmentProfile;
        let env = EnvironmentProfile {
            platform: "bare_metal".into(),
            provider: "none".into(),
            services: vec!["sshd".into()],
            ..Default::default()
        };
        let profile = build_host_profile_from_env(&env);
        assert!(profile.contains("bare_metal"));
        assert!(profile.contains("sshd"));
    }

    // Spec 029 PR-C.2: ai_verify_ambiguous now resolves the provider
    // via `state.ai_router.provider_for(Classify)` instead of reading
    // the legacy `state.ai_provider` field. When the router has no
    // Classify-capable provider (rules-only mode or classifier-only
    // with the classifier declining Classify), the function must
    // return early without panicking.
    #[tokio::test]
    async fn ai_verify_ambiguous_writes_needs_review_when_router_has_no_classify_provider() {
        use crate::config::AgentConfig;
        use crate::tests::triage_test_state;

        let tmp = tempfile::tempdir().unwrap();
        let mut state = triage_test_state(tmp.path());
        // triage_test_state leaves state.ai_router as AiRouter::disabled();
        // the router yields None for every capability.
        assert!(state
            .ai_router
            .provider_for(crate::ai::Capability::Classify)
            .is_none());

        let mut cfg = AgentConfig::default();
        cfg.observation.ai_verification = true;

        let items = vec![AmbiguousItem {
            incident_id: "proto_anomaly:SshVersionAnomaly:198.51.100.99:t".into(),
            score: 55,
            evidence: serde_json::json!({"dst_ip": "198.51.100.99"}),
            detector: "proto_anomaly".into(),
            title: "t".into(),
        }];

        // Spec 062 Phase 1: with no Classify provider the item must NOT be
        // left undecided (the pre-062 silent leak) — it must get an explicit
        // needs_review decision row in the audit trail.
        ai_verify_ambiguous(items, &cfg, &mut state).await;

        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let jsonl = tmp.path().join(format!("decisions-{today}.jsonl"));
        let body = std::fs::read_to_string(&jsonl).unwrap_or_default();
        assert!(
            body.contains("\"action_type\":\"needs_review\"") && body.contains("198.51.100.99"),
            "no-Classify-provider must produce a needs_review decision, got: {body}"
        );
    }

    #[tokio::test]
    async fn ai_verify_ambiguous_empty_items_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(tmp.path());
        let cfg = crate::config::AgentConfig::default();
        ai_verify_ambiguous(Vec::new(), &cfg, &mut state).await;
        // No panic = pass.
    }

    #[tokio::test]
    async fn ai_verify_ambiguous_off_verification_still_floors_to_needs_review() {
        // ai_verification = false must NOT mean "silently drop"; the
        // deterministic floor (needs_review) still applies so nothing leaks.
        let tmp = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(tmp.path());
        let items = vec![AmbiguousItem {
            incident_id: "obs-disabled-1".into(),
            score: 55,
            evidence: serde_json::json!({"detector": "test"}),
            detector: "test".into(),
            title: "t".into(),
        }];
        let mut cfg = crate::config::AgentConfig::default();
        cfg.observation.ai_verification = false;
        ai_verify_ambiguous(items, &cfg, &mut state).await;

        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let jsonl = tmp.path().join(format!("decisions-{today}.jsonl"));
        let body = std::fs::read_to_string(&jsonl).unwrap_or_default();
        assert!(
            body.contains("needs_review") && body.contains("obs-disabled-1"),
            "ai_verification=off must still floor to needs_review, got: {body}"
        );
    }

    #[test]
    fn partition_unresolved_keeps_only_items_without_a_verdict() {
        let mk = |id: &str| AmbiguousItem {
            incident_id: id.into(),
            score: 50,
            evidence: serde_json::json!({}),
            detector: "d".into(),
            title: "t".into(),
        };
        let items = vec![mk("a"), mk("b"), mk("c")];
        let mut resolved = std::collections::HashSet::new();
        resolved.insert("b".to_string()); // LLM decided b
        let left = partition_unresolved(items, &resolved);
        let ids: Vec<&str> = left.iter().map(|i| i.incident_id.as_str()).collect();
        assert_eq!(ids, vec!["a", "c"], "only items without a verdict remain");
    }

    #[test]
    fn partition_unresolved_empty_when_all_resolved() {
        let items = vec![AmbiguousItem {
            incident_id: "x".into(),
            score: 50,
            evidence: serde_json::json!({}),
            detector: "d".into(),
            title: "t".into(),
        }];
        let mut resolved = std::collections::HashSet::new();
        resolved.insert("x".to_string());
        assert!(partition_unresolved(items, &resolved).is_empty());
    }

    #[test]
    fn needs_review_entry_has_correct_shape_and_target_ip() {
        let item = AmbiguousItem {
            incident_id: "inc-9".into(),
            score: 57,
            evidence: serde_json::json!({"dst_ip": "203.0.113.42"}),
            detector: "proto_anomaly".into(),
            title: "t".into(),
        };
        let e = needs_review_entry(&item, "no AI verifier configured", chrono::Utc::now());
        assert_eq!(e.action_type, "needs_review");
        assert_eq!(e.ai_provider, "needs-review");
        assert!(!e.auto_executed, "needs_review takes no action");
        assert_eq!(e.execution_result, "awaiting_human");
        assert_eq!(e.estimated_threat, "unknown");
        assert_eq!(e.decision_layer.as_deref(), Some("observation_verifier"));
        assert_eq!(e.target_ip.as_deref(), Some("203.0.113.42"));
        assert!(e.reason.contains("57") && e.reason.contains("human review"));
    }

    #[test]
    fn needs_review_entry_target_ip_none_when_evidence_has_no_dst_ip() {
        let item = AmbiguousItem {
            incident_id: "inc-10".into(),
            score: 50,
            evidence: serde_json::json!({"detector": "x"}),
            detector: "x".into(),
            title: "t".into(),
        };
        let e = needs_review_entry(&item, "why", chrono::Utc::now());
        assert!(e.target_ip.is_none());
    }

    #[test]
    fn mark_needs_review_writes_decision_and_notify_is_safe_without_telegram() {
        use crate::tests::triage_test_state;
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = triage_test_state(tmp.path());
        // Phase 3 notify ON, but no telegram client / sqlite store on the test
        // state -> the notify branch must short-circuit, not panic.
        let mut cfg = crate::config::AgentConfig::default();
        cfg.learning.needs_review_notify = true;
        assert!(state.telegram_client.is_none());

        let items = vec![AmbiguousItem {
            incident_id: "inc-mnr-1".into(),
            score: 55,
            evidence: serde_json::json!({"dst_ip": "203.0.113.80"}),
            detector: "proto_anomaly".into(),
            title: "ambiguous".into(),
        }];
        mark_needs_review(&items, &cfg, &mut state, "no AI verifier configured");

        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        assert!(
            crate::decisions::count_decisions_for_date(tmp.path(), &today) >= 1,
            "mark_needs_review must still write the needs_review decision row"
        );
    }
}
