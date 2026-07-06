//! Spec 018 — Layer 2: Correlation-driven escalation.
//!
//! Drains completed attack chains from the correlation engine and escalates
//! response: multi-technique → longer block, repeat offender → permanent block,
//! kill chain → block + kill + critical alert.
//!
//! Runs in the slow loop (30s tick), after events are fed into the correlation
//! engine. Uses the knowledge graph and IP reputation for context.

use std::path::Path;

use chrono::Utc;
use tracing::{info, warn};

use crate::config::ChannelFilterLevel;
use crate::{
    ai, allowlist, config, correlation_engine, decisions, execute_decision, AgentState,
    LocalIpReputation,
};
use innerwarden_core::entities::{EntityRef, EntityType};

#[cfg(test)]
use crate::agent_context::incident_detector;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Provider label when `ip` is in the cloud / CDN / agent-service safelist and
/// must NOT be auto-blocked by a correlation chain or the repeat-offender path.
///
/// Uses [`cloud_safelist::safelist_label`](crate::cloud_safelist::safelist_label)
/// (the CIDR walk), NEVER `identify_provider` (the first-octet heuristic). The
/// heuristic only matches a hardcoded set of first octets, so it silently MISSES
/// safelisted CIDR ranges whose first octet it does not enumerate. 2026-05-08
/// switched the repeat-offender + decision paths to `safelist_label`, but the
/// correlation-chain path was missed and still used `identify_provider` - which
/// let the `Data Exfiltration (eBPF Sequence)` chain ban Canonical
/// `185.125.190.49` (`185.125.188.0/22`; first octet 185 is not in the
/// heuristic) on the Hetzner box 2026-06-27, breaking apt / livepatch. Both
/// correlation paths now share this one gate so they cannot drift apart again.
fn safelisted_provider(ip: &str) -> Option<&'static str> {
    crate::cloud_safelist::safelist_label(ip)
}

/// Process completed correlation chains and repeat-offender patterns.
/// Called once per slow-loop tick (30s).
pub(crate) async fn process_correlation_escalations(
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    if !cfg.responder.enabled {
        return;
    }

    // 1. Drain completed attack chains from the correlation engine.
    let chains = state.correlation_engine.drain_completed();
    for chain in &chains {
        handle_completed_chain(chain, data_dir, cfg, state).await;
    }

    // 2. Check for repeat offenders (IPs blocked 3+ times in history).
    check_repeat_offenders(data_dir, cfg, state).await;

    // 3. Multi-technique detection: IPs that triggered 2+ distinct detectors
    //    within the correlation window get their block escalated.
    check_multi_technique(data_dir, cfg, state).await;
}

// ---------------------------------------------------------------------------
// Attack chain response
// ---------------------------------------------------------------------------

/// Respond to a completed correlation chain.
/// Kill chain patterns (reverse shell, bind shell, etc.) get the strongest
/// response: block IP + kill process + critical alert.
async fn handle_completed_chain(
    chain: &correlation_engine::AttackChain,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    // Extract primary IP from chain events.
    let primary_ip = chain
        .events
        .iter()
        .flat_map(|e| &e.entities)
        .find(|e| e.r#type == EntityType::Ip)
        .map(|e| e.value.clone());

    let Some(ip) = primary_ip else {
        info!(
            chain_id = %chain.chain_id,
            rule = %chain.rule_name,
            "correlation chain completed but no IP found — logging only"
        );
        return;
    };

    // Guard checks (same as Layer 1).
    if crate::incident_auto_rules::is_internal_ip_pub(&ip) {
        return;
    }
    // Cloud-provider / CDN safelist: prevent correlation chains (CL-008 in
    // particular — file.read_access → network.outbound_connect within 60s —
    // matches every normal web server, and would otherwise ban Cloudflare,
    // AWS, and our own Oracle peer ranges en masse). `execute_block_ip`
    // already guards at the executor, but short-circuiting here keeps the
    // ip_reputation counter, cooldown table, and knowledge-graph decision
    // edge from being polluted in the first place.
    //
    // 2026-06-27 (fix/correlation-chain-safelist-bypass): switched from
    // `identify_provider` (first-octet heuristic) to the shared
    // `safelisted_provider` (CIDR walk) - the same fix the repeat-offender path
    // got on 2026-05-08 but this path was missed, so the `Data Exfiltration
    // (eBPF Sequence)` chain banned Canonical 185.125.190.49 on Hetzner.
    if let Some(provider) = safelisted_provider(&ip) {
        info!(
            chain_id = %chain.chain_id,
            rule = %chain.rule_id,
            ip = %ip,
            provider,
            "correlation chain targeted a cloud-provider IP — skipping escalation"
        );
        state.ip_reputations.remove(&ip);
        return;
    }
    if allowlist::is_ip_allowlisted(&ip, &cfg.allowlist.trusted_ips)
        || allowlist::is_ip_allowlisted(&ip, &state.dynamic_trusted_ips)
    {
        return;
    }
    if state.operator_ips.contains_key(&ip) {
        return;
    }

    // Cooldown: one chain response per IP per 10 minutes.
    let cooldown_key = format!("chain:{}:{}", chain.rule_id, ip);
    let cooldown_cutoff = Utc::now() - chrono::Duration::seconds(600);
    if state
        .store
        .get_cooldown(crate::state_store::CooldownTable::Decision, &cooldown_key)
        .is_some_and(|ts| ts > cooldown_cutoff)
    {
        return;
    }

    info!(
        chain_id = %chain.chain_id,
        rule = %chain.rule_name,
        ip = %ip,
        confidence = chain.confidence,
        stages = chain.stages_matched,
        "correlation chain completed — escalating response"
    );

    // Build a synthetic incident for the decision pipeline.
    let incident = innerwarden_core::incident::Incident {
        ts: chain.last_ts,
        host: std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string()),
        incident_id: format!("correlation:{}:{}", chain.chain_id, ip),
        severity: chain.severity.clone(),
        title: format!("Attack chain: {}", chain.rule_name),
        summary: chain.summary.clone(),
        evidence: serde_json::json!({
            "chain_id": chain.chain_id,
            "rule_id": chain.rule_id,
            "stages_matched": chain.stages_matched,
            "stages_total": chain.stages_total,
            "layers": chain.layers_involved.iter().map(|l| format!("{l:?}")).collect::<Vec<_>>(),
        }),
        recommended_checks: vec![],
        tags: vec!["correlation".to_string(), chain.rule_id.clone()],
        entities: vec![EntityRef::ip(&ip)],
    };

    // Determine block duration based on chain severity and confidence.
    let block_label = if chain.confidence >= 0.90 {
        "48h"
    } else {
        "24h"
    };

    let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
    let mut decision = ai::AiDecision {
        action: ai::AiAction::BlockIp {
            ip: ip.clone(),
            skill_id: skill_id.clone(),
        },
        confidence: chain.confidence,
        auto_execute: true,
        reason: format!(
            "Correlation chain: {} ({} stages, {:.0}% confidence, block {block_label})",
            chain.rule_name,
            chain.stages_matched,
            chain.confidence * 100.0,
        ),
        alternatives: vec![],
        estimated_threat: format!("{:?}", chain.severity).to_lowercase(),
    };

    // Spec 043 Phase 1b — direct-block coverage. Same rationale as the
    // repeat-offender / multi-technique wiring below: completed
    // correlation chains also bypass the AI-router decide path, so the
    // KG modifier hook needs to fire here too. Anchor pinned alongside
    // the other two direct-block anchors at the bottom of this file.
    crate::incident_decision_eval::apply_kg_decide_modifier(
        &incident,
        cfg,
        state,
        &mut decision,
        data_dir,
    );

    let (execution_result, cloudflare_pushed) =
        execute_decision(&decision, &incident, data_dir, cfg, state).await;

    // Audit trail.
    let entry = decisions::DecisionEntry {
        ts: Utc::now(),
        incident_id: incident.incident_id.clone(),
        host: incident.host.clone(),
        ai_provider: format!("correlation:{}", chain.rule_id),
        action_type: "block_ip".to_string(),
        target_ip: Some(ip.clone()),
        target_user: None,
        skill_id: Some(skill_id),
        confidence: chain.confidence,
        auto_executed: true,
        dry_run: cfg.responder.dry_run,
        reason: decision.reason.clone(),
        estimated_threat: decision.estimated_threat.clone(),
        execution_result: execution_result.clone(),
        prev_hash: None,
        decision_layer: Some("correlation_rule".to_string()),
    };
    if let Some(writer) = &mut state.decision_writer {
        if let Err(e) = writer.write(&entry) {
            warn!("failed to write chain decision: {e:#}");
        }
    }

    // Knowledge graph.
    {
        let auto_executed = !execution_result.starts_with("skipped");
        let mut graph = state.knowledge_graph.write().unwrap();
        graph.ingest_decision(
            &incident.incident_id,
            "block_ip",
            Some(&ip),
            decision.confidence,
            &decision.reason,
            auto_executed,
            Utc::now(),
        );
    }

    // IP reputation: chain participation weighs more than single incidents.
    let rep = state
        .ip_reputations
        .entry(ip.clone())
        .or_insert_with(LocalIpReputation::new);
    rep.record_incident();
    if !execution_result.starts_with("skipped") {
        rep.record_block();
        // Extra reputation penalty for chain involvement.
        rep.reputation_score += chain.confidence * 3.0;
    }

    // Cooldown.
    state.store.set_cooldown(
        crate::state_store::CooldownTable::Decision,
        &cooldown_key,
        Utc::now(),
    );

    // Telegram notification.
    if cfg.telegram.bot.enabled
        && cfg.telegram.channel_notifications.notification_level == ChannelFilterLevel::All
        && !execution_result.starts_with("skipped")
    {
        if let Some(ref tg) = state.telegram_client {
            let tg = tg.clone();
            let rule_name = chain.rule_name.clone();
            let ip_owned = ip.clone();
            let host = incident.host.clone();
            let confidence = chain.confidence;
            tokio::spawn(async move {
                let _ = tg
                    .send_action_report(
                        "Blocked (correlation chain)",
                        &ip_owned,
                        &rule_name,
                        confidence,
                        &host,
                        false,
                        None,
                        None,
                        cloudflare_pushed,
                    )
                    .await;
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Repeat offender detection
// ---------------------------------------------------------------------------

/// Returns `true` and removes the reputation entry when `ip` is not a valid
/// IP/CIDR target. A corrupted `ip-reputation.json` (e.g. stray octet > 255
/// from a broken upstream feed) would otherwise reach the firewall, fail
/// silently on add, and register a zombie "Active" lifecycle entry that can
/// never be reverted — producing the orphaned-response dashboard alert.
pub(crate) fn drop_invalid_repeat_offender(
    ip: &str,
    ip_reputations: &mut std::collections::HashMap<String, crate::ip_reputation::LocalIpReputation>,
    sqlite_store: Option<&crate::state_store::StateStore>,
) -> bool {
    // 2026-05-08 (fix/automated-block-paths-reject-cidr): use the
    // stricter `is_single_ip_block_target` so CIDR keys get pruned
    // from the automated path. Operator's prod 2026-05-08 had
    // `136.216.0.0/16` cycling every 2h since 2026-05-07 because
    // `is_valid_block_target` accepts CIDRs (intentional for
    // manual operator commands), and the repeat-offender loop then
    // happily re-emitted BlockIp on the /16. A real UFW rule of
    // `deny from 136.216.0.0/16` would have banned a public /16
    // (~65k IPs).
    //
    // 2026-05-08 (fix/ai-router-cidr-guard-and-zombie-purge): also
    // mirror the purge into SQLite so a restart doesn't re-load the
    // zombie entry from kv_state. Optional `sqlite_store` keeps the
    // helper unit-testable without a full AgentState (existing
    // tests pass `None` and only assert the in-memory behaviour).
    if !crate::decision_block_ip::is_single_ip_block_target(ip) {
        warn!(
            ip = %ip,
            "repeat-offender: skipping invalid or CIDR target — removing from ip_reputations"
        );
        ip_reputations.remove(ip);
        if let Some(sq) = sqlite_store {
            sq.delete_ip_reputation(ip);
        }
        return true;
    }
    false
}

/// Check IPs blocked 3+ times → escalate to permanent block (7 days).
async fn check_repeat_offenders(
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    // Collect IPs with 3+ blocks that haven't been permanently blocked yet.
    let repeat_ips: Vec<(String, u32)> = state
        .ip_reputations
        .iter()
        .filter(|(_, rep)| rep.total_blocks >= 3)
        .map(|(ip, rep)| (ip.clone(), rep.total_blocks))
        .collect();

    for (ip, total_blocks) in repeat_ips {
        // Guard: never feed a malformed target into the block pipeline.
        if drop_invalid_repeat_offender(&ip, &mut state.ip_reputations, Some(&state.store)) {
            continue;
        }

        let cooldown_key = format!("repeat-offender:{ip}");
        // Only fire once per 24h per IP.
        let cooldown_cutoff = Utc::now() - chrono::Duration::seconds(86400);
        if state
            .store
            .get_cooldown(crate::state_store::CooldownTable::Decision, &cooldown_key)
            .is_some_and(|ts| ts > cooldown_cutoff)
        {
            continue;
        }

        // Guard checks.
        if crate::incident_auto_rules::is_internal_ip_pub(&ip) {
            continue;
        }
        // Cloud-provider / CDN / agent-service safelist — drop the
        // reputation entry outright so the next correlation burst
        // cannot bump this IP back above the escalation threshold.
        // Production data from 2026-04-18 showed repeat-offender
        // compounding on Cloudflare CIDRs after CL-008 kept refiring
        // on legitimate outbound traffic.
        //
        // 2026-05-08 (fix/repeat-offender-safelist-bypass): switched
        // from `identify_provider` (first-octet heuristic) to the CIDR
        // walk. The heuristic missed 208.95.112.0/24 (ip-api.com - the
        // agent's OWN GeoIP service, blocked 37x in prod),
        // 91.189.88.0/21 (Canonical archive, blocked 14x),
        // 199.232.0.0/16 (Fastly, blocked 7x). The CIDR walk catches
        // all of them. Shares `safelisted_provider` with the chain path
        // (2026-06-27) so they can't drift apart again.
        if let Some(provider) = safelisted_provider(&ip) {
            info!(
                ip = %ip,
                provider,
                total_blocks,
                "repeat-offender: purging cloud-provider IP from reputation state"
            );
            state.ip_reputations.remove(&ip);
            // Mirror the in-memory purge into SQLite so a restart
            // doesn't re-load the same zombie entry from kv_state.
            state.store.delete_ip_reputation(&ip);
            continue;
        }
        if allowlist::is_ip_allowlisted(&ip, &cfg.allowlist.trusted_ips)
            || allowlist::is_ip_allowlisted(&ip, &state.dynamic_trusted_ips)
        {
            continue;
        }
        if state.operator_ips.contains_key(&ip) {
            continue;
        }

        info!(
            ip = %ip,
            total_blocks,
            "repeat offender: {total_blocks} blocks — escalating to 7-day block"
        );

        let incident = innerwarden_core::incident::Incident {
            ts: Utc::now(),
            host: std::env::var("HOSTNAME")
                .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
                .unwrap_or_else(|_| "unknown".to_string()),
            incident_id: format!("repeat-offender:{}:{}", ip, Utc::now().timestamp()),
            severity: innerwarden_core::event::Severity::High,
            title: format!("Repeat offender: {ip} blocked {total_blocks} times"),
            summary: format!(
                "IP {ip} has been blocked {total_blocks} times. Escalating to extended block."
            ),
            evidence: serde_json::json!({ "total_blocks": total_blocks }),
            recommended_checks: vec![],
            tags: vec!["repeat-offender".to_string()],
            entities: vec![EntityRef::ip(&ip)],
        };

        let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
        let mut decision = ai::AiDecision {
            action: ai::AiAction::BlockIp {
                ip: ip.clone(),
                skill_id: skill_id.clone(),
            },
            confidence: 0.98,
            auto_execute: true,
            reason: format!(
                "Repeat offender: {ip} blocked {total_blocks}x — extended block (7 days)"
            ),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        };

        // Spec 043 Phase 1b — direct-block coverage. Run the KG modifier
        // hook here too (not just the AI-decide path) so the shadow log
        // captures the high-volume direct-block decisions. Pre-1b the
        // shadow log only saw AI-router decisions (<5% of prod volume on
        // a busy host); now repeat-offender + multi-technique direct
        // blocks also flow through. In shadow mode this only writes a
        // log line; in enforce mode it adjusts decision.confidence
        // BEFORE execute_decision so a strongly-benign-history entity
        // can suppress an over-eager repeat-offender extended block.
        // Critical floor still applies — never suppress real Critical.
        crate::incident_decision_eval::apply_kg_decide_modifier(
            &incident,
            cfg,
            state,
            &mut decision,
            data_dir,
        );

        let (execution_result, _) =
            execute_decision(&decision, &incident, data_dir, cfg, state).await;

        let entry = decisions::DecisionEntry {
            ts: Utc::now(),
            incident_id: incident.incident_id.clone(),
            host: incident.host.clone(),
            ai_provider: "repeat-offender".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some(ip.clone()),
            target_user: None,
            skill_id: Some(skill_id),
            confidence: 0.98,
            auto_executed: true,
            dry_run: cfg.responder.dry_run,
            reason: decision.reason.clone(),
            estimated_threat: "high".to_string(),
            execution_result: execution_result.clone(),
            prev_hash: None,
            decision_layer: Some("correlation_rule".to_string()),
        };
        if let Some(writer) = &mut state.decision_writer {
            if let Err(e) = writer.write(&entry) {
                warn!("failed to write repeat-offender decision: {e:#}");
            }
        }

        state.store.set_cooldown(
            crate::state_store::CooldownTable::Decision,
            &cooldown_key,
            Utc::now(),
        );
    }
}

// ---------------------------------------------------------------------------
// Multi-technique detection
// ---------------------------------------------------------------------------

/// Check for IPs that triggered 2+ distinct detectors recently.
/// These get an escalated block (48h instead of 12h/24h).
async fn check_multi_technique(data_dir: &Path, cfg: &config::AgentConfig, state: &mut AgentState) {
    // Query the knowledge graph for IPs with multiple distinct incident detectors
    // in the last 30 minutes.
    let cutoff = Utc::now() - chrono::Duration::seconds(1800);
    let multi_technique_ips = {
        let graph = state.knowledge_graph.read().unwrap();
        find_multi_technique_ips(&graph, cutoff)
    };

    for (ip, detectors) in multi_technique_ips {
        // 2026-05-08 (fix/automated-block-paths-reject-cidr): the
        // KG can carry a CIDR string in an Ip node if some upstream
        // populated it that way. Reject CIDR + invalid targets at
        // the entry of the automated path. Operator's prod 2026-05-08
        // proved this happens (136.216.0.0/16 was cycling via the
        // repeat-offender twin of this loop); the same protection
        // belongs here in case multi-technique ever sees the same
        // shape.
        if !crate::decision_block_ip::is_single_ip_block_target(&ip) {
            warn!(
                ip = %ip,
                "multi-technique: skipping invalid or CIDR target"
            );
            continue;
        }

        let cooldown_key = format!("multi-technique:{ip}");
        let cooldown_cutoff = Utc::now() - chrono::Duration::seconds(3600);
        if state
            .store
            .get_cooldown(crate::state_store::CooldownTable::Decision, &cooldown_key)
            .is_some_and(|ts| ts > cooldown_cutoff)
        {
            continue;
        }

        // Guard checks.
        if crate::incident_auto_rules::is_internal_ip_pub(&ip) {
            continue;
        }
        if allowlist::is_ip_allowlisted(&ip, &cfg.allowlist.trusted_ips)
            || allowlist::is_ip_allowlisted(&ip, &state.dynamic_trusted_ips)
        {
            continue;
        }
        if state.operator_ips.contains_key(&ip) {
            continue;
        }

        let detector_list = detectors.join(", ");
        info!(
            ip = %ip,
            detectors = %detector_list,
            "multi-technique: {count} distinct detectors — escalating block to 48h",
            count = detectors.len()
        );

        let incident = innerwarden_core::incident::Incident {
            ts: Utc::now(),
            host: std::env::var("HOSTNAME")
                .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
                .unwrap_or_else(|_| "unknown".to_string()),
            incident_id: format!("multi-technique:{}:{}", ip, Utc::now().timestamp()),
            severity: innerwarden_core::event::Severity::High,
            title: format!("Multi-technique attack from {ip}"),
            summary: format!(
                "IP {ip} triggered {count} distinct detectors: {detector_list}. Escalating.",
                count = detectors.len()
            ),
            evidence: serde_json::json!({ "detectors": detectors }),
            recommended_checks: vec![],
            tags: vec!["multi-technique".to_string()],
            entities: vec![EntityRef::ip(&ip)],
        };

        let skill_id = format!("block-ip-{}", cfg.responder.block_backend);
        let mut decision = ai::AiDecision {
            action: ai::AiAction::BlockIp {
                ip: ip.clone(),
                skill_id: skill_id.clone(),
            },
            confidence: 0.92,
            auto_execute: true,
            reason: format!(
                "Multi-technique: {ip} triggered {count} detectors ({detector_list}) — block 48h",
                count = detectors.len()
            ),
            alternatives: vec![],
            estimated_threat: "high".to_string(),
        };

        // Spec 043 Phase 1b — direct-block coverage. See repeat-offender
        // wiring above for the rationale (KG modifier shadow-logging on
        // the high-volume direct-block paths so prod data accumulates
        // in minutes instead of days).
        crate::incident_decision_eval::apply_kg_decide_modifier(
            &incident,
            cfg,
            state,
            &mut decision,
            data_dir,
        );

        let (execution_result, _) =
            execute_decision(&decision, &incident, data_dir, cfg, state).await;

        let entry = decisions::DecisionEntry {
            ts: Utc::now(),
            incident_id: incident.incident_id.clone(),
            host: incident.host.clone(),
            ai_provider: "multi-technique".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some(ip.clone()),
            target_user: None,
            skill_id: Some(skill_id),
            confidence: 0.92,
            auto_executed: true,
            dry_run: cfg.responder.dry_run,
            reason: decision.reason.clone(),
            estimated_threat: "high".to_string(),
            execution_result: execution_result.clone(),
            prev_hash: None,
            decision_layer: Some("correlation_rule".to_string()),
        };
        if let Some(writer) = &mut state.decision_writer {
            if let Err(e) = writer.write(&entry) {
                warn!("failed to write multi-technique decision: {e:#}");
            }
        }

        // Update reputation.
        let rep = state
            .ip_reputations
            .entry(ip.clone())
            .or_insert_with(LocalIpReputation::new);
        if !execution_result.starts_with("skipped") {
            rep.record_block();
        }

        state.store.set_cooldown(
            crate::state_store::CooldownTable::Decision,
            &cooldown_key,
            Utc::now(),
        );
    }
}

/// Query the knowledge graph for IPs that triggered 2+ distinct detectors
/// since `cutoff`.
fn find_multi_technique_ips(
    graph: &crate::knowledge_graph::graph::KnowledgeGraph,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> Vec<(String, Vec<String>)> {
    use std::collections::{HashMap, HashSet};

    let mut ip_detectors: HashMap<String, HashSet<String>> = HashMap::new();
    let nodes = graph.nodes();

    // Walk all incident nodes and their IP edges.
    for (&node_id, node) in nodes.iter() {
        let (detector, ts) = match node {
            crate::knowledge_graph::types::Node::Incident { detector, ts, .. } => (detector, ts),
            _ => continue,
        };

        if *ts < cutoff {
            continue;
        }

        // Find the IP connected to this incident via TriggeredBy edge.
        for edge in graph.all_edges(node_id) {
            if !matches!(
                edge.relation,
                crate::knowledge_graph::types::Relation::TriggeredBy
            ) {
                continue;
            }
            if let Some(crate::knowledge_graph::types::Node::Ip { addr, .. }) = nodes.get(&edge.to)
            {
                ip_detectors
                    .entry(addr.clone())
                    .or_default()
                    .insert(detector.clone());
            }
        }
    }

    // Return only IPs with 2+ distinct detectors.
    ip_detectors
        .into_iter()
        .filter(|(_, detectors)| detectors.len() >= 2)
        .map(|(ip, detectors)| {
            let mut sorted: Vec<String> = detectors.into_iter().collect();
            sorted.sort();
            (ip, sorted)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::{graph::KnowledgeGraph, types::*};

    fn add_incident(
        graph: &mut KnowledgeGraph,
        detector: &str,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> NodeId {
        graph.add_node(Node::Incident {
            incident_id: format!(
                "{detector}:test:{}",
                ts.timestamp_nanos_opt().unwrap_or_default()
            ),
            detector: detector.into(),
            severity: "High".into(),
            title: detector.into(),
            summary: "".into(),
            ts,
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
        })
    }

    // `drop_invalid_repeat_offender` is the gate that keeps corrupted
    // `ip-reputation.json` entries from ever reaching the block pipeline.
    // Cover every production-seen failure shape + the happy path.
    #[test]
    fn drop_invalid_removes_octet_out_of_range() {
        use crate::ip_reputation::LocalIpReputation;
        use std::collections::HashMap;

        let mut map: HashMap<String, LocalIpReputation> = HashMap::new();
        map.insert("129.950.5.0".to_string(), LocalIpReputation::new());
        let dropped = drop_invalid_repeat_offender("129.950.5.0", &mut map, None);
        assert!(dropped);
        assert!(!map.contains_key("129.950.5.0"));
    }

    #[test]
    fn drop_invalid_keeps_valid_ipv4() {
        use crate::ip_reputation::LocalIpReputation;
        use std::collections::HashMap;

        let mut map: HashMap<String, LocalIpReputation> = HashMap::new();
        map.insert("8.8.8.8".to_string(), LocalIpReputation::new());
        let dropped = drop_invalid_repeat_offender("8.8.8.8", &mut map, None);
        assert!(!dropped);
        assert!(map.contains_key("8.8.8.8"));
    }

    /// 2026-05-08 (fix/automated-block-paths-reject-cidr): contract
    /// CHANGED. Previously this anchor asserted that CIDRs were KEPT
    /// in `ip_reputations` (the rationale was "operators can manually
    /// block /24s of botnet networks"). Operator's prod 2026-05-08
    /// proved the operational cost: `136.216.0.0/16` cycled every 2h
    /// for two days because the repeat-offender loop happily re-fired
    /// BlockIp on the CIDR, and a successful UFW path would have
    /// banned a /16 of public IP space (~65k IPs). The new contract:
    /// the AUTOMATED repeat-offender path rejects every CIDR. Manual
    /// operator commands keep using `is_valid_block_target` (which
    /// still accepts CIDRs) — only the automated emitter is locked
    /// down. The exact prod IP `136.216.0.0/16` is the test fixture
    /// so a regression here fires loud.
    #[test]
    fn drop_invalid_drops_cidr_from_automated_path() {
        use crate::ip_reputation::LocalIpReputation;
        use std::collections::HashMap;

        let mut map: HashMap<String, LocalIpReputation> = HashMap::new();
        map.insert("136.216.0.0/16".to_string(), LocalIpReputation::new());
        let dropped = drop_invalid_repeat_offender("136.216.0.0/16", &mut map, None);
        assert!(
            dropped,
            "CIDR target MUST be dropped from the automated path (prod regression IP)"
        );
        assert!(
            !map.contains_key("136.216.0.0/16"),
            "the CIDR entry MUST be removed from ip_reputations so the next \
             tick doesn't re-emit BlockIp on it"
        );
    }

    #[test]
    fn drop_invalid_handles_every_production_bad_sample() {
        use crate::ip_reputation::LocalIpReputation;
        use std::collections::HashMap;

        for bad in [
            "129.491.8.0",
            "129.950.5.15",
            "129.950.5.0",
            "129.952.2.0",
            "130.806.3.0",
            "129.950.5.5",
            "137.274.6",
            "130.932.0.0",
            "129.525.8.0",
            "130.890.9.0",
            "130.806.1.17",
        ] {
            let mut map: HashMap<String, LocalIpReputation> = HashMap::new();
            map.insert(bad.to_string(), LocalIpReputation::new());
            assert!(
                drop_invalid_repeat_offender(bad, &mut map, None),
                "'{bad}' must be classified as invalid"
            );
            assert!(map.is_empty(), "'{bad}' must be removed from reputations");
        }
    }

    #[test]
    fn drop_invalid_noop_when_ip_not_in_map() {
        use crate::ip_reputation::LocalIpReputation;
        use std::collections::HashMap;

        // Even if the ip isn't in the map, the predicate should still return
        // true/false based on validity, and remove() is a no-op.
        let mut map: HashMap<String, LocalIpReputation> = HashMap::new();
        map.insert("1.2.3.4".to_string(), LocalIpReputation::new());
        let dropped = drop_invalid_repeat_offender("129.950.5.0", &mut map, None);
        assert!(dropped);
        assert_eq!(map.len(), 1); // unchanged
        assert!(map.contains_key("1.2.3.4"));
    }

    #[test]
    fn extract_detector_from_incident_id() {
        assert_eq!(
            incident_detector("ssh_bruteforce:1.2.3.4:12345"),
            "ssh_bruteforce"
        );
        assert_eq!(incident_detector("port_scan:10.0.0.1:67890"), "port_scan");
        assert_eq!(incident_detector("single_word"), "single_word");
    }

    #[test]
    fn find_multi_technique_empty_graph() {
        let graph = KnowledgeGraph::new();
        let result =
            find_multi_technique_ips(&graph, chrono::Utc::now() - chrono::Duration::hours(1));
        assert!(result.is_empty());
    }

    #[test]
    fn find_multi_technique_single_detector_not_returned() {
        // One IP with one detector → should NOT appear in results.
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();

        let ip_id = graph.ensure_ip("1.2.3.4", now);
        let inc_id = graph.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:1.2.3.4:001".into(),
            detector: "ssh_bruteforce".into(),
            severity: "High".into(),
            title: "SSH brute force".into(),
            summary: "".into(),
            ts: now,
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
        graph.add_edge(Edge::new(inc_id, ip_id, Relation::TriggeredBy, now));

        let result = find_multi_technique_ips(&graph, now - chrono::Duration::hours(1));
        assert!(result.is_empty(), "single detector should not be returned");
    }

    #[test]
    fn find_multi_technique_two_detectors_returned() {
        // One IP with two distinct detectors → should appear.
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();

        let ip_id = graph.ensure_ip("5.6.7.8", now);

        let inc1 = graph.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:5.6.7.8:001".into(),
            detector: "ssh_bruteforce".into(),
            severity: "High".into(),
            title: "SSH brute force".into(),
            summary: "".into(),
            ts: now,
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
        graph.add_edge(Edge::new(inc1, ip_id, Relation::TriggeredBy, now));

        let inc2 = graph.add_node(Node::Incident {
            incident_id: "port_scan:5.6.7.8:002".into(),
            detector: "port_scan".into(),
            severity: "Medium".into(),
            title: "Port scan".into(),
            summary: "".into(),
            ts: now,
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
        graph.add_edge(Edge::new(inc2, ip_id, Relation::TriggeredBy, now));

        let result = find_multi_technique_ips(&graph, now - chrono::Duration::hours(1));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "5.6.7.8");
        assert_eq!(result[0].1.len(), 2);
        assert!(result[0].1.contains(&"port_scan".to_string()));
        assert!(result[0].1.contains(&"ssh_bruteforce".to_string()));
    }

    #[test]
    fn find_multi_technique_ignores_non_triggeredby_edges_and_non_ip_targets() {
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();

        let ip = graph.ensure_ip("4.4.4.4", now);
        let domain = graph.ensure_domain("example.test");
        let ssh = add_incident(&mut graph, "ssh_bruteforce", now);
        let web = add_incident(&mut graph, "web_scan", now);
        let dns = add_incident(&mut graph, "dns_probe", now);

        graph.add_edge(Edge::new(ssh, ip, Relation::CorrelatedWith, now));
        graph.add_edge(Edge::new(web, domain, Relation::TriggeredBy, now));
        graph.add_edge(Edge::new(dns, ip, Relation::TriggeredBy, now));

        let result = find_multi_technique_ips(&graph, now - chrono::Duration::minutes(30));
        assert!(
            result.is_empty(),
            "only TriggeredBy edges to Ip nodes should count toward multi-technique correlation"
        );
    }

    #[test]
    fn find_multi_technique_sorts_detector_names_for_stable_payloads() {
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();
        let ip = graph.ensure_ip("7.7.7.7", now);

        for detector in ["z_last", "a_first", "m_middle"] {
            let inc = add_incident(&mut graph, detector, now);
            graph.add_edge(Edge::new(inc, ip, Relation::TriggeredBy, now));
        }

        let result = find_multi_technique_ips(&graph, now - chrono::Duration::minutes(30));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "7.7.7.7");
        assert_eq!(
            result[0].1,
            vec![
                "a_first".to_string(),
                "m_middle".to_string(),
                "z_last".to_string()
            ]
        );
    }

    #[test]
    fn find_multi_technique_keeps_cutoff_boundary_incidents() {
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();
        let cutoff = now - chrono::Duration::minutes(30);
        let ip = graph.ensure_ip("8.8.4.4", now);

        let boundary = add_incident(&mut graph, "boundary_detector", cutoff);
        let recent = add_incident(&mut graph, "recent_detector", now);
        graph.add_edge(Edge::new(boundary, ip, Relation::TriggeredBy, cutoff));
        graph.add_edge(Edge::new(recent, ip, Relation::TriggeredBy, now));

        let result = find_multi_technique_ips(&graph, cutoff);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].1,
            vec![
                "boundary_detector".to_string(),
                "recent_detector".to_string()
            ],
            "incidents exactly at cutoff are still inside the correlation window"
        );
    }

    #[test]
    fn find_multi_technique_old_incidents_excluded() {
        // Incidents older than cutoff should not count.
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();
        let old = now - chrono::Duration::hours(2);

        let ip_id = graph.ensure_ip("9.9.9.9", now);

        let inc1 = graph.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:9.9.9.9:001".into(),
            detector: "ssh_bruteforce".into(),
            severity: "High".into(),
            title: "".into(),
            summary: "".into(),
            ts: old, // OLD
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
        graph.add_edge(Edge::new(inc1, ip_id, Relation::TriggeredBy, old));

        let inc2 = graph.add_node(Node::Incident {
            incident_id: "port_scan:9.9.9.9:002".into(),
            detector: "port_scan".into(),
            severity: "Medium".into(),
            title: "".into(),
            summary: "".into(),
            ts: now, // RECENT
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
        graph.add_edge(Edge::new(inc2, ip_id, Relation::TriggeredBy, now));

        // Cutoff 1 hour ago — only the port_scan is recent, ssh_bruteforce is 2h old.
        let result = find_multi_technique_ips(&graph, now - chrono::Duration::hours(1));
        assert!(
            result.is_empty(),
            "old incident should be excluded by cutoff"
        );
    }

    #[test]
    fn find_multi_technique_multiple_ips() {
        // Two IPs, only one with 2+ detectors.
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();

        // IP A: 2 detectors
        let ip_a = graph.ensure_ip("1.1.1.1", now);
        let inc_a1 = graph.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:1.1.1.1:001".into(),
            detector: "ssh_bruteforce".into(),
            severity: "High".into(),
            title: "".into(),
            summary: "".into(),
            ts: now,
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
        graph.add_edge(Edge::new(inc_a1, ip_a, Relation::TriggeredBy, now));
        let inc_a2 = graph.add_node(Node::Incident {
            incident_id: "web_scan:1.1.1.1:002".into(),
            detector: "web_scan".into(),
            severity: "Medium".into(),
            title: "".into(),
            summary: "".into(),
            ts: now,
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
        graph.add_edge(Edge::new(inc_a2, ip_a, Relation::TriggeredBy, now));

        // IP B: 1 detector only
        let ip_b = graph.ensure_ip("2.2.2.2", now);
        let inc_b1 = graph.add_node(Node::Incident {
            incident_id: "port_scan:2.2.2.2:003".into(),
            detector: "port_scan".into(),
            severity: "Low".into(),
            title: "".into(),
            summary: "".into(),
            ts: now,
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
        graph.add_edge(Edge::new(inc_b1, ip_b, Relation::TriggeredBy, now));

        let result = find_multi_technique_ips(&graph, now - chrono::Duration::hours(1));
        assert_eq!(result.len(), 1, "only IP A should appear");
        assert_eq!(result[0].0, "1.1.1.1");
    }

    #[test]
    fn find_multi_technique_same_detector_twice_not_counted() {
        // Same detector firing twice should NOT count as multi-technique.
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();

        let ip_id = graph.ensure_ip("3.3.3.3", now);
        for i in 0..3 {
            let inc = graph.add_node(Node::Incident {
                incident_id: format!("ssh_bruteforce:3.3.3.3:00{i}"),
                detector: "ssh_bruteforce".into(),
                severity: "High".into(),
                title: "".into(),
                summary: "".into(),
                ts: now,
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
            graph.add_edge(Edge::new(inc, ip_id, Relation::TriggeredBy, now));
        }

        let result = find_multi_technique_ips(&graph, now - chrono::Duration::hours(1));
        assert!(result.is_empty(), "same detector 3x is not multi-technique");
    }

    // ─── Spec 024 contract tests ───────────────────────────────────────
    //
    // `drop_invalid_repeat_offender` is the sole guard that prevents
    // repeat-offender escalation from feeding a malformed target into the
    // block pipeline. Spec 024 formalises the contract so the guard cannot
    // be deleted or reversed by a future edit without a loud test failure.
    //
    // Contract:
    //   - drop_invalid(ip, map) returns true  ⇒ ip was invalid; it has been
    //     evicted from the reputation map.
    //   - drop_invalid(ip, map) returns false ⇒ ip is a valid block target;
    //     map is unchanged for that ip.
    //   - drop_invalid is pure in the ip input: no I/O, no logging that
    //     could fail, no global state read. It is safe to call from inside
    //     a hot loop.
    //   - For every production-observed malformed ip (see the bad-sample
    //     list in `drop_invalid_handles_every_production_bad_sample`) the
    //     function MUST evict. Expanding that list over time is the point.

    #[test]
    fn contract_drop_invalid_is_pure_in_ip() {
        use crate::ip_reputation::LocalIpReputation;
        use std::collections::HashMap;

        // Calling on an absent ip with a populated map must not touch
        // other entries.
        let mut map: HashMap<String, LocalIpReputation> = HashMap::new();
        map.insert("1.1.1.1".to_string(), LocalIpReputation::new());
        map.insert("2.2.2.2".to_string(), LocalIpReputation::new());
        let dropped = drop_invalid_repeat_offender("bogus-ip", &mut map, None);
        assert!(dropped, "malformed ip must be reported as dropped");
        assert_eq!(map.len(), 2, "unrelated entries must survive");
        assert!(map.contains_key("1.1.1.1"));
        assert!(map.contains_key("2.2.2.2"));
    }

    #[test]
    fn contract_drop_invalid_boundary_is_true_valid_ip_passes_through() {
        use crate::ip_reputation::LocalIpReputation;
        use std::collections::HashMap;

        let mut map: HashMap<String, LocalIpReputation> = HashMap::new();
        map.insert("203.0.113.55".to_string(), LocalIpReputation::new());
        let dropped = drop_invalid_repeat_offender("203.0.113.55", &mut map, None);
        assert!(!dropped, "valid public ip must not be dropped");
        assert!(map.contains_key("203.0.113.55"));
    }

    #[test]
    fn contract_drop_invalid_is_idempotent_on_already_absent_ips() {
        use crate::ip_reputation::LocalIpReputation;
        use std::collections::HashMap;

        let mut map: HashMap<String, LocalIpReputation> = HashMap::new();
        map.insert("129.999.0.0".to_string(), LocalIpReputation::new());

        // First call: evicts.
        assert!(drop_invalid_repeat_offender("129.999.0.0", &mut map, None));
        assert!(!map.contains_key("129.999.0.0"));

        // Second call: still returns true (invalid is invalid), no panic.
        assert!(drop_invalid_repeat_offender("129.999.0.0", &mut map, None));
        assert!(!map.contains_key("129.999.0.0"));
    }

    // ── Spec 043 Phase 1b anchors (AUDIT-SPEC043-PHASE1B) ──────────────
    //
    // Pre-Phase-1b the KG modifier hook fired only on the AI-router
    // decide path. Prod evidence (2026-05-06): on a busy host the
    // AI-router decide path accounts for <5% of actual block decisions
    // (the rest flow through `repeat-offender` direct-blocks that
    // bypass the AI router entirely). The shadow log filled in days
    // instead of minutes.
    //
    // These anchors pin the source-grep contract: the
    // `apply_kg_decide_modifier` call MUST appear at both direct-block
    // sites in this file (repeat-offender + multi-technique). A future
    // refactor that drops either call silently regresses the coverage
    // and re-creates the slow-fill problem.

    #[test]
    fn phase_1b_repeat_offender_path_invokes_kg_decide_modifier() {
        let src = include_str!("correlation_response.rs");
        let ro_idx = src
            .find("Repeat offender: {ip} blocked {total_blocks}x — extended block (7 days)")
            .expect("repeat-offender decision construction marker missing");
        let exec_idx = src[ro_idx..]
            .find("execute_decision(&decision, &incident, data_dir, cfg, state)")
            .expect("execute_decision call missing after repeat-offender block");
        let between = &src[ro_idx..ro_idx + exec_idx];
        assert!(
            between.contains("apply_kg_decide_modifier"),
            "Spec 043 Phase 1b: apply_kg_decide_modifier MUST be called \
             between the repeat-offender AiDecision construction and \
             execute_decision so the KG shadow log captures direct-block \
             decisions. Pre-Phase-1b the shadow log only saw AI-router \
             decisions (<5% of prod volume). Drop this call and prod \
             takes days to fill the log instead of minutes."
        );
    }

    #[test]
    fn phase_1b_multi_technique_path_invokes_kg_decide_modifier() {
        let src = include_str!("correlation_response.rs");
        let mt_idx = src
            .find("Multi-technique: {ip} triggered {count} detectors")
            .expect("multi-technique decision construction marker missing");
        let exec_idx = src[mt_idx..]
            .find("execute_decision(&decision, &incident, data_dir, cfg, state)")
            .expect("execute_decision call missing after multi-technique block");
        let between = &src[mt_idx..mt_idx + exec_idx];
        assert!(
            between.contains("apply_kg_decide_modifier"),
            "Spec 043 Phase 1b: apply_kg_decide_modifier MUST be called \
             between the multi-technique AiDecision construction and \
             execute_decision (mirror anchor — same rationale as the \
             repeat-offender anchor above)."
        );
    }

    #[test]
    fn phase_1b_completed_chain_path_invokes_kg_decide_modifier() {
        let src = include_str!("correlation_response.rs");
        let chain_idx = src
            .find("Correlation chain: {} ({} stages,")
            .expect("completed-chain decision construction marker missing");
        let exec_idx = src[chain_idx..]
            .find("execute_decision(&decision, &incident, data_dir, cfg, state)")
            .expect("execute_decision call missing after completed-chain block");
        let between = &src[chain_idx..chain_idx + exec_idx];
        assert!(
            between.contains("apply_kg_decide_modifier"),
            "Spec 043 Phase 1b: apply_kg_decide_modifier MUST be called \
             between the completed-chain AiDecision construction and \
             execute_decision. Correlation chains bypass the AI-router \
             decide path same as repeat-offender / multi-technique, so \
             the KG modifier hook needs to fire here too."
        );
    }

    #[test]
    fn safelisted_provider_uses_cidr_walk_not_first_octet_heuristic() {
        // Hetzner 2026-06-27: the `Data Exfiltration (eBPF Sequence)` chain
        // banned Canonical 185.125.190.49 (apt/livepatch) because the chain
        // path still gated on `identify_provider` (first-octet heuristic) after
        // the 2026-05-08 fix switched the sibling paths to the CIDR walk. This
        // pins that the shared gate catches the CIDR-only ranges the heuristic
        // misses, while real attackers stay blockable.
        crate::cloud_safelist::init();

        // Regression witness: the OLD gate (first-octet 185) returns None, which
        // is exactly why the chain blocked Canonical.
        assert!(
            crate::cloud_safelist::identify_provider("185.125.190.49").is_none(),
            "identify_provider misses 185.x - the bug's root cause"
        );
        // The fixed gate catches it (185.125.188.0/22 is in the safelist).
        assert!(
            safelisted_provider("185.125.190.49").is_some(),
            "Canonical 185.125.190.49 must be safelisted via the CIDR walk"
        );
        // Other CIDR-only ranges the first-octet heuristic also misses.
        assert!(
            safelisted_provider("208.95.112.1").is_some(),
            "ip-api.com (the agent's own GeoIP) must be safelisted"
        );
        assert!(
            safelisted_provider("199.232.58.137").is_some(),
            "Fastly must be safelisted"
        );

        // Anti-evasion: a real attacker outside every safelist range is still
        // blockable by both correlation paths.
        assert!(safelisted_provider("203.0.113.45").is_none());
        assert!(safelisted_provider("45.148.10.121").is_none());
    }

    #[tokio::test]
    async fn both_correlation_paths_skip_cloud_safelisted_ip() {
        // Exercises the two call sites `safelisted_provider` feeds (the
        // 2026-06-27 fix/correlation-chain-safelist-bypass), not just the
        // helper in isolation: a cloud-provider IP reaching either the
        // repeat-offender path or the completed-chain path must be purged
        // from reputation state, never escalated to a block. Canonical
        // 185.125.190.49 sits in the CIDR-only range (185.125.188.0/22) the
        // old first-octet heuristic missed, so this also pins the fix.
        crate::cloud_safelist::init();
        let tmp = tempfile::tempdir().unwrap();
        let cfg = config::AgentConfig::default();

        // Path 1: repeat-offender (check_repeat_offenders).
        let mut state = crate::tests::triage_test_state(tmp.path());
        let mut rep = LocalIpReputation::new();
        rep.total_blocks = 3; // qualifies for repeat-offender escalation
        state
            .ip_reputations
            .insert("185.125.190.49".to_string(), rep);
        check_repeat_offenders(tmp.path(), &cfg, &mut state).await;
        assert!(
            !state.ip_reputations.contains_key("185.125.190.49"),
            "repeat-offender path must purge the cloud-safelisted IP, not escalate it"
        );

        // Path 2: completed correlation chain (handle_completed_chain).
        let mut state = crate::tests::triage_test_state(tmp.path());
        state
            .ip_reputations
            .insert("185.125.190.49".to_string(), LocalIpReputation::new());
        let chain = correlation_engine::AttackChain {
            chain_id: "test-chain".to_string(),
            rule_id: "CL-008".to_string(),
            rule_name: "Data Exfiltration (eBPF Sequence)".to_string(),
            start_ts: Utc::now(),
            last_ts: Utc::now(),
            events: vec![correlation_engine::CorrelationEvent {
                ts: Utc::now(),
                layer: correlation_engine::Layer::Network,
                source: "detector".into(),
                kind: "c2_callback".into(),
                severity: innerwarden_core::event::Severity::High,
                entities: vec![EntityRef::ip("185.125.190.49")],
                details: serde_json::Value::Null,
                incident_id: String::new(),
            }],
            stages_matched: 2,
            stages_total: 2,
            confidence: 1.0,
            layers_involved: vec![correlation_engine::Layer::Network],
            severity: innerwarden_core::event::Severity::High,
            summary: "test".to_string(),
        };
        handle_completed_chain(&chain, tmp.path(), &cfg, &mut state).await;
        assert!(
            !state.ip_reputations.contains_key("185.125.190.49"),
            "completed-chain path must purge the cloud-safelisted IP, not escalate it"
        );
    }
}
