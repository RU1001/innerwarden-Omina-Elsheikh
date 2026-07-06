//! Daily AI Intelligence Briefing — generates structured threat summary from knowledge graph.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::{Arc, RwLock};

use crate::dashboard::types::OverviewSnapshot;
use crate::knowledge_graph::types::{Node, NodeType, Relation};
use crate::knowledge_graph::KnowledgeGraph;

/// The generated briefing result.
#[derive(Debug, Clone, Serialize)]
pub struct Briefing {
    pub generated_at: DateTime<Utc>,
    pub date: String,
    pub threat_level: String,
    pub summary: String,
}

/// Topline counters derived from the canonical `OverviewSnapshot`.
/// 2026-05-02 audit B1/P1 (Spec 039 Phase 1): briefing must read its
/// counts from the same snapshot the dashboard tiles read, so the
/// "0 needing action" / "2 awaiting" contradiction the auditor saw on
/// the same screen cannot recur. The canonical mapping is:
///
/// | briefing | OverviewSnapshot bucket |
/// |---|---|
/// | `contained` | blocked + observing + honeypot |
/// | `ignored`   | dismissed + allowlisted |
/// | `unresolved` | attention.incidents |
/// | `unresolved_high_crit` | attention.severities (high+critical) |
/// | `blocked_ips` count | blocked.unique_attackers |
///
/// Narrative detail (top attacker IPs with detector breakdown,
/// per-detector list, action descriptions, unresolved entity refs)
/// keeps coming from the KG walk — the snapshot only carries
/// aggregate counts.
struct BriefingCounters {
    contained: usize,
    ignored: usize,
    unresolved: usize,
    unresolved_high_crit: usize,
    blocked_ips_count: usize,
}

impl BriefingCounters {
    fn from_snapshot(snap: &OverviewSnapshot) -> Self {
        let b = &snap.buckets;
        let attention_high = b.attention.severities.get("high").copied().unwrap_or(0);
        let attention_crit = b.attention.severities.get("critical").copied().unwrap_or(0);
        // `contained` and `unresolved` are INCIDENT counts — they feed the
        // "Operator-relevant incidents today" / "OBSERVING: N incidents" lines,
        // which must agree with the Sensors HUD `total_incidents` and the
        // Report total (all incident sums; anchored by
        // consistency_incidents_today).
        //
        // `ignored`, on the other hand, must equal the Home tile "Filtered out"
        // = `dismissed.unique_attackers` (data_api.rs:659). It previously used
        // `dismissed.incidents + allowlisted.incidents`, which is what produced
        // the operator's "Ignored 21 vs Filtered out 11" mismatch: one attacker
        // fires many incidents (types.rs documents this "21 vs 10" confusion),
        // and allowlisted is a separate operator-trust bucket that is NOT part
        // of "flagged"/"filtered out".
        Self {
            contained: b.blocked.incidents + b.observing.incidents + b.honeypot.incidents,
            ignored: b.dismissed.unique_attackers,
            unresolved: b.attention.incidents,
            unresolved_high_crit: attention_high + attention_crit,
            blocked_ips_count: b.blocked.unique_attackers,
        }
    }
}

/// Build the structured context from the knowledge graph for LLM consumption.
/// Separates contained (resolved) from unresolved, marks internal IPs,
/// and shows actions already taken.
///
/// 2026-05-02 (Spec 039 P1): pass `Some(snapshot)` to lock topline
/// counters to the same numbers the dashboard tiles paint. When
/// `None`, falls back to the legacy KG scan — used by tests and the
/// boot path before the first overview is computed.
pub fn build_briefing_context(
    kg: &Arc<RwLock<KnowledgeGraph>>,
    snapshot: Option<&OverviewSnapshot>,
) -> String {
    let graph = kg.read().unwrap();

    let incident_nodes = graph.nodes_of_type(NodeType::Incident);

    // Categorize incidents
    let mut contained = 0usize;
    let mut ignored = 0usize;
    let mut unresolved = 0usize;
    let mut unresolved_high_crit = 0usize;
    let mut by_detector: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut by_severity: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut actions_taken: Vec<String> = Vec::new();
    let mut unresolved_list: Vec<(String, String, String)> = Vec::new(); // (severity, title, entity)

    for &id in &incident_nodes {
        if let Some(Node::Incident {
            detector,
            severity,
            title,
            decision,
            decision_target,
            auto_executed,
            research_only,
            ..
        }) = graph.get_node(id)
        {
            // Skip research-only incidents — these are self-traffic (agent
            // notifications, cloud metadata, CrowdSec polling) that pollute
            // the briefing with false "threats" like Telegram API IPs.
            if *research_only {
                continue;
            }
            *by_detector.entry(detector.clone()).or_default() += 1;
            *by_severity.entry(severity.to_lowercase()).or_default() += 1;

            match decision.as_deref() {
                Some("block_ip") => {
                    contained += 1;
                    let target = decision_target.as_deref().unwrap_or("?");
                    let mode = if *auto_executed {
                        "auto-blocked"
                    } else {
                        "manual"
                    };
                    actions_taken.push(format!("Blocked IP {} ({}) — {}", target, mode, title));
                }
                Some("monitor") => {
                    contained += 1;
                }
                Some("honeypot") => {
                    contained += 1;
                }
                Some("kill_process") => {
                    contained += 1;
                    actions_taken.push(format!("Killed process — {}", title));
                }
                Some("suspend_user_sudo") => {
                    contained += 1;
                    actions_taken.push(format!("Suspended sudo — {}", title));
                }
                Some("ignore") => {
                    ignored += 1;
                }
                Some(_) => {
                    contained += 1;
                }
                None => {
                    // Check if this "unresolved" incident only involves
                    // self-traffic IPs — if so, it's a pre-fix FP that
                    // wasn't marked research_only. Don't count it as
                    // needing attention.
                    let entities: Vec<String> = graph
                        .outgoing_edges(id)
                        .iter()
                        .filter(|e| e.relation == Relation::TriggeredBy)
                        .filter_map(|e| graph.get_node(e.to))
                        .filter_map(|n| {
                            if let Node::Ip { addr, .. } = n {
                                Some(addr.clone())
                            } else {
                                None
                            }
                        })
                        .collect();
                    let all_self = !entities.is_empty()
                        && entities
                            .iter()
                            .all(|ip| crate::cloud_safelist::is_self_traffic_ip(ip));
                    if all_self {
                        ignored += 1; // Treat as noise for briefing purposes
                    } else {
                        unresolved += 1;
                        let sev = severity.to_lowercase();
                        if sev == "high" || sev == "critical" {
                            unresolved_high_crit += 1;
                            let entity = entities.first().cloned().unwrap_or_default();
                            if unresolved_list.len() < 10 {
                                unresolved_list.push((sev, title.clone(), entity));
                            }
                        }
                    }
                }
            }
        }
    }

    // Top attackers — ONLY external IPs, annotate if already blocked
    let mut ip_data: std::collections::HashMap<String, (usize, Vec<String>, bool)> =
        std::collections::HashMap::new();
    for &inc_id in &incident_nodes {
        if let Some(Node::Incident {
            detector,
            decision,
            decision_target,
            research_only,
            ..
        }) = graph.get_node(inc_id)
        {
            if *research_only {
                continue;
            }
            for edge in graph.outgoing_edges(inc_id) {
                if edge.relation != Relation::TriggeredBy {
                    continue;
                }
                if let Some(Node::Ip {
                    addr, is_internal, ..
                }) = graph.get_node(edge.to)
                {
                    if *is_internal {
                        continue;
                    }
                    // Skip self-traffic IPs (cloud providers, agent services,
                    // local interfaces) — same filter as investigation.rs
                    if crate::cloud_safelist::is_self_traffic_ip(addr) {
                        continue;
                    }
                    let entry = ip_data
                        .entry(addr.clone())
                        .or_insert((0, Vec::new(), false));
                    entry.0 += 1;
                    if !entry.1.contains(detector) {
                        entry.1.push(detector.clone());
                    }
                    if decision.as_deref() == Some("block_ip")
                        && decision_target.as_deref() == Some(addr.as_str())
                    {
                        entry.2 = true; // Already blocked
                    }
                }
            }
        }
    }
    let mut top_attackers: Vec<_> = ip_data.into_iter().collect();
    top_attackers.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    top_attackers.truncate(10);

    // Detectors sorted
    let mut sorted_detectors: Vec<_> = by_detector.into_iter().collect();
    sorted_detectors.sort_by(|a, b| b.1.cmp(&a.1));
    sorted_detectors.truncate(10);

    // Threat level — based on UNRESOLVED, not total. Recomputed
    // below from the canonical counters once the snapshot is folded in.
    // This early scan-based value is unused; kept here as documentation
    // of the legacy threshold map until the threshold helper itself
    // moves into a function that takes counters as input.
    let _threat_level_legacy = if unresolved_high_crit > 5 {
        "CRITICAL"
    } else if unresolved_high_crit > 0 {
        "ELEVATED"
    } else if unresolved > 10 {
        "MODERATE"
    } else {
        "LOW"
    };

    // Count unique blocked IPs (not decisions — matches dashboard KPI).
    // Used as the legacy fallback when no snapshot is provided.
    let blocked_ips: std::collections::HashSet<&str> = actions_taken
        .iter()
        .filter_map(|a| {
            if a.starts_with("Blocked IP ") {
                a.split_whitespace().nth(2)
            } else {
                None
            }
        })
        .collect();

    // 2026-05-02 (Spec 039 P1): when an OverviewSnapshot is available,
    // use its bucket counts for the topline numbers. This is the same
    // source the dashboard tiles read, so the briefing can never paint
    // a contradictory headline ("0 needing action" while the tile
    // says "2 awaiting"). Narrative detail still comes from the KG
    // walk above.
    let counters = match snapshot {
        Some(snap) => BriefingCounters::from_snapshot(snap),
        None => BriefingCounters {
            contained,
            ignored,
            unresolved,
            unresolved_high_crit,
            blocked_ips_count: blocked_ips.len(),
        },
    };

    // Build context
    let operator_incidents = counters.contained + counters.unresolved; // excludes research_only
    let mut ctx = format!(
        "SECURITY INTELLIGENCE CONTEXT — {}\n\n\
         SITUATION STATUS:\n\
         - Operator-relevant incidents today: {}\n\
         - BLOCKED: {} unique IP{} auto-blocked by AI\n\
         - OBSERVING: {} incidents being monitored (AI is handling, no human action needed)\n\
         - IGNORED: {} confirmed non-threats\n\
         - The server uses SSH key-only authentication — password brute-force cannot succeed\n\
         - Most external activity is routine internet scanning that fails at protocol level\n\n\
         IMPORTANT: The AI is handling everything. {} of {} incidents are already resolved or being monitored.\n\
         Human attention needed: {}.\n\n",
        Utc::now().format("%Y-%m-%d"),
        operator_incidents,
        counters.blocked_ips_count,
        if counters.blocked_ips_count == 1 { "" } else { "s" },
        counters.unresolved,
        counters.ignored,
        counters.contained + counters.unresolved, operator_incidents,
        if counters.unresolved_high_crit == 0 {
            "NONE — everything is handled".to_string()
        } else {
            format!("{} high/critical items to review", counters.unresolved_high_crit)
        },
    );

    if !actions_taken.is_empty() {
        ctx.push_str("ACTIONS ALREADY TAKEN BY AI:\n");
        for (i, action) in actions_taken.iter().take(10).enumerate() {
            ctx.push_str(&format!("  {}. {}\n", i + 1, action));
        }
        if actions_taken.len() > 10 {
            ctx.push_str(&format!(
                "  ... and {} more actions\n",
                actions_taken.len() - 10
            ));
        }
        ctx.push('\n');
    }

    if !unresolved_list.is_empty() {
        ctx.push_str("UNRESOLVED THREATS NEEDING ATTENTION:\n");
        for (sev, title, entity) in &unresolved_list {
            ctx.push_str(&format!(
                "  - [{}] {} ({})\n",
                sev.to_uppercase(),
                title,
                entity
            ));
        }
        ctx.push('\n');
    }

    ctx.push_str("TOP ATTACKERS (external IPs only):\n");
    for (ip, (count, dets, blocked)) in &top_attackers {
        let status = if *blocked { " [ALREADY BLOCKED]" } else { "" };
        ctx.push_str(&format!(
            "  - {} — {} incidents, detectors: {}{}\n",
            ip,
            count,
            dets.join(", "),
            status
        ));
    }

    ctx.push_str("\nDETECTOR ACTIVITY:\n");
    for (det, count) in &sorted_detectors {
        ctx.push_str(&format!("  - {}: {}\n", det, count));
    }

    ctx.push_str(&format!(
        "\nKNOWLEDGE GRAPH: {} nodes, {} edges\n\
         EVENTS INGESTED: {}\n",
        graph.metrics().node_count,
        graph.metrics().edge_count,
        graph.total_events_ingested,
    ));

    ctx
}

/// The LLM prompt for generating the briefing.
///
/// Format-only instructions. Tone is owned by the system prompt (the bot
/// personality, plumbed via `briefing_system_prompt`). Prior revision
/// carried a second "You are the AI security agent..." framing plus a
/// "Be reassuring" / "Write for someone who is NOT a security professional"
/// line here, which fought the persona and produced consultant-speak like
/// "everything is under control" and "no further action needed".
pub fn briefing_prompt(context: &str) -> String {
    format!(
        "Write a daily briefing from the state snapshot below.\n\
         \n\
         Counting rules:\n\
         - CONTAINED/BLOCKED items are resolved. Count them, do not dramatise them.\n\
         - IGNORED items are confirmed noise. Do not mention them.\n\
         - UNRESOLVED items are being OBSERVED by the AI. Only flag the ones that \
           genuinely need a human decision.\n\
         - Quote numbers only from the snapshot below. Do not invent counts.\n\
         \n\
         Structure (under 150 words total):\n\
         1. STATUS: one line. Is the server safe right now?\n\
         2. WHAT THE AI DID: 2-3 short lines. Name the actions (blocks, monitoring, \
            honeypot redirects). Quote the totals from the snapshot.\n\
         3. NEEDS ATTENTION: omit this section entirely unless something genuinely \
            requires a human decision.\n\
         \n\
         ---\n\
         \n\
         {context}"
    )
}

/// Parse the LLM response into a structured Briefing.
pub fn parse_briefing(llm_response: &str, context_threat_level: &str) -> Briefing {
    Briefing {
        generated_at: Utc::now(),
        date: Utc::now().format("%Y-%m-%d").to_string(),
        threat_level: context_threat_level.to_string(),
        summary: llm_response.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::types::{Edge, Node, Relation};

    // parse_briefing preserves threat level and summary text
    #[test]
    fn parse_briefing_preserves_fields() {
        let briefing = parse_briefing("All clear today.", "LOW");
        assert_eq!(briefing.threat_level, "LOW");
        assert_eq!(briefing.summary, "All clear today.");
        assert!(!briefing.date.is_empty());
    }

    // parse_briefing with elevated threat level
    #[test]
    fn parse_briefing_elevated_threat_level() {
        let briefing = parse_briefing("3 unresolved threats.", "ELEVATED");
        assert_eq!(briefing.threat_level, "ELEVATED");
        assert!(briefing.summary.contains("unresolved"));
    }

    #[test]
    fn briefing_prompt_contains_context() {
        let ctx = "SITUATION STATUS:\n- Operator-relevant incidents today: 5\n";
        let prompt = briefing_prompt(ctx);
        assert!(prompt.contains("SITUATION STATUS"));
        assert!(prompt.contains("150 words"));
    }

    #[test]
    fn briefing_prompt_keeps_format_structure() {
        let prompt = briefing_prompt("test context");
        assert!(prompt.contains("STATUS"));
        assert!(prompt.contains("WHAT THE AI DID"));
        assert!(prompt.contains("NEEDS ATTENTION"));
        // Counting rules still present so the model doesn't dramatise noise.
        assert!(prompt.contains("CONTAINED"));
        assert!(prompt.contains("IGNORED"));
    }

    #[test]
    fn briefing_prompt_does_not_carry_tone_instructions() {
        // Tone is owned by the system prompt (bot personality). The user
        // message must not re-assert "Be reassuring" / "non-technical" /
        // "trusted security guard", which previously fought the persona
        // and produced consultant-speak in the output.
        let prompt = briefing_prompt("x");
        for banned in [
            "Be reassuring",
            "non-technical",
            "trusted security guard",
            "You are the AI security agent",
            "under control",
        ] {
            assert!(
                !prompt.contains(banned),
                "prompt must not include tone instruction {banned:?}",
            );
        }
    }

    fn add_incident(
        graph: &mut KnowledgeGraph,
        incident_id: &str,
        detector: &str,
        severity: &str,
        title: &str,
        ip: &str,
        decision: Option<&str>,
        decision_target: Option<&str>,
        auto_executed: bool,
        research_only: bool,
        ts: chrono::DateTime<Utc>,
    ) {
        let ip_id = graph.ensure_ip(ip, ts);
        let inc_id = graph.add_node(Node::Incident {
            incident_id: incident_id.to_string(),
            detector: detector.to_string(),
            severity: severity.to_string(),
            title: title.to_string(),
            summary: format!("{title} summary"),
            ts,
            mitre_ids: vec![],
            decision: decision.map(|d| d.to_string()),
            confidence: Some(0.9),
            decision_reason: Some("unit test".to_string()),
            decision_target: decision_target.map(|t| t.to_string()),
            auto_executed,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only,
        });
        graph.add_edge(Edge::new(inc_id, ip_id, Relation::TriggeredBy, ts));
    }

    #[test]
    fn build_briefing_context_summarizes_resolved_and_unresolved_activity() {
        crate::cloud_safelist::init();
        let now = Utc::now();
        let mut graph = KnowledgeGraph::new();

        add_incident(
            &mut graph,
            "ssh_bruteforce:203.0.113.10:1",
            "ssh_bruteforce",
            "high",
            "SSH brute-force",
            "203.0.113.10",
            Some("block_ip"),
            Some("203.0.113.10"),
            true,
            false,
            now,
        );
        add_incident(
            &mut graph,
            "port_scan:203.0.113.10:2",
            "port_scan",
            "medium",
            "Port scan",
            "203.0.113.10",
            Some("ignore"),
            None,
            false,
            false,
            now,
        );
        add_incident(
            &mut graph,
            "ransomware:198.51.100.5:3",
            "ransomware",
            "critical",
            "Ransomware behavior",
            "198.51.100.5",
            None,
            None,
            false,
            false,
            now,
        );
        add_incident(
            &mut graph,
            "self_traffic:198.18.0.1:4",
            "self_traffic",
            "low",
            "Agent cloud check",
            "198.18.0.1",
            None,
            None,
            false,
            true,
            now,
        );

        let kg = Arc::new(RwLock::new(graph));
        let context = build_briefing_context(&kg, None);

        assert!(context.contains("SECURITY INTELLIGENCE CONTEXT"));
        assert!(context.contains("ACTIONS ALREADY TAKEN BY AI"));
        assert!(context.contains("Blocked IP 203.0.113.10"));
        assert!(context.contains("UNRESOLVED THREATS NEEDING ATTENTION"));
        assert!(context.contains("[CRITICAL] Ransomware behavior"));
        assert!(context.contains("TOP ATTACKERS (external IPs only)"));
        assert!(context.contains("203.0.113.10"));
        assert!(context.contains("DETECTOR ACTIVITY"));
        assert!(context.contains("KNOWLEDGE GRAPH"));
    }

    #[test]
    fn build_briefing_context_handles_empty_graph() {
        let kg = Arc::new(RwLock::new(KnowledgeGraph::new()));
        let context = build_briefing_context(&kg, None);
        assert!(context.contains("Operator-relevant incidents today: 0"));
        assert!(context.contains("Human attention needed: NONE"));
        assert!(context.contains("TOP ATTACKERS (external IPs only):"));
    }

    // 2026-05-02 audit B1/P1 (Spec 039 P1) anchor: when an
    // OverviewSnapshot is provided, the briefing's topline counters
    // must come from the snapshot's bucket counts — NOT from a
    // separate KG scan. This is the auditor's #1 release blocker
    // (single source of truth across briefing + dashboard tiles).
    #[test]
    fn build_briefing_context_reads_topline_counters_from_snapshot() {
        use crate::dashboard::types::{
            BucketStats, DetectorCount, OutcomeBuckets, OverviewSnapshot, PendingBreakdown,
            SystemHealth,
        };
        let kg = Arc::new(RwLock::new(KnowledgeGraph::new()));

        // Counts are by UNIQUE ATTACKER — the dashboard's basis. The fixture
        // mirrors the operator-reported mismatch: dismissed has 21 INCIDENTS but
        // 11 distinct IPs, and the briefing must paint 11 (the "Filtered out"
        // tile), NOT 21 and NOT 21+allowlisted. blocked 4 / observing 2 /
        // honeypot 1 / dismissed 11 / allowlisted 1 / attention 2 distinct IPs.
        let mut attention_severities = std::collections::BTreeMap::new();
        attention_severities.insert("critical".to_string(), 1);
        attention_severities.insert("high".to_string(), 1);
        let snap = OverviewSnapshot {
            date: "2026-05-02".to_string(),
            generated_at: Utc::now(),
            health: SystemHealth::OperatingNormally,
            buckets: OutcomeBuckets {
                blocked: BucketStats {
                    incidents: 5,
                    unique_attackers: 4,
                    severities: Default::default(),
                },
                observing: BucketStats {
                    incidents: 3,
                    unique_attackers: 2,
                    severities: Default::default(),
                },
                honeypot: BucketStats {
                    incidents: 1,
                    unique_attackers: 1,
                    severities: Default::default(),
                },
                dismissed: BucketStats {
                    incidents: 21,
                    unique_attackers: 11,
                    severities: Default::default(),
                },
                allowlisted: BucketStats {
                    incidents: 6,
                    unique_attackers: 3,
                    severities: Default::default(),
                },
                attention: BucketStats {
                    incidents: 3,
                    unique_attackers: 2,
                    severities: attention_severities,
                },
            },
            pending: PendingBreakdown::default(),
            events_today: 1234,
            top_detectors: vec![DetectorCount {
                detector: "ssh_bruteforce".to_string(),
                count: 1,
            }],
        };

        let context = build_briefing_context(&kg, Some(&snap));

        // contained  = blocked.incidents + observing.incidents + honeypot.incidents = 5+3+1 = 9
        // ignored    = dismissed.unique_attackers = 11 (NOT 21 incidents, NOT + allowlisted)
        // unresolved = attention.incidents = 3
        // unresolved_high_crit = attention.severities[critical]+[high] = 1+1 = 2
        // operator_incidents = contained + unresolved = 9+3 = 12
        // blocked_ips_count = blocked.unique_attackers = 4
        assert!(
            context.contains("Operator-relevant incidents today: 12"),
            "operator_incidents stays incident-based (HUD/Report agreement); got: {context}"
        );
        assert!(
            context.contains("BLOCKED: 4 unique IPs"),
            "blocked count is unique attackers; got: {context}"
        );
        assert!(
            context.contains("OBSERVING: 3 incidents"),
            "OBSERVING uses unresolved INCIDENTS (3); got: {context}"
        );
        assert!(
            context.contains("IGNORED: 11 confirmed"),
            "IGNORED must equal dashboard 'Filtered out' = dismissed.unique_attackers (11), \
             not dismissed.incidents (21) and not + allowlisted; got: {context}"
        );
        assert!(
            context.contains("2 high/critical items to review"),
            "high/critical must use snapshot severities; got: {context}"
        );
    }

    #[test]
    fn build_briefing_context_falls_back_to_kg_when_no_snapshot() {
        // Back-compat: callers that pass `None` still use the KG scan.
        // This test pins the fallback path for the boot/cold path.
        let kg = Arc::new(RwLock::new(KnowledgeGraph::new()));
        let context = build_briefing_context(&kg, None);
        assert!(context.contains("Operator-relevant incidents today: 0"));
    }
}
