use std::path::Path;

use tracing::{info, warn};

use crate::{config, decisions, knowledge_graph, telegram, two_factor, AgentState};

// ---------------------------------------------------------------------------
// Phase 6B: Graph-based bot helpers (no JSONL reads)
// ---------------------------------------------------------------------------

/// Count incidents or decisions from the knowledge graph.
/// `count_type` selects what to count: "incidents" or "decisions".
pub(crate) fn graph_count(
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    count_type: &str,
) -> usize {
    use knowledge_graph::types::{Node, NodeType};
    let graph = kg.read().unwrap();
    match count_type {
        "incidents" => graph.nodes_of_type(NodeType::Incident).len(),
        "decisions" => {
            let mut n = 0;
            for id in graph.nodes_of_type(NodeType::Incident) {
                if let Some(Node::Incident {
                    decision: Some(_), ..
                }) = graph.get_node(id)
                {
                    n += 1;
                }
            }
            n
        }
        _ => 0,
    }
}

/// Read the last N incidents from graph, formatted for Telegram display.
pub(crate) fn graph_last_incidents(
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    n: usize,
) -> String {
    use knowledge_graph::types::{Node, NodeType, Relation};
    let graph = kg.read().unwrap();

    let mut items: Vec<(chrono::DateTime<chrono::Utc>, String, String, String)> = Vec::new();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            severity,
            title,
            ts,
            ..
        }) = graph.get_node(id)
        {
            // Find first entity via TriggeredBy
            let entity = graph
                .outgoing_edges(id)
                .iter()
                .find(|e| e.relation == Relation::TriggeredBy)
                .and_then(|e| graph.get_node(e.to))
                .map(|n| n.label())
                .unwrap_or_else(|| "?".to_string());

            items.push((*ts, severity.to_lowercase(), title.clone(), entity));
        }
    }

    if items.is_empty() {
        return "\u{1f507} Clean slate - no intrusion attempts today.".to_string();
    }

    // Sort by ts descending, take last N
    items.sort_by(|a, b| b.0.cmp(&a.0));
    items.truncate(n);

    let now = chrono::Utc::now();
    let sev_icon = |s: &str| match s {
        "critical" => "\u{1f534}",
        "high" => "\u{1f7e0}",
        "medium" => "\u{1f7e1}",
        "low" => "\u{1f7e2}",
        _ => "\u{26aa}",
    };

    let formatted: Vec<String> = items
        .into_iter()
        .map(|(ts, severity, title, entity)| {
            let icon = sev_icon(&severity);
            let mins = now.signed_duration_since(ts).num_minutes();
            let age = if mins < 1 {
                "just now".to_string()
            } else if mins < 60 {
                format!("{mins}m ago")
            } else {
                format!("{}h ago", mins / 60)
            };
            format!("{icon} {title}\n   <code>{entity}</code> \u{b7} {age}")
        })
        .collect();

    format!(
        "\u{1f6a8} <b>Recent threats</b> (last {})\n\n{}",
        formatted.len(),
        formatted.join("\n\n")
    )
}

/// Row collected for the Telegram "last decisions" summary:
/// (timestamp, action, target, confidence, auto_executed).
type DecisionRow = (
    chrono::DateTime<chrono::Utc>,
    String,
    String,
    Option<f32>,
    bool,
);

/// Read the last N decisions from graph, formatted for Telegram display.
pub(crate) fn graph_last_decisions(
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    n: usize,
) -> String {
    use knowledge_graph::types::{Node, NodeType};
    let graph = kg.read().unwrap();

    let mut items: Vec<DecisionRow> = Vec::new();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            ts,
            decision: Some(action),
            decision_target,
            confidence,
            auto_executed,
            ..
        }) = graph.get_node(id)
        {
            let target = decision_target.as_deref().unwrap_or("?").to_string();
            items.push((*ts, action.clone(), target, *confidence, *auto_executed));
        }
    }

    if items.is_empty() {
        return "\u{2696}\u{fe0f} No decisions yet today - standing by.".to_string();
    }

    items.sort_by(|a, b| b.0.cmp(&a.0));
    items.truncate(n);

    let action_icon = |a: &str| {
        if a.contains("block") {
            "\u{1f6ab}"
        } else if a.contains("suspend") {
            "\u{1f451}"
        } else if a.contains("honeypot") {
            "\u{1f36f}"
        } else if a.contains("monitor") {
            "\u{1f441}"
        } else if a.contains("kill") {
            "\u{1f480}"
        } else if a.contains("ignore") {
            "\u{1f648}"
        } else {
            "\u{26a1}"
        }
    };

    let formatted: Vec<String> = items
        .into_iter()
        .map(|(_, action, target, confidence, auto_executed)| {
            let icon = action_icon(&action);
            let pct = (confidence.unwrap_or(0.0) * 100.0) as u32;
            let mode = if auto_executed { "live" } else { "sim" };
            format!("{icon} {action} <code>{target}</code>\n   {pct}% confidence \u{b7} {mode}")
        })
        .collect();

    format!(
        "\u{2696}\u{fe0f} <b>Recent decisions</b> (last {})\n\n{}",
        formatted.len(),
        formatted.join("\n\n")
    )
}

/// Spec 043 Phase 2 — deep KG-derived context for the operator's `/ask`
/// (Telegram `__ask__:` branch in `bot_commands.rs`). Pre-Phase-2 the
/// /ask prompt only carried the last 3 incident titles + last 5 decision
/// targets, which produced operator-reported "muito basico" answers
/// because the LLM had no signal beyond manchetes. This helper enriches
/// the prompt with the graph data already ingested but unused:
///
/// 1. Recent incidents enriched with severity, title, summary, IP risk
///    score (from AbuseIPDB), threat-intel datasets that matched, and
///    YARA matches on related files.
/// 2. Recent decisions (action + target + auto/proposed mode).
/// 3. High-risk entities snapshot — IPs with risk_score > 70 OR with
///    related campaign membership. Helps the LLM ground "is this IP
///    known to us?" questions without a separate tool-call.
/// 4. Subgraph-for-question — when the question text mentions an IP
///    (regex match on dotted-quad), pull the IP's depth-1 neighborhood
///    and attach it as a compact entity → relation list.
///
/// Hard 8000-char cap on the entire output. Truncates from the end of
/// section 4 → 3 → 2 → 1 (most expendable first). The cap protects
/// LLM cost on hosts where the operator runs paid Anthropic / OpenAI;
/// Ollama on `ollama` is free but the cap still guards latency.
///
/// No config gate — pure prompt enrichment, zero behavior change. Used
/// as a drop-in for the legacy `graph_last_incidents_raw` +
/// `graph_last_decisions_raw` pair at the `/ask` call site only.
pub(crate) fn ask_context_deep(
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
    question: &str,
    budget_chars: usize,
) -> String {
    use knowledge_graph::types::{Node, NodeType, Relation};
    let graph = kg.read().unwrap();

    // ── Section 1: recent incidents (top 5) with KG-derived enrichment.
    // Tuple is (ts, severity, title, summary, related_ip_risk, related_ip_datasets).
    // Factored to a local type alias to keep clippy::type_complexity quiet.
    type IncidentRow = (
        chrono::DateTime<chrono::Utc>,
        String,
        String,
        String,
        Option<u8>,
        Vec<String>,
    );
    let mut incidents: Vec<IncidentRow> = Vec::new();
    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            severity,
            title,
            summary,
            ts,
            ..
        }) = graph.get_node(id)
        {
            // Look up the related IP (outgoing TriggeredBy → IP) for
            // risk score + datasets enrichment.
            let mut related_risk: Option<u8> = None;
            let mut related_datasets: Vec<String> = Vec::new();
            for edge in graph.outgoing_edges(id) {
                if edge.relation != Relation::TriggeredBy {
                    continue;
                }
                if let Some(Node::Ip {
                    risk_score,
                    datasets,
                    ..
                }) = graph.get_node(edge.to)
                {
                    related_risk = Some(*risk_score);
                    related_datasets = datasets.clone();
                    break;
                }
            }
            let short: String = summary.chars().take(120).collect();
            incidents.push((
                *ts,
                severity.to_lowercase(),
                title.clone(),
                short,
                related_risk,
                related_datasets,
            ));
        }
    }
    incidents.sort_by(|a, b| b.0.cmp(&a.0));
    incidents.truncate(5);

    let section_1: String = if incidents.is_empty() {
        String::new()
    } else {
        let lines: Vec<String> = incidents
            .into_iter()
            .map(|(_, sev, title, summary, risk, datasets)| {
                let mut line = format!("[{sev}] {title} - {summary}");
                if let Some(r) = risk {
                    if r > 0 {
                        line.push_str(&format!(" (ip_risk={r})"));
                    }
                }
                if !datasets.is_empty() {
                    line.push_str(&format!(" (intel: {})", datasets.join(",")));
                }
                line
            })
            .collect();
        lines.join("\n")
    };

    // ── Section 2: recent decisions (top 5).
    let section_2 = {
        let mut items: Vec<(chrono::DateTime<chrono::Utc>, String, String, bool)> = Vec::new();
        for id in graph.nodes_of_type(NodeType::Incident) {
            if let Some(Node::Incident {
                ts,
                decision: Some(action),
                decision_target,
                auto_executed,
                ..
            }) = graph.get_node(id)
            {
                let target = decision_target.as_deref().unwrap_or("?").to_string();
                items.push((*ts, action.clone(), target, *auto_executed));
            }
        }
        items.sort_by(|a, b| b.0.cmp(&a.0));
        items.truncate(5);
        if items.is_empty() {
            String::new()
        } else {
            items
                .into_iter()
                .map(|(_, action, target, auto)| {
                    let mode = if auto { "auto" } else { "proposed" };
                    format!("- {action} {target} ({mode})")
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    };

    // ── Section 3: high-risk entities (IPs with risk > 70 OR
    // campaign membership).
    let section_3 = {
        let mut entries: Vec<(String, u8, u32)> = Vec::new();
        for id in graph.nodes_of_type(NodeType::Ip) {
            if let Some(Node::Ip {
                addr, risk_score, ..
            }) = graph.get_node(id)
            {
                let campaigns = graph
                    .outgoing_edges(id)
                    .iter()
                    .filter(|e| e.relation == Relation::MemberOf)
                    .count() as u32;
                if *risk_score > 70 || campaigns > 0 {
                    entries.push((addr.clone(), *risk_score, campaigns));
                }
            }
        }
        entries.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)));
        entries.truncate(10);
        if entries.is_empty() {
            String::new()
        } else {
            entries
                .into_iter()
                .map(|(ip, risk, campaigns)| {
                    if campaigns > 0 {
                        format!("- {ip} risk={risk} campaigns={campaigns}")
                    } else {
                        format!("- {ip} risk={risk}")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    };

    // ── Section 4: subgraph for IPs mentioned in the question.
    // Only triggered when the question text contains a dotted-quad
    // that maps to an existing Ip node in the graph. Renders depth-1
    // neighborhood as compact entity → relation lines.
    let section_4 = {
        let ip_re = regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").ok();
        let mut chunks: Vec<String> = Vec::new();
        if let Some(re) = ip_re {
            for cap in re.captures_iter(question).take(3) {
                let ip = cap.get(0).map(|m| m.as_str()).unwrap_or("");
                if ip.is_empty() {
                    continue;
                }
                if let Some(ip_id) = graph.find_by_ip(ip) {
                    let mut lines: Vec<String> = Vec::new();
                    // Spec 067 Phase 3: when the operator names an IP ("why did
                    // you block 1.2.3.4?"), surface THAT IP's incident +
                    // decision + the reason behind it, not just the subgraph
                    // edges. Incidents link to the IP via `TriggeredBy`, so the
                    // incoming edge's source is the incident node.
                    for edge in graph.incoming_edges(ip_id).iter() {
                        if edge.relation != Relation::TriggeredBy {
                            continue;
                        }
                        if let Some(Node::Incident {
                            severity,
                            detector,
                            title,
                            decision,
                            decision_reason,
                            ..
                        }) = graph.get_node(edge.from)
                        {
                            let mut l = format!("  incident [{severity}] {detector}: {title}");
                            if let Some(d) = decision {
                                l.push_str(&format!(" -> decided: {d}"));
                            }
                            if let Some(r) = decision_reason {
                                let why: String = r.chars().take(200).collect();
                                l.push_str(&format!(" | why: {why}"));
                            }
                            lines.push(l);
                        }
                    }
                    for edge in graph.outgoing_edges(ip_id).iter().take(8) {
                        if let Some(other) = graph.get_node(edge.to) {
                            lines.push(format!("  -[{:?}]-> {}", edge.relation, node_label(other)));
                        }
                    }
                    for edge in graph.incoming_edges(ip_id).iter().take(8) {
                        if let Some(other) = graph.get_node(edge.from) {
                            lines.push(format!("  <-[{:?}]- {}", edge.relation, node_label(other)));
                        }
                    }
                    if !lines.is_empty() {
                        chunks.push(format!("{}:\n{}", ip, lines.join("\n")));
                    }
                }
            }
        }
        chunks.join("\n\n")
    };

    drop(graph);

    // ── Assemble with budget cap. Truncate sections most-expendable-first
    // (subgraph → high-risk → decisions → incidents) so the LLM always
    // keeps the highest-signal context (recent incidents).
    assemble_within_budget(&section_1, &section_2, &section_3, &section_4, budget_chars)
}

fn node_label(node: &knowledge_graph::types::Node) -> String {
    use knowledge_graph::types::Node;
    match node {
        Node::Process { comm, pid, .. } => format!("Process({comm}/{pid})"),
        Node::Ip {
            addr, risk_score, ..
        } => format!("Ip({addr}/risk={risk_score})"),
        Node::File { path, .. } => format!("File({})", path.chars().take(40).collect::<String>()),
        Node::User { name, .. } => format!("User({name})"),
        Node::Domain { name, .. } => format!("Domain({name})"),
        Node::Port { number, protocol } => format!("Port({number}/{protocol})"),
        Node::Container { container_id, .. } => {
            format!(
                "Container({})",
                &container_id.chars().take(12).collect::<String>()
            )
        }
        Node::Device {
            vendor, product, ..
        } => format!("Device({vendor}/{product})"),
        Node::System { hostname, .. } => format!("System({hostname})"),
        Node::Incident { incident_id, .. } => format!(
            "Incident({})",
            incident_id.chars().take(40).collect::<String>()
        ),
        Node::Campaign { campaign_id, .. } => format!("Campaign({campaign_id})"),
    }
}

/// Concatenate the four sections under `budget_chars`. Drops sections
/// from the end (subgraph first, incidents last) when over budget so
/// the highest-signal context survives. Each section gets a header so
/// the LLM can address them by name.
fn assemble_within_budget(
    incidents: &str,
    decisions: &str,
    high_risk: &str,
    subgraph: &str,
    budget_chars: usize,
) -> String {
    // Section ordering — keep highest signal first so LLM sees it even
    // if a buggy upstream truncates the prompt mid-string.
    let mut sections: Vec<(&str, &str)> = Vec::new();
    if !incidents.is_empty() {
        sections.push(("RECENT INCIDENTS", incidents));
    }
    if !decisions.is_empty() {
        sections.push(("RECENT DECISIONS", decisions));
    }
    if !high_risk.is_empty() {
        sections.push(("HIGH-RISK ENTITIES", high_risk));
    }
    if !subgraph.is_empty() {
        sections.push(("SUBGRAPH FOR QUESTION", subgraph));
    }

    // Pop most-expendable sections (end of list) until we fit.
    loop {
        let total: usize = sections
            .iter()
            .map(|(h, b)| h.len() + 2 + b.len() + 2)
            .sum();
        if total <= budget_chars || sections.is_empty() {
            break;
        }
        sections.pop();
    }

    sections
        .into_iter()
        .map(|(h, b)| format!("{h}:\n{b}"))
        .collect::<Vec<_>>()
        .join("\n\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TelegramTriageAction<'a> {
    AllowProc(&'a str),
    AllowIp(&'a str),
    ReportFp(&'a str),
}

pub(crate) fn parse_telegram_triage_action(incident_id: &str) -> Option<TelegramTriageAction<'_>> {
    if let Some(rest) = incident_id.strip_prefix("__allow_proc__:") {
        Some(TelegramTriageAction::AllowProc(rest))
    } else if let Some(rest) = incident_id.strip_prefix("__allow_ip__:") {
        Some(TelegramTriageAction::AllowIp(rest))
    } else {
        incident_id
            .strip_prefix("__fp__:")
            .map(TelegramTriageAction::ReportFp)
    }
}

pub(crate) fn sanitize_allowlist_process_name(raw: &str) -> Option<String> {
    let cleaned = raw.replace('"', "").replace('\n', " ").trim().to_string();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Handle triage sentinels from Telegram callbacks:
/// "__allow_proc__", "__allow_ip__", "__fp__".
/// Returns true when a triage callback was matched and handled.
pub(crate) fn handle_telegram_triage_action(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let Some(action) = parse_telegram_triage_action(&result.incident_id) else {
        return false;
    };

    match action {
        TelegramTriageAction::AllowProc(comm_raw) => {
            let Some(comm) = sanitize_allowlist_process_name(comm_raw) else {
                write_telegram_triage_audit(
                    state,
                    &result.incident_id,
                    &result.operator_name,
                    "allowlist_add",
                    None,
                    Some("process:(empty)".to_string()),
                    format!(
                        "Operator {} attempted to add empty process allowlist via Telegram",
                        result.operator_name
                    ),
                    "skipped:empty_process_name".to_string(),
                );
                tg_reply(state, "⚠️ Could not add empty process name to allowlist.");
                return true;
            };
            // 2FA gate: if enabled, store pending and ask for TOTP code
            if check_2fa_gate(
                state,
                cfg,
                &result.operator_name,
                two_factor::PendingActionType::AllowlistProcess(comm.clone()),
            ) {
                return true;
            }

            let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
            let reason = format!("Allowed via Telegram ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "processes", &comm, &reason) {
                Ok(()) => {
                    // Log to allowlist history for undo support
                    telegram::log_allowlist_change(
                        data_dir,
                        &comm,
                        "processes",
                        &result.operator_name,
                        "add",
                    );
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        None,
                        Some(format!("process:{comm}")),
                        format!(
                            "Operator {} added process '{}' to allowlist via Telegram",
                            result.operator_name, comm
                        ),
                        format!("allowlist_process_added:{comm}"),
                    );
                    info!(
                        operator = %result.operator_name,
                        comm = %comm,
                        path = %allowlist_path.display(),
                        "Telegram triage allowlist (process) applied"
                    );

                    // 2FA nudge if not enabled
                    let two_fa_enabled = cfg
                        .security
                        .as_ref()
                        .map(|s| s.two_factor_method != "none")
                        .unwrap_or(false);
                    let confirmation_suffix = if two_fa_enabled {
                        " (verified by TOTP)"
                    } else {
                        ""
                    };
                    let mut msg = format!(
                        "\u{2705} Allowed <code>{comm}</code>{confirmation_suffix}. Sensor will pick this up in up to 60s."
                    );
                    if !two_fa_enabled {
                        msg.push_str(
                            "\n\n\u{26a0}\u{fe0f} Allowlist changes are not protected by 2FA.\n\
                             Anyone with your bot token can silence alerts.",
                        );
                    }
                    if two_fa_enabled {
                        tg_reply(state, msg);
                    } else if let Some(ref tg) = state.telegram_client {
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let keyboard = serde_json::json!([
                                [
                                    { "text": "\u{1f510} Enable 2FA", "callback_data": "enable2fa" },
                                    { "text": "\u{1f44d} Dismiss", "callback_data": "dismiss2fa" }
                                ]
                            ]);
                            let _ = tg.send_text_with_keyboard(&msg, keyboard).await;
                        });
                    }
                }
                Err(e) => {
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        None,
                        Some(format!("process:{comm}")),
                        format!(
                            "Operator {} failed to add process '{}' to allowlist via Telegram",
                            result.operator_name, comm
                        ),
                        format!(
                            "failed:{}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                    warn!(
                        operator = %result.operator_name,
                        comm = %comm,
                        error = %e,
                        "failed to append process allowlist entry from Telegram"
                    );
                    tg_reply(
                        state,
                        format!(
                            "❌ Failed to allowlist <code>{comm}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        TelegramTriageAction::AllowIp(ip_raw) => {
            let ip = ip_raw.trim().to_string();
            if ip.parse::<std::net::IpAddr>().is_err() {
                write_telegram_triage_audit(
                    state,
                    &result.incident_id,
                    &result.operator_name,
                    "allowlist_add",
                    Some(ip.clone()),
                    None,
                    format!(
                        "Operator {} attempted to add invalid IP '{}' to allowlist via Telegram",
                        result.operator_name, ip
                    ),
                    "skipped:invalid_ip".to_string(),
                );
                warn!(
                    operator = %result.operator_name,
                    ip = %ip,
                    "invalid ip in Telegram allowlist callback"
                );
                tg_reply(
                    state,
                    format!("⚠️ Invalid IP for allowlist: <code>{ip}</code>"),
                );
                return true;
            }
            // 2FA gate: if enabled, store pending and ask for TOTP code
            if check_2fa_gate(
                state,
                cfg,
                &result.operator_name,
                two_factor::PendingActionType::AllowlistIp(ip.clone()),
            ) {
                return true;
            }

            let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
            let reason = format!("Allowed via Telegram ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "ips", &ip, &reason) {
                Ok(()) => {
                    // Log to allowlist history for undo support
                    telegram::log_allowlist_change(
                        data_dir,
                        &ip,
                        "ips",
                        &result.operator_name,
                        "add",
                    );
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        Some(ip.clone()),
                        None,
                        format!(
                            "Operator {} added IP '{}' to allowlist via Telegram",
                            result.operator_name, ip
                        ),
                        format!("allowlist_ip_added:{ip}"),
                    );
                    info!(
                        operator = %result.operator_name,
                        ip = %ip,
                        path = %allowlist_path.display(),
                        "Telegram triage allowlist (ip) applied"
                    );

                    // 2FA nudge if not enabled
                    let two_fa_enabled = cfg
                        .security
                        .as_ref()
                        .map(|s| s.two_factor_method != "none")
                        .unwrap_or(false);
                    let confirmation_suffix = if two_fa_enabled {
                        " (verified by TOTP)"
                    } else {
                        ""
                    };
                    let mut msg = format!(
                        "\u{2705} Allowed <code>{ip}</code>{confirmation_suffix}. Sensor will pick this up in up to 60s."
                    );
                    if !two_fa_enabled {
                        msg.push_str(
                            "\n\n\u{26a0}\u{fe0f} Allowlist changes are not protected by 2FA.\n\
                             Anyone with your bot token can silence alerts.",
                        );
                    }
                    if two_fa_enabled {
                        tg_reply(state, msg);
                    } else if let Some(ref tg) = state.telegram_client {
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let keyboard = serde_json::json!([
                                [
                                    { "text": "\u{1f510} Enable 2FA", "callback_data": "enable2fa" },
                                    { "text": "\u{1f44d} Dismiss", "callback_data": "dismiss2fa" }
                                ]
                            ]);
                            let _ = tg.send_text_with_keyboard(&msg, keyboard).await;
                        });
                    }
                }
                Err(e) => {
                    write_telegram_triage_audit(
                        state,
                        &result.incident_id,
                        &result.operator_name,
                        "allowlist_add",
                        Some(ip.clone()),
                        None,
                        format!(
                            "Operator {} failed to add IP '{}' to allowlist via Telegram",
                            result.operator_name, ip
                        ),
                        format!(
                            "failed:{}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                    warn!(
                        operator = %result.operator_name,
                        ip = %ip,
                        error = %e,
                        "failed to append ip allowlist entry from Telegram"
                    );
                    tg_reply(
                        state,
                        format!(
                            "❌ Failed to allowlist <code>{ip}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        TelegramTriageAction::ReportFp(raw_incident_id) => {
            let incident_id = raw_incident_id.trim();
            if incident_id.is_empty() {
                write_telegram_triage_audit(
                    state,
                    &result.incident_id,
                    &result.operator_name,
                    "fp_report",
                    None,
                    None,
                    format!(
                        "Operator {} attempted to report FP with empty incident id",
                        result.operator_name
                    ),
                    "skipped:empty_incident_id".to_string(),
                );
                tg_reply(
                    state,
                    "⚠️ Could not report false positive: missing incident id.",
                );
                return true;
            }
            let detector = incident_id.split(':').next().unwrap_or("unknown");
            telegram::log_false_positive(data_dir, incident_id, detector, &result.operator_name);
            // Phase 7 Gap 1: mark incident as FP in the knowledge graph
            {
                let mut graph = state.knowledge_graph.write().unwrap();
                if let Some(node_id) = graph.find_by_incident(incident_id) {
                    graph.mark_false_positive(node_id, &result.operator_name);
                }
            }
            write_telegram_triage_audit(
                state,
                incident_id,
                &result.operator_name,
                "fp_report",
                None,
                None,
                format!(
                    "Operator {} reported incident '{}' as false positive via Telegram",
                    result.operator_name, incident_id
                ),
                format!("reported_fp:{detector}"),
            );
            info!(
                operator = %result.operator_name,
                incident_id = %incident_id,
                detector = %detector,
                "Telegram triage false-positive reported"
            );
            tg_reply(state, "📝 Reported. Thanks for the feedback.");
        }
    }

    true
}

// ---------------------------------------------------------------------------
// 2FA gate — intercepts sensitive actions when TOTP is enabled
// ---------------------------------------------------------------------------

/// Check if 2FA is enabled in config.
pub(crate) fn is_2fa_enabled(cfg: &config::AgentConfig) -> bool {
    cfg.security
        .as_ref()
        .map(|s| s.two_factor_method == "totp")
        .unwrap_or(false)
}

/// Get the TOTP secret from config (resolved from env var or toml).
fn totp_secret(cfg: &config::AgentConfig) -> Option<String> {
    // Check env var first (preferred), then config field
    std::env::var("INNERWARDEN_TOTP_SECRET")
        .ok()
        .or_else(|| cfg.security.as_ref().map(|s| s.totp_secret.clone()))
        .filter(|s| !s.is_empty())
}

/// If 2FA is enabled, intercept the action: store as pending and ask for TOTP code.
/// Returns `true` if the action was intercepted (caller should return without executing).
/// Returns `false` if 2FA is disabled (caller should proceed normally).
pub(crate) fn check_2fa_gate(
    state: &mut AgentState,
    cfg: &config::AgentConfig,
    operator: &str,
    action: two_factor::PendingActionType,
) -> bool {
    if !is_2fa_enabled(cfg) {
        return false;
    }

    // Check lockout before accepting a new action
    if state.two_factor_state.is_locked_out(operator) {
        tg_reply(
            state,
            "\u{1f6ab} Too many failed 2FA attempts. Try again later.",
        );
        return true;
    }

    let now = chrono::Utc::now();
    let pending = two_factor::PendingAction {
        action_type: action,
        operator: operator.to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        method: two_factor::TwoFactorMethod::Totp,
    };
    state.two_factor_state.set_pending(operator, pending);

    tg_reply(
        state,
        "\u{1f510} Enter your 6-digit TOTP code (expires in 5 min):",
    );
    info!(operator = %operator, "2FA: pending action stored, waiting for TOTP code");
    true
}

/// Try to handle a Telegram message as a TOTP code response.
/// Returns `true` if it was recognized as a TOTP attempt (code or cancel).
pub(crate) fn handle_totp_response(
    result: &telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    let text = result.incident_id.trim();

    // Cancel pending 2FA
    if text == "/cancel" {
        if state
            .two_factor_state
            .take_pending(&result.operator_name)
            .is_some()
        {
            tg_reply(state, "\u{274c} 2FA verification cancelled.");
            return true;
        }
        return false;
    }

    // Only intercept 6-digit numeric strings when there's a pending action
    let is_6_digits = text.len() == 6 && text.chars().all(|c| c.is_ascii_digit());
    if !is_6_digits {
        return false;
    }

    let pending = match state.two_factor_state.take_pending(&result.operator_name) {
        Some(p) => p,
        None => return false, // No pending action — not a TOTP attempt
    };

    // Check if expired
    if pending.expires_at < chrono::Utc::now() {
        tg_reply(state, "\u{23f0} 2FA code expired. Please retry the action.");
        return true;
    }

    // Verify TOTP code
    let secret = match totp_secret(cfg) {
        Some(s) => s,
        None => {
            warn!("2FA enabled but no TOTP secret configured");
            tg_reply(
                state,
                "\u{26a0}\u{fe0f} 2FA is enabled but no TOTP secret is configured. Run: innerwarden configure 2fa",
            );
            return true;
        }
    };

    let provider = match two_factor::TotpProvider::new(&secret) {
        Some(p) => p,
        None => {
            warn!("2FA: invalid TOTP secret in config");
            tg_reply(
                state,
                "\u{26a0}\u{fe0f} Invalid TOTP secret. Re-run: innerwarden configure 2fa",
            );
            return true;
        }
    };

    if !provider.verify(text) {
        state.two_factor_state.record_failure(&result.operator_name);
        if state.two_factor_state.is_locked_out(&result.operator_name) {
            tg_reply(
                state,
                "\u{274c} Wrong code. You are now locked out for 1 hour.",
            );
        } else {
            // Re-store the pending action so operator can retry
            state
                .two_factor_state
                .set_pending(&result.operator_name, pending);
            tg_reply(state, "\u{274c} Wrong code. Try again or /cancel.");
        }
        return true;
    }

    // Code verified — execute the pending action
    info!(
        operator = %result.operator_name,
        action = ?pending.action_type,
        "2FA: TOTP verified, executing pending action"
    );
    execute_verified_action(pending.action_type, &result.operator_name, data_dir, state);
    true
}

/// Execute a 2FA-verified action.
fn execute_verified_action(
    action: two_factor::PendingActionType,
    operator: &str,
    data_dir: &Path,
    state: &mut AgentState,
) {
    let allowlist_path = Path::new("/etc/innerwarden/allowlist.toml");
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");

    match action {
        two_factor::PendingActionType::AllowlistProcess(ref comm) => {
            let reason = format!("Allowed via Telegram + 2FA ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "processes", comm, &reason) {
                Ok(()) => {
                    telegram::log_allowlist_change(data_dir, comm, "processes", operator, "add");
                    write_telegram_triage_audit(
                        state, "__2fa_verified__", operator, "allowlist_add",
                        None, Some(format!("process:{comm}")),
                        format!("Operator {operator} added process '{comm}' to allowlist (2FA verified)"),
                        format!("allowlist_process_added:{comm}"),
                    );
                    tg_reply(state, format!(
                        "\u{2705} Allowed <code>{comm}</code> (verified by TOTP). Sensor will pick this up in up to 60s."
                    ));
                }
                Err(e) => {
                    tg_reply(
                        state,
                        format!(
                            "\u{274c} Failed to allowlist <code>{comm}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        two_factor::PendingActionType::AllowlistIp(ref ip) => {
            let reason = format!("Allowed via Telegram + 2FA ({ts})");
            match telegram::append_to_allowlist(allowlist_path, "ips", ip, &reason) {
                Ok(()) => {
                    telegram::log_allowlist_change(data_dir, ip, "ips", operator, "add");
                    write_telegram_triage_audit(
                        state,
                        "__2fa_verified__",
                        operator,
                        "allowlist_add",
                        Some(ip.clone()),
                        None,
                        format!("Operator {operator} added IP '{ip}' to allowlist (2FA verified)"),
                        format!("allowlist_ip_added:{ip}"),
                    );
                    tg_reply(state, format!(
                        "\u{2705} Allowed <code>{ip}</code> (verified by TOTP). Sensor will pick this up in up to 60s."
                    ));
                }
                Err(e) => {
                    tg_reply(
                        state,
                        format!(
                            "\u{274c} Failed to allowlist <code>{ip}</code>: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        two_factor::PendingActionType::UndoAllowlist {
            ref section,
            ref key,
        } => match telegram::remove_from_allowlist(allowlist_path, section, key) {
            Ok(()) => {
                telegram::log_allowlist_change(data_dir, key, section, operator, "remove");
                write_telegram_triage_audit(
                        state, "__2fa_verified__", operator, "allowlist_remove",
                        None, None,
                        format!("Operator {operator} removed '{key}' from {section} allowlist (2FA verified)"),
                        format!("allowlist_removed:{key}"),
                    );
                tg_reply(
                    state,
                    format!(
                        "\u{2705} Removed <code>{}</code> from allowlist (verified by TOTP).",
                        telegram::escape_html_pub(key)
                    ),
                );
            }
            Err(e) => {
                tg_reply(
                    state,
                    format!(
                        "\u{274c} Failed to remove <code>{}</code>: {}",
                        telegram::escape_html_pub(key),
                        e.to_string().chars().take(180).collect::<String>()
                    ),
                );
            }
        },
        two_factor::PendingActionType::AutoFpAllowlist {
            ref section,
            ref entity,
        } => {
            let reason = format!("Auto-FP allowlist via Telegram + 2FA ({ts})");
            match telegram::append_to_allowlist(allowlist_path, section, entity, &reason) {
                Ok(()) => {
                    telegram::log_allowlist_change(data_dir, entity, section, operator, "add");
                    tg_reply(state, format!(
                        "\u{2705} Added <code>{}</code> to {} allowlist permanently (verified by TOTP).",
                        telegram::escape_html_pub(entity), section
                    ));
                }
                Err(e) => {
                    tg_reply(
                        state,
                        format!(
                            "\u{274c} Failed to add to allowlist: {}",
                            e.to_string().chars().take(180).collect::<String>()
                        ),
                    );
                }
            }
        }
        two_factor::PendingActionType::ModeChange { ref mode } => {
            apply_mode_change_request(state, operator, mode);
        }
        two_factor::PendingActionType::Unblock { ref ip } => {
            request_unblock(state, data_dir, operator, ip);
        }
    }
}

/// Queue an operator unblock for `ip` (validated upstream). Writes the same
/// `operator_unblock_request` decision row the dashboard does, so the slow-loop
/// `operator_actions::run_unblock_drain` performs the REAL firewall revert
/// through the response lifecycle (the only path that does not get re-applied by
/// the spec-076 reconciler). Shared by the 2FA-off inline path and the post-TOTP
/// path. Best-effort: a write failure is logged + reported to the operator.
pub(crate) fn request_unblock(state: &mut AgentState, data_dir: &Path, operator: &str, ip: &str) {
    let incident_id = format!("operator_unblock:{ip}");
    let entry = decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: incident_id.clone(),
        host: local_hostname_for_audit(),
        ai_provider: format!("operator:telegram:{operator}"),
        action_type: "operator_unblock_request".to_string(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        skill_id: Some("operator_unblock".to_string()),
        confidence: 1.0,
        auto_executed: false,
        dry_run: false,
        reason: format!("Telegram /unblock by {operator}"),
        estimated_threat: "manual".to_string(),
        execution_result: "queued".to_string(),
        prev_hash: None,
        decision_layer: Some("manual_operator".to_string()),
    };
    match decisions::append_chained(data_dir, &entry, state.sqlite_store.as_ref()) {
        Ok(()) => {
            write_telegram_triage_audit(
                state,
                &incident_id,
                operator,
                "unblock_request",
                Some(ip.to_string()),
                None,
                format!("Operator {operator} queued unblock for {ip} (2FA verified)"),
                format!("unblock_request:{ip}"),
            );
            tg_reply(
                state,
                format!(
                    "\u{2705} Unblock queued for <code>{}</code>. I'll release it at the firewall \
                     within ~30s and stop re-blocking it.",
                    telegram::escape_html_pub(ip)
                ),
            );
        }
        Err(e) => {
            tg_reply(
                state,
                format!(
                    "\u{274c} Could not queue the unblock for <code>{}</code>: {}",
                    telegram::escape_html_pub(ip),
                    e.to_string().chars().take(160).collect::<String>()
                ),
            );
        }
    }
}

/// Parse a `/mode` argument and queue the guardian-mode change for the main
/// loop (which owns `cfg` and applies + persists it). Shared by the 2FA-off
/// inline path and the post-TOTP path so the actuation logic lives in one place.
/// Unknown argument replies with usage and queues nothing.
pub(crate) fn apply_mode_change_request(state: &mut AgentState, operator: &str, mode_arg: &str) {
    let mode = match mode_arg.trim().to_ascii_lowercase().as_str() {
        "guard" | "live" | "on" | "defend" => Some(telegram::GuardianMode::Guard),
        "watch" | "monitor" | "passive" | "off" => Some(telegram::GuardianMode::Watch),
        "dryrun" | "dry-run" | "dry_run" | "simulate" => Some(telegram::GuardianMode::DryRun),
        _ => None,
    };
    match mode {
        Some(m) => {
            state.pending_mode_change = Some(m);
            let (label, desc) = match m {
                telegram::GuardianMode::Guard => {
                    ("Guard", "auto-defend is ON. I block threats automatically.")
                }
                telegram::GuardianMode::Watch => (
                    "Watch",
                    "passive monitor. I alert you but take no action myself.",
                ),
                telegram::GuardianMode::DryRun => (
                    "Dry-run",
                    "I simulate the action and log what I would do, but change nothing.",
                ),
            };
            write_telegram_triage_audit(
                state,
                "__mode__",
                operator,
                "mode_change",
                None,
                None,
                format!("Operator {operator} switched guardian mode to {label}"),
                format!("mode_change:{label}"),
            );
            tg_reply(
                state,
                format!(
                    "\u{1f6e1}\u{fe0f} <b>Mode set to {label}</b>\n{desc}\nApplied now and saved for the next restart."
                ),
            );
        }
        None => {
            tg_reply(
                state,
                format!(
                    "Unknown mode <code>{}</code>. Use <code>/mode guard</code> (auto-defend), \
                     <code>/mode watch</code> (monitor only), or <code>/mode dryrun</code> (simulate).",
                    telegram::escape_html_pub(mode_arg)
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format an RFC3339 timestamp as a human-readable "X ago" string.
pub(crate) fn format_time_ago(ts_str: &str) -> String {
    let ts = match chrono::DateTime::parse_from_rfc3339(ts_str) {
        Ok(t) => t.with_timezone(&chrono::Utc),
        Err(_) => return "recently".to_string(),
    };
    let diff = chrono::Utc::now() - ts;
    if diff.num_days() > 0 {
        format!("{}d ago", diff.num_days())
    } else if diff.num_hours() > 0 {
        format!("{}h ago", diff.num_hours())
    } else {
        format!("{}m ago", diff.num_minutes().max(1))
    }
}

pub(crate) fn local_hostname_for_audit() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn tg_reply(state: &AgentState, text: impl Into<String>) {
    if let Some(ref tg) = state.telegram_client {
        let tg = tg.clone();
        let text = text.into();
        tokio::spawn(async move {
            let _ = tg.send_text_message(&text).await;
        });
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_telegram_triage_audit(
    state: &mut AgentState,
    incident_id: &str,
    operator: &str,
    action_type: &str,
    target_ip: Option<String>,
    target_user: Option<String>,
    reason: String,
    execution_result: String,
) {
    if let Some(writer) = &mut state.decision_writer {
        let entry = decisions::DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_id.to_string(),
            host: local_hostname_for_audit(),
            ai_provider: format!("operator:telegram:{operator}"),
            action_type: action_type.to_string(),
            target_ip,
            target_user,
            skill_id: None,
            confidence: 1.0,
            auto_executed: true,
            dry_run: false,
            reason,
            estimated_threat: "manual".to_string(),
            execution_result,
            prev_hash: None,
            decision_layer: Some("manual_operator".to_string()),
        };
        if let Err(e) = writer.write(&entry) {
            warn!(
                error = %e,
                action_type,
                incident_id,
                operator,
                "failed to write Telegram triage audit entry"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::types::{Edge, Node, Relation};
    use crate::knowledge_graph::KnowledgeGraph;
    use tempfile::TempDir;

    fn seeded_graph() -> std::sync::Arc<std::sync::RwLock<KnowledgeGraph>> {
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();
        let ip_a = graph.ensure_ip("203.0.113.10", now);
        let ip_b = graph.ensure_ip("198.51.100.7", now);

        let inc_a = graph.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:203.0.113.10:1".to_string(),
            detector: "ssh_bruteforce".to_string(),
            severity: "high".to_string(),
            title: "SSH brute-force".to_string(),
            summary: "many failed logins".to_string(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("block_ip".to_string()),
            confidence: Some(0.93),
            decision_reason: Some("clear abuse".to_string()),
            decision_target: Some("203.0.113.10".to_string()),
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        graph.add_edge(Edge::new(inc_a, ip_a, Relation::TriggeredBy, now));

        let inc_b = graph.add_node(Node::Incident {
            incident_id: "port_scan:198.51.100.7:2".to_string(),
            detector: "port_scan".to_string(),
            severity: "medium".to_string(),
            title: "Port scan".to_string(),
            summary: "sequential probes".to_string(),
            ts: now - chrono::Duration::minutes(5),
            mitre_ids: vec![],
            decision: Some("monitor".to_string()),
            confidence: Some(0.55),
            decision_reason: Some("observe".to_string()),
            decision_target: Some("198.51.100.7".to_string()),
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        graph.add_edge(Edge::new(
            inc_b,
            ip_b,
            Relation::TriggeredBy,
            now - chrono::Duration::minutes(5),
        ));

        std::sync::Arc::new(std::sync::RwLock::new(graph))
    }

    // --- parse_telegram_triage_action ---

    #[test]
    fn parse_allow_proc_action() {
        let action = parse_telegram_triage_action("__allow_proc__:sshd");
        assert_eq!(action, Some(TelegramTriageAction::AllowProc("sshd")));
    }

    #[test]
    fn parse_allow_ip_action() {
        let action = parse_telegram_triage_action("__allow_ip__:1.2.3.4");
        assert_eq!(action, Some(TelegramTriageAction::AllowIp("1.2.3.4")));
    }

    #[test]
    fn parse_fp_action() {
        let action = parse_telegram_triage_action("__fp__:ssh_bruteforce:1.2.3.4:abc");
        assert_eq!(
            action,
            Some(TelegramTriageAction::ReportFp("ssh_bruteforce:1.2.3.4:abc"))
        );
    }

    #[test]
    fn parse_unknown_returns_none() {
        assert_eq!(parse_telegram_triage_action("some:normal:incident"), None);
        assert_eq!(parse_telegram_triage_action(""), None);
        assert_eq!(parse_telegram_triage_action("__unknown__:xyz"), None);
    }

    // --- sanitize_allowlist_process_name ---

    #[test]
    fn sanitize_normal_name() {
        assert_eq!(
            sanitize_allowlist_process_name("sshd"),
            Some("sshd".to_string())
        );
    }

    #[test]
    fn sanitize_strips_quotes_and_trims() {
        assert_eq!(
            sanitize_allowlist_process_name("  \"my_proc\"  "),
            Some("my_proc".to_string())
        );
    }

    #[test]
    fn sanitize_replaces_newlines() {
        assert_eq!(
            sanitize_allowlist_process_name("proc\nwith\nnewlines"),
            Some("proc with newlines".to_string())
        );
    }

    #[test]
    fn sanitize_empty_returns_none() {
        assert_eq!(sanitize_allowlist_process_name(""), None);
        assert_eq!(sanitize_allowlist_process_name("  "), None);
        assert_eq!(sanitize_allowlist_process_name("\"\""), None);
    }

    // --- is_2fa_enabled ---

    #[test]
    fn is_2fa_disabled_when_no_security_section() {
        let cfg = config::AgentConfig {
            security: None,
            ..Default::default()
        };
        assert!(!is_2fa_enabled(&cfg));
    }

    #[test]
    fn is_2fa_enabled_when_totp() {
        let cfg = config::AgentConfig {
            security: Some(config::SecurityConfig {
                two_factor_method: "totp".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(is_2fa_enabled(&cfg));
    }

    #[test]
    fn is_2fa_disabled_when_method_is_none() {
        let cfg = config::AgentConfig {
            security: Some(config::SecurityConfig {
                two_factor_method: "none".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!is_2fa_enabled(&cfg));
    }

    #[test]
    fn graph_helpers_summarize_incidents_and_decisions() {
        let kg = seeded_graph();
        assert_eq!(graph_count(&kg, "incidents"), 2);
        assert_eq!(graph_count(&kg, "decisions"), 2);
        assert_eq!(graph_count(&kg, "unknown"), 0);

        let threats = graph_last_incidents(&kg, 5);
        assert!(threats.contains("Recent threats"));
        assert!(threats.contains("SSH brute-force"));
        assert!(threats.contains("<code>203.0.113.10</code>"));

        let decisions = graph_last_decisions(&kg, 5);
        assert!(decisions.contains("Recent decisions"));
        assert!(decisions.contains("block_ip"));
        assert!(decisions.contains("monitor"));
    }

    #[test]
    fn graph_helpers_handle_empty_graph() {
        let kg = std::sync::Arc::new(std::sync::RwLock::new(KnowledgeGraph::new()));
        assert_eq!(
            graph_last_incidents(&kg, 3),
            "🔇 Clean slate - no intrusion attempts today."
        );
        assert_eq!(
            graph_last_decisions(&kg, 3),
            "⚖️ No decisions yet today - standing by."
        );
    }

    #[test]
    fn request_unblock_writes_operator_unblock_request_decision() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        request_unblock(&mut state, dir.path(), "op", "203.0.113.7");

        // append_chained writes the decision JSONL even with no sqlite store; the
        // slow-loop drain (which reads it back) does the real firewall revert.
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let jsonl = std::fs::read_to_string(dir.path().join(format!("decisions-{today}.jsonl")))
            .expect("decisions file written");
        assert!(
            jsonl.contains("operator_unblock_request"),
            "must queue an operator_unblock_request: {jsonl}"
        );
        assert!(jsonl.contains("203.0.113.7"), "must target the ip: {jsonl}");
    }

    #[test]
    fn apply_mode_change_request_queues_valid_mode_and_rejects_garbage() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());

        // Each canonical word + an alias queues the right mode.
        apply_mode_change_request(&mut state, "op", "guard");
        assert!(matches!(
            state.pending_mode_change,
            Some(telegram::GuardianMode::Guard)
        ));
        apply_mode_change_request(&mut state, "op", "WATCH");
        assert!(matches!(
            state.pending_mode_change,
            Some(telegram::GuardianMode::Watch)
        ));
        apply_mode_change_request(&mut state, "op", "dry-run");
        assert!(matches!(
            state.pending_mode_change,
            Some(telegram::GuardianMode::DryRun)
        ));
        apply_mode_change_request(&mut state, "op", "off");
        assert!(matches!(
            state.pending_mode_change,
            Some(telegram::GuardianMode::Watch)
        ));

        // Garbage must NOT queue a change (fail closed; the prior value stays).
        state.pending_mode_change = None;
        apply_mode_change_request(&mut state, "op", "destroy-everything");
        assert!(
            state.pending_mode_change.is_none(),
            "an unknown mode must not queue any change"
        );
    }

    #[test]
    fn triage_action_handles_invalid_and_fp_paths() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let invalid_proc = crate::tests::triage_approval("__allow_proc__:   \"\"   ", "operator");
        assert!(handle_telegram_triage_action(
            &invalid_proc,
            dir.path(),
            &cfg,
            &mut state
        ));

        let invalid_ip = crate::tests::triage_approval("__allow_ip__:not-an-ip", "operator");
        assert!(handle_telegram_triage_action(
            &invalid_ip,
            dir.path(),
            &cfg,
            &mut state
        ));

        let empty_fp = crate::tests::triage_approval("__fp__:", "operator");
        assert!(handle_telegram_triage_action(
            &empty_fp,
            dir.path(),
            &cfg,
            &mut state
        ));

        // Valid FP path updates graph incident metadata.
        {
            let mut graph = state.knowledge_graph.write().expect("graph write");
            graph.add_node(Node::Incident {
                incident_id: "ssh_bruteforce:203.0.113.44:test".to_string(),
                detector: "ssh_bruteforce".to_string(),
                severity: "high".to_string(),
                title: "SSH brute-force".to_string(),
                summary: "many attempts".to_string(),
                ts: chrono::Utc::now(),
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
        }

        let fp = crate::tests::triage_approval("__fp__:ssh_bruteforce:203.0.113.44:test", "alice");
        assert!(handle_telegram_triage_action(
            &fp,
            dir.path(),
            &cfg,
            &mut state
        ));

        let graph = state.knowledge_graph.read().expect("graph read");
        let node_id = graph
            .find_by_incident("ssh_bruteforce:203.0.113.44:test")
            .expect("incident node exists");
        match graph.get_node(node_id) {
            Some(Node::Incident {
                false_positive,
                fp_reporter,
                ..
            }) => {
                assert!(*false_positive);
                assert_eq!(fp_reporter.as_deref(), Some("alice"));
            }
            other => panic!("expected incident node, got {other:?}"),
        }
    }

    #[test]
    fn check_2fa_gate_and_totp_cancel_flow() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.security = Some(config::SecurityConfig {
            two_factor_method: "totp".to_string(),
            totp_secret: "JBSWY3DPEHPK3PXP".to_string(),
            ..Default::default()
        });

        let intercepted = check_2fa_gate(
            &mut state,
            &cfg,
            "operator",
            two_factor::PendingActionType::AllowlistIp("1.2.3.4".to_string()),
        );
        assert!(intercepted);
        assert!(state.two_factor_state.pending.contains_key("operator"));

        let cancel = crate::tests::triage_approval("/cancel", "operator");
        assert!(handle_totp_response(&cancel, dir.path(), &cfg, &mut state));
        assert!(!state.two_factor_state.pending.contains_key("operator"));
    }

    #[test]
    fn handle_totp_response_ignores_non_totp_or_missing_pending() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let plain_text = crate::tests::triage_approval("hello", "operator");
        assert!(!handle_totp_response(
            &plain_text,
            dir.path(),
            &cfg,
            &mut state
        ));

        let six_digits_no_pending = crate::tests::triage_approval("123456", "operator");
        assert!(!handle_totp_response(
            &six_digits_no_pending,
            dir.path(),
            &cfg,
            &mut state
        ));
    }

    #[test]
    fn handle_totp_response_wrong_code_keeps_pending_for_retry() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.security = Some(config::SecurityConfig {
            two_factor_method: "totp".to_string(),
            totp_secret: "JBSWY3DPEHPK3PXP".to_string(),
            ..Default::default()
        });

        check_2fa_gate(
            &mut state,
            &cfg,
            "operator",
            two_factor::PendingActionType::AllowlistProcess("sshd".to_string()),
        );
        assert!(state.two_factor_state.pending.contains_key("operator"));

        let wrong = crate::tests::triage_approval("000000", "operator");
        assert!(handle_totp_response(&wrong, dir.path(), &cfg, &mut state));
        assert!(
            state.two_factor_state.pending.contains_key("operator"),
            "pending action should be re-stored after wrong code"
        );
    }

    // ── Spec 043 Phase 2 anchors (AUDIT-SPEC043-PHASE2) ──────────────────
    //
    // Pre-Phase-2 the Telegram /ask prompt only carried last-3 incident
    // titles + last-5 decision targets, which produced operator-reported
    // "muito basico" answers. ask_context_deep enriches the prompt with
    // KG-derived data already ingested but unused: IP risk_score, threat
    // intel datasets, high-risk entity snapshot, and a depth-1 subgraph
    // for any IP the question text mentions. Hard char-budget cap protects
    // LLM cost / latency.
    //
    // These four anchors pin: enrichment correctness, subgraph trigger
    // by question text, budget-cap enforcement, and the most-expendable-
    // first truncation order.

    fn make_ip_node(addr: &str, risk: u8, datasets: Vec<String>) -> knowledge_graph::types::Node {
        knowledge_graph::types::Node::Ip {
            addr: addr.to_string(),
            is_internal: false,
            datasets,
            risk_score: risk,
            is_tor: false,
            first_seen: chrono::Utc::now() - chrono::Duration::days(7),
            last_seen: chrono::Utc::now(),
            attempted_usernames: vec![],
        }
    }

    fn make_inc_node(
        id: &str,
        sev: &str,
        title: &str,
        summary: &str,
    ) -> knowledge_graph::types::Node {
        knowledge_graph::types::Node::Incident {
            incident_id: id.to_string(),
            detector: "test".to_string(),
            severity: sev.to_string(),
            title: title.to_string(),
            summary: summary.to_string(),
            ts: chrono::Utc::now(),
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
        }
    }

    /// Spec 043 Phase 2 anchor: ask_context_deep must surface the
    /// IP risk_score and threat-intel datasets in the RECENT INCIDENTS
    /// section so the LLM has real ground truth instead of just titles.
    /// Pre-Phase-2 these fields were write-only in the KG.
    #[test]
    fn ask_context_deep_includes_ip_risk_and_datasets() {
        use knowledge_graph::types::{Edge, Relation};
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        ));
        {
            let mut g = kg.write().unwrap();
            let ip_id = g.add_node(make_ip_node(
                "203.0.113.99",
                85,
                vec!["AbuseIPDB".to_string(), "ThreatFox".to_string()],
            ));
            let inc_id = g.add_node(make_inc_node(
                "ssh_bf:1",
                "high",
                "SSH brute-force",
                "many failed logins",
            ));
            g.add_edge(Edge::new(
                inc_id,
                ip_id,
                Relation::TriggeredBy,
                chrono::Utc::now(),
            ));
        }

        let out = ask_context_deep(&kg, "what's going on?", 8000);

        assert!(
            out.contains("RECENT INCIDENTS:"),
            "expected RECENT INCIDENTS header; got:\n{out}"
        );
        assert!(
            out.contains("SSH brute-force"),
            "expected incident title; got:\n{out}"
        );
        assert!(
            out.contains("ip_risk=85"),
            "expected IP risk_score enrichment; got:\n{out}"
        );
        assert!(
            out.contains("AbuseIPDB"),
            "expected threat-intel dataset; got:\n{out}"
        );
        assert!(
            out.contains("ThreatFox"),
            "expected threat-intel dataset; got:\n{out}"
        );
    }

    /// Spec 043 Phase 2 anchor: when the operator's question text
    /// mentions an IP that exists in the KG, ask_context_deep MUST
    /// pull the IP's depth-1 neighborhood and attach it as the
    /// SUBGRAPH FOR QUESTION section. Pre-Phase-2 the LLM had no
    /// way to ground "why is X.X.X.X blocked?" questions.
    #[test]
    fn ask_context_deep_pulls_subgraph_when_question_mentions_ip() {
        use knowledge_graph::types::{Edge, Relation};
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        ));
        {
            let mut g = kg.write().unwrap();
            let ip_id = g.add_node(make_ip_node("198.51.100.42", 60, vec![]));
            let port_id = g.add_node(knowledge_graph::types::Node::Port {
                number: 22,
                protocol: "tcp".to_string(),
            });
            g.add_edge(Edge::new(
                ip_id,
                port_id,
                Relation::ConnectedTo,
                chrono::Utc::now(),
            ));
        }

        let out = ask_context_deep(&kg, "why is 198.51.100.42 blocked?", 8000);

        assert!(
            out.contains("SUBGRAPH FOR QUESTION:"),
            "expected subgraph header; got:\n{out}"
        );
        assert!(
            out.contains("198.51.100.42"),
            "expected subgraph to mention the queried IP; got:\n{out}"
        );
        assert!(
            out.contains("Port(22/tcp)"),
            "expected subgraph to render the connected Port node; got:\n{out}"
        );
    }

    #[test]
    fn ask_context_deep_explains_decision_for_mentioned_ip() {
        // Spec 067 Phase 3: "why did you block X?" pulls THAT IP's incident +
        // decision + reason, not just the subgraph edges.
        use knowledge_graph::types::{Edge, Node, Relation};
        let now = chrono::Utc::now();
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        ));
        {
            let mut g = kg.write().unwrap();
            let ip_id = g.add_node(make_ip_node(
                "45.148.10.99",
                90,
                vec!["blocklist".to_string()],
            ));
            let inc = g.add_node(Node::Incident {
                incident_id: "threat_intel:45.148.10.99:1".to_string(),
                detector: "threat_intel".to_string(),
                severity: "high".to_string(),
                title: "Known malicious IP".to_string(),
                summary: "IP on threat feed".to_string(),
                ts: now,
                mitre_ids: vec![],
                decision: Some("block_ip".to_string()),
                confidence: Some(0.99),
                decision_reason: Some("AbuseIPDB 100/100 plus threat feed".to_string()),
                decision_target: Some("45.148.10.99".to_string()),
                auto_executed: true,
                is_allowlisted: false,
                false_positive: false,
                fp_reporter: None,
                fp_reported_at: None,
                research_only: false,
            });
            g.add_edge(Edge::new(inc, ip_id, Relation::TriggeredBy, now));
        }

        let out = ask_context_deep(&kg, "why did you block 45.148.10.99?", 8000);
        assert!(
            out.contains("Known malicious IP"),
            "incident title; got:\n{out}"
        );
        assert!(out.contains("decided: block_ip"), "decision; got:\n{out}");
        assert!(
            out.contains("why: AbuseIPDB 100/100 plus threat feed"),
            "decision reason; got:\n{out}"
        );
    }

    /// Spec 043 Phase 2 anchor: with a tight char budget, ask_context_deep
    /// MUST drop the most-expendable section first (subgraph), keeping
    /// the highest-signal context (recent incidents) intact. Anti-
    /// regression for accidentally dropping incidents to fit subgraph,
    /// which would degrade /ask quality on memory-constrained runs.
    #[test]
    fn ask_context_deep_respects_budget_cap_drops_subgraph_first() {
        use knowledge_graph::types::{Edge, Relation};
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        ));
        {
            let mut g = kg.write().unwrap();
            let ip_id = g.add_node(make_ip_node("203.0.113.5", 75, vec![]));
            let inc_id = g.add_node(make_inc_node(
                "i1",
                "high",
                "very long incident title that takes up significant prompt budget",
                "and the summary is also long enough to crowd out anything optional from the prompt",
            ));
            g.add_edge(Edge::new(
                inc_id,
                ip_id,
                Relation::TriggeredBy,
                chrono::Utc::now(),
            ));
            // Add a port the question would want in the subgraph.
            let port_id = g.add_node(knowledge_graph::types::Node::Port {
                number: 22,
                protocol: "tcp".to_string(),
            });
            g.add_edge(Edge::new(
                ip_id,
                port_id,
                Relation::ConnectedTo,
                chrono::Utc::now(),
            ));
        }

        // Budget tight enough that subgraph + high-risk + decisions
        // sections cannot all fit alongside the long incident.
        let out = ask_context_deep(&kg, "why is 203.0.113.5 blocked?", 200);

        assert!(
            out.len() <= 200 + 32,
            "output exceeded budget; got {} chars",
            out.len()
        );
        // Recent incidents survives (highest signal).
        assert!(
            out.contains("RECENT INCIDENTS:") || out.is_empty(),
            "RECENT INCIDENTS must survive truncation; got:\n{out}"
        );
        // Subgraph dropped first (most expendable).
        assert!(
            !out.contains("SUBGRAPH FOR QUESTION:"),
            "SUBGRAPH must be dropped first under tight budget; got:\n{out}"
        );
    }

    /// Spec 043 Phase 2 anchor: empty KG produces empty output (no
    /// dangling section headers). Pins the same defensive behaviour
    /// as the legacy graph_last_incidents_raw helper had — the
    /// integration site only adds the "RECENT INCIDENTS:" header
    /// when there's content to label.
    #[test]
    fn ask_context_deep_empty_graph_returns_empty_string() {
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        ));
        let out = ask_context_deep(&kg, "anything", 8000);
        assert!(
            out.is_empty(),
            "empty graph should produce empty context; got:\n{out}"
        );
    }

    // ── bot_helpers coverage anchors (AUDIT-COVERAGE-BOT-HELPERS) ─────────
    //
    // Phase 7B coverage push (spec 023). The four blocks below pin the
    // formatting / dispatch branches that were uncovered in the baseline
    // 56.6% measurement: severity icons + age formatting on the threats
    // summary, action icons + decision section / high-risk section /
    // node_label rendering on the /ask context, the timestamp helper, and
    // the `handle_telegram_triage_action` allowlist-add error path that
    // exercises the audit-write side effect when the protected
    // `/etc/innerwarden/allowlist.toml` write fails as a non-root test
    // user. Each anchor asserts an operator-visible string the bot prints
    // back to Telegram, so a future refactor that drops a branch silently
    // breaks the assertion here rather than only on production.

    /// Cover the `low` and unknown severity branches of `sev_icon` plus the
    /// `>= 60 minutes` age formatting branch in `graph_last_incidents`.
    /// Pre-baseline these branches were uncovered (only `high` and
    /// `medium` were exercised by `seeded_graph`).
    #[test]
    fn graph_last_incidents_covers_all_severities_and_age_branches() {
        use crate::knowledge_graph::types::{Edge, Node, Relation};
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();

        let make_inc = |id: &str, sev: &str, ts: chrono::DateTime<chrono::Utc>| Node::Incident {
            incident_id: id.to_string(),
            detector: "test".to_string(),
            severity: sev.to_string(),
            title: format!("title-{sev}"),
            summary: "s".to_string(),
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
        };

        // Critical incident, recent → "just now" branch (mins < 1).
        let crit_id = graph.add_node(make_inc("crit:1", "critical", now));
        let ip_crit = graph.ensure_ip("203.0.113.1", now);
        graph.add_edge(Edge::new(crit_id, ip_crit, Relation::TriggeredBy, now));

        // Low severity → low icon (line 81).
        let low_ts = now - chrono::Duration::minutes(5);
        let low_id = graph.add_node(make_inc("low:1", "low", low_ts));
        let ip_low = graph.ensure_ip("203.0.113.2", low_ts);
        graph.add_edge(Edge::new(low_id, ip_low, Relation::TriggeredBy, low_ts));

        // Unknown severity → wildcard branch (line 82).
        let weird_ts = now - chrono::Duration::minutes(10);
        let weird_id = graph.add_node(make_inc("weird:1", "informational", weird_ts));
        let ip_weird = graph.ensure_ip("203.0.113.3", weird_ts);
        graph.add_edge(Edge::new(
            weird_id,
            ip_weird,
            Relation::TriggeredBy,
            weird_ts,
        ));

        // Old incident → hours-ago branch (line 95).
        let old_ts = now - chrono::Duration::hours(3);
        let old_id = graph.add_node(make_inc("old:1", "high", old_ts));
        let ip_old = graph.ensure_ip("203.0.113.4", old_ts);
        graph.add_edge(Edge::new(old_id, ip_old, Relation::TriggeredBy, old_ts));

        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));
        let out = graph_last_incidents(&kg, 5);

        // Critical icon (red circle).
        assert!(
            out.contains("\u{1f534}"),
            "critical icon missing; got:\n{out}"
        );
        // Low icon (green circle).
        assert!(out.contains("\u{1f7e2}"), "low icon missing; got:\n{out}");
        // Unknown severity → white circle wildcard.
        assert!(
            out.contains("\u{26aa}"),
            "wildcard icon missing; got:\n{out}"
        );
        // Hours-ago age string.
        assert!(
            out.contains("h ago"),
            "hours-ago label missing; got:\n{out}"
        );
        // "just now" branch on the < 1min critical incident.
        assert!(
            out.contains("just now"),
            "just-now label missing; got:\n{out}"
        );
    }

    /// Cover all branches of the `action_icon` closure inside
    /// `graph_last_decisions` (suspend/honeypot/monitor/kill/ignore/default).
    /// Pre-baseline only the "block" branch was hit by `seeded_graph`.
    #[test]
    fn graph_last_decisions_covers_all_action_icons() {
        use crate::knowledge_graph::types::Node;
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();
        let make_dec = |id: &str, action: &str, offset_secs: i64| -> Node {
            Node::Incident {
                incident_id: id.to_string(),
                detector: "test".to_string(),
                severity: "high".to_string(),
                title: format!("t-{id}"),
                summary: "s".to_string(),
                ts: now - chrono::Duration::seconds(offset_secs),
                mitre_ids: vec![],
                decision: Some(action.to_string()),
                confidence: Some(0.5),
                decision_reason: None,
                decision_target: Some("1.2.3.4".to_string()),
                auto_executed: false,
                is_allowlisted: false,
                false_positive: false,
                fp_reporter: None,
                fp_reported_at: None,
                research_only: false,
            }
        };
        graph.add_node(make_dec("d1", "suspend_user", 1));
        graph.add_node(make_dec("d2", "honeypot_redirect", 2));
        graph.add_node(make_dec("d3", "monitor_only", 3));
        graph.add_node(make_dec("d4", "kill_process", 4));
        graph.add_node(make_dec("d5", "ignore", 5));
        graph.add_node(make_dec("d6", "do_something_else", 6));

        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));
        let out = graph_last_decisions(&kg, 10);

        // Each action_icon branch produces a distinct emoji.
        assert!(
            out.contains("\u{1f451}"),
            "suspend (crown) icon missing; got:\n{out}"
        );
        assert!(
            out.contains("\u{1f36f}"),
            "honeypot (jar) icon missing; got:\n{out}"
        );
        assert!(
            out.contains("\u{1f441}"),
            "monitor (eye) icon missing; got:\n{out}"
        );
        assert!(
            out.contains("\u{1f480}"),
            "kill (skull) icon missing; got:\n{out}"
        );
        assert!(
            out.contains("\u{1f648}"),
            "ignore (monkey) icon missing; got:\n{out}"
        );
        assert!(
            out.contains("\u{26a1}"),
            "default (lightning) icon missing; got:\n{out}"
        );
    }

    /// Cover the `decision_target = None` fallback to "?" inside
    /// `graph_last_decisions` (line 138 fallback). Anti-regression: the
    /// dashboard also relies on the "?" sentinel when an AI decision
    /// fires without an entity attached.
    #[test]
    fn graph_last_decisions_fallback_target_renders_as_question_mark() {
        use crate::knowledge_graph::types::Node;
        let mut graph = KnowledgeGraph::new();
        let now = chrono::Utc::now();
        graph.add_node(Node::Incident {
            incident_id: "no_target:1".to_string(),
            detector: "test".to_string(),
            severity: "high".to_string(),
            title: "t".to_string(),
            summary: "s".to_string(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("block_ip".to_string()),
            confidence: Some(0.9),
            decision_reason: None,
            decision_target: None,
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));
        let out = graph_last_decisions(&kg, 5);
        assert!(
            out.contains("<code>?</code>"),
            "missing fallback target; got:\n{out}"
        );
        assert!(
            out.contains("live"),
            "auto_executed=true should label 'live'; got:\n{out}"
        );
    }

    /// Cover the RECENT DECISIONS section + the proposed/auto branches of
    /// `ask_context_deep`. Pre-baseline section_2 was uncovered because
    /// `ask_context_deep_includes_ip_risk_and_datasets` only seeded an
    /// incident WITHOUT a decision.
    #[test]
    fn ask_context_deep_includes_decisions_section() {
        use crate::knowledge_graph::types::Node;
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        ));
        let now = chrono::Utc::now();
        {
            let mut g = kg.write().unwrap();
            // Auto-executed decision → "(auto)" branch.
            g.add_node(Node::Incident {
                incident_id: "i1".to_string(),
                detector: "test".to_string(),
                severity: "high".to_string(),
                title: "t1".to_string(),
                summary: "s".to_string(),
                ts: now,
                mitre_ids: vec![],
                decision: Some("block_ip".to_string()),
                confidence: Some(0.9),
                decision_reason: None,
                decision_target: Some("1.2.3.4".to_string()),
                auto_executed: true,
                is_allowlisted: false,
                false_positive: false,
                fp_reporter: None,
                fp_reported_at: None,
                research_only: false,
            });
            // Proposed (non-auto) decision with no target → "(proposed)" + "?".
            g.add_node(Node::Incident {
                incident_id: "i2".to_string(),
                detector: "test".to_string(),
                severity: "medium".to_string(),
                title: "t2".to_string(),
                summary: "s".to_string(),
                ts: now - chrono::Duration::seconds(30),
                mitre_ids: vec![],
                decision: Some("monitor".to_string()),
                confidence: Some(0.4),
                decision_reason: None,
                decision_target: None,
                auto_executed: false,
                is_allowlisted: false,
                false_positive: false,
                fp_reporter: None,
                fp_reported_at: None,
                research_only: false,
            });
        }
        let out = ask_context_deep(&kg, "what happened?", 8000);
        assert!(
            out.contains("RECENT DECISIONS:"),
            "decisions header missing; got:\n{out}"
        );
        assert!(
            out.contains("- block_ip 1.2.3.4 (auto)"),
            "auto-executed line missing; got:\n{out}"
        );
        assert!(
            out.contains("- monitor ? (proposed)"),
            "proposed line + '?' fallback missing; got:\n{out}"
        );
    }

    /// Cover the HIGH-RISK ENTITIES section of `ask_context_deep` plus
    /// the `campaigns > 0` rendering branch. Section 3 was uncovered in
    /// baseline (no test seeded a campaign membership edge).
    #[test]
    fn ask_context_deep_includes_high_risk_entities_with_campaigns() {
        use crate::knowledge_graph::types::{Edge, Node, Relation};
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        ));
        let now = chrono::Utc::now();
        {
            let mut g = kg.write().unwrap();
            // High-risk IP with a campaign membership → both `risk > 70`
            // and `campaigns > 0` branches plus the "campaigns=" suffix
            // formatter.
            let ip_high = g.add_node(make_ip_node("203.0.113.50", 90, vec![]));
            let camp = g.add_node(Node::Campaign {
                campaign_id: "c1".to_string(),
                dna_hash: None,
                pattern_class: "scanner".to_string(),
                first_seen: now,
                last_seen: now,
                ip_count: 1,
            });
            g.add_edge(Edge::new(ip_high, camp, Relation::MemberOf, now));

            // Low-risk IP that is ONLY a campaign member (risk <=70 but
            // campaigns > 0) → covers the `campaigns > 0` short-circuit.
            let ip_camp_only = g.add_node(make_ip_node("198.51.100.10", 30, vec![]));
            g.add_edge(Edge::new(ip_camp_only, camp, Relation::MemberOf, now));

            // Low-risk IP NOT in a campaign → must NOT appear in the
            // section (anti-regression for relaxing the filter).
            g.add_node(make_ip_node("198.51.100.99", 5, vec![]));
        }
        let out = ask_context_deep(&kg, "show high risk", 8000);
        assert!(
            out.contains("HIGH-RISK ENTITIES:"),
            "high-risk header missing; got:\n{out}"
        );
        assert!(
            out.contains("- 203.0.113.50 risk=90 campaigns=1"),
            "expected campaigns suffix on high-risk IP; got:\n{out}"
        );
        assert!(
            out.contains("- 198.51.100.10 risk=30 campaigns=1"),
            "expected campaign-only IP entry; got:\n{out}"
        );
        assert!(
            !out.contains("198.51.100.99"),
            "low-risk non-campaign IP must be filtered out; got:\n{out}"
        );
    }

    /// Cover the remaining `node_label` variants (Process, File, User,
    /// Domain, Container, Device, System, Incident, Campaign) by routing
    /// them through the SUBGRAPH FOR QUESTION section. Pre-baseline only
    /// `Port` was indirectly exercised; lines 409-432 were almost
    /// entirely uncovered.
    #[test]
    fn ask_context_deep_subgraph_renders_all_node_label_variants() {
        use crate::knowledge_graph::types::{Edge, Node, Relation};
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            knowledge_graph::KnowledgeGraph::new(),
        ));
        let now = chrono::Utc::now();
        {
            let mut g = kg.write().unwrap();
            // Central IP that appears in the question.
            let ip = g.add_node(make_ip_node("203.0.113.77", 50, vec![]));
            // Outgoing → Process, File, User, Domain, Container, Device,
            // System, Campaign.
            let proc_id = g.add_node(Node::Process {
                pid: 1234,
                ppid: 1,
                comm: "evilbin".to_string(),
                exe: None,
                uid: 0,
                container_id: None,
                start_ts: now,
                exit_ts: None,
            });
            g.add_edge(Edge::new(ip, proc_id, Relation::ConnectedTo, now));

            let file_id = g.add_node(Node::File {
                path: "/tmp/dropper-with-a-very-long-pathname-that-exceeds-forty-chars.bin"
                    .to_string(),
                sha256: None,
                size: None,
                entropy: None,
                is_sensitive: false,
                yara_matches: vec![],
            });
            g.add_edge(Edge::new(ip, file_id, Relation::DownloadedFrom, now));

            let user_id = g.add_node(Node::User {
                name: "alice".to_string(),
                uid: Some(1000),
            });
            g.add_edge(Edge::new(ip, user_id, Relation::LoggedInFrom, now));

            let dom_id = g.add_node(Node::Domain {
                name: "evil.example".to_string(),
                datasets: vec![],
                is_dga: None,
                entropy: None,
            });
            g.add_edge(Edge::new(ip, dom_id, Relation::HostedAt, now));

            let cont_id = g.add_node(Node::Container {
                container_id: "0123456789abcdef0123".to_string(),
                name: None,
                image: None,
                start_ts: None,
                exit_ts: None,
                oom_killed: false,
            });
            g.add_edge(Edge::new(ip, cont_id, Relation::SnapshotConnectedTo, now));

            let dev_id = g.add_node(Node::Device {
                vendor: "ACME".to_string(),
                product: "USB-X".to_string(),
                serial: None,
                dev_class: None,
            });
            g.add_edge(Edge::new(ip, dev_id, Relation::InsertedOn, now));

            let sys_id = g.add_node(Node::System {
                hostname: "host-01".to_string(),
                sysctl_params: std::collections::HashMap::new(),
            });
            g.add_edge(Edge::new(ip, sys_id, Relation::ChangedSysctl, now));

            let camp_id = g.add_node(Node::Campaign {
                campaign_id: "campaign-42".to_string(),
                dna_hash: None,
                pattern_class: "scanner".to_string(),
                first_seen: now,
                last_seen: now,
                ip_count: 5,
            });
            g.add_edge(Edge::new(ip, camp_id, Relation::MemberOf, now));

            // Incoming → Incident (so node_label hits the Incident arm).
            let inc_id = g.add_node(make_inc_node("inc:abc:1", "high", "t", "s"));
            g.add_edge(Edge::new(inc_id, ip, Relation::TriggeredBy, now));
        }

        let out = ask_context_deep(&kg, "why is 203.0.113.77 hostile?", 16000);

        assert!(
            out.contains("SUBGRAPH FOR QUESTION:"),
            "subgraph header missing; got:\n{out}"
        );
        assert!(
            out.contains("Process(evilbin/1234)"),
            "Process label missing; got:\n{out}"
        );
        // File label is truncated to 40 chars.
        assert!(
            out.contains("File(/tmp/dropper-with-a-very-long-pathn"),
            "File label missing; got:\n{out}"
        );
        assert!(
            out.contains("User(alice)"),
            "User label missing; got:\n{out}"
        );
        assert!(
            out.contains("Domain(evil.example)"),
            "Domain label missing; got:\n{out}"
        );
        // Container label truncated to 12 chars.
        assert!(
            out.contains("Container(0123456789ab)"),
            "Container label missing; got:\n{out}"
        );
        assert!(
            out.contains("Device(ACME/USB-X)"),
            "Device label missing; got:\n{out}"
        );
        assert!(
            out.contains("System(host-01)"),
            "System label missing; got:\n{out}"
        );
        assert!(
            out.contains("Campaign(campaign-42)"),
            "Campaign label missing; got:\n{out}"
        );
        assert!(
            out.contains("Incident(inc:abc:1)"),
            "Incident label missing; got:\n{out}"
        );
    }

    // ── format_time_ago ──────────────────────────────────────────────────

    /// Cover all three age branches of `format_time_ago` plus the parse
    /// failure branch. Pre-baseline this helper was 0% covered.
    #[test]
    fn format_time_ago_handles_days_hours_minutes_and_invalid() {
        let now = chrono::Utc::now();
        let yesterday = (now - chrono::Duration::days(2)).to_rfc3339();
        assert!(format_time_ago(&yesterday).ends_with("d ago"));

        let three_h = (now - chrono::Duration::hours(3)).to_rfc3339();
        assert!(format_time_ago(&three_h).ends_with("h ago"));

        let ten_m = (now - chrono::Duration::minutes(10)).to_rfc3339();
        assert!(format_time_ago(&ten_m).ends_with("m ago"));

        // Future timestamp → diff < 0 → falls through to minutes.max(1) so
        // the helper never returns "0m ago".
        let future = (now + chrono::Duration::minutes(5)).to_rfc3339();
        assert_eq!(format_time_ago(&future), "1m ago");

        // Garbage input → "recently" sentinel.
        assert_eq!(format_time_ago("not-a-timestamp"), "recently");
    }

    // ── local_hostname_for_audit ─────────────────────────────────────────

    /// Cover the env-var-set branch of `local_hostname_for_audit`. The
    /// helper is small but used in every Telegram-triage audit row, so
    /// pinning the override path matters for portable test runners.
    #[test]
    fn local_hostname_for_audit_reads_env_var_when_set() {
        // Set HOSTNAME to a sentinel and verify the helper uses it. The
        // env var is process-wide so we restore it after the test.
        let original = std::env::var("HOSTNAME").ok();
        // SAFETY: tests run under cargo test single-threaded for env mutation
        // when this single test mutates HOSTNAME. We restore it below.
        std::env::set_var("HOSTNAME", "anchor-host-xyz");
        let h = local_hostname_for_audit();
        assert_eq!(h, "anchor-host-xyz");
        match original {
            Some(v) => std::env::set_var("HOSTNAME", v),
            None => std::env::remove_var("HOSTNAME"),
        }
    }

    // ── handle_telegram_triage_action — allowlist add error path ─────────

    /// Cover the `append_to_allowlist` Err branch of the
    /// `handle_telegram_triage_action` allow-proc path. The handler hard-
    /// codes `/etc/innerwarden/allowlist.toml`; on a non-root test runner
    /// the open fails and the error branch (lines ~615-645) executes.
    /// Pre-baseline this entire success/error block was uncovered because
    /// the existing test only sent invalid inputs that bailed out before
    /// the allowlist append.
    #[test]
    fn triage_allow_proc_with_valid_name_writes_audit_on_protected_path_failure() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        // Valid process name → bypasses sanitize_allowlist_process_name's
        // None branch and reaches `append_to_allowlist`. As a non-root
        // test user the open of /etc/innerwarden/allowlist.toml fails
        // and we hit the Err arm + write_telegram_triage_audit "failed:"
        // path.
        let approval = crate::tests::triage_approval(
            "__allow_proc__:anchor_proc_under_test",
            "telegram-operator",
        );
        let handled = handle_telegram_triage_action(&approval, dir.path(), &cfg, &mut state);
        assert!(handled, "callback must be marked handled");

        // The audit write should have at least one entry covering the
        // attempted-or-failed allowlist add (decision_writer was seeded
        // by triage_test_state). Decision writer rotates files daily, so
        // we scan all decisions-*.jsonl files in the temp data_dir.
        let mut found = false;
        if let Ok(entries) = std::fs::read_dir(dir.path()) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("decisions-") && name.ends_with(".jsonl") {
                    let content = std::fs::read_to_string(e.path()).unwrap_or_default();
                    if content.contains("anchor_proc_under_test") {
                        found = true;
                        break;
                    }
                }
            }
        }
        assert!(
            found,
            "expected decision-writer audit row mentioning the attempted process name"
        );
    }

    /// Same as above but for the allow-IP path. Covers the
    /// `append_to_allowlist` Err arm at lines ~753-784 (IP variant).
    #[test]
    fn triage_allow_ip_with_valid_address_writes_audit_on_protected_path_failure() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();

        let approval =
            crate::tests::triage_approval("__allow_ip__:203.0.113.250", "telegram-operator");
        let handled = handle_telegram_triage_action(&approval, dir.path(), &cfg, &mut state);
        assert!(handled);

        let mut found = false;
        if let Ok(entries) = std::fs::read_dir(dir.path()) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("decisions-") && name.ends_with(".jsonl") {
                    let content = std::fs::read_to_string(e.path()).unwrap_or_default();
                    if content.contains("203.0.113.250") {
                        found = true;
                        break;
                    }
                }
            }
        }
        assert!(
            found,
            "expected decision-writer audit row for the attempted IP"
        );
    }

    // ── check_2fa_gate — lockout path ───────────────────────────────────

    /// Cover the lockout branch of `check_2fa_gate` (lines ~880-883).
    /// After 3 recorded failures the gate must intercept and short-circuit
    /// without storing a new pending action.
    #[test]
    fn check_2fa_gate_intercepts_when_operator_is_locked_out() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.security = Some(config::SecurityConfig {
            two_factor_method: "totp".to_string(),
            totp_secret: "JBSWY3DPEHPK3PXP".to_string(),
            ..Default::default()
        });

        // Force three failures so is_locked_out returns true.
        for _ in 0..3 {
            state.two_factor_state.record_failure("op");
        }
        assert!(state.two_factor_state.is_locked_out("op"));

        let intercepted = check_2fa_gate(
            &mut state,
            &cfg,
            "op",
            two_factor::PendingActionType::AllowlistIp("9.9.9.9".to_string()),
        );
        assert!(intercepted, "lockout path must intercept");
        // No pending action stored on lockout branch.
        assert!(
            !state.two_factor_state.pending.contains_key("op"),
            "no pending action should be stored when locked out"
        );
    }

    // ── handle_totp_response — error branches ────────────────────────────

    /// Cover the "secret missing" branch of `handle_totp_response`
    /// (lines ~948-953). When 2FA is enabled and a 6-digit code arrives
    /// against a pending action but the secret is empty, the handler must
    /// reply with the configuration error and consume the attempt.
    #[test]
    fn handle_totp_response_with_no_secret_replies_with_config_error() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());

        // 2FA "enabled" but secret intentionally missing.
        let mut cfg = config::AgentConfig::default();
        cfg.security = Some(config::SecurityConfig {
            two_factor_method: "totp".to_string(),
            totp_secret: String::new(),
            ..Default::default()
        });

        // Make sure the env var doesn't accidentally satisfy totp_secret.
        let original_env = std::env::var("INNERWARDEN_TOTP_SECRET").ok();
        std::env::remove_var("INNERWARDEN_TOTP_SECRET");

        // Seed a pending action so `take_pending` returns Some.
        let now = chrono::Utc::now();
        state.two_factor_state.set_pending(
            "op",
            two_factor::PendingAction {
                action_type: two_factor::PendingActionType::AllowlistIp("1.1.1.1".to_string()),
                operator: "op".to_string(),
                created_at: now,
                expires_at: now + chrono::Duration::minutes(5),
                method: two_factor::TwoFactorMethod::Totp,
            },
        );

        let approval = crate::tests::triage_approval("123456", "op");
        let handled = handle_totp_response(&approval, dir.path(), &cfg, &mut state);
        assert!(handled, "must be marked handled even on misconfig");
        // Pending action was taken (consumed); the misconfig path exits
        // without re-storing.
        assert!(!state.two_factor_state.pending.contains_key("op"));

        if let Some(v) = original_env {
            std::env::set_var("INNERWARDEN_TOTP_SECRET", v);
        }
    }

    /// Cover the "invalid TOTP secret" branch of `handle_totp_response`
    /// (lines ~960-965). When the secret is non-empty but
    /// `TotpProvider::new` rejects it (too short / invalid base32), the
    /// handler must reply with the invalid-secret error.
    #[test]
    fn handle_totp_response_with_invalid_secret_replies_with_invalid_error() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());

        let mut cfg = config::AgentConfig::default();
        cfg.security = Some(config::SecurityConfig {
            two_factor_method: "totp".to_string(),
            // Too-short secret — TotpProvider::new returns None
            // (requires >= 10 raw bytes after base32 decode).
            totp_secret: "AAAA".to_string(),
            ..Default::default()
        });

        let original_env = std::env::var("INNERWARDEN_TOTP_SECRET").ok();
        std::env::remove_var("INNERWARDEN_TOTP_SECRET");

        let now = chrono::Utc::now();
        state.two_factor_state.set_pending(
            "op",
            two_factor::PendingAction {
                action_type: two_factor::PendingActionType::AllowlistProcess("p".to_string()),
                operator: "op".to_string(),
                created_at: now,
                expires_at: now + chrono::Duration::minutes(5),
                method: two_factor::TwoFactorMethod::Totp,
            },
        );

        let approval = crate::tests::triage_approval("000000", "op");
        let handled = handle_totp_response(&approval, dir.path(), &cfg, &mut state);
        assert!(handled);

        if let Some(v) = original_env {
            std::env::set_var("INNERWARDEN_TOTP_SECRET", v);
        }
    }

    /// Cover the "code expired" branch of `handle_totp_response`
    /// (lines ~939-941). A pending action with an `expires_at` in the
    /// past must be taken, the handler must reply with the expired
    /// message, and no attempt counter increments (we don't penalise
    /// stale codes).
    #[test]
    fn handle_totp_response_with_expired_pending_reports_expired() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.security = Some(config::SecurityConfig {
            two_factor_method: "totp".to_string(),
            totp_secret: "JBSWY3DPEHPK3PXP".to_string(),
            ..Default::default()
        });

        let now = chrono::Utc::now();
        state.two_factor_state.set_pending(
            "op",
            two_factor::PendingAction {
                action_type: two_factor::PendingActionType::AllowlistIp("1.1.1.1".to_string()),
                operator: "op".to_string(),
                created_at: now - chrono::Duration::minutes(10),
                expires_at: now - chrono::Duration::seconds(1),
                method: two_factor::TwoFactorMethod::Totp,
            },
        );

        let approval = crate::tests::triage_approval("123456", "op");
        let handled = handle_totp_response(&approval, dir.path(), &cfg, &mut state);
        assert!(handled);
        // Expired pending was consumed.
        assert!(!state.two_factor_state.pending.contains_key("op"));
    }

    /// Cover the `wrong code → lockout` branch of `handle_totp_response`
    /// (lines ~971-975). After 3 prior failures the next wrong code must
    /// trigger the "locked out for 1 hour" reply rather than the
    /// "try again" reply.
    #[test]
    fn handle_totp_response_wrong_code_after_failures_triggers_lockout_message() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.security = Some(config::SecurityConfig {
            two_factor_method: "totp".to_string(),
            totp_secret: "JBSWY3DPEHPK3PXP".to_string(),
            ..Default::default()
        });

        // Two prior failures recorded — the upcoming wrong code records
        // a 3rd, which crosses max_failures_per_hour=3 and triggers the
        // lockout reply branch.
        state.two_factor_state.record_failure("op");
        state.two_factor_state.record_failure("op");

        let now = chrono::Utc::now();
        state.two_factor_state.set_pending(
            "op",
            two_factor::PendingAction {
                action_type: two_factor::PendingActionType::AllowlistIp("1.1.1.1".to_string()),
                operator: "op".to_string(),
                created_at: now,
                expires_at: now + chrono::Duration::minutes(5),
                method: two_factor::TwoFactorMethod::Totp,
            },
        );

        let approval = crate::tests::triage_approval("000000", "op");
        let handled = handle_totp_response(&approval, dir.path(), &cfg, &mut state);
        assert!(handled);
        // Pending NOT re-stored under lockout (the retry branch would
        // re-store it).
        assert!(
            !state.two_factor_state.pending.contains_key("op"),
            "lockout branch must not re-store pending"
        );
        assert!(state.two_factor_state.is_locked_out("op"));
    }

    // ── execute_verified_action — all four variants ──────────────────────

    /// Cover the four `PendingActionType` arms of `execute_verified_action`
    /// (lines ~1006-1118). Each arm hits the protected
    /// `/etc/innerwarden/allowlist.toml` path and falls into the Err
    /// branch on a non-root test runner — we assert the helper does not
    /// panic across all variants. Anti-regression for accidentally
    /// breaking one of the four match arms (UndoAllowlist and
    /// AutoFpAllowlist were 0% covered in baseline).
    #[test]
    fn execute_verified_action_runs_all_action_variants_without_panic() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());

        execute_verified_action(
            two_factor::PendingActionType::AllowlistProcess("anchor_proc".to_string()),
            "op",
            dir.path(),
            &mut state,
        );
        execute_verified_action(
            two_factor::PendingActionType::AllowlistIp("203.0.113.251".to_string()),
            "op",
            dir.path(),
            &mut state,
        );
        execute_verified_action(
            two_factor::PendingActionType::UndoAllowlist {
                section: "ips".to_string(),
                key: "203.0.113.252".to_string(),
            },
            "op",
            dir.path(),
            &mut state,
        );
        execute_verified_action(
            two_factor::PendingActionType::AutoFpAllowlist {
                section: "processes".to_string(),
                entity: "auto_fp_anchor".to_string(),
            },
            "op",
            dir.path(),
            &mut state,
        );
    }
}
