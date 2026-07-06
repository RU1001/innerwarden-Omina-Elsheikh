use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

fn safe_date_component(date: &str) -> Option<String> {
    use chrono::Datelike;

    let bytes = date.as_bytes();
    if bytes.len() != 10
        || !bytes.iter().enumerate().all(|(i, &b)| match i {
            4 | 7 => b == b'-',
            _ => b.is_ascii_digit(),
        })
    {
        return None;
    }
    let parsed = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;
    Some(format!(
        "{:04}-{:02}-{:02}",
        parsed.year(),
        parsed.month(),
        parsed.day()
    ))
}

fn safe_name_component(value: &str, fallback: &str) -> String {
    let safe: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if safe.is_empty() {
        fallback.to_string()
    } else {
        safe
    }
}

/// Build a dated file path from bounded components.
///
/// Dates are parsed and re-formatted from `NaiveDate` primitives rather than
/// filtered from the original string. That gives CodeQL and humans the same
/// guarantee: the final path component is freshly constructed, not a cleaned-up
/// slice of request input.
fn safe_dated_file(dir: &Path, prefix: &str, date: &str, ext: &str) -> PathBuf {
    let prefix = safe_name_component(prefix, "file");
    let ext = safe_name_component(ext, "dat");
    let date = safe_date_component(date).unwrap_or_else(|| "invalid-date".to_string());
    dir.join(format!("{prefix}-{date}.{ext}"))
}
use std::time::SystemTime;

use anyhow::{Context, Result};
use chrono::{DateTime, Local, NaiveDate, Utc};
use innerwarden_core::{entities::EntityType, event::Event, incident::Incident};
use serde::Serialize;
use serde_json::Value;

use tracing::warn;

use crate::decisions::DecisionEntry;
use crate::telemetry;

fn safe_kpi_filename(path: &Path) -> Option<String> {
    let filename = path.file_name()?.to_str()?;
    let stem = filename.strip_suffix(".jsonl")?;
    let date_start = stem.len().checked_sub(10)?;
    let date = &stem[date_start..];
    let separator = date_start.checked_sub(1)?;
    if stem.as_bytes().get(separator) != Some(&b'-') {
        return None;
    }
    let prefix = stem.get(..separator)?;
    if !matches!(prefix, "events" | "incidents" | "decisions") {
        return None;
    }
    let safe_date = safe_date_component(date)?;
    Some(format!("{prefix}-{safe_date}.jsonl"))
}

fn warn_kpi_open_failure(kind: &str, path: &Path, error: &std::io::Error) {
    warn!(
        kind,
        path = %path.display(),
        error = %error,
        "report KPI file open failed (per-day count for this kind dropped)"
    );
}

/// Open a per-day KPI JSONL file (events / incidents / decisions),
/// surfacing genuine I/O failure via `warn!` while staying silent on
/// the steady-state `NotFound` case (most days have no JSONL on disk
/// because the reporting window scans 30 days back). Replaces three
/// silent `if let Ok(f) = File::open(&path)` sites in the 30-day KPI
/// scan loop (Spec 037 I-13 follow-up #2, third slice).
///
/// `kind` is the bounded label "events" / "incidents" / "decisions"
/// so the operator can identify which KPI lost data. Returns
/// `Some(File)` so the caller drives the BufReader; `None` means
/// either the file did not exist (normal) or the open failed and the
/// warn already fired.
fn open_kpi_file_or_warn(path: &Path, kind: &str) -> Option<File> {
    let safe_filename = safe_kpi_filename(path)?;
    let parent = path.parent()?;
    let base = match parent.canonicalize() {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn_kpi_open_failure(kind, parent, &e);
            return None;
        }
    };
    let target = base.join(safe_filename);
    let path = match target.canonicalize() {
        Ok(v) if v.starts_with(&base) => v,
        Ok(_) => return None,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn_kpi_open_failure(kind, &target, &e);
            return None;
        }
    };
    match File::open(&path) {
        Ok(f) => Some(f),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn_kpi_open_failure(kind, &path, &e);
            None
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GeneratedReport {
    pub markdown_path: PathBuf,
    pub json_path: PathBuf,
    pub report: TrialReport,
}

#[derive(Debug, Serialize)]
pub struct TrialReport {
    pub generated_at: DateTime<Utc>,
    pub analyzed_date: String,
    pub data_dir: String,
    pub operational_health: OperationalHealth,
    pub operational_telemetry: OperationalTelemetry,
    pub detection_summary: DetectionSummary,
    pub agent_ai_summary: AgentAiSummary,
    /// Sliding 6-hour window spanning today + yesterday if needed.
    /// Always use this section for "last N hours" ops-check queries.
    pub recent_window: RecentWindow,
    pub trend_summary: TrendSummary,
    pub anomaly_hints: Vec<AnomalyHint>,
    pub data_quality: DataQuality,
    pub suggested_improvements: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct OperationalHealth {
    pub expected_files_present: bool,
    pub state_json_readable: bool,
    pub agent_state_json_readable: bool,
    pub files: Vec<FileHealth>,
}

#[derive(Debug, Serialize)]
pub struct FileHealth {
    pub file: String,
    pub exists: bool,
    pub readable: bool,
    pub size_bytes: u64,
    pub modified_secs_ago: Option<u64>,
    pub jsonl_valid: Option<bool>,
    pub lines: Option<u64>,
    pub malformed_lines: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct OperationalTelemetry {
    pub available: bool,
    pub last_tick: Option<String>,
    /// Wave 6b (memory-opt): mirrors `TelemetrySnapshot` field type
    /// (`Arc<str>`) so the per-tick `from(snapshot)` conversion in
    /// `build_operational_telemetry` is a cheap pointer-clone instead
    /// of a per-key `String` re-allocation. Wire format unchanged
    /// (serde renders `Arc<str>` as JSON string).
    pub events_by_collector: BTreeMap<std::sync::Arc<str>, u64>,
    pub incidents_by_detector: BTreeMap<std::sync::Arc<str>, u64>,
    pub gate_pass_count: u64,
    pub ai_sent_count: u64,
    pub ai_decision_count: u64,
    pub avg_decision_latency_ms: f64,
    pub errors_by_component: BTreeMap<String, u64>,
    pub decisions_by_action: BTreeMap<String, u64>,
    pub dry_run_execution_count: u64,
    pub real_execution_count: u64,
}

#[derive(Debug, Serialize)]
pub struct DetectionSummary {
    pub total_events: u64,
    pub total_incidents: u64,
    pub incidents_by_type: BTreeMap<String, u64>,
    pub top_ips: Vec<NamedCount>,
    pub top_entities: Vec<NamedCount>,
}

#[derive(Debug, Serialize)]
pub struct AgentAiSummary {
    pub total_decisions: u64,
    pub decisions_by_action: BTreeMap<String, u64>,
    pub average_confidence: f64,
    pub ignore_count: u64,
    pub block_ip_count: u64,
    pub dry_run_count: u64,
    pub skills_used: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
pub struct DataQuality {
    pub empty_files: Vec<String>,
    pub malformed_jsonl: BTreeMap<String, u64>,
    pub incidents_without_entities: u64,
    pub decisions_without_action: u64,
    pub files_not_growing: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TrendSummary {
    pub previous_date: Option<String>,
    pub events: CountDelta,
    pub incidents: CountDelta,
    pub decisions: CountDelta,
    pub incident_rate_per_1k_events: FloatDelta,
    pub decision_rate_per_incident: FloatDelta,
    pub average_confidence: FloatDelta,
}

#[derive(Debug, Serialize)]
pub struct CountDelta {
    pub current: u64,
    pub previous: u64,
    pub delta: i64,
    pub pct_change: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct FloatDelta {
    pub current: f64,
    pub previous: f64,
    pub delta: f64,
    pub pct_change: Option<f64>,
}

/// Statistics for a sliding 6-hour window that may span two calendar days.
/// This is the source of truth for "last 6 hours" metrics shown in ops checks.
#[derive(Debug, Clone, Serialize)]
pub struct RecentWindow {
    /// Width of the window in seconds (always 6 * 3600).
    pub window_secs: u64,
    /// Total events in the window (capped at a sane scan limit).
    pub events: u64,
    /// Total incidents in the window.
    pub incidents: u64,
    /// High or Critical incidents in the window.
    pub high_critical_incidents: u64,
    /// Total decision lines in the window.
    pub decisions: u64,
    /// Decision counts grouped by action_type (e.g. "block_ip", "ignore").
    pub decisions_by_action: BTreeMap<String, u64>,
    /// Most recent event timestamp seen in the window ("none" if empty).
    pub latest_event_ts: String,
    /// Most recent incident timestamp seen in the window ("none" if empty).
    pub latest_incident_ts: String,
    /// Most recent decision timestamp seen in the window ("none" if empty).
    pub latest_decision_ts: String,
    /// Most recent telemetry snapshot timestamp for today ("none" if empty).
    pub latest_telemetry_ts: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct AnomalyHint {
    pub severity: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct NamedCount {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Default, Clone)]
struct ParseOutcome {
    exists: bool,
    readable: bool,
    size_bytes: u64,
    modified_secs_ago: Option<u64>,
    lines: u64,
    malformed_lines: u64,
}

impl ParseOutcome {
    fn jsonl_valid(&self) -> bool {
        self.exists && self.readable && self.malformed_lines == 0
    }
}

#[derive(Debug, Default, Clone)]
struct Counters {
    total_events: u64,
    total_incidents: u64,
    total_decisions: u64,
    confidence_sum: f64,

    incidents_by_type: HashMap<String, u64>,
    ip_counts: HashMap<String, u64>,
    entity_counts: HashMap<String, u64>,
    decisions_by_action: HashMap<String, u64>,
    skills_used: HashMap<String, u64>,

    ignore_count: u64,
    block_ip_count: u64,
    dry_run_count: u64,

    incidents_without_entities: u64,
    decisions_without_action: u64,

    malformed_jsonl: BTreeMap<String, u64>,
    empty_files: Vec<String>,
    files_not_growing: Vec<String>,
}

/// Populate counters from the knowledge graph instead of JSONL files.
fn populate_counters_from_graph(
    graph: &crate::knowledge_graph::KnowledgeGraph,
    counters: &mut Counters,
) {
    use crate::knowledge_graph::types::*;

    // Events: count non-snapshot edges as a FALLBACK only. The KG edge
    // count is a 30×-inflation proxy for events (each event creates
    // multiple edges: incident → ip, incident → process, etc), same
    // bug PR22/PR23 chased for the Home strip. Callers that have
    // access to SQLite OVERWRITE this field with
    // `Store::events_count_for_date(date)`; this fallback only
    // survives for in-memory test fixtures that never built a store.
    counters.total_events = graph
        .edges_slice()
        .iter()
        .filter(|e| !e.is_snapshot())
        .count() as u64;

    // Incidents
    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            incident_id: _,
            detector,
            decision,
            confidence,
            auto_executed,
            research_only,
            ..
        }) = graph.get_node(id)
        {
            // 2026-05-14 — exclude research_only incidents (sensor
            // self-traffic flagged at ingest time per spec 015). Same
            // filter compute_overview_counts_from_sqlite applies.
            // Pre-PR27: Report's Trend showed `Incidents 1211` raw
            // count, the Summary showed `Incidents Today 223`
            // filtered count — operator-visible disagreement on the
            // same page. Filtering here lifts the Trend (and Top IPs
            // / Incidents By Type) to the same semantic the Summary
            // already used.
            if *research_only {
                continue;
            }
            counters.total_incidents += 1;
            *counters
                .incidents_by_type
                .entry(detector.clone())
                .or_insert(0) += 1;

            // Collect IPs from TriggeredBy edges
            let has_entity = graph
                .outgoing_edges(id)
                .iter()
                .any(|e| e.relation == Relation::TriggeredBy);
            if !has_entity {
                counters.incidents_without_entities += 1;
            }
            for edge in graph.outgoing_edges(id) {
                if edge.relation == Relation::TriggeredBy {
                    if let Some(Node::Ip { addr, .. }) = graph.get_node(edge.to) {
                        // 2026-05-14 — skip self-traffic / private IPs
                        // for the operator-facing Top IPs list. Before
                        // this filter the Report's Top IPs included
                        // 10.0.0.238 (the host's own internal address)
                        // and 127.0.0.1 (loopback) as the top two
                        // "attackers". Mirrors the same filter
                        // overview-counts + Cases entities apply.
                        if !is_report_visible_ip(addr) {
                            continue;
                        }
                        *counters.ip_counts.entry(addr.clone()).or_insert(0) += 1;
                        *counters
                            .entity_counts
                            .entry(format!("ip:{}", addr))
                            .or_insert(0) += 1;
                    }
                    if let Some(Node::User { name, .. }) = graph.get_node(edge.to) {
                        *counters
                            .entity_counts
                            .entry(format!("user:{}", name))
                            .or_insert(0) += 1;
                    }
                }
            }

            // Decisions
            if let Some(action) = decision {
                counters.total_decisions += 1;
                *counters
                    .decisions_by_action
                    .entry(action.clone())
                    .or_insert(0) += 1;
                counters.confidence_sum += confidence.unwrap_or(0.0) as f64;
                match action.as_str() {
                    "ignore" => counters.ignore_count += 1,
                    "block_ip" => counters.block_ip_count += 1,
                    _ => {}
                }
                if !*auto_executed {
                    counters.dry_run_count += 1;
                }
            }
        }
    }
}

/// Compute a `TrialReport` from the knowledge graph (live, no JSONL).
/// File health checks still use the filesystem.
pub fn compute_for_date_from_graph(
    data_dir: &Path,
    date: Option<&str>,
    graph: &crate::knowledge_graph::KnowledgeGraph,
) -> TrialReport {
    let today = Local::now().date_naive().format("%Y-%m-%d").to_string();
    let analyzed_date = match date {
        Some(d) => d.to_string(),
        None => today.clone(),
    };
    let analyzed_is_today = analyzed_date == today;

    // File health checks (still filesystem-based — that's their purpose)
    let events_path = safe_dated_file(data_dir, "events", &analyzed_date, "jsonl");
    let incidents_path = safe_dated_file(data_dir, "incidents", &analyzed_date, "jsonl");
    let decisions_path = safe_dated_file(data_dir, "decisions", &analyzed_date, "jsonl");
    let summary_path = safe_dated_file(data_dir, "summary", &analyzed_date, "md");
    let state = data_dir.join("state.json");
    let agent_state = data_dir.join("agent-state.json");

    let mut files = Vec::new();
    let mut counters = Counters::default();

    // Quick file health (existence + size, no parsing)
    for (name, path) in [
        ("events", &events_path),
        ("incidents", &incidents_path),
        ("decisions", &decisions_path),
    ] {
        let exists = path.exists();
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if exists && size == 0 {
            counters.empty_files.push(name.to_string());
        }
        if exists && !analyzed_is_today && size == 0 {
            counters.files_not_growing.push(name.to_string());
        }
        let modified_secs_ago = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .map(|d| d.as_secs());
        files.push(FileHealth {
            file: name.to_string(),
            exists,
            readable: exists,
            size_bytes: size,
            modified_secs_ago,
            jsonl_valid: if exists { Some(true) } else { None },
            lines: None,
            malformed_lines: None,
        });
    }

    let summary_info = parse_plain_file(&summary_path);
    files.push(file_health_plain("summary", &summary_info));
    let state_info = parse_state_file(&state);
    files.push(file_health_plain("state", &state_info));
    let agent_state_info = parse_state_file(&agent_state);
    files.push(file_health_plain("agent-state", &agent_state_info));

    // Populate counters from graph
    populate_counters_from_graph(graph, &mut counters);

    // PR28 — overwrite `total_events` with the canonical SQLite count
    // for the date. The KG-edges-as-events proxy in
    // populate_counters_from_graph inflates by ~30× (each event
    // creates multiple edges); same Gap 1 fix PR23 applied to the
    // Home strip. Only overwrites when the store is reachable AND
    // returns a non-error count — test fixtures without a store keep
    // the legacy proxy via the populate path.
    if let Ok(store) = innerwarden_store::Store::open(data_dir) {
        if let Ok(count) = store.events_count_for_date(&analyzed_date) {
            counters.total_events = count;
        }
    }

    // If SQLite DB exists, data files are present (JSONL no longer required)
    // Canonicalize data_dir to prevent path traversal (CodeQL: path-injection).
    let db_exists = std::fs::canonicalize(data_dir)
        .map(|d| d.join("innerwarden.db").exists())
        .unwrap_or(false);
    let expected_files_present = db_exists || files.iter().all(|f| f.exists);
    let state_json_readable = state_info.exists && state_info.readable;
    let agent_state_json_readable = agent_state_info.exists && agent_state_info.readable;
    let operational_telemetry = build_operational_telemetry(data_dir, &analyzed_date);

    let detection_summary = DetectionSummary {
        total_events: counters.total_events,
        total_incidents: counters.total_incidents,
        incidents_by_type: to_btreemap(counters.incidents_by_type.clone()),
        top_ips: top_n(&counters.ip_counts, 10),
        top_entities: top_n(&counters.entity_counts, 10),
    };

    let avg_conf = if counters.total_decisions > 0 {
        counters.confidence_sum / counters.total_decisions as f64
    } else {
        0.0
    };
    let agent_ai_summary = AgentAiSummary {
        total_decisions: counters.total_decisions,
        decisions_by_action: to_btreemap(counters.decisions_by_action.clone()),
        average_confidence: avg_conf,
        ignore_count: counters.ignore_count,
        block_ip_count: counters.block_ip_count,
        dry_run_count: counters.dry_run_count,
        skills_used: to_btreemap(counters.skills_used.clone()),
    };

    let data_quality = DataQuality {
        empty_files: counters.empty_files.clone(),
        malformed_jsonl: counters.malformed_jsonl.clone(),
        incidents_without_entities: counters.incidents_without_entities,
        decisions_without_action: counters.decisions_without_action,
        files_not_growing: counters.files_not_growing.clone(),
    };

    // Trends: use previous day's JSONL counters as comparison (graph only has current state)
    let previous_date = detect_previous_date(data_dir, &analyzed_date);
    let previous_counters = previous_date
        .as_ref()
        .map(|d| compute_day_counters(data_dir, d));
    let trend_summary = build_trend_summary(&counters, previous_counters.as_ref(), previous_date);
    let anomaly_hints = build_anomaly_hints(
        &detection_summary,
        &agent_ai_summary,
        &data_quality,
        &trend_summary,
        previous_counters.as_ref(),
    );

    let operational_health = OperationalHealth {
        expected_files_present,
        state_json_readable,
        agent_state_json_readable,
        files,
    };

    let recent_window = compute_recent_window(data_dir, &analyzed_date);

    let mut report = TrialReport {
        generated_at: Utc::now(),
        analyzed_date,
        data_dir: data_dir.display().to_string(),
        operational_health,
        operational_telemetry,
        detection_summary,
        agent_ai_summary,
        recent_window,
        trend_summary,
        anomaly_hints,
        data_quality,
        suggested_improvements: vec![],
    };
    report.suggested_improvements = build_suggestions(&report);
    report
}

/// Compute a `TrialReport` for the given date (or the latest available date if
/// `date` is `None`) without writing any files to disk.
/// Used by the dashboard `/api/report` endpoint (JSONL fallback).
pub fn compute_for_date(data_dir: &Path, date: Option<&str>) -> TrialReport {
    let today = Local::now().date_naive().format("%Y-%m-%d").to_string();
    let analyzed_date = match date {
        Some(d) => d.to_string(),
        None => detect_latest_date(data_dir).unwrap_or_else(|| today.clone()),
    };
    let previous_date = detect_previous_date(data_dir, &analyzed_date);
    let analyzed_is_today = analyzed_date == today;

    let events = safe_dated_file(data_dir, "events", &analyzed_date, "jsonl");
    let incidents = safe_dated_file(data_dir, "incidents", &analyzed_date, "jsonl");
    let decisions = safe_dated_file(data_dir, "decisions", &analyzed_date, "jsonl");
    let summary = safe_dated_file(data_dir, "summary", &analyzed_date, "md");
    let state = data_dir.join("state.json");
    let agent_state = data_dir.join("agent-state.json");

    let mut counters = Counters::default();
    let mut files = Vec::new();

    let events_outcome = parse_events_file(&events, &mut counters);
    record_quality_hints("events", &events_outcome, analyzed_is_today, &mut counters);
    files.push(file_health_jsonl("events", &events_outcome));

    let incidents_outcome = parse_incidents_file(&incidents, &mut counters);
    record_quality_hints(
        "incidents",
        &incidents_outcome,
        analyzed_is_today,
        &mut counters,
    );
    files.push(file_health_jsonl("incidents", &incidents_outcome));

    let decisions_outcome = parse_decisions_file(&decisions, &mut counters);
    record_quality_hints(
        "decisions",
        &decisions_outcome,
        analyzed_is_today,
        &mut counters,
    );
    files.push(file_health_jsonl("decisions", &decisions_outcome));

    let summary_info = parse_plain_file(&summary);
    record_plain_file_hints("summary", &summary_info, analyzed_is_today, &mut counters);
    files.push(file_health_plain("summary", &summary_info));

    let state_info = parse_state_file(&state);
    record_plain_file_hints("state", &state_info, false, &mut counters);
    files.push(file_health_plain("state", &state_info));

    let agent_state_info = parse_state_file(&agent_state);
    record_plain_file_hints("agent-state", &agent_state_info, false, &mut counters);
    files.push(file_health_plain("agent-state", &agent_state_info));

    // If SQLite DB exists, data files are present (JSONL no longer required)
    // Canonicalize data_dir to prevent path traversal (CodeQL: path-injection).
    let db_exists = std::fs::canonicalize(data_dir)
        .map(|d| d.join("innerwarden.db").exists())
        .unwrap_or(false);
    let expected_files_present = db_exists || files.iter().all(|f| f.exists);
    let state_json_readable = state_info.exists && state_info.readable;
    let agent_state_json_readable = agent_state_info.exists && agent_state_info.readable;
    let operational_telemetry = build_operational_telemetry(data_dir, &analyzed_date);

    let detection_summary = DetectionSummary {
        total_events: counters.total_events,
        total_incidents: counters.total_incidents,
        incidents_by_type: to_btreemap(counters.incidents_by_type.clone()),
        top_ips: top_n(&counters.ip_counts, 10),
        top_entities: top_n(&counters.entity_counts, 10),
    };

    let avg_conf = if counters.total_decisions > 0 {
        counters.confidence_sum / counters.total_decisions as f64
    } else {
        0.0
    };
    let agent_ai_summary = AgentAiSummary {
        total_decisions: counters.total_decisions,
        decisions_by_action: to_btreemap(counters.decisions_by_action.clone()),
        average_confidence: avg_conf,
        ignore_count: counters.ignore_count,
        block_ip_count: counters.block_ip_count,
        dry_run_count: counters.dry_run_count,
        skills_used: to_btreemap(counters.skills_used.clone()),
    };

    let data_quality = DataQuality {
        empty_files: counters.empty_files.clone(),
        malformed_jsonl: counters.malformed_jsonl.clone(),
        incidents_without_entities: counters.incidents_without_entities,
        decisions_without_action: counters.decisions_without_action,
        files_not_growing: counters.files_not_growing.clone(),
    };

    let previous_counters = previous_date
        .as_ref()
        .map(|d| compute_day_counters(data_dir, d));

    let trend_summary = build_trend_summary(&counters, previous_counters.as_ref(), previous_date);
    let anomaly_hints = build_anomaly_hints(
        &detection_summary,
        &agent_ai_summary,
        &data_quality,
        &trend_summary,
        previous_counters.as_ref(),
    );

    let operational_health = OperationalHealth {
        expected_files_present,
        state_json_readable,
        agent_state_json_readable,
        files,
    };

    let recent_window = compute_recent_window(data_dir, &analyzed_date);

    let mut report = TrialReport {
        generated_at: Utc::now(),
        analyzed_date,
        data_dir: data_dir.display().to_string(),
        operational_health,
        operational_telemetry,
        detection_summary,
        agent_ai_summary,
        recent_window,
        trend_summary,
        anomaly_hints,
        data_quality,
        suggested_improvements: vec![],
    };
    report.suggested_improvements = build_suggestions(&report);
    report
}

/// List dates for which at least one data file (events/incidents/decisions) exists.
/// Returns dates in descending order (most recent first).
pub fn list_available_dates(data_dir: &Path) -> Vec<String> {
    let mut dates = collect_available_dates(data_dir);
    dates.sort_by(|a, b| b.cmp(a));
    dates
}

pub fn generate(data_dir: &Path, output_dir: &Path) -> Result<GeneratedReport> {
    let report_date = Local::now().date_naive().format("%Y-%m-%d").to_string();
    // Try loading graph from SQLite store first, then file snapshot
    let graph = {
        let mut g = None;
        if let Ok(store) = innerwarden_store::Store::open(data_dir) {
            g = crate::knowledge_graph::KnowledgeGraph::load_from_store(&store);
        }
        g.unwrap_or_else(|| crate::knowledge_graph::KnowledgeGraph::load_today_snapshot(data_dir))
    };
    let report = if graph.metrics().node_count > 0 {
        compute_for_date_from_graph(data_dir, None, &graph)
    } else {
        // Graph empty — supplement zero counters from SQLite tables
        let mut report = compute_for_date(data_dir, None);
        if let Ok(store) = innerwarden_store::Store::open(data_dir) {
            if report.detection_summary.total_events == 0 {
                report.detection_summary.total_events = store.events_count().unwrap_or(0);
            }
            if report.detection_summary.total_incidents == 0 {
                report.detection_summary.total_incidents = store.incidents_count().unwrap_or(0);
            }
            if report.agent_ai_summary.total_decisions == 0 {
                report.agent_ai_summary.total_decisions = store.decisions_count().unwrap_or(0);
            }
        }
        report
    };

    let json_path = safe_dated_file(output_dir, "trial-report", &report_date, "json");
    let md_path = safe_dated_file(output_dir, "trial-report", &report_date, "md");

    let json_file = File::create(&json_path)
        .with_context(|| format!("failed to create {}", json_path.display()))?;
    serde_json::to_writer_pretty(json_file, &report)
        .with_context(|| format!("failed to write {}", json_path.display()))?;

    let markdown = render_markdown(&report);
    fs::write(&md_path, markdown)
        .with_context(|| format!("failed to write {}", md_path.display()))?;

    Ok(GeneratedReport {
        markdown_path: md_path,
        json_path,
        report,
    })
}

fn detect_latest_date(data_dir: &Path) -> Option<String> {
    collect_available_dates(data_dir).into_iter().max()
}

fn detect_previous_date(data_dir: &Path, analyzed_date: &str) -> Option<String> {
    collect_available_dates(data_dir)
        .into_iter()
        .filter(|date| date.as_str() < analyzed_date)
        .max()
}

/// Canonicalize `data_dir` to an absolute path, resolving symlinks.
///
/// Security note: `data_dir` is NOT user-supplied. It comes from the agent's
/// `--data-dir` CLI flag (default: /var/lib/innerwarden) set at process startup,
/// not from HTTP request parameters. CodeQL traces it from the Axum handler's
/// `State<DashboardState>` but `state.data_dir` is fixed at startup, not per-request.
fn trusted_data_dir(data_dir: &Path) -> Option<PathBuf> {
    data_dir.canonicalize().ok()
}

fn collect_available_dates(data_dir: &Path) -> Vec<String> {
    let mut dates = BTreeSet::new();

    // Check SQLite store for graph snapshot dates
    if let Ok(store) = innerwarden_store::Store::open(data_dir) {
        if let Ok(snapshots) = store.list_graph_snapshots() {
            for info in snapshots {
                dates.insert(info.date);
            }
        }
    }

    // Also check filesystem for JSONL/summary files (legacy fallback)
    let data_dir = match trusted_data_dir(data_dir) {
        Some(p) => p,
        None => return dates.into_iter().collect(),
    };
    let entries = match fs::read_dir(&data_dir) {
        Ok(entries) => entries,
        Err(_) => return dates.into_iter().collect(),
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        let candidate = extract_date(&name, "events-", ".jsonl")
            .or_else(|| extract_date(&name, "incidents-", ".jsonl"))
            .or_else(|| extract_date(&name, "decisions-", ".jsonl"))
            .or_else(|| extract_date(&name, "summary-", ".md"));
        if let Some(date) = candidate {
            dates.insert(date);
        }
    }

    dates.into_iter().collect()
}

fn build_operational_telemetry(data_dir: &Path, analyzed_date: &str) -> OperationalTelemetry {
    match telemetry::read_latest_snapshot(data_dir, analyzed_date) {
        Some(snapshot) => OperationalTelemetry {
            available: true,
            last_tick: Some(snapshot.tick),
            events_by_collector: snapshot.events_by_collector,
            incidents_by_detector: snapshot.incidents_by_detector,
            gate_pass_count: snapshot.gate_pass_count,
            ai_sent_count: snapshot.ai_sent_count,
            ai_decision_count: snapshot.ai_decision_count,
            avg_decision_latency_ms: snapshot.avg_decision_latency_ms,
            errors_by_component: snapshot.errors_by_component,
            decisions_by_action: snapshot.decisions_by_action,
            dry_run_execution_count: snapshot.dry_run_execution_count,
            real_execution_count: snapshot.real_execution_count,
        },
        None => OperationalTelemetry {
            available: false,
            last_tick: None,
            events_by_collector: BTreeMap::new(),
            incidents_by_detector: BTreeMap::new(),
            gate_pass_count: 0,
            ai_sent_count: 0,
            ai_decision_count: 0,
            avg_decision_latency_ms: 0.0,
            errors_by_component: BTreeMap::new(),
            decisions_by_action: BTreeMap::new(),
            dry_run_execution_count: 0,
            real_execution_count: 0,
        },
    }
}

fn extract_date(name: &str, prefix: &str, suffix: &str) -> Option<String> {
    let raw = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .ok()
        .map(|_| raw.to_string())
}

fn parse_events_file(path: &Path, counters: &mut Counters) -> ParseOutcome {
    parse_jsonl(path, |event: Event| {
        counters.total_events += 1;

        for e in event.entities {
            let key = format!("{:?}:{}", e.r#type, e.value);
            *counters.entity_counts.entry(key).or_insert(0) += 1;

            if e.r#type == EntityType::Ip && is_report_visible_ip(&e.value) {
                *counters.ip_counts.entry(e.value).or_insert(0) += 1;
            }
        }
    })
}

fn parse_incidents_file(path: &Path, counters: &mut Counters) -> ParseOutcome {
    parse_jsonl(path, |incident: Incident| {
        counters.total_incidents += 1;

        let incident_type = incident
            .incident_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();
        *counters.incidents_by_type.entry(incident_type).or_insert(0) += 1;

        if incident.entities.is_empty() {
            counters.incidents_without_entities += 1;
        }

        for e in incident.entities {
            let key = format!("{:?}:{}", e.r#type, e.value);
            *counters.entity_counts.entry(key).or_insert(0) += 1;

            if e.r#type == EntityType::Ip && is_report_visible_ip(&e.value) {
                *counters.ip_counts.entry(e.value).or_insert(0) += 1;
            }
        }
    })
}

/// 2026-05-14 — report-page filter for the operator-facing Top IPs
/// list. Drops RFC1918 / loopback / link-local (own host noise) AND
/// `cloud_safelist::is_self_traffic_ip` matches (Cloudflare edge,
/// agent's bound interface IPs). Same filter the overview counts +
/// Cases entities apply; the Report's Top IPs panel was the last
/// surface that surfaced self-traffic as "attackers".
fn is_report_visible_ip(ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    if crate::incident_auto_rules::is_internal_ip_pub(ip) {
        return false;
    }
    if crate::cloud_safelist::is_self_traffic_ip(ip) {
        return false;
    }
    true
}

fn parse_decisions_file(path: &Path, counters: &mut Counters) -> ParseOutcome {
    let mut outcome = file_info(path);
    if !outcome.exists {
        return outcome;
    }

    let file = match File::open(path) {
        Ok(f) => {
            outcome.readable = true;
            f
        }
        Err(_) => return outcome,
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(v) => v,
            Err(_) => {
                outcome.malformed_lines += 1;
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        outcome.lines += 1;

        let value: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                outcome.malformed_lines += 1;
                continue;
            }
        };

        let action_present = value
            .get("action_type")
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if !action_present {
            counters.decisions_without_action += 1;
        }

        let decision: DecisionEntry = match serde_json::from_value(value) {
            Ok(d) => d,
            Err(_) => {
                outcome.malformed_lines += 1;
                continue;
            }
        };

        counters.total_decisions += 1;
        counters.confidence_sum += f64::from(decision.confidence);

        *counters
            .decisions_by_action
            .entry(decision.action_type.clone())
            .or_insert(0) += 1;

        if decision.action_type == "ignore" {
            counters.ignore_count += 1;
        }
        if decision.action_type == "block_ip" {
            counters.block_ip_count += 1;
        }
        if decision.dry_run {
            counters.dry_run_count += 1;
        }
        if let Some(skill) = decision.skill_id {
            *counters.skills_used.entry(skill).or_insert(0) += 1;
        }
    }

    outcome
}

/// Compute the 6-hour sliding window report.
///
/// Reads both `analyzed_date` and the previous date files, filtering entries
/// to those with a `ts` field within the last 6 hours. This correctly handles
/// midnight rollovers where the window spans two calendar days.
/// Cache for compute_recent_window keyed by (date, snapshot_mtime).
/// Same rationale as COUNTERS_CACHE: avoid disk loads on every dashboard poll.
static RECENT_WINDOW_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<(String, u64), RecentWindow>>,
> = std::sync::OnceLock::new();

fn recent_window_cache_handle(
) -> &'static std::sync::Mutex<std::collections::HashMap<(String, u64), RecentWindow>> {
    RECENT_WINDOW_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn compute_recent_window(data_dir: &Path, analyzed_date: &str) -> RecentWindow {
    compute_recent_window_at(data_dir, analyzed_date, Utc::now())
}

/// Time-injected variant of `compute_recent_window`. The public function
/// passes `Utc::now()`; tests pass a controlled instant to exercise the
/// midnight-rollover path deterministically.
fn compute_recent_window_at(
    data_dir: &Path,
    analyzed_date: &str,
    now: DateTime<Utc>,
) -> RecentWindow {
    const WINDOW_SECS: i64 = 6 * 3600;
    let cutoff = now - chrono::Duration::seconds(WINDOW_SECS);

    // Cache check: keyed on snapshot mtime + date.
    let snap_path = data_dir.join(format!("graph-snapshot-{analyzed_date}.json"));
    let mtime = std::fs::metadata(&snap_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let key = (analyzed_date.to_string(), mtime);
    if let Ok(cache) = recent_window_cache_handle().lock() {
        if let Some(w) = cache.get(&key) {
            return w.clone();
        }
    }

    // Phase 7 Gap 5: try graph snapshots for an approximate 6h window. We
    // load BOTH today's and yesterday's snapshots so cross-midnight windows
    // see all relevant buckets — pre-2026-04-23 the fast path only loaded
    // today's snapshot and string-compared bucket keys, which produced
    // zero events around midnight (`RECURRING_BUGS.md` "report.rs 6h-window
    // snapshot fast path subcounts near midnight"). Bucket keys are now
    // ISO `YYYY-MM-DDTHH:MM` (parsed via `super::knowledge_graph::buckets`)
    // so the comparison is `chrono::DateTime`-typed, not string.
    let mut snapshots: Vec<(NaiveDate, crate::knowledge_graph::KnowledgeGraph)> = Vec::new();
    if let Some(today_g) =
        crate::knowledge_graph::KnowledgeGraph::load_dated_sqlite_first(data_dir, analyzed_date)
    {
        if let Ok(d) = NaiveDate::parse_from_str(analyzed_date, "%Y-%m-%d") {
            snapshots.push((d, today_g));
        }
    }
    if let Some(prev_date_str) = NaiveDate::parse_from_str(analyzed_date, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.pred_opt())
        .map(|d| (d, d.format("%Y-%m-%d").to_string()))
    {
        let (prev_d, prev_str) = prev_date_str;
        if cutoff.date_naive() <= prev_d {
            if let Some(prev_g) =
                crate::knowledge_graph::KnowledgeGraph::load_dated_sqlite_first(data_dir, &prev_str)
            {
                snapshots.push((prev_d, prev_g));
            }
        }
    }

    let total_nodes: usize = snapshots.iter().map(|(_, g)| g.metrics().node_count).sum();
    if total_nodes > 0 {
        use crate::knowledge_graph::buckets::parse_bucket_key;
        use crate::knowledge_graph::types::{Node, NodeType};

        let mut events: u64 = 0;
        let mut incidents: u64 = 0;
        let mut high_critical: u64 = 0;
        let mut decisions: u64 = 0;
        let mut decisions_by_action: BTreeMap<String, u64> = BTreeMap::new();
        let mut latest_incident_ts = String::from("none");
        let mut seen_incident_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for (snap_date, graph) in &snapshots {
            // Walk the timeline with chrono comparison instead of string compare.
            // Old `HH:MM`-only keys (pre-fix snapshots) are interpreted as the
            // snapshot's date.
            for (bucket, sources) in &graph.event_timeline {
                if let Some(bucket_ts) = parse_bucket_key(bucket, *snap_date) {
                    if bucket_ts >= cutoff {
                        events += sources.values().sum::<usize>() as u64;
                    }
                }
            }

            for id in graph.nodes_of_type(NodeType::Incident) {
                if let Some(Node::Incident {
                    ts,
                    severity,
                    decision,
                    incident_id,
                    ..
                }) = graph.get_node(id)
                {
                    if *ts >= cutoff {
                        // Dedup across two snapshots so an Incident that was
                        // ingested yesterday and persists in today's graph too
                        // does not get double-counted.
                        if !seen_incident_ids.insert(incident_id.clone()) {
                            continue;
                        }
                        incidents += 1;
                        let sev = severity.to_lowercase();
                        if sev == "high" || sev == "critical" {
                            high_critical += 1;
                        }
                        let ts_str = ts.to_rfc3339();
                        if ts_str > latest_incident_ts || latest_incident_ts == "none" {
                            latest_incident_ts = ts_str.clone();
                        }
                        if let Some(action) = decision {
                            decisions += 1;
                            *decisions_by_action.entry(action.clone()).or_default() += 1;
                        }
                    }
                }
            }
        }

        let result = RecentWindow {
            window_secs: WINDOW_SECS as u64,
            events,
            incidents,
            high_critical_incidents: high_critical,
            decisions,
            decisions_by_action,
            latest_event_ts: "graph".to_string(),
            latest_incident_ts,
            latest_decision_ts: "graph".to_string(),
            latest_telemetry_ts: "graph".to_string(),
        };
        if let Ok(mut cache) = recent_window_cache_handle().lock() {
            if cache.len() > 30 {
                cache.clear();
            }
            cache.insert(key.clone(), result.clone());
        }
        return result;
    }

    // Fallback: JSONL scan
    // Determine which dates to scan (today + optionally yesterday)
    let dates_to_scan: Vec<String> = {
        let mut v = vec![analyzed_date.to_string()];
        if let Some(prev) = NaiveDate::parse_from_str(analyzed_date, "%Y-%m-%d")
            .ok()
            .and_then(|d| d.pred_opt())
            .map(|d| d.format("%Y-%m-%d").to_string())
        {
            v.push(prev);
        }
        v
    };

    let mut events: u64 = 0;
    let mut incidents: u64 = 0;
    let mut high_critical: u64 = 0;
    let mut decisions: u64 = 0;
    let mut decisions_by_action: BTreeMap<String, u64> = BTreeMap::new();
    let mut latest_event_ts = String::from("none");
    let mut latest_incident_ts = String::from("none");
    let mut latest_decision_ts = String::from("none");
    let mut latest_telemetry_ts = String::from("none");

    for date in &dates_to_scan {
        // ── Events ──────────────────────────────────────────────────────────
        let path = safe_dated_file(data_dir, "events", date, "jsonl");
        if let Some(f) = open_kpi_file_or_warn(&path, "events") {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
                    let ts_str = v
                        .get("ts")
                        .and_then(|t| t.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if let Ok(ts) = ts_str.parse::<DateTime<Utc>>() {
                        if ts >= cutoff {
                            events += 1;
                            if ts_str > latest_event_ts || latest_event_ts == "none" {
                                latest_event_ts = ts_str;
                            }
                        }
                    }
                }
            }
        }

        // ── Incidents ────────────────────────────────────────────────────────
        let path = safe_dated_file(data_dir, "incidents", date, "jsonl");
        if let Some(f) = open_kpi_file_or_warn(&path, "incidents") {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
                    let ts_str = v
                        .get("ts")
                        .and_then(|t| t.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if let Ok(ts) = ts_str.parse::<DateTime<Utc>>() {
                        if ts >= cutoff {
                            incidents += 1;
                            let sev = v
                                .get("severity")
                                .and_then(|s| s.as_str())
                                .unwrap_or("")
                                .to_lowercase();
                            if sev == "high" || sev == "critical" {
                                high_critical += 1;
                            }
                            if ts_str > latest_incident_ts || latest_incident_ts == "none" {
                                latest_incident_ts = ts_str;
                            }
                        }
                    }
                }
            }
        }

        // ── Decisions ────────────────────────────────────────────────────────
        let path = safe_dated_file(data_dir, "decisions", date, "jsonl");
        if let Some(f) = open_kpi_file_or_warn(&path, "decisions") {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
                    let ts_str = v
                        .get("ts")
                        .and_then(|t| t.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if let Ok(ts) = ts_str.parse::<DateTime<Utc>>() {
                        if ts >= cutoff {
                            decisions += 1;
                            let action = v
                                .get("action_type")
                                .and_then(|a| a.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            *decisions_by_action.entry(action).or_insert(0) += 1;
                            if ts_str > latest_decision_ts || latest_decision_ts == "none" {
                                latest_decision_ts = ts_str;
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Telemetry latest (today only, most recent snapshot) ─────────────────
    let telem_path = safe_dated_file(data_dir, "telemetry", analyzed_date, "jsonl");
    if let Ok(f) = File::open(&telem_path) {
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
                if let Some(ts_str) = v.get("ts").and_then(|t| t.as_str()) {
                    if ts_str > latest_telemetry_ts.as_str() || latest_telemetry_ts == "none" {
                        latest_telemetry_ts = ts_str.to_string();
                    }
                }
            }
        }
    }

    let result = RecentWindow {
        window_secs: WINDOW_SECS as u64,
        events,
        incidents,
        high_critical_incidents: high_critical,
        decisions,
        decisions_by_action,
        latest_event_ts,
        latest_incident_ts,
        latest_decision_ts,
        latest_telemetry_ts,
    };
    if let Ok(mut cache) = recent_window_cache_handle().lock() {
        if cache.len() > 30 {
            cache.clear();
        }
        cache.insert(key, result.clone());
    }
    result
}

/// Cache for compute_day_counters keyed by (date, snapshot_mtime).
/// Yesterday's snapshot is frozen, so once loaded the result is reusable
/// for the rest of the day. This prevents the dashboard /api/report endpoint
/// from re-loading the disk snapshot on every poll (was causing 2 graph
/// loads + integrity-check pruning every 30s on each dashboard refresh).
static COUNTERS_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<(String, u64), Counters>>,
> = std::sync::OnceLock::new();

fn cache_handle() -> &'static std::sync::Mutex<std::collections::HashMap<(String, u64), Counters>> {
    COUNTERS_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn compute_day_counters(data_dir: &Path, date: &str) -> Counters {
    // Cache key: (date, snapshot_mtime). If mtime hasn't changed, return cached.
    let snap_path = data_dir.join(format!("graph-snapshot-{date}.json"));
    let mtime = std::fs::metadata(&snap_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let key = (date.to_string(), mtime);
    if let Ok(cache) = cache_handle().lock() {
        if let Some(c) = cache.get(&key) {
            return c.clone();
        }
    }

    // Try SQLite store first, then dated file snapshot, then JSONL
    let mut counters = {
        let from_store = innerwarden_store::Store::open(data_dir)
            .ok()
            .and_then(|store| {
                crate::knowledge_graph::KnowledgeGraph::load_dated_from_store(&store, date)
            })
            .filter(|g| g.metrics().node_count > 0);
        if let Some(graph) = from_store {
            counters_from_graph(&graph)
        } else if let Some(graph) =
            crate::knowledge_graph::KnowledgeGraph::load_dated(data_dir, date)
        {
            if graph.metrics().node_count > 0 {
                counters_from_graph(&graph)
            } else {
                counters_from_jsonl(data_dir, date)
            }
        } else {
            counters_from_jsonl(data_dir, date)
        }
    };

    // PR28 — same SQLite-events override as compute_for_date_from_graph.
    // The dated-graph path counts edges as a proxy for events; the
    // SQLite `events` table is the canonical source per spec 016.
    // Without this the Report's Trend showed `Events 146,887` while
    // the Home strip showed `~213,000` for the SAME day.
    if let Ok(store) = innerwarden_store::Store::open(data_dir) {
        if let Ok(count) = store.events_count_for_date(date) {
            counters.total_events = count;
        }
    }

    if let Ok(mut cache) = cache_handle().lock() {
        // Cap cache size to prevent unbounded growth
        if cache.len() > 30 {
            cache.clear();
        }
        cache.insert(key, counters.clone());
    }

    counters
}

fn counters_from_jsonl(data_dir: &Path, date: &str) -> Counters {
    let events = safe_dated_file(data_dir, "events", date, "jsonl");
    let incidents = safe_dated_file(data_dir, "incidents", date, "jsonl");
    let decisions = safe_dated_file(data_dir, "decisions", date, "jsonl");

    let mut counters = Counters::default();
    parse_events_file(&events, &mut counters);
    parse_incidents_file(&incidents, &mut counters);
    parse_decisions_file(&decisions, &mut counters);
    counters
}

/// Extract report counters from a graph snapshot (Phase 7).
fn counters_from_graph(graph: &crate::knowledge_graph::KnowledgeGraph) -> Counters {
    let mut counters = Counters::default();
    populate_counters_from_graph(graph, &mut counters);
    counters
}

fn parse_state_file(path: &Path) -> ParseOutcome {
    let mut outcome = file_info(path);
    if !outcome.exists {
        return outcome;
    }
    let content = match fs::read_to_string(path) {
        Ok(c) => {
            outcome.readable = true;
            c
        }
        Err(_) => return outcome,
    };
    if serde_json::from_str::<Value>(&content).is_err() {
        outcome.readable = false;
    }
    outcome
}

fn parse_plain_file(path: &Path) -> ParseOutcome {
    let mut outcome = file_info(path);
    if !outcome.exists {
        return outcome;
    }
    if File::open(path).is_ok() {
        outcome.readable = true;
    }
    outcome
}

fn parse_jsonl<T, F>(path: &Path, mut on_item: F) -> ParseOutcome
where
    T: serde::de::DeserializeOwned,
    F: FnMut(T),
{
    let mut outcome = file_info(path);
    if !outcome.exists {
        return outcome;
    }

    let file = match File::open(path) {
        Ok(f) => {
            outcome.readable = true;
            f
        }
        Err(_) => return outcome,
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(v) => v,
            Err(_) => {
                outcome.malformed_lines += 1;
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        outcome.lines += 1;
        match serde_json::from_str::<T>(trimmed) {
            Ok(item) => on_item(item),
            Err(_) => outcome.malformed_lines += 1,
        }
    }

    outcome
}

fn file_info(path: &Path) -> ParseOutcome {
    match fs::metadata(path) {
        Ok(meta) => ParseOutcome {
            exists: true,
            size_bytes: meta.len(),
            modified_secs_ago: meta
                .modified()
                .ok()
                .and_then(|m| SystemTime::now().duration_since(m).ok())
                .map(|d| d.as_secs()),
            ..Default::default()
        },
        Err(_) => ParseOutcome::default(),
    }
}

fn file_health_jsonl(name: &str, outcome: &ParseOutcome) -> FileHealth {
    FileHealth {
        file: name.to_string(),
        exists: outcome.exists,
        readable: outcome.readable,
        size_bytes: outcome.size_bytes,
        modified_secs_ago: outcome.modified_secs_ago,
        jsonl_valid: Some(outcome.jsonl_valid()),
        lines: Some(outcome.lines),
        malformed_lines: Some(outcome.malformed_lines),
    }
}

fn file_health_plain(name: &str, outcome: &ParseOutcome) -> FileHealth {
    FileHealth {
        file: name.to_string(),
        exists: outcome.exists,
        readable: outcome.readable,
        size_bytes: outcome.size_bytes,
        modified_secs_ago: outcome.modified_secs_ago,
        jsonl_valid: None,
        lines: None,
        malformed_lines: None,
    }
}

fn record_quality_hints(
    name: &str,
    outcome: &ParseOutcome,
    check_growth: bool,
    counters: &mut Counters,
) {
    if outcome.exists && outcome.size_bytes == 0 {
        counters.empty_files.push(name.to_string());
    }
    if outcome.malformed_lines > 0 {
        counters
            .malformed_jsonl
            .insert(name.to_string(), outcome.malformed_lines);
    }
    if check_growth
        && outcome.exists
        && outcome.size_bytes > 0
        && outcome.modified_secs_ago.unwrap_or(0) > 6 * 60 * 60
    {
        counters.files_not_growing.push(name.to_string());
    }
}

fn record_plain_file_hints(
    name: &str,
    outcome: &ParseOutcome,
    check_growth: bool,
    counters: &mut Counters,
) {
    if outcome.exists && outcome.size_bytes == 0 {
        counters.empty_files.push(name.to_string());
    }
    if check_growth
        && outcome.exists
        && outcome.size_bytes > 0
        && outcome.modified_secs_ago.unwrap_or(0) > 6 * 60 * 60
    {
        counters.files_not_growing.push(name.to_string());
    }
}

fn to_btreemap(map: HashMap<String, u64>) -> BTreeMap<String, u64> {
    map.into_iter().collect()
}

fn top_n(map: &HashMap<String, u64>, n: usize) -> Vec<NamedCount> {
    let mut items: Vec<NamedCount> = map
        .iter()
        .map(|(name, count)| NamedCount {
            name: name.clone(),
            count: *count,
        })
        .collect();
    items.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    items.truncate(n);
    items
}

fn build_trend_summary(
    current: &Counters,
    previous: Option<&Counters>,
    previous_date: Option<String>,
) -> TrendSummary {
    let previous_events = previous.map(|c| c.total_events).unwrap_or(0);
    let previous_incidents = previous.map(|c| c.total_incidents).unwrap_or(0);
    let previous_decisions = previous.map(|c| c.total_decisions).unwrap_or(0);

    let current_incident_rate = incident_rate_per_1k_events(current);
    let previous_incident_rate = previous.map(incident_rate_per_1k_events).unwrap_or(0.0);

    let current_decision_rate = decision_rate_per_incident(current);
    let previous_decision_rate = previous.map(decision_rate_per_incident).unwrap_or(0.0);

    let current_avg_conf = average_confidence(current);
    let previous_avg_conf = previous.map(average_confidence).unwrap_or(0.0);

    TrendSummary {
        previous_date,
        events: count_delta(current.total_events, previous_events),
        incidents: count_delta(current.total_incidents, previous_incidents),
        decisions: count_delta(current.total_decisions, previous_decisions),
        incident_rate_per_1k_events: float_delta(current_incident_rate, previous_incident_rate),
        decision_rate_per_incident: float_delta(current_decision_rate, previous_decision_rate),
        average_confidence: float_delta(current_avg_conf, previous_avg_conf),
    }
}

fn build_anomaly_hints(
    detection_summary: &DetectionSummary,
    agent_ai_summary: &AgentAiSummary,
    data_quality: &DataQuality,
    trend_summary: &TrendSummary,
    previous: Option<&Counters>,
) -> Vec<AnomalyHint> {
    let mut hints = Vec::new();

    if !data_quality.malformed_jsonl.is_empty() {
        hints.push(AnomalyHint {
            severity: "high".to_string(),
            code: "malformed_jsonl".to_string(),
            message: format!(
                "Malformed JSONL detected: {}.",
                map_or_none(&data_quality.malformed_jsonl)
            ),
        });
    }

    if detection_summary.total_events == 0 {
        hints.push(AnomalyHint {
            severity: "high".to_string(),
            code: "no_events".to_string(),
            message:
                "No events captured for analyzed day; collectors may be blocked or misconfigured."
                    .to_string(),
        });
    }

    if detection_summary.total_incidents > 0 && agent_ai_summary.total_decisions == 0 {
        hints.push(AnomalyHint {
            severity: "high".to_string(),
            code: "incident_without_ai_decision".to_string(),
            message: "Incidents exist but no AI decisions were recorded; check agent AI settings and credentials."
                .to_string(),
        });
    }

    if trend_summary.incidents.previous > 0
        && trend_summary.incidents.delta >= 5
        && trend_summary.incidents.pct_change.unwrap_or(0.0) >= 100.0
    {
        hints.push(AnomalyHint {
            severity: "high".to_string(),
            code: "incident_spike".to_string(),
            message: format!(
                "Incidents doubled or more vs previous day (delta: {}).",
                signed_i64(trend_summary.incidents.delta)
            ),
        });
    }

    if trend_summary.average_confidence.delta <= -0.2
        && trend_summary.decisions.current >= 5
        && trend_summary.decisions.previous >= 5
    {
        hints.push(AnomalyHint {
            severity: "medium".to_string(),
            code: "confidence_drop".to_string(),
            message: format!(
                "Average AI confidence dropped from {:.3} to {:.3}.",
                trend_summary.average_confidence.previous, trend_summary.average_confidence.current
            ),
        });
    }

    if agent_ai_summary.total_decisions >= 10 {
        let ignore_ratio =
            agent_ai_summary.ignore_count as f64 / agent_ai_summary.total_decisions as f64;
        if ignore_ratio > 0.9 {
            hints.push(AnomalyHint {
                severity: "medium".to_string(),
                code: "ignore_saturation".to_string(),
                message: format!(
                    "Ignore ratio is {:.1}% ({} of {} decisions).",
                    ignore_ratio * 100.0,
                    agent_ai_summary.ignore_count,
                    agent_ai_summary.total_decisions
                ),
            });
        }
    }

    if let Some(previous) = previous {
        let mut new_incident_types = Vec::new();
        for (kind, count) in &detection_summary.incidents_by_type {
            let previous_count = previous.incidents_by_type.get(kind).copied().unwrap_or(0);
            if previous_count == 0 && *count >= 3 {
                new_incident_types.push(kind.clone());
            }
        }
        if !new_incident_types.is_empty() {
            new_incident_types.sort();
            hints.push(AnomalyHint {
                severity: "medium".to_string(),
                code: "new_incident_type".to_string(),
                message: format!(
                    "New incident types crossed noise floor: {}.",
                    new_incident_types.join(", ")
                ),
            });
        }
    }

    if !data_quality.files_not_growing.is_empty() {
        hints.push(AnomalyHint {
            severity: "medium".to_string(),
            code: "stale_ingest_files".to_string(),
            message: format!(
                "Some active-day artifacts look stale: {}.",
                list_or_none(&data_quality.files_not_growing)
            ),
        });
    }

    hints
}

fn count_delta(current: u64, previous: u64) -> CountDelta {
    CountDelta {
        current,
        previous,
        delta: signed_u64_diff(current, previous),
        pct_change: pct_change(current as f64, previous as f64),
    }
}

fn float_delta(current: f64, previous: f64) -> FloatDelta {
    FloatDelta {
        current,
        previous,
        delta: current - previous,
        pct_change: pct_change(current, previous),
    }
}

fn average_confidence(counters: &Counters) -> f64 {
    if counters.total_decisions > 0 {
        counters.confidence_sum / counters.total_decisions as f64
    } else {
        0.0
    }
}

fn incident_rate_per_1k_events(counters: &Counters) -> f64 {
    if counters.total_events > 0 {
        counters.total_incidents as f64 * 1000.0 / counters.total_events as f64
    } else {
        0.0
    }
}

fn decision_rate_per_incident(counters: &Counters) -> f64 {
    if counters.total_incidents > 0 {
        counters.total_decisions as f64 / counters.total_incidents as f64
    } else {
        0.0
    }
}

fn pct_change(current: f64, previous: f64) -> Option<f64> {
    if previous.abs() < f64::EPSILON {
        None
    } else {
        Some(((current - previous) / previous) * 100.0)
    }
}

fn signed_u64_diff(current: u64, previous: u64) -> i64 {
    if current >= previous {
        (current - previous).min(i64::MAX as u64) as i64
    } else {
        -((previous - current).min(i64::MAX as u64) as i64)
    }
}

fn build_suggestions(report: &TrialReport) -> Vec<String> {
    let mut suggestions = Vec::new();

    if !report.operational_health.expected_files_present {
        suggestions.push(
            "Some expected artifacts are missing; verify both sensor and agent services are running."
                .to_string(),
        );
    }
    if !report.operational_health.state_json_readable
        || !report.operational_health.agent_state_json_readable
    {
        suggestions.push(
            "State files could not be parsed; inspect state.json/agent-state.json integrity."
                .to_string(),
        );
    }
    if !report.data_quality.malformed_jsonl.is_empty() {
        suggestions.push(
            "Malformed JSONL lines detected; review producer logs and rotate corrupted files."
                .to_string(),
        );
    }
    if report.detection_summary.total_events == 0 {
        suggestions.push(
            "No events were captured; validate collector permissions (auth.log/journald access)."
                .to_string(),
        );
    }
    if report.detection_summary.total_incidents == 0 && report.detection_summary.total_events > 0 {
        suggestions.push(
            "Events exist but no incidents; run a controlled SSH brute-force test to validate detection."
                .to_string(),
        );
    }
    if report.detection_summary.total_incidents > 0 && report.agent_ai_summary.total_decisions == 0
    {
        suggestions.push(
            "Incidents exist but no AI decisions; verify agent AI config and API key availability."
                .to_string(),
        );
    }
    if report.agent_ai_summary.total_decisions > 0 {
        let ignore_ratio = report.agent_ai_summary.ignore_count as f64
            / report.agent_ai_summary.total_decisions as f64;
        if ignore_ratio > 0.8 {
            suggestions.push(
                "Most activity is being filtered as benign — normal for an internet-facing host. No action needed unless you expected some of it to be blocked."
                    .to_string(),
            );
        }
    }
    // `incidents_without_entities` is an internal detector-payload diagnostic,
    // not something the operator can act on, so it is deliberately NOT surfaced
    // as an operator suggestion.
    if !report.data_quality.files_not_growing.is_empty() {
        suggestions.push(
            "Some active-day files appear stale (>6h without updates); verify ingest pipeline health."
                .to_string(),
        );
    }
    if !report.operational_telemetry.available {
        suggestions.push(
            "Telemetry snapshot not found; run the agent with telemetry enabled for richer health metrics on the dashboard."
                .to_string(),
        );
    } else {
        if !report.operational_telemetry.errors_by_component.is_empty() {
            suggestions.push(
                "Some components reported errors; check the Health tab and inspect the error counters."
                    .to_string(),
            );
        }
        if report.operational_telemetry.ai_decision_count > 0
            && report.operational_telemetry.avg_decision_latency_ms > 2000.0
        {
            suggestions.push(
                "AI decision latency is high (>2s avg); check your AI provider and network — slow decisions delay automatic responses."
                    .to_string(),
            );
        }
    }
    if !report.anomaly_hints.is_empty() {
        suggestions.push(
            "Recent activity shows day-over-day spikes or behaviour shifts — worth a look in the Intelligence tab."
                .to_string(),
        );
    }
    if suggestions.is_empty() {
        suggestions.push("Everything looks healthy — no action needed.".to_string());
    }

    suggestions
}

fn render_markdown(report: &TrialReport) -> String {
    let mut out = String::new();
    let _ = writeln!(&mut out, "# InnerWarden Trial Report");
    let _ = writeln!(&mut out);
    let _ = writeln!(
        &mut out,
        "- Generated at: {}",
        report.generated_at.to_rfc3339()
    );
    let _ = writeln!(&mut out, "- Analyzed date: {}", report.analyzed_date);
    let _ = writeln!(&mut out, "- Data dir: `{}`", report.data_dir);
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Operational health");
    let _ = writeln!(
        &mut out,
        "- Expected files present: {}",
        yes_no(report.operational_health.expected_files_present)
    );
    let _ = writeln!(
        &mut out,
        "- state.json readable: {}",
        yes_no(report.operational_health.state_json_readable)
    );
    let _ = writeln!(
        &mut out,
        "- agent-state.json readable: {}",
        yes_no(report.operational_health.agent_state_json_readable)
    );
    let _ = writeln!(&mut out);
    let _ = writeln!(
        &mut out,
        "| File | Exists | Readable | Size (bytes) | JSONL valid | Lines | Malformed |"
    );
    let _ = writeln!(
        &mut out,
        "|------|--------|----------|--------------|-------------|-------|-----------|"
    );
    for f in &report.operational_health.files {
        let _ = writeln!(
            &mut out,
            "| {} | {} | {} | {} | {} | {} | {} |",
            f.file,
            yes_no(f.exists),
            yes_no(f.readable),
            f.size_bytes,
            f.jsonl_valid.map(yes_no).unwrap_or_else(|| "-".to_string()),
            f.lines
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            f.malformed_lines
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
        );
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Detection summary");
    let _ = writeln!(
        &mut out,
        "- Total events: {}",
        report.detection_summary.total_events
    );
    let _ = writeln!(
        &mut out,
        "- Total incidents: {}",
        report.detection_summary.total_incidents
    );
    let _ = writeln!(&mut out, "- Incidents by type:");
    if report.detection_summary.incidents_by_type.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (k, v) in &report.detection_summary.incidents_by_type {
            let _ = writeln!(&mut out, "  - {}: {}", k, v);
        }
    }
    let _ = writeln!(&mut out, "- Top IPs:");
    if report.detection_summary.top_ips.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for e in &report.detection_summary.top_ips {
            let _ = writeln!(&mut out, "  - {}: {}", e.name, e.count);
        }
    }
    let _ = writeln!(&mut out, "- Most frequent entities:");
    if report.detection_summary.top_entities.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for e in &report.detection_summary.top_entities {
            let _ = writeln!(&mut out, "  - {}: {}", e.name, e.count);
        }
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Agent / AI summary");
    let _ = writeln!(
        &mut out,
        "- Total decisions: {}",
        report.agent_ai_summary.total_decisions
    );
    let _ = writeln!(
        &mut out,
        "- Average confidence: {:.3}",
        report.agent_ai_summary.average_confidence
    );
    let _ = writeln!(
        &mut out,
        "- Ignore decisions: {}",
        report.agent_ai_summary.ignore_count
    );
    let _ = writeln!(
        &mut out,
        "- block_ip decisions: {}",
        report.agent_ai_summary.block_ip_count
    );
    let _ = writeln!(
        &mut out,
        "- Dry-run decisions: {}",
        report.agent_ai_summary.dry_run_count
    );
    let _ = writeln!(&mut out, "- Decisions by action:");
    if report.agent_ai_summary.decisions_by_action.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (k, v) in &report.agent_ai_summary.decisions_by_action {
            let _ = writeln!(&mut out, "  - {}: {}", k, v);
        }
    }
    let _ = writeln!(&mut out, "- Skills used:");
    if report.agent_ai_summary.skills_used.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (k, v) in &report.agent_ai_summary.skills_used {
            let _ = writeln!(&mut out, "  - {}: {}", k, v);
        }
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Recent 6h window");
    let _ = writeln!(&mut out, "- Events: {}", report.recent_window.events);
    let _ = writeln!(&mut out, "- Incidents: {}", report.recent_window.incidents);
    let _ = writeln!(
        &mut out,
        "- High/critical incidents: {}",
        report.recent_window.high_critical_incidents
    );
    let _ = writeln!(&mut out, "- Decisions: {}", report.recent_window.decisions);
    let _ = writeln!(&mut out, "- Decisions by action:");
    if report.recent_window.decisions_by_action.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (k, v) in &report.recent_window.decisions_by_action {
            let _ = writeln!(&mut out, "  - {}: {}", k, v);
        }
    }
    let _ = writeln!(
        &mut out,
        "- Latest event ts: {}",
        report.recent_window.latest_event_ts
    );
    let _ = writeln!(
        &mut out,
        "- Latest incident ts: {}",
        report.recent_window.latest_incident_ts
    );
    let _ = writeln!(
        &mut out,
        "- Latest decision ts: {}",
        report.recent_window.latest_decision_ts
    );
    let _ = writeln!(
        &mut out,
        "- Latest telemetry ts: {}",
        report.recent_window.latest_telemetry_ts
    );
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Operational telemetry");
    let _ = writeln!(
        &mut out,
        "- Available: {}",
        yes_no(report.operational_telemetry.available)
    );
    if let Some(last_tick) = &report.operational_telemetry.last_tick {
        let _ = writeln!(&mut out, "- Last tick snapshot: {}", last_tick);
    } else {
        let _ = writeln!(&mut out, "- Last tick snapshot: none");
    }
    let _ = writeln!(
        &mut out,
        "- Gate pass count: {}",
        report.operational_telemetry.gate_pass_count
    );
    let _ = writeln!(
        &mut out,
        "- AI sent count: {}",
        report.operational_telemetry.ai_sent_count
    );
    let _ = writeln!(
        &mut out,
        "- AI decision count: {}",
        report.operational_telemetry.ai_decision_count
    );
    let _ = writeln!(
        &mut out,
        "- Avg decision latency (ms): {:.2}",
        report.operational_telemetry.avg_decision_latency_ms
    );
    let _ = writeln!(
        &mut out,
        "- Dry-run executions: {}",
        report.operational_telemetry.dry_run_execution_count
    );
    let _ = writeln!(
        &mut out,
        "- Real executions: {}",
        report.operational_telemetry.real_execution_count
    );
    let _ = writeln!(&mut out, "- Events by collector:");
    if report.operational_telemetry.events_by_collector.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (collector, count) in &report.operational_telemetry.events_by_collector {
            let _ = writeln!(&mut out, "  - {}: {}", collector, count);
        }
    }
    let _ = writeln!(&mut out, "- Incidents by detector:");
    if report
        .operational_telemetry
        .incidents_by_detector
        .is_empty()
    {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (detector, count) in &report.operational_telemetry.incidents_by_detector {
            let _ = writeln!(&mut out, "  - {}: {}", detector, count);
        }
    }
    let _ = writeln!(&mut out, "- Errors by component:");
    if report.operational_telemetry.errors_by_component.is_empty() {
        let _ = writeln!(&mut out, "  - none");
    } else {
        for (component, count) in &report.operational_telemetry.errors_by_component {
            let _ = writeln!(&mut out, "  - {}: {}", component, count);
        }
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Trend deltas (v2)");
    match &report.trend_summary.previous_date {
        Some(previous_date) => {
            let _ = writeln!(&mut out, "- Previous date: {}", previous_date);
            let _ = writeln!(
                &mut out,
                "- Events: {}",
                render_count_delta(&report.trend_summary.events)
            );
            let _ = writeln!(
                &mut out,
                "- Incidents: {}",
                render_count_delta(&report.trend_summary.incidents)
            );
            let _ = writeln!(
                &mut out,
                "- Decisions: {}",
                render_count_delta(&report.trend_summary.decisions)
            );
            let _ = writeln!(
                &mut out,
                "- Incident rate / 1k events: {}",
                render_float_delta(&report.trend_summary.incident_rate_per_1k_events, 3)
            );
            let _ = writeln!(
                &mut out,
                "- Decision rate / incident: {}",
                render_float_delta(&report.trend_summary.decision_rate_per_incident, 3)
            );
            let _ = writeln!(
                &mut out,
                "- Average confidence: {}",
                render_float_delta(&report.trend_summary.average_confidence, 3)
            );
        }
        None => {
            let _ = writeln!(
                &mut out,
                "- No previous day artifacts found; trend deltas will appear after another full day."
            );
        }
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Anomaly hints");
    if report.anomaly_hints.is_empty() {
        let _ = writeln!(&mut out, "- none");
    } else {
        for hint in &report.anomaly_hints {
            let _ = writeln!(
                &mut out,
                "- [{}] {}: {}",
                hint.severity, hint.code, hint.message
            );
        }
    }
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Data quality / anomalies");
    let _ = writeln!(
        &mut out,
        "- Empty files: {}",
        list_or_none(&report.data_quality.empty_files)
    );
    let _ = writeln!(
        &mut out,
        "- Malformed JSONL: {}",
        map_or_none(&report.data_quality.malformed_jsonl)
    );
    let _ = writeln!(
        &mut out,
        "- Incidents without entities: {}",
        report.data_quality.incidents_without_entities
    );
    let _ = writeln!(
        &mut out,
        "- Decisions without action: {}",
        report.data_quality.decisions_without_action
    );
    let _ = writeln!(
        &mut out,
        "- Files not growing (heuristic): {}",
        list_or_none(&report.data_quality.files_not_growing)
    );
    let _ = writeln!(&mut out);

    let _ = writeln!(&mut out, "## Suggested improvements");
    for suggestion in &report.suggested_improvements {
        let _ = writeln!(&mut out, "- {}", suggestion);
    }

    out
}

fn yes_no(v: bool) -> String {
    if v {
        "yes".to_string()
    } else {
        "no".to_string()
    }
}

fn render_count_delta(delta: &CountDelta) -> String {
    format!(
        "current={} previous={} delta={} ({})",
        delta.current,
        delta.previous,
        signed_i64(delta.delta),
        format_pct(delta.pct_change)
    )
}

fn render_float_delta(delta: &FloatDelta, precision: usize) -> String {
    format!(
        "current={cur:.p$} previous={prev:.p$} delta={signed} ({pct})",
        cur = delta.current,
        prev = delta.previous,
        p = precision,
        signed = signed_f64(delta.delta, precision),
        pct = format_pct(delta.pct_change)
    )
}

fn signed_i64(v: i64) -> String {
    if v > 0 {
        format!("+{v}")
    } else {
        v.to_string()
    }
}

fn signed_f64(v: f64, precision: usize) -> String {
    if v > 0.0 {
        format!("+{:.*}", precision, v)
    } else {
        format!("{:.*}", precision, v)
    }
}

fn format_pct(v: Option<f64>) -> String {
    match v {
        Some(v) => format!("{:+.1}%", v),
        None => "n/a".to_string(),
    }
}

fn list_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn map_or_none(items: &BTreeMap<String, u64>) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};

    use crate::knowledge_graph::types::{Edge, Node, Relation};
    use crate::telemetry::TelemetrySnapshot;
    use chrono::{Local, Utc};
    use innerwarden_core::{
        entities::EntityRef,
        event::{Event, Severity},
        incident::Incident,
    };
    use tempfile::TempDir;

    #[test]
    fn generates_report_files_and_counts() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        let events_path = dir.path().join(format!("events-{date}.jsonl"));
        let incidents_path = dir.path().join(format!("incidents-{date}.jsonl"));
        let decisions_path = dir.path().join(format!("decisions-{date}.jsonl"));
        let summary_path = dir.path().join(format!("summary-{date}.md"));
        let state_path = dir.path().join("state.json");
        let agent_state_path = dir.path().join("agent-state.json");

        let e1 = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: "fail".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4"), EntityRef::user("root")],
        };
        let e2 = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: "fail2".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        fs::write(
            &events_path,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&e1).unwrap(),
                serde_json::to_string(&e2).unwrap()
            ),
        )
        .unwrap();

        let inc = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
            severity: Severity::High,
            title: "bruteforce".to_string(),
            summary: "summary".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        fs::write(
            &incidents_path,
            format!("{}\n", serde_json::to_string(&inc).unwrap()),
        )
        .unwrap();

        let dec = DecisionEntry {
            ts: Utc::now(),
            incident_id: inc.incident_id.clone(),
            host: "h".to_string(),
            ai_provider: "openai".to_string(),
            action_type: "ignore".to_string(),
            target_ip: None,
            target_user: None,
            skill_id: None,
            confidence: 0.8,
            auto_executed: false,
            dry_run: true,
            reason: "test".to_string(),
            estimated_threat: "low".to_string(),
            execution_result: "skipped".to_string(),
            prev_hash: None,
            decision_layer: None,
        };
        fs::write(
            &decisions_path,
            format!("{}\n", serde_json::to_string(&dec).unwrap()),
        )
        .unwrap();

        fs::write(&summary_path, "# summary\n").unwrap();
        fs::write(&state_path, r#"{"cursors":{"auth_log":10}}"#).unwrap();
        fs::write(
            &agent_state_path,
            r#"{"events":{"2026-03-13":10},"incidents":{"2026-03-13":5}}"#,
        )
        .unwrap();

        let out = generate(dir.path(), dir.path()).unwrap();
        assert!(out.markdown_path.exists());
        assert!(out.json_path.exists());
        assert_eq!(out.report.detection_summary.total_events, 2);
        assert_eq!(out.report.detection_summary.total_incidents, 1);
        assert_eq!(out.report.agent_ai_summary.total_decisions, 1);
        assert!(out.report.trend_summary.previous_date.is_none());
    }

    #[test]
    fn tracks_malformed_decisions_and_missing_action() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        fs::write(
            dir.path().join(format!("events-{date}.jsonl")),
            "not-json\n",
        )
        .unwrap();
        fs::write(dir.path().join(format!("incidents-{date}.jsonl")), "").unwrap();
        fs::write(
            dir.path().join(format!("decisions-{date}.jsonl")),
            r#"{"foo":"bar","confidence":0.5}"#,
        )
        .unwrap();
        fs::write(dir.path().join(format!("summary-{date}.md")), "").unwrap();
        fs::write(dir.path().join("state.json"), "{}").unwrap();
        fs::write(dir.path().join("agent-state.json"), "{}").unwrap();

        let out = generate(dir.path(), dir.path()).unwrap();
        assert!(out.report.data_quality.decisions_without_action > 0);
        assert!(!out.report.data_quality.malformed_jsonl.is_empty());
        let anomaly_codes: HashSet<&str> = out
            .report
            .anomaly_hints
            .iter()
            .map(|hint| hint.code.as_str())
            .collect();
        assert!(anomaly_codes.contains("malformed_jsonl"));
    }

    #[test]
    fn computes_day_over_day_trends_and_anomalies() {
        let dir = TempDir::new().unwrap();
        let previous_date = "2026-03-12";
        let current_date = "2026-03-13";

        let previous_events = dir.path().join(format!("events-{previous_date}.jsonl"));
        let previous_incidents = dir.path().join(format!("incidents-{previous_date}.jsonl"));
        let previous_decisions = dir.path().join(format!("decisions-{previous_date}.jsonl"));
        let previous_summary = dir.path().join(format!("summary-{previous_date}.md"));

        let current_events = dir.path().join(format!("events-{current_date}.jsonl"));
        let current_incidents = dir.path().join(format!("incidents-{current_date}.jsonl"));
        let current_decisions = dir.path().join(format!("decisions-{current_date}.jsonl"));
        let current_summary = dir.path().join(format!("summary-{current_date}.md"));

        let state_path = dir.path().join("state.json");
        let agent_state_path = dir.path().join("agent-state.json");

        let prev_events_payload = (0..4)
            .map(|_| {
                serde_json::to_string(&Event {
                    ts: Utc::now(),
                    host: "h".to_string(),
                    source: "auth.log".to_string(),
                    kind: "ssh.login_failed".to_string(),
                    severity: Severity::Info,
                    summary: "prev".to_string(),
                    details: serde_json::json!({}),
                    tags: vec![],
                    entities: vec![EntityRef::ip("1.2.3.4"), EntityRef::user("root")],
                })
                .unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&previous_events, format!("{prev_events_payload}\n")).unwrap();

        let previous_incident = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:prev".to_string(),
            severity: Severity::High,
            title: "bruteforce".to_string(),
            summary: "prev".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        fs::write(
            &previous_incidents,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&previous_incident).unwrap(),
                serde_json::to_string(&previous_incident).unwrap()
            ),
        )
        .unwrap();

        let previous_decisions_payload = (0..6)
            .map(|i| {
                serde_json::to_string(&DecisionEntry {
                    ts: Utc::now(),
                    incident_id: format!("prev-{i}"),
                    host: "h".to_string(),
                    ai_provider: "openai".to_string(),
                    action_type: if i == 0 { "ignore" } else { "block_ip" }.to_string(),
                    target_ip: Some("1.2.3.4".to_string()),
                    target_user: None,
                    skill_id: Some("block-ip-ufw".to_string()),
                    confidence: 0.95,
                    auto_executed: false,
                    dry_run: true,
                    reason: "prev".to_string(),
                    estimated_threat: "high".to_string(),
                    execution_result: "skipped".to_string(),
                    prev_hash: None,
                    decision_layer: None,
                })
                .unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(
            &previous_decisions,
            format!("{previous_decisions_payload}\n"),
        )
        .unwrap();
        fs::write(&previous_summary, "# prev\n").unwrap();

        let current_events_payload = (0..20)
            .map(|_| {
                serde_json::to_string(&Event {
                    ts: Utc::now(),
                    host: "h".to_string(),
                    source: "auth.log".to_string(),
                    kind: "ssh.login_failed".to_string(),
                    severity: Severity::Info,
                    summary: "current".to_string(),
                    details: serde_json::json!({}),
                    tags: vec![],
                    entities: vec![EntityRef::ip("1.2.3.4"), EntityRef::user("root")],
                })
                .unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&current_events, format!("{current_events_payload}\n")).unwrap();

        let current_bruteforce = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:current".to_string(),
            severity: Severity::High,
            title: "bruteforce".to_string(),
            summary: "current".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        let current_port_scan = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "port_scan:1.2.3.4:current".to_string(),
            severity: Severity::High,
            title: "port scan".to_string(),
            summary: "current".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        let current_incidents_payload = vec![
            &current_bruteforce,
            &current_bruteforce,
            &current_bruteforce,
            &current_bruteforce,
            &current_bruteforce,
            &current_port_scan,
            &current_port_scan,
            &current_port_scan,
            &current_port_scan,
            &current_port_scan,
        ]
        .into_iter()
        .map(|incident| serde_json::to_string(incident).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
        fs::write(&current_incidents, format!("{current_incidents_payload}\n")).unwrap();

        let current_decisions_payload = (0..12)
            .map(|i| {
                serde_json::to_string(&DecisionEntry {
                    ts: Utc::now(),
                    incident_id: format!("current-{i}"),
                    host: "h".to_string(),
                    ai_provider: "openai".to_string(),
                    action_type: if i < 11 { "ignore" } else { "block_ip" }.to_string(),
                    target_ip: Some("1.2.3.4".to_string()),
                    target_user: None,
                    skill_id: Some("block-ip-ufw".to_string()),
                    confidence: 0.4,
                    auto_executed: false,
                    dry_run: true,
                    reason: "current".to_string(),
                    estimated_threat: "medium".to_string(),
                    execution_result: "skipped".to_string(),
                    prev_hash: None,
                    decision_layer: None,
                })
                .unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&current_decisions, format!("{current_decisions_payload}\n")).unwrap();

        fs::write(&current_summary, "# current\n").unwrap();
        fs::write(&state_path, r#"{"cursors":{"auth_log":10}}"#).unwrap();
        fs::write(
            &agent_state_path,
            r#"{"events":{"2026-03-13":10},"incidents":{"2026-03-13":5}}"#,
        )
        .unwrap();

        let out = generate(dir.path(), dir.path()).unwrap();

        assert_eq!(
            out.report.trend_summary.previous_date,
            Some(previous_date.to_string())
        );
        assert_eq!(out.report.trend_summary.incidents.current, 10);
        assert_eq!(out.report.trend_summary.incidents.previous, 2);
        assert_eq!(out.report.trend_summary.incidents.delta, 8);
        assert!(out.report.trend_summary.incidents.pct_change.unwrap_or(0.0) > 100.0);

        let anomaly_codes: HashSet<&str> = out
            .report
            .anomaly_hints
            .iter()
            .map(|hint| hint.code.as_str())
            .collect();
        assert!(anomaly_codes.contains("incident_spike"));
        assert!(anomaly_codes.contains("confidence_drop"));
        assert!(anomaly_codes.contains("ignore_saturation"));
        assert!(anomaly_codes.contains("new_incident_type"));
    }

    #[test]
    fn compute_for_date_happy_path_with_explicit_date() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-16";

        let event = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: "event".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4"), EntityRef::user("root")],
        };
        fs::write(
            dir.path().join(format!("events-{date}.jsonl")),
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();

        let incident = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
            severity: Severity::High,
            title: "bruteforce".to_string(),
            summary: "summary".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        fs::write(
            dir.path().join(format!("incidents-{date}.jsonl")),
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();

        let decision = DecisionEntry {
            ts: Utc::now(),
            incident_id: incident.incident_id.clone(),
            host: "h".to_string(),
            ai_provider: "openai".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.91,
            auto_executed: true,
            dry_run: false,
            reason: "test".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
            decision_layer: None,
        };
        fs::write(
            dir.path().join(format!("decisions-{date}.jsonl")),
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        fs::write(dir.path().join(format!("summary-{date}.md")), "# summary\n").unwrap();
        fs::write(dir.path().join("state.json"), "{}").unwrap();
        fs::write(dir.path().join("agent-state.json"), "{}").unwrap();

        let report = compute_for_date(dir.path(), Some(date));
        assert_eq!(report.analyzed_date, date);
        assert_eq!(report.detection_summary.total_events, 1);
        assert_eq!(report.detection_summary.total_incidents, 1);
        assert_eq!(report.agent_ai_summary.total_decisions, 1);
        assert_eq!(
            report
                .agent_ai_summary
                .decisions_by_action
                .get("block_ip")
                .copied(),
            Some(1)
        );
        assert!(report.operational_health.expected_files_present);
    }

    #[test]
    fn compute_for_date_none_with_no_data_defaults_to_today_and_zeroes() {
        let dir = TempDir::new().unwrap();
        let today = Local::now().date_naive().format("%Y-%m-%d").to_string();

        let report = compute_for_date(dir.path(), None);
        assert_eq!(report.analyzed_date, today);
        assert_eq!(report.detection_summary.total_events, 0);
        assert_eq!(report.detection_summary.total_incidents, 0);
        assert_eq!(report.agent_ai_summary.total_decisions, 0);
        assert!(report
            .operational_health
            .files
            .iter()
            .filter(|file| file.file == "events"
                || file.file == "incidents"
                || file.file == "decisions")
            .all(|file| !file.exists));
        assert!(report.data_quality.empty_files.is_empty());
    }

    #[test]
    fn list_available_dates_returns_descending_unique_dates() {
        let dir = TempDir::new().unwrap();

        fs::write(dir.path().join("events-2026-03-10.jsonl"), "{}\n").unwrap();
        fs::write(dir.path().join("incidents-2026-03-12.jsonl"), "{}\n").unwrap();
        fs::write(dir.path().join("decisions-2026-03-12.jsonl"), "{}\n").unwrap();
        fs::write(dir.path().join("summary-2026-03-11.md"), "# summary\n").unwrap();
        fs::write(dir.path().join("events-2026-03-xx.jsonl"), "{}\n").unwrap();
        fs::write(dir.path().join("random-file.txt"), "x").unwrap();

        let dates = list_available_dates(dir.path());
        assert_eq!(
            dates,
            vec![
                "2026-03-12".to_string(),
                "2026-03-11".to_string(),
                "2026-03-10".to_string()
            ]
        );
    }

    #[test]
    fn list_available_dates_edge_returns_empty_when_no_matching_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("state.json"), "{}").unwrap();

        let dates = list_available_dates(dir.path());
        assert!(dates.is_empty());
    }

    #[test]
    fn safe_dated_file_sanitizes_date_component() {
        let dir = TempDir::new().unwrap();
        let path = safe_dated_file(dir.path(), "events", "../2026-03-16::malicious", "jsonl");

        assert_eq!(
            path.file_name().and_then(|v| v.to_str()),
            Some("events-invalid-date.jsonl")
        );
    }

    #[test]
    fn safe_dated_file_reformats_valid_date_component() {
        let dir = TempDir::new().unwrap();
        let path = safe_dated_file(dir.path(), "events", "2026-03-16", "jsonl");

        assert_eq!(
            path.file_name().and_then(|v| v.to_str()),
            Some("events-2026-03-16.jsonl")
        );
    }

    #[test]
    fn helper_formatters_handle_signs_and_empty_values() {
        assert_eq!(yes_no(true), "yes");
        assert_eq!(yes_no(false), "no");
        assert_eq!(signed_i64(7), "+7");
        assert_eq!(signed_i64(-7), "-7");
        assert_eq!(signed_f64(1.236, 2), "+1.24");
        assert_eq!(signed_f64(-1.236, 2), "-1.24");
        assert_eq!(format_pct(Some(12.34)), "+12.3%");
        assert_eq!(format_pct(None), "n/a");
        assert_eq!(list_or_none(&[]), "none");
        assert_eq!(list_or_none(&["alpha".to_string()]), "alpha");

        let mut map = BTreeMap::new();
        map.insert("x".to_string(), 2);
        assert_eq!(map_or_none(&map), "x=2");
    }

    #[test]
    fn build_suggestions_returns_default_when_report_is_healthy() {
        let report = TrialReport {
            generated_at: Utc::now(),
            analyzed_date: "2026-03-16".to_string(),
            data_dir: "/tmp".to_string(),
            operational_health: OperationalHealth {
                expected_files_present: true,
                state_json_readable: true,
                agent_state_json_readable: true,
                files: vec![],
            },
            operational_telemetry: OperationalTelemetry {
                available: true,
                last_tick: Some("tick".to_string()),
                events_by_collector: BTreeMap::new(),
                incidents_by_detector: BTreeMap::new(),
                gate_pass_count: 1,
                ai_sent_count: 1,
                ai_decision_count: 1,
                avg_decision_latency_ms: 200.0,
                errors_by_component: BTreeMap::new(),
                decisions_by_action: BTreeMap::new(),
                dry_run_execution_count: 1,
                real_execution_count: 0,
            },
            detection_summary: DetectionSummary {
                total_events: 10,
                total_incidents: 2,
                incidents_by_type: BTreeMap::new(),
                top_ips: vec![],
                top_entities: vec![],
            },
            agent_ai_summary: AgentAiSummary {
                total_decisions: 2,
                decisions_by_action: BTreeMap::new(),
                average_confidence: 0.9,
                ignore_count: 0,
                block_ip_count: 1,
                dry_run_count: 1,
                skills_used: BTreeMap::new(),
            },
            recent_window: RecentWindow {
                window_secs: 6 * 3600,
                events: 0,
                incidents: 0,
                high_critical_incidents: 0,
                decisions: 0,
                decisions_by_action: BTreeMap::new(),
                latest_event_ts: "none".to_string(),
                latest_incident_ts: "none".to_string(),
                latest_decision_ts: "none".to_string(),
                latest_telemetry_ts: "none".to_string(),
            },
            trend_summary: TrendSummary {
                previous_date: Some("2026-03-15".to_string()),
                events: count_delta(10, 8),
                incidents: count_delta(2, 2),
                decisions: count_delta(2, 2),
                incident_rate_per_1k_events: float_delta(200.0, 250.0),
                decision_rate_per_incident: float_delta(1.0, 1.0),
                average_confidence: float_delta(0.9, 0.9),
            },
            anomaly_hints: vec![],
            data_quality: DataQuality {
                empty_files: vec![],
                malformed_jsonl: BTreeMap::new(),
                incidents_without_entities: 0,
                decisions_without_action: 0,
                files_not_growing: vec![],
            },
            suggested_improvements: vec![],
        };

        assert_eq!(
            build_suggestions(&report),
            vec!["Everything looks healthy — no action needed.".to_string()]
        );
    }

    #[test]
    fn compute_for_date_from_graph_happy_path_counts_graph_data() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-16";

        fs::write(dir.path().join(format!("events-{date}.jsonl")), "{}\n").unwrap();
        fs::write(dir.path().join(format!("incidents-{date}.jsonl")), "{}\n").unwrap();
        fs::write(dir.path().join(format!("decisions-{date}.jsonl")), "{}\n").unwrap();
        fs::write(dir.path().join(format!("summary-{date}.md")), "# summary\n").unwrap();
        fs::write(dir.path().join("state.json"), "{}").unwrap();
        fs::write(dir.path().join("agent-state.json"), "{}").unwrap();

        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let incident_id = graph.add_node(Node::Incident {
            incident_id: "inc-1".to_string(),
            detector: "ssh_bruteforce".to_string(),
            severity: "high".to_string(),
            title: "title".to_string(),
            summary: "summary".to_string(),
            ts: Utc::now(),
            mitre_ids: vec![],
            decision: Some("block_ip".to_string()),
            confidence: Some(0.9),
            decision_reason: Some("reason".to_string()),
            decision_target: Some("1.2.3.4".to_string()),
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        let ip_id = graph.add_node(Node::Ip {
            addr: "1.2.3.4".to_string(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            attempted_usernames: vec![],
        });
        let user_id = graph.add_node(Node::User {
            name: "root".to_string(),
            uid: Some(0),
        });
        graph.add_edge(Edge::new(
            incident_id,
            ip_id,
            Relation::TriggeredBy,
            Utc::now(),
        ));
        graph.add_edge(Edge::new(
            incident_id,
            user_id,
            Relation::TriggeredBy,
            Utc::now(),
        ));

        let report = compute_for_date_from_graph(dir.path(), Some(date), &graph);
        assert_eq!(report.analyzed_date, date);
        // PR28: total_events now reads from SQLite events table (the
        // canonical source per spec 016). This fixture builds a KG
        // with 2 edges but writes ZERO rows to the events table, so
        // the SQLite override correctly yields 0. The dedicated test
        // `compute_for_date_from_graph_reads_events_count_from_sqlite`
        // exercises the populated-store happy path.
        assert_eq!(report.detection_summary.total_events, 0);
        assert_eq!(report.detection_summary.total_incidents, 1);
        assert_eq!(
            report
                .detection_summary
                .incidents_by_type
                .get("ssh_bruteforce")
                .copied(),
            Some(1)
        );
        assert_eq!(report.agent_ai_summary.total_decisions, 1);
        assert_eq!(
            report
                .agent_ai_summary
                .decisions_by_action
                .get("block_ip")
                .copied(),
            Some(1)
        );
        assert_eq!(report.data_quality.incidents_without_entities, 0);
        assert!(report.operational_health.expected_files_present);
    }

    #[test]
    fn compute_for_date_from_graph_reads_events_count_from_sqlite() {
        // 2026-05-14 — Report Trend showed `Events 146,887` (KG edge
        // count, ~30× inflated) while Home strip showed ~213,000 for
        // the same day (SQLite). PR28 makes compute_for_date_from_graph
        // OVERWRITE the KG-edges proxy with the canonical SQLite
        // `events` table count for the date.
        //
        // This runtime test plants:
        //   * 7 fake events in SQLite for the target date
        //   * 100 graph edges (the legacy proxy would yield 100)
        //   * 1 graph edge for a different date (must be excluded)
        // and asserts the report's total_events is **7**, proving
        // the SQLite path wins over the inflated proxy.
        use innerwarden_core::event::{Event, Severity};

        let dir = TempDir::new().unwrap();
        let date = "2026-05-13";
        let day_ts = format!("{date}T08:00:00+00:00");

        // SQLite: 7 events on the target date, 1 on a different date.
        let store = innerwarden_store::Store::open(dir.path()).expect("open store");
        for i in 0..7 {
            let ev = Event {
                ts: chrono::DateTime::parse_from_rfc3339(&day_ts)
                    .unwrap()
                    .with_timezone(&chrono::Utc)
                    + chrono::Duration::seconds(i),
                host: "h".into(),
                source: "auditd".into(),
                kind: "exec".into(),
                severity: Severity::Info,
                summary: "fixture".into(),
                details: serde_json::json!({}),
                tags: vec![],
                entities: vec![],
            };
            store.insert_event(&ev).unwrap();
        }
        // Different date — must be filtered.
        let other = Event {
            ts: chrono::DateTime::parse_from_rfc3339("2026-05-10T08:00:00+00:00")
                .unwrap()
                .with_timezone(&chrono::Utc),
            host: "h".into(),
            source: "auditd".into(),
            kind: "exec".into(),
            severity: Severity::Info,
            summary: "old day".into(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        store.insert_event(&other).unwrap();

        // KG: add 100 non-snapshot edges to verify the proxy would
        // have produced an inflated count. The override must win.
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let a = graph.add_node(Node::Ip {
            addr: "1.2.3.4".to_string(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            attempted_usernames: vec![],
        });
        let b = graph.add_node(Node::User {
            name: "root".to_string(),
            uid: Some(0),
        });
        for _ in 0..100 {
            graph.add_edge(Edge::new(a, b, Relation::TriggeredBy, Utc::now()));
        }

        let report = compute_for_date_from_graph(dir.path(), Some(date), &graph);
        assert_eq!(
            report.detection_summary.total_events, 7,
            "PR28 — Report's total_events must come from SQLite \
             events_count_for_date (7 on target date), NOT from KG \
             edge count (would be 100). The KG proxy inflated this \
             surface ~30× pre-PR28."
        );
    }

    #[test]
    fn populate_counters_from_graph_excludes_research_only_incidents() {
        // 2026-05-14 — Report Trend showed `Incidents 1211` while
        // Summary showed `Incidents Today 223` on the SAME page for
        // the SAME day. Cause: this function counted every Incident
        // node, including those flagged `research_only` (sensor
        // self-traffic auto-tagged at ingest per spec 015). The
        // Summary used compute_overview_counts_from_sqlite which
        // already filtered research_only.
        //
        // Anchor: two incidents (one normal, one research_only),
        // total_incidents must be 1 (the normal one).
        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let now = Utc::now();
        graph.add_node(Node::Incident {
            incident_id: "real-attack:1".to_string(),
            detector: "ssh_bruteforce".to_string(),
            severity: "high".to_string(),
            title: "real".to_string(),
            summary: "real".to_string(),
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
        graph.add_node(Node::Incident {
            incident_id: "self-traffic:1".to_string(),
            detector: "proto_anomaly".to_string(),
            severity: "low".to_string(),
            title: "self".to_string(),
            summary: "self".to_string(),
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
            research_only: true,
        });

        let counters = counters_from_graph(&graph);
        assert_eq!(
            counters.total_incidents, 1,
            "PR27 — research_only incidents must NOT inflate Trend's \
             total_incidents. Without this filter the Trend and the \
             Summary disagreed on the same page (1211 vs 223 in prod \
             on 2026-05-14)."
        );
        // The non-research_only detector must appear in the type
        // breakdown; the research_only one must NOT.
        assert_eq!(
            counters.incidents_by_type.get("ssh_bruteforce").copied(),
            Some(1)
        );
        assert!(
            !counters.incidents_by_type.contains_key("proto_anomaly"),
            "research_only incidents must not contribute to incidents_by_type"
        );
    }

    #[test]
    fn compute_for_date_from_graph_none_defaults_to_today() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("state.json"), "{}").unwrap();
        fs::write(dir.path().join("agent-state.json"), "{}").unwrap();

        let graph = crate::knowledge_graph::KnowledgeGraph::new();
        let report = compute_for_date_from_graph(dir.path(), None, &graph);
        let today = Local::now().date_naive().format("%Y-%m-%d").to_string();

        assert_eq!(report.analyzed_date, today);
    }

    #[test]
    fn compute_for_date_from_graph_edge_tracks_empty_historical_files() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-01";

        fs::write(dir.path().join(format!("events-{date}.jsonl")), "").unwrap();
        fs::write(dir.path().join(format!("incidents-{date}.jsonl")), "").unwrap();
        fs::write(dir.path().join(format!("decisions-{date}.jsonl")), "").unwrap();
        fs::write(dir.path().join(format!("summary-{date}.md")), "# summary\n").unwrap();
        fs::write(dir.path().join("state.json"), "{}").unwrap();
        fs::write(dir.path().join("agent-state.json"), "{}").unwrap();

        let graph = crate::knowledge_graph::KnowledgeGraph::new();
        let report = compute_for_date_from_graph(dir.path(), Some(date), &graph);

        assert_eq!(report.detection_summary.total_events, 0);
        assert_eq!(report.detection_summary.total_incidents, 0);
        assert_eq!(report.agent_ai_summary.total_decisions, 0);
        assert_eq!(report.data_quality.empty_files.len(), 3);
        assert!(report
            .data_quality
            .empty_files
            .contains(&"events".to_string()));
        assert!(report
            .data_quality
            .empty_files
            .contains(&"incidents".to_string()));
        assert!(report
            .data_quality
            .empty_files
            .contains(&"decisions".to_string()));
        assert_eq!(report.data_quality.files_not_growing.len(), 3);
        assert!(report
            .data_quality
            .files_not_growing
            .contains(&"events".to_string()));
        assert!(report
            .data_quality
            .files_not_growing
            .contains(&"incidents".to_string()));
        assert!(report
            .data_quality
            .files_not_growing
            .contains(&"decisions".to_string()));
    }

    #[test]
    fn generate_prefers_graph_snapshot_when_available() {
        let dir = TempDir::new().unwrap();
        let today = Local::now().date_naive().format("%Y-%m-%d").to_string();

        fs::write(dir.path().join(format!("events-{today}.jsonl")), "").unwrap();
        fs::write(dir.path().join(format!("incidents-{today}.jsonl")), "").unwrap();
        fs::write(dir.path().join(format!("decisions-{today}.jsonl")), "").unwrap();
        fs::write(
            dir.path().join(format!("summary-{today}.md")),
            "# summary\n",
        )
        .unwrap();
        fs::write(dir.path().join("state.json"), "{}").unwrap();
        fs::write(dir.path().join("agent-state.json"), "{}").unwrap();

        let mut graph = crate::knowledge_graph::KnowledgeGraph::new();
        let incident_id = graph.add_node(Node::Incident {
            incident_id: "inc-generate".to_string(),
            detector: "ssh_bruteforce".to_string(),
            severity: "high".to_string(),
            title: "title".to_string(),
            summary: "summary".to_string(),
            ts: Utc::now(),
            mitre_ids: vec![],
            decision: Some("ignore".to_string()),
            confidence: Some(0.8),
            decision_reason: Some("reason".to_string()),
            decision_target: Some("1.2.3.4".to_string()),
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        let ip_id = graph.add_node(Node::Ip {
            addr: "1.2.3.4".to_string(),
            is_internal: false,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            attempted_usernames: vec![],
        });
        graph.add_edge(Edge::new(
            incident_id,
            ip_id,
            Relation::TriggeredBy,
            Utc::now(),
        ));
        graph.save_dated_snapshot(dir.path()).unwrap();

        let out = generate(dir.path(), dir.path()).unwrap();
        assert_eq!(out.report.detection_summary.total_incidents, 1);
        assert_eq!(out.report.agent_ai_summary.total_decisions, 1);
        assert_eq!(
            out.report
                .agent_ai_summary
                .decisions_by_action
                .get("ignore")
                .copied(),
            Some(1)
        );
    }

    #[test]
    fn reads_operational_telemetry_snapshot() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        fs::write(
            dir.path().join(format!("events-{date}.jsonl")),
            format!(
                "{}\n",
                serde_json::to_string(&Event {
                    ts: Utc::now(),
                    host: "h".to_string(),
                    source: "auth.log".to_string(),
                    kind: "ssh.login_failed".to_string(),
                    severity: Severity::Info,
                    summary: "event".to_string(),
                    details: serde_json::json!({}),
                    tags: vec![],
                    entities: vec![EntityRef::ip("1.2.3.4")],
                })
                .unwrap()
            ),
        )
        .unwrap();
        fs::write(
            dir.path().join(format!("incidents-{date}.jsonl")),
            format!(
                "{}\n",
                serde_json::to_string(&Incident {
                    ts: Utc::now(),
                    host: "h".to_string(),
                    incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
                    severity: Severity::High,
                    title: "bruteforce".to_string(),
                    summary: "summary".to_string(),
                    evidence: serde_json::json!({}),
                    recommended_checks: vec![],
                    tags: vec![],
                    entities: vec![EntityRef::ip("1.2.3.4")],
                })
                .unwrap()
            ),
        )
        .unwrap();
        fs::write(
            dir.path().join(format!("decisions-{date}.jsonl")),
            format!(
                "{}\n",
                serde_json::to_string(&DecisionEntry {
                    ts: Utc::now(),
                    incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
                    host: "h".to_string(),
                    ai_provider: "openai".to_string(),
                    action_type: "ignore".to_string(),
                    target_ip: None,
                    target_user: None,
                    skill_id: None,
                    confidence: 0.9,
                    auto_executed: false,
                    dry_run: true,
                    reason: "test".to_string(),
                    estimated_threat: "low".to_string(),
                    execution_result: "skipped".to_string(),
                    prev_hash: None,
                    decision_layer: None,
                })
                .unwrap()
            ),
        )
        .unwrap();
        fs::write(dir.path().join(format!("summary-{date}.md")), "# summary\n").unwrap();
        fs::write(dir.path().join("state.json"), "{}").unwrap();
        fs::write(dir.path().join("agent-state.json"), "{}").unwrap();

        // Wave 6b: TelemetrySnapshot map keys are now `Arc<str>`.
        let mut events_by_collector: BTreeMap<std::sync::Arc<str>, u64> = BTreeMap::new();
        events_by_collector.insert(std::sync::Arc::<str>::from("auth.log"), 12);
        let mut incidents_by_detector: BTreeMap<std::sync::Arc<str>, u64> = BTreeMap::new();
        incidents_by_detector.insert(std::sync::Arc::<str>::from("ssh_bruteforce"), 4);
        let mut errors_by_component = BTreeMap::new();
        errors_by_component.insert("webhook".to_string(), 1);
        let mut decisions_by_action = BTreeMap::new();
        decisions_by_action.insert("block_ip".to_string(), 3);

        let snapshot = TelemetrySnapshot {
            ts: Utc::now(),
            tick: "incident_tick".to_string(),
            events_by_collector,
            incidents_by_detector,
            gate_pass_count: 4,
            incidents_by_tenant: Default::default(),
            ai_sent_count: 4,
            ai_decision_count: 4,
            avg_decision_latency_ms: 210.0,
            errors_by_component,
            decisions_by_action,
            dry_run_execution_count: 3,
            real_execution_count: 0,
            gate_suppressed_total: 0,
            telegram_sent_count: 0,
        };
        fs::write(
            dir.path().join(format!("telemetry-{date}.jsonl")),
            format!("{}\n", serde_json::to_string(&snapshot).unwrap()),
        )
        .unwrap();

        let out = generate(dir.path(), dir.path()).unwrap();
        assert!(out.report.operational_telemetry.available);
        assert_eq!(
            out.report
                .operational_telemetry
                .events_by_collector
                .get("auth.log")
                .copied(),
            Some(12)
        );
        assert_eq!(out.report.operational_telemetry.gate_pass_count, 4);
        assert_eq!(
            out.report
                .operational_telemetry
                .errors_by_component
                .get("webhook")
                .copied(),
            Some(1)
        );
    }

    // ── compute_recent_window cross-midnight regression ──────────────
    //
    // Anchor for `RECURRING_BUGS.md` "report.rs 6h-window snapshot fast
    // path subcounts near midnight". The previous implementation
    // string-compared bucket keys against `cutoff.format("%H:%M")` which
    // returned zero events whenever the cutoff fell into yesterday.
    // The fix:
    //   1. bucket key carries a date dimension (`YYYY-MM-DDTHH:MM`),
    //   2. comparison is `chrono::DateTime`-typed via `parse_bucket_key`,
    //   3. yesterday's snapshot is loaded whenever cutoff is yesterday.

    fn write_kg_with_telemetry(
        dir: &Path,
        date: &str,
        telemetry_events: &[(chrono::DateTime<chrono::Utc>, &str)],
    ) {
        use crate::knowledge_graph::KnowledgeGraph;
        let mut g = KnowledgeGraph::new();
        // Need at least one node so `metrics().node_count > 0` and the fast
        // path engages.
        g.ensure_ip("203.0.113.1", chrono::Utc::now());
        for (ts, source) in telemetry_events {
            g.record_event_telemetry(source, "test_kind", *ts);
        }
        let path = dir.join(format!("graph-snapshot-{date}.json"));
        g.save_snapshot(&path).expect("save snapshot");
    }

    #[test]
    fn recent_window_crosses_midnight_correctly() {
        use chrono::TimeZone;
        let dir = tempfile::tempdir().expect("tempdir");

        // "now" is 02:00 UTC on 2026-04-23. The 6h window covers
        // 20:00 yesterday (2026-04-22) → 02:00 today.
        let now = chrono::Utc.with_ymd_and_hms(2026, 4, 23, 2, 0, 0).unwrap();
        let yesterday_2030 = chrono::Utc
            .with_ymd_and_hms(2026, 4, 22, 20, 30, 0)
            .unwrap();
        let yesterday_1900 = chrono::Utc.with_ymd_and_hms(2026, 4, 22, 19, 0, 0).unwrap();
        let today_0100 = chrono::Utc.with_ymd_and_hms(2026, 4, 23, 1, 0, 0).unwrap();

        // Today's snapshot: 1 event at 01:00 (in window).
        write_kg_with_telemetry(dir.path(), "2026-04-23", &[(today_0100, "test_source")]);
        // Yesterday's snapshot: 1 event at 20:30 (in window) + 1 event at
        // 19:00 (BEFORE the window cutoff of 20:00 — must NOT be counted).
        write_kg_with_telemetry(
            dir.path(),
            "2026-04-22",
            &[
                (yesterday_2030, "test_source"),
                (yesterday_1900, "test_source"),
            ],
        );

        // Important: clear the in-process cache because other tests in this
        // file may have populated it for the same `analyzed_date`.
        if let Ok(mut cache) = recent_window_cache_handle().lock() {
            cache.clear();
        }

        let win = compute_recent_window_at(dir.path(), "2026-04-23", now);
        assert_eq!(
            win.events, 2,
            "must count 20:30 (yesterday) + 01:00 (today), not 19:00 (out of window)"
        );
    }

    #[test]
    fn recent_window_only_today_when_cutoff_within_today() {
        use chrono::TimeZone;
        let dir = tempfile::tempdir().expect("tempdir");

        // "now" is 18:00 UTC. Cutoff = 12:00 same day. No need to load
        // yesterday's snapshot at all; if it exists it must NOT be summed.
        let now = chrono::Utc.with_ymd_and_hms(2026, 4, 23, 18, 0, 0).unwrap();
        let today_1500 = chrono::Utc.with_ymd_and_hms(2026, 4, 23, 15, 0, 0).unwrap();
        let today_0900 = chrono::Utc.with_ymd_and_hms(2026, 4, 23, 9, 0, 0).unwrap();
        let yesterday_2200 = chrono::Utc.with_ymd_and_hms(2026, 4, 22, 22, 0, 0).unwrap();

        write_kg_with_telemetry(
            dir.path(),
            "2026-04-23",
            &[(today_1500, "src"), (today_0900, "src")],
        );
        // Yesterday has events but the cutoff is within today; yesterday's
        // events must be ignored. (We still LOAD yesterday's snapshot in
        // case the cutoff date equals yesterday, but in this scenario
        // cutoff.date_naive() == today, so the yesterday load is skipped.)
        write_kg_with_telemetry(dir.path(), "2026-04-22", &[(yesterday_2200, "src")]);

        if let Ok(mut cache) = recent_window_cache_handle().lock() {
            cache.clear();
        }

        let win = compute_recent_window_at(dir.path(), "2026-04-23", now);
        // Only the 15:00 event is within the 12:00–18:00 window. 09:00 is
        // before, yesterday is irrelevant.
        assert_eq!(win.events, 1);
    }

    #[test]
    fn recent_window_legacy_hhmm_keys_interpreted_as_snapshot_date() {
        // A snapshot written by an agent BEFORE the bucket-key fix has
        // bare `HH:MM` keys. The reader interprets them as the snapshot's
        // date (back-compat). This test pins that contract so we cannot
        // accidentally drop it during a future refactor.
        use crate::knowledge_graph::KnowledgeGraph;
        use chrono::TimeZone;
        let dir = tempfile::tempdir().expect("tempdir");

        let now = chrono::Utc.with_ymd_and_hms(2026, 4, 23, 2, 0, 0).unwrap();

        // Build a graph and inject a legacy bare-HH:MM bucket key directly,
        // simulating a snapshot written before the fix.
        let mut g = KnowledgeGraph::new();
        g.ensure_ip("203.0.113.1", chrono::Utc::now());
        // Wave 6c: event_timeline keys are now `Arc<str>`.
        g.event_timeline
            .entry(std::sync::Arc::<str>::from("20:30"))
            .or_default()
            .insert(std::sync::Arc::<str>::from("legacy_source"), 1);
        let path = dir.path().join("graph-snapshot-2026-04-22.json");
        g.save_snapshot(&path).expect("save snapshot");

        // Today's snapshot is empty but present so the today-load succeeds.
        write_kg_with_telemetry(dir.path(), "2026-04-23", &[]);

        if let Ok(mut cache) = recent_window_cache_handle().lock() {
            cache.clear();
        }

        let win = compute_recent_window_at(dir.path(), "2026-04-23", now);
        assert_eq!(
            win.events, 1,
            "legacy HH:MM key must be interpreted as the snapshot's date (yesterday) and counted"
        );
    }

    // Spec 037 I-13 follow-up #2 (third slice): open_kpi_file_or_warn
    //
    // Wraps the three silent `if let Ok(f) = File::open(&path)` sites in
    // the 30-day KPI scan loop (events / incidents / decisions).
    // `NotFound` is the steady state (most days have no JSONL on disk),
    // so the helper warns only on genuine I/O failures.

    #[test]
    fn open_kpi_file_or_warn_returns_some_silently_on_existing_file() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("events-2026-04-28.jsonl");
        std::fs::write(&path, b"{}\n").expect("seed kpi file");

        let result = open_kpi_file_or_warn(&path, "events");
        assert!(result.is_some(), "existing file must yield Some(File)");

        let captured = crate::test_util::drain_capture();
        assert!(
            !captured.contains("report KPI file open failed"),
            "happy path must not emit failure warn, got: {captured}"
        );
    }

    #[test]
    fn open_kpi_file_or_warn_returns_none_silently_on_not_found() {
        // The 30-day KPI scan reaches dates with no JSONL on disk
        // every iteration; warning on each would flood logs. Only
        // genuine I/O failures should surface.
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("incidents-2026-04-28.jsonl");

        let result = open_kpi_file_or_warn(&path, "incidents");
        assert!(result.is_none(), "missing file must yield None");

        let captured = crate::test_util::drain_capture();
        assert!(
            captured.is_empty() || !captured.contains("report KPI file open failed"),
            "NotFound is steady state and must NOT emit a warn, got: {captured}"
        );
    }

    #[test]
    fn open_kpi_file_or_warn_returns_none_and_warns_on_io_failure() {
        // Force `File::open` to fail with something other than NotFound
        // by parking the path beneath a regular file: the open call
        // returns NotADirectory (Linux) or similar -- not NotFound.
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let blocking_file = dir.path().join("blocker");
        std::fs::write(&blocking_file, b"i am a regular file").expect("seed blocker");
        let path = blocking_file.join("decisions-2026-04-28.jsonl");

        let result = open_kpi_file_or_warn(&path, "decisions");
        assert!(result.is_none(), "io-failure path must yield None");

        let captured = crate::test_util::drain_capture();
        assert!(
            captured.contains("report KPI file open failed"),
            "io-failure warn missing, got: {captured}"
        );
        assert!(
            captured.contains("kind=\"decisions\"") || captured.contains("kind=decisions"),
            "kind label missing, got: {captured}"
        );
        assert!(
            captured.contains("error="),
            "error field missing, got: {captured}"
        );
    }
}
