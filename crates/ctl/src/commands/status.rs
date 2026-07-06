use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use innerwarden_store::Store;

use crate::capability::CapabilityRegistry;
use crate::module_manifest::{is_module_enabled, scan_modules_dir};
use crate::{
    count_jsonl_lines, epoch_secs_to_date, make_opts, read_last_incident_summary, resolve_data_dir,
    systemd, today_date_string, unknown_cap_error, yesterday_date_string, Cli,
};

fn resolve_report_date(date_arg: &str, today: &str, yesterday: &str) -> String {
    match date_arg {
        "today" => today.to_string(),
        "yesterday" => yesterday.to_string(),
        other => other.to_string(),
    }
}

fn summary_dates_from_filenames(names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter_map(|name| {
            name.strip_prefix("summary-")
                .and_then(|s| s.strip_suffix(".md"))
                .map(|d| d.to_string())
        })
        .collect()
}

/// Format an incident RFC3339 timestamp as the "time ago" string used by the
/// status header. Mirrors `read_last_incident_summary` exactly so the store
/// path and the JSONL path produce identical "Last threat" suffixes.
fn format_incident_time_ago(ts: &str) -> String {
    if let Ok(incident_time) = chrono::DateTime::parse_from_rfc3339(ts) {
        let diff = chrono::Utc::now() - incident_time.with_timezone(&chrono::Utc);
        let mins = diff.num_minutes();
        if mins < 1 {
            "just now".to_string()
        } else if mins < 60 {
            format!("{mins}m ago")
        } else if mins < 1440 {
            format!("{}h ago", mins / 60)
        } else {
            format!("{}d ago", mins / 1440)
        }
    } else if ts.len() >= 16 {
        format!("{} UTC", &ts[11..16])
    } else {
        ts.to_string()
    }
}

/// Resolve today's event count, incident count, and last-incident summary.
///
/// Prefers the unified SQLite store (the canonical source the sensor/agent
/// write to — the JSONL counters lie with "0" on migrated boxes). Falls back
/// to the legacy per-day JSONL files when the store cannot be opened OR has no
/// data for today, for backward compat with non-migrated boxes.
fn today_counts(dir: &Path, today: &str) -> (usize, usize, Option<(String, String)>) {
    // Window start for "today" incidents: midnight UTC, RFC3339, matched
    // lexicographically against the store's `ts` column.
    let start_ts = format!("{today}T00:00:00+00:00");

    if let Ok(store) = Store::open(dir) {
        let events_today = store.events_count_for_date(today).unwrap_or_else(|e| {
            eprintln!("  [warn] status: events_count_for_date failed ({e:#})");
            0
        });
        let incidents_today = match store.incidents_since_ts(&start_ts, 100_000) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  [warn] status: incidents_since_ts failed ({e:#})");
                Vec::new()
            }
        };

        // Only trust the store when it actually has today's data; an empty
        // store on a mid-migration box must fall through to JSONL below.
        if events_today > 0 || !incidents_today.is_empty() {
            let incidents_count = incidents_today.len();
            // incidents_since_ts is ascending by ts -> the last element is the
            // most recent incident today.
            let last_incident = incidents_today.last().map(|inc| {
                (
                    inc.title.clone(),
                    format_incident_time_ago(&inc.ts.to_rfc3339()),
                )
            });
            return (events_today as usize, incidents_count, last_incident);
        }
    }

    // Legacy JSONL fallback (store absent / unreadable / empty for today).
    let events_count = count_jsonl_lines(&dir.join(format!("events-{today}.jsonl")));
    let incidents_count = count_jsonl_lines(&dir.join(format!("incidents-{today}.jsonl")));
    let last_incident = read_last_incident_summary(&dir.join(format!("incidents-{today}.jsonl")));
    (events_count, incidents_count, last_incident)
}

pub(crate) fn cmd_status(cli: &Cli, registry: &CapabilityRegistry, id: &str) -> Result<()> {
    let cap = registry.get(id).ok_or_else(|| unknown_cap_error(id))?;
    let opts = make_opts(cli, HashMap::new(), false);
    let status = if cap.is_enabled(&opts) {
        "enabled"
    } else {
        "disabled"
    };
    println!("Capability:  {}", cap.name());
    println!("ID:          {}", cap.id());
    println!("Status:      {status}");
    println!("Description: {}", cap.description());
    Ok(())
}

pub(crate) fn cmd_status_global(
    cli: &Cli,
    registry: &CapabilityRegistry,
    modules_dir: &Path,
) -> Result<()> {
    println!("InnerWarden Status");
    println!("{}", "═".repeat(56));

    println!("\nServices");
    for unit in &["innerwarden-sensor", "innerwarden-agent"] {
        // service_status is platform-aware: systemd on Linux, process presence
        // on macOS. Distinguish Unknown ("could not determine") from Inactive so
        // a running launchd daemon is never falsely reported as "stopped"
        // (2026-07-01 macOS finding F7).
        let (indicator, label) = match systemd::service_status(unit) {
            systemd::ServiceStatus::Active => ("●", "running"),
            systemd::ServiceStatus::Inactive => ("○", "stopped"),
            systemd::ServiceStatus::Unknown => ("◐", "unknown"),
        };
        println!("  {indicator} {unit:<28} {label}");
    }

    let data_dir: Option<PathBuf> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|doc| {
            doc.get("output")
                .and_then(|o| o.get("data_dir"))
                .and_then(|d| d.as_str())
                .map(PathBuf::from)
        })
        .or_else(|| Some(PathBuf::from("/var/lib/innerwarden")));

    if let Some(ref dir) = data_dir {
        let today = today_date_string();
        let (events_count, incidents_count, last_incident) = today_counts(dir, &today);

        println!("\nToday  ({})", today);
        println!("  Events logged:    {events_count}");
        println!("  Threats detected: {incidents_count}");
        if let Some((title, when)) = last_incident {
            println!("  Last threat:      {title}  [{when}]");
        } else if incidents_count == 0 {
            println!("  Last threat:      none - quiet day so far");
        }
    }

    let agent_doc: Option<toml_edit::DocumentMut> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse().ok());

    let ai_enabled = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|a| a.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ai_provider = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|a| a.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("openai")
        .to_string();
    let responder_enabled = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("responder"))
        .and_then(|r| r.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let dry_run = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("responder"))
        .and_then(|r| r.get("dry_run"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    println!("\nAI & Response");
    if ai_enabled {
        println!("  ● AI analysis     active  ({ai_provider})");
    } else {
        println!("  ○ AI analysis     disabled");
    }
    // Single source of truth for "is the agent actually acting?": the
    // posture headline + CTA are shared with the agent boot log and the
    // installer, so the operator reads the same sentence everywhere.
    let posture =
        innerwarden_core::policy::EnforcementPosture::from_responder(responder_enabled, dry_run);
    let indicator = if posture.is_enforcing() { "●" } else { "○" };
    println!("  {indicator} Responder       {}", posture.headline());
    if let Some(cta) = posture.cta() {
        println!("      {cta}");
    }

    println!("\nCapabilities");
    let opts = make_opts(cli, HashMap::new(), false);
    for cap in registry.all() {
        let enabled = cap.is_enabled(&opts);
        let indicator = if enabled { "●" } else { "○" };
        let label = if enabled { "enabled " } else { "disabled" };
        println!(
            "  {indicator} {:<20} {}  {}",
            cap.id(),
            label,
            cap.description()
        );
    }

    println!("\nModules  ({})", modules_dir.display());
    let modules = scan_modules_dir(modules_dir);
    if modules.is_empty() {
        println!("  (none installed)");
    } else {
        for m in &modules {
            let enabled = is_module_enabled(&cli.sensor_config, &cli.agent_config, m);
            let indicator = if enabled { "●" } else { "○" };
            let label = if enabled { "enabled " } else { "disabled" };
            println!("  {indicator} {:<20} {}  {}", m.id, label, m.name);
        }
    }

    println!();
    Ok(())
}

pub(crate) fn cmd_report(cli: &Cli, date_arg: &str, data_dir: &Path) -> Result<()> {
    let effective_dir = if data_dir == Path::new("/var/lib/innerwarden") {
        cli.agent_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.agent_config).ok())
            .flatten()
            .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
            .and_then(|doc| {
                doc.get("output")
                    .and_then(|o| o.get("data_dir"))
                    .and_then(|d| d.as_str())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| data_dir.to_path_buf())
    } else {
        data_dir.to_path_buf()
    };

    let date = resolve_report_date(date_arg, &today_date_string(), &yesterday_date_string());

    let summary_path = effective_dir.join(format!("summary-{date}.md"));

    if !summary_path.exists() {
        let entries: Vec<String> = std::fs::read_dir(&effective_dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        let mut available = summary_dates_from_filenames(&entries);

        if available.is_empty() {
            println!("No summary found for {date}.");
            println!();
            println!("Summary files are generated by innerwarden-agent every 30 minutes.");
            println!("Make sure the agent is running:  innerwarden status");
        } else {
            available.sort();
            available.reverse();
            println!("No summary found for {date}.");
            println!();
            println!("Available dates:");
            for d in available.iter().take(7) {
                println!("  innerwarden report --date {d}");
            }
        }
        return Ok(());
    }

    let content = std::fs::read_to_string(&summary_path)
        .with_context(|| format!("failed to read {}", summary_path.display()))?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("### ") {
            println!("\n  {}", rest);
        } else if let Some(rest) = line.strip_prefix("## ") {
            println!("\n{}", rest.to_uppercase());
            println!("{}", "─".repeat(48));
        } else if let Some(rest) = line.strip_prefix("# ") {
            println!("{}", rest);
            println!("{}", "═".repeat(56));
        } else if line.starts_with("---") {
        } else {
            println!("{line}");
        }
    }

    println!();
    println!("Full report: {}", summary_path.display());
    Ok(())
}

pub(crate) fn cmd_navigator(output: Option<&str>) -> Result<()> {
    let layer = generate_navigator_layer();
    let json = serde_json::to_string_pretty(&layer)?;
    if let Some(path) = output {
        std::fs::write(path, &json)?;
        eprintln!("  ✓ Navigator layer written to {path}");
        eprintln!("  Open https://mitre-attack.github.io/attack-navigator/ and load the file.");
    } else {
        println!("{json}");
    }
    Ok(())
}

fn generate_navigator_layer() -> serde_json::Value {
    // All detector -> technique mappings (mirrors agent/mitre.rs)
    let techniques: Vec<(&str, &str, &str)> = vec![
        ("T1110.001", "Credential Access", "ssh_bruteforce"),
        ("T1110.004", "Credential Access", "credential_stuffing"),
        ("T1110", "Credential Access", "distributed_ssh"),
        ("T1003", "Credential Access", "credential_harvest"),
        ("T1078", "Initial Access", "suspicious_login"),
        ("T1595", "Reconnaissance", "port_scan"),
        (
            "T1595.002",
            "Reconnaissance",
            "web_scan, user_agent_scanner",
        ),
        ("T1499", "Impact", "search_abuse"),
        ("T1496", "Impact", "crypto_miner"),
        ("T1498", "Impact", "outbound_anomaly"),
        ("T1486", "Impact", "ransomware"),
        ("T1059", "Execution", "execution_guard, process_tree"),
        ("T1059.004", "Execution", "reverse_shell"),
        ("T1610", "Execution", "docker_anomaly"),
        ("T1620", "Defense Evasion", "fileless"),
        ("T1098", "Defense Evasion", "integrity_alert"),
        ("T1070", "Defense Evasion", "log_tampering"),
        ("T1014", "Defense Evasion", "rootkit"),
        ("T1055", "Defense Evasion", "process_injection"),
        ("T1505.003", "Persistence", "web_shell"),
        ("T1098.004", "Persistence", "ssh_key_injection"),
        ("T1547.006", "Persistence", "kernel_module_load"),
        ("T1053.003", "Persistence", "crontab_persistence"),
        ("T1543.002", "Persistence", "systemd_persistence"),
        ("T1136", "Persistence", "user_creation"),
        ("T1611", "Privilege Escalation", "container_escape"),
        ("T1068", "Privilege Escalation", "privesc"),
        ("T1548", "Privilege Escalation", "sudo_abuse"),
        ("T1548.001", "Privilege Escalation", "sudo_abuse"),
        ("T1071", "Command and Control", "c2_callback"),
        ("T1571", "Command and Control", "c2_callback"),
        ("T1048.001", "Exfiltration", "dns_tunneling"),
        (
            "T1041",
            "Exfiltration",
            "data_exfiltration, data_exfil_ebpf",
        ),
        ("T1021", "Lateral Movement", "lateral_movement"),
        ("T1546.004", "Persistence", "sensitive_write"),
        ("T1037.004", "Persistence", "sensitive_write"),
        ("T1574.006", "Persistence", "sensitive_write"),
        ("T1556", "Credential Access", "sensitive_write"),
        ("T1053.002", "Persistence", "at_job_persist"),
        ("T1222.002", "Defense Evasion", "file_permission_mod"),
        ("T1564.001", "Defense Evasion", "hidden_artifact"),
        ("T1219", "Command and Control", "remote_access_tool"),
        ("T1489", "Impact", "service_stop"),
        ("T1529", "Impact", "system_shutdown"),
        ("T1040", "Credential Access", "network_sniffing"),
        ("T1036.005", "Defense Evasion", "masquerading"),
        ("T1560", "Collection", "data_archive"),
        ("T1090", "Command and Control", "proxy_tunnel"),
        ("T1105", "Command and Control", "execution_guard"),
        ("T1140", "Defense Evasion", "execution_guard"),
        ("T1552.001", "Credential Access", "data_exfil_ebpf"),
        ("T1552.004", "Credential Access", "private_key_search"),
        ("T1562.001", "Defense Evasion", "sudo_abuse"),
        ("T1562.004", "Defense Evasion", "sudo_abuse"),
        ("T1485", "Impact", "sudo_abuse"),
    ];

    let tech_entries: Vec<serde_json::Value> = techniques
        .iter()
        .map(|(tid, _tactic, detectors)| {
            serde_json::json!({
                "techniqueID": tid,
                "score": 1,
                "color": "#00ff00",
                "comment": format!("Detectors: {detectors}"),
                "enabled": true,
                "showSubtechniques": true,
            })
        })
        .collect();

    serde_json::json!({
        "name": "InnerWarden Detection Coverage",
        "versions": {
            "attack": "16",
            "navigator": "5.1.0",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": format!(
            "InnerWarden: {} MITRE ATT&CK techniques covered by 49 detectors + 8 YARA + 8 Sigma rules",
            tech_entries.len()
        ),
        "gradient": {
            "colors": ["#ffe766", "#00ff00"],
            "minValue": 1,
            "maxValue": 3
        },
        "techniques": tech_entries,
    })
}

/// Render the Collectors + Detectors sections of `innerwarden get sensor`
/// from the unified SQLite store when the agent telemetry snapshot is absent.
///
/// Collectors come from `events_timeline_for_date` (per-minute buckets summed
/// per source). Detectors come from today's incidents, keyed by the same
/// `detector_kind` derivation the agent telemetry uses (the first
/// colon-delimited segment of `incident_id`). The AI/response section is NOT
/// reconstructable from the store (those counters live only in the agent
/// snapshot), so it is intentionally omitted rather than shown as zeros.
///
/// Returns `true` when the store yielded any events or incidents for `today`
/// (sections were printed), `false` otherwise (store absent / unreadable /
/// empty for today) so the caller can show the legacy "No telemetry" message.
fn render_sensor_status_from_store(dir: &Path, today: &str) -> bool {
    let store = match Store::open(dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [warn] sensor status: store open failed ({e:#})");
            return false;
        }
    };

    // Collectors: sum per-minute buckets per source.
    let mut events_by_source: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();
    if let Ok(timeline) = store.events_timeline_for_date(today) {
        for (_bucket, per_source) in timeline {
            for (source, count) in per_source {
                *events_by_source.entry(source).or_insert(0) += count;
            }
        }
    }

    // Detectors: today's incidents grouped by detector_kind (first segment of
    // incident_id), mirroring `agent::correlation::detector_kind`.
    let start_ts = format!("{today}T00:00:00+00:00");
    let mut incidents_by_detector: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();
    if let Ok(incidents) = store.incidents_since_ts(&start_ts, 100_000) {
        for inc in &incidents {
            let detector = inc
                .incident_id
                .split(':')
                .next()
                .unwrap_or("unknown")
                .to_string();
            *incidents_by_detector.entry(detector).or_insert(0) += 1;
        }
    }

    if events_by_source.is_empty() && incidents_by_detector.is_empty() {
        return false;
    }

    println!("Collectors (events today):");
    if events_by_source.is_empty() {
        println!("  (no events recorded yet today)");
    } else {
        let mut pairs: Vec<(&String, u64)> =
            events_by_source.iter().map(|(k, v)| (k, *v)).collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        for (source, count) in &pairs {
            println!("  ● {:<30} {:>6} events", source, count);
        }
    }

    println!();
    println!("Detectors (incidents today):");
    if incidents_by_detector.is_empty() {
        println!("  (no incidents today)");
    } else {
        let mut pairs: Vec<(&String, u64)> =
            incidents_by_detector.iter().map(|(k, v)| (k, *v)).collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        for (detector, count) in &pairs {
            println!("  ⚠  {:<30} {:>6} incidents", detector, count);
        }
    }

    true
}

pub(crate) fn cmd_sensor_status(cli: &Cli, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let today = epoch_secs_to_date(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );

    let telemetry_path = effective_dir.join(format!("telemetry-{today}.jsonl"));
    let snapshot: Option<serde_json::Value> = std::fs::read_to_string(&telemetry_path)
        .ok()
        .and_then(|content| {
            content
                .lines()
                .rfind(|l| !l.trim().is_empty())
                .and_then(|line| serde_json::from_str(line).ok())
        });

    println!("InnerWarden - sensor status  ({})\n", today);

    let Some(snap) = snapshot else {
        // The agent telemetry snapshot is absent, but the sensor may still be
        // writing events/incidents to the unified SQLite store. Render the
        // collector + detector breakdown from the store so the operator is not
        // told "no data" while the store holds tens of thousands of events.
        // (AI / response counts live only in the agent snapshot — they are
        // omitted here, not fabricated.)
        if render_sensor_status_from_store(&effective_dir, &today) {
            println!();
            return Ok(());
        }
        println!("  No telemetry data for today.");
        println!("  Is the agent running?  innerwarden status");
        return Ok(());
    };

    println!("Collectors (events today):");
    let by_collector = snap["events_by_collector"].as_object();
    match by_collector {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (source, count) in &pairs {
                println!("  ● {:<30} {:>6} events", source, count);
            }
        }
        _ => println!("  (no events recorded yet today)"),
    }

    println!();
    println!("Detectors (incidents today):");
    let by_detector = snap["incidents_by_detector"].as_object();
    match by_detector {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (detector, count) in &pairs {
                println!("  ⚠  {:<30} {:>6} incidents", detector, count);
            }
        }
        _ => println!("  (no incidents today)"),
    }

    let ai_sent = snap["ai_sent_count"].as_u64().unwrap_or(0);
    let ai_decided = snap["ai_decision_count"].as_u64().unwrap_or(0);
    let avg_ms = snap["avg_decision_latency_ms"].as_f64().unwrap_or(0.0);
    let real_exec = snap["real_execution_count"].as_u64().unwrap_or(0);
    let dry_exec = snap["dry_run_execution_count"].as_u64().unwrap_or(0);
    let gate_pass = snap["gate_pass_count"].as_u64().unwrap_or(0);

    println!();
    println!("AI & Response (today):");
    println!("  Passed algorithm gate:  {gate_pass}");
    println!("  Sent to AI:             {ai_sent}");
    println!("  AI decisions:           {ai_decided}  (avg {avg_ms:.0}ms)");
    if real_exec > 0 {
        println!("  Actions executed:       {real_exec}  (live)");
    }
    if dry_exec > 0 {
        println!("  Actions simulated:      {dry_exec}  (dry-run)");
    }

    let errors = snap["errors_by_component"].as_object();
    if let Some(map) = errors {
        if !map.is_empty() {
            println!();
            println!("Errors:");
            for (comp, count) in map {
                println!("  ✗ {comp}: {}", count.as_u64().unwrap_or(0));
            }
        }
    }

    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_cli(temp: &TempDir) -> Cli {
        Cli {
            sensor_config: temp.path().join("sensor.toml"),
            agent_config: temp.path().join("agent.toml"),
            data_dir: temp.path().join("data"),
            dry_run: true,
            command: None,
        }
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("test should create parent directory");
        }
        std::fs::write(path, content).expect("test should write fixture");
    }

    fn today() -> String {
        epoch_secs_to_date(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    }

    #[test]
    fn resolve_report_date_expands_relative_keywords() {
        // Ensures user-friendly date shortcuts map to concrete dates consistently.
        assert_eq!(
            resolve_report_date("today", "2026-04-16", "2026-04-15"),
            "2026-04-16"
        );
        assert_eq!(
            resolve_report_date("yesterday", "2026-04-16", "2026-04-15"),
            "2026-04-15"
        );
    }

    #[test]
    fn resolve_report_date_keeps_explicit_date_strings() {
        // Covers pass-through behavior for explicit date arguments.
        assert_eq!(
            resolve_report_date("2026-04-01", "2026-04-16", "2026-04-15"),
            "2026-04-01"
        );
    }

    #[test]
    fn summary_dates_from_filenames_extracts_only_summary_files() {
        // Verifies summary date discovery ignores unrelated files and keeps valid report dates.
        let names = vec![
            "summary-2026-04-16.md".to_string(),
            "summary-2026-04-15.md".to_string(),
            "events-2026-04-16.jsonl".to_string(),
            "summary-2026-04-14.txt".to_string(),
        ];
        let dates = summary_dates_from_filenames(&names);
        assert_eq!(dates, vec!["2026-04-16", "2026-04-15"]);
    }

    #[test]
    fn generate_navigator_layer_has_expected_metadata() {
        // Ensures exported ATT&CK layer preserves required metadata used by the Navigator UI.
        let layer = generate_navigator_layer();
        assert_eq!(
            layer["name"].as_str().expect("layer name"),
            "InnerWarden Detection Coverage"
        );
        assert_eq!(
            layer["domain"].as_str().expect("layer domain"),
            "enterprise-attack"
        );
        assert_eq!(
            layer["versions"]["layer"].as_str().expect("layer version"),
            "4.5"
        );
    }

    #[test]
    fn generate_navigator_layer_contains_known_techniques() {
        // Guards the detector-to-technique map so key ATT&CK IDs are not lost during refactors.
        let layer = generate_navigator_layer();
        let techniques = layer["techniques"]
            .as_array()
            .expect("techniques must be array");
        let ids: Vec<&str> = techniques
            .iter()
            .filter_map(|t| t["techniqueID"].as_str())
            .collect();
        assert!(ids.contains(&"T1110.001"));
        assert!(ids.contains(&"T1485"));
    }

    #[test]
    fn generate_navigator_layer_sets_visual_defaults_for_each_technique() {
        // Confirms each technique entry keeps score/color/display defaults expected by ATT&CK Navigator.
        let layer = generate_navigator_layer();
        let techniques = layer["techniques"]
            .as_array()
            .expect("techniques must be array");
        let first = techniques.first().expect("at least one technique");
        assert_eq!(first["score"].as_i64().expect("score"), 1);
        assert_eq!(first["color"].as_str().expect("color"), "#00ff00");
        assert_eq!(first["enabled"].as_bool().expect("enabled"), true);
        assert_eq!(
            first["showSubtechniques"]
                .as_bool()
                .expect("showSubtechniques"),
            true
        );
    }

    #[test]
    fn generate_navigator_layer_technique_count_matches_description() {
        // Ensures description count stays in sync with actual entries to avoid stale exported metadata.
        let layer = generate_navigator_layer();
        let techniques = layer["techniques"]
            .as_array()
            .expect("techniques must be array");
        let description = layer["description"].as_str().expect("description");
        assert!(description.contains(&techniques.len().to_string()));
        assert!(techniques.len() >= 40);
    }

    #[test]
    fn cmd_navigator_writes_layer_to_requested_file() {
        let temp = TempDir::new().expect("tempdir");
        let output = temp.path().join("navigator.json");

        cmd_navigator(output.to_str()).expect("navigator export should succeed");

        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output).expect("navigator json"))
                .expect("valid navigator json");
        assert_eq!(written["name"], "InnerWarden Detection Coverage");
        assert!(written["techniques"].as_array().expect("techniques").len() >= 40);
    }

    #[test]
    fn cmd_report_handles_missing_summaries_and_lists_available_dates() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("reports");
        std::fs::create_dir_all(&data_dir).expect("reports dir");

        cmd_report(&cli, "today", &data_dir).expect("missing report without files is ok");

        write_file(&data_dir.join("summary-2026-04-16.md"), "# Daily\nbody\n");
        write_file(&data_dir.join("summary-2026-04-15.md"), "# Daily\nbody\n");
        cmd_report(&cli, "2026-04-14", &data_dir).expect("missing report with alternatives is ok");
    }

    #[test]
    fn cmd_report_reads_summary_from_agent_configured_data_dir() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("agent-data");
        write_file(
            &cli.agent_config,
            &format!("[output]\ndata_dir = \"{}\"\n", data_dir.display()),
        );
        write_file(
            &data_dir.join("summary-2026-04-16.md"),
            "# InnerWarden\n---\n## Highlights\n### Finding\nAll clear\n",
        );

        cmd_report(&cli, "2026-04-16", Path::new("/var/lib/innerwarden"))
            .expect("configured report should render");
    }

    #[test]
    fn cmd_status_global_reads_config_data_and_empty_modules() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("status-data");
        let today = today();
        write_file(
            &cli.agent_config,
            &format!(
                "[output]\ndata_dir = \"{}\"\n[ai]\nenabled = true\nprovider = \"ollama\"\n[responder]\nenabled = true\ndry_run = false\n",
                data_dir.display()
            ),
        );
        write_file(
            &cli.sensor_config,
            "[collectors.exec_audit]\nenabled = true\n",
        );
        write_file(&data_dir.join(format!("events-{today}.jsonl")), "{}\n{}\n");
        write_file(
            &data_dir.join(format!("incidents-{today}.jsonl")),
            "{\"title\":\"Suspicious login\",\"ts\":\"2026-04-16T10:00:00Z\"}\n",
        );
        let modules_dir = temp.path().join("modules");
        std::fs::create_dir_all(&modules_dir).expect("modules dir");

        let registry = CapabilityRegistry::default_all();
        cmd_status_global(&cli, &registry, &modules_dir).expect("global status should render");
    }

    #[test]
    fn cmd_status_global_renders_monitor_only_posture_when_responder_disabled() {
        // Exercises the non-enforcing branch (responder disabled -> the
        // posture CTA line is printed), the default a fresh install ships.
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("status-data");
        write_file(
            &cli.agent_config,
            &format!(
                "[output]\ndata_dir = \"{}\"\n[ai]\nenabled = false\nprovider = \"ollama\"\n[responder]\nenabled = false\ndry_run = true\n",
                data_dir.display()
            ),
        );
        write_file(
            &cli.sensor_config,
            "[collectors.exec_audit]\nenabled = true\n",
        );
        let modules_dir = temp.path().join("modules");
        std::fs::create_dir_all(&modules_dir).expect("modules dir");

        let registry = CapabilityRegistry::default_all();
        // Asserts the disabled-responder path renders without panicking; the
        // posture wording itself is unit-tested in innerwarden_core.
        cmd_status_global(&cli, &registry, &modules_dir)
            .expect("global status should render in monitor-only mode");
    }

    #[test]
    fn cmd_sensor_status_handles_missing_and_empty_telemetry() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("sensor-data");

        cmd_sensor_status(&cli, &data_dir).expect("missing telemetry is ok");

        write_file(
            &data_dir.join(format!("telemetry-{}.jsonl", today())),
            "{\"events_by_collector\":{},\"incidents_by_detector\":{},\"errors_by_component\":{}}\n",
        );
        cmd_sensor_status(&cli, &data_dir).expect("empty telemetry maps are ok");
    }

    #[test]
    fn cmd_sensor_status_renders_populated_snapshot_branches() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("sensor-data");
        write_file(
            &data_dir.join(format!("telemetry-{}.jsonl", today())),
            "{\"events_by_collector\":{\"exec\":5,\"nginx\":2},\"incidents_by_detector\":{\"sudo_abuse\":3},\"ai_sent_count\":4,\"ai_decision_count\":2,\"avg_decision_latency_ms\":123.4,\"real_execution_count\":1,\"dry_run_execution_count\":2,\"gate_pass_count\":7,\"errors_by_component\":{\"sensor\":1}}\n",
        );

        cmd_sensor_status(&cli, &data_dir).expect("populated telemetry should render");
    }

    #[test]
    fn cmd_metrics_reports_missing_empty_and_populated_telemetry() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("metrics-data");

        let missing = cmd_metrics(&cli, &data_dir).expect_err("missing telemetry should error");
        assert!(missing.to_string().contains("cannot read"));

        let telemetry = data_dir.join(format!("telemetry-{}.jsonl", today()));
        write_file(&telemetry, "\n\n");
        cmd_metrics(&cli, &data_dir).expect("empty telemetry file is reported");

        write_file(
            &telemetry,
            "{\"ts\":0}\n{\"events_by_collector\":{\"exec\":2,\"nginx\":8},\"incidents_by_detector\":{\"ssh\":1},\"decisions_by_action\":{\"block_ip\":1,\"ignore\":2},\"avg_decision_latency_ms\":45.6,\"ai_sent_count\":3,\"ai_decision_count\":2,\"gate_pass_count\":4,\"real_execution_count\":1,\"dry_run_execution_count\":5}\n",
        );
        cmd_metrics(&cli, &data_dir).expect("populated telemetry metrics should render");
    }

    /// Spec 044 Phase 2.3: `innerwarden get posture` reads the snapshot
    /// the agent writes and pretty-prints it. The hint message when the
    /// file is missing is the visible signal that the operator is on a
    /// pre-spec-044 binary or that the agent has not booted yet.
    #[test]
    fn cmd_posture_missing_file_emits_hint_and_returns_ok() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("posture-data");
        // Function returns Ok even when the file is missing — the
        // operator sees the diagnostic via println, not via stderr.
        cmd_posture(&cli, &data_dir).expect("missing snapshot is not an error");
    }

    /// All four probe surfaces present + ok: exercises every branch
    /// of the pretty-printer (sshd directive lines, listener loop,
    /// sudo group lines, sudoers.d list, firewall backend list,
    /// allowed-ports list).
    #[test]
    fn cmd_posture_renders_full_snapshot_branches() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("posture-data");
        let path = data_dir.join("posture.json");
        let snap = r#"{
          "captured_at": "2026-05-09T15:00:00Z",
          "sshd": {
            "probe_state": "ok",
            "password_authentication": "no",
            "kbd_interactive_authentication": "no",
            "permit_root_login": "no",
            "pubkey_authentication": "yes",
            "max_auth_tries": 6,
            "ports": [22, 2222]
          },
          "services": {
            "probe_state": "ok",
            "listeners": [
              {"proto": "tcp", "port": 22, "addr": "0.0.0.0", "comm": "sshd"},
              {"proto": "tcp", "port": 8787, "addr": "0.0.0.0", "comm": "innerwarden-age"}
            ]
          },
          "sudo": {
            "probe_state": "ok",
            "sudo_group_members": ["alice", "deploy"],
            "wheel_group_members": [],
            "admin_group_members": [],
            "sudoers_d_filenames": ["deploy", "zz-innerwarden-deny-bob"]
          },
          "firewall": {
            "probe_state": "ok",
            "active_backends": ["ufw"],
            "default_policy": "drop",
            "allowed_tcp_ports": [22, 8787]
          }
        }"#;
        write_file(&path, snap);
        cmd_posture(&cli, &data_dir).expect("full ok snapshot renders");
    }

    /// Failed / unavailable probes: exercises the error branch in each
    /// section. Anchors that the command does NOT panic when probe
    /// states are not Ok — the operator might have an agent running on
    /// a host without sshd / nft / sudo.
    #[test]
    fn cmd_posture_renders_failed_and_unavailable_probe_states() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("posture-data");
        let path = data_dir.join("posture.json");
        let snap = r#"{
          "captured_at": "2026-05-09T15:00:00Z",
          "sshd": {"probe_state": "unavailable", "error": "sshd binary not found"},
          "services": {"probe_state": "failed", "listeners": [], "error": "ss exit 1"},
          "sudo": {"probe_state": "unavailable", "error": "getent: not found"},
          "firewall": {"probe_state": "unavailable"}
        }"#;
        write_file(&path, snap);
        cmd_posture(&cli, &data_dir).expect("error states render without panic");
    }

    #[test]
    fn cmd_posture_malformed_json_returns_err() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("posture-data");
        let path = data_dir.join("posture.json");
        write_file(&path, "{not json");
        let err = cmd_posture(&cli, &data_dir).expect_err("malformed JSON must error");
        assert!(err.to_string().contains("malformed JSON"));
    }

    // ---- SQLite-store routing tests (spec: get readers route to store) ----

    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::{Event, Severity};
    use innerwarden_core::incident::Incident;
    use innerwarden_store::Store;

    fn today_ts(hhmmss: &str) -> String {
        format!("{}T{hhmmss}+00:00", today())
    }

    fn seed_event(store: &Store, source: &str) {
        let ev = Event {
            ts: chrono::DateTime::parse_from_rfc3339(&today_ts("09:00:00"))
                .unwrap()
                .with_timezone(&chrono::Utc),
            host: "h".to_string(),
            source: source.to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Medium,
            summary: "exec".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        store.insert_event(&ev).expect("seed event");
    }

    fn seed_incident(store: &Store, detector: &str, ip: &str, title: &str) {
        let inc = Incident {
            ts: chrono::DateTime::parse_from_rfc3339(&today_ts("10:30:00"))
                .unwrap()
                .with_timezone(&chrono::Utc),
            host: "h".to_string(),
            incident_id: format!("{detector}:{ip}:test"),
            severity: Severity::High,
            title: title.to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        store.insert_incident(&inc).expect("seed incident");
    }

    #[test]
    fn today_counts_prefers_store_over_jsonl() {
        let temp = TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let today = today();

        // JSONL files claim ZERO (file absent) — the bug being fixed. The
        // store holds the real data.
        let store = Store::open(&data_dir).expect("open store");
        for _ in 0..5 {
            seed_event(&store, "auth_log");
        }
        seed_incident(&store, "ssh_bruteforce", "203.0.113.10", "SSH Brute Force");
        drop(store);

        let (events, incidents, last) = today_counts(&data_dir, &today);
        assert_eq!(
            events, 5,
            "events come from the store, not the missing JSONL"
        );
        assert_eq!(incidents, 1, "incident counted from the store");
        let (title, _when) = last.expect("last incident from store");
        assert_eq!(title, "SSH Brute Force");
    }

    #[test]
    fn today_counts_falls_back_to_jsonl_when_store_empty() {
        let temp = TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let today = today();

        // Empty store (created but no rows) + legacy JSONL with data -> the
        // fallback path must surface the JSONL counts.
        let _store = Store::open(&data_dir).expect("open store");
        write_file(
            &data_dir.join(format!("events-{today}.jsonl")),
            "{}\n{}\n{}\n",
        );
        write_file(
            &data_dir.join(format!("incidents-{today}.jsonl")),
            &format!(
                "{{\"title\":\"Legacy threat\",\"ts\":\"{}\"}}\n",
                today_ts("11:00:00")
            ),
        );

        let (events, incidents, last) = today_counts(&data_dir, &today);
        assert_eq!(events, 3, "events fall back to JSONL line count");
        assert_eq!(incidents, 1, "incidents fall back to JSONL line count");
        assert_eq!(last.expect("last from jsonl").0, "Legacy threat");
    }

    #[test]
    fn cmd_status_global_renders_store_backed_counts() {
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("status-data");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        write_file(
            &cli.agent_config,
            &format!(
                "[output]\ndata_dir = \"{}\"\n[ai]\nenabled = true\nprovider = \"ollama\"\n[responder]\nenabled = true\ndry_run = false\n",
                data_dir.display()
            ),
        );
        write_file(
            &cli.sensor_config,
            "[collectors.exec_audit]\nenabled = true\n",
        );
        let store = Store::open(&data_dir).expect("open store");
        seed_event(&store, "auth_log");
        seed_incident(&store, "port_scan", "203.0.113.20", "Port scan");
        drop(store);

        let modules_dir = temp.path().join("modules");
        std::fs::create_dir_all(&modules_dir).expect("modules dir");
        let registry = CapabilityRegistry::default_all();
        // Default data_dir sentinel so resolve_data_dir reads the agent config
        // (which points at our seeded store directory).
        cmd_status_global(&cli, &registry, &modules_dir).expect("store-backed status renders");
    }

    #[test]
    fn render_sensor_status_from_store_reports_collectors_and_detectors() {
        let temp = TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let today = today();

        let store = Store::open(&data_dir).expect("open store");
        seed_event(&store, "auth_log");
        seed_event(&store, "auth_log");
        seed_event(&store, "ebpf_syscall");
        seed_incident(&store, "ssh_bruteforce", "203.0.113.30", "Brute force");
        drop(store);

        // Returns true when the store yields data.
        assert!(render_sensor_status_from_store(&data_dir, &today));
    }

    #[test]
    fn render_sensor_status_from_store_returns_false_when_empty() {
        let temp = TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let _store = Store::open(&data_dir).expect("open store");
        assert!(!render_sensor_status_from_store(&data_dir, &today()));
    }

    #[test]
    fn cmd_sensor_status_renders_store_when_no_telemetry_snapshot() {
        // No telemetry-*.jsonl present, but the store holds today's events —
        // the command must render from the store instead of "No telemetry".
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("sensor-data");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let store = Store::open(&data_dir).expect("open store");
        seed_event(&store, "dns_capture");
        seed_incident(&store, "dns_tunneling", "203.0.113.40", "DNS tunnel");
        drop(store);

        cmd_sensor_status(&cli, &data_dir).expect("store-backed sensor status renders");
    }

    #[test]
    fn metrics_breakdowns_from_store_returns_maps_when_seeded() {
        let temp = TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let today = today();
        let store = Store::open(&data_dir).expect("open store");
        seed_event(&store, "auth_log");
        seed_event(&store, "nginx_access");
        seed_incident(&store, "ssh_bruteforce", "203.0.113.50", "Brute");
        drop(store);

        let (events, incidents) = metrics_breakdowns_from_store(&data_dir, &today);
        let events = events.expect("event map present");
        assert_eq!(events.get("auth_log").copied(), Some(1));
        assert_eq!(events.get("nginx_access").copied(), Some(1));
        let incidents = incidents.expect("incident map present");
        assert_eq!(incidents.get("ssh_bruteforce").copied(), Some(1));
    }

    #[test]
    fn metrics_breakdowns_from_store_returns_none_when_empty() {
        let temp = TempDir::new().expect("tempdir");
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let _store = Store::open(&data_dir).expect("open store");
        let (events, incidents) = metrics_breakdowns_from_store(&data_dir, &today());
        assert!(events.is_none());
        assert!(incidents.is_none());
    }

    #[test]
    fn cmd_metrics_prefers_store_breakdowns_over_snapshot() {
        // Telemetry snapshot exists (so the "cannot read" gate passes) but its
        // event counter reads 0 / stale; the store holds the real per-source
        // counts. The command must render without panicking and prefer store.
        let temp = TempDir::new().expect("tempdir");
        let cli = test_cli(&temp);
        let data_dir = temp.path().join("metrics-data");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let today = today();
        write_file(
            &data_dir.join(format!("telemetry-{today}.jsonl")),
            "{\"events_by_collector\":{},\"incidents_by_detector\":{},\"decisions_by_action\":{\"block_ip\":1},\"ai_sent_count\":2,\"ai_decision_count\":1,\"gate_pass_count\":3,\"avg_decision_latency_ms\":10.0,\"real_execution_count\":1,\"dry_run_execution_count\":0}\n",
        );
        let store = Store::open(&data_dir).expect("open store");
        seed_event(&store, "auth_log");
        seed_incident(&store, "ssh_bruteforce", "203.0.113.60", "Brute");
        drop(store);

        cmd_metrics(&cli, &data_dir).expect("store-backed metrics render");
    }

    #[test]
    fn format_incident_time_ago_matches_buckets() {
        // Bad timestamp -> raw passthrough (short string branch).
        assert_eq!(format_incident_time_ago("bad"), "bad");
        // A recent timestamp -> "just now" or "Nm ago" (never panics).
        let recent = chrono::Utc::now().to_rfc3339();
        let out = format_incident_time_ago(&recent);
        assert!(out == "just now" || out.ends_with("m ago"));
    }
}

/// Build the per-source event counts and per-detector incident counts for
/// `today` from the unified SQLite store, for `cmd_metrics`.
///
/// Each return slot is `Some(map)` only when the store actually yielded data
/// for that dimension, so the caller falls back to the agent telemetry
/// snapshot maps when the store is absent / unreadable / empty. Event sources
/// are summed from `events_timeline_for_date`; detector keys are the first
/// colon-delimited segment of each incident's `incident_id` (matching the
/// agent telemetry's `detector_kind`).
#[allow(clippy::type_complexity)]
fn metrics_breakdowns_from_store(
    dir: &Path,
    today: &str,
) -> (Option<HashMap<String, u64>>, Option<HashMap<String, u64>>) {
    let store = match Store::open(dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [warn] metrics: store open failed ({e:#})");
            return (None, None);
        }
    };

    let mut events_by_source: HashMap<String, u64> = HashMap::new();
    if let Ok(timeline) = store.events_timeline_for_date(today) {
        for (_bucket, per_source) in timeline {
            for (source, count) in per_source {
                *events_by_source.entry(source).or_insert(0) += count;
            }
        }
    }

    let start_ts = format!("{today}T00:00:00+00:00");
    let mut incidents_by_detector: HashMap<String, u64> = HashMap::new();
    if let Ok(incidents) = store.incidents_since_ts(&start_ts, 100_000) {
        for inc in &incidents {
            let detector = inc
                .incident_id
                .split(':')
                .next()
                .unwrap_or("unknown")
                .to_string();
            *incidents_by_detector.entry(detector).or_insert(0) += 1;
        }
    }

    (
        (!events_by_source.is_empty()).then_some(events_by_source),
        (!incidents_by_detector.is_empty()).then_some(incidents_by_detector),
    )
}

pub(crate) fn cmd_metrics(cli: &Cli, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let today = epoch_secs_to_date(now_secs);

    let telemetry_path = effective_dir.join(format!("telemetry-{today}.jsonl"));
    let content = std::fs::read_to_string(&telemetry_path)
        .with_context(|| format!("cannot read {}", telemetry_path.display()))?;

    let first_line: Option<serde_json::Value> = content
        .lines()
        .find(|l| !l.trim().is_empty())
        .and_then(|line| serde_json::from_str(line).ok());

    let snapshot: Option<serde_json::Value> = content
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .and_then(|line| serde_json::from_str(line).ok());

    let Some(snap) = snapshot else {
        println!("InnerWarden - metrics  ({})\n", today);
        println!("  No telemetry data for today.");
        println!("  Is the agent running?  innerwarden status");
        return Ok(());
    };

    println!("InnerWarden - metrics  ({})\n", today);

    // Prefer the unified SQLite store for the event/incident breakdowns so the
    // totals match `get status` (the agent telemetry snapshot's
    // events_by_collector counter can lag or read 0 on migrated boxes). The
    // decisions / AI-pipeline / uptime sections below stay snapshot-sourced —
    // those counters live only in the agent snapshot, not the store.
    let (store_events, store_incidents) = metrics_breakdowns_from_store(&effective_dir, &today);

    println!("Events processed today:");
    let snap_collector: HashMap<String, u64> = snap["events_by_collector"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0)))
                .collect()
        })
        .unwrap_or_default();
    let events_map = store_events.as_ref().unwrap_or(&snap_collector);
    let mut total_events: u64 = 0;
    if events_map.is_empty() {
        println!("  (no events recorded yet today)");
    } else {
        let mut pairs: Vec<(&String, u64)> = events_map
            .iter()
            .map(|(k, v)| {
                total_events += *v;
                (k, *v)
            })
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        for (source, count) in &pairs {
            println!("  {:<30} {:>6}", source, count);
        }
        println!("  {:<30} {:>6}", "TOTAL", total_events);
    }

    println!();
    println!("Incidents detected today:");
    let snap_detector: HashMap<String, u64> = snap["incidents_by_detector"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0)))
                .collect()
        })
        .unwrap_or_default();
    let incidents_map = store_incidents.as_ref().unwrap_or(&snap_detector);
    let mut total_incidents: u64 = 0;
    if incidents_map.is_empty() {
        println!("  (no incidents today)");
    } else {
        let mut pairs: Vec<(&String, u64)> = incidents_map
            .iter()
            .map(|(k, v)| {
                total_incidents += *v;
                (k, *v)
            })
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        for (detector, count) in &pairs {
            println!("  {:<30} {:>6}", detector, count);
        }
        println!("  {:<30} {:>6}", "TOTAL", total_incidents);
    }

    println!();
    println!("Decisions made today:");
    let by_action = snap["decisions_by_action"].as_object();
    let mut total_decisions: u64 = 0;
    match by_action {
        Some(map) if !map.is_empty() => {
            let mut pairs: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| {
                    let c = v.as_u64().unwrap_or(0);
                    total_decisions += c;
                    (k, c)
                })
                .collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            for (action, count) in &pairs {
                println!("  {:<30} {:>6}", action, count);
            }
            println!("  {:<30} {:>6}", "TOTAL", total_decisions);
        }
        _ => println!("  (no decisions today)"),
    }

    let avg_ms = snap["avg_decision_latency_ms"].as_f64().unwrap_or(0.0);
    let ai_sent = snap["ai_sent_count"].as_u64().unwrap_or(0);
    let ai_decided = snap["ai_decision_count"].as_u64().unwrap_or(0);
    let gate_pass = snap["gate_pass_count"].as_u64().unwrap_or(0);
    let real_exec = snap["real_execution_count"].as_u64().unwrap_or(0);
    let dry_exec = snap["dry_run_execution_count"].as_u64().unwrap_or(0);

    println!();
    println!("AI pipeline:");
    println!("  Passed algorithm gate:    {:>6}", gate_pass);
    println!("  Sent to AI:               {:>6}", ai_sent);
    println!("  AI decisions:             {:>6}", ai_decided);
    println!("  Avg decision latency:     {:>5.0} ms", avg_ms);
    println!("  Actions executed (live):  {:>6}", real_exec);
    println!("  Actions simulated (dry):  {:>6}", dry_exec);

    if let Some(ref first) = first_line {
        if let Some(first_ts) = first["ts"].as_u64().or_else(|| first["timestamp"].as_u64()) {
            let uptime_secs = now_secs.saturating_sub(first_ts);
            let hours = uptime_secs / 3600;
            let minutes = (uptime_secs % 3600) / 60;
            println!();
            println!("Agent uptime (approx):      {}h {}m", hours, minutes);
        }
    }

    println!();
    Ok(())
}

/// `innerwarden get posture` — pretty-print the host posture snapshot
/// the agent uses for severity downgrade decisions (spec 044 Phase 2).
///
/// Reads `data_dir/posture.json` written by the agent's slow loop. The
/// command is read-only — refreshing the snapshot is the agent's job
/// (10 min cadence + boot snapshot + fanotify-triggered refresh).
///
/// When the file is missing the operator gets a hint: usually means
/// the agent is on an older binary that pre-dates spec 044, or the
/// agent has not been running long enough for the boot snapshot to
/// land. Refusing to fabricate fields here is deliberate — the
/// downgrade engine reads the same JSON and a stale or fabricated
/// view here would mask divergence from what the agent actually sees.
pub(crate) fn cmd_posture(cli: &Cli, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let path = effective_dir.join("posture.json");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("InnerWarden - host posture\n");
            println!("  No snapshot at {}.", path.display());
            println!();
            println!("  Causes:");
            println!("    - agent has not booted since spec 044 deploy");
            println!("    - agent is on an older binary (pre-2026-05-09)");
            println!();
            println!("  The agent writes this file at boot and refreshes every 10 min.");
            return Ok(());
        }
        Err(e) => {
            anyhow::bail!("cannot read {}: {e}", path.display());
        }
    };

    let snap: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("malformed JSON at {}", path.display()))?;

    let captured_at = snap["captured_at"].as_str().unwrap_or("?");
    println!("InnerWarden - host posture\n");
    println!("  Snapshot taken: {captured_at}");
    println!();

    // SSHD ─────────────────────────────────────────────────────────────────
    let sshd = &snap["sshd"];
    let sshd_state = sshd["probe_state"].as_str().unwrap_or("?");
    println!("SSHD ({sshd_state}):");
    if sshd_state == "ok" {
        let pa = sshd["password_authentication"].as_str().unwrap_or("?");
        let kbd = sshd["kbd_interactive_authentication"]
            .as_str()
            .unwrap_or("?");
        let prl = sshd["permit_root_login"].as_str().unwrap_or("?");
        let pk = sshd["pubkey_authentication"].as_str().unwrap_or("?");
        let mat = sshd["max_auth_tries"].as_u64();
        println!("  PasswordAuthentication        : {pa}");
        println!("  KbdInteractiveAuthentication  : {kbd}");
        println!("  PermitRootLogin               : {prl}");
        println!("  PubkeyAuthentication          : {pk}");
        if let Some(n) = mat {
            println!("  MaxAuthTries                  : {n}");
        }
        if let Some(ports) = sshd["ports"].as_array() {
            let list: Vec<String> = ports
                .iter()
                .filter_map(|p| p.as_u64().map(|n| n.to_string()))
                .collect();
            if !list.is_empty() {
                println!("  Listen ports                  : {}", list.join(", "));
            }
        }
    } else if let Some(err) = sshd["error"].as_str() {
        println!("  error: {err}");
    }
    println!();

    // Listening services ───────────────────────────────────────────────────
    let services = &snap["services"];
    let svc_state = services["probe_state"].as_str().unwrap_or("?");
    println!("Listening services ({svc_state}):");
    if svc_state == "ok" {
        if let Some(listeners) = services["listeners"].as_array() {
            if listeners.is_empty() {
                println!("  (no listeners)");
            } else {
                for l in listeners {
                    let proto = l["proto"].as_str().unwrap_or("?");
                    let port = l["port"].as_u64().unwrap_or(0);
                    let addr = l["addr"].as_str().unwrap_or("?");
                    let comm = l["comm"].as_str().unwrap_or("?");
                    println!("  {proto:<3} {addr}:{port}  {comm}");
                }
            }
        }
    } else if let Some(err) = services["error"].as_str() {
        println!("  error: {err}");
    }
    println!();

    // Sudo ─────────────────────────────────────────────────────────────────
    let sudo = &snap["sudo"];
    let sudo_state = sudo["probe_state"].as_str().unwrap_or("?");
    println!("Sudo ({sudo_state}):");
    if sudo_state == "ok" {
        for (key, label) in [
            ("sudo_group_members", "group sudo "),
            ("wheel_group_members", "group wheel"),
            ("admin_group_members", "group admin"),
        ] {
            if let Some(arr) = sudo[key].as_array() {
                let names: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                if !names.is_empty() {
                    println!("  {label}: {}", names.join(", "));
                }
            }
        }
        if let Some(arr) = sudo["sudoers_d_filenames"].as_array() {
            let names: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            if !names.is_empty() {
                println!("  /etc/sudoers.d/: {}", names.join(", "));
            }
        }
    } else if let Some(err) = sudo["error"].as_str() {
        println!("  error: {err}");
    }
    println!();

    // Firewall ─────────────────────────────────────────────────────────────
    let fw = &snap["firewall"];
    let fw_state = fw["probe_state"].as_str().unwrap_or("?");
    println!("Firewall ({fw_state}):");
    if fw_state == "ok" {
        if let Some(arr) = fw["active_backends"].as_array() {
            let names: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            if !names.is_empty() {
                println!("  Active backends   : {}", names.join(", "));
            }
        }
        let policy = fw["default_policy"].as_str().unwrap_or("?");
        println!("  Default INPUT     : {policy}");
        if let Some(ports) = fw["allowed_tcp_ports"].as_array() {
            let list: Vec<String> = ports
                .iter()
                .filter_map(|p| p.as_u64().map(|n| n.to_string()))
                .collect();
            if !list.is_empty() {
                println!("  Allowed TCP ports : {}", list.join(", "));
            }
        }
    } else if let Some(err) = fw["error"].as_str() {
        println!("  error: {err}");
    }
    println!();

    Ok(())
}
