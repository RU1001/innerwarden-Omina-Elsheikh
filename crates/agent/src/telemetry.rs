use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use innerwarden_core::{event::Event, incident::Incident};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::ai::AiAction;
use crate::correlation;

/// Wave 6b (memory-opt, 2026-05-05): the keys in
/// `events_by_collector` and the other `BTreeMap<*, u64>` fields here
/// repeat across every observed event (only ~5-10 distinct collector
/// names exist in steady state). Pre-Wave-6b each `.entry(event.source.clone())`
/// cycle allocated a fresh `String` per event regardless of whether
/// the entry already existed (HashMap/BTreeMap take owned keys, drop
/// duplicates after lookup). With `Arc<str>` interned at the call
/// site, the lookup uses a 16-byte pointer-clone in the steady-state
/// case where the entry already exists. Wire format is unchanged
/// (serde renders `Arc<str>` as a plain JSON string).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub ts: DateTime<Utc>,
    pub tick: String,
    pub events_by_collector: BTreeMap<Arc<str>, u64>,
    pub incidents_by_detector: BTreeMap<Arc<str>, u64>,
    pub gate_pass_count: u64,
    /// Added by spec 024 Phase 7 (feedback loop). Snapshots written before
    /// that land on disk without this field, so default to 0 on replay.
    #[serde(default)]
    pub gate_suppressed_total: u64,
    pub ai_sent_count: u64,
    /// Added by spec 024 Phase 7 (telegram-sent counter for the
    /// `innerwarden_telegram_msgs_per_hour` drift metric). Default to 0
    /// on replay of pre-Phase-7 snapshots.
    #[serde(default)]
    pub telegram_sent_count: u64,
    pub ai_decision_count: u64,
    pub avg_decision_latency_ms: f64,
    pub errors_by_component: BTreeMap<String, u64>,
    pub decisions_by_action: BTreeMap<String, u64>,
    pub dry_run_execution_count: u64,
    pub real_execution_count: u64,
    /// Spec 084 P0 1C: per-tenant incident counts, keyed by the `tenant:<id>`
    /// tag that `tenancy::enrich_incident` stamps on container-scoped incidents.
    /// Default empty on replay of pre-084 snapshots.
    #[serde(default)]
    pub incidents_by_tenant: BTreeMap<String, u64>,
}

/// Map a physical (source, kind) tuple to its logical telemetry stream id.
///
/// The Sensors panel on the dashboard groups events by stream, not by raw
/// collector source. Most events map straight through (stream = source),
/// but a few logical streams are fed by more than one physical collector
/// and silently report 0 if we attribute by source alone. The current
/// cross-source pairing is the kernel firewall log: both
/// `syslog_firewall` (reading /var/log/syslog) and `journald` (reading
/// systemd-journald's kernel facility) parse the same `[UFW BLOCK]`
/// lines, so we attribute either physical emitter to the
/// `syslog_firewall` stream key.
///
/// Pure function so the mapping table is unit-testable without spinning
/// up the agent loop. Keep the match arms exhaustive and add new
/// cross-source pairings here when the dashboard introduces a new
/// logical stream.
pub fn telemetry_stream_for<'a>(source: &'a str, kind: &'a str) -> &'a str {
    // Kernel firewall blocks: journald and syslog_firewall both emit
    // `kind = "network.connection_blocked"` from the same source-of-truth
    // (kernel ringbuffer). Pin both to the syslog_firewall stream so the
    // dashboard reports the real block count, regardless of which physical
    // collector won the race to the line.
    if kind == "network.connection_blocked" {
        return "syslog_firewall";
    }
    source
}

/// Spec 056 Phase 3: process-global named-counter registry backing the
/// playbook `emit_metric` virtual skill.
///
/// `emit_metric` lets an operator count how often a playbook step runs
/// (hit rate per host) without threading `&mut AgentState` into the
/// declarative executor — the same decoupling the gate-suppressed /
/// telegram-sent counters use via `Arc<AtomicU64>`, except the metric
/// name is operator-chosen so a fixed struct field cannot hold it. The
/// registry is monotonic for the process lifetime; the dashboard
/// endpoint (Phase 5) reads it via [`playbook_metrics_snapshot`].
static PLAYBOOK_METRICS: std::sync::OnceLock<std::sync::Mutex<BTreeMap<String, u64>>> =
    std::sync::OnceLock::new();

fn playbook_metrics() -> &'static std::sync::Mutex<BTreeMap<String, u64>> {
    PLAYBOOK_METRICS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// Increment the named playbook counter by `by` and return the new total.
/// A poisoned lock (a prior panic while holding it) is recovered rather
/// than propagated — a metric counter must never crash the incident loop.
pub fn emit_counter(name: &str, by: u64) -> u64 {
    let mut map = playbook_metrics().lock().unwrap_or_else(|p| p.into_inner());
    let entry = map.entry(name.to_string()).or_insert(0);
    *entry = entry.saturating_add(by);
    *entry
}

/// Current value of a single playbook counter (0 if never emitted).
/// Read path: the Phase 5 dashboard/CLI introspection surfaces these;
/// today only the test suite reads them, so allow dead_code until then.
#[allow(dead_code)]
pub fn playbook_metric_value(name: &str) -> u64 {
    playbook_metrics()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(name)
        .copied()
        .unwrap_or(0)
}

/// Snapshot of every playbook counter, for dashboard / CLI introspection.
#[allow(dead_code)]
pub fn playbook_metrics_snapshot() -> BTreeMap<String, u64> {
    playbook_metrics()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
}

#[derive(Debug, Default)]
pub struct TelemetryState {
    events_by_collector: BTreeMap<Arc<str>, u64>,
    incidents_by_detector: BTreeMap<Arc<str>, u64>,
    gate_pass_count: u64,
    gate_suppressed_total: Arc<AtomicU64>,
    ai_sent_count: u64,
    telegram_sent_count: Arc<AtomicU64>,
    ai_decision_count: u64,
    decision_latency_sum_ms: u128,
    errors_by_component: BTreeMap<String, u64>,
    decisions_by_action: BTreeMap<String, u64>,
    dry_run_execution_count: u64,
    real_execution_count: u64,
    incidents_by_tenant: BTreeMap<String, u64>,
}

impl TelemetryState {
    pub fn with_external_counters(
        telegram_sent_count: Arc<AtomicU64>,
        gate_suppressed_total: Arc<AtomicU64>,
    ) -> Self {
        Self {
            telegram_sent_count,
            gate_suppressed_total,
            ..Self::default()
        }
    }

    pub fn observe_events(&mut self, events: &[Event]) {
        for event in events {
            // Wave 6b: intern source so the BTreeMap key allocation is
            // shared across every observe_events call with the same
            // collector name. Pre-Wave-6b each call allocated a fresh
            // String even when the entry already existed.
            //
            // 2026-05-21: attribute by *telemetry stream* rather than raw
            // physical source. The dashboard's Sensors panel groups events
            // by logical stream (e.g. "syslog_firewall" = firewall blocks
            // regardless of whether the kernel line was read via the
            // syslog_firewall collector or via journald's kernel parser).
            // `telemetry_stream_for` picks the right bucket so the panel
            // does not silently report 0 for a stream that two separate
            // collectors are feeding.
            let stream = telemetry_stream_for(&event.source, &event.kind);
            *self
                .events_by_collector
                .entry(crate::knowledge_graph::intern::intern(stream))
                .or_insert(0) += 1;
        }
    }

    pub fn observe_incident(&mut self, incident: &Incident) {
        let kind = correlation::detector_kind(incident);
        // Wave 6b: detector kind is one of ~50 known strings; intern so
        // the BTreeMap dedupes the key allocation across the day.
        *self
            .incidents_by_detector
            .entry(crate::knowledge_graph::intern::intern(&kind))
            .or_insert(0) += 1;
        // Spec 084 P0 1C: per-tenant incident count from the `tenant:<id>` tag
        // that `tenancy::enrich_incident` stamps (the agent enriches incidents
        // before this observe call). Host / non-k8s incidents carry no such tag
        // and so create no per-tenant bucket.
        if let Some(tenant) = incident.tags.iter().find_map(|t| t.strip_prefix("tenant:")) {
            *self
                .incidents_by_tenant
                .entry(tenant.to_string())
                .or_insert(0) += 1;
        }
    }

    pub fn observe_gate_pass(&mut self) {
        self.gate_pass_count += 1;
    }

    pub fn gate_suppressed_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.gate_suppressed_total)
    }

    pub fn observe_ai_sent(&mut self) {
        self.ai_sent_count += 1;
    }

    pub fn observe_ai_decision(&mut self, action: &AiAction, latency_ms: u128) {
        self.ai_decision_count += 1;
        self.decision_latency_sum_ms += latency_ms;
        *self
            .decisions_by_action
            .entry(action_tag(action).to_string())
            .or_insert(0) += 1;
    }

    pub fn observe_execution_path(&mut self, dry_run: bool) {
        if dry_run {
            self.dry_run_execution_count += 1;
        } else {
            self.real_execution_count += 1;
        }
    }

    pub fn observe_error(&mut self, component: &str) {
        *self
            .errors_by_component
            .entry(component.to_string())
            .or_insert(0) += 1;
    }

    pub fn snapshot(&self, tick: &str) -> TelemetrySnapshot {
        let avg_latency = if self.ai_decision_count > 0 {
            self.decision_latency_sum_ms as f64 / self.ai_decision_count as f64
        } else {
            0.0
        };

        TelemetrySnapshot {
            ts: Utc::now(),
            tick: tick.to_string(),
            events_by_collector: self.events_by_collector.clone(),
            incidents_by_detector: self.incidents_by_detector.clone(),
            gate_pass_count: self.gate_pass_count,
            gate_suppressed_total: self.gate_suppressed_total.load(Ordering::Relaxed),
            ai_sent_count: self.ai_sent_count,
            telegram_sent_count: self.telegram_sent_count.load(Ordering::Relaxed),
            ai_decision_count: self.ai_decision_count,
            avg_decision_latency_ms: avg_latency,
            errors_by_component: self.errors_by_component.clone(),
            decisions_by_action: self.decisions_by_action.clone(),
            dry_run_execution_count: self.dry_run_execution_count,
            real_execution_count: self.real_execution_count,
            incidents_by_tenant: self.incidents_by_tenant.clone(),
        }
    }
}

pub struct TelemetryWriter {
    data_dir: std::path::PathBuf,
    current_date: String,
    writer: BufWriter<File>,
}

impl TelemetryWriter {
    pub fn new(data_dir: &Path) -> Result<Self> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let file = open_or_create(data_dir, &today)?;
        Ok(Self {
            data_dir: data_dir.to_owned(),
            current_date: today,
            writer: BufWriter::new(file),
        })
    }

    pub fn write(&mut self, snapshot: &TelemetrySnapshot) -> Result<()> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        if today != self.current_date {
            if let Err(e) = self.writer.flush() {
                warn!("telemetry flush failed during date rollover: {e}");
            }
            let file = open_or_create(&self.data_dir, &today)?;
            self.writer = BufWriter::new(file);
            self.current_date = today;
        }

        let line =
            serde_json::to_string(snapshot).context("failed to serialize telemetry snapshot")?;
        writeln!(self.writer, "{line}").context("failed to write telemetry snapshot")?;
        self.writer
            .flush()
            .context("failed to flush telemetry snapshot")?;
        Ok(())
    }

    pub fn flush(&mut self) {
        if let Err(e) = self.writer.flush() {
            warn!("telemetry writer flush failed: {e}");
        }
    }
}

pub fn read_latest_snapshot(data_dir: &Path, date: &str) -> Option<TelemetrySnapshot> {
    let path = telemetry_path_for_date(data_dir, date)?;
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);

    let mut latest: Option<TelemetrySnapshot> = None;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                warn!("failed to read telemetry line: {e}");
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<TelemetrySnapshot>(trimmed) {
            Ok(snapshot) => match &latest {
                Some(current) if current.ts >= snapshot.ts => {}
                _ => latest = Some(snapshot),
            },
            Err(e) => {
                warn!("failed to parse telemetry snapshot: {e}");
                continue;
            }
        }
    }

    latest
}

/// Returns the newest telemetry snapshot whose timestamp is <= `not_after`.
/// This is used to compute trailing-window deltas (for example, "last hour")
/// from cumulative counters.
pub fn read_snapshot_at(
    data_dir: &Path,
    date: &str,
    not_after: DateTime<Utc>,
) -> Option<TelemetrySnapshot> {
    let path = telemetry_path_for_date(data_dir, date)?;
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);

    let mut candidate: Option<TelemetrySnapshot> = None;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                warn!("failed to read telemetry line: {e}");
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<TelemetrySnapshot>(trimmed) {
            Ok(snapshot) => {
                if snapshot.ts > not_after {
                    continue;
                }
                match &candidate {
                    Some(current) if current.ts >= snapshot.ts => {}
                    _ => candidate = Some(snapshot),
                }
            }
            Err(e) => {
                warn!("failed to parse telemetry snapshot: {e}");
            }
        }
    }

    candidate
}

fn action_tag(action: &AiAction) -> &'static str {
    match action {
        AiAction::BlockIp { .. } => "block_ip",
        AiAction::Monitor { .. } => "monitor",
        AiAction::Honeypot { .. } => "honeypot",
        AiAction::SuspendUserSudo { .. } => "suspend_user_sudo",
        AiAction::KillProcess { .. } => "kill_process",
        AiAction::BlockContainer { .. } => "block_container",
        AiAction::RequestConfirmation { .. } => "request_confirmation",
        AiAction::KillChainResponse { .. } => "kill_chain_response",
        AiAction::Ignore { .. } => "ignore",
        AiAction::Dismiss { .. } => "dismiss",
    }
}

fn open_or_create(data_dir: &Path, date: &str) -> Result<File> {
    let safe_date: String = date
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    let path = data_dir.join(format!("telemetry-{safe_date}.jsonl"));
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))
}

fn telemetry_path_for_date(data_dir: &Path, date: &str) -> Option<std::path::PathBuf> {
    // Validate date format strictly - reject anything that isn't YYYY-MM-DD.
    let parsed = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;
    let safe_date = parsed.format("%Y-%m-%d").to_string();
    let canonical = std::fs::canonicalize(data_dir).ok()?;
    let target = canonical.join(format!("telemetry-{safe_date}.jsonl"));
    if !target.starts_with(&canonical) {
        return None;
    }
    Some(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai;
    use chrono::Utc;
    use innerwarden_core::{
        entities::EntityRef,
        event::{Event, Severity},
        incident::Incident,
    };
    use tempfile::TempDir;

    /// 2026-05-21 anchor: events from any collector whose kind is
    /// `network.connection_blocked` (syslog_firewall + journald both
    /// emit this for kernel UFW lines) get aggregated into the
    /// `syslog_firewall` telemetry stream. Pre-fix the Sensors panel
    /// reported 0 firewall blocks because the journald-sourced events
    /// landed in a separate bucket the panel did not query.
    #[test]
    fn telemetry_stream_for_pins_kernel_firewall_to_syslog_firewall() {
        assert_eq!(
            telemetry_stream_for("syslog_firewall", "network.connection_blocked"),
            "syslog_firewall",
            "syslog_firewall emitting its own kind stays on the stream"
        );
        assert_eq!(
            telemetry_stream_for("journald", "network.connection_blocked"),
            "syslog_firewall",
            "journald-parsed UFW lines belong on the syslog_firewall stream"
        );
        // Pass-through for any non-cross-sourced kind: the stream id
        // equals the physical source.
        assert_eq!(
            telemetry_stream_for("journald", "ssh.login_failed"),
            "journald"
        );
        assert_eq!(
            telemetry_stream_for("docker", "container.started"),
            "docker"
        );
    }

    /// Wave 6b (AUDIT-WAVE6B-INTERN) anchor: 1000 events with the same
    /// `source = "auth_log"` produce a `events_by_collector` BTreeMap
    /// with ONE entry whose key is pointer-equal to
    /// `intern("auth_log")`. Pre-Wave-6b each call did
    /// `entry(event.source.clone())` which allocated a fresh `String`
    /// PER EVENT — `BTreeMap::entry` takes owned keys so the
    /// duplicate is allocated and then dropped after the lookup.
    /// With `Arc<str>` interned at the call site, the per-event
    /// cost is a 16-byte pointer-clone.
    #[test]
    fn observe_events_interns_collector_key_via_arc_str() {
        let gate_counter = Arc::new(AtomicU64::new(0));
        let telegram_counter = Arc::new(AtomicU64::new(0));
        let mut state = TelemetryState::with_external_counters(telegram_counter, gate_counter);
        let ev = Event {
            ts: Utc::now(),
            host: "h".into(),
            source: "auth_log".into(),
            kind: "ssh.login_failed".into(),
            severity: Severity::Medium,
            summary: "s".into(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        let batch = vec![ev.clone(); 1000];
        state.observe_events(&batch);
        // Take a snapshot to inspect the map.
        let snap = state.snapshot("tick");
        assert_eq!(
            snap.events_by_collector.len(),
            1,
            "1000 events with the same source produce ONE map entry"
        );
        assert_eq!(
            snap.events_by_collector.values().copied().sum::<u64>(),
            1000
        );
        // The key must share its allocation with `intern("auth_log")` —
        // pointer-equality on the underlying `Arc<str>` proves the
        // interner is wired at the insert site.
        let canonical = crate::knowledge_graph::intern::intern("auth_log");
        let stored_key = snap.events_by_collector.keys().next().unwrap();
        assert!(
            Arc::ptr_eq(stored_key, &canonical),
            "events_by_collector key must share Arc allocation with intern(\"auth_log\")"
        );
    }

    /// Wave 6b: round-trip JSON serialize → deserialize keeps the wire
    /// format identical to pre-Wave-6b. The keys go from `Arc<str>` to
    /// JSON string and back; deserialization produces a fresh
    /// `Arc<str>` per key (no auto-interning on cold load), but
    /// content equality is preserved so consumers see the same data.
    #[test]
    fn telemetry_snapshot_arc_str_keys_round_trip_through_json() {
        let mut events_by_collector: BTreeMap<Arc<str>, u64> = BTreeMap::new();
        events_by_collector.insert(crate::knowledge_graph::intern::intern("auth_log"), 42);
        events_by_collector.insert(crate::knowledge_graph::intern::intern("ebpf"), 99);
        let snap = TelemetrySnapshot {
            ts: Utc::now(),
            tick: "t".into(),
            events_by_collector,
            incidents_by_detector: BTreeMap::new(),
            gate_pass_count: 0,
            gate_suppressed_total: 0,
            ai_sent_count: 0,
            telegram_sent_count: 0,
            ai_decision_count: 0,
            avg_decision_latency_ms: 0.0,
            errors_by_component: BTreeMap::new(),
            decisions_by_action: BTreeMap::new(),
            dry_run_execution_count: 0,
            real_execution_count: 0,
            incidents_by_tenant: BTreeMap::new(),
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        // Wire format check: keys appear as plain JSON strings, not
        // any Arc-tagged structure. Pre- and post-Wave-6b consumers
        // must parse the SAME wire format.
        assert!(
            json.contains("\"auth_log\":42"),
            "auth_log key must serialize as a plain JSON string: {json}"
        );
        assert!(json.contains("\"ebpf\":99"));
        let back: TelemetrySnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.events_by_collector.get("auth_log").copied(), Some(42));
        assert_eq!(back.events_by_collector.get("ebpf").copied(), Some(99));
    }

    #[test]
    fn telemetry_state_tracks_counts_and_latency() {
        let gate_counter = Arc::new(AtomicU64::new(0));
        let telegram_counter = Arc::new(AtomicU64::new(0));
        let mut state =
            TelemetryState::with_external_counters(telegram_counter.clone(), gate_counter.clone());

        let ev = Event {
            ts: Utc::now(),
            host: "h".into(),
            source: "auth.log".into(),
            kind: "ssh.login_failed".into(),
            severity: Severity::Info,
            summary: "x".into(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        state.observe_events(&[ev]);

        let inc = Incident {
            ts: Utc::now(),
            host: "h".into(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".into(),
            severity: Severity::High,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        state.observe_incident(&inc);
        state.observe_gate_pass();
        gate_counter.fetch_add(1, Ordering::Relaxed);
        telegram_counter.fetch_add(1, Ordering::Relaxed);
        state.observe_ai_sent();
        state.observe_ai_decision(
            &ai::AiAction::BlockIp {
                ip: "1.2.3.4".to_string(),
                skill_id: "block-ip-ufw".to_string(),
            },
            120,
        );
        state.observe_execution_path(true);
        state.observe_error("ai_provider");

        let snap = state.snapshot("incident_tick");
        assert_eq!(snap.events_by_collector.get("auth.log").copied(), Some(1));
        assert_eq!(
            snap.incidents_by_detector.get("ssh_bruteforce").copied(),
            Some(1)
        );
        assert_eq!(snap.gate_pass_count, 1);
        assert_eq!(snap.gate_suppressed_total, 1);
        assert_eq!(snap.ai_sent_count, 1);
        assert_eq!(snap.telegram_sent_count, 1);
        assert_eq!(snap.ai_decision_count, 1);
        assert_eq!(snap.avg_decision_latency_ms, 120.0);
        assert_eq!(snap.dry_run_execution_count, 1);
        assert_eq!(snap.real_execution_count, 0);
        assert_eq!(
            snap.errors_by_component.get("ai_provider").copied(),
            Some(1)
        );
        assert_eq!(snap.decisions_by_action.get("block_ip").copied(), Some(1));
    }

    // Spec 084 P0 1C: incidents carrying a `tenant:<id>` tag (stamped by
    // tenancy::enrich_incident) are counted per tenant; host/non-k8s incidents
    // (no tag) create no bucket.
    #[test]
    fn observe_incident_counts_per_tenant_tag() {
        let mut state = TelemetryState::default();
        let mk = |id: &str, tags: Vec<String>| Incident {
            ts: Utc::now(),
            host: "h".into(),
            incident_id: id.into(),
            severity: Severity::High,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags,
            entities: vec![],
        };
        state.observe_incident(&mk(
            "reverse_shell:1",
            vec!["ebpf".into(), "tenant:acme-corp".into()],
        ));
        state.observe_incident(&mk("privesc:2", vec!["tenant:acme-corp".into()]));
        state.observe_incident(&mk("c2_callback:3", vec!["tenant:globex-inc".into()]));
        state.observe_incident(&mk("ssh_bruteforce:4", vec![])); // host, no tenant

        let snap = state.snapshot("t");
        assert_eq!(snap.incidents_by_tenant.get("acme-corp").copied(), Some(2));
        assert_eq!(snap.incidents_by_tenant.get("globex-inc").copied(), Some(1));
        // the host incident created no per-tenant bucket
        assert_eq!(snap.incidents_by_tenant.len(), 2);
    }

    #[test]
    fn telemetry_writer_and_reader_roundtrip() {
        let dir = TempDir::new().unwrap();
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let mut writer = TelemetryWriter::new(dir.path()).unwrap();

        let gate_counter = Arc::new(AtomicU64::new(0));
        let telegram_counter = Arc::new(AtomicU64::new(0));
        let mut state =
            TelemetryState::with_external_counters(telegram_counter.clone(), gate_counter.clone());
        state.observe_gate_pass();
        telegram_counter.fetch_add(1, Ordering::Relaxed);
        let first = state.snapshot("incident_tick");
        writer.write(&first).unwrap();

        state.observe_ai_sent();
        let second = state.snapshot("incident_tick");
        writer.write(&second).unwrap();
        writer.flush();

        let latest = read_latest_snapshot(dir.path(), &date).unwrap();
        assert_eq!(latest.ai_sent_count, 1);
        assert_eq!(latest.gate_pass_count, 1);
        assert_eq!(latest.telegram_sent_count, 1);
    }

    #[test]
    fn read_snapshot_at_returns_nearest_snapshot_not_after_threshold() {
        let dir = TempDir::new().unwrap();
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let path = dir.path().join(format!("telemetry-{date}.jsonl"));

        let now = Utc::now();
        let older = TelemetrySnapshot {
            ts: now - chrono::Duration::minutes(75),
            tick: "old".to_string(),
            events_by_collector: BTreeMap::new(),
            incidents_by_detector: BTreeMap::new(),
            gate_pass_count: 0,
            gate_suppressed_total: 0,
            ai_sent_count: 0,
            telegram_sent_count: 1,
            ai_decision_count: 0,
            avg_decision_latency_ms: 0.0,
            errors_by_component: BTreeMap::new(),
            decisions_by_action: BTreeMap::new(),
            dry_run_execution_count: 0,
            real_execution_count: 0,
            incidents_by_tenant: BTreeMap::new(),
        };
        let newer = TelemetrySnapshot {
            ts: now - chrono::Duration::minutes(61),
            tick: "near".to_string(),
            events_by_collector: BTreeMap::new(),
            incidents_by_detector: BTreeMap::new(),
            gate_pass_count: 0,
            gate_suppressed_total: 0,
            ai_sent_count: 0,
            telegram_sent_count: 2,
            ai_decision_count: 0,
            avg_decision_latency_ms: 0.0,
            errors_by_component: BTreeMap::new(),
            decisions_by_action: BTreeMap::new(),
            dry_run_execution_count: 0,
            real_execution_count: 0,
            incidents_by_tenant: BTreeMap::new(),
        };
        let too_new = TelemetrySnapshot {
            ts: now - chrono::Duration::minutes(10),
            tick: "future".to_string(),
            events_by_collector: BTreeMap::new(),
            incidents_by_detector: BTreeMap::new(),
            gate_pass_count: 0,
            gate_suppressed_total: 0,
            ai_sent_count: 0,
            telegram_sent_count: 99,
            ai_decision_count: 0,
            avg_decision_latency_ms: 0.0,
            errors_by_component: BTreeMap::new(),
            decisions_by_action: BTreeMap::new(),
            dry_run_execution_count: 0,
            real_execution_count: 0,
            incidents_by_tenant: BTreeMap::new(),
        };

        let mut content = String::new();
        content.push_str(&serde_json::to_string(&older).unwrap());
        content.push('\n');
        content.push_str(&serde_json::to_string(&newer).unwrap());
        content.push('\n');
        content.push_str(&serde_json::to_string(&too_new).unwrap());
        content.push('\n');
        std::fs::write(path, content).unwrap();

        let threshold = now - chrono::Duration::hours(1);
        let chosen = read_snapshot_at(dir.path(), &date, threshold).unwrap();
        assert_eq!(chosen.tick, "near");
        assert_eq!(chosen.telegram_sent_count, 2);
    }

    #[test]
    fn snapshot_deserialises_without_gate_suppressed_or_telegram_sent() {
        // Pre-spec-024-Phase-7 snapshots landed on disk without the new
        // fields. After the upgrade they would fail parsing and flood the
        // log with warnings. `#[serde(default)]` on both fields makes
        // replay tolerant.
        let legacy = r#"{
            "ts": "2026-04-17T16:50:00Z",
            "tick": "incident_tick",
            "events_by_collector": {"auth.log": 42},
            "incidents_by_detector": {},
            "gate_pass_count": 3,
            "ai_sent_count": 1,
            "ai_decision_count": 1,
            "avg_decision_latency_ms": 120.0,
            "errors_by_component": {},
            "decisions_by_action": {},
            "dry_run_execution_count": 1,
            "real_execution_count": 0
        }"#;
        let parsed: TelemetrySnapshot =
            serde_json::from_str(legacy).expect("legacy snapshot must parse");
        assert_eq!(parsed.gate_suppressed_total, 0);
        assert_eq!(parsed.telegram_sent_count, 0);
        assert_eq!(parsed.gate_pass_count, 3);
        assert_eq!(parsed.ai_sent_count, 1);
    }
}
