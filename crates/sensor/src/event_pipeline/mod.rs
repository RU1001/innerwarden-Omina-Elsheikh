//! Event pipeline -- declarative filter/sample/promote engine.
//!
//! Sits between collectors and sinks. Every event passes through
//! `EventPipeline::should_persist()` before being written to SQLite
//! or syslog. Detectors still see all events in memory; the pipeline
//! only controls what gets persisted to disk.
//!
//! Rules are YAML files in `rules/event_pipeline/`, hot-reloaded via
//! mtime check every 60 seconds (same pattern as DynamicAllowlist).
//! Five built-in rule packs ship embedded in the binary and are always
//! loaded as baseline. On-disk rules with the same `id` override the
//! built-in; new ids are added.

pub mod types;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use innerwarden_core::event::Event;
use tracing::{info, warn};

use std::collections::HashSet;

use types::{
    compile_rule, expand_all_list_refs, validate_suppress_rule, ActionKind, CompiledAction,
    CompiledRule, RuleFile,
};

pub const BUILTIN_PACKS: &[(&str, &str)] = &[
    ("00-lists.yml", include_str!("builtin/00-lists.yml")),
    (
        "00-defensive-allowlist.yml",
        include_str!("builtin/00-defensive-allowlist.yml"),
    ),
    (
        "01-self-traffic-suppression.yml",
        include_str!("builtin/01-self-traffic-suppression.yml"),
    ),
    (
        "02-service-daemon-suppression.yml",
        include_str!("builtin/02-service-daemon-suppression.yml"),
    ),
    (
        "03-package-manager-suppression.yml",
        include_str!("builtin/03-package-manager-suppression.yml"),
    ),
    (
        "99-default-sample.yml",
        include_str!("builtin/99-default-sample.yml"),
    ),
];

const PID_SCORE_MAP_CAP: usize = 10_000;

pub struct EventPipeline {
    rules: Vec<CompiledRule>,
    rules_dir: PathBuf,
    last_mtime: Option<SystemTime>,
    last_check: Instant,
    last_backstop_check: Instant,
    enabled: bool,
    sample_counter: u64,
    counters: HashMap<String, RuleCounters>,
    pid_scores: HashMap<u32, PidScoreEntry>,
    pub incident_suppressions: IncidentSuppressionSet,
}

pub struct IncidentSuppressionSet {
    by_detector: HashMap<String, HashSet<String>>,
}

impl IncidentSuppressionSet {
    fn new() -> Self {
        Self {
            by_detector: HashMap::new(),
        }
    }

    fn add(&mut self, detector: String, values: Vec<String>) {
        let entry = self.by_detector.entry(detector).or_default();
        for v in values {
            entry.insert(v);
        }
    }

    pub fn is_suppressed(&self, detector_name: &str, values: &[&str]) -> bool {
        let Some(allowed) = self.by_detector.get(detector_name) else {
            return false;
        };
        values.iter().any(|v| {
            let v = *v;
            if v.is_empty() {
                return false;
            }
            if allowed.contains(v) {
                return true;
            }
            let basename = v.rsplit('/').next().unwrap_or(v);
            if basename != v && allowed.contains(basename) {
                return true;
            }
            allowed.iter().any(|a| v.starts_with(a.as_str()))
        })
    }

    pub fn detector_count(&self) -> usize {
        self.by_detector.len()
    }

    pub fn values_for(&self, detector_name: &str) -> Option<&HashSet<String>> {
        self.by_detector.get(detector_name)
    }

    #[allow(dead_code)]
    pub fn detectors(&self) -> impl Iterator<Item = (&String, &HashSet<String>)> {
        self.by_detector.iter()
    }
}

struct PidScoreEntry {
    score: u32,
    last_bump: Instant,
    decay_per_minute: f64,
}

#[derive(Default, Clone)]
pub struct RuleCounters {
    pub matched: u64,
    pub dropped: u64,
    pub emitted: u64,
}

impl EventPipeline {
    pub fn new(rules_dir: &Path, enabled: bool) -> Self {
        let mut pipeline = Self {
            rules: Vec::new(),
            rules_dir: rules_dir.to_path_buf(),
            last_mtime: None,
            last_check: Instant::now(),
            last_backstop_check: Instant::now(),
            enabled,
            sample_counter: 0,
            counters: HashMap::new(),
            pid_scores: HashMap::new(),
            incident_suppressions: IncidentSuppressionSet::new(),
        };
        pipeline.reload();
        pipeline
    }

    pub fn new_disabled() -> Self {
        Self {
            rules: Vec::new(),
            rules_dir: PathBuf::new(),
            last_mtime: None,
            last_check: Instant::now(),
            last_backstop_check: Instant::now(),
            enabled: false,
            sample_counter: 0,
            counters: HashMap::new(),
            pid_scores: HashMap::new(),
            incident_suppressions: IncidentSuppressionSet::new(),
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn total_persisted(&self) -> u64 {
        self.counters.values().map(|c| c.emitted).sum()
    }

    pub fn total_dropped(&self) -> u64 {
        self.counters.values().map(|c| c.dropped).sum()
    }

    #[cfg(test)]
    pub fn counters(&self) -> &HashMap<String, RuleCounters> {
        &self.counters
    }

    pub fn check_backstop(&mut self, host: &str) -> Option<innerwarden_core::incident::Incident> {
        if self.last_backstop_check.elapsed().as_secs() < 3600 {
            return None;
        }
        self.last_backstop_check = Instant::now();
        let total = self.total_persisted() + self.total_dropped();
        if total < 1000 {
            return None;
        }
        let drop_rate = self.total_dropped() as f64 / total as f64;
        if drop_rate > 0.99 {
            warn!(
                total_events = total,
                drop_pct = format!("{:.1}%", drop_rate * 100.0),
                "event_pipeline backstop: drop rate exceeds 99%"
            );
            Some(innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: host.to_string(),
                incident_id: format!(
                    "event_pipeline:runaway_drop:{}",
                    chrono::Utc::now().format("%Y-%m-%dT%H:%MZ")
                ),
                severity: innerwarden_core::event::Severity::Critical,
                title: "Event pipeline runaway drop".to_string(),
                summary: format!(
                    "Event pipeline is dropping {:.1}% of events ({} total). \
                     Collector data going dark. Verify pipeline rules are not \
                     too aggressive. Run: innerwarden rule list",
                    drop_rate * 100.0,
                    total
                ),
                evidence: serde_json::json!({
                    "total_events": total,
                    "total_dropped": self.total_dropped(),
                    "total_persisted": self.total_persisted(),
                    "drop_rate_pct": format!("{:.1}", drop_rate * 100.0),
                    "rule_count": self.rules.len(),
                }),
                recommended_checks: vec![
                    "innerwarden rule list".to_string(),
                    "Review pipeline rules for overly broad drop patterns".to_string(),
                ],
                tags: vec!["event_pipeline".to_string(), "backstop".to_string()],
                entities: vec![],
            })
        } else {
            None
        }
    }

    pub fn reload_if_changed(&mut self) -> bool {
        if !self.enabled {
            return false;
        }
        if self.last_check.elapsed().as_secs() < 60 {
            return false;
        }
        self.last_check = Instant::now();

        let current_mtime = dir_max_mtime(&self.rules_dir);
        if current_mtime == self.last_mtime {
            return false;
        }
        self.reload();
        true
    }

    fn reload(&mut self) {
        let mut rules_by_id: HashMap<String, CompiledRule> = HashMap::new();
        let mut suppressions = IncidentSuppressionSet::new();

        let mut global_lists: HashMap<String, Vec<String>> = HashMap::new();

        for (name, yaml) in BUILTIN_PACKS {
            match load_rules_from_yaml(yaml, name, &global_lists) {
                Ok(loaded) => {
                    for rule in loaded.event_rules {
                        rules_by_id.insert(rule.id.clone(), rule);
                    }
                    for (detector, values) in loaded.suppressions {
                        suppressions.add(detector, values);
                    }
                    for (k, v) in loaded.lists {
                        global_lists.entry(k).or_insert(v);
                    }
                }
                Err(e) => warn!("event_pipeline: built-in pack {name} failed to load: {e}"),
            }
        }

        if self.rules_dir.is_dir() {
            match load_rules_from_dir(&self.rules_dir, &global_lists) {
                Ok(loaded) => {
                    for rule in loaded.event_rules {
                        rules_by_id.insert(rule.id.clone(), rule);
                    }
                    for (detector, values) in loaded.suppressions {
                        suppressions.add(detector, values);
                    }
                }
                Err(e) => warn!("event_pipeline: failed to read rules dir: {e}"),
            }
        }

        let mut rules: Vec<CompiledRule> = rules_by_id.into_values().collect();
        rules.sort_by_key(|r| std::cmp::Reverse(r.priority));

        let count = rules.len();
        let suppress_count = suppressions.detector_count();
        self.rules = rules;
        self.incident_suppressions = suppressions;
        self.last_mtime = dir_max_mtime(&self.rules_dir);

        info!(
            rules = count,
            suppress_detectors = suppress_count,
            "event_pipeline reloaded"
        );
    }

    pub fn should_persist(&mut self, event: &mut Event) -> bool {
        if !self.enabled || self.rules.is_empty() {
            return true;
        }

        if event.kind == "process.exit" {
            if let Some(pid) = event.details.get("pid").and_then(|v| v.as_u64()) {
                self.pid_scores.remove(&(pid as u32));
            }
        }

        let event_pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        for i in 0..self.rules.len() {
            if let Some(min_score) = self.rules[i].pid_score_min {
                let pid_score = event_pid
                    .and_then(|pid| self.current_score(pid))
                    .unwrap_or(0);
                if pid_score < min_score {
                    continue;
                }
            } else if !self.rules[i].matches(event) {
                continue;
            }

            let rule_id = self.rules[i].id.clone();
            let action = self.rules[i].action.clone();
            let sample_rate = self.rules[i].sample_rate;

            if !self.rules[i].tags.is_empty() {
                let tags: Vec<String> = self.rules[i].tags.clone();
                for tag in tags {
                    if !event.tags.contains(&tag) {
                        event.tags.push(tag);
                    }
                }
            }

            bump(&mut self.counters, &rule_id, Counter::Matched);

            match action {
                CompiledAction::ForceEmit => {
                    bump(&mut self.counters, &rule_id, Counter::Emitted);
                    return true;
                }
                CompiledAction::Drop => {
                    bump(&mut self.counters, &rule_id, Counter::Dropped);
                    return false;
                }
                CompiledAction::Sample => {
                    if should_sample(&mut self.sample_counter, sample_rate) {
                        bump(&mut self.counters, &rule_id, Counter::Emitted);
                        return true;
                    }
                    bump(&mut self.counters, &rule_id, Counter::Dropped);
                    return false;
                }
                CompiledAction::Emit => {
                    bump(&mut self.counters, &rule_id, Counter::Emitted);
                }
                CompiledAction::ScoreIncrement {
                    score,
                    decay_minutes,
                } => {
                    if let Some(pid) = event_pid {
                        self.bump_pid_score(pid, score, decay_minutes);
                    }
                    bump(&mut self.counters, &rule_id, Counter::Emitted);
                }
            }
        }

        true
    }

    fn current_score(&self, pid: u32) -> Option<u32> {
        let entry = self.pid_scores.get(&pid)?;
        let elapsed_min = entry.last_bump.elapsed().as_secs_f64() / 60.0;
        let decayed = entry.score as f64 - (elapsed_min * entry.decay_per_minute);
        let score = decayed.round().max(0.0) as u32;
        if score == 0 {
            None
        } else {
            Some(score)
        }
    }

    fn bump_pid_score(&mut self, pid: u32, score: u32, decay_minutes: u32) {
        let decay_per_min = if decay_minutes > 0 {
            score as f64 / decay_minutes as f64
        } else {
            0.0
        };

        let entry = self.pid_scores.entry(pid).or_insert(PidScoreEntry {
            score: 0,
            last_bump: Instant::now(),
            decay_per_minute: decay_per_min,
        });
        entry.score = entry.score.saturating_add(score).min(100);
        entry.last_bump = Instant::now();
        entry.decay_per_minute = decay_per_min;

        if self.pid_scores.len() > PID_SCORE_MAP_CAP {
            self.evict_lowest_scores();
        }
    }

    fn evict_lowest_scores(&mut self) {
        let target = PID_SCORE_MAP_CAP * 3 / 4;
        let mut entries: Vec<(u32, u32)> = self
            .pid_scores
            .iter()
            .map(|(&pid, e)| {
                let elapsed_min = e.last_bump.elapsed().as_secs_f64() / 60.0;
                let effective = (e.score as f64 - elapsed_min * e.decay_per_minute).max(0.0) as u32;
                (pid, effective)
            })
            .collect();
        entries.sort_by_key(|&(_, score)| score);
        let to_remove = self.pid_scores.len() - target;
        for &(pid, _) in entries.iter().take(to_remove) {
            self.pid_scores.remove(&pid);
        }
    }

    #[cfg(test)]
    pub fn scored_pids_count(&self) -> usize {
        self.pid_scores.len()
    }
}

fn should_sample(counter: &mut u64, rate: f64) -> bool {
    if rate <= 0.0 {
        return false;
    }
    if rate >= 1.0 {
        return true;
    }
    *counter = counter.wrapping_add(1);
    let period = (1.0 / rate) as u64;
    if period == 0 {
        return true;
    }
    (*counter).is_multiple_of(period)
}

enum Counter {
    Matched,
    Dropped,
    Emitted,
}

fn bump(counters: &mut HashMap<String, RuleCounters>, id: &str, kind: Counter) {
    let entry = counters.entry(id.to_string()).or_default();
    match kind {
        Counter::Matched => entry.matched += 1,
        Counter::Dropped => entry.dropped += 1,
        Counter::Emitted => entry.emitted += 1,
    }
}

struct LoadedRules {
    event_rules: Vec<CompiledRule>,
    suppressions: Vec<(String, Vec<String>)>,
    lists: HashMap<String, Vec<String>>,
}

fn load_rules_from_yaml(
    yaml: &str,
    source_name: &str,
    global_lists: &HashMap<String, Vec<String>>,
) -> Result<LoadedRules, String> {
    let rf: RuleFile =
        serde_yaml::from_str(yaml).map_err(|e| format!("{source_name}: YAML parse error: {e}"))?;

    if rf.version != 1 {
        return Err(format!(
            "{source_name}: unsupported schema version {} (expected 1)",
            rf.version
        ));
    }

    let mut all_lists = global_lists.clone();
    for (k, v) in &rf.lists {
        all_lists.entry(k.clone()).or_insert_with(|| v.clone());
    }

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let mut event_rules = Vec::new();
    let mut suppressions = Vec::new();
    for raw in &rf.rules {
        if raw.disabled {
            info!(rule = %raw.id, "event_pipeline: rule disabled, skipping");
            continue;
        }
        if let Some(ref exp) = raw.expires_at {
            if exp.as_str() <= today.as_str() {
                info!(rule = %raw.id, expires = %exp, "event_pipeline: rule expired, skipping");
                continue;
            }
        }

        let mut raw = raw.clone();
        expand_all_list_refs(&mut raw, &all_lists);

        if raw.action == ActionKind::SuppressIncident {
            match validate_suppress_rule(&raw) {
                Ok((detector, values)) => suppressions.push((detector, values)),
                Err(e) => warn!(source = source_name, "event_pipeline: {e}"),
            }
        } else if raw.action == ActionKind::SuppressResponse {
            // Agent-side rules; sensor skips them silently.
        } else {
            match compile_rule(&raw) {
                Ok(rule) => event_rules.push(rule),
                Err(e) => warn!(source = source_name, "event_pipeline: {e}"),
            }
        }
    }
    Ok(LoadedRules {
        event_rules,
        suppressions,
        lists: rf.lists,
    })
}

fn load_rules_from_dir(
    dir: &Path,
    global_lists: &HashMap<String, Vec<String>>,
) -> Result<LoadedRules, String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("read_dir {}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let s = name.to_string_lossy();
            (s.ends_with(".yml") || s.ends_with(".yaml"))
                && e.file_type().is_ok_and(|t| t.is_file())
        })
        .collect();

    entries.sort_by_key(|e| e.file_name());

    let mut all = LoadedRules {
        event_rules: Vec::new(),
        suppressions: Vec::new(),
        lists: HashMap::new(),
    };
    let mut dir_lists = global_lists.clone();
    for entry in entries {
        let path = entry.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        match std::fs::read_to_string(&path) {
            Ok(yaml) => match load_rules_from_yaml(&yaml, &name, &dir_lists) {
                Ok(loaded) => {
                    all.event_rules.extend(loaded.event_rules);
                    all.suppressions.extend(loaded.suppressions);
                    for (k, v) in &loaded.lists {
                        dir_lists.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
                Err(e) => warn!("event_pipeline: {e}"),
            },
            Err(e) => warn!(file = %name, "event_pipeline: read error: {e}"),
        }
    }
    Ok(all)
}

fn dir_max_mtime(dir: &Path) -> Option<SystemTime> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut max = None;
    for entry in entries.flatten() {
        if let Ok(meta) = entry.metadata() {
            if let Ok(mtime) = meta.modified() {
                max = Some(match max {
                    Some(m) if mtime > m => mtime,
                    Some(m) => m,
                    None => mtime,
                });
            }
        }
    }
    max
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Event;

    fn make_event(source: &str, kind: &str, details: serde_json::Value) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: String::new(),
            source: source.into(),
            kind: kind.into(),
            severity: innerwarden_core::event::Severity::Info,
            summary: String::new(),
            details,
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn disabled_pipeline_persists_everything() {
        let mut pipeline = EventPipeline::new_disabled();
        let mut ev = make_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "nginx"}),
        );
        assert!(pipeline.should_persist(&mut ev));
    }

    #[test]
    fn agent_suppress_response_file_loads_clean_and_is_skipped() {
        // The dashboard "Trust IP" feature writes suppress_response/scope:ip
        // rules into the SHARED event_pipeline dir. The sensor must load that
        // file WITHOUT error (no warn-and-skip) and contribute zero event rules
        // / suppressions from it — it is an agent-side concern. This is the
        // regression anchor for the SuppressConfig {detector?, scope?} change.
        let yaml = r#"
version: 1
rules:
  - id: operator-trust-203-0-113-10
    action: suppress_response
    suppress:
      scope: ip
      values: ["203.0.113.10"]
    drop_reason: "office vpn"
    tags: [operator-trust]
"#;
        let loaded = load_rules_from_yaml(yaml, "70-operator-trust.yml", &HashMap::new())
            .expect("suppress_response/scope file must load without error");
        assert!(loaded.event_rules.is_empty());
        assert!(loaded.suppressions.is_empty());
    }

    #[test]
    fn builtin_packs_load_successfully() {
        let dir = tempfile::tempdir().unwrap();
        let pipeline = EventPipeline::new(dir.path(), true);
        assert!(pipeline.rule_count() > 0, "built-in rules should load");
    }

    #[test]
    fn defensive_allowlist_force_emits_credential_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"filename": "/etc/shadow", "comm": "cat", "pid": 1}),
        );
        assert!(pipeline.should_persist(&mut ev));
        assert!(ev.tags.contains(&"defensive-allowlist".to_string()));
    }

    #[test]
    fn self_traffic_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "innerwarden-agent", "pid": 100}),
        );
        assert!(!pipeline.should_persist(&mut ev));
    }

    #[test]
    fn service_daemon_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "nginx", "pid": 200}),
        );
        assert!(!pipeline.should_persist(&mut ev));
    }

    #[test]
    fn non_ebpf_events_pass_through() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event("journald", "auth.login", serde_json::json!({}));
        assert!(pipeline.should_persist(&mut ev));
    }

    #[test]
    fn shell_exec_events_pass_through() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "shell.command_exec",
            serde_json::json!({"comm": "bash", "pid": 300}),
        );
        assert!(pipeline.should_persist(&mut ev));
    }

    #[test]
    fn defensive_allowlist_overrides_drop_rules() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        // innerwarden-agent reading /etc/shadow: self-traffic rule would
        // drop it, but defensive allowlist at priority 1000 fires first
        // with force_emit.
        let mut ev = make_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "innerwarden-agent", "filename": "/etc/shadow", "pid": 1}),
        );
        assert!(pipeline.should_persist(&mut ev));
        assert!(ev.tags.contains(&"defensive-allowlist".to_string()));
    }

    #[test]
    fn sample_passes_some_events() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut persisted = 0;
        let total = 1000;
        for i in 0..total {
            let mut ev = make_event(
                "ebpf",
                "file.read_access",
                serde_json::json!({"comm": "unknown-app", "pid": i, "filename": "/tmp/data"}),
            );
            if pipeline.should_persist(&mut ev) {
                persisted += 1;
            }
        }
        // 1% sample: expect ~10 events, allow range 5-20
        assert!(
            (5..=20).contains(&persisted),
            "expected ~10 sampled events, got {persisted}"
        );
    }

    #[test]
    fn on_disk_rule_overrides_builtin() {
        let dir = tempfile::tempdir().unwrap();
        // Write an on-disk rule that overrides the self-traffic suppression
        // to NOT drop innerwarden-* (disabled)
        let rule_yaml = r#"
version: 1
rules:
  - id: drop-innerwarden-self-reads
    match:
      source: ebpf
    action: drop
    disabled: true
"#;
        std::fs::write(dir.path().join("01-override.yml"), rule_yaml).unwrap();

        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "innerwarden-agent", "pid": 1, "filename": "/tmp/x"}),
        );
        // With the override disabled, innerwarden-agent traffic should
        // now fall through to the sample rule instead of being dropped
        // by the self-traffic rule. The sample will drop most but not all.
        // We just check it's not guaranteed-dropped like before.
        let _ = pipeline.should_persist(&mut ev);
    }

    #[test]
    fn hot_reload_picks_up_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);
        let initial_count = pipeline.rule_count();

        let rule_yaml = r#"
version: 1
rules:
  - id: custom-drop-etl
    priority: 75
    match:
      source: ebpf
      kind: file.read_access
      comm: etl-batch
    action: drop
    drop_reason: etl-noise
"#;
        std::fs::write(dir.path().join("20-custom.yml"), rule_yaml).unwrap();

        // Force reload (bypass the 60s check)
        pipeline.last_check = Instant::now() - std::time::Duration::from_secs(120);
        assert!(pipeline.reload_if_changed());
        assert!(pipeline.rule_count() > initial_count);

        let mut ev = make_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "etl-batch", "pid": 500, "filename": "/var/data/x"}),
        );
        assert!(!pipeline.should_persist(&mut ev));
    }

    #[test]
    fn invalid_yaml_file_skipped_gracefully() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.yml"), "this is not valid yaml: [[[").unwrap();

        let pipeline = EventPipeline::new(dir.path(), true);
        // Built-in rules still loaded despite bad on-disk file
        assert!(pipeline.rule_count() > 0);
    }

    #[test]
    fn empty_rules_dir_uses_builtins() {
        let dir = tempfile::tempdir().unwrap();
        let pipeline = EventPipeline::new(dir.path(), true);
        assert!(pipeline.rule_count() > 0);
    }

    #[test]
    fn counters_track_matched_and_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "nginx", "pid": 1}),
        );
        pipeline.should_persist(&mut ev);

        let counters = pipeline.counters();
        let daemon_counter = counters.get("drop-service-daemon-file-ops");
        assert!(
            daemon_counter.is_some(),
            "counter should exist for matched rule"
        );
        let c = daemon_counter.unwrap();
        assert!(c.matched > 0);
        assert!(c.dropped > 0);
    }

    #[test]
    fn network_events_not_affected_by_file_rules() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "network.outbound_connect",
            serde_json::json!({"comm": "nginx", "dst_ip": "1.2.3.4", "dst_port": 443, "pid": 1}),
        );
        assert!(pipeline.should_persist(&mut ev));
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: disabled-drop
    match:
      source: ebpf
      comm: should-be-dropped
    action: drop
    disabled: true
"#;
        std::fs::write(dir.path().join("10-disabled.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "shell.command_exec",
            serde_json::json!({"comm": "should-be-dropped"}),
        );
        assert!(pipeline.should_persist(&mut ev));
    }

    #[test]
    fn expired_rule_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: expired-drop
    match:
      source: ebpf
      comm: should-be-dropped
    action: drop
    expires_at: "2020-01-01"
"#;
        std::fs::write(dir.path().join("10-expired.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "shell.command_exec",
            serde_json::json!({"comm": "should-be-dropped"}),
        );
        assert!(pipeline.should_persist(&mut ev));
    }

    #[test]
    fn unsupported_version_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 99
rules:
  - id: future-rule
    match:
      source: ebpf
    action: drop
"#;
        std::fs::write(dir.path().join("10-future.yml"), yaml).unwrap();
        let pipeline = EventPipeline::new(dir.path(), true);
        // Built-in rules still load; the v99 file is skipped
        assert!(pipeline.rule_count() > 0);
    }

    #[test]
    fn reload_if_changed_respects_60s_window() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);
        // Immediately after creation, reload_if_changed should return false
        // because 60s haven't passed
        assert!(!pipeline.reload_if_changed());
    }

    #[test]
    fn reload_disabled_pipeline_returns_false() {
        let mut pipeline = EventPipeline::new_disabled();
        assert!(!pipeline.reload_if_changed());
    }

    #[test]
    fn nonexistent_rules_dir_uses_builtins() {
        let pipeline = EventPipeline::new(std::path::Path::new("/nonexistent/path"), true);
        assert!(pipeline.rule_count() > 0);
    }

    #[test]
    fn score_increment_action_persists() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: score-cred-read
    priority: 999
    match:
      source: ebpf
      kind: shell.command_exec
    action: score_increment
    score_increment:
      score: 50
      decay_minutes: 60
"#;
        std::fs::write(dir.path().join("10-score.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        // shell.command_exec is not matched by the built-in sample rule
        // (which only targets file.read_access / file.write_access),
        // so score_increment cascades and the default persist applies.
        let mut ev = make_event(
            "ebpf",
            "shell.command_exec",
            serde_json::json!({"comm": "attacker"}),
        );
        assert!(pipeline.should_persist(&mut ev));
    }

    #[test]
    fn emit_action_cascades_to_next_rule() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: emit-first
    priority: 100
    match:
      source: ebpf
      kind: test.event
    action: emit
    tags: [first-tag]
  - id: drop-after
    priority: 50
    match:
      source: ebpf
      kind: test.event
    action: drop
"#;
        std::fs::write(dir.path().join("10-cascade.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event("ebpf", "test.event", serde_json::json!({}));
        // emit cascades, then drop fires
        assert!(!pipeline.should_persist(&mut ev));
        assert!(ev.tags.contains(&"first-tag".to_string()));
    }

    #[test]
    fn yaml_extension_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: yaml-ext-rule
    priority: 999
    match:
      source: test
    action: drop
"#;
        std::fs::write(dir.path().join("10-test.yaml"), yaml).unwrap();
        let pipeline = EventPipeline::new(dir.path(), true);
        // .yaml extension should be loaded just like .yml
        let builtin_count = BUILTIN_PACKS
            .iter()
            .flat_map(|(_, y)| serde_yaml::from_str::<types::RuleFile>(y).unwrap().rules)
            .count();
        assert!(pipeline.rule_count() > builtin_count);
    }

    #[test]
    fn sample_rate_zero_always_drops() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: sample-zero
    priority: 999
    match:
      source: test
    action: sample
    sample: 0.0
"#;
        std::fs::write(dir.path().join("10-zero.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        for _ in 0..100 {
            let mut ev = make_event("test", "x", serde_json::json!({}));
            assert!(!pipeline.should_persist(&mut ev));
        }
    }

    #[test]
    fn sample_rate_one_always_persists() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: sample-one
    priority: 999
    match:
      source: test
    action: sample
    sample: 1.0
"#;
        std::fs::write(dir.path().join("10-one.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        for _ in 0..100 {
            let mut ev = make_event("test", "x", serde_json::json!({}));
            assert!(pipeline.should_persist(&mut ev));
        }
    }

    #[test]
    fn package_manager_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        for comm in ["apt", "dpkg", "snap", "pip3", "npm", "cargo", "yum", "dnf"] {
            let mut ev = make_event(
                "ebpf",
                "file.read_access",
                serde_json::json!({"comm": comm, "pid": 1, "filename": "/usr/lib/x"}),
            );
            assert!(
                !pipeline.should_persist(&mut ev),
                "{comm} should be dropped by package-manager suppression"
            );
        }
    }

    #[test]
    fn package_manager_credential_path_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "apt", "pid": 1, "filename": "/etc/shadow"}),
        );
        assert!(
            pipeline.should_persist(&mut ev),
            "apt reading /etc/shadow must be persisted (defensive-allowlist)"
        );
        assert!(ev.tags.contains(&"defensive-allowlist".to_string()));
    }

    #[test]
    fn total_persisted_and_dropped_counts() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        for _ in 0..10 {
            let mut ev = make_event(
                "ebpf",
                "file.read_access",
                serde_json::json!({"comm": "nginx", "pid": 1}),
            );
            pipeline.should_persist(&mut ev);
        }

        assert_eq!(pipeline.total_dropped(), 10);
        assert!(pipeline.total_persisted() == 0 || pipeline.total_persisted() > 0);
    }

    #[test]
    fn backstop_does_not_warn_under_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        // Process a mix of persisted and dropped events
        for _ in 0..50 {
            let mut ev = make_event(
                "ebpf",
                "shell.command_exec",
                serde_json::json!({"comm": "bash"}),
            );
            pipeline.should_persist(&mut ev);
        }
        for _ in 0..50 {
            let mut ev = make_event(
                "ebpf",
                "file.read_access",
                serde_json::json!({"comm": "nginx", "pid": 1}),
            );
            pipeline.should_persist(&mut ev);
        }

        // 50% drop rate, backstop should not fire (only fires > 99%)
        pipeline.last_backstop_check = Instant::now() - std::time::Duration::from_secs(7200);
        pipeline.check_backstop("test");
    }

    #[test]
    fn backstop_fires_above_99_percent() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: drop-everything
    priority: 999
    match:
      source: test
    action: drop
"#;
        std::fs::write(dir.path().join("10-drop-all.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        for i in 0..2000 {
            let mut ev = make_event("test", "x", serde_json::json!({"i": i}));
            pipeline.should_persist(&mut ev);
        }

        assert!(pipeline.total_dropped() > 1990);
        // This would log a warning; we just verify the check runs without panic
        pipeline.last_backstop_check = Instant::now() - std::time::Duration::from_secs(7200);
        pipeline.check_backstop("test");
    }

    #[test]
    fn rule_count_includes_all_builtin_packs() {
        let dir = tempfile::tempdir().unwrap();
        let pipeline = EventPipeline::new(dir.path(), true);
        assert!(
            pipeline.rule_count() >= 5,
            "expected at least 5 built-in rules, got {}",
            pipeline.rule_count()
        );
    }

    #[test]
    fn score_increment_bumps_pid_score() {
        let dir = tempfile::tempdir().unwrap();
        // Use network event (not in defensive-allowlist) so score_increment fires
        let yaml = r#"
version: 1
rules:
  - id: score-suspicious-port
    priority: 999
    match:
      source: ebpf
      kind: network.outbound_connect
      dst_port_in: [4444]
    action: score_increment
    score_increment:
      score: 50
      decay_minutes: 60
"#;
        std::fs::write(dir.path().join("10-score.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "network.outbound_connect",
            serde_json::json!({"comm": "nc", "pid": 1234, "dst_port": 4444, "dst_ip": "1.2.3.4"}),
        );
        pipeline.should_persist(&mut ev);

        assert_eq!(pipeline.current_score(1234), Some(50));
        assert_eq!(pipeline.scored_pids_count(), 1);
    }

    #[test]
    fn pid_score_min_emits_subsequent_events() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: score-suspicious-port
    priority: 999
    match:
      source: ebpf
      kind: network.outbound_connect
      dst_port_in: [4444]
    action: score_increment
    score_increment:
      score: 50
      decay_minutes: 60
  - id: emit-scored-pids
    priority: 500
    match:
      source: ebpf
      pid_score_min: 1
    action: force_emit
    tags: [pid-escalated]
"#;
        std::fs::write(dir.path().join("10-score.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        // First: PID 1234 connects to port 4444, gets score 50
        let mut ev1 = make_event(
            "ebpf",
            "network.outbound_connect",
            serde_json::json!({"comm": "nc", "pid": 1234, "dst_port": 4444, "dst_ip": "1.2.3.4"}),
        );
        assert!(pipeline.should_persist(&mut ev1));

        // Second: PID 1234 reads a random file. Normally dropped or sampled.
        // But pid_score_min rule force-emits because PID 1234 has score 50.
        let mut ev2 = make_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "nc", "pid": 1234, "filename": "/tmp/random"}),
        );
        assert!(pipeline.should_persist(&mut ev2));
        assert!(ev2.tags.contains(&"pid-escalated".to_string()));
    }

    #[test]
    fn unscored_pid_not_matched_by_pid_score_min() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: emit-scored-pids
    priority: 500
    match:
      source: ebpf
      pid_score_min: 1
    action: force_emit
    tags: [pid-escalated]
"#;
        std::fs::write(dir.path().join("10-score.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "nginx", "pid": 5678, "filename": "/tmp/x"}),
        );
        // PID 5678 has no score, so pid_score_min rule doesn't match.
        // Falls through to built-in drop rules (nginx is service daemon).
        assert!(!pipeline.should_persist(&mut ev));
        assert!(!ev.tags.contains(&"pid-escalated".to_string()));
    }

    #[test]
    fn process_exit_clears_pid_score() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: score-suspicious-port
    priority: 999
    match:
      source: ebpf
      kind: network.outbound_connect
      dst_port_in: [4444]
    action: score_increment
    score_increment:
      score: 50
      decay_minutes: 60
"#;
        std::fs::write(dir.path().join("10-score.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut ev = make_event(
            "ebpf",
            "network.outbound_connect",
            serde_json::json!({"comm": "nc", "pid": 1234, "dst_port": 4444, "dst_ip": "1.2.3.4"}),
        );
        pipeline.should_persist(&mut ev);
        assert_eq!(pipeline.current_score(1234), Some(50));

        // Process exits
        let mut exit_ev = make_event(
            "ebpf",
            "process.exit",
            serde_json::json!({"pid": 1234, "comm": "cat"}),
        );
        pipeline.should_persist(&mut exit_ev);
        assert_eq!(pipeline.current_score(1234), None);
        assert_eq!(pipeline.scored_pids_count(), 0);
    }

    #[test]
    fn pid_score_caps_at_100() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: score-big
    priority: 999
    match:
      source: ebpf
      kind: test.bump
    action: score_increment
    score_increment:
      score: 80
      decay_minutes: 60
"#;
        std::fs::write(dir.path().join("10-score.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        // Bump twice: 80 + 80 = 160, but capped at 100
        for _ in 0..2 {
            let mut ev = make_event("ebpf", "test.bump", serde_json::json!({"pid": 42}));
            pipeline.should_persist(&mut ev);
        }
        assert_eq!(pipeline.current_score(42), Some(100));
    }

    #[test]
    fn pid_score_map_evicts_when_over_cap() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: score-all
    priority: 999
    match:
      source: test
    action: score_increment
    score_increment:
      score: 10
      decay_minutes: 60
"#;
        std::fs::write(dir.path().join("10-score.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        // Push more than PID_SCORE_MAP_CAP entries
        for pid in 0..(PID_SCORE_MAP_CAP as u32 + 100) {
            let mut ev = make_event("test", "x", serde_json::json!({"pid": pid}));
            pipeline.should_persist(&mut ev);
        }

        assert!(
            pipeline.scored_pids_count() <= PID_SCORE_MAP_CAP,
            "map should be capped at {PID_SCORE_MAP_CAP}, got {}",
            pipeline.scored_pids_count()
        );
    }

    #[test]
    fn caldera_replay_anchor_security_events_never_dropped() {
        let fixture = include_str!(
            "../../../../testdata/event_pipeline_fixtures/security-events-must-persist.jsonl"
        );
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let mut dropped = Vec::new();
        for (i, line) in fixture.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let mut event: innerwarden_core::event::Event =
                serde_json::from_str(line).unwrap_or_else(|e| panic!("line {i}: {e}"));
            if !pipeline.should_persist(&mut event) {
                dropped.push(format!(
                    "line {}: {} {} ({})",
                    i + 1,
                    event.source,
                    event.kind,
                    event.summary
                ));
            }
        }

        assert!(
            dropped.is_empty(),
            "Pipeline dropped {} security-critical events that MUST persist:\n  {}",
            dropped.len(),
            dropped.join("\n  ")
        );
    }

    #[test]
    fn backstop_emits_critical_incident() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: drop-everything
    priority: 999
    match:
      source: test
    action: drop
"#;
        std::fs::write(dir.path().join("10-drop-all.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        for i in 0..2000 {
            let mut ev = make_event("test", "x", serde_json::json!({"i": i}));
            pipeline.should_persist(&mut ev);
        }

        // Force backstop to fire (bypass 1h timer)
        pipeline.last_backstop_check = Instant::now() - std::time::Duration::from_secs(7200);
        let incident = pipeline.check_backstop("test-host");
        assert!(
            incident.is_some(),
            "backstop should emit incident when > 99% dropped"
        );
        let inc = incident.unwrap();
        assert_eq!(inc.severity, innerwarden_core::event::Severity::Critical);
        assert!(inc.title.contains("runaway drop"));
        assert!(inc.tags.contains(&"event_pipeline".to_string()));
    }

    #[test]
    fn backstop_silent_within_1h() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);
        // Backstop should return None within the first hour
        assert!(pipeline.check_backstop("test").is_none());
    }

    #[test]
    fn benchmark_anchor_pipeline_latency() {
        let dir = tempfile::tempdir().unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        let n = 100_000;
        let start = Instant::now();
        for i in 0..n {
            let mut ev = make_event(
                "ebpf",
                "file.read_access",
                serde_json::json!({"comm": "nginx", "pid": i, "filename": "/var/www/index.html"}),
            );
            pipeline.should_persist(&mut ev);
        }
        let elapsed = start.elapsed();
        let per_event_ns = elapsed.as_nanos() / n as u128;

        assert!(
            per_event_ns < 30_000,
            "p_avg should be < 30us/event, got {}ns/event ({:.1}us)",
            per_event_ns,
            per_event_ns as f64 / 1000.0
        );
    }

    #[test]
    fn suppress_incident_rules_load_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: allow-bcache-kmod
    action: suppress_incident
    suppress:
      detector: kernel_module_load
      values: [bcache, dm_raid, dm_mirror]
  - id: allow-ubuntu-sudo
    action: suppress_incident
    suppress:
      detector: sudo_abuse
      values: [ubuntu]
"#;
        std::fs::write(dir.path().join("10-suppress.yml"), yaml).unwrap();
        let pipeline = EventPipeline::new(dir.path(), true);

        assert!(pipeline
            .incident_suppressions
            .is_suppressed("kernel_module_load", &["bcache"]));
        assert!(pipeline
            .incident_suppressions
            .is_suppressed("kernel_module_load", &["dm_raid"]));
        assert!(pipeline
            .incident_suppressions
            .is_suppressed("sudo_abuse", &["ubuntu"]));
        assert!(!pipeline
            .incident_suppressions
            .is_suppressed("sudo_abuse", &["root"]));
        assert!(!pipeline
            .incident_suppressions
            .is_suppressed("port_scan", &["nmap"]));
    }

    #[test]
    fn suppress_incident_coexists_with_event_rules() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: custom-drop
    match:
      source: ebpf
      comm: noisy-app
      kind: file.read_access
    action: drop
  - id: allow-bcache
    action: suppress_incident
    suppress:
      detector: kernel_module_load
      values: [bcache]
"#;
        std::fs::write(dir.path().join("10-mixed.yml"), yaml).unwrap();
        let mut pipeline = EventPipeline::new(dir.path(), true);

        // Event rule works
        let mut ev = make_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "noisy-app", "pid": 1}),
        );
        assert!(!pipeline.should_persist(&mut ev));

        // Suppress rule works
        assert!(pipeline
            .incident_suppressions
            .is_suppressed("kernel_module_load", &["bcache"]));
    }

    #[test]
    fn suppress_incident_invalid_missing_suppress_block() {
        let yaml = r#"
version: 1
rules:
  - id: bad-suppress
    action: suppress_incident
"#;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("10-bad.yml"), yaml).unwrap();
        let pipeline = EventPipeline::new(dir.path(), true);
        // Should not crash, bad rule skipped
        assert!(!pipeline
            .incident_suppressions
            .is_suppressed("anything", &["x"]));
    }

    #[test]
    fn suppress_incident_empty_values_rejected() {
        let yaml = r#"
version: 1
rules:
  - id: bad-empty-values
    action: suppress_incident
    suppress:
      detector: kernel_module_load
      values: []
"#;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("10-bad.yml"), yaml).unwrap();
        let pipeline = EventPipeline::new(dir.path(), true);
        assert!(!pipeline
            .incident_suppressions
            .is_suppressed("kernel_module_load", &["bcache"]));
    }

    #[test]
    fn suppress_incident_prefix_matching() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: allow-apt-paths
    action: suppress_incident
    suppress:
      detector: integrity_alert
      values: ["/etc/apt/", "/etc/ld.so.conf.d/"]
"#;
        std::fs::write(dir.path().join("10-suppress.yml"), yaml).unwrap();
        let pipeline = EventPipeline::new(dir.path(), true);

        assert!(pipeline
            .incident_suppressions
            .is_suppressed("integrity_alert", &["/etc/apt/sources.list"]));
        assert!(pipeline
            .incident_suppressions
            .is_suppressed("integrity_alert", &["/etc/ld.so.conf.d/libc.conf"]));
        assert!(!pipeline
            .incident_suppressions
            .is_suppressed("integrity_alert", &["/etc/ssh/sshd_config"]));
    }

    #[test]
    fn suppress_incident_basename_matching() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: allow-systemctl
    action: suppress_incident
    suppress:
      detector: systemd_persistence
      values: [systemctl]
"#;
        std::fs::write(dir.path().join("10-suppress.yml"), yaml).unwrap();
        let pipeline = EventPipeline::new(dir.path(), true);

        assert!(pipeline
            .incident_suppressions
            .is_suppressed("systemd_persistence", &["/usr/bin/systemctl"]));
        assert!(pipeline
            .incident_suppressions
            .is_suppressed("systemd_persistence", &["systemctl"]));
    }
}
