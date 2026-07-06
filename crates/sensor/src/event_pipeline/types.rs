use std::collections::{HashMap, HashSet};

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// YAML serde types (operator-facing schema)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    pub version: u32,
    #[serde(default)]
    #[allow(dead_code)]
    pub metadata: Option<FileMetadata>,
    #[serde(default)]
    pub lists: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct FileMetadata {
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub last_reviewed: Option<String>,
    #[serde(default)]
    pub source_motivation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    pub id: String,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default, rename = "match")]
    pub match_preds: Option<MatchPredicates>,
    pub action: ActionKind,
    #[serde(default)]
    pub drop_reason: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub sample: Option<f64>,
    #[serde(default)]
    pub score_increment: Option<ScoreIncrementConfig>,
    #[serde(default)]
    pub suppress: Option<SuppressConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressConfig {
    /// Detector name for `suppress_incident` rules (sensor-side). Optional so
    /// that agent-side `suppress_response` rules — which key on `scope`, not a
    /// detector — parse cleanly under `deny_unknown_fields` instead of making
    /// the sensor warn-and-skip the whole file. `validate_suppress_rule`
    /// enforces presence for `suppress_incident`.
    #[serde(default)]
    pub detector: Option<String>,
    /// Scope for agent-side `suppress_response` rules: `"ip"` | `"user"` |
    /// `"process"`. Ignored by the sensor (it skips `suppress_response` rules);
    /// consumed by the agent's `YamlResponseRules`. Present here only so the
    /// sensor's strict schema accepts the shared rule file, hence `dead_code`.
    #[serde(default)]
    #[allow(dead_code)]
    pub scope: Option<String>,
    pub values: Vec<String>,
}

fn default_priority() -> u32 {
    50
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Emit,
    ForceEmit,
    Drop,
    Sample,
    ScoreIncrement,
    SuppressIncident,
    SuppressResponse,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchPredicates {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_in: Option<Vec<String>>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub kind_in: Option<Vec<String>>,
    #[serde(default)]
    pub comm: Option<String>,
    #[serde(default)]
    pub comm_in: Option<Vec<String>>,
    #[serde(default)]
    pub comm_glob: Option<Vec<String>>,
    #[serde(default)]
    pub path_in: Option<Vec<String>>,
    #[serde(default)]
    pub path_glob: Option<Vec<String>>,
    #[serde(default)]
    pub path_prefix: Option<Vec<String>>,
    #[serde(default)]
    pub severity_min: Option<String>,
    #[serde(default)]
    pub uid_in: Option<Vec<u32>>,
    #[serde(default)]
    pub dst_port_in: Option<Vec<u16>>,
    #[serde(default)]
    pub parent_comm_in: Option<Vec<String>>,
    #[serde(default)]
    pub pid_score_min: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreIncrementConfig {
    pub score: u32,
    pub decay_minutes: u32,
}

// ---------------------------------------------------------------------------
// Compiled rule (pre-processed at load time for fast matching)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledAction {
    Emit,
    ForceEmit,
    Drop,
    Sample,
    ScoreIncrement { score: u32, decay_minutes: u32 },
}

#[allow(dead_code)]
impl CompiledAction {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::ForceEmit | Self::Drop | Self::Sample)
    }
}

#[allow(dead_code)]
pub struct CompiledRule {
    pub id: String,
    pub priority: u32,
    pub action: CompiledAction,
    pub sample_rate: f64,
    pub tags: Vec<String>,
    pub drop_reason: Option<String>,

    pub source_exact: Option<String>,
    pub source_set: Option<HashSet<String>>,
    pub kind_exact: Option<String>,
    pub kind_set: Option<HashSet<String>>,
    pub kind_glob: Option<GlobSet>,
    pub comm_exact: Option<String>,
    pub comm_set: Option<HashSet<String>>,
    pub comm_glob: Option<GlobSet>,
    pub path_set: Option<HashSet<String>>,
    pub path_glob: Option<GlobSet>,
    pub path_prefixes: Option<Vec<String>>,
    pub severity_min_rank: Option<u8>,
    pub uid_set: Option<HashSet<u32>>,
    pub dst_port_set: Option<HashSet<u16>>,
    pub parent_comm_set: Option<HashSet<String>>,
    pub pid_score_min: Option<u32>,
}

impl CompiledRule {
    pub fn matches(&self, event: &innerwarden_core::event::Event) -> bool {
        if let Some(ref s) = self.source_exact {
            if event.source != *s {
                return false;
            }
        }
        if let Some(ref set) = self.source_set {
            if !set.contains(&event.source) {
                return false;
            }
        }

        if let Some(ref k) = self.kind_exact {
            if event.kind != *k {
                return false;
            }
        }
        if let Some(ref set) = self.kind_set {
            if !set.contains(&event.kind) {
                return false;
            }
        }
        if let Some(ref gs) = self.kind_glob {
            if !gs.is_match(&event.kind) {
                return false;
            }
        }

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Some(ref c) = self.comm_exact {
            if comm != c.as_str() {
                return false;
            }
        }
        if let Some(ref set) = self.comm_set {
            if !set.contains(comm) {
                return false;
            }
        }
        if let Some(ref gs) = self.comm_glob {
            if !gs.is_match(comm) {
                return false;
            }
        }

        let path = event
            .details
            .get("filename")
            .or_else(|| event.details.get("path"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Some(ref set) = self.path_set {
            if !set.contains(path) {
                return false;
            }
        }
        if let Some(ref gs) = self.path_glob {
            if !gs.is_match(path) {
                return false;
            }
        }
        if let Some(ref prefixes) = self.path_prefixes {
            if !prefixes.iter().any(|p| path.starts_with(p.as_str())) {
                return false;
            }
        }

        if let Some(min_rank) = self.severity_min_rank {
            if severity_rank(&event.severity) < min_rank {
                return false;
            }
        }

        if let Some(ref set) = self.uid_set {
            let uid = event
                .details
                .get("uid")
                .and_then(|v| v.as_u64())
                .unwrap_or(u64::MAX) as u32;
            if !set.contains(&uid) {
                return false;
            }
        }

        if let Some(ref set) = self.dst_port_set {
            let port = event
                .details
                .get("dst_port")
                .and_then(|v| v.as_u64())
                .unwrap_or(u64::MAX) as u16;
            if !set.contains(&port) {
                return false;
            }
        }

        if let Some(ref set) = self.parent_comm_set {
            let parent = event
                .details
                .get("parent_comm")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !set.contains(parent) {
                return false;
            }
        }

        true
    }
}

pub fn compile_rule(raw: &RawRule) -> Result<CompiledRule, String> {
    if raw.priority > 1000 {
        return Err(format!(
            "rule '{}': priority {} exceeds max 1000",
            raw.id, raw.priority
        ));
    }
    if raw.action == ActionKind::Sample {
        let rate = raw.sample.unwrap_or(0.0);
        if !(0.0..=1.0).contains(&rate) {
            return Err(format!(
                "rule '{}': sample rate {rate} not in [0.0, 1.0]",
                raw.id
            ));
        }
    }
    if raw.action == ActionKind::ScoreIncrement {
        let si = raw.score_increment.as_ref().ok_or_else(|| {
            format!(
                "rule '{}': score_increment action requires score_increment field",
                raw.id
            )
        })?;
        if si.score == 0 || si.score > 100 {
            return Err(format!(
                "rule '{}': score_increment.score {} not in [1, 100]",
                raw.id, si.score
            ));
        }
    }
    if raw.action == ActionKind::SuppressIncident || raw.action == ActionKind::SuppressResponse {
        return Err(format!(
            "rule '{}': {:?} rules are handled separately",
            raw.id, raw.action
        ));
    }

    if raw.match_preds.is_none() {
        return Err(format!(
            "rule '{}': match block is required for action {:?}",
            raw.id, raw.action
        ));
    }

    let action = match raw.action {
        ActionKind::Emit => CompiledAction::Emit,
        ActionKind::ForceEmit => CompiledAction::ForceEmit,
        ActionKind::Drop => CompiledAction::Drop,
        ActionKind::Sample => CompiledAction::Sample,
        ActionKind::ScoreIncrement => {
            let si = raw.score_increment.as_ref().unwrap();
            CompiledAction::ScoreIncrement {
                score: si.score,
                decay_minutes: si.decay_minutes,
            }
        }
        ActionKind::SuppressIncident | ActionKind::SuppressResponse => {
            unreachable!("handled above")
        }
    };

    let mp = raw.match_preds.as_ref().unwrap();

    let kind_glob = compile_glob_set_opt(mp.kind.as_deref(), &raw.id, "kind")?;
    let comm_glob = compile_glob_set_list_opt(mp.comm_glob.as_deref(), &raw.id, "comm_glob")?;
    let path_glob = compile_glob_set_list_opt(mp.path_glob.as_deref(), &raw.id, "path_glob")?;

    Ok(CompiledRule {
        id: raw.id.clone(),
        priority: raw.priority,
        action,
        sample_rate: raw.sample.unwrap_or(0.0),
        tags: raw.tags.clone(),
        drop_reason: raw.drop_reason.clone(),
        source_exact: mp.source.clone(),
        source_set: mp.source_in.as_ref().map(|v| v.iter().cloned().collect()),
        kind_exact: if mp.kind.as_ref().is_some_and(|k| !has_glob_chars(k)) {
            mp.kind.clone()
        } else {
            None
        },
        kind_set: mp.kind_in.as_ref().map(|v| v.iter().cloned().collect()),
        kind_glob: if mp.kind.as_ref().is_some_and(|k| has_glob_chars(k)) {
            kind_glob
        } else {
            None
        },
        comm_exact: mp.comm.clone(),
        comm_set: mp.comm_in.as_ref().map(|v| v.iter().cloned().collect()),
        comm_glob,
        path_set: mp.path_in.as_ref().map(|v| v.iter().cloned().collect()),
        path_glob,
        path_prefixes: mp.path_prefix.clone(),
        severity_min_rank: mp.severity_min.as_deref().map(severity_str_to_rank),
        uid_set: mp.uid_in.as_ref().map(|v| v.iter().copied().collect()),
        dst_port_set: mp.dst_port_in.as_ref().map(|v| v.iter().copied().collect()),
        parent_comm_set: mp
            .parent_comm_in
            .as_ref()
            .map(|v| v.iter().cloned().collect()),
        pid_score_min: mp.pid_score_min,
    })
}

pub fn validate_suppress_rule(raw: &RawRule) -> Result<(String, Vec<String>), String> {
    let sc = raw.suppress.as_ref().ok_or_else(|| {
        format!(
            "rule '{}': suppress_incident action requires suppress field",
            raw.id
        )
    })?;
    let detector = sc.detector.as_deref().unwrap_or("");
    if detector.is_empty() {
        return Err(format!(
            "rule '{}': suppress.detector must not be empty",
            raw.id
        ));
    }
    if sc.values.is_empty() {
        return Err(format!(
            "rule '{}': suppress.values must not be empty",
            raw.id
        ));
    }
    Ok((detector.to_string(), sc.values.clone()))
}

pub fn expand_list_refs(values: &mut Option<Vec<String>>, lists: &HashMap<String, Vec<String>>) {
    let Some(vals) = values.as_mut() else { return };
    let mut expanded = Vec::new();
    for v in vals.drain(..) {
        if let Some(name) = v.strip_prefix('$') {
            if let Some(list) = lists.get(name) {
                expanded.extend(list.iter().cloned());
            } else {
                tracing::warn!("event_pipeline: unknown list reference ${name}");
                expanded.push(v);
            }
        } else {
            expanded.push(v);
        }
    }
    *vals = expanded;
}

pub fn expand_all_list_refs(raw: &mut RawRule, lists: &HashMap<String, Vec<String>>) {
    if let Some(ref mut mp) = raw.match_preds {
        expand_list_refs(&mut mp.source_in, lists);
        expand_list_refs(&mut mp.kind_in, lists);
        expand_list_refs(&mut mp.comm_in, lists);
        expand_list_refs(&mut mp.comm_glob, lists);
        expand_list_refs(&mut mp.path_in, lists);
        expand_list_refs(&mut mp.path_glob, lists);
        expand_list_refs(&mut mp.path_prefix, lists);
        expand_list_refs(&mut mp.parent_comm_in, lists);
    }
    if let Some(ref mut suppress) = raw.suppress {
        let mut vals = Some(suppress.values.clone());
        expand_list_refs(&mut vals, lists);
        if let Some(v) = vals {
            suppress.values = v;
        }
    }
}

fn has_glob_chars(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

fn compile_glob_set_opt(
    pattern: Option<&str>,
    rule_id: &str,
    field: &str,
) -> Result<Option<GlobSet>, String> {
    let Some(pat) = pattern else { return Ok(None) };
    if !has_glob_chars(pat) {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    builder.add(
        Glob::new(pat)
            .map_err(|e| format!("rule '{rule_id}': invalid {field} glob '{pat}': {e}"))?,
    );
    Ok(Some(builder.build().map_err(|e| {
        format!("rule '{rule_id}': failed to build {field} globset: {e}")
    })?))
}

fn compile_glob_set_list_opt(
    patterns: Option<&[String]>,
    rule_id: &str,
    field: &str,
) -> Result<Option<GlobSet>, String> {
    let Some(pats) = patterns else {
        return Ok(None);
    };
    if pats.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pat in pats {
        builder.add(
            Glob::new(pat)
                .map_err(|e| format!("rule '{rule_id}': invalid {field} glob '{pat}': {e}"))?,
        );
    }
    Ok(Some(builder.build().map_err(|e| {
        format!("rule '{rule_id}': failed to build {field} globset: {e}")
    })?))
}

fn severity_rank(sev: &innerwarden_core::event::Severity) -> u8 {
    use innerwarden_core::event::Severity;
    match sev {
        Severity::Debug => 0,
        Severity::Info => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

fn severity_str_to_rank(s: &str) -> u8 {
    match s {
        "debug" => 0,
        "info" => 1,
        "low" => 2,
        "medium" => 3,
        "high" => 4,
        "critical" => 5,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::{Event, Severity};

    fn test_event(source: &str, kind: &str, details: serde_json::Value) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: String::new(),
            source: source.into(),
            kind: kind.into(),
            severity: Severity::Info,
            summary: String::new(),
            details,
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn parse_minimal_rule_file() {
        let yaml = r#"
version: 1
rules:
  - id: test-drop
    match:
      source: ebpf
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rf.version, 1);
        assert_eq!(rf.rules.len(), 1);
        assert_eq!(rf.rules[0].id, "test-drop");
        assert_eq!(rf.rules[0].action, ActionKind::Drop);
        assert_eq!(rf.rules[0].priority, 50);
    }

    #[test]
    fn parse_full_rule_file() {
        let yaml = r#"
version: 1
metadata:
  author: test
  description: test file
rules:
  - id: allow-creds
    priority: 1000
    match:
      source: ebpf
      kind_in: [file.read_access, file.write_access]
      path_glob: ["/etc/shadow", "/etc/passwd"]
    action: force_emit
    tags: [defensive-allowlist]
  - id: drop-noise
    priority: 80
    match:
      source: ebpf
      kind: file.read_access
      comm_in: [nginx, apache2]
    action: drop
    drop_reason: service-daemon
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rf.rules.len(), 2);
        assert_eq!(rf.rules[0].action, ActionKind::ForceEmit);
        assert_eq!(rf.rules[1].action, ActionKind::Drop);
    }

    #[test]
    fn reject_unknown_fields() {
        let yaml = r#"
version: 1
rules:
  - id: bad
    match:
      source: ebpf
    action: drop
    bogus_field: true
"#;
        assert!(serde_yaml::from_str::<RuleFile>(yaml).is_err());
    }

    #[test]
    fn reject_invalid_priority_via_yaml() {
        let yaml = r#"
version: 1
rules:
  - id: test
    priority: 1001
    match:
      source: ebpf
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert!(compile_rule(&rf.rules[0]).is_err());
    }

    #[test]
    fn reject_sample_out_of_range() {
        let yaml = r#"
version: 1
rules:
  - id: bad-sample
    match:
      source: ebpf
    action: sample
    sample: 1.5
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert!(compile_rule(&rf.rules[0]).is_err());
    }

    #[test]
    fn compile_and_match_source() {
        let yaml = r#"
version: 1
rules:
  - id: match-ebpf
    match:
      source: ebpf
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({})
        )));
        assert!(!rule.matches(&test_event("journald", "auth.login", serde_json::json!({}))));
    }

    #[test]
    fn compile_and_match_comm_in() {
        let yaml = r#"
version: 1
rules:
  - id: match-comm
    match:
      source: ebpf
      comm_in: [nginx, apache2]
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "nginx", "pid": 1234})
        )));
        assert!(!rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "curl", "pid": 5678})
        )));
    }

    #[test]
    fn compile_and_match_path_glob() {
        let yaml = r#"
version: 1
rules:
  - id: match-path
    match:
      source: ebpf
      path_glob: ["/etc/shadow", "/etc/passwd"]
    action: force_emit
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"filename": "/etc/shadow", "pid": 1})
        )));
        assert!(!rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"filename": "/var/log/syslog", "pid": 1})
        )));
    }

    #[test]
    fn compile_and_match_comm_glob() {
        let yaml = r#"
version: 1
rules:
  - id: match-comm-glob
    match:
      source: ebpf
      comm_glob: ["innerwarden-*"]
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "innerwarden-agent"})
        )));
        assert!(!rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "nginx"})
        )));
    }

    #[test]
    fn compile_and_match_kind_in() {
        let yaml = r#"
version: 1
rules:
  - id: match-kind-in
    match:
      source: ebpf
      kind_in: [file.read_access, file.write_access]
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({})
        )));
        assert!(!rule.matches(&test_event(
            "ebpf",
            "shell.command_exec",
            serde_json::json!({})
        )));
    }

    #[test]
    fn compile_and_match_dst_port_in() {
        let yaml = r#"
version: 1
rules:
  - id: match-port
    match:
      source: ebpf
      dst_port_in: [4444, 1337]
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "network.outbound_connect",
            serde_json::json!({"dst_port": 4444, "comm": "nc"})
        )));
        assert!(!rule.matches(&test_event(
            "ebpf",
            "network.outbound_connect",
            serde_json::json!({"dst_port": 443, "comm": "curl"})
        )));
    }

    #[test]
    fn compile_and_match_parent_comm_in() {
        let yaml = r#"
version: 1
rules:
  - id: match-parent
    match:
      source: ebpf
      parent_comm_in: [apache2, nginx]
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "shell.command_exec",
            serde_json::json!({"parent_comm": "apache2", "comm": "sh"})
        )));
        assert!(!rule.matches(&test_event(
            "ebpf",
            "shell.command_exec",
            serde_json::json!({"parent_comm": "bash", "comm": "ls"})
        )));
    }

    #[test]
    fn compile_and_match_source_in() {
        let yaml = r#"
version: 1
rules:
  - id: match-source-in
    match:
      source_in: [ebpf, auditd]
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({})
        )));
        assert!(rule.matches(&test_event("auditd", "exec", serde_json::json!({}))));
        assert!(!rule.matches(&test_event("journald", "auth", serde_json::json!({}))));
    }

    #[test]
    fn compile_and_match_path_in() {
        let yaml = r#"
version: 1
rules:
  - id: match-path-in
    match:
      source: ebpf
      path_in: ["/etc/shadow", "/etc/passwd"]
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"filename": "/etc/shadow"})
        )));
        assert!(!rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"filename": "/etc/hosts"})
        )));
    }

    #[test]
    fn compile_and_match_path_prefix() {
        let yaml = r#"
version: 1
rules:
  - id: match-prefix
    match:
      source: ebpf
      path_prefix: ["/var/log/", "/tmp/"]
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"filename": "/var/log/syslog"})
        )));
        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"filename": "/tmp/build-123"})
        )));
        assert!(!rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"filename": "/etc/shadow"})
        )));
    }

    #[test]
    fn compile_and_match_severity_min() {
        let yaml = r#"
version: 1
rules:
  - id: match-severity
    match:
      source: ebpf
      severity_min: medium
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        let mut high_ev = test_event("ebpf", "alert", serde_json::json!({}));
        high_ev.severity = Severity::High;
        assert!(rule.matches(&high_ev));

        let low_ev = test_event("ebpf", "noise", serde_json::json!({}));
        assert!(!rule.matches(&low_ev)); // Info < Medium
    }

    #[test]
    fn compile_and_match_uid_in() {
        let yaml = r#"
version: 1
rules:
  - id: match-uid
    match:
      source: ebpf
      uid_in: [0, 1000]
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"uid": 0, "comm": "cat"})
        )));
        assert!(!rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"uid": 33, "comm": "www-data"})
        )));
    }

    #[test]
    fn compile_and_match_comm_exact() {
        let yaml = r#"
version: 1
rules:
  - id: match-comm-exact
    match:
      source: ebpf
      comm: nginx
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "nginx"})
        )));
        assert!(!rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"comm": "nginx-debug"})
        )));
    }

    #[test]
    fn compile_and_match_kind_glob() {
        let yaml = r#"
version: 1
rules:
  - id: match-kind-glob
    match:
      source: ebpf
      kind: "file.*"
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({})
        )));
        assert!(rule.matches(&test_event(
            "ebpf",
            "file.write_access",
            serde_json::json!({})
        )));
        assert!(!rule.matches(&test_event(
            "ebpf",
            "shell.command_exec",
            serde_json::json!({})
        )));
    }

    #[test]
    fn compile_score_increment_action() {
        let yaml = r#"
version: 1
rules:
  - id: score-test
    match:
      source: ebpf
    action: score_increment
    score_increment:
      score: 50
      decay_minutes: 60
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();
        assert_eq!(
            rule.action,
            CompiledAction::ScoreIncrement {
                score: 50,
                decay_minutes: 60
            }
        );
    }

    #[test]
    fn reject_score_increment_missing_config() {
        let yaml = r#"
version: 1
rules:
  - id: bad-score
    match:
      source: ebpf
    action: score_increment
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert!(compile_rule(&rf.rules[0]).is_err());
    }

    #[test]
    fn reject_score_increment_zero() {
        let yaml = r#"
version: 1
rules:
  - id: bad-score-zero
    match:
      source: ebpf
    action: score_increment
    score_increment:
      score: 0
      decay_minutes: 60
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert!(compile_rule(&rf.rules[0]).is_err());
    }

    #[test]
    fn compile_emit_action() {
        let yaml = r#"
version: 1
rules:
  - id: emit-test
    match:
      source: ebpf
    action: emit
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();
        assert_eq!(rule.action, CompiledAction::Emit);
    }

    #[test]
    fn compile_sample_action() {
        let yaml = r#"
version: 1
rules:
  - id: sample-test
    match:
      source: ebpf
    action: sample
    sample: 0.5
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();
        assert_eq!(rule.action, CompiledAction::Sample);
        assert!((rule.sample_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn path_field_falls_back_to_path_key() {
        let yaml = r#"
version: 1
rules:
  - id: match-path-key
    match:
      source: ebpf
      path_glob: ["/etc/shadow"]
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let rule = compile_rule(&rf.rules[0]).unwrap();

        // "path" key instead of "filename"
        assert!(rule.matches(&test_event(
            "ebpf",
            "file.read_access",
            serde_json::json!({"path": "/etc/shadow"})
        )));
    }

    #[test]
    fn is_terminal_returns_correct_values() {
        assert!(CompiledAction::ForceEmit.is_terminal());
        assert!(CompiledAction::Drop.is_terminal());
        assert!(CompiledAction::Sample.is_terminal());
        assert!(!CompiledAction::Emit.is_terminal());
        assert!(!CompiledAction::ScoreIncrement {
            score: 1,
            decay_minutes: 1
        }
        .is_terminal());
    }

    #[test]
    fn builtin_packs_parse_and_compile() {
        for (name, yaml) in super::super::BUILTIN_PACKS {
            let rf: RuleFile =
                serde_yaml::from_str(yaml).unwrap_or_else(|e| panic!("{name}: parse error: {e}"));
            for raw in &rf.rules {
                if raw.disabled {
                    continue;
                }
                compile_rule(raw)
                    .unwrap_or_else(|e| panic!("{name} rule '{}': compile error: {e}", raw.id));
            }
        }
    }

    #[test]
    fn compile_rule_rejects_suppress_incident() {
        let yaml = r#"
version: 1
rules:
  - id: suppress-test
    action: suppress_incident
    suppress:
      detector: kernel_module_load
      values: [bcache]
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        match compile_rule(&rf.rules[0]) {
            Err(e) => assert!(e.contains("handled separately"), "got: {e}"),
            Ok(_) => panic!("should have been rejected"),
        }
    }

    #[test]
    fn compile_rule_rejects_missing_match_block() {
        let yaml = r#"
version: 1
rules:
  - id: no-match
    action: drop
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        match compile_rule(&rf.rules[0]) {
            Err(e) => assert!(e.contains("match block is required"), "got: {e}"),
            Ok(_) => panic!("should have been rejected"),
        }
    }

    #[test]
    fn validate_suppress_rule_ok() {
        let yaml = r#"
version: 1
rules:
  - id: valid-suppress
    action: suppress_incident
    suppress:
      detector: kernel_module_load
      values: [bcache, dm_raid]
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        let result = validate_suppress_rule(&rf.rules[0]);
        assert!(result.is_ok());
        let (det, vals) = result.unwrap();
        assert_eq!(det, "kernel_module_load");
        assert_eq!(vals, vec!["bcache", "dm_raid"]);
    }

    #[test]
    fn validate_suppress_rule_missing_suppress() {
        let yaml = r#"
version: 1
rules:
  - id: no-suppress-block
    action: suppress_incident
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert!(validate_suppress_rule(&rf.rules[0]).is_err());
    }

    #[test]
    fn validate_suppress_rule_empty_detector() {
        let yaml = r#"
version: 1
rules:
  - id: empty-det
    action: suppress_incident
    suppress:
      detector: ""
      values: [x]
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert!(validate_suppress_rule(&rf.rules[0]).is_err());
    }

    #[test]
    fn validate_suppress_rule_empty_values() {
        let yaml = r#"
version: 1
rules:
  - id: empty-vals
    action: suppress_incident
    suppress:
      detector: kernel_module_load
      values: []
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert!(validate_suppress_rule(&rf.rules[0]).is_err());
    }

    #[test]
    fn parse_suppress_config() {
        let yaml = r#"
version: 1
rules:
  - id: suppress-test
    action: suppress_incident
    suppress:
      detector: sudo_abuse
      values: [ubuntu, deploy]
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rf.rules[0].action, ActionKind::SuppressIncident);
        let sc = rf.rules[0].suppress.as_ref().unwrap();
        assert_eq!(sc.detector.as_deref(), Some("sudo_abuse"));
        assert_eq!(sc.values, vec!["ubuntu", "deploy"]);
    }

    #[test]
    fn suppress_response_scope_rule_parses_and_is_skipped_by_sensor() {
        // Agent-side suppress_response rules (scope, no detector) must parse
        // cleanly under the sensor's deny_unknown_fields schema — otherwise the
        // sensor warn-skips the whole shared rule file. The sensor skips the
        // rule itself (it's an agent-side concern); we only assert it loads.
        let yaml = r#"
version: 1
rules:
  - id: operator-trust-203-0-113-10
    action: suppress_response
    suppress:
      scope: ip
      values: ["203.0.113.10"]
    drop_reason: "office vpn"
    expires_at: "2026-06-20T12:00:00Z"
    tags: [operator-trust]
"#;
        let rf: RuleFile = serde_yaml::from_str(yaml).expect("suppress_response/scope must parse");
        assert_eq!(rf.rules[0].action, ActionKind::SuppressResponse);
        let sc = rf.rules[0].suppress.as_ref().unwrap();
        assert_eq!(sc.scope.as_deref(), Some("ip"));
        assert!(sc.detector.is_none());
    }
}
