//! Operator "Trust Exec" — authorise a binary path for the Execution Gate from
//! the dashboard / Telegram (and visible to `innerwarden rule list`).
//!
//! ## What this does (read before changing)
//!
//! The Execution Gate (paid Active Defence) enforces an allowlist of exec paths
//! in the kernel (eBPF LSM `bprm_check_security`). When the gate blocks (or, in
//! observe mode, would-block) an unknown binary, the operator decides whether it
//! is legitimate. Approving one writes an **`allow_exec` rule** here; the paid
//! `exec-gate watch` daemon hot-reloads this directory each cycle and reconciles
//! the live `EXEC_ALLOWLIST` BPF map, so the next exec of that path passes.
//!
//! ## Why a rule file (not a direct map write)
//!
//! - **Open-core seam.** The OSS agent owns the approval UX (the free channels:
//!   dashboard / Telegram / Slack); the paid daemon owns enforcement (the map).
//!   They meet at this shared rules directory — no compile-time coupling.
//! - **Durable + auditable.** An approval is the same artifact an advanced user
//!   can hand-write (`action: allow_exec`), survives restarts, shows up in
//!   `innerwarden rule list`, and can be `rule disable`d.
//! - **Inert without the paid daemon.** With no watch running nothing reads these
//!   into a map, so the file is harmless on a free install (matches the gate
//!   primitive shipping free + inert).
//!
//! The file format is exactly what `config-sign exec-gate`'s
//! `load_allow_exec_paths` parses:
//! ```yaml
//! version: 1
//! rules:
//!   - id: operator-exec-...
//!     action: allow_exec
//!     paths: ["/opt/app/bin/server"]
//!     tags: [operator-exec]
//! ```
//!
//! Provenance (who/when/why) is recorded in the hash-chained admin-actions audit
//! by the dashboard/Telegram handler; the rule file carries the path + reason.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Default exec-gate rules directory (shared with the paid `exec-gate watch`
/// daemon + the agent + `innerwarden rule`). Mirrors
/// `innerwarden_config_sign::exec_gate::DEFAULT_EXEC_RULES_DIR`.
pub const DEFAULT_EXEC_RULES_DIR: &str = "/etc/innerwarden/rules/exec-gate";

/// Dashboard-managed file. The `70-` prefix orders it after built-in/user packs;
/// the fixed name means no operator input ever reaches a filesystem path.
pub const MANAGED_FILE: &str = "70-operator-exec.yml";

/// Tag stamped on every rule we own so reads can tell our entries apart from a
/// hand-written `allow_exec` rule sharing the file.
pub const EXEC_TAG: &str = "operator-exec";

/// Hard cap on a `reason` length.
pub const MAX_REASON_LEN: usize = 1000;
/// Hard cap on a path length (generous; real exec paths are < 4096).
pub const MAX_PATH_LEN: usize = 4096;

/// Managed-file path inside a rules dir.
pub fn managed_file_in(rules_dir: &Path) -> PathBuf {
    rules_dir.join(MANAGED_FILE)
}

/// One authorised exec path as surfaced to the dashboard list endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecEntry {
    /// The authorised absolute binary path.
    pub path: String,
    /// Operator rationale.
    pub reason: String,
    /// Stable rule id (`operator-exec-<slug>`), usable with `rule disable <id>`.
    pub id: String,
}

// --- On-disk rule schema (a subset of the exec-gate rule schema) -------------
// Lenient (no deny_unknown_fields): we only read our own file, but a future
// schema field must never make the read fail.

#[derive(Debug, Default, Serialize, Deserialize)]
struct RuleFile {
    version: u32,
    #[serde(default)]
    rules: Vec<ExecRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExecRule {
    id: String,
    action: String,
    paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

/// Validate and normalise an operator-supplied exec path.
///
/// The gate enforces on `FNV(absolute path)`, so only a literal absolute path is
/// meaningful (a glob would never match a kernel `bprm->filename`). Rejects:
/// empty, non-absolute, any `..` component (path-traversal / ambiguity), control
/// characters, and over-long input. A trailing `/` is stripped.
pub fn validate_exec_path(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("path is required".to_string());
    }
    if t.len() > MAX_PATH_LEN {
        return Err(format!("path must be <= {MAX_PATH_LEN} characters"));
    }
    if !t.starts_with('/') {
        return Err("path must be absolute (start with '/')".to_string());
    }
    if t.contains('\0') || t.chars().any(|c| c.is_control()) {
        return Err("path contains control characters".to_string());
    }
    if t.split('/').any(|seg| seg == "..") {
        return Err("path must not contain '..' components".to_string());
    }
    if t.contains('*') || t.contains('?') {
        return Err(
            "globs are not supported — the kernel enforces on an exact path; authorise each binary"
                .to_string(),
        );
    }
    // strip a single trailing slash (but keep root "/")
    let norm = if t.len() > 1 {
        t.trim_end_matches('/')
    } else {
        t
    };
    if norm.is_empty() {
        return Err("path must be absolute (start with '/')".to_string());
    }
    Ok(norm.to_string())
}

/// Stable, human-readable rule id for a path. Non-alphanumeric → `-` (this is the
/// YAML `id`, not a filename — sanitisation is for readability + `rule disable`).
fn rule_id_for(path: &str) -> String {
    let slug: String = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("operator-exec-{slug}")
}

fn read_rules(file: &Path) -> Vec<ExecRule> {
    let Ok(content) = std::fs::read_to_string(file) else {
        return Vec::new();
    };
    serde_yaml::from_str::<RuleFile>(&content)
        .map(|f| f.rules)
        .unwrap_or_default()
}

/// Read exec entries for the dashboard list. Only `allow_exec` rules tagged
/// [`EXEC_TAG`] are returned, one entry per path.
pub fn read_entries(file: &Path) -> Vec<ExecEntry> {
    read_rules(file)
        .into_iter()
        .filter(|r| r.action == "allow_exec")
        .filter(|r| r.tags.iter().any(|t| t == EXEC_TAG))
        .flat_map(|r| {
            let reason = r.reason.clone().unwrap_or_default();
            let id = r.id.clone();
            r.paths.into_iter().map(move |p| ExecEntry {
                path: p,
                reason: reason.clone(),
                id: id.clone(),
            })
        })
        .collect()
}

/// Authorise (or replace, by exact normalised path) an exec path. Returns the
/// entry written. Atomic write (temp + rename) so the watch never reads a
/// half-written file.
pub fn add(rules_dir: &Path, raw_path: &str, reason: &str) -> Result<ExecEntry, String> {
    let path = validate_exec_path(raw_path)?;
    let reason = reason.trim();
    if reason.is_empty() {
        return Err("reason is required".to_string());
    }
    if reason.chars().count() > MAX_REASON_LEN {
        return Err(format!("reason must be <= {MAX_REASON_LEN} characters"));
    }

    let id = rule_id_for(&path);
    let rule = ExecRule {
        id: id.clone(),
        action: "allow_exec".to_string(),
        paths: vec![path.clone()],
        reason: Some(reason.to_string()),
        tags: vec![EXEC_TAG.to_string()],
    };

    let file = managed_file_in(rules_dir);
    let mut rules = read_rules(&file);
    // Upsert by path within our own rules (keep unrelated rules intact).
    rules.retain(|r| !r.paths.iter().any(|p| p == &path));
    rules.push(rule);
    write_atomic(&file, &rules)?;

    Ok(ExecEntry {
        path,
        reason: reason.to_string(),
        id,
    })
}

/// Remove an authorised path by exact (normalised) value. True when removed.
pub fn remove(rules_dir: &Path, raw_path: &str) -> Result<bool, String> {
    let path = validate_exec_path(raw_path)?;
    let file = managed_file_in(rules_dir);
    let mut rules = read_rules(&file);
    let before = rules.len();
    rules.retain(|r| !r.paths.iter().any(|p| p == &path));
    let removed = rules.len() != before;
    if removed {
        write_atomic(&file, &rules)?;
    }
    Ok(removed)
}

fn write_atomic(file: &Path, rules: &[ExecRule]) -> Result<(), String> {
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let doc = RuleFile {
        version: 1,
        rules: rules.to_vec(),
    };
    let body = serde_yaml::to_string(&doc).map_err(|e| format!("serialize: {e}"))?;
    let header = "# Managed by InnerWarden \"Trust Exec\". Do not hand-edit; use the\n\
                  # dashboard / Telegram or `innerwarden rule`. Each rule authorises a\n\
                  # binary PATH for the Execution Gate: the paid `exec-gate watch`\n\
                  # daemon hot-reloads these and lets the path execute. Without the paid\n\
                  # daemon running these rules are inert.\n";
    let tmp = file.with_extension("yml.tmp");
    std::fs::write(&tmp, format!("{header}{body}"))
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, file).map_err(|e| format!("rename into {}: {e}", file.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_absolute_and_normalises() {
        assert_eq!(
            validate_exec_path(" /opt/app/server ").unwrap(),
            "/opt/app/server"
        );
        assert_eq!(
            validate_exec_path("/usr/local/bin/tool/").unwrap(),
            "/usr/local/bin/tool"
        );
        assert_eq!(validate_exec_path("/").unwrap(), "/");
    }

    #[test]
    fn validate_rejects_relative_traversal_glob_and_garbage() {
        assert!(validate_exec_path("").is_err());
        assert!(validate_exec_path("relative/path").is_err());
        assert!(validate_exec_path("/opt/../etc/shadow").is_err());
        assert!(validate_exec_path("/usr/bin/*").is_err());
        assert!(validate_exec_path("/opt/app/**").is_err());
        assert!(validate_exec_path("/opt/x?y").is_err());
        assert!(validate_exec_path("/opt/\nbad").is_err());
        assert!(validate_exec_path(&format!("/{}", "x".repeat(MAX_PATH_LEN))).is_err());
    }

    #[test]
    fn add_writes_rule_readable_back_and_in_allow_exec_format() {
        let dir = tempfile::tempdir().unwrap();
        let e = add(dir.path(), "/opt/app/server", "app runtime").unwrap();
        assert_eq!(e.path, "/opt/app/server");
        assert_eq!(e.id, "operator-exec--opt-app-server");

        let entries = read_entries(&managed_file_in(dir.path()));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/opt/app/server");
        assert_eq!(entries[0].reason, "app runtime");

        // The on-disk YAML must be in the `action: allow_exec` + `paths:` shape
        // the paid config-sign loader parses.
        let raw = std::fs::read_to_string(managed_file_in(dir.path())).unwrap();
        assert!(raw.contains("action: allow_exec"));
        assert!(raw.contains("/opt/app/server"));
    }

    #[test]
    fn add_upserts_by_path() {
        let dir = tempfile::tempdir().unwrap();
        add(dir.path(), "/opt/app/server", "first").unwrap();
        add(dir.path(), "/opt/app/server", "second").unwrap();
        let entries = read_entries(&managed_file_in(dir.path()));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason, "second");
    }

    #[test]
    fn add_rejects_empty_and_overlong_reason() {
        let dir = tempfile::tempdir().unwrap();
        assert!(add(dir.path(), "/opt/x", "").is_err());
        let long = "x".repeat(MAX_REASON_LEN + 1);
        assert!(add(dir.path(), "/opt/x", &long).is_err());
        assert!(read_entries(&managed_file_in(dir.path())).is_empty());
    }

    #[test]
    fn remove_existing_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        add(dir.path(), "/opt/app/server", "r").unwrap();
        assert!(remove(dir.path(), "/opt/app/server").unwrap());
        assert!(read_entries(&managed_file_in(dir.path())).is_empty());
        assert!(!remove(dir.path(), "/opt/app/server").unwrap());
    }

    #[test]
    fn missing_file_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_entries(&managed_file_in(dir.path())).is_empty());
    }

    #[test]
    fn untagged_allow_exec_rules_are_not_listed() {
        // A hand-written allow_exec rule WITHOUT our tag must not appear as an
        // operator entry (we only manage our own).
        let dir = tempfile::tempdir().unwrap();
        let file = managed_file_in(dir.path());
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(
            &file,
            "version: 1\nrules:\n  - id: hand\n    action: allow_exec\n    paths: [\"/x\"]\n",
        )
        .unwrap();
        assert!(read_entries(&file).is_empty());
    }
}
