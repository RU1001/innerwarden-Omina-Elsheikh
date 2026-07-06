//! `iw-guard install claude-code` - wire the guardrail into Claude Code as a
//! fail-closed PreToolUse:Bash hook, in ONE command, offline.
//!
//! Unlike the Linux `innerwarden agent install-hook` (which POSTs to a running
//! agent over HTTPS via a bash+python3+curl script), this points the hook
//! straight at `iw-guard hook` - the in-process adapter that reads Claude's tool
//! call on stdin, runs the check-command engine locally, and blocks (exit 2) on a
//! dangerous verdict. No agent, no HTTP, no python3: just the binary. So the same
//! one command works on Windows, macOS, and Linux.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Resolve the user home directory cross-platform (`USERPROFILE` on Windows,
/// `HOME` elsewhere).
pub fn home_dir() -> Result<PathBuf, String> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{var} is not set; pass --settings explicitly"))
}

/// What was installed, for the caller's report.
#[derive(Debug)]
pub struct Report {
    pub settings_path: PathBuf,
    pub hook_command: String,
    pub block_review: bool,
}

/// Idempotently add a PreToolUse `Bash` hook running `hook_command` to a settings
/// JSON object. Existing keys, hooks, and other PreToolUse entries are preserved;
/// re-running with the same command does not duplicate the entry.
pub fn merge_pretooluse_bash_hook(mut settings: Value, hook_command: &str) -> Value {
    if !settings.is_object() {
        settings = json!({});
    }
    let obj = settings.as_object_mut().expect("object");
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let pre = hooks
        .as_object_mut()
        .expect("object")
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));
    if !pre.is_array() {
        *pre = json!([]);
    }
    let arr = pre.as_array_mut().expect("array");
    let already = arr.iter().any(|e| {
        e.get("hooks")
            .and_then(|h| h.as_array())
            .map(|hs| {
                hs.iter()
                    .any(|x| x.get("command").and_then(|c| c.as_str()) == Some(hook_command))
            })
            .unwrap_or(false)
    });
    if !already {
        arr.push(json!({
            "matcher": "Bash",
            "hooks": [ { "type": "command", "command": hook_command } ]
        }));
    }
    settings
}

/// The shell command Claude Code runs for the hook: the quoted iw-guard path plus
/// `hook` (and `--block-review` when requested). Quoting handles a path with
/// spaces (e.g. `C:\Users\Some Name\...`).
pub fn hook_command(iw_guard: &Path, block_review: bool) -> String {
    let flag = if block_review { " --block-review" } else { "" };
    format!("\"{}\" hook{flag}", iw_guard.display())
}

/// Core installer with the home directory injected, so it is unit-testable
/// against a temp dir without touching the real home. `iw_guard` is the path to
/// this binary that the hook will invoke.
pub fn install_hook(
    home: &Path,
    agent: &str,
    settings: Option<&str>,
    iw_guard: &Path,
    block_review: bool,
) -> Result<Report, String> {
    if agent != "claude-code" {
        return Err(format!(
            "unsupported agent '{agent}' (only 'claude-code' is supported today)"
        ));
    }

    let settings_path = match settings {
        Some(p) => PathBuf::from(p),
        None => home.join(".claude/settings.json"),
    };
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }

    let existing: Value = match fs::read_to_string(&settings_path) {
        Ok(s) if !s.trim().is_empty() => serde_json::from_str(&s)
            .map_err(|_| format!("{} is not valid JSON", settings_path.display()))?,
        _ => json!({}),
    };

    let cmd = hook_command(iw_guard, block_review);
    let merged = merge_pretooluse_bash_hook(existing, &cmd);
    let body = serde_json::to_string_pretty(&merged).map_err(|e| e.to_string())? + "\n";
    fs::write(&settings_path, body)
        .map_err(|e| format!("writing {}: {e}", settings_path.display()))?;

    Ok(Report {
        settings_path,
        hook_command: cmd,
        block_review,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_into_empty_adds_bash_hook() {
        let out = merge_pretooluse_bash_hook(json!({}), "\"/p/iw-guard\" hook");
        let entry = &out["hooks"]["PreToolUse"][0];
        assert_eq!(entry["matcher"], "Bash");
        assert_eq!(entry["hooks"][0]["type"], "command");
        assert_eq!(entry["hooks"][0]["command"], "\"/p/iw-guard\" hook");
    }

    #[test]
    fn merge_is_idempotent() {
        let once = merge_pretooluse_bash_hook(json!({}), "cmd");
        let twice = merge_pretooluse_bash_hook(once.clone(), "cmd");
        assert_eq!(twice["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        assert_eq!(once, twice);
    }

    #[test]
    fn merge_preserves_existing_settings_and_hooks() {
        let existing = json!({
            "model": "sonnet",
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Write", "hooks": [ { "type": "command", "command": "/other.sh" } ] }
                ],
                "PostToolUse": [ { "matcher": "Bash", "hooks": [] } ]
            }
        });
        let out = merge_pretooluse_bash_hook(existing, "cmd");
        assert_eq!(out["model"], "sonnet");
        assert!(out["hooks"]["PostToolUse"].is_array());
        let pre = out["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2);
        assert!(pre.iter().any(|e| e["matcher"] == "Write"));
        assert!(pre.iter().any(|e| e["hooks"][0]["command"] == "cmd"));
    }

    #[test]
    fn merge_repairs_non_object_settings() {
        let out = merge_pretooluse_bash_hook(json!([1, 2, 3]), "cmd");
        assert!(out["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn hook_command_quotes_path_and_wires_block_review() {
        let c = hook_command(Path::new("/usr/local/bin/iw-guard"), false);
        assert_eq!(c, "\"/usr/local/bin/iw-guard\" hook");
        let c2 = hook_command(Path::new("/x/iw-guard"), true);
        assert_eq!(c2, "\"/x/iw-guard\" hook --block-review");
    }

    #[test]
    fn install_hook_writes_and_merges_settings() {
        let home = tempfile::TempDir::new().unwrap();
        let settings = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(&settings, r#"{"model":"sonnet"}"#).unwrap();

        let iw = Path::new("/opt/iw-guard");
        install_hook(home.path(), "claude-code", None, iw, true).unwrap();

        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["model"], "sonnet", "unrelated key preserved");
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "\"/opt/iw-guard\" hook --block-review"
        );

        // Idempotent.
        install_hook(home.path(), "claude-code", None, iw, true).unwrap();
        let v2: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v2["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn install_hook_respects_explicit_settings_path() {
        let home = tempfile::TempDir::new().unwrap();
        let custom = home.path().join("custom/place/settings.json");
        let r = install_hook(
            home.path(),
            "claude-code",
            Some(custom.to_str().unwrap()),
            Path::new("/x/iw-guard"),
            false,
        )
        .unwrap();
        assert!(custom.exists());
        assert_eq!(r.settings_path, custom);
        assert!(!r.block_review);
    }

    #[test]
    fn install_hook_rejects_unknown_agent() {
        let home = tempfile::TempDir::new().unwrap();
        let err = install_hook(home.path(), "cursor", None, Path::new("/x"), false).unwrap_err();
        assert!(err.contains("unsupported agent"));
    }
}
