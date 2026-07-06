//! `innerwarden agent install-hook` — wire InnerWarden's in-path command guard
//! into an AI coding agent (Claude Code) as a PreToolUse hook.
//!
//! The MCP server (`agent mcp-serve`) and the HTTP `check-command` endpoint are
//! both *advisory*: a cooperating agent has to choose to ask. A coding agent
//! that runs commands through its raw shell tool bypasses them. This installs
//! the *enforcing* path: a PreToolUse hook that POSTs every proposed shell
//! command to the loopback `check-command` brain and blocks it (exit 2) before
//! it executes when the verdict is dangerous, failing CLOSED if the endpoint is
//! unreachable.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};

const DEFAULT_URL: &str = "https://127.0.0.1:8787";

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set; pass --settings explicitly")
}

/// Build the guard script. `block_review` extends blocking to `review` verdicts
/// (by default only `deny` blocks). Always fails CLOSED on an unreachable or
/// unparsable inspection result, so a stopped agent does not silently open the
/// gate.
fn guard_script(url: &str, block_review: bool, tenant: Option<&str>) -> String {
    let deny_cases = if block_review {
        "deny | review"
    } else {
        "deny"
    };
    // Spec 084 P0 1D: when a tenant is supplied, the guard stamps every
    // check-command call with it (body field + `X-InnerWarden-Tenant` header)
    // so a multi-tenant fleet attributes guard activity per tenant. Empty when
    // unset, in which case the header + body field are omitted.
    let tenant = tenant.map(str::trim).unwrap_or("");
    format!(
        r#"#!/usr/bin/env bash
# InnerWarden guard hook for Claude Code (PreToolUse:Bash).
# Installed by `innerwarden agent install-hook`. Sends each proposed shell
# command to InnerWarden's check-command brain and blocks (exit 2) on a
# dangerous verdict, failing CLOSED if the endpoint is unreachable.
IW_URL="${{INNERWARDEN_DASHBOARD_URL:-{url}}}"
IW_TENANT="{tenant}"
input="$(cat)"
cmd="$(printf '%s' "$input" | python3 -c 'import sys, json
try: print(json.load(sys.stdin).get("tool_input", {{}}).get("command", ""))
except Exception: print("")')"
[ -z "$cmd" ] && exit 0
resp=""
for _ in 1 2 3; do
  resp="$(curl -sk -m 8 -X POST "$IW_URL/api/agent/check-command" \
    -H 'content-type: application/json' \
    ${{IW_TENANT:+-H "x-innerwarden-tenant: $IW_TENANT"}} \
    -d "$(python3 -c 'import json, sys
b = {{"command": sys.argv[1]}}
if len(sys.argv) > 2 and sys.argv[2]: b["tenant"] = sys.argv[2]
print(json.dumps(b))' "$cmd" "$IW_TENANT")" 2>/dev/null)"
  [ -n "$resp" ] && break
done
read -r rec risk expl < <(printf '%s' "$resp" | python3 -c 'import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get("recommendation", "ERROR"), d.get("risk_score", 0), (d.get("explanation", "") or "")[:200].replace(chr(10), " "))
except Exception:
    print("ERROR 0 inspection-unreachable")')
case "$rec" in
  {deny_cases})
    echo "InnerWarden blocked this command (rec=$rec risk=$risk): $expl" >&2
    exit 2 ;;
  ERROR)
    echo "InnerWarden inspection unreachable - failing closed. Start the agent or set INNERWARDEN_DASHBOARD_URL." >&2
    exit 2 ;;
  *)
    exit 0 ;;
esac
"#
    )
}

/// Idempotently add a PreToolUse `Bash` hook pointing at `script_path` to a
/// settings JSON object. Existing keys, hooks, and other PreToolUse entries are
/// preserved; re-running does not duplicate the entry.
fn merge_pretooluse_bash_hook(mut settings: Value, script_path: &str) -> Value {
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
                    .any(|x| x.get("command").and_then(|c| c.as_str()) == Some(script_path))
            })
            .unwrap_or(false)
    });
    if !already {
        arr.push(json!({
            "matcher": "Bash",
            "hooks": [ { "type": "command", "command": script_path } ]
        }));
    }
    settings
}

pub(crate) fn run(
    agent: &str,
    settings: Option<&str>,
    url: Option<&str>,
    block_review: bool,
    tenant: Option<&str>,
) -> Result<()> {
    run_in(&home()?, agent, settings, url, block_review, tenant)
}

/// Core of [`run`] with the home directory injected, so the full install
/// (path resolution, script write, settings merge, report) is unit-testable
/// against a temp dir without touching the real `$HOME`.
fn run_in(
    home: &Path,
    agent: &str,
    settings: Option<&str>,
    url: Option<&str>,
    block_review: bool,
    tenant: Option<&str>,
) -> Result<()> {
    if agent != "claude-code" {
        anyhow::bail!("unsupported agent '{agent}' (only 'claude-code' is supported today)");
    }
    let url = url.unwrap_or(DEFAULT_URL);

    // 1. Write the guard script (0755).
    let script_path = home.join(".config/innerwarden/claude_code_guard.sh");
    if let Some(parent) = script_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(&script_path, guard_script(url, block_review, tenant))
        .with_context(|| format!("writing {}", script_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("chmod {}", script_path.display()))?;
    }

    // 2. Merge the PreToolUse hook into the agent's settings.json.
    let settings_path = match settings {
        Some(p) => PathBuf::from(p),
        None => home.join(".claude/settings.json"),
    };
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let existing: Value = match fs::read_to_string(&settings_path) {
        Ok(s) if !s.trim().is_empty() => serde_json::from_str(&s)
            .with_context(|| format!("{} is not valid JSON", settings_path.display()))?,
        _ => json!({}),
    };
    let script_str = script_path.to_string_lossy().to_string();
    let merged = merge_pretooluse_bash_hook(existing, &script_str);
    fs::write(
        &settings_path,
        serde_json::to_string_pretty(&merged)? + "\n",
    )
    .with_context(|| format!("writing {}", settings_path.display()))?;

    // 3. Report.
    println!();
    println!("  \x1b[1;36m\u{1f6e1}  InnerWarden guard hook installed for {agent}\x1b[0m");
    println!();
    println!("  guard script : {}", script_path.display());
    println!("  settings     : {}", settings_path.display());
    println!("  inspect URL  : {url}");
    println!(
        "  blocks on    : {}",
        if block_review {
            "deny + review"
        } else {
            "deny"
        }
    );
    println!();
    println!("  Every shell command the agent runs is now sent to InnerWarden's");
    println!("  check-command brain BEFORE it executes; dangerous commands are");
    println!("  blocked (fail-closed if the agent is not running). Verify with:");
    println!("    innerwarden get status");
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_into_empty_adds_bash_hook() {
        let out = merge_pretooluse_bash_hook(json!({}), "/path/guard.sh");
        let entry = &out["hooks"]["PreToolUse"][0];
        assert_eq!(entry["matcher"], "Bash");
        assert_eq!(entry["hooks"][0]["type"], "command");
        assert_eq!(entry["hooks"][0]["command"], "/path/guard.sh");
    }

    #[test]
    fn merge_is_idempotent() {
        let once = merge_pretooluse_bash_hook(json!({}), "/g.sh");
        let twice = merge_pretooluse_bash_hook(once.clone(), "/g.sh");
        assert_eq!(
            twice["hooks"]["PreToolUse"].as_array().unwrap().len(),
            1,
            "re-running must not duplicate the hook"
        );
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
        let out = merge_pretooluse_bash_hook(existing, "/g.sh");
        assert_eq!(out["model"], "sonnet", "unrelated keys preserved");
        assert!(out["hooks"]["PostToolUse"].is_array(), "other events kept");
        let pre = out["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2, "existing Write hook kept, Bash hook added");
        assert!(pre.iter().any(|e| e["matcher"] == "Write"));
        assert!(pre.iter().any(|e| e["hooks"][0]["command"] == "/g.sh"));
    }

    #[test]
    fn merge_repairs_non_object_settings() {
        // A corrupt/array settings root is replaced, not panicked on.
        let out = merge_pretooluse_bash_hook(json!([1, 2, 3]), "/g.sh");
        assert!(out["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn guard_script_deny_only_blocks_deny() {
        let s = guard_script("https://127.0.0.1:8787", false, None);
        assert!(s.contains("/api/agent/check-command"));
        assert!(s.contains("exit 2"), "must be able to block");
        assert!(s.contains("inspection-unreachable"), "must fail closed");
        assert!(s.contains("  deny)"), "deny-only case present");
        assert!(!s.contains("deny | review"));
        // No tenant -> empty IW_TENANT, so the header expansion is a no-op.
        assert!(s.contains("IW_TENANT=\"\""));
    }

    #[test]
    fn guard_script_block_review_extends_cases() {
        let s = guard_script("https://example:9", true, None);
        assert!(s.contains("deny | review"));
        assert!(s.contains("https://example:9"));
    }

    // Spec 084 P0 1D: a tenant is baked into the script as IW_TENANT and flows
    // to the check-command brain via the header + body field.
    #[test]
    fn guard_script_stamps_tenant() {
        let s = guard_script("https://127.0.0.1:8787", false, Some("acme-corp"));
        assert!(s.contains("IW_TENANT=\"acme-corp\""));
        assert!(s.contains("x-innerwarden-tenant: $IW_TENANT"));
        assert!(s.contains("b[\"tenant\"] = sys.argv[2]"));
    }

    #[test]
    fn run_in_writes_script_and_merges_settings() {
        let home = tempfile::TempDir::new().unwrap();
        // Pre-existing settings with an unrelated key, to prove the merge
        // preserves it.
        let settings = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(&settings, r#"{"model":"sonnet"}"#).unwrap();

        run_in(
            home.path(),
            "claude-code",
            None,
            Some("https://h:1"),
            true,
            None,
        )
        .unwrap();

        // Guard script written, fail-closed, block-review wired, 0755.
        let script = home.path().join(".config/innerwarden/claude_code_guard.sh");
        let body = std::fs::read_to_string(&script).unwrap();
        assert!(body.contains("/api/agent/check-command"));
        assert!(body.contains("deny | review"));
        assert!(body.contains("inspection-unreachable"));
        assert!(body.contains("https://h:1"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&script).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }

        // Settings merged: unrelated key kept, our PreToolUse Bash hook added.
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["model"], "sonnet");
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
                .as_str()
                .unwrap(),
            script.to_string_lossy()
        );

        // Idempotent: a second run does not duplicate the hook.
        run_in(
            home.path(),
            "claude-code",
            None,
            Some("https://h:1"),
            true,
            None,
        )
        .unwrap();
        let v2: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v2["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn run_in_respects_explicit_settings_path_and_deny_only() {
        let home = tempfile::TempDir::new().unwrap();
        let custom = home.path().join("custom/place/settings.json");
        run_in(
            home.path(),
            "claude-code",
            Some(custom.to_str().unwrap()),
            None,
            false,
            None,
        )
        .unwrap();
        assert!(custom.exists(), "explicit --settings path is honoured");
        let script = home.path().join(".config/innerwarden/claude_code_guard.sh");
        let body = std::fs::read_to_string(&script).unwrap();
        assert!(
            body.contains("  deny)"),
            "deny-only when block_review=false"
        );
        assert!(!body.contains("deny | review"));
    }

    #[test]
    fn run_in_rejects_unknown_agent() {
        let home = tempfile::TempDir::new().unwrap();
        let err = run_in(home.path(), "cursor", None, None, false, None).unwrap_err();
        assert!(err.to_string().contains("unsupported agent"));
    }
}
