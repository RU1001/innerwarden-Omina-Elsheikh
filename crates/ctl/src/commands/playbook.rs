//! Spec 056 Phase 5c: `innerwarden playbook test` CLI.
//!
//! Dry-runs a SOC playbook against a captured incident by POSTing to the
//! running agent's `POST /api/playbook/test` (spec 056 Phase 5b). The
//! agent owns the real executor, so the CLI is a thin client: it never
//! re-implements matching/interpolation/execution (zero drift). The same
//! endpoint backs the dashboard and the future Active Defense LLM.

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine;

/// Default dashboard address (loopback, no TLS) used by the agent unless
/// the operator overrode `[dashboard] bind`. Override with `--url`.
const DEFAULT_URL: &str = "http://127.0.0.1:8787";

/// `innerwarden playbook test <id> --incident-file <path>`.
pub fn cmd_playbook_test(
    playbook_id: &str,
    incident_file: &Path,
    url: Option<&str>,
    user: Option<&str>,
    password: Option<&str>,
    insecure: bool,
) -> Result<()> {
    let incident = read_incident_json(incident_file)?;
    let base = url.unwrap_or(DEFAULT_URL).trim_end_matches('/');
    let endpoint = format!("{base}/api/playbook/test");
    let body = serde_json::json!({
        "playbook_id": playbook_id,
        "incident": incident,
    });

    let agent = build_agent(insecure);
    let mut req = agent
        .post(&endpoint)
        .header("Content-Type", "application/json");
    // Basic auth: flag wins, else env (matches the dashboard's
    // INNERWARDEN_DASHBOARD_USER / _PASSWORD knobs). Loopback-no-auth
    // installs need neither.
    let auth_user = user
        .map(str::to_string)
        .or_else(|| std::env::var("INNERWARDEN_DASHBOARD_USER").ok());
    if let Some(u) = auth_user {
        let p = password
            .map(str::to_string)
            .or_else(|| std::env::var("INNERWARDEN_DASHBOARD_PASSWORD").ok())
            .unwrap_or_default();
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
        req = req.header("Authorization", format!("Basic {token}"));
    }

    // ureq treats >= 400 as Err, so a 401 (auth required) surfaces here
    // with the address + auth hint.
    let resp = req.send(body.to_string()).map_err(|e| {
        anyhow::anyhow!(
            "POST {endpoint} failed: {e}. Is the agent dashboard running and reachable? \
             Override the address with --url; pass --user/--password if auth is enabled."
        )
    })?;
    let value: serde_json::Value = resp
        .into_body()
        .read_json()
        .context("agent response was not valid JSON")?;

    print!("{}", format_test_output(playbook_id, &value));
    Ok(())
}

/// Build the HTTP agent. With `insecure`, TLS certificate verification is
/// disabled so the CLI can reach the agent dashboard's self-signed HTTPS
/// cert (`https://127.0.0.1:8787`); otherwise the default verifying agent.
fn build_agent(insecure: bool) -> ureq::Agent {
    if insecure {
        ureq::Agent::config_builder()
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .disable_verification(true)
                    .build(),
            )
            .build()
            .into()
    } else {
        ureq::Agent::new_with_defaults()
    }
}

/// Read the incident JSON from `path`. Accepts a single JSON object or a
/// JSONL file (e.g. a line copied from `incidents-<date>.jsonl`); the
/// first non-empty line is used.
fn read_incident_json(path: &Path) -> Result<serde_json::Value> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read incident file {}", path.display()))?;
    let line = content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .with_context(|| format!("incident file {} is empty", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(line)
        .with_context(|| format!("incident file {} is not valid JSON", path.display()))?;
    Ok(value)
}

/// Render the simulate response deterministically (no timestamps / wall
/// clock), so the same incident always prints the same output. Pure, for
/// unit-testing.
fn format_test_output(playbook_id: &str, v: &serde_json::Value) -> String {
    let mut out = String::new();

    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        out.push_str(&format!("Playbook test failed: {err}\n"));
        if let Some(avail) = v.get("available").and_then(|a| a.as_array()) {
            let ids: Vec<&str> = avail.iter().filter_map(|x| x.as_str()).collect();
            out.push_str(&format!("Available playbooks: {}\n", ids.join(", ")));
        }
        return out;
    }

    let matched = v.get("matched").and_then(|m| m.as_bool()).unwrap_or(false);
    out.push_str(&format!("Playbook: {playbook_id}\n"));
    out.push_str(&format!(
        "Matched:  {}\n",
        if matched { "yes" } else { "no" }
    ));
    if !matched {
        out.push_str("(playbook triggers/conditions did not match this incident)\n");
        return out;
    }

    out.push_str("Dry run:  yes (no skills fired, no audit written)\n");
    if let Some(summary) = v.get("summary").and_then(|s| s.as_str()) {
        out.push_str(&format!("Summary:  {summary}\n"));
    }

    if let Some(steps) = v.pointer("/outcome/steps").and_then(|s| s.as_array()) {
        out.push_str("\nSteps:\n");
        for step in steps {
            let id = step.get("step_id").and_then(|x| x.as_str()).unwrap_or("?");
            let skill = step.get("skill").and_then(|x| x.as_str()).unwrap_or("?");
            let st = step.get("status").and_then(|x| x.as_str()).unwrap_or("?");
            let msg = step.get("message").and_then(|x| x.as_str()).unwrap_or("");
            out.push_str(&format!("  [{st}] {id} ({skill}) - {msg}\n"));
        }
    }

    if let Some(cmds) = v.pointer("/outcome/commands").and_then(|c| c.as_array()) {
        if !cmds.is_empty() {
            out.push_str("\nQueued commands (would run after the playbook):\n");
            for c in cmds {
                let kind = c.get("command").and_then(|x| x.as_str()).unwrap_or("?");
                out.push_str(&format!("  {kind} {c}\n"));
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_error_lists_available() {
        let v = serde_json::json!({
            "error": "unknown playbook",
            "available": ["pb-a", "pb-b"],
        });
        let out = format_test_output("pb-x", &v);
        assert!(out.contains("Playbook test failed: unknown playbook"));
        assert!(out.contains("Available playbooks: pb-a, pb-b"));
    }

    #[test]
    fn format_not_matched() {
        let v = serde_json::json!({ "matched": false });
        let out = format_test_output("pb-x", &v);
        assert!(out.contains("Matched:  no"));
        assert!(out.contains("did not match"));
        assert!(!out.contains("Dry run"));
    }

    #[test]
    fn format_matched_is_deterministic_and_lists_steps_and_commands() {
        let v = serde_json::json!({
            "matched": true,
            "dry_run": true,
            "summary": "playbook pb-x: 1 success, 1 queued",
            "outcome": {
                "steps": [
                    {"step_id": "tarpit", "skill": "block_ip_xdp", "status": "success", "message": "DRY RUN: would block"},
                    {"step_id": "alert", "skill": "route_alert", "status": "queued", "message": "route_alert queued"}
                ],
                "commands": [
                    {"command": "route_alert", "step_id": "alert", "destination": null, "severity_override": null}
                ]
            }
        });
        let out1 = format_test_output("pb-x", &v);
        let out2 = format_test_output("pb-x", &v);
        // Determinism: same input -> byte-identical output.
        assert_eq!(out1, out2);
        assert!(out1.contains("Matched:  yes"));
        assert!(out1.contains("Summary:  playbook pb-x: 1 success, 1 queued"));
        assert!(out1.contains("[success] tarpit (block_ip_xdp)"));
        assert!(out1.contains("[queued] alert (route_alert)"));
        assert!(out1.contains("Queued commands"));
        assert!(out1.contains("route_alert"));
    }

    #[test]
    fn build_agent_constructs_in_both_modes() {
        // Both the verifying and the insecure (cert-skip) agents construct
        // without panicking; the insecure path exercises the TlsConfig builder.
        let _verifying = build_agent(false);
        let _insecure = build_agent(true);
    }

    #[test]
    fn read_incident_uses_first_nonempty_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inc.jsonl");
        std::fs::write(
            &path,
            "\n  \n{\"incident_id\":\"x:1\",\"host\":\"h\"}\n{\"other\":1}\n",
        )
        .unwrap();
        let v = read_incident_json(&path).unwrap();
        assert_eq!(v["incident_id"], "x:1");
    }

    #[test]
    fn read_incident_rejects_empty_and_bad_json() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.jsonl");
        std::fs::write(&empty, "\n\n").unwrap();
        assert!(read_incident_json(&empty).is_err());

        let bad = dir.path().join("bad.jsonl");
        std::fs::write(&bad, "not json\n").unwrap();
        assert!(read_incident_json(&bad).is_err());
    }
}
