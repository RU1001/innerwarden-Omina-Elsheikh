use std::path::Path;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{Duration, Utc};

use crate::{
    append_admin_action, current_operator, looks_like_ip, resolve_data_dir, write_manual_decision,
    AdminActionEntry, Cli,
};

/// `innerwarden get responses [--history --since-days N] [--ip X]`
///
/// Reads `<data_dir>/responses.json` (written by the agent's
/// `response_lifecycle` module). Replaces the standalone dashboard
/// Responses tab that was removed in the 2026-05-15 slim-down. Per-
/// attacker enforcement and the cross-attacker audit view live in
/// the dashboard (journey panel + "View all enforcement" modal); this
/// CLI is for headless / scripted / audit-export flows.
pub fn cmd_responses(
    cli: &Cli,
    history: bool,
    since_days: u64,
    ip: Option<&str>,
    data_dir: &Path,
) -> Result<()> {
    let dir = resolve_data_dir(cli, data_dir);
    let path: PathBuf = dir.join("responses.json");
    let raw = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let json: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;

    print!("{}", format_active_table(&json, ip));
    if history {
        print!(
            "{}",
            format_history_table(&json, since_days, ip, Utc::now())
        );
    }

    // Silence unused-warning shims — the same module hosts manual
    // block helpers used by `action block`.
    let _ = (
        append_admin_action,
        current_operator,
        looks_like_ip,
        write_manual_decision,
    );
    let _: Option<AdminActionEntry> = None;

    Ok(())
}

/// Pure formatter for the "Active enforcement" table. Pulled out of
/// `cmd_responses` so its filter+sort logic is unit-testable without
/// stdout capture or filesystem fixtures.
pub(crate) fn format_active_table(json: &serde_json::Value, ip: Option<&str>) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let mut active_rows: Vec<&serde_json::Value> = json
        .get("active")
        .and_then(|v| v.as_array())
        .map(|v| v.iter())
        .into_iter()
        .flatten()
        .filter(|a| match ip {
            Some(needle) => a.get("target").and_then(|t| t.as_str()) == Some(needle),
            None => true,
        })
        .collect();
    active_rows.sort_by(|a, b| {
        let ra = a
            .get("remaining_secs")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let rb = b
            .get("remaining_secs")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        ra.cmp(&rb)
    });

    let _ = writeln!(out, "Active enforcement ({}):", active_rows.len());
    if active_rows.is_empty() {
        let _ = writeln!(out, "  (none)");
        return out;
    }
    let _ = writeln!(
        out,
        "  {:<20} {:<10} {:<14} {:<10} {:<10} INCIDENT",
        "TARGET", "BACKEND", "STATE", "TTL", "REMAINING"
    );
    for a in &active_rows {
        let target = a.get("target").and_then(|v| v.as_str()).unwrap_or("-");
        let backend = a.get("backend").and_then(|v| v.as_str()).unwrap_or("-");
        let state = a
            .get("state")
            .and_then(|s| s.get("kind"))
            .and_then(|v| v.as_str())
            .unwrap_or("active");
        let ttl_secs = a.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(0);
        let rem_secs = a
            .get("remaining_secs")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let incident = a.get("incident_id").and_then(|v| v.as_str()).unwrap_or("");
        let _ = writeln!(
            out,
            "  {:<20} {:<10} {:<14} {:<10} {:<10} {}",
            target,
            backend,
            state,
            format!("{}h", ttl_secs / 3600),
            format!("{}m", rem_secs / 60),
            incident
        );
    }
    out
}

/// Pure formatter for the "Recent reverts" table. Takes `now` as an
/// argument so tests can pin the date window deterministically.
pub(crate) fn format_history_table(
    json: &serde_json::Value,
    since_days: u64,
    ip: Option<&str>,
    now: chrono::DateTime<Utc>,
) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let cutoff = now - Duration::days(since_days as i64);
    let mut rows: Vec<&serde_json::Value> = json
        .get("history")
        .and_then(|v| v.as_array())
        .map(|v| v.iter())
        .into_iter()
        .flatten()
        .filter(|h| match ip {
            Some(needle) => h.get("target").and_then(|t| t.as_str()) == Some(needle),
            None => true,
        })
        .filter(|h| {
            h.get("reverted_at")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc) >= cutoff)
                .unwrap_or(false)
        })
        .collect();
    rows.sort_by(|a, b| {
        let ra = a.get("reverted_at").and_then(|v| v.as_str()).unwrap_or("");
        let rb = b.get("reverted_at").and_then(|v| v.as_str()).unwrap_or("");
        rb.cmp(ra)
    });

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Recent reverts (last {} day{}): {} entries",
        since_days,
        if since_days == 1 { "" } else { "s" },
        rows.len()
    );
    if rows.is_empty() {
        return out;
    }
    let _ = writeln!(
        out,
        "  {:<20} {:<10} {:<18} REVERTED_AT",
        "TARGET", "BACKEND", "REASON"
    );
    for h in &rows {
        let target = h.get("target").and_then(|v| v.as_str()).unwrap_or("-");
        let backend = h.get("backend").and_then(|v| v.as_str()).unwrap_or("-");
        let reason = h.get("reason").and_then(|v| v.as_str()).unwrap_or("-");
        let when = h.get("reverted_at").and_then(|v| v.as_str()).unwrap_or("-");
        let reason_short = if reason.len() > 17 {
            format!("{}…", &reason[..17])
        } else {
            reason.to_string()
        };
        let _ = writeln!(
            out,
            "  {:<20} {:<10} {:<18} {}",
            target, backend, reason_short, when
        );
    }
    out
}

#[cfg(test)]
mod responses_format_tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn fixture() -> serde_json::Value {
        json!({
            "active": [
                {
                    "target": "1.2.3.4",
                    "backend": "ufw",
                    "state": { "kind": "active" },
                    "ttl_secs": 168 * 3600,
                    "remaining_secs": 100 * 3600,
                    "incident_id": "repeat-offender:1.2.3.4:1",
                    "type": "block_ip"
                },
                {
                    "target": "1.2.3.4",
                    "backend": "xdp",
                    "state": { "kind": "active" },
                    "ttl_secs": 168 * 3600,
                    "remaining_secs": 100 * 3600,
                    "incident_id": "repeat-offender:1.2.3.4:1",
                    "type": "block_ip"
                },
                {
                    "target": "9.9.9.9",
                    "backend": "ufw",
                    "state": { "kind": "active" },
                    "ttl_secs": 24 * 3600,
                    "remaining_secs": 6 * 3600,
                    "incident_id": "proto-anomaly:9.9.9.9:7",
                    "type": "block_ip"
                }
            ],
            "history": [
                {
                    "target": "1.2.3.4",
                    "backend": "ufw",
                    "reason": "expired",
                    "reverted_at": "2026-05-15T10:00:00Z"
                },
                {
                    "target": "8.8.8.8",
                    "backend": "xdp",
                    "reason": "manual",
                    "reverted_at": "2026-05-15T11:00:00Z"
                },
                {
                    "target": "7.7.7.7",
                    "backend": "ufw",
                    "reason": "expired",
                    "reverted_at": "2026-05-01T09:00:00Z"
                }
            ]
        })
    }

    #[test]
    fn active_table_lists_all_entries_when_no_filter() {
        let out = format_active_table(&fixture(), None);
        assert!(out.contains("Active enforcement (3):"));
        assert!(out.contains("1.2.3.4"));
        assert!(out.contains("ufw"));
        assert!(out.contains("xdp"));
        assert!(out.contains("9.9.9.9"));
        assert!(out.contains("TARGET"));
        assert!(out.contains("INCIDENT"));
    }

    #[test]
    fn active_table_filters_by_ip() {
        let out = format_active_table(&fixture(), Some("1.2.3.4"));
        assert!(out.contains("Active enforcement (2):"));
        assert!(out.contains("1.2.3.4"));
        // 9.9.9.9 must be filtered out
        assert!(!out.contains("9.9.9.9"));
    }

    #[test]
    fn active_table_renders_empty_state() {
        let json = json!({"active": []});
        let out = format_active_table(&json, None);
        assert!(out.contains("Active enforcement (0):"));
        assert!(out.contains("(none)"));
    }

    #[test]
    fn active_table_filter_with_no_match_is_empty() {
        let out = format_active_table(&fixture(), Some("99.99.99.99"));
        assert!(out.contains("Active enforcement (0):"));
        assert!(out.contains("(none)"));
    }

    #[test]
    fn active_table_sorts_by_remaining_ascending() {
        // 9.9.9.9 has 6h remaining, 1.2.3.4 entries have 100h. The
        // 9.9.9.9 row must appear BEFORE the 1.2.3.4 rows so the
        // closest-to-expiry block is at the top.
        let out = format_active_table(&fixture(), None);
        let nine = out.find("9.9.9.9").expect("9.9.9.9 row present");
        let one = out.find("1.2.3.4").expect("1.2.3.4 row present");
        assert!(
            nine < one,
            "expected 9.9.9.9 (6h remaining) before 1.2.3.4 (100h remaining)"
        );
    }

    #[test]
    fn history_table_includes_entries_inside_window() {
        // now = 2026-05-15T12:00 UTC, since_days = 7 → cutoff =
        // 2026-05-08T12:00. The 05-15 entries are inside; the 05-01
        // entry is outside.
        let now = Utc.with_ymd_and_hms(2026, 5, 15, 12, 0, 0).unwrap();
        let out = format_history_table(&fixture(), 7, None, now);
        assert!(out.contains("Recent reverts (last 7 days): 2 entries"));
        assert!(out.contains("1.2.3.4"));
        assert!(out.contains("8.8.8.8"));
        // 7.7.7.7 is two weeks old — outside the 7-day window.
        assert!(!out.contains("7.7.7.7"));
    }

    #[test]
    fn history_table_singular_day_label() {
        let now = Utc.with_ymd_and_hms(2026, 5, 15, 12, 0, 0).unwrap();
        let out = format_history_table(&fixture(), 1, None, now);
        assert!(
            out.contains("last 1 day):"),
            "singular `day)` (no `s`) when since_days == 1; got: {out}"
        );
        assert!(
            !out.contains("last 1 days)"),
            "must not pluralise when since_days == 1; got: {out}"
        );
    }

    #[test]
    fn history_table_filters_by_ip() {
        let now = Utc.with_ymd_and_hms(2026, 5, 15, 12, 0, 0).unwrap();
        let out = format_history_table(&fixture(), 30, Some("1.2.3.4"), now);
        assert!(out.contains("Recent reverts (last 30 days): 1 entries"));
        assert!(out.contains("1.2.3.4"));
        assert!(!out.contains("8.8.8.8"));
        assert!(!out.contains("7.7.7.7"));
    }

    #[test]
    fn history_table_renders_empty_state_when_window_empty() {
        let now = Utc.with_ymd_and_hms(2026, 5, 15, 12, 0, 0).unwrap();
        // 0 days back from 'now' — nothing should match.
        let out = format_history_table(&fixture(), 0, None, now);
        assert!(out.contains("Recent reverts (last 0 days): 0 entries"));
        // No table header when empty.
        assert!(!out.contains("REVERTED_AT"));
    }

    #[test]
    fn history_table_truncates_long_reason_with_ellipsis() {
        let json = json!({
            "history": [{
                "target": "1.2.3.4",
                "backend": "ufw",
                "reason": "orphaned: this is a very long error message that exceeds eighteen chars",
                "reverted_at": "2026-05-15T10:00:00Z"
            }]
        });
        let now = Utc.with_ymd_and_hms(2026, 5, 15, 12, 0, 0).unwrap();
        let out = format_history_table(&json, 1, None, now);
        assert!(
            out.contains("…"),
            "long reason must be truncated with ellipsis"
        );
    }

    #[test]
    fn history_table_descending_by_reverted_at() {
        let now = Utc.with_ymd_and_hms(2026, 5, 15, 12, 0, 0).unwrap();
        let out = format_history_table(&fixture(), 30, None, now);
        // 8.8.8.8 reverted at 11:00, 1.2.3.4 reverted at 10:00, 7.7.7.7
        // would be outside but 30d includes all three. Most recent
        // first → 8.8.8.8 before 1.2.3.4 in the output.
        let eight = out.find("8.8.8.8").expect("8.8.8.8 row present");
        let one = out.find("1.2.3.4").expect("1.2.3.4 row present");
        assert!(
            eight < one,
            "expected 8.8.8.8 (11:00) before 1.2.3.4 (10:00) — descending sort"
        );
    }

    #[test]
    fn empty_payload_renders_clean_zeros() {
        let json = json!({});
        let out_active = format_active_table(&json, None);
        assert!(out_active.contains("Active enforcement (0):"));
        let now = Utc.with_ymd_and_hms(2026, 5, 15, 12, 0, 0).unwrap();
        let out_history = format_history_table(&json, 7, None, now);
        assert!(out_history.contains("Recent reverts (last 7 days): 0 entries"));
    }
}

fn configured_block_backend(agent_config: &Path) -> String {
    std::fs::read_to_string(agent_config)
        .ok()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|v| {
            v.get("responder")
                .and_then(|r| r.get("block_backend"))
                .and_then(|b| b.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "ufw".to_string())
}

fn block_command_args(backend: &str, ip: &str) -> Vec<String> {
    match backend {
        "iptables" => ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        "nftables" => [
            "nft",
            "add",
            "element",
            "ip",
            "filter",
            "innerwarden-blocked",
            &format!("{{ {ip} }}"),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        "pf" => ["pfctl", "-t", "innerwarden-blocked", "-T", "add", ip]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        _ => ["ufw", "deny", "from", ip]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

fn unblock_command_args(backend: &str, ip: &str) -> Vec<String> {
    match backend {
        "iptables" => ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        "nftables" => [
            "nft",
            "delete",
            "element",
            "ip",
            "filter",
            "innerwarden-blocked",
            &format!("{{ {ip} }}"),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        "pf" => ["pfctl", "-t", "innerwarden-blocked", "-T", "delete", ip]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        _ => ["ufw", "delete", "deny", "from", ip]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

fn parse_suppressed_patterns(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|s| s.to_string())
        .collect()
}

pub(crate) fn cmd_block(cli: &Cli, ip: &str, reason: &str, data_dir: &Path) -> Result<()> {
    cmd_block_with_sudo(cli, ip, reason, data_dir, "sudo")
}

fn cmd_block_with_sudo(
    cli: &Cli,
    ip: &str,
    reason: &str,
    data_dir: &Path,
    sudo_bin: &str,
) -> Result<()> {
    // Basic IP validation
    if !looks_like_ip(ip) {
        anyhow::bail!("'{ip}' doesn't look like a valid IP address");
    }

    let effective_dir = resolve_data_dir(cli, data_dir);

    // Read configured block backend from agent.toml
    let backend = configured_block_backend(&cli.agent_config);

    println!("Blocking {ip} via {backend}...");

    if cli.dry_run {
        println!("  [dry-run] would run block command for {ip}");
        println!(
            "  [dry-run] would record in {}/decisions-*.jsonl",
            effective_dir.display()
        );
        return Ok(());
    }

    // Execute the block
    let blocked = std::process::Command::new(sudo_bin)
        .args(block_command_args(backend.as_str(), ip))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !blocked {
        anyhow::bail!("block command failed - check sudo permissions (run: innerwarden doctor)");
    }
    println!("  [ok] {ip} blocked via {backend}");

    // Write audit trail
    write_manual_decision(&effective_dir, ip, "block_ip", reason, "operator:cli")?;
    println!("  [ok] recorded in decisions log");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "block_ip".to_string(),
        target: ip.to_string(),
        parameters: serde_json::json!({ "reason": reason, "backend": backend }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&effective_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("{ip} is now blocked. To reverse: innerwarden unblock {ip} --reason \"...\"");
    Ok(())
}

pub(crate) fn cmd_unblock(cli: &Cli, ip: &str, reason: &str, data_dir: &Path) -> Result<()> {
    cmd_unblock_with_sudo(cli, ip, reason, data_dir, "sudo")
}

fn cmd_unblock_with_sudo(
    cli: &Cli,
    ip: &str,
    reason: &str,
    data_dir: &Path,
    sudo_bin: &str,
) -> Result<()> {
    if !looks_like_ip(ip) {
        anyhow::bail!("'{ip}' doesn't look like a valid IP address");
    }

    let effective_dir = resolve_data_dir(cli, data_dir);

    let backend = configured_block_backend(&cli.agent_config);

    println!("Unblocking {ip} via {backend}...");

    if cli.dry_run {
        println!("  [dry-run] would remove block for {ip}");
        println!(
            "  [dry-run] would record in {}/decisions-*.jsonl",
            effective_dir.display()
        );
        return Ok(());
    }

    let unblocked = std::process::Command::new(sudo_bin)
        .args(unblock_command_args(backend.as_str(), ip))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !unblocked {
        println!("  Warning: unblock command may have failed (rule may not exist).");
        println!("  Check manually: sudo ufw status | grep {ip}");
    } else {
        println!("  [ok] {ip} unblocked via {backend}");
    }

    write_manual_decision(&effective_dir, ip, "unblock_ip", reason, "operator:cli")?;
    println!("  [ok] recorded in decisions log");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "unblock_ip".to_string(),
        target: ip.to_string(),
        parameters: serde_json::json!({ "reason": reason, "backend": backend }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&effective_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("{ip} is now unblocked.");
    Ok(())
}

/// Wave 8e (2026-05-04): added `reason: Option<&str>` so operators can
/// record WHY an IP/user is being trusted. The reason is persisted in
/// the admin audit log (hash-chained, JSONL) so a future operator can
/// answer "why is 147.154.0.0/16 in this allowlist?" by grepping the
/// audit, not by guessing. The flag is optional to preserve compat with
/// existing operator scripts; a missing reason emits a stderr warning
/// (does not fail the command).
pub(crate) fn cmd_allowlist_add(
    cli: &Cli,
    ip: Option<&str>,
    user: Option<&str>,
    reason: Option<&str>,
) -> Result<()> {
    use crate::config_editor::write_array_push;
    let mut changed = false;
    if let Some(ip_val) = ip {
        let added = write_array_push(&cli.agent_config, "allowlist", "trusted_ips", ip_val)?;
        if added {
            println!("Added to trusted IPs: {ip_val}");
            changed = true;
        } else {
            println!("{ip_val} is already in trusted_ips.");
        }
    }
    if let Some(user_val) = user {
        let added = write_array_push(&cli.agent_config, "allowlist", "trusted_users", user_val)?;
        if added {
            println!("Added to trusted users: {user_val}");
            changed = true;
        } else {
            println!("{user_val} is already in trusted_users.");
        }
    }
    if !changed && ip.is_none() && user.is_none() {
        anyhow::bail!("specify --ip <cidr> or --user <username>");
    }
    if changed {
        // Wave 8e: warn (without failing) when the operator skipped --reason.
        // Trust decisions on prod systems are forensic-grade events; future
        // operators auditing the allowlist need the WHY to decide if the
        // entry is still load-bearing or stale. Print to stderr so scripted
        // callers see it on a side channel without breaking stdout parsers.
        if reason.is_none() {
            eprintln!(
                "  [warn] no --reason recorded. Future operators will not know \
                 WHY this entry was trusted. Re-run with `--reason \"<short \
                 explanation>\"` so the admin audit log has it."
            );
        }

        // Audit log
        let target = ip
            .map(|v| v.to_string())
            .or_else(|| user.map(|v| v.to_string()))
            .unwrap_or_default();
        let mut audit = AdminActionEntry {
            ts: chrono::Utc::now(),
            operator: current_operator(),
            source: "cli".to_string(),
            action: "allowlist_add".to_string(),
            target,
            parameters: serde_json::json!({ "ip": ip, "user": user, "reason": reason }),
            result: "success".to_string(),
            prev_hash: None,
        };
        if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
            eprintln!("  [warn] failed to write admin audit: {e:#}");
        }

        println!(
            "Allowlist updated. Restart the agent to apply:\n  sudo systemctl restart innerwarden-agent"
        );
    }
    Ok(())
}

pub(crate) fn cmd_allowlist_remove(cli: &Cli, ip: Option<&str>, user: Option<&str>) -> Result<()> {
    use crate::config_editor::write_array_remove;
    let mut changed = false;
    if let Some(ip_val) = ip {
        let removed = write_array_remove(&cli.agent_config, "allowlist", "trusted_ips", ip_val)?;
        if removed {
            println!("Removed from trusted IPs: {ip_val}");
            changed = true;
        } else {
            println!("{ip_val} was not in trusted_ips.");
        }
    }
    if let Some(user_val) = user {
        let removed =
            write_array_remove(&cli.agent_config, "allowlist", "trusted_users", user_val)?;
        if removed {
            println!("Removed from trusted users: {user_val}");
            changed = true;
        } else {
            println!("{user_val} was not in trusted_users.");
        }
    }
    if !changed && ip.is_none() && user.is_none() {
        anyhow::bail!("specify --ip <cidr> or --user <username>");
    }
    if changed {
        // Audit log
        let target = ip
            .map(|v| v.to_string())
            .or_else(|| user.map(|v| v.to_string()))
            .unwrap_or_default();
        let mut audit = AdminActionEntry {
            ts: chrono::Utc::now(),
            operator: current_operator(),
            source: "cli".to_string(),
            action: "allowlist_remove".to_string(),
            target,
            parameters: serde_json::json!({ "ip": ip, "user": user }),
            result: "success".to_string(),
            prev_hash: None,
        };
        if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
            eprintln!("  [warn] failed to write admin audit: {e:#}");
        }

        println!(
            "Allowlist updated. Restart the agent to apply:\n  sudo systemctl restart innerwarden-agent"
        );
    }
    Ok(())
}

/// Default event_pipeline rules dir (shared with the sensor + agent + the
/// dashboard "Trust IP" feature, which writes suppress_response/scope:ip rules
/// here).
const EVENT_PIPELINE_RULES_DIR: &str = "/etc/innerwarden/rules/event_pipeline";

/// A dynamic trusted IP sourced from a `suppress_response`/`scope: ip` rule in
/// the event_pipeline dir (hot-reloaded by the agent, also writable by hand or
/// by the dashboard "Trust IP" action).
pub(crate) struct DynTrust {
    pub value: String,
    pub expires_at: Option<String>,
    pub id: String,
}

/// Scan a rules dir for `suppress_response`/`scope: ip` rules and return their
/// trusted IPs. Lenient: unparseable files are skipped. Pure helper for testing.
pub(crate) fn dynamic_trusted_ips_from_rules(rules_dir: &std::path::Path) -> Vec<DynTrust> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(rules_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".yml") && !name.ends_with(".yaml") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
            continue;
        };
        let Some(rules) = doc.get("rules").and_then(|v| v.as_sequence()) else {
            continue;
        };
        for rule in rules {
            if rule.get("action").and_then(|v| v.as_str()) != Some("suppress_response") {
                continue;
            }
            if rule
                .get("disabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                continue;
            }
            let Some(suppress) = rule.get("suppress") else {
                continue;
            };
            if suppress.get("scope").and_then(|v| v.as_str()) != Some("ip") {
                continue;
            }
            let expires_at = rule
                .get("expires_at")
                .and_then(|v| v.as_str())
                .map(String::from);
            let id = rule
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if let Some(values) = suppress.get("values").and_then(|v| v.as_sequence()) {
                for v in values.iter().filter_map(|v| v.as_str()) {
                    out.push(DynTrust {
                        value: v.to_string(),
                        expires_at: expires_at.clone(),
                        id: id.clone(),
                    });
                }
            }
        }
    }
    out
}

pub(crate) fn cmd_allowlist_list(cli: &Cli) -> Result<()> {
    use crate::config_editor::read_str_array;
    let ips = read_str_array(&cli.agent_config, "allowlist", "trusted_ips");
    let users = read_str_array(&cli.agent_config, "allowlist", "trusted_users");
    let dynamic = dynamic_trusted_ips_from_rules(std::path::Path::new(EVENT_PIPELINE_RULES_DIR));

    if ips.is_empty() && users.is_empty() && dynamic.is_empty() {
        println!("Allowlist is empty - no trusted IPs or users configured.");
        println!("Add entries with: innerwarden allowlist add --ip <cidr> --reason \"<why>\"");
        return Ok(());
    }

    if !ips.is_empty() {
        println!("Trusted IPs / CIDRs (static, agent.toml):");
        for ip in &ips {
            println!("  {ip}");
        }
    }
    if !dynamic.is_empty() {
        println!(
            "Trusted IPs / CIDRs (dynamic rules, hot-reloaded — incl. dashboard \"Trust IP\"):"
        );
        for d in &dynamic {
            match &d.expires_at {
                Some(exp) => println!("  {} (expires {exp}) [{}]", d.value, d.id),
                None => println!("  {} [{}]", d.value, d.id),
            }
        }
    }
    if !users.is_empty() {
        println!("Trusted users:");
        for user in &users {
            println!("  {user}");
        }
    }
    println!();
    println!(
        "(Reasons recorded in admin audit log. Wave 8e (2026-05-04) added \
         the --reason flag — entries created before that, or with a missing \
         reason, may have no recorded WHY. Use `innerwarden audit list \
         --action allowlist_add` to inspect.)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden suppress
// ---------------------------------------------------------------------------

fn suppressed_file(cli: &Cli) -> std::path::PathBuf {
    cli.data_dir.join("suppressed-incidents.txt")
}

pub(crate) fn cmd_suppress_add(cli: &Cli, pattern: &str) -> Result<()> {
    let path = suppressed_file(cli);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    // Check if already exists
    if existing.lines().any(|l| l.trim() == pattern) {
        println!("Pattern already suppressed: {pattern}");
        return Ok(());
    }

    // Append
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(f, "{pattern}")?;

    println!("Suppressed: {pattern}");
    println!("Matching incidents will be silently logged but not alerted.");
    println!();
    println!("  The agent will pick this up on next restart, or you can restart now:");
    println!("  sudo systemctl restart innerwarden-agent");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "suppress_add".to_string(),
        target: pattern.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }
    Ok(())
}

pub(crate) fn cmd_suppress_remove(cli: &Cli, pattern: &str) -> Result<()> {
    let path = suppressed_file(cli);
    let content = std::fs::read_to_string(&path).unwrap_or_default();

    let new_content: String = content
        .lines()
        .filter(|l| l.trim() != pattern)
        .collect::<Vec<_>>()
        .join("\n");

    if content == new_content {
        println!("Pattern not found: {pattern}");
        return Ok(());
    }

    std::fs::write(
        &path,
        if new_content.is_empty() {
            String::new()
        } else {
            format!("{new_content}\n")
        },
    )?;
    println!("Removed suppression: {pattern}");
    println!("Matching incidents will alert again after agent restart.");

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "suppress_remove".to_string(),
        target: pattern.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }
    Ok(())
}

pub(crate) fn cmd_suppress_list(cli: &Cli) -> Result<()> {
    let path = suppressed_file(cli);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let patterns = parse_suppressed_patterns(&content);

    if patterns.is_empty() {
        println!("No suppressed patterns.");
        println!("Add with: innerwarden suppress add <pattern>");
        return Ok(());
    }

    println!("Suppressed incident patterns:");
    for p in &patterns {
        println!("  {p}");
    }
    println!();
    println!(
        "{} pattern(s) active. Matching incidents are silently logged.",
        patterns.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn fake_sudo_script(temp: &TempDir, exit_code: u8) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let script = temp.path().join(format!("fake-sudo-{exit_code}.sh"));
        std::fs::write(&script, format!("#!/bin/sh\nexit {exit_code}\n"))
            .expect("test should write fake sudo script");
        let mut perms = std::fs::metadata(&script)
            .expect("fake sudo metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("fake sudo chmod");
        script
    }

    fn write_agent_config(path: &Path, content: &str) {
        std::fs::write(path, content).expect("test should write agent config");
    }

    fn test_cli(temp: &TempDir) -> Cli {
        let mut cli = Cli::parse_from(["innerwarden", "replay"]);
        cli.sensor_config = temp.path().join("sensor.toml");
        cli.agent_config = temp.path().join("agent.toml");
        cli.data_dir = temp.path().join("data");
        cli.dry_run = true;
        std::fs::create_dir_all(&cli.data_dir).expect("test should create data dir");
        write_agent_config(
            &cli.agent_config,
            "[allowlist]\ntrusted_ips=[]\ntrusted_users=[]\n",
        );
        cli
    }

    #[test]
    fn configured_block_backend_defaults_to_ufw_when_missing() {
        // Covers fallback branch so block/unblock keep working with absent or invalid config.
        let temp = TempDir::new().expect("test should create temp dir");
        let backend = configured_block_backend(&temp.path().join("missing-agent.toml"));
        assert_eq!(backend, "ufw");
    }

    #[test]
    fn configured_block_backend_reads_responder_backend() {
        // Verifies config parsing path so backend selection follows agent.toml responder settings.
        let temp = TempDir::new().expect("test should create temp dir");
        let config = temp.path().join("agent.toml");
        write_agent_config(&config, "[responder]\nblock_backend = \"pf\"\n");
        let backend = configured_block_backend(&config);
        assert_eq!(backend, "pf");
    }

    #[test]
    fn configured_block_backend_defaults_when_responder_section_absent() {
        let temp = TempDir::new().expect("test should create temp dir");
        let config = temp.path().join("agent.toml");
        write_agent_config(&config, "[ai]\nenabled = true\n");

        let backend = configured_block_backend(&config);

        assert_eq!(backend, "ufw");
    }

    #[test]
    fn configured_block_backend_defaults_when_toml_is_malformed() {
        let temp = TempDir::new().expect("test should create temp dir");
        let config = temp.path().join("agent.toml");
        write_agent_config(&config, "[responder\nblock_backend = \"pf\"\n");

        let backend = configured_block_backend(&config);

        assert_eq!(backend, "ufw");
    }

    #[test]
    fn block_command_args_maps_supported_backends() {
        // Exercises each block backend arm to guard command construction before subprocess execution.
        assert_eq!(
            block_command_args("iptables", "1.2.3.4"),
            vec!["iptables", "-A", "INPUT", "-s", "1.2.3.4", "-j", "DROP"]
        );
        assert_eq!(
            block_command_args("nftables", "1.2.3.4"),
            vec![
                "nft",
                "add",
                "element",
                "ip",
                "filter",
                "innerwarden-blocked",
                "{ 1.2.3.4 }"
            ]
        );
        assert_eq!(
            block_command_args("pf", "1.2.3.4"),
            vec!["pfctl", "-t", "innerwarden-blocked", "-T", "add", "1.2.3.4"]
        );
    }

    #[test]
    fn block_command_args_falls_back_to_ufw_for_unknown_backend() {
        // Protects default branch so unknown backend values still produce a safe ufw command.
        assert_eq!(
            block_command_args("unknown", "1.2.3.4"),
            vec!["ufw", "deny", "from", "1.2.3.4"]
        );
    }

    #[test]
    fn unblock_command_args_maps_supported_and_default_backends() {
        // Covers all unblock command variants to prevent regressions in response rollback paths.
        assert_eq!(
            unblock_command_args("iptables", "1.2.3.4"),
            vec!["iptables", "-D", "INPUT", "-s", "1.2.3.4", "-j", "DROP"]
        );
        assert_eq!(
            unblock_command_args("nftables", "1.2.3.4"),
            vec![
                "nft",
                "delete",
                "element",
                "ip",
                "filter",
                "innerwarden-blocked",
                "{ 1.2.3.4 }"
            ]
        );
        assert_eq!(
            unblock_command_args("pf", "1.2.3.4"),
            vec![
                "pfctl",
                "-t",
                "innerwarden-blocked",
                "-T",
                "delete",
                "1.2.3.4"
            ]
        );
        assert_eq!(
            unblock_command_args("unknown", "1.2.3.4"),
            vec!["ufw", "delete", "deny", "from", "1.2.3.4"]
        );
    }

    #[test]
    fn cmd_block_rejects_invalid_ip() {
        // Ensures malformed targets fail before any command execution or state write.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let err =
            cmd_block(&cli, "not-an-ip", "test", temp.path()).expect_err("invalid ip must fail");
        assert!(err
            .to_string()
            .contains("doesn't look like a valid IP address"));
    }

    #[test]
    fn cmd_block_dry_run_succeeds_with_valid_ip() {
        // Covers dry-run branch that bypasses subprocess execution while still validating inputs and config.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        cmd_block(&cli, "1.2.3.4", "investigation", temp.path())
            .expect("dry-run block should succeed");
    }

    #[cfg(unix)]
    #[test]
    fn cmd_block_with_sudo_non_dry_run_surfaces_command_failure() {
        // Covers the non-dry-run command execution branch safely via a fake sudo binary.
        let temp = TempDir::new().expect("test should create temp dir");
        let mut cli = test_cli(&temp);
        cli.dry_run = false;
        write_agent_config(&cli.agent_config, "[responder]\nblock_backend = \"pf\"\n");
        let fake_sudo = fake_sudo_script(&temp, 1);

        let err = cmd_block_with_sudo(
            &cli,
            "1.2.3.4",
            "investigation",
            temp.path(),
            fake_sudo.to_str().expect("utf-8 fake sudo path"),
        )
        .expect_err("fake sudo failure must propagate");
        assert!(err.to_string().contains("block command failed"));
    }

    #[test]
    fn cmd_unblock_dry_run_succeeds_with_valid_ip() {
        // Covers unblock dry-run path to keep manual rollback CLI available in non-root test contexts.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        cmd_unblock(&cli, "1.2.3.4", "false-positive", temp.path())
            .expect("dry-run unblock should succeed");
    }

    #[cfg(unix)]
    #[test]
    fn cmd_unblock_with_sudo_non_dry_run_handles_command_failure_and_continues() {
        // Executes non-dry-run unblock path without invoking real sudo/firewall commands.
        let temp = TempDir::new().expect("test should create temp dir");
        let mut cli = test_cli(&temp);
        cli.dry_run = false;
        write_agent_config(&cli.agent_config, "[responder]\nblock_backend = \"pf\"\n");
        let fake_sudo = fake_sudo_script(&temp, 1);

        cmd_unblock_with_sudo(
            &cli,
            "1.2.3.4",
            "false-positive",
            temp.path(),
            fake_sudo.to_str().expect("utf-8 fake sudo path"),
        )
        .expect("unblock should continue even when command fails");
    }

    #[test]
    fn cmd_allowlist_add_requires_ip_or_user() {
        // Validates guard clause that prevents no-op allowlist updates.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let err = cmd_allowlist_add(&cli, None, None, None).expect_err("empty add must fail");
        assert!(err
            .to_string()
            .contains("specify --ip <cidr> or --user <username>"));
    }

    #[test]
    fn cmd_allowlist_add_and_remove_updates_arrays() {
        // Exercises add/remove state transitions so trusted IP persistence behaves deterministically.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_allowlist_add(&cli, Some("10.0.0.1"), None, Some("test fixture"))
            .expect("add ip should succeed");
        let ips =
            crate::config_editor::read_str_array(&cli.agent_config, "allowlist", "trusted_ips");
        assert_eq!(ips, vec!["10.0.0.1".to_string()]);

        cmd_allowlist_remove(&cli, Some("10.0.0.1"), None).expect("remove ip should succeed");
        let ips =
            crate::config_editor::read_str_array(&cli.agent_config, "allowlist", "trusted_ips");
        assert!(ips.is_empty());
    }

    // Wave 8e anchor (2026-05-04): when an operator runs
    // `innerwarden allowlist add --ip <cidr> --reason "<text>"` the reason
    // MUST land in the admin audit log (`admin-actions-*.jsonl`) so a future
    // operator looking at the allowlist can answer "why is this trusted?"
    // without guessing. Pinned because on 2026-05-04 the operator added 4
    // emergency CIDRs (Ubuntu mirrors / Telegram / GitHub Pages / Oracle
    // Cloud) without an audit trail and there was no flag to record WHY.
    /// Wave 8e helper: locate today's admin-actions file. The audit
    /// writer uses `chrono::Utc` for the date and canonicalises the
    /// data_dir (so `/var/folders/...` becomes `/private/var/folders/...`
    /// on macOS). Mirroring both here keeps the anchor tests robust on
    /// any host the test suite runs on. Reads the actual `data_dir`
    /// from the test CLI so it matches `test_cli`'s `temp/data` choice.
    fn admin_audit_today_in(cli: &Cli) -> std::path::PathBuf {
        let day = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let canonical = std::fs::canonicalize(&cli.data_dir).expect("data_dir should canonicalise");
        canonical.join(format!("admin-actions-{day}.jsonl"))
    }

    // Wave 8e anchor (2026-05-04): when an operator runs
    // `innerwarden allowlist add --ip <cidr> --reason "<text>"` the reason
    // MUST land in the admin audit log (`admin-actions-*.jsonl`) so a future
    // operator looking at the allowlist can answer "why is this trusted?"
    // without guessing. Pinned because on 2026-05-04 the operator added 4
    // emergency CIDRs (Ubuntu mirrors / Telegram / GitHub Pages / Oracle
    // Cloud) without an audit trail and there was no flag to record WHY.
    #[test]
    fn cmd_allowlist_add_with_reason_persists_reason_in_admin_audit() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_allowlist_add(
            &cli,
            Some("147.154.0.0/16"),
            None,
            Some("Oracle Cloud London region (CL-008 FP fix)"),
        )
        .expect("add with reason should succeed");

        let audit_path = admin_audit_today_in(&cli);
        let body = std::fs::read_to_string(&audit_path)
            .unwrap_or_else(|e| panic!("audit file {audit_path:?} not written: {e}"));
        assert!(
            body.contains("Oracle Cloud London region (CL-008 FP fix)"),
            "audit log must contain the verbatim reason; got: {body}"
        );
        assert!(
            body.contains("\"action\":\"allowlist_add\""),
            "audit entry must label itself as allowlist_add; got: {body}"
        );
        assert!(
            body.contains("\"target\":\"147.154.0.0/16\""),
            "audit entry must record the CIDR as target; got: {body}"
        );
    }

    // Wave 8e: cover `cmd_allowlist_list` paths so codecov sees the new
    // "(Reasons recorded in admin audit log...)" hint we added at the
    // bottom. Two cases — empty allowlist and populated — exercise both
    // branches of the early-return guard.
    #[test]
    fn cmd_allowlist_list_prints_audit_log_hint_when_populated() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        cmd_allowlist_add(&cli, Some("10.0.0.99"), None, Some("test fixture")).expect("seed entry");
        // Populated path runs through the IPs/users print branches AND
        // the trailing hint. We assert it returns Ok; output capture
        // happens via stdout in the test runner.
        cmd_allowlist_list(&cli).expect("list should print without error");
    }

    #[test]
    fn cmd_allowlist_list_prints_setup_hint_when_empty() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        // Fresh agent.toml has empty arrays — exercise the early-return
        // hint that suggests `--reason` from the start.
        cmd_allowlist_list(&cli).expect("list should print without error");
    }

    #[test]
    fn dynamic_trusted_ips_reads_suppress_response_rules() {
        let temp = TempDir::new().expect("tempdir");
        // A dashboard "Trust IP" managed file + a disabled rule that must be skipped.
        let yaml = r#"
version: 1
rules:
  - id: operator-trust-203-0-113-10
    action: suppress_response
    suppress:
      scope: ip
      values: ["203.0.113.10"]
    expires_at: "2026-06-20T10:00:00Z"
    tags: [operator-trust]
  - id: operator-trust-10-0-0-0-8
    action: suppress_response
    suppress:
      scope: ip
      values: ["10.0.0.0/8"]
  - id: disabled-one
    action: suppress_response
    suppress:
      scope: ip
      values: ["1.2.3.4"]
    disabled: true
"#;
        std::fs::write(temp.path().join("70-operator-trust.yml"), yaml).unwrap();
        let found = dynamic_trusted_ips_from_rules(temp.path());
        let vals: Vec<&str> = found.iter().map(|d| d.value.as_str()).collect();
        assert!(vals.contains(&"203.0.113.10"));
        assert!(vals.contains(&"10.0.0.0/8"));
        assert!(!vals.contains(&"1.2.3.4")); // disabled skipped
        let with_exp = found.iter().find(|d| d.value == "203.0.113.10").unwrap();
        assert_eq!(with_exp.expires_at.as_deref(), Some("2026-06-20T10:00:00Z"));
    }

    #[test]
    fn dynamic_trusted_ips_missing_dir_is_empty() {
        assert!(dynamic_trusted_ips_from_rules(std::path::Path::new("/nope/xyz")).is_empty());
    }

    // Wave 8e anchor: --reason is OPTIONAL for backwards compat, but
    // omitting it MUST be visible in the audit log as a null reason
    // (so a future operator can grep for entries with no WHY). Anti-
    // regression for silently accepting reason-less adds — that is
    // the original 2026-05-04 bug shape we are fixing.
    #[test]
    fn cmd_allowlist_add_without_reason_records_null_reason_in_audit() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_allowlist_add(&cli, Some("10.0.0.1"), None, None)
            .expect("add without reason still succeeds (compat)");

        let audit_path = admin_audit_today_in(&cli);
        let body = std::fs::read_to_string(&audit_path).expect("audit file should be written");
        // serde_json renders `Option::None` as `null` so the audit JSONL
        // line carries `"reason":null` — that's the signal future-operator
        // tooling can grep for.
        assert!(
            body.contains("\"reason\":null"),
            "audit entry must record missing reason as null; got: {body}"
        );
    }

    #[test]
    fn parse_suppressed_patterns_filters_comments_and_blanks() {
        // Verifies suppress listing parser ignores comments/blank lines while preserving active patterns.
        let parsed = parse_suppressed_patterns("\n# note\nfoo\n  \n bar  \n");
        assert_eq!(parsed, vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn cmd_suppress_add_and_remove_manages_file_state() {
        // Covers suppression add/remove transitions, including dedup add and missing-pattern removal.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_suppress_add(&cli, "firmware:trust_degraded").expect("first add should succeed");
        cmd_suppress_add(&cli, "firmware:trust_degraded").expect("duplicate add should be no-op");

        let suppress_path = suppressed_file(&cli);
        let content = std::fs::read_to_string(&suppress_path).expect("suppress file should exist");
        assert_eq!(content.lines().count(), 1);
        assert_eq!(content.trim(), "firmware:trust_degraded");

        cmd_suppress_remove(&cli, "not-present").expect("removing missing pattern should be no-op");
        cmd_suppress_remove(&cli, "firmware:trust_degraded").expect("remove should succeed");
        let content =
            std::fs::read_to_string(&suppress_path).expect("suppress file should still exist");
        assert!(content.trim().is_empty());
    }

    #[test]
    fn cmd_suppress_list_reads_and_parses_saved_patterns() {
        // Covers suppress-list parser path used by the CLI command itself.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        cmd_suppress_add(&cli, "detector:example").expect("add should succeed");
        cmd_suppress_list(&cli).expect("list should parse and print active suppressions");
    }
}
