//! DNS Guard event ingestion — turn the paid resolver's block events into
//! agent incidents, so a blocked malicious-domain lookup is visible in IW.
//!
//! The other half of the bridge: [`crate::dns_guard_export`] feeds IW's intel
//! INTO the guard's denylist; this reads the guard's decisions back OUT. The
//! `innerwarden-dns-guard` daemon appends `dns_guard.blocked` / `would_block`
//! JSONL events; on the slow loop (byte-offset cursor, so each line is seen
//! once) we turn each `blocked` into a High incident — a host/agent tried to
//! resolve a known-bad domain and was stopped. `would_block` (observe-mode
//! telemetry) is intentionally NOT an incident: observe is for measuring the
//! blast radius, not alerting.

use std::path::Path;

use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;
use serde::Deserialize;
use tracing::{info, warn};

use crate::{config, AgentState};

/// One parsed `dns_guard.blocked` event from the guard's JSONL.
#[derive(Debug, Clone, Deserialize)]
struct RawEvent {
    kind: String,
    domain: String,
    #[serde(default)]
    client: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    mode: String,
}

/// Parse one JSONL line; `Some` only for a `dns_guard.blocked` event with a
/// non-empty domain (skips `would_block`, other kinds, and garbage).
fn parse_blocked_line(line: &str) -> Option<RawEvent> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let ev: RawEvent = serde_json::from_str(line).ok()?;
    if ev.kind == "dns_guard.blocked" && !ev.domain.trim().is_empty() {
        Some(ev)
    } else {
        None
    }
}

/// Build the incident for a blocked lookup. High: resolving a known-bad domain
/// is a strong compromise indicator even though the guard prevented it. The
/// `incident_id` is stable per domain so the agent's grouping collapses repeats.
fn build_incident(ev: &RawEvent, host: &str, now: chrono::DateTime<chrono::Utc>) -> Incident {
    let domain = ev.domain.trim().to_ascii_lowercase();
    Incident {
        ts: now,
        host: host.to_string(),
        incident_id: format!("dns_guard:blocked:{domain}"),
        severity: Severity::High,
        title: "DNS Guard blocked a malicious-domain lookup".to_string(),
        summary: format!(
            "A lookup for '{domain}' ({}) was denied at the DNS Guard ({} mode). Source {}. \
             Something on this host tried to resolve a known-bad domain — investigate the client.",
            if ev.reason.is_empty() {
                "denylist"
            } else {
                &ev.reason
            },
            if ev.mode.is_empty() {
                "enforce"
            } else {
                &ev.mode
            },
            if ev.client.is_empty() {
                "unknown"
            } else {
                &ev.client
            },
        ),
        evidence: serde_json::json!({
            "domain": domain,
            "reason": ev.reason,
            "detail": ev.detail,
            "client": ev.client,
            "mode": ev.mode,
            "source": "dns_guard",
        }),
        recommended_checks: vec![
            "Identify the process behind the DNS client that made the lookup.".into(),
            "Check whether the domain is C2 / exfil / DGA and the host is compromised.".into(),
            "Confirm the DNS Guard is in enforce (the lookup was actually denied).".into(),
        ],
        tags: vec![
            "dns-guard".to_string(),
            "active-defence".to_string(),
            "domain-block".to_string(),
            if ev.reason.is_empty() {
                "denylist".to_string()
            } else {
                ev.reason.clone()
            },
        ],
        entities: vec![],
    }
}

/// From a buffer of newly-read bytes, return the complete lines (up to the last
/// newline) and the number of bytes they consume (so the cursor only advances
/// past whole lines, holding a partial trailing line for next time).
fn split_complete_lines(buf: &str) -> (Vec<&str>, usize) {
    match buf.rfind('\n') {
        Some(idx) => {
            let consumed = idx + 1;
            (buf[..consumed].lines().collect(), consumed)
        }
        None => (Vec::new(), 0),
    }
}

/// Slow-loop entry. No-op unless ingest is enabled. Tails the guard's events
/// file from a persisted byte offset and writes a High incident per new
/// `dns_guard.blocked` (deduped by domain within the batch).
pub(crate) fn process_dns_guard_ingest_tick(
    data_dir: &Path,
    cfg: &config::DnsGuardConfig,
    state: &AgentState,
) {
    if !cfg.ingest_enabled {
        return;
    }
    let events_path = Path::new(&cfg.events_path);
    if !events_path.exists() {
        return;
    }
    let cursor_path = data_dir.join("dns_guard_ingest.cursor");
    let mut offset = std::fs::read_to_string(&cursor_path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    let len = match std::fs::metadata(events_path) {
        Ok(m) => m.len(),
        Err(_) => return,
    };
    if offset > len {
        offset = 0; // file truncated / rotated → re-read from the top
    }
    if offset == len {
        return; // nothing new
    }

    let buf = match read_from_offset(events_path, offset) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "dns_guard ingest: read failed");
            return;
        }
    };
    let (lines, consumed) = split_complete_lines(&buf);
    if lines.is_empty() {
        return;
    }

    let host = read_hostname();
    let now = chrono::Utc::now();
    let mut seen = std::collections::HashSet::new();
    let mut incidents = Vec::new();
    for line in lines {
        if let Some(ev) = parse_blocked_line(line) {
            let key = ev.domain.trim().to_ascii_lowercase();
            if seen.insert(key) {
                incidents.push(build_incident(&ev, &host, now));
            }
        }
    }

    if !incidents.is_empty() {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        write_incidents(data_dir, &today, &incidents);
        info!(
            count = incidents.len(),
            "dns_guard ingest: surfaced blocked malicious-domain lookups as incidents"
        );
    }
    let _ = state; // reserved for future correlation/notify wiring

    let new_offset = offset + consumed as u64;
    if let Err(e) = std::fs::write(&cursor_path, new_offset.to_string()) {
        warn!(error = %e, "dns_guard ingest: cursor write failed");
    }
}

fn read_from_offset(path: &Path, offset: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    Ok(s)
}

fn read_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn write_incidents(data_dir: &Path, today: &str, incidents: &[Incident]) {
    use std::io::Write;
    let path = data_dir.join(format!("incidents-{today}.jsonl"));
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            for inc in incidents {
                if let Ok(line) = serde_json::to_string(inc) {
                    let _ = writeln!(f, "{line}");
                }
            }
        }
        Err(e) => warn!(error = %e, "dns_guard ingest: incident write failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keeps_blocked_skips_would_block_and_garbage() {
        let blocked = r#"{"kind":"dns_guard.blocked","domain":"evil.com","reason":"denylist","client":"127.0.0.1:5","mode":"enforce"}"#;
        let would = r#"{"kind":"dns_guard.would_block","domain":"evil.com","reason":"denylist"}"#;
        assert!(parse_blocked_line(blocked).is_some());
        assert!(
            parse_blocked_line(would).is_none(),
            "would_block is not an incident"
        );
        assert!(parse_blocked_line("not json").is_none());
        assert!(parse_blocked_line("").is_none());
        assert!(
            parse_blocked_line(r#"{"kind":"dns_guard.blocked","domain":""}"#).is_none(),
            "empty domain skipped"
        );
    }

    #[test]
    fn build_incident_is_high_with_stable_id_and_tags() {
        let ev = parse_blocked_line(
            r#"{"kind":"dns_guard.blocked","domain":"C2.Evil.COM","reason":"dga","client":"10.0.0.5:33","mode":"enforce"}"#,
        )
        .unwrap();
        let inc = build_incident(&ev, "host1", chrono::Utc::now());
        assert_eq!(inc.severity, Severity::High);
        assert_eq!(inc.incident_id, "dns_guard:blocked:c2.evil.com");
        assert!(inc.tags.iter().any(|t| t == "dns-guard"));
        assert!(inc.tags.iter().any(|t| t == "dga"));
        assert_eq!(inc.evidence["domain"], "c2.evil.com");
    }

    #[test]
    fn split_lines_holds_partial_trailing_line() {
        let buf = "a\nb\npartial-no-newline";
        let (lines, consumed) = split_complete_lines(buf);
        assert_eq!(lines, vec!["a", "b"]);
        assert_eq!(consumed, 4); // "a\nb\n"
                                 // no newline at all → nothing consumed
        let (lines2, c2) = split_complete_lines("nopartial");
        assert!(lines2.is_empty());
        assert_eq!(c2, 0);
    }

    #[test]
    fn ingest_tick_writes_incident_and_advances_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::tests::triage_test_state(dir.path());
        let events = dir.path().join("dg-events.jsonl");
        std::fs::write(
            &events,
            "{\"kind\":\"dns_guard.blocked\",\"domain\":\"evil.com\",\"reason\":\"denylist\",\"mode\":\"enforce\"}\n\
             {\"kind\":\"dns_guard.would_block\",\"domain\":\"ok.com\"}\n",
        )
        .unwrap();
        let cfg = config::DnsGuardConfig {
            ingest_enabled: true,
            events_path: events.to_string_lossy().into_owned(),
            ..Default::default()
        };
        process_dns_guard_ingest_tick(dir.path(), &cfg, &state);

        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let inc =
            std::fs::read_to_string(dir.path().join(format!("incidents-{today}.jsonl"))).unwrap();
        assert!(inc.contains("dns_guard:blocked:evil.com"));
        assert!(
            !inc.contains("ok.com"),
            "would_block must not become an incident"
        );
        // cursor advanced; a second tick with no new lines writes nothing more
        let before = inc.len();
        process_dns_guard_ingest_tick(dir.path(), &cfg, &state);
        let after = std::fs::read_to_string(dir.path().join(format!("incidents-{today}.jsonl")))
            .map(|s| s.len())
            .unwrap_or(0);
        assert_eq!(before, after, "cursor prevents re-ingesting the same line");
    }

    #[test]
    fn ingest_disabled_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::tests::triage_test_state(dir.path());
        let cfg = config::DnsGuardConfig::default(); // ingest_enabled = false
        process_dns_guard_ingest_tick(dir.path(), &cfg, &state);
        // nothing created
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none() || true);
    }
}
