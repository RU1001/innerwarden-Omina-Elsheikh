//! DNS Guard intel bridge — export the agent's known-malicious domains to the
//! denylist file the paid `innerwarden-dns-guard` resolver hot-reloads.
//!
//! Free InnerWarden *detects* malicious domains (IOC feeds + dns_c2 /
//! dns_tunneling intel, consolidated in [`crate::threat_feeds`]); the paid DNS
//! Guard *prevents* their resolution. This module is the wire between them: on
//! the slow loop (throttled), when `[dns_guard] export_enabled = true`, it writes
//! the agent's `malicious_domains` set to `denylist_path` — atomically (temp +
//! rename, so the guard never reads a half-written file) and only when the
//! content changed (so it doesn't churn the guard's reload). Same free-detect /
//! paid-prevent line as the Execution Gate.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};

use tracing::{info, warn};

use crate::{config, AgentState};

/// Export at most once per this interval (the guard reloads every ~60s anyway).
const EXPORT_INTERVAL_SECS: i64 = 300;

static LAST_EXPORT_TS: AtomicI64 = AtomicI64::new(0);

/// Pure: at least `min_secs` elapsed since `last`? (0 = never → always true.)
fn interval_elapsed(last: i64, now: i64, min_secs: i64) -> bool {
    last == 0 || now - last >= min_secs
}

/// Slow-loop entry point. No-op unless the export is enabled. Self-throttled.
pub(crate) fn process_dns_guard_export_tick(cfg: &config::DnsGuardConfig, state: &AgentState) {
    if !cfg.export_enabled {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let last = LAST_EXPORT_TS.load(Ordering::Relaxed);
    if !interval_elapsed(last, now, EXPORT_INTERVAL_SECS) {
        return;
    }
    LAST_EXPORT_TS.store(now, Ordering::Relaxed);

    let domains = gather_malicious_domains(state);
    let content = build_denylist_content(&domains, &chrono::Utc::now().to_rfc3339());

    match write_if_changed(Path::new(&cfg.denylist_path), &content) {
        Ok(true) => info!(
            count = domains.len(),
            path = %cfg.denylist_path,
            "DNS Guard denylist exported (changed)"
        ),
        Ok(false) => tracing::debug!(count = domains.len(), "DNS Guard denylist unchanged"),
        Err(e) => warn!(error = %e, path = %cfg.denylist_path, "DNS Guard denylist export failed"),
    }
}

/// Collect the agent's known-malicious domains (deduped + sorted, cleaned).
/// Sourced from the consolidated threat-feed intel. Returns empty if no feed is
/// configured.
fn gather_malicious_domains(state: &AgentState) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(tf) = state.threat_feed.as_ref() {
        for raw in &tf.state().malicious_domains {
            if let Some(d) = clean_domain_entry(raw) {
                out.insert(d);
            }
        }
    }
    out
}

/// A threat-feed "domain" entry may be a bare domain OR a **hosts-file line**
/// (`0.0.0.0 evil.com`, `127.0.0.1\tevil.com`) — many public domain blocklists
/// ship in hosts format and the feed ingestion stored the raw lines. Take the
/// last whitespace-separated token as the candidate, lowercase it, strip a
/// trailing dot, and reject anything not domain-shaped (a bare IP, no dot, or
/// non-hostname characters). Without this the denylist fills with `127.0.0.1\t…`
/// junk that never matches a real query.
fn clean_domain_entry(raw: &str) -> Option<String> {
    let token = raw.split_whitespace().last()?;
    let d = token.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || !d.contains('.') {
        return None;
    }
    // reject a bare IPv4 (all digits + dots)
    if d.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    // only hostname-legal characters
    if !d
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return None;
    }
    Some(d)
}

/// Render the denylist file content: a header comment + one domain per line,
/// sorted. The DNS Guard ignores `#` comments and refuses public-suffix entries
/// on load, so this is the producer half of the contract.
fn build_denylist_content(domains: &BTreeSet<String>, generated_at: &str) -> String {
    let mut s = String::new();
    s.push_str("# InnerWarden DNS Guard denylist — AUTO-GENERATED, do not edit by hand.\n");
    s.push_str("# Source: agent threat-feed intel (IOC feeds + dns_c2 / dns_tunneling).\n");
    s.push_str(&format!(
        "# generated_at: {generated_at}  entries: {}\n",
        domains.len()
    ));
    for d in domains {
        s.push_str(d);
        s.push('\n');
    }
    s
}

/// Write `content` to `path` atomically (temp + rename) only if it differs from
/// what is already there. Returns `true` if a write happened.
fn write_if_changed(path: &Path, content: &str) -> std::io::Result<bool> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        if existing == content {
            return Ok(false);
        }
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, path)?;
    Ok(true)
}

#[cfg(test)]
fn reset_throttle_for_test() {
    LAST_EXPORT_TS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_tick_writes_denylist_when_enabled() {
        reset_throttle_for_test();
        let dir = tempfile::tempdir().unwrap();
        let state = crate::tests::triage_test_state(dir.path());
        let path = dir.path().join("dns-deny.txt");
        let cfg = config::DnsGuardConfig {
            export_enabled: true,
            denylist_path: path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        // No threat feed configured in the test state → empty domain set, but the
        // header file is still written (exercises throttle + gather + build + write).
        process_dns_guard_export_tick(&cfg, &state);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("# InnerWarden DNS Guard denylist"));
        assert!(body.contains("entries: 0"));
    }

    #[test]
    fn process_tick_noop_when_disabled() {
        reset_throttle_for_test();
        let dir = tempfile::tempdir().unwrap();
        let state = crate::tests::triage_test_state(dir.path());
        let path = dir.path().join("dns-deny.txt");
        let cfg = config::DnsGuardConfig {
            export_enabled: false,
            denylist_path: path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        process_dns_guard_export_tick(&cfg, &state);
        assert!(!path.exists(), "disabled export writes nothing");
    }

    #[test]
    fn interval_throttle_respects_min_and_never() {
        assert!(interval_elapsed(0, 1000, 300));
        assert!(!interval_elapsed(1000, 1100, 300));
        assert!(interval_elapsed(1000, 1300, 300));
    }

    #[test]
    fn clean_domain_entry_handles_hosts_format_and_junk() {
        // bare domain
        assert_eq!(clean_domain_entry("Evil.COM."), Some("evil.com".into()));
        // hosts-file lines (the real test001 feed shape) → just the domain
        assert_eq!(
            clean_domain_entry("127.0.0.1\twww.rnft8u0a.shop"),
            Some("www.rnft8u0a.shop".into())
        );
        assert_eq!(
            clean_domain_entry("0.0.0.0 c2.evil.net"),
            Some("c2.evil.net".into())
        );
        // junk / non-domains rejected
        assert_eq!(clean_domain_entry("127.0.0.1"), None); // bare IP
        assert_eq!(clean_domain_entry("localhost"), None); // no dot
        assert_eq!(clean_domain_entry(""), None);
        assert_eq!(clean_domain_entry("# comment"), None); // last token "comment" has no dot
        assert_eq!(clean_domain_entry("bad domain with spaces!.x"), None); // illegal char
    }

    #[test]
    fn build_content_is_sorted_with_header_and_count() {
        let mut d = BTreeSet::new();
        d.insert("zeta.com".to_string());
        d.insert("alpha.com".to_string());
        d.insert("c2.evil.net".to_string());
        let out = build_denylist_content(&d, "2026-06-18T00:00:00Z");
        let lines: Vec<&str> = out.lines().collect();
        // header (3 comment lines) then sorted domains
        assert!(lines[0].starts_with("# InnerWarden DNS Guard denylist"));
        assert!(out.contains("entries: 3"));
        let domains: Vec<&str> = lines
            .iter()
            .filter(|l| !l.starts_with('#'))
            .copied()
            .collect();
        assert_eq!(domains, vec!["alpha.com", "c2.evil.net", "zeta.com"]);
    }

    #[test]
    fn build_content_empty_set_has_header_zero_entries() {
        let out = build_denylist_content(&BTreeSet::new(), "t");
        assert!(out.contains("entries: 0"));
        assert!(out.lines().all(|l| l.starts_with('#')));
    }

    #[test]
    fn write_if_changed_writes_then_skips_identical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns-deny.txt");
        let content = "# header\nevil.com\n";
        assert!(
            write_if_changed(&path, content).unwrap(),
            "first write happens"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
        assert!(
            !write_if_changed(&path, content).unwrap(),
            "identical content is skipped (no reload churn)"
        );
        // changed content writes again
        assert!(write_if_changed(&path, "# header\nevil.com\nbad.net\n").unwrap());
    }

    #[test]
    fn write_if_changed_is_atomic_no_tmp_left() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dns-deny.txt");
        write_if_changed(&path, "x\n").unwrap();
        assert!(
            !path.with_extension("tmp").exists(),
            "temp file renamed away"
        );
    }
}
