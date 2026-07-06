//! Operator "Trust IP" — a monitor-only allowlist managed from the dashboard
//! (and visible to the `innerwarden rule` / `innerwarden trust` CLIs).
//!
//! ## What "trust" means here (read this before changing anything)
//!
//! A trusted IP/CIDR is merged into `state.dynamic_trusted_ips`, which the
//! automated response path consults (`incident_flow.rs`, `incident_auto_rules.rs`,
//! `correlation_response.rs`). Being trusted means the agent will **not
//! auto-block / auto-respond** to that IP. It does **NOT** blind detection:
//! incidents for a trusted IP are STILL created, STILL logged to JSONL, and
//! STILL notified (Telegram/Slack/webhook) — notifications dispatch before the
//! allowlist skip. There is deliberately no "drop / suppress detection" mode on
//! this surface, so a dashboard-authenticated session cannot self-allowlist into
//! silence.
//!
//! ## Integration with the user-facing rule system
//!
//! Trust entries are written as ordinary **`suppress_response` / `scope: ip`
//! rules** — the exact format a user can hand-write — into a managed file inside
//! the event_pipeline rules directory (`70-operator-trust.yml`). Consequences:
//!
//! - The agent's `YamlResponseRules` hot-reload (every 30 s) already reads these
//!   into `dynamic_trusted_ips` and drops expired ones via `expires_at`, so no
//!   special wiring is needed in the agent loop.
//! - `innerwarden rule list` shows each entry and `innerwarden rule disable <id>`
//!   can disable one — the dashboard and the CLI operate on the same artifact.
//! - The sensor shares this directory but skips `suppress_response` rules; the
//!   `SuppressConfig { detector?, scope? }` schema (sensor `types.rs`) lets the
//!   file parse cleanly instead of warn-and-skipping.
//!
//! Full provenance (who/when/reason) is recorded in the hash-chained
//! admin-actions audit trail by the dashboard handler; the rule file carries the
//! IP, the reason (`drop_reason`), and the optional expiry.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Default event_pipeline rules directory (shared with the sensor + the agent
/// hot-reload + `innerwarden rule`).
pub const DEFAULT_RULES_DIR: &str = "/etc/innerwarden/rules/event_pipeline";

/// Name of the dashboard-managed rule file inside the rules dir. The `70-`
/// prefix orders it after the built-in/user packs; the fixed name means no
/// operator input ever reaches a filesystem path (no traversal).
pub const MANAGED_FILE: &str = "70-operator-trust.yml";

/// Tag stamped on every rule we own, so reads can tell our entries apart from
/// any hand-written `suppress_response` rule that happens to share the file.
pub const TRUST_TAG: &str = "operator-trust";

/// Maximum time-to-live an operator may set, in hours (one year).
pub const MAX_TTL_HOURS: u64 = 24 * 365;

/// Narrowest CIDR prefix length we accept (i.e. the broadest range). `/8`
/// (≈16M addresses) covers every legitimate trust case. Anything broader is
/// rejected: it stops `0.0.0.0/0` AND the two-halves end-run
/// (`0.0.0.0/1` + `128.0.0.0/1`).
pub const MIN_V4_PREFIX: u32 = 8;
/// IPv6 floor.
pub const MIN_V6_PREFIX: u32 = 16;

/// Hard cap on the operator `reason` length.
pub const MAX_REASON_LEN: usize = 1000;

/// Managed-file path inside a rules dir.
pub fn managed_file_in(rules_dir: &Path) -> PathBuf {
    rules_dir.join(MANAGED_FILE)
}

/// One trusted IP/CIDR as surfaced to the dashboard list endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEntry {
    /// The trusted IP or CIDR.
    pub value: String,
    /// Operator rationale (stored as the rule's `drop_reason`).
    pub reason: String,
    /// Stable rule id (`operator-trust-<sanitized>`), usable with
    /// `innerwarden rule disable <id>`.
    pub id: String,
    /// When the trust lapses. `None` = never expires.
    pub expires_at: Option<DateTime<Utc>>,
}

impl TrustEntry {
    /// True when `now` is at or past `expires_at`.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }
}

// --- On-disk rule schema (a subset of the event_pipeline rule schema) --------
// Deliberately NOT `deny_unknown_fields`: we only ever read our own managed
// file, but staying lenient means a future schema field never makes a read fail.

#[derive(Debug, Default, Serialize, Deserialize)]
struct RuleFile {
    version: u32,
    #[serde(default)]
    rules: Vec<TrustRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustRule {
    id: String,
    action: String,
    suppress: Suppress,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    drop_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Suppress {
    scope: String,
    values: Vec<String>,
}

/// Validate and normalize an operator-supplied trust target.
///
/// Accepts an exact IP or a CIDR. Internal/private ranges are allowed (trusting
/// your own office/VPN/LB range is the point). Rejects empty input, non-IP/CIDR
/// input, and any prefix broader than `/8` (v4) or `/16` (v6) — see the const
/// docs for why.
pub fn validate_target(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("ip is required".to_string());
    }

    if let Some((base, prefix)) = t.split_once('/') {
        let base_ip: IpAddr = base
            .parse()
            .map_err(|_| format!("'{base}' is not a valid IP address"))?;
        let prefix_len: u32 = prefix
            .parse()
            .map_err(|_| format!("'{prefix}' is not a valid CIDR prefix length"))?;
        let (max, min) = match base_ip {
            IpAddr::V4(_) => (32, MIN_V4_PREFIX),
            IpAddr::V6(_) => (128, MIN_V6_PREFIX),
        };
        if prefix_len > max {
            return Err(format!(
                "prefix /{prefix_len} is out of range for this address family (max /{max})"
            ));
        }
        if prefix_len < min {
            return Err(format!(
                "refusing to trust /{prefix_len}: too broad (min /{min}). Trusting a range \
                 this large would disable auto-response for a huge slice of the internet."
            ));
        }
        Ok(format!("{base_ip}/{prefix_len}"))
    } else {
        let ip: IpAddr = t
            .parse()
            .map_err(|_| format!("'{t}' is not a valid IP address or CIDR"))?;
        Ok(ip.to_string())
    }
}

/// Stable, human-readable rule id for a value. Non-alphanumeric chars become
/// `-` (this is the YAML `id` field, not a filename — sanitization is for
/// readability + `rule disable`, not security).
fn rule_id_for(value: &str) -> String {
    let slug: String = value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("operator-trust-{slug}")
}

fn read_rules(file: &Path) -> Vec<TrustRule> {
    let Ok(content) = std::fs::read_to_string(file) else {
        return Vec::new();
    };
    serde_yaml::from_str::<RuleFile>(&content)
        .map(|f| f.rules)
        .unwrap_or_default()
}

/// Read trust entries for the dashboard list (including expired ones, flagged at
/// the call site). Only rules tagged [`TRUST_TAG`] with `scope: ip` are returned.
pub fn read_entries(file: &Path) -> Vec<TrustEntry> {
    read_rules(file)
        .into_iter()
        .filter(|r| r.action == "suppress_response" && r.suppress.scope == "ip")
        .filter(|r| r.tags.iter().any(|t| t == TRUST_TAG))
        .filter_map(|r| {
            r.suppress.values.first().map(|v| TrustEntry {
                value: v.clone(),
                reason: r.drop_reason.clone().unwrap_or_default(),
                id: r.id.clone(),
                expires_at: r.expires_at,
            })
        })
        .collect()
}

/// Add (or replace, by exact normalized value) a trusted IP/CIDR. Returns the
/// entry written. The write is atomic (temp file + rename) so the slow-loop
/// reader never sees a half-written file.
pub fn add(
    rules_dir: &Path,
    raw_value: &str,
    reason: &str,
    ttl_hours: Option<u64>,
    now: DateTime<Utc>,
) -> Result<TrustEntry, String> {
    let value = validate_target(raw_value)?;
    let reason = reason.trim();
    if reason.is_empty() {
        return Err("reason is required".to_string());
    }
    if reason.chars().count() > MAX_REASON_LEN {
        return Err(format!("reason must be <= {MAX_REASON_LEN} characters"));
    }
    let expires_at = match ttl_hours {
        None => None,
        Some(0) => return Err("ttl_hours must be greater than zero".to_string()),
        Some(h) if h > MAX_TTL_HOURS => {
            return Err(format!("ttl_hours must be <= {MAX_TTL_HOURS}"));
        }
        Some(h) => Some(now + chrono::Duration::hours(h as i64)),
    };

    let id = rule_id_for(&value);
    let rule = TrustRule {
        id: id.clone(),
        action: "suppress_response".to_string(),
        suppress: Suppress {
            scope: "ip".to_string(),
            values: vec![value.clone()],
        },
        drop_reason: Some(reason.to_string()),
        expires_at,
        tags: vec![TRUST_TAG.to_string()],
    };

    let file = managed_file_in(rules_dir);
    let mut rules = read_rules(&file);
    // Upsert by value within our own rules (keep any unrelated rules intact).
    rules.retain(|r| r.suppress.values.first().map(String::as_str) != Some(value.as_str()));
    rules.push(rule);
    write_atomic(&file, &rules)?;

    Ok(TrustEntry {
        value,
        reason: reason.to_string(),
        id,
        expires_at,
    })
}

/// Remove a trusted IP/CIDR by exact (normalized) value. Returns true when an
/// entry was actually removed.
pub fn remove(rules_dir: &Path, raw_value: &str) -> Result<bool, String> {
    let value = validate_target(raw_value)?;
    let file = managed_file_in(rules_dir);
    let mut rules = read_rules(&file);
    let before = rules.len();
    rules.retain(|r| r.suppress.values.first().map(String::as_str) != Some(value.as_str()));
    let removed = rules.len() != before;
    if removed {
        write_atomic(&file, &rules)?;
    }
    Ok(removed)
}

fn write_atomic(file: &Path, rules: &[TrustRule]) -> Result<(), String> {
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let doc = RuleFile {
        version: 1,
        rules: rules.to_vec(),
    };
    let body = serde_yaml::to_string(&doc).map_err(|e| format!("serialize: {e}"))?;
    let header = "# Managed by InnerWarden \"Trust IP\". Do not hand-edit; use the\n\
                  # dashboard or `innerwarden trust`. Each rule below suppresses the\n\
                  # AUTOMATED response for an IP/CIDR (monitor-only): the IP is still\n\
                  # detected, logged, and you are still notified — only the auto-block\n\
                  # is skipped. Time-boxed rules expire on their own.\n";
    let tmp = file.with_extension("yml.tmp");
    std::fs::write(&tmp, format!("{header}{body}"))
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, file).map_err(|e| format!("rename into {}: {e}", file.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn validate_accepts_ip_and_cidr() {
        assert_eq!(validate_target(" 203.0.113.10 ").unwrap(), "203.0.113.10");
        assert_eq!(validate_target("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(validate_target("::1").unwrap(), "::1");
        assert_eq!(validate_target("2001:db8::/32").unwrap(), "2001:db8::/32");
        assert!(validate_target("192.168.1.0/24").is_ok());
    }

    #[test]
    fn validate_rejects_garbage_and_too_broad() {
        assert!(validate_target("").is_err());
        assert!(validate_target("not-an-ip").is_err());
        assert!(validate_target("1.2.3.4/99").is_err());
        assert!(validate_target("0.0.0.0/0").is_err());
        assert!(validate_target("::/0").is_err());
        // two-halves end-run + anything broader than /8 (v4) / /16 (v6)
        assert!(validate_target("0.0.0.0/1").is_err());
        assert!(validate_target("128.0.0.0/1").is_err());
        assert!(validate_target("10.0.0.0/7").is_err());
        assert!(validate_target("10.0.0.0/8").is_ok());
        assert!(validate_target("2001:db8::/15").is_err());
        assert!(validate_target("2001:db8::/16").is_ok());
    }

    #[test]
    fn add_writes_rule_readable_as_entry_and_by_yaml_rules() {
        let dir = tempfile::tempdir().unwrap();
        let now = ts("2026-06-13T10:00:00Z");
        add(dir.path(), "203.0.113.10", "office vpn", None, now).unwrap();

        // dashboard list view
        let entries = read_entries(&managed_file_in(dir.path()));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "203.0.113.10");
        assert_eq!(entries[0].reason, "office vpn");
        assert_eq!(entries[0].id, "operator-trust-203-0-113-10");

        // end-to-end: the agent's hot-reload picks it up as a trusted IP
        let yr = crate::allowlist::YamlResponseRules::load_at(dir.path(), now);
        assert!(yr.trusted_ips.contains(&"203.0.113.10".to_string()));
    }

    #[test]
    fn add_upserts_by_value() {
        let dir = tempfile::tempdir().unwrap();
        let now = ts("2026-06-13T10:00:00Z");
        add(dir.path(), "10.0.0.0/8", "first", None, now).unwrap();
        add(dir.path(), "10.0.0.0/8", "second", None, now).unwrap();
        let entries = read_entries(&managed_file_in(dir.path()));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason, "second");
    }

    #[test]
    fn ttl_entry_expires_out_of_yaml_rules() {
        let dir = tempfile::tempdir().unwrap();
        let now = ts("2026-06-13T10:00:00Z");
        add(dir.path(), "198.51.100.7", "temp", Some(24), now).unwrap();
        // active within the window
        let yr =
            crate::allowlist::YamlResponseRules::load_at(dir.path(), ts("2026-06-13T11:00:00Z"));
        assert!(yr.trusted_ips.contains(&"198.51.100.7".to_string()));
        // expired two days later — gone from the active trusted set
        let yr2 =
            crate::allowlist::YamlResponseRules::load_at(dir.path(), ts("2026-06-15T10:00:00Z"));
        assert!(yr2.trusted_ips.is_empty());
        // but still on disk, flagged expired for the dashboard list
        let entries = read_entries(&managed_file_in(dir.path()));
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_expired_at(ts("2026-06-15T10:00:00Z")));
    }

    #[test]
    fn add_rejects_bad_ttl_reason_and_overlong_reason() {
        let dir = tempfile::tempdir().unwrap();
        let now = ts("2026-06-13T10:00:00Z");
        assert!(add(dir.path(), "1.1.1.1", "", None, now).is_err());
        assert!(add(dir.path(), "1.1.1.1", "r", Some(0), now).is_err());
        assert!(add(dir.path(), "1.1.1.1", "r", Some(MAX_TTL_HOURS + 1), now).is_err());
        let long = "x".repeat(MAX_REASON_LEN + 1);
        assert!(add(dir.path(), "1.1.1.1", &long, None, now).is_err());
        assert!(read_entries(&managed_file_in(dir.path())).is_empty());
    }

    #[test]
    fn remove_existing_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let now = ts("2026-06-13T10:00:00Z");
        add(dir.path(), "203.0.113.10", "vpn", None, now).unwrap();
        assert!(remove(dir.path(), "203.0.113.10").unwrap());
        assert!(read_entries(&managed_file_in(dir.path())).is_empty());
        assert!(!remove(dir.path(), "203.0.113.10").unwrap());
    }

    #[test]
    fn missing_file_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_entries(&managed_file_in(dir.path())).is_empty());
    }
}
