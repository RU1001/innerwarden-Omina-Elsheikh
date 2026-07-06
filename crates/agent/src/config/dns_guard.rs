//! DNS Guard export config section.
//!
//! The free agent knows which domains are malicious (IOC feeds, dns_c2 /
//! dns_tunneling intel). The paid `innerwarden-dns-guard` resolver enforces
//! against a denylist file it hot-reloads. This section is the **free → paid
//! intel bridge**: when enabled, the agent periodically exports its known-bad
//! domains to `denylist_path`, and the running DNS Guard picks them up live.
//! Free detection feeds paid prevention — the same line as the Execution Gate.

use super::*;

/// `[dns_guard]` — export the agent's malicious-domain intel to the DNS Guard's
/// denylist file. Default OFF (the consumer is the paid DNS Guard; an OSS-only
/// install does nothing here).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsGuardConfig {
    /// Master switch for the denylist export. Off by default.
    #[serde(default)]
    pub export_enabled: bool,
    /// File the agent writes (and the DNS Guard's `--denylist` reads). Written
    /// atomically (temp + rename) so the guard never reads a half-written file.
    /// Defaults to the **data dir** (`/var/lib/innerwarden`), not the config dir:
    /// the agent runs as the unprivileged `innerwarden` user and can only write
    /// its data dir — a `/etc/innerwarden` default fails with permission denied
    /// (found deploying on a real box). The DNS Guard runs as root and reads it
    /// from there.
    #[serde(default = "default_dns_guard_denylist_path")]
    pub denylist_path: String,
    /// Master switch for ingesting the DNS Guard's block events back into the
    /// agent as incidents (so a blocked malicious lookup is visible in IW). Off
    /// by default.
    #[serde(default)]
    pub ingest_enabled: bool,
    /// The DNS Guard's events JSONL (matches the daemon's `--events`). The agent
    /// tails it (byte-offset cursor) and turns `dns_guard.blocked` lines into
    /// incidents.
    #[serde(default = "default_dns_guard_events_path")]
    pub events_path: String,
}

impl Default for DnsGuardConfig {
    fn default() -> Self {
        Self {
            export_enabled: false,
            denylist_path: default_dns_guard_denylist_path(),
            ingest_enabled: false,
            events_path: default_dns_guard_events_path(),
        }
    }
}

fn default_dns_guard_denylist_path() -> String {
    "/var/lib/innerwarden/dns-deny.txt".to_string()
}

fn default_dns_guard_events_path() -> String {
    "/var/lib/innerwarden/dns_guard-events.jsonl".to_string()
}
