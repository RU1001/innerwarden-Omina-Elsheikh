//! Unified response lifecycle: tracks all active responses (block IP, container pause,
//! nginx deny, sudo suspension) with TTL and auto-revert.
//!
//! State machine (per entry):
//!
//!     Active ──(TTL expires | manual revert)──▶ RevertPending
//!                                                    │
//!                     ┌──────────────────────────────┤
//!                     ▼                              │
//!              mark_reverted(ok)          mark_revert_failed(err)
//!                     │                              │
//!                     ▼                 classify error ─ AlreadyAbsent ──▶ history
//!                 history                              └─ Transient
//!                                                         │
//!                                       attempts < MAX ───┤
//!                                                         │
//!                                              RevertFailed (stays in active)
//!                                                         │
//!                                       stage_pending_reverts on next tick
//!                                                         │
//!                                                         ▼
//!                                                  RevertPending
//!                                       attempts >= MAX ──▶ Orphaned → history + alert
//!
//! Key invariants:
//! - The audit trail (history) only records **terminal** states. An entry
//!   marked `expired`/`manual`/`already_absent` means the revert command
//!   was confirmed to have succeeded or the rule was confirmed to be absent.
//!   `orphaned` means the system has given up trying to revert — the rule
//!   may still be active in the kernel/firewall.
//! - While retries are in flight, the entry stays in `active` with its
//!   current state (`RevertFailed`) so dashboards can surface the drift.
//! - `is_tracked` treats all non-terminal states as "still active" to avoid
//!   duplicate registration while a retry is in progress.

use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Read a v2 response-lifecycle snapshot file, surfacing genuine I/O
/// failure via `warn!` while staying silent on `NotFound` (steady
/// state on first boot before any snapshot has been written).
/// Replaces the silent `if let Ok(content) = read_to_string(&path)`
/// fallback in `try_load_v2` (Spec 037 I-13 follow-up #2).
///
/// On a real I/O error (perms, FS error) the operator loses the
/// response-lifecycle state across restart and the agent silently
/// starts with an empty lifecycle table. The warn carries path +
/// error so the operator can recover the file or fix permissions.
fn read_v2_snapshot_or_warn(path: &std::path::Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(c) => Some(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "response lifecycle v2 snapshot read failed (lifecycle state lost across restart)"
            );
            None
        }
    }
}

/// Maximum number of revert attempts before an entry is declared Orphaned
/// and an alert is raised.
const MAX_REVERT_ATTEMPTS: u32 = 3;

/// Spec 076 phase 2: an enforcement is considered "verified live" only if the
/// reconciler confirmed it within this window. Longer than the reconcile
/// interval (~5 min) so one missed tick does not flip the dashboard to
/// unverified; short enough that a truly dropped rule shows as stale quickly.
const ENFORCEMENT_VERIFY_STALE_SECS: i64 = 900;

/// Backend that applied the response (determines how to revert).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBackend {
    Xdp,
    Ufw,
    Iptables,
    Nftables,
    Pf,
    Cloudflare,
    Nginx,
    Container,
    Sudo,
}

/// Type of response action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    BlockIp,
    BlockContainer,
    SuspendSudo,
    RateLimitNginx,
    KillProcess,
}

/// Why a revert was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevertTrigger {
    /// TTL expired.
    TtlExpired,
    /// Manual revert (dashboard action, operator command).
    Manual,
}

/// State of a tracked response in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LifecycleState {
    /// Rule is applied, TTL not yet reached. Normal operating state.
    Active,
    /// Revert has been handed to the executor but completion has not been
    /// reported yet. Short-lived (one cleanup tick). `prior_attempts` is
    /// the number of failed attempts BEFORE this staging, so after a
    /// subsequent `mark_revert_failed` the new total is `prior_attempts+1`.
    /// Required so retries accumulate across the RevertFailed ↔ RevertPending
    /// ping-pong instead of resetting to zero each tick.
    RevertPending {
        since: DateTime<Utc>,
        trigger: RevertTrigger,
        prior_attempts: u32,
    },
    /// Last revert attempt failed with a transient error. Entry stays in
    /// `active` so dashboards show the drift; next cleanup tick will
    /// re-stage it for another attempt until `attempts >= MAX_REVERT_ATTEMPTS`.
    RevertFailed {
        last_attempt_at: DateTime<Utc>,
        attempts: u32,
        last_error: String,
        trigger: RevertTrigger,
    },
}

/// A tracked active response with TTL.
#[derive(Debug, Clone, Serialize)]
pub struct ActiveResponse {
    pub id: String,
    pub response_type: ResponseType,
    pub backend: ResponseBackend,
    pub target: String,
    pub incident_id: String,
    pub created_at: DateTime<Utc>,
    pub ttl_secs: i64,
    pub expires_at: DateTime<Utc>,
    /// Backend-specific handle needed for revert (e.g., nftables rule handle).
    pub revert_handle: Option<String>,
    /// Lifecycle state. All entries start as `Active`.
    #[serde(default = "LifecycleState::default_active")]
    pub state: LifecycleState,
}

impl LifecycleState {
    #[allow(dead_code)] // used as serde default; also kept for explicit initialization callers
    fn default_active() -> Self {
        LifecycleState::Active
    }
}

/// Action to revert a response.
#[derive(Debug, Clone)]
pub struct RevertAction {
    pub id: String,
    pub backend: ResponseBackend,
    pub target: String,
    pub revert_handle: Option<String>,
}

/// What should happen after a revert attempt fails. Returned by
/// `mark_revert_failed` so the caller can fire alerts on Orphaned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureOutcome {
    /// The error string indicated the rule was already gone. Treated as
    /// success; entry moved to history with reason `already_absent`.
    AlreadyAbsent,
    /// Transient error; entry transitioned to `RevertFailed` and will be
    /// retried on the next cleanup tick.
    Retrying { attempt: u32 },
    /// Retry budget exhausted. Entry moved to history with reason `orphaned`.
    /// The rule may still be active in the kernel/firewall — the system
    /// admits it lost control and stops trying.
    ///
    /// The caller is **not** expected to route this into Telegram/Slack/
    /// webhook notifications. Orphaned is a local/kernel state drift
    /// condition — an observability concern for a technical operator
    /// watching logs, Prometheus, and the responses dashboard — not an
    /// interrupt-worthy pager event. Push notifications are reserved for
    /// incident-level signals (real attacker activity). Surface is: WARN
    /// log with structured fields, Prometheus counter
    /// (`innerwarden_responses_orphaned_total`), and the entry living in
    /// history with `reason="orphaned: <stderr>"` so the dashboard
    /// paints it in red.
    Orphaned {
        backend: ResponseBackend,
        target: String,
        last_error: String,
        trigger: RevertTrigger,
    },
    /// Called `mark_revert_failed` on an id that wasn't in `RevertPending`.
    /// Shouldn't happen in practice; logged as a warning.
    UnknownId,
}

/// Classification of a revert error string. Drives the retry/give-up policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    /// The rule was already gone (another actor removed it, reboot, etc).
    /// Treat as success.
    AlreadyAbsent,
    /// Transient failure — worth retrying.
    Transient,
}

fn classify_revert_error(err: &str) -> ErrorKind {
    let lower = err.to_lowercase();
    // Patterns per backend, verified against real stderr on Ubuntu 24.04
    // aarch64 (kernel 6.8.0-106) by running each backend's delete command
    // against a non-existent rule and capturing the output:
    //
    //   iptables-1.8.10: "iptables: Bad rule (does a matching rule exist in
    //                     that chain?)."  exit=1
    //   nft-1.0.9:       "Error: Could not process rule: No such file or
    //                     directory"  exit=1
    //   bpftool (key):   "Error: delete failed: No such file or directory"
    //                    exit=254
    //   bpftool (path):  "Error: bpf obj get (...): No such file or
    //                     directory"  exit=255
    //
    // UFW IS DIFFERENT: `ufw delete deny from <ip>` for a non-existent rule
    // prints "Could not delete non-existent rule" but exits 0, so run_cmd
    // returns Ok(()) and this classifier is never called. The entry is
    // then routed through mark_reverted("expired") rather than
    // mark_revert_failed -> already_absent. Functionally correct (ufw is
    // saying "nothing to do, consider it done"), but means the
    // already_absent counter is systematically undercounted for ufw
    // deployments. Left as-is: detecting this would require parsing stdout
    // inside run_cmd which is invasive. The ufw marker below is kept as
    // defense-in-depth in case a future ufw version starts returning
    // non-zero — then the substring "non-existent" still classifies correctly.
    const ABSENT_MARKERS: &[&str] = &[
        // Generic ENOENT variants. "No such file or directory" from any
        // kernel syscall wrapper passes through this.
        "no such",
        "not found",
        "does not exist",
        "doesn't exist",
        // ufw phrasing (defense-in-depth, see note above).
        "non-existent",
        "nonexistent",
        // iptables phrasings.
        "no chain/target/match",
        "matching rule exist",
        // nft phrasing when rule was referenced by handle that's gone.
        "rule does not exist",
    ];
    if ABSENT_MARKERS.iter().any(|m| lower.contains(m)) {
        ErrorKind::AlreadyAbsent
    } else {
        ErrorKind::Transient
    }
}

/// Unified lifecycle manager for all response actions.
pub struct ResponseLifecycle {
    active: Vec<ActiveResponse>,
    history: VecDeque<CompletedResponse>,
    next_id: u64,
    /// Counters for Prometheus.
    total_registered: u64,
    total_reverted: u64,
    total_expired: u64,
    /// Number of individual revert attempt failures (not entries — an entry
    /// can contribute multiple failures before being orphaned or resolved).
    total_revert_failures: u64,
    /// Reverts that resolved because the rule was already gone.
    total_already_absent: u64,
    /// Entries given up on after exhausting retries. These are the ones that
    /// require operator attention.
    total_orphaned: u64,
    /// Spec 076 phase 2: target -> when its block was last CONFIRMED live against
    /// the real firewall by the slow-loop reconciler. A side table (not a field
    /// on every ActiveResponse) so it does not touch every construction site;
    /// the dashboard joins it so "enforced" reflects the live rule, not the TTL.
    verified_live: std::collections::HashMap<String, DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompletedResponse {
    pub id: String,
    pub response_type: ResponseType,
    pub backend: ResponseBackend,
    pub target: String,
    pub incident_id: String,
    pub created_at: DateTime<Utc>,
    pub reverted_at: DateTime<Utc>,
    pub reason: String, // "expired" or "manual"
}

impl ResponseLifecycle {
    pub fn new() -> Self {
        Self {
            active: Vec::new(),
            history: VecDeque::new(),
            next_id: 1,
            total_registered: 0,
            total_reverted: 0,
            total_expired: 0,
            total_revert_failures: 0,
            total_already_absent: 0,
            total_orphaned: 0,
            verified_live: std::collections::HashMap::new(),
        }
    }

    /// Record that `target`'s block was just confirmed live against the real
    /// firewall (or re-applied) at `now`. Spec 076 phase 2.
    pub fn mark_verified_live(&mut self, target: &str, now: DateTime<Utc>) {
        self.verified_live.insert(target.to_string(), now);
    }

    /// Active, TTL-valid BlockIp targets + their backend — the set the
    /// reconciler checks against the live firewall.
    pub fn active_block_ip_targets(&self, now: DateTime<Utc>) -> Vec<(String, ResponseBackend)> {
        self.active
            .iter()
            .filter(|r| {
                r.response_type == ResponseType::BlockIp
                    && r.state == LifecycleState::Active
                    && r.expires_at > now
            })
            .map(|r| (r.target.clone(), r.backend.clone()))
            .collect()
    }

    /// Restore active responses from a previous snapshot.
    ///
    /// Priority order:
    ///   1. v2 SQLite blob `responses_snapshot`
    ///   2. v2 file `responses.snapshot.json`
    ///   3. v1 SQLite blob `responses` or file `responses.json`
    ///      (the legacy `to_json()`-shaped dashboard view — preserved
    ///      as fallback so existing data dirs keep working after
    ///      upgrade; the first slow-loop tick writes v2 alongside v1
    ///      so the next restart picks the v2 path).
    ///
    /// After load, hydrates any `block_ip` decisions from today's JSONL
    /// that are not already tracked — covers code paths that bypass
    /// `ResponseLifecycle::register` (always-on honeypot, dashboard
    /// manual actions). This reconciliation step is preserved for both
    /// v1 and v2 load paths.
    pub fn load_snapshot(
        data_dir: &std::path::Path,
        store: Option<&innerwarden_store::Store>,
    ) -> Self {
        if let Some(mut lifecycle) = Self::try_load_v2(data_dir, store) {
            // RC-2 follow-up (2026-04-30): the canonical decisions are
            // in SQLite. When a Store is wired the boot reconciler
            // reads from there; the JSONL fallback only fires when no
            // SQLite handle is available (test paths and historical
            // configs without a store). The two reconcilers are
            // intentionally separate functions because their failure
            // modes differ — SQLite cannot be silently absent in prod,
            // so a missing store is a developer signal not a routine
            // skip.
            if let Some(sq) = store {
                Self::hydrate_from_decisions_sqlite(&mut lifecycle, sq);
            } else {
                Self::hydrate_from_decisions_jsonl(&mut lifecycle, data_dir);
            }
            if !lifecycle.active.is_empty() || !lifecycle.history.is_empty() {
                info!(
                    active = lifecycle.active.len(),
                    history = lifecycle.history.len(),
                    total_registered = lifecycle.total_registered,
                    format = "v2",
                    "response lifecycle restored"
                );
            }
            return lifecycle;
        }
        // v1 fallback — legacy shape below.
        let content = if let Some(sq) = store {
            match sq.get_blob("responses") {
                Ok(Some(json)) => {
                    tracing::info!("loaded response lifecycle from sqlite blob (v1)");
                    json
                }
                _ => {
                    let path = data_dir.join("responses.json");
                    match std::fs::read_to_string(&path) {
                        Ok(c) => c,
                        Err(_) => return Self::new(),
                    }
                }
            }
        } else {
            let path = data_dir.join("responses.json");
            match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => return Self::new(),
            }
        };
        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return Self::new(),
        };

        let mut lifecycle = Self::new();
        let now = Utc::now();

        // Restore active responses
        if let Some(active_arr) = json["active"].as_array() {
            for item in active_arr {
                let target = item["target"].as_str().unwrap_or_default();
                let incident_id = item["incident_id"].as_str().unwrap_or_default();
                let ttl_secs = item["ttl_secs"].as_i64().unwrap_or(3600);
                let created_at = item["created_at"]
                    .as_str()
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                    .unwrap_or(now);
                let expires_at = item["expires_at"]
                    .as_str()
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                    .unwrap_or(created_at + chrono::Duration::seconds(ttl_secs));
                let backend = match item["backend"].as_str().unwrap_or("ufw") {
                    "xdp" => ResponseBackend::Xdp,
                    "iptables" => ResponseBackend::Iptables,
                    "nftables" => ResponseBackend::Nftables,
                    "pf" => ResponseBackend::Pf,
                    "cloudflare" => ResponseBackend::Cloudflare,
                    "nginx" => ResponseBackend::Nginx,
                    "container" => ResponseBackend::Container,
                    "sudo" => ResponseBackend::Sudo,
                    _ => ResponseBackend::Ufw,
                };
                let response_type = match item["type"].as_str().unwrap_or("block_ip") {
                    "block_container" => ResponseType::BlockContainer,
                    "suspend_sudo" => ResponseType::SuspendSudo,
                    "rate_limit_nginx" => ResponseType::RateLimitNginx,
                    "kill_process" => ResponseType::KillProcess,
                    _ => ResponseType::BlockIp,
                };

                if target.is_empty() {
                    continue;
                }

                // Drop entries whose target is not a valid IP/CIDR — a
                // malformed target is a zombie rule that ufw/iptables
                // rejected on add but made it into the snapshot anyway.
                // Leaving it Active guarantees an orphaned-response alert
                // in ~1h when the revert fails.
                if response_type == ResponseType::BlockIp
                    && !crate::decision_block_ip::is_valid_block_target(target)
                {
                    tracing::warn!(
                        target = %target,
                        "skipping invalid target while loading response lifecycle snapshot"
                    );
                    continue;
                }

                let id = format!("resp-{}", lifecycle.next_id);
                lifecycle.next_id += 1;
                // Restore state if present (entries mid-retry survive restart).
                // Unknown/missing state defaults to Active so legacy snapshots
                // just keep working.
                let state = parse_state_from_json(&item["state"]).unwrap_or(LifecycleState::Active);
                lifecycle.active.push(ActiveResponse {
                    id,
                    response_type,
                    backend,
                    target: target.to_string(),
                    incident_id: incident_id.to_string(),
                    created_at,
                    ttl_secs,
                    expires_at,
                    revert_handle: item["revert_handle"].as_str().map(String::from),
                    state,
                });
                lifecycle.total_registered += 1;
            }
        }

        // Restore counters from totals (keep accumulated counts across restarts)
        if let Some(totals) = json.get("totals") {
            lifecycle.total_registered = totals["registered"]
                .as_u64()
                .unwrap_or(lifecycle.total_registered);
            lifecycle.total_expired = totals["expired"].as_u64().unwrap_or(0);
            lifecycle.total_reverted = totals["reverted"].as_u64().unwrap_or(0);
            lifecycle.total_revert_failures = totals["revert_failures"].as_u64().unwrap_or(0);
            lifecycle.total_already_absent = totals["already_absent"].as_u64().unwrap_or(0);
            lifecycle.total_orphaned = totals["orphaned"].as_u64().unwrap_or(0);
        }

        // Restore history
        if let Some(history_arr) = json["history"].as_array() {
            for item in history_arr {
                let target = item["target"].as_str().unwrap_or_default();
                if target.is_empty() {
                    continue;
                }
                let backend = match item["backend"].as_str().unwrap_or("ufw") {
                    "xdp" => ResponseBackend::Xdp,
                    "iptables" => ResponseBackend::Iptables,
                    "nftables" => ResponseBackend::Nftables,
                    "pf" => ResponseBackend::Pf,
                    "cloudflare" => ResponseBackend::Cloudflare,
                    _ => ResponseBackend::Ufw,
                };
                let response_type = match item["type"].as_str().unwrap_or("block_ip") {
                    "block_container" => ResponseType::BlockContainer,
                    "suspend_sudo" => ResponseType::SuspendSudo,
                    _ => ResponseType::BlockIp,
                };
                lifecycle.history.push_back(CompletedResponse {
                    id: item["id"].as_str().unwrap_or("").to_string(),
                    response_type,
                    backend,
                    target: target.to_string(),
                    incident_id: item["incident_id"].as_str().unwrap_or("").to_string(),
                    created_at: item["created_at"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(now),
                    reverted_at: item["reverted_at"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(now),
                    reason: item["reason"].as_str().unwrap_or("expired").to_string(),
                });
            }
        }

        // Same SQLite-first reconciliation as the v2 path. JSONL only
        // when no Store handle is present (legacy / test). See the v2
        // load branch above for the rationale.
        if let Some(sq) = store {
            Self::hydrate_from_decisions_sqlite(&mut lifecycle, sq);
        } else {
            Self::hydrate_from_decisions_jsonl(&mut lifecycle, data_dir);
        }

        if !lifecycle.active.is_empty() || !lifecycle.history.is_empty() {
            info!(
                active = lifecycle.active.len(),
                history = lifecycle.history.len(),
                total_registered = lifecycle.total_registered,
                format = "v1",
                "response lifecycle restored"
            );
        }

        lifecycle
    }

    /// Try to load a v2 snapshot from SQLite blob or JSON file. Returns
    /// `None` if neither source is present or if the content is not
    /// tagged `schema_version: 2`. Kept separate from `load_snapshot`
    /// so the v1 fallback path remains untouched on the failure branch.
    fn try_load_v2(
        data_dir: &std::path::Path,
        store: Option<&innerwarden_store::Store>,
    ) -> Option<Self> {
        if let Some(sq) = store {
            if let Ok(Some(content)) = sq.get_blob("responses_snapshot") {
                if let Some(lc) = Self::from_v2_content(&content) {
                    tracing::info!("loaded response lifecycle from sqlite blob (v2)");
                    return Some(lc);
                }
            }
        }
        let path = data_dir.join("responses.snapshot.json");
        if let Some(content) = read_v2_snapshot_or_warn(&path) {
            if let Some(lc) = Self::from_v2_content(&content) {
                tracing::info!("loaded response lifecycle from responses.snapshot.json (v2)");
                return Some(lc);
            }
        }
        None
    }

    /// Parse a v2 snapshot. Strictly requires `schema_version: 2` so a
    /// misrouted v1 payload (e.g. someone wrote the dashboard view into
    /// the wrong blob by mistake) returns `None` and falls through to
    /// the v1 loader instead of partial-matching a wrong shape.
    fn from_v2_content(content: &str) -> Option<Self> {
        let json: serde_json::Value = serde_json::from_str(content).ok()?;
        if json.get("schema_version").and_then(|v| v.as_u64()) != Some(2) {
            return None;
        }
        let now = Utc::now();
        let mut lc = Self::new();

        if let Some(arr) = json["active"].as_array() {
            for item in arr {
                let target = item["target"].as_str().unwrap_or_default();
                if target.is_empty() {
                    continue;
                }
                let response_type = parse_response_type(item["type"].as_str());
                if response_type == ResponseType::BlockIp
                    && !crate::decision_block_ip::is_valid_block_target(target)
                {
                    tracing::warn!(
                        target = %target,
                        "skipping invalid target while loading response lifecycle snapshot (v2)"
                    );
                    continue;
                }
                let created_at = item["created_at"]
                    .as_str()
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                    .unwrap_or(now);
                let ttl_secs = item["ttl_secs"].as_i64().unwrap_or(3600);
                let expires_at = item["expires_at"]
                    .as_str()
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                    .unwrap_or(created_at + chrono::Duration::seconds(ttl_secs));
                lc.active.push(ActiveResponse {
                    id: item["id"].as_str().unwrap_or("").to_string(),
                    response_type,
                    backend: parse_backend(item["backend"].as_str()),
                    target: target.to_string(),
                    incident_id: item["incident_id"].as_str().unwrap_or("").to_string(),
                    created_at,
                    ttl_secs,
                    expires_at,
                    revert_handle: item["revert_handle"].as_str().map(String::from),
                    state: parse_state_from_json(&item["state"]).unwrap_or(LifecycleState::Active),
                });
            }
        }

        // History in natural order (no .rev() on the write side).
        if let Some(arr) = json["history"].as_array() {
            for item in arr {
                let target = item["target"].as_str().unwrap_or_default();
                if target.is_empty() {
                    continue;
                }
                lc.history.push_back(CompletedResponse {
                    id: item["id"].as_str().unwrap_or("").to_string(),
                    response_type: parse_response_type(item["type"].as_str()),
                    backend: parse_backend(item["backend"].as_str()),
                    target: target.to_string(),
                    incident_id: item["incident_id"].as_str().unwrap_or("").to_string(),
                    created_at: item["created_at"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(now),
                    reverted_at: item["reverted_at"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(now),
                    reason: item["reason"].as_str().unwrap_or("expired").to_string(),
                });
            }
        }

        if let Some(totals) = json.get("totals") {
            lc.total_registered = totals["registered"].as_u64().unwrap_or(0);
            lc.total_expired = totals["expired"].as_u64().unwrap_or(0);
            lc.total_reverted = totals["reverted"].as_u64().unwrap_or(0);
            lc.total_revert_failures = totals["revert_failures"].as_u64().unwrap_or(0);
            lc.total_already_absent = totals["already_absent"].as_u64().unwrap_or(0);
            lc.total_orphaned = totals["orphaned"].as_u64().unwrap_or(0);
        }
        lc.next_id = json["next_id"].as_u64().unwrap_or(1);
        Some(lc)
    }

    /// Reconciliation: pick up `block_ip` decisions from today's JSONL
    /// that are not already tracked in `active`. Runs after either v1
    /// or v2 load so code paths that bypass `ResponseLifecycle::register`
    /// (always-on honeypot, dashboard manual actions) still show up on
    /// the `/api/responses` dashboard after a restart.
    fn hydrate_from_decisions_jsonl(lifecycle: &mut Self, data_dir: &std::path::Path) {
        let now = Utc::now();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let decisions_path = data_dir.join(format!("decisions-{today}.jsonl"));
        let Ok(content) = std::fs::read_to_string(&decisions_path) else {
            return;
        };
        let tracked_targets: std::collections::HashSet<String> =
            lifecycle.active.iter().map(|r| r.target.clone()).collect();
        let mut added = 0usize;
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if entry["action_type"].as_str() != Some("block_ip") {
                continue;
            }
            let Some(ip) = entry["target_ip"].as_str() else {
                continue;
            };
            if ip.is_empty() || tracked_targets.contains(ip) {
                continue;
            }
            if !crate::decision_block_ip::is_valid_block_target(ip) {
                tracing::warn!(
                    target = %ip,
                    "skipping invalid target while hydrating from decisions JSONL"
                );
                continue;
            }
            if lifecycle.active.iter().any(|r| r.target == ip) {
                continue;
            }
            let ts = entry["ts"]
                .as_str()
                .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                .unwrap_or(now);
            let ttl = 3600i64;
            let expires_at = ts + chrono::Duration::seconds(ttl);
            if expires_at <= now {
                continue;
            }
            let skill_id = entry["skill_id"].as_str().unwrap_or("block-ip-ufw");
            let backend = if skill_id.contains("xdp") {
                ResponseBackend::Xdp
            } else if skill_id.contains("iptables") {
                ResponseBackend::Iptables
            } else if skill_id.contains("nftables") {
                ResponseBackend::Nftables
            } else {
                ResponseBackend::Ufw
            };
            let incident_id = entry["incident_id"].as_str().unwrap_or("").to_string();
            let id = format!("resp-{}", lifecycle.next_id);
            lifecycle.next_id += 1;
            lifecycle.active.push(ActiveResponse {
                id,
                response_type: ResponseType::BlockIp,
                backend,
                target: ip.to_string(),
                incident_id,
                created_at: ts,
                ttl_secs: ttl,
                expires_at,
                revert_handle: None,
                state: LifecycleState::Active,
            });
            lifecycle.total_registered += 1;
            added += 1;
        }
        if added > 0 {
            info!(added, "hydrated response lifecycle from today's decisions");
        }
    }

    /// SQLite counterpart of `hydrate_from_decisions_jsonl`. Same
    /// semantic — pick up today's `block_ip` decisions that are NOT
    /// already tracked in `lifecycle.active` so always-on-honeypot and
    /// dashboard-manual paths surface on `/api/responses` after a
    /// restart. Reads from the canonical SQLite `decisions` table
    /// (RC-2 follow-up 2026-04-30) instead of the parallel JSONL file
    /// the legacy reconciler scanned.
    ///
    /// Why the body mirrors the JSONL one almost verbatim: the
    /// invariants are exactly the same — skip empty target_ip, skip
    /// invalid targets, skip already-expired, skip already-tracked,
    /// derive backend from skill_id. The only meaningful difference is
    /// the row source (SQLite vs JSONL), so the duplication is
    /// intentional rather than premature abstraction.
    fn hydrate_from_decisions_sqlite(lifecycle: &mut Self, store: &innerwarden_store::Store) {
        Self::hydrate_from_decisions_sqlite_at(lifecycle, store, Utc::now());
    }

    /// Clock-injectable core of `hydrate_from_decisions_sqlite`. Splitting
    /// `now` out keeps the midnight-window behaviour deterministically
    /// testable without touching the global clock.
    fn hydrate_from_decisions_sqlite_at(
        lifecycle: &mut Self,
        store: &innerwarden_store::Store,
        now: DateTime<Utc>,
    ) {
        // Query yesterday and today (UTC). A block's TTL is at most one
        // hour, so a still-active block recorded shortly before midnight
        // lives under yesterday's date partition (`ts LIKE 'date%'`).
        // Querying only `today` silently dropped such blocks on any
        // restart in the first hour after UTC midnight, and made these
        // hydration tests flaky when they ran in the first 60s after
        // midnight (the seeded `now - 60s` row landed under yesterday).
        // The `expires_at <= now` filter below discards anything genuinely
        // past its TTL, so widening the query window cannot resurrect
        // stale blocks.
        let today = now.date_naive();
        let date_strings = [
            (today - chrono::Duration::days(1))
                .format("%Y-%m-%d")
                .to_string(),
            today.format("%Y-%m-%d").to_string(),
        ];
        let mut rows = Vec::new();
        for date in &date_strings {
            match store.block_ip_decisions_for_date(date) {
                Ok(r) => rows.extend(r),
                Err(e) => {
                    warn!(
                        error = %e,
                        date = %date,
                        "block_ip_decisions_for_date failed during hydration"
                    );
                }
            }
        }
        let tracked_targets: std::collections::HashSet<String> =
            lifecycle.active.iter().map(|r| r.target.clone()).collect();
        let mut added = 0usize;
        for (ts_iso, ip, incident_id, data_json) in rows {
            if ip.is_empty() || tracked_targets.contains(&ip) {
                continue;
            }
            if !crate::decision_block_ip::is_valid_block_target(&ip) {
                tracing::warn!(
                    target = %ip,
                    "skipping invalid target while hydrating from SQLite decisions"
                );
                continue;
            }
            if lifecycle.active.iter().any(|r| r.target == ip) {
                continue;
            }
            let ts = ts_iso.parse::<DateTime<Utc>>().unwrap_or(now);
            let ttl = 3600i64;
            let expires_at = ts + chrono::Duration::seconds(ttl);
            if expires_at <= now {
                continue;
            }
            // skill_id lives inside the JSON `data` blob; bare-column
            // schema does not surface it. Parse defensively — a row
            // missing the field still yields a usable ufw default.
            let skill_id = serde_json::from_str::<serde_json::Value>(&data_json)
                .ok()
                .and_then(|v| v.get("skill_id").and_then(|s| s.as_str()).map(String::from))
                .unwrap_or_else(|| "block-ip-ufw".to_string());
            let backend = if skill_id.contains("xdp") {
                ResponseBackend::Xdp
            } else if skill_id.contains("iptables") {
                ResponseBackend::Iptables
            } else if skill_id.contains("nftables") {
                ResponseBackend::Nftables
            } else {
                ResponseBackend::Ufw
            };
            let id = format!("resp-{}", lifecycle.next_id);
            lifecycle.next_id += 1;
            lifecycle.active.push(ActiveResponse {
                id,
                response_type: ResponseType::BlockIp,
                backend,
                target: ip,
                incident_id,
                created_at: ts,
                ttl_secs: ttl,
                expires_at,
                revert_handle: None,
                state: LifecycleState::Active,
            });
            lifecycle.total_registered += 1;
            added += 1;
        }
        if added > 0 {
            info!(
                added,
                "hydrated response lifecycle from sqlite decisions (RC-2 canonical path)"
            );
        }
    }

    /// Register a new response. Returns the response ID.
    pub fn register(
        &mut self,
        response_type: ResponseType,
        backend: ResponseBackend,
        target: &str,
        incident_id: &str,
        ttl_secs: i64,
        revert_handle: Option<String>,
    ) -> String {
        // PR #426 Wave 4e: invariant — caller must dedupe via
        // `is_tracked()` before calling register. A duplicate (target,
        // backend) entry is a real bug shape: the kernel rule already
        // exists, the agent thinks it doesn't, both entries race on
        // revert. This loud failure in tests catches the contract
        // violation; release builds skip the check.
        debug_assert!(
            !self
                .active
                .iter()
                .any(|r| r.target == target && r.backend == backend),
            "register invariant: caller must check is_tracked() first — \
             duplicate (target={target}, backend={backend:?}) would race on revert"
        );

        // Note: ttl_secs = 0 is a legitimate API use (immediate expiry,
        // exercised by the lifecycle's revert-after-expiry tests).
        // Negative TTL is also tolerated — `stage_pending_reverts`
        // handles "already expired" entries deterministically. No
        // invariant assert here.

        let id = format!("resp-{}", self.next_id);
        self.next_id += 1;

        let now = Utc::now();
        let response = ActiveResponse {
            id: id.clone(),
            response_type,
            backend,
            target: target.to_string(),
            incident_id: incident_id.to_string(),
            created_at: now,
            ttl_secs,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            revert_handle,
            state: LifecycleState::Active,
        };

        info!(
            id = %response.id,
            backend = ?response.backend,
            target = %response.target,
            ttl_secs,
            "response registered"
        );

        self.active.push(response);
        self.total_registered += 1;
        id
    }

    /// Scan active entries for work that needs a revert command issued.
    /// Called from the slow loop (every 30s).
    ///
    /// Transitions:
    /// - `Active` with expired TTL → `RevertPending { TtlExpired }`
    /// - `RevertFailed` with attempts < MAX → `RevertPending { <same trigger> }`
    ///
    /// The entry **stays in `active`** after this call. The caller is
    /// responsible for executing each returned `RevertAction` and then calling
    /// `mark_reverted` or `mark_revert_failed` to drive the terminal
    /// transition. This is the fix for the "audit trail lies" bug: until the
    /// revert is confirmed, the entry is never declared complete.
    pub fn stage_pending_reverts(&mut self) -> Vec<RevertAction> {
        let now = Utc::now();
        let mut reverts = Vec::new();

        for entry in self.active.iter_mut() {
            let next_state = match &entry.state {
                LifecycleState::Active if now > entry.expires_at => {
                    Some(LifecycleState::RevertPending {
                        since: now,
                        trigger: RevertTrigger::TtlExpired,
                        prior_attempts: 0,
                    })
                }
                LifecycleState::RevertFailed {
                    attempts, trigger, ..
                } if *attempts < MAX_REVERT_ATTEMPTS => Some(LifecycleState::RevertPending {
                    since: now,
                    trigger: *trigger,
                    // Carry accumulated failures across the ping-pong so
                    // mark_revert_failed can compute new_attempts correctly.
                    prior_attempts: *attempts,
                }),
                _ => None,
            };
            if let Some(next) = next_state {
                entry.state = next;
                reverts.push(RevertAction {
                    id: entry.id.clone(),
                    backend: entry.backend.clone(),
                    target: entry.target.clone(),
                    revert_handle: entry.revert_handle.clone(),
                });
            }
        }

        // Cap history at 1000 entries (history only grows via terminal transitions).
        while self.history.len() > 1000 {
            self.history.pop_front();
        }

        reverts
    }

    /// Request a manual revert for a specific response by ID. Transitions
    /// `Active` or `RevertFailed` to `RevertPending { Manual }` and returns
    /// the action to execute. The caller must then call `mark_reverted` or
    /// `mark_revert_failed` to close the loop.
    #[allow(dead_code)] // wired to POST /api/responses/:id/revert in spec 016
    pub fn request_manual_revert(&mut self, id: &str) -> Option<RevertAction> {
        let now = Utc::now();
        let entry = self.active.iter_mut().find(|r| r.id == id)?;
        // Don't re-stage something already in-flight.
        if matches!(entry.state, LifecycleState::RevertPending { .. }) {
            return None;
        }
        // Preserve accumulated failure count if we're escalating a failed
        // TTL revert to a manual one (rare but valid).
        let prior_attempts = match &entry.state {
            LifecycleState::RevertFailed { attempts, .. } => *attempts,
            _ => 0,
        };
        entry.state = LifecycleState::RevertPending {
            since: now,
            trigger: RevertTrigger::Manual,
            prior_attempts,
        };
        Some(RevertAction {
            id: entry.id.clone(),
            backend: entry.backend.clone(),
            target: entry.target.clone(),
            revert_handle: entry.revert_handle.clone(),
        })
    }

    /// Terminal success path. Called by the executor after a revert command
    /// completed without error (or after a failure was classified as
    /// `AlreadyAbsent`). Moves the entry out of `active` and into `history`.
    ///
    /// `reason` values in practice:
    /// - `"expired"` — normal TTL success
    /// - `"manual"` — dashboard/operator action
    /// - `"already_absent"` — rule was already gone (treated as success)
    pub fn mark_reverted(&mut self, id: &str, reason: &str) {
        let now = Utc::now();
        let Some(idx) = self.active.iter().position(|r| r.id == id) else {
            warn!(id, "mark_reverted called on unknown id");
            return;
        };
        let resp = self.active.remove(idx);
        // Figure out the original trigger if we're mid-pending; fall back to
        // TtlExpired so the counter math stays sane if something weird happens.
        let trigger = match &resp.state {
            LifecycleState::RevertPending { trigger, .. } => *trigger,
            LifecycleState::RevertFailed { trigger, .. } => *trigger,
            LifecycleState::Active => {
                // Caller jumped straight to mark_reverted without staging.
                // This is fine for code paths that own their own revert
                // (Container/Nginx/Sudo), just account it as TTL.
                RevertTrigger::TtlExpired
            }
        };
        match trigger {
            RevertTrigger::TtlExpired => self.total_expired += 1,
            RevertTrigger::Manual => self.total_reverted += 1,
        }
        if reason == "already_absent" {
            self.total_already_absent += 1;
        }
        self.history.push_back(CompletedResponse {
            id: resp.id,
            response_type: resp.response_type,
            backend: resp.backend,
            target: resp.target,
            incident_id: resp.incident_id,
            created_at: resp.created_at,
            reverted_at: now,
            reason: reason.to_string(),
        });
        while self.history.len() > 1000 {
            self.history.pop_front();
        }
    }

    /// Terminal failure path. Called by the executor after a revert command
    /// returned an error. Classifies the error autonomously:
    ///
    /// - `AlreadyAbsent` (stderr indicates the rule was gone) → entry moves to
    ///   history as `already_absent` (success).
    /// - `Transient` + `attempts < MAX` → entry transitions to `RevertFailed`,
    ///   stays in active, will be retried next tick.
    /// - `Transient` + `attempts >= MAX` → entry moves to history as
    ///   `orphaned`. Returns `FailureOutcome::Orphaned { .. }` so the caller
    ///   can fire a high-severity alert via the normal notification pipeline.
    pub fn mark_revert_failed(&mut self, id: &str, error: String) -> FailureOutcome {
        let now = Utc::now();
        self.total_revert_failures += 1;

        let Some(idx) = self.active.iter().position(|r| r.id == id) else {
            warn!(id, "mark_revert_failed called on unknown id");
            return FailureOutcome::UnknownId;
        };

        // Determine trigger and prior attempts from the current state.
        // The source of truth for `prior_attempts` is whichever state the
        // entry is currently in — RevertPending carries it forward from the
        // previous RevertFailed (if any) via stage_pending_reverts.
        let (trigger, prior_attempts) = match &self.active[idx].state {
            LifecycleState::RevertPending {
                trigger,
                prior_attempts,
                ..
            } => (*trigger, *prior_attempts),
            LifecycleState::RevertFailed {
                trigger, attempts, ..
            } => (*trigger, *attempts),
            LifecycleState::Active => {
                // Unexpected — we got a failure report for something that
                // was never staged. Log and treat as transient with 0 prior
                // attempts so retry logic still applies.
                warn!(id, "mark_revert_failed called on entry in Active state");
                (RevertTrigger::TtlExpired, 0u32)
            }
        };

        let kind = classify_revert_error(&error);
        if kind == ErrorKind::AlreadyAbsent {
            // Rule was already gone — success in disguise. Caller-provided
            // error becomes part of the audit trail via `reason`.
            info!(id, %error, "revert target already absent — treating as success");
            self.mark_reverted(id, "already_absent");
            return FailureOutcome::AlreadyAbsent;
        }

        let new_attempts = prior_attempts + 1;
        if new_attempts >= MAX_REVERT_ATTEMPTS {
            // Exhausted. Move to history as orphaned and surface to caller.
            let resp = self.active.remove(idx);
            let backend = resp.backend.clone();
            let target = resp.target.clone();
            let last_error = error.clone();
            self.total_orphaned += 1;
            self.history.push_back(CompletedResponse {
                id: resp.id,
                response_type: resp.response_type,
                backend: resp.backend,
                target: resp.target,
                incident_id: resp.incident_id,
                created_at: resp.created_at,
                reverted_at: now,
                reason: format!("orphaned: {error}"),
            });
            while self.history.len() > 1000 {
                self.history.pop_front();
            }
            warn!(
                id,
                backend = ?backend,
                target = %target,
                attempts = new_attempts,
                error = %error,
                "response ORPHANED — revert retries exhausted, rule may still be active"
            );
            return FailureOutcome::Orphaned {
                backend,
                target,
                last_error,
                trigger,
            };
        }

        // Still have retry budget. Transition to RevertFailed and keep in active.
        self.active[idx].state = LifecycleState::RevertFailed {
            last_attempt_at: now,
            attempts: new_attempts,
            last_error: error,
            trigger,
        };
        warn!(
            id,
            attempts = new_attempts,
            max = MAX_REVERT_ATTEMPTS,
            "revert failed — will retry on next cleanup tick"
        );
        FailureOutcome::Retrying {
            attempt: new_attempts,
        }
    }

    /// 2026-05-02 audit B3 fix: garbage-collect orphaned history
    /// entries older than `older_than_secs`. Returns the number of
    /// entries pruned. The auditor saw 17 orphaned response entries
    /// sitting in `responses.json` for >48 h with no GC step and no
    /// retry path; this sweep is the GC half of the contract.
    ///
    /// Scope is intentionally narrow: we only prune entries whose
    /// `reason` field starts with `"orphaned:"` (the format written by
    /// `mark_revert_failed` when retries exhaust). Other reasons
    /// (`expired`, `manual`, `already_absent`) stay in history at the
    /// 1000-entry cap regardless of age — they are part of the audit
    /// trail an operator legitimately wants to look back on.
    ///
    /// Pruning is silent at INFO level when 0 entries are removed and
    /// at WARN when any are — orphaned drift is exactly the class of
    /// signal the operator wants to see in journald. The returned
    /// count is also surfaced via Prometheus by the slow-loop caller.
    pub fn gc_orphaned_responses(&mut self, older_than_secs: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::seconds(older_than_secs);
        let before = self.history.len();
        self.history.retain(|r| {
            // Only orphaned entries are eligible for GC. Other
            // completion reasons (expired/manual/already_absent) are
            // legitimate audit trail; the 1000-entry cap on history
            // already bounds those.
            if !r.reason.starts_with("orphaned:") {
                return true;
            }
            r.reverted_at > cutoff
        });
        let pruned = before - self.history.len();
        if pruned > 0 {
            warn!(
                pruned,
                older_than_hours = older_than_secs / 3600,
                "response lifecycle: pruned {pruned} orphaned response history entries older \
                 than {} h (audit B3) — original revert attempts exhausted long ago, kernel \
                 state has drifted; check `journalctl -u innerwarden-agent | grep ORPHANED` \
                 for the original failures",
                older_than_secs / 3600
            );
        }
        pruned
    }

    /// Get all currently active responses.
    #[allow(dead_code)] // snapshot read path for the dashboard lifecycle view
    pub fn list_active(&self) -> &[ActiveResponse] {
        &self.active
    }

    /// Get recent history of completed (expired/reverted) responses.
    #[allow(dead_code)] // snapshot read path for the dashboard history drawer
    pub fn list_history(&self) -> &VecDeque<CompletedResponse> {
        &self.history
    }
}

/// Per-orphan diagnostic emitted by the dashboard's `/api/responses/orphans`
/// endpoint. Each field maps directly to a card row the operator sees.
#[derive(Debug, Clone, Serialize)]
pub struct OrphanDiagnostic {
    pub id: String,
    pub target: String,
    pub backend: ResponseBackend,
    pub incident_id: String,
    pub created_at: DateTime<Utc>,
    pub reverted_at: DateTime<Utc>,
    /// Stderr from the last revert attempt (parsed out of
    /// `CompletedResponse::reason` which has shape `"orphaned: <error>"`).
    pub last_error: String,
    /// Operator-facing classification of the failure mode. Cluster
    /// header on the dashboard groups orphans by this value so a
    /// single fix (`enable IPv6 in /etc/default/ufw`) can resolve
    /// many at once.
    pub cluster: OrphanErrorCluster,
    /// Human-readable string describing what command the agent tried
    /// to run during revert. NOT executed at diagnostic time —
    /// purely informational. The actual revert path lives in
    /// `execute_revert` and is unchanged.
    pub revert_command: String,
    /// PR #420 Wave 3: operator resolution if one has been recorded.
    /// `None` means the orphan is still unresolved. The dashboard
    /// uses this to filter resolved orphans out of the live cluster
    /// summary while still surfacing them in a "resolved" section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<OrphanResolution>,
}

/// Operator-facing classification of orphan revert failure patterns.
/// Mapping is heuristic but covers the common modes documented in
/// the explore agent's pre-PR-#419 audit:
///   - IPv6 rule format mismatch
///   - nftables handle missing
///   - rule already absent (false orphan, kernel state actually clean)
///   - permission / sudo timeout
///   - external mutation (rule renumbered or removed by fail2ban etc)
///   - unknown / catch-all
///
/// The dashboard groups orphans by this enum and shows the suggested
/// fix per cluster (Wave 4 telemetry pass extends with counters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrphanErrorCluster {
    Ipv6Mismatch,
    NftablesHandleMissing,
    RuleAlreadyAbsent,
    PermissionDenied,
    ExternalMutation,
    Unknown,
}

/// Pure classifier — keeps the matching logic testable without
/// touching the lifecycle state.
pub fn classify_orphan_error(stderr: &str) -> OrphanErrorCluster {
    let s = stderr.to_lowercase();
    // IPv6: agent created an IPv6 rule but the codepath used IPv4
    // commands (iptables only handles v4 — uses `ip6tables` for v6).
    if s.contains("ipv6")
        || s.contains("inet6")
        || s.contains("address family")
        || s.contains("does not match")
    {
        return OrphanErrorCluster::Ipv6Mismatch;
    }
    // nftables-specific: handle stored at create time was None.
    if s.contains("no nftables handle") || s.contains("handle missing") {
        return OrphanErrorCluster::NftablesHandleMissing;
    }
    // The rule was already absent — false orphan.
    if s.contains("non-existent")
        || s.contains("does not exist")
        || s.contains("not found")
        || s.contains("no such")
        || s.contains("matching rule exist")
    {
        return OrphanErrorCluster::RuleAlreadyAbsent;
    }
    // Permission / sudo issues.
    if s.contains("permission denied")
        || s.contains("operation not permitted")
        || s.contains("must be run as root")
        || s.contains("sudo: a password is required")
    {
        return OrphanErrorCluster::PermissionDenied;
    }
    // External mutation — fail2ban or manual edits renumbered or
    // rewrote the rule between create and delete.
    if s.contains("rule renumber") || s.contains("file modified") {
        return OrphanErrorCluster::ExternalMutation;
    }
    OrphanErrorCluster::Unknown
}

/// Describe the revert command shape per backend. Operator-facing
/// hint shown on the diagnostic card. Mirrors the actual commands
/// run in `execute_revert` so the operator sees what the agent
/// tried, even when the lifecycle bookkeeping records only the
/// stderr.
pub fn describe_revert_command(backend: &ResponseBackend, target: &str) -> String {
    match backend {
        ResponseBackend::Ufw => format!("sudo ufw delete deny from {target}"),
        ResponseBackend::Iptables => {
            format!("sudo iptables -D INPUT -s {target} -j DROP")
        }
        ResponseBackend::Nftables => {
            format!("sudo nft delete rule inet filter input <handle> (target {target})")
        }
        ResponseBackend::Pf => format!("(pf manual revert: target {target})"),
        ResponseBackend::Xdp => {
            format!("sudo bpftool map delete pinned /sys/fs/bpf/innerwarden/blocklist key {target}")
        }
        ResponseBackend::Cloudflare => format!("(cloudflare api revert: target {target})"),
        ResponseBackend::Nginx => format!("(nginx config revert: target {target})"),
        ResponseBackend::Container => format!("(container unpause: target {target})"),
        ResponseBackend::Sudo => {
            format!("(sudo restore: gpasswd -d {target} suspended-ops; cleanup .iw-suspended)")
        }
    }
}

/// 2026-05-03 (PR #419 Wave 2): parse the persisted `responses.json`
/// (or SQLite blob) and enumerate orphan entries with diagnostic
/// classification. The dashboard endpoint reads from disk rather
/// than the in-memory lifecycle (matches the existing `/api/responses`
/// pattern), so this helper takes the raw JSON shape and walks
/// the `history` array.
pub fn enumerate_orphans_from_responses_json(raw: &str) -> Vec<OrphanDiagnostic> {
    let Ok(value): Result<serde_json::Value, _> = serde_json::from_str(raw) else {
        return Vec::new();
    };
    let history = match value.get("history").and_then(|h| h.as_array()) {
        Some(arr) => arr,
        None => return Vec::new(),
    };
    history
        .iter()
        .filter_map(|entry| {
            let reason = entry.get("reason").and_then(|r| r.as_str())?;
            if !reason.starts_with("orphaned:") {
                return None;
            }
            let last_error = reason
                .strip_prefix("orphaned:")
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let cluster = classify_orphan_error(&last_error);
            let backend = parse_backend(entry.get("backend").and_then(|b| b.as_str()));
            let target = entry
                .get("target")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let revert_command = describe_revert_command(&backend, &target);
            let id = entry
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            let incident_id = entry
                .get("incident_id")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            let created_at = entry
                .get("created_at")
                .and_then(|s| s.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&chrono::Utc))
                .unwrap_or_else(chrono::Utc::now);
            let reverted_at = entry
                .get("reverted_at")
                .and_then(|s| s.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&chrono::Utc))
                .unwrap_or_else(chrono::Utc::now);
            Some(OrphanDiagnostic {
                id,
                target,
                backend,
                incident_id,
                created_at,
                reverted_at,
                last_error,
                cluster,
                revert_command,
                resolution: None,
            })
        })
        .collect()
}

// ─── PR #420 Wave 3 — operator-driven orphan resolution ───────────
//
// The dashboard cannot mutate the agent loop's `ResponseLifecycle`
// directly (different ownership). Instead, operator decisions are
// appended to a sidecar JSONL `orphan_resolutions.jsonl` in the
// data dir. The orphan diagnostic enumerator joins against this
// file so resolved orphans are filtered (or surfaced separately).
// Append-only — every operator action keeps an audit trail outside
// of `admin-actions-YYYY-MM-DD.jsonl` so re-resolving an id keeps
// each step.

/// Operator-driven resolution recorded by Wave 3 dashboard endpoints.
/// Stored as a JSONL line in `<data_dir>/orphan_resolutions.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanResolution {
    /// Orphan id (matches `CompletedResponse::id`).
    pub orphan_id: String,
    /// "cleared" — operator reviewed and confirms the entry is stale.
    /// "already_gone" — operator confirms the kernel state was actually clean.
    pub kind: String,
    /// Operator-supplied free-text reason. Mandatory at API boundary.
    pub reason: String,
    /// Dashboard username (basic-auth user) at the time of action.
    pub operator: String,
    /// When the resolution was recorded.
    pub resolved_at: DateTime<Utc>,
}

impl OrphanResolution {
    /// Allowed values of `kind`. Public so the handler validates input
    /// against the same list — no string magic in two places.
    pub const KIND_CLEARED: &'static str = "cleared";
    pub const KIND_ALREADY_GONE: &'static str = "already_gone";
}

/// Append-only writer for `orphan_resolutions.jsonl`. Relies on POSIX
/// `O_APPEND` atomicity for writes shorter than `PIPE_BUF` (4096 B on
/// Linux/macOS) — a single resolution line is ~250 B so concurrent
/// dashboard clicks cannot interleave. No `flock` ceremony.
pub fn append_orphan_resolution(
    data_dir: &std::path::Path,
    resolution: &OrphanResolution,
) -> std::io::Result<()> {
    use std::io::Write;
    let canonical = std::fs::canonicalize(data_dir)?;
    let path = canonical.join("orphan_resolutions.jsonl");
    if !path.starts_with(&canonical) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "constructed path escapes data directory",
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let line = serde_json::to_string(resolution)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("serde: {e}")))?;
    // Compose the full line + newline first so the kernel sees a
    // single write() — keeps it under PIPE_BUF and atomic with O_APPEND.
    let bytes = format!("{line}\n");
    file.write_all(bytes.as_bytes())?;
    file.flush()
}

/// Read every resolution recorded so far. Last-write-wins per orphan
/// id (operator may revise their decision; the latest line is the
/// effective one). Malformed lines are skipped, never panic.
///
/// Canonicalizes `data_dir` and rejects paths that escape it. Mirrors
/// the writer's CWE-22 guard so CodeQL `rust/path-injection` is closed
/// on both directions.
pub fn read_orphan_resolutions(
    data_dir: &std::path::Path,
) -> std::collections::HashMap<String, OrphanResolution> {
    use std::collections::HashMap;
    // Canonicalize the directory; if it can't be resolved the file
    // also can't be read — return empty.
    let canonical = match std::fs::canonicalize(data_dir) {
        Ok(p) => p,
        Err(_) => return HashMap::new(),
    };
    let path = canonical.join("orphan_resolutions.jsonl");
    if !path.starts_with(&canonical) {
        // Defence in depth: a future change that constructs the
        // filename dynamically must not escape data_dir.
        return HashMap::new();
    }
    // Stream the resolutions log line by line rather than holding the whole
    // file in RAM only to build a last-wins map.
    use std::io::BufRead as _;
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return HashMap::new(),
    };
    let mut latest: HashMap<String, OrphanResolution> = HashMap::new();
    for line in std::io::BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
    {
        if let Ok(r) = serde_json::from_str::<OrphanResolution>(&line) {
            // Last-wins: a later append overrides earlier resolutions
            // for the same orphan id (operator changed their mind).
            latest.insert(r.orphan_id.clone(), r);
        }
    }
    latest
}

impl ResponseLifecycle {
    /// Check if an IP is already tracked (to avoid duplicates).
    pub fn is_tracked(&self, target: &str, backend: &ResponseBackend) -> bool {
        self.active
            .iter()
            .any(|r| r.target == target && &r.backend == backend)
    }

    /// True if `ip` has a live `BlockIp` response right now: an entry that is
    /// still `Active` and whose TTL has not expired. This is the
    /// **TTL-accurate** "currently blocked" view — unlike `state.blocklist`
    /// (a `HashSet` that is NOT pruned when a block's TTL expires; the XDP
    /// cleanup loop only prunes `xdp_block_times`). Callers use this to skip
    /// redundant work for an already-blocked IP without the risk of treating
    /// an expired block as still active.
    ///
    /// Field evidence (oneroom Hetzner, 2026-05-31): a single threat-feed IP
    /// that was already firewall-blocked re-fired `threat_intel` every cycle;
    /// each re-fire re-ran the block (re-adding a live ufw rule) and leaked the
    /// fresh incident to the orphan-recovery sweep — 9 re-blocks + 68 dismisses
    /// for one IP in a day. Gating that churn on this check stops it.
    pub fn is_ip_actively_blocked(&self, ip: &str, now: DateTime<Utc>) -> bool {
        self.active.iter().any(|r| {
            r.response_type == ResponseType::BlockIp
                && r.target == ip
                && r.state == LifecycleState::Active
                && r.expires_at > now
        })
    }

    /// Lifecycle ids of every `BlockIp` entry currently tracked for `ip`,
    /// regardless of TTL/state (a `RevertFailed` entry is still a live rule we
    /// must try to revert). Used by the operator-unblock drain to drive each
    /// entry through `request_manual_revert` → `execute_revert` →
    /// `mark_reverted`. Returns an empty vec when the IP has no tracked block.
    pub fn active_block_ids_for_ip(&self, ip: &str) -> Vec<String> {
        self.active
            .iter()
            .filter(|r| r.response_type == ResponseType::BlockIp && r.target == ip)
            .map(|r| r.id.clone())
            .collect()
    }

    /// Generate Prometheus metrics lines.
    #[allow(dead_code)] // exposed by /metrics endpoint in spec 016
    pub fn to_prometheus_lines(&self) -> String {
        let mut out = String::new();

        out.push_str("# HELP innerwarden_responses_active Currently active response actions\n");
        out.push_str("# TYPE innerwarden_responses_active gauge\n");

        // Count by backend
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for r in &self.active {
            let key = match r.backend {
                ResponseBackend::Xdp => "xdp",
                ResponseBackend::Ufw => "ufw",
                ResponseBackend::Iptables => "iptables",
                ResponseBackend::Nftables => "nftables",
                ResponseBackend::Pf => "pf",
                ResponseBackend::Cloudflare => "cloudflare",
                ResponseBackend::Nginx => "nginx",
                ResponseBackend::Container => "container",
                ResponseBackend::Sudo => "sudo",
            };
            *counts.entry(key).or_default() += 1;
        }
        for (backend, count) in &counts {
            out.push_str(&format!(
                "innerwarden_responses_active{{backend=\"{backend}\"}} {count}\n"
            ));
        }

        out.push_str("# HELP innerwarden_responses_total Total response actions registered\n");
        out.push_str("# TYPE innerwarden_responses_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_total {}\n",
            self.total_registered
        ));

        out.push_str("# HELP innerwarden_responses_expired_total Responses expired by TTL\n");
        out.push_str("# TYPE innerwarden_responses_expired_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_expired_total {}\n",
            self.total_expired
        ));

        out.push_str("# HELP innerwarden_responses_reverted_total Responses manually reverted\n");
        out.push_str("# TYPE innerwarden_responses_reverted_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_reverted_total {}\n",
            self.total_reverted
        ));

        out.push_str("# HELP innerwarden_responses_revert_failures_total Count of failed revert attempts (not entries)\n");
        out.push_str("# TYPE innerwarden_responses_revert_failures_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_revert_failures_total {}\n",
            self.total_revert_failures
        ));

        out.push_str("# HELP innerwarden_responses_already_absent_total Reverts that resolved because rule was already gone\n");
        out.push_str("# TYPE innerwarden_responses_already_absent_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_already_absent_total {}\n",
            self.total_already_absent
        ));

        out.push_str("# HELP innerwarden_responses_orphaned_total Responses given up on — rule may still be active in kernel/firewall\n");
        out.push_str("# TYPE innerwarden_responses_orphaned_total counter\n");
        out.push_str(&format!(
            "innerwarden_responses_orphaned_total {}\n",
            self.total_orphaned
        ));

        // Break down current active entries by state for live drift visibility.
        let (n_active, n_pending, n_failed) = self.state_counts();
        out.push_str(
            "# HELP innerwarden_responses_by_state Active entries broken down by lifecycle state\n",
        );
        out.push_str("# TYPE innerwarden_responses_by_state gauge\n");
        out.push_str(&format!(
            "innerwarden_responses_by_state{{state=\"active\"}} {n_active}\n"
        ));
        out.push_str(&format!(
            "innerwarden_responses_by_state{{state=\"revert_pending\"}} {n_pending}\n"
        ));
        out.push_str(&format!(
            "innerwarden_responses_by_state{{state=\"revert_failed\"}} {n_failed}\n"
        ));

        out
    }

    /// Count entries by lifecycle state. Used for metrics and tests.
    pub fn state_counts(&self) -> (usize, usize, usize) {
        let mut n_active = 0usize;
        let mut n_pending = 0usize;
        let mut n_failed = 0usize;
        for r in &self.active {
            match r.state {
                LifecycleState::Active => n_active += 1,
                LifecycleState::RevertPending { .. } => n_pending += 1,
                LifecycleState::RevertFailed { .. } => n_failed += 1,
            }
        }
        (n_active, n_pending, n_failed)
    }

    /// PR #425 Wave 4d: count *current* orphans, not the cumulative counter.
    ///
    /// `total_orphaned` is monotonic — it never decreases, by design (audit
    /// trail / Prometheus counter convention). Until 2026-05-03 the dashboard
    /// banner read this as if it were a gauge, displaying "17 orphaned
    /// responses (rule may still be active)" months after the actual entries
    /// had been GC'd, which gaslit the operator into looking for ghost rules.
    ///
    /// "Current orphans" = sum of two buckets:
    ///
    /// 1. `history` entries whose `reason` starts with `orphaned:` — the
    ///    operator-visible, still-pending audit gap. PR #408's GC sweep
    ///    eventually prunes these (default 7-day retention) but they remain
    ///    visible during the diagnostic window.
    /// 2. `active` entries with `state.kind == revert_failed` — defense in
    ///    depth. The lifecycle is *supposed* to move retried-failed entries
    ///    out of `active`, but if the move ever races a snapshot save, the
    ///    operator-visible count still reflects reality.
    ///
    /// Returns 0 on a healthy system. Any non-zero value is the right number
    /// for the banner to scream about, never the lifetime counter.
    pub fn current_orphan_count(&self) -> usize {
        let in_history = self
            .history
            .iter()
            .filter(|r| r.reason.starts_with("orphaned:"))
            .count();
        let in_active = self
            .active
            .iter()
            .filter(|r| matches!(r.state, LifecycleState::RevertFailed { .. }))
            .count();
        in_history + in_active
    }

    /// Serialize active responses as JSON (for /api/responses).
    /// Canonical persistence snapshot (v2). Distinct from `to_json()`,
    /// which is the dashboard view. `to_json()` reverses history for
    /// "most recent first" display and caps at 50 entries, and silently
    /// drops `revert_handle` and `next_id`; those choices are correct
    /// for presentation but wrong for restart, which is why this
    /// method exists.
    pub fn to_snapshot(&self) -> serde_json::Value {
        let active: Vec<serde_json::Value> = self
            .active
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "type": r.response_type,
                    "backend": r.backend,
                    "target": r.target,
                    "incident_id": r.incident_id,
                    "created_at": r.created_at.to_rfc3339(),
                    "expires_at": r.expires_at.to_rfc3339(),
                    "ttl_secs": r.ttl_secs,
                    "revert_handle": r.revert_handle,
                    "state": r.state,
                })
            })
            .collect();
        // Natural push_back order, no truncation — full history round-trips.
        let history: Vec<serde_json::Value> = self
            .history
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "type": r.response_type,
                    "backend": r.backend,
                    "target": r.target,
                    "incident_id": r.incident_id,
                    "created_at": r.created_at.to_rfc3339(),
                    "reverted_at": r.reverted_at.to_rfc3339(),
                    "reason": r.reason,
                })
            })
            .collect();
        serde_json::json!({
            "schema_version": 2,
            "next_id": self.next_id,
            "active": active,
            "history": history,
            "totals": {
                "registered": self.total_registered,
                "expired": self.total_expired,
                "reverted": self.total_reverted,
                "revert_failures": self.total_revert_failures,
                "already_absent": self.total_already_absent,
                "orphaned": self.total_orphaned,
            },
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        let now = Utc::now();
        let active: Vec<serde_json::Value> = self
            .active
            .iter()
            .map(|r| {
                let remaining = (r.expires_at - now).num_seconds().max(0);
                // Spec 076 phase 2: surface when the rule was last confirmed live
                // so the dashboard can show "enforced (verified)" vs a stale TTL.
                let verified = self.verified_live.get(&r.target);
                let verified_recent = verified
                    .map(|t| (now - *t).num_seconds() < ENFORCEMENT_VERIFY_STALE_SECS)
                    .unwrap_or(false);
                serde_json::json!({
                    "id": r.id,
                    "type": r.response_type,
                    "backend": r.backend,
                    "target": r.target,
                    "incident_id": r.incident_id,
                    "created_at": r.created_at.to_rfc3339(),
                    "expires_at": r.expires_at.to_rfc3339(),
                    "ttl_secs": r.ttl_secs,
                    "remaining_secs": remaining,
                    "state": r.state,
                    "last_verified_live": verified.map(|t| t.to_rfc3339()),
                    "enforcement_verified": verified_recent,
                })
            })
            .collect();

        let history: Vec<serde_json::Value> = self
            .history
            .iter()
            .rev()
            .take(50)
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "type": r.response_type,
                    "backend": r.backend,
                    "target": r.target,
                    "incident_id": r.incident_id,
                    "created_at": r.created_at.to_rfc3339(),
                    "reverted_at": r.reverted_at.to_rfc3339(),
                    "reason": r.reason,
                })
            })
            .collect();

        let (n_active, n_pending, n_failed) = self.state_counts();
        let orphans_now = self.current_orphan_count();

        // PR #425 Wave 4d: explicit gauge / counter separation in the JSON
        // shape. Frontend reads `gauges.*` for "right now" displays
        // (banner, KPI grid current-state cards, sub-header) and reads
        // `totals.*` only when the operator is explicitly looking at
        // lifetime numbers. Pre-Wave-4d the dashboard read `totals.orphaned`
        // for the banner, which lied because counters never decrement.
        serde_json::json!({
            "active": active,
            "active_count": self.active.len(),
            "state_counts": {
                "active": n_active,
                "revert_pending": n_pending,
                "revert_failed": n_failed,
            },
            "gauges": {
                "active": self.active.len(),
                "in_retry": n_failed,
                "pending": n_pending,
                "orphaned": orphans_now,
            },
            "history": history,
            "totals": {
                "registered": self.total_registered,
                "expired": self.total_expired,
                "reverted": self.total_reverted,
                "revert_failures": self.total_revert_failures,
                "already_absent": self.total_already_absent,
                "orphaned": self.total_orphaned,
            }
        })
    }
}

fn parse_backend(s: Option<&str>) -> ResponseBackend {
    match s.unwrap_or("ufw") {
        "xdp" => ResponseBackend::Xdp,
        "iptables" => ResponseBackend::Iptables,
        "nftables" => ResponseBackend::Nftables,
        "pf" => ResponseBackend::Pf,
        "cloudflare" => ResponseBackend::Cloudflare,
        "nginx" => ResponseBackend::Nginx,
        "container" => ResponseBackend::Container,
        "sudo" => ResponseBackend::Sudo,
        _ => ResponseBackend::Ufw,
    }
}

fn parse_response_type(s: Option<&str>) -> ResponseType {
    match s.unwrap_or("block_ip") {
        "block_container" => ResponseType::BlockContainer,
        "suspend_sudo" => ResponseType::SuspendSudo,
        "rate_limit_nginx" => ResponseType::RateLimitNginx,
        "kill_process" => ResponseType::KillProcess,
        _ => ResponseType::BlockIp,
    }
}

/// Parse a serialized `LifecycleState` back out of JSON. Missing/unknown
/// shapes fall back to `Active` so legacy snapshots just work. Only used by
/// `load_snapshot`.
fn parse_state_from_json(v: &serde_json::Value) -> Option<LifecycleState> {
    let kind = v.get("kind").and_then(|k| k.as_str())?;
    match kind {
        "active" => Some(LifecycleState::Active),
        "revert_pending" => {
            let since = v
                .get("since")
                .and_then(|s| s.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(Utc::now);
            let trigger = parse_trigger(v.get("trigger")).unwrap_or(RevertTrigger::TtlExpired);
            let prior_attempts = v
                .get("prior_attempts")
                .and_then(|a| a.as_u64())
                .unwrap_or(0) as u32;
            Some(LifecycleState::RevertPending {
                since,
                trigger,
                prior_attempts,
            })
        }
        "revert_failed" => {
            let last_attempt_at = v
                .get("last_attempt_at")
                .and_then(|s| s.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(Utc::now);
            let attempts = v.get("attempts").and_then(|a| a.as_u64()).unwrap_or(0) as u32;
            let last_error = v
                .get("last_error")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let trigger = parse_trigger(v.get("trigger")).unwrap_or(RevertTrigger::TtlExpired);
            Some(LifecycleState::RevertFailed {
                last_attempt_at,
                attempts,
                last_error,
                trigger,
            })
        }
        _ => None,
    }
}

fn parse_trigger(v: Option<&serde_json::Value>) -> Option<RevertTrigger> {
    match v.and_then(|s| s.as_str())? {
        "ttl_expired" => Some(RevertTrigger::TtlExpired),
        "manual" => Some(RevertTrigger::Manual),
        _ => None,
    }
}

/// Execute a revert action on the appropriate backend.
///
/// Returns `Ok(())` on success (or when the backend's revert is a no-op
/// tracked elsewhere). Returns `Err(stderr_like_string)` on failure so the
/// caller can classify and decide retry/orphan. The string is what the
/// autonomous classifier in `mark_revert_failed` inspects — it MUST contain
/// the raw stderr from the backend tool when that's what failed, so patterns
/// like "no such", "non-existent", etc. flow through.
pub async fn execute_revert(revert: &RevertAction, dry_run: bool) -> Result<(), String> {
    let desc = format!("{:?} {}", revert.backend, revert.target);

    if dry_run {
        info!(id = %revert.id, action = %desc, "DRY RUN: would revert response");
        return Ok(());
    }

    let result = match &revert.backend {
        ResponseBackend::Ufw => {
            run_cmd("sudo", &["ufw", "delete", "deny", "from", &revert.target]).await
        }
        ResponseBackend::Iptables => {
            run_cmd(
                "sudo",
                &[
                    "iptables",
                    "-D",
                    "INPUT",
                    "-s",
                    &revert.target,
                    "-j",
                    "DROP",
                ],
            )
            .await
        }
        ResponseBackend::Nftables => {
            if let Some(handle) = &revert.revert_handle {
                run_cmd(
                    "sudo",
                    &[
                        "nft", "delete", "rule", "inet", "filter", "input", "handle", handle,
                    ],
                )
                .await
            } else {
                Err("no nftables handle stored for revert".to_string())
            }
        }
        ResponseBackend::Xdp => {
            // XDP revert via bpftool — parse IP octets.
            if let Ok(addr) = revert.target.parse::<std::net::Ipv4Addr>() {
                let b = addr.octets();
                run_cmd(
                    "sudo",
                    &[
                        "bpftool",
                        "map",
                        "delete",
                        "pinned",
                        "/sys/fs/bpf/innerwarden/blocklist",
                        "key",
                        &b[0].to_string(),
                        &b[1].to_string(),
                        &b[2].to_string(),
                        &b[3].to_string(),
                    ],
                )
                .await
            } else {
                Err(format!("cannot parse IP for XDP revert: {}", revert.target))
            }
        }
        // Container, Nginx, Sudo reverts are still handled by their existing
        // cleanup functions (file-based metadata with expires_at). The lifecycle
        // tracks them for dashboard visibility but delegates revert to the
        // existing code paths.
        ResponseBackend::Container | ResponseBackend::Nginx | ResponseBackend::Sudo => {
            // These are managed by their own metadata files and cleanup functions.
            // The lifecycle tracks them for visibility only.
            Ok(())
        }
        ResponseBackend::Cloudflare | ResponseBackend::Pf => {
            // Cloudflare: would need rule_id to delete. PF: macOS only.
            // Not auto-reverted for now.
            warn!(backend = ?revert.backend, "auto-revert not implemented for this backend");
            Ok(())
        }
    };

    if result.is_ok() {
        info!(id = %revert.id, backend = ?revert.backend, target = %revert.target, "response reverted");
    }
    result
}

async fn run_cmd(program: &str, args: &[&str]) -> Result<(), String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("spawn {program}: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "{program} {} exited {}: {}",
            args.join(" "),
            output.status,
            stderr.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(lc: &mut ResponseLifecycle, ip: &str, ttl: i64) -> String {
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Ufw,
            ip,
            "inc-test",
            ttl,
            None,
        )
    }

    #[test]
    fn verified_live_drives_to_json_enforcement_flag() {
        // Spec 076 phase 2: the reconciler stamps last_verified_live; the
        // dashboard JSON reflects it so "enforced" means the rule is live.
        let mut lc = ResponseLifecycle::new();
        let now = Utc::now();
        reg(&mut lc, "203.0.113.7", 3600);

        let targets = lc.active_block_ip_targets(now);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, "203.0.113.7");

        // Before verification: unverified, no timestamp.
        let j = lc.to_json();
        assert_eq!(
            j["active"][0]["enforcement_verified"],
            serde_json::json!(false)
        );
        assert!(j["active"][0]["last_verified_live"].is_null());

        // After the reconciler confirms it live: verified + timestamp present.
        lc.mark_verified_live("203.0.113.7", Utc::now());
        let j2 = lc.to_json();
        assert_eq!(
            j2["active"][0]["enforcement_verified"],
            serde_json::json!(true)
        );
        assert!(j2["active"][0]["last_verified_live"].is_string());
    }

    #[test]
    fn is_ip_actively_blocked_true_for_live_block_false_for_expired_or_other() {
        let mut lc = ResponseLifecycle::new();
        let now = Utc::now();

        // Live block (1h TTL): expires_at well in the future → actively blocked.
        reg(&mut lc, "1.2.3.4", 3600);
        assert!(lc.is_ip_actively_blocked("1.2.3.4", now));

        // A different IP is not blocked.
        assert!(!lc.is_ip_actively_blocked("9.9.9.9", now));

        // An expired block (negative TTL → expires_at in the past) is NOT
        // active, even though `state.blocklist` would still contain the IP.
        reg(&mut lc, "5.6.7.8", -10);
        assert!(!lc.is_ip_actively_blocked("5.6.7.8", now));

        // A non-BlockIp response on an IP-shaped target must not count as a
        // block (e.g. an nginx rate-limit on the same address).
        lc.register(
            ResponseType::RateLimitNginx,
            ResponseBackend::Nginx,
            "10.0.0.1",
            "inc-test",
            3600,
            None,
        );
        assert!(!lc.is_ip_actively_blocked("10.0.0.1", now));
    }

    #[test]
    fn test_register_and_expire_success_path() {
        let mut lc = ResponseLifecycle::new();

        // Register with 0-second TTL (expires immediately).
        let id = reg(&mut lc, "1.2.3.4", 0);

        assert_eq!(lc.list_active().len(), 1);
        assert!(matches!(lc.list_active()[0].state, LifecycleState::Active));

        std::thread::sleep(std::time::Duration::from_millis(10));

        // Stage should find it expired and transition to RevertPending, NOT
        // move it to history — the audit trail only records confirmed reverts.
        let staged = lc.stage_pending_reverts();
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].target, "1.2.3.4");
        assert_eq!(staged[0].backend, ResponseBackend::Ufw);
        assert_eq!(
            lc.list_active().len(),
            1,
            "entry stays in active until confirmed"
        );
        assert!(
            lc.list_history().is_empty(),
            "history must not grow before confirmation"
        );
        assert!(matches!(
            lc.list_active()[0].state,
            LifecycleState::RevertPending {
                trigger: RevertTrigger::TtlExpired,
                ..
            }
        ));

        // Caller confirms the revert ran successfully.
        lc.mark_reverted(&id, "expired");
        assert_eq!(lc.list_active().len(), 0);
        assert_eq!(lc.list_history().len(), 1);
        assert_eq!(lc.list_history()[0].reason, "expired");
    }

    #[test]
    fn test_revert_failure_keeps_in_active_and_retries() {
        let mut lc = ResponseLifecycle::new();
        let id = reg(&mut lc, "7.7.7.7", 0);
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Tick #1: stage + fail with a transient error.
        let staged = lc.stage_pending_reverts();
        assert_eq!(staged.len(), 1);
        let outcome = lc.mark_revert_failed(&id, "sudo: sudo token timeout".to_string());
        assert!(matches!(outcome, FailureOutcome::Retrying { attempt: 1 }));
        assert_eq!(lc.list_active().len(), 1, "still in active while retrying");
        assert!(lc.list_history().is_empty(), "nothing in history yet");
        assert!(matches!(
            lc.list_active()[0].state,
            LifecycleState::RevertFailed { attempts: 1, .. }
        ));

        // Tick #2: stage should pick it up again.
        let staged = lc.stage_pending_reverts();
        assert_eq!(
            staged.len(),
            1,
            "RevertFailed with budget should be restaged"
        );

        // Tick #2 success closes it out.
        lc.mark_reverted(&id, "expired");
        assert_eq!(lc.list_active().len(), 0);
        assert_eq!(lc.list_history().len(), 1);
        assert_eq!(lc.list_history()[0].reason, "expired");
    }

    #[test]
    fn test_revert_exhaustion_becomes_orphaned() {
        let mut lc = ResponseLifecycle::new();
        let id = reg(&mut lc, "8.8.8.8", 0);
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Three failing attempts.
        let mut last_outcome = FailureOutcome::UnknownId;
        for _ in 0..MAX_REVERT_ATTEMPTS {
            let staged = lc.stage_pending_reverts();
            assert_eq!(staged.len(), 1);
            last_outcome = lc.mark_revert_failed(&id, "generic transient error".to_string());
        }

        // Final attempt should be Orphaned + entry moved to history.
        match last_outcome {
            FailureOutcome::Orphaned {
                ref target,
                ref backend,
                ..
            } => {
                assert_eq!(target, "8.8.8.8");
                assert_eq!(backend, &ResponseBackend::Ufw);
            }
            other => panic!("expected Orphaned, got {other:?}"),
        }
        assert_eq!(lc.list_active().len(), 0);
        assert_eq!(lc.list_history().len(), 1);
        assert!(lc.list_history()[0].reason.starts_with("orphaned"));

        // Counter should have bumped.
        let prom = lc.to_prometheus_lines();
        assert!(prom.contains("innerwarden_responses_orphaned_total 1"));
        assert!(prom.contains("innerwarden_responses_revert_failures_total 3"));
    }

    #[test]
    fn test_revert_failure_already_absent_is_success() {
        let mut lc = ResponseLifecycle::new();
        let id = reg(&mut lc, "9.9.9.9", 0);
        std::thread::sleep(std::time::Duration::from_millis(10));

        lc.stage_pending_reverts();
        // UFW's "could not delete non-existent rule" is one of the markers.
        let outcome =
            lc.mark_revert_failed(&id, "ERROR: Could not delete non-existent rule".to_string());
        assert_eq!(outcome, FailureOutcome::AlreadyAbsent);
        assert_eq!(lc.list_active().len(), 0);
        assert_eq!(lc.list_history().len(), 1);
        assert_eq!(lc.list_history()[0].reason, "already_absent");

        let prom = lc.to_prometheus_lines();
        assert!(prom.contains("innerwarden_responses_already_absent_total 1"));
    }

    #[test]
    fn test_classify_revert_error_patterns() {
        // ── Verified against real stderr captured on Ubuntu 24.04 aarch64,
        //    kernel 6.8.0-106, by running each backend's delete command
        //    against a non-existent rule. If any of these fail, a tool has
        //    drifted its error message and we risk orphaning responses that
        //    were actually fine. The "VERIFIED" cases are byte-for-byte
        //    real output; the "defense-in-depth" cases are guesses at
        //    variations not observed but plausible across versions.

        let absent_cases = [
            // ──── iptables (VERIFIED on iptables-1.8.10) ────
            // `sudo iptables -D INPUT -s 198.51.100.42 -j DROP` → exit 1
            "iptables: Bad rule (does a matching rule exist in that chain?).",
            // ──── nftables (VERIFIED on nft-1.0.9) ────
            // `sudo nft delete rule inet iwtest input handle <gone>` → exit 1
            "Error: Could not process rule: No such file or directory",
            // ──── bpftool (VERIFIED on bpftool from kernel 6.8) ────
            // `sudo bpftool map delete pinned <missing_path> key ...` → exit 255
            "Error: bpf obj get (/tmp/nonexistent_map): No such file or directory",
            // `sudo bpftool map delete pinned <real_path> key <missing>` → exit 254
            "Error: delete failed: No such file or directory",
            // ──── ufw (defense-in-depth only) ────
            // In practice ufw exits 0 for delete-non-existent so this path
            // is never hit via run_cmd. Kept in case a future ufw version
            // starts returning non-zero, or a wrapper forwards the message
            // through some stderr-carrying channel.
            "ERROR: Could not delete non-existent rule",
            // ──── defense-in-depth: plausible variants ────
            "iptables v1.8.7: No chain/target/match by that name.",
            "Error: Could not process rule: No such process",
            "nft: rule does not exist",
            "key nonexistent",
            "entry doesn't exist in map",
        ];
        for c in absent_cases {
            assert_eq!(
                classify_revert_error(c),
                ErrorKind::AlreadyAbsent,
                "expected AlreadyAbsent for {c:?}"
            );
        }

        // Transient errors — genuinely retry-able. None of these mean the
        // rule was gone, so they must NOT trip the already_absent path (if
        // they did, we'd silently mark a rule reverted that's actually
        // still enforced in the kernel/firewall).
        let transient_cases = [
            "sudo: a terminal is required to read the password",
            "sudo: no tty present and no askpass program specified",
            "Operation not permitted",
            "Permission denied",
            "connection refused",
            "Resource temporarily unavailable",
            "Error: Could not open socket to kernel: Operation not permitted",
            // Kernel says "busy", NOT "not found" — critical distinction.
            "nft: Error: Could not process rule: Device or resource busy",
        ];
        for c in transient_cases {
            assert_eq!(
                classify_revert_error(c),
                ErrorKind::Transient,
                "expected Transient for {c:?}"
            );
        }
    }

    #[test]
    fn test_rehydrate_from_snapshot_preserves_state() {
        // Mid-retry persistence: if the agent crashes while an entry is in
        // RevertFailed state, the snapshot should preserve attempts so we
        // don't reset the retry budget on restart.
        let mut lc = ResponseLifecycle::new();
        let id = reg(&mut lc, "172.16.0.1", 0);
        std::thread::sleep(std::time::Duration::from_millis(10));
        lc.stage_pending_reverts();
        lc.mark_revert_failed(&id, "sudo: token expired".to_string());
        // Entry is now RevertFailed{attempts:1}. Serialize + round-trip.
        let snapshot = lc.to_json();
        let active = snapshot["active"].as_array().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0]["state"]["kind"], "revert_failed");
        assert_eq!(active[0]["state"]["attempts"], 1);

        // Write to temp dir and reload.
        let tmp = std::env::temp_dir().join(format!("innerwarden-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("responses.json"),
            serde_json::to_string(&snapshot).unwrap(),
        )
        .unwrap();
        let reloaded = ResponseLifecycle::load_snapshot(&tmp, None);
        assert_eq!(reloaded.list_active().len(), 1);
        match &reloaded.list_active()[0].state {
            LifecycleState::RevertFailed { attempts, .. } => {
                assert_eq!(*attempts, 1, "attempts counter must survive reload");
            }
            other => panic!("expected RevertFailed after reload, got {other:?}"),
        }
        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // Invalid IP/CIDR targets in the snapshot must be silently dropped on
    // load so they cannot become zombie "Active" entries that orphan an
    // hour later when revert fails.
    #[test]
    fn test_rehydrate_drops_invalid_ip_targets() {
        let tmp =
            std::env::temp_dir().join(format!("innerwarden-test-invalid-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let snap = serde_json::json!({
            "active": [
                {
                    "id": "resp-1",
                    "type": "block_ip",
                    "backend": "ufw",
                    "target": "1.2.3.4",
                    "incident_id": "inc-good",
                    "created_at": chrono::Utc::now().to_rfc3339(),
                    "expires_at": (chrono::Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339(),
                    "ttl_secs": 3600i64
                },
                {
                    "id": "resp-2",
                    "type": "block_ip",
                    "backend": "ufw",
                    "target": "129.950.5.0", // invalid — must be dropped
                    "incident_id": "inc-bad",
                    "created_at": chrono::Utc::now().to_rfc3339(),
                    "expires_at": (chrono::Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339(),
                    "ttl_secs": 3600i64
                },
                {
                    "id": "resp-3",
                    "type": "block_ip",
                    "backend": "ufw",
                    "target": "136.216.0.0/16", // valid CIDR — must survive
                    "incident_id": "inc-cidr",
                    "created_at": chrono::Utc::now().to_rfc3339(),
                    "expires_at": (chrono::Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339(),
                    "ttl_secs": 3600i64
                }
            ],
            "active_count": 3,
            "history": [],
            "totals": { "registered": 3, "expired": 0, "reverted": 0 }
        });
        std::fs::write(
            tmp.join("responses.json"),
            serde_json::to_string(&snap).unwrap(),
        )
        .unwrap();
        let reloaded = ResponseLifecycle::load_snapshot(&tmp, None);
        let targets: Vec<&str> = reloaded
            .list_active()
            .iter()
            .map(|r| r.target.as_str())
            .collect();
        assert_eq!(
            targets.len(),
            2,
            "exactly one entry should have been pruned"
        );
        assert!(targets.contains(&"1.2.3.4"));
        assert!(targets.contains(&"136.216.0.0/16"));
        assert!(!targets.contains(&"129.950.5.0"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // Secondary hydration path (`decisions-<date>.jsonl`) must also drop
    // invalid targets. Without this, a historical decision row for an
    // invalid IP rehydrates as a zombie Active entry on every restart.
    #[test]
    fn test_decisions_jsonl_hydration_drops_invalid_targets() {
        let tmp = std::env::temp_dir().join(format!(
            "innerwarden-test-dec-invalid-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        // Empty snapshot so we exercise only the JSONL path.
        std::fs::write(
            tmp.join("responses.json"),
            r#"{"active":[],"history":[],"totals":{}}"#,
        )
        .unwrap();

        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let now_rfc = chrono::Utc::now().to_rfc3339();
        // Three rows: one valid, one octet-out-of-range, one valid CIDR.
        let jsonl = format!(
            r#"{{"ts":"{now_rfc}","action_type":"block_ip","target_ip":"1.2.3.4","incident_id":"inc-good","skill_id":"block-ip-ufw"}}
{{"ts":"{now_rfc}","action_type":"block_ip","target_ip":"129.950.5.0","incident_id":"inc-bad","skill_id":"block-ip-ufw"}}
{{"ts":"{now_rfc}","action_type":"block_ip","target_ip":"136.216.0.0/16","incident_id":"inc-cidr","skill_id":"block-ip-ufw"}}
"#
        );
        std::fs::write(tmp.join(format!("decisions-{today}.jsonl")), jsonl).unwrap();

        let lc = ResponseLifecycle::load_snapshot(&tmp, None);
        let targets: Vec<&str> = lc.list_active().iter().map(|r| r.target.as_str()).collect();
        assert_eq!(
            targets.len(),
            2,
            "exactly one JSONL row should have been pruned; got: {:?}",
            targets
        );
        assert!(targets.contains(&"1.2.3.4"));
        assert!(targets.contains(&"136.216.0.0/16"));
        assert!(!targets.contains(&"129.950.5.0"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_rehydrate_legacy_snapshot_defaults_to_active() {
        // Backwards-compat: snapshots from before the state machine don't
        // have a `state` field. Those entries must load as Active so legacy
        // responses.json files Just Work on first run after upgrade.
        let tmp =
            std::env::temp_dir().join(format!("innerwarden-test-legacy-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let legacy = serde_json::json!({
            "active": [{
                "id": "resp-1",
                "type": "block_ip",
                "backend": "ufw",
                "target": "192.0.2.50",
                "incident_id": "inc-legacy",
                "created_at": chrono::Utc::now().to_rfc3339(),
                "expires_at": (chrono::Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339(),
                "ttl_secs": 3600i64,
                // Note: no "state" field — this is legacy shape.
            }],
            "active_count": 1,
            "history": [],
            "totals": { "registered": 1, "expired": 0, "reverted": 0 }
        });
        std::fs::write(
            tmp.join("responses.json"),
            serde_json::to_string(&legacy).unwrap(),
        )
        .unwrap();
        let reloaded = ResponseLifecycle::load_snapshot(&tmp, None);
        assert_eq!(reloaded.list_active().len(), 1);
        assert!(matches!(
            reloaded.list_active()[0].state,
            LifecycleState::Active
        ));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Restart consistency anchors (spec 037 slice 4 PR-3) ──────────
    //
    // Four invariants the write → restart → load round-trip must hold:
    //   1. SQLite blob is the canonical source: writing only to the blob
    //      and loading with a store handle recovers full state.
    //   2. JSON file is the legacy fallback: writing only to the file and
    //      loading with a store handle (empty blob) still recovers state.
    //   3. JSON-only path (store=None) still works for pre-migration dirs.
    //   4. SQLite wins when both are present — guards against a stale
    //      responses.json hiding a newer SQLite state after upgrade.
    //
    // The tests use fresh tempdirs with NO decisions-*.jsonl, so the
    // JSONL rehydration path (which is the reconciliation logic and out
    // of scope for this slice) stays dormant.

    fn stateful_lifecycle_fixture() -> ResponseLifecycle {
        // Build a lifecycle that exercises every persisted field: two
        // active entries in distinct states, two history rows, and all
        // six totals set to distinct non-zero values so a silent drop
        // in any counter would surface as a mismatch.
        //
        // Timestamps are truncated to whole seconds so the
        // rfc3339 → DateTime round-trip in the loader does not lose
        // nanoseconds and produce spurious structural inequality.
        use chrono::Timelike;
        let created_at = Utc::now().with_nanosecond(0).unwrap();
        let expires_at = created_at + chrono::Duration::seconds(3600);
        let mut lc = ResponseLifecycle::new();
        lc.active.push(ActiveResponse {
            id: "resp-1".into(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Ufw,
            target: "203.0.113.10".into(),
            incident_id: "inc-a".into(),
            created_at,
            ttl_secs: 3600,
            expires_at,
            revert_handle: None,
            state: LifecycleState::Active,
        });
        lc.active.push(ActiveResponse {
            id: "resp-2".into(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Iptables,
            target: "203.0.113.11".into(),
            incident_id: "inc-b".into(),
            created_at,
            ttl_secs: 7200,
            expires_at: created_at + chrono::Duration::seconds(7200),
            revert_handle: None,
            state: LifecycleState::Active,
        });
        lc.history.push_back(CompletedResponse {
            id: "resp-0".into(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Ufw,
            target: "203.0.113.9".into(),
            incident_id: "inc-h1".into(),
            created_at,
            reverted_at: created_at,
            reason: "expired".into(),
        });
        lc.history.push_back(CompletedResponse {
            id: "resp-h2".into(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Nftables,
            target: "203.0.113.8".into(),
            incident_id: "inc-h2".into(),
            created_at,
            reverted_at: created_at,
            reason: "manual".into(),
        });
        lc.next_id = 5;
        lc.total_registered = 7;
        lc.total_reverted = 2;
        lc.total_expired = 1;
        lc.total_revert_failures = 3;
        lc.total_already_absent = 1;
        lc.total_orphaned = 1;
        lc
    }

    fn assert_state_matches(
        expected: &ResponseLifecycle,
        loaded: &ResponseLifecycle,
        scenario: &str,
    ) {
        // Active — order-preserving compare on the fields that round-trip.
        // `revert_handle` is intentionally dropped by `to_json`; not compared.
        assert_eq!(
            loaded.active.len(),
            expected.active.len(),
            "{scenario}: active length"
        );
        for (i, (e, l)) in expected.active.iter().zip(loaded.active.iter()).enumerate() {
            assert_eq!(e.id, l.id, "{scenario}: active[{i}].id");
            assert_eq!(e.target, l.target, "{scenario}: active[{i}].target");
            assert_eq!(
                e.incident_id, l.incident_id,
                "{scenario}: active[{i}].incident_id"
            );
            assert_eq!(e.ttl_secs, l.ttl_secs, "{scenario}: active[{i}].ttl_secs");
            assert_eq!(
                e.response_type, l.response_type,
                "{scenario}: active[{i}].response_type"
            );
            assert_eq!(e.backend, l.backend, "{scenario}: active[{i}].backend");
        }

        // History.
        assert_eq!(
            loaded.history.len(),
            expected.history.len(),
            "{scenario}: history length"
        );
        for (i, (e, l)) in expected
            .history
            .iter()
            .zip(loaded.history.iter())
            .enumerate()
        {
            assert_eq!(e.id, l.id, "{scenario}: history[{i}].id");
            assert_eq!(e.target, l.target, "{scenario}: history[{i}].target");
            assert_eq!(e.reason, l.reason, "{scenario}: history[{i}].reason");
            assert_eq!(e.backend, l.backend, "{scenario}: history[{i}].backend");
        }

        // Totals — all six must survive.
        assert_eq!(
            expected.total_registered, loaded.total_registered,
            "{scenario}: total_registered"
        );
        assert_eq!(
            expected.total_reverted, loaded.total_reverted,
            "{scenario}: total_reverted"
        );
        assert_eq!(
            expected.total_expired, loaded.total_expired,
            "{scenario}: total_expired"
        );
        assert_eq!(
            expected.total_revert_failures, loaded.total_revert_failures,
            "{scenario}: total_revert_failures"
        );
        assert_eq!(
            expected.total_already_absent, loaded.total_already_absent,
            "{scenario}: total_already_absent"
        );
        assert_eq!(
            expected.total_orphaned, loaded.total_orphaned,
            "{scenario}: total_orphaned"
        );
    }

    #[test]
    fn restart_round_trip_via_sqlite_blob_preserves_full_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(dir.path()).expect("store");
        let expected = stateful_lifecycle_fixture();

        let serialized = serde_json::to_string(&expected.to_snapshot()).expect("serialize");
        store
            .set_blob("responses_snapshot", &serialized)
            .expect("set_blob");
        // Intentionally NO responses.snapshot.json on disk — proves the
        // SQLite blob is a complete source on its own.

        let loaded = ResponseLifecycle::load_snapshot(dir.path(), Some(&store));
        assert_state_matches(&expected, &loaded, "sqlite-blob-only");
    }

    #[test]
    fn restart_round_trip_via_json_fallback_when_blob_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Fresh store with no `responses_snapshot` blob — triggers the
        // v2 JSON-file fallback.
        let store = innerwarden_store::Store::open(dir.path()).expect("store");
        let expected = stateful_lifecycle_fixture();

        std::fs::write(
            dir.path().join("responses.snapshot.json"),
            serde_json::to_string(&expected.to_snapshot()).expect("serialize"),
        )
        .expect("write snapshot json");

        let loaded = ResponseLifecycle::load_snapshot(dir.path(), Some(&store));
        assert_state_matches(&expected, &loaded, "json-fallback-with-store");
    }

    #[test]
    fn restart_round_trip_via_json_when_store_is_none() {
        // Pre-SQLite deployments: no store handle, JSON file is the only
        // source. Must still round-trip cleanly via the v2 snapshot file.
        let dir = tempfile::tempdir().expect("tempdir");
        let expected = stateful_lifecycle_fixture();

        std::fs::write(
            dir.path().join("responses.snapshot.json"),
            serde_json::to_string(&expected.to_snapshot()).expect("serialize"),
        )
        .expect("write snapshot json");

        let loaded = ResponseLifecycle::load_snapshot(dir.path(), None);
        assert_state_matches(&expected, &loaded, "json-only-no-store");
    }

    #[test]
    fn restart_prefers_sqlite_blob_over_json_when_both_present() {
        // Canonical-source invariant. If the snapshot JSON file is stale
        // (e.g. operator restored a backup that predated a tick) and the
        // SQLite blob has fresher state, load_snapshot MUST pick the
        // blob. Otherwise state silently regresses on restart whenever
        // the two sides disagree.
        use chrono::Timelike;
        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(dir.path()).expect("store");

        let stale_at = Utc::now().with_nanosecond(0).unwrap();
        let mut stale_json = ResponseLifecycle::new();
        stale_json.active.push(ActiveResponse {
            id: "stale-1".into(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Ufw,
            target: "198.51.100.50".into(),
            incident_id: "inc-stale".into(),
            created_at: stale_at,
            ttl_secs: 3600,
            expires_at: stale_at + chrono::Duration::seconds(3600),
            revert_handle: None,
            state: LifecycleState::Active,
        });
        stale_json.total_registered = 999;
        std::fs::write(
            dir.path().join("responses.snapshot.json"),
            serde_json::to_string(&stale_json.to_snapshot()).expect("serialize stale"),
        )
        .expect("write stale json");

        let expected = stateful_lifecycle_fixture();
        store
            .set_blob(
                "responses_snapshot",
                &serde_json::to_string(&expected.to_snapshot()).expect("serialize fresh"),
            )
            .expect("set_blob");

        let loaded = ResponseLifecycle::load_snapshot(dir.path(), Some(&store));
        assert_state_matches(&expected, &loaded, "sqlite-wins-over-json");
        assert_ne!(
            loaded.total_registered, 999,
            "loaded state must NOT come from the stale JSON file"
        );
    }

    #[test]
    fn to_snapshot_preserves_history_order() {
        // Inverse of the pre-PR bug. to_json() reversed history via .rev();
        // to_snapshot() must preserve natural push_back order so the
        // first-reverted entry stays first on restart.
        let expected = stateful_lifecycle_fixture();
        let snapshot = expected.to_snapshot();
        let arr = snapshot["history"].as_array().expect("history array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["id"].as_str(), Some("resp-0"));
        assert_eq!(arr[1]["id"].as_str(), Some("resp-h2"));
        assert!(
            snapshot["schema_version"].as_u64() == Some(2),
            "snapshot must carry schema_version=2"
        );
    }

    #[test]
    fn to_snapshot_preserves_revert_handle_and_next_id() {
        // Two fields to_json() silently dropped. revert_handle is needed
        // to revert nftables rules after restart; next_id prevents ID
        // collisions with history entries after a reload.
        use chrono::Timelike;
        let created_at = Utc::now().with_nanosecond(0).unwrap();
        let mut lc = ResponseLifecycle::new();
        lc.active.push(ActiveResponse {
            id: "resp-42".into(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Nftables,
            target: "203.0.113.77".into(),
            incident_id: "inc-nft".into(),
            created_at,
            ttl_secs: 3600,
            expires_at: created_at + chrono::Duration::seconds(3600),
            revert_handle: Some("nft-handle-42".into()),
            state: LifecycleState::Active,
        });
        lc.next_id = 99;

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("responses.snapshot.json"),
            serde_json::to_string(&lc.to_snapshot()).expect("serialize"),
        )
        .expect("write");

        let reloaded = ResponseLifecycle::load_snapshot(dir.path(), None);
        assert_eq!(reloaded.active.len(), 1);
        assert_eq!(
            reloaded.active[0].revert_handle.as_deref(),
            Some("nft-handle-42"),
            "revert_handle must survive snapshot round-trip"
        );
        assert_eq!(reloaded.next_id, 99, "next_id must survive round-trip");
    }

    #[test]
    fn load_v1_fallback_still_works_for_legacy_snapshots() {
        // Upgrade path anchor: a dir that only has the old `responses.json`
        // (v1 shape from to_json()) must still load so operators do not
        // lose state after the first boot post-upgrade. The load goes
        // through load_v1 — known to flip history order (pre-existing
        // bug) — but counts and active entries must come back.
        let dir = tempfile::tempdir().expect("tempdir");
        let expected = stateful_lifecycle_fixture();
        // Emit v1 format (to_json) — no schema_version, reversed history,
        // no next_id, no revert_handle.
        std::fs::write(
            dir.path().join("responses.json"),
            serde_json::to_string(&expected.to_json()).expect("serialize"),
        )
        .expect("write v1 json");

        let loaded = ResponseLifecycle::load_snapshot(dir.path(), None);
        assert_eq!(
            loaded.active.len(),
            expected.active.len(),
            "v1 fallback must recover active entries"
        );
        assert_eq!(
            loaded.total_registered, expected.total_registered,
            "v1 fallback must recover totals"
        );
        // Known v1 limitation: history order is reversed. Document rather
        // than assert order here so the anchor does not mask the bug
        // that motivated this PR. The fix only applies going forward —
        // the first boot after upgrade still pays this one-time cost.
        assert_eq!(
            loaded.history.len(),
            expected.history.len(),
            "v1 history length must survive"
        );
    }

    #[test]
    fn test_manual_revert_success() {
        let mut lc = ResponseLifecycle::new();

        let id = lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Iptables,
            "5.6.7.8",
            "inc-002",
            3600,
            None,
        );

        let action = lc.request_manual_revert(&id).unwrap();
        assert_eq!(action.target, "5.6.7.8");
        assert_eq!(lc.list_active().len(), 1, "still in active until confirmed");
        assert!(matches!(
            lc.list_active()[0].state,
            LifecycleState::RevertPending {
                trigger: RevertTrigger::Manual,
                ..
            }
        ));

        lc.mark_reverted(&id, "manual");
        assert_eq!(lc.list_active().len(), 0);
        assert_eq!(lc.list_history().len(), 1);
        assert_eq!(lc.list_history()[0].reason, "manual");
    }

    #[test]
    fn test_manual_revert_failure_then_orphan() {
        let mut lc = ResponseLifecycle::new();
        let id = lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Iptables,
            "5.6.7.8",
            "inc-002",
            3600,
            None,
        );

        // Manual trigger with transient failure.
        lc.request_manual_revert(&id).unwrap();
        let outcome = lc.mark_revert_failed(&id, "some random failure".to_string());
        assert!(matches!(outcome, FailureOutcome::Retrying { attempt: 1 }));

        // State should preserve the Manual trigger through retries.
        if let LifecycleState::RevertFailed { trigger, .. } = lc.list_active()[0].state {
            assert_eq!(trigger, RevertTrigger::Manual);
        } else {
            panic!("expected RevertFailed state");
        }
    }

    #[test]
    fn test_request_manual_revert_idempotent_on_pending() {
        let mut lc = ResponseLifecycle::new();
        let id = lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Ufw,
            "1.1.1.1",
            "inc",
            3600,
            None,
        );
        assert!(lc.request_manual_revert(&id).is_some());
        // Second call while already pending should be a no-op (None) so we
        // don't double-issue the command.
        assert!(lc.request_manual_revert(&id).is_none());
    }

    #[test]
    fn test_is_tracked_includes_failed_entries() {
        // A RevertFailed entry is still "tracked" — the rule is supposed to
        // be there. We must NOT accept a duplicate registration while we're
        // still trying to revert.
        let mut lc = ResponseLifecycle::new();
        let id = reg(&mut lc, "10.0.0.1", 0);
        std::thread::sleep(std::time::Duration::from_millis(10));
        lc.stage_pending_reverts();
        lc.mark_revert_failed(&id, "sudo failure".to_string());
        assert!(lc.is_tracked("10.0.0.1", &ResponseBackend::Ufw));
    }

    #[test]
    fn test_is_tracked() {
        let mut lc = ResponseLifecycle::new();
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Xdp,
            "10.0.0.1",
            "inc-003",
            3600,
            None,
        );
        assert!(lc.is_tracked("10.0.0.1", &ResponseBackend::Xdp));
        assert!(!lc.is_tracked("10.0.0.1", &ResponseBackend::Ufw));
        assert!(!lc.is_tracked("10.0.0.2", &ResponseBackend::Xdp));
    }

    #[test]
    fn test_prometheus_output() {
        let mut lc = ResponseLifecycle::new();
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Ufw,
            "1.1.1.1",
            "inc-004",
            3600,
            None,
        );
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Xdp,
            "2.2.2.2",
            "inc-005",
            3600,
            None,
        );

        let prom = lc.to_prometheus_lines();
        assert!(prom.contains("innerwarden_responses_active{backend=\"ufw\"} 1"));
        assert!(prom.contains("innerwarden_responses_active{backend=\"xdp\"} 1"));
        assert!(prom.contains("innerwarden_responses_total 2"));
        // New counters exposed even when zero.
        assert!(prom.contains("innerwarden_responses_revert_failures_total 0"));
        assert!(prom.contains("innerwarden_responses_already_absent_total 0"));
        assert!(prom.contains("innerwarden_responses_orphaned_total 0"));
        assert!(prom.contains("innerwarden_responses_by_state{state=\"active\"} 2"));
    }

    #[test]
    fn test_json_output_exposes_state() {
        let mut lc = ResponseLifecycle::new();
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Iptables,
            "3.3.3.3",
            "inc-006",
            3600,
            None,
        );

        let json = lc.to_json();
        assert_eq!(json["active_count"], 1);
        assert_eq!(json["active"][0]["target"], "3.3.3.3");
        assert_eq!(json["active"][0]["state"]["kind"], "active");
        assert!(json["active"][0]["remaining_secs"].as_i64().unwrap() > 3500);
        assert_eq!(json["state_counts"]["active"], 1);
        assert_eq!(json["state_counts"]["revert_pending"], 0);
        assert_eq!(json["state_counts"]["revert_failed"], 0);
    }

    #[test]
    fn test_history_cap() {
        // History growth happens via mark_reverted; use manual revert path.
        let mut lc = ResponseLifecycle::new();
        for i in 0..1100 {
            let id = lc.register(
                ResponseType::BlockIp,
                ResponseBackend::Ufw,
                &format!("10.0.{}.{}", i / 256, i % 256),
                "inc",
                3600,
                None,
            );
            lc.request_manual_revert(&id);
            lc.mark_reverted(&id, "manual");
        }
        assert!(lc.history.len() <= 1000);
    }

    // ─── Spec 024 contract tests ───────────────────────────────────────
    //
    // `register` contract:
    //   - returns a non-empty id.
    //   - immediately, `is_tracked(target, backend)` ⇒ true.
    //   - total_registered strictly increases by 1 per call.
    //   - the entry starts in `LifecycleState::Active`.
    //   - register does NOT itself validate targets; validation lives
    //     upstream (decision_block_ip::is_valid_block_target) and in
    //     `load_snapshot`. The PR #124 zombie-rule bug was the snapshot
    //     path forgetting that invariant — this test pins it on the
    //     register contract so any future inversion (e.g. "maybe we
    //     should validate inside register?") must update the test.

    #[test]
    fn contract_register_returns_id_and_marks_tracked() {
        let mut lc = ResponseLifecycle::new();
        let id = lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Ufw,
            "198.51.100.7",
            "inc-contract-1",
            3600,
            None,
        );
        assert!(!id.is_empty(), "register must return a non-empty id");
        assert!(
            lc.is_tracked("198.51.100.7", &ResponseBackend::Ufw),
            "is_tracked must return true immediately after register"
        );
        assert_eq!(lc.total_registered, 1);
        let state = &lc.list_active()[0].state;
        assert!(matches!(state, LifecycleState::Active));
    }

    #[test]
    fn contract_register_accepts_arbitrary_target_string_upstream_validates() {
        // Register's caller is expected to validate the target. This test
        // documents that boundary: a malformed target does land in the
        // lifecycle if someone calls register directly. In production all
        // callers go through decision_block_ip::execute_block which rejects
        // invalid IPs upstream.
        let mut lc = ResponseLifecycle::new();
        let id = lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Ufw,
            "not-an-ip-at-all",
            "inc-contract-2",
            3600,
            None,
        );
        assert!(!id.is_empty());
        assert!(lc.is_tracked("not-an-ip-at-all", &ResponseBackend::Ufw));
    }

    #[test]
    fn contract_register_totals_monotonic_across_calls() {
        let mut lc = ResponseLifecycle::new();
        for i in 0..5 {
            let before = lc.total_registered;
            lc.register(
                ResponseType::BlockIp,
                ResponseBackend::Ufw,
                &format!("192.0.2.{i}"),
                &format!("inc-{i}"),
                60,
                None,
            );
            assert_eq!(lc.total_registered, before + 1);
        }
        assert_eq!(lc.list_active().len(), 5);
    }

    #[test]
    fn contract_is_tracked_is_backend_scoped() {
        // Same target, different backends ⇒ must be tracked independently.
        // This keeps the dedup logic from collapsing e.g. an xdp kernel
        // rule and a ufw userspace rule for the same IP into one entry.
        let mut lc = ResponseLifecycle::new();
        lc.register(
            ResponseType::BlockIp,
            ResponseBackend::Xdp,
            "203.0.113.9",
            "inc-a",
            60,
            None,
        );
        assert!(lc.is_tracked("203.0.113.9", &ResponseBackend::Xdp));
        assert!(
            !lc.is_tracked("203.0.113.9", &ResponseBackend::Ufw),
            "backend identity must be part of the tracked key"
        );
    }

    // Spec 037 I-13 follow-up #2: read_v2_snapshot_or_warn
    //
    // Wraps the silent `if let Ok(content) = read_to_string(&path)`
    // fallback in `try_load_v2`. NotFound is steady state on first
    // boot; only real I/O errors should warn.

    #[test]
    fn read_v2_snapshot_or_warn_returns_none_silently_on_not_found() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("responses.snapshot.json");

        let result = read_v2_snapshot_or_warn(&path);
        assert!(result.is_none(), "missing file must yield None");

        let captured = crate::test_util::drain_capture();
        assert!(
            !captured.contains("response lifecycle v2 snapshot read failed"),
            "NotFound must NOT emit warn, got: {captured}"
        );
    }

    #[test]
    fn read_v2_snapshot_or_warn_returns_none_and_warns_on_io_failure() {
        // Park target path beneath a regular file so `read_to_string`
        // returns NotADirectory / similar (any non-NotFound error).
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let blocking_file = dir.path().join("blocker");
        std::fs::write(&blocking_file, b"i am a regular file").expect("seed blocker");
        let path = blocking_file.join("responses.snapshot.json");

        let result = read_v2_snapshot_or_warn(&path);
        assert!(result.is_none(), "io-failure must yield None");

        let captured = crate::test_util::drain_capture();
        assert!(
            captured.contains("response lifecycle v2 snapshot read failed"),
            "io-failure warn missing, got: {captured}"
        );
        assert!(
            captured.contains("error="),
            "error field missing, got: {captured}"
        );
    }

    // ── RC-2 follow-up (2026-04-30): SQLite-backed reconciler anchors ──
    //
    // The legacy `hydrate_from_decisions_jsonl` reads from a parallel
    // JSONL file whose date convention (Local-now) drifted from the
    // SQLite canonical path (Utc-stored). The new
    // `hydrate_from_decisions_sqlite` reads from `decisions` table and
    // is the path `load_snapshot` uses when a Store is present. These
    // anchors lock both the SoT contract and the dedup behaviour.

    fn insert_block_ip_decision(
        store: &innerwarden_store::Store,
        ts_iso: &str,
        target: &str,
        incident_id: &str,
        skill_id: Option<&str>,
    ) {
        let data = serde_json::json!({
            "skill_id": skill_id.unwrap_or("block-ip-ufw"),
            "ts": ts_iso,
            "incident_id": incident_id,
            "action_type": "block_ip",
            "target_ip": target,
        });
        let row = innerwarden_store::decisions::DecisionRow {
            ts: ts_iso.to_string(),
            incident_id: incident_id.to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some(target.to_string()),
            target_user: None,
            confidence: 0.9,
            auto_executed: true,
            reason: Some("test".to_string()),
            data: serde_json::to_string(&data).expect("serialize"),
        };
        store.insert_decision(&row).expect("insert decision");
    }

    #[test]
    fn hydrate_from_decisions_sqlite_picks_up_unregistered_block_ip() {
        // RC-2 anchor: a block_ip decision recorded directly through
        // the canonical SQLite path (e.g. by an always-on honeypot or
        // dashboard manual action that bypassed `register`) must be
        // surfaced as an active response after restart.
        use chrono::Timelike;
        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(dir.path()).expect("store");

        let now = Utc::now().with_nanosecond(0).unwrap();
        let recent_ts = now - chrono::Duration::seconds(60);
        insert_block_ip_decision(
            &store,
            &recent_ts.to_rfc3339(),
            "203.0.113.10",
            "ssh:bf:1",
            Some("block-ip-ufw"),
        );

        let mut lifecycle = ResponseLifecycle::new();
        ResponseLifecycle::hydrate_from_decisions_sqlite(&mut lifecycle, &store);

        assert_eq!(lifecycle.active.len(), 1, "active block must be hydrated");
        assert_eq!(lifecycle.active[0].target, "203.0.113.10");
        assert_eq!(lifecycle.active[0].backend, ResponseBackend::Ufw);
        assert_eq!(
            lifecycle.total_registered, 1,
            "counter must move so the dashboard tile reports the catch-up"
        );
    }

    #[test]
    fn hydrate_from_decisions_sqlite_does_not_duplicate_already_tracked() {
        // The reconciler must skip targets the v2 snapshot already
        // restored — otherwise `total_registered` double-counts and
        // the dashboard active list shows two `resp-N` rows for the
        // same IP.
        use chrono::Timelike;
        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(dir.path()).expect("store");

        let now = Utc::now().with_nanosecond(0).unwrap();
        let recent_ts = now - chrono::Duration::seconds(60);
        insert_block_ip_decision(
            &store,
            &recent_ts.to_rfc3339(),
            "203.0.113.20",
            "ssh:bf:2",
            None,
        );

        let mut lifecycle = ResponseLifecycle::new();
        // Pretend the v2 snapshot already restored this target.
        lifecycle.active.push(ActiveResponse {
            id: "resp-pre".into(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Ufw,
            target: "203.0.113.20".into(),
            incident_id: "ssh:bf:2".into(),
            created_at: recent_ts,
            ttl_secs: 3600,
            expires_at: recent_ts + chrono::Duration::seconds(3600),
            revert_handle: None,
            state: LifecycleState::Active,
        });
        lifecycle.total_registered = 1;

        ResponseLifecycle::hydrate_from_decisions_sqlite(&mut lifecycle, &store);

        assert_eq!(
            lifecycle.active.len(),
            1,
            "must not duplicate the already-tracked target"
        );
        assert_eq!(
            lifecycle.total_registered, 1,
            "counter must not double-count"
        );
    }

    #[test]
    fn hydrate_from_decisions_sqlite_skips_expired_blocks() {
        // A block_ip decision older than its 1h TTL is already past
        // expiry. The reconciler must not resurrect it as `Active` —
        // otherwise the operator sees stale "active" rows the kernel
        // already removed.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(dir.path()).expect("store");

        let stale_ts = Utc::now() - chrono::Duration::hours(2);
        insert_block_ip_decision(
            &store,
            &stale_ts.to_rfc3339(),
            "203.0.113.30",
            "ssh:bf:3",
            None,
        );

        let mut lifecycle = ResponseLifecycle::new();
        ResponseLifecycle::hydrate_from_decisions_sqlite(&mut lifecycle, &store);

        assert_eq!(
            lifecycle.active.len(),
            0,
            "expired blocks must not be re-surfaced as active"
        );
    }

    #[test]
    fn hydrate_from_decisions_sqlite_at_includes_pre_midnight_block() {
        // Regression: a block recorded shortly before UTC midnight stays
        // active for up to an hour, but lives under *yesterday's* date
        // partition. A restart in the first hour of the next day must
        // still hydrate it. Before the yesterday+today query window this
        // was silently dropped, and the `now - 60s` seed in the sibling
        // tests made them flake in the first 60s after midnight. Inject a
        // fixed `now` just after midnight so the case is deterministic.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(dir.path()).expect("store");

        let now = "2026-01-02T00:00:30Z"
            .parse::<DateTime<Utc>>()
            .expect("parse now");
        // 60s earlier => 2026-01-01T23:59:30Z (yesterday's partition);
        // expires at 2026-01-02T00:59:30Z, still after `now`.
        let pre_midnight = now - chrono::Duration::seconds(60);
        assert_eq!(
            pre_midnight.date_naive(),
            now.date_naive() - chrono::Duration::days(1),
            "fixture must straddle the UTC day boundary"
        );
        insert_block_ip_decision(
            &store,
            &pre_midnight.to_rfc3339(),
            "203.0.113.40",
            "ssh:bf:midnight",
            Some("block-ip-ufw"),
        );

        let mut lifecycle = ResponseLifecycle::new();
        ResponseLifecycle::hydrate_from_decisions_sqlite_at(&mut lifecycle, &store, now);

        assert_eq!(
            lifecycle.active.len(),
            1,
            "a pre-midnight block still within TTL must hydrate after midnight"
        );
        assert_eq!(lifecycle.active[0].target, "203.0.113.40");
    }

    #[test]
    fn hydrate_from_decisions_sqlite_at_skips_expired_pre_midnight_block() {
        // The widened yesterday+today window must not resurrect a
        // yesterday block whose 1h TTL already lapsed by `now`.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(dir.path()).expect("store");

        let now = "2026-01-02T02:00:00Z"
            .parse::<DateTime<Utc>>()
            .expect("parse now");
        // 23:00 yesterday + 1h TTL => expired at 00:00, well before now.
        let stale = "2026-01-01T23:00:00Z"
            .parse::<DateTime<Utc>>()
            .expect("parse stale");
        insert_block_ip_decision(
            &store,
            &stale.to_rfc3339(),
            "203.0.113.41",
            "ssh:bf:midnight-stale",
            None,
        );

        let mut lifecycle = ResponseLifecycle::new();
        ResponseLifecycle::hydrate_from_decisions_sqlite_at(&mut lifecycle, &store, now);

        assert_eq!(
            lifecycle.active.len(),
            0,
            "expired yesterday block must not resurrect via the widened window"
        );
    }

    #[test]
    fn hydrate_from_decisions_sqlite_derives_backend_from_skill_id() {
        // The legacy JSONL reconciler walked the JSON entry to read
        // `skill_id` and pick a ResponseBackend. The SQLite path keeps
        // the same derivation by parsing the `data` blob — anchor
        // covers the four known skills (xdp / iptables / nftables /
        // default ufw) so a future schema change that drops skill_id
        // from the data JSON is caught.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(dir.path()).expect("store");
        let now = Utc::now() - chrono::Duration::seconds(60);

        for (target, skill, expected) in [
            ("203.0.113.40", "block-ip-xdp", ResponseBackend::Xdp),
            (
                "203.0.113.41",
                "block-ip-iptables",
                ResponseBackend::Iptables,
            ),
            (
                "203.0.113.42",
                "block-ip-nftables",
                ResponseBackend::Nftables,
            ),
            ("203.0.113.43", "block-ip-ufw", ResponseBackend::Ufw),
        ] {
            insert_block_ip_decision(&store, &now.to_rfc3339(), target, "inc", Some(skill));
            let mut lifecycle = ResponseLifecycle::new();
            ResponseLifecycle::hydrate_from_decisions_sqlite(&mut lifecycle, &store);
            let row = lifecycle
                .active
                .iter()
                .find(|r| r.target == target)
                .unwrap_or_else(|| panic!("no active row for {target}"));
            assert_eq!(row.backend, expected, "backend mismatch for skill={skill}");
        }
    }

    // ── 2026-05-02 audit B3 anchors — orphan response GC ────────────
    //
    // The auditor saw 17 entries with reason="orphaned: ..." sitting in
    // `responses.json` for >48 h with no GC path. These anchors pin
    // the new sweep so a future refactor that drops the call from
    // boot.rs (or weakens the predicate) is caught at build time.

    #[test]
    fn gc_orphaned_responses_prunes_only_old_orphaned_entries() {
        let mut lc = ResponseLifecycle::new();
        let now = Utc::now();
        // Three orphaned, three non-orphaned. Mix of ages.
        lc.history.push_back(CompletedResponse {
            id: "old-orphan".to_string(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Ufw,
            target: "203.0.113.10".to_string(),
            incident_id: "inc-1".to_string(),
            created_at: now - chrono::Duration::days(10),
            reverted_at: now - chrono::Duration::days(8),
            reason: "orphaned: ufw delete failed".to_string(),
        });
        lc.history.push_back(CompletedResponse {
            id: "fresh-orphan".to_string(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Ufw,
            target: "203.0.113.11".to_string(),
            incident_id: "inc-2".to_string(),
            created_at: now - chrono::Duration::hours(2),
            reverted_at: now - chrono::Duration::hours(1),
            reason: "orphaned: rule still present".to_string(),
        });
        lc.history.push_back(CompletedResponse {
            id: "very-old-but-expired".to_string(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Ufw,
            target: "203.0.113.12".to_string(),
            incident_id: "inc-3".to_string(),
            created_at: now - chrono::Duration::days(30),
            reverted_at: now - chrono::Duration::days(28),
            reason: "expired".to_string(),
        });
        lc.history.push_back(CompletedResponse {
            id: "old-manual".to_string(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Ufw,
            target: "203.0.113.13".to_string(),
            incident_id: "inc-4".to_string(),
            created_at: now - chrono::Duration::days(20),
            reverted_at: now - chrono::Duration::days(20),
            reason: "manual".to_string(),
        });
        lc.history.push_back(CompletedResponse {
            id: "old-already-absent".to_string(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Ufw,
            target: "203.0.113.14".to_string(),
            incident_id: "inc-5".to_string(),
            created_at: now - chrono::Duration::days(20),
            reverted_at: now - chrono::Duration::days(20),
            reason: "already_absent".to_string(),
        });

        // 7-day cutoff: only `old-orphan` (8d old, reason orphaned)
        // should be pruned. Fresh orphan stays. expired/manual/
        // already_absent stay regardless of age.
        let pruned = lc.gc_orphaned_responses(7 * 24 * 3600);
        assert_eq!(pruned, 1, "only the 8-day-old orphan must be pruned");
        let ids: Vec<&str> = lc.history.iter().map(|r| r.id.as_str()).collect();
        assert!(!ids.contains(&"old-orphan"));
        assert!(ids.contains(&"fresh-orphan"));
        assert!(ids.contains(&"very-old-but-expired"));
        assert!(ids.contains(&"old-manual"));
        assert!(ids.contains(&"old-already-absent"));
    }

    #[test]
    fn gc_orphaned_responses_is_noop_on_empty_history() {
        let mut lc = ResponseLifecycle::new();
        let pruned = lc.gc_orphaned_responses(7 * 24 * 3600);
        assert_eq!(pruned, 0);
        assert_eq!(lc.history.len(), 0);
    }

    #[test]
    fn gc_orphaned_responses_preserves_all_when_threshold_is_huge() {
        let mut lc = ResponseLifecycle::new();
        let now = Utc::now();
        for i in 0..5 {
            lc.history.push_back(CompletedResponse {
                id: format!("orph-{i}"),
                response_type: ResponseType::BlockIp,
                backend: ResponseBackend::Ufw,
                target: format!("203.0.113.{i}"),
                incident_id: format!("inc-{i}"),
                created_at: now - chrono::Duration::days(30),
                reverted_at: now - chrono::Duration::days(30),
                reason: format!("orphaned: failure {i}"),
            });
        }
        // Threshold of 365 days: nothing should be pruned (all 30
        // days old).
        let pruned = lc.gc_orphaned_responses(365 * 24 * 3600);
        assert_eq!(pruned, 0);
        assert_eq!(lc.history.len(), 5);
    }

    // ─── PR #419 Wave 2 — orphan diagnostic anchor tests ────────────
    //
    // These pin the heuristic classifier and the JSON enumerator to
    // their expected behaviour so the dashboard's `/api/responses/orphans`
    // surface stays stable. Stderr fixtures come from real revert
    // failures observed in prod (responses.json on the Oracle host).

    #[test]
    fn classify_orphan_error_ipv6_mismatch() {
        // Real iptables output when v6 rule is fed to the v4 binary.
        let s = "iptables v1.8.7: host/network `2001:db8::1' not found: \
                 Address family for hostname not supported by AF_INET";
        assert_eq!(classify_orphan_error(s), OrphanErrorCluster::Ipv6Mismatch);
    }

    #[test]
    fn classify_orphan_error_nftables_handle_missing() {
        let s = "no nftables handle stored at create time";
        assert_eq!(
            classify_orphan_error(s),
            OrphanErrorCluster::NftablesHandleMissing
        );
    }

    #[test]
    fn classify_orphan_error_rule_already_absent() {
        // ufw renumbered the rule between create and revert.
        let s = "ERROR: Could not delete non-existent rule";
        assert_eq!(
            classify_orphan_error(s),
            OrphanErrorCluster::RuleAlreadyAbsent
        );
    }

    #[test]
    fn classify_orphan_error_permission_denied() {
        let s = "sudo: a password is required";
        assert_eq!(
            classify_orphan_error(s),
            OrphanErrorCluster::PermissionDenied
        );
    }

    #[test]
    fn classify_orphan_error_external_mutation() {
        let s = "fail2ban rule renumber detected";
        assert_eq!(
            classify_orphan_error(s),
            OrphanErrorCluster::ExternalMutation
        );
    }

    #[test]
    fn classify_orphan_error_unknown_falls_through() {
        let s = "completely unfamiliar failure";
        assert_eq!(classify_orphan_error(s), OrphanErrorCluster::Unknown);
    }

    #[test]
    fn describe_revert_command_per_backend() {
        // Operator-facing strings — pinned so the dashboard card
        // always reflects what the agent actually attempted.
        assert_eq!(
            describe_revert_command(&ResponseBackend::Ufw, "1.2.3.4"),
            "sudo ufw delete deny from 1.2.3.4"
        );
        assert_eq!(
            describe_revert_command(&ResponseBackend::Iptables, "5.6.7.8"),
            "sudo iptables -D INPUT -s 5.6.7.8 -j DROP"
        );
        let nft = describe_revert_command(&ResponseBackend::Nftables, "9.9.9.9");
        assert!(nft.contains("nft delete rule"));
        assert!(nft.contains("9.9.9.9"));
    }

    #[test]
    fn enumerate_orphans_from_responses_json_happy_path() {
        let raw = serde_json::json!({
            "active": [],
            "history": [
                {
                    "id": "r-1",
                    "response_type": "block_ip",
                    "backend": "ufw",
                    "target": "203.0.113.7",
                    "incident_id": "inc-7",
                    "created_at": "2026-04-30T10:00:00Z",
                    "reverted_at": "2026-04-30T11:00:00Z",
                    "reason": "orphaned: ERROR: Could not delete non-existent rule"
                },
                {
                    "id": "r-2",
                    "response_type": "block_ip",
                    "backend": "iptables",
                    "target": "203.0.113.8",
                    "incident_id": "inc-8",
                    "created_at": "2026-04-30T10:05:00Z",
                    "reverted_at": "2026-04-30T11:05:00Z",
                    "reason": "expired_ttl"
                }
            ]
        })
        .to_string();

        let out = enumerate_orphans_from_responses_json(&raw);
        // Only the orphaned entry is returned, even though both are in history.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "r-1");
        assert_eq!(out[0].target, "203.0.113.7");
        assert_eq!(out[0].backend, ResponseBackend::Ufw);
        assert_eq!(out[0].cluster, OrphanErrorCluster::RuleAlreadyAbsent);
        assert!(out[0].last_error.contains("non-existent"));
        assert!(out[0].revert_command.contains("ufw delete deny"));
    }

    #[test]
    fn enumerate_orphans_from_responses_json_malformed_input() {
        // Garbage in -> empty out, never panic.
        assert!(enumerate_orphans_from_responses_json("").is_empty());
        assert!(enumerate_orphans_from_responses_json("not json").is_empty());
        assert!(enumerate_orphans_from_responses_json("{}").is_empty());
        // history present but not an array.
        let bad = r#"{"history": "oops"}"#;
        assert!(enumerate_orphans_from_responses_json(bad).is_empty());
        // history with a non-orphan entry only.
        let none = r#"{"history": [{"reason": "expired_ttl"}]}"#;
        assert!(enumerate_orphans_from_responses_json(none).is_empty());
    }

    // ─── PR #420 Wave 3 — orphan resolution storage anchor tests ────

    #[test]
    fn append_then_read_orphan_resolution_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let r = OrphanResolution {
            orphan_id: "orph-1".to_string(),
            kind: OrphanResolution::KIND_CLEARED.to_string(),
            reason: "stale entry, IP no longer relevant".to_string(),
            operator: "alice".to_string(),
            resolved_at: chrono::Utc::now(),
        };
        append_orphan_resolution(dir.path(), &r).unwrap();
        let loaded = read_orphan_resolutions(dir.path());
        assert_eq!(loaded.len(), 1);
        let got = loaded.get("orph-1").expect("orphan-1 present");
        assert_eq!(got.kind, OrphanResolution::KIND_CLEARED);
        assert_eq!(got.reason, "stale entry, IP no longer relevant");
        assert_eq!(got.operator, "alice");
    }

    #[test]
    fn read_orphan_resolutions_last_write_wins() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = OrphanResolution {
            orphan_id: "orph-X".to_string(),
            kind: OrphanResolution::KIND_CLEARED.to_string(),
            reason: "first".to_string(),
            operator: "alice".to_string(),
            resolved_at: chrono::Utc::now(),
        };
        append_orphan_resolution(dir.path(), &a).unwrap();
        // Second append for the same orphan_id with different fields.
        a.kind = OrphanResolution::KIND_ALREADY_GONE.to_string();
        a.reason = "actually it was already gone".to_string();
        a.operator = "bob".to_string();
        append_orphan_resolution(dir.path(), &a).unwrap();

        let loaded = read_orphan_resolutions(dir.path());
        assert_eq!(loaded.len(), 1, "still keyed by orphan_id");
        let got = loaded.get("orph-X").unwrap();
        assert_eq!(got.kind, OrphanResolution::KIND_ALREADY_GONE);
        assert_eq!(got.operator, "bob");
        assert_eq!(got.reason, "actually it was already gone");
    }

    #[test]
    fn read_orphan_resolutions_skips_malformed_lines() {
        // Mix of valid + garbage lines — readers must never panic.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("orphan_resolutions.jsonl");
        let mut content = String::new();
        content.push_str("not json at all\n");
        content.push_str("{}\n"); // missing required fields
        let valid = OrphanResolution {
            orphan_id: "orph-Y".to_string(),
            kind: OrphanResolution::KIND_CLEARED.to_string(),
            reason: "ok".to_string(),
            operator: "alice".to_string(),
            resolved_at: chrono::Utc::now(),
        };
        content.push_str(&serde_json::to_string(&valid).unwrap());
        content.push('\n');
        content.push_str("{trailing garbage\n");
        std::fs::write(&path, content).unwrap();

        let loaded = read_orphan_resolutions(dir.path());
        assert_eq!(loaded.len(), 1, "only the well-formed line survives");
        assert!(loaded.contains_key("orph-Y"));
    }

    #[test]
    fn read_orphan_resolutions_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        // Don't create the file at all.
        let loaded = read_orphan_resolutions(dir.path());
        assert!(loaded.is_empty());
    }

    // ─── PR #425 Wave 4d — current_orphan_count + gauges shape ───
    //
    // Real prod observation 2026-05-03: dashboard banner showed
    // "17 orphaned (rule may still be active)" but the JSON had zero
    // entries with reason="orphaned:" and zero active in revert_failed.
    // Mechanism: `total_orphaned` is a monotonic counter, never
    // decrements after PR #408's GC pruned the entries. Banner read
    // it as a gauge.
    //
    // These tests pin the new contract: `current_orphan_count()`
    // returns 0 when no entries actually exist, regardless of
    // `total_orphaned`. `to_json()` exposes both shapes — `gauges.*`
    // for the banner / now-display, `totals.*` for lifetime counters.

    #[test]
    fn current_orphan_count_returns_zero_on_clean_system() {
        let mut lc = ResponseLifecycle::new();
        // Simulate a system that had orphans in the past (counter
        // bumped) but GC pruned them all. `total_orphaned` is high,
        // current count must be zero.
        lc.total_orphaned = 17;
        assert_eq!(
            lc.current_orphan_count(),
            0,
            "current count must reflect actual entries, not the lifetime counter"
        );
    }

    #[test]
    fn current_orphan_count_counts_history_entries() {
        let mut lc = ResponseLifecycle::new();
        let now = Utc::now();
        for i in 0..3 {
            lc.history.push_back(CompletedResponse {
                id: format!("orph-{i}"),
                response_type: ResponseType::BlockIp,
                backend: ResponseBackend::Ufw,
                target: format!("203.0.113.{i}"),
                incident_id: format!("inc-{i}"),
                created_at: now - chrono::Duration::hours(2),
                reverted_at: now - chrono::Duration::hours(1),
                reason: format!("orphaned: rule does not exist on attempt {i}"),
            });
        }
        // Add a non-orphan history entry — must not be counted.
        lc.history.push_back(CompletedResponse {
            id: "expired-1".into(),
            response_type: ResponseType::BlockIp,
            backend: ResponseBackend::Ufw,
            target: "203.0.113.99".into(),
            incident_id: "inc-99".into(),
            created_at: now - chrono::Duration::hours(2),
            reverted_at: now - chrono::Duration::hours(1),
            reason: "expired".into(),
        });
        assert_eq!(lc.current_orphan_count(), 3);
    }

    #[test]
    fn to_json_exposes_gauges_shape_distinct_from_totals() {
        // The dashboard's banner reads gauges.orphaned (current);
        // the lifetime KPI reads totals.orphaned. They must differ
        // when the counter has been bumped but the entries have
        // been GC'd. This anchor pins both shapes simultaneously.
        let mut lc = ResponseLifecycle::new();
        lc.total_orphaned = 17;
        // Zero history entries with reason="orphaned:" → current
        // count is 0 even though counter says 17.
        let v = lc.to_json();
        assert_eq!(
            v["gauges"]["orphaned"].as_u64().unwrap(),
            0,
            "gauges.orphaned must reflect current entries (0 here)"
        );
        assert_eq!(
            v["totals"]["orphaned"].as_u64().unwrap(),
            17,
            "totals.orphaned keeps the lifetime counter (17 here)"
        );
        // The two MUST be queryable separately so dashboard JS
        // distinguishes "now" from "ever".
        assert_ne!(
            v["gauges"]["orphaned"], v["totals"]["orphaned"],
            "anti-regression: a future refactor must not collapse them back into one field"
        );
    }
}
