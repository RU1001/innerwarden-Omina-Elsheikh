use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::ai::AiDecision;

// ---------------------------------------------------------------------------
// Decision log entry
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct DecisionEntry {
    pub ts: DateTime<Utc>,
    pub incident_id: String,
    pub host: String,
    pub ai_provider: String,

    /// Serialized AiAction tag (e.g. "block_ip", "ignore")
    pub action_type: String,
    pub target_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_user: Option<String>,
    pub skill_id: Option<String>,

    pub confidence: f32,
    pub auto_executed: bool,
    pub dry_run: bool,

    /// AI's textual reasoning
    pub reason: String,
    pub estimated_threat: String,

    /// Result of skill execution ("ok", "skipped", "failed: ...")
    pub execution_result: String,

    /// SHA-256 hash of the previous decision entry (tamper detection chain)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,

    /// Spec 049 PR17 — write-time-pinned decision layer.
    ///
    /// The writer site declares which spec 049 §8.2.E layer made the
    /// call (`algorithm_gate`, `killchain_fast_path`, `correlation_rule`,
    /// `ai_local_warden`, `ai_llm`, `auto_rule`, `honeypot_post_session`,
    /// `observation_verifier`, `manual_operator`). The dashboard
    /// drill-down reads this first and only falls back to the
    /// `decision_provenance` heuristic for legacy JSONL entries written
    /// before PR17. Pinning closes the bug class PR16 fixed at read time
    /// (a new gate provider silently demoting to "Unknown" because the
    /// classifier did not yet know about it).
    ///
    /// `Option<String>` (not the typed enum) keeps `decisions.rs` free
    /// of a layering dependency on `dashboard/`. The string must match
    /// the snake_case form `DecisionLayer::as_str()` emits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_layer: Option<String>,
}

// ---------------------------------------------------------------------------
// Decision writer
// ---------------------------------------------------------------------------

pub struct DecisionWriter {
    data_dir: std::path::PathBuf,
    current_date: String,
    writer: BufWriter<File>,
    /// SHA-256 hash of the last written decision entry for hash chaining.
    last_hash: Option<String>,
    /// Unified SQLite store (spec 016). When present every JSONL write is
    /// mirrored into the `decisions` table so the dashboard, `/metrics`, and
    /// the spec-024 drift harness all see the same reality as the audit log.
    /// Before this dual-write the sqlite copy was only populated by the
    /// one-shot legacy migration, which left production dashboards reading
    /// a stale table while the JSONL audit trail kept growing.
    store: Option<Arc<innerwarden_store::Store>>,
}

impl DecisionWriter {
    /// JSONL-only constructor retained for tests and any future callers that
    /// intentionally want to opt out of the sqlite mirror. Production uses
    /// [`DecisionWriter::with_store`] to keep the audit file and the
    /// `decisions` table in lockstep.
    #[allow(dead_code)]
    pub fn new(data_dir: &Path) -> Result<Self> {
        Self::with_store(data_dir, None)
    }

    /// Constructor that also takes an optional SQLite store. Production calls
    /// this with `Some(state.sqlite_store.clone())` so every decision written
    /// via `DecisionWriter::write` lands in both the JSONL audit file and
    /// the `decisions` table.
    pub fn with_store(
        data_dir: &Path,
        store: Option<Arc<innerwarden_store::Store>>,
    ) -> Result<Self> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let file = open_or_create(data_dir, &today)?;
        let last_hash = read_last_hash(data_dir, &today);
        Ok(Self {
            data_dir: data_dir.to_owned(),
            current_date: today,
            writer: BufWriter::new(file),
            last_hash,
            store,
        })
    }

    /// Append a decision to the daily JSONL.
    /// Rotates to a new file at midnight.
    /// Each entry includes a hash chain pointer to the previous entry.
    ///
    /// # Wave 3 (AUDIT-WAVE3-CHAIN-RACE, 2026-05-04 ultrareview)
    ///
    /// Pre-fix this method buffered writes through `BufWriter<File>` and
    /// re-read `disk_hash` to "guard against external writers". That
    /// guard is racy: between the `read_last_hash` call and the actual
    /// `writeln!` an external writer (the always-on honeypot calling
    /// `append_chained`, or a parallel slow-loop tick) could append its
    /// own entry. Both writers would compute their `prev_hash` from the
    /// same on-disk state and produce a forked chain. The fix routes
    /// the write through [`append_chained_locked`] so every writer
    /// (struct or free function) holds an `flock(LOCK_EX)` over the
    /// daily JSONL while it reads-the-hash, builds the line, writes,
    /// and flushes. The struct's BufWriter is bypassed because flock
    /// is on the `File` not the BufWriter, and an unflushed BufWriter
    /// would leave the lock held over data not yet on disk.
    pub fn write(&mut self, entry: &DecisionEntry) -> Result<()> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        if today != self.current_date {
            self.writer.flush().ok();
            let file = open_or_create(&self.data_dir, &today)?;
            self.writer = BufWriter::new(file);
            self.current_date = today.clone();
        }

        // Wave 3 fix: route through the locked-append helper so the
        // always-on honeypot path (which calls `append_chained`) and
        // this struct's path can never race the hash chain.
        let line = append_chained_locked(
            &self.data_dir,
            &self.current_date,
            entry,
            self.store.as_ref(),
        )?;
        // Update the in-memory cache so consecutive writes from the
        // same struct keep their cheap-prev-hash optimisation.
        self.last_hash = Some(sha256_hex(&line));
        Ok(())
    }

    pub fn flush(&mut self) {
        if let Err(e) = self.writer.flush() {
            warn!("decision writer flush failed: {e}");
        }
    }
}

/// Internal serialization helper that borrows fields instead of cloning.
#[derive(Serialize)]
struct ChainedEntry<'a> {
    ts: DateTime<Utc>,
    incident_id: &'a str,
    host: &'a str,
    ai_provider: &'a str,
    action_type: &'a str,
    target_ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_user: Option<&'a str>,
    skill_id: Option<&'a str>,
    confidence: f32,
    auto_executed: bool,
    dry_run: bool,
    reason: &'a str,
    estimated_threat: &'a str,
    execution_result: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_hash: Option<&'a str>,
}

/// Wave 3 (AUDIT-WAVE3-CHAIN-RACE) helper: tight `\d{4}-\d{2}-\d{2}`
/// validator for the `today` segment of the daily JSONL filename. Pure
/// 10-char check (4 digit + `-` + 2 digit + `-` + 2 digit) so CodeQL's
/// taint tracker sees the path component as sanitised. Rejects any
/// length / non-digit / non-`-` character that would let an attacker
/// who somehow controlled `today` perform path traversal via `..` or
/// inject NUL bytes / globs.
fn is_iso_date(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 10 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        match i {
            4 | 7 => {
                if *b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_digit() {
                    return false;
                }
            }
        }
    }
    true
}

fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Read the last line of today's decisions file and compute its SHA-256 hash.
/// Returns None if the file doesn't exist or is empty.
fn read_last_hash(data_dir: &Path, date: &str) -> Option<String> {
    let path = data_dir.join(format!("decisions-{date}.jsonl"));
    let file = File::open(&path).ok()?;
    let reader = BufReader::new(file);
    let mut last_line: Option<String> = None;
    for l in reader.lines().map_while(Result::ok) {
        if !l.trim().is_empty() {
            last_line = Some(l);
        }
    }
    last_line.map(|l| sha256_hex(&l))
}

fn open_or_create(data_dir: &Path, date: &str) -> Result<File> {
    let path = data_dir.join(format!("decisions-{date}.jsonl"));
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))
}

/// Count decision entries in `decisions-<date>.jsonl` (one per line). The
/// CANONICAL "how many decisions did the agent make on <date>" — used by
/// the daily briefing. Reads the persisted log, so it is restart-robust,
/// unlike `bot_helpers::graph_count(kg, "decisions")` which counts
/// in-memory KG Incident nodes that still carry an attached decision and
/// collapses toward 0 after a reboot (the KG is rebuilt from incidents,
/// not decisions). Missing file -> 0. (NUMBER_CONSISTENCY: "decisions
/// made today".)
pub fn count_decisions_for_date(data_dir: &Path, date: &str) -> usize {
    let path = data_dir.join(format!("decisions-{date}.jsonl"));
    // Stream the (all-day-growing) log line by line instead of slurping the
    // whole file into a String just to count non-empty lines.
    let Ok(file) = File::open(&path) else {
        return 0;
    };
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .count()
}

/// Count `block_ip` decisions in `decisions-<date>.jsonl` whose timestamp
/// falls in the SAME UTC hour as `now`. Restart-robust (reads the persisted
/// log). Used by the baseline silence detector to tell a benign `auth_log`
/// drop (scanners dropped at the firewall, so they never reach `sshd`) apart
/// from a real compromise that muzzles auth logging.
///
/// Both the file date and the hour filter derive from `now` (UTC). On a
/// UTC-clocked host (prod) this matches the `chrono::Local` date the writer
/// uses; on an off-UTC host the counts could be off only for incidents in the
/// hour straddling local midnight — acceptable for a benign/real heuristic.
pub fn count_block_ips_in_current_hour(
    data_dir: &Path,
    now: chrono::DateTime<chrono::Utc>,
) -> usize {
    let date = now.format("%Y-%m-%d").to_string();
    let path = data_dir.join(format!("decisions-{date}.jsonl"));
    let hour_prefix = now.format("%Y-%m-%dT%H").to_string();
    // Stream the daily log rather than holding the whole file in RAM.
    let Ok(file) = File::open(&path) else {
        return 0;
    };
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(&l).ok())
        .filter(|v| {
            v.get("action_type").and_then(|a| a.as_str()) == Some("block_ip")
                && v.get("ts")
                    .and_then(|t| t.as_str())
                    .is_some_and(|ts| ts.starts_with(&hour_prefix))
        })
        .count()
}

/// Standalone hash-chained append for code paths that don't own a `DecisionWriter`
/// (e.g. the always-on honeypot task). Routes through [`append_chained_locked`]
/// so it shares the file-level flock with `DecisionWriter::write`.
pub fn append_chained(
    data_dir: &Path,
    entry: &DecisionEntry,
    store: Option<&Arc<innerwarden_store::Store>>,
) -> Result<()> {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let _ = append_chained_locked(data_dir, &today, entry, store)?;
    Ok(())
}

/// Wave 3 (AUDIT-WAVE3-CHAIN-RACE) anchor: hash-chained append with
/// an exclusive file lock that BOTH the struct-based `DecisionWriter`
/// path and the standalone `append_chained` path use. The lock spans
/// from the `read_last_hash` call to the post-flush release, so two
/// concurrent appenders cannot both compute `prev_hash` from the same
/// on-disk state and fork the chain.
///
/// Returns the canonical JSON line that was written so the caller can
/// update its in-memory `last_hash` cache (the new line's SHA-256 is
/// the next entry's `prev_hash`).
///
/// Implementation notes:
/// * `flock(LOCK_EX)` is reaped automatically when the `File` drops
///   at the end of this function. We do NOT keep the lock across
///   the SQLite mirror because that ran outside the lock pre-fix
///   and adding it under-lock would extend the critical section
///   for no chain-integrity benefit.
/// * Errors from the `flock` call are wrapped with context so the
///   caller's error log captures both the syscall + the path.
fn append_chained_locked(
    data_dir: &Path,
    today: &str,
    entry: &DecisionEntry,
    store: Option<&Arc<innerwarden_store::Store>>,
) -> Result<String> {
    // Defense-in-depth: callers always pass `chrono::Local::now()` formatted
    // as `%Y-%m-%d`, so `today` is structurally `\d{4}-\d{2}-\d{2}`. Validate
    // the shape here to (a) reject any future caller that forwards
    // attacker-controlled input + (b) document the path-construction
    // contract for CodeQL's taint tracker (CWE-22 path traversal).
    if !is_iso_date(today) {
        anyhow::bail!(
            "decisions append_chained_locked: refusing to construct path with non-ISO-date segment {today:?}"
        );
    }
    let path: PathBuf = data_dir.join(format!("decisions-{today}.jsonl"));
    let mut f = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;

    f.lock_exclusive()
        .with_context(|| format!("flock(LOCK_EX) on {}", path.display()))?;

    // Re-read the last hash from disk INSIDE the lock so we observe
    // every write that landed before this one and exclude every write
    // that is still waiting on the lock.
    let last_hash = read_last_hash(data_dir, today);

    let chained = ChainedEntry {
        ts: entry.ts,
        incident_id: &entry.incident_id,
        host: &entry.host,
        ai_provider: &entry.ai_provider,
        action_type: &entry.action_type,
        target_ip: entry.target_ip.as_deref(),
        target_user: entry.target_user.as_deref(),
        skill_id: entry.skill_id.as_deref(),
        confidence: entry.confidence,
        auto_executed: entry.auto_executed,
        dry_run: entry.dry_run,
        reason: &entry.reason,
        estimated_threat: &entry.estimated_threat,
        execution_result: &entry.execution_result,
        prev_hash: last_hash.as_deref(),
    };
    let line = serde_json::to_string(&chained).context("failed to serialize decision entry")?;

    use std::io::Write;
    writeln!(f, "{line}").context("failed to write decision entry")?;
    f.flush().context("failed to flush decision entry")?;
    // Lock released automatically when `f` drops below.

    if let Some(store) = store {
        mirror_to_sqlite(store, entry, &line);
    }
    Ok(line)
}

const MIRROR_MAX_ATTEMPTS: u32 = 3;
const MIRROR_INITIAL_BACKOFF_MS: u64 = 50;

/// Try an SQLite-write closure up to `max_attempts` times with
/// exponential backoff (`initial_backoff_ms << (attempt - 1)`). Returns
/// the closure's last error on permanent failure so the caller can
/// surface it. Extracted from `mirror_to_sqlite` so the retry policy
/// can be unit-tested with a closure that does not require a real
/// `innerwarden_store::Store`.
///
/// `sleep` is a test injection point — production passes
/// `std::thread::sleep`; tests pass a no-op so backoffs do not slow
/// the suite.
fn retry_sqlite_write<F, E, S>(
    mut op: F,
    max_attempts: u32,
    initial_backoff_ms: u64,
    mut sleep: S,
) -> std::result::Result<u32, E>
where
    F: FnMut() -> std::result::Result<(), E>,
    S: FnMut(std::time::Duration),
{
    let mut last_err = None;
    for attempt in 1..=max_attempts {
        match op() {
            Ok(()) => return Ok(attempt),
            Err(e) => {
                last_err = Some(e);
                if attempt < max_attempts {
                    let backoff_ms = initial_backoff_ms << (attempt - 1);
                    sleep(std::time::Duration::from_millis(backoff_ms));
                }
            }
        }
    }
    Err(last_err.expect("at least one attempt must have run"))
}

/// Write a decision row to the SQLite `decisions` table. Shared by
/// `DecisionWriter::write` and `append_chained` so the two writers can
/// never drift in what they mirror. A mirror failure degrades to a `warn!`:
/// the JSONL audit trail has already succeeded, and a transient SQLite
/// error must not discard the whole decision.
///
/// Retry policy lives in `retry_sqlite_write`: up to `MIRROR_MAX_ATTEMPTS`
/// attempts with exponential backoff. The store layer already uses
/// `BEGIN IMMEDIATE` + `PRAGMA busy_timeout = 30000` so the first
/// attempt succeeds in ~all real-world cases; the retries are
/// belt-and-suspenders against worst-case WAL contention (e.g.
/// concurrent honeypot accept fan-out vs background graph-snapshot
/// transaction). On final failure we surface the error inline in the
/// `warn!` message — operators read this in plain `journalctl` output,
/// not `-o verbose`, so the error must not hide behind a structured
/// field alone.
fn mirror_to_sqlite(store: &innerwarden_store::Store, entry: &DecisionEntry, line: &str) {
    let row = innerwarden_store::decisions::DecisionRow {
        ts: entry.ts.to_rfc3339(),
        incident_id: entry.incident_id.clone(),
        action_type: entry.action_type.clone(),
        target_ip: entry.target_ip.clone(),
        target_user: entry.target_user.clone(),
        confidence: entry.confidence as f64,
        auto_executed: entry.auto_executed,
        reason: Some(entry.reason.clone()),
        data: line.to_owned(),
    };

    if let Err(e) = retry_sqlite_write(
        || store.insert_decision(&row).map(|_| ()),
        MIRROR_MAX_ATTEMPTS,
        MIRROR_INITIAL_BACKOFF_MS,
        std::thread::sleep,
    ) {
        // All retries exhausted. Surface the underlying error in the
        // message (not just the structured field) so operators see the
        // cause without needing `journalctl -o verbose`. The JSONL row
        // is the canonical record at this point.
        warn!(
            incident_id = %entry.incident_id,
            ai_provider = %entry.ai_provider,
            error = %e,
            "decision written to JSONL but sqlite mirror failed after {MIRROR_MAX_ATTEMPTS} attempts: {e}"
        );
    }
}

// ---------------------------------------------------------------------------
// Helper: build DecisionEntry from an AiDecision
// ---------------------------------------------------------------------------

/// Spec 049 PR17 — derive the canonical `decision_layer` string from
/// an AI provider name. The router emits these names (`local_classifier`,
/// `local_warden`, `openai`, `anthropic`, `ollama`, `llm`) into the
/// `ai_provider` field; this helper keeps the write-time pin in sync
/// with the heuristic in
/// `decision_provenance::classify_decision_layer_from_fields` so the
/// operator-facing label is identical regardless of which path
/// (pinned or fallback) classified the row.
///
/// Returns `"unknown"` for unrecognised provider strings — the caller
/// should override `entry.decision_layer` post-construction when they
/// have the right layer context (manual operator, observation
/// verifier, honeypot, etc.).
pub fn ai_provider_to_decision_layer(provider: &str) -> &'static str {
    match provider.to_ascii_lowercase().as_str() {
        "local_classifier" | "local_warden" => "ai_local_warden",
        "openai" | "anthropic" | "ollama" | "llm" => "ai_llm",
        _ => "unknown",
    }
}

/// Build a [`DecisionEntry`] from an [`AiDecision`].
///
/// Spec 049 PR17 — `decision_layer` is auto-set from the
/// `ai_provider` via [`ai_provider_to_decision_layer`]. AI-router
/// callers get the correct pin for free; non-router callers (manual
/// operator, observation verifier, etc.) should mutate
/// `entry.decision_layer` after construction.
pub fn build_entry(
    incident_id: &str,
    host: &str,
    ai_provider: &str,
    decision: &AiDecision,
    dry_run: bool,
    execution_result: &str,
) -> DecisionEntry {
    use crate::ai::AiAction;

    let (action_type, target_ip, target_user, skill_id) = match &decision.action {
        AiAction::BlockIp { ip, skill_id } => (
            "block_ip".to_string(),
            Some(ip.clone()),
            None,
            Some(skill_id.clone()),
        ),
        AiAction::Monitor { ip } => ("monitor".to_string(), Some(ip.clone()), None, None),
        AiAction::Honeypot { ip } => ("honeypot".to_string(), Some(ip.clone()), None, None),
        AiAction::SuspendUserSudo { user, .. } => (
            "suspend_user_sudo".to_string(),
            None,
            Some(user.clone()),
            Some("suspend-user-sudo".to_string()),
        ),
        AiAction::KillProcess { user, .. } => (
            "kill_process".to_string(),
            None,
            Some(user.clone()),
            Some("kill-process".to_string()),
        ),
        AiAction::BlockContainer { container_id, .. } => (
            "block_container".to_string(),
            Some(container_id.clone()),
            None,
            Some("block-container".to_string()),
        ),
        AiAction::RequestConfirmation { .. } => {
            ("request_confirmation".to_string(), None, None, None)
        }
        AiAction::KillChainResponse { .. } => (
            "kill_chain_response".to_string(),
            None,
            None,
            Some("kill-chain-response".to_string()),
        ),
        AiAction::Ignore { .. } => ("ignore".to_string(), None, None, None),
        AiAction::Dismiss { .. } => ("dismiss".to_string(), None, None, None),
    };

    DecisionEntry {
        ts: Utc::now(),
        incident_id: incident_id.to_string(),
        host: host.to_string(),
        ai_provider: ai_provider.to_string(),
        action_type,
        target_ip,
        target_user,
        skill_id,
        confidence: decision.confidence,
        auto_executed: decision.auto_execute,
        dry_run,
        reason: decision.reason.clone(),
        estimated_threat: decision.estimated_threat.clone(),
        execution_result: execution_result.to_string(),
        prev_hash: None, // Set by DecisionWriter::write() via hash chaining
        decision_layer: Some(ai_provider_to_decision_layer(ai_provider).to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::AiAction;

    #[test]
    fn count_decisions_for_date_counts_lines_and_handles_missing() {
        let dir = tempfile::tempdir().unwrap();
        // Missing file -> 0 (not an error).
        assert_eq!(count_decisions_for_date(dir.path(), "2026-05-13"), 0);
        // Three non-empty lines (+ a blank line that must not count).
        std::fs::write(
            dir.path().join("decisions-2026-05-13.jsonl"),
            "{\"a\":1}\n{\"a\":2}\n\n{\"a\":3}\n",
        )
        .unwrap();
        assert_eq!(count_decisions_for_date(dir.path(), "2026-05-13"), 3);
    }

    #[test]
    fn count_block_ips_in_current_hour_filters_action_and_hour() {
        use chrono::Timelike;
        let dir = tempfile::tempdir().unwrap();
        let now = chrono::Utc::now();
        // Pick a clearly-different hour for the negative case.
        let other_hour = (now.hour() + 12) % 24;
        let date = now.format("%Y-%m-%d");
        let cur = now.format("%Y-%m-%dT%H");
        let lines = format!(
            "{{\"action_type\":\"block_ip\",\"ts\":\"{cur}:05:00Z\"}}\n\
             {{\"action_type\":\"block_ip\",\"ts\":\"{cur}:30:00Z\"}}\n\
             {{\"action_type\":\"dismiss\",\"ts\":\"{cur}:31:00Z\"}}\n\
             {{\"action_type\":\"block_ip\",\"ts\":\"{date}T{other_hour:02}:00:00Z\"}}\n"
        );
        std::fs::write(dir.path().join(format!("decisions-{date}.jsonl")), lines).unwrap();

        // 2 block_ip in the current hour; the dismiss and the other-hour
        // block_ip are excluded.
        assert_eq!(count_block_ips_in_current_hour(dir.path(), now), 2);
        // Missing file -> 0.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(count_block_ips_in_current_hour(empty.path(), now), 0);
    }

    #[test]
    fn test_build_entry_block_ip() {
        let decision = AiDecision {
            action: AiAction::BlockIp {
                ip: "10.0.0.1".to_string(),
                skill_id: "block-ip-xdp".to_string(),
            },
            confidence: 0.95,
            reason: "malicious".to_string(),
            auto_execute: true,
            estimated_threat: "high".to_string(),
            alternatives: vec![],
        };

        let entry = build_entry("inc-123", "host-1", "openai", &decision, false, "success");

        assert_eq!(entry.incident_id, "inc-123");
        assert_eq!(entry.action_type, "block_ip");
        assert_eq!(entry.target_ip, Some("10.0.0.1".to_string()));
        assert_eq!(entry.skill_id, Some("block-ip-xdp".to_string()));
        assert_eq!(entry.execution_result, "success");
    }

    #[test]
    fn decision_writer_dual_writes_to_jsonl_and_sqlite() {
        // Regression guard: before the spec-016 follow-up the writer only
        // wrote JSONL, leaving dashboards reading a decisions table that
        // had not been touched since the legacy migration. The dual-write
        // must land every entry in both the audit file and the sqlite
        // mirror so `/metrics` + the spec-024 drift harness see the same
        // reality as the audit trail of record.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(innerwarden_store::Store::open(dir.path()).expect("store"));
        let mut writer =
            DecisionWriter::with_store(dir.path(), Some(store.clone())).expect("writer");

        let entry = DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: "inc-dual-1".into(),
            host: "h".into(),
            ai_provider: "test".into(),
            action_type: "block_ip".into(),
            target_ip: Some("203.0.113.9".into()),
            target_user: None,
            skill_id: Some("block-ip-ufw".into()),
            confidence: 0.91,
            auto_executed: true,
            dry_run: false,
            reason: "synthetic".into(),
            estimated_threat: "high".into(),
            execution_result: "ok".into(),
            prev_hash: None,
            decision_layer: None,
        };
        writer.write(&entry).expect("write decision");

        // JSONL side.
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let jsonl_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let jsonl = std::fs::read_to_string(&jsonl_path).expect("jsonl exists");
        assert!(jsonl.contains("inc-dual-1"), "jsonl must carry the entry");

        // Sqlite side.
        let count = store.decisions_count().expect("count");
        assert_eq!(count, 1, "sqlite decisions table must receive one row");
    }

    #[test]
    fn decision_writer_without_store_keeps_jsonl_path_working() {
        // Back-compat: constructing without a store (tests, pre-016 deploys)
        // must not require the sqlite path to be available.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut writer = DecisionWriter::new(dir.path()).expect("writer");
        let entry = DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: "inc-jsonl-only".into(),
            host: "h".into(),
            ai_provider: "test".into(),
            action_type: "ignore".into(),
            target_ip: None,
            target_user: None,
            skill_id: None,
            confidence: 0.4,
            auto_executed: false,
            dry_run: true,
            reason: "low".into(),
            estimated_threat: "low".into(),
            execution_result: "skipped".into(),
            prev_hash: None,
            decision_layer: None,
        };
        writer.write(&entry).expect("write without store");
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let jsonl = std::fs::read_to_string(dir.path().join(format!("decisions-{today}.jsonl")))
            .expect("jsonl written");
        assert!(jsonl.contains("inc-jsonl-only"));
    }

    #[test]
    fn test_build_entry_suspend_user() {
        let decision = AiDecision {
            action: AiAction::SuspendUserSudo {
                user: "alice".to_string(),
                duration_secs: 3600,
            },
            confidence: 0.8,
            reason: "sudo fail".to_string(),
            auto_execute: true,
            estimated_threat: "medium".to_string(),
            alternatives: vec![],
        };

        let entry = build_entry("inc-456", "host-2", "anthropic", &decision, true, "dry ran");

        assert_eq!(entry.action_type, "suspend_user_sudo");
        assert_eq!(entry.target_user, Some("alice".to_string()));
        assert_eq!(entry.target_ip, None);
        assert_eq!(entry.dry_run, true);
    }

    fn burst_entry(incident: &str) -> DecisionEntry {
        DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident.into(),
            host: "h".into(),
            ai_provider: "test".into(),
            action_type: "block_ip".into(),
            target_ip: Some("203.0.113.99".into()),
            target_user: None,
            skill_id: Some("block-ip-ufw".into()),
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: "synthetic".into(),
            estimated_threat: "high".into(),
            execution_result: "ok".into(),
            prev_hash: None,
            decision_layer: None,
        }
    }

    fn read_jsonl_lines(dir: &std::path::Path) -> Vec<String> {
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let path = dir.join(format!("decisions-{today}.jsonl"));
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(String::from)
            .collect()
    }

    #[test]
    fn append_chained_mirrors_to_sqlite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(innerwarden_store::Store::open(dir.path()).expect("store"));
        let entry = burst_entry("inc-append-1");

        append_chained(dir.path(), &entry, Some(&store)).expect("append_chained");

        let jsonl = read_jsonl_lines(dir.path());
        assert_eq!(jsonl.len(), 1, "JSONL must contain exactly the one entry");
        assert!(jsonl[0].contains("inc-append-1"));

        let count = store.decisions_count().expect("count");
        assert_eq!(
            count, 1,
            "SQLite decisions table must receive the mirrored row"
        );
    }

    #[test]
    fn append_chained_with_none_skips_sqlite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(innerwarden_store::Store::open(dir.path()).expect("store"));
        let entry = burst_entry("inc-append-none");

        append_chained(dir.path(), &entry, None).expect("append_chained None");

        let jsonl = read_jsonl_lines(dir.path());
        assert_eq!(jsonl.len(), 1, "JSONL still writes when store is None");

        let count = store.decisions_count().expect("count");
        assert_eq!(count, 0, "SQLite must stay untouched when store is None");
    }

    #[test]
    fn jsonl_and_sqlite_counts_match_under_mixed_writer_burst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(innerwarden_store::Store::open(dir.path()).expect("store"));
        let mut writer =
            DecisionWriter::with_store(dir.path(), Some(store.clone())).expect("writer");

        for i in 0..5 {
            writer
                .write(&burst_entry(&format!("inc-writer-{i}")))
                .expect("writer.write");
            append_chained(
                dir.path(),
                &burst_entry(&format!("inc-append-{i}")),
                Some(&store),
            )
            .expect("append_chained");
        }

        let jsonl = read_jsonl_lines(dir.path());
        let sqlite = store.decisions_count().expect("count") as usize;
        assert_eq!(
            jsonl.len(),
            sqlite,
            "JSONL and SQLite counts must match after mixed-writer burst"
        );
        assert_eq!(jsonl.len(), 10, "10 total entries (5 + 5) expected");
    }

    #[test]
    fn hash_chain_stays_intact_across_mixed_writers() {
        // Two invariants matter when DecisionWriter and append_chained interleave:
        //   1. The SQLite hash chain remains self-consistent (its own scheme:
        //      SHA-256(prev_hash || data)).
        //   2. For each sequence position, the JSONL line and the SQLite
        //      `data` column hold the same canonical JSON. Divergence here
        //      means the two stores disagree on what actually happened.
        // The two hash schemes differ by design (JSONL hashes the whole line
        // including prev_hash; SQLite hashes prev_hash concatenated with
        // data), so byte-equal chain comparison is not the right check —
        // content correspondence plus self-consistency is.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(innerwarden_store::Store::open(dir.path()).expect("store"));
        let mut writer =
            DecisionWriter::with_store(dir.path(), Some(store.clone())).expect("writer");

        writer
            .write(&burst_entry("inc-mix-1"))
            .expect("writer.write 1");
        append_chained(dir.path(), &burst_entry("inc-mix-2"), Some(&store))
            .expect("append_chained 2");
        writer
            .write(&burst_entry("inc-mix-3"))
            .expect("writer.write 3");
        append_chained(dir.path(), &burst_entry("inc-mix-4"), Some(&store))
            .expect("append_chained 4");

        let chain = store.verify_hash_chain().expect("verify");
        assert!(
            chain.intact,
            "SQLite hash chain must remain intact, broken_at = {:?}",
            chain.broken_at
        );
        assert_eq!(chain.verified, 4);

        let jsonl = read_jsonl_lines(dir.path());
        let sqlite_rows = store
            .decisions_since(0, 100)
            .expect("decisions_since")
            .into_iter()
            .map(|(_, data)| data)
            .collect::<Vec<_>>();
        assert_eq!(
            jsonl.len(),
            sqlite_rows.len(),
            "mixed-writer burst must keep JSONL and SQLite row counts aligned"
        );
        for (i, (j, s)) in jsonl.iter().zip(sqlite_rows.iter()).enumerate() {
            assert_eq!(
                j, s,
                "row {i} diverges between JSONL line and SQLite data column"
            );
        }
    }

    #[test]
    fn test_build_entry_dismiss_uses_dismiss_action_type() {
        // Regression: before AiAction::Dismiss existed, classifier
        // predictions of "dismiss" were silently collapsed into "ignore"
        // in the decision record. Check the distinct action_type survives.
        let decision = AiDecision {
            action: AiAction::Dismiss {
                reason: "below noise floor".to_string(),
            },
            confidence: 0.95,
            reason: "noise-gate filter".to_string(),
            auto_execute: true,
            estimated_threat: "low".to_string(),
            alternatives: vec![],
        };

        let entry = build_entry(
            "inc-dismiss-1",
            "host",
            "local_classifier",
            &decision,
            false,
            "filed",
        );

        assert_eq!(entry.action_type, "dismiss");
        assert_eq!(entry.target_ip, None);
        assert_eq!(entry.target_user, None);
        assert_eq!(entry.skill_id, None);
    }

    // ── Wave 3 anchors (AUDIT-WAVE3-CHAIN-RACE) ────────────────────────
    //
    // Pre-fix the struct-based `DecisionWriter::write` and the standalone
    // `append_chained` both did `read_last_hash` then `writeln!` without
    // a file lock. Two concurrent appenders (the slow loop + the always-on
    // honeypot, or the slow loop + a manual operator action) could both
    // read the same on-disk hash, build entries with the same `prev_hash`,
    // and fork the chain. The fix routes both writers through
    // `append_chained_locked` which holds `flock(LOCK_EX)` over the
    // read-hash + write + flush sequence.

    fn make_test_entry(idx: usize) -> DecisionEntry {
        DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: format!("inc-{idx}"),
            host: "test-host".to_string(),
            ai_provider: "test".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some(format!("203.0.113.{idx}")),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: format!("test entry {idx}"),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
            decision_layer: None,
        }
    }

    #[test]
    fn concurrent_append_chained_does_not_fork_the_hash_chain() {
        // 4 OS threads each call `append_chained` 25 times against the
        // same data_dir + day. Without flock the writers race and >=2
        // entries end up sharing a `prev_hash` (forked chain). With
        // flock the chain is linear: every entry's `prev_hash` matches
        // the SHA-256 of its predecessor.
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().to_path_buf();

        let n_threads = 4;
        let per_thread = 25;
        let handles: Vec<_> = (0..n_threads)
            .map(|t| {
                let data_dir = data_dir.clone();
                std::thread::spawn(move || {
                    for i in 0..per_thread {
                        let entry = make_test_entry(t * per_thread + i);
                        append_chained(&data_dir, &entry, None).expect("append must succeed");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread panicked");
        }

        // Read every line from the daily JSONL + verify the chain.
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let path = data_dir.join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&path).expect("read jsonl");
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines.len(),
            n_threads * per_thread,
            "all writes must land in the file"
        );

        // Build (hash, prev_hash) pairs and verify the chain. The first
        // line has prev_hash = None; every subsequent line must have
        // prev_hash equal to the SHA-256 of the line BEFORE it.
        let mut prev_seen: Option<String> = None;
        let mut prev_hashes_seen = std::collections::HashSet::new();
        for (i, line) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let line_prev = v
                .get("prev_hash")
                .and_then(|x| x.as_str())
                .map(String::from);
            // Anti-fork: NO two entries should share a non-None prev_hash.
            // (The first entry has None; all others must have unique prev_hashes.)
            if let Some(ref ph) = line_prev {
                assert!(
                    prev_hashes_seen.insert(ph.clone()),
                    "fork detected: line {i} duplicates prev_hash {ph} - the chain has split"
                );
            }
            // Linear chain: this line's prev_hash matches the previous
            // line's computed hash.
            assert_eq!(
                line_prev, prev_seen,
                "chain broken at line {i}: expected prev_hash {prev_seen:?}, got {line_prev:?}"
            );
            prev_seen = Some(sha256_hex(line));
        }
    }

    #[test]
    fn is_iso_date_accepts_canonical_today_format() {
        assert!(is_iso_date("2026-05-04"));
        assert!(is_iso_date("0001-01-01"));
        assert!(is_iso_date("9999-12-31"));
    }

    #[test]
    fn is_iso_date_rejects_path_traversal_and_garbage() {
        // Anti-regression: every shape that could let an attacker
        // who somehow controlled the `today` arg perform path
        // traversal or inject globs / NUL bytes must be rejected.
        for evil in &[
            "",
            "2026-05-4",       // wrong digit count
            "2026-5-04",       // wrong digit count
            "2026/05/04",      // wrong separator
            "../etc/passwd",   // path traversal classic
            "2026-05-04/../x", // path traversal smuggled in
            "2026-05-04\0",    // NUL terminator
            "2026-05-*",       // glob wildcard
            "2026-05-04 ",     // trailing space
            " 2026-05-04",     // leading space
            "26-05-04",        // wrong year width
        ] {
            assert!(
                !is_iso_date(evil),
                "is_iso_date must reject {evil:?} but did not"
            );
        }
    }

    #[test]
    fn append_chained_locked_refuses_non_iso_date_segment() {
        // Pin the path-construction guard end-to-end: passing a
        // non-ISO-date segment errors out BEFORE any open()/lock()
        // syscall, so an attacker-controlled `today` cannot reach
        // the filesystem layer.
        let dir = tempfile::tempdir().expect("tempdir");
        let entry = make_test_entry(0);
        let result = append_chained_locked(dir.path(), "../etc/passwd", &entry, None);
        let err = result.expect_err("path traversal must be refused");
        assert!(
            format!("{err:#}").contains("non-ISO-date segment"),
            "error must surface the validator's reason; got: {err:#}"
        );
    }

    #[test]
    fn append_chained_persists_entries_in_strict_serialization_order() {
        // Single-threaded baseline: 5 sequential calls produce 5 lines
        // forming a strict prev_hash -> hash chain. Anti-regression
        // for accidentally introducing batching that violates the
        // one-entry-per-flush invariant the audit-trail consumer
        // depends on.
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().to_path_buf();
        for i in 0..5 {
            let entry = make_test_entry(i);
            append_chained(&data_dir, &entry, None).unwrap();
        }
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let path = data_dir.join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 5);

        // First entry: prev_hash absent (the serializer uses
        // `skip_serializing_if = "Option::is_none"` so the field is
        // omitted entirely when the value is None).
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert!(
            first.get("prev_hash").is_none() || first.get("prev_hash").unwrap().is_null(),
            "first entry must have no prev_hash"
        );

        // Every subsequent entry: prev_hash matches predecessor's SHA-256.
        for i in 1..lines.len() {
            let v: serde_json::Value = serde_json::from_str(lines[i]).unwrap();
            let prev_hash = v
                .get("prev_hash")
                .and_then(|x| x.as_str())
                .expect("non-first entries must carry a non-null prev_hash");
            let expected = sha256_hex(lines[i - 1]);
            assert_eq!(prev_hash, expected, "chain broken at line {i}");
        }
    }

    #[test]
    fn is_iso_date_accepts_well_formed_dates() {
        assert!(is_iso_date("2026-05-04"));
        assert!(is_iso_date("0000-01-01"));
        assert!(is_iso_date("9999-12-31"));
    }

    #[test]
    fn is_iso_date_rejects_path_traversal_shapes() {
        assert!(!is_iso_date("../etc/pwd"));
        assert!(!is_iso_date("..\\windows"));
        assert!(!is_iso_date("2026/05/04"));
        assert!(!is_iso_date("2026-5-04"), "single-digit month rejected");
        assert!(!is_iso_date("2026-05-4"), "single-digit day rejected");
        assert!(
            !is_iso_date("2026-05-04 "),
            "trailing whitespace breaks length"
        );
        assert!(!is_iso_date("2026-05-04\0"), "NUL injection rejected");
    }

    #[test]
    fn is_iso_date_rejects_length_drift() {
        assert!(!is_iso_date(""), "empty string");
        assert!(!is_iso_date("2026-05-0"), "9 chars too short");
        assert!(!is_iso_date("2026-05-041"), "11 chars too long");
        assert!(!is_iso_date("26-05-04"), "2-digit year");
    }

    #[test]
    fn is_iso_date_rejects_wrong_separator_positions() {
        assert!(!is_iso_date("2026_05-04"), "underscore at pos 4");
        assert!(!is_iso_date("2026-05_04"), "underscore at pos 7");
        assert!(!is_iso_date("20260-5-04"), "dashes shifted");
        assert!(!is_iso_date("2026--5-04"), "double dash");
    }

    #[test]
    fn is_iso_date_rejects_non_digit_year_month_day() {
        assert!(!is_iso_date("YYYY-05-04"), "letters in year");
        assert!(!is_iso_date("2026-MM-04"), "letters in month");
        assert!(!is_iso_date("2026-05-DD"), "letters in day");
        assert!(!is_iso_date("2026-05-0a"), "letter in day");
    }

    #[test]
    fn append_chained_locked_returns_canonical_line_matching_disk_content() {
        // The return value of `append_chained_locked` is the exact
        // line that lands on disk - the caller's in-memory `last_hash`
        // cache (sha256_hex of the returned line) must match what the
        // next reader will see in the file. Pin that contract.
        let dir = tempfile::tempdir().expect("tempdir");
        let entry = make_test_entry(0);
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let returned_line =
            append_chained_locked(dir.path(), &today, &entry, None).expect("append must succeed");

        let path = dir.path().join(format!("decisions-{today}.jsonl"));
        let on_disk = std::fs::read_to_string(&path).expect("read");
        let on_disk_trimmed = on_disk.trim_end_matches('\n');

        assert_eq!(
            returned_line, on_disk_trimmed,
            "returned line must equal the line written to disk byte-for-byte"
        );
    }

    #[test]
    fn append_chained_to_existing_file_chains_from_existing_tail() {
        // Pre-existing file with N entries: a fresh `append_chained`
        // call must read the LAST entry's hash and use it as the new
        // entry's prev_hash. Anti-regression for accidentally
        // re-anchoring the chain to None when the file is non-empty
        // (which would silently break audit-trail verification).
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().to_path_buf();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        // Seed: 3 entries through the same path so the chain is real.
        for i in 0..3 {
            append_chained(&data_dir, &make_test_entry(i), None).unwrap();
        }
        let path = data_dir.join(format!("decisions-{today}.jsonl"));
        let seed_lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();
        let seed_tail_hash = sha256_hex(&seed_lines[seed_lines.len() - 1]);

        // The 4th append must chain from the seed_tail_hash.
        append_chained(&data_dir, &make_test_entry(99), None).unwrap();
        let all_lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();
        assert_eq!(all_lines.len(), 4);

        let fourth: serde_json::Value = serde_json::from_str(&all_lines[3]).unwrap();
        let fourth_prev = fourth
            .get("prev_hash")
            .and_then(|x| x.as_str())
            .expect("4th entry must carry prev_hash from existing tail");
        assert_eq!(
            fourth_prev, seed_tail_hash,
            "4th entry's prev_hash must equal SHA-256 of the 3rd entry"
        );
    }

    #[test]
    fn struct_writer_and_append_chained_share_one_linear_chain() {
        // Cross-path race: a long-lived `DecisionWriter` (struct path,
        // BufWriter cached) interleaves writes with bare `append_chained`
        // calls (the always-on honeypot's path). Pre-fix the struct
        // writer's stale BufWriter would lose entries appended through
        // the bare path between flushes. With the locked-helper routing,
        // both paths write through the same flock and produce one linear
        // chain.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut writer = DecisionWriter::new(dir.path()).expect("writer");

        // Interleave: struct, bare, struct, bare, struct.
        writer.write(&make_test_entry(0)).unwrap();
        append_chained(dir.path(), &make_test_entry(1), None).unwrap();
        writer.write(&make_test_entry(2)).unwrap();
        append_chained(dir.path(), &make_test_entry(3), None).unwrap();
        writer.write(&make_test_entry(4)).unwrap();
        writer.flush();

        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let path = dir.path().join(format!("decisions-{today}.jsonl"));
        let lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();
        assert_eq!(lines.len(), 5, "all 5 writes must land");

        // Verify strict linear chain across both paths.
        let mut prev_hash: Option<String> = None;
        for (i, line) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let line_prev = v
                .get("prev_hash")
                .and_then(|x| x.as_str())
                .map(String::from);
            assert_eq!(
                line_prev, prev_hash,
                "chain broken at line {i} (cross-path)"
            );
            prev_hash = Some(sha256_hex(line));
        }
    }

    // ── retry_sqlite_write anchors (2026-05-19 prod-bug
    // fix/sqlite-mirror-lock-race) ─────────────────────────────────────
    //
    // The retry helper is extracted from `mirror_to_sqlite` so we can
    // unit-test the policy without needing a real `innerwarden_store::Store`
    // that can be forced into transient failure. The closure form lets
    // us simulate "BUSY-N-then-success" and "permanent-failure" without
    // touching SQLite at all.

    #[test]
    fn retry_sqlite_write_returns_first_attempt_on_immediate_success() {
        let mut calls = 0u32;
        let mut sleep_calls = 0u32;
        let result = retry_sqlite_write(
            || -> std::result::Result<(), &'static str> {
                calls += 1;
                Ok(())
            },
            3,
            50,
            |_| sleep_calls += 1,
        );
        assert_eq!(result, Ok(1), "first-attempt success must report attempt=1");
        assert_eq!(calls, 1, "closure must run exactly once on success");
        assert_eq!(sleep_calls, 0, "no backoff sleep on first-attempt success");
    }

    #[test]
    fn retry_sqlite_write_retries_transient_failures_then_succeeds() {
        let mut calls = 0u32;
        let mut sleeps: Vec<std::time::Duration> = Vec::new();
        let result = retry_sqlite_write(
            || -> std::result::Result<(), &'static str> {
                calls += 1;
                if calls < 3 {
                    Err("database is locked")
                } else {
                    Ok(())
                }
            },
            3,
            50,
            |d| sleeps.push(d),
        );
        assert_eq!(result, Ok(3), "succeeds on third attempt");
        assert_eq!(calls, 3, "closure called once per attempt");
        assert_eq!(
            sleeps,
            vec![
                std::time::Duration::from_millis(50),
                std::time::Duration::from_millis(100),
            ],
            "exponential backoff: 50ms then 100ms between three attempts"
        );
    }

    #[test]
    fn retry_sqlite_write_returns_last_error_after_exhausting_attempts() {
        let mut calls = 0u32;
        let result = retry_sqlite_write(
            || -> std::result::Result<(), String> {
                calls += 1;
                Err(format!("attempt {calls} failed"))
            },
            3,
            50,
            |_| {},
        );
        assert_eq!(calls, 3, "must run all three attempts on permanent failure");
        // The LAST error must propagate — operators need the most recent
        // SQLite error message, not the first one.
        assert_eq!(result, Err("attempt 3 failed".to_string()));
    }

    #[test]
    fn retry_sqlite_write_skips_backoff_after_final_attempt() {
        // Anti-regression: a naïve loop might sleep after the final
        // failure too, adding latency for nothing. The current
        // implementation sleeps only BETWEEN attempts.
        let mut sleeps = 0u32;
        let _ = retry_sqlite_write(
            || -> std::result::Result<(), &'static str> { Err("nope") },
            3,
            50,
            |_| sleeps += 1,
        );
        assert_eq!(
            sleeps, 2,
            "3 attempts → 2 backoff sleeps (between attempts 1→2 and 2→3), never after the final attempt"
        );
    }
}
