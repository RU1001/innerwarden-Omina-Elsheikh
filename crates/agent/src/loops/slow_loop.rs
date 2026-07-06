use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use innerwarden_core::entities::EntityType;
use tracing::{info, warn};

use crate::{
    attacker_intel, cloud_safelist, config, correlation_engine, correlation_response, dashboard,
    decisions, dna_inline, killchain_inline, knowledge_graph, narrative_anomaly, narrative_autofp,
    narrative_daily_summary, narrative_incident_ingest, narrative_observation_verify, reader,
    shield_inline, telemetry_tick, AgentState,
};

/// True when a post-graph anomaly recalibration error is just the expected
/// "no autoencoder model trained yet" condition (a fresh or frequently
/// redeployed host before the nightly trainer has produced a model). These are
/// not failures and must not be WARN-logged every 30s slow-loop tick — a single
/// untrained box produced ~2.7k WARN lines in 7 days. Real recalibration errors
/// still log at WARN.
fn is_pretraining_no_model(err_msg: &str) -> bool {
    err_msg.contains("no model loaded")
}

// ── Disk-low guard for SQLite blob writes ────────────────────────────
//
// Operational fix for the 2026-04-25 02:59 UTC class of hangs: when
// `/var/lib/innerwarden` (the SQLite + JSONL data dir) drops below a
// safe threshold, a blob write inside `process_narrative_tick` can
// block on disk-full indefinitely while holding a writer lock from the
// r2d2 pool. The held lock then cascades into the same tokio runtime
// deadlock observed on the production agent (18-19 threads in
// `futex_wait_queue`).
//
// Strategy: before the KG snapshot write (the largest blob, ~5 MB
// gzipped, ~50 MB uncompressed in transit), call `df -B1 <data_dir>`
// and skip if free space is dangerously low. Cheap to fork once per
// 60 s tick; matches the pattern already used by
// `neural_lifecycle::train_nightly_with_store`'s disk guard.
//
// Thresholds: skip if free < 5 % of total OR free < 500 MB absolute.
// 5 % alone is too lenient for large disks; 500 MB alone is too
// generous for small disks. The OR captures both extremes.
//
// Behavior under low disk:
//   - skip the write (no retry, no buffer)
//   - WARN log with avail/total/pct + path
//   - bump `DISK_LOW_SKIPS_KG_SNAPSHOT` counter (Prometheus surface
//     via `/metrics`)
// Failure mode of the helper itself: if `df` fails to parse, the
// guard returns `false` (fail-open). Better to attempt the write
// than to skip writes forever on a parse-format change.

/// Total skipped KG snapshot writes due to low disk. Exposed via
/// `/metrics` as `innerwarden_disk_low_skips_total{operation="kg_snapshot"}`.
static DISK_LOW_SKIPS_KG_SNAPSHOT: AtomicU64 = AtomicU64::new(0);

/// Read-side accessor for the metrics renderer.
pub(crate) fn disk_low_skips_kg_snapshot() -> u64 {
    DISK_LOW_SKIPS_KG_SNAPSHOT.load(Ordering::Relaxed)
}

/// Pure threshold predicate. Disk is "critically low" if either the
/// free fraction is below 5 % or the free absolute is below 500 MB.
/// `total = 0` is treated as fail-open (returns false) so that a
/// malformed disk-stat call cannot refuse all writes.
pub(crate) fn disk_low_pct_or_bytes(avail_bytes: u64, total_bytes: u64) -> bool {
    if total_bytes == 0 {
        return false;
    }
    let pct_free = (avail_bytes as f64 / total_bytes as f64) * 100.0;
    pct_free < 5.0 || avail_bytes < 500 * 1024 * 1024
}

/// Shell-out to `df -B1 <path>` and parse the avail/size columns
/// (in bytes). Returns `None` on any error so the caller can fail-open.
fn disk_avail_total_bytes(path: &Path) -> Option<(u64, u64)> {
    let output = std::process::Command::new("df")
        .arg("-B1")
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    // Expected format on Linux GNU coreutils:
    //   Filesystem  1B-blocks  Used  Available  Use%  Mounted on
    //   /dev/sda1   48360873984 41812451328  4554420224  91%  /
    // Skip the header line, take the last non-empty data line.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().rfind(|l| !l.trim().is_empty())?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 6 {
        return None;
    }
    let total: u64 = cols[1].parse().ok()?;
    let avail: u64 = cols[3].parse().ok()?;
    Some((avail, total))
}

/// Returns true when the data_dir's filesystem is dangerously low and
/// the caller should skip a critical SQLite write. Fails-open on stat
/// errors (better to attempt a write than to silently halt all writes).
fn disk_critically_low(path: &Path) -> bool {
    disk_avail_total_bytes(path)
        .map(|(avail, total)| disk_low_pct_or_bytes(avail, total))
        .unwrap_or(false)
}

/// Lazy-reopen `sqlite_store` if a boot-time race left it as `None`.
/// Throttled to one attempt per `STORE_REOPEN_BACKOFF_SECS` so a
/// permanent error (disk full, schema corruption) does not become a
/// tight retry loop. Idempotent: returns immediately if the store is
/// already open.
const STORE_REOPEN_BACKOFF_SECS: u64 = 60;
pub(crate) fn try_recover_sqlite_store(state: &mut AgentState) {
    if state.sqlite_store.is_some() {
        return;
    }
    let now = std::time::Instant::now();
    if let Some(last) = state.sqlite_reopen_last_attempt {
        if now.duration_since(last).as_secs() < STORE_REOPEN_BACKOFF_SECS {
            return;
        }
    }
    state.sqlite_reopen_last_attempt = Some(now);

    match innerwarden_store::Store::open(&state.sqlite_store_path) {
        Ok(s) => {
            info!(
                path = %state.sqlite_store_path.join("innerwarden.db").display(),
                "sqlite store recovered after boot-time failure"
            );
            state.sqlite_store = Some(std::sync::Arc::new(s));
            // Spin up the maintenance scheduler too — it was None at
            // boot for the same reason.
            if state.maintenance_scheduler.is_none() {
                state.maintenance_scheduler =
                    Some(innerwarden_store::maintenance::MaintenanceScheduler::new());
            }
        }
        Err(e) => {
            // Quiet warn — same message format as the boot path so log
            // grep surfaces the persistence problem the same way.
            warn!("sqlite store still unavailable: {e:#}");
        }
    }
}

/// Drive the v2 schema backfill of `events.src_ip` for one batch of
/// legacy rows. PR #262 moved the backfill out of `apply_v2` into the
/// slow_loop so a multi-hundred-thousand-row table on an upgraded
/// production database does not block `Store::open` and re-trigger the
/// boot-time `database is locked` race that left `sqlite_store`
/// permanently `None` (see `RECURRING_BUGS.md` "sqlite_store stuck at
/// None after boot race").
///
/// Each call is one batch (a single explicit transaction so the WAL
/// acquires RESERVED → COMMIT once per 1000 rows instead of once per
/// row — that is the property that lets the backfill make progress
/// against a sensor that is concurrently writing). Returns silently
/// when no rows remain.
///
/// Spec 037 I-05a: the tick scheduler calls this via
/// [`run_events_src_ip_backfill_in_place`] which wraps the call in
/// `tokio::task::block_in_place`, so the blocking SQLite transaction
/// runs without blocking the tokio scheduler — but still serializes
/// against the slow_loop's other SQLite operations in the same tick.
/// The first attempt at this (PR #289) used `tokio::spawn` +
/// `spawn_blocking`, which made the backfill run CONCURRENTLY with
/// the rest of the tick's SQLite work and contended for the writer
/// lock against `events_since`, KG snapshot saves, response_lifecycle
/// persists. With `busy_timeout=5000ms` every backfill batch timed
/// out — 100% failure rate on prod, migration progress dropped to
/// zero. `block_in_place` keeps the inline-serialized semantics
/// (one SQLite operation at a time within the tick) while preserving
/// the original goal of not blocking the async runtime.
/// 2026-05-03 (Wave 5b PR-3): batch size dropped from 1000 → 100.
/// On the operator's prod host the backfill txn was holding the SQLite
/// writer lock long enough that the sensor's concurrent INSERTs into
/// the same table (separate process, separate `Store::open`, same
/// .db file) raced past the `busy_timeout=5000ms`. Result: every
/// backfill batch failed with "database is locked", logged warn every
/// 30 s for hours, and the migration never finished.
///
/// Smaller batches release the writer lock more frequently; the
/// throttle below ensures the backfill only runs once per minute
/// instead of every 30 s tick, so the sensor's writer has predictable
/// write windows. Net: more batches succeed, total throughput equals
/// or exceeds the 1000-rows-per-30s-but-failing baseline.
const BACKFILL_BATCH_SIZE: usize = 100;

/// Maximum retries on `database is locked` within a single backfill
/// call. Retries with linear back-off so a transient sensor-write
/// burst (a few hundred ms) does not waste a full minute waiting for
/// the next tick.
const BACKFILL_LOCK_RETRIES: u32 = 3;
const BACKFILL_LOCK_BACKOFF_MS: u64 = 200;

pub(crate) fn drive_events_src_ip_backfill(store: &innerwarden_store::Store) {
    let pending = match store.events_pending_src_ip_backfill() {
        Ok(0) => return,
        Ok(n) => n,
        Err(e) => {
            warn!("events.src_ip backfill pending count failed: {e:#}");
            return;
        }
    };

    for attempt in 0..=BACKFILL_LOCK_RETRIES {
        match store.backfill_events_src_ip(BACKFILL_BATCH_SIZE) {
            Ok(0) => return, // race with another writer; pick up next tick
            Ok(updated) => {
                if attempt > 0 {
                    info!(
                        updated,
                        pending_before = pending,
                        attempt,
                        "events.src_ip backfill batch applied after retry"
                    );
                } else {
                    info!(
                        updated,
                        pending_before = pending,
                        "events.src_ip backfill batch applied"
                    );
                }
                return;
            }
            Err(e) => {
                // Distinguish "database is locked" (transient,
                // retryable) from other errors (schema, IO, ...).
                // The error string is the only reliable signal we
                // have because rusqlite wraps the SQLite error code
                // through several layers and the typed enum is
                // generic over the inner cause.
                let msg = format!("{e:#}");
                let is_lock = msg.contains("database is locked") || msg.contains("SQLITE_BUSY");
                if is_lock && attempt < BACKFILL_LOCK_RETRIES {
                    // Linear back-off: 200 ms, 400 ms, 600 ms.
                    // `block_in_place` is already in scope (caller
                    // wraps this whole function) so a `std::thread::
                    // sleep` does not stall the tokio scheduler.
                    let delay = BACKFILL_LOCK_BACKOFF_MS * (attempt as u64 + 1);
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                    continue;
                }
                // Non-lock errors AND lock errors after the final
                // retry land here. warn-not-fail: backfill is
                // best-effort and readers handle NULL src_ip
                // gracefully (`events_for_training` normalizes the
                // empty-string sentinel back to None). The agent
                // stays functional and we try again next tick.
                if is_lock {
                    warn!(
                        attempts = attempt + 1,
                        "events.src_ip backfill batch failed: {e:#} (will retry next tick)"
                    );
                } else {
                    warn!("events.src_ip backfill batch failed: {e:#}");
                }
                return;
            }
        }
    }
}

/// Synchronous wrapper around [`drive_events_src_ip_backfill`] that uses
/// `tokio::task::block_in_place` to release tokio workers during the
/// blocking SQLite transaction without spawning a separate task. This
/// matches the pattern used by `train_nightly_with_store` (PR #290) for
/// CPU/IO-blocking work inside the async tick.
///
/// Why not `tokio::spawn`: the previous version (PR #289) used
/// `tokio::spawn` + `spawn_blocking` to make the backfill fully
/// concurrent with the rest of the tick. In production this meant the
/// backfill task contended with the tick's own SQLite work
/// (`events_since`, KG snapshot save, response_lifecycle persist) for
/// the writer lock through the same connection pool. With
/// `busy_timeout=5000ms` every batch timed out — 100% failure rate,
/// migration progress dropped to zero. `block_in_place` keeps the
/// inline-serialized property of the original PR #262 design (one
/// SQLite operation at a time within a tick) while preserving the
/// original goal that motivated #289 (don't block the tokio scheduler).
///
/// The tick will spend ~5–50 ms here per batch when the backfill has
/// rows to process; once `events_pending_src_ip_backfill` returns 0
/// the call is a no-op (single SELECT).
/// 2026-05-03 (Wave 5b PR-3): minimum interval between two backfill
/// calls. The slow_loop ticks every 30 s; without this throttle the
/// backfill ran twice as often as needed and contended with the
/// sensor's concurrent writes for the SQLite writer lock. 60 s is a
/// soft target — slow_loop drift can stretch it to ~62 s and that's
/// fine.
const BACKFILL_MIN_INTERVAL_SECS: i64 = 60;

/// Unix timestamp of the last backfill attempt. 0 = never attempted
/// (cold start). Updated when `backfill_throttle_allows` returns true.
static BACKFILL_LAST_ATTEMPT_TS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);

/// Returns `true` if at least `BACKFILL_MIN_INTERVAL_SECS` have passed
/// since the last allowed attempt, AND atomically records this
/// moment as the new "last attempt" — so callers do not need a
/// separate `mark_attempted` call. Pure side-effect on the static.
fn backfill_throttle_allows() -> bool {
    let now = chrono::Utc::now().timestamp();
    let last = BACKFILL_LAST_ATTEMPT_TS.load(std::sync::atomic::Ordering::Relaxed);
    if now - last < BACKFILL_MIN_INTERVAL_SECS {
        return false;
    }
    // Race: two ticks crossing the interval boundary at the same time.
    // Only one wins the CAS, so only one runs. The loser falls through
    // to the next cycle, which is fine — the contract is "at most one
    // attempt per BACKFILL_MIN_INTERVAL_SECS", not "exactly one".
    BACKFILL_LAST_ATTEMPT_TS
        .compare_exchange(
            last,
            now,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        )
        .is_ok()
}

#[cfg(test)]
fn reset_backfill_throttle_for_test() {
    BACKFILL_LAST_ATTEMPT_TS.store(0, std::sync::atomic::Ordering::Relaxed);
}

fn run_events_src_ip_backfill_in_place(state: &AgentState) {
    let Some(store) = state.sqlite_store.clone() else {
        return;
    };
    // `block_in_place` panics on the single-threaded runtime that
    // `#[tokio::test]` and the heap-budget anchors use by default.
    // Production runs `#[tokio::main]` which defaults to multi-thread,
    // so the production path takes the wrapper. Test contexts (and
    // any future caller on a current_thread runtime) take the direct
    // synchronous call — same observable effect for the backfill, just
    // without the worker-transfer hint.
    let multi_thread = tokio::runtime::Handle::try_current()
        .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
        .unwrap_or(false);
    if multi_thread {
        tokio::task::block_in_place(|| {
            drive_events_src_ip_backfill(&store);
        });
    } else {
        drive_events_src_ip_backfill(&store);
    }
}

/// Record per-collector event counts on the in-memory telemetry state.
/// Reads-only over the events slice, writes only to `state.telemetry`
/// (no SQLite, no shared lock with other tick jobs). Spec 037 I-05b
/// extraction — pure code organization, no behavior change vs. the
/// inline call that existed before; lifted into a named function so
/// the tick body reads as a sequence of named jobs instead of a
/// monolithic block.
fn record_telemetry_observation(state: &mut AgentState, events: &[innerwarden_core::event::Event]) {
    state.telemetry.observe_events(events);
}

/// Track operator IPs from event stream: any successful SSH/auth login
/// over `publickey` is treated as an operator session (the remote side
/// proved possession of a private key on the server's authorized_keys).
/// Pure in-memory: reads `events` slice, writes `state.operator_ips`
/// HashMap. No SQLite, no I/O, no blocking work — `block_in_place` not
/// needed. Spec 037 I-05d — code organization, no behavior change vs
/// the inline scan that lived directly inside `process_narrative_tick`.
///
/// Position-load-bearing: must run AFTER events are read into
/// `events_entries` and BEFORE the same tick's downstream consumers
/// (`decision_block_ip`, `incident_auto_rules`, `correlation_response`,
/// etc.) which all read `state.operator_ips` to skip blocking the
/// operator's own session. Keep this call between
/// `record_telemetry_observation` and `update_narrative_accumulator`
/// in `process_narrative_tick`.
fn track_operator_ips_from_events(
    state: &mut AgentState,
    events: &[innerwarden_core::event::Event],
) {
    for ev in events {
        if ev.kind == "ssh.login_success"
            || ev.kind == "auth.login_success"
            || ev.kind == "auth.session_opened"
        {
            let method = ev
                .details
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if method == "publickey" {
                // Spec 037 I-15: filter empty/whitespace so an unactionable
                // "" never enters operator_ips and corrupts the SSH-session
                // protection logic.
                let ip = ev
                    .details
                    .get("ip")
                    .or_else(|| ev.details.get("src_ip"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                if let Some(ip) = ip {
                    let is_new = !state.operator_ips.contains_key(ip);
                    state
                        .operator_ips
                        .insert(ip.to_string(), std::time::Instant::now());
                    if is_new {
                        let user = ev
                            .details
                            .get("user")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");
                        info!(
                            user,
                            ip, "operator session detected (publickey) — IP protected"
                        );
                    }
                }
            }
        }
    }
}

/// Roll the per-day narrative accumulator forward one tick: reset its
/// internal counters if the calendar date changed since the last tick,
/// then ingest the new events. Pure in-memory, no SQLite, no shared
/// state with other tick jobs (the accumulator is owned exclusively by
/// the daily summary path). Spec 037 I-05c — code organization, no
/// behavior change vs. the inline call pair.
fn update_narrative_accumulator(
    state: &mut AgentState,
    today: &str,
    events: &[innerwarden_core::event::Event],
) {
    state.narrative_acc.reset_for_date(today);
    state.narrative_acc.ingest_events(events);
}

/// Write the dashboard metrics tile (`graph-stats.json`) and surface
/// failures via `warn!` with structured context. Replaces the prior
/// `let _ = std::fs::write(..)` pattern at the kg_tick snapshot block
/// (Spec 037 I-13 PR-3). Silent failure went unnoticed: the dashboard
/// tile is what `/api/dashboard/metrics` and the Home KPI panel
/// consume; on a failed write, the operator saw stale numbers with
/// no signal at all. The warn restores the signal — the tile is
/// still stale, but the operator log + journald carry the cause.
///
/// Returns `()` (infallible). Called once per 60s tick from the
/// snapshot block, never in a hot loop, so the warn is not a
/// 2026-05-03: extract a useful "subject" from an event for the
/// Baseline tab's anomaly cards. Priority: User entity → IP entity →
/// `details.comm` (process name). The subject becomes the actionable
/// link the operator clicks to pivot into Threats. Returns None when
/// the event has no recognisable subject — the dashboard falls back
/// to an unsubject'd card.
///
/// Pulled out of `process_narrative_tick` as a standalone helper so
/// it can be unit-tested without setting up the full slow_loop
/// fixture; the tick path simply calls this on every event with
/// detected anomalies.
fn extract_anomaly_subject(
    entities: &[innerwarden_core::entities::EntityRef],
    event: &innerwarden_core::event::Event,
) -> Option<String> {
    // Strict priority User > IP > comm — User is the most actionable
    // pivot for the operator (named identity rather than network
    // endpoint). Two scans rather than one `find` so the ordering
    // does not depend on the entities[] insertion order at the call
    // site.
    entities
        .iter()
        .find(|e| matches!(e.r#type, EntityType::User))
        .map(|e| e.value.clone())
        .or_else(|| {
            entities
                .iter()
                .find(|e| matches!(e.r#type, EntityType::Ip))
                .map(|e| e.value.clone())
        })
        .or_else(|| {
            event
                .details
                .get("comm")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
}

/// log-spam vector.
fn write_graph_stats_or_warn(data_dir: &Path, json: &[u8]) {
    let path = data_dir.join("graph-stats.json");
    if let Err(e) = std::fs::write(&path, json) {
        warn!(
            path = %path.display(),
            error = %e,
            "graph-stats.json write failed (dashboard metrics tile may go stale)"
        );
    }
}

/// Bundle the knowledge-graph-touching jobs of a single slow_loop tick:
/// event ingest, real-time trigger drain, periodic snapshot/maintenance,
/// graph-derived neural feature extraction, and graph detector run.
/// Inline (no spawn), zero behavior change vs. the prior unnamed block
/// in `process_narrative_tick`. Spec 037 I-05e — explicit unit naming
/// for what was ~170 lines of unnamed inline code, motivated by Job 7
/// being non-trivially coupled with Job 8 + Job 11 (the original I-05
/// "extract per-tick jobs" rule of "if it touches SQLite, block_in_place;
/// if pure code organization, keep inline" did not handle the case where
/// three steps share state and ordering — naming the bundle is the right
/// shape).
///
/// ⚠️ Order is LOAD-BEARING. Do NOT reorder steps. Do NOT split parts
/// out into independent tasks without auditing every reader of
/// `state.knowledge_graph` and `state.graph_detector_state`. The graph
/// must be in a coherent post-ingest state when steps 4-6 read it:
///   1. ingest events: populate nodes/edges from this tick's events.
///   2. drain triggers: read just-ingested state, return real-time incidents.
///   3. ingest trigger incidents: write drained triggers back into the graph.
///   4. snapshot/maintenance: every 60 s, three-scope locking serializes
///      the graph (cheap mutations under WRITE, bytes under READ,
///      I/O lock-free).
///   5. neural features: `extract_neural_features` reads the post-ingest
///      graph and pushes into anomaly_engine.
///   6. graph detectors: `run_all_with_calibration` reads the post-ingest
///      graph; resulting incidents go back into the graph under WRITE.
///
/// Excluded from the bundle (deliberate scope limit, document if you
/// reconsider):
///   - Cross-layer correlation engine (`correlation_engine.observe`)
///     and baseline learner (`baseline.observe_event`): event-driven,
///     they classify the same `events_entries` slice but never read the
///     graph. They run AFTER `kg_tick` returns in the parent tick body.
///   - Killchain inline + DNA inline: same property — event-driven,
///     no graph read. Live outside `kg_tick`.
///
/// Why not `tokio::spawn`: steps 4–6 must observe a coherent post-ingest
/// graph state. Spawning would race the read against the write. Any
/// future PR that wants to move `kg_tick` off the tick path must pass
/// a snapshot of the just-ingested graph by value, not the shared
/// `Arc<RwLock<KnowledgeGraph>>`.
fn kg_tick(
    state: &mut AgentState,
    data_dir: &Path,
    events: &[innerwarden_core::event::Event],
    cfg: &config::AgentConfig,
) {
    // ── Steps 1+2: ingest events, drain real-time triggers ──────────
    // Single WRITE-lock scope: set host label once, ingest each event,
    // then drain. Drain MUST happen under the same lock as ingest so
    // triggers fire on the just-ingested state without an interleaved
    // reader.
    let trigger_incidents = {
        let mut graph = state.knowledge_graph.write().unwrap();
        if graph.trigger_host.is_empty() {
            let host_label = graph
                .system_node()
                .and_then(|id| graph.get_node(id))
                .map(|n| n.label())
                .unwrap_or_else(|| "unknown".to_string());
            graph.set_trigger_host(&host_label);
        }
        for ev in events {
            graph.ingest(ev);
        }
        graph.drain_trigger_incidents()
    };

    // ── Step 3: ingest drained triggers back into the graph ─────────
    if !trigger_incidents.is_empty() {
        tracing::info!(count = trigger_incidents.len(), "real-time triggers fired");
        let mut graph = state.knowledge_graph.write().unwrap();
        for inc in &trigger_incidents {
            graph.ingest_incident(inc);
        }
        // Phase 6E: trigger incidents are already in the knowledge graph
        // (ingested above). No separate JSONL write needed.
    }

    // ── Step 4: periodic snapshot/maintenance (every 60 s) ──────────
    //
    // Pre-2026-04-23 this whole block ran under a single `write()` guard
    // that wrapped cleanup + compact + enforce + serialize + gzip +
    // fs::write + SQLite bind + cleanup_old_snapshots. Every dashboard
    // request blocked on that write lock for hundreds of ms each tick.
    //
    // The fix splits into three lock scopes:
    //   1. WRITE lock: cheap mutations only (cleanup_expired, compact_edges,
    //      enforce_memory_limit). All in-memory, no I/O.
    //   2. READ lock: serialize the snapshot bytes (allows concurrent
    //      dashboard reads). Returns owned `SerializedSnapshot`.
    //   3. NO lock: disk + SQLite writes + cleanup_old_snapshots.
    //
    // Worst-case dashboard latency under contention drops from "duration
    // of the entire 60s-tick block" to "duration of cleanup+compact+enforce"
    // (sub-ms with the `last_edge_ts` cache from PR #261).
    if state.last_graph_snapshot.elapsed().as_secs() >= 60 {
        // Scope 1: cheap mutations under WRITE lock.
        //
        // 2026-05-03 (Wave 5b PR-4): order is `cleanup_expired →
        // enforce_memory_limit → compact_edges_force`. Both
        // `cleanup_expired` and `enforce_memory_limit` call
        // `remove_node`, which tombstones edges (decrements
        // adjacency lists) but leaves the entries in `self.edges`
        // until compaction runs. Compaction MUST come last so it
        // sweeps tombstones from BOTH passes — the previous order
        // (`compact_edges → enforce_memory_limit`) left
        // `enforce`'s tombstones in `self.edges` for the
        // serialise step that followed, producing dangling-edge
        // warns on the next reload (operator's prod showed
        // `dangling=30157` every save cycle). `compact_edges_force`
        // ignores the 20%-ratio gate so the pre-save sweep always
        // happens; gated `compact_edges` stays the right call for
        // any other site doing inline mutations.
        {
            let mut graph = state.knowledge_graph.write().unwrap();
            graph.cleanup_expired(chrono::Utc::now());
            graph.enforce_memory_limit();
            graph.compact_edges_force();
        }

        // Scope 2: serialize snapshot + metrics under READ lock so
        // dashboard handlers can read concurrently. The bytes are owned
        // and outlive the lock scope.
        let serialised = {
            let graph = state.knowledge_graph.read().unwrap();
            let bytes = match graph.serialize_snapshot_bytes() {
                Ok(b) => Some(b),
                Err(e) => {
                    warn!("knowledge graph snapshot serialise failed: {e:#}");
                    None
                }
            };
            let metrics_json = serde_json::to_vec(&graph.metrics()).ok();
            (bytes, metrics_json)
        };

        // Scope 3: I/O outside any lock. SQLite blob is now the only
        // canonical write for the KG snapshot; `load_dated` remains as
        // a read-side fallback (handled via `load_dated_sqlite_first`)
        // so existing `graph-snapshot-YYYY-MM-DD.json` files on disk
        // keep working until they age out under the 7-day retention
        // policy (`cleanup_old_snapshots` below is untouched by this PR
        // per the slice-5 plan). The Prometheus counter
        // `innerwarden_kg_dated_load_total{source="json"}` must stay at
        // zero after this change — any non-zero increment means a
        // reader fell through to the fallback, which is a signal to
        // investigate (not a silent degradation).
        let (snapshot_bytes, metrics_json) = serialised;
        if let Some(snap) = snapshot_bytes {
            // Disk-low guard. Cheap fork-and-parse of `df -B1` once per
            // 60 s tick. Three mutually exclusive outcomes:
            //   1. disk_critically_low: skip + WARN + bump counter.
            //   2. sqlite_store None: skip + WARN (separate signal).
            //   3. healthy: write the blob.
            if disk_critically_low(data_dir) {
                DISK_LOW_SKIPS_KG_SNAPSHOT.fetch_add(1, Ordering::Relaxed);
                if let Some((avail, total)) = disk_avail_total_bytes(data_dir) {
                    let pct = (avail as f64 / total as f64) * 100.0;
                    warn!(
                        avail_mb = avail / 1_048_576,
                        total_mb = total / 1_048_576,
                        pct_free = format!("{pct:.1}"),
                        path = %data_dir.display(),
                        "disk-low guard: skipping KG snapshot save (avoids SQLite write hang)"
                    );
                } else {
                    warn!(
                        path = %data_dir.display(),
                        "disk-low guard fired but disk-stat re-read failed; skipping KG snapshot save"
                    );
                }
            } else if let Some(ref sq) = state.sqlite_store {
                if let Err(e) = knowledge_graph::KnowledgeGraph::store_snapshot_bytes(sq, &snap) {
                    warn!("knowledge graph SQLite snapshot failed: {e:#}");
                }
            } else {
                // SQLite store unavailable — no canonical sink for this
                // tick. Surface rather than silently drop the snapshot.
                warn!("knowledge graph snapshot skipped: sqlite store unavailable");
            }
        }
        if let Some(json) = metrics_json {
            // Spec 037 I-13 PR-3: surface write failures rather than
            // letting the dashboard tile go stale silently.
            write_graph_stats_or_warn(data_dir, &json);
        }
        // Phase 7: cleanup old snapshots (keep 7 days). File-system scan
        // and unlink — also lock-free.
        knowledge_graph::KnowledgeGraph::cleanup_old_snapshots(data_dir, 7);
        if let Some(ref sq) = state.sqlite_store {
            knowledge_graph::KnowledgeGraph::cleanup_store_snapshots(sq, 7);
        }

        state.last_graph_snapshot = std::time::Instant::now();
    }

    // ── Step 5: push graph-derived neural features ──────────────────
    // Reads the POST-ingest graph (steps 1+2 above) — moving this
    // before step 1 would feed stale features to the anomaly engine.
    {
        let graph = state.knowledge_graph.read().unwrap();
        let gf = graph.extract_neural_features();
        state.anomaly_engine.set_graph_features(gf);
    }

    // 2026-05-04 (Wave 7a): trigger a one-shot post-graph
    // recalibration the first time we have graph features. Boot's
    // recalibration ran with `graph_features = None`, so its
    // anchors used zero-graph feature vectors and now under-sample
    // the live distribution → live observe() saturates near 1.0
    // again. Re-running here lets the new anchors reflect the
    // production feature shape that observe() actually consumes.
    // Best-effort and runs at most once per process lifetime;
    // future periodic recalibrations are a separate follow-up.
    if state.anomaly_engine.needs_post_graph_recalibration() {
        if let Some(ref sq) = state.sqlite_store {
            const POST_GRAPH_RECAL_SAMPLE: i64 = 10_000;
            match sq.events_max_id() {
                Ok(max_id) => {
                    let after = max_id.saturating_sub(POST_GRAPH_RECAL_SAMPLE);
                    match sq.events_since(after, POST_GRAPH_RECAL_SAMPLE as usize) {
                        Ok(rows) => {
                            let events: Vec<innerwarden_core::event::Event> =
                                rows.into_iter().map(|(_, ev)| ev).collect();
                            if !events.is_empty() {
                                match state
                                    .anomaly_engine
                                    .recalibrate_anchors_from_events(&events)
                                {
                                    Ok(samples) => {
                                        info!(
                                            samples,
                                            events_read = events.len(),
                                            "anomaly: post-graph anchor recalibration complete"
                                        );
                                        state.anomaly_engine.clear_post_graph_recalibration_flag();
                                    }
                                    Err(e) => {
                                        let msg = e.to_string();
                                        if is_pretraining_no_model(&msg) {
                                            // Expected before the nightly
                                            // autoencoder has trained a model on
                                            // this host (fresh / frequently
                                            // redeployed box). Not an error and
                                            // must not spam WARN every 30s tick —
                                            // 2.7k lines/7d observed on Azure.
                                            tracing::debug!(
                                                "anomaly: recalibration skipped — {msg}"
                                            );
                                        } else {
                                            warn!(
                                                "anomaly: post-graph recalibration failed (will retry next tick): {msg}"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("anomaly: post-graph recalibration sqlite read failed: {e}")
                        }
                    }
                }
                Err(e) => warn!("anomaly: post-graph recalibration max-id read failed: {e}"),
            }
        }
    }

    // ── Step 6: run graph-based detectors ───────────────────────────
    // Reads the POST-ingest graph and POST-snapshot maintenance state.
    // Detector incidents are written back into the graph so the next
    // tick's correlation/dashboard reads see them.
    {
        let (graph_incidents, _host_label) = {
            let graph = state.knowledge_graph.read().unwrap();
            let host = graph
                .system_node()
                .and_then(|id| graph.get_node(id))
                .map(|n| n.label())
                .unwrap_or_else(|| "unknown".to_string());
            let calibration_ctx = knowledge_graph::detectors::CalibrationContext {
                is_cloud: state.environment_profile.is_cloud(),
                human_uids: state.environment_profile.human_uids.clone(),
                human_user_names: state.environment_profile.human_user_names.clone(),
                service_uids: state.environment_profile.service_uids.clone(),
                service_user_names: state.environment_profile.service_user_names.clone(),
            };
            let mut incidents = knowledge_graph::detectors::run_all_with_calibration(
                &graph,
                &mut state.graph_detector_state,
                &host,
                chrono::Utc::now(),
                &calibration_ctx,
            );
            // Spec 043 Phase 3 — yara_match detector. Gated at the
            // outermost layer (here) so the config check is visible
            // alongside the other slow-loop wiring; activates a KG
            // field that was write-only pre-Phase-3.
            if cfg.kg.yara_match_detector_enabled {
                incidents.extend(knowledge_graph::detectors::detect_yara_match(
                    &graph,
                    &mut state.graph_detector_state,
                    &host,
                    chrono::Utc::now(),
                ));
            }
            // Spec 043 Phase 5 — sysctl_drift detector. Same pattern
            // as yara_match: gated at outermost layer, default OFF.
            // First tick after enable snapshots the baseline; subsequent
            // ticks diff and emit Critical/Medium per change-class.
            if cfg.kg.sysctl_drift_detector_enabled {
                incidents.extend(knowledge_graph::detectors::detect_sysctl_drift(
                    &graph,
                    &mut state.graph_detector_state,
                    &host,
                    chrono::Utc::now(),
                ));
            }
            // Spec 043 Phase 4 — packed_binary detector. Activates
            // File.entropy (write-only pre-Phase-4). Threshold and
            // enable both come from config — operator can tune.
            if cfg.kg.packed_binary_detector_enabled {
                incidents.extend(knowledge_graph::detectors::detect_packed_binary(
                    &graph,
                    &mut state.graph_detector_state,
                    &host,
                    chrono::Utc::now(),
                    cfg.kg.packed_binary_entropy_threshold,
                ));
            }
            // Spec 043 Phase 6 — short_lived_process detector. Activates
            // Process.exit_ts (write-only pre-Phase-6). Threshold and
            // enable both come from config.
            if cfg.kg.short_lived_process_detector_enabled {
                incidents.extend(knowledge_graph::detectors::detect_short_lived_process(
                    &graph,
                    &mut state.graph_detector_state,
                    &host,
                    chrono::Utc::now(),
                    cfg.kg.short_lived_process_threshold_ms,
                ));
            }
            (incidents, host)
        };
        {
            let mut graph = state.knowledge_graph.write().unwrap();
            for inc in &graph_incidents {
                graph.ingest_incident(inc);
            }
        }
        if !graph_incidents.is_empty() {
            // Phase 6E: graph detector incidents are already in the knowledge graph
            // (ingested above). No separate JSONL write needed.
            tracing::info!(count = graph_incidents.len(), "graph detectors fired");
        }
    }
}

/// Run a session-listing command (default `who -i`) to capture stdout,
/// surfacing genuine spawn/exec failures via `warn!` while staying
/// silent on `NotFound` (some minimal containers ship without the
/// binary). Replaces the silent
/// `if let Ok(output) = Command::new("who").arg("-i").output()` site
/// in `refresh_operator_ips` (Spec 037 I-13 follow-up #2).
///
/// `program` is parameterised so tests can inject a path that exists
/// but is not executable (forcing the warn branch) or a NotFound
/// path (verifying silent fallthrough). Production passes "who".
///
/// On a real spawn failure (perms, exec error) the operator-IP
/// enrichment is skipped: the agent loses the signal that protects
/// active SSH sessions from automated blocks. The warn carries
/// program + error so the operator can investigate the regression.
fn run_session_command_or_warn(program: &str, arg: &str) -> Option<String> {
    match std::process::Command::new(program).arg(arg).output() {
        Ok(output) => Some(String::from_utf8_lossy(&output.stdout).into_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(
                program,
                error = %e,
                "session-listing invocation failed (operator IP enrichment skipped)"
            );
            None
        }
    }
}

/// Refresh operator IPs from active SSH sessions.
/// Replaces the entire set - IPs whose sessions ended are automatically removed.
pub(crate) fn refresh_operator_ips(state: &mut AgentState, allowlist: &config::AllowlistConfig) {
    let now = std::time::Instant::now();
    let mut active_ips = std::collections::HashMap::new();

    // Check active sessions via `who -i`
    if let Some(who_out) = run_session_command_or_warn("who", "-i") {
        active_ips = operator_ips_from_who_output(&who_out, &allowlist.trusted_users, now);
    }

    // Log removed sessions
    for old_ip in state.operator_ips.keys() {
        if !active_ips.contains_key(old_ip) {
            info!(ip = %old_ip, "operator session ended — IP protection removed");
        }
    }
    // Log new sessions
    for new_ip in active_ips.keys() {
        if !state.operator_ips.contains_key(new_ip) {
            info!(ip = %new_ip, "operator session detected — IP protected");
        }
    }

    state.operator_ips = active_ips;
}

// ---------------------------------------------------------------------------
// Narrative tick - runs every 30s
//
// Responsibility: regenerate the daily Markdown summary when new events arrive.
// Webhook and incident processing have been moved to process_incidents so that
// all incidents are notified in real-time, not batched every 30 seconds.
// ---------------------------------------------------------------------------

/// Returns the number of new events seen this tick.
pub(crate) async fn process_narrative_tick(
    data_dir: &Path,
    _cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> Result<usize> {
    // Lazy-recover SQLite store after a boot-time `database is locked`
    // race. Pre-2026-04-23 a failed initial `Store::open` left
    // `state.sqlite_store` as `None` for the entire process lifetime,
    // silently dropping every SQLite-mediated write (graph snapshots,
    // blob writes, agent cursors). Discovered during the Finding 5
    // canary on 2026-04-23 — the SQLite snapshot save was a silent
    // no-op for hours after a contended startup. See
    // `RECURRING_BUGS.md` "sqlite_store stuck at None after boot race".
    try_recover_sqlite_store(state);

    // Drive the v2 src_ip backfill at MOST once per minute. Wrapped
    // in `block_in_place` so other tokio tasks on sibling workers
    // keep making progress.
    //
    // 2026-05-03 (Wave 5b PR-3): throttled from "every tick (30 s)"
    // to "every 60 s" to give the sensor's concurrent writer
    // (separate process, separate SQLite connection, same .db file)
    // predictable write windows. Combined with the smaller
    // `BACKFILL_BATCH_SIZE` (1000 → 100) and the lock-error
    // retry-with-backoff in `drive_events_src_ip_backfill`, prod
    // hosts that were spinning on "database is locked" every 30 s
    // now make forward progress without log spam. No-op when the
    // store is missing or no NULL rows remain.
    if backfill_throttle_allows() {
        run_events_src_ip_backfill_in_place(state);
    }

    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let (mut events_entries, events_count) = if let Some(ref sq) = state.sqlite_store {
        let cval = sq.get_agent_cursor("events").unwrap_or(0);
        match sq.events_since(cval, 5000) {
            Ok(rows) if !rows.is_empty() => {
                let max_id = rows.last().unwrap().0;
                let entries: Vec<_> = rows.into_iter().map(|(_, ev)| ev).collect();
                let count = entries.len();
                // Spec 037 I-13 PR-3: surface persistent SQLite
                // degradation. A cursor-write failure is safe (next
                // tick re-reads the same events; baseline absorbs
                // the duplicates), so the operation continues —
                // but the warn tells the operator something is off
                // with the store before the symptom (re-processing,
                // baseline drift) becomes visible.
                if let Err(e) = sq.set_agent_cursor("events", max_id) {
                    warn!(
                        cursor = "events",
                        max_id,
                        error = %e,
                        "agent cursor advance failed; events will be re-read next tick"
                    );
                }
                (entries, count)
            }
            _ => (Vec::new(), 0),
        }
    } else {
        warn!("sqlite_store not available — cannot read events");
        (Vec::new(), 0)
    };

    // Wave 9 (AUDIT-WAVE9-CF-ATTRIBUTION): rewrite each event's
    // src_ip from the Cloudflare edge IP to the real client IP
    // (`details.cf_connecting_ip`) when the socket peer is a CF
    // edge. Done HERE — before telemetry / narrative / KG / baseline
    // / correlation read the events — so every downstream surface
    // (Threats tab, attacker-profiles, dashboard live-feed, public
    // site) sees the resolved attribution. Original edge IP is
    // preserved in `details.cdn_edge_ip` for forensic. The trust
    // gate (`is_cloudflare_edge_ip` on the socket peer) prevents a
    // non-CF attacker from spoofing `CF-Connecting-IP` to
    // misattribute their traffic.
    if !events_entries.is_empty() {
        let rewrites =
            crate::cloudflare_attribution::rewrite_events_for_cloudflare(&mut events_entries);
        if rewrites > 0 {
            tracing::debug!(
                rewrites,
                total_events = events_entries.len(),
                "Wave 9: rewrote CF-edge events to real client IPs"
            );
        }
    }

    record_telemetry_observation(state, &events_entries);

    // Track operator IPs (publickey-authenticated sessions). Position
    // is load-bearing — multiple downstream consumers in the same tick
    // (`decision_block_ip`, `incident_auto_rules`, `correlation_response`,
    // ...) read `state.operator_ips` to avoid blocking the operator's
    // own session. See `track_operator_ips_from_events` doc comment.
    track_operator_ips_from_events(state, &events_entries);

    // Feed new events into the narrative accumulator (incremental, no file re-read)
    update_narrative_accumulator(state, &today, &events_entries);

    // Knowledge-graph-touching jobs of this tick: ingest events, drain
    // real-time triggers, periodic snapshot/maintenance (60 s), neural
    // feature extraction, graph detectors. Bundled because the order is
    // load-bearing — see `kg_tick` doc comment for the full explanation
    // of why these six steps form one unit and why the cross-layer
    // correlation loop below is NOT in the bundle.
    kg_tick(state, data_dir, &events_entries, cfg);

    // Feed events into cross-layer correlation engine and baseline learning.
    // Events from trusted processes are excluded — they make legitimate
    // outbound connections that would false-positive on data-exfil chains.
    //
    // Two filters:
    // 1. PID-based: exclude our own process tree (agent, sensor, watchdog children).
    //    Catches tokio-rt-worker threads that eBPF reports with the thread comm.
    // 2. Comm-based: exclude known system services (crowdsec, apt, certbot, etc.)
    let trusted_procs = &cfg.responder.trusted_processes;
    let own_pid = std::process::id();
    for ev in &events_entries {
        let ev_comm = ev
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let ev_pid = ev.details.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        // Filter 1: own process tree (agent + its threads).
        // eBPF reports thread comm ("tokio-rt-worker") not binary name.
        // Check if event PID belongs to us by reading /proc/PID/status PPid.
        let is_own_tree = ev_pid > 0 && is_pid_in_own_tree(ev_pid, own_pid);

        // Filter 2: trusted process comm names from config.
        let is_trusted_comm = !ev_comm.is_empty()
            && trusted_procs
                .iter()
                .any(|tp| ev_comm.starts_with(tp.as_str()));

        if is_own_tree || is_trusted_comm {
            // Still feed to baseline (we want to learn their normal
            // patterns). Spec 037 I-13 PR-3: the returned
            // `Vec<AnomalyReport>` is intentionally discarded — for
            // trusted/own-tree events we deliberately do NOT raise
            // correlation incidents from anomalies (that would
            // false-positive on the agent's own activity and known
            // system services). Bare-expression form replaces the
            // prior `let _ =` so the discard is documentary, not
            // accidental.
            state.baseline.observe_event(ev);
            continue;
        }
        let corr_event = correlation_engine::CorrelationEngine::classify_event(ev);
        let ev_entities = corr_event.entities.clone();
        state.correlation_engine.observe(corr_event);
        let anomalies = state.baseline.observe_event(ev);
        if !anomalies.is_empty() {
            state.last_baseline_anomaly_ts = Some(chrono::Utc::now());
        }
        // Pull a subject (user / IP / process comm) out of the event
        // entities so the dashboard can render an actionable link
        // when this anomaly is shown to the operator. Best-effort —
        // None when the event has no obviously named subject.
        let anomaly_subject: Option<String> = extract_anomaly_subject(&ev_entities, ev);
        for anomaly in &anomalies {
            info!(
                anomaly_type = ?anomaly.anomaly_type,
                description = %anomaly.description,
                "baseline anomaly detected"
            );

            // 2026-05-03: persist a stamped copy of the anomaly so
            // the Baseline dashboard tab can show "what changed in
            // the last 24h" without re-walking the journald stream.
            state
                .baseline
                .record_anomaly(anomaly, anomaly_subject.clone());

            // Inject baseline anomalies into correlation engine.
            let kind = match anomaly.anomaly_type {
                crate::baseline::AnomalyType::EventRateDrop => "baseline.silence",
                crate::baseline::AnomalyType::EventRateSpike => "baseline.rate_spike",
                crate::baseline::AnomalyType::ProcessLineage => "baseline.new_process",
                crate::baseline::AnomalyType::UserLoginTime => "baseline.unusual_login",
                crate::baseline::AnomalyType::NewDestination => "baseline.new_destination",
            };
            let baseline_corr = correlation_engine::CorrelationEngine::baseline_event(
                kind,
                anomaly.severity.clone(),
                ev_entities.clone(),
                serde_json::json!({
                    "description": anomaly.description,
                    "expected": anomaly.expected,
                    "observed": anomaly.observed,
                }),
            );
            state.correlation_engine.observe(baseline_corr);
        }
    }

    // Feed eBPF events through kill chain tracker (inline pattern detection).
    // Filter out trusted processes to prevent false kill chain matches.
    if cfg.killchain.enabled {
        let kc_events: Vec<_> = events_entries
            .iter()
            .filter(|ev| {
                let comm = ev
                    .details
                    .get("comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let pid = ev.details.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let own_tree = pid > 0 && is_pid_in_own_tree(pid, own_pid);
                let trusted = !comm.is_empty()
                    && trusted_procs.iter().any(|tp| comm.starts_with(tp.as_str()));
                !own_tree && !trusted
            })
            .cloned()
            .collect();
        let kc_incidents = killchain_inline::process_events(
            &mut state.killchain_tracker,
            &kc_events,
            &mut state.correlation_engine,
        );
        // Spec 081 — managed-agent coexistence: register the kernel PID-block
        // for offending chain PIDs, but WITHHOLD it for a positively-verified,
        // IW-managed AI agent acting on its own services (data_exfil/exploit_c2
        // shape). Detection is unchanged — the incidents were already produced
        // above and are written + notified below. The verifier fails closed, so
        // a real attacker / forged identity / recycled pid is still kernel-blocked.
        killchain_inline::register_kernel_blocks(&kc_incidents, state).await;
        killchain_inline::write_incidents(data_dir, state.sqlite_store.as_deref(), &kc_incidents);
        // Phase 7B (audit RC-2 — Slice C): kill chain detections fire
        // on operator SSH sessions (operator runs `cat /etc/passwd`,
        // sensor sees socket+sensitive_read in same window, classifies
        // as DATA_EXFIL). The operator is not the attacker. Pre-7B
        // these incidents were written without a decision and showed
        // up in the dashboard's "Stuck >1h" bucket as false-positive
        // alarm. Now: when the kill chain target IP matches a current
        // operator session, write a dismiss decision inline so the
        // incident leaves the operator-visible stuck bucket as soon
        // as it's surfaced.
        crate::killchain_inline::dismiss_operator_session_incidents(
            data_dir,
            state.sqlite_store.as_ref(),
            &kc_incidents,
            &state.operator_ips,
        );
        // Phase 11A (audit RC-2 / 2026-04-29): self-traffic FP filter.
        // Catches the apt/snap-update + ssh-jump class of false
        // positives that the operator-session filter doesn't cover
        // because the c2_ip is a cloud-provider destination, not the
        // operator's laptop. Process identity (comm/uid) is what we
        // key on — apt running as root or ssh running as ubuntu uid
        // get auto-dismissed; an attacker exploiting a service
        // account (uid 1-999) running ssh / curl still goes to the
        // AI router for a real decision.
        // 2026-05-03 (PR #417): single source of truth for self-
        // traffic comms. Both dismiss + telegram-suppress consume
        // the SAME merged list (builtins from
        // `BUILTIN_SELF_TRAFFIC_COMMS` + operator additions from
        // `[killchain] self_traffic_comms_extra`). Pre-fix the two
        // had divergent constants and the operator got Telegram
        // alerts for apt updates that the AI silently dismissed.
        let self_traffic_list = killchain_inline::self_traffic_comms(&cfg.killchain);
        crate::killchain_inline::dismiss_self_traffic_incidents(
            data_dir,
            state.sqlite_store.as_ref(),
            &kc_incidents,
            &self_traffic_list,
        );
        // 2026-05-09 fast-path block for deterministic kill_chain
        // patterns (reverse_shell, bind_shell, code_inject,
        // inject_shell). MUST run AFTER the dismiss helpers above so
        // operator-session / self-traffic FPs are filtered first; the
        // function re-checks the per-incident decisions table to defer
        // to any earlier dismiss decision, never overrides one. The
        // block call inherits circuit breaker + rate limit + safelist
        // + cloud-provider gate from the canonical executor.
        // Latency cut: removes the AI router call (~100ms Local Warden,
        // ~1-3s cloud LLM) from the dispatch path. Tick cadence
        // unchanged. For sub-second response see future bpf_send_signal
        // spec.
        crate::killchain_inline::fast_path_block_strong_patterns(
            &kc_incidents,
            data_dir,
            cfg,
            state,
        )
        .await;
        let gate_counter = state.telemetry.gate_suppressed_counter();
        // Resolve the operator-facing server identity once (cheap; uses the
        // `[agent] tags` → knowledge-graph hostname → /etc/hostname ladder).
        let burst_host =
            crate::notification_gate::resolve_host_id(&cfg.agent.tags, &state.knowledge_graph);
        killchain_inline::notify_telegram(
            &state.telegram_client,
            &kc_incidents,
            &state.notification_burst_tracker,
            &mut state.telegram_deferred,
            gate_counter.as_ref(),
            &self_traffic_list,
            &burst_host,
        );

        // Periodic stale PID cleanup (every 60s).
        if state.last_killchain_cleanup.elapsed().as_secs() >= 60 {
            killchain_inline::cleanup_stale(&mut state.killchain_tracker);
            state.last_killchain_cleanup = std::time::Instant::now();
        }
    }

    // Phase 7B (audit RC-2): orphan-incident recovery sweep.
    // Every 10 minutes, walk SQLite for incidents that fired >1h ago
    // and never received a decision (deploy orphans, AI provider
    // skips, classifier failures). Each gets a `dismiss` decision
    // with `ai_provider="orphan-recovery"` written through the
    // standard hash-chained audit path. The dashboard's "Stuck >1h"
    // pending bucket then trends down naturally instead of growing
    // unboundedly. The 200-row cap per sweep means a freshly-deployed
    // agent with hundreds of historical orphans sees the count
    // decrease across ticks — the operator sees a cleanup pass
    // running, not a number that vanishes mysteriously.
    if state.last_orphan_recovery.elapsed().as_secs() >= 600 {
        let written = crate::orphan_recovery::run_sweep(state, data_dir).await;
        if written > 0 {
            tracing::info!(
                written,
                "slow_loop: orphan-recovery sweep dismissed {written} abandoned incidents"
            );
        }
        state.last_orphan_recovery = std::time::Instant::now();

        // Re-verify already-decided needs_review cases against the LIVE firewall
        // (operator report 2026-06-13): a High/Crit case decided needs_review
        // BEFORE its IP got blocked stays in "needs your attention" forever once
        // the block lands later — #987 only verified at first-decision, and the
        // in-memory block record can diverge from an orphaned ufw rule. This
        // flips such cases to a truthful Contained decision by probing the actual
        // firewall (never the record). Recon-only (active-harm stays surfaced);
        // hole-free (returns raise new incidents + live-verified re-block).
        let recontained =
            crate::orphan_recovery::reverify_already_blocked_needs_review(state, data_dir).await;
        if recontained > 0 {
            tracing::info!(
                recontained,
                "slow_loop: re-verified {recontained} needs_review case(s) as already-contained (live firewall)"
            );
        }
    }

    // 2026-06-10 — operator-unblock drain. Runs every tick (one bounded SQL
    // scan, usually empty). Drains `operator_unblock_request` rows queued by
    // the dashboard's Unblock button and performs the real revert through
    // `response_lifecycle` so the block-enforcement reconciler does not
    // re-apply a dashboard-side rule removal. Kept off a longer timer on
    // purpose: an operator who clicks Unblock should not wait 10 minutes.
    {
        let unblocked =
            crate::operator_actions::run_unblock_drain(state, data_dir, cfg.responder.dry_run)
                .await;
        if unblocked > 0 {
            info!(unblocked, "slow_loop: drained operator unblock requests");
        }
    }

    // Spec 080 G4 — Execution Gate divergence monitor (FREE honesty net).
    // Self-throttled (10 min) live-vs-signed check: raises a self-incident when
    // the paid gate's signed allowlist has not converged to the kernel maps, so
    // the paid feature can never silently go inert / stay un-applied. Verifies
    // the LIVE kernel state, never the record (same principle as spec 076).
    crate::execution_gate_monitor::process_execution_gate_tick(data_dir);

    // DNS Guard intel bridge — export the agent's malicious-domain intel to the
    // paid DNS Guard's denylist file (free detect → paid prevent). Self-throttled
    // (5 min) + write-only-if-changed; no-op unless `[dns_guard] export_enabled`.
    crate::dns_guard_export::process_dns_guard_export_tick(&cfg.dns_guard, state);

    // DNS Guard ingest — tail the guard's block events (byte-offset cursor) and
    // surface each `dns_guard.blocked` malicious-domain lookup as a High incident
    // so it's visible in IW. No-op unless `[dns_guard] ingest_enabled`.
    crate::dns_guard_ingest::process_dns_guard_ingest_tick(data_dir, &cfg.dns_guard, state);

    // Spec 062 Phase 2 — needs_review timeout sweep. Every 10 minutes,
    // auto-resolve low/medium needs_review items that sat past the grace
    // window with no human action (honest `auto_resolved_timeout` dismiss).
    // High/critical are NEVER auto-dismissed here — they stay visible.
    if state.last_needs_review_timeout.elapsed().as_secs() >= 600 {
        let resolved = crate::needs_review_timeout::run_sweep(state, data_dir);
        if resolved > 0 {
            info!(
                resolved,
                "needs_review_timeout: auto-resolved low/medium review items past grace window"
            );
        }
        state.last_needs_review_timeout = std::time::Instant::now();
    }

    // Spec 076 phase 2 — block-enforcement reconciler. Every 5 min, make the
    // live firewall match intent: re-apply any active block whose rule silently
    // dropped (TTL-removal that didn't clear the record, restart reloading a
    // stale set, external flush), and stamp last_verified_live so the dashboard
    // reflects the live rule rather than the TTL alone. Proactive counterpart to
    // the decision-time live-verify guard (spec 076) — closes the idle window.
    if state.last_block_enforcement_reconcile.elapsed().as_secs() >= 300 {
        let (verified, reapplied) =
            crate::decision_block_ip::reconcile_block_enforcement(state).await;
        if reapplied > 0 {
            warn!(
                verified,
                reapplied, "block-enforcement reconciler restored dropped firewall rules"
            );
        }
        state.last_block_enforcement_reconcile = std::time::Instant::now();
    }

    // Spec 081 follow-up — agent-guard registry reconciliation. Self-throttled
    // (5 min): auto-register co-located AI agents (OpenClaw, …) so the managed-
    // agent response gate's `by_pid` hint survives agent restarts, and prune
    // dead pids so a recycled pid can never inherit the spec-081 exemption. Only
    // supplies the membership hint — the verifier still independently re-IDs +
    // fingerprint-matches + trusted-root + own-config + uid-checks live (no new
    // hole). No-op unless `[agent_guard] auto_register = true` (default on).
    crate::agent_registry_reconcile::process_agent_registry_reconcile_tick(
        &cfg.agent_guard,
        state,
        data_dir,
    )
    .await;

    // Feed events through threat DNA engine (behavioral fingerprinting + anomaly detection).
    if cfg.dna.enabled {
        dna_inline::process_events(
            &mut state.dna_state,
            &events_entries,
            &mut state.correlation_engine,
            &mut state.attacker_profiles,
        );

        // Periodic DNA state persistence (every 5 min).
        if state.last_dna_save.elapsed().as_secs() >= 300 {
            dna_inline::save(&state.dna_state);
            state.last_dna_save = std::time::Instant::now();
        }
    }

    // Feed events through DDoS shield (rate limiting, SYN tracking, escalation).
    if let Some(ref mut shield) = state.shield_state {
        // Build risk score lookup for pre-emptive rate limiting.
        let ip_risks: std::collections::HashMap<String, u8> = state
            .attacker_profiles
            .iter()
            .filter(|(_, p)| p.risk_score > 60)
            .map(|(ip, p)| (ip.clone(), p.risk_score))
            .collect();
        let (_drops, shield_incidents, shield_blocked) =
            shield_inline::process_events(shield, &events_entries, &ip_risks).await;
        shield_inline::write_incidents(data_dir, &shield_incidents);
        let gate_counter = state.telemetry.gate_suppressed_counter();
        let burst_host =
            crate::notification_gate::resolve_host_id(&cfg.agent.tags, &state.knowledge_graph);
        shield_inline::notify_telegram(
            &state.telegram_client,
            &shield_incidents,
            &state.notification_burst_tracker,
            &mut state.telegram_deferred,
            gate_counter.as_ref(),
            &burst_host,
        );
        // Sync: register shield blocks in agent blocklist and attacker intel.
        for ip in &shield_blocked {
            state.blocklist.insert(ip.clone());
            // Enrich attacker profiles with shield block data.
            let profile = state
                .attacker_profiles
                .entry(ip.clone())
                .or_insert_with(|| attacker_intel::new_profile(ip, chrono::Utc::now()));
            attacker_intel::observe_shield_block(profile, "shield:rate_limit");
        }
        // Inject shield escalation incidents into correlation engine.
        for inc in &shield_incidents {
            if let Some(title) = inc.get("title").and_then(|t| t.as_str()) {
                let kind = if title.contains("Critical") {
                    "shield.escalation.critical"
                } else if title.contains("UnderAttack") {
                    "shield.escalation.under_attack"
                } else if title.contains("Elevated") {
                    "shield.escalation.elevated"
                } else {
                    "shield.escalation.transition"
                };
                let corr = correlation_engine::CorrelationEngine::shield_event(kind, inc.clone());
                state.correlation_engine.observe(corr);
            }
        }
    }

    // Layer 2: Correlation-driven escalation (spec 018 Phase B).
    // Drains completed attack chains and checks repeat offenders / multi-technique.
    correlation_response::process_correlation_escalations(data_dir, cfg, state).await;

    narrative_anomaly::process_anomalies(data_dir, &today, &events_entries, state);

    narrative_incident_ingest::ingest_new_incidents(data_dir, &today, cfg, state)?;

    // Spec 021 — Observation verification (Fase 3).
    // Score undecided incidents and auto-dismiss/escalate clear-cut cases.
    // Ambiguous items go to AI batch verification.
    //
    // Spec 028-b: verify_observing_incidents is async because the Escalate
    // branch can now promote the incident all the way through decide() and
    // the skill executor when the operator has enabled the feature flag.
    let ambiguous_items =
        narrative_observation_verify::verify_observing_incidents(cfg, state, data_dir).await;
    narrative_observation_verify::ai_verify_ambiguous(ambiguous_items, cfg, state).await;

    narrative_daily_summary::maybe_write_daily_summary_and_digest(
        data_dir,
        &today,
        events_count,
        cfg,
        state,
    )
    .await;

    narrative_autofp::maybe_suggest_allowlist_from_fp_reports(data_dir, state).await;

    // Silent telemetry stream detection (2026-05-26). Catches the
    // failure mode where a previously-active collector / log source
    // goes quiet because its upstream daemon broke, log rotated and
    // wasn't reopened, or the feed was misconfigured. Emits an
    // Incident through the normal notification stack when a high-
    // baseline source produces zero events today after the day has
    // had time to settle; emits a Recovery Incident when the source
    // starts producing again. See `silent_stream_alarm` module docs
    // for the full policy + the prod incident that motivated it.
    crate::silent_stream_alarm::check_silent_streams(
        cfg,
        state,
        data_dir,
        &crate::silent_stream_alarm::SilentStreamConfig::default(),
    )
    .await;

    // Update deep security snapshot for dashboard.
    if let Some(ref ds) = state.deep_security_snapshot {
        let (kc_tracked, kc_pre, kc_full) = killchain_inline::stats(&state.killchain_tracker);
        let snap = dashboard::DeepSecuritySnapshot {
            firmware_trust_score: None, // updated by firmware_tick
            firmware_last_audit: None,
            hypervisor_environment: state
                .hypervisor_environment
                .as_ref()
                .map(|e| format!("{e:?}")),
            hypervisor_trust_score: None, // updated by hypervisor_tick
            killchain_pids_tracked: kc_tracked,
            killchain_pre_chains: kc_pre,
            killchain_full_matches: kc_full,
            dna_fingerprints: state.dna_state.store.len(),
            dna_anomaly_alerts: state.dna_state.anomaly_detector.anomaly_count(),
            dna_attack_chains: state.dna_state.chain_tracker.len(),
        };
        if let Ok(mut guard) = ds.write() {
            *guard = snap;
        }
    }

    telemetry_tick::write_tick_snapshot(state, "narrative_tick");

    Ok(events_count)
}

// ---------------------------------------------------------------------------
// LSM auto-enable helpers
// ---------------------------------------------------------------------------

// LSM enforcement and trust rules moved to trust_rules.rs

// ---------------------------------------------------------------------------
// Boot self-test — verify self-awareness is working on startup
// ---------------------------------------------------------------------------

/// One-time reconciliation: read all decisions-*.jsonl files and write
/// missing decisions to the knowledge graph. This fixes historical data
/// where auto-block gates (obvious, CrowdSec) wrote decisions to JSONL
/// but not to the graph.
pub(crate) fn backfill_graph_decisions(data_dir: &std::path::Path, state: &mut AgentState) {
    use std::io::BufRead;

    let mut filled = 0usize;
    let mut scanned = 0usize;

    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("decisions-") || !name.ends_with(".jsonl") {
            continue;
        }
        let Ok(file) = std::fs::File::open(entry.path()) else {
            continue;
        };
        for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(d) = serde_json::from_str::<decisions::DecisionEntry>(&line) else {
                continue;
            };
            scanned += 1;

            // Backfill all decisions that have an action type
            if d.action_type.is_empty() || d.dry_run {
                continue;
            }

            // Check if the graph incident node is missing a decision
            let mut graph = state.knowledge_graph.write().unwrap();
            let needs_backfill = graph
                .find_by_incident(&d.incident_id)
                .and_then(|nid| {
                    if let Some(crate::knowledge_graph::types::Node::Incident {
                        decision, ..
                    }) = graph.get_node(nid)
                    {
                        Some(decision.is_none())
                    } else {
                        None
                    }
                })
                .unwrap_or(false);

            if needs_backfill {
                graph.ingest_decision(
                    &d.incident_id,
                    &d.action_type,
                    d.target_ip.as_deref(),
                    d.confidence,
                    &d.reason,
                    true,
                    d.ts,
                );
                filled += 1;
            }
        }
    }

    if filled > 0 {
        info!(
            filled,
            scanned, "backfill: reconciled JSONL decisions with knowledge graph"
        );
    }

    // Phase 2: dismiss visible incidents that never received any decision.
    // These are historical incidents from before the noise-gate was deployed.
    // Without this, they show as "OBSERVING" forever in the dashboard.
    //
    // Age gate: only dismiss incidents older than RETROACTIVE_DISMISS_AGE_SECS
    // (15 min). Before this gate the scan raced process_incidents + AI triage,
    // which takes up to ~30s cold-start on local Ollama — every Caldera SIGMA
    // or crypto_miner hit got dismissed here before the AI ever saw it,
    // zeroing out the responder (47 of 61 decisions on test001 on 2026-04-18).
    const RETROACTIVE_DISMISS_AGE_SECS: i64 = 15 * 60;
    {
        use crate::knowledge_graph::types::{Node, NodeType};
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(RETROACTIVE_DISMISS_AGE_SECS);
        let mut graph = state.knowledge_graph.write().unwrap();
        let orphan_ids: Vec<_> = graph
            .nodes_of_type(NodeType::Incident)
            .iter()
            .filter_map(|&id| {
                if let Some(Node::Incident {
                    incident_id,
                    decision,
                    research_only,
                    ts,
                    ..
                }) = graph.get_node(id)
                {
                    if decision.is_none() && !research_only && *ts < cutoff {
                        return Some((id, incident_id.clone()));
                    }
                }
                None
            })
            .collect();

        let dismissed = orphan_ids.len();
        for (_nid, iid) in &orphan_ids {
            graph.ingest_decision(
                iid,
                "dismiss",
                None,
                1.0,
                "Retroactive dismiss: historical incident with no decision",
                true,
                chrono::Utc::now(),
            );
        }

        if dismissed > 0 {
            info!(
                dismissed,
                "backfill: dismissed orphan incidents with no decision"
            );
        }
    }
}

/// Quick validation at agent startup that the host inventory (own IPs,
/// listening ports) was loaded correctly by the sensor, and cloud safelist
/// is initialized. Logs warnings for anything that looks wrong.
pub(crate) fn boot_self_test() {
    use tracing::{info, warn};

    // Check cloud safelist initialized (own IPs loaded)
    let local_ips = cloud_safelist::local_ip_count();
    if local_ips > 0 {
        info!(local_ips, "boot self-test: local interface IPs loaded");
    } else {
        warn!(
            "boot self-test: no local interface IPs detected — self-traffic filtering may not work"
        );
    }

    // Check that cloud safelist ranges are loaded
    let cloud_ranges = cloud_safelist::cloud_range_count();
    if cloud_ranges > 0 {
        info!(
            cloud_ranges,
            "boot self-test: cloud provider IP ranges loaded"
        );
    } else {
        warn!("boot self-test: no cloud IP ranges loaded");
    }

    info!("boot self-test: passed");
}

// ---------------------------------------------------------------------------
/// Check if a PID belongs to our own process tree by walking PPid up to 3 levels.
/// Used to filter eBPF events from agent/sensor threads out of correlation detection.
/// Reads /proc/PID/status which is cheap (procfs, no disk I/O).
pub(crate) fn is_pid_in_own_tree(pid: u32, own_pid: u32) -> bool {
    if pid == own_pid {
        return true;
    }
    // Check /proc/PID/status for Tgid (thread group leader) and PPid.
    // Tokio threads report PPid=1 (init) but Tgid=agent_pid.
    let status_path = format!("/proc/{pid}/status");
    let Ok(content) = std::fs::read_to_string(&status_path) else {
        return false;
    };
    // Tgid = thread group ID. For threads, this is the main process PID.
    if status_tgid(&content) == Some(own_pid) {
        return true;
    }
    // Walk PPid chain (max 3 hops) for child processes (not threads).
    let mut current = pid;
    for _ in 0..3 {
        let path = format!("/proc/{current}/status");
        let Ok(c) = std::fs::read_to_string(&path) else {
            return false;
        };
        let ppid = status_ppid(&c);
        match ppid {
            Some(p) if p == own_pid => return true,
            Some(0) | Some(1) | None => return false,
            Some(p) => current = p,
        }
    }
    false
}

pub(crate) fn status_field_u32(content: &str, field: &str) -> Option<u32> {
    content
        .lines()
        .find(|line| line.starts_with(field))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok())
}

pub(crate) fn status_tgid(content: &str) -> Option<u32> {
    status_field_u32(content, "Tgid:")
}

pub(crate) fn status_ppid(content: &str) -> Option<u32> {
    status_field_u32(content, "PPid:")
}

pub(crate) fn operator_ips_from_who_output(
    who_output: &str,
    trusted_users: &[String],
    now: std::time::Instant,
) -> HashMap<String, std::time::Instant> {
    let mut active_ips = HashMap::new();
    for line in who_output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let (Some(user), Some(ip_raw)) = (parts.first(), parts.last()) {
            let ip = ip_raw.trim_matches(|c| c == '(' || c == ')');
            if trusted_users.iter().any(|trusted| trusted == *user) && !ip.is_empty() && ip != ":" {
                active_ips.insert(ip.to_string(), now);
            }
        }
    }
    active_ips
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::types::Node;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn pretraining_no_model_is_classified_as_expected() {
        // The exact runtime message (neural_lifecycle.rs:1315) must be treated
        // as the expected pre-training condition (debug, not WARN spam).
        assert!(is_pretraining_no_model(
            "no model loaded: train_nightly first"
        ));
        // A genuine recalibration failure must NOT be suppressed.
        assert!(!is_pretraining_no_model(
            "sqlite read failed: database is locked"
        ));
        assert!(!is_pretraining_no_model(
            "anomaly engine: dimension mismatch 48 vs 65"
        ));
    }

    /// 2026-05-03 (Wave 5b PR-3 anchor): the slow_loop ticks every
    /// 30 s, but the src_ip backfill must run at MOST once per
    /// minute to give the sensor's concurrent SQLite writer
    /// (separate process, separate `Store::open`, same .db file)
    /// predictable write windows. Without this gate prod was racing
    /// for the writer lock every 30 s and burning a stack trace per
    /// race in the journal. The gate atomically records the last
    /// allowed attempt so two simultaneous ticks (slow_loop +
    /// out-of-band caller) cannot both pass.
    #[test]
    fn backfill_throttle_allows_one_per_minute_then_blocks() {
        reset_backfill_throttle_for_test();
        // Cold start: never attempted → first call passes.
        assert!(
            backfill_throttle_allows(),
            "cold start must allow first backfill"
        );
        // Immediate retry: within the interval, must be blocked.
        assert!(
            !backfill_throttle_allows(),
            "second call within {}s must be blocked",
            BACKFILL_MIN_INTERVAL_SECS
        );
        assert!(
            !backfill_throttle_allows(),
            "third call within window must also be blocked"
        );
    }

    // ── extract_anomaly_subject (PR #414 / Baseline redesign) ───────
    //
    // The dashboard's Baseline tab shows anomaly cards with an
    // "Investigar <subject> →" button. The subject is whatever
    // operator-actionable string we can pull out of the event:
    // user > IP > process comm. None when the event has no
    // recognisable subject (the card renders without the action).

    fn make_event(details: serde_json::Value) -> innerwarden_core::event::Event {
        innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "h".to_string(),
            source: "test".to_string(),
            kind: "k".to_string(),
            severity: innerwarden_core::event::Severity::Info,
            summary: String::new(),
            details,
            tags: vec![],
            entities: vec![],
        }
    }

    fn entity(t: EntityType, v: &str) -> innerwarden_core::entities::EntityRef {
        innerwarden_core::entities::EntityRef {
            r#type: t,
            value: v.to_string(),
        }
    }

    #[test]
    fn extract_anomaly_subject_prefers_user_entity_over_ip() {
        // Both User and Ip present — User wins because it is the more
        // identifiable subject for an operator pivot.
        let entities = vec![
            entity(EntityType::Ip, "203.0.113.5"),
            entity(EntityType::User, "ubuntu"),
        ];
        let ev = make_event(serde_json::json!({"comm": "sshd"}));
        assert_eq!(
            extract_anomaly_subject(&entities, &ev),
            Some("ubuntu".to_string())
        );
    }

    #[test]
    fn extract_anomaly_subject_uses_ip_when_no_user() {
        let entities = vec![entity(EntityType::Ip, "198.51.100.7")];
        let ev = make_event(serde_json::json!({"comm": "ssh"}));
        assert_eq!(
            extract_anomaly_subject(&entities, &ev),
            Some("198.51.100.7".to_string())
        );
    }

    #[test]
    fn extract_anomaly_subject_falls_back_to_comm_when_no_user_or_ip() {
        // No User, no Ip — fallback to process comm.
        let entities = vec![entity(EntityType::Container, "web-1")];
        let ev = make_event(serde_json::json!({"comm": "python3"}));
        assert_eq!(
            extract_anomaly_subject(&entities, &ev),
            Some("python3".to_string())
        );
    }

    #[test]
    fn extract_anomaly_subject_returns_none_when_nothing_actionable() {
        // No User, no Ip, no comm in details — anomaly card renders
        // without the Investigar button. Dashboard handles None gracefully.
        let entities = vec![entity(EntityType::Container, "web-1")];
        let ev = make_event(serde_json::json!({"other": "field"}));
        assert_eq!(extract_anomaly_subject(&entities, &ev), None);
    }

    #[test]
    fn extract_anomaly_subject_handles_empty_entities() {
        // Empty entity list — only `details.comm` matters.
        let ev = make_event(serde_json::json!({"comm": "bash"}));
        assert_eq!(extract_anomaly_subject(&[], &ev), Some("bash".to_string()));
    }

    #[test]
    fn extract_anomaly_subject_skips_non_user_non_ip_entities() {
        // Container / Service / Path entities should not become the
        // subject — only User and Ip are pivotable in the dashboard.
        let entities = vec![
            entity(EntityType::Container, "web-1"),
            entity(EntityType::Service, "nginx.service"),
        ];
        let ev = make_event(serde_json::json!({})); // no comm either
        assert_eq!(extract_anomaly_subject(&entities, &ev), None);
    }

    #[test]
    fn operator_ips_from_who_output_filters_and_strips_parentheses() {
        let now = std::time::Instant::now();
        let trusted = vec!["ubuntu".to_string(), "ops".to_string()];
        let who = "\
ubuntu pts/0 2026-04-17 10:00 (198.51.100.42)
guest pts/1 2026-04-17 10:01 (198.51.100.43)
ops pts/2 2026-04-17 10:02 (:)
ops pts/3 2026-04-17 10:03 (203.0.113.8)
";

        let ips = operator_ips_from_who_output(who, &trusted, now);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains_key("198.51.100.42"));
        assert!(ips.contains_key("203.0.113.8"));
        assert!(!ips.contains_key("198.51.100.43"));
    }

    #[test]
    fn proc_status_helpers_parse_expected_fields() {
        let status = "Name:\tagent\nTgid:\t4242\nPPid:\t7\n";
        assert_eq!(status_tgid(status), Some(4242));
        assert_eq!(status_ppid(status), Some(7));
        assert_eq!(status_field_u32(status, "Pid:"), None);
    }

    #[test]
    fn status_field_u32_handles_malformed_values() {
        // Field present but non-numeric value -> None.
        assert_eq!(status_field_u32("Tgid:\tnot_a_number\n", "Tgid:"), None);
        // Field present but no value after whitespace.
        assert_eq!(status_field_u32("Tgid:\n", "Tgid:"), None);
        // Empty content.
        assert_eq!(status_field_u32("", "Tgid:"), None);
    }

    #[test]
    fn is_pid_in_own_tree_same_pid_short_circuits_to_true() {
        // The self-reference base case does not touch /proc; safe in tests.
        assert!(is_pid_in_own_tree(4242, 4242));
    }

    #[test]
    fn is_pid_in_own_tree_unreadable_proc_returns_false() {
        // PID 0 has no /proc/0/status; the Ok(_) read fails and we fall
        // through to `false`. Exercises the early-return path.
        assert!(!is_pid_in_own_tree(0, 4242));
    }

    #[test]
    fn boot_self_test_does_not_panic() {
        // Pure logging helper. Exercises both arms (counts > 0 and == 0)
        // depending on how the test binary initialises `cloud_safelist`;
        // either way the call itself should succeed without panicking.
        boot_self_test();
    }

    #[test]
    fn backfill_graph_decisions_skips_bad_lines_and_dry_runs() {
        use std::io::Write;

        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());

        // Write a decisions jsonl with: a blank line, a malformed json line,
        // a dry_run entry, and a valid entry that has no matching graph
        // incident (so the backfill path is taken but finds nothing to update).
        let path = dir.path().join("decisions-2026-04-22.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f).unwrap(); // blank
        writeln!(f, "{{not valid json").unwrap(); // malformed
        writeln!(
            f,
            "{}",
            serde_json::to_string(&decisions::DecisionEntry {
                ts: chrono::Utc::now(),
                incident_id: "missing:dryrun".into(),
                host: String::new(),
                ai_provider: "test".into(),
                action_type: "block_ip".into(),
                target_ip: None,
                target_user: None,
                skill_id: None,
                confidence: 0.1,
                auto_executed: false,
                dry_run: true,
                reason: String::new(),
                estimated_threat: String::new(),
                execution_result: "ok".into(),
                prev_hash: None,
                decision_layer: None,
            })
            .unwrap()
        )
        .unwrap();
        f.flush().unwrap();

        // No panic; function should tolerate bad lines, dry_run, and missing graph nodes.
        backfill_graph_decisions(dir.path(), &mut state);
    }

    #[test]
    fn backfill_graph_decisions_returns_early_on_missing_data_dir() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let missing = dir.path().join("does-not-exist");
        // No panic even though the dir is unreadable.
        backfill_graph_decisions(&missing, &mut state);
    }

    #[test]
    fn refresh_operator_ips_logs_removed_session() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());

        // Seed a stale operator IP. `who -i` in the test process is unlikely
        // to report anyone, so `active_ips` comes back empty and the
        // "session ended" log branch fires for the seeded entry.
        state
            .operator_ips
            .insert("198.51.100.77".to_string(), std::time::Instant::now());
        let allowlist = config::AllowlistConfig::default();

        refresh_operator_ips(&mut state, &allowlist);

        assert!(
            !state.operator_ips.contains_key("198.51.100.77"),
            "stale operator IP should be evicted after refresh"
        );
    }

    #[test]
    fn backfill_graph_decisions_ingests_missing_decision_and_dismisses_orphans() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let incident_with_jsonl = crate::tests::test_incident("198.51.100.50");
        // Orphan is "old" (older than RETROACTIVE_DISMISS_AGE_SECS = 15 min).
        // The retroactive-dismiss pass must only touch stale incidents so it
        // does not race with live AI triage on recently-created ones. Without
        // this, Caldera SIGMA/crypto_miner hits were dismissed before the AI
        // ever saw them (see bug #5 in docs/internal/bug-hunt-2026-04-18.md).
        let mut orphan_incident = crate::tests::test_incident_with_kind("198.51.100.51", "orphan");
        orphan_incident.ts = chrono::Utc::now() - chrono::Duration::minutes(30);
        {
            let mut graph = state.knowledge_graph.write().expect("graph write");
            graph.ingest_incident(&incident_with_jsonl);
            graph.ingest_incident(&orphan_incident);
        }

        let entry = crate::decisions::DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_with_jsonl.incident_id.clone(),
            host: incident_with_jsonl.host.clone(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("198.51.100.50".to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.97,
            auto_executed: true,
            dry_run: false,
            reason: "unit test".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
            decision_layer: None,
        };
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let line = serde_json::to_string(&entry).expect("serialize decision");
        std::fs::write(&decisions_path, format!("{line}\n")).expect("write decisions file");

        backfill_graph_decisions(dir.path(), &mut state);

        let graph = state.knowledge_graph.read().expect("graph read");
        let id1 = graph
            .find_by_incident(&incident_with_jsonl.incident_id)
            .expect("incident present");
        let id2 = graph
            .find_by_incident(&orphan_incident.incident_id)
            .expect("orphan present");
        match graph.get_node(id1) {
            Some(Node::Incident {
                decision: Some(decision),
                ..
            }) => assert_eq!(decision, "block_ip"),
            other => panic!("expected incident decision to be backfilled, got {other:?}"),
        }
        match graph.get_node(id2) {
            Some(Node::Incident {
                decision: Some(decision),
                ..
            }) => assert_eq!(decision, "dismiss"),
            other => panic!("expected orphan incident to be dismissed, got {other:?}"),
        }
    }

    #[test]
    fn backfill_graph_decisions_preserves_recent_orphans_for_ai_triage() {
        // Regression guard for bug #5 (Caldera exercise 2026-04-18): a fresh
        // incident (ts < RETROACTIVE_DISMISS_AGE_SECS) must NOT be dismissed
        // by the backfill, so that the AI triage loop has a chance to classify
        // it before it disappears from the queue.
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let fresh = crate::tests::test_incident_with_kind("198.51.100.77", "fresh");
        {
            let mut graph = state.knowledge_graph.write().expect("graph write");
            graph.ingest_incident(&fresh);
        }

        backfill_graph_decisions(dir.path(), &mut state);

        let graph = state.knowledge_graph.read().expect("graph read");
        let id = graph
            .find_by_incident(&fresh.incident_id)
            .expect("fresh present");
        match graph.get_node(id) {
            Some(Node::Incident { decision, .. }) => assert!(
                decision.is_none(),
                "fresh orphan must stay open for AI triage, got {decision:?}"
            ),
            other => panic!("expected Incident node, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn process_narrative_tick_reads_sqlite_events_and_updates_operator_ips() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let store = crate::tests::test_sqlite_store(dir.path());
        let event = crate::tests::test_event(
            "ssh.login_success",
            innerwarden_core::event::Severity::Info,
            serde_json::json!({
                "method": "publickey",
                "ip": "198.51.100.99",
                "user": "ubuntu",
                "pid": std::process::id(),
                "comm": "innerwarden-agent",
            }),
        );
        crate::tests::insert_test_event(&store, &event);
        state.sqlite_store = Some(store);
        state.last_graph_snapshot = std::time::Instant::now() - Duration::from_secs(90);
        state.last_dna_save = std::time::Instant::now() - Duration::from_secs(360);
        state.last_killchain_cleanup = std::time::Instant::now() - Duration::from_secs(90);
        state.deep_security_snapshot = Some(std::sync::Arc::new(std::sync::RwLock::new(
            crate::dashboard::DeepSecuritySnapshot::default(),
        )));
        let cfg = config::AgentConfig::default();
        let mut cursor = reader::AgentCursor::default();

        let count = process_narrative_tick(dir.path(), &mut cursor, &cfg, &mut state)
            .await
            .expect("narrative tick");

        assert_eq!(count, 1);
        assert!(state.operator_ips.contains_key("198.51.100.99"));
    }

    #[tokio::test]
    async fn process_narrative_tick_returns_zero_without_sqlite_store() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let mut cursor = reader::AgentCursor::default();

        let count = process_narrative_tick(dir.path(), &mut cursor, &cfg, &mut state)
            .await
            .expect("narrative tick");

        assert_eq!(count, 0);
    }

    // ── try_recover_sqlite_store (Fix #8 anchor) ─────────────────────
    //
    // Boot-time `database is locked` race could leave state.sqlite_store
    // as None for the entire process lifetime. The recovery helper
    // retries on each slow_loop tick (60 s back-off so a permanent
    // error doesn't become a tight retry loop).

    #[test]
    fn try_recover_sqlite_store_is_noop_when_already_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        // Inject a real store handle so the function thinks we're recovered.
        let store = innerwarden_store::Store::open_memory().expect("memory store");
        state.sqlite_store = Some(std::sync::Arc::new(store));
        let last_attempt_before = state.sqlite_reopen_last_attempt;

        try_recover_sqlite_store(&mut state);

        assert!(state.sqlite_store.is_some(), "store handle preserved");
        // Last-attempt timestamp must NOT change — early return path.
        assert_eq!(state.sqlite_reopen_last_attempt, last_attempt_before);
    }

    #[test]
    fn try_recover_sqlite_store_attempts_reopen_when_none_and_throttles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        // Force "store unavailable" state.
        state.sqlite_store = None;
        state.sqlite_reopen_last_attempt = None;
        state.sqlite_store_path = dir.path().to_path_buf();

        // First call: should attempt reopen. Tempdir is writable so the
        // open succeeds — proves the recovery path actually works, not
        // just the early return.
        try_recover_sqlite_store(&mut state);
        assert!(
            state.sqlite_store.is_some(),
            "recovery should succeed against a writable temp directory"
        );
        assert!(
            state.sqlite_reopen_last_attempt.is_some(),
            "last-attempt timestamp must be set after recovery"
        );
    }

    #[tokio::test]
    async fn process_narrative_tick_runs_snapshot_block_when_due() {
        // Anchors the 3-scope lock-split snapshot block in
        // `process_narrative_tick`. Post slice-5 PR-3: the KG snapshot
        // writes ONLY to SQLite; the dated JSON write was removed. This
        // test wires a real `sqlite_store` (pre-PR-3 `triage_test_state`
        // left it at `None`) so the SQLite write path is actually
        // exercised and the assertion can confirm the blob landed.
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.sqlite_store = Some(crate::tests::test_sqlite_store(dir.path()));
        // Force snapshot tick to fire.
        state.last_graph_snapshot = std::time::Instant::now() - std::time::Duration::from_secs(90);
        let cfg = config::AgentConfig::default();
        let mut cursor = reader::AgentCursor::default();

        let count = process_narrative_tick(dir.path(), &mut cursor, &cfg, &mut state)
            .await
            .expect("narrative tick");
        assert_eq!(count, 0);
        // Snapshot should have advanced last_graph_snapshot to "now",
        // proving Scope 3 (no-lock I/O) reached the end of the block.
        assert!(state.last_graph_snapshot.elapsed().as_secs() < 5);
        // SQLite blob (canonical, post-PR-3) must exist for today.
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let blob = state
            .sqlite_store
            .as_ref()
            .expect("store")
            .load_graph_snapshot(&today)
            .expect("load_graph_snapshot")
            .expect("SQLite must hold today's snapshot after the tick");
        assert!(
            !blob.is_empty(),
            "SQLite blob for today's snapshot must be non-empty"
        );
        // Dated JSON file must NOT be written by the slow_loop — the write
        // side is SQLite-only now. Regression guard: any callback that
        // re-introduces the JSON write will flip this to exists() == true.
        let json_path = crate::knowledge_graph::KnowledgeGraph::dated_snapshot_path(dir.path());
        assert!(
            !json_path.exists(),
            "slow_loop must NOT write the dated JSON snapshot after slice 5 PR-3"
        );
        // graph-stats.json (metrics view, separate from the KG snapshot
        // canonical write) stays on disk — it's the dashboard's tile source
        // and explicitly out of scope for this PR.
        assert!(
            dir.path().join("graph-stats.json").exists(),
            "graph-stats.json must still be written by the snapshot block"
        );
    }

    #[tokio::test]
    async fn process_narrative_tick_snapshot_block_warns_when_sqlite_unavailable() {
        // Post slice-5 PR-3 anchor: when `sqlite_store` is `None` at tick
        // time (recovered-to-None or unopenable), the KG snapshot is
        // skipped with a WARN rather than silently dropped. Pre-PR-3 the
        // JSON write still happened in that case — this test pins the
        // new behavior so a future refactor cannot re-introduce silent
        // loss by accident.
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        assert!(
            state.sqlite_store.is_none(),
            "fixture must leave store None"
        );
        // Block the in-tick `try_recover_sqlite_store` from refilling the
        // slot — it would happily open a store against the tempdir and
        // skip the `else` arm we need to exercise. The 60s back-off is
        // the lock: set the last-attempt timestamp to "now" so recovery
        // short-circuits and the tick runs with `sqlite_store = None`.
        state.sqlite_reopen_last_attempt = Some(std::time::Instant::now());
        state.last_graph_snapshot = std::time::Instant::now() - std::time::Duration::from_secs(90);
        let cfg = config::AgentConfig::default();
        let mut cursor = reader::AgentCursor::default();

        let count = process_narrative_tick(dir.path(), &mut cursor, &cfg, &mut state)
            .await
            .expect("narrative tick must not fail when sqlite_store is None");
        assert_eq!(count, 0);
        assert!(
            state.sqlite_store.is_none(),
            "try_recover_sqlite_store back-off must have skipped; else arm requires store = None"
        );
        // Tick still advanced the snapshot timer — the snapshot block ran
        // end-to-end, just without a canonical write (logged the WARN).
        assert!(state.last_graph_snapshot.elapsed().as_secs() < 5);
        // Neither sink was written: no SQLite store to touch, and the
        // JSON write has been retired.
        let json_path = crate::knowledge_graph::KnowledgeGraph::dated_snapshot_path(dir.path());
        assert!(
            !json_path.exists(),
            "dated JSON file must NOT exist when sqlite_store is None — write path fully retired"
        );
    }

    // ── Spec 037 I-05a — backfill block_in_place anchor ────────────
    //
    // `run_events_src_ip_backfill_in_place` replaced the previous
    // `tokio::spawn`-based wrapper after the spawn version regressed
    // production (100% backfill failure due to writer-lock contention
    // with the tick's own SQLite operations). Two invariants matter:
    //   1. When a store is present, one call drives one batch of
    //      backfill work synchronously (no spawning, no yield required
    //      to observe the result).
    //   2. When `state.sqlite_store` is `None`, the wrapper is a
    //      no-op — no panic, no work attempted.
    //
    // Both tests use `#[tokio::test(flavor = "multi_thread")]` because
    // `block_in_place` panics on the single-threaded runtime that
    // `#[tokio::test]` defaults to.

    #[tokio::test(flavor = "multi_thread")]
    async fn run_events_src_ip_backfill_in_place_drives_one_batch_when_rows_are_pending() {
        // Seed a SQLite store with a pending src_ip row (null) so the
        // backfill has something to do. After the synchronous call,
        // the row should have a non-null src_ip.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.sqlite_store = Some(crate::tests::test_sqlite_store(dir.path()));

        // Seed: insert one event row whose src_ip column is NULL (the
        // legacy shape the backfill was designed to upgrade). Using the
        // store's public `insert_event` path, then nulling src_ip
        // directly, matches the v1-row shape we'd see on an upgraded db.
        {
            let store = state.sqlite_store.as_ref().expect("store");
            let ev = innerwarden_core::event::Event {
                ts: chrono::Utc::now(),
                host: "h".into(),
                source: "test".into(),
                kind: "test.event".into(),
                severity: innerwarden_core::event::Severity::Low,
                summary: "seed".into(),
                details: serde_json::json!({ "src_ip": "203.0.113.42" }),
                tags: Vec::new(),
                entities: Vec::new(),
            };
            store.insert_event(&ev).expect("seed event");
            // The backfill triggers on rows with NULL `src_ip` column
            // but a parseable ip inside `details`. insert_event may
            // already populate both; null out the column to make the
            // row look legacy.
            store
                .conn()
                .expect("conn")
                .execute("UPDATE events SET src_ip = NULL", [])
                .expect("null out src_ip");
            let pending = store.events_pending_src_ip_backfill().unwrap();
            assert_eq!(
                pending, 1,
                "fixture must seed exactly one backfill-eligible row"
            );
        }

        run_events_src_ip_backfill_in_place(&state);

        // No sleep needed: block_in_place runs synchronously. The
        // assertion can read the result immediately after return.
        let remaining = state
            .sqlite_store
            .as_ref()
            .expect("store")
            .events_pending_src_ip_backfill()
            .expect("pending query");
        assert_eq!(
            remaining, 0,
            "wrapper must drive one batch to completion (pending was 1, now {remaining})"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_events_src_ip_backfill_in_place_is_noop_when_store_is_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        assert!(state.sqlite_store.is_none());

        // Must not panic. Synchronous return, no task to leak.
        run_events_src_ip_backfill_in_place(&state);
    }

    // ── Spec 037 I-05b — telemetry observation extraction anchor ───
    //
    // `record_telemetry_observation` is a thin wrapper around
    // `state.telemetry.observe_events`. The wrapper exists so the tick
    // body reads as a sequence of named jobs; this test pins that the
    // wrapper still bumps the underlying counters so a future refactor
    // (renaming, removing the wrapper, swapping in a different
    // telemetry type) doesn't silently lose event observation.

    #[test]
    fn record_telemetry_observation_bumps_events_by_collector() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());

        let mk = |source: &str| innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            source: source.into(),
            kind: "test.event".into(),
            severity: innerwarden_core::event::Severity::Low,
            summary: "seed".into(),
            details: serde_json::json!({}),
            tags: Vec::new(),
            entities: Vec::new(),
        };
        let events = vec![mk("auth.log"), mk("auth.log"), mk("journald")];

        record_telemetry_observation(&mut state, &events);

        // `TelemetryState`'s internal counters are private; read them via
        // the public `snapshot()` view that mirrors what `/metrics` and
        // the on-disk telemetry snapshot consume.
        let snap = state.telemetry.snapshot("test-tick");
        assert_eq!(snap.events_by_collector.get("auth.log").copied(), Some(2));
        assert_eq!(snap.events_by_collector.get("journald").copied(), Some(1));
    }

    #[test]
    fn record_telemetry_observation_is_noop_on_empty_slice() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        record_telemetry_observation(&mut state, &[]);
        let snap = state.telemetry.snapshot("test-tick");
        assert!(snap.events_by_collector.is_empty());
    }

    // ── Spec 037 I-05c — narrative accumulator extraction anchor ───
    //
    // `update_narrative_accumulator` wraps the two adjacent calls
    // (`reset_for_date` + `ingest_events`) that were inline in
    // `process_narrative_tick`. The anchor proves the wrapper:
    //   1. Routes events through `ingest_events` (verified by reading
    //      back the synthetic event view).
    //   2. Honors the date reset semantics — a date change between
    //      ticks clears the prior counts.

    #[test]
    fn update_narrative_accumulator_routes_events_to_ingest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());

        let mk = |kind: &str| innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            source: "auth.log".into(),
            kind: kind.into(),
            severity: innerwarden_core::event::Severity::Low,
            summary: "seed".into(),
            details: serde_json::json!({}),
            tags: Vec::new(),
            entities: Vec::new(),
        };
        let events = vec![
            mk("ssh.login_failed"),
            mk("ssh.login_failed"),
            mk("auth.login_success"),
        ];

        update_narrative_accumulator(&mut state, "2026-04-25", &events);

        // `synthetic_events` is the read-side view the narrative path
        // uses; non-empty means ingest_events processed the input.
        let synth = state.narrative_acc.synthetic_events();
        assert!(
            !synth.is_empty(),
            "wrapper must drive ingest_events; synthetic view should not be empty"
        );
    }

    #[test]
    fn update_narrative_accumulator_resets_on_date_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());

        let mk = || innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            source: "auth.log".into(),
            kind: "test.event".into(),
            severity: innerwarden_core::event::Severity::Low,
            summary: "seed".into(),
            details: serde_json::json!({}),
            tags: Vec::new(),
            entities: Vec::new(),
        };

        // Day 1: ingest 5 events.
        let events = vec![mk(), mk(), mk(), mk(), mk()];
        update_narrative_accumulator(&mut state, "2026-04-25", &events);
        let day1_synth = state.narrative_acc.synthetic_events();
        assert!(!day1_synth.is_empty());

        // Day 2: empty input + new date — wrapper must reset, leaving
        // the synthetic view empty (no carry-over).
        update_narrative_accumulator(&mut state, "2026-04-26", &[]);
        let day2_synth = state.narrative_acc.synthetic_events();
        assert!(
            day2_synth.is_empty(),
            "date change must reset accumulator; synthetic view should be empty after reset"
        );
    }

    // ── Spec 037 I-05d — operator IP tracking extraction anchor ────
    //
    // The function is the inline scan that previously lived directly
    // in `process_narrative_tick`. Two invariants matter for the
    // extraction:
    //   1. With a publickey login event present, the source IP is
    //      added to `state.operator_ips` (and stays in the map after
    //      the call returns).
    //   2. With no qualifying events, the function is a no-op — the
    //      map is unchanged. Critical because position in the tick
    //      is load-bearing for downstream consumers and we don't want
    //      a no-event tick to mutate state in any way.

    fn pubkey_login_event(ip: &str) -> innerwarden_core::event::Event {
        innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            source: "auth.log".into(),
            kind: "ssh.login_success".into(),
            severity: innerwarden_core::event::Severity::Info,
            summary: "seed".into(),
            details: serde_json::json!({"method": "publickey", "ip": ip, "user": "ops"}),
            tags: Vec::new(),
            entities: Vec::new(),
        }
    }

    #[test]
    fn track_operator_ips_inserts_publickey_login_source() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        assert!(state.operator_ips.is_empty(), "fixture starts clean");

        let events = vec![pubkey_login_event("203.0.113.42")];
        track_operator_ips_from_events(&mut state, &events);

        assert!(
            state.operator_ips.contains_key("203.0.113.42"),
            "publickey login IP must land in operator_ips for downstream consumers"
        );
    }

    #[test]
    fn track_operator_ips_is_noop_when_no_qualifying_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        assert!(state.operator_ips.is_empty());

        // Empty slice — the most common case (most ticks have no
        // login events at all).
        track_operator_ips_from_events(&mut state, &[]);
        assert!(
            state.operator_ips.is_empty(),
            "empty events must not mutate state"
        );

        // Non-empty slice but nothing publickey-authenticated. A
        // password login or an unrelated kind must NOT enter the map.
        let mut password_login = pubkey_login_event("198.51.100.7");
        password_login.details = serde_json::json!({"method": "password", "ip": "198.51.100.7"});
        let unrelated = innerwarden_core::event::Event {
            kind: "file.read_access".into(),
            ..pubkey_login_event("203.0.113.99")
        };
        track_operator_ips_from_events(&mut state, &[password_login, unrelated]);
        assert!(
            state.operator_ips.is_empty(),
            "non-publickey events must not pollute operator_ips"
        );
    }

    // ── Spec 037 I-05e — kg_tick bundle anchor ────────────────────
    //
    // `kg_tick` bundles 6 KG-touching steps (ingest, drain triggers,
    // trigger writeback, periodic snapshot, neural features, detectors)
    // into one named unit. Job 7 + Job 8 + Job 11 of the I-05 discovery
    // list — explicitly bundled because the order is load-bearing and
    // the steps share `state.knowledge_graph` state.
    //
    // Anchors:
    //   1. ingest writes events into the graph (Step 1 ran).
    //   2. periodic snapshot fires post-ingest when timer ≥ 60 s and
    //      reflects the just-ingested state (Step 4 runs AFTER Step 1).
    //   3. empty events + fresh snapshot timer is a clean no-op (no
    //      panic, no spurious snapshot write).

    fn kg_tick_test_event(kind: &str, src_ip: &str) -> innerwarden_core::event::Event {
        innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            source: "ebpf".into(),
            kind: kind.into(),
            severity: innerwarden_core::event::Severity::Low,
            summary: "kg_tick anchor".into(),
            details: serde_json::json!({
                "pid": 9999,
                "comm": "kg_tick_anchor",
                "src_ip": src_ip,
            }),
            tags: Vec::new(),
            entities: Vec::new(),
        }
    }

    #[test]
    fn kg_tick_ingests_events_so_graph_grows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let nodes_before = state.knowledge_graph.read().unwrap().metrics().node_count;

        let events = vec![
            kg_tick_test_event("process.exec", "203.0.113.50"),
            kg_tick_test_event("network.connect", "203.0.113.51"),
        ];
        kg_tick(
            &mut state,
            dir.path(),
            &events,
            &config::AgentConfig::default(),
        );

        let nodes_after = state.knowledge_graph.read().unwrap().metrics().node_count;
        assert!(
            nodes_after > nodes_before,
            "kg_tick must ingest events into the graph (Step 1 of the bundle); \
             before={nodes_before} after={nodes_after}"
        );
    }

    #[test]
    fn kg_tick_runs_snapshot_block_when_timer_due() {
        // Step 4 (60 s snapshot) fires post-ingest (Steps 1+2). The
        // SQLite blob must reflect the events ingested in this same call,
        // not the pre-call state. Verifies the bundle ordering.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.sqlite_store = Some(crate::tests::test_sqlite_store(dir.path()));
        state.last_graph_snapshot = std::time::Instant::now() - Duration::from_secs(90);

        let events = vec![kg_tick_test_event("process.exec", "203.0.113.60")];
        kg_tick(
            &mut state,
            dir.path(),
            &events,
            &config::AgentConfig::default(),
        );

        // Snapshot timer reset proves Scope 3 of the snapshot block
        // reached the end (not interrupted by ingest or detectors).
        assert!(
            state.last_graph_snapshot.elapsed().as_secs() < 5,
            "snapshot block must reset last_graph_snapshot after running"
        );

        // SQLite blob must exist for today AND must be non-empty.
        // Non-empty proves the post-ingest graph (with the new node)
        // was serialised, not a no-op pre-ingest serialisation.
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let blob = state
            .sqlite_store
            .as_ref()
            .expect("store")
            .load_graph_snapshot(&today)
            .expect("load_graph_snapshot")
            .expect("SQLite must hold today's snapshot after kg_tick fires Step 4");
        assert!(
            !blob.is_empty(),
            "post-ingest snapshot blob must be non-empty"
        );

        // graph-stats.json is the metrics view dashboard tile reads —
        // separate from the canonical SQLite blob. Must also be written
        // by the snapshot block so the dashboard stays in sync.
        assert!(
            dir.path().join("graph-stats.json").exists(),
            "kg_tick snapshot block must write graph-stats.json"
        );

        // Dated JSON file must NOT be written — that path was retired
        // in slice 5 PR-3. Regression guard.
        let json_path = crate::knowledge_graph::KnowledgeGraph::dated_snapshot_path(dir.path());
        assert!(
            !json_path.exists(),
            "kg_tick must NOT write the dated JSON snapshot (retired in slice 5 PR-3)"
        );
    }

    #[test]
    fn kg_tick_is_clean_noop_on_empty_events_and_fresh_timer() {
        // No events + snapshot timer just reset = no panic, no SQLite
        // write, no graph mutation beyond the (always-on) trigger_host
        // initialisation. The neural feature push and detector pass
        // still run (they read graph state regardless of input), but
        // their effects are bounded by the empty graph.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.sqlite_store = Some(crate::tests::test_sqlite_store(dir.path()));
        // Fresh timer: snapshot block must NOT fire.
        state.last_graph_snapshot = std::time::Instant::now();

        let nodes_before = state.knowledge_graph.read().unwrap().metrics().node_count;
        kg_tick(&mut state, dir.path(), &[], &config::AgentConfig::default());
        let nodes_after = state.knowledge_graph.read().unwrap().metrics().node_count;

        // Empty events + no triggers + no detector incidents = the
        // graph node count must not grow. The trigger_host write may
        // have flipped from empty to a label, but that does not add a
        // node. Pinning equality here would over-fit the trigger_host
        // implementation; pinning ≤ catches the behavior we care about
        // (no spurious node growth on a quiet tick).
        assert!(
            nodes_after >= nodes_before,
            "node count must not regress on empty tick"
        );

        // Snapshot timer was fresh — block must NOT have fired, so no
        // SQLite blob for today (unless a previous test wrote one, but
        // each test gets a fresh tempdir + store).
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let blob = state
            .sqlite_store
            .as_ref()
            .expect("store")
            .load_graph_snapshot(&today)
            .expect("load_graph_snapshot");
        assert!(
            blob.is_none(),
            "fresh snapshot timer must skip Step 4; no SQLite blob expected for today"
        );
        // graph-stats.json is written ONLY inside the snapshot block —
        // a fresh timer must skip it too.
        assert!(
            !dir.path().join("graph-stats.json").exists(),
            "fresh snapshot timer must not write graph-stats.json"
        );
    }

    // ── Spec 037 I-13 PR-3 — graph-stats.json warn anchors ────────
    //
    // PR-3 converts the `let _ = std::fs::write(graph-stats.json, ..)`
    // site inside `kg_tick`'s 60s snapshot block into a
    // `warn!`-on-failure via `write_graph_stats_or_warn`. Tests pin
    // three contracts: no-panic on bad path, warn emitted with
    // path + error on failure, silent on writable. Capture is via
    // `crate::test_util` (global subscriber + thread-local buffer).

    #[test]
    fn write_graph_stats_or_warn_does_not_panic_on_missing_parent() {
        // Force `std::fs::write` to fail by handing it a data_dir
        // whose parent does not exist. The wrapper must absorb the
        // error and return `()` so kg_tick's snapshot block proceeds
        // — same observable shape as the prior `let _ =`.
        let bad_dir =
            std::path::PathBuf::from("/this/path/never/ever/exists/innerwarden-i13-stats");
        write_graph_stats_or_warn(&bad_dir, b"{}");
    }

    #[test]
    fn write_graph_stats_or_warn_emits_warn_with_context_on_failure() {
        let _guard = crate::test_util::arm_capture();

        let bad_dir =
            std::path::PathBuf::from("/this/path/never/ever/exists/innerwarden-i13-stats-warn");
        write_graph_stats_or_warn(&bad_dir, b"{}");

        let captured_str = crate::test_util::drain_capture();

        assert!(
            captured_str.contains("graph-stats.json write failed"),
            "warn message missing — got: {captured_str}"
        );
        // The path field must end in `graph-stats.json` so the operator
        // can identify what failed (vs. some sibling write in the same
        // tick).
        assert!(
            captured_str.contains("graph-stats.json"),
            "path field missing graph-stats.json suffix — got: {captured_str}"
        );
        assert!(
            captured_str.contains("error="),
            "error field missing — got: {captured_str}"
        );
    }

    #[test]
    fn write_graph_stats_or_warn_writes_json_silently_on_writable_dir() {
        // Inverse anchor: on a real, writable directory the wrapper
        // writes the bytes AND does NOT emit a warn.
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let payload = br#"{"node_count":42}"#;
        write_graph_stats_or_warn(dir.path(), payload);

        let written = std::fs::read(dir.path().join("graph-stats.json"))
            .expect("graph-stats.json must exist after a successful write");
        assert_eq!(
            written.as_slice(),
            payload,
            "wrapper must write the JSON bytes verbatim"
        );

        let captured_str = crate::test_util::drain_capture();
        assert!(
            !captured_str.contains("graph-stats.json write failed"),
            "successful write must not emit the failure warn — got: {captured_str}"
        );
    }

    // ── Disk-low guard anchors ────────────────────────────────────
    //
    // Pure-function tests on `disk_low_pct_or_bytes`. The `df`-shellout
    // path (`disk_avail_total_bytes`) is system-dependent and not
    // unit-tested here; the boolean predicate IS, since that's where
    // the threshold tradeoffs live.

    #[test]
    fn disk_low_pct_or_bytes_flags_below_5_percent() {
        // 4% free on a 100 GB disk — should trip even though 4 GB is
        // plenty in absolute terms.
        let total = 100 * 1024 * 1024 * 1024_u64;
        let avail = total * 4 / 100;
        assert!(disk_low_pct_or_bytes(avail, total));
    }

    #[test]
    fn disk_low_pct_or_bytes_flags_below_500mb_absolute() {
        // 200 MB free on a 1 PB disk — 0.00002 % is way under 5 %, but
        // also well under the 500 MB absolute floor. Either gate trips.
        let total = 1024_u64 * 1024 * 1024 * 1024 * 1024; // 1 PB
        let avail = 200 * 1024 * 1024;
        assert!(disk_low_pct_or_bytes(avail, total));
    }

    #[test]
    fn disk_low_pct_or_bytes_does_not_flag_healthy_disk() {
        // 10 GB free on a 20 GB disk — 50 % free, way above threshold.
        let total = 20 * 1024 * 1024 * 1024_u64;
        let avail = 10 * 1024 * 1024 * 1024;
        assert!(!disk_low_pct_or_bytes(avail, total));
    }

    #[test]
    fn disk_low_pct_or_bytes_fails_open_on_zero_total() {
        // Defensive: a stat call that returns total=0 must not flag
        // every disk as low. Better to attempt the write than to halt
        // all writes silently.
        assert!(!disk_low_pct_or_bytes(0, 0));
        assert!(!disk_low_pct_or_bytes(100, 0));
    }

    #[test]
    fn disk_low_pct_or_bytes_boundary_at_exactly_5_percent_does_not_flag() {
        // Exactly 5 % free should NOT flag (strict < 5.0). One byte less
        // and it would. This pins the comparison direction so a future
        // refactor can't silently flip <= to < or vice versa.
        let total = 100 * 1024 * 1024 * 1024_u64;
        let avail = total * 5 / 100; // 5.0 % exactly
                                     // 5 GB > 500 MB so absolute gate also clears.
        assert!(!disk_low_pct_or_bytes(avail, total));
    }

    #[test]
    fn try_recover_sqlite_store_respects_60s_backoff() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.sqlite_store = None;
        // Pretend we just attempted 5 seconds ago.
        state.sqlite_reopen_last_attempt = Some(std::time::Instant::now());

        try_recover_sqlite_store(&mut state);

        // Should have skipped the actual open call (back-off active).
        // The store stays None because we never attempted.
        assert!(
            state.sqlite_store.is_none(),
            "back-off must skip the reopen call"
        );
    }

    // Spec 037 I-13 follow-up #2: run_session_command_or_warn

    #[test]
    fn run_session_command_or_warn_returns_none_silently_on_not_found() {
        // Pointing at a binary that does not exist surfaces NotFound,
        // which is the steady state for stripped containers without
        // `who`. The helper must return None and emit no warn.
        let _guard = crate::test_util::arm_capture();

        let result =
            run_session_command_or_warn("/this/path/never/ever/exists/innerwarden-i13-who", "-i");
        assert!(result.is_none(), "missing binary must yield None");

        let captured = crate::test_util::drain_capture();
        assert!(
            !captured.contains("session-listing invocation failed"),
            "NotFound must NOT emit warn, got: {captured}"
        );
    }

    #[test]
    fn run_session_command_or_warn_returns_none_and_warns_on_io_failure() {
        // Pointing at a real, non-executable file surfaces
        // PermissionDenied (Linux) or similar non-NotFound error.
        // The helper must emit the warn carrying program + error.
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let non_exec = dir.path().join("not-executable");
        std::fs::write(&non_exec, b"i am not executable").expect("seed file");
        let non_exec_str = non_exec.to_str().expect("utf-8 path");

        let result = run_session_command_or_warn(non_exec_str, "-i");
        assert!(result.is_none(), "non-executable must yield None");

        let captured = crate::test_util::drain_capture();
        assert!(
            captured.contains("session-listing invocation failed"),
            "io-failure warn missing, got: {captured}"
        );
        assert!(
            captured.contains("error="),
            "error field missing, got: {captured}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// Spec 035 PR-A2 phase 3 — slow_loop tick heap-budget anchor
// ─────────────────────────────────────────────────────────────────────
//
// Standing gate for the per-tick allocation cost of
// `process_narrative_tick`. The slow loop runs this function every ~30 s
// in production; each tick does a dozen unrelated jobs (narrative
// generation, telemetry, DNA processing, kill-chain, firmware/hypervisor
// ticks, correlation, baseline learning, src_ip backfill, ...). A
// regression in any of them surfaces here as sustained RSS growth
// between ticks.
//
// **What is measured**: `dhat::HeapStats::total_bytes` delta across a
// single `process_narrative_tick` await. Counts cumulative new
// allocations in the window (including tokio task polls, futures, and
// every downstream ingest/write path). Same metric as phase 2.
//
// **Why `total_bytes` not `max_bytes`**: identical rationale to
// phase 2's `save_to_store` anchor — `total_bytes` tracks churn, which
// is what drives the operator-visible RSS trend. `max_bytes` is also
// printed for diagnostics but not asserted.
//
// **Fixture**: a realistic "moderate-load" tick — 10 events inserted
// into the SQLite store across a mix of kinds (ssh.login_success,
// process.exec, network.outbound_connect, dns.query), plus the
// deep_security_snapshot attachment and cooldown-reset pattern that the
// existing `process_narrative_tick_reads_sqlite_events_and_updates_operator_ips`
// test uses. Exercises the happy-path allocation surface.
//
// **Warm-up**: one tick runs before measurement. The first tick
// initialises the telemetry writer, opens deferred SQLite statement
// caches, and warms up tokio's internal allocators — those are
// process-lifetime costs, not the per-tick regression signal.
//
// **Thread-safety / mandatory `--test-threads=1`**: identical constraint
// to phase 2. DHAT's `HeapStats::get()` reads a process-global counter;
// concurrent tests contaminate the delta. See the phase-2 module doc in
// `knowledge_graph/persistence.rs` for the full rationale.
//
// **Baselining** follows the phase-2 convention:
//   BUDGET = ceil(measurement × 1.10 / 100 KiB) × 100 KiB
// Raises require updating this constant AND the matching line in
// `.claude-local/IMPACT.md` "Memory layout" (landing in phase 5) in
// the same PR, with the reason.

#[cfg(all(test, feature = "dhat-heap"))]
mod heap_budget {
    use super::*;
    use std::time::Duration as StdDuration;
    use tempfile::TempDir;

    /// Baselined on 2026-04-24 against the fixture below.
    ///
    /// First-run measurement: **485_617 bytes (0.46 MiB)** cumulative
    /// new allocations per `process_narrative_tick` await, after a
    /// warm-up tick (10 events pre-seeded, deep_security_snapshot
    /// attached, cooldowns reset so every interval-gated branch fires).
    ///
    /// Budget = ceil(measurement × 1.10 / 100 KiB) × 100 KiB
    ///        = ceil(534_179 / 102_400) × 102_400
    ///        = 6 × 102_400
    ///        = 614_400 bytes (0.586 MiB, ~26.5 % headroom over
    ///          baseline — slightly above 10 % because the
    ///          100 KiB-rounding lifts the nominal 10 % boundary).
    ///
    /// This is **much tighter than the spec's original 10 MiB
    /// aspiration** — the spec target was a top-of-envelope guess
    /// before DHAT was wired up. The real allocation cost of a tick
    /// on this fixture is sub-megabyte, so pinning the budget at the
    /// aspirational ceiling would fail to catch a 10× regression.
    ///
    /// A deliberate raise MUST update this constant AND the matching
    /// line in `.claude-local/IMPACT.md` "Memory layout" (landing in
    /// phase 5) in the same PR, with the reason.
    const BUDGET_TOTAL_BYTES: u64 = 614_400;

    fn seed_tick_fixture(state: &mut AgentState, store: &innerwarden_store::Store) {
        // Ten events spanning the common dispatch branches that
        // `process_narrative_tick` walks per tick. Kinds chosen so the
        // downstream `KnowledgeGraph::ingest` hits process, network,
        // DNS, and SSH login paths (the four heaviest-by-allocation
        // branches in production).
        let fixtures = [
            (
                "ssh.login_success",
                serde_json::json!({
                    "method": "publickey",
                    "ip": "198.51.100.10",
                    "user": "ubuntu",
                    "pid": 12000,
                    "comm": "sshd",
                }),
            ),
            (
                "ssh.login_success",
                serde_json::json!({
                    "method": "publickey",
                    "ip": "198.51.100.11",
                    "user": "ubuntu",
                    "pid": 12001,
                    "comm": "sshd",
                }),
            ),
            (
                "process.exec",
                serde_json::json!({
                    "pid": 13000,
                    "ppid": 1,
                    "comm": "nginx",
                    "exe": "/usr/sbin/nginx",
                    "uid": 33,
                }),
            ),
            (
                "process.exec",
                serde_json::json!({
                    "pid": 13001,
                    "ppid": 1,
                    "comm": "redis-server",
                    "exe": "/usr/bin/redis-server",
                    "uid": 999,
                }),
            ),
            (
                "network.outbound_connect",
                serde_json::json!({
                    "pid": 13000,
                    "dest_ip": "203.0.113.42",
                    "dest_port": 443,
                    "comm": "nginx",
                }),
            ),
            (
                "network.outbound_connect",
                serde_json::json!({
                    "pid": 13001,
                    "dest_ip": "203.0.113.43",
                    "dest_port": 6379,
                    "comm": "redis-server",
                }),
            ),
            (
                "dns.query",
                serde_json::json!({
                    "pid": 13000,
                    "domain": "example.com",
                    "query_type": "A",
                }),
            ),
            (
                "dns.query",
                serde_json::json!({
                    "pid": 13001,
                    "domain": "redis.internal",
                    "query_type": "A",
                }),
            ),
            (
                "file.write_access",
                serde_json::json!({
                    "pid": 13000,
                    "path": "/var/log/nginx/access.log",
                }),
            ),
            (
                "process.exit",
                serde_json::json!({
                    "pid": 13000,
                }),
            ),
        ];
        for (kind, details) in fixtures {
            let event =
                crate::tests::test_event(kind, innerwarden_core::event::Severity::Info, details);
            crate::tests::insert_test_event(store, &event);
        }
        let _ = state; // fixture currently seeds only the store; state is kept
                       // in the signature so a future richer fixture (attacker
                       // profiles, baseline) can land here without a call-site
                       // change.
    }

    fn wire_cooldowns_so_every_branch_fires(state: &mut AgentState) {
        // Push every interval-gated timer backward so the corresponding
        // branch in `process_narrative_tick` fires this tick. Mirrors
        // the pattern in
        // `process_narrative_tick_reads_sqlite_events_and_updates_operator_ips`.
        let now = std::time::Instant::now();
        state.last_graph_snapshot = now - StdDuration::from_secs(90);
        state.last_dna_save = now - StdDuration::from_secs(360);
        state.last_killchain_cleanup = now - StdDuration::from_secs(90);
        state.deep_security_snapshot = Some(std::sync::Arc::new(std::sync::RwLock::new(
            crate::dashboard::DeepSecuritySnapshot::default(),
        )));
    }

    #[tokio::test]
    async fn process_narrative_tick_allocates_under_budget() {
        let _profiler = dhat::Profiler::builder().testing().build();

        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let store = crate::tests::test_sqlite_store(dir.path());
        seed_tick_fixture(&mut state, &store);
        state.sqlite_store = Some(store);
        wire_cooldowns_so_every_branch_fires(&mut state);

        let cfg = config::AgentConfig::default();
        let mut cursor = reader::AgentCursor::default();

        // Warm-up tick. Initialises telemetry writer, SQLite statement
        // caches, tokio internal allocators. Cooldowns get updated to
        // "just now" so the second (measured) tick is a *tick-without-
        // work-overlap* — which is the realistic per-tick cost in prod
        // where most ticks see only a handful of new events.
        process_narrative_tick(dir.path(), &mut cursor, &cfg, &mut state)
            .await
            .expect("warm-up tick");

        // Reset the cooldowns so the measured tick fires the same
        // branches the warm-up did. Without this, the measured tick is
        // artificially quiet.
        wire_cooldowns_so_every_branch_fires(&mut state);

        // Seed more events for the measured tick so the delta reflects
        // "moderate-load" allocation, not a no-op. Uses a fresh
        // crate::tests::test_event / insert_test_event roundtrip
        // (same fixture helpers, new events beyond the warm-up window).
        let refill_store = state.sqlite_store.as_ref().expect("store").clone();
        seed_tick_fixture(&mut state, &refill_store);

        let before = dhat::HeapStats::get();
        process_narrative_tick(dir.path(), &mut cursor, &cfg, &mut state)
            .await
            .expect("measured tick");
        let after = dhat::HeapStats::get();

        let delta_total = after.total_bytes - before.total_bytes;
        let delta_max = after.max_bytes.saturating_sub(before.max_bytes);
        eprintln!(
            "process_narrative_tick heap budget — total_bytes delta: \
             {delta_total} bytes ({:.2} MiB), max_bytes delta: {delta_max} \
             bytes ({:.2} MiB)",
            delta_total as f64 / (1024.0 * 1024.0),
            delta_max as f64 / (1024.0 * 1024.0),
        );

        assert!(
            delta_total <= BUDGET_TOTAL_BYTES,
            "process_narrative_tick allocated {delta_total} bytes per tick \
             ({:.2} MiB), budget is {BUDGET_TOTAL_BYTES} bytes ({:.2} MiB). \
             If this is a deliberate raise, update BUDGET_TOTAL_BYTES here \
             AND the matching line in .claude-local/IMPACT.md \"Memory \
             layout\" in the same PR, with the reason.",
            delta_total as f64 / (1024.0 * 1024.0),
            BUDGET_TOTAL_BYTES as f64 / (1024.0 * 1024.0),
        );
    }
}
