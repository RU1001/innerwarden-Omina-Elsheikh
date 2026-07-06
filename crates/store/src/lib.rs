//! Unified SQLite storage backend for InnerWarden.
//!
//! Replaces JSONL files, redb, and JSON snapshots with a single
//! `innerwarden.db` SQLite database. Used by both sensor (sync)
//! and agent (async via `spawn_blocking`).
//!
//! WAL mode enables concurrent reads from agent while sensor writes.

pub mod cursors;
pub mod decisions;
pub mod error;
pub mod events;
pub mod graph;
pub mod incidents;
pub mod kv;
pub mod maintenance;
pub mod migration;
pub mod schema;
pub mod state_blobs;

use std::path::{Path, PathBuf};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tracing::info;

use crate::error::{Result, StoreError};

/// Unified storage backend backed by SQLite.
///
/// Thread-safe via r2d2 connection pool. WAL mode enables concurrent
/// reader/writer access across sensor and agent processes.
pub struct Store {
    pool: Pool<SqliteConnectionManager>,
    data_dir: PathBuf,
}

impl Store {
    /// Open or create the database at `data_dir/innerwarden.db`.
    ///
    /// Runs schema migrations if needed. Configures WAL mode and
    /// performance-oriented PRAGMAs.
    pub fn open(data_dir: &Path) -> Result<Self> {
        // Canonicalize data_dir to prevent path traversal attacks.
        let data_dir = std::fs::canonicalize(data_dir).map_err(StoreError::Io)?;
        if !data_dir.is_dir() {
            return Err(StoreError::Other("data_dir is not a directory".into()));
        }
        let db_path = data_dir.join("innerwarden.db");

        // Pre-create the DB file with group-writable permissions (0660) so that
        // both sensor (root:innerwarden) and agent (innerwarden:innerwarden) can
        // write. NOT world-readable: contains security-sensitive data (incidents,
        // decisions, attacker profiles). SQLite's internal open() uses 0644,
        // ignoring the process UMask.
        if !db_path.exists() {
            if let Ok(f) = std::fs::File::create(&db_path) {
                drop(f);
            }
        }
        // Enforce 0660 on every open, not only on first-create. Heals existing
        // deployments where SQLite or an older build left the file at 0644, and
        // re-applies after any out-of-band chmod. Fail-silent on non-unix or
        // missing file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o660));
            // SQLite WAL sidecars carry the same sensitive data.
            for sidecar in ["innerwarden.db-wal", "innerwarden.db-shm"] {
                let p = data_dir.join(sidecar);
                if p.exists() {
                    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o660));
                }
            }
        }

        // Spec 030: apply PRAGMAs via `with_init` so every pooled
        // connection (not just the first fetched) gets the same
        // runtime configuration. Without this, connections lazily
        // created after the first `pool.get()` used sqlite defaults
        // for per-connection PRAGMAs (cache_size, mmap_size,
        // temp_store, etc.) which contributed silently to the RSS
        // growth this spec targets.
        let manager = SqliteConnectionManager::file(&db_path)
            .with_init(|conn| conn.execute_batch(PRAGMA_SETUP));
        // Pool sizing 2026-05-02: bumped from 4 to 16 after a prod
        // outage (07:52-08:07 UTC) where every operation timed out
        // with `connection pool error: timed out waiting for
        // connection`. Concurrent consumers in steady state include
        // the slow-loop tick, dashboard handlers (one per HTTP
        // request), maintenance scheduler 5-min/hourly/daily tasks,
        // response_lifecycle, attacker_intel, KG snapshot writer,
        // orphan recovery sweep, and the audit hash-chain verifier.
        // Four concurrent consumers exhausts pool=4 instantly when
        // any one of them holds a conn for more than the time the
        // others can wait — and the slow-loop's KG snapshot blob
        // write CAN take seconds with a 145k-edge graph.
        //
        // `connection_timeout` is set to 5 s (down from r2d2's
        // 30 s default) so a leak surfaces fast in the log instead
        // of stalling handlers for half a minute. Callers who hit
        // the timeout already log a warn — the new short window
        // makes the leak signal emerge in seconds rather than a
        // multi-minute outage.
        //
        // **Invariant**: never hold a `Store::conn()` across an
        // `await`. The pool is sync; an `.await` while holding a
        // conn means the runtime can park the task and another
        // task can take the conn — easy fan-out into deadlock when
        // every task is waiting on the next.
        // Establish WAL mode ONCE, on a single connection, BEFORE building the
        // pool. WAL is a persistent property of the db file, so once it is set
        // the 16 pooled connections' `PRAGMA journal_mode = WAL` (in
        // PRAGMA_SETUP) is a no-op that acquires no exclusive lock. Without
        // this, `build()` opens all 16 connections at once and each races on
        // the WAL mode-change transition, which returns SQLITE_BUSY immediately
        // regardless of the `busy_timeout` set earlier in the same batch (a
        // known SQLite quirk). r2d2's default handler logs each race as
        // `ERROR ... database is locked` on every fresh start, which looks
        // alarming even though the schema-open retry below recovers. Doing it
        // once up front keeps the warm 16-connection pool AND removes the spam.
        // Best-effort: a failure here is non-fatal — the pool's own PRAGMA_SETUP
        // still sets WAL (just with the race), and the retry below recovers.
        if let Ok(conn) = r2d2_sqlite::rusqlite::Connection::open(&db_path) {
            let _ = conn.execute_batch("PRAGMA busy_timeout = 30000; PRAGMA journal_mode = WAL;");
        }

        let pool = Pool::builder()
            .max_size(16)
            .connection_timeout(std::time::Duration::from_secs(5))
            .build(manager)
            .map_err(StoreError::Pool)?;

        // Ensure the schema on one connection after the pool is up.
        // Wrapped in a small retry — even with the long `busy_timeout`
        // (PRAGMA_SETUP) as the first pragma, the FIRST `pool.get()`
        // after process startup races with the sensor's own boot-time
        // PRAGMA setup
        // (both processes set `journal_mode = WAL` at the same instant
        // when the database file is fresh-on-disk). Three attempts × 1 s
        // back-off is enough for any realistic startup race; longer
        // contention is a different problem (e.g. forgotten zombie
        // process holding an exclusive lock) and should still surface
        // as an error rather than block boot indefinitely.
        const SCHEMA_OPEN_ATTEMPTS: u32 = 3;
        const SCHEMA_OPEN_BACKOFF: std::time::Duration = std::time::Duration::from_millis(1000);
        let mut last_err: Option<StoreError> = None;
        for attempt in 1..=SCHEMA_OPEN_ATTEMPTS {
            match pool.get() {
                Ok(conn) => match schema::ensure_schema(&conn) {
                    Ok(()) => {
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                    }
                },
                Err(e) => {
                    last_err = Some(StoreError::Pool(e));
                }
            }
            if attempt < SCHEMA_OPEN_ATTEMPTS {
                std::thread::sleep(SCHEMA_OPEN_BACKOFF);
            }
        }
        if let Some(e) = last_err {
            return Err(e);
        }

        info!(path = %db_path.display(), "store opened (sqlite WAL)");

        Ok(Self { pool, data_dir })
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory() -> Result<Self> {
        let manager =
            SqliteConnectionManager::memory().with_init(|conn| conn.execute_batch(PRAGMA_SETUP));
        let pool = Pool::builder()
            .max_size(1) // memory DB is single-connection
            .build(manager)
            .map_err(StoreError::Pool)?;

        {
            let conn = pool.get().map_err(StoreError::Pool)?;
            schema::ensure_schema(&conn)?;
        }

        Ok(Self {
            pool,
            data_dir: PathBuf::from(":memory:"),
        })
    }

    /// Get a pooled connection.
    pub fn conn(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        self.pool.get().map_err(StoreError::Pool)
    }

    /// Return the data directory path.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Return the database file size in bytes (0 for in-memory).
    pub fn db_size_bytes(&self) -> Result<u64> {
        let db_path = self.data_dir.join("innerwarden.db");
        match std::fs::metadata(&db_path) {
            Ok(m) => Ok(m.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    /// Return current schema version.
    pub fn schema_version(&self) -> Result<i64> {
        let conn = self.conn()?;
        schema::schema_version(&conn)
    }
}

/// Per-connection PRAGMA script. Applied via
/// `SqliteConnectionManager::with_init` so every connection the
/// r2d2 pool creates gets the same configuration.
///
/// Spec 030 tuning (replaces the earlier `cache_size = -8000` + no
/// `mmap_size` + implicit `temp_store`):
/// - `cache_size = -2000` holds the per-connection page cache at
///   2 MB. With a pool of four, that caps the sqlite-owned page
///   cache in the agent at ~8 MB instead of the previous ~32 MB
///   (four × 8 MB). The OS page cache still serves hot pages for
///   reads, so the miss cost is negligible for our workload.
/// - `mmap_size = 0` disables sqlite's internal memory-mapped IO
///   so reads go through `read()` and the OS page cache. Without
///   this, sqlite can map hundreds of MB of the db into the
///   process address space, which inflates RSS even though the
///   data is shared with the OS cache.
/// - `temp_store = FILE` keeps temporary tables on disk instead of
///   in RAM. Our queries rarely touch temp tables (no big sorts)
///   so the disk cost is invisible; the RAM savings are real on
///   the odd large query.
// `busy_timeout` MUST be the first pragma. Setting `journal_mode = WAL`
// (or any pragma that touches the journal in WAL mode) needs to acquire a
// brief shared lock; if another process is mid-write at that instant the
// call returns SQLITE_BUSY immediately. The SQLite default `busy_timeout`
// is 0 — no wait. By setting it first we guarantee every subsequent pragma
// (and every `ensure_schema` insert) honors the wait. Pre-2026-04-23
// `journal_mode = WAL` was first; on a host where the sensor opens the
// same database concurrently with the agent, the agent's `Store::open`
// failed at boot with "database is locked" and the agent ran for the
// rest of the session without SQLite (see `RECURRING_BUGS.md` "sensor
// holds DB lock during agent boot").
//
// 30 s (was 5 s) reduces "database is locked" failures under sustained
// writer contention. Symptom on 2026-04-26: `events.src_ip` backfill
// degraded to 100 % failure rate over a few hours of uptime — every
// batch raced with a slow_loop SQLite operation (events_since, KG
// snapshot save, response_lifecycle persist) and timed out at 5 s.
// Backfill is best-effort and idempotent, so a longer wait per attempt
// trades latency for success rate without any correctness risk. The
// agent already logs `WARN ... database is locked` on legitimate
// timeouts, so a stuck connection still surfaces — it just takes
// longer to give up.
const PRAGMA_SETUP: &str = "PRAGMA busy_timeout = 30000;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA cache_size = -2000;
         PRAGMA mmap_size = 0;
         PRAGMA temp_store = 1;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA auto_vacuum = INCREMENTAL;";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_memory() {
        let store = Store::open_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), schema::CURRENT_VERSION);
    }

    /// 2026-05-02 prod outage anchor: the file-backed pool must
    /// expose enough connections to absorb concurrent slow-loop +
    /// dashboard + maintenance traffic. Pool=4 caused
    /// `connection pool error: timed out waiting for connection`
    /// across every Store call after ~50 minutes of uptime
    /// (07:52-08:07 UTC). Bumped to 16 with a 5 s acquire timeout
    /// so a future leak surfaces in seconds, not minutes.
    ///
    /// The anchor checks the pool's `state().max_size` so a future
    /// "let's drop max_size for memory" change cannot regress the
    /// outage class without a deliberate code edit + this test
    /// going red.
    #[test]
    fn file_backed_pool_carries_outage_safe_max_size() {
        use tempfile::TempDir;
        let td = TempDir::new().unwrap();
        let store = Store::open(td.path()).expect("open file-backed");
        // The invariant: max_size must comfortably exceed the
        // four-concurrent-consumer floor that exhausted the prior
        // pool. Anything below 8 risks the same outage; we ship 16.
        // The pool grows on demand, so we acquire 8 simultaneous
        // connections and assert all 8 are live — pool=4 would have
        // blocked on the 5th call (caught here as a None from
        // `try_get()` because `connection_timeout` is short).
        let mut held = Vec::new();
        for i in 0..8 {
            let conn = store
                .pool
                .try_get()
                .unwrap_or_else(|| panic!("pool blocked at connection {i}; max_size regressed"));
            held.push(conn);
        }
        assert_eq!(
            held.len(),
            8,
            "pool must hand out >= 8 simultaneous connections"
        );
    }

    #[test]
    fn fresh_store_opens_in_wal_mode_without_lock_errors() {
        // The pre-pool WAL establishment must leave a fresh db in WAL mode, so
        // the 16 pooled connections' `journal_mode = WAL` is a no-op that never
        // races (no "database is locked" ERROR spam on first start).
        use tempfile::TempDir;
        let td = TempDir::new().unwrap();
        let store = Store::open(td.path()).expect("open file-backed");
        let conn = store.pool.get().expect("get conn");
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("query journal_mode");
        assert_eq!(
            mode.to_lowercase(),
            "wal",
            "fresh store must be in WAL mode"
        );
    }

    // Spec 030: verify the tuned PRAGMAs apply to every pooled
    // connection. The earlier code path ran the PRAGMA batch on one
    // fetched connection and relied on the pool returning the same
    // one - which only held for the first `pool.get()` call. The
    // `with_init` migration guarantees all connections are
    // configured, so we assert on freshly fetched connections.
    fn read_pragma(conn: &rusqlite::Connection, name: &str) -> i64 {
        let sql = format!("PRAGMA {name}");
        conn.query_row(&sql, [], |r| r.get::<_, i64>(0))
            .unwrap_or_else(|e| panic!("PRAGMA {name} query failed: {e:?}"))
    }

    #[test]
    fn pragmas_are_set_on_every_pool_connection_memory() {
        // Memory DBs do not support mmap, so `PRAGMA mmap_size` returns
        // no row on them. Skip that assertion and focus on the
        // per-connection runtime values that do apply to in-memory.
        let store = Store::open_memory().unwrap();
        let conn = store.conn().unwrap();
        assert_eq!(read_pragma(&conn, "cache_size"), -2000);
        assert_eq!(read_pragma(&conn, "temp_store"), 1);
        assert_eq!(read_pragma(&conn, "synchronous"), 1);
    }

    #[test]
    fn pragmas_apply_to_file_pool_across_fetches() {
        use tempfile::TempDir;
        let td = TempDir::new().unwrap();
        let store = Store::open(td.path()).unwrap();

        // Cycle through a few pool fetches to exercise connections
        // beyond the first one. Each returned conn must have the
        // full spec-030 tuning applied, including mmap_size which
        // is only meaningful on file-backed databases.
        for _ in 0..8 {
            let conn = store.conn().unwrap();
            assert_eq!(read_pragma(&conn, "cache_size"), -2000);
            assert_eq!(read_pragma(&conn, "mmap_size"), 0);
            assert_eq!(read_pragma(&conn, "temp_store"), 1);
            assert_eq!(read_pragma(&conn, "synchronous"), 1);
        }
    }

    #[test]
    fn test_open_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.schema_version().unwrap(), schema::CURRENT_VERSION);
        assert!(store.db_size_bytes().unwrap() > 0);
    }

    #[test]
    fn test_reopen_preserves_schema() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _store = Store::open(dir.path()).unwrap();
        }
        // Reopen — should not fail or re-migrate
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.schema_version().unwrap(), schema::CURRENT_VERSION);
    }

    // ── PRAGMA order regression (sensor↔agent boot race anchor) ──────
    //
    // `busy_timeout` MUST be the first pragma so the rest of the batch
    // honors the 5 s wait. If a future refactor reorders the batch and
    // puts `journal_mode = WAL` first again, two concurrent processes
    // (sensor + agent) racing for the same DB at boot will reproduce
    // "database is locked" because the journal_mode pragma runs with
    // the SQLite default `busy_timeout = 0`. Pre-2026-04-23 prod
    // symptom: agent ran for hours with `state.sqlite_store = None`
    // because the boot-time `Store::open` lost the race.

    #[test]
    fn pragma_setup_starts_with_busy_timeout() {
        // The text MUST start with `PRAGMA busy_timeout`. Any other
        // pragma first reintroduces the race.
        let trimmed = PRAGMA_SETUP.trim_start();
        assert!(
            trimmed.starts_with("PRAGMA busy_timeout"),
            "PRAGMA_SETUP must set busy_timeout first; got: {}",
            &trimmed[..40.min(trimmed.len())]
        );
    }

    #[test]
    fn pragma_setup_includes_journal_mode_wal_after_busy_timeout() {
        let busy_pos = PRAGMA_SETUP
            .find("PRAGMA busy_timeout")
            .expect("busy_timeout pragma present");
        let journal_pos = PRAGMA_SETUP
            .find("PRAGMA journal_mode = WAL")
            .expect("journal_mode pragma present");
        assert!(
            busy_pos < journal_pos,
            "busy_timeout (pos {busy_pos}) must precede journal_mode (pos {journal_pos})"
        );
    }

    #[test]
    fn pragma_busy_timeout_is_active_on_freshly_pooled_connection() {
        // After `Store::open`, every connection from the pool must report
        // a non-zero `busy_timeout`. Proves the with_init batch ran before
        // any user code can call `pool.get()` — the very property that
        // the PRAGMA_SETUP order fix relies on.
        //
        // The exact value (currently 30 000 ms) is asserted via the
        // separate `pragma_setup_busy_timeout_is_at_least_30s` test below
        // so this anchor stays focused on "the pragma actually applied"
        // and doesn't churn whenever the budget is tuned.
        let store = Store::open_memory().unwrap();
        let conn = store.conn().unwrap();
        let busy = read_pragma(&conn, "busy_timeout");
        assert!(
            busy >= 5000,
            "busy_timeout must be at least 5000 ms on every connection (got {busy})"
        );
    }

    #[test]
    fn pragma_setup_busy_timeout_is_at_least_30s() {
        // Pinned to 30 s after the 2026-04-26 backfill regression: under
        // sustained writer-lock contention from concurrent slow_loop
        // SQLite operations, 5 s timed out 100 % of attempts. 30 s is the
        // value chosen to absorb that contention while still failing
        // loudly if a connection is genuinely stuck. If a future tune
        // wants to lower it, this anchor blocks the change so the
        // operational tradeoff has to be re-justified.
        let store = Store::open_memory().unwrap();
        let conn = store.conn().unwrap();
        let busy = read_pragma(&conn, "busy_timeout");
        assert!(
            busy >= 30_000,
            "busy_timeout must be at least 30 000 ms (got {busy}); see PRAGMA_SETUP comment"
        );
    }

    #[test]
    fn store_open_succeeds_when_called_twice_concurrently() {
        // Defense-in-depth: even if two processes race the journal_mode
        // pragma, the SCHEMA_OPEN_ATTEMPTS retry inside `Store::open` must
        // recover. Simulate by opening twice in rapid succession on the
        // same data directory.
        let dir = tempfile::tempdir().unwrap();
        let h1 = std::thread::spawn({
            let p = dir.path().to_path_buf();
            move || Store::open(&p)
        });
        let h2 = std::thread::spawn({
            let p = dir.path().to_path_buf();
            move || Store::open(&p)
        });
        assert!(
            h1.join().unwrap().is_ok(),
            "first concurrent open must succeed"
        );
        assert!(
            h2.join().unwrap().is_ok(),
            "second concurrent open must succeed"
        );
    }
}
