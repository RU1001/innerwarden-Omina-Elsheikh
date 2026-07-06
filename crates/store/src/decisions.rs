//! Decision audit trail with SHA-256 hash chain.
//!
//! Each decision row contains `prev_hash` (hash of previous row's `row_hash`)
//! and `row_hash` (SHA-256 of `prev_hash || data`). This enables tamper
//! detection: if any row is modified, the chain breaks.

use rusqlite::{params, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::error::{Result, StoreError};
use crate::Store;

/// One row of the audit-trail view (paginated decision history with
/// hash-chain pointers). Returned by `Store::audit_trail`. Field
/// names mirror the SQLite columns so the dashboard JSON shape is
/// stable and the consumer (compliance.rs) does not need a second
/// translation layer. `prev_hash` is `None` for the first row in the
/// chain (genesis) and for rows immediately after a documented
/// chain break (where the verifier intentionally re-anchors).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DecisionAuditRecord {
    pub id: i64,
    pub ts: String,
    pub incident_id: String,
    pub action_type: String,
    pub target_ip: Option<String>,
    pub target_user: Option<String>,
    pub confidence: Option<f64>,
    pub auto_executed: bool,
    pub reason: Option<String>,
    pub prev_hash: Option<String>,
    pub row_hash: String,
}

/// Result of hash chain verification.
#[derive(Debug, Clone)]
pub struct HashChainResult {
    /// Number of rows verified (excludes documented-break rows, which
    /// are skipped not verified).
    pub verified: u64,
    /// If the chain has an UNDOCUMENTED break, the seq at which it
    /// broke. `None` means either the chain is intact OR every
    /// break is registered in `chain_break_audit`.
    pub broken_at: Option<i64>,
    /// True iff there are no undocumented breaks. Documented breaks
    /// (rows in `chain_break_audit`) do not flip this to false —
    /// they are operationally tolerated by design.
    pub intact: bool,
    /// Count of documented breaks encountered during this scan.
    /// Purely informational. The hourly maintenance log includes
    /// this so the operator sees the audit trail's true state:
    /// "1234 verified, 0 undocumented, 4702 documented breaks".
    pub documented_breaks: u64,
}

/// A compact, publishable commitment to the decision log's current tip — the
/// "anchor". The hash chain proves the log is internally CONSISTENT, but it
/// cannot by itself detect the whole log being deleted, or rolled back to an
/// earlier state and re-grown with a fresh (internally-consistent) chain — an
/// attacker with write access can forge a clean chain from a new root. An
/// operator periodically records an anchor somewhere OUTSIDE this host (a second
/// box, a ticket, a transparency log); [`Store::verify_against_anchor`] later
/// proves the log still contains that exact committed history.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecisionAnchor {
    /// `id` of the tip (latest) decision row when the anchor was taken.
    pub seq: i64,
    /// `row_hash` of that tip row — the head of the committed chain. Because
    /// each `row_hash = SHA-256(prev_hash || data)` chains back to genesis, this
    /// single value commits to the entire prefix `[1..=seq]`.
    pub row_hash: String,
    /// Total decision rows at anchor time (informational; the strong check is
    /// `row_hash` at `seq`).
    pub count: u64,
}

/// Outcome of checking the live log against a previously-published
/// [`DecisionAnchor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum AnchorVerdict {
    /// The anchored tip row is present with the same `row_hash` — every decision
    /// committed up to the anchor is still there, unchanged (newer rows may have
    /// been appended since). No deletion or rollback.
    Intact,
    /// The anchored tip row is GONE — the log was truncated/rolled back past it,
    /// or deleted and restarted. Tamper the internal chain cannot detect.
    Truncated,
    /// The anchored tip row exists but its `row_hash` differs — the committed
    /// history was rewritten. Tamper.
    Rewritten,
}

/// One registered chain break. Returned by `Store::list_chain_breaks`
/// for audit display. Order is the order the breaks were registered.
#[derive(Debug, Clone)]
pub struct ChainBreakRecord {
    pub id: i64,
    pub rowid_start: i64,
    pub rowid_end: i64,
    pub registered_at: String,
    pub operator: String,
    pub reason: String,
    pub prev_chain_end_hash: Option<String>,
}

/// A decision entry for insertion. The store computes the hash chain
/// automatically — callers do not set `prev_hash` or `row_hash`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DecisionRow {
    pub ts: String,
    pub incident_id: String,
    pub action_type: String,
    pub target_ip: Option<String>,
    pub target_user: Option<String>,
    pub confidence: f64,
    pub auto_executed: bool,
    pub reason: Option<String>,
    /// Full JSON of the original DecisionEntry (canonical serialization).
    pub data: String,
}

/// Spec 062 Phase 4 — aggregate dismissal stats for a learned-suppression
/// shape `(detector | target_ip)`. Returned by
/// [`Store::shape_dismissal_stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShapeDismissalStats {
    /// `dismiss` decisions on this shape whose `ai_provider` is NOT in the
    /// caller's exclusion list (orphan-recovery + learned-suppression).
    pub genuine_dismissals: u64,
    /// Decisions on this shape whose `action_type` is one of the caller's
    /// "weighty" action types (block_ip / monitor / kill / ...). Any > 0
    /// means the shape must never be auto-suppressed.
    pub actioned: u64,
}

impl Store {
    /// Insert a decision with automatic hash chaining.
    ///
    /// The caller provides the canonical JSON `data` string. The store
    /// reads the last `row_hash`, computes `new_hash = SHA-256(prev_hash || data)`,
    /// and inserts the row atomically.
    pub fn insert_decision(&self, row: &DecisionRow) -> Result<i64> {
        let mut conn = self.conn()?;
        // Use a transaction to ensure atomicity of read-last-hash + insert.
        //
        // IMMEDIATE (not DEFERRED, which is the rusqlite default): the body
        // is SELECT row_hash → INSERT, i.e. a read-then-write pattern. With
        // DEFERRED, both transactions promote from SHARED to RESERVED on
        // the INSERT, and only one wins — the loser gets `SQLITE_BUSY`
        // *immediately*, bypassing `PRAGMA busy_timeout` entirely (the
        // 30 s wait does NOT apply to lock-upgrade contention, only to
        // lock acquisition at transaction start). Prod symptom (2026-05-19,
        // ~22 h after v0.14.0 install): 13 honeypot:abuseipdb_gate
        // decisions JSONL-only with `F_ERROR=sqlite error: database is
        // locked` while the JSONL audit trail was healthy. IMMEDIATE
        // grabs RESERVED up-front, so the second writer waits under
        // busy_timeout instead of dying — and parallel honeypot accepts
        // serialise cleanly instead of racing the WAL.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let prev_hash: Option<String> = tx
            .query_row(
                "SELECT row_hash FROM decisions ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .ok();

        let row_hash = compute_hash(prev_hash.as_deref(), &row.data);

        tx.execute(
            "INSERT INTO decisions
             (ts, incident_id, action_type, target_ip, target_user,
              confidence, auto_executed, reason, prev_hash, row_hash, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                row.ts,
                row.incident_id,
                row.action_type,
                row.target_ip,
                row.target_user,
                row.confidence,
                row.auto_executed as i32,
                row.reason,
                prev_hash,
                row_hash,
                row.data,
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Spec 062 Phase 4 — count repeated-dismissal stats for a
    /// learned-suppression shape `(detector | target_ip)`.
    ///
    /// `detector_prefix` is matched against `incident_id` as
    /// `"<detector_prefix>:%"` (incident ids are `detector:...`).
    ///
    /// - `genuine_dismissals`: `dismiss` decisions on this shape whose
    ///   `ai_provider` is NOT in `excluded_providers`. The exclusion list
    ///   removes the orphan-recovery silent-leak (counting it would
    ///   launder the bug spec 062 fixes into "learning") and
    ///   learned-suppression's own output (anti-loop). `ai_provider` lives
    ///   inside the JSON `data` blob, not a column, so it is excluded via
    ///   `data NOT LIKE '%"ai_provider":"<p>"%'`.
    /// - `actioned`: decisions on this shape whose `action_type` is in
    ///   `actioned_types` (block_ip / monitor / kill / ...). Any > 0 means
    ///   the shape is "weighty" and must never auto-suppress.
    ///
    /// Both are indexed `COUNT(*)` queries scoped by `target_ip`
    /// (`idx_decisions` on target via the action index + the small
    /// per-IP candidate set keep them cheap even for the hottest shapes).
    pub fn shape_dismissal_stats(
        &self,
        detector_prefix: &str,
        target_ip: &str,
        excluded_providers: &[&str],
        actioned_types: &[&str],
    ) -> Result<ShapeDismissalStats> {
        let conn = self.conn()?;
        let detector_like = format!("{detector_prefix}:%");

        // ── genuine dismissals ──────────────────────────────────────────
        let mut sql = String::from(
            "SELECT COUNT(*) FROM decisions \
             WHERE target_ip = ?1 AND incident_id LIKE ?2 AND action_type = 'dismiss'",
        );
        let mut binds: Vec<Box<dyn rusqlite::ToSql>> = vec![
            Box::new(target_ip.to_string()),
            Box::new(detector_like.clone()),
        ];
        for (i, p) in excluded_providers.iter().enumerate() {
            sql.push_str(&format!(" AND data NOT LIKE ?{}", i + 3));
            binds.push(Box::new(format!("%\"ai_provider\":\"{p}\"%")));
        }
        let genuine_dismissals: u64 = {
            let refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
            conn.query_row(&sql, refs.as_slice(), |r| r.get::<_, i64>(0))? as u64
        };

        // ── weighty (actioned) history ──────────────────────────────────
        let actioned: u64 = if actioned_types.is_empty() {
            0
        } else {
            let placeholders: Vec<String> = (0..actioned_types.len())
                .map(|i| format!("?{}", i + 3))
                .collect();
            let sql2 = format!(
                "SELECT COUNT(*) FROM decisions \
                 WHERE target_ip = ?1 AND incident_id LIKE ?2 AND action_type IN ({})",
                placeholders.join(", ")
            );
            let mut binds2: Vec<Box<dyn rusqlite::ToSql>> =
                vec![Box::new(target_ip.to_string()), Box::new(detector_like)];
            for t in actioned_types {
                binds2.push(Box::new(t.to_string()));
            }
            let refs: Vec<&dyn rusqlite::ToSql> = binds2.iter().map(|b| b.as_ref()).collect();
            conn.query_row(&sql2, refs.as_slice(), |r| r.get::<_, i64>(0))? as u64
        };

        Ok(ShapeDismissalStats {
            genuine_dismissals,
            actioned,
        })
    }

    /// Get the hash of the last decision in the chain (None if empty).
    pub fn last_decision_hash(&self) -> Result<Option<String>> {
        let conn = self.conn()?;
        let result = conn
            .query_row(
                "SELECT row_hash FROM decisions ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();
        Ok(result)
    }

    /// Verify the entire hash chain.
    ///
    /// 2026-05-01 update: rows whose id falls inside a registered
    /// `chain_break_audit` range are treated as documented breaks —
    /// the SHA mismatch is logged as a "documented break" count and
    /// the verifier continues from the row's stored hash as the new
    /// chain anchor (so post-range rows verify cleanly).
    ///
    /// `intact = false` ONLY for undocumented breaks. Documented
    /// breaks are operationally tolerated: an operator who ran a
    /// manual recovery sweep, registered the rowid range with a
    /// reason, gets no permanent hourly Telegram alert.
    ///
    /// On the first UNDOCUMENTED break the verifier returns early
    /// (existing semantics — `broken_at` is the first such row).
    /// Documented breaks before that point are still counted in
    /// `documented_breaks` so the operator can see the audit trail
    /// state at a glance.
    pub fn verify_hash_chain(&self) -> Result<HashChainResult> {
        let conn = self.conn()?;
        // Load all documented break ranges up-front. The table is
        // tiny in practice (one row per recovery sweep, expected to
        // be < 100 entries even for long-lived deployments) so an
        // in-memory Vec is the right shape.
        let mut break_stmt = conn
            .prepare("SELECT rowid_start, rowid_end FROM chain_break_audit ORDER BY rowid_start")?;
        let break_rows =
            break_stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?;
        let mut breaks: Vec<(i64, i64)> = Vec::new();
        for r in break_rows {
            breaks.push(r?);
        }
        let in_break = |id: i64| breaks.iter().any(|(s, e)| id >= *s && id <= *e);

        let mut stmt =
            conn.prepare("SELECT id, prev_hash, row_hash, data FROM decisions ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;

        let mut prev_computed: Option<String> = None;
        let mut verified: u64 = 0;
        let mut documented_breaks: u64 = 0;

        for row in rows {
            let (seq, stored_prev, stored_hash, data) = row?;

            if in_break(seq) {
                // Documented break — skip SHA verification, advance
                // the chain anchor to whatever this row stores so
                // the next legit row's prev_hash check works.
                documented_breaks += 1;
                prev_computed = Some(stored_hash);
                continue;
            }

            // Check prev_hash matches our running state
            if stored_prev != prev_computed {
                return Ok(HashChainResult {
                    verified,
                    broken_at: Some(seq),
                    intact: false,
                    documented_breaks,
                });
            }

            // Recompute hash and verify
            let expected_hash = compute_hash(prev_computed.as_deref(), &data);
            if stored_hash != expected_hash {
                return Ok(HashChainResult {
                    verified,
                    broken_at: Some(seq),
                    intact: false,
                    documented_breaks,
                });
            }

            prev_computed = Some(stored_hash);
            verified += 1;
        }

        Ok(HashChainResult {
            verified,
            broken_at: None,
            intact: true,
            documented_breaks,
        })
    }

    /// Compute a publishable [`DecisionAnchor`] over the current tip of the
    /// decision log. `None` when the log is empty (nothing to anchor). The
    /// operator records the returned anchor OUTSIDE this host; a later
    /// [`Store::verify_against_anchor`] then detects deletion/rollback that the
    /// hash chain alone cannot (a log rebuilt from a new root still verifies).
    pub fn compute_anchor(&self) -> Result<Option<DecisionAnchor>> {
        let conn = self.conn()?;
        let tip: Option<(i64, String)> = conn
            .query_row(
                "SELECT id, row_hash FROM decisions ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((seq, row_hash)) = tip else {
            return Ok(None);
        };
        let count =
            conn.query_row("SELECT COUNT(*) FROM decisions", [], |r| r.get::<_, i64>(0))? as u64;
        Ok(Some(DecisionAnchor {
            seq,
            row_hash,
            count,
        }))
    }

    /// Verify the live log against a previously-published [`DecisionAnchor`].
    /// [`AnchorVerdict::Intact`] proves the committed history is still present
    /// and unchanged; `Truncated` / `Rewritten` prove tamper that the internal
    /// chain (which a rebuilt-from-a-new-root log would still pass) cannot catch.
    pub fn verify_against_anchor(&self, anchor: &DecisionAnchor) -> Result<AnchorVerdict> {
        let conn = self.conn()?;
        let stored: Option<String> = conn
            .query_row(
                "SELECT row_hash FROM decisions WHERE id = ?1",
                params![anchor.seq],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match stored {
            None => AnchorVerdict::Truncated,
            Some(h) if h != anchor.row_hash => AnchorVerdict::Rewritten,
            Some(_) => AnchorVerdict::Intact,
        })
    }

    /// Register an intentional break in the decisions hash chain.
    ///
    /// Used after manual SQL recovery, bulk import, schema rewrite —
    /// any operation that inserts decision rows without going
    /// through `insert_decision` (which computes the chain hash).
    /// Future calls to `verify_hash_chain` skip the SHA check for
    /// rows in `[rowid_start, rowid_end]` and report them in the
    /// `documented_breaks` count instead of triggering an undocumented
    /// `broken_at` alert.
    ///
    /// Idempotent on overlapping ranges? Not by design — duplicate
    /// registrations are stored separately so the audit trail keeps
    /// each registration event. Verifier only cares whether ANY
    /// registration covers a row.
    pub fn register_chain_break(
        &self,
        rowid_start: i64,
        rowid_end: i64,
        operator: &str,
        reason: &str,
        prev_chain_end_hash: Option<&str>,
    ) -> Result<i64> {
        if rowid_end < rowid_start {
            return Err(StoreError::Other(format!(
                "invalid range: rowid_end={rowid_end} < rowid_start={rowid_start}"
            )));
        }
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO chain_break_audit \
             (rowid_start, rowid_end, registered_at, operator, reason, prev_chain_end_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                rowid_start,
                rowid_end,
                chrono::Utc::now().to_rfc3339(),
                operator,
                reason,
                prev_chain_end_hash,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// List every registered chain break. Used by audit dashboards
    /// and the integrity report so the operator can see "yes the
    /// chain has gaps but here's why each one exists".
    pub fn list_chain_breaks(&self) -> Result<Vec<ChainBreakRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, rowid_start, rowid_end, registered_at, operator, reason, \
                    prev_chain_end_hash \
             FROM chain_break_audit ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ChainBreakRecord {
                id: r.get(0)?,
                rowid_start: r.get(1)?,
                rowid_end: r.get(2)?,
                registered_at: r.get(3)?,
                operator: r.get(4)?,
                reason: r.get(5)?,
                prev_chain_end_hash: r.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Paginated audit-trail view: latest-first decision rows with
    /// the structured columns the dashboard needs (action_type,
    /// target, confidence, auto_executed flag, hash chain pointers).
    ///
    /// 2026-05-01 (audit-ui spec): the prior accessors expose only
    /// `(id, data_json)` — fine for cross-checking but the dashboard
    /// needs the typed columns broken out so it can filter / sort /
    /// render without parsing every JSON blob client-side. The query
    /// is bounded by `limit` (default 50, max 500) to keep payloads
    /// small for the operator's primary use case (browse the most
    /// recent N decisions). Older history is reachable by paging
    /// with `before_id` cursor.
    ///
    /// `before_id`: when `Some(id)`, return rows with id < before_id;
    /// when `None`, return the most recent rows. This is a cursor
    /// rather than offset because new rows arriving between pages
    /// would otherwise shift the offset and skip records.
    pub fn audit_trail(
        &self,
        before_id: Option<i64>,
        limit: usize,
        action_filter: Option<&str>,
    ) -> Result<Vec<DecisionAuditRecord>> {
        let conn = self.conn()?;
        let limit = limit.clamp(1, 500) as i64;
        let before = before_id.unwrap_or(i64::MAX);
        let action_pat = action_filter
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string());
        let sql = if action_pat.is_some() {
            "SELECT id, ts, incident_id, action_type, target_ip, target_user, \
             confidence, auto_executed, reason, prev_hash, row_hash \
             FROM decisions \
             WHERE id < ?1 AND action_type = ?3 \
             ORDER BY id DESC \
             LIMIT ?2"
        } else {
            "SELECT id, ts, incident_id, action_type, target_ip, target_user, \
             confidence, auto_executed, reason, prev_hash, row_hash \
             FROM decisions \
             WHERE id < ?1 \
             ORDER BY id DESC \
             LIMIT ?2"
        };
        let mut stmt = conn.prepare_cached(sql)?;
        let map_row = |row: &rusqlite::Row| -> rusqlite::Result<DecisionAuditRecord> {
            Ok(DecisionAuditRecord {
                id: row.get(0)?,
                ts: row.get(1)?,
                incident_id: row.get(2)?,
                action_type: row.get(3)?,
                target_ip: row.get(4)?,
                target_user: row.get(5)?,
                confidence: row.get(6)?,
                auto_executed: row.get::<_, i64>(7)? != 0,
                reason: row.get(8)?,
                prev_hash: row.get(9)?,
                row_hash: row.get(10)?,
            })
        };
        let mut results = Vec::new();
        if let Some(action) = action_pat {
            let rows = stmt.query_map(params![before, limit, action], map_row)?;
            for row in rows {
                results.push(row?);
            }
        } else {
            let rows = stmt.query_map(params![before, limit], map_row)?;
            for row in rows {
                results.push(row?);
            }
        }
        Ok(results)
    }

    /// Fetch a single decision audit record by id. Returns `None`
    /// when the id does not exist. Used by the operator override
    /// endpoint to read the original decision (its target,
    /// confidence, etc.) before chaining a follow-up override row.
    pub fn decision_by_id(&self, id: i64) -> Result<Option<DecisionAuditRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, ts, incident_id, action_type, target_ip, target_user, \
             confidence, auto_executed, reason, prev_hash, row_hash \
             FROM decisions WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(DecisionAuditRecord {
                id: row.get(0)?,
                ts: row.get(1)?,
                incident_id: row.get(2)?,
                action_type: row.get(3)?,
                target_ip: row.get(4)?,
                target_user: row.get(5)?,
                confidence: row.get(6)?,
                auto_executed: row.get::<_, i64>(7)? != 0,
                reason: row.get(8)?,
                prev_hash: row.get(9)?,
                row_hash: row.get(10)?,
            }));
        }
        Ok(None)
    }

    /// Read decisions with id > `after_id`, up to `limit`.
    pub fn decisions_since(&self, after_id: i64, limit: usize) -> Result<Vec<(i64, String)>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare_cached("SELECT id, data FROM decisions WHERE id > ?1 ORDER BY id LIMIT ?2")?;
        let rows = stmt.query_map(params![after_id, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Read all decisions for a given incident_id.
    pub fn decisions_for_incident(&self, incident_id: &str) -> Result<Vec<String>> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare_cached("SELECT data FROM decisions WHERE incident_id = ?1 ORDER BY id")?;
        let rows = stmt.query_map(params![incident_id], |row| row.get::<_, String>(0))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Cheap existence check: is there ANY decision row in the table
    /// for this `incident_id`? Returns `true` after the first match.
    ///
    /// 2026-05-08 (fix/inline-decision-vs-ai-router-race): the agent
    /// has multiple parallel decision writers for kill_chain incidents.
    /// `killchain_inline::dismiss_self_traffic_incidents` writes a
    /// `dismiss` decision synchronously when the sensor's killchain
    /// stream reports a 2-bit chain on a known operator/system tool.
    /// The agent's main triage loop reads incidents-*.jsonl on a 2s
    /// poll cadence, runs the AI router on the same incident, and
    /// writes a SECOND decision (often `block_ip`) milliseconds to
    /// seconds later.
    ///
    /// Operator-visible: a `kill_chain DATA_EXFIL` incident would land
    /// a `dismiss` row from `self-traffic-fp` AND a `block_ip` row from
    /// `local_classifier` for the same `incident_id`, making the
    /// dashboard report the IP as both "auto-dismissed" and "auto-
    /// blocked". Operator's prod 2026-05-08 had this exact shape on
    /// 20.26.156.215 (Microsoft Azure UK / git-fetch FP).
    ///
    /// The fix: `evaluate_pre_ai_flow` calls this helper at the top of
    /// the gate. If a decision already exists for the incident_id, the
    /// AI router is skipped — the inline path's verdict stands. Indexed
    /// by `idx_decisions_incident` so the lookup is O(log N).
    pub fn has_decision_for_incident(&self, incident_id: &str) -> Result<bool> {
        let conn = self.conn()?;
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM decisions WHERE incident_id = ?1 LIMIT 1",
                params![incident_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(exists.is_some())
    }

    /// Count total decisions.
    pub fn decisions_count(&self) -> Result<u64> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM decisions", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Spec 049 PR20 — return EVERY decision whose `ts` falls on the
    /// given UTC date (action_type is NOT filtered), in
    /// `(ts_iso, incident_id, data_json)` form, ordered by id ascending.
    ///
    /// Used by the dashboard's `compute_incidents_blocking` to fold in
    /// decisions from the Wave-10b non-incident-pipeline prefixes
    /// (`honeypot:always-on:abuseipdb:`, `repeat-offender:`,
    /// `proto_anomaly:` direct, etc.). Those paths emit a decision
    /// without ever creating a sensor incident row; reading them via
    /// this helper lets the operator-visible audit trail surface
    /// every action regardless of which path emitted it.
    pub fn decisions_for_date(
        &self,
        date: &str,
        limit: usize,
    ) -> Result<Vec<(String, String, String)>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare_cached(
            "SELECT ts, incident_id, data \
             FROM decisions \
             WHERE ts LIKE ?1 \
             ORDER BY id \
             LIMIT ?2",
        )?;
        let pattern = format!("{date}%");
        let rows = stmt.query_map(params![pattern, limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Return `block_ip` decisions whose `ts` falls on the given UTC date,
    /// in `(ts_iso, target_ip, incident_id, data_json)` form, ordered by
    /// id ascending so the caller sees them in append order.
    ///
    /// This replaces the legacy `decisions-YYYY-MM-DD.jsonl` reconciler
    /// path (RC-2 surface): the JSONL was a parallel write target whose
    /// schema, ordering, and date convention drifted from the SQLite
    /// canonical path. Boot-time reconcilers now consume this helper.
    pub fn block_ip_decisions_for_date(
        &self,
        date: &str,
    ) -> Result<Vec<(String, String, String, String)>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare_cached(
            "SELECT ts, target_ip, incident_id, data \
             FROM decisions \
             WHERE action_type = 'block_ip' AND ts LIKE ?1 \
             ORDER BY id",
        )?;
        let pattern = format!("{date}%");
        let rows = stmt.query_map(params![pattern], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (ts, ip, iid, data) = row?;
            // Keep rows even when target_ip is empty so the caller can
            // surface a warning; the legacy JSONL reconciler used a
            // similar guard (`continue` when missing) and the test
            // anchors expect that semantic.
            out.push((ts, ip, iid, data));
        }
        Ok(out)
    }
}

/// Compute SHA-256 hash for hash chain: `SHA-256(prev_hash || data)`.
fn compute_hash(prev_hash: Option<&str>, data: &str) -> String {
    let mut hasher = Sha256::new();
    if let Some(ph) = prev_hash {
        hasher.update(ph.as_bytes());
    }
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_decision(incident: &str, action: &str) -> DecisionRow {
        let data = serde_json::json!({
            "ts": "2026-04-12T10:00:00Z",
            "incident_id": incident,
            "action_type": action,
            "confidence": 0.95,
            "auto_executed": true,
            "reason": "test decision",
        });
        DecisionRow {
            ts: "2026-04-12T10:00:00Z".into(),
            incident_id: incident.into(),
            action_type: action.into(),
            target_ip: Some("1.2.3.4".into()),
            target_user: None,
            confidence: 0.95,
            auto_executed: true,
            reason: Some("test decision".into()),
            data: serde_json::to_string(&data).unwrap(),
        }
    }

    #[test]
    fn test_insert_and_chain() {
        let store = Store::open_memory().unwrap();

        let id1 = store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        let id2 = store
            .insert_decision(&sample_decision("inc-2", "ignore"))
            .unwrap();
        let id3 = store
            .insert_decision(&sample_decision("inc-3", "monitor"))
            .unwrap();

        assert!(id3 > id2);
        assert!(id2 > id1);
        assert_eq!(store.decisions_count().unwrap(), 3);

        // Hash chain should be intact
        let result = store.verify_hash_chain().unwrap();
        assert!(result.intact);
        assert_eq!(result.verified, 3);
        assert!(result.broken_at.is_none());
    }

    #[test]
    fn test_chain_detects_tampering() {
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        store
            .insert_decision(&sample_decision("inc-2", "ignore"))
            .unwrap();

        // Tamper with the first row's data
        {
            let conn = store.conn().unwrap();
            conn.execute("UPDATE decisions SET data = 'tampered' WHERE id = 1", [])
                .unwrap();
        }

        let result = store.verify_hash_chain().unwrap();
        assert!(!result.intact);
        assert_eq!(result.broken_at, Some(1));
    }

    #[test]
    fn test_last_hash() {
        let store = Store::open_memory().unwrap();
        assert!(store.last_decision_hash().unwrap().is_none());

        store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        let hash = store.last_decision_hash().unwrap();
        assert!(hash.is_some());
        assert_eq!(hash.unwrap().len(), 64); // SHA-256 hex
    }

    // Helper: simulate a manual SQL break by inserting a decision
    // row directly with a non-canonical row_hash (mirrors the
    // `manual-orphan-recovery-2026-04-29` operation that prompted
    // this whole feature).
    fn insert_manual_decision(store: &Store, incident: &str, sentinel_hash: &str) -> i64 {
        let conn = store.conn().unwrap();
        let data = serde_json::json!({
            "ai_provider": "manual-test",
            "incident_id": incident,
            "action_type": "dismiss",
            "ts": chrono::Utc::now().to_rfc3339(),
        });
        conn.execute(
            "INSERT INTO decisions \
             (ts, incident_id, action_type, target_ip, target_user, confidence, \
              auto_executed, reason, prev_hash, row_hash, data) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                chrono::Utc::now().to_rfc3339(),
                incident,
                "dismiss",
                Option::<String>::None,
                Option::<String>::None,
                1.0,
                1,
                "test manual",
                Option::<String>::None,
                sentinel_hash,
                data.to_string(),
            ],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn verify_hash_chain_flags_undocumented_break_as_intact_false() {
        // Pre-existing semantic: a row with mismatched row_hash that
        // is NOT in chain_break_audit must produce `intact=false`
        // and `broken_at=Some(rowid)`.
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-clean", "block_ip"))
            .unwrap();
        let bad_id = insert_manual_decision(&store, "inc-bad", "sentinel-bad");
        let chain = store.verify_hash_chain().unwrap();
        assert!(
            !chain.intact,
            "undocumented manual insert must mark chain not-intact"
        );
        assert_eq!(chain.broken_at, Some(bad_id));
        assert_eq!(chain.documented_breaks, 0);
    }

    #[test]
    fn verify_hash_chain_skips_documented_break_range() {
        // After registering the broken rowid range in
        // chain_break_audit, the verifier reports `intact=true` and
        // counts the break in `documented_breaks` instead of firing
        // an `intact=false` alert. This is the exact prod scenario
        // that prompted the feature: 4702 rows of manual orphan
        // recovery sweep on 2026-04-29 17:26 UTC.
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-clean", "block_ip"))
            .unwrap();
        let bad_id = insert_manual_decision(&store, "inc-bad", "sentinel-bad");
        let extra_bad = insert_manual_decision(&store, "inc-bad-2", "sentinel-bad-2");
        store
            .register_chain_break(
                bad_id,
                extra_bad,
                "test-operator",
                "manual recovery sweep — verifier should skip these rows",
                Some("last-good-hash"),
            )
            .unwrap();
        let chain = store.verify_hash_chain().unwrap();
        assert!(
            chain.intact,
            "documented breaks must NOT mark the chain as not-intact"
        );
        assert_eq!(chain.broken_at, None);
        assert_eq!(chain.documented_breaks, 2);
    }

    #[test]
    fn verify_hash_chain_resumes_after_documented_break() {
        // The verifier must continue verifying rows AFTER a
        // documented break range. A new legit insert post-range goes
        // through `insert_decision` which reads the LAST row's
        // row_hash as prev_hash — so its chain link points back to
        // the sentinel. The verifier, when it skips the documented
        // break, sets `prev_computed = stored_hash` (the sentinel)
        // so the next legit row's prev_hash check succeeds.
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-clean", "block_ip"))
            .unwrap();
        let bad_id = insert_manual_decision(&store, "inc-bad", "sentinel-bad");
        store
            .register_chain_break(
                bad_id,
                bad_id,
                "test-operator",
                "single-row manual insert",
                None,
            )
            .unwrap();
        // Now a legit insert: should chain off the sentinel hash.
        store
            .insert_decision(&sample_decision("inc-clean-2", "monitor"))
            .unwrap();
        let chain = store.verify_hash_chain().unwrap();
        assert!(chain.intact);
        assert_eq!(chain.documented_breaks, 1);
        // 2 legit rows verified (the first and the third); the
        // middle is documented.
        assert_eq!(chain.verified, 2);
    }

    #[test]
    fn verify_hash_chain_undocumented_break_after_documented_still_alerts() {
        // Documented break covers rows 2..3. Row 4 is ALSO a
        // manual insert but not registered. Verifier must report
        // `broken_at=4`, NOT swallow it because earlier breaks
        // were documented.
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-clean", "block_ip"))
            .unwrap();
        let bad_id = insert_manual_decision(&store, "inc-bad", "sentinel-1");
        let _bad_id2 = insert_manual_decision(&store, "inc-bad", "sentinel-2");
        let undoc = insert_manual_decision(&store, "inc-undoc", "sentinel-undoc");
        store
            .register_chain_break(bad_id, bad_id + 1, "test-op", "documented", None)
            .unwrap();
        let chain = store.verify_hash_chain().unwrap();
        assert!(
            !chain.intact,
            "undocumented break after documented must alert"
        );
        assert_eq!(chain.broken_at, Some(undoc));
        assert_eq!(chain.documented_breaks, 2);
    }

    #[test]
    fn register_chain_break_rejects_inverted_range() {
        let store = Store::open_memory().unwrap();
        let err = store
            .register_chain_break(100, 50, "op", "test", None)
            .unwrap_err();
        match err {
            StoreError::Other(msg) => assert!(msg.contains("invalid range")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn list_chain_breaks_returns_registered_records() {
        let store = Store::open_memory().unwrap();
        store
            .register_chain_break(100, 200, "op-a", "first sweep", None)
            .unwrap();
        store
            .register_chain_break(500, 502, "op-b", "second sweep", Some("hash-x"))
            .unwrap();
        let records = store.list_chain_breaks().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].operator, "op-a");
        assert_eq!(records[0].rowid_start, 100);
        assert_eq!(records[0].rowid_end, 200);
        assert_eq!(records[1].reason, "second sweep");
        assert_eq!(records[1].prev_chain_end_hash.as_deref(), Some("hash-x"));
    }

    #[test]
    fn test_audit_trail_returns_latest_first_with_hash_pointers() {
        // Anchors the dashboard audit-trail viewer (audit finding 5.7).
        // The viewer's primary use case is "operator wants to see
        // the most recent N decisions with hash chain pointers";
        // this test pins:
        //   - default ordering is latest-first (by id desc)
        //   - the typed columns are returned (action_type, target_ip,
        //     auto_executed, confidence) and not just the JSON blob
        //   - prev_hash and row_hash are populated and chain
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        store
            .insert_decision(&sample_decision("inc-2", "monitor"))
            .unwrap();
        store
            .insert_decision(&sample_decision("inc-3", "dismiss"))
            .unwrap();

        let rows = store.audit_trail(None, 50, None).unwrap();
        assert_eq!(rows.len(), 3, "all three decisions returned");
        // Latest-first: dismiss (id=3) before monitor (id=2) before block_ip (id=1)
        assert_eq!(rows[0].action_type, "dismiss");
        assert_eq!(rows[1].action_type, "monitor");
        assert_eq!(rows[2].action_type, "block_ip");
        // Typed columns surface, not just JSON blob.
        assert_eq!(rows[0].target_ip.as_deref(), Some("1.2.3.4"));
        assert!(rows[0].auto_executed);
        assert_eq!(rows[0].confidence, Some(0.95));
        // Hash chain populated: row N's prev_hash == row N+1's row_hash
        // (rows are returned latest-first, so the chain links go
        // "older row's row_hash" == "newer row's prev_hash").
        assert!(!rows[0].row_hash.is_empty());
        assert_eq!(
            rows[0].prev_hash.as_deref(),
            Some(rows[1].row_hash.as_str())
        );
        assert_eq!(
            rows[1].prev_hash.as_deref(),
            Some(rows[2].row_hash.as_str())
        );
        // First-ever row has no predecessor (genesis).
        assert!(rows[2].prev_hash.is_none());
    }

    #[test]
    fn test_audit_trail_paginates_via_before_id_cursor() {
        // Cursor pagination invariant: a "next page" request with
        // the last-seen id returns ONLY rows older than that id.
        // Anchored separately so a refactor that switches to offset
        // pagination is caught (offsets shift if new rows arrive
        // between page loads, the failure mode this test prevents).
        let store = Store::open_memory().unwrap();
        for i in 0..7 {
            store
                .insert_decision(&sample_decision(&format!("inc-{i}"), "block_ip"))
                .unwrap();
        }
        let page1 = store.audit_trail(None, 3, None).unwrap();
        assert_eq!(page1.len(), 3);
        assert_eq!(page1[0].id, 7); // latest
        let cursor = page1.last().unwrap().id;
        let page2 = store.audit_trail(Some(cursor), 3, None).unwrap();
        assert_eq!(page2.len(), 3);
        // page2[0] must be id=4 (cursor was 5; we want ids < 5)
        assert_eq!(page2[0].id, 4);
        assert!(
            page2.iter().all(|r| r.id < cursor),
            "cursor invariant: every page-2 row has id < cursor"
        );
    }

    #[test]
    fn test_audit_trail_filters_by_action_type() {
        // The viewer's filter dropdown must produce a server-side
        // restriction, not a client-side filter on already-fetched
        // rows (the latter would skip relevant matches in older
        // pages). Anchor the SQL filter path.
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        store
            .insert_decision(&sample_decision("inc-2", "monitor"))
            .unwrap();
        store
            .insert_decision(&sample_decision("inc-3", "block_ip"))
            .unwrap();
        store
            .insert_decision(&sample_decision("inc-4", "dismiss"))
            .unwrap();
        let blocks = store.audit_trail(None, 50, Some("block_ip")).unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().all(|r| r.action_type == "block_ip"));
        let dismisses = store.audit_trail(None, 50, Some("dismiss")).unwrap();
        assert_eq!(dismisses.len(), 1);
        // Empty filter is treated as no filter (matches the
        // dashboard's "all actions" option which sends "").
        let all = store.audit_trail(None, 50, Some("")).unwrap();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn test_decision_by_id_returns_typed_record_or_none() {
        // Anchors the operator-override path (`tracked-spec-ai-override`):
        // the override endpoint reads the original decision via this
        // accessor before chaining a follow-up row. The accessor must:
        //   - return a typed DecisionAuditRecord (typed columns, not
        //     just the JSON blob — the override builder needs
        //     incident_id, target_ip, action_type, row_hash)
        //   - return None for unknown ids (operator typo / stale UI)
        let store = Store::open_memory().unwrap();
        let id = store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        let r = store.decision_by_id(id).unwrap().expect("found");
        assert_eq!(r.id, id);
        assert_eq!(r.incident_id, "inc-1");
        assert_eq!(r.action_type, "block_ip");
        assert_eq!(r.target_ip.as_deref(), Some("1.2.3.4"));
        assert!(!r.row_hash.is_empty());
        assert!(store.decision_by_id(99_999).unwrap().is_none());
    }

    #[test]
    fn test_audit_trail_clamps_limit() {
        // Defensive: a misconfigured client must not be able to
        // pull the whole table on a refresh loop. limit clamps at
        // 500 even if the caller passes a huge value (and at 1
        // even if 0).
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        // Lower bound: limit=0 should not panic; min is 1.
        let zero = store.audit_trail(None, 0, None).unwrap();
        assert_eq!(zero.len(), 1, "limit=0 clamped to 1");
        // Upper bound: limit=10000 should clamp to 500. With only 1
        // row inserted we cannot directly observe the cap, but the
        // call must not error.
        let huge = store.audit_trail(None, 10_000, None).unwrap();
        assert_eq!(huge.len(), 1);
    }

    #[test]
    fn test_decisions_for_incident() {
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        store
            .insert_decision(&sample_decision("inc-1", "monitor"))
            .unwrap();
        store
            .insert_decision(&sample_decision("inc-2", "ignore"))
            .unwrap();

        let for_inc1 = store.decisions_for_incident("inc-1").unwrap();
        assert_eq!(for_inc1.len(), 2);

        let for_inc2 = store.decisions_for_incident("inc-2").unwrap();
        assert_eq!(for_inc2.len(), 1);
    }

    /// 2026-05-08 anchor (fix/inline-decision-vs-ai-router-race):
    /// `has_decision_for_incident` is the gate that prevents a second
    /// decision-writer (the AI router) from racing the inline killchain
    /// dismiss path. Pre-fix, two decision rows for the same incident_id
    /// would land — `dismiss` from `self-traffic-fp` and `block_ip` from
    /// `local_classifier` — and the dashboard's Profiles tab credited
    /// the second row to the IP, surfacing operator self-traffic
    /// (Microsoft Azure UK / git-fetch) as a "high-risk attacker". The
    /// gate's contract is: `true` after ANY prior decision row for the
    /// `incident_id`. This anchor pins both arms of that contract — a
    /// single dismiss must be enough to short-circuit the AI router,
    /// AND a previously-unseen incident_id must cleanly return false.
    #[test]
    fn has_decision_for_incident_returns_true_after_first_row_for_id() {
        let store = Store::open_memory().unwrap();

        // Cold path: no prior decisions → must return false.
        assert!(
            !store.has_decision_for_incident("inc-fresh").unwrap(),
            "missing incident_id must return false (cheap-exit)"
        );

        // Single dismiss landed: must return true even though it's not
        // a block. The contract is "any decision wins" — the gate does
        // not need to inspect action_type.
        store
            .insert_decision(&sample_decision("inc-killchain", "dismiss"))
            .unwrap();
        assert!(
            store.has_decision_for_incident("inc-killchain").unwrap(),
            "first dismiss must short-circuit the AI router race"
        );

        // Different incident_id stays uncovered — anti-regression for
        // accidentally globbing the LIKE pattern.
        assert!(
            !store
                .has_decision_for_incident("inc-killchain-other")
                .unwrap(),
            "different incident_id must not match"
        );

        // Multiple rows for the same incident_id keep returning true
        // (idempotent — the gate doesn't need to count).
        store
            .insert_decision(&sample_decision("inc-killchain", "block_ip"))
            .unwrap();
        assert!(
            store.has_decision_for_incident("inc-killchain").unwrap(),
            "two rows must still report true"
        );
    }

    /// 2026-05-19 prod-bug anchor (fix/sqlite-mirror-lock-race): the
    /// always-on honeypot AbuseIPDB gate path lost 13 decisions from
    /// SQLite over 22 h post v0.14.0 install. Root cause: `insert_decision`
    /// used `BEGIN DEFERRED` (rusqlite default), so when two concurrent
    /// honeypot accepts both ran `SELECT row_hash → INSERT decisions`,
    /// both acquired SHARED on the read, then BOTH tried to upgrade to
    /// RESERVED on the INSERT. One won; the other got `SQLITE_BUSY`
    /// IMMEDIATELY — `PRAGMA busy_timeout = 30000` does NOT apply to
    /// lock upgrades, only to lock acquisition at transaction start.
    /// JSONL had the row; SQLite did not.
    ///
    /// Fix: `BEGIN IMMEDIATE` grabs RESERVED at transaction start.
    /// Concurrent writers then queue under `busy_timeout` instead of
    /// dying. This test reproduces the prod call pattern (parallel
    /// inserts from threads sharing one file-backed `Store`) and
    /// asserts every insert succeeds and every row lands. The same
    /// test against the pre-fix code (DEFERRED) flakes within a few
    /// runs with "database is locked"; against IMMEDIATE it is stable
    /// for any thread count up to the pool size.
    #[test]
    fn concurrent_insert_decision_does_not_deadlock_under_immediate_tx() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(Store::open(dir.path()).expect("open file-backed store"));

        const THREADS: usize = 6;
        const PER_THREAD: usize = 10;

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let store = Arc::clone(&store);
                thread::spawn(move || -> Result<()> {
                    for i in 0..PER_THREAD {
                        store
                            .insert_decision(&sample_decision(
                                &format!("inc-thread-{t}-{i}"),
                                "block_ip",
                            ))
                            .map_err(|e| {
                                // Surface the actual SQLite error in the
                                // panic message — without this, a flake
                                // shows as a generic JoinError.
                                StoreError::Other(format!("thread {t} iter {i}: {e}"))
                            })?;
                    }
                    Ok(())
                })
            })
            .collect();

        for h in handles {
            h.join()
                .expect("thread did not panic")
                .expect("every concurrent insert must succeed under IMMEDIATE + busy_timeout");
        }

        // Cross-check: total row count matches the expected fan-in.
        let conn = store.conn().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM decisions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count as usize, THREADS * PER_THREAD);

        // The hash chain must verify cleanly across the concurrent
        // insertions — IMMEDIATE serialises the read-prev-hash + insert,
        // so the chain is contiguous despite the threading.
        let result = store.verify_hash_chain().expect("verify chain");
        assert!(
            result.intact,
            "hash chain must remain intact across concurrent IMMEDIATE inserts; broken_at = {:?}",
            result.broken_at
        );
    }

    // ── shape_dismissal_stats (spec 062 Phase 4) ────────────────────────

    fn seed_shape(store: &Store, incident_id: &str, ip: &str, action: &str, provider: &str) {
        let data = serde_json::json!({ "ai_provider": provider }).to_string();
        store
            .insert_decision(&DecisionRow {
                ts: "2026-05-30T00:00:00Z".to_string(),
                incident_id: incident_id.to_string(),
                action_type: action.to_string(),
                target_ip: Some(ip.to_string()),
                target_user: None,
                confidence: 1.0,
                auto_executed: true,
                reason: None,
                data,
            })
            .unwrap();
    }

    const EXCL: &[&str] = &["orphan-recovery", "learned-suppression"];
    const ACTED: &[&str] = &["block_ip", "monitor", "kill_process"];

    #[test]
    fn shape_dismissal_stats_counts_genuine_dismissals() {
        let store = Store::open_memory().unwrap();
        let ip = "169.254.169.254";
        for i in 0..7 {
            seed_shape(
                &store,
                &format!("imds_ssrf:{ip}:{i}"),
                ip,
                "dismiss",
                "noise-gate",
            );
        }
        let s = store
            .shape_dismissal_stats("imds_ssrf", ip, EXCL, ACTED)
            .unwrap();
        assert_eq!(s.genuine_dismissals, 7);
        assert_eq!(s.actioned, 0);
    }

    #[test]
    fn shape_dismissal_stats_excludes_orphan_recovery_and_self() {
        let store = Store::open_memory().unwrap();
        let ip = "169.254.169.254";
        seed_shape(&store, "imds_ssrf:x:1", ip, "dismiss", "noise-gate");
        seed_shape(&store, "imds_ssrf:x:2", ip, "dismiss", "orphan-recovery");
        seed_shape(
            &store,
            "imds_ssrf:x:3",
            ip,
            "dismiss",
            "learned-suppression",
        );
        let s = store
            .shape_dismissal_stats("imds_ssrf", ip, EXCL, ACTED)
            .unwrap();
        // Only the noise-gate dismissal counts; leak + own output excluded.
        assert_eq!(s.genuine_dismissals, 1);
    }

    #[test]
    fn shape_dismissal_stats_counts_actioned_history() {
        let store = Store::open_memory().unwrap();
        let ip = "203.0.113.5";
        seed_shape(&store, "port_scan:x:1", ip, "dismiss", "noise-gate");
        seed_shape(&store, "port_scan:x:2", ip, "block_ip", "manual");
        seed_shape(&store, "port_scan:x:3", ip, "monitor", "manual");
        let s = store
            .shape_dismissal_stats("port_scan", ip, EXCL, ACTED)
            .unwrap();
        assert_eq!(s.genuine_dismissals, 1);
        assert_eq!(s.actioned, 2);
    }

    #[test]
    fn shape_dismissal_stats_scopes_by_detector_and_ip() {
        let store = Store::open_memory().unwrap();
        let ip = "169.254.169.254";
        seed_shape(&store, "imds_ssrf:x:1", ip, "dismiss", "noise-gate");
        // Same IP, different detector — must NOT count for imds_ssrf.
        seed_shape(&store, "reverse_shell:x:1", ip, "dismiss", "noise-gate");
        // Same detector, different IP — must NOT count.
        seed_shape(&store, "imds_ssrf:y:1", "8.8.8.8", "dismiss", "noise-gate");
        let s = store
            .shape_dismissal_stats("imds_ssrf", ip, EXCL, ACTED)
            .unwrap();
        assert_eq!(s.genuine_dismissals, 1);
    }

    #[test]
    fn shape_dismissal_stats_empty_actioned_list_returns_zero_actioned() {
        let store = Store::open_memory().unwrap();
        let ip = "203.0.113.9";
        seed_shape(&store, "port_scan:x:1", ip, "block_ip", "manual");
        let s = store
            .shape_dismissal_stats("port_scan", ip, EXCL, &[])
            .unwrap();
        assert_eq!(
            s.actioned, 0,
            "empty actioned_types must short-circuit to 0"
        );
    }

    #[test]
    fn shape_dismissal_stats_no_exclusions_counts_everything() {
        let store = Store::open_memory().unwrap();
        let ip = "169.254.169.254";
        seed_shape(&store, "imds_ssrf:x:1", ip, "dismiss", "orphan-recovery");
        seed_shape(&store, "imds_ssrf:x:2", ip, "dismiss", "noise-gate");
        let s = store
            .shape_dismissal_stats("imds_ssrf", ip, &[], ACTED)
            .unwrap();
        assert_eq!(s.genuine_dismissals, 2);
    }

    // ── anchor (whole-log deletion / rollback detection) ─────────────────

    #[test]
    fn empty_log_has_no_anchor() {
        let store = Store::open_memory().unwrap();
        assert!(store.compute_anchor().unwrap().is_none());
    }

    #[test]
    fn anchor_intact_after_appending_more_rows() {
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        store
            .insert_decision(&sample_decision("inc-2", "ignore"))
            .unwrap();
        let anchor = store.compute_anchor().unwrap().expect("non-empty → anchor");
        // Appending new decisions must NOT invalidate the committed prefix.
        store
            .insert_decision(&sample_decision("inc-3", "monitor"))
            .unwrap();
        assert_eq!(
            store.verify_against_anchor(&anchor).unwrap(),
            AnchorVerdict::Intact
        );
    }

    #[test]
    fn anchor_detects_truncation_when_tip_row_deleted() {
        let store = Store::open_memory().unwrap();
        store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        let id2 = store
            .insert_decision(&sample_decision("inc-2", "ignore"))
            .unwrap();
        let anchor = store.compute_anchor().unwrap().unwrap();
        assert_eq!(anchor.seq, id2);
        // Roll the log back past the anchor (delete the anchored tip) — the
        // internal chain would still verify, the anchor catches it.
        store
            .conn()
            .unwrap()
            .execute("DELETE FROM decisions WHERE id = ?1", params![id2])
            .unwrap();
        assert!(
            store.verify_hash_chain().unwrap().intact,
            "chain still self-consistent"
        );
        assert_eq!(
            store.verify_against_anchor(&anchor).unwrap(),
            AnchorVerdict::Truncated
        );
    }

    #[test]
    fn anchor_detects_rewrite_of_committed_history() {
        let store = Store::open_memory().unwrap();
        let id1 = store
            .insert_decision(&sample_decision("inc-1", "block_ip"))
            .unwrap();
        let anchor = store.compute_anchor().unwrap().unwrap();
        store
            .conn()
            .unwrap()
            .execute(
                "UPDATE decisions SET row_hash = 'deadbeef' WHERE id = ?1",
                params![id1],
            )
            .unwrap();
        assert_eq!(
            store.verify_against_anchor(&anchor).unwrap(),
            AnchorVerdict::Rewritten
        );
    }

    #[test]
    fn anchor_json_round_trips() {
        // The operator publishes the anchor off-host, so it must serialize.
        let a = DecisionAnchor {
            seq: 42,
            row_hash: "abc123".into(),
            count: 42,
        };
        let j = serde_json::to_string(&a).unwrap();
        let back: DecisionAnchor = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
