#[cfg(test)]
use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::telemetry::TelemetrySnapshot;

#[derive(Clone, Debug)]
pub struct AdvisoryEntry {
    pub advisory_id: String,
    pub command_hash: String,
    pub command_preview: String,
    pub risk_score: u32,
    pub recommendation: String,
    pub signals: Vec<String>,
    pub ts: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// D3 - action request / response structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct BlockIpRequest {
    /// Target IP address to block.
    pub(super) ip: String,
    /// Operator-supplied reason (mandatory - becomes the audit trail entry).
    pub(super) reason: String,
    /// Optional incident ID to associate this action with.
    pub(super) incident_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SuspendUserRequest {
    /// Linux username to suspend from sudo.
    pub(super) user: String,
    /// Operator-supplied reason (mandatory).
    pub(super) reason: String,
    /// How long to suspend (seconds). Defaults to 3600 (1 hour).
    pub(super) duration_secs: Option<u64>,
    /// Optional incident ID to associate this action with.
    pub(super) incident_id: Option<String>,
}

/// Operator override of an AI decision (audit-only for v1).
/// 2026-05-01 (`tracked-spec-ai-override`): closes audit findings
/// 2.4 + 5.4. The original AI decision stays in the chain — the
/// override is a NEW row that points back via reason text and
/// `prev_decision_id`. Body fields:
/// - `decision_id`: the original AI decision being overridden
/// - `new_action`: what the operator would have decided
///   (`block_ip` | `monitor` | `dismiss` | `request_confirmation`)
/// - `reason`: operator's rationale (mandatory; goes into the
///   audit trail and is rendered in the compliance viewer).
#[derive(Debug, Deserialize)]
pub(crate) struct OverrideDecisionRequest {
    pub(super) decision_id: i64,
    pub(super) new_action: String,
    pub(super) reason: String,
}

/// Operator re-opens a dismissed/closed incident for re-review.
/// V1 is audit-only: writes a `operator_reopen` decision row to the
/// hash chain. The incident's `outcome` field in the graph is NOT
/// mutated yet (out of scope for v1); the audit row records the
/// operator's intent. A follow-up spec will add the state-machine
/// integration that re-routes reopened incidents through AI triage.
#[derive(Debug, Deserialize)]
pub(crate) struct ReopenIncidentRequest {
    pub(super) incident_id: String,
    pub(super) reason: String,
}

/// Operator labels a decision as TP (true positive — the AI got
/// it right) or FP (false positive — the AI was wrong). Appended
/// to `data_dir/decision-labels.jsonl` for future classifier
/// retraining. Body fields:
/// - `decision_id`: which decision is being labelled
/// - `label`: `"TP"` or `"FP"`
/// - `reason`: optional operator note (empty allowed for quick clicks).
#[derive(Debug, Deserialize)]
pub(crate) struct LabelDecisionRequest {
    pub(super) decision_id: i64,
    pub(super) label: String,
    #[serde(default)]
    pub(super) reason: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HoneypotTestRequest {
    /// Operator-supplied reason (mandatory).
    pub(super) reason: String,
    /// Duration in seconds for the honeypot session (default: 120).
    pub(super) duration_secs: Option<u64>,
}

/// Operator requests that a firewall block on `ip` be removed (2026-06-10).
/// The natural complement to Block IP — a contained/blocked case offered no
/// way to lift the block from the UI. This endpoint does NOT touch the
/// firewall synchronously; it QUEUES the unblock (writes an
/// `operator_unblock_request` decision row per incident). The agent's slow
/// loop drains the queue and performs the revert through the real
/// `response_lifecycle`, so the spec-076 reconciler does not fight a
/// dashboard-side rule removal. Body fields:
/// - `ip`: the IP to unblock (must parse as a valid IP address).
/// - `reason`: operator rationale (mandatory; audit trail).
/// - `incident_ids`: the case's incidents, so each leaves the "blocked"
///   bucket once the drain writes the terminal `operator_unblock` row. Empty
///   is allowed (a synthetic marker incident is used so the IP still unblocks).
#[derive(Debug, Deserialize)]
pub(crate) struct UnblockIpRequest {
    pub(super) ip: String,
    pub(super) reason: String,
    #[serde(default)]
    pub(super) incident_ids: Vec<String>,
}

/// Operator triages a whole case (2026-06-10): dismiss it out of "Needs your
/// attention", mark it as monitored/observing, or re-open it. Writes one
/// operator-action decision per incident in the case; because the dashboard
/// read path classifies the LATEST decision per incident, the operator's row
/// wins and the case moves to the right bucket. Body fields:
/// - `incident_ids`: every incident in the case (the frontend already has them
///   from the journey payload).
/// - `action`: `"dismiss"` | `"monitor"` | `"reopen"`.
/// - `reason`: operator rationale (mandatory; audit trail).
#[derive(Debug, Deserialize)]
pub(crate) struct TriageCaseRequest {
    pub(super) incident_ids: Vec<String>,
    pub(super) action: String,
    pub(super) reason: String,
}

/// Operator "Trust IP" (monitor-only allowlist). Adds an IP/CIDR to
/// `dynamic_trusted_ips` so the agent stops AUTO-blocking it — the IP is still
/// detected, logged, and notified (see `operator_trust.rs`). Body fields:
/// - `ip`: the IP or CIDR to trust (internal/private ranges ARE allowed here,
///   unlike the block path; `/0` is rejected).
/// - `reason`: operator rationale (mandatory; audit trail).
/// - `ttl_hours`: optional time-box. Omit for permanent trust; when set the
///   entry expires on its own (≤ one slow-loop tick after lapsing).
#[derive(Debug, Deserialize)]
pub(crate) struct TrustIpRequest {
    pub(super) ip: String,
    pub(super) reason: String,
    #[serde(default)]
    pub(super) ttl_hours: Option<u64>,
}

/// Remove an IP/CIDR from the operator trust list (re-enables auto-response).
/// `reason` is optional (recorded for the audit trail when present).
#[derive(Debug, Deserialize)]
pub(crate) struct UntrustIpRequest {
    pub(super) ip: String,
    #[serde(default)]
    pub(super) reason: String,
}

/// Authorise a binary PATH for the Execution Gate (operator "Trust Exec").
/// - `path`: absolute binary path to allow (no globs — the kernel enforces an
///   exact path).
/// - `reason`: operator rationale (mandatory; audit trail).
/// - `totp`: 6-digit 2FA code. Required when `[security].method = "totp"` (arming
///   exec is a sensitive action); ignored when 2FA is disabled.
#[derive(Debug, Deserialize)]
pub(crate) struct TrustExecRequest {
    pub(super) path: String,
    pub(super) reason: String,
    #[serde(default)]
    pub(super) totp: String,
}

/// Remove a path from the Execution Gate operator allowlist.
#[derive(Debug, Deserialize)]
pub(crate) struct UntrustExecRequest {
    pub(super) path: String,
    #[serde(default)]
    pub(super) reason: String,
    #[serde(default)]
    pub(super) totp: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ActionResponse {
    pub(super) success: bool,
    pub(super) dry_run: bool,
    pub(super) message: String,
    /// Echoes back the skill ID that was invoked (or would have been).
    pub(super) skill_id: String,
}

// ---------------------------------------------------------------------------
// Query structs
// ---------------------------------------------------------------------------

/// Spec 049 PR6 — `Current state` band counters. Distinct from the
/// flat `OverviewResponse` counters because Current state IGNORES
/// the request's date/hour filter — it always reflects today's
/// live product state so the operator never loses situational
/// awareness while auditing a historical window. The three fields
/// mirror the three Selected-period leaf counters but read from a
/// today-only no-hour-filter compute pass.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct CurrentStateBlock {
    /// Unique attacker IPs in `Contained` outcome today (= blocked +
    /// honeypot). PR6 approximation: today's count from
    /// `compute_overview_counts_from_sqlite` with no hour filter.
    /// A future PR may swap this for live `xdp_block_times` reads
    /// so the "blocked from yesterday with 48h TTL still active"
    /// case shows correctly.
    pub(crate) currently_blocked: usize,
    /// Today's `Observing` outcome count.
    pub(crate) currently_observing: usize,
    /// Today's `Needs review` outcome count.
    pub(crate) needs_review_now: usize,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    pub(super) limit: Option<usize>,
    pub(super) date: Option<String>,
    pub(super) severity_min: Option<String>,
    pub(super) detector: Option<String>,
    /// Spec 049 PR4 — hour-of-day filter on the selected date.
    /// Inclusive lower bound, 0-23 (UTC, matches the date semantics).
    /// Filter only applies when BOTH `hour_from` AND `hour_to` are
    /// present AND `hour_from <= hour_to` AND both <= 23. Any other
    /// combination = no hour filter (the handler treats malformed
    /// pairs as absent). Cross-midnight ranges (22:00..02:00) are
    /// NOT supported in PR4 — operator picks two adjacent dates if
    /// they need to span a midnight boundary.
    pub(super) hour_from: Option<u32>,
    /// Spec 049 PR4 — inclusive upper bound, 0-23 (UTC). See
    /// `hour_from` for the validation contract.
    pub(super) hour_to: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EntitiesQuery {
    pub(super) limit: Option<usize>,
    pub(super) date: Option<String>,
    pub(super) severity_min: Option<String>,
    pub(super) detector: Option<String>,
    pub(super) group_by: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // severity_min/detector accepted for API forward-compat; graph filters land in spec 016
pub(crate) struct JourneyQuery {
    pub(super) subject_type: Option<String>,
    pub(super) subject: Option<String>,
    // Backward compatibility with D2.1 clients
    pub(super) ip: Option<String>,
    pub(super) date: Option<String>,
    pub(super) severity_min: Option<String>,
    pub(super) detector: Option<String>,
    pub(super) window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AiExplainQuery {
    pub(super) r#type: Option<String>,
    pub(super) value: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // severity_min/detector accepted for API forward-compat; graph filters land in spec 016
pub(crate) struct ClusterQuery {
    pub(super) limit: Option<usize>,
    pub(super) date: Option<String>,
    pub(super) severity_min: Option<String>,
    pub(super) detector: Option<String>,
    pub(super) window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ExportQuery {
    pub(super) date: Option<String>,
    pub(super) format: Option<String>,
    pub(super) subject_type: Option<String>,
    pub(super) subject: Option<String>,
    // Backward compatibility with D2.1 clients
    pub(super) ip: Option<String>,
    pub(super) severity_min: Option<String>,
    pub(super) detector: Option<String>,
    pub(super) group_by: Option<String>,
    pub(super) limit: Option<usize>,
    pub(super) window_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReportQuery {
    /// Optional specific date (YYYY-MM-DD). Defaults to latest available.
    pub(super) date: Option<String>,
}

// ---------------------------------------------------------------------------
// Response structs - existing
// ---------------------------------------------------------------------------

/// Phase 7 (audit RC-2 / 2026-04-29): the operator-facing snapshot.
/// This is the structured replacement for the flat OverviewResponse
/// fields. It exists so the Home tile, Threats list, and any future
/// surface render from a *single* shape — no more "tile counts
/// incidents, list counts IPs, two unrelated truths in one screen".
///
/// Top-level shape (one of three discriminants the front-end keys on):
///
/// * `health` — verbal status the hero tile renders ("Operating",
///   "Backed up", "AI not responding"). Derived from the buckets and
///   pending breakdown so a future change to one of those propagates
///   into the verb without front-end edits.
/// * `buckets` — for each operator-relevant outcome (blocked, observing,
///   honeypot, dismissed, allowlisted, attention) we expose BOTH the
///   incident count *and* the unique-attacker-IP count. The two
///   numbers tell different stories (volume of action vs. distinct
///   threats neutralised) and a Principal-level UX rejects the
///   "single-number-with-implicit-unit" pattern that caused the
///   2026-04-29 confusion.
/// * `pending` — incidents without a final decision, broken out by
///   the *reason* they're pending (in_flight, declined, cooldown,
///   stuck). The "stuck" sub-bucket is the operator-visible health
///   signal: if it's non-zero for more than a tick, the AI pipeline
///   is wedged.
///
/// `OverviewResponse` keeps its flat fields populated from this
/// snapshot so existing clients (Telegram bot's status command, etc)
/// don't break. The frontend has migrated to read `snapshot.*`.
#[derive(Debug, Serialize, Clone)]
pub(crate) struct OverviewSnapshot {
    pub(crate) date: String,
    pub(crate) generated_at: chrono::DateTime<Utc>,
    pub(crate) health: SystemHealth,
    pub(crate) buckets: OutcomeBuckets,
    pub(crate) pending: PendingBreakdown,
    /// Total events scanned today (sensor counter, not date-filtered
    /// in the lossy KG sense — comes from telemetry snapshot which
    /// the sensor maintains independently of the agent's KG).
    pub(crate) events_today: usize,
    pub(crate) top_detectors: Vec<DetectorCount>,
}

/// Operator-readable verb. The front-end maps each variant to a
/// colour and a one-line headline. Derived in the backend so the
/// thresholds for each state are testable in one place and not
/// duplicated across UI surfaces.
///
/// Phase 7B (2026-04-29) refined the verbs to distinguish "AI is
/// down right now" (no recent decisions in the past 5 minutes) from
/// "AI is fine but has accumulated abandoned incidents from earlier"
/// (recent decisions are flowing, but old incidents are still
/// undecided). The pre-7B path lumped both into AiNotResponding,
/// which generated false-positive system-health alerts whenever a
/// past hour had any decisionless incident even though the AI was
/// processing normally.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum SystemHealth {
    /// AI is processing decisions in normal cadence; pending count
    /// stays bounded; no stuck incidents over the threshold.
    OperatingNormally,
    /// Pending incidents are accumulating but the AI is still
    /// answering — likely a burst of activity. Yellow.
    BackedUp { pending_in_flight: usize },
    /// **AI is fine right now**, but earlier-day incidents got
    /// abandoned (no decision within 1h). The orphan recovery pass
    /// will sweep them; operator gets a soft signal rather than a
    /// false alarm. Yellow.
    AbandonedBacklog {
        stuck_count: usize,
        last_decision_secs_ago: i64,
    },
    /// **AI is genuinely not responding** — no decision has been
    /// written in the last 5 minutes despite incidents accumulating
    /// for over 1h. Either provider is down, classifier failed to
    /// load, or pipeline is wedged on a config error. Red — operator
    /// must look. Carries the count and last-decision age for the
    /// headline.
    AiNotResponding {
        stuck_count: usize,
        last_decision_secs_ago: Option<i64>,
    },
    /// 2026-05-01 dashboard QA audit finding 1.2: the green PROTECTED
    /// banner was sitting on top of 17 orphaned + 111 revert
    /// failures + 1393 expired responses. None of those is an "AI
    /// is down right now" emergency, so they did not trip the
    /// existing red verbs. They are a chronic cumulative drift —
    /// silent failures that the banner must not conceal. `Degraded`
    /// turns the badge yellow with operator-readable reasons. The
    /// reason strings are user-facing and appear on the banner; keep
    /// them short, specific, and actionable (e.g. include numbers).
    Degraded { reasons: Vec<String> },
}

/// One pair of counters per outcome. The pair (`incidents`,
/// `unique_attackers`) is what unblocks the "21 vs 10" confusion that
/// motivated Phase 7. `severities` is a small breakdown so the front
/// end can render a critical/high/medium/low strip without a
/// follow-up request.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct BucketStats {
    /// Number of *incidents* in this bucket today.
    pub(crate) incidents: usize,
    /// Number of *distinct attacker IPs* in this bucket today. Always
    /// `<= incidents` (one attacker can fire many incidents).
    pub(crate) unique_attackers: usize,
    /// Severity histogram — ordered map keyed by the canonical
    /// severity string ("critical", "high", "medium", "low", "info").
    pub(crate) severities: std::collections::BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct OutcomeBuckets {
    pub(crate) blocked: BucketStats,
    pub(crate) observing: BucketStats,
    pub(crate) honeypot: BucketStats,
    pub(crate) dismissed: BucketStats,
    /// Incidents that matched the operator's allowlist (static config
    /// or dynamic /etc/innerwarden/allowlist.toml). Pre-Phase-7 these
    /// silently inflated `attention` because they had no decision; now
    /// they have a dedicated bucket the operator can audit.
    pub(crate) allowlisted: BucketStats,
    /// Incidents that *do* need attention — see `pending` for the
    /// reason-by-reason breakdown.
    pub(crate) attention: BucketStats,
}

/// Why a "needs attention" incident is sitting without a final
/// decision. The categorisation drives both the Home tile drill-down
/// and the SystemHealth verb above.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct PendingBreakdown {
    /// Incident fired in the last 5 minutes; AI is about to run.
    /// Normal in-flight state — operator should not be alarmed.
    pub(super) in_flight: usize,
    /// AI ran and explicitly declined to decide
    /// (`escalate` / `request_confirmation`). Operator must triage.
    pub(super) declined_by_ai: usize,
    /// Same (action, detector, entity) tuple was decided <1h ago, so
    /// this incident inherits that decision via the cooldown table.
    /// Functionally handled, no operator action needed.
    pub(super) cooldown_suppressed: usize,
    /// Incident is more than 1 hour old, has no decision, and has no
    /// cooldown row covering it. AI pipeline is wedged. **This is
    /// the watchdog signal.**
    pub(super) stuck: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct OverviewResponse {
    pub(super) date: String,
    pub(super) events_count: usize,
    pub(super) incidents_count: usize,
    pub(super) decisions_count: usize,
    /// Incidents where AI decided to act (block, kill, honeypot, monitor).
    /// This is the "real threat" count. incidents_count - confirmed = noise/ignored.
    pub(super) ai_confirmed: usize,
    /// Incidents where AI executed a response action (block_ip, kill_process, etc).
    pub(super) ai_responded: usize,
    /// Incidents where AI decided to ignore (false positive or low risk).
    pub(super) ai_ignored: usize,
    /// Incidents with no decision yet — need human attention.
    pub(super) unresolved_count: usize,
    /// Incidents safely resolved (blocked, killed, contained, monitored, honeypot).
    pub(super) safely_resolved: usize,
    /// Distinct attacker IPs the AI took a non-ignore action on today.
    /// Reported by the home tile so the number matches what the operator
    /// sees when they click through to the Threats tab (which dedupes by
    /// IP). Pre-2026-04-23 home displayed `safely_resolved` (incident
    /// count) and threats displayed unique-IP-count; the operator saw
    /// "54 handled" but counted only ~14 entries on the threats page.
    /// See `NUMBER_CONSISTENCY.md` row "handled count".
    pub(super) handled_ips_today: usize,
    /// Spec 037 Threats UX bundle: incidents whose decision was a
    /// terminal containment (`block_ip` or `honeypot`). Drives the
    /// Threats-tab "Blocked" KPI. Replaces the prior threats.js
    /// computation that summed pivot-item outcomes, which depended on
    /// the currently-selected pivot and gave inconsistent counts.
    pub(super) blocked_count: usize,
    /// Spec 037 Threats UX bundle: incidents whose decision was
    /// `monitor` (the AI is watching but not containing). Drives the
    /// Threats-tab "Observing" KPI.
    pub(super) observing_count: usize,
    /// Spec 037 Threats UX bundle: incidents that need operator
    /// attention -- either no decision was reached, or the decision
    /// was `request_confirmation`. Drives the Threats-tab "Needs
    /// attention" KPI.
    pub(super) attention_count: usize,
    /// Spec 049 — distinct attacker IPs whose decision was `dismiss`
    /// / `ignore` ("filtered out as noise"). Pre-spec-049 these were
    /// silently uncounted (`KpiBucket::None`). Drives the new "Filtered
    /// out" sub-breakdown on the Home strip and the matching pivot
    /// in Cases. See `case_metrics.rs` for the math contract.
    pub(super) filtered_out_count: usize,
    /// Spec 049 — `Flagged by system = blocked + observing + filtered_out + attention`.
    /// MSSP volume number, computed by the backend so every consumer
    /// (Home strip, Briefings, exports) reads the same reconciliation.
    pub(super) flagged_by_system_count: usize,
    /// Spec 049 — `Warden decisions = blocked + observing + filtered_out`.
    /// "Operator did not have to act" number. Dismiss counts as a
    /// decision, not a no-op (spec 049 Q1+Q7).
    pub(super) warden_decisions_count: usize,
    /// Spec 049 PR4 — operator timezone label (IANA name like
    /// `"America/Sao_Paulo"`, or `"UTC"` fallback). Emitted by the
    /// backend so the scope picker can render "Today (TZ)" without
    /// relying on browser-derived TZ (which drifts across analysts
    /// and the MSSP's clients). Resolution order: env `TZ`,
    /// `/etc/timezone`, then `"UTC"`. The current PR's hour filter
    /// (`hour_from` / `hour_to`) still interprets hours in UTC; a
    /// follow-up PR may add operator-TZ conversion at the picker
    /// layer.
    pub(super) timezone: String,
    /// Spec 049 PR6 — `Current state` band on the Cases tab header.
    /// ALWAYS reflects today's full-day counts, regardless of the
    /// request's `date` / `hour_from` / `hour_to` query params.
    /// Operator can pick `Yesterday 14h-16h` in the scope picker and
    /// the `Selected period` band reads those counters (flat
    /// `blocked_count` / `observing_count` / `attention_count`),
    /// while the `Current state` band keeps showing what is alive
    /// right now in the product. The two bands are deliberately
    /// independent (spec 049 §8.2.A) so the operator can audit a
    /// historical window without losing situational awareness.
    pub(super) current_state: CurrentStateBlock,
    /// Breakdown by severity level: {"critical": N, "high": N, ...}
    pub(super) severity_breakdown: std::collections::HashMap<String, usize>,
    /// Incidents from allowlisted IPs/users (can be hidden in dashboard).
    pub(super) allowlisted_count: usize,
    pub(super) top_detectors: Vec<DetectorCount>,
    pub(super) latest_telemetry: Option<TelemetrySnapshot>,
    /// Phase 7 (audit RC-2): the typed snapshot the front-end
    /// migrated to. The flat fields above stay populated from this
    /// snapshot so existing API clients (Telegram bot, exporters)
    /// keep working unchanged. `None` only when the snapshot path is
    /// unavailable (sleep mode / no SQLite store).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) snapshot: Option<OverviewSnapshot>,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct DetectorCount {
    pub(crate) detector: String,
    pub(crate) count: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct IncidentListResponse {
    pub(super) date: String,
    pub(super) total: usize,
    pub(super) items: Vec<IncidentView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DecisionListResponse {
    pub(super) date: String,
    pub(super) total: usize,
    pub(super) items: Vec<DecisionView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct IncidentView {
    pub(super) ts: chrono::DateTime<Utc>,
    pub(super) incident_id: String,
    pub(super) severity: String,
    /// Effective severity after considering outcome: blocked critical → medium, ignored → info.
    pub(super) effective_severity: String,
    pub(super) title: String,
    pub(super) summary: String,
    pub(super) entities: Vec<String>,
    pub(super) tags: Vec<String>,
    /// Resolution status: "blocked", "suspended", "monitored", "ignored", or "open"
    pub(super) outcome: String,
    /// What action was taken (e.g. "block-ip-ufw", "fail2ban:sshd")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) action_taken: Option<String>,
    /// AI decision confidence (0.0 - 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) confidence: Option<f32>,
    /// True if the source entity is in the allowlist.
    pub(super) is_allowlisted: bool,
    /// Spec 049 PR15 — set to `Some(true)` only when the request
    /// scope is a past date AND at least one IP entity on this row
    /// is currently `BlockState::BlockedNow` (kernel-enforced).
    /// Today-scope responses and past rows with expired blocks omit
    /// the field entirely so the JSON payload stays small.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) still_active_now: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DecisionView {
    pub(super) ts: chrono::DateTime<Utc>,
    pub(super) incident_id: String,
    pub(super) action_type: String,
    pub(super) target_ip: Option<String>,
    pub(super) skill_id: Option<String>,
    pub(super) confidence: f32,
    pub(super) auto_executed: bool,
    pub(super) dry_run: bool,
    pub(super) reason: String,
    pub(super) execution_result: String,
}

// ---------------------------------------------------------------------------
// Response structs - D2 journey
// ---------------------------------------------------------------------------

/// Summarizes an attacker (IP with at least one incident) for the left panel.
#[derive(Debug, Serialize)]
pub(crate) struct AttackerSummary {
    pub(super) ip: String,
    pub(super) first_seen: chrono::DateTime<Utc>,
    pub(super) last_seen: chrono::DateTime<Utc>,
    pub(super) max_severity: String,
    pub(super) detectors: Vec<String>,
    /// "blocked" | "monitoring" | "honeypot" | "active" | "unknown"
    pub(super) outcome: String,
    pub(super) incident_count: usize,
    pub(super) event_count: usize,
    /// Phase 3 (audit RC-4): kernel-evidence block state. Separates
    /// "decision was made" from "block currently active" from "block
    /// expired". `None` only when the agent has no SQLite store wired
    /// (test fixtures); production always emits one of the variants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) block_state: Option<crate::dashboard::threat_contract::BlockState>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EntitiesResponse {
    pub(super) date: String,
    pub(super) attackers: Vec<AttackerSummary>,
}

/// One timestamped entry in an attacker's journey timeline.
#[derive(Debug, Serialize)]
pub(crate) struct JourneyEntry {
    pub(super) ts: chrono::DateTime<Utc>,
    /// "event" | "incident" | "decision" | "honeypot_ssh" | "honeypot_http" | "honeypot_banner"
    pub(super) kind: String,
    pub(super) data: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct JourneySummary {
    pub(super) total_entries: usize,
    pub(super) events_count: usize,
    pub(super) incidents_count: usize,
    pub(super) decisions_count: usize,
    pub(super) honeypot_count: usize,
    pub(super) first_event: Option<chrono::DateTime<Utc>>,
    pub(super) first_incident: Option<chrono::DateTime<Utc>>,
    pub(super) first_decision: Option<chrono::DateTime<Utc>>,
    pub(super) first_honeypot: Option<chrono::DateTime<Utc>>,
    pub(super) pivot_shortcuts: Vec<String>,
    pub(super) hints: Vec<String>,
}

/// D5 - High-level attack assessment derived from the journey entries.
#[derive(Debug, Serialize)]
pub(crate) struct JourneyVerdict {
    /// Detected attack vector: "ssh_bruteforce" | "credential_stuffing" |
    /// "port_scan" | "sudo_abuse" | "unknown"
    pub(super) entry_vector: String,
    /// "no_evidence_of_success" | "likely_success" | "confirmed_success" | "inconclusive"
    pub(super) access_status: String,
    /// "no_evidence" | "attempted" | "confirmed" | "inconclusive"
    pub(super) privilege_status: String,
    /// "blocked" | "monitored" | "honeypot" | "active" | "unknown"
    pub(super) containment_status: String,
    /// "engaged" | "diverted" | "not_engaged"
    pub(super) honeypot_status: String,
    /// "high" | "medium" | "low"
    pub(super) confidence: String,
}

/// D5 - A logical phase of the attack story derived from consecutive entries.
#[derive(Debug, Serialize)]
pub(crate) struct JourneyChapter {
    /// Stage label: "reconnaissance" | "initial_access_attempt" | "access_success" |
    /// "privilege_abuse" | "response" | "containment" | "honeypot_interaction" | "unknown"
    pub(super) stage: String,
    pub(super) title: String,
    pub(super) summary: String,
    pub(super) start_ts: chrono::DateTime<Utc>,
    pub(super) end_ts: chrono::DateTime<Utc>,
    pub(super) entry_count: usize,
    /// Key facts / evidence highlights (usernames, ports, credentials, etc.)
    pub(super) evidence_highlights: Vec<String>,
    /// Indices into the parent `entries` array for drill-down
    pub(super) entry_indices: Vec<usize>,
}

#[derive(Debug, Serialize)]
pub(crate) struct JourneyResponse {
    pub(super) subject_type: String,
    pub(super) subject: String,
    pub(super) date: String,
    pub(super) first_seen: Option<chrono::DateTime<Utc>>,
    pub(super) last_seen: Option<chrono::DateTime<Utc>>,
    pub(super) outcome: String,
    pub(super) summary: JourneySummary,
    /// D5 - high-level attack assessment
    pub(super) verdict: JourneyVerdict,
    /// D5 - logical attack chapters derived from entries
    pub(super) chapters: Vec<JourneyChapter>,
    pub(super) entries: Vec<JourneyEntry>,
    /// Phase 3 (audit RC-4): kernel-evidence block state. Populated
    /// only when subject_type == "ip" -- detector and user pivots have
    /// no single IP to query against xdp_block_times.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) block_state: Option<crate::dashboard::threat_contract::BlockState>,
    /// Spec 049 PR10 — Cases drill-down recurrence block. Populated
    /// only when `subject_type == "ip"` AND the agent has an
    /// `AttackerProfile` for that IP in `attacker_profiles` SQLite
    /// blob. User and detector pivots have no single IP to look up;
    /// they emit `None`. Frontend renders the block on the journey
    /// detail view above the timeline so the operator never loses
    /// sight of "is this attacker new or has it visited before?".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) recurrence: Option<crate::dashboard::case_recurrence::RecurrenceBlock>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PivotItem {
    pub(super) group_by: String,
    pub(super) value: String,
    pub(super) first_seen: chrono::DateTime<Utc>,
    pub(super) last_seen: chrono::DateTime<Utc>,
    pub(super) max_severity: String,
    pub(super) incident_count: usize,
    pub(super) event_count: usize,
    pub(super) outcome: String,
    pub(super) detectors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PivotResponse {
    pub(super) date: String,
    pub(super) group_by: String,
    pub(super) total: usize,
    pub(super) items: Vec<PivotItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClusterItem {
    pub(super) cluster_id: String,
    pub(super) pivot: String,
    pub(super) pivot_type: String,
    pub(super) pivot_value: String,
    pub(super) start_ts: DateTime<Utc>,
    pub(super) end_ts: DateTime<Utc>,
    pub(super) incident_count: usize,
    pub(super) detector_kinds: Vec<String>,
    pub(super) incident_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClusterResponse {
    pub(super) date: String,
    pub(super) total: usize,
    pub(super) items: Vec<ClusterItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InvestigationExport {
    pub(super) generated_at: DateTime<Utc>,
    pub(super) date: String,
    pub(super) filters: serde_json::Value,
    pub(super) group_by: String,
    pub(super) subject_type: Option<String>,
    pub(super) subject: Option<String>,
    pub(super) overview: OverviewResponse,
    pub(super) pivots: Vec<PivotItem>,
    pub(super) clusters: Vec<ClusterItem>,
    pub(super) journey: Option<JourneyResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PivotKind {
    Ip,
    User,
    Detector,
}

impl PivotKind {
    pub(crate) fn parse(raw: Option<&str>) -> Self {
        match raw.unwrap_or("ip").trim().to_ascii_lowercase().as_str() {
            "user" => Self::User,
            "detector" => Self::Detector,
            _ => Self::Ip,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::User => "user",
            Self::Detector => "detector",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct InvestigationFilters {
    pub(super) severity_min: Option<u8>,
    pub(super) detector: Option<String>,
}

impl InvestigationFilters {
    pub(crate) fn from_query(severity_min: Option<&str>, detector: Option<&str>) -> Self {
        let severity_min = severity_min
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| severity_order(v.to_ascii_lowercase().as_str()));
        let severity_min = match severity_min {
            Some(0) | None => None,
            other => other,
        };

        let detector = detector
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_ascii_lowercase());

        Self {
            severity_min,
            detector,
        }
    }

    /// Severity rank threshold (0 = no filter). Same numeric scale as
    /// `crate::dashboard::investigation::severity_rank` so producers and
    /// consumers compare against the same totem.
    pub(crate) fn severity_min_rank(&self) -> u8 {
        self.severity_min.unwrap_or(0)
    }

    /// Lowercased detector substring for `contains` filtering. `None`
    /// means "match all detectors".
    pub(crate) fn detector_lower(&self) -> Option<&str> {
        self.detector.as_deref()
    }
}

// ---------------------------------------------------------------------------
// Internal accumulator for grouping events/incidents by IP
// ---------------------------------------------------------------------------

#[cfg(test)]
#[derive(Default)]
pub(crate) struct IpAccumulator {
    pub(super) first_seen: Option<chrono::DateTime<Utc>>,
    pub(super) last_seen: Option<chrono::DateTime<Utc>>,
    pub(super) max_severity: u8,
    pub(super) max_severity_str: String,
    pub(super) detectors: BTreeSet<String>,
    pub(super) ips: BTreeSet<String>,
    pub(super) incident_count: usize,
    pub(super) event_count: usize,
}

#[cfg(test)]
impl IpAccumulator {
    pub(crate) fn update_time(&mut self, ts: chrono::DateTime<Utc>) {
        if self.first_seen.is_none_or(|existing| ts < existing) {
            self.first_seen = Some(ts);
        }
        if self.last_seen.is_none_or(|existing| ts > existing) {
            self.last_seen = Some(ts);
        }
    }
}

// ---------------------------------------------------------------------------
// Presentation logic mappers
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(crate) fn classify_phase(event_kind: &str) -> &'static str {
    let lower = event_kind.to_ascii_lowercase();
    if lower.contains("port_scan") || lower.contains("recon") {
        "reconnaissance"
    } else if lower.contains("login_success")
        || lower.contains("_accepted")
        || lower.contains("auth_success")
    {
        "access_success"
    } else if lower.contains("sudo") || lower.contains("privilege") {
        "privilege_abuse"
    } else if lower.contains("persist") {
        "persistence"
    } else if lower.contains("exec") || lower.contains("shell") {
        "execution"
    } else {
        "initial_access_attempt"
    }
}

#[allow(dead_code)]
pub(crate) fn severity_color(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "#ff4444",
        "high" => "#ff8800",
        "medium" => "#ffbb33",
        "low" => "#00C851",
        "info" => "#33b5e5",
        _ => "#888888",
    }
}

#[allow(dead_code)]
pub(crate) fn status_determination(outcome: &str) -> &'static str {
    match outcome.to_ascii_lowercase().as_str() {
        "blocked" | "killed" => "contained",
        "monitoring" | "monitored" => "observing",
        "honeypot" | "diverted" => "contained",
        // Spec 028-c: "escalated" routes to the "needs your attention" bucket
        // explicitly so operators can see obs-verify escalates that have no
        // resolving decision yet.
        "escalated" | "active" | "open" => "needs_attention",
        "dismissed" | "ignored" => "observing",
        _ => "needs_attention",
    }
}

pub(crate) fn severity_order(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_phase() {
        // Assert valid mapped logic matching specification goals
        assert_eq!(classify_phase("nmap_port_scan"), "reconnaissance");
        assert_eq!(classify_phase("recon_probe"), "reconnaissance");
        assert_eq!(classify_phase("ssh_login_success"), "access_success");
        assert_eq!(classify_phase("pubkey_accepted"), "access_success");
        assert_eq!(classify_phase("sudo_failure"), "privilege_abuse");
        assert_eq!(classify_phase("kernel_module_persist"), "persistence");
        assert_eq!(classify_phase("reverse_shell"), "execution");
        assert_eq!(classify_phase("ssh_brute_force"), "initial_access_attempt");
        assert_eq!(classify_phase("unknown_event"), "initial_access_attempt");
    }

    #[test]
    fn test_severity_color_mapper() {
        assert_eq!(severity_color("critical"), "#ff4444");
        assert_eq!(severity_color("CRITICAL"), "#ff4444");
        assert_eq!(severity_color("INFO"), "#33b5e5");
        assert_eq!(severity_color("unknown"), "#888888");
    }

    #[test]
    fn test_status_determination_logic() {
        assert_eq!(status_determination("blocked"), "contained");
        assert_eq!(status_determination("killed"), "contained");
        assert_eq!(status_determination("honeypot"), "contained");
        assert_eq!(status_determination("monitoring"), "observing");
        assert_eq!(status_determination("dismissed"), "observing");
        assert_eq!(status_determination("active"), "needs_attention");
        // Spec 028-c: escalated items need operator attention, same bucket
        // as active/open.
        assert_eq!(status_determination("escalated"), "needs_attention");
        assert_eq!(status_determination("ESCALATED"), "needs_attention");
        assert_eq!(status_determination("unknown"), "needs_attention");
    }

    #[test]
    fn test_severity_order() {
        assert_eq!(severity_order("critical"), 5);
        assert_eq!(severity_order("high"), 4);
        assert_eq!(severity_order("medium"), 3);
        assert_eq!(severity_order("low"), 2);
        assert_eq!(severity_order("info"), 1);
        assert_eq!(severity_order("unknown"), 0);
    }

    #[test]
    fn test_pivot_kind_parsing() {
        assert_eq!(PivotKind::parse(Some("user")), PivotKind::User);
        assert_eq!(PivotKind::parse(Some("USER")), PivotKind::User);
        assert_eq!(PivotKind::parse(Some("detector")), PivotKind::Detector);
        assert_eq!(PivotKind::parse(Some("ip")), PivotKind::Ip);
        assert_eq!(PivotKind::parse(Some("anything_else")), PivotKind::Ip); // default
        assert_eq!(PivotKind::parse(None), PivotKind::Ip); // default
    }

    #[test]
    fn test_pivot_kind_as_str() {
        assert_eq!(PivotKind::User.as_str(), "user");
        assert_eq!(PivotKind::Ip.as_str(), "ip");
        assert_eq!(PivotKind::Detector.as_str(), "detector");
    }

    #[test]
    fn test_investigation_filters_from_query() {
        let filters = InvestigationFilters::from_query(Some("high"), Some(" ssh_bruteforce "));
        assert_eq!(filters.severity_min, Some(4));
        assert_eq!(filters.detector, Some("ssh_bruteforce".to_string()));

        let empty = InvestigationFilters::from_query(Some(""), Some(""));
        assert_eq!(empty.severity_min, None);
        assert_eq!(empty.detector, None);

        let unknown_severity = InvestigationFilters::from_query(Some("invalid"), None);
        assert_eq!(unknown_severity.severity_min, None); // Returns 0 which is mapped to None
    }

    #[test]
    fn test_ip_accumulator_update_time() {
        let mut acc = IpAccumulator::default();
        let early = Utc::now() - chrono::Duration::hours(2);
        let late = Utc::now() - chrono::Duration::hours(1);

        acc.update_time(late);
        assert_eq!(acc.first_seen, Some(late));
        assert_eq!(acc.last_seen, Some(late));

        // Updating with an earlier time shifts first_seen but not last_seen
        acc.update_time(early);
        assert_eq!(acc.first_seen, Some(early));
        assert_eq!(acc.last_seen, Some(late));
    }

    #[test]
    fn test_classify_phase_exhaustive() {
        // Assert every single logical event classification pathway
        assert_eq!(classify_phase("test_port_scan_active"), "reconnaissance"); // contains port_scan
        assert_eq!(classify_phase("deep_reconnaissance"), "reconnaissance"); // contains recon
        assert_eq!(
            classify_phase("test_login_success_action"),
            "access_success"
        ); // contains login_success
        assert_eq!(classify_phase("password_accepted"), "access_success"); // contains _accepted
        assert_eq!(classify_phase("user_auth_success"), "access_success"); // contains auth_success
        assert_eq!(classify_phase("user_sudo_escalation"), "privilege_abuse"); // contains sudo
        assert_eq!(classify_phase("root_privilege_granted"), "privilege_abuse"); // contains privilege
        assert_eq!(classify_phase("startup_persistence_added"), "persistence"); // contains persist
        assert_eq!(classify_phase("test_execution_command"), "execution"); // contains exec
        assert_eq!(classify_phase("reverse_shell_opened"), "execution"); // contains shell
        assert_eq!(
            classify_phase("web_vulnerability_exploit"),
            "initial_access_attempt"
        ); // unknown defaults to initial access
    }

    #[test]
    fn test_status_determination_exhaustive() {
        let contained = vec!["blocked", "killed", "honeypot", "diverted"];
        for status in contained {
            assert_eq!(status_determination(status), "contained");
            assert_eq!(status_determination(&status.to_uppercase()), "contained");
        }

        let observing = vec!["monitoring", "monitored", "dismissed", "ignored"];
        for status in observing {
            assert_eq!(status_determination(status), "observing");
        }

        let needs_attention = vec!["active", "open", "something_else", ""];
        for status in needs_attention {
            assert_eq!(status_determination(status), "needs_attention");
        }
    }

    // ── InvestigationFilters helpers (Inconsistency 3 anchor) ────────

    #[test]
    fn investigation_filters_from_query_normalises_severity_and_detector() {
        let f = InvestigationFilters::from_query(Some("HIGH"), Some(" SSH "));
        assert_eq!(f.severity_min_rank(), 4); // "high" rank
        assert_eq!(f.detector_lower(), Some("ssh")); // trimmed + lowercased
    }

    #[test]
    fn investigation_filters_treats_empty_strings_as_no_filter() {
        let f = InvestigationFilters::from_query(Some(""), Some("   "));
        assert_eq!(f.severity_min_rank(), 0);
        assert_eq!(f.detector_lower(), None);

        let none = InvestigationFilters::from_query(None, None);
        assert_eq!(none.severity_min_rank(), 0);
        assert_eq!(none.detector_lower(), None);
    }

    #[test]
    fn investigation_filters_unknown_severity_collapses_to_zero() {
        // severity_order returns 0 for "panic" / "warn" / typos. The filter
        // collapses 0 to "no filter" so a typo doesn't accidentally exclude
        // every incident.
        let f = InvestigationFilters::from_query(Some("panic"), None);
        assert_eq!(f.severity_min_rank(), 0);
    }

    #[test]
    fn investigation_filters_severity_min_rank_matches_string_severity_rank() {
        // The `severity_min_rank` returned here is compared against the
        // result of `dashboard::investigation::severity_rank` on individual
        // incident severities. Pin the same scale on both ends so a future
        // refactor cannot silently drift.
        for (s, expected) in &[
            ("critical", 5),
            ("high", 4),
            ("medium", 3),
            ("low", 2),
            ("info", 1),
        ] {
            let f = InvestigationFilters::from_query(Some(s), None);
            assert_eq!(
                f.severity_min_rank(),
                *expected,
                "severity_min={s} expected rank {expected}"
            );
        }
    }
}
