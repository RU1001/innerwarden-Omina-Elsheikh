use std::io::Write;
use std::path::Path;
use std::sync::atomic::AtomicU64;

use tracing::{info, warn};

use innerwarden_killchain::detector::process_lsm_blocked;
use innerwarden_killchain::tracker::PidTracker;

use crate::correlation_engine;

/// `comm` values whose events the kill chain tracker must ignore. These are
/// the platform's own thread names — the agent, sensor, and watchdog. Without
/// this list, routine agent activity (outbound threat-feed fetches +
/// credential file reads) trivially matches DATA_EXFIL against the agent
/// itself.
///
/// Linux `comm` is truncated to 15 characters (`TASK_COMM_LEN = 16` including
/// NUL), so the binary names below are already in their truncated form as
/// they appear in kernel events.
pub const KILLCHAIN_SELF_EXCLUDED_COMMS: &[&str] = &[
    "tokio-rt-worker", // tokio async runtime worker pool (15 chars)
    "innerwarden-age", // innerwarden-agent (truncated)
    "innerwarden-sen", // innerwarden-sensor (truncated)
    "innerwarden-wat", // innerwarden-watchdog (truncated)
];

/// Process a batch of sensor events through the kill chain tracker.
/// Returns incidents (JSON values) for any detected chains.
/// Also feeds the correlation engine with kill chain events.
pub(crate) fn process_events(
    tracker: &mut PidTracker,
    events: &[innerwarden_core::event::Event],
    correlation_engine: &mut correlation_engine::CorrelationEngine,
) -> Vec<serde_json::Value> {
    let mut all_incidents = Vec::new();

    for event in events {
        // Spec 052 Phase 1b — gap E (sched_process_exit GC):
        // When a registered PID exits, drop it from BLOCKED_PIDS so
        // the kernel doesn't carry stale entries until LRU eviction.
        // Cheap to call (returns silently if PID isn't in map).
        // Runs BEFORE the tracker so we don't miss exit events for
        // PIDs that the tracker also processes.
        if event.kind == "process.exit" {
            if let Some(pid) = event.details.get("pid").and_then(|p| p.as_u64()) {
                crate::lsm_policy::unregister_blocked_pid(pid as u32);
            }
        }

        // Convert core Event to JSON for the killchain tracker.
        let json = event_to_tracker_json(event);
        let incidents = tracker.process_event(&json);

        for inc in &incidents {
            // Feed kill chain detections into the correlation engine.
            let pattern = evidence_obj(inc)
                .and_then(|e| e.get("pattern"))
                .and_then(|p| p.as_str())
                .unwrap_or("unknown");

            let severity_str = inc
                .get("severity")
                .and_then(|s| s.as_str())
                .unwrap_or("medium");

            // Spec 052 Phase 1b: the offending PID is registered with the
            // kernel LSM block so the chain's NEXT execve hits -EPERM
            // synchronously (instead of waiting for the agent's kill_process
            // skill to race against the malicious exec).
            //
            // Spec 081 (2026-06-18): the kernel PID-block registration is NO
            // LONGER done here. This function is sync and has no access to the
            // agent-guard registry, so it cannot tell a real attacker apart
            // from a legit, IW-managed AI agent whose own startup matched the
            // chain signature. Kernel-denying a managed agent's next execve
            // severs the very agent IW is meant to guard. The registration moves
            // to `register_kernel_blocks` (async), which consults the
            // `managed_agent_guard` verifier and WITHHOLDS the kernel block ONLY
            // for a positively-verified managed agent. The verifier fails closed,
            // so a real attacker is still kernel-blocked. Detection is unchanged:
            // the incident still fires.
            //
            // NO TIMING REGRESSION (Defect-3 review): `process_events` is, and
            // always was, called ONLY from the slow_loop tick (`slow_loop.rs`),
            // never the fast incident loop. `register_kernel_blocks` is invoked
            // in the SAME tick, immediately after `process_events` returns (see
            // `slow_loop.rs`: `process_events(...)` then `register_kernel_blocks(
            // &kc_incidents, state).await`). So a real-attacker (non-managed) PID
            // is registered with the kernel block in the same tick it was before
            // this change — the verify happens inline and never delays the block
            // for non-managed PIDs. The block was never a fast-loop / kernel-time
            // response in the first place; the move only adds the agent-aware
            // withhold, it does not change WHEN the block lands.

            let kind = format!("killchain.{}", pattern);
            let mut corr_event = correlation_engine::CorrelationEngine::killchain_event(
                &kind,
                serde_json::json!({
                    "pattern": pattern,
                    "severity": severity_str,
                    "pid": evidence_obj(inc).and_then(|ev| ev.get("pid")),
                }),
            );
            // Phase 014-C: carry incident_id so link_correlated_incidents can
            // create CorrelatedWith edges if this kill chain pattern is part
            // of a larger multi-stage cross-layer attack chain.
            if let Some(iid) = inc.get("incident_id").and_then(|v| v.as_str()) {
                corr_event.incident_id = iid.to_string();
            }
            correlation_engine.observe(corr_event);
        }

        all_incidents.extend(incidents);

        // 2026-05-21: enrich LSM-blocked execve events into structured
        // "Kill chain BLOCKED" incidents. The kernel `bprm_check_security`
        // LSM hook in `crates/sensor-ebpf/src/main.rs:836` writes
        // `KILL_CHAIN_BLOCKED` into the filename slot when it denies an
        // execve that follows an attack pattern. The sensor surfaces those
        // as events with `kind = "lsm.exec_blocked"`, and the killchain
        // crate's `detector::process_lsm_blocked` builds an enriched
        // incident (pattern name, timeline, C2 IP, chain flags hex).
        //
        // Pre-fix the migration shipped without calling that detector — the
        // function had ZERO callers in the workspace. The agent's
        // `knowledge_graph::ingestion::ingest_lsm_exec_blocked` only added a
        // graph edge (`Relation::ExecBlocked`), which never surfaces in the
        // dashboard as an incident. Wiring the detector here makes blocked
        // execves operator-visible alongside the regular `kill_chain:detected`
        // incidents.
        //
        // Today on prod this code path is dormant because the LSM hook is
        // failing to attach (separate bug — see `ebpf_syscall.rs:514`); the
        // wiring is in place so the moment the hook loads, the operator
        // sees actionable "Kill chain BLOCKED" incidents instead of silent
        // graph edges.
        if event.kind == "lsm.exec_blocked" {
            if let Some(blocked_incident) = process_lsm_blocked(&json, tracker) {
                let pattern = evidence_obj(&blocked_incident)
                    .and_then(|ev| ev.get("pattern"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("unknown");
                let kind = format!("killchain.blocked.{}", pattern);
                let mut corr_event = correlation_engine::CorrelationEngine::killchain_event(
                    &kind,
                    serde_json::json!({
                        "pattern": pattern,
                        "severity": "critical",
                        "pid": evidence_obj(&blocked_incident).and_then(|ev| ev.get("pid")),
                        "lsm_blocked": true,
                    }),
                );
                if let Some(iid) = blocked_incident.get("incident_id").and_then(|v| v.as_str()) {
                    corr_event.incident_id = iid.to_string();
                }
                correlation_engine.observe(corr_event);
                all_incidents.push(blocked_incident);
            }
        }
    }

    all_incidents
}

/// Kill chain patterns for which the kernel PID-block is gated by the
/// managed-agent verifier (spec 081). These are exactly the patterns the
/// co-located OpenClaw class trips on its own startup
/// (sensitive-read → outbound-connect): `data_exfil` (sensitive_read|socket)
/// and `exploit_c2` (mprotect|socket — node's V8 JIT RWX + its own outbound
/// socket). For every OTHER pattern (reverse_shell, code_inject, bind_shell,
/// …) the kernel block is registered UNCONDITIONALLY — those are not the
/// managed-agent false-positive shape and an attacker must never buy the
/// kernel-deny exemption by tripping one of them.
const MANAGED_AGENT_GATED_PATTERNS: &[&str] = &["data_exfil", "exploit_c2"];

fn is_managed_agent_gated_pattern(pattern: &str) -> bool {
    MANAGED_AGENT_GATED_PATTERNS
        .iter()
        .any(|p| pattern.eq_ignore_ascii_case(p))
}

/// Spec 081 — kernel PID-block registration, gated by the managed-agent
/// verifier. Runs in the slow_loop (async) AFTER `process_events`, where the
/// agent-guard registry + signature index are reachable.
///
/// For each kill chain incident carrying a pid:
///   - For `data_exfil` / `exploit_c2` (the managed-agent FP shape), consult
///     `managed_agent_guard::verify_managed_agent_self_activity`. If the source
///     is a positively-verified, IW-managed agent acting on its own services,
///     WITHHOLD the kernel block (the irreversible execve-deny) and emit a
///     truthful audit line — the incident + notification still fired in
///     `process_events`. The verifier fails closed: a real attacker, a forged
///     identity, a recycled pid, or an unregistered process is still blocked.
///   - For every other pattern, register the kernel block unconditionally
///     (preserves spec 052 Phase 1b behaviour for the non-FP chains).
///
/// Best-effort + idempotent: if the BLOCKED_PIDS map isn't pinned this is a
/// logged no-op, exactly as before.
pub(crate) async fn register_kernel_blocks(
    incidents: &[serde_json::Value],
    state: &crate::AgentState,
) {
    if incidents.is_empty() {
        return;
    }
    // Snapshot the registry once for this batch (cheap clone-free read behind
    // the async mutex). Held only for the duration of the verification loop.
    let registry = state.agent_registry.lock().await;
    let resolver = crate::managed_agent_guard::SystemProc;

    for inc in incidents {
        let Some(ev) = evidence_obj(inc) else {
            continue;
        };
        let Some(pid) = ev.get("pid").and_then(|p| p.as_u64()) else {
            continue;
        };
        let pid = pid as u32;
        let pattern = ev.get("pattern").and_then(|p| p.as_str()).unwrap_or("");

        // Per-incident decision: Some((agent_id, name)) → WITHHOLD the kernel
        // block (positively-verified managed agent on its own services); None →
        // register the block. Pulled into a pure-of-AgentState helper so the
        // gating logic is testable with a stub resolver + hand-built registry.
        if let Some((agent_id, name)) =
            evaluate_kernel_block_withhold(ev, &registry, &state.signature_index, &resolver)
        {
            let comm = ev.get("comm").and_then(|c| c.as_str()).unwrap_or("");
            warn!(
                pid,
                comm = %comm,
                pattern = %pattern,
                agent_id = %agent_id,
                agent = %name,
                "withheld_kernel_block: managed-agent-self-activity — kill chain {pattern} \
                 attributed to verified managed agent {agent_id} ({name}); kernel PID-block \
                 WITHHELD (incident + notification still fired). Detection unchanged."
            );
            continue;
        }

        // Default: register the kernel block (spec 052 Phase 1b behaviour).
        let reason = format!("kill_chain:{pattern}");
        crate::lsm_policy::register_blocked_pid(pid, &reason);
    }
}

/// Pure-of-`AgentState` per-incident decision for the kernel PID-block (spec
/// 081). `ev` is the killchain incident's evidence object (from
/// [`evidence_obj`]). Returns `Some((agent_id, name))` when the kernel block
/// should be WITHHELD — i.e. the pattern is in the managed-agent-gated set AND
/// `managed_agent_guard::verify_managed_agent_self_activity` returns `Managed`
/// (a positively-verified, IW-managed agent acting on its own services).
/// Returns `None` (block proceeds) for any non-gated pattern, and for a gated
/// pattern whose source fails verification (unregistered pid, forged identity,
/// recycled pid, …) — the verifier fails closed.
///
/// IDENTICAL behaviour to the former inline body of [`register_kernel_blocks`];
/// extracting it lets the gate be exercised with a stub resolver without an
/// async `AgentState`. The caller still owns the actual
/// `register_blocked_pid`/audit-log side effects.
pub(crate) fn evaluate_kernel_block_withhold(
    ev: &serde_json::Value,
    registry: &innerwarden_agent_guard::registry::Registry,
    sigindex: &innerwarden_agent_guard::signatures::SignatureIndex,
    resolver: &dyn crate::managed_agent_guard::ProcResolver,
) -> Option<(String, String)> {
    let pid = ev.get("pid").and_then(|p| p.as_u64())? as u32;
    let pattern = ev.get("pattern").and_then(|p| p.as_str()).unwrap_or("");
    if !is_managed_agent_gated_pattern(pattern) {
        return None;
    }
    let comm = ev.get("comm").and_then(|c| c.as_str()).unwrap_or("");
    // DATA_EXFIL kill chains now carry the sensitive read path (the killchain
    // tracker records the file that set CHAIN_SENSITIVE_READ and emits it as
    // `sensitive_file`, spec-081). When present, the verifier's own-config gate
    // applies on THIS kernel-block path too, exactly like the userspace
    // IP-block path: a subverted-but-genuine managed agent reading a NON-own
    // file (/etc/shadow, another user's key) is NotManaged → the kernel block
    // lands. `exploit_c2` (mprotect-RWX + socket, no file read) legitimately has
    // no path → identity-only verification, as before.
    let read_path = ev.get("sensitive_file").and_then(|p| p.as_str());

    // Fail closed: a DATA_EXFIL chain can ONLY complete through a sensitive
    // `file.open` (that is what sets CHAIN_SENSITIVE_READ), so the tracker
    // always records the path. An absent `sensitive_file` on a data_exfil
    // incident is therefore anomalous — never withhold the kernel block on
    // identity alone for it, because we cannot prove the read was own-config.
    // (exploit_c2 has no file dimension and is exempt from this guard.)
    if pattern.eq_ignore_ascii_case("data_exfil") && read_path.is_none() {
        return None;
    }

    let verdict = crate::managed_agent_guard::verify_managed_agent_self_activity(
        pid, comm, read_path, registry, sigindex, resolver,
        // Destination reputation is not threaded into the kernel-block path
        // today (the kernel block is source-keyed, not dst-keyed); the userspace
        // IP-block path is where a known-bad destination forces the block. Pass
        // false here.
        false,
    );
    match verdict {
        crate::managed_agent_guard::ManagedAgentVerdict::Managed { agent_id, name } => {
            Some((agent_id, name))
        }
        crate::managed_agent_guard::ManagedAgentVerdict::NotManaged => None,
    }
}

/// Write kill chain incidents to the daily JSONL file **and** the unified
/// SQLite store (when available). The JSONL path is retained for legacy
/// consumers; SQLite is the source of truth for dashboard queries, attacker
/// intel, and monthly reports, so missing sqlite writes make kill chain
/// detections invisible to the rest of the agent.
pub(crate) fn write_incidents(
    data_dir: &Path,
    sqlite_store: Option<&innerwarden_store::Store>,
    incidents: &[serde_json::Value],
) {
    if incidents.is_empty() {
        return;
    }

    let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
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
            info!(count = incidents.len(), "killchain: emitted incidents");
        }
        Err(e) => warn!(error = %e, "killchain: failed to write incidents"),
    }

    if let Some(store) = sqlite_store {
        let mut persisted = 0usize;
        for inc in incidents {
            match serde_json::from_value::<innerwarden_core::incident::Incident>(inc.clone()) {
                Ok(parsed) => {
                    // Structural guard: `core::Incident` now tolerates missing
                    // fields via `#[serde(default)]` (spec 035 A5, JSONL
                    // backwards compat), so garbage input like
                    // `{"foo": 1}` parses into a default-filled Incident
                    // with an empty `incident_id`. Drop those before they
                    // reach sqlite — an incident without an id is not an
                    // incident.
                    if parsed.incident_id.is_empty() {
                        warn!("killchain: incident missing incident_id, skipping");
                        continue;
                    }
                    if let Err(e) = store.insert_incident(&parsed) {
                        warn!(error = %e, "killchain: sqlite insert_incident failed");
                    } else {
                        persisted += 1;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "killchain: incident JSON did not match Incident schema");
                }
            }
        }
        if persisted > 0 {
            info!(persisted, "killchain: incidents persisted to sqlite");
        }
    }
}

// 2026-05-02 audit B2/P3 fix: patterns whose required bitmask carries
// strong forensic semantics — reverse shells, code injection, full
// exploit chains. Kernel-level evidence on these chains is not
// something a binary-name heuristic ("ssh is a tool") may overrule.
// `data_exfil` is intentionally absent because it is the noisy 2-bit
// `socket + sensitive_read` signal that fires on legitimate apt/snap
// updates reading /etc/resolv.conf and connecting to mirrors —
// keeping its existing operator-context dismiss is what stops the
// operator's own SSH session from drowning the dashboard in
// false-positive DATA_EXFIL incidents. The auditor's release rule
// (`kill_chain ... must NEVER reach AI decision dismiss with
// confidence >=0.95`) is held by the strong-pattern guard below;
// the data_exfil escape hatch ships at confidence 0.94 (see
// inline-decision write below) so the post-decision untouchable
// gate never sees a 1.0-confidence dismiss for the strong classes.
const STRONG_KILLCHAIN_PATTERNS: &[&str] = &[
    "reverse_shell",
    "bind_shell",
    "code_inject",
    "inject_shell",
    "exploit_shell",
    "exploit_c2",
    "full_exploit",
];

/// True iff the kill chain pattern carries kernel-level forensic
/// semantics that must never be auto-dismissed by binary-name /
/// operator-session heuristics. The auditor (2026-05-02) flagged
/// kill_chain dismisses at 100% confidence for kernel-level evidence
/// as a release blocker; this predicate is the in-process gate.
fn is_strong_killchain_pattern(pattern: &str) -> bool {
    STRONG_KILLCHAIN_PATTERNS
        .iter()
        .any(|p| pattern.eq_ignore_ascii_case(p))
}

/// 2026-05-09: subset of STRONG_KILLCHAIN_PATTERNS where the AI
/// verdict is deterministic (always block) AND the false-positive
/// rate is ~0 because the kernel evidence is precise. For these
/// patterns we shortcut the AI router and write the block decision +
/// execute the block immediately in the slow_loop tick. This cuts the
/// response time by the AI call latency (~100 ms Local Warden, ~1-3 s
/// cloud LLM) and adds resilience: if the AI provider is down, strong
/// patterns still get blocked.
///
/// Deliberately EXCLUDES `data_exfil` and `exploit_c2` even though
/// both are in STRONG_KILLCHAIN_PATTERNS: those have a real FP rate
/// (the codex/openclaw class — npm exec → Cloudflare with
/// socket+sensitive_read), and the AI dismiss path is the right
/// place to filter them. The fast-path is for patterns where the AI
/// has zero useful input.
///
/// The `operator-session` and `self-traffic-comm` dismiss helpers
/// run BEFORE this in the slow_loop; their dismiss decisions block
/// the fast-path via the per-incident decision check below. So the
/// fast-path NEVER overrides an operator-session or self-traffic
/// FP filter.
const FAST_PATH_KILLCHAIN_PATTERNS: &[&str] = &[
    // Emitted by `innerwarden-killchain` crate (the bitmask matcher
    // wired into killchain_inline::process_events). These are the
    // labels seen in prod incidents.
    "reverse_shell",
    "bind_shell",
    "code_inject",
    "inject_shell",
    // Emitted by the userspace sensor detector
    // (crates/sensor/src/detectors/reverse_shell.rs). Same kernel
    // evidence shape (connect+dup2 / bind+listen+dup2), different
    // emitter — sensor-side aggregator with the `ebpf_` prefix.
    // Both detection paths converge on the fast-path so a single
    // implementation change can not silently break it.
    "ebpf_reverse_shell",
    "ebpf_bind_shell",
];

pub(crate) fn is_fast_path_killchain_pattern(pattern: &str) -> bool {
    FAST_PATH_KILLCHAIN_PATTERNS
        .iter()
        .any(|p| pattern.eq_ignore_ascii_case(p))
}

/// Pure predicate: does this incident qualify for the fast-path block?
/// Returns `Some((pattern, c2_ip, incident_id))` when yes.
///
/// Caller is responsible for the per-incident decision-existence check
/// (so fast-path does not override an earlier dismiss). Pulled out as
/// a pure function so the rule itself is unit-testable without a
/// live AgentState.
pub(crate) fn fast_path_extract_block_target(
    inc_json: &serde_json::Value,
) -> Option<(String, String, String)> {
    let ev = inc_json
        .get("evidence")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())?;
    let pattern = ev.get("pattern").and_then(|v| v.as_str())?;
    if !is_fast_path_killchain_pattern(pattern) {
        return None;
    }
    let c2_ip = ev.get("c2_ip").and_then(|v| v.as_str())?;
    if c2_ip.is_empty() {
        return None;
    }
    let incident_id = inc_json.get("incident_id").and_then(|v| v.as_str())?;
    if incident_id.is_empty() {
        return None;
    }
    Some((
        pattern.to_string(),
        c2_ip.to_string(),
        incident_id.to_string(),
    ))
}

/// Phase 7B (audit RC-2 — Slice C): for each kill chain incident
/// whose target IP belongs to an active operator SSH session, write a
/// `dismiss` decision through the standard hash-chained audit path.
/// The operator running `cat /etc/passwd` from their SSH shell is not
/// an attacker, but the eBPF detector legitimately fires on the
/// `socket + sensitive_read` co-occurrence. Pre-7B these incidents
/// stayed decisionless and accumulated in the dashboard's "Stuck >1h"
/// bucket as a false-positive alarm. The dismiss decision carries
/// `ai_provider="operator-session-fp"` and a reason explaining the
/// session match so the audit log makes the call visible.
///
/// 2026-05-02 audit B2/P3: strong kill chain patterns
/// (reverse_shell, code_inject, full_exploit, etc) are skipped here
/// even if the target IP matches the operator session — the auditor
/// observed `kill_chain DATA_EXFIL @ 100% DISMISS` and ruled that
/// kernel-level forensic evidence may not be overruled by IP / binary
/// heuristics. Skipped incidents flow through the standard AI router
/// where `incident_untouchable` forces RequestConfirmation.
pub(crate) fn dismiss_operator_session_incidents(
    data_dir: &Path,
    sqlite_store: Option<&std::sync::Arc<innerwarden_store::Store>>,
    incidents: &[serde_json::Value],
    operator_ips: &std::collections::HashMap<String, std::time::Instant>,
) {
    if incidents.is_empty() || operator_ips.is_empty() {
        return;
    }
    for inc in incidents {
        // Phase 11 fix: the killchain tracker emits `evidence` as an
        // array containing one object (`evidence: [{...}]`). The
        // pre-Phase-11 read tried `.get("evidence").get("c2_ip")`
        // which works only when evidence is an object — silently
        // returning None on the real array schema. Net effect: the
        // operator-session FP dismiss never fired in prod for the
        // 2 weeks since Phase 7B shipped. The helper below reads
        // both shapes (array-of-one and bare object) to keep the
        // dismiss compatible with any tracker variant that lands.
        let evidence_obj = inc.get("evidence").and_then(|e| match e {
            serde_json::Value::Array(arr) => arr.first(),
            obj @ serde_json::Value::Object(_) => Some(obj),
            _ => None,
        });
        let Some(ev) = evidence_obj else { continue };
        let target_ip = ev.get("c2_ip").and_then(|v| v.as_str());
        let Some(target_ip) = target_ip else { continue };
        if !operator_ips.contains_key(target_ip) {
            continue;
        }
        // Match — write the dismiss decision inline.
        let incident_id = inc
            .get("incident_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if incident_id.is_empty() {
            continue;
        }
        let pattern = ev.get("pattern").and_then(|p| p.as_str()).unwrap_or("?");
        // 2026-05-02 audit B2 guard: kernel-level forensic patterns
        // (reverse_shell, full_exploit, code_inject, ...) must reach
        // the AI router so incident_untouchable can force
        // RequestConfirmation. The IP-match heuristic is strong but
        // not strong enough to overrule kernel evidence.
        if is_strong_killchain_pattern(pattern) {
            warn!(
                incident_id = %incident_id,
                pattern = %pattern,
                target_ip = %target_ip,
                "killchain: skipping operator-session-fp dismiss for strong pattern \
                 (audit B2/P3) — incident routes through AI router + untouchable"
            );
            continue;
        }
        let entry = crate::decisions::DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_id.to_string(),
            host: std::env::var("HOSTNAME")
                .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
                .unwrap_or_else(|_| "unknown".to_string()),
            ai_provider: "operator-session-fp".to_string(),
            action_type: "dismiss".to_string(),
            target_ip: Some(target_ip.to_string()),
            target_user: None,
            skill_id: None,
            confidence: 1.0,
            auto_executed: true,
            dry_run: false,
            reason: format!(
                "Auto-dismissed: kill chain {pattern} target IP matches an active operator SSH \
                 session ({target_ip}). The operator's own shell tripped the socket+sensitive_read \
                 pattern; this is a known false positive on operator-initiated activity."
            ),
            estimated_threat: "none".to_string(),
            execution_result: "dismissed".to_string(),
            prev_hash: None,
            decision_layer: Some("killchain_fast_path".to_string()),
        };
        if let Err(e) = crate::decisions::append_chained(data_dir, &entry, sqlite_store) {
            warn!(
                incident_id = %incident_id,
                error = %e,
                "killchain: failed to write operator-session-fp dismiss decision"
            );
        }
    }
}

/// Phase 11 (audit RC-2 / 2026-04-29 Slice C+): kill chain incidents
/// where the process making the socket is a well-known operator or
/// system tool (`ssh`, `scp`, `rsync`, `apt`, `snap`, etc.) running
/// under a regular-user uid (>=1000) are auto-dismissed inline. This
/// is the "Microsoft Azure outbound apt update" class of false
/// positives that surfaced post-Phase-7 — the agent's own apt/snap
/// update process trips `socket+sensitive_read` against legitimate
/// cloud destinations and the dashboard reports them as DATA_EXFIL.
///
/// The dismiss carries `ai_provider="self-traffic-fp"` and a reason
/// explaining the process+uid match so the audit log makes the call
/// visible. The operator can grep decisions for this provider to
/// audit all auto-dismissed false positives over time.
///
/// Heuristic — process is "self-traffic-class" when:
/// 1. comm is in `SELF_TRAFFIC_COMMS` (operator/system tools), AND
/// 2. uid >= 1000 (regular operator) OR uid == 0 (root, system tool)
///
/// Anything else stays for the AI router to decide.
///
/// 2026-05-03: this list is the **single source of truth** for what
/// the agent considers "operator/system traffic that legitimately
/// trips kill_chain's `socket + sensitive_read` co-occurrence". Both
/// `dismiss_self_traffic_incidents` (which writes the dismiss
/// decision) and `notify_telegram` (which suppresses the Telegram
/// alert) consume from `self_traffic_comms(cfg)` so they cannot
/// drift out of sync. Pre-2026-05-03 they had separate constants —
/// the dismiss list included `apt`/`snap`/`cloud-init`, the
/// Telegram allowlist did not, so operators saw "Critical Threat"
/// alerts for apt updates while the AI silently dismissed them.
///
/// Operators can extend this list per-deploy via
/// `[killchain] self_traffic_comms_extra = ["puppet", "chef"]` in
/// agent.toml. Builtins below cover the common Linux tooling.
pub(crate) const BUILTIN_SELF_TRAFFIC_COMMS: &[&str] = &[
    // Operator-driven outbound tooling: SSH jumps, file copies, git ops, package managers.
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "git",
    "git-remote-", // git-remote-https etc (truncated form)
    "curl",
    "wget",
    // 2026-05-05 (Wave 9b): libcurl-using package fetchers (apt, snap, etc)
    // launch worker threads whose `comm` becomes the protocol scheme rather
    // than the parent binary name. On 2026-04-28..05-04 prod these accounted
    // for 77 of 169 (45%) killchain DATA_EXFIL incidents that did not get
    // auto-dismissed because the comms were absent from this list. Kept
    // separately from `apt`/`snap` so a future contributor sees the
    // motivation; the prefix matcher in `matches_self_traffic_comm` does
    // not actually need them broken out.
    "http",
    "https",
    // System package management & daemons that legitimately do
    // socket + sensitive_read against cloud / mirror endpoints.
    "apt",
    "apt-get",
    "snap",
    "snapd",
    "systemd-resolv",  // truncated systemd-resolved
    "systemd-network", // truncated systemd-networkd
    "chronyd",
    "ntpd",
    "fwupdmgr",
    "unattended-upgr", // truncated unattended-upgrade
    "needrestart",
    // Cloud-init / systemd helpers that fetch metadata at boot.
    "cloud-init",
];

/// Subset of [`BUILTIN_SELF_TRAFFIC_COMMS`] whose dismissal does NOT require
/// the uid to be either 0 or >=1000.
///
/// **Why this exists.** The general uid filter (`uid == 0 || uid >= 1000`)
/// was added to catch lateral-movement-flavoured cases like `www-data` (uid
/// 33) running `ssh`. For ssh / scp / git / rsync that is the right call,
/// because those comms can spawn shells and pivot. For pure network-fetcher
/// comms (`apt`, `http`, `https`, `wget`, package daemons) the uid is
/// largely irrelevant: the operation is "download from a public host" and
/// the worst-case interpretation of an unexpected uid is "compromised
/// service used the package manager", which still does not warrant a
/// `kill_chain DATA_EXFIL @ Critical` alert.
///
/// **Real-world prod symptom.** Debian/Ubuntu apt runs its HTTPS download
/// step under uid 105 (`_apt`, the unprivileged sandbox), and the worker's
/// `comm` becomes `http` or `https` rather than `apt`. Pre-Wave-9b that hit
/// BOTH gates (comm not in list AND uid 105 fails the {0, >=1000} check),
/// so the operator's nightly apt update produced 9-15 critical "DATA_EXFIL
/// to Ubuntu mirror IP" incidents per day that reached the AI router.
///
/// **Login-shell tools deliberately stay uid-checked.** `ssh`, `scp`,
/// `sftp`, `rsync`, `git`, `git-remote-` are NOT in this set. The lateral-
/// movement risk on those comms still justifies the {0, >=1000} gate.
const UID_AGNOSTIC_FETCHER_COMMS: &[&str] = &[
    "apt",
    "apt-get",
    "snap",
    "snapd",
    "http",
    "https",
    "curl",
    "wget",
    "systemd-resolv",
    "systemd-network",
    "chronyd",
    "ntpd",
    "fwupdmgr",
    "unattended-upgr",
    "needrestart",
    "cloud-init",
];

/// True iff `comm` is a network-fetcher tool whose dismissal does not need
/// the uid to be in `{0, >=1000}`. Uses the same prefix-match semantics as
/// [`matches_self_traffic_comm`].
fn comm_is_uid_agnostic_fetcher(comm: &str) -> bool {
    if comm.is_empty() {
        return false;
    }
    UID_AGNOSTIC_FETCHER_COMMS
        .iter()
        .any(|prefix| comm == *prefix || comm.starts_with(*prefix))
}

/// Returns the merged self-traffic comm list: builtins + operator
/// additions from `[killchain].self_traffic_comms_extra`. This is
/// the function both consumers (dismiss + telegram-suppress) MUST
/// call; never bypass to read `BUILTIN_SELF_TRAFFIC_COMMS` directly,
/// or operator-added comms get ignored.
pub(crate) fn self_traffic_comms(cfg: &crate::config::KillchainConfig) -> Vec<String> {
    let mut merged: Vec<String> = BUILTIN_SELF_TRAFFIC_COMMS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    for extra in &cfg.self_traffic_comms_extra {
        let trimmed = extra.trim();
        if !trimmed.is_empty() && !merged.iter().any(|c| c == trimmed) {
            merged.push(trimmed.to_string());
        }
    }
    merged
}

/// Match a process `comm` against a self-traffic comm list using the
/// same prefix-match semantics as the original constant (e.g.
/// `git-remote-` covers `git-remote-https`).
pub(crate) fn matches_self_traffic_comm(comm: &str, list: &[String]) -> bool {
    if comm.is_empty() {
        return false;
    }
    list.iter()
        .any(|prefix| comm == prefix.as_str() || comm.starts_with(prefix.as_str()))
}

pub(crate) fn dismiss_self_traffic_incidents(
    data_dir: &Path,
    sqlite_store: Option<&std::sync::Arc<innerwarden_store::Store>>,
    incidents: &[serde_json::Value],
    self_traffic_list: &[String],
) {
    if incidents.is_empty() {
        return;
    }
    for inc in incidents {
        // Pull comm + uid from the structured evidence (Phase 11
        // schema bump in `crates/killchain`). Bail on missing fields
        // so a future schema change doesn't silently mis-dismiss.
        let evidence = inc.get("evidence").and_then(|v| v.as_array());
        let Some(evidence_arr) = evidence else {
            continue;
        };
        let Some(ev) = evidence_arr.first() else {
            continue;
        };
        let comm = ev.get("comm").and_then(|v| v.as_str()).unwrap_or("");
        let uid = ev.get("uid").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
        let pid = ev.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
        let pattern = ev
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let c2_ip = ev
            .get("c2_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if comm.is_empty() {
            continue;
        }

        // Self-traffic check: comm matches a known operator/system tool.
        if !matches_self_traffic_comm(comm, self_traffic_list) {
            continue;
        }
        // Uid policy:
        //   - Login-shell tools (ssh, scp, sftp, rsync, git, git-remote-)
        //     require uid in {0, >=1000}. Service-account uids (1-999)
        //     running these comms could be lateral movement and deserve a
        //     real AI decision.
        //   - Network-fetcher tools (apt, http, https, wget, snap, ...)
        //     are uid-agnostic. The operation is "download from a public
        //     host", not shell escalation, so the uid is irrelevant to
        //     the FP determination. This unblocks the apt-as-_apt (uid
        //     105) case that flooded prod with FP DATA_EXFIL incidents
        //     pre-Wave-9b.
        let uid_ok = comm_is_uid_agnostic_fetcher(comm) || uid == 0 || uid >= 1000;
        if !uid_ok {
            continue;
        }

        let incident_id = inc
            .get("incident_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if incident_id.is_empty() {
            continue;
        }
        // 2026-05-02 audit B2 guard: kernel-level forensic patterns
        // (reverse_shell, full_exploit, code_inject, ...) must NEVER
        // be silently dismissed by a binary-name heuristic — even if
        // the comm is `ssh` and the uid is 0/operator. The auditor
        // saw "kill_chain DATA_EXFIL → DISMISS @ 100%" with rationale
        // 'ssh is a known operator/system tool' and ruled that
        // kernel-level fd-redirect-to-socket evidence may not be
        // overruled here. Skipped incidents flow through the AI
        // router and hit `incident_untouchable::transform`.
        if is_strong_killchain_pattern(&pattern) {
            warn!(
                incident_id = %incident_id,
                pattern = %pattern,
                comm = %comm,
                uid = %uid,
                "killchain: skipping self-traffic-fp dismiss for strong pattern \
                 (audit B2/P3) — incident routes through AI router + untouchable"
            );
            continue;
        }
        let entry = crate::decisions::DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_id.to_string(),
            host: std::env::var("HOSTNAME")
                .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
                .unwrap_or_else(|_| "unknown".to_string()),
            ai_provider: "self-traffic-fp".to_string(),
            action_type: "dismiss".to_string(),
            target_ip: if c2_ip.is_empty() {
                None
            } else {
                Some(c2_ip.clone())
            },
            target_user: None,
            skill_id: None,
            confidence: 1.0,
            auto_executed: true,
            dry_run: false,
            reason: format!(
                "Auto-dismissed: kill chain {pattern} target {c2_ip} fired by process \
                 {comm} (PID {pid}, UID {uid}). {comm} is a known operator/system tool, \
                 not attacker activity (apt/snap update, ssh jump, git fetch, etc)."
            ),
            estimated_threat: "none".to_string(),
            execution_result: "dismissed".to_string(),
            prev_hash: None,
            decision_layer: Some("killchain_fast_path".to_string()),
        };
        if let Err(e) = crate::decisions::append_chained(data_dir, &entry, sqlite_store) {
            warn!(
                incident_id = %incident_id,
                error = %e,
                "killchain: failed to write self-traffic-fp dismiss decision"
            );
        }
    }
}

/// 2026-05-09: shortcut the AI router for kill_chain patterns where
/// the AI verdict is deterministic (always block) AND the FP rate is
/// ~0. Runs in the slow_loop tick AFTER `dismiss_operator_session_incidents`
/// and `dismiss_self_traffic_incidents` so any earlier dismiss decision
/// short-circuits the fast-path block (we re-check the SQLite decisions
/// table before blocking).
///
/// Latency win on prod: removes the AI call from the dispatch path
/// (~100 ms Local Warden, ~1-3 s cloud LLM). The slow_loop tick
/// cadence (`incident_poll_secs = 2` default) is unchanged — this is
/// not a kernel-time response. For sub-second response see the
/// future `bpf_send_signal()` spec.
///
/// Resilience win: if the AI provider is down or rate-limited, strong
/// patterns still get blocked at this layer.
///
/// Cost win: zero LLM call cost for fast-path patterns.
///
/// Determinism win: the verdict is the rule, not a model output.
/// A future Local Warden retrain that drifts on these patterns does
/// not change behaviour.
pub(crate) async fn fast_path_block_strong_patterns(
    incidents: &[serde_json::Value],
    data_dir: &std::path::Path,
    cfg: &crate::config::AgentConfig,
    state: &mut crate::AgentState,
) {
    if incidents.is_empty() {
        return;
    }
    // Skill picker: same convention as local_classifier::decide and
    // correlation_response. `format!("block-ip-{}", block_backend)` —
    // operator's configured firewall backend wins.
    let block_skill_id = format!("block-ip-{}", cfg.responder.block_backend);

    for inc_json in incidents {
        let Some((pattern, c2_ip, incident_id)) = fast_path_extract_block_target(inc_json) else {
            continue;
        };

        // Per-incident decision-existence check. The dismiss helpers
        // (operator-session, self-traffic-comm, cloud-destination not
        // landed) write their dismiss decisions BEFORE this function
        // runs in the slow_loop. If any decision is already on file
        // for this incident, the fast-path defers — never overrides
        // an earlier verdict.
        if let Some(store) = state.sqlite_store.as_ref() {
            if store
                .decisions_for_incident(&incident_id)
                .map(|d| !d.is_empty())
                .unwrap_or(false)
            {
                continue;
            }
        }

        // Parse the killchain JSON into a structured Incident. If the
        // schema does not match (e.g. older killchain emitter), skip
        // — the AI router path will pick it up later.
        let incident: innerwarden_core::incident::Incident =
            match serde_json::from_value(inc_json.clone()) {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!(
                        incident_id = %incident_id,
                        error = %e,
                        "killchain fast-path: incident JSON did not parse, deferring to AI router"
                    );
                    continue;
                }
            };

        // Synthetic AiDecision tagged with `ai_provider="fast-path-strong-pattern"`
        // so the audit trail is unambiguous: this block was not the AI's
        // verdict, it was the rule.
        let decision = crate::ai::AiDecision {
            action: crate::ai::AiAction::BlockIp {
                ip: c2_ip.clone(),
                skill_id: block_skill_id.clone(),
            },
            confidence: 1.0,
            auto_execute: true,
            reason: format!(
                "Fast-path: kill chain pattern `{pattern}` is in the deterministic-block \
                 set (reverse_shell / bind_shell / code_inject / inject_shell). The AI \
                 verdict for these is always `block_ip`; we shortcut the AI call to cut \
                 response time and stay resilient when the AI provider is degraded. \
                 Existing safeguards still apply: circuit breaker, rate limit, safelist, \
                 cloud-provider check, untouchable gate."
            ),
            alternatives: vec![],
            estimated_threat: "critical".to_string(),
        };

        // Delegate to the canonical block executor. This inherits all
        // existing safeguards: circuit breaker (max blocks/hour),
        // per-minute rate limit, eligibility check (operator session,
        // safelist, cloud-provider gate), and writes the audit decision
        // through the standard hash-chained path.
        let _ = crate::decision_block_ip::execute_block_ip_decision(
            &c2_ip,
            &block_skill_id,
            &decision,
            &incident,
            data_dir,
            cfg,
            state,
        )
        .await;
    }
}

/// Service-process allowlist — distinct from `BUILTIN_SELF_TRAFFIC_COMMS`.
/// These are long-running services (web gateways, runtimes, databases)
/// whose `socket + dup` co-occurrence is normal during request
/// handling. Different semantic from self-traffic (operator/system
/// tooling). Kept as its own const because they are operationally
/// different concepts; merging would mis-skip apt-vs-postgres.
const KILLCHAIN_SERVICE_ALLOWLIST: &[&str] = &[
    "ruby",
    "python",
    "python3",
    "node",
    "java",
    "beam.smp", // runtimes
    "nginx",
    "haproxy",
    "envoy",
    "caddy", // proxies
    "postgres",
    "mysqld",
    "redis-server", // databases
    "openclaw",
    "innerwarden", // our own
];

/// Notify via Telegram for critical kill chain detections.
/// Gated through the centralized notification gate.
///
/// 2026-05-03 (PR #417): `self_traffic_list` is the SAME list
/// `dismiss_self_traffic_incidents` uses — keeps the two paths in
/// lock-step. Without this, the operator received Telegram alerts
/// for apt/snap/cloud-init updates that the AI then silently
/// auto-dismissed (the previous version of this function had its
/// own hardcoded service allowlist that lacked apt/snap/etc).
pub(crate) fn notify_telegram(
    telegram_client: &Option<std::sync::Arc<crate::telegram::TelegramClient>>,
    incidents: &[serde_json::Value],
    burst_tracker: &crate::notification_gate::BurstTracker,
    deferred: &mut std::collections::HashMap<String, u32>,
    gate_suppressed_counter: &AtomicU64,
    self_traffic_list: &[String],
    host: &str,
) {
    let Some(tg) = telegram_client else { return };

    for inc in incidents {
        let severity = inc
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("medium");
        if severity != "critical" {
            continue;
        }

        // Skip known service processes (socket+dup is normal for them).
        let comm = evidence_obj(inc)
            .and_then(|ev| ev.get("comm"))
            .and_then(|c| c.as_str())
            .unwrap_or("");
        if KILLCHAIN_SERVICE_ALLOWLIST
            .iter()
            .any(|a| comm.starts_with(a))
        {
            continue;
        }
        // 2026-05-03: also skip self-traffic comms (apt, snap, ssh,
        // cloud-init, ...). The dismiss path will write a
        // `self-traffic-fp` decision shortly; suppressing the alert
        // here means the operator never gets paged for an apt update.
        if matches_self_traffic_comm(comm, self_traffic_list) {
            continue;
        }

        // Gate through notification policy.
        let ctx = crate::notification_gate::NotificationContext::from_killchain_json(inc);
        let verdict =
            crate::notification_gate::should_notify_with_counter(&ctx, gate_suppressed_counter);

        match verdict {
            crate::notification_gate::NotificationVerdict::SendNow => {
                let title = inc
                    .get("title")
                    .and_then(|t| t.as_str())
                    .unwrap_or("Kill chain detected");
                let summary = inc.get("summary").and_then(|s| s.as_str()).unwrap_or("");
                let pattern = evidence_obj(inc)
                    .and_then(|ev| ev.get("pattern"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("unknown");

                let msg = format!(
                    "\u{26d3}\u{fe0f} <b>Kill Chain Alert</b>\n\n\
                     \u{1f534} CRITICAL\n\
                     <b>{title}</b>\n\
                     Pattern: {pattern}\n\
                     {summary}",
                );
                let tg = tg.clone();
                tokio::spawn(async move {
                    let _ = tg.send_alert_html(&msg).await;
                });
            }
            crate::notification_gate::NotificationVerdict::DailyBriefingOnly => {
                *deferred.entry(ctx.detector.clone()).or_insert(0) += 1;
                if ctx.is_contained {
                    let category = crate::notification_gate::burst_category(&ctx.detector);
                    // Attacker IP best-effort from the kill-chain evidence
                    // (C2 endpoint) so the burst summary can count sources.
                    let source_ip = evidence_obj(inc)
                        .and_then(|ev| {
                            ev.get("c2_ip")
                                .or_else(|| ev.get("source_ip"))
                                .or_else(|| ev.get("remote_ip"))
                        })
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty());
                    if let Some(mut summary) = burst_tracker.record_contained(category, source_ip) {
                        summary.host = host.to_string();
                        let msg = crate::notification_gate::format_burst_summary(host, &summary);
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let _ = tg.send_alert_html(&msg).await;
                        });
                    }
                }
                info!(
                    detector = %ctx.detector,
                    "killchain notification deferred to daily briefing"
                );
            }
            crate::notification_gate::NotificationVerdict::Drop => {}
        }
    }
}

/// Return the first/only evidence object from a kill chain incident.
///
/// The killchain crate (`tracker.rs:329 / :429`) wraps evidence as
/// `"evidence": [evidence_obj]` — a single-element array. Pre-Spec 053
/// (2026-05-22) six call sites in this file accessed it as `.get("pid")`,
/// `.get("pattern")`, `.get("comm")` directly on the array Value, which
/// silently returned None. The result: correlation_engine received
/// `pattern="unknown"` for every chain, `pid=null` for every chain,
/// `dismiss_self_traffic_incidents` had comm="" so its allowlist never
/// matched, etc. All bugs silent because of `.unwrap_or` fallbacks.
///
/// Use this helper instead of inline `.get("evidence").and_then(...)`
/// chains. Also tolerates an Object shape (forward-compat — if the
/// tracker ever drops the array wrap), matching line 368's pattern that
/// was already doing the right thing.
fn evidence_obj(inc: &serde_json::Value) -> Option<&serde_json::Value> {
    inc.get("evidence").and_then(|e| match e {
        serde_json::Value::Array(arr) => arr.first(),
        obj @ serde_json::Value::Object(_) => Some(obj),
        _ => None,
    })
}

/// Convert an innerwarden_core::Event to the JSON format expected by PidTracker.
fn event_to_tracker_json(event: &innerwarden_core::event::Event) -> serde_json::Value {
    serde_json::json!({
        "kind": event.kind,
        "source": event.source,
        "host": event.host,
        "ts": event.ts.to_rfc3339(),
        "details": event.details,
    })
}

/// Periodic maintenance: clean up stale PIDs from the tracker.
pub(crate) fn cleanup_stale(tracker: &mut PidTracker) {
    tracker.cleanup_stale();
}

/// Get tracker stats for telemetry/logging.
pub(crate) fn stats(tracker: &PidTracker) -> (usize, usize, usize) {
    tracker.stats()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test fixture: builtins-only self-traffic list (no config extras).
    /// Mirrors what `self_traffic_comms(default_cfg)` returns at runtime.
    fn test_self_traffic_list() -> Vec<String> {
        BUILTIN_SELF_TRAFFIC_COMMS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    // ── Spec 053 anchors — evidence_obj helper ────────────────────────
    //
    // Six call sites in this file used to access `evidence.pid` /
    // `evidence.pattern` / `evidence.comm` as if `evidence` were a JSON
    // object, but `crates/killchain/src/tracker.rs:329 / :429` wraps
    // it in an array `[evidence]`. JSON's `.get(string)` on an Array
    // returns None silently, so:
    //   - correlation_engine was always fed `pattern="unknown"`
    //   - correlation_engine pid field was always null
    //   - dismiss_self_traffic_incidents had comm="" → allowlist never matched
    //   - notification builder said "unknown" pattern in operator messages
    //   - register_blocked_pid (Spec 052 Phase 1b) was never called
    // All silent because every site had `.unwrap_or(...)` fallback.
    //
    // These anchors prevent the same class of bug returning if the
    // tracker output shape changes again.

    fn build_incident_with_array_evidence(
        pid: u32,
        pattern: &str,
        comm: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "incident_id": format!("kill_chain:detected:{}:{}:2026-05-22T16:00Z", pattern, pid),
            "severity": "critical",
            "evidence": [{
                "pid": pid,
                "pattern": pattern,
                "comm": comm,
                "chain_flags": "0x101",
            }],
        })
    }

    #[test]
    fn evidence_obj_extracts_from_array_shape() {
        let inc = build_incident_with_array_evidence(1234, "data_exfil", "python3");
        let ev = evidence_obj(&inc).expect("array evidence must resolve");
        assert_eq!(ev.get("pid").and_then(|v| v.as_u64()), Some(1234));
        assert_eq!(
            ev.get("pattern").and_then(|v| v.as_str()),
            Some("data_exfil")
        );
        assert_eq!(ev.get("comm").and_then(|v| v.as_str()), Some("python3"));
    }

    #[test]
    fn evidence_obj_tolerates_object_shape_forward_compat() {
        // If the tracker ever drops the array wrap (one-element arrays
        // are awkward), the same helper still works. This is the same
        // pattern used by line 368's dismiss_operator_session_incidents
        // — keep both call sites consistent.
        let inc = serde_json::json!({
            "incident_id": "kill_chain:detected:data_exfil:1234:2026-05-22T16:00Z",
            "evidence": { "pid": 1234, "pattern": "data_exfil", "comm": "python3" },
        });
        let ev = evidence_obj(&inc).expect("object evidence must resolve");
        assert_eq!(ev.get("pid").and_then(|v| v.as_u64()), Some(1234));
    }

    #[test]
    fn evidence_obj_returns_none_when_evidence_missing() {
        let inc = serde_json::json!({
            "incident_id": "kill_chain:detected:data_exfil:1234:2026-05-22T16:00Z",
        });
        assert!(evidence_obj(&inc).is_none());
    }

    #[test]
    fn evidence_obj_returns_none_when_evidence_empty_array() {
        let inc = serde_json::json!({
            "incident_id": "kill_chain:detected:data_exfil:1234:2026-05-22T16:00Z",
            "evidence": [],
        });
        assert!(evidence_obj(&inc).is_none());
    }

    #[test]
    fn evidence_obj_returns_none_for_invalid_shape() {
        // Number/string/bool/null all reject — only Array/Object accepted.
        for bogus in [
            serde_json::json!({ "evidence": null }),
            serde_json::json!({ "evidence": 42 }),
            serde_json::json!({ "evidence": "string" }),
            serde_json::json!({ "evidence": true }),
        ] {
            assert!(
                evidence_obj(&bogus).is_none(),
                "evidence_obj must reject non-Array/Object: {bogus:?}"
            );
        }
    }

    #[test]
    fn evidence_obj_demonstrates_the_silent_bug_the_old_code_had() {
        // ANTI-REGRESSION: this test captures exactly what the buggy
        // pre-Spec-053 code was doing. If anyone reverts to the inline
        // pattern, this assertion documents why it's broken.
        let inc = build_incident_with_array_evidence(1234, "data_exfil", "python3");

        // OLD (BUGGY): `.get("evidence").and_then(|e| e.get("pid"))`
        // Returns None because evidence is an Array, not an Object.
        let buggy = inc
            .get("evidence")
            .and_then(|e| e.get("pid"))
            .and_then(|v| v.as_u64());
        assert_eq!(
            buggy, None,
            "documenting the silent bug: array.get(string) returns None"
        );

        // NEW (CORRECT): via evidence_obj helper.
        let correct = evidence_obj(&inc)
            .and_then(|ev| ev.get("pid"))
            .and_then(|v| v.as_u64());
        assert_eq!(correct, Some(1234), "helper recovers the pid");
    }

    // ── Spec 052 Phase 1b — gap E anchor (sched_process_exit GC) ────
    //
    // `process_events` must call `lsm_policy::unregister_blocked_pid`
    // when an Event with `kind == "process.exit"` arrives, so dead
    // PIDs don't accumulate in BLOCKED_PIDS (LRU fallback exists but
    // is the long way around). On non-Linux the underlying function
    // is a no-op stub — the test here verifies the WIRING happens
    // (no panic, no incident-emit side effect) regardless of platform.

    #[test]
    fn process_exit_event_triggers_gc_path_without_panic() {
        let mut tracker = PidTracker::new();
        let mut engine = correlation_engine::CorrelationEngine::new();
        let exit_event = innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "process.exit".into(),
            severity: innerwarden_core::event::Severity::Info,
            summary: String::new(),
            details: serde_json::json!({ "pid": 4242u32, "comm": "python3", "exit_code": 0 }),
            tags: vec![],
            entities: vec![],
        };
        let incidents = process_events(&mut tracker, &[exit_event], &mut engine);
        // process.exit alone doesn't trigger a kill chain — no incidents.
        assert!(
            incidents.is_empty(),
            "process.exit alone must not fire chain"
        );
        // The important assertion is that we got HERE without panicking
        // (verifying the unregister_blocked_pid wiring is callable).
    }

    #[test]
    fn process_exit_without_pid_does_not_call_unregister() {
        // Defensive: process.exit events with missing/null pid must
        // skip the GC path silently instead of panicking on as_u64().
        let mut tracker = PidTracker::new();
        let mut engine = correlation_engine::CorrelationEngine::new();
        let bad_event = innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "process.exit".into(),
            severity: innerwarden_core::event::Severity::Info,
            summary: String::new(),
            details: serde_json::json!({ "comm": "python3" }), // no pid
            tags: vec![],
            entities: vec![],
        };
        let _ = process_events(&mut tracker, &[bad_event], &mut engine);
        // No panic = test passes.
    }

    // ── Phase 7B Slice C anchors ────────────────────────────────────
    //
    // dismiss_operator_session_incidents must (1) skip non-operator
    // IPs entirely, (2) write a dismiss decision when c2_ip matches an
    // active operator session, and (3) be a no-op on empty inputs.

    #[test]
    fn dismiss_operator_session_skips_non_operator_target() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:2026-04-29T10:00Z",
            "evidence": {
                "c2_ip": "203.0.113.99",
                "pattern": "DATA_EXFIL",
            }
        })];
        // operator_ips is empty — c2_ip 203.0.113.99 must NOT match.
        let operator_ips: std::collections::HashMap<String, std::time::Instant> =
            std::collections::HashMap::new();
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &incidents, &operator_ips);
        assert_eq!(store.decisions_count().unwrap(), 0);
    }

    /// 2026-05-21 anchor: lsm.exec_blocked events with the kernel marker
    /// `KILL_CHAIN_BLOCKED` in the filename slot must surface as
    /// enriched incidents via `killchain::detector::process_lsm_blocked`.
    /// Pre-fix the migration shipped without calling that detector at
    /// all — the function had zero callers in the workspace — so a
    /// real kernel LSM block produced only a silent KG edge instead
    /// of an operator-visible "Kill chain BLOCKED" critical incident.
    #[test]
    fn process_events_enriches_lsm_blocked_into_killchain_incident() {
        use chrono::Utc;
        use innerwarden_core::event::{Event, Severity};

        let mut tracker = PidTracker::new();
        // Seed the tracker with enough chain flags to make the LSM
        // detector emit an enriched incident (without a tracked PID it
        // falls back to a minimal-info incident — still operator-visible).
        // The kernel emits the event when its own chain check fires,
        // so the PID state is normally pre-populated. Even without it
        // the detector returns Some on the well-formed event.
        let mut engine = correlation_engine::CorrelationEngine::new();
        let now = Utc::now();
        let lsm_event = Event {
            ts: now,
            host: "h".into(),
            source: "ebpf".into(),
            kind: "lsm.exec_blocked".into(),
            severity: Severity::High,
            summary: "kernel LSM blocked execve".into(),
            details: serde_json::json!({
                "pid": 42u32,
                "uid": 1000u32,
                "comm": "bash",
                "filename": "KILL_CHAIN_BLOCKED",
            }),
            tags: vec![],
            entities: vec![],
        };

        let incidents = process_events(&mut tracker, &[lsm_event], &mut engine);

        assert!(
            !incidents.is_empty(),
            "lsm.exec_blocked with KILL_CHAIN_BLOCKED marker must enrich \
             into at least one incident"
        );
        let blocked = incidents
            .iter()
            .find(|inc| {
                inc.get("incident_id")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s.starts_with("kill_chain:blocked:"))
            })
            .expect("must produce kill_chain:blocked:* incident");
        let title = blocked.get("title").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            title.contains("Kill chain BLOCKED"),
            "title must reflect the LSM block — got: {title}"
        );
    }

    #[test]
    fn dismiss_operator_session_writes_dismiss_when_target_is_operator() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:2026-04-29T10:00Z",
            "evidence": {
                "c2_ip": "203.0.113.99",
                "pattern": "DATA_EXFIL",
            }
        })];
        let mut operator_ips = std::collections::HashMap::new();
        operator_ips.insert("203.0.113.99".to_string(), std::time::Instant::now());
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &incidents, &operator_ips);
        assert_eq!(store.decisions_count().unwrap(), 1);
        let decisions = store
            .decisions_for_incident("kill_chain:detected:DATA_EXFIL:2026-04-29T10:00Z")
            .unwrap();
        assert_eq!(decisions.len(), 1);
        // The decision JSON line must encode the auto-dismiss
        // explanation the operator can audit later.
        let decoded: serde_json::Value = serde_json::from_str(&decisions[0]).unwrap();
        assert_eq!(decoded["action_type"], "dismiss");
        assert_eq!(decoded["ai_provider"], "operator-session-fp");
    }

    #[test]
    fn dismiss_operator_session_handles_array_evidence_from_tracker() {
        // The killchain tracker emits `evidence: [{...}]` (array of
        // one object). Pre-Phase-11 the dismiss helper read from
        // object-shape evidence and silently failed on array data,
        // so the operator-session FP never fired in prod for 2 weeks
        // after Phase 7B was deployed. This anchor pins the
        // array-shape read path so the regression is caught at
        // build time if the read regresses.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:1234:2026-04-29T15:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "20.26.156.215",
                "pid": 1234,
                "comm": "ssh",
                "uid": 1001,
            }]
        })];
        let mut operator_ips = std::collections::HashMap::new();
        operator_ips.insert("20.26.156.215".to_string(), std::time::Instant::now());
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &incidents, &operator_ips);
        assert_eq!(
            store.decisions_count().unwrap(),
            1,
            "array-shape evidence must be read correctly"
        );
    }

    #[test]
    fn dismiss_operator_session_is_noop_when_inputs_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let mut operator_ips = std::collections::HashMap::new();
        operator_ips.insert("10.0.0.5".to_string(), std::time::Instant::now());
        // Empty incidents.
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &[], &operator_ips);
        assert_eq!(store.decisions_count().unwrap(), 0);
        // Empty operator_ips, with incidents.
        let incidents = vec![serde_json::json!({
            "incident_id": "x:y",
            "evidence": {"c2_ip": "1.2.3.4"}
        })];
        let empty_ops: std::collections::HashMap<String, std::time::Instant> =
            std::collections::HashMap::new();
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &incidents, &empty_ops);
        assert_eq!(store.decisions_count().unwrap(), 0);
    }

    // ── Phase 11A: self-traffic FP anchors ────────────────────────────
    //
    // dismiss_self_traffic_incidents must (1) write a dismiss when
    // comm matches a self-traffic tool with operator uid, (2) skip
    // incidents whose process is unknown / a service account, (3)
    // be a no-op on incidents missing structured pid/comm/uid in
    // evidence (forward-compatibility with older tracker schemas).

    #[test]
    fn dismiss_self_traffic_writes_dismiss_for_apt_root() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:1234:2026-04-29T10:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "20.26.156.215",
                "pid": 1234,
                "comm": "apt",
                "uid": 0,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 1);
        let decisions = store
            .decisions_for_incident("kill_chain:detected:DATA_EXFIL:1234:2026-04-29T10:00Z")
            .unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&decisions[0]).unwrap();
        assert_eq!(decoded["action_type"], "dismiss");
        assert_eq!(decoded["ai_provider"], "self-traffic-fp");
    }

    #[test]
    fn dismiss_self_traffic_writes_dismiss_for_ssh_operator_uid() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:5678:2026-04-29T11:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "203.0.113.50",
                "pid": 5678,
                "comm": "ssh",
                "uid": 1001,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 1);
    }

    #[test]
    fn dismiss_self_traffic_skips_unknown_comm() {
        // A process that's not in SELF_TRAFFIC_COMMS must NOT be
        // dismissed — needs to go to the AI router for a real call.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:9999:2026-04-29T12:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "203.0.113.99",
                "pid": 9999,
                "comm": "evil_tool",
                "uid": 1001,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 0);
    }

    #[test]
    fn dismiss_self_traffic_skips_service_account_uid() {
        // A web server (uid 33 / www-data) running ssh is NOT typical
        // operator activity — could be lateral movement via stolen
        // shell. Don't auto-dismiss.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:7777:2026-04-29T13:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "203.0.113.20",
                "pid": 7777,
                "comm": "ssh",
                "uid": 33,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 0);
    }

    #[test]
    fn dismiss_self_traffic_skips_incidents_without_structured_evidence() {
        // Forward-compat: an incident from an older killchain version
        // without comm/uid/pid in evidence must NOT be dismissed
        // blindly. AI router handles it.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:1111:2026-04-29T14:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "203.0.113.5",
                // No pid/comm/uid — older schema.
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 0);
    }

    // ── 2026-05-09: fast-path block anchors ───────────────────────────
    //
    // The fast-path shortcuts the AI router for kill_chain patterns
    // where the AI verdict is deterministic (always block). The
    // anchors below pin the FP boundary: the fast-path must trigger
    // ONLY for the explicit pattern set, must defer when an earlier
    // dismiss decision exists, must reject malformed input. The user
    // explicitly named "ancoras pra nao estragar nada" as a release
    // requirement — every entry below is a regression guard.

    /// Headline positive anchor: an `ebpf_reverse_shell` incident with
    /// a non-empty c2_ip MUST qualify for the fast-path block. This
    /// is the prod-shape repro: if the eBPF detector fires reverse
    /// shell, fast-path takes it.
    #[test]
    fn fast_path_extracts_block_target_for_reverse_shell() {
        let inc = serde_json::json!({
            "incident_id": "reverse_shell:ebpf_reverse_shell:9000:2026-05-09T22:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "ebpf_reverse_shell",
                "c2_ip": "203.0.113.45",
                "c2_port": 4444,
                "pid": 9000,
                "comm": "bash",
            }]
        });
        // killchain crate emits the bare `reverse_shell` label.
        let inc_canonical = serde_json::json!({
            "incident_id": "reverse_shell:9000:2026-05-09T22:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "reverse_shell",
                "c2_ip": "203.0.113.45",
                "c2_port": 4444,
                "pid": 9000,
                "comm": "bash",
            }]
        });
        let extracted = fast_path_extract_block_target(&inc_canonical);
        assert!(extracted.is_some(), "reverse_shell + c2_ip must qualify");
        let (pattern, c2_ip, incident_id) = extracted.unwrap();
        assert_eq!(pattern, "reverse_shell");
        assert_eq!(c2_ip, "203.0.113.45");
        assert!(incident_id.contains("9000"));
        // Sensor reverse_shell detector emits `ebpf_reverse_shell` —
        // both labels qualify so a single detection layer change
        // cannot silently bypass the fast-path. Anchor pins the
        // dual-label coverage.
        let extracted_ebpf = fast_path_extract_block_target(&inc);
        assert!(
            extracted_ebpf.is_some(),
            "ebpf_reverse_shell from the sensor detector must also qualify; \
             both detection layers (killchain crate + sensor reverse_shell) \
             must converge on the fast-path"
        );
    }

    /// I1 (spec 045 invariant): `data_exfil` is in STRONG_KILLCHAIN_PATTERNS
    /// but MUST NOT be in the fast-path. The codex/openclaw FP class hits
    /// data_exfil; the AI dismiss path is the right place to filter it.
    /// Removing data_exfil from this exclusion would re-introduce the
    /// 2026-05-09 codex prod incident.
    #[test]
    fn fast_path_skips_data_exfil_pattern() {
        assert!(
            !is_fast_path_killchain_pattern("data_exfil"),
            "data_exfil must NEVER be fast-path-blocked — codex/openclaw \
             class of FP relies on the AI dismiss path"
        );
        let inc = serde_json::json!({
            "incident_id": "kill_chain:data_exfil:3452:2026-05-09T20:34Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "data_exfil",
                "c2_ip": "104.16.5.34",
                "comm": "npm exec codex-",
            }]
        });
        assert!(fast_path_extract_block_target(&inc).is_none());
    }

    /// Same guard for `exploit_c2` — the codex prod incident actually
    /// classified as EXPLOIT_C2 (2/3 bits FULL_EXPLOIT). Must stay
    /// in the AI path so the dismiss can land.
    #[test]
    fn fast_path_skips_exploit_c2_pattern() {
        assert!(
            !is_fast_path_killchain_pattern("exploit_c2"),
            "exploit_c2 must NEVER be fast-path-blocked — the prod \
             codex incident hit this pattern; AI dismiss must run"
        );
        let inc = serde_json::json!({
            "incident_id": "kill_chain:exploit_c2:3452:2026-05-09T20:34Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "exploit_c2",
                "c2_ip": "104.16.5.34",
                "comm": "npm exec codex-",
            }]
        });
        assert!(fast_path_extract_block_target(&inc).is_none());
    }

    /// Defensive: `exploit_shell` and `full_exploit` are in
    /// STRONG_KILLCHAIN_PATTERNS but NOT in the fast-path list. They
    /// have a non-zero historical FP rate, so the AI router stays
    /// in the loop. Pin the exclusion.
    #[test]
    fn fast_path_skips_exploit_shell_and_full_exploit() {
        assert!(!is_fast_path_killchain_pattern("exploit_shell"));
        assert!(!is_fast_path_killchain_pattern("full_exploit"));
    }

    /// The fast-path set: kernel-evidence patterns from the killchain
    /// crate AND their `ebpf_` aliases from the sensor reverse_shell
    /// detector. If a future PR adds an entry, this test forces the
    /// author to update the assertion AND justify the addition in
    /// the commit message.
    #[test]
    fn fast_path_pattern_list_is_exactly_the_documented_six() {
        let recognised = [
            "reverse_shell",
            "bind_shell",
            "code_inject",
            "inject_shell",
            "ebpf_reverse_shell",
            "ebpf_bind_shell",
        ];
        for p in recognised {
            assert!(
                is_fast_path_killchain_pattern(p),
                "{p} must be in the fast-path list"
            );
        }
        // Case insensitivity (defensive — sensor sometimes upper-cases).
        assert!(is_fast_path_killchain_pattern("REVERSE_SHELL"));
        assert!(is_fast_path_killchain_pattern("Bind_Shell"));
        // Anything outside the documented set must NOT qualify.
        for forbidden in [
            "data_exfil",
            "exploit_c2",
            "exploit_shell",
            "full_exploit",
            "DATA_EXFIL",
            "ssh_bruteforce",
            "proto_anomaly",
            "killchain.unknown",
            "",
        ] {
            assert!(
                !is_fast_path_killchain_pattern(forbidden),
                "{forbidden} must NOT be in the fast-path list (would create FP risk)"
            );
        }
    }

    /// Empty c2_ip → no block target. The fast-path needs an IP to
    /// pass to the block executor; without one we defer to AI router
    /// (which can still produce a non-block verdict like Monitor).
    #[test]
    fn fast_path_skips_when_c2_ip_is_empty() {
        let inc = serde_json::json!({
            "incident_id": "reverse_shell:9000:2026-05-09T22:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "reverse_shell",
                "c2_ip": "",
                "pid": 9000,
            }]
        });
        assert!(fast_path_extract_block_target(&inc).is_none());
    }

    /// Missing c2_ip field (older killchain schema) → no block target.
    /// Forward-compat with future schema changes.
    #[test]
    fn fast_path_skips_when_c2_ip_field_absent() {
        let inc = serde_json::json!({
            "incident_id": "reverse_shell:9000:2026-05-09T22:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "reverse_shell",
                // No c2_ip field at all.
                "pid": 9000,
            }]
        });
        assert!(fast_path_extract_block_target(&inc).is_none());
    }

    /// Missing incident_id → no block target. Without incident_id we
    /// cannot dedupe against existing decisions, so we defer.
    #[test]
    fn fast_path_skips_when_incident_id_absent() {
        let inc = serde_json::json!({
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "reverse_shell",
                "c2_ip": "203.0.113.45",
            }]
        });
        assert!(fast_path_extract_block_target(&inc).is_none());
    }

    /// Empty evidence array → no block target.
    #[test]
    fn fast_path_skips_when_evidence_empty() {
        let inc = serde_json::json!({
            "incident_id": "x",
            "evidence": []
        });
        assert!(fast_path_extract_block_target(&inc).is_none());
    }

    /// Missing evidence field → no block target.
    #[test]
    fn fast_path_skips_when_evidence_absent() {
        let inc = serde_json::json!({
            "incident_id": "x"
        });
        assert!(fast_path_extract_block_target(&inc).is_none());
    }

    // event_to_tracker_json preserves key fields
    #[test]
    fn event_to_tracker_json_has_required_fields() {
        let event = innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "myhost".into(),
            kind: "syscall.execve".into(),
            source: "ebpf".into(),
            details: serde_json::json!({"pid": 1234, "comm": "bash"}),
            severity: innerwarden_core::event::Severity::Medium,
            summary: String::new(),
            tags: vec![],
            entities: vec![],
        };
        let json = event_to_tracker_json(&event);
        assert_eq!(json["kind"], "syscall.execve");
        assert_eq!(json["source"], "ebpf");
        assert_eq!(json["host"], "myhost");
        assert!(json["ts"].as_str().is_some());
        assert_eq!(json["details"]["pid"], 1234);
        assert_eq!(json["details"]["comm"], "bash");
    }

    // event_to_tracker_json handles empty details
    #[test]
    fn event_to_tracker_json_empty_details() {
        let event = innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            kind: "file.read".into(),
            source: "audit".into(),
            details: serde_json::json!({}),
            severity: innerwarden_core::event::Severity::Low,
            summary: String::new(),
            tags: vec![],
            entities: vec![],
        };
        let json = event_to_tracker_json(&event);
        assert_eq!(json["kind"], "file.read");
        assert!(json["details"].is_object());
    }

    // Self-exclusion: the platform's own thread names are all present and
    // each fits in Linux's 15-char comm limit.
    #[test]
    fn self_excluded_comms_cover_platform_threads_and_respect_comm_len() {
        const COMM_LEN: usize = 15;
        for name in KILLCHAIN_SELF_EXCLUDED_COMMS {
            assert!(
                name.len() <= COMM_LEN,
                "'{name}' exceeds {COMM_LEN}-char comm limit — kernel would truncate it and the match would never fire"
            );
        }
        assert!(KILLCHAIN_SELF_EXCLUDED_COMMS.contains(&"tokio-rt-worker"));
        assert!(KILLCHAIN_SELF_EXCLUDED_COMMS.contains(&"innerwarden-age"));
        assert!(KILLCHAIN_SELF_EXCLUDED_COMMS.contains(&"innerwarden-sen"));
        assert!(KILLCHAIN_SELF_EXCLUDED_COMMS.contains(&"innerwarden-wat"));
    }

    // Wiring: a tracker built with the self-exclusion list ignores events
    // attributed to the agent's tokio worker pool.
    #[test]
    fn tracker_configured_with_self_exclusions_drops_tokio_rt_worker() {
        let mut tracker =
            PidTracker::new().with_excluded_comms(KILLCHAIN_SELF_EXCLUDED_COMMS.iter().copied());

        let connect = serde_json::json!({
            "kind": "network.outbound_connect",
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": "h",
            "details": {
                "pid": 1234,
                "uid": 0,
                "comm": "tokio-rt-worker",
                "dst_ip": "1.1.1.1",
                "dst_port": 443
            }
        });
        let read = serde_json::json!({
            "kind": "file.read_access",
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": "h",
            "details": {
                "pid": 1234,
                "uid": 0,
                "comm": "tokio-rt-worker",
                "filename": "/root/.ssh/id_rsa"
            }
        });

        assert!(tracker.process_event(&connect).is_empty());
        assert!(tracker.process_event(&read).is_empty());
        assert_eq!(tracker.stats(), (0, 0, 0));
    }

    // write_incidents must persist a conforming incident to the sqlite store
    // when one is provided, *and* to the JSONL file (unchanged legacy path).
    #[test]
    fn write_incidents_persists_to_sqlite_when_store_provided() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(tmp.path()).expect("open sqlite");

        let incident = serde_json::json!({
            "ts": "2026-04-16T15:52:02.428033127+00:00",
            "host": "testhost",
            "incident_id": "kill_chain:detected:DATA_EXFIL:999:2026-04-16T15:52Z",
            "severity": "critical",
            "title": "Kill chain detected: DATA_EXFIL (PID 999, attacker)",
            "summary": "PID 999 (attacker) completed DATA_EXFIL pattern.",
            "evidence": [{"pattern": "DATA_EXFIL"}],
            "recommended_checks": [],
            "tags": ["kill_chain", "detected", "data_exfil"],
            "entities": []
        });

        write_incidents(tmp.path(), Some(&store), &[incident]);

        assert_eq!(store.incidents_count().unwrap(), 1);
        let found = store
            .get_incident("kill_chain:detected:DATA_EXFIL:999:2026-04-16T15:52Z")
            .unwrap();
        assert!(found.is_some(), "incident must be queryable by incident_id");

        let jsonl = std::fs::read_to_string(tmp.path().join(format!(
            "incidents-{}.jsonl",
            chrono::Local::now().date_naive().format("%Y-%m-%d")
        )))
        .expect("jsonl written");
        assert!(jsonl.contains("DATA_EXFIL"));
    }

    // write_incidents without a store must still write JSONL and not panic.
    #[test]
    fn write_incidents_without_store_still_writes_jsonl() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let incident = serde_json::json!({
            "ts": "2026-04-16T15:52:02.428033127+00:00",
            "host": "testhost",
            "incident_id": "kill_chain:detected:REVERSE_SHELL:42:2026-04-16T15:52Z",
            "severity": "critical",
            "title": "t",
            "summary": "s",
            "evidence": [],
            "recommended_checks": [],
            "tags": [],
            "entities": []
        });
        write_incidents(tmp.path(), None, &[incident]);
        let jsonl = std::fs::read_to_string(tmp.path().join(format!(
            "incidents-{}.jsonl",
            chrono::Local::now().date_naive().format("%Y-%m-%d")
        )))
        .expect("jsonl written");
        assert!(jsonl.contains("REVERSE_SHELL"));
    }

    // A malformed incident (missing `incident_id`) must be dropped before it
    // reaches sqlite — the rest of the batch still writes. Pre-spec-035-A5
    // the serde layer rejected records missing required fields; post-A5 the
    // wire type tolerates missing fields (JSONL backwards-compat with old
    // releases), so the guard moved to a structural check in `write_incidents`
    // on the one invariant that still rules a record out as "not an incident":
    // a non-empty id. See spec 035 A5 and the comment in `write_incidents`.
    #[test]
    fn write_incidents_skips_malformed_and_persists_valid() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(tmp.path()).expect("open sqlite");

        let bad = serde_json::json!({"not_an_incident": true});
        let good = serde_json::json!({
            "ts": "2026-04-16T15:52:02.428033127+00:00",
            "host": "h",
            "incident_id": "kill_chain:detected:DATA_EXFIL:1:2026-04-16T15:52Z",
            "severity": "critical",
            "title": "t",
            "summary": "s",
            "evidence": [],
            "recommended_checks": [],
            "tags": [],
            "entities": []
        });

        write_incidents(tmp.path(), Some(&store), &[bad, good]);

        assert_eq!(store.incidents_count().unwrap(), 1);
    }

    // An empty incident slice must be a cheap no-op — no JSONL file created,
    // no sqlite write attempted.
    #[test]
    fn write_incidents_empty_is_noop() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = innerwarden_store::Store::open(tmp.path()).expect("open sqlite");
        write_incidents(tmp.path(), Some(&store), &[]);
        assert_eq!(store.incidents_count().unwrap(), 0);

        let expected_jsonl = tmp.path().join(format!(
            "incidents-{}.jsonl",
            chrono::Local::now().date_naive().format("%Y-%m-%d")
        ));
        assert!(
            !expected_jsonl.exists(),
            "no JSONL file should be created for empty input"
        );
    }

    // ─── Spec 024 contract tests ───────────────────────────────────────
    //
    // PidTracker::process_event contract:
    //   - Events whose `details.comm` matches `KILLCHAIN_SELF_EXCLUDED_COMMS`
    //     MUST NOT mutate tracker state. Self-exclusion is the whole reason
    //     the platform stopped DATA_EXFIL'ing itself in PR #124.
    //   - Events unrelated to kill-chain bits (e.g. a cold exec that is not
    //     in any known pattern) MUST NOT emit an incident.
    //   - When an event DOES advance a pattern, process_event returns a
    //     non-empty Vec. The specific contents are the PidTracker's own
    //     business; the agent contract is only about presence/absence.

    #[test]
    fn contract_excluded_comm_never_mutates_state() {
        let mut tracker =
            PidTracker::new().with_excluded_comms(KILLCHAIN_SELF_EXCLUDED_COMMS.iter().copied());
        let (pids_before, _, _) = tracker.stats();

        for comm in KILLCHAIN_SELF_EXCLUDED_COMMS.iter().copied() {
            let ev = serde_json::json!({
                "kind": "network.outbound_connect",
                "ts": chrono::Utc::now().to_rfc3339(),
                "host": "h",
                "details": {
                    "pid": 1111,
                    "uid": 0,
                    "comm": comm,
                    "dst_ip": "1.1.1.1",
                    "dst_port": 443
                }
            });
            let incidents = tracker.process_event(&ev);
            assert!(
                incidents.is_empty(),
                "self-excluded comm '{comm}' must never emit incidents"
            );
        }
        let (pids_after, _, _) = tracker.stats();
        assert_eq!(
            pids_before, pids_after,
            "self-excluded comms must not mutate tracker state"
        );
    }

    #[test]
    fn contract_innocent_event_emits_no_incidents() {
        // A noop event must produce a Vec with zero incidents. We assert
        // on length (Vec API) rather than identity so the storage layer is
        // free to change.
        let mut tracker = PidTracker::new();
        let ev = serde_json::json!({
            "kind": "file.read_access",
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": "h",
            "details": {
                "pid": 9999,
                "uid": 1000,
                "comm": "user-shell",
                "filename": "/home/user/.bashrc"
            }
        });
        let out: Vec<serde_json::Value> = tracker.process_event(&ev);
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn contract_returns_vec_not_option() {
        // Signature check: if someone ever changes process_event to return
        // Option<Incident> (which it *has* looked like in the past), scenario
        // and replay pipelines that iterate will silently lose batches.
        let mut tracker = PidTracker::new();
        let out: Vec<serde_json::Value> = tracker.process_event(&serde_json::json!({
            "kind": "noop",
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": "h",
            "details": {"pid": 1, "comm": "init"}
        }));
        // Vec is iterable by reference and by value. Both compile ⇒ contract holds.
        let _ = out.iter().count();
        let _ = out.into_iter().count();
    }

    // KILLCHAIN_COMM_ALLOWLIST prevents notification for known service processes
    #[test]
    fn comm_allowlist_blocks_known_services() {
        let allowlist: &[&str] = &[
            "ruby",
            "python",
            "python3",
            "node",
            "java",
            "beam.smp",
            "nginx",
            "haproxy",
            "envoy",
            "caddy",
            "postgres",
            "mysqld",
            "redis-server",
            "openclaw",
            "innerwarden",
        ];
        // Known services should be in the list
        assert!(allowlist.iter().any(|a| "nginx".starts_with(a)));
        assert!(allowlist.iter().any(|a| "python3".starts_with(a)));
        assert!(allowlist.iter().any(|a| "innerwarden-agent".starts_with(a)));
        // Unknown attacker binaries should NOT match
        assert!(!allowlist.iter().any(|a| "nc".starts_with(a)));
        assert!(!allowlist.iter().any(|a| "bash".starts_with(a)));
    }

    // ── 2026-05-02 audit B2/P3 anchors — strong kill chain pattern guard ──
    //
    // The auditor saw `kill_chain DATA_EXFIL → DISMISS @ 100% confidence`
    // with rationale "ssh is a known operator/system tool". The durable
    // rule is that kernel-level forensic patterns must NEVER be silently
    // auto-dismissed by binary-name / IP heuristics. These anchors pin
    // the strong-pattern guard against future regression: a fixture
    // incident with detector kill_chain and a strong pattern must NOT
    // be dismissed even when every other condition (operator-IP match,
    // operator/system comm, root/operator uid) lines up. data_exfil
    // dismiss is preserved — that's the noisy 2-bit signal whose
    // operator-context dismiss kept the dashboard usable pre-audit;
    // the strong patterns route through the AI router + untouchable
    // gate for an explicit operator confirmation.

    #[test]
    fn dismiss_operator_session_skips_reverse_shell_pattern_even_for_operator_ip() {
        // Strong pattern + operator-IP match: must not dismiss. Auditor
        // rule: kernel-level forensic evidence overrides the IP match.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:REVERSE_SHELL:2026-05-02T10:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "REVERSE_SHELL",
                "c2_ip": "203.0.113.99",
                "pid": 1234,
                "comm": "ssh",
                "uid": 1001,
            }]
        })];
        let mut operator_ips = std::collections::HashMap::new();
        operator_ips.insert("203.0.113.99".to_string(), std::time::Instant::now());
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &incidents, &operator_ips);
        assert_eq!(
            store.decisions_count().unwrap(),
            0,
            "REVERSE_SHELL must NOT be auto-dismissed (audit B2/P3): operator-IP heuristic \
             cannot overrule kernel-level forensic evidence — the incident must reach the AI \
             router so incident_untouchable can force RequestConfirmation"
        );
    }

    #[test]
    fn dismiss_operator_session_still_dismisses_data_exfil_for_operator_ip() {
        // Preserve the apt/snap/cloud-init noise reduction: data_exfil
        // is the noisy 2-bit `socket+sensitive_read` pattern that fires
        // on legit package updates reading /etc/resolv.conf and
        // connecting to mirrors. Operator-IP match remains a strong
        // enough signal here. Audit B2 narrowed the suppression to
        // strong patterns; the data_exfil escape hatch survives.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:2026-05-02T10:30Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "20.26.156.215",
                "pid": 1234,
                "comm": "ssh",
                "uid": 1001,
            }]
        })];
        let mut operator_ips = std::collections::HashMap::new();
        operator_ips.insert("20.26.156.215".to_string(), std::time::Instant::now());
        dismiss_operator_session_incidents(tmp.path(), Some(&store), &incidents, &operator_ips);
        assert_eq!(
            store.decisions_count().unwrap(),
            1,
            "DATA_EXFIL with operator-IP match must remain auto-dismissed — disabling this \
             would re-flood the dashboard with false-positive apt/snap/cloud-init traffic"
        );
    }

    #[test]
    fn dismiss_self_traffic_skips_full_exploit_pattern_even_for_root_apt() {
        // Strong pattern + apt + uid 0: must NOT dismiss. The "apt
        // running as root" heuristic is fine for data_exfil noise
        // reduction but cannot overrule a FULL_EXPLOIT chain.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:FULL_EXPLOIT:2026-05-02T11:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "FULL_EXPLOIT",
                "c2_ip": "203.0.113.50",
                "pid": 5678,
                "comm": "apt",
                "uid": 0,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(
            store.decisions_count().unwrap(),
            0,
            "FULL_EXPLOIT must NOT be auto-dismissed even when comm/uid match self-traffic \
             (audit B2/P3) — kernel-level kill chain evidence routes through AI router + \
             incident_untouchable instead"
        );
    }

    #[test]
    fn dismiss_self_traffic_skips_code_inject_for_ssh_operator_uid() {
        // CODE_INJECT chain (ptrace + mprotect RWX) with comm=ssh +
        // uid=1001 must reach the AI router — binary-name heuristic
        // cannot overrule a code-injection signature.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:CODE_INJECT:2026-05-02T11:30Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "CODE_INJECT",
                "c2_ip": "203.0.113.77",
                "pid": 9999,
                "comm": "ssh",
                "uid": 1001,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 0);
    }

    #[test]
    fn is_strong_killchain_pattern_recognises_all_documented_strong_patterns() {
        // Lock the canonical strong-pattern set. If a future contributor
        // adds a new pattern in `crates/killchain/src/patterns.rs`, this
        // test serves as the trigger to re-evaluate whether it should
        // be in STRONG_KILLCHAIN_PATTERNS too.
        for p in [
            "reverse_shell",
            "REVERSE_SHELL",
            "bind_shell",
            "code_inject",
            "inject_shell",
            "exploit_shell",
            "exploit_c2",
            "full_exploit",
            "FULL_EXPLOIT",
        ] {
            assert!(
                is_strong_killchain_pattern(p),
                "expected `{p}` to be classified as a strong kill chain pattern"
            );
        }
        // data_exfil is intentionally NOT strong — see comment on
        // STRONG_KILLCHAIN_PATTERNS in this module for the rationale.
        assert!(!is_strong_killchain_pattern("data_exfil"));
        assert!(!is_strong_killchain_pattern("DATA_EXFIL"));
    }

    // ── 2026-05-03 (PR #417) anchors — single source of truth for ──
    //                     self-traffic comms
    //
    // Pre-PR-#417 the dismiss path used SELF_TRAFFIC_COMMS (apt,
    // snap, ssh, cloud-init, ...) and the Telegram notify path had
    // its own KILLCHAIN_COMM_ALLOWLIST (nginx, postgres, ruby, ...).
    // The two lists drifted: dismiss recognised apt as FP and
    // skipped the AI router; notify did NOT, so the operator got
    // 11 Telegram alerts for an apt update before AI silently
    // dismissed them. These anchors pin the SoT contract.

    #[test]
    fn matches_self_traffic_comm_uses_prefix_semantics() {
        let list = test_self_traffic_list();
        // Exact match.
        assert!(matches_self_traffic_comm("apt", &list));
        assert!(matches_self_traffic_comm("ssh", &list));
        assert!(matches_self_traffic_comm("cloud-init", &list));
        // Prefix match: `git-remote-https` matches `git-remote-`.
        assert!(matches_self_traffic_comm("git-remote-https", &list));
        // Empty comm never matches.
        assert!(!matches_self_traffic_comm("", &list));
        // Unknown comm.
        assert!(!matches_self_traffic_comm("evil_tool", &list));
    }

    #[test]
    fn self_traffic_comms_returns_builtins_when_config_extras_empty() {
        let cfg = crate::config::KillchainConfig::default();
        assert!(cfg.self_traffic_comms_extra.is_empty());
        let list = self_traffic_comms(&cfg);
        // Builtins all present.
        for builtin in BUILTIN_SELF_TRAFFIC_COMMS {
            assert!(
                list.iter().any(|c| c == *builtin),
                "builtin `{builtin}` must be in the merged list when extras is empty"
            );
        }
        assert_eq!(list.len(), BUILTIN_SELF_TRAFFIC_COMMS.len());
    }

    #[test]
    fn self_traffic_comms_appends_operator_extras() {
        // Operator extends via `[killchain] self_traffic_comms_extra`.
        let cfg = crate::config::KillchainConfig {
            self_traffic_comms_extra: vec![
                "puppet".to_string(),
                "chef-client".to_string(),
                "salt-minion".to_string(),
            ],
            ..Default::default()
        };
        let list = self_traffic_comms(&cfg);
        assert!(list.iter().any(|c| c == "puppet"));
        assert!(list.iter().any(|c| c == "chef-client"));
        assert!(list.iter().any(|c| c == "salt-minion"));
        // Builtins still there.
        assert!(list.iter().any(|c| c == "apt"));
    }

    #[test]
    fn self_traffic_comms_dedupes_extras_against_builtins() {
        // Operator accidentally lists `apt` (already a builtin).
        // Merged list must not have it twice.
        let cfg = crate::config::KillchainConfig {
            self_traffic_comms_extra: vec!["apt".to_string(), "puppet".to_string()],
            ..Default::default()
        };
        let list = self_traffic_comms(&cfg);
        let apt_count = list.iter().filter(|c| c.as_str() == "apt").count();
        assert_eq!(
            apt_count, 1,
            "duplicate extras must be deduped against builtins"
        );
    }

    #[test]
    fn self_traffic_comms_trims_and_skips_empty_extras() {
        let cfg = crate::config::KillchainConfig {
            self_traffic_comms_extra: vec![
                "  puppet  ".to_string(),
                "".to_string(),
                "   ".to_string(),
            ],
            ..Default::default()
        };
        let list = self_traffic_comms(&cfg);
        assert!(list.iter().any(|c| c == "puppet"));
        assert!(!list.iter().any(|c| c.is_empty() || c.trim().is_empty()));
    }

    // ── 2026-05-05 (Wave 9b) anchors — service-account fetcher dismiss ──
    //
    // The general uid filter (uid == 0 || uid >= 1000) was too strict for
    // network-fetcher comms. Specifically: Debian/Ubuntu apt runs its
    // HTTPS download under uid 105 (`_apt`, the unprivileged sandbox), and
    // the worker thread's `comm` becomes `http` or `https`. Pre-Wave-9b
    // both gates rejected the dismiss (comm not in BUILTIN list AND uid
    // 105 fails the {0, >=1000} check) and the operator's nightly apt
    // update produced 9-15 critical "DATA_EXFIL to Ubuntu mirror IP"
    // incidents per day that reached the AI router (62 https + 15 http
    // incidents in the 7d window 2026-04-28..05-04).
    //
    // Anchors below pin: (1) http/https/etc are now in the self-traffic
    // list, (2) the uid check is bypassed for fetcher comms only,
    // (3) login-shell comms (ssh, scp, ...) still enforce the uid check
    // so the original lateral-movement protection is intact.

    #[test]
    fn dismiss_self_traffic_dismisses_apt_https_thread_at_apt_uid_105() {
        // The exact prod symptom that motivated Wave 9b: apt's https
        // worker (uid 105 = _apt) downloads from Ubuntu mirror.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:1234:2026-05-05T03:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "91.189.91.46",
                "pid": 1234,
                "comm": "https",
                "uid": 105,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(
            store.decisions_count().unwrap(),
            1,
            "apt's https worker at uid 105 (_apt) MUST be auto-dismissed - this was 62 \
             of 169 prod incidents per 7d window pre-Wave-9b"
        );
    }

    #[test]
    fn dismiss_self_traffic_dismisses_apt_http_at_apt_uid() {
        // Same path as above but the http (port 80) variant.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:5555:2026-05-05T03:01Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "91.189.91.104",
                "pid": 5555,
                "comm": "http",
                "uid": 105,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 1);
    }

    #[test]
    fn dismiss_self_traffic_dismisses_apt_at_apt_uid_directly() {
        // Even when the worker comm IS `apt` (no thread-rename), uid 105
        // would have failed pre-Wave-9b. After Wave 9b apt is fetcher-class
        // and uid-agnostic.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:7777:2026-05-05T03:02Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "91.189.91.46",
                "pid": 7777,
                "comm": "apt",
                "uid": 105,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 1);
    }

    #[test]
    fn dismiss_self_traffic_still_blocks_ssh_at_service_account_uid() {
        // Lateral-movement guard on login-shell comms must NOT regress.
        // ssh from www-data (uid 33) is not legitimate operator activity
        // and must reach the AI router for a real call. This is the test
        // the Wave 9b uid-agnostic carveout MUST NOT erode.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:8888:2026-05-05T03:03Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "203.0.113.20",
                "pid": 8888,
                "comm": "ssh",
                "uid": 33,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(
            store.decisions_count().unwrap(),
            0,
            "ssh from www-data (uid 33) MUST still reach the AI router - the Wave 9b \
             fetcher carveout cannot erode the lateral-movement guard on login-shell comms"
        );
    }

    #[test]
    fn dismiss_self_traffic_still_dismisses_ssh_at_operator_uid() {
        // Pre-Wave-9b ssh at uid >= 1000 was already dismissed via the
        // {0, >=1000} gate. This anchor pins that it still IS dismissed
        // post-Wave-9b (the old branch is preserved as the fallback when
        // the comm is not a fetcher).
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:9001:2026-05-05T03:04Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "20.26.156.215",
                "pid": 9001,
                "comm": "ssh",
                "uid": 1001,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(store.decisions_count().unwrap(), 1);
    }

    #[test]
    fn comm_is_uid_agnostic_fetcher_recognises_documented_fetchers() {
        // Lock the fetcher set against a future contributor accidentally
        // moving a comm out of UID_AGNOSTIC_FETCHER_COMMS without bumping
        // a comment. If you add a comm here, also add a behavioural test
        // upstream that exercises it through dismiss_self_traffic.
        for comm in [
            "apt",
            "apt-get",
            "snap",
            "snapd",
            "http",
            "https",
            "curl",
            "wget",
            "systemd-resolv",
            "systemd-network",
            "chronyd",
            "ntpd",
            "fwupdmgr",
            "unattended-upgr",
            "needrestart",
            "cloud-init",
        ] {
            assert!(
                comm_is_uid_agnostic_fetcher(comm),
                "expected `{comm}` to be classified as a uid-agnostic fetcher comm"
            );
        }
        // Login-shell tools must NOT be uid-agnostic - the lateral-
        // movement guard applies to them.
        for login in ["ssh", "scp", "sftp", "rsync", "git", "git-remote-https"] {
            assert!(
                !comm_is_uid_agnostic_fetcher(login),
                "`{login}` must require the uid check (lateral-movement guard)"
            );
        }
        // Empty comm is never a fetcher (avoids matching everything via
        // the "starts_with empty" pitfall).
        assert!(!comm_is_uid_agnostic_fetcher(""));
    }

    #[test]
    fn dismiss_self_traffic_still_skips_strong_pattern_for_apt_uid_105() {
        // Wave 9b extends the dismiss for fetcher comms across uids, but
        // the strong-pattern guard (audit B2/P3) MUST still skip. apt at
        // uid 105 with REVERSE_SHELL is still a kernel-level forensic
        // signal that cannot be overruled by a comm/uid heuristic.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:REVERSE_SHELL:6666:2026-05-05T03:05Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "REVERSE_SHELL",
                "c2_ip": "203.0.113.99",
                "pid": 6666,
                "comm": "https",
                "uid": 105,
            }]
        })];
        dismiss_self_traffic_incidents(
            tmp.path(),
            Some(&store),
            &incidents,
            &test_self_traffic_list(),
        );
        assert_eq!(
            store.decisions_count().unwrap(),
            0,
            "REVERSE_SHELL must NEVER be auto-dismissed even when comm/uid match the \
             new fetcher carveout - kernel-level forensic evidence routes through the \
             AI router + incident_untouchable"
        );
    }

    #[test]
    fn dismiss_self_traffic_skips_when_comm_not_in_extended_list() {
        // Operator-added comm `puppet` was on the dismiss path now —
        // dismiss MUST honour it. End-to-end anchor that the merged
        // list flows through to the dismiss decision.
        let tmp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(innerwarden_store::Store::open_memory().expect("open_memory"));
        let incidents = vec![serde_json::json!({
            "incident_id": "kill_chain:detected:DATA_EXFIL:1234:2026-05-03T08:00Z",
            "evidence": [{
                "kind": "kill_chain_detected",
                "pattern": "DATA_EXFIL",
                "c2_ip": "203.0.113.20",
                "pid": 1234,
                "comm": "puppet",
                "uid": 0,
            }]
        })];
        let cfg = crate::config::KillchainConfig {
            self_traffic_comms_extra: vec!["puppet".to_string()],
            ..Default::default()
        };
        let extended_list = self_traffic_comms(&cfg);
        dismiss_self_traffic_incidents(tmp.path(), Some(&store), &incidents, &extended_list);
        assert_eq!(
            store.decisions_count().unwrap(),
            1,
            "puppet (operator-added) must be dismissed via self-traffic-fp path"
        );
    }

    #[test]
    fn telegram_notify_and_dismiss_consume_same_self_traffic_list() {
        // The KEY anchor: this test will fail at build-time if anyone
        // re-introduces a separate hardcoded comm allowlist in
        // notify_telegram. Both code paths in killchain_inline.rs
        // must call `matches_self_traffic_comm(comm, list)` against
        // the SAME list. Pre-PR-#417 they had divergent constants
        // and the operator received Telegram alerts for apt updates
        // that were silently auto-dismissed.
        let src = include_str!("killchain_inline.rs");

        // dismiss path uses matches_self_traffic_comm.
        assert!(
            src.contains("matches_self_traffic_comm(comm, self_traffic_list)"),
            "dismiss_self_traffic_incidents must use matches_self_traffic_comm \
             against the passed-in list"
        );

        // notify_telegram path also uses matches_self_traffic_comm.
        let notify_section_start = src
            .find("pub(crate) fn notify_telegram(")
            .expect("notify_telegram fn must exist");
        let notify_section = &src[notify_section_start..];
        assert!(
            notify_section.contains("matches_self_traffic_comm(comm, self_traffic_list)"),
            "notify_telegram MUST call matches_self_traffic_comm against the SAME \
             self_traffic_list — anchored on PR #417 to prevent the dismiss/notify \
             drift that flooded the operator's Telegram with apt-update FPs"
        );

        // The new architecture: KILLCHAIN_SERVICE_ALLOWLIST (services
        // that do socket+dup as part of normal request handling)
        // exists separately from BUILTIN_SELF_TRAFFIC_COMMS (operator
        // tooling that does socket+sensitive_read on package
        // updates). Both names must be present and distinct.
        assert!(src.contains("KILLCHAIN_SERVICE_ALLOWLIST"));
        assert!(src.contains("BUILTIN_SELF_TRAFFIC_COMMS"));
    }

    // ── Spec 081 — kernel-block withhold gate (evaluate_kernel_block_withhold) ──
    //
    // The async `register_kernel_blocks` loop body is extracted into the pure
    // `evaluate_kernel_block_withhold` so the gating logic is testable with a
    // stub `/proc` resolver + hand-built registry, no AgentState. These cover:
    //   - gated pattern (data_exfil/exploit_c2) + verified managed agent → Some
    //     (withhold)
    //   - non-gated pattern (reverse_shell) → None (block proceeds)
    //   - gated pattern but unregistered pid → None (fail closed)
    //   - the `is_managed_agent_gated_pattern` predicate itself.

    use innerwarden_agent_guard::registry::Registry;
    use innerwarden_agent_guard::signatures::SignatureIndex;

    const KC_INTERP: &str = "/usr/bin/node";
    const KC_SCRIPT: &str = "/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js";

    fn kc_registry_with_openclaw(pid: u32) -> Registry {
        let mut reg = Registry::new();
        reg.connect_with_facts(
            "OpenClaw",
            pid,
            Some("ag-kc"),
            Some(KC_INTERP.to_string()),
            Some(1000),
            Some(format!("{KC_INTERP}|{KC_SCRIPT}")),
        )
        .expect("connect");
        reg
    }

    fn kc_openclaw_stub(pid: u32) -> crate::managed_agent_guard::test_support::StubProc {
        crate::managed_agent_guard::test_support::StubProc::default().with_proc(
            pid,
            crate::managed_agent_guard::ResolvedProcess {
                argv: vec![
                    KC_INTERP.to_string(),
                    KC_SCRIPT.to_string(),
                    "gateway".to_string(),
                ],
                exe_path: Some(KC_INTERP.to_string()),
                uid: Some(1000),
            },
        )
    }

    #[test]
    fn is_managed_agent_gated_pattern_matches_data_exfil_and_exploit_c2_only() {
        assert!(is_managed_agent_gated_pattern("data_exfil"));
        assert!(is_managed_agent_gated_pattern("exploit_c2"));
        assert!(is_managed_agent_gated_pattern("DATA_EXFIL")); // case-insensitive
                                                               // Other patterns are NOT gated — an attacker must never buy the
                                                               // kernel-deny exemption by tripping reverse_shell / code_inject.
        assert!(!is_managed_agent_gated_pattern("reverse_shell"));
        assert!(!is_managed_agent_gated_pattern("code_inject"));
        assert!(!is_managed_agent_gated_pattern(""));
    }

    #[test]
    fn evaluate_kernel_block_withhold_managed_for_gated_pattern() {
        let pid = 4242;
        let reg = kc_registry_with_openclaw(pid);
        let sigindex = SignatureIndex::new();
        let stub = kc_openclaw_stub(pid);
        // exploit_c2 (node V8 JIT mprotect-RWX + its own outbound socket) has no
        // file dimension, so identity-only verification withholds the block —
        // this is OpenClaw's every-boot FP. (data_exfil now requires a present
        // own-config `sensitive_file`; see the own-config tests below.)
        let ev = serde_json::json!({
            "pid": pid,
            "pattern": "exploit_c2",
            "comm": "MainThread",
        });
        let out = evaluate_kernel_block_withhold(&ev, &reg, &sigindex, &stub);
        let (_id, name) = out.expect("gated pattern + managed agent → withhold");
        assert_eq!(name, "OpenClaw");
    }

    #[test]
    fn evaluate_kernel_block_withhold_blocks_data_exfil_without_sensitive_file() {
        // Fail-closed guard: a data_exfil incident with NO `sensitive_file`
        // (anomalous — the chain can only complete via a sensitive file.open)
        // must NOT be withheld on identity alone. The block lands.
        let pid = 4242;
        let reg = kc_registry_with_openclaw(pid);
        let sigindex = SignatureIndex::new();
        let stub = kc_openclaw_stub(pid);
        let ev = serde_json::json!({
            "pid": pid,
            "pattern": "data_exfil",
            "comm": "MainThread",
        });
        assert!(
            evaluate_kernel_block_withhold(&ev, &reg, &sigindex, &stub).is_none(),
            "data_exfil with no sensitive_file must fail closed (block proceeds)"
        );
    }

    #[test]
    fn evaluate_kernel_block_withhold_none_for_non_gated_pattern() {
        let pid = 4242;
        let reg = kc_registry_with_openclaw(pid);
        let sigindex = SignatureIndex::new();
        let stub = kc_openclaw_stub(pid);
        // reverse_shell is NOT in the managed-agent-gated set → block proceeds
        // (None) WITHOUT even consulting the verifier.
        let ev = serde_json::json!({
            "pid": pid,
            "pattern": "reverse_shell",
            "comm": "MainThread",
        });
        assert!(
            evaluate_kernel_block_withhold(&ev, &reg, &sigindex, &stub).is_none(),
            "non-gated pattern must never be withheld"
        );
    }

    #[test]
    fn evaluate_kernel_block_withhold_none_for_unregistered_pid() {
        let pid = 4242;
        let reg = Registry::new(); // nobody registered
        let sigindex = SignatureIndex::new();
        let stub = kc_openclaw_stub(pid);
        let ev = serde_json::json!({
            "pid": pid,
            "pattern": "data_exfil",
            "comm": "MainThread",
        });
        assert!(
            evaluate_kernel_block_withhold(&ev, &reg, &sigindex, &stub).is_none(),
            "gated pattern but unregistered pid must fail closed (block proceeds)"
        );
    }

    #[test]
    fn evaluate_kernel_block_withhold_none_without_pid() {
        let reg = kc_registry_with_openclaw(4242);
        let sigindex = SignatureIndex::new();
        let stub = kc_openclaw_stub(4242);
        // Evidence missing pid → None (no source to attribute).
        let ev = serde_json::json!({ "pattern": "data_exfil", "comm": "MainThread" });
        assert!(evaluate_kernel_block_withhold(&ev, &reg, &sigindex, &stub).is_none());
    }

    // ── Spec-081 own-config gate ON the kernel-block path ──────────────────
    //
    // DATA_EXFIL kill chains now carry the read path as `sensitive_file`
    // (killchain tracker change). The two tests below prove the verifier's
    // own-config gate now governs the kernel execve-deny exactly like the
    // userspace IP-block path: reading OWN config → withhold; reading
    // /etc/shadow → the block LANDS even for the genuine managed agent. Before
    // this change `read_path` was always None on the kernel path, so a
    // subverted-but-genuine agent reading /etc/shadow wrongly bought the
    // execve-deny exemption.

    #[test]
    fn evaluate_kernel_block_withhold_managed_when_sensitive_file_is_own_config() {
        let pid = 4242;
        let reg = kc_registry_with_openclaw(pid);
        let sigindex = SignatureIndex::new();
        // Agent reading its OWN /home/lab/.env (under the script-derived home,
        // owned by the agent uid) — the legitimate startup FP.
        let stub = kc_openclaw_stub(pid).with_owner("/home/lab/.env", 1000);
        let ev = serde_json::json!({
            "pid": pid,
            "pattern": "data_exfil",
            "comm": "MainThread",
            "sensitive_file": "/home/lab/.env",
        });
        let out = evaluate_kernel_block_withhold(&ev, &reg, &sigindex, &stub);
        let (_id, name) = out.expect("own-config read by verified managed agent → withhold");
        assert_eq!(name, "OpenClaw");
    }

    #[test]
    fn evaluate_kernel_block_withhold_blocks_when_sensitive_file_is_etc_shadow() {
        let pid = 4242;
        let reg = kc_registry_with_openclaw(pid);
        let sigindex = SignatureIndex::new();
        // SAME verified managed agent + SAME gated pattern, but the read is
        // /etc/shadow — NOT its own config. Owner uid 0 != proc uid 1000, and
        // the path is outside the agent's home/install. The kernel block MUST
        // land (None). This is the hole #5 closes: identity alone no longer
        // buys the execve-deny exemption when the read is a foreign secret.
        let stub = kc_openclaw_stub(pid).with_owner("/etc/shadow", 0);
        let ev = serde_json::json!({
            "pid": pid,
            "pattern": "data_exfil",
            "comm": "MainThread",
            "sensitive_file": "/etc/shadow",
        });
        assert!(
            evaluate_kernel_block_withhold(&ev, &reg, &sigindex, &stub).is_none(),
            "a verified managed agent reading /etc/shadow must still be kernel-blocked"
        );
    }
}
