//! Execution Gate divergence monitor (spec 080 G4) — the FREE honesty net.
//!
//! Runs on the agent's slow loop. Reads the LIVE pinned `EXEC_ALLOWLIST` +
//! `LSM_POLICY` maps and the signed allowlist file, then raises a self-incident
//! when the kernel state has diverged from the signed intent — so the paid
//! Execution Gate can never silently go inert / stay un-applied (the 2026-06-17
//! Oracle case: signed `observe`/1685 while the kernel gate was inert/0). Same
//! principle as spec 076 block live-verify: never trust the record, verify the
//! live kernel state.
//!
//! Free per spec 080 §10: keeping the paid feature honest is a safety net, not a
//! paid add-on. The verdict logic lives in `innerwarden_core::execution_gate`
//! (shared, unit-tested); this file is the live-map glue + the slow-loop wiring.

use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};

use innerwarden_core::execution_gate::{
    self, evaluate_divergence_with_lsm, Divergence, GateMode, GateState,
};
use innerwarden_core::incident::Incident;
use tracing::warn;

/// Check the gate at most once per this interval (cheap: two pinned-map reads +
/// one file read).
const CHECK_INTERVAL_SECS: i64 = 600;
/// Emit the drift self-incident at most once per this interval while drift
/// persists (avoid a 30s-tick incident flood — the operator gets one durable
/// signal, re-raised every 6h until they fix it).
const INCIDENT_COOLDOWN_SECS: i64 = 6 * 3600;

static CHECK_LAST_TS: AtomicI64 = AtomicI64::new(0);
static INCIDENT_LAST_TS: AtomicI64 = AtomicI64::new(0);

/// Pure: at least `min_secs` elapsed since `last`? (0 = never → always true.)
fn interval_elapsed(last: i64, now: i64, min_secs: i64) -> bool {
    last == 0 || now - last >= min_secs
}

/// Atomically claim a slot if the interval elapsed (CAS so two ticks crossing
/// the boundary don't both fire). Thin wrapper over [`interval_elapsed`].
fn throttle_allows(slot: &AtomicI64, now: i64, min_secs: i64) -> bool {
    let last = slot.load(Ordering::Relaxed);
    if !interval_elapsed(last, now, min_secs) {
        return false;
    }
    slot.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

/// Slow-loop entry point. Self-throttles to [`CHECK_INTERVAL_SECS`]; emits a
/// self-incident (cooldown [`INCIDENT_COOLDOWN_SECS`]) when the live kernel
/// state has diverged from the signed config. No-op when nothing is configured
/// or the gate isn't loaded.
pub(crate) fn process_execution_gate_tick(data_dir: &Path) {
    let now = chrono::Utc::now().timestamp();
    if !throttle_allows(&CHECK_LAST_TS, now, CHECK_INTERVAL_SECS) {
        return;
    }
    let gate = gather_gate_state();
    // Read the kernel's active-LSM list so an armed-but-LSM-inactive gate (the
    // maps say enforce, but `bpf` is not in the active stack so the hook can
    // never run) is caught, not silently trusted.
    let bpf_lsm_active = execution_gate::read_bpf_lsm_active();
    handle_gate_state(data_dir, &gate, bpf_lsm_active, now, &INCIDENT_LAST_TS);
}

/// Evaluate a gathered [`GateState`] and emit a cooldown-gated self-incident on
/// drift. Returns `true` if an incident was written. Split from the live gather
/// (and with the cooldown slot injected) so the drift/emit/cooldown path is
/// unit-testable with a synthetic state and a private, parallel-safe slot.
fn handle_gate_state(
    data_dir: &Path,
    gate: &GateState,
    bpf_lsm_active: Option<bool>,
    now: i64,
    incident_slot: &AtomicI64,
) -> bool {
    let divergence = evaluate_divergence_with_lsm(gate, bpf_lsm_active);
    if !divergence.is_drift() {
        tracing::debug!(
            signed = ?gate.signed_count,
            live = ?gate.live_count,
            live_mode = gate.live_mode.label(),
            "execution gate: live state matches signed intent"
        );
        return false;
    }

    if !throttle_allows(incident_slot, now, INCIDENT_COOLDOWN_SECS) {
        tracing::debug!(
            ?divergence,
            "execution gate: drift persists, incident on cooldown"
        );
        return false;
    }

    let host = read_hostname();
    let Some(inc) = build_divergence_incident(&host, gate, &divergence, chrono::Utc::now()) else {
        return false;
    };
    warn!(
        signed = ?gate.signed_count,
        live = ?gate.live_count,
        live_mode = gate.live_mode.label(),
        "execution gate DRIFT: paid gate has not converged to the signed config"
    );
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    write_incident(data_dir, &today, &inc);
    true
}

/// Build the self-incident for a divergence verdict. `None` for `Divergence::None`.
fn build_divergence_incident(
    host: &str,
    gate: &GateState,
    divergence: &Divergence,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Incident> {
    use innerwarden_core::event::Severity;

    let (severity, incident_id, title, summary) = match divergence {
        Divergence::None => return None,
        Divergence::ActiveButEmpty { mode, .. } => {
            let sev = if matches!(mode, GateMode::Enforce) {
                Severity::Critical
            } else {
                Severity::High
            };
            (
                sev,
                format!("execution_gate:active_but_empty:{}", mode.label()),
                "Execution Gate is armed with an empty allowlist".to_string(),
                format!(
                    "The kernel Execution Gate is in {} mode but the live EXEC_ALLOWLIST is empty. \
                     In enforce mode this denies EVERY exec (host brick risk); in observe mode it \
                     means no real coverage. The signed allowlist has not been applied to the kernel.",
                    mode.label()
                ),
            )
        }
        Divergence::ApplyDrift {
            signed,
            live,
            intended_mode,
            live_mode,
        } => (
            Severity::High,
            format!("execution_gate:apply_drift:{signed}:{live}"),
            "Execution Gate apply drift (signed config not in kernel)".to_string(),
            format!(
                "The signed Execution Gate config (intent: {}, {signed} entries) has not converged \
                 to the kernel: the live map has {live} entries and the gate mode is {}. The paid \
                 reconcile/apply path is staged-not-applied — observe telemetry is not flowing and \
                 arming now would be unsafe. Re-run a FULL exec-gate apply, then verify the live \
                 map count equals the signed count.",
                intended_mode.map(|m| m.label()).unwrap_or("unknown"),
                live_mode.label(),
            ),
        ),
        Divergence::ScopeArmedButEmpty { mode } => (
            // Not a brick (nothing is denied), but a false sense of security: the
            // gate looks armed yet protects nothing. High, not Critical.
            Severity::High,
            format!("execution_gate:scope_armed_but_empty:{}", mode.label()),
            "Execution Gate is agent-scoped but no cgroup is in scope".to_string(),
            format!(
                "The kernel Execution Gate is in {} mode and agent-scoped (LSM_POLICY key 4 = 1), \
                 but the live EXEC_GATE_SCOPE map is EMPTY. Every exec is then out-of-scope and \
                 allowed before any allowlist lookup, so the gate is protecting NOTHING while \
                 appearing armed. Resolve the protected agent's cgroup id and write it into \
                 EXEC_GATE_SCOPE, or disarm (set key 4 = 0 / key 3 = 0).",
                mode.label()
            ),
        ),
        Divergence::ArmedButLsmInactive { mode } => (
            // The maps say enforce, but the kernel BPF-LSM cannot run, so the gate
            // denies NOTHING. Critical: the operator believes they are protected
            // and are not (worse than a visible disarm).
            Severity::Critical,
            format!("execution_gate:armed_but_lsm_inactive:{}", mode.label()),
            "Execution Gate is armed but the kernel BPF-LSM is not active".to_string(),
            format!(
                "The kernel Execution Gate is in {} mode, but `bpf` is NOT in the active LSM stack \
                 (/sys/kernel/security/lsm), so the innerwarden_lsm_exec_gate hook cannot run and \
                 the gate denies NOTHING while reporting armed — a false sense of security. This is \
                 the stock Ubuntu/Azure default (CONFIG_LSM omits bpf). Add `lsm=...,bpf` to the \
                 kernel cmdline (GRUB_CMDLINE_LINUX) and REBOOT, then re-verify the gate blocks an \
                 unknown exec. Until then treat the agent as UNGATED.",
                mode.label()
            ),
        ),
    };

    Some(Incident {
        ts: now,
        host: host.to_string(),
        incident_id,
        severity,
        title,
        summary,
        evidence: serde_json::json!({
            "signed_count": gate.signed_count,
            "intended_mode": gate.intended_mode.map(|m| m.label()),
            "live_count": gate.live_count,
            "live_mode": gate.live_mode.label(),
            "live_scope_armed": gate.live_scope_armed,
            "live_scope_count": gate.live_scope_count,
            "exec_allowlist_pin": execution_gate::EXEC_ALLOWLIST_PIN,
            "exec_gate_scope_pin": execution_gate::EXEC_GATE_SCOPE_PIN,
            "lsm_policy_pin": execution_gate::LSM_POLICY_PIN,
            "spec": "080-G4+083",
        }),
        recommended_checks: vec![
            "Run `innerwarden doctor` — the Execution Gate section shows signed vs live.".into(),
            "Run a FULL `config-sign exec-gate apply` (not incremental) so the kernel map reconverges.".into(),
            "Confirm `bpftool map dump` count for EXEC_ALLOWLIST equals the signed file count.".into(),
            "Do NOT arm (enforce) until live == signed and a zero-deny rehearse passes.".into(),
        ],
        tags: vec![
            "execution-gate".to_string(),
            "active-defence".to_string(),
            "apply-drift".to_string(),
            "self-incident".to_string(),
        ],
        entities: vec![],
    })
}

fn read_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn write_incident(data_dir: &Path, today: &str, inc: &Incident) {
    use std::io::Write;
    let path = data_dir.join(format!("incidents-{today}.jsonl"));
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            if let Ok(line) = serde_json::to_string(inc) {
                let _ = writeln!(f, "{line}");
            }
        }
        Err(e) => warn!(error = %e, "execution gate monitor: failed to write incident"),
    }
}

/// Gather the live + intended gate state. The signed-file read is portable; the
/// live-map reads are Linux+aya only (stubbed elsewhere → `live_count = None`).
fn gather_gate_state() -> GateState {
    let (signed_count, intended_mode) = read_signed_allowlist();
    // Live kernel-map reads are aya/kernel glue (codecov-excluded, like
    // lsm_policy/aya_impl.rs) — see `execution_gate_aya`.
    let (live_count, live_mode, live_scope_armed, live_scope_count) =
        crate::execution_gate_aya::read_live_gate();
    GateState {
        signed_count,
        intended_mode,
        live_count,
        live_mode,
        live_scope_armed,
        live_scope_count,
    }
}

/// Read + parse the signed allowlist file (portable: a plain JSON read).
fn read_signed_allowlist() -> (Option<usize>, Option<GateMode>) {
    let raw = match std::fs::read_to_string(execution_gate::SIGNED_ALLOWLIST_FILE) {
        Ok(s) => s,
        Err(_) => return (None, None),
    };
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(v) => execution_gate::parse_signed_allowlist(&v),
        Err(_) => (None, None),
    }
}

#[cfg(test)]
fn reset_throttle_for_test() {
    CHECK_LAST_TS.store(0, Ordering::Relaxed);
    INCIDENT_LAST_TS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;
    use innerwarden_core::execution_gate::evaluate_divergence;

    fn drift_state() -> GateState {
        GateState {
            signed_count: Some(1685),
            intended_mode: Some(GateMode::Observe),
            live_count: Some(0),
            live_mode: GateMode::Inert,
            live_scope_armed: None,
            live_scope_count: None,
        }
    }

    #[test]
    fn handle_gate_state_emits_incident_on_drift() {
        // Private slot → parallel-safe (no shared throttle static).
        let slot = AtomicI64::new(0);
        let dir = tempfile::tempdir().unwrap();
        let wrote = handle_gate_state(dir.path(), &drift_state(), None, 10_000, &slot);
        assert!(wrote, "drift must write a self-incident");
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let body =
            std::fs::read_to_string(dir.path().join(format!("incidents-{today}.jsonl"))).unwrap();
        assert!(body.contains("apply_drift"));
    }

    #[test]
    fn handle_gate_state_respects_incident_cooldown() {
        let slot = AtomicI64::new(0);
        let dir = tempfile::tempdir().unwrap();
        // First drift emits; an immediate second drift is cooldown-suppressed.
        assert!(handle_gate_state(
            dir.path(),
            &drift_state(),
            None,
            10_000,
            &slot
        ));
        assert!(
            !handle_gate_state(dir.path(), &drift_state(), None, 10_100, &slot),
            "second drift within the cooldown window must NOT re-emit"
        );
    }

    #[test]
    fn handle_gate_state_noop_when_healthy() {
        let slot = AtomicI64::new(0);
        let dir = tempfile::tempdir().unwrap();
        let healthy = GateState {
            signed_count: Some(1685),
            intended_mode: Some(GateMode::Observe),
            live_count: Some(1685),
            live_mode: GateMode::Observe,
            live_scope_armed: None,
            live_scope_count: None,
        };
        assert!(!handle_gate_state(
            dir.path(),
            &healthy,
            None,
            10_000,
            &slot
        ));
    }

    #[test]
    fn handle_gate_state_flags_armed_but_lsm_inactive() {
        // The Azure-6.17 OpenClaw-box finding: maps say enforce + scoped + full
        // allowlist (map-only verdict = healthy), but bpf is NOT in the active LSM
        // stack -> the hook can't run -> Critical self-incident so the operator is
        // told the gate is a no-op instead of silently trusting `mode:armed`.
        let slot = AtomicI64::new(0);
        let dir = tempfile::tempdir().unwrap();
        let armed = GateState {
            signed_count: Some(3628),
            intended_mode: Some(GateMode::Enforce),
            live_count: Some(3628),
            live_mode: GateMode::Enforce,
            live_scope_armed: Some(true),
            live_scope_count: Some(1),
        };
        // bpf active / unknown => no incident (map verdict healthy)
        assert!(!handle_gate_state(
            dir.path(),
            &armed,
            Some(true),
            10_000,
            &slot
        ));
        assert!(!handle_gate_state(dir.path(), &armed, None, 10_050, &slot));
        // bpf inactive => Critical incident
        assert!(handle_gate_state(
            dir.path(),
            &armed,
            Some(false),
            10_100,
            &slot
        ));
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let body =
            std::fs::read_to_string(dir.path().join(format!("incidents-{today}.jsonl"))).unwrap();
        assert!(body.contains("armed_but_lsm_inactive"));
        assert!(body.contains("critical"));
    }

    #[test]
    fn tick_runs_end_to_end_and_is_noop_without_a_gate() {
        reset_throttle_for_test();
        let dir = tempfile::tempdir().unwrap();
        // No signed file + no pinned maps on the test host → GateState is
        // all-None / inert → Divergence::None → no incident. Drives the tick
        // orchestrator + gather_gate_state + read_signed_allowlist + the live
        // reader (stub off Linux). Must not panic and must write nothing.
        process_execution_gate_tick(dir.path());
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        assert!(
            !dir.path().join(format!("incidents-{today}.jsonl")).exists(),
            "a host with no gate must not produce an execution-gate incident"
        );
    }

    #[test]
    fn interval_elapsed_respects_min_and_never_state() {
        assert!(interval_elapsed(0, 1000, 600), "never-fired always allowed");
        assert!(!interval_elapsed(1000, 1100, 600), "100s < 600s");
        assert!(interval_elapsed(1000, 1600, 600), "exactly 600s elapsed");
        assert!(interval_elapsed(1000, 5000, 600));
    }

    #[test]
    fn throttle_allows_then_blocks_until_interval() {
        let slot = AtomicI64::new(0);
        assert!(
            throttle_allows(&slot, 1000, 600),
            "first call claims the slot"
        );
        assert!(
            !throttle_allows(&slot, 1300, 600),
            "within interval blocked"
        );
        assert!(
            throttle_allows(&slot, 1600, 600),
            "interval elapsed re-allows"
        );
    }

    #[test]
    fn no_incident_for_healthy_state() {
        let gate = GateState {
            signed_count: None,
            intended_mode: None,
            live_count: Some(0),
            live_mode: GateMode::Inert,
            live_scope_armed: None,
            live_scope_count: None,
        };
        let d = evaluate_divergence(&gate);
        assert!(build_divergence_incident("h", &gate, &d, chrono::Utc::now()).is_none());
    }

    #[test]
    fn apply_drift_builds_high_incident_the_oracle_case() {
        let gate = GateState {
            signed_count: Some(1685),
            intended_mode: Some(GateMode::Observe),
            live_count: Some(0),
            live_mode: GateMode::Inert,
            live_scope_armed: None,
            live_scope_count: None,
        };
        let d = evaluate_divergence(&gate);
        let inc = build_divergence_incident("oracle", &gate, &d, chrono::Utc::now())
            .expect("drift => incident");
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.incident_id.starts_with("execution_gate:apply_drift"));
        assert_eq!(inc.evidence["signed_count"], 1685);
        assert_eq!(inc.evidence["live_count"], 0);
        assert_eq!(inc.evidence["live_mode"], "inert");
        assert!(inc.tags.iter().any(|t| t == "execution-gate"));
    }

    #[test]
    fn enforce_empty_builds_critical_brick_incident() {
        let gate = GateState {
            signed_count: Some(10),
            intended_mode: Some(GateMode::Enforce),
            live_count: Some(0),
            live_mode: GateMode::Enforce,
            live_scope_armed: None,
            live_scope_count: None,
        };
        let d = evaluate_divergence(&gate);
        let inc = build_divergence_incident("box", &gate, &d, chrono::Utc::now()).unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.incident_id.contains("active_but_empty"));
        assert!(inc.title.contains("armed with an empty allowlist"));
    }

    #[test]
    fn observe_empty_builds_high_blind_incident() {
        let gate = GateState {
            signed_count: None,
            intended_mode: None,
            live_count: Some(0),
            live_mode: GateMode::Observe,
            live_scope_armed: None,
            live_scope_count: None,
        };
        let d = evaluate_divergence(&gate);
        let inc = build_divergence_incident("box", &gate, &d, chrono::Utc::now()).unwrap();
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.incident_id.contains("active_but_empty"));
    }

    #[test]
    fn scope_armed_but_empty_builds_high_false_security_incident() {
        // Gate enforce + agent-scoped, allowlist FULL, but scope map empty: it
        // protects nothing (every exec out-of-scope). High false-security, not a
        // brick.
        let gate = GateState {
            signed_count: None,
            intended_mode: None,
            live_count: Some(50),
            live_mode: GateMode::Enforce,
            live_scope_armed: Some(true),
            live_scope_count: Some(0),
        };
        let d = evaluate_divergence(&gate);
        let inc = build_divergence_incident("box", &gate, &d, chrono::Utc::now())
            .expect("scope-armed-but-empty => incident");
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.incident_id.contains("scope_armed_but_empty"));
        assert!(inc.title.contains("agent-scoped but no cgroup"));
        assert_eq!(inc.evidence["live_scope_count"], 0);
        assert_eq!(inc.evidence["live_scope_armed"], true);
    }

    #[test]
    fn write_incident_appends_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let gate = GateState {
            signed_count: Some(1685),
            intended_mode: Some(GateMode::Observe),
            live_count: Some(0),
            live_mode: GateMode::Inert,
            live_scope_armed: None,
            live_scope_count: None,
        };
        let d = evaluate_divergence(&gate);
        let inc = build_divergence_incident("h", &gate, &d, chrono::Utc::now()).unwrap();
        write_incident(dir.path(), "2026-06-17", &inc);
        let body = std::fs::read_to_string(dir.path().join("incidents-2026-06-17.jsonl")).unwrap();
        assert!(body.contains("apply_drift"));
        // round-trips as a valid Incident line
        let parsed: Incident = serde_json::from_str(body.trim()).unwrap();
        assert_eq!(parsed.severity, Severity::High);
    }

    #[test]
    fn signed_reader_is_none_when_file_absent() {
        // SIGNED_ALLOWLIST_FILE won't exist on the test host → (None, None).
        let (c, m) = read_signed_allowlist();
        // On a dev/CI box without the paid file this is None; assert it doesn't panic
        // and is internally consistent (mode only when a file parsed).
        if c.is_none() {
            assert!(m.is_none());
        }
    }
}
