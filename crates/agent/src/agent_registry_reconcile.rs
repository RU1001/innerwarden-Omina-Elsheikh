//! Spec 081 follow-up — auto-register co-located AI agents so the managed-agent
//! response gate stays robust across agent restarts.
//!
//! ## Why
//! Spec 081 withholds the auto-block / kernel-deny RESPONSE for a positively
//! verified, IW-managed AI agent (e.g. OpenClaw) reading its OWN config and
//! connecting to its OWN services. The verifier's FIRST signal is a registry hit
//! (`registry.by_pid(pid)` in [`crate::managed_agent_guard`]). Today that
//! registry is populated only when the operator runs `innerwarden agent connect
//! <pid>`, and entries are **PID-keyed**. When the co-located agent restarts it
//! gets a new pid, the stored entry is stale, the verifier returns `NotManaged`,
//! and enforce re-severs the agent IW is meant to guard.
//!
//! ## What this does
//! On the slow loop (throttled to ~5 min via a timestamp on `AgentState`, NOT
//! every 30s tick), reconcile the registry with the live agent processes:
//!   1. `agent_guard::detect::scan_processes` finds running processes matching a
//!      known agent signature (`identify_cmdline`), returning a name + pid per
//!      agent.
//!   2. Any detected pid NOT already in the registry is `connect()`-ed — the
//!      hardened `connect()` captures the live `/proc` exe_path / owner_uid /
//!      cmdline_fingerprint the spec-081 verifier cross-checks.
//!   3. Any registry entry whose pid is no longer a live process (not in the
//!      freshly-detected set AND `/proc/<pid>` is gone) is `disconnect()`-ed, so a
//!      recycled/stale pid can never inherit the spec-081 exemption.
//!   4. Persist the registry after any change to the SAME
//!      `agent-guard-registry.json` snapshot the agent loads at boot.
//!
//! ## Security — this does NOT widen the spec-081 exemption (no new hole)
//! Auto-registration only provides the `registry.by_pid(pid)` MEMBERSHIP hint.
//! The spec-081 verifier ([`crate::managed_agent_guard::decide`]) STILL
//! independently gates the auto-block exemption on ALL of: a live
//! `identify_cmdline` re-ID of the running process, an EXACT
//! `cmdline_fingerprint` equality against the value captured at connect, the
//! interpreter + identity script sitting in a trusted (non-attacker-writable)
//! root, the incident's read path being the agent's OWN config (own home /
//! install dir, owned by the agent's uid, and NOT a high-value credential
//! sub-path), and a matching uid — all re-verified LIVE at decision time,
//! fail-closed. `scan_processes` only returns processes that already match a
//! known agent SIGNATURE, and the verifier additionally rejects any registry
//! entry whose `kind` is not `Agent`/`Tool` (so an auto-registered `Runtime`
//! like Ollama is never exempted). So auto-registering detected agents cannot
//! grant the response relaxation to anything the verifier would not already
//! accept on its own (a real agent running from a trusted path reading its own
//! config). Pruning dead pids is pure hardening: it removes the only thing a
//! pid-recycling attacker could try to inherit.

use std::path::Path;

use innerwarden_agent_guard::detect::{self, DetectedAgent};
use innerwarden_agent_guard::registry::Registry;
use tracing::{info, warn};

use crate::{config, AgentState};

/// Reconcile at most once per this interval. The slow loop ticks every ~30s; the
/// registry only needs to track agent restarts, so 5 min is plenty and keeps the
/// per-tick `/proc` scan cost negligible.
const RECONCILE_INTERVAL_SECS: u64 = 300;

/// Never register beyond this many agents. A co-located host runs a handful; this
/// is a guard against a pathological scan (or a hostile attempt to flood the
/// registry with thousands of signature-matching processes) blowing the registry
/// up. Detection + the incident still fire for anything beyond the cap — only the
/// auto-registration is capped.
const MAX_REGISTERED_AGENTS: usize = 64;

/// Outcome of one reconcile pass — how many entries were added / removed. The
/// thin tick uses `changed()` to decide whether to persist.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReconcileOutcome {
    pub registered: usize,
    pub pruned: usize,
}

impl ReconcileOutcome {
    fn changed(&self) -> bool {
        self.registered > 0 || self.pruned > 0
    }
}

/// PURE reconcile core. Operates on an in-process [`Registry`] with an injected
/// `detected` list and a `pid_alive` predicate, so the whole add/prune/cap
/// behaviour is unit-testable without a real `/proc` or a live agent.
///
/// - Registers every detected pid that is not already in the registry, up to
///   `cap` total entries (never panics on a /proc race — a vanished pid simply
///   fails the hardened `connect()` capture and is logged, not fatal).
/// - Prunes every registry entry whose pid is neither in the freshly-detected
///   set NOR reported alive by `pid_alive`.
///
/// `pid_alive` lets the prune step keep a still-running registered agent that the
/// scan happened to miss this pass (e.g. a transient read race), so we only ever
/// drop a pid that is BOTH undetected AND dead.
pub(crate) fn reconcile<F>(
    registry: &mut Registry,
    detected: &[DetectedAgent],
    pid_alive: F,
    cap: usize,
) -> ReconcileOutcome
where
    F: Fn(u32) -> bool,
{
    let mut outcome = ReconcileOutcome::default();

    // The set of pids the scan reported as live agents this pass.
    let detected_pids: std::collections::HashSet<u32> = detected.iter().map(|d| d.pid).collect();

    // ── 1. Register newly-detected agents not already present ────────────────
    // `connect()` is the SINGLE gate: it rejects an already-registered pid (the
    // common steady-state case where the scan re-detects an agent it registered
    // a prior pass — operator `agent connect` or auto). We only count + log a
    // genuinely-new registration; a re-detect (or a lost race) returns Err and
    // is skipped. The hardened connect captures live /proc facts (exe_path /
    // owner_uid / cmdline_fingerprint) — exactly what the spec-081 verifier
    // cross-checks; a /proc race (pid gone between scan and connect) just yields
    // None facts, connect still succeeds, never panics.
    for d in detected {
        if registry.count_total() >= cap {
            warn!(cap, name = %d.name, pid = d.pid, "agent-guard auto-register: registry at cap, skipping further auto-registrations");
            break;
        }
        match registry.connect(&d.name, d.pid, None) {
            Ok(id) => {
                outcome.registered += 1;
                info!("auto-registered agent {} pid {} as {id}", d.name, d.pid);
            }
            // Already registered (re-detected) or lost a concurrent-insert race.
            // Benign and expected every steady-state pass — skip silently.
            Err(_) => continue,
        }
    }

    // ── 2. Prune entries whose pid is gone (undetected AND not alive) ─────────
    // Collect first (id, pid) so we don't mutate the registry while iterating it.
    let prune_ids: Vec<String> = registry
        .list()
        .into_iter()
        .filter(|a| !detected_pids.contains(&a.pid) && !pid_alive(a.pid))
        .map(|a| a.id)
        .collect();
    for id in prune_ids {
        if registry.disconnect(&id) {
            outcome.pruned += 1;
            info!("pruned stale managed agent registry entry {id} (pid no longer live)");
        }
    }

    outcome
}

/// `/proc/<pid>` liveness probe used by the production reconcile. A pid is alive
/// when its `/proc` dir exists. Cheap, never panics.
fn proc_pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Slow-loop entry point. No-op unless `[agent_guard] auto_register = true`.
/// Self-throttled via `state.last_agent_registry_reconcile` (a timestamp on
/// `AgentState`) so the `/proc` scan runs at most every
/// [`RECONCILE_INTERVAL_SECS`], not every 30s tick.
pub(crate) async fn process_agent_registry_reconcile_tick(
    cfg: &config::AgentGuardConfig,
    state: &mut AgentState,
    data_dir: &Path,
) {
    if !cfg.auto_register {
        return;
    }
    if state.last_agent_registry_reconcile.elapsed().as_secs() < RECONCILE_INTERVAL_SECS {
        return;
    }
    state.last_agent_registry_reconcile = std::time::Instant::now();

    // Scan /proc for known agent signatures (cmdline-aware). Cheap, fail-soft:
    // returns an empty vec when /proc is unreadable.
    let detected = detect::scan_processes(&state.signature_index);

    let outcome = {
        let mut registry = state.agent_registry.lock().await;
        reconcile(
            &mut registry,
            &detected,
            proc_pid_alive,
            MAX_REGISTERED_AGENTS,
        )
    };

    // Persist only when something changed, to the SAME snapshot the agent loads
    // at boot. Fail-soft: log on error, do not roll back the in-memory state
    // (matches the dashboard connect/disconnect persistence).
    if outcome.changed() {
        let snapshot_path = data_dir.join("agent-guard-registry.json");
        let registry = state.agent_registry.lock().await;
        if let Err(e) = registry.save_to(&snapshot_path) {
            warn!(error = %e, path = %snapshot_path.display(), "agent-guard auto-register: failed to persist registry after reconcile");
        } else {
            info!(
                registered = outcome.registered,
                pruned = outcome.pruned,
                "agent-guard auto-register: registry reconciled and persisted"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_agent_guard::signatures::SignatureIndex;

    /// Build a `DetectedAgent` the way `scan_processes` would, for a given
    /// signature name + pid. `integration`/`comm`/`vendor` are not load-bearing
    /// for the reconcile (only `name` + `pid` are), so keep them minimal.
    fn detected(name: &str, pid: u32) -> DetectedAgent {
        DetectedAgent {
            name: name.to_string(),
            vendor: "test".to_string(),
            pid,
            comm: "MainThread".to_string(),
            integration: "official".to_string(),
            mcp_configs: vec![],
        }
    }

    /// A pid-alive predicate from an explicit set of "live" pids — lets the prune
    /// tests run without touching a real `/proc`.
    fn alive_in(set: &[u32]) -> impl Fn(u32) -> bool + '_ {
        move |pid| set.contains(&pid)
    }

    #[test]
    fn registers_new_detected_agent_and_skips_already_registered() {
        let mut reg = Registry::new();
        // Operator already connected OpenClaw at pid 1000 (e.g. via `agent connect`).
        reg.connect("OpenClaw", 1000, Some("operator"))
            .expect("seed connect");
        let before = reg.count_total();

        // Scan finds the already-registered 1000 AND a new agent at 2000.
        let scan = [detected("OpenClaw", 1000), detected("Claude Code", 2000)];

        let outcome = reconcile(
            &mut reg,
            &scan,
            alive_in(&[1000, 2000]),
            MAX_REGISTERED_AGENTS,
        );

        // Only the NEW pid (2000) is registered; the existing 1000 is not doubled.
        assert_eq!(outcome.registered, 1, "exactly one new agent registered");
        assert_eq!(outcome.pruned, 0);
        assert_eq!(reg.count_total(), before + 1);
        assert!(reg.by_pid(2000).is_some(), "new agent now in registry");
        // 1000 still present exactly once (no duplicate-pid entry was minted).
        assert!(reg.by_pid(1000).is_some());
        assert_eq!(reg.list().iter().filter(|a| a.pid == 1000).count(), 1);
    }

    #[test]
    fn prunes_dead_pid_but_keeps_live_one() {
        let mut reg = Registry::new();
        // Two registered agents: 1000 (will be dead) and 2000 (still alive).
        reg.connect("OpenClaw", 1000, None).expect("connect 1000");
        reg.connect("OpenClaw", 2000, None).expect("connect 2000");

        // The scan this pass detects NEITHER (e.g. both missed by a comm rename),
        // but the liveness predicate reports 2000 alive (its /proc still exists)
        // and 1000 dead. Only the BOTH-undetected-AND-dead 1000 is pruned.
        let scan: [DetectedAgent; 0] = [];
        let outcome = reconcile(&mut reg, &scan, alive_in(&[2000]), MAX_REGISTERED_AGENTS);

        assert_eq!(outcome.registered, 0);
        assert_eq!(outcome.pruned, 1, "exactly the dead pid is pruned");
        assert!(
            reg.by_pid(1000).is_none(),
            "dead pid 1000 removed so a recycled pid can't inherit the exemption"
        );
        assert!(
            reg.by_pid(2000).is_some(),
            "still-alive pid 2000 kept even though this scan missed it"
        );
    }

    #[test]
    fn detected_live_entry_is_never_pruned() {
        // A registered agent the scan DID detect this pass must survive even if
        // the alive-predicate is pessimistic (defends the prune ordering).
        let mut reg = Registry::new();
        reg.connect("OpenClaw", 3000, None).expect("connect");
        let scan = [detected("OpenClaw", 3000)];
        let outcome = reconcile(&mut reg, &scan, alive_in(&[]), MAX_REGISTERED_AGENTS);
        assert_eq!(outcome.pruned, 0, "a detected pid is never pruned");
        assert!(reg.by_pid(3000).is_some());
    }

    #[test]
    fn respects_the_registration_cap() {
        let mut reg = Registry::new();
        // Seed one existing entry so the cap counts pre-existing entries too.
        // Mark pid 1 alive so the prune step keeps it (this test isolates the cap).
        reg.connect("OpenClaw", 1, None).expect("seed");
        let cap = 3;

        // Five distinct new detected agents; only (cap - 1) = 2 may be added.
        let scan: Vec<DetectedAgent> = (10..15).map(|p| detected("Claude Code", p)).collect();
        let outcome = reconcile(&mut reg, &scan, alive_in(&[1]), cap);

        assert_eq!(outcome.registered, cap - 1, "cap caps new registrations");
        assert_eq!(outcome.pruned, 0, "the alive seed is not pruned");
        assert_eq!(reg.count_total(), cap, "registry never exceeds the cap");
    }

    #[test]
    fn proc_race_pid_vanished_mid_scan_does_not_panic() {
        // A pid in the detected list that no longer exists when `connect` runs its
        // live /proc capture: the capture yields all-None facts but connect still
        // succeeds. This must not panic. We use a pid that is extremely unlikely
        // to be live (u32::MAX) so the real `connect` -> `capture_proc_facts`
        // hits its fail-soft all-None branch.
        let mut reg = Registry::new();
        let scan = [detected("OpenClaw", u32::MAX)];
        let outcome = reconcile(&mut reg, &scan, alive_in(&[]), MAX_REGISTERED_AGENTS);
        // It registered the entry (membership hint) without panicking; the
        // verifier will later fail-closed because the live /proc facts are gone.
        assert_eq!(outcome.registered, 1);
        assert!(reg.by_pid(u32::MAX).is_some());
    }

    #[test]
    fn empty_detected_and_all_alive_is_a_noop() {
        let mut reg = Registry::new();
        reg.connect("OpenClaw", 5000, None).expect("connect");
        let scan: [DetectedAgent; 0] = [];
        // Nothing detected, but the one entry is reported alive → no change.
        let outcome = reconcile(&mut reg, &scan, alive_in(&[5000]), MAX_REGISTERED_AGENTS);
        assert_eq!(outcome, ReconcileOutcome::default());
        assert!(reg.by_pid(5000).is_some());
    }

    #[tokio::test]
    async fn tick_skips_entirely_when_auto_register_false() {
        // auto_register = false → the whole step is a no-op: the throttle
        // timestamp is NOT advanced and the registry is untouched (no scan, no
        // persist). We prove the timestamp is left alone (still "long ago") so a
        // later enable runs immediately.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        // Make the throttle clearly "due" so only the disabled-gate can stop it.
        state.last_agent_registry_reconcile = std::time::Instant::now()
            - std::time::Duration::from_secs(RECONCILE_INTERVAL_SECS + 60);
        let due_before = state.last_agent_registry_reconcile;

        let cfg = config::AgentGuardConfig {
            auto_register: false,
        };
        process_agent_registry_reconcile_tick(&cfg, &mut state, dir.path()).await;

        assert_eq!(
            state.last_agent_registry_reconcile, due_before,
            "disabled step must not advance the throttle timestamp"
        );
        // No snapshot file was written by the disabled step.
        assert!(
            !dir.path().join("agent-guard-registry.json").exists(),
            "disabled step must not persist the registry"
        );
        // The registry remains empty (the test state seeds none).
        assert_eq!(state.agent_registry.lock().await.count_total(), 0);
    }

    #[tokio::test]
    async fn tick_throttle_blocks_a_second_immediate_call() {
        // First call (enabled, due) advances the throttle; a second immediate call
        // is throttled out and leaves the timestamp it just set.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.last_agent_registry_reconcile = std::time::Instant::now()
            - std::time::Duration::from_secs(RECONCILE_INTERVAL_SECS + 60);
        let cfg = config::AgentGuardConfig {
            auto_register: true,
        };
        process_agent_registry_reconcile_tick(&cfg, &mut state, dir.path()).await;
        let after_first = state.last_agent_registry_reconcile;
        // Within the interval → second call returns early without re-stamping.
        process_agent_registry_reconcile_tick(&cfg, &mut state, dir.path()).await;
        assert_eq!(
            state.last_agent_registry_reconcile, after_first,
            "a call within the interval must be throttled out"
        );
    }

    /// Active path WITH a real change: a registered agent whose pid is dead gets
    /// pruned by the live tick, the registry is persisted to disk, and the
    /// throttle advances. Covers the scan → reconcile-prune → changed → save_to
    /// branch that the no-change throttle test does not exercise.
    #[tokio::test]
    async fn tick_prunes_dead_pid_and_persists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        // A pid that does not exist in /proc: the scan won't detect it and
        // proc_pid_alive() is false, so the reconcile prunes it.
        const DEAD_PID: u32 = u32::MAX - 1;
        state
            .agent_registry
            .lock()
            .await
            .connect("OpenClaw", DEAD_PID, None)
            .expect("seed dead-pid agent");
        state.last_agent_registry_reconcile = std::time::Instant::now()
            - std::time::Duration::from_secs(RECONCILE_INTERVAL_SECS + 60);
        let cfg = config::AgentGuardConfig {
            auto_register: true,
        };

        process_agent_registry_reconcile_tick(&cfg, &mut state, dir.path()).await;

        assert!(
            state.agent_registry.lock().await.by_pid(DEAD_PID).is_none(),
            "the dead pid must be pruned by the active tick"
        );
        assert!(
            dir.path().join("agent-guard-registry.json").exists(),
            "a change (prune) must persist the registry snapshot to disk"
        );
        assert_ne!(
            state.last_agent_registry_reconcile,
            std::time::Instant::now()
                - std::time::Duration::from_secs(RECONCILE_INTERVAL_SECS + 60),
            "the throttle timestamp advanced"
        );
    }

    #[tokio::test]
    async fn tick_persist_failure_is_fail_soft_and_keeps_inmemory_change() {
        // save_to errors must NOT roll back the in-memory reconcile (fail-soft,
        // matches the dashboard connect/disconnect persistence). We force the
        // error by pointing the "data dir" at a regular FILE, so
        // `<file>/agent-guard-registry.json` cannot be created (ENOTDIR).
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        const DEAD_PID: u32 = u32::MAX - 2;
        state
            .agent_registry
            .lock()
            .await
            .connect("OpenClaw", DEAD_PID, None)
            .expect("seed dead-pid agent");
        state.last_agent_registry_reconcile = std::time::Instant::now()
            - std::time::Duration::from_secs(RECONCILE_INTERVAL_SECS + 60);
        let cfg = config::AgentGuardConfig {
            auto_register: true,
        };

        // A real file used as the (invalid) data dir so the snapshot write fails.
        let not_a_dir = dir.path().join("iam-a-file");
        std::fs::write(&not_a_dir, b"x").expect("write file");

        process_agent_registry_reconcile_tick(&cfg, &mut state, &not_a_dir).await;

        // The prune still happened in memory despite the persist failure.
        assert!(
            state.agent_registry.lock().await.by_pid(DEAD_PID).is_none(),
            "the dead pid is still pruned in memory even when persistence fails"
        );
        // And no snapshot was written under the bogus path.
        assert!(
            !not_a_dir.join("agent-guard-registry.json").exists(),
            "no snapshot is written when save_to fails"
        );
    }

    #[test]
    fn default_config_auto_register_is_on() {
        // The product should "just work" for a co-located agent.
        assert!(config::AgentGuardConfig::default().auto_register);
    }

    #[test]
    fn scan_processes_smoke_does_not_panic() {
        // Exercises the real /proc scan path used by the tick (result is
        // host-dependent; we only assert it returns without panicking).
        let index = SignatureIndex::new();
        let _ = detect::scan_processes(&index);
        // proc_pid_alive on our own pid is true on Linux, false elsewhere — either
        // way it must not panic.
        let _ = proc_pid_alive(std::process::id());
    }
}
