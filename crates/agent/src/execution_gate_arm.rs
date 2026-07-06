//! Execution Gate WRITER (spec 083 arming) — applies a vetted
//! [`innerwarden_core::execution_gate::ArmPlan`] to the pinned kernel maps via
//! aya, agent-scoped only.
//!
//! The SAFETY decision (refuse enforce-with-empty, require a scope cgroup, etc.)
//! is `core::plan_arm` — pure and unit-tested. This file is only the apply: the
//! actual `EXEC_ALLOWLIST` / `EXEC_GATE_SCOPE` / `LSM_POLICY` writes, which need
//! CAP_BPF + the real pins that CI lacks, so it is excluded from the patch
//! coverage gate (codecov.yml) exactly like `execution_gate_aya.rs`. Correctness
//! of the writes is proven on a real kernel by the `#[ignore]`d on-box test at
//! the bottom (run with `cargo test -p innerwarden-agent -- --ignored`).
//!
//! The arm/disarm functions have no in-tree caller yet — the `innerwarden
//! exec-gate` command + the observe->enforce rehearsal that drive them are a
//! follow-up (PR4). They are validated here and wired there.
#![allow(dead_code)]

#[cfg(target_os = "linux")]
use innerwarden_core::execution_gate::{self, ArmPlan, GateMode};
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;

/// Resolve a pid's cgroup-v2 id = the inode of its cgroupfs directory, which is
/// exactly what `bpf_get_current_cgroup_id()` returns and what `EXEC_GATE_SCOPE`
/// keys on. `None` if the unified path can't be parsed or the dir can't be
/// stat'd (cgroup v1-only host, or the pid is gone).
#[cfg(target_os = "linux")]
pub(crate) fn resolve_cgroup_id(pid: u32) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = execution_gate::parse_cgroup_v2_path(&raw)?;
    // cgroup2 is mounted at /sys/fs/cgroup; the unified "/foo" maps to that dir.
    let dir = format!("/sys/fs/cgroup{rel}");
    std::fs::metadata(&dir).ok().map(|m| m.ino())
}

/// Live `EXEC_ALLOWLIST` key set, for the reconcile diff. Empty on any read
/// failure (the reconcile then simply inserts the whole target).
#[cfg(target_os = "linux")]
fn live_allowlist_keys() -> BTreeSet<u64> {
    use aya::maps::{HashMap as AyaHashMap, Map, MapData};
    let Ok(md) = MapData::from_pin(execution_gate::EXEC_ALLOWLIST_PIN) else {
        return BTreeSet::new();
    };
    let Ok(typed) = AyaHashMap::<MapData, u64, u8>::try_from(Map::HashMap(md)) else {
        return BTreeSet::new();
    };
    typed.keys().filter_map(|k| k.ok()).collect()
}

/// Apply a vetted [`ArmPlan`] to the kernel maps. ORDER is chosen for
/// host-safety:
/// 1. reconcile the allowlist — **inserts before removes**, so the live set is
///    never a strict subset of the target mid-apply (no transient under-coverage);
/// 2. write the scope cgroup id into `EXEC_GATE_SCOPE`;
/// 3. set `LSM_POLICY` key 4 = 1 (scoped) **before** key 3 (mode), so the gate is
///    already scoped the instant it goes active — there is never a window of
///    host-wide enforcement.
#[cfg(target_os = "linux")]
pub(crate) fn apply_arm_plan(plan: &ArmPlan) -> anyhow::Result<()> {
    use aya::maps::{HashMap as AyaHashMap, Map, MapData};
    // 1. allowlist reconcile (insert, then remove)
    {
        let md = MapData::from_pin(execution_gate::EXEC_ALLOWLIST_PIN)?;
        let mut al = AyaHashMap::<MapData, u64, u8>::try_from(Map::HashMap(md))?;
        for k in &plan.reconcile.to_insert {
            al.insert(k, 1u8, 0)?;
        }
        for k in &plan.reconcile.to_remove {
            let _ = al.remove(k);
        }
    }
    // 2. scope cgroup id
    {
        let md = MapData::from_pin(execution_gate::EXEC_GATE_SCOPE_PIN)?;
        let mut sc = AyaHashMap::<MapData, u64, u8>::try_from(Map::HashMap(md))?;
        sc.insert(plan.scope_cgroup_id, 1u8, 0)?;
    }
    // 3. policy: scope bit FIRST, then mode
    {
        let md = MapData::from_pin(execution_gate::LSM_POLICY_PIN)?;
        let mut pol = AyaHashMap::<MapData, u32, u32>::try_from(Map::HashMap(md))?;
        pol.insert(execution_gate::GATE_SCOPE_KEY, 1u32, 0)?; // key 4 = scoped
        let mode_val: u32 = match plan.mode {
            GateMode::Enforce => 1,
            GateMode::Observe => 2,
            _ => 0,
        };
        pol.insert(execution_gate::GATE_MODE_KEY, mode_val, 0)?; // key 3 = mode
    }
    Ok(())
}

/// Disarm: set mode inert (key 3 = 0) FIRST so the gate stops denying
/// immediately, then clear the scope bit (key 4 = 0). The allowlist + scope-map
/// entries are left in place (harmless while inert; a re-arm reconciles them).
/// Always safe, no preconditions — disarm must work even with no entitlement.
#[cfg(target_os = "linux")]
pub(crate) fn disarm() -> anyhow::Result<()> {
    use aya::maps::{HashMap as AyaHashMap, Map, MapData};
    let md = MapData::from_pin(execution_gate::LSM_POLICY_PIN)?;
    let mut pol = AyaHashMap::<MapData, u32, u32>::try_from(Map::HashMap(md))?;
    pol.insert(execution_gate::GATE_MODE_KEY, 0u32, 0)?; // inert first
    pol.insert(execution_gate::GATE_SCOPE_KEY, 0u32, 0)?;
    Ok(())
}

/// Resolve a pid's cgroup, vet the request via `core::plan_arm`, and apply it —
/// agent-scoped. The single entry the CLI/agent flow (PR4) will call. Returns the
/// applied plan, or an error carrying the safety refusal.
#[cfg(target_os = "linux")]
pub(crate) fn arm_scoped(
    pid: u32,
    target_paths: &[String],
    mode: GateMode,
) -> anyhow::Result<ArmPlan> {
    let cgid = resolve_cgroup_id(pid).unwrap_or(0);
    let target = execution_gate::target_allowlist_keys(target_paths);
    let live = live_allowlist_keys();
    let plan = execution_gate::plan_arm(target, &live, cgid, mode)
        .map_err(|r| anyhow::anyhow!("execution gate arm refused: {r:?}"))?;
    apply_arm_plan(&plan)?;
    Ok(plan)
}

// ── On-box validation (real kernel only) ──────────────────────────────────────
// Ignored by default: needs CAP_BPF + the pinned gate maps, which CI has neither
// of. Run on a box with the sensor loaded (gate attached + inert):
//   sudo -E cargo test -p innerwarden-agent -- --ignored exec_gate_arm_roundtrip
// OBSERVE-ONLY: it never sets enforce, so even a panic mid-test cannot deny an
// exec; it disarms at the end regardless.
#[cfg(all(test, target_os = "linux"))]
mod onbox {
    use super::*;
    use aya::maps::{HashMap as AyaHashMap, Map, MapData};

    fn live_policy(key: u32) -> Option<u32> {
        let md = MapData::from_pin(execution_gate::LSM_POLICY_PIN).ok()?;
        let typed = AyaHashMap::<MapData, u32, u32>::try_from(Map::HashMap(md)).ok()?;
        typed.get(&key, 0).ok()
    }
    fn scope_has(id: u64) -> bool {
        let Ok(md) = MapData::from_pin(execution_gate::EXEC_GATE_SCOPE_PIN) else {
            return false;
        };
        let Ok(typed) = AyaHashMap::<MapData, u64, u8>::try_from(Map::HashMap(md)) else {
            return false;
        };
        typed.get(&id, 0).is_ok()
    }

    #[test]
    #[ignore = "needs CAP_BPF + pinned gate maps; run on a real box with --ignored"]
    fn exec_gate_arm_roundtrip() {
        // Resolve THIS test process's own cgroup id.
        let pid = std::process::id();
        let cgid = resolve_cgroup_id(pid).expect("resolve own cgroup id");
        assert!(cgid != 0, "cgroup id must be non-zero");

        // Arm OBSERVE (never denies), scoped to our cgroup, allowlisting /bin/true.
        let plan = arm_scoped(pid, &["/usr/bin/true".to_string()], GateMode::Observe)
            .expect("observe arm should apply");
        assert_eq!(plan.scope_cgroup_id, cgid);

        // Verify the live maps reflect the arm.
        assert_eq!(
            live_policy(execution_gate::GATE_MODE_KEY),
            Some(2),
            "key3 observe"
        );
        assert_eq!(
            live_policy(execution_gate::GATE_SCOPE_KEY),
            Some(1),
            "key4 scoped"
        );
        assert!(scope_has(cgid), "our cgroup id is in EXEC_GATE_SCOPE");

        // Disarm -> inert.
        disarm().expect("disarm");
        assert_eq!(
            live_policy(execution_gate::GATE_MODE_KEY),
            Some(0),
            "key3 inert"
        );
        assert_eq!(
            live_policy(execution_gate::GATE_SCOPE_KEY),
            Some(0),
            "key4 off"
        );
    }
}
