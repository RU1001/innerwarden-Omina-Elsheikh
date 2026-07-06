//! Aya FFI layer for the Execution Gate live maps (spec 080 G4).
//!
//! Excluded from the patch-coverage gate (see codecov.yml) for the same reason
//! as `lsm_policy/aya_impl.rs`: every line here calls into aya, which calls into
//! the kernel — reading the pinned maps at
//! `/sys/fs/bpf/innerwarden/{exec_allowlist,lsm_policy}` needs CAP_BPF + the real
//! pins, which CI has neither of. The testable verdict logic this delegates to
//! (`innerwarden_core::execution_gate` + the monitor's pure helpers) is
//! unit-tested; end-to-end validation happens against the prod kernel.

#[cfg(target_os = "linux")]
use innerwarden_core::execution_gate;
use innerwarden_core::execution_gate::GateMode;

/// `(live EXEC_ALLOWLIST count, live gate mode, live scope-armed, live
/// EXEC_GATE_SCOPE count)`. Any `None` means that map could not be read (no pin,
/// no privilege, non-Linux) — the verdict treats it as "unknown, do not cry
/// wolf". `scope_armed = Some(true)` when `LSM_POLICY` key 4 = 1 (spec 083).
#[cfg(target_os = "linux")]
pub(crate) fn read_live_gate() -> (Option<usize>, GateMode, Option<bool>, Option<usize>) {
    let (scope_armed, scope_count) = read_live_scope();
    (
        read_live_allowlist_count(),
        read_live_gate_mode(),
        scope_armed,
        scope_count,
    )
}

/// `(scope armed from LSM_POLICY key 4, EXEC_GATE_SCOPE entry count)`. When the
/// policy map reads but key 4 is absent, scope is host-wide => `Some(false)`;
/// when the map can't be read at all, `None` (unknown). The scope-entry count is
/// `None` only when EXEC_GATE_SCOPE itself can't be read.
#[cfg(target_os = "linux")]
fn read_live_scope() -> (Option<bool>, Option<usize>) {
    use aya::maps::{HashMap as AyaHashMap, Map, MapData};
    let armed = (|| {
        // The OUTER `?` is what distinguishes "map unreadable" (-> None, unknown)
        // from a readable map. Once readable, `get` returns Err for an absent key;
        // `.ok().unwrap_or(0)` maps that (and an unreadable value) to 0 = host-wide,
        // so key 4 absent => Some(false), key 4 == 1 => Some(true). The value can
        // only become `true` when the key is actually present and equal to 1.
        let md = MapData::from_pin(execution_gate::LSM_POLICY_PIN).ok()?;
        let typed = AyaHashMap::<MapData, u32, u32>::try_from(Map::HashMap(md)).ok()?;
        Some(
            typed
                .get(&execution_gate::GATE_SCOPE_KEY, 0)
                .ok()
                .unwrap_or(0)
                == 1,
        )
    })();
    let count = (|| {
        let md = MapData::from_pin(execution_gate::EXEC_GATE_SCOPE_PIN).ok()?;
        let typed = AyaHashMap::<MapData, u64, u8>::try_from(Map::HashMap(md)).ok()?;
        Some(typed.keys().filter(|k| k.is_ok()).count())
    })();
    (armed, count)
}

#[cfg(target_os = "linux")]
fn read_live_allowlist_count() -> Option<usize> {
    use aya::maps::{HashMap as AyaHashMap, Map, MapData};
    let md = MapData::from_pin(execution_gate::EXEC_ALLOWLIST_PIN).ok()?;
    let map = Map::HashMap(md);
    let typed = AyaHashMap::<MapData, u64, u8>::try_from(map).ok()?;
    Some(typed.keys().filter(|k| k.is_ok()).count())
}

#[cfg(target_os = "linux")]
fn read_live_gate_mode() -> GateMode {
    use aya::maps::{HashMap as AyaHashMap, Map, MapData};
    let Ok(md) = MapData::from_pin(execution_gate::LSM_POLICY_PIN) else {
        return GateMode::Inert; // no policy map = nothing consults the gate
    };
    let map = Map::HashMap(md);
    let Ok(typed) = AyaHashMap::<MapData, u32, u32>::try_from(map) else {
        return GateMode::Inert;
    };
    let v = typed.get(&execution_gate::GATE_MODE_KEY, 0).ok();
    GateMode::from_policy_key(v)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn read_live_gate() -> (Option<usize>, GateMode, Option<bool>, Option<usize>) {
    // No BPF maps off Linux — unknown live state, inert, scope unknown.
    (None, GateMode::Inert, None, None)
}
