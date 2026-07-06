//! Execution Gate state + divergence verdict (spec 080 G4 — the FREE honesty net).
//!
//! Pure, dependency-light types shared by the agent (live aya map readers + the
//! slow-loop self-incident) and ctl (`doctor`'s read-only report). The honesty
//! rule — same principle as spec 076 block live-verify — is: NEVER trust the
//! signed config file as proof that the kernel is configured. Compare the signed
//! intent to the LIVE pinned map, and raise drift when they disagree, so the
//! paid Execution Gate can never silently go inert (the 2026-06-17 Oracle case:
//! a signed `observe` allowlist with 1685 entries while the kernel gate was
//! inert with 0 entries — staged but never applied).

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Pin path the sensor pins + the paid active-defence watcher writes. Lowercase
/// on purpose (an aya ByName pin would use the UPPERCASE map name; see the
/// spec-080-P0 note in `crates/sensor/src/collectors/ebpf_syscall.rs`).
pub const EXEC_ALLOWLIST_PIN: &str = "/sys/fs/bpf/innerwarden/exec_allowlist";
/// Pin path for the policy map (`u32 -> u32`).
pub const LSM_POLICY_PIN: &str = "/sys/fs/bpf/innerwarden/lsm_policy";
/// LSM_POLICY key 3 = gate_mode (0 inert, 1 enforce, 2 observe). See
/// `crates/sensor-ebpf/src/main.rs`.
pub const GATE_MODE_KEY: u32 = 3;
/// Default signed allowlist file (paid active-defence managed). Shape:
/// `{ "mode": "observe", "entries": { "<fnv>": "<path>", ... } }`.
pub const SIGNED_ALLOWLIST_FILE: &str = "/etc/innerwarden/exec_allowlist.json";
/// LSM_POLICY key 4 = scope mode (0 host-wide, 1 agent-scoped — spec 083). When
/// 1, the kernel gate only consults the allowlist for execs whose cgroup id is in
/// `EXEC_GATE_SCOPE`; every exec outside that set returns allow before any lookup
/// (the agent-scoped, host-safe arming path). See `crates/sensor-ebpf/src/main.rs`.
pub const GATE_SCOPE_KEY: u32 = 4;
/// Pin path for the agent-scope map (`u64 cgroup_id -> u8`, spec 083). The sensor
/// pins it; the writer (paid active-defence) populates the agent's cgroup id(s).
pub const EXEC_GATE_SCOPE_PIN: &str = "/sys/fs/bpf/innerwarden/exec_gate_scope";

/// The gate's operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateMode {
    /// Loaded but consulted for nothing — denies nothing (the free default).
    Inert,
    /// Denies an unknown exec with `-EPERM` (paid, armed).
    Enforce,
    /// Logs what it *would* deny but allows it (paid, telemetry).
    Observe,
    /// A policy value we don't recognise.
    Unknown,
}

impl GateMode {
    /// From the live LSM_POLICY key-3 value. A missing key (`None`) is inert —
    /// the kernel gate consults nothing until the bit is set.
    pub fn from_policy_key(v: Option<u32>) -> Self {
        match v {
            None | Some(0) => GateMode::Inert,
            Some(1) => GateMode::Enforce,
            Some(2) => GateMode::Observe,
            Some(_) => GateMode::Unknown,
        }
    }

    /// From the signed file's `mode` string.
    pub fn from_str_label(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "observe" => GateMode::Observe,
            "enforce" | "arm" | "armed" | "block" => GateMode::Enforce,
            "inert" | "off" | "disarm" | "disarmed" | "disabled" | "none" => GateMode::Inert,
            _ => GateMode::Unknown,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            GateMode::Inert => "inert",
            GateMode::Enforce => "enforce",
            GateMode::Observe => "observe",
            GateMode::Unknown => "unknown",
        }
    }

    /// Enforce or observe — the gate is actually doing something (and so the
    /// live allowlist had better be populated).
    pub fn is_active(&self) -> bool {
        matches!(self, GateMode::Enforce | GateMode::Observe)
    }
}

/// Live + intended Execution Gate state, gathered from the kernel maps + the
/// signed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateState {
    /// Entries in the signed allowlist file (`None` = no file / unreadable).
    pub signed_count: Option<usize>,
    /// Intended mode from the signed file's `mode` field (`None` = no file).
    pub intended_mode: Option<GateMode>,
    /// Entries in the LIVE pinned `EXEC_ALLOWLIST` map (`None` = map unavailable:
    /// gate not loaded, no pin, or no privilege to read it).
    pub live_count: Option<usize>,
    /// Live gate mode from `LSM_POLICY` key 3.
    pub live_mode: GateMode,
    /// Live scope mode from `LSM_POLICY` key 4 (spec 083): `Some(true)` =
    /// agent-scoped (the gate only consults the allowlist for cgroups in
    /// `EXEC_GATE_SCOPE`), `Some(false)` = host-wide, `None` = unreadable.
    pub live_scope_armed: Option<bool>,
    /// Entries in the live `EXEC_GATE_SCOPE` map — the cgroup ids the gate is
    /// scoped to (`None` = unreadable, like `live_count`).
    pub live_scope_count: Option<usize>,
}

/// Ignore a live-vs-signed gap smaller than this percent — the paid watcher
/// applies incrementally, so a small transient lag is not drift.
const APPLY_GAP_TOLERANCE_PCT: usize = 5;

/// The verdict of comparing live kernel state to signed intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// Live state matches intent (or nothing is configured) — healthy.
    None,
    /// The gate is ACTIVE (enforce/observe) but the live allowlist is empty.
    /// Enforce + empty = every exec denied (brick); observe + empty = blind.
    /// The single most dangerous state — highest priority.
    ActiveButEmpty { mode: GateMode, live: usize },
    /// A signed config exists (entries and/or an active intended mode) but the
    /// kernel never converged to it: live map short/empty, or live mode inert
    /// while the file intends active. The "staged-not-applied" drift.
    ApplyDrift {
        signed: usize,
        live: usize,
        intended_mode: Option<GateMode>,
        live_mode: GateMode,
    },
    /// The gate is ACTIVE and agent-scoped (`LSM_POLICY` key 4 = 1) but the live
    /// `EXEC_GATE_SCOPE` map is empty (spec 083). Every exec is then out-of-scope
    /// and returns allow before any allowlist lookup, so the gate protects
    /// NOTHING while appearing armed — a false sense of security (not a brick:
    /// nothing is denied). Distinct from `ActiveButEmpty`, which is the allowlist
    /// being empty while the gate WOULD gate.
    ScopeArmedButEmpty { mode: GateMode },
    /// The gate is ACTIVE (enforce/observe) in the maps, but the kernel's BPF
    /// LSM is not in the active LSM stack (`bpf` absent from
    /// `/sys/kernel/security/lsm`), so no `BPF_PROG_TYPE_LSM` hook — including
    /// `innerwarden_lsm_exec_gate` — can run. The gate denies NOTHING while the
    /// maps report `armed enforce`: the most dangerous false sense of security,
    /// because every other signal (mode, allowlist, scope) looks correct. Seen on
    /// stock Ubuntu/Azure kernels, whose `CONFIG_LSM` omits `bpf` and which were
    /// not booted with an explicit `lsm=...,bpf` on the kernel cmdline. OUTRANKS
    /// every other divergence: when the LSM cannot run, no map state matters.
    ArmedButLsmInactive { mode: GateMode },
}

impl Divergence {
    pub fn is_drift(&self) -> bool {
        !matches!(self, Divergence::None)
    }
}

/// The securityfs file that lists the LSMs the running kernel actually has in
/// its active stack (comma-separated). The BPF LSM can only enforce when `bpf`
/// appears here — which requires the kernel's `CONFIG_LSM` to include it OR the
/// box to have been booted with `lsm=...,bpf` on the cmdline. Stock Ubuntu/Azure
/// kernels omit it from `CONFIG_LSM`, so an operator can `arm enforce`, see
/// `mode:armed`, and be completely unprotected.
pub const KERNEL_LSM_PIN: &str = "/sys/kernel/security/lsm";

/// PURE: is `bpf` one of the comma-separated tokens in the kernel LSM list?
/// Exact-token match (splits on `,`) so a substring like `bpfoobar` never
/// counts. Trims whitespace/newlines.
pub fn bpf_in_lsm_list(contents: &str) -> bool {
    contents.trim().split(',').any(|t| t.trim() == "bpf")
}

/// Read [`KERNEL_LSM_PIN`] and report whether `bpf` is in the active LSM stack.
/// `None` when the file cannot be read (non-Linux, no securityfs, or no
/// privilege) — an unreadable list must NEVER be treated as "inactive" and cry
/// wolf, exactly like an unreadable map count (privilege-blind reader safety).
pub fn read_bpf_lsm_active() -> Option<bool> {
    std::fs::read_to_string(KERNEL_LSM_PIN)
        .ok()
        .map(|s| bpf_in_lsm_list(&s))
}

/// [`evaluate_divergence`] plus the kernel-LSM-active preflight. When the gate
/// is active in the maps but `bpf` is DEFINITIVELY not in the active LSM stack
/// (`Some(false)`), the BPF-LSM hook cannot run at all, so the gate is inert in
/// practice regardless of the maps — this OUTRANKS every map-derived divergence.
/// `None` (unreadable LSM list) is treated as "cannot tell" and falls through to
/// the normal map-based verdict (no wolf-crying). Callers that can read the LSM
/// list (ctl, the agent monitor) should use this; the pure map-only
/// [`evaluate_divergence`] stays for callers with no LSM visibility.
pub fn evaluate_divergence_with_lsm(s: &GateState, bpf_lsm_active: Option<bool>) -> Divergence {
    if s.live_mode.is_active() && bpf_lsm_active == Some(false) {
        return Divergence::ArmedButLsmInactive { mode: s.live_mode };
    }
    evaluate_divergence(s)
}

/// PURE verdict over a [`GateState`]. Order matters: active-but-empty (active
/// danger) outranks staged-not-applied.
///
/// A live map we could not read (`live_count = None`) NEVER produces drift on
/// its own — an unreadable map must not masquerade as "empty" and cry wolf
/// (privilege-blind reader safety).
pub fn evaluate_divergence(s: &GateState) -> Divergence {
    // 0) Agent-scoped (spec 083) but the scope map is empty: the gate is active
    //    and key 4 = 1, yet no cgroup is in EXEC_GATE_SCOPE, so every exec is
    //    out-of-scope -> allowed before any allowlist lookup. The gate protects
    //    nothing while looking armed. This OUTRANKS ActiveButEmpty: when the
    //    scope is empty the allowlist is never consulted, so an empty allowlist
    //    is not a brick here — the missing scope is the real problem.
    if s.live_mode.is_active() && s.live_scope_armed == Some(true) && s.live_scope_count == Some(0)
    {
        return Divergence::ScopeArmedButEmpty { mode: s.live_mode };
    }

    // 1) Live gate armed/observing but the allowlist is empty AND the gate would
    //    actually consult it: host-wide, or scoped-with-a-non-empty-scope, or the
    //    scope dimension is unknown.
    //
    //    Conservative call when scoped(=Some(true)) but the scope COUNT is
    //    unreadable (None): we can't confirm whether the scope gates every exec
    //    out, so we cannot promote to ScopeArmedButEmpty (step 0 needs
    //    `live_scope_count == Some(0)`). The allowlist IS readable and empty and
    //    the gate IS active, which is a real problem either way — an in-scope
    //    brick or no protection — so we still flag it here as ActiveButEmpty
    //    rather than hide it. (Symmetric with `live_count == None`, which never
    //    reaches this branch and stays silent — an unreadable allowlist must not
    //    masquerade as empty.)
    if s.live_mode.is_active() && s.live_count == Some(0) {
        return Divergence::ActiveButEmpty {
            mode: s.live_mode,
            live: 0,
        };
    }

    // 2) Signed config present but not converged in the kernel. Needs a real
    //    live read to claim drift.
    let signed = s.signed_count.unwrap_or(0);
    let intends_active = s.intended_mode.map(|m| m.is_active()).unwrap_or(false);
    if (signed > 0 || intends_active) && s.live_count.is_some() {
        let live_n = s.live_count.unwrap_or(0);
        let count_drift = signed > 0
            && live_n < signed
            && (live_n == 0 || (signed - live_n) * (100 / APPLY_GAP_TOLERANCE_PCT) > signed);
        let mode_drift = intends_active && !s.live_mode.is_active();
        if count_drift || mode_drift {
            return Divergence::ApplyDrift {
                signed,
                live: live_n,
                intended_mode: s.intended_mode,
                live_mode: s.live_mode,
            };
        }
    }

    Divergence::None
}

/// Parse the signed allowlist file JSON into `(entry_count, intended_mode)`.
/// Canonical shape `{ "mode": "observe", "entries": { ... } }`; tolerates a bare
/// entries array/object. Either component may be absent.
pub fn parse_signed_allowlist(value: &serde_json::Value) -> (Option<usize>, Option<GateMode>) {
    let count = match value.get("entries") {
        Some(e) => count_json_collection(e),
        None => match value {
            serde_json::Value::Array(a) => Some(a.len()),
            // A bare object with no wrapper fields = the entries map itself.
            serde_json::Value::Object(o) if !o.contains_key("mode") => Some(o.len()),
            _ => None,
        },
    };
    let mode = value
        .get("mode")
        .and_then(|m| m.as_str())
        .map(GateMode::from_str_label);
    (count, mode)
}

fn count_json_collection(v: &serde_json::Value) -> Option<usize> {
    match v {
        serde_json::Value::Array(a) => Some(a.len()),
        serde_json::Value::Object(o) => Some(o.len()),
        _ => None,
    }
}

/// Count entries in `bpftool map dump` text. bpftool prints one `key: …` block
/// per entry (or `"key": …` with `-j`), and newer versions append a
/// `Found N elements` summary; an empty map prints only the summary. Returns 0
/// when nothing parses.
pub fn count_bpftool_dump(text: &str) -> usize {
    let key_lines = text
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("key:") || t.starts_with("\"key\"")
        })
        .count();
    if key_lines > 0 {
        return key_lines;
    }
    for l in text.lines() {
        if let Some(rest) = l.trim().strip_prefix("Found ") {
            if let Some(n) = rest
                .split_whitespace()
                .next()
                .and_then(|x| x.parse::<usize>().ok())
            {
                return n;
            }
        }
    }
    0
}

/// Parse the `value:` u32 (little-endian, first 4 bytes) from a
/// `bpftool map lookup … key … value: BB BB BB BB` line. Used to read the live
/// gate mode (LSM_POLICY key 3) without aya from ctl. Returns `None` if the map
/// has no such key (`bpftool` prints "Not found" / non-zero) or it can't parse.
pub fn parse_bpftool_value_u32(text: &str) -> Option<u32> {
    let after = text.split("value:").nth(1)?;
    let bytes: Vec<u8> = after
        .split_whitespace()
        .take(4)
        .map(|b| u8::from_str_radix(b.trim_start_matches("0x"), 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    if bytes.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// FNV-1a (64-bit) of a path, hashed over the bytes up to the first NUL and
/// capped at 256 bytes — the userspace MIRROR of the in-kernel hasher
/// `fnv1a_path` in `crates/sensor-ebpf/src/main.rs`. This value IS the
/// `EXEC_ALLOWLIST` key: the kernel hashes the exec path the same way at
/// `bprm_check_security`, so a key produced here is exactly the key the kernel
/// looks up. The two implementations MUST stay byte-for-byte identical — if they
/// ever diverge, an armed *enforce* gate would deny every binary (no allowlist
/// key could ever match the kernel's hash). `fnv1a_*` tests pin that agreement,
/// including a source-parity check against the kernel constants.
pub fn fnv1a_path(buf: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a 64-bit offset basis
    let mut i = 0usize;
    // Bounded by 256 (mirrors the kernel's verifier-bounded loop) and by len.
    while i < 256 && i < buf.len() {
        let b = buf[i];
        if b == 0 {
            break;
        }
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3); // FNV-1a 64-bit prime
        i += 1;
    }
    h
}

/// Convenience: the `EXEC_ALLOWLIST` key for an executable path string. Equal to
/// [`fnv1a_path`] over the path's UTF-8 bytes.
pub fn allowlist_key(path: &str) -> u64 {
    fnv1a_path(path.as_bytes())
}

// ── Arming brain (spec 083): PURE planning ────────────────────────────────────
//
// What to WRITE to the kernel maps to arm the gate around the agent's cgroup.
// Everything here is pure + host-portable + unit-tested; it touches no map, does
// no I/O, and arms nothing. The actual writes (aya) + the cgroup-id stat that
// turns a parsed path into the inode the kernel compares are the on-box half,
// validated on a real kernel. Keeping the brain here means the diff/plan that
// drives an arm is testable without a kernel and a writer can never blind-wipe.

/// The set of `EXEC_ALLOWLIST` keys (FNV-1a of each path) for a target allowlist.
/// A `BTreeSet` so a plan is deterministic regardless of input order.
pub fn target_allowlist_keys(paths: &[String]) -> BTreeSet<u64> {
    paths.iter().map(|p| allowlist_key(p)).collect()
}

/// An idempotent reconcile plan to bring the LIVE `EXEC_ALLOWLIST` to a target
/// key set: only the difference, never a blind wipe (mirrors spec 076's
/// verify-live, re-apply-on-divergence). Empty plan = already converged.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReconcilePlan {
    /// Keys present in the target but not live — to insert.
    pub to_insert: BTreeSet<u64>,
    /// Keys present live but not in the target — to remove.
    pub to_remove: BTreeSet<u64>,
}

impl ReconcilePlan {
    /// Nothing to do — the live map already equals the target.
    pub fn is_noop(&self) -> bool {
        self.to_insert.is_empty() && self.to_remove.is_empty()
    }
}

/// Diff the live key set against the target. The caller applies `to_insert` then
/// `to_remove` against the pinned map; it must NEVER clear the map and rebuild
/// (that would leave a window of an empty allowlist under an armed enforce gate —
/// the brick). A purely additive-then-subtractive reconcile keeps the live set a
/// superset-or-equal of the target throughout.
pub fn reconcile_allowlist(live: &BTreeSet<u64>, target: &BTreeSet<u64>) -> ReconcilePlan {
    ReconcilePlan {
        to_insert: target.difference(live).copied().collect(),
        to_remove: live.difference(target).copied().collect(),
    }
}

/// Parse the cgroup-v2 path from the contents of `/proc/<pid>/cgroup`. Under the
/// unified hierarchy that file has a single `0::/<path>` line; the `/<path>` is
/// the cgroupfs-relative directory whose inode equals
/// `bpf_get_current_cgroup_id()` for that task (the key the kernel compares
/// against `EXEC_GATE_SCOPE`). Returns `None` for a cgroup-v1-only or empty file.
/// PURE: the caller stats `/sys/fs/cgroup/<path>` to get the id (on-box).
pub fn parse_cgroup_v2_path(proc_cgroup: &str) -> Option<String> {
    proc_cgroup.lines().find_map(|line| {
        // The unified (v2) controller line is the one with an empty controller
        // list: "0::/...". v1 lines look like "N:controller:/...".
        let path = line.strip_prefix("0::")?;
        let path = path.trim();
        if path.is_empty() {
            None
        } else {
            Some(path.to_string())
        }
    })
}

/// A vetted, SAFE plan to arm the gate around a single cgroup (agent-scoped,
/// spec 083). Only produced by [`plan_arm`] when the request passed every safety
/// check; the caller applies it via aya (insert/remove the reconcile, write the
/// scope cgroup id, then set the policy mode + scope bit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmPlan {
    /// Allowlist diff to reach the target (apply inserts BEFORE removes so the
    /// live set is never a strict subset of the target mid-apply).
    pub reconcile: ReconcilePlan,
    /// The cgroup id to write into `EXEC_GATE_SCOPE` (key 4 scoping target).
    pub scope_cgroup_id: u64,
    /// The mode to set in `LSM_POLICY` key 3 — `Observe` or `Enforce` only.
    pub mode: GateMode,
}

/// Why an arm request was refused. A refusal NEVER touches a map — the gate is
/// left exactly as it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArmRefusal {
    /// Enforce requested but the resulting allowlist would be empty: every
    /// in-scope exec would be denied (-EPERM), bricking the agent's own cgroup.
    /// The single most important guard (mirrors the k7 host-wide brick lesson,
    /// scaled to one pod). Observe-with-empty is allowed (it only learns).
    EnforceWithEmptyAllowlist,
    /// No cgroup id to scope to (unresolved / 0). A scoped gate with an empty
    /// scope protects nothing, so refuse rather than arm a no-op that looks armed.
    NoScopeCgroup,
    /// Mode was not `Observe`/`Enforce` — use the disarm path for inert.
    NotAnArmMode,
}

/// Vet an arm request and produce a SAFE [`ArmPlan`], or refuse. Pure: it reads
/// no map and writes nothing — the caller applies the returned plan via aya or
/// surfaces the refusal. Agent-scoped ONLY (a host-wide arm is not a product path
/// here — that is the brick the k7 incident proved). `cgroup_id == 0` means the
/// agent's cgroup could not be resolved.
pub fn plan_arm(
    target_keys: BTreeSet<u64>,
    live_keys: &BTreeSet<u64>,
    cgroup_id: u64,
    mode: GateMode,
) -> Result<ArmPlan, ArmRefusal> {
    if !mode.is_active() {
        return Err(ArmRefusal::NotAnArmMode);
    }
    if cgroup_id == 0 {
        return Err(ArmRefusal::NoScopeCgroup);
    }
    // After the reconcile the live allowlist == target_keys. Enforce over an
    // empty allowlist denies every in-scope exec — never arm that.
    if mode == GateMode::Enforce && target_keys.is_empty() {
        return Err(ArmRefusal::EnforceWithEmptyAllowlist);
    }
    let reconcile = reconcile_allowlist(live_keys, &target_keys);
    Ok(ArmPlan {
        reconcile,
        scope_cgroup_id: cgroup_id,
        mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(
        signed: Option<usize>,
        intended: Option<GateMode>,
        live: Option<usize>,
        live_mode: GateMode,
    ) -> GateState {
        // Scope unknown (None) by default — the spec-083 scope dimension only
        // affects the verdict when it is actually readable, so these legacy
        // host-wide-era cases behave exactly as before.
        GateState {
            signed_count: signed,
            intended_mode: intended,
            live_count: live,
            live_mode,
            live_scope_armed: None,
            live_scope_count: None,
        }
    }

    fn state_scoped(
        signed: Option<usize>,
        intended: Option<GateMode>,
        live: Option<usize>,
        live_mode: GateMode,
        scope_armed: Option<bool>,
        scope_count: Option<usize>,
    ) -> GateState {
        GateState {
            signed_count: signed,
            intended_mode: intended,
            live_count: live,
            live_mode,
            live_scope_armed: scope_armed,
            live_scope_count: scope_count,
        }
    }

    #[test]
    fn gate_mode_from_policy_key() {
        assert_eq!(GateMode::from_policy_key(None), GateMode::Inert);
        assert_eq!(GateMode::from_policy_key(Some(0)), GateMode::Inert);
        assert_eq!(GateMode::from_policy_key(Some(1)), GateMode::Enforce);
        assert_eq!(GateMode::from_policy_key(Some(2)), GateMode::Observe);
        assert_eq!(GateMode::from_policy_key(Some(9)), GateMode::Unknown);
    }

    #[test]
    fn gate_mode_from_str_and_active() {
        assert_eq!(GateMode::from_str_label("observe"), GateMode::Observe);
        assert_eq!(GateMode::from_str_label("ENFORCE"), GateMode::Enforce);
        assert_eq!(GateMode::from_str_label(" arm "), GateMode::Enforce);
        assert_eq!(GateMode::from_str_label("inert"), GateMode::Inert);
        assert_eq!(GateMode::from_str_label("wat"), GateMode::Unknown);
        assert!(GateMode::Enforce.is_active());
        assert!(GateMode::Observe.is_active());
        assert!(!GateMode::Inert.is_active());
        assert!(!GateMode::Unknown.is_active());
    }

    #[test]
    fn healthy_when_converged() {
        // armed observe, live populated to signed count — no drift.
        let d = evaluate_divergence(&state(
            Some(1685),
            Some(GateMode::Observe),
            Some(1685),
            GateMode::Observe,
        ));
        assert_eq!(d, Divergence::None);
    }

    #[test]
    fn healthy_when_nothing_configured() {
        // no signed file, gate inert, live readable + empty — an OSS box with
        // the gate loaded but never armed. Silent.
        let d = evaluate_divergence(&state(None, None, Some(0), GateMode::Inert));
        assert_eq!(d, Divergence::None);
    }

    #[test]
    fn the_oracle_case_is_apply_drift() {
        // signed observe / 1685, but kernel inert / 0 — staged-not-applied.
        let d = evaluate_divergence(&state(
            Some(1685),
            Some(GateMode::Observe),
            Some(0),
            GateMode::Inert,
        ));
        assert_eq!(
            d,
            Divergence::ApplyDrift {
                signed: 1685,
                live: 0,
                intended_mode: Some(GateMode::Observe),
                live_mode: GateMode::Inert,
            }
        );
        assert!(d.is_drift());
    }

    #[test]
    fn enforce_with_empty_map_is_active_but_empty_brick_risk() {
        let d = evaluate_divergence(&state(
            Some(1685),
            Some(GateMode::Enforce),
            Some(0),
            GateMode::Enforce,
        ));
        // ActiveButEmpty outranks ApplyDrift: live enforce + empty = brick.
        assert_eq!(
            d,
            Divergence::ActiveButEmpty {
                mode: GateMode::Enforce,
                live: 0
            }
        );
    }

    #[test]
    fn observe_with_empty_map_is_active_but_empty_blind() {
        let d = evaluate_divergence(&state(None, None, Some(0), GateMode::Observe));
        assert_eq!(
            d,
            Divergence::ActiveButEmpty {
                mode: GateMode::Observe,
                live: 0
            }
        );
    }

    #[test]
    fn unreadable_live_map_never_cries_wolf() {
        // signed says observe/1685 but we couldn't read the live map. No drift —
        // a privilege-blind reader must not claim the kernel is empty.
        let d = evaluate_divergence(&state(
            Some(1685),
            Some(GateMode::Observe),
            None,
            GateMode::Inert,
        ));
        assert_eq!(d, Divergence::None);
    }

    #[test]
    fn small_incremental_lag_within_tolerance_is_not_drift() {
        // 1685 signed, 1660 live (~1.5% behind) while still applying — tolerated.
        let d = evaluate_divergence(&state(
            Some(1685),
            Some(GateMode::Observe),
            Some(1660),
            GateMode::Observe,
        ));
        assert_eq!(d, Divergence::None);
    }

    #[test]
    fn large_count_gap_is_drift_even_when_modes_agree() {
        // 1685 signed vs 100 live (94% behind), both observe — apply stalled.
        let d = evaluate_divergence(&state(
            Some(1685),
            Some(GateMode::Observe),
            Some(100),
            GateMode::Observe,
        ));
        assert!(matches!(
            d,
            Divergence::ApplyDrift {
                signed: 1685,
                live: 100,
                ..
            }
        ));
    }

    #[test]
    fn mode_drift_alone_is_flagged() {
        // signed intends enforce, counts match, but live mode is inert.
        let d = evaluate_divergence(&state(
            Some(10),
            Some(GateMode::Enforce),
            Some(10),
            GateMode::Inert,
        ));
        assert!(matches!(
            d,
            Divergence::ApplyDrift {
                live_mode: GateMode::Inert,
                ..
            }
        ));
    }

    #[test]
    fn parse_signed_canonical_shape() {
        let v = serde_json::json!({
            "mode": "observe",
            "entries": { "111": "/usr/bin/a", "222": "/usr/bin/b", "333": "/usr/bin/c" }
        });
        let (count, mode) = parse_signed_allowlist(&v);
        assert_eq!(count, Some(3));
        assert_eq!(mode, Some(GateMode::Observe));
    }

    #[test]
    fn parse_signed_bare_array_and_missing_mode() {
        let v = serde_json::json!(["/a", "/b"]);
        let (count, mode) = parse_signed_allowlist(&v);
        assert_eq!(count, Some(2));
        assert_eq!(mode, None);
    }

    #[test]
    fn parse_signed_bare_entries_object() {
        let v = serde_json::json!({ "111": "/a", "222": "/b" });
        let (count, mode) = parse_signed_allowlist(&v);
        assert_eq!(count, Some(2));
        assert_eq!(mode, None);
    }

    #[test]
    fn count_bpftool_dump_variants() {
        // plain text entries
        let plain = "key: 01 02 03 04  value: 01\nkey: 05 06 07 08  value: 01\n";
        assert_eq!(count_bpftool_dump(plain), 2);
        // empty map summary
        assert_eq!(count_bpftool_dump("Found 0 elements"), 0);
        // json form
        let json = "[{\n\"key\": 1,\n\"value\": 1\n},{\n\"key\": 2,\n\"value\": 1\n}]";
        assert_eq!(count_bpftool_dump(json), 2);
        // nothing parseable
        assert_eq!(count_bpftool_dump("garbage"), 0);
    }

    #[test]
    fn parse_bpftool_value_u32_reads_little_endian() {
        // observe (2) at key 3
        let txt = "key: 03 00 00 00  value: 02 00 00 00";
        assert_eq!(parse_bpftool_value_u32(txt), Some(2));
        // enforce (1)
        assert_eq!(
            parse_bpftool_value_u32("key: 03 00 00 00  value: 01 00 00 00"),
            Some(1)
        );
        // no value section
        assert_eq!(parse_bpftool_value_u32("Not found"), None);
    }

    #[test]
    fn bpf_in_lsm_list_exact_token_only() {
        // real Azure 6.17 (bpf ABSENT) vs a bpf-enabled stack, plus anti-substring.
        assert!(!bpf_in_lsm_list(
            "lockdown,capability,landlock,yama,apparmor,ima,evm"
        ));
        assert!(bpf_in_lsm_list(
            "lockdown,capability,landlock,yama,apparmor,bpf,ima,evm\n"
        ));
        assert!(bpf_in_lsm_list("capability,bpf"));
        assert!(bpf_in_lsm_list(" bpf , yama ")); // whitespace tolerated
        assert!(!bpf_in_lsm_list("bpfoobar,capability")); // substring must NOT match
        assert!(!bpf_in_lsm_list("")); // empty
    }

    #[test]
    fn armed_but_lsm_inactive_outranks_everything() {
        // Gate armed enforce, scope+allowlist perfectly healthy, BUT bpf not in the
        // active LSM stack -> the hook cannot run -> the gate is inert in practice.
        // This is the real Azure-6.17 OpenClaw-box finding: mode:armed, silently no
        // enforcement. Must OUTRANK the map-derived verdict.
        let gate = state_scoped(
            Some(3628),
            Some(GateMode::Enforce),
            Some(3628),
            GateMode::Enforce,
            Some(true),
            Some(1),
        );
        // map-only verdict: healthy
        assert_eq!(evaluate_divergence(&gate), Divergence::None);
        // with the LSM preflight: inactive -> ArmedButLsmInactive
        let d = evaluate_divergence_with_lsm(&gate, Some(false));
        assert_eq!(
            d,
            Divergence::ArmedButLsmInactive {
                mode: GateMode::Enforce
            }
        );
        assert!(d.is_drift());
    }

    #[test]
    fn armed_but_lsm_inactive_outranks_scope_armed_but_empty() {
        // Even a would-be ScopeArmedButEmpty is superseded: if the LSM can't run,
        // the empty scope is moot.
        let gate = state_scoped(
            Some(10),
            Some(GateMode::Enforce),
            Some(10),
            GateMode::Enforce,
            Some(true),
            Some(0), // scope empty -> would be ScopeArmedButEmpty on map-only
        );
        assert_eq!(
            evaluate_divergence(&gate),
            Divergence::ScopeArmedButEmpty {
                mode: GateMode::Enforce
            }
        );
        assert_eq!(
            evaluate_divergence_with_lsm(&gate, Some(false)),
            Divergence::ArmedButLsmInactive {
                mode: GateMode::Enforce
            }
        );
    }

    #[test]
    fn lsm_active_or_unreadable_falls_through_to_map_verdict() {
        // bpf active (Some(true)) or unreadable (None) must NOT cry wolf: the
        // wrapper delegates to the pure map verdict.
        let healthy = state_scoped(
            Some(3628),
            Some(GateMode::Enforce),
            Some(3628),
            GateMode::Enforce,
            Some(true),
            Some(1),
        );
        assert_eq!(
            evaluate_divergence_with_lsm(&healthy, Some(true)),
            Divergence::None
        );
        assert_eq!(
            evaluate_divergence_with_lsm(&healthy, None),
            Divergence::None
        );
        // And an INERT gate on a bpf-less kernel is not flagged (nothing claims
        // to be enforcing, so there is no false sense of security).
        let inert = state(Some(0), None, Some(0), GateMode::Inert);
        assert_eq!(
            evaluate_divergence_with_lsm(&inert, Some(false)),
            Divergence::None
        );
    }

    #[test]
    fn scope_armed_but_empty_when_scoped_on_with_no_cgroup_in_scope() {
        // active + key4=scoped + EXEC_GATE_SCOPE empty => gate protects nothing.
        let d = evaluate_divergence(&state_scoped(
            Some(10),
            Some(GateMode::Enforce),
            Some(10), // allowlist is FULL — irrelevant, nothing is in scope
            GateMode::Enforce,
            Some(true),
            Some(0),
        ));
        assert_eq!(
            d,
            Divergence::ScopeArmedButEmpty {
                mode: GateMode::Enforce
            }
        );
        assert!(d.is_drift());
    }

    #[test]
    fn scope_empty_outranks_active_but_empty() {
        // scoped + scope-empty + allowlist ALSO empty: this is NOT a brick (every
        // exec is out-of-scope -> allowed), so it must read as ScopeArmedButEmpty,
        // not ActiveButEmpty.
        let d = evaluate_divergence(&state_scoped(
            None,
            None,
            Some(0),
            GateMode::Enforce,
            Some(true),
            Some(0),
        ));
        assert_eq!(
            d,
            Divergence::ScopeArmedButEmpty {
                mode: GateMode::Enforce
            }
        );
    }

    #[test]
    fn scoped_with_a_populated_scope_and_empty_allowlist_is_active_but_empty() {
        // scoped ON, scope has a cgroup, but the allowlist is empty: in-scope
        // execs WILL be denied -> the real brick-within-the-pod. ActiveButEmpty.
        let d = evaluate_divergence(&state_scoped(
            Some(5),
            Some(GateMode::Enforce),
            Some(0),
            GateMode::Enforce,
            Some(true),
            Some(1),
        ));
        assert_eq!(
            d,
            Divergence::ActiveButEmpty {
                mode: GateMode::Enforce,
                live: 0
            }
        );
    }

    #[test]
    fn host_wide_empty_allowlist_is_still_active_but_empty() {
        // key4=host-wide (Some(false)) + empty allowlist + enforce = host brick.
        let d = evaluate_divergence(&state_scoped(
            None,
            None,
            Some(0),
            GateMode::Enforce,
            Some(false),
            None,
        ));
        assert_eq!(
            d,
            Divergence::ActiveButEmpty {
                mode: GateMode::Enforce,
                live: 0
            }
        );
    }

    #[test]
    fn scope_unreadable_does_not_change_the_verdict() {
        // scope dimension unknown (None) -> behaves exactly like the pre-spec-083
        // logic: active + empty allowlist = ActiveButEmpty.
        let d = evaluate_divergence(&state_scoped(
            None,
            None,
            Some(0),
            GateMode::Observe,
            None,
            None,
        ));
        assert_eq!(
            d,
            Divergence::ActiveButEmpty {
                mode: GateMode::Observe,
                live: 0
            }
        );
    }

    #[test]
    fn scoped_but_scope_count_unreadable_falls_back_to_active_but_empty() {
        // key4=scoped(true) but EXEC_GATE_SCOPE unreadable (None) + empty
        // allowlist: we cannot confirm the scope is empty, so we do NOT promote
        // to ScopeArmedButEmpty (step 0 needs scope_count==Some(0)); the empty
        // allowlist on an active gate is still flagged conservatively.
        let d = evaluate_divergence(&state_scoped(
            None,
            None,
            Some(0),
            GateMode::Enforce,
            Some(true),
            None,
        ));
        assert_eq!(
            d,
            Divergence::ActiveButEmpty {
                mode: GateMode::Enforce,
                live: 0
            }
        );
    }

    #[test]
    fn scoped_and_converged_is_healthy() {
        // scoped ON, scope populated, allowlist populated, mode observe -> no drift.
        let d = evaluate_divergence(&state_scoped(
            Some(10),
            Some(GateMode::Observe),
            Some(10),
            GateMode::Observe,
            Some(true),
            Some(2),
        ));
        assert_eq!(d, Divergence::None);
    }

    #[test]
    fn fnv1a_matches_canonical_fnv1a_64_vectors() {
        // Canonical FNV-1a 64-bit test vectors. Proves the constants + algorithm
        // are standard FNV-1a-64, not a private variant — the empty input returns
        // the offset basis, the rest are the published reference values.
        assert_eq!(fnv1a_path(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_path(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_path(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn fnv1a_stops_at_first_nul_like_the_kernel() {
        // The kernel breaks the loop on the first NUL; bytes past it are ignored,
        // so a path and the same path with garbage past a NUL hash identically.
        assert_eq!(
            fnv1a_path(b"/usr/bin/cat"),
            fnv1a_path(b"/usr/bin/cat\0junk")
        );
        assert_eq!(fnv1a_path(b""), fnv1a_path(b"\0anything"));
    }

    #[test]
    fn fnv1a_caps_at_256_bytes() {
        // Bytes at/after index 256 must not affect the hash (verifier-bound mirror).
        let mut a = vec![b'x'; 256];
        let mut b = a.clone();
        b.push(b'y'); // 257th byte, must be ignored
        assert_eq!(fnv1a_path(&a), fnv1a_path(&b));
        // ...but the first 256 DO matter.
        a[255] = b'z';
        assert_ne!(fnv1a_path(&a), fnv1a_path(&vec![b'x'; 256]));
    }

    #[test]
    fn allowlist_key_hashes_the_path_bytes() {
        assert_eq!(allowlist_key("/usr/bin/cat"), fnv1a_path(b"/usr/bin/cat"));
        // Distinct paths -> distinct keys.
        assert_ne!(allowlist_key("/usr/bin/cat"), allowlist_key("/usr/bin/sh"));
    }

    #[test]
    fn fnv1a_source_parity_with_kernel_hasher() {
        // The kernel hasher (sensor-ebpf) and this userspace mirror MUST use
        // identical constants + structure. Pin that by asserting the kernel source
        // still declares the same offset basis, prime, 256-bound loop, and NUL
        // break. If a future edit changes the kernel FNV, this fails until the
        // mirror above is brought back into agreement (the keys would otherwise
        // silently stop matching and an armed enforce gate would block everything).
        let kernel = include_str!("../../sensor-ebpf/src/main.rs");
        assert!(
            kernel.contains("0xcbf2_9ce4_8422_2325"),
            "kernel FNV offset basis drifted from the userspace mirror"
        );
        assert!(
            kernel.contains("0x0000_0100_0000_01b3"),
            "kernel FNV prime drifted from the userspace mirror"
        );
        assert!(
            kernel.contains("while i < 256 && i < buf.len()"),
            "kernel FNV bound drifted from the userspace mirror"
        );
        assert!(
            kernel.contains("if b == 0 {"),
            "kernel FNV NUL-break drifted from the userspace mirror"
        );
    }

    #[test]
    fn target_allowlist_keys_hash_and_dedup() {
        let keys = target_allowlist_keys(&[
            "/usr/bin/bash".into(),
            "/usr/bin/cat".into(),
            "/usr/bin/bash".into(), // duplicate path -> one key
        ]);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&allowlist_key("/usr/bin/bash")));
        assert!(keys.contains(&allowlist_key("/usr/bin/cat")));
    }

    #[test]
    fn reconcile_is_the_diff_not_a_wipe() {
        let live: BTreeSet<u64> = [1, 2, 3].into_iter().collect();
        let target: BTreeSet<u64> = [2, 3, 4].into_iter().collect();
        let plan = reconcile_allowlist(&live, &target);
        assert_eq!(plan.to_insert, [4].into_iter().collect());
        assert_eq!(plan.to_remove, [1].into_iter().collect());
        assert!(!plan.is_noop());
    }

    #[test]
    fn reconcile_noop_when_converged() {
        let s: BTreeSet<u64> = [10, 20].into_iter().collect();
        assert!(reconcile_allowlist(&s, &s).is_noop());
    }

    #[test]
    fn reconcile_insert_only_and_remove_only() {
        let empty = BTreeSet::new();
        let two: BTreeSet<u64> = [1, 2].into_iter().collect();
        // empty live -> insert all, remove none
        let add = reconcile_allowlist(&empty, &two);
        assert_eq!(add.to_insert, two);
        assert!(add.to_remove.is_empty());
        // empty target -> remove all, insert none (explicit, not a blind wipe)
        let drop = reconcile_allowlist(&two, &empty);
        assert!(drop.to_insert.is_empty());
        assert_eq!(drop.to_remove, two);
    }

    #[test]
    fn parse_cgroup_v2_path_unified() {
        assert_eq!(
            parse_cgroup_v2_path("0::/system.slice/innerwarden-agent.service\n").as_deref(),
            Some("/system.slice/innerwarden-agent.service")
        );
        // root cgroup
        assert_eq!(parse_cgroup_v2_path("0::/").as_deref(), Some("/"));
        // a k8s pod cgroup
        assert_eq!(
            parse_cgroup_v2_path("0::/kubepods.slice/kubepods-besteffort.slice/pod123.slice\n")
                .as_deref(),
            Some("/kubepods.slice/kubepods-besteffort.slice/pod123.slice")
        );
    }

    #[test]
    fn parse_cgroup_v2_path_ignores_v1_and_empty() {
        // cgroup v1 only (legacy hierarchies) -> no unified line -> None
        assert_eq!(
            parse_cgroup_v2_path("12:pids:/user.slice\n11:memory:/user.slice\n"),
            None
        );
        // hybrid: v1 lines + the unified line -> picks the unified path
        assert_eq!(
            parse_cgroup_v2_path("11:memory:/foo\n0::/bar\n").as_deref(),
            Some("/bar")
        );
        assert_eq!(parse_cgroup_v2_path(""), None);
        // "0::" with no path is not a usable cgroup path
        assert_eq!(parse_cgroup_v2_path("0::\n"), None);
    }

    #[test]
    fn plan_arm_refuses_enforce_with_empty_allowlist() {
        // The headline guard: enforce over an empty allowlist would brick the
        // scoped cgroup. Refused, no plan.
        let live = BTreeSet::new();
        let r = plan_arm(BTreeSet::new(), &live, 9772, GateMode::Enforce);
        assert_eq!(r, Err(ArmRefusal::EnforceWithEmptyAllowlist));
    }

    #[test]
    fn plan_arm_allows_observe_with_empty_allowlist() {
        // Observe never denies — an empty allowlist just learns. Allowed.
        let live = BTreeSet::new();
        let plan = plan_arm(BTreeSet::new(), &live, 9772, GateMode::Observe)
            .expect("observe+empty is safe");
        assert_eq!(plan.mode, GateMode::Observe);
        assert_eq!(plan.scope_cgroup_id, 9772);
        assert!(plan.reconcile.is_noop());
    }

    #[test]
    fn plan_arm_refuses_without_a_scope_cgroup() {
        let live = BTreeSet::new();
        let target: BTreeSet<u64> = [allowlist_key("/usr/bin/bash")].into_iter().collect();
        assert_eq!(
            plan_arm(target, &live, 0, GateMode::Enforce),
            Err(ArmRefusal::NoScopeCgroup)
        );
    }

    #[test]
    fn plan_arm_refuses_inert_and_unknown_modes() {
        let live = BTreeSet::new();
        let t: BTreeSet<u64> = [1].into_iter().collect();
        assert_eq!(
            plan_arm(t.clone(), &live, 1, GateMode::Inert),
            Err(ArmRefusal::NotAnArmMode)
        );
        assert_eq!(
            plan_arm(t, &live, 1, GateMode::Unknown),
            Err(ArmRefusal::NotAnArmMode)
        );
    }

    #[test]
    fn plan_arm_enforce_nonempty_yields_correct_reconcile() {
        // live has {bash, stale}; target {bash, cat} -> insert cat, remove stale.
        let bash = allowlist_key("/usr/bin/bash");
        let cat = allowlist_key("/usr/bin/cat");
        let stale = allowlist_key("/tmp/old");
        let live: BTreeSet<u64> = [bash, stale].into_iter().collect();
        let target: BTreeSet<u64> = [bash, cat].into_iter().collect();
        let plan = plan_arm(target, &live, 555, GateMode::Enforce).expect("safe enforce");
        assert_eq!(plan.mode, GateMode::Enforce);
        assert_eq!(plan.scope_cgroup_id, 555);
        assert_eq!(plan.reconcile.to_insert, [cat].into_iter().collect());
        assert_eq!(plan.reconcile.to_remove, [stale].into_iter().collect());
    }
}
