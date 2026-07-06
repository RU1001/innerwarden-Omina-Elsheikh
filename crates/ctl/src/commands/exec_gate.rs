//! `innerwarden exec-gate` — operator CLI for the agent-scoped Execution Gate
//! (spec 083). ctl is aya-free, so the map writes go through `bpftool` (the same
//! tool ctl already uses to READ the gate in `doctor`). The SAFETY decision is
//! `innerwarden_core::execution_gate::plan_arm` (pure, unit-tested); this module
//! resolves the target cgroup, builds the plan, and translates it into bpftool
//! commands.
//!
//! Commands: `status`, `arm --observe`, `rehearse`, `enforce`, `disarm`. The safe
//! flow is observe first (never denies), watch the would-block events, allowlist
//! the binaries, `rehearse` until clean, then `enforce`. `enforce` flips to deny
//! ONLY after a clean rehearsal (observe-armed + scoped + zero would-block in the
//! window), so nobody flips enforce blind (the k7 brick lesson). Personal use is
//! free; the professional/fleet layer is the separate paid product.

use innerwarden_core::event::Event;
use innerwarden_core::execution_gate::{self as eg, GateMode};
use innerwarden_store::Store;
use std::collections::BTreeSet;
use std::path::Path;

/// Default rehearsal window (seconds) — how far back the would-block scan looks.
const DEFAULT_REHEARSE_WINDOW_SECS: u64 = 300;

/// Little-endian `0xNN` byte args for a bpftool map key/value of `n` bytes.
pub(crate) fn le_hex(v: u64, n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("0x{:02x}", (v >> (8 * i)) & 0xff))
        .collect()
}

fn map_update(pin: &str, key: Vec<String>, val: Vec<String>) -> Vec<String> {
    let mut c = vec![
        "map".into(),
        "update".into(),
        "pinned".into(),
        pin.into(),
        "key".into(),
    ];
    c.extend(key);
    c.push("value".into());
    c.extend(val);
    c.push("any".into());
    c
}

fn map_delete(pin: &str, key: Vec<String>) -> Vec<String> {
    let mut c = vec![
        "map".into(),
        "delete".into(),
        "pinned".into(),
        pin.into(),
        "key".into(),
    ];
    c.extend(key);
    c
}

/// PURE translation of a vetted [`eg::ArmPlan`] into the ordered list of bpftool
/// commands that apply it. Order is host-safe: allowlist inserts, then removes,
/// then the scope cgroup id, then `LSM_POLICY` key 4 (scope) BEFORE key 3 (mode),
/// so the gate is scoped the instant it goes active.
pub(crate) fn arm_commands(plan: &eg::ArmPlan) -> Vec<Vec<String>> {
    let mut cmds = Vec::new();
    for k in &plan.reconcile.to_insert {
        cmds.push(map_update(
            eg::EXEC_ALLOWLIST_PIN,
            le_hex(*k, 8),
            vec!["0x01".into()],
        ));
    }
    for k in &plan.reconcile.to_remove {
        cmds.push(map_delete(eg::EXEC_ALLOWLIST_PIN, le_hex(*k, 8)));
    }
    cmds.push(map_update(
        eg::EXEC_GATE_SCOPE_PIN,
        le_hex(plan.scope_cgroup_id, 8),
        vec!["0x01".into()],
    ));
    cmds.push(map_update(
        eg::LSM_POLICY_PIN,
        le_hex(eg::GATE_SCOPE_KEY as u64, 4),
        le_hex(1, 4),
    ));
    let mode_val: u64 = match plan.mode {
        GateMode::Enforce => 1,
        GateMode::Observe => 2,
        _ => 0,
    };
    cmds.push(map_update(
        eg::LSM_POLICY_PIN,
        le_hex(eg::GATE_MODE_KEY as u64, 4),
        le_hex(mode_val, 4),
    ));
    cmds
}

/// PURE: disarm commands — `LSM_POLICY` key 3 = 0 (stop denying) THEN key 4 = 0.
/// Leaves the allowlist + scope entries (harmless while inert).
pub(crate) fn disarm_commands() -> Vec<Vec<String>> {
    vec![
        map_update(
            eg::LSM_POLICY_PIN,
            le_hex(eg::GATE_MODE_KEY as u64, 4),
            le_hex(0, 4),
        ),
        map_update(
            eg::LSM_POLICY_PIN,
            le_hex(eg::GATE_SCOPE_KEY as u64, 4),
            le_hex(0, 4),
        ),
    ]
}

/// PURE: parse the u64 keys from a `bpftool map dump` of `EXEC_ALLOWLIST` (the
/// keys are 8 little-endian bytes on each `key:` line). Used to read the live
/// allowlist for the reconcile diff.
pub(crate) fn parse_bpftool_u64_keys(dump: &str) -> BTreeSet<u64> {
    let mut out = BTreeSet::new();
    for line in dump.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("key:") else {
            continue;
        };
        let bytes: Vec<u8> = rest
            .split_whitespace()
            .take(8)
            .filter_map(|b| u8::from_str_radix(b.trim_start_matches("0x"), 16).ok())
            .collect();
        if bytes.len() == 8 {
            let mut v = 0u64;
            for (i, b) in bytes.iter().enumerate() {
                v |= (*b as u64) << (8 * i);
            }
            out.insert(v);
        }
    }
    out
}

// ── I/O (real kernel + bpftool; exercised on a box, error-path only in CI) ────

fn resolve_cgroup_id(pid: u32) -> Option<u64> {
    // cgroup ids come from /proc + /sys (Linux). The exec-gate is already
    // runtime-gated to Linux, so on Windows (spec 085 Phase 0) return None.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let raw = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
        let rel = eg::parse_cgroup_v2_path(&raw)?;
        std::fs::metadata(format!("/sys/fs/cgroup{rel}"))
            .ok()
            .map(|m| m.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

fn bpftool(args: &[String]) -> anyhow::Result<()> {
    let out = std::process::Command::new("bpftool").args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "bpftool {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

fn live_allowlist_keys() -> BTreeSet<u64> {
    match std::process::Command::new("bpftool")
        .args(["map", "dump", "pinned", eg::EXEC_ALLOWLIST_PIN])
        .output()
    {
        Ok(o) if o.status.success() => parse_bpftool_u64_keys(&String::from_utf8_lossy(&o.stdout)),
        _ => BTreeSet::new(),
    }
}

/// PURE decision + translation: vet an arm request and return the ordered bpftool
/// commands to apply it, or a human-readable refusal. No I/O — `cgid` and `live`
/// are resolved by the caller, so every branch is unit-testable. Observe-only
/// today (enforce is refused until the rehearsal lands).
pub(crate) fn arm_plan_for_cli(
    cgid: u64,
    observe: bool,
    paths: &[String],
    live: &BTreeSet<u64>,
) -> Result<Vec<Vec<String>>, String> {
    if !observe {
        return Err(
            "`arm` only sets observe. To enforce, use `exec-gate enforce --pid <PID>` \
             — it flips to enforce only after a clean rehearsal (observe-armed, scoped, zero \
             would-block in the window)."
                .to_string(),
        );
    }
    if cgid == 0 {
        return Err(
            "could not resolve a cgroup-v2 id for the target pid (process gone, or a \
             cgroup-v1 host). The Execution Gate scopes on the unified cgroup."
                .to_string(),
        );
    }
    let target = eg::target_allowlist_keys(paths);
    let plan = eg::plan_arm(target, live, cgid, GateMode::Observe)
        .map_err(|r| format!("refused: {r:?}"))?;
    Ok(arm_commands(&plan))
}

/// `innerwarden exec-gate arm --pid <PID> --observe [--path P ...]`.
pub(crate) fn cmd_arm(pid: u32, observe: bool, paths: &[String]) -> anyhow::Result<()> {
    ensure_gate_available()?;
    let cgid = resolve_cgroup_id(pid).unwrap_or(0);
    let cmds = arm_plan_for_cli(cgid, observe, paths, &live_allowlist_keys())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    for cmd in cmds {
        bpftool(&cmd)?;
    }
    println!(
        "Execution Gate armed: OBSERVE, scoped to pid {pid} (cgroup id {cgid}), \
         {} binaries allowlisted. Observe never denies — it logs what it WOULD block. \
         Disarm with `innerwarden exec-gate disarm`.",
        paths.len()
    );
    Ok(())
}

fn bpftool_lookup_u32(pin: &str, key: u32) -> Option<u32> {
    let out = std::process::Command::new("bpftool")
        .args([
            "map",
            "lookup",
            "pinned",
            pin,
            "key",
            &key.to_string(),
            "0",
            "0",
            "0",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    eg::parse_bpftool_value_u32(&String::from_utf8_lossy(&out.stdout))
}

fn bpftool_dump_count(pin: &str) -> usize {
    match std::process::Command::new("bpftool")
        .args(["map", "dump", "pinned", pin])
        .output()
    {
        Ok(o) if o.status.success() => eg::count_bpftool_dump(&String::from_utf8_lossy(&o.stdout)),
        _ => 0,
    }
}

/// Why the Execution Gate CLI cannot operate on this host.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GateUnavailable {
    /// Not a Linux host — the gate is an eBPF-LSM feature (macOS/other) (F4).
    NotLinux,
    /// Linux, but no working `bpftool` for this kernel (F2).
    NoBpftool,
}

impl GateUnavailable {
    /// Actionable one-liner. `krel` is the running kernel release, used only for
    /// the `linux-tools-<rel>` package hint in the `NoBpftool` case.
    pub(crate) fn message(&self, krel: &str) -> String {
        match self {
            GateUnavailable::NotLinux => "The Execution Gate is a Linux eBPF-LSM feature \
                 — it is not available on this platform."
                .to_string(),
            GateUnavailable::NoBpftool => format!(
                "bpftool is unavailable for this kernel — install linux-tools-{krel} \
                 (or your distro's kernel-tools package) so the Execution Gate CLI can \
                 read and write the pinned BPF maps."
            ),
        }
    }
}

/// PURE: decide whether the gate CLI can run from the two host probes. Both
/// branches are unit-tested; the caller supplies `is_linux = cfg!(target_os =
/// "linux")` and `bpftool_ok = bpftool_available()`.
pub(crate) fn exec_gate_unavailable(is_linux: bool, bpftool_ok: bool) -> Option<GateUnavailable> {
    if !is_linux {
        Some(GateUnavailable::NotLinux)
    } else if !bpftool_ok {
        Some(GateUnavailable::NoBpftool)
    } else {
        None
    }
}

/// I/O: is a working `bpftool` present for THIS kernel? On Ubuntu, `bpftool` is a
/// wrapper that execs the versioned binary from `linux-tools-$(uname -r)`; when
/// that package is absent it prints a "not found for kernel" warning and exits
/// non-zero (F2 — every exec-gate map op then failed with a bare exit 1).
/// `bpftool version` succeeding is a reliable readiness probe.
fn bpftool_available() -> bool {
    matches!(
        std::process::Command::new("bpftool").arg("version").output(),
        Ok(o) if o.status.success()
    )
}

/// I/O: running kernel release (`uname -r`), for the linux-tools package hint.
fn kernel_release() -> String {
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "$(uname -r)".to_string())
}

/// I/O gate for the mutating subcommands (arm/disarm/enforce): hard-fail with an
/// actionable message when the gate CLI cannot operate, instead of a bare
/// bpftool exit 1 that silently leaves the gate unchanged (F2).
fn ensure_gate_available() -> anyhow::Result<()> {
    if let Some(u) = exec_gate_unavailable(cfg!(target_os = "linux"), bpftool_available()) {
        anyhow::bail!("{}", u.message(&kernel_release()));
    }
    Ok(())
}

/// `innerwarden exec-gate status` — read-only summary of the live gate.
pub(crate) fn cmd_status() -> anyhow::Result<()> {
    // Never claim "inert" when we simply could not read the maps. On macOS the
    // gate does not exist; on a Linux box without linux-tools we cannot read the
    // pinned maps at all — reporting "inert" there (F2b) told operators the gate
    // was OFF while it was actually enforcing. Distinguish unreadable from inert.
    match exec_gate_unavailable(cfg!(target_os = "linux"), bpftool_available()) {
        Some(GateUnavailable::NotLinux) => {
            println!("Execution Gate: not available on this platform (Linux eBPF-LSM only).");
            return Ok(());
        }
        Some(GateUnavailable::NoBpftool) => {
            println!(
                "Execution Gate: status UNKNOWN — cannot read the pinned BPF maps. This does \
                 NOT mean the gate is off; it may be armed. {}",
                GateUnavailable::NoBpftool.message(&kernel_release())
            );
            return Ok(());
        }
        None => {}
    }
    let mode = GateMode::from_policy_key(bpftool_lookup_u32(eg::LSM_POLICY_PIN, eg::GATE_MODE_KEY));
    let scoped = bpftool_lookup_u32(eg::LSM_POLICY_PIN, eg::GATE_SCOPE_KEY) == Some(1);
    let allow = bpftool_dump_count(eg::EXEC_ALLOWLIST_PIN);
    let scope = bpftool_dump_count(eg::EXEC_GATE_SCOPE_PIN);
    println!(
        "Execution Gate: mode={}, scope={}, allowlist={} binaries, scope_cgroups={}",
        mode.label(),
        if scoped { "agent-scoped" } else { "host-wide" },
        allow,
        scope
    );
    if mode == GateMode::Inert {
        println!("The gate is inert — it denies nothing. `arm --observe` to start.");
    } else if let Some(w) = lsm_inactive_status_warning(mode, eg::read_bpf_lsm_active()) {
        println!("{w}");
    }
    Ok(())
}

/// PURE: the `status` warning shown when the gate is in an ACTIVE mode but `bpf`
/// is definitively not in the kernel's active LSM stack — the hook cannot run, so
/// the gate denies NOTHING despite reporting armed (stock Ubuntu/Azure default,
/// the Azure-6.17 finding). `None` (bpf active / mode inert / LSM list unreadable)
/// = no warning, so an unreadable list never cries wolf.
fn lsm_inactive_status_warning(mode: GateMode, bpf_lsm_active: Option<bool>) -> Option<String> {
    if mode.is_active() && bpf_lsm_active == Some(false) {
        Some(format!(
            "  WARNING: `bpf` is NOT in the active kernel LSM stack (/sys/kernel/security/lsm), \
             so this gate CANNOT enforce — it currently denies nothing despite mode={}. \
             Add `lsm=...,bpf` to the kernel cmdline (GRUB_CMDLINE_LINUX) and reboot, then re-check.",
            mode.label()
        ))
    } else {
        None
    }
}

/// PURE: the reason `enforce` refuses when `bpf` is definitively absent from the
/// active LSM stack — enforce would be a silent no-op and the rehearsal is hollow
/// (no would-block event can fire while the hook is inert). `None` = safe to
/// proceed (bpf active, or the list is unreadable — never block on unreadable).
fn enforce_lsm_block_reason(bpf_lsm_active: Option<bool>) -> Option<String> {
    if bpf_lsm_active == Some(false) {
        Some(
            "refusing to enforce: `bpf` is NOT in the active kernel LSM stack \
             (/sys/kernel/security/lsm), so the Execution Gate hook cannot run and enforce would \
             deny NOTHING (a false sense of security). The rehearsal cannot be trusted either — no \
             would-block event can fire while the hook is inert. Add `lsm=...,bpf` to the kernel \
             cmdline (GRUB_CMDLINE_LINUX), reboot, confirm `bpf` appears in /sys/kernel/security/lsm, \
             then re-arm --observe, re-rehearse, and enforce."
                .to_string(),
        )
    } else {
        None
    }
}

/// `innerwarden exec-gate disarm`.
pub(crate) fn cmd_disarm() -> anyhow::Result<()> {
    ensure_gate_available()?;
    for cmd in disarm_commands() {
        bpftool(&cmd)?;
    }
    println!("Execution Gate disarmed (inert). The host and the agent are ungated.");
    Ok(())
}

// ── Rehearsal-gated enforce (spec 083, observe -> enforce safely) ─────────────

/// PURE: whether flipping the gate to ENFORCE is safe, given the live state and
/// the rehearsal result. Enforce only when the gate is ALREADY observe-armed and
/// scoped to this cgroup AND zero would-block events fired in the window (every
/// binary the agent ran is allowlisted). Anything else is refused — never a blind
/// flip.
pub(crate) fn enforce_decision(
    live_mode: GateMode,
    scoped: bool,
    cgid_in_scope: bool,
    would_block: usize,
) -> Result<(), String> {
    if live_mode != GateMode::Observe {
        return Err("the gate is not in observe mode for this agent. Run \
             `arm --pid <PID> --observe` first, let it run, then enforce."
            .to_string());
    }
    if !scoped || !cgid_in_scope {
        return Err(
            "the gate is not agent-scoped to this pid's cgroup. Re-arm observe scoped \
             to the right pid before enforcing."
                .to_string(),
        );
    }
    if would_block > 0 {
        return Err(format!(
            "rehearsal not clean: {would_block} would-block event(s) in the window — those \
             binaries would be DENIED under enforce. Run `exec-gate rehearse --pid <PID>` to \
             list them, allowlist them, then enforce."
        ));
    }
    Ok(())
}

/// PURE: count would-block events for one cgroup + the distinct binary paths.
pub(crate) fn filter_would_block_for_cgroup(
    events: &[(i64, Event)],
    cgid: u64,
) -> (usize, Vec<String>) {
    let mut count = 0usize;
    let mut paths = BTreeSet::new();
    for (_, ev) in events {
        if ev.details.get("cgroup_id").and_then(|v| v.as_u64()) == Some(cgid) {
            count += 1;
            if let Some(f) = ev.details.get("filename").and_then(|v| v.as_str()) {
                paths.insert(f.to_string());
            }
        }
    }
    (count, paths.into_iter().collect())
}

/// I/O: query the store for would-block events for `cgid` over the last `window`
/// seconds, returning (count, distinct paths).
fn scan_would_block(
    dir: &Path,
    cgid: u64,
    window_secs: u64,
) -> anyhow::Result<(usize, Vec<String>)> {
    let store = Store::open(dir)
        .map_err(|e| anyhow::anyhow!("open event store at {}: {e:#}", dir.display()))?;
    let since = (chrono::Utc::now() - chrono::Duration::seconds(window_secs as i64)).to_rfc3339();
    let events = store.events_by_kind_since("lsm.exec_gate_would_block", &since, 50_000)?;
    Ok(filter_would_block_for_cgroup(&events, cgid))
}

/// I/O: is `cgid` present in the EXEC_GATE_SCOPE map?
fn bpftool_scope_has(cgid: u64) -> bool {
    let mut args = vec![
        "map".to_string(),
        "lookup".to_string(),
        "pinned".to_string(),
        eg::EXEC_GATE_SCOPE_PIN.to_string(),
        "key".to_string(),
    ];
    args.extend(le_hex(cgid, 8));
    matches!(
        std::process::Command::new("bpftool").args(&args).output(),
        Ok(o) if o.status.success()
    )
}

/// `innerwarden exec-gate rehearse --pid <PID> [--window N]` — read-only: show the
/// would-block events for the pid's cgroup so the operator knows whether enforce
/// is safe and which binaries still need allowlisting.
pub(crate) fn cmd_rehearse(pid: u32, window: Option<u64>, dir: &Path) -> anyhow::Result<()> {
    ensure_gate_available()?;
    let window = window.unwrap_or(DEFAULT_REHEARSE_WINDOW_SECS);
    let cgid = resolve_cgroup_id(pid).unwrap_or(0);
    if cgid == 0 {
        anyhow::bail!("could not resolve a cgroup-v2 id for pid {pid}.");
    }
    let (count, paths) = scan_would_block(dir, cgid, window)?;
    if count == 0 {
        println!(
            "Rehearsal CLEAN for pid {pid} (cgroup {cgid}): 0 would-block in the last {window}s. \
             Safe to `exec-gate enforce --pid {pid}`."
        );
    } else {
        println!(
            "Rehearsal for pid {pid} (cgroup {cgid}): {count} would-block in the last {window}s, \
             from {} binaries:",
            paths.len()
        );
        for p in &paths {
            println!("  {p}");
        }
        println!(
            "Allowlist these (`exec-gate arm --pid {pid} --observe --path <P> ...`) and \
             re-rehearse, or they will be DENIED under enforce."
        );
    }
    Ok(())
}

/// `innerwarden exec-gate enforce --pid <PID> [--window N]` — flip the gate to
/// enforce, but ONLY after a clean rehearsal (observe-armed + scoped + zero
/// would-block in the window). Otherwise refused — the gate is never flipped blind.
pub(crate) fn cmd_enforce(pid: u32, window: Option<u64>, dir: &Path) -> anyhow::Result<()> {
    ensure_gate_available()?;
    let window = window.unwrap_or(DEFAULT_REHEARSE_WINDOW_SECS);
    let cgid = resolve_cgroup_id(pid).unwrap_or(0);
    if cgid == 0 {
        anyhow::bail!("could not resolve a cgroup-v2 id for pid {pid}.");
    }
    // Preflight: the BPF-LSM must actually be in the kernel's active LSM stack, or
    // the gate hook can never run — enforce would be a silent no-op AND the
    // rehearsal that "passed" was hollow (no would-block event can fire when the
    // hook is inert). Refuse rather than hand the operator a false sense of
    // security (the Azure-6.17 finding: stock CONFIG_LSM omits `bpf`).
    if let Some(reason) = enforce_lsm_block_reason(eg::read_bpf_lsm_active()) {
        anyhow::bail!("{reason}");
    }
    let live_mode =
        GateMode::from_policy_key(bpftool_lookup_u32(eg::LSM_POLICY_PIN, eg::GATE_MODE_KEY));
    let scoped = bpftool_lookup_u32(eg::LSM_POLICY_PIN, eg::GATE_SCOPE_KEY) == Some(1);
    let cgid_in_scope = bpftool_scope_has(cgid);
    let (would_block, _paths) = scan_would_block(dir, cgid, window)?;
    enforce_decision(live_mode, scoped, cgid_in_scope, would_block)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // Flip key 3 to enforce; scope + allowlist are already in place from observe.
    bpftool(&map_update(
        eg::LSM_POLICY_PIN,
        le_hex(eg::GATE_MODE_KEY as u64, 4),
        le_hex(1, 4),
    ))?;
    println!(
        "Execution Gate ENFORCING, scoped to pid {pid} (cgroup {cgid}). Unknown binaries in its \
         cgroup are now denied (-EPERM); the host and other processes are untouched. \
         `exec-gate disarm` to stop."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── availability gate (F2/F2b/F4) ────────────────────────────────────────
    #[test]
    fn exec_gate_unavailable_flags_non_linux() {
        assert_eq!(
            exec_gate_unavailable(false, true),
            Some(GateUnavailable::NotLinux),
            "macOS/other: gate does not exist regardless of bpftool"
        );
        assert_eq!(
            exec_gate_unavailable(false, false),
            Some(GateUnavailable::NotLinux)
        );
    }

    #[test]
    fn exec_gate_unavailable_flags_missing_bpftool_on_linux() {
        assert_eq!(
            exec_gate_unavailable(true, false),
            Some(GateUnavailable::NoBpftool),
            "Linux without linux-tools: cannot drive the maps (F2)"
        );
    }

    #[test]
    fn exec_gate_available_when_linux_and_bpftool_present() {
        assert_eq!(exec_gate_unavailable(true, true), None);
    }

    /// Exercise the real I/O probes (they run on the Linux CI host too):
    /// `uname -r` yields a non-empty release; `bpftool_available` returns a
    /// bool; `ensure_gate_available` returns Ok or a NoBpftool error depending
    /// on whether the CI image ships bpftool — both are valid, non-panicking
    /// paths through the code.
    #[test]
    fn gate_io_probes_execute() {
        let krel = kernel_release();
        assert!(!krel.is_empty());
        let _present: bool = bpftool_available();
        // Ok when the host can run the gate (Linux + bpftool); otherwise a
        // non-empty actionable error (NoBpftool on Linux CI without linux-tools,
        // or NotLinux when this test runs on a dev Mac). Both are valid paths.
        match ensure_gate_available() {
            Ok(()) => {}
            Err(e) => assert!(!e.to_string().is_empty()),
        }
    }

    #[test]
    fn gate_unavailable_messages_are_actionable() {
        // NoBpftool message names the exact package to install for this kernel.
        let m = GateUnavailable::NoBpftool.message("6.17.0-1018-azure");
        assert!(m.contains("linux-tools-6.17.0-1018-azure"));
        assert!(m.to_lowercase().contains("bpftool"));
        // NotLinux message is platform-honest and does not mention bpftool.
        let m2 = GateUnavailable::NotLinux.message("irrelevant");
        assert!(m2.contains("not available on this platform"));
        assert!(!m2.contains("linux-tools"));
    }

    #[test]
    fn le_hex_is_little_endian() {
        assert_eq!(le_hex(0x04, 4), vec!["0x04", "0x00", "0x00", "0x00"]);
        // cgroup id 9772 = 0x262c -> LE 8 bytes
        assert_eq!(
            le_hex(9772, 8),
            vec!["0x2c", "0x26", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00"]
        );
    }

    #[test]
    fn arm_commands_order_and_content() {
        let plan = eg::ArmPlan {
            reconcile: eg::ReconcilePlan {
                to_insert: [0xaa].into_iter().collect(),
                to_remove: [0xbb].into_iter().collect(),
            },
            scope_cgroup_id: 9772,
            mode: GateMode::Observe,
        };
        let cmds = arm_commands(&plan);
        // insert, remove, scope, key4=1, key3=2 (observe) — in that order.
        assert_eq!(cmds.len(), 5);
        assert_eq!(cmds[0][1], "update"); // allowlist insert
        assert!(cmds[0].contains(&eg::EXEC_ALLOWLIST_PIN.to_string()));
        assert_eq!(cmds[1][1], "delete"); // allowlist remove
        assert!(cmds[2].contains(&eg::EXEC_GATE_SCOPE_PIN.to_string()));
        // key4 (scope) before key3 (mode)
        assert_eq!(
            cmds[3],
            map_update(eg::LSM_POLICY_PIN, le_hex(4, 4), le_hex(1, 4))
        );
        assert_eq!(
            cmds[4],
            map_update(eg::LSM_POLICY_PIN, le_hex(3, 4), le_hex(2, 4))
        );
    }

    #[test]
    fn disarm_sets_mode_then_scope_to_zero() {
        let cmds = disarm_commands();
        assert_eq!(cmds.len(), 2);
        assert_eq!(
            cmds[0],
            map_update(eg::LSM_POLICY_PIN, le_hex(3, 4), le_hex(0, 4))
        );
        assert_eq!(
            cmds[1],
            map_update(eg::LSM_POLICY_PIN, le_hex(4, 4), le_hex(0, 4))
        );
    }

    #[test]
    fn parse_bpftool_u64_keys_reads_le_8_bytes() {
        let dump = "key: 2c 26 00 00 00 00 00 00  value: 01\n\
                    key: aa bb 00 00 00 00 00 00  value: 01\n\
                    Found 2 elements";
        let keys = parse_bpftool_u64_keys(dump);
        assert!(keys.contains(&9772));
        assert!(keys.contains(&0xbbaa));
        assert_eq!(keys.len(), 2);
        // empty dump
        assert!(parse_bpftool_u64_keys("Found 0 elements").is_empty());
    }

    #[test]
    fn arm_plan_for_cli_refuses_enforce() {
        let live = BTreeSet::new();
        let err = arm_plan_for_cli(123, false, &[], &live).unwrap_err();
        assert!(err.contains("rehearsal"));
    }

    #[test]
    fn arm_plan_for_cli_refuses_zero_cgid() {
        let live = BTreeSet::new();
        let err = arm_plan_for_cli(0, true, &["/usr/bin/true".into()], &live).unwrap_err();
        assert!(err.contains("cgroup"));
    }

    #[test]
    fn arm_plan_for_cli_observe_empty_is_scope_and_policy_only() {
        // observe + no paths: no allowlist insert -> scope + key4 + key3 = 3 cmds.
        let live = BTreeSet::new();
        let cmds = arm_plan_for_cli(9772, true, &[], &live).expect("observe empty ok");
        assert_eq!(cmds.len(), 3);
        assert!(cmds[0].contains(&eg::EXEC_GATE_SCOPE_PIN.to_string()));
        // last is key3 = 2 (observe)
        assert_eq!(
            cmds[2],
            map_update(eg::LSM_POLICY_PIN, le_hex(3, 4), le_hex(2, 4))
        );
    }

    #[test]
    fn arm_plan_for_cli_observe_with_a_path_inserts_allowlist() {
        let live = BTreeSet::new();
        let cmds = arm_plan_for_cli(9772, true, &["/usr/bin/true".into()], &live).unwrap();
        // allowlist insert + scope + key4 + key3 = 4 cmds.
        assert_eq!(cmds.len(), 4);
        assert_eq!(cmds[0][1], "update");
        assert!(cmds[0].contains(&eg::EXEC_ALLOWLIST_PIN.to_string()));
    }

    // ── I/O fns: CI-safe failure / read paths. bpftool + the target /proc entry
    //    are absent in CI; these assertions also hold on a box (bogus pid, bad
    //    args, read-only) so they never mutate a real gate. ──────────────────────

    #[test]
    fn resolve_cgroup_id_none_for_bogus_pid() {
        assert!(resolve_cgroup_id(u32::MAX).is_none());
    }

    #[test]
    fn lsm_inactive_status_warning_only_when_active_and_bpf_off() {
        // armed + bpf inactive -> warn (the Azure-6.17 finding).
        let w = lsm_inactive_status_warning(GateMode::Enforce, Some(false));
        assert!(w.as_deref().unwrap().contains("CANNOT enforce"));
        assert!(w.as_deref().unwrap().contains("lsm=...,bpf"));
        assert!(lsm_inactive_status_warning(GateMode::Observe, Some(false)).is_some());
        // bpf active / unreadable / inert mode -> no warning (never cry wolf).
        assert!(lsm_inactive_status_warning(GateMode::Enforce, Some(true)).is_none());
        assert!(lsm_inactive_status_warning(GateMode::Enforce, None).is_none());
        assert!(lsm_inactive_status_warning(GateMode::Inert, Some(false)).is_none());
    }

    #[test]
    fn enforce_lsm_block_reason_only_when_bpf_off() {
        let r = enforce_lsm_block_reason(Some(false));
        assert!(r.as_deref().unwrap().contains("refusing to enforce"));
        assert!(r.as_deref().unwrap().contains("lsm=...,bpf"));
        // active / unreadable -> proceed (None). Unreadable must never block a real arm.
        assert!(enforce_lsm_block_reason(Some(true)).is_none());
        assert!(enforce_lsm_block_reason(None).is_none());
    }

    #[test]
    fn bpftool_errors_on_failure() {
        // CI: no bpftool -> spawn error. Box: unknown subcommand -> non-zero exit.
        assert!(bpftool(&["definitely-not-a-bpftool-subcommand".to_string()]).is_err());
    }

    #[test]
    fn live_allowlist_keys_is_callable() {
        // Read-only; empty in CI, possibly non-empty on a box. Just exercise it.
        let _ = live_allowlist_keys();
    }

    #[test]
    fn cmd_status_is_read_only_and_ok() {
        // status only READS + prints (inert when nothing is readable) — safe in CI
        // and on a box.
        assert!(cmd_status().is_ok());
    }

    #[test]
    fn cmd_arm_errors_on_unresolvable_pid() {
        // bogus pid -> cgid 0 -> refused BEFORE any write.
        assert!(cmd_arm(u32::MAX, true, &[]).is_err());
    }

    #[test]
    fn cmd_arm_errors_on_enforce() {
        // enforce is refused before any map write, regardless of the pid.
        assert!(cmd_arm(123, false, &[]).is_err());
    }

    #[test]
    fn cmd_disarm_errors_without_bpftool() {
        // Disarm WRITES, so only assert it where bpftool is ABSENT (CI): the first
        // map update fails -> Err, never mutating a real gate. Skipped on a box.
        if std::process::Command::new("bpftool")
            .arg("version")
            .output()
            .is_err()
        {
            assert!(cmd_disarm().is_err());
        }
    }

    // ── PR4b: rehearsal-gated enforce ─────────────────────────────────────────

    fn wb_event(cgid: u64, file: &str) -> (i64, Event) {
        (
            0,
            Event {
                ts: chrono::Utc::now(),
                host: "h".into(),
                source: "ebpf".into(),
                kind: "lsm.exec_gate_would_block".into(),
                severity: innerwarden_core::event::Severity::Info,
                summary: String::new(),
                details: serde_json::json!({"cgroup_id": cgid, "filename": file}),
                tags: vec![],
                entities: vec![],
            },
        )
    }

    #[test]
    fn enforce_decision_requires_observe_mode() {
        assert!(enforce_decision(GateMode::Inert, true, true, 0).is_err());
        assert!(enforce_decision(GateMode::Enforce, true, true, 0).is_err());
    }

    #[test]
    fn enforce_decision_requires_scope() {
        assert!(enforce_decision(GateMode::Observe, false, true, 0).is_err());
        assert!(enforce_decision(GateMode::Observe, true, false, 0).is_err());
    }

    #[test]
    fn enforce_decision_refuses_dirty_rehearsal() {
        let e = enforce_decision(GateMode::Observe, true, true, 3).unwrap_err();
        assert!(e.contains("rehearsal not clean"));
        assert!(e.contains('3'));
    }

    #[test]
    fn enforce_decision_allows_clean_observe_scoped() {
        assert!(enforce_decision(GateMode::Observe, true, true, 0).is_ok());
    }

    #[test]
    fn filter_would_block_counts_and_dedups_paths() {
        let evs = vec![
            wb_event(9772, "/tmp/a"),
            wb_event(9772, "/tmp/a"),
            wb_event(9772, "/tmp/b"),
            wb_event(1, "/tmp/c"), // other cgroup — excluded
        ];
        let (count, paths) = filter_would_block_for_cgroup(&evs, 9772);
        assert_eq!(count, 3);
        assert_eq!(paths, vec!["/tmp/a".to_string(), "/tmp/b".to_string()]);
        // no events for an unknown cgroup
        assert_eq!(filter_would_block_for_cgroup(&evs, 42).0, 0);
    }

    #[test]
    fn scan_would_block_reads_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.insert_event(&wb_event(9772, "/tmp/x").1).unwrap();
        store.insert_event(&wb_event(9772, "/tmp/y").1).unwrap();
        store.insert_event(&wb_event(555, "/tmp/z").1).unwrap(); // other cgroup
        let (count, paths) = scan_would_block(dir.path(), 9772, 3600).unwrap();
        assert_eq!(count, 2);
        assert_eq!(paths, vec!["/tmp/x".to_string(), "/tmp/y".to_string()]);
    }

    #[test]
    fn bpftool_scope_has_false_for_absent() {
        // No bpftool / no pin / key absent -> false (never a spurious true).
        assert!(!bpftool_scope_has(0xdead_beef));
    }

    #[test]
    fn cmd_rehearse_and_enforce_error_on_unresolvable_pid() {
        // bogus pid -> cgid 0 -> bail before any store/bpftool work.
        let dir = std::path::Path::new("/nonexistent-data-dir");
        assert!(cmd_rehearse(u32::MAX, None, dir).is_err());
        assert!(cmd_enforce(u32::MAX, None, dir).is_err());
    }
}
