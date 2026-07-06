//! Spec 069 follow-up #2 — promote orphan high-signal kernel syscall events
//! to incidents, with **layered** false-positive containment.
//!
//! ## Why
//!
//! Post-#919 the eBPF ring reader emits `process.ptrace_attach` (Critical),
//! `memory.mprotect_exec` RWX (Critical), `filesystem.mount` in-container
//! (Critical) and `process.memfd_create` (High). Before this module **no
//! sensor detector matched those kinds, no correlation rule referenced them,
//! and `is_passthrough_source` is a hardcoded `false`** — so they landed in
//! the DB + knowledge graph but never became incidents, never reached AI
//! triage, never triggered a response. An attacker using direct
//! ptrace/mprotect/memfd/mount was *seen but not acted on*.
//!
//! ## Philosophy: detect wide, contain FP across layers (never at detect time)
//!
//! Suppressing at detection loses coverage. Instead we promote aggressively
//! and let InnerWarden's existing layers strip false positives **before the
//! operator sees an alert**:
//!
//! 1. **Default allowlist** (this module) — `comm` sets of common-good actors
//!    that are stable *across* servers (debuggers ptrace; JIT runtimes mark
//!    RWX; init/desktop/container managers use memfd). Curated + documented.
//! 2. **Per-server allowlist** — `DynamicAllowlist::is_process_allowed`
//!    (`allowlist.toml`), so operators tune each host without a recompile.
//! 3. **Incident suppression** — `DetectorSet::is_incident_suppressed`
//!    (per-kind `kernel_*` name) at the call site in `process_event`.
//! 4. **Agent layers (downstream, no code here)** — baseline learned-normal,
//!    cloud safelist, and the AI `decide()` triage decide block vs ignore.
//!
//! Only an event that survives **all** layers reaches the operator.

use innerwarden_core::event::{Event, Severity};
use innerwarden_core::incident::Incident;

use crate::collectors::ebpf_syscall::is_killing_signal;
use crate::detectors::allowlists::DynamicAllowlist;

/// Debuggers legitimately `ptrace` other processes.
const PTRACE_DEBUGGERS: &[&str] = &[
    "gdb",
    "gdbserver",
    "strace",
    "ltrace",
    "lldb",
    "lldb-server",
    "valgrind",
    "rr",
    "perf",
    "dlv",
    "drgn",
    "crash",
    "bpftrace",
    "memcheck",
    "callgrind",
];

/// JIT / managed runtimes legitimately mark memory RWX.
const JIT_RUNTIMES: &[&str] = &[
    "node",
    "java",
    "python",
    "python3",
    "dotnet",
    "mono",
    "ruby",
    "php",
    "beam.smp",
    "erlang",
    "julia",
    "luajit",
    "v8",
    "chrome",
    "chromium",
    "firefox",
    "wine",
    "wineserver",
    "qemu",
    "qemu-system",
    "clr",
    "node.js",
    "deno",
    "bun",
    "Web Content",
    "WebKitWebProc",
];

/// Processes that legitimately use `memfd_create`. This `comm` set is the FIRST
/// FP layer; it is intentionally complemented by the NON-forgeable exe-path
/// trust check ([`memfd_exe_is_trusted`]) so that a trusted on-disk binary whose
/// thread comm is generic (e.g. a Rust runtime's `tokio-rt-worker`) is also
/// cleared without widening this spoofable list to cover it.
const MEMFD_LEGIT: &[&str] = &[
    "systemd",
    "systemd-udevd",
    "(sd-pam)",
    // systemd's per-unit executor helper (PID 1 lineage); creates a memfd as
    // part of normal unit startup. comm renders as `(sd-executor)`; `base`
    // strips the parens, so the bare name is listed.
    "sd-executor",
    "dbus-daemon",
    "dbus-broker",
    "snapd",
    // fwupd's CLI/daemon stages firmware blobs through memfd. Legit Ubuntu/RHEL
    // firmware-update tooling, not a fileless-payload actor.
    "fwupdmgr",
    "fwupd",
    "chrome",
    "chromium",
    "firefox",
    "gnome-shell",
    "pulseaudio",
    "pipewire",
    "wireplumber",
    "docker",
    "containerd",
    "dockerd",
    "crun",
    "runc",
    "qemu",
    "qemu-system",
    "Xorg",
    "Xwayland",
];

/// Security / monitoring daemons whose death is a defense-evasion signal:
/// sending a killing signal to one of these is `T1562.001 Impair Defenses:
/// Disable or Modify Tools`, the classic move that precedes the rest of an
/// intrusion. InnerWarden's own components are listed as defense-in-depth
/// (the watchdog is the authoritative backstop for the sensor/agent, but a
/// kill of any of them is still worth an incident).
///
/// Names are matched **truncated to 15 chars** (`comm_in`) because
/// `/proc/<pid>/comm` and `bpf_get_current_comm()` are limited to
/// `TASK_COMM_LEN` (16) => 15 chars, so `innerwarden-watchdog` is reported
/// as `innerwarden-wat`. The readable form is kept here for clarity.
const SECURITY_TOOLS: &[&str] = &[
    // InnerWarden
    "innerwarden",
    "innerwarden-sensor",
    "innerwarden-agent",
    "innerwarden-watchdog",
    "innerwarden-supervisor",
    "innerwarden-shield",
    // Host IDS / audit / FIM
    "auditd",
    "falco",
    "tetragon",
    "osqueryd",
    "ossec-analysisd",
    "ossec-syscheckd",
    "ossec-logcollector",
    "wazuh-agentd",
    "wazuh-modulesd",
    "wazuh-logcollector",
    "aide",
    "tripwire",
    "samhain",
    "sandfly",
    // Network IDS
    "suricata",
    "snort",
    "zeek",
    // AV / EDR
    "clamd",
    "clamav",
    "freshclam",
    "falcon-sensor",
    "falcond",
    "sentinelone",
    "sentineld",
    "s1-agent",
    "cbagentd",
    "cbdaemon",
    "cb-enterprise",
    // Blockers / SIEM shippers
    "fail2ban-server",
    "crowdsec",
    "filebeat",
    "auditbeat",
    "splunkd",
];

/// Init senders whose comm is forgeable but whose identity is anchored to
/// **PID 1** — the allowlist match is only honoured when the sender really is
/// PID 1, so a process that renamed itself to `systemd`/`init` via
/// `prctl(PR_SET_NAME)` does NOT get a free pass. `systemctl restart auditd`
/// is delivered by systemd (PID 1), so the real case still passes.
const PID1_SENDERS: &[&str] = &["systemd", "init"];

/// Process/service managers that legitimately deliver killing signals to
/// daemons (the FP vector for `systemctl restart auditd`-style activity, plus
/// package upgrades, log rotation, and container lifecycle). This default
/// allowlist is the FIRST FP layer; bespoke watchdogs / process-managers
/// belong in the per-server `allowlist.toml` (`kind = kernel_kill`), NOT here.
/// Never add shells (`sh`/`bash`) — they are forgeable and attacker-controlled.
/// Matched truncated to 15 like the tool list.
const KILL_SIGNAL_SENDERS: &[&str] = &[
    "systemd-shutdown",
    "shutdown",
    "innerwarden-watchdog",
    "innerwarden-supervisor",
    "supervisord",
    "monit",
    "logrotate",
    "dpkg",
    "rpm",
    "apt",
    "containerd",
    "dockerd",
    "docker",
    "podman",
    "runc",
    "crun",
];

/// Compare a (possibly `TASK_COMM_LEN`-truncated) comm base name against a
/// readable name, truncating the readable name the same way the kernel does.
/// All comparison names are ASCII, so byte-slicing at 15 is char-safe.
fn comm_matches(comm_base: &str, name: &str) -> bool {
    comm_base == &name[..name.len().min(15)]
}

/// True when `comm_base` matches any name in `list` under `comm_matches`.
fn comm_in(comm_base: &str, list: &[&str]) -> bool {
    list.iter().any(|n| comm_matches(comm_base, n))
}

/// PTRACE request ops that read/write/control another process — the
/// injection / credential-dump surface. PEEK (read) ops are deliberately
/// excluded as too noisy; ATTACH/SEIZE are the entry to any injection.
/// POKETEXT=4 POKEDATA=5 POKEUSR=6 SETREGS=13 SETFPREGS=15 ATTACH=16
/// SETREGSET=0x4205 SEIZE=0x4206.
fn ptrace_op_is_invasive(req: u64) -> bool {
    matches!(req, 4 | 5 | 6 | 13 | 15 | 16 | 0x4205 | 0x4206)
}

/// Normalise a comm to its base name (strip a path, strip kernel-thread
/// parens) for allowlist comparison.
fn comm_base(comm: &str) -> &str {
    let b = comm.rsplit('/').next().unwrap_or(comm);
    b.trim_matches(|c: char| c == '(' || c == ')')
}

/// True for kernel threads (kworker, the NMI watchdog, ksoftirqd, migration,
/// rcu_*, ...). They run with a non-zero cgroup_id, so the eBPF `in_container`
/// heuristic (cgroup_id != 0) tags them as "in a container" — but a kernel
/// thread never escapes a container. Their comm is the bracketed /
/// parenthesised kernel-thread display form (`[kworker/u8:2]`, `(watchdog)`) or
/// a bare `kworker`. Userspace process comms never start with `[`/`(`.
fn is_kernel_thread(comm: &str) -> bool {
    let c = comm.trim();
    c.starts_with('[')
        || c.starts_with('(')
        || c.starts_with("kworker")
        || matches!(
            comm_base(c),
            "watchdog"
                | "ksoftirqd"
                | "migration"
                | "kthreadd"
                | "rcu_sched"
                | "rcu_bh"
                | "kswapd0"
                | "khugepaged"
                | "kcompactd0"
                | "kdevtmpfs"
                | "kauditd"
                | "ksmd"
                | "oom_reaper"
        )
}

/// NON-forgeable FP layer for `memfd_create`: true when the creating process's
/// kernel-captured exe path (`details.exe_path`, the execve filename) lives
/// under a package-managed system directory. A trusted on-disk binary creating a
/// memfd is normal; only an absent / `/tmp` / deleted / memfd-backed exe stays
/// promotable. Shares `path_trust` with `host_drift` so the two agree.
fn memfd_exe_is_trusted(ev: &Event) -> bool {
    let exe = text(ev, "exe_path");
    !exe.is_empty() && crate::path_trust::is_trusted_system_path(exe)
}

/// The per-kind detector name used for incident-level suppression
/// (`is_incident_suppressed`) so operators can tune each independently.
pub(crate) fn suppression_name(kind: &str) -> &'static str {
    match kind {
        "process.ptrace_attach" => "kernel_ptrace",
        "memory.mprotect_exec" => "kernel_mprotect",
        "process.memfd_create" => "kernel_memfd",
        "filesystem.mount" => "kernel_mount",
        "process.signal" => "kernel_kill",
        _ => "kernel_exploit",
    }
}

fn num(ev: &Event, k: &str) -> u64 {
    ev.details.get(k).and_then(|v| v.as_u64()).unwrap_or(0)
}
fn flag(ev: &Event, k: &str) -> bool {
    ev.details.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
}
fn text<'a>(ev: &'a Event, k: &str) -> &'a str {
    ev.details.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

fn build_incident(
    ev: &Event,
    severity: Severity,
    title: String,
    summary: String,
    checks: Vec<String>,
    tag: &str,
) -> Incident {
    let pid = num(ev, "pid");
    let target = num(ev, "target_pid");
    Incident {
        ts: ev.ts,
        host: ev.host.clone(),
        // Include target_pid so a kill-storm (one sender SIGKILLing auditd then
        // falco in the same minute) does not collapse to a single deduped
        // incident and hide kills #2..#N. Arms with no target contribute `:0`.
        incident_id: format!(
            "kernel:{}:{}:{}:{}",
            tag,
            pid,
            target,
            ev.ts.format("%Y-%m-%dT%H:%MZ")
        ),
        severity,
        title,
        summary,
        evidence: serde_json::json!([ev.details]),
        recommended_checks: checks,
        tags: vec![
            "ebpf".to_string(),
            "kernel_exploit".to_string(),
            tag.to_string(),
        ],
        entities: ev.entities.clone(),
    }
}

/// Promote a high-signal kernel syscall event to an incident, or `None` if
/// it is benign / allowlisted. Layers 1 (default allowlist) and 2 (per-server
/// `DynamicAllowlist`) are applied here; layer 3 (incident suppression) is at
/// the call site.
pub(crate) fn kernel_syscall_incident(
    ev: &Event,
    allowlist: &DynamicAllowlist,
) -> Option<Incident> {
    let comm = text(ev, "comm");
    let base = comm_base(comm);
    let pid = num(ev, "pid");

    match ev.kind.as_str() {
        "process.ptrace_attach" => {
            let req = num(ev, "request");
            let target = num(ev, "target_pid");
            // Only invasive ops into a *different* live process.
            if !ptrace_op_is_invasive(req) || target == 0 || target == pid {
                return None;
            }
            if PTRACE_DEBUGGERS.contains(&base)
                || allowlist.is_process_allowed(comm, Some("kernel_ptrace"))
            {
                return None;
            }
            let op = text(ev, "request_name");
            Some(build_incident(
                ev,
                Severity::Critical,
                format!("Process injection via ptrace: {comm} (PID {pid})"),
                format!(
                    "{comm} (PID {pid}) issued {op} against PID {target} — writing to or seizing \
                     another process is the core of code injection and credential dumping (T1055.008 / \
                     T1003). The actor is not a known debugger.",
                ),
                vec![
                    format!("Inspect PID {pid} ({comm}) and its parent — unexpected ptrace source"),
                    format!("Check what PID {target} is and whether its memory was tampered"),
                ],
                "ptrace_injection",
            ))
        }
        "memory.mprotect_exec" => {
            // Only RWX (writable + executable) — the shellcode-staging signal.
            if !flag(ev, "rwx") {
                return None;
            }
            if JIT_RUNTIMES.contains(&base)
                || allowlist.is_process_allowed(comm, Some("kernel_mprotect"))
            {
                return None;
            }
            Some(build_incident(
                ev,
                Severity::Critical,
                format!("RWX memory by non-JIT process: {comm} (PID {pid})"),
                format!(
                    "{comm} (PID {pid}) marked memory read+write+execute at {} ({} bytes). RWX is the \
                     classic shellcode / runtime-unpacking pattern (T1055) and {comm} is not a known \
                     JIT/managed runtime.",
                    text(ev, "addr"),
                    num(ev, "len"),
                ),
                vec![
                    format!("Dump and inspect the RWX region of PID {pid}"),
                    "Confirm the binary is signed/expected; scan for injected shellcode".to_string(),
                ],
                "rwx_mprotect",
            ))
        }
        "process.memfd_create" => {
            // Three FP layers, all of which must miss before we promote:
            //   1. forgeable `comm` allowlist (curated common-good actors),
            //   2. per-server `allowlist.toml`,
            //   3. NON-forgeable exe-path trust: a memfd created by a binary
            //      that lives on disk under a package-managed system path is
            //      normal (browsers, systemd's executor, fwupd, and Rust/tokio
            //      services all do it). The exe path is the kernel-captured
            //      execve filename, so unlike `comm` it cannot be spoofed from
            //      `/tmp`. This is what clears generic thread comms like
            //      `tokio-rt-worker` (the agent's own runtime) without adding a
            //      spoofable comm any Rust payload could wear. The real fileless
            //      signal (a deleted / memfd-backed exec) is explicitly NOT
            //      trusted (see `path_trust::is_trusted_system_path`), and the
            //      `fexecve`-from-memfd follow-up stays in the recommended checks.
            if MEMFD_LEGIT.contains(&base)
                || allowlist.is_process_allowed(comm, Some("kernel_memfd"))
                || memfd_exe_is_trusted(ev)
            {
                return None;
            }
            Some(build_incident(
                ev,
                Severity::High,
                format!("Fileless payload staging via memfd: {comm} (PID {pid})"),
                format!(
                    "{comm} (PID {pid}) created an anonymous in-memory file ({}). memfd-backed execution \
                     leaves nothing on disk (T1620 fileless) and {comm} is not a known legitimate memfd \
                     user.",
                    text(ev, "name"),
                ),
                vec![
                    format!("Check whether PID {pid} exec'd from the memfd (fexecve)"),
                    format!("Inspect PID {pid} lineage — how was it spawned"),
                ],
                "memfd_fileless",
            ))
        }
        "filesystem.mount" => {
            // Mounting from inside a container is the namespace-escape signal.
            if !flag(ev, "in_container") || allowlist.is_process_allowed(comm, Some("kernel_mount"))
            {
                return None;
            }
            // FP guard (2026-06-03, prod): the eBPF `in_container` heuristic is
            // `cgroup_id != 0`, which also matches KERNEL THREADS (kworker, the
            // NMI watchdog, ...). Their internal mount work carries no readable
            // source/target/fs. A real escape is a userspace process mounting a
            // SPECIFIC host path. Skip kernel threads and arg-less mounts — they
            // fired Critical false positives on prod (`[kworker/u8:2]` /
            // `(watchdog)` around agent restart windows, empty mount args).
            let source = text(ev, "source");
            let target = text(ev, "target");
            let fs_type = text(ev, "fs_type");
            if is_kernel_thread(comm)
                || (source.is_empty() && target.is_empty() && fs_type.is_empty())
            {
                return None;
            }
            Some(build_incident(
                ev,
                Severity::Critical,
                format!("Mount inside container: {comm} (PID {pid})"),
                format!(
                    "{comm} (PID {pid}) called mount inside a container — mounting the host filesystem or \
                     a sensitive path is a container/namespace escape primitive (T1611). \
                     source={source} target={target} fs={fs_type}.",
                ),
                vec![
                    format!("Identify the container of PID {pid} and what it mounted"),
                    "Verify the container is not privileged / lacks CAP_SYS_ADMIN".to_string(),
                ],
                "container_mount_escape",
            ))
        }
        "process.signal" => {
            // Killing/freezing signals matter for defense evasion: SIGKILL(9)/
            // SIGTERM(15) kill, SIGSTOP(19) freezes, plus the wider set in
            // `is_killing_signal` (so `kill -ABRT`/`-QUIT`/RT-signal evasions
            // do not slip through). Must match the resolver's gate.
            let signal = num(ev, "signal") as u32;
            if !is_killing_signal(signal) {
                return None;
            }
            let target = num(ev, "target_pid");
            if target == 0 || target == pid {
                return None;
            }
            // `target_comm` is resolved best-effort at emission (/proc). If the
            // target already exited (SIGKILL race) we cannot confirm it was a
            // security tool, so we stay silent rather than alert on every kill
            // — the watchdog is the authoritative backstop for InnerWarden's
            // own processes, and a future pid-registry can close the race.
            let target_comm = text(ev, "target_comm");
            let target_base = comm_base(target_comm);
            if target_base.is_empty() || !comm_in(target_base, SECURITY_TOOLS) {
                return None;
            }
            // FP layer: the service manager / IW's own supervisor restarting a
            // daemon, a tool managing itself (same comm), or an operator-tuned
            // allowlist entry is legitimate. `systemd`/`init` are honoured only
            // when the sender really is PID 1 — a comm rename to "systemd" is
            // not enough (anti-spoof).
            let sender_is_init = comm_in(base, PID1_SENDERS) && pid == 1;
            if sender_is_init
                || comm_in(base, KILL_SIGNAL_SENDERS)
                || base == target_base
                || allowlist.is_process_allowed(comm, Some("kernel_kill"))
            {
                return None;
            }
            let sig_name = text(ev, "signal_name");
            Some(build_incident(
                ev,
                Severity::Critical,
                format!("Security tool killed: {comm} (PID {pid}) -> {target_comm} (PID {target})"),
                format!(
                    "{comm} (PID {pid}) sent {sig_name} to {target_comm} (PID {target}), a \
                     security/monitoring process. Killing defensive tooling is the Impair Defenses \
                     move (T1562.001) that clears the way for the rest of an intrusion. The sender is \
                     not the service manager or a known supervisor.",
                ),
                vec![
                    format!("Confirm whether {target_comm} (PID {target}) is still running; restart it if down"),
                    format!("Inspect PID {pid} ({comm}) and its parent — why is it signalling a security tool"),
                ],
                "defense_evasion_kill",
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str, details: serde_json::Value) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: "h".into(),
            source: "ebpf".into(),
            kind: kind.into(),
            severity: Severity::High,
            summary: "s".into(),
            details,
            tags: vec![],
            entities: vec![],
        }
    }

    fn empty_allowlist() -> DynamicAllowlist {
        // load() of a missing path yields an empty dynamic allowlist (the
        // static const lists inside allowlists.rs still apply — which is why
        // the positive tests below use clearly attacker-shaped comms).
        DynamicAllowlist::load(std::path::Path::new("/nonexistent/iw-test-allowlist.toml"))
    }

    #[test]
    fn ptrace_invasive_into_other_process_promotes() {
        let inc = kernel_syscall_incident(
            &ev(
                "process.ptrace_attach",
                serde_json::json!({"pid":1000,"target_pid":2000,"request":16,"request_name":"PTRACE_ATTACH","comm":"evil"}),
            ),
            &empty_allowlist(),
        )
        .expect("non-debugger ATTACH into another process must promote");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.tags.contains(&"ptrace_injection".to_string()));
    }

    #[test]
    fn ptrace_debugger_and_self_and_readop_are_benign() {
        // debugger comm
        assert!(kernel_syscall_incident(
            &ev(
                "process.ptrace_attach",
                serde_json::json!({"pid":1,"target_pid":2,"request":16,"comm":"gdb"})
            ),
            &empty_allowlist()
        )
        .is_none());
        // self / thread (target == pid)
        assert!(kernel_syscall_incident(
            &ev(
                "process.ptrace_attach",
                serde_json::json!({"pid":5,"target_pid":5,"request":16,"comm":"evil"})
            ),
            &empty_allowlist()
        )
        .is_none());
        // non-invasive read op (PEEKTEXT=1)
        assert!(kernel_syscall_incident(
            &ev(
                "process.ptrace_attach",
                serde_json::json!({"pid":1,"target_pid":2,"request":1,"comm":"evil"})
            ),
            &empty_allowlist()
        )
        .is_none());
    }

    #[test]
    fn mprotect_rwx_non_jit_promotes_but_jit_and_non_rwx_are_benign() {
        assert!(kernel_syscall_incident(
            &ev(
                "memory.mprotect_exec",
                serde_json::json!({"pid":1,"rwx":true,"addr":"0xdead","len":4096,"comm":"evil"})
            ),
            &empty_allowlist()
        )
        .is_some());
        // JIT runtime
        assert!(kernel_syscall_incident(
            &ev(
                "memory.mprotect_exec",
                serde_json::json!({"pid":1,"rwx":true,"comm":"node"})
            ),
            &empty_allowlist()
        )
        .is_none());
        // not RWX (RX only)
        assert!(kernel_syscall_incident(
            &ev(
                "memory.mprotect_exec",
                serde_json::json!({"pid":1,"rwx":false,"comm":"evil"})
            ),
            &empty_allowlist()
        )
        .is_none());
    }

    #[test]
    fn memfd_non_legit_promotes_legit_is_benign() {
        assert!(kernel_syscall_incident(
            &ev(
                "process.memfd_create",
                serde_json::json!({"pid":1,"name":"x","comm":"evil"})
            ),
            &empty_allowlist()
        )
        .is_some());
        assert!(kernel_syscall_incident(
            &ev(
                "process.memfd_create",
                serde_json::json!({"pid":1,"name":"x","comm":"systemd"})
            ),
            &empty_allowlist()
        )
        .is_none());
    }

    #[test]
    fn memfd_fwupdmgr_and_sd_executor_are_benign() {
        // Prod FP (2026-06 audit): fwupd's CLI and systemd's per-unit executor
        // legitimately create memfds. `(sd-executor)` strips to `sd-executor`.
        for comm in ["fwupdmgr", "fwupd", "(sd-executor)"] {
            assert!(
                kernel_syscall_incident(
                    &ev(
                        "process.memfd_create",
                        serde_json::json!({"pid":1,"name":"x","comm":comm})
                    ),
                    &empty_allowlist()
                )
                .is_none(),
                "{comm} memfd must not promote"
            );
        }
    }

    #[test]
    fn memfd_trusted_exe_path_clears_generic_thread_comm() {
        // Prod FP: a Rust service's worker thread reports comm `tokio-rt-worker`
        // (generic, NOT on the comm allowlist) but its exe lives on disk under a
        // system path. The non-forgeable exe-path trust must clear it.
        assert!(
            kernel_syscall_incident(
                &ev(
                    "process.memfd_create",
                    serde_json::json!({"pid":42,"name":"x","comm":"tokio-rt-worker","exe_path":"/usr/local/bin/innerwarden-agent"})
                ),
                &empty_allowlist()
            )
            .is_none(),
            "trusted exe path must suppress the generic-comm memfd FP"
        );
    }

    #[test]
    fn memfd_untrusted_exe_path_still_promotes_anti_evasion() {
        // Anti-evasion: the exe-path trust must NOT become a free pass. A Rust
        // payload wearing `tokio-rt-worker` but running from /tmp (or with a
        // deleted backing file) must STILL promote, exactly the fileless case.
        for exe in ["/tmp/payload", "/usr/bin/python3 (deleted)", "memfd:evil"] {
            assert!(
                kernel_syscall_incident(
                    &ev(
                        "process.memfd_create",
                        serde_json::json!({"pid":42,"name":"x","comm":"tokio-rt-worker","exe_path":exe})
                    ),
                    &empty_allowlist()
                )
                .is_some(),
                "untrusted/volatile exe_path ({exe}) must still promote"
            );
        }
    }

    #[test]
    fn memfd_missing_exe_path_falls_back_to_comm_gate() {
        // No exe_path => the exe-trust layer abstains; an attacker-shaped comm
        // with no on-disk anchor still promotes (current behaviour preserved).
        assert!(kernel_syscall_incident(
            &ev(
                "process.memfd_create",
                serde_json::json!({"pid":1,"name":"x","comm":"evil"})
            ),
            &empty_allowlist()
        )
        .is_some());
    }

    #[test]
    fn mount_in_container_promotes_host_mount_is_benign() {
        let inc = kernel_syscall_incident(
            &ev(
                "filesystem.mount",
                serde_json::json!({"pid":1,"in_container":true,"source":"/dev/sda","target":"/mnt","fs_type":"ext4","comm":"evilmount"}),
            ),
            &empty_allowlist(),
        );
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
        // host-side mount (not in container) is normal admin activity
        assert!(kernel_syscall_incident(
            &ev(
                "filesystem.mount",
                serde_json::json!({"pid":1,"in_container":false,"comm":"mount"})
            ),
            &empty_allowlist()
        )
        .is_none());
    }

    #[test]
    fn mount_kernel_thread_and_argless_are_benign() {
        // Prod FP 2026-06-03: kernel threads (kworker, the NMI watchdog) run
        // with cgroup_id != 0 so `in_container` is true, but they are not
        // container escapes; their mount work has empty source/target/fs.
        for comm in [
            "[kworker/u8:2]",
            "(watchdog)",
            "kworker/0:1H",
            "ksoftirqd/0",
        ] {
            assert!(
                kernel_syscall_incident(
                    &ev(
                        "filesystem.mount",
                        serde_json::json!({"pid":2712174,"in_container":true,"source":"","target":"","fs_type":"","comm":comm})
                    ),
                    &empty_allowlist()
                )
                .is_none(),
                "kernel thread {comm} must not fire container_mount_escape"
            );
        }
        // A userspace process with an arg-less mount is also not actionable.
        assert!(kernel_syscall_incident(
            &ev(
                "filesystem.mount",
                serde_json::json!({"pid":1,"in_container":true,"source":"","target":"","fs_type":"","comm":"bash"})
            ),
            &empty_allowlist()
        )
        .is_none());
        // But a userspace process mounting a real host path still promotes
        // (regression guard: the FP fix must not blind real escapes).
        assert!(kernel_syscall_incident(
            &ev(
                "filesystem.mount",
                serde_json::json!({"pid":1,"in_container":true,"source":"/dev/sda","target":"/host","fs_type":"ext4","comm":"sh"})
            ),
            &empty_allowlist()
        )
        .is_some());
    }

    #[test]
    fn unrelated_kind_is_ignored() {
        assert!(kernel_syscall_incident(
            &ev("process.exit", serde_json::json!({"pid":1,"comm":"x"})),
            &empty_allowlist()
        )
        .is_none());
    }

    #[test]
    fn kill_security_tool_by_non_manager_promotes() {
        let inc = kernel_syscall_incident(
            &ev(
                "process.signal",
                serde_json::json!({"pid":1000,"target_pid":42,"signal":9,"signal_name":"SIGKILL","target_comm":"auditd","comm":"evil"}),
            ),
            &empty_allowlist(),
        )
        .expect("non-manager SIGKILL of a security tool must promote");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.tags.contains(&"defense_evasion_kill".to_string()));
    }

    #[test]
    fn kill_security_tool_matches_truncated_comm() {
        // /proc/<pid>/comm truncates innerwarden-watchdog to 15 chars.
        let inc = kernel_syscall_incident(
            &ev(
                "process.signal",
                serde_json::json!({"pid":7,"target_pid":8,"signal":15,"signal_name":"SIGTERM","target_comm":"innerwarden-wat","comm":"nc"}),
            ),
            &empty_allowlist(),
        );
        assert!(
            inc.is_some(),
            "truncated security-tool comm must still match"
        );
    }

    #[test]
    fn kill_security_tool_benign_cases() {
        // service manager restarting the daemon (`systemctl restart auditd`)
        assert!(kernel_syscall_incident(
            &ev("process.signal", serde_json::json!({"pid":1,"target_pid":8,"signal":15,"signal_name":"SIGTERM","target_comm":"auditd","comm":"systemd"})),
            &empty_allowlist()
        )
        .is_none());
        // target is not a security tool
        assert!(kernel_syscall_incident(
            &ev("process.signal", serde_json::json!({"pid":1,"target_pid":8,"signal":9,"signal_name":"SIGKILL","target_comm":"bash","comm":"evil"})),
            &empty_allowlist()
        )
        .is_none());
        // non-killing signal (SIGCONT=18) is not defense evasion
        assert!(kernel_syscall_incident(
            &ev("process.signal", serde_json::json!({"pid":1,"target_pid":8,"signal":18,"signal_name":"SIGCONT","target_comm":"auditd","comm":"evil"})),
            &empty_allowlist()
        )
        .is_none());
        // a known service/process manager (logrotate calling kill in postrotate)
        assert!(kernel_syscall_incident(
            &ev("process.signal", serde_json::json!({"pid":900,"target_pid":8,"signal":15,"signal_name":"SIGTERM","target_comm":"auditd","comm":"logrotate"})),
            &empty_allowlist()
        )
        .is_none());
        // target_comm unresolved (lost the SIGKILL race) => stay silent
        assert!(kernel_syscall_incident(
            &ev("process.signal", serde_json::json!({"pid":1,"target_pid":8,"signal":9,"signal_name":"SIGKILL","target_comm":"","comm":"evil"})),
            &empty_allowlist()
        )
        .is_none());
        // self / same process (target == pid)
        assert!(kernel_syscall_incident(
            &ev("process.signal", serde_json::json!({"pid":8,"target_pid":8,"signal":9,"signal_name":"SIGKILL","target_comm":"auditd","comm":"auditd"})),
            &empty_allowlist()
        )
        .is_none());
        // a tool managing itself (sender base == target base)
        assert!(kernel_syscall_incident(
            &ev("process.signal", serde_json::json!({"pid":1,"target_pid":8,"signal":15,"signal_name":"SIGTERM","target_comm":"falco","comm":"falco"})),
            &empty_allowlist()
        )
        .is_none());
    }

    #[test]
    fn kill_security_tool_broadened_signals_promote() {
        // SIGABRT(6) and a real-time signal (40) must not slip through.
        for sig in [6u64, 40u64] {
            assert!(
                kernel_syscall_incident(
                    &ev(
                        "process.signal",
                        serde_json::json!({"pid":1000,"target_pid":8,"signal":sig,"signal_name":"x","target_comm":"falco","comm":"evil"})
                    ),
                    &empty_allowlist()
                )
                .is_some(),
                "signal {sig} at a security tool must promote"
            );
        }
    }

    #[test]
    fn kill_security_tool_systemd_spoof_promotes_but_real_pid1_is_benign() {
        // A process that renamed itself "systemd" but is NOT PID 1 is spoofing
        // the init allowlist -> must still promote.
        assert!(kernel_syscall_incident(
            &ev("process.signal", serde_json::json!({"pid":4242,"target_pid":8,"signal":9,"signal_name":"SIGKILL","target_comm":"auditd","comm":"systemd"})),
            &empty_allowlist()
        )
        .is_some());
        // The real init (PID 1) restarting a unit is benign.
        assert!(kernel_syscall_incident(
            &ev("process.signal", serde_json::json!({"pid":1,"target_pid":8,"signal":15,"signal_name":"SIGTERM","target_comm":"auditd","comm":"systemd"})),
            &empty_allowlist()
        )
        .is_none());
    }

    #[test]
    fn kill_security_tool_distinct_targets_distinct_incident_ids() {
        // A kill-storm against two different tools in the same minute must not
        // collapse into one deduped incident.
        let a = kernel_syscall_incident(
            &ev("process.signal", serde_json::json!({"pid":1000,"target_pid":8,"signal":9,"signal_name":"SIGKILL","target_comm":"auditd","comm":"evil"})),
            &empty_allowlist(),
        )
        .expect("first kill promotes");
        let b = kernel_syscall_incident(
            &ev("process.signal", serde_json::json!({"pid":1000,"target_pid":9,"signal":9,"signal_name":"SIGKILL","target_comm":"falco","comm":"evil"})),
            &empty_allowlist(),
        )
        .expect("second kill promotes");
        assert_ne!(
            a.incident_id, b.incident_id,
            "different targets must yield different incident ids"
        );
    }

    #[test]
    fn is_killing_signal_set() {
        for s in [1u32, 2, 3, 6, 9, 10, 12, 15, 19, 34, 50, 64] {
            assert!(is_killing_signal(s), "signal {s} must be killing");
        }
        for s in [0u32, 4, 5, 7, 8, 11, 13, 17, 18, 23, 28, 33, 65] {
            assert!(!is_killing_signal(s), "signal {s} must not be killing");
        }
    }

    #[test]
    fn comm_matches_truncates_like_the_kernel() {
        assert!(comm_matches("innerwarden-wat", "innerwarden-watchdog"));
        assert!(comm_matches("innerwarden-age", "innerwarden-agent"));
        assert!(comm_matches("auditd", "auditd"));
        assert!(comm_matches("falco", "falco"));
        assert!(!comm_matches("evil", "auditd"));
        assert!(comm_in("innerwarden-sen", SECURITY_TOOLS));
        assert!(comm_in("systemd", PID1_SENDERS));
        assert!(comm_in("logrotate", KILL_SIGNAL_SENDERS));
        assert!(!comm_in("systemd", KILL_SIGNAL_SENDERS));
        assert!(!comm_in("evil", SECURITY_TOOLS));
    }

    #[test]
    fn suppression_name_is_per_kind() {
        assert_eq!(suppression_name("process.ptrace_attach"), "kernel_ptrace");
        assert_eq!(suppression_name("memory.mprotect_exec"), "kernel_mprotect");
        assert_eq!(suppression_name("process.memfd_create"), "kernel_memfd");
        assert_eq!(suppression_name("filesystem.mount"), "kernel_mount");
        assert_eq!(suppression_name("process.signal"), "kernel_kill");
    }
}
