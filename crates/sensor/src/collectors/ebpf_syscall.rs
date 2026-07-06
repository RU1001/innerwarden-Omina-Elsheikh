//! eBPF syscall collector - kernel-level visibility via tracepoints.
//!
//! Replaces (or complements) audit-based collection with zero-latency
//! kernel-level process execution and network connection monitoring.
//!
//! Requires: Linux kernel 5.8+, CAP_BPF + CAP_PERFMON (or root).
//! Gracefully disables itself when eBPF is not available.

#![allow(dead_code, unused_imports)]
// Functions are used only when compiled with --features ebpf

use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};
use std::net::Ipv4Addr;
use tracing::{error, info, warn};

/// Embedded eBPF bytecode (compiled into the sensor binary).
/// Built with: cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
/// When the feature `ebpf-embedded` is enabled, the bytecode is baked into the binary
/// via include_bytes! - no separate file needed. `innerwarden upgrade` updates everything.
///
/// Spec 069 #3: the object is included from `OUT_DIR` (copied there by
/// `build.rs`), not directly from the sensor-ebpf target dir. Cargo tracks
/// `OUT_DIR` includes for rebuild, so a freshly-built `.o` re-embeds
/// automatically — no more manual `touch` of this file to dodge a stale object.
#[cfg(feature = "ebpf-embedded")]
const EBPF_BYTECODE_EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/innerwarden-ebpf"));

/// Fallback paths for when bytecode is NOT embedded (dev mode or separate deploy).
const EBPF_OBJ_PATH: &str = "/usr/local/lib/innerwarden/innerwarden-ebpf";
const EBPF_OBJ_PATH_DEV: &str =
    "crates/sensor-ebpf/target/bpfel-unknown-none/release/innerwarden-ebpf";

/// Runtime count of eBPF programs this sensor actually attached, set by
/// [`run`] after the attach phase. `usize::MAX` is the sentinel for "not
/// attached yet / eBPF never started" (distinct from a real 0). This closes
/// the gap the `build_ebpf_status` comment flagged: eBPF can be *available*
/// (loads fine) yet attach 0 programs at runtime — e.g. under a restrictive
/// systemd sandbox — leaving the sensor host-blind while it still reports
/// "active". The health layer reads this to surface that state.
static EBPF_ATTACHED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

/// How many eBPF programs the sensor attached at runtime. `None` until the
/// attach phase has run (or if eBPF never started); `Some(0)` means eBPF
/// loaded but nothing attached — the sensor is host-blind.
pub fn ebpf_progs_attached() -> Option<usize> {
    match EBPF_ATTACHED.load(std::sync::atomic::Ordering::Relaxed) {
        usize::MAX => None,
        n => Some(n),
    }
}

/// Check if eBPF is available on this system.
pub fn is_ebpf_available() -> bool {
    ebpf_unavailability_reason().is_none()
}

/// Why eBPF cannot load on this host, or `None` when it can.
///
/// This is the operator-facing companion to [`is_ebpf_available`]. When
/// eBPF is unavailable the sensor still runs (fail-open: userspace
/// collectors keep working), but ~44 kernel programs and all LSM-based
/// enforcement go dark. Pre-2026-05-29 that happened with only a `warn!`
/// in the journal, so an operator on a BTF-less kernel ran a sensor that
/// looked healthy while its kernel layer was silent. The returned reason
/// flows into `collector-health.json` (eBPF row -> `Unsupported`) so the
/// Sensors HUD says plainly why the kernel feed is dark.
///
/// Note: this is the BOOT-TIME, STATIC check (Linux + kernel >= 5.8 +
/// BTF + bytecode present). A runtime load failure caused by a missing
/// `CAP_BPF` is detected later, inside the collector task, and is not yet
/// reflected here (tracked as a follow-up; would need runtime health
/// write-back).
pub fn ebpf_unavailability_reason() -> Option<String> {
    let osrelease = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok();
    let btf_exists = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();
    classify_ebpf_availability(
        cfg!(target_os = "linux"),
        osrelease.as_deref(),
        btf_exists,
        has_ebpf_bytecode(),
    )
}

/// Pure classifier behind [`ebpf_unavailability_reason`]. Kept free of
/// I/O so every branch is unit-testable on any OS. Returns `None` when
/// eBPF can load, or `Some(reason)` with an operator-readable cause.
/// Check order mirrors the historical `is_ebpf_available` short-circuits
/// (platform -> kernel version -> BTF -> bytecode) so behaviour is
/// unchanged; only the explanation is new.
fn classify_ebpf_availability(
    is_linux: bool,
    osrelease: Option<&str>,
    btf_exists: bool,
    bytecode_exists: bool,
) -> Option<String> {
    if !is_linux {
        return Some("not Linux: eBPF kernel instrumentation is Linux-only".to_string());
    }
    match osrelease {
        None => {
            return Some(
                "could not read /proc/sys/kernel/osrelease to verify the kernel version"
                    .to_string(),
            );
        }
        Some(release) => {
            let parts: Vec<u32> = release
                .trim()
                .split('.')
                .take(2)
                .filter_map(|p| p.parse().ok())
                .collect();
            if parts.len() >= 2 && (parts[0] < 5 || (parts[0] == 5 && parts[1] < 8)) {
                return Some(format!(
                    "kernel {}.{} is older than 5.8 (eBPF CO-RE requires 5.8+)",
                    parts[0], parts[1]
                ));
            }
        }
    }
    if !btf_exists {
        return Some(
            "/sys/kernel/btf/vmlinux missing: kernel built without CONFIG_DEBUG_INFO_BTF, \
             so CO-RE relocations cannot resolve"
                .to_string(),
        );
    }
    if !bytecode_exists {
        return Some(
            "eBPF bytecode object not found (built without `ebpf-embedded` and no object on disk)"
                .to_string(),
        );
    }
    None
}

/// Check if eBPF bytecode is available (embedded or on disk).
/// Separated from `is_ebpf_available()` for testability on non-Linux.
fn has_ebpf_bytecode() -> bool {
    #[cfg(feature = "ebpf-embedded")]
    {
        true
    }
    #[cfg(not(feature = "ebpf-embedded"))]
    {
        std::path::Path::new(EBPF_OBJ_PATH).exists()
            || std::path::Path::new(EBPF_OBJ_PATH_DEV).exists()
    }
}

/// Find the eBPF bytecode file.
fn find_ebpf_obj() -> Option<String> {
    if std::path::Path::new(EBPF_OBJ_PATH).exists() {
        Some(EBPF_OBJ_PATH.to_string())
    } else if std::path::Path::new(EBPF_OBJ_PATH_DEV).exists() {
        Some(EBPF_OBJ_PATH_DEV.to_string())
    } else {
        None
    }
}

/// Resolve parent PID from /proc/<pid>/status. Best-effort (returns 0 on failure).
/// Decode a `setns(2)` nstype mask into a short human label (Spec 070).
/// nstype 0 means "any namespace type, determined by the fd".
fn setns_nstype_name(nstype: u32) -> String {
    if nstype == 0 {
        return "by-fd".to_string();
    }
    const FLAGS: &[(u32, &str)] = &[
        (0x1000_0000, "user"),   // CLONE_NEWUSER
        (0x0002_0000, "mnt"),    // CLONE_NEWNS
        (0x4000_0000, "net"),    // CLONE_NEWNET
        (0x2000_0000, "pid"),    // CLONE_NEWPID
        (0x0400_0000, "uts"),    // CLONE_NEWUTS
        (0x0800_0000, "ipc"),    // CLONE_NEWIPC
        (0x0200_0000, "cgroup"), // CLONE_NEWCGROUP
        (0x0000_0080, "time"),   // CLONE_NEWTIME
    ];
    let mut parts = Vec::new();
    for (bit, name) in FLAGS {
        if nstype & bit != 0 {
            parts.push(*name);
        }
    }
    if parts.is_empty() {
        format!("0x{nstype:x}")
    } else {
        parts.join("+")
    }
}

fn resolve_ppid(pid: u32) -> u32 {
    let path = format!("/proc/{pid}/status");
    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PPid:\t") {
                return val.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Spec 050-PR1 follow-up to #662: resolve the parent PID with kernel-
/// first precedence. Every relevant eBPF event struct carries `ppid`
/// already populated from `task_struct->real_parent->tgid` by the
/// kernel probe; reading it costs zero. Only fall through to
/// `resolve_ppid` (a userspace /proc read) when the kernel value is
/// missing (zero) — which is rare and indicates either an older
/// sensor build that didn't populate the field, or an event for a
/// task whose parent was already reaped.
///
/// Pre-fix the userspace path was the **only** path, so short-lived
/// processes (whoami, id — execute in microseconds) returned ppid=0
/// because /proc/<pid>/status was gone by the time userspace read it.
/// Smoke test 2026-05-17 on Oracle prod captured 10 disguised recon
/// execs all with ppid=0; `discovery_anomaly` requires ppid > 0 for
/// per-parent grouping and so never accumulated the burst.
fn resolve_ppid_kernel_first(kernel_ppid: u32, pid: u32) -> u32 {
    if kernel_ppid != 0 {
        kernel_ppid
    } else {
        resolve_ppid(pid)
    }
}

/// Non-forgeable container + Kubernetes pod identity parsed from
/// `/proc/<pid>/cgroup`. The kernel writes this cgroup path; a process inside a
/// container cannot forge it. `container_id` is the 12-char runtime container
/// id, `pod_uid` is the Kubernetes pod UID (present only for pods — the
/// per-tenant anchor), and `runtime` is the container runtime inferred from the
/// cgroup leaf/prefix.
///
/// Spec 084 P0: `pod_uid` + `runtime` are the missing hops that let the agent
/// map an event to its owning pod -> namespace -> tenant **without trusting any
/// process-supplied label**. The cgroup path is the non-forgeable root of the
/// `cgroup_id -> container -> pod -> tenant` attribution chain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ContainerIdentity {
    pub container_id: String,
    pub pod_uid: Option<String>,
    pub runtime: Option<String>,
}

/// Resolve a PID's container/pod identity, memoised per PID.
///
/// Spec 069: the eBPF ring reader calls this for ~15 event kinds, once per
/// event. Without the cache it was a synchronous `/proc/<pid>/cgroup` read on
/// the hot path of the async ring-drain loop — the dominant per-event cost. On
/// a busy host the kprobe syscall handlers (now that they read args correctly)
/// produce events faster than that blocking read could drain them, so events
/// surfaced tens of seconds late. Memoising collapses repeated lookups for the
/// same PID to a map hit. Pid reuse can briefly serve a stale id; acceptable for
/// container attribution and bounded by an 8192-entry cap.
fn resolve_container_identity(pid: u32) -> Option<std::sync::Arc<ContainerIdentity>> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    const CACHE_CAP: usize = 8192;
    // Cache the identity behind an `Arc` so a cache hit (every event on a
    // container host) is a refcount bump, not a fresh clone of the whole
    // `ContainerIdentity` (container_id + pod_uid + runtime Strings) per event.
    static CACHE: OnceLock<Mutex<HashMap<u32, Option<Arc<ContainerIdentity>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    // Recover from a poisoned lock rather than branching on the error so the
    // happy path stays single-expression.
    {
        let map = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = map.get(&pid) {
            return v.clone();
        }
    }
    let result = resolve_container_identity_uncached(pid).map(Arc::new);
    let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
    if map.len() >= CACHE_CAP {
        map.clear();
    }
    map.insert(pid, result.clone());
    result
}

fn resolve_container_identity_uncached(pid: u32) -> Option<ContainerIdentity> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    parse_container_identity_from_cgroup(&content)
}

/// Attach the Kubernetes pod UID + container runtime to an event's `details`.
/// The 12-char `container_id` is already set by the per-event builders / inline
/// sites; this adds the two extra non-forgeable hops uniformly. Best-effort:
/// host processes and non-k8s containers simply omit the fields.
fn attach_pod_runtime(details: &mut serde_json::Value, identity: Option<&ContainerIdentity>) {
    if let Some(id) = identity {
        if let Some(pod) = &id.pod_uid {
            details["pod_uid"] = serde_json::Value::String(pod.clone());
        }
        if let Some(rt) = &id.runtime {
            details["runtime"] = serde_json::Value::String(rt.clone());
        }
    }
}

/// Parse container + pod identity out of `/proc/<pid>/cgroup` contents. Pure
/// (no I/O) so the Docker/Podman/CRI-O/k8s formats are unit-testable without a
/// real container.
///
/// The container id is the cgroup LEAF identifier. It appears in several shapes
/// depending on runtime + cgroup driver:
///   cgroupfs:  0::/docker/<id>
///              0::/kubepods/besteffort/pod<uuid>/<id>
///   systemd:   0::/system.slice/docker-<id>.scope
///              0::/kubepods.slice/.../kubepods-besteffort-pod<uuid>.slice/cri-containerd-<id>.scope
///              0::/.../crio-<id>.scope
///   podman:    0::/libpod-<id>.scope
///
/// Take the leaf path segment, drop a trailing ".scope", then take the last
/// '-'-delimited token: the runtime prefixes (docker-, cri-containerd-, crio-,
/// libpod-) are dash-joined alpha, while the id itself is hex with no '-'. A
/// plain "<id>" leaf (cgroupfs) has no '-' and is returned whole. The pod UID
/// (when present) is parsed from the `pod<uuid>` slice/segment higher in the
/// path; the runtime is inferred from the leaf prefix or the path.
fn parse_container_identity_from_cgroup(content: &str) -> Option<ContainerIdentity> {
    for line in content.lines() {
        // cgroup v2: "0::/path"; v1: "12:pids:/path". The path is after the
        // last ':' so both drivers share one code path.
        let path = line.rsplit(':').next().unwrap_or(line);
        let leaf = match path.rsplit('/').next() {
            Some(l) => l,
            None => continue,
        };
        let leaf = leaf.strip_suffix(".scope").unwrap_or(leaf);
        let id = leaf.rsplit('-').next().unwrap_or(leaf);
        if id.len() >= 12 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(ContainerIdentity {
                container_id: id[..12].to_string(),
                pod_uid: extract_pod_uid(path),
                runtime: detect_runtime(path, leaf),
            });
        }
    }
    None
}

/// Extract a Kubernetes pod UID from a cgroup path. The pod slice/segment
/// carries the UID: the systemd driver escapes the UUID dashes to underscores
/// (`kubepods-besteffort-pod<uid>.slice`), the cgroupfs driver keeps them
/// (`/kubepods/besteffort/pod<uid>/`). Normalised to a canonical lowercase
/// dashed UUID. Returns None for non-k8s containers and host processes.
fn extract_pod_uid(path: &str) -> Option<String> {
    for seg in path.split('/') {
        let seg = seg.strip_suffix(".slice").unwrap_or(seg);
        // A segment can contain "pod" twice ("kubepods-besteffort-pod<uid>");
        // scan every occurrence and keep the first that yields a valid UID.
        let mut start = 0;
        while let Some(rel) = seg[start..].find("pod") {
            let i = start + rel + 3;
            let cand: String = seg[i..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit() || *c == '-' || *c == '_')
                .collect();
            let norm = cand.replace('_', "-").to_lowercase();
            if is_pod_uid(&norm) {
                return Some(norm);
            }
            start = i;
        }
    }
    None
}

/// A Kubernetes pod UID is a UUID: 32 hex digits, optionally dash-grouped
/// 8-4-4-4-12. Accept both the dashed and undashed (32 raw hex) forms.
fn is_pod_uid(s: &str) -> bool {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Infer the container runtime from the cgroup leaf prefix (systemd driver) or
/// the path (cgroupfs driver). Returns None for host processes.
fn detect_runtime(path: &str, leaf: &str) -> Option<String> {
    for (prefix, rt) in [
        ("cri-containerd-", "containerd"),
        ("containerd-", "containerd"),
        ("docker-", "docker"),
        ("crio-", "crio"),
        ("libpod-", "podman"),
    ] {
        if leaf.starts_with(prefix) {
            return Some(rt.to_string());
        }
    }
    // cgroupfs driver: the leaf is the bare id, so infer from the path.
    if path.contains("/docker/") {
        Some("docker".to_string())
    } else if path.contains("kubepods") {
        Some("containerd".to_string())
    } else {
        None
    }
}

/// Read full command-line arguments from /proc/PID/cmdline.
/// Returns the argv as a vector of strings. Best-effort: returns
/// just the filename if /proc read fails (process may have exited).
fn read_proc_cmdline(pid: u32, filename: &str) -> Vec<String> {
    let path = format!("/proc/{pid}/cmdline");
    match std::fs::read(&path) {
        Ok(data) if !data.is_empty() => data
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect(),
        _ => vec![filename.to_string()],
    }
}

/// Spec 069 follow-up #2: best-effort resolve the *target* process name for a
/// `kill()`-class event so `kernel_promote` can flag a process killing a
/// security tool (T1562.001) without re-resolving `/proc` itself.
///
/// Signals that terminate or freeze a daemon at its default disposition, so
/// directing one at a security tool is the defense-evasion signal:
/// SIGHUP(1)/SIGINT(2)/SIGQUIT(3)/SIGABRT(6) terminate, SIGKILL(9)/SIGTERM(15)
/// kill, SIGUSR1(10)/SIGUSR2(12) terminate by default (several tools treat them
/// as reload/exit), SIGSTOP(19) freezes, and every real-time signal (34..=64)
/// defaults to terminate. Crash signals (SIGILL/SIGTRAP/SIGSEGV/SIGBUS/SIGFPE)
/// and benign ones (SIGCHLD/SIGCONT/SIGWINCH/SIGURG) are excluded so the rule
/// is not noisy. This is the single source of truth shared by the `/proc`
/// target-comm resolver here and `kernel_promote`'s `process.signal` arm — they
/// MUST agree or a killing signal arrives with no `target_comm` and slips
/// through.
pub(crate) fn is_killing_signal(sig: u32) -> bool {
    matches!(sig, 1 | 2 | 3 | 6 | 9 | 10 | 12 | 15 | 19) || (34..=64).contains(&sig)
}

/// Bounded to killing/freezing signals (`is_killing_signal`) so we do not
/// `/proc`-read for every `kill(pid, 0)` liveness probe or benign
/// SIGCHLD/SIGCONT. Best-effort: a target that already exited (lost the SIGKILL
/// race) yields an empty string, in which case the promoter stays silent rather
/// than guess.
fn resolve_target_comm(signal: u32, target_pid: u32) -> String {
    if is_killing_signal(signal) {
        crate::detectors::exec_context::proc_comm(target_pid).unwrap_or_default()
    } else {
        String::new()
    }
}

/// Convert a kernel execve event to an Inner Warden Event.
///
/// Reads `/proc/{ppid}/comm` so the 050-PR0 context-aware allowlist
/// (`detectors::exec_context::classify`) stays I/O-free on the hot
/// path — the classifier reads `parent_comm` from `event.details`
/// rather than re-resolving it for every detector that needs it. The
/// lookup is best-effort: a missing file (parent exited, namespaced
/// `/proc`) yields an empty `parent_comm`, which the classifier maps
/// to the safe `AttackerInferred` default.
#[allow(clippy::too_many_arguments)]
fn execve_to_event(
    pid: u32,
    uid: u32,
    ppid: u32,
    cgroup_id: u64,
    container_id: Option<&str>,
    comm: &str,
    filename: &str,
    kernel_argv: Vec<String>,
    host: &str,
) -> Event {
    // Prefer the argv captured IN-KERNEL at execve entry (see the eBPF
    // read_argv_slot! unroll): it is complete and reliable even for a
    // short-lived process. /proc/PID/cmdline is only a fallback for when the
    // kernel gave us nothing useful (an older sensor eBPF that zeroes argv, or a
    // failed read) - and for a dead process it degrades to just [filename]
    // anyway, which is exactly the blindness this replaces.
    let full_argv = if kernel_argv.len() > 1 {
        kernel_argv
    } else {
        read_proc_cmdline(pid, filename)
    };
    let argc = full_argv.len();
    let command = full_argv.join(" ");
    // Move each token into the JSON array instead of cloning it: `command` and
    // `argc` are already computed above, so `full_argv` is no longer needed.
    let argv_json: Vec<serde_json::Value> = full_argv
        .into_iter()
        .map(serde_json::Value::String)
        .collect();

    let parent_comm = crate::detectors::exec_context::proc_comm(ppid).unwrap_or_default();
    // Controlling-terminal proof for the exec_context classifier: read the
    // PARENT's tty (the long-lived shell), not the microsecond-lived recon child
    // whose /proc entry is often already gone. tty_nr != 0 ⇒ real interactive
    // session; an implant / reverse shell / daemon-spawned shell has none.
    let has_tty = crate::detectors::exec_context::proc_has_tty(ppid);

    let mut details = serde_json::json!({
        "pid": pid,
        "uid": uid,
        "ppid": ppid,
        "comm": comm,
        "parent_comm": parent_comm,
        "has_tty": has_tty,
        "command": command,
        "argv": argv_json,
        "argc": argc,
        "cgroup_id": cgroup_id,
    });
    if let Some(cid) = container_id {
        details["container_id"] = serde_json::Value::String(cid.to_string());
    }

    let mut tags = vec!["ebpf".to_string(), "exec".to_string()];
    let mut entities = vec![];
    if let Some(cid) = container_id {
        tags.push("container".to_string());
        entities.push(EntityRef::container(cid));
    }

    Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: "shell.command_exec".to_string(),
        severity: Severity::Info,
        summary: if argc > 1 {
            format!("Shell command executed: {command}")
        } else {
            format!("Shell command executed: {filename}")
        },
        details,
        tags,
        entities,
    }
}

/// Convert a kernel connect event to an Inner Warden Event.
#[allow(clippy::too_many_arguments)]
fn connect_to_event(
    pid: u32,
    uid: u32,
    ppid: u32,
    cgroup_id: u64,
    container_id: Option<&str>,
    comm: &str,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    host: &str,
    exe_path: Option<&str>,
) -> Event {
    let mut details = serde_json::json!({
        "pid": pid,
        "uid": uid,
        "ppid": ppid,
        "comm": comm,
        "dst_ip": dst_ip.to_string(),
        "dst_port": dst_port,
        "cgroup_id": cgroup_id,
    });
    if let Some(cid) = container_id {
        details["container_id"] = serde_json::Value::String(cid.to_string());
    }
    // Spec: non-forgeable process identity for downstream detectors (e.g.
    // imds_ssrf). `exe_path` is the binary captured at execve (from the
    // ExecveCtx cache), NOT the forgeable `comm`. An attacker who renames
    // their process `cloud-init` cannot also be running from a root-owned
    // vendor path. Absent when the connecting pid was not seen execve
    // (e.g. a daemon that started before the sensor) — the detector then
    // falls back to a best-effort /proc/<pid>/exe read.
    if let Some(exe) = exe_path {
        details["exe_path"] = serde_json::Value::String(exe.to_string());
    }

    let mut tags = vec!["ebpf".to_string(), "network".to_string()];
    let mut entities = vec![
        EntityRef::ip(dst_ip.to_string()),
        EntityRef::user(uid_to_name(uid)),
    ];
    if let Some(cid) = container_id {
        tags.push("container".to_string());
        entities.push(EntityRef::container(cid));
    }

    Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: "network.outbound_connect".to_string(),
        severity: if dst_port == 4444 || dst_port == 1337 || dst_port == 31337 {
            Severity::High
        } else {
            Severity::Info
        },
        summary: format!("{comm} (pid={pid}) connecting to {dst_ip}:{dst_port}"),
        details,
        tags,
        entities,
    }
}

/// Resolve a uid to a user name for entity tagging. Used by eBPF events
/// so that correlation rules with `entity_must_match` can match two events
/// from the same user (e.g. file read + network connect → CL-008 exfil).
fn uid_to_name(uid: u32) -> String {
    match uid {
        0 => "root".to_string(),
        _ => format!("uid:{uid}"),
    }
}

/// Convert a kernel file open event to an Inner Warden Event.
#[allow(clippy::too_many_arguments)]
fn file_open_to_event(
    pid: u32,
    uid: u32,
    ppid: u32,
    cgroup_id: u64,
    container_id: Option<&str>,
    comm: &str,
    filename: &str,
    flags: u32,
    host: &str,
    exe_path: Option<&str>,
) -> Event {
    let is_write = flags & 0x3 != 0; // O_WRONLY or O_RDWR

    let mut details = serde_json::json!({
        "pid": pid,
        "uid": uid,
        "ppid": ppid,
        "comm": comm,
        "filename": filename,
        "flags": flags,
        "write": is_write,
        "cgroup_id": cgroup_id,
    });
    if let Some(cid) = container_id {
        details["container_id"] = serde_json::Value::String(cid.to_string());
    }
    // Non-forgeable process identity (the execve-captured exe path, NOT the
    // forgeable `comm`). data_exfil_ebpf uses it so an attacker who `cp`s a
    // payload to `/tmp/sshd` (comm=sshd) cannot inherit sshd's blanket
    // credential-read exemption — a comm-spoofed reader from an untrusted path
    // is not exempt. Absent when the pid was not seen execve (a daemon that
    // predates the sensor), in which case the detector falls back to comm.
    if let Some(exe) = exe_path {
        details["exe_path"] = serde_json::Value::String(exe.to_string());
    }

    let mut tags = vec!["ebpf".to_string(), "file".to_string()];
    let mut entities = vec![EntityRef::user(uid_to_name(uid))];
    entities.push(EntityRef::path(filename));
    if let Some(cid) = container_id {
        tags.push("container".to_string());
        entities.push(EntityRef::container(cid));
    }

    Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: if is_write {
            "file.write_access".to_string()
        } else {
            "file.read_access".to_string()
        },
        severity: if is_write
            && (filename.contains("shadow")
                || filename.contains("sudoers")
                || filename.contains("authorized_keys"))
        {
            Severity::High
        } else {
            Severity::Info
        },
        summary: format!(
            "{comm} (pid={pid}) {} {filename}",
            if is_write { "writing" } else { "reading" }
        ),
        details,
        tags,
        entities,
    }
}

// Privilege escalation allowlist: uses centralized PRIVESC_ALLOWED from
// allowlists.rs. Previously a local duplicate list lived here; now unified so
// additions in one place cover both collector and detector.

/// Convert a kernel privilege escalation event to an Inner Warden Event.
fn privesc_to_event(
    pid: u32,
    old_uid: u32,
    new_uid: u32,
    cgroup_id: u64,
    container_id: Option<&str>,
    comm: &str,
    host: &str,
) -> Option<Event> {
    let comm_base = comm.split('/').next_back().unwrap_or(comm);

    // Filter legitimate escalation processes using the centralized allowlist.
    // Handles kernel task parentheses via comm_in_allowlist: (install) -> install.
    if crate::detectors::allowlists::is_innerwarden_process(old_uid as u64, comm_base)
        || crate::detectors::allowlists::comm_in_allowlist(
            comm_base,
            crate::detectors::allowlists::PRIVESC_ALLOWED,
        )
    {
        return None;
    }

    let severity = if container_id.is_some() {
        Severity::Critical // escalation inside container is always critical
    } else {
        Severity::High
    };

    let mut details = serde_json::json!({
        "pid": pid,
        "old_uid": old_uid,
        "new_uid": new_uid,
        "comm": comm,
        "cgroup_id": cgroup_id,
    });
    if let Some(cid) = container_id {
        details["container_id"] = serde_json::Value::String(cid.to_string());
    }

    let mut tags = vec![
        "ebpf".to_string(),
        "kprobe".to_string(),
        "privesc".to_string(),
    ];
    let mut entities = vec![];
    if let Some(cid) = container_id {
        tags.push("container".to_string());
        entities.push(EntityRef::container(cid));
    }

    let summary = if let Some(cid) = container_id {
        format!(
            "Privilege escalation: {comm} (pid={pid}) uid {old_uid} → {new_uid} [container {cid}]"
        )
    } else {
        format!("Privilege escalation: {comm} (pid={pid}) uid {old_uid} → {new_uid}")
    };

    Some(Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: "privilege.escalation".to_string(),
        severity,
        summary,
        details,
        tags,
        entities,
    })
}

/// Extract a null-terminated string from a byte slice.
fn bytes_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// `ExecveEvent.argv[0]` lives at bytes 352..480 of the `#[repr(C)]` layout
/// (after kind/pid/tgid/uid/gid/ppid = 24, cgroup_id = 8, comm = 64,
/// filename = 256). The Execution Gate writes `b"EXEC_GATE"` there so its
/// kind-6 blocks are distinguishable from the legacy full-hook / kill-chain /
/// neural blocks — every other kind-6 emitter zeroes argv, so the marker is
/// unambiguous. `filename` then carries the REAL attempted path (a denied exec
/// leaves `/proc/<pid>` pointing at the old image, so the path is only
/// recoverable from the event itself).
const EXEC_GATE_MARKER: &[u8; 9] = b"EXEC_GATE";
/// Observe-mode (spec 077 P2): the gate emits this marker instead of EXEC_GATE
/// when LSM_POLICY key 3 == 2 — a would-block (exec was ALLOWED, logged only).
const EXEC_OBSERVE_MARKER: &[u8; 9] = b"EXEC_OBSV";
const EXECVE_ARGV0_OFFSET: usize = 352;

#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
fn is_exec_gate_block(data: &[u8]) -> bool {
    let end = EXECVE_ARGV0_OFFSET + EXEC_GATE_MARKER.len();
    data.len() >= end && data[EXECVE_ARGV0_OFFSET..end] == EXEC_GATE_MARKER[..]
}

/// True when this kind-6 event is an OBSERVE-mode would-block (gate allowed it).
#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
fn is_exec_gate_observe(data: &[u8]) -> bool {
    let end = EXECVE_ARGV0_OFFSET + EXEC_OBSERVE_MARKER.len();
    data.len() >= end && data[EXECVE_ARGV0_OFFSET..end] == EXEC_OBSERVE_MARKER[..]
}

/// Pin path for the XDP blocklist BPF map.
/// The agent writes to this map via bpftool to add/remove blocked IPs.
const XDP_PIN_DIR: &str = "/sys/fs/bpf/innerwarden";
const XDP_BLOCKLIST_PIN: &str = "/sys/fs/bpf/innerwarden/blocklist";
const XDP_ALLOWLIST_PIN: &str = "/sys/fs/bpf/innerwarden/allowlist";

/// 2026-05-08: ensure the BPF pin directory exists before any attach
/// step tries to pin a map. Both `attach_lsm` and `attach_xdp` write
/// pinned maps under `/sys/fs/bpf/innerwarden/`; pre-fix, the dir was
/// only created inside `attach_xdp`, which runs AFTER `attach_lsm`. So
/// LSM/CGROUP/COMM pins always failed silently on first boot until
/// `attach_xdp` ran. Operator-visible: `LSM: failed to pin policy map`
/// plus `CGROUP_CAPABILITIES: failed to pin` warnings during sensor
/// startup, with the (only) recovery path being a sensor restart.
///
/// Returns `Ok(())` if the dir already exists or was created. Returns
/// `Err` only when bpffs is unwritable from the sensor's namespace
/// (e.g. systemd unit has `/sys/fs/bpf` in `ReadOnlyPaths`). The
/// caller then logs and proceeds without pins — same as the legacy
/// behaviour, but with the dir-creation failure surfaced exactly
/// once instead of cascading through every map pin.
#[cfg(feature = "ebpf")]
fn ensure_bpf_pin_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(XDP_PIN_DIR)
}

/// Detect the default network interface for XDP attachment.
fn detect_default_interface() -> Option<String> {
    // Read /proc/net/route - first non-loopback default route
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 && fields[1] == "00000000" {
                return Some(fields[0].to_string());
            }
        }
    }
    None
}

/// Pin path for the LSM policy map.
const LSM_POLICY_PIN: &str = "/sys/fs/bpf/innerwarden/lsm_policy";
/// Pin path for per-cgroup capability map.
const CGROUP_CAP_PIN: &str = "/sys/fs/bpf/innerwarden/cgroup_capabilities";
/// Pin path for per-comm capability map.
const COMM_CAP_PIN: &str = "/sys/fs/bpf/innerwarden/comm_capabilities";
/// Pin path for the BLOCKED_PIDS LRU map consulted by `innerwarden_lsm_exec_min`.
/// The agent populates this via `agent::lsm_policy::register_blocked_pid`.
const BLOCKED_PIDS_PIN: &str = "/sys/fs/bpf/innerwarden/blocked_pids";

/// Pin path for the Execution Gate allowlist (FNV(path) -> 1). Pinned so the paid
/// Active Defence `config-sign exec-gate` tooling can populate it from userspace.
/// The map + gate ship free + INERT; only LSM_POLICY key 3 = 1 (license-gated
/// arming) makes the `bprm_check_security` hook enforce against it.
const EXEC_ALLOWLIST_PIN: &str = "/sys/fs/bpf/innerwarden/exec_allowlist";

/// Pin path for the Execution Gate SCOPE (cgroup id -> 1). Populated by the paid
/// `config-sign exec-gate` tooling with the AI agent's cgroup id(s). Consulted by
/// the gate ONLY when `LSM_POLICY` key 4 = 1 (agent-scoped mode): enforce solely
/// inside these cgroups, allow the rest of the host. Empty + scoped = the gate
/// never fires (fail-open), so a wipe is safe, not a brick.
const EXEC_GATE_SCOPE_PIN: &str = "/sys/fs/bpf/innerwarden/exec_gate_scope";

/// Pin path for the Execution Gate trusted DIRECTORY-PREFIX map
/// (FNV(dir-prefix-with-trailing-slash) -> 1). Populated by the paid
/// `config-sign exec-gate` tooling with OS-maintenance dir prefixes so host-wide
/// enforce does not deny per-kernel dpkg/initramfs maintainer scripts (the
/// "managed installer" trust). Consulted by the gate after the exact-hash
/// allowlist miss; empty + armed = no prefix trusted = unchanged behaviour.
const EXEC_TRUSTED_PREFIX_PIN: &str = "/sys/fs/bpf/innerwarden/exec_trusted_prefix";

/// Attach LSM execution policy and pin the policy map.
/// Requires `lsm=...,bpf` in kernel boot cmdline.
/// Non-critical - if LSM is not available, the sensor continues without it.
#[cfg(feature = "ebpf")]
fn attach_lsm(bpf: &mut aya::Ebpf) {
    use aya::programs::Lsm;

    // Spec 052 Phase 1: run the minimal LSM loader FIRST. The existing
    // `innerwarden_lsm_exec` block below uses `return;` on load failure
    // (kernel ≥ 6.4 always fails due to body complexity — see spec 052),
    // which would short-circuit past this new loader. Putting it first
    // avoids that pre-existing latent control-flow bug without disturbing
    // the legacy paths.
    match bpf.program_mut("innerwarden_lsm_exec_min") {
        Some(prog) => {
            let lsm_res: Result<&mut Lsm, _> = prog.try_into();
            match lsm_res {
                Ok(lsm) => {
                    let btf = aya::Btf::from_sys_fs().ok();
                    if let Some(b) = btf.as_ref() {
                        if let Err(e) = lsm.load("bprm_check_security", b) {
                            warn!("innerwarden_lsm_exec_min: failed to load: {:?}", e);
                        } else if let Err(e) = lsm.attach() {
                            warn!(error = %e, "innerwarden_lsm_exec_min: failed to attach");
                        } else {
                            info!("eBPF: innerwarden_lsm_exec_min → bprm_check_security (Spec 052 Phase 1) ✅");
                        }
                    } else {
                        info!("innerwarden_lsm_exec_min: BTF not available; skipping");
                    }
                }
                Err(e) => {
                    info!(error = %e, "innerwarden_lsm_exec_min: not available as Lsm");
                }
            }
        }
        None => {
            info!("innerwarden_lsm_exec_min program not found in .o (sensor built without Spec 052 Phase 1?)");
        }
    }

    // Execution Gate (Active Defence) — dedicated minimal LSM on bprm_check_security.
    // Attaches alongside _min; inert unless LSM_POLICY key 3 = 1 (license-gated arm).
    // Lives in its own program because the full innerwarden_lsm_exec fails the
    // verifier on kernel ≥ 6.4, so a gate buried there never runs.
    match bpf.program_mut("innerwarden_lsm_exec_gate") {
        Some(prog) => {
            let lsm_res: Result<&mut Lsm, _> = prog.try_into();
            match lsm_res {
                Ok(lsm) => {
                    let btf = aya::Btf::from_sys_fs().ok();
                    if let Some(b) = btf.as_ref() {
                        if let Err(e) = lsm.load("bprm_check_security", b) {
                            warn!("innerwarden_lsm_exec_gate: failed to load: {:?}", e);
                        } else if let Err(e) = lsm.attach() {
                            warn!(error = %e, "innerwarden_lsm_exec_gate: failed to attach");
                        } else {
                            info!("eBPF: innerwarden_lsm_exec_gate → bprm_check_security (Execution Gate) ✅");
                        }
                    } else {
                        info!("innerwarden_lsm_exec_gate: BTF not available; skipping");
                    }
                }
                Err(e) => info!(error = %e, "innerwarden_lsm_exec_gate: not available as Lsm"),
            }
        }
        None => {
            info!("innerwarden_lsm_exec_gate program not found in .o");
        }
    }

    // PR-A: create_user_ns LSM hook — container escape detection.
    // Defaults to observe; blocks only when caller PID is in BLOCKED_PIDS
    // (populated by agent's kill chain detector). Safe to enable in prod
    // because legitimate userns creators (Chrome, podman, snap, Docker
    // rootless) are never in BLOCKED_PIDS so they pass through unaffected.
    match bpf.program_mut("innerwarden_lsm_create_user_ns") {
        Some(prog) => {
            let lsm_res: Result<&mut Lsm, _> = prog.try_into();
            match lsm_res {
                Ok(lsm) => {
                    let btf = aya::Btf::from_sys_fs().ok();
                    if let Some(b) = btf.as_ref() {
                        if let Err(e) = lsm.load("userns_create", b) {
                            warn!("innerwarden_lsm_create_user_ns: failed to load: {:?}", e);
                        } else if let Err(e) = lsm.attach() {
                            warn!(error = %e, "innerwarden_lsm_create_user_ns: failed to attach");
                        } else {
                            info!("eBPF: innerwarden_lsm_create_user_ns → create_user_ns (PR-A container escape) ✅");
                        }
                    }
                }
                Err(e) => info!(error = %e, "innerwarden_lsm_create_user_ns: not available as Lsm"),
            }
        }
        None => {
            info!("innerwarden_lsm_create_user_ns program not found in .o");
        }
    }

    // PR-B: ptrace_access_check LSM hook — process injection block.
    // Observe by default; blocks only when caller PID is in BLOCKED_PIDS.
    match bpf.program_mut("innerwarden_lsm_ptrace_access") {
        Some(prog) => {
            let lsm_res: Result<&mut Lsm, _> = prog.try_into();
            match lsm_res {
                Ok(lsm) => {
                    let btf = aya::Btf::from_sys_fs().ok();
                    if let Some(b) = btf.as_ref() {
                        if let Err(e) = lsm.load("ptrace_access_check", b) {
                            warn!("innerwarden_lsm_ptrace_access: failed to load: {:?}", e);
                        } else if let Err(e) = lsm.attach() {
                            warn!(error = %e, "innerwarden_lsm_ptrace_access: failed to attach");
                        } else {
                            info!("eBPF: innerwarden_lsm_ptrace_access → ptrace_access_check (PR-B process injection block) ✅");
                        }
                    }
                }
                Err(e) => info!(error = %e, "innerwarden_lsm_ptrace_access: not available as Lsm"),
            }
        }
        None => {
            info!("innerwarden_lsm_ptrace_access program not found in .o");
        }
    }

    // PR-C: bpf_prog LSM hook — VoidLink-style eBPF weaponization block.
    // Observe by default; blocks only when caller PID is in BLOCKED_PIDS.
    match bpf.program_mut("innerwarden_lsm_bpf_prog_load") {
        Some(prog) => {
            let lsm_res: Result<&mut Lsm, _> = prog.try_into();
            match lsm_res {
                Ok(lsm) => {
                    let btf = aya::Btf::from_sys_fs().ok();
                    if let Some(b) = btf.as_ref() {
                        if let Err(e) = lsm.load("bpf_prog", b) {
                            warn!("innerwarden_lsm_bpf_prog_load: failed to load: {:?}", e);
                        } else if let Err(e) = lsm.attach() {
                            warn!(error = %e, "innerwarden_lsm_bpf_prog_load: failed to attach");
                        } else {
                            info!("eBPF: innerwarden_lsm_bpf_prog_load → bpf_prog (PR-C eBPF weaponization block) ✅");
                        }
                    }
                }
                Err(e) => info!(error = %e, "innerwarden_lsm_bpf_prog_load: not available as Lsm"),
            }
        }
        None => {
            info!("innerwarden_lsm_bpf_prog_load program not found in .o");
        }
    }

    // PR-D: mmap_file LSM hook — real-time RWX block from chain-flagged PIDs.
    // Observe by default; blocks only when caller PID is in BLOCKED_PIDS.
    match bpf.program_mut("innerwarden_lsm_mmap_file") {
        Some(prog) => {
            let lsm_res: Result<&mut Lsm, _> = prog.try_into();
            match lsm_res {
                Ok(lsm) => {
                    let btf = aya::Btf::from_sys_fs().ok();
                    if let Some(b) = btf.as_ref() {
                        if let Err(e) = lsm.load("mmap_file", b) {
                            warn!("innerwarden_lsm_mmap_file: failed to load: {:?}", e);
                        } else if let Err(e) = lsm.attach() {
                            warn!(error = %e, "innerwarden_lsm_mmap_file: failed to attach");
                        } else {
                            info!("eBPF: innerwarden_lsm_mmap_file → mmap_file (PR-D real-time RWX block) ✅");
                        }
                    }
                }
                Err(e) => info!(error = %e, "innerwarden_lsm_mmap_file: not available as Lsm"),
            }
        }
        None => {
            info!("innerwarden_lsm_mmap_file program not found in .o");
        }
    }

    match bpf.program_mut("innerwarden_lsm_exec") {
        Some(prog) => {
            let lsm_try: Result<&mut Lsm, _> = prog.try_into();
            match lsm_try {
                Ok(lsm) => {
                    let btf = aya::Btf::from_sys_fs().ok();
                    if let Some(b) = btf.as_ref() {
                        if let Err(e) = lsm.load("bprm_check_security", b) {
                            // 2026-05-22: this is the legacy 600-LOC hook that
                            // never loads on kernel ≥ 6.4 (verifier complexity).
                            // Spec 052 supersedes it via innerwarden_lsm_exec_min
                            // (loaded above). Logging kept for one release cycle
                            // for diff visibility; Phase 3 retires this block.
                            info!(
                                "innerwarden_lsm_exec: failed to load (expected on kernel ≥ 6.4, superseded by Spec 052): {:?}",
                                e
                            );
                        } else if let Err(e) = lsm.attach() {
                            warn!(error = %e, "innerwarden_lsm_exec: failed to attach");
                        } else {
                            info!(
                                "eBPF: innerwarden_lsm_exec → bprm_check_security (legacy hook) ✅"
                            );
                        }
                    }
                }
                Err(e) => {
                    info!(error = %e, "innerwarden_lsm_exec: not available (kernel may lack lsm=bpf)");
                }
            }
        }
        None => {
            info!("eBPF: innerwarden_lsm_exec program not found");
        }
    }

    // Attach LSM file_open hook for sensitive path write protection.
    // Non-critical — if it fails, we still have observe-only via the openat tracepoint.
    match bpf.program_mut("innerwarden_lsm_file_open") {
        Some(prog) => {
            let lsm_try: Result<&mut Lsm, _> = prog.try_into();
            match lsm_try {
                Ok(lsm) => {
                    let btf = aya::Btf::from_sys_fs().ok();
                    if let Some(b) = btf.as_ref() {
                        if let Err(e) = lsm.load("file_open", b) {
                            info!(error = %e, "innerwarden_lsm_file_open: failed to load");
                        } else if let Err(e) = lsm.attach() {
                            warn!(error = %e, "innerwarden_lsm_file_open: failed to attach");
                        } else {
                            info!("eBPF: innerwarden_lsm_file_open → file_open (sensitive path protection) ✅");
                        }
                    }
                }
                Err(e) => {
                    info!(error = %e, "innerwarden_lsm_file_open: not available");
                }
            }
        }
        None => {
            info!(
                "eBPF: innerwarden_lsm_file_open not found — sensitive path blocking unavailable"
            );
        }
    }

    // Phase 2: LSM bpf hook — monitor eBPF program loading (VoidLink defense)
    match bpf.program_mut("innerwarden_lsm_bpf") {
        Some(prog) => {
            let lsm: &mut aya::programs::Lsm = match prog.try_into() {
                Ok(l) => l,
                Err(e) => {
                    info!(error = %e, "innerwarden_lsm_bpf: not available");
                    pin_lsm_policy(bpf);
                    return;
                }
            };
            let btf = aya::Btf::from_sys_fs().ok();
            if let Err(e) = lsm.load("bpf", btf.as_ref().unwrap()) {
                info!(error = %e, "innerwarden_lsm_bpf: failed to load");
            } else if let Err(e) = lsm.attach() {
                warn!(error = %e, "innerwarden_lsm_bpf: failed to attach");
            } else {
                info!("eBPF: innerwarden_lsm_bpf → bpf (eBPF program loading) ✅");
            }
        }
        None => {
            info!("eBPF: innerwarden_lsm_bpf not found — BPF load monitoring unavailable");
        }
    }

    pin_lsm_policy(bpf);
}

/// Re-pin a PERSISTENT map across a sensor restart WITHOUT losing its entries.
///
/// Spec 080 P0: the old code did `remove_file(pin)` then `map.pin(pin)` for the
/// persistent maps. The remove-first avoids `EEXIST` (the previous instance's
/// pin still references a live map), but it makes the fresh empty map the pinned
/// one and DROPS every entry — fatal for `EXEC_ALLOWLIST` (the Execution Gate
/// allowlist the active-defence reconciler writes incrementally and never
/// re-applies) and `LSM_POLICY` (which holds the arm bit). A sensor restart
/// (e.g. a deploy) silently zeroed the live allowlist on prod.
///
/// Here we read the old pinned map's `(key, value)` pairs first, re-pin the
/// fresh map, then write the saved pairs back, so the allowlist + policy survive
/// a restart. Fail-open throughout (the sensor must never crash); a fresh box
/// with no prior pin just restores nothing.
#[cfg(feature = "ebpf")]
fn repin_preserving<K, V>(bpf: &mut aya::Ebpf, name: &str, pin: &str)
where
    K: aya::Pod,
    V: aya::Pod,
{
    let saved: Vec<(K, V)> = if std::path::Path::new(pin).exists() {
        aya::maps::MapData::from_pin(pin)
            .ok()
            .and_then(|md| {
                // aya's typed HashMap is built from a `Map`, not a raw
                // `MapData`; wrap the pinned data in the HashMap variant.
                let map = aya::maps::Map::HashMap(md);
                aya::maps::HashMap::<_, K, V>::try_from(&map)
                    .ok()
                    .map(|old| old.iter().filter_map(Result::ok).collect())
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let Some(map) = bpf.map_mut(name) else {
        return;
    };
    let _ = std::fs::remove_file(pin);
    if let Err(e) = map.pin(pin) {
        warn!(error = %e, "{name}: failed to pin");
        return;
    }
    info!("eBPF: {name} pinned at {pin}");

    if saved.is_empty() {
        return;
    }
    if let Some(map) = bpf.map_mut(name) {
        if let Ok(mut hm) = aya::maps::HashMap::<_, K, V>::try_from(map) {
            let n = saved.len();
            for (k, v) in &saved {
                let _ = hm.insert(k, v, 0);
            }
            info!("eBPF: {name}: restored {n} entries across sensor restart");
        }
    }
}

#[cfg(feature = "ebpf")]
fn pin_lsm_policy(bpf: &mut aya::Ebpf) {
    // Pin the LSM_POLICY map so the agent can enable/disable enforcement.
    // Spec 080 P0: preserve entries across restart — LSM_POLICY holds the
    // exec-gate arm bit (key 3); EXEC_ALLOWLIST holds the signed allowlist.
    repin_preserving::<u32, u32>(bpf, "LSM_POLICY", LSM_POLICY_PIN);
    info!("eBPF: LSM enforcement is OFF by default - enable via: bpftool map update pinned {LSM_POLICY_PIN} key 0 0 0 0 value 1 0 0 0");

    // Execution Gate allowlist — MUST survive restart (active-defence writes it
    // incrementally and does not re-apply; a wipe = empty allowlist = brick on
    // arm). u64 FNV(path) keys, u8 value.
    repin_preserving::<u64, u8>(bpf, "EXEC_ALLOWLIST", EXEC_ALLOWLIST_PIN);

    // Execution Gate SCOPE (cgroup id -> 1) — agent-scoped enforcement (spec 083).
    // Preserve across restart like the allowlist so the agent stays scoped; a
    // wipe is fail-open (empty scope = gate never fires) so it is not a brick.
    repin_preserving::<u64, u8>(bpf, "EXEC_GATE_SCOPE", EXEC_GATE_SCOPE_PIN);

    // Execution Gate trusted DIRECTORY-PREFIX map (managed-installer trust for
    // host-wide enforce). Preserve across restart like the allowlist; empty +
    // armed = no prefix trusted = fail-open, so a wipe is safe.
    repin_preserving::<u64, u8>(bpf, "EXEC_TRUSTED_PREFIX", EXEC_TRUSTED_PREFIX_PIN);

    // Capability + blocked-pid maps. These have the same restart-wipe behaviour
    // (TODO spec 080 P0 follow-up: BLOCKED_PIDS is an LRU map + the capability
    // maps use different value types; the agent re-registers BLOCKED_PIDS today,
    // so they are lower-priority than the Execution Gate pair above).
    for (map_name, pin_path) in [
        ("CGROUP_CAPABILITIES", CGROUP_CAP_PIN),
        ("COMM_CAPABILITIES", COMM_CAP_PIN),
        ("BLOCKED_PIDS", BLOCKED_PIDS_PIN),
    ] {
        if let Some(map) = bpf.map_mut(map_name) {
            let _ = std::fs::remove_file(pin_path);
            if let Err(e) = map.pin(pin_path) {
                warn!(error = %e, "{map_name}: failed to pin");
            } else {
                info!("eBPF: {map_name} pinned at {pin_path}");
            }
        }
    }

    // Populate INODE_SIZE map for overlayfs drift detection.
    // sizeof(struct inode) varies by kernel config; query BTF at runtime.
    populate_inode_size(bpf);

    // Populate BPRM_OFFSETS (linux_binprm.filename byte offset) from BTF so the
    // Execution Gate reads the right field across kernels (CO-RE).
    populate_bprm_offset(bpf);

    // Populate TASK_OFFSETS (task_struct.real_parent + .tgid byte offsets) from
    // BTF so the execve handler can read the real parent PID in-kernel for
    // short-lived execs (the /proc fallback misses those).
    populate_task_offsets(bpf);
}

/// Query the `linux_binprm.filename` byte offset from kernel BTF and write it to
/// the BPRM_OFFSETS map (key 0). The Execution Gate eBPF reads it so it works
/// across kernels (the offset differs: 96 on 6.8). Falls back to the eBPF default
/// (96) if BTF is unavailable.
#[cfg(feature = "ebpf")]
fn populate_bprm_offset(bpf: &mut aya::Ebpf) {
    use aya::maps::HashMap as BpfHashMap;

    let off = match std::fs::read("/sys/kernel/btf/vmlinux") {
        Ok(btf) => crate::btf_offsets::member_offset(&btf, "linux_binprm", "filename"),
        Err(e) => {
            info!(error = %e, "BPRM_OFFSETS: no kernel BTF — Execution Gate uses default offset 96");
            None
        }
    };
    let Some(off) = off else {
        info!("BPRM_OFFSETS: linux_binprm.filename not in BTF — Execution Gate uses default 96");
        return;
    };
    if let Some(map) = bpf.map_mut("BPRM_OFFSETS") {
        let mut hash: BpfHashMap<_, u32, u32> = match map.try_into() {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %e, "BPRM_OFFSETS: map type mismatch");
                return;
            }
        };
        if let Err(e) = hash.insert(0u32, off, 0) {
            warn!(error = %e, "BPRM_OFFSETS: failed to write filename offset");
        } else {
            info!("eBPF: BPRM_OFFSETS linux_binprm.filename offset = {off} (from BTF)");
        }
    }
}

/// Query `task_struct.real_parent` + `.tgid` byte offsets from kernel BTF and
/// write them to the TASK_OFFSETS map (key 0 = real_parent, key 1 = tgid). The
/// execve eBPF handler reads them to capture the real parent PID in-kernel for
/// short-lived execs (e.g. systemd's sealed-executor `fexecve`) whose
/// `/proc/<pid>/status` is gone before the userspace ring reader can read it —
/// without this their `ppid` stays 0. If BTF is unavailable or the members are
/// absent, the map stays empty and the handler leaves `ppid = 0` (the userspace
/// `/proc` fallback applies — unchanged behaviour, never a guessed offset).
#[cfg(feature = "ebpf")]
fn populate_task_offsets(bpf: &mut aya::Ebpf) {
    use aya::maps::HashMap as BpfHashMap;

    let btf = match std::fs::read("/sys/kernel/btf/vmlinux") {
        Ok(b) => b,
        Err(e) => {
            info!(error = %e, "TASK_OFFSETS: no kernel BTF — execve ppid uses /proc fallback");
            return;
        }
    };
    let real_parent = crate::btf_offsets::member_offset(&btf, "task_struct", "real_parent");
    let tgid = crate::btf_offsets::member_offset(&btf, "task_struct", "tgid");
    let (Some(real_parent), Some(tgid)) = (real_parent, tgid) else {
        info!("TASK_OFFSETS: task_struct.real_parent/tgid not in BTF — execve ppid uses /proc fallback");
        return;
    };
    if let Some(map) = bpf.map_mut("TASK_OFFSETS") {
        let mut hash: BpfHashMap<_, u32, u32> = match map.try_into() {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %e, "TASK_OFFSETS: map type mismatch");
                return;
            }
        };
        let ok0 = hash.insert(0u32, real_parent, 0);
        let ok1 = hash.insert(1u32, tgid, 0);
        if ok0.is_err() || ok1.is_err() {
            warn!("TASK_OFFSETS: failed to write task_struct offsets");
        } else {
            info!(
                "eBPF: TASK_OFFSETS task_struct.real_parent={real_parent} tgid={tgid} (from BTF)"
            );
        }
    }
}

/// Query sizeof(struct inode) from kernel BTF and write it to the INODE_SIZE map.
/// This enables the eBPF overlay drift detector to find ovl_inode.__upperdentry
/// at (inode_ptr + sizeof(struct inode)) without needing BTF for the private ovl_inode.
#[cfg(feature = "ebpf")]
fn populate_inode_size(bpf: &mut aya::Ebpf) {
    use aya::maps::HashMap as BpfHashMap;

    // Try to get sizeof(struct inode) from BTF via bpftool
    let inode_size = match std::process::Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
    {
        Ok(output) if output.status.success() => {
            let btf_dump = String::from_utf8_lossy(&output.stdout);
            // Parse: look for "struct inode {" and count to closing "}"
            // This is heuristic — production should use proper BTF parsing.
            // Fallback: use bpftool to query the size directly.
            None.or_else(|| {
                // Try bpftool btf dump id 1 to get struct sizes
                let size_output = std::process::Command::new("bpftool")
                    .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux"])
                    .output()
                    .ok()?;
                let text = String::from_utf8_lossy(&size_output.stdout);
                // Look for: [NNN] STRUCT 'inode' size=XXX
                for line in text.lines() {
                    if line.contains("STRUCT 'inode'") && line.contains("size=") {
                        if let Some(size_str) = line.split("size=").nth(1) {
                            let size_str = size_str.split_whitespace().next().unwrap_or("0");
                            if let Ok(size) = size_str.parse::<u64>() {
                                if size > 100 && size < 2000 {
                                    return Some(size);
                                }
                            }
                        }
                    }
                }
                None
            })
            .unwrap_or_else(|| {
                // If BTF dump doesn't contain it, try the raw text from format c
                // and look for "} __attribute__((preserve_access_index));"
                // after "struct inode {"
                drop(btf_dump);
                0
            })
        }
        _ => 0,
    };

    if inode_size == 0 {
        info!("eBPF: could not determine sizeof(struct inode) from BTF — container drift detection disabled");
        info!("eBPF: ensure bpftool is installed and /sys/kernel/btf/vmlinux exists");
        return;
    }

    if let Some(map) = bpf.map_mut("INODE_SIZE") {
        let mut hash: BpfHashMap<_, u32, u64> = match map.try_into() {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %e, "INODE_SIZE map: wrong type");
                return;
            }
        };
        if let Err(e) = hash.insert(0u32, inode_size, 0) {
            warn!(error = %e, "INODE_SIZE map: failed to insert");
        } else {
            info!(
                inode_size,
                "eBPF: container drift detection enabled (sizeof(struct inode) = {inode_size})"
            );
        }
    }
}

#[cfg(not(feature = "ebpf"))]
fn attach_lsm(_bpf: &mut ()) {}

/// Attach XDP firewall program and pin the blocklist map.
/// Non-critical - if it fails, the sensor continues without XDP.
#[cfg(feature = "ebpf")]
fn attach_xdp(bpf: &mut aya::Ebpf) {
    use aya::programs::{Xdp, XdpMode};

    let iface = match detect_default_interface() {
        Some(i) => i,
        None => {
            warn!("XDP: no default network interface found - skipping XDP firewall");
            return;
        }
    };

    match bpf.program_mut("innerwarden_xdp") {
        Some(prog) => {
            let xdp: &mut Xdp = match prog.try_into() {
                Ok(x) => x,
                Err(e) => {
                    warn!(error = %e, "innerwarden_xdp: not an XDP program");
                    return;
                }
            };
            if let Err(e) = xdp.load() {
                warn!(error = %e, "innerwarden_xdp: failed to load");
                return;
            }
            // Use SKB mode (generic) for maximum compatibility.
            // Native mode (XdpMode::Driver) is faster but requires driver support.
            //
            // 2026-05-08: do NOT early-return on attach failure. The most
            // common cause is `EBUSY` because the previous sensor instance
            // left an XDP link attached to the same interface (kernel-level
            // attachments survive the userspace process exit). Pre-fix, the
            // sensor would warn + return without pinning the BLOCKLIST /
            // ALLOWLIST maps — leaving the agent unable to push blocks even
            // though the in-kernel XDP program from the previous lifetime
            // was still happily dropping packets. That meant a restart of
            // the sensor (e.g. from `systemctl restart`) actively REMOVED
            // wire-speed blocking until the operator manually detached the
            // stale link with `bpftool link detach`. By falling through to
            // the pin step we keep the previous-instance program functional
            // (the maps it references can still be updated by the agent)
            // until either the kernel reaps the orphaned link or the
            // operator triggers a clean detach + re-attach cycle.
            let attach_outcome = xdp.attach(&iface, XdpMode::Skb);
            match &attach_outcome {
                Ok(_) => {
                    info!(iface = %iface, "eBPF: innerwarden_xdp → {iface} (XDP firewall) ✅");
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        iface = %iface,
                        "innerwarden_xdp: failed to attach (likely EBUSY — \
                         previous sensor lifetime's XDP link is still active \
                         on this interface). Continuing to pin maps so the \
                         agent can push blocks via the existing in-kernel \
                         program. To trigger a clean re-attach: \
                         `sudo bpftool link list` to find the xdp link id, \
                         then `sudo bpftool link detach id <ID>` and restart \
                         the sensor."
                    );
                    // Fall through — pin the maps anyway so the agent's
                    // bpftool path still finds them.
                }
            }
        }
        None => {
            info!("eBPF: innerwarden_xdp program not found - XDP firewall not available");
            return;
        }
    }

    // Pin the BLOCKLIST map so the agent can access it via bpftool.
    // The pin directory is created earlier in `run_collector` via
    // `ensure_bpf_pin_dir`; we no longer recreate it here.
    if let Some(map) = bpf.map_mut("BLOCKLIST") {
        let _ = std::fs::remove_file(XDP_BLOCKLIST_PIN);
        if let Err(e) = map.pin(XDP_BLOCKLIST_PIN) {
            warn!(error = %e, "XDP: failed to pin blocklist map");
        } else {
            info!("eBPF: XDP blocklist pinned at {XDP_BLOCKLIST_PIN}");
        }
    }

    // Pin the ALLOWLIST map for operator-managed never-drop IPs
    if let Some(map) = bpf.map_mut("ALLOWLIST") {
        let _ = std::fs::remove_file(XDP_ALLOWLIST_PIN);
        if let Err(e) = map.pin(XDP_ALLOWLIST_PIN) {
            warn!(error = %e, "XDP: failed to pin allowlist map");
        } else {
            info!("eBPF: XDP allowlist pinned at {XDP_ALLOWLIST_PIN}");
        }
    }
}

#[cfg(not(feature = "ebpf"))]
fn attach_xdp(_bpf: &mut ()) {}

// ---------------------------------------------------------------------------
// Kernel filter population - shared runtime allowlists
// ---------------------------------------------------------------------------
//
// Handler bitmask for COMM_ALLOWLIST:
//   bit 0 = execve, 1 = connect, 2 = openat, 3 = ptrace,
//   4 = setuid, 5 = bind, 6 = mount, 7 = memfd, 8 = init_module
//
// Sources: curated runtime security allowlists adapted for InnerWarden.

#[cfg(feature = "ebpf")]
fn populate_kernel_filters(bpf: &mut aya::Ebpf) {
    use aya::maps::HashMap;

    // --- COMM_ALLOWLIST: safe processes per handler ---
    if let Ok(mut map) =
        HashMap::<_, [u8; 16], u32>::try_from(bpf.map_mut("COMM_ALLOWLIST").unwrap())
    {
        // Helper: create 16-byte key from comm name
        let key = |name: &str| -> [u8; 16] {
            let mut k = [0u8; 16];
            let bytes = name.as_bytes();
            k[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
            k
        };

        const EXECVE: u32 = 1 << 0;
        const CONNECT: u32 = 1 << 1;
        const OPENAT: u32 = 1 << 2;
        const PTRACE: u32 = 1 << 3;
        const SETUID: u32 = 1 << 4;
        const BIND: u32 = 1 << 5;
        // bit 6 = mount (never allowlisted)
        // bit 7 = memfd
        // bit 8 = init_module (never allowlisted)

        // Package managers - noisy on execve, openat, connect
        for comm in [
            "apt", "apt-get", "dpkg", "dnf", "yum", "rpm", "snap", "apk", "pip", "pip3", "conda",
            "npm", "gem",
        ] {
            let _ = map.insert(key(comm), EXECVE | OPENAT | CONNECT, 0);
        }

        // Build tools - noisy on execve, openat
        for comm in [
            "cargo", "rustc", "gcc", "g++", "cc1", "cc1plus", "clang", "ld", "ar", "make", "cmake",
            "ninja", "javac", "go",
        ] {
            let _ = map.insert(key(comm), EXECVE | OPENAT, 0);
        }

        // Coreutils - noisy on openat, execve (spawned constantly by scripts)
        for comm in [
            "cat", "ls", "cp", "mv", "rm", "mkdir", "chmod", "chown", "ln", "head", "tail", "wc",
            "sort", "cut", "tr", "sed", "awk", "grep", "find", "xargs", "tee", "touch", "date",
            "sleep", "true", "false", "echo", "env", "pwd", "id", "whoami", "basename", "dirname",
            "readlink", "stat", "test", "seq", "yes", "dd", "df", "du", "uname", "mktemp",
        ] {
            let _ = map.insert(key(comm), EXECVE | OPENAT, 0);
        }

        // System daemons - allowed on setuid, connect, openat, bind
        for comm in [
            "systemd",
            "systemd-logind",
            "systemd-resolve",
            "systemd-timesyn",
            "systemd-network",
        ] {
            let _ = map.insert(key(comm), SETUID | CONNECT | OPENAT | BIND, 0);
        }

        // SSH daemons - allowed on setuid (legitimate priv change), bind
        for comm in ["sshd", "sshd-session"] {
            let _ = map.insert(key(comm), SETUID | BIND, 0);
        }

        // Auth/login - allowed on setuid
        for comm in [
            "sudo",
            "su",
            "login",
            "cron",
            "crond",
            "polkitd",
            "dbus-daemon",
        ] {
            let _ = map.insert(key(comm), SETUID, 0);
        }

        // Web/DB servers - allowed on bind (they legitimately bind ports)
        for comm in [
            "nginx",
            "apache2",
            "httpd",
            "redis-server",
            "mysqld",
            "postgres",
            "mongod",
            "memcached",
        ] {
            let _ = map.insert(key(comm), BIND, 0);
        }

        // Container runtimes - allowed on bind, connect, openat
        for comm in [
            "dockerd",
            "containerd",
            "containerd-shim",
            "runc",
            "crio",
            "podman",
        ] {
            let _ = map.insert(key(comm), BIND | CONNECT | OPENAT, 0);
        }

        // Debuggers - allowed on ptrace (their whole purpose)
        for comm in ["gdb", "strace", "ltrace", "lldb", "perf", "valgrind"] {
            let _ = map.insert(key(comm), PTRACE, 0);
        }

        // Monitoring agents - noisy on openat, connect
        for comm in [
            "prometheus",
            "node_exporter",
            "grafana",
            "telegraf",
            "collectd",
            "fluentd",
            "filebeat",
        ] {
            let _ = map.insert(key(comm), OPENAT | CONNECT, 0);
        }

        // Log rotation / coreutils - allowed on unlink, rename
        const UNLINK: u32 = 1 << 13;
        const RENAME: u32 = 1 << 14;
        for comm in ["logrotate", "journald", "rsyslogd", "systemd-journal"] {
            let _ = map.insert(key(comm), UNLINK | RENAME | OPENAT, 0);
        }

        // JIT runtimes - allowed on mprotect (they make memory executable legitimately)
        const MPROTECT: u32 = 1 << 11;
        for comm in [
            "node", "python3", "python", "java", "ruby", "php", "dotnet", "mono", "v8", "wasmtime",
        ] {
            let _ = map.insert(key(comm), MPROTECT, 0);
        }

        // Container runtimes - also allowed on clone, dup, listen, accept
        const DUP: u32 = 1 << 9;
        const LISTEN: u32 = 1 << 10;
        const CLONE: u32 = 1 << 12;
        const ACCEPT: u32 = 1 << 17;
        for comm in [
            "dockerd",
            "containerd",
            "containerd-shim",
            "runc",
            "crio",
            "podman",
        ] {
            let _ = map.insert(
                key(comm),
                BIND | CONNECT | OPENAT | CLONE | DUP | LISTEN | ACCEPT,
                0,
            );
        }

        // Shells - allowed on dup, clone (normal shell behavior)
        for comm in ["bash", "sh", "zsh", "dash", "ash", "fish", "tcsh", "ksh"] {
            let _ = map.insert(key(comm), DUP | CLONE, 0);
        }

        // Inner Warden itself - skip everything except mount + init_module
        let all_but_critical = EXECVE
            | CONNECT
            | OPENAT
            | PTRACE
            | SETUID
            | BIND
            | DUP
            | LISTEN
            | MPROTECT
            | CLONE
            | UNLINK
            | RENAME
            | ACCEPT;
        for comm in [
            "innerwarden-sen",
            "innerwarden-age",
            "innerwarden-dna",
            "innerwarden-shi",
        ] {
            let _ = map.insert(key(comm), all_but_critical, 0);
        }

        let count = map.keys().count();
        tracing::info!(count, "eBPF: COMM_ALLOWLIST populated");
    } else {
        tracing::warn!("eBPF: COMM_ALLOWLIST map not found - kernel filters disabled");
    }
}

// ---------------------------------------------------------------------------
// InnerWarden self-suppression (keep our OWN syscalls out of the ring buffer)
// ---------------------------------------------------------------------------
//
// The sensor, agent, watchdog and supervisor are heavy multi-threaded tokio
// programs. Their worker threads run under comm="tokio-rt-worker", which the
// comm-keyed COMM_ALLOWLIST cannot match (it only sees the process comm, e.g.
// "innerwarden-age"). On a busy node — observed on a real k3s cloud box where
// the agent's tokio threads were 75% of the captured eBPF stream — InnerWarden's
// own syscalls flood the ring buffer and starve the real host + container signal
// (events dropped at RingBuf::reserve before they are ever processed). The
// userspace `comm.starts_with("innerwarden")` filter runs AFTER reserve, so it
// cannot save the ring slot.
//
// Fix: suppress IN-KERNEL by CGROUP. All of a process's threads share one
// cgroup, so a single id covers every tokio worker. We seed CGROUP_ALLOWLIST
// (value 1 = skip non-critical events; the in-kernel `is_cgroup_allowed()` gate
// already consults it, while genuine critical paths — credential reads, IMDS,
// the kill-chain — still emit) with InnerWarden's own cgroups and refresh on a
// timer so a service restart (which lands in a fresh cgroup) is followed.
//
// Identity is NON-FORGEABLE: a process is "InnerWarden" only when /proc/<pid>/exe
// resolves to an `innerwarden-*` binary in the sensor's own install directory.
// We deliberately do NOT trust comm (an attacker could set comm=innerwarden-x to
// get its own cgroup suppressed and go invisible).

/// Parse the cgroup-v2 relative path from `/proc/<pid>/cgroup` contents.
/// v2 is a single `0::<path>` line. Returns the `<path>` (leading slash kept).
#[allow(dead_code)]
fn parse_cgroup_v2_rel_path(content: &str) -> Option<&str> {
    content.lines().find_map(|l| l.strip_prefix("0::"))
}

/// True when `exe` is one of InnerWarden's own binaries — `innerwarden-*` living
/// in `install_dir` (the sensor's own binary directory). Non-forgeable: keyed on
/// the real binary behind `/proc/<pid>/exe`, never on comm.
#[allow(dead_code)]
fn is_innerwarden_exe(exe: &std::path::Path, install_dir: &std::path::Path) -> bool {
    exe.parent() == Some(install_dir)
        && exe
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("innerwarden-"))
}

/// Compute the (to_add, to_remove) delta for the self-cgroup allowlist: add ids
/// newly seen, remove ids we previously added that are gone (e.g. a restarted
/// service's stale cgroup). Pure set algebra so it is unit-testable.
#[allow(dead_code)]
fn cgroup_allowlist_delta(
    current: &std::collections::BTreeSet<u64>,
    previously_added: &std::collections::BTreeSet<u64>,
) -> (Vec<u64>, Vec<u64>) {
    let to_add = current.difference(previously_added).copied().collect();
    let to_remove = previously_added.difference(current).copied().collect();
    (to_add, to_remove)
}

/// Build the absolute cgroup-v2 directory path for a process from the contents
/// of its `/proc/<pid>/cgroup` file: `<unified-mount>/<rel>`. Pure (no I/O) so
/// the path-join logic is unit-testable independent of the host; the inode stat
/// lives in `cgroup_id_of_pid`. `None` on cgroup v1 (no `0::` line).
#[allow(dead_code)]
fn cgroup_dir_path(cgroup_file: &str) -> Option<std::path::PathBuf> {
    let rel = parse_cgroup_v2_rel_path(cgroup_file)?;
    Some(std::path::Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// Resolve the cgroup-v2 id of a pid: the inode of its cgroup directory under
/// `/sys/fs/cgroup`, which is exactly what `bpf_get_current_cgroup_id()` returns
/// for tasks in that cgroup. `None` if the process is gone or on cgroup v1.
/// Thin I/O wrapper over the pure `cgroup_dir_path`; `allow(dead_code)` keeps the
/// non-`ebpf` build (which still compiles the pure helpers + their tests) clean.
#[cfg(unix)]
#[allow(dead_code)]
fn cgroup_id_of_pid(pid: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let abs = cgroup_dir_path(&content)?;
    std::fs::metadata(abs).ok().map(|m| m.ino())
}

// cgroup ids are a Linux/proc concept. On Windows (spec 085 Phase 0) return
// None; the eBPF run() that consumes this is Linux-only and feature-gated.
#[cfg(not(unix))]
#[allow(dead_code)]
fn cgroup_id_of_pid(_pid: &str) -> Option<u64> {
    None
}

/// Pure core of the self-cgroup scan: given `(exe, cgroup_id)` for each running
/// process, keep only the cgroup ids whose exe is one of InnerWarden's own
/// binaries in `install_dir`. No `/proc` I/O, so the non-forgeable exe filter
/// (the no-regression invariant — a `/tmp/innerwarden-evil` or a plain `bash` is
/// never selected) is unit-testable independent of the host. A `None` id (cgroup
/// gone / v1) drops the entry.
#[allow(dead_code)]
fn select_self_cgroups<'a, I>(
    procs: I,
    install_dir: &std::path::Path,
) -> std::collections::BTreeSet<u64>
where
    I: IntoIterator<Item = (&'a std::path::Path, Option<u64>)>,
{
    procs
        .into_iter()
        .filter(|(exe, _)| is_innerwarden_exe(exe, install_dir))
        .filter_map(|(_, id)| id)
        .collect()
}

/// Cgroup ids of every running InnerWarden process — the sensor itself plus the
/// agent (whether a systemd service or a watchdog-spawned child), watchdog and
/// supervisor — identified non-forgeably by exe path. One id per process covers
/// all of its threads. Thin I/O wrapper: scans `/proc`, resolves each pid's exe,
/// and defers the keep/drop decision to the pure `select_self_cgroups`. Only
/// stats the cgroup of a pid whose exe already looks like ours (avoids a stat
/// per host pid); `select_self_cgroups` re-validates so the invariant holds
/// regardless. Only called from the feature-gated refresh task.
#[allow(dead_code)]
fn innerwarden_self_cgroup_ids(install_dir: &std::path::Path) -> std::collections::BTreeSet<u64> {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return std::collections::BTreeSet::new();
    };
    let procs: Vec<(std::path::PathBuf, Option<u64>)> = rd
        .flatten()
        .filter_map(|ent| {
            let fname = ent.file_name();
            let pid = fname.to_str()?;
            if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
            // Only stat the cgroup for our own binaries; the pure core re-checks.
            if !is_innerwarden_exe(&exe, install_dir) {
                return None;
            }
            Some((exe, cgroup_id_of_pid(pid)))
        })
        .collect();
    select_self_cgroups(procs.iter().map(|(e, id)| (e.as_path(), *id)), install_dir)
}

/// Re-resolve InnerWarden's self-cgroups and reconcile the in-kernel
/// CGROUP_ALLOWLIST: add the new ones, drop ones we previously added that have
/// disappeared. Only touches ids it manages, so it never clobbers entries added
/// for other reasons. `value 1` = "skip non-critical events" per the map.
#[cfg(feature = "ebpf")]
fn refresh_self_cgroup_allowlist(
    map: &mut aya::maps::HashMap<aya::maps::MapData, u64, u32>,
    install_dir: &std::path::Path,
    previously_added: &mut std::collections::BTreeSet<u64>,
) -> usize {
    let current = innerwarden_self_cgroup_ids(install_dir);
    let (to_add, to_remove) = cgroup_allowlist_delta(&current, previously_added);
    for id in &to_add {
        let _ = map.insert(id, 1u32, 0);
    }
    for id in &to_remove {
        let _ = map.remove(id);
    }
    *previously_added = current;
    previously_added.len()
}

/// Architecture syscall entry-wrapper symbol for a bare syscall name.
/// On x86_64 the SYSCALL_DEFINE macro generates `__x64_sys_<name>`, on aarch64
/// `__arm64_sys_<name>`. The wrapper takes a single `struct pt_regs *`, from
/// which the eBPF handler reads the real syscall arguments. Evaluated for the
/// build/deploy host arch (the eBPF object is built on the same host).
///
/// Pure string logic (no `aya`), so it is not behind the `ebpf` feature and is
/// unit-testable; `allow(dead_code)` covers the non-`ebpf` build where only the
/// feature-gated `attach_syscall_kprobe` (and tests) call it.
#[allow(dead_code)]
fn syscall_wrapper_symbol(syscall: &str) -> String {
    #[cfg(target_arch = "aarch64")]
    let prefix = "__arm64_sys_";
    #[cfg(not(target_arch = "aarch64"))]
    let prefix = "__x64_sys_";
    format!("{prefix}{syscall}")
}

/// Spec 069: attach a syscall handler as a kprobe on the architecture syscall
/// ENTRY WRAPPER (`__x64_sys_<name>` / `__arm64_sys_<name>`). A kprobe fires
/// ONLY on its target syscall, so it reads the correct pt_regs and does not
/// flood the EVENTS ring buffer the way a `sys_enter` raw_tracepoint did (that
/// fired on every syscall, starving `RingBuf::reserve` so events never
/// surfaced — the spec-069 Phase 2 root cause). Fail-open: a missing program,
/// failed load, or unresolved symbol logs a warning and is skipped, never
/// aborting sensor startup. `syscalls` lists the candidate wrapper names (more
/// than one for syscalls with several entry points, e.g. dup2/dup3); each that
/// resolves is attached to the same program.
#[cfg(feature = "ebpf")]
/// Returns the number of syscall wrappers this program successfully attached to
/// (0 = not monitored). The caller sums these to detect a host-blind sensor.
fn attach_syscall_kprobe(bpf: &mut aya::Ebpf, prog_name: &str, syscalls: &[&str]) -> usize {
    use aya::programs::KProbe;

    let Some(prog) = bpf.program_mut(prog_name) else {
        warn!("{prog_name}: kprobe program not found in bytecode");
        return 0;
    };
    let kp: &mut KProbe = match prog.try_into() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "{prog_name}: not a KProbe program");
            return 0;
        }
    };
    if let Err(e) = kp.load() {
        warn!(error = %e, "{prog_name}: kprobe load (verifier) failed");
        return 0;
    }
    let mut attached = 0usize;
    for sc in syscalls {
        let sym = syscall_wrapper_symbol(sc);
        match kp.attach(sym.as_str(), 0) {
            Ok(_) => {
                info!("eBPF: {prog_name} → {sym} (kprobe) ✅");
                attached += 1;
            }
            Err(e) => warn!(error = %e, "{prog_name}: kprobe attach to {sym} failed"),
        }
    }
    if attached == 0 {
        warn!("{prog_name}: no syscall wrapper symbol resolved - syscall not monitored");
    }
    attached
}

#[cfg(feature = "ebpf")]
fn attach_tp(bpf: &mut aya::Ebpf, name: &str, category: &str, tp_name: &str) -> bool {
    use aya::programs::TracePoint;

    if let Some(prog) = bpf.program_mut(name) {
        if let Ok(tp) = TryInto::<&mut TracePoint>::try_into(prog) {
            if tp.load().is_ok() {
                if let Err(e) = tp.attach(category, tp_name) {
                    warn!(error = %e, "{name}: failed to attach to {category}/{tp_name}");
                } else {
                    info!("eBPF: {name} → {tp_name} ✅");
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(feature = "ebpf")]
pub async fn run(tx: crate::event_channels::EbpfTx, host: String) {
    use aya::maps::RingBuf;
    use aya::programs::TracePoint;
    use std::os::fd::{AsRawFd, FromRawFd};

    // Spec 069 #6: validate the hardcoded pt_regs syscall-arg offsets against
    // the running kernel's BTF and warn loudly on mismatch (a future kernel
    // that reorders pt_regs would otherwise make every arg read garbage
    // silently). Fail-open.
    crate::btf_offsets::verify_pt_regs_offsets();

    if !is_ebpf_available() {
        warn!("eBPF not available - falling back to audit-based collection");
        return;
    }

    // Load eBPF bytecode: prefer embedded (baked into binary), fallback to file on disk.
    #[cfg(feature = "ebpf-embedded")]
    let bytes = {
        info!(
            "eBPF collector: using embedded bytecode ({} bytes)",
            EBPF_BYTECODE_EMBEDDED.len()
        );
        EBPF_BYTECODE_EMBEDDED.to_vec()
    };

    #[cfg(not(feature = "ebpf-embedded"))]
    let bytes = {
        let obj_path = match find_ebpf_obj() {
            Some(p) => p,
            None => {
                warn!("eBPF bytecode not found - skipping eBPF collector");
                return;
            }
        };
        info!(path = %obj_path, "eBPF collector: loading bytecode from file");
        match std::fs::read(&obj_path) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "failed to read eBPF bytecode");
                return;
            }
        }
    };

    // CO-RE loader: use BTF relocations when available for cross-kernel portability
    let btf = aya::Btf::from_sys_fs().ok();
    if btf.is_some() {
        info!("eBPF: BTF available - CO-RE relocations enabled");
    }
    let mut bpf = match aya::EbpfLoader::new().btf(btf.as_ref()).load(&bytes) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to load eBPF programs into kernel (need root or CAP_BPF)");
            return;
        }
    };

    // --- Attach syscall handlers: dispatcher mode or individual tracepoints ---
    // Spec 053 fix: SKIP the dispatcher entirely on prod. Empirical finding
    // 2026-05-22: aya 0.13's dispatcher pattern loads dispatch_* tail call
    // targets, inserts them into SYSCALL_DISPATCH prog_array, post-set lookup
    // confirms entries persist — yet bpf_tail_call from the dispatcher to
    // dispatch_execve silently fails (dispatcher.run_cnt = 8M, dispatch_execve.
    // run_cnt = 0 over many execves on kernel 6.8.0-1052-oracle). Root cause
    // is likely an attach-type / load-time cookie incompatibility between
    // aya's RawTracePoint loader and bpf_tail_call's target validation.
    //
    // The .o ALSO contains standalone tracepoint handlers (innerwarden_execve,
    // innerwarden_connect, innerwarden_openat, etc.) which DO work via the
    // typed-tracepoint code path. Use those exclusively until the dispatcher
    // bug is root-caused. Doing this means we burn one tracepoint slot per
    // monitored syscall (still well within kernel limits) but events finally
    // start flowing.
    // Spec 069 Phase 2: each syscall handler is a kprobe on the architecture
    // syscall ENTRY WRAPPER (`__x64_sys_<name>` / `__arm64_sys_<name>`), reading
    // args from the wrapper's `struct pt_regs *`. Validated on kernel 7.0
    // x86_64 (kill(pid,sig) round-trips exactly). This replaced the previous
    // `sys_enter` raw_tracepoint dispatch, which fired on EVERY syscall and
    // flooded the EVENTS ring buffer, starving `reserve()` so events never
    // surfaced. Each attach is fail-open (missing symbol → warn + skip).
    // Count successful attaches: 0 syscall kprobes = the sensor is host-blind
    // (loaded but nothing attached, e.g. under a restrictive systemd sandbox),
    // which the health layer must surface instead of reporting "active".
    let mut attached_progs = 0usize;
    {
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_execve", &["execve"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_connect", &["connect"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_openat", &["openat"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_ptrace", &["ptrace"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_setuid", &["setuid"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_bind", &["bind"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_mount", &["mount"]);
        attached_progs +=
            attach_syscall_kprobe(&mut bpf, "dispatch_memfd_create", &["memfd_create"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_init_module", &["init_module"]);
        // dup2 is x86_64-only; dup3 exists on both arches. Attach both candidates;
        // the absent one fails-open on aarch64.
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_dup", &["dup3", "dup2"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_listen", &["listen"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_mprotect", &["mprotect"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_clone", &["clone"]);
        // Spec 070: setns(2) — privilege-provenance pivot (emit-only).
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_setns", &["setns"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_unlink", &["unlinkat"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_rename", &["renameat2"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_kill", &["kill"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_prctl", &["prctl"]);
        attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_accept", &["accept4"]);
        // ioperm/iopl are x86_64-only (absent from the aarch64 bytecode →
        // fail-open skip there).
        #[cfg(target_arch = "x86_64")]
        {
            attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_ioperm", &["ioperm"]);
            attached_progs += attach_syscall_kprobe(&mut bpf, "dispatch_iopl", &["iopl"]);
        }
    }

    // --- Always attach non-tracepoint programs individually ---

    // Attach commit_creds kprobe (privilege escalation detection - non-critical)
    if let Some(prog) = bpf.program_mut("innerwarden_privesc") {
        use aya::programs::KProbe;
        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
            if kp.load().is_ok() {
                if let Err(e) = kp.attach("commit_creds", 0) {
                    warn!(error = %e, "innerwarden_privesc: failed to attach to commit_creds");
                } else {
                    info!("eBPF: innerwarden_privesc → commit_creds (privilege escalation) ✅");
                    attached_progs += 1;
                }
            }
        }
    }

    // Attach sched_process_exit via raw_tracepoint (rootkit lifecycle tracking -
    // non-critical). Spec 069: raw_tp attach (BPF_RAW_TRACEPOINT_OPEN) is gated by
    // CAP_BPF+CAP_PERFMON and works under the non-root sensor on kernel 7.0, where
    // the perf-tracepoint attach path fails with perf_event_paranoid=4.
    {
        use aya::programs::RawTracePoint;
        if let Some(prog) = bpf.program_mut("innerwarden_process_exit") {
            if let Ok(rtp) = TryInto::<&mut RawTracePoint>::try_into(prog) {
                if rtp.load().is_ok() {
                    if let Err(e) = rtp.attach("sched_process_exit") {
                        warn!(error = %e, "innerwarden_process_exit: failed to attach");
                    } else {
                        info!("eBPF: innerwarden_process_exit → sched_process_exit (raw_tp) ✅");
                        attached_progs += 1;
                    }
                }
            }
        }
    }

    // io_uring monitoring (non-critical — requires kernel 5.10+ with io_uring tracepoints)
    // Try the 6.4+ name first, fall back to the pre-6.4 name.
    if !attach_tp(
        &mut bpf,
        "innerwarden_io_uring_submit",
        "io_uring",
        "io_uring_submit_req",
    ) {
        attach_tp(
            &mut bpf,
            "innerwarden_io_uring_submit",
            "io_uring",
            "io_uring_submit_sqe",
        );
    }
    attach_tp(
        &mut bpf,
        "innerwarden_io_uring_create",
        "io_uring",
        "io_uring_create",
    );

    // Create the BPF pin directory once before any attach step tries
    // to pin a map. attach_lsm pins LSM_POLICY/CGROUP_CAP/COMM_CAP
    // immediately; attach_xdp pins BLOCKLIST/ALLOWLIST. Pre-2026-05-08
    // the dir was only created inside attach_xdp, so LSM pins always
    // failed silently on first boot. If this fails (e.g. systemd unit
    // restricts /sys/fs/bpf to read-only), every subsequent pin will
    // fail too — the warn here gives the operator one clear signal
    // instead of three confusing ones.
    if let Err(e) = ensure_bpf_pin_dir() {
        warn!(
            error = %e,
            "eBPF: failed to create pin directory {XDP_PIN_DIR} — \
             check that /sys/fs/bpf is in `ReadWritePaths` (not \
             `ReadOnlyPaths`) of the sensor's systemd unit. \
             Map pinning will be skipped; XDP firewall + LSM \
             policy enforcement will fall back to in-memory state \
             that does not survive sensor restart."
        );
    }

    // Attach LSM execution policy (non-critical - requires lsm=bpf in kernel cmdline)
    attach_lsm(&mut bpf);

    // Attach XDP firewall (non-critical - continues without it)
    attach_xdp(&mut bpf);

    // Record the runtime attach count so the health layer surfaces a
    // host-blind sensor (bytecode loaded but 0 programs attached) instead of
    // reporting "active". This is the runtime companion to the static
    // `ebpf_unavailability_reason` check — see `build_ebpf_status`.
    EBPF_ATTACHED.store(attached_progs, std::sync::atomic::Ordering::Relaxed);
    if attached_progs == 0 {
        error!(
            "eBPF: 0 programs attached - the sensor is HOST-BLIND. The bytecode \
             loaded but every attach failed, so kernel syscall detection is OFF \
             and host telemetry will not flow. Check systemd sandboxing \
             (RestrictNamespaces / a private mount namespace masking \
             /sys/kernel/tracing), capabilities (CAP_BPF, CAP_PERFMON, \
             CAP_SYS_ADMIN), and perf_event_paranoid."
        );
    } else {
        info!("eBPF: attached {attached_progs} syscall/core programs");
    }

    // Phase 2: Firmware security hooks (non-critical on ARM — some x86 only)
    // MSR write monitoring (x86 only — kprobe on native_write_msr)
    if let Some(prog) = bpf.program_mut("innerwarden_msr_write") {
        use aya::programs::KProbe;
        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
            if kp.load().is_ok() {
                match kp.attach("native_write_msr", 0) {
                    Ok(_) => info!("eBPF: innerwarden_msr_write → native_write_msr ✅"),
                    Err(e) => info!(error = %e, "innerwarden_msr_write: not available (x86 only)"),
                }
            }
        }
    }
    // I/O port access (ioperm/iopl) is attached as a kprobe in the spec-069
    // syscall block above (x86_64-only).
    // ACPI method evaluation (kprobe — available on any system with ACPI)
    if let Some(prog) = bpf.program_mut("innerwarden_acpi_eval") {
        use aya::programs::KProbe;
        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
            if kp.load().is_ok() {
                match kp.attach("acpi_evaluate_object", 0) {
                    Ok(_) => info!("eBPF: innerwarden_acpi_eval → acpi_evaluate_object ✅"),
                    Err(e) => info!(error = %e, "innerwarden_acpi_eval: ACPI not available"),
                }
            }
        }
    }
    // BPF program loading (LSM hook — requires lsm=bpf)
    // This is attached via attach_lsm() which handles LSM hooks.

    // Phase 3: Red team gap hooks — timestomp + truncate detection
    // Bare #[kprobe] in eBPF code; attached to kernel functions here.
    // Uses PrivEscEvent as lightweight carrier (same ring buffer layout).
    // Timestomp detection: kprobe on vfs_utimes
    if let Some(prog) = bpf.program_mut("innerwarden_utimensat") {
        use aya::programs::KProbe;
        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
            match kp.load() {
                Ok(()) => match kp.attach("vfs_utimes", 0) {
                    Ok(_) => info!("eBPF: innerwarden_utimensat → vfs_utimes (timestomp) ✅"),
                    Err(e) => warn!(error = %e, "innerwarden_utimensat: attach failed"),
                },
                Err(e) => warn!(error = %e, "innerwarden_utimensat: load failed"),
            }
        } else {
            warn!("innerwarden_utimensat: not a KProbe program type");
        }
    } else {
        warn!("innerwarden_utimensat: program not found in bytecode");
    }
    // Log tampering detection: kprobe on do_truncate
    if let Some(prog) = bpf.program_mut("innerwarden_truncate") {
        use aya::programs::KProbe;
        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
            match kp.load() {
                Ok(()) => match kp.attach("do_truncate", 0) {
                    Ok(_) => info!("eBPF: innerwarden_truncate → do_truncate (log tampering) ✅"),
                    Err(e) => warn!(error = %e, "innerwarden_truncate: attach failed"),
                },
                Err(e) => warn!(error = %e, "innerwarden_truncate: load failed"),
            }
        } else {
            warn!("innerwarden_truncate: not a KProbe program type");
        }
    } else {
        warn!("innerwarden_truncate: program not found in bytecode");
    }

    // Trace of the Times: attach kprobe/kretprobe pairs for timing measurement.
    {
        let timing_targets = [
            (
                "innerwarden_tot_iterate_dir_entry",
                "innerwarden_tot_iterate_dir_ret",
                "iterate_dir",
            ),
            (
                "innerwarden_tot_filldir64_entry",
                "innerwarden_tot_filldir64_ret",
                "filldir64",
            ),
            (
                "innerwarden_tot_tcp4_entry",
                "innerwarden_tot_tcp4_ret",
                "tcp4_seq_show",
            ),
            (
                "innerwarden_tot_procdir_entry",
                "innerwarden_tot_procdir_ret",
                "proc_pid_readdir",
            ),
        ];
        for (entry_prog, ret_prog, func_name) in &timing_targets {
            // Attach kprobe (entry).
            let entry_ok = if let Some(prog) = bpf.program_mut(entry_prog) {
                use aya::programs::KProbe;
                if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
                    kp.load().is_ok() && kp.attach(func_name, 0).is_ok()
                } else {
                    false
                }
            } else {
                false
            };
            // Attach kretprobe (return).
            let ret_ok = if let Some(prog) = bpf.program_mut(ret_prog) {
                use aya::programs::KProbe;
                if let Ok(kp) = TryInto::<&mut KProbe>::try_into(prog) {
                    kp.load().is_ok() && kp.attach(func_name, 0).is_ok()
                } else {
                    false
                }
            } else {
                false
            };
            if entry_ok && ret_ok {
                info!("eBPF: ToT timing probe → {func_name} (entry+return) ✅");
            } else if entry_ok || ret_ok {
                warn!("eBPF: ToT {func_name}: partial attach (entry={entry_ok}, ret={ret_ok})");
            } else {
                info!("eBPF: ToT {func_name}: not available on this kernel");
            }
        }
    }

    // Populate kernel-level noise filters BEFORE taking ring buffer borrow
    populate_kernel_filters(&mut bpf);

    // InnerWarden self-suppression: seed SELF_CGROUP with our own services'
    // cgroups so their syscalls — including the integrity collector's credential
    // reads — are dropped IN-KERNEL (via `is_self_cgroup()`) before
    // RingBuf::reserve, instead of flooding the ring and starving real host +
    // container signal. `take_map` hands ownership to this loop (no borrow
    // conflict with the EVENTS ring below); the kernel map stays live and the
    // in-kernel gate keeps consulting it. The refresh runs INLINE in the ring
    // loop below (a `tokio::spawn`'d task did not get scheduled inside this eBPF
    // collector); it re-resolves every 30s to follow service restarts.
    let self_install_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/local/bin"));
    let mut self_cgroup_map = bpf
        .take_map("SELF_CGROUP")
        .and_then(|m| aya::maps::HashMap::<_, u64, u32>::try_from(m).ok());
    let mut self_cgroup_added = std::collections::BTreeSet::new();
    let mut last_self_refresh = std::time::Instant::now();
    match self_cgroup_map {
        Some(ref mut map) => {
            let n = refresh_self_cgroup_allowlist(map, &self_install_dir, &mut self_cgroup_added);
            info!(
                self_cgroups = n,
                "eBPF: InnerWarden self-cgroup suppression seeded"
            );
        }
        None => warn!(
            "eBPF: SELF_CGROUP map absent - self-suppression disabled (ring may flood under load)"
        ),
    }

    // Spec 052 Phase 1d: small in-memory cache that lets the kind=35
    // (LsmDecisionEvent) dispatch arm enrich its event with the comm,
    // filename, and uid captured by the earlier kind=1 (ExecveEvent)
    // tracepoint for the same PID. The kernel tracepoint
    // (sys_enter_execve) fires before the LSM hook (bprm_check_security),
    // so for any blocked exec the ExecveEvent arrives in the ringbuf
    // ahead of the LsmDecisionEvent — typically within microseconds.
    //
    // The cache is bounded: aged out when > 1024 entries (drop anything
    // older than 5 seconds). That holds ~50 seconds of context at the
    // typical prod execve rate while keeping the working set tiny.
    //
    // INV-LSM-04 anchor: ensures `lsm.blocked` events carry filename +
    // comm + uid context, so operators can read the SQLite events table
    // (or dashboard) and see "X blocked from executing Y" without
    // joining two tables themselves.
    struct ExecveCtx {
        comm: String,
        filename: String,
        uid: u32,
        ts_ns: u64,
    }
    let mut execve_cache: std::collections::HashMap<u32, ExecveCtx> =
        std::collections::HashMap::with_capacity(256);

    // Read from ring buffer
    let mut ring_buf = match RingBuf::try_from(bpf.map_mut("EVENTS").unwrap()) {
        Ok(rb) => rb,
        Err(e) => {
            warn!(error = %e, "eBPF: failed to open ring buffer");
            return;
        }
    };

    info!("eBPF collector active - kernel-level syscall monitoring (27 hooks + 5 firmware)");

    // Setup epoll-based wakeup via AsyncFd wrapping the ring buffer's raw fd.
    // Falls back to 100ms sleep polling if fd duplication or AsyncFd fails.
    let async_fd = {
        let ring_fd = ring_buf.as_raw_fd();
        // dup() so AsyncFd owns an independent fd and won't close the ring buffer's fd
        let duped = unsafe { libc::dup(ring_fd) };
        if duped >= 0 {
            // Safety: duped is a valid fd we just created
            let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(duped) };
            match tokio::io::unix::AsyncFd::new(owned) {
                Ok(afd) => {
                    info!("eBPF: ring buffer epoll wakeup enabled (fd={ring_fd})");
                    Some(afd)
                }
                Err(e) => {
                    warn!(error = %e, "eBPF: AsyncFd creation failed - falling back to poll");
                    None
                }
            }
        } else {
            warn!("eBPF: dup() failed - falling back to poll");
            None
        }
    };

    // Safe byte parsing: returns from match arm with `continue` on malformed data
    macro_rules! read_u16 {
        ($data:expr, $range:expr) => {
            match $data[$range].try_into().ok().map(u16::from_ne_bytes) {
                Some(v) => v,
                None => continue,
            }
        };
    }
    macro_rules! read_u32 {
        ($data:expr, $range:expr) => {
            match $data[$range].try_into().ok().map(u32::from_ne_bytes) {
                Some(v) => v,
                None => continue,
            }
        };
    }
    macro_rules! read_u64 {
        ($data:expr, $range:expr) => {
            match $data[$range].try_into().ok().map(u64::from_ne_bytes) {
                Some(v) => v,
                None => continue,
            }
        };
    }

    loop {
        // Refresh InnerWarden's own-cgroup suppression set every 30s, inline in
        // the ring loop (a spawned task never got scheduled here). Follows service
        // restarts (fresh cgroup) and picks up the agent when it starts after the
        // sensor. Cheap: a /proc scan gated to once per 30s.
        if let Some(ref mut map) = self_cgroup_map {
            if last_self_refresh.elapsed() >= std::time::Duration::from_secs(30) {
                refresh_self_cgroup_allowlist(map, &self_install_dir, &mut self_cgroup_added);
                last_self_refresh = std::time::Instant::now();
            }
        }
        while let Some(item) = ring_buf.next() {
            let data: &[u8] = &item;
            if data.len() < 4 {
                continue;
            }

            let kind = read_u32!(data, 0..4);

            let event = match kind {
                // ExecveEvent layout (#[repr(C)]):
                //   kind(4) pid(4) tgid(4) uid(4) gid(4) ppid(4) cgroup_id(8) comm(64) filename(256)
                //   Offsets: 0  4  8  12  16  20  24  32..96  96..352
                1 if data.len() >= 352 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 12..16);
                    // Spec 050-PR1 follow-up to #662: prefer the
                    // kernel-provided ppid (already in the eBPF event
                    // struct at offset 20-24, copied from
                    // task_struct->real_parent->pid). Falling back to
                    // `resolve_ppid()` (/proc/<pid>/status) silently
                    // returns 0 for short-lived processes — whoami / id
                    // exit in microseconds, before userspace can read.
                    // Smoke test 2026-05-17 confirmed: 10 disguised
                    // recon execs all landed with ppid=0, blocking
                    // discovery_anomaly's ppid-pivoted grouping.
                    let kernel_ppid = read_u32!(data, 20..24);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);
                    let filename = bytes_to_string(&data[96..352]);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    // argv[] captured in-kernel (struct offsets: argv 352..1376 =
                    // 8 slots x 128 bytes, argc at 1376). Preferred over
                    // /proc/PID/cmdline in execve_to_event because /proc is already
                    // gone for a short-lived rm/find by the time this reader runs.
                    // Older sensor eBPF zeroes argv -> argc 0 -> /proc fallback.
                    let kernel_argv: Vec<String> = if data.len() >= 1380 {
                        let argc = (read_u32!(data, 1376..1380) as usize).min(8);
                        let mut v = Vec::with_capacity(argc);
                        for i in 0..argc {
                            let start = 352 + i * 128;
                            let s = bytes_to_string(&data[start..start + 128]);
                            if s.is_empty() {
                                break;
                            }
                            v.push(s);
                        }
                        v
                    } else {
                        Vec::new()
                    };

                    // Spec 052 Phase 1d: cache for join with LsmDecisionEvent
                    // (kind=35). Insert before any early-return below so a
                    // future LSM block on this pid has context to merge.
                    // Capped at 1024 entries; aged out at 5s when full.
                    let ts_ns_now = {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default();
                        now.as_nanos() as u64
                    };
                    execve_cache.insert(
                        pid,
                        ExecveCtx {
                            comm: comm.clone(),
                            filename: filename.clone(),
                            uid,
                            ts_ns: ts_ns_now,
                        },
                    );
                    if execve_cache.len() > 1024 {
                        let cutoff = ts_ns_now.saturating_sub(5_000_000_000);
                        execve_cache.retain(|_, ctx| ctx.ts_ns >= cutoff);
                    }

                    let ppid = resolve_ppid_kernel_first(kernel_ppid, pid);
                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());

                    let mut ev = execve_to_event(
                        pid,
                        uid,
                        ppid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        &filename,
                        kernel_argv,
                        &host,
                    );
                    attach_pod_runtime(&mut ev.details, cident.as_deref());
                    Some(ev)
                }
                // ConnectEvent layout (#[repr(C)]):
                //   kind(4) pid(4) tgid(4) uid(4) ppid(4) _pad(4) cgroup_id(8) comm(64)
                //   dst_addr(4) dst_port(2) family(2) ts_ns(8)
                //   Offsets: 0  4  8  12  16  20  24  32..96  96  100  102
                2 if data.len() >= 104 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 12..16);
                    // Kernel ppid at offset 16-20 (see layout comment
                    // above). Same rationale as kind=1 — /proc lookup
                    // races with short-lived processes; kernel value is
                    // sourced from task_struct and always valid.
                    let kernel_ppid = read_u32!(data, 16..20);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);
                    let addr_raw = read_u32!(data, 96..100);
                    let port = read_u16!(data, 100..102);

                    // The eBPF program already converts from network byte
                    // order via u32::from_be_bytes. The ring buffer
                    // serializes in native order; read_u32! restores the
                    // same host-endian value. Ipv4Addr::from(u32) expects
                    // host-endian, so no swap needed.
                    let ip = Ipv4Addr::from(addr_raw);

                    if ip.is_loopback() || ip.is_private() || ip.is_unspecified() {
                        continue;
                    }

                    let ppid = resolve_ppid_kernel_first(kernel_ppid, pid);
                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());

                    let exe_path = execve_cache.get(&pid).map(|c| c.filename.clone());
                    let mut ev = connect_to_event(
                        pid,
                        uid,
                        ppid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        ip,
                        port,
                        &host,
                        exe_path.as_deref(),
                    );
                    attach_pod_runtime(&mut ev.details, cident.as_deref());
                    Some(ev)
                }
                // FileOpenEvent layout (#[repr(C)]):
                //   kind(4) pid(4) uid(4) ppid(4) cgroup_id(8) comm(64) filename(256) flags(4)
                //   Offsets: 0  4  8  12  16  24..88  88..344  344
                3 if data.len() >= 348 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    // Kernel ppid at offset 12-16.
                    let kernel_ppid = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);
                    let filename = bytes_to_string(&data[88..344]);
                    let flags = read_u32!(data, 344..348);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    let ppid = resolve_ppid_kernel_first(kernel_ppid, pid);
                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());
                    let exe_path = execve_cache.get(&pid).map(|c| c.filename.clone());

                    let mut ev = file_open_to_event(
                        pid,
                        uid,
                        ppid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        &filename,
                        flags,
                        &host,
                        exe_path.as_deref(),
                    );
                    attach_pod_runtime(&mut ev.details, cident.as_deref());
                    Some(ev)
                }
                // FileWrite from LSM file_open hook (same layout as FileOpenEvent)
                // Emitted when a non-allowlisted process writes to sensitive paths.
                4 if data.len() >= 348 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    // Kernel ppid at offset 12-16 (same layout as kind=3).
                    let kernel_ppid = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);
                    let filename = bytes_to_string(&data[88..344]);
                    let flags = read_u32!(data, 344..348);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    let ppid = resolve_ppid_kernel_first(kernel_ppid, pid);
                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());
                    let exe_path = execve_cache.get(&pid).map(|c| c.filename.clone());

                    let mut ev = file_open_to_event(
                        pid,
                        uid,
                        ppid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        &filename,
                        flags,
                        &host,
                        exe_path.as_deref(),
                    );
                    attach_pod_runtime(&mut ev.details, cident.as_deref());
                    Some(ev)
                }
                // PrivEscEvent layout (#[repr(C)]):
                //   kind(4) pid(4) tgid(4) old_uid(4) new_uid(4) _pad(4) cgroup_id(8) comm(64) ts_ns(8)
                //   Offsets: 0  4  8  12  16  20  24  32..96
                5 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let old_uid = read_u32!(data, 12..16);
                    let new_uid = read_u32!(data, 16..20);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());

                    privesc_to_event(
                        pid,
                        old_uid,
                        new_uid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        &host,
                    )
                    .map(|mut ev| {
                        attach_pod_runtime(&mut ev.details, cident.as_deref());
                        ev
                    })
                }
                // LSM blocked execution - uses ExecveEvent layout but kind=6
                // Same offsets as ExecveEvent: kind(4) pid(4) tgid(4) uid(4) gid(4) ppid(4) cgroup_id(8) comm(64) filename(256)
                6 if data.len() >= 352 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);
                    let filename = bytes_to_string(&data[96..352]);
                    let gate = is_exec_gate_block(data);
                    // Observe mode (spec 077 P2): the gate WOULD have blocked but
                    // allowed the exec (learning). Logged only, never an incident.
                    let observe = is_exec_gate_observe(data);

                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());

                    let mut details = serde_json::json!({
                        "pid": pid,
                        "uid": uid,
                        "comm": comm,
                        "filename": filename,
                        "cgroup_id": cgroup_id,
                        "action": if observe { "would_block" } else { "blocked" },
                    });
                    if gate {
                        details["blocked_by"] = serde_json::Value::String("exec_gate".to_string());
                    } else if observe {
                        details["would_block_by"] =
                            serde_json::Value::String("exec_gate".to_string());
                    }
                    if let Some(cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }
                    attach_pod_runtime(&mut details, cident.as_deref());

                    let mut tags = vec!["ebpf".to_string(), "lsm".to_string()];
                    tags.push(if observe { "would_block" } else { "blocked" }.to_string());
                    if gate || observe {
                        tags.push("exec_gate".to_string());
                    }
                    if observe {
                        tags.push("observe".to_string());
                    }
                    let mut entities = vec![];
                    if let Some(cid) = container_id {
                        tags.push("container".to_string());
                        entities.push(EntityRef::container(cid));
                    }

                    let (kind, summary, severity) = if observe {
                        (
                            "lsm.exec_gate_would_block".to_string(),
                            format!(
                                "Execution Gate (observe) would block: {comm} tried to run {filename} \
                                 — allowed (learning). Approve to allowlist, or it is denied once armed."
                            ),
                            // Learning signal, not a block — keep it out of the
                            // critical incident stream (onboarding can be noisy).
                            Severity::Info,
                        )
                    } else if gate {
                        (
                            "lsm.exec_gate_blocked".to_string(),
                            format!(
                                "Execution Gate blocked unknown binary: {comm} tried to run {filename}"
                            ),
                            Severity::Critical,
                        )
                    } else {
                        (
                            "lsm.exec_blocked".to_string(),
                            format!("LSM blocked execution: {comm} tried to run {filename}"),
                            Severity::Critical,
                        )
                    };

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind,
                        severity,
                        summary,
                        details,
                        tags,
                        entities,
                    })
                }
                // ContainerDrift: ExecveEvent layout with kind=26.
                // Binary executed from overlayfs upper layer (not in original image).
                26 if data.len() >= 352 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);
                    let filename = bytes_to_string(&data[96..352]);

                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());

                    let mut details = serde_json::json!({
                        "pid": pid,
                        "uid": uid,
                        "comm": comm,
                        "filename": filename,
                        "cgroup_id": cgroup_id,
                        "container_id": container_id.as_deref().unwrap_or(""),
                        "overlay_upper": true,
                    });
                    attach_pod_runtime(&mut details, cident.as_deref());

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "shell.command_exec".to_string(),
                        severity: Severity::Critical,
                        summary: format!(
                            "Container drift: {comm} executed {filename} (overlay upper layer)"
                        ),
                        details,
                        tags: vec!["ebpf".to_string(), "container_drift".to_string()],
                        entities: vec![],
                    })
                }
                // Spec 052 Phase 1c — LsmDecisionEvent layout (#[repr(C)]):
                //   kind(4) pid(4) tgid(4) reason(4) ts_ns(8) = 24 bytes
                // Emitted by `innerwarden_lsm_exec_min` ONLY on block. Carries
                // no comm/filename/uid — the userspace agent joins by PID
                // against the existing `innerwarden_execve` event stream
                // (kind=1) to recover that context. Until the agent ships
                // the join (next sub-PR), the operator still gets the bare
                // "lsm.blocked" event in JSONL with pid + tgid + reason.
                35 if data.len() >= 24 => {
                    // LSM_HOOK_* wire-format constants — kept in sync with
                    // crates/sensor-ebpf-types/src/lib.rs anchor tests.
                    // The sensor crate doesn't directly depend on
                    // innerwarden-ebpf-types (events are parsed via byte
                    // offsets, not Rust types), so inline the constants
                    // here rather than add a workspace dep just for 5 u32s.
                    const LSM_HOOK_BPRM_CHECK_SECURITY: u32 = 1;
                    const LSM_HOOK_CREATE_USER_NS: u32 = 2;
                    const LSM_HOOK_PTRACE_ACCESS_CHECK: u32 = 3;
                    const LSM_HOOK_MMAP_FILE: u32 = 4;
                    const LSM_HOOK_BPF_PROG_LOAD: u32 = 5;
                    let pid = read_u32!(data, 4..8);
                    let tgid = read_u32!(data, 8..12);
                    let hook_id = read_u32!(data, 12..16);
                    // ts_ns is captured by the kernel hook but the userspace
                    // event's `ts` field is the JSONL-canonical UTC time so
                    // operators don't have to translate boot-relative ns.

                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());

                    // PR-A: the `reason` field at offset 12 was repurposed
                    // as `hook_id` (sensor-ebpf-types LSM_HOOK_*) so kind=35
                    // events from create_user_ns / ptrace_access_check /
                    // mmap_file / bpf_prog_load all dispatch through this
                    // one arm. Map to a human-readable hook name + tag.
                    let (hook_name, source_program) = match hook_id {
                        LSM_HOOK_BPRM_CHECK_SECURITY => {
                            ("bprm_check_security", "innerwarden_lsm_exec_min")
                        }
                        LSM_HOOK_CREATE_USER_NS => {
                            ("userns_create", "innerwarden_lsm_create_user_ns")
                        }
                        LSM_HOOK_PTRACE_ACCESS_CHECK => {
                            ("ptrace_access_check", "innerwarden_lsm_ptrace_access")
                        }
                        LSM_HOOK_MMAP_FILE => ("mmap_file", "innerwarden_lsm_mmap_file"),
                        LSM_HOOK_BPF_PROG_LOAD => ("bpf_prog", "innerwarden_lsm_bpf_prog_load"),
                        _ => ("unknown", "unknown"),
                    };

                    // Spec 052 Phase 1d: join with the earlier ExecveEvent
                    // (kind=1) for the same PID — only meaningful for
                    // bprm_check_security blocks. Other hooks (userns,
                    // ptrace, mmap, bpf) don't have a corresponding execve
                    // for the SAME action so join_source stays "n/a".
                    let join_execve = hook_id == LSM_HOOK_BPRM_CHECK_SECURITY;
                    let exec_ctx = if join_execve {
                        execve_cache.get(&pid)
                    } else {
                        None
                    };

                    let mut details = serde_json::json!({
                        "pid": pid,
                        "tgid": tgid,
                        "hook_id": hook_id,
                        "hook": hook_name,
                        "action": "blocked",
                        "source_program": source_program,
                    });
                    if let Some(cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }
                    attach_pod_runtime(&mut details, cident.as_deref());
                    if let Some(ctx) = exec_ctx {
                        details["filename"] = serde_json::Value::String(ctx.filename.clone());
                        details["comm"] = serde_json::Value::String(ctx.comm.clone());
                        details["uid"] = serde_json::Value::from(ctx.uid);
                        details["join_source"] =
                            serde_json::Value::String("execve_tracepoint".to_string());
                    } else if join_execve {
                        details["join_source"] =
                            serde_json::Value::String("cache_miss".to_string());
                    } else {
                        details["join_source"] = serde_json::Value::String("n/a".to_string());
                    }

                    let mut tags = vec![
                        "ebpf".to_string(),
                        "lsm".to_string(),
                        "blocked".to_string(),
                        "spec_052".to_string(),
                        format!("hook:{hook_name}"),
                    ];
                    let mut entities = vec![];
                    if let Some(cid) = container_id {
                        tags.push("container".to_string());
                        entities.push(EntityRef::container(cid));
                    }
                    if hook_id == LSM_HOOK_CREATE_USER_NS {
                        tags.push("container_escape".to_string());
                    }

                    let summary = if let Some(ctx) = exec_ctx {
                        format!(
                            "LSM kernel-block: {} (PID {pid}) denied execve to {} \
                             — innerwarden_lsm_exec_min",
                            ctx.comm, ctx.filename
                        )
                    } else {
                        format!(
                            "LSM kernel-block: {hook_name} denied for PID {pid} (TGID {tgid}) \
                             by {source_program}"
                        )
                    };

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "lsm.blocked".to_string(),
                        severity: Severity::Critical,
                        summary,
                        details,
                        tags,
                        entities,
                    })
                }
                // ProcessExitEvent layout (#[repr(C)]):
                //   kind(4) pid(4) tgid(4) comm(64) exit_code(4) ts_ns(8)
                //   Offsets: 0  4  8  12..76  76  80
                7 if data.len() >= 80 => {
                    let pid = read_u32!(data, 4..8);
                    let comm = bytes_to_string(&data[12..76]);

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.exit".to_string(),
                        severity: Severity::Debug,
                        summary: format!("Process exited: {comm} (PID {pid})"),
                        details: serde_json::json!({
                            "pid": pid,
                            "comm": comm,
                        }),
                        tags: vec!["ebpf".to_string()],
                        entities: vec![],
                    })
                }
                // PtraceEvent: kind(4) pid(4) uid(4) target_pid(4) request(4) _pad(4) cgroup_id(8) comm(64) ts_ns(8)
                // Offsets: 0  4  8  12  16  20  24  32..96
                8 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let target_pid = read_u32!(data, 12..16);
                    let request = read_u32!(data, 16..20);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    let request_name = match request {
                        4 => "PTRACE_POKETEXT",
                        5 => "PTRACE_POKEDATA",
                        16 => "PTRACE_ATTACH",
                        0x4206 => "PTRACE_SEIZE",
                        _ => "UNKNOWN",
                    };
                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());

                    let mut details = serde_json::json!({
                        "pid": pid, "uid": uid, "target_pid": target_pid,
                        "request": request, "request_name": request_name,
                        "comm": comm, "cgroup_id": cgroup_id,
                    });
                    if let Some(cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }
                    attach_pod_runtime(&mut details, cident.as_deref());

                    let mut tags = vec![
                        "ebpf".to_string(),
                        "ptrace".to_string(),
                        "injection".to_string(),
                    ];
                    if container_id.is_some() {
                        tags.push("container".to_string());
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.ptrace_attach".to_string(),
                        severity: Severity::Critical,
                        summary: format!(
                            "{comm} (PID {pid}) called {request_name} on PID {target_pid}"
                        ),
                        details,
                        tags,
                        entities: vec![],
                    })
                }
                // SetUidEvent: kind(4) pid(4) uid(4) target_uid(4) syscall_nr(4) _pad(4) cgroup_id(8) comm(64) ts_ns(8)
                // Offsets: 0  4  8  12  16  20  24  32..96
                9 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let target_uid = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());
                    let mut details = serde_json::json!({
                        "pid": pid, "uid": uid, "target_uid": target_uid,
                        "comm": comm, "cgroup_id": cgroup_id,
                    });
                    if let Some(cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }
                    attach_pod_runtime(&mut details, cident.as_deref());

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "privilege.setuid".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (PID {pid}, uid {uid}) called setuid(0) - escalating to root"
                        ),
                        details,
                        tags: vec!["ebpf".to_string(), "privesc".to_string()],
                        entities: vec![],
                    })
                }
                // SocketBindEvent: kind(4) pid(4) uid(4) protocol(2) family(2) port(2) _pad(2) addr(4) cgroup_id(8) comm(64) ts_ns(8)
                // Offsets: 0  4  8  12  14  16  18  20  24  32..96
                10 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let family = read_u16!(data, 12..14);
                    let port = read_u16!(data, 16..18);
                    let addr_raw = read_u32!(data, 20..24);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    let ip = std::net::Ipv4Addr::from(addr_raw);
                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());

                    // Low ports or INADDR_ANY are more suspicious
                    let severity = if port < 1024 || addr_raw == 0 {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    let mut details = serde_json::json!({
                        "pid": pid, "uid": uid, "port": port,
                        "addr": format!("{ip}"), "family": family,
                        "comm": comm, "cgroup_id": cgroup_id,
                    });
                    if let Some(cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }
                    attach_pod_runtime(&mut details, cident.as_deref());

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "network.bind_listen".to_string(),
                        severity,
                        summary: format!("{comm} (PID {pid}) binding to {ip}:{port}"),
                        details,
                        tags: vec![
                            "ebpf".to_string(),
                            "network".to_string(),
                            "bind".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // MountEvent: kind(4) pid(4) uid(4) flags(4) cgroup_id(8) comm(64) source(256) target(256) fs_type(32) ts_ns(8)
                // Offsets: 0  4  8  12  16  24..88  88..344  344..600  600..632
                11 if data.len() >= 632 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let flags = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);
                    let source = bytes_to_string(&data[88..344]);
                    let target = bytes_to_string(&data[344..600]);
                    let fs_type = bytes_to_string(&data[600..632]);

                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());
                    let in_container = cgroup_id > 1;

                    let severity = if in_container {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    let mut details = serde_json::json!({
                        "pid": pid, "uid": uid, "flags": flags,
                        "source": source, "target": target, "fs_type": fs_type,
                        "comm": comm, "cgroup_id": cgroup_id,
                        "in_container": in_container,
                    });
                    if let Some(cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }
                    attach_pod_runtime(&mut details, cident.as_deref());

                    let mut tags = vec!["ebpf".to_string(), "mount".to_string()];
                    if in_container {
                        tags.push("container_escape".to_string());
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "filesystem.mount".to_string(),
                        severity,
                        summary: format!(
                            "{comm} (PID {pid}) mounting {source} on {target} (type: {fs_type})"
                        ),
                        details,
                        tags,
                        entities: vec![],
                    })
                }
                // MemfdCreateEvent: kind(4) pid(4) uid(4) flags(4) cgroup_id(8) comm(64) name(256) ts_ns(8)
                // Offsets: 0  4  8  12  16  24..88  88..344
                12 if data.len() >= 344 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let flags = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);
                    let name = bytes_to_string(&data[88..344]);

                    let cident = resolve_container_identity(pid);
                    let container_id = cident.as_ref().map(|c| c.container_id.as_str());

                    let mut details = serde_json::json!({
                        "pid": pid, "uid": uid, "flags": flags,
                        "name": name, "comm": comm, "cgroup_id": cgroup_id,
                    });
                    if let Some(cid) = container_id {
                        details["container_id"] = serde_json::Value::String(cid.to_string());
                    }
                    attach_pod_runtime(&mut details, cident.as_deref());

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.memfd_create".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (PID {pid}) created anonymous memory file: {name}"
                        ),
                        details,
                        tags: vec![
                            "ebpf".to_string(),
                            "fileless".to_string(),
                            "memfd".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // ModuleLoadEvent: kind(4) pid(4) uid(4) syscall_nr(4) cgroup_id(8) comm(64) ts_ns(8)
                // Offsets: 0  4  8  12  16  24..88
                13 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "kernel.module_load".to_string(),
                        severity: Severity::Critical,
                        summary: format!("{comm} (PID {pid}, uid {uid}) loading kernel module"),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec![
                            "ebpf".to_string(),
                            "kernel".to_string(),
                            "module_load".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // DupEvent: kind(4) pid(4) uid(4) oldfd(4) newfd(4) _pad(4) cgroup_id(8) comm(64)
                14 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let oldfd = read_u32!(data, 12..16);
                    let newfd = read_u32!(data, 16..20);
                    let comm = bytes_to_string(&data[24..88]);
                    let fd_name = match newfd {
                        0 => "stdin",
                        1 => "stdout",
                        2 => "stderr",
                        _ => "fd",
                    };
                    // Resolve ppid so reverse_shell can correlate a fork()'d
                    // reverse shell (connect in the parent, dup2 onto stdio in the
                    // child — socat/python). Only for stdio redirects (newfd<=2,
                    // the reverse-shell case); a non-stdio dup skips the /proc read.
                    let ppid = if newfd <= 2 { resolve_ppid(pid) } else { 0 };
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.fd_redirect".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (PID {pid}) redirected fd {oldfd} → {fd_name}({newfd})"
                        ),
                        details: serde_json::json!({"pid": pid, "uid": uid, "oldfd": oldfd, "newfd": newfd, "comm": comm, "ppid": ppid}),
                        tags: vec!["ebpf".to_string(), "reverse_shell".to_string()],
                        entities: vec![],
                    })
                }
                // ListenEvent: kind(4) pid(4) uid(4) backlog(4) cgroup_id(8) comm(64)
                15 if data.len() >= 80 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let backlog = read_u32!(data, 12..16);
                    let comm = bytes_to_string(&data[24..88]);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "network.listen".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (PID {pid}) started listening (backlog={backlog})"
                        ),
                        details: serde_json::json!({"pid": pid, "uid": uid, "backlog": backlog, "comm": comm}),
                        tags: vec![
                            "ebpf".to_string(),
                            "network".to_string(),
                            "listen".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // MprotectEvent: kind(4) pid(4) uid(4) prot(4) addr(8) len(8) cgroup_id(8) comm(64)
                16 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let prot = read_u32!(data, 12..16);
                    let addr = read_u64!(data, 16..24);
                    let len = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[40..104]);
                    let rwx = prot & 0x7 == 0x7; // PROT_READ|PROT_WRITE|PROT_EXEC
                    Some(Event {
                        ts: chrono::Utc::now(), host: host.to_string(), source: "ebpf".to_string(),
                        kind: "memory.mprotect_exec".to_string(),
                        severity: if rwx { Severity::Critical } else { Severity::High },
                        summary: format!("{comm} (PID {pid}) mprotect → executable memory at 0x{addr:x} ({len} bytes){}", if rwx { " [RWX - shellcode indicator]" } else { "" }),
                        details: serde_json::json!({"pid": pid, "uid": uid, "prot": prot, "addr": format!("0x{addr:x}"), "len": len, "rwx": rwx, "comm": comm}),
                        tags: vec!["ebpf".to_string(), "shellcode".to_string()], entities: vec![],
                    })
                }
                // CloneEvent: kind(4) pid(4) uid(4) _pad(4) clone_flags(8) cgroup_id(8) comm(64)
                17 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let clone_flags = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[32..96]);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.clone".to_string(),
                        severity: Severity::Debug,
                        summary: format!("{comm} (PID {pid}) clone(flags=0x{clone_flags:x})"),
                        details: serde_json::json!({"pid": pid, "uid": uid, "clone_flags": format!("0x{clone_flags:x}"), "comm": comm}),
                        tags: vec!["ebpf".to_string()],
                        entities: vec![],
                    })
                }
                // SetnsEvent (Spec 070): kind(4) pid(4) tgid(4) uid(4) fd(4,i32)
                //   nstype(4) cgroup_id(8) comm(64) ts_ns(8) — total 104.
                // Emit-only; the `setns_owner` detector resolves the target
                // namespace owner uid in userspace from /proc/<pid>/fd/<fd>.
                36 if data.len() >= 104 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 12..16);
                    let fd = read_u32!(data, 16..20) as i32;
                    let nstype = read_u32!(data, 20..24);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);
                    let nstype_name = setns_nstype_name(nstype);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "namespace.setns".to_string(),
                        severity: Severity::Debug,
                        summary: format!(
                            "{comm} (PID {pid}, uid {uid}) setns(fd={fd}, {nstype_name})"
                        ),
                        details: serde_json::json!({
                            "pid": pid,
                            "uid": uid,
                            "fd": fd,
                            "nstype": nstype,
                            "nstype_name": nstype_name,
                            "cgroup_id": cgroup_id,
                            "comm": comm,
                        }),
                        tags: vec!["ebpf".to_string(), "namespace".to_string()],
                        entities: vec![],
                    })
                }
                // UnlinkEvent: kind(4) pid(4) uid(4) _pad(4) cgroup_id(8) comm(64) filename(256)
                18 if data.len() >= 344 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let comm = bytes_to_string(&data[24..88]);
                    let filename = bytes_to_string(&data[88..344]);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "file.delete".to_string(),
                        severity: Severity::High,
                        summary: format!("{comm} (PID {pid}) deleting {filename}"),
                        details: serde_json::json!({"pid": pid, "uid": uid, "filename": filename, "comm": comm}),
                        tags: vec!["ebpf".to_string(), "evidence_destruction".to_string()],
                        entities: vec![],
                    })
                }
                // RenameEvent: kind(4) pid(4) uid(4) _pad(4) cgroup_id(8) comm(64) oldname(256) newname(256)
                19 if data.len() >= 600 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let comm = bytes_to_string(&data[24..88]);
                    let oldname = bytes_to_string(&data[88..344]);
                    let newname = bytes_to_string(&data[344..600]);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "file.rename".to_string(),
                        severity: Severity::High,
                        summary: format!("{comm} (PID {pid}) renaming {oldname} → {newname}"),
                        details: serde_json::json!({"pid": pid, "uid": uid, "oldname": oldname, "newname": newname, "comm": comm}),
                        tags: vec!["ebpf".to_string(), "binary_replacement".to_string()],
                        entities: vec![],
                    })
                }
                // KillEvent: kind(4) pid(4) uid(4) target_pid(4) signal(4) _pad(4) cgroup_id(8) comm(64)
                20 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let target_pid = read_u32!(data, 12..16);
                    let signal = read_u32!(data, 16..20);
                    // KillEvent: signal(16..20) then 4 bytes pad to 8-align
                    // cgroup_id(24..32); comm starts at offset 32.
                    let comm = bytes_to_string(&data[32..96]);
                    let sig_name = match signal {
                        1 => "SIGHUP",
                        2 => "SIGINT",
                        3 => "SIGQUIT",
                        6 => "SIGABRT",
                        9 => "SIGKILL",
                        10 => "SIGUSR1",
                        12 => "SIGUSR2",
                        15 => "SIGTERM",
                        19 => "SIGSTOP",
                        34..=64 => "SIGRT",
                        _ => "SIG?",
                    };
                    let target_comm = resolve_target_comm(signal, target_pid);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.signal".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (PID {pid}) sending {sig_name} to PID {target_pid}"
                        ),
                        details: serde_json::json!({"pid": pid, "uid": uid, "target_pid": target_pid, "signal": signal, "signal_name": sig_name, "comm": comm, "target_comm": target_comm}),
                        tags: vec!["ebpf".to_string(), "kill_signal".to_string()],
                        entities: vec![],
                    })
                }
                // PrctlEvent: kind(4) pid(4) uid(4) option(4) arg2(8) cgroup_id(8) comm(64)
                21 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let option = read_u32!(data, 12..16);
                    let comm = bytes_to_string(&data[32..96]);
                    let op_name = match option {
                        15 => "PR_SET_NAME",
                        38 => "PR_SET_NO_NEW_PRIVS",
                        _ => "unknown",
                    };
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "process.prctl".to_string(),
                        severity: Severity::Medium,
                        summary: format!("{comm} (PID {pid}) prctl({op_name})"),
                        details: serde_json::json!({"pid": pid, "uid": uid, "option": option, "op_name": op_name, "comm": comm}),
                        tags: vec!["ebpf".to_string(), "prctl".to_string()],
                        entities: vec![],
                    })
                }
                // AcceptEvent: kind(4) pid(4) uid(4) _pad(4) cgroup_id(8) comm(64)
                22 if data.len() >= 80 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let comm = bytes_to_string(&data[24..88]);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "network.accept".to_string(),
                        severity: Severity::Debug,
                        summary: format!("{comm} (PID {pid}) accepted incoming connection"),
                        details: serde_json::json!({"pid": pid, "uid": uid, "comm": comm}),
                        tags: vec!["ebpf".to_string(), "network".to_string()],
                        entities: vec![],
                    })
                }
                // EXPERIMENTAL: EfiCallEvent: kind(4) pid(4) uid(4) _pad(4) cgroup_id(8) comm(64) ts_ns(8)
                23 if data.len() >= 88 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let comm = bytes_to_string(&data[24..88]);
                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "firmware.efi_call".to_string(),
                        severity: Severity::Debug,
                        summary: format!(
                            "[EXPERIMENTAL] {comm} (PID {pid}) EFI Runtime Services call"
                        ),
                        details: serde_json::json!({"pid": pid, "uid": uid, "comm": comm, "experimental": true}),
                        tags: vec![
                            "ebpf".to_string(),
                            "firmware".to_string(),
                            "experimental".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // IoUringEvent: kind(4) pid(4) uid(4) opcode(1) sqe_flags(1) _pad(2) fd(4)
                //   cgroup_id(8) comm(64) ts_ns(8)
                // Offsets: 0  4  8  12  13  14  16  20  24..88  88
                24 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let opcode = data[12];
                    let sqe_flags = data[13];
                    let fd = read_u32!(data, 16..20) as i32;
                    let cgroup_id = read_u64!(data, 20..28);
                    let comm = bytes_to_string(&data[28..92]);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "io_uring.submit".to_string(),
                        severity: Severity::Info,
                        summary: format!(
                            "{comm} (pid={pid}) io_uring submit opcode={opcode} fd={fd}"
                        ),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "opcode": opcode, "sqe_flags": sqe_flags,
                            "fd": fd, "cgroup_id": cgroup_id,
                        }),
                        tags: vec!["ebpf".to_string(), "io_uring".to_string()],
                        entities: vec![],
                    })
                }
                // IoUringCreateEvent: kind(4) pid(4) uid(4) ring_fd(4) sq_entries(4)
                //   cq_entries(4) flags(4) _pad(4) cgroup_id(8) comm(64) ts_ns(8)
                // Offsets: 0  4  8  12  16  20  24  28  32..96  96
                25 if data.len() >= 104 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let ring_fd = read_u32!(data, 12..16) as i32;
                    let sq_entries = read_u32!(data, 16..20);
                    let cq_entries = read_u32!(data, 20..24);
                    let flags = read_u32!(data, 24..28);
                    let cgroup_id = read_u64!(data, 32..40);
                    let comm = bytes_to_string(&data[40..104]);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "io_uring.create".to_string(),
                        severity: Severity::Info,
                        summary: format!(
                            "{comm} (pid={pid}) created io_uring ring (sq={sq_entries})"
                        ),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "ring_fd": ring_fd, "sq_entries": sq_entries,
                            "cq_entries": cq_entries, "flags": flags,
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec!["ebpf".to_string(), "io_uring".to_string()],
                        entities: vec![],
                    })
                }
                // ── Phase 2: Firmware hooks ──────────────────────

                // MsrWriteEvent: kind(4) pid(4) uid(4) pad(4) msr_addr(8) lo(4) hi(4) cgroup(8) comm(64) ts(8)
                27 if data.len() >= 104 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let msr_addr = read_u64!(data, 16..24);
                    let msr_lo = read_u32!(data, 24..28);
                    let msr_hi = read_u32!(data, 28..32);
                    let cgroup_id = read_u64!(data, 32..40);
                    let comm = bytes_to_string(&data[40..104]);

                    let msr_name = match msr_addr {
                        0xC0000081 => "STAR",
                        0xC0000082 => "LSTAR (syscall entry)",
                        0xC0000083 => "CSTAR",
                        0xC0000084 => "SF_MASK",
                        0x1F2 => "IA32_SMRR_PHYSBASE",
                        0x1F3 => "IA32_SMRR_PHYSMASK",
                        0x3A => "IA32_FEATURE_CONTROL",
                        _ => "UNKNOWN",
                    };

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "firmware.msr_write".to_string(),
                        severity: Severity::Critical,
                        summary: format!(
                            "{comm} (pid={pid}) wrote to MSR {msr_name} (0x{msr_addr:X}) = 0x{msr_hi:08X}{msr_lo:08X}"
                        ),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "msr_address": format!("0x{msr_addr:X}"),
                            "msr_name": msr_name,
                            "msr_value": format!("0x{msr_hi:08X}{msr_lo:08X}"),
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec!["ebpf".to_string(), "firmware".to_string(), "msr".to_string()],
                        entities: vec![],
                    })
                }
                // IopermEvent: kind(4) pid(4) uid(4) pad(4) from(8) num(8) turn_on(8) cgroup(8) comm(64) ts(8)
                28 if data.len() >= 112 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let port_from = read_u64!(data, 16..24);
                    let port_num = read_u64!(data, 24..32);
                    let cgroup_id = read_u64!(data, 40..48);
                    let comm = bytes_to_string(&data[48..112]);

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "firmware.ioperm".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (pid={pid}) requested I/O port access: ports 0x{port_from:X}-0x{:X}",
                            port_from + port_num
                        ),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "port_from": port_from, "port_num": port_num,
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec!["ebpf".to_string(), "firmware".to_string(), "hardware".to_string()],
                        entities: vec![],
                    })
                }
                // IoplEvent: kind(4) pid(4) uid(4) pad(4) level(8) cgroup(8) comm(64) ts(8)
                29 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let level = read_u64!(data, 16..24);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "firmware.iopl".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "{comm} (pid={pid}) elevated I/O privilege level to {level}"
                        ),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "level": level, "cgroup_id": cgroup_id,
                        }),
                        tags: vec![
                            "ebpf".to_string(),
                            "firmware".to_string(),
                            "hardware".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // AcpiEvalEvent: kind(4) pid(4) uid(4) pad(4) cgroup(8) pathname(64) comm(64) ts(8)
                30 if data.len() >= 160 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let cgroup_id = read_u64!(data, 16..24);
                    let pathname = bytes_to_string(&data[24..88]);
                    let comm = bytes_to_string(&data[88..152]);

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "firmware.acpi_eval".to_string(),
                        severity: Severity::Debug,
                        summary: format!("{comm} (pid={pid}) ACPI evaluate: {pathname}"),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "pathname": pathname, "cgroup_id": cgroup_id,
                        }),
                        tags: vec![
                            "ebpf".to_string(),
                            "firmware".to_string(),
                            "acpi".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // TimingProbeEvent: kind(4) pid(4) target(4) pad(4) delta_ns(8) cgroup(8) comm(64) ts(8)
                32 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let target = read_u32!(data, 8..12);
                    let delta_ns = read_u64!(data, 16..24);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    let target_name = match target {
                        1 => "iterate_dir",
                        2 => "filldir64",
                        3 => "tcp4_seq_show",
                        4 => "proc_pid_readdir",
                        _ => "unknown",
                    };

                    // Timing events are high-volume. Only emit as events
                    // when delta is unusually large (> 1ms = possible hook).
                    // Normal deltas are sub-microsecond.
                    if delta_ns > 1_000_000 {
                        Some(Event {
                            ts: chrono::Utc::now(),
                            host: host.to_string(),
                            source: "ebpf".to_string(),
                            kind: "firmware.timing_anomaly".to_string(),
                            severity: Severity::High,
                            summary: format!(
                                "{target_name} took {:.1}ms (pid={pid} {comm}) — possible kernel hook",
                                delta_ns as f64 / 1_000_000.0,
                            ),
                            details: serde_json::json!({
                                "pid": pid, "comm": comm,
                                "target": target_name,
                                "delta_ns": delta_ns,
                                "delta_ms": delta_ns as f64 / 1_000_000.0,
                                "cgroup_id": cgroup_id,
                            }),
                            tags: vec!["ebpf".to_string(), "firmware".to_string(), "timing".to_string()],
                            entities: vec![],
                        })
                    } else {
                        // Normal timing — silently collected for baseline building.
                        // TODO: accumulate in a buffer for periodic Trace of the Times analysis.
                        None
                    }
                }
                // BpfLoadEvent: kind(4) pid(4) uid(4) bpf_cmd(4) cgroup(8) comm(64) ts(8)
                31 if data.len() >= 96 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 8..12);
                    let bpf_cmd = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 16..24);
                    let comm = bytes_to_string(&data[24..88]);

                    let cmd_name = match bpf_cmd {
                        0 => "BPF_MAP_CREATE",
                        5 => "BPF_PROG_LOAD",
                        18 => "BPF_BTF_LOAD",
                        28 => "BPF_LINK_CREATE",
                        _ => "UNKNOWN",
                    };

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.to_string(),
                        source: "ebpf".to_string(),
                        kind: "firmware.bpf_load".to_string(),
                        severity: Severity::Medium,
                        summary: format!(
                            "{comm} (pid={pid}) loaded eBPF: {cmd_name} (cmd={bpf_cmd})"
                        ),
                        details: serde_json::json!({
                            "pid": pid, "uid": uid, "comm": comm,
                            "bpf_cmd": bpf_cmd, "cmd_name": cmd_name,
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec![
                            "ebpf".to_string(),
                            "firmware".to_string(),
                            "bpf_load".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // Utimensat: timestomp (reuses PrivEscEvent layout)
                // kind(4) pid(4) tgid(4) old_uid(4) new_uid(4) _pad(4) cgroup_id(8) comm(64) ts_ns(8) = 104 bytes
                33 if data.len() >= 104 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    // Filter benign system processes (centralized allowlist)
                    if crate::detectors::allowlists::is_innerwarden_process(uid as u64, &comm)
                        || comm == "tokio-rt-worker"
                        || (uid == 0
                            && crate::detectors::allowlists::comm_in_allowlist(
                                &comm,
                                crate::detectors::allowlists::TRUNCATE_ALLOWED,
                            ))
                    {
                        continue;
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.clone(),
                        source: "ebpf".to_string(),
                        kind: "file.timestomp".to_string(),
                        severity: Severity::High,
                        summary: format!(
                            "File timestamp modification by {} (pid={}, uid={})",
                            comm, pid, uid
                        ),
                        details: serde_json::json!({
                            "comm": comm,
                            "pid": pid,
                            "uid": uid,
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec![
                            "ebpf".to_string(),
                            "defense_evasion".to_string(),
                            "timestomp".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                // Truncate: log tampering (reuses PrivEscEvent layout)
                34 if data.len() >= 104 => {
                    let pid = read_u32!(data, 4..8);
                    let uid = read_u32!(data, 12..16);
                    let cgroup_id = read_u64!(data, 24..32);
                    let comm = bytes_to_string(&data[32..96]);

                    // Filter benign system log management (uid=0 check prevents
                    // attacker evasion via prctl; non-root truncate always alerts)
                    if comm.starts_with("innerwarden")
                        || (uid == 0
                            && matches!(
                                comm.as_str(),
                                "systemd-journal"
                                    | "logrotate"
                                    | "rsyslogd"
                                    | "systemd"
                                    | "systemd-tmpfile"
                                    | "sshd"
                            ))
                    {
                        continue;
                    }

                    Some(Event {
                        ts: chrono::Utc::now(),
                        host: host.clone(),
                        source: "ebpf".to_string(),
                        kind: "file.truncate".to_string(),
                        severity: Severity::High,
                        summary: format!("File truncated by {} (pid={}, uid={})", comm, pid, uid),
                        details: serde_json::json!({
                            "comm": comm,
                            "pid": pid,
                            "uid": uid,
                            "cgroup_id": cgroup_id,
                        }),
                        tags: vec![
                            "ebpf".to_string(),
                            "defense_evasion".to_string(),
                            "log_tampering".to_string(),
                        ],
                        entities: vec![],
                    })
                }
                _ => None,
            };

            if let Some(ev) = event {
                // Spec 069 follow-up #1 (Option C): non-blocking emit. The
                // drain loop MUST NOT block — emit classifies into prio /
                // emergency / bulk and drops (counted) rather than awaiting,
                // so the kernel ring never overflows behind us.
                let _ = tx.emit(ev);
            }
        }

        // Consumer gone (shutdown) → every lane closed → stop draining.
        if tx.is_closed() {
            info!("eBPF collector: all channels closed, stopping");
            return;
        }

        // Wait for ring buffer readability via epoll, but ALWAYS with a 100ms
        // timeout so the ring is still drained on kernels where the ring-buffer
        // epoll wakeup is not delivered reliably. Observed on Linux 7.0 (Azure):
        // the kprobes fire (run_cnt climbs into the thousands) but
        // `afd.readable().await` blocked forever after the initial drain, so
        // every subsequent event accumulated in the ring unseen and userspace
        // captured nothing. Polling on timeout makes the drain robust to
        // wakeup-delivery differences across kernels while keeping the fast
        // epoll-wakeup path on kernels that signal correctly.
        if let Some(ref afd) = async_fd {
            match tokio::time::timeout(std::time::Duration::from_millis(100), afd.readable()).await
            {
                Ok(Ok(mut guard)) => {
                    guard.clear_ready();
                }
                Ok(Err(_)) => {
                    // epoll error - fall back to a short sleep this iteration
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(_) => {
                    // No wakeup within 100ms: loop back and drain the ring
                    // directly (poll fallback). This is the path that keeps
                    // Linux 7.0 capturing.
                }
            }
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

/// Fallback when ebpf feature is not enabled.
#[cfg(not(feature = "ebpf"))]
pub async fn run(_tx: crate::event_channels::EbpfTx, _host: String) {
    if is_ebpf_available() {
        info!("eBPF is available but the sensor was compiled without --features ebpf");
        info!("Rebuild with: cargo build --features ebpf -p innerwarden-sensor");
    }
    // Silently return - other collectors handle detection
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Execution Gate: kind-6 events from the gate carry b"EXEC_GATE" in
    // argv[0] (bytes 352..361) and the REAL attempted path in filename;
    // legacy/kill-chain/neural kind-6 emitters zero argv. This anchor pins
    // the marker offset against ExecveEvent layout drift.
    #[test]
    fn exec_gate_marker_detected_only_when_present() {
        // Full-size ExecveEvent buffer, argv zeroed → NOT a gate block.
        let mut data = vec![0u8; 1400];
        assert!(!is_exec_gate_block(&data));
        // Marker at argv[0] → gate block.
        data[EXECVE_ARGV0_OFFSET..EXECVE_ARGV0_OFFSET + EXEC_GATE_MARKER.len()]
            .copy_from_slice(EXEC_GATE_MARKER);
        assert!(is_exec_gate_block(&data));
        // Marker must be exact — a prefix is not enough.
        data[EXECVE_ARGV0_OFFSET + 8] = 0;
        assert!(!is_exec_gate_block(&data));
        // Buffer too short for argv (legacy 352-byte minimum) → never a gate block.
        assert!(!is_exec_gate_block(&vec![0u8; 352]));
        assert!(!is_exec_gate_block(b""));
    }

    // Spec 077 P2: observe mode emits EXEC_OBSV (would-block, allowed) — distinct
    // from EXEC_GATE (real block). The two markers must not cross-detect.
    #[test]
    fn exec_observe_marker_distinct_from_block() {
        let mut data = vec![0u8; 1400];
        assert!(!is_exec_gate_observe(&data));
        data[EXECVE_ARGV0_OFFSET..EXECVE_ARGV0_OFFSET + EXEC_OBSERVE_MARKER.len()]
            .copy_from_slice(EXEC_OBSERVE_MARKER);
        assert!(is_exec_gate_observe(&data));
        assert!(!is_exec_gate_block(&data)); // observe is NOT a block
                                             // and a real block is not an observe
        let mut blk = vec![0u8; 1400];
        blk[EXECVE_ARGV0_OFFSET..EXECVE_ARGV0_OFFSET + EXEC_GATE_MARKER.len()]
            .copy_from_slice(EXEC_GATE_MARKER);
        assert!(is_exec_gate_block(&blk));
        assert!(!is_exec_gate_observe(&blk));
    }

    // Spec 069: the syscall handlers attach as kprobes on the architecture
    // syscall ENTRY WRAPPER. The symbol must match the build-host arch.
    #[test]
    fn syscall_wrapper_symbol_uses_arch_prefix() {
        let sym = syscall_wrapper_symbol("kill");
        if cfg!(target_arch = "aarch64") {
            assert_eq!(sym, "__arm64_sys_kill");
        } else {
            assert_eq!(sym, "__x64_sys_kill");
        }
        // The bare name is always the suffix regardless of arch.
        assert!(syscall_wrapper_symbol("openat").ends_with("sys_openat"));
    }

    // Spec 069: resolve_container_identity is memoised; a second lookup for the
    // same PID must return the same value (PID 0 has no container → None, cached).
    #[test]
    fn resolve_container_identity_is_memoised() {
        let first = resolve_container_identity(0);
        let second = resolve_container_identity(0);
        assert_eq!(first, second);
        assert_eq!(first, None);
    }

    // Spec 069: the cgroup parser is pure; cover Docker/Podman/k8s + no-match.
    // Convenience: the 12-char container id half of the parsed identity.
    #[test]
    fn parse_container_id_from_cgroup_formats() {
        let cid = |s: &str| parse_container_identity_from_cgroup(s).map(|c| c.container_id);
        assert_eq!(
            cid("0::/docker/abcdef0123456789aa"),
            Some("abcdef012345".to_string())
        );
        assert_eq!(
            cid("0::/libpod-fedcba9876543210bb.scope"),
            Some("fedcba987654".to_string())
        );
        assert_eq!(
            cid("0::/kubepods/besteffort/pod1234/0011223344556677"),
            Some("001122334455".to_string())
        );
        // systemd cgroup driver (the real k3s/k8s shape) — previously mis-parsed
        // to the constant "cri-containe" for every pod.
        assert_eq!(
            cid(
                "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pode2ad6fd3_524d.slice/cri-containerd-8317eb4a8dd5fbb4b3f663b25f6d39c943bb1cf0ba0c14b973c9ad069605f57f.scope"
            ),
            Some("8317eb4a8dd5".to_string())
        );
        // systemd-driver Docker + CRI-O.
        assert_eq!(
            cid("0::/system.slice/docker-abcdef0123456789aa.scope"),
            Some("abcdef012345".to_string())
        );
        assert_eq!(
            cid("0::/machine.slice/crio-001122334455667788.scope"),
            Some("001122334455".to_string())
        );
        // Short ids and unrelated lines yield nothing.
        assert_eq!(cid("0::/docker/short"), None);
        assert_eq!(cid("0::/user.slice"), None);
        assert_eq!(cid("0::/"), None);
    }

    // Spec 084 P0: the per-tenant attribution anchors — pod_uid (the k8s pod
    // UID) and runtime — parsed from the cgroup path for BOTH cgroup drivers.
    #[test]
    fn parse_pod_identity_k8s_systemd_driver() {
        // Real k3s/containerd systemd-driver shape: a full 32-hex pod UID is
        // escaped with underscores inside the `kubepods-besteffort-pod<uid>.slice`
        // segment; the container id lives in the `cri-containerd-<id>.scope` leaf.
        let id = parse_container_identity_from_cgroup(
            "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pode2ad6fd3_524d_4f6a_9b1c_0a1b2c3d4e5f.slice/cri-containerd-8317eb4a8dd5fbb4b3f663b25f6d39c943bb1cf0ba0c14b973c9ad069605f57f.scope"
        )
        .expect("k8s pod cgroup must parse");
        assert_eq!(id.container_id, "8317eb4a8dd5");
        assert_eq!(
            id.pod_uid.as_deref(),
            Some("e2ad6fd3-524d-4f6a-9b1c-0a1b2c3d4e5f")
        );
        assert_eq!(id.runtime.as_deref(), Some("containerd"));
    }

    #[test]
    fn parse_pod_identity_k8s_cgroupfs_driver() {
        // cgroupfs driver keeps the canonical dashed UUID and a bare-hex leaf.
        let id = parse_container_identity_from_cgroup(
            "0::/kubepods/burstable/pod3f5a8b2c-1d4e-4f5a-8b2c-9f0a1b2c3d4e/8317eb4a8dd5fbb4b3f663b25f6d39c943bb1cf0ba0c14b973c9ad069605f57f"
        )
        .expect("cgroupfs k8s pod must parse");
        assert_eq!(id.container_id, "8317eb4a8dd5");
        assert_eq!(
            id.pod_uid.as_deref(),
            Some("3f5a8b2c-1d4e-4f5a-8b2c-9f0a1b2c3d4e")
        );
        assert_eq!(id.runtime.as_deref(), Some("containerd"));
    }

    #[test]
    fn parse_identity_runtime_inference() {
        // systemd-driver Docker leaf → docker; bare cgroupfs docker path → docker.
        assert_eq!(
            parse_container_identity_from_cgroup(
                "0::/system.slice/docker-abcdef0123456789aa.scope"
            )
            .and_then(|c| c.runtime),
            Some("docker".to_string())
        );
        assert_eq!(
            parse_container_identity_from_cgroup("0::/docker/abcdef0123456789aa")
                .and_then(|c| c.runtime),
            Some("docker".to_string())
        );
        // CRI-O leaf prefix → crio; podman libpod → podman.
        assert_eq!(
            parse_container_identity_from_cgroup("0::/machine.slice/crio-001122334455667788.scope")
                .and_then(|c| c.runtime),
            Some("crio".to_string())
        );
        assert_eq!(
            parse_container_identity_from_cgroup("0::/libpod-fedcba9876543210bb.scope")
                .and_then(|c| c.runtime),
            Some("podman".to_string())
        );
        // A plain Docker container (no pod) has no pod_uid.
        assert_eq!(
            parse_container_identity_from_cgroup("0::/docker/abcdef0123456789aa")
                .and_then(|c| c.pod_uid),
            None
        );
    }

    #[test]
    fn pod_uid_validator_rejects_non_uuids() {
        assert!(is_pod_uid("3f5a8b2c-1d4e-4f5a-8b2c-9f0a1b2c3d4e")); // dashed
        assert!(is_pod_uid("3f5a8b2c1d4e4f5a8b2c9f0a1b2c3d4e")); // undashed 32 hex
        assert!(!is_pod_uid("1234")); // too short
        assert!(!is_pod_uid("g_not_hex_g_not_hex_g_not_hex_gg")); // non-hex
        assert!(!is_pod_uid("")); // empty
    }

    // Spec 084 P0: GOLD fixtures captured LIVE from a real k3s v1.36.2+k3s1
    // (containerd) node on 2026-06-29 — two pods in two tenant namespaces. The
    // `pod_uid` asserted here is the exact value `kubectl get pod -o
    // jsonpath='{.metadata.uid}'` returned, proving the cgroup-derived UID
    // round-trips to the Kubernetes API object without any label trust. If a
    // future containerd/k3s release changes the cgroup shape this test fails and
    // the parser must be updated to keep per-tenant attribution at 100%.
    #[test]
    fn parse_real_k3s_v136_cgroups_gold() {
        let a = parse_container_identity_from_cgroup(
            "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podd729dbb9_5684_498d_9c5f_7244bfbba548.slice/cri-containerd-4858a7b75b55f36c13e0991cf8370fd2d05edbf33d7d813c06f4cb7a24318025.scope"
        )
        .expect("real k3s pod-a cgroup must parse");
        assert_eq!(a.container_id, "4858a7b75b55");
        assert_eq!(
            a.pod_uid.as_deref(),
            Some("d729dbb9-5684-498d-9c5f-7244bfbba548")
        );
        assert_eq!(a.runtime.as_deref(), Some("containerd"));

        let b = parse_container_identity_from_cgroup(
            "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podb9b2ae1e_9f07_4656_b1f5_71d0f7cb6191.slice/cri-containerd-1a0fb1e4f294cafd9e0da8c2e65de9310bccf1f6f6c950ecb09aa5f9343dfa1c.scope"
        )
        .expect("real k3s pod-b cgroup must parse");
        assert_eq!(b.container_id, "1a0fb1e4f294");
        assert_eq!(
            b.pod_uid.as_deref(),
            Some("b9b2ae1e-9f07-4656-b1f5-71d0f7cb6191")
        );
        assert_eq!(b.runtime.as_deref(), Some("containerd"));
    }

    // Spec 084 P0: directly exercise the pod/runtime enrichment that the ring
    // decode arms apply to every container-scoped event. The decode arms
    // themselves only run against a live kernel ring buffer (covered by the
    // on-box live validation), so these cover the same logic via the helper +
    // builders — the exact `let mut ev = builder(..); attach_pod_runtime(&mut
    // ev.details, cident.as_deref())` shape used in every arm.
    #[test]
    fn attach_pod_runtime_adds_pod_and_runtime() {
        let id = ContainerIdentity {
            container_id: "4858a7b75b55".to_string(),
            pod_uid: Some("d729dbb9-5684-498d-9c5f-7244bfbba548".to_string()),
            runtime: Some("containerd".to_string()),
        };
        let mut details = serde_json::json!({"pid": 1});
        attach_pod_runtime(&mut details, Some(&id));
        assert_eq!(details["pod_uid"], "d729dbb9-5684-498d-9c5f-7244bfbba548");
        assert_eq!(details["runtime"], "containerd");

        // Host process (None) adds nothing.
        let mut bare = serde_json::json!({"pid": 1});
        attach_pod_runtime(&mut bare, None);
        assert!(bare.get("pod_uid").is_none());
        assert!(bare.get("runtime").is_none());

        // A plain Docker container (no pod): runtime present, pod_uid absent.
        let docker = ContainerIdentity {
            container_id: "abcdef012345".to_string(),
            pod_uid: None,
            runtime: Some("docker".to_string()),
        };
        let mut d2 = serde_json::json!({});
        attach_pod_runtime(&mut d2, Some(&docker));
        assert_eq!(d2["runtime"], "docker");
        assert!(d2.get("pod_uid").is_none());
    }

    // Zero-regression guard for the Arc-cached identity: a repeated lookup of
    // the same pid must serve the SAME allocation (a refcount bump), not
    // re-resolve or clone. In a non-container env (typical CI) both resolve to
    // None; the assertion then only checks the cache stays consistent.
    #[test]
    fn resolve_container_identity_cache_shares_the_arc() {
        let pid = std::process::id();
        let a = resolve_container_identity(pid);
        let b = resolve_container_identity(pid);
        match (a, b) {
            (Some(x), Some(y)) => assert!(
                std::sync::Arc::ptr_eq(&x, &y),
                "cache hit must share the Arc, not re-clone the identity"
            ),
            (None, None) => {}
            _ => panic!("cache returned inconsistent Some/None for the same pid"),
        }
    }

    #[test]
    fn builders_then_attach_carry_full_pod_identity() {
        let id = ContainerIdentity {
            container_id: "4858a7b75b55".to_string(),
            pod_uid: Some("d729dbb9-5684-498d-9c5f-7244bfbba548".to_string()),
            runtime: Some("containerd".to_string()),
        };
        // execve
        let mut ev = execve_to_event(
            0,
            0,
            1,
            99,
            Some("4858a7b75b55"),
            "bash",
            "/usr/bin/id",
            vec![],
            "h",
        );
        attach_pod_runtime(&mut ev.details, Some(&id));
        assert_eq!(ev.details["container_id"], "4858a7b75b55");
        assert_eq!(
            ev.details["pod_uid"],
            "d729dbb9-5684-498d-9c5f-7244bfbba548"
        );
        assert_eq!(ev.details["runtime"], "containerd");
        assert!(ev.tags.contains(&"container".to_string()));

        // connect
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        let mut ev = connect_to_event(
            0,
            0,
            1,
            99,
            Some("4858a7b75b55"),
            "curl",
            ip,
            443,
            "h",
            None,
        );
        attach_pod_runtime(&mut ev.details, Some(&id));
        assert_eq!(
            ev.details["pod_uid"],
            "d729dbb9-5684-498d-9c5f-7244bfbba548"
        );
        assert_eq!(ev.details["runtime"], "containerd");

        // file_open
        let mut ev = file_open_to_event(
            0,
            0,
            1,
            99,
            Some("4858a7b75b55"),
            "cat",
            "/etc/hostname",
            0,
            "h",
            None,
        );
        attach_pod_runtime(&mut ev.details, Some(&id));
        assert_eq!(ev.details["runtime"], "containerd");

        // privesc inside a container is Critical; comm not in PRIVESC_ALLOWED.
        let mut ev =
            privesc_to_event(0, 1000, 0, 99, Some("4858a7b75b55"), "zz_attacker", "h").unwrap();
        attach_pod_runtime(&mut ev.details, Some(&id));
        assert_eq!(
            ev.details["pod_uid"],
            "d729dbb9-5684-498d-9c5f-7244bfbba548"
        );
        assert_eq!(ev.severity, Severity::Critical);
    }

    #[test]
    fn execve_event_maps_to_shell_command_exec() {
        // Use PID 0 to avoid reading /proc/<pid>/cmdline of a real process.
        let event = execve_to_event(
            0,
            0,
            1,
            0,
            None,
            "bash",
            "/usr/bin/curl",
            vec![],
            "test-host",
        );
        assert_eq!(event.source, "ebpf");
        assert_eq!(event.kind, "shell.command_exec");
        assert!(event.summary.contains("curl"));
        assert_eq!(event.details["pid"], 0);
        assert_eq!(event.details["ppid"], 1);
    }

    #[test]
    fn execve_prefers_kernel_argv_over_proc() {
        // A short-lived rm exits before /proc can be read; the in-kernel argv is
        // the only reliable source of `-rf` + the target. When the kernel gives us
        // the full argv, it must be used verbatim (not the /proc[pid=0] fallback).
        let kargv = vec![
            "/usr/bin/rm".to_string(),
            "-rf".to_string(),
            "/home/user/data".to_string(),
        ];
        let event = execve_to_event(0, 0, 1, 0, None, "rm", "/usr/bin/rm", kargv, "h");
        assert_eq!(event.details["argc"], 3);
        assert_eq!(event.details["command"], "/usr/bin/rm -rf /home/user/data");
        assert_eq!(event.details["argv"][1], "-rf");
        assert_eq!(event.details["argv"][2], "/home/user/data");
    }

    #[test]
    fn execve_event_with_container() {
        let event = execve_to_event(
            1234,
            0,
            1,
            12345,
            Some("abc123def456"),
            "bash",
            "/usr/bin/curl",
            vec![],
            "test-host",
        );
        assert_eq!(event.details["container_id"], "abc123def456");
        assert_eq!(event.details["cgroup_id"], 12345);
        assert!(event.tags.contains(&"container".to_string()));
    }

    #[test]
    fn connect_event_high_severity_for_reverse_shell_ports() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let event = connect_to_event(5678, 1000, 1, 0, None, "nc", ip, 4444, "test-host", None);
        assert_eq!(event.severity, Severity::High);

        let event_normal =
            connect_to_event(5678, 1000, 1, 0, None, "curl", ip, 443, "test-host", None);
        assert_eq!(event_normal.severity, Severity::Info);
    }

    #[test]
    fn connect_event_carries_exe_path_when_present() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let event = connect_to_event(
            5678,
            1000,
            1,
            0,
            None,
            "unifiedmonitori",
            ip,
            443,
            "test-host",
            Some("/snap/oracle-cloud-agent/95/plugins/unifiedmonitoring/unifiedmonitoring"),
        );
        assert_eq!(
            event.details["exe_path"],
            "/snap/oracle-cloud-agent/95/plugins/unifiedmonitoring/unifiedmonitoring"
        );
    }

    #[test]
    fn connect_event_with_container() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let event = connect_to_event(
            5678,
            1000,
            1,
            99999,
            Some("container123"),
            "nc",
            ip,
            4444,
            "test-host",
            None,
        );
        assert_eq!(event.details["container_id"], "container123");
        assert!(event.tags.contains(&"container".to_string()));
    }

    #[test]
    fn file_open_event_write_to_shadow() {
        let event = file_open_to_event(
            100,
            0,
            1,
            0,
            None,
            "vim",
            "/etc/shadow",
            0x1, // O_WRONLY
            "test-host",
            None,
        );
        assert_eq!(event.kind, "file.write_access");
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.details["ppid"], 1);
    }

    #[test]
    fn file_open_event_read_normal() {
        let event = file_open_to_event(
            100,
            1000,
            1,
            0,
            None,
            "cat",
            "/etc/passwd",
            0x0, // O_RDONLY
            "test-host",
            None,
        );
        assert_eq!(event.kind, "file.read_access");
        assert_eq!(event.severity, Severity::Info);
        // No exe_path passed -> the field is absent (data_exfil then falls back to
        // the comm exemption).
        assert!(event.details.get("exe_path").is_none());
    }

    #[test]
    fn file_open_event_carries_exe_path_when_present() {
        // The non-forgeable exe path (from the execve cache) is stamped onto file
        // read/write events so data_exfil_ebpf can reject a comm-spoofed daemon
        // reading from an untrusted path (`cp evil /tmp/sshd`).
        let event = file_open_to_event(
            100,
            1000,
            1,
            0,
            None,
            "sshd",
            "/home/u/.aws/credentials",
            0x0,
            "test-host",
            Some("/tmp/sshd"),
        );
        assert_eq!(event.details["exe_path"], "/tmp/sshd");
    }

    #[test]
    fn bytes_to_string_handles_null_terminator() {
        let buf = b"hello\0world\0\0\0";
        assert_eq!(bytes_to_string(buf), "hello");
    }

    #[test]
    fn ebpf_availability_on_non_linux() {
        if cfg!(target_os = "macos") {
            assert!(!is_ebpf_available());
        }
    }

    #[test]
    fn classify_ebpf_available_when_all_prereqs_met() {
        assert_eq!(
            classify_ebpf_availability(true, Some("6.8.0-generic"), true, true),
            None
        );
        // 5.8 exactly is the floor and is allowed.
        assert_eq!(
            classify_ebpf_availability(true, Some("5.8.0"), true, true),
            None
        );
    }

    #[test]
    fn classify_ebpf_reasons_are_specific_and_ordered() {
        // Non-Linux short-circuits before any kernel/BTF check.
        assert!(classify_ebpf_availability(false, Some("6.8.0"), true, true)
            .unwrap()
            .contains("Linux"));
        // Unreadable osrelease.
        assert!(classify_ebpf_availability(true, None, true, true)
            .unwrap()
            .contains("osrelease"));
        // Kernel too old names the version and the 5.8 floor.
        let old = classify_ebpf_availability(true, Some("4.18.0-el8"), true, true).unwrap();
        assert!(old.contains("4.18") && old.contains("5.8"));
        // 5.7 is just under the floor.
        assert!(classify_ebpf_availability(true, Some("5.7.19"), true, true)
            .unwrap()
            .contains("5.8"));
        // BTF missing (the common RHEL8 / custom-kernel silent case).
        assert!(classify_ebpf_availability(true, Some("6.8.0"), false, true)
            .unwrap()
            .contains("BTF"));
        // Bytecode missing.
        assert!(classify_ebpf_availability(true, Some("6.8.0"), true, false)
            .unwrap()
            .contains("bytecode"));
    }

    #[test]
    fn classify_ebpf_reasons_have_no_em_dashes() {
        for reason in [
            classify_ebpf_availability(false, Some("6.8.0"), true, true),
            classify_ebpf_availability(true, None, true, true),
            classify_ebpf_availability(true, Some("4.18.0"), true, true),
            classify_ebpf_availability(true, Some("6.8.0"), false, true),
            classify_ebpf_availability(true, Some("6.8.0"), true, false),
        ]
        .into_iter()
        .flatten()
        {
            assert!(!reason.contains('\u{2014}'), "no em dashes: {reason}");
        }
    }

    #[test]
    fn resolve_ppid_nonexistent_process() {
        // PID 999999999 shouldn't exist
        assert_eq!(resolve_ppid(999_999_999), 0);
    }

    #[test]
    fn resolve_container_id_host_process() {
        // Host process shouldn't have a container ID
        // (pid 1 is always the init process on the host)
        if cfg!(target_os = "linux") {
            assert!(resolve_container_identity(1).is_none());
        }
    }

    // ── spec 050-PR1 follow-up #662 follow-up: kernel-first ppid resolution ──
    //
    // The eBPF event struct already carries `task_struct->real_parent->tgid`;
    // userspace must prefer it over a /proc/<pid>/status race-y read. Smoke
    // test 2026-05-17 captured 10 disguised recon execs (whoami, id, ...)
    // all landing with ppid=0 because /proc read happened after the
    // short-lived processes had exited.

    #[test]
    fn resolve_ppid_kernel_first_uses_kernel_value_when_nonzero() {
        // Pass a clearly-nonexistent pid so the /proc fallback would
        // return 0; assert the function still returns the kernel value.
        let kernel_ppid = 12345;
        let result = resolve_ppid_kernel_first(kernel_ppid, 4_000_000_000);
        assert_eq!(
            result, kernel_ppid,
            "kernel-provided ppid must win over /proc fallback"
        );
    }

    #[test]
    fn resolve_ppid_kernel_first_falls_back_to_proc_when_kernel_zero() {
        // Kernel value = 0 → fall back to /proc. The fallback for a
        // nonexistent pid is also 0; the contract is that the function
        // is correctly DELEGATING (not crashing, not panicking).
        let result = resolve_ppid_kernel_first(0, 4_000_000_000);
        assert_eq!(
            result, 0,
            "fallback for nonexistent pid yields 0 (delegation contract)"
        );
    }

    #[test]
    fn resolve_ppid_kernel_first_falls_back_to_real_proc_data_when_available() {
        // When the pid exists in /proc and kernel value is 0, fall back
        // and pick up the real ppid. PID 1 (init) is always present
        // and has ppid 0 — but the systemd PID 1 case is an edge:
        // anything with PID > 1 has a real ppid. Run only on Linux.
        if cfg!(target_os = "linux") {
            let result_for_self = resolve_ppid_kernel_first(0, std::process::id());
            // The test process has a real parent (the test runner or
            // cargo). ppid should be nonzero.
            assert!(
                result_for_self > 0,
                "self pid={} via /proc fallback yielded ppid=0, expected nonzero",
                std::process::id()
            );
        }
    }

    // SEC-001: eBPF availability tests
    #[test]
    fn ebpf_availability_non_linux_returns_false() {
        // On macOS (CI/dev), should always return false
        if cfg!(not(target_os = "linux")) {
            assert!(!is_ebpf_available());
        }
    }

    #[test]
    fn ebpf_obj_paths_are_absolute() {
        assert!(EBPF_OBJ_PATH.starts_with('/'));
    }

    #[test]
    fn has_ebpf_bytecode_returns_bool() {
        // Without the ebpf-embedded feature, checks disk paths which don't
        // exist in dev/CI — returns false. With embedded, returns true.
        // Either way, the function must not panic.
        let result = has_ebpf_bytecode();
        if cfg!(feature = "ebpf-embedded") {
            assert!(result);
        } else {
            // On dev machines the bytecode files typically don't exist
            // (they're only built with `cargo +nightly build --target bpfel-unknown-none`)
            let _ = result; // just verify it doesn't panic
        }
    }

    #[test]
    fn resolve_target_comm_only_reads_proc_for_killing_signals() {
        // Non-killing signals never touch /proc => always empty, no I/O.
        assert_eq!(resolve_target_comm(0, 1), ""); // signal 0 (liveness probe)
        assert_eq!(resolve_target_comm(17, 1), ""); // SIGCHLD
        assert_eq!(resolve_target_comm(18, 1), ""); // SIGCONT
        assert_eq!(resolve_target_comm(28, 1), ""); // SIGWINCH
                                                    // Killing signals attempt /proc resolution; PID 0 is never a real
                                                    // target so proc_comm() returns None => empty, deterministically.
        assert_eq!(resolve_target_comm(9, 0), ""); // SIGKILL
        assert_eq!(resolve_target_comm(6, 0), ""); // SIGABRT (newly covered)
        assert_eq!(resolve_target_comm(40, 0), ""); // real-time signal
        assert_eq!(resolve_target_comm(19, 0), ""); // SIGSTOP
    }

    // ---- InnerWarden self-suppression (CGROUP_ALLOWLIST seeding) ----

    #[test]
    fn parse_cgroup_v2_rel_path_extracts_the_unified_path() {
        // cgroup v2: single "0::<path>" line.
        assert_eq!(
            parse_cgroup_v2_rel_path("0::/system.slice/innerwarden-agent.service\n"),
            Some("/system.slice/innerwarden-agent.service")
        );
        // Root cgroup.
        assert_eq!(parse_cgroup_v2_rel_path("0::/\n"), Some("/"));
        // cgroup v1 (no "0::" line) → None, we only handle v2.
        assert_eq!(
            parse_cgroup_v2_rel_path("12:devices:/\n11:memory:/system.slice\n"),
            None
        );
        assert_eq!(parse_cgroup_v2_rel_path(""), None);
    }

    #[test]
    fn is_innerwarden_exe_is_nonforgeable_and_dir_scoped() {
        let dir = std::path::Path::new("/usr/local/bin");
        // Our own binaries in the install dir → true.
        for b in [
            "innerwarden-sensor",
            "innerwarden-agent",
            "innerwarden-watchdog",
            "innerwarden-supervisor",
        ] {
            assert!(is_innerwarden_exe(&dir.join(b), dir), "{b} should match");
        }
        // Right name, WRONG directory (a dropped/renamed copy) → false: an
        // attacker can't drop /tmp/innerwarden-evil to get itself suppressed.
        assert!(!is_innerwarden_exe(
            std::path::Path::new("/tmp/innerwarden-evil"),
            dir
        ));
        // In the dir but not one of ours → false.
        assert!(!is_innerwarden_exe(&dir.join("bash"), dir));
        // Prefix-only collision outside the family is still gated by the dir +
        // the `innerwarden-` (with dash) prefix.
        assert!(!is_innerwarden_exe(&dir.join("innerwardenX"), dir));
    }

    #[test]
    fn cgroup_allowlist_delta_adds_new_and_drops_stale() {
        use std::collections::BTreeSet;
        // First run: nothing tracked yet → everything current is added.
        let current: BTreeSet<u64> = [10, 20, 30].into_iter().collect();
        let prev: BTreeSet<u64> = BTreeSet::new();
        let (add, remove) = cgroup_allowlist_delta(&current, &prev);
        assert_eq!(add, vec![10, 20, 30]);
        assert!(remove.is_empty());

        // Agent restarted: its old cgroup (20) is gone, a new one (40) appeared.
        let prev: BTreeSet<u64> = [10, 20, 30].into_iter().collect();
        let current: BTreeSet<u64> = [10, 30, 40].into_iter().collect();
        let (add, remove) = cgroup_allowlist_delta(&current, &prev);
        assert_eq!(add, vec![40], "the restarted service's new cgroup is added");
        assert_eq!(remove, vec![20], "the stale cgroup is dropped, not leaked");

        // Steady state: no churn → no map writes.
        let (add, remove) = cgroup_allowlist_delta(&current, &current);
        assert!(add.is_empty() && remove.is_empty());
    }

    #[test]
    fn cgroup_dir_path_joins_unified_mount_with_the_relative_path() {
        use std::path::Path;
        // A normal service cgroup: <mount>/<rel> with the single leading slash
        // collapsed (join would otherwise treat "/system.slice" as absolute and
        // discard the mount).
        assert_eq!(
            cgroup_dir_path("0::/system.slice/innerwarden-agent.service\n"),
            Some(Path::new("/sys/fs/cgroup/system.slice/innerwarden-agent.service").to_path_buf())
        );
        // Root cgroup → the mount itself.
        assert_eq!(
            cgroup_dir_path("0::/\n"),
            Some(Path::new("/sys/fs/cgroup").to_path_buf())
        );
        // A nested k8s pod cgroup, the shape the tenancy resolver walks.
        assert_eq!(
            cgroup_dir_path("0::/kubepods/besteffort/pod13e125db/abc123\n"),
            Some(Path::new("/sys/fs/cgroup/kubepods/besteffort/pod13e125db/abc123").to_path_buf())
        );
        // cgroup v1 (no "0::" line) → None: we never fabricate a path.
        assert_eq!(cgroup_dir_path("11:memory:/system.slice\n"), None);
    }

    #[test]
    fn select_self_cgroups_keeps_only_our_binaries_in_the_install_dir() {
        use std::collections::BTreeSet;
        use std::path::Path;
        let dir = Path::new("/usr/local/bin");

        let sensor = dir.join("innerwarden-sensor");
        let agent = dir.join("innerwarden-agent");
        let watchdog = dir.join("innerwarden-watchdog");
        let bash = dir.join("bash");
        let evil = Path::new("/tmp/innerwarden-evil");
        let agent_no_cgroup = dir.join("innerwarden-supervisor");

        let procs: Vec<(&Path, Option<u64>)> = vec![
            (sensor.as_path(), Some(100)),
            (agent.as_path(), Some(200)),
            (watchdog.as_path(), Some(300)),
            (bash.as_path(), Some(400)),       // not ours → dropped
            (evil, Some(500)),                 // wrong dir → dropped (no evasion)
            (agent_no_cgroup.as_path(), None), // ours but cgroup gone → dropped
        ];

        let got = select_self_cgroups(procs, dir);
        let want: BTreeSet<u64> = [100, 200, 300].into_iter().collect();
        assert_eq!(got, want);
    }

    // CROSS-TEST: the no-regression invariant. Self-suppression must NEVER hide a
    // non-InnerWarden process — that is exactly the bug that would make a rogue
    // tenant invisible. A renamed/dropped copy in the wrong dir, an ordinary host
    // binary, and a same-prefix impostor must all be excluded; only the genuine
    // install-dir binaries survive. If a future refactor widens the exe filter
    // this test fails before the change can ship.
    #[test]
    fn self_suppression_never_selects_a_non_innerwarden_cgroup() {
        use std::path::Path;
        let dir = Path::new("/usr/local/bin");

        // Every shape an attacker (or a regression) might use to sneak in.
        let attacker_shapes = [
            Path::new("/tmp/innerwarden-evil").to_path_buf(), // right name, wrong dir
            Path::new("/home/user/innerwarden-agent").to_path_buf(), // copied elsewhere
            dir.join("innerwardenX"),                         // prefix collision, no dash
            dir.join("bash"),                                 // ordinary host tool
            dir.join("sshd"),                                 // ordinary host daemon
            Path::new("/usr/bin/python3").to_path_buf(),      // a rogue agent runtime
        ];
        for (i, exe) in attacker_shapes.iter().enumerate() {
            let id = 900 + i as u64;
            let got = select_self_cgroups(vec![(exe.as_path(), Some(id))], dir);
            assert!(
                got.is_empty(),
                "{} must NOT be suppressed (would hide a real process)",
                exe.display()
            );
        }

        // Sanity floor: a genuine binary in the install dir IS selected, so the
        // test above is proving exclusion, not just an always-empty function.
        let real = dir.join("innerwarden-agent");
        assert_eq!(
            select_self_cgroups(vec![(real.as_path(), Some(42))], dir),
            std::collections::BTreeSet::from([42])
        );
    }

    // Integration smoke (Linux only): the live I/O path resolves a real cgroup id
    // for our own pid (proc 0 alias) without panicking. This is the only test
    // that touches /proc + /sys/fs/cgroup, so it is the thin wrapper's coverage.
    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_id_of_pid_resolves_self_on_linux() {
        // "self" is a valid /proc entry but not all-ascii-digits, so go through
        // our real numeric pid the way the scanner does.
        let pid = std::process::id().to_string();
        // On a cgroup-v2 host this is Some(inode); on a v1-only or restricted
        // host it is None. Either way it must not panic — that is the contract.
        let _ = cgroup_id_of_pid(&pid);
        // And the pure path builder agrees with what /proc/<pid>/cgroup says.
        if let Ok(content) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
            if content.lines().any(|l| l.starts_with("0::")) {
                assert!(
                    cgroup_dir_path(&content).is_some(),
                    "v2 host must yield a cgroup dir path"
                );
            }
        }
    }
}
