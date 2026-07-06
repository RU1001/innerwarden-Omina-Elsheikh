//! Inner Warden eBPF programs - kernel-level security monitoring.
//!
//! Tracepoints:
//!   - sys_enter_execve: captures every process execution
//!   - sys_enter_connect: captures outbound network connections
//!   - sys_enter_openat: captures sensitive file access
//!   - sched_process_exit: captures process exits (rootkit detection)
//!
//! Kprobes:
//!   - commit_creds: detects privilege escalation (uid 1000 → uid 0)
//!
//! LSM (Linux Security Modules):
//!   - bprm_check_security: blocks execution from /tmp, /dev/shm (policy-gated)
//!
//! XDP:
//!   - innerwarden_xdp: wire-speed IP blocking at the network driver level
//!
//! Events are sent to userspace via a shared ring buffer.
//! Blocked IPs are managed via a shared HashMap (agent ↔ kernel).

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_task, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, kretprobe, lsm, map, tracepoint, xdp},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, ProbeContext, RetProbeContext, TracePointContext, XdpContext},
};

// raw_tracepoint + RawTracePointContext are used by the always-on
// `sched_process_exit` handler (spec 069 Phase 1).
use aya_ebpf::{macros::raw_tracepoint, programs::RawTracePointContext};
use aya_log_ebpf::info;
use innerwarden_ebpf_types::{
    AcceptEvent, AcpiEvalEvent, BpfLoadEvent, CloneEvent, ConnectEvent, DupEvent, ExecveEvent,
    IopermEvent, IoplEvent, KillEvent, ListenEvent, LsmDecisionEvent, MemfdCreateEvent,
    ModuleLoadEvent, MountEvent, MprotectEvent, MsrWriteEvent, PrctlEvent, PrivEscEvent,
    ProcessExitEvent, PtraceEvent, RenameEvent, SetUidEvent, SetnsEvent, SocketBindEvent,
    SyscallKind, TimingProbeEvent, TimingTarget, TruncateEvent, UnlinkEvent, UtimensatEvent,
    MAX_ARGS, MAX_ARG_LEN, MAX_COMM_LEN, MAX_FILENAME_LEN,
};

// ---------------------------------------------------------------------------
// Ring buffer - shared between all eBPF programs, read by userspace
// ---------------------------------------------------------------------------

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0); // 4 MB ring buffer (spec 069: kprobe syscall handlers produce real events; absorb bursts)

// ---------------------------------------------------------------------------
// XDP blocklist - IPv4 addresses to drop at wire speed
// ---------------------------------------------------------------------------
//
// Populated by the agent via aya userspace API.
// Key: IPv4 address as u32 (network byte order)
// Value: flags (1 = block, 0 = removed/placeholder)
// Max 10,000 IPs - enough for most threat scenarios.

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(10_000, 0);

/// XDP allowlist - IPs that must NEVER be dropped, regardless of blocklist.
/// Operator IPs, payment gateways, CDN ranges, API partners.
/// Checked BEFORE blocklist: allowlist wins.
#[map]
static ALLOWLIST: HashMap<u32, u32> = HashMap::with_max_entries(1_000, 0);

/// IPv6 blocklist - same as BLOCKLIST but keyed by 128-bit IPv6 address.
#[map]
static BLOCKLIST_V6: HashMap<[u8; 16], u32> = HashMap::with_max_entries(10_000, 0);

/// IPv6 allowlist - same as ALLOWLIST but keyed by 128-bit IPv6 address.
#[map]
static ALLOWLIST_V6: HashMap<[u8; 16], u32> = HashMap::with_max_entries(1_000, 0);

// ---------------------------------------------------------------------------
// Kernel-level noise filters - populated by userspace, checked before emit
// ---------------------------------------------------------------------------

/// Comm allowlist - processes that should never trigger alerts.
/// Key: first 16 bytes of comm name (zero-padded).
/// Value: bitmask of handlers to skip (bit 0=execve, 1=connect, 2=openat,
///   3=ptrace, 4=setuid, 5=bind, 6=mount, 7=memfd, 8=init_module, ...,
///   18=setns).
/// Populated by agent on boot from config (e.g., cargo, rustc, apt, systemd).
#[map]
static COMM_ALLOWLIST: HashMap<[u8; 16], u32> = HashMap::with_max_entries(256, 0);

/// Cgroup allowlist - containers that are known-safe (monitoring, database).
/// Key: cgroup_id. Value: 1 = skip all non-critical events.
/// Populated by agent from container inventory.
#[map]
static CGROUP_ALLOWLIST: HashMap<u64, u32> = HashMap::with_max_entries(128, 0);

/// InnerWarden's OWN service cgroups (sensor, agent, watchdog, supervisor).
/// Key: cgroup_id. Value: 1. Populated by the userspace loader from non-forgeable
/// `/proc/<pid>/exe` identity, refreshed in the ring loop. Checked FIRST in the
/// high-volume handlers via `is_self_cgroup()` so InnerWarden's own syscalls —
/// including the integrity collector's credential reads — are dropped before the
/// ring reserve and never flood the buffer or self-alert. DISTINCT from
/// CGROUP_ALLOWLIST (known-safe containers, non-secret gate only): this map fully
/// mutes a cgroup, so only our own non-forgeable cgroups may ever enter it — a
/// container can never be silenced through it.
#[map]
static SELF_CGROUP: HashMap<u64, u32> = HashMap::with_max_entries(16, 0);

/// Per-PID rate limiter - prevents ring buffer flood from noisy processes.
/// Key: PID. Value: last emission timestamp (ktime_ns).
/// If a PID emitted within the last RATE_LIMIT_NS, the event is dropped.
/// Cleaned up periodically by userspace.
#[map]
static PID_RATE_LIMIT: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

// ---------------------------------------------------------------------------
// Kill Chain Detection - per-PID syscall correlation
// ---------------------------------------------------------------------------
//
// Tracks syscall sequences per PID to detect attack patterns in the kernel.
// Each handler sets a bit flag. When the accumulated flags match a known
// attack pattern, the LSM denies execution.
//
// Bit flags:
//   0 = socket/connect (outbound)     4 = bind (server socket)
//   1 = dup2 fd→stdin (0)             5 = listen (server ready)
//   2 = dup2 fd→stdout (1)            6 = ptrace (injection)
//   3 = dup2 fd→stderr (2)            7 = mprotect RWX (shellcode)
//   8 = openat sensitive path          (credential/config read)
//
// Attack patterns (bitwise AND):
//   REVERSE_SHELL = socket + dup(stdin) + dup(stdout) = 0b0000_0111 = 0x07
//   BIND_SHELL    = bind + listen + dup(stdin) + dup(stdout) = 0b0011_0110 = 0x36
//   CODE_INJECT   = ptrace + mprotect(RWX) = 0b1100_0000 = 0xC0
//   DATA_EXFIL    = sensitive_read + socket = 0b1_0000_0001 = 0x101

/// Per-PID kill chain flags. Key: PID. Value: accumulated bit flags.
/// Checked by LSM before allowing execve. Cleaned on process exit.
#[map]
static PID_CHAIN: HashMap<u32, u32> = HashMap::with_max_entries(8192, 0);

const CHAIN_SOCKET: u32 = 1 << 0;
const CHAIN_DUP_STDIN: u32 = 1 << 1;
const CHAIN_DUP_STDOUT: u32 = 1 << 2;
const CHAIN_DUP_STDERR: u32 = 1 << 3;
const CHAIN_BIND: u32 = 1 << 4;
const CHAIN_LISTEN: u32 = 1 << 5;
const CHAIN_PTRACE: u32 = 1 << 6;
const CHAIN_MPROTECT: u32 = 1 << 7;
const CHAIN_SENSITIVE_READ: u32 = 1 << 8; // openat on /etc/shadow, .ssh/, credentials

const PATTERN_REVERSE_SHELL: u32 = CHAIN_SOCKET | CHAIN_DUP_STDIN | CHAIN_DUP_STDOUT;
const PATTERN_BIND_SHELL: u32 = CHAIN_BIND | CHAIN_LISTEN | CHAIN_DUP_STDIN | CHAIN_DUP_STDOUT;
const PATTERN_CODE_INJECT: u32 = CHAIN_PTRACE | CHAIN_MPROTECT;
// Zero-day exploit patterns - generic, no CVE signature needed:
// Exploit → shellcode: mprotect(RWX) then redirect I/O
const PATTERN_EXPLOIT_SHELL: u32 = CHAIN_MPROTECT | CHAIN_DUP_STDIN | CHAIN_DUP_STDOUT;
// Exploit → inject + shell: ptrace into process then spawn shell
const PATTERN_INJECT_SHELL: u32 = CHAIN_PTRACE | CHAIN_DUP_STDIN;
// Exploit → RWX + outbound: shellcode phones home
const PATTERN_EXPLOIT_C2: u32 = CHAIN_MPROTECT | CHAIN_SOCKET;
// Full exploit chain: RWX memory + inject + redirect + outbound
const PATTERN_FULL_EXPLOIT: u32 = CHAIN_MPROTECT | CHAIN_PTRACE | CHAIN_SOCKET;
// Data exfiltration: read sensitive file + has outbound socket
const PATTERN_DATA_EXFIL: u32 = CHAIN_SENSITIVE_READ | CHAIN_SOCKET;

/// Set a kill chain flag for the current PID.
#[inline(always)]
fn chain_flag(pid: u32, flag: u32) {
    let current = unsafe { PID_CHAIN.get(&pid) }.copied().unwrap_or(0);
    let _ = PID_CHAIN.insert(&pid, &(current | flag), 0);
}

/// Check if PID has accumulated an attack pattern. Returns true if kill chain detected.
#[inline(always)]
fn chain_is_attack(pid: u32) -> bool {
    let flags = unsafe { PID_CHAIN.get(&pid) }.copied().unwrap_or(0);
    if flags == 0 {
        return false;
    }
    // Shell patterns
    (flags & PATTERN_REVERSE_SHELL) == PATTERN_REVERSE_SHELL
        || (flags & PATTERN_BIND_SHELL) == PATTERN_BIND_SHELL
        // Injection patterns
        || (flags & PATTERN_CODE_INJECT) == PATTERN_CODE_INJECT
        // Zero-day exploit patterns
        || (flags & PATTERN_EXPLOIT_SHELL) == PATTERN_EXPLOIT_SHELL
        || (flags & PATTERN_INJECT_SHELL) == PATTERN_INJECT_SHELL
        || (flags & PATTERN_EXPLOIT_C2) == PATTERN_EXPLOIT_C2
        || (flags & PATTERN_FULL_EXPLOIT) == PATTERN_FULL_EXPLOIT
        // Data exfiltration: read credentials/config + outbound socket
        || (flags & PATTERN_DATA_EXFIL) == PATTERN_DATA_EXFIL
}

/// Clear kill chain for a PID (called on process exit).
#[inline(always)]
fn chain_clear(pid: u32) {
    let _ = PID_CHAIN.remove(&pid);
}

/// Minimum nanoseconds between events from the same PID (100ms = 100_000_000 ns).
/// Prevents cargo, find, grep from flooding the ring buffer during builds.
const RATE_LIMIT_NS: u64 = 100_000_000;

/// Exception list - specific (comm, handler) pairs to always skip.
/// Key: first 16 bytes of comm. Value: always 1.
/// More granular than COMM_ALLOWLIST - for processes that are noisy on one
/// handler but relevant on others (e.g., sshd is noisy on openat but
/// critical on connect and setuid).
#[map]
static EXCEPTION_LIST: HashMap<[u8; 16], u32> = HashMap::with_max_entries(512, 0);

// ---------------------------------------------------------------------------
// Shared filter helpers
// ---------------------------------------------------------------------------

/// Check if the current process comm is in the allowlist for this handler.
/// Returns true if the event should be SKIPPED (process is allowed).
#[inline(always)]
fn is_comm_allowed(handler_bit: u32) -> bool {
    if let Ok(comm) = bpf_get_current_comm() {
        let mut key = [0u8; 16];
        let len = comm.len().min(16);
        key[..len].copy_from_slice(&comm[..len]);

        if let Some(&mask) = unsafe { COMM_ALLOWLIST.get(&key) } {
            return mask & (1 << handler_bit) != 0;
        }
    }
    false
}

/// Check if the current cgroup is in the allowlist (known-safe container).
/// Returns true if the event should be SKIPPED.
#[inline(always)]
fn is_cgroup_allowed() -> bool {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    unsafe { CGROUP_ALLOWLIST.get(&cgroup_id) }.is_some()
}

/// True when the current task is one of InnerWarden's OWN processes (by cgroup).
/// Drops our own syscalls — including credential reads the integrity collector
/// makes — in-kernel before reserve, so we never flood the ring or alert on
/// ourselves. Non-forgeable: SELF_CGROUP holds only our real service cgroups,
/// seeded from `/proc/<pid>/exe`. Empty by default → no-op until seeded.
#[inline(always)]
fn is_self_cgroup() -> bool {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    unsafe { SELF_CGROUP.get(&cgroup_id) }.is_some()
}

/// Per-PID rate limiter. Returns true if the event should be SKIPPED.
/// Allows max 1 event per RATE_LIMIT_NS per PID per handler.
#[inline(always)]
fn is_rate_limited(pid: u32) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };

    if let Some(&last_ts) = unsafe { PID_RATE_LIMIT.get(&pid) } {
        if now.saturating_sub(last_ts) < RATE_LIMIT_NS {
            return true; // too soon - skip
        }
    }

    // Update timestamp (best-effort, ignore error if map is full)
    let _ = PID_RATE_LIMIT.insert(&pid, &now, 0);
    false
}

// Spec 069 #5: the spec-053 tail-call dispatcher (a single `sys_enter`
// raw_tracepoint that read the syscall number and `bpf_tail_call`ed into
// per-syscall handlers via a `ProgramArray`) was removed. It was gated behind
// a `dispatcher` cargo feature that is not declared in any manifest, so it
// never compiled — and the approach was abandoned because aya 0.13's
// `bpf_tail_call` silently no-ops on this loader. The live path is per-syscall
// kprobes on the architecture wrapper reading args via the `syscall_arg!`
// macro below. The old `raw_arg` / `syscall_arg_offset` helpers went with it.

// Spec 069: read syscall arguments from a kprobe on the architecture syscall
// wrapper (`__x64_sys_<name>` / `__arm64_sys_<name>`), which takes a single
// `struct pt_regs *`. These are MACROS, not functions, because on the BPF
// target every function-call boundary in this read path silently returned
// garbage (so every arg-filtered handler — kill/openat/connect/... — dropped
// all its events). Three gotchas, all fixed only by fully-inline expansion,
// validated live on kernel 7.0 x86_64 (kill(pid,sig) round-trips exactly):
//   1. The context arg `ctx.arg::<u64>(0)` (the wrapper's pt_regs pointer) must
//      be read on the program's OWNED context, inline — not through a borrowed
//      `&ProbeContext` passed to a helper.
//   2. The pt_regs dereference `bpf_probe_read_kernel(regs + off)` must be
//      inline in the handler, not behind a fn call that takes `regs`.
//   3. The register offset must be a compile-time literal — a runtime
//      `syscall_arg_offset(idx)` mis-reads. `$n` is a literal and the offset is
//      taken in an inline-`const`, so it folds. The wrapper offsets are
//      FRED-safe.

/// Read syscall argument `$n` (0-5) inline from a kprobe handler's OWNED `ctx`.
/// Yields `Result<u64, i64>`. Use inside an `unsafe` block.
///
/// The register offset is selected by a per-arg MACRO ARM (`__sc_off!`) so it
/// expands to a literal at the call site. (`bpf_probe_read_kernel(regs.add(N))`
/// only reads correctly on the BPF target when `N` is a literal; a `const fn`
/// offset behind a value mis-reads.)
macro_rules! syscall_arg {
    ($ctx:expr, $n:tt) => {{
        let __regs = ($ctx).arg::<u64>(0).unwrap_or(0) as *const u8;
        if __regs.is_null() {
            Err(1i64)
        } else {
            bpf_probe_read_kernel(__regs.add(__sc_off!($n)) as *const u64)
        }
    }};
}

/// Read syscall argument `$n` (0-5) inline from an already-resolved entry
/// `pt_regs` pointer (obtained once via `ctx.arg::<u64>(0)` on the owned
/// context). Yields `Result<u64, i64>`. Use inside an `unsafe` block.
macro_rules! syscall_arg_at {
    ($regs:expr, $n:tt) => {
        bpf_probe_read_kernel(($regs).add(__sc_off!($n)) as *const u64)
    };
}

/// Read the `$i`-th entry of an execve `argv[]` array (userspace `char **` at
/// `$base`) into `event.argv[$i]`, updating `$n` to the count captured. `$i`
/// MUST be a literal so the index into the reserved ring entry is constant (the
/// eBPF verifier rejects a runtime index into `event.argv`). Evaluates to `true`
/// when an arg was read, `false` at the argv NULL terminator; callers chain with
/// `&&` so capture stops at the first NULL (manual unroll, no loop). Fail-soft:
/// a bad userspace read stops capture rather than aborting the event.
macro_rules! read_argv_slot {
    ($base:expr, $i:literal, $event:expr, $n:expr) => {{
        let slot = ($base as usize + $i * core::mem::size_of::<u64>()) as *const u64;
        let str_addr = unsafe { bpf_probe_read_user(slot) }.unwrap_or(0);
        if str_addr != 0 {
            unsafe {
                let _ = bpf_probe_read_user_str_bytes(str_addr as *const u8, &mut $event.argv[$i]);
            }
            $n = $i as u32 + 1;
            true
        } else {
            false
        }
    }};
}

// Per-arg pt_regs byte offset as a LITERAL (expands at the call site). Two
// arch-specific definitions selected by build-host cfg. Literals are required:
// a runtime/const-fn offset value mis-reads on the BPF target.
#[cfg(iw_arch_x86_64)]
macro_rules! __sc_off {
    // rdi, rsi, rdx, r10, r8, r9
    (0) => {
        112
    };
    (1) => {
        104
    };
    (2) => {
        96
    };
    (3) => {
        56
    };
    (4) => {
        72
    };
    (5) => {
        64
    };
}
#[cfg(iw_arch_aarch64)]
macro_rules! __sc_off {
    // x0..x5
    (0) => {
        0
    };
    (1) => {
        8
    };
    (2) => {
        16
    };
    (3) => {
        24
    };
    (4) => {
        32
    };
    (5) => {
        40
    };
}

// ---------------------------------------------------------------------------
// XDP: innerwarden_xdp - wire-speed IP blocking (IPv4 + IPv6)
// ---------------------------------------------------------------------------
//
// Attached to a network interface. For every incoming packet:
//   1. Parse Ethernet header to determine protocol (IPv4 or IPv6)
//   2. Extract source IP (4 bytes for IPv4, 16 bytes for IPv6)
//   3. Check allowlist FIRST — never drop protected IPs
//   4. Check blocklist — if found → XDP_DROP (packet never reaches kernel stack)
//   5. If not found → XDP_PASS (normal processing)
//
// Performance: 10-25 million packets per second drop rate.
// Zero CPU overhead for dropped packets.

#[xdp]
pub fn innerwarden_xdp(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS, // fail-open: never break networking
    }
}

#[inline(always)]
fn try_xdp_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Need at least Ethernet header (14 bytes)
    if data + 14 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse EtherType (offset 12, 2 bytes)
    let eth_proto = u16::from_be_bytes(unsafe {
        let ptr = data as *const u8;
        [*ptr.add(12), *ptr.add(13)]
    });

    match eth_proto {
        // IPv4 (EtherType 0x0800)
        0x0800 => {
            // Ethernet (14) + IPv4 header (20) = 34 bytes minimum
            if data + 34 > data_end {
                return Ok(xdp_action::XDP_PASS);
            }
            // Source IP at offset 14 (eth) + 12 (ip src) = 26, 4 bytes
            let src_ip = u32::from_ne_bytes(unsafe {
                let ptr = data as *const u8;
                [*ptr.add(26), *ptr.add(27), *ptr.add(28), *ptr.add(29)]
            });
            if unsafe { ALLOWLIST.get(&src_ip) }.is_some() {
                return Ok(xdp_action::XDP_PASS);
            }
            if unsafe { BLOCKLIST.get(&src_ip) }.is_some() {
                return Ok(xdp_action::XDP_DROP);
            }
            Ok(xdp_action::XDP_PASS)
        }
        // IPv6 (EtherType 0x86DD)
        0x86DD => {
            // Ethernet (14) + IPv6 header (40) = 54 bytes minimum
            if data + 54 > data_end {
                return Ok(xdp_action::XDP_PASS);
            }
            // Source IP at offset 14 (eth) + 8 (ipv6 src) = 22, 16 bytes
            let mut src_ip = [0u8; 16];
            unsafe {
                let ptr = data as *const u8;
                let mut i = 0;
                while i < 16 {
                    src_ip[i] = *ptr.add(22 + i);
                    i += 1;
                }
            }
            if unsafe { ALLOWLIST_V6.get(&src_ip) }.is_some() {
                return Ok(xdp_action::XDP_PASS);
            }
            if unsafe { BLOCKLIST_V6.get(&src_ip) }.is_some() {
                return Ok(xdp_action::XDP_DROP);
            }
            Ok(xdp_action::XDP_PASS)
        }
        // Not IP — pass through (ARP, etc.)
        _ => Ok(xdp_action::XDP_PASS),
    }
}

// ---------------------------------------------------------------------------
// Kprobe: commit_creds - privilege escalation detection
// ---------------------------------------------------------------------------
//
// Fires when the kernel applies new credentials to a process.
// Detects: non-root process becoming root through unexpected paths.
//
// commit_creds(struct cred *new) - the `cred` struct contains the new uid.
// We compare current uid (before) with new uid (from cred arg).
// If old_uid != 0 && new_uid == 0 → privilege escalation.
//
// Legitimate escalation (sudo, su, login, sshd, cron) is filtered
// in userspace to avoid false positives.

/// Offset of `uid` field in `struct cred` (after atomic_long_t usage).
/// Linux 5.x+: usage(8) → uid(4) at offset 8.
const CRED_UID_OFFSET: usize = 8;

#[kprobe]
pub fn innerwarden_privesc(ctx: ProbeContext) -> u32 {
    match try_privesc(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_privesc(ctx: &ProbeContext) -> Result<(), i64> {
    // Current uid (before credential change)
    let old_uid = bpf_get_current_uid_gid() as u32;

    // Only care about non-root processes gaining root
    if old_uid == 0 {
        return Ok(());
    }

    // Read the new cred pointer (first argument to commit_creds)
    let cred_ptr: *const u8 = unsafe { ctx.arg(0).ok_or(1i64)? };

    // Read new uid from struct cred (offset 8: after atomic_long_t usage)
    let new_uid: u32 = unsafe {
        bpf_probe_read_kernel(cred_ptr.add(CRED_UID_OFFSET) as *const u32).map_err(|e| e)?
    };

    // Only fire when escalating TO root
    if new_uid != 0 {
        return Ok(());
    }

    // At this point: old_uid != 0, new_uid == 0 → privilege escalation
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let mut entry = match EVENTS.reserve::<PrivEscEvent>(0) {
        Some(e) => e,
        None => return Ok(()), // ring buffer full - fail-open
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::PrivEsc as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.old_uid = old_uid;
    event.new_uid = new_uid;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);

    Ok(())
}

// ---------------------------------------------------------------------------
// LSM: bprm_check_security - block execution from dangerous paths
// ---------------------------------------------------------------------------
//
// Enforces execution policy at the kernel level. When enabled via the
// LSM_POLICY map, blocks binaries executed from:
//   /tmp/       - common staging area for malware
//   /dev/shm/   - shared memory, often used for fileless malware
//   /var/tmp/   - persistent temp, another staging area
//
// Policy map keys:
//   0 = master switch (1 = enforce, 0 = disabled)
//
// Returns 0 to allow, -EPERM (-1) to deny.
// When policy map is empty or key 0 is not set → allow (fail-open).

/// Policy map - controls LSM enforcement.
/// Key 0 = master switch: 0 = disabled (observe only), 1 = enforce (block).
/// Key 1 = sensitive write protection: 0 = observe only, 1 = block writes.
/// Key 2 = gradual mode (overrides key 0/1 when set):
///   0 = disabled, 1 = log-only (allow, emit event), 2 = warn (allow, emit WARN event),
///   3 = enforce (block + emit event). When key 2 > 0, it takes priority over keys 0/1.
/// Managed by the agent via bpftool on the pinned map.
#[map]
static LSM_POLICY: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);

/// Execution Gate allowlist (Active Defence / paid). Key = FNV-1a hash of the
/// executing binary's path (≤256 bytes, NUL-terminated prefix). Value = 1
/// (allowed). Populated by the userspace loader from the signed allowlist; pinned
/// at `/sys/fs/bpf/innerwarden/exec_allowlist` so it survives sensor restart.
///
/// Enforcement is gated by `LSM_POLICY` key 3 (exec-gate mode): 0 = off
/// (dry-run default — the gate is inert), 1 = enforce (an exec whose path-hash is
/// not present is blocked with -EPERM). Path-hash (not inode) is the v1 key: it
/// reuses the filename read the hook already does and avoids fragile per-kernel
/// inode struct offsets; the binary-swap gap is covered by the sensor's FIM.
#[map]
static EXEC_ALLOWLIST: HashMap<u64, u8> = HashMap::with_max_entries(20_000, 0);

/// Execution Gate trusted DIRECTORY-PREFIX allowlist (Active Defence / paid).
/// Key = FNV-1a hash of a directory path prefix INCLUDING its trailing `/`
/// (e.g. `FNV("/var/lib/dpkg/info/")`, `FNV("/etc/cron.daily/")`). An exec whose
/// path lies under ANY trusted prefix is allowed even when its exact path-hash
/// is absent from `EXEC_ALLOWLIST`.
///
/// This is the "managed installer" trust for host-wide enforce: OS-maintenance
/// scripts (dpkg maintainer scripts, initramfs, cron.daily, grub.d, kernel
/// hooks) live in root-only-writable dirs whose per-file path changes every
/// kernel/package version (`linux-image-<ver>.postinst`) but whose parent dir is
/// stable. Exact-hash seeding therefore self-DoSes the next `apt`/kernel update;
/// a stable directory prefix does not. A non-root / hijacked-agent attacker (the
/// gate's threat model — root can disarm the gate) cannot drop a file in these
/// dirs, so prefix trust adds no bypass. Populated + pinned by the userspace
/// loader; empty by default (no prefix trusted) so behaviour is unchanged until
/// the paid loader seeds it.
#[map]
static EXEC_TRUSTED_PREFIX: HashMap<u64, u8> = HashMap::with_max_entries(64, 0);

/// Per-CPU scratch for reading the exec path OFF the stack. `innerwarden_lsm_exec`
/// is already near the 512-byte BPF stack limit; a 256-byte path buffer on its
/// stack overflows the verifier/LLVM limit (caught on the test001 x86_64 build).
/// A per-CPU array holds the scratch buffer at zero stack cost.
#[map]
static EXEC_PATH_SCRATCH: PerCpuArray<[u8; 256]> = PerCpuArray::with_max_entries(1, 0);

/// `linux_binprm` field byte offsets, populated by the userspace loader from
/// kernel BTF (CO-RE) so the Execution Gate works across kernel versions where
/// the struct layout differs. Key 0 = `filename` byte offset (96 on 6.8). The
/// gate falls back to 96 if this map is empty.
#[map]
static BPRM_OFFSETS: HashMap<u32, u32> = HashMap::with_max_entries(4, 0);

/// `task_struct` field byte offsets, populated by the userspace loader from
/// kernel BTF (CO-RE) so the execve handler can read the real parent across
/// kernels. Key 0 = `real_parent` (a `task_struct *`); key 1 = `tgid` (the
/// process PID). Absent / 0 means the handler skips the read and leaves
/// `ppid = 0` (the userspace `/proc/<pid>/status` fallback then applies, i.e.
/// the pre-existing behaviour) — it NEVER reads a guessed offset.
#[map]
static TASK_OFFSETS: HashMap<u32, u32> = HashMap::with_max_entries(4, 0);

/// `task_struct->real_parent->tgid` for the current task: the parent PROCESS's
/// PID, captured in-kernel at execve time. Returns 0 when the BTF offsets are
/// unavailable or any kernel read fails, so the worst case is the pre-existing
/// `ppid = 0` (userspace then reads `/proc`). This exists because the execve
/// hook fires for SHORT-LIVED execs (notably systemd's sealed-executor
/// `fexecve` of `/proc/self/fd/N`) whose `/proc` entry is already gone by the
/// time the userspace ring reader looks — so the `/proc` fallback alone leaves
/// their `ppid = 0`, which made the spec-PR1 fileless-systemd parent-lineage
/// gate inert in prod. Mirrors the Execution Gate's `BPRM_OFFSETS` map-supplied
/// offset + `bpf_probe_read_kernel` pattern; no vmlinux/CO-RE relocation needed.
#[inline(always)]
fn current_real_parent_tgid() -> u32 {
    let rp_off = match unsafe { TASK_OFFSETS.get(&0u32) }.copied() {
        Some(o) if o != 0 => o as usize,
        _ => return 0,
    };
    let tgid_off = match unsafe { TASK_OFFSETS.get(&1u32) }.copied() {
        Some(o) if o != 0 => o as usize,
        _ => return 0,
    };
    let task = unsafe { bpf_get_current_task() };
    if task == 0 {
        return 0;
    }
    // task_struct->real_parent (a pointer), then ->tgid on that parent.
    let parent = match unsafe { bpf_probe_read_kernel((task as usize + rp_off) as *const u64) } {
        Ok(p) if p != 0 => p,
        _ => return 0,
    };
    match unsafe { bpf_probe_read_kernel((parent as usize + tgid_off) as *const u32) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

/// Execution Gate SCOPE (Active Defence / paid). Key = cgroup id of a process
/// tree the gate should enforce (typically the AI agent's systemd cgroup and any
/// descendant cgroups). Value = 1. Populated by the userspace loader from the
/// resolved agent cgroup id(s); pinned at `/sys/fs/bpf/innerwarden/exec_gate_scope`
/// so it survives sensor restart.
///
/// Used ONLY when `LSM_POLICY` key 4 (scope mode) == 1: the gate then applies
/// solely to tasks whose current cgroup id is present here, and allows every
/// other exec on the host unconditionally (host maintenance, containers, other
/// services are never gated). When key 4 is absent/0 the gate is host-wide, the
/// original behaviour, so this is opt-in with no regression. This is the
/// "zero-trust for the AI agent" scoping: lock the agent's executable surface
/// without touching the rest of the machine.
#[map]
static EXEC_GATE_SCOPE: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

/// Per-PID and per-TGID block list consulted by `innerwarden_lsm_exec_min`.
/// Spec 052 / INV-LSM-06: LRU eviction at capacity so a worm-style burst can't
/// silently drop new registrations. INV-LSM-07: the agent inserts BOTH the PID
/// (thread id) and TGID (process id) of each blocked task — kernel hook checks
/// TGID first, falls back to PID — so cross-thread chains don't slip past.
/// Pinned at `/sys/fs/bpf/innerwarden/blocked_pids` by the userspace loader so
/// the map survives sensor restart. Value byte: 1 = block, anything else = allow.
#[map]
static BLOCKED_PIDS: LruHashMap<u32, u8> = LruHashMap::with_max_entries(4096, 0);

/// sizeof(struct inode) for the running kernel - populated by userspace from BTF.
/// Used for overlayfs upper-layer detection: __upperdentry is at inode_ptr + sizeof(struct inode).
/// Key: 0. Value: sizeof(struct inode) in bytes.
/// Avoids needing BTF for the private ovl_inode struct.
#[map]
static INODE_SIZE: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;

/// Neural anomaly score computed by the agent and written here for kernel-level enforcement.
/// Key 0 = anomaly_score (Q16.16 fixed-point, 0.0-1.0 range → 0-65536).
/// Key 1 = threshold (Q16.16, default 0.75 → 49152).
/// Key 2 = last_update_ns (u64 truncated to i32 low bits — staleness check).
///
/// The agent runs the autoencoder forward pass in userspace (f32 precision),
/// computes the anomaly score, and writes it here via bpftool every 30s.
/// The LSM hook reads the cached score — zero latency added to execve.
///
/// Why not run inference in-kernel:
/// - Stack limit (512B) can't hold input (192B) + intermediate (192B) + weights
/// - 1880 map lookups per execve adds ~100μs latency to every process spawn
/// - Agent-computed score is fresher (uses full event window, not single syscall)
///
/// The kernel enforces the agent's decision at wire speed — the agent is the brain,
/// the kernel is the muscle.
#[map]
static NEURAL_SCORE: HashMap<u32, i32> = HashMap::with_max_entries(4, 0);

/// Per-cgroup capability bitmask. Key: cgroup_id. Value: bitmask of allowed capabilities.
/// Populated by the agent from config. When guard mode is on and a cgroup has a capability
/// bit set, that action is ALLOWED for processes in that cgroup.
#[map]
static CGROUP_CAPABILITIES: HashMap<u64, u32> = HashMap::with_max_entries(256, 0);

/// Per-process capability bitmask. Key: first 16 bytes of comm. Value: bitmask.
/// Same semantics as CGROUP_CAPABILITIES but per process name.
/// Replaces hardcoded byte-comparison allowlists in LSM hooks.
#[map]
static COMM_CAPABILITIES: HashMap<[u8; 16], u32> = HashMap::with_max_entries(256, 0);

/// Check if the current process or its cgroup has a specific capability.
/// Returns true if the action should be ALLOWED.
#[inline(always)]
fn has_capability(cap_bit: u32) -> bool {
    // Check per-cgroup first (more specific)
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if let Some(&caps) = unsafe { CGROUP_CAPABILITIES.get(&cgroup_id) } {
        if caps & cap_bit != 0 {
            return true;
        }
    }
    // Check per-comm
    if let Ok(comm) = bpf_get_current_comm() {
        let mut key = [0u8; 16];
        let len = comm.len().min(16);
        key[..len].copy_from_slice(&comm[..len]);
        if let Some(&caps) = unsafe { COMM_CAPABILITIES.get(&key) } {
            if caps & cap_bit != 0 {
                return true;
            }
        }
    }
    false
}

/// FNV-1a hash of a path buffer up to the first NUL (or 256 bytes). Used as the
/// `EXEC_ALLOWLIST` key for the Execution Gate. Bounded constant loop (256) so
/// the eBPF verifier accepts it; no division, sleepable-safe. The same function
/// runs in userspace (loader) to populate the map, so the keys agree.
#[inline(always)]
fn fnv1a_path(buf: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
    let mut i = 0usize;
    // Bounded by 256 (constant) for the verifier; also by buf.len().
    while i < 256 && i < buf.len() {
        let b = buf[i];
        if b == 0 {
            break;
        }
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime
        i += 1;
    }
    h
}

/// Number of leading directory levels the prefix-trust check considers. Trusted
/// maintenance dirs are shallow (`/var/lib/dpkg/info/` = 4, `/usr/share/
/// initramfs-tools/` = 3), so 8 covers every real prefix. This bounds the map
/// lookups to a small CONSTANT — a lookup inside the byte-scan loop instead blew
/// the eBPF verifier's 1M-instruction budget (256 iters × a branching lookup).
/// Gate decision for the exec at `buf`: exact path-hash on `EXEC_ALLOWLIST`, OR
/// its PARENT DIRECTORY on `EXEC_TRUSTED_PREFIX` (managed-installer trust).
///
/// Verifier budget is the hard constraint here: the exact-allowlist FNV already
/// loops the full 256-byte path and nearly fills the 1M-instruction limit, so a
/// SEPARATE prefix scan, a per-iteration array write, OR a map lookup inside any
/// loop all blow it (measured: each → `processed 1000001 insns`). So this does
/// the cheapest possible thing: the SAME single FNV loop also remembers the
/// running hash at the last `/` — which is `FNV(parent-dir-including-slash)`,
/// exactly the key the loader stores (`FNV("/var/lib/dpkg/info/")`) — as one
/// extra scalar, no lookup/array in the loop. Then just TWO lookups OUTSIDE the
/// loop. Immediate-parent only (not every ancestor), so the loader seeds each
/// concrete maintenance dir incl. nested ones (`/usr/share/initramfs-tools/
/// scripts/local-top/`). Empty prefix map (default) → exact-allowlist-only →
/// unchanged behaviour. Same FNV constants + trailing-slash convention as the
/// loader, so keys agree.
#[inline(always)]
fn exec_gate_allowed(buf: &[u8]) -> bool {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
    let mut parent: u64 = 0; // running hash at the last '/' = FNV(parent dir)
    let mut i = 0usize;
    while i < 256 && i < buf.len() {
        let b = buf[i];
        if b == 0 {
            break;
        }
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime
        if b == b'/' {
            parent = h;
        }
        i += 1;
    }
    if unsafe { EXEC_ALLOWLIST.get(&h) }.is_some() {
        return true; // exact path-hash on the allowlist
    }
    if parent != 0 && unsafe { EXEC_TRUSTED_PREFIX.get(&parent) }.is_some() {
        return true; // parent dir is a trusted maintenance dir
    }
    false
}

// LSM hook entry point. Marked `sleepable` so the program lands in
// the `lsm.s/` ELF section instead of `lsm/`. On kernel ≥ 6.4 the
// verifier tightens the BTF FUNC arg0 check for `lsm/` programs: it
// requires arg0 to match the kernel's `bpf_lsm_<hook>` signature
// (e.g. `*const struct linux_binprm` for bprm_check_security). The
// aya `#[lsm]` macro emits the FUNC with `arg0 = c_void`, so the
// verifier rejects non-sleepable LSM with EINVAL + a BTF type
// mismatch in the log. The `sleepable` flag flips the section to
// `lsm.s/` which uses a different attach path (tracing-style with
// attach_btf_id supplied by libbpf at load time) and bypasses the
// per-program BTF FUNC arg check. Confirmed empirically against the
// Bombini agent on kernel 6.8.0-1052-oracle: their only LSM hook
// that loads is the one marked `sleepable`.
// Constraints to keep this hook sleepable-safe: no bpf_spin_lock,
// no bpf_for_each_map_elem with non-sleepable callbacks. This body
// only does map lookups + ring-buffer writes + bpf_get_current_*
// helpers — all sleepable-compatible. Return -EPERM still works
// (sleepable LSM has supported denial since kernel 5.10).
#[lsm(hook = "bprm_check_security", sleepable)]
pub fn innerwarden_lsm_exec(ctx: LsmContext) -> i32 {
    match try_lsm_exec(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // fail-open: allow on error
    }
}

// ── Execution Gate: DEDICATED minimal LSM program (Active Defence) ─────
// The gate lives in its OWN program, NOT in `innerwarden_lsm_exec` above: that
// full hook fails the verifier on kernel ≥ 6.4 (too complex) and only the
// `_min` hook actually attaches there — so a gate buried in the full hook never
// runs (confirmed on test001 6.8: full hook LoadError EINVAL, gate did not block).
// This program does ONLY the gate (one path read + a bounded FNV + one map
// lookup), keeping total verifier complexity low enough to load on 6.x. Inert
// unless LSM_POLICY key 3 == 1 (license-gated arming). Multiple LSM programs may
// attach to the same hook; any `-EPERM` denies the exec.
#[lsm(hook = "bprm_check_security", sleepable)]
pub fn innerwarden_lsm_exec_gate(ctx: LsmContext) -> i32 {
    match try_exec_gate(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // fail-open: allow on error
    }
}

fn try_exec_gate(ctx: &LsmContext) -> Result<i32, i64> {
    // LSM_POLICY key 3 = exec-gate mode: 0 = off (inert), 1 = enforce (deny
    // unknown with -EPERM), 2 = OBSERVE (emit a would-block event but ALLOW —
    // for safe onboarding: learn the allowlist on a live host without bricking
    // it, then flip to enforce after a clean window). Spec 077 P2.
    let mode = unsafe { LSM_POLICY.get(&3u32) }.copied().unwrap_or(0);
    if mode != 1 && mode != 2 {
        return Ok(0);
    }
    let observe = mode == 2;
    // Agent-scoped enforcement (spec 083): when LSM_POLICY key 4 == 1 the gate
    // applies ONLY to tasks whose cgroup is in EXEC_GATE_SCOPE (the AI agent's
    // cgroup tree). Every other exec on the host — system services, containers,
    // package maintenance — is allowed unconditionally, so a general server can
    // run the gate around just the agent without bricking apt/certbot/Docker.
    // key 4 absent/0 = host-wide (the original, unchanged behaviour). Opt-in, no
    // regression. One map read + (when scoped) one cgroup lookup: verifier-cheap.
    let scoped = unsafe { LSM_POLICY.get(&4u32) }.copied().unwrap_or(0) == 1;
    if scoped {
        let cg = unsafe { bpf_get_current_cgroup_id() };
        if unsafe { EXEC_GATE_SCOPE.get(&cg) }.is_none() {
            return Ok(0); // outside the agent's scope → not gated
        }
    }
    // Read bprm->filename. The byte offset is supplied at load time by the
    // userspace loader from kernel BTF (CO-RE) via BPRM_OFFSETS key 0, so the gate
    // works across kernels — the offset differs (96 on 6.8; `filename` is at
    // bits_offset 768 there, NOT 72 which is `cred`). 96 is the fallback default.
    let bprm_ptr: *const u8 = unsafe { ctx.arg(0) };
    let filename_off = unsafe { BPRM_OFFSETS.get(&0u32) }.copied().unwrap_or(96) as usize;
    let filename_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(bprm_ptr.add(filename_off) as *const *const u8).map_err(|e| e)?
    };
    // Read the path into the per-cpu scratch (off-stack), then hash exactly the
    // bytes `str_bytes` RETURNS (the path without the NUL, no over-read). Hashing
    // the buffer instead was a bug (empty/wrong hash → everything missed → all
    // blocked). Fail-open (allow) if the path cannot be read.
    let scratch = match EXEC_PATH_SCRATCH.get_ptr_mut(0) {
        Some(p) => unsafe { &mut *p },
        None => return Ok(0),
    };
    let path = match unsafe { bpf_probe_read_kernel_str_bytes(filename_ptr, &mut scratch[..]) } {
        Ok(p) => p,
        Err(_) => return Ok(0),
    };
    // Exact path-hash on the allowlist, OR the parent dir is a trusted
    // maintenance dir (managed-installer trust for OS dirs whose per-file paths
    // change every kernel/package version). One FNV pass computes both keys.
    if exec_gate_allowed(path) {
        return Ok(0);
    }

    // Unknown binary under an armed gate — emit a block event carrying the REAL
    // attempted path in `filename` (read straight from bprm->filename, same
    // verifier-proven pattern as the legacy hook) and the b"EXEC_GATE" marker in
    // argv[0] (every other kind-6 emitter zeroes argv, so the marker is
    // unambiguous). The consumer renders it as `lsm.exec_gate_blocked` with the
    // path inline — no fragile execve-event correlation needed (a denied exec
    // leaves /proc/<pid> pointing at the OLD image, so userspace could not
    // recover the attempted path after the fact).
    let pid_tgid = bpf_get_current_pid_tgid();
    let ts = unsafe { bpf_ktime_get_ns() };
    let cg = unsafe { bpf_get_current_cgroup_id() };
    if let Some(mut entry) = EVENTS.reserve::<innerwarden_ebpf_types::ExecveEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::LsmBlocked as u32;
        event.pid = pid_tgid as u32;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = bpf_get_current_uid_gid() as u32;
        event.gid = 0;
        event.ppid = 0;
        event.cgroup_id = cg;
        event.ts_ns = ts;
        event.argc = 0;
        event.argv = [[0u8; 128]; 8];
        event.filename = [0u8; 256];
        let _ = unsafe { bpf_probe_read_kernel_str_bytes(filename_ptr, &mut event.filename) };
        // Marker distinguishes a real block (enforce) from a would-block
        // (observe) so the consumer renders lsm.exec_gate_blocked vs
        // lsm.exec_gate_would_block. Both are 9 bytes.
        let marker: &[u8] = if observe { b"EXEC_OBSV" } else { b"EXEC_GATE" };
        event.argv[0][..marker.len()].copy_from_slice(marker);
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    // Observe mode allows the exec (learning, no brick); enforce denies it.
    if observe {
        Ok(0)
    } else {
        Ok(-1) // unknown binary under an armed gate → -EPERM
    }
}

// ── Spec 052 Phase 1: minimal LSM hook ────────────────────────────────
// Empirically verified on kernel 6.8.0-1052-oracle (branch
// lsm/diagnostic-minimal, since deleted) to load successfully where
// `innerwarden_lsm_exec` above fails. The body deliberately stays
// trivial — only map lookups, helper calls, and a single fixed-shape
// ringbuf submit. Anything that pushes verifier complexity (dentry
// reads, `bpf_probe_read_kernel` traversal, branching state machines)
// goes through the older hook above, which is kept in parallel during
// the Phase 1 soak and retired in Phase 3.
//
// INV-LSM-02: this body must NOT call check_overlay_drift, must NOT
// call `bpf_probe_read_kernel` on dentry/file paths, must NOT emit
// variable-length payloads. Only one `submit` call with the constant
// 24-byte `LsmDecisionEvent`. The CI script
// `scripts/verify-lsm-minimal.sh` grep-checks this contract.
//
// INV-LSM-07: kernel checks the TGID first, then the PID, so a chain
// matched against a thread that is not the one calling execve still
// fires the block.
#[lsm(hook = "bprm_check_security", sleepable)]
pub fn innerwarden_lsm_exec_min(_ctx: LsmContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    // INV-LSM-07: TGID first, PID fallback. Distinct keys covered.
    let blocked_by_tgid = unsafe { BLOCKED_PIDS.get(&tgid) }.copied().unwrap_or(0) != 0;
    let blocked_by_pid =
        !blocked_by_tgid && unsafe { BLOCKED_PIDS.get(&pid) }.copied().unwrap_or(0) != 0;

    if !(blocked_by_tgid || blocked_by_pid) {
        return 0; // allow: no event emitted (silent allow per spec)
    }

    // Emit a 24-byte fixed-shape decision event. Userspace agent joins
    // by pid against the existing `innerwarden_execve` tracepoint stream
    // to recover {comm, filename, uid}. Reason is set by userspace at
    // registration time; the kernel hook can't know it here, so the
    // value sent is a sentinel (0) — Phase 1 follow-up can extend the
    // map value type from u8 to (u8, u8) carrying the reason.
    if let Some(mut entry) = EVENTS.reserve::<LsmDecisionEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::LsmDecision as u32;
        event.pid = pid;
        event.tgid = tgid;
        event.reason = innerwarden_ebpf_types::LSM_HOOK_BPRM_CHECK_SECURITY;
        event.ts_ns = unsafe { bpf_ktime_get_ns() };
        entry.submit(0);
    }
    // If the ringbuf is full we still block — the decision is more
    // important than the event log. Userspace will detect the gap by
    // seeing a process_exit for a pid in BLOCKED_PIDS without a
    // corresponding decision event.

    -1 // -EPERM
}

// ── PR-A: create_user_ns LSM hook (container escape detection) ─────
//
// `security_create_user_ns(struct cred *cred)` fires when a process
// calls `unshare(CLONE_NEWUSER)` or `clone(CLONE_NEWUSER)`. Inside a
// rootless container, this is the primary vector to gain CAP_SYS_ADMIN
// in a new namespace — the foundation for most container-escape
// exploits (CVE-2022-0492 cgroups, CVE-2024-1086, etc).
//
// Default behaviour: observe + block only when PID is in BLOCKED_PIDS.
// We do NOT block unconditionally because legitimate users include
// Chrome's sandbox, podman rootless, snap confinement, Docker rootless,
// Firefox sandbox — all create user namespaces on every launch.
//
// The agent populates BLOCKED_PIDS via the kill chain detector. If a
// PID is registered (because PidTracker matched an attack pattern) and
// that PID then tries to create a user namespace, this hook denies
// with -EPERM and emits LsmDecisionEvent tagged with
// LSM_HOOK_CREATE_USER_NS so the operator dashboard can distinguish
// "blocked exec" from "blocked container escape".
#[lsm(hook = "userns_create", sleepable)]
pub fn innerwarden_lsm_create_user_ns(_ctx: LsmContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    // INV-LSM-07: TGID first, PID fallback.
    let blocked_by_tgid = unsafe { BLOCKED_PIDS.get(&tgid) }.copied().unwrap_or(0) != 0;
    let blocked_by_pid =
        !blocked_by_tgid && unsafe { BLOCKED_PIDS.get(&pid) }.copied().unwrap_or(0) != 0;

    if !(blocked_by_tgid || blocked_by_pid) {
        return 0; // allow (default for non-attack PIDs — no FPs on Chrome/Docker/etc)
    }

    if let Some(mut entry) = EVENTS.reserve::<LsmDecisionEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::LsmDecision as u32;
        event.pid = pid;
        event.tgid = tgid;
        event.reason = innerwarden_ebpf_types::LSM_HOOK_CREATE_USER_NS;
        event.ts_ns = unsafe { bpf_ktime_get_ns() };
        entry.submit(0);
    }

    -1 // -EPERM — block container escape attempt
}

// ── PR-B: ptrace_access_check LSM hook (process injection block) ───
//
// `security_ptrace_access_check(struct task_struct *child, unsigned int mode)`
// fires when a process attempts ptrace(PTRACE_ATTACH/SEIZE/POKETEXT) on
// another. This is the kernel-level gatekeeper for process injection —
// SHELLINJECT, CodeInject, MeterRefactor and most LD_PRELOAD-less
// shellcode loaders pivot through ptrace.
//
// Default behaviour: observe + block only when PID is in BLOCKED_PIDS.
// We do NOT block unconditionally because legitimate ptrace users:
// gdb, strace, lldb, perf, container debug tools, valgrind, rr.
// These never get registered as attackers so they pass through.
//
// Note: this hook only checks the CALLER (tracer). It cannot also
// protect the TARGET (tracee) from a specific PID — that would
// require a second map BLOCKED_TRACE_TARGETS. Phase 2 enhancement.
// Note: ptrace_access_check is NOT in the kernel's sleepable LSM
// allow-list (verifier: "bpf_lsm_ptrace_access_check is not sleepable").
// Use non-sleepable LSM here. Our minimal body has no ctx access and
// no probe_read_kernel calls so the kernel 6.4 verifier complexity
// rejection that motivated Spec 052's sleepable-by-default for the
// other hooks doesn't apply.
#[lsm(hook = "ptrace_access_check")]
pub fn innerwarden_lsm_ptrace_access(_ctx: LsmContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let blocked_by_tgid = unsafe { BLOCKED_PIDS.get(&tgid) }.copied().unwrap_or(0) != 0;
    let blocked_by_pid =
        !blocked_by_tgid && unsafe { BLOCKED_PIDS.get(&pid) }.copied().unwrap_or(0) != 0;

    if !(blocked_by_tgid || blocked_by_pid) {
        return 0; // allow (gdb / strace / lldb / perf all unaffected)
    }

    if let Some(mut entry) = EVENTS.reserve::<LsmDecisionEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::LsmDecision as u32;
        event.pid = pid;
        event.tgid = tgid;
        event.reason = innerwarden_ebpf_types::LSM_HOOK_PTRACE_ACCESS_CHECK;
        event.ts_ns = unsafe { bpf_ktime_get_ns() };
        entry.submit(0);
    }

    -1 // -EPERM — block process injection attempt
}

// ── PR-C: bpf_prog LSM hook (VoidLink-style eBPF weaponization block) ─
//
// `security_bpf_prog(struct bpf_prog *prog)` fires when a BPF program is
// loaded into the kernel via BPF_PROG_LOAD syscall. Modern rootkits
// (VoidLink, Symbiote, BPFDoor) weaponize eBPF — they load programs that
// hide files, intercept syscalls, mask network connections. This hook
// kernel-side-denies the load attempt from chain-flagged PIDs.
//
// Default behaviour: observe + block only when PID is in BLOCKED_PIDS.
// We do NOT block unconditionally — legitimate BPF loaders include:
// innerwarden (us!), systemd-resolved, cilium-agent, falco, custom
// monitoring. They never get registered as attackers → pass through.
//
// Note: the legacy `innerwarden_lsm_bpf` hook (`security_bpf`) is
// kept in parallel — it fires for ALL bpf() syscalls including map
// ops, this one only on program load. Operator can distinguish via
// hook_id in lsm.blocked details.
#[lsm(hook = "bpf_prog", sleepable)]
pub fn innerwarden_lsm_bpf_prog_load(_ctx: LsmContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let blocked_by_tgid = unsafe { BLOCKED_PIDS.get(&tgid) }.copied().unwrap_or(0) != 0;
    let blocked_by_pid =
        !blocked_by_tgid && unsafe { BLOCKED_PIDS.get(&pid) }.copied().unwrap_or(0) != 0;

    if !(blocked_by_tgid || blocked_by_pid) {
        return 0; // allow (innerwarden, systemd, cilium, falco all unaffected)
    }

    if let Some(mut entry) = EVENTS.reserve::<LsmDecisionEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::LsmDecision as u32;
        event.pid = pid;
        event.tgid = tgid;
        event.reason = innerwarden_ebpf_types::LSM_HOOK_BPF_PROG_LOAD;
        event.ts_ns = unsafe { bpf_ktime_get_ns() };
        entry.submit(0);
    }

    -1 // -EPERM — block eBPF weaponization attempt
}

// ── PR-D: mmap_file LSM hook (real-time RWX block) ─────────────────
//
// `security_mmap_file(struct file *file, unsigned long reqprot,
//   unsigned long prot, unsigned long flags)` fires on every mmap()
// of a file. We hook it specifically to deny PROT_EXEC mappings from
// chain-flagged PIDs — the kernel-side equivalent of our proc_maps
// polling for `memory.rwx_memory` events but REAL-TIME (at mmap
// instant, not on next 5s scan).
//
// Default behaviour: observe + block only when PID is in BLOCKED_PIDS.
// We do NOT block all PROT_EXEC mmaps unconditionally — that would
// break every JIT compiler (V8/Node, JVM, PyPy, .NET, LuaJIT) and
// dynamic linker on the system. Legitimate users pass through
// because they're never registered as attackers.
//
// Note: we don't inspect `prot` from ctx because that requires
// `bpf_probe_read_kernel` from args (verifier complexity risk).
// Instead we treat ALL mmap_file calls from blocked PIDs as denial-
// worthy — broad but the block target is already a known attacker.
#[lsm(hook = "mmap_file", sleepable)]
pub fn innerwarden_lsm_mmap_file(_ctx: LsmContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let blocked_by_tgid = unsafe { BLOCKED_PIDS.get(&tgid) }.copied().unwrap_or(0) != 0;
    let blocked_by_pid =
        !blocked_by_tgid && unsafe { BLOCKED_PIDS.get(&pid) }.copied().unwrap_or(0) != 0;

    if !(blocked_by_tgid || blocked_by_pid) {
        return 0; // allow (all JIT compilers + dynamic linkers unaffected)
    }

    if let Some(mut entry) = EVENTS.reserve::<LsmDecisionEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::LsmDecision as u32;
        event.pid = pid;
        event.tgid = tgid;
        event.reason = innerwarden_ebpf_types::LSM_HOOK_MMAP_FILE;
        event.ts_ns = unsafe { bpf_ktime_get_ns() };
        entry.submit(0);
    }

    -1 // -EPERM — block mmap from chain-flagged PID
}

fn try_lsm_exec(ctx: &LsmContext) -> Result<i32, i64> {
    // NB: the Execution Gate lives in its OWN dedicated LSM program
    // (`innerwarden_lsm_exec_gate`) — this full hook fails the verifier on kernel
    // ≥ 6.4, so anything here only runs on older kernels.

    // ── Container drift detection (ALWAYS runs, even without guard mode) ──
    // Check if the binary is on an overlayfs upper layer (dropped after container start).
    // __upperdentry is at inode_ptr + sizeof(struct inode).
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if cgroup_id != 0 {
        // In a container — check for overlayfs drift
        if let Some(&inode_size) = unsafe { INODE_SIZE.get(&0u32) } {
            if inode_size > 0 {
                let _ = check_overlay_drift(ctx, cgroup_id, inode_size);
            }
        }
    }

    // ── Guard mode enforcement ──
    // Key 2 (gradual mode) takes priority over key 0 when set.
    // Mode: 0=disabled, 1=log, 2=warn, 3=enforce
    let gradual_mode = unsafe { LSM_POLICY.get(&2u32) }.copied().unwrap_or(0);
    if gradual_mode > 0 {
        // Gradual mode active: 1=log (allow all), 2=warn (allow all), 3=enforce
        if gradual_mode < 3 {
            // Log/warn mode: events are always emitted by the code below,
            // but we never return -EPERM. The agent reads the events and
            // decides severity based on mode (warn = High, log = Info).
            // Fall through to detection logic but override the block at the end.
        }
        // Mode 3 (enforce) falls through to normal blocking logic.
    } else {
        // Legacy: check key 0 (master switch)
        let enabled = unsafe { LSM_POLICY.get(&0u32) };
        if enabled.is_none() || *enabled.unwrap() == 0 {
            return Ok(0); // policy disabled - allow everything
        }
    }
    let should_block = gradual_mode == 0 || gradual_mode >= 3;

    // Kill chain detection: check both PID and TGID (thread group leader).
    // When a process forks (subprocess.run, os.system), the child has a new PID
    // but the parent's chain flags stay on the parent PID. By checking the TGID
    // (which equals the parent PID for the main thread), we catch cases where
    // the parent accumulated the chain and the child does the execve.
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    if chain_is_attack(pid) || (tgid != pid && chain_is_attack(tgid)) {
        // Emit blocked event before denying
        let uid = bpf_get_current_uid_gid() as u32;
        let ts = unsafe { bpf_ktime_get_ns() };
        let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

        if let Some(mut entry) = EVENTS.reserve::<innerwarden_ebpf_types::ExecveEvent>(0) {
            let event = unsafe { &mut *entry.as_mut_ptr() };
            event.kind = SyscallKind::LsmBlocked as u32;
            event.pid = pid;
            event.tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
            event.uid = uid;
            event.gid = 0;
            event.ppid = 0;
            event.cgroup_id = cgroup_id;
            event.ts_ns = ts;
            event.argc = 0;
            event.argv = [[0u8; 128]; 8];
            event.filename = [0u8; 256];
            // Write "KILL_CHAIN_BLOCKED" as filename
            let msg = b"KILL_CHAIN_BLOCKED";
            event.filename[..msg.len()].copy_from_slice(msg);

            if let Ok(comm) = bpf_get_current_comm() {
                event.comm[..comm.len().min(MAX_COMM_LEN)]
                    .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
            }

            entry.submit(0);
        }

        chain_clear(pid); // Clean up after blocking
        return Ok(-1); // -EPERM: deny execution
    }

    // ── Neural anomaly enforcement ──
    // Read the agent-computed anomaly score from NEURAL_SCORE map.
    // If score > threshold, block execution (high anomaly = likely attack).
    // Score is Q16.16 fixed-point: 0 = normal, 65536 = max anomaly.
    if should_block {
        let score = unsafe { NEURAL_SCORE.get(&0u32) }.copied().unwrap_or(0);
        let threshold = unsafe { NEURAL_SCORE.get(&1u32) }.copied().unwrap_or(49152); // 0.75 default
        if score > threshold && score > 0 {
            // Neural model says this execution context is anomalous.
            // Emit event and block.
            let pid = bpf_get_current_pid_tgid() as u32;
            let uid = bpf_get_current_uid_gid() as u32;
            let ts = unsafe { bpf_ktime_get_ns() };
            let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

            if let Some(mut entry) = EVENTS.reserve::<innerwarden_ebpf_types::ExecveEvent>(0) {
                let event = unsafe { &mut *entry.as_mut_ptr() };
                event.kind = SyscallKind::LsmBlocked as u32;
                event.pid = pid;
                event.tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
                event.uid = uid;
                event.gid = 0;
                event.ppid = 0;
                event.cgroup_id = cgroup_id;
                event.ts_ns = ts;
                event.argc = 0;
                event.argv = [[0u8; 128]; 8];
                event.filename = [0u8; 256];
                let msg = b"NEURAL_ANOMALY_BLOCKED";
                event.filename[..msg.len()].copy_from_slice(msg);
                if let Ok(comm) = bpf_get_current_comm() {
                    event.comm[..comm.len().min(MAX_COMM_LEN)]
                        .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
                }
                entry.submit(0);
            }
            return Ok(-1); // -EPERM: neural model blocked execution
        }
    }

    // For bprm_check_security(struct linux_binprm *bprm):
    // Read the bprm pointer (first argument to the LSM hook)
    let bprm_ptr: *const u8 = unsafe { ctx.arg(0) };

    // linux_binprm->filename offset on kernel 6.x
    // struct linux_binprm { ..., const char *filename @ offset 72, ... }
    const BPRM_FILENAME_OFFSET: usize = 72;

    let filename_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(bprm_ptr.add(BPRM_FILENAME_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };

    // Read first 16 bytes of the filename to check the prefix
    let mut buf = [0u8; 16];
    unsafe {
        let _ = bpf_probe_read_kernel(filename_ptr as *const [u8; 16]).map(|v| buf = v);
    }

    // Check dangerous prefixes
    let is_dangerous =
        // /tmp/
        (buf[0] == b'/' && buf[1] == b't' && buf[2] == b'm' && buf[3] == b'p' && buf[4] == b'/')
        // /dev/shm/
        || (buf[0] == b'/' && buf[1] == b'd' && buf[2] == b'e' && buf[3] == b'v' && buf[4] == b'/' && buf[5] == b's' && buf[6] == b'h' && buf[7] == b'm' && buf[8] == b'/')
        // /var/tmp/
        || (buf[0] == b'/' && buf[1] == b'v' && buf[2] == b'a' && buf[3] == b'r' && buf[4] == b'/' && buf[5] == b't' && buf[6] == b'm' && buf[7] == b'p' && buf[8] == b'/');

    if !is_dangerous {
        return Ok(0); // safe path - allow
    }

    // LSM allowlist: certain processes are always allowed to execute from temp paths.
    // Package managers, build tools, and system updaters legitimately use /tmp.
    if let Ok(comm) = bpf_get_current_comm() {
        let c = &comm;
        let is_allowed =
            // Package managers
            (c[0] == b'd' && c[1] == b'p' && c[2] == b'k' && c[3] == b'g')     // dpkg
            || (c[0] == b'a' && c[1] == b'p' && c[2] == b't')                    // apt*
            || (c[0] == b'd' && c[1] == b'n' && c[2] == b'f')                    // dnf
            || (c[0] == b'y' && c[1] == b'u' && c[2] == b'm')                    // yum
            || (c[0] == b'r' && c[1] == b'p' && c[2] == b'm')                    // rpm
            || (c[0] == b's' && c[1] == b'n' && c[2] == b'a' && c[3] == b'p')    // snap
            // Build tools
            || (c[0] == b'c' && c[1] == b'c' && c[2] == 0)                       // cc
            || (c[0] == b'g' && c[1] == b'c' && c[2] == b'c')                    // gcc
            || (c[0] == b'l' && c[1] == b'd' && (c[2] == 0 || c[2] == b'.'))     // ld
            || (c[0] == b'c' && c[1] == b'a' && c[2] == b'r' && c[3] == b'g')    // cargo
            || (c[0] == b'r' && c[1] == b'u' && c[2] == b's' && c[3] == b't')    // rustc
            // System
            || (c[0] == b's' && c[1] == b'y' && c[2] == b's' && c[3] == b't'); // systemd*
        if is_allowed {
            return Ok(0);
        }
    }

    // Block execution from dangerous path
    // Also emit an event so the sensor sees the blocked attempt
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if let Some(mut entry) = EVENTS.reserve::<innerwarden_ebpf_types::ExecveEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = 6; // LSM blocked execution (new kind)
        event.pid = pid;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = uid;
        event.gid = 0;
        event.ppid = 0;
        event.cgroup_id = cgroup_id;
        event.ts_ns = ts;
        event.argc = 0;
        event.argv = [[0u8; 128]; 8];

        // Copy filename to event
        event.filename = [0u8; 256];
        let copy_len = buf.len().min(256);
        event.filename[..copy_len].copy_from_slice(&buf[..copy_len]);

        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }

        entry.submit(0);
    }

    // Gradual mode: log/warn modes allow execution, only enforce blocks.
    if should_block {
        Ok(-1) // -EPERM: deny execution
    } else {
        Ok(0) // log/warn mode: allow but event was already emitted above
    }
}

// ---------------------------------------------------------------------------
// Container drift detection via overlayfs upper-layer check
// ---------------------------------------------------------------------------
//
// Checks if the binary being executed is in the overlayfs upper layer.
// The upper layer contains files created/modified after container start —
// i.e., not in the original image. This is container drift.
//
// Technique: __upperdentry is the first field after vfs_inode
// in struct ovl_inode. So its offset = inode_ptr + sizeof(struct inode).
// sizeof(struct inode) is queried from kernel BTF by userspace and stored
// in the INODE_SIZE map.

fn check_overlay_drift(ctx: &LsmContext, cgroup_id: u64, inode_size: u64) -> Result<(), i64> {
    // bprm_check_security(struct linux_binprm *bprm)
    let bprm_ptr: *const u8 = unsafe { ctx.arg(0) };

    // bprm->file @ offset 48 (kernel 6.x: struct linux_binprm has
    // struct vm_area_struct *vma, unsigned long limit, mm, flags, etc. before file)
    const BPRM_FILE_OFFSET: usize = 48;
    let file_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(bprm_ptr.add(BPRM_FILE_OFFSET) as *const *const u8).map_err(|e| e)?
    };
    if file_ptr.is_null() {
        return Ok(());
    }

    // file->f_path.dentry @ offset 16 (f_path is { mnt(8), dentry(8) } at offset 8)
    const F_PATH_DENTRY_OFFSET: usize = 16;
    let dentry_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(file_ptr.add(F_PATH_DENTRY_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };
    if dentry_ptr.is_null() {
        return Ok(());
    }

    // dentry->d_sb @ offset 104 (kernel 6.x)
    const DENTRY_D_SB_OFFSET: usize = 104;
    let sb_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(dentry_ptr.add(DENTRY_D_SB_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };
    if sb_ptr.is_null() {
        return Ok(());
    }

    // super_block->s_magic @ offset 104 (kernel 6.x)
    const SB_S_MAGIC_OFFSET: usize = 104;
    let s_magic: u64 = unsafe {
        bpf_probe_read_kernel(sb_ptr.add(SB_S_MAGIC_OFFSET) as *const u64).map_err(|e| e)?
    };
    if s_magic != OVERLAYFS_SUPER_MAGIC {
        return Ok(()); // Not overlayfs — skip
    }

    // dentry->d_inode @ offset 48 (kernel 6.x)
    const DENTRY_D_INODE_OFFSET: usize = 48;
    let inode_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(dentry_ptr.add(DENTRY_D_INODE_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };
    if inode_ptr.is_null() {
        return Ok(());
    }

    // __upperdentry is at inode_ptr + sizeof(struct inode)
    let upper_dentry: *const u8 = unsafe {
        bpf_probe_read_kernel(inode_ptr.add(inode_size as usize) as *const *const u8)
            .map_err(|e| e)?
    };

    if upper_dentry.is_null() {
        return Ok(()); // Lower layer — part of original image, no drift
    }

    // DRIFT DETECTED: binary is in overlayfs upper layer (dropped after container start)
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    if let Some(mut entry) = EVENTS.reserve::<innerwarden_ebpf_types::ExecveEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = innerwarden_ebpf_types::SyscallKind::ContainerDrift as u32;
        event.pid = pid;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = uid;
        event.gid = 0;
        event.ppid = 0;
        event.cgroup_id = cgroup_id;
        event.ts_ns = ts;
        event.argc = 0;
        event.argv = [[0u8; 128]; 8];

        // Read the filename from bprm->filename
        const BPRM_FILENAME_OFFSET: usize = 72;
        let filename_ptr: *const u8 = unsafe {
            bpf_probe_read_kernel(bprm_ptr.add(BPRM_FILENAME_OFFSET) as *const *const u8)
                .unwrap_or(core::ptr::null())
        };
        event.filename = [0u8; 256];
        if !filename_ptr.is_null() {
            unsafe {
                let _ = bpf_probe_read_kernel_str_bytes(filename_ptr, &mut event.filename);
            }
        }

        if let Ok(comm) = bpf_get_current_comm() {
            event.comm = [0u8; MAX_COMM_LEN];
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }

        entry.submit(0);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// LSM: file_open - block writes to sensitive paths (guard mode)
// ---------------------------------------------------------------------------
//
// Protects critical system files from unauthorized modification.
// When enabled via LSM_POLICY key 1, blocks write opens to:
//   /etc/shadow, /etc/passwd, /etc/sudoers*
//   ~/.ssh/authorized_keys, ~/.ssh/id_*
//   /etc/cron*, /var/spool/cron/
//   /etc/systemd/system/
//   /etc/ld.so.preload, /etc/ld.so.conf*
//   /etc/pam.d/
//
// Policy key 1 = 1 → enforce (block writes), 0 or absent → observe only.
// Always emits FileOpenEvent with kind=FileWrite for visibility.

#[lsm(hook = "file_open", sleepable)]
pub fn innerwarden_lsm_file_open(ctx: LsmContext) -> i32 {
    match try_lsm_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // fail-open
    }
}

fn try_lsm_file_open(ctx: &LsmContext) -> Result<i32, i64> {
    // file_open(struct file *file)
    // struct file { ... f_flags @ offset 76 (kernel 6.x), f_path.dentry @ offset ... }
    // We read f_flags to check for write mode.
    let file_ptr: *const u8 = unsafe { ctx.arg(0) };

    // f_flags offset in struct file (kernel 6.x)
    const F_FLAGS_OFFSET: usize = 76;
    let flags: u32 = unsafe {
        bpf_probe_read_kernel(file_ptr.add(F_FLAGS_OFFSET) as *const u32).map_err(|e| e)?
    };

    // Only interested in write opens: O_WRONLY(1), O_RDWR(2), O_CREAT(0x40), O_TRUNC(0x200)
    let is_write = (flags & 0x3) != 0 || (flags & 0x40) != 0 || (flags & 0x200) != 0;
    if !is_write {
        return Ok(0);
    }

    // Read filename from f_path.dentry->d_name
    // struct file { f_path { struct vfsmount *mnt; struct dentry *dentry } @ offset 16 }
    // f_path.dentry @ offset 24 (after mnt pointer)
    const F_PATH_DENTRY_OFFSET: usize = 24;
    let dentry_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(file_ptr.add(F_PATH_DENTRY_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };

    // dentry->d_name.name @ offset 40 (kernel 6.x, after d_name { hash_len, name })
    // d_name is struct qstr at offset 32 in dentry, name ptr is at qstr+8 = dentry+40
    const DENTRY_NAME_OFFSET: usize = 40;
    let name_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(dentry_ptr.add(DENTRY_NAME_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };

    let mut name_buf = [0u8; 64];
    unsafe {
        let _ = bpf_probe_read_kernel_str_bytes(name_ptr, &mut name_buf);
    }

    // Classify the filename into a capability category
    let n = &name_buf;
    let cap_bit: u32 = if
    // shadow, passwd, gshadow, group
    (n[0] == b's'
        && n[1] == b'h'
        && n[2] == b'a'
        && n[3] == b'd'
        && n[4] == b'o'
        && n[5] == b'w')
        || (n[0] == b'p'
            && n[1] == b'a'
            && n[2] == b's'
            && n[3] == b's'
            && n[4] == b'w'
            && n[5] == b'd')
        || (n[0] == b'g' && n[1] == b's' && n[2] == b'h' && n[3] == b'a' && n[4] == b'd')
    {
        innerwarden_ebpf_types::CAP_WRITE_CREDENTIALS
    } else if
    // authorized_keys, id_rsa, id_ed25519
    n[0] == b'a'
        && n[1] == b'u'
        && n[2] == b't'
        && n[3] == b'h'
        && n[4] == b'o'
        && n[5] == b'r'
    {
        innerwarden_ebpf_types::CAP_WRITE_SSH
    } else if
    // sudoers
    n[0] == b's'
        && n[1] == b'u'
        && n[2] == b'd'
        && n[3] == b'o'
        && n[4] == b'e'
        && n[5] == b'r'
        && n[6] == b's'
    {
        innerwarden_ebpf_types::CAP_WRITE_SUDO
    } else if
    // crontab, cron.d
    n[0] == b'c' && n[1] == b'r' && n[2] == b'o' && n[3] == b'n' {
        innerwarden_ebpf_types::CAP_WRITE_CRON
    } else if
    // ld.so.preload, ld.so.conf
    n[0] == b'l' && n[1] == b'd' && n[2] == b'.' && n[3] == b's' && n[4] == b'o' {
        innerwarden_ebpf_types::CAP_WRITE_LDPRELOAD
    } else if
    // .bashrc, .profile (persistence via shell config)
    (n[0] == b'.' && n[1] == b'b' && n[2] == b'a' && n[3] == b's' && n[4] == b'h')
        || (n[0] == b'.' && n[1] == b'p' && n[2] == b'r' && n[3] == b'o' && n[4] == b'f')
    {
        innerwarden_ebpf_types::CAP_WRITE_PERSISTENCE
    } else {
        return Ok(0); // Not a sensitive path
    };

    // Check capability maps: if this process/cgroup has the capability, allow
    if has_capability(cap_bit) {
        return Ok(0);
    }

    // Emit event for visibility (always, regardless of guard mode)
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if let Some(mut entry) = EVENTS.reserve::<innerwarden_ebpf_types::FileOpenEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = innerwarden_ebpf_types::SyscallKind::FileWrite as u32;
        event.pid = pid;
        event.uid = uid;
        event.ppid = 0;
        event.cgroup_id = cgroup_id;
        event.flags = flags;
        event.ts_ns = ts;

        // Copy filename
        event.filename = [0u8; 256];
        let copy_len = name_buf.len().min(256);
        event.filename[..copy_len].copy_from_slice(&name_buf[..copy_len]);

        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }

        entry.submit(0);
    }

    // Check enforcement mode: key 2 (gradual) takes priority over key 1.
    let gradual_mode = unsafe { LSM_POLICY.get(&2u32) }.copied().unwrap_or(0);
    if gradual_mode >= 3 {
        return Ok(-1); // enforce mode: block the write
    }
    if gradual_mode > 0 {
        return Ok(0); // log/warn mode: allow but event was already emitted above
    }

    // Legacy: key 1 (binary on/off)
    let guard_writes = unsafe { LSM_POLICY.get(&1u32) };
    if guard_writes.is_some() && *guard_writes.unwrap() == 1 {
        return Ok(-1); // -EPERM: block the write
    }

    Ok(0) // observe only
}

// ---------------------------------------------------------------------------
// sched:sched_process_exit - track process exits for rootkit detection
// ---------------------------------------------------------------------------
//
// By tracking both execve (birth) and exit (death), the rootkit detector
// can distinguish between:
//   - Short-lived processes that exited normally (not rootkits)
//   - Long-running processes that disappeared from /proc (real rootkits)

// Spec 069: attach via raw_tracepoint (BPF_RAW_TRACEPOINT_OPEN) instead of the
// perf-tracepoint path. On kernel 7.0 / Ubuntu 26.04 with perf_event_paranoid=4
// the perf PERF_TYPE_TRACEPOINT attach is not satisfied by CAP_PERFMON alone, so
// the typed `#[tracepoint]` programs fail to attach under the non-root sensor.
// raw-tracepoint open is gated only by CAP_BPF+CAP_PERFMON and bypasses that path.
// The handler ignores tracepoint args (uses bpf_get_current_*), so the conversion
// is a pure context-type change with no logic difference.
#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn innerwarden_process_exit(ctx: RawTracePointContext) -> u32 {
    match try_process_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_process_exit(_ctx: &RawTracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    // Kill chain: clean up PID state on exit
    chain_clear(pid);
    let tgid = (pid_tgid >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<ProcessExitEvent>(0) {
        Some(e) => e,
        None => return Ok(()), // ring buffer full - fail-open
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::ProcessExit as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.exit_code = 0; // exit code not directly available in tracepoint args
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// ptrace request constants - process injection detection (used by dispatch_ptrace)
// ---------------------------------------------------------------------------
//
// dispatch_ptrace only emits events for dangerous ptrace operations:
//   PTRACE_ATTACH (16)    - attach to a running process
//   PTRACE_SEIZE (0x4206) - modern attach variant
//   PTRACE_POKETEXT (4)   - write to process memory (code injection)
//   PTRACE_POKEDATA (5)   - write to process data
//
// PTRACE_TRACEME (0) is benign (child requesting tracing) and is ignored.

const PTRACE_POKETEXT: u64 = 4;
const PTRACE_POKEDATA: u64 = 5;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_SEIZE: u64 = 0x4206;

// ---------------------------------------------------------------------------
// mprotect constant - shellcode detection (RWX memory, used by dispatch_mprotect)
// ---------------------------------------------------------------------------
// dispatch_mprotect only emits when PROT_EXEC (0x4) is added - making memory executable.

const PROT_EXEC: u64 = 0x4;

// ---------------------------------------------------------------------------
// prctl constants - process name spoofing, privs manipulation (used by dispatch_prctl)
// ---------------------------------------------------------------------------
// dispatch_prctl only emits PR_SET_NAME(15) and PR_SET_NO_NEW_PRIVS(38).

const PR_SET_NAME: u64 = 15;
const PR_SET_NO_NEW_PRIVS: u64 = 38;

// Spec 069 #4: the legacy `innerwarden_accept` sys_enter_accept4 tracepoint was
// removed here — it was a compiled-but-NEVER-ATTACHED duplicate of the live
// `dispatch_accept` kprobe below (the loader attaches only the kprobe), so it
// emitted nothing yet bloated the object and risked a double-emit if anyone
// wired it up. The spec 069 #4 audit (adversarially verified) confirmed every
// high-volume syscall handler already discards in-kernel — per-PID rate limit
// (`is_rate_limited`) + comm/cgroup allowlists + path/IP narrowing (openat to
// /etc|/root|/home credential-aware, unlink/rename to sensitive prefixes,
// connect to external AF_INET, dup onto std{in,out,err}) — so no over-broad
// emit or userspace-late-sampling remained to push down into eBPF.

// ---------------------------------------------------------------------------
// Per-syscall kprobe handlers (spec 069 Phase 2)
// ---------------------------------------------------------------------------
//
// Each handler is a kprobe on the architecture syscall ENTRY WRAPPER
// (`__x64_sys_<name>` / `__arm64_sys_<name>`, chosen by the loader). A kprobe
// fires only on its target syscall, so a handler no longer self-filters on a
// syscall number — the old `SYS_*` number tables were deleted with the
// `sys_enter` raw_tracepoint dispatch they served. Args are read from the
// wrapper's `struct pt_regs *` via the `syscall_arg!` / `syscall_arg_at!`
// macros (see their docs). kprobe attach works under the non-root sensor
// (perf_event_paranoid=4 + CAP_PERFMON) on kernel 7.0.
#[kprobe]
pub fn dispatch_execve(ctx: ProbeContext) -> u32 {
    // Resolve the syscall entry pt_regs pointer on the OWNED context (a borrowed
    // context mis-reads on BPF — see the `syscall_arg!` macro note), then hand
    // the raw pointer to the handler.
    let regs = ctx.arg::<u64>(0).unwrap_or(0) as *const u8;
    let _ = try_dispatch_execve(regs);
    0
}

#[inline(always)]
fn try_dispatch_execve(regs: *const u8) -> Result<(), i64> {
    if is_self_cgroup() || is_comm_allowed(0) || is_cgroup_allowed() {
        return Ok(());
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return Ok(());
    }

    let filename_ptr: *const u8 = unsafe { syscall_arg_at!(regs, 0)? as *const u8 };
    // Skip if the filename pointer read failed or is null — avoids emitting a
    // bogus exec event with an empty command line.
    if filename_ptr.is_null() {
        return Ok(());
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<ExecveEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Execve as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    event.gid = gid;
    // Capture the real parent PID in-kernel: the execve hook fires for
    // short-lived processes whose /proc entry is gone before the userspace
    // ring reader can read PPid, so the /proc fallback alone leaves ppid=0
    // (which made the fileless-systemd parent-lineage gate inert in prod).
    // 0 here => userspace /proc fallback (unchanged) — never a guessed offset.
    event.ppid = current_real_parent_tgid();
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    event.argc = 0;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename);
    }
    // Capture argv IN-KERNEL from the caller's still-mapped userspace memory.
    // Userspace otherwise reconstructs argv from /proc/PID/cmdline, but a
    // short-lived process (rm, find) exits before the ring reader runs, so /proc
    // is already gone and only argv[0] survives -- leaving argv-based detectors
    // (data_destruction_pattern) blind to `-rf` and the target path. Reading here
    // at execve entry is reliable: the CALLING process's argv array is still live
    // in its address space. Manually unrolled (see read_argv_slot!) so every index
    // into the reserved ring entry is constant; `&&` stops at the NULL terminator.
    event.argv = [[0u8; MAX_ARG_LEN]; MAX_ARGS];
    let argv_base = unsafe { syscall_arg_at!(regs, 1) }.unwrap_or(0);
    let mut argc: u32 = 0;
    if argv_base != 0
        && read_argv_slot!(argv_base, 0, event, argc)
        && read_argv_slot!(argv_base, 1, event, argc)
        && read_argv_slot!(argv_base, 2, event, argc)
        && read_argv_slot!(argv_base, 3, event, argc)
        && read_argv_slot!(argv_base, 4, event, argc)
        && read_argv_slot!(argv_base, 5, event, argc)
        && read_argv_slot!(argv_base, 6, event, argc)
    {
        let _ = read_argv_slot!(argv_base, 7, event, argc);
    }
    event.argc = argc;
    entry.submit(0);
    Ok(())
}

#[kprobe]
pub fn dispatch_connect(ctx: ProbeContext) -> u32 {
    let regs = ctx.arg::<u64>(0).unwrap_or(0) as *const u8;
    let _ = try_dispatch_connect(regs);
    0
}

#[inline(always)]
fn try_dispatch_connect(regs: *const u8) -> Result<(), i64> {
    // InnerWarden's own outbound connects (agent → k8s API / Azure IMDS / cloud
    // for tenancy + cloud detection) are self-noise — drop them. Safe before the
    // IMDS parse: SELF_CGROUP is our non-forgeable own cgroup, an attacker cannot
    // enter it, so a real IMDS-SSRF from any other cgroup still surfaces.
    if is_self_cgroup() {
        return Ok(());
    }
    // Parse the destination BEFORE the comm allowlist gate so a renamed process
    // cannot suppress an IMDS connect (see is_imds below). The 8-byte sockaddr
    // read is cheap and connect is far lower frequency than openat.
    let addr_ptr: *const u8 = unsafe { syscall_arg_at!(regs, 1)? as *const u8 };
    let sa_buf = unsafe { bpf_probe_read_user(addr_ptr as *const [u8; 8]).unwrap_or([0u8; 8]) };
    let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);
    if family != 2 {
        return Ok(());
    }
    let port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    let addr = u32::from_be_bytes([sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]]);
    if sa_buf[4] == 127 || addr == 0 {
        return Ok(());
    }
    // Cloud instance-metadata endpoint (169.254.169.254 — AWS/GCP/Azure/OpenStack
    // IMDS). A connect here is how cloud credentials are stolen (imds_ssrf). It is
    // a hardcoded link-local IP (no DNS for dns_capture to surface) and otherwise
    // legitimate (never in a threat feed), so NOTHING else backstops it — it must
    // bypass the comm/cgroup allowlist or a renamed process steals creds silently.
    let is_imds = sa_buf[4] == 169 && sa_buf[5] == 254 && sa_buf[6] == 169 && sa_buf[7] == 254;
    if !is_imds && (is_comm_allowed(1) || is_cgroup_allowed()) {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<ConnectEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Connect as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    event.ppid = 0;
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.dst_addr = addr;
    event.dst_port = port;
    event.family = family;
    event.ts_ns = ts;
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }
    entry.submit(0);
    Ok(())
}

// Simpler handlers - most only read 0-2 args.
// ptrace, setuid, bind, mount, memfd_create, init_module, dup, listen, mprotect,
// clone, unlink, rename, kill, prctl, accept - each follows the same pattern:
// read args from the entry pt_regs via the `syscall_arg!` macro.

#[kprobe]
pub fn dispatch_ptrace(ctx: ProbeContext) -> u32 {
    if is_comm_allowed(3) || is_cgroup_allowed() {
        return 0;
    }
    let request = unsafe { syscall_arg!(ctx, 0).unwrap_or(0) };
    let target_pid = unsafe { syscall_arg!(ctx, 1).unwrap_or(0) };
    if request != PTRACE_ATTACH
        && request != PTRACE_SEIZE
        && request != PTRACE_POKETEXT
        && request != PTRACE_POKEDATA
    {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<PtraceEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Ptrace as u32;
        event.pid = pid;
        event.uid = uid;
        event.target_pid = target_pid as u32;
        event.request = request as u32;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_setuid(ctx: ProbeContext) -> u32 {
    if is_comm_allowed(4) {
        return 0;
    }
    let target_uid = unsafe { syscall_arg!(ctx, 0).unwrap_or(u64::MAX) } as u32;
    let current_uid = bpf_get_current_uid_gid() as u32;
    if current_uid == 0 || target_uid != 0 {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<SetUidEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::SetUid as u32;
        event.pid = pid;
        event.uid = current_uid;
        event.target_uid = target_uid;
        event.syscall_nr = 0;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_mprotect(ctx: ProbeContext) -> u32 {
    if is_comm_allowed(11) || is_cgroup_allowed() {
        return 0;
    }
    let addr = unsafe { syscall_arg!(ctx, 0).unwrap_or(0) };
    let len = unsafe { syscall_arg!(ctx, 1).unwrap_or(0) };
    let prot = unsafe { syscall_arg!(ctx, 2).unwrap_or(0) };
    if prot & PROT_EXEC == 0 {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return 0;
    }
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<MprotectEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Mprotect as u32;
        event.pid = pid;
        event.uid = uid;
        event.prot = prot as u32;
        event.addr = addr;
        event.len = len;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_kill(ctx: ProbeContext) -> u32 {
    if is_comm_allowed(15) {
        return 0;
    }
    // kill(pid, sig): pid=arg0, sig=arg1
    let target_pid = unsafe { syscall_arg!(ctx, 0).unwrap_or(0) } as u32;
    let signal = unsafe { syscall_arg!(ctx, 1).unwrap_or(0) } as u32;
    if signal != 9 && signal != 15 && signal != 19 {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<KillEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Kill as u32;
        event.pid = pid;
        event.uid = uid;
        event.target_pid = target_pid;
        event.signal = signal;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

// Spec 069: kprobe handlers for the remaining syscalls. Each reads args from
// the entry pt_regs via the `syscall_arg!` macro (syscall-ABI position) and
// mirrors the logic of its typed `innerwarden_*` counterpart.

/// Bounded scan for a credential dir/file ANYWHERE in the path: `/.ssh/`,
/// `/.aws/`, `/.kube/`, `/.gnupg/`, `/.env*`, `/.docker/`. Catches home/root
/// private keys and cloud/k8s creds (`/home/u/.ssh/id_rsa`,
/// `/root/.aws/credentials`, `/home/u/.kube/config`) plus the `.env`
/// application-secret file and Docker registry auth — the credentials an AI
/// coding agent touches most — read via an openat-allowlisted tool (`cat`/`head`)
/// or an interpreter comm. These are high-value AND low-frequency-legit, so they
/// must bypass the comm allowlist and the rate-limit like the /etc secrets do.
///
/// 2026-07-02 (agent cred-exfil blind spot, found by a live red-team): `.env`
/// and `.docker/` were absent, so an interpreter comm (python/node/openclaw)
/// reading `~/project/.env` then connecting out had its READ dropped by the
/// openat comm-allowlist before the userspace data_exfil detector could see it —
/// even though the detector's `SENSITIVE_PATHS` lists `.env`. The two layers
/// disagreed; this aligns the kernel emit set with them.
///
/// Verifier-safe: one constant-bounded loop; the 3-byte discriminator only runs
/// at a `/.` boundary. Matching 3 bytes means `/.env` (and `.env.local`,
/// `.env.production`, direnv's `.envrc`) and `/.docker/` all count.
#[inline(always)]
fn contains_secret_dir(buf: &[u8]) -> bool {
    let mut i = 0usize;
    while i < 250 && i + 5 < buf.len() {
        let b0 = buf[i];
        if b0 == 0 {
            break;
        }
        if b0 == b'/' && buf[i + 1] == b'.' {
            let a = buf[i + 2];
            let b = buf[i + 3];
            let c = buf[i + 4];
            // /.ssh/  /.aws/  /.kube/  /.gnupg/  /.env*  /.docker/
            if (a == b's' && b == b's' && c == b'h')
                || (a == b'a' && b == b'w' && c == b's')
                || (a == b'k' && b == b'u' && c == b'b')
                || (a == b'g' && b == b'n' && c == b'u')
                || (a == b'e' && b == b'n' && c == b'v')
                || (a == b'd' && b == b'o' && c == b'c')
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[kprobe]
pub fn dispatch_openat(ctx: ProbeContext) -> u32 {
    // InnerWarden's own file reads (incl. the integrity collector reading
    // /etc/shadow etc.) are noise + would flood the ring — drop before the path
    // read. Non-forgeable (own cgroup only); empty map → no-op until seeded.
    if is_self_cgroup() {
        return 0;
    }
    // openat(dfd, filename, flags, mode): filename=arg1, flags=arg2
    let Ok(filename_ptr) = (unsafe { syscall_arg!(ctx, 1) }) else {
        return 0;
    };
    let mut filename_buf = [0u8; 256];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut filename_buf);
    }
    let f = &filename_buf;
    let etc = f[0] == b'/' && f[1] == b'e' && f[2] == b't' && f[3] == b'c' && f[4] == b'/';
    // High-value credential files under /etc: shadow, passwd, sudoers, gshadow,
    // ssh/ssl. These ALWAYS emit (an attacker reading them must never be lost to
    // rate-limiting). Matched on the two bytes after "/etc/".
    let is_credential = etc
        && ((f[5] == b's' && f[6] == b'h')   // shadow
            || (f[5] == b'p' && f[6] == b'a') // passwd
            || (f[5] == b's' && f[6] == b'u') // sudoers
            || (f[5] == b'g' && f[6] == b's') // gshadow
            || (f[5] == b's' && f[6] == b's')); // ssh / ssl
                                                // Broader sensitive telemetry: any /etc, /root, /home read. High volume on a
                                                // live host, so rate-limited below (the kprobe now reads filenames correctly
                                                // and would otherwise flood the ring buffer).
                                                // Credential dirs anywhere (/.ssh/, /.aws/, /.kube/, /.gnupg/) — home/root
                                                // private keys + cloud/k8s creds. High value, low legit frequency.
    let secret_dir = contains_secret_dir(f);
    let is_sensitive = etc
        || (f[0] == b'/' && f[1] == b'r' && f[2] == b'o' && f[3] == b'o' && f[4] == b't')
        || (f[0] == b'/' && f[1] == b'h' && f[2] == b'o' && f[3] == b'm' && f[4] == b'e')
        || secret_dir;
    // Kill-chain credential bit (CHAIN_SENSITIVE_READ -> DATA_EXFIL, which can
    // gate the LSM execve-block): ONLY genuine /etc secrets, NOT the broad
    // telemetry set. Previously this fired on EVERY /etc|/root|/home read, so
    // any process reading /etc/passwd (world-readable, nss), /etc/ssl certs (TLS
    // clients), or any home/root file and then connecting out tripped the kernel
    // DATA_EXFIL chain. Excludes /etc/passwd + /etc/ssl|ssh; mirrors the
    // userspace is_sensitive_read_path tightening. Home-dir private keys/creds
    // are still detected via the userspace tracker (the broad telemetry emit
    // below keeps surfacing those reads).
    let is_chain_credential = etc
        && ((f[5] == b's' && f[6] == b'h')   // shadow
            || (f[5] == b's' && f[6] == b'u') // sudoers
            || (f[5] == b'g' && f[6] == b's')); // gshadow
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_chain_credential {
        chain_flag(pid, CHAIN_SENSITIVE_READ);
    }
    // Genuinely-secret reads must NOT be dropped by the openat comm/cgroup
    // allowlist. `cat`/`head`/`less` are on the openat allowlist bit (volume
    // control for noisy readers), so before this an attacker reading a secret via
    // any allowlisted tool returned 0 here and the event never reached SIGMA-004 /
    // the userspace sensitive-read / data_exfil detectors — a rename-free in-kernel
    // evasion. The bypass set is narrow and high-value / low-legit-frequency:
    //   - /etc/shadow|sudoers|gshadow (is_chain_credential)
    //   - /etc/ssh host keys (etc + "ssh", distinguished from /etc/ssl by f[7]=='h')
    //   - /.ssh/ /.aws/ /.kube/ /.gnupg/ anywhere (home/root keys, cloud/k8s creds)
    // Deliberately EXCLUDED: /etc/passwd (world-readable, nss) and /etc/ssl certs
    // (read on every TLS handshake) — bypassing those would flood the ring buffer.
    let etc_ssh = etc && f[5] == b's' && f[6] == b's' && f[7] == b'h';
    let is_secret_read = is_chain_credential || etc_ssh || secret_dir;
    if !is_secret_read && (is_comm_allowed(2) || is_cgroup_allowed()) {
        return 0;
    }
    if !is_sensitive {
        return 0;
    }
    // Always surface credential reads (incl. the secret dirs); rate-limit the
    // broad /etc|/root|/home telemetry remainder.
    if !is_credential && !secret_dir && is_rate_limited(pid) {
        return 0;
    }
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let flags = unsafe { syscall_arg!(ctx, 2).unwrap_or(0) } as u32;
    if let Some(mut entry) = EVENTS.reserve::<innerwarden_ebpf_types::FileOpenEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = innerwarden_ebpf_types::SyscallKind::FileOpen as u32;
        event.pid = pid;
        event.uid = uid;
        event.ppid = 0;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.filename = filename_buf;
        event.flags = flags;
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_bind(ctx: ProbeContext) -> u32 {
    // bind(fd, addr, addrlen): addr=arg1
    let Ok(addr_ptr) = (unsafe { syscall_arg!(ctx, 1) }) else {
        return 0;
    };
    let sa_buf = unsafe { bpf_probe_read_user(addr_ptr as *const [u8; 8]).unwrap_or([0u8; 8]) };
    let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);
    if family != 2 {
        return 0;
    }
    let port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    let addr = u32::from_be_bytes([sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]]);
    if port == 0 {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    chain_flag(pid, CHAIN_BIND);
    if is_comm_allowed(5) || is_cgroup_allowed() {
        return 0;
    }
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<SocketBindEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::SocketBind as u32;
        event.pid = pid;
        event.uid = uid;
        event.protocol = 0;
        event.family = family;
        event.port = port;
        event._pad = 0;
        event.addr = addr;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_mount(ctx: ProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return 0;
    }
    // mount(dev, dir, type, flags, data): dev=arg0, dir=arg1, type=arg2, flags=arg3
    let source_ptr = unsafe { syscall_arg!(ctx, 0).unwrap_or(0) };
    let target_ptr = unsafe { syscall_arg!(ctx, 1).unwrap_or(0) };
    let type_ptr = unsafe { syscall_arg!(ctx, 2).unwrap_or(0) };
    let flags = unsafe { syscall_arg!(ctx, 3).unwrap_or(0) };
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<MountEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Mount as u32;
        event.pid = pid;
        event.uid = uid;
        event.flags = flags as u32;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        event.source = [0u8; MAX_FILENAME_LEN];
        event.target = [0u8; MAX_FILENAME_LEN];
        event.fs_type = [0u8; 32];
        unsafe {
            let _ = bpf_probe_read_user_str_bytes(source_ptr as *const u8, &mut event.source);
            let _ = bpf_probe_read_user_str_bytes(target_ptr as *const u8, &mut event.target);
            let _ = bpf_probe_read_user_str_bytes(type_ptr as *const u8, &mut event.fs_type);
        }
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_memfd_create(ctx: ProbeContext) -> u32 {
    if is_comm_allowed(7) {
        return 0;
    }
    // memfd_create(name, flags): name=arg0, flags=arg1
    let name_ptr = unsafe { syscall_arg!(ctx, 0).unwrap_or(0) };
    let flags = unsafe { syscall_arg!(ctx, 1).unwrap_or(0) } as u32;
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<MemfdCreateEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::MemfdCreate as u32;
        event.pid = pid;
        event.uid = uid;
        event.flags = flags;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        event.name = [0u8; MAX_FILENAME_LEN];
        unsafe {
            let _ = bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut event.name);
        }
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_init_module(_ctx: ProbeContext) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<ModuleLoadEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::InitModule as u32;
        event.pid = pid;
        event.uid = uid;
        event.syscall_nr = 0;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_dup(ctx: ProbeContext) -> u32 {
    // dup2/dup3(oldfd, newfd, ...): oldfd=arg0, newfd=arg1
    let oldfd = unsafe { syscall_arg!(ctx, 0).unwrap_or(0) } as u32;
    let newfd = unsafe { syscall_arg!(ctx, 1).unwrap_or(u64::MAX) } as u32;
    if newfd > 2 {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    match newfd {
        0 => chain_flag(pid, CHAIN_DUP_STDIN),
        1 => chain_flag(pid, CHAIN_DUP_STDOUT),
        2 => chain_flag(pid, CHAIN_DUP_STDERR),
        _ => {}
    }
    if is_comm_allowed(9) || is_cgroup_allowed() {
        return 0;
    }
    // Spec 069: dup2/dup3 onto stdio is common in normal shells; rate-limit per
    // PID so it can't flood the ring on a busy host (the chain flags above are
    // still set every time for kill-chain correlation).
    if is_rate_limited(pid) {
        return 0;
    }
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<DupEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Dup as u32;
        event.pid = pid;
        event.uid = uid;
        event.oldfd = oldfd;
        event.newfd = newfd;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_listen(ctx: ProbeContext) -> u32 {
    // listen(fd, backlog): backlog=arg1
    let backlog = unsafe { syscall_arg!(ctx, 1).unwrap_or(0) } as u32;
    let pid = bpf_get_current_pid_tgid() as u32;
    chain_flag(pid, CHAIN_LISTEN);
    if is_comm_allowed(10) || is_cgroup_allowed() {
        return 0;
    }
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<ListenEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Listen as u32;
        event.pid = pid;
        event.uid = uid;
        event.backlog = backlog;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

// Spec 070: setns(2) entry — privilege-provenance pivot primitive.
// Emit-only. A root task joining a namespace owned by a non-root uid is the
// technique-independent signature of container-escape / userns-based LPE; the
// owner-uid check is done in userspace (`setns_owner` detector) since walking
// the nsfs file -> ns -> owner -> uid chain in BPF is the fragile nested-offset
// class. Comm handler bit 18; rate-limited like its siblings so runc /
// containerd setns floods cannot starve the ring.
#[kprobe]
pub fn dispatch_setns(ctx: ProbeContext) -> u32 {
    // Emit-only: NO in-kernel comm/cgroup suppression gate. The shared
    // `is_comm_allowed(18) || is_cgroup_allowed()` gate used by the other
    // handlers swallowed `call_usermodehelper` kernel helpers (e.g.
    // `cifs.upcall`): in that task context the kprobe fires (run_cnt advances)
    // but the gate bails before `EVENTS.reserve`, even though the allowlist maps
    // hold no matching entry — so the CIFSwitch (CVE-2026-46243) pivot, a root
    // task joining a non-root-owned user namespace, never reached the ring.
    // setns is a low-volume, high-value syscall, so we always emit here and let
    // the userspace `setns_owner` detector filter container runtimes by
    // non-forgeable exe path + owner-uid. [A2: kernel-helper blind spot]
    // setns(fd, nstype): fd=arg0, nstype=arg1
    let fd = unsafe { syscall_arg!(ctx, 0).unwrap_or(u64::MAX) } as i32;
    let nstype = unsafe { syscall_arg!(ctx, 1).unwrap_or(0) } as u32;
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    // NOTE: deliberately NOT rate-limited. `is_rate_limited` is per-PID and
    // SHARED across handlers; a process does execve (which stamps the limiter)
    // then setns within the same 100ms window, so a per-PID limit would drop
    // every real setns. setns is a low-volume, high-value syscall — container
    // runtimes are filtered by comm bit 18 / cgroup and in the userspace
    // `setns_owner` detector instead.
    let tgid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<SetnsEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Setns as u32;
        event.pid = pid;
        event.tgid = tgid;
        event.uid = uid;
        event.fd = fd;
        event.nstype = nstype;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_clone(ctx: ProbeContext) -> u32 {
    if is_comm_allowed(12) || is_cgroup_allowed() {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return 0;
    }
    // clone(clone_flags, ...): clone_flags=arg0
    let clone_flags = unsafe { syscall_arg!(ctx, 0).unwrap_or(0) };
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<CloneEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Clone as u32;
        event.pid = pid;
        event.uid = uid;
        event.clone_flags = clone_flags;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_unlink(ctx: ProbeContext) -> u32 {
    if is_comm_allowed(13) || is_cgroup_allowed() {
        return 0;
    }
    // unlinkat(dfd, pathname, flag): pathname=arg1
    let Ok(path_ptr) = (unsafe { syscall_arg!(ctx, 1) }) else {
        return 0;
    };
    let mut path_buf = [0u8; 64];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(path_ptr as *const u8, &mut path_buf);
    }
    let f = &path_buf;
    let is_sensitive = (f[0] == b'/'
        && f[1] == b'v'
        && f[2] == b'a'
        && f[3] == b'r'
        && f[4] == b'/'
        && f[5] == b'l'
        && f[6] == b'o'
        && f[7] == b'g')
        || (f[0] == b'/' && f[1] == b'e' && f[2] == b't' && f[3] == b'c' && f[4] == b'/')
        || (f[0] == b'/' && f[1] == b'r' && f[2] == b'o' && f[3] == b'o' && f[4] == b't');
    if !is_sensitive {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<UnlinkEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Unlink as u32;
        event.pid = pid;
        event.uid = uid;
        event._pad = 0;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        event.filename = [0u8; MAX_FILENAME_LEN];
        unsafe {
            let _ = bpf_probe_read_user_str_bytes(path_ptr as *const u8, &mut event.filename);
        }
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_rename(ctx: ProbeContext) -> u32 {
    if is_comm_allowed(14) || is_cgroup_allowed() {
        return 0;
    }
    // renameat2(olddfd, oldname, newdfd, newname, flags): oldname=arg1, newname=arg3
    let Ok(oldname_ptr) = (unsafe { syscall_arg!(ctx, 1) }) else {
        return 0;
    };
    let Ok(newname_ptr) = (unsafe { syscall_arg!(ctx, 3) }) else {
        return 0;
    };
    let mut buf = [0u8; 16];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(newname_ptr as *const u8, &mut buf);
    }
    let f = &buf;
    let is_sensitive =
        (f[0] == b'/' && f[1] == b'e' && f[2] == b't' && f[3] == b'c' && f[4] == b'/')
            || (f[0] == b'/' && f[1] == b'u' && f[2] == b's' && f[3] == b'r')
            || (f[0] == b'/' && f[1] == b'b' && f[2] == b'i' && f[3] == b'n');
    if !is_sensitive {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<RenameEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Rename as u32;
        event.pid = pid;
        event.uid = uid;
        event._pad = 0;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        event.oldname = [0u8; MAX_FILENAME_LEN];
        event.newname = [0u8; MAX_FILENAME_LEN];
        unsafe {
            let _ = bpf_probe_read_user_str_bytes(oldname_ptr as *const u8, &mut event.oldname);
            let _ = bpf_probe_read_user_str_bytes(newname_ptr as *const u8, &mut event.newname);
        }
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_prctl(ctx: ProbeContext) -> u32 {
    if is_comm_allowed(16) {
        return 0;
    }
    // prctl(option, arg2, ...): option=arg0, arg2=arg1
    let option = unsafe { syscall_arg!(ctx, 0).unwrap_or(0) };
    let arg2 = unsafe { syscall_arg!(ctx, 1).unwrap_or(0) };
    if option != PR_SET_NAME && option != PR_SET_NO_NEW_PRIVS {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    // Spec 069: PR_SET_NAME fires on routine thread naming; rate-limit per PID
    // so it can't flood the ring on a busy host.
    if is_rate_limited(pid) {
        return 0;
    }
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<PrctlEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Prctl as u32;
        event.pid = pid;
        event.uid = uid;
        event.option = option as u32;
        event.arg2 = arg2;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[kprobe]
pub fn dispatch_accept(_ctx: ProbeContext) -> u32 {
    if is_comm_allowed(17) || is_cgroup_allowed() {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return 0;
    }
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<AcceptEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Accept as u32;
        event.pid = pid;
        event.uid = uid;
        event._pad = 0;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[cfg(iw_arch_x86_64)]
#[kprobe]
pub fn dispatch_ioperm(ctx: ProbeContext) -> u32 {
    // ioperm(from, num, turn_on): from=arg0, num=arg1, turn_on=arg2
    let from = unsafe { syscall_arg!(ctx, 0).unwrap_or(0) };
    let num = unsafe { syscall_arg!(ctx, 1).unwrap_or(0) };
    let turn_on = unsafe { syscall_arg!(ctx, 2).unwrap_or(0) };
    if turn_on != 1 {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<IopermEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Ioperm as u32;
        event.pid = pid;
        event.uid = uid;
        event._pad = 0;
        event.port_from = from;
        event.port_num = num;
        event.turn_on = turn_on;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        event.comm = [0u8; MAX_COMM_LEN];
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

#[cfg(iw_arch_x86_64)]
#[kprobe]
pub fn dispatch_iopl(ctx: ProbeContext) -> u32 {
    // iopl(level): level=arg0
    let level = unsafe { syscall_arg!(ctx, 0).unwrap_or(0) };
    if level == 0 {
        return 0;
    }
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    if let Some(mut entry) = EVENTS.reserve::<IoplEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = SyscallKind::Iopl as u32;
        event.pid = pid;
        event.uid = uid;
        event._pad = 0;
        event.level = level;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        event.ts_ns = ts;
        event.comm = [0u8; MAX_COMM_LEN];
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }
        entry.submit(0);
    }
    0
}

// ---------------------------------------------------------------------------
// io_uring monitoring - detect syscall bypass evasion
// ---------------------------------------------------------------------------
//
// io_uring submits operations via shared ring buffers, bypassing traditional
// syscall interception (seccomp, audit). Attackers use this for invisible
// file I/O, network connections, and data exfiltration.
//
// Tracepoint name changed in kernel 6.4:
//   5.10-6.3: io_uring:io_uring_submit_sqe
//   6.4+:     io_uring:io_uring_submit_req
// Both have identical layout for the fields we read.
//
// Offsets (from tracepoint format, after 8-byte common header):
//   ctx(8) req(8) user_data(8) opcode(1) _pad(3) flags(4) sq_thread(1)

/// io_uring SQE submission — fires on every submitted operation.
/// We use the 6.4+ name; the userspace loader tries both names.
#[tracepoint]
pub fn innerwarden_io_uring_submit(ctx: TracePointContext) -> u32 {
    match try_io_uring_submit(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_io_uring_submit(ctx: &TracePointContext) -> Result<(), i64> {
    // Offsets after 8-byte common header
    let opcode: u8 = unsafe { ctx.read_at(32)? };

    // Only emit events for security-relevant opcodes to avoid flooding
    let is_relevant = matches!(
        opcode,
        9  | // SENDMSG
        10 | // RECVMSG
        13 | // ACCEPT
        16 | // CONNECT
        18 | // OPENAT
        26 | // SEND
        27 | // RECV
        28 | // OPENAT2
        35 | // RENAMEAT
        36 | // UNLINKAT
        45 | // SOCKET
        46 | // URING_CMD
        53 // SEND_ZC
    );
    if !is_relevant {
        return Ok(());
    }

    // Noise filters
    if is_comm_allowed(2) || is_cgroup_allowed() {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    if is_rate_limited(pid) {
        return Ok(());
    }

    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let flags: u32 = unsafe { ctx.read_at(36).unwrap_or(0) };

    let mut entry = match EVENTS.reserve::<innerwarden_ebpf_types::IoUringEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = innerwarden_ebpf_types::SyscallKind::IoUring as u32;
    event.pid = pid;
    event.uid = uid;
    event.opcode = opcode;
    event.sqe_flags = 0;
    event._pad = 0;
    event.fd = -1; // fd not directly available in the tracepoint
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

/// io_uring ring creation — fires when a process creates an io_uring instance.
#[tracepoint]
pub fn innerwarden_io_uring_create(ctx: TracePointContext) -> u32 {
    match try_io_uring_create(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_io_uring_create(ctx: &TracePointContext) -> Result<(), i64> {
    if is_comm_allowed(2) || is_cgroup_allowed() {
        return Ok(());
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // Offsets after 8-byte common header
    let ring_fd: i32 = unsafe { ctx.read_at(8).unwrap_or(-1) };
    // ctx pointer at offset 16, skip it
    let sq_entries: u32 = unsafe { ctx.read_at(24).unwrap_or(0) };
    let cq_entries: u32 = unsafe { ctx.read_at(28).unwrap_or(0) };
    let flags: u32 = unsafe { ctx.read_at(32).unwrap_or(0) };

    let mut entry = match EVENTS.reserve::<innerwarden_ebpf_types::IoUringCreateEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = innerwarden_ebpf_types::SyscallKind::IoUringCreate as u32;
    event.pid = pid;
    event.uid = uid;
    event.ring_fd = ring_fd;
    event.sq_entries = sq_entries;
    event.cq_entries = cq_entries;
    event.flags = flags;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 2: Firmware security hooks
// ---------------------------------------------------------------------------

/// Kprobe on native_write_msr — detects writes to sensitive MSRs.
/// Sensitive: LSTAR (syscall entry point), STAR, CSTAR, SF_MASK, SMRR, APIC_BASE.
/// A rootkit that hooks syscalls rewrites LSTAR. Any unexpected MSR write is critical.
#[kprobe]
pub fn innerwarden_msr_write(ctx: ProbeContext) -> u32 {
    match try_msr_write(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_msr_write(ctx: &ProbeContext) -> Result<(), i64> {
    // native_write_msr(unsigned int msr, u64 val)
    let msr_addr: u64 = ctx.arg(0).ok_or(1i64)?;

    // Only alert on security-sensitive MSRs.
    // 0xC0000081 = STAR, 0xC0000082 = LSTAR (syscall entry), 0xC0000083 = CSTAR,
    // 0xC0000084 = SF_MASK, 0x1F2 = IA32_SMRR_PHYSBASE, 0x1F3 = IA32_SMRR_PHYSMASK,
    // 0xFEE00000 region = APIC, 0x3A = IA32_FEATURE_CONTROL
    let sensitive = matches!(
        msr_addr,
        0xC0000081 | 0xC0000082 | 0xC0000083 | 0xC0000084 | 0x1F2 | 0x1F3 | 0x3A
    );
    if !sensitive {
        return Ok(());
    }

    let msr_value: u64 = ctx.arg(1).ok_or(1i64)?;
    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<MsrWriteEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::MsrWrite as u32;
    event.pid = pid;
    event.uid = uid;
    event._pad = 0;
    event.msr_address = msr_addr;
    event.msr_value_lo = msr_value as u32;
    event.msr_value_hi = (msr_value >> 32) as u32;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

/// Kprobe on acpi_evaluate_object — monitors ACPI method execution.
/// ACPI rootkits embed code in AML methods (DSDT/SSDT). Monitoring which
/// methods execute at runtime creates a behavioral baseline.
#[kprobe]
pub fn innerwarden_acpi_eval(ctx: ProbeContext) -> u32 {
    match try_acpi_eval(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_acpi_eval(ctx: &ProbeContext) -> Result<(), i64> {
    // acpi_evaluate_object(handle, pathname, params, return_buf)
    // arg1 = pathname (char * — ACPI method name like "\_SB.PCI0._STA")
    let pathname_ptr: *const u8 = ctx.arg::<u64>(1).ok_or(1i64)? as *const u8;

    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<AcpiEvalEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::AcpiEval as u32;
    event.pid = pid;
    event.uid = uid;
    event._pad = 0;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.pathname = [0u8; MAX_COMM_LEN];
    event.comm = [0u8; MAX_COMM_LEN];

    // Read ACPI method pathname from kernel memory.
    if !pathname_ptr.is_null() {
        let _ = unsafe { bpf_probe_read_kernel_str_bytes(pathname_ptr, &mut event.pathname) };
    }

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

/// LSM hook on bpf — monitors all BPF syscall operations.
/// Detects unauthorized eBPF program loading (VoidLink rootkit defense).
/// Logs BPF_PROG_LOAD, BPF_MAP_CREATE, etc. from non-innerwarden processes.
#[lsm(hook = "bpf", sleepable)]
pub fn innerwarden_lsm_bpf(ctx: LsmContext) -> i32 {
    match try_lsm_bpf(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // allow on error (fail-open)
    }
}

#[inline(always)]
fn try_lsm_bpf(ctx: &LsmContext) -> Result<i32, i64> {
    // LSM bpf hook: int security_bpf(int cmd, ...)
    // arg0 = BPF command (BPF_PROG_LOAD=5, BPF_MAP_CREATE=0)
    let bpf_cmd: u32 = unsafe { ctx.arg::<u32>(0) };

    // Only log program loads and map creates (not lookups/reads).
    // BPF_MAP_CREATE=0, BPF_PROG_LOAD=5, BPF_BTF_LOAD=18, BPF_LINK_CREATE=28
    if bpf_cmd != 0 && bpf_cmd != 5 && bpf_cmd != 18 && bpf_cmd != 28 {
        return Ok(0);
    }

    // Skip our own process.
    let comm = bpf_get_current_comm().map_err(|_| 1i64)?;
    // "innerwarden" starts with "in" + "ne" — quick check first 4 bytes.
    if comm.len() >= 12 && comm[0] == b'i' && comm[1] == b'n' && comm[2] == b'n' && comm[3] == b'e'
    {
        return Ok(0);
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<BpfLoadEvent>(0) {
        Some(e) => e,
        None => return Ok(0),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::BpfLoad as u32;
    event.pid = pid;
    event.uid = uid;
    event.bpf_cmd = bpf_cmd;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];
    event.comm[..comm.len().min(MAX_COMM_LEN)]
        .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);

    entry.submit(0);
    Ok(0) // always allow (monitoring only, not enforcement)
}

// ---------------------------------------------------------------------------
// Trace of the Times — kernel function timing probes
// ---------------------------------------------------------------------------
//
// Each target function gets a kprobe (entry) + kretprobe (return) pair.
// The kprobe stores bpf_ktime_get_ns() keyed by (pid_tgid << 4 | target_id).
// The kretprobe reads it, computes the delta, and sends a TimingProbeEvent.

/// Temporary storage for kprobe entry timestamps.
/// Key: (pid_tgid << 4) | target_id — unique per thread+function.
/// Value: entry timestamp in nanoseconds.
#[map]
static TIMING_ENTRY: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

/// Inline: record kprobe entry timestamp.
#[inline(always)]
fn timing_entry(target: TimingTarget) {
    let key = (bpf_get_current_pid_tgid() << 4) | (target as u64);
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = TIMING_ENTRY.insert(&key, &ts, 0);
}

/// Inline: compute delta and emit timing event on kretprobe.
#[inline(always)]
fn timing_return(target: TimingTarget) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let key = (pid_tgid << 4) | (target as u64);

    let entry_ts = match unsafe { TIMING_ENTRY.get(&key) } {
        Some(ts) => *ts,
        None => return Ok(()), // no matching entry (missed or filtered)
    };
    let _ = TIMING_ENTRY.remove(&key);

    let now = unsafe { bpf_ktime_get_ns() };
    let delta = now.saturating_sub(entry_ts);

    // Skip very short deltas (< 100ns = likely noise or inline function).
    if delta < 100 {
        return Ok(());
    }

    let pid = pid_tgid as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let mut entry = match EVENTS.reserve::<TimingProbeEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::TimingProbe as u32;
    event.pid = pid;
    event.target = target as u32;
    event._pad = 0;
    event.delta_ns = delta;
    event.cgroup_id = cgroup_id;
    event.ts_ns = now;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ── iterate_dir: primary getdents handler (file hiding) ─────────────────

#[kprobe]
pub fn innerwarden_tot_iterate_dir_entry(_ctx: ProbeContext) -> u32 {
    timing_entry(TimingTarget::IterateDir);
    0
}

#[kretprobe]
pub fn innerwarden_tot_iterate_dir_ret(_ctx: RetProbeContext) -> u32 {
    let _ = timing_return(TimingTarget::IterateDir);
    0
}

// ── filldir64: directory entry callback (filtered by rootkits) ──────────

#[kprobe]
pub fn innerwarden_tot_filldir64_entry(_ctx: ProbeContext) -> u32 {
    timing_entry(TimingTarget::Filldir64);
    0
}

#[kretprobe]
pub fn innerwarden_tot_filldir64_ret(_ctx: RetProbeContext) -> u32 {
    let _ = timing_return(TimingTarget::Filldir64);
    0
}

// ── tcp4_seq_show: /proc/net/tcp display (hidden connections) ───────────

#[kprobe]
pub fn innerwarden_tot_tcp4_entry(_ctx: ProbeContext) -> u32 {
    timing_entry(TimingTarget::Tcp4SeqShow);
    0
}

#[kretprobe]
pub fn innerwarden_tot_tcp4_ret(_ctx: RetProbeContext) -> u32 {
    let _ = timing_return(TimingTarget::Tcp4SeqShow);
    0
}

// ── proc_pid_readdir: /proc process listing (process hiding) ────────────

#[kprobe]
pub fn innerwarden_tot_procdir_entry(_ctx: ProbeContext) -> u32 {
    timing_entry(TimingTarget::ProcPidReaddir);
    0
}

#[kretprobe]
pub fn innerwarden_tot_procdir_ret(_ctx: RetProbeContext) -> u32 {
    let _ = timing_return(TimingTarget::ProcPidReaddir);
    0
}

// ---------------------------------------------------------------------------
// Phase 3: Red team gap hooks — timestomp + truncate
// ---------------------------------------------------------------------------

/// Kprobe on vfs_utimes — detects timestomp (touch -t, touch -r).
/// vfs_utimes is called by utimensat/futimesat/utimes syscalls.
#[kprobe]
pub fn innerwarden_utimensat(ctx: ProbeContext) -> u32 {
    match try_utimensat(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_utimensat(_ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    if pid == 0 {
        return Ok(());
    }

    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // After reserve: NO early returns (`?`) — Aya RingBufEntry has no Drop,
    // so an unreleased reference causes verifier rejection.
    let mut entry = match EVENTS.reserve::<PrivEscEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Utimensat as u32;
    event.pid = pid;
    event.tgid = (pid_tgid >> 32) as u32;
    event.old_uid = uid;
    event.new_uid = 0;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

/// Kprobe on do_truncate — detects log file truncation.
/// do_truncate is called by truncate/ftruncate syscalls.
#[kprobe]
pub fn innerwarden_truncate(ctx: ProbeContext) -> u32 {
    match try_truncate(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_truncate(_ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;

    if pid == 0 {
        return Ok(());
    }

    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // After reserve: NO early returns (`?`) — Aya RingBufEntry has no Drop,
    // so an unreleased reference causes verifier rejection.
    let mut entry = match EVENTS.reserve::<PrivEscEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Truncate as u32;
    event.pid = pid;
    event.tgid = (pid_tgid >> 32) as u32;
    event.old_uid = uid;
    event.new_uid = 0;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;
    event.comm = [0u8; MAX_COMM_LEN];

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Panic handler (required for no_std)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
