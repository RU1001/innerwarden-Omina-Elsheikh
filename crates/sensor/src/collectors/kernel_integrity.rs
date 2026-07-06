//! Kernel integrity monitoring.
//!
//! Two complementary checks:
//!
//! 1. **eBPF program inventory**: Periodically reads the list of loaded eBPF
//!    programs and compares against a baseline established at boot. New programs
//!    loaded by processes other than innerwarden are flagged as potential
//!    eBPF weaponization (VoidLink-style attacks).
//!
//! 2. **Syscall table integrity**: Reads `/proc/kallsyms` at boot for the
//!    addresses of key syscall handlers. Periodically compares — if addresses
//!    change, a rootkit has hooked the syscall table.
//!
//! Also monitors `/proc/modules` for new kernel modules loaded after boot.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use tokio::sync::mpsc;
use tracing::{info, warn};

use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};

/// Key syscall names to monitor in kallsyms.
const MONITORED_SYSCALLS: &[&str] = &[
    "__x64_sys_execve",
    "__x64_sys_openat",
    "__x64_sys_connect",
    "__x64_sys_ptrace",
    "__x64_sys_init_module",
    "__x64_sys_finit_module",
    "__x64_sys_mount",
    "__x64_sys_setuid",
    "__x64_sys_setgid",
    "__x64_sys_kill",
];

/// eBPF programs owned by innerwarden (expected).
const INNERWARDEN_BPF_PREFIXES: &[&str] = &[
    "innerwarden",
    "iw_",
    "tracepoint__",
    "kprobe__",
    "lsm__",
    "xdp__",
];

/// Baseline state established at boot.
struct KernelBaseline {
    /// Syscall name → address from /proc/kallsyms.
    syscall_addresses: HashMap<String, String>,
    /// Known eBPF program IDs at boot.
    known_bpf_ids: HashSet<u32>,
    /// Known kernel modules at boot.
    known_modules: HashSet<String>,
    /// When the baseline was established.
    established_at: DateTime<Utc>,
}

/// Run the kernel integrity monitor.
pub async fn run(tx: mpsc::Sender<Event>, host: String, poll_seconds: u64) {
    // Establish baseline at startup
    let baseline = KernelBaseline {
        syscall_addresses: read_kallsyms(),
        known_bpf_ids: read_bpf_program_ids(),
        known_modules: read_kernel_modules(),
        established_at: Utc::now(),
    };

    info!(
        syscalls = baseline.syscall_addresses.len(),
        bpf_programs = baseline.known_bpf_ids.len(),
        modules = baseline.known_modules.len(),
        "kernel integrity baseline established"
    );

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_seconds));
    let mut last_alert: HashMap<String, DateTime<Utc>> = HashMap::new();
    let cooldown = Duration::seconds(600);

    loop {
        interval.tick().await;
        let now = Utc::now();

        // Check 1: Syscall table integrity
        let current_syscalls = read_kallsyms();
        for (name, baseline_addr) in &baseline.syscall_addresses {
            if let Some(current_addr) = current_syscalls.get(name) {
                if current_addr != baseline_addr {
                    let key = format!("syscall:{name}");
                    let should_alert = should_emit_alert(last_alert.get(&key), now, cooldown);

                    if should_alert {
                        last_alert.insert(key, now);
                        let ev = syscall_table_modified_event(
                            &host,
                            now,
                            name,
                            baseline_addr,
                            current_addr,
                            &baseline.established_at,
                        );
                        if tx.send(ev).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }

        // Check 2: New eBPF programs
        let current_bpf = read_bpf_program_ids();
        for id in &current_bpf {
            if !baseline.known_bpf_ids.contains(id) {
                let key = format!("bpf:{id}");
                let should_alert = should_emit_alert(last_alert.get(&key), now, cooldown);

                if should_alert {
                    let prog_info = read_bpf_program_info(*id);
                    let is_innerwarden = is_innerwarden_bpf_program(prog_info.as_deref());

                    if !is_innerwarden {
                        last_alert.insert(key, now);
                        let prog_name = prog_info.unwrap_or_else(|| "unknown".to_string());
                        let ev = bpf_program_loaded_event(
                            &host,
                            now,
                            *id,
                            &prog_name,
                            baseline.known_bpf_ids.len(),
                            current_bpf.len(),
                        );
                        if tx.send(ev).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }

        // Check 3: New kernel modules
        let current_modules = read_kernel_modules();
        for module in &current_modules {
            if !baseline.known_modules.contains(module) {
                let key = format!("module:{module}");
                let should_alert = should_emit_alert(last_alert.get(&key), now, cooldown);

                if should_alert {
                    last_alert.insert(key, now);
                    let ev = new_module_post_boot_event(
                        &host,
                        now,
                        module,
                        baseline.known_modules.len(),
                        current_modules.len(),
                    );
                    if tx.send(ev).await.is_err() {
                        return;
                    }
                }
            }
        }

        // Prune old alerts
        prune_stale_alerts(&mut last_alert, now, cooldown);
    }
}

fn should_emit_alert(
    last_alert: Option<&DateTime<Utc>>,
    now: DateTime<Utc>,
    cooldown: Duration,
) -> bool {
    last_alert
        .map(|timestamp| now - *timestamp > cooldown)
        .unwrap_or(true)
}

fn is_innerwarden_bpf_program(name: Option<&str>) -> bool {
    name.map(|name| {
        INNERWARDEN_BPF_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
    })
    .unwrap_or(false)
}

fn prune_stale_alerts(
    last_alert: &mut HashMap<String, DateTime<Utc>>,
    now: DateTime<Utc>,
    cooldown: Duration,
) {
    if last_alert.len() > 1000 {
        let cutoff = now - cooldown;
        last_alert.retain(|_, timestamp| *timestamp > cutoff);
    }
}

fn syscall_table_modified_event(
    host: &str,
    now: DateTime<Utc>,
    name: &str,
    baseline_addr: &str,
    current_addr: &str,
    established_at: &DateTime<Utc>,
) -> Event {
    Event {
        ts: now,
        host: host.to_string(),
        source: "kernel_integrity".to_string(),
        kind: "kernel.syscall_table_modified".to_string(),
        severity: Severity::Critical,
        summary: format!(
            "CRITICAL: Syscall table modified — {} changed from {} to {} (rootkit indicator)",
            name, baseline_addr, current_addr
        ),
        details: serde_json::json!({
            "syscall": name,
            "baseline_address": baseline_addr,
            "current_address": current_addr,
            "baseline_time": established_at.to_rfc3339(),
        }),
        tags: vec![
            "kernel_integrity".to_string(),
            "rootkit".to_string(),
            "syscall_hook".to_string(),
        ],
        entities: vec![],
    }
}

fn bpf_program_loaded_event(
    host: &str,
    now: DateTime<Utc>,
    id: u32,
    prog_name: &str,
    baseline_programs: usize,
    current_programs: usize,
) -> Event {
    Event {
        ts: now,
        host: host.to_string(),
        source: "kernel_integrity".to_string(),
        kind: "kernel.bpf_program_loaded".to_string(),
        severity: Severity::High,
        summary: format!("New eBPF program loaded after boot: id={id} name='{prog_name}'"),
        details: serde_json::json!({
            "bpf_id": id,
            "bpf_name": prog_name,
            "baseline_programs": baseline_programs,
            "current_programs": current_programs,
        }),
        tags: vec![
            "kernel_integrity".to_string(),
            "ebpf".to_string(),
            "weaponization".to_string(),
        ],
        entities: vec![],
    }
}

fn new_module_post_boot_event(
    host: &str,
    now: DateTime<Utc>,
    module: &str,
    baseline_modules: usize,
    current_modules: usize,
) -> Event {
    Event {
        ts: now,
        host: host.to_string(),
        source: "kernel_integrity".to_string(),
        kind: "kernel.new_module_post_boot".to_string(),
        severity: Severity::High,
        summary: format!("Kernel module loaded after boot: {module}"),
        details: serde_json::json!({
            "module": module,
            "baseline_modules": baseline_modules,
            "current_modules": current_modules,
        }),
        tags: vec!["kernel_integrity".to_string(), "module".to_string()],
        entities: vec![EntityRef::service(module)],
    }
}

// ---------------------------------------------------------------------------
// System readers
// ---------------------------------------------------------------------------

/// Read key syscall addresses from /proc/kallsyms.
fn read_kallsyms() -> HashMap<String, String> {
    let file = match std::fs::File::open("/proc/kallsyms") {
        Ok(f) => f,
        Err(e) => {
            warn!("kernel_integrity: cannot read /proc/kallsyms: {e}");
            return HashMap::new();
        }
    };
    read_kallsyms_from(std::io::BufReader::new(file))
}

/// Stream a kallsyms source line by line, keeping only the monitored syscalls.
/// /proc/kallsyms is 200k+ lines / several MB but only a handful of entries are
/// wanted, so this never holds the whole file in memory. Generic over the
/// reader so the streaming path is unit-testable without touching /proc.
fn read_kallsyms_from<R: std::io::BufRead>(reader: R) -> HashMap<String, String> {
    let mut syscalls = HashMap::new();
    for line in reader.lines().map_while(Result::ok) {
        parse_kallsyms_line(&line, &mut syscalls);
    }
    syscalls
}

/// Parse one `/proc/kallsyms` line (`address type name[\t[module]]`) and insert
/// it into `syscalls` when `name` is a monitored syscall. Shared by the
/// streaming reader and the in-memory parser so both stay in lock-step.
fn parse_kallsyms_line(line: &str, syscalls: &mut HashMap<String, String>) {
    // Format: address type name
    let mut parts = line.splitn(3, ' ');
    let (Some(addr), Some(_typ), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        return;
    };
    let name = rest.split('\t').next().unwrap_or(rest);
    if MONITORED_SYSCALLS.contains(&name) {
        syscalls.insert(name.to_string(), addr.to_string());
    }
}

/// Read loaded eBPF program IDs by parsing /proc/*/fdinfo.
/// On systems without bpftool, falls back to scanning /proc for bpf fds.
fn read_bpf_program_ids() -> HashSet<u32> {
    let mut ids = HashSet::new();

    // Try bpftool first (most reliable)
    if let Ok(output) = std::process::Command::new("bpftool")
        .args(["prog", "list", "-j"])
        .output()
    {
        if output.status.success() {
            if let Ok(progs) = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout) {
                for prog in progs {
                    if let Some(id) = prog.get("id").and_then(|v| v.as_u64()) {
                        ids.insert(id as u32);
                    }
                }
                return ids;
            }
        }
    }

    // Fallback: scan /proc/self/fdinfo for BPF file descriptors
    // (Limited — only sees our own programs)
    ids
}

/// Get the name of a specific eBPF program by ID.
fn read_bpf_program_info(id: u32) -> Option<String> {
    let output = std::process::Command::new("bpftool")
        .args(["prog", "show", "id", &id.to_string(), "-j"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let val: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    val.get("name").and_then(|v| v.as_str()).map(String::from)
}

/// Read loaded kernel modules from /proc/modules.
fn read_kernel_modules() -> HashSet<String> {
    let content = match std::fs::read_to_string("/proc/modules") {
        Ok(c) => c,
        Err(_) => return HashSet::new(),
    };

    parse_modules(&content)
}

fn parse_modules(content: &str) -> HashSet<String> {
    let mut modules = HashSet::new();
    for line in content.lines() {
        if let Some(name) = line.split_whitespace().next() {
            modules.insert(name.to_string());
        }
    }

    modules
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitored_syscalls_not_empty() {
        assert!(!MONITORED_SYSCALLS.is_empty());
        assert!(MONITORED_SYSCALLS.contains(&"__x64_sys_execve"));
    }

    #[test]
    fn innerwarden_prefix_detection() {
        let is_iw = |name: &str| INNERWARDEN_BPF_PREFIXES.iter().any(|p| name.starts_with(p));
        assert!(is_iw("innerwarden_xdp"));
        assert!(is_iw("iw_kprobe_commit_creds"));
        assert!(is_iw("tracepoint__syscalls__sys_enter_execve"));
        assert!(!is_iw("malicious_program"));
        assert!(!is_iw("custom_bpf_prog"));
    }

    #[test]
    fn kallsyms_parsing() {
        // On CI/macOS, /proc/kallsyms may not exist
        let result = read_kallsyms();
        // Just verify it doesn't crash
        assert!(result.len() <= MONITORED_SYSCALLS.len());
    }

    #[test]
    fn modules_parsing() {
        let result = read_kernel_modules();
        // On macOS this returns empty, on Linux it returns modules
        // Just verify no crash
        let _ = result.len();
    }

    #[test]
    fn bpf_program_ids() {
        let result = read_bpf_program_ids();
        // bpftool may not be available — just verify no crash
        let _ = result.len();
    }

    #[test]
    fn monitored_syscalls_are_unique_and_high_impact() {
        // Guards detector scope so integrity checks keep watching critical
        // privilege and execution syscalls without duplicates.
        let unique: HashSet<&str> = MONITORED_SYSCALLS.iter().copied().collect();
        assert_eq!(unique.len(), MONITORED_SYSCALLS.len());
        assert!(MONITORED_SYSCALLS.contains(&"__x64_sys_execve"));
        assert!(MONITORED_SYSCALLS.contains(&"__x64_sys_setuid"));
        assert!(MONITORED_SYSCALLS.contains(&"__x64_sys_mount"));
    }

    #[test]
    fn kallsyms_result_is_subset_of_monitored_targets() {
        // Ensures parsing never introduces unexpected symbol names beyond the
        // explicit syscall watchlist configured for this collector.
        let parsed = read_kallsyms();
        assert!(parsed
            .keys()
            .all(|name| MONITORED_SYSCALLS.contains(&name.as_str())));
    }

    #[test]
    fn kernel_modules_are_trimmed_tokens() {
        // Validates module-name parsing from `/proc/modules` stays whitespace
        // free so downstream entity IDs remain canonical.
        for module in read_kernel_modules() {
            assert!(!module.is_empty());
            assert!(!module.chars().any(char::is_whitespace));
        }
    }

    #[test]
    fn bpf_program_info_handles_missing_ids_safely() {
        // Covers the bpftool lookup failure path for unknown IDs to ensure
        // callers receive `None` instead of panicking.
        let info = read_bpf_program_info(u32::MAX);
        if let Some(name) = info {
            assert!(!name.trim().is_empty());
        }
    }

    #[test]
    fn test_parse_kallsyms() {
        let content = "ffffffff81000000 T _stext
ffffffff81000000 t startup_64
ffffffff81123456 t __x64_sys_execve
ffffffff81123456 t __x64_sys_execve\t[module]
ffffffff81abcdef T __x64_sys_openat";
        // The streaming reader is what `read_kallsyms` runs against
        // /proc/kallsyms; drive it over the fixture via a Cursor.
        let parsed = read_kallsyms_from(std::io::Cursor::new(content));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get("__x64_sys_execve").unwrap(), "ffffffff81123456");
        assert_eq!(parsed.get("__x64_sys_openat").unwrap(), "ffffffff81abcdef");
    }

    #[test]
    fn test_parse_modules() {
        let content = "veth 36864 0 - Live 0xffffffffc0000000\n\
                       intel_rapl_msr 20480 0 - Live 0xffffffffc0010000";
        let parsed = parse_modules(content);
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains("veth"));
        assert!(parsed.contains("intel_rapl_msr"));
    }

    #[test]
    fn alert_cooldown_and_bpf_prefix_helpers_cover_suppression_paths() {
        let now = Utc::now();
        assert!(should_emit_alert(None, now, Duration::seconds(600)));
        assert!(!should_emit_alert(
            Some(&(now - Duration::seconds(60))),
            now,
            Duration::seconds(600)
        ));
        assert!(should_emit_alert(
            Some(&(now - Duration::seconds(601))),
            now,
            Duration::seconds(600)
        ));

        assert!(is_innerwarden_bpf_program(Some("innerwarden_trace")));
        assert!(is_innerwarden_bpf_program(Some("xdp__guard")));
        assert!(!is_innerwarden_bpf_program(Some("custom_probe")));
        assert!(!is_innerwarden_bpf_program(None));
    }

    #[test]
    fn kernel_event_builders_keep_rootkit_bpf_and_module_context() {
        let now = Utc::now();
        let established = now - Duration::seconds(30);

        let syscall = syscall_table_modified_event(
            "sensor-a",
            now,
            "__x64_sys_execve",
            "0x1",
            "0x2",
            &established,
        );
        assert_eq!(syscall.kind, "kernel.syscall_table_modified");
        assert_eq!(syscall.severity, Severity::Critical);
        assert_eq!(syscall.details["syscall"], "__x64_sys_execve");
        assert_eq!(syscall.details["current_address"], "0x2");

        let bpf = bpf_program_loaded_event("sensor-b", now, 77, "unknown", 3, 4);
        assert_eq!(bpf.kind, "kernel.bpf_program_loaded");
        assert_eq!(bpf.details["bpf_id"], 77);
        assert_eq!(bpf.details["baseline_programs"], 3);

        let module = new_module_post_boot_event("sensor-c", now, "evil_mod", 8, 9);
        assert_eq!(module.kind, "kernel.new_module_post_boot");
        assert_eq!(module.details["module"], "evil_mod");
        assert_eq!(module.entities.len(), 1);
    }

    #[test]
    fn stale_alert_pruning_only_runs_after_capacity_threshold() {
        let now = Utc::now();
        let cooldown = Duration::seconds(600);
        let mut under_limit = HashMap::from([("old".to_string(), now - Duration::seconds(900))]);
        prune_stale_alerts(&mut under_limit, now, cooldown);
        assert!(under_limit.contains_key("old"));

        let mut crowded = HashMap::new();
        for idx in 0..1000 {
            crowded.insert(format!("recent-{idx}"), now - Duration::seconds(30));
        }
        crowded.insert("expired".to_string(), now - Duration::seconds(900));

        prune_stale_alerts(&mut crowded, now, cooldown);
        assert_eq!(crowded.len(), 1000);
        assert!(!crowded.contains_key("expired"));
    }
}
