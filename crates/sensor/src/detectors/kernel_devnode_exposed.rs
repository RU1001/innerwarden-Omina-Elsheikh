//! kernel_devnode_exposed — sensitive kernel device-node permission watchdog.
//!
//! A wide class of Linux kernel attack surface is exposed via character /
//! block device nodes: RDMA verbs (`/dev/infiniband/uverbs*`), KVM
//! (`/dev/kvm`), direct memory (`/dev/mem`), userspace I/O kernel drivers
//! (`/dev/uio*`), vhost-net (`/dev/vhost-*`), Intel ME (`/dev/mei*`), and so
//! on. The kernel ships these with conservative defaults, but vendor images
//! and operator post-install scripts frequently relax permissions, exposing
//! large chunks of kernel attack surface to unprivileged users.
//!
//! Real-world trigger that motivated this detector: a default Azure VM with
//! the `mana_ib` (Microsoft Azure InfiniBand) driver ships
//! `/dev/infiniband/uverbs0` and `uverbs1` as mode `0666`. Any unprivileged
//! local user can `open(2)` the RDMA verbs ioctl ABI without any group
//! membership or capability. Every historical CVE class in the RDMA core
//! (CVE-2022-32296, CVE-2023-25775, CVE-2024-23848, …) becomes auto-RCE
//! against a kernel attacker on those hosts. The owner of the host usually
//! has no idea the surface is exposed because they never installed the
//! driver themselves.
//!
//! This detector is the behavioural complement to `lynis` / `cis-cat`:
//! those tools scan once. This detector polls every N seconds and flags a
//! Medium incident the moment a sensitive devnode's permissions are more
//! permissive than the documented safe-default. If an unprivileged process
//! subsequently *opens* the exposed device and gains capabilities, the
//! agent's cross-layer correlation rule **CL-071** escalates the chain to
//! Critical.
//!
//! Architectural decisions, in case future contributors revisit:
//!
//! - **Polling, not event-driven.** `inotify` on `/dev` would fire on
//!   every devnode created by `udev` — high churn, low signal. A periodic
//!   poll covers boot-time misconfiguration AND post-boot `chmod` drift
//!   with the same code path.
//! - **Per-pattern `max_allowed_mode`.** Each watchlist entry declares the
//!   most permissive mode that is still acceptable. A devnode triggers
//!   when its actual mode has any bit set beyond the allowed mask. This is
//!   simpler than per-bit policies and lets operators tune via the
//!   `[detectors.kernel_devnode_exposed.allowlist]` toml section.
//! - **Fail-open on read failures.** If a path glob does not expand or a
//!   `stat(2)` fails, we log `warn!` and skip — never propagate with `?`.
//!   Defends the sensor loop against transient filesystem oddities.
//! - **Cooldown via incident_id.** The event-to-incident promotion path
//!   embeds the path slug and the hour-bucket timestamp in the incident
//!   id so the same exposure does not re-fire every 15 min unless the
//!   permission flips.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Default poll interval. 15 minutes — slow enough that the detector adds
/// no measurable load, fast enough to catch a `chmod` drift inside a
/// reasonable operator response window.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 900;

/// One entry in the watchlist of sensitive devnodes.
///
/// `pattern` is either a literal path (`/dev/kvm`) or a glob
/// (`/dev/uio*`). `max_allowed_mode` is the most permissive mode bits
/// (octal) that we consider safe — any bit set in the actual mode that is
/// **not** set in this mask flags the entry as exposed. `surface` is a
/// human-readable label describing what the device exposes; it is used in
/// the incident summary so operators understand the risk without needing
/// to look the device up.
///
/// `String` fields (not `&'static str`) so operator overrides loaded from
/// TOML at runtime can extend or replace the built-in entries without
/// fighting the borrow checker.
#[derive(Debug, Clone)]
pub struct WatchEntry {
    pub pattern: String,
    pub max_allowed_mode: u32,
    pub surface: String,
}

impl WatchEntry {
    fn new(pattern: &str, max_allowed_mode: u32, surface: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
            max_allowed_mode,
            surface: surface.to_string(),
        }
    }
}

/// Built-in watchlist. The default-safe modes match the documented
/// upstream defaults (or the strictest practical setting for the device
/// class). Operators with legitimate exposures (e.g. a dedicated KVM
/// server group) should override via the allowlist toml section.
pub fn default_watchlist() -> Vec<WatchEntry> {
    vec![
        WatchEntry::new(
            "/dev/infiniband/uverbs*",
            0o660,
            "RDMA verbs ioctl ABI (mana_ib / mlx5 / etc.)",
        ),
        WatchEntry::new("/dev/infiniband/rdma_cm", 0o660, "RDMA Connection Manager"),
        WatchEntry::new("/dev/kvm", 0o660, "KVM hypervisor interface"),
        WatchEntry::new("/dev/mem", 0o600, "Direct physical memory"),
        WatchEntry::new("/dev/kmem", 0o600, "Direct kernel virtual memory"),
        WatchEntry::new("/dev/port", 0o600, "x86 I/O port space"),
        WatchEntry::new("/dev/uio*", 0o660, "Userspace I/O kernel driver"),
        WatchEntry::new(
            "/dev/vhost-*",
            0o660,
            "vhost virtio backend (vhost-net / vhost-scsi)",
        ),
        WatchEntry::new("/dev/mei*", 0o660, "Intel Management Engine interface"),
        WatchEntry::new(
            "/dev/loop-control",
            0o660,
            "Loop device control (mount tricks)",
        ),
        WatchEntry::new("/dev/cuse", 0o660, "Character device in userspace"),
        WatchEntry::new("/dev/dma_heap/*", 0o660, "DMA heap allocator"),
    ]
}

/// Filesystem facade so the detector can be unit-tested without touching
/// the real `/dev/`. Production uses [`RealDevnodeReader`]; tests use a
/// [`tests::MockReader`].
pub trait DevnodeMetadataReader: Send + Sync {
    /// Expand a literal path or glob pattern into the set of paths that
    /// currently exist on the host. Order is implementation-defined.
    fn expand(&self, pattern: &str) -> Vec<PathBuf>;

    /// Return the file mode (low 12 bits) of `path`, or an `io::Error`.
    fn mode_of(&self, path: &Path) -> io::Result<u32>;
}

#[derive(Debug, Default)]
pub struct RealDevnodeReader;

impl DevnodeMetadataReader for RealDevnodeReader {
    fn expand(&self, pattern: &str) -> Vec<PathBuf> {
        expand_pattern(pattern)
    }

    fn mode_of(&self, path: &Path) -> io::Result<u32> {
        let meta = std::fs::symlink_metadata(path)?;
        // Mask to the permission bits (suid/sgid/sticky are not part of
        // the "world-accessible" decision). On Windows (spec 085 Phase 0)
        // there is no unix mode and /dev nodes do not exist, so return 0 ->
        // never world-accessible -> the detector no-ops.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Ok(meta.permissions().mode() & 0o777)
        }
        #[cfg(not(unix))]
        {
            let _ = meta;
            Ok(0)
        }
    }
}

/// Tiny purpose-built matcher for the patterns we use here
/// (`<dir>/<prefix>*<suffix>` shape). We avoid pulling in the `glob`
/// crate as a runtime dependency because the patterns we handle are all
/// of this form — anything more complex would warrant `glob`.
///
/// Behaviour:
///   - No `*` in `pattern`: returns `[pattern]` if the file exists,
///     otherwise empty.
///   - One `*`: split into `<dir>/<file_prefix>*<file_suffix>` and
///     list `dir`, keeping entries whose name starts with
///     `file_prefix` and ends with `file_suffix`.
///   - Multiple `*` or `?` / `[…]`: returns empty and logs a `warn!`
///     — we don't claim to handle those here.
fn expand_pattern(pattern: &str) -> Vec<PathBuf> {
    if !pattern.contains('*') && !pattern.contains('?') && !pattern.contains('[') {
        let p = PathBuf::from(pattern);
        return if p.exists() { vec![p] } else { Vec::new() };
    }
    if pattern.contains('?') || pattern.contains('[') || pattern.matches('*').count() > 1 {
        warn!(
            pattern,
            "kernel_devnode_exposed: pattern uses unsupported wildcard, skipping"
        );
        return Vec::new();
    }
    let star_pos = match pattern.find('*') {
        Some(p) => p,
        None => return Vec::new(),
    };
    let last_slash = pattern[..star_pos].rfind('/').unwrap_or(0);
    let dir = &pattern[..last_slash];
    let file_prefix = &pattern[last_slash + 1..star_pos];
    let file_suffix = &pattern[star_pos + 1..];
    let dir_path = if dir.is_empty() {
        Path::new("/")
    } else {
        Path::new(dir)
    };
    let entries = match std::fs::read_dir(dir_path) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|de| {
            let name = de.file_name().to_string_lossy().into_owned();
            if name.starts_with(file_prefix) && name.ends_with(file_suffix) {
                Some(de.path())
            } else {
                None
            }
        })
        .collect()
}

/// Match a single watchlist entry against the live filesystem.
///
/// `path` is one expanded path (already exists at probe time); `entry`
/// is the rule it matched. Returns `Some(Event)` when the actual mode is
/// strictly more permissive than `entry.max_allowed_mode`.
#[derive(Clone)]
pub struct KernelDevnodeExposedDetector {
    host: String,
    watchlist: Vec<WatchEntry>,
    allowlist: Vec<String>,
    reader: Arc<dyn DevnodeMetadataReader>,
}

impl KernelDevnodeExposedDetector {
    pub fn with_real_reader(
        host: impl Into<String>,
        watchlist: Vec<WatchEntry>,
        allowlist: Vec<String>,
    ) -> Self {
        Self {
            host: host.into(),
            watchlist,
            allowlist,
            reader: Arc::new(RealDevnodeReader),
        }
    }

    /// Test-only ctor that lets us inject a mocked
    /// [`DevnodeMetadataReader`]. Production code goes through
    /// [`Self::with_real_reader`].
    #[cfg(test)]
    pub fn with_reader(
        host: impl Into<String>,
        watchlist: Vec<WatchEntry>,
        allowlist: Vec<String>,
        reader: Arc<dyn DevnodeMetadataReader>,
    ) -> Self {
        Self {
            host: host.into(),
            watchlist,
            allowlist,
            reader,
        }
    }

    pub fn scan_once_at(&self, now: DateTime<Utc>) -> Vec<Event> {
        let mut out = Vec::new();
        for entry in &self.watchlist {
            for path in self.reader.expand(&entry.pattern) {
                if self
                    .allowlist
                    .iter()
                    .any(|a| a.as_str() == path.to_string_lossy())
                {
                    continue;
                }
                match self.reader.mode_of(&path) {
                    Ok(mode) => {
                        let extra_bits = mode & !entry.max_allowed_mode & 0o777;
                        if extra_bits != 0 {
                            out.push(build_exposed_event(&self.host, &path, mode, entry, now));
                        }
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e,
                              "kernel_devnode_exposed: stat failed");
                    }
                }
            }
        }
        out
    }
}

pub async fn run(
    tx: mpsc::Sender<Event>,
    host: String,
    poll_interval_secs: u64,
    watchlist: Vec<WatchEntry>,
    allowlist: Vec<String>,
) {
    let poll_interval_secs = poll_interval_secs.max(1);
    let detector = KernelDevnodeExposedDetector::with_real_reader(host, watchlist, allowlist);
    info!(
        patterns = detector.watchlist.len(),
        poll_interval_secs, "kernel_devnode_exposed detector starting"
    );
    loop {
        let detector_for_poll = detector.clone();
        let events =
            match tokio::task::spawn_blocking(move || detector_for_poll.scan_once_at(Utc::now()))
                .await
            {
                Ok(events) => events,
                Err(e) => {
                    warn!(error = %e, "kernel_devnode_exposed poll task failed");
                    Vec::new()
                }
            };
        for event in events {
            if tx.send(event).await.is_err() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(poll_interval_secs)).await;
        if tx.is_closed() {
            return;
        }
    }
}

fn build_exposed_event(
    host: &str,
    path: &Path,
    actual_mode: u32,
    entry: &WatchEntry,
    polled_at: DateTime<Utc>,
) -> Event {
    let path_str = path.display().to_string();
    Event {
        ts: polled_at,
        host: host.to_string(),
        source: "kernel_devnode_exposed".to_string(),
        kind: "integrity.devnode_exposed".to_string(),
        severity: Severity::Medium,
        summary: format!(
            "Kernel device {path_str} mode {actual_mode:#o} > safe {max:#o} ({surface})",
            max = entry.max_allowed_mode,
            surface = entry.surface,
        ),
        details: serde_json::json!({
            "path": path_str,
            "actual_mode_octal": format!("{actual_mode:#o}"),
            "max_allowed_mode_octal": format!("{:#o}", entry.max_allowed_mode),
            "extra_permission_bits_octal": format!("{:#o}", actual_mode & !entry.max_allowed_mode & 0o777),
            "surface": entry.surface,
            "polled_at": polled_at.to_rfc3339(),
            "mitre_techniques": ["T1068"],
        }),
        tags: vec![
            "integrity".to_string(),
            "devnode".to_string(),
            "hardening".to_string(),
            "T1068".to_string(),
        ],
        entities: vec![EntityRef::path(path_str)],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockReader {
        // pattern -> expanded paths
        expansions: HashMap<String, Vec<PathBuf>>,
        // path -> mode
        modes: Mutex<HashMap<PathBuf, io::Result<u32>>>,
    }

    impl MockReader {
        fn new() -> Self {
            Self {
                expansions: HashMap::new(),
                modes: Mutex::new(HashMap::new()),
            }
        }
        fn with_expansion(mut self, pattern: &str, paths: &[&str]) -> Self {
            self.expansions.insert(
                pattern.to_string(),
                paths.iter().map(PathBuf::from).collect(),
            );
            self
        }
        fn with_mode(self, path: &str, mode: u32) -> Self {
            self.modes
                .lock()
                .unwrap()
                .insert(PathBuf::from(path), Ok(mode));
            self
        }
        fn with_stat_error(self, path: &str, error: io::ErrorKind) -> Self {
            self.modes
                .lock()
                .unwrap()
                .insert(PathBuf::from(path), Err(io::Error::from(error)));
            self
        }
    }

    impl DevnodeMetadataReader for MockReader {
        fn expand(&self, pattern: &str) -> Vec<PathBuf> {
            self.expansions
                .get(pattern)
                .cloned()
                .unwrap_or_else(Vec::new)
        }
        fn mode_of(&self, path: &Path) -> io::Result<u32> {
            let mut modes = self.modes.lock().unwrap();
            match modes.remove(path) {
                Some(r) => r,
                None => Err(io::Error::from(io::ErrorKind::NotFound)),
            }
        }
    }

    fn one_entry(pattern: &str, max: u32) -> Vec<WatchEntry> {
        vec![WatchEntry::new(pattern, max, "test surface")]
    }

    #[test]
    fn world_writable_uverbs_triggers_event() {
        // Azure mana scenario: /dev/infiniband/uverbs0 mode 0666, max 0660
        let reader = MockReader::new()
            .with_expansion("/dev/infiniband/uverbs*", &["/dev/infiniband/uverbs0"])
            .with_mode("/dev/infiniband/uverbs0", 0o666);
        let det = KernelDevnodeExposedDetector::with_reader(
            "test-host",
            one_entry("/dev/infiniband/uverbs*", 0o660),
            vec![],
            Arc::new(reader),
        );
        let events = det.scan_once_at(Utc::now());
        assert_eq!(events.len(), 1, "world-writable devnode must fire");
        let ev = &events[0];
        assert_eq!(ev.kind, "integrity.devnode_exposed");
        assert_eq!(ev.severity, Severity::Medium);
        assert_eq!(ev.details["path"], "/dev/infiniband/uverbs0");
        assert_eq!(ev.details["actual_mode_octal"], "0o666");
        assert_eq!(ev.details["max_allowed_mode_octal"], "0o660");
        // 0o666 & !0o660 & 0o777 = 0o006 (world rw)
        assert_eq!(ev.details["extra_permission_bits_octal"], "0o6");
        assert!(ev
            .tags
            .iter()
            .any(|t| t == "T1068" || t == "hardening" || t == "integrity"));
    }

    #[test]
    fn mode_within_max_does_not_trigger() {
        let reader = MockReader::new()
            .with_expansion("/dev/kvm", &["/dev/kvm"])
            .with_mode("/dev/kvm", 0o660);
        let det = KernelDevnodeExposedDetector::with_reader(
            "test-host",
            one_entry("/dev/kvm", 0o660),
            vec![],
            Arc::new(reader),
        );
        assert!(det.scan_once_at(Utc::now()).is_empty());
    }

    #[test]
    fn stricter_than_max_does_not_trigger() {
        // /dev/kvm mode 0600 (root only) — stricter than max 0660 — fine
        let reader = MockReader::new()
            .with_expansion("/dev/kvm", &["/dev/kvm"])
            .with_mode("/dev/kvm", 0o600);
        let det = KernelDevnodeExposedDetector::with_reader(
            "test-host",
            one_entry("/dev/kvm", 0o660),
            vec![],
            Arc::new(reader),
        );
        assert!(det.scan_once_at(Utc::now()).is_empty());
    }

    #[test]
    fn allowlisted_path_skipped_even_when_exposed() {
        // Operator explicitly accepts the exposure (e.g. dedicated RDMA box)
        let reader = MockReader::new()
            .with_expansion("/dev/infiniband/uverbs*", &["/dev/infiniband/uverbs0"])
            .with_mode("/dev/infiniband/uverbs0", 0o666);
        let det = KernelDevnodeExposedDetector::with_reader(
            "test-host",
            one_entry("/dev/infiniband/uverbs*", 0o660),
            vec!["/dev/infiniband/uverbs0".to_string()],
            Arc::new(reader),
        );
        assert!(det.scan_once_at(Utc::now()).is_empty());
    }

    #[test]
    fn missing_path_is_silently_skipped() {
        // No expansion matches → no events, no warnings
        let reader = MockReader::new();
        let det = KernelDevnodeExposedDetector::with_reader(
            "test-host",
            one_entry("/dev/kvm", 0o660),
            vec![],
            Arc::new(reader),
        );
        assert!(det.scan_once_at(Utc::now()).is_empty());
    }

    #[test]
    fn stat_error_warns_and_skips_path_but_keeps_scanning_others() {
        // First path errors, second path is exposed — we must still emit
        // the second event despite the first failing.
        let reader = MockReader::new()
            .with_expansion("/dev/uio*", &["/dev/uio0", "/dev/uio1"])
            .with_stat_error("/dev/uio0", io::ErrorKind::PermissionDenied)
            .with_mode("/dev/uio1", 0o666);
        let det = KernelDevnodeExposedDetector::with_reader(
            "test-host",
            one_entry("/dev/uio*", 0o660),
            vec![],
            Arc::new(reader),
        );
        let events = det.scan_once_at(Utc::now());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].details["path"], "/dev/uio1");
    }

    #[test]
    fn world_readable_only_mem_triggers() {
        // /dev/mem must be 0600 (root only). 0o644 has world-read =>
        // expose physical memory contents to any process.
        let reader = MockReader::new()
            .with_expansion("/dev/mem", &["/dev/mem"])
            .with_mode("/dev/mem", 0o644);
        let det = KernelDevnodeExposedDetector::with_reader(
            "test-host",
            one_entry("/dev/mem", 0o600),
            vec![],
            Arc::new(reader),
        );
        let events = det.scan_once_at(Utc::now());
        assert_eq!(events.len(), 1);
        // 0o644 & !0o600 = 0o044 (group r + other r)
        assert_eq!(events[0].details["extra_permission_bits_octal"], "0o44");
    }

    #[test]
    fn default_watchlist_covers_the_known_high_impact_devnodes() {
        // Guard against silent regression of the default list: every
        // historically-exploited devnode class must remain present.
        let wl = default_watchlist();
        let patterns: Vec<&str> = wl.iter().map(|w| w.pattern.as_str()).collect();
        for must in &[
            "/dev/infiniband/uverbs*",
            "/dev/kvm",
            "/dev/mem",
            "/dev/kmem",
            "/dev/port",
            "/dev/uio*",
            "/dev/vhost-*",
        ] {
            assert!(
                patterns.contains(must),
                "default_watchlist() must contain {must}; we removed it accidentally"
            );
        }
    }

    #[test]
    fn real_reader_literal_path_resolves_when_present_and_skips_when_absent() {
        let reader = RealDevnodeReader;
        // Path that always exists on a Linux test runner
        let etc = reader.expand("/etc/passwd");
        assert_eq!(etc, vec![PathBuf::from("/etc/passwd")]);
        // Path that almost certainly does not exist
        let nope = reader.expand("/dev/innerwarden-no-such-devnode-xyz");
        assert!(nope.is_empty());
    }
}
