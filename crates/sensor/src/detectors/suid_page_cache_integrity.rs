use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{info, warn};

pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

pub const DEFAULT_ALLOWLIST: &[&str] = &[
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/pkexec",
];

/// Standard directories that hold setuid-root helpers. Top-level dirs are scanned
/// flat; the `lib`/`libexec` trees are walked recursively (bounded) because
/// distro SUID helpers live deep there (ssh-keysign, dbus-daemon-launch-helper,
/// polkit-agent-helper-1, ...).
const SUID_SCAN_DIRS_FLAT: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];
const SUID_SCAN_DIRS_DEEP: &[&str] = &["/usr/lib", "/usr/libexec", "/usr/lib64"];
const SUID_SCAN_MAX_DEPTH: usize = 4;
const SUID_SCAN_MAX_FILES: usize = 1024;

pub trait PageCacheReader: Send + Sync {
    fn path_exists(&self, path: &Path) -> bool;
    fn read_via_page_cache(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn drop_page_cache_for(&self, path: &Path) -> io::Result<()>;
    fn read_direct_from_disk(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Enumerate the live setuid-root binaries on the host so the integrity scan
    /// is not limited to a fixed allowlist. Default empty (mocks/tests stay
    /// deterministic); the real reader walks the standard binary dirs.
    fn enumerate_suid(&self) -> Vec<PathBuf> {
        Vec::new()
    }
}

#[derive(Debug, Default)]
pub struct RealPageCacheReader;

impl PageCacheReader for RealPageCacheReader {
    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read_via_page_cache(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn drop_page_cache_for(&self, path: &Path) -> io::Result<()> {
        fadvise_dontneed(path)
    }

    fn read_direct_from_disk(&self, path: &Path) -> io::Result<Vec<u8>> {
        read_direct(path)
    }

    fn enumerate_suid(&self) -> Vec<PathBuf> {
        enumerate_suid_binaries()
    }
}

/// Walk the standard binary directories and return every regular file carrying
/// the setuid bit (mode & 0o4000). Bounded in depth and count so a pathological
/// filesystem cannot make the scan run away. Best-effort: unreadable dirs are
/// skipped silently (the detector is fail-open). Non-unix builds return empty.
#[cfg(unix)]
fn enumerate_suid_binaries() -> Vec<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let mut found: Vec<PathBuf> = Vec::new();
    let push_if_suid = |path: &Path, found: &mut Vec<PathBuf>| {
        if let Ok(md) = std::fs::symlink_metadata(path) {
            // Real file (not a symlink — we scan the actual binary), setuid set.
            if md.is_file() && md.permissions().mode() & 0o4000 != 0 {
                found.push(path.to_path_buf());
            }
        }
    };

    // Flat dirs: one level only.
    for dir in SUID_SCAN_DIRS_FLAT {
        if found.len() >= SUID_SCAN_MAX_FILES {
            break;
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if found.len() >= SUID_SCAN_MAX_FILES {
                    break;
                }
                push_if_suid(&entry.path(), &mut found);
            }
        }
    }

    // Deep dirs: bounded-depth recursion (BFS).
    let mut stack: Vec<(PathBuf, usize)> = SUID_SCAN_DIRS_DEEP
        .iter()
        .map(|d| (PathBuf::from(d), 0))
        .collect();
    while let Some((dir, depth)) = stack.pop() {
        if found.len() >= SUID_SCAN_MAX_FILES {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Use symlink_metadata so we never follow a symlink into a loop.
            let Ok(md) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if md.is_dir() && depth < SUID_SCAN_MAX_DEPTH {
                stack.push((path, depth + 1));
            } else if md.is_file() && md.permissions().mode() & 0o4000 != 0 {
                found.push(path);
                if found.len() >= SUID_SCAN_MAX_FILES {
                    break;
                }
            }
        }
    }

    found
}

#[cfg(not(unix))]
fn enumerate_suid_binaries() -> Vec<PathBuf> {
    Vec::new()
}

pub struct SuidPageCacheIntegrityDetector<R: PageCacheReader> {
    host: String,
    allowlist: Vec<PathBuf>,
    reader: Arc<R>,
}

impl<R: PageCacheReader> Clone for SuidPageCacheIntegrityDetector<R> {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            allowlist: self.allowlist.clone(),
            reader: Arc::clone(&self.reader),
        }
    }
}

impl SuidPageCacheIntegrityDetector<RealPageCacheReader> {
    pub fn with_real_reader(host: impl Into<String>, allowlist: Vec<PathBuf>) -> Self {
        Self::new(host, allowlist, RealPageCacheReader)
    }
}

impl<R: PageCacheReader> SuidPageCacheIntegrityDetector<R> {
    pub fn new(host: impl Into<String>, allowlist: Vec<PathBuf>, reader: R) -> Self {
        Self {
            host: host.into(),
            allowlist,
            reader: Arc::new(reader),
        }
    }

    pub fn scan_once_at(&self, now: DateTime<Utc>) -> Vec<Event> {
        // Scan the configured floor (always) UNION the live setuid binaries found
        // on the host, deduped. The fixed allowlist alone left every off-list
        // SUID-root helper (fusermount3, Xorg, ntfs-3g, ssh-keysign, distro
        // helpers under /usr/lib*) un-checked for page-cache poisoning.
        let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        let mut targets: Vec<PathBuf> = Vec::new();
        for path in self
            .allowlist
            .iter()
            .cloned()
            .chain(self.reader.enumerate_suid())
        {
            if seen.insert(path.clone()) {
                targets.push(path);
            }
        }
        targets
            .iter()
            .filter_map(|path| self.scan_path(path, now))
            .collect()
    }

    fn scan_path(&self, path: &Path, now: DateTime<Utc>) -> Option<Event> {
        if !self.reader.path_exists(path) {
            return None;
        }

        let via_page_cache = match self.reader.read_via_page_cache(path) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "suid_page_cache_integrity page-cache read failed");
                return None;
            }
        };

        if let Err(e) = self.reader.drop_page_cache_for(path) {
            warn!(path = %path.display(), error = %e, "suid_page_cache_integrity posix_fadvise(POSIX_FADV_DONTNEED) failed");
        }

        let on_disk = match self.reader.read_direct_from_disk(path) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "suid_page_cache_integrity direct disk read failed");
                return None;
            }
        };

        let sha256_via_page_cache = sha256_hex(&via_page_cache);
        let sha256_on_disk = sha256_hex(&on_disk);

        (sha256_on_disk != sha256_via_page_cache).then(|| {
            build_mismatch_event(
                &self.host,
                path,
                &sha256_on_disk,
                &sha256_via_page_cache,
                now,
            )
        })
    }
}

pub async fn run(
    tx: mpsc::Sender<Event>,
    host: String,
    poll_interval_secs: u64,
    allowlist: Vec<PathBuf>,
) {
    let poll_interval_secs = poll_interval_secs.max(1);
    let detector = SuidPageCacheIntegrityDetector::with_real_reader(host, allowlist);

    info!(
        paths = detector.allowlist.len(),
        poll_interval_secs, "suid_page_cache_integrity detector starting"
    );

    loop {
        let detector_for_poll = detector.clone();
        let events =
            match tokio::task::spawn_blocking(move || detector_for_poll.scan_once_at(Utc::now()))
                .await
            {
                Ok(events) => events,
                Err(e) => {
                    warn!(error = %e, "suid_page_cache_integrity poll task failed");
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

fn build_mismatch_event(
    host: &str,
    path: &Path,
    sha256_on_disk: &str,
    sha256_via_page_cache: &str,
    polled_at: DateTime<Utc>,
) -> Event {
    let path_str = path.display().to_string();
    Event {
        ts: polled_at,
        host: host.to_string(),
        source: "suid_page_cache_integrity".to_string(),
        kind: "integrity.page_cache_mismatch".to_string(),
        severity: Severity::Critical,
        summary: format!("SUID binary corrupted in page cache: {path_str}"),
        details: serde_json::json!({
            "path": path_str,
            "sha256_on_disk": sha256_on_disk,
            "sha256_via_page_cache": sha256_via_page_cache,
            "polled_at": polled_at.to_rfc3339(),
            "mitre_techniques": ["T1014", "T1068"],
        }),
        tags: vec![
            "integrity".to_string(),
            "page_cache".to_string(),
            "suid".to_string(),
            "T1014".to_string(),
            "T1068".to_string(),
        ],
        entities: vec![EntityRef::path(path_str)],
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(target_os = "linux")]
fn fadvise_dontneed(path: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let file = std::fs::File::open(path)?;
    let rc = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

#[cfg(not(target_os = "linux"))]
fn fadvise_dontneed(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_direct(path: &Path) -> io::Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(path)?;
    let fd = file.as_raw_fd();
    let block_size = 4096usize;
    let mut ptr: *mut libc::c_void = std::ptr::null_mut();
    let rc = unsafe { libc::posix_memalign(&mut ptr, block_size, block_size) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    let _guard = AlignedBuffer(ptr);

    let mut out = Vec::new();
    loop {
        let nread = unsafe { libc::read(fd, ptr, block_size) };
        if nread < 0 {
            return Err(io::Error::last_os_error());
        }
        if nread == 0 {
            break;
        }
        let nread = nread as usize;
        let chunk = unsafe { std::slice::from_raw_parts(ptr as *const u8, nread) };
        out.extend_from_slice(chunk);
        if nread < block_size {
            break;
        }
    }

    Ok(out)
}

#[cfg(target_os = "linux")]
struct AlignedBuffer(*mut libc::c_void);

#[cfg(target_os = "linux")]
impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe { libc::free(self.0) };
    }
}

#[cfg(not(target_os = "linux"))]
fn read_direct(path: &Path) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashSet, VecDeque};
    use std::sync::Mutex;

    struct MockReader {
        existing_paths: HashSet<PathBuf>,
        page_reads: Mutex<VecDeque<io::Result<Vec<u8>>>>,
        disk_reads: Mutex<VecDeque<io::Result<Vec<u8>>>>,
        fadvise_calls: Mutex<usize>,
        enumerated: Vec<PathBuf>,
    }

    impl MockReader {
        fn new(path: &str) -> Self {
            Self {
                existing_paths: HashSet::from([PathBuf::from(path)]),
                page_reads: Mutex::new(VecDeque::new()),
                disk_reads: Mutex::new(VecDeque::new()),
                fadvise_calls: Mutex::new(0),
                enumerated: Vec::new(),
            }
        }

        fn missing() -> Self {
            Self {
                existing_paths: HashSet::new(),
                page_reads: Mutex::new(VecDeque::new()),
                disk_reads: Mutex::new(VecDeque::new()),
                fadvise_calls: Mutex::new(0),
                enumerated: Vec::new(),
            }
        }

        /// Make this path both exist and be returned by enumerate_suid (i.e. a
        /// live SUID binary discovered dynamically, NOT on the fixed allowlist).
        fn with_enumerated(mut self, path: &str) -> Self {
            self.existing_paths.insert(PathBuf::from(path));
            self.enumerated.push(PathBuf::from(path));
            self
        }

        fn push_page_read(&self, result: io::Result<Vec<u8>>) {
            self.page_reads.lock().unwrap().push_back(result);
        }

        fn push_disk_read(&self, result: io::Result<Vec<u8>>) {
            self.disk_reads.lock().unwrap().push_back(result);
        }

        fn fadvise_call_count(&self) -> usize {
            *self.fadvise_calls.lock().unwrap()
        }
    }

    impl PageCacheReader for MockReader {
        fn path_exists(&self, path: &Path) -> bool {
            self.existing_paths.contains(path)
        }

        fn read_via_page_cache(&self, _path: &Path) -> io::Result<Vec<u8>> {
            self.page_reads
                .lock()
                .unwrap()
                .pop_front()
                .expect("mock page-cache read not queued")
        }

        fn drop_page_cache_for(&self, _path: &Path) -> io::Result<()> {
            *self.fadvise_calls.lock().unwrap() += 1;
            Ok(())
        }

        fn read_direct_from_disk(&self, _path: &Path) -> io::Result<Vec<u8>> {
            self.disk_reads
                .lock()
                .unwrap()
                .pop_front()
                .expect("mock disk read not queued")
        }

        fn enumerate_suid(&self) -> Vec<PathBuf> {
            self.enumerated.clone()
        }
    }

    fn detector(reader: MockReader) -> SuidPageCacheIntegrityDetector<MockReader> {
        SuidPageCacheIntegrityDetector::new("test-host", vec![PathBuf::from("/usr/bin/su")], reader)
    }

    #[test]
    fn test_divergent_hashes_fire_critical_incident() {
        let reader = MockReader::new("/usr/bin/su");
        reader.push_page_read(Ok(b"poisoned-cache".to_vec()));
        reader.push_disk_read(Ok(b"clean-disk".to_vec()));
        let detector = detector(reader);
        let now = DateTime::parse_from_rfc3339("2026-05-23T08:34:34Z")
            .unwrap()
            .with_timezone(&Utc);

        let events = detector.scan_once_at(now);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.kind, "integrity.page_cache_mismatch");
        assert_eq!(event.severity, Severity::Critical);
        assert_eq!(event.details["path"], "/usr/bin/su");
        assert_eq!(event.details["sha256_on_disk"], sha256_hex(b"clean-disk"));
        assert_eq!(
            event.details["sha256_via_page_cache"],
            sha256_hex(b"poisoned-cache")
        );
        assert_eq!(event.details["polled_at"], now.to_rfc3339());
        assert_eq!(event.details["mitre_techniques"][0], "T1014");
        assert_eq!(event.details["mitre_techniques"][1], "T1068");
        assert_eq!(
            event.summary,
            "SUID binary corrupted in page cache: /usr/bin/su"
        );
        assert_eq!(detector.reader.fadvise_call_count(), 1);
    }

    /// Regression anchor (evasion audit E6, 2026-06-20): the detector used to
    /// scan ONLY the fixed 10-path allowlist, so page-cache poisoning of any
    /// off-list SUID-root binary (fusermount3, Xorg, ntfs-3g, ssh-keysign, distro
    /// helpers under /usr/lib*) was never checked. It now also scans every live
    /// SUID binary returned by enumerate_suid(). Here a poisoned binary that is
    /// NOT on the allowlist is discovered via enumeration and fires Critical.
    #[test]
    fn test_enumerated_offlist_suid_binary_is_scanned() {
        let reader = MockReader::new("/usr/bin/su").with_enumerated("/usr/lib/openssh/ssh-keysign");
        // allowlisted /usr/bin/su: clean (page == disk)
        reader.push_page_read(Ok(b"su-clean".to_vec()));
        reader.push_disk_read(Ok(b"su-clean".to_vec()));
        // enumerated off-list ssh-keysign: poisoned (page != disk)
        reader.push_page_read(Ok(b"keysign-poisoned".to_vec()));
        reader.push_disk_read(Ok(b"keysign-clean".to_vec()));
        let detector = detector(reader);

        let events = detector.scan_once_at(Utc::now());

        assert_eq!(
            events.len(),
            1,
            "the off-allowlist SUID binary must be scanned"
        );
        assert_eq!(
            events[0].details["path"], "/usr/lib/openssh/ssh-keysign",
            "the dynamically-enumerated SUID binary fired, not the allowlisted one"
        );
        assert_eq!(events[0].severity, Severity::Critical);
    }

    /// A path on BOTH the allowlist and the enumerated set is scanned once, not
    /// twice (dedup), so we don't double-read/double-alert.
    #[test]
    fn test_allowlist_and_enumerated_overlap_dedup() {
        let reader = MockReader::new("/usr/bin/su").with_enumerated("/usr/bin/su");
        reader.push_page_read(Ok(b"x".to_vec()));
        reader.push_disk_read(Ok(b"x".to_vec()));
        let detector = detector(reader);

        let events = detector.scan_once_at(Utc::now());

        assert!(events.is_empty());
        // exactly one scan happened (one fadvise), proving dedup
        assert_eq!(detector.reader.fadvise_call_count(), 1);
    }

    #[test]
    fn test_matching_hashes_emit_nothing() {
        let reader = MockReader::new("/usr/bin/su");
        reader.push_page_read(Ok(b"same-bytes".to_vec()));
        reader.push_disk_read(Ok(b"same-bytes".to_vec()));
        let detector = detector(reader);

        let events = detector.scan_once_at(Utc::now());

        assert!(events.is_empty());
        assert_eq!(detector.reader.fadvise_call_count(), 1);
    }

    #[test]
    fn test_missing_binary_is_silent_no_op() {
        let detector = detector(MockReader::missing());

        let events = detector.scan_once_at(Utc::now());

        assert!(events.is_empty());
        assert_eq!(detector.reader.fadvise_call_count(), 0);
    }

    #[test]
    fn test_read_failure_is_warn_only_does_not_crash_detector() {
        let reader = MockReader::new("/usr/bin/su");
        reader.push_page_read(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "permission denied",
        )));
        reader.push_page_read(Ok(b"poisoned-cache".to_vec()));
        reader.push_disk_read(Ok(b"clean-disk".to_vec()));
        let detector = detector(reader);

        let first_poll = detector.scan_once_at(Utc::now());
        let second_poll = detector.scan_once_at(Utc::now());

        assert!(first_poll.is_empty());
        assert_eq!(second_poll.len(), 1);
    }

    #[test]
    fn test_real_reader_matching_tempfile_emits_nothing() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let path = dir.path().join("suid-fixture");
        std::fs::write(&path, vec![0x41; 8192]).unwrap();
        let detector =
            SuidPageCacheIntegrityDetector::with_real_reader("test-host", vec![path.clone()]);

        let events = detector.scan_once_at(Utc::now());

        assert!(events.is_empty());
        assert!(detector.reader.path_exists(&path));
    }

    #[tokio::test(start_paused = true)]
    async fn test_run_loop_uses_minimum_interval_and_can_be_cancelled() {
        let (tx, _rx) = mpsc::channel(1);
        let handle = tokio::spawn(run(tx, "test-host".to_string(), 0, Vec::new()));

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        handle.abort();
    }
}
