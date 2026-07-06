//! SUID binary inventory collector.
//!
//! Periodically scans the filesystem for setuid/setgid binaries and
//! maintains a baseline. Alerts when new SUID binaries appear,
//! especially in suspicious paths (/tmp, /dev/shm).

use std::collections::HashMap;
use std::path::Path;

use chrono::Utc;
use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::info;

/// Paths to scan for SUID binaries.
const SCAN_PATHS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/libexec",
    "/bin",
    "/sbin",
    "/opt",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
];

/// Dangerous paths where SUID binaries should never exist.
const DANGER_PATHS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/home", "/root"];

#[derive(Debug, Clone)]
struct SuidBinary {
    path: String,
    mode: u32,
    uid: u32,
    size: u64,
    sha256: String,
}

pub async fn run(tx: mpsc::Sender<Event>, host_id: String, interval_secs: u64) {
    info!("suid_inventory: starting (interval: {interval_secs}s)");

    // Build initial baseline
    let mut baseline: HashMap<String, SuidBinary> = HashMap::new();
    let initial = scan_suid_binaries();
    for bin in &initial {
        baseline.insert(bin.path.clone(), bin.clone());
    }
    info!("suid_inventory: baseline {} SUID binaries", baseline.len());

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

        let current = scan_suid_binaries();
        let now = Utc::now();

        for bin in &current {
            let is_new = !baseline.contains_key(&bin.path);
            let hash_changed = baseline
                .get(&bin.path)
                .map(|b| b.sha256 != bin.sha256)
                .unwrap_or(false);

            if !is_new && !hash_changed {
                continue;
            }

            let event = build_suid_change_event(&host_id, now, bin, is_new);

            let _ = tx.send(event).await;
            baseline.insert(bin.path.clone(), bin.clone());
        }
    }
}

fn scan_suid_binaries() -> Vec<SuidBinary> {
    let mut results = Vec::new();

    for scan_path in SCAN_PATHS {
        let path = Path::new(scan_path);
        if !path.exists() {
            continue;
        }
        scan_dir_recursive(path, &mut results, 3); // max depth 3
    }

    results
}

fn scan_dir_recursive(dir: &Path, results: &mut Vec<SuidBinary>, depth: u32) {
    if depth == 0 {
        return;
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.is_dir() {
            scan_dir_recursive(&path, results, depth - 1);
            continue;
        }

        if !path.is_file() {
            continue;
        }

        let Ok(meta) = path.metadata() else {
            continue;
        };

        let mode = meta_mode(&meta);

        // Check for SUID (0o4000) or SGID (0o2000)
        if mode & 0o6000 == 0 {
            continue;
        }

        let sha256 = match compute_sha256(&path) {
            Some(h) => h,
            None => continue,
        };

        results.push(SuidBinary {
            path: path.to_string_lossy().to_string(),
            mode,
            uid: meta_uid(&meta),
            size: meta.len(),
            sha256,
        });
    }
}

fn build_suid_change_event(
    host_id: &str,
    now: chrono::DateTime<Utc>,
    bin: &SuidBinary,
    is_new: bool,
) -> Event {
    let in_danger_path = is_in_danger_path(&bin.path);
    let severity = classify_suid_change_severity(is_new, in_danger_path);
    let action = suid_action_label(is_new);

    Event {
        ts: now,
        host: host_id.to_string(),
        source: "suid_inventory".into(),
        kind: format!("file.{action}"),
        severity,
        summary: format!(
            "SUID binary {}: {} (mode: {:o}, sha256: {})",
            action,
            bin.path,
            bin.mode,
            &bin.sha256[..16]
        ),
        details: serde_json::json!({
            "action": action,
            "path": bin.path,
            "mode": format!("{:o}", bin.mode),
            "uid": bin.uid,
            "size": bin.size,
            "sha256": bin.sha256,
            "in_danger_path": in_danger_path,
        }),
        tags: vec!["suid".into(), "inventory".into()],
        entities: vec![EntityRef::path(bin.path.clone())],
    }
}

fn compute_sha256(path: &Path) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    if data.len() > 100_000_000 {
        return None; // Skip files >100MB
    }
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(format!("{:x}", hasher.finalize()))
}

fn is_in_danger_path(path: &str) -> bool {
    DANGER_PATHS.iter().any(|prefix| path.starts_with(prefix))
}

fn classify_suid_change_severity(is_new: bool, in_danger_path: bool) -> Severity {
    if in_danger_path {
        Severity::Critical
    } else if is_new {
        Severity::High
    } else {
        Severity::Medium
    }
}

fn suid_action_label(is_new: bool) -> &'static str {
    if is_new {
        "new_suid"
    } else {
        "suid_modified"
    }
}

#[cfg(unix)]
fn meta_uid(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.uid()
}

#[cfg(not(unix))]
fn meta_uid(_meta: &std::fs::Metadata) -> u32 {
    0
}

// SUID/SGID bits are a unix file-mode concept. On Windows (spec 085 Phase 0)
// there is no mode, so return 0 -> no file matches the 0o6000 mask -> the SUID
// inventory is empty (safe no-op). Real Windows behaviour is a later phase.
#[cfg(unix)]
fn meta_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn meta_mode(_meta: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_danger_paths() {
        // Ensures path risk classifier catches canonical unsafe writable locations.
        assert!(is_in_danger_path("/tmp/evil"));
        assert!(is_in_danger_path("/dev/shm/backdoor"));
        assert!(!is_in_danger_path("/usr/bin/sudo"));
    }

    #[test]
    fn classify_suid_change_severity_prioritizes_danger_paths() {
        // Verifies dangerous locations are always critical regardless of change type.
        assert!(matches!(
            classify_suid_change_severity(true, true),
            Severity::Critical
        ));
        assert!(matches!(
            classify_suid_change_severity(false, true),
            Severity::Critical
        ));
    }

    #[test]
    fn classify_suid_change_severity_distinguishes_new_and_modified_binaries() {
        // Guards normal severity split between new SUID creation and hash-only drift.
        assert!(matches!(
            classify_suid_change_severity(true, false),
            Severity::High
        ));
        assert!(matches!(
            classify_suid_change_severity(false, false),
            Severity::Medium
        ));
    }

    #[test]
    fn suid_action_label_matches_change_kind() {
        // Confirms event kind labels remain stable for downstream routing and analytics.
        assert_eq!(suid_action_label(true), "new_suid");
        assert_eq!(suid_action_label(false), "suid_modified");
    }

    #[test]
    fn compute_sha256_hashes_small_files_and_ignores_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("payload.bin");
        std::fs::write(&file, b"innerwarden").unwrap();

        let digest = compute_sha256(&file).unwrap();
        assert_eq!(
            digest,
            "de10c070ac7779a62bda785e6cf5708cfc82f0c131d093a47f963cc1443c1d6f"
        );
        assert!(compute_sha256(&dir.path().join("missing.bin")).is_none());
    }

    // SUID bits are unix-only (set_mode); the collector no-ops on Windows.
    #[cfg(unix)]
    #[test]
    fn scan_dir_recursive_collects_suid_files_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("regular");
        let suid = dir.path().join("helper");
        std::fs::write(&regular, b"regular").unwrap();
        std::fs::write(&suid, b"suid").unwrap();

        let mut perms = std::fs::metadata(&suid).unwrap().permissions();
        perms.set_mode(0o4755);
        std::fs::set_permissions(&suid, perms).unwrap();

        let mut results = Vec::new();
        scan_dir_recursive(dir.path(), &mut results, 2);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, suid.to_string_lossy());
        assert_eq!(results[0].sha256.len(), 64);
    }

    #[test]
    fn suid_change_event_marks_dangerous_new_binaries_as_critical() {
        let bin = SuidBinary {
            path: "/tmp/dropper".to_string(),
            mode: 0o4755,
            uid: 0,
            size: 12,
            sha256: "0123456789abcdef0123456789abcdef".to_string(),
        };

        let ev = build_suid_change_event("sensor-a", Utc::now(), &bin, true);
        assert_eq!(ev.kind, "file.new_suid");
        assert_eq!(ev.severity, Severity::Critical);
        assert_eq!(ev.details["in_danger_path"], true);
        assert_eq!(ev.entities[0].value, "/tmp/dropper");
    }

    #[test]
    fn suid_change_event_marks_non_dangerous_modifications_as_medium() {
        let bin = SuidBinary {
            path: "/usr/bin/tool".to_string(),
            mode: 0o2755,
            uid: 0,
            size: 24,
            sha256: "fedcba9876543210fedcba9876543210".to_string(),
        };

        let ev = build_suid_change_event("sensor-b", Utc::now(), &bin, false);
        assert_eq!(ev.kind, "file.suid_modified");
        assert_eq!(ev.severity, Severity::Medium);
        assert_eq!(ev.details["action"], "suid_modified");
    }
}
