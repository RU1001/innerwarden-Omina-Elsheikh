use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Paths where executables are expected but not from package managers.
/// These are NOT flagged as drift.
const DEVELOPMENT_PATHS: &[&str] = &[
    "/home/",            // user binaries, development
    "/root/",            // root home
    "/var/lib/docker/",  // container layers
    "/run/",             // runtime mounts
    "/proc/",            // procfs
    "/sys/",             // sysfs
    "/tmp/cargo-",       // cargo build temp files
    "/tmp/rustc",        // rustc temp files
    "/tmp/npm-",         // npm temp files
    "/tmp/pip-",         // pip temp files
    "/tmp/dpkg-",        // dpkg install temp (e.g. /tmp/dpkg-tmp.*)
    "/tmp/apt-",         // apt install temp
    "/var/cache/",       // package manager caches
    "/usr/lib/rustlib/", // Rust toolchain
    "/usr/share/cargo/", // cargo shared
];

/// Processes that legitimately execute from non-standard paths.
const ALLOWED_PROCESSES: &[&str] = &[
    "ld-linux",
    "ld.so",
    "ldconfig",
    "update-alternatives",
    "dpkg",
    "apt",
    "rpm",
    "yum",
    "snap",
    "flatpak",
    "pip",
    "npm",
    "npx",
    "cargo",
    "rustc",
    "cc",
    "cc1",
    "gcc",
    "g++",
    "ld",
    "as",
    "ar",
    "make",
    "cmake",
    "go",
    "python",
    "python3",
    "node",
    "java",
    "innerwarden",
    "prometheus",
    "telegraf",
    "node_export",
    "grafana",
];

/// Detects execution of binaries from unexpected filesystem locations.
///
/// On a well-managed server, binaries should come from package managers
/// (installed in /usr/bin, /usr/sbin, /opt, etc). A binary executed from
/// /tmp, /dev/shm, /var/tmp, or a writable directory outside the trusted
/// paths is suspicious — possible malware, web shell, or post-exploitation.
///
/// This detector complements LSM exec blocking (which blocks /tmp, /dev/shm)
/// by also flagging executions from other non-standard paths that aren't
/// blocked but are suspicious.
pub struct HostDriftDetector {
    host: String,
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
    /// Known good paths from a baseline scan (populated on startup)
    known_paths: HashSet<String>,
}

impl HostDriftDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
            known_paths: HashSet::new(),
        }
    }

    /// Add a known-good executable path to the baseline.
    /// Called during startup from a dpkg/rpm scan.
    #[allow(dead_code)]
    pub fn add_known_path(&mut self, path: String) {
        self.known_paths.insert(path);
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }

        // Only process host events (not containers)
        let cgroup_id = event
            .details
            .get("cgroup_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let container_id = event
            .details
            .get("container_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !container_id.is_empty() || cgroup_id != 0 {
            return None; // Container events handled by container_drift detector
        }

        // Prefer "filename" (eBPF events carry the binary path).
        // Fallback: extract the binary path from "argv[0]" or the first
        // whitespace-delimited token of "command".  Using the raw command
        // string would match argument text (e.g. "/tmp/script.sh" passed
        // as a bash -c argument), producing floods of false positives.
        let filename: String = event
            .details
            .get("filename")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                // Try argv[0] first (exec_audit gives full argv array)
                event
                    .details
                    .get("argv")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .or_else(|| {
                // Last resort: first token of "command" (the binary path)
                event
                    .details
                    .get("command")
                    .and_then(|v| v.as_str())
                    .and_then(|cmd| cmd.split_whitespace().next())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        if filename.is_empty() {
            return None;
        }
        let filename = filename.as_str();

        // Non-absolute path → the sensor couldn't resolve the binary location
        // for this event. "pgrep" vs "/usr/bin/pgrep" are semantically
        // different: the latter is a real location we can compare against
        // TRUSTED_PATHS, the former is a name without context. Firing a
        // "Host drift: executed from non-standard path" alert for a bare
        // name is wrong by construction — we don't know WHERE it executed
        // from. Observed 2026-04-11 as 23,673 Medium "host_drift pgrep pid=0
        // uid=0 comm=unknown" incidents per day, all from unresolved events.
        // Real drift (binary in /tmp, /dev/shm, /home/…) has an absolute
        // path and is unaffected by this guard.
        if !filename.starts_with('/') {
            return None;
        }

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Skip allowlisted processes — but ONLY when the binary is not in an
        // untrusted staging dir. `comm` is forgeable (argv0 / prctl), so a
        // payload renamed `cargo` from /tmp must not escape via the comm
        // allowlist; the exe path is non-forgeable (spec 072 Part D-sensor).
        if is_allowed_process(comm) && !path_in_untrusted_staging(filename) {
            return None;
        }

        // Skip if in trusted path
        if is_trusted_path(filename) || is_development_path(filename) {
            return None;
        }

        // Skip if in the known-good baseline
        if self.known_paths.contains(filename) {
            return None;
        }

        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Classify severity based on path
        let severity = classify_path_severity(filename);

        let key = format!("host_drift:{filename}");
        if let Some(&last) = self.alerted.get(&key) {
            if event.ts - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key, event.ts);

        if self.alerted.len() > 500 {
            let cutoff = event.ts - self.cooldown;
            self.alerted.retain(|_, t| *t > cutoff);
        }

        Some(Incident {
            ts: event.ts,
            host: self.host.clone(),
            incident_id: format!("host_drift:{comm}:{}", event.ts.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title: format!("Host drift: {comm} executed from non-standard path"),
            summary: format!(
                "Binary '{filename}' was executed from a non-standard location. \
                 Process: {comm} (pid={pid}, uid={uid}). This path is not in the \
                 trusted package manager directories (/usr/bin, /usr/sbin, /opt, etc.) \
                 and was not in the system baseline."
            ),
            evidence: serde_json::json!([{
                "kind": "host_drift",
                "filename": filename,
                "comm": comm,
                "pid": pid,
                "uid": uid,
                // Spec 072 Part D-sensor: non-forgeable staging classification.
                "exe_untrusted_staging": path_in_untrusted_staging(filename),
            }]),
            recommended_checks: vec![
                format!("Inspect binary: file {filename} && sha256sum {filename}"),
                format!("Check provenance: dpkg -S {filename} || rpm -qf {filename}"),
                format!("Check process: ps -p {pid} -o pid,ppid,user,comm,args"),
                format!("Check file age: stat {filename}"),
            ],
            tags: vec!["host_drift".to_string(), "unexpected_binary".to_string()],
            entities: vec![EntityRef::path(filename)],
        })
    }
}

fn is_trusted_path(path: &str) -> bool {
    // Single source of truth shared with `kernel_promote`'s memfd trust check
    // (cross-test: `host_drift_and_path_trust_agree`).
    crate::path_trust::is_trusted_system_path(path)
}

fn is_development_path(path: &str) -> bool {
    DEVELOPMENT_PATHS.iter().any(|p| path.starts_with(p))
}

fn is_allowed_process(comm: &str) -> bool {
    // Short names (cc, ld, as, ar) require exact match to avoid false allowlisting
    // (e.g., "cca" is not "cc"). Longer names use starts_with for variants
    // (e.g., "cargo-build" starts with "cargo").
    ALLOWED_PROCESSES.iter().any(|p| {
        if p.len() <= 3 {
            comm == *p
        } else {
            comm == *p || comm.starts_with(p)
        }
    })
}

/// Untrusted staging directories — a binary here is malware staging, never a
/// real allowlisted tool. Spec 072 Part D-sensor: the exe path (`filename`) is
/// captured at execve and is non-forgeable, unlike `comm`.
fn path_in_untrusted_staging(path: &str) -> bool {
    path.starts_with("/tmp/") || path.starts_with("/dev/shm/") || path.starts_with("/var/tmp/")
}

fn classify_path_severity(path: &str) -> Severity {
    // High-risk temp directories (malware staging)
    if path_in_untrusted_staging(path) {
        return Severity::Critical;
    }
    // World-writable or unusual locations
    if path.starts_with("/var/www/")
        || path.starts_with("/var/cache/")
        || path.contains("/.hidden")
        || path.contains("/...")
    {
        return Severity::High;
    }
    Severity::Medium
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Event;

    fn exec_event(comm: &str, filename: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("{comm} exec {filename}"),
            details: serde_json::json!({
                "comm": comm,
                "filename": filename,
                "pid": 1234,
                "uid": 0,
                "cgroup_id": 0,
                "container_id": "",
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn detects_tmp_execution() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("evil", "/tmp/payload");
        let inc = det.process(&ev);
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    // Spec 072 Part D-sensor: the comm allowlist is gated on the non-forgeable
    // exe path so a renamed payload in a staging dir cannot escape via it.
    #[test]
    fn allowlisted_comm_from_raw_staging_fires() {
        // comm spoofed to `cargo` but the binary is a raw /tmp payload → FIRE.
        let mut det = HostDriftDetector::new("test", 300);
        let inc = det.process(&exec_event("cargo", "/tmp/payload"));
        assert!(
            inc.is_some(),
            "an allowlisted comm running from a raw staging path must not be skipped"
        );
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn allowlisted_comm_from_cargo_build_temp_still_skipped() {
        // Regression: real cargo build temp files (/tmp/cargo-*) are a
        // development path and stay suppressed — the staging gate did not
        // break legitimate builds.
        let mut det = HostDriftDetector::new("test", 300);
        assert!(det
            .process(&exec_event("cargo", "/tmp/cargo-abc123/build-script-build"))
            .is_none());
    }

    #[test]
    fn allowlisted_comm_from_nonstaging_path_still_skipped() {
        // A non-staging, non-trusted path with an allowlisted comm still skips
        // via the comm allowlist (the gate only revokes it for staging dirs).
        let mut det = HostDriftDetector::new("test", 300);
        assert!(det
            .process(&exec_event("cargo", "/srv/build/cargo"))
            .is_none());
    }

    #[test]
    fn path_in_untrusted_staging_classifies_dirs() {
        assert!(path_in_untrusted_staging("/tmp/x"));
        assert!(path_in_untrusted_staging("/var/tmp/x"));
        assert!(path_in_untrusted_staging("/dev/shm/x"));
        assert!(!path_in_untrusted_staging("/usr/bin/cargo"));
        assert!(!path_in_untrusted_staging("/srv/build/cargo"));
    }

    #[test]
    fn detects_devshm_execution() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("miner", "/dev/shm/xmrig");
        let inc = det.process(&ev);
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn detects_webroot_execution() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("php", "/var/www/html/shell.php");
        let inc = det.process(&ev);
        assert!(inc.is_some());
        assert_eq!(inc.unwrap().severity, Severity::High);
    }

    #[test]
    fn allows_trusted_path() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("bash", "/usr/bin/bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn host_drift_and_path_trust_agree() {
        // Cross-test: host_drift's exec-location trust check and the shared
        // `path_trust` predicate kernel_promote uses for memfd creators MUST
        // agree, so a binary trusted for one is trusted for the other. Pins the
        // single-source-of-truth refactor.
        use crate::path_trust::is_trusted_system_path;
        for p in [
            "/usr/bin/fwupdmgr",
            "/usr/local/bin/innerwarden-agent",
            "/lib/systemd/systemd-executor",
        ] {
            assert!(is_trusted_path(p), "drift should trust {p}");
            assert!(is_trusted_system_path(p), "path_trust should trust {p}");
        }
        for p in ["/tmp/iw_dl_sensor", "/dev/shm/x", "/home/u/payload"] {
            assert!(!is_trusted_path(p), "drift should distrust {p}");
            assert!(!is_trusted_system_path(p), "path_trust should distrust {p}");
        }
    }

    #[test]
    fn allows_opt_path() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("innerwarden-sensor", "/opt/innerwarden/bin/sensor");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_container_events() {
        let mut det = HostDriftDetector::new("test", 300);
        let mut ev = exec_event("evil", "/tmp/payload");
        ev.details["container_id"] = serde_json::json!("abc123");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn known_path_baseline() {
        let mut det = HostDriftDetector::new("test", 300);
        det.add_known_path("/custom/bin/mytool".to_string());
        let ev = exec_event("mytool", "/custom/bin/mytool");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn allows_package_manager() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("dpkg", "/tmp/dpkg-tmp.123");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn cooldown_works() {
        let mut det = HostDriftDetector::new("test", 300);
        let ev = exec_event("evil", "/tmp/payload");
        assert!(det.process(&ev).is_some());
        assert!(det.process(&ev).is_none());
    }
}
