use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects fileless malware execution via eBPF execve events.
///
/// Fileless execution occurs when a binary runs from memory-backed paths
/// rather than on-disk files. Attackers use memfd_create, /proc/self/fd,
/// or deleted binaries to evade file-based detection.
///
/// Suspicious paths:
///   - /memfd:*         - anonymous memory-backed file (memfd_create)
///   - /dev/fd/*        - file descriptor pseudo-filesystem
///   - /proc/self/fd/*  - process file descriptor symlinks
///   - /proc/<pid>/fd/* - another process's file descriptors
///   - *(deleted)       - binary was deleted after execution started
pub struct FilelessDetector {
    window: Duration,
    /// Suppress re-alerts per pid within window
    alerted: HashMap<u32, DateTime<Utc>>,
    host: String,
}

/// systemd manager binaries (the system + per-user manager and its per-unit
/// executor helper), matched by the NON-FORGEABLE on-disk exe path read from
/// `/proc/<ppid>/exe` — never the spoofable `comm`. systemd v254+ copies
/// `systemd-executor` into a sealed memfd and `fexecve`s it via
/// `/proc/self/fd/N`, so the launching process is always a direct child of one
/// of these.
const SYSTEMD_MANAGER_EXES: &[&str] = &[
    "/lib/systemd/systemd",
    "/usr/lib/systemd/systemd",
    "/lib/systemd/systemd-executor",
    "/usr/lib/systemd/systemd-executor",
];

impl FilelessDetector {
    pub fn new(host: impl Into<String>, window_seconds: u64) -> Self {
        Self {
            window: Duration::seconds(window_seconds as i64),
            alerted: HashMap::new(),
            host: host.into(),
        }
    }

    /// Returns true if the path indicates fileless execution.
    fn is_fileless_path(path: &str) -> bool {
        path.starts_with("/memfd:")
            || path.starts_with("/dev/fd/")
            || path.starts_with("/proc/self/fd/")
            || path.starts_with("/proc/")
                && path.contains("/fd/")
                && path
                    .strip_prefix("/proc/")
                    .and_then(|rest| rest.split('/').next())
                    .map(|seg| seg.chars().all(|c| c.is_ascii_digit()))
                    .unwrap_or(false)
            || path.ends_with("(deleted)")
    }

    /// True when this fileless exec is systemd's sealed-executor unit-launch
    /// mechanism, identified by NON-FORGEABLE lineage — never the spoofable
    /// `comm`.
    ///
    /// systemd v254+ copies `systemd-executor` into a sealed memfd and
    /// `fexecve`s it via `/proc/self/fd/N` (the running process's own fd) at the
    /// start of every unit, so on a busy host the fileless detector fires
    /// Critical hundreds of times a day (prod Azure 7d: 1206, all
    /// `comm=systemd`). The tell is that the LAUNCHING PROCESS IS A DIRECT CHILD
    /// OF SYSTEMD: the caller reads `/proc/<ppid>/exe` (the kernel symlink,
    /// which `prctl(PR_SET_NAME)` / `argv[0]` cannot forge) and passes it here.
    ///
    /// Anti-evasion — this stays deliberately narrow:
    ///   * Only the *self*-fd `fexecve` form is systemd's pattern. A `/memfd:`,
    ///     `/dev/fd/`, `(deleted)`, or `/proc/<other-pid>/fd/` backing keeps
    ///     firing even when the parent is systemd.
    ///   * A shell / dropper launching a fileless payload
    ///     (`bash -c 'exec /proc/self/fd/3'`) has parent exe `/usr/bin/bash`,
    ///     NOT a systemd manager → still fires.
    ///   * `parent_exe == None` (raced/gone/EACCES) does NOT suppress — fail
    ///     safe to firing.
    ///   * The memfd payload itself is still caught at creation time by
    ///     `kernel_promote` (`process.memfd_create`, exe-path trust), so the
    ///     residual case (a root attacker double-forks to reparent to PID 1 then
    ///     `fexecve`s its own memfd) is still seen one layer up.
    fn is_systemd_unit_launch(command: &str, pid: u32, parent_exe: Option<&str>) -> bool {
        let self_fexecve = command.starts_with("/proc/self/fd/")
            || command.starts_with(&format!("/proc/{pid}/fd/"));
        if !self_fexecve {
            return false;
        }
        matches!(parent_exe, Some(exe) if SYSTEMD_MANAGER_EXES.contains(&exe))
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" {
            return None;
        }

        let command = event.details["command"].as_str().unwrap_or("");
        if command.is_empty() || !Self::is_fileless_path(command) {
            return None;
        }

        let pid = event.details["pid"].as_u64()? as u32;
        let uid = event.details["uid"].as_u64().unwrap_or(0) as u32;
        let comm = event.details["comm"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        // Container runtimes (runc, crun, containerd-shim) legitimately execute
        // from memfd/procfs paths. Not fileless malware.
        if comm == "runc"
            || comm.starts_with("containerd")
            || comm == "crun"
            || comm.starts_with("docker")
        {
            return None;
        }

        // Non-forgeable suppression of systemd's sealed-executor unit launch
        // (prod Azure 7d: 1206 Critical FPs, all comm=systemd). Resolve the
        // launching lineage via /proc/<ppid>/exe (kernel symlink, not the
        // spoofable comm); only the self-fd fexecve form with a systemd-manager
        // parent is suppressed — see `is_systemd_unit_launch` for the
        // anti-evasion boundary (memfd/dev-fd/deleted/shell-parent still fire).
        let ppid = event.details["ppid"].as_u64().unwrap_or(0) as u32;
        if ppid != 0 {
            let parent_exe = crate::detectors::provenance::read_exe(ppid);
            if Self::is_systemd_unit_launch(command, pid, parent_exe.as_deref()) {
                return None;
            }
        }

        let container_id = event.details["container_id"]
            .as_str()
            .map(|s| s.to_string());

        let now = event.ts;

        // Suppress re-alerts for same pid within window
        if let Some(&last) = self.alerted.get(&pid) {
            if now - last < self.window {
                return None;
            }
        }
        self.alerted.insert(pid, now);

        let severity = Severity::Critical;

        let mut tags = vec![
            "ebpf".to_string(),
            "fileless".to_string(),
            "malware".to_string(),
        ];
        let mut entities = vec![];
        if let Some(ref cid) = container_id {
            tags.push("container".to_string());
            entities.push(EntityRef::container(cid));
        }

        let summary = if let Some(ref cid) = container_id {
            format!(
                "Fileless execution: {comm} (pid={pid}, uid={uid}) running from {command} in container {cid}"
            )
        } else {
            format!("Fileless execution: {comm} (pid={pid}, uid={uid}) running from {command}")
        };

        // Prune stale entries
        if self.alerted.len() > 1000 {
            let cutoff = now - self.window;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "fileless:{comm}:{pid}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!("Fileless execution detected: {command}"),
            summary,
            evidence: serde_json::json!([{
                "kind": "fileless_execution",
                "comm": comm,
                "pid": pid,
                "uid": uid,
                "command": command,
                "container_id": container_id,
            }]),
            recommended_checks: vec![
                format!("Investigate process {comm} (pid={pid}) - fileless execution is a strong indicator of malware"),
                format!("Check parent process: ps -o ppid= -p {pid}"),
                format!("Dump process memory: cat /proc/{pid}/maps"),
                "Review network connections from this process: ss -tunp | grep {pid}".to_string(),
                "If unexpected: kill the process immediately and investigate the attack vector".to_string(),
            ],
            tags,
            entities,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A pid guaranteed to be ABOVE the kernel `pid_max` ceiling (2^22 =
    /// 4_194_304), so `/proc/<DEAD_PID>` never exists and `read_exe` is
    /// deterministically `None`. The detector fixtures use this as the parent
    /// pid so the live `/proc/<ppid>/exe` resolution in `process()` does NOT
    /// race a real (possibly systemd, on a root CI box) pid and flip the
    /// systemd-launch suppression on/off non-deterministically. See
    /// RECURRING_BUGS.md "Flaky tests that read REAL /proc with a small
    /// hardcoded pid". The systemd-suppression itself is covered separately by
    /// the pure `is_systemd_unit_launch` tests with an injected `parent_exe`.
    const DEAD_PID: u32 = 4_000_000_001;

    fn fileless_event(
        command: &str,
        comm: &str,
        pid: u32,
        container_id: Option<&str>,
        ts: DateTime<Utc>,
    ) -> Event {
        let mut details = serde_json::json!({
            "pid": pid,
            "uid": 1000,
            "ppid": DEAD_PID,
            "comm": comm,
            "command": command,
            "argv": [command],
            "argc": 1,
            "cgroup_id": 0,
        });
        if let Some(cid) = container_id {
            details["container_id"] = serde_json::Value::String(cid.to_string());
        }

        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Shell command executed: {command}"),
            details,
            tags: vec!["ebpf".to_string(), "exec".to_string()],
            entities: vec![],
        }
    }

    #[test]
    fn detects_memfd_execution() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&fileless_event(
            "/memfd:payload",
            "malware",
            1234,
            None,
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("/memfd:payload"));
        assert!(inc.summary.contains("malware"));
    }

    #[test]
    fn detects_dev_fd_execution() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&fileless_event("/dev/fd/3", "bash", 5678, None, now));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("/dev/fd/3"));
    }

    #[test]
    fn detects_proc_self_fd_execution() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&fileless_event(
            "/proc/self/fd/63",
            "python3",
            9999,
            None,
            now,
        ));
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains("/proc/self/fd/63"));
    }

    #[test]
    fn detects_proc_pid_fd_execution() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&fileless_event("/proc/1234/fd/5", "sh", 4321, None, now));
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains("/proc/1234/fd/5"));
    }

    #[test]
    fn detects_deleted_binary() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&fileless_event(
            "/tmp/dropper (deleted)",
            "dropper",
            7777,
            None,
            now,
        ));
        assert!(inc.is_some());
        assert!(inc.unwrap().title.contains("(deleted)"));
    }

    #[test]
    fn detects_container_fileless() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let inc = det.process(&fileless_event(
            "/memfd:exploit",
            "exploit",
            1234,
            Some("abc123def456"),
            now,
        ));
        assert!(inc.is_some());
        let inc = inc.unwrap();
        assert!(inc.summary.contains("container"));
        assert!(inc.tags.contains(&"container".to_string()));
    }

    #[test]
    fn suppresses_realert() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&fileless_event("/memfd:x", "mal", 1234, None, now))
            .is_some());
        assert!(det
            .process(&fileless_event(
                "/memfd:x",
                "mal",
                1234,
                None,
                now + Duration::seconds(5)
            ))
            .is_none());
    }

    #[test]
    fn different_pids_alert_independently() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&fileless_event("/memfd:a", "mal", 100, None, now))
            .is_some());
        assert!(det
            .process(&fileless_event("/memfd:b", "mal", 200, None, now))
            .is_some());
    }

    #[test]
    fn ignores_normal_execution() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        assert!(det
            .process(&fileless_event("/usr/bin/curl", "curl", 1234, None, now))
            .is_none());
        assert!(det
            .process(&fileless_event("/bin/bash", "bash", 1234, None, now))
            .is_none());
    }

    #[test]
    fn ignores_non_exec_events() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        let event = Event {
            ts: now,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: "not an exec".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn does_not_match_proc_non_numeric() {
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();

        // /proc/cpuinfo contains /proc/ but is not a fileless path
        assert!(det
            .process(&fileless_event("/proc/cpuinfo", "cat", 1234, None, now))
            .is_none());
        // /proc/net/fd/something - "net" is not a pid
        assert!(det
            .process(&fileless_event("/proc/net/fd/1", "cat", 1234, None, now))
            .is_none());
    }

    // ─────────────────────────────────────────────────────────────────
    // systemd sealed-executor suppression (prod Azure FP: 1206 Critical/wk,
    // all comm=systemd). Pure-fn tests with an INJECTED parent_exe so they
    // never read live /proc (deterministic) and prove the anti-evasion
    // boundary. The detector wiring resolves parent_exe via
    // provenance::read_exe(ppid) in process().
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn systemd_self_fexecve_with_systemd_parent_is_suppressed() {
        // The exact prod pattern: command=/proc/self/fd/N, launched by systemd.
        assert!(FilelessDetector::is_systemd_unit_launch(
            "/proc/self/fd/9",
            38424,
            Some("/usr/lib/systemd/systemd"),
        ));
        // Self by explicit own-pid fd path is the same mechanism.
        assert!(FilelessDetector::is_systemd_unit_launch(
            "/proc/38424/fd/9",
            38424,
            Some("/usr/lib/systemd/systemd"),
        ));
        // The per-user manager + the executor helper exe also match.
        for parent in [
            "/lib/systemd/systemd",
            "/lib/systemd/systemd-executor",
            "/usr/lib/systemd/systemd-executor",
        ] {
            assert!(
                FilelessDetector::is_systemd_unit_launch("/proc/self/fd/3", 7, Some(parent)),
                "{parent} must be recognised as a systemd manager"
            );
        }
    }

    #[test]
    fn systemd_pattern_with_non_systemd_parent_still_fires() {
        // ANTI-EVASION: a shell/dropper launching a fileless payload via the
        // self-fd form must NOT be suppressed — the parent exe is the shell,
        // not systemd. `bash -c 'exec /proc/self/fd/3'`.
        for parent in [
            "/usr/bin/bash",
            "/bin/sh",
            "/tmp/dropper",
            "/usr/bin/python3",
            "/usr/sbin/sshd",
        ] {
            assert!(
                !FilelessDetector::is_systemd_unit_launch("/proc/self/fd/3", 100, Some(parent)),
                "parent {parent} is not systemd → must still fire"
            );
        }
    }

    #[test]
    fn systemd_unknown_parent_fails_safe_to_firing() {
        // ANTI-EVASION / fail-safe: cannot resolve the parent exe (raced exit,
        // kernel task, EACCES) → do NOT suppress.
        assert!(!FilelessDetector::is_systemd_unit_launch(
            "/proc/self/fd/3",
            100,
            None
        ));
    }

    #[test]
    fn memfd_devfd_deleted_never_suppressed_even_with_systemd_parent() {
        // ANTI-EVASION: only the self-fd fexecve form is systemd's pattern. A
        // direct /memfd:, /dev/fd/, or (deleted) backing is the real fileless
        // signal and MUST keep firing even if the parent reads as systemd
        // (e.g. a payload double-forked to reparent under PID 1).
        for command in [
            "/memfd:payload",
            "/dev/fd/3",
            "/tmp/x (deleted)",
            "/memfd:systemd-executor",
        ] {
            assert!(
                !FilelessDetector::is_systemd_unit_launch(
                    command,
                    100,
                    Some("/usr/lib/systemd/systemd"),
                ),
                "{command} is not the self-fd form → must still fire"
            );
        }
    }

    #[test]
    fn proc_other_pid_fd_not_suppressed() {
        // ANTI-EVASION: exec'ing ANOTHER process's fd (/proc/<other>/fd/N) is
        // not systemd's self-fexecve and must keep firing even with a systemd
        // parent — reading another task's fd table is suspicious.
        assert!(!FilelessDetector::is_systemd_unit_launch(
            "/proc/1234/fd/5",
            4321,
            Some("/usr/lib/systemd/systemd"),
        ));
    }

    #[test]
    fn systemd_renamed_payload_path_not_trusted() {
        // ANTI-EVASION: trust is keyed on the exact exe PATH, not a basename.
        // A payload at /tmp/systemd or /home/u/.local/systemd-executor is NOT a
        // systemd manager.
        for parent in [
            "/tmp/systemd",
            "/home/u/.local/bin/systemd",
            "/var/tmp/systemd-executor",
            "/usr/lib/systemd/systemd-evil",
        ] {
            assert!(
                !FilelessDetector::is_systemd_unit_launch("/proc/self/fd/3", 100, Some(parent)),
                "{parent} must not pass as a systemd manager"
            );
        }
    }

    #[test]
    fn detector_fires_when_parent_unresolvable_live() {
        // Integration through process(): the fixture uses DEAD_PID as ppid, so
        // the live provenance::read_exe(ppid) returns None and the systemd
        // suppression does NOT engage — the self-fd fileless exec still
        // promotes. This pins that the new /proc resolution does not silently
        // swallow real fileless events when the parent can't be proven systemd.
        let mut det = FilelessDetector::new("test", 300);
        let now = Utc::now();
        let inc = det.process(&fileless_event(
            "/proc/self/fd/63",
            "python3",
            9999,
            None,
            now,
        ));
        assert!(
            inc.is_some(),
            "self-fd fileless with an unresolvable (DEAD_PID) parent must still fire"
        );
        assert_eq!(inc.unwrap().severity, Severity::Critical);
    }
}
