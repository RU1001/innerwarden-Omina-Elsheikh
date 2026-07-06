//! Keylogger via bash trap detection (spec 050-PR2).
//!
//! Catches the classic Linux keylogger persistence trick: append a
//! `trap '...' DEBUG` or similar to a shell startup file (`.bashrc`,
//! `.bash_profile`, `/etc/profile`, etc.) so every interactive command
//! gets logged or proxied. MITRE T1056.004 + T1546.004.
//!
//! Detected via two routes:
//!   1. `file.write_access` to a shell startup file by a non-package
//!      manager parent — the **canonical** signal.
//!   2. `shell.command_exec` of `bash -c "exec > >(tee ...)"` style
//!      stdout duplication patterns — secondary signal.
//!
//! Anti-FP gates:
//!   - Package manager parents (`dpkg`, `apt`, `unattended-upgr`,
//!     `dnf`, etc.) silence file.write_access — they legitimately
//!     touch /etc/profile.d/* during package install.
//!   - Language/runtime toolchain installers (`rustup-init`, `pip`,
//!     `npm`, `nvm`, `conda`, …) writing within their OWN user scope are
//!     DOWNGRADED to Low (not suppressed) — `rustup-init` appending
//!     `~/.cargo/env` to the user's `~/.profile` is a normal install, not a
//!     keylogger. The incident is still recorded for provenance, and any
//!     installer-claimed write OUTSIDE its scope (a non-root process touching
//!     `/root` or `/etc`) stays CRITICAL so a comm-spoofing attacker cannot
//!     use the downgrade as a blind spot.
//!   - Operator-extensible `[detectors.keylogger_bash_trap]` TOML.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const SHELL_STARTUP_PATHS: &[&str] = &[
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/zsh/zshrc",
    "/etc/zsh/zshenv",
    "/etc/profile.d/",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.profile",
    "/root/.zshrc",
    "/home/", // matches any user's home .bashrc / .bash_profile / .zshrc
];

const PKG_MANAGER_PARENTS: &[&str] = &[
    "dpkg",
    "apt",
    "apt-get",
    "unattended-upgr",
    "needrestart",
    "dnf",
    "yum",
    "rpm",
    "zypper",
    "pacman",
    "apk",
];

/// Language / runtime toolchain installers that legitimately write a shell
/// startup file to add themselves to `PATH` or source an env file (e.g.
/// `rustup-init` appends `. "$HOME/.cargo/env"` to `~/.profile`; `nvm`,
/// `pyenv`, `conda` do the same). Unlike the system package managers above
/// (which we suppress outright), a toolchain installer runs in a USER context
/// and its `comm` is more easily spoofable, so we do NOT suppress it — we
/// DOWNGRADE to Low and keep recording it (see `process_file_write`). That
/// way a comm-spoofing attacker still leaves a triage-able incident instead
/// of a free pass, while a real `rustup-init` no longer pages the operator
/// with a CRITICAL "keylogger persistence" alert.
const TOOLCHAIN_INSTALLERS: &[&str] = &[
    "rustup-init",
    "rustup",
    "cargo",
    "pip",
    "pip3",
    "pipx",
    "uv",
    "poetry",
    "npm",
    "yarn",
    "pnpm",
    "nvm",
    "pyenv",
    "rbenv",
    "gem",
    "bundle",
    "conda",
    "mamba",
    "nix",
    "nix-env",
    "deno",
    "bun",
    "sdkman",
    "brew",
];

pub struct KeyloggerBashTrapDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl KeyloggerBashTrapDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(600),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        match event.kind.as_str() {
            "file.write_access" => self.process_file_write(event),
            "shell.command_exec" | "process.exec" => self.process_exec(event),
            _ => None,
        }
    }

    fn process_file_write(&mut self, event: &Event) -> Option<Incident> {
        let filename = event
            .details
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !is_shell_startup_path(filename) {
            return None;
        }
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        // Comm here is the actual writer (file.write_access fires AFTER
        // the open with comm == new process name). Filter package
        // managers via comm directly.
        if is_pkg_manager(comm) {
            return None;
        }
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_pkg_manager(parent_comm) {
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
        // Provenance grading (anti-FP without a detection blind spot):
        // a recognized language/runtime toolchain installer writing within
        // its OWN scope is benign provenance -> record at Low, do not page.
        // Anything else stays CRITICAL. Crucially this is a DOWNGRADE, never a
        // suppression: a comm-spoofing attacker still produces a Low incident
        // that the agent triage / dashboard can surface, and any installer
        // writing OUTSIDE its own scope (a non-root process touching /root,
        // /etc or system files) keeps CRITICAL — that cross-privilege write is
        // exactly the persistence move we must not relax.
        let toolchain = is_toolchain_installer(comm) || is_toolchain_installer(parent_comm);
        let benign = toolchain && installer_write_is_benign(filename, uid);
        let severity = if benign {
            Severity::Low
        } else {
            Severity::Critical
        };
        self.emit(
            event,
            filename,
            comm,
            parent_comm,
            pid,
            uid,
            "shell_startup_write",
            severity,
            benign,
        )
    }

    fn process_exec(&mut self, event: &Event) -> Option<Incident> {
        // Catch `bash -c "exec > >(tee ...)"` and similar stdout
        // duplication patterns in the command line. Less reliable than
        // the file-write path but worth having as a secondary signal.
        let command = event
            .details
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !is_trap_or_tee_pattern(command) {
            return None;
        }
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
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
        self.emit(
            event,
            command,
            comm,
            parent_comm,
            pid,
            uid,
            "trap_or_tee_pattern",
            Severity::Critical,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        event: &Event,
        target: &str,
        comm: &str,
        parent_comm: &str,
        pid: u64,
        uid: u64,
        sub_kind: &str,
        severity: Severity,
        benign: bool,
    ) -> Option<Incident> {
        let now = event.ts;
        let key = format!("{uid}:{target}");
        if let Some(&last) = self.last_fired.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.last_fired.insert(key.clone(), now);
        let (title, summary, tags) = if benign {
            (
                format!("Shell startup file written by installer `{comm}`: `{target}`"),
                format!(
                    "Recognized toolchain/package installer `{comm}` (parent \
                     `{parent_comm}`, pid={pid}, uid={uid}) wrote shell startup file \
                     `{target}` within its own user scope. This is the normal install \
                     pattern (adding a tool to PATH / sourcing an env file), recorded \
                     at low severity for provenance. It would be a CRITICAL keylogger \
                     persistence signal (T1546.004) if the writer were unrecognized or \
                     the target were outside the writer's own home (e.g. a non-root \
                     process writing /root or /etc)."
                ),
                vec!["persistence".to_string(), "benign-provenance".to_string()],
            )
        } else {
            (
                format!("Possible keylogger persistence: {sub_kind} target=`{target}`"),
                format!(
                    "Detector `{sub_kind}` matched on `{target}` (writer/launcher \
                     comm=`{comm}`, parent=`{parent_comm}`, pid={pid}, uid={uid}). \
                     Modifying shell startup files or rigging stdout duplication is \
                     the classic Linux keylogger persistence trick (T1056.004 / T1546.004)."
                ),
                vec!["collection".to_string(), "persistence".to_string()],
            )
        };
        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "keylogger_bash_trap:{sub_kind}:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity,
            title,
            summary,
            evidence: serde_json::json!([{
                "kind": "keylogger_bash_trap",
                "sub_kind": sub_kind,
                "target": target,
                "comm": comm,
                "parent_comm": parent_comm,
                "uid": uid,
                "pid": pid,
                "benign_provenance": benign,
                "mitre": ["T1056.004", "T1546.004"],
            }]),
            recommended_checks: vec![
                format!("Diff the modified file against package-manager baseline: dpkg-query -S {target} ; md5sum {target}"),
                "If a deploy automation legitimately writes shell startup files, allowlist via [detectors.keylogger_bash_trap]".to_string(),
                format!("Inspect the writing process: ps -p {pid} -o pid,ppid,user,comm,args"),
            ],
            tags,
            entities: vec![],
        })
    }
}

/// True when a recognized toolchain installer's write to `filename` (by a
/// process running as `uid`) stays within scope we consider a normal install:
/// - root (uid 0) may write any startup file (system or per-user install);
/// - a non-root user may write only under `/home/` (their session), NOT
///   `/root`, `/etc`, or other system locations.
///
/// A non-root process writing root/system startup files is a cross-privilege
/// persistence move and must stay CRITICAL even if its `comm` claims to be an
/// installer (anti-evasion). Cross-USER home writes cannot be resolved cheaply
/// in the sensor (no `/etc/passwd` lookup) so they remain "benign" but are
/// still RECORDED at Low for the agent/AI triage layer to catch.
fn installer_write_is_benign(filename: &str, uid: u64) -> bool {
    if uid == 0 {
        return true;
    }
    filename.starts_with("/home/")
}

fn is_shell_startup_path(filename: &str) -> bool {
    if filename.is_empty() {
        return false;
    }
    // /home/<user>/{.bashrc,.bash_profile,.profile,.zshrc} cases.
    if filename.starts_with("/home/")
        && (filename.ends_with("/.bashrc")
            || filename.ends_with("/.bash_profile")
            || filename.ends_with("/.profile")
            || filename.ends_with("/.zshrc")
            || filename.ends_with("/.zshenv"))
    {
        return true;
    }
    SHELL_STARTUP_PATHS
        .iter()
        .any(|p| filename.starts_with(p) && *p != "/home/")
}

fn is_pkg_manager(comm: &str) -> bool {
    if comm.is_empty() {
        return false;
    }
    let base = comm.split('/').next_back().unwrap_or(comm);
    let base = base.trim_matches(|c: char| c == '(' || c == ')');
    PKG_MANAGER_PARENTS.iter().any(|p| base.starts_with(p))
}

fn is_toolchain_installer(comm: &str) -> bool {
    if comm.is_empty() {
        return false;
    }
    let base = comm.split('/').next_back().unwrap_or(comm);
    let base = base.trim_matches(|c: char| c == '(' || c == ')');
    // Exact-match (not starts_with) so a binary called e.g. `npm_evil` does
    // not inherit the installer downgrade. The real installer comms are short
    // and fit within TASK_COMM_LEN, so exact match is safe.
    TOOLCHAIN_INSTALLERS.contains(&base)
}

fn is_trap_or_tee_pattern(command: &str) -> bool {
    if command.is_empty() {
        return false;
    }
    let lower = command.to_lowercase();
    // Conservative — require explicit trap+(DEBUG|ERR) co-occurrence,
    // or the exec>>(tee ... shape, to avoid FP on benign `trap '...'`
    // for cleanup or `tee` invocations.
    (lower.contains("trap ") && (lower.contains(" debug") || lower.contains(" err")))
        || lower.contains("exec > >(tee ")
        || lower.contains("exec >(tee ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_event(filename: &str, comm: &str, parent_comm: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "file.write_access".into(),
            severity: Severity::Info,
            summary: format!("write {filename}"),
            details: serde_json::json!({
                "pid": 4242,
                "uid": 1000,
                "ppid": 4241,
                "comm": comm,
                "parent_comm": parent_comm,
                "filename": filename,
                "write": true,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn exec_event(command: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: format!("exec {command}"),
            details: serde_json::json!({
                "pid": 4242,
                "uid": 1000,
                "ppid": 4241,
                "comm": "bash",
                "parent_comm": "bash",
                "command": command,
                "argv": ["bash", "-c", command],
                "argc": 3,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn write_event_uid(filename: &str, comm: &str, parent_comm: &str, uid: u64) -> Event {
        let mut ev = write_event(filename, comm, parent_comm);
        ev.details["uid"] = serde_json::json!(uid);
        ev
    }

    #[test]
    fn fires_on_write_to_bashrc_by_non_pkg_writer() {
        let mut det = KeyloggerBashTrapDetector::new("test");
        let ev = write_event("/home/ubuntu/.bashrc", "evil_script", "bash");
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn toolchain_installer_writing_own_home_is_low_not_critical() {
        // The rustup-init FP: comm=rustup-init wrote /home/ubuntu/.profile as a
        // normal user (uid 1000) to add ~/.cargo/bin to PATH. Must be recorded
        // (provenance) but NOT a CRITICAL keylogger page.
        let mut det = KeyloggerBashTrapDetector::new("test");
        let ev = write_event("/home/ubuntu/.profile", "rustup-init", "sh");
        let inc = det
            .process(&ev)
            .expect("should still RECORD (not suppress)");
        assert_eq!(
            inc.severity,
            Severity::Low,
            "installer write must downgrade"
        );
        assert!(inc.title.contains("installer"), "title: {}", inc.title);
        assert_eq!(
            inc.evidence[0]["benign_provenance"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn root_installer_writing_user_profile_is_low() {
        let mut det = KeyloggerBashTrapDetector::new("test");
        let ev = write_event_uid("/home/ubuntu/.bashrc", "pip3", "sh", 0);
        let inc = det.process(&ev).expect("should record");
        assert_eq!(inc.severity, Severity::Low);
    }

    #[test]
    fn spoofed_installer_writing_root_file_as_user_stays_critical() {
        // Anti-evasion: a process CLAIMING to be an installer (comm spoof) that
        // writes /root/.bashrc while NOT root is a cross-privilege persistence
        // move — it must NOT inherit the installer downgrade.
        let mut det = KeyloggerBashTrapDetector::new("test");
        let ev = write_event_uid("/root/.bashrc", "rustup-init", "bash", 1000);
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(
            inc.severity,
            Severity::Critical,
            "cross-priv write stays critical"
        );
        assert!(inc.title.contains("keylogger"), "title: {}", inc.title);
    }

    #[test]
    fn spoofed_installer_writing_etc_as_user_stays_critical() {
        let mut det = KeyloggerBashTrapDetector::new("test");
        let ev = write_event_uid("/etc/profile", "npm", "bash", 1000);
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn non_installer_comm_is_not_downgraded() {
        // A binary whose comm merely contains an installer substring (npm_evil)
        // must NOT be treated as an installer (exact match guard).
        let mut det = KeyloggerBashTrapDetector::new("test");
        let ev = write_event("/home/ubuntu/.profile", "npm_evil", "bash");
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn fires_on_write_to_etc_profile_by_non_pkg_writer() {
        let mut det = KeyloggerBashTrapDetector::new("test");
        let ev = write_event("/etc/profile", "implant", "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn silences_when_pkg_manager_is_writer() {
        let mut det = KeyloggerBashTrapDetector::new("test");
        let ev = write_event("/etc/profile.d/bash_completion.sh", "dpkg", "apt-get");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_pkg_manager_is_parent() {
        let mut det = KeyloggerBashTrapDetector::new("test");
        let ev = write_event("/root/.bashrc", "sh", "dpkg");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_writes_to_non_shell_startup_paths() {
        let mut det = KeyloggerBashTrapDetector::new("test");
        for path in ["/var/log/syslog", "/tmp/foo", "/etc/hosts"] {
            assert!(det.process(&write_event(path, "x", "bash")).is_none());
        }
    }

    #[test]
    fn fires_on_trap_debug_exec_pattern() {
        let mut det = KeyloggerBashTrapDetector::new("test");
        let ev = exec_event("bash -c \"trap 'log \\$BASH_COMMAND' DEBUG\"");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_exec_tee_redirect_pattern() {
        let mut det = KeyloggerBashTrapDetector::new("test");
        let ev = exec_event("bash -c \"exec > >(tee -a /tmp/keylog) 2>&1; bash\"");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn ignores_benign_trap_invocation() {
        let mut det = KeyloggerBashTrapDetector::new("test");
        // Trap without DEBUG/ERR keyword is not the keylogger pattern.
        let ev = exec_event("bash -c \"trap 'rm -f /tmp/lock' EXIT\"");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = KeyloggerBashTrapDetector::new("test");
        let ev = write_event("/home/ubuntu/.bashrc", "evil", "bash");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(30);
        assert!(det.process(&ev2).is_none());
    }
}
