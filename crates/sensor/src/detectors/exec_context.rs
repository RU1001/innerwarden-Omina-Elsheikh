//! Execution context classifier — the 2-axis half of the discovery
//! allowlist (spec 050-PR0).
//!
//! Before spec 050, every `whoami`/`ps`/`id`/`uname` exec was suppressed
//! by `DISCOVERY_ALLOWED` regardless of *who* ran it. The 2026-05-16
//! Caldera "InnerWarden Full Validation" run made the gap visible: a
//! sandcat agent running the exact same recon commands as a logged-in
//! operator was silenced by the blanket allowlist. Operator stated:
//! "se o user normal faz, o allow list deveria pegar o user normal não
//! o caldeira."
//!
//! This module classifies an execve event into one of five buckets:
//!
//!   - `OpInteractive` — TTY-attached interactive shell session run by a
//!     non-system uid. Operator running `whoami` from their ssh shell.
//!   - `PackageManagerPostinst` — dpkg/apt/yum/dnf post-install scripts.
//!     `apt upgrade` shells out to `whoami` legitimately.
//!   - `Automation` — config-management tooling: ansible / salt / puppet
//!     / chef / terraform / cfengine.
//!   - `BootOrMotd` — early-boot window (first 60 s of sensor uptime) or
//!     MOTD scripts (`00-header`, `update-motd`, …).
//!   - `AttackerInferred` — none of the above, treated as suspicious.
//!     This is the **default**: context must be proven benign or it
//!     does not get the allowlist treatment.
//!
//! The classifier is **pure** with respect to event fields — it reads
//! the values already in `event.details` (`comm`, `uid`, `pid`,
//! `parent_comm`) and the sensor start instant. Producers of
//! `shell.command_exec` events are responsible for populating those
//! fields. The eBPF execve path was extended in 050-PR0 to enrich
//! events with `parent_comm` via `/proc/{ppid}/comm`. Auditd-derived
//! events that lack the fields fall through to `AttackerInferred` — the
//! safe default that means "treat as suspicious, let the detector's
//! per-detector allowlist decide."

use std::collections::HashSet;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use innerwarden_core::event::Event;

/// Execution-context bucket for a `shell.command_exec` event.
///
/// Determines whether a discovery-style command (`whoami`, `ps`, …)
/// should be silenced or surfaced. `OpInteractive` / `PackageManagerPostinst`
/// / `Automation` / `BootOrMotd` → silence. `AttackerInferred` → surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecContext {
    /// TTY-attached interactive shell session, non-system uid.
    OpInteractive,
    /// Post-install hook of a package manager (dpkg / apt / yum / dnf).
    PackageManagerPostinst,
    /// Config-management automation (ansible / salt / puppet / chef / terraform).
    Automation,
    /// Within the first 60 s of sensor uptime OR an MOTD-style parent.
    BootOrMotd,
    /// None of the above — default. Treated as suspicious.
    AttackerInferred,
}

impl ExecContext {
    /// Whether this context counts as "benign" for the discovery
    /// allowlist. Anything other than `AttackerInferred` is benign.
    pub fn is_benign(self) -> bool {
        !matches!(self, ExecContext::AttackerInferred)
    }

    /// Short slug for telemetry / test assertions. Stable; emitted
    /// into `[detectors.discovery_anomaly]` reason fields in 050-PR1.
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            ExecContext::OpInteractive => "op_interactive",
            ExecContext::PackageManagerPostinst => "package_manager_postinst",
            ExecContext::Automation => "automation",
            ExecContext::BootOrMotd => "boot_or_motd",
            ExecContext::AttackerInferred => "attacker_inferred",
        }
    }
}

/// Sensor uptime origin. Set once by `init_sensor_start` at boot; if
/// unset, `boot_window_active` returns false (no boot-window
/// suppression), which is the safe default for tests and offline tools.
static SENSOR_START: OnceLock<Instant> = OnceLock::new();

/// Boot window — exec events within this many seconds of sensor start
/// are treated as `BootOrMotd`. Spec 050 §3.4 specifies 60 s; long
/// enough to cover the systemd target chain on a stock Ubuntu boot
/// (≤ 30 s in our measurements) plus margin, short enough that an
/// attacker who lands inside the window cannot abuse it indefinitely.
const BOOT_WINDOW_SECS: u64 = 60;

/// Initialise the sensor-start instant. Idempotent; only the first
/// call wins. Call from sensor `main()` after argument parsing.
pub fn init_sensor_start() {
    let _ = SENSOR_START.set(Instant::now());
}

/// Returns true if we're still inside the boot window.
fn boot_window_active() -> bool {
    SENSOR_START
        .get()
        .map(|start| start.elapsed() < Duration::from_secs(BOOT_WINDOW_SECS))
        .unwrap_or(false)
}

/// Test-only visibility into `boot_window_active`. Anchors in
/// `boot::build_detectors::tests` use this to assert that constructing a
/// DetectorSet does not silently set `SENSOR_START` and flip every
/// subsequent classification into the 60 s boot-window benign branch.
#[cfg(test)]
pub(crate) fn boot_window_active_for_test() -> bool {
    boot_window_active()
}

fn interactive_shells() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        ["bash", "zsh", "fish", "sh", "dash", "ksh", "tmux", "screen"]
            .into_iter()
            .collect()
    })
}

fn package_manager_parents() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        [
            // Debian / Ubuntu
            "dpkg",
            "dpkg-preconfigu",
            "dpkg-reconfigur",
            "apt",
            "apt-get",
            "apt-listchanges",
            "apt.systemd.dai",
            "aptitude",
            "unattended-upgr",
            "needrestart",
            // RHEL / Fedora / Rocky / Alma
            "yum",
            "dnf",
            "dnf-automatic",
            "rpm",
            // Snap (cross-distro)
            "snap",
            "snapd",
            // SUSE / openSUSE
            "zypper",
            "zypp-refresh",
            // Arch / Manjaro
            "pacman",
            // Alpine
            "apk",
            // NixOS — both interactive and rebuild paths spawn discovery
            // commands during build / activation.
            "nix",
            "nix-env",
            "nix-build",
            "nixos-rebuild",
            // Gentoo (operator-friendly even though it's niche; cost is
            // ~30 bytes of static string).
            "emerge",
            "portage",
            // Void Linux
            "xbps-install",
            "xbps-remove",
        ]
        .into_iter()
        .collect()
    })
}

fn automation_parents() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        [
            "ansible",
            "ansible-playboo",
            "ansible-runner",
            "salt",
            "salt-call",
            "salt-minion",
            "puppet",
            "chef-client",
            "cfengine",
            "terraform",
        ]
        .into_iter()
        .collect()
    })
}

fn motd_parents() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        [
            "00-header",
            "10-help-text",
            "50-motd-news",
            "60-unminimize",
            "91-release-upgr",
            "release-upgrade",
            "run-parts",
            "update-motd",
            "pam_motd",
        ]
        .into_iter()
        .collect()
    })
}

/// System UID threshold. Anything ≤ 999 is a system account on Debian-
/// family / Red Hat-family distros (operator uids start at 1000).
/// Matches the `is_innerwarden_process` convention.
const SYSTEM_UID_MAX: u64 = 999;

/// Classify the execution context of a `shell.command_exec` event.
///
/// Reads `parent_comm`, `uid` from `event.details`. Missing fields
/// fall through to `AttackerInferred`.
pub fn classify(event: &Event) -> ExecContext {
    classify_with_boot_window(event, boot_window_active())
}

/// Test-friendly variant: caller supplies the boot-window flag instead
/// of reading the process-wide `OnceLock`. Production code calls
/// `classify`; tests call this directly.
pub fn classify_with_boot_window(event: &Event, in_boot_window: bool) -> ExecContext {
    let details = &event.details;
    let parent_comm = details
        .get("parent_comm")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let uid = details.get("uid").and_then(|v| v.as_u64()).unwrap_or(0);
    // Controlling-terminal proof, populated by the execve emitter from the
    // PARENT's /proc/<pid>/stat tty_nr. Missing ⇒ false (surface it). See below.
    let has_tty = details
        .get("has_tty")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if in_boot_window || is_motd_parent(parent_comm) {
        return ExecContext::BootOrMotd;
    }

    if is_package_manager_parent(parent_comm) {
        return ExecContext::PackageManagerPostinst;
    }

    if is_automation_parent(parent_comm) {
        return ExecContext::Automation;
    }

    // OpInteractive (the discovery free-pass for "operator running whoami from
    // their ssh shell") requires a REAL interactive session, not just a parent
    // named like a shell. parent_comm is forgeable (`prctl(PR_SET_NAME,"bash")`)
    // and even a genuine `bash -c` spawned by cron/systemd/an implant matches the
    // name — so the name alone silenced the ENTIRE discovery tactic for any
    // implant parented by a shell (evasion audit E3, re-opening the spec-050 gap).
    // The controlling tty is the discriminator: an interactive ssh shell owns a
    // pts (tty_nr ≠ 0); an implant / reverse shell / daemon-spawned shell has
    // none. No tty ⇒ fall through to AttackerInferred and let the discovery
    // detectors + their thresholds + AI triage decide.
    if uid > SYSTEM_UID_MAX && is_interactive_shell_parent(parent_comm) && has_tty {
        return ExecContext::OpInteractive;
    }

    ExecContext::AttackerInferred
}

fn parent_basename(parent_comm: &str) -> &str {
    let base = parent_comm.split('/').next_back().unwrap_or(parent_comm);
    base.trim_matches(|c: char| c == '(' || c == ')')
}

fn is_interactive_shell_parent(parent_comm: &str) -> bool {
    !parent_comm.is_empty() && interactive_shells().contains(parent_basename(parent_comm))
}

fn is_package_manager_parent(parent_comm: &str) -> bool {
    !parent_comm.is_empty()
        && package_manager_parents()
            .iter()
            .any(|pm| parent_basename(parent_comm).starts_with(*pm))
}

fn is_automation_parent(parent_comm: &str) -> bool {
    !parent_comm.is_empty()
        && automation_parents()
            .iter()
            .any(|am| parent_basename(parent_comm).starts_with(*am))
}

fn is_motd_parent(parent_comm: &str) -> bool {
    !parent_comm.is_empty()
        && motd_parents()
            .iter()
            .any(|m| parent_basename(parent_comm).starts_with(*m))
}

/// Look up a process's `comm` from `/proc/<pid>/comm`. Best-effort:
/// returns `None` if the process has exited or `/proc` is not
/// available (containerised builds). The execve event emitter is
/// expected to call this once per execve and stash the result in
/// `event.details.parent_comm` so the classifier stays I/O-free.
pub fn proc_comm(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let path = format!("/proc/{pid}/comm");
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Does `pid` have a controlling terminal? Reads `tty_nr` from
/// `/proc/<pid>/stat` (nonzero ⇒ an attached tty/pts). This is the signal
/// that distinguishes a REAL interactive operator shell (ssh session → pts,
/// tty_nr ≠ 0) from a programmatic shell with no terminal — an implant, a
/// reverse shell, a `bash -c` spawned by cron/systemd, a sandcat agent
/// (tty_nr == 0). The execve emitter calls this on the PARENT pid (the
/// long-lived shell, not the microsecond-lived recon child) and stashes the
/// result as `has_tty` so the classifier stays I/O-free.
///
/// `/proc/<pid>/stat` layout: `pid (comm) state ppid pgrp session tty_nr …`.
/// `comm` may contain spaces and parens, so fields are parsed after the LAST
/// `)`; tty_nr is then the 5th whitespace field. Best-effort: a missing
/// file / unparseable line returns false (the safe, surface-it default).
pub fn proc_has_tty(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some(idx) = stat.rfind(')') else {
        return false;
    };
    // after ')': [0]=state [1]=ppid [2]=pgrp [3]=session [4]=tty_nr
    stat[idx + 1..]
        .split_whitespace()
        .nth(4)
        .and_then(|t| t.parse::<i64>().ok())
        .map(|tty_nr| tty_nr != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::event::Severity;
    use serde_json::json;

    fn exec_event_tty(
        comm: &str,
        parent_comm: &str,
        uid: u64,
        command: &str,
        has_tty: bool,
    ) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: format!("Shell command executed: {command}"),
            details: json!({
                "pid": 1234,
                "uid": uid,
                "ppid": 999,
                "comm": comm,
                "parent_comm": parent_comm,
                "has_tty": has_tty,
                "command": command,
                "argv": [command],
                "argc": 1,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    /// Default helper: an interactive session (has_tty = true). The non-tty
    /// (implant) case uses `exec_event_tty(.., false)`.
    fn exec_event(comm: &str, parent_comm: &str, uid: u64, command: &str) -> Event {
        exec_event_tty(comm, parent_comm, uid, command, true)
    }

    #[test]
    fn operator_in_interactive_ssh_shell_classifies_as_op_interactive() {
        // Operator `ubuntu@host:~$ whoami` — uid 1000, parent is bash.
        // This is the canonical "user normal" case the operator
        // flagged on 2026-05-16.
        let ev = exec_event("whoami", "bash", 1000, "whoami");
        let ctx = classify_with_boot_window(&ev, false);
        assert_eq!(ctx, ExecContext::OpInteractive);
        assert!(ctx.is_benign());
    }

    /// Regression anchor (evasion audit E3, 2026-06-20): an implant parented by
    /// a shell — either a renamed parent (`prctl(PR_SET_NAME,"bash")`) or a real
    /// `bash -c` spawned by cron/systemd/a reverse shell — has uid > 999 and a
    /// shell-named parent, so the NAME-only check granted it OpInteractive and
    /// silenced the ENTIRE discovery tactic (re-opening the spec-050 gap). With no
    /// controlling tty it must now classify AttackerInferred so the discovery
    /// detectors run. The operator's live interactive shell (has_tty) is unchanged.
    #[test]
    fn shell_parented_implant_without_tty_is_attacker_inferred() {
        let ev = exec_event_tty("whoami", "bash", 1000, "whoami", false);
        let ctx = classify_with_boot_window(&ev, false);
        assert_eq!(
            ctx,
            ExecContext::AttackerInferred,
            "a shell-named parent with NO controlling tty is not a real interactive \
             session and must not get the discovery free-pass"
        );
        assert!(!ctx.is_benign());
        // The same command WITH a tty (genuine operator ssh shell) stays benign.
        let ev_tty = exec_event_tty("whoami", "bash", 1000, "whoami", true);
        assert_eq!(
            classify_with_boot_window(&ev_tty, false),
            ExecContext::OpInteractive
        );
    }

    /// A missing `has_tty` field (non-eBPF source, e.g. auditd) defaults to the
    /// safe "surface it" direction — no OpInteractive free-pass on identity alone.
    #[test]
    fn missing_has_tty_defaults_to_not_op_interactive() {
        let mut ev = exec_event_tty("whoami", "bash", 1000, "whoami", true);
        ev.details.as_object_mut().unwrap().remove("has_tty");
        assert_eq!(
            classify_with_boot_window(&ev, false),
            ExecContext::AttackerInferred
        );
    }

    #[test]
    fn caldera_sandcat_classifies_as_attacker_inferred() {
        // Sandcat agent — uid 1000, parent is its own binary, no
        // interactive shell. This is the canonical "caldera" case the
        // operator flagged: same uid as a real user, but no shell
        // context, so the allowlist must NOT silence it.
        let ev = exec_event("whoami", "sandcat", 1000, "whoami");
        let ctx = classify_with_boot_window(&ev, false);
        assert_eq!(ctx, ExecContext::AttackerInferred);
        assert!(!ctx.is_benign());
    }

    #[test]
    fn dpkg_postinst_classifies_as_package_manager() {
        // `apt upgrade` runs maintainer scripts that legitimately shell
        // out to `whoami` / `id` / `update-alternatives`. The 2026-05-16
        // operator-reported FP wave (kernel_module, sudo_abuse, etc.)
        // had `dpkg` as the parent.
        let ev = exec_event("whoami", "dpkg", 0, "whoami");
        assert_eq!(
            classify_with_boot_window(&ev, false),
            ExecContext::PackageManagerPostinst
        );

        let ev = exec_event("id", "apt-get", 0, "id");
        assert_eq!(
            classify_with_boot_window(&ev, false),
            ExecContext::PackageManagerPostinst
        );

        let ev = exec_event("uname", "unattended-upgr", 0, "uname -a");
        assert_eq!(
            classify_with_boot_window(&ev, false),
            ExecContext::PackageManagerPostinst
        );
    }

    #[test]
    fn non_debian_package_managers_classify_as_package_manager() {
        // Spec 050-PR0 was designed against Ubuntu + RHEL Caldera
        // data, but the classifier ships to Alpine, SUSE, Arch,
        // NixOS, Gentoo, Void hosts too. Each family must silence
        // its own package-manager postinst — without this, an
        // operator running `zypper refresh` or an Alpine container
        // doing `apk add` would trip discovery_burst spuriously.
        for parent in [
            "zypper",        // SUSE / openSUSE
            "pacman",        // Arch / Manjaro
            "apk",           // Alpine
            "nix",           // NixOS interactive
            "nixos-rebuild", // NixOS activation
            "emerge",        // Gentoo
            "xbps-install",  // Void
        ] {
            let ev = exec_event("whoami", parent, 0, "whoami");
            assert_eq!(
                classify_with_boot_window(&ev, false),
                ExecContext::PackageManagerPostinst,
                "parent={parent} should classify as PackageManagerPostinst"
            );
        }
    }

    #[test]
    fn ansible_run_classifies_as_automation() {
        let ev = exec_event("ps", "ansible-playboo", 0, "ps aux");
        assert_eq!(
            classify_with_boot_window(&ev, false),
            ExecContext::Automation
        );

        let ev = exec_event("id", "salt-call", 0, "id");
        assert_eq!(
            classify_with_boot_window(&ev, false),
            ExecContext::Automation
        );
    }

    #[test]
    fn boot_window_classifies_as_boot_or_motd() {
        let ev = exec_event("whoami", "sandcat", 1000, "whoami");
        // Even though parent is `sandcat`, the boot-window override
        // wins. This is intentional: in the first 60 s of sensor
        // uptime we cannot reliably distinguish recon from systemd
        // unit startup that legitimately runs `uname` / `id`.
        let ctx = classify_with_boot_window(&ev, true);
        assert_eq!(ctx, ExecContext::BootOrMotd);
    }

    #[test]
    fn motd_parent_classifies_as_boot_or_motd_outside_window() {
        let ev = exec_event("uname", "00-header", 0, "uname -r");
        assert_eq!(
            classify_with_boot_window(&ev, false),
            ExecContext::BootOrMotd
        );
    }

    #[test]
    fn root_uid_with_bash_parent_is_not_op_interactive() {
        // System processes that spawn bash (e.g., cron running a shell
        // script as root) are not "operator interactive". uid > 999 is
        // the gate.
        let ev = exec_event("whoami", "bash", 0, "whoami");
        assert_eq!(
            classify_with_boot_window(&ev, false),
            ExecContext::AttackerInferred
        );
    }

    #[test]
    fn empty_parent_comm_falls_through_to_attacker_inferred() {
        // Auditd events lack ppid / parent_comm. They get the safe
        // default: AttackerInferred.
        let ev = exec_event("whoami", "", 1000, "whoami");
        assert_eq!(
            classify_with_boot_window(&ev, false),
            ExecContext::AttackerInferred
        );
    }

    #[test]
    fn parent_basename_handles_paths_and_parens() {
        let ev = exec_event("whoami", "/usr/bin/bash", 1000, "whoami");
        assert_eq!(
            classify_with_boot_window(&ev, false),
            ExecContext::OpInteractive
        );

        let ev = exec_event("whoami", "(bash)", 1000, "whoami");
        assert_eq!(
            classify_with_boot_window(&ev, false),
            ExecContext::OpInteractive
        );
    }

    #[test]
    fn context_str_slugs_are_stable() {
        assert_eq!(ExecContext::OpInteractive.as_str(), "op_interactive");
        assert_eq!(
            ExecContext::PackageManagerPostinst.as_str(),
            "package_manager_postinst"
        );
        assert_eq!(ExecContext::Automation.as_str(), "automation");
        assert_eq!(ExecContext::BootOrMotd.as_str(), "boot_or_motd");
        assert_eq!(ExecContext::AttackerInferred.as_str(), "attacker_inferred");
    }

    #[test]
    fn benign_flag_inverts_attacker_inferred() {
        assert!(ExecContext::OpInteractive.is_benign());
        assert!(ExecContext::PackageManagerPostinst.is_benign());
        assert!(ExecContext::Automation.is_benign());
        assert!(ExecContext::BootOrMotd.is_benign());
        assert!(!ExecContext::AttackerInferred.is_benign());
    }

    #[test]
    fn proc_comm_returns_none_for_pid_zero() {
        assert!(proc_comm(0).is_none());
    }

    #[test]
    fn proc_comm_returns_none_for_nonexistent_pid() {
        // PID 4,000,000,000 is reserved high; never exists in /proc.
        assert!(proc_comm(4_000_000_000).is_none());
    }
}
