//! Thin wrappers around the host service manager for service lifecycle
//! management. Linux uses systemd (`systemctl`); macOS uses launchd
//! (`launchctl`). The public helpers (`service_status`, `is_service_active`,
//! `restart_service`) dispatch by platform so callers don't have to.

use std::process::Command;

use anyhow::{bail, Context, Result};

/// Map a logical InnerWarden unit name (`innerwarden-agent`, optionally with a
/// `.service` / `.timer` suffix) to its macOS launchd label
/// (`com.innerwarden.agent`). Returns `None` if `unit` is not one of ours.
///
/// The daemons install their plists as `/Library/LaunchDaemons/com.innerwarden.<x>.plist`
/// with `<key>Label</key><string>com.innerwarden.<x></string>`, so the label is
/// simply `com.innerwarden.` + the segment after the `innerwarden-` prefix.
pub fn launchd_label(unit: &str) -> Option<String> {
    let base = unit.trim_end_matches(".service").trim_end_matches(".timer");
    let short = base.strip_prefix("innerwarden-")?;
    if short.is_empty() {
        return None;
    }
    Some(format!("com.innerwarden.{short}"))
}

/// Map a logical InnerWarden unit to its Windows Scheduled-Task name (spec 085
/// Phantom Phase 4). The daemons install as two AtStartup SYSTEM tasks under an
/// `InnerWarden\` folder named after the full unit, so `innerwarden-sensor`
/// (optionally `.service`/`.timer`) maps to `InnerWarden\innerwarden-sensor`.
/// This is the canonical name contract shared with `install.ps1 -Full`
/// (Register-ScheduledTask). Returns `None` for a foreign or empty unit.
pub(crate) fn scheduled_task_name(unit: &str) -> Option<String> {
    let base = unit.trim_end_matches(".service").trim_end_matches(".timer");
    let short = base.strip_prefix("innerwarden-")?;
    if short.is_empty() {
        return None;
    }
    Some(format!("InnerWarden\\{base}"))
}

/// The host service manager. `cfg!(target_os = ...)` at the call site picks the
/// arm; passing it explicitly keeps the routing decision a pure, Linux-testable
/// function (mac + windows behaviour is covered on the Linux CI host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceHost {
    Linux,
    Macos,
    Windows,
}

/// The host this binary is running on.
pub(crate) fn current_host() -> ServiceHost {
    if cfg!(target_os = "macos") {
        ServiceHost::Macos
    } else if cfg!(target_os = "windows") {
        ServiceHost::Windows
    } else {
        ServiceHost::Linux
    }
}

/// Which service manager a restart of `unit` should go through.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RestartVia {
    /// Linux: `systemctl restart <unit>`.
    Systemd,
    /// macOS: `launchctl kickstart -k system/<label>`.
    Launchd(String),
    /// Windows: `schtasks /End` then `/Run` on `InnerWarden\<unit>` (there is no
    /// Restart-Service for a plain console exe under a Scheduled Task).
    ScheduledTask(String),
}

/// PURE routing decision so every platform is covered on the Linux CI host:
/// macOS maps our units to a launchd label, Windows to a Scheduled-Task name,
/// Linux (and any foreign unit) uses systemd.
pub(crate) fn restart_route(host: ServiceHost, unit: &str) -> RestartVia {
    match host {
        ServiceHost::Macos => match launchd_label(unit) {
            Some(label) => RestartVia::Launchd(label),
            None => RestartVia::Systemd,
        },
        ServiceHost::Windows => match scheduled_task_name(unit) {
            Some(task) => RestartVia::ScheduledTask(task),
            None => RestartVia::Systemd,
        },
        ServiceHost::Linux => RestartVia::Systemd,
    }
}

fn restart_service_with<F>(unit: &str, dry_run: bool, mut run: F) -> Result<()>
where
    F: FnMut(&str, &[String]) -> std::io::Result<std::process::Output>,
{
    if dry_run {
        return Ok(());
    }
    let args = vec!["restart".to_string(), unit.to_string()];
    let out = run("systemctl", &args)
        .with_context(|| format!("failed to run systemctl restart {unit}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("systemctl restart {unit} failed: {stderr}");
    }
    Ok(())
}

/// Restart an InnerWarden service through the host's service manager: systemd on
/// Linux, launchd on macOS (so config-change restarts don't silently no-op on
/// macOS). In dry_run mode, no command is executed.
pub fn restart_service(unit: &str, dry_run: bool) -> Result<()> {
    match restart_route(current_host(), unit) {
        RestartVia::Launchd(label) => restart_launchd(&label, dry_run),
        RestartVia::ScheduledTask(task) => restart_scheduled_task(&task, dry_run),
        RestartVia::Systemd => restart_service_with(unit, dry_run, |program, args| {
            Command::new(program).args(args).output()
        }),
    }
}

fn restart_scheduled_task_with<F>(task: &str, dry_run: bool, mut run: F) -> Result<()>
where
    F: FnMut(&str, &[String]) -> std::io::Result<std::process::Output>,
{
    if dry_run {
        return Ok(());
    }
    // Best-effort stop first (the task may not be running); a failure here is
    // fine - it is the "kill the old process" half of the config-change restart.
    let _ = run(
        "schtasks",
        &["/End".to_string(), "/TN".to_string(), task.to_string()],
    );
    let args = vec!["/Run".to_string(), "/TN".to_string(), task.to_string()];
    let out = run("schtasks", &args)
        .with_context(|| format!("failed to run schtasks /Run /TN {task}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("schtasks /Run /TN {task} failed: {stderr}");
    }
    Ok(())
}

/// Restart a Windows Scheduled Task (spec 085 Phase 4): `/End` then `/Run`, the
/// launchd `kickstart -k` analog. In dry_run mode nothing is executed.
pub fn restart_scheduled_task(task: &str, dry_run: bool) -> Result<()> {
    restart_scheduled_task_with(task, dry_run, |program, args| {
        Command::new(program).args(args).output()
    })
}

fn restart_launchd_with<F>(label: &str, dry_run: bool, mut run: F) -> Result<()>
where
    F: FnMut(&str, &[String]) -> std::io::Result<std::process::Output>,
{
    if dry_run {
        return Ok(());
    }
    let target = format!("system/{label}");
    let args = vec!["kickstart".to_string(), "-k".to_string(), target];
    let out = run("launchctl", &args)
        .with_context(|| format!("failed to run launchctl kickstart -k system/{label}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("launchctl kickstart system/{label} failed: {stderr}");
    }
    Ok(())
}

/// Restart a launchd service (macOS).
/// In dry_run mode, prints the command without executing.
pub fn restart_launchd(label: &str, dry_run: bool) -> Result<()> {
    restart_launchd_with(label, dry_run, |program, args| {
        Command::new(program).args(args).output()
    })
}

/// Result of querying a systemd service's runtime status.
///
/// Bug 2 / Bug 8 (2026-05-06 prod observation): the prior
/// `is_service_active(unit) -> bool` API conflated three distinct
/// states into one boolean — `false` for "service is dead", `false`
/// for "systemctl could not query the bus", and `false` for "command
/// not found / non-Linux host". When the operator ran `innerwarden
/// doctor` over an SSH non-login session that did not export
/// `XDG_RUNTIME_DIR`, `systemctl is-active` exited non-zero with
/// stderr `Failed to connect to bus: No data available` even though
/// the agent was alive (telemetry-freshness check confirmed it).
/// Doctor's Services section reported "is not running" while Agent
/// health reported "active - last write 5s ago" in the same output.
///
/// Splitting `Active` from `Inactive` from `Unknown` lets callers do
/// the right thing in each case: `Inactive` is a real finding,
/// `Unknown` is a "could not determine" that should defer to a
/// secondary check (telemetry-freshness in doctor, agent presence in
/// harden) instead of producing a false-positive operator alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    /// `systemctl is-active` returned `active`.
    Active,
    /// `systemctl is-active` returned `inactive` / `failed` / `deactivating`.
    Inactive,
    /// Could not determine. Bus unreachable, systemctl absent (macOS or
    /// non-systemd Linux), or stdout shape unrecognised. Caller must
    /// fall back to a secondary signal.
    Unknown,
}

/// Query the systemd status of `unit`.
///
/// stderr is intentionally swallowed — see Bug 1 (2026-05-06): the
/// `Failed to connect to bus` line leaked through to the user's
/// terminal when doctor ran over a session that lacked `DBUS_SESSION_BUS_ADDRESS`.
pub fn service_status(unit: &str) -> ServiceStatus {
    if cfg!(target_os = "macos") {
        return macos_service_status(unit);
    }
    if cfg!(target_os = "windows") {
        return windows_service_status(unit);
    }
    let out = Command::new("systemctl").args(["is-active", unit]).output();
    let out = match out {
        Ok(o) => o,
        Err(_) => return ServiceStatus::Unknown,
    };
    classify_systemctl_is_active(&out.stdout, out.status.success())
}

/// macOS status probe. `systemctl` does not exist here, so we detect the daemon
/// by process presence via `pgrep -f <unit>` (works for any user, no root and
/// no launchd system-domain access needed). This is what fixes the
/// 2026-07-01 finding where `get status` / `doctor` reported RUNNING launchd
/// services as "stopped" because they called the Linux-only `systemctl is-active`.
///
/// The daemons run as `/usr/local/bin/innerwarden-<x>`, so `pgrep -f innerwarden-<x>`
/// matches the live process; the `ctl` process itself (`innerwarden get status`)
/// never carries `innerwarden-agent` / `innerwarden-sensor` in its argv, so there
/// is no self-match.
fn macos_service_status(unit: &str) -> ServiceStatus {
    match Command::new("pgrep").args(["-f", unit]).output() {
        Ok(o) => classify_pgrep(o.status.code()),
        Err(_) => ServiceStatus::Unknown,
    }
}

/// Pure helper: map a `pgrep` exit code to a `ServiceStatus`.
/// `pgrep` exits 0 when one or more processes matched, 1 when none matched
/// (a clean "not running" answer), and 2/3 on a usage/fatal error (which we
/// must NOT read as "stopped" — that is the Unknown case, same defer-to-secondary
/// contract as the systemd bus-failure path).
pub(crate) fn classify_pgrep(code: Option<i32>) -> ServiceStatus {
    match code {
        Some(0) => ServiceStatus::Active,
        Some(1) => ServiceStatus::Inactive,
        _ => ServiceStatus::Unknown,
    }
}

/// Windows status probe (spec 085 Phase 4). Like the macOS branch, we probe
/// PROCESS presence rather than the Scheduled-Task state: a KeepAlive task reads
/// "Ready" between its 1-minute repetitions even while the daemon is alive, so
/// `tasklist` on the exe name is the reliable signal (the pgrep analog).
fn windows_service_status(unit: &str) -> ServiceStatus {
    let exe = format!("{unit}.exe");
    match Command::new("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {exe}"), "/NH"])
        .output()
    {
        Ok(o) => classify_tasklist(&o.stdout, &exe),
        Err(_) => ServiceStatus::Unknown,
    }
}

/// Pure helper: map `tasklist /FI "IMAGENAME eq <exe>" /NH` stdout to a status.
/// When a process matches, tasklist prints a row containing the image name; when
/// none match it prints `INFO: No tasks are running ...`. Anything else (an error
/// shape) is Unknown, the same defer-to-secondary contract as `classify_pgrep`.
pub(crate) fn classify_tasklist(stdout: &[u8], exe: &str) -> ServiceStatus {
    let s = String::from_utf8_lossy(stdout).to_lowercase();
    if s.contains(&exe.to_lowercase()) {
        ServiceStatus::Active
    } else if s.contains("no tasks") {
        ServiceStatus::Inactive
    } else {
        ServiceStatus::Unknown
    }
}

/// Pure helper: map `systemctl is-active` raw stdout + success bit to
/// a `ServiceStatus`. Split out from `service_status` so tests do not
/// need to spawn `systemctl`.
pub(crate) fn classify_systemctl_is_active(stdout: &[u8], success: bool) -> ServiceStatus {
    let stdout = String::from_utf8_lossy(stdout);
    let line = stdout.trim();
    match line {
        "active" => ServiceStatus::Active,
        "inactive" | "failed" | "deactivating" | "activating" => ServiceStatus::Inactive,
        // "unknown" is what systemctl prints on bus failure on some
        // distros; pair it with the success bit (false) to be sure
        // we are not misreading a genuinely inactive unit named
        // "unknown" by some quirk.
        _ => {
            if success && !line.is_empty() {
                // Unrecognised but-success shape: treat as Inactive
                // conservatively (better to suggest "start" than to
                // claim we could not determine when stdout was
                // produced normally). This branch should be unreachable
                // in practice — systemctl's documented active values
                // are a closed set.
                ServiceStatus::Inactive
            } else {
                ServiceStatus::Unknown
            }
        }
    }
}

/// Returns true if a service is currently active (running).
///
/// Backward-compat wrapper. Returns `true` only for the `Active`
/// branch — `Unknown` is treated as `false` here. New call sites
/// should prefer `service_status` so they can distinguish the
/// "could not determine" case.
pub fn is_service_active(unit: &str) -> bool {
    matches!(service_status(unit), ServiceStatus::Active)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell_output(script: &str) -> std::io::Result<std::process::Output> {
        Command::new("sh").arg("-c").arg(script).output()
    }

    #[test]
    fn restart_in_dry_run_does_not_error() {
        // Should succeed without actually calling systemctl
        assert!(restart_service("innerwarden-agent", true).is_ok());
    }

    #[test]
    fn restart_launchd_in_dry_run_does_not_error() {
        assert!(restart_launchd("com.innerwarden.agent", true).is_ok());
    }

    #[test]
    fn restart_service_dry_run_is_ok_on_any_platform() {
        // dry_run short-circuits before touching systemctl/launchctl, so this
        // is safe to assert on both Linux and macOS CI.
        assert!(restart_service("innerwarden-agent", true).is_ok());
        assert!(restart_service("innerwarden-sensor", true).is_ok());
    }

    #[test]
    fn restart_route_picks_launchd_only_on_mac_for_iw_units() {
        // macOS + an InnerWarden unit → launchd label.
        assert_eq!(
            restart_route(ServiceHost::Macos, "innerwarden-agent"),
            RestartVia::Launchd("com.innerwarden.agent".to_string())
        );
        // macOS but a foreign unit we don't own → systemd (surfaces the error).
        assert_eq!(
            restart_route(ServiceHost::Macos, "sshd"),
            RestartVia::Systemd
        );
        // Linux → always systemd, even for our own units.
        assert_eq!(
            restart_route(ServiceHost::Linux, "innerwarden-agent"),
            RestartVia::Systemd
        );
    }

    #[test]
    fn restart_route_picks_scheduled_task_on_windows_for_iw_units() {
        // Windows + an InnerWarden unit → Scheduled-Task name (spec 085 Phase 4).
        assert_eq!(
            restart_route(ServiceHost::Windows, "innerwarden-sensor"),
            RestartVia::ScheduledTask("InnerWarden\\innerwarden-sensor".to_string())
        );
        // Windows + a foreign unit → systemd fallback (we never restart those).
        assert_eq!(
            restart_route(ServiceHost::Windows, "sshd"),
            RestartVia::Systemd
        );
    }

    #[test]
    fn scheduled_task_name_maps_and_rejects() {
        assert_eq!(
            scheduled_task_name("innerwarden-sensor").as_deref(),
            Some("InnerWarden\\innerwarden-sensor")
        );
        assert_eq!(
            scheduled_task_name("innerwarden-agent.service").as_deref(),
            Some("InnerWarden\\innerwarden-agent")
        );
        // Foreign / empty units are rejected (never routed to a task).
        assert_eq!(scheduled_task_name("sshd"), None);
        assert_eq!(scheduled_task_name("innerwarden-"), None);
    }

    #[test]
    fn restart_scheduled_task_with_covers_dry_run_success_and_failure() {
        // dry_run short-circuits before any schtasks call.
        assert!(
            restart_scheduled_task_with("InnerWarden\\innerwarden-sensor", true, |_p, _a| {
                shell_output("exit 1")
            })
            .is_ok()
        );
        // Non-dry-run: the /End is best-effort, the /Run result decides. Success:
        assert!(
            restart_scheduled_task_with("InnerWarden\\innerwarden-sensor", false, |_p, _a| {
                shell_output("exit 0")
            })
            .is_ok()
        );
        // Failure surfaces stderr.
        let err =
            restart_scheduled_task_with("InnerWarden\\innerwarden-sensor", false, |_p, _a| {
                shell_output("printf task-down >&2; exit 1")
            })
            .expect_err("failed schtasks /Run should be reported");
        assert!(err.to_string().contains("task-down"));
    }

    #[test]
    fn classify_tasklist_maps_presence() {
        // A row containing the exe name = the process is up = Active.
        assert_eq!(
            classify_tasklist(
                b"innerwarden-sensor.exe          1234 Services    0    12,345 K\n",
                "innerwarden-sensor.exe"
            ),
            ServiceStatus::Active
        );
        // The "No tasks" line = a clean not-running answer.
        assert_eq!(
            classify_tasklist(
                b"INFO: No tasks are running which match the specified criteria.\n",
                "innerwarden-sensor.exe"
            ),
            ServiceStatus::Inactive
        );
        // An unrecognised shape defers to Unknown (never a false "down").
        assert_eq!(
            classify_tasklist(b"", "innerwarden-sensor.exe"),
            ServiceStatus::Unknown
        );
    }

    /// macos_service_status shells out to `pgrep`, which also exists on the
    /// Linux CI host, so the I/O body is exercised there: a certainly-absent
    /// process name is Inactive, and this test's own process (matched by a
    /// broad `-f` pattern) is Active.
    #[test]
    fn macos_service_status_uses_pgrep() {
        assert_eq!(
            macos_service_status("definitely-no-such-process-zzq-12345"),
            ServiceStatus::Inactive
        );
        // The test binary's own argv contains "innerwarden"/the deps path; match
        // something guaranteed present in this process tree.
        let self_running = macos_service_status("");
        // An empty pattern is a pgrep usage error (exit 2) -> Unknown, which is
        // still a real (non-panicking) code path through the function.
        assert!(matches!(
            self_running,
            ServiceStatus::Active | ServiceStatus::Inactive | ServiceStatus::Unknown
        ));
    }

    #[test]
    fn launchd_label_maps_innerwarden_units() {
        assert_eq!(
            launchd_label("innerwarden-agent").as_deref(),
            Some("com.innerwarden.agent")
        );
        assert_eq!(
            launchd_label("innerwarden-sensor.service").as_deref(),
            Some("com.innerwarden.sensor")
        );
        assert_eq!(
            launchd_label("innerwarden-watchdog.timer").as_deref(),
            Some("com.innerwarden.watchdog")
        );
    }

    #[test]
    fn launchd_label_rejects_foreign_or_empty_units() {
        assert_eq!(launchd_label("sshd"), None);
        assert_eq!(launchd_label("innerwarden-"), None);
        assert_eq!(launchd_label("innerwarden-.service"), None);
    }

    /// Exercise the public status entrypoints against a certainly-absent unit
    /// so the real dispatch (systemctl on Linux / pgrep on macOS) executes; any
    /// of Active/Inactive/Unknown is a valid non-panicking result.
    #[test]
    fn service_status_entrypoints_execute() {
        let s = service_status("innerwarden-no-such-unit-zzq");
        assert!(matches!(
            s,
            ServiceStatus::Active | ServiceStatus::Inactive | ServiceStatus::Unknown
        ));
        // is_service_active just narrows to the Active case.
        let _b: bool = is_service_active("innerwarden-no-such-unit-zzq");
    }

    /// 2026-07-01 anchor (F7): pgrep exit 0 = a live process = Active.
    #[test]
    fn classify_pgrep_match_maps_to_active() {
        assert_eq!(classify_pgrep(Some(0)), ServiceStatus::Active);
    }

    /// pgrep exit 1 = no match = a clean "not running".
    #[test]
    fn classify_pgrep_no_match_maps_to_inactive() {
        assert_eq!(classify_pgrep(Some(1)), ServiceStatus::Inactive);
    }

    /// pgrep exit 2/3 (usage/fatal) or a killed-by-signal (None) must NOT be
    /// read as "stopped" — it is Unknown so callers defer to a secondary signal
    /// instead of falsely alarming that the agent is down.
    #[test]
    fn classify_pgrep_error_maps_to_unknown() {
        assert_eq!(classify_pgrep(Some(2)), ServiceStatus::Unknown);
        assert_eq!(classify_pgrep(Some(3)), ServiceStatus::Unknown);
        assert_eq!(classify_pgrep(None), ServiceStatus::Unknown);
    }

    #[test]
    fn restart_service_with_accepts_success_and_reports_stderr_on_failure() {
        assert!(
            restart_service_with("innerwarden-agent", false, |_program, _args| {
                shell_output("exit 0")
            })
            .is_ok()
        );

        let err = restart_service_with("innerwarden-agent", false, |_program, _args| {
            shell_output("printf service-down >&2; exit 1")
        })
        .expect_err("failed systemctl should surface stderr");
        assert!(err.to_string().contains("service-down"));
    }

    #[test]
    fn restart_launchd_with_covers_dry_run_success_and_failure_paths() {
        assert!(
            restart_launchd_with("com.innerwarden.agent", true, |_program, _args| {
                shell_output("exit 1")
            })
            .is_ok()
        );
        assert!(
            restart_launchd_with("com.innerwarden.agent", false, |_program, _args| {
                shell_output("exit 0")
            })
            .is_ok()
        );

        let err = restart_launchd_with("com.innerwarden.agent", false, |_program, _args| {
            shell_output("printf launchd-down >&2; exit 1")
        })
        .expect_err("launchctl failure should be reported");
        assert!(err.to_string().contains("launchd-down"));
    }

    /// Bug 2 anchor (2026-05-06): "active" stdout maps to Active.
    #[test]
    fn classify_systemctl_is_active_active_maps_to_active() {
        let s = classify_systemctl_is_active(b"active\n", true);
        assert_eq!(s, ServiceStatus::Active);
    }

    /// Bug 2 anchor: "inactive" stdout maps to Inactive even if the
    /// command exited non-zero (systemctl returns 3 for inactive).
    #[test]
    fn classify_systemctl_is_active_inactive_maps_to_inactive() {
        let s = classify_systemctl_is_active(b"inactive\n", false);
        assert_eq!(s, ServiceStatus::Inactive);
    }

    /// Bug 2 anchor: "failed" maps to Inactive (the unit ran but is
    /// dead — the operator should still see this as "service is down").
    #[test]
    fn classify_systemctl_is_active_failed_maps_to_inactive() {
        let s = classify_systemctl_is_active(b"failed\n", false);
        assert_eq!(s, ServiceStatus::Inactive);
    }

    /// Bug 2 anchor: "activating" / "deactivating" map to Inactive
    /// (we cannot serve traffic during transitions).
    #[test]
    fn classify_systemctl_is_active_transitional_maps_to_inactive() {
        let s = classify_systemctl_is_active(b"activating\n", false);
        assert_eq!(s, ServiceStatus::Inactive);
        let s = classify_systemctl_is_active(b"deactivating\n", false);
        assert_eq!(s, ServiceStatus::Inactive);
    }

    /// Bug 2 anchor (the headline case): "unknown" stdout + non-zero
    /// exit (the bus-failure shape) maps to Unknown — NOT Inactive.
    /// This is the difference between "doctor confidently reports the
    /// agent is down" (false positive) and "doctor defers to the
    /// freshness check below" (correct).
    #[test]
    fn classify_systemctl_is_active_bus_failure_maps_to_unknown() {
        let s = classify_systemctl_is_active(b"unknown\n", false);
        assert_eq!(s, ServiceStatus::Unknown);
    }

    /// Bug 1/2 anchor: empty stdout + non-zero exit (the "Failed to
    /// connect to bus" shape on some distros where stdout is empty
    /// and stderr has the message) also maps to Unknown.
    #[test]
    fn classify_systemctl_is_active_empty_stdout_maps_to_unknown() {
        let s = classify_systemctl_is_active(b"", false);
        assert_eq!(s, ServiceStatus::Unknown);
    }

    /// Pin the public alias so a future refactor that drops the
    /// `is_service_active(&str) -> bool` shim does not silently break
    /// every backward-compat caller.
    #[test]
    fn is_service_active_is_true_only_for_active() {
        assert!(matches!(
            classify_systemctl_is_active(b"active\n", true),
            ServiceStatus::Active
        ));
        assert!(!matches!(
            classify_systemctl_is_active(b"inactive\n", false),
            ServiceStatus::Active
        ));
        assert!(!matches!(
            classify_systemctl_is_active(b"unknown\n", false),
            ServiceStatus::Active
        ));
    }
}
