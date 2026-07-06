use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::{load_env_file, systemd, Cli};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceAction {
    Restart,
    Start,
    Skip,
}

/// Outcome of the post-download arch smoke-test (`<binary> --version`).
#[derive(Debug, PartialEq, Eq)]
enum SmokeOutcome {
    /// Ran and printed the expected version.
    Ok,
    /// Ran on this CPU (good enough to install) but did not print the expected
    /// version string. Soft warning, not a hard stop.
    RanUnverified(String),
    /// Could not execute at all (spawn failure) or was killed by a signal: the
    /// wrong-arch / corrupt-binary case. Hard stop: refuse the swap.
    CannotRun(String),
}

/// Pure verdict from the raw smoke-test signals, separated from process
/// spawning so every branch is unit-tested.
///
/// Hard-fails ONLY when the binary could not execute (spawn failure) or was
/// killed by a signal. A clean non-zero exit still proves the binary RUNS on
/// this arch (e.g. a future build that does not recognise `--version`), so it is
/// treated as soft: we must not break upgrades on a cosmetic mismatch, only on
/// a genuine "this binary does not run here" (the wrong-CPU-arch outage class).
fn smoke_test_verdict(
    spawned: bool,
    signaled: bool,
    exit_code: Option<i32>,
    stdout: &str,
    expected_version: &str,
) -> SmokeOutcome {
    if !spawned {
        return SmokeOutcome::CannotRun(
            "could not execute (likely the wrong CPU architecture)".to_string(),
        );
    }
    if signaled {
        return SmokeOutcome::CannotRun(
            "killed by a signal while running (corrupt or wrong-arch binary)".to_string(),
        );
    }
    if exit_code == Some(0) && stdout.contains(expected_version) {
        return SmokeOutcome::Ok;
    }
    SmokeOutcome::RanUnverified(format!(
        "did not report version {expected_version} (exit={exit_code:?})"
    ))
}

/// Run `<path> --version` and classify the outcome. Unix-only (the only targets
/// InnerWarden ships). The staged binary must already be sha256+sig verified.
fn run_smoke_test(path: &Path, expected_version: &str) -> SmokeOutcome {
    run_smoke_test_with(expected_version, || {
        std::process::Command::new(path).arg("--version").output()
    })
}

/// Core of [`run_smoke_test`] with the spawn injected so the retry logic is
/// unit-testable without a real process. A freshly-staged binary can transiently
/// fail to exec — ETXTBSY (26) if a concurrent fork still holds a write fd to
/// it, or EAGAIN (11) if the host is briefly out of process slots — neither of
/// which means the binary is unusable. Retry those a few times before declaring
/// `CannotRun`, which would abort the upgrade and keep the old binary behind a
/// misleading wrong-arch message. Permanent errors (e.g. ENOENT) fail fast.
fn run_smoke_test_with<F>(expected_version: &str, mut spawn: F) -> SmokeOutcome
where
    F: FnMut() -> std::io::Result<std::process::Output>,
{
    let mut attempt = 0u32;
    let result = loop {
        match spawn() {
            Ok(out) => break Ok(out),
            Err(e) => {
                let transient = matches!(e.raw_os_error(), Some(26) | Some(11));
                if transient && attempt < 5 {
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(10 * u64::from(attempt)));
                    continue;
                }
                break Err(e);
            }
        }
    };
    match result {
        Err(_) => smoke_test_verdict(false, false, None, "", expected_version),
        Ok(out) => {
            // A process cannot be signal-killed on Windows (spec 085 Phase 0),
            // so `signaled=false` there; the arch smoke-test relies on the
            // exit-code + version match, which is cross-platform.
            let signaled = {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    out.status.signal().is_some()
                }
                #[cfg(not(unix))]
                {
                    false
                }
            };
            let stdout = String::from_utf8_lossy(&out.stdout);
            smoke_test_verdict(true, signaled, out.status.code(), &stdout, expected_version)
        }
    }
}

/// Stage one downloaded binary into the install dir, arch-smoke-test it there (a
/// trusted path, so the host's own `host_drift` does not flag the check the way
/// a `/tmp` exec would), then install it to all of its target names and drop the
/// staging copy. I/O is injected (`install` / `smoke` / `remove`) so the
/// staging-gate-then-install-all flow is unit-tested without filesystem or
/// process I/O, the same inject-for-test shape as [`restart_after_upgrade`].
/// Hard-fails (keeping the existing binary) only on `SmokeOutcome::CannotRun`.
fn stage_and_install<I, S, R>(
    binary: &str,
    tmp_path: &Path,
    dests: &[PathBuf],
    expected_version: &str,
    mut install: I,
    smoke: S,
    mut remove: R,
) -> Result<()>
where
    I: FnMut(&Path, &Path) -> Result<()>,
    S: FnOnce(&Path, &str) -> SmokeOutcome,
    R: FnMut(&Path),
{
    let staged = dests
        .first()
        .map(|d| d.with_extension("iwnew"))
        .context("install_paths returned no destination")?;
    install(tmp_path, &staged)?;
    match smoke(&staged, expected_version) {
        SmokeOutcome::CannotRun(why) => {
            remove(&staged);
            anyhow::bail!(
                "arch smoke-test failed for {binary}: {why}. Refusing to install; \
                 the existing binary is untouched. (sha256 + signature already \
                 verified, so this is an execution failure, almost certainly a \
                 wrong-CPU-architecture asset.)"
            );
        }
        SmokeOutcome::RanUnverified(note) => {
            println!("  [warn] {binary} ran but {note}; proceeding (bytes are signed).");
        }
        SmokeOutcome::Ok => {}
    }
    for dest in dests {
        install(&staged, dest)?;
        println!("  [done] {} → {}", binary, dest.display());
    }
    remove(&staged);
    Ok(())
}

fn release_date_suffix(release_date: Option<&str>) -> String {
    release_date.map(|d| format!("  [{d}]")).unwrap_or_default()
}

fn release_date_display(release_date: Option<&str>) -> String {
    release_date.map(|d| format!(" ({d})")).unwrap_or_default()
}

fn telegram_notification_ready(bot_token: &str, chat_id: &str) -> bool {
    !bot_token.is_empty() && !chat_id.is_empty()
}

fn changelog_snippet(body: Option<&str>, max_chars: usize) -> String {
    body.unwrap_or("")
        .chars()
        .take(max_chars)
        .collect::<String>()
}

/// Map the build OS to the `uname -s`-shaped family install.sh reports, so the
/// `os` dimension is consistent across the install.sh and upgrade ping paths.
fn telemetry_os() -> &'static str {
    match std::env::consts::OS {
        "linux" => "Linux",
        "macos" => "Darwin",
        other => other,
    }
}

/// Build the anonymous ping URL. Pure (no I/O) so the query shape — which must
/// match the install.sh ping and what `pages/api/ping.ts` reads — is testable.
fn ping_url(tag: &str, os: &str, arch: &str, event: &str) -> String {
    format!("https://www.innerwarden.com/api/ping?v={tag}&os={os}&arch={arch}&event={event}")
}

/// Fire the anonymous, opt-OUT install/upgrade ping (best-effort, never blocks
/// or fails the command). Mirrors the install.sh ping: version + OS + arch +
/// event, no IP/PII (the server hashes ip+day into a dedup id and discards the
/// IP). Suppressed by `INNERWARDEN_NO_TELEMETRY=1`. Prints a one-line notice so
/// the default-on collection is transparent.
/// Telemetry is opt-OUT: enabled unless `INNERWARDEN_NO_TELEMETRY=1`. Pure over
/// its input so the policy is unit-tested without touching the process env.
fn telemetry_enabled_from(no_telemetry: Option<&str>) -> bool {
    no_telemetry != Some("1")
}

fn send_telemetry_ping(tag: &str, event: &str) {
    let no_telemetry = std::env::var("INNERWARDEN_NO_TELEMETRY").ok();
    if !telemetry_enabled_from(no_telemetry.as_deref()) {
        return;
    }
    let arch = crate::upgrade::detect_arch().unwrap_or("unknown");
    let os = telemetry_os();
    println!(
        "\n  Sent an anonymous {event} ping (version + OS + CPU arch only — no IP, no host data)."
    );
    println!(
        "  Opt out any time with INNERWARDEN_NO_TELEMETRY=1. Details: https://www.innerwarden.com/privacy"
    );
    do_ping(&ping_url(tag, os, arch, event));
}

/// Fire one GET at `url`. Best-effort: a short timeout, errors ignored —
/// telemetry must never break or slow an upgrade. Separated from
/// [`send_telemetry_ping`] so the network send is exercised against a local
/// mock in tests (the rest of `send_telemetry_ping` is env + stdout).
fn do_ping(url: &str) {
    let _ = ureq::get(url)
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(5)))
        .build()
        .call();
}

fn render_upgrade_notification(
    latest: &str,
    current: &str,
    date_suffix: &str,
    changelog: &str,
) -> String {
    format!(
        "🆕 <b>Inner Warden {latest} available</b>\n\n\
         Current: {current}\n\
         New: {latest}{date_suffix}\n\n\
         {changelog}\n\n\
         Upgrade: <code>innerwarden upgrade --yes</code>"
    )
}

fn confirmation_accepted(answer: &str) -> bool {
    let normalized = answer.trim().to_lowercase();
    normalized.is_empty() || normalized == "y" || normalized == "yes"
}

fn classify_service_action(is_active: bool, unit_exists: bool) -> ServiceAction {
    if is_active {
        ServiceAction::Restart
    } else if unit_exists {
        ServiceAction::Start
    } else {
        ServiceAction::Skip
    }
}

/// Decide which units to restart after the binaries are swapped.
///
/// **Watchdog hosts (the paid Active-Defence supervisor).** When
/// `innerwarden-watchdog` is active the agent runs as a watchdog-SPAWNED child
/// and `innerwarden-agent.service` is disabled (but its unit file still exists).
/// Naively restarting `innerwarden-agent` there does two wrong things: it spawns
/// a SECOND agent alongside the watchdog's child (duplicate-instance flood), and
/// it does NOT refresh the running child's binary (the watchdog keeps the old
/// one). So on a watchdog host we skip the agent unit entirely and restart the
/// watchdog instead — restarting the watchdog tears down its cgroup (watchdog +
/// child agent) and respawns the agent on the freshly-swapped binary. Never
/// `systemctl start innerwarden-agent` on a watchdog host.
///
/// Pure so the policy is unit-tested without touching systemd. `(is_active,
/// unit_exists)` per unit; returns the ordered (unit, action) plan.
fn plan_service_restarts(
    watchdog_active: bool,
    sensor: (bool, bool),
    agent: (bool, bool),
) -> Vec<(&'static str, ServiceAction)> {
    let mut plan = vec![(
        "innerwarden-sensor",
        classify_service_action(sensor.0, sensor.1),
    )];
    if watchdog_active {
        // Respawn the agent via its supervisor, not as a standalone service.
        plan.push(("innerwarden-watchdog", ServiceAction::Restart));
    } else {
        plan.push((
            "innerwarden-agent",
            classify_service_action(agent.0, agent.1),
        ));
    }
    plan
}

/// Execute a restart plan, calling `restart` for each Restart/Start unit and
/// printing the outcome. `restart` is injected (production passes
/// `systemd::restart_service`) so the control flow — Restart propagates errors,
/// Start is best-effort, Skip is a no-op — is unit-tested without touching
/// systemd. A failed Restart aborts the upgrade (the swapped binary is in place
/// but the service did not come back, which the operator must see); a failed
/// Start only warns (the unit was already stopped).
fn execute_restart_plan<F>(plan: &[(&str, ServiceAction)], mut restart: F) -> Result<()>
where
    F: FnMut(&str) -> Result<()>,
{
    for (unit, action) in plan {
        match action {
            ServiceAction::Restart => {
                restart(unit)?;
                println!("  [done] Restarted {unit}");
            }
            ServiceAction::Start => match restart(unit) {
                Ok(()) => println!("  [done] Started {unit}"),
                Err(e) => {
                    println!("  [warn] Could not start {unit}: {e}");
                    println!("         Check logs: journalctl -u {unit} -n 30");
                }
            },
            ServiceAction::Skip => {}
        }
    }
    Ok(())
}

/// Restart the services after a binary swap, with all systemd I/O injected so the
/// full policy — detect watchdog, build the plan, print the watchdog notice,
/// execute — is unit-tested without touching the host. Production wires
/// `systemd::is_service_active` / unit-file existence / `systemd::restart_service`;
/// tests pass in-memory closures. Keeping the I/O at the call site to a single
/// line (these three closures) is deliberate: it is the only part the unit tests
/// cannot reach, and it contains no logic.
fn restart_after_upgrade<A, E, R>(is_active: A, unit_exists: E, mut restart: R) -> Result<()>
where
    A: Fn(&str) -> bool,
    E: Fn(&str) -> bool,
    R: FnMut(&str) -> Result<()>,
{
    let state = |unit: &str| (is_active(unit), unit_exists(unit));
    let watchdog_active = is_active("innerwarden-watchdog");
    let plan = plan_service_restarts(
        watchdog_active,
        state("innerwarden-sensor"),
        state("innerwarden-agent"),
    );
    if watchdog_active {
        println!("  [info] watchdog active — respawning the agent via innerwarden-watchdog (not as a standalone service)");
    }
    execute_restart_plan(&plan, &mut restart)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_upgrade(
    cli: &Cli,
    check_only: bool,
    yes: bool,
    notify: bool,
    install_dir: &Path,
    allow_unsigned_stable: bool,
    allow_unsigned_canary: bool,
) -> Result<()> {
    use crate::upgrade::*;

    println!("Checking for updates...");

    let release =
        fetch_latest_release().context("could not reach GitHub - check network and try again")?;

    cmd_upgrade_with_release(
        cli,
        check_only,
        yes,
        notify,
        install_dir,
        release,
        allow_unsigned_stable,
        allow_unsigned_canary,
    )
}

#[allow(clippy::too_many_arguments)]
fn cmd_upgrade_with_release(
    cli: &Cli,
    check_only: bool,
    yes: bool,
    notify: bool,
    install_dir: &Path,
    release: crate::upgrade::GithubRelease,
    allow_unsigned_stable: bool,
    allow_unsigned_canary: bool,
) -> Result<()> {
    use crate::upgrade::*;

    let current = CURRENT_VERSION;
    let latest = strip_v(&release.tag_name);

    let date_suffix = release_date_suffix(release.release_date());

    println!("  Current version:  {current}");

    if !is_newer(current, &release.tag_name) {
        println!("  Latest release:   {latest}{date_suffix} - already up to date.");
        return Ok(());
    }

    println!(
        "  Latest release:   {latest}{date_suffix}  ({})",
        release.html_url
    );

    // --notify: send Telegram alert about available update (for cron use)
    if notify {
        let env_file = cli
            .agent_config
            .parent()
            .map(|p| p.join("agent.env"))
            .unwrap_or_else(|| std::path::PathBuf::from("/etc/innerwarden/agent.env"));
        let env_vars = load_env_file(&env_file);
        let bot_token = env_vars
            .get("TELEGRAM_BOT_TOKEN")
            .cloned()
            .or_else(|| std::env::var("TELEGRAM_BOT_TOKEN").ok())
            .unwrap_or_default();
        let chat_id = env_vars
            .get("TELEGRAM_CHAT_ID")
            .cloned()
            .or_else(|| std::env::var("TELEGRAM_CHAT_ID").ok())
            .unwrap_or_default();
        if telegram_notification_ready(&bot_token, &chat_id) {
            // Extract changelog from release body
            let changelog = changelog_snippet(release.body.as_deref(), 500);
            let text = render_upgrade_notification(latest, current, &date_suffix, &changelog);
            let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
            let _ = ureq::post(&url).send_json(serde_json::json!({
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
            }));
            println!("  Telegram notification sent.");
        } else {
            println!("  --notify: Telegram not configured, skipping notification.");
        }
    }

    if check_only {
        println!("\nRun 'innerwarden upgrade' to install.");
        return Ok(());
    }

    // Auto-backup configs before upgrade
    let config_dir = cli
        .agent_config
        .parent()
        .unwrap_or(Path::new("/etc/innerwarden"));
    if config_dir.exists() {
        match tempfile::Builder::new()
            .prefix("innerwarden-backup-pre-upgrade-")
            .suffix(".tar.gz")
            .tempfile()
        {
            Ok(tmp) => {
                let backup_path = tmp.path().to_string_lossy().to_string();
                print!("  Backing up configs to {backup_path}... ");
                match std::process::Command::new("tar")
                    .args(["czf", &backup_path, "-C", "/"])
                    .arg(config_dir.strip_prefix("/").unwrap_or(config_dir))
                    .output()
                {
                    Ok(out) if out.status.success() => {
                        // Keep the backup file (prevent cleanup on drop)
                        let _ = tmp.keep();
                        println!("done");
                    }
                    _ => println!("skipped (tar failed, continuing anyway)"),
                }
            }
            Err(_) => {
                println!("  Skipping backup (could not create temp file)");
            }
        }
    }

    // Detect architecture
    let arch = detect_arch().ok_or_else(|| {
        anyhow::anyhow!(
            "unsupported CPU architecture '{}' - build from source for your platform",
            std::env::consts::ARCH
        )
    })?;

    // Build download plan
    let plan = build_plan(&release, arch);

    if plan.is_empty() {
        anyhow::bail!(
            "no assets found for linux-{arch} in release {} - \
             check {} for manual download",
            release.tag_name,
            release.html_url
        );
    }

    println!("\nAssets available for linux-{arch}:");
    for dp in &plan {
        let sha_status = if dp.sha256_asset.is_some() {
            "sha256 ✓"
        } else {
            "no sha256"
        };
        let sig_status = if dp.sig_asset.is_some() {
            "  sig ✓"
        } else {
            ""
        };
        println!(
            "  {:<28} {}  ({}{})",
            dp.target.binary,
            fmt_bytes(dp.asset.size),
            sha_status,
            sig_status
        );
    }

    let dest_paths: Vec<_> = plan
        .iter()
        .flat_map(|dp| install_paths(dp.target, install_dir))
        .collect();

    println!("\nWill install to {}:", install_dir.display());
    for p in &dest_paths {
        println!("  {}", p.display());
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nProceed? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !confirmation_accepted(&input) {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    let tmp_dir = tempfile::tempdir().context("failed to create temp directory")?;

    for dp in &plan {
        let binary = dp.target.binary;
        print!("  Downloading {binary}... ");
        std::io::stdout().flush()?;

        let tmp_path = tmp_dir.path().join(binary);
        let bytes = download(&dp.asset.browser_download_url, &tmp_path)?;

        // Verify SHA-256 if sidecar is present
        if let Some(sha_asset) = dp.sha256_asset {
            let expected = fetch_expected_hash(&sha_asset.browser_download_url)?;
            let actual = sha256_file(&tmp_path)?;
            if actual != expected {
                anyhow::bail!(
                    "SHA-256 mismatch for {binary}:\n  expected {expected}\n  got      {actual}"
                );
            }
            print!("{}  sha256 ok", fmt_bytes(bytes));
        } else {
            print!("{}  (no sha256 sidecar)", fmt_bytes(bytes));
        }

        // Spec 048 — fail-closed signature policy. Stable releases MUST
        // carry a `.sig`; canary releases are best-effort until canary
        // signing infrastructure ships. The pre-Spec 048 behaviour
        // ("warn and continue" on every missing sig) was the gap that
        // let "the website says signed but the installer doesn't
        // verify" persist for as long as it did. Override only via the
        // explicit operator-visible flags.
        match dp.sig_asset {
            Some(sig_asset) => {
                let sig_b64 = fetch_signature(&sig_asset.browser_download_url)?;
                let binary_bytes = std::fs::read(&tmp_path)
                    .context("cannot read downloaded binary for sig check")?;
                verify_signature(&binary_bytes, &sig_b64)?;
                println!("  sig ok");
            }
            None if release.is_canary() && allow_unsigned_canary => {
                println!();
                println!(
                    "  [warn] unsigned canary release - signature verification skipped \
                     for {binary} (--allow-unsigned-canary set)"
                );
            }
            None if !release.is_canary() && allow_unsigned_stable => {
                println!();
                println!(
                    "  [WARN] STABLE release {} has no .sig for {binary}; proceeding \
                     because --allow-unsigned-stable was passed. This is the kind of \
                     override that defeats the policy — every invocation should be \
                     auditable.",
                    release.tag_name
                );
            }
            None => {
                println!();
                if release.is_canary() {
                    anyhow::bail!(
                        "canary release {} has no .sig for {binary}; pass \
                         --allow-unsigned-canary to proceed (canary signing is on the \
                         spec 048 follow-up roadmap)",
                        release.tag_name
                    );
                } else {
                    anyhow::bail!(
                        "stable release {} has no .sig for {binary}; refusing to \
                         install. The Ed25519 release signing key is embedded in this \
                         binary and verifies signatures shipped with stable releases. \
                         If you absolutely must install an unsigned stable release, \
                         pass --allow-unsigned-stable (NOT recommended; logged in CI \
                         release-anchor reviews).",
                        release.tag_name
                    );
                }
            }
        }

        // Arch smoke-test BEFORE swapping the live binary. sha256+sig prove the
        // bytes are authentic, but NOT that they execute on THIS host's CPU;
        // installing an x86_64 build on aarch64 took prod down on 2026-06-10.
        // Stage the verified binary into the install dir (a package-trusted path,
        // so the host's own host_drift detector does not flag the check the way a
        // /tmp exec would) and run `--version`; refuse the swap if it cannot run.
        let dests = install_paths(dp.target, install_dir);
        stage_and_install(
            binary,
            &tmp_path,
            &dests,
            strip_v(&release.tag_name),
            |src, dest| install_binary(src, dest, false),
            run_smoke_test,
            |p| {
                let _ = std::fs::remove_file(p);
            },
        )?;
    }

    // Fix permissions on existing config files - files written before v0.1.9 may
    // be root:root 600, which prevents innerwarden-agent (User=innerwarden) from
    // reading them. chmod 640 + chgrp innerwarden is fail-silent.
    fix_config_dir_permissions(
        cli.agent_config
            .parent()
            .unwrap_or(std::path::Path::new("/etc/innerwarden")),
    );

    // Restart running services; also start the agent if it has a unit file but is
    // stopped. On a watchdog host the agent is respawned via the watchdog instead
    // of as a standalone service (see restart_after_upgrade / plan_service_restarts).
    println!();
    restart_after_upgrade(
        systemd::is_service_active,
        |unit| std::path::Path::new(&format!("/etc/systemd/system/{unit}.service")).exists(),
        |unit| systemd::restart_service(unit, false),
    )?;

    let date_display = release_date_display(release.release_date());

    println!(
        "\nInnerWarden upgraded to {}{} successfully.",
        release.tag_name, date_display
    );

    // Anonymous upgrade ping (opt-OUT, event=upgrade) — `innerwarden upgrade`
    // does not go through install.sh, so without this the upgrade path is
    // invisible to the install_ping stream. Same anonymous/minimal data + the
    // same INNERWARDEN_NO_TELEMETRY=1 opt-out + the same printed notice.
    send_telemetry_ping(&release.tag_name, "upgrade");

    // Show what's new in this release
    if let Some(preview) = release.changelog_preview() {
        println!("\nWhat's new in {}:", release.tag_name);
        println!("─────────────────────────────────────────────────");
        for line in preview.lines() {
            println!("  {line}");
        }
        println!("─────────────────────────────────────────────────");
        println!("  Full release notes: {}", release.html_url);
    } else {
        println!("  Release notes: {}", release.html_url);
    }

    Ok(())
}

/// Fix permissions on all config files in the innerwarden config directory.
/// chmod 640 + chgrp innerwarden so the service user (User=innerwarden) can read them.
/// Fail-silent - best-effort in environments where the group doesn't exist.
fn fix_config_dir_permissions(config_dir: &Path) {
    // Unix chmod/chgrp of config files. On Windows (spec 085 Phase 0) this is a
    // no-op concept; the ACL equivalent belongs to a later phase.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(entries) = std::fs::read_dir(config_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640));
                let _ = std::process::Command::new("chgrp")
                    .arg("innerwarden")
                    .arg(&path)
                    .output();
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = config_dir;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_verdict_spawn_failure_is_hard_stop() {
        // Wrong-CPU-arch asset: spawn fails (ENOEXEC). MUST hard-stop.
        assert!(matches!(
            smoke_test_verdict(false, false, None, "", "0.15.26"),
            SmokeOutcome::CannotRun(_)
        ));
    }

    #[test]
    fn smoke_verdict_signal_is_hard_stop() {
        // Killed by a signal (e.g. SIGILL on a bad-arch binary). MUST hard-stop.
        assert!(matches!(
            smoke_test_verdict(true, true, None, "", "0.15.26"),
            SmokeOutcome::CannotRun(_)
        ));
    }

    #[test]
    fn smoke_verdict_version_match_is_ok() {
        assert_eq!(
            smoke_test_verdict(
                true,
                false,
                Some(0),
                "innerwarden-sensor 0.15.26",
                "0.15.26"
            ),
            SmokeOutcome::Ok
        );
    }

    #[test]
    fn smoke_verdict_clean_nonzero_exit_is_soft_not_hard() {
        // Ran on this arch but exited non-zero (e.g. did not recognise
        // --version). It RUNS here, so this must NOT abort the upgrade.
        assert!(matches!(
            smoke_test_verdict(true, false, Some(2), "usage: ...", "0.15.26"),
            SmokeOutcome::RanUnverified(_)
        ));
    }

    #[test]
    fn smoke_verdict_zero_exit_wrong_version_is_soft() {
        // Runs, exits clean, but reports a different version: soft warn, proceed.
        assert!(matches!(
            smoke_test_verdict(true, false, Some(0), "innerwarden 0.15.25", "0.15.26"),
            SmokeOutcome::RanUnverified(_)
        ));
    }

    #[test]
    fn run_smoke_test_on_missing_binary_cannot_run() {
        let v = run_smoke_test(
            std::path::Path::new("/nonexistent/iw-smoke-test-xyz"),
            "0.15.26",
        );
        assert!(matches!(v, SmokeOutcome::CannotRun(_)));
    }

    fn write_exec_script(dir: &std::path::Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("fakebin");
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn run_smoke_test_real_binary_version_match_is_ok() {
        // Exercises the spawn-succeeds branch: a real executable that prints the
        // expected version exits 0 and matches => Ok.
        let tmp = tempfile::tempdir().unwrap();
        let bin = write_exec_script(tmp.path(), "#!/bin/sh\necho \"fakebin 9.9.9\"\n");
        assert_eq!(run_smoke_test(&bin, "9.9.9"), SmokeOutcome::Ok);
    }

    #[test]
    fn run_smoke_test_real_binary_nonzero_exit_is_soft() {
        // Spawns fine but exits non-zero: it RUNS on this arch, so soft, not a
        // hard stop.
        let tmp = tempfile::tempdir().unwrap();
        let bin = write_exec_script(tmp.path(), "#!/bin/sh\nexit 3\n");
        assert!(matches!(
            run_smoke_test(&bin, "9.9.9"),
            SmokeOutcome::RanUnverified(_)
        ));
    }

    fn fake_output(exit_code: i32, stdout: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(exit_code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn run_smoke_test_retries_transient_etxtbsy_then_succeeds() {
        // A transient exec failure (ETXTBSY: a concurrent fork still holds a
        // write fd to the freshly-staged binary) must be retried, not reported
        // as "cannot run on this arch". This is also what makes the real-binary
        // smoke test deterministic under parallel `cargo test` load.
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let v = run_smoke_test_with("9.9.9", || {
            let n = calls.get();
            calls.set(n + 1);
            if n < 2 {
                Err(std::io::Error::from_raw_os_error(26)) // ETXTBSY
            } else {
                Ok(fake_output(0, "fakebin 9.9.9"))
            }
        });
        assert_eq!(v, SmokeOutcome::Ok);
        assert_eq!(
            calls.get(),
            3,
            "should retry the two transient failures then succeed"
        );
    }

    #[test]
    fn run_smoke_test_does_not_retry_permanent_error() {
        // A permanent spawn error (ENOENT) is a real "cannot run" and must fail
        // fast — no retry loop.
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let v = run_smoke_test_with("9.9.9", || {
            calls.set(calls.get() + 1);
            Err(std::io::Error::from_raw_os_error(2)) // ENOENT
        });
        assert!(matches!(v, SmokeOutcome::CannotRun(_)));
        assert_eq!(calls.get(), 1, "a permanent error must not be retried");
    }

    fn dests(n: usize) -> Vec<PathBuf> {
        (0..n)
            .map(|i| PathBuf::from(format!("/usr/local/bin/iw-bin-{i}")))
            .collect()
    }

    #[test]
    fn stage_and_install_ok_installs_all_dests_from_staged_and_cleans_up() {
        use std::cell::RefCell;
        let installs = RefCell::new(Vec::<(PathBuf, PathBuf)>::new());
        let removed = RefCell::new(Vec::<PathBuf>::new());
        let ds = dests(2);
        let r = stage_and_install(
            "iw-bin",
            Path::new("/tmp/dl/iw-bin"),
            &ds,
            "1.2.3",
            |src, dest| {
                installs
                    .borrow_mut()
                    .push((src.to_path_buf(), dest.to_path_buf()));
                Ok(())
            },
            |_p, _v| SmokeOutcome::Ok,
            |p| removed.borrow_mut().push(p.to_path_buf()),
        );
        assert!(r.is_ok());
        let staged = PathBuf::from("/usr/local/bin/iw-bin-0.iwnew");
        // tmp -> staged, then staged -> each of the 2 dests.
        assert_eq!(installs.borrow().len(), 3);
        assert_eq!(
            installs.borrow()[0],
            (PathBuf::from("/tmp/dl/iw-bin"), staged.clone())
        );
        assert_eq!(installs.borrow()[1], (staged.clone(), ds[0].clone()));
        assert_eq!(installs.borrow()[2], (staged.clone(), ds[1].clone()));
        assert_eq!(removed.borrow().as_slice(), &[staged]);
    }

    #[test]
    fn stage_and_install_ran_unverified_still_installs() {
        use std::cell::RefCell;
        let installs = RefCell::new(0usize);
        let r = stage_and_install(
            "iw-bin",
            Path::new("/tmp/iw-bin"),
            &dests(1),
            "1.2.3",
            |_s, _d| {
                *installs.borrow_mut() += 1;
                Ok(())
            },
            |_p, _v| SmokeOutcome::RanUnverified("no version".into()),
            |_p| {},
        );
        assert!(r.is_ok());
        assert_eq!(*installs.borrow(), 2); // tmp->staged + 1 dest
    }

    #[test]
    fn stage_and_install_cannot_run_bails_before_dest_install() {
        use std::cell::RefCell;
        let installs = RefCell::new(0usize);
        let removed = RefCell::new(0usize);
        let r = stage_and_install(
            "iw-bin",
            Path::new("/tmp/iw-bin"),
            &dests(2),
            "1.2.3",
            |_s, _d| {
                *installs.borrow_mut() += 1;
                Ok(())
            },
            |_p, _v| SmokeOutcome::CannotRun("wrong arch".into()),
            |_p| {
                *removed.borrow_mut() += 1;
            },
        );
        let e = r.unwrap_err().to_string();
        assert!(e.contains("Refusing to install"), "{e}");
        assert!(e.contains("wrong arch"), "{e}");
        assert_eq!(
            *installs.borrow(),
            1,
            "only the staged install, no dest swap"
        );
        assert_eq!(*removed.borrow(), 1, "staged copy cleaned up on abort");
    }

    #[test]
    fn stage_and_install_propagates_install_error() {
        let r = stage_and_install(
            "iw-bin",
            Path::new("/tmp/iw-bin"),
            &dests(1),
            "1.2.3",
            |_s, _d| anyhow::bail!("disk full"),
            |_p, _v| SmokeOutcome::Ok,
            |_p| {},
        );
        assert!(r.unwrap_err().to_string().contains("disk full"));
    }
    use crate::upgrade::{detect_arch, GithubAsset, GithubRelease, CURRENT_VERSION};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use tempfile::TempDir;

    #[test]
    #[test]
    fn plan_restarts_normal_host_restarts_sensor_and_agent() {
        // No watchdog: agent is its own active service (test001 / Azure pattern).
        let plan = plan_service_restarts(false, (true, true), (true, true));
        assert_eq!(
            plan,
            vec![
                ("innerwarden-sensor", ServiceAction::Restart),
                ("innerwarden-agent", ServiceAction::Restart),
            ]
        );
    }

    #[test]
    fn plan_restarts_watchdog_host_respawns_via_watchdog_not_agent() {
        // Watchdog active, agent.service DISABLED but unit-file present (Oracle
        // prod). Must NOT touch innerwarden-agent (would duplicate-flood); restart
        // the watchdog so it respawns the agent on the new binary.
        let plan = plan_service_restarts(true, (true, true), (false, true));
        assert_eq!(
            plan,
            vec![
                ("innerwarden-sensor", ServiceAction::Restart),
                ("innerwarden-watchdog", ServiceAction::Restart),
            ]
        );
        // The agent unit must never appear in a watchdog plan.
        assert!(!plan.iter().any(|(u, _)| *u == "innerwarden-agent"));
    }

    #[test]
    fn plan_restarts_normal_host_starts_stopped_agent() {
        // Agent installed but stopped, no watchdog → Start it (existing behaviour).
        let plan = plan_service_restarts(false, (true, true), (false, true));
        assert_eq!(plan[1], ("innerwarden-agent", ServiceAction::Start));
    }

    #[test]
    fn execute_restart_plan_calls_restart_for_restart_and_start_skips_skip() {
        let plan = [
            ("innerwarden-sensor", ServiceAction::Restart),
            ("innerwarden-agent", ServiceAction::Start),
            ("innerwarden-noop", ServiceAction::Skip),
        ];
        let mut called: Vec<String> = Vec::new();
        execute_restart_plan(&plan, |unit| {
            called.push(unit.to_string());
            Ok(())
        })
        .unwrap();
        // Restart + Start invoke the callback; Skip does not.
        assert_eq!(called, vec!["innerwarden-sensor", "innerwarden-agent"]);
    }

    #[test]
    fn execute_restart_plan_propagates_restart_error_but_not_start_error() {
        // A failing Restart aborts the whole plan (returns Err).
        let restart_plan = [("innerwarden-sensor", ServiceAction::Restart)];
        let err = execute_restart_plan(&restart_plan, |_| anyhow::bail!("boom")).is_err();
        assert!(err, "a failed Restart must abort the upgrade");

        // A failing Start is best-effort (warn only) — the plan still succeeds.
        let start_plan = [("innerwarden-agent", ServiceAction::Start)];
        let ok = execute_restart_plan(&start_plan, |_| anyhow::bail!("stopped")).is_ok();
        assert!(ok, "a failed Start must not abort the upgrade");
    }

    #[test]
    fn restart_after_upgrade_watchdog_host_restarts_sensor_and_watchdog_not_agent() {
        // Watchdog active; agent.service present but inactive (Oracle prod). The
        // full policy (detect → plan → execute) must restart sensor + watchdog and
        // never the agent unit.
        let active = |u: &str| u == "innerwarden-sensor" || u == "innerwarden-watchdog";
        let exists = |_: &str| true; // all unit files present
        let mut restarted: Vec<String> = Vec::new();
        restart_after_upgrade(active, exists, |u| {
            restarted.push(u.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            restarted,
            vec!["innerwarden-sensor", "innerwarden-watchdog"]
        );
        assert!(!restarted.iter().any(|u| u == "innerwarden-agent"));
    }

    #[test]
    fn restart_after_upgrade_normal_host_restarts_sensor_and_agent() {
        // No watchdog; sensor + agent both active services (test001 / Azure).
        let active = |u: &str| u == "innerwarden-sensor" || u == "innerwarden-agent";
        let exists = |_: &str| true;
        let mut restarted: Vec<String> = Vec::new();
        restart_after_upgrade(active, exists, |u| {
            restarted.push(u.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(restarted, vec!["innerwarden-sensor", "innerwarden-agent"]);
    }

    #[test]
    fn restart_after_upgrade_propagates_a_failed_sensor_restart() {
        let active = |_: &str| true;
        let exists = |_: &str| true;
        let err = restart_after_upgrade(active, exists, |_| anyhow::bail!("sensor down")).is_err();
        assert!(
            err,
            "a failed required-service restart must abort the upgrade"
        );
    }

    #[test]
    fn execute_restart_plan_watchdog_plan_restarts_sensor_and_watchdog_only() {
        // End-to-end of the watchdog path: the plan from a watchdog host, executed,
        // must invoke restart for sensor + watchdog and NEVER the agent unit.
        let plan = plan_service_restarts(true, (true, true), (false, true));
        let mut called: Vec<String> = Vec::new();
        execute_restart_plan(&plan, |unit| {
            called.push(unit.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(called, vec!["innerwarden-sensor", "innerwarden-watchdog"]);
        assert!(!called.iter().any(|u| u == "innerwarden-agent"));
    }

    #[test]
    fn ping_url_matches_install_sh_query_shape() {
        // Must mirror install.sh: ?v=&os=&arch=&event= against the www host so
        // pages/api/ping.ts reads every field. The upgrade path always sends
        // event=upgrade.
        let u = ping_url("v0.15.12", "Linux", "x86_64", "upgrade");
        assert_eq!(
            u,
            "https://www.innerwarden.com/api/ping?v=v0.15.12&os=Linux&arch=x86_64&event=upgrade"
        );
        assert!(u.starts_with("https://www.innerwarden.com/api/ping?"));
    }

    #[test]
    fn do_ping_sends_the_get_with_the_query() {
        // Exercises the real network send against a local mock: the upgrade
        // ping must reach the server as a GET carrying the install.sh-shaped
        // query (v/os/arch/event).
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = s.write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        do_ping(&format!(
            "http://{addr}/api/ping?v=v0.15.12&os=Linux&arch=x86_64&event=upgrade"
        ));
        let req = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("mock server received the ping");
        assert!(
            req.starts_with("GET /api/ping?v=v0.15.12&os=Linux&arch=x86_64&event=upgrade"),
            "unexpected request line: {req}"
        );
    }

    #[test]
    fn telemetry_is_opt_out() {
        // Opt-OUT: on unless explicitly "1".
        assert!(telemetry_enabled_from(None));
        assert!(telemetry_enabled_from(Some("0")));
        assert!(telemetry_enabled_from(Some("")));
        assert!(telemetry_enabled_from(Some("true"))); // only "1" disables
        assert!(!telemetry_enabled_from(Some("1")));
    }

    #[test]
    fn telemetry_os_is_uname_s_shaped() {
        // Matches install.sh's `uname -s` family so the os dimension is
        // consistent across install + upgrade pings.
        let os = telemetry_os();
        assert!(matches!(os, "Linux" | "Darwin") || !os.is_empty());
        #[cfg(target_os = "linux")]
        assert_eq!(os, "Linux");
        #[cfg(target_os = "macos")]
        assert_eq!(os, "Darwin");
    }

    fn test_cli(dir: &TempDir, dry_run: bool) -> Cli {
        let agent_path = dir.path().join("agent.toml");
        std::fs::write(&agent_path, "").unwrap();
        Cli {
            sensor_config: dir.path().join("config.toml"),
            agent_config: agent_path,
            data_dir: dir.path().to_path_buf(),
            dry_run,
            command: None,
        }
    }

    fn release(tag_name: &str, assets: Vec<GithubAsset>) -> GithubRelease {
        GithubRelease {
            tag_name: tag_name.to_string(),
            html_url: "https://github.com/InnerWarden/innerwarden/releases/tag/test".to_string(),
            assets,
            published_at: Some("2026-04-17T12:34:56Z".to_string()),
            body: Some("release notes".to_string()),
            prerelease: Some(false),
        }
    }

    fn canary_release(tag_name: &str, assets: Vec<GithubAsset>) -> GithubRelease {
        let mut r = release(tag_name, assets);
        r.prerelease = Some(true);
        r
    }

    fn asset(name: impl Into<String>, size: u64) -> GithubAsset {
        let name = name.into();
        GithubAsset {
            browser_download_url: format!("https://example.com/{name}"),
            name,
            size,
        }
    }

    fn asset_with_url(name: impl Into<String>, url: String, size: u64) -> GithubAsset {
        GithubAsset {
            name: name.into(),
            browser_download_url: url,
            size,
        }
    }

    fn local_http_server(responses: Vec<String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for body in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 1024];
                let _ = stream.read(&mut request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        format!("http://{addr}")
    }

    fn matching_assets_with_sidecars(arch: &str) -> Vec<GithubAsset> {
        let mut assets = Vec::new();
        for binary in ["innerwarden-sensor", "innerwarden-agent", "innerwarden-ctl"] {
            let base = format!("{binary}-linux-{arch}");
            assets.push(asset(&base, 10_000));
            assets.push(asset(format!("{base}.sha256"), 65));
            assets.push(asset(format!("{base}.sig"), 88));
        }
        assets
    }

    fn matching_assets_without_sidecars(arch: &str) -> Vec<GithubAsset> {
        ["innerwarden-sensor", "innerwarden-agent", "innerwarden-ctl"]
            .into_iter()
            .map(|binary| asset(format!("{binary}-linux-{arch}"), 10_000))
            .collect()
    }

    fn write_release_fixture(dir: &TempDir, tag_name: &str) -> std::path::PathBuf {
        let path = dir.path().join("latest-release.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "tag_name": tag_name,
                "html_url": "https://github.com/InnerWarden/innerwarden/releases/tag/test",
                "assets": [],
                "published_at": "2026-04-17T12:34:56Z",
                "body": "release notes"
            })
            .to_string(),
        )
        .unwrap();
        path
    }

    fn with_latest_release_fixture<T>(path: &Path, f: impl FnOnce() -> T) -> T {
        static RELEASE_FIXTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = RELEASE_FIXTURE_LOCK.lock().unwrap();
        let prior = std::env::var_os("INNERWARDEN_TEST_LATEST_RELEASE_JSON");
        std::env::set_var("INNERWARDEN_TEST_LATEST_RELEASE_JSON", path);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        match prior {
            Some(value) => std::env::set_var("INNERWARDEN_TEST_LATEST_RELEASE_JSON", value),
            None => std::env::remove_var("INNERWARDEN_TEST_LATEST_RELEASE_JSON"),
        }
        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[test]
    fn release_date_formatters_render_expected_shapes() {
        // Ensures release date decorations remain stable for summary and success output lines.
        assert_eq!(release_date_suffix(Some("2026-04-17")), "  [2026-04-17]");
        assert_eq!(release_date_display(Some("2026-04-17")), " (2026-04-17)");
        assert_eq!(release_date_suffix(None), "");
        assert_eq!(release_date_display(None), "");
    }

    #[test]
    fn telegram_notification_ready_requires_both_values() {
        // Covers notify precondition gating so partial credentials do not trigger outbound requests.
        assert!(telegram_notification_ready("token", "chat"));
        assert!(!telegram_notification_ready("", "chat"));
        assert!(!telegram_notification_ready("token", ""));
    }

    #[test]
    fn changelog_snippet_truncates_to_limit() {
        // Verifies changelog extraction keeps deterministic maximum length for Telegram notifications.
        let body = "abcdef";
        assert_eq!(changelog_snippet(Some(body), 3), "abc");
        assert_eq!(changelog_snippet(Some(body), 10), "abcdef");
    }

    #[test]
    fn changelog_snippet_handles_missing_body() {
        // Protects optional-release-body path used when GitHub release notes are empty.
        assert_eq!(changelog_snippet(None, 500), "");
    }

    #[test]
    fn render_upgrade_notification_includes_core_fields() {
        // Ensures notification text preserves key fields and upgrade command guidance.
        let text = render_upgrade_notification("0.12.0", "0.11.0", "  [2026-04-17]", "notes");
        assert!(text.contains("Inner Warden 0.12.0 available"));
        assert!(text.contains("Current: 0.11.0"));
        assert!(text.contains("New: 0.12.0  [2026-04-17]"));
        assert!(text.contains("innerwarden upgrade --yes"));
    }

    #[test]
    fn confirmation_accepted_matches_cli_prompt_behavior() {
        // Guards confirmation parser so Enter/y/yes continue and other values abort.
        assert!(confirmation_accepted(""));
        assert!(confirmation_accepted("y"));
        assert!(confirmation_accepted("YES"));
        assert!(!confirmation_accepted("n"));
        assert!(!confirmation_accepted("later"));
    }

    #[test]
    fn classify_service_action_covers_all_runtime_states() {
        // Ensures restart loop keeps the same branch decisions for active, installed, and missing units.
        assert_eq!(classify_service_action(true, true), ServiceAction::Restart);
        assert_eq!(classify_service_action(false, true), ServiceAction::Start);
        assert_eq!(classify_service_action(false, false), ServiceAction::Skip);
    }

    #[test]
    fn cmd_upgrade_fetches_release_and_delegates_to_upgrade_flow() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);
        let fixture = write_release_fixture(&dir, &format!("v{CURRENT_VERSION}"));

        with_latest_release_fixture(&fixture, || {
            cmd_upgrade(&cli, false, true, false, dir.path(), false, false).unwrap();
        });
    }

    #[test]
    fn cmd_upgrade_with_release_returns_ok_when_already_current() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);

        cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            release(CURRENT_VERSION, Vec::new()),
            false, // allow_unsigned_stable
            false, // allow_unsigned_canary
        )
        .unwrap();
    }

    #[test]
    fn cmd_upgrade_with_release_check_only_skips_asset_validation() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);

        cmd_upgrade_with_release(
            &cli,
            true,
            true,
            false,
            dir.path(),
            release("v999.0.0", Vec::new()),
            false,
            false,
        )
        .unwrap();
    }

    #[test]
    fn cmd_upgrade_with_release_notify_without_credentials_skips_send() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);
        let env_file = cli.agent_config.parent().unwrap().join("agent.env");
        std::fs::write(
            &env_file,
            "TELEGRAM_BOT_TOKEN=\"\"\nTELEGRAM_CHAT_ID=\"\"\n",
        )
        .unwrap();

        cmd_upgrade_with_release(
            &cli,
            true,
            true,
            true,
            dir.path(),
            release("v999.0.0", Vec::new()),
            false,
            false,
        )
        .unwrap();
    }

    #[test]
    fn cmd_upgrade_with_release_errors_when_no_matching_assets_exist() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);
        let err = cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            release("v999.0.0", vec![asset("innerwarden-ctl-linux-riscv64", 10)]),
            false,
            false,
        )
        .unwrap_err();

        assert!(err.to_string().contains("no assets found"));
    }

    #[test]
    fn cmd_upgrade_with_release_dry_run_renders_assets_with_sidecars() {
        let Some(arch) = detect_arch() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);

        cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            release("v999.0.0", matching_assets_with_sidecars(arch)),
            false,
            false,
        )
        .unwrap();
    }

    // ── Spec 048 — fail-closed signature policy anchors ──
    //
    // Pre-Spec-048 the updater warned-and-continued when a stable
    // release shipped without `.sig` files. That was the policy gap
    // that let "the website says signed but the installer doesn't
    // verify" persist. Anchors below pin the new fail-closed contract.

    /// Spec 048 anchor #6 — Inv. 1 (stable release without sig MUST
    /// fail). The fixture release has the binary asset but no `.sig`
    /// sidecar; the updater MUST refuse to install. The current
    /// architecture matters: pre-Spec-048 the same fixture printed a
    /// warning and proceeded. `test_cli(&dir, false)` disables
    /// dry_run so the sig-gate code path actually runs (dry_run
    /// would short-circuit upstream).
    #[test]
    fn update_fails_closed_when_stable_release_has_no_sig() {
        let Some(arch) = detect_arch() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);
        // Build assets with binary ONLY — no .sha256, no .sig. The
        // sig gate runs AFTER the SHA gate, so omitting .sha256 lets
        // us reach the sig branch under test without forging a SHA.
        let url = local_http_server(vec!["binary-content".to_string()]);
        let assets_with_url = vec![asset_with_url(
            format!("innerwarden-ctl-linux-{arch}"),
            format!("{url}/bin"),
            14,
        )];
        let err = cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            release("v999.0.0", assets_with_url),
            false, // allow_unsigned_stable: NO override
            false,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no .sig") || msg.contains("refusing to install"),
            "stable release without .sig must error before install — got: {msg}"
        );
    }

    /// Spec 048 anchor #7 — escape hatch (emergency override).
    /// `--allow-unsigned-stable` exists for migration / air-gapped
    /// builds. It MUST allow install but emit a noisy warn block.
    /// We can only assert the gate runs (full install path requires
    /// /usr/local/bin permissions); the precondition is that no
    /// "no .sig" anyhow::bail fires. Dry_run OFF so the sig-gate
    /// path runs.
    #[test]
    fn update_with_allow_unsigned_stable_flag_proceeds_past_sig_gate() {
        let Some(arch) = detect_arch() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);
        // Binary only — flag is true so the override is exercised.
        let url = local_http_server(vec!["binary-content".to_string()]);
        let assets = vec![asset_with_url(
            format!("innerwarden-ctl-linux-{arch}"),
            format!("{url}/bin"),
            14,
        )];
        // The full install will fail downstream (write to /usr/local/bin
        // without root) but we only care that the sig gate passed.
        let err = cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            release("v999.0.0", assets),
            true, // allow_unsigned_stable: override ON
            false,
        )
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
        assert!(
            !err.contains("no .sig") && !err.contains("refusing to install"),
            "with --allow-unsigned-stable, the sig gate must NOT abort. \
             Other downstream errors (sha mismatch, install perms) are \
             allowed. Got: {err}"
        );
    }

    /// Spec 048 anchor #8 — Inv. 6 (canary without flag aborts).
    /// Canary releases ship without `.sig` today; until canary
    /// signing infrastructure lands, the operator MUST opt in via
    /// `--allow-unsigned-canary` to install one. Dry_run OFF so the
    /// sig-gate path runs.
    #[test]
    fn update_canary_without_allow_unsigned_canary_aborts() {
        let Some(arch) = detect_arch() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);
        // Binary only (no .sha256, no .sig) — sig gate runs after
        // SHA gate, so omitting .sha256 reaches the sig branch under
        // test without forging a SHA.
        let url = local_http_server(vec!["binary-content".to_string()]);
        let assets = vec![asset_with_url(
            format!("innerwarden-ctl-linux-{arch}"),
            format!("{url}/bin"),
            14,
        )];
        let err = cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            canary_release("v999.0.0-canary", assets),
            false,
            false, // allow_unsigned_canary OFF
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("canary release") && msg.contains("--allow-unsigned-canary"),
            "canary without --allow-unsigned-canary must error with the \
             specific guidance message — got: {msg}"
        );
    }

    #[test]
    fn cmd_upgrade_with_release_dry_run_allows_assets_without_sidecars() {
        let Some(arch) = detect_arch() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);

        cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            release("v999.0.0", matching_assets_without_sidecars(arch)),
            true, // pre-spec-048 fixture has no .sig — needs override to assert prior
            // happy-path semantics (download path completes; sig gate bypassed)
            false,
        )
        .unwrap();
    }

    #[test]
    fn cmd_upgrade_with_release_rejects_checksum_mismatch_before_install() {
        let Some(arch) = detect_arch() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);
        let base_url = local_http_server(vec![
            "downloaded-binary".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ]);
        let binary_name = format!("innerwarden-ctl-linux-{arch}");
        let assets = vec![
            asset_with_url(&binary_name, format!("{base_url}/bin"), 17),
            asset_with_url(
                format!("{binary_name}.sha256"),
                format!("{base_url}/sha"),
                65,
            ),
        ];

        let err = cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            dir.path(),
            release("v999.0.0", assets),
            true, // sig override: this test asserts the SHA mismatch error fires
            // FIRST (before sig gate would even run)
            false,
        )
        .unwrap_err();

        assert!(err.to_string().contains("SHA-256 mismatch"));
    }

    #[test]
    fn cmd_upgrade_with_release_surfaces_install_failure_after_download() {
        let Some(arch) = detect_arch() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);
        let base_url = local_http_server(vec!["downloaded-binary".to_string()]);
        let binary_name = format!("innerwarden-ctl-linux-{arch}");
        let assets = vec![asset_with_url(&binary_name, format!("{base_url}/bin"), 17)];

        let err = cmd_upgrade_with_release(
            &cli,
            false,
            true,
            false,
            &dir.path().join("missing-install-dir"),
            release("v999.0.0", assets),
            true, // sig override: this test asserts the install-failure
            // error path; sig gate is upstream and not under test here
            false,
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("install failed")
                || err.to_string().contains("failed to run install command")
        );
    }

    #[test]
    fn fix_config_dir_permissions_ignores_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        fix_config_dir_permissions(&dir.path().join("missing"));
    }

    #[test]
    fn fix_config_dir_permissions_visits_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("agent.toml");
        std::fs::write(&file, "[agent]\n").unwrap();

        fix_config_dir_permissions(dir.path());

        assert!(file.exists());
    }
}
