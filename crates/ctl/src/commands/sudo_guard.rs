//! `innerwarden __sudo-suspend` / `__sudo-restore` — privileged helper
//! subcommands for the agent's `suspend-user-sudo` response.
//!
//! These are hidden (`#[clap(hide = true)]`) and meant to be invoked ONLY via a
//! tightly-scoped sudoers grant:
//!
//! ```text
//! innerwarden ALL=(ALL) NOPASSWD: \
//!   /usr/local/bin/innerwarden __sudo-suspend --user *, \
//!   /usr/local/bin/innerwarden __sudo-restore --user *
//! ```
//!
//! The whole point is that this grant carries **no arbitrary-content
//! primitive**. Unlike the old `sudo install <a /tmp file> → /etc/sudoers.d/…`
//! grant — where the caller controlled the *content* written into sudoers.d and
//! could therefore install a `NOPASSWD: ALL` rule for full root — the only
//! attacker-influenced input here is a username, and the only content this can
//! ever write is a hard-coded *deny-all* rule. Root itself is refused, so the
//! worst a compromised caller can do is deny sudo to some non-root user, which
//! is fail-safe.
//!
//! The filename and rule body come from [`innerwarden_core::sudo_guard`] so the
//! root helper and the unprivileged agent never disagree about what was written.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use innerwarden_core::sudo_guard::{
    is_valid_username, render_sudo_deny_rule, sanitize_sudoers_filename_segment, DENY_FILE_DIR,
    DENY_FILE_PREFIX,
};

/// Guard: refuse to touch root's sudo. Suspending root is either a self-DoS or
/// an attacker locking out the real administrator; and root does not need sudo
/// to be root, so denying it buys no security. Also rejects invalid usernames
/// before they reach a filename or `visudo`.
fn validate_target(user: &str) -> Result<()> {
    if !is_valid_username(user) {
        bail!("invalid username '{user}'");
    }
    if user == "root" {
        bail!("refusing to suspend sudo for 'root'");
    }
    Ok(())
}

/// Pure predicate (testable without being root): euid 0 is root.
fn is_effective_root(euid: u32) -> bool {
    euid == 0
}

/// Refuse to run unless we are actually root (euid 0). Invoked via the sudoers
/// grant we always are; a direct call by the unprivileged agent would fail on
/// the sudoers.d write anyway — this just turns that into a clear message.
fn require_root() -> Result<()> {
    // geteuid is always available and infallible on Linux/macOS.
    extern "C" {
        fn geteuid() -> u32;
    }
    if !is_effective_root(unsafe { geteuid() }) {
        bail!("__sudo-suspend/__sudo-restore must run as root (via the sudoers grant)");
    }
    Ok(())
}

/// Absolute deny-file path for `user` under `dir`. The real call passes
/// [`DENY_FILE_DIR`]; tests pass a tempdir. The filename segment is sanitized
/// (via `core::sudo_guard`) so sudo's includedir does not silently skip it.
fn deny_file_in(dir: &Path, user: &str) -> PathBuf {
    dir.join(format!(
        "{DENY_FILE_PREFIX}{}",
        sanitize_sudoers_filename_segment(user)
    ))
}

/// Validate a candidate sudoers file with `visudo -cf`. Extracted as the real
/// validator injected into [`install_deny_dropin`]; tests inject a stub so the
/// fs/rename/permission logic is exercised without visudo or root.
fn visudo_validate(path: &Path) -> Result<()> {
    let out = std::process::Command::new("visudo")
        .arg("-cf")
        .arg(path)
        .output()
        .with_context(|| "failed to run visudo (is it installed?)")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("generated sudoers rule failed visudo validation: {stderr}");
    }
    Ok(())
}

/// Generate + atomically install the deny-all drop-in for `user` into `dir`,
/// running `validate` on the candidate before it can be loaded. Split out of
/// [`cmd_sudo_suspend`] so the write / validate / chmod / rename logic is
/// unit-testable against a tempdir with a stub validator (the root check and
/// visudo are the only parts that need a live root/host). Returns the installed
/// path.
fn install_deny_dropin(
    dir: &Path,
    user: &str,
    expires_at: DateTime<Utc>,
    validate: impl Fn(&Path) -> Result<()>,
) -> Result<String> {
    let deny_path = deny_file_in(dir, user);
    let rule = render_sudo_deny_rule(user, expires_at);

    // Write to a temp IN the same directory so the final rename is atomic (same
    // filesystem). The temp name contains a `.`, which sudo's includedir
    // silently skips — so even mid-write the partial file is never loaded.
    let file_name = deny_path
        .file_name()
        .and_then(|s| s.to_str())
        .context("deny file has no name")?;
    let tmp_path = dir.join(format!(".{file_name}.tmp"));

    write_root_only(&tmp_path, &rule)
        .with_context(|| format!("write temp sudoers rule {}", tmp_path.display()))?;

    // Validate BEFORE it can ever be loaded; on failure leave nothing behind.
    if let Err(e) = validate(&tmp_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // 0440 root:root — the caller is already root, so ownership is correct.
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o440))
        .with_context(|| format!("chmod 0440 {}", tmp_path.display()))?;

    if let Err(e) = std::fs::rename(&tmp_path, &deny_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e)
            .with_context(|| format!("install sudoers deny rule to {}", deny_path.display()));
    }

    Ok(deny_path.to_string_lossy().into_owned())
}

/// Remove the deny drop-in for `user` under `dir` (idempotent — Ok if gone).
/// Split out of [`cmd_sudo_restore`] for the same testability reason.
fn remove_deny_dropin(dir: &Path, user: &str) -> Result<String> {
    let deny_path = deny_file_in(dir, user);
    match std::fs::remove_file(&deny_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e)
                .with_context(|| format!("remove sudoers deny rule {}", deny_path.display()))
        }
    }
    Ok(deny_path.to_string_lossy().into_owned())
}

/// Validate + parse + install, parameterised by `dir` and the sudoers
/// `validate` fn so the whole suspend orchestration is unit-testable against a
/// tempdir + stub validator (the real call passes DENY_FILE_DIR + visudo). The
/// root check stays in the thin `cmd_sudo_suspend` wrapper.
fn suspend_impl(
    dir: &Path,
    user: &str,
    expires: &str,
    validate: impl Fn(&Path) -> Result<()>,
) -> Result<String> {
    validate_target(user)?;
    let expires_at: DateTime<Utc> = expires
        .parse()
        .with_context(|| format!("parse --expires '{expires}' as an RFC 3339 timestamp"))?;
    install_deny_dropin(dir, user, expires_at, validate)
}

/// Validate + remove, parameterised by `dir` for the same testability reason.
fn restore_impl(dir: &Path, user: &str) -> Result<String> {
    validate_target(user)?;
    remove_deny_dropin(dir, user)
}

/// `innerwarden __sudo-suspend --user <u> --expires <rfc3339>`
///
/// Generate and atomically install a deny-all drop-in for `user`, validating it
/// with `visudo -cf` before it goes live. Prints the installed path on success.
pub(crate) fn cmd_sudo_suspend(user: &str, expires: &str) -> Result<()> {
    require_root()?;
    let installed = suspend_impl(Path::new(DENY_FILE_DIR), user, expires, visudo_validate)?;
    println!("{installed}");
    Ok(())
}

/// `innerwarden __sudo-restore --user <u>`
///
/// Remove the deny drop-in for `user` (idempotent — succeeds if already gone).
pub(crate) fn cmd_sudo_restore(user: &str) -> Result<()> {
    require_root()?;
    let removed = restore_impl(Path::new(DENY_FILE_DIR), user)?;
    println!("{removed}");
    Ok(())
}

/// Create/truncate `path` with mode 0600 and write `content`. The final mode is
/// set to 0440 by the caller after validation; 0600 during the write window
/// keeps the temp unreadable to non-root.
fn write_root_only(path: &Path, content: &str) -> Result<()> {
    use std::fs::OpenOptions;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(content.as_bytes())?;
    f.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_target_rejects_root_and_bad_names() {
        assert!(validate_target("root").is_err());
        assert!(validate_target("a b").is_err());
        assert!(validate_target("../x").is_err());
        assert!(validate_target("").is_err());
    }

    #[test]
    fn validate_target_accepts_normal_users() {
        assert!(validate_target("deploy").is_ok());
        assert!(validate_target("john.doe").is_ok());
        assert!(validate_target("svc-web_1").is_ok());
    }

    #[test]
    fn suspend_rejects_bad_expires_without_touching_fs() {
        // root check happens first; on a non-root test runner this returns the
        // require_root error before any parse. Either way it must be Err and
        // must not create a file.
        let r = cmd_sudo_suspend("deploy", "not-a-timestamp");
        assert!(r.is_err());
    }

    #[test]
    fn write_root_only_sets_0600_and_writes_content() {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("x");
        write_root_only(&p, "hello").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "hello");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn deny_file_in_sanitizes_and_joins_dir() {
        let p = deny_file_in(Path::new("/etc/sudoers.d"), "john.doe");
        assert_eq!(
            p,
            PathBuf::from("/etc/sudoers.d/zz-innerwarden-deny-john_doe")
        );
    }

    fn ts() -> DateTime<Utc> {
        "2026-07-03T00:00:00Z".parse().unwrap()
    }

    #[test]
    fn install_deny_dropin_writes_deny_rule_0440_and_clears_temp() {
        let td = tempfile::tempdir().unwrap();
        let installed = install_deny_dropin(td.path(), "deploy", ts(), |_| Ok(())).unwrap();
        let path = PathBuf::from(&installed);

        // The installed file is the deny-all rule, mode 0440, in the tempdir.
        assert_eq!(path, td.path().join("zz-innerwarden-deny-deploy"));
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("deploy ALL=(ALL:ALL) !ALL"));
        assert!(body.contains("# expires_at="));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o440);

        // No temp left behind.
        assert!(!td.path().join(".zz-innerwarden-deny-deploy.tmp").exists());
    }

    #[test]
    fn install_deny_dropin_sanitizes_filename_for_dotted_user() {
        let td = tempfile::tempdir().unwrap();
        let installed = install_deny_dropin(td.path(), "john.doe", ts(), |_| Ok(())).unwrap();
        // Filename sanitized (`.`→`_`) so sudo's includedir loads it; the rule
        // body keeps the real username.
        assert!(installed.ends_with("zz-innerwarden-deny-john_doe"));
        let body = std::fs::read_to_string(&installed).unwrap();
        assert!(body.contains("john.doe ALL=(ALL:ALL) !ALL"));
    }

    #[test]
    fn install_deny_dropin_failed_validation_leaves_nothing() {
        let td = tempfile::tempdir().unwrap();
        let err =
            install_deny_dropin(td.path(), "deploy", ts(), |_| bail!("bad rule")).unwrap_err();
        assert!(format!("{err:#}").contains("bad rule"));
        // Neither the final file nor the temp survives a rejected validation.
        assert!(!td.path().join("zz-innerwarden-deny-deploy").exists());
        assert!(!td.path().join(".zz-innerwarden-deny-deploy.tmp").exists());
    }

    #[test]
    fn remove_deny_dropin_removes_then_is_idempotent() {
        let td = tempfile::tempdir().unwrap();
        install_deny_dropin(td.path(), "deploy", ts(), |_| Ok(())).unwrap();
        let target = td.path().join("zz-innerwarden-deny-deploy");
        assert!(target.exists());

        // First remove deletes it; second is a no-op (still Ok).
        remove_deny_dropin(td.path(), "deploy").unwrap();
        assert!(!target.exists());
        remove_deny_dropin(td.path(), "deploy").unwrap();
    }

    #[test]
    fn visudo_validate_rejects_a_syntactically_invalid_rule() {
        // Real visudo on the test host: a bare non-rule must fail validation.
        // Skips cleanly if visudo is unavailable (e.g. minimal CI image).
        let td = tempfile::tempdir().unwrap();
        let bad = td.path().join("bad");
        std::fs::write(&bad, "this is not a sudoers rule\n").unwrap();
        match std::process::Command::new("visudo").arg("-V").output() {
            Ok(_) => assert!(visudo_validate(&bad).is_err()),
            Err(_) => { /* visudo not installed here; nothing to assert */ }
        }
    }

    #[test]
    fn is_effective_root_only_true_for_uid_0() {
        assert!(is_effective_root(0));
        assert!(!is_effective_root(1000));
        assert!(!is_effective_root(1));
    }

    #[test]
    fn suspend_impl_installs_deny_rule_for_valid_input() {
        // The suspend orchestration (validate -> parse -> install) runs without
        // root against a tempdir + stub validator.
        let td = tempfile::tempdir().unwrap();
        let installed =
            suspend_impl(td.path(), "deploy", "2026-07-03T00:00:00Z", |_| Ok(())).unwrap();
        assert_eq!(
            installed,
            td.path()
                .join("zz-innerwarden-deny-deploy")
                .to_string_lossy()
        );
        let body = std::fs::read_to_string(&installed).unwrap();
        assert!(body.contains("deploy ALL=(ALL:ALL) !ALL"));
    }

    #[test]
    fn suspend_impl_rejects_bad_expires_and_root() {
        let td = tempfile::tempdir().unwrap();
        // Bad timestamp -> parse error, no file written.
        assert!(suspend_impl(td.path(), "deploy", "not-a-ts", |_| Ok(())).is_err());
        assert!(!td.path().join("zz-innerwarden-deny-deploy").exists());
        // root refused before anything.
        assert!(suspend_impl(td.path(), "root", "2026-07-03T00:00:00Z", |_| Ok(())).is_err());
        // Invalid username refused.
        assert!(suspend_impl(td.path(), "a b", "2026-07-03T00:00:00Z", |_| Ok(())).is_err());
    }

    #[test]
    fn restore_impl_removes_and_refuses_root() {
        let td = tempfile::tempdir().unwrap();
        suspend_impl(td.path(), "deploy", "2026-07-03T00:00:00Z", |_| Ok(())).unwrap();
        // restore_impl removes the drop-in for a valid user, idempotently.
        restore_impl(td.path(), "deploy").unwrap();
        assert!(!td.path().join("zz-innerwarden-deny-deploy").exists());
        restore_impl(td.path(), "deploy").unwrap();
        // root refused.
        assert!(restore_impl(td.path(), "root").is_err());
    }
}
