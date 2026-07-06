use std::future::Future;
use std::path::Path;
use std::pin::Pin;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use innerwarden_core::sudo_guard::{deny_file_path, is_valid_username};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

const DEFAULT_TTL_SECS: u64 = 1800;
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 86_400;

pub struct SuspendUserSudo;

#[derive(Debug, Serialize, Deserialize)]
struct SuspensionMetadata {
    user: String,
    deny_file: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    reason: String,
}

impl ResponseSkill for SuspendUserSudo {
    fn id(&self) -> &'static str {
        "suspend-user-sudo"
    }

    fn name(&self) -> &'static str {
        "Suspend User Sudo"
    }

    fn description(&self) -> &'static str {
        "Temporarily denies all sudo commands for a user by writing a sudoers drop-in rule with TTL metadata."
    }

    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }

    fn applicable_to(&self) -> &'static [&'static str] {
        &["sudo_abuse"]
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let Some(user) = ctx.target_user.clone() else {
                return SkillResult {
                    success: false,
                    message: "suspend-user-sudo: no target user in context".to_string(),
                };
            };

            if !is_valid_username(&user) {
                return SkillResult {
                    success: false,
                    message: format!("suspend-user-sudo: invalid username '{user}'"),
                };
            }

            let ttl_secs = ctx
                .duration_secs
                .unwrap_or(DEFAULT_TTL_SECS)
                .clamp(MIN_TTL_SECS, MAX_TTL_SECS);
            let created_at = Utc::now();
            let expires_at = created_at + Duration::seconds(ttl_secs as i64);
            // The on-disk deny-file path is derived once, canonically, in
            // `innerwarden_core::sudo_guard::deny_file_path` — the same helper
            // the privileged `__sudo-suspend` subcommand uses — so what the
            // agent records in metadata can never diverge from what the root
            // helper actually writes. (It also sanitizes the `.`/`~` characters
            // sudo's includedir silently skips, so `john.doe` does not become a
            // no-op suspension.)
            let deny_file = deny_file_path(&user);

            if dry_run {
                info!(
                    user,
                    ttl_secs, deny_file, "DRY RUN: would suspend sudo for user"
                );
                return SkillResult {
                    success: true,
                    message: format!(
                        "DRY RUN: would suspend sudo for user {user} for {ttl_secs}s via {deny_file}"
                    ),
                };
            }

            // Delegate the privileged write to the hard-coded helper subcommand.
            // The narrow sudoers grant permits only
            // `innerwarden __sudo-suspend --user *` (and `__sudo-restore`), so a
            // compromised agent cannot install arbitrary sudoers content — the
            // binary generates a deny-all rule itself, validates it with visudo,
            // and refuses `root`. See `innerwarden_core::sudo_guard` and
            // `crates/ctl/src/commands/sudo_guard.rs`.
            let expires_rfc3339 = expires_at.to_rfc3339();
            let output = Command::new("sudo")
                .args([
                    "innerwarden",
                    "__sudo-suspend",
                    "--user",
                    &user,
                    "--expires",
                    &expires_rfc3339,
                ])
                .output()
                .await;
            let outcome = match output {
                Ok(out) if out.status.success() => SuspendOutcome::Ok,
                Ok(out) => {
                    SuspendOutcome::HelperFailed(String::from_utf8_lossy(&out.stderr).into_owned())
                }
                Err(e) => SuspendOutcome::SpawnError(e.to_string()),
            };

            finish_suspend(
                &ctx.data_dir,
                &user,
                ttl_secs,
                created_at,
                expires_at,
                &deny_file,
                &ctx.incident.summary,
                outcome,
            )
        })
    }
}

/// Outcome of invoking the `__sudo-suspend` helper — the seam that keeps
/// `finish_suspend`'s branch logic testable without spawning a real `sudo`.
enum SuspendOutcome {
    Ok,
    /// Helper ran but returned non-zero; carries its stderr.
    HelperFailed(String),
    /// The `sudo` process could not be spawned; carries the error text.
    SpawnError(String),
}

/// Given the helper outcome, write metadata on success and produce the
/// `SkillResult`. Split out of `execute` so the success / helper-error /
/// spawn-error branches + the metadata write are unit-testable without
/// spawning `sudo`.
#[allow(clippy::too_many_arguments)]
fn finish_suspend(
    data_dir: &Path,
    user: &str,
    ttl_secs: u64,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    deny_file: &str,
    reason: &str,
    outcome: SuspendOutcome,
) -> SkillResult {
    match outcome {
        SuspendOutcome::Ok => {}
        SuspendOutcome::HelperFailed(stderr) => {
            warn!(user, stderr = %stderr, "failed to suspend sudo via helper");
            return SkillResult {
                success: false,
                message: format!("failed to suspend sudo for {user}: {}", stderr.trim()),
            };
        }
        SuspendOutcome::SpawnError(e) => {
            warn!(user, error = %e, "failed to spawn __sudo-suspend helper");
            return SkillResult {
                success: false,
                message: format!("failed to suspend sudo for {user}: {e}"),
            };
        }
    }

    let meta = SuspensionMetadata {
        user: user.to_string(),
        deny_file: deny_file.to_string(),
        created_at,
        expires_at,
        reason: reason.to_string(),
    };
    if let Err(e) = write_metadata(data_dir, &meta) {
        warn!(user, error = %e, "failed to write suspension metadata");
    }

    info!(user, ttl_secs, deny_file, expires_at = %expires_at, "suspended sudo access for user");
    SkillResult {
        success: true,
        message: format!("Suspended sudo for user {user} for {ttl_secs}s (until {expires_at})"),
    }
}

pub async fn cleanup_expired_sudo_suspensions(data_dir: &Path, dry_run: bool) -> Result<usize> {
    let dir = metadata_dir(data_dir);
    if !dir.exists() {
        return Ok(0);
    }

    let mut removed = 0usize;
    let now = Utc::now();

    // Wave 3 (AUDIT-WAVE3-SYNC-IO): enumerate + parse + filter all
    // metadata files on the blocking thread pool, then iterate the
    // resulting plan in async land to run the sudo command. The
    // pre-fix loop did `std::fs::read_dir` + `std::fs::read_to_string`
    // + `std::fs::remove_file` directly inside an async fn, blocking
    // the tokio worker thread (each call could iterate hundreds of
    // entries and synchronously read each file - tens of ms per
    // tick under prod load). Pinned by
    // `cleanup_expired_sudo_offloads_io_to_blocking_pool`.
    let plan = list_expired_suspensions(&dir, now).await?;

    for ExpiredSuspension { path, meta } in plan {
        if dry_run {
            info!(
                user = %meta.user,
                deny_file = %meta.deny_file,
                "DRY RUN: would remove expired sudo suspension"
            );
            let _ = tokio::fs::remove_file(&path).await;
            removed += 1;
            continue;
        }

        let output = Command::new("sudo")
            .args(["innerwarden", "__sudo-restore", "--user", &meta.user])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let _ = tokio::fs::remove_file(&path).await;
                removed += 1;
                info!(user = %meta.user, "expired sudo suspension removed");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                warn!(
                    user = %meta.user,
                    deny_file = %meta.deny_file,
                    stderr = %stderr,
                    "failed to remove expired sudo suspension"
                );
            }
            Err(e) => {
                warn!(
                    user = %meta.user,
                    deny_file = %meta.deny_file,
                    error = %e,
                    "failed to spawn remove command for expired suspension"
                );
            }
        }
    }

    Ok(removed)
}

/// Wave 3 (AUDIT-WAVE3-SYNC-IO): metadata + filesystem path for one
/// expired suspension. Carried out of the blocking-pool enumeration
/// step so the async caller only does the (genuinely async) sudo
/// `rm -f` command + the per-entry tokio::fs cleanup.
struct ExpiredSuspension {
    path: std::path::PathBuf,
    meta: SuspensionMetadata,
}

/// Wave 3 (AUDIT-WAVE3-SYNC-IO): runs the synchronous read_dir +
/// per-file parse + expiry filter on the blocking thread pool so
/// the tokio worker does not stall while the agent walks tens-to-
/// hundreds of suspension records. Returns only the entries whose
/// `expires_at <= now`; corrupt JSON is logged + the file deleted
/// inline (still on the blocking pool, so still safe). Pinned by
/// the `cleanup_expired_sudo_*` anchor tests.
async fn list_expired_suspensions(
    dir: &Path,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<ExpiredSuspension>> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || enumerate_expired_suspensions_sync(&dir, now))
        .await
        .context("spawn_blocking for cleanup_expired_sudo enumeration")?
}

/// Wave 3 helper extracted for direct unit-testing without tokio.
/// Pure sync I/O over a directory of `*.json` suspension records.
fn enumerate_expired_suspensions_sync(
    dir: &Path,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<ExpiredSuspension>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
        let entry = match entry {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "failed to read suspension metadata entry");
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        let meta = match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<SuspensionMetadata>(&s).ok())
        {
            Some(v) => v,
            None => {
                warn!(path = %path.display(), "invalid suspension metadata; removing file");
                let _ = std::fs::remove_file(&path);
                continue;
            }
        };
        if meta.expires_at > now {
            continue;
        }
        out.push(ExpiredSuspension { path, meta });
    }
    Ok(out)
}

fn write_metadata(data_dir: &Path, meta: &SuspensionMetadata) -> Result<()> {
    let dir = metadata_dir(data_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create metadata dir {}", dir.display()))?;

    let path = dir.join(format!("{}.json", meta.user));
    let content = serde_json::to_string_pretty(meta)?;
    std::fs::write(&path, content)
        .with_context(|| format!("failed to write suspension metadata {}", path.display()))?;
    Ok(())
}

fn metadata_dir(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("sudo-suspensions")
}

// The username validation, filename sanitisation, and deny-rule rendering that
// used to live here are now the single source of truth in
// `innerwarden_core::sudo_guard` (shared with the privileged `__sudo-suspend`
// helper). Their unit tests live alongside them there.

#[cfg(test)]
mod tests {
    use super::*;

    // Filename-sanitisation and deny-rule rendering are now tested in
    // `innerwarden_core::sudo_guard`. The tests below cover this skill's own
    // behaviour: validation gating, TTL clamping, the sanitized filename
    // reaching the dry-run message, metadata persistence, and cleanup.

    fn skill_context(user: Option<&str>, duration_secs: Option<u64>) -> SkillContext {
        SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: Utc::now(),
                host: "host".to_string(),
                incident_id: "sudo_abuse:deploy:test".to_string(),
                severity: innerwarden_core::event::Severity::Critical,
                title: "sudo abuse".to_string(),
                summary: "suspicious sudo use".to_string(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: None,
            target_user: user.map(str::to_string),
            target_container: None,
            duration_secs,
            host: "host".to_string(),
            data_dir: std::env::temp_dir(),
            honeypot: crate::skills::HoneypotRuntimeConfig::default(),
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn dry_run_succeeds() {
        let ctx = skill_context(Some("deploy"), Some(600));

        let res = SuspendUserSudo.execute(&ctx, true).await;
        assert!(res.success);
        assert!(res.message.contains("DRY RUN"));
        assert!(res.message.contains("deploy"));
        assert!(res.message.contains("600s"));
    }

    #[tokio::test]
    async fn dry_run_clamps_ttl_and_uses_sanitized_filename() {
        let too_short = skill_context(Some("john.doe"), Some(1));
        let res = SuspendUserSudo.execute(&too_short, true).await;
        assert!(res.success);
        assert!(res.message.contains("60s"));
        assert!(res.message.contains("zz-innerwarden-deny-john_doe"));
        assert!(!res.message.contains("zz-innerwarden-deny-john.doe"));

        let too_long = skill_context(Some("deploy"), Some(MAX_TTL_SECS + 1));
        let res = SuspendUserSudo.execute(&too_long, true).await;
        assert!(res.success);
        assert!(res.message.contains("86400s"));
    }

    #[tokio::test]
    async fn execute_rejects_missing_or_invalid_user_before_sudo() {
        let missing = skill_context(None, Some(600));
        let res = SuspendUserSudo.execute(&missing, false).await;
        assert!(!res.success);
        assert!(res.message.contains("no target user"));

        let invalid = skill_context(Some("../etc/passwd"), Some(600));
        let res = SuspendUserSudo.execute(&invalid, false).await;
        assert!(!res.success);
        assert!(res.message.contains("invalid username"));
    }

    #[test]
    fn username_validation_is_strict() {
        assert!(is_valid_username("deploy"));
        assert!(is_valid_username("svc_user-1"));
        assert!(is_valid_username("john.doe"));
        assert!(is_valid_username("machine$"));
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("../etc/passwd"));
        assert!(!is_valid_username("bad user"));
        assert!(!is_valid_username("@bad"));
        assert!(!is_valid_username(&"a".repeat(65)));
    }

    #[test]
    fn finish_suspend_ok_writes_metadata_and_succeeds() {
        let td = tempfile::tempdir().expect("tempdir");
        let created = Utc::now();
        let expires = created + Duration::minutes(30);
        let res = finish_suspend(
            td.path(),
            "deploy",
            1800,
            created,
            expires,
            "/etc/sudoers.d/zz-innerwarden-deny-deploy",
            "suspicious sudo",
            SuspendOutcome::Ok,
        );
        assert!(res.success);
        assert!(res.message.contains("Suspended sudo for user deploy"));
        // Metadata persisted on the Ok path.
        let persisted = metadata_dir(td.path()).join("deploy.json");
        assert!(persisted.exists());
    }

    #[test]
    fn finish_suspend_helper_failure_reports_stderr_and_writes_no_metadata() {
        let td = tempfile::tempdir().expect("tempdir");
        let now = Utc::now();
        let res = finish_suspend(
            td.path(),
            "deploy",
            1800,
            now,
            now,
            "/etc/sudoers.d/zz-innerwarden-deny-deploy",
            "r",
            SuspendOutcome::HelperFailed("  visudo rejected\n".to_string()),
        );
        assert!(!res.success);
        assert!(res.message.contains("visudo rejected"));
        assert!(!metadata_dir(td.path()).join("deploy.json").exists());
    }

    #[test]
    fn finish_suspend_spawn_error_reports_error() {
        let td = tempfile::tempdir().expect("tempdir");
        let now = Utc::now();
        let res = finish_suspend(
            td.path(),
            "deploy",
            1800,
            now,
            now,
            "/etc/sudoers.d/zz-innerwarden-deny-deploy",
            "r",
            SuspendOutcome::SpawnError("No such file or directory".to_string()),
        );
        assert!(!res.success);
        assert!(res.message.contains("No such file or directory"));
        assert!(!metadata_dir(td.path()).join("deploy.json").exists());
    }

    #[test]
    fn write_metadata_persists_reason_and_paths() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let meta = SuspensionMetadata {
            user: "deploy".to_string(),
            deny_file: "/etc/sudoers.d/zz-innerwarden-deny-deploy".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(30),
            reason: "suspicious sudo use".to_string(),
        };

        write_metadata(data_dir.path(), &meta).expect("metadata write");
        let path = metadata_dir(data_dir.path()).join("deploy.json");
        let persisted: SuspensionMetadata =
            serde_json::from_str(&std::fs::read_to_string(path).expect("metadata should exist"))
                .expect("valid metadata json");
        assert_eq!(persisted.user, "deploy");
        assert_eq!(persisted.deny_file, meta.deny_file);
        assert_eq!(persisted.reason, "suspicious sudo use");
    }

    // ── Wave 3 anchors (AUDIT-WAVE3-SYNC-IO) ───────────────────────────
    //
    // The pre-fix `cleanup_expired_sudo_suspensions` did `std::fs::read_dir`
    // + per-file `std::fs::read_to_string` directly inside an async fn,
    // blocking the tokio worker thread for as long as the parse loop
    // took. The fix offloads enumeration to `spawn_blocking` and runs
    // the per-entry sudo command + tokio::fs::remove_file in async
    // land. The pure-sync helper `enumerate_expired_suspensions_sync`
    // is unit-tested here without a tokio runtime.

    fn write_meta_at(dir: &Path, user: &str, expires_at: chrono::DateTime<chrono::Utc>) {
        let meta = SuspensionMetadata {
            user: user.to_string(),
            deny_file: format!("/etc/sudoers.d/zz-innerwarden-deny-{user}"),
            created_at: chrono::Utc::now(),
            expires_at,
            reason: "test".into(),
        };
        let path = dir.join(format!("{user}.json"));
        std::fs::write(&path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
    }

    #[tokio::test]
    async fn cleanup_dry_run_removes_expired_metadata_without_sudo() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let dir = metadata_dir(data_dir.path());
        std::fs::create_dir_all(&dir).expect("metadata dir");
        let now = chrono::Utc::now();
        write_meta_at(&dir, "expired_one", now - chrono::Duration::seconds(1));
        write_meta_at(&dir, "fresh_one", now + chrono::Duration::hours(1));

        let removed = cleanup_expired_sudo_suspensions(data_dir.path(), true)
            .await
            .expect("dry-run cleanup");
        assert_eq!(removed, 1);
        assert!(!dir.join("expired_one.json").exists());
        assert!(dir.join("fresh_one.json").exists());
    }

    #[test]
    fn enumerate_expired_suspensions_returns_only_expired_entries() {
        // Mixed bag: one expired, one not, one corrupt JSON, one
        // non-`.json` file. Helper returns only the expired entry;
        // the corrupt file gets removed inline.
        let dir = tempfile::tempdir().expect("tempdir");
        let now = chrono::Utc::now();
        write_meta_at(
            dir.path(),
            "expired_user",
            now - chrono::Duration::seconds(60),
        );
        write_meta_at(dir.path(), "fresh_user", now + chrono::Duration::hours(1));
        std::fs::write(dir.path().join("corrupt.json"), "not json").unwrap();
        std::fs::write(dir.path().join("README.txt"), "ignore me").unwrap();

        let out = enumerate_expired_suspensions_sync(dir.path(), now)
            .expect("enumerate must succeed on a valid dir");
        assert_eq!(out.len(), 1, "exactly one expired entry");
        assert_eq!(out[0].meta.user, "expired_user");
        // Corrupt file was removed inline.
        assert!(
            !dir.path().join("corrupt.json").exists(),
            "corrupt JSON removed inline"
        );
        // Non-JSON file untouched.
        assert!(dir.path().join("README.txt").exists(), "non-json untouched");
        // Fresh entry retained.
        assert!(dir.path().join("fresh_user.json").exists());
    }

    #[test]
    fn enumerate_expired_suspensions_empty_dir_returns_empty_vec() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = enumerate_expired_suspensions_sync(dir.path(), chrono::Utc::now()).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn enumerate_expired_suspensions_missing_dir_errors_with_context() {
        let nope = std::path::Path::new("/var/empty/_innerwarden_no_such_dir_for_test");
        let result = enumerate_expired_suspensions_sync(nope, chrono::Utc::now());
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(format!("{err:#}").contains("read_dir"));
    }
}
