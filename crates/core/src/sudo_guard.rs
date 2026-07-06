//! Canonical helpers for the `suspend-user-sudo` response, shared by the agent
//! skill and the privileged `innerwarden __sudo-suspend` / `__sudo-restore`
//! helper subcommands.
//!
//! # Why this is one module
//!
//! Suspending a user's sudo means writing a root-owned drop-in under
//! `/etc/sudoers.d/`. The agent runs as the unprivileged `innerwarden` user, so
//! it cannot write there directly; it shells out through `sudo`. The **old**
//! design granted the innerwarden user `sudo install <a /tmp file> →
//! /etc/sudoers.d/…`, which is a privilege-escalation primitive: whoever
//! controls that `/tmp` file controls the *content* of a file in `sudoers.d`,
//! and can install `innerwarden ALL=(ALL) NOPASSWD: ALL` for full root.
//!
//! The fix is to never grant "install an arbitrary file into sudoers.d". The
//! privileged step is a dedicated, hard-coded helper subcommand
//! (`innerwarden __sudo-suspend --user <u> --expires <ts>`) that GENERATES the
//! drop-in itself — the only attacker-influenced input is a username, and the
//! only content it can ever write is a *deny-all* rule. The worst a compromised
//! caller can do through the narrowed grant is deny sudo to some user, which is
//! fail-safe, not escalation.
//!
//! For that to hold, "the filename/rule the agent believes it wrote" and "the
//! filename/rule the root helper actually wrote" must never diverge — so both
//! sides compute them here, once.

use chrono::{DateTime, Utc};

/// Directory sudo reads drop-ins from (`includedir`).
pub const DENY_FILE_DIR: &str = "/etc/sudoers.d";

/// Filename prefix for an Inner Warden sudo-deny drop-in. The `zz-` sorts it
/// last so it wins over any earlier grant for the same user, and it is the
/// stable token the narrowed `__sudo-restore` grant / cleanup match on.
pub const DENY_FILE_PREFIX: &str = "zz-innerwarden-deny-";

/// Validate a username before it is ever used to build a sudoers filename or
/// rule body. Conservative on purpose: a name that reaches a root-run helper
/// and a file under `/etc/sudoers.d/` must not carry shell metacharacters,
/// whitespace, or path separators.
///
/// Allows the real-world Linux username charset: first char alphanumeric / `_`
/// / `-`; remaining chars additionally `.` and `$` (trailing `$` machine
/// accounts, `john.doe`). Length 1..=64.
pub fn is_valid_username(user: &str) -> bool {
    if user.is_empty() || user.len() > 64 {
        return false;
    }

    let mut chars = user.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if !(first.is_ascii_alphanumeric() || first == '_' || first == '-') {
        return false;
    }

    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '$')
}

/// Replace characters that sudo's `includedir` silently skips (`.` and `~`,
/// per sudoers(5)) with `_`, so the resulting `/etc/sudoers.d/` filename is
/// actually loaded. The rule *body* still uses the real username so sudo
/// matches the right account; only the on-disk filename is mangled.
///
/// Real Linux usernames may legitimately contain `.` (e.g. `john.doe`), which
/// `is_valid_username` allows — without this, `zz-innerwarden-deny-john.doe`
/// would be silently ignored and the suspension would be a no-op.
pub fn sanitize_sudoers_filename_segment(s: &str) -> String {
    s.chars()
        .map(|c| if c == '.' || c == '~' { '_' } else { c })
        .collect()
}

/// Absolute path of the deny drop-in for `user` (filename segment sanitized).
///
/// The caller is expected to have validated `user` with [`is_valid_username`]
/// first; this function only sanitizes the *includedir-skip* characters, it is
/// not a substitute for validation.
pub fn deny_file_path(user: &str) -> String {
    format!(
        "{DENY_FILE_DIR}/{DENY_FILE_PREFIX}{}",
        sanitize_sudoers_filename_segment(user)
    )
}

/// The exact sudoers rule body written into the deny drop-in. `expires_at` is
/// recorded only as an informational comment — sudo does not enforce a TTL; the
/// agent's cleanup loop removes the file when it expires. The functional line
/// is the deny-all: `<user> ALL=(ALL:ALL) !ALL`.
pub fn render_sudo_deny_rule(user: &str, expires_at: DateTime<Utc>) -> String {
    format!(
        "# Managed by Inner Warden\n# user={user}\n# expires_at={expires_at}\n{user} ALL=(ALL:ALL) !ALL\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn valid_usernames_pass() {
        for u in ["root", "deploy", "john.doe", "svc-web", "user_1", "m$"] {
            assert!(is_valid_username(u), "{u} should be valid");
        }
    }

    #[test]
    fn invalid_usernames_rejected() {
        for u in [
            "",
            " ",
            "a b",
            "../etc",
            "a/b",
            "a;b",
            "a$(id)",
            "a`b`",
            ".hidden",
            &"x".repeat(65),
        ] {
            assert!(!is_valid_username(u), "{u:?} should be rejected");
        }
    }

    #[test]
    fn sanitize_replaces_includedir_skip_chars() {
        assert_eq!(sanitize_sudoers_filename_segment("john.doe"), "john_doe");
        assert_eq!(sanitize_sudoers_filename_segment("bak~"), "bak_");
        assert_eq!(sanitize_sudoers_filename_segment("a.b~c"), "a_b_c");
        // Safe chars pass through untouched.
        assert_eq!(sanitize_sudoers_filename_segment("svc-web_1"), "svc-web_1");
    }

    #[test]
    fn deny_file_path_is_sanitized_and_under_sudoers_d() {
        assert_eq!(
            deny_file_path("john.doe"),
            "/etc/sudoers.d/zz-innerwarden-deny-john_doe"
        );
        assert!(deny_file_path("deploy").starts_with("/etc/sudoers.d/zz-innerwarden-deny-"));
    }

    #[test]
    fn render_contains_metadata_and_deny_line() {
        let expires_at = Utc::now() + Duration::minutes(30);
        let rule = render_sudo_deny_rule("deploy", expires_at);
        assert!(rule.contains("# Managed by Inner Warden"));
        assert!(rule.contains("# user=deploy"));
        assert!(rule.contains(&format!("# expires_at={expires_at}")));
        assert!(rule.contains("deploy ALL=(ALL:ALL) !ALL"));
    }
}
