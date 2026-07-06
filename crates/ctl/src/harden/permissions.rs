use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn check_permissions(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Permissions";

    // World-writable files in sensitive dirs
    if let Some(raw) = env.command_stdout(
        "find",
        &["/etc", "-maxdepth", "2", "-perm", "-o+w", "-type", "f"],
    ) {
        let files: Vec<&str> = raw.trim().lines().collect();
        if files.is_empty() || (files.len() == 1 && files[0].is_empty()) {
            passed.push("No world-writable files in /etc".into());
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::High,
                title: format!("{} world-writable file(s) in /etc", files.len()),
                fix: format!(
                    "Review and fix: {}",
                    files.into_iter().take(3).collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }

    // SUID binaries outside standard set.
    //
    // 2026-05-25: extended for Ubuntu 26.04 LTS. Canonical adopted
    // sudo-rs (Rust reimplementation) as the default sudo via the
    // memory-safe userland initiative, with sudo-tradicional kept in
    // parallel via update-alternatives. The new layout introduces
    // four additional SUID paths that a clean install carries:
    //   /usr/bin/sudo.ws              — sudo 1.9.17 traditional
    //   /usr/lib/cargo/bin/su         — sudo-rs su
    //   /usr/lib/cargo/bin/sudo       — sudo-rs sudo (active)
    //   /usr/lib/mariadb/auth_pam_tool
    //   /usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool
    //                                  — mariadb-server PAM auth
    //
    // The static list is the fast path. A dpkg-query fallback below
    // (`is_owned_by_trusted_package`) catches paths a future distro
    // release renames again, so the operator does not have to chase
    // each Ubuntu LTS upgrade with a code change.
    let standard_suid = [
        "/usr/bin/sudo",
        "/usr/bin/sudo.ws",
        "/usr/bin/su",
        "/usr/bin/passwd",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/newgrp",
        "/usr/bin/gpasswd",
        "/usr/bin/mount",
        "/usr/bin/umount",
        "/usr/bin/fusermount",
        "/usr/bin/fusermount3",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/snapd/snap-confine",
        "/usr/bin/pkexec",
        "/usr/bin/at",
        "/usr/bin/crontab",
        // Ubuntu 26.04 sudo-rs layout
        "/usr/lib/cargo/bin/su",
        "/usr/lib/cargo/bin/sudo",
        "/usr/lib/cargo/bin/visudo",
        // MariaDB / MySQL PAM auth helpers
        "/usr/lib/mariadb/auth_pam_tool",
        "/usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool",
    ];
    if let Some(out) = env.command_stdout("find", &["/usr", "-perm", "-4000", "-type", "f"]) {
        let suids: Vec<String> = out
            .trim()
            .lines()
            .filter(|l| !l.is_empty())
            .filter(|l| !standard_suid.contains(l))
            .filter(|l| !is_owned_by_trusted_package(env, l))
            .map(String::from)
            .collect();
        if suids.is_empty() {
            passed.push("No unusual SUID binaries".into());
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: format!("{} non-standard SUID binary(ies)", suids.len()),
                fix: format!(
                    "Review if needed: {}",
                    suids.into_iter().take(5).collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }

    // /etc/shadow permissions
    if let Some(mode) = env.metadata_mode("/etc/shadow").map(|mode| mode & 0o777) {
        if mode <= 0o640 {
            passed.push(format!("/etc/shadow permissions: {:03o}", mode));
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Critical,
                title: format!("/etc/shadow too permissive: {:03o}", mode),
                fix: "Run: sudo chmod 640 /etc/shadow".into(),
            });
        }
    }

    // /etc/gshadow permissions
    if let Some(mode) = env.metadata_mode("/etc/gshadow").map(|mode| mode & 0o777) {
        if mode <= 0o640 {
            passed.push(format!("/etc/gshadow permissions: {:03o}", mode));
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::High,
                title: format!("/etc/gshadow too permissive: {:03o}", mode),
                fix: "Run: sudo chmod 640 /etc/gshadow".into(),
            });
        }
    }

    // /etc/sudoers permissions
    if let Some(mode) = env.metadata_mode("/etc/sudoers").map(|mode| mode & 0o777) {
        if mode <= 0o440 {
            passed.push(format!("/etc/sudoers permissions: {:03o}", mode));
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::High,
                title: format!("/etc/sudoers too permissive: {:03o}", mode),
                fix: "Run: sudo chmod 440 /etc/sudoers".into(),
            });
        }
    }

    // SSH directory permissions
    for home in ["/root", "/home"] {
        for entry in env.read_dir(home) {
            let ssh_dir = format!("{}/.ssh", entry.path);
            if env.path_exists(&ssh_dir) {
                if let Some(mode) = env.metadata_mode(&ssh_dir).map(|mode| mode & 0o777) {
                    if mode > 0o700 {
                        findings.push(Finding {
                            category: cat,
                            severity: Severity::High,
                            title: format!("{ssh_dir} too permissive: {mode:03o}"),
                            fix: format!("Run: sudo chmod 700 {ssh_dir}"),
                        });
                    }
                }
                let ak = format!("{ssh_dir}/authorized_keys");
                if let Some(mode) = env.metadata_mode(&ak).map(|mode| mode & 0o777) {
                    if mode > 0o600 {
                        findings.push(Finding {
                            category: cat,
                            severity: Severity::High,
                            title: format!("{ak} too permissive: {mode:03o}"),
                            fix: format!("Run: sudo chmod 600 {ak}"),
                        });
                    }
                }
            }
        }
    }

    // /tmp sticky bit
    if let Some(mode) = env.metadata_mode("/tmp") {
        if mode & 0o1000 != 0 {
            passed.push("/tmp has sticky bit set".into());
        } else {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: "/tmp missing sticky bit".into(),
                fix: "Run: sudo chmod +t /tmp".into(),
            });
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

/// Owning-package prefixes considered "trusted" for SUID binaries.
/// Matched with `starts_with` so version-suffixed package names
/// (`mariadb-server-10.11`) and arch-suffixed ones (`sudo:amd64`) from
/// `dpkg-query` output are absorbed without enumerating every variant.
///
/// 2026-05-25: introduced after a fresh Ubuntu 26.04 LTS install
/// produced 4 SUID false positives (sudo.ws / sudo-rs binaries /
/// mariadb's auth_pam_tool). The static `standard_suid` list above
/// is the fast path; this dpkg fallback survives the next distro
/// rename without requiring a code change.
const TRUSTED_OWNER_PREFIXES: &[&str] = &[
    "sudo",           // sudo, sudo-rs, sudo:amd64, sudo-ldap
    "mariadb-server", // mariadb-server, mariadb-server-10.11
    "mariadb-plugin",
    "mysql-server",
    "mysql-common",
    "postgresql-",
    "openssh", // openssh-client, openssh-server, openssh-sftp-server
    "policykit-1",
    "polkitd",
    "util-linux",
    "passwd", // the package, not the binary
    "login",
    "cron",
    "at",
    "fuse", // /usr/bin/fusermount(3) under fuse / fuse3
    "fuse3",
    "snapd", // /usr/lib/snapd/snap-confine
    "dbus",  // /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    "ntfs-3g",
    "bubblewrap", // /usr/bin/bwrap
    "uidmap",     // /usr/bin/newuidmap, newgidmap (rootless containers)
    // 2026-06-14: mount helpers that ship a SUID-root binary on a clean
    // install. Observed on an Azure host where cifs-utils' /usr/sbin/mount.cifs
    // raised a medium false positive — it is a packaged mount helper, not an
    // attacker-planted SUID (a planted binary would not be dpkg-owned).
    "cifs-utils",     // /usr/sbin/mount.cifs
    "ecryptfs-utils", // /usr/bin/mount.ecryptfs_private
];

/// Returns true when `dpkg-query -S` reports the path as owned by a
/// package whose name starts with any of [`TRUSTED_OWNER_PREFIXES`].
/// Returns false when dpkg is unavailable, when the file is unowned,
/// or when the owning package is not on the trusted list — so the
/// static whitelist above remains the primary gate; this fallback
/// only reduces false positives, never widens detection.
///
/// dpkg-query output shape:
///   "sudo: /usr/bin/sudo"             (no arch suffix)
///   "sudo:amd64: /usr/bin/sudo"       (arch suffix)
///   "mariadb-server-10.11: /usr/lib/mariadb/auth_pam_tool"
///
/// Splitting on the first ':' isolates the package name in every
/// case because arch suffixes always appear AFTER the package name
/// and BEFORE the path separator.
///
/// Queries both the given path AND its usrmerge alias. `find /usr -perm -4000`
/// reports canonical paths (`/usr/sbin/mount.cifs`), but some packages still
/// record the pre-merge alias in their dpkg file list (cifs-utils ships
/// `/sbin/mount.cifs`). Without the alias retry, the dpkg lookup misses and a
/// perfectly normal packaged SUID helper is reported as anomalous.
fn is_owned_by_trusted_package(env: &impl HardenEnv, path: &str) -> bool {
    if dpkg_owner_is_trusted(env, path) {
        return true;
    }
    if let Some(alias) = usrmerge_alias(path) {
        if dpkg_owner_is_trusted(env, &alias) {
            return true;
        }
    }
    false
}

/// Toggle the `/usr` prefix for usrmerge-aliased paths so a dpkg lookup
/// succeeds whether dpkg recorded the canonical (`/usr/sbin/x`) or the
/// pre-merge alias (`/sbin/x`). Returns `None` for paths outside the
/// merged directories (nothing to toggle).
fn usrmerge_alias(path: &str) -> Option<String> {
    const MERGED: [&str; 4] = ["/sbin/", "/bin/", "/lib/", "/lib64/"];
    if let Some(rest) = path.strip_prefix("/usr") {
        if MERGED.iter().any(|d| rest.starts_with(d)) {
            return Some(rest.to_string()); // /usr/sbin/x -> /sbin/x
        }
    }
    if MERGED.iter().any(|d| path.starts_with(d)) {
        return Some(format!("/usr{path}")); // /sbin/x -> /usr/sbin/x
    }
    None
}

/// Single-path dpkg ownership check against [`TRUSTED_OWNER_PREFIXES`].
fn dpkg_owner_is_trusted(env: &impl HardenEnv, path: &str) -> bool {
    let Some(raw) = env.command_stdout("dpkg-query", &["-S", path]) else {
        return false;
    };
    let line = raw.trim();
    if line.is_empty() {
        return false;
    }
    let Some((pkg, _)) = line.split_once(':') else {
        return false;
    };
    TRUSTED_OWNER_PREFIXES.iter().any(|p| pkg.starts_with(p))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harden::env::{DirEntry, HardenEnv};
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Mock HardenEnv that returns canned command output keyed by
    /// `(program, args_joined)` so each test pins exactly what
    /// `dpkg-query -S <path>` would have returned on a real host.
    struct MockEnv {
        outputs: RefCell<HashMap<String, Option<String>>>,
    }

    impl MockEnv {
        fn new() -> Self {
            Self {
                outputs: RefCell::new(HashMap::new()),
            }
        }
        fn with_dpkg(self, path: &str, output: Option<&str>) -> Self {
            let key = format!("dpkg-query -S {path}");
            self.outputs
                .borrow_mut()
                .insert(key, output.map(String::from));
            self
        }
    }

    impl HardenEnv for MockEnv {
        fn read_to_string(&self, _path: &str) -> Option<String> {
            None
        }
        fn read_bytes(&self, _path: &str) -> Option<Vec<u8>> {
            None
        }
        fn read_dir(&self, _path: &str) -> Vec<DirEntry> {
            Vec::new()
        }
        fn path_exists(&self, _path: &str) -> bool {
            false
        }
        fn metadata_mode(&self, _path: &str) -> Option<u32> {
            None
        }
        fn command_stdout(&self, program: &str, args: &[&str]) -> Option<String> {
            let key = format!("{program} {}", args.join(" "));
            self.outputs.borrow().get(&key).cloned().flatten()
        }
    }

    // ── 2026-05-25 anchors — Ubuntu 26.04 SUID FP fix ────────────────────

    #[test]
    fn trusted_owner_matches_sudo_rs_with_arch_suffix() {
        // The exact dpkg-query output the operator's Ubuntu 26.04 box
        // returned for the sudo-rs sudo binary. Pin that the arch
        // suffix (":amd64") is absorbed.
        let env = MockEnv::new().with_dpkg(
            "/usr/lib/cargo/bin/sudo",
            Some("sudo-rs:amd64: /usr/lib/cargo/bin/sudo"),
        );
        assert!(is_owned_by_trusted_package(&env, "/usr/lib/cargo/bin/sudo"));
    }

    #[test]
    fn trusted_owner_matches_mariadb_with_version_suffix() {
        // mariadb-server-10.11 is the version-suffixed package name on
        // Ubuntu 24.04. Pin that the version suffix is absorbed by
        // `starts_with("mariadb-server")`.
        let env = MockEnv::new().with_dpkg(
            "/usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool",
            Some("mariadb-server-10.11: /usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool"),
        );
        assert!(is_owned_by_trusted_package(
            &env,
            "/usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool"
        ));
    }

    #[test]
    fn trusted_owner_matches_sudo_ws_path() {
        // /usr/bin/sudo.ws is owned by the traditional `sudo` package
        // even though the binary name carries the `.ws` suffix from
        // update-alternatives. Pin that the package name (sudo) is
        // what gets matched, not the binary path.
        let env = MockEnv::new().with_dpkg("/usr/bin/sudo.ws", Some("sudo: /usr/bin/sudo.ws"));
        assert!(is_owned_by_trusted_package(&env, "/usr/bin/sudo.ws"));
    }

    #[test]
    fn trusted_owner_matches_cifs_utils_via_usrmerge_alias() {
        // 2026-06-14: the exact Azure repro. `find` reports the canonical
        // /usr/sbin/mount.cifs, but cifs-utils records /sbin/mount.cifs in its
        // dpkg file list, so a direct lookup on the canonical path MISSES.
        // The usrmerge-alias retry must still resolve it as trusted.
        let env = MockEnv::new()
            .with_dpkg("/usr/sbin/mount.cifs", None) // canonical: dpkg "no path found"
            .with_dpkg("/sbin/mount.cifs", Some("cifs-utils: /sbin/mount.cifs"));
        assert!(is_owned_by_trusted_package(&env, "/usr/sbin/mount.cifs"));
    }

    #[test]
    fn usrmerge_alias_toggles_usr_prefix_both_ways() {
        assert_eq!(usrmerge_alias("/usr/sbin/x").as_deref(), Some("/sbin/x"));
        assert_eq!(usrmerge_alias("/usr/bin/x").as_deref(), Some("/bin/x"));
        assert_eq!(usrmerge_alias("/sbin/x").as_deref(), Some("/usr/sbin/x"));
        assert_eq!(usrmerge_alias("/lib/x").as_deref(), Some("/usr/lib/x"));
        // Non-merged paths have no alias.
        assert_eq!(usrmerge_alias("/opt/x"), None);
        assert_eq!(usrmerge_alias("/usr/local/sbin/x"), None);
    }

    #[test]
    fn untrusted_owner_returns_false() {
        // Sanity: a package not in TRUSTED_OWNER_PREFIXES (e.g. a
        // hypothetical attacker-installed `weird-pkg`) must NOT
        // pass the fallback. The whole point is to narrow, not widen.
        let env = MockEnv::new().with_dpkg("/usr/bin/evil", Some("weird-pkg: /usr/bin/evil"));
        assert!(!is_owned_by_trusted_package(&env, "/usr/bin/evil"));
    }

    #[test]
    fn dpkg_unavailable_returns_false() {
        // Alpine / NixOS / custom builds: no dpkg on PATH, so
        // command_stdout returns None. Fallback must degrade
        // gracefully back to the static whitelist (i.e. return
        // false here so the file stays flagged unless the static
        // list catches it).
        let env = MockEnv::new(); // no dpkg output configured
        assert!(!is_owned_by_trusted_package(&env, "/usr/bin/anything"));
    }

    #[test]
    fn dpkg_empty_output_returns_false() {
        // dpkg-query exits 1 when the file is not owned by any
        // package, producing empty stdout. command_stdout might
        // return Some("") in that case — the helper must treat
        // that as "no trusted owner" rather than panicking on
        // split_once.
        let env = MockEnv::new().with_dpkg("/opt/custom/binary", Some(""));
        assert!(!is_owned_by_trusted_package(&env, "/opt/custom/binary"));
    }

    #[test]
    fn dpkg_malformed_output_returns_false() {
        // Defensive: if dpkg output lacks the ':' separator for any
        // reason (e.g. unexpected error message captured to stdout),
        // the helper must not panic on split_once. Return false and
        // let the static list handle the path.
        let env = MockEnv::new().with_dpkg("/usr/bin/weird", Some("garbled output no colon here"));
        assert!(!is_owned_by_trusted_package(&env, "/usr/bin/weird"));
    }
}
