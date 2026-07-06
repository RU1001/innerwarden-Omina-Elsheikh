//! Single source of truth for "is this binary's on-disk path package-manager /
//! OS-trusted?".
//!
//! Used by both [`crate::detectors::host_drift`] (does an exec come from a
//! non-standard location?) and `crate::kernel_promote` (is the process that
//! created a `memfd` a trusted on-disk binary?). It lives at the sensor crate
//! root (NOT under `detectors/`) because `kernel_promote` is itself a crate-root
//! module and because this is a path utility, not a detector; keeping it out of
//! `detectors/` also keeps the "82 detectors" count honest. The cross-test
//! `host_drift_and_path_trust_agree` pins that the two callers never disagree
//! about what "trusted" means.
//!
//! # Why path, not comm
//!
//! `comm` (`bpf_get_current_comm`) is the basename of the running binary and is
//! attacker-forgeable via `argv0` / `prctl(PR_SET_NAME)`. The exe **path** used
//! here is the kernel-captured `execve` filename (spec 070 provenance): an
//! attacker cannot make a payload staged in `/tmp` report a `/usr/bin` path. So
//! a path-anchored trust check is a real signal where a comm allowlist is not.

/// Directories where package managers / the OS install real binaries. A binary
/// whose absolute on-disk path starts with one of these is package-trusted.
pub const TRUSTED_SYSTEM_PATHS: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib64/",
    "/opt/",
    "/snap/",
    "/nix/store/",
];

/// True when `path` is a non-empty absolute path under a trusted system dir AND
/// shows no sign of being a deleted / in-memory backing file.
///
/// The `(deleted)` suffix (how the kernel renders an unlinked exe), an empty
/// path, and a `memfd:` backing name are NEVER trusted: a process whose backing
/// file is gone or in-memory is the classic fileless / self-tamper signal and
/// must stay eligible for promotion even if the *recorded* directory looks fine.
pub fn is_trusted_system_path(path: &str) -> bool {
    let p = path.trim();
    if p.is_empty() || p.contains("(deleted)") || p.contains("memfd:") {
        return false;
    }
    TRUSTED_SYSTEM_PATHS.iter().any(|dir| p.starts_with(dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusts_package_manager_dirs() {
        assert!(is_trusted_system_path("/usr/bin/fwupdmgr"));
        assert!(is_trusted_system_path("/usr/local/bin/innerwarden-agent"));
        assert!(is_trusted_system_path("/usr/lib/systemd/systemd-executor"));
        assert!(is_trusted_system_path("/sbin/init"));
        assert!(is_trusted_system_path(
            "/snap/firefox/current/usr/bin/firefox"
        ));
    }

    #[test]
    fn rejects_untrusted_and_volatile_paths() {
        assert!(!is_trusted_system_path("/tmp/iw_dl_sensor"));
        assert!(!is_trusted_system_path("/dev/shm/x"));
        assert!(!is_trusted_system_path("/home/user/payload"));
        assert!(!is_trusted_system_path(""));
        assert!(!is_trusted_system_path("   "));
        // A deleted backing file is the fileless tamper signal, never trusted,
        // even under a system dir.
        assert!(!is_trusted_system_path("/usr/bin/python3 (deleted)"));
        assert!(!is_trusted_system_path("memfd:payload (deleted)"));
        assert!(!is_trusted_system_path("memfd:foo"));
    }

    #[test]
    fn relative_or_bare_name_is_not_trusted() {
        // No directory context => cannot prove trust.
        assert!(!is_trusted_system_path("fwupdmgr"));
        assert!(!is_trusted_system_path("./payload"));
    }
}
