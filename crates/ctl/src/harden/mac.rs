//! Mandatory Access Control posture: is AppArmor or SELinux actually enforcing?
//!
//! A host with neither MAC active relies solely on discretionary (user/group)
//! permissions — a root compromise is then unconfined. Kernel lockdown is
//! covered separately in `firmware.rs`, so this category focuses on the
//! userspace confinement layer only.

use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

/// Decide the MAC posture from the three observable signals:
/// - `apparmor_enabled`: contents of `/sys/module/apparmor/parameters/enabled`
///   ("Y" when the AppArmor LSM is active).
/// - `getenforce`: stdout of the `getenforce` command ("Enforcing" /
///   "Permissive" / "Disabled") when SELinux userspace tools are present.
/// - `selinux_enforce`: contents of `/sys/fs/selinux/enforce` ("1"/"0") — the
///   kernel-side truth, used when `getenforce` is unavailable.
pub(super) fn evaluate_mac(
    apparmor_enabled: Option<&str>,
    getenforce: Option<&str>,
    selinux_enforce: Option<&str>,
    category: &'static str,
) -> (Vec<String>, Vec<Finding>) {
    let mut passed = Vec::new();
    let mut findings = Vec::new();

    let apparmor_on = apparmor_enabled
        .map(|s| s.trim().eq_ignore_ascii_case("y"))
        .unwrap_or(false);

    let getenforce = getenforce.map(|s| s.trim().to_string());
    let selinux_enforcing = getenforce
        .as_deref()
        .map(|s| s.eq_ignore_ascii_case("enforcing"))
        .unwrap_or(false)
        || selinux_enforce.map(|s| s.trim() == "1").unwrap_or(false);
    let selinux_permissive = getenforce
        .as_deref()
        .map(|s| s.eq_ignore_ascii_case("permissive"))
        .unwrap_or(false)
        || selinux_enforce.map(|s| s.trim() == "0").unwrap_or(false);

    if apparmor_on {
        passed.push("AppArmor is enabled".into());
    } else if selinux_enforcing {
        passed.push("SELinux is enforcing".into());
    } else if selinux_permissive {
        findings.push(Finding {
            category,
            severity: Severity::Medium,
            title: "SELinux is in permissive mode (logs but does not block)".into(),
            fix: "Set 'SELINUX=enforcing' in /etc/selinux/config, then reboot \
                  (or run: sudo setenforce 1)"
                .into(),
        });
    } else {
        findings.push(Finding {
            category,
            severity: Severity::High,
            title: "No Mandatory Access Control active (AppArmor/SELinux off)".into(),
            fix: "Enable AppArmor (sudo systemctl enable --now apparmor) or \
                  SELinux for the distro to confine compromised processes."
                .into(),
        });
    }

    (passed, findings)
}

pub(super) fn check_mac(env: &impl HardenEnv) -> CheckResult {
    let cat = "Access Control";
    let apparmor = env.read_to_string("/sys/module/apparmor/parameters/enabled");
    let getenforce = env.command_stdout("getenforce", &[]);
    let selinux_enforce = env.read_to_string("/sys/fs/selinux/enforce");

    let (passed, findings) = evaluate_mac(
        apparmor.as_deref(),
        getenforce.as_deref(),
        selinux_enforce.as_deref(),
        cat,
    );
    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apparmor_enabled_passes() {
        let (passed, findings) = evaluate_mac(Some("Y\n"), None, None, "Access Control");
        assert!(findings.is_empty());
        assert!(passed.iter().any(|p| p.contains("AppArmor")));
    }

    #[test]
    fn selinux_enforcing_via_getenforce_passes() {
        let (passed, findings) = evaluate_mac(None, Some("Enforcing\n"), None, "Access Control");
        assert!(findings.is_empty());
        assert!(passed.iter().any(|p| p.contains("SELinux")));
    }

    #[test]
    fn selinux_enforcing_via_sysfs_passes_when_no_tools() {
        let (passed, findings) = evaluate_mac(None, None, Some("1"), "Access Control");
        assert!(findings.is_empty());
        assert_eq!(passed.len(), 1);
    }

    #[test]
    fn selinux_permissive_is_medium() {
        let (_passed, findings) = evaluate_mac(None, Some("Permissive"), None, "Access Control");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn no_mac_is_high() {
        // AppArmor present but disabled, SELinux absent → unconfined host.
        let (passed, findings) = evaluate_mac(Some("N"), None, None, "Access Control");
        assert!(passed.is_empty());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn nothing_observable_is_high() {
        let (_passed, findings) = evaluate_mac(None, None, None, "Access Control");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }
}
