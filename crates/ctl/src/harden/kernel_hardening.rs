//! Extended kernel hardening sysctls (CIS-aligned), kept separate from the
//! core `kernel.rs` network checks so each stays small and independently
//! testable.
//!
//! Deliberate omission: `kernel.perf_event_paranoid`. CIS recommends raising
//! it, but InnerWarden's own eBPF sensor needs it LOW to attach under
//! `CAP_PERFMON`. Recommending a higher value here would tell the operator to
//! break the very product running the scan, so it is left out on purpose.

use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

/// Raw sysctl values read from `/proc/sys`. `None` means the file could not be
/// read (older kernel without the knob, or no permission) — treated as "not
/// confirmed secure" so it surfaces rather than silently passing.
#[derive(Default)]
pub(super) struct KernelHardeningValues<'a> {
    pub kptr_restrict: Option<&'a str>,
    pub dmesg_restrict: Option<&'a str>,
    pub ptrace_scope: Option<&'a str>,
    pub unprivileged_bpf_disabled: Option<&'a str>,
    pub bpf_jit_harden: Option<&'a str>,
    pub protected_hardlinks: Option<&'a str>,
    pub protected_symlinks: Option<&'a str>,
    pub protected_fifos: Option<&'a str>,
    pub protected_regular: Option<&'a str>,
    pub suid_dumpable: Option<&'a str>,
    pub rp_filter: Option<&'a str>,
    pub log_martians: Option<&'a str>,
    pub icmp_echo_ignore_broadcasts: Option<&'a str>,
    pub send_redirects: Option<&'a str>,
    pub kexec_load_disabled: Option<&'a str>,
}

/// One sysctl expectation: a human title, the fix command, severity when the
/// value is not satisfactory, and a predicate over the observed value.
struct Rule {
    secure_title: &'static str,
    finding_title: &'static str,
    fix: &'static str,
    severity: Severity,
    ok: fn(&str) -> bool,
}

fn eval_one(
    value: Option<&str>,
    rule: &Rule,
    category: &'static str,
    passed: &mut Vec<String>,
    findings: &mut Vec<Finding>,
) {
    match value {
        Some(v) if (rule.ok)(v) => passed.push(rule.secure_title.into()),
        _ => findings.push(Finding {
            category,
            severity: rule.severity,
            title: rule.finding_title.into(),
            fix: rule.fix.into(),
        }),
    }
}

fn is_one_or_two(v: &str) -> bool {
    v == "1" || v == "2"
}
fn is_one_two_or_three(v: &str) -> bool {
    v == "1" || v == "2" || v == "3"
}
fn is_one(v: &str) -> bool {
    v == "1"
}
fn is_zero(v: &str) -> bool {
    v == "0"
}

pub(super) fn evaluate_kernel_hardening(
    vals: &KernelHardeningValues,
    category: &'static str,
) -> (Vec<String>, Vec<Finding>) {
    let mut passed = Vec::new();
    let mut findings = Vec::new();

    let specs: [(Option<&str>, Rule); 15] = [
        (
            vals.kptr_restrict,
            Rule {
                secure_title: "Kernel pointers restricted (kptr_restrict)",
                finding_title: "Kernel pointers exposed (kptr_restrict = 0)",
                fix: "Run: sudo sysctl -w kernel.kptr_restrict=1",
                severity: Severity::Medium,
                ok: is_one_or_two,
            },
        ),
        (
            vals.dmesg_restrict,
            Rule {
                secure_title: "dmesg restricted to root",
                finding_title: "dmesg readable by unprivileged users",
                fix: "Run: sudo sysctl -w kernel.dmesg_restrict=1",
                severity: Severity::Low,
                ok: is_one,
            },
        ),
        (
            vals.ptrace_scope,
            Rule {
                secure_title: "Yama ptrace scope restricted",
                finding_title: "ptrace not restricted (Yama ptrace_scope = 0)",
                fix: "Run: sudo sysctl -w kernel.yama.ptrace_scope=1",
                severity: Severity::Medium,
                ok: is_one_two_or_three,
            },
        ),
        (
            vals.unprivileged_bpf_disabled,
            Rule {
                secure_title: "Unprivileged BPF disabled",
                finding_title: "Unprivileged BPF allowed (attack surface)",
                fix: "Run: sudo sysctl -w kernel.unprivileged_bpf_disabled=1",
                severity: Severity::Medium,
                ok: is_one_or_two,
            },
        ),
        (
            vals.bpf_jit_harden,
            Rule {
                secure_title: "BPF JIT hardened",
                finding_title: "BPF JIT not hardened (JIT spray risk)",
                fix: "Run: sudo sysctl -w net.core.bpf_jit_harden=2",
                severity: Severity::Low,
                ok: is_one_or_two,
            },
        ),
        (
            vals.protected_hardlinks,
            Rule {
                secure_title: "Hardlink protection enabled",
                finding_title: "Hardlink protection disabled (TOCTOU risk)",
                fix: "Run: sudo sysctl -w fs.protected_hardlinks=1",
                severity: Severity::Medium,
                ok: is_one,
            },
        ),
        (
            vals.protected_symlinks,
            Rule {
                secure_title: "Symlink protection enabled",
                finding_title: "Symlink protection disabled (symlink attacks)",
                fix: "Run: sudo sysctl -w fs.protected_symlinks=1",
                severity: Severity::Medium,
                ok: is_one,
            },
        ),
        (
            vals.protected_fifos,
            Rule {
                secure_title: "FIFO protection enabled",
                finding_title: "FIFO protection disabled",
                fix: "Run: sudo sysctl -w fs.protected_fifos=1",
                severity: Severity::Low,
                ok: is_one_or_two,
            },
        ),
        (
            vals.protected_regular,
            Rule {
                secure_title: "Regular-file protection enabled",
                finding_title: "Regular-file protection disabled",
                fix: "Run: sudo sysctl -w fs.protected_regular=1",
                severity: Severity::Low,
                ok: is_one_or_two,
            },
        ),
        (
            vals.suid_dumpable,
            Rule {
                secure_title: "SUID core dumps disabled",
                finding_title: "SUID programs are core-dumpable (credential leak)",
                fix: "Run: sudo sysctl -w fs.suid_dumpable=0",
                severity: Severity::Medium,
                ok: is_zero,
            },
        ),
        (
            vals.rp_filter,
            Rule {
                secure_title: "Reverse-path filtering enabled",
                finding_title: "Reverse-path filtering off (IP spoofing risk)",
                fix: "Run: sudo sysctl -w net.ipv4.conf.all.rp_filter=1",
                severity: Severity::Low,
                ok: is_one_or_two,
            },
        ),
        (
            vals.log_martians,
            Rule {
                secure_title: "Martian packets logged",
                finding_title: "Martian packets not logged",
                fix: "Run: sudo sysctl -w net.ipv4.conf.all.log_martians=1",
                severity: Severity::Low,
                ok: is_one,
            },
        ),
        (
            vals.icmp_echo_ignore_broadcasts,
            Rule {
                secure_title: "ICMP broadcast echoes ignored",
                finding_title: "ICMP broadcast echoes accepted (smurf amplification)",
                fix: "Run: sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1",
                severity: Severity::Low,
                ok: is_one,
            },
        ),
        (
            vals.send_redirects,
            Rule {
                secure_title: "ICMP redirects not sent",
                finding_title: "Host sends ICMP redirects (router-only behavior)",
                fix: "Run: sudo sysctl -w net.ipv4.conf.all.send_redirects=0",
                severity: Severity::Low,
                ok: is_zero,
            },
        ),
        (
            vals.kexec_load_disabled,
            Rule {
                secure_title: "kexec disabled (no runtime kernel replace)",
                finding_title: "kexec_load enabled (runtime kernel replacement)",
                fix: "Run: sudo sysctl -w kernel.kexec_load_disabled=1",
                severity: Severity::Medium,
                ok: is_one,
            },
        ),
    ];

    for (value, rule) in &specs {
        eval_one(*value, rule, category, &mut passed, &mut findings);
    }

    (passed, findings)
}

pub(super) fn check_kernel_hardening(env: &impl HardenEnv) -> CheckResult {
    let cat = "Kernel Hardening";
    let read = |p: &str| env.read_to_string(p).map(|s| s.trim().to_string());

    let kptr = read("/proc/sys/kernel/kptr_restrict");
    let dmesg = read("/proc/sys/kernel/dmesg_restrict");
    let ptrace = read("/proc/sys/kernel/yama/ptrace_scope");
    let unpriv_bpf = read("/proc/sys/kernel/unprivileged_bpf_disabled");
    let jit = read("/proc/sys/net/core/bpf_jit_harden");
    let p_hard = read("/proc/sys/fs/protected_hardlinks");
    let p_sym = read("/proc/sys/fs/protected_symlinks");
    let p_fifo = read("/proc/sys/fs/protected_fifos");
    let p_reg = read("/proc/sys/fs/protected_regular");
    let suid_dump = read("/proc/sys/fs/suid_dumpable");
    let rp = read("/proc/sys/net/ipv4/conf/all/rp_filter");
    let martians = read("/proc/sys/net/ipv4/conf/all/log_martians");
    let icmp_bcast = read("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts");
    let send_redir = read("/proc/sys/net/ipv4/conf/all/send_redirects");
    let kexec = read("/proc/sys/kernel/kexec_load_disabled");

    let vals = KernelHardeningValues {
        kptr_restrict: kptr.as_deref(),
        dmesg_restrict: dmesg.as_deref(),
        ptrace_scope: ptrace.as_deref(),
        unprivileged_bpf_disabled: unpriv_bpf.as_deref(),
        bpf_jit_harden: jit.as_deref(),
        protected_hardlinks: p_hard.as_deref(),
        protected_symlinks: p_sym.as_deref(),
        protected_fifos: p_fifo.as_deref(),
        protected_regular: p_reg.as_deref(),
        suid_dumpable: suid_dump.as_deref(),
        rp_filter: rp.as_deref(),
        log_martians: martians.as_deref(),
        icmp_echo_ignore_broadcasts: icmp_bcast.as_deref(),
        send_redirects: send_redir.as_deref(),
        kexec_load_disabled: kexec.as_deref(),
    };

    let (passed, findings) = evaluate_kernel_hardening(&vals, cat);
    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(v: &'static str) -> KernelHardeningValues<'static> {
        KernelHardeningValues {
            kptr_restrict: Some(v),
            dmesg_restrict: Some(v),
            ptrace_scope: Some(v),
            unprivileged_bpf_disabled: Some(v),
            bpf_jit_harden: Some(v),
            protected_hardlinks: Some(v),
            protected_symlinks: Some(v),
            protected_fifos: Some(v),
            protected_regular: Some(v),
            suid_dumpable: Some(v),
            rp_filter: Some(v),
            log_martians: Some(v),
            icmp_echo_ignore_broadcasts: Some(v),
            send_redirects: Some(v),
            kexec_load_disabled: Some(v),
        }
    }

    #[test]
    fn hardened_modern_ubuntu_defaults_pass() {
        // A box matching CIS recommendations: every knob at its secure value.
        let vals = KernelHardeningValues {
            kptr_restrict: Some("1"),
            dmesg_restrict: Some("1"),
            ptrace_scope: Some("1"),
            unprivileged_bpf_disabled: Some("2"),
            bpf_jit_harden: Some("2"),
            protected_hardlinks: Some("1"),
            protected_symlinks: Some("1"),
            protected_fifos: Some("1"),
            protected_regular: Some("2"),
            suid_dumpable: Some("0"),
            rp_filter: Some("1"),
            log_martians: Some("1"),
            icmp_echo_ignore_broadcasts: Some("1"),
            send_redirects: Some("0"),
            kexec_load_disabled: Some("1"),
        };
        let (passed, findings) = evaluate_kernel_hardening(&vals, "Kernel Hardening");
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
        assert_eq!(passed.len(), 15);
    }

    #[test]
    fn insecure_box_flags_every_knob() {
        // suid_dumpable/send_redirects insecure = "1"; the rest insecure = "0".
        let mut vals = all("0");
        vals.suid_dumpable = Some("1");
        vals.send_redirects = Some("1");
        let (passed, findings) = evaluate_kernel_hardening(&vals, "Kernel Hardening");
        assert!(passed.is_empty(), "unexpected passes: {passed:?}");
        assert_eq!(findings.len(), 15);
        // The high-value gaps must be Medium, not Low (kptr_restrict,
        // ptrace_scope, unprivileged_bpf, protected_hardlinks,
        // protected_symlinks, suid_dumpable, kexec_load_disabled = 7).
        let medium = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        assert_eq!(medium, 7, "expected 7 medium findings: {findings:?}");
    }

    #[test]
    fn unreadable_values_are_flagged_not_silently_passed() {
        let vals = KernelHardeningValues::default(); // all None
        let (passed, findings) = evaluate_kernel_hardening(&vals, "Kernel Hardening");
        assert!(passed.is_empty());
        assert_eq!(findings.len(), 15);
    }

    #[test]
    fn ptrace_scope_three_is_accepted() {
        let mut vals = all("1");
        vals.ptrace_scope = Some("3");
        let (_passed, findings) = evaluate_kernel_hardening(&vals, "Kernel Hardening");
        assert!(!findings.iter().any(|f| f.title.contains("ptrace")));
    }
}
