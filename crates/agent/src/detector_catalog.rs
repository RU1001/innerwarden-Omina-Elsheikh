//! Explained-alerts catalog (spec 075).
//!
//! A single, plain-language source of "what is this + why it matters" per
//! detector kind, fused with the MITRE mapping from [`crate::mitre`]. It turns
//! a raw detector name in a notification into a sentence an operator
//! understands — so an alert reads as "InnerWarden saw this, knows what it is,
//! and is handling it" instead of `keylogger_bash_trap from shell_startup_write`.
//!
//! Design notes:
//! - Pure data + pure functions: no I/O, trivially testable.
//! - The MITRE layer is NOT duplicated here — it is read live from
//!   `mitre::map_detector` so the two never drift.
//! - Unknown detectors get a safe humanised fallback (never panics, never
//!   blank) so a new detector still produces a readable alert before it is
//!   curated here.

/// Plain-language explanation of a detector for operator-facing alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectorExplanation {
    /// What was observed, in plain words (no jargon).
    pub what: &'static str,
    /// Why InnerWarden watches for it — the attacker goal it maps to.
    pub why: &'static str,
}

/// Plain-language "what + why" for the detectors operators see most. Curated
/// for the common set; everything else falls back to a humanised default.
pub fn explain(detector: &str) -> DetectorExplanation {
    let e = |what, why| DetectorExplanation { what, why };
    match detector {
        "ssh_bruteforce" => e(
            "Repeated failed SSH logins from one source.",
            "Attackers guess passwords at scale to get their first foothold on the box.",
        ),
        "credential_stuffing" => e(
            "Many logins tried with leaked username/password pairs.",
            "Attackers replay stolen credentials hoping one still works here.",
        ),
        "port_scan" => e(
            "One source probed many ports/services in a short window.",
            "Reconnaissance: attackers map what is exposed before they pick a way in.",
        ),
        "web_scan" | "web_scanner" => e(
            "Automated probing of web paths/endpoints.",
            "Attackers hunt for vulnerable apps, admin panels, and known exploits.",
        ),
        "reverse_shell" => e(
            "A local process opened an interactive shell back out to a remote host.",
            "This is how an attacker gets hands-on control after they break in, rarely benign.",
        ),
        "web_shell" => e(
            "A web-servable script that can execute commands was written or hit.",
            "A backdoor planted in your web root for persistent remote control.",
        ),
        "rootkit" => e(
            "Signs of hidden processes/files or tampered kernel structures.",
            "Attackers hide their presence at the kernel level to survive and evade you.",
        ),
        "keylogger_bash_trap" => e(
            "Something wrote to a shell startup file (e.g. .bashrc / .profile).",
            "Attackers plant a trap there to capture every command typed on the host (a keylogger).",
        ),
        "auditd_disable" => e(
            "The host audit subsystem was stopped, disabled, or tampered with.",
            "Attackers blind logging before the loud part of an attack so you cannot see it.",
        ),
        "selinux_apparmor_disable" => e(
            "A mandatory-access-control system (SELinux/AppArmor) was disabled.",
            "Attackers tear down OS guardrails to move freely.",
        ),
        "privesc" => e(
            "A process gained or used root through a path its lineage does not justify.",
            "Privilege escalation: turning a limited foothold into full control of the host.",
        ),
        "data_exfiltration" | "data_exfil_ebpf" => e(
            "An unusual volume of data was staged or sent outbound.",
            "Attackers steal your data; this is the payday step of many breaches.",
        ),
        "dns_tunneling" => e(
            "Data smuggled inside DNS queries.",
            "Attackers use DNS as a covert channel to exfiltrate data or reach command-and-control.",
        ),
        "crypto_miner" => e(
            "A process matches cryptocurrency-mining behaviour.",
            "Attackers hijack your CPU/GPU to mine coins on your bill.",
        ),
        "process_injection" => e(
            "Code was injected into another running process.",
            "Attackers run inside a trusted process to hide and bypass defences.",
        ),
        "container_escape" => e(
            "A container did something consistent with breaking out to the host.",
            "Escaping the container turns one compromised app into a compromised server.",
        ),
        "ransomware" => e(
            "A burst of rapid file rewrites with high-entropy (encrypted) content.",
            "Ransomware encrypting your files for extortion. Speed of detection is everything.",
        ),
        "reverse_shell_listener" | "c2_callback" => e(
            "A process is beaconing to a likely command-and-control server.",
            "The implant phoning home for instructions after a compromise.",
        ),
        // ── Daily-briefing coverage (2026-06): the digest routes every
        // per-detector line through `explain`, so the categories that
        // showed up most on prod must each have a plain "what + why".
        "threat_intel" => e(
            "Connections matched public blocklists of known-bad hosts (scanners/botnets).",
            "These hosts are already documented as malicious, so they are auto-blocked on contact.",
        ),
        "proto_anomaly" => e(
            "Traffic did not match the protocol its port normally speaks (junk on SSH/HTTP).",
            "It usually means probing or a misconfiguration: someone poking a service the wrong way.",
        ),
        "kernel_devnode_exposed" => e(
            "A program touched a low-level kernel device that ordinary apps should never open.",
            "It is a privilege-escalation technique: a foothold reaching for full control of the box.",
        ),
        "network_sniffing" => e(
            "A process started capturing raw network traffic.",
            "Packet capture can steal credentials and session tokens in transit.",
        ),
        "kernel" => e(
            "Unusual low-level kernel activity.",
            "The kernel is the deepest, most serious layer to see noise on. Tampering here is hard to undo.",
        ),
        "telemetry.stream_silence" => e(
            "One of InnerWarden's own sensors went quiet unexpectedly.",
            "It is usually a glitch, but it can also be someone silencing our logging before an attack.",
        ),
        "logging_config_change" => e(
            "The server's logging settings were changed.",
            "Attackers often disable or redirect logs to cover their tracks.",
        ),
        "automated_file_collection" => e(
            "A script was bulk-collecting files across the host.",
            "This is how data-theft tooling stages files before exfiltrating them.",
        ),
        "suspicious_login" => e(
            "A login succeeded but looked off: odd time, location, or account.",
            "It can mean an attacker is using stolen but valid credentials.",
        ),
        // Honeypot is a RESPONSE, not a detector; the digest renders it via
        // `friendly_detector_name`, but a curated gloss here keeps any caller
        // that routes "honeypot" through `explain` honest and non-jargon.
        "honeypot" => e(
            "Attackers were lured into the decoy trap and safely observed.",
            "The decoy soaks up the attack and gathers intelligence while the real host stays untouched.",
        ),
        _ => DetectorExplanation {
            // Never blank: humanise the raw name and give an honest generic line
            // so a freshly-added detector still reads sensibly until curated.
            what: "Suspicious activity matched one of InnerWarden's detectors.",
            why: "It fits a known attacker behaviour pattern worth flagging.",
        },
    }
}

/// A compact MITRE attribution line for a detector, e.g.
/// `MITRE T1110.001 · Brute Force: Password Guessing`. `None` when the detector
/// has no mapping (kept live from `mitre.rs`, never duplicated here).
pub fn mitre_line(detector: &str) -> Option<String> {
    crate::mitre::map_detector(detector)
        .map(|m| format!("MITRE {} · {}", m.technique_id, m.technique_name))
}

/// Turn a raw `snake_case` / `dotted.detector` name into a Title-Cased,
/// space-separated label that never leaks the machine name to a boss.
///
/// The daily briefing used to fall through to the raw detector string
/// (`kernel_devnode_exposed`, `telemetry.stream_silence`) on any uncurated
/// detector. This is the safe humanised replacement: even a brand-new detector
/// renders as "Kernel Devnode Exposed", not the snake_case token.
pub fn humanize_detector(detector: &str) -> String {
    let cleaned = detector.replace(['_', '.'], " ");
    let mut out = String::with_capacity(cleaned.len());
    for word in cleaned.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    if out.is_empty() {
        "Suspicious Activity".to_string()
    } else {
        out
    }
}

/// One boss-readable digest line for a detector: a short label plus the
/// plain-language "why it matters" clause, so the operator learns enough to ask
/// for the right fix. e.g. for `ssh_bruteforce`:
/// `Repeated failed SSH logins. Attackers guess passwords at scale to get
/// their first foothold on the box.`
///
/// The label prefers the curated [`crate::telegram::friendly_detector_name`]
/// gloss; otherwise it falls back to [`humanize_detector`] (never snake_case).
/// The "why" comes from [`explain`], which always returns a sentence.
pub fn digest_gloss(detector: &str) -> String {
    let why = explain(detector).why;
    let label = friendly_label(detector);
    format!("{label}. {why}")
}

/// A short human label for a detector, used as the leading clause of
/// [`digest_gloss`]. Honeypot is a response, not a detector, so it gets an
/// explicit phrasing instead of the generic "Threat Detected".
fn friendly_label(detector: &str) -> String {
    if detector == "honeypot" {
        return "Decoy trap engaged".to_string();
    }
    let friendly = crate::telegram::friendly_detector_name(detector);
    // `friendly_detector_name` returns the raw detector unchanged when it has
    // no curated label — humanise that so no snake_case ever leaks.
    if friendly == detector {
        humanize_detector(detector)
    } else {
        friendly.to_string()
    }
}

/// True when `explain` has a curated (non-fallback) entry for this detector.
/// Test-only for now; un-gate when a notification surface needs to branch on
/// it (Phase 2). Kept here so the fallback contract stays asserted.
#[cfg(test)]
fn is_curated(detector: &str) -> bool {
    explain(detector) != explain("__definitely_not_a_real_detector__")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_detectors_have_nonblank_what_and_why() {
        for d in [
            "ssh_bruteforce",
            "reverse_shell",
            "keylogger_bash_trap",
            "auditd_disable",
            "privesc",
            "ransomware",
            "data_exfiltration",
        ] {
            let ex = explain(d);
            assert!(!ex.what.is_empty(), "{d} what empty");
            assert!(!ex.why.is_empty(), "{d} why empty");
            assert!(is_curated(d), "{d} should be curated");
        }
    }

    #[test]
    fn unknown_detector_falls_back_safely() {
        let ex = explain("some_brand_new_detector");
        assert!(!ex.what.is_empty());
        assert!(!ex.why.is_empty());
        assert!(!is_curated("some_brand_new_detector"));
    }

    #[test]
    fn mitre_line_reuses_mitre_map() {
        // ssh_bruteforce is mapped in mitre.rs -> must produce a line.
        let line = mitre_line("ssh_bruteforce").expect("ssh_bruteforce is mapped");
        assert!(line.starts_with("MITRE T"));
        assert!(line.contains("Brute Force"));
        // An unmapped name yields None (no fabricated technique).
        assert!(mitre_line("__unmapped__").is_none());
    }

    #[test]
    fn keylogger_explanation_matches_the_real_world_case() {
        // The 2026-06-09 rustup FP: the alert must read as a keylogger watch,
        // not a raw detector name.
        let ex = explain("keylogger_bash_trap");
        assert!(ex.what.to_lowercase().contains("shell startup"));
        assert!(ex.why.to_lowercase().contains("keylogger"));
    }

    /// Daily-briefing coverage (2026-06): every detector the briefing now routes
    /// through `explain` must be CURATED — a fallback gloss in the boss report
    /// is the exact "raw detector name leaked" failure this work removes.
    #[test]
    fn newly_added_briefing_detectors_are_all_curated() {
        for d in [
            "threat_intel",
            "proto_anomaly",
            "kernel_devnode_exposed",
            "network_sniffing",
            "kernel",
            "telemetry.stream_silence",
            "logging_config_change",
            "automated_file_collection",
            "suspicious_login",
            "honeypot",
        ] {
            let ex = explain(d);
            assert!(!ex.what.is_empty(), "{d} what empty");
            assert!(!ex.why.is_empty(), "{d} why empty");
            assert!(
                is_curated(d),
                "{d} must have a curated gloss, not the fallback"
            );
            // No snake_case / dotted machine name may survive into the gloss.
            assert!(
                !ex.why.contains('_'),
                "{d} why leaks snake_case: {}",
                ex.why
            );
        }
    }

    #[test]
    fn humanize_detector_never_leaks_snake_or_dotted_case() {
        assert_eq!(
            humanize_detector("kernel_devnode_exposed"),
            "Kernel Devnode Exposed"
        );
        assert_eq!(
            humanize_detector("telemetry.stream_silence"),
            "Telemetry Stream Silence"
        );
        assert_eq!(humanize_detector("proto_anomaly"), "Proto Anomaly");
        // Empty / weird input still produces a safe, readable label.
        assert_eq!(humanize_detector(""), "Suspicious Activity");
        let h = humanize_detector("some_brand_new_detector");
        assert!(
            !h.contains('_'),
            "humanised label must not contain underscores: {h}"
        );
    }

    #[test]
    fn digest_gloss_is_boss_readable_and_carries_a_why() {
        // Curated detector → friendly label + why clause, no snake_case. The
        // label and why are joined by a period (no em dash anywhere).
        let g = digest_gloss("ssh_bruteforce");
        assert!(g.contains(". "), "gloss must join label and why: {g}");
        assert!(!g.contains('\u{2014}'), "gloss must carry no em dash: {g}");
        assert!(!g.contains("ssh_bruteforce"), "raw name leaked: {g}");
        // Uncurated-label detector still humanises (kernel_devnode_exposed has
        // no friendly_detector_name entry but a curated explain why).
        let g2 = digest_gloss("kernel_devnode_exposed");
        assert!(
            g2.starts_with("Kernel Devnode Exposed"),
            "humanised label: {g2}"
        );
        assert!(
            !g2.contains("kernel_devnode_exposed"),
            "raw name leaked: {g2}"
        );
        // Honeypot is a response, not a detector.
        let g3 = digest_gloss("honeypot");
        assert!(
            g3.starts_with("Decoy trap engaged"),
            "honeypot phrasing: {g3}"
        );
    }
}
