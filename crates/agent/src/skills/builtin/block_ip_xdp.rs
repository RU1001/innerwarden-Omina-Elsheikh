use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

/// XDP firewall block - drops packets at the network driver level.
///
/// Instead of adding a firewall rule (ufw/iptables), this inserts the IP
/// into a BPF hash map that the XDP program checks on every incoming packet.
/// Drop rate: 10-25 million packets per second, zero CPU overhead.
///
/// Supports both IPv4 and IPv6. Uses separate pinned maps:
///   - /sys/fs/bpf/innerwarden/blocklist    (IPv4, key: 4 bytes)
///   - /sys/fs/bpf/innerwarden/blocklist_v6 (IPv6, key: 16 bytes)
pub struct BlockIpXdp;

/// Path where the XDP IPv4 blocklist map is pinned.
const BLOCKLIST_PIN: &str = "/sys/fs/bpf/innerwarden/blocklist";
/// Path where the XDP IPv6 blocklist map is pinned.
const BLOCKLIST_V6_PIN: &str = "/sys/fs/bpf/innerwarden/blocklist_v6";

impl ResponseSkill for BlockIpXdp {
    fn id(&self) -> &'static str {
        "block-ip-xdp"
    }
    fn name(&self) -> &'static str {
        "Block IP via XDP (wire-speed)"
    }
    fn description(&self) -> &'static str {
        "Drops packets from the attacking IP at the network driver level using XDP. \
         10-25 million pps drop rate, zero CPU overhead. \
         The fastest possible firewall - packets never reach the kernel network stack."
    }
    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }
    fn applicable_to(&self) -> &'static [&'static str] {
        &[
            "ssh_bruteforce",
            "port_scan",
            "credential_stuffing",
            "c2_callback",
            "distributed_ssh",
            "reverse_shell",
            "lateral_movement",
            "data_exfiltration",
            "data_exfil_ebpf",
            "ransomware",
            "process_injection",
            "container_escape",
            "web_shell",
            "dns_tunneling",
            "crypto_miner",
            "packet_flood",
            "fileless",
            "web_scan",
            "ssh_key_injection",
            "suspicious_login",
        ]
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let ip = match &ctx.target_ip {
                Some(ip) => ip.clone(),
                None => {
                    return SkillResult {
                        success: false,
                        message: "block-ip-xdp: no target IP in context".to_string(),
                    }
                }
            };

            // Determine IP version and prepare key bytes + map path
            let (map_pin, key_args): (&str, Vec<String>) = if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                let b = v4.octets();
                (
                    BLOCKLIST_PIN,
                    vec![
                        b[0].to_string(),
                        b[1].to_string(),
                        b[2].to_string(),
                        b[3].to_string(),
                    ],
                )
            } else if let Ok(v6) = ip.parse::<Ipv6Addr>() {
                let b = v6.octets();
                (BLOCKLIST_V6_PIN, b.iter().map(|x| x.to_string()).collect())
            } else {
                return SkillResult {
                    success: false,
                    message: format!("block-ip-xdp: invalid IP address: {ip}"),
                };
            };

            if dry_run {
                info!(
                    ip,
                    "DRY RUN: would insert {ip} into XDP blocklist (wire-speed drop)"
                );
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would block {ip} via XDP (wire-speed)"),
                };
            }

            // Check if pinned map exists.
            //
            // 2026-05-03 (Wave 5b PR-2): no per-call WARN here. The
            // `xdp_availability` gate in `decision_block_ip` is the
            // canonical surface for XDP-unavailable warnings; it
            // emits one operator-actionable WARN per 5 min with the
            // recovery recipe. Logging here AS WELL would re-create
            // the spam this PR fixes (operator's prod was producing
            // two WARN lines per block decision, one from each path).
            // The skill still returns success=false so the caller
            // can call `xdp_availability::mark_failed` and gate
            // future attempts.
            if !std::path::Path::new(map_pin).exists() {
                return SkillResult {
                    success: false,
                    message: format!(
                        "XDP not available (map not found at {map_pin}). \
                         Ensure innerwarden-sensor is running with XDP attached."
                    ),
                };
            }

            // Insert into pinned BPF map via bpftool
            let mut args = vec![
                "bpftool".to_string(),
                "map".to_string(),
                "update".to_string(),
                "pinned".to_string(),
                map_pin.to_string(),
                "key".to_string(),
            ];
            args.extend(key_args);
            args.extend([
                "value".to_string(),
                "1".to_string(),
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                "any".to_string(),
            ]);

            let output = tokio::process::Command::new("sudo")
                .args(&args[..])
                .output()
                .await;

            match output {
                Ok(out) if out.status.success() => {
                    info!(ip, "blocked via XDP (wire-speed drop)");
                    SkillResult {
                        success: true,
                        message: format!("Blocked {ip} via XDP - wire-speed drop active"),
                    }
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(ip, stderr = %stderr, "bpftool map update failed");
                    SkillResult {
                        success: false,
                        message: format!("XDP block failed for {ip}: {stderr}"),
                    }
                }
                Err(e) => {
                    warn!(ip, error = %e, "failed to spawn bpftool");
                    SkillResult {
                        success: false,
                        message: format!("failed to run bpftool: {e}"),
                    }
                }
            }
        })
    }
}

/// Check if XDP firewall is available on this system.
#[allow(dead_code)]
pub fn is_xdp_available() -> bool {
    std::path::Path::new(BLOCKLIST_PIN).exists()
}

/// Classify a `sudo bpftool map delete` failure as a NON-transient privilege
/// problem (the agent cannot run bpftool — e.g. no sudoers entry, no tty, not
/// root) rather than a transient kernel/map drift.
///
/// Why this matters: the boot-loop XDP TTL sweep keeps a local entry and
/// retries "next tick" on failure, which is correct for a transient kernel
/// drift but WRONG for a privilege failure — that never recovers on its own,
/// so every 30s slow-loop tick re-spawns `sudo` and re-logs. Observed on a
/// non-root deploy (agent `User=innerwarden`, block backend `ufw`, no sudoers
/// rule for bpftool): 44,415 failed sudo-auths + 44,260 WARN lines in 7 days
/// for a single stuck entry. A privilege failure must back off, not hammer.
///
/// The match is on the lowercased stderr; covers the common sudo/kernel
/// permission signatures.
pub fn is_xdp_privilege_failure(stderr_lower: &str) -> bool {
    stderr_lower.contains("conversation failed")
        || stderr_lower.contains("password is required")
        || stderr_lower.contains("askpass")
        || stderr_lower.contains("no tty present")
        || stderr_lower.contains("not allowed to execute")
        || stderr_lower.contains("not in the sudoers")
        || stderr_lower.contains("permission denied")
        || stderr_lower.contains("operation not permitted")
        || stderr_lower.contains("must be run as root")
}

/// Exponential backoff (in seconds) for repeated non-transient XDP cleanup
/// failures, keyed on the count of consecutive failures for that IP.
///
/// Starts at 60s and doubles, capped at 1 hour. The cap (rather than "give up
/// forever") means a privilege that gets granted later — operator adds the
/// sudoers rule, or restarts the agent as root — is still picked up within an
/// hour without the every-tick sudo storm in between. A fresh boot clears the
/// backoff map entirely, so a restart retries immediately.
pub fn xdp_cleanup_backoff_secs(consecutive_failures: u32) -> i64 {
    const BASE: i64 = 60;
    const CAP: i64 = 3600;
    let shift = consecutive_failures.saturating_sub(1).min(6);
    BASE.saturating_mul(1_i64 << shift).min(CAP)
}

/// Wave 4 (AUDIT-WAVE4-XDP-IPV6) helper: dispatch an IP string to the
/// matching XDP blocklist pin path + bpftool key bytes. Returns `None`
/// for non-IP input so callers can drop the local poison entry without
/// invoking bpftool.
///
/// Shared by [`xdp_unblock_ip`] (the skill helper) AND the boot-loop
/// adaptive TTL expiry path in `crates/agent/src/loops/boot.rs`. Pre-fix
/// the boot loop did `ip.parse::<Ipv4Addr>()` and dropped any IPv6 entry
/// as "poison", leaving every v6 entry in the kernel `BLOCKLIST_V6_PIN`
/// map forever even after the TTL expired. Caught by Copilot review on
/// PR #462 (2026-05-05). Routing both paths through the same helper
/// makes a future "v4-only refactor" fail at compile time.
pub fn xdp_blocklist_pin_for_ip(ip: &str) -> Option<(&'static str, Vec<String>)> {
    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
        let b = v4.octets();
        Some((
            BLOCKLIST_PIN,
            vec![
                b[0].to_string(),
                b[1].to_string(),
                b[2].to_string(),
                b[3].to_string(),
            ],
        ))
    } else if let Ok(v6) = ip.parse::<Ipv6Addr>() {
        let b = v6.octets();
        Some((BLOCKLIST_V6_PIN, b.iter().map(|x| x.to_string()).collect()))
    } else {
        None
    }
}

/// Remove an IP from the XDP blocklist (unblock).
///
/// # Wave 4 (AUDIT-WAVE4-XDP-IPV6, 2026-05-04 ultrareview)
///
/// Pre-fix this only parsed the input as `Ipv4Addr`, so any IPv6 entry
/// the matching `execute()` path inserted into `BLOCKLIST_V6_PIN` was
/// never removed by the unblock path - the v6 entry stayed in the
/// kernel map forever even after the operator (or the response
/// lifecycle TTL sweep) requested removal. The fix routes through
/// [`xdp_blocklist_pin_for_ip`] which mirrors the version-detection
/// that `execute()` already does.
#[allow(dead_code)]
pub async fn xdp_unblock_ip(ip: &str) -> Result<(), String> {
    let (map_pin, key_args) =
        xdp_blocklist_pin_for_ip(ip).ok_or_else(|| format!("invalid IP: {ip}"))?;

    let mut args: Vec<String> = vec![
        "bpftool".into(),
        "map".into(),
        "delete".into(),
        "pinned".into(),
        map_pin.into(),
        "key".into(),
    ];
    args.extend(key_args);

    let output = tokio::process::Command::new("sudo")
        .args(&args[..])
        .output()
        .await
        .map_err(|e| format!("failed to run bpftool: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::{HoneypotRuntimeConfig, SkillContext};

    fn make_ctx(ip: Option<&str>) -> SkillContext {
        SkillContext {
            incident: innerwarden_core::incident::Incident {
                ts: chrono::Utc::now(),
                host: "h".into(),
                incident_id: "id".into(),
                severity: innerwarden_core::event::Severity::High,
                title: "t".into(),
                summary: "s".into(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: vec![],
                entities: vec![],
            },
            target_ip: ip.map(str::to_string),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: "h".into(),
            data_dir: std::env::temp_dir(),
            honeypot: HoneypotRuntimeConfig::default(),
            ai_provider: None,
        }
    }

    #[tokio::test]
    async fn dry_run_xdp_ipv4() {
        let ctx = make_ctx(Some("1.2.3.4"));
        let result = BlockIpXdp.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
        assert!(result.message.contains("1.2.3.4"));
    }

    #[tokio::test]
    async fn dry_run_xdp_ipv6() {
        let ctx = make_ctx(Some("2001:db8::1"));
        let result = BlockIpXdp.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
        assert!(result.message.contains("2001:db8::1"));
    }

    #[tokio::test]
    async fn invalid_ip_xdp() {
        let ctx = make_ctx(Some("not-an-ip"));
        let result = BlockIpXdp.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("invalid IP"));
    }

    #[tokio::test]
    async fn no_target_ip_xdp() {
        let ctx = make_ctx(None);
        let result = BlockIpXdp.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("no target IP"));
    }

    #[test]
    fn skill_metadata_xdp() {
        assert_eq!(BlockIpXdp.id(), "block-ip-xdp");
        assert!(BlockIpXdp.name().contains("XDP"));
        assert_eq!(BlockIpXdp.tier(), SkillTier::Open);
        // XDP handles many more detectors than other skills
        assert!(BlockIpXdp.applicable_to().len() > 10);
        assert!(BlockIpXdp.applicable_to().contains(&"reverse_shell"));
        assert!(BlockIpXdp.applicable_to().contains(&"ransomware"));
    }

    // ── Wave 4 anchors (AUDIT-WAVE4-XDP-IPV6) ──────────────────────────
    //
    // Pre-fix `xdp_unblock_ip` only parsed input as `Ipv4Addr`, so any
    // IPv6 entry the matching `execute()` path inserted into
    // `BLOCKLIST_V6_PIN` was never removed - the v6 entry stayed in
    // the kernel map forever even after the operator (or the response
    // lifecycle TTL sweep) requested removal. The fix mirrors the
    // version-detection that `execute()` already does.

    // ── XDP cleanup backoff anchors (non-root deploy flood fix) ────────
    //
    // A non-root agent (User=innerwarden) with block backend `ufw` has no
    // sudoers rule for bpftool, so the boot-loop XDP TTL sweep's
    // `sudo bpftool map delete` fails every tick. Pre-fix that retried +
    // logged every 30s slow-loop tick: 44,415 failed sudo-auths + 44,260
    // WARN lines in 7 days for one stuck entry. The classifier routes such
    // permanent failures into exponential backoff instead.

    #[test]
    fn privilege_failures_are_classified_non_transient() {
        for s in [
            "sudo: a password is required",         // NOPASSWD rule missing
            "sudo: a terminal is required to read the password; either use the -s option to read from standard input or configure an askpass helper",
            "sudo: no tty present and no askpass program specified",
            "sudo: pam_unix(sudo:auth): conversation failed",
            "user innerwarden is not allowed to execute",
            "innerwarden is not in the sudoers file",
            "bpftool: permission denied",
            "operation not permitted",
            "must be run as root",
        ] {
            assert!(
                is_xdp_privilege_failure(&s.to_lowercase()),
                "should be a privilege failure: {s}"
            );
        }
    }

    #[test]
    fn transient_drift_is_not_a_privilege_failure() {
        // Genuine kernel/map drift must stay on the retry-next-tick path,
        // NOT get backed off (it can recover on its own).
        for s in [
            "error: bpftool: map element not found",
            "no such file or directory",
            "cannot read map: invalid argument",
            "",
        ] {
            assert!(
                !is_xdp_privilege_failure(&s.to_lowercase()),
                "should NOT be a privilege failure: {s}"
            );
        }
    }

    #[test]
    fn cleanup_backoff_grows_then_caps_at_one_hour() {
        assert_eq!(xdp_cleanup_backoff_secs(0), 60); // saturating_sub floor
        assert_eq!(xdp_cleanup_backoff_secs(1), 60);
        assert_eq!(xdp_cleanup_backoff_secs(2), 120);
        assert_eq!(xdp_cleanup_backoff_secs(3), 240);
        assert_eq!(xdp_cleanup_backoff_secs(7), 3600); // 60 * 2^6 = 3840 -> capped
        assert_eq!(xdp_cleanup_backoff_secs(100), 3600); // stays capped, no overflow
    }

    #[test]
    fn xdp_unblock_ip_handles_ipv4_addresses() {
        let (pin, key) = xdp_blocklist_pin_for_ip("203.0.113.42").expect("v4 must parse");
        assert_eq!(pin, BLOCKLIST_PIN);
        assert_eq!(key, vec!["203", "0", "113", "42"]);
    }

    #[test]
    fn xdp_unblock_ip_handles_ipv6_addresses() {
        // The headline anchor for the bug: a v6 unblock must route to
        // BLOCKLIST_V6_PIN with 16 key bytes, NOT to BLOCKLIST_PIN
        // with `Err(invalid IP)`.
        let (pin, key) = xdp_blocklist_pin_for_ip("2001:db8::1").expect("v6 must parse");
        assert_eq!(pin, BLOCKLIST_V6_PIN);
        assert_eq!(key.len(), 16, "IPv6 key must be 16 bytes (128 bits)");
        // Last byte is `1`, the rest of the low half is `0`, the
        // high half is the documented prefix `2001:db8::/32`.
        assert_eq!(key[0], "32"); // 0x20
        assert_eq!(key[1], "1"); // 0x01
        assert_eq!(key[2], "13"); // 0x0d
        assert_eq!(key[3], "184"); // 0xb8
        assert_eq!(key[15], "1");
    }

    #[test]
    fn xdp_unblock_ip_handles_ipv6_loopback() {
        let (pin, key) = xdp_blocklist_pin_for_ip("::1").expect("loopback v6 must parse");
        assert_eq!(pin, BLOCKLIST_V6_PIN);
        // ::1 is fifteen 0 bytes followed by a 1.
        assert_eq!(key.len(), 16);
        for k in &key[..15] {
            assert_eq!(k, "0");
        }
        assert_eq!(key[15], "1");
    }

    #[test]
    fn xdp_unblock_ip_rejects_garbage_input() {
        for evil in &[
            "not-an-ip",
            "",
            "256.256.256.256",
            "12345::xyzzy",
            "..",
            "/",
        ] {
            assert!(
                xdp_blocklist_pin_for_ip(evil).is_none(),
                "invalid input {evil:?} must return None"
            );
        }
    }

    #[test]
    fn xdp_blocklist_pin_for_ip_routes_v4_and_v6_to_distinct_maps() {
        // Anti-regression for accidentally collapsing the two maps in
        // a future refactor (which would silently break the actual
        // prod failure mode: IPv6 entry inserted into V6 map but
        // delete called against the V4 map).
        let (v4_pin, v4_key) = xdp_blocklist_pin_for_ip("198.51.100.7").unwrap();
        let (v6_pin, v6_key) = xdp_blocklist_pin_for_ip("2001:db8::dead:beef").unwrap();
        assert_ne!(v4_pin, v6_pin, "v4 and v6 maps must be distinct pins");
        assert_eq!(v4_key.len(), 4, "v4 key is 4 bytes");
        assert_eq!(v6_key.len(), 16, "v6 key is 16 bytes");
        assert!(v4_pin.ends_with("/blocklist"));
        assert!(v6_pin.ends_with("/blocklist_v6"));
    }

    #[test]
    fn xdp_blocklist_pin_for_ip_returns_none_for_garbage() {
        // Pin the contract that the boot-loop TTL expiry path depends
        // on: garbage returns None so the caller can drop the local
        // poison entry without invoking bpftool with bad arguments.
        assert!(xdp_blocklist_pin_for_ip("").is_none());
        assert!(xdp_blocklist_pin_for_ip("256.0.0.1").is_none());
        assert!(xdp_blocklist_pin_for_ip("not-an-ip").is_none());
        assert!(xdp_blocklist_pin_for_ip("12345::xyzzy").is_none());
    }
}
