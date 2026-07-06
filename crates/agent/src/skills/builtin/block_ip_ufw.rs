use std::future::Future;
use std::pin::Pin;

use tracing::{info, warn};

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

use super::firewall_target::{format_skill_outcome, is_valid_firewall_target};

pub struct BlockIpUfw;

/// PURE: the `ufw` argv for blocking `ip`. `insert 1` (not a bare `deny`, which
/// appends) so the attacker deny wins over broad `allow <port>` rules — ufw is
/// first-match-wins. Kept as a function so a regression to append is caught by a
/// unit test, not only in production.
fn ufw_block_args(ip: &str) -> Vec<&str> {
    vec![
        "ufw",
        "insert",
        "1",
        "deny",
        "from",
        ip,
        "comment",
        "innerwarden",
    ]
}

impl ResponseSkill for BlockIpUfw {
    fn id(&self) -> &'static str {
        "block-ip-ufw"
    }
    fn name(&self) -> &'static str {
        "Block IP via ufw"
    }
    fn description(&self) -> &'static str {
        "Permanently blocks the attacking IP using ufw (Uncomplicated Firewall). \
         Inserts a DENY rule at position 1 (with the 'innerwarden' comment) so it \
         wins over any broad `allow <port>` rules — ufw is first-match-wins, so an \
         appended deny would leak on already-allowed ports (80/443). \
         Requires: sudo ufw insert 1 deny from <IP> (configured in /etc/sudoers.d/innerwarden)."
    }
    fn tier(&self) -> SkillTier {
        SkillTier::Open
    }
    fn applicable_to(&self) -> &'static [&'static str] {
        &["ssh_bruteforce", "port_scan", "credential_stuffing"]
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
                        message: "block-ip-ufw: no target IP in context".to_string(),
                    }
                }
            };

            // Defense in depth: callers *should* validate targets before
            // reaching here, but a missed boundary must never trigger a
            // `ufw deny` for a malformed string. ufw silently accepts some
            // junk on add and then rejects revert, which manifests as an
            // orphaned-response alert on the dashboard.
            if !is_valid_firewall_target(&ip) {
                warn!(
                    ip,
                    "block-ip-ufw: rejecting invalid target before invoking ufw"
                );
                return SkillResult {
                    success: false,
                    message: format!("block-ip-ufw: {ip} is not a valid IP/CIDR"),
                };
            }

            if dry_run {
                info!(
                    ip,
                    "DRY RUN: would execute: sudo ufw insert 1 deny from {ip} comment 'innerwarden'"
                );
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would block {ip} via ufw"),
                };
            }

            // `ufw insert 1` — NOT a bare `ufw deny` (which appends). ufw evaluates
            // user rules top-to-bottom, first match wins. A web/hosting box has
            // broad `allow 80/443` rules; an APPENDED `deny from <ip>` sits below
            // them and never matches for HTTP traffic, so the attacker's flood is
            // allowed by the port rule and the "block" silently leaks (proven live
            // 2026-07-02: an abuser kept reaching :8080 through an appended deny;
            // inserting at position 1 cut it off). Position 1 puts the attacker
            // deny above every allow so it wins.
            let output = tokio::process::Command::new("sudo")
                .args(ufw_block_args(&ip))
                .output()
                .await;

            let result = format_skill_outcome("ufw", &ip, output);
            if result.success {
                info!(ip, "blocked via ufw");
            } else {
                warn!(ip, message = %result.message, "ufw block command failed");
            }
            result
        })
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
    async fn dry_run_ufw() {
        let ctx = make_ctx(Some("192.168.1.1"));
        let result = BlockIpUfw.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
        assert!(result.message.contains("192.168.1.1"));
    }

    #[tokio::test]
    async fn no_target_ip_ufw() {
        let ctx = make_ctx(None);
        let result = BlockIpUfw.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("no target IP"));
    }

    #[test]
    fn ufw_block_inserts_at_position_1_not_append() {
        // Regression anchor for the 2026-07-02 finding: a bare `ufw deny from` is
        // APPENDED and loses to a broad `allow 80/443` above it (first-match-wins),
        // so the block silently leaks on the exact ports a web host has open. The
        // deny must be inserted at position 1.
        let args = ufw_block_args("1.2.3.4");
        assert_eq!(
            &args[0..3],
            &["ufw", "insert", "1"],
            "must insert at position 1"
        );
        assert!(args.contains(&"deny") && args.contains(&"from") && args.contains(&"1.2.3.4"));
        assert!(args.contains(&"innerwarden"), "keeps the audit comment");
        // position of `1` is immediately after `insert` and before `deny`.
        let ins = args.iter().position(|a| *a == "insert").unwrap();
        assert_eq!(args[ins + 1], "1");
        assert!(args.iter().position(|a| *a == "deny").unwrap() > ins);
    }

    #[test]
    fn skill_metadata_ufw() {
        assert_eq!(BlockIpUfw.id(), "block-ip-ufw");
        assert!(BlockIpUfw.name().contains("ufw"));
        assert_eq!(BlockIpUfw.tier(), SkillTier::Open);
        assert!(BlockIpUfw.applicable_to().contains(&"credential_stuffing"));
    }

    // Invalid targets must fail the skill with success=false *without*
    // spawning a ufw subprocess. A dry-run passes through the validator
    // too, so this exercises both execution modes with a single ctx.
    #[tokio::test]
    async fn rejects_invalid_target_before_spawn() {
        for bad in ["129.950.5.0", "130.890.9.0", "137.274.6", "not-an-ip", ""] {
            let ctx = make_ctx(Some(bad));
            // dry_run=true proves the validator runs *before* the dry-run
            // branch — otherwise bad inputs would falsely report success.
            let result = BlockIpUfw.execute(&ctx, true).await;
            assert!(!result.success, "'{bad}' should be rejected");
            assert!(
                result.message.contains("not a valid"),
                "message for '{bad}' should explain the rejection, got: {}",
                result.message
            );
        }
    }

    #[tokio::test]
    async fn dry_run_accepts_valid_cidr() {
        let ctx = make_ctx(Some("10.0.0.0/24"));
        let result = BlockIpUfw.execute(&ctx, true).await;
        assert!(
            result.success,
            "CIDR /24 must be accepted: {:?}",
            result.message
        );
    }

    #[test]
    fn is_valid_firewall_target_accepts_ips_and_cidrs() {
        assert!(is_valid_firewall_target("1.2.3.4"));
        assert!(is_valid_firewall_target("2001:db8::1"));
        assert!(is_valid_firewall_target("10.0.0.0/8"));
        assert!(is_valid_firewall_target("2001:db8::/32"));
        assert!(is_valid_firewall_target("192.168.1.1/32"));
    }

    #[test]
    fn is_valid_firewall_target_rejects_malformed() {
        assert!(!is_valid_firewall_target(""));
        assert!(!is_valid_firewall_target("129.950.5.0"));
        assert!(!is_valid_firewall_target("130.890.9.0"));
        assert!(!is_valid_firewall_target("137.274.6"));
        assert!(!is_valid_firewall_target("not-an-ip"));
        assert!(!is_valid_firewall_target("10.0.0.0/33"));
        assert!(!is_valid_firewall_target("10.0.0.0/abc"));
        assert!(!is_valid_firewall_target("2001:db8::/129"));
    }
}
