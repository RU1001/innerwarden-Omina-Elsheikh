use std::future::Future;
use std::pin::Pin;

use tracing::{info, warn};

use super::firewall_target::{format_skill_outcome, is_valid_firewall_target};
use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

/// Block an attacking IP with the built-in Windows Firewall (spec 085 Phantom
/// Phase 2). The Windows analog of `block_ip_pf` (macOS) / `block_ip_ufw`
/// (Linux). Adds an inbound block rule via `netsh advfirewall firewall add rule`.
pub struct BlockIpWindows;

impl BlockIpWindows {
    /// The Windows Firewall rule name for a given target. The IP is already
    /// validated by [`is_valid_firewall_target`] before this is built, so it
    /// contains only IP/CIDR characters and is safe as a rule-name suffix.
    fn rule_name(ip: &str) -> String {
        format!("innerwarden-blocked-{ip}")
    }
}

impl ResponseSkill for BlockIpWindows {
    fn id(&self) -> &'static str {
        "block-ip-windows"
    }
    fn name(&self) -> &'static str {
        "Block IP via Windows Firewall"
    }
    fn description(&self) -> &'static str {
        "Permanently blocks the attacking IP using the built-in Windows Firewall. \
         Adds an inbound block rule via \
         `netsh advfirewall firewall add rule name=innerwarden-blocked-<IP> \
         dir=in action=block remoteip=<IP> enable=yes profile=any`, deleting any \
         prior rule for the same IP first so a repeat block replaces rather than \
         stacks duplicates. No third-party firewall required; the rule persists \
         across reboots. Requires an elevated context (the service runs as a \
         privileged account)."
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
                        message: "block-ip-windows: no target IP in context".to_string(),
                    }
                }
            };

            // Reject anything that is not a bare IP / CIDR BEFORE building the
            // netsh command. Combined with passing each token as a separate
            // process argument (no shell), this closes command-injection: the
            // IP can only ever be IP/CIDR characters.
            if !is_valid_firewall_target(&ip) {
                warn!(
                    ip,
                    "block-ip-windows: rejecting invalid target before invoking netsh"
                );
                return SkillResult {
                    success: false,
                    message: format!("block-ip-windows: {ip} is not a valid IP/CIDR"),
                };
            }

            let rule = Self::rule_name(&ip);

            if dry_run {
                info!(
                    ip,
                    "DRY RUN: would execute: netsh advfirewall firewall add rule \
                     name={rule} dir=in action=block remoteip={ip}"
                );
                return SkillResult {
                    success: true,
                    message: format!("DRY RUN: would block {ip} via Windows Firewall"),
                };
            }

            // netsh `add rule` is NOT idempotent: re-blocking the same IP stacks
            // duplicate rules with the same name (unlike pf's set-semantics
            // table). Delete any prior innerwarden rule for this IP first
            // (best-effort; "No rules match" is fine) so a repeat block replaces
            // rather than piles up.
            let _ = tokio::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={rule}"),
                ])
                .output()
                .await;

            // Each `key=value` token is a single argument; nothing goes through a
            // shell, so the validated IP cannot break out of its token.
            let output = tokio::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={rule}"),
                    "dir=in",
                    "action=block",
                    &format!("remoteip={ip}"),
                    "enable=yes",
                    "profile=any",
                ])
                .output()
                .await;

            let result = format_skill_outcome("windows-firewall", &ip, output);
            if result.success {
                info!(ip, "blocked via Windows Firewall");
            } else {
                warn!(ip, message = %result.message, "Windows Firewall block command failed");
            }
            result
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    async fn dry_run_logs_without_executing() {
        let ctx = make_ctx(Some("1.2.3.4"));
        let result = BlockIpWindows.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
        assert!(result.message.contains("1.2.3.4"));
    }

    #[tokio::test]
    async fn no_target_ip_returns_error() {
        let ctx = make_ctx(None);
        let result = BlockIpWindows.execute(&ctx, true).await;
        assert!(!result.success);
        assert!(result.message.contains("no target IP"));
    }

    #[test]
    fn skill_metadata() {
        assert_eq!(BlockIpWindows.id(), "block-ip-windows");
        assert!(BlockIpWindows.name().contains("Windows Firewall"));
        assert!(BlockIpWindows.description().contains("netsh"));
        assert_eq!(BlockIpWindows.tier(), SkillTier::Open);
        assert!(BlockIpWindows.applicable_to().contains(&"ssh_bruteforce"));
        assert!(BlockIpWindows.applicable_to().contains(&"port_scan"));
        assert!(BlockIpWindows
            .applicable_to()
            .contains(&"credential_stuffing"));
    }

    #[tokio::test]
    async fn rejects_invalid_target_before_spawn() {
        // Includes shell/netsh metacharacters: the validator must reject them so
        // they never reach the command builder.
        for bad in [
            "129.950.5.0",
            "not-an-ip",
            "",
            "1.2.3.4 && calc.exe",
            "1.2.3.4\"",
            "1.2.3.4|whoami",
        ] {
            let ctx = make_ctx(Some(bad));
            let result = BlockIpWindows.execute(&ctx, true).await;
            assert!(!result.success, "'{bad}' should be rejected");
        }
    }

    #[tokio::test]
    async fn dry_run_accepts_valid_cidr() {
        let ctx = make_ctx(Some("10.0.0.0/24"));
        let result = BlockIpWindows.execute(&ctx, true).await;
        assert!(result.success);
    }

    #[test]
    fn rule_name_embeds_validated_ip() {
        assert_eq!(
            BlockIpWindows::rule_name("203.0.113.9"),
            "innerwarden-blocked-203.0.113.9"
        );
    }
}
