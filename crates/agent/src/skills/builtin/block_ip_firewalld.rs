use std::future::Future;
use std::pin::Pin;

use tracing::{info, warn};

use super::firewall_target::{format_skill_outcome, is_valid_firewall_target};
use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

/// Block an attacking IP on hosts that use **firewalld** (RHEL, Rocky,
/// CentOS, Fedora, openSUSE). These distros ship firewalld and do NOT
/// have `ufw`, so the ufw/iptables backends silently no-op there: a
/// fresh InnerWarden install on Rocky could detect but never block
/// (readiness-audit B2). firewalld is the native, persistent-capable
/// front end to nftables/iptables on that whole distro family.
///
/// Uses a runtime rich rule (immediate effect), matching the
/// non-persistent-across-reboot behaviour of the iptables backend; the
/// description says so plainly so operators who need reboot persistence
/// add `--permanent` themselves. `firewall-cmd` lives at
/// `/usr/bin/firewall-cmd` on these distros, which is also what the
/// generated sudoers rule grants, so the bare `sudo firewall-cmd`
/// invocation resolves to the granted path (no path drift).
pub struct BlockIpFirewalld;

/// Build the firewalld rich rule that drops traffic from `ip`. Pure so
/// the rule string (and the v4/v6 family selection firewalld requires)
/// is unit-testable without invoking `firewall-cmd`. The caller MUST
/// have validated `ip` with `is_valid_firewall_target` first.
///
/// `priority="-1"` (a negative, i.e. low, priority) makes this source drop
/// evaluate BEFORE the zone's allowed services/ports — the firewalld analogue of
/// `ufw insert 1` / `iptables -I INPUT 1`. A default-priority (0) source drop can
/// be ordered after the port/service accepts, letting an attacker's HTTP flood
/// through on an already-open 80/443 (the same first-match leak fixed in the ufw
/// skill live on 2026-07-02; the firewalld path was not live-verified — only ufw
/// was — but the priority is the documented firewalld precedence mechanism).
fn build_block_rich_rule(ip: &str) -> String {
    let family = if ip.contains(':') { "ipv6" } else { "ipv4" };
    format!("rule priority=\"-1\" family=\"{family}\" source address=\"{ip}\" drop")
}

/// The decided action for a block-ip-firewalld call, separated from the
/// async `execute` so every decision branch (no target, invalid target,
/// dry-run, real block) is unit-testable without spawning `firewall-cmd`
/// or `sudo`. `execute` becomes a thin dispatcher over this; only the
/// `Execute` spawn arm touches I/O.
#[derive(Debug, PartialEq, Eq)]
enum FirewalldPlan {
    /// Refuse before touching the firewall (message is operator-facing).
    Reject(String),
    /// Dry-run: report intent, change nothing (message is operator-facing).
    DryRun(String),
    /// Run `sudo firewall-cmd --add-rich-rule=<rich_rule>` for `ip`.
    Execute { ip: String, rich_rule: String },
}

/// Pure decision step: validate the target and pick the action. No I/O,
/// no logging.
fn plan_firewalld_block(ctx: &SkillContext, dry_run: bool) -> FirewalldPlan {
    let ip = match &ctx.target_ip {
        Some(ip) => ip.clone(),
        None => return FirewalldPlan::Reject("block-ip-firewalld: no target IP in context".into()),
    };
    if !is_valid_firewall_target(&ip) {
        return FirewalldPlan::Reject(format!("block-ip-firewalld: {ip} is not a valid IP/CIDR"));
    }
    let rich_rule = build_block_rich_rule(&ip);
    if dry_run {
        return FirewalldPlan::DryRun(format!("DRY RUN: would block {ip} via firewalld"));
    }
    FirewalldPlan::Execute { ip, rich_rule }
}

impl ResponseSkill for BlockIpFirewalld {
    fn id(&self) -> &'static str {
        "block-ip-firewalld"
    }
    fn name(&self) -> &'static str {
        "Block IP via firewalld"
    }
    fn description(&self) -> &'static str {
        "Blocks the attacking IP with a firewalld rich rule (drop) on RHEL/Rocky/CentOS/Fedora. \
         Requires: sudo firewall-cmd --add-rich-rule=... (configured in /etc/sudoers.d/innerwarden). \
         Note: runtime rule (immediate); add --permanent manually if you need it to survive a firewalld reload."
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
            match plan_firewalld_block(ctx, dry_run) {
                FirewalldPlan::Reject(message) => {
                    warn!(%message, "block-ip-firewalld: refusing before invoking firewall-cmd");
                    SkillResult {
                        success: false,
                        message,
                    }
                }
                FirewalldPlan::DryRun(message) => {
                    info!(%message, "block-ip-firewalld dry-run");
                    SkillResult {
                        success: true,
                        message,
                    }
                }
                FirewalldPlan::Execute { ip, rich_rule } => {
                    let output = tokio::process::Command::new("sudo")
                        .args(["firewall-cmd", &format!("--add-rich-rule={rich_rule}")])
                        .output()
                        .await;
                    let result = format_skill_outcome("firewalld", &ip, output);
                    if result.success {
                        info!(ip, "blocked via firewalld");
                    } else {
                        warn!(ip, message = %result.message, "firewalld block command failed");
                    }
                    result
                }
            }
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

    #[test]
    fn rich_rule_selects_ipv4_family() {
        assert_eq!(
            build_block_rich_rule("203.0.113.5"),
            r#"rule priority="-1" family="ipv4" source address="203.0.113.5" drop"#
        );
    }

    #[test]
    fn rich_rule_selects_ipv6_family() {
        assert_eq!(
            build_block_rich_rule("2001:db8::1"),
            r#"rule priority="-1" family="ipv6" source address="2001:db8::1" drop"#
        );
    }

    #[test]
    fn rich_rule_has_low_priority_to_win_over_allows() {
        // Regression anchor: without a low (negative) priority a source-drop rich
        // rule can be ordered after the zone's allowed services, leaking on open
        // ports (the firewalld analogue of the ufw append leak).
        let r = build_block_rich_rule("203.0.113.5");
        assert!(
            r.contains(r#"priority="-1""#),
            "drop must have a low priority: {r}"
        );
        assert!(
            r.starts_with("rule priority="),
            "priority comes right after `rule`"
        );
    }

    #[test]
    fn metadata_is_firewalld() {
        assert_eq!(BlockIpFirewalld.id(), "block-ip-firewalld");
        assert!(BlockIpFirewalld.name().contains("firewalld"));
    }

    #[test]
    fn plan_rejects_missing_target() {
        match plan_firewalld_block(&make_ctx(None), false) {
            FirewalldPlan::Reject(m) => assert!(m.contains("no target IP")),
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn plan_rejects_invalid_target() {
        match plan_firewalld_block(&make_ctx(Some("not-an-ip")), false) {
            FirewalldPlan::Reject(m) => assert!(m.contains("not a valid")),
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn plan_dry_run_reports_intent_without_executing() {
        match plan_firewalld_block(&make_ctx(Some("203.0.113.5")), true) {
            FirewalldPlan::DryRun(m) => {
                assert!(m.contains("DRY RUN") && m.contains("203.0.113.5"))
            }
            other => panic!("expected DryRun, got {other:?}"),
        }
    }

    #[test]
    fn plan_execute_carries_validated_ip_and_rich_rule() {
        match plan_firewalld_block(&make_ctx(Some("203.0.113.5")), false) {
            FirewalldPlan::Execute { ip, rich_rule } => {
                assert_eq!(ip, "203.0.113.5");
                assert_eq!(
                    rich_rule,
                    r#"rule priority="-1" family="ipv4" source address="203.0.113.5" drop"#
                );
            }
            other => panic!("expected Execute, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dry_run_does_not_execute_and_reports_intent() {
        let result = BlockIpFirewalld
            .execute(&make_ctx(Some("203.0.113.5")), true)
            .await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
        assert!(result.message.contains("203.0.113.5"));
    }

    #[tokio::test]
    async fn rejects_missing_target() {
        let result = BlockIpFirewalld.execute(&make_ctx(None), true).await;
        assert!(!result.success);
        assert!(result.message.contains("no target IP"));
    }

    #[tokio::test]
    async fn rejects_invalid_target_before_invoking() {
        let result = BlockIpFirewalld
            .execute(&make_ctx(Some("not-an-ip")), false)
            .await;
        assert!(!result.success);
        assert!(result.message.contains("not a valid"));
    }
}
