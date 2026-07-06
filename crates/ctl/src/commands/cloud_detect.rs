//! Cloud-platform detection → host-side allowlist of platform infrastructure.
//!
//! Some clouds use a fixed infrastructure IP OUTSIDE their published customer
//! ranges — e.g. Azure's "wireserver" `168.63.129.16` (DNS / DHCP / health /
//! PaaS), the same IP on every Azure VM. It is never an attacker, but the
//! agent's generic cloud safelist can't know it without hardcoding a never-block
//! IP into the product's block path (a published universal bypass + blind spot).
//!
//! Instead, `setup` detects the host's cloud (offline, via DMI) and writes the
//! platform infra into the HOST's allowlist — a server-side rule the operator
//! can see, edit, or remove in `agent.toml [allowlist]`. Per-host, automatic,
//! and out of the universal block path.

use anyhow::Result;

use crate::Cli;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloudPlatform {
    Azure,
    Aws,
    Gcp,
    Oracle,
}

impl CloudPlatform {
    pub(crate) fn label(self) -> &'static str {
        match self {
            CloudPlatform::Azure => "Azure",
            CloudPlatform::Aws => "AWS",
            CloudPlatform::Gcp => "GCP",
            CloudPlatform::Oracle => "Oracle Cloud",
        }
    }
}

/// Classify the host's cloud from DMI strings (offline, no network).
///
/// Azure is matched ONLY by its fixed chassis asset tag, never by `sys_vendor`
/// alone: an on-prem Hyper-V VM also reports vendor "Microsoft Corporation", and
/// misclassifying it as Azure would allowlist an IP it should not.
pub(crate) fn classify_cloud(
    asset_tag: &str,
    sys_vendor: &str,
    product_name: &str,
) -> Option<CloudPlatform> {
    let tag = asset_tag.trim();
    let vendor = sys_vendor.trim();
    let product = product_name.trim();

    // Azure stamps this exact chassis asset tag on every VM.
    if tag == "7783-7084-3265-9085-8269-3286-77" {
        return Some(CloudPlatform::Azure);
    }
    if vendor.contains("Amazon") || product.contains("Amazon EC2") {
        return Some(CloudPlatform::Aws);
    }
    if vendor.contains("Google") || product.contains("Google Compute Engine") {
        return Some(CloudPlatform::Gcp);
    }
    if vendor.contains("Oracle") || product.contains("Oracle") {
        return Some(CloudPlatform::Oracle);
    }
    None
}

/// Platform-infrastructure IPs to add to the host allowlist for a given cloud,
/// as `(ip_or_cidr, reason)`. Only platforms with a fixed IP outside their
/// published customer ranges need an entry; AWS / GCP / Oracle infra is already
/// covered by the agent's cloud-safelist ranges, so they return nothing.
pub(crate) fn platform_infra_allowlist(
    p: CloudPlatform,
) -> &'static [(&'static str, &'static str)] {
    match p {
        CloudPlatform::Azure => &[(
            "168.63.129.16",
            "Azure platform wireserver (DNS/DHCP/health) - host infrastructure, not an attacker",
        )],
        CloudPlatform::Aws | CloudPlatform::Gcp | CloudPlatform::Oracle => &[],
    }
}

/// Read a DMI field, trimmed. Empty string when unavailable (non-Linux, no
/// permission, or the file is absent).
fn read_dmi(name: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/dmi/id/{name}"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Detect the host's cloud platform from DMI. `None` when unknown / not a
/// recognized cloud (bare metal, unsupported provider).
pub(crate) fn detect_cloud() -> Option<CloudPlatform> {
    classify_cloud(
        &read_dmi("chassis_asset_tag"),
        &read_dmi("sys_vendor"),
        &read_dmi("product_name"),
    )
}

/// Setup step: detect the cloud and add its platform infrastructure to the host
/// allowlist (idempotent). Returns the number of entries added/ensured. Safe to
/// re-run; `cmd_allowlist_add` skips entries already present.
pub(crate) fn apply_cloud_platform_allowlist(cli: &Cli) -> Result<usize> {
    match detect_cloud() {
        Some(platform) => apply_for_platform(cli, platform),
        None => Ok(0),
    }
}

/// Add a known platform's infrastructure to the host allowlist. Split from
/// detection so it is testable without depending on the host's actual DMI.
pub(crate) fn apply_for_platform(cli: &Cli, platform: CloudPlatform) -> Result<usize> {
    let entries = platform_infra_allowlist(platform);
    if entries.is_empty() {
        println!(
            "  Detected {} — platform infrastructure already covered by the cloud safelist.",
            platform.label()
        );
        return Ok(0);
    }
    println!(
        "  Detected {} — adding platform infrastructure to the host allowlist:",
        platform.label()
    );
    for (ip, reason) in entries {
        crate::commands::response::cmd_allowlist_add(cli, Some(ip), None, Some(reason))?;
    }
    Ok(entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_azure_only_by_chassis_tag() {
        assert_eq!(
            classify_cloud(
                "7783-7084-3265-9085-8269-3286-77",
                "Microsoft Corporation",
                "Virtual Machine"
            ),
            Some(CloudPlatform::Azure)
        );
        // On-prem Hyper-V: same vendor, NO Azure tag → must NOT be Azure.
        assert_eq!(
            classify_cloud("", "Microsoft Corporation", "Virtual Machine"),
            None
        );
    }

    #[test]
    fn classify_aws_gcp_oracle_and_unknown() {
        assert_eq!(
            classify_cloud("", "Amazon EC2", "m5.large"),
            Some(CloudPlatform::Aws)
        );
        assert_eq!(
            classify_cloud("", "Google", "Google Compute Engine"),
            Some(CloudPlatform::Gcp)
        );
        assert_eq!(
            classify_cloud("", "Oracle Corporation", "Oracle Cloud"),
            Some(CloudPlatform::Oracle)
        );
        assert_eq!(classify_cloud("", "Dell Inc.", "PowerEdge R740"), None);
    }

    #[test]
    fn azure_has_wireserver_others_empty() {
        assert!(platform_infra_allowlist(CloudPlatform::Azure)
            .iter()
            .any(|(ip, _)| *ip == "168.63.129.16"));
        assert!(platform_infra_allowlist(CloudPlatform::Aws).is_empty());
        assert!(platform_infra_allowlist(CloudPlatform::Gcp).is_empty());
        assert!(platform_infra_allowlist(CloudPlatform::Oracle).is_empty());
    }

    #[test]
    fn labels_are_present_for_every_platform() {
        for p in [
            CloudPlatform::Azure,
            CloudPlatform::Aws,
            CloudPlatform::Gcp,
            CloudPlatform::Oracle,
        ] {
            assert!(!p.label().is_empty());
        }
    }

    fn test_cli(dir: &std::path::Path) -> Cli {
        let agent = dir.join("agent.toml");
        std::fs::write(&agent, "").unwrap();
        Cli {
            sensor_config: dir.join("config.toml"),
            agent_config: agent,
            data_dir: dir.to_path_buf(),
            dry_run: false,
            command: None,
        }
    }

    #[test]
    fn apply_for_platform_azure_writes_wireserver_to_allowlist() {
        let tmp = tempfile::tempdir().unwrap();
        let cli = test_cli(tmp.path());
        let n = apply_for_platform(&cli, CloudPlatform::Azure).expect("apply azure");
        assert_eq!(n, 1);
        let agent = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(
            agent.contains("168.63.129.16"),
            "wireserver must land in [allowlist] trusted_ips: {agent}"
        );
        // Idempotent: re-running does not duplicate.
        let n2 = apply_for_platform(&cli, CloudPlatform::Azure).expect("re-apply");
        assert_eq!(n2, 1);
        assert_eq!(
            std::fs::read_to_string(&cli.agent_config)
                .unwrap()
                .matches("168.63.129.16")
                .count(),
            1
        );
    }

    #[test]
    fn apply_for_platform_aws_adds_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let cli = test_cli(tmp.path());
        let n = apply_for_platform(&cli, CloudPlatform::Aws).expect("apply aws");
        assert_eq!(n, 0);
        assert!(!std::fs::read_to_string(&cli.agent_config)
            .unwrap()
            .contains("168.63"));
    }

    #[test]
    fn detect_cloud_runs_without_panic() {
        // Exercises read_dmi + detect_cloud on the test host (result varies by
        // environment; we only assert it does not panic).
        let _ = detect_cloud();
    }

    #[test]
    fn apply_cloud_platform_allowlist_wrapper_runs() {
        // Exercises the detect→apply wrapper end to end against a temp config.
        // Result depends on the host's DMI (Ok(0) off-cloud, Ok(1) on Azure CI),
        // so we only assert it does not error.
        let tmp = tempfile::tempdir().unwrap();
        let cli = test_cli(tmp.path());
        apply_cloud_platform_allowlist(&cli).expect("wrapper must not error");
    }
}
