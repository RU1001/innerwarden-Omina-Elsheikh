//! Misc config sections (allowlist, playbooks, agent metadata).
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

/// Entities in the allowlist are still logged and notified but skip the AI
/// gate - no automated response skill is ever executed for them.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct AllowlistConfig {
    /// IP addresses or CIDR ranges that are never auto-responded to.
    /// Examples: ["10.0.0.1", "192.168.0.0/24"]
    #[serde(default)]
    pub trusted_ips: Vec<String>,

    /// Usernames that are never auto-responded to.
    /// Examples: ["deploy", "backup"]
    #[serde(default)]
    pub trusted_users: Vec<String>,

    /// YOUR OWN infrastructure IPs/CIDRs (other boxes you run, a sibling
    /// server, a CI runner). Traffic whose external IPs are all your own
    /// infrastructure is treated as self-traffic: it is still detected and
    /// kept for training/investigation, but it is flagged `research_only` so
    /// it does NOT appear in the operator threats feed or the public live
    /// feed. This is for YOUR boxes only, set per deployment; it is empty by
    /// default and nothing is hardcoded into the product. Do NOT list a cloud
    /// provider range here to silence an attacker (attackers use the cloud
    /// too) - this is for addresses you own and control.
    /// Examples: ["172.212.178.34", "10.20.0.0/24"]
    #[serde(default)]
    pub self_infra_ips: Vec<String>,
}

/// Spec 056 SOC response playbooks.
///
/// Playbooks are deterministic, operator-authored incident-response runbooks
/// in `/etc/innerwarden/rules/playbooks/`. Phase 1 shipped the loader; Phase
/// 2 adds the executor. The `enabled` master switch defaults to `false` so a
/// fresh install (or an upgrade that has not yet opted in) never starts
/// auto-executing block/suspend steps from the built-in playbooks. CTL
/// (`innerwarden rule list --type playbooks`) lists them regardless.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaybooksConfig {
    /// Master switch. When false the agent does not run playbooks on
    /// incidents. Default `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Directory of operator playbook YAML files. Built-ins are always
    /// embedded regardless of this path. Default
    /// `/etc/innerwarden/rules/playbooks`.
    #[serde(default = "default_playbooks_dir")]
    pub rules_dir: String,
    /// Shadow mode. When true (and `enabled`), matching playbooks run for
    /// their audit trail ONLY — skills never fire and Phase-3b side effects
    /// (route_alert / capture_pcap / set_tag) are logged but not performed —
    /// REGARDLESS of `[responder] dry_run`. Lets an operator validate new
    /// playbooks on a live host (where the AI/decision path keeps blocking
    /// for real) without the unproven playbook engine touching anything.
    /// Default `false`.
    #[serde(default)]
    pub shadow: bool,
}

impl Default for PlaybooksConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rules_dir: default_playbooks_dir(),
            shadow: false,
        }
    }
}

/// `[agent]` section: per-host identity. Today it carries asset `tags`
/// (e.g. `["env=prod", "role=web"]`) that playbook `conditions.asset_tags`
/// match against, letting an operator scope a playbook to a host role.
/// Spec 058's server profiles will add `profile = "<id>"` here and select
/// via these same tags. Empty `tags` = a playbook with no `asset_tags`
/// condition still fires; one WITH an `asset_tags` condition stays inert
/// until the host is tagged.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSection {
    #[serde(default)]
    pub tags: Vec<String>,
}
