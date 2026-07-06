//! `[agent_guard]` config section — managed-agent coexistence (spec 081).
//!
//! Spec 081 withholds the auto-block / kernel-deny RESPONSE for a positively
//! verified, IW-managed AI agent acting on its OWN config / services. The
//! verifier's first signal is a registry hit (`registry.by_pid(pid)`). Today the
//! registry is only populated when the operator runs `innerwarden agent connect
//! <pid>`, and entries are PID-keyed — so when a co-located agent (OpenClaw)
//! restarts under a new pid, its entry is stale and the verifier fails closed,
//! re-severing the agent IW is meant to guard.
//!
//! This section gates the slow-loop registry reconciliation that keeps the
//! registry in sync with the live agent processes automatically. Default ON so
//! the product "just works" for a co-located agent; an operator who wants
//! manual-only control over the registry can set `auto_register = false`.

use super::*;

/// `[agent_guard]` — managed-agent coexistence behaviour.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentGuardConfig {
    /// Auto-register co-located AI agents detected on the host (and prune dead
    /// pids) on the slow loop so the spec-081 verifier's `by_pid` membership hint
    /// survives agent restarts. ON by default — auto-registration ONLY supplies
    /// the membership hint; the verifier still independently gates the response
    /// exemption on live re-ID + fingerprint + trusted-root + own-config + uid.
    #[serde(default = "default_auto_register")]
    pub auto_register: bool,
}

impl Default for AgentGuardConfig {
    fn default() -> Self {
        Self {
            auto_register: default_auto_register(),
        }
    }
}

fn default_auto_register() -> bool {
    true
}
