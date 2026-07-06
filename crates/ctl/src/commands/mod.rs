pub(crate) mod agent;
pub(crate) mod agent_install_hook;
pub(crate) mod agent_mcp_serve;
pub(crate) mod agent_proxy;
pub(crate) mod ai;
pub(crate) mod audit;
pub(crate) mod capability;
pub(crate) mod chain_break;
pub(crate) mod circuit;
pub(crate) mod cloud_detect;
pub(crate) mod core;
pub(crate) mod dashboard;
pub(crate) mod exec_gate;
pub(crate) mod firmware;
pub(crate) mod history;
pub(crate) mod integrations;
pub(crate) mod mesh;
pub(crate) mod module;
pub(crate) mod notify;
pub(crate) mod ops;
pub(crate) mod playbook;
pub(crate) mod reconcile;
pub(crate) mod replay;
pub(crate) mod responder;
pub(crate) mod response;
pub(crate) mod rule;
pub(crate) mod setup;
pub(crate) mod status;

// sudo_guard is a unix sudoers.d helper (OpenOptionsExt/PermissionsExt +
// extern geteuid); it has no Windows portable form. On Windows (spec 085
// Phase 0) a stub bails so the two callers in main.rs still link; UAC/token
// elevation replaces sudo there in a later phase.
#[cfg(unix)]
pub(crate) mod sudo_guard;
#[cfg(windows)]
pub(crate) mod sudo_guard {
    use anyhow::{bail, Result};
    pub(crate) fn cmd_sudo_suspend(_user: &str, _expires: &str) -> Result<()> {
        bail!("sudo suspension is not supported on Windows")
    }
    pub(crate) fn cmd_sudo_restore(_user: &str) -> Result<()> {
        bail!("sudo suspension is not supported on Windows")
    }
}
pub(crate) mod uninstall;
pub(crate) mod update;
pub(crate) mod watchdog;
