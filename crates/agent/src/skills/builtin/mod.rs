mod block_container;
mod block_ip_firewalld;
mod block_ip_iptables;
mod block_ip_nftables;
mod block_ip_pf;
mod block_ip_ufw;
// Windows Firewall skill: registered only on Windows (spec 085 Phase 2). Also
// compiled in the `test` cfg so its OS-agnostic tests (validation + dry-run) run
// on the Linux CI host; on a non-test Linux/macOS build it is absent (it would
// otherwise be dead code, since the registry only wires it under cfg(windows)).
#[cfg(any(target_os = "windows", test))]
mod block_ip_windows;
mod block_ip_xdp;
mod firewall_target;
pub(crate) mod honeypot;
mod kill_chain_response;
mod kill_process;
mod monitor_ip;
mod rate_limit_nginx;
mod suspend_user_sudo;

pub use block_container::{cleanup_expired_container_blocks, BlockContainer};
pub use block_ip_firewalld::BlockIpFirewalld;
pub use block_ip_iptables::BlockIpIptables;
pub use block_ip_nftables::BlockIpNftables;
pub use block_ip_pf::BlockIpPf;
pub use block_ip_ufw::BlockIpUfw;
#[cfg(any(target_os = "windows", test))]
pub use block_ip_windows::BlockIpWindows;
pub use block_ip_xdp::{
    is_xdp_privilege_failure, xdp_blocklist_pin_for_ip, xdp_cleanup_backoff_secs, BlockIpXdp,
};
pub(crate) use honeypot::run_sandbox_worker as run_honeypot_sandbox_worker;
pub use honeypot::Honeypot;
pub use kill_chain_response::KillChainResponse;
pub use kill_process::KillProcess;
pub use monitor_ip::MonitorIp;
pub use rate_limit_nginx::{cleanup_expired_nginx_blocks, RateLimitNginx};
pub use suspend_user_sudo::{cleanup_expired_sudo_suspensions, SuspendUserSudo};
