//! Dashboard config section.
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

/// Dashboard config - trusted proxy IPs and other dashboard-related settings.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardConfig {
    /// Master switch for the embedded dashboard server. Combined with
    /// the `--dashboard` CLI flag via AND: both must be set for the
    /// dashboard to spawn. Default: `true`, so existing deploys that
    /// rely on `--dashboard` alone are unchanged. Operators running
    /// `innerwarden-agent --dashboard` for ad-hoc checks but who
    /// want a permanent "headless agent" config can set this to
    /// `false`. The dashboard load also lazy-allocates the agent-
    /// guard regex engine (~36 MB live, per jeprof 2026-05-02) and
    /// the HTTP/TLS runtime — disabling it cuts ~50-70 MB RSS.
    #[serde(default = "default_dashboard_enabled")]
    pub enabled: bool,
    /// Listen address for the dashboard server, e.g. `"127.0.0.1:8787"`
    /// (loopback-only, the secure default) or `"0.0.0.0:8787"` (all
    /// interfaces — reachable on the public/LAN IP). When set, this takes
    /// precedence over the `--dashboard-bind` CLI flag, so operators configure
    /// dashboard access in ONE place (`agent.toml`) instead of editing the
    /// systemd unit / watchdog `--agent-arg`. `None` = fall back to the CLI
    /// flag (which defaults to loopback). Manage it with `innerwarden dashboard
    /// {status,expose,local}`.
    #[serde(default)]
    pub bind: Option<String>,
    /// List of trusted reverse-proxy IPs. Only when the connecting IP is in
    /// this list will X-Forwarded-For / X-Real-IP headers be honoured.
    /// Example: `["127.0.0.1", "::1", "10.0.0.1"]`
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Session inactivity timeout in minutes. Default: 480 (8 hours).
    #[serde(default = "default_session_timeout_minutes")]
    pub session_timeout_minutes: u64,
    /// Maximum number of concurrent sessions per user. Default: 5.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: default_dashboard_enabled(),
            bind: None,
            trusted_proxies: vec![],
            session_timeout_minutes: default_session_timeout_minutes(),
            max_sessions: default_max_sessions(),
        }
    }
}
