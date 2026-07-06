use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,
    pub output: OutputConfig,
    #[serde(default)]
    pub collectors: CollectorsConfig,
    #[serde(default)]
    pub detectors: DetectorsConfig,
    #[serde(default)]
    pub calibration: CalibrationConfig,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    #[serde(default)]
    pub event_pipeline: EventPipelineConfig,
}

#[derive(Debug, Deserialize)]
pub struct EventPipelineConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_event_pipeline_rules_dir")]
    pub rules_dir: String,
}

impl Default for EventPipelineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_dir: default_event_pipeline_rules_dir(),
        }
    }
}

fn default_event_pipeline_rules_dir() -> String {
    "/etc/innerwarden/rules/event_pipeline".to_string()
}

#[derive(Debug, Default, Deserialize)]
pub struct AllowlistConfig {
    /// Users excluded from sudo abuse detection.
    #[serde(default)]
    pub trusted_users: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AgentConfig {
    pub host_id: String,
}

#[derive(Debug, Deserialize)]
pub struct OutputConfig {
    pub data_dir: String,
    #[serde(default = "default_true")]
    pub write_events: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct CollectorsConfig {
    #[serde(default)]
    pub auth_log: AuthLogConfig,
    #[serde(default)]
    pub integrity: IntegrityConfig,
    #[serde(default)]
    pub journald: JournaldConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    #[serde(default)]
    pub exec_audit: ExecAuditConfig,
    #[serde(default)]
    pub nginx_access: NginxAccessConfig,
    #[serde(default)]
    pub nginx_error: NginxErrorConfig,
    #[serde(default)]
    pub macos_log: MacosLogConfig,
    /// Windows ETW / Event Log collector (spec 085). OPT-IN like macos_log
    /// (defaults to `enabled = false`) so it never spawns on Linux/macOS
    /// prod; the spawn site additionally gates on `cfg!(target_os = "windows")`.
    #[serde(default)]
    pub windows_etw: WindowsEtwConfig,
    #[serde(default)]
    pub syslog_firewall: SyslogFirewallConfig,
    #[serde(default)]
    pub cloudtrail: CloudTrailConfig,

    // Always-on collectors. Pre-2026-05-25 each of these was hard-coded
    // to `tokio::spawn(...)` in boot/spawn_collectors.rs with no config
    // gate. That worked for prod (operator wants every layer of the
    // defence on by default) but made `run_loop` untestable — the
    // spawned tasks each cloned `tx` and looped forever, so
    // `rx.recv()` never returned `None`. Adding individual config
    // sections (each defaulting to `enabled = true` so prod TOML
    // doesn't have to declare them — omission == on) lets
    // `Config::test_default` flip them all off via
    // `CollectorsConfig::all_disabled` and makes the run_loop side
    // unit-testable, mirroring the boot_init coverage shipped in #813.
    #[serde(default)]
    pub ebpf_syscall: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub firmware_integrity: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub proc_maps: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub fanotify_watch: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub kernel_integrity: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub cgroup_abuse: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub dns_capture: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub http_capture: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub net_snapshot: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub usb_monitor: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub suid_inventory: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub sysctl_drift: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub systemd_inventory: AlwaysOnCollectorConfig,
    #[serde(default)]
    pub tcp_stream: AlwaysOnCollectorConfig,
    /// audit_state (spec 074): polls the kernel audit `enabled` flag and emits
    /// `audit.disabled` when it is found off (method-independent T1562.001).
    /// Default-on like the other always-on collectors; fail-open if auditctl
    /// is absent.
    #[serde(default)]
    pub audit_state: AlwaysOnCollectorConfig,
    /// tunnel_iface: watches `/sys/class/net` for a NEW tun/WireGuard
    /// interface appearing at runtime — the rename-proof behavioural signal
    /// of a mesh/overlay VPN being brought up (complements the c2_web_tunnel
    /// exec-name detection). Interfaces present at startup are baselined.
    #[serde(default)]
    pub tunnel_iface: AlwaysOnCollectorConfig,
}

impl CollectorsConfig {
    /// Construct a CollectorsConfig with every collector explicitly
    /// disabled — for unit tests that spin up a Config and call
    /// `boot::spawn_collectors::spawn_collectors` without also kicking
    /// off every always-on background task.
    ///
    /// Unlike `Default::default()`, this is **not** the production
    /// default — production omits unset sections and they fall back to
    /// `enabled = true` via [`AlwaysOnCollectorConfig::default`]. Tests
    /// that just want a quiet Config should prefer
    /// [`Config::test_default`], which already calls this.
    pub(crate) fn all_disabled() -> Self {
        Self {
            // Sections whose Default already produces enabled = false.
            integrity: IntegrityConfig::default(),
            journald: JournaldConfig::default(),
            docker: DockerConfig::default(),
            exec_audit: ExecAuditConfig::default(),
            nginx_access: NginxAccessConfig::default(),
            nginx_error: NginxErrorConfig::default(),
            macos_log: MacosLogConfig::default(),
            // Default already produces enabled = false (opt-in).
            windows_etw: WindowsEtwConfig::default(),
            syslog_firewall: SyslogFirewallConfig::default(),
            cloudtrail: CloudTrailConfig::default(),
            // auth_log defaults to enabled = true (sshd auth is the
            // baseline signal everyone wants on). Explicitly disable
            // it here so tests don't try to tail /var/log/auth.log.
            auth_log: AuthLogConfig {
                enabled: false,
                ..AuthLogConfig::default()
            },
            // Always-on collectors: default-true in prod, explicit
            // false here.
            ebpf_syscall: AlwaysOnCollectorConfig { enabled: false },
            firmware_integrity: AlwaysOnCollectorConfig { enabled: false },
            proc_maps: AlwaysOnCollectorConfig { enabled: false },
            fanotify_watch: AlwaysOnCollectorConfig { enabled: false },
            kernel_integrity: AlwaysOnCollectorConfig { enabled: false },
            cgroup_abuse: AlwaysOnCollectorConfig { enabled: false },
            dns_capture: AlwaysOnCollectorConfig { enabled: false },
            http_capture: AlwaysOnCollectorConfig { enabled: false },
            net_snapshot: AlwaysOnCollectorConfig { enabled: false },
            usb_monitor: AlwaysOnCollectorConfig { enabled: false },
            suid_inventory: AlwaysOnCollectorConfig { enabled: false },
            sysctl_drift: AlwaysOnCollectorConfig { enabled: false },
            systemd_inventory: AlwaysOnCollectorConfig { enabled: false },
            tcp_stream: AlwaysOnCollectorConfig { enabled: false },
            audit_state: AlwaysOnCollectorConfig { enabled: false },
            tunnel_iface: AlwaysOnCollectorConfig { enabled: false },
        }
    }
}

/// Minimal config for collectors that were hard-coded `tokio::spawn`
/// pre-2026-05-25. Single `enabled: bool` field, defaults to `true`
/// so existing production configs (which never declared these
/// sections) keep spawning every always-on collector.
#[derive(Debug, Deserialize, Clone, Copy)]
pub struct AlwaysOnCollectorConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for AlwaysOnCollectorConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MacosLogConfig {
    #[serde(default)]
    pub enabled: bool,
}

/// Windows ETW / Event Log collector config (spec 085).
///
/// OPT-IN: `enabled` defaults to `false` (mirrors [`MacosLogConfig`]) so an
/// existing Linux/macOS prod TOML upgrades with no edits and never spawns
/// this collector. Windows operators turn it on with:
///
/// ```toml
/// [collectors.windows_etw]
/// enabled = true
/// # optional overrides (defaults shown):
/// # channels = ["Security", "Microsoft-Windows-Sysmon/Operational"]
/// # poll_seconds = 5
/// # batch_cap = 200
/// ```
///
/// The tuning fields each carry a `#[serde(default = "...")]` (like
/// [`ExecAuditConfig`]) so a partial `[collectors.windows_etw]` section still
/// parses. They are threaded into `WindowsEtwCollector` in
/// `boot::spawn_collectors` via its `with_*` builders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsEtwConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_etw_channels")]
    pub channels: Vec<String>,
    #[serde(default = "default_etw_poll_seconds")]
    pub poll_seconds: u64,
    #[serde(default = "default_etw_batch_cap")]
    pub batch_cap: u32,
}

impl Default for WindowsEtwConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            channels: default_etw_channels(),
            poll_seconds: default_etw_poll_seconds(),
            batch_cap: default_etw_batch_cap(),
        }
    }
}

fn default_etw_channels() -> Vec<String> {
    vec![
        "Security".to_string(),
        "Microsoft-Windows-Sysmon/Operational".to_string(),
    ]
}

fn default_etw_poll_seconds() -> u64 {
    5
}

fn default_etw_batch_cap() -> u32 {
    200
}

#[derive(Debug, Deserialize)]
pub struct ExecAuditConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_exec_audit_path")]
    pub path: String,
    #[serde(default)]
    pub include_tty: bool,
}

impl Default for ExecAuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_exec_audit_path(),
            include_tty: false,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct JournaldConfig {
    #[serde(default)]
    pub enabled: bool,
    /// systemd unit names to filter on (e.g. "sshd", "sudo"). Empty = all units.
    #[serde(default = "default_journald_units")]
    pub units: Vec<String>,
}

impl Default for JournaldConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            units: default_journald_units(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct DockerConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct IntegrityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_poll_seconds")]
    pub poll_seconds: u64,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            paths: vec![],
            poll_seconds: default_poll_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthLogConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_auth_log_path")]
    pub path: String,
}

impl Default for AuthLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_auth_log_path(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct DetectorsConfig {
    #[serde(default)]
    pub ssh_bruteforce: SshBruteforceConfig,
    #[serde(default)]
    pub credential_stuffing: CredentialStuffingConfig,
    #[serde(default)]
    pub port_scan: PortScanConfig,
    #[serde(default)]
    pub sudo_abuse: SudoAbuseConfig,
    #[serde(default)]
    pub search_abuse: SearchAbuseConfig,
    #[serde(default)]
    pub web_scan: WebScanConfig,
    #[serde(default)]
    pub user_agent_scanner: UserAgentScannerConfig,
    #[serde(default)]
    pub execution_guard: ExecutionGuardConfig,
    #[serde(default)]
    pub docker_anomaly: DockerAnomalyConfig,
    #[serde(default)]
    pub integrity_alert: IntegrityAlertConfig,
    #[serde(default)]
    pub setns_owner: SetnsOwnerConfig,
    #[serde(default)]
    pub untrusted_root_exec: UntrustedRootExecConfig,
    #[serde(default)]
    pub log_tampering: LogTamperingConfig,
    #[serde(default)]
    pub dns_tunneling: DnsTunnelingConfig,
    #[serde(default)]
    pub lateral_movement: LateralMovementConfig,
    #[serde(default)]
    pub crypto_miner: CryptoMinerConfig,
    #[serde(default)]
    pub outbound_anomaly: OutboundAnomalyConfig,
    #[serde(default)]
    pub rootkit: RootkitConfig,
    #[serde(default)]
    pub reverse_shell: ReverseShellConfig,
    #[serde(default)]
    pub ssh_key_injection: SshKeyInjectionConfig,
    #[serde(default)]
    pub web_shell: WebShellConfig,
    #[serde(default)]
    pub kernel_module_load: KernelModuleLoadConfig,
    #[serde(default)]
    pub crontab_persistence: CrontabPersistenceConfig,
    #[serde(default)]
    pub data_exfiltration: DataExfiltrationConfig,
    #[serde(default)]
    pub process_injection: ProcessInjectionConfig,
    #[serde(default)]
    pub user_creation: UserCreationConfig,
    #[serde(default)]
    pub systemd_persistence: SystemdPersistenceConfig,
    #[serde(default)]
    pub ransomware: RansomwareConfig,
    #[serde(default)]
    pub credential_harvest: CredentialHarvestConfig,
    #[serde(default)]
    pub packet_flood: PacketFloodConfig,
    #[serde(default)]
    pub suspicious_login: SuspiciousLoginConfig,
    #[serde(default)]
    pub suid_page_cache_integrity: SuidPageCacheIntegrityConfig,
    #[serde(default)]
    pub kernel_devnode_exposed: KernelDevnodeExposedConfig,
    #[serde(default)]
    pub imds_ssrf: ImdsSsrfConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct SuspiciousLoginConfig {
    /// Enable time-of-day anomaly detection based on a 7-day user login baseline.
    /// When true, logins outside a user's normal hours fire a Medium-severity incident.
    #[serde(default)]
    pub anomaly_hours_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct SuidPageCacheIntegrityConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_suid_page_cache_integrity_poll_interval_secs")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_suid_page_cache_integrity_allowlist")]
    pub allowlist: Vec<String>,
}

impl Default for SuidPageCacheIntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: default_suid_page_cache_integrity_poll_interval_secs(),
            allowlist: default_suid_page_cache_integrity_allowlist(),
        }
    }
}

fn default_suid_page_cache_integrity_poll_interval_secs() -> u64 {
    crate::detectors::suid_page_cache_integrity::DEFAULT_POLL_INTERVAL_SECS
}

fn default_suid_page_cache_integrity_allowlist() -> Vec<String> {
    crate::detectors::suid_page_cache_integrity::DEFAULT_ALLOWLIST
        .iter()
        .map(|path| (*path).to_string())
        .collect()
}

/// Per-pattern entry in the operator-tunable kernel devnode watchlist.
///
/// `max_allowed_mode_octal` is parsed as octal (so a TOML value like
/// "0o660" or "660" both work). When parsing fails we fall back to the
/// hardcoded default for that pattern so a typo cannot accidentally
/// disable detection by widening the allowed mode to all bits.
#[derive(Debug, Deserialize, Clone)]
pub struct KernelDevnodeWatchEntryConfig {
    pub pattern: String,
    pub max_allowed_mode_octal: String,
    #[serde(default)]
    pub surface: String,
}

#[derive(Debug, Deserialize)]
pub struct KernelDevnodeExposedConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_kernel_devnode_exposed_poll_interval_secs")]
    pub poll_interval_secs: u64,
    /// Per-path explicit exclusions. A path matched by `expand()` that
    /// appears here is silently skipped even when exposed — useful for
    /// dedicated RDMA / KVM hosts where the operator intentionally
    /// widens permissions.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Operator overrides for the default watchlist. Each entry replaces
    /// the built-in entry for the same `pattern` if present; otherwise
    /// it extends the watchlist with a new pattern.
    #[serde(default)]
    pub overrides: Vec<KernelDevnodeWatchEntryConfig>,
}

impl Default for KernelDevnodeExposedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: default_kernel_devnode_exposed_poll_interval_secs(),
            allowlist: Vec::new(),
            overrides: Vec::new(),
        }
    }
}

fn default_kernel_devnode_exposed_poll_interval_secs() -> u64 {
    crate::detectors::kernel_devnode_exposed::DEFAULT_POLL_INTERVAL_SECS
}

/// IMDS SSRF detector — watches outbound connects to cloud-metadata
/// endpoints (`169.254.169.254` / `fd00:ec2::254`) and fires when the
/// accessing process is not in the built-in cloud-tool allowlist.
///
/// Default enabled because the detector is FP-safe by construction
/// (only fires when a non-cloud-tool process explicitly hits IMDS).
/// `allowlist_comms` is the operator escape hatch for app processes
/// that legitimately use IAM via the cloud SDKs — adding `python3`
/// silences the HIGH-tier alert for that comm only.
///
/// Example TOML:
///
/// ```toml
/// [detectors.imds_ssrf]
/// enabled = true
/// cooldown_seconds = 600
/// allowlist_comms = ["python3", "ruby"]
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct ImdsSsrfConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_imds_ssrf_cooldown_seconds")]
    pub cooldown_seconds: u64,
    /// DEPRECATED (2026-05-31): comm is forgeable (`prctl(PR_SET_NAME)` /
    /// `argv[0]`), so a comm allowlist is a detector BYPASS — an attacker
    /// names their tool `cloud-init` and IMDS cred-theft is ignored. This
    /// field is accepted for config back-compat but **no longer gates**
    /// legitimacy. Use `allowlist_exe_prefixes` instead.
    #[serde(default)]
    pub allowlist_comms: Vec<String>,
    /// Operator-extended legitimacy allowlist, matched against the accessing
    /// process's real executable path (`exe_path`, captured at execve / read
    /// from `/proc/<pid>/exe`) with `starts_with`. Non-forgeable: an attacker
    /// cannot run from a root-owned vendor path without already being root.
    /// Use directory prefixes with a trailing `/` (e.g.
    /// `"/snap/my-cloud-agent/"`) to avoid sibling-directory spoofing.
    #[serde(default)]
    pub allowlist_exe_prefixes: Vec<String>,
}

impl Default for ImdsSsrfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_imds_ssrf_cooldown_seconds(),
            allowlist_comms: Vec::new(),
            allowlist_exe_prefixes: Vec::new(),
        }
    }
}

fn default_imds_ssrf_cooldown_seconds() -> u64 {
    crate::detectors::imds_ssrf::DEFAULT_COOLDOWN_SECONDS
}

#[derive(Debug, Deserialize)]
pub struct SshBruteforceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold")]
    pub threshold: usize,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
}

impl Default for SshBruteforceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: default_threshold(),
            window_seconds: default_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CredentialStuffingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_credential_stuffing_threshold")]
    pub threshold: usize,
    #[serde(default = "default_credential_stuffing_window_seconds")]
    pub window_seconds: u64,
}

impl Default for CredentialStuffingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_credential_stuffing_threshold(),
            window_seconds: default_credential_stuffing_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PortScanConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_port_scan_threshold")]
    pub threshold: usize,
    #[serde(default = "default_port_scan_window_seconds")]
    pub window_seconds: u64,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_port_scan_threshold(),
            window_seconds: default_port_scan_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SudoAbuseConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_sudo_abuse_threshold")]
    pub threshold: usize,
    #[serde(default = "default_sudo_abuse_window_seconds")]
    pub window_seconds: u64,
}

impl Default for SudoAbuseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_sudo_abuse_threshold(),
            window_seconds: default_sudo_abuse_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NginxAccessConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_nginx_access_path")]
    pub path: String,
}

impl Default for NginxAccessConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_nginx_access_path(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SearchAbuseConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_search_abuse_threshold")]
    pub threshold: usize,
    #[serde(default = "default_search_abuse_window_seconds")]
    pub window_seconds: u64,
    /// Path prefix to monitor. Empty string means all paths.
    #[serde(default = "default_search_abuse_path_prefix")]
    pub path_prefix: String,
}

impl Default for SearchAbuseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_search_abuse_threshold(),
            window_seconds: default_search_abuse_window_seconds(),
            path_prefix: default_search_abuse_path_prefix(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ExecutionGuardConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Execution mode. Only "observe" is implemented in this version.
    /// Future: "contain" (suspend-user-sudo + isolate session) and
    ///         "strict" (pre-execution interception via eBPF/LSM).
    #[serde(default = "default_execution_guard_mode")]
    pub mode: String,
    /// Correlation window for timeline sequence detection (default: 300s)
    #[serde(default = "default_execution_guard_window_seconds")]
    pub window_seconds: u64,
}

impl Default for ExecutionGuardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_execution_guard_mode(),
            window_seconds: default_execution_guard_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DockerAnomalyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_docker_anomaly_threshold")]
    pub threshold: usize,
    #[serde(default = "default_docker_anomaly_window_seconds")]
    pub window_seconds: u64,
}

impl Default for DockerAnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_docker_anomaly_threshold(),
            window_seconds: default_docker_anomaly_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct IntegrityAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_integrity_alert_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

/// Spec 070 — untrusted namespace-pivot detector. Default ON: it is a
/// low-noise, technique-independent privilege-escalation signal (root joining a
/// user namespace outside any container runtime context).
#[derive(Debug, Deserialize)]
pub struct SetnsOwnerConfig {
    #[serde(default = "default_setns_owner_enabled")]
    pub enabled: bool,
    #[serde(default = "default_setns_owner_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for SetnsOwnerConfig {
    fn default() -> Self {
        Self {
            enabled: default_setns_owner_enabled(),
            cooldown_seconds: default_setns_owner_cooldown_seconds(),
        }
    }
}

/// Spec 070 — untrusted-root-execution detector. Default ON: uid-0 execution of
/// a binary from an unprivileged-writable path (outside any container) is the
/// most technique-independent post-exploit signal there is.
#[derive(Debug, Deserialize)]
pub struct UntrustedRootExecConfig {
    #[serde(default = "default_untrusted_root_exec_enabled")]
    pub enabled: bool,
    #[serde(default = "default_untrusted_root_exec_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for UntrustedRootExecConfig {
    fn default() -> Self {
        Self {
            enabled: default_untrusted_root_exec_enabled(),
            cooldown_seconds: default_untrusted_root_exec_cooldown_seconds(),
        }
    }
}

impl Default for IntegrityAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cooldown_seconds: default_integrity_alert_cooldown_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LogTamperingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_log_tampering_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for LogTamperingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_log_tampering_cooldown_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DnsTunnelingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dns_tunneling_entropy_threshold")]
    pub entropy_threshold: f64,
    #[serde(default = "default_dns_tunneling_volume_threshold")]
    pub volume_threshold: usize,
    #[serde(default = "default_dns_tunneling_length_threshold")]
    pub length_threshold: usize,
    #[serde(default = "default_dns_tunneling_window_seconds")]
    pub window_seconds: u64,
}

impl Default for DnsTunnelingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            entropy_threshold: default_dns_tunneling_entropy_threshold(),
            volume_threshold: default_dns_tunneling_volume_threshold(),
            length_threshold: default_dns_tunneling_length_threshold(),
            window_seconds: default_dns_tunneling_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LateralMovementConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_lateral_movement_ssh_threshold")]
    pub ssh_threshold: usize,
    #[serde(default = "default_lateral_movement_scan_threshold")]
    pub scan_threshold: usize,
    #[serde(default = "default_lateral_movement_window_seconds")]
    pub window_seconds: u64,
}

impl Default for LateralMovementConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ssh_threshold: default_lateral_movement_ssh_threshold(),
            scan_threshold: default_lateral_movement_scan_threshold(),
            window_seconds: default_lateral_movement_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CryptoMinerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_crypto_miner_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for CryptoMinerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_crypto_miner_cooldown_seconds(),
        }
    }
}

fn default_crypto_miner_cooldown_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct OutboundAnomalyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_outbound_anomaly_connection_flood_threshold")]
    pub connection_flood_threshold: usize,
    #[serde(default = "default_outbound_anomaly_port_spray_threshold")]
    pub port_spray_threshold: usize,
    #[serde(default = "default_outbound_anomaly_udp_flood_threshold")]
    pub udp_flood_threshold: usize,
    #[serde(default = "default_outbound_anomaly_fanout_threshold")]
    pub fanout_threshold: usize,
    #[serde(default = "default_outbound_anomaly_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_outbound_anomaly_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for OutboundAnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            connection_flood_threshold: default_outbound_anomaly_connection_flood_threshold(),
            port_spray_threshold: default_outbound_anomaly_port_spray_threshold(),
            udp_flood_threshold: default_outbound_anomaly_udp_flood_threshold(),
            fanout_threshold: default_outbound_anomaly_fanout_threshold(),
            window_seconds: default_outbound_anomaly_window_seconds(),
            cooldown_seconds: default_outbound_anomaly_cooldown_seconds(),
        }
    }
}

fn default_outbound_anomaly_connection_flood_threshold() -> usize {
    50
}

fn default_outbound_anomaly_port_spray_threshold() -> usize {
    20
}

fn default_outbound_anomaly_udp_flood_threshold() -> usize {
    100
}

fn default_outbound_anomaly_fanout_threshold() -> usize {
    10
}

fn default_outbound_anomaly_window_seconds() -> u64 {
    60
}

fn default_outbound_anomaly_cooldown_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct RootkitConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_rootkit_check_interval_seconds")]
    pub check_interval_seconds: u64,
    #[serde(default = "default_rootkit_cooldown_seconds")]
    pub cooldown_seconds: u64,
    /// Enable kernel function timing analysis for rootkit detection.
    /// Detects syscall hooks by measuring inter-event timing anomalies.
    #[serde(default = "default_true")]
    pub timing_enabled: bool,
    /// Minimum samples before a syscall timing profile is considered trained.
    #[serde(default = "default_rootkit_timing_min_samples")]
    pub timing_min_samples: u64,
    /// Z-score threshold for flagging a single timing anomaly.
    #[serde(default = "default_rootkit_timing_z_threshold")]
    pub timing_z_threshold: f64,
    /// Consecutive anomalous timings required to raise an incident.
    #[serde(default = "default_rootkit_timing_consecutive_threshold")]
    pub timing_consecutive_threshold: usize,
}

impl Default for RootkitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: default_rootkit_check_interval_seconds(),
            cooldown_seconds: default_rootkit_cooldown_seconds(),
            timing_enabled: true,
            timing_min_samples: default_rootkit_timing_min_samples(),
            timing_z_threshold: default_rootkit_timing_z_threshold(),
            timing_consecutive_threshold: default_rootkit_timing_consecutive_threshold(),
        }
    }
}

fn default_rootkit_check_interval_seconds() -> u64 {
    60
}

fn default_rootkit_cooldown_seconds() -> u64 {
    600
}

fn default_rootkit_timing_min_samples() -> u64 {
    100
}

fn default_rootkit_timing_z_threshold() -> f64 {
    // Cloud VMs have network-attached disks with I/O jitter that causes
    // z-scores of 15-47 regularly. Real rootkits cause z-scores >100
    // consistently. Auto-detect cloud and use a higher threshold.
    if is_cloud_vm() {
        20.0
    } else {
        4.0
    }
}

/// Detect if running on a cloud VM by reading DMI product_name/sys_vendor.
/// Used to auto-calibrate timing thresholds that are sensitive to I/O jitter
/// from network-attached storage.
fn is_cloud_vm() -> bool {
    let product_name = std::fs::read_to_string("/sys/class/dmi/id/product_name")
        .unwrap_or_default()
        .to_lowercase();
    let sys_vendor = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor")
        .unwrap_or_default()
        .to_lowercase();
    let combined = format!("{product_name} {sys_vendor}");

    // Match known cloud providers and hypervisors
    [
        "oracle",
        "oci",
        "amazon",
        "aws",
        "ec2",
        "google",
        "gce",
        "microsoft",
        "azure",
        "hyper-v",
        "digitalocean",
        "hetzner",
        "linode",
        "akamai",
        "vultr",
        "ovh",
        "vmware",
        "virtualbox",
        "qemu",
        "kvm",
        "xen",
        "bhyve",
    ]
    .iter()
    .any(|sig| combined.contains(sig))
}

fn default_rootkit_timing_consecutive_threshold() -> usize {
    5
}

#[derive(Debug, Deserialize)]
pub struct ReverseShellConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_reverse_shell_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for ReverseShellConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_reverse_shell_cooldown_seconds(),
        }
    }
}

fn default_reverse_shell_cooldown_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct SshKeyInjectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_ssh_key_injection_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for SshKeyInjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_ssh_key_injection_cooldown_seconds(),
        }
    }
}

fn default_ssh_key_injection_cooldown_seconds() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct WebShellConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_web_shell_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for WebShellConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_web_shell_cooldown_seconds(),
        }
    }
}

fn default_web_shell_cooldown_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct KernelModuleLoadConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_kernel_module_load_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for KernelModuleLoadConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_kernel_module_load_cooldown_seconds(),
        }
    }
}

fn default_kernel_module_load_cooldown_seconds() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct CrontabPersistenceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_crontab_persistence_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for CrontabPersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_crontab_persistence_cooldown_seconds(),
        }
    }
}

fn default_crontab_persistence_cooldown_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct DataExfiltrationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_data_exfiltration_correlation_window_seconds")]
    pub correlation_window_seconds: u64,
    #[serde(default = "default_data_exfiltration_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for DataExfiltrationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            correlation_window_seconds: default_data_exfiltration_correlation_window_seconds(),
            cooldown_seconds: default_data_exfiltration_cooldown_seconds(),
        }
    }
}

fn default_data_exfiltration_correlation_window_seconds() -> u64 {
    60
}

fn default_data_exfiltration_cooldown_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct ProcessInjectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_process_injection_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for ProcessInjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_process_injection_cooldown_seconds(),
        }
    }
}

fn default_process_injection_cooldown_seconds() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct UserCreationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_user_creation_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for UserCreationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_user_creation_cooldown_seconds(),
        }
    }
}

fn default_user_creation_cooldown_seconds() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct SystemdPersistenceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_systemd_persistence_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for SystemdPersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_systemd_persistence_cooldown_seconds(),
        }
    }
}

fn default_systemd_persistence_cooldown_seconds() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct RansomwareConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_ransomware_file_threshold")]
    pub file_threshold: usize,
    #[serde(default = "default_ransomware_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_ransomware_cooldown_seconds")]
    pub cooldown_seconds: u64,
    /// Shannon entropy threshold (bits/byte). Writes with entropy above this are
    /// considered encrypted. Default 7.5 (max is 8.0 for perfectly random data).
    #[serde(default = "default_ransomware_entropy_threshold")]
    pub entropy_threshold: f64,
    /// Number of high-entropy writes per process before triggering a Critical alert.
    /// Default 3 - detect ransomware on the first few encrypted files.
    #[serde(default = "default_ransomware_entropy_count_threshold")]
    pub entropy_count_threshold: usize,
}

impl Default for RansomwareConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file_threshold: default_ransomware_file_threshold(),
            window_seconds: default_ransomware_window_seconds(),
            cooldown_seconds: default_ransomware_cooldown_seconds(),
            entropy_threshold: default_ransomware_entropy_threshold(),
            entropy_count_threshold: default_ransomware_entropy_count_threshold(),
        }
    }
}

fn default_ransomware_file_threshold() -> usize {
    50
}

fn default_ransomware_window_seconds() -> u64 {
    30
}

fn default_ransomware_cooldown_seconds() -> u64 {
    60
}

fn default_ransomware_entropy_threshold() -> f64 {
    7.5
}

fn default_ransomware_entropy_count_threshold() -> usize {
    3
}

#[derive(Debug, Deserialize)]
pub struct CredentialHarvestConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_credential_harvest_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for CredentialHarvestConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: default_credential_harvest_cooldown_seconds(),
        }
    }
}

fn default_credential_harvest_cooldown_seconds() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct PacketFloodConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_packet_flood_syn_threshold")]
    pub syn_threshold: usize,
    #[serde(default = "default_packet_flood_http_threshold")]
    pub http_threshold: usize,
    #[serde(default = "default_packet_flood_slowloris_threshold")]
    pub slowloris_threshold: usize,
    #[serde(default = "default_packet_flood_udp_threshold")]
    pub udp_threshold: usize,
    #[serde(default = "default_packet_flood_rate_multiplier")]
    pub rate_multiplier: f64,
    #[serde(default = "default_packet_flood_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_packet_flood_cooldown_seconds")]
    pub cooldown_seconds: u64,
}

impl Default for PacketFloodConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            syn_threshold: default_packet_flood_syn_threshold(),
            http_threshold: default_packet_flood_http_threshold(),
            slowloris_threshold: default_packet_flood_slowloris_threshold(),
            udp_threshold: default_packet_flood_udp_threshold(),
            rate_multiplier: default_packet_flood_rate_multiplier(),
            window_seconds: default_packet_flood_window_seconds(),
            cooldown_seconds: default_packet_flood_cooldown_seconds(),
        }
    }
}

fn default_packet_flood_syn_threshold() -> usize {
    100
}

fn default_packet_flood_http_threshold() -> usize {
    200
}

fn default_packet_flood_slowloris_threshold() -> usize {
    50
}

fn default_packet_flood_udp_threshold() -> usize {
    50
}

fn default_packet_flood_rate_multiplier() -> f64 {
    10.0
}

fn default_packet_flood_window_seconds() -> u64 {
    30
}

fn default_packet_flood_cooldown_seconds() -> u64 {
    60
}

fn default_lateral_movement_ssh_threshold() -> usize {
    3
}

fn default_lateral_movement_scan_threshold() -> usize {
    5
}

fn default_lateral_movement_window_seconds() -> u64 {
    300
}

fn default_dns_tunneling_entropy_threshold() -> f64 {
    4.0
}

fn default_dns_tunneling_volume_threshold() -> usize {
    15
}

fn default_dns_tunneling_length_threshold() -> usize {
    100
}

fn default_dns_tunneling_window_seconds() -> u64 {
    60
}

fn default_true() -> bool {
    true
}

fn default_threshold() -> usize {
    8
}

fn default_port_scan_threshold() -> usize {
    12
}

fn default_credential_stuffing_threshold() -> usize {
    6
}

fn default_sudo_abuse_threshold() -> usize {
    3
}

fn default_window_seconds() -> u64 {
    300
}

fn default_port_scan_window_seconds() -> u64 {
    60
}

fn default_credential_stuffing_window_seconds() -> u64 {
    300
}

fn default_sudo_abuse_window_seconds() -> u64 {
    300
}

fn default_poll_seconds() -> u64 {
    60
}

fn default_auth_log_path() -> String {
    "/var/log/auth.log".to_string()
}

fn default_exec_audit_path() -> String {
    "/var/log/audit/audit.log".to_string()
}

fn default_journald_units() -> Vec<String> {
    vec!["sshd".to_string(), "sudo".to_string()]
}

fn default_nginx_access_path() -> String {
    "/var/log/nginx/access.log".to_string()
}

fn default_search_abuse_threshold() -> usize {
    30
}

fn default_search_abuse_window_seconds() -> u64 {
    60
}

fn default_search_abuse_path_prefix() -> String {
    "/api/search".to_string()
}

fn default_execution_guard_mode() -> String {
    "observe".to_string()
}

fn default_execution_guard_window_seconds() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct NginxErrorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_nginx_error_path")]
    pub path: String,
}

impl Default for NginxErrorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_nginx_error_path(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct WebScanConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_web_scan_threshold")]
    pub threshold: usize,
    #[serde(default = "default_web_scan_window_seconds")]
    pub window_seconds: u64,
}

impl Default for WebScanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_web_scan_threshold(),
            window_seconds: default_web_scan_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct UserAgentScannerConfig {
    #[serde(default)]
    pub enabled: bool,
}

fn default_nginx_error_path() -> String {
    "/var/log/nginx/error.log".to_string()
}

fn default_web_scan_threshold() -> usize {
    15
}

fn default_web_scan_window_seconds() -> u64 {
    60
}

#[derive(Debug, Deserialize)]
pub struct SyslogFirewallConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Path to syslog or kern.log. Defaults to /var/log/syslog on Debian/Ubuntu,
    /// /var/log/kern.log is a common alternative.
    #[serde(default = "default_syslog_firewall_path")]
    pub path: String,
}

impl Default for SyslogFirewallConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_syslog_firewall_path(),
        }
    }
}

fn default_syslog_firewall_path() -> String {
    "/var/log/syslog".to_string()
}

#[derive(Debug, Deserialize)]
pub struct CloudTrailConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Directory containing pre-extracted CloudTrail JSON files.
    #[serde(default = "default_cloudtrail_dir")]
    pub dir: String,
}

impl Default for CloudTrailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: default_cloudtrail_dir(),
        }
    }
}

fn default_cloudtrail_dir() -> String {
    "/var/log/cloudtrail".to_string()
}

fn default_docker_anomaly_threshold() -> usize {
    3
}

fn default_docker_anomaly_window_seconds() -> u64 {
    300
}

fn default_integrity_alert_cooldown_seconds() -> u64 {
    3600
}

fn default_setns_owner_enabled() -> bool {
    true
}

fn default_setns_owner_cooldown_seconds() -> u64 {
    300
}

fn default_untrusted_root_exec_enabled() -> bool {
    true
}

fn default_untrusted_root_exec_cooldown_seconds() -> u64 {
    300
}

fn default_log_tampering_cooldown_seconds() -> u64 {
    600
}

// ---------------------------------------------------------------------------
// Calibration — operator-declared host inventory
// ---------------------------------------------------------------------------

/// Operator-declared expectations about what SHOULD be running on this host.
/// Used by the sensor to suppress false positives from known services.
///
/// ```toml
/// [calibration]
/// expected_services = ["nginx", "postgres", "redis", "node"]
/// expected_outbound = ["api.telegram.org", "api.openai.com", "abuseipdb.com"]
/// ```
#[derive(Debug, Deserialize, Default, Clone)]
pub struct CalibrationConfig {
    /// Services the operator expects to be running. Process names (comm).
    /// Detectors use this to suppress FPs from known infrastructure.
    /// Reserved for wiring to outbound_anomaly and c2_callback detectors.
    #[serde(default)]
    #[allow(dead_code)]
    pub expected_services: Vec<String>,

    /// Outbound destinations the operator expects. Domains or IPs.
    /// DNS C2 and outbound anomaly detectors use this to avoid flagging
    /// legitimate API calls.
    /// Reserved for wiring to dns_c2 and outbound_anomaly detectors.
    #[serde(default)]
    #[allow(dead_code)]
    pub expected_outbound: Vec<String>,

    /// UIDs of trusted operators. Discovery burst and other detectors
    /// apply higher thresholds for these UIDs. If empty, auto-detected
    /// from /etc/passwd (uid >= 1000 with login shell).
    #[serde(default)]
    pub trusted_uids: Vec<u32>,
}

impl CalibrationConfig {
    /// Returns trusted UIDs — either from config or auto-detected from /etc/passwd.
    /// Auto-detection finds UIDs >= 1000 with login shells (same logic as
    /// environment_profile.rs in the agent crate).
    pub fn effective_trusted_uids(&self) -> Vec<u32> {
        if !self.trusted_uids.is_empty() {
            return self.trusted_uids.clone();
        }
        // Auto-detect: parse /etc/passwd for human UIDs
        auto_detect_human_uids()
    }
}

/// Detect human UIDs from /etc/passwd (uid >= 1000, with login shell).
/// Returns empty vec on non-Linux or if /etc/passwd is unreadable.
fn auto_detect_human_uids() -> Vec<u32> {
    let content = match std::fs::read_to_string("/etc/passwd") {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    parse_human_uids_from_passwd(&content)
}

fn parse_human_uids_from_passwd(content: &str) -> Vec<u32> {
    let nologin_shells = ["/usr/sbin/nologin", "/bin/false", "/sbin/nologin"];

    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 7 {
                return None;
            }
            let uid: u32 = parts[2].parse().ok()?;
            let shell = parts[6];

            if (1000..65534).contains(&uid) && !nologin_shells.iter().any(|s| shell.ends_with(s)) {
                Some(uid)
            } else {
                None
            }
        })
        .collect()
}

pub fn load(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(Path::new(path))
        .with_context(|| format!("failed to read config: {path}"))?;
    toml::from_str(&content).with_context(|| "failed to parse config")
}

// 2026-05-25 (PR-F1): `test_default` is unused in this commit because
// it's added as a foundation for PR-F2 (SharedCursors adoption) and
// PR-F3 (Sensor::run extraction + integration anchors). Both pending
// PRs will call it; suppressing dead_code here keeps clippy clean
// during the staging period.
#[allow(dead_code)]
impl Config {
    /// Construct a minimal Config for tests. Every collector and
    /// detector inherits its derived `Default` impl, which for the
    /// ones with an `enabled: bool` field means `enabled = false`.
    /// Tests can selectively flip `cfg.collectors.X.enabled = true`
    /// or `cfg.detectors.Y.enabled = true` to exercise a specific
    /// path without writing a TOML file to disk.
    ///
    /// `host_id` is the sentinel `"test-host"`. `data_dir` is the
    /// sentinel `"/tmp/innerwarden-test"` — tests that touch disk
    /// should override with a `tempfile::TempDir` path.
    ///
    /// 2026-05-25 (PR-F1): introduced to unblock unit testing of
    /// `boot/*` helpers. Pre-this, every test that called
    /// `build_detector_set`, `spawn_collectors`, or `run_event_loop`
    /// had to serialise a TOML, write it to a tempfile, then load it
    /// back via `config::load`. That was fragile because every
    /// detector schema change broke every test.
    pub(crate) fn test_default() -> Self {
        Self {
            agent: AgentConfig {
                host_id: "test-host".to_string(),
            },
            output: OutputConfig {
                data_dir: "/tmp/innerwarden-test".to_string(),
                write_events: true,
            },
            collectors: CollectorsConfig::all_disabled(),
            // Two polling detectors run as their own tokio task (via
            // `boot::spawn_collectors::spawn_collectors`) rather than
            // per-event handlers, and both default to `enabled = true`.
            // They have to be flipped off here so `run` exits cleanly
            // in tests — every other detector runs inside the consumer
            // loop and never holds a clone of `tx`.
            detectors: DetectorsConfig {
                suid_page_cache_integrity: SuidPageCacheIntegrityConfig {
                    enabled: false,
                    ..SuidPageCacheIntegrityConfig::default()
                },
                kernel_devnode_exposed: KernelDevnodeExposedConfig {
                    enabled: false,
                    ..KernelDevnodeExposedConfig::default()
                },
                ..DetectorsConfig::default()
            },
            calibration: CalibrationConfig::default(),
            allowlist: AllowlistConfig::default(),
            event_pipeline: EventPipelineConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_human_uids_from_passwd_filters_system_and_nologin_accounts() {
        // Ensures UID auto-detection keeps only interactive human accounts.
        let passwd = "\
root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
alice:x:1000:1000:Alice:/home/alice:/bin/bash\n\
bob:x:1001:1001:Bob:/home/bob:/bin/zsh\n\
svc:x:1002:1002:Svc:/home/svc:/bin/false\n\
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
        let uids = parse_human_uids_from_passwd(passwd);
        assert_eq!(uids, vec![1000, 1001]);
    }

    #[test]
    fn effective_trusted_uids_prefers_explicit_configuration() {
        // Covers explicit override path so operator-provided trusted UIDs are never replaced by autodetect.
        let cfg = CalibrationConfig {
            trusted_uids: vec![42, 84],
            ..Default::default()
        };
        assert_eq!(cfg.effective_trusted_uids(), vec![42, 84]);
    }

    #[test]
    fn default_helpers_expose_expected_sensor_defaults() {
        // Guards key default values used when config omits optional fields.
        assert_eq!(default_poll_seconds(), 60);
        assert_eq!(default_journald_units(), vec!["sshd", "sudo"]);
    }

    #[test]
    fn load_minimal_config_applies_nested_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sensor.toml");
        std::fs::write(
            &path,
            r#"
[agent]
host_id = "host-a"

[output]
data_dir = "/tmp/innerwarden"
"#,
        )
        .unwrap();

        let cfg = load(path.to_str().unwrap()).unwrap();
        assert_eq!(cfg.agent.host_id, "host-a");
        assert_eq!(cfg.output.data_dir, "/tmp/innerwarden");
        assert!(cfg.output.write_events);
        assert!(cfg.collectors.auth_log.enabled);
        assert_eq!(cfg.collectors.integrity.poll_seconds, 60);
        assert!(cfg.detectors.ssh_bruteforce.enabled);
        assert!(cfg.detectors.suid_page_cache_integrity.enabled);
        assert_eq!(
            cfg.detectors.suid_page_cache_integrity.poll_interval_secs,
            30
        );
        assert!(cfg
            .detectors
            .suid_page_cache_integrity
            .allowlist
            .contains(&"/usr/bin/su".to_string()));
        assert!(cfg.detectors.log_tampering.enabled);
        assert!(cfg.allowlist.trusted_users.is_empty());
    }

    #[test]
    fn load_respects_nested_overrides_and_surfaces_parse_errors() {
        let dir = tempfile::tempdir().unwrap();
        let valid = dir.path().join("sensor-valid.toml");
        std::fs::write(
            &valid,
            r#"
[agent]
host_id = "host-b"

[output]
data_dir = "/var/lib/innerwarden"
write_events = false

[collectors.exec_audit]
enabled = true
path = "/tmp/exec.log"
include_tty = true

[detectors.port_scan]
enabled = true
threshold = 99
window_seconds = 42

[detectors.suid_page_cache_integrity]
enabled = true
poll_interval_secs = 7
allowlist = ["/tmp/test-su"]

[allowlist]
trusted_users = ["alice", "bob"]
"#,
        )
        .unwrap();

        let cfg = load(valid.to_str().unwrap()).unwrap();
        assert!(!cfg.output.write_events);
        assert!(cfg.collectors.exec_audit.enabled);
        assert_eq!(cfg.collectors.exec_audit.path, "/tmp/exec.log");
        assert!(cfg.collectors.exec_audit.include_tty);
        assert!(cfg.detectors.port_scan.enabled);
        assert_eq!(cfg.detectors.port_scan.threshold, 99);
        assert_eq!(cfg.detectors.port_scan.window_seconds, 42);
        assert!(cfg.detectors.suid_page_cache_integrity.enabled);
        assert_eq!(
            cfg.detectors.suid_page_cache_integrity.poll_interval_secs,
            7
        );
        assert_eq!(
            cfg.detectors.suid_page_cache_integrity.allowlist,
            vec!["/tmp/test-su"]
        );
        assert_eq!(cfg.allowlist.trusted_users, vec!["alice", "bob"]);

        let invalid = dir.path().join("sensor-invalid.toml");
        std::fs::write(&invalid, "[agent\nhost_id = nope").unwrap();
        assert!(load(invalid.to_str().unwrap()).is_err());
        assert!(load(dir.path().join("missing.toml").to_str().unwrap()).is_err());
    }

    #[test]
    fn kernel_devnode_exposed_toml_round_trip_loads_allowlist_and_overrides() {
        // Anchors the TOML schema for [detectors.kernel_devnode_exposed].
        // Operators write this section when they have legitimately
        // widened a devnode mode (allowlist) or when they want to add
        // a new pattern to the watchlist (overrides). The keys here
        // are the contract that future config refactors must keep.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devnode.toml");
        std::fs::write(
            &path,
            r#"
[agent]
host_id = "host-c"

[output]
data_dir = "/var/lib/innerwarden"
write_events = true

[detectors.kernel_devnode_exposed]
enabled = true
poll_interval_secs = 600
allowlist = ["/dev/infiniband/uverbs0", "/dev/kvm"]

[[detectors.kernel_devnode_exposed.overrides]]
pattern = "/dev/custom-driver"
max_allowed_mode_octal = "660"
surface = "operator-defined driver"

[[detectors.kernel_devnode_exposed.overrides]]
pattern = "/dev/kvm"
max_allowed_mode_octal = "0o666"
surface = "dedicated kvm host"
"#,
        )
        .unwrap();
        let cfg = load(path.to_str().unwrap()).unwrap();
        let devnode = &cfg.detectors.kernel_devnode_exposed;
        assert!(devnode.enabled);
        assert_eq!(devnode.poll_interval_secs, 600);
        assert_eq!(
            devnode.allowlist,
            vec![
                "/dev/infiniband/uverbs0".to_string(),
                "/dev/kvm".to_string()
            ]
        );
        assert_eq!(devnode.overrides.len(), 2);
        assert_eq!(devnode.overrides[0].pattern, "/dev/custom-driver");
        assert_eq!(devnode.overrides[0].max_allowed_mode_octal, "660");
        assert_eq!(devnode.overrides[0].surface, "operator-defined driver");
        assert_eq!(devnode.overrides[1].pattern, "/dev/kvm");
        assert_eq!(devnode.overrides[1].max_allowed_mode_octal, "0o666");
    }

    #[test]
    fn config_default_structs_preserve_runtime_security_thresholds() {
        let exec = ExecAuditConfig::default();
        assert!(!exec.enabled);
        assert_eq!(exec.path, "/var/log/audit/audit.log");
        assert!(!exec.include_tty);

        let journald = JournaldConfig::default();
        assert!(!journald.enabled);
        assert_eq!(journald.units, vec!["sshd", "sudo"]);

        let integrity = IntegrityConfig::default();
        assert!(!integrity.enabled);
        assert!(integrity.paths.is_empty());
        assert_eq!(integrity.poll_seconds, 60);

        let auth = AuthLogConfig::default();
        assert!(auth.enabled);
        assert_eq!(auth.path, "/var/log/auth.log");

        let ssh = SshBruteforceConfig::default();
        assert!(ssh.enabled);
        assert_eq!(ssh.threshold, 8);
        assert_eq!(ssh.window_seconds, 300);

        let suid_page_cache = SuidPageCacheIntegrityConfig::default();
        assert!(suid_page_cache.enabled);
        assert_eq!(suid_page_cache.poll_interval_secs, 30);
        assert!(suid_page_cache
            .allowlist
            .contains(&"/usr/bin/su".to_string()));

        // kernel_devnode_exposed: on by default, 15-min poll, no
        // overrides — operators only fill these if they intentionally
        // widened a devnode mode.
        let devnode = KernelDevnodeExposedConfig::default();
        assert!(devnode.enabled);
        assert_eq!(devnode.poll_interval_secs, 900);
        assert!(devnode.allowlist.is_empty());
        assert!(devnode.overrides.is_empty());

        let stuffing = CredentialStuffingConfig::default();
        assert!(!stuffing.enabled);
        assert_eq!(stuffing.threshold, 6);
        assert_eq!(stuffing.window_seconds, 300);

        let port_scan = PortScanConfig::default();
        assert!(!port_scan.enabled);
        assert_eq!(port_scan.threshold, 12);
        assert_eq!(port_scan.window_seconds, 60);

        let sudo = SudoAbuseConfig::default();
        assert!(!sudo.enabled);
        assert_eq!(sudo.threshold, 3);
        assert_eq!(sudo.window_seconds, 300);

        let nginx = NginxAccessConfig::default();
        assert!(!nginx.enabled);
        assert_eq!(nginx.path, "/var/log/nginx/access.log");

        let search = SearchAbuseConfig::default();
        assert!(!search.enabled);
        assert_eq!(search.threshold, 30);
        assert_eq!(search.window_seconds, 60);
        assert_eq!(search.path_prefix, "/api/search");

        let guard = ExecutionGuardConfig::default();
        assert!(!guard.enabled);
        assert_eq!(guard.mode, "observe");
        assert_eq!(guard.window_seconds, 300);

        let docker = DockerAnomalyConfig::default();
        assert!(!docker.enabled);
        assert_eq!(docker.threshold, 3);
        assert_eq!(docker.window_seconds, 300);

        let integrity_alert = IntegrityAlertConfig::default();
        assert!(!integrity_alert.enabled);
        assert_eq!(integrity_alert.cooldown_seconds, 3600);

        let tamper = LogTamperingConfig::default();
        assert!(tamper.enabled);
        assert_eq!(tamper.cooldown_seconds, 600);

        let dns = DnsTunnelingConfig::default();
        assert!(dns.enabled);
        assert_eq!(dns.entropy_threshold, 4.0);
        assert_eq!(dns.volume_threshold, 15);
        assert_eq!(dns.length_threshold, 100);
        assert_eq!(dns.window_seconds, 60);

        let lateral = LateralMovementConfig::default();
        assert!(lateral.enabled);
        assert_eq!(lateral.ssh_threshold, 3);
        assert_eq!(lateral.scan_threshold, 5);
        assert_eq!(lateral.window_seconds, 300);

        let miner = CryptoMinerConfig::default();
        assert!(miner.enabled);
        assert_eq!(miner.cooldown_seconds, 300);

        let outbound = OutboundAnomalyConfig::default();
        assert!(outbound.enabled);
        assert_eq!(outbound.connection_flood_threshold, 50);
        assert_eq!(outbound.port_spray_threshold, 20);
        assert_eq!(outbound.udp_flood_threshold, 100);
        assert_eq!(outbound.fanout_threshold, 10);
        assert_eq!(outbound.window_seconds, 60);
        assert_eq!(outbound.cooldown_seconds, 300);

        let rootkit = RootkitConfig::default();
        assert!(rootkit.enabled);
        assert_eq!(rootkit.check_interval_seconds, 60);
        assert_eq!(rootkit.cooldown_seconds, 600);
        assert!(rootkit.timing_enabled);
        assert_eq!(rootkit.timing_min_samples, 100);
        assert!(rootkit.timing_z_threshold >= 4.0);
        assert_eq!(rootkit.timing_consecutive_threshold, 5);

        let reverse = ReverseShellConfig::default();
        assert!(reverse.enabled);
        assert_eq!(reverse.cooldown_seconds, 300);

        let ssh_key = SshKeyInjectionConfig::default();
        assert!(ssh_key.enabled);
        assert_eq!(ssh_key.cooldown_seconds, 600);

        let web_shell = WebShellConfig::default();
        assert!(web_shell.enabled);
        assert_eq!(web_shell.cooldown_seconds, 300);

        let kernel_module = KernelModuleLoadConfig::default();
        assert!(kernel_module.enabled);
        assert_eq!(kernel_module.cooldown_seconds, 600);

        let crontab = CrontabPersistenceConfig::default();
        assert!(crontab.enabled);
        assert_eq!(crontab.cooldown_seconds, 300);

        let exfil = DataExfiltrationConfig::default();
        assert!(exfil.enabled);
        assert_eq!(exfil.correlation_window_seconds, 60);
        assert_eq!(exfil.cooldown_seconds, 300);

        let inject = ProcessInjectionConfig::default();
        assert!(inject.enabled);
        assert_eq!(inject.cooldown_seconds, 600);

        let create_user = UserCreationConfig::default();
        assert!(create_user.enabled);
        assert_eq!(create_user.cooldown_seconds, 600);

        let systemd = SystemdPersistenceConfig::default();
        assert!(systemd.enabled);
        assert_eq!(systemd.cooldown_seconds, 600);

        let ransomware = RansomwareConfig::default();
        assert!(ransomware.enabled);
        assert_eq!(ransomware.file_threshold, 50);
        assert_eq!(ransomware.window_seconds, 30);
        assert_eq!(ransomware.cooldown_seconds, 60);
        assert_eq!(ransomware.entropy_threshold, 7.5);
        assert_eq!(ransomware.entropy_count_threshold, 3);

        let harvest = CredentialHarvestConfig::default();
        assert!(harvest.enabled);
        assert_eq!(harvest.cooldown_seconds, 600);

        // spec 085 Phase 1: Windows ETW collector config (opt-in, off by default).
        let etw = WindowsEtwConfig::default();
        assert!(!etw.enabled);
        assert_eq!(etw.poll_seconds, 5);
        assert_eq!(etw.batch_cap, 200);
        assert_eq!(etw.channels.len(), 2);
        assert!(etw.channels.iter().any(|c| c == "Security"));

        let flood = PacketFloodConfig::default();
        assert!(flood.enabled);
        assert_eq!(flood.syn_threshold, 100);
        assert_eq!(flood.http_threshold, 200);
        assert_eq!(flood.slowloris_threshold, 50);
        assert_eq!(flood.udp_threshold, 50);
        assert_eq!(flood.rate_multiplier, 10.0);
        assert_eq!(flood.window_seconds, 30);
        assert_eq!(flood.cooldown_seconds, 60);

        let nginx_error = NginxErrorConfig::default();
        assert!(!nginx_error.enabled);
        assert_eq!(nginx_error.path, "/var/log/nginx/error.log");

        let web_scan = WebScanConfig::default();
        assert!(!web_scan.enabled);
        assert_eq!(web_scan.threshold, 15);
        assert_eq!(web_scan.window_seconds, 60);

        let syslog = SyslogFirewallConfig::default();
        assert!(!syslog.enabled);
        assert_eq!(syslog.path, "/var/log/syslog");

        let cloudtrail = CloudTrailConfig::default();
        assert!(!cloudtrail.enabled);
        assert_eq!(cloudtrail.dir, "/var/log/cloudtrail");
    }

    #[test]
    fn effective_trusted_uids_auto_detect_branch_returns_human_uid_candidates_only() {
        let detected = CalibrationConfig::default().effective_trusted_uids();
        assert!(detected.iter().all(|uid| (1000..65534).contains(uid)));
    }
}
