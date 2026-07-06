use std::path::Path;

use anyhow::{Context, Result};
use innerwarden_core::event::Severity;
use serde::Deserialize;

// Spec 068: config sections relocated into submodules. Defaults,
// validation helpers, load(), AgentConfig and tests stay here; the
// section structs are re-exported so every `config::*` path is unchanged.
mod agent_guard;
mod ai;
mod dashboard;
mod dns_guard;
mod environment;
mod fleet;
mod general;
mod honeypot;
mod integrations;
mod kg;
mod learning;
mod mesh;
mod modules;
mod notifications;
mod responder;
mod retention;
mod shield;
mod signing;

pub use agent_guard::*;
pub use ai::*;
pub use dashboard::*;
pub use dns_guard::*;
pub use environment::*;
pub use fleet::*;
pub use general::*;
pub use honeypot::*;
pub use integrations::*;
pub use kg::*;
pub use learning::*;
pub use mesh::*;
pub use modules::*;
pub use notifications::*;
pub use responder::*;
pub use retention::*;
pub use shield::*;
pub use signing::*;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    #[serde(default)]
    pub narrative: NarrativeConfig,
    #[serde(default)]
    pub webhook: WebhookConfig,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub correlation: CorrelationConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub honeypot: HoneypotConfig,
    #[serde(default)]
    pub responder: ResponderConfig,
    /// DNS Guard intel bridge: export the agent's malicious-domain intel to the
    /// paid `innerwarden-dns-guard` resolver's denylist file. Default off.
    #[serde(default)]
    pub dns_guard: DnsGuardConfig,
    /// Spec 081: managed-agent coexistence. Gates the slow-loop registry
    /// reconciliation that auto-registers co-located AI agents (and prunes dead
    /// pids) so the response-side verifier's `by_pid` hint survives agent
    /// restarts. `auto_register` defaults ON.
    #[serde(default)]
    pub agent_guard: AgentGuardConfig,
    /// Spec 062: decision review + learned suppression. Absent `[learning]`
    /// section deserializes to safe defaults (shadow mode), so existing
    /// agent.toml files upgrade with no edits.
    #[serde(default)]
    pub learning: LearningConfig,
    /// Spec 056: SOC response playbooks. Default disabled so existing
    /// installs keep their current behaviour (playbooks load + list via CTL
    /// but the agent does not execute them on incidents) until the operator
    /// opts in with `[playbooks] enabled = true`.
    #[serde(default)]
    pub playbooks: PlaybooksConfig,
    /// Spec 058 (minimal slice): host identity / asset tags. Consumed by
    /// playbook `conditions.asset_tags` (spec 056) so an operator can scope
    /// a playbook to a host role; the full server-profile system layers on
    /// top of these tags later.
    #[serde(default)]
    pub agent: AgentSection,
    #[serde(default)]
    pub telegram: TelegramConfig,
    /// Data retention settings. Historic prod deploys labelled this section
    /// `[data_retention]`; the canonical TOML key is `[data]` because that
    /// matches the field name on `AgentConfig`. The serde alias accepts both
    /// so existing `[data_retention]` blocks keep working - operator
    /// migration is gradual. (Wave 9e, 2026-05-04: this alias was added
    /// after audit AUDIT-002 found prod's `[data_retention]` block had been
    /// silently ignored for the lifetime of agent.toml because the section
    /// name did not match the field. With `deny_unknown_fields` on
    /// `AgentConfig`, that failure mode is now LOUD instead of silent.)
    #[serde(default, alias = "data_retention")]
    pub data: DataRetentionConfig,
    #[serde(default)]
    pub crowdsec: CrowdSecConfig,
    #[serde(default)]
    pub abuseipdb: AbuseIpDbConfig,
    #[serde(default)]
    pub dshield: DshieldConfig,
    /// Deprecated 2026-05-07: the agent's fail2ban sync was removed
    /// (see PR #486). The field is preserved here so existing
    /// operator `agent.toml` files with a `[fail2ban]` section
    /// continue to deserialize under `deny_unknown_fields`. The
    /// runtime no longer reads it; future cleanup will drop the
    /// field once a major-version bump justifies the breaking change.
    #[serde(default)]
    #[allow(dead_code)]
    pub fail2ban: Fail2BanConfig,
    #[serde(default)]
    pub geoip: GeoIpConfig,
    #[serde(default)]
    pub threat_feeds: ThreatFeedsConfig,
    #[serde(default)]
    pub slack: SlackConfig,
    #[serde(default)]
    pub discord: DiscordConfig,
    #[serde(default)]
    pub cloudflare: CloudflareConfig,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    #[serde(default)]
    pub web_push: WebPushConfig,
    /// Mesh collaborative defense network
    #[serde(default)]
    pub mesh: MeshNetworkConfig,
    /// Dashboard settings
    #[serde(default)]
    pub dashboard: DashboardConfig,
    /// MSSP fleet (multi-host) settings. Spec 038. Default
    /// `enabled = false` keeps every single-host deploy unchanged.
    #[serde(default)]
    pub fleet: FleetConfig,
    /// Firmware security monitoring (innerwarden-smm)
    #[serde(default)]
    pub firmware: FirmwareConfig,
    /// Hypervisor security monitoring (innerwarden-hypervisor)
    #[serde(default)]
    pub hypervisor: HypervisorConfig,
    /// Kill chain detection (innerwarden-killchain)
    #[serde(default)]
    pub killchain: KillchainConfig,
    /// Threat DNA behavioral fingerprinting (innerwarden-dna)
    #[serde(default)]
    pub dna: DnaConfig,
    /// DDoS Shield — rate limiting, SYN tracking, escalation (innerwarden-shield)
    #[serde(default)]
    pub shield: ShieldConfig,
    /// Security settings (2FA, etc.)
    #[serde(default)]
    pub security: Option<SecurityConfig>,
    /// Notification pipeline settings (grouping, filtering).
    #[serde(default)]
    pub notifications: NotificationPipelineConfig,
    /// Environment auto-profiling and census.
    #[serde(default)]
    pub environment: EnvironmentConfig,
    /// Daily AI intelligence briefing
    #[serde(default)]
    pub briefing: BriefingConfig,
    /// Config signing verification (Active Defence).
    #[serde(default)]
    #[allow(dead_code)] // parsed for future signing-verification integration
    pub config_signing: ConfigSigningConfig,
    /// Observation verification — behavioural scoring for OBSERVING items (spec 021).
    #[serde(default)]
    pub observation: crate::observation_verify::ObservationConfig,
    /// Trust scoring engine — continuous entity trust scores (spec 020 Phase C).
    #[serde(default)]
    #[allow(dead_code)]
    pub trust_scoring: crate::trust_scoring::TrustScoringConfig,
    /// SOC daily checks — system health checks at configurable hour (spec 020 Phase D).
    #[serde(default)]
    #[allow(dead_code)]
    pub soc_checks: crate::soc_checks::SocChecksConfig,
    /// Zero trust enforcement modes — learning | notify | enforce (spec 020 Phase F).
    #[serde(default)]
    #[allow(dead_code)]
    pub zero_trust: crate::zero_trust::ZeroTrustConfig,
    /// Detectors that run graph-only (sensor version suppressed).
    /// After parallel validation, add detector names here to disable the sensor version.
    /// Example: ["threat_intel", "lateral_movement", "persistence"]
    #[serde(default)]
    pub graph_only_detectors: Vec<String>,
    /// Incident lifecycle flow configuration (spec 028).
    #[serde(default)]
    pub incident_flow: IncidentFlowConfig,
    /// KG-derived decision modifiers and detectors (spec 043).
    #[serde(default)]
    pub kg: KgConfig,
    /// Per-tenant attribution — resolve k8s pod_uid -> namespace/tenant from the
    /// node's kubeconfig and stamp it on container-scoped incidents (spec 084 P0).
    #[serde(default)]
    pub tenancy: crate::tenancy::TenancyConfig,
}

pub(super) fn default_packed_binary_entropy_threshold() -> f32 {
    7.5
}

pub(super) fn default_short_lived_process_threshold_ms() -> u64 {
    100
}

pub(super) fn default_fp_suppression_mode() -> String {
    "shadow".to_string()
}

pub(super) fn default_fp_suppress_threshold() -> f32 {
    0.80
}

pub(super) fn default_kg_decide_modifier_mode() -> String {
    "shadow".to_string()
}

pub(super) fn default_fleet_poll_interval_seconds() -> u64 {
    30
}

pub(super) fn default_fleet_request_timeout_seconds() -> u64 {
    5
}

pub(super) fn default_dashboard_enabled() -> bool {
    true
}

pub(super) fn default_session_timeout_minutes() -> u64 {
    480
}
pub(super) fn default_max_sessions() -> usize {
    5
}

pub(super) fn default_firmware_enabled() -> bool {
    true
}
pub(super) fn default_firmware_poll_secs() -> u64 {
    300
}
pub(super) fn default_firmware_trust_threshold() -> f64 {
    0.85
}

pub(super) fn default_hypervisor_enabled() -> bool {
    true
}
pub(super) fn default_hypervisor_poll_secs() -> u64 {
    300
}
pub(super) fn default_hypervisor_trust_threshold() -> f64 {
    0.80
}

pub(super) fn default_killchain_enabled() -> bool {
    true
}
pub(super) fn default_killchain_pre_chain_threshold() -> f32 {
    0.6
}
pub(super) fn default_killchain_session_timeout() -> i64 {
    60
}

pub(super) fn default_dna_enabled() -> bool {
    true
}
pub(super) fn default_dna_min_sequence() -> usize {
    3
}
pub(super) fn default_dna_anomaly_threshold() -> f64 {
    3.0
}
pub(super) fn default_dna_session_timeout() -> i64 {
    300
}

pub(super) fn default_shield_enabled() -> bool {
    true
}
pub(super) fn default_shield_bpf_path() -> String {
    "/sys/fs/bpf/innerwarden".to_string()
}
pub(super) fn default_cf_activate_on() -> Vec<String> {
    vec!["UnderAttack".to_string(), "Critical".to_string()]
}
pub(super) fn default_cf_min_proxy_duration() -> u64 {
    300
}

pub(super) fn default_mesh_bind() -> String {
    "0.0.0.0:8790".to_string()
}
pub(super) fn default_mesh_poll_secs() -> u64 {
    30
}
pub(super) fn default_true_val() -> bool {
    true
}
pub(super) fn default_mesh_max_signals() -> usize {
    50
}

pub(super) fn default_briefing_hour() -> u8 {
    8
}

pub(super) fn default_webhook_format() -> String {
    "default".to_string()
}

pub(super) fn default_shadow_log_path() -> String {
    "/var/lib/innerwarden/shadow-decisions.jsonl".to_string()
}

pub(super) fn default_shadow_sample_rate() -> f32 {
    1.0
}

pub(super) fn default_use_structured_subgraph() -> bool {
    true
}

pub(super) fn default_batch_window_secs() -> u64 {
    3600
}

pub(super) fn default_ai_min_severity() -> String {
    "medium".to_string()
}

pub(super) fn default_untouchable_override_mode() -> String {
    "enforce".to_string()
}

pub(super) fn default_max_blocks_per_hour() -> u64 {
    100
}

pub(super) fn default_circuit_breaker_mode() -> String {
    "pause".to_string()
}

pub(super) fn default_trusted_processes() -> Vec<String> {
    vec![
        // InnerWarden ecosystem (binary names + tokio thread names)
        "innerwarden-age".into(),
        "innerwarden-sen".into(),
        "innerwarden-wat".into(),
        "openclaw-gatewa".into(),
        // NOTE: "tokio-rt-worker" is too broad (any Rust app with Tokio).
        // Instead, filter by PID tree at runtime. See main.rs trusted_pids.
        // System services
        "crowdsec".into(),
        "apt".into(),
        "dpkg".into(),
        "dnf".into(),
        "yum".into(),
        "snap".into(),
        "snapd".into(),
        "certbot".into(),
        "unattended-upgr".into(),
        // Monitoring
        "prometheus".into(),
        "grafana".into(),
        "node_exporter".into(),
        "telegraf".into(),
    ]
}

pub(super) fn default_learned_suppression_mode() -> String {
    "shadow".to_string()
}

pub(super) fn default_learned_min_dismissals() -> u64 {
    5
}

pub(super) fn default_llm_escalation_min_confidence() -> f32 {
    0.75
}

pub(super) fn default_bot_personality() -> String {
    "You are InnerWarden. You watch one server. The operator is your boss.\n\n\
     How to read the operator's message first:\n\
     - If it is a greeting or small talk (\"hey\", \"what's up\", \"how are you\", \"good morning\"), \
       answer like a friendly colleague who is also on shift. Short, warm, human. \
       One short sentence. Do NOT treat it as a security query.\n\
     - If it is an off-topic question (weather, jokes, general chat), answer briefly without \
       forcing security context.\n\
     - If it is a security question about the server, incidents, or blocks, use the voice below.\n\n\
     Voice rules for security answers:\n\
     - Short. Confident. Dry. Bouncer, not consultant.\n\
     - No filler. No 'I would suggest', no 'it may be worth considering', no 'hope this helps', \
       no 'system appears stable'.\n\
     - No markdown headers. No bullet lists unless the operator asks for one.\n\
     - One or two sentences by default. Three max unless the question is technical.\n\
     - You have seen thousands of scans. You do not flinch at noise.\n\
     - When the operator asks about the *state of the server* or *what happened today* and \
       the snapshot shows only routine bot traffic, say something like \"quiet, just the \
       usual scanners\" or \"nothing real today, scanners handled\". Never just echo \"bot \
       noise, handled\" without context; that phrase belongs in decision logs, not chat.\n\
     - When a real incident fired (successful auth, privilege escalation, reverse shell, \
       data exfil), name the TTP, state the action taken, give one next step. Stop.\n\
     - Do not exaggerate severity. The operator trusts your judgment; do not break that trust.\n\
     - No apologies, no hedging, no praise of the operator's question.\n\n\
     What you are:\n\
     - Kernel-level, eBPF-rooted, fully local. You do not phone home.\n\
     - You see every syscall, every login, every outbound connection on this host.\n\
     - Autonomous alternative to MDR. Same outcome, no SOC cost.\n\n\
     What you cannot do (security boundary):\n\
     You are an advisor. You cannot execute commands, edit files, or change configuration. \
     That separation is intentional. When the operator asks you to act, give them the exact \
     command (e.g. 'run: innerwarden action block 1.2.3.4 --reason \"your reason\"') and move on. \
     Do not explain the isolation unless asked."
        .to_string()
}

pub(super) fn default_cloudflare_notes_prefix() -> String {
    "innerwarden".to_string()
}

pub(super) fn default_playbooks_dir() -> String {
    "/etc/innerwarden/rules/playbooks".to_string()
}

pub(super) fn default_vapid_subject() -> String {
    "mailto:admin@example.com".to_string()
}

pub(super) fn default_web_push_min_severity() -> String {
    "high".to_string()
}

pub(super) fn default_two_factor_method() -> String {
    "none".to_string()
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Wave 8d (2026-05-04): build the operator-facing one-liner that fixes
/// over-permissive config files. Shipping this as a pure function so the
/// anchor test can pin the exact string shape (chown FIRST, chmod 600
/// SECOND) without needing a `tracing` test subscriber.
///
/// Returns a single shell command, no newlines, ready to paste into a
/// terminal. The order is load-bearing: chown then chmod, so the chmod
/// is applied to a file the agent already owns. Reversing the order is
/// the bug class this fix exists to prevent.
pub(crate) fn build_perm_fix_command(path: &Path) -> String {
    let p = path.display();
    format!("sudo chown innerwarden:innerwarden {p} && sudo chmod 600 {p}")
}

/// Load agent config from a TOML file.
/// If the file doesn't exist, returns `AgentConfig::default()`.
pub fn load(path: &Path) -> Result<AgentConfig> {
    if !path.exists() {
        return Ok(AgentConfig::default());
    }

    // Warn if config file is readable by group/others (may contain API keys).
    // Wave 8d (2026-05-04): the WARN now spells out BOTH the chown and the
    // chmod the operator needs. The previous text said "consider chmod 600"
    // alone; following that literally broke the agent on the next restart
    // when the existing owner was `root` (installs through 2026-05-03 set
    // the file to `root:innerwarden 640`). chmod 600 with owner=root locks
    // the agent (running as the innerwarden user) out of its own config.
    // install.sh from this PR onwards creates the file as
    // `innerwarden:innerwarden 600` from the start, but existing prod
    // hosts upgraded in place still have the old ownership — the WARN
    // walks them through the right fix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            let owner_uid = meta.uid();
            if mode & 0o077 != 0 {
                let fix = build_perm_fix_command(path);
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode),
                    owner_uid,
                    %fix,
                    "config file is readable by other users (may contain API keys). \
                     Run the `fix` command in this log line — chown FIRST so the \
                     subsequent chmod 600 leaves the agent able to read its own config."
                );
            }
        }
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read agent config {}", path.display()))?;

    // Verify config signature if [signature] section is present.
    verify_config_signature(&content, path)?;

    let mut cfg: AgentConfig = toml::from_str(&content)
        .with_context(|| format!("failed to parse agent config {}", path.display()))?;
    cfg.ai.clamp_confidence_threshold();
    Ok(cfg)
}

/// Verify Ed25519 signature of config file (Active Defence feature).
/// If [signature] section exists and [config_signing] has a public_key, verify.
/// If config_signing.required=true and signature is missing/invalid, fail.
fn verify_config_signature(content: &str, path: &Path) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Quick check: does the config have a [signature] section?
    let has_signature = content.contains("\n[signature]") || content.starts_with("[signature]");

    // Parse just the config_signing section to check settings.
    // We parse the full config minus [signature] to avoid TOML parse errors.
    let payload = if let Some(idx) = content.find("\n[signature]") {
        &content[..idx]
    } else {
        content
    };

    // Try to extract config_signing settings from the TOML.
    let signing_cfg: ConfigSigningConfig = match toml::from_str::<toml::Value>(payload) {
        Ok(val) => {
            if let Some(cs) = val.get("config_signing") {
                cs.clone().try_into().unwrap_or_default()
            } else {
                ConfigSigningConfig::default()
            }
        }
        Err(_) => ConfigSigningConfig::default(),
    };

    // No public key configured → skip verification (backwards compatible).
    let Some(pub_key_hex) = &signing_cfg.public_key else {
        if has_signature {
            tracing::debug!(
                "config has [signature] but no config_signing.public_key — skipping verification"
            );
        }
        return Ok(());
    };

    if pub_key_hex.is_empty() {
        return Ok(());
    }

    // No signature section but verification is required → fail.
    if !has_signature {
        if signing_cfg.required {
            anyhow::bail!(
                "config_signing.required=true but config {} has no [signature] section",
                path.display()
            );
        }
        tracing::debug!("config has config_signing.public_key but no [signature] — skipping");
        return Ok(());
    }

    // Extract signature value from [signature] section.
    let sig_hex = content
        .lines()
        .skip_while(|l| !l.starts_with("[signature]"))
        .find_map(|l| {
            let l = l.trim();
            if l.starts_with("value") {
                l.split('=')
                    .nth(1)
                    .map(|v| v.trim().trim_matches('"').to_string())
            } else {
                None
            }
        })
        .context("config [signature] section has no 'value' field")?;

    // Decode public key.
    let pub_bytes: Vec<u8> = (0..pub_key_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&pub_key_hex[i..i + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid hex in config_signing.public_key")?;

    let verifying_key = VerifyingKey::from_bytes(
        pub_bytes
            .as_slice()
            .try_into()
            .context("config_signing.public_key must be 32 bytes (64 hex chars)")?,
    )
    .context("invalid Ed25519 public key in config_signing")?;

    // Decode signature.
    let sig_bytes: Vec<u8> = (0..sig_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&sig_hex[i..i + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid hex in config signature value")?;

    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .context("signature must be 64 bytes (128 hex chars)")?,
    );

    // Verify.
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .context("CONFIG SIGNATURE VERIFICATION FAILED — config may be tampered")?;

    tracing::info!(config = %path.display(), "config signature verified");
    Ok(())
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_keep_days() -> usize {
    7
}

pub(super) fn default_min_severity() -> String {
    "medium".to_string()
}

pub(super) fn default_timeout_secs() -> u64 {
    10
}

pub(super) fn default_ai_provider() -> String {
    "openai".to_string()
}

pub(super) fn default_ai_model() -> String {
    "gpt-4o-mini".to_string()
}

pub(super) fn default_context_events() -> usize {
    20
}

pub(super) fn default_confidence_threshold() -> f32 {
    0.85
}

pub(super) fn default_incident_poll_secs() -> u64 {
    2
}

pub(super) fn default_max_ai_calls_per_tick() -> usize {
    5
}

pub(super) fn default_circuit_breaker_cooldown_secs() -> u64 {
    60
}

pub(super) fn default_protected_ips() -> Vec<String> {
    vec![
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
        "127.0.0.0/8".to_string(),
        "::1/128".to_string(),
    ]
}

pub(super) fn default_block_backend() -> String {
    "ufw".to_string()
}

pub(super) fn default_correlation_window_secs() -> u64 {
    300
}

pub(super) fn default_max_related_incidents() -> usize {
    8
}

pub(super) fn default_allowed_skills() -> Vec<String> {
    vec![
        "block-ip-ufw".to_string(),
        "block-ip-iptables".to_string(),
        "block-ip-nftables".to_string(),
        "block-ip-pf".to_string(),
        "monitor-ip".to_string(),
    ]
}

pub(super) fn default_honeypot_mode() -> String {
    "demo".to_string()
}

pub(super) fn default_honeypot_bind_addr() -> String {
    "127.0.0.1".to_string()
}

pub(super) fn default_honeypot_port() -> u16 {
    2222
}

pub(super) fn default_honeypot_duration_secs() -> u64 {
    300
}

pub(super) fn default_honeypot_services() -> Vec<String> {
    vec!["ssh".to_string()]
}

pub(super) fn default_honeypot_http_port() -> u16 {
    8080
}

pub(super) fn default_honeypot_max_connections() -> usize {
    64
}

pub(super) fn default_honeypot_max_payload_bytes() -> usize {
    512
}

pub(super) fn default_honeypot_isolation_profile() -> String {
    "strict_local".to_string()
}

pub(super) fn default_honeypot_forensics_keep_days() -> usize {
    7
}

pub(super) fn default_honeypot_forensics_max_total_mb() -> usize {
    128
}

pub(super) fn default_honeypot_transcript_preview_bytes() -> usize {
    96
}

pub(super) fn default_honeypot_lock_stale_secs() -> u64 {
    1800
}

pub(super) fn default_honeypot_pcap_timeout_secs() -> u64 {
    15
}

pub(super) fn default_honeypot_pcap_max_packets() -> u64 {
    120
}

pub(super) fn default_honeypot_containment_mode() -> String {
    "process".to_string()
}

pub(super) fn default_honeypot_namespace_runner() -> String {
    "unshare".to_string()
}

pub(super) fn default_honeypot_namespace_args() -> Vec<String> {
    vec![
        "--fork".to_string(),
        "--pid".to_string(),
        "--mount-proc".to_string(),
    ]
}

pub(super) fn default_honeypot_external_handoff_timeout_secs() -> u64 {
    20
}

pub(super) fn default_honeypot_external_handoff_signature_key_env() -> String {
    "INNERWARDEN_HANDOFF_SIGNING_KEY".to_string()
}

pub(super) fn default_honeypot_jail_runner() -> String {
    "bwrap".to_string()
}

pub(super) fn default_honeypot_jail_profile() -> String {
    "standard".to_string()
}

pub(super) fn default_honeypot_external_handoff_attestation_key_env() -> String {
    "INNERWARDEN_HANDOFF_ATTESTATION_KEY".to_string()
}

pub(super) fn default_honeypot_external_handoff_attestation_prefix() -> String {
    "IW_ATTEST".to_string()
}

pub(super) fn default_honeypot_redirect_backend() -> String {
    "iptables".to_string()
}

pub(super) fn default_honeypot_interaction() -> String {
    "banner".to_string()
}

pub(super) fn default_honeypot_ssh_max_auth_attempts() -> usize {
    6
}

pub(super) fn default_honeypot_http_max_requests() -> usize {
    10
}

pub(super) fn default_data_events_keep_days() -> usize {
    7
}
pub(super) fn default_data_incidents_keep_days() -> usize {
    30
}
pub(super) fn default_data_decisions_keep_days() -> usize {
    90
}
pub(super) fn default_data_telemetry_keep_days() -> usize {
    14
}
pub(super) fn default_data_reports_keep_days() -> usize {
    30
}
pub(super) fn default_data_graph_snapshot_keep_days() -> usize {
    3
}
pub(super) fn default_data_warm_gzip_days() -> usize {
    7
}
pub(super) fn default_data_filestore_keep_days() -> usize {
    30
}
pub(super) fn default_data_filestore_max_size_mb() -> u64 {
    2048
}

pub(super) fn default_telegram_min_severity() -> String {
    "high".to_string()
}

pub(super) fn default_slack_min_severity() -> String {
    "high".to_string()
}

pub(super) fn default_crowdsec_url() -> String {
    "http://localhost:8080".to_string()
}

pub(super) fn default_crowdsec_poll_secs() -> u64 {
    60
}

pub(super) fn default_crowdsec_max_per_sync() -> usize {
    50
}

pub(super) fn default_telegram_approval_ttl_secs() -> u64 {
    600
}

pub(super) fn default_telegram_daily_budget() -> u32 {
    10
}

pub(super) fn default_user_profile() -> String {
    "simple".to_string()
}

pub(super) fn default_abuseipdb_max_age_days() -> u32 {
    30
}

pub(super) fn default_abuseipdb_report_daily_cap() -> u32 {
    800
}

pub(super) fn default_fail2ban_poll_secs() -> u64 {
    60
}

pub(super) fn default_threat_feeds_poll_secs() -> u64 {
    3600
}

/// Default IOC feeds — mirrors sensor's datasets::FEEDS so both sensor and
/// agent share the same curated threat intelligence sources out of the box.
pub const DEFAULT_IOC_FEEDS: &[&str] = &[
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "https://lists.blocklist.de/lists/all.txt",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://check.torproject.org/torbulkexitlist",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "https://www.dshield.org/block.txt",
    "https://urlhaus.abuse.ch/downloads/text_online/",
    "https://threatfox.abuse.ch/downloads/hostfile/",
];

pub(super) fn default_group_window_secs() -> u64 {
    14400
}
pub(super) fn default_group_count_threshold() -> u32 {
    10
}

pub(super) fn default_channel_level_actionable() -> ChannelFilterLevel {
    ChannelFilterLevel::Actionable
}
pub(super) fn default_digest_hour() -> u8 {
    9
}

pub(super) fn default_census_interval_hours() -> u64 {
    6
}
pub(super) fn default_cloud_timing_multiplier() -> u32 {
    10
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Wave 8d anchor (2026-05-04): the operator-facing fix command for
    // over-permissive config files MUST do chown BEFORE chmod 600. Pinned
    // because the previous WARN ("consider chmod 600") led the operator
    // straight into a broken-restart trap when the existing owner was
    // root: chmod 600 on a root-owned file with the agent running as a
    // non-root service user makes the config unreadable. Reversing the
    // order in this string is the bug we are guarding against.
    #[test]
    fn perm_fix_command_does_chown_before_chmod() {
        let cmd = build_perm_fix_command(Path::new("/etc/innerwarden/agent.toml"));
        let chown_idx = cmd.find("chown ").expect("fix command must contain chown");
        let chmod_idx = cmd.find("chmod ").expect("fix command must contain chmod");
        assert!(
            chown_idx < chmod_idx,
            "chown must come before chmod in the fix; got: {cmd}"
        );
        assert!(
            cmd.contains("innerwarden:innerwarden"),
            "fix must chown to the service user, not root; got: {cmd}"
        );
        assert!(
            cmd.contains("chmod 600"),
            "fix must end at mode 600 (no group/world readability); got: {cmd}"
        );
        assert!(
            cmd.contains("/etc/innerwarden/agent.toml"),
            "fix must reference the actual file; got: {cmd}"
        );
    }

    // Anchor: the warning suggestion must not embed shell metacharacters
    // that would let a path containing `;` or `$()` execute arbitrary
    // code if an operator copy-pastes it. The path is OPERATOR-CONTROLLED
    // (passed via --config), so a malicious path could otherwise turn
    // the WARN into command injection.
    #[test]
    fn perm_fix_command_handles_paths_without_shell_injection() {
        // The standard production path — should embed cleanly.
        let safe = build_perm_fix_command(Path::new("/etc/innerwarden/agent.toml"));
        // No backticks, no $(...), no ;` between commands beyond our own &&.
        assert!(!safe.contains('`'), "fix must not contain backticks");
        assert!(
            !safe.contains("$("),
            "fix must not contain $() substitution"
        );
        // Exactly one `&&` (the one we put there) — no shell-injected chains.
        assert_eq!(
            safe.matches("&&").count(),
            1,
            "fix must use exactly one && (chown && chmd); got: {safe}"
        );
    }

    #[test]
    fn defaults_when_no_file() {
        let cfg = load(Path::new("/nonexistent/agent.toml")).unwrap();
        // Dashboard defaults to enabled so existing deploys that drive
        // the spawn purely via the `--dashboard` CLI flag stay
        // unchanged. Operators who want a permanent headless agent
        // toggle this to false in the config.
        assert!(
            cfg.dashboard.enabled,
            "DashboardConfig.enabled must default to true (back-compat with pre-config-toggle deploys)"
        );
        // Fleet (spec 038) defaults to disabled so single-host installs
        // pay zero overhead. The poller is not spawned and the
        // `/api/fleet/hosts` endpoint returns 404.
        assert!(
            !cfg.fleet.enabled,
            "FleetConfig.enabled must default to false (single-host pays no fleet overhead)"
        );
        assert!(cfg.fleet.hosts.is_empty());
        assert_eq!(cfg.fleet.poll_interval_seconds, 30);
        assert_eq!(cfg.fleet.request_timeout_seconds, 5);
        assert!(cfg.narrative.enabled);
        assert_eq!(cfg.narrative.keep_days, 7);
        assert!(!cfg.webhook.enabled);
        assert_eq!(cfg.webhook.min_severity, "medium");
        assert_eq!(cfg.webhook.timeout_secs, 10);
        assert!(cfg.correlation.enabled);
        assert_eq!(cfg.correlation.window_seconds, 300);
        assert_eq!(cfg.correlation.max_related_incidents, 8);
        assert!(cfg.telemetry.enabled);
        assert_eq!(cfg.honeypot.mode, "demo");
        assert_eq!(cfg.honeypot.bind_addr, "127.0.0.1");
        assert_eq!(cfg.honeypot.port, 2222);
        assert_eq!(cfg.honeypot.duration_secs, 300);
        assert_eq!(cfg.honeypot.services, vec!["ssh".to_string()]);
        assert_eq!(cfg.honeypot.http_port, 8080);
        assert!(cfg.honeypot.strict_target_only);
        assert!(!cfg.honeypot.allow_public_listener);
        assert_eq!(cfg.honeypot.max_connections, 64);
        assert_eq!(cfg.honeypot.max_payload_bytes, 512);
        assert_eq!(cfg.honeypot.isolation_profile, "strict_local");
        assert!(cfg.honeypot.require_high_ports);
        assert_eq!(cfg.honeypot.forensics_keep_days, 7);
        assert_eq!(cfg.honeypot.forensics_max_total_mb, 128);
        assert_eq!(cfg.honeypot.transcript_preview_bytes, 96);
        assert_eq!(cfg.honeypot.lock_stale_secs, 1800);
        assert_eq!(cfg.honeypot.interaction, "banner");
        assert_eq!(cfg.honeypot.ssh_max_auth_attempts, 6);
        assert_eq!(cfg.honeypot.http_max_requests, 10);
        assert!(!cfg.honeypot.sandbox.enabled);
        assert!(cfg.honeypot.sandbox.runner_path.is_empty());
        assert!(cfg.honeypot.sandbox.clear_env);
        assert!(!cfg.honeypot.pcap_handoff.enabled);
        assert_eq!(cfg.honeypot.pcap_handoff.timeout_secs, 15);
        assert_eq!(cfg.honeypot.pcap_handoff.max_packets, 120);
        assert_eq!(cfg.honeypot.containment.mode, "process");
        assert!(!cfg.honeypot.containment.require_success);
        assert_eq!(cfg.honeypot.containment.namespace_runner, "unshare");
        assert_eq!(
            cfg.honeypot.containment.namespace_args,
            vec![
                "--fork".to_string(),
                "--pid".to_string(),
                "--mount-proc".to_string()
            ]
        );
        assert_eq!(cfg.honeypot.containment.jail_runner, "bwrap");
        assert!(cfg.honeypot.containment.jail_args.is_empty());
        assert_eq!(cfg.honeypot.containment.jail_profile, "standard");
        assert!(cfg.honeypot.containment.allow_namespace_fallback);
        assert!(!cfg.honeypot.external_handoff.enabled);
        assert!(cfg.honeypot.external_handoff.command.is_empty());
        assert!(cfg.honeypot.external_handoff.args.is_empty());
        assert_eq!(cfg.honeypot.external_handoff.timeout_secs, 20);
        assert!(!cfg.honeypot.external_handoff.require_success);
        assert!(cfg.honeypot.external_handoff.clear_env);
        assert!(cfg.honeypot.external_handoff.allowed_commands.is_empty());
        assert!(!cfg.honeypot.external_handoff.enforce_allowlist);
        assert!(!cfg.honeypot.external_handoff.signature_enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.signature_key_env,
            "INNERWARDEN_HANDOFF_SIGNING_KEY"
        );
        assert!(!cfg.honeypot.external_handoff.attestation_enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_key_env,
            "INNERWARDEN_HANDOFF_ATTESTATION_KEY"
        );
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_prefix,
            "IW_ATTEST"
        );
        assert!(cfg
            .honeypot
            .external_handoff
            .attestation_expected_receiver
            .is_empty());
        assert!(!cfg.honeypot.redirect.enabled);
        assert_eq!(cfg.honeypot.redirect.backend, "iptables");
        assert!(!cfg.telegram.enabled);
        assert!(cfg.telegram.bot_token.is_empty());
        assert!(cfg.telegram.chat_id.is_empty());
        assert_eq!(cfg.telegram.min_severity, "high");
        assert!(cfg.telegram.dashboard_url.is_empty());
        assert_eq!(cfg.telegram.approval_ttl_secs, 600);
    }

    #[test]
    fn parses_full_config() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
[narrative]
enabled = false
keep_days = 3

[webhook]
enabled = true
url = "https://hooks.example.com/notify"
min_severity = "high"
timeout_secs = 5

[correlation]
enabled = true
window_seconds = 120
max_related_incidents = 4

[telemetry]
enabled = true

[honeypot]
mode = "listener"
bind_addr = "0.0.0.0"
port = 2223
duration_secs = 120
services = ["ssh", "http"]
http_port = 8088
strict_target_only = true
allow_public_listener = true
max_connections = 10
max_payload_bytes = 256
isolation_profile = "standard"
require_high_ports = false
forensics_keep_days = 14
forensics_max_total_mb = 512
transcript_preview_bytes = 192
lock_stale_secs = 600
interaction = "medium"
ssh_max_auth_attempts = 3
http_max_requests = 5

[honeypot.sandbox]
enabled = true
runner_path = "/usr/local/bin/innerwarden-agent"
clear_env = false

[honeypot.pcap_handoff]
enabled = true
timeout_secs = 20
max_packets = 200

[honeypot.containment]
mode = "jail"
require_success = true
namespace_runner = "/usr/bin/unshare"
namespace_args = ["--fork", "--pid", "--mount-proc", "--net"]
jail_runner = "/usr/bin/bwrap"
jail_args = ["--die-with-parent", "--unshare-all"]
jail_profile = "strict"
allow_namespace_fallback = false

[honeypot.external_handoff]
enabled = true
command = "/usr/local/bin/iw-handoff"
args = ["--session-id", "{{session_id}}", "--metadata", "{{metadata_path}}", "--evidence", "{{evidence_path}}", "--pcap", "{{pcap_path}}"]
timeout_secs = 25
require_success = true
clear_env = false
allowed_commands = ["/usr/local/bin/iw-handoff", "/usr/local/bin/iw-alt"]
enforce_allowlist = true
signature_enabled = true
signature_key_env = "IW_HANDOFF_KEY"
attestation_enabled = true
attestation_key_env = "IW_HANDOFF_ATTEST_KEY"
attestation_prefix = "IW_ATTEST"
attestation_expected_receiver = "receiver-a"

[honeypot.redirect]
enabled = true
backend = "iptables"

[telegram]
enabled = true
bot_token = "1234567890:AAAAAAAAAA"
chat_id = "-1001234567890"
min_severity = "critical"
dashboard_url = "http://my-server:8787"
approval_ttl_secs = 300
"#
        )
        .unwrap();

        let cfg = load(f.path()).unwrap();
        assert!(!cfg.narrative.enabled);
        assert_eq!(cfg.narrative.keep_days, 3);
        assert!(cfg.webhook.enabled);
        assert_eq!(cfg.webhook.url, "https://hooks.example.com/notify");
        assert_eq!(cfg.webhook.parsed_min_severity(), Severity::High);
        assert_eq!(cfg.webhook.timeout_secs, 5);
        assert!(cfg.correlation.enabled);
        assert_eq!(cfg.correlation.window_seconds, 120);
        assert_eq!(cfg.correlation.max_related_incidents, 4);
        assert!(cfg.telemetry.enabled);
        assert_eq!(cfg.honeypot.mode, "listener");
        assert_eq!(cfg.honeypot.bind_addr, "0.0.0.0");
        assert_eq!(cfg.honeypot.port, 2223);
        assert_eq!(cfg.honeypot.duration_secs, 120);
        assert_eq!(
            cfg.honeypot.services,
            vec!["ssh".to_string(), "http".to_string()]
        );
        assert_eq!(cfg.honeypot.http_port, 8088);
        assert!(cfg.honeypot.strict_target_only);
        assert!(cfg.honeypot.allow_public_listener);
        assert_eq!(cfg.honeypot.max_connections, 10);
        assert_eq!(cfg.honeypot.max_payload_bytes, 256);
        assert_eq!(cfg.honeypot.isolation_profile, "standard");
        assert!(!cfg.honeypot.require_high_ports);
        assert_eq!(cfg.honeypot.forensics_keep_days, 14);
        assert_eq!(cfg.honeypot.forensics_max_total_mb, 512);
        assert_eq!(cfg.honeypot.transcript_preview_bytes, 192);
        assert_eq!(cfg.honeypot.lock_stale_secs, 600);
        assert_eq!(cfg.honeypot.interaction, "medium");
        assert_eq!(cfg.honeypot.ssh_max_auth_attempts, 3);
        assert_eq!(cfg.honeypot.http_max_requests, 5);
        assert!(cfg.honeypot.sandbox.enabled);
        assert_eq!(
            cfg.honeypot.sandbox.runner_path,
            "/usr/local/bin/innerwarden-agent"
        );
        assert!(!cfg.honeypot.sandbox.clear_env);
        assert!(cfg.honeypot.pcap_handoff.enabled);
        assert_eq!(cfg.honeypot.pcap_handoff.timeout_secs, 20);
        assert_eq!(cfg.honeypot.pcap_handoff.max_packets, 200);
        assert_eq!(cfg.honeypot.containment.mode, "jail");
        assert!(cfg.honeypot.containment.require_success);
        assert_eq!(
            cfg.honeypot.containment.namespace_runner,
            "/usr/bin/unshare"
        );
        assert_eq!(
            cfg.honeypot.containment.namespace_args,
            vec![
                "--fork".to_string(),
                "--pid".to_string(),
                "--mount-proc".to_string(),
                "--net".to_string()
            ]
        );
        assert_eq!(cfg.honeypot.containment.jail_runner, "/usr/bin/bwrap");
        assert_eq!(
            cfg.honeypot.containment.jail_args,
            vec!["--die-with-parent".to_string(), "--unshare-all".to_string()]
        );
        assert_eq!(cfg.honeypot.containment.jail_profile, "strict");
        assert!(!cfg.honeypot.containment.allow_namespace_fallback);
        assert!(cfg.honeypot.external_handoff.enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.command,
            "/usr/local/bin/iw-handoff"
        );
        assert_eq!(
            cfg.honeypot.external_handoff.args,
            vec![
                "--session-id".to_string(),
                "{session_id}".to_string(),
                "--metadata".to_string(),
                "{metadata_path}".to_string(),
                "--evidence".to_string(),
                "{evidence_path}".to_string(),
                "--pcap".to_string(),
                "{pcap_path}".to_string(),
            ]
        );
        assert_eq!(cfg.honeypot.external_handoff.timeout_secs, 25);
        assert!(cfg.honeypot.external_handoff.require_success);
        assert!(!cfg.honeypot.external_handoff.clear_env);
        assert_eq!(
            cfg.honeypot.external_handoff.allowed_commands,
            vec![
                "/usr/local/bin/iw-handoff".to_string(),
                "/usr/local/bin/iw-alt".to_string()
            ]
        );
        assert!(cfg.honeypot.external_handoff.enforce_allowlist);
        assert!(cfg.honeypot.external_handoff.signature_enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.signature_key_env,
            "IW_HANDOFF_KEY"
        );
        assert!(cfg.honeypot.external_handoff.attestation_enabled);
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_key_env,
            "IW_HANDOFF_ATTEST_KEY"
        );
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_prefix,
            "IW_ATTEST"
        );
        assert_eq!(
            cfg.honeypot.external_handoff.attestation_expected_receiver,
            "receiver-a"
        );
        assert!(cfg.honeypot.redirect.enabled);
        assert_eq!(cfg.honeypot.redirect.backend, "iptables");
        assert!(cfg.telegram.enabled);
        assert_eq!(cfg.telegram.bot_token, "1234567890:AAAAAAAAAA");
        assert_eq!(cfg.telegram.chat_id, "-1001234567890");
        assert_eq!(cfg.telegram.parsed_min_severity(), Severity::Critical);
        assert_eq!(cfg.telegram.dashboard_url, "http://my-server:8787");
        assert_eq!(cfg.telegram.approval_ttl_secs, 300);
    }

    #[test]
    fn parsed_min_severity_unknown_defaults_to_medium() {
        let cfg = WebhookConfig {
            min_severity: "bogus".into(),
            ..Default::default()
        };
        assert_eq!(cfg.parsed_min_severity(), Severity::Medium);
    }

    #[test]
    fn telegram_validate_disabled_is_ok() {
        let cfg = TelegramConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn telegram_validate_enabled_missing_token() {
        let cfg = TelegramConfig {
            enabled: true,
            bot_token: String::new(),
            chat_id: "-1001234567890".into(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("bot_token"),
            "error should mention bot_token: {err}"
        );
    }

    #[test]
    fn telegram_validate_enabled_missing_chat_id() {
        let cfg = TelegramConfig {
            enabled: true,
            bot_token: "1234567890:AAAAAAAAAA".into(),
            chat_id: String::new(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("chat_id"),
            "error should mention chat_id: {err}"
        );
    }

    #[test]
    fn telegram_validate_enabled_configured_is_ok() {
        let cfg = TelegramConfig {
            enabled: true,
            bot_token: "1234567890:AAAAAAAAAA".into(),
            chat_id: "-1001234567890".into(),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn telegram_validate_invalid_summary_hour() {
        let cfg = TelegramConfig {
            daily_summary_hour: Some(25),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("daily_summary_hour"),
            "error should mention daily_summary_hour: {err}"
        );
    }

    #[test]
    fn telegram_validate_valid_summary_hour() {
        let cfg = TelegramConfig {
            daily_summary_hour: Some(23),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    // -- AI config tests --

    #[test]
    fn ai_parsed_min_severity_defaults_to_medium() {
        // v0.12.4: default floor lowered from "high" to "medium" so AI
        // triage sees the Medium-severity layer (where most bot campaigns
        // live). Operators can still set "high" in agent.toml explicitly.
        let cfg = AiConfig::default();
        assert_eq!(cfg.parsed_min_severity(), Severity::Medium);
    }

    #[test]
    fn ai_parsed_min_severity_accepts_all_levels() {
        let mut cfg = AiConfig::default();
        cfg.min_severity = "low".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Low);
        cfg.min_severity = "medium".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Medium);
        cfg.min_severity = "high".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::High);
        cfg.min_severity = "critical".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Critical);
    }

    #[test]
    fn ai_parsed_min_severity_unknown_defaults_to_high() {
        let mut cfg = AiConfig::default();
        cfg.min_severity = "galaxy".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::High);
    }

    #[test]
    fn ai_resolved_api_key_prefers_config() {
        let mut cfg = AiConfig::default();
        cfg.api_key = "my-key".into();
        assert_eq!(cfg.resolved_api_key(), "my-key");
    }

    #[test]
    fn ai_resolved_api_key_empty_config_falls_to_env() {
        let cfg = AiConfig::default();
        // Without env var set, returns empty string
        let key = cfg.resolved_api_key();
        // This just checks it doesn't panic; actual value depends on env
        let _ = key;
    }

    #[test]
    fn ai_default_values() {
        let cfg = AiConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.provider, "openai");
        assert!(
            (cfg.confidence_threshold - 0.85).abs() < f32::EPSILON,
            "default threshold should be 0.85"
        );
        assert!(cfg.max_ai_calls_per_tick > 0);
        assert_eq!(cfg.circuit_breaker_threshold, 0); // disabled by default
    }

    // -- Telegram additional tests --

    #[test]
    fn telegram_is_simple_profile_case_insensitive() {
        let mut cfg = TelegramConfig::default();
        cfg.user_profile = "Simple".into();
        assert!(cfg.is_simple_profile());
        cfg.user_profile = "SIMPLE".into();
        assert!(cfg.is_simple_profile());
        cfg.user_profile = "technical".into();
        assert!(!cfg.is_simple_profile());
    }

    #[test]
    fn telegram_parsed_min_severity_all_levels() {
        let mut cfg = TelegramConfig::default();
        cfg.min_severity = "low".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Low);
        cfg.min_severity = "medium".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Medium);
        cfg.min_severity = "critical".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Critical);
        cfg.min_severity = "nonsense".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::High); // default fallback
    }

    // -- Slack config tests --

    #[test]
    fn slack_parsed_min_severity_defaults_to_high() {
        let cfg = SlackConfig::default();
        assert_eq!(cfg.parsed_min_severity(), Severity::High);
    }

    #[test]
    fn slack_parsed_min_severity_unknown_defaults_to_high() {
        let mut cfg = SlackConfig::default();
        cfg.min_severity = "banana".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::High);
    }

    // -- Webhook config tests --

    #[test]
    fn webhook_parsed_min_severity_all_levels() {
        let mut cfg = WebhookConfig::default();
        cfg.min_severity = "debug".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Debug);
        cfg.min_severity = "info".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Info);
        cfg.min_severity = "low".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Low);
        cfg.min_severity = "high".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::High);
        cfg.min_severity = "critical".into();
        assert_eq!(cfg.parsed_min_severity(), Severity::Critical);
    }

    // -- Responder defaults --

    #[test]
    fn responder_defaults() {
        let cfg = ResponderConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.dry_run);
        assert!(!cfg.allowed_skills.is_empty());
    }

    // -- Channel notification defaults --

    #[test]
    fn channel_notification_default_is_actionable() {
        let cfg = ChannelNotificationConfig::default();
        assert_eq!(cfg.notification_level, ChannelFilterLevel::Actionable);
    }

    // -- Briefing config defaults --

    #[test]
    fn briefing_defaults() {
        let cfg = BriefingConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.hour, 8);
        assert_eq!(cfg.minute, 0);
        assert!(cfg.telegram);
    }

    #[test]
    fn clamp_confidence_threshold_fixes_unreachable_upper_bound() {
        let mut ai = AiConfig::default();
        ai.confidence_threshold = 1.01;
        ai.clamp_confidence_threshold();
        assert!(
            (ai.confidence_threshold - default_confidence_threshold()).abs() < f32::EPSILON,
            "threshold > 1.0 must be clamped to default"
        );
    }

    #[test]
    fn clamp_confidence_threshold_fixes_negative() {
        let mut ai = AiConfig::default();
        ai.confidence_threshold = -0.5;
        ai.clamp_confidence_threshold();
        assert!(
            (ai.confidence_threshold - default_confidence_threshold()).abs() < f32::EPSILON,
            "negative threshold must be clamped to default"
        );
    }

    #[test]
    fn clamp_confidence_threshold_leaves_valid_values_untouched() {
        for v in [0.0_f32, 0.5, 0.7, 0.85, 0.99, 1.0] {
            let mut ai = AiConfig::default();
            ai.confidence_threshold = v;
            ai.clamp_confidence_threshold();
            assert!(
                (ai.confidence_threshold - v).abs() < f32::EPSILON,
                "valid threshold {v} must not be clamped",
            );
        }
    }

    #[test]
    fn load_clamps_bogus_confidence_threshold() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "[ai]\nconfidence_threshold = 1.01").unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert!(
            (cfg.ai.confidence_threshold - default_confidence_threshold()).abs() < f32::EPSILON,
            "load() must apply clamp so autonomous execution can fire"
        );
    }

    /// 2026-05-02 follow-up: operators running a shared binary on
    /// multiple hosts (some with dashboard, some headless) want the
    /// toggle in TOML, not in the systemd ExecStart line. The boot
    /// path AND-gates `cli.dashboard && cfg.dashboard.enabled` so
    /// the config field has real effect: setting `enabled = false`
    /// keeps the agent-guard regex compile, HTTP/TLS runtime, and
    /// session machinery off (~50-70 MB RSS).
    #[test]
    fn dashboard_enabled_can_be_overridden_to_false() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "[dashboard]\nenabled = false").unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert!(
            !cfg.dashboard.enabled,
            "TOML `[dashboard].enabled = false` must parse and propagate"
        );
        // Other dashboard defaults must not regress when only the
        // toggle is overridden.
        assert_eq!(
            cfg.dashboard.session_timeout_minutes,
            default_session_timeout_minutes()
        );
        assert_eq!(cfg.dashboard.max_sessions, default_max_sessions());
    }

    /// Spec 038 Phase 1: enabling fleet mode with a host roster must
    /// parse cleanly and propagate to the runtime. The poller in
    /// `boot.rs` reads from `cfg.fleet`; this anchor pins that the
    /// shape (hosts as table-array with `id` / `url` / `token_env`)
    /// is what the loader produces.
    #[test]
    fn fleet_enabled_with_host_list_parses() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "[fleet]\nenabled = true\npoll_interval_seconds = 60\n\
             [[fleet.hosts]]\nid = \"prod-eu\"\nurl = \"https://eu.example.com:8787\"\ntoken_env = \"FLEET_TOKEN_EU\"\n\
             [[fleet.hosts]]\nid = \"prod-us\"\nurl = \"https://us.example.com:8787\""
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert!(cfg.fleet.enabled);
        assert_eq!(cfg.fleet.poll_interval_seconds, 60);
        assert_eq!(cfg.fleet.hosts.len(), 2);
        assert_eq!(cfg.fleet.hosts[0].id, "prod-eu");
        assert_eq!(cfg.fleet.hosts[0].url, "https://eu.example.com:8787");
        assert_eq!(cfg.fleet.hosts[0].token_env, "FLEET_TOKEN_EU");
        assert_eq!(cfg.fleet.hosts[1].id, "prod-us");
        // Missing token_env / username_env / password_env default to
        // empty string, not an error. Phase 4 reads username +
        // password env vars only when they are set; an unconfigured
        // host stays in static-bearer mode.
        assert!(cfg.fleet.hosts[1].token_env.is_empty());
        assert!(cfg.fleet.hosts[1].username_env.is_empty());
        assert!(cfg.fleet.hosts[1].password_env.is_empty());
    }

    /// Spec 038 Phase 4: the manager consumes a host with
    /// username/password env vars instead of a static bearer when
    /// the operator wants automatic login refresh on 401.
    #[test]
    fn fleet_phase4_login_refresh_config_parses() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "[fleet]\nenabled = true\n\
             [[fleet.hosts]]\nid = \"prod-eu\"\nurl = \"https://eu.example.com:8787\"\nusername_env = \"FLEET_USER_EU\"\npassword_env = \"FLEET_PASS_EU\""
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert_eq!(cfg.fleet.hosts[0].username_env, "FLEET_USER_EU");
        assert_eq!(cfg.fleet.hosts[0].password_env, "FLEET_PASS_EU");
        assert!(cfg.fleet.hosts[0].token_env.is_empty());
    }

    #[test]
    fn shadow_config_default_is_disabled() {
        let s = ShadowConfig::default();
        assert!(!s.enabled);
        assert!(s.provider.is_empty());
        assert!(s.api_key.is_empty());
        assert!(s.model.is_empty());
        assert!(s.base_url.is_empty());
        assert!(s.api_version.is_empty());
        assert_eq!(s.log_path, "/var/lib/innerwarden/shadow-decisions.jsonl");
        assert_eq!(
            s.sample_rate, 1.0,
            "default must preserve legacy 100% shadow behaviour"
        );
    }

    #[test]
    fn shadow_config_validate_rejects_out_of_range_sample_rate() {
        // Operator typo guard. After RESULTS_V3 lowered shadow sampling
        // to 0.1 in prod, a bad edit (e.g. `1.1` or negative) must fail
        // at startup rather than silently clamp.
        let mut s = ShadowConfig::default();
        s.enabled = true;
        s.provider = "azure_openai".to_string();

        s.sample_rate = 1.5;
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("sample_rate"),
            "validate must mention sample_rate, got: {err}"
        );

        s.sample_rate = -0.1;
        assert!(s.validate().is_err());

        s.sample_rate = f32::NAN;
        assert!(s.validate().is_err());

        // Disabled config skips the check.
        s.enabled = false;
        s.sample_rate = f32::INFINITY;
        assert!(s.validate().is_ok(), "disabled shadow skips validation");

        // Boundary values pass.
        s.enabled = true;
        s.sample_rate = 0.0;
        assert!(s.validate().is_ok());
        s.sample_rate = 1.0;
        assert!(s.validate().is_ok());
        s.sample_rate = 0.1;
        assert!(s.validate().is_ok());
    }

    #[test]
    fn shadow_config_default_log_path_constant() {
        assert_eq!(
            default_shadow_log_path(),
            "/var/lib/innerwarden/shadow-decisions.jsonl"
        );
    }

    #[test]
    fn shadow_resolved_api_key_field_wins() {
        let mut s = ShadowConfig::default();
        s.api_key = "explicit-key".into();
        s.provider = "openai".into();
        assert_eq!(s.resolved_api_key(), "explicit-key");
    }

    #[test]
    fn shadow_resolved_api_key_matches_each_provider_branch() {
        // Each provider branch must compile + run without panic regardless of
        // the host's env. Function returns String (never errors).
        for provider in ["openai", "anthropic", "ollama", "azure_openai", "unknown"] {
            let mut s = ShadowConfig::default();
            s.provider = provider.into();
            // field empty -> goes into match
            let _ = s.resolved_api_key();
        }
    }

    #[test]
    fn ai_config_default_has_disabled_shadow() {
        let cfg = AiConfig::default();
        assert!(!cfg.shadow.enabled);
        assert!(cfg.api_version.is_empty());
    }

    #[test]
    fn load_parses_shadow_config_block() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"[ai]
provider = "azure_openai"
model = "gpt-5-4-mini"
base_url = "https://example-resource.openai.azure.com"
api_version = "2024-12-01-preview"

[ai.shadow]
enabled = true
provider = "stub"
log_path = "/tmp/shadow.jsonl"
"#
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert_eq!(cfg.ai.provider, "azure_openai");
        assert_eq!(cfg.ai.api_version, "2024-12-01-preview");
        assert!(cfg.ai.shadow.enabled);
        assert_eq!(cfg.ai.shadow.provider, "stub");
        assert_eq!(cfg.ai.shadow.log_path, "/tmp/shadow.jsonl");
    }

    #[test]
    fn ai_resolved_api_key_recognises_azure_env() {
        // The AiConfig::resolved_api_key match added "azure_openai" arm.
        // Same coverage guarantee as shadow: hit each branch without panic.
        for provider in ["openai", "anthropic", "ollama", "azure_openai", "unknown"] {
            let mut ai = AiConfig::default();
            ai.provider = provider.into();
            let _ = ai.resolved_api_key();
        }
    }

    // Spec 028-b: incident_flow config defaults keep the flag off and the
    // skip-fase3 list empty so bundled deploy changes nothing about decision
    // behaviour until operator flips the flag explicitly.
    #[test]
    fn incident_flow_defaults_are_conservative() {
        let cfg = IncidentFlowConfig::default();
        assert!(!cfg.escalate_to_decide);
        assert!(cfg.detectors_skip_fase3.is_empty());
    }

    #[test]
    fn load_parses_incident_flow_section() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"[incident_flow]
escalate_to_decide = true
detectors_skip_fase3 = ["threat_intel", "sudo_abuse", "suspicious_execution"]
"#
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert!(cfg.incident_flow.escalate_to_decide);
        assert_eq!(cfg.incident_flow.detectors_skip_fase3.len(), 3);
        assert!(cfg
            .incident_flow
            .detectors_skip_fase3
            .iter()
            .any(|d| d == "threat_intel"));
    }

    // Spec 029 PR-C: RoleProviderConfig default is disabled + empty.
    // When both per-role blocks are absent from agent.toml the router
    // falls back to the primary [ai] provider (PR-B back-compat).
    #[test]
    fn role_provider_config_default_is_disabled() {
        let r = RoleProviderConfig::default();
        assert!(
            r.enabled.is_none(),
            "default leaves enabled unset (inferred)"
        );
        assert!(!r.is_active(), "no provider configured -> inactive");
        assert!(r.provider.is_empty());
        assert!(r.api_key.is_empty());
        assert!(r.model.is_empty());
        assert!(r.base_url.is_empty());
        assert!(r.api_version.is_empty());
    }

    // Spec 029 PR-C: ai_config defaults keep both per-role blocks
    // disabled so pre-029 configs auto-use the primary [ai] block.
    #[test]
    fn ai_config_default_has_disabled_per_role_blocks() {
        let cfg = AiConfig::default();
        assert!(!cfg.classifier.is_active());
        assert!(!cfg.llm.is_active());
    }

    // Spec 029 PR-C: to_ai_config maps the per-role fields into a
    // full AiConfig shell suitable for ai::build_provider. Shared
    // knobs (confidence_threshold, min_severity, etc.) default.
    #[test]
    fn role_provider_to_ai_config_maps_fields() {
        let role = RoleProviderConfig {
            enabled: Some(true),
            provider: "azure_openai".into(),
            api_key: "explicit".into(),
            model: "gpt-5.4-mini".into(),
            base_url: "https://example.openai.azure.com".into(),
            api_version: "2024-12-01-preview".into(),
        };
        let cfg = role.to_ai_config();
        assert!(cfg.enabled);
        assert_eq!(cfg.provider, "azure_openai");
        assert_eq!(cfg.api_key, "explicit");
        assert_eq!(cfg.model, "gpt-5.4-mini");
        assert_eq!(cfg.base_url, "https://example.openai.azure.com");
        assert_eq!(cfg.api_version, "2024-12-01-preview");
        // Shared knobs come from AiConfig::default().
        assert!(!cfg.shadow.enabled);
        assert_eq!(cfg.min_severity, "medium");
    }

    // Spec 029 PR-C: empty api_key on to_ai_config stays empty so
    // the downstream AiConfig::resolved_api_key env-var fallback
    // (OPENAI_API_KEY, AZURE_OPENAI_API_KEY, etc.) fires normally.
    #[test]
    fn role_provider_to_ai_config_preserves_empty_api_key() {
        let role = RoleProviderConfig {
            enabled: Some(true),
            provider: "openai".into(),
            api_key: String::new(),
            ..Default::default()
        };
        let cfg = role.to_ai_config();
        assert!(cfg.api_key.is_empty());
    }

    // Spec 029 PR-C: parses the warden + llm TOML sections.
    #[test]
    fn load_parses_warden_and_llm_sections() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"[ai]
enabled = true
provider = "stub"

[ai.warden]
enabled = true
provider = "local_warden"
base_url = "/var/lib/innerwarden/models/warden"

[ai.llm]
enabled = true
provider = "azure_openai"
model = "gpt-5.4-mini"
base_url = "https://example.openai.azure.com"
api_version = "2024-12-01-preview"
"#
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();

        assert!(cfg.ai.enabled);
        assert_eq!(cfg.ai.provider, "stub");

        assert!(cfg.ai.classifier.is_active());
        assert_eq!(cfg.ai.classifier.provider, "local_warden");
        assert_eq!(
            cfg.ai.classifier.base_url,
            "/var/lib/innerwarden/models/warden"
        );

        assert!(cfg.ai.llm.is_active());
        assert_eq!(cfg.ai.llm.provider, "azure_openai");
        assert_eq!(cfg.ai.llm.model, "gpt-5.4-mini");
        assert_eq!(cfg.ai.llm.api_version, "2024-12-01-preview");
    }

    // 2026-05-03: back-compat anchor — old `[ai.classifier]` TOMLs
    // must keep parsing. Existing prod configs MUST NOT break on
    // upgrade.
    #[test]
    fn load_accepts_legacy_classifier_alias_for_warden_section() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"[ai]
enabled = true
provider = "stub"

[ai.classifier]
enabled = true
provider = "local_classifier"
base_url = "/var/lib/innerwarden/models/classifier"
"#
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert!(
            cfg.ai.classifier.is_active(),
            "legacy [ai.classifier] section must still deserialize"
        );
        assert_eq!(cfg.ai.classifier.provider, "local_classifier");
    }

    // Release-blocker B1 regression (2026-05-29): `install.sh` /
    // `innerwarden setup` write `[ai.warden] provider = "local_warden"`
    // WITHOUT `enabled = true`. Before the tri-state `is_active()` the
    // section parsed with `enabled = false`, so the on-device model -
    // downloaded and SHA-verified on disk - was silently never loaded
    // and every fresh install ran Decide on the (often unconfigured)
    // cloud fallback. A warden section that names a provider must be
    // active even when `enabled` is omitted.
    #[test]
    fn warden_section_with_provider_but_no_enabled_is_active() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"[ai.warden]
provider = "local_warden"
base_url = "/var/lib/innerwarden/models/classifier"
"#
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert!(
            cfg.ai.classifier.enabled.is_none(),
            "the install path does not write the enabled key"
        );
        assert!(
            cfg.ai.classifier.is_active(),
            "a [ai.warden] with a provider configured MUST activate the on-device model"
        );
        assert!(!cfg.ai.classifier.is_provider_set_but_disabled());
    }

    // Counterpart: an explicit `enabled = false` is respected even when
    // a provider is configured (operator deliberately parked the model),
    // and the boot path flags it as provider-set-but-disabled so the
    // skip is loud, never silent.
    #[test]
    fn warden_section_explicitly_disabled_with_provider_stays_inactive() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"[ai.warden]
enabled = false
provider = "local_warden"
base_url = "/var/lib/innerwarden/models/classifier"
"#
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert_eq!(cfg.ai.classifier.enabled, Some(false));
        assert!(!cfg.ai.classifier.is_active());
        assert!(
            cfg.ai.classifier.is_provider_set_but_disabled(),
            "boot path must be able to warn about a disabled-but-configured slot"
        );
    }

    // Spec 029 PR-C: legacy `[ai]` only config is still parsed with
    // classifier/llm blocks defaulting to disabled. Back-compat gate.
    #[test]
    fn load_without_per_role_sections_leaves_slots_disabled() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"[ai]
enabled = true
provider = "stub"
model = "legacy"
"#
        )
        .unwrap();
        let cfg = load(tmp.path()).unwrap();
        assert_eq!(cfg.ai.provider, "stub");
        // Per-role blocks default to disabled so the boot path falls
        // back to the primary [ai] provider for both slots.
        assert!(!cfg.ai.classifier.is_active());
        assert!(!cfg.ai.llm.is_active());
    }

    // ── Wave 9e anchors (2026-05-04) — strict schema gate ─────────────────
    //
    // AUDIT-002 root cause: prod's agent.toml had a `[data_retention]`
    // section with an `enabled` and `keep_days` keys, but the AgentConfig
    // field is `pub data: DataRetentionConfig` (TOML key would be `[data]`),
    // and `enabled`/`keep_days` are not fields on DataRetentionConfig (real
    // names are `events_keep_days`, `filestore_keep_days`, etc). The whole
    // section silently deserialised as the default for who knows how long;
    // the operator's Wave 9c attempt to set `filestore_max_size_mb = 1024`
    // there was a no-op for the same reason.
    //
    // The fix is two-pronged:
    //   1. `#[serde(deny_unknown_fields)]` on every nested *Config struct so
    //      typo'd keys produce a LOUD startup error instead of being dropped
    //      silently.
    //   2. `#[serde(alias = "data_retention")]` on `AgentConfig::data` so
    //      existing `[data_retention]` blocks keep working - operators
    //      migrate at their own pace and a forced rename does not brick the
    //      next deploy.
    //
    // These anchors pin both sides. Removing either is a regression because
    // (1) takes us back to silent drift, (2) bricks every existing
    // [data_retention] config on the next deploy.

    #[test]
    fn data_retention_alias_resolves_to_data_section() {
        // Existing prod-style config. With the alias on `pub data`, this
        // section parses into `cfg.data` (the canonical AgentConfig field),
        // and the inner field `filestore_max_size_mb` is now actually
        // applied (pre-alias the section was dropped silently).
        let toml_src = r#"
[data_retention]
filestore_max_size_mb = 1024
events_keep_days = 14
"#;
        let cfg: AgentConfig = toml::from_str(toml_src)
            .expect("[data_retention] alias must resolve to [data] - this is the AUDIT-002 fix");
        assert_eq!(cfg.data.filestore_max_size_mb, 1024);
        assert_eq!(cfg.data.events_keep_days, 14);
    }

    #[test]
    fn data_section_canonical_name_works_too() {
        // The canonical TOML key is `[data]` because that matches the
        // AgentConfig field name. Both forms must parse so operators can
        // migrate gradually without a flag day.
        let toml_src = r#"
[data]
filestore_max_size_mb = 512
"#;
        let cfg: AgentConfig =
            toml::from_str(toml_src).expect("canonical [data] section must parse");
        assert_eq!(cfg.data.filestore_max_size_mb, 512);
    }

    #[test]
    fn unknown_top_level_section_fails_loudly() {
        // A typo'd or invented section name is rejected by serde because
        // AgentConfig has #[serde(deny_unknown_fields)]. This is the gate
        // that prevents the AUDIT-002 class of silent drift on top-level
        // sections.
        let toml_src = r#"
[bogus_section]
key = "value"
"#;
        let err = toml::from_str::<AgentConfig>(toml_src).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("unknown field") || msg.contains("bogus_section"),
            "deny_unknown_fields must reject [bogus_section]; got: {msg}"
        );
    }

    #[test]
    fn unknown_inner_key_fails_loudly_in_data_section() {
        // The actual prod failure mode: under [data_retention] (or [data])
        // the operator wrote keys that are not fields on
        // DataRetentionConfig. With deny_unknown_fields on the inner struct
        // those typos fail at boot.
        let toml_src = r#"
[data]
keep_dayss = 7
"#;
        let err = toml::from_str::<AgentConfig>(toml_src).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("unknown field") || msg.contains("keep_dayss"),
            "deny_unknown_fields must reject `keep_dayss` typo; got: {msg}"
        );
    }

    #[test]
    fn legacy_data_retention_with_unknown_inner_key_also_fails_loudly() {
        // Same as above but via the [data_retention] alias, so the alias
        // does not weaken the strictness of the inner schema. The previous
        // prod agent.toml had `keep_days = 7` and `enabled = true` under
        // [data_retention] - both are not fields on DataRetentionConfig.
        // After this change those would now LOUDLY fail at boot, prompting
        // the operator to either remove them or correct the field name.
        let toml_src = r#"
[data_retention]
keep_days = 7
enabled = true
"#;
        let err = toml::from_str::<AgentConfig>(toml_src).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("unknown field"),
            "alias must NOT bypass deny_unknown_fields on the inner DataRetentionConfig; got: {msg}"
        );
    }

    #[test]
    fn empty_config_uses_defaults_cleanly() {
        // Sanity: an empty file parses to AgentConfig::default(). This is
        // the path that `crate::config::load` takes for a missing file via
        // an explicit early-return; testing the in-memory parse confirms
        // the wire compatibility too. If a future struct breaks Default,
        // this anchor catches it before the agent panics on first restart.
        let cfg: AgentConfig = toml::from_str("").expect("empty config is valid");
        assert_eq!(
            cfg.data.filestore_max_size_mb,
            default_data_filestore_max_size_mb()
        );
    }

    #[test]
    fn learning_section_absent_uses_safe_defaults() {
        // Spec 062 migration rule: an existing agent.toml with NO
        // [learning] section must upgrade cleanly to shadow mode (no
        // behaviour change) and N = 5 — never silently disabled, never
        // enforcing by default. Repeats the [observation]-absent gap fix.
        let cfg: AgentConfig = toml::from_str("").expect("empty config is valid");
        assert_eq!(cfg.learning.suppression_mode, "shadow");
        assert_eq!(cfg.learning.min_dismissals, 5);
        // Spec 062 Phase 5 defaults: LLM escalation on, 0.75 confidence floor.
        assert!(cfg.learning.llm_escalation_enabled);
        assert!((cfg.learning.llm_escalation_min_confidence - 0.75).abs() < f32::EPSILON);
        // Spec 062 Phase 3: needs_review Telegram notify is opt-in (default off).
        assert!(!cfg.learning.needs_review_notify);
        // Spec 062 Phase 6a: label channel is additive, on by default.
        assert!(cfg.learning.emit_labels);
        // Spec 062 Phase 6b: mesh corroboration is opt-in (default off).
        assert!(!cfg.learning.mesh_suppression_corroboration);
    }

    #[test]
    fn learning_section_parses_needs_review_notify_override() {
        let src = "[learning]\nneeds_review_notify = true\n";
        let cfg: AgentConfig = toml::from_str(src).expect("phase3 learning parses");
        assert!(cfg.learning.needs_review_notify);
    }

    #[test]
    fn learning_section_parses_phase6_overrides() {
        let src = "[learning]\nemit_labels = false\nmesh_suppression_corroboration = true\n";
        let cfg: AgentConfig = toml::from_str(src).expect("phase6 learning parses");
        assert!(!cfg.learning.emit_labels);
        assert!(cfg.learning.mesh_suppression_corroboration);
    }

    #[test]
    fn learning_section_parses_enforce_override() {
        let src = "[learning]\nsuppression_mode = \"enforce\"\nmin_dismissals = 10\n";
        let cfg: AgentConfig = toml::from_str(src).expect("learning section parses");
        assert_eq!(cfg.learning.suppression_mode, "enforce");
        assert_eq!(cfg.learning.min_dismissals, 10);
        // Phase 5 fields keep their defaults when omitted.
        assert!(cfg.learning.llm_escalation_enabled);
    }

    #[test]
    fn learning_section_parses_phase5_overrides() {
        let src = "[learning]\nllm_escalation_enabled = false\n\
                   llm_escalation_min_confidence = 0.9\n";
        let cfg: AgentConfig = toml::from_str(src).expect("phase5 learning parses");
        assert!(!cfg.learning.llm_escalation_enabled);
        assert!((cfg.learning.llm_escalation_min_confidence - 0.9).abs() < f32::EPSILON);
        assert_eq!(cfg.learning.suppression_mode, "shadow");
    }

    #[test]
    fn agent_section_tags_parse_and_default_empty() {
        // Spec 058 minimal slice: host asset tags drive playbook
        // `conditions.asset_tags`.
        let cfg: AgentConfig = toml::from_str("[agent]\ntags = [\"env=prod\", \"role=web\"]\n")
            .expect("[agent] tags must parse");
        assert_eq!(
            cfg.agent.tags,
            vec!["env=prod".to_string(), "role=web".to_string()]
        );
        // Absent section -> empty tags (no asset_tags gate on any playbook).
        let empty: AgentConfig = toml::from_str("").expect("empty config valid");
        assert!(empty.agent.tags.is_empty());
    }

    #[test]
    fn every_top_level_section_is_documented_with_an_inner_struct() {
        // Lock the set of top-level sections so a future contributor cannot
        // remove a section silently (which would make every operator's
        // existing config fail loudly). Adding a new section is fine; the
        // assertion lives over a stable subset that prod has been parsing
        // for months. If a section is RENAMED, this test fails AND it must
        // be paired with a `#[serde(alias)]` on the new field name (same
        // pattern as `data_retention -> data` here).
        let known = &[
            "narrative",
            "webhook",
            "ai",
            "correlation",
            "telemetry",
            "honeypot",
            "responder",
            "telegram",
            "agent",
            "data",
            // "data_retention" is intentionally NOT here: toml refuses to
            // parse the same field twice via aliases. The alias is exercised
            // by `data_retention_alias_resolves_to_data_section` instead.
            "crowdsec",
            "abuseipdb",
            "fail2ban",
            "geoip",
            "threat_feeds",
            "slack",
            "cloudflare",
            "allowlist",
            "web_push",
            "mesh",
            "dashboard",
            "fleet",
            "firmware",
            "hypervisor",
            "killchain",
            "dna",
            "shield",
            "security",
            "notifications",
            "environment",
            "briefing",
            "config_signing",
            "observation",
            "trust_scoring",
            "soc_checks",
            "zero_trust",
            "graph_only_detectors",
            "incident_flow",
            "agent_guard",
        ];
        // Build a minimal TOML with every section header. None of the
        // sections gets unknown keys, so they all default-fill. If any
        // section name in the list is wrong, parsing fails.
        let mut toml_src = String::new();
        for name in known {
            // [graph_only_detectors] is a Vec, not a section; skip header.
            if *name == "graph_only_detectors" {
                continue;
            }
            toml_src.push_str(&format!("[{}]\n", name));
        }
        let result: Result<AgentConfig, _> = toml::from_str(&toml_src);
        assert!(
            result.is_ok(),
            "minimal [section] file with all known sections must parse; got: {:#}",
            result.err().unwrap()
        );
    }
}
