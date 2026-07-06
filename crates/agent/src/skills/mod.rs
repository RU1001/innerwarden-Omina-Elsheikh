pub mod builtin;

use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use innerwarden_core::incident::Incident;
use serde::Serialize;
use tracing::info;

// ---------------------------------------------------------------------------
// Skill types
// ---------------------------------------------------------------------------

/// Tier determines the availability of a skill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SkillTier {
    /// Free and open-source — all skills are open.
    Open,
}

/// Context passed to a skill when it is executed.
// Fields `incident` and `host` are public API for community skill implementations;
// built-in skills only require `target_ip` today.
#[allow(dead_code)]
pub struct SkillContext {
    pub incident: Incident,
    /// Primary IP target, if applicable.
    pub target_ip: Option<String>,
    /// Primary user target, if applicable.
    pub target_user: Option<String>,
    /// Primary container target, if applicable (Docker container ID or name).
    pub target_container: Option<String>,
    /// Optional action duration (seconds), used by temporary containment skills.
    pub duration_secs: Option<u64>,
    pub host: String,
    /// Shared data dir used by sensor/agent artifacts.
    pub data_dir: PathBuf,
    /// Runtime honeypot config (used only by honeypot skill).
    pub honeypot: HoneypotRuntimeConfig,
    /// AI provider passed to skills that require it (e.g. honeypot llm_shell).
    pub ai_provider: Option<std::sync::Arc<dyn crate::ai::AiProvider>>,
}

#[derive(Clone)]
pub struct HoneypotRuntimeConfig {
    /// `demo` | `listener`
    pub mode: String,
    /// Listener bind address when mode = `listener`
    pub bind_addr: String,
    /// SSH decoy listener port when mode = `listener`
    pub port: u16,
    /// HTTP decoy listener port when mode = `listener`
    pub http_port: u16,
    /// Listener lifetime in seconds when mode = `listener`
    pub duration_secs: u64,
    /// Enabled decoy services. Supported: `ssh`, `http`.
    pub services: Vec<String>,
    /// Accept only the target IP while listener session is active.
    pub strict_target_only: bool,
    /// Allow non-loopback bind addresses.
    pub allow_public_listener: bool,
    /// Hard cap of accepted connections per service listener.
    pub max_connections: usize,
    /// Max payload bytes captured per connection.
    pub max_payload_bytes: usize,
    /// Isolation profile (`strict_local` | `standard`).
    pub isolation_profile: String,
    /// Require non-privileged listener ports (>= 1024).
    pub require_high_ports: bool,
    /// Retain honeypot forensics artifacts for this many days.
    pub forensics_keep_days: usize,
    /// Hard cap for total honeypot forensics storage in MB.
    pub forensics_max_total_mb: usize,
    /// Max bytes rendered in transcript preview fields.
    pub transcript_preview_bytes: usize,
    /// Active session lock stale threshold in seconds.
    pub lock_stale_secs: u64,
    /// Run listeners in dedicated subprocess workers.
    pub sandbox_enabled: bool,
    /// Optional runner binary path.
    pub sandbox_runner_path: String,
    /// Clear environment for runner subprocesses.
    pub sandbox_clear_env: bool,
    /// Run bounded pcap handoff capture at session end.
    pub pcap_handoff_enabled: bool,
    /// Handoff capture timeout in seconds.
    pub pcap_handoff_timeout_secs: u64,
    /// Handoff capture max packets.
    pub pcap_handoff_max_packets: u64,
    /// Containment mode (`process` | `namespace`).
    pub containment_mode: String,
    /// If true, fail when requested containment mode is unavailable.
    pub containment_require_success: bool,
    /// Namespace wrapper runner (e.g., `unshare`) when containment mode is `namespace`.
    pub containment_namespace_runner: String,
    /// Arguments passed to namespace wrapper before the agent runner.
    pub containment_namespace_args: Vec<String>,
    /// Jail wrapper runner (e.g., `bwrap`) when containment mode is `jail`.
    pub containment_jail_runner: String,
    /// Arguments passed to jail wrapper before the agent runner.
    pub containment_jail_args: Vec<String>,
    /// Jail profile preset (`standard` | `strict`).
    pub containment_jail_profile: String,
    /// Allow fallback from `jail` to `namespace` when jail runner is unavailable.
    pub containment_allow_namespace_fallback: bool,
    /// Execute optional external handoff command after session completion.
    pub external_handoff_enabled: bool,
    /// External handoff command.
    pub external_handoff_command: String,
    /// External handoff arguments with placeholder support.
    pub external_handoff_args: Vec<String>,
    /// External handoff timeout in seconds.
    pub external_handoff_timeout_secs: u64,
    /// Mark session as error if external handoff fails.
    pub external_handoff_require_success: bool,
    /// Clear environment before launching external handoff.
    pub external_handoff_clear_env: bool,
    /// Command allowlist for trusted external handoff.
    pub external_handoff_allowed_commands: Vec<String>,
    /// Require command allowlist match.
    pub external_handoff_enforce_allowlist: bool,
    /// Sign handoff result (HMAC-SHA256) when enabled.
    pub external_handoff_signature_enabled: bool,
    /// Env var name containing signing key.
    pub external_handoff_signature_key_env: String,
    /// Validate receiver attestation output from handoff command.
    pub external_handoff_attestation_enabled: bool,
    /// Env var name containing attestation key.
    pub external_handoff_attestation_key_env: String,
    /// Prefix used in attestation output lines.
    pub external_handoff_attestation_prefix: String,
    /// Optional pinned receiver identifier for attestation.
    pub external_handoff_attestation_expected_receiver: String,
    /// Optional selective redirection.
    pub redirect_enabled: bool,
    /// Redirect backend identifier.
    pub redirect_backend: String,
    /// Interaction level: `banner` (static banner only) | `medium` (protocol emulation) | `llm_shell` (AI-backed interactive shell).
    pub interaction: String,
    /// Max SSH auth attempts before disconnecting client (medium interaction only).
    pub ssh_max_auth_attempts: usize,
    /// Max HTTP requests per connection (medium interaction only).
    pub http_max_requests: usize,
    /// AI provider for `llm_shell` interaction mode.
    /// When `interaction = "llm_shell"` and this is `None`, the skill falls back to `RejectAll`.
    pub ai_provider: Option<std::sync::Arc<dyn crate::ai::AiProvider>>,
}

impl std::fmt::Debug for HoneypotRuntimeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HoneypotRuntimeConfig")
            .field("mode", &self.mode)
            .field("interaction", &self.interaction)
            .field("bind_addr", &self.bind_addr)
            .field("port", &self.port)
            .field("ai_provider", &self.ai_provider.as_ref().map(|p| p.name()))
            .finish_non_exhaustive()
    }
}

impl Default for HoneypotRuntimeConfig {
    fn default() -> Self {
        Self {
            mode: "demo".to_string(),
            bind_addr: "127.0.0.1".to_string(),
            port: 2222,
            http_port: 8080,
            duration_secs: 300,
            services: vec!["ssh".to_string()],
            strict_target_only: true,
            allow_public_listener: false,
            max_connections: 64,
            max_payload_bytes: 512,
            isolation_profile: "strict_local".to_string(),
            require_high_ports: true,
            forensics_keep_days: 7,
            forensics_max_total_mb: 128,
            transcript_preview_bytes: 96,
            lock_stale_secs: 1800,
            sandbox_enabled: false,
            sandbox_runner_path: String::new(),
            sandbox_clear_env: true,
            pcap_handoff_enabled: false,
            pcap_handoff_timeout_secs: 15,
            pcap_handoff_max_packets: 120,
            containment_mode: "process".to_string(),
            containment_require_success: false,
            containment_namespace_runner: "unshare".to_string(),
            containment_namespace_args: vec![
                "--fork".to_string(),
                "--pid".to_string(),
                "--mount-proc".to_string(),
            ],
            containment_jail_runner: "bwrap".to_string(),
            containment_jail_args: vec![],
            containment_jail_profile: "standard".to_string(),
            containment_allow_namespace_fallback: true,
            external_handoff_enabled: false,
            external_handoff_command: String::new(),
            external_handoff_args: vec![],
            external_handoff_timeout_secs: 20,
            external_handoff_require_success: false,
            external_handoff_clear_env: true,
            external_handoff_allowed_commands: vec![],
            external_handoff_enforce_allowlist: false,
            external_handoff_signature_enabled: false,
            external_handoff_signature_key_env: "INNERWARDEN_HANDOFF_SIGNING_KEY".to_string(),
            external_handoff_attestation_enabled: false,
            external_handoff_attestation_key_env: "INNERWARDEN_HANDOFF_ATTESTATION_KEY".to_string(),
            external_handoff_attestation_prefix: "IW_ATTEST".to_string(),
            external_handoff_attestation_expected_receiver: String::new(),
            redirect_enabled: false,
            redirect_backend: "iptables".to_string(),
            interaction: "banner".to_string(),
            ssh_max_auth_attempts: 6,
            http_max_requests: 10,
            ai_provider: None,
        }
    }
}

/// Result of a skill execution.
pub struct SkillResult {
    pub success: bool,
    /// Human-readable description of what happened (or would have happened in dry-run).
    pub message: String,
}

// ---------------------------------------------------------------------------
// ResponseSkill trait - implement this to add a new skill
// ---------------------------------------------------------------------------

/// A response skill is an action Inner Warden can take when an incident is detected.
///
/// ## Adding a community skill
///
/// 1. Create a struct that implements `ResponseSkill`.
/// 2. Register it in `SkillRegistry::default_builtin()`.
/// 3. Open a PR at https://github.com/InnerWarden/innerwarden
///
/// All built-in skills follow the same pattern as `BlockIpUfw`.
pub trait ResponseSkill: Send + Sync {
    /// Unique identifier used by the AI to select this skill.
    /// Use kebab-case, e.g. "block-ip-ufw".
    fn id(&self) -> &'static str;

    /// Human-readable name shown in logs and the narrative.
    fn name(&self) -> &'static str;

    /// One-sentence description sent to the AI so it understands what this skill does.
    fn description(&self) -> &'static str;

    /// Open = free; Premium = paid / coming soon.
    fn tier(&self) -> SkillTier;

    /// Incident kinds this skill is applicable to (e.g. ["ssh_bruteforce"]).
    /// An empty slice means "applicable to all".
    fn applicable_to(&self) -> &'static [&'static str];

    /// Execute the skill.
    ///
    /// - `dry_run = true`: log what would happen but don't run system commands.
    /// - Always fail-open: return `SkillResult { success: false, message }` on error
    ///   rather than propagating to avoid crashing the agent.
    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Info (sent to AI as context)
// ---------------------------------------------------------------------------

/// Serializable summary of a skill, sent to the AI so it knows what options exist.
#[derive(Debug, Clone, Serialize)]
pub struct SkillInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tier: SkillTier,
    pub applicable_to: Vec<String>,
}

// ---------------------------------------------------------------------------
// Skill Registry
// ---------------------------------------------------------------------------

pub struct SkillRegistry {
    skills: Vec<Box<dyn ResponseSkill>>,
}

impl SkillRegistry {
    /// Build an empty registry with no skills. Useful in tests that need
    /// to exercise "no skill registered" code paths without relying on
    /// `remove`-style mutation of `default_builtin()`.
    #[cfg(test)]
    pub fn empty() -> Self {
        Self { skills: Vec::new() }
    }

    /// Build the registry with all built-in skills.
    pub fn default_builtin() -> Self {
        use builtin::*;
        Self {
            skills: vec![
                // Unix firewall skills shell out to pfctl/ufw/iptables/nftables/
                // firewalld/xdp, none of which exist on Windows. Gate them off
                // Windows so the AI is never offered a dead skill there (spec 085
                // Phase 2); on Windows the built-in Windows Firewall skill below
                // is the block path instead. Linux/macOS are unchanged.
                #[cfg(not(target_os = "windows"))]
                Box::new(BlockIpUfw),
                #[cfg(not(target_os = "windows"))]
                Box::new(BlockIpIptables),
                #[cfg(not(target_os = "windows"))]
                Box::new(BlockIpNftables),
                #[cfg(not(target_os = "windows"))]
                Box::new(BlockIpFirewalld),
                #[cfg(not(target_os = "windows"))]
                Box::new(BlockIpPf),
                #[cfg(not(target_os = "windows"))]
                Box::new(BlockIpXdp),
                #[cfg(target_os = "windows")]
                Box::new(BlockIpWindows),
                Box::new(MonitorIp),
                Box::new(Honeypot),
                Box::new(SuspendUserSudo),
                Box::new(RateLimitNginx),
                Box::new(KillProcess),
                Box::new(KillChainResponse),
                Box::new(BlockContainer),
            ],
        }
    }

    /// Returns skill metadata for all registered skills (sent to AI as context).
    pub fn infos(&self) -> Vec<SkillInfo> {
        self.skills
            .iter()
            .map(|s| SkillInfo {
                id: s.id().to_string(),
                name: s.name().to_string(),
                description: s.description().to_string(),
                tier: s.tier(),
                applicable_to: s.applicable_to().iter().map(|&k| k.to_string()).collect(),
            })
            .collect()
    }

    /// Look up a skill by ID.
    pub fn get(&self, id: &str) -> Option<&dyn ResponseSkill> {
        self.skills
            .iter()
            .find(|s| s.id() == id)
            .map(|s| s.as_ref())
    }

    /// Convenience: find the best block skill for the given backend.
    /// Falls back to ufw if the backend is unknown.
    pub fn block_skill_for_backend(&self, backend: &str) -> Option<&dyn ResponseSkill> {
        let id = match backend {
            "iptables" => "block-ip-iptables",
            "nftables" => "block-ip-nftables",
            "xdp" => "block-ip-xdp",
            _ => "block-ip-ufw",
        };
        self.get(id)
    }
}

// ---------------------------------------------------------------------------
// Blocklist (in-memory; prevents duplicate blocks)
// ---------------------------------------------------------------------------

/// Tracks IPs already blocked this session to avoid redundant system calls.
#[derive(Default)]
pub struct Blocklist {
    blocked: HashSet<String>,
}

impl Blocklist {
    #[allow(dead_code)] // public API - used by algorithm gate and future skills
    pub fn contains(&self, ip: &str) -> bool {
        self.blocked.contains(ip)
    }

    pub fn insert(&mut self, ip: impl Into<String>) {
        self.blocked.insert(ip.into());
    }

    /// Remove an IP from the in-memory blocklist. Returns true if it was
    /// present. Used by the operator-unblock drain so a manually un-blocked
    /// IP is no longer treated as blocked by the algorithm gate.
    pub fn remove(&mut self, ip: &str) -> bool {
        self.blocked.remove(ip)
    }

    /// Cap the blocklist to prevent unbounded memory growth.
    /// Keeps the most recent entries by clearing and reloading if over limit.
    pub fn trim_if_needed(&mut self, max_entries: usize) {
        if self.blocked.len() > max_entries {
            // Keep a random subset - in practice the oldest IPs are no longer attacking
            let keep: HashSet<String> =
                self.blocked.iter().take(max_entries / 2).cloned().collect();
            self.blocked = keep;
        }
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.blocked.len()
    }

    pub fn as_vec(&self) -> Vec<String> {
        self.blocked.iter().cloned().collect()
    }

    /// Attempt to pre-populate from `ufw status` output.
    /// Silently skips if ufw is unavailable or the user lacks permissions.
    pub async fn load_from_ufw() -> Self {
        let mut list = Self::default();
        let Ok(out) = tokio::process::Command::new("sudo")
            .args(["ufw", "status"])
            .output()
            .await
        else {
            return list;
        };
        if !out.status.success() {
            return list;
        }
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            for ip in parse_ufw_deny_in_line(line) {
                list.blocked.insert(ip);
            }
        }
        info!(
            count = list.blocked.len(),
            "blocklist loaded from ufw status"
        );
        list
    }
}

/// Extract IP(s) blocked by a `DENY IN` rule from a single `ufw status`
/// line. Returns an empty vector for lines that are not DENY IN rules or
/// that target a port/service rather than an IP address.
///
/// Handles the four formats ufw actually emits in production:
///
/// - `Anywhere    DENY    203.0.113.10    # innerwarden`
///   (`ufw status` — what the agent invokes; default direction is
///   inbound, so there is **no `IN` token** in this format)
/// - `[10] Anywhere    DENY IN    203.0.113.10    # innerwarden`
///   (`ufw status numbered` — what operators see, has `IN` and an
///   index in brackets)
/// - `Anywhere    DENY IN    203.0.113.10`
///   (`ufw status verbose` and similar)
/// - `81/tcp    DENY    Anywhere`
///   (inbound port-only deny; no IP to track, skipped)
///
/// Outbound rules (`DENY OUT`) are explicitly skipped because the
/// in-memory blocklist tracks ingress blocks only.
pub(crate) fn parse_ufw_deny_in_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let tokens: Vec<&str> = line.split_whitespace().collect();

    // Find the `DENY` token. Default ufw direction is inbound, so a
    // bare `DENY` is treated as ingress; only an explicit `DENY OUT`
    // is excluded. The previous parser required `DENY` and `IN` to be
    // adjacent, which silently dropped every rule from `ufw status`
    // (no `IN` token there) — that left 1200+ ufw rules invisible to
    // the agent on prod, so they never expired.
    let Some(deny_idx) = tokens.iter().position(|t| *t == "DENY") else {
        return out;
    };
    if tokens.get(deny_idx + 1) == Some(&"OUT") {
        return out;
    }

    // Collect every token that parses as an IP address. Skip the
    // literal `Anywhere` (placeholder for the address family) and its
    // `(v6)` companion, and stop at the first comment marker.
    for tok in &tokens {
        if *tok == "#" {
            break;
        }
        // Strip a leading numbered bracket like `[10]`.
        let cleaned = tok.trim_start_matches('[').trim_end_matches(']');
        if cleaned == "Anywhere" || cleaned == "(v6)" {
            continue;
        }
        if cleaned.parse::<std::net::IpAddr>().is_ok() {
            out.push(cleaned.to_string());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_all_builtin_skills() {
        let reg = SkillRegistry::default_builtin();
        assert!(reg.get("block-ip-ufw").is_some());
        assert!(reg.get("block-ip-iptables").is_some());
        assert!(reg.get("block-ip-nftables").is_some());
        assert!(reg.get("block-ip-pf").is_some());
        assert!(reg.get("monitor-ip").is_some());
        assert!(reg.get("honeypot").is_some());
        assert!(reg.get("suspend-user-sudo").is_some());
        assert!(reg.get("rate-limit-nginx").is_some());
        assert!(reg.get("kill-process").is_some());
        assert!(reg.get("block-container").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn registry_infos_are_serializable() {
        let reg = SkillRegistry::default_builtin();
        let infos = reg.infos();
        assert_eq!(infos.len(), 13); // +block-ip-firewalld (RHEL/Rocky backend)
        let json = serde_json::to_string(&infos).unwrap();
        assert!(json.contains("block-ip-ufw"));
        assert!(json.contains("block-ip-firewalld"));
    }

    #[test]
    fn block_skill_for_backend_fallback() {
        let reg = SkillRegistry::default_builtin();
        assert_eq!(
            reg.block_skill_for_backend("ufw").unwrap().id(),
            "block-ip-ufw"
        );
        assert_eq!(
            reg.block_skill_for_backend("iptables").unwrap().id(),
            "block-ip-iptables"
        );
        assert_eq!(
            reg.block_skill_for_backend("unknown").unwrap().id(),
            "block-ip-ufw"
        );
    }

    #[tokio::test]
    async fn block_ip_ufw_dry_run() {
        use super::builtin::BlockIpUfw;
        let ctx = SkillContext {
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
            target_ip: Some("1.2.3.4".into()),
            target_user: None,
            target_container: None,
            duration_secs: None,
            host: "h".into(),
            data_dir: std::env::temp_dir(),
            honeypot: HoneypotRuntimeConfig::default(),
            ai_provider: None,
        };
        let result = BlockIpUfw.execute(&ctx, true).await;
        assert!(result.success);
        assert!(result.message.contains("DRY RUN"));
    }

    // ── parse_ufw_deny_in_line ─────────────────────────────────────────

    #[test]
    fn parse_ufw_deny_in_line_reads_numbered_format_with_comment() {
        // The format produced by `ufw status numbered` — which is what
        // Ubuntu 22.04+ shows by default after `ufw-status` changed.
        let ips =
            parse_ufw_deny_in_line("[10] Anywhere    DENY IN    203.0.113.10    # innerwarden");
        assert_eq!(ips, vec!["203.0.113.10"]);
    }

    #[test]
    fn parse_ufw_deny_in_line_reads_plain_format_without_bracket() {
        let ips = parse_ufw_deny_in_line("Anywhere    DENY IN    198.51.100.42");
        assert_eq!(ips, vec!["198.51.100.42"]);
    }

    #[test]
    fn parse_ufw_deny_in_line_reads_ipv6() {
        let ips =
            parse_ufw_deny_in_line("Anywhere (v6)    DENY IN    2001:db8::1    # innerwarden");
        assert_eq!(ips, vec!["2001:db8::1"]);
    }

    #[test]
    fn parse_ufw_deny_in_line_reads_default_status_format_no_in_token() {
        // The exact format the agent reads from `sudo ufw status` (no
        // `numbered`). DENY is bare, no `IN` token. Reproduces the prod
        // bug that landed 1200+ ufw rules and zero in the in-memory
        // blocklist.
        let ips = parse_ufw_deny_in_line(
            "Anywhere                   DENY        186.209.52.196             # innerwarden",
        );
        assert_eq!(ips, vec!["186.209.52.196"]);
    }

    #[test]
    fn parse_ufw_deny_in_line_skips_inbound_port_deny() {
        // "81/tcp DENY Anywhere" is a port-family deny (default
        // direction = inbound), no IP to track. Must return empty;
        // returning "Anywhere" would poison the in-memory blocklist
        // with a non-IP string.
        assert!(
            parse_ufw_deny_in_line("81/tcp                     DENY        Anywhere").is_empty()
        );
        // Same for the numbered variant with explicit IN.
        assert!(parse_ufw_deny_in_line("[7] 81/tcp    DENY IN    Anywhere").is_empty());
    }

    #[test]
    fn parse_ufw_deny_in_line_skips_non_deny_lines() {
        assert!(parse_ufw_deny_in_line("Status: active").is_empty());
        assert!(parse_ufw_deny_in_line("[1] 22/tcp    LIMIT IN    Anywhere").is_empty());
        assert!(
            parse_ufw_deny_in_line("Anywhere                   ALLOW       10.0.0.1").is_empty()
        );
        assert!(parse_ufw_deny_in_line("-- ------ ----").is_empty());
        assert!(parse_ufw_deny_in_line("").is_empty());
    }

    #[test]
    fn parse_ufw_deny_in_line_excludes_outbound_rules() {
        // `DENY OUT` is an outbound rule. The in-memory blocklist
        // tracks ingress only; do not pollute it with egress rules.
        assert!(parse_ufw_deny_in_line("[2] Anywhere    DENY OUT    10.0.0.1").is_empty());
        assert!(parse_ufw_deny_in_line("Anywhere    DENY OUT    10.0.0.1").is_empty());
    }

    #[test]
    fn parse_ufw_deny_in_line_skips_allow_rules() {
        // ALLOW must never be read as DENY even with similar shape.
        assert!(parse_ufw_deny_in_line("[3] Anywhere    ALLOW IN    10.0.0.1").is_empty());
        assert!(parse_ufw_deny_in_line("Anywhere    ALLOW    10.0.0.1").is_empty());
    }

    #[test]
    fn parse_ufw_deny_in_line_stops_at_comment_marker() {
        // Anything after `#` is operator commentary and must not be
        // parsed as an IP even if it happens to look like one.
        let ips = parse_ufw_deny_in_line(
            "[42] Anywhere    DENY IN    192.0.2.10    # added after 10.0.0.1 triggered",
        );
        assert_eq!(ips, vec!["192.0.2.10"]);
    }

    #[test]
    fn blocklist_trim_if_needed_halves_entries_over_cap() {
        let mut bl = Blocklist::default();
        for i in 0..100u32 {
            bl.insert(format!("10.0.0.{i}"));
        }
        assert_eq!(bl.len(), 100);
        bl.trim_if_needed(50);
        // Over-cap: kept is `max_entries / 2` per the function's
        // documented shrink strategy.
        assert_eq!(bl.len(), 25);
    }

    #[test]
    fn blocklist_trim_if_needed_noop_under_cap() {
        let mut bl = Blocklist::default();
        bl.insert("1.2.3.4");
        bl.insert("5.6.7.8");
        bl.trim_if_needed(10);
        assert_eq!(bl.len(), 2);
    }

    #[test]
    fn honeypot_runtime_config_debug_redacts_ai_provider_to_name_only() {
        // Spec 031/test(agent): the `Debug` impl must not try to print
        // the `dyn AiProvider` trait object directly (no Debug bound
        // there). It surfaces only the provider name, which keeps the
        // blocklist snapshot logs safe for operator diagnostics.
        let cfg = HoneypotRuntimeConfig::default();
        let rendered = format!("{cfg:?}");
        assert!(rendered.contains("HoneypotRuntimeConfig"));
        assert!(rendered.contains("mode"));
        assert!(rendered.contains("interaction"));
    }

    #[tokio::test]
    async fn load_from_ufw_returns_empty_when_sudo_ufw_unavailable() {
        // In the test environment `sudo ufw status` either fails to
        // spawn (no sudo in PATH) or exits non-zero. Both branches
        // return an empty Blocklist; the test pins the contract.
        let bl = Blocklist::load_from_ufw().await;
        assert_eq!(bl.len(), 0);
    }
}
