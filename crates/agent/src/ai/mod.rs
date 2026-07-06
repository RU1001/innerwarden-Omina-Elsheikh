mod anthropic;
mod azure_openai;
pub mod capability;
#[cfg(feature = "local-classifier")]
mod local_classifier;
mod ollama;
mod openai;
pub mod router;
mod shadow;
mod stub;

// Spec 029 PR-A: these re-exports become consumed in PR-B when
// `AgentState` gains an `ai_router` field. During PR-A they are
// unused externally, so allow(unused_imports) keeps clippy happy on
// the infrastructure PR without weakening the lint elsewhere.
#[allow(unused_imports)]
pub use capability::{AiCapabilities, Capability};
#[allow(unused_imports)]
pub use router::{AiRouter, RouterBuildError};

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::Result;
use async_trait::async_trait;
use innerwarden_core::{entities::EntityType, event::Event, incident::Incident};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::AiConfig;

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

/// The action the AI recommends (and may auto-execute).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AiAction {
    /// Block the attacking IP immediately via the configured firewall backend.
    /// `skill_id` is the skill the AI selected (e.g. "block-ip-ufw").
    BlockIp { ip: String, skill_id: String },

    /// Shadow-monitor the IP - log all its activity without blocking.
    /// Premium feature stub; community can implement full tracking.
    Monitor { ip: String },

    /// Trigger honeypot response.
    /// Behavior depends on runtime mode:
    /// - `demo`: synthetic marker
    /// - `listener`: bounded multi-service decoy listeners with optional redirect
    Honeypot { ip: String },

    /// Temporarily suspend sudo privileges for a user.
    /// Implemented by the `suspend-user-sudo` skill using a sudoers drop-in.
    SuspendUserSudo { user: String, duration_secs: u64 },

    /// Kill all processes owned by a user (pkill -9 -u <user>).
    /// Used for suspicious execution incidents.
    KillProcess { user: String, duration_secs: u64 },

    /// Pause or stop a Docker container in response to an anomaly.
    /// `action` is "pause" (default, reversible) or "stop".
    BlockContainer {
        container_id: String,
        action: String,
    },

    /// Send a confirmation request to the operator webhook before acting.
    RequestConfirmation { summary: String },

    /// Execute the kill-chain-response skill: kill process, block C2, capture forensics.
    /// Triggered when the eBPF LSM blocks a kill chain pattern.
    KillChainResponse { reason: String },

    /// No action required - false positive or already handled.
    Ignore { reason: String },

    /// Low-priority incident filed without any action. Semantically distinct
    /// from Ignore: Dismiss is "below the noise floor, not worth reviewing",
    /// Ignore is "considered and rejected". The local classifier (spec 027)
    /// was trained with these as separate labels and collapsing them loses
    /// information in shadow/audit logs and downstream metrics.
    Dismiss { reason: String },
}

/// The structured decision returned by an AI provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiDecision {
    pub action: AiAction,

    /// Confidence score 0.0–1.0. Below the configured threshold, the decision
    /// is logged but NOT auto-executed even if `auto_execute` is true.
    pub confidence: f32,

    /// Whether the AI considers this safe to execute automatically.
    pub auto_execute: bool,

    /// Human-readable explanation of the reasoning.
    pub reason: String,

    /// Alternative actions the AI considered.
    pub alternatives: Vec<String>,

    /// Estimated threat level: "low" | "medium" | "high" | "critical"
    pub estimated_threat: String,
}

impl AiAction {
    /// Short name used as the action key in trust rules (e.g. "block_ip").
    pub fn name(&self) -> &'static str {
        match self {
            AiAction::BlockIp { .. } => "block_ip",
            AiAction::Monitor { .. } => "monitor",
            AiAction::Honeypot { .. } => "honeypot",
            AiAction::SuspendUserSudo { .. } => "suspend_user_sudo",
            AiAction::KillProcess { .. } => "kill_process",
            AiAction::BlockContainer { .. } => "block_container",
            AiAction::RequestConfirmation { .. } => "request_confirmation",
            AiAction::KillChainResponse { .. } => "kill_chain_response",
            AiAction::Ignore { .. } => "ignore",
            AiAction::Dismiss { .. } => "dismiss",
        }
    }

    /// Spec 062 Phase 5: is this a high-impact enforcement action whose
    /// blast radius warrants a human veto when the deciding model is not
    /// confident? These cut real access — block traffic, suspend a user's
    /// sudo, kill a user's processes, pause a container, or run the
    /// kill-chain response (kill + block C2 + forensics). A wrong
    /// autonomous call here is operator-visible and disruptive.
    ///
    /// Soft actions (`Monitor` / `Dismiss` / `Ignore` /
    /// `RequestConfirmation`) and the low-blast `Honeypot` deception are
    /// NOT high-impact — they pass through without the confidence gate.
    /// Mirrors the "com peso, confirma" weight split that learned
    /// suppression uses ([`crate::learned_suppression::ACTIONED_TYPES`]).
    pub fn is_high_impact(&self) -> bool {
        matches!(
            self,
            AiAction::BlockIp { .. }
                | AiAction::SuspendUserSudo { .. }
                | AiAction::KillProcess { .. }
                | AiAction::BlockContainer { .. }
                | AiAction::KillChainResponse { .. }
        )
    }
}

impl AiDecision {
    /// Convenience constructor for a no-op decision.
    #[allow(dead_code)]
    pub fn ignore(reason: impl Into<String>) -> Self {
        Self {
            action: AiAction::Ignore {
                reason: reason.into(),
            },
            confidence: 1.0,
            auto_execute: false,
            reason: String::new(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Context passed to the AI provider
// ---------------------------------------------------------------------------

pub struct DecisionContext<'a> {
    pub incident: &'a Incident,
    /// Recent events from the same entity (IP/user) for contextual analysis
    pub recent_events: Vec<&'a Event>,
    /// Temporally correlated incidents sharing pivot(s) (ip/user/detector kind)
    pub related_incidents: Vec<&'a Incident>,
    /// IPs already in the blocklist (to avoid duplicate blocks)
    pub already_blocked: Vec<String>,
    /// Available skill IDs (sent to the AI so it can select the right one)
    pub available_skills: Vec<SkillInfo>,
    /// Optional AbuseIPDB reputation data for the primary IP (enrichment).
    pub ip_reputation: Option<crate::abuseipdb::IpReputation>,
    /// Optional geolocation data for the primary IP (enrichment via ip-api.com).
    pub ip_geo: Option<crate::geoip::GeoInfo>,
    /// Optional DShield (SANS ISC) context line for the primary IP, pre-rendered
    /// via `DshieldReputation::as_context_line()` (spec 067 Phase 2). Read from
    /// the attacker profile's cached DShield data (NO network call on the
    /// decide path). Carries the IP's global attacked-target count and
    /// threat-feed membership (the "what this IP is used for" signal AbuseIPDB
    /// lacks).
    /// `None` when DShield is disabled or the profile is not yet backfilled.
    pub ip_dshield: Option<String>,
    /// Structured DShield signal for the deterministic Context Gate: `true` when
    /// ISC has confirmed the primary IP attacking the community (reports > 0 or
    /// active threat-feed membership, via `DshieldReputation::is_known_attacker`).
    /// The trained classifier's text input is intentionally NOT changed (novel
    /// input is out-of-distribution; enriching it is the re-distill path). The
    /// gate around the classifier uses this to PREVENT a benign dismiss and to
    /// ESCALATE a low-confidence passive close. Only ever escalates, never
    /// relaxes. `false` when DShield is off, unknown, or the IP is clean.
    // Read only by the `warden_context_gate`, which is behind the
    // `local-classifier` feature; without that feature there is no reader, so the
    // default build would warn. It is always written (the decide path sets it) and
    // is genuinely used in the prod build (local-classifier is on there).
    #[allow(dead_code)]
    pub ip_dshield_attacker: bool,
    /// Optional compact host-posture line (spec 067 Phase 2b), from
    /// `posture::ai_context_line()`. Lets the LLM reason with the same
    /// defensive facts the downgrade engine uses (e.g. an ssh_bruteforce on a
    /// `PasswordAuthentication=no` host is already neutralized), so the AI does
    /// not over-react to attacks the host config already refuses. `None` when
    /// the posture probe has not succeeded.
    pub host_posture: Option<String>,
    /// Optional summary of prior operator/agent decisions for this exact
    /// `(detector | ip)` shape (spec 067 Phase 2c), from
    /// `learned_suppression::prior_decisions_context()`. The single biggest
    /// "stop re-surfacing settled noise" lever: the LLM learns that this shape
    /// was dismissed N times (likely noise) or actioned before (recurring
    /// threat). `None` when there is no prior history for the shape.
    pub prior_decisions: Option<String>,
    /// Knowledge graph context: attack narrative + impact analysis.
    /// Generated by `knowledge_graph::narrative::attack_narrative()`.
    ///
    /// Kept as a fallback — when `graph_subgraph` is populated, provider
    /// `build_prompt` implementations prefer the structured JSON. The
    /// prose form is still generated because the decision audit trail and
    /// the dashboard narrative consume it.
    pub graph_context: Option<String>,
    /// Spec 025: same neighbourhood as `graph_context`, rendered as a
    /// compact `{nodes, edges}` JSON payload. Measured on qwen2.5:3b:
    /// 53% → 73% action accuracy when the LLM consumes the subgraph
    /// directly instead of re-deriving structure from prose.
    pub graph_subgraph: Option<serde_json::Value>,
    /// Spec 056 Phase 4: one-line summary of any deterministic SOC
    /// playbook that already executed for this incident (from
    /// [`crate::playbook_engine::executor::PlaybookOutcome::summary`]).
    /// Surfaced in the LLM prompt so the AI ENRICHES rather than
    /// duplicates the playbook's actions (spec 056 invariant #5: AI sees
    /// playbook output, never the inverse). `None` when no playbook fired,
    /// in which case the prompt is identical to the pre-Phase-4 behaviour.
    pub playbook_outcome: Option<String>,
}

/// Render the playbook-outcome prompt block for the LLM providers. Empty
/// when no playbook ran, so the prompt is byte-identical to pre-Phase-4.
/// Shared by every `build_prompt` so the wording (and the "do not
/// duplicate" instruction) stays consistent across providers.
pub(crate) fn playbook_prompt_section(outcome: &Option<String>) -> String {
    match outcome {
        Some(summary) if !summary.is_empty() => format!(
            "\nDETERMINISTIC PLAYBOOK ALREADY EXECUTED (do NOT repeat these \
             actions; add enrichment or longer-term response only):\n{summary}\n"
        ),
        _ => String::new(),
    }
}

/// Render the DShield (SANS ISC) enrichment block for the LLM providers (spec
/// 067 Phase 2). Empty when no DShield data, so the prompt is byte-identical
/// for IPs without it. The line carries the IP's global attacked-target count,
/// first/last-seen, and threat-feed membership (the "what this IP is used for"
/// signal AbuseIPDB does not provide). Shared by every `build_prompt` so the
/// wording stays consistent across providers.
pub(crate) fn dshield_prompt_section(line: &Option<String>) -> String {
    match line {
        Some(l) if !l.is_empty() => {
            format!("\nDSHIELD (SANS ISC global attack telemetry):\n{l}\n")
        }
        _ => String::new(),
    }
}

/// Render the host-posture block for the LLM providers (spec 067 Phase 2b).
/// Empty when no posture is available. Tells the AI which defensive config the
/// host already enforces, so it does not over-react to an attack the host
/// refuses anyway (the same signal the severity-downgrade engine uses).
pub(crate) fn posture_prompt_section(line: &Option<String>) -> String {
    match line {
        Some(l) if !l.is_empty() => format!(
            "\nHOST POSTURE (defensive config that may already neutralize this; \
             do not over-react to what the host already refuses):\n{l}\n"
        ),
        _ => String::new(),
    }
}

/// Render the prior-decisions block for the LLM providers (spec 067 Phase 2c).
/// Empty when the shape has no prior history. Tells the AI how this exact
/// `(detector | ip)` shape was decided before so it stops re-surfacing settled
/// noise and respects a previously-actioned recurring threat.
pub(crate) fn prior_decisions_prompt_section(line: &Option<String>) -> String {
    match line {
        Some(l) if !l.is_empty() => format!(
            "\nPRIOR DECISIONS FOR THIS PATTERN (weigh against re-surfacing \
             settled noise):\n{l}\n"
        ),
        _ => String::new(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SkillInfo {
    pub id: String,
    /// Incident kinds this skill applies to (empty = all).
    /// Serialized to AI so it can match skills to incident types.
    pub applicable_to: Vec<String>,
}

// ---------------------------------------------------------------------------
// AiProvider trait - implement this to add a new provider
// ---------------------------------------------------------------------------

/// Implement this trait to add a new AI provider to Inner Warden.
///
/// Open-source contributions welcome: https://github.com/InnerWarden/innerwarden
#[async_trait]
pub trait AiProvider: Send + Sync {
    /// Short identifier shown in logs, e.g. "openai", "anthropic".
    fn name(&self) -> &'static str;

    /// Which capability roles this provider can serve. The `AiRouter`
    /// reads this to decide where to dispatch each call site.
    ///
    /// Default is `ALL` for backwards compatibility with general-
    /// purpose LLM providers that already implement both `decide()`
    /// and `chat()`. Narrow providers (the distilled local
    /// classifier, deterministic stubs) override with their real
    /// capability set so the router does not send them work they
    /// cannot do.
    fn capabilities(&self) -> capability::AiCapabilities {
        capability::AiCapabilities::ALL
    }

    /// Analyse an incident and return a decision.
    async fn decide(&self, ctx: &DecisionContext<'_>) -> Result<AiDecision>;

    /// Send a free-form chat message with a system prompt and get a plain-text response.
    /// Used by the Telegram conversational bot.
    async fn chat(&self, system_prompt: &str, user_message: &str) -> Result<String>;
}

// ---------------------------------------------------------------------------
// Algorithm gate - runs BEFORE calling the AI (no I/O, no cost)
// ---------------------------------------------------------------------------

/// Returns true if the incident is worth sending to the AI provider.
///
/// Avoids wasting API calls on noise or already-handled incidents.
pub fn should_invoke_ai(
    incident: &Incident,
    already_blocked: &HashSet<String>,
    min_severity: &innerwarden_core::event::Severity,
) -> bool {
    use innerwarden_core::event::Severity;

    // Check against configured minimum severity
    let dominated_by_min = match min_severity {
        Severity::Low => matches!(incident.severity, Severity::Debug | Severity::Info),
        Severity::Medium => matches!(
            incident.severity,
            Severity::Debug | Severity::Info | Severity::Low
        ),
        Severity::High => !matches!(incident.severity, Severity::High | Severity::Critical),
        Severity::Critical => !matches!(incident.severity, Severity::Critical),
        _ => true,
    };
    if dominated_by_min {
        return false;
    }

    // Extract the primary IP entity from the incident
    let ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == EntityType::Ip)
        .map(|e| e.value.as_str());

    if let Some(ip_str) = ip {
        // Skip if already blocked
        if already_blocked.contains(ip_str) {
            return false;
        }

        // Skip RFC1918 / loopback / link-local - these are internal and
        // should not be auto-blocked without deeper investigation
        if let Ok(addr) = ip_str.parse::<IpAddr>() {
            if is_private_or_loopback(addr) {
                info!(ip = ip_str, "skipping AI analysis for private/loopback IP");
                return false;
            }
        }
    }

    true
}

/// Check if incident severity is strictly below the configured min_severity threshold.
/// Extracted so `incident_flow` can distinguish "below severity" from other skip reasons.
pub fn is_below_severity_threshold(
    severity: &innerwarden_core::event::Severity,
    min_severity: &innerwarden_core::event::Severity,
) -> bool {
    use innerwarden_core::event::Severity;
    match min_severity {
        Severity::Low => matches!(severity, Severity::Debug | Severity::Info),
        Severity::Medium => matches!(severity, Severity::Debug | Severity::Info | Severity::Low),
        Severity::High => !matches!(severity, Severity::High | Severity::Critical),
        Severity::Critical => !matches!(severity, Severity::Critical),
        _ => true,
    }
}

/// Check if an IP is private (RFC1918, link-local, etc.).
/// Exported for use by enrichment backfill to skip non-routable IPs.
pub fn is_private_ip(addr: IpAddr) -> bool {
    is_private_or_loopback(addr)
}

fn is_private_or_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

// ---------------------------------------------------------------------------
// Factory - creates the right provider based on config
// ---------------------------------------------------------------------------

/// Known OpenAI-compatible providers and their default base URLs + models.
/// Any provider that speaks the `/v1/chat/completions` format works here.
const OPENAI_COMPATIBLE: &[(&str, &str, &str)] = &[
    // (provider name, default base_url, default model)
    ("openai", "https://api.openai.com", "gpt-4o-mini"),
    (
        "groq",
        "https://api.groq.com/openai",
        "llama-3.3-70b-versatile",
    ),
    ("deepseek", "https://api.deepseek.com", "deepseek-chat"),
    (
        "together",
        "https://api.together.xyz",
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    ),
    ("minimax", "https://api.minimaxi.chat", "MiniMax-Text-01"),
    ("mistral", "https://api.mistral.ai", "mistral-small-latest"),
    ("xai", "https://api.x.ai", "grok-3-mini-fast"),
    (
        "gemini",
        "https://generativelanguage.googleapis.com/v1beta/openai",
        "gemini-2.0-flash",
    ),
    (
        "fireworks",
        "https://api.fireworks.ai/inference",
        "accounts/fireworks/models/llama-v3p3-70b-instruct",
    ),
    (
        "openrouter",
        "https://openrouter.ai/api",
        "meta-llama/llama-3.3-70b-instruct",
    ),
];

/// Reject plain HTTP for remote AI provider endpoints.
/// Only `localhost` / `127.0.0.1` / `[::1]` are allowed over HTTP.
///
/// # Wave 4 (AUDIT-WAVE4-AI-IPV6, 2026-05-04 ultrareview)
///
/// Pre-fix the host extraction did `.split(':').next()` then
/// `.split('/').next()` on the post-`http://` slice. That mangled
/// IPv6 bracket forms: `http://[::1]:8080/path` produced host `[`
/// (the split-on-`:` cut after the opening bracket), which then
/// failed every loopback comparison. Operators running a local
/// IPv6 LLM endpoint (`[::1]:8080`, `[::1]:11434/api/...`) hit
/// "HTTP is not allowed" even though `::1` is a documented loopback.
/// The new extractor uses [`extract_url_host`] which understands
/// the bracket form.
fn validate_ai_base_url(url: &str) -> Result<()> {
    if url.is_empty() {
        return Ok(());
    }
    if url.starts_with("http://") {
        let host_part = url.strip_prefix("http://").unwrap_or("");
        let host = extract_url_host(host_part);
        if host != "localhost" && host != "127.0.0.1" && host != "::1" {
            anyhow::bail!(
                "HTTP is not allowed for remote AI providers (use HTTPS). Got: {}",
                url
            );
        }
    }
    Ok(())
}

/// Wave 4 (AUDIT-WAVE4-AI-IPV6) helper: extract the bare host from a
/// URL fragment that comes AFTER the scheme (e.g. `[::1]:8080/path` or
/// `127.0.0.1:8080/path` or `localhost`). Handles four shapes:
///
/// * IPv6 bracket form `[host]:port/path` → return `host` (bracket
///   contents).
/// * Authority with userinfo `user[:pass]@host[:port]/path` → strip
///   userinfo first, then re-extract from the remainder. Skipping
///   this step let `http://localhost:pw@evil.example` masquerade as
///   loopback because the split-on-`:` returned `"localhost"` even
///   though the real host is `evil.example`. Caught by Copilot
///   review on PR #462 (2026-05-05) — the same userinfo-bypass
///   class that hits naive URL parsers in many ecosystems.
/// * IPv4 / hostname `host:port/path` → return `host` (everything
///   before the first `:` or `/`).
/// * Bare host with no port / path → return as-is.
///
/// Path component (after the first `/`) is also stripped first so
/// that `host/userinfo@evil` never reaches the userinfo branch.
///
/// Pure: no allocations, no I/O. Pinned by `extract_url_host_*`
/// anchor tests.
fn extract_url_host(host_part: &str) -> &str {
    // Strip the path first so `/` cannot smuggle a fake `@` past
    // the userinfo check. Per RFC 3986 the authority ends at `/`,
    // `?`, or `#`; checking `/` is enough for our HTTP-loopback gate.
    let authority = host_part.split('/').next().unwrap_or("");

    // Strip userinfo per RFC 3986 §3.2.1: `user[:pass]@host[:port]`.
    // The LAST `@` separates userinfo from host because userinfo
    // can itself contain `@` per the percent-encoded grammar
    // (rare but legal). Use rfind to pin the boundary.
    let after_userinfo = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };

    if let Some(rest) = after_userinfo.strip_prefix('[') {
        // IPv6 bracket form: read until `]`.
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
        // Malformed (no closing bracket) - fall through to the
        // generic split; the comparison will fail anyway.
    }
    after_userinfo.split(':').next().unwrap_or("")
}

pub fn build_provider(cfg: &AiConfig, block_backend: &str) -> Result<Box<dyn AiProvider>> {
    build_single(
        &cfg.provider,
        cfg.resolved_api_key(),
        &cfg.model,
        &cfg.base_url,
        &cfg.api_version,
        cfg.confidence_threshold,
        block_backend,
    )
}

/// Build the shadow observer as a standalone provider. Returns `None`
/// when `[ai.shadow]` is disabled. Errors when enabled but the
/// resulting provider would duplicate the Decide-serving one (same
/// provider+base_url+model), which would silently degrade shadow
/// into a useless self-comparison.
///
/// Called by the router after the Decide slot is resolved, so the
/// "differs from" check compares against whatever provider actually
/// serves Decide (classifier slot when configured, primary [ai]
/// otherwise) rather than hardcoding [ai] primary.
pub fn build_shadow_observer(
    shadow_cfg: &crate::config::ShadowConfig,
    decide_provider_provider: &str,
    decide_provider_base_url: &str,
    decide_provider_model: &str,
    confidence_threshold: f32,
    block_backend: &str,
) -> Result<Option<Box<dyn AiProvider>>> {
    if !shadow_cfg.enabled {
        return Ok(None);
    }
    if shadow_cfg.provider.is_empty() {
        anyhow::bail!("[ai.shadow].enabled is true but provider is empty");
    }
    if shadow_cfg.provider == decide_provider_provider
        && shadow_cfg.base_url == decide_provider_base_url
        && shadow_cfg.model == decide_provider_model
    {
        anyhow::bail!(
            "[ai.shadow] must differ from the Decide-serving provider (same provider+base_url+model configured)"
        );
    }
    let shadow = build_single(
        &shadow_cfg.provider,
        shadow_cfg.resolved_api_key(),
        &shadow_cfg.model,
        &shadow_cfg.base_url,
        &shadow_cfg.api_version,
        confidence_threshold,
        block_backend,
    )?;
    Ok(Some(shadow))
}

/// Wrap a primary provider with a shadow observer for parallel
/// Decide auditing. Returns the primary unchanged when shadow is
/// `None`. Keeps the shadow path a one-liner at call sites so the
/// router stays easy to read.
///
/// `sample_rate` in `[0.0, 1.0]` controls the fraction of `decide()`
/// calls that exercise the shadow path. `1.0` (legacy default) means
/// every call. `0.1` runs the shadow on ~10% of calls — preserves a
/// drift-detection sample after the initial validation window is
/// satisfied. See `ShadowConfig::sample_rate`.
pub fn wrap_with_shadow(
    primary: Box<dyn AiProvider>,
    shadow: Option<Box<dyn AiProvider>>,
    log_path: &str,
    sample_rate: f32,
) -> Box<dyn AiProvider> {
    match shadow {
        Some(shadow) => {
            tracing::info!(
                primary = %primary.name(),
                shadow = %shadow.name(),
                log_path = %log_path,
                sample_rate,
                "shadow mode enabled"
            );
            Box::new(shadow::ShadowProvider::with_sample_rate(
                primary,
                shadow,
                log_path,
                sample_rate,
            ))
        }
        None => primary,
    }
}

/// Build a single provider from flat parameters. Extracted so the same logic
/// can be reused by the shadow-mode path.
fn build_single(
    provider: &str,
    api_key: String,
    model: &str,
    base_url: &str,
    api_version: &str,
    #[allow(unused_variables)] confidence_threshold: f32,
    #[allow(unused_variables)] block_backend: &str,
) -> Result<Box<dyn AiProvider>> {
    // Suppress unused warning when local-classifier feature is off
    let _ = confidence_threshold;
    let _ = block_backend;
    // Spec 024 — deterministic stub used by the scenario-qa harness. Returns
    // fixed decisions per detector kind so scenario envelopes stay stable
    // across runs. Opt-in only (provider = "stub"); has no effect on
    // production configs.
    if provider == "stub" {
        return Ok(Box::new(stub::StubAiProvider::new()));
    }

    // Check if provider is OpenAI-compatible (including "openai" itself)
    if let Some(&(_, default_url, default_model)) = OPENAI_COMPATIBLE
        .iter()
        .find(|&&(name, _, _)| name == provider)
    {
        let base_url = if base_url.is_empty() {
            default_url.to_string()
        } else {
            validate_ai_base_url(base_url)?;
            base_url.to_string()
        };
        let model = if model.is_empty() {
            default_model.to_string()
        } else {
            model.to_string()
        };
        return Ok(Box::new(openai::OpenAiProvider::with_base_url(
            api_key, model, base_url,
        )?));
    }

    match provider {
        // 2026-05-03: canonical provider id is `local_warden` (Local
        // Warden Model). `local_classifier` is accepted as a legacy
        // alias so existing prod TOMLs upgrade cleanly. Internal
        // symbols (struct, file, cargo feature) keep the original
        // name — operator-facing strings only.
        #[cfg(feature = "local-classifier")]
        "local_warden" | "local_classifier" => {
            if base_url.is_empty() {
                anyhow::bail!(
                    "local_warden requires base_url = <dir with model.onnx + tokenizer.json>"
                );
            }
            let dir = std::path::Path::new(base_url);
            let threshold = if confidence_threshold > 0.0 {
                confidence_threshold
            } else {
                0.85
            };
            Ok(Box::new(local_classifier::LocalClassifier::from_dir(
                dir,
                threshold,
                block_backend,
            )?))
        }
        #[cfg(not(feature = "local-classifier"))]
        "local_warden" | "local_classifier" => {
            anyhow::bail!(
                "local_warden provider requires building innerwarden-agent with --features local-classifier"
            )
        }
        "azure_openai" => {
            if base_url.is_empty() {
                anyhow::bail!(
                    "azure_openai requires base_url (e.g. https://<resource>.openai.azure.com)"
                );
            }
            validate_ai_base_url(base_url)?;
            if model.is_empty() {
                anyhow::bail!(
                    "azure_openai requires model = <deployment-name> (as configured in Azure AI Foundry)"
                );
            }
            let api_version = if api_version.is_empty() {
                "2024-12-01-preview".to_string()
            } else {
                api_version.to_string()
            };
            Ok(Box::new(azure_openai::AzureOpenAiProvider::new(
                api_key,
                model.to_string(),
                base_url.to_string(),
                api_version,
            )?))
        }
        "anthropic" => Ok(Box::new(anthropic::AnthropicProvider::new(
            api_key,
            model.to_string(),
        )?)),
        "ollama" => {
            let api_key_opt = if api_key.is_empty() {
                None
            } else {
                Some(api_key)
            };

            let base_url = if !base_url.is_empty() {
                validate_ai_base_url(base_url)?;
                base_url.to_string()
            } else if api_key_opt.is_some() {
                "https://api.ollama.com".to_string()
            } else {
                let env_url = std::env::var("OLLAMA_BASE_URL")
                    .unwrap_or_else(|_| "http://localhost:11434".to_string());
                validate_ai_base_url(&env_url)?;
                env_url
            };

            let model = if model.is_empty() || model == "gpt-4o-mini" {
                if api_key_opt.is_some() {
                    "qwen3-coder:480b".to_string()
                } else {
                    "llama3.2".to_string()
                }
            } else {
                model.to_string()
            };
            Ok(Box::new(ollama::OllamaProvider::new(
                base_url,
                model,
                api_key_opt,
            )?))
        }
        other => {
            // SEC-017: Unknown provider name — require explicit base_url.
            // If base_url is set, treat as OpenAI-compatible endpoint.
            // Without base_url, fail closed to prevent accidental data egress.
            if !base_url.is_empty() {
                validate_ai_base_url(base_url)?;
                tracing::info!(
                    provider = other,
                    base_url = %base_url,
                    "treating unknown provider as OpenAI-compatible via base_url"
                );
                Ok(Box::new(openai::OpenAiProvider::with_base_url(
                    api_key,
                    model.to_string(),
                    base_url.to_string(),
                )?))
            } else {
                anyhow::bail!(
                    "unknown AI provider '{}'. Set provider to 'openai', 'anthropic', \
                     or 'ollama', or provide a base_url for OpenAI-compatible endpoints.",
                    other
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};

    #[test]
    fn playbook_prompt_section_none_and_empty_are_blank() {
        assert_eq!(playbook_prompt_section(&None), "");
        assert_eq!(playbook_prompt_section(&Some(String::new())), "");
    }

    #[test]
    fn playbook_prompt_section_wraps_summary_with_no_duplicate_instruction() {
        let s = playbook_prompt_section(&Some("playbook pb: 1 success".to_string()));
        assert!(s.contains("DETERMINISTIC PLAYBOOK ALREADY EXECUTED"));
        assert!(s.contains("do NOT repeat"));
        assert!(s.contains("playbook pb: 1 success"));
    }

    fn make_incident(severity: Severity, ip: &str) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "host".into(),
            incident_id: "test-id".into(),
            severity,
            title: "Test".into(),
            summary: "test".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    // ── Wave 4 anchors (AUDIT-WAVE4-AI-IPV6) ───────────────────────────
    //
    // Pre-fix `validate_ai_base_url` rejected loopback IPv6 bracket
    // forms like `http://[::1]:8080/path` because the host extractor
    // did `.split(':').next()` on the post-`http://` slice and got
    // `[`. Operators running a local IPv6 LLM endpoint (Ollama on
    // `[::1]:11434`, vLLM on `[::1]:8000`) hit "HTTP is not allowed"
    // even though `::1` is a documented loopback. The new
    // `extract_url_host` helper understands the bracket form.

    #[test]
    fn extract_url_host_handles_ipv6_bracket_with_port_and_path() {
        // The exact prod failure shape (Ollama on IPv6 loopback).
        assert_eq!(extract_url_host("[::1]:11434/api/generate"), "::1");
    }

    #[test]
    fn extract_url_host_handles_ipv6_bracket_no_port() {
        assert_eq!(extract_url_host("[::1]/api/v1"), "::1");
        assert_eq!(extract_url_host("[::1]"), "::1");
    }

    #[test]
    fn extract_url_host_handles_ipv6_bracket_with_full_address() {
        // A full-form IPv6 (not just loopback) round-trips through
        // the bracket extractor too.
        assert_eq!(extract_url_host("[2001:db8::1]:443/v1"), "2001:db8::1");
    }

    #[test]
    fn extract_url_host_handles_ipv4_with_port_and_path() {
        assert_eq!(extract_url_host("127.0.0.1:8080/v1"), "127.0.0.1");
        assert_eq!(extract_url_host("203.0.113.42:443"), "203.0.113.42");
    }

    #[test]
    fn extract_url_host_handles_bare_hostname() {
        assert_eq!(extract_url_host("localhost"), "localhost");
        assert_eq!(
            extract_url_host("api.example.com:443/v1"),
            "api.example.com"
        );
    }

    #[test]
    fn validate_ai_base_url_accepts_ipv6_loopback_http_with_port_and_path() {
        // The headline anchor: every shape an operator running a local
        // IPv6 LLM endpoint over plain HTTP would write. Pre-fix all
        // of these errored with "HTTP is not allowed".
        assert!(validate_ai_base_url("http://[::1]").is_ok());
        assert!(validate_ai_base_url("http://[::1]:11434").is_ok());
        assert!(validate_ai_base_url("http://[::1]:11434/api/generate").is_ok());
        assert!(validate_ai_base_url("http://[::1]/api").is_ok());
    }

    #[test]
    fn validate_ai_base_url_still_accepts_existing_loopback_forms() {
        // Anti-regression for the pre-fix loopback set still working.
        assert!(validate_ai_base_url("http://localhost").is_ok());
        assert!(validate_ai_base_url("http://localhost:11434/api/generate").is_ok());
        assert!(validate_ai_base_url("http://127.0.0.1").is_ok());
        assert!(validate_ai_base_url("http://127.0.0.1:11434/api").is_ok());
    }

    #[test]
    fn validate_ai_base_url_still_rejects_remote_http() {
        // Anti-regression: tightening the host extractor must NOT
        // weaken the security gate. Remote HTTP (any non-loopback
        // host) must still be refused.
        for evil in &[
            "http://api.openai.com/v1",
            "http://10.0.0.5:8080",
            "http://[2001:db8::1]:443",
            "http://example.com",
        ] {
            assert!(
                validate_ai_base_url(evil).is_err(),
                "remote HTTP {evil:?} must be rejected"
            );
        }
    }

    #[test]
    fn extract_url_host_strips_userinfo_before_authority_split() {
        // The Copilot-review anchor on PR #462. Pre-fix
        // extract_url_host("localhost:pw@evil.example") returned
        // "localhost" because split-on-`:` ran BEFORE the userinfo
        // stripper, so `validate_ai_base_url("http://localhost:pw@evil.example")`
        // accepted the URL as loopback even though the real authority
        // is `evil.example`. This is the URL-userinfo-bypass class.
        assert_eq!(
            extract_url_host("user@example.com"),
            "example.com",
            "userinfo with no password"
        );
        assert_eq!(
            extract_url_host("user:pw@example.com"),
            "example.com",
            "userinfo with password"
        );
        assert_eq!(
            extract_url_host("localhost:pw@evil.example"),
            "evil.example",
            "the headline bypass: real host wins, not the bare userinfo"
        );
        assert_eq!(
            extract_url_host("user:pw@example.com:443/v1"),
            "example.com",
            "userinfo + port + path"
        );
        // RFC 3986: userinfo can itself contain `@` (rare, percent
        // encoded). Use rfind so the LAST `@` is the boundary.
        assert_eq!(
            extract_url_host("a@b@example.com"),
            "example.com",
            "multiple `@`: the LAST one is the userinfo boundary"
        );
        // A `/` before any `@` belongs to the path, so the `@` in the
        // path must NOT be treated as userinfo.
        assert_eq!(
            extract_url_host("real.example/spoof@evil.example"),
            "real.example",
            "path content with `@` does not get treated as authority"
        );
    }

    #[test]
    fn validate_ai_base_url_rejects_userinfo_bypass_remote() {
        // End-to-end pin for the bypass: the high-level gate must
        // refuse `http://localhost:pw@evil.example` even though the
        // bare `localhost` substring appears in the URL. This is the
        // Copilot-review concern from PR #462.
        for evil in &[
            "http://localhost:pw@evil.example",
            "http://user@api.openai.com/v1",
            "http://user:pass@10.0.0.5:8080",
            "http://127.0.0.1:fake@evil.example/api",
            "http://[::1]:fake@evil.example/api",
        ] {
            assert!(
                validate_ai_base_url(evil).is_err(),
                "userinfo-bypass remote HTTP {evil:?} must be rejected"
            );
        }
    }

    #[test]
    fn gate_passes_high_severity_external_ip() {
        let inc = make_incident(Severity::High, "1.2.3.4");
        assert!(should_invoke_ai(&inc, &HashSet::new(), &Severity::High));
    }

    #[test]
    fn gate_passes_medium_severity_with_medium_config() {
        let inc = make_incident(Severity::Medium, "1.2.3.4");
        assert!(should_invoke_ai(&inc, &HashSet::new(), &Severity::Medium));
    }

    #[test]
    fn gate_blocks_medium_with_high_config() {
        let inc = make_incident(Severity::Medium, "1.2.3.4");
        assert!(!should_invoke_ai(&inc, &HashSet::new(), &Severity::High));
    }

    #[test]
    fn gate_blocks_already_blocked_ip() {
        let inc = make_incident(Severity::High, "1.2.3.4");
        let mut blocked = HashSet::new();
        blocked.insert("1.2.3.4".to_string());
        assert!(!should_invoke_ai(&inc, &blocked, &Severity::High));
    }

    #[test]
    fn gate_blocks_low_severity() {
        let inc = make_incident(Severity::Low, "1.2.3.4");
        assert!(!should_invoke_ai(&inc, &HashSet::new(), &Severity::High));
    }

    #[test]
    fn gate_blocks_private_ip() {
        let inc = make_incident(Severity::High, "192.168.1.100");
        assert!(!should_invoke_ai(&inc, &HashSet::new(), &Severity::High));
    }

    #[test]
    fn gate_blocks_loopback() {
        let inc = make_incident(Severity::Critical, "127.0.0.1");
        assert!(!should_invoke_ai(&inc, &HashSet::new(), &Severity::High));
    }

    #[test]
    fn ignore_decision_helper() {
        let d = AiDecision::ignore("test reason");
        assert!(matches!(d.action, AiAction::Ignore { .. }));
        assert!(!d.auto_execute);
    }

    // SEC-017: Unknown provider without base_url must fail.
    #[test]
    fn build_provider_unknown_no_base_url_fails() {
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "nonexistent-provider".into(),
            base_url: String::new(),
            ..Default::default()
        };
        let result = build_provider(&cfg, "ufw");
        assert!(
            result.is_err(),
            "should fail for unknown provider without base_url"
        );
        let err = format!("{}", result.err().unwrap());
        assert!(
            err.contains("unknown AI provider"),
            "expected 'unknown AI provider' error, got: {err}"
        );
    }

    #[test]
    fn build_provider_unknown_with_base_url_succeeds() {
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "custom-llm".into(),
            base_url: "https://my-llm.example.com".into(),
            api_key: "test-key".into(),
            model: "my-model".into(),
            ..Default::default()
        };
        let result = build_provider(&cfg, "ufw");
        assert!(
            result.is_ok(),
            "should accept unknown provider with base_url"
        );
    }

    #[test]
    fn build_provider_known_provider_succeeds() {
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "ollama".into(),
            ..Default::default()
        };
        let result = build_provider(&cfg, "ufw");
        assert!(result.is_ok());
    }

    #[test]
    fn build_provider_stub_succeeds_without_api_key() {
        // Spec 024: the scenario-qa harness must be able to build a provider
        // without any API key or external service. This is the contract.
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "stub".into(),
            ..Default::default()
        };
        let provider = build_provider(&cfg, "ufw").expect("stub provider must build offline");
        assert_eq!(provider.name(), "stub");
    }

    #[test]
    fn build_shadow_observer_empty_provider_fails() {
        let shadow = crate::config::ShadowConfig {
            enabled: true,
            ..Default::default()
        };
        let err = build_shadow_observer(&shadow, "stub", "", "", 0.85, "ufw")
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("shadow") && err.contains("empty"),
            "expected shadow-empty error, got: {err}"
        );
    }

    #[test]
    fn build_shadow_observer_matching_target_fails() {
        // Same provider + same base_url + same model as the Decide-serving
        // slot must be rejected; otherwise shadow provides no signal.
        let shadow = crate::config::ShadowConfig {
            enabled: true,
            provider: "ollama".into(),
            base_url: "http://localhost:11434".into(),
            model: "llama3.2".into(),
            ..Default::default()
        };
        let err = build_shadow_observer(
            &shadow,
            "ollama",
            "http://localhost:11434",
            "llama3.2",
            0.85,
            "ufw",
        )
        .err()
        .unwrap()
        .to_string();
        assert!(
            err.contains("must differ"),
            "expected 'must differ' error, got: {err}"
        );
    }

    #[test]
    fn build_shadow_observer_distinct_config_succeeds() {
        // Target stub + shadow stub-with-different-model is allowed because
        // the check compares (provider, base_url, model) tuple.
        let shadow = crate::config::ShadowConfig {
            enabled: true,
            provider: "stub".into(),
            model: "different".into(),
            ..Default::default()
        };
        let observer = build_shadow_observer(&shadow, "stub", "", "", 0.85, "ufw")
            .expect("shadow observer must build")
            .expect("enabled shadow must return Some");
        assert_eq!(observer.name(), "stub");
    }

    #[test]
    fn build_shadow_observer_disabled_returns_none() {
        let shadow = crate::config::ShadowConfig::default();
        let observer = build_shadow_observer(&shadow, "stub", "", "", 0.85, "ufw")
            .expect("disabled shadow must not error");
        assert!(observer.is_none());
    }

    #[test]
    fn wrap_with_shadow_no_shadow_returns_primary_unchanged() {
        let primary = build_provider(
            &crate::config::AiConfig {
                enabled: true,
                provider: "stub".into(),
                ..Default::default()
            },
            "ufw",
        )
        .expect("stub builds");
        let wrapped = wrap_with_shadow(primary, None, "/tmp/unused.jsonl", 1.0);
        assert_eq!(wrapped.name(), "stub");
    }

    #[test]
    fn build_provider_azure_succeeds_with_explicit_base_url() {
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "azure_openai".into(),
            base_url: "https://example-resource.openai.azure.com".into(),
            model: "gpt-5-4-mini".into(),
            api_version: "2024-12-01-preview".into(),
            api_key: "dummy".into(),
            ..Default::default()
        };
        let provider = build_provider(&cfg, "ufw").expect("azure provider must build");
        assert_eq!(provider.name(), "azure_openai");
    }

    #[test]
    fn build_provider_azure_requires_base_url() {
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "azure_openai".into(),
            base_url: String::new(),
            model: "gpt-5-4-mini".into(),
            api_key: "dummy".into(),
            ..Default::default()
        };
        let err = build_provider(&cfg, "ufw").err().unwrap().to_string();
        assert!(err.contains("base_url"), "got: {err}");
    }

    #[test]
    fn build_provider_azure_requires_model() {
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "azure_openai".into(),
            base_url: "https://example-resource.openai.azure.com".into(),
            model: String::new(),
            api_key: "dummy".into(),
            ..Default::default()
        };
        let err = build_provider(&cfg, "ufw").err().unwrap().to_string();
        assert!(err.contains("model"), "got: {err}");
    }

    #[test]
    fn build_provider_azure_defaults_api_version_when_empty() {
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "azure_openai".into(),
            base_url: "https://example-resource.openai.azure.com".into(),
            model: "gpt-5-4-mini".into(),
            api_version: String::new(),
            api_key: "dummy".into(),
            ..Default::default()
        };
        // Empty api_version should fall back to default (not a bail)
        assert!(build_provider(&cfg, "ufw").is_ok());
    }

    #[cfg(not(feature = "local-classifier"))]
    #[test]
    fn build_provider_local_classifier_without_feature_fails() {
        let cfg = crate::config::AiConfig {
            enabled: true,
            provider: "local_classifier".into(),
            base_url: "/tmp/nonexistent-model-dir".into(),
            ..Default::default()
        };
        let err = build_provider(&cfg, "ufw").err().unwrap().to_string();
        assert!(
            err.contains("local-classifier"),
            "expected build-feature guidance, got: {err}"
        );
    }
}
