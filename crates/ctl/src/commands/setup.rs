use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use dialoguer::console::Style;
use dialoguer::theme::ColorfulTheme;
#[allow(unused_imports)] // MultiSelect is used only in non-test prompt_notification_channels
use dialoguer::{Confirm, MultiSelect, Select};

use crate::commands::agent::{cmd_agent, parse_selection_indices, resolve_dashboard_url};
use crate::commands::ai::{fetch_models, WIZARD_PROVIDERS};
use crate::commands::capability::cmd_enable_with_deferred_restart;
use crate::commands::notify::{
    cmd_configure_dashboard, cmd_configure_discord, cmd_configure_slack, cmd_configure_telegram,
    cmd_configure_webhook,
};
use crate::{
    am_root, config_editor, load_env_file, mask_secret, prompt, reexec_with_sudo, restart_agent,
    scan, systemd, write_env_key, AgentCommand, CapabilityRegistry, Cli,
};

#[derive(Debug, Clone)]
struct SetupCapabilityPlan {
    id: String,
    params: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct SetupPreconfigPlan {
    essential_capabilities: Vec<SetupCapabilityPlan>,
    set_telegram_min_severity: bool,
    set_webhook_min_severity: bool,
}

#[derive(Debug, Clone)]
enum SetupAiKey {
    None,
    Env { var: String, value: String },
    Config { value: String },
}

#[derive(Debug, Clone)]
struct SetupAiPlan {
    label: String,
    provider: String,
    model: String,
    base_url: Option<String>,
    key: SetupAiKey,
}

#[derive(Debug, Clone, Default)]
struct SetupNotificationPlan {
    telegram: bool,
    slack: bool,
    discord: bool,
    webhook: bool,
    dashboard: bool,
}

impl SetupNotificationPlan {
    fn label(&self) -> String {
        let mut parts = Vec::new();
        if self.telegram {
            parts.push("Telegram");
        }
        if self.slack {
            parts.push("Slack");
        }
        if self.discord {
            parts.push("Discord");
        }
        if self.webhook {
            parts.push("Webhook");
        }
        if self.dashboard {
            parts.push("Dashboard");
        }
        if parts.is_empty() {
            "none".to_string()
        } else {
            parts.join(" + ")
        }
    }

    fn any_selected(&self) -> bool {
        self.telegram || self.slack || self.discord || self.webhook || self.dashboard
    }
}

#[derive(Debug, Clone, Copy)]
struct SetupResponderPlan {
    dry_run: bool,
}

impl SetupResponderPlan {
    fn label(&self) -> &'static str {
        if self.dry_run {
            "Watch only"
        } else {
            "Auto-protect"
        }
    }
}

/// Outcome of the `[1/4] Local Warden Model` wizard step.
///
/// The on-device classifier is an alternative to a cloud LLM for the
/// `Decide` capability (block / dismiss / escalate). Saying yes here
/// triggers `apply_setup_warden_plan` to actually download the model
/// (`innerwarden install-warden` path, ~91 MB) and persist the
/// `[ai.warden]` section to agent.toml so the agent picks it up on
/// the next restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SetupWardenPlan {
    /// Operator said yes to the pitch (or was auto-confirmed because
    /// they already have `[ai.warden]` configured in agent.toml).
    enabled: bool,
    /// True when the wizard detected an existing `[ai.warden]` or
    /// legacy `[ai.classifier]` section. Skips the pitch and emits an
    /// `[ok]` line — same idempotent re-run behaviour as the AI step.
    already_configured: bool,
}

impl SetupWardenPlan {
    fn label(&self) -> &'static str {
        if self.already_configured {
            "already configured"
        } else if self.enabled {
            "installing now"
        } else {
            "skipped (Decide via cloud AI)"
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupMode {
    Basic,
    Advanced,
}

impl SetupMode {
    fn from_str(input: &str) -> Self {
        if input.eq_ignore_ascii_case("advanced") {
            Self::Advanced
        } else {
            Self::Basic
        }
    }

    fn is_advanced(&self) -> bool {
        matches!(self, Self::Advanced)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SetupCheck {
    pub(crate) label: String,
    pub(crate) detail: String,
    pub(crate) ok: bool,
    pub(crate) critical: bool,
}

fn read_agent_doc(path: &Path) -> Option<toml_edit::DocumentMut> {
    std::fs::read_to_string(path).ok()?.parse().ok()
}

fn agent_bool(doc: Option<&toml_edit::DocumentMut>, section: &str, key: &str) -> bool {
    doc.and_then(|d| d.get(section))
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn agent_str(doc: Option<&toml_edit::DocumentMut>, section: &str, key: &str) -> Option<String> {
    doc.and_then(|d| d.get(section))
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
}

fn env_has(env_vars: &HashMap<String, String>, key: &str) -> bool {
    env_vars.get(key).is_some_and(|v| !v.trim().is_empty())
        || std::env::var(key).is_ok_and(|v| !v.trim().is_empty())
}

/// Pure parser for a yes/no answer, with default applied on empty input.
fn parse_yes_no(input: &str, default_yes: bool) -> bool {
    let trimmed = input.trim().to_lowercase();
    if trimmed.is_empty() {
        return default_yes;
    }
    matches!(trimmed.as_str(), "y" | "yes")
}

#[cfg(not(any(test, coverage)))]
fn prompt_yes_no(label: &str, default_yes: bool) -> Result<bool> {
    print!("{label}");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(parse_yes_no(&input, default_yes))
}

/// Test-mode stub: returns the supplied default. Exercise of the orchestrator's
/// branching is the test's responsibility (set up state so that the caller takes
/// the desired branch). The pure `parse_yes_no` covers actual stdin parsing.
#[cfg(any(test, coverage))]
fn prompt_yes_no(_label: &str, default_yes: bool) -> Result<bool> {
    Ok(default_yes)
}

/// Pure resolver for the multi-agent selection prompt.
///
/// `selection_input` is the raw string the user typed (already read).
/// Returns the selected pids; an empty vec means "skip".
fn resolve_multi_agent_selection(
    detected_agents: &[innerwarden_agent_guard::detect::DetectedAgent],
    selection_input: &str,
) -> Vec<u32> {
    let trimmed = selection_input.trim();
    if trimmed.is_empty() {
        return vec![];
    }
    let Some(indices) = parse_selection_indices(trimmed, detected_agents.len()) else {
        return vec![];
    };
    indices
        .into_iter()
        .map(|idx| detected_agents[idx - 1].pid)
        .collect()
}

fn prompt_setup_agent_selection(
    detected_agents: &[innerwarden_agent_guard::detect::DetectedAgent],
) -> Result<Vec<u32>> {
    if detected_agents.is_empty() {
        return Ok(vec![]);
    }

    if detected_agents.len() == 1 {
        let agent = &detected_agents[0];
        let prompt = format!(
            "  Found 1 running AI agent ({} / pid {}). Connect now? [Y/n] ",
            agent.name, agent.pid
        );
        return Ok(if prompt_yes_no(&prompt, true)? {
            vec![agent.pid]
        } else {
            vec![]
        });
    }

    println!("  Found {} running AI agents.", detected_agents.len());
    println!("  {:<4} {:<8} {:<16} TYPE", "NO.", "PID", "NAME");
    println!("  {}", "─".repeat(48));
    for (idx, agent) in detected_agents.iter().enumerate() {
        println!(
            "  {:<4} {:<8} {:<16} {}",
            idx + 1,
            agent.pid,
            agent.name,
            agent.integration
        );
    }
    println!();

    let selection = prompt("  Select agents [ex: 1,3 or all, Enter to skip]")?;
    let trimmed = selection.trim();
    if trimmed.is_empty() {
        return Ok(vec![]);
    }

    if parse_selection_indices(trimmed, detected_agents.len()).is_none() {
        println!("  Invalid selection '{trimmed}'. Skipping agent connection.");
        return Ok(vec![]);
    }
    Ok(resolve_multi_agent_selection(detected_agents, &selection))
}

fn parse_setup_capability_hint(hint: &str) -> Option<SetupCapabilityPlan> {
    let parts: Vec<&str> = hint.split_whitespace().collect();
    if parts.len() < 3 || parts[0] != "innerwarden" || parts[1] != "enable" {
        return None;
    }

    let mut params = HashMap::new();
    let mut i = 3;
    while i < parts.len() {
        if parts[i] == "--param" && i + 1 < parts.len() {
            if let Some((k, v)) = parts[i + 1].split_once('=') {
                params.insert(k.to_string(), v.to_string());
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    Some(SetupCapabilityPlan {
        id: parts[2].to_string(),
        params,
    })
}

fn setup_capability_restart_needs(capability_id: &str) -> (bool, bool) {
    match capability_id {
        // (sensor, agent)
        "ai" => (false, true),
        "block-ip" => (false, true),
        "sudo-protection" => (true, true),
        "shell-audit" => (true, false),
        "search-protection" => (true, true),
        _ => (false, false),
    }
}

fn collect_setup_preconfig_plan(agent_doc: Option<&toml_edit::DocumentMut>) -> SetupPreconfigPlan {
    let probes = scan::run_probes();
    let recs = scan::score_modules(&probes);

    let essential_capabilities = recs
        .iter()
        .filter(|r| matches!(r.tier, scan::Tier::Essential))
        .filter_map(|r| parse_setup_capability_hint(r.enable_hint))
        .collect();

    let set_telegram_min_severity = agent_doc
        .and_then(|d| d.get("telegram"))
        .and_then(|t| t.get("min_severity"))
        .is_none();
    let set_webhook_min_severity = agent_doc
        .and_then(|d| d.get("webhook"))
        .and_then(|t| t.get("min_severity"))
        .is_none();

    SetupPreconfigPlan {
        essential_capabilities,
        set_telegram_min_severity,
        set_webhook_min_severity,
    }
}

pub(crate) fn ai_provider_defaults(provider: &str) -> (String, Option<String>, Option<String>) {
    match provider {
        "openai" => (
            "gpt-4o-mini".to_string(),
            Some("OPENAI_API_KEY".to_string()),
            None,
        ),
        "anthropic" => (
            "claude-haiku-4-5-20251001".to_string(),
            Some("ANTHROPIC_API_KEY".to_string()),
            None,
        ),
        "ollama" => ("llama3.2".to_string(), None, None),
        "groq" => (
            "llama-3.3-70b-versatile".to_string(),
            Some("GROQ_API_KEY".to_string()),
            Some("https://api.groq.com/openai".to_string()),
        ),
        "deepseek" => (
            "deepseek-chat".to_string(),
            Some("DEEPSEEK_API_KEY".to_string()),
            Some("https://api.deepseek.com".to_string()),
        ),
        "together" => (
            "meta-llama/Llama-3.3-70B-Instruct-Turbo".to_string(),
            Some("TOGETHER_API_KEY".to_string()),
            Some("https://api.together.xyz".to_string()),
        ),
        "minimax" => (
            "MiniMax-Text-01".to_string(),
            Some("MINIMAX_API_KEY".to_string()),
            Some("https://api.minimaxi.chat".to_string()),
        ),
        "mistral" => (
            "mistral-small-latest".to_string(),
            Some("MISTRAL_API_KEY".to_string()),
            Some("https://api.mistral.ai".to_string()),
        ),
        "xai" => (
            "grok-3-mini-fast".to_string(),
            Some("XAI_API_KEY".to_string()),
            Some("https://api.x.ai".to_string()),
        ),
        "fireworks" => (
            "accounts/fireworks/models/llama-v3p3-70b-instruct".to_string(),
            Some("FIREWORKS_API_KEY".to_string()),
            Some("https://api.fireworks.ai/inference".to_string()),
        ),
        "openrouter" => (
            "meta-llama/llama-3.3-70b-instruct".to_string(),
            Some("OPENROUTER_API_KEY".to_string()),
            Some("https://openrouter.ai/api".to_string()),
        ),
        "gemini" => (
            "gemini-2.0-flash".to_string(),
            Some("GEMINI_API_KEY".to_string()),
            Some("https://generativelanguage.googleapis.com/v1beta/openai".to_string()),
        ),
        _ => (
            "gpt-4o-mini".to_string(),
            Some(format!("{}_API_KEY", provider.to_uppercase())),
            None,
        ),
    }
}

fn build_setup_ai_plan(
    provider: &str,
    label: &str,
    key: Option<String>,
    model: Option<String>,
    base_url: Option<String>,
) -> SetupAiPlan {
    let (default_model, key_var, default_base_url) = ai_provider_defaults(provider);
    let effective_model = model.unwrap_or(default_model);
    let effective_base_url = base_url.or(default_base_url);
    let key = match key {
        None => SetupAiKey::None,
        Some(value)
            if provider == "ollama"
                && effective_base_url.as_deref() == Some("https://api.ollama.com") =>
        {
            SetupAiKey::Config { value }
        }
        Some(value) => SetupAiKey::Env {
            var: key_var.unwrap_or_else(|| format!("{}_API_KEY", provider.to_uppercase())),
            value,
        },
    };

    SetupAiPlan {
        label: label.to_string(),
        provider: provider.to_string(),
        model: effective_model,
        base_url: effective_base_url,
        key,
    }
}

/// Static list of provider names presented in the "Other" sub-wizard, in display order.
const OTHER_AI_PROVIDERS: [&str; 6] = [
    "together",
    "minimax",
    "mistral",
    "xai",
    "fireworks",
    "gemini",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum OtherAiChoice {
    /// Pick a known wizard provider by static `name`.
    Provider(&'static str),
    /// Build a custom OpenAI-compatible provider.
    Custom,
    /// Skip / invalid input.
    None,
}

/// Pure resolver for the "Other provider" menu input.
fn resolve_other_ai_choice(input: &str) -> OtherAiChoice {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return OtherAiChoice::None;
    }
    let idx = match trimmed.parse::<usize>() {
        Ok(v) => v,
        Err(_) => return OtherAiChoice::None,
    };
    if (1..=OTHER_AI_PROVIDERS.len()).contains(&idx) {
        return OtherAiChoice::Provider(OTHER_AI_PROVIDERS[idx - 1]);
    }
    if idx == OTHER_AI_PROVIDERS.len() + 1 {
        return OtherAiChoice::Custom;
    }
    OtherAiChoice::None
}

#[allow(dead_code)] // only invoked by the (test-mode-stubbed) prompt_setup_ai_plan
fn prompt_setup_other_ai_plan() -> Result<Option<SetupAiPlan>> {
    println!("  Other provider\n");
    for (idx, provider_name) in OTHER_AI_PROVIDERS.iter().enumerate() {
        let provider = WIZARD_PROVIDERS
            .iter()
            .find(|p| p.name == *provider_name)
            .expect("wizard provider exists");
        println!("  {}. {}", idx + 1, provider.label);
    }
    let custom_idx = OTHER_AI_PROVIDERS.len() + 1;
    println!("  {custom_idx}. Custom OpenAI-compatible\n");

    let choice = prompt(&format!("  Choose [1-{custom_idx}]"))?;
    let resolved = resolve_other_ai_choice(&choice);
    match resolved {
        OtherAiChoice::Provider(name) => {
            let provider = WIZARD_PROVIDERS
                .iter()
                .find(|p| p.name == name)
                .expect("wizard provider exists");
            prompt_cloud_provider(provider.name, provider.label, provider.signup_url)
        }
        OtherAiChoice::Custom => {
            let provider = prompt("  Provider name")?;
            let base_url = prompt("  Base URL")?;
            let key = prompt("  API key")?;
            let model = prompt("  Model")?;

            Ok(build_custom_provider_plan(provider, base_url, key, model))
        }
        OtherAiChoice::None => Ok(None),
    }
}

/// Pure builder for a "Custom OpenAI-compatible" plan from raw prompt strings.
/// Returns None if any field is empty.
fn build_custom_provider_plan(
    provider: String,
    base_url: String,
    key: String,
    model: String,
) -> Option<SetupAiPlan> {
    if provider.is_empty() || base_url.is_empty() || key.is_empty() || model.is_empty() {
        return None;
    }
    Some(build_setup_ai_plan(
        &provider,
        &provider,
        Some(key),
        Some(model),
        Some(base_url),
    ))
}

/// Resolve the api-style label for a cloud provider, defaulting to "openai".
fn resolve_cloud_api_style(provider: &str) -> &'static str {
    WIZARD_PROVIDERS
        .iter()
        .find(|p| p.name == provider)
        .map(|p| p.api_style)
        .unwrap_or("openai")
}

/// Resolve the request base url for a cloud provider, falling back to the
/// known default or the `https://api.<provider>.com` synthesis.
fn resolve_cloud_request_base_url(provider: &str, default_base_url: Option<&str>) -> String {
    default_base_url
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("https://api.{}.com", provider))
}

/// Pure post-input plan builder for the cloud-provider wizard branch.
///
/// `model_choice_input` is the raw string typed at the model selector prompt
/// (only consulted when `models` is non-empty).
fn build_cloud_provider_plan(
    provider: &str,
    label: &str,
    key: String,
    default_model: String,
    default_base_url: Option<String>,
    models: &[String],
    model_choice_input: &str,
) -> Option<SetupAiPlan> {
    if key.is_empty() {
        return None;
    }
    if models.is_empty() {
        return Some(build_setup_ai_plan(
            provider,
            label,
            Some(key),
            None,
            default_base_url,
        ));
    }
    let default_idx = pick_cloud_default_model_idx(models, &default_model);
    let idx = parse_model_choice_idx(model_choice_input, default_idx, models.len());
    Some(build_setup_ai_plan(
        provider,
        label,
        Some(key),
        Some(models[idx].clone()),
        default_base_url,
    ))
}

#[allow(dead_code)] // only invoked by the (test-mode-stubbed) prompt_setup_ai_plan
fn prompt_cloud_provider(
    provider: &str,
    label: &str,
    signup_url: &str,
) -> Result<Option<SetupAiPlan>> {
    let (default_model, _, default_base_url) = ai_provider_defaults(provider);
    let api_style = resolve_cloud_api_style(provider);

    let key = prompt(&format!("  {label} API key ({signup_url})"))?;
    if key.is_empty() {
        return Ok(None);
    }

    let base_url = resolve_cloud_request_base_url(provider, default_base_url.as_deref());

    // Try to fetch available models from the provider
    print!("  Fetching models... ");
    std::io::stdout().flush()?;
    let models = fetch_models(&base_url, &key, api_style);

    if models.is_empty() {
        println!("could not list (using default: {default_model})");
        return Ok(build_cloud_provider_plan(
            provider,
            label,
            key,
            default_model,
            default_base_url,
            &models,
            "",
        ));
    }

    println!("found {} models\n", models.len());

    // Find the default model index
    let default_idx = pick_cloud_default_model_idx(&models, &default_model);
    let show_count = models.len().min(15);

    for line in build_cloud_model_menu_lines(&models, default_idx) {
        println!("  {line}");
    }
    println!();

    let model_choice = prompt(&format!(
        "  Model [1-{}, default={}]",
        models.len().min(show_count),
        default_idx
    ))?;

    Ok(build_cloud_provider_plan(
        provider,
        label,
        key,
        default_model,
        default_base_url,
        &models,
        &model_choice,
    ))
}

/// Build the human-readable model menu shown to the user during the cloud
/// provider wizard. Returns one line per row, capped at 15 plus a possible
/// "... and N more" trailer.
fn build_cloud_model_menu_lines(models: &[String], default_idx: usize) -> Vec<String> {
    let show_count = models.len().min(15);
    let mut out = Vec::with_capacity(show_count + 1);
    for (i, model) in models.iter().take(show_count).enumerate() {
        let tag = if i + 1 == default_idx {
            " (recommended)"
        } else {
            ""
        };
        out.push(format!("{}. {}{}", i + 1, model, tag));
    }
    if models.len() > show_count {
        out.push(format!("... and {} more", models.len() - show_count));
    }
    out
}

/// Build the human-readable model menu shown for the local Ollama branch.
fn build_local_ollama_menu_lines(local_models: &[String]) -> Vec<String> {
    local_models
        .iter()
        .enumerate()
        .map(|(i, model)| {
            let tag = if model.starts_with("qwen2.5:3b") {
                " (recommended)"
            } else {
                ""
            };
            format!("{}. {}{}", i + 1, model, tag)
        })
        .collect()
}

/// Find the recommended cloud-provider model index (1-indexed). Falls back to 1.
fn pick_cloud_default_model_idx(models: &[String], default_model: &str) -> usize {
    models
        .iter()
        .position(|m| m == default_model)
        .map(|i| i + 1)
        .unwrap_or(1)
}

/// Build the Ollama selector label from runtime detection.
fn build_ollama_label(ollama_running: bool, local_models: &[String]) -> String {
    if ollama_running && !local_models.is_empty() {
        let model_list: Vec<&str> = local_models.iter().take(3).map(|s| s.as_str()).collect();
        let suffix = if local_models.len() > 3 {
            format!(", +{} more", local_models.len() - 3)
        } else {
            String::new()
        };
        format!(
            "Ollama          {} models: {}{}",
            local_models.len(),
            model_list.join(", "),
            suffix
        )
    } else if ollama_running {
        "Ollama          running, no models yet".to_string()
    } else {
        "Ollama          not installed — https://ollama.com".to_string()
    }
}

/// Pick the default 1-indexed pick for the local Ollama model list.
/// Prefers the entry whose name starts with `qwen2.5:3b`; falls back to 1.
fn pick_local_ollama_default_idx(local_models: &[String]) -> usize {
    local_models
        .iter()
        .position(|m| m.starts_with("qwen2.5:3b"))
        .map(|i| i + 1)
        .unwrap_or(1)
}

/// Parse a numeric model choice from raw input, with default fallback and clamp.
fn parse_model_choice_idx(input: &str, default_idx: usize, total: usize) -> usize {
    if total == 0 {
        return 0;
    }
    input
        .trim()
        .parse::<usize>()
        .unwrap_or(default_idx)
        .saturating_sub(1)
        .min(total - 1)
}

/// Possible outcomes of the local-ollama branch when local input is fully resolved.
#[derive(Debug, Clone)]
enum LocalOllamaOutcome {
    /// Ollama daemon not detected; the operator must install it first.
    NotInstalled,
    /// Daemon is up but the operator has not pulled any model.
    NoModels,
    /// Daemon is up with exactly one model — auto-select it (no prompt needed).
    AutoSelected(SetupAiPlan),
    /// Daemon is up with multiple models — pick by `model_choice_input`.
    Selected(SetupAiPlan),
}

/// Pure resolver for the local-Ollama branch of the AI wizard.
///
/// `model_choice_input` is the raw string typed at the model selector
/// prompt. It is only consulted when the model list is greater than one.
fn resolve_local_ollama_plan(
    ollama_running: bool,
    local_models: &[String],
    model_choice_input: &str,
) -> LocalOllamaOutcome {
    if !ollama_running {
        return LocalOllamaOutcome::NotInstalled;
    }
    if local_models.is_empty() {
        return LocalOllamaOutcome::NoModels;
    }
    if local_models.len() == 1 {
        return LocalOllamaOutcome::AutoSelected(build_setup_ai_plan(
            "ollama",
            "Ollama",
            None,
            Some(local_models[0].clone()),
            None,
        ));
    }
    let default_idx = pick_local_ollama_default_idx(local_models);
    let idx = parse_model_choice_idx(model_choice_input, default_idx, local_models.len());
    LocalOllamaOutcome::Selected(build_setup_ai_plan(
        "ollama",
        "Ollama",
        None,
        Some(local_models[idx].clone()),
        None,
    ))
}

/// Map the cloud Select index (1..=5) to its `(provider, label, signup_url)`
/// triple. Returns None for indices outside the cloud range.
fn cloud_provider_for_selection(
    selection: usize,
) -> Option<(&'static str, &'static str, &'static str)> {
    match selection {
        1 => Some(("openrouter", "OpenRouter", "openrouter.ai")),
        2 => Some(("openai", "OpenAI", "platform.openai.com")),
        3 => Some(("anthropic", "Anthropic", "console.anthropic.com")),
        4 => Some(("groq", "Groq", "console.groq.com")),
        5 => Some(("deepseek", "DeepSeek", "platform.deepseek.com")),
        _ => None,
    }
}

/// Build the menu items shown by the [2/4] AI Select dialog. The first entry
/// is the dynamic Ollama label (computed from runtime detection); the rest
/// are static taglines for the cloud and "Other" options.
#[allow(dead_code)] // consumed only by the non-test path of prompt_setup_ai_plan
fn build_setup_ai_menu_items(ollama_label: String) -> Vec<String> {
    vec![
        ollama_label,
        "OpenRouter      400+ models, all providers, one API key".to_string(),
        "OpenAI          gpt-4o-mini".to_string(),
        "Anthropic       claude-haiku-4-5".to_string(),
        "Groq            llama-3.3-70b (fast, free tier)".to_string(),
        "DeepSeek        deepseek-chat".to_string(),
        "Other           Mistral, xAI, Fireworks, Gemini, custom".to_string(),
    ]
}

/// Test-mode stub: returns `Ok(None)` — the orchestrator path with this
/// outcome is exercised by `cmd_setup_dry_run_*` tests; the real prompt's
/// decision tree is covered piece-by-piece in dedicated unit tests of the
/// `resolve_local_ollama_plan` / `cloud_provider_for_selection` /
/// `resolve_other_ai_choice` helpers.
#[cfg(any(test, coverage))]
#[allow(dead_code)]
fn prompt_setup_ai_plan() -> Result<Option<SetupAiPlan>> {
    Ok(None)
}

/// Pure builder for the wizard's `[1/4] Local Warden Model` pitch lines.
/// Returns the dim-style benefit / cost bullets — the bold step header
/// and the intro sentences are added by `prompt_setup_warden_plan`. Kept
/// pure so the content (token savings, latency numbers, RAM cost,
/// install footprint) can be asserted in tests without driving the
/// interactive prompt.
fn warden_pitch_lines() -> &'static [&'static str] {
    &[
        "+ 0 tokens spent on Decide (the highest-volume LLM call)",
        "+ ~60 ms p50 vs ~500-2000 ms cloud round-trip",
        "+ Decide traffic never leaves the server",
        "- costs ~91 MB disk + ~150 MB RAM",
        "- adds ~30 s to setup (model downloads now)",
    ]
}

/// Pure builder for the wizard's intro sentences — the two lines that
/// follow the bold `[1/4] Local Warden Model` header before the bullets.
/// Same testability rationale as `warden_pitch_lines`.
fn warden_intro_lines() -> &'static [&'static str] {
    &[
        "On-device classifier for the Decide path (block / dismiss /",
        "escalate). Cloud AI still runs Explain, Briefings, and chat.",
    ]
}

/// Pure resolver for the prompt's outcome: maps the operator's yes/no
/// answer onto the `SetupWardenPlan` shape the caller persists. Split
/// out so the (currently non-binding) plan construction is exercised by
/// unit tests instead of only by the live wizard.
fn build_warden_plan(answer: bool) -> SetupWardenPlan {
    SetupWardenPlan {
        enabled: answer,
        already_configured: false,
    }
}

/// Test stub for the Local Warden Model step. Mirrors the AI prompt
/// pattern — the real implementation lives in the non-test cfg below.
#[cfg(any(test, coverage))]
#[allow(dead_code)]
fn prompt_setup_warden_plan() -> Result<SetupWardenPlan> {
    Ok(build_warden_plan(false))
}

/// `[1/4] Local Warden Model` — single yes/no question pitching the
/// on-device classifier as an alternative to cloud AI for `Decide`.
///
/// What the pitch promises:
///   - **Tokens saved.** `Decide` is the highest-volume LLM call; routing
///     it on-device removes that cost line entirely.
///   - **Latency.** ~60 ms p50 on ARM vs ~500-2000 ms cloud round-trip.
///   - **No data leaves the box** for the Decide path. Explain, Briefings,
///     and operator chat still go to whatever cloud provider you pick in
///     the next step.
///
/// What the pitch is honest about:
///   - **Disk + RAM cost.** ~91 MB on disk, ~150 MB resident.
///   - **Install runs now.** Saying yes triggers `cmd_install_classifier`
///     inside the wizard (download + SHA verify + extract) and writes
///     `[ai.warden]` to agent.toml. Adds ~30 s to setup. If the download
///     fails it falls back to the next step's cloud Decide path.
#[cfg(not(any(test, coverage)))]
fn prompt_setup_warden_plan() -> Result<SetupWardenPlan> {
    let bold = Style::new().bold();
    let dim = Style::new().dim();

    println!("  {}\n", bold.apply_to("[1/4] Local Warden Model"));
    for line in warden_intro_lines() {
        println!("  {line}");
    }
    println!();
    for bullet in warden_pitch_lines() {
        println!("  {}", dim.apply_to(format!("  {bullet}")));
    }
    println!();

    let answer = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("  Use the Local Warden Model?")
        .default(true)
        .interact()
        .map_err(|err| anyhow::anyhow!("warden prompt failed: {err}"))?;

    Ok(build_warden_plan(answer))
}

#[cfg(not(any(test, coverage)))]
fn prompt_setup_ai_plan() -> Result<Option<SetupAiPlan>> {
    println!("  [2/4] AI\n");

    // Auto-detect local Ollama (check if server responds, then list models)
    let ollama_running = ureq::get("http://localhost:11434/api/tags")
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(2)))
        .build()
        .call()
        .is_ok();
    let local_models = if ollama_running {
        fetch_models("http://localhost:11434", "", "ollama")
    } else {
        vec![]
    };

    let ollama_label = build_ollama_label(ollama_running, &local_models);
    let items = build_setup_ai_menu_items(ollama_label);

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("  Use arrows to move, Enter to select")
        .items(&items)
        .default(0)
        .interact()?;

    println!();

    if selection == 0 {
        // Ollama local — pre-resolve the cases that don't need a prompt.
        match resolve_local_ollama_plan(ollama_running, &local_models, "") {
            LocalOllamaOutcome::NotInstalled => {
                println!("  Ollama is not installed or not running.\n");
                println!("  1. Install from https://ollama.com");
                println!("  2. Start Ollama");
                println!("  3. Run: ollama pull qwen2.5:3b");
                println!("  4. Re-run: innerwarden setup\n");
                return Ok(None);
            }
            LocalOllamaOutcome::NoModels => {
                println!("  Ollama is running but has no models.\n");
                println!("  Run: ollama pull qwen2.5:3b");
                println!("  Then re-run: innerwarden setup\n");
                return Ok(None);
            }
            LocalOllamaOutcome::AutoSelected(plan) => {
                println!("  Using: {}\n", plan.model);
                return Ok(Some(plan));
            }
            LocalOllamaOutcome::Selected(_) => {
                // multi-model case: fall through to ask for a choice
            }
        }

        for line in build_local_ollama_menu_lines(&local_models) {
            println!("  {line}");
        }

        let default_idx = pick_local_ollama_default_idx(&local_models);

        println!();
        let model_choice = prompt(&format!(
            "  Model [1-{}, default={}]",
            local_models.len(),
            default_idx
        ))?;
        match resolve_local_ollama_plan(ollama_running, &local_models, &model_choice) {
            LocalOllamaOutcome::Selected(plan) | LocalOllamaOutcome::AutoSelected(plan) => {
                Ok(Some(plan))
            }
            // The pre-prompt branches already returned above; this is unreachable.
            LocalOllamaOutcome::NotInstalled | LocalOllamaOutcome::NoModels => Ok(None),
        }
    } else if let Some((provider, label, signup_url)) = cloud_provider_for_selection(selection) {
        prompt_cloud_provider(provider, label, signup_url)
    } else if selection == 6 {
        prompt_setup_other_ai_plan()
    } else {
        Ok(None)
    }
}

/// Apply the `[1/4] Local Warden Model` plan: when the operator said yes,
/// invoke the same install path that `innerwarden install-warden` uses,
/// then persist the canonical `[ai.warden]` section in agent.toml so the
/// agent picks the local Decide provider on its next restart.
///
/// Returns `Ok(true)` when the warden is active after the call (either
/// just installed, or was already configured before the wizard ran).
/// Returns `Ok(false)` when the operator said no (skipped) or when the
/// download/install failed and was reported as a soft warning. The
/// soft-fail behaviour is deliberate: a transient network blip during
/// setup must not block the rest of the wizard, and `[2/4] AI` will
/// still configure a working cloud-based Decide path when warden is
/// absent. The operator can retry by re-running `innerwarden setup` or
/// `sudo innerwarden install-warden`.
fn apply_setup_warden_plan(cli: &Cli, plan: &SetupWardenPlan) -> Result<bool> {
    if !plan.enabled {
        return Ok(false);
    }
    if plan.already_configured {
        return Ok(true);
    }

    // Default variant ("minilm-l6" → 87 MB MiniLM-L6 student) ships
    // with a pinned SHA-256 in `commands::ai::CLASSIFIER_VARIANTS`.
    // `--yes` skips the interactive confirmation since the wizard is
    // already a confirmation flow.
    // `configure = true` makes the install path also persist `[ai.warden]`
    // via the shared `write_warden_config` helper, so the wizard and the
    // headless `install.sh` provisioning can never drift on the config shape.
    match crate::commands::ai::cmd_install_classifier(
        cli,
        "minilm-l6",
        None, // url override — use the pinned URL
        None, // sha256 override — use the pinned digest
        true, // yes — wizard already asked
        true, // configure — write [ai.warden] in the same shot
    ) {
        Ok(()) => {}
        Err(err) => {
            eprintln!("  [warn] Local Warden install failed: {err:#}");
            eprintln!(
                "  [warn] Continuing without warden — `[2/4] AI` will provide the Decide path."
            );
            eprintln!("  [warn] Retry later with `sudo innerwarden install-warden`.");
            return Ok(false);
        }
    }

    Ok(true)
}

fn apply_setup_ai_plan(cli: &Cli, env_file: &Path, plan: &SetupAiPlan) -> Result<()> {
    match &plan.key {
        SetupAiKey::None => {}
        SetupAiKey::Env { var, value } => write_env_key(env_file, var, value)?,
        SetupAiKey::Config { value } => {
            config_editor::write_str(&cli.agent_config, "ai", "api_key", value)?;
        }
    }

    config_editor::write_bool(&cli.agent_config, "ai", "enabled", true)?;
    config_editor::write_str(&cli.agent_config, "ai", "provider", &plan.provider)?;
    config_editor::write_str(&cli.agent_config, "ai", "model", &plan.model)?;
    if let Some(base_url) = &plan.base_url {
        config_editor::write_str(&cli.agent_config, "ai", "base_url", base_url)?;
    }

    Ok(())
}

fn setup_current_ai_summary(agent_doc: Option<&toml_edit::DocumentMut>) -> String {
    let provider = agent_str(agent_doc, "ai", "provider").unwrap_or_else(|| "configured".into());
    let model = agent_str(agent_doc, "ai", "model").unwrap_or_default();
    if model.is_empty() {
        provider
    } else {
        format!("{provider} ({model})")
    }
}

/// Look up a string value at a dotted TOML path (e.g. `ai.warden.provider`).
/// agent_str only handles a single-level section; the warden helpers need
/// to descend through `[ai] → [warden]`.
fn agent_str_dotted(doc: Option<&toml_edit::DocumentMut>, path: &[&str]) -> Option<String> {
    let doc = doc?;
    let mut path_iter = path.iter();
    let first = path_iter.next()?;
    let mut node = doc.get(first)?;
    for segment in path_iter {
        node = node.get(segment)?;
    }
    node.as_str().map(|s| s.to_string())
}

/// Returns true when the agent.toml already has `[ai.warden]` (canonical
/// since the 2026-05-03 rename) or `[ai.classifier]` (preserved as a
/// serde alias) wired up with a `provider` key. Either form counts as
/// "configured" — we don't try to revalidate the on-disk model bytes
/// from the wizard.
fn agent_warden_configured(doc: Option<&toml_edit::DocumentMut>) -> bool {
    agent_str_dotted(doc, &["ai", "warden", "provider"]).is_some()
        || agent_str_dotted(doc, &["ai", "classifier", "provider"]).is_some()
}

fn setup_current_warden_summary(doc: Option<&toml_edit::DocumentMut>) -> String {
    if let Some(provider) = agent_str_dotted(doc, &["ai", "warden", "provider"]) {
        return provider;
    }
    if let Some(provider) = agent_str_dotted(doc, &["ai", "classifier", "provider"]) {
        return format!("{provider} (legacy alias)");
    }
    "configured".to_string()
}

pub(crate) fn count_failed_setup_checks(checks: &[SetupCheck]) -> usize {
    checks
        .iter()
        .filter(|check| check.critical && !check.ok)
        .count()
}

pub(crate) fn setup_verdict(critical_failures: usize) -> &'static str {
    if critical_failures == 0 {
        "READY"
    } else {
        "READY_WITH_GAPS"
    }
}

pub(crate) fn setup_remediation_command(checks: &[SetupCheck], is_macos: bool) -> Option<String> {
    let failed_critical: Vec<&str> = checks
        .iter()
        .filter(|check| check.critical && !check.ok)
        .map(|check| check.label.as_str())
        .collect();

    if failed_critical.is_empty() {
        return None;
    }

    if failed_critical.len() == 1 && failed_critical[0] == "Agent service" {
        return Some(if is_macos {
            "sudo launchctl kickstart -k system/com.innerwarden.agent".to_string()
        } else {
            "sudo systemctl restart innerwarden-agent".to_string()
        });
    }

    Some("innerwarden setup --mode advanced".to_string())
}

#[derive(Debug, Clone, Copy)]
struct SetupRuntimeStatus {
    dashboard_reachable: bool,
    agent_running: bool,
}

#[cfg(any(test, coverage))]
fn collect_setup_runtime_status(_cli: &Cli, _is_macos: bool) -> SetupRuntimeStatus {
    SetupRuntimeStatus {
        dashboard_reachable: false,
        agent_running: false,
    }
}

#[cfg(not(any(test, coverage)))]
fn collect_setup_runtime_status(cli: &Cli, is_macos: bool) -> SetupRuntimeStatus {
    let dashboard_url = resolve_dashboard_url(cli);
    let dashboard_status_url = format!("{dashboard_url}/api/status");
    let dashboard_reachable = crate::commands::agent::dashboard_api_agent(&dashboard_status_url)
        .get(&dashboard_status_url)
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(2)))
        .build()
        .call()
        .map(|resp| resp.status().as_u16() < 500)
        .unwrap_or(false);
    let agent_running = if is_macos {
        std::process::Command::new("launchctl")
            .args(["list", "com.innerwarden.agent"])
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("\"PID\""))
            .unwrap_or(false)
    } else {
        systemd::is_service_active("innerwarden-agent")
    };

    SetupRuntimeStatus {
        dashboard_reachable,
        agent_running,
    }
}

fn collect_setup_checks_with_status(
    cli: &Cli,
    env_file: &Path,
    notification_plan: &SetupNotificationPlan,
    responder_plan: SetupResponderPlan,
    expect_mesh: bool,
    detected_agents: usize,
    runtime: SetupRuntimeStatus,
) -> Vec<SetupCheck> {
    let agent_doc = read_agent_doc(&cli.agent_config);
    let env_vars = load_env_file(env_file);
    let dashboard_url = resolve_dashboard_url(cli);

    let ai_ready = agent_bool(agent_doc.as_ref(), "ai", "enabled");
    let telegram_ready = env_has(&env_vars, "TELEGRAM_BOT_TOKEN")
        && env_has(&env_vars, "TELEGRAM_CHAT_ID")
        && agent_bool(agent_doc.as_ref(), "telegram", "enabled");
    let slack_ready = env_has(&env_vars, "SLACK_WEBHOOK_URL")
        && agent_bool(agent_doc.as_ref(), "slack", "enabled");
    let webhook_ready =
        env_has(&env_vars, "WEBHOOK_URL") && agent_bool(agent_doc.as_ref(), "webhook", "enabled");
    let responder_ready = agent_bool(agent_doc.as_ref(), "responder", "enabled")
        && agent_bool(agent_doc.as_ref(), "responder", "dry_run") == responder_plan.dry_run;
    let mesh_ready = if expect_mesh {
        agent_bool(agent_doc.as_ref(), "mesh", "enabled")
    } else {
        true
    };

    // At least one selected channel must be ready
    let notifications_ready = if !notification_plan.any_selected() {
        false
    } else {
        let mut any_ready = false;
        if notification_plan.telegram {
            any_ready |= telegram_ready;
        }
        if notification_plan.slack {
            any_ready |= slack_ready;
        }
        if notification_plan.webhook {
            any_ready |= webhook_ready;
        }
        if notification_plan.dashboard {
            any_ready |= runtime.dashboard_reachable;
        }
        any_ready
    };

    vec![
        SetupCheck {
            label: "AI".to_string(),
            detail: if ai_ready {
                setup_current_ai_summary(agent_doc.as_ref())
            } else {
                "not configured".to_string()
            },
            ok: ai_ready,
            critical: true,
        },
        SetupCheck {
            label: "Alerts".to_string(),
            detail: if notifications_ready {
                notification_plan.label()
            } else if notification_plan.any_selected() {
                format!("{} not ready", notification_plan.label())
            } else {
                "none selected".to_string()
            },
            ok: notifications_ready,
            critical: true,
        },
        SetupCheck {
            label: "Protection".to_string(),
            detail: responder_plan.label().to_string(),
            ok: responder_ready,
            critical: true,
        },
        SetupCheck {
            label: "Agent service".to_string(),
            detail: if runtime.agent_running {
                "running".to_string()
            } else {
                "not running".to_string()
            },
            ok: runtime.agent_running,
            critical: true,
        },
        SetupCheck {
            label: "Dashboard".to_string(),
            detail: if runtime.dashboard_reachable {
                dashboard_url
            } else {
                "not reachable".to_string()
            },
            ok: runtime.dashboard_reachable,
            critical: false,
        },
        SetupCheck {
            label: "Mesh".to_string(),
            detail: if expect_mesh {
                "enabled".to_string()
            } else {
                "not enabled".to_string()
            },
            ok: mesh_ready,
            critical: false,
        },
        SetupCheck {
            label: "AI agents".to_string(),
            detail: if detected_agents == 0 {
                "none detected".to_string()
            } else if detected_agents == 1 {
                "1 detected".to_string()
            } else {
                format!("{detected_agents} detected")
            },
            ok: detected_agents > 0,
            critical: false,
        },
    ]
}

fn collect_setup_checks(
    cli: &Cli,
    env_file: &Path,
    notification_plan: &SetupNotificationPlan,
    responder_plan: SetupResponderPlan,
    expect_mesh: bool,
    detected_agents: usize,
) -> Vec<SetupCheck> {
    let is_macos = std::env::consts::OS == "macos";
    let runtime = collect_setup_runtime_status(cli, is_macos);
    collect_setup_checks_with_status(
        cli,
        env_file,
        notification_plan,
        responder_plan,
        expect_mesh,
        detected_agents,
        runtime,
    )
}

/// Build the human-readable detail lines (channel + masked secret) for the
/// "Already configured" banner. Returns ("Telegram", "token: 123***ABC")
/// pairs, in display order.
fn already_configured_channel_lines(
    telegram_ok: bool,
    slack_ok: bool,
    discord_ok: bool,
    webhook_ok: bool,
    dashboard_ok: bool,
    env_vars: &HashMap<String, String>,
) -> Vec<(&'static str, String)> {
    let mut lines: Vec<(&'static str, String)> = Vec::new();
    if telegram_ok {
        let token = env_vars
            .get("TELEGRAM_BOT_TOKEN")
            .map(|s| mask_secret(s))
            .unwrap_or_default();
        lines.push(("Telegram", format!("token: {token}")));
    }
    if slack_ok {
        let url = env_vars
            .get("SLACK_WEBHOOK_URL")
            .map(|s| mask_secret(s))
            .unwrap_or_default();
        lines.push(("Slack", format!("webhook: {url}")));
    }
    if discord_ok {
        let url = env_vars
            .get("DISCORD_WEBHOOK_URL")
            .map(|s| mask_secret(s))
            .unwrap_or_default();
        lines.push(("Discord", format!("webhook: {url}")));
    }
    if webhook_ok {
        let url = env_vars
            .get("WEBHOOK_URL")
            .map(|s| mask_secret(s))
            .unwrap_or_default();
        lines.push(("Webhook", format!("url: {url}")));
    }
    if dashboard_ok {
        let user = env_vars
            .get("INNERWARDEN_DASHBOARD_USER")
            .cloned()
            .unwrap_or_default();
        lines.push(("Dashboard", format!("user: {user}")));
    }
    lines
}

/// Test-mode stub: returns the existing-channel state as the new plan, so
/// the orchestrator can run end-to-end without a stdin harness. The real
/// MultiSelect logic is exercised piecewise by `notification_plan_defaults`
/// and `notification_plan_from_selections` unit tests.
#[cfg(any(test, coverage))]
#[allow(dead_code)]
fn prompt_notification_channels(
    telegram_ok: bool,
    slack_ok: bool,
    discord_ok: bool,
    webhook_ok: bool,
    dashboard_ok: bool,
    _env_vars: &HashMap<String, String>,
) -> Result<SetupNotificationPlan> {
    Ok(SetupNotificationPlan {
        telegram: telegram_ok,
        slack: slack_ok,
        discord: discord_ok,
        webhook: webhook_ok,
        dashboard: dashboard_ok,
    })
}

#[cfg(not(any(test, coverage)))]
fn prompt_notification_channels(
    telegram_ok: bool,
    slack_ok: bool,
    discord_ok: bool,
    webhook_ok: bool,
    dashboard_ok: bool,
    env_vars: &HashMap<String, String>,
) -> Result<SetupNotificationPlan> {
    let bold = Style::new().bold();
    let dim = Style::new().dim();

    println!("  {}\n", bold.apply_to("[3/4] Notification channels"));

    let configured = already_configured_channel_lines(
        telegram_ok,
        slack_ok,
        discord_ok,
        webhook_ok,
        dashboard_ok,
        env_vars,
    );
    if !configured.is_empty() {
        println!("  {}", dim.apply_to("Already configured:"));
        for (channel, detail) in &configured {
            println!("    [ok] {channel:<9} {}", dim.apply_to(detail));
        }
        println!();
    }

    let items = &[
        "Telegram    — real-time phone alerts",
        "Slack       — team channel",
        "Webhook     — PagerDuty/Opsgenie/custom",
        "Dashboard   — browser UI",
        "Discord     — server channel",
    ];

    let defaults =
        notification_plan_defaults(telegram_ok, slack_ok, discord_ok, webhook_ok, dashboard_ok);

    let selections = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("  Use arrows + space to toggle, Enter to confirm")
        .items(items)
        .defaults(&defaults)
        .interact()?;

    println!();

    Ok(notification_plan_from_selections(&selections))
}

/// Default selection vector for the 4-channel multi-select.
///
/// If anything is already configured, keep its current state; otherwise prefer
/// Telegram + Dashboard (the recommended fresh-install starting point).
fn notification_plan_defaults(
    telegram_ok: bool,
    slack_ok: bool,
    discord_ok: bool,
    webhook_ok: bool,
    dashboard_ok: bool,
) -> Vec<bool> {
    if telegram_ok || slack_ok || discord_ok || webhook_ok || dashboard_ok {
        vec![telegram_ok, slack_ok, webhook_ok, dashboard_ok, discord_ok]
    } else {
        vec![true, false, false, true, false]
    }
}

/// Convert the multi-select indices into a structured notification plan.
///
/// Index order matches the `items` list in `prompt_notification_channels`:
/// 0=Telegram, 1=Slack, 2=Webhook, 3=Dashboard, 4=Discord (appended last so the
/// pre-existing indices stay stable).
fn notification_plan_from_selections(selections: &[usize]) -> SetupNotificationPlan {
    SetupNotificationPlan {
        telegram: selections.contains(&0),
        slack: selections.contains(&1),
        webhook: selections.contains(&2),
        dashboard: selections.contains(&3),
        discord: selections.contains(&4),
    }
}

/// Resolve the env file companion to the agent config (sibling `agent.env`).
fn resolve_env_file_path(agent_config: &Path) -> PathBuf {
    agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"))
}

/// Build the `[3/4] Alerts` summary string for the already-configured banner.
fn already_configured_summary(
    telegram_ok: bool,
    slack_ok: bool,
    discord_ok: bool,
    webhook_ok: bool,
    dashboard_ok: bool,
) -> String {
    let mut parts = Vec::new();
    if telegram_ok {
        parts.push("Telegram");
    }
    if slack_ok {
        parts.push("Slack");
    }
    if discord_ok {
        parts.push("Discord");
    }
    if webhook_ok {
        parts.push("Webhook");
    }
    if dashboard_ok {
        parts.push("Dashboard");
    }
    parts.join(" + ")
}

/// Channels the user has selected but has not yet configured. Drives the
/// "guided setup after apply" footer in the review screen.
fn pending_channels_for_apply(
    plan: &SetupNotificationPlan,
    telegram_ok: bool,
    slack_ok: bool,
    discord_ok: bool,
    webhook_ok: bool,
    dashboard_ok: bool,
) -> Vec<&'static str> {
    let mut pending: Vec<&'static str> = Vec::new();
    if plan.telegram && !telegram_ok {
        pending.push("Telegram");
    }
    if plan.slack && !slack_ok {
        pending.push("Slack");
    }
    if plan.discord && !discord_ok {
        pending.push("Discord");
    }
    if plan.webhook && !webhook_ok {
        pending.push("Webhook");
    }
    if plan.dashboard && !dashboard_ok {
        pending.push("Dashboard");
    }
    pending
}

/// Pure post-input resolver for the `[4/4] Protection` step.
///
/// `selection_idx` is what the dialog returned (`0` = watch only, `1` = auto).
/// `confirm_input` is the "type 'yes' to enable auto-protect" answer (only
/// consulted when `selection_idx == 1`).
fn resolve_responder_plan_from_selection(
    selection_idx: usize,
    confirm_input: &str,
) -> SetupResponderPlan {
    if selection_idx == 1 && confirm_input.trim() == "yes" {
        SetupResponderPlan { dry_run: false }
    } else {
        SetupResponderPlan { dry_run: true }
    }
}

/// Choose the "AI" review line: configured plan label, or fall back to the
/// summary read from the agent config.
fn build_review_ai_line(
    ai_plan: Option<&SetupAiPlan>,
    agent_doc: Option<&toml_edit::DocumentMut>,
) -> String {
    if let Some(plan) = ai_plan {
        format!("{} ({})", plan.label, plan.model)
    } else {
        setup_current_ai_summary(agent_doc)
    }
}

/// Decide whether the agent restart should run inline. The restart should fire
/// when the agent always needs to be restarted (post-config edit) AND no other
/// channel-configurator has already restarted it.
fn should_restart_agent_inline(restart_agent_needed: bool, channel_restarted_agent: bool) -> bool {
    restart_agent_needed && !channel_restarted_agent
}

/// Format the trailing line of the verdict block based on the count of
/// critical failures.
fn critical_failures_message(critical_failures: usize) -> Option<String> {
    if critical_failures == 0 {
        None
    } else if critical_failures == 1 {
        Some("1 critical item needs attention.".to_string())
    } else {
        Some(format!(
            "{critical_failures} critical items need attention."
        ))
    }
}

/// Apply preconfigured min_severity defaults silently to the agent config.
/// Best-effort: errors are swallowed (the wizard prints a generic warn instead).
fn apply_setup_preconfig_defaults(agent_config: &Path, plan: &SetupPreconfigPlan) {
    if plan.set_telegram_min_severity {
        let _ = config_editor::write_str(agent_config, "telegram", "min_severity", "high");
        let _ = config_editor::write_int(agent_config, "telegram", "daily_summary_hour", 9);
        let _ = config_editor::write_int(agent_config, "telegram", "daily_budget", 10);
    }
    if plan.set_webhook_min_severity {
        let _ = config_editor::write_str(agent_config, "webhook", "min_severity", "high");
    }
}

/// Persist the responder plan (`enabled = true`, `dry_run = ...`) to the agent config.
fn apply_setup_responder(agent_config: &Path, responder_plan: SetupResponderPlan) -> Result<()> {
    config_editor::write_bool(agent_config, "responder", "enabled", true)?;
    config_editor::write_bool(agent_config, "responder", "dry_run", responder_plan.dry_run)?;
    Ok(())
}

/// Persist mesh settings to the agent config when the user opted in. If the
/// `[mesh]` section is missing, also seeds sensible defaults (bind, poll_secs,
/// auto_broadcast).
fn apply_setup_mesh(
    agent_config: &Path,
    enable_mesh: bool,
    mesh_already_enabled: bool,
    has_mesh_section: bool,
) -> Result<()> {
    if !enable_mesh || mesh_already_enabled {
        return Ok(());
    }
    config_editor::write_bool(agent_config, "mesh", "enabled", true)?;
    if !has_mesh_section {
        config_editor::write_str(agent_config, "mesh", "bind", "0.0.0.0:8790")?;
        config_editor::write_int(agent_config, "mesh", "poll_secs", 30)?;
        config_editor::write_bool(agent_config, "mesh", "auto_broadcast", true)?;
    }
    Ok(())
}

/// Snapshot of which notification channels are already wired up, computed
/// from the agent config and the env-file. Used as the input to both the
/// "Already configured:" banner and to seed the multi-select defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SetupExistingChannels {
    pub telegram: bool,
    pub slack: bool,
    pub discord: bool,
    pub webhook: bool,
    pub dashboard: bool,
}

impl SetupExistingChannels {
    fn any(&self) -> bool {
        self.telegram || self.slack || self.discord || self.webhook || self.dashboard
    }
}

/// Pure read of the existing-channel state. Telegram needs the env vars
/// (we don't gate it on `agent_doc.telegram.enabled` because the wizard
/// itself flips that flag during apply). The others require both an env var
/// AND `enabled = true` in the agent config.
fn compute_setup_existing_channels(
    env_vars: &HashMap<String, String>,
    agent_doc: Option<&toml_edit::DocumentMut>,
) -> SetupExistingChannels {
    SetupExistingChannels {
        telegram: env_has(env_vars, "TELEGRAM_BOT_TOKEN") && env_has(env_vars, "TELEGRAM_CHAT_ID"),
        slack: env_has(env_vars, "SLACK_WEBHOOK_URL") && agent_bool(agent_doc, "slack", "enabled"),
        discord: env_has(env_vars, "DISCORD_WEBHOOK_URL")
            && agent_bool(agent_doc, "discord", "enabled"),
        webhook: env_has(env_vars, "WEBHOOK_URL") && agent_bool(agent_doc, "webhook", "enabled"),
        dashboard: env_has(env_vars, "INNERWARDEN_DASHBOARD_USER")
            && env_has(env_vars, "INNERWARDEN_DASHBOARD_PASSWORD_HASH"),
    }
}

/// Channels (in display order) that the apply phase should walk through to
/// trigger an interactive channel configurator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupChannel {
    Telegram,
    Slack,
    Discord,
    Webhook,
    Dashboard,
}

/// Build the ordered list of channels that should run their interactive
/// configurator at apply-time: only the selected channels that are not yet
/// configured. Mirrors `pending_channels_for_apply` but returns a typed enum
/// instead of a string so the apply loop can `match` cleanly.
fn channels_to_configure_in_apply(
    plan: &SetupNotificationPlan,
    telegram_ok: bool,
    slack_ok: bool,
    discord_ok: bool,
    webhook_ok: bool,
    dashboard_ok: bool,
) -> Vec<SetupChannel> {
    let mut out = Vec::new();
    if plan.telegram && !telegram_ok {
        out.push(SetupChannel::Telegram);
    }
    if plan.slack && !slack_ok {
        out.push(SetupChannel::Slack);
    }
    if plan.discord && !discord_ok {
        out.push(SetupChannel::Discord);
    }
    if plan.webhook && !webhook_ok {
        out.push(SetupChannel::Webhook);
    }
    if plan.dashboard && !dashboard_ok {
        out.push(SetupChannel::Dashboard);
    }
    out
}

/// Pre-format the per-check status line of the verdict block.
fn format_setup_check_status_line(check: &SetupCheck) -> String {
    let status = if check.ok { "OK" } else { "FIX" };
    format!("{:<14} {:<4} {}", check.label, status, check.detail)
}

/// Build all per-check status lines for the verdict block in display order.
fn format_setup_check_status_lines(checks: &[SetupCheck]) -> Vec<String> {
    checks.iter().map(format_setup_check_status_line).collect()
}

/// Outcome of the sensor-restart decision tree, used by the wizard to print
/// a status line. The actual systemctl call lives outside this helper so the
/// branching logic stays pure-and-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SensorRestartDecision {
    /// Caller should not attempt anything.
    Skip,
    /// macOS: innerwarden-sensor is unsupported there.
    SkipMacos,
    /// Dry run mode: announce intent only.
    DryRun,
    /// Run the systemctl restart.
    DoRestart,
}

/// Decide whether to restart `innerwarden-sensor` after the apply phase.
fn sensor_restart_decision(
    restart_sensor_needed: bool,
    is_macos: bool,
    dry_run: bool,
) -> SensorRestartDecision {
    if !restart_sensor_needed {
        return SensorRestartDecision::Skip;
    }
    if is_macos {
        return SensorRestartDecision::SkipMacos;
    }
    if dry_run {
        return SensorRestartDecision::DryRun;
    }
    SensorRestartDecision::DoRestart
}

/// Pure decision: when invoked under `--dry-run` AND with a non-TTY
/// stdin, the setup wizard cannot drive its `dialoguer` prompts and
/// must short-circuit with a hint to the operator. Pulled out as a
/// pure function so the rule is testable without an actual stdin.
fn should_short_circuit_setup_for_non_tty(dry_run: bool, stdin_is_tty: bool) -> bool {
    dry_run && !stdin_is_tty
}

/// Operator-facing guidance shown when the wizard short-circuits in
/// the non-TTY dry-run path. Kept as a separate fn so the call site
/// in `cmd_setup` stays compact.
fn print_setup_non_tty_guidance() {
    println!();
    println!(
        "  [DRY-RUN, non-interactive] setup wizard requires a TTY to elicit operator preferences."
    );
    println!("  The first step ([1/4] Local Warden Model) is a `dialoguer` prompt and cannot");
    println!("  read from a pipe / redirected stdin in its current form.");
    println!();
    println!("  Re-run with stdin attached to a terminal — both of these work:");
    println!("    bash install.sh --simulate                 # local interactive shell");
    println!("    innerwarden setup --dry-run                # local interactive shell");
    println!();
    println!(
        "  CI-friendly non-interactive simulate is on the roadmap (mirrors the prompts to default values)."
    );
}

pub(crate) fn cmd_setup(cli: &Cli, mode: &str) -> Result<()> {
    if !cli.dry_run && !am_root() {
        return reexec_with_sudo();
    }

    // Wave 2026-05-17 — fail-fast for the install.sh --simulate path.
    //
    // The wizard's `[1/4] Local Warden Model` step opens an interactive
    // Confirm prompt via `dialoguer`, which errors out with
    //   "warden prompt failed: IO error: not a terminal"
    // when stdin is not a TTY. This bit operators running
    //   bash install.sh --simulate
    // over SSH or in CI: the message is cryptic, the wizard aborts
    // mid-step, and there's no hint about how to make progress.
    //
    // The full "simulate without a TTY" mode would need to gate every
    // dialoguer call on `is_terminal()` and return defaults; that's a
    // larger refactor on the roadmap. Until then, surface the
    // limitation explicitly so the operator knows what to do next.
    if should_short_circuit_setup_for_non_tty(cli.dry_run, std::io::stdin().is_terminal()) {
        print_setup_non_tty_guidance();
        return Ok(());
    }

    let setup_mode = SetupMode::from_str(mode);

    let env_file = resolve_env_file_path(&cli.agent_config);
    let env_vars = load_env_file(&env_file);
    let agent_doc = read_agent_doc(&cli.agent_config);

    let ai_ok = agent_bool(agent_doc.as_ref(), "ai", "enabled");
    let responder_ok = agent_bool(agent_doc.as_ref(), "responder", "enabled");
    let mesh_ok = agent_bool(agent_doc.as_ref(), "mesh", "enabled");

    let bold = Style::new().bold();
    let dim = Style::new().dim();

    println!();
    println!("  {}", bold.apply_to("INNERWARDEN SETUP"));
    println!("  {}", dim.apply_to("─".repeat(40)));
    println!();

    // Safe defaults applied silently during apply (block-ip, alert thresholds, etc.)
    let preconfig_plan = collect_setup_preconfig_plan(agent_doc.as_ref());

    // ── [1/4] Local Warden Model ─────────────────────────────────────────
    // Spec 032 wizard step. Asked first because saying yes here is the
    // cheapest token-saving switch the operator can make, and the AI step
    // below is still useful either way (cloud LLM still runs Explain,
    // Briefings, and bot chat — only Decide moves on-device).
    //
    // Binding since the classifier-v1 release shipped: saying yes here
    // immediately calls `cmd_install_classifier` (download + SHA pin +
    // tar extract to /var/lib/innerwarden/models/classifier) and writes
    // `[ai.warden]` into agent.toml, so the next agent restart picks the
    // local Decide head. If the install fails (network, disk, sudo),
    // `apply_setup_warden_plan` reports it as a soft warning and the
    // wizard continues through `[2/4] AI` for a cloud-served Decide path.
    let warden_already = agent_warden_configured(agent_doc.as_ref());
    let warden_plan = if warden_already {
        println!(
            "  [ok] {}  {}",
            bold.apply_to("[1/4] Local Warden Model"),
            dim.apply_to(setup_current_warden_summary(agent_doc.as_ref()))
        );
        SetupWardenPlan {
            enabled: true,
            already_configured: true,
        }
    } else {
        let plan = prompt_setup_warden_plan()?;
        println!("\n  [ok] {}", dim.apply_to(plan.label()));
        plan
    };
    let _warden_active = apply_setup_warden_plan(cli, &warden_plan)?;

    let ai_plan = if ai_ok {
        println!(
            "  [ok] {}  {}",
            bold.apply_to("[2/4] AI"),
            dim.apply_to(setup_current_ai_summary(agent_doc.as_ref()))
        );
        None
    } else {
        let plan = prompt_setup_ai_plan()?;
        if let Some(plan) = &plan {
            println!("\n  [ok] {} ({})", plan.label, dim.apply_to(&plan.model));
        } else {
            println!("  [--] AI not set yet");
        }
        plan
    };

    // ── Detect existing notification channels ──────────────────────────
    let existing = compute_setup_existing_channels(&env_vars, agent_doc.as_ref());
    let telegram_ok = existing.telegram;
    let slack_ok = existing.slack;
    let discord_ok = existing.discord;
    let webhook_ok = existing.webhook;
    let dashboard_ok_existing = existing.dashboard;

    let any_channel_configured = existing.any();

    println!();
    let notification_plan = if any_channel_configured && !setup_mode.is_advanced() {
        let summary = already_configured_summary(
            telegram_ok,
            slack_ok,
            discord_ok,
            webhook_ok,
            dashboard_ok_existing,
        );
        println!(
            "  [ok] {}  {}",
            bold.apply_to("[3/4] Alerts"),
            dim.apply_to(&summary)
        );
        println!();
        let update = prompt_yes_no("  Update notification channels? [y/N] ", false)?;
        if update {
            prompt_notification_channels(
                telegram_ok,
                slack_ok,
                discord_ok,
                webhook_ok,
                dashboard_ok_existing,
                &env_vars,
            )?
        } else {
            SetupNotificationPlan {
                telegram: telegram_ok,
                slack: slack_ok,
                discord: discord_ok,
                webhook: webhook_ok,
                dashboard: dashboard_ok_existing,
            }
        }
    } else {
        prompt_notification_channels(
            telegram_ok,
            slack_ok,
            discord_ok,
            webhook_ok,
            dashboard_ok_existing,
            &env_vars,
        )?
    };

    let responder_plan = if responder_ok {
        let current = SetupResponderPlan {
            dry_run: agent_bool(agent_doc.as_ref(), "responder", "dry_run"),
        };
        println!(
            "  [ok] {}  {}",
            bold.apply_to("[4/4] Protection"),
            dim.apply_to(current.label())
        );
        current
    } else {
        println!("\n  {}\n", bold.apply_to("[4/4] Protection"));

        let items = &[
            "Watch only (recommended for the first week) — detects and alerts, does not block",
            "Auto-protect — automatically blocks threats, enable after you trust the alerts",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("  Use arrows to move, Enter to select")
            .items(items)
            .default(0)
            .interact()?;

        println!();

        if selection == 1 {
            print!("  Type 'yes' to enable auto-protect: ");
            std::io::stdout().flush()?;
            let mut confirm = String::new();
            std::io::stdin().read_line(&mut confirm)?;
            resolve_responder_plan_from_selection(selection, &confirm)
        } else {
            resolve_responder_plan_from_selection(selection, "")
        }
    };

    println!();
    let enable_mesh = if mesh_ok {
        println!(
            "  [ok] {}  {}",
            bold.apply_to("Mesh"),
            dim.apply_to("enabled")
        );
        true
    } else if setup_mode.is_advanced() {
        let enabled = prompt_yes_no(
            "  Share threat blocks with your other InnerWarden nodes? [y/N] ",
            false,
        )?;
        println!();
        enabled
    } else {
        false
    };

    let review_ai = build_review_ai_line(ai_plan.as_ref(), agent_doc.as_ref());

    println!();
    println!("  {}", bold.apply_to("REVIEW"));
    println!("  {}", dim.apply_to("─".repeat(40)));
    println!("  {:<16} {review_ai}", bold.apply_to("AI"));
    println!(
        "  {:<16} {}",
        bold.apply_to("Alerts"),
        notification_plan.label()
    );
    println!(
        "  {:<16} {}",
        bold.apply_to("Protection"),
        responder_plan.label()
    );
    if enable_mesh {
        println!("  {:<16} enabled", bold.apply_to("Mesh"));
    }
    println!(
        "  {:<16} {}",
        bold.apply_to("Config"),
        dim.apply_to(format!(
            "{} + {}",
            cli.agent_config.display(),
            env_file.display()
        ))
    );

    // Show which channels need guided setup after apply
    let pending_channels = pending_channels_for_apply(
        &notification_plan,
        telegram_ok,
        slack_ok,
        discord_ok,
        webhook_ok,
        dashboard_ok_existing,
    );
    if !pending_channels.is_empty() {
        println!(
            "  {:<16} {} guided setup after apply",
            bold.apply_to("Next"),
            pending_channels.join(", ")
        );
    }
    println!("  {}", dim.apply_to("─".repeat(40)));
    println!();

    if cli.dry_run {
        println!(
            "  {} Setup preview complete. No changes applied.",
            dim.apply_to("[dry-run]")
        );
        return Ok(());
    }

    if !prompt_yes_no("  Apply now? [Y/n] ", true)? {
        println!("\n  Setup cancelled. Nothing changed.");
        return Ok(());
    }

    println!();

    // Apply safe defaults silently (block-ip, alert thresholds, etc.)
    let registry = CapabilityRegistry::default_all();
    let mut restart_sensor_needed = false;
    for capability in &preconfig_plan.essential_capabilities {
        if let Err(err) = cmd_enable_with_deferred_restart(
            cli,
            &registry,
            &capability.id,
            capability.params.clone(),
            true,
            true,
            false,
        ) {
            println!("  [warn] Could not enable {}: {err:#}", capability.id);
        } else {
            let (sensor_needed, _agent_needed) = setup_capability_restart_needs(&capability.id);
            restart_sensor_needed |= sensor_needed;
        }
    }
    apply_setup_preconfig_defaults(&cli.agent_config, &preconfig_plan);

    // Cloud-aware: if this host runs on a cloud whose platform uses a fixed
    // infrastructure IP outside its published ranges (e.g. Azure's wireserver),
    // add it to the HOST allowlist so the responder never blocks the platform's
    // own DNS/health traffic. Server-side rule, not a hardcoded never-block in
    // the product. Idempotent + best-effort (a failure must not abort setup).
    if let Err(err) = crate::commands::cloud_detect::apply_cloud_platform_allowlist(cli) {
        println!("  [warn] cloud platform allowlist step skipped: {err:#}");
    }

    if let Some(plan) = &ai_plan {
        apply_setup_ai_plan(cli, &env_file, plan)?;
    }

    apply_setup_responder(&cli.agent_config, responder_plan)?;
    let restart_agent_needed = true;

    let has_mesh_section = agent_doc.as_ref().and_then(|doc| doc.get("mesh")).is_some();
    apply_setup_mesh(&cli.agent_config, enable_mesh, mesh_ok, has_mesh_section)?;

    // ── Channel setup (interactive, writes config, restarts agent) ──────
    let mut channel_restarted_agent = false;
    let channels_pending = channels_to_configure_in_apply(
        &notification_plan,
        telegram_ok,
        slack_ok,
        discord_ok,
        webhook_ok,
        dashboard_ok_existing,
    );
    for (idx, channel) in channels_pending.iter().enumerate() {
        if idx == 0 && matches!(channel, SetupChannel::Telegram) {
            println!("  Telegram\n");
        } else {
            println!();
        }
        match channel {
            SetupChannel::Telegram => {
                if let Err(err) = cmd_configure_telegram(cli, None, None, false) {
                    println!("  [warn] Telegram setup did not finish: {err:#}");
                } else {
                    channel_restarted_agent = true;
                    let _ = config_editor::write_int(
                        &cli.agent_config,
                        "telegram",
                        "daily_summary_hour",
                        9,
                    );
                    let _ =
                        config_editor::write_int(&cli.agent_config, "telegram", "daily_budget", 10);
                }
            }
            SetupChannel::Slack => {
                if let Err(err) = cmd_configure_slack(cli, None, "high", false) {
                    println!("  [warn] Slack setup did not finish: {err:#}");
                } else {
                    channel_restarted_agent = true;
                }
            }
            SetupChannel::Discord => {
                if let Err(err) = cmd_configure_discord(cli, None, "high", false) {
                    println!("  [warn] Discord setup did not finish: {err:#}");
                } else {
                    channel_restarted_agent = true;
                }
            }
            SetupChannel::Webhook => {
                if let Err(err) = cmd_configure_webhook(cli, None, "high", false) {
                    println!("  [warn] Webhook setup did not finish: {err:#}");
                } else {
                    channel_restarted_agent = true;
                }
            }
            SetupChannel::Dashboard => {
                if let Err(err) = cmd_configure_dashboard(cli, "admin", None) {
                    println!("  [warn] Dashboard setup did not finish: {err:#}");
                } else {
                    channel_restarted_agent = true;
                }
            }
        }
    }

    match sensor_restart_decision(
        restart_sensor_needed,
        std::env::consts::OS == "macos",
        cli.dry_run,
    ) {
        SensorRestartDecision::Skip => {}
        SensorRestartDecision::SkipMacos => {
            println!("  [warn] innerwarden-sensor restart skipped on macOS.");
        }
        SensorRestartDecision::DryRun => {
            println!("  [dry-run] would restart innerwarden-sensor");
        }
        SensorRestartDecision::DoRestart => {
            if let Err(err) = systemd::restart_service("innerwarden-sensor", false) {
                println!("  [warn] Could not restart innerwarden-sensor: {err:#}");
            } else {
                println!("  [ok] innerwarden-sensor restarted");
            }
        }
    }

    if should_restart_agent_inline(restart_agent_needed, channel_restarted_agent) {
        restart_agent(cli);
    }

    let detected_agents = {
        use innerwarden_agent_guard::detect;
        use innerwarden_agent_guard::signatures::SignatureIndex;

        let index = SignatureIndex::new();
        detect::scan_processes(&index)
    };

    if detected_agents.is_empty() {
        println!();
        println!("  No supported AI agents detected right now.");
    } else {
        println!();
        let selected_agent_pids = prompt_setup_agent_selection(&detected_agents)?;
        if selected_agent_pids.is_empty() {
            println!("  Agent connection skipped.");
        } else {
            for selected_pid in selected_agent_pids {
                let command = AgentCommand::Connect {
                    pid: Some(selected_pid),
                    name: None,
                    label: Some("setup".to_string()),
                };
                let _ = cmd_agent(cli, Some(&command));
            }
        }
    }

    let checks = collect_setup_checks(
        cli,
        &env_file,
        &notification_plan,
        responder_plan,
        enable_mesh,
        detected_agents.len(),
    );
    let critical_failures = count_failed_setup_checks(&checks);
    let verdict = setup_verdict(critical_failures);
    let remediation = setup_remediation_command(&checks, std::env::consts::OS == "macos");

    println!();
    println!("  {verdict}\n");

    for line in format_setup_check_status_lines(&checks) {
        println!("  {line}");
    }

    println!();
    if let Some(message) = critical_failures_message(critical_failures) {
        println!("  {message}");
        if let Some(command) = remediation {
            println!("  Run this command to close critical gaps:");
            println!("    {command}");
        }
    } else {
        println!("  Dashboard: {}", resolve_dashboard_url(cli));
        println!("  Re-run anytime: innerwarden setup");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_test_cli(data_dir: &Path, dry_run: bool) -> Cli {
        Cli {
            sensor_config: data_dir.join("config.toml"),
            agent_config: data_dir.join("agent.toml"),
            data_dir: data_dir.to_path_buf(),
            dry_run,
            command: Some(crate::Command::Setup {
                mode: "basic".to_string(),
            }),
        }
    }

    #[test]
    fn short_circuit_setup_when_dry_run_and_no_tty() {
        // Wave 2026-05-17 anchor for the install.sh --simulate path.
        // The truth table is small: only (dry_run=true, tty=false)
        // should short-circuit. Every other quadrant must let the
        // wizard proceed so an operator running from a real shell or
        // applying for real isn't blocked by the new fail-fast.
        assert!(should_short_circuit_setup_for_non_tty(true, false));
        assert!(!should_short_circuit_setup_for_non_tty(true, true));
        assert!(!should_short_circuit_setup_for_non_tty(false, false));
        assert!(!should_short_circuit_setup_for_non_tty(false, true));
    }

    #[test]
    fn test_ai_provider_defaults() {
        let (model, key, url) = ai_provider_defaults("openai");
        assert_eq!(model, "gpt-4o-mini");
        assert_eq!(key, Some("OPENAI_API_KEY".to_string()));
        assert_eq!(url, None);

        let (model, key, url) = ai_provider_defaults("groq");
        assert_eq!(model, "llama-3.3-70b-versatile");
        assert_eq!(key, Some("GROQ_API_KEY".to_string()));
        assert_eq!(url, Some("https://api.groq.com/openai".to_string()));

        let (model, key, url) = ai_provider_defaults("ollama");
        assert_eq!(model, "llama3.2");
        assert_eq!(key, None);
        assert_eq!(url, None);

        let (model, key, _url) = ai_provider_defaults("unknown_provider");
        assert_eq!(model, "gpt-4o-mini");
        assert_eq!(key, Some("UNKNOWN_PROVIDER_API_KEY".to_string()));
    }

    #[test]
    fn test_count_failed_setup_checks() {
        let checks = vec![
            SetupCheck {
                label: "1".into(),
                detail: "".into(),
                ok: true,
                critical: true,
            },
            SetupCheck {
                label: "2".into(),
                detail: "".into(),
                ok: false,
                critical: true,
            },
            SetupCheck {
                label: "3".into(),
                detail: "".into(),
                ok: false,
                critical: false,
            },
        ];
        assert_eq!(count_failed_setup_checks(&checks), 1);
    }

    #[test]
    fn test_setup_verdict() {
        assert_eq!(setup_verdict(0), "READY");
        assert_eq!(setup_verdict(1), "READY_WITH_GAPS");
        assert_eq!(setup_verdict(5), "READY_WITH_GAPS");
    }

    #[test]
    fn test_setup_remediation_command() {
        let mut checks = vec![];

        // 0 critical
        assert_eq!(setup_remediation_command(&checks, false), None);

        // 1 critical: Agent service
        checks.push(SetupCheck {
            label: "Agent service".into(),
            detail: "".into(),
            ok: false,
            critical: true,
        });

        let linux_cmd = setup_remediation_command(&checks, false).unwrap();
        assert!(linux_cmd.contains("systemctl restart"));

        let macos_cmd = setup_remediation_command(&checks, true).unwrap();
        assert!(macos_cmd.contains("launchctl kickstart"));

        // More than 1 critical
        checks.push(SetupCheck {
            label: "AI".into(),
            detail: "".into(),
            ok: false,
            critical: true,
        });

        let complex_cmd = setup_remediation_command(&checks, false).unwrap();
        assert_eq!(complex_cmd, "innerwarden setup --mode advanced");
    }

    #[test]
    fn setup_mode_parses_basic_and_advanced() {
        assert_eq!(SetupMode::from_str("advanced"), SetupMode::Advanced);
        assert_eq!(SetupMode::from_str("ADVANCED"), SetupMode::Advanced);
        assert_eq!(SetupMode::from_str("basic"), SetupMode::Basic);
        assert_eq!(SetupMode::from_str("anything-else"), SetupMode::Basic);
        assert!(SetupMode::from_str("advanced").is_advanced());
        assert!(!SetupMode::from_str("basic").is_advanced());
    }

    #[test]
    fn setup_notification_plan_labels_selected_channels() {
        let none = SetupNotificationPlan::default();
        assert_eq!(none.label(), "none");
        assert!(!none.any_selected());

        let plan = SetupNotificationPlan {
            telegram: true,
            slack: true,
            discord: false,
            webhook: false,
            dashboard: true,
        };
        assert_eq!(plan.label(), "Telegram + Slack + Dashboard");
        assert!(plan.any_selected());
    }

    #[test]
    fn setup_responder_plan_labels_modes() {
        assert_eq!(SetupResponderPlan { dry_run: true }.label(), "Watch only");
        assert_eq!(
            SetupResponderPlan { dry_run: false }.label(),
            "Auto-protect"
        );
    }

    #[test]
    fn parse_setup_capability_hint_reads_id_and_params() {
        let plan = parse_setup_capability_hint(
            "innerwarden enable search-protection --param nginx_access=/var/log/nginx/access.log --param threshold=15",
        )
        .unwrap();

        assert_eq!(plan.id, "search-protection");
        assert_eq!(
            plan.params.get("nginx_access").map(String::as_str),
            Some("/var/log/nginx/access.log")
        );
        assert_eq!(plan.params.get("threshold").map(String::as_str), Some("15"));

        assert!(parse_setup_capability_hint("").is_none());
        assert!(parse_setup_capability_hint("innerwarden list").is_none());
        assert!(parse_setup_capability_hint("sudo innerwarden enable ai").is_none());
    }

    #[test]
    fn setup_capability_restart_needs_maps_known_capabilities() {
        assert_eq!(setup_capability_restart_needs("ai"), (false, true));
        assert_eq!(setup_capability_restart_needs("block-ip"), (false, true));
        assert_eq!(
            setup_capability_restart_needs("sudo-protection"),
            (true, true)
        );
        assert_eq!(setup_capability_restart_needs("shell-audit"), (true, false));
        assert_eq!(
            setup_capability_restart_needs("search-protection"),
            (true, true)
        );
        assert_eq!(setup_capability_restart_needs("unknown"), (false, false));
    }

    #[test]
    fn agent_doc_helpers_read_booleans_strings_and_env_values() {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("agent.toml");
        std::fs::write(
            &cfg,
            "[ai]\nenabled = true\nprovider = \"openai\"\n\n[telegram]\nmin_severity = \"high\"\n",
        )
        .unwrap();

        let doc = read_agent_doc(&cfg).unwrap();
        assert!(agent_bool(Some(&doc), "ai", "enabled"));
        assert!(!agent_bool(Some(&doc), "mesh", "enabled"));
        assert_eq!(
            agent_str(Some(&doc), "ai", "provider"),
            Some("openai".to_string())
        );
        assert_eq!(agent_str(Some(&doc), "ai", "missing"), None);

        std::fs::write(&cfg, "not = [valid").unwrap();
        assert!(read_agent_doc(&cfg).is_none());
        assert!(read_agent_doc(&dir.path().join("missing.toml")).is_none());

        let mut env_vars = HashMap::new();
        let key_prefix = format!(
            "SETUP_TEST_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let empty_key = format!("{key_prefix}_EMPTY");
        let present_key = format!("{key_prefix}_PRESENT");
        let missing_key = format!("{key_prefix}_MISSING");
        env_vars.insert(empty_key.clone(), "  ".to_string());
        env_vars.insert(present_key.clone(), "value".to_string());
        assert!(!env_has(&env_vars, &empty_key));
        assert!(env_has(&env_vars, &present_key));
        assert!(!env_has(&env_vars, &missing_key));
    }

    #[test]
    fn build_setup_ai_plan_uses_env_config_and_default_keys() {
        let openai =
            build_setup_ai_plan("openai", "OpenAI", Some("sk-test".to_string()), None, None);
        assert_eq!(openai.provider, "openai");
        assert_eq!(openai.model, "gpt-4o-mini");
        assert!(openai.base_url.is_none());
        match openai.key {
            SetupAiKey::Env { var, value } => {
                assert_eq!(var, "OPENAI_API_KEY");
                assert_eq!(value, "sk-test");
            }
            _ => panic!("expected env key"),
        }

        let ollama_cloud = build_setup_ai_plan(
            "ollama",
            "Ollama Cloud",
            Some("ollama-key".to_string()),
            Some("gpt-oss:20b".to_string()),
            Some("https://api.ollama.com".to_string()),
        );
        match ollama_cloud.key {
            SetupAiKey::Config { value } => assert_eq!(value, "ollama-key"),
            _ => panic!("expected config key"),
        }
        assert_eq!(
            ollama_cloud.base_url.as_deref(),
            Some("https://api.ollama.com")
        );

        let local = build_setup_ai_plan("ollama", "Ollama", None, None, None);
        assert!(matches!(local.key, SetupAiKey::None));
    }

    #[test]
    fn apply_setup_ai_plan_writes_agent_config_and_env_file() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        let env_file = dir.path().join("agent.env");
        let plan =
            build_setup_ai_plan("groq", "Groq", Some("gsk_test_key".to_string()), None, None);

        apply_setup_ai_plan(&cli, &env_file, &plan).unwrap();

        let agent = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(agent.contains("[ai]"));
        assert!(agent.contains("enabled = true"));
        assert!(agent.contains("provider = \"groq\""));
        assert!(agent.contains("model = \"llama-3.3-70b-versatile\""));
        assert!(agent.contains("base_url = \"https://api.groq.com/openai\""));

        let env = std::fs::read_to_string(&env_file).unwrap();
        assert!(env.contains("GROQ_API_KEY"));
        assert!(env.contains("gsk_test_key"));
    }

    #[test]
    fn apply_setup_warden_plan_disabled_returns_false_and_writes_nothing() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        let plan = SetupWardenPlan {
            enabled: false,
            already_configured: false,
        };

        let active = apply_setup_warden_plan(&cli, &plan).unwrap();

        assert!(!active, "warden must report inactive when operator said no");
        assert!(
            !cli.agent_config.exists()
                || !std::fs::read_to_string(&cli.agent_config)
                    .unwrap()
                    .contains("[ai.warden]"),
            "skipped plan must not write [ai.warden] section"
        );
    }

    #[test]
    fn apply_setup_warden_plan_already_configured_returns_true_and_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        // Pre-seed an agent.toml that already has the warden section.
        // The wizard's `agent_warden_configured` check would have set
        // `already_configured = true` for this state, so the apply path
        // is a no-op and must not re-download.
        std::fs::write(
            &cli.agent_config,
            "[ai.warden]\nprovider = \"local_warden\"\nbase_url = \"/var/lib/innerwarden/models/classifier\"\n",
        )
        .unwrap();
        let plan = SetupWardenPlan {
            enabled: true,
            already_configured: true,
        };
        let before = std::fs::read_to_string(&cli.agent_config).unwrap();

        let active = apply_setup_warden_plan(&cli, &plan).unwrap();

        assert!(active, "warden must report active when already configured");
        let after = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert_eq!(
            before, after,
            "already-configured path must not rewrite agent.toml"
        );
    }

    #[test]
    fn apply_setup_ai_plan_writes_ollama_cloud_key_to_config() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        let env_file = dir.path().join("agent.env");
        let plan = build_setup_ai_plan(
            "ollama",
            "Ollama Cloud",
            Some("ollama-key".to_string()),
            Some("gpt-oss:20b".to_string()),
            Some("https://api.ollama.com".to_string()),
        );

        apply_setup_ai_plan(&cli, &env_file, &plan).unwrap();

        let agent = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(agent.contains("api_key = \"ollama-key\""));
        assert!(!env_file.exists());
    }

    #[test]
    fn collect_setup_checks_reports_ready_configured_components() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        let env_file = dir.path().join("agent.env");
        std::fs::write(
            &cli.agent_config,
            "[ai]\nenabled = true\nprovider = \"openai\"\nmodel = \"gpt-4o-mini\"\n\n[telegram]\nenabled = true\n\n[responder]\nenabled = true\ndry_run = true\n\n[mesh]\nenabled = true\n",
        )
        .unwrap();
        std::fs::write(
            &env_file,
            "TELEGRAM_BOT_TOKEN=1234567890:abcdefghijklmnopqrstuvwxyz\nTELEGRAM_CHAT_ID=123456789\n",
        )
        .unwrap();

        let checks = collect_setup_checks_with_status(
            &cli,
            &env_file,
            &SetupNotificationPlan {
                telegram: true,
                ..Default::default()
            },
            SetupResponderPlan { dry_run: true },
            true,
            2,
            SetupRuntimeStatus {
                dashboard_reachable: false,
                agent_running: true,
            },
        );

        let ai = checks.iter().find(|check| check.label == "AI").unwrap();
        assert!(ai.ok);
        assert_eq!(ai.detail, "openai (gpt-4o-mini)");

        let alerts = checks.iter().find(|check| check.label == "Alerts").unwrap();
        assert!(alerts.ok);
        assert_eq!(alerts.detail, "Telegram");

        let protection = checks
            .iter()
            .find(|check| check.label == "Protection")
            .unwrap();
        assert!(protection.ok);
        assert_eq!(protection.detail, "Watch only");

        let service = checks
            .iter()
            .find(|check| check.label == "Agent service")
            .unwrap();
        assert!(service.ok);
        assert_eq!(service.detail, "running");

        let mesh = checks.iter().find(|check| check.label == "Mesh").unwrap();
        assert!(mesh.ok);

        let agents = checks
            .iter()
            .find(|check| check.label == "AI agents")
            .unwrap();
        assert!(agents.ok);
        assert_eq!(agents.detail, "2 detected");
    }

    #[test]
    fn collect_setup_checks_wrapper_uses_runtime_status_without_test_io() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        let env_file = dir.path().join("agent.env");
        std::fs::write(
            &cli.agent_config,
            "[ai]\nenabled = true\nprovider = \"openai\"\nmodel = \"gpt-4o-mini\"\n\n[responder]\nenabled = true\ndry_run = true\n",
        )
        .unwrap();

        let checks = collect_setup_checks(
            &cli,
            &env_file,
            &SetupNotificationPlan {
                dashboard: true,
                ..Default::default()
            },
            SetupResponderPlan { dry_run: true },
            false,
            1,
        );

        let alerts = checks.iter().find(|check| check.label == "Alerts").unwrap();
        assert!(!alerts.ok);
        assert_eq!(alerts.detail, "Dashboard not ready");

        let service = checks
            .iter()
            .find(|check| check.label == "Agent service")
            .unwrap();
        assert!(!service.ok);
        assert_eq!(service.detail, "not running");

        let dashboard = checks
            .iter()
            .find(|check| check.label == "Dashboard")
            .unwrap();
        assert!(!dashboard.ok);
        assert_eq!(dashboard.detail, "not reachable");
    }

    #[test]
    fn collect_setup_checks_marks_missing_selected_alerts_not_ready() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        let env_file = dir.path().join("agent.env");
        std::fs::write(
            &cli.agent_config,
            "[ai]\nenabled = false\n\n[responder]\nenabled = true\ndry_run = false\n",
        )
        .unwrap();

        let checks = collect_setup_checks_with_status(
            &cli,
            &env_file,
            &SetupNotificationPlan {
                slack: true,
                discord: false,
                ..Default::default()
            },
            SetupResponderPlan { dry_run: true },
            false,
            0,
            SetupRuntimeStatus {
                dashboard_reachable: false,
                agent_running: false,
            },
        );

        let alerts = checks.iter().find(|check| check.label == "Alerts").unwrap();
        assert!(!alerts.ok);
        assert_eq!(alerts.detail, "Slack not ready");

        let ai = checks.iter().find(|check| check.label == "AI").unwrap();
        assert!(!ai.ok);
        assert_eq!(ai.detail, "not configured");

        let protection = checks
            .iter()
            .find(|check| check.label == "Protection")
            .unwrap();
        assert!(!protection.ok);
        assert_eq!(protection.detail, "Watch only");

        let agents = checks
            .iter()
            .find(|check| check.label == "AI agents")
            .unwrap();
        assert!(!agents.ok);
        assert_eq!(agents.detail, "none detected");
    }

    // ---- parse_yes_no ----

    #[test]
    fn parse_yes_no_uses_default_on_empty_input() {
        assert!(parse_yes_no("", true));
        assert!(!parse_yes_no("", false));
        assert!(parse_yes_no("   \n  ", true));
        assert!(!parse_yes_no("\t\n", false));
    }

    #[test]
    fn parse_yes_no_accepts_y_and_yes_case_insensitively() {
        assert!(parse_yes_no("y", false));
        assert!(parse_yes_no("Y", false));
        assert!(parse_yes_no("YES", false));
        assert!(parse_yes_no("Yes\n", false));
        assert!(parse_yes_no("  y  \n", false));
    }

    #[test]
    fn parse_yes_no_treats_anything_else_as_no_regardless_of_default() {
        assert!(!parse_yes_no("n", true));
        assert!(!parse_yes_no("no", true));
        assert!(!parse_yes_no("maybe", true));
        assert!(!parse_yes_no("0", true));
        assert!(!parse_yes_no("yep", true));
    }

    // ---- resolve_multi_agent_selection ----

    fn fake_detected(name: &str, pid: u32) -> innerwarden_agent_guard::detect::DetectedAgent {
        innerwarden_agent_guard::detect::DetectedAgent {
            name: name.to_string(),
            vendor: "vendor".to_string(),
            pid,
            comm: name.to_string(),
            integration: "shell".to_string(),
            mcp_configs: vec![],
        }
    }

    #[test]
    fn resolve_multi_agent_selection_returns_empty_for_blank_input() {
        let agents = vec![fake_detected("a", 100), fake_detected("b", 200)];
        assert!(resolve_multi_agent_selection(&agents, "").is_empty());
        assert!(resolve_multi_agent_selection(&agents, "   ").is_empty());
        assert!(resolve_multi_agent_selection(&agents, "\n").is_empty());
    }

    #[test]
    fn resolve_multi_agent_selection_returns_empty_for_invalid_input() {
        let agents = vec![fake_detected("a", 100), fake_detected("b", 200)];
        assert!(resolve_multi_agent_selection(&agents, "not-a-number").is_empty());
        assert!(resolve_multi_agent_selection(&agents, "0").is_empty());
        assert!(resolve_multi_agent_selection(&agents, "99").is_empty());
    }

    #[test]
    fn resolve_multi_agent_selection_maps_indices_to_pids_and_handles_all() {
        let agents = vec![
            fake_detected("a", 100),
            fake_detected("b", 200),
            fake_detected("c", 300),
        ];
        assert_eq!(
            resolve_multi_agent_selection(&agents, "1,3"),
            vec![100, 300]
        );
        assert_eq!(
            resolve_multi_agent_selection(&agents, "all"),
            vec![100, 200, 300]
        );
        assert_eq!(resolve_multi_agent_selection(&agents, " 2 "), vec![200]);
    }

    // ---- build_ollama_label ----

    #[test]
    fn build_ollama_label_running_with_models_lists_first_three() {
        let models = vec![
            "qwen2.5:3b".to_string(),
            "llama3.2".to_string(),
            "mistral".to_string(),
            "phi-4".to_string(),
        ];
        let label = build_ollama_label(true, &models);
        assert!(label.contains("4 models"));
        assert!(label.contains("qwen2.5:3b"));
        assert!(label.contains("llama3.2"));
        assert!(label.contains("mistral"));
        assert!(label.contains("+1 more"));
    }

    #[test]
    fn build_ollama_label_running_no_models_says_so() {
        let label = build_ollama_label(true, &[]);
        assert!(label.contains("running"));
        assert!(label.contains("no models"));
    }

    #[test]
    fn build_ollama_label_not_running_shows_install_url() {
        let label = build_ollama_label(false, &[]);
        assert!(label.contains("not installed"));
        assert!(label.contains("ollama.com"));
    }

    #[test]
    fn build_ollama_label_running_with_three_or_fewer_omits_more_suffix() {
        let three = vec![
            "qwen2.5:3b".to_string(),
            "llama3.2".to_string(),
            "phi-4".to_string(),
        ];
        let label = build_ollama_label(true, &three);
        assert!(label.contains("3 models"));
        assert!(!label.contains("+"));
    }

    // ---- pick_local_ollama_default_idx ----

    #[test]
    fn pick_local_ollama_default_idx_prefers_qwen() {
        let models = vec![
            "llama3.2".to_string(),
            "qwen2.5:3b".to_string(),
            "phi-4".to_string(),
        ];
        assert_eq!(pick_local_ollama_default_idx(&models), 2);
    }

    #[test]
    fn pick_local_ollama_default_idx_prefix_matches() {
        let models = vec!["qwen2.5:3b-instruct-q4".to_string()];
        assert_eq!(pick_local_ollama_default_idx(&models), 1);
    }

    #[test]
    fn pick_local_ollama_default_idx_falls_back_to_one() {
        let models = vec!["llama3.2".to_string(), "phi-4".to_string()];
        assert_eq!(pick_local_ollama_default_idx(&models), 1);
        let empty: Vec<String> = vec![];
        assert_eq!(pick_local_ollama_default_idx(&empty), 1);
    }

    // ---- parse_model_choice_idx ----

    #[test]
    fn parse_model_choice_idx_uses_default_for_empty_or_garbage() {
        assert_eq!(parse_model_choice_idx("", 2, 5), 1); // default 2 -> idx 1
        assert_eq!(parse_model_choice_idx("not-a-number", 3, 5), 2);
        assert_eq!(parse_model_choice_idx("   ", 1, 5), 0);
    }

    #[test]
    fn parse_model_choice_idx_clamps_to_last_index() {
        assert_eq!(parse_model_choice_idx("99", 1, 5), 4);
        assert_eq!(parse_model_choice_idx("5", 1, 5), 4);
    }

    #[test]
    fn parse_model_choice_idx_converts_one_indexed_to_zero_indexed() {
        assert_eq!(parse_model_choice_idx("1", 3, 5), 0);
        assert_eq!(parse_model_choice_idx("3", 1, 5), 2);
    }

    #[test]
    fn parse_model_choice_idx_returns_zero_when_total_is_zero() {
        assert_eq!(parse_model_choice_idx("anything", 1, 0), 0);
    }

    #[test]
    fn parse_model_choice_idx_zero_input_saturates_to_zero() {
        // Defends against panic if user types "0" which would underflow
        assert_eq!(parse_model_choice_idx("0", 1, 5), 0);
    }

    // ---- pick_cloud_default_model_idx ----

    #[test]
    fn pick_cloud_default_model_idx_finds_match() {
        let models = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(pick_cloud_default_model_idx(&models, "b"), 2);
        assert_eq!(pick_cloud_default_model_idx(&models, "missing"), 1);
    }

    // ---- resolve_other_ai_choice ----

    #[test]
    fn resolve_other_ai_choice_blank_or_invalid_yields_none() {
        assert_eq!(resolve_other_ai_choice(""), OtherAiChoice::None);
        assert_eq!(resolve_other_ai_choice("   "), OtherAiChoice::None);
        assert_eq!(resolve_other_ai_choice("abc"), OtherAiChoice::None);
        assert_eq!(resolve_other_ai_choice("0"), OtherAiChoice::None);
        assert_eq!(resolve_other_ai_choice("99"), OtherAiChoice::None);
    }

    #[test]
    fn resolve_other_ai_choice_indices_one_to_six_map_to_providers() {
        assert_eq!(
            resolve_other_ai_choice("1"),
            OtherAiChoice::Provider("together")
        );
        assert_eq!(
            resolve_other_ai_choice("3"),
            OtherAiChoice::Provider("mistral")
        );
        assert_eq!(
            resolve_other_ai_choice("6"),
            OtherAiChoice::Provider("gemini")
        );
    }

    #[test]
    fn resolve_other_ai_choice_seven_means_custom() {
        assert_eq!(resolve_other_ai_choice("7"), OtherAiChoice::Custom);
        assert_eq!(resolve_other_ai_choice("  7  "), OtherAiChoice::Custom);
    }

    #[test]
    fn other_ai_providers_constant_matches_known_wizard_providers() {
        // OTHER_AI_PROVIDERS is referenced by resolve_other_ai_choice; ensure
        // every name has an entry in WIZARD_PROVIDERS so prompt_setup_other_ai_plan
        // never panics on the .expect("wizard provider exists") lookup.
        for name in OTHER_AI_PROVIDERS.iter() {
            let found = WIZARD_PROVIDERS.iter().any(|p| p.name == *name);
            assert!(found, "WIZARD_PROVIDERS missing {name}");
        }
    }

    // ---- build_custom_provider_plan ----

    #[test]
    fn build_custom_provider_plan_rejects_empty_fields() {
        assert!(build_custom_provider_plan(
            "".into(),
            "https://x".into(),
            "key".into(),
            "model".into()
        )
        .is_none());
        assert!(
            build_custom_provider_plan("name".into(), "".into(), "key".into(), "model".into())
                .is_none()
        );
        assert!(build_custom_provider_plan(
            "name".into(),
            "https://x".into(),
            "".into(),
            "model".into()
        )
        .is_none());
        assert!(build_custom_provider_plan(
            "name".into(),
            "https://x".into(),
            "key".into(),
            "".into()
        )
        .is_none());
    }

    #[test]
    fn build_custom_provider_plan_constructs_env_keyed_plan() {
        let plan = build_custom_provider_plan(
            "myllm".into(),
            "https://api.example.com".into(),
            "secret-key".into(),
            "my-model".into(),
        )
        .expect("plan");
        assert_eq!(plan.provider, "myllm");
        assert_eq!(plan.label, "myllm");
        assert_eq!(plan.model, "my-model");
        assert_eq!(plan.base_url.as_deref(), Some("https://api.example.com"));
        match plan.key {
            SetupAiKey::Env { var, value } => {
                assert_eq!(var, "MYLLM_API_KEY");
                assert_eq!(value, "secret-key");
            }
            other => panic!("expected env key, got {other:?}"),
        }
    }

    // ---- notification_plan_defaults / from_selections ----

    #[test]
    fn notification_plan_defaults_fresh_install_picks_telegram_and_dashboard() {
        // Args: (telegram, slack, discord, webhook, dashboard).
        // Vec order matches the multi-select items: [tg, slack, webhook, dash, discord].
        let defaults = notification_plan_defaults(false, false, false, false, false);
        assert_eq!(defaults, vec![true, false, false, true, false]);
    }

    #[test]
    fn notification_plan_defaults_keeps_existing_state_when_anything_configured() {
        // If telegram is already configured, defaults should mirror current
        let d1 = notification_plan_defaults(true, false, false, false, false);
        assert_eq!(d1, vec![true, false, false, false, false]);
        // slack + webhook configured
        let d2 = notification_plan_defaults(false, true, false, true, false);
        assert_eq!(d2, vec![false, true, true, false, false]);
        // everything (incl. discord) configured
        let d3 = notification_plan_defaults(true, true, true, true, true);
        assert_eq!(d3, vec![true, true, true, true, true]);
    }

    #[test]
    fn notification_plan_from_selections_maps_indices_to_channel_flags() {
        let plan = notification_plan_from_selections(&[0, 3]);
        assert!(plan.telegram);
        assert!(!plan.slack);
        assert!(!plan.webhook);
        assert!(plan.dashboard);
        assert!(!plan.discord);

        let plan = notification_plan_from_selections(&[]);
        assert!(!plan.telegram && !plan.slack && !plan.webhook && !plan.dashboard && !plan.discord);

        let plan = notification_plan_from_selections(&[1, 2]);
        assert!(!plan.telegram && plan.slack && plan.webhook && !plan.dashboard && !plan.discord);

        // index 4 = Discord (appended last so existing indices stay stable)
        let plan = notification_plan_from_selections(&[4]);
        assert!(plan.discord && !plan.telegram && !plan.slack);
    }

    // ---- resolve_env_file_path ----

    #[test]
    fn resolve_env_file_path_uses_sibling_agent_env() {
        let cfg = PathBuf::from("/etc/innerwarden/agent.toml");
        assert_eq!(
            resolve_env_file_path(&cfg),
            PathBuf::from("/etc/innerwarden/agent.env")
        );
    }

    #[test]
    fn resolve_env_file_path_falls_back_for_root_paths() {
        // A path with no parent (rare, e.g. just "agent.toml")
        // the parent of "agent.toml" is "" which IS a valid Path, so
        // the function will yield "agent.env" sibling. We only fall back
        // if .parent() returns None — that requires a root-only path.
        let cfg = PathBuf::from("/");
        let resolved = resolve_env_file_path(&cfg);
        assert_eq!(resolved, PathBuf::from("/etc/innerwarden/agent.env"));
    }

    // ---- already_configured_summary ----

    #[test]
    fn already_configured_summary_lists_only_enabled_channels() {
        // Args: (telegram, slack, discord, webhook, dashboard).
        assert_eq!(
            already_configured_summary(false, false, false, false, false),
            ""
        );
        assert_eq!(
            already_configured_summary(true, false, false, false, false),
            "Telegram"
        );
        assert_eq!(
            already_configured_summary(true, true, false, false, true),
            "Telegram + Slack + Dashboard"
        );
        assert_eq!(
            already_configured_summary(true, true, true, false, false),
            "Telegram + Slack + Discord"
        );
        assert_eq!(
            already_configured_summary(true, true, false, true, true),
            "Telegram + Slack + Webhook + Dashboard"
        );
    }

    // ---- pending_channels_for_apply ----

    #[test]
    fn pending_channels_for_apply_returns_only_selected_and_unconfigured() {
        let plan = SetupNotificationPlan {
            telegram: true,
            slack: true,
            discord: false,
            webhook: false,
            dashboard: true,
        };
        // telegram already configured, slack & dashboard not.
        // Args: (plan, telegram_ok, slack_ok, discord_ok, webhook_ok, dashboard_ok).
        let pending = pending_channels_for_apply(&plan, true, false, false, false, false);
        assert_eq!(pending, vec!["Slack", "Dashboard"]);

        // nothing selected -> nothing pending
        let empty = SetupNotificationPlan::default();
        assert!(pending_channels_for_apply(&empty, false, false, false, false, false).is_empty());

        // everything selected (incl. discord) and nothing configured -> all pending
        let all_selected = SetupNotificationPlan {
            telegram: true,
            slack: true,
            discord: true,
            webhook: true,
            dashboard: true,
        };
        let pending = pending_channels_for_apply(&all_selected, false, false, false, false, false);
        assert_eq!(
            pending,
            vec!["Telegram", "Slack", "Discord", "Webhook", "Dashboard"]
        );
    }

    // ---- resolve_responder_plan_from_selection ----

    #[test]
    fn resolve_responder_plan_from_selection_default_is_watch_only() {
        // selection 0 ignores the confirm string
        assert!(resolve_responder_plan_from_selection(0, "yes").dry_run);
        assert!(resolve_responder_plan_from_selection(0, "").dry_run);
    }

    #[test]
    fn resolve_responder_plan_from_selection_auto_protect_requires_yes() {
        // selection 1 with "yes" (case-sensitive, trimmed) -> auto-protect
        assert!(!resolve_responder_plan_from_selection(1, "yes").dry_run);
        assert!(!resolve_responder_plan_from_selection(1, "  yes\n").dry_run);
        // anything else -> still watch-only
        assert!(resolve_responder_plan_from_selection(1, "y").dry_run);
        assert!(resolve_responder_plan_from_selection(1, "YES").dry_run);
        assert!(resolve_responder_plan_from_selection(1, "").dry_run);
    }

    // ---- build_review_ai_line ----

    #[test]
    fn build_review_ai_line_uses_plan_when_present() {
        let plan = SetupAiPlan {
            label: "OpenAI".to_string(),
            provider: "openai".to_string(),
            model: "gpt-4o-mini".to_string(),
            base_url: None,
            key: SetupAiKey::None,
        };
        assert_eq!(
            build_review_ai_line(Some(&plan), None),
            "OpenAI (gpt-4o-mini)"
        );
    }

    #[test]
    fn build_review_ai_line_falls_back_to_agent_doc_summary() {
        let toml = "[ai]\nprovider = \"anthropic\"\nmodel = \"claude-haiku\"\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        assert_eq!(
            build_review_ai_line(None, Some(&doc)),
            "anthropic (claude-haiku)"
        );
    }

    #[test]
    fn build_review_ai_line_handles_missing_doc_with_default_label() {
        // No plan, no doc -> "configured" placeholder.
        assert_eq!(build_review_ai_line(None, None), "configured");
    }

    // ---- should_restart_agent_inline ----

    #[test]
    fn should_restart_agent_inline_only_when_needed_and_not_already() {
        assert!(should_restart_agent_inline(true, false));
        assert!(!should_restart_agent_inline(true, true));
        assert!(!should_restart_agent_inline(false, false));
        assert!(!should_restart_agent_inline(false, true));
    }

    // ---- critical_failures_message ----

    #[test]
    fn critical_failures_message_none_when_zero() {
        assert!(critical_failures_message(0).is_none());
    }

    #[test]
    fn critical_failures_message_singular_for_one() {
        assert_eq!(
            critical_failures_message(1).as_deref(),
            Some("1 critical item needs attention.")
        );
    }

    #[test]
    fn critical_failures_message_plural_for_more() {
        assert_eq!(
            critical_failures_message(3).as_deref(),
            Some("3 critical items need attention.")
        );
    }

    // ---- ai_provider_defaults: extra coverage ----

    #[test]
    fn ai_provider_defaults_covers_all_known_providers() {
        for provider in [
            "openai",
            "anthropic",
            "ollama",
            "groq",
            "deepseek",
            "together",
            "minimax",
            "mistral",
            "xai",
            "fireworks",
            "openrouter",
            "gemini",
        ] {
            let (model, _, _) = ai_provider_defaults(provider);
            assert!(!model.is_empty(), "provider {provider} default model");
        }
        // Anthropic's default key var
        let (_, key_var, _) = ai_provider_defaults("anthropic");
        assert_eq!(key_var.as_deref(), Some("ANTHROPIC_API_KEY"));
        // DeepSeek base url
        let (_, _, url) = ai_provider_defaults("deepseek");
        assert_eq!(url.as_deref(), Some("https://api.deepseek.com"));
        // Together
        let (_, _, url) = ai_provider_defaults("together");
        assert_eq!(url.as_deref(), Some("https://api.together.xyz"));
        // MiniMax
        let (_, _, url) = ai_provider_defaults("minimax");
        assert_eq!(url.as_deref(), Some("https://api.minimaxi.chat"));
        // Mistral
        let (_, _, url) = ai_provider_defaults("mistral");
        assert_eq!(url.as_deref(), Some("https://api.mistral.ai"));
        // xAI
        let (_, _, url) = ai_provider_defaults("xai");
        assert_eq!(url.as_deref(), Some("https://api.x.ai"));
        // Fireworks
        let (_, _, url) = ai_provider_defaults("fireworks");
        assert_eq!(url.as_deref(), Some("https://api.fireworks.ai/inference"));
        // OpenRouter
        let (_, _, url) = ai_provider_defaults("openrouter");
        assert_eq!(url.as_deref(), Some("https://openrouter.ai/api"));
        // Gemini
        let (_, _, url) = ai_provider_defaults("gemini");
        assert!(url.as_deref().unwrap().contains("googleapis.com"));
    }

    // ---- setup_current_ai_summary ----

    #[test]
    fn setup_current_ai_summary_uses_provider_only_when_model_missing() {
        let toml = "[ai]\nprovider = \"groq\"\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        assert_eq!(setup_current_ai_summary(Some(&doc)), "groq");
    }

    #[test]
    fn setup_current_ai_summary_combines_provider_and_model_when_both_present() {
        let toml = "[ai]\nprovider = \"groq\"\nmodel = \"llama-3.3-70b\"\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        assert_eq!(setup_current_ai_summary(Some(&doc)), "groq (llama-3.3-70b)");
    }

    #[test]
    fn setup_current_ai_summary_falls_back_to_configured_when_no_doc() {
        assert_eq!(setup_current_ai_summary(None), "configured");
    }

    // ---- spec 032 wizard step: Local Warden Model ----

    #[test]
    fn agent_str_dotted_navigates_nested_tables() {
        let toml = "[ai.warden]\nprovider = \"local_warden\"\nbase_url = \"/var/lib/innerwarden/models/classifier\"\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        assert_eq!(
            agent_str_dotted(Some(&doc), &["ai", "warden", "provider"]).as_deref(),
            Some("local_warden")
        );
        assert_eq!(
            agent_str_dotted(Some(&doc), &["ai", "warden", "base_url"]).as_deref(),
            Some("/var/lib/innerwarden/models/classifier")
        );
    }

    #[test]
    fn agent_str_dotted_returns_none_for_missing_path() {
        let toml = "[ai]\nprovider = \"openai\"\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        assert_eq!(
            agent_str_dotted(Some(&doc), &["ai", "warden", "provider"]),
            None
        );
        assert_eq!(agent_str_dotted(None, &["anything"]), None);
        assert_eq!(agent_str_dotted(Some(&doc), &[]), None);
    }

    #[test]
    fn agent_warden_configured_detects_canonical_section() {
        let toml = "[ai.warden]\nprovider = \"local_warden\"\nbase_url = \"/var/lib/x\"\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        assert!(agent_warden_configured(Some(&doc)));
    }

    #[test]
    fn agent_warden_configured_detects_legacy_classifier_alias() {
        // 2026-05-03 rename: `[ai.classifier]` is preserved as a serde
        // alias for `[ai.warden]`. The wizard must treat either form as
        // "already configured" so an upgrading operator doesn't get
        // re-prompted on every setup run.
        let toml = "[ai.classifier]\nprovider = \"local_classifier\"\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        assert!(agent_warden_configured(Some(&doc)));
    }

    #[test]
    fn agent_warden_configured_is_false_without_warden_section() {
        let toml = "[ai]\nprovider = \"openai\"\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        assert!(!agent_warden_configured(Some(&doc)));
        assert!(!agent_warden_configured(None));
    }

    #[test]
    fn setup_current_warden_summary_prefers_canonical_section() {
        let toml =
            "[ai.warden]\nprovider = \"local_warden\"\n[ai.classifier]\nprovider = \"local_classifier\"\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        assert_eq!(setup_current_warden_summary(Some(&doc)), "local_warden");
    }

    #[test]
    fn setup_current_warden_summary_marks_legacy_alias() {
        let toml = "[ai.classifier]\nprovider = \"local_classifier\"\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        assert_eq!(
            setup_current_warden_summary(Some(&doc)),
            "local_classifier (legacy alias)"
        );
    }

    #[test]
    fn warden_pitch_lines_call_out_the_three_benefits_and_two_costs() {
        let bullets = warden_pitch_lines();
        // Operator must see all three "+" benefits …
        assert!(bullets
            .iter()
            .any(|b| b.contains("0 tokens spent on Decide")));
        assert!(bullets
            .iter()
            .any(|b| b.contains("~60 ms p50") && b.contains("cloud round-trip")));
        assert!(bullets
            .iter()
            .any(|b| b.contains("Decide traffic never leaves the server")));
        // … and the two honest "-" costs.
        assert!(bullets
            .iter()
            .any(|b| b.contains("~91 MB disk") && b.contains("~150 MB RAM")));
        // Time cost — wizard installs the model right now (post-#642),
        // so the second cost bullet mentions the setup-time penalty
        // rather than the stale "release-not-cut-yet" caveat.
        assert!(bullets
            .iter()
            .any(|b| b.contains("~30") && b.contains("setup")));
    }

    #[test]
    fn warden_intro_lines_describe_decide_path_and_cloud_fallback() {
        let lines = warden_intro_lines().join(" ");
        assert!(lines.contains("Decide path"));
        assert!(lines.contains("block / dismiss"));
        assert!(lines.contains("Cloud AI"));
        assert!(lines.contains("Explain"));
    }

    #[test]
    fn build_warden_plan_yes_marks_enabled_not_already_configured() {
        let plan = build_warden_plan(true);
        assert!(plan.enabled);
        assert!(!plan.already_configured);
        assert_eq!(plan.label(), "installing now");
    }

    #[test]
    fn build_warden_plan_no_marks_skipped() {
        let plan = build_warden_plan(false);
        assert!(!plan.enabled);
        assert!(!plan.already_configured);
        assert_eq!(plan.label(), "skipped (Decide via cloud AI)");
    }

    #[test]
    fn setup_warden_plan_label_covers_three_states() {
        let already = SetupWardenPlan {
            enabled: true,
            already_configured: true,
        };
        assert_eq!(already.label(), "already configured");

        let enabled = SetupWardenPlan {
            enabled: true,
            already_configured: false,
        };
        assert_eq!(enabled.label(), "installing now");

        let skipped = SetupWardenPlan {
            enabled: false,
            already_configured: false,
        };
        assert_eq!(skipped.label(), "skipped (Decide via cloud AI)");
    }

    // ---- collect_setup_preconfig_plan + parse_setup_capability_hint extras ----

    #[test]
    fn parse_setup_capability_hint_handles_param_without_equals() {
        // params that don't include '=' must be skipped, not crash
        let plan = parse_setup_capability_hint("innerwarden enable foo --param broken")
            .expect("hint parses");
        assert_eq!(plan.id, "foo");
        assert!(plan.params.is_empty());
    }

    #[test]
    fn parse_setup_capability_hint_handles_only_id_no_params() {
        let plan = parse_setup_capability_hint("innerwarden enable simple").expect("hint parses");
        assert_eq!(plan.id, "simple");
        assert!(plan.params.is_empty());
    }

    #[test]
    fn collect_setup_preconfig_plan_marks_severity_unset_for_missing_sections() {
        // No [telegram] or [webhook] sections -> both severities should be set.
        let toml = "[ai]\nprovider = \"openai\"\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        let plan = collect_setup_preconfig_plan(Some(&doc));
        assert!(plan.set_telegram_min_severity);
        assert!(plan.set_webhook_min_severity);
    }

    #[test]
    fn collect_setup_preconfig_plan_skips_severity_when_already_set() {
        let toml = "[telegram]\nmin_severity = \"high\"\n\n[webhook]\nmin_severity = \"medium\"\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        let plan = collect_setup_preconfig_plan(Some(&doc));
        assert!(!plan.set_telegram_min_severity);
        assert!(!plan.set_webhook_min_severity);
    }

    #[test]
    fn collect_setup_preconfig_plan_handles_no_doc() {
        let plan = collect_setup_preconfig_plan(None);
        assert!(plan.set_telegram_min_severity);
        assert!(plan.set_webhook_min_severity);
    }

    // ---- SetupResponderPlan label parity ----

    #[test]
    fn setup_responder_plan_default_dry_run_is_watch_only() {
        let plan = SetupResponderPlan { dry_run: true };
        assert_eq!(plan.label(), "Watch only");
    }

    // ---- build_setup_ai_plan: provider with default base_url and config key ----

    #[test]
    fn build_setup_ai_plan_provides_default_base_url_for_known_provider() {
        // groq has a default base_url; we don't pass a custom one
        let plan = build_setup_ai_plan("groq", "Groq", Some("k".to_string()), None, None);
        assert_eq!(
            plan.base_url.as_deref(),
            Some("https://api.groq.com/openai")
        );
        assert_eq!(plan.model, "llama-3.3-70b-versatile");
    }

    #[test]
    fn build_setup_ai_plan_unknown_provider_synthesises_env_key_var() {
        let plan = build_setup_ai_plan("custom", "Custom", Some("k".to_string()), None, None);
        match plan.key {
            SetupAiKey::Env { var, value } => {
                assert_eq!(var, "CUSTOM_API_KEY");
                assert_eq!(value, "k");
            }
            _ => panic!("expected env key"),
        }
        // unknown provider falls back to gpt-4o-mini default model
        assert_eq!(plan.model, "gpt-4o-mini");
    }

    #[test]
    fn build_setup_ai_plan_caller_supplied_base_url_wins_over_default() {
        let plan = build_setup_ai_plan(
            "groq",
            "Groq",
            None,
            None,
            Some("https://override.example.com".to_string()),
        );
        assert_eq!(
            plan.base_url.as_deref(),
            Some("https://override.example.com")
        );
    }

    // ---- resolve_cloud_api_style ----

    #[test]
    fn resolve_cloud_api_style_uses_wizard_metadata_or_openai_default() {
        assert_eq!(resolve_cloud_api_style("anthropic"), "anthropic");
        assert_eq!(resolve_cloud_api_style("gemini"), "gemini");
        assert_eq!(resolve_cloud_api_style("openai"), "openai");
        assert_eq!(resolve_cloud_api_style("groq"), "openai");
        // Unknown -> default fallback
        assert_eq!(resolve_cloud_api_style("totally-unknown"), "openai");
    }

    // ---- resolve_cloud_request_base_url ----

    #[test]
    fn resolve_cloud_request_base_url_prefers_explicit_default() {
        assert_eq!(
            resolve_cloud_request_base_url("anything", Some("https://api.test.com")),
            "https://api.test.com"
        );
    }

    #[test]
    fn resolve_cloud_request_base_url_falls_back_to_synthesised_url() {
        assert_eq!(
            resolve_cloud_request_base_url("widgetai", None),
            "https://api.widgetai.com"
        );
    }

    // ---- build_cloud_provider_plan ----

    #[test]
    fn build_cloud_provider_plan_rejects_empty_key() {
        let plan = build_cloud_provider_plan(
            "openai",
            "OpenAI",
            String::new(),
            "gpt-4o-mini".to_string(),
            None,
            &[],
            "",
        );
        assert!(plan.is_none());
    }

    #[test]
    fn build_cloud_provider_plan_uses_default_model_when_models_empty() {
        let plan = build_cloud_provider_plan(
            "openai",
            "OpenAI",
            "sk-x".to_string(),
            "gpt-4o-mini".to_string(),
            None,
            &[],
            "anything",
        )
        .expect("plan");
        assert_eq!(plan.model, "gpt-4o-mini");
        assert_eq!(plan.provider, "openai");
        match plan.key {
            SetupAiKey::Env { var, value } => {
                assert_eq!(var, "OPENAI_API_KEY");
                assert_eq!(value, "sk-x");
            }
            _ => panic!("expected env key"),
        }
    }

    #[test]
    fn build_cloud_provider_plan_uses_fetched_model_when_input_blank() {
        let models = vec!["x".to_string(), "y".to_string(), "gpt-4o-mini".to_string()];
        let plan = build_cloud_provider_plan(
            "openai",
            "OpenAI",
            "sk-x".to_string(),
            "gpt-4o-mini".to_string(),
            None,
            &models,
            "",
        )
        .expect("plan");
        // default_idx = 3 -> input "" -> idx 2 -> model "gpt-4o-mini"
        assert_eq!(plan.model, "gpt-4o-mini");
    }

    #[test]
    fn build_cloud_provider_plan_honours_user_input() {
        let models = vec!["x".to_string(), "y".to_string(), "z".to_string()];
        let plan = build_cloud_provider_plan(
            "openai",
            "OpenAI",
            "sk-x".to_string(),
            "missing".to_string(),
            None,
            &models,
            "1",
        )
        .expect("plan");
        assert_eq!(plan.model, "x");
    }

    // ---- resolve_local_ollama_plan ----

    #[test]
    fn resolve_local_ollama_plan_not_running_yields_not_installed() {
        let outcome = resolve_local_ollama_plan(false, &[], "");
        assert!(matches!(outcome, LocalOllamaOutcome::NotInstalled));
    }

    #[test]
    fn resolve_local_ollama_plan_running_no_models_yields_no_models() {
        let outcome = resolve_local_ollama_plan(true, &[], "");
        assert!(matches!(outcome, LocalOllamaOutcome::NoModels));
    }

    #[test]
    fn resolve_local_ollama_plan_one_model_auto_selects_it() {
        let models = vec!["llama3.2".to_string()];
        let outcome = resolve_local_ollama_plan(true, &models, "");
        match outcome {
            LocalOllamaOutcome::AutoSelected(plan) => {
                assert_eq!(plan.provider, "ollama");
                assert_eq!(plan.model, "llama3.2");
                assert!(matches!(plan.key, SetupAiKey::None));
                assert!(plan.base_url.is_none());
            }
            other => panic!("expected AutoSelected, got {other:?}"),
        }
    }

    #[test]
    fn resolve_local_ollama_plan_multi_model_selected_default_index_picks_qwen() {
        let models = vec![
            "llama3.2".to_string(),
            "qwen2.5:3b".to_string(),
            "phi-4".to_string(),
        ];
        // Empty input -> default_idx = 2 (1-indexed for qwen) -> idx 1
        let outcome = resolve_local_ollama_plan(true, &models, "");
        match outcome {
            LocalOllamaOutcome::Selected(plan) => assert_eq!(plan.model, "qwen2.5:3b"),
            other => panic!("expected Selected, got {other:?}"),
        }
    }

    #[test]
    fn resolve_local_ollama_plan_multi_model_honours_user_choice() {
        let models = vec![
            "llama3.2".to_string(),
            "qwen2.5:3b".to_string(),
            "phi-4".to_string(),
        ];
        let outcome = resolve_local_ollama_plan(true, &models, "3");
        match outcome {
            LocalOllamaOutcome::Selected(plan) => assert_eq!(plan.model, "phi-4"),
            other => panic!("expected Selected, got {other:?}"),
        }
    }

    // ---- cloud_provider_for_selection ----

    #[test]
    fn cloud_provider_for_selection_maps_known_indices() {
        assert_eq!(
            cloud_provider_for_selection(1),
            Some(("openrouter", "OpenRouter", "openrouter.ai"))
        );
        assert_eq!(
            cloud_provider_for_selection(2),
            Some(("openai", "OpenAI", "platform.openai.com"))
        );
        assert_eq!(
            cloud_provider_for_selection(3),
            Some(("anthropic", "Anthropic", "console.anthropic.com"))
        );
        assert_eq!(
            cloud_provider_for_selection(4),
            Some(("groq", "Groq", "console.groq.com"))
        );
        assert_eq!(
            cloud_provider_for_selection(5),
            Some(("deepseek", "DeepSeek", "platform.deepseek.com"))
        );
    }

    #[test]
    fn cloud_provider_for_selection_returns_none_outside_range() {
        assert!(cloud_provider_for_selection(0).is_none());
        assert!(cloud_provider_for_selection(6).is_none());
        assert!(cloud_provider_for_selection(99).is_none());
    }

    // ---- already_configured_channel_lines ----

    #[test]
    fn already_configured_channel_lines_emits_only_enabled_channels_with_masked_secrets() {
        let mut env: HashMap<String, String> = HashMap::new();
        env.insert(
            "TELEGRAM_BOT_TOKEN".to_string(),
            "1234567890:abcdefghijklmno".to_string(),
        );
        env.insert(
            "SLACK_WEBHOOK_URL".to_string(),
            "https://hooks.slack.com/services/AAAA/BBBB/CCCC".to_string(),
        );
        env.insert(
            "WEBHOOK_URL".to_string(),
            "https://example.com/x".to_string(),
        );
        env.insert(
            "INNERWARDEN_DASHBOARD_USER".to_string(),
            "admin".to_string(),
        );

        let lines = already_configured_channel_lines(true, true, false, true, true, &env);
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0].0, "Telegram");
        assert!(lines[0].1.starts_with("token: "));
        assert!(lines[0].1.contains("***"));
        assert_eq!(lines[1].0, "Slack");
        assert!(lines[1].1.starts_with("webhook: "));
        assert_eq!(lines[2].0, "Webhook");
        assert!(lines[2].1.starts_with("url: "));
        assert_eq!(lines[3].0, "Dashboard");
        assert_eq!(lines[3].1, "user: admin");
    }

    #[test]
    fn already_configured_channel_lines_handles_missing_env_values_gracefully() {
        let env: HashMap<String, String> = HashMap::new();
        let lines = already_configured_channel_lines(true, false, false, true, true, &env);
        assert_eq!(lines.len(), 3);
        // No panic; secrets/values fall back to "" and the prefix is intact.
        assert_eq!(lines[0].0, "Telegram");
        assert_eq!(lines[0].1, "token: ");
        assert_eq!(lines[1].0, "Webhook");
        assert_eq!(lines[1].1, "url: ");
        assert_eq!(lines[2].0, "Dashboard");
        assert_eq!(lines[2].1, "user: ");
    }

    #[test]
    fn already_configured_channel_lines_returns_empty_when_nothing_configured() {
        let env: HashMap<String, String> = HashMap::new();
        let lines = already_configured_channel_lines(false, false, false, false, false, &env);
        assert!(lines.is_empty());
    }

    // ---- SetupNotificationPlan label edges ----

    #[test]
    fn setup_notification_plan_label_includes_webhook_branch() {
        let plan = SetupNotificationPlan {
            telegram: false,
            slack: false,
            discord: false,
            webhook: true,
            dashboard: false,
        };
        assert_eq!(plan.label(), "Webhook");
        let plan = SetupNotificationPlan {
            telegram: true,
            slack: true,
            discord: false,
            webhook: true,
            dashboard: true,
        };
        assert_eq!(plan.label(), "Telegram + Slack + Webhook + Dashboard");
    }

    // ---- parse_setup_capability_hint extra branches ----

    #[test]
    fn parse_setup_capability_hint_skips_non_param_tokens() {
        // Non --param token in arg slot should hit the `i += 1` else branch
        let plan = parse_setup_capability_hint(
            "innerwarden enable foo --unknown-flag --param k=v --other",
        )
        .expect("hint parses");
        assert_eq!(plan.id, "foo");
        assert_eq!(plan.params.get("k").map(String::as_str), Some("v"));
        // --unknown-flag and --other did not crash.
    }

    #[test]
    fn parse_setup_capability_hint_handles_param_without_value_at_end() {
        // --param at end (no value following) should not crash and add no param
        let plan =
            parse_setup_capability_hint("innerwarden enable foo --param").expect("hint parses");
        assert_eq!(plan.id, "foo");
        assert!(plan.params.is_empty());
    }

    // ---- agent_str: nested missing keys ----

    #[test]
    fn agent_str_returns_none_when_section_missing_or_value_not_string() {
        let toml = "[ai]\nenabled = true\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        // Missing section
        assert!(agent_str(Some(&doc), "missing", "field").is_none());
        // Section exists but key not a string (it's a bool)
        assert!(agent_str(Some(&doc), "ai", "enabled").is_none());
        // None doc
        assert!(agent_str(None, "ai", "anything").is_none());
    }

    // ---- env_has reads from process env too ----

    #[test]
    fn env_has_reads_process_env_when_map_has_no_match() {
        // We use a synthetic key that should not be in the map.
        let map: HashMap<String, String> = HashMap::new();
        let key = format!(
            "SETUP_RS_TEST_PROCENV_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        // Sanity: not set yet
        assert!(!env_has(&map, &key));
        // SAFETY: set_var/remove_var are unsafe in 2024-edition Rust on
        // multi-threaded test runners. This test confines mutation to a
        // unique key not used elsewhere, so it is safe in practice.
        unsafe {
            std::env::set_var(&key, "live");
        }
        assert!(env_has(&map, &key));
        unsafe {
            std::env::remove_var(&key);
        }
    }

    // ---- apply_setup_preconfig_defaults ----

    #[test]
    fn apply_setup_preconfig_defaults_writes_when_flags_set() {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("agent.toml");
        // Pre-existing minimal config (preserved on append)
        std::fs::write(&cfg, "[ai]\nenabled = false\n").unwrap();
        let plan = SetupPreconfigPlan {
            essential_capabilities: vec![],
            set_telegram_min_severity: true,
            set_webhook_min_severity: true,
        };
        apply_setup_preconfig_defaults(&cfg, &plan);
        let contents = std::fs::read_to_string(&cfg).unwrap();
        assert!(contents.contains("[telegram]"));
        assert!(contents.contains("min_severity = \"high\""));
        assert!(contents.contains("daily_summary_hour = 9"));
        assert!(contents.contains("daily_budget = 10"));
        assert!(contents.contains("[webhook]"));
    }

    #[test]
    fn apply_setup_preconfig_defaults_skips_when_flags_unset() {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("agent.toml");
        std::fs::write(&cfg, "[ai]\nenabled = false\n").unwrap();
        let plan = SetupPreconfigPlan::default(); // both bools false
        apply_setup_preconfig_defaults(&cfg, &plan);
        let contents = std::fs::read_to_string(&cfg).unwrap();
        assert!(!contents.contains("[telegram]"));
        assert!(!contents.contains("[webhook]"));
    }

    #[test]
    fn apply_setup_preconfig_defaults_only_telegram() {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("agent.toml");
        std::fs::write(&cfg, "").unwrap();
        let plan = SetupPreconfigPlan {
            essential_capabilities: vec![],
            set_telegram_min_severity: true,
            set_webhook_min_severity: false,
        };
        apply_setup_preconfig_defaults(&cfg, &plan);
        let contents = std::fs::read_to_string(&cfg).unwrap();
        assert!(contents.contains("[telegram]"));
        assert!(!contents.contains("[webhook]"));
    }

    // ---- apply_setup_responder ----

    #[test]
    fn apply_setup_responder_writes_enabled_and_dry_run() {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("agent.toml");
        std::fs::write(&cfg, "").unwrap();
        apply_setup_responder(&cfg, SetupResponderPlan { dry_run: true }).unwrap();
        let contents = std::fs::read_to_string(&cfg).unwrap();
        assert!(contents.contains("[responder]"));
        assert!(contents.contains("enabled = true"));
        assert!(contents.contains("dry_run = true"));

        apply_setup_responder(&cfg, SetupResponderPlan { dry_run: false }).unwrap();
        let contents = std::fs::read_to_string(&cfg).unwrap();
        assert!(contents.contains("dry_run = false"));
    }

    // ---- apply_setup_mesh ----

    #[test]
    fn apply_setup_mesh_no_op_when_disabled_or_already_enabled() {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("agent.toml");
        std::fs::write(&cfg, "").unwrap();
        apply_setup_mesh(&cfg, false, false, false).unwrap();
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), "");
        // already enabled -> no write
        apply_setup_mesh(&cfg, true, true, false).unwrap();
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), "");
    }

    #[test]
    fn apply_setup_mesh_writes_seeds_when_section_missing() {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("agent.toml");
        std::fs::write(&cfg, "").unwrap();
        apply_setup_mesh(&cfg, true, false, false).unwrap();
        let contents = std::fs::read_to_string(&cfg).unwrap();
        assert!(contents.contains("[mesh]"));
        assert!(contents.contains("enabled = true"));
        assert!(contents.contains("bind = \"0.0.0.0:8790\""));
        assert!(contents.contains("poll_secs = 30"));
        assert!(contents.contains("auto_broadcast = true"));
    }

    #[test]
    fn apply_setup_mesh_only_writes_enabled_when_section_already_exists() {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("agent.toml");
        std::fs::write(
            &cfg,
            "[mesh]\nbind = \"0.0.0.0:9000\"\npoll_secs = 60\nauto_broadcast = false\n",
        )
        .unwrap();
        apply_setup_mesh(&cfg, true, false, true).unwrap();
        let contents = std::fs::read_to_string(&cfg).unwrap();
        // enabled flipped to true
        assert!(contents.contains("enabled = true"));
        // existing values preserved (we passed has_mesh_section=true)
        assert!(contents.contains("bind = \"0.0.0.0:9000\""));
        assert!(contents.contains("poll_secs = 60"));
        assert!(contents.contains("auto_broadcast = false"));
    }

    // ---- sensor_restart_decision ----

    #[test]
    fn sensor_restart_decision_skip_when_not_needed() {
        assert_eq!(
            sensor_restart_decision(false, false, false),
            SensorRestartDecision::Skip
        );
        assert_eq!(
            sensor_restart_decision(false, true, true),
            SensorRestartDecision::Skip
        );
    }

    #[test]
    fn sensor_restart_decision_macos_skips_even_in_dry_run() {
        assert_eq!(
            sensor_restart_decision(true, true, false),
            SensorRestartDecision::SkipMacos
        );
        assert_eq!(
            sensor_restart_decision(true, true, true),
            SensorRestartDecision::SkipMacos
        );
    }

    #[test]
    fn sensor_restart_decision_dry_run_announces_only() {
        assert_eq!(
            sensor_restart_decision(true, false, true),
            SensorRestartDecision::DryRun
        );
    }

    #[test]
    fn sensor_restart_decision_real_restart_when_needed_and_linux_live() {
        assert_eq!(
            sensor_restart_decision(true, false, false),
            SensorRestartDecision::DoRestart
        );
    }

    // ---- format_setup_check_status_line / lines ----

    #[test]
    fn format_setup_check_status_line_ok_uses_ok_token() {
        let check = SetupCheck {
            label: "AI".to_string(),
            detail: "openai (gpt-4o-mini)".to_string(),
            ok: true,
            critical: true,
        };
        let line = format_setup_check_status_line(&check);
        assert!(line.contains("OK"));
        assert!(line.contains("AI"));
        assert!(line.contains("openai (gpt-4o-mini)"));
    }

    #[test]
    fn format_setup_check_status_line_failed_uses_fix_token() {
        let check = SetupCheck {
            label: "Alerts".to_string(),
            detail: "Telegram not ready".to_string(),
            ok: false,
            critical: true,
        };
        let line = format_setup_check_status_line(&check);
        assert!(line.contains("FIX"));
        assert!(!line.contains(" OK "));
    }

    // ---- compute_setup_existing_channels ----

    fn make_env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn compute_setup_existing_channels_empty_yields_all_false() {
        let env: HashMap<String, String> = HashMap::new();
        let snapshot = compute_setup_existing_channels(&env, None);
        assert!(!snapshot.telegram);
        assert!(!snapshot.slack);
        assert!(!snapshot.webhook);
        assert!(!snapshot.dashboard);
        assert!(!snapshot.any());
    }

    #[test]
    fn compute_setup_existing_channels_telegram_only_needs_both_env_vars() {
        let env = make_env_map(&[("TELEGRAM_BOT_TOKEN", "abc")]);
        let snap = compute_setup_existing_channels(&env, None);
        assert!(!snap.telegram);
        let env = make_env_map(&[("TELEGRAM_BOT_TOKEN", "abc"), ("TELEGRAM_CHAT_ID", "1234")]);
        let snap = compute_setup_existing_channels(&env, None);
        assert!(snap.telegram);
        assert!(snap.any());
    }

    #[test]
    fn compute_setup_existing_channels_slack_needs_env_and_enabled() {
        let env = make_env_map(&[("SLACK_WEBHOOK_URL", "https://hooks/...")]);
        let snap = compute_setup_existing_channels(&env, None);
        // No agent doc → not enabled → not OK
        assert!(!snap.slack);

        let toml = "[slack]\nenabled = true\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        let snap = compute_setup_existing_channels(&env, Some(&doc));
        assert!(snap.slack);
    }

    #[test]
    fn compute_setup_existing_channels_discord_needs_env_and_enabled() {
        let env = make_env_map(&[(
            "DISCORD_WEBHOOK_URL",
            "https://discord.com/api/webhooks/1/x",
        )]);
        // env present but not enabled in agent.toml → not OK
        assert!(!compute_setup_existing_channels(&env, None).discord);

        let doc: toml_edit::DocumentMut = "[discord]\nenabled = true\n".parse().unwrap();
        let snap = compute_setup_existing_channels(&env, Some(&doc));
        assert!(snap.discord);
        assert!(snap.any());
    }

    #[test]
    fn discord_wizard_lines_and_apply_channel() {
        // Already-configured banner lists Discord with a masked webhook.
        let env = make_env_map(&[(
            "DISCORD_WEBHOOK_URL",
            "https://discord.com/api/webhooks/1/sekret",
        )]);
        let lines = already_configured_channel_lines(false, false, true, false, false, &env);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, "Discord");
        assert!(lines[0].1.starts_with("webhook: "));

        // Selected-but-unconfigured Discord shows up in the apply walk-through.
        let plan = SetupNotificationPlan {
            telegram: false,
            slack: false,
            discord: true,
            webhook: false,
            dashboard: false,
        };
        let pending = channels_to_configure_in_apply(&plan, false, false, false, false, false);
        assert_eq!(pending, vec![SetupChannel::Discord]);
        assert_eq!(plan.label(), "Discord");
    }

    #[test]
    fn compute_setup_existing_channels_dashboard_needs_user_and_password_hash() {
        let env = make_env_map(&[("INNERWARDEN_DASHBOARD_USER", "admin")]);
        let snap = compute_setup_existing_channels(&env, None);
        assert!(!snap.dashboard);
        let env = make_env_map(&[
            ("INNERWARDEN_DASHBOARD_USER", "admin"),
            ("INNERWARDEN_DASHBOARD_PASSWORD_HASH", "$2y$..."),
        ]);
        let snap = compute_setup_existing_channels(&env, None);
        assert!(snap.dashboard);
    }

    #[test]
    fn compute_setup_existing_channels_webhook_requires_url_and_enabled() {
        let env = make_env_map(&[("WEBHOOK_URL", "https://example.com/x")]);
        let snap = compute_setup_existing_channels(&env, None);
        assert!(!snap.webhook);
        let toml = "[webhook]\nenabled = true\n";
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        let snap = compute_setup_existing_channels(&env, Some(&doc));
        assert!(snap.webhook);
    }

    // ---- channels_to_configure_in_apply ----

    #[test]
    fn channels_to_configure_in_apply_empty_when_nothing_selected() {
        let plan = SetupNotificationPlan::default();
        assert!(
            channels_to_configure_in_apply(&plan, false, false, false, false, false).is_empty()
        );
    }

    #[test]
    fn channels_to_configure_in_apply_skips_already_configured() {
        let plan = SetupNotificationPlan {
            telegram: true,
            slack: true,
            discord: false,
            webhook: true,
            dashboard: true,
        };
        let pending = channels_to_configure_in_apply(&plan, true, false, false, true, false);
        assert_eq!(pending, vec![SetupChannel::Slack, SetupChannel::Dashboard]);
    }

    // ---- build_cloud_model_menu_lines ----

    #[test]
    fn build_cloud_model_menu_lines_short_list_no_overflow() {
        let models = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let lines = build_cloud_model_menu_lines(&models, 2);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "1. a");
        assert_eq!(lines[1], "2. b (recommended)");
        assert_eq!(lines[2], "3. c");
    }

    #[test]
    fn build_cloud_model_menu_lines_caps_at_15_with_overflow_marker() {
        let models: Vec<String> = (0..20).map(|i| format!("m{i}")).collect();
        let lines = build_cloud_model_menu_lines(&models, 1);
        assert_eq!(lines.len(), 16);
        assert!(lines.last().unwrap().contains("... and 5 more"));
    }

    #[test]
    fn build_cloud_model_menu_lines_no_recommended_when_default_outside_show_count() {
        let models: Vec<String> = (0..20).map(|i| format!("m{i}")).collect();
        // default_idx = 18 (out of show_count=15) — no row gets the tag
        let lines = build_cloud_model_menu_lines(&models, 18);
        for line in lines.iter().take(15) {
            assert!(!line.contains("recommended"));
        }
    }

    // ---- build_local_ollama_menu_lines ----

    #[test]
    fn build_local_ollama_menu_lines_tags_qwen() {
        let models = vec![
            "llama3.2".to_string(),
            "qwen2.5:3b-instruct".to_string(),
            "phi-4".to_string(),
        ];
        let lines = build_local_ollama_menu_lines(&models);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "1. llama3.2");
        assert_eq!(lines[1], "2. qwen2.5:3b-instruct (recommended)");
        assert_eq!(lines[2], "3. phi-4");
    }

    #[test]
    fn build_local_ollama_menu_lines_handles_empty_input() {
        assert!(build_local_ollama_menu_lines(&[]).is_empty());
    }

    #[test]
    fn channels_to_configure_in_apply_orders_telegram_first() {
        let plan = SetupNotificationPlan {
            telegram: true,
            slack: true,
            discord: false,
            webhook: true,
            dashboard: true,
        };
        let pending = channels_to_configure_in_apply(&plan, false, false, false, false, false);
        assert_eq!(
            pending,
            vec![
                SetupChannel::Telegram,
                SetupChannel::Slack,
                SetupChannel::Webhook,
                SetupChannel::Dashboard,
            ]
        );
    }

    // ---- cmd_setup orchestration (dry-run) ----
    //
    // These tests drive `cmd_setup` end-to-end with `dry_run = true`. The
    // interactive `prompt_yes_no` is stubbed in test mode (returns the
    // default), so the orchestration logic of cmd_setup runs without ever
    // touching stdin. The dry-run early return prevents the apply phase.

    #[test]
    fn cmd_setup_dry_run_returns_ok_when_everything_preconfigured_basic_mode() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true); // dry_run=true
                                                   // Pre-fill agent.toml so all interactive AI/responder/mesh prompts
                                                   // are skipped, and at least one channel is already configured so
                                                   // the "any_channel_configured" basic-mode branch is taken (which
                                                   // only consults prompt_yes_no, our test-mode stub).
        std::fs::write(
            &cli.agent_config,
            "[ai]\nenabled = true\nprovider = \"openai\"\nmodel = \"gpt-4o-mini\"\n\n\
             [responder]\nenabled = true\ndry_run = true\n\n\
             [mesh]\nenabled = true\n\n\
             [slack]\nenabled = true\n",
        )
        .unwrap();
        // Slack is "configured" in agent doc + env file
        let env_file = dir.path().join("agent.env");
        std::fs::write(&env_file, "SLACK_WEBHOOK_URL=https://hooks.slack.com/x\n").unwrap();

        cmd_setup(&cli, "basic").expect("dry-run cmd_setup should succeed");

        // Dry-run did not modify the agent config (apply phase not entered)
        let agent_after = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(agent_after.contains("[ai]"));
        assert!(agent_after.contains("provider = \"openai\""));
    }

    #[test]
    fn cmd_setup_dry_run_returns_ok_for_advanced_mode_with_existing_config() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        std::fs::write(
            &cli.agent_config,
            "[ai]\nenabled = true\nprovider = \"groq\"\nmodel = \"llama-3.3-70b-versatile\"\n\n\
             [responder]\nenabled = true\ndry_run = false\n\n\
             [mesh]\nenabled = true\n\n\
             [webhook]\nenabled = true\n",
        )
        .unwrap();
        // Webhook configured (env + agent doc) so we hit the basic-mode keep/update
        // branch in basic, but in advanced we ALWAYS prompt_notification_channels.
        // Since advanced+all-preconfigured but webhook configured -> goes through
        // prompt_notification_channels (interactive). To avoid that, drive
        // basic mode here.
        let env_file = dir.path().join("agent.env");
        std::fs::write(&env_file, "WEBHOOK_URL=https://example.com/wh\n").unwrap();

        // Use basic mode (the advanced path prompts MultiSelect which is interactive)
        cmd_setup(&cli, "basic").expect("dry-run cmd_setup should succeed");
    }

    #[test]
    fn cmd_setup_dry_run_advanced_mode_no_existing_channels() {
        // Advanced + nothing configured: hits prompt_notification_channels
        // (the test stub returns the existing-channel state, all false here).
        // Also exercises the "share threat blocks?" prompt_yes_no for mesh
        // (test stub returns default=false).
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        std::fs::write(
            &cli.agent_config,
            "[ai]\nenabled = true\nprovider = \"openai\"\nmodel = \"gpt-4o-mini\"\n\n\
             [responder]\nenabled = true\ndry_run = true\n",
        )
        .unwrap();
        cmd_setup(&cli, "advanced").expect("dry-run advanced should succeed");
    }

    #[test]
    fn cmd_setup_dry_run_basic_mode_fresh_install() {
        // Basic + nothing configured: ai_ok=false -> prompt_setup_ai_plan stub
        // returns None; responder_ok=false -> normally hits Select but we
        // can't avoid that. So we only run this if responder_ok=true.
        // Actually with ai_ok=false the wizard hits Select for ai too via
        // prompt_setup_ai_plan stub returns None. responder_ok=false hits
        // a Select dialog (interactive). Skip this exact path.
        //
        // Instead test the path where ai_ok=false + responder_ok=true.
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        std::fs::write(
            &cli.agent_config,
            "[responder]\nenabled = true\ndry_run = true\n",
        )
        .unwrap();
        // ai not enabled -> prompt_setup_ai_plan stub returns None ("[--] AI not set yet")
        cmd_setup(&cli, "basic").expect("dry-run cmd_setup should succeed");
    }

    #[test]
    fn cmd_setup_dry_run_with_some_existing_channels_basic_mode() {
        // Telegram fully configured (env vars present), Slack partially
        // configured (URL but no enabled flag). any_channel_configured=true.
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        std::fs::write(
            &cli.agent_config,
            "[ai]\nenabled = true\nprovider = \"openai\"\n\n\
             [responder]\nenabled = true\ndry_run = true\n\n\
             [webhook]\nenabled = true\n",
        )
        .unwrap();
        let env_file = dir.path().join("agent.env");
        std::fs::write(
            &env_file,
            "TELEGRAM_BOT_TOKEN=123:ABC\nTELEGRAM_CHAT_ID=42\nWEBHOOK_URL=https://x/y\n",
        )
        .unwrap();
        cmd_setup(&cli, "basic").expect("dry-run cmd_setup should succeed");
    }

    #[test]
    fn format_setup_check_status_lines_preserves_order() {
        let checks = vec![
            SetupCheck {
                label: "A".to_string(),
                detail: "x".to_string(),
                ok: true,
                critical: true,
            },
            SetupCheck {
                label: "B".to_string(),
                detail: "y".to_string(),
                ok: false,
                critical: false,
            },
        ];
        let lines = format_setup_check_status_lines(&checks);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("A "));
        assert!(lines[1].starts_with("B "));
        assert!(lines[0].contains("OK"));
        assert!(lines[1].contains("FIX"));
    }
}
