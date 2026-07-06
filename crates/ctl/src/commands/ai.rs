use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;

use crate::{config_editor, prompt, require_sudo, restart_agent, systemd, write_env_key, Cli};

/// Default Azure OpenAI `api-version` written by `configure ai azure_openai`.
/// This is the stable chat-completions version the agent's azure provider
/// targets; operators can override it by editing `[ai].api_version`.
pub(crate) const AZURE_DEFAULT_API_VERSION: &str = "2024-12-01-preview";

#[derive(Debug, Clone, Copy)]
pub(crate) struct WizardProvider {
    pub(crate) name: &'static str,
    pub(crate) label: &'static str,
    pub(crate) signup_url: &'static str,
    pub(crate) models_url: &'static str,
    pub(crate) api_style: &'static str,
}

pub(crate) const WIZARD_PROVIDERS: &[WizardProvider] = &[
    WizardProvider {
        name: "openai",
        label: "OpenAI",
        signup_url: "platform.openai.com",
        models_url: "https://api.openai.com",
        api_style: "openai",
    },
    WizardProvider {
        name: "anthropic",
        label: "Anthropic",
        signup_url: "console.anthropic.com",
        models_url: "https://api.anthropic.com",
        api_style: "anthropic",
    },
    WizardProvider {
        name: "groq",
        label: "Groq",
        signup_url: "console.groq.com",
        models_url: "https://api.groq.com/openai",
        api_style: "openai",
    },
    WizardProvider {
        name: "deepseek",
        label: "DeepSeek",
        signup_url: "platform.deepseek.com",
        models_url: "https://api.deepseek.com",
        api_style: "openai",
    },
    WizardProvider {
        name: "together",
        label: "Together",
        signup_url: "api.together.ai",
        models_url: "https://api.together.xyz",
        api_style: "openai",
    },
    WizardProvider {
        name: "minimax",
        label: "MiniMax",
        signup_url: "platform.minimaxi.com",
        models_url: "https://api.minimaxi.chat",
        api_style: "openai",
    },
    WizardProvider {
        name: "mistral",
        label: "Mistral",
        signup_url: "console.mistral.ai",
        models_url: "https://api.mistral.ai",
        api_style: "openai",
    },
    WizardProvider {
        name: "xai",
        label: "xAI / Grok",
        signup_url: "console.x.ai",
        models_url: "https://api.x.ai",
        api_style: "openai",
    },
    WizardProvider {
        name: "fireworks",
        label: "Fireworks",
        signup_url: "fireworks.ai",
        models_url: "https://api.fireworks.ai/inference",
        api_style: "openai",
    },
    WizardProvider {
        name: "openrouter",
        label: "OpenRouter",
        signup_url: "openrouter.ai",
        models_url: "https://openrouter.ai/api",
        api_style: "openai",
    },
    WizardProvider {
        name: "gemini",
        label: "Google Gemini",
        signup_url: "aistudio.google.com",
        models_url: "https://generativelanguage.googleapis.com",
        api_style: "gemini",
    },
];

fn models_url(base_url: &str, api_key: &str, api_style: &str) -> String {
    match api_style {
        "anthropic" => format!("{base_url}/v1/models"),
        "ollama" => format!("{base_url}/api/tags"),
        "gemini" => format!("{base_url}/v1beta/models?key={api_key}"),
        _ => format!("{base_url}/v1/models"),
    }
}

fn parse_models_response(body: &serde_json::Value, api_style: &str) -> Vec<String> {
    if api_style == "gemini" {
        body.get("models")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        m.get("name")
                            .and_then(|n| n.as_str())
                            .map(|s| s.strip_prefix("models/").unwrap_or(s).to_string())
                    })
                    .filter(|m| {
                        let l = m.to_lowercase();
                        l.contains("gemini") && !l.contains("embed") && !l.contains("aqa")
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else if api_style == "ollama" {
        body.get("models")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        m.get("name")
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        body.get("data")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        m.get("id")
                            .and_then(|id| id.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn is_inference_model(model: &str) -> bool {
    let l = model.to_lowercase();
    !l.contains("embed")
        && !l.contains("tts")
        && !l.contains("whisper")
        && !l.contains("dall-e")
        && !l.contains("davinci")
        && !l.contains("babbage")
        && !l.contains("moderation")
        && !l.contains("search")
}

fn filter_inference_models(models: Vec<String>) -> Vec<String> {
    let mut filtered: Vec<String> = models
        .into_iter()
        .filter(|m| is_inference_model(m))
        .collect();
    filtered.sort();
    filtered
}

fn choose_model_from_input(models: &[String], choice: &str) -> String {
    let trimmed = choice.trim();
    if trimmed.is_empty() {
        return models[0].clone();
    }
    if let Ok(idx) = trimmed.parse::<usize>() {
        let idx = idx.saturating_sub(1).min(models.len() - 1);
        return models[idx].clone();
    }
    trimmed.to_string()
}

pub(crate) fn fetch_models(base_url: &str, api_key: &str, api_style: &str) -> Vec<String> {
    let url = models_url(base_url, api_key, api_style);

    let resp = match api_style {
        "anthropic" => ureq::get(&url)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .call(),
        "gemini" => ureq::get(&url).call(),
        _ => ureq::get(&url)
            .header("Authorization", &format!("Bearer {api_key}"))
            .call(),
    };

    let resp = match resp {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let body: serde_json::Value = match resp.into_body().read_json() {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let models = parse_models_response(&body, api_style);
    filter_inference_models(models)
}

fn ask_key_and_model(
    provider: &WizardProvider,
    custom_base_url: Option<&str>,
) -> Result<(String, Option<String>)> {
    println!(
        "{} - enter your API key (get one at {})",
        provider.label, provider.signup_url
    );
    let key = prompt("API key")?;
    if key.is_empty() {
        anyhow::bail!("API key cannot be empty");
    }

    let base_url = custom_base_url.unwrap_or(provider.models_url);
    print!("\n  Fetching available models...");
    std::io::stdout().flush().ok();
    let models = fetch_models(base_url, &key, provider.api_style);

    if models.is_empty() {
        println!(" could not fetch model list.");
        println!("  Enter a model name manually, or press Enter for the provider default.\n");
        let model = prompt("Model")?;
        let model = if model.is_empty() { None } else { Some(model) };
        return Ok((key, model));
    }

    println!(" found {} models.\n", models.len());
    let show = models.len().min(20);
    for (i, m) in models.iter().take(show).enumerate() {
        println!("  {:>2}. {}", i + 1, m);
    }
    if models.len() > show {
        println!(
            "  ... and {} more (type the name to use any)",
            models.len() - show
        );
    }
    println!();
    let model_choice = prompt(&format!("Model [1-{show}, or type name, default=1]"))?;
    let model = choose_model_from_input(&models, &model_choice);

    Ok((key, Some(model)))
}

pub(crate) fn cmd_configure_ai_interactive(cli: &Cli) -> Result<()> {
    println!("InnerWarden - AI provider setup\n");
    println!("InnerWarden uses AI to evaluate threats and decide how to respond.");
    println!("Choose a provider - any one works. Pick what you already have:\n");
    for (i, p) in WIZARD_PROVIDERS.iter().enumerate() {
        println!("  {}. {}", i + 1, p.label);
    }
    let ollama_idx = WIZARD_PROVIDERS.len() + 1;
    let other_idx = WIZARD_PROVIDERS.len() + 2;
    println!("  {ollama_idx}. Ollama       - local, no API key needed");
    println!("  {other_idx}. Other        - any OpenAI-compatible API");
    println!("  s. Skip for now\n");

    let choice = prompt(&format!("Choose provider [1-{other_idx}/s]"))?;
    println!();

    let trimmed = choice.trim().to_lowercase();
    if trimmed == "s" {
        println!("Skipped. Run later:  innerwarden configure ai <provider> --key <key>");
        return Ok(());
    }

    let num: usize = trimmed.parse().unwrap_or(0);

    if num >= 1 && num <= WIZARD_PROVIDERS.len() {
        let provider = &WIZARD_PROVIDERS[num - 1];
        let (key, model) = ask_key_and_model(provider, None)?;
        cmd_configure_ai(cli, provider.name, Some(&key), model.as_deref(), None)
    } else if num == ollama_idx {
        let local_models = fetch_models("http://localhost:11434", "", "ollama");
        if local_models.is_empty() {
            println!("Ollama not running locally. Installing...\n");
            cmd_ai_install(cli, "qwen3-coder:480b", None, false)
        } else {
            println!("Found {} local Ollama models:\n", local_models.len());
            for (i, m) in local_models.iter().enumerate() {
                println!("  {}. {}", i + 1, m);
            }
            println!();
            let mc = prompt(&format!("Model [1-{}, default=1]", local_models.len()))?;
            let idx = mc
                .trim()
                .parse::<usize>()
                .unwrap_or(1)
                .saturating_sub(1)
                .min(local_models.len() - 1);
            cmd_configure_ai(cli, "ollama", None, Some(&local_models[idx]), None)
        }
    } else if num == other_idx {
        println!("Any provider with an OpenAI-compatible API works.\n");
        let name = prompt("Provider name (e.g. fireworks, openrouter, together)")?;
        let base_url = prompt("Base URL (e.g. https://api.example.com)")?;
        if base_url.is_empty() {
            anyhow::bail!("Base URL is required");
        }
        println!("\n{name} - enter your API key");
        let key = prompt("API key")?;
        if key.is_empty() {
            anyhow::bail!("API key cannot be empty");
        }
        print!("\n  Fetching available models...");
        std::io::stdout().flush().ok();
        let models = fetch_models(&base_url, &key, "openai");
        let model = if models.is_empty() {
            println!(" could not fetch model list.");
            let m = prompt("Model name")?;
            if m.is_empty() {
                None
            } else {
                Some(m)
            }
        } else {
            println!(" found {} models.\n", models.len());
            let show = models.len().min(20);
            for (i, m) in models.iter().take(show).enumerate() {
                println!("  {:>2}. {}", i + 1, m);
            }
            println!();
            let mc = prompt(&format!("Model [1-{show}, default=1]"))?;
            Some(choose_model_from_input(&models, &mc))
        };
        cmd_configure_ai(cli, &name, Some(&key), model.as_deref(), Some(&base_url))
    } else {
        println!("Skipped. Run later:  innerwarden configure ai <provider> --key <key>");
        Ok(())
    }
}

pub(crate) fn cmd_ai_install(
    cli: &Cli,
    model: &str,
    api_key_arg: Option<&str>,
    yes: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let is_macos = std::env::consts::OS == "macos";

    // Resolve API key: --api-key flag > OLLAMA_API_KEY env var > interactive prompt
    let api_key = if let Some(k) = api_key_arg {
        k.to_string()
    } else if let Ok(k) = std::env::var("OLLAMA_API_KEY") {
        if !k.is_empty() {
            k
        } else {
            prompt_ollama_api_key()?
        }
    } else {
        prompt_ollama_api_key()?
    };

    println!("InnerWarden AI - Ollama cloud setup");
    println!();
    println!("  Provider: Ollama cloud (https://api.ollama.com)");
    println!("  Model:    {model}");
    let masked = "*".repeat(api_key.len().min(12));
    println!("  API key:  {masked} (masked)");
    println!();

    if !yes {
        print!("Configure innerwarden-agent with these settings? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_lowercase();
        if !trimmed.is_empty() && trimmed != "y" {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Configure agent.toml and restart
    println!("[1/2] Updating innerwarden-agent config...");
    if cli.dry_run {
        println!(
            "  [dry-run] would set [ai] enabled=true provider=ollama model={model} base_url=https://api.ollama.com api_key=<redacted>"
        );
    } else {
        config_editor::write_bool(&cli.agent_config, "ai", "enabled", true)?;
        config_editor::write_str(&cli.agent_config, "ai", "provider", "ollama")?;
        config_editor::write_str(&cli.agent_config, "ai", "model", model)?;
        config_editor::write_str(
            &cli.agent_config,
            "ai",
            "base_url",
            "https://api.ollama.com",
        )?;
        config_editor::write_str(&cli.agent_config, "ai", "api_key", &api_key)?;
        println!("  [ok] agent.toml updated");
    }

    println!("[2/2] Restarting innerwarden-agent...");
    if cli.dry_run {
        println!("  [dry-run] would restart innerwarden-agent");
    } else {
        if is_macos {
            systemd::restart_launchd("com.innerwarden.agent", false)?;
        } else {
            systemd::restart_service("innerwarden-agent", false)?;
        }
        println!("  [ok] innerwarden-agent restarted");
    }

    println!();
    println!("Done. Ollama cloud AI is active.");
    println!("Model:   {model}");
    println!("Tier:    Free (check https://ollama.com/pricing for limits)");
    println!();
    println!("Run 'innerwarden doctor' to validate the connection.");
    Ok(())
}

pub(crate) fn cmd_configure_ai(
    cli: &Cli,
    provider: &str,
    key: Option<&str>,
    model: Option<&str>,
    base_url: Option<&str>,
) -> Result<()> {
    cmd_configure_ai_with_restart(cli, provider, key, model, base_url, true)
}

fn cmd_configure_ai_with_restart(
    cli: &Cli,
    provider: &str,
    key: Option<&str>,
    model: Option<&str>,
    base_url: Option<&str>,
    restart: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    // "azure" is the natural name a user types; the agent's provider id is
    // "azure_openai". Alias it so the config that lands is actually usable
    // instead of a silently-wrong `provider = "azure"` the agent can't load.
    let provider = if provider.eq_ignore_ascii_case("azure") {
        "azure_openai"
    } else {
        provider
    };
    let is_azure = provider == "azure_openai";
    let (default_model, key_var, default_base_url) =
        crate::commands::setup::ai_provider_defaults(provider);
    let model = model.unwrap_or(&default_model);

    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    if let Some(var) = key_var {
        let k = key.ok_or_else(|| {
            anyhow::anyhow!(
                "provider '{}' requires an API key.\nRun:\n  innerwarden configure ai {} --key <your-key>",
                provider,
                provider
            )
        })?;

        if cli.dry_run {
            println!(
                "  [dry-run] would write {}=<redacted> to {}",
                var,
                env_file.display()
            );
        } else {
            write_env_key(&env_file, &var, k)?;
            println!("  [ok] {var} saved to {}", env_file.display());
        }
    }

    let base_url = base_url.or(default_base_url.as_deref());

    // Azure OpenAI has no fixed endpoint — it is per-resource. Without it the
    // agent builds `/openai/deployments/<model>/chat/completions?...` against an
    // empty host and every request 404s with no obvious cause. Fail loudly at
    // configure-time instead of writing a config that silently never works.
    if is_azure && base_url.is_none() {
        anyhow::bail!(
            "provider 'azure_openai' requires --base-url (your Azure resource endpoint).\nRun:\n  innerwarden configure ai azure_openai --key <key> --model <deployment> --base-url https://<resource>.openai.azure.com"
        );
    }

    if cli.dry_run {
        match base_url {
            Some(url) => println!(
                "  [dry-run] would set [ai] enabled=true provider={provider} model={model} base_url={url} in {}",
                cli.agent_config.display()
            ),
            None => println!(
                "  [dry-run] would set [ai] enabled=true provider={provider} model={model} in {}",
                cli.agent_config.display()
            ),
        }
        if is_azure {
            println!("  [dry-run] would set [ai] api_version={AZURE_DEFAULT_API_VERSION}");
        }
    } else {
        config_editor::write_bool(&cli.agent_config, "ai", "enabled", true)?;
        config_editor::write_str(&cli.agent_config, "ai", "provider", provider)?;
        config_editor::write_str(&cli.agent_config, "ai", "model", model)?;
        if let Some(url) = base_url {
            config_editor::write_str(&cli.agent_config, "ai", "base_url", url)?;
        }
        // Azure's chat endpoint is versioned via a required `api-version` query
        // param. The agent reads it from [ai].api_version; if we leave it empty
        // the URL ends in `?api-version=` and Azure rejects it. Write a known-good
        // default so a fresh `configure ai azure_openai` works with no extra step.
        if is_azure {
            config_editor::write_str(
                &cli.agent_config,
                "ai",
                "api_version",
                AZURE_DEFAULT_API_VERSION,
            )?;
            println!("  [ok] api_version set to {AZURE_DEFAULT_API_VERSION} (edit agent.toml to override)");
        }
        println!("  [ok] agent.toml updated (provider={provider}, model={model})");
    }

    if restart {
        restart_agent(cli);
    }
    println!("AI configured. Run 'innerwarden doctor' to validate.");
    Ok(())
}

pub(crate) fn prompt_ollama_api_key() -> Result<String> {
    println!("Ollama API key required.");
    println!();
    println!("  1. Create a free account at https://ollama.com");
    println!("  2. Go to https://ollama.com/settings/api-keys");
    println!("  3. Click 'New API Key', copy the key, and paste it below.");
    println!();
    print!("Ollama API key: ");
    std::io::stdout().flush()?;
    let mut key = String::new();
    std::io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();
    if key.is_empty() {
        anyhow::bail!(
            "No API key provided.\n\
             You can also set the OLLAMA_API_KEY environment variable and re-run."
        );
    }
    Ok(key)
}

// ---------------------------------------------------------------------------
// Local SecureBERT classifier installer
// ---------------------------------------------------------------------------

/// Pinned release artifact metadata for the supported classifier
/// variants. URL stays in one place so air-gapped operators can pull
/// the same archive from a mirror with `--url`.
pub(crate) struct ClassifierVariant {
    /// Name accepted on the CLI.
    name: &'static str,
    /// Default GitHub release URL.
    url: &'static str,
    /// SHA-256 of the tar.gz archive at the URL above.
    sha256: &'static str,
    /// Approximate uncompressed size, used in the operator preview.
    approx_size_mb: u32,
    /// Brief one-liner shown in the preview.
    description: &'static str,
}

const CLASSIFIER_VARIANTS: &[ClassifierVariant] = &[
    ClassifierVariant {
        name: "minilm-l6",
        // Pinned to `classifier-v1` GitHub release published 2026-05-16
        // (issue #642). Tarball contains model.onnx + model.onnx.data +
        // tokenizer.json + meta.json + validation_report.json from the
        // minilm-l6-distill-v2 training run.
        url: "https://github.com/InnerWarden/innerwarden/releases/download/classifier-v1/minilm-l6.tar.gz",
        sha256: "7c1745fd64e809b698d4a3ee0edbaaf3102f8c80f5dc724347a07fc154698c3b",
        approx_size_mb: 87,
        description: "MiniLM L6 distilled (87 MB, ~60 ms p50 on ARM, recommended)",
    },
    ClassifierVariant {
        name: "roberta-v1",
        // roberta-v1 (the SecureBERT teacher, ~474 MB) is not in the
        // `classifier-v1` release yet — the 80 MB MiniLM-L6 student
        // ships first because its F1 (0.793) matches the teacher's
        // (0.791) at a fifth of the disk / RAM cost. Operators who want
        // the heavier model can still install today by passing both
        // `--url` and `--sha256` against a private mirror; the next
        // `classifier-v2` cut will add the teacher artefact.
        url: "https://github.com/InnerWarden/innerwarden/releases/download/classifier-v1/roberta-v1.tar.gz",
        sha256: "TBD-publish-pin-after-release",
        approx_size_mb: 478,
        description: "RoBERTa V1 (478 MB, full precision, validated 0.975 on block_ip)",
    },
];

const CLASSIFIER_INSTALL_DIR: &str = "/var/lib/innerwarden/models/classifier";

/// Resolve a CLI variant name to its pinned metadata. Pure helper so
/// the `--model` validation has its own unit test without touching
/// the network.
pub(crate) fn resolve_classifier_variant(name: &str) -> Option<&'static ClassifierVariant> {
    CLASSIFIER_VARIANTS.iter().find(|v| v.name == name)
}

/// `innerwarden install-warden` (formerly `install-classifier`) —
/// fetch and install the Local Warden Model files used by the
/// agent's `local_warden` AI provider. Replaces the deleted
/// defender-brain pipeline.
pub(crate) fn cmd_install_classifier(
    cli: &Cli,
    model: &str,
    url_override: Option<&str>,
    sha256_override: Option<&str>,
    yes: bool,
    configure: bool,
) -> Result<()> {
    cmd_install_classifier_with_target(
        cli,
        model,
        url_override,
        sha256_override,
        yes,
        configure,
        CLASSIFIER_INSTALL_DIR,
    )
}

/// Write the canonical `[ai.warden]` section into `agent_config` so the
/// agent's provider resolver picks the on-device Decide head on its next
/// restart. Shared by `install-warden --configure` (headless / install.sh)
/// and the interactive setup wizard so the two paths can never drift.
///
/// Emits `enabled = true` explicitly. The agent now also infers an
/// omitted `enabled` from a non-empty `provider`
/// (`RoleProviderConfig::is_active`), but writing the flag keeps the
/// generated `agent.toml` self-documenting and immune to any future
/// change in that inference. Pre-2026-05-29 this helper wrote only
/// `provider` + `base_url`; the section then parsed with
/// `enabled = false` and the on-device model - already downloaded and
/// SHA-verified on disk - was silently never loaded (release-blocker
/// B1 in the readiness audit).
pub(crate) fn write_warden_config(agent_config: &std::path::Path, base_url: &str) -> Result<()> {
    crate::config_editor::write_bool(agent_config, "ai.warden", "enabled", true)?;
    crate::config_editor::write_str(agent_config, "ai.warden", "provider", "local_warden")?;
    crate::config_editor::write_str(agent_config, "ai.warden", "base_url", base_url)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_install_classifier_with_target(
    cli: &Cli,
    model: &str,
    url_override: Option<&str>,
    sha256_override: Option<&str>,
    yes: bool,
    configure: bool,
    target_dir: &str,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }

    let variant = resolve_classifier_variant(model).ok_or_else(|| {
        let supported: Vec<&str> = CLASSIFIER_VARIANTS.iter().map(|v| v.name).collect();
        anyhow::anyhow!(
            "unknown classifier variant `{model}`. Supported: {}",
            supported.join(", ")
        )
    })?;

    let url = url_override.unwrap_or(variant.url);
    let expected_sha = sha256_override.unwrap_or(variant.sha256);

    println!("InnerWarden Local Warden Model install");
    println!();
    println!("  Variant: {} - {}", variant.name, variant.description);
    println!("  URL:     {url}");
    println!("  SHA-256: {expected_sha}");
    println!("  Target:  {target_dir}");
    println!("  Size:    ~{} MB", variant.approx_size_mb);
    println!();
    println!("Local Warden Model replaces the (now removed) AlphaZero defender brain.");
    println!("With `--configure` this writes `[ai.warden]` (enabled = true, provider =");
    println!("\"local_warden\", base_url = \"{target_dir}\") so the agent loads the");
    println!("on-device Decide head on its next restart. Without `--configure`, run");
    println!("`innerwarden configure ai` after install to wire the slot.");
    println!();

    if expected_sha.starts_with("TBD") {
        // The compiled-in SHA is a placeholder because the model release
        // (tag `classifier-v1` / artefact `minilm-l6.tar.gz`) has not been
        // published yet — see InnerWarden/innerwarden#642 for status. Two
        // workarounds:
        //   - operator-side: pass `--url <signed-url> --sha256 <hex>` to
        //     install from a private mirror that has the artefact;
        //   - wait for the release to land and rerun `install-warden`.
        // Either way we refuse to install without a real hash so we never
        // silently ship an unverified model file.
        println!("WARNING: pinned SHA-256 not published yet. The `classifier-v1` release that");
        println!("         ships the model artefact has not been cut — see issue #642");
        println!("         (https://github.com/InnerWarden/innerwarden/issues/642) for status.");
        println!();
        println!("To install today, pass both flags so the integrity check still runs:");
        println!("  sudo innerwarden install-warden --url <mirror-url> --sha256 <hex-digest>");
        println!();
        println!("Refusing to install without a verified hash. The agent will fall back to the");
        println!("configured cloud AI provider for `Decide` until the local classifier lands.");
        // Test anchor (line 1188): the error string must contain
        // "requires --sha256" so the existing
        // cmd_install_classifier_with_target_requires_sha_until_pinned
        // test still catches this branch.
        anyhow::bail!(
            "Local Warden install requires --sha256: the compiled-in pin is a placeholder \
             until the `classifier-v1` release lands (see InnerWarden/innerwarden#642). \
             Pass --url and --sha256 from a trusted mirror, or wait for the release."
        );
    }

    let stdin = std::io::stdin();
    let mut stdin_lock = stdin.lock();
    if !confirm_install(yes, &mut stdin_lock)? {
        println!("Aborted.");
        return Ok(());
    }

    if cli.dry_run {
        println!("[dry-run] would download {url}");
        println!("[dry-run] would verify SHA-256 against {expected_sha}");
        println!("[dry-run] would extract into {target_dir}");
        if configure {
            println!(
                "[dry-run] would write [ai.warden] into {}",
                cli.agent_config.display()
            );
        }
        return Ok(());
    }

    install_classifier_archive(url, expected_sha, target_dir)?;

    // `--configure` (used by install.sh headless provisioning): wire the
    // [ai.warden] section in the same shot so the model is not just on disk
    // but actually selected as the Decide provider. Without it the operator
    // must run `innerwarden configure ai` separately.
    if configure {
        write_warden_config(&cli.agent_config, target_dir)?;
        println!();
        println!(
            "Wired [ai.warden] in {} (provider=local_warden).",
            cli.agent_config.display()
        );
    }

    println!();
    println!("Done. Restart the agent to load the classifier:");
    println!("  {}", agent_restart_hint());
    Ok(())
}

/// Platform-correct "restart the agent" command line. macOS uses launchd, not
/// systemd, so `systemctl restart` there is a no-op that misleads the user (F6).
fn agent_restart_hint() -> &'static str {
    agent_restart_hint_for(cfg!(target_os = "macos"))
}

/// Pure inner (tested for both platforms on the Linux CI host).
fn agent_restart_hint_for(mac: bool) -> &'static str {
    if mac {
        "sudo launchctl kickstart -k system/com.innerwarden.agent"
    } else {
        "sudo systemctl restart innerwarden-agent"
    }
}

fn confirm_install<R: std::io::BufRead>(yes: bool, input: &mut R) -> Result<bool> {
    if yes {
        return Ok(true);
    }

    print!("Proceed with install? [Y/n] ");
    std::io::stdout().flush()?;

    let mut line = String::new();
    input.read_line(&mut line)?;
    let trimmed = line.trim().to_lowercase();
    Ok(trimmed.is_empty() || trimmed == "y")
}

/// Download the archive at `url`, verify the SHA-256, and extract it
/// into `target_dir`. Split out so the operator-facing wrapper can
/// stay short and the IO logic has a clear seam for future tests.
fn install_classifier_archive(url: &str, expected_sha: &str, target_dir: &str) -> Result<()> {
    use std::process::Command;

    let target = std::path::Path::new(target_dir);
    std::fs::create_dir_all(target).map_err(|e| anyhow::anyhow!("create {target_dir}: {e}"))?;

    let tmp = std::env::temp_dir().join("innerwarden-classifier.tar.gz");

    println!("[1/3] Downloading...");
    let status = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(&tmp)
        .arg(url)
        .status()
        .map_err(|e| anyhow::anyhow!("spawn curl: {e}"))?;
    if !status.success() {
        anyhow::bail!("curl failed (exit {status})");
    }

    println!("[2/3] Verifying SHA-256...");
    let bytes = std::fs::read(&tmp)?;
    let actual = sha256_hex(&bytes);
    if actual != expected_sha {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("SHA-256 mismatch: expected {expected_sha}, got {actual}");
    }

    println!("[3/3] Extracting into {target_dir}...");
    // Capture stderr so we can drop the harmless macOS-xattr noise: the model
    // tarball is packaged on macOS, which stamps `com.apple.provenance` extended
    // headers that GNU tar on Linux doesn't recognise and warns about once per
    // file ("Ignoring unknown extended header keyword 'LIBARCHIVE.xattr...'").
    // The files extract fine; the warnings just look alarming. We filter only
    // those lines and pass any real tar error through. Portable (no
    // GNU-tar-only `--warning=` flag that would break bsdtar on macOS).
    let output = Command::new("tar")
        .args(["-xzf"])
        .arg(&tmp)
        .args(["-C", target_dir])
        .output()
        .map_err(|e| anyhow::anyhow!("spawn tar: {e}"))?;
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        if line.contains("Ignoring unknown extended header keyword") {
            continue;
        }
        eprintln!("{line}");
    }
    if !output.status.success() {
        anyhow::bail!("tar failed (exit {})", output.status);
    }
    let _ = std::fs::remove_file(&tmp);
    Ok(())
}

/// Hex SHA-256 of a byte slice. Pure helper kept private; the variant
/// catalogue tests exercise it indirectly.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read as _};
    use std::net::TcpListener;
    use std::process::Command as ProcessCommand;
    use std::sync::{Mutex, OnceLock};
    use std::thread;

    /// F6 anchor (2026-07-01): the post-install restart hint uses the host's
    /// real service manager — launchd on macOS, systemd elsewhere.
    #[test]
    fn agent_restart_hint_matches_platform() {
        let h = agent_restart_hint();
        if cfg!(target_os = "macos") {
            assert!(h.contains("launchctl"));
            assert!(!h.contains("systemctl"));
        } else {
            assert!(h.contains("systemctl restart innerwarden-agent"));
        }
    }

    #[test]
    fn agent_restart_hint_for_both_platforms() {
        assert!(agent_restart_hint_for(true).contains("launchctl kickstart"));
        assert!(agent_restart_hint_for(false).contains("systemctl restart innerwarden-agent"));
    }
    use tempfile::TempDir;

    fn install_archive_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn make_cli(data_dir: &std::path::Path, dry_run: bool) -> Cli {
        Cli {
            sensor_config: data_dir.join("config.toml"),
            agent_config: data_dir.join("agent.toml"),
            data_dir: data_dir.to_path_buf(),
            dry_run,
            command: None,
        }
    }

    fn create_classifier_archive(tmp: &TempDir, name: &str) -> (std::path::PathBuf, String) {
        let payload = tmp.path().join("payload");
        std::fs::create_dir_all(&payload).expect("create payload dir");
        std::fs::write(payload.join("model.onnx"), b"fake-model").expect("write model");
        std::fs::write(payload.join("tokenizer.json"), br#"{"type":"fake"}"#)
            .expect("write tokenizer");

        let archive = tmp.path().join(name);
        let status = ProcessCommand::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&payload)
            .arg("model.onnx")
            .arg("tokenizer.json")
            .status()
            .expect("spawn tar");
        assert!(status.success(), "tar failed with status {status}");

        let bytes = std::fs::read(&archive).expect("read archive");
        let sha = sha256_hex(&bytes);
        (archive, sha)
    }

    fn serve_models_once(body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind model test server");
        let addr = listener.local_addr().expect("test server address");
        let body = body.to_string();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept model request");
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write model response");
        });
        format!("http://{addr}")
    }

    #[test]
    fn wizard_providers_have_unique_names_and_supported_styles() {
        let mut names = std::collections::BTreeSet::new();
        for provider in WIZARD_PROVIDERS {
            assert!(!provider.name.is_empty());
            assert!(!provider.label.is_empty());
            assert!(!provider.signup_url.is_empty());
            assert!(provider.models_url.starts_with("https://"));
            assert!(matches!(
                provider.api_style,
                "openai" | "anthropic" | "gemini"
            ));
            assert!(
                names.insert(provider.name),
                "duplicate wizard provider: {}",
                provider.name
            );
        }
        assert!(names.contains("openai"));
        assert!(names.contains("gemini"));
    }

    #[test]
    fn models_url_builds_expected_paths_per_api_style() {
        // Ensures provider-specific model-discovery endpoints remain stable.
        assert_eq!(
            models_url("https://api.example.com", "k", "openai"),
            "https://api.example.com/v1/models"
        );
        assert_eq!(
            models_url("https://api.example.com", "k", "anthropic"),
            "https://api.example.com/v1/models"
        );
        assert_eq!(
            models_url("https://api.example.com", "k", "ollama"),
            "https://api.example.com/api/tags"
        );
        assert_eq!(
            models_url("https://api.example.com", "k", "gemini"),
            "https://api.example.com/v1beta/models?key=k"
        );
    }

    #[test]
    fn parse_models_response_openai_reads_data_ids() {
        // Covers OpenAI-compatible response parsing used by most providers in the wizard.
        let body = serde_json::json!({
            "data": [
                { "id": "gpt-4.1" },
                { "id": "gpt-4o-mini" }
            ]
        });
        let models = parse_models_response(&body, "openai");
        assert_eq!(models, vec!["gpt-4.1", "gpt-4o-mini"]);
    }

    #[test]
    fn parse_models_response_returns_empty_for_malformed_shapes() {
        assert!(parse_models_response(&serde_json::json!({}), "openai").is_empty());
        assert!(parse_models_response(&serde_json::json!({ "data": {} }), "openai").is_empty());
        assert!(parse_models_response(&serde_json::json!({ "models": {} }), "ollama").is_empty());
        assert!(parse_models_response(&serde_json::json!({ "models": [] }), "gemini").is_empty());
    }

    #[test]
    fn parse_models_response_ollama_reads_model_names() {
        // Ensures Ollama local model listing maps from "models[].name" correctly.
        let body = serde_json::json!({
            "models": [
                { "name": "qwen3:latest" },
                { "name": "llama3.3:70b" }
            ]
        });
        let models = parse_models_response(&body, "ollama");
        assert_eq!(models, vec!["qwen3:latest", "llama3.3:70b"]);
    }

    #[test]
    fn parse_models_response_gemini_filters_non_generation_models() {
        // Verifies Gemini parsing keeps generation-capable models and excludes embed/aqa variants.
        let body = serde_json::json!({
            "models": [
                { "name": "models/gemini-2.5-pro" },
                { "name": "models/gemini-embedding-001" },
                { "name": "models/aqa" },
                { "name": "models/gemini-2.5-flash" }
            ]
        });
        let models = parse_models_response(&body, "gemini");
        assert_eq!(models, vec!["gemini-2.5-pro", "gemini-2.5-flash"]);
    }

    #[test]
    fn is_inference_model_rejects_non_inference_families() {
        // Guards model filtering so text-only and admin endpoints don't appear in responder choices.
        assert!(is_inference_model("gpt-4o-mini"));
        assert!(!is_inference_model("text-embedding-3-large"));
        assert!(!is_inference_model("dall-e-3"));
        assert!(!is_inference_model("whisper-1"));
        assert!(!is_inference_model("omni-moderation-latest"));
    }

    #[test]
    fn filter_inference_models_filters_and_sorts_models() {
        // Ensures final model list is deterministic and excludes unsupported classes.
        let models = vec![
            "zeta-model".to_string(),
            "text-embedding-3-small".to_string(),
            "alpha-model".to_string(),
        ];
        let filtered = filter_inference_models(models);
        assert_eq!(filtered, vec!["alpha-model", "zeta-model"]);
    }

    #[test]
    fn fetch_models_openai_reads_filters_and_sorts_local_response() {
        let base = serve_models_once(
            r#"{"data":[{"id":"zeta-chat"},{"id":"text-embedding-3-small"},{"id":"alpha-chat"}]}"#,
        );

        let models = fetch_models(&base, "test-key", "openai");

        assert_eq!(models, vec!["alpha-chat", "zeta-chat"]);
    }

    #[test]
    fn fetch_models_gemini_reads_local_response() {
        let base = serve_models_once(
            r#"{"models":[{"name":"models/gemini-2.5-pro"},{"name":"models/gemini-embedding-001"}]}"#,
        );

        let models = fetch_models(&base, "test-key", "gemini");

        assert_eq!(models, vec!["gemini-2.5-pro"]);
    }

    #[test]
    fn fetch_models_anthropic_reads_local_response() {
        let base = serve_models_once(
            r#"{"data":[{"id":"claude-haiku-4-5-20251001"},{"id":"text-embedding-3-small"}]}"#,
        );

        let models = fetch_models(&base, "test-key", "anthropic");

        assert_eq!(models, vec!["claude-haiku-4-5-20251001"]);
    }

    #[test]
    fn fetch_models_ollama_reads_local_response() {
        let base = serve_models_once(
            r#"{"models":[{"name":"qwen3-coder:480b"},{"name":"nomic-embed-text"}]}"#,
        );

        let models = fetch_models(&base, "", "ollama");

        assert_eq!(models, vec!["qwen3-coder:480b"]);
    }

    #[test]
    fn fetch_models_returns_empty_on_malformed_json() {
        let base = serve_models_once("not-json");

        let models = fetch_models(&base, "test-key", "openai");

        assert!(models.is_empty());
    }

    #[test]
    fn choose_model_from_input_uses_default_for_empty_choice() {
        // Covers default-selection branch to keep interactive UX predictable.
        let models = vec!["first".to_string(), "second".to_string()];
        assert_eq!(choose_model_from_input(&models, ""), "first");
    }

    #[test]
    fn choose_model_from_input_supports_index_and_name() {
        // Exercises numeric selection and free-form model selection in one place.
        let models = vec!["first".to_string(), "second".to_string()];
        assert_eq!(choose_model_from_input(&models, "2"), "second");
        assert_eq!(
            choose_model_from_input(&models, "custom-model"),
            "custom-model"
        );
    }

    #[test]
    fn choose_model_from_input_clamps_numeric_choice() {
        let models = vec!["first".to_string(), "second".to_string()];
        assert_eq!(choose_model_from_input(&models, "0"), "first");
        assert_eq!(choose_model_from_input(&models, "999"), "second");
    }

    #[test]
    fn cmd_configure_ai_dry_run_requires_key_for_keyed_provider() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), true);

        let err = cmd_configure_ai(&cli, "openai", None, None, None)
            .expect_err("openai requires an API key");

        assert!(err.to_string().contains("requires an API key"));
    }

    #[test]
    fn cmd_configure_ai_dry_run_accepts_ollama_without_key() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), true);

        cmd_configure_ai(&cli, "ollama", None, Some("llama3.3"), None)
            .expect("ollama should not require an API key");
    }

    #[test]
    fn cmd_configure_ai_dry_run_accepts_custom_provider_base_url() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), true);

        cmd_configure_ai(
            &cli,
            "acme",
            Some("secret"),
            Some("acme-chat"),
            Some("https://api.acme.invalid"),
        )
        .expect("custom provider dry-run should accept explicit key and base url");
    }

    #[test]
    fn cmd_configure_ai_dry_run_uses_provider_defaults() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), true);

        cmd_configure_ai(&cli, "groq", Some("secret"), None, None)
            .expect("known provider should use default model and base url");
    }

    #[test]
    fn cmd_configure_ai_writes_config_and_env_without_restart_for_tests() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), false);

        cmd_configure_ai_with_restart(
            &cli,
            "openai",
            Some("sk-test"),
            Some("gpt-4.1-mini"),
            Some("https://api.openai.example"),
            false,
        )
        .expect("configure ai should write temp config");

        let agent = std::fs::read_to_string(&cli.agent_config).expect("read agent config");
        assert!(agent.contains("[ai]"));
        assert!(agent.contains("enabled = true"));
        assert!(agent.contains("provider = \"openai\""));
        assert!(agent.contains("model = \"gpt-4.1-mini\""));
        assert!(agent.contains("base_url = \"https://api.openai.example\""));

        let env = std::fs::read_to_string(tmp.path().join("agent.env")).expect("read agent env");
        assert_eq!(env, "OPENAI_API_KEY=sk-test\n");
    }

    #[test]
    fn cmd_configure_ai_azure_requires_base_url() {
        // Azure has no fixed endpoint; configuring it without --base-url would
        // write a config that silently 404s. Fail loudly instead.
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), true);

        let err = cmd_configure_ai(&cli, "azure_openai", Some("k"), Some("dep"), None)
            .expect_err("azure must require a base url");
        assert!(err.to_string().contains("requires --base-url"));
    }

    #[test]
    fn cmd_configure_ai_azure_alias_writes_api_version_and_provider() {
        // `azure` is aliased to `azure_openai` and a working api_version default
        // is written so the agent's chat endpoint is valid out of the box.
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), false);

        cmd_configure_ai_with_restart(
            &cli,
            "azure",
            Some("azure-key"),
            Some("gpt-5.4-mini"),
            Some("https://res.openai.azure.com"),
            false,
        )
        .expect("azure configure should write temp config");

        let agent = std::fs::read_to_string(&cli.agent_config).expect("read agent config");
        assert!(agent.contains("provider = \"azure_openai\""));
        assert!(agent.contains("model = \"gpt-5.4-mini\""));
        assert!(agent.contains("base_url = \"https://res.openai.azure.com\""));
        assert!(
            agent.contains(&format!("api_version = \"{AZURE_DEFAULT_API_VERSION}\"")),
            "azure config must persist a non-empty api_version: {agent}"
        );

        let env = std::fs::read_to_string(tmp.path().join("agent.env")).expect("read agent env");
        assert_eq!(env, "AZURE_OPENAI_API_KEY=azure-key\n");
    }

    #[test]
    fn cmd_ai_install_dry_run_accepts_explicit_key() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), true);

        cmd_ai_install(&cli, "qwen3-coder:480b", Some("ollama-test-key"), true)
            .expect("dry-run ollama install should not touch system services");
    }

    #[test]
    fn cmd_ai_install_dry_run_reads_key_from_environment() {
        let _guard = env_lock().lock().expect("env lock");
        let previous = std::env::var_os("OLLAMA_API_KEY");
        std::env::set_var("OLLAMA_API_KEY", "env-ollama-key");

        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), true);
        let result = cmd_ai_install(&cli, "qwen3-coder:480b", None, true);

        match previous {
            Some(value) => std::env::set_var("OLLAMA_API_KEY", value),
            None => std::env::remove_var("OLLAMA_API_KEY"),
        }

        result.expect("dry-run ollama install should read env key");
    }

    // ── install-classifier helpers ─────────────────────────────────────

    #[test]
    fn confirm_install_accepts_default_yes_and_explicit_yes() {
        let mut empty = Cursor::new(b"\n");
        assert!(confirm_install(false, &mut empty).expect("empty input accepted"));

        let mut yes = Cursor::new(b"y\n");
        assert!(confirm_install(false, &mut yes).expect("explicit yes accepted"));

        let mut ignored = Cursor::new(b"n\n");
        assert!(confirm_install(true, &mut ignored).expect("--yes bypasses prompt"));
    }

    #[test]
    fn confirm_install_rejects_negative_input() {
        let mut no = Cursor::new(b"n\n");
        assert!(!confirm_install(false, &mut no).expect("n rejects"));

        let mut no_word = Cursor::new(b"no\n");
        assert!(!confirm_install(false, &mut no_word).expect("no rejects"));
    }

    #[test]
    fn cmd_install_classifier_with_target_rejects_unknown_variant() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), false);
        let err = cmd_install_classifier_with_target(
            &cli,
            "unknown-model",
            None,
            Some("deadbeef"),
            true,
            false,
            tmp.path().to_str().expect("utf8 temp path"),
        )
        .expect_err("unknown variant must fail");

        let msg = err.to_string();
        assert!(msg.contains("unknown classifier variant"));
        assert!(msg.contains("minilm-l6"));
        assert!(msg.contains("roberta-v1"));
    }

    #[test]
    fn cmd_install_classifier_with_target_requires_sha_until_pinned() {
        // 2026-05-16: the `minilm-l6` variant landed in `classifier-v1`
        // with a real pinned SHA, so the placeholder branch no longer
        // fires for it. `roberta-v1` (the SecureBERT teacher) still
        // ships with a TBD pin until the next `classifier-v2` cut, and
        // it remains the anchor for this regression test.
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), true);
        let err = cmd_install_classifier_with_target(
            &cli,
            "roberta-v1",
            None,
            None,
            true,
            false,
            tmp.path().to_str().expect("utf8 temp path"),
        )
        .expect_err("missing override hash must fail until pin is published");

        assert!(
            err.to_string().contains("requires --sha256"),
            "error should mention --sha256, got: {err:#}"
        );
    }

    #[test]
    fn cmd_install_classifier_with_target_dry_run_allows_explicit_sha() {
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), true);
        // configure = true exercises the dry-run "would write [ai.warden]"
        // branch; dry-run must NOT actually touch agent.toml.
        cmd_install_classifier_with_target(
            &cli,
            "minilm-l6",
            Some("https://example.invalid/classifier.tar.gz"),
            Some("0123456789abcdef"),
            true,
            true,
            tmp.path().to_str().expect("utf8 temp path"),
        )
        .expect("dry-run with explicit hash should pass");
        assert!(
            !cli.agent_config.exists(),
            "dry-run must not write agent.toml"
        );
    }

    #[test]
    fn install_classifier_archive_rejects_sha_mismatch() {
        let _guard = install_archive_lock().lock().expect("lock");
        let tmp = TempDir::new().expect("tempdir");
        let target = tmp.path().join("target");
        let (archive, _sha) = create_classifier_archive(&tmp, "classifier.tar.gz");
        let url = format!("file://{}", archive.display());
        let err = install_classifier_archive(
            &url,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            target.to_str().expect("utf8 temp path"),
        )
        .expect_err("sha mismatch must fail");

        assert!(
            err.to_string().contains("SHA-256 mismatch"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn install_classifier_archive_reports_tar_error_for_invalid_archive() {
        let _guard = install_archive_lock().lock().expect("lock");
        let tmp = TempDir::new().expect("tempdir");
        let archive = tmp.path().join("broken.tar.gz");
        std::fs::write(&archive, b"this-is-not-a-tarball").expect("write bad archive");
        let sha = sha256_hex(&std::fs::read(&archive).expect("read bad archive"));
        let url = format!("file://{}", archive.display());
        let target = tmp.path().join("target");
        let err =
            install_classifier_archive(&url, &sha, target.to_str().expect("utf8 target path"))
                .expect_err("invalid archive must fail tar");

        assert!(
            err.to_string().contains("tar failed"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn cmd_install_classifier_with_target_installs_local_archive() {
        let _guard = install_archive_lock().lock().expect("lock");
        let tmp = TempDir::new().expect("tempdir");
        let cli = make_cli(tmp.path(), false);
        let target = tmp.path().join("installed");
        let (archive, sha) = create_classifier_archive(&tmp, "ok.tar.gz");
        let url = format!("file://{}", archive.display());

        cmd_install_classifier_with_target(
            &cli,
            "minilm-l6",
            Some(url.as_str()),
            Some(sha.as_str()),
            true,
            true, // configure -> also write [ai.warden]
            target.to_str().expect("utf8 target path"),
        )
        .expect("local install should succeed");

        assert!(target.join("model.onnx").is_file());
        assert!(target.join("tokenizer.json").is_file());
        // configure = true wired the on-device provider into agent.toml.
        let agent_toml = std::fs::read_to_string(&cli.agent_config).expect("agent.toml written");
        assert!(
            agent_toml.contains("provider = \"local_warden\""),
            "agent.toml must select local_warden, got: {agent_toml}"
        );
        // Release-blocker B1: the section MUST carry `enabled = true`,
        // otherwise the agent parses the slot as disabled and the model
        // is downloaded but never loaded.
        assert!(
            agent_toml.contains("enabled = true"),
            "agent.toml [ai.warden] must enable the slot, got: {agent_toml}"
        );
        assert!(agent_toml.contains(target.to_str().unwrap()));
    }

    #[test]
    fn write_warden_config_writes_canonical_section() {
        let tmp = TempDir::new().expect("tempdir");
        let agent_toml = tmp.path().join("agent.toml");
        write_warden_config(&agent_toml, "/var/lib/innerwarden/models/classifier")
            .expect("write [ai.warden]");
        let content = std::fs::read_to_string(&agent_toml).expect("read agent.toml");
        assert!(
            content.contains("enabled = true"),
            "must enable the slot: {content}"
        );
        assert!(content.contains("provider = \"local_warden\""));
        assert!(content.contains("/var/lib/innerwarden/models/classifier"));
    }

    #[test]
    fn resolve_classifier_variant_returns_known_names() {
        let v = resolve_classifier_variant("minilm-l6").expect("minilm-l6 known");
        assert_eq!(v.name, "minilm-l6");
        assert!(v.description.contains("MiniLM"));

        let v = resolve_classifier_variant("roberta-v1").expect("roberta-v1 known");
        assert_eq!(v.name, "roberta-v1");
    }

    #[test]
    fn resolve_classifier_variant_returns_none_for_unknown() {
        assert!(resolve_classifier_variant("not-a-real-variant").is_none());
        assert!(resolve_classifier_variant("").is_none());
    }

    #[test]
    fn sha256_hex_matches_known_test_vectors() {
        // Empty input vector is the canonical SHA-256 sanity check.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // "abc" — the second vector cited in FIPS 180-4 §6.2.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn classifier_variants_have_distinct_names() {
        // Catalogue invariant: the CLI dispatcher matches by name, so
        // duplicate names would silently shadow.
        let mut names: Vec<&str> = CLASSIFIER_VARIANTS.iter().map(|v| v.name).collect();
        names.sort_unstable();
        let unique = names
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        assert_eq!(unique, names.len(), "duplicate variant names: {names:?}");
    }
}
