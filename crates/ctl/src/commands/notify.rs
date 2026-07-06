use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};

use crate::{
    config_editor, hostname, load_env_file, prompt, prompt_with_hint, require_sudo, restart_agent,
    send_telegram_message_md, systemd, write_env_key, Cli,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestHourConfig {
    Disabled,
    Hour(u8),
}

fn is_valid_telegram_token(token: &str) -> bool {
    token.contains(':') && token.split(':').next().is_some_and(|s| !s.is_empty())
}

fn is_numeric_chat_id(chat_id: &str) -> bool {
    chat_id
        .trim_start_matches('-')
        .chars()
        .all(|c| c.is_ascii_digit())
}

fn is_valid_alert_severity(min_severity: &str) -> bool {
    matches!(min_severity, "low" | "medium" | "high" | "critical")
}

fn is_valid_slack_webhook_url(url: &str) -> bool {
    url.starts_with("https://hooks.slack.com/")
}

fn is_valid_webhook_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

fn channel_selected(test_only: Option<&str>, channel: &str) -> bool {
    test_only.is_none_or(|candidate| candidate == channel)
}

fn parse_digest_hour_config(hour_str: &str) -> Result<DigestHourConfig> {
    if matches!(hour_str, "off" | "none" | "disable") {
        return Ok(DigestHourConfig::Disabled);
    }

    let hour: u8 = hour_str
        .parse()
        .map_err(|_| anyhow::anyhow!("expected a number 0-23 or 'off', got '{hour_str}'"))?;
    if hour > 23 {
        anyhow::bail!("hour must be 0-23, got {hour}");
    }
    Ok(DigestHourConfig::Hour(hour))
}

pub(crate) fn cmd_configure_telegram(
    cli: &Cli,
    token_arg: Option<&str>,
    chat_id_arg: Option<&str>,
    no_test: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // ── Step 1: bot token ──────────────────────────────────────────────────
    let token = if let Some(t) = token_arg {
        t.to_string()
    } else {
        println!("InnerWarden - Telegram setup\n");
        println!("Step 1 - Create a bot");
        println!("  1. Open Telegram and message @BotFather");
        println!("  2. Send:  /newbot");
        println!("  3. Choose a name and username for your bot");
        println!("  4. Copy the token BotFather gives you (looks like 123456789:ABCdef...)\n");
        let t = prompt("Bot token")?;
        if t.is_empty() {
            anyhow::bail!("token cannot be empty");
        }
        t
    };

    // Basic format check: digits : alphanumeric
    if !is_valid_telegram_token(&token) {
        anyhow::bail!(
            "token looks wrong - expected format: 123456789:ABCdef...\nGet one from @BotFather on Telegram."
        );
    }

    // ── Step 2: chat ID ────────────────────────────────────────────────────
    let chat_id = if let Some(c) = chat_id_arg {
        c.to_string()
    } else {
        // Try to discover chat_id from pending updates (works if user already messaged the bot)
        let discovered = discover_telegram_chat_id(&token);

        match discovered {
            Some(id) => {
                println!("\n  Found your chat ID automatically: {id}");
                print!("  Use this chat ID? [Y/n] ");
                std::io::stdout().flush()?;
                let mut ans = String::new();
                std::io::stdin().read_line(&mut ans)?;
                if ans.trim().to_lowercase() == "n" {
                    let manual = prompt_with_hint(
                        "Chat ID",
                        "send a message to your bot first, then re-run",
                    )?;
                    if manual.is_empty() {
                        anyhow::bail!("chat ID cannot be empty");
                    }
                    manual
                } else {
                    id
                }
            }
            None => {
                println!();
                println!("  Now open Telegram and send any message to your bot.");
                println!("  Waiting for your message...");
                std::io::stdout().flush()?;

                // Long-poll getUpdates (5s timeout per request, up to 2 minutes total)
                let mut found = None;
                for _ in 0..24 {
                    if let Some(id) = discover_telegram_chat_id(&token) {
                        found = Some(id);
                        break;
                    }
                    // discover_telegram_chat_id already waits 5s via long poll
                    print!(".");
                    std::io::stdout().flush()?;
                }
                println!();

                match found {
                    Some(id) => {
                        println!("  ✓ Got it! Chat ID: {id}");
                        id
                    }
                    None => {
                        println!("  Timed out. Enter your chat ID manually:");
                        println!("  (Message @userinfobot on Telegram to get it)");
                        let c = prompt("Chat ID")?;
                        if c.is_empty() {
                            anyhow::bail!("chat ID cannot be empty");
                        }
                        c
                    }
                }
            }
        }
    };

    // Validate chat_id is numeric (may be negative for groups)
    if !is_numeric_chat_id(&chat_id) {
        anyhow::bail!(
            "chat ID must be a number (e.g. 123456789 for a user, -100... for a group).\nGet yours by messaging @userinfobot on Telegram."
        );
    }

    // ── Save credentials ───────────────────────────────────────────────────
    if cli.dry_run {
        println!(
            "\n  [dry-run] would write TELEGRAM_BOT_TOKEN=... to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would write TELEGRAM_CHAT_ID={chat_id} to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would set [telegram] enabled=true in {}",
            cli.agent_config.display()
        );
    } else {
        write_env_key(&env_file, "TELEGRAM_BOT_TOKEN", &token)?;
        write_env_key(&env_file, "TELEGRAM_CHAT_ID", &chat_id)?;
        println!("\n  [ok] Credentials saved to {}", env_file.display());

        config_editor::write_bool(&cli.agent_config, "telegram", "enabled", true)?;
        println!("  [ok] agent.toml: telegram.enabled = true");
    }

    // ── Test notification ──────────────────────────────────────────────────
    if !no_test && !cli.dry_run {
        print!("  Sending test notification... ");
        std::io::stdout().flush()?;
        match send_telegram_test(&token, &chat_id) {
            Ok(()) => println!("sent!"),
            Err(e) => {
                println!("failed");
                println!();
                println!("  Warning: could not send test message: {e:#}");
                println!("  Your credentials have been saved. Check token and chat_id with:");
                println!("  innerwarden doctor");
            }
        }
    }

    // ── Restart agent ──────────────────────────────────────────────────────
    let is_macos = std::env::consts::OS == "macos";
    if cli.dry_run {
        let cmd = if is_macos {
            "sudo launchctl kickstart -k system/com.innerwarden.agent"
        } else {
            "sudo systemctl restart innerwarden-agent"
        };
        println!("  [dry-run] would restart: {cmd}");
    } else if is_macos {
        let _ = systemd::restart_launchd("com.innerwarden.agent", false);
        println!("  [ok] innerwarden-agent restarted");
    } else {
        let _ = systemd::restart_service("innerwarden-agent", false);
        println!("  [ok] innerwarden-agent restarted");
    }

    println!();
    println!("Telegram is ready.");
    println!();
    println!("  Your bot sends alerts and responds to commands:");
    println!("    /menu       - interactive button menu");
    println!("    /status     - system overview");
    println!("    /incidents  - last incidents");
    println!("    /decisions  - last decisions");
    println!("    /ask <q>    - ask the AI a question");
    println!();
    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "telegram".to_string(),
        parameters: serde_json::json!({}),
        result: if cli.dry_run {
            "dry_run".to_string()
        } else {
            "success".to_string()
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("Next steps:");
    println!("  innerwarden status       - check services and active capabilities");
    println!("  innerwarden doctor       - validate the full setup");
    println!("  innerwarden test-alert   - send a test alert right now");
    Ok(())
}

/// Try to get the chat_id by long-polling for new messages.
/// First clears any pending updates, then waits for a fresh message.
fn discover_telegram_chat_id(token: &str) -> Option<String> {
    discover_telegram_chat_id_from_api_base("https://api.telegram.org", token)
}

fn discover_telegram_chat_id_from_api_base(api_base: &str, token: &str) -> Option<String> {
    let api_base = api_base.trim_end_matches('/');
    // Step 1: Clear old updates by fetching with offset -1
    let clear_url = format!("{api_base}/bot{token}/getUpdates?offset=-1&limit=1&timeout=0");
    let mut next_offset = 0i64;
    if let Ok(resp) = ureq::get(&clear_url).call() {
        if let Ok(json) = resp.into_body().read_json::<serde_json::Value>() {
            if let Some(last) = json["result"].as_array().and_then(|a| a.last()) {
                if let Some(uid) = last["update_id"].as_i64() {
                    next_offset = uid + 1; // Skip past all old updates
                }
            }
        }
    }

    // Step 2: Long-poll for a NEW message (timeout=5s per request)
    let poll_url =
        format!("{api_base}/bot{token}/getUpdates?offset={next_offset}&limit=1&timeout=5");
    let resp = ureq::get(&poll_url).call().ok()?;
    let json: serde_json::Value = resp.into_body().read_json().ok()?;
    telegram_chat_id_from_updates(&json)
}

fn telegram_chat_id_from_updates(json: &serde_json::Value) -> Option<String> {
    json["result"]
        .as_array()?
        .first()?
        .get("message")?
        .get("chat")?
        .get("id")?
        .as_i64()
        .map(|id| id.to_string())
}

/// Send a test Telegram message to confirm the configuration works.
fn send_telegram_test(token: &str, chat_id: &str) -> Result<()> {
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    send_telegram_test_to_url(&url, chat_id)
}

fn send_telegram_test_to_url(url: &str, chat_id: &str) -> Result<()> {
    let body = serde_json::json!({
        "chat_id": chat_id,
        "text": "✅ <b>InnerWarden connected</b>\n\nYou'll receive alerts here when High or Critical threats are detected on your server.\n\n<b>Commands:</b>\n/menu - interactive button menu\n/status - system overview\n/incidents - last incidents\n/decisions - last decisions\n/ask &lt;question&gt; - ask the AI\n\nOr just type a question in plain text.",
        "parse_mode": "HTML"
    });
    let resp = ureq::post(url)
        .header("Content-Type", "application/json")
        .send(body.to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let json: serde_json::Value = resp.into_body().read_json()?;
    validate_telegram_send_response(&json)
}

fn validate_telegram_send_response(json: &serde_json::Value) -> Result<()> {
    if json["ok"].as_bool() != Some(true) {
        anyhow::bail!(
            "{}",
            json["description"].as_str().unwrap_or("unknown error")
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden configure slack
// ---------------------------------------------------------------------------

pub(crate) fn cmd_configure_slack(
    cli: &Cli,
    webhook_url_arg: Option<&str>,
    min_severity: &str,
    no_test: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // ── Webhook URL ────────────────────────────────────────────────────────
    let webhook_url = if let Some(u) = webhook_url_arg {
        u.to_string()
    } else {
        println!("InnerWarden - Slack setup\n");
        println!("Step 1 - Create an Incoming Webhook");
        println!("  1. Go to https://api.slack.com/apps and click 'Create New App'");
        println!("  2. Choose 'From scratch', name it 'InnerWarden', pick your workspace");
        println!("  3. Click 'Incoming Webhooks' → toggle On → 'Add New Webhook to Workspace'");
        println!("  4. Choose a channel (e.g. #security-alerts) → Allow");
        println!("  5. Copy the webhook URL (starts with https://hooks.slack.com/...)\n");
        let u = prompt("Webhook URL")?;
        if u.is_empty() {
            anyhow::bail!("webhook URL cannot be empty");
        }
        u
    };

    if !is_valid_slack_webhook_url(&webhook_url) {
        anyhow::bail!(
            "webhook URL should start with https://hooks.slack.com/\nGet one at https://api.slack.com/apps"
        );
    }

    // Validate severity
    if !is_valid_alert_severity(min_severity) {
        anyhow::bail!("min-severity must be one of: low, medium, high, critical");
    }

    // ── Save credentials ───────────────────────────────────────────────────
    if cli.dry_run {
        println!(
            "\n  [dry-run] would write SLACK_WEBHOOK_URL=... to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would set [slack] enabled=true min_severity={min_severity} in {}",
            cli.agent_config.display()
        );
    } else {
        write_env_key(&env_file, "SLACK_WEBHOOK_URL", &webhook_url)?;
        println!("\n  [ok] Webhook URL saved to {}", env_file.display());

        config_editor::write_bool(&cli.agent_config, "slack", "enabled", true)?;
        config_editor::write_str(&cli.agent_config, "slack", "min_severity", min_severity)?;
        println!("  [ok] agent.toml: slack.enabled = true, min_severity = {min_severity}");
    }

    // ── Test notification ──────────────────────────────────────────────────
    if !no_test && !cli.dry_run {
        print!("  Sending test notification... ");
        std::io::stdout().flush()?;
        match send_slack_test(&webhook_url) {
            Ok(()) => println!("sent!"),
            Err(e) => {
                println!("failed");
                println!();
                println!("  Warning: could not send test message: {e:#}");
                println!("  Your URL has been saved. Verify it at https://api.slack.com/apps");
            }
        }
    }

    // ── Restart agent ──────────────────────────────────────────────────────
    let is_macos = std::env::consts::OS == "macos";
    if cli.dry_run {
        let cmd = if is_macos {
            "sudo launchctl kickstart -k system/com.innerwarden.agent"
        } else {
            "sudo systemctl restart innerwarden-agent"
        };
        println!("  [dry-run] would restart: {cmd}");
    } else if is_macos {
        let _ = systemd::restart_launchd("com.innerwarden.agent", false);
        println!("  [ok] innerwarden-agent restarted");
    } else {
        let _ = systemd::restart_service("innerwarden-agent", false);
        println!("  [ok] innerwarden-agent restarted");
    }

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "slack".to_string(),
        parameters: serde_json::json!({ "min_severity": min_severity }),
        result: if cli.dry_run {
            "dry_run".to_string()
        } else {
            "success".to_string()
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("Slack configured. You'll receive alerts for {min_severity}+ incidents.");
    println!("Run 'innerwarden doctor' to validate the full setup.");
    Ok(())
}

fn send_slack_test(webhook_url: &str) -> Result<()> {
    let body = serde_json::json!({
        "text": "✅ *InnerWarden* is connected. You'll receive security alerts here."
    });
    ureq::post(webhook_url)
        .header("Content-Type", "application/json")
        .send(body.to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

fn is_valid_discord_webhook_url(url: &str) -> bool {
    (url.starts_with("https://discord.com/api/webhooks/")
        || url.starts_with("https://discordapp.com/api/webhooks/")
        || url.starts_with("https://canary.discord.com/api/webhooks/")
        || url.starts_with("https://ptb.discord.com/api/webhooks/"))
        && url.matches('/').count() >= 6
}

fn send_discord_test(webhook_url: &str) -> Result<()> {
    let body = serde_json::json!({
        "content": "✅ **InnerWarden** is connected. You'll receive security alerts here."
    });
    ureq::post(webhook_url)
        .header("Content-Type", "application/json")
        .send(body.to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// Configure Discord Incoming Webhook notifications (spec 078 P3b).
///
/// Mirrors [`cmd_configure_slack`]: prompts for / accepts a webhook URL, saves
/// it to `agent.env` (`DISCORD_WEBHOOK_URL`), flips `[discord] enabled = true`
/// + `min_severity` in agent.toml, sends a test message, and restarts the agent.
pub(crate) fn cmd_configure_discord(
    cli: &Cli,
    webhook_url_arg: Option<&str>,
    min_severity: &str,
    no_test: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // ── Webhook URL ────────────────────────────────────────────────────────
    let webhook_url = if let Some(u) = webhook_url_arg {
        u.to_string()
    } else {
        println!("InnerWarden - Discord setup\n");
        println!("Step 1 - Create an Incoming Webhook");
        println!("  1. In your Discord server: Server Settings → Integrations → Webhooks");
        println!("  2. Click 'New Webhook', name it 'InnerWarden', pick a channel");
        println!("  3. Click 'Copy Webhook URL'");
        println!("     (starts with https://discord.com/api/webhooks/...)\n");
        let u = prompt("Webhook URL")?;
        if u.is_empty() {
            anyhow::bail!("webhook URL cannot be empty");
        }
        u
    };

    if !is_valid_discord_webhook_url(&webhook_url) {
        anyhow::bail!(
            "webhook URL should start with https://discord.com/api/webhooks/\nCreate one in Server Settings → Integrations → Webhooks"
        );
    }

    // Validate severity
    if !is_valid_alert_severity(min_severity) {
        anyhow::bail!("min-severity must be one of: low, medium, high, critical");
    }

    // ── Save credentials ───────────────────────────────────────────────────
    if cli.dry_run {
        println!(
            "\n  [dry-run] would write DISCORD_WEBHOOK_URL=... to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would set [discord] enabled=true min_severity={min_severity} in {}",
            cli.agent_config.display()
        );
    } else {
        write_env_key(&env_file, "DISCORD_WEBHOOK_URL", &webhook_url)?;
        println!("\n  [ok] Webhook URL saved to {}", env_file.display());

        config_editor::write_bool(&cli.agent_config, "discord", "enabled", true)?;
        config_editor::write_str(&cli.agent_config, "discord", "min_severity", min_severity)?;
        println!("  [ok] agent.toml: discord.enabled = true, min_severity = {min_severity}");
    }

    // ── Test notification ──────────────────────────────────────────────────
    if !no_test && !cli.dry_run {
        print!("  Sending test notification... ");
        std::io::stdout().flush()?;
        match send_discord_test(&webhook_url) {
            Ok(()) => println!("sent!"),
            Err(e) => {
                println!("failed");
                println!();
                println!("  Warning: could not send test message: {e:#}");
                println!(
                    "  Your URL has been saved. Verify the webhook in Discord server settings."
                );
            }
        }
    }

    // ── Restart agent ──────────────────────────────────────────────────────
    let is_macos = std::env::consts::OS == "macos";
    if cli.dry_run {
        let cmd = if is_macos {
            "sudo launchctl kickstart -k system/com.innerwarden.agent"
        } else {
            "sudo systemctl restart innerwarden-agent"
        };
        println!("  [dry-run] would restart: {cmd}");
    } else if is_macos {
        let _ = systemd::restart_launchd("com.innerwarden.agent", false);
        println!("  [ok] innerwarden-agent restarted");
    } else {
        let _ = systemd::restart_service("innerwarden-agent", false);
        println!("  [ok] innerwarden-agent restarted");
    }

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "discord".to_string(),
        parameters: serde_json::json!({ "min_severity": min_severity }),
        result: if cli.dry_run {
            "dry_run".to_string()
        } else {
            "success".to_string()
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("Discord configured. You'll receive alerts for {min_severity}+ incidents.");
    println!("Run 'innerwarden doctor' to validate the full setup.");
    Ok(())
}

pub(crate) fn cmd_configure_webhook(
    cli: &Cli,
    url_arg: Option<&str>,
    min_severity: &str,
    no_test: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    // Validate severity
    if !is_valid_alert_severity(min_severity) {
        anyhow::bail!("min-severity must be one of: low, medium, high, critical");
    }

    let url = if let Some(u) = url_arg {
        u.to_string()
    } else {
        println!("InnerWarden - Webhook setup\n");
        println!("Sends a JSON POST to your endpoint for every alert.\n");
        println!("Works with:");
        println!("  PagerDuty, Opsgenie, Discord, Microsoft Teams, Google Chat,");
        println!("  DingTalk, Feishu/Lark, WeCom, n8n, Zapier, Make, Home Assistant\n");
        println!("Tip: for PagerDuty, set format later with:");
        println!("  innerwarden configure webhook --format pagerduty\n");
        let u = prompt("Webhook URL")?;
        if u.is_empty() {
            anyhow::bail!("URL cannot be empty");
        }
        u
    };

    if !is_valid_webhook_url(&url) {
        anyhow::bail!("URL must start with http:// or https://");
    }

    if cli.dry_run {
        println!("\n  [dry-run] would set [webhook] enabled=true url=... min_severity={min_severity} in {}", cli.agent_config.display());
    } else {
        config_editor::write_bool(&cli.agent_config, "webhook", "enabled", true)?;
        config_editor::write_str(&cli.agent_config, "webhook", "url", &url)?;
        config_editor::write_str(&cli.agent_config, "webhook", "min_severity", min_severity)?;
        println!("\n  [ok] agent.toml: webhook.enabled = true, min_severity = {min_severity}");
    }

    if !no_test && !cli.dry_run {
        print!("  Sending test request... ");
        std::io::stdout().flush()?;
        match send_webhook_test(&url) {
            Ok(status) => println!("ok (HTTP {status})"),
            Err(e) => {
                println!("failed");
                println!();
                println!("  Warning: {e:#}");
                println!("  Your URL has been saved. Check the endpoint is reachable.");
            }
        }
    }

    restart_agent(cli);

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "webhook".to_string(),
        parameters: serde_json::json!({ "min_severity": min_severity }),
        result: if cli.dry_run {
            "dry_run".to_string()
        } else {
            "success".to_string()
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("Webhook configured. Alerts ({min_severity}+) will be sent to your endpoint.");
    println!("Run 'innerwarden doctor' to validate.");
    Ok(())
}

fn send_webhook_test(url: &str) -> Result<u16> {
    let body = serde_json::json!({
        "source": "innerwarden",
        "kind": "test",
        "severity": "low",
        "summary": "InnerWarden webhook test - configuration successful",
        "host": hostname()
    });
    let resp = ureq::post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "innerwarden-ctl/1.0")
        .send(body.to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(resp.status().as_u16())
}

// ---------------------------------------------------------------------------
// innerwarden configure dashboard
// ---------------------------------------------------------------------------

fn find_innerwarden_agent_bin() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("INNERWARDEN_AGENT_BIN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }
    for path in &[
        "/usr/local/bin/innerwarden-agent",
        "/usr/bin/innerwarden-agent",
    ] {
        if Path::new(path).exists() {
            return Some(PathBuf::from(path));
        }
    }
    which_bin("innerwarden-agent")
}

pub(crate) fn cmd_configure_dashboard(
    cli: &Cli,
    user: &str,
    password_arg: Option<&str>,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // When password is provided via --password flag, use it directly.
    // Otherwise let the agent binary handle prompting (hidden input + confirm = 2 prompts total).
    let hash = if let Some(password) = password_arg {
        // Non-interactive path: pipe password to agent subprocess.
        let agent_bin = find_innerwarden_agent_bin().ok_or_else(|| {
            anyhow::anyhow!(
                "innerwarden-agent not found - run ./install.sh first or generate hash manually:\
                    \n  innerwarden-agent --dashboard-generate-password-hash"
            )
        })?;

        let output = std::process::Command::new(&agent_bin)
            .arg("--dashboard-generate-password-hash")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write as _;
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = writeln!(stdin, "{password}");
                    let _ = writeln!(stdin, "{password}");
                }
                child.wait_with_output()
            })
            .map_err(|e| anyhow::anyhow!("failed to run agent binary: {e}"))?;

        if !output.status.success() {
            anyhow::bail!("agent binary failed to generate hash");
        }
        let raw = String::from_utf8_lossy(&output.stdout);
        raw.lines()
            .find(|l| l.starts_with("$argon2"))
            .map(|s| s.trim().to_string())
            .ok_or_else(|| anyhow::anyhow!("agent binary returned unexpected output"))?
    } else {
        // Interactive path: let the agent binary prompt for password (hidden, with confirm).
        // This avoids the duplicate-prompt issue - only 2 prompts instead of 3.
        println!("InnerWarden - Dashboard setup\n");
        println!("The dashboard requires a login to protect your security data.");
        println!("Choose a strong password (min 8 chars).\n");

        let agent_bin = find_innerwarden_agent_bin().ok_or_else(|| {
            anyhow::anyhow!(
                "innerwarden-agent not found - run ./install.sh first or generate hash manually:\
                    \n  innerwarden-agent --dashboard-generate-password-hash"
            )
        })?;

        // Inherit stdin/stderr so rpassword can read from the terminal directly.
        let output = std::process::Command::new(&agent_bin)
            .arg("--dashboard-generate-password-hash")
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .output()
            .map_err(|e| anyhow::anyhow!("failed to run agent binary: {e}"))?;

        if !output.status.success() {
            anyhow::bail!("password setup failed");
        }
        let raw = String::from_utf8_lossy(&output.stdout);
        raw.lines()
            .find(|l| l.starts_with("$argon2"))
            .map(|s| s.trim().to_string())
            .ok_or_else(|| anyhow::anyhow!("agent binary returned unexpected output"))?
    };

    if cli.dry_run {
        println!(
            "\n  [dry-run] would write INNERWARDEN_DASHBOARD_USER={user} to {}",
            env_file.display()
        );
        println!(
            "  [dry-run] would write INNERWARDEN_DASHBOARD_PASSWORD_HASH=<hash> to {}",
            env_file.display()
        );
        println!("  [dry-run] would add --dashboard to service ExecStart if missing");
    } else {
        write_env_key(&env_file, "INNERWARDEN_DASHBOARD_USER", user)?;
        write_env_key(&env_file, "INNERWARDEN_DASHBOARD_PASSWORD_HASH", &hash)?;
        println!("\n  [ok] Credentials saved to {}", env_file.display());
    }

    // Ensure --dashboard is in the service ExecStart
    ensure_dashboard_flag_in_service(cli);

    // Offer to expose the dashboard on the network. The login above is now set,
    // so the agent will accept a non-loopback bind (SEC-005). Default NO — an
    // open admin panel is NEVER the silent default; we ASK (issue #1046). The
    // bind is stored config-driven in `[dashboard] bind`, managed afterwards by
    // `innerwarden dashboard {open,close,status}`.
    let mut exposed = false;
    if password_arg.is_none() && !cli.dry_run {
        exposed = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(
                "Make the dashboard reachable from other machines (network), not just localhost? \
                 It requires the login you just set.",
            )
            .default(false)
            .interact()
            .unwrap_or(false);
        let bind = if exposed {
            "0.0.0.0:8787"
        } else {
            "127.0.0.1:8787"
        };
        let _ = crate::config_editor::write_str(&cli.agent_config, "dashboard", "bind", bind);
        if exposed {
            println!(
                "  [ok] Dashboard set to listen on the network (0.0.0.0:8787). Login required."
            );
            println!(
                "  ⚠ Lock the firewall to trusted IPs: `innerwarden dashboard open` (auto-locks to your IP), \
                 or `sudo ufw allow from <your-ip> to any port 8787`."
            );
        }
    }

    restart_agent(cli);
    println!();
    println!("Dashboard configured.");
    if exposed {
        println!("  URL:      https://YOUR_SERVER_IP:8787  (network — login required)");
    } else {
        println!("  URL:      https://localhost:8787  (localhost only — use the SSH tunnel below)");
    }
    println!("  Username: {user}");
    println!("  Password: (the one you entered)");
    println!();
    println!("To access from your browser via SSH tunnel:");
    println!("  ssh -L 8787:127.0.0.1:8787 user@YOUR_SERVER");
    println!("  Then open: https://localhost:8787");
    println!();
    println!("If you use nginx, add this to your server block:");
    println!("  location / {{");
    println!("      proxy_pass http://127.0.0.1:8787;");
    println!("      proxy_set_header Host $host;");
    println!("      proxy_set_header Authorization $http_authorization;");
    println!("      proxy_pass_header Authorization;");
    println!("      proxy_http_version 1.1;");
    println!("      proxy_buffering off;");
    println!("  }}");
    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "dashboard".to_string(),
        parameters: serde_json::json!({ "user": user }),
        result: if cli.dry_run {
            "dry_run".to_string()
        } else {
            "success".to_string()
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("Run 'innerwarden doctor' to validate.");
    Ok(())
}

/// Add `--dashboard` to the innerwarden-agent service ExecStart if not already present.
fn ensure_dashboard_flag_in_service(cli: &Cli) {
    // Only applies to Linux systemd
    if std::env::consts::OS == "macos" {
        return;
    }
    let service_path = "/etc/systemd/system/innerwarden-agent.service";
    let Ok(content) = std::fs::read_to_string(service_path) else {
        return;
    };
    if content.contains("--dashboard") {
        return;
    }
    let Some(patched) = add_dashboard_flag_to_service_content(&content) else {
        return;
    };

    if cli.dry_run {
        println!("  [dry-run] would add --dashboard to {service_path}");
        return;
    }

    if std::fs::write(service_path, patched).is_ok() {
        let _ = std::process::Command::new("systemctl")
            .arg("daemon-reload")
            .status();
        println!("  [ok] --dashboard added to {service_path}");
    } else {
        println!(
            "  [warn] could not update {service_path} - add --dashboard to ExecStart manually"
        );
    }
}

fn add_dashboard_flag_to_service_content(content: &str) -> Option<String> {
    if content.contains("--dashboard") {
        return None;
    }

    let mut changed = false;
    let patched = content
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("ExecStart=") {
                changed = true;
                format!("{line} --dashboard")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    changed.then_some(patched)
}

fn which_bin(name: &str) -> Option<PathBuf> {
    std::env::var("PATH").ok()?.split(':').find_map(|dir| {
        let p = PathBuf::from(dir).join(name);
        if p.exists() {
            Some(p)
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------

pub(crate) fn cmd_test_alert(cli: &Cli, channel: Option<&str>) -> Result<()> {
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // Detect permission-denied early - don't check exists() first because
    // the directory itself may be inaccessible, making exists() return false.
    if let Err(e) = std::fs::read_to_string(&env_file) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            eprintln!("Permission denied reading {}", env_file.display());
            eprintln!("Credentials are stored in a protected file.");
            eprintln!();
            let args: Vec<String> = std::env::args().collect();
            let cmd_args = args[1..].join(" ");
            eprintln!("Run with sudo:");
            eprintln!("  sudo innerwarden {cmd_args}");
            std::process::exit(1);
        }
        // File not found or other error - fine, load_env_file will return empty map
    }

    // Load agent.env for credentials
    let env_vars = load_env_file(&env_file);

    let test_only = channel;
    let mut any_tested = false;
    let mut any_failed = false;

    // Same label real incidents are stamped with (sensor `[agent] host_id`),
    // so the operator can tell which box a test alert came from when several
    // hosts share one Telegram chat / Slack channel.
    let host = crate::helpers::host_label(&cli.sensor_config);

    println!("InnerWarden - test alert ({host})\n");

    // ── Telegram ─────────────────────────────────────────────────────────
    let try_telegram = channel_selected(test_only, "telegram");
    if try_telegram {
        let token = env_vars
            .get("TELEGRAM_BOT_TOKEN")
            .cloned()
            .or_else(|| std::env::var("TELEGRAM_BOT_TOKEN").ok());
        let chat_id = env_vars
            .get("TELEGRAM_CHAT_ID")
            .cloned()
            .or_else(|| std::env::var("TELEGRAM_CHAT_ID").ok());
        match (token, chat_id) {
            (Some(tok), Some(cid)) if !tok.is_empty() && !cid.is_empty() => {
                any_tested = true;
                print!("  Telegram ... ");
                std::io::stdout().flush().ok();
                let msg = format!(
                    "🔔 *Test alert from InnerWarden*\nFrom host: `{host}`\n\nYour Telegram notifications are working correctly\\."
                );
                match send_telegram_message_md(&tok, &cid, &msg) {
                    Ok(()) => println!("ok"),
                    Err(e) => {
                        println!("FAILED: {e:#}");
                        any_failed = true;
                    }
                }
            }
            _ => {
                if test_only == Some("telegram") {
                    println!("  Telegram ... not configured (run: innerwarden notify telegram)");
                    any_failed = true;
                } else {
                    println!("  Telegram ... skipped (not configured)");
                }
            }
        }
    }

    // ── Slack ─────────────────────────────────────────────────────────────
    let try_slack = channel_selected(test_only, "slack");
    if try_slack {
        let webhook = env_vars
            .get("SLACK_WEBHOOK_URL")
            .cloned()
            .or_else(|| std::env::var("SLACK_WEBHOOK_URL").ok());
        match webhook {
            Some(url) if !url.is_empty() => {
                any_tested = true;
                print!("  Slack ...... ");
                std::io::stdout().flush().ok();
                let payload = serde_json::json!({
                    "text": format!("🔔 *Test alert from InnerWarden* — host `{host}` — Slack notifications are working correctly.")
                });
                match ureq::post(&url)
                    .header("Content-Type", "application/json")
                    .send(payload.to_string())
                {
                    Ok(_) => println!("ok"),
                    Err(e) => {
                        println!("FAILED: {e:#}");
                        any_failed = true;
                    }
                }
            }
            _ => {
                if test_only == Some("slack") {
                    println!("  Slack ...... not configured (run: innerwarden configure slack)");
                    any_failed = true;
                } else {
                    println!("  Slack ...... skipped (not configured)");
                }
            }
        }
    }

    // ── Webhook ───────────────────────────────────────────────────────────
    let try_webhook = channel_selected(test_only, "webhook");
    if try_webhook {
        // Read webhook URL and enabled flag from agent.toml
        let agent_doc: Option<toml_edit::DocumentMut> = cli
            .agent_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.agent_config).ok())
            .flatten()
            .and_then(|s| s.parse().ok());

        let webhook_url: Option<String> = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("webhook"))
            .and_then(|w| w.get("url"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string());
        let webhook_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("webhook"))
            .and_then(|w| w.get("enabled"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false);

        match webhook_url {
            Some(url) if !url.is_empty() && webhook_enabled => {
                any_tested = true;
                print!("  Webhook .... ");
                std::io::stdout().flush().ok();
                let payload = serde_json::json!({
                    "type": "test",
                    "message": "Test alert from InnerWarden - webhook notifications are working correctly."
                });
                match ureq::post(&url)
                    .header("Content-Type", "application/json")
                    .config()
                    .timeout_global(Some(std::time::Duration::from_secs(10)))
                    .build()
                    .send(payload.to_string())
                {
                    Ok(_) => println!("ok"),
                    Err(e) => {
                        println!("FAILED: {e:#}");
                        any_failed = true;
                    }
                }
            }
            _ => {
                if test_only == Some("webhook") {
                    println!("  Webhook .... not configured (run: innerwarden configure webhook)");
                    any_failed = true;
                } else {
                    println!("  Webhook .... skipped (not configured)");
                }
            }
        }
    }

    println!();
    if !any_tested {
        println!("No channels configured yet.");
        println!("Run 'innerwarden configure' to set up notifications.");
        return Ok(());
    }
    if any_failed {
        anyhow::bail!("One or more channels failed - run 'innerwarden doctor' for details");
    }
    println!("All channels ok.");
    Ok(())
}

pub(crate) fn cmd_notify_web_push_setup(cli: &Cli, subject: Option<&str>) -> Result<()> {
    use config_editor::{write_bool, write_str};
    use std::io::Write as _;

    println!("Setting up Web Push notifications (RFC 8291 / VAPID)...");
    println!();

    let has_existing = cli.agent_config.exists() && {
        let content = std::fs::read_to_string(&cli.agent_config).unwrap_or_default();
        content.contains("vapid_public_key") && !content.contains(r#"vapid_public_key = """#)
    };

    if has_existing {
        println!("⚠  VAPID keys are already configured.");
        print!("   Generate new keys? This will break existing browser subscriptions. [y/N] ");
        std::io::stdout().flush().ok();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Keeping existing keys.");
            println!();
            print_web_push_next_steps(&cli.agent_config)?;
            return Ok(());
        }
    }

    let (private_pem, public_b64) = generate_vapid_keys_ctl()?;
    let subject_val = subject.unwrap_or("mailto:admin@example.com");

    write_str(
        &cli.agent_config,
        "web_push",
        "vapid_public_key",
        &public_b64,
    )?;
    write_str(&cli.agent_config, "web_push", "vapid_subject", subject_val)?;
    write_bool(&cli.agent_config, "web_push", "enabled", true)?;

    let env_path = cli
        .agent_config
        .parent()
        .unwrap_or(std::path::Path::new("/etc/innerwarden"))
        .join("agent.env");
    append_or_replace_env(&env_path, "INNERWARDEN_VAPID_PRIVATE_KEY", &private_pem)?;

    println!("✓  VAPID key pair generated");
    println!("   Public key  → {}", &cli.agent_config.display());
    println!(
        "   Private key → {} (INNERWARDEN_VAPID_PRIVATE_KEY)",
        env_path.display()
    );
    println!();

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "web_push".to_string(),
        parameters: serde_json::json!({ "subject": subject_val }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    print_web_push_next_steps(&cli.agent_config)?;
    Ok(())
}

fn generate_vapid_keys_ctl() -> Result<(String, String)> {
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use p256::{ecdsa::SigningKey, EncodedPoint};

    let signing_key = SigningKey::random(&mut rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    let pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("failed to serialize VAPID private key: {e}"))?
        .to_string();
    let public_bytes = EncodedPoint::from(verifying_key).to_bytes().to_vec();
    use base64::Engine as _;
    let public_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&public_bytes);
    Ok((pem, public_b64))
}

fn append_or_replace_env(path: &std::path::Path, key: &str, value: &str) -> Result<()> {
    use std::io::Write as _;

    let existing = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        String::new()
    };

    let escaped_value = format!("\"{}\"", value.replace('\n', "\\n"));

    let mut lines: Vec<String> = existing
        .lines()
        .filter(|l| !l.starts_with(&format!("{key}=")))
        .map(|l| l.to_string())
        .collect();
    lines.push(format!("{key}={escaped_value}"));

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    for line in &lines {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

fn print_web_push_next_steps(agent_config: &std::path::Path) -> Result<()> {
    println!("Next steps:");
    println!("  1. Restart the agent:");
    println!("       sudo systemctl restart innerwarden-agent");
    println!("  2. Open the InnerWarden dashboard");
    println!("  3. Click 'Enable browser notifications' in the top bar");
    println!("  4. Allow notifications when your browser asks");
    println!();
    println!(
        "The public key is configured in: {}",
        agent_config.display()
    );
    println!("Browsers will receive High and Critical incident alerts in real time,");
    println!("even when the dashboard tab is not open (requires browser running).");
    Ok(())
}

// ---------------------------------------------------------------------------
// Digest & budget configuration
// ---------------------------------------------------------------------------

pub(crate) fn cmd_configure_digest(cli: &Cli, hour_str: &str) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }

    let digest_config = parse_digest_hour_config(hour_str)?;

    if digest_config == DigestHourConfig::Disabled {
        if cli.dry_run {
            println!("  [dry-run] would remove [telegram] daily_summary_hour");
        } else {
            config_editor::remove_key(&cli.agent_config, "telegram", "daily_summary_hour")?;
            println!("  Daily Telegram digest disabled.");
            restart_agent(cli);
        }
        return Ok(());
    }

    let hour = match digest_config {
        DigestHourConfig::Hour(hour) => hour,
        DigestHourConfig::Disabled => unreachable!("handled above"),
    };

    if cli.dry_run {
        println!("  [dry-run] would set [telegram] daily_summary_hour = {hour}");
    } else {
        config_editor::write_int(
            &cli.agent_config,
            "telegram",
            "daily_summary_hour",
            i64::from(hour),
        )?;
        println!("  Daily Telegram digest set to {hour:02}:00 local time.");
        restart_agent(cli);
    }

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "telegram.daily_summary_hour".to_string(),
        parameters: serde_json::json!({ "hour": hour }),
        result: if cli.dry_run {
            "dry_run".to_string()
        } else {
            "success".to_string()
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn test_cli(temp: &TempDir) -> Cli {
        let mut cli = Cli::parse_from(["innerwarden", "replay"]);
        cli.sensor_config = temp.path().join("sensor.toml");
        cli.agent_config = temp.path().join("agent.toml");
        cli.data_dir = temp.path().join("data");
        cli.dry_run = true;
        std::fs::create_dir_all(&cli.data_dir).expect("test should create data dir");
        cli
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("test should create parent directory");
        }
        std::fs::write(path, content).expect("test should write fixture");
    }

    fn serve_status(status: u16, requests: usize) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("test server should bind");
        let addr = listener.local_addr().expect("server address");
        std::thread::spawn(move || {
            for _ in 0..requests {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request);
                let reason = if status == 200 { "OK" } else { "Accepted" };
                let body = "{}";
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}/hook")
    }

    fn serve_json_bodies(bodies: Vec<&'static str>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("test server should bind");
        let addr = listener.local_addr().expect("server address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        std::thread::spawn(move || {
            for body in bodies {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut request = [0u8; 2048];
                let read = stream.read(&mut request).unwrap_or(0);
                let request_text = String::from_utf8_lossy(&request[..read]);
                if let Some(line) = request_text.lines().next() {
                    seen.lock()
                        .expect("request log lock")
                        .push(line.to_string());
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{addr}"), requests)
    }

    #[cfg(unix)]
    fn write_fake_agent(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("innerwarden-agent");
        write_file(&path, body);
        let mut perms = std::fs::metadata(&path)
            .expect("fake agent metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("fake agent executable");
        path
    }

    fn with_agent_bin<T>(path: &Path, f: impl FnOnce() -> T) -> T {
        static AGENT_BIN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = AGENT_BIN_ENV_LOCK
            .lock()
            .expect("agent env test lock should not be poisoned");
        let prior = std::env::var_os("INNERWARDEN_AGENT_BIN");
        std::env::set_var("INNERWARDEN_AGENT_BIN", path);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        match prior {
            Some(value) => std::env::set_var("INNERWARDEN_AGENT_BIN", value),
            None => std::env::remove_var("INNERWARDEN_AGENT_BIN"),
        }
        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[test]
    fn is_valid_telegram_token_accepts_botfather_shape() {
        // Protects the happy path where a BotFather-style token should pass lightweight validation.
        assert!(is_valid_telegram_token("123456789:ABCdef_token"));
    }

    #[test]
    fn is_valid_telegram_token_rejects_missing_prefix_or_separator() {
        // Covers malformed token branches so obvious copy/paste mistakes fail fast.
        assert!(!is_valid_telegram_token("123456789"));
        assert!(!is_valid_telegram_token(":ABCdef_token"));
    }

    #[test]
    fn is_numeric_chat_id_accepts_user_and_group_formats() {
        // Ensures both direct-user and negative group IDs remain accepted by CLI validation.
        assert!(is_numeric_chat_id("123456789"));
        assert!(is_numeric_chat_id("-1001234567890"));
    }

    #[test]
    fn is_numeric_chat_id_rejects_non_numeric_values() {
        // Guards error path for chat IDs containing letters or punctuation.
        assert!(!is_numeric_chat_id("chat_123"));
        assert!(!is_numeric_chat_id("-100abc"));
    }

    #[test]
    fn is_valid_alert_severity_accepts_supported_values() {
        // Verifies channel filtering only accepts known severity levels used by notification config.
        assert!(is_valid_alert_severity("low"));
        assert!(is_valid_alert_severity("medium"));
        assert!(is_valid_alert_severity("high"));
        assert!(is_valid_alert_severity("critical"));
    }

    #[test]
    fn is_valid_alert_severity_rejects_unknown_value() {
        // Covers rejection branch to prevent unsupported levels from silently entering config.
        assert!(!is_valid_alert_severity("urgent"));
    }

    #[test]
    fn webhook_validators_enforce_expected_schemes() {
        // Confirms Slack and generic webhook validators keep provider-specific URL constraints.
        assert!(is_valid_slack_webhook_url(
            "https://hooks.slack.com/services/T000/B000/XXX"
        ));
        assert!(!is_valid_slack_webhook_url("https://example.com/webhook"));
        assert!(is_valid_webhook_url("http://localhost:8080/hook"));
        assert!(is_valid_webhook_url("https://example.com/hook"));
        assert!(!is_valid_webhook_url("ftp://example.com/hook"));
    }

    #[test]
    fn channel_selected_matches_optional_filter() {
        // Ensures test-alert channel targeting executes exactly the requested channel when provided.
        assert!(channel_selected(None, "telegram"));
        assert!(channel_selected(Some("telegram"), "telegram"));
        assert!(!channel_selected(Some("slack"), "telegram"));
    }

    #[test]
    fn parse_digest_hour_config_maps_disable_aliases() {
        // Verifies all disable aliases land in the same branch that removes the digest key.
        assert_eq!(
            parse_digest_hour_config("off").expect("off should parse"),
            DigestHourConfig::Disabled
        );
        assert_eq!(
            parse_digest_hour_config("none").expect("none should parse"),
            DigestHourConfig::Disabled
        );
        assert_eq!(
            parse_digest_hour_config("disable").expect("disable should parse"),
            DigestHourConfig::Disabled
        );
    }

    #[test]
    fn parse_digest_hour_config_accepts_hour_bounds() {
        // Covers accepted numeric range boundaries used for digest scheduling.
        assert_eq!(
            parse_digest_hour_config("0").expect("0 should parse"),
            DigestHourConfig::Hour(0)
        );
        assert_eq!(
            parse_digest_hour_config("23").expect("23 should parse"),
            DigestHourConfig::Hour(23)
        );
    }

    #[test]
    fn parse_digest_hour_config_rejects_invalid_inputs() {
        // Protects failure branches for non-numeric and out-of-range values.
        let err = parse_digest_hour_config("24").expect_err("24 must be rejected");
        assert!(err.to_string().contains("hour must be 0-23"));
        let err = parse_digest_hour_config("1h").expect_err("1h must be rejected");
        assert!(err.to_string().contains("expected a number"));
    }

    #[test]
    fn append_or_replace_env_creates_and_replaces_existing_key() {
        let temp = TempDir::new().expect("test should create temp dir");
        let env_path = temp.path().join("agent.env");

        append_or_replace_env(&env_path, "FOO", "one").expect("first write should succeed");
        append_or_replace_env(&env_path, "BAR", "two").expect("second write should succeed");
        append_or_replace_env(&env_path, "FOO", "three").expect("replace should succeed");

        let content = std::fs::read_to_string(&env_path).expect("env file should exist");
        assert!(content.contains("BAR=\"two\""));
        assert!(content.contains("FOO=\"three\""));
        assert!(!content.contains("FOO=\"one\""));
        assert_eq!(
            content.lines().filter(|l| l.starts_with("FOO=")).count(),
            1,
            "FOO should be unique after replace"
        );
    }

    #[test]
    fn which_bin_returns_none_for_missing_binary() {
        assert!(which_bin("innerwarden-definitely-missing-binary").is_none());
    }

    #[test]
    fn telegram_chat_id_from_updates_reads_first_message_chat() {
        let json = serde_json::json!({
            "result": [
                { "message": { "chat": { "id": -1001234567890i64 } } }
            ]
        });
        assert_eq!(
            telegram_chat_id_from_updates(&json).as_deref(),
            Some("-1001234567890")
        );
        assert!(telegram_chat_id_from_updates(&serde_json::json!({"result": []})).is_none());
    }

    #[test]
    fn discover_telegram_chat_id_from_api_base_uses_clear_offset_then_poll() {
        let (base_url, requests) = serve_json_bodies(vec![
            r#"{"result":[{"update_id":41}]}"#,
            r#"{"result":[{"message":{"chat":{"id":123456789}}}]}"#,
        ]);

        assert_eq!(
            discover_telegram_chat_id_from_api_base(&base_url, "123:abc").as_deref(),
            Some("123456789")
        );
        let requests = requests.lock().expect("request log lock");
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("offset=-1"));
        assert!(requests[1].contains("offset=42"));
    }

    #[test]
    fn validate_telegram_send_response_accepts_ok_and_surfaces_errors() {
        validate_telegram_send_response(&serde_json::json!({"ok": true}))
            .expect("ok telegram response should pass");

        let err = validate_telegram_send_response(
            &serde_json::json!({"ok": false, "description": "bad chat"}),
        )
        .expect_err("telegram error should be surfaced");
        assert!(err.to_string().contains("bad chat"));

        let err = validate_telegram_send_response(&serde_json::json!({"ok": false}))
            .expect_err("telegram error without description should use fallback");
        assert!(err.to_string().contains("unknown error"));
    }

    #[test]
    fn send_telegram_test_to_url_posts_expected_payload_and_checks_json() {
        let (url, requests) = serve_json_bodies(vec![r#"{"ok":true}"#]);
        send_telegram_test_to_url(&url, "-100123").expect("ok telegram response should pass");
        assert_eq!(requests.lock().expect("request log lock").len(), 1);

        let (url, _) = serve_json_bodies(vec![r#"{"ok":false,"description":"bad token"}"#]);
        let err = send_telegram_test_to_url(&url, "-100123")
            .expect_err("telegram API failure should fail test send");
        assert!(err.to_string().contains("bad token"));
    }

    #[test]
    fn find_innerwarden_agent_bin_uses_env_override_when_present() {
        let temp = TempDir::new().expect("test should create temp dir");
        let agent = temp.path().join("innerwarden-agent");
        write_file(&agent, "#!/bin/sh\n");

        with_agent_bin(&agent, || {
            assert_eq!(
                find_innerwarden_agent_bin().as_deref(),
                Some(agent.as_path())
            );
        });
    }

    #[test]
    fn generate_vapid_keys_ctl_returns_pem_and_public_key() {
        let (private_pem, public_b64) = generate_vapid_keys_ctl().expect("keygen should succeed");
        assert!(private_pem.contains("BEGIN PRIVATE KEY"));
        assert!(!public_b64.is_empty());
    }

    #[test]
    fn cmd_configure_digest_dry_run_covers_hour_and_disable_branches() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_configure_digest(&cli, "off").expect("disable branch should succeed");
        cmd_configure_digest(&cli, "7").expect("hour branch should succeed");
    }

    #[test]
    fn cmd_configure_budget_dry_run_succeeds() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        cmd_configure_budget(&cli, 42).expect("dry-run budget config should succeed");
    }

    #[test]
    fn cmd_configure_telegram_dry_run_validates_inputs_and_audits() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_configure_telegram(
            &cli,
            Some("123456789:ABCdef_token"),
            Some("-1001234567890"),
            true,
        )
        .expect("dry-run telegram config should succeed");

        let err = cmd_configure_telegram(&cli, Some("bad-token"), Some("123"), true)
            .expect_err("bad token should be rejected");
        assert!(err.to_string().contains("token looks wrong"));

        let err =
            cmd_configure_telegram(&cli, Some("123456789:ABCdef_token"), Some("chat_123"), true)
                .expect_err("bad chat id should be rejected");
        assert!(err.to_string().contains("chat ID must be a number"));
    }

    #[test]
    fn cmd_configure_slack_dry_run_validates_url_and_severity() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_configure_slack(
            &cli,
            Some("https://hooks.slack.com/services/T000/B000/XXX"),
            "critical",
            true,
        )
        .expect("dry-run slack config should succeed");

        let err = cmd_configure_slack(&cli, Some("https://example.com/hook"), "high", true)
            .expect_err("non-slack URL should fail");
        assert!(err.to_string().contains("hooks.slack.com"));

        let err = cmd_configure_slack(
            &cli,
            Some("https://hooks.slack.com/services/T000/B000/XXX"),
            "urgent",
            true,
        )
        .expect_err("bad severity should fail");
        assert!(err.to_string().contains("min-severity"));
    }

    #[test]
    fn cmd_configure_discord_dry_run_validates_url_and_severity() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_configure_discord(
            &cli,
            Some("https://discord.com/api/webhooks/123456789/AbCdEf-token"),
            "critical",
            true,
        )
        .expect("dry-run discord config should succeed");

        let err = cmd_configure_discord(&cli, Some("https://example.com/hook"), "high", true)
            .expect_err("non-discord URL should fail");
        assert!(err.to_string().contains("discord.com/api/webhooks"));

        let err = cmd_configure_discord(
            &cli,
            Some("https://discord.com/api/webhooks/123456789/AbCdEf-token"),
            "urgent",
            true,
        )
        .expect_err("bad severity should fail");
        assert!(err.to_string().contains("min-severity"));
    }

    #[test]
    fn discord_webhook_url_validation() {
        assert!(is_valid_discord_webhook_url(
            "https://discord.com/api/webhooks/123/abc"
        ));
        assert!(is_valid_discord_webhook_url(
            "https://ptb.discord.com/api/webhooks/123/abc"
        ));
        assert!(!is_valid_discord_webhook_url("https://hooks.slack.com/x"));
        assert!(!is_valid_discord_webhook_url(
            "https://discord.com/api/webhooks/"
        ));
    }

    #[test]
    fn cmd_configure_discord_non_dry_run_persists_env_and_config() {
        let temp = TempDir::new().expect("tempdir");
        let mut cli = test_cli(&temp);
        cli.dry_run = false; // exercise the real persist + restart path
        std::fs::write(&cli.agent_config, "").expect("seed agent.toml");

        // require_sudo passes because the temp config dir is writable; no_test
        // skips the network call; the agent restart is best-effort (`let _ =`)
        // and fails harmlessly with no systemd unit present.
        cmd_configure_discord(
            &cli,
            Some("https://discord.com/api/webhooks/123456789/AbCdEf-token"),
            "high",
            true,
        )
        .expect("non-dry-run discord config should persist");

        let env = std::fs::read_to_string(temp.path().join("agent.env")).expect("agent.env");
        assert!(env.contains("DISCORD_WEBHOOK_URL="));
        let toml = std::fs::read_to_string(&cli.agent_config).expect("agent.toml");
        assert!(toml.contains("[discord]"));
        assert!(toml.contains("enabled = true"));
        assert!(toml.contains("high"));
    }

    #[test]
    fn send_discord_test_posts_to_webhook() {
        let url = serve_status(204, 1);
        send_discord_test(&url).expect("discord test post should succeed against mock");
    }

    #[test]
    fn cmd_configure_webhook_dry_run_validates_url_and_severity() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_configure_webhook(
            &cli,
            Some("https://example.com/innerwarden"),
            "medium",
            true,
        )
        .expect("dry-run webhook config should succeed");

        let err = cmd_configure_webhook(&cli, Some("ftp://example.com/hook"), "high", true)
            .expect_err("bad scheme should fail");
        assert!(err.to_string().contains("URL must start"));

        let err = cmd_configure_webhook(&cli, Some("https://example.com/hook"), "urgent", true)
            .expect_err("bad severity should fail");
        assert!(err.to_string().contains("min-severity"));
    }

    #[test]
    fn send_slack_and_webhook_tests_accept_local_http_success() {
        let slack_url = serve_status(200, 1);
        send_slack_test(&slack_url).expect("local slack-style endpoint should accept post");

        let webhook_url = serve_status(202, 1);
        let status = send_webhook_test(&webhook_url).expect("local webhook should accept post");
        assert_eq!(status, 202);
    }

    #[test]
    fn send_slack_and_webhook_tests_surface_connection_errors() {
        let closed_url = "http://127.0.0.1:1/hook";
        assert!(send_slack_test(closed_url).is_err());
        assert!(send_webhook_test(closed_url).is_err());
    }

    #[test]
    fn cmd_test_alert_reports_missing_and_successful_local_channels() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_test_alert(&cli, None).expect("no configured channels should be reported");
        cmd_test_alert(&cli, Some("telegram")).expect("missing telegram is reported");
        cmd_test_alert(&cli, Some("slack")).expect("missing slack is reported");
        cmd_test_alert(&cli, Some("webhook")).expect("missing webhook is reported");

        let url = serve_status(200, 2);
        let env_file = cli
            .agent_config
            .parent()
            .expect("agent parent")
            .join("agent.env");
        write_file(&env_file, &format!("SLACK_WEBHOOK_URL=\"{url}\"\n"));
        write_file(
            &cli.agent_config,
            &format!("[webhook]\nenabled = true\nurl = \"{url}\"\n"),
        );

        cmd_test_alert(&cli, None).expect("configured local slack and webhook should pass");
    }

    #[test]
    fn cmd_test_alert_bails_when_configured_local_channels_fail() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let closed_url = "http://127.0.0.1:1/hook";

        let env_file = cli
            .agent_config
            .parent()
            .expect("agent parent")
            .join("agent.env");
        write_file(&env_file, &format!("SLACK_WEBHOOK_URL=\"{closed_url}\"\n"));
        let err = cmd_test_alert(&cli, Some("slack"))
            .expect_err("configured slack failure should fail command");
        assert!(err.to_string().contains("One or more channels failed"));

        write_file(
            &cli.agent_config,
            &format!("[webhook]\nenabled = true\nurl = \"{closed_url}\"\n"),
        );
        let err = cmd_test_alert(&cli, Some("webhook"))
            .expect_err("configured webhook failure should fail command");
        assert!(err.to_string().contains("One or more channels failed"));
    }

    #[test]
    fn cmd_notify_web_push_setup_writes_config_env_and_audit() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_notify_web_push_setup(&cli, Some("mailto:security@example.com"))
            .expect("web push setup should generate keys");

        let agent = std::fs::read_to_string(&cli.agent_config).expect("agent config");
        assert!(agent.contains("[web_push]"));
        assert!(agent.contains("enabled = true"));
        assert!(agent.contains("mailto:security@example.com"));

        let env_file = cli
            .agent_config
            .parent()
            .expect("agent parent")
            .join("agent.env");
        let env = std::fs::read_to_string(env_file).expect("agent env");
        assert!(env.contains("INNERWARDEN_VAPID_PRIVATE_KEY="));
        assert!(env.contains("BEGIN PRIVATE KEY"));

        let audit_written = std::fs::read_dir(&cli.data_dir)
            .expect("audit dir")
            .flatten()
            .any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("admin-actions-"))
            });
        assert!(audit_written);
    }

    #[test]
    fn cmd_notify_web_push_setup_keeps_existing_keys_on_default_answer() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        write_file(
            &cli.agent_config,
            "[web_push]\nvapid_public_key = \"existing-key\"\n",
        );

        cmd_notify_web_push_setup(&cli, None)
            .expect("existing key branch should keep configuration by default");

        let agent = std::fs::read_to_string(&cli.agent_config).expect("agent config");
        assert!(agent.contains("existing-key"));
    }

    #[cfg(unix)]
    #[test]
    fn cmd_configure_dashboard_dry_run_uses_agent_hash_output() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let agent = write_fake_agent(
            temp.path(),
            "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '$argon2id$v=19$m=1,t=1,p=1$abc$def'\n",
        );

        with_agent_bin(&agent, || {
            cmd_configure_dashboard(&cli, "admin", Some("correct horse battery staple"))
                .expect("dashboard dry-run should accept fake agent hash");
        });
    }

    #[cfg(unix)]
    #[test]
    fn cmd_configure_dashboard_interactive_path_uses_agent_stdout() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let agent = write_fake_agent(
            temp.path(),
            "#!/bin/sh\nprintf '%s\\n' '$argon2id$v=19$m=1,t=1,p=1$abc$def'\n",
        );

        with_agent_bin(&agent, || {
            cmd_configure_dashboard(&cli, "admin", None)
                .expect("dashboard dry-run interactive path should accept fake agent hash");
        });
    }

    #[cfg(unix)]
    #[test]
    fn cmd_configure_dashboard_reports_agent_failures_and_bad_output() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        let failing = write_fake_agent(temp.path(), "#!/bin/sh\nexit 42\n");
        let err = with_agent_bin(&failing, || {
            cmd_configure_dashboard(&cli, "admin", Some("password"))
                .expect_err("failing agent should surface an error")
        });
        assert!(err.to_string().contains("agent binary failed"));

        let bad_output = write_fake_agent(temp.path(), "#!/bin/sh\nprintf '%s\\n' 'not-a-hash'\n");
        let err = with_agent_bin(&bad_output, || {
            cmd_configure_dashboard(&cli, "admin", Some("password"))
                .expect_err("bad hash output should surface an error")
        });
        assert!(err.to_string().contains("unexpected output"));
    }

    #[test]
    fn add_dashboard_flag_to_service_content_patches_execstart_when_missing() {
        let content = "[Service]\nEnvironmentFile=/etc/innerwarden/agent.env\nExecStart=/usr/bin/innerwarden-agent\n";
        let patched = add_dashboard_flag_to_service_content(content)
            .expect("service content with ExecStart should be patched");
        assert!(patched.contains("ExecStart=/usr/bin/innerwarden-agent --dashboard"));

        assert!(add_dashboard_flag_to_service_content(&patched).is_none());
        assert!(add_dashboard_flag_to_service_content("[Service]\nRestart=always\n").is_none());
    }
}

pub(crate) fn cmd_configure_budget(cli: &Cli, max: u32) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }

    if cli.dry_run {
        println!("  [dry-run] would set [telegram] daily_budget = {max}");
    } else {
        config_editor::write_int(
            &cli.agent_config,
            "telegram",
            "daily_budget",
            i64::from(max),
        )?;
        println!("  Telegram daily budget set to {max} notifications/day.");
        println!("  Critical alerts always break the budget.");
        restart_agent(cli);
    }

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "telegram.daily_budget".to_string(),
        parameters: serde_json::json!({ "max": max }),
        result: if cli.dry_run {
            "dry_run".to_string()
        } else {
            "success".to_string()
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}
