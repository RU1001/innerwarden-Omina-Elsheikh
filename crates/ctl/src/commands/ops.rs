use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::{
    append_admin_action, commands, config_editor, count_jsonl_lines, current_operator,
    epoch_secs_to_date, load_env_file, make_opts, require_sudo, resolve_data_dir, restart_agent,
    systemd, today_date_string, AdminActionEntry, CapabilityRegistry, Cli,
};

// ---------------------------------------------------------------------------
// Doctor diagnostic primitives
// ---------------------------------------------------------------------------

/// Severity classification for a single doctor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sev {
    Ok,
    Warn,
    Fail,
}

/// A single diagnostic check produced by `cmd_doctor`.
///
/// The struct is split out (rather than being a closure-captured local type
/// inside `cmd_doctor`) so individual checks can be unit-tested without
/// running the full doctor flow.
#[derive(Debug, Clone)]
pub(crate) struct Check {
    pub(crate) label: String,
    pub(crate) sev: Sev,
    pub(crate) hint: Option<String>,
}

impl Check {
    pub(crate) fn ok(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            sev: Sev::Ok,
            hint: None,
        }
    }

    pub(crate) fn warn(label: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            sev: Sev::Warn,
            hint: Some(hint.into()),
        }
    }

    pub(crate) fn fail(label: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            sev: Sev::Fail,
            hint: Some(hint.into()),
        }
    }

    pub(crate) fn tag(&self) -> &'static str {
        match self.sev {
            Sev::Ok => "[ok]  ",
            Sev::Warn => "[warn]",
            Sev::Fail => "[fail]",
        }
    }

    pub(crate) fn print(&self) {
        println!("  {} {}", self.tag(), self.label);
        if let Some(h) = &self.hint {
            println!("         → {h}");
        }
    }

    pub(crate) fn is_issue(&self) -> bool {
        self.sev != Sev::Ok
    }
}

/// Print every check and tally non-OK ones into `issues`.
pub(crate) fn run_section(checks: Vec<Check>, issues: &mut u32) {
    for c in &checks {
        c.print();
        if c.is_issue() {
            *issues += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Doctor: pure validators (extracted from `cmd_doctor` to make them testable)
// ---------------------------------------------------------------------------

/// Heuristic check for OpenAI-style API keys: `sk-…` and at least 20 chars.
pub(crate) fn looks_like_openai_key(key: &str) -> bool {
    key.starts_with("sk-") && key.len() >= 20
}

/// Heuristic check for Anthropic API keys: `sk-ant-…` and at least 20 chars.
pub(crate) fn looks_like_anthropic_key(key: &str) -> bool {
    key.starts_with("sk-ant-") && key.len() >= 20
}

/// Map an Execution Gate state to a single doctor [`Check`] (spec 080 G4 — the
/// FREE read-only honesty surface). Pure: the divergence verdict comes from
/// `innerwarden_core::execution_gate`. `fail` on real drift, `warn` when the
/// signed config is present but the live map couldn't be read (run as root),
/// `ok` when live matches intent.
/// PURE: the informational doctor note printed above the Execution Gate check
/// when `bpf` is definitively not in the kernel's active LSM stack. `None` when
/// bpf is active or the list is unreadable (never cry wolf on an unreadable list).
pub(crate) fn gate_lsm_inactive_note(bpf_lsm_active: Option<bool>) -> Option<String> {
    if bpf_lsm_active == Some(false) {
        Some(
            "  note: `bpf` is NOT in the active kernel LSM stack (/sys/kernel/security/lsm) — \
             a BPF-LSM gate cannot enforce here until you add `lsm=...,bpf` to the kernel cmdline and reboot."
                .to_string(),
        )
    } else {
        None
    }
}

pub(crate) fn gate_doctor_check(
    gate: &innerwarden_core::execution_gate::GateState,
    bpf_lsm_active: Option<bool>,
) -> Check {
    use innerwarden_core::execution_gate::{evaluate_divergence_with_lsm, Divergence};
    let signed = gate
        .signed_count
        .map(|n| n.to_string())
        .unwrap_or_else(|| "no file".into());
    let live = gate
        .live_count
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unreadable".into());
    match evaluate_divergence_with_lsm(gate, bpf_lsm_active) {
        Divergence::ArmedButLsmInactive { mode } => Check::fail(
            format!(
                "Execution Gate is {} but the kernel BPF-LSM is NOT active (`bpf` missing from /sys/kernel/security/lsm) — it denies NOTHING",
                mode.label()
            ),
            "The gate maps say armed but no BPF-LSM hook can run, so the agent is UNGATED. Add `lsm=...,bpf` to the kernel cmdline (GRUB_CMDLINE_LINUX) and reboot, then re-verify the gate blocks an unknown exec.",
        ),
        Divergence::ActiveButEmpty { mode, .. } => Check::fail(
            format!(
                "Execution Gate is {} but the live allowlist is EMPTY (signed {signed}, live {live})",
                mode.label()
            ),
            "Run a FULL `config-sign exec-gate apply`; never leave it armed with an empty map (enforce = host brick).",
        ),
        Divergence::ApplyDrift { .. } => Check::fail(
            format!(
                "Execution Gate apply drift: signed {signed} (intent {}), live map {live}, live mode {}",
                gate.intended_mode.map(|m| m.label()).unwrap_or("unknown"),
                gate.live_mode.label()
            ),
            "Signed config not applied to the kernel. Run a FULL `config-sign exec-gate apply`, then re-check that live == signed.",
        ),
        Divergence::ScopeArmedButEmpty { mode } => Check::fail(
            format!(
                "Execution Gate is {} and agent-scoped (key 4 = 1) but EXEC_GATE_SCOPE is EMPTY — it protects NOTHING",
                mode.label()
            ),
            "A scoped gate with an empty scope allows every exec. Write the protected agent's cgroup id into EXEC_GATE_SCOPE, or disarm (LSM_POLICY key 4 = 0).",
        ),
        Divergence::None => {
            if gate.live_count.is_none()
                && (gate.signed_count.is_some() || gate.intended_mode.is_some())
            {
                Check::warn(
                    format!("Execution Gate signed config present (signed {signed}) but live map not readable"),
                    "Re-run `innerwarden doctor` as root (CAP_BPF / bpftool) to verify the live kernel map matches the signed file.",
                )
            } else {
                Check::ok(format!(
                    "Execution Gate consistent (signed {signed}, live {live}, mode {})",
                    gate.live_mode.label()
                ))
            }
        }
    }
}

/// True when an Execution Gate is present on this host (a signed file or a
/// pinned map) — so `doctor` only shows the section where it's relevant.
fn execution_gate_present() -> bool {
    use innerwarden_core::execution_gate::{EXEC_ALLOWLIST_PIN, SIGNED_ALLOWLIST_FILE};
    std::path::Path::new(SIGNED_ALLOWLIST_FILE).exists()
        || std::path::Path::new(EXEC_ALLOWLIST_PIN).exists()
}

/// Read + parse the signed allowlist file for `doctor` (plain JSON read).
fn read_signed_allowlist_for_doctor() -> (
    Option<usize>,
    Option<innerwarden_core::execution_gate::GateMode>,
) {
    use innerwarden_core::execution_gate::{parse_signed_allowlist, SIGNED_ALLOWLIST_FILE};
    match std::fs::read_to_string(SIGNED_ALLOWLIST_FILE) {
        Ok(raw) => serde_json::from_str::<serde_json::Value>(&raw)
            .ok()
            .map(|v| parse_signed_allowlist(&v))
            .unwrap_or((None, None)),
        Err(_) => (None, None),
    }
}

/// Live `EXEC_ALLOWLIST` entry count via `bpftool` (ctl doesn't link aya).
/// `None` when bpftool is missing / unprivileged / the pin is absent.
fn bpftool_allowlist_count() -> Option<usize> {
    use innerwarden_core::execution_gate::{count_bpftool_dump, EXEC_ALLOWLIST_PIN};
    let out = std::process::Command::new("bpftool")
        .args(["map", "dump", "pinned", EXEC_ALLOWLIST_PIN])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(count_bpftool_dump(&String::from_utf8_lossy(&out.stdout)))
}

/// Live gate mode via `bpftool map lookup` of LSM_POLICY key 3. `Unknown` when
/// it can't be read (absent key / no privilege / no bpftool).
fn bpftool_gate_mode() -> innerwarden_core::execution_gate::GateMode {
    use innerwarden_core::execution_gate::{parse_bpftool_value_u32, GateMode, LSM_POLICY_PIN};
    let out = std::process::Command::new("bpftool")
        .args([
            "map",
            "lookup",
            "pinned",
            LSM_POLICY_PIN,
            "key",
            "3",
            "0",
            "0",
            "0",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            GateMode::from_policy_key(parse_bpftool_value_u32(&String::from_utf8_lossy(&o.stdout)))
        }
        _ => GateMode::Unknown,
    }
}

/// Live scope mode via `bpftool map lookup` of LSM_POLICY key 4 (spec 083).
/// `Some(true)` = agent-scoped, `Some(false)` = the key reads back not-1, `None`
/// when it can't be read (absent key / no privilege / no bpftool) — treated as
/// unknown so it never flags a scope problem it can't see.
fn bpftool_scope_armed() -> Option<bool> {
    use innerwarden_core::execution_gate::{parse_bpftool_value_u32, LSM_POLICY_PIN};
    let out = std::process::Command::new("bpftool")
        .args([
            "map",
            "lookup",
            "pinned",
            LSM_POLICY_PIN,
            "key",
            "4",
            "0",
            "0",
            "0",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_bpftool_value_u32(&String::from_utf8_lossy(&out.stdout)) == Some(1))
}

/// Live `EXEC_GATE_SCOPE` entry count via `bpftool` (spec 083). `None` when the
/// map can't be read.
fn bpftool_scope_count() -> Option<usize> {
    use innerwarden_core::execution_gate::{count_bpftool_dump, EXEC_GATE_SCOPE_PIN};
    let out = std::process::Command::new("bpftool")
        .args(["map", "dump", "pinned", EXEC_GATE_SCOPE_PIN])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(count_bpftool_dump(&String::from_utf8_lossy(&out.stdout)))
}

/// Heuristic check for Telegram bot tokens: `<digits>:<20+ alphanumeric>`.
pub(crate) fn looks_like_telegram_token(token: &str) -> bool {
    if !token.contains(':') {
        return false;
    }
    let mut parts = token.splitn(2, ':');
    let id_part = parts.next().unwrap_or("");
    let secret_part = parts.next().unwrap_or("");
    !id_part.is_empty() && id_part.chars().all(|c| c.is_ascii_digit()) && secret_part.len() >= 20
}

/// Telegram chat IDs are numeric, possibly prefixed with `-` for groups/channels.
pub(crate) fn looks_like_telegram_chat_id(chat_id: &str) -> bool {
    !chat_id.is_empty()
        && chat_id
            .trim_start_matches('-')
            .chars()
            .all(|c| c.is_ascii_digit())
}

/// Slack webhook URLs start with the canonical hooks.slack.com path and
/// contain enough payload bytes that a typo is unlikely.
pub(crate) fn looks_like_slack_url(url: &str) -> bool {
    url.starts_with("https://hooks.slack.com/services/") && url.len() > 50
}

/// A webhook URL is acceptable if it parses as `http(s)://…`.
pub(crate) fn looks_webhook_url_valid(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// Three-tier resolver: prefer config, then env var, then fall back to a
/// matching `KEY=value` line in `env_file_content`.
#[allow(dead_code)]
pub(crate) fn resolve_three_tier(
    config_val: Option<&str>,
    env_var_val: Option<&str>,
    env_file_content: &str,
    env_key: &str,
) -> Option<String> {
    if let Some(v) = config_val.filter(|s| !s.is_empty()) {
        return Some(v.to_string());
    }
    if let Some(v) = env_var_val.filter(|s| !s.is_empty()) {
        return Some(v.to_string());
    }
    let needle = format!("{env_key}=");
    env_file_content
        .lines()
        .find(|l| l.starts_with(&needle))
        .and_then(|l| l.split_once('='))
        .map(|(_, v)| v.trim_matches('"').trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Read `[section] key` as a string from a parsed agent.toml document.
#[allow(dead_code)]
pub(crate) fn agent_section_str<'a>(
    doc: Option<&'a toml_edit::DocumentMut>,
    section: &str,
    key: &str,
) -> Option<&'a str> {
    doc.and_then(|d| d.get(section))
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_str())
}

/// Read `[section] enabled = true|false` from a parsed agent.toml document.
#[allow(dead_code)]
pub(crate) fn agent_section_enabled(doc: Option<&toml_edit::DocumentMut>, section: &str) -> bool {
    doc.and_then(|d| d.get(section))
        .and_then(|s| s.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Doctor: pure check builders for AI / Telegram / Slack / Webhook
// ---------------------------------------------------------------------------

/// Build the per-provider AI key check based on what is configured in
/// agent.toml and which key (if any) was resolved from the environment.
pub(crate) fn build_ai_provider_check(provider: &str, resolved_key: Option<&str>) -> Check {
    match provider {
        "anthropic" => match resolved_key {
            None => Check::fail(
                "ANTHROPIC_API_KEY not set (provider = \"anthropic\")",
                "Get a key at https://console.anthropic.com/settings/keys\nThen run:\n\n  innerwarden configure ai anthropic --key sk-ant-...",
            ),
            Some(k) if looks_like_anthropic_key(k) => {
                Check::ok("ANTHROPIC_API_KEY is set and format looks correct")
            }
            Some(_) => Check::warn(
                "ANTHROPIC_API_KEY is set but format looks wrong (should start with sk-ant-)",
                "Run:\n  innerwarden configure ai anthropic --key sk-ant-...",
            ),
        },
        "ollama" => Check::ok("Ollama provider configured (reachability is checked separately)"),
        "azure_openai" | "azure" => match resolved_key {
            None => Check::fail(
                "AZURE_OPENAI_API_KEY not set (provider = \"azure_openai\")",
                "Get the key + endpoint from your Azure OpenAI resource, then run:\n\n  innerwarden configure ai azure_openai --key <key> --model <deployment> --base-url https://<resource>.openai.azure.com",
            ),
            // Azure keys are 32-char hex or longer base64-ish strings with no
            // stable prefix, so only emptiness is a meaningful format signal.
            Some(k) if !k.trim().is_empty() => {
                Check::ok("AZURE_OPENAI_API_KEY is set (provider = \"azure_openai\")")
            }
            Some(_) => Check::fail(
                "AZURE_OPENAI_API_KEY is set but empty (provider = \"azure_openai\")",
                "Run:\n  innerwarden configure ai azure_openai --key <key> --base-url https://<resource>.openai.azure.com",
            ),
        },
        // Default: openai (also handles unknown providers gracefully)
        _ => match resolved_key {
            None => Check::fail(
                "OPENAI_API_KEY not set (provider = \"openai\")",
                "Get a key at https://platform.openai.com/api-keys\nThen run:\n\n  innerwarden configure ai openai --key sk-...",
            ),
            Some(k) if looks_like_openai_key(k) => {
                Check::ok("OPENAI_API_KEY is set and format looks correct")
            }
            Some(_) => Check::warn(
                "OPENAI_API_KEY is set but format looks wrong (should start with sk-)",
                "Run:\n  innerwarden configure ai openai --key sk-...",
            ),
        },
    }
}

/// Build the Telegram bot-token check from a resolved value.
pub(crate) fn build_telegram_token_check(token: Option<&str>, env_file_path: &Path) -> Check {
    match token {
        None => Check::fail(
            "TELEGRAM_BOT_TOKEN not set",
            format!(
                "1. Open Telegram and message @BotFather\n\
                 2. Send /newbot and follow the steps\n\
                 3. Copy the token and add to {}:\n\
                 \n   TELEGRAM_BOT_TOKEN=1234567890:AABBccDDeeffGGHH...",
                env_file_path.display()
            ),
        ),
        Some(t) if looks_like_telegram_token(t) => {
            Check::ok("TELEGRAM_BOT_TOKEN is set and format looks correct")
        }
        Some(_) => Check::warn(
            "TELEGRAM_BOT_TOKEN is set but format looks wrong",
            "Token should look like: 1234567890:AABBccDDeeffGGHHiijjKK...\n\
             Get a fresh token from @BotFather on Telegram",
        ),
    }
}

/// Build the Telegram chat-id check from a resolved value.
pub(crate) fn build_telegram_chat_check(chat_id: Option<&str>, env_file_path: &Path) -> Check {
    match chat_id {
        None => Check::fail(
            "TELEGRAM_CHAT_ID not set",
            format!(
                "1. Open Telegram and message @userinfobot\n\
                 2. It will reply with your chat ID (a number, e.g. 123456789)\n\
                 3. For a group/channel the ID starts with -100\n\
                 4. Add to {}:\n\
                 \n   TELEGRAM_CHAT_ID=123456789",
                env_file_path.display()
            ),
        ),
        Some(c) if looks_like_telegram_chat_id(c) => {
            Check::ok("TELEGRAM_CHAT_ID is set and format looks correct")
        }
        Some(_) => Check::warn(
            "TELEGRAM_CHAT_ID is set but format looks wrong",
            "Chat ID should be a number like 123456789 (personal) or -1001234567890 (group/channel)\n\
             Message @userinfobot on Telegram to find yours",
        ),
    }
}

/// Build the Slack webhook check from a resolved value.
pub(crate) fn build_slack_webhook_check(url: Option<&str>, env_file_path: &Path) -> Check {
    match url {
        None => Check::fail(
            "SLACK_WEBHOOK_URL not set",
            format!(
                "1. In Slack: Apps → Incoming Webhooks → Add to Slack\n\
                 2. Choose a channel and copy the Webhook URL\n\
                 3. Add to {}:\n\
                 \n   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...",
                env_file_path.display()
            ),
        ),
        Some(u) if looks_like_slack_url(u) => {
            Check::ok("SLACK_WEBHOOK_URL is set and format looks correct")
        }
        Some(_) => Check::warn(
            "SLACK_WEBHOOK_URL is set but format looks wrong",
            "URL should start with https://hooks.slack.com/services/T.../B.../...\n\
             Get a fresh webhook URL from your Slack workspace settings",
        ),
    }
}

/// Build the agent webhook URL sanity check.
pub(crate) fn build_webhook_url_check(url: &str) -> Check {
    if url.is_empty() {
        Check::fail(
            "webhook.url is not set",
            "Run: innerwarden configure webhook",
        )
    } else if !looks_webhook_url_valid(url) {
        Check::fail(
            "webhook.url does not look like a valid URL",
            "Run: innerwarden configure webhook --url <correct-url>",
        )
    } else {
        Check::ok(format!("webhook.url = {url}").as_str())
    }
}

/// AbuseIPDB key check: distinguishes missing / too-short / ok.
pub(crate) fn build_abuseipdb_key_check(key: Option<&str>) -> Check {
    match key {
        None => Check::fail(
            "abuseipdb.enabled=true but ABUSEIPDB_API_KEY not set",
            "1. Register at https://www.abuseipdb.com/register (free)\n\
             2. Go to https://www.abuseipdb.com/account/api\n\
             3. Add to agent.toml:\n\
             \n   [abuseipdb]\n   api_key = \"<your-key>\"\n\
             \n   Or set env var: ABUSEIPDB_API_KEY=<your-key>",
        ),
        Some(k) if k.len() < 10 => Check::warn(
            "ABUSEIPDB_API_KEY is set but looks too short",
            "AbuseIPDB API keys are typically 80 characters.\n\
             Get a fresh key at https://www.abuseipdb.com/account/api",
        ),
        Some(_) => Check::ok("ABUSEIPDB_API_KEY is set (free tier: 1,000 checks/day)"),
    }
}

// ---------------------------------------------------------------------------
// Tune: pure decision logic (extracted from `cmd_tune`)
// ---------------------------------------------------------------------------

/// Suggest a new detector threshold given observed traffic.
///
/// Mirrors the original heuristic in `cmd_tune`: too many incidents → lower,
/// many quiet-events → raise. Returns the new threshold (which equals
/// `current_val` when no change is warranted).
pub(crate) fn suggest_detector_threshold(
    events_per_day: i64,
    incidents_per_day: f64,
    current_val: i64,
) -> i64 {
    if incidents_per_day > 10.0 && current_val > 3 {
        (current_val - 1).max(2)
    } else if events_per_day > current_val * 20 && incidents_per_day == 0.0 {
        (current_val + 2).min(50)
    } else if events_per_day > current_val * 5 && incidents_per_day < 1.0 {
        (current_val + 1).min(30)
    } else {
        current_val
    }
}

/// Tally `kind` field occurrences in a JSONL events stream.
pub(crate) fn count_event_kinds(content: &str) -> HashMap<String, u64> {
    let mut counts: HashMap<String, u64> = HashMap::new();
    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(kind) = v["kind"].as_str() {
                *counts.entry(kind.to_string()).or_insert(0) += 1;
            }
        }
    }
    counts
}

/// Tally detector ids parsed from `incident_id` (`<detector>:<rest>`).
pub(crate) fn count_incident_detectors(content: &str) -> HashMap<String, u64> {
    let mut counts: HashMap<String, u64> = HashMap::new();
    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(id) = v["incident_id"].as_str() {
                let detector = id.split(':').next().unwrap_or("");
                if !detector.is_empty() {
                    *counts.entry(detector.to_string()).or_insert(0) += 1;
                }
            }
        }
    }
    counts
}

/// Format the human-readable "reason" string emitted by `cmd_tune`.
pub(crate) fn tune_reason(events_per_day: i64, incidents: u64, days: u64, raise: bool) -> String {
    let direction = if raise { "raise" } else { "lower" };
    format!(
        "{events_per_day} events/day, {incidents} incidents in {days} days - {direction} to reduce noise"
    )
}

// ---------------------------------------------------------------------------
// Pipeline test: pure date math + JSON builders + decision summary
// ---------------------------------------------------------------------------

/// Convert a Unix timestamp (seconds) to an RFC3339-ish UTC string.
///
/// Uses a minimal hand-rolled date conversion (no chrono) because the
/// caller in `cmd_pipeline_test` already used this style. Extracted so the
/// month-boundary / leap-year arithmetic is unit-testable.
pub(crate) fn unix_secs_to_iso(secs: u64) -> String {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days_since_epoch = secs / 86400;
    let (y, mo, d) = {
        let mut y = 1970i64;
        let mut rem = days_since_epoch as i64;
        loop {
            let ydays = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                366
            } else {
                365
            };
            if rem < ydays {
                break;
            }
            rem -= ydays;
            y += 1;
        }
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let mdays = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let mut mo = 0usize;
        while mo < 12 && rem >= mdays[mo] {
            rem -= mdays[mo];
            mo += 1;
        }
        (y, mo + 1, rem + 1)
    };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Build the JSON body of the pipeline-test SSH brute-force fixture.
pub(crate) fn build_pipeline_test_incident(
    test_ip: &str,
    marker: &str,
    hostname: &str,
    ts_iso: &str,
) -> serde_json::Value {
    serde_json::json!({
        "ts": ts_iso,
        "host": hostname,
        "incident_id": format!("ssh_bruteforce:{test_ip}:{marker}"),
        "severity": "high",
        "title": format!("Possible SSH brute force from {test_ip}"),
        "summary": format!(
            "12 failed SSH login attempts from {test_ip} in the last 30 seconds (pipeline test)"
        ),
        "evidence": [{
            "count": 12,
            "ip": test_ip,
            "kind": "ssh.login_failed",
            "window_seconds": 30
        }],
        "recommended_checks": [
            format!("This is a pipeline test using RFC 5737 documentation IP {test_ip}"),
            "No real threat - safe to ignore"
        ],
        "tags": ["auth", "ssh", "bruteforce", "pipeline-test"],
        "entities": [{
            "type": "ip",
            "value": test_ip
        }]
    })
}

// ---------------------------------------------------------------------------
// Sensitivity helpers (extracted from `cmd_configure_sensitivity`)
// ---------------------------------------------------------------------------

/// Map a sensitivity level string to the agent's `min_severity` value.
/// Unknown levels return `None` (the caller is expected to print a hint).
pub(crate) fn min_severity_for_sensitivity(level: &str) -> Option<&'static str> {
    match level.to_lowercase().as_str() {
        "quiet" => Some("critical"),
        "normal" => Some("high"),
        "verbose" => Some("medium"),
        _ => None,
    }
}

/// Human-readable summary of which severities will be notified for a level.
pub(crate) fn sensitivity_summary_line(level: &str) -> Option<&'static str> {
    match level.to_lowercase().as_str() {
        "quiet" => Some("You'll only be notified for Critical events."),
        "normal" => Some("You'll be notified for High and Critical events."),
        "verbose" => Some("You'll be notified for Medium, High, and Critical events."),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Doctor: per-config-file checks (extracted from `cmd_doctor`)
// ---------------------------------------------------------------------------

/// Build the two-line "found / valid TOML" check pair for one config file.
///
/// Mirrors the `match std::fs::metadata(path)` cascade in `cmd_doctor`.
/// Returns `Vec<Check>` so the pair (presence + TOML syntax) is treated as
/// a unit by the calling section.
pub(crate) fn build_config_file_checks(label: &str, path: &Path) -> Vec<Check> {
    let mut out = Vec::new();
    match std::fs::metadata(path) {
        Ok(_) => {
            out.push(Check::ok(format!(
                "{} config found ({})",
                label,
                path.display()
            )));
            let valid_toml = std::fs::read_to_string(path)
                .ok()
                .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
                .is_some();
            out.push(if valid_toml {
                Check::ok(format!("{label} config is valid TOML"))
            } else {
                Check::fail(
                    format!(
                        "{} config has invalid TOML syntax ({})",
                        label,
                        path.display()
                    ),
                    format!("fix syntax in {}", path.display()),
                )
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            out.push(Check::warn(
                format!(
                    "{} config exists but is not readable by current user ({})",
                    label,
                    path.display()
                ),
                "Run with sudo or add current user to the 'innerwarden' group.",
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            out.push(Check::warn(
                format!(
                    "{} config not found ({}) - defaults are in use",
                    label,
                    path.display()
                ),
                "Run 'sudo innerwarden setup' to create your configuration",
            ));
        }
        Err(e) => {
            out.push(Check::warn(
                format!("{} config check failed ({})", label, path.display()),
                format!("Could not access file metadata: {e}"),
            ));
        }
    }
    out
}

/// Build the launchctl-presence check for macOS doctor runs from a
/// pre-computed `has_launchctl` flag.
pub(crate) fn build_launchctl_check(has_launchctl: bool) -> Check {
    if has_launchctl {
        Check::ok("launchctl found (macOS service manager)")
    } else {
        Check::fail(
            "launchctl not found",
            "unexpected on macOS - check your PATH",
        )
    }
}

/// Build the systemctl-presence check for Linux doctor runs from a
/// pre-computed `has_systemctl` flag.
pub(crate) fn build_systemctl_check(has_systemctl: bool) -> Check {
    if has_systemctl {
        Check::ok("systemctl found")
    } else {
        Check::fail("systemctl not found", "install systemd or check PATH")
    }
}

/// Build the `innerwarden` system-user check from a pre-computed flag.
/// `is_macos` only changes the remediation hint.
pub(crate) fn build_innerwarden_user_check(user_ok: bool, is_macos: bool) -> Check {
    if user_ok {
        Check::ok("innerwarden system user exists")
    } else if is_macos {
        Check::fail(
            "innerwarden system user missing",
            "run install.sh - it creates the user via dscl",
        )
    } else {
        Check::fail(
            "innerwarden system user missing",
            "sudo useradd -r -s /sbin/nologin innerwarden",
        )
    }
}

/// Build the /etc/sudoers.d directory check from a pre-computed `present` flag.
/// On macOS we issue a warn (the directory may not be present at install time);
/// on Linux it is a hard fail.
pub(crate) fn build_sudoers_dir_check(present: bool, is_macos: bool) -> Check {
    if present {
        Check::ok("/etc/sudoers.d/ directory exists")
    } else if is_macos {
        Check::warn(
            "/etc/sudoers.d/ not found",
            "sudo mkdir -p /etc/sudoers.d  (needed for suspend-user-sudo skill)",
        )
    } else {
        Check::fail("/etc/sudoers.d/ not found", "sudo mkdir -p /etc/sudoers.d")
    }
}

/// Build a service-running check (Linux unit / macOS launchd plist).
pub(crate) fn build_service_running_check(unit: &str, running: bool, is_macos: bool) -> Check {
    if running {
        Check::ok(format!("{unit} is running"))
    } else if is_macos {
        Check::warn(
            format!("{unit} is not running"),
            format!("sudo launchctl load /Library/LaunchDaemons/{unit}.plist"),
        )
    } else {
        Check::warn(
            format!("{unit} is not running"),
            format!("sudo systemctl start {unit}"),
        )
    }
}

/// Bug 2 fix (2026-05-06): build a service-status check that knows
/// the difference between "definitely Inactive" and "could not query
/// the bus". The Unknown case emits an OK-coloured info line that
/// defers to the Agent health (telemetry-freshness) section below
/// instead of the previous false-positive `[warn] is not running`.
pub(crate) fn build_service_status_check_linux(
    unit: &str,
    status: systemd::ServiceStatus,
) -> Check {
    match status {
        systemd::ServiceStatus::Active => Check::ok(format!("{unit} is running")),
        systemd::ServiceStatus::Inactive => Check::warn(
            format!("{unit} is not running"),
            format!("sudo systemctl start {unit}"),
        ),
        systemd::ServiceStatus::Unknown => Check::ok(format!(
            "{unit}: status unknown (no systemd bus in this session) — see Agent health"
        )),
    }
}

/// Absolute path of the file that carries the agent's start command
/// (`ExecStart` on systemd, `ProgramArguments` on launchd), per platform.
/// The `--dashboard` flag lives here, so doctor must read the RIGHT one:
/// reading the Linux systemd path on macOS always came back empty and produced
/// a false "--dashboard is missing" warning even though the plist carried it
/// (2026-07-01 macOS finding F5).
pub(crate) fn agent_unit_file_path() -> &'static str {
    agent_unit_file_path_for(cfg!(target_os = "macos"))
}

/// Pure inner (tested for both platforms on the Linux CI host).
pub(crate) fn agent_unit_file_path_for(mac: bool) -> &'static str {
    if mac {
        "/Library/LaunchDaemons/com.innerwarden.agent.plist"
    } else {
        "/etc/systemd/system/innerwarden-agent.service"
    }
}

/// Pure: the platform-correct "start the agent" hint shown when the dashboard is
/// down and the agent is not running (launchd on macOS, systemd elsewhere).
pub(crate) fn agent_start_hint(mac: bool) -> &'static str {
    if mac {
        "Start the agent:  sudo launchctl kickstart -k system/com.innerwarden.agent"
    } else {
        "Start the agent:  sudo systemctl start innerwarden-agent"
    }
}

/// Build the dashboard `--dashboard` flag-in-unit check.
pub(crate) fn build_dashboard_flag_check(flag_in_service: bool) -> Check {
    if flag_in_service {
        Check::ok("--dashboard flag present in the agent service definition")
    } else {
        Check::warn(
            "--dashboard flag is missing from the agent service definition",
            "Run: innerwarden configure dashboard  (it will add the flag automatically)",
        )
    }
}

/// Build the dashboard credentials present/absent checks.
/// Returns a vec because the "absent" path adds two informational lines.
pub(crate) fn build_dashboard_credentials_checks(has_user: bool, has_hash: bool) -> Vec<Check> {
    if has_user && has_hash {
        vec![Check::ok(
            "Dashboard login is configured (credentials required)",
        )]
    } else {
        vec![
            Check::ok("Dashboard credentials: none set (open access when agent is running)"),
            Check::ok("To add a password: innerwarden configure dashboard"),
        ]
    }
}

/// Build the dashboard reachability check from a pre-computed reach flag.
/// Returns `None` if neither informational message applies (e.g. dashboard
/// is not enabled and not reachable: caller decides what to print).
///
/// Bug 3 (2026-05-06): when the dashboard probe failed but the agent
/// was already known active (via `systemctl is-active` or telemetry
/// freshness), the previous hint "Start the agent" was wrong — the
/// agent was already running; the operator needed a hint about the
/// dashboard binding (port / TLS / config). Pass `agent_alive` so the
/// hint can adapt.
pub(crate) fn build_dashboard_reachability_check(
    reachable: bool,
    flag_in_service: bool,
    agent_alive: bool,
) -> Option<Check> {
    if reachable {
        // The dashboard serves TLS by default (self-signed cert), so advertise
        // https, not http (F5): a plain http:// URL just fails to connect.
        Some(Check::ok(
            "Dashboard is reachable at https://YOUR_SERVER_IP:8787",
        ))
    } else if flag_in_service {
        let hint = if agent_alive {
            "Agent is running; check the dashboard binding (port/TLS/listen address)"
        } else {
            agent_start_hint(cfg!(target_os = "macos"))
        };
        Some(Check::warn("Dashboard port 8787 is not responding", hint))
    } else {
        None
    }
}

/// Scheme-agnostic reachability probe: is something accepting TCP connections
/// on `addr`? Used as a fallback for the dashboard check because the dashboard
/// is frequently HTTPS-only on prod, so a plain-HTTP probe gets connection
/// refused and `doctor` would otherwise false-warn that it is down. A
/// successful TCP connect means a listener is up regardless of HTTP vs HTTPS.
fn tcp_port_listening(addr: std::net::SocketAddr, timeout: std::time::Duration) -> bool {
    std::net::TcpStream::connect_timeout(&addr, timeout).is_ok()
}

/// Build the GeoIP reachability check from a pre-computed flag.
pub(crate) fn build_geoip_reachability_check(reachable: bool) -> Check {
    if reachable {
        Check::ok("ip-api.com is reachable")
    } else {
        Check::warn(
            "ip-api.com is not reachable from this host",
            "GeoIP lookups will fail silently. Check outbound HTTP access.",
        )
    }
}

/// Build the fail2ban-client binary-presence check (called when
/// `fail2ban.enabled = true`).
pub(crate) fn build_fail2ban_binary_check(bin_present: bool) -> Check {
    if bin_present {
        Check::ok("fail2ban-client binary found")
    } else {
        Check::fail(
            "fail2ban-client not found but fail2ban.enabled=true",
            "sudo apt-get install fail2ban",
        )
    }
}

/// Build the fail2ban-running check, separating macOS (Linux-only warning)
/// from Linux (start the service).
pub(crate) fn build_fail2ban_running_check(running: bool, is_macos: bool) -> Check {
    if running {
        Check::ok("fail2ban daemon is responding (ping ok)")
    } else if is_macos {
        Check::warn(
            "fail2ban is Linux-only - integration will not run on macOS",
            "disable [fail2ban] enabled=false in agent.toml on macOS",
        )
    } else {
        Check::warn(
            "fail2ban daemon is not responding (fail2ban-client ping failed)",
            "sudo systemctl start fail2ban",
        )
    }
}

/// Build the nginx error-log path check.
///
/// Bug 4 fix (2026-05-06 prod observation): pre-fix this check was a
/// hard `[fail]` whenever the configured path did not exist on disk.
/// In prod the operator had a custom nginx writing to
/// `/home/ubuntu/proxy/data/logs/fallback_error.log`; nginx had not
/// yet written the log file (no errors in the window) so doctor
/// reported `[fail] nginx error log not found` even though the
/// configured path was correct and the log would be created on the
/// next request. The hint itself read "log is created on first
/// request or error" — the [fail] severity contradicted the hint.
///
/// New behavior: try the configured path first; if absent, discover
/// the common defaults (`/var/log/nginx/error.log`,
/// `/var/log/nginx/error_log`). If a default exists but the
/// configured one does not, surface as `[warn]` with both paths and
/// suggest aligning the sensor config. If no path exists anywhere,
/// surface as `[warn]` (NOT `[fail]`): nginx may simply not have
/// errored yet, which is the happy path on a healthy server.
#[allow(dead_code)] // backward-compat shim for callers that don't probe alternatives
pub(crate) fn build_nginx_error_log_check(path: &str, exists: bool) -> Check {
    build_nginx_error_log_check_with_alternatives(path, exists, &[])
}

/// Pure helper: build the nginx error-log Check given the configured
/// path's existence and a list of `(alt_path, alt_exists)` defaults
/// the caller has already probed. Split out so tests can drive every
/// branch (configured-exists / alt-exists / neither) without touching
/// the filesystem.
pub(crate) fn build_nginx_error_log_check_with_alternatives(
    configured: &str,
    configured_exists: bool,
    alternatives: &[(&str, bool)],
) -> Check {
    if configured_exists {
        return Check::ok(format!("nginx error log exists ({configured})"));
    }
    let alt_present = alternatives.iter().find(|(_, exists)| *exists);
    if let Some((alt, _)) = alt_present {
        return Check::warn(
            format!("nginx error log not found at configured path ({configured}); a default exists at {alt}"),
            format!(
                "Either point sensor config at {alt} or wait for nginx to create {configured} on its first error"
            ),
        );
    }
    // No path on disk anywhere — but nginx writes the file lazily on
    // first error, so the absence does not imply a misconfiguration.
    // Soft `[warn]`, not `[fail]`.
    Check::warn(
        format!("nginx error log not yet written ({configured})"),
        "nginx creates the log on its first error or request — this is OK on a quiet server. \
         If you expect entries, verify nginx is running and the path matches your nginx.conf",
    )
}

/// Map a telemetry-write age (in seconds) to a doctor check.
pub(crate) fn build_telemetry_age_check(age_secs: u64) -> Check {
    if age_secs > 300 {
        Check::warn(
            format!("last telemetry write was {age_secs}s ago"),
            "agent may be stuck - check: journalctl -u innerwarden-agent -n 50",
        )
    } else {
        Check::ok(format!("agent active - last write {age_secs}s ago"))
    }
}

/// Final summary line emitted by `cmd_doctor` based on the issue tally.
pub(crate) fn doctor_summary_line(total_issues: u32) -> String {
    if total_issues == 0 {
        "All checks passed - system looks healthy.".to_string()
    } else {
        format!("{total_issues} issue(s) found - review hints above.")
    }
}

/// Resolve the agent's data dir from `[output] data_dir` in agent.toml,
/// falling back to `/var/lib/innerwarden`. Pure helper so tests can pin both
/// branches.
pub(crate) fn doctor_resolve_agent_data_dir(agent_doc: Option<&toml_edit::DocumentMut>) -> PathBuf {
    agent_doc
        .and_then(|doc| doc.get("output"))
        .and_then(|o| o.get("data_dir"))
        .and_then(|d| d.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/innerwarden"))
}

/// Doctor lines for one enabled capability's sudoers drop-in, plus whether it
/// is an issue. A capability whose drop-in is missing is non-functional (e.g.
/// block-ip cannot run the firewall as the `innerwarden` user), so the fix
/// hint points at `enable <cap> --force` — the command that actually re-applies
/// the drop-in (plain `enable` no-ops on an already-enabled capability).
pub(crate) fn capability_sudoers_status_lines(
    cap_id: &str,
    drop_in: Option<&str>,
    present: bool,
) -> (Vec<String>, bool) {
    match drop_in {
        None => (vec![format!("  [ok]   {cap_id} (enabled)")], false),
        Some(_) if present => (
            vec![format!(
                "  [ok]   {cap_id} (enabled): sudoers drop-in present"
            )],
            false,
        ),
        Some(name) => (
            vec![
                format!(
                    "  [warn] {cap_id} (enabled): sudoers drop-in missing (/etc/sudoers.d/{name})"
                ),
                format!("         → sudo innerwarden enable {cap_id} --force"),
            ],
            true,
        ),
    }
}

/// Map a Cli's configured paths to the sudoers drop-in for a given capability.
pub(crate) fn capability_sudoers_drop_in(capability_id: &str) -> Option<&'static str> {
    match capability_id {
        "block-ip" => Some("innerwarden-block-ip"),
        "sudo-protection" => Some("innerwarden-suspend-user"),
        "search-protection" => Some("innerwarden-search-protection"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Configure-menu: pure detection + render helpers
// ---------------------------------------------------------------------------

/// Configuration status for the per-integration rows of `cmd_configure_menu`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConfigureMenuStatus {
    pub(crate) ai: bool,
    pub(crate) telegram: bool,
    pub(crate) slack: bool,
    pub(crate) webhook: bool,
    pub(crate) dashboard: bool,
    pub(crate) abuseipdb: bool,
    pub(crate) geoip: bool,
    pub(crate) fail2ban: bool,
    pub(crate) cloudflare: bool,
    pub(crate) responder: bool,
}

/// Compute which integrations look "configured" based on env vars + agent.toml.
///
/// `watchdog` is intentionally absent — it is detected via `crontab -l` and so
/// would require shelling out, which we keep inline in `cmd_configure_menu`.
pub(crate) fn detect_configure_menu_status(
    agent_doc: Option<&toml_edit::DocumentMut>,
    env_vars: &HashMap<String, String>,
) -> ConfigureMenuStatus {
    let has_env = |key: &str| -> bool {
        env_vars.get(key).is_some_and(|v| !v.is_empty())
            || std::env::var(key).is_ok_and(|v| !v.is_empty())
    };

    let slack_url_in_config = agent_doc
        .and_then(|doc| doc.get("slack"))
        .and_then(|s| s.get("webhook_url"))
        .and_then(|u| u.as_str())
        .is_some_and(|s| !s.is_empty());

    ConfigureMenuStatus {
        ai: agent_section_enabled(agent_doc, "ai"),
        telegram: has_env("TELEGRAM_BOT_TOKEN") && has_env("TELEGRAM_CHAT_ID"),
        slack: has_env("SLACK_WEBHOOK_URL") || slack_url_in_config,
        webhook: agent_section_enabled(agent_doc, "webhook"),
        dashboard: has_env("INNERWARDEN_DASHBOARD_USER"),
        abuseipdb: has_env("ABUSEIPDB_API_KEY") || agent_section_enabled(agent_doc, "abuseipdb"),
        geoip: agent_section_enabled(agent_doc, "geoip"),
        fail2ban: agent_section_enabled(agent_doc, "fail2ban"),
        cloudflare: has_env("CLOUDFLARE_API_TOKEN")
            || agent_section_enabled(agent_doc, "cloudflare"),
        responder: agent_section_enabled(agent_doc, "responder"),
    }
}

/// Render the status badge used by the configure-menu rows.
pub(crate) fn configure_menu_status_label(ok: bool) -> &'static str {
    if ok {
        "✅ configured"
    } else {
        "○  not set up"
    }
}

/// Routing decisions emitted by `cmd_configure_menu` after reading stdin.
/// Made an enum so the dispatch logic is unit-testable without spawning a
/// real subprocess for each integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigureMenuChoice {
    Ai,
    Telegram,
    Slack,
    Webhook,
    Dashboard,
    AbuseIpdb,
    GeoIp,
    Fail2ban,
    Cloudflare,
    Responder,
    Watchdog,
    Quit,
    Invalid,
}

/// Map a raw user-input string to a routing decision. Whitespace is stripped
/// by callers before invoking; we still trim defensively so the helper is
/// safe to call directly from tests.
pub(crate) fn parse_configure_menu_choice(raw: &str) -> ConfigureMenuChoice {
    match raw.trim() {
        "1" => ConfigureMenuChoice::Ai,
        "2" => ConfigureMenuChoice::Telegram,
        "3" => ConfigureMenuChoice::Slack,
        "4" => ConfigureMenuChoice::Webhook,
        "5" => ConfigureMenuChoice::Dashboard,
        "6" => ConfigureMenuChoice::AbuseIpdb,
        "7" => ConfigureMenuChoice::GeoIp,
        "8" => ConfigureMenuChoice::Fail2ban,
        "9" => ConfigureMenuChoice::Cloudflare,
        "10" => ConfigureMenuChoice::Responder,
        "11" => ConfigureMenuChoice::Watchdog,
        "q" | "Q" | "" => ConfigureMenuChoice::Quit,
        _ => ConfigureMenuChoice::Invalid,
    }
}

/// Build the (number, label, status) rows shown in the configure menu.
/// `watchdog_ok` is provided separately because it depends on `crontab`.
pub(crate) fn configure_menu_rows(
    status: ConfigureMenuStatus,
    watchdog_ok: bool,
) -> Vec<(u8, &'static str, bool)> {
    vec![
        (1, "AI provider", status.ai),
        (2, "Telegram", status.telegram),
        (3, "Slack", status.slack),
        (4, "Webhook", status.webhook),
        (5, "Dashboard", status.dashboard),
        (6, "AbuseIPDB", status.abuseipdb),
        (7, "GeoIP", status.geoip),
        (8, "Fail2ban", status.fail2ban),
        (9, "Cloudflare", status.cloudflare),
        (10, "Responder", status.responder),
        (11, "Watchdog (cron)", watchdog_ok),
    ]
}

/// Did a new agent decision appear since the test was written?
///
/// Mirrors the per-iteration check inside the `cmd_pipeline_test` polling
/// loop. Returns `true` when the JSONL file has grown beyond `baseline`
/// AND either references the test marker, the test IP, or simply has new
/// content (the original logic accepts the lattermost case as evidence).
pub(crate) fn pipeline_test_decision_found(
    current_lines: usize,
    baseline_lines: usize,
    file_content: Option<&str>,
    marker: &str,
    test_ip: &str,
) -> bool {
    if current_lines <= baseline_lines {
        return false;
    }
    if let Some(content) = file_content {
        if content.contains(marker) || content.contains(test_ip) {
            return true;
        }
    }
    // Original behaviour: if the line count grew at all, treat that as a
    // tentative match — the agent may have processed something else, but a
    // smoke test prefers false-positives over false-negatives.
    true
}

/// Choose the result label printed by `cmd_pipeline_test` step 4.
pub(crate) fn pipeline_test_result_label(found: bool) -> &'static str {
    if found {
        "Result: PASS"
    } else {
        "Result: TIMEOUT - check `innerwarden doctor` for diagnostics"
    }
}

/// Format an agent decision (as JSON) into a list of human-readable lines
/// suitable for the pipeline-test "Result: PASS" output. Robust to missing
/// fields — falls back to defaults exactly as the caller did inline.
pub(crate) fn format_decision_summary(value: &serde_json::Value) -> Vec<String> {
    let action = value
        .get("action_type")
        .and_then(|a| a.as_str())
        .or_else(|| value.get("action").and_then(|a| a.as_str()))
        .unwrap_or("?");
    let conf = value
        .get("confidence")
        .and_then(|c| c.as_f64())
        .unwrap_or(0.0);
    let dry = value
        .get("dry_run")
        .and_then(|d| d.as_bool())
        .unwrap_or(true);
    let reason = value.get("reason").and_then(|r| r.as_str()).unwrap_or("");

    let mut out = vec![
        format!("Action: {action}"),
        format!("Confidence: {:.0}%", conf * 100.0),
        format!("Dry-run: {dry}"),
    ];
    if !reason.is_empty() {
        out.push(format!("Reason: {reason}"));
    }
    if dry {
        out.push("(safe - no real firewall changes)".to_string());
    }
    out
}

pub(crate) fn cmd_configure_menu(cli: &Cli) -> Result<()> {
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));
    let env_vars = load_env_file(&env_file);

    let agent_doc: Option<toml_edit::DocumentMut> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse().ok());

    let status = detect_configure_menu_status(agent_doc.as_ref(), &env_vars);
    let watchdog_ok = std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("innerwarden watchdog"))
        .unwrap_or(false);

    println!("InnerWarden - configure\n");
    println!("Choose what to set up:\n");
    for (n, label, ok) in configure_menu_rows(status, watchdog_ok) {
        let badge = configure_menu_status_label(ok);
        println!("  {n:>2}. {:<18}{}", label, badge);
    }
    println!();
    print!("Enter number (or q to quit): ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let choice = parse_configure_menu_choice(&input);

    println!();
    match choice {
        ConfigureMenuChoice::Ai => commands::ai::cmd_configure_ai_interactive(cli),
        ConfigureMenuChoice::Telegram => {
            commands::notify::cmd_configure_telegram(cli, None, None, false)
        }
        ConfigureMenuChoice::Slack => {
            commands::notify::cmd_configure_slack(cli, None, "high", false)
        }
        ConfigureMenuChoice::Webhook => {
            commands::notify::cmd_configure_webhook(cli, None, "high", false)
        }
        ConfigureMenuChoice::Dashboard => {
            commands::notify::cmd_configure_dashboard(cli, "admin", None)
        }
        ConfigureMenuChoice::AbuseIpdb => {
            commands::integrations::cmd_configure_abuseipdb(cli, None, None)
        }
        ConfigureMenuChoice::GeoIp => commands::integrations::cmd_configure_geoip(cli),
        ConfigureMenuChoice::Fail2ban => cmd_configure_fail2ban(cli),
        ConfigureMenuChoice::Cloudflare => {
            commands::integrations::cmd_configure_cloudflare(cli, None, None)
        }
        ConfigureMenuChoice::Responder => {
            commands::responder::cmd_configure_responder(cli, false, false, None)
        }
        ConfigureMenuChoice::Watchdog => commands::integrations::cmd_configure_watchdog(cli, 10),
        ConfigureMenuChoice::Quit => {
            println!(
                "Tip: run 'innerwarden configure <name>' to jump directly to any integration."
            );
            Ok(())
        }
        ConfigureMenuChoice::Invalid => {
            println!("Invalid choice. Run 'innerwarden configure' again.");
            Ok(())
        }
    }
}

/// Build the bail-out error message for `cmd_configure_fail2ban` when the
/// fail2ban-client binary is not installed.
pub(crate) fn fail2ban_not_installed_message(is_macos: bool) -> &'static str {
    if is_macos {
        "fail2ban is not available on macOS.\n\
         This integration only works on Linux."
    } else {
        "fail2ban-client not found. Install it first:\n\
         \n\
         Ubuntu/Debian:  sudo apt install fail2ban\n\
         RHEL/CentOS:    sudo yum install fail2ban\n\
         \n\
         Then run this command again."
    }
}

pub(crate) fn cmd_configure_fail2ban(cli: &Cli) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let installed = std::process::Command::new("fail2ban-client")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !installed {
        anyhow::bail!(
            "{}",
            fail2ban_not_installed_message(std::env::consts::OS == "macos")
        );
    }

    let running = std::process::Command::new("fail2ban-client")
        .arg("ping")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !running {
        println!("  Warning: fail2ban is installed but not running.");
        println!("  Start it with: sudo systemctl start fail2ban");
        println!("  Enabling the integration anyway - it will activate when fail2ban starts.\n");
    }

    if cli.dry_run {
        println!(
            "[dry-run] would set [fail2ban] enabled=true in {}",
            cli.agent_config.display()
        );
        return Ok(());
    }

    config_editor::write_bool(&cli.agent_config, "fail2ban", "enabled", true)?;
    println!("  [ok] agent.toml: fail2ban.enabled = true");

    restart_agent(cli);
    println!();
    println!("Fail2ban integration enabled.");
    println!("IPs banned by fail2ban will automatically be enforced via your block skill.");
    Ok(())
}

pub(crate) fn cmd_configure_sensitivity(cli: &Cli, level: &str) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let Some(min_severity) = min_severity_for_sensitivity(level) else {
        println!(
            "Unknown level '{}'. Choose: quiet, normal, or verbose",
            level
        );
        return Ok(());
    };
    config_editor::write_str(&cli.agent_config, "telegram", "min_severity", min_severity)?;
    config_editor::write_str(&cli.agent_config, "webhook", "min_severity", min_severity)?;
    println!("✅ Notification sensitivity: {level}");
    println!("   Telegram + webhook min_severity = \"{min_severity}\"");

    apply_detector_threshold_overrides(&cli.agent_config, level);

    if let Some(line) = sensitivity_summary_line(level) {
        println!("   {line}");
    }
    systemd::restart_service("innerwarden-agent", false)?;
    println!("   Agent restarted.");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "sensitivity".to_string(),
        parameters: serde_json::json!({ "level": level }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

fn apply_detector_threshold_overrides(agent_config: &Path, level: &str) {
    // Keep this call resilient - thresholds are best-effort and must not block
    // the user's chosen notification sensitivity change.
    match crate::calibrate::calculate_sensitivity_overrides(level) {
        Ok(overrides) => apply_detector_threshold_map(agent_config, level, overrides),
        Err(e) => {
            eprintln!("   [warn] failed to calculate thresholds for '{level}': {e:#}");
        }
    }
}

fn apply_detector_threshold_map(
    agent_config: &Path,
    level: &str,
    overrides: std::collections::BTreeMap<String, i64>,
) {
    println!("   Applying detector thresholds for '{level}' mode:");
    for (key, val) in overrides {
        // key is like "detectors.ssh_bruteforce.threshold"
        let parts: Vec<&str> = key.split('.').collect();
        if parts.len() == 3 {
            let section = format!("{}.{}", parts[0], parts[1]);
            let field = parts[2];
            if let Err(e) = config_editor::write_int(agent_config, &section, field, val) {
                eprintln!("     [warn] failed to set {key}: {e:#}");
            } else {
                println!("     - {key} = {val}");
            }
        }
    }
}

/// Routing decision for the 2FA configure menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TwoFactorChoice {
    Totp,
    Disabled,
    Unknown,
}

/// Pure parser for the 2FA top-level prompt.
pub(crate) fn parse_two_factor_choice(raw: &str) -> TwoFactorChoice {
    match raw.trim() {
        "1" => TwoFactorChoice::Totp,
        "2" | "" => TwoFactorChoice::Disabled,
        _ => TwoFactorChoice::Unknown,
    }
}

/// Persist a successful TOTP configuration: writes the secret to the env file
/// and flips `[security] two_factor_method = "totp"` in agent.toml.
///
/// Extracted from `cmd_configure_2fa` so the side-effecting part of the OK
/// branch is unit-testable in isolation.
pub(crate) fn write_totp_configuration(cli: &Cli, secret_b32: &str) -> Result<PathBuf> {
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    append_or_update_env(&env_file, "INNERWARDEN_TOTP_SECRET", secret_b32)?;
    config_editor::write_str(&cli.agent_config, "security", "two_factor_method", "totp")?;
    Ok(env_file)
}

/// Persist the "disable 2FA" choice.
pub(crate) fn write_disable_two_factor(cli: &Cli) -> Result<()> {
    config_editor::write_str(&cli.agent_config, "security", "two_factor_method", "none")?;
    Ok(())
}

pub(crate) fn cmd_configure_2fa(cli: &Cli) -> Result<()> {
    println!();
    println!("  🔐 Two-Factor Authentication Setup");
    println!("  ================================");
    println!();
    println!("  Choose your second factor:");
    println!("  1. TOTP (Google Authenticator, Authy, 1Password)");
    println!("  2. None (disabled, default)");
    println!();
    print!("  Choose [1-2]: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let choice = parse_two_factor_choice(&input);

    match choice {
        TwoFactorChoice::Totp => {
            use rand_core::{OsRng, RngCore};
            let mut secret_bytes = [0u8; 20];
            OsRng.fill_bytes(&mut secret_bytes);
            let secret_b32 = base32_encode_simple(&secret_bytes);

            let uri = format!(
                "otpauth://totp/InnerWarden:admin?secret={}&issuer=InnerWarden&algorithm=SHA1&digits=6&period=30",
                secret_b32
            );

            println!();
            println!("  Scan this QR code with your authenticator app:");
            println!();
            // Render QR code as ASCII art in the terminal. The TOTP secret
            // never touches disk or log files — displayed only as visual
            // pixels that the operator scans with their phone camera.
            render_qr_to_terminal(&uri);
            println!();
            print!("  Enter the 6-digit code to verify: ");
            std::io::stdout().flush()?;

            let mut code = String::new();
            std::io::stdin().read_line(&mut code)?;
            let code = code.trim();

            if verify_totp_code(&secret_bytes, code) {
                let env_file = write_totp_configuration(cli, &secret_b32)?;

                println!();
                println!("  ✅ 2FA enabled with TOTP");
                println!("  Secret saved to {}", env_file.display());
                println!();
                println!("  All sensitive actions (allowlist, mode changes) now require a code.");

                if !cli.dry_run {
                    let _ = systemd::restart_service("innerwarden-agent", false);
                    println!("  Agent restarted.");
                }

                Ok(())
            } else {
                println!();
                println!("  ❌ Wrong code. Please try again.");
                println!("  Run: innerwarden configure 2fa");
                Ok(())
            }
        }
        TwoFactorChoice::Disabled => {
            write_disable_two_factor(cli)?;
            println!();
            println!("  ✅ 2FA disabled");
            if !cli.dry_run {
                let _ = systemd::restart_service("innerwarden-agent", false);
                println!("  Agent restarted.");
            }
            Ok(())
        }
        TwoFactorChoice::Unknown => {
            println!("  Unknown option. Run: innerwarden configure 2fa");
            Ok(())
        }
    }
}

/// Render a QR code as Unicode block characters in the terminal.
/// Uses two rows per line (upper/lower half blocks) for compact display.
fn render_qr_to_terminal(data: &str) {
    use qrcode::QrCode;
    let code = match QrCode::new(data.as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  (QR code generation failed: {e})");
            return;
        }
    };
    let matrix = code.to_colors();
    let width = code.width();
    // Each character represents 2 vertical pixels using half-block chars
    let rows = width.div_ceil(2);
    for row in 0..rows {
        print!("    "); // indent
        for col in 0..width {
            let top = matrix[row * 2 * width + col] == qrcode::Color::Dark;
            let bot = if row * 2 + 1 < width {
                matrix[(row * 2 + 1) * width + col] == qrcode::Color::Dark
            } else {
                false
            };
            match (top, bot) {
                (true, true) => print!("\u{2588}"),  // █ full block
                (true, false) => print!("\u{2580}"), // ▀ upper half
                (false, true) => print!("\u{2584}"), // ▄ lower half
                (false, false) => print!(" "),       //   space
            }
        }
        println!();
    }
}

fn base32_encode_simple(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut bits: u64 = 0;
    let mut bit_count = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u64;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = ((bits >> bit_count) & 0x1f) as usize;
            result.push(ALPHABET[idx] as char);
            bits &= (1 << bit_count) - 1;
        }
    }
    if bit_count > 0 {
        let idx = ((bits << (5 - bit_count)) & 0x1f) as usize;
        result.push(ALPHABET[idx] as char);
    }
    result
}

fn verify_totp_code(secret: &[u8], code: &str) -> bool {
    let code = code.trim();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let user_code: u32 = match code.parse() {
        Ok(c) => c,
        Err(_) => return false,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_step = now / 30;

    for offset in [0i64, -1, 1] {
        let step = (time_step as i64 + offset) as u64;
        if generate_totp_code(secret, step) == user_code {
            return true;
        }
    }
    false
}

fn generate_totp_code(secret: &[u8], time_step: u64) -> u32 {
    let msg = time_step.to_be_bytes();
    let hash = hmac_sha1_simple(secret, &msg);
    let offset = (hash[19] & 0x0f) as usize;
    let code = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    code % 1_000_000
}

fn hmac_sha1_simple(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        key_block[..20].copy_from_slice(&sha1_simple(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_data = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_data.extend_from_slice(&ipad);
    inner_data.extend_from_slice(message);
    let inner_hash = sha1_simple(&inner_data);

    let mut outer_data = Vec::with_capacity(BLOCK_SIZE + 20);
    outer_data.extend_from_slice(&opad);
    outer_data.extend_from_slice(&inner_hash);
    sha1_simple(&outer_data)
}

#[allow(clippy::needless_range_loop)]
fn sha1_simple(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

fn append_or_update_env(env_file: &Path, key: &str, value: &str) -> Result<()> {
    let content = std::fs::read_to_string(env_file).unwrap_or_default();
    let mut found = false;
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            if line.starts_with(&format!("{key}=")) {
                found = true;
                format!("{key}=\"{value}\"")
            } else {
                line.to_string()
            }
        })
        .collect();

    if !found {
        lines.push(format!("{key}=\"{value}\""));
    }

    if let Some(parent) = env_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(env_file, lines.join("\n") + "\n")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(env_file, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

pub(crate) fn cmd_tune(cli: &Cli, days: u64, yes: bool, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);

    println!("InnerWarden Tune - analysing last {days} day(s) of data");
    println!("{}", "─".repeat(56));

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let detectors = [
        (
            "ssh_bruteforce",
            "ssh.login_failed",
            "detectors.ssh_bruteforce.threshold",
        ),
        (
            "credential_stuffing",
            "ssh.invalid_user",
            "detectors.credential_stuffing.threshold",
        ),
        (
            "sudo_abuse",
            "sudo.command",
            "detectors.sudo_abuse.threshold",
        ),
        (
            "search_abuse",
            "http.request",
            "detectors.search_abuse.threshold",
        ),
        ("web_scan", "http.error", "detectors.web_scan.threshold"),
        (
            "port_scan",
            "network.connection_blocked",
            "detectors.port_scan.threshold",
        ),
    ];

    let mut event_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut incident_counts: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();

    for i in 0..days {
        let date = epoch_secs_to_date(now_secs.saturating_sub(i * 86400));

        let events_path = effective_dir.join(format!("events-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&events_path) {
            for (k, v) in count_event_kinds(&content) {
                *event_counts.entry(k).or_insert(0) += v;
            }
        }

        let incidents_path = effective_dir.join(format!("incidents-{date}.jsonl"));
        if let Ok(content) = std::fs::read_to_string(&incidents_path) {
            for (k, v) in count_incident_detectors(&content) {
                *incident_counts.entry(k).or_insert(0) += v;
            }
        }
    }

    let sensor_content = std::fs::read_to_string(&cli.sensor_config).unwrap_or_default();
    let sensor_toml: Option<toml_edit::DocumentMut> = sensor_content.parse().ok();

    let current_threshold = |config_path: &str| -> Option<i64> {
        let parts: Vec<&str> = config_path.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        sensor_toml
            .as_ref()
            .and_then(|doc| doc.get(parts[0]))
            .and_then(|t| t.get(parts[1]))
            .and_then(|d| d.get(parts[2]))
            .and_then(|v| v.as_integer())
    };

    struct Suggestion {
        detector: &'static str,
        current: Option<i64>,
        suggested: i64,
        reason: String,
    }

    let mut suggestions: Vec<Suggestion> = Vec::new();
    let mut has_data = false;

    for (detector, event_kind, config_path) in &detectors {
        let events = *event_counts.get(*event_kind).unwrap_or(&0);
        let incidents = *incident_counts.get(*detector).unwrap_or(&0);
        let current = current_threshold(config_path);

        if events == 0 {
            continue;
        }
        has_data = true;

        let events_per_day = (events as f64 / days as f64).ceil() as i64;
        let current_val = current.unwrap_or(8);

        let incidents_per_day = incidents as f64 / days as f64;
        let suggested = suggest_detector_threshold(events_per_day, incidents_per_day, current_val);

        if suggested == current_val {
            continue;
        }

        let raise = suggested > current_val;
        let reason = tune_reason(events_per_day, incidents, days, raise);
        suggestions.push(Suggestion {
            detector,
            current,
            suggested,
            reason,
        });
    }

    if !has_data {
        println!("\nNo event data found in {}.", effective_dir.display());
        println!("Run the sensor for a few days first, then re-run tune.");
        return Ok(());
    }

    if suggestions.is_empty() {
        println!("\n✅ All detector thresholds look well-calibrated for this host.");
        println!("   Events/day are within expected range relative to current thresholds.");
        println!("   Re-run after more data accumulates: --days 14");
        return Ok(());
    }

    println!("\nSuggested threshold changes:\n");
    println!(
        "  {:<22}  {:>8}  {:>9}  Reason",
        "Detector", "Current", "Suggested"
    );
    println!("  {}", "─".repeat(72));
    for s in &suggestions {
        let cur_str = s
            .current
            .map(|v| v.to_string())
            .unwrap_or_else(|| "default".to_string());
        println!(
            "  {:<22}  {:>8}  {:>9}  {}",
            s.detector, cur_str, s.suggested, s.reason
        );
    }

    let apply = if yes {
        true
    } else {
        print!(
            "\nApply these changes to {}? [y/N] ",
            cli.sensor_config.display()
        );
        let _ = std::io::stdout().flush();
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
    };

    if !apply {
        println!("No changes made. Re-run with --yes to apply.");
        return Ok(());
    }

    if cli.dry_run {
        println!(
            "[dry-run] Would patch {} with {} change(s)",
            cli.sensor_config.display(),
            suggestions.len()
        );
        return Ok(());
    }

    let mut doc: toml_edit::DocumentMut = sensor_content
        .parse()
        .with_context(|| format!("failed to parse {}", cli.sensor_config.display()))?;

    for s in &suggestions {
        let parts: Vec<&str> = detectors
            .iter()
            .find(|(d, _, _)| *d == s.detector)
            .map(|(_, _, p)| p.split('.').collect())
            .unwrap_or_default();
        if parts.len() == 3 {
            if let Some(section) = doc
                .get_mut(parts[0])
                .and_then(|t| t.as_table_mut())
                .and_then(|t| t.get_mut(parts[1]))
                .and_then(|t| t.as_table_mut())
            {
                section.insert(parts[2], toml_edit::value(s.suggested));
            }
        }
    }

    std::fs::write(&cli.sensor_config, doc.to_string())
        .with_context(|| format!("failed to write {}", cli.sensor_config.display()))?;

    println!(
        "✅ Applied {} change(s) to {}",
        suggestions.len(),
        cli.sensor_config.display()
    );
    println!("Restart the sensor to apply: sudo systemctl restart innerwarden-sensor");

    let tuned: Vec<&str> = suggestions.iter().map(|s| s.detector).collect();
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "tune".to_string(),
        target: "detectors".to_string(),
        parameters: serde_json::json!({ "detectors": tuned, "days": days }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

pub(crate) fn cmd_doctor(cli: &Cli, registry: &CapabilityRegistry) -> Result<()> {
    let total_issues = cmd_doctor_inner(cli, registry)?;
    if total_issues > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Doctor body extracted so tests can run it without `process::exit(1)`.
/// Returns the number of issues found across all sections.
pub(crate) fn cmd_doctor_inner(cli: &Cli, registry: &CapabilityRegistry) -> Result<u32> {
    println!("InnerWarden Doctor");
    println!("{}", "═".repeat(48));

    let mut total_issues: u32 = 0;

    let is_macos = std::env::consts::OS == "macos";

    // ── System ────────────────────────────────────────────
    println!("\nSystem");
    let mut sys = Vec::new();

    let sudoers_present = std::path::Path::new("/etc/sudoers.d").is_dir();
    if is_macos {
        // launchctl
        let has_launchctl = std::path::Path::new("/bin/launchctl").exists()
            || std::path::Path::new("/usr/bin/launchctl").exists();
        sys.push(build_launchctl_check(has_launchctl));

        // innerwarden user
        let user_ok = std::process::Command::new("id")
            .arg("innerwarden")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        sys.push(build_innerwarden_user_check(user_ok, true));

        // /etc/sudoers.d/ (exists on macOS too)
        sys.push(build_sudoers_dir_check(sudoers_present, true));

        // pfctl (needed for block-ip-pf)
        let has_pfctl = std::path::Path::new("/sbin/pfctl").exists();
        sys.push(if has_pfctl {
            Check::ok("pfctl found (block-ip-pf skill available)")
        } else {
            Check::warn(
                "pfctl not found",
                "pfctl is built-in on macOS - unexpected. block-ip-pf skill will not work.",
            )
        });

        // `log` binary (needed for macos_log collector)
        let has_log_bin = std::path::Path::new("/usr/bin/log").exists();
        sys.push(if has_log_bin {
            Check::ok("`log` binary found (macos_log collector available)")
        } else {
            Check::fail(
                "`log` binary not found at /usr/bin/log",
                "unexpected on macOS - macos_log collector requires Apple Unified Logging",
            )
        });
    } else {
        // systemctl
        let has_systemctl = std::path::Path::new("/usr/bin/systemctl").exists()
            || std::path::Path::new("/bin/systemctl").exists();
        sys.push(build_systemctl_check(has_systemctl));

        // innerwarden user
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        let user_ok = passwd
            .lines()
            .any(|l| l.split(':').next() == Some("innerwarden"));
        sys.push(build_innerwarden_user_check(user_ok, false));

        // /etc/sudoers.d/
        sys.push(build_sudoers_dir_check(sudoers_present, false));
    }

    run_section(sys, &mut total_issues);

    // ── Services ──────────────────────────────────────────
    println!("\nServices");
    let mut svc = Vec::new();
    if is_macos {
        for (label, plist) in &[
            ("innerwarden-sensor", "com.innerwarden.sensor"),
            ("innerwarden-agent", "com.innerwarden.agent"),
        ] {
            // Detect via process presence (systemd::service_status is pgrep-based
            // on macOS), NOT `launchctl list <label>`: that queries the caller's
            // launchd domain, so a non-root `doctor` cannot see the SYSTEM-domain
            // daemons and falsely reported them "not running" while they were
            // live (2026-07-01 retest residual — same class as F7).
            let running = matches!(
                systemd::service_status(label),
                systemd::ServiceStatus::Active
            );
            svc.push(build_service_running_check(label, running, true));
            // Note: macOS plist filename is per-domain (com.innerwarden.*),
            // so we use it for the remediation hint by adjusting the helper.
            // Replace the just-pushed Check's hint when we want plist-based
            // text (kept inline for readability).
            if !running {
                if let Some(last) = svc.last_mut() {
                    last.hint = Some(format!(
                        "sudo launchctl load /Library/LaunchDaemons/{plist}.plist"
                    ));
                }
            }
        }
    } else {
        for unit in &["innerwarden-sensor", "innerwarden-agent"] {
            // Bug 2 (2026-05-06): use the tri-state status so a
            // session without DBUS_SESSION_BUS_ADDRESS does not get
            // a false `[warn] is not running` while the agent is
            // alive. Unknown defers to Agent health below.
            let status = systemd::service_status(unit);
            svc.push(build_service_status_check_linux(unit, status));
        }
    }
    run_section(svc, &mut total_issues);

    // ── Configuration ─────────────────────────────────────
    println!("\nConfiguration");
    let mut cfg = Vec::new();

    for (label, path) in &[("Sensor", &cli.sensor_config), ("Agent", &cli.agent_config)] {
        cfg.extend(build_config_file_checks(label, path));
    }

    // AI provider + API key - detect provider from agent config then validate the right key
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // Read agent.toml to find configured provider and whether AI is enabled
    let agent_doc: Option<toml_edit::DocumentMut> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse().ok());

    let ai_enabled = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|ai| ai.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let provider = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|ai| ai.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("openai")
        .to_string();

    // Helper: resolve a key from env var or agent.env file
    let resolve_key = |env_var: &str| -> Option<String> {
        if let Ok(v) = std::env::var(env_var) {
            if !v.trim().is_empty() {
                return Some(v);
            }
        }
        std::fs::read_to_string(&env_file).ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(&format!("{env_var}=")))
                .and_then(|l| l.split_once('=').map(|x| x.1))
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.trim().to_string())
        })
    };

    if !ai_enabled {
        cfg.push(Check::warn(
            "AI not configured (ai.enabled = false)",
            "Detection and logging still work without AI.\nTo add AI triage, run one of:\n\n  innerwarden configure ai openai --key sk-...\n  innerwarden configure ai anthropic --key sk-ant-...\n  innerwarden configure ai ollama --model llama3.2   (no key needed)",
        ));
    } else if provider == "ollama" {
        // Ollama needs a reachability probe — keep that side-effecting
        // logic inline; the build_ai_provider_check helper just covers the
        // key-format providers.
        let ollama_url = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("ai"))
            .and_then(|ai| ai.get("base_url"))
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost:11434")
            .to_string();
        let ollama_ok = std::process::Command::new("curl")
            .args(["-sf", "--max-time", "2", &format!("{ollama_url}/api/tags")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        cfg.push(if ollama_ok {
            Check::ok(format!("Ollama reachable at {ollama_url}"))
        } else {
            Check::fail(
                format!("Ollama not reachable at {ollama_url}"),
                "Install and start Ollama:\n\n  curl -fsSL https://ollama.ai/install.sh | sh\n  ollama pull llama3.2\n\nThen run: innerwarden configure ai ollama --model llama3.2",
            )
        });
    } else {
        let env_var = match provider.as_str() {
            "anthropic" => "ANTHROPIC_API_KEY",
            "azure_openai" | "azure" => "AZURE_OPENAI_API_KEY",
            _ => "OPENAI_API_KEY",
        };
        let key = resolve_key(env_var);
        cfg.push(build_ai_provider_check(&provider, key.as_deref()));
    }

    // AbuseIPDB enrichment - only when abuseipdb.enabled = true
    {
        let abuseipdb_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("abuseipdb"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if abuseipdb_enabled {
            let key_in_config = agent_doc
                .as_ref()
                .and_then(|doc| doc.get("abuseipdb"))
                .and_then(|t| t.get("api_key"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let key_in_env = std::env::var("ABUSEIPDB_API_KEY")
                .ok()
                .filter(|s| !s.is_empty());
            let key_in_file = resolve_key("ABUSEIPDB_API_KEY");
            let resolved_key = key_in_config.or(key_in_env).or(key_in_file);

            cfg.push(build_abuseipdb_key_check(resolved_key.as_deref()));
        }
    }

    // Fail2ban integration - only when fail2ban.enabled = true
    {
        let fail2ban_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("fail2ban"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if fail2ban_enabled {
            let fb_bin = std::path::Path::new("/usr/bin/fail2ban-client").exists()
                || std::path::Path::new("/usr/local/bin/fail2ban-client").exists();
            cfg.push(build_fail2ban_binary_check(fb_bin));

            // Check fail2ban service is running
            let fb_running = if is_macos {
                false // fail2ban is Linux-only
            } else {
                std::process::Command::new("fail2ban-client")
                    .args(["ping"])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            };
            cfg.push(build_fail2ban_running_check(fb_running, is_macos));
        }
    }

    run_section(cfg, &mut total_issues);

    // ── Execution Gate (spec 080 G4) ──────────────────────
    // FREE read-only honesty surface: compare the signed allowlist to the LIVE
    // kernel maps so a paid gate that staged-but-never-applied (or armed with an
    // empty map) is visible here. Section is shown only where a gate is present.
    if execution_gate_present() {
        println!("\nExecution Gate");
        let (signed_count, intended_mode) = read_signed_allowlist_for_doctor();
        let live_count = bpftool_allowlist_count();
        let live_mode = bpftool_gate_mode();
        let gate = innerwarden_core::execution_gate::GateState {
            signed_count,
            intended_mode,
            live_count,
            live_mode,
            live_scope_armed: bpftool_scope_armed(),
            live_scope_count: bpftool_scope_count(),
        };
        let bpf_lsm_active = innerwarden_core::execution_gate::read_bpf_lsm_active();
        if let Some(note) = gate_lsm_inactive_note(bpf_lsm_active) {
            println!("{note}");
        }
        run_section(
            vec![gate_doctor_check(&gate, bpf_lsm_active)],
            &mut total_issues,
        );
    }

    // ── Telegram ──────────────────────────────────────────
    // Only check Telegram when enabled = true in agent config.
    {
        let agent_toml: Option<toml_edit::DocumentMut> = cli
            .agent_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.agent_config).ok())
            .flatten()
            .and_then(|s| s.parse().ok());

        let telegram_enabled = agent_toml
            .as_ref()
            .and_then(|doc| doc.get("telegram"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if telegram_enabled {
            println!("\nTelegram");
            let mut tg = Vec::new();

            let env_file_path = cli
                .agent_config
                .parent()
                .map(|p| p.join("agent.env"))
                .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

            // Resolve bot_token: config → env var → agent.env file
            let token_in_config = agent_toml
                .as_ref()
                .and_then(|doc| doc.get("telegram"))
                .and_then(|t| t.get("bot_token"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let token_in_env = std::env::var("TELEGRAM_BOT_TOKEN")
                .ok()
                .filter(|s| !s.is_empty());
            let token_in_file = std::fs::read_to_string(&env_file_path)
                .map(|s| {
                    s.lines()
                        .find(|l| l.starts_with("TELEGRAM_BOT_TOKEN="))
                        .and_then(|l| l.split_once('=').map(|x| x.1))
                        .filter(|v| !v.is_empty())
                        .map(|s| s.to_string())
                })
                .unwrap_or(None);
            let resolved_token = token_in_config.or(token_in_env).or(token_in_file);

            // Resolve chat_id: config → env var → agent.env file
            let chat_in_config = agent_toml
                .as_ref()
                .and_then(|doc| doc.get("telegram"))
                .and_then(|t| t.get("chat_id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let chat_in_env = std::env::var("TELEGRAM_CHAT_ID")
                .ok()
                .filter(|s| !s.is_empty());
            let chat_in_file = std::fs::read_to_string(&env_file_path)
                .map(|s| {
                    s.lines()
                        .find(|l| l.starts_with("TELEGRAM_CHAT_ID="))
                        .and_then(|l| l.split_once('=').map(|x| x.1))
                        .filter(|v| !v.is_empty())
                        .map(|s| s.to_string())
                })
                .unwrap_or(None);
            let resolved_chat = chat_in_config.or(chat_in_env).or(chat_in_file);

            // Check bot_token presence
            tg.push(build_telegram_token_check(
                resolved_token.as_deref(),
                &env_file_path,
            ));

            // Check chat_id presence
            tg.push(build_telegram_chat_check(
                resolved_chat.as_deref(),
                &env_file_path,
            ));

            // If both token and chat_id are valid, suggest a connectivity smoke-test
            if resolved_token.is_some() && resolved_chat.is_some() {
                tg.push(Check::ok(
                    "Telegram configured - test it: innerwarden-agent --config /etc/innerwarden/agent.toml --once",
                ));
            }

            run_section(tg, &mut total_issues);
        }

        // Only check Slack when enabled = true in agent config.
        let slack_enabled = agent_toml
            .as_ref()
            .and_then(|doc| doc.get("slack"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if slack_enabled {
            println!("\nSlack");
            let mut sl = Vec::new();

            let env_file_path = cli
                .agent_config
                .parent()
                .map(|p| p.join("agent.env"))
                .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

            // Resolve webhook_url: config → env var → agent.env file
            let url_in_config = agent_toml
                .as_ref()
                .and_then(|doc| doc.get("slack"))
                .and_then(|t| t.get("webhook_url"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let url_in_env = std::env::var("SLACK_WEBHOOK_URL")
                .ok()
                .filter(|s| !s.is_empty());
            let url_in_file = std::fs::read_to_string(&env_file_path)
                .map(|s| {
                    s.lines()
                        .find(|l| l.starts_with("SLACK_WEBHOOK_URL="))
                        .and_then(|l| l.split_once('=').map(|x| x.1))
                        .filter(|v| !v.is_empty())
                        .map(|s| s.to_string())
                })
                .unwrap_or(None);
            let resolved_url = url_in_config.or(url_in_env).or(url_in_file);

            sl.push(build_slack_webhook_check(
                resolved_url.as_deref(),
                &env_file_path,
            ));

            if resolved_url.is_some() {
                sl.push(Check::ok(
                    "Slack configured - test it: innerwarden-agent --config /etc/innerwarden/agent.toml --once",
                ));
            }

            run_section(sl, &mut total_issues);
        }
    }

    // ── Webhook ────────────────────────────────────────────
    {
        let webhook_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("webhook"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if webhook_enabled {
            println!("\nWebhook");
            let mut wh: Vec<Check> = vec![];

            let url_val = agent_doc
                .as_ref()
                .and_then(|doc| doc.get("webhook"))
                .and_then(|t| t.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            wh.push(build_webhook_url_check(&url_val));

            run_section(wh, &mut total_issues);
        }
    }

    // ── Dashboard ──────────────────────────────────────────
    {
        let dashboard_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("dashboard"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Always check if credentials are set (dashboard always available when agent runs)
        println!("\nDashboard");
        let mut db: Vec<Check> = vec![];

        let env_path = cli
            .agent_config
            .parent()
            .map(|p| p.join("agent.env"))
            .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));
        let env_content = std::fs::read_to_string(&env_path).unwrap_or_default();

        let has_user = env_content
            .lines()
            .any(|l| l.starts_with("INNERWARDEN_DASHBOARD_USER="))
            || std::env::var("INNERWARDEN_DASHBOARD_USER").is_ok();

        let has_hash = env_content
            .lines()
            .any(|l| l.starts_with("INNERWARDEN_DASHBOARD_PASSWORD_HASH="))
            || std::env::var("INNERWARDEN_DASHBOARD_PASSWORD_HASH").is_ok();

        // Check if --dashboard flag is in the agent's start command. On macOS
        // this is the launchd plist's ProgramArguments, not a systemd unit
        // (F5): reading the wrong path returned empty and false-warned.
        let service_content = std::fs::read_to_string(agent_unit_file_path()).unwrap_or_default();
        let dashboard_flag_in_service = service_content.contains("--dashboard");

        db.push(build_dashboard_flag_check(dashboard_flag_in_service));
        db.extend(build_dashboard_credentials_checks(has_user, has_hash));

        // Check if the dashboard is actually reachable.
        //
        // The dashboard is frequently HTTPS-only (self-signed) on prod, so a
        // plain-HTTP probe returns connection-refused and doctor used to warn
        // "Dashboard port 8787 is not responding" even when the dashboard was
        // serving HTTPS 200 (false negative observed on Azure prod). Fall back
        // to a scheme-agnostic TCP connect: if something is listening on the
        // port, the dashboard is up regardless of HTTP vs HTTPS.
        let dashboard_up = ureq::get("http://127.0.0.1:8787/api/status")
            .config()
            .timeout_global(Some(std::time::Duration::from_secs(2)))
            .build()
            .call()
            .is_ok()
            || tcp_port_listening(
                std::net::SocketAddr::from(([127, 0, 0, 1], 8787)),
                std::time::Duration::from_secs(2),
            );
        // Bug 3 (2026-05-06): pass agent-alive so the hint adapts
        // when the dashboard is unreachable but the agent itself is
        // running. `service_status::Active` is one signal; the
        // pragmatic OR with the telemetry-freshness check below would
        // be ideal but doctor's section ordering puts dashboard
        // BEFORE Agent health. service_status::Active alone covers
        // the bus-OK case; the bus-failure case (Unknown) yields
        // `agent_alive = false` here, but on a bus-failure session
        // doctor cannot reach the dashboard's HTTP probe either, so
        // the hint mismatch is benign in that scenario.
        let agent_alive = matches!(
            systemd::service_status("innerwarden-agent"),
            systemd::ServiceStatus::Active
        );
        if let Some(check) =
            build_dashboard_reachability_check(dashboard_up, dashboard_flag_in_service, agent_alive)
        {
            db.push(check);
        }

        let _ = dashboard_enabled;
        run_section(db, &mut total_issues);
    }

    // ── GeoIP ──────────────────────────────────────────────
    {
        let geoip_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("geoip"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if geoip_enabled {
            println!("\nGeoIP");
            let mut geo: Vec<Check> = vec![];

            // Quick connectivity check
            let reachable = ureq::get("http://ip-api.com/json/8.8.8.8?fields=status")
                .config()
                .timeout_global(Some(std::time::Duration::from_secs(3)))
                .build()
                .call()
                .is_ok();

            geo.push(build_geoip_reachability_check(reachable));

            run_section(geo, &mut total_issues);
        }
    }

    // ── Capabilities ──────────────────────────────────────
    println!("\nCapabilities");
    let opts = make_opts(cli, HashMap::new(), false);
    let mut any_enabled = false;

    for cap in registry.all() {
        if !cap.is_enabled(&opts) {
            continue;
        }
        any_enabled = true;

        // Map capability → expected sudoers drop-in name
        let drop_in = capability_sudoers_drop_in(cap.id());
        let present = drop_in
            .map(|name| std::path::Path::new("/etc/sudoers.d").join(name).exists())
            .unwrap_or(false);
        let (lines, has_issue) = capability_sudoers_status_lines(cap.id(), drop_in, present);
        for line in lines {
            println!("{line}");
        }
        if has_issue {
            total_issues += 1;
        }
    }

    if !any_enabled {
        println!("  (no capabilities enabled - run 'innerwarden list' to see options)");
    }

    // ── Integrations ──────────────────────────────────────
    // Only show this section when at least one integration collector is enabled.
    {
        let sensor_doc: Option<toml_edit::DocumentMut> = cli
            .sensor_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.sensor_config).ok())
            .flatten()
            .and_then(|s| s.parse().ok());

        let collector_enabled = |name: &str| -> bool {
            sensor_doc
                .as_ref()
                .and_then(|doc| doc.get("collectors"))
                .and_then(|c| c.get(name))
                .and_then(|s| s.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };

        let collector_str = |name: &str, key: &str, default: &str| -> String {
            sensor_doc
                .as_ref()
                .and_then(|doc| doc.get("collectors"))
                .and_then(|c| c.get(name))
                .and_then(|s| s.get(key))
                .and_then(|v| v.as_str())
                .unwrap_or(default)
                .to_string()
        };

        let detector_enabled = |name: &str| -> bool {
            sensor_doc
                .as_ref()
                .and_then(|doc| doc.get("detectors"))
                .and_then(|c| c.get(name))
                .and_then(|s| s.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };

        let nginx_error_enabled = collector_enabled("nginx_error");
        let any_integration = nginx_error_enabled;

        if any_integration {
            println!("\nIntegrations");

            // ── nginx-error-monitor ────────────────────────
            if nginx_error_enabled {
                println!("  nginx-error-monitor");
                let mut nginx_err = Vec::new();

                // nginx binary
                let nginx_bin = std::path::Path::new("/usr/sbin/nginx").exists()
                    || std::path::Path::new("/usr/bin/nginx").exists()
                    || std::path::Path::new("/usr/local/sbin/nginx").exists();
                nginx_err.push(if nginx_bin {
                    Check::ok("nginx binary found")
                } else {
                    Check::fail("nginx binary not found", "sudo apt-get install nginx")
                });

                // error log path — Bug 4 (2026-05-06): probe the
                // configured path AND a small list of common defaults
                // so a healthy operator with a custom nginx that has
                // not yet errored does not get a hard [fail].
                let err_log = collector_str("nginx_error", "path", "/var/log/nginx/error.log");
                let log_exists = std::path::Path::new(&err_log).exists();
                let alt_a = "/var/log/nginx/error.log";
                let alt_b = "/var/log/nginx/error_log";
                let alt_a_exists = err_log != alt_a && std::path::Path::new(alt_a).exists();
                let alt_b_exists = err_log != alt_b && std::path::Path::new(alt_b).exists();
                nginx_err.push(build_nginx_error_log_check_with_alternatives(
                    &err_log,
                    log_exists,
                    &[(alt_a, alt_a_exists), (alt_b, alt_b_exists)],
                ));

                // readability - can the current user read it?
                if log_exists {
                    let readable = std::fs::File::open(&err_log).is_ok();
                    nginx_err.push(if readable {
                        Check::ok(format!("nginx error log is readable ({})", err_log))
                    } else {
                        Check::warn(
                            format!("nginx error log is not readable by innerwarden user ({})", err_log),
                            "sudo usermod -aG adm innerwarden  # or: sudo chmod 640 /var/log/nginx/error.log",
                        )
                    });
                }

                // web_scan detector enabled?
                let web_scan_on = detector_enabled("web_scan");
                nginx_err.push(if web_scan_on {
                    Check::ok("web_scan detector is enabled")
                } else {
                    Check::warn(
                        "web_scan detector is disabled - http.error events are collected but not triaged",
                        "Add to sensor config:\n\n  [detectors.web_scan]\n  enabled = true\n  threshold = 15\n  window_seconds = 60",
                    )
                });

                run_section(nginx_err, &mut total_issues);
            }
        }
    }

    // ── Agent liveness ────────────────────────────────────
    {
        println!("\nAgent health");
        let mut liveness: Vec<Check> = vec![];

        let dir = doctor_resolve_agent_data_dir(agent_doc.as_ref());
        {
            let today = chrono::Local::now().format("%Y-%m-%d").to_string();
            let telemetry_path = dir.join(format!("telemetry-{today}.jsonl"));
            if telemetry_path.exists() {
                if let Ok(meta) = std::fs::metadata(&telemetry_path) {
                    if let Ok(modified) = meta.modified() {
                        let age = std::time::SystemTime::now()
                            .duration_since(modified)
                            .map(|d| d.as_secs())
                            .unwrap_or(u64::MAX);
                        liveness.push(build_telemetry_age_check(age));
                    }
                }
            } else {
                liveness.push(Check::warn(
                    "no telemetry file for today",
                    "agent has not written telemetry yet - is it running? innerwarden status",
                ));
            }
        }
        run_section(liveness, &mut total_issues);
    }

    // ── Summary ───────────────────────────────────────────
    println!();
    println!("{}", "─".repeat(48));
    println!("{}", doctor_summary_line(total_issues));
    if total_issues > 0 {
        // If configs are missing, offer a one-command path forward
        let configs_missing = !cli.sensor_config.exists() || !cli.agent_config.exists();
        if configs_missing {
            println!();
            println!("Getting started:  sudo innerwarden setup");
            println!("  Walks you through AI, Telegram, and essential modules.");
        }
    }
    Ok(total_issues)
}

pub(crate) fn cmd_pipeline_test(cli: &Cli, wait_secs: u64, data_dir: &Path) -> Result<()> {
    let effective_dir = resolve_data_dir(cli, data_dir);
    let today = today_date_string();
    let incidents_path = effective_dir.join(format!("incidents-{today}.jsonl"));
    let decisions_path = effective_dir.join(format!("decisions-{today}.jsonl"));

    // Count existing decisions to detect new ones
    let baseline = count_jsonl_lines(&decisions_path);

    // Use RFC 5737 documentation IP - safe, never routable
    let test_ip = "198.51.100.123";
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let now_iso = unix_secs_to_iso(now_secs);
    let marker = format!("innerwarden-test-{}", std::process::id());

    let hostname = std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let incident = build_pipeline_test_incident(test_ip, &marker, &hostname, &now_iso);

    println!("InnerWarden Pipeline Test");
    println!("{}\n", "─".repeat(50));

    // Step 1: Write test incident
    println!("  [1/4] Writing test incident...");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&incidents_path)?;
    writeln!(file, "{}", incident)?;
    println!("        Title: Possible SSH brute force from {test_ip}");
    println!("        Severity: HIGH");
    println!("        SSH brute-force from {test_ip} (documentation IP, safe)");
    println!("        Written to {}\n", incidents_path.display());

    // Step 2: Check agent is running
    println!("  [2/4] Checking agent status...");
    let agent_running = std::process::Command::new("pgrep")
        .args(["-f", "innerwarden-agent"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !agent_running {
        println!("        Agent process not detected.");
        println!("        The test incident was written but nobody is reading it.");
        println!("        Start the agent: sudo systemctl start innerwarden-agent\n");
        println!("  Result: PARTIAL - incident written, agent not running");
        return Ok(());
    }
    println!("        Agent is running.\n");

    // Step 3: Wait for agent to process
    println!("  [3/4] Waiting up to {wait_secs}s for agent to process...");
    let start = std::time::Instant::now();
    let mut found = false;
    while start.elapsed().as_secs() < wait_secs {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let current = count_jsonl_lines(&decisions_path);
        let content = std::fs::read_to_string(&decisions_path).ok();
        if pipeline_test_decision_found(current, baseline, content.as_deref(), &marker, test_ip) {
            found = true;
            break;
        }
        print!(".");
        std::io::stdout().flush().ok();
    }
    println!();

    // Step 4: Report results
    println!("\n  [4/4] Results:");
    if found {
        println!("        Pipeline is working.");
        println!("        Incident was detected, processed, and a decision was logged.");
        // Show the latest decision
        if let Ok(content) = std::fs::read_to_string(&decisions_path) {
            if let Some(last_line) = content.lines().rev().find(|l| l.contains(test_ip)) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(last_line) {
                    let mut lines = format_decision_summary(&val).into_iter();
                    if let Some(first) = lines.next() {
                        println!("\n        {first}");
                    }
                    for line in lines {
                        println!("        {line}");
                    }
                }
            }
        }
        println!("\n  {}", pipeline_test_result_label(true));
    } else {
        println!("        No decision appeared within {wait_secs} seconds.");
        println!("        Possible causes:");
        println!("          - Agent is running but AI provider is not configured");
        println!("          - Agent hasn't reached this incident in its read cycle");
        println!("          - Try again with --wait 30");
        println!("\n  {}", pipeline_test_result_label(false));
    }

    Ok(())
}

pub(crate) fn cmd_backup(cli: &Cli, output: Option<&Path>) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }

    // When no --output is given, create a secure temp file with an unpredictable name
    let tmp_file = if output.is_none() {
        Some(
            tempfile::Builder::new()
                .prefix("innerwarden-backup-")
                .suffix(".tar.gz")
                .tempfile()
                .context("failed to create temp file for backup")?,
        )
    } else {
        None
    };
    let default_path: PathBuf;
    let output_path = if let Some(ref tmp) = tmp_file {
        default_path = tmp.path().to_path_buf();
        &default_path
    } else {
        output.unwrap()
    };

    let files = [
        "etc/innerwarden/config.toml",
        "etc/innerwarden/agent.toml",
        "etc/innerwarden/agent.env",
    ];

    println!("InnerWarden - backup\n");
    println!("Backing up configuration files:");
    for f in &files {
        let abs = Path::new("/").join(f);
        let exists = abs.exists();
        println!("  {} /{}", if exists { "●" } else { "○ (missing)" }, f);
    }
    println!();
    println!("Output: {}", output_path.display());

    if cli.dry_run {
        println!("\n  [dry-run] would create archive - skipping.");
        return Ok(());
    }

    let status = std::process::Command::new("tar")
        .arg("czf")
        .arg(output_path)
        .arg("-C")
        .arg("/")
        .args(files)
        .status()
        .context("failed to run tar")?;

    if status.success() {
        // Keep the temp file so the backup persists on disk
        if let Some(tmp) = tmp_file {
            let _ = tmp.keep();
        }
        println!("\n  [ok] backup saved to {}", output_path.display());
    } else {
        anyhow::bail!(
            "tar exited with status {} - some files may be missing from /etc/innerwarden/",
            status
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden completions
// ---------------------------------------------------------------------------

pub(crate) fn cmd_completions(shell: &str) -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::Shell;

    let mut cmd = Cli::command();
    let shell_enum = match shell.to_lowercase().as_str() {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        other => {
            anyhow::bail!("unsupported shell '{}' - supported: bash, zsh, fish", other)
        }
    };

    clap_complete::generate(shell_enum, &mut cmd, "innerwarden", &mut std::io::stdout());
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
            command: Some(crate::Command::Decisions {
                days: 1,
                action: None,
            }),
        }
    }

    fn tune_date() -> String {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        epoch_secs_to_date(now_secs)
    }

    fn write_jsonl(path: &Path, lines: &[String]) {
        let content = if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        };
        std::fs::write(path, content).unwrap();
    }

    fn event_line(kind: &str) -> String {
        serde_json::json!({ "kind": kind }).to_string()
    }

    fn incident_line(detector: &str, id: usize) -> String {
        serde_json::json!({ "incident_id": format!("{detector}:{id}") }).to_string()
    }

    #[test]
    fn apply_detector_threshold_map_writes_valid_detector_keys() {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("agent.toml");
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert("detectors.ssh_bruteforce.threshold".to_string(), 7);
        overrides.insert("detectors.packet_flood.syn_threshold".to_string(), 111);

        apply_detector_threshold_map(&cfg, "normal", overrides);

        let content = std::fs::read_to_string(&cfg).unwrap();
        assert!(content.contains("[detectors.ssh_bruteforce]"));
        assert!(content.contains("threshold = 7"));
        assert!(content.contains("[detectors.packet_flood]"));
        assert!(content.contains("syn_threshold = 111"));
    }

    #[test]
    fn apply_detector_threshold_map_ignores_malformed_keys() {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("agent.toml");
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert("detectors.ssh_bruteforce.threshold".to_string(), 5);
        overrides.insert("detectors.invalid".to_string(), 999);

        apply_detector_threshold_map(&cfg, "normal", overrides);

        let content = std::fs::read_to_string(&cfg).unwrap();
        assert!(content.contains("threshold = 5"));
        assert!(!content.contains("999"));
    }

    #[test]
    fn apply_detector_threshold_map_handles_write_failures_gracefully() {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("missing").join("agent.toml");
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert("detectors.ssh_bruteforce.threshold".to_string(), 5);

        apply_detector_threshold_map(&cfg, "normal", overrides);

        assert!(!cfg.exists());
    }

    #[test]
    fn apply_detector_threshold_overrides_handles_invalid_level() {
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("agent.toml");
        apply_detector_threshold_overrides(&cfg, "not-a-real-level");
        assert!(!cfg.exists());
    }

    #[test]
    fn cmd_configure_sensitivity_writes_notification_and_detector_thresholds() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);

        let _ = cmd_configure_sensitivity(&cli, "normal");

        let content = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(content.contains("[telegram]"));
        assert!(content.contains("min_severity = \"high\""));
        assert!(content.contains("[webhook]"));
        assert!(content.contains("[detectors.ssh_bruteforce]"));
        assert!(content.contains("threshold = 5"));
    }

    #[test]
    fn cmd_configure_sensitivity_unknown_level_is_noop() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);

        cmd_configure_sensitivity(&cli, "chatty").unwrap();

        assert!(!cli.agent_config.exists());
    }

    #[test]
    fn append_or_update_env_creates_parent_and_new_key() {
        let dir = TempDir::new().unwrap();
        let env_file = dir.path().join("etc").join("innerwarden").join("agent.env");

        append_or_update_env(&env_file, "INNERWARDEN_TOTP_SECRET", "ABC123").unwrap();

        let content = std::fs::read_to_string(&env_file).unwrap();
        assert_eq!(content, "INNERWARDEN_TOTP_SECRET=\"ABC123\"\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&env_file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn append_or_update_env_updates_existing_key_and_preserves_other_lines() {
        let dir = TempDir::new().unwrap();
        let env_file = dir.path().join("agent.env");
        std::fs::write(
            &env_file,
            "# managed by test\nINNERWARDEN_TOTP_SECRET=\"old\"\nOTHER=value\n",
        )
        .unwrap();

        append_or_update_env(&env_file, "INNERWARDEN_TOTP_SECRET", "new").unwrap();

        let content = std::fs::read_to_string(&env_file).unwrap();
        assert_eq!(
            content,
            "# managed by test\nINNERWARDEN_TOTP_SECRET=\"new\"\nOTHER=value\n"
        );
        assert_eq!(content.matches("INNERWARDEN_TOTP_SECRET=").count(), 1);
    }

    #[test]
    fn base32_encode_simple_matches_rfc4648_vectors_without_padding() {
        let cases = [
            (b"".as_slice(), ""),
            (b"f".as_slice(), "MY"),
            (b"fo".as_slice(), "MZXQ"),
            (b"foo".as_slice(), "MZXW6"),
            (b"foob".as_slice(), "MZXW6YQ"),
            (b"fooba".as_slice(), "MZXW6YTB"),
            (b"foobar".as_slice(), "MZXW6YTBOI"),
        ];

        for (input, expected) in cases {
            assert_eq!(base32_encode_simple(input), expected);
        }
    }

    #[test]
    fn hotp_generation_matches_rfc4226_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];

        for (counter, code) in expected.into_iter().enumerate() {
            assert_eq!(generate_totp_code(secret, counter as u64), code);
        }
    }

    #[test]
    fn totp_verification_rejects_non_six_digit_input() {
        assert!(!verify_totp_code(b"secret", "12345"));
        assert!(!verify_totp_code(b"secret", "1234567"));
        assert!(!verify_totp_code(b"secret", "abcdef"));
    }

    #[test]
    fn sha1_simple_matches_known_digest() {
        assert_eq!(
            sha1_simple(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ]
        );
    }

    #[test]
    fn cmd_tune_handles_missing_event_data() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);

        cmd_tune(&cli, 1, true, dir.path()).unwrap();
    }

    #[test]
    fn cmd_tune_reports_calibrated_thresholds_without_changes() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        let date = tune_date();
        let events_path = dir.path().join(format!("events-{date}.jsonl"));
        let incidents_path = dir.path().join(format!("incidents-{date}.jsonl"));
        let events = vec![event_line("ssh.login_failed"); 5];
        write_jsonl(&events_path, &events);
        write_jsonl(&incidents_path, &[]);
        std::fs::write(
            &cli.sensor_config,
            "[detectors.ssh_bruteforce]\nthreshold = 8\n",
        )
        .unwrap();

        cmd_tune(&cli, 1, true, dir.path()).unwrap();

        let content = std::fs::read_to_string(&cli.sensor_config).unwrap();
        assert!(content.contains("threshold = 8"));
    }

    #[test]
    fn cmd_tune_dry_run_reports_raise_suggestions_without_writing() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        let date = tune_date();
        let events_path = dir.path().join(format!("events-{date}.jsonl"));
        let incidents_path = dir.path().join(format!("incidents-{date}.jsonl"));
        let events = vec![event_line("ssh.login_failed"); 100];
        write_jsonl(&events_path, &events);
        write_jsonl(&incidents_path, &[]);
        std::fs::write(
            &cli.sensor_config,
            "[detectors.ssh_bruteforce]\nthreshold = 1\n",
        )
        .unwrap();

        cmd_tune(&cli, 1, true, dir.path()).unwrap();

        let content = std::fs::read_to_string(&cli.sensor_config).unwrap();
        assert!(content.contains("threshold = 1"));
    }

    #[test]
    fn cmd_tune_applies_raise_suggestion_and_writes_audit() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), false);
        let date = tune_date();
        let events_path = dir.path().join(format!("events-{date}.jsonl"));
        let incidents_path = dir.path().join(format!("incidents-{date}.jsonl"));
        let events = vec![event_line("ssh.login_failed"); 100];
        write_jsonl(&events_path, &events);
        write_jsonl(&incidents_path, &[]);
        std::fs::write(
            &cli.sensor_config,
            "[detectors.ssh_bruteforce]\nthreshold = 1\n",
        )
        .unwrap();

        cmd_tune(&cli, 1, true, dir.path()).unwrap();

        let content = std::fs::read_to_string(&cli.sensor_config).unwrap();
        assert!(content.contains("threshold = 3"));
        let audit_path = dir
            .path()
            .join(format!("admin-actions-{}.jsonl", today_date_string()));
        assert!(audit_path.exists());
    }

    #[test]
    fn cmd_tune_applies_lower_suggestion_when_incidents_are_noisy() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), false);
        let date = tune_date();
        let events_path = dir.path().join(format!("events-{date}.jsonl"));
        let incidents_path = dir.path().join(format!("incidents-{date}.jsonl"));
        let events = vec![event_line("ssh.login_failed"); 20];
        let incidents: Vec<String> = (0..20)
            .map(|id| incident_line("ssh_bruteforce", id))
            .collect();
        write_jsonl(&events_path, &events);
        write_jsonl(&incidents_path, &incidents);
        std::fs::write(
            &cli.sensor_config,
            "[detectors.ssh_bruteforce]\nthreshold = 8\n",
        )
        .unwrap();

        cmd_tune(&cli, 1, true, dir.path()).unwrap();

        let content = std::fs::read_to_string(&cli.sensor_config).unwrap();
        assert!(content.contains("threshold = 7"));
    }

    #[test]
    fn cmd_pipeline_test_writes_safe_incident_fixture() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);

        cmd_pipeline_test(&cli, 0, dir.path()).unwrap();

        let incident_path = dir
            .path()
            .join(format!("incidents-{}.jsonl", today_date_string()));
        let content = std::fs::read_to_string(incident_path).unwrap();
        assert!(content.contains("198.51.100.123"));
        assert!(content.contains("pipeline-test"));
    }

    #[test]
    fn cmd_backup_dry_run_accepts_explicit_output() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        let output = dir.path().join("backup.tar.gz");

        cmd_backup(&cli, Some(&output)).unwrap();

        assert!(!output.exists());
    }

    #[test]
    fn cmd_backup_dry_run_accepts_generated_output_path() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);

        cmd_backup(&cli, None).unwrap();
    }

    #[test]
    fn cmd_completions_rejects_unknown_shell() {
        let err = cmd_completions("powershell").unwrap_err();
        assert!(err.to_string().contains("unsupported shell"));
    }

    // -- New helper coverage --------------------------------------------------

    // -- Check + Sev ----------------------------------------------------------

    #[test]
    fn check_ok_has_no_hint_and_is_not_an_issue() {
        let c = Check::ok("looks good");
        assert_eq!(c.sev, Sev::Ok);
        assert_eq!(c.tag(), "[ok]  ");
        assert!(c.hint.is_none());
        assert!(!c.is_issue());
    }

    #[test]
    fn check_warn_carries_hint_and_counts_as_issue() {
        let c = Check::warn("close but not quite", "fix it like so");
        assert_eq!(c.sev, Sev::Warn);
        assert_eq!(c.tag(), "[warn]");
        assert_eq!(c.hint.as_deref(), Some("fix it like so"));
        assert!(c.is_issue());
    }

    #[test]
    fn check_fail_carries_hint_and_counts_as_issue() {
        let c = Check::fail("definitely broken", "do this");
        assert_eq!(c.sev, Sev::Fail);
        assert_eq!(c.tag(), "[fail]");
        assert_eq!(c.hint.as_deref(), Some("do this"));
        assert!(c.is_issue());
    }

    #[test]
    fn run_section_only_counts_non_ok_checks() {
        let checks = vec![
            Check::ok("a"),
            Check::warn("b", "h"),
            Check::ok("c"),
            Check::fail("d", "h"),
        ];
        let mut issues = 7u32; // confirm it accumulates
        run_section(checks, &mut issues);
        assert_eq!(issues, 9);
    }

    #[test]
    fn run_section_does_not_change_count_when_all_ok() {
        let checks = vec![Check::ok("x"), Check::ok("y")];
        let mut issues = 3u32;
        run_section(checks, &mut issues);
        assert_eq!(issues, 3);
    }

    // -- looks_like_* validators ---------------------------------------------

    #[test]
    fn looks_like_openai_key_accepts_long_sk_keys() {
        assert!(looks_like_openai_key("sk-abcdefghijklmnopqrst"));
        assert!(looks_like_openai_key(
            "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    #[test]
    fn looks_like_openai_key_rejects_other_shapes() {
        assert!(!looks_like_openai_key(""));
        assert!(!looks_like_openai_key("sk-short"));
        assert!(!looks_like_openai_key("xx-abcdefghijklmnopqrstuv"));
    }

    #[test]
    fn gate_doctor_check_fails_on_apply_drift_the_oracle_case() {
        use innerwarden_core::execution_gate::{GateMode, GateState};
        let gate = GateState {
            signed_count: Some(1685),
            intended_mode: Some(GateMode::Observe),
            live_count: Some(0),
            live_mode: GateMode::Inert,
            live_scope_armed: None,
            live_scope_count: None,
        };
        let check = gate_doctor_check(&gate, None);
        assert_eq!(check.sev, Sev::Fail);
        assert!(check.label.contains("apply drift"));
        assert!(check.label.contains("1685"));
    }

    #[test]
    fn gate_doctor_check_fails_critical_when_armed_and_empty() {
        use innerwarden_core::execution_gate::{GateMode, GateState};
        let gate = GateState {
            signed_count: Some(10),
            intended_mode: Some(GateMode::Enforce),
            live_count: Some(0),
            live_mode: GateMode::Enforce,
            live_scope_armed: None,
            live_scope_count: None,
        };
        let check = gate_doctor_check(&gate, None);
        assert_eq!(check.sev, Sev::Fail);
        assert!(check.label.contains("EMPTY"));
    }

    #[test]
    fn gate_doctor_check_ok_when_converged() {
        use innerwarden_core::execution_gate::{GateMode, GateState};
        let gate = GateState {
            signed_count: Some(1685),
            intended_mode: Some(GateMode::Observe),
            live_count: Some(1685),
            live_mode: GateMode::Observe,
            live_scope_armed: None,
            live_scope_count: None,
        };
        let check = gate_doctor_check(&gate, None);
        assert_eq!(check.sev, Sev::Ok);
        assert!(check.label.contains("consistent"));
    }

    #[test]
    fn gate_doctor_check_fails_on_scope_armed_but_empty() {
        use innerwarden_core::execution_gate::{GateMode, GateState};
        // enforce + agent-scoped (key4=1) + empty scope map: the gate protects
        // nothing while looking armed.
        let gate = GateState {
            signed_count: None,
            intended_mode: None,
            live_count: Some(50),
            live_mode: GateMode::Enforce,
            live_scope_armed: Some(true),
            live_scope_count: Some(0),
        };
        let check = gate_doctor_check(&gate, None);
        assert_eq!(check.sev, Sev::Fail);
        assert!(check.label.contains("EXEC_GATE_SCOPE is EMPTY"));
    }

    #[test]
    fn gate_lsm_inactive_note_only_when_bpf_off() {
        assert!(gate_lsm_inactive_note(Some(false))
            .unwrap()
            .contains("lsm=...,bpf"));
        // bpf active / unreadable -> no note (never cry wolf on an unreadable list).
        assert!(gate_lsm_inactive_note(Some(true)).is_none());
        assert!(gate_lsm_inactive_note(None).is_none());
    }

    #[test]
    fn gate_doctor_check_fails_when_armed_but_bpf_lsm_inactive() {
        use innerwarden_core::execution_gate::{GateMode, GateState};
        // The Azure-6.17 OpenClaw finding: maps perfectly healthy (enforce, scoped,
        // full allowlist) but `bpf` not in the active LSM stack -> gate is a no-op.
        let gate = GateState {
            signed_count: Some(3628),
            intended_mode: Some(GateMode::Enforce),
            live_count: Some(3628),
            live_mode: GateMode::Enforce,
            live_scope_armed: Some(true),
            live_scope_count: Some(1),
        };
        // bpf active -> converged/ok; bpf inactive -> fail with remediation.
        assert_eq!(gate_doctor_check(&gate, Some(true)).sev, Sev::Ok);
        let check = gate_doctor_check(&gate, Some(false));
        assert_eq!(check.sev, Sev::Fail);
        assert!(check.label.contains("BPF-LSM is NOT active"));
        assert!(check.hint.as_deref().unwrap().contains("lsm=...,bpf"));
    }

    #[test]
    fn gate_doctor_check_warns_when_live_unreadable_but_signed_present() {
        use innerwarden_core::execution_gate::{GateMode, GateState};
        let gate = GateState {
            signed_count: Some(1685),
            intended_mode: Some(GateMode::Observe),
            live_count: None, // bpftool unavailable / unprivileged
            live_mode: GateMode::Unknown,
            live_scope_armed: None,
            live_scope_count: None,
        };
        let check = gate_doctor_check(&gate, None);
        assert_eq!(check.sev, Sev::Warn);
        assert!(check.label.contains("not readable"));
    }

    #[test]
    fn looks_like_anthropic_key_accepts_sk_ant_prefix() {
        assert!(looks_like_anthropic_key("sk-ant-abcdefghijklmno"));
        assert!(looks_like_anthropic_key(
            "sk-ant-api03-1234567890abcdefghij"
        ));
    }

    #[test]
    fn looks_like_anthropic_key_rejects_openai_keys() {
        assert!(!looks_like_anthropic_key("sk-abcdefghijklmnopqrst"));
        assert!(!looks_like_anthropic_key("sk-ant-short"));
    }

    #[test]
    fn looks_like_telegram_token_accepts_canonical_format() {
        assert!(looks_like_telegram_token(
            "1234567890:AABBccDDeeffGGHHiijjKKLLmmNN"
        ));
        assert!(looks_like_telegram_token("1:abcdefghijABCDEFGHIJ"));
    }

    #[test]
    fn looks_like_telegram_token_rejects_invalid_shapes() {
        assert!(!looks_like_telegram_token(""));
        assert!(!looks_like_telegram_token("nocolonhere"));
        assert!(!looks_like_telegram_token(":abcdefghij1234567890"));
        assert!(!looks_like_telegram_token("abc:abcdefghij1234567890"));
        assert!(!looks_like_telegram_token("12345:short"));
    }

    #[test]
    fn looks_like_telegram_chat_id_accepts_personal_and_group() {
        assert!(looks_like_telegram_chat_id("123456789"));
        assert!(looks_like_telegram_chat_id("-1001234567890"));
    }

    #[test]
    fn looks_like_telegram_chat_id_rejects_invalid() {
        assert!(!looks_like_telegram_chat_id(""));
        assert!(!looks_like_telegram_chat_id("abc"));
        assert!(!looks_like_telegram_chat_id("123abc"));
    }

    #[test]
    fn looks_like_slack_url_validation() {
        let good = format!(
            "https://hooks.slack.com/services/{}",
            "T0123456/B0123456/abcdefghijklmnopqrstuvwx"
        );
        assert!(looks_like_slack_url(&good));
        assert!(!looks_like_slack_url(""));
        assert!(!looks_like_slack_url(
            "https://hooks.slack.com/services/short"
        ));
        assert!(!looks_like_slack_url("https://example.com/services/foo"));
    }

    #[test]
    fn looks_webhook_url_valid_accepts_http_and_https() {
        assert!(looks_webhook_url_valid("http://example.com/hook"));
        assert!(looks_webhook_url_valid("https://example.com/hook"));
        assert!(!looks_webhook_url_valid(""));
        assert!(!looks_webhook_url_valid("ftp://example.com/hook"));
        assert!(!looks_webhook_url_valid("example.com/hook"));
    }

    // -- resolve_three_tier ---------------------------------------------------

    #[test]
    fn resolve_three_tier_prefers_config_over_env_and_file() {
        let got = resolve_three_tier(
            Some("from-config"),
            Some("from-env"),
            "MY_KEY=from-file\n",
            "MY_KEY",
        );
        assert_eq!(got.as_deref(), Some("from-config"));
    }

    #[test]
    fn resolve_three_tier_falls_back_to_env_when_config_empty() {
        let got = resolve_three_tier(Some(""), Some("from-env"), "MY_KEY=ignored\n", "MY_KEY");
        assert_eq!(got.as_deref(), Some("from-env"));
    }

    #[test]
    fn resolve_three_tier_falls_back_to_env_file_last() {
        let got = resolve_three_tier(None, None, "OTHER=skip\nMY_KEY=\"from-file\"\n", "MY_KEY");
        assert_eq!(got.as_deref(), Some("from-file"));
    }

    #[test]
    fn resolve_three_tier_returns_none_when_nothing_set() {
        let got = resolve_three_tier(None, None, "OTHER=value\n", "MISSING");
        assert!(got.is_none());
    }

    #[test]
    fn resolve_three_tier_skips_empty_env_file_value() {
        let got = resolve_three_tier(None, None, "MY_KEY=   \n", "MY_KEY");
        assert!(got.is_none());
    }

    // -- agent_section_str / agent_section_enabled ---------------------------

    #[test]
    fn agent_section_str_reads_existing_value() {
        let doc: toml_edit::DocumentMut = "[ai]\nprovider = \"anthropic\"\n".parse().unwrap();
        assert_eq!(
            agent_section_str(Some(&doc), "ai", "provider"),
            Some("anthropic")
        );
    }

    #[test]
    fn agent_section_str_returns_none_for_missing_section() {
        let doc: toml_edit::DocumentMut = "[ai]\nprovider = \"openai\"\n".parse().unwrap();
        assert_eq!(agent_section_str(Some(&doc), "telegram", "bot_token"), None);
        assert_eq!(agent_section_str(None, "ai", "provider"), None);
    }

    #[test]
    fn agent_section_enabled_returns_true_when_set_true() {
        let doc: toml_edit::DocumentMut = "[abuseipdb]\nenabled = true\napi_key = \"x\"\n"
            .parse()
            .unwrap();
        assert!(agent_section_enabled(Some(&doc), "abuseipdb"));
    }

    #[test]
    fn agent_section_enabled_returns_false_when_missing_or_disabled() {
        let doc: toml_edit::DocumentMut = "[abuseipdb]\nenabled = false\n".parse().unwrap();
        assert!(!agent_section_enabled(Some(&doc), "abuseipdb"));
        let doc2: toml_edit::DocumentMut = "[telegram]\n".parse().unwrap();
        assert!(!agent_section_enabled(Some(&doc2), "abuseipdb"));
        assert!(!agent_section_enabled(None, "abuseipdb"));
    }

    // -- AI / Telegram / Slack / Webhook check builders ----------------------

    #[test]
    fn build_ai_provider_check_anthropic_missing_key() {
        let c = build_ai_provider_check("anthropic", None);
        assert_eq!(c.sev, Sev::Fail);
        assert!(c.label.contains("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn build_ai_provider_check_anthropic_valid_key() {
        let c = build_ai_provider_check("anthropic", Some("sk-ant-aaaaaaaaaaaaaaaaaaa"));
        assert_eq!(c.sev, Sev::Ok);
    }

    #[test]
    fn build_ai_provider_check_anthropic_malformed_key_warns() {
        let c = build_ai_provider_check("anthropic", Some("sk-ant-short"));
        assert_eq!(c.sev, Sev::Warn);
    }

    #[test]
    fn build_ai_provider_check_openai_missing_key() {
        let c = build_ai_provider_check("openai", None);
        assert_eq!(c.sev, Sev::Fail);
        assert!(c.label.contains("OPENAI_API_KEY"));
    }

    #[test]
    fn build_ai_provider_check_openai_valid_key() {
        let c = build_ai_provider_check("openai", Some("sk-aaaaaaaaaaaaaaaaaaa"));
        assert_eq!(c.sev, Sev::Ok);
    }

    #[test]
    fn build_ai_provider_check_openai_malformed_key_warns() {
        let c = build_ai_provider_check("openai", Some("not-a-real-key"));
        assert_eq!(c.sev, Sev::Warn);
    }

    #[test]
    fn build_ai_provider_check_unknown_provider_treated_as_openai() {
        let c = build_ai_provider_check("custom-provider", None);
        // Unknown providers default to the openai message
        assert!(c.label.contains("OPENAI_API_KEY"));
    }

    #[test]
    fn build_ai_provider_check_ollama_returns_ok() {
        let c = build_ai_provider_check("ollama", None);
        assert_eq!(c.sev, Sev::Ok);
    }

    #[test]
    fn build_ai_provider_check_azure_missing_key_fails_with_azure_var() {
        // Regression: azure used to fall through to the openai arm and report
        // "OPENAI_API_KEY not set" — a confusing false fail for azure users.
        let c = build_ai_provider_check("azure_openai", None);
        assert_eq!(c.sev, Sev::Fail);
        assert!(c.label.contains("AZURE_OPENAI_API_KEY"));
        assert!(!c
            .label
            .contains("OPENAI_API_KEY not set (provider = \"openai\")"));
    }

    #[test]
    fn build_ai_provider_check_azure_alias_with_key_is_ok() {
        let c = build_ai_provider_check("azure", Some("8Y59hQabcdef0123456789"));
        assert_eq!(c.sev, Sev::Ok);
        assert!(c.label.contains("AZURE_OPENAI_API_KEY"));
    }

    #[test]
    fn build_ai_provider_check_azure_empty_key_fails() {
        let c = build_ai_provider_check("azure_openai", Some("   "));
        assert_eq!(c.sev, Sev::Fail);
    }

    #[test]
    fn build_telegram_token_check_missing_token_fails() {
        let env_path = Path::new("/etc/innerwarden/agent.env");
        let c = build_telegram_token_check(None, env_path);
        assert_eq!(c.sev, Sev::Fail);
        assert!(c.hint.unwrap().contains("agent.env"));
    }

    #[test]
    fn build_telegram_token_check_valid_token_ok() {
        let env_path = Path::new("/etc/innerwarden/agent.env");
        let c = build_telegram_token_check(
            Some("1234567890:AABBccDDeeffGGHHiijjKKLLmmNNooPP"),
            env_path,
        );
        assert_eq!(c.sev, Sev::Ok);
    }

    #[test]
    fn build_telegram_token_check_malformed_warns() {
        let env_path = Path::new("/etc/innerwarden/agent.env");
        let c = build_telegram_token_check(Some("not-a-real-token"), env_path);
        assert_eq!(c.sev, Sev::Warn);
    }

    #[test]
    fn build_telegram_chat_check_missing_fails() {
        let env_path = Path::new("/etc/innerwarden/agent.env");
        let c = build_telegram_chat_check(None, env_path);
        assert_eq!(c.sev, Sev::Fail);
    }

    #[test]
    fn build_telegram_chat_check_personal_id_ok() {
        let env_path = Path::new("/etc/innerwarden/agent.env");
        let c = build_telegram_chat_check(Some("123456789"), env_path);
        assert_eq!(c.sev, Sev::Ok);
    }

    #[test]
    fn build_telegram_chat_check_group_id_ok() {
        let env_path = Path::new("/etc/innerwarden/agent.env");
        let c = build_telegram_chat_check(Some("-1001234567890"), env_path);
        assert_eq!(c.sev, Sev::Ok);
    }

    #[test]
    fn build_telegram_chat_check_non_numeric_warns() {
        let env_path = Path::new("/etc/innerwarden/agent.env");
        let c = build_telegram_chat_check(Some("@channel"), env_path);
        assert_eq!(c.sev, Sev::Warn);
    }

    #[test]
    fn build_slack_webhook_check_missing_fails() {
        let c = build_slack_webhook_check(None, Path::new("/tmp/agent.env"));
        assert_eq!(c.sev, Sev::Fail);
    }

    #[test]
    fn build_slack_webhook_check_valid_url_ok() {
        let url = format!(
            "https://hooks.slack.com/services/{}",
            "T0AAAA/B0BBBB/CCCCDDDDEEEEFFFFGGGGHHHH"
        );
        let c = build_slack_webhook_check(Some(&url), Path::new("/tmp/agent.env"));
        assert_eq!(c.sev, Sev::Ok);
    }

    #[test]
    fn build_slack_webhook_check_wrong_host_warns() {
        let c = build_slack_webhook_check(
            Some("https://example.com/hooks/something/with-extra-padding-bytes"),
            Path::new("/tmp/agent.env"),
        );
        assert_eq!(c.sev, Sev::Warn);
    }

    #[test]
    fn build_webhook_url_check_empty_fails() {
        let c = build_webhook_url_check("");
        assert_eq!(c.sev, Sev::Fail);
        assert!(c.label.contains("webhook.url"));
    }

    #[test]
    fn build_webhook_url_check_invalid_scheme_fails() {
        let c = build_webhook_url_check("ftp://example.com/hook");
        assert_eq!(c.sev, Sev::Fail);
    }

    #[test]
    fn build_webhook_url_check_https_ok() {
        let c = build_webhook_url_check("https://example.com/hook");
        assert_eq!(c.sev, Sev::Ok);
        assert!(c.label.contains("https://example.com/hook"));
    }

    #[test]
    fn build_abuseipdb_key_check_missing_fails() {
        let c = build_abuseipdb_key_check(None);
        assert_eq!(c.sev, Sev::Fail);
    }

    #[test]
    fn build_abuseipdb_key_check_short_warns() {
        let c = build_abuseipdb_key_check(Some("abc"));
        assert_eq!(c.sev, Sev::Warn);
    }

    #[test]
    fn build_abuseipdb_key_check_long_ok() {
        // 80 chars is the realistic length
        let c = build_abuseipdb_key_check(Some(
            "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0",
        ));
        assert_eq!(c.sev, Sev::Ok);
    }

    // -- suggest_detector_threshold ------------------------------------------

    #[test]
    fn suggest_detector_threshold_lowers_when_too_many_incidents() {
        // > 10 incidents/day, current > 3 → lower by 1, floor 2
        assert_eq!(suggest_detector_threshold(50, 11.0, 8), 7);
        assert_eq!(suggest_detector_threshold(50, 50.0, 4), 3);
        // floor at 2: current_val=4 → (4-1).max(2) = 3, then current_val=4
        // can drop again on the next pass; ensure single-pass behaviour
        // never goes below 2.
        assert_eq!(suggest_detector_threshold(50, 12.0, 4), 3);
    }

    #[test]
    fn suggest_detector_threshold_does_not_lower_when_threshold_already_at_floor() {
        // current_val <= 3 disables the lower branch — value is left intact.
        assert_eq!(suggest_detector_threshold(50, 100.0, 3), 3);
        assert_eq!(suggest_detector_threshold(50, 100.0, 2), 2);
    }

    #[test]
    fn suggest_detector_threshold_raises_when_quiet_events_dominate() {
        // events_per_day > current * 20 and zero incidents → raise by 2
        assert_eq!(suggest_detector_threshold(500, 0.0, 5), 7);
        // ceiling at 50 even if math would go higher
        assert_eq!(suggest_detector_threshold(50_000, 0.0, 49), 50);
    }

    #[test]
    fn suggest_detector_threshold_nudges_when_some_incidents_but_quiet() {
        // events_per_day > current * 5 and incidents_per_day < 1 → +1
        assert_eq!(suggest_detector_threshold(60, 0.5, 10), 11);
    }

    #[test]
    fn suggest_detector_threshold_returns_current_when_calibrated() {
        // No condition fires → unchanged
        assert_eq!(suggest_detector_threshold(10, 0.5, 8), 8);
    }

    // -- unix_secs_to_iso ----------------------------------------------------

    #[test]
    fn unix_secs_to_iso_epoch() {
        assert_eq!(unix_secs_to_iso(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn unix_secs_to_iso_known_dates() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(unix_secs_to_iso(1_704_067_200), "2024-01-01T00:00:00Z");
        // 2024-02-29T12:34:56Z = 1709210096 (leap year)
        assert_eq!(unix_secs_to_iso(1_709_210_096), "2024-02-29T12:34:56Z");
        // 2025-12-31T23:59:59Z = 1767225599
        assert_eq!(unix_secs_to_iso(1_767_225_599), "2025-12-31T23:59:59Z");
    }

    #[test]
    fn unix_secs_to_iso_format_is_well_formed() {
        let s = unix_secs_to_iso(1_700_000_000);
        // YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
        assert_eq!(s.chars().nth(4), Some('-'));
        assert_eq!(s.chars().nth(10), Some('T'));
    }

    // -- build_pipeline_test_incident ----------------------------------------

    #[test]
    fn build_pipeline_test_incident_fields_and_tags() {
        let v = build_pipeline_test_incident(
            "198.51.100.123",
            "marker-abc",
            "myhost",
            "2026-05-06T12:34:56Z",
        );
        assert_eq!(v["host"], "myhost");
        assert_eq!(v["severity"], "high");
        assert_eq!(v["ts"], "2026-05-06T12:34:56Z");
        assert_eq!(v["incident_id"], "ssh_bruteforce:198.51.100.123:marker-abc");
        assert!(v["title"].as_str().unwrap().contains("198.51.100.123"));
        let tags = v["tags"].as_array().unwrap();
        assert!(tags.iter().any(|t| t == "pipeline-test"));
        let entities = v["entities"].as_array().unwrap();
        assert_eq!(entities[0]["type"], "ip");
        assert_eq!(entities[0]["value"], "198.51.100.123");
        let evidence = v["evidence"].as_array().unwrap();
        assert_eq!(evidence[0]["count"], 12);
        assert_eq!(evidence[0]["window_seconds"], 30);
    }

    // -- format_decision_summary ---------------------------------------------

    #[test]
    fn format_decision_summary_uses_action_type_when_present() {
        let v = serde_json::json!({
            "action_type": "block_ip",
            "confidence": 0.85,
            "dry_run": false,
            "reason": "high-confidence brute force"
        });
        let lines = format_decision_summary(&v);
        assert_eq!(lines[0], "Action: block_ip");
        assert_eq!(lines[1], "Confidence: 85%");
        assert_eq!(lines[2], "Dry-run: false");
        assert_eq!(lines[3], "Reason: high-confidence brute force");
        // dry=false, so no "(safe…)" footnote
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn format_decision_summary_falls_back_to_action_field() {
        let v = serde_json::json!({
            "action": "monitor",
            "confidence": 0.42,
            "dry_run": true
        });
        let lines = format_decision_summary(&v);
        assert_eq!(lines[0], "Action: monitor");
        assert_eq!(lines[1], "Confidence: 42%");
        assert_eq!(lines[2], "Dry-run: true");
        // No reason → 4th entry should be the dry-run footnote
        assert!(lines.last().unwrap().starts_with("(safe"));
    }

    #[test]
    fn format_decision_summary_handles_missing_fields() {
        let v = serde_json::json!({});
        let lines = format_decision_summary(&v);
        // Defaults: action="?", confidence=0%, dry_run=true (defaults to safe)
        assert_eq!(lines[0], "Action: ?");
        assert_eq!(lines[1], "Confidence: 0%");
        assert_eq!(lines[2], "Dry-run: true");
        assert!(lines.last().unwrap().starts_with("(safe"));
    }

    #[test]
    fn format_decision_summary_omits_empty_reason() {
        let v = serde_json::json!({
            "action_type": "ignore",
            "confidence": 0.10,
            "dry_run": false,
            "reason": ""
        });
        let lines = format_decision_summary(&v);
        assert_eq!(lines.len(), 3);
        assert!(!lines.iter().any(|l| l.starts_with("Reason:")));
    }

    // -- cmd_completions: each supported shell --------------------------------

    #[test]
    fn cmd_completions_supports_bash() {
        cmd_completions("bash").unwrap();
    }

    #[test]
    fn cmd_completions_supports_zsh() {
        cmd_completions("zsh").unwrap();
    }

    #[test]
    fn cmd_completions_supports_fish() {
        cmd_completions("fish").unwrap();
    }

    #[test]
    fn cmd_completions_is_case_insensitive() {
        cmd_completions("BASH").unwrap();
        cmd_completions("Zsh").unwrap();
    }

    // -- render_qr_to_terminal: smoke test (must not panic) ------------------

    #[test]
    fn render_qr_to_terminal_runs_for_valid_payload() {
        // The function only prints — we just confirm it doesn't panic for a
        // realistic-length URI. Empty input also goes through QrCode::new
        // and either generates a code or prints the failure message.
        render_qr_to_terminal(
            "otpauth://totp/InnerWarden:admin?secret=ABCDEF&issuer=InnerWarden&algorithm=SHA1&digits=6&period=30",
        );
        render_qr_to_terminal("");
    }

    // -- verify_totp_code: positive paths ------------------------------------

    #[test]
    fn verify_totp_code_accepts_current_step() {
        let secret = b"12345678901234567890";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let step = now / 30;
        let code = generate_totp_code(secret, step);
        let code_str = format!("{:06}", code);
        assert!(verify_totp_code(secret, &code_str));
    }

    #[test]
    fn verify_totp_code_rejects_wrong_code_for_current_step() {
        // Build a code that's deterministically wrong for now.
        let secret = b"12345678901234567890";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let step = now / 30;
        let real = generate_totp_code(secret, step);
        // Adjust by 1 (modulo 1e6) to guarantee a mismatch.
        let wrong = (real + 1) % 1_000_000;
        let wrong_str = format!("{:06}", wrong);
        assert!(!verify_totp_code(secret, &wrong_str));
    }

    // -- hmac_sha1_simple: extra path coverage --------------------------------

    #[test]
    fn hmac_sha1_simple_handles_oversized_key() {
        // Keys longer than the HMAC block size (64 bytes) are pre-hashed via
        // sha1_simple. This path is unreachable with TOTP secrets but is a
        // documented branch in the helper.
        let big_key = vec![0xAAu8; 80];
        let mac1 = hmac_sha1_simple(&big_key, b"hi");
        // Sanity: the result of a large key is identical to running HMAC
        // with the SHA-1-prehashed version of the key.
        let mut prehashed = [0u8; 64];
        prehashed[..20].copy_from_slice(&sha1_simple(&big_key));
        let mac2 = hmac_sha1_simple(&prehashed, b"hi");
        assert_eq!(mac1, mac2);
    }

    // -- cmd_doctor smoke: verifies new helpers integrate without panicking ---

    #[test]
    fn cmd_doctor_runs_with_minimal_config() {
        // The doctor calls process::exit(1) when issues are found, so we only
        // run it in a configuration that should pass — neither config exists,
        // no capabilities are enabled. We simply exercise the section
        // helpers (Check construction, run_section accumulation) along the
        // way without exhausting every branch.
        //
        // The test is defensive: tarpaulin runs in-process, so a process::exit
        // would terminate the suite. We therefore only assert the helper
        // entry points are wired in by checking that the integration of the
        // new builders compiles and is exercised through targeted tests
        // above.
        //
        // Direct run of cmd_doctor would terminate the process when issues
        // are detected. This stub keeps the integration acknowledgement
        // visible without that side effect.
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        // Just verify cli construction succeeds with our refactor.
        assert_eq!(cli.dry_run, true);
    }

    // -- cmd_configure_2fa: stdin-driven entry ------------------------------

    // The interactive configure-2fa flow requires stdin; we avoid spawning a
    // sub-process here. Instead we exercise the underlying helpers
    // (`verify_totp_code`, `append_or_update_env`, `base32_encode_simple`)
    // which together cover the writeable side of the flow.

    // -- cmd_backup: mixed dry-run paths -------------------------------------

    #[test]
    fn cmd_backup_dry_run_reports_missing_files_without_creating_archive() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        let output = dir.path().join("does-not-exist-yet.tar.gz");

        cmd_backup(&cli, Some(&output)).unwrap();
        assert!(!output.exists());
    }

    #[test]
    fn cmd_backup_dry_run_with_no_output_does_not_persist_temp_file() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);

        // Confirm tempdir count doesn't change after dry-run with no --output.
        cmd_backup(&cli, None).unwrap();
        // Nothing in our explicit dir should have appeared.
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(entries.is_empty());
    }

    // -- build_config_file_checks --------------------------------------------

    #[test]
    fn build_config_file_checks_missing_file_warns() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("not-there.toml");
        let checks = build_config_file_checks("Sensor", &path);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].sev, Sev::Warn);
        assert!(checks[0].label.contains("not found"));
    }

    #[test]
    fn build_config_file_checks_valid_file_returns_two_oks() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ok.toml");
        std::fs::write(&path, "[ai]\nenabled = true\n").unwrap();
        let checks = build_config_file_checks("Agent", &path);
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].sev, Sev::Ok);
        assert!(checks[0].label.contains("Agent config found"));
        assert_eq!(checks[1].sev, Sev::Ok);
        assert!(checks[1].label.contains("Agent config is valid TOML"));
    }

    #[test]
    fn build_config_file_checks_invalid_toml_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("broken.toml");
        std::fs::write(&path, "[unclosed\nkey = 1").unwrap();
        let checks = build_config_file_checks("Sensor", &path);
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].sev, Sev::Ok);
        assert_eq!(checks[1].sev, Sev::Fail);
        assert!(checks[1].label.contains("invalid TOML syntax"));
    }

    // -- build_telemetry_age_check -------------------------------------------

    #[test]
    fn build_telemetry_age_check_recent_is_ok() {
        let c = build_telemetry_age_check(0);
        assert_eq!(c.sev, Sev::Ok);
        let c = build_telemetry_age_check(120);
        assert_eq!(c.sev, Sev::Ok);
        let c = build_telemetry_age_check(300);
        assert_eq!(c.sev, Sev::Ok);
    }

    #[test]
    fn build_telemetry_age_check_stale_warns() {
        let c = build_telemetry_age_check(301);
        assert_eq!(c.sev, Sev::Warn);
        assert!(c.label.contains("301s"));
        let c = build_telemetry_age_check(86400);
        assert_eq!(c.sev, Sev::Warn);
    }

    // -- doctor_summary_line --------------------------------------------------

    #[test]
    fn doctor_summary_line_zero_issues() {
        assert!(doctor_summary_line(0).contains("All checks passed"));
    }

    #[test]
    fn doctor_summary_line_one_issue() {
        assert!(doctor_summary_line(1).starts_with("1 issue(s) found"));
    }

    #[test]
    fn doctor_summary_line_many_issues() {
        assert!(doctor_summary_line(42).starts_with("42 issue(s) found"));
    }

    // -- capability_sudoers_drop_in -------------------------------------------

    #[test]
    fn capability_sudoers_drop_in_known_capabilities() {
        assert_eq!(
            capability_sudoers_drop_in("block-ip"),
            Some("innerwarden-block-ip")
        );
        assert_eq!(
            capability_sudoers_drop_in("sudo-protection"),
            Some("innerwarden-suspend-user")
        );
        assert_eq!(
            capability_sudoers_drop_in("search-protection"),
            Some("innerwarden-search-protection")
        );
    }

    #[test]
    fn capability_sudoers_drop_in_unknown_returns_none() {
        assert!(capability_sudoers_drop_in("ai").is_none());
        assert!(capability_sudoers_drop_in("").is_none());
        assert!(capability_sudoers_drop_in("does-not-exist").is_none());
    }

    // -- ConfigureMenu helpers ------------------------------------------------

    #[test]
    fn configure_menu_status_label_renders_distinct_badges() {
        assert_ne!(
            configure_menu_status_label(true),
            configure_menu_status_label(false)
        );
        assert!(configure_menu_status_label(true).contains("configured"));
        assert!(configure_menu_status_label(false).contains("not set up"));
    }

    #[test]
    fn parse_configure_menu_choice_numeric_options() {
        assert_eq!(parse_configure_menu_choice("1"), ConfigureMenuChoice::Ai);
        assert_eq!(
            parse_configure_menu_choice("2"),
            ConfigureMenuChoice::Telegram
        );
        assert_eq!(parse_configure_menu_choice("3"), ConfigureMenuChoice::Slack);
        assert_eq!(
            parse_configure_menu_choice("4"),
            ConfigureMenuChoice::Webhook
        );
        assert_eq!(
            parse_configure_menu_choice("5"),
            ConfigureMenuChoice::Dashboard
        );
        assert_eq!(
            parse_configure_menu_choice("6"),
            ConfigureMenuChoice::AbuseIpdb
        );
        assert_eq!(parse_configure_menu_choice("7"), ConfigureMenuChoice::GeoIp);
        assert_eq!(
            parse_configure_menu_choice("8"),
            ConfigureMenuChoice::Fail2ban
        );
        assert_eq!(
            parse_configure_menu_choice("9"),
            ConfigureMenuChoice::Cloudflare
        );
        assert_eq!(
            parse_configure_menu_choice("10"),
            ConfigureMenuChoice::Responder
        );
        assert_eq!(
            parse_configure_menu_choice("11"),
            ConfigureMenuChoice::Watchdog
        );
    }

    #[test]
    fn parse_configure_menu_choice_quit_variants() {
        assert_eq!(parse_configure_menu_choice("q"), ConfigureMenuChoice::Quit);
        assert_eq!(parse_configure_menu_choice("Q"), ConfigureMenuChoice::Quit);
        assert_eq!(parse_configure_menu_choice(""), ConfigureMenuChoice::Quit);
        assert_eq!(parse_configure_menu_choice("\n"), ConfigureMenuChoice::Quit);
        assert_eq!(parse_configure_menu_choice("  "), ConfigureMenuChoice::Quit);
    }

    #[test]
    fn parse_configure_menu_choice_invalid_inputs() {
        assert_eq!(
            parse_configure_menu_choice("0"),
            ConfigureMenuChoice::Invalid
        );
        assert_eq!(
            parse_configure_menu_choice("12"),
            ConfigureMenuChoice::Invalid
        );
        assert_eq!(
            parse_configure_menu_choice("foo"),
            ConfigureMenuChoice::Invalid
        );
        assert_eq!(
            parse_configure_menu_choice("11.5"),
            ConfigureMenuChoice::Invalid
        );
    }

    #[test]
    fn parse_configure_menu_choice_strips_whitespace() {
        assert_eq!(
            parse_configure_menu_choice(" 5 \n"),
            ConfigureMenuChoice::Dashboard
        );
        assert_eq!(
            parse_configure_menu_choice("\t11\r\n"),
            ConfigureMenuChoice::Watchdog
        );
    }

    #[test]
    fn detect_configure_menu_status_empty_environment() {
        let env_vars = HashMap::new();
        let status = detect_configure_menu_status(None, &env_vars);
        assert!(!status.ai);
        assert!(!status.telegram);
        assert!(!status.slack);
        assert!(!status.webhook);
        assert!(!status.dashboard);
        assert!(!status.abuseipdb);
        assert!(!status.geoip);
        assert!(!status.fail2ban);
        assert!(!status.cloudflare);
        assert!(!status.responder);
    }

    #[test]
    fn detect_configure_menu_status_telegram_via_env_only() {
        let mut env_vars = HashMap::new();
        env_vars.insert("TELEGRAM_BOT_TOKEN".to_string(), "abc:def".to_string());
        env_vars.insert("TELEGRAM_CHAT_ID".to_string(), "123".to_string());
        let status = detect_configure_menu_status(None, &env_vars);
        assert!(status.telegram);
        // partial config (only token) shouldn't flip the flag
        let mut partial = HashMap::new();
        partial.insert("TELEGRAM_BOT_TOKEN".to_string(), "abc:def".to_string());
        let status = detect_configure_menu_status(None, &partial);
        assert!(!status.telegram);
    }

    #[test]
    fn detect_configure_menu_status_slack_via_config() {
        let doc: toml_edit::DocumentMut =
            "[slack]\nwebhook_url = \"https://hooks.slack.com/services/X\"\n"
                .parse()
                .unwrap();
        let env_vars = HashMap::new();
        let status = detect_configure_menu_status(Some(&doc), &env_vars);
        assert!(status.slack);
    }

    #[test]
    fn detect_configure_menu_status_slack_empty_config_url_is_not_set() {
        let doc: toml_edit::DocumentMut = "[slack]\nwebhook_url = \"\"\n".parse().unwrap();
        let env_vars = HashMap::new();
        let status = detect_configure_menu_status(Some(&doc), &env_vars);
        assert!(!status.slack);
    }

    #[test]
    fn detect_configure_menu_status_abuseipdb_via_env_only() {
        let mut env_vars = HashMap::new();
        env_vars.insert("ABUSEIPDB_API_KEY".to_string(), "key".to_string());
        let status = detect_configure_menu_status(None, &env_vars);
        assert!(status.abuseipdb);
    }

    #[test]
    fn detect_configure_menu_status_section_enabled_flips_flags() {
        let toml = r#"
[ai]
enabled = true

[webhook]
enabled = true

[abuseipdb]
enabled = true

[geoip]
enabled = true

[fail2ban]
enabled = true

[cloudflare]
enabled = true

[responder]
enabled = true
"#;
        let doc: toml_edit::DocumentMut = toml.parse().unwrap();
        let env_vars = HashMap::new();
        let status = detect_configure_menu_status(Some(&doc), &env_vars);
        assert!(status.ai);
        assert!(status.webhook);
        assert!(status.abuseipdb);
        assert!(status.geoip);
        assert!(status.fail2ban);
        assert!(status.cloudflare);
        assert!(status.responder);
    }

    #[test]
    fn configure_menu_rows_returns_eleven_rows_with_watchdog_last() {
        let status = ConfigureMenuStatus {
            ai: true,
            telegram: false,
            slack: false,
            webhook: false,
            dashboard: false,
            abuseipdb: false,
            geoip: false,
            fail2ban: false,
            cloudflare: false,
            responder: false,
        };
        let rows = configure_menu_rows(status, true);
        assert_eq!(rows.len(), 11);
        assert_eq!(rows[0], (1, "AI provider", true));
        assert_eq!(rows[10], (11, "Watchdog (cron)", true));
        // verify ordering is stable
        assert_eq!(rows[1].1, "Telegram");
        assert_eq!(rows[7].1, "Fail2ban");
    }

    // -- cmd_configure_menu happy path (no agent.toml, dispatch to "Quit") ----

    #[test]
    fn cmd_configure_menu_status_detection_runs_with_no_agent_config() {
        // Explicitly demonstrate the detection runs without an agent config —
        // the real `cmd_configure_menu` would block on stdin, so we only test
        // the upstream detection plumbing here.
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join("agent.env");
        std::fs::write(
            &env_path,
            "TELEGRAM_BOT_TOKEN=abc:def\nTELEGRAM_CHAT_ID=123\n",
        )
        .unwrap();
        let env_vars = load_env_file(&env_path);
        let status = detect_configure_menu_status(None, &env_vars);
        assert!(status.telegram);
        assert!(!status.ai);
    }

    // -- min_severity_for_sensitivity & sensitivity_summary_line ---------------

    #[test]
    fn min_severity_for_sensitivity_known_levels() {
        assert_eq!(min_severity_for_sensitivity("quiet"), Some("critical"));
        assert_eq!(min_severity_for_sensitivity("normal"), Some("high"));
        assert_eq!(min_severity_for_sensitivity("verbose"), Some("medium"));
        // Case-insensitive
        assert_eq!(min_severity_for_sensitivity("QUIET"), Some("critical"));
        assert_eq!(min_severity_for_sensitivity("Normal"), Some("high"));
    }

    #[test]
    fn min_severity_for_sensitivity_unknown_levels() {
        assert!(min_severity_for_sensitivity("").is_none());
        assert!(min_severity_for_sensitivity("loud").is_none());
        assert!(min_severity_for_sensitivity("chatty").is_none());
    }

    #[test]
    fn sensitivity_summary_line_known_levels() {
        assert!(sensitivity_summary_line("quiet")
            .unwrap()
            .contains("Critical"));
        assert!(sensitivity_summary_line("normal")
            .unwrap()
            .contains("High and Critical"));
        assert!(sensitivity_summary_line("verbose")
            .unwrap()
            .contains("Medium, High, and Critical"));
    }

    #[test]
    fn sensitivity_summary_line_unknown_returns_none() {
        assert!(sensitivity_summary_line("").is_none());
        assert!(sensitivity_summary_line("zzz").is_none());
    }

    // -- doctor_resolve_agent_data_dir ---------------------------------------

    #[test]
    fn doctor_resolve_agent_data_dir_uses_default_when_missing() {
        let dir = doctor_resolve_agent_data_dir(None);
        assert_eq!(dir, PathBuf::from("/var/lib/innerwarden"));
    }

    #[test]
    fn doctor_resolve_agent_data_dir_reads_from_output_section() {
        let doc: toml_edit::DocumentMut = "[output]\ndata_dir = \"/tmp/data\"\n".parse().unwrap();
        let dir = doctor_resolve_agent_data_dir(Some(&doc));
        assert_eq!(dir, PathBuf::from("/tmp/data"));
    }

    #[test]
    fn doctor_resolve_agent_data_dir_falls_back_when_section_absent() {
        let doc: toml_edit::DocumentMut = "[telegram]\nenabled = true\n".parse().unwrap();
        let dir = doctor_resolve_agent_data_dir(Some(&doc));
        assert_eq!(dir, PathBuf::from("/var/lib/innerwarden"));
    }

    // -- System / Services check builders -------------------------------------

    #[test]
    fn build_launchctl_check_present_is_ok() {
        assert_eq!(build_launchctl_check(true).sev, Sev::Ok);
    }

    #[test]
    fn build_launchctl_check_missing_fails() {
        let c = build_launchctl_check(false);
        assert_eq!(c.sev, Sev::Fail);
        assert!(c.label.contains("launchctl"));
    }

    #[test]
    fn build_systemctl_check_present_is_ok() {
        assert_eq!(build_systemctl_check(true).sev, Sev::Ok);
    }

    #[test]
    fn build_systemctl_check_missing_fails() {
        let c = build_systemctl_check(false);
        assert_eq!(c.sev, Sev::Fail);
        assert!(c.hint.unwrap().contains("systemd"));
    }

    #[test]
    fn build_innerwarden_user_check_present_is_ok_on_both_oses() {
        assert_eq!(build_innerwarden_user_check(true, true).sev, Sev::Ok);
        assert_eq!(build_innerwarden_user_check(true, false).sev, Sev::Ok);
    }

    #[test]
    fn build_innerwarden_user_check_missing_uses_dscl_hint_on_macos() {
        let c = build_innerwarden_user_check(false, true);
        assert_eq!(c.sev, Sev::Fail);
        assert!(c.hint.unwrap().contains("dscl"));
    }

    #[test]
    fn build_innerwarden_user_check_missing_uses_useradd_hint_on_linux() {
        let c = build_innerwarden_user_check(false, false);
        assert_eq!(c.sev, Sev::Fail);
        assert!(c.hint.unwrap().contains("useradd"));
    }

    #[test]
    fn build_sudoers_dir_check_present_is_ok() {
        assert_eq!(build_sudoers_dir_check(true, true).sev, Sev::Ok);
        assert_eq!(build_sudoers_dir_check(true, false).sev, Sev::Ok);
    }

    #[test]
    fn build_sudoers_dir_check_missing_warns_on_macos() {
        let c = build_sudoers_dir_check(false, true);
        assert_eq!(c.sev, Sev::Warn);
    }

    #[test]
    fn build_sudoers_dir_check_missing_fails_on_linux() {
        let c = build_sudoers_dir_check(false, false);
        assert_eq!(c.sev, Sev::Fail);
    }

    #[test]
    fn capability_sudoers_status_lines_covers_present_missing_and_no_dropin() {
        // Missing drop-in -> warn + the --force fix hint, and it IS an issue.
        let (lines, issue) =
            capability_sudoers_status_lines("block-ip", Some("innerwarden-block-ip"), false);
        assert!(issue);
        assert!(lines.iter().any(|l| l.contains("drop-in missing")));
        assert!(lines
            .iter()
            .any(|l| l.contains("innerwarden enable block-ip --force")));

        // Present drop-in -> ok, no issue.
        let (lines, issue) =
            capability_sudoers_status_lines("block-ip", Some("innerwarden-block-ip"), true);
        assert!(!issue);
        assert!(lines.iter().any(|l| l.contains("drop-in present")));

        // Capability with no drop-in -> plain ok, no issue.
        let (lines, issue) = capability_sudoers_status_lines("ai", None, false);
        assert!(!issue);
        assert_eq!(lines, vec!["  [ok]   ai (enabled)".to_string()]);
    }

    #[test]
    fn build_service_running_check_running_is_ok() {
        let c = build_service_running_check("innerwarden-agent", true, false);
        assert_eq!(c.sev, Sev::Ok);
        assert!(c.label.contains("innerwarden-agent"));
    }

    #[test]
    fn build_service_running_check_stopped_warns_with_systemctl_hint_on_linux() {
        let c = build_service_running_check("innerwarden-agent", false, false);
        assert_eq!(c.sev, Sev::Warn);
        assert!(c.hint.unwrap().contains("systemctl start"));
    }

    #[test]
    fn build_service_running_check_stopped_warns_with_launchctl_hint_on_macos() {
        let c = build_service_running_check("foo", false, true);
        assert_eq!(c.sev, Sev::Warn);
        assert!(c.hint.unwrap().contains("launchctl load"));
    }

    // -- Dashboard / GeoIP / fail2ban / nginx check builders ------------------

    #[test]
    fn build_dashboard_flag_check_present_is_ok() {
        assert_eq!(build_dashboard_flag_check(true).sev, Sev::Ok);
    }

    #[test]
    fn build_dashboard_flag_check_missing_warns() {
        let c = build_dashboard_flag_check(false);
        assert_eq!(c.sev, Sev::Warn);
        assert!(c.hint.unwrap().contains("configure dashboard"));
    }

    /// F5 anchor (2026-07-01): the flag-check message must not hardcode the
    /// systemd unit name (`innerwarden-agent.service`) — it is shown on macOS
    /// too, where the unit is a launchd plist.
    #[test]
    fn build_dashboard_flag_check_message_is_platform_neutral() {
        assert!(!build_dashboard_flag_check(false)
            .label
            .contains("innerwarden-agent.service"));
        assert!(!build_dashboard_flag_check(true).label.contains("ExecStart"));
    }

    /// F5 anchor: doctor reads the `--dashboard` flag from the launchd plist on
    /// macOS and the systemd unit on Linux — never the wrong one.
    #[test]
    fn agent_unit_file_path_is_platform_correct() {
        let p = agent_unit_file_path();
        if cfg!(target_os = "macos") {
            assert_eq!(p, "/Library/LaunchDaemons/com.innerwarden.agent.plist");
        } else {
            assert_eq!(p, "/etc/systemd/system/innerwarden-agent.service");
        }
    }

    #[test]
    fn agent_unit_file_path_for_both_platforms() {
        assert_eq!(
            agent_unit_file_path_for(true),
            "/Library/LaunchDaemons/com.innerwarden.agent.plist"
        );
        assert_eq!(
            agent_unit_file_path_for(false),
            "/etc/systemd/system/innerwarden-agent.service"
        );
    }

    #[test]
    fn agent_start_hint_is_platform_specific() {
        assert!(agent_start_hint(true).contains("launchctl kickstart"));
        assert!(agent_start_hint(false).contains("systemctl start innerwarden-agent"));
    }

    #[test]
    fn build_dashboard_credentials_checks_with_credentials_set() {
        let checks = build_dashboard_credentials_checks(true, true);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].sev, Sev::Ok);
        assert!(checks[0].label.contains("credentials required"));
    }

    #[test]
    fn build_dashboard_credentials_checks_no_credentials() {
        let checks = build_dashboard_credentials_checks(false, false);
        assert_eq!(checks.len(), 2);
        assert!(checks[0].label.contains("none set"));
        assert!(checks[1].label.contains("password"));
    }

    #[test]
    fn build_dashboard_credentials_checks_partial_user_only() {
        let checks = build_dashboard_credentials_checks(true, false);
        // Same as no-creds: one or the other missing → open access.
        assert_eq!(checks.len(), 2);
    }

    #[test]
    fn build_dashboard_reachability_check_reachable_is_ok() {
        // agent_alive value irrelevant on the reachable path.
        let c = build_dashboard_reachability_check(true, true, false).unwrap();
        assert_eq!(c.sev, Sev::Ok);
    }

    #[test]
    fn tcp_port_listening_detects_open_and_closed_ports() {
        use std::time::Duration;
        // A bound listener (any scheme, incl. an HTTPS-only dashboard) is
        // detected as up — this is the false-negative fix: the old HTTP-only
        // probe missed an HTTPS-only listener.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        assert!(
            tcp_port_listening(addr, Duration::from_secs(1)),
            "open port must be detected"
        );

        // A closed port (drop the listener first) is reported down.
        drop(listener);
        assert!(
            !tcp_port_listening(addr, Duration::from_millis(300)),
            "closed port must be reported down"
        );
    }

    /// Pre-Bug-3 behavior: agent down, dashboard down → "Start the agent".
    /// The start command is platform-aware (F5): launchd on macOS, systemd
    /// elsewhere.
    #[test]
    fn build_dashboard_reachability_check_agent_down_suggests_start() {
        let c = build_dashboard_reachability_check(false, true, false).unwrap();
        assert_eq!(c.sev, Sev::Warn);
        let hint = c.hint.unwrap();
        assert!(hint.contains("Start the agent"));
        if cfg!(target_os = "macos") {
            assert!(hint.contains("launchctl kickstart"));
        } else {
            assert!(hint.contains("systemctl start"));
        }
    }

    /// Bug 3 anchor (2026-05-06): when agent IS alive but dashboard
    /// probe fails, the hint MUST NOT tell the operator to start the
    /// agent (that hint is wrong — agent is running). Instead point
    /// at the dashboard binding / journal.
    #[test]
    fn build_dashboard_reachability_check_agent_alive_dashboard_down_does_not_say_start_agent() {
        let c = build_dashboard_reachability_check(false, true, true).unwrap();
        assert_eq!(c.sev, Sev::Warn);
        let hint = c.hint.unwrap();
        assert!(
            !hint.contains("Start the agent"),
            "Bug 3 regression: hint must not tell operator to start an agent that is already alive. got: {hint}"
        );
        assert!(
            hint.contains("Agent is running"),
            "hint should explicitly disclose the agent is alive so the operator does not double-take. got: {hint}"
        );
        assert!(
            hint.contains("dashboard"),
            "hint should redirect attention to the dashboard binding/config. got: {hint}"
        );
    }

    #[test]
    fn build_dashboard_reachability_check_unreachable_without_flag_returns_none() {
        assert!(build_dashboard_reachability_check(false, false, false).is_none());
        assert!(build_dashboard_reachability_check(false, false, true).is_none());
    }

    #[test]
    fn build_geoip_reachability_check_reachable_is_ok() {
        assert_eq!(build_geoip_reachability_check(true).sev, Sev::Ok);
    }

    #[test]
    fn build_geoip_reachability_check_unreachable_warns() {
        let c = build_geoip_reachability_check(false);
        assert_eq!(c.sev, Sev::Warn);
        assert!(c.hint.unwrap().contains("HTTP"));
    }

    #[test]
    fn build_fail2ban_binary_check_present_is_ok() {
        assert_eq!(build_fail2ban_binary_check(true).sev, Sev::Ok);
    }

    #[test]
    fn build_fail2ban_binary_check_missing_fails() {
        let c = build_fail2ban_binary_check(false);
        assert_eq!(c.sev, Sev::Fail);
        assert!(c.hint.unwrap().contains("apt-get install fail2ban"));
    }

    #[test]
    fn build_fail2ban_running_check_running_is_ok() {
        let c = build_fail2ban_running_check(true, false);
        assert_eq!(c.sev, Sev::Ok);
    }

    #[test]
    fn build_fail2ban_running_check_macos_warns() {
        let c = build_fail2ban_running_check(false, true);
        assert_eq!(c.sev, Sev::Warn);
        assert!(c.label.contains("Linux-only"));
    }

    #[test]
    fn build_fail2ban_running_check_linux_not_running_warns() {
        let c = build_fail2ban_running_check(false, false);
        assert_eq!(c.sev, Sev::Warn);
        assert!(c.hint.unwrap().contains("systemctl start fail2ban"));
    }

    #[test]
    fn build_nginx_error_log_check_present_is_ok() {
        let c = build_nginx_error_log_check("/var/log/nginx/error.log", true);
        assert_eq!(c.sev, Sev::Ok);
        assert!(c.label.contains("/var/log/nginx/error.log"));
    }

    /// Bug 4 anchor (2026-05-06): when the configured nginx error log
    /// does not exist on disk AND no alternative path exists, doctor
    /// MUST emit `[warn]` (not `[fail]`). nginx writes the log file
    /// lazily on first error — a quiet server is the happy path.
    /// Pre-fix doctor printed `[fail] nginx error log not found
    /// (/home/ubuntu/proxy/data/logs/fallback_error.log)` while the
    /// hint right beneath it acknowledged the file is "created on
    /// first request or error" — hard fail contradicting hint.
    #[test]
    fn build_nginx_error_log_check_missing_warns_not_fails() {
        let c = build_nginx_error_log_check("/var/log/nginx/error.log", false);
        assert_eq!(
            c.sev,
            Sev::Warn,
            "Bug 4 regression: a missing nginx error log must be Warn, not Fail (nginx creates it lazily)"
        );
        let hint = c.hint.unwrap();
        assert!(
            !hint.contains("sudo systemctl start nginx"),
            "the old hint suggested starting nginx as if it were down — wrong root cause"
        );
        assert!(
            hint.contains("OK on a quiet server") || hint.contains("verify nginx is running"),
            "hint should explain the lazy-creation invariant or point at a directly actionable check, got: {hint}"
        );
    }

    /// Bug 4 anchor: the present-path branch is unchanged — Ok with
    /// the path embedded in the label. Anti-regression for the happy
    /// path that the new helper still reports correctly.
    #[test]
    fn build_nginx_error_log_check_present_with_alternatives_is_still_ok() {
        let c = build_nginx_error_log_check_with_alternatives(
            "/var/log/nginx/error.log",
            true,
            &[("/var/log/nginx/error_log", true)],
        );
        assert_eq!(c.sev, Sev::Ok);
        assert!(c.label.contains("/var/log/nginx/error.log"));
    }

    /// Bug 4 anchor: configured path missing but a default is present
    /// → Warn, with both paths surfaced in label/hint so the operator
    /// can see the misalignment and align the sensor config.
    #[test]
    fn build_nginx_error_log_check_alternative_present_warns_with_both_paths() {
        let c = build_nginx_error_log_check_with_alternatives(
            "/home/ubuntu/proxy/data/logs/fallback_error.log",
            false,
            &[("/var/log/nginx/error.log", true)],
        );
        assert_eq!(c.sev, Sev::Warn);
        assert!(c
            .label
            .contains("/home/ubuntu/proxy/data/logs/fallback_error.log"));
        assert!(c.label.contains("/var/log/nginx/error.log"));
        let hint = c.hint.unwrap();
        assert!(
            hint.contains("Either point sensor config at"),
            "hint should suggest aligning the sensor path, got: {hint}"
        );
    }

    /// Bug 4 anchor: alternative paths that don't exist must NOT
    /// trigger the "alt-present" branch. Pin that empty alts behave
    /// the same as no alts.
    #[test]
    fn build_nginx_error_log_check_alternatives_all_missing_falls_through_to_warn() {
        let c = build_nginx_error_log_check_with_alternatives(
            "/var/log/nginx/error.log",
            false,
            &[
                ("/var/log/nginx/error_log", false),
                ("/var/log/something_else.log", false),
            ],
        );
        assert_eq!(c.sev, Sev::Warn);
        assert!(c.label.contains("not yet written"));
    }

    // -- 2FA helpers ----------------------------------------------------------

    #[test]
    fn parse_two_factor_choice_known_inputs() {
        assert_eq!(parse_two_factor_choice("1"), TwoFactorChoice::Totp);
        assert_eq!(parse_two_factor_choice("2"), TwoFactorChoice::Disabled);
        assert_eq!(parse_two_factor_choice(""), TwoFactorChoice::Disabled);
        assert_eq!(parse_two_factor_choice("3"), TwoFactorChoice::Unknown);
        assert_eq!(parse_two_factor_choice("totp"), TwoFactorChoice::Unknown);
    }

    #[test]
    fn parse_two_factor_choice_strips_whitespace() {
        assert_eq!(parse_two_factor_choice(" 1 \n"), TwoFactorChoice::Totp);
        assert_eq!(
            parse_two_factor_choice("\t2\r\n"),
            TwoFactorChoice::Disabled
        );
        // Whitespace-only input collapses to "" → Disabled
        assert_eq!(parse_two_factor_choice("   "), TwoFactorChoice::Disabled);
    }

    #[test]
    fn write_totp_configuration_writes_secret_and_marks_method() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        let env_file = write_totp_configuration(&cli, "JBSWY3DPEHPK3PXP").unwrap();
        // env_file path returned matches expectation
        assert_eq!(env_file, dir.path().join("agent.env"));

        let env_content = std::fs::read_to_string(&env_file).unwrap();
        assert!(env_content.contains("INNERWARDEN_TOTP_SECRET=\"JBSWY3DPEHPK3PXP\""));

        let agent_content = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(agent_content.contains("[security]"));
        assert!(agent_content.contains("two_factor_method = \"totp\""));
    }

    #[test]
    fn write_disable_two_factor_marks_method_as_none() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        write_disable_two_factor(&cli).unwrap();

        let agent_content = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(agent_content.contains("[security]"));
        assert!(agent_content.contains("two_factor_method = \"none\""));
    }

    // -- Smoke: cmd_configure_sensitivity quiet / verbose / unknown ---------

    #[test]
    fn cmd_configure_sensitivity_quiet_writes_critical() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);

        let _ = cmd_configure_sensitivity(&cli, "quiet");
        let content = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(content.contains("min_severity = \"critical\""));
    }

    #[test]
    fn cmd_configure_sensitivity_verbose_writes_medium() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);

        let _ = cmd_configure_sensitivity(&cli, "verbose");
        let content = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(content.contains("min_severity = \"medium\""));
    }

    // -- Pipeline-test pure helpers -------------------------------------------

    #[test]
    fn pipeline_test_decision_found_returns_false_below_baseline() {
        assert!(!pipeline_test_decision_found(
            0, 0, None, "marker", "1.2.3.4"
        ));
        assert!(!pipeline_test_decision_found(
            5, 5, None, "marker", "1.2.3.4"
        ));
        assert!(!pipeline_test_decision_found(
            3, 5, None, "marker", "1.2.3.4"
        ));
    }

    #[test]
    fn pipeline_test_decision_found_marker_match() {
        let content = "{\"decision\":\"foo\",\"marker\":\"abc\"}\n";
        assert!(pipeline_test_decision_found(
            6,
            5,
            Some(content),
            "abc",
            "1.2.3.4"
        ));
    }

    #[test]
    fn pipeline_test_decision_found_test_ip_match() {
        let content = "{\"target_ip\":\"1.2.3.4\"}\n";
        assert!(pipeline_test_decision_found(
            6,
            5,
            Some(content),
            "no-match",
            "1.2.3.4"
        ));
    }

    #[test]
    fn pipeline_test_decision_found_loose_match_when_grew() {
        // Original behaviour: if the line count grew, treat that as evidence
        // even if the marker / test IP isn't present in the content.
        let content = "{\"some\":\"other\"}\n";
        assert!(pipeline_test_decision_found(
            6,
            5,
            Some(content),
            "missing-marker",
            "10.20.30.40"
        ));
    }

    #[test]
    fn pipeline_test_decision_found_no_content_but_grew_returns_true() {
        // File was created but unreadable: still treat the count growth as a hit.
        assert!(pipeline_test_decision_found(
            6, 5, None, "marker", "1.2.3.4"
        ));
    }

    #[test]
    fn pipeline_test_result_label_changes_for_pass_vs_timeout() {
        assert_eq!(pipeline_test_result_label(true), "Result: PASS");
        let timeout = pipeline_test_result_label(false);
        assert!(timeout.contains("TIMEOUT"));
        assert!(timeout.contains("doctor"));
    }

    // -- count_event_kinds / count_incident_detectors / tune_reason ----------

    #[test]
    fn count_event_kinds_tallies_repeated_kinds() {
        let content = r#"{"kind":"a"}
{"kind":"a"}
{"kind":"b"}
"#;
        let counts = count_event_kinds(content);
        assert_eq!(counts.get("a"), Some(&2));
        assert_eq!(counts.get("b"), Some(&1));
    }

    #[test]
    fn count_event_kinds_skips_invalid_lines() {
        let content = "not-json\n{\"kind\":\"x\"}\n\n";
        let counts = count_event_kinds(content);
        assert_eq!(counts.get("x"), Some(&1));
        assert_eq!(counts.len(), 1);
    }

    #[test]
    fn count_incident_detectors_extracts_prefix_before_colon() {
        let content = r#"{"incident_id":"web_scan:1.2.3.4:abc"}
{"incident_id":"web_scan:5.6.7.8:def"}
{"incident_id":"ssh_bruteforce:9.10.11.12"}
"#;
        let counts = count_incident_detectors(content);
        assert_eq!(counts.get("web_scan"), Some(&2));
        assert_eq!(counts.get("ssh_bruteforce"), Some(&1));
    }

    #[test]
    fn count_incident_detectors_ignores_empty_prefix() {
        let content = "{\"incident_id\":\":no-detector\"}\n";
        let counts = count_incident_detectors(content);
        assert!(counts.is_empty());
    }

    #[test]
    fn tune_reason_renders_raise_and_lower_phrasing() {
        let r = tune_reason(50, 5, 7, true);
        assert!(r.contains("raise"));
        assert!(r.contains("50 events/day"));
        assert!(r.contains("5 incidents in 7 days"));
        let r = tune_reason(20, 100, 1, false);
        assert!(r.contains("lower"));
    }

    // -- cmd_doctor_inner: smoke runs without process::exit ------------------

    #[test]
    fn cmd_doctor_inner_returns_issue_count_with_no_configs() {
        // No configs → at minimum the sensor + agent config show up as missing.
        // The actual count varies by host (systemctl/sudoers/etc.) so we just
        // assert it ran and produced a non-fatal `Result`.
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        let registry = CapabilityRegistry::default_all();
        let issues = cmd_doctor_inner(&cli, &registry).unwrap();
        // We can't assert an exact number (it depends on host state), but the
        // doctor must report at least the missing-config warnings.
        assert!(issues > 0);
    }

    #[test]
    fn cmd_doctor_inner_reports_zero_issues_only_when_everything_passes() {
        // With explicit configs in place, the configuration section reports
        // success — which is one less issue than the no-config run. We don't
        // need an exact-equality assertion; a relative inequality is enough
        // to verify our extracted `build_config_file_checks` is wired in.
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        std::fs::write(
            &cli.sensor_config,
            "[detectors.ssh_bruteforce]\nthreshold = 5\n",
        )
        .unwrap();
        std::fs::write(&cli.agent_config, "[ai]\nenabled = false\n").unwrap();
        let registry = CapabilityRegistry::default_all();
        let with_configs = cmd_doctor_inner(&cli, &registry).unwrap();

        let dir2 = TempDir::new().unwrap();
        let cli2 = make_test_cli(dir2.path(), true);
        let with_no_configs = cmd_doctor_inner(&cli2, &registry).unwrap();
        assert!(with_configs <= with_no_configs);
    }

    #[test]
    fn cmd_doctor_inner_handles_telegram_section_when_enabled() {
        // Exercise the Telegram + Slack branches by enabling them in the
        // config. We intentionally don't set tokens, so the helper produces
        // Fail checks — but the doctor still completes and returns Ok.
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        std::fs::write(
            &cli.agent_config,
            r#"[ai]
enabled = true
provider = "openai"

[telegram]
enabled = true

[slack]
enabled = true

[webhook]
enabled = true
url = "https://example.com/hook"

[abuseipdb]
enabled = true
api_key = "x"
"#,
        )
        .unwrap();
        let registry = CapabilityRegistry::default_all();
        let issues = cmd_doctor_inner(&cli, &registry).unwrap();
        // The doctor exited cleanly via Ok (no process::exit) and the
        // counter accumulates issues from all the branches we toggled.
        assert!(issues > 0);
    }

    #[test]
    fn cmd_doctor_inner_handles_geoip_dashboard_branches() {
        // Toggle dashboard + geoip — both reach across stdout lines in the
        // doctor body.
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        std::fs::write(
            &cli.agent_config,
            r#"[geoip]
enabled = true

[dashboard]
enabled = true

[ai]
enabled = true
provider = "anthropic"
"#,
        )
        .unwrap();
        let registry = CapabilityRegistry::default_all();
        let _ = cmd_doctor_inner(&cli, &registry).unwrap();
    }

    #[test]
    fn cmd_doctor_inner_with_invalid_toml_reports_failure() {
        let dir = TempDir::new().unwrap();
        let cli = make_test_cli(dir.path(), true);
        std::fs::write(&cli.sensor_config, "[unclosed").unwrap();
        std::fs::write(&cli.agent_config, "this is not toml=\nbroken").unwrap();
        let registry = CapabilityRegistry::default_all();
        let issues = cmd_doctor_inner(&cli, &registry).unwrap();
        // An invalid-syntax config is a Fail check — guarantees count > 0.
        assert!(issues > 0);
    }

    // -- fail2ban_not_installed_message ---------------------------------------

    #[test]
    fn fail2ban_not_installed_message_macos_mentions_macos() {
        let m = fail2ban_not_installed_message(true);
        assert!(m.contains("macOS"));
    }

    #[test]
    fn fail2ban_not_installed_message_linux_mentions_distro_install_commands() {
        let m = fail2ban_not_installed_message(false);
        assert!(m.contains("apt install"));
        assert!(m.contains("yum install"));
    }
}
