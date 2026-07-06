//! Notification channel + delivery config sections (telegram, slack, webhook, web-push, narrative, briefing, pipeline).
//!
//! Spec 068 relocation: moved verbatim out of the former monolithic
//! `config.rs`. No logic change; serde defaults + helpers stay in
//! `config/mod.rs` and resolve through `use super::*`.

use super::*;

// ---------------------------------------------------------------------------
// Narrative
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NarrativeConfig {
    /// Generate daily Markdown summaries (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Number of daily summaries to keep before removing older ones
    #[serde(default = "default_keep_days")]
    pub keep_days: usize,
}

impl Default for NarrativeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            keep_days: default_keep_days(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
// enabled/telegram consumed by briefing scheduler wiring in main.rs; kept accessible for inspection
#[serde(deny_unknown_fields)]
pub struct BriefingConfig {
    /// Enable daily AI intelligence briefing (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hour to auto-generate briefing (0-23, local time). Default: 8
    #[serde(default = "default_briefing_hour")]
    pub hour: u8,
    /// Minute within the hour. Default: 0
    #[serde(default)]
    pub minute: u8,
    /// Also send briefing via Telegram (default: true)
    #[serde(default = "default_true")]
    pub telegram: bool,
}

impl Default for BriefingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hour: 8,
            minute: 0,
            telegram: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Webhook
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    /// Enable webhook notifications
    #[serde(default)]
    pub enabled: bool,

    /// HTTP endpoint to POST incident payloads to
    #[serde(default)]
    pub url: String,

    /// Minimum severity to notify (default: "medium")
    /// Accepted values: "debug", "info", "low", "medium", "high", "critical"
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    /// Request timeout in seconds (default: 10)
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Payload format: "default", "pagerduty", "opsgenie" (default: "default")
    /// PagerDuty: set url to https://events.pagerduty.com/v2/enqueue?routing_key=YOUR_KEY
    /// Opsgenie: set url to https://api.opsgenie.com/v2/alerts with GenieKey header in url
    #[serde(default = "default_webhook_format")]
    pub format: String,

    /// Notification pipeline filter and digest settings.
    #[serde(default)]
    pub channel_notifications: ChannelNotificationConfig,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            min_severity: default_min_severity(),
            timeout_secs: default_timeout_secs(),
            format: default_webhook_format(),
            channel_notifications: ChannelNotificationConfig::default(),
        }
    }
}

impl WebhookConfig {
    /// Parse min_severity string into a Severity, defaulting to Medium on error.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                tracing::warn!(
                    min_severity = other,
                    "unrecognised min_severity - defaulting to 'medium'"
                );
                Severity::Medium
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Telegram
// ---------------------------------------------------------------------------

/// Configuration for the Telegram conversational bot interface.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TelegramBotConfig {
    /// Enable the conversational bot interface (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Personality prompt prepended to all bot AI interactions.
    #[serde(default = "default_bot_personality")]
    pub personality: String,
}

impl Default for TelegramBotConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            personality: default_bot_personality(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    /// Enable Telegram notifications (T.1) and approval bot (T.2)
    #[serde(default)]
    pub enabled: bool,

    /// Telegram bot token. Prefer env var TELEGRAM_BOT_TOKEN.
    #[serde(default)]
    pub bot_token: String,

    /// Telegram chat ID to send messages to. Prefer env var TELEGRAM_CHAT_ID.
    #[serde(default)]
    pub chat_id: String,

    /// Minimum severity to send T.1 notifications (default: "high").
    /// Accepted values: "debug", "info", "low", "medium", "high", "critical"
    #[serde(default = "default_telegram_min_severity")]
    pub min_severity: String,

    /// Optional base URL for dashboard deep-links in notification messages.
    /// Example: "http://your-server:8787"
    #[serde(default)]
    pub dashboard_url: String,

    /// TTL in seconds for pending T.2 operator approval requests (default: 600 = 10 min).
    /// Unanswered requests are discarded as "ignore" when they expire.
    #[serde(default = "default_telegram_approval_ttl_secs")]
    pub approval_ttl_secs: u64,

    /// Send the daily Markdown summary via Telegram at this local hour (0–23).
    /// Set e.g. `daily_summary_hour = 8` for an 8:00 AM digest.
    /// Omit or comment out to disable.
    #[serde(default)]
    pub daily_summary_hour: Option<u8>,

    /// Maximum Telegram notifications per day (default: 10).
    /// Only immediate threats count against the budget. Critical severity
    /// always breaks the budget. Everything else goes to the daily digest.
    #[allow(dead_code)]
    #[serde(default = "default_telegram_daily_budget")]
    pub daily_budget: u32,

    /// Dev mode: adds a "Check FP" button to every notification.
    /// When pressed, logs the incident to a false-positive review file
    /// for later analysis. Useful for tuning detectors.
    #[serde(default)]
    pub dev_mode: bool,

    /// User profile: "simple" or "technical". Controls alert language and detail level.
    /// Simple: plain language, no IPs, no detector names. For non-technical users.
    /// Technical: full details, IPs, severity codes, evidence. For sysadmins.
    #[serde(default = "default_user_profile")]
    pub user_profile: String,

    /// Conversational bot configuration.
    #[serde(default)]
    pub bot: TelegramBotConfig,

    /// Notification pipeline filter and digest settings.
    #[serde(default)]
    pub channel_notifications: ChannelNotificationConfig,
}

impl TelegramConfig {
    /// Validate Telegram configuration. Call after loading config.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.enabled {
            if self.resolved_bot_token().is_empty() {
                anyhow::bail!("telegram.enabled=true but bot_token is not configured");
            }
            if self.resolved_chat_id().is_empty() {
                anyhow::bail!("telegram.enabled=true but chat_id is not configured");
            }
        }
        if let Some(h) = self.daily_summary_hour {
            if h > 23 {
                anyhow::bail!("telegram.daily_summary_hour must be 0-23, got {h}");
            }
        }
        Ok(())
    }

    /// Resolve bot_token: config field takes precedence, then env var TELEGRAM_BOT_TOKEN.
    pub fn resolved_bot_token(&self) -> String {
        if !self.bot_token.is_empty() {
            return self.bot_token.clone();
        }
        std::env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default()
    }

    /// Resolve chat_id: config field takes precedence, then env var TELEGRAM_CHAT_ID.
    pub fn resolved_chat_id(&self) -> String {
        if !self.chat_id.is_empty() {
            return self.chat_id.clone();
        }
        std::env::var("TELEGRAM_CHAT_ID").unwrap_or_default()
    }

    /// Parse min_severity string into a Severity, defaulting to High on error.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                tracing::warn!(
                    min_severity = other,
                    "unrecognised telegram min_severity - defaulting to 'high'"
                );
                Severity::High
            }
        }
    }

    /// Returns true if the user profile is "simple" (non-technical).
    pub fn is_simple_profile(&self) -> bool {
        self.user_profile.eq_ignore_ascii_case("simple")
    }
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            chat_id: String::new(),
            min_severity: default_telegram_min_severity(),
            dashboard_url: String::new(),
            approval_ttl_secs: default_telegram_approval_ttl_secs(),
            daily_summary_hour: None,
            daily_budget: default_telegram_daily_budget(),
            dev_mode: false,
            user_profile: default_user_profile(),
            bot: TelegramBotConfig::default(),
            channel_notifications: ChannelNotificationConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Slack
// ---------------------------------------------------------------------------

/// Configuration for Slack Incoming Webhook notifications.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlackConfig {
    /// Enable Slack notifications (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// Slack Incoming Webhook URL.
    /// Example: "https://hooks.slack.com/services/T.../B.../..."
    /// Prefer env var SLACK_WEBHOOK_URL.
    #[serde(default)]
    pub webhook_url: String,

    /// Minimum severity to notify (default: "high").
    /// Accepted values: "debug", "info", "low", "medium", "high", "critical"
    #[serde(default = "default_slack_min_severity")]
    pub min_severity: String,

    /// Optional base URL for dashboard deep-links in messages.
    /// Example: "http://your-server:8787"
    #[serde(default)]
    pub dashboard_url: String,

    /// Notification pipeline filter and digest settings.
    #[serde(default)]
    pub channel_notifications: ChannelNotificationConfig,
}

impl SlackConfig {
    /// Resolve webhook_url: config field takes precedence, then env var SLACK_WEBHOOK_URL.
    pub fn resolved_webhook_url(&self) -> String {
        if !self.webhook_url.is_empty() {
            return self.webhook_url.clone();
        }
        std::env::var("SLACK_WEBHOOK_URL").unwrap_or_default()
    }

    /// Parse min_severity string into a Severity, defaulting to High on error.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                tracing::warn!(
                    min_severity = other,
                    "unrecognised slack min_severity - defaulting to 'high'"
                );
                Severity::High
            }
        }
    }
}

impl Default for SlackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: String::new(),
            min_severity: default_slack_min_severity(),
            dashboard_url: String::new(),
            channel_notifications: ChannelNotificationConfig::default(),
        }
    }
}

/// Configuration for Discord Incoming Webhook notifications (spec 078 P3).
///
/// Mirrors [`SlackConfig`]: a new operator-facing chat channel plugs in here +
/// in `notification_channels::collect_chat_channels` + `loops::boot`, with no
/// dispatch-site edits.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscordConfig {
    /// Enable Discord notifications (default: false)
    #[serde(default)]
    pub enabled: bool,

    /// Discord Incoming Webhook URL.
    /// Example: "https://discord.com/api/webhooks/<id>/<token>"
    /// Prefer env var DISCORD_WEBHOOK_URL.
    #[serde(default)]
    pub webhook_url: String,

    /// Minimum severity to notify (default: "high").
    #[serde(default = "default_discord_min_severity")]
    pub min_severity: String,

    /// Optional base URL for dashboard deep-links in messages.
    #[serde(default)]
    pub dashboard_url: String,

    /// Notification pipeline filter and digest settings.
    #[serde(default)]
    pub channel_notifications: ChannelNotificationConfig,
}

fn default_discord_min_severity() -> String {
    "high".to_string()
}

impl DiscordConfig {
    /// Resolve webhook_url: config field takes precedence, then env var DISCORD_WEBHOOK_URL.
    pub fn resolved_webhook_url(&self) -> String {
        if !self.webhook_url.is_empty() {
            return self.webhook_url.clone();
        }
        std::env::var("DISCORD_WEBHOOK_URL").unwrap_or_default()
    }

    /// Parse min_severity string into a Severity, defaulting to High on error.
    pub fn parsed_min_severity(&self) -> Severity {
        match self.min_severity.to_lowercase().as_str() {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                tracing::warn!(
                    min_severity = other,
                    "unrecognised discord min_severity - defaulting to 'high'"
                );
                Severity::High
            }
        }
    }
}

impl Default for DiscordConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: String::new(),
            min_severity: default_discord_min_severity(),
            dashboard_url: String::new(),
            channel_notifications: ChannelNotificationConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Web Push
// ---------------------------------------------------------------------------

/// Browser Web Push notification configuration (RFC 8291 / VAPID RFC 8292).
///
/// Generate keys with: `innerwarden notify web-push setup`
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WebPushConfig {
    /// Enable browser push notifications for High/Critical incidents.
    #[serde(default)]
    pub enabled: bool,

    /// VAPID subject - must be "mailto:..." or "https://..." for push service contact.
    #[serde(default = "default_vapid_subject")]
    pub vapid_subject: String,

    /// VAPID private key in PKCS#8 PEM format.
    /// Set via agent.env: INNERWARDEN_VAPID_PRIVATE_KEY=<pem>
    #[serde(default)]
    pub vapid_private_key: String,

    /// VAPID public key - base64url-encoded uncompressed P-256 point (65 bytes → 87 chars).
    /// This value is served to browsers at GET /api/push/vapid-key.
    #[serde(default)]
    pub vapid_public_key: String,

    /// Minimum severity for push notification: "high" or "critical" (default: "high")
    #[serde(default = "default_web_push_min_severity")]
    pub min_severity: String,

    /// Notification pipeline filter and digest settings.
    #[serde(default)]
    pub channel_notifications: ChannelNotificationConfig,
}

impl Default for WebPushConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            vapid_subject: default_vapid_subject(),
            vapid_private_key: String::new(),
            vapid_public_key: String::new(),
            min_severity: default_web_push_min_severity(),
            channel_notifications: ChannelNotificationConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Notification Pipeline (Feature 005)
// ---------------------------------------------------------------------------

/// Notification filter level for a channel.
/// Controls which incident groups are forwarded to this channel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelFilterLevel {
    /// Every incident group (first event + summaries).
    #[default]
    All,
    /// Only groups that need human decision (not auto-resolved, ambiguous, or
    /// above confidence threshold).
    Actionable,
    /// Only HIGH/CRITICAL that are not auto-resolved.
    Critical,
    /// Silent — only digest (if configured).
    None,
}

/// Digest frequency for a notification channel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestFrequency {
    Daily,
    Hourly,
    #[default]
    None,
}

/// Top-level notification pipeline config.
///
/// ```toml
/// [notifications]
/// group_window_secs = 14400
/// group_count_threshold = 10
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationPipelineConfig {
    /// Grouping window in seconds. Incidents from the same detector+entity
    /// within this window are grouped into a single notification.
    ///
    /// Default bumped 3600 → 14400 (1 h → 4 h) on 2026-05-24 after the
    /// operator observed the same IP firing 4 identical
    /// "Critical — Threat Detected" alerts across a 12-hour span. The
    /// previous 1 h window expired between attack bursts of the same
    /// IP+detector pair and re-fired immediate notifications each
    /// time. 4 h covers the typical scanner re-engagement cadence
    /// without losing genuinely-new alerts when an attack returns the
    /// next morning.
    #[serde(default = "default_group_window_secs")]
    pub group_window_secs: u64,

    /// Emit an early group summary when this many incidents accumulate,
    /// without waiting for the window to close.
    #[serde(default = "default_group_count_threshold")]
    pub group_count_threshold: u32,
}

impl Default for NotificationPipelineConfig {
    fn default() -> Self {
        Self {
            group_window_secs: default_group_window_secs(),
            group_count_threshold: default_group_count_threshold(),
        }
    }
}

/// Per-channel notification filter and digest settings.
///
/// Embedded inside each channel config (Telegram, Slack, etc.) as:
/// ```toml
/// [telegram]
/// notification_level = "actionable"
/// digest = "daily"
/// digest_hour = 9
/// ```
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
#[serde(deny_unknown_fields)]
pub struct ChannelNotificationConfig {
    /// Filter level for real-time notifications.
    #[serde(default = "default_channel_level_actionable")]
    pub notification_level: ChannelFilterLevel,

    /// Digest frequency.
    #[serde(default)]
    pub digest: DigestFrequency,

    /// Hour of day (0–23, local time) to send daily digest.
    /// Only used when `digest = "daily"`.
    #[serde(default = "default_digest_hour")]
    pub digest_hour: u8,
}

impl Default for ChannelNotificationConfig {
    fn default() -> Self {
        Self {
            notification_level: default_channel_level_actionable(),
            digest: DigestFrequency::None,
            digest_hour: default_digest_hour(),
        }
    }
}
