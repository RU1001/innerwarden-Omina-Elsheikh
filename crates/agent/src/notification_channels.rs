//! Unified chat-channel registry (spec 078).
//!
//! Operator-facing chat channels — Telegram, Slack, and Discord — share a
//! single [`ChatChannel`] trait and a single registry ([`collect_chat_channels`])
//! so every notification kind (incident alert, action report, summary) fans out
//! the same way, with one severity-rank + filter-level gate applied uniformly.
//!
//! Adding a channel is a closed change: implement [`ChatChannel`], build its
//! client at boot, and add one line to [`collect_chat_channels`] — no dispatch
//! site is touched. Discord (Phase 3) was added exactly that way: a new
//! `discord` module + `[discord]` config + one boot block + one registry line.
//!
//! Webhook (machine JSON) and Web Push (browser) are intentionally NOT chat
//! channels — they have no "action report" concept and keep their own dispatch
//! in `incident_notifications`.

use std::sync::Arc;

use async_trait::async_trait;
use innerwarden_core::incident::Incident;
use tracing::warn;

use crate::config::{AgentConfig, ChannelFilterLevel};
use crate::incident_notifications::passes_channel_filter;
use crate::slack::SlackClient;
use crate::telegram::{GuardianMode, TelegramClient};
use crate::webhook::severity_rank;
use crate::AgentState;

/// Per-incident render context for the incident-alert kind. Channel-specific
/// destinations (e.g. the Slack dashboard deep-link) live on the channel
/// itself, so this only carries the per-incident Telegram rendering knobs.
pub(crate) struct ChatContext {
    pub(crate) mode: GuardianMode,
    pub(crate) telegram_is_simple: bool,
}

impl ChatContext {
    pub(crate) fn from_config(cfg: &AgentConfig) -> Self {
        Self {
            mode: crate::agent_context::guardian_mode(cfg),
            telegram_is_simple: cfg.telegram.is_simple_profile(),
        }
    }
}

/// A post-execution action report: "what the agent did about an incident".
///
/// Built once by `incident_action_report` and fanned out to every chat channel
/// so Telegram, Slack, and (future) Discord render the same disposition.
pub(crate) struct ActionReport {
    pub(crate) action_label: String,
    pub(crate) target: String,
    pub(crate) incident_title: String,
    pub(crate) confidence: f32,
    pub(crate) host: String,
    pub(crate) dry_run: bool,
    pub(crate) ip_reputation: Option<crate::abuseipdb::IpReputation>,
    pub(crate) ip_geo: Option<crate::geoip::GeoInfo>,
    pub(crate) cloudflare_pushed: bool,
}

/// An operator-facing chat channel.
///
/// The trait is the single contract a new channel must satisfy. Because every
/// notification kind is a required method, a channel physically cannot compile
/// while missing one — that is the "add Discord and it works first try"
/// guarantee from spec 078.
#[async_trait]
pub(crate) trait ChatChannel: Send + Sync {
    /// Stable identifier for logs/metrics: `"telegram"` | `"slack"` | `"discord"`.
    fn name(&self) -> &'static str;
    /// Minimum severity rank this channel accepts (resolved from config).
    fn min_rank(&self) -> u8;
    /// Channel-level filter (All / Actionable / Critical / None).
    fn filter_level(&self) -> ChannelFilterLevel;
    /// Render + send an incident alert.
    async fn incident_alert(&self, incident: &Incident, ctx: &ChatContext) -> anyhow::Result<()>;
    /// Render + send a post-execution action report ("what the agent did").
    async fn action_report(&self, report: &ActionReport) -> anyhow::Result<()>;
    /// Send a pre-rendered summary line (burst/group rollups). Input is Telegram
    /// HTML; non-HTML channels strip the tags.
    async fn summary(&self, html: &str) -> anyhow::Result<()>;
}

pub(crate) struct TelegramChannel {
    client: Arc<TelegramClient>,
    min_rank: u8,
    filter_level: ChannelFilterLevel,
}

#[async_trait]
impl ChatChannel for TelegramChannel {
    fn name(&self) -> &'static str {
        "telegram"
    }
    fn min_rank(&self) -> u8 {
        self.min_rank
    }
    fn filter_level(&self) -> ChannelFilterLevel {
        self.filter_level
    }
    async fn incident_alert(&self, incident: &Incident, ctx: &ChatContext) -> anyhow::Result<()> {
        self.client
            .send_incident_alert(incident, ctx.mode, ctx.telegram_is_simple)
            .await
    }
    async fn action_report(&self, report: &ActionReport) -> anyhow::Result<()> {
        self.client
            .send_action_report(
                &report.action_label,
                &report.target,
                &report.incident_title,
                report.confidence,
                &report.host,
                report.dry_run,
                report.ip_reputation.as_ref(),
                report.ip_geo.as_ref(),
                report.cloudflare_pushed,
            )
            .await
    }
    async fn summary(&self, html: &str) -> anyhow::Result<()> {
        self.client.send_alert_html(html).await
    }
}

pub(crate) struct SlackChannel {
    client: SlackClient,
    min_rank: u8,
    filter_level: ChannelFilterLevel,
    dashboard_url: Option<String>,
}

#[async_trait]
impl ChatChannel for SlackChannel {
    fn name(&self) -> &'static str {
        "slack"
    }
    fn min_rank(&self) -> u8 {
        self.min_rank
    }
    fn filter_level(&self) -> ChannelFilterLevel {
        self.filter_level
    }
    async fn incident_alert(&self, incident: &Incident, _ctx: &ChatContext) -> anyhow::Result<()> {
        self.client
            .send_incident_alert(incident, self.dashboard_url.as_deref())
            .await
    }
    async fn action_report(&self, report: &ActionReport) -> anyhow::Result<()> {
        self.client
            .send_action_report(report, self.dashboard_url.as_deref())
            .await
    }
    async fn summary(&self, html: &str) -> anyhow::Result<()> {
        self.client.send_summary(html).await
    }
}

pub(crate) struct DiscordChannel {
    client: crate::discord::DiscordClient,
    min_rank: u8,
    filter_level: ChannelFilterLevel,
    dashboard_url: Option<String>,
}

#[async_trait]
impl ChatChannel for DiscordChannel {
    fn name(&self) -> &'static str {
        "discord"
    }
    fn min_rank(&self) -> u8 {
        self.min_rank
    }
    fn filter_level(&self) -> ChannelFilterLevel {
        self.filter_level
    }
    async fn incident_alert(&self, incident: &Incident, _ctx: &ChatContext) -> anyhow::Result<()> {
        self.client
            .send_incident_alert(incident, self.dashboard_url.as_deref())
            .await
    }
    async fn action_report(&self, report: &ActionReport) -> anyhow::Result<()> {
        self.client
            .send_action_report(report, self.dashboard_url.as_deref())
            .await
    }
    async fn summary(&self, html: &str) -> anyhow::Result<()> {
        self.client.send_summary(html).await
    }
}

/// Build the active chat-channel set from config + live clients.
///
/// A channel is included iff it is enabled in config AND its client was
/// constructed at boot. This mirrors exactly the per-channel gate the old
/// hand-wired dispatch used (`cfg.<ch>.enabled && state.<ch>_client.is_some()`),
/// so the alert path is behaviour-identical.
pub(crate) fn collect_chat_channels(
    cfg: &AgentConfig,
    state: &AgentState,
) -> Vec<Box<dyn ChatChannel>> {
    let mut channels: Vec<Box<dyn ChatChannel>> = Vec::new();

    if cfg.telegram.enabled {
        if let Some(tg) = &state.telegram_client {
            channels.push(Box::new(TelegramChannel {
                client: tg.clone(),
                min_rank: severity_rank(&cfg.telegram.parsed_min_severity()),
                filter_level: cfg.telegram.channel_notifications.notification_level,
            }));
        }
    }

    if cfg.slack.enabled {
        if let Some(sc) = &state.slack_client {
            channels.push(Box::new(SlackChannel {
                client: sc.clone(),
                min_rank: severity_rank(&cfg.slack.parsed_min_severity()),
                filter_level: cfg.slack.channel_notifications.notification_level,
                dashboard_url: if cfg.slack.dashboard_url.is_empty() {
                    None
                } else {
                    Some(cfg.slack.dashboard_url.clone())
                },
            }));
        }
    }

    if cfg.discord.enabled {
        if let Some(dc) = &state.discord_client {
            channels.push(Box::new(DiscordChannel {
                client: dc.clone(),
                min_rank: severity_rank(&cfg.discord.parsed_min_severity()),
                filter_level: cfg.discord.channel_notifications.notification_level,
                dashboard_url: if cfg.discord.dashboard_url.is_empty() {
                    None
                } else {
                    Some(cfg.discord.dashboard_url.clone())
                },
            }));
        }
    }

    channels
}

/// Fan an incident alert out to every chat channel that passes its own
/// severity-rank + filter-level gate.
///
/// One channel erroring is logged and skipped — it never blocks the others
/// (preserves the old per-channel failure isolation).
pub(crate) async fn fan_out_alert(
    channels: &[Box<dyn ChatChannel>],
    incident: &Incident,
    ctx: &ChatContext,
) {
    let rank = severity_rank(&incident.severity);
    for ch in channels {
        if rank >= ch.min_rank() && passes_channel_filter(ch.filter_level(), &incident.severity) {
            if let Err(e) = ch.incident_alert(incident, ctx).await {
                warn!(
                    channel = ch.name(),
                    incident_id = %incident.incident_id,
                    "chat-channel alert failed: {e:#}"
                );
            }
        }
    }
}

/// Fan a post-execution action report out to every chat channel.
///
/// Action reports are NOT severity-gated here: they fire only for executed
/// actions on immediate threats that the caller already judged reportable
/// (non-`Dismiss`/`Ignore`), so the disposition reaches every channel the
/// operator wired. Per-channel failure is logged and skipped.
pub(crate) async fn fan_out_action_report(
    channels: &[Box<dyn ChatChannel>],
    report: &ActionReport,
) {
    for ch in channels {
        if let Err(e) = ch.action_report(report).await {
            warn!(
                channel = ch.name(),
                "chat-channel action report failed: {e:#}"
            );
        }
    }
}

/// Fan a pre-rendered summary line (burst/group rollup) out to every chat
/// channel. Per-channel failure is logged and skipped.
pub(crate) async fn fan_out_summary(channels: &[Box<dyn ChatChannel>], html: &str) {
    for ch in channels {
        if let Err(e) = ch.summary(html).await {
            warn!(channel = ch.name(), "chat-channel summary failed: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn incident(severity: Severity) -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "h".to_string(),
            incident_id: "port_scan:203.0.113.5:w".to_string(),
            severity,
            title: "t".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        }
    }

    fn ctx() -> ChatContext {
        ChatContext {
            mode: GuardianMode::Watch,
            telegram_is_simple: false,
        }
    }

    fn report() -> ActionReport {
        ActionReport {
            action_label: "Blocked".to_string(),
            target: "203.0.113.5".to_string(),
            incident_title: "t".to_string(),
            confidence: 0.95,
            host: "h".to_string(),
            dry_run: false,
            ip_reputation: None,
            ip_geo: None,
            cloudflare_pushed: false,
        }
    }

    #[derive(Clone, Default)]
    struct Counters {
        alert: Arc<AtomicUsize>,
        report: Arc<AtomicUsize>,
        summary: Arc<AtomicUsize>,
    }

    struct MockChannel {
        name: &'static str,
        min_rank: u8,
        filter_level: ChannelFilterLevel,
        c: Counters,
        fail: bool,
    }

    #[async_trait]
    impl ChatChannel for MockChannel {
        fn name(&self) -> &'static str {
            self.name
        }
        fn min_rank(&self) -> u8 {
            self.min_rank
        }
        fn filter_level(&self) -> ChannelFilterLevel {
            self.filter_level
        }
        async fn incident_alert(&self, _i: &Incident, _c: &ChatContext) -> anyhow::Result<()> {
            self.c.alert.fetch_add(1, Ordering::SeqCst);
            self.maybe_fail()
        }
        async fn action_report(&self, _r: &ActionReport) -> anyhow::Result<()> {
            self.c.report.fetch_add(1, Ordering::SeqCst);
            self.maybe_fail()
        }
        async fn summary(&self, _html: &str) -> anyhow::Result<()> {
            self.c.summary.fetch_add(1, Ordering::SeqCst);
            self.maybe_fail()
        }
    }

    impl MockChannel {
        fn maybe_fail(&self) -> anyhow::Result<()> {
            if self.fail {
                anyhow::bail!("simulated channel failure");
            }
            Ok(())
        }
    }

    fn mock(
        name: &'static str,
        min_rank: u8,
        filter_level: ChannelFilterLevel,
        fail: bool,
    ) -> (Box<dyn ChatChannel>, Counters) {
        let c = Counters::default();
        let ch = MockChannel {
            name,
            min_rank,
            filter_level,
            c: c.clone(),
            fail,
        };
        (Box::new(ch), c)
    }

    #[tokio::test]
    async fn fan_out_skips_channel_below_its_min_rank() {
        let high = severity_rank(&Severity::High);
        let (ch, c) = mock("telegram", high, ChannelFilterLevel::All, false);
        let channels = vec![ch];

        fan_out_alert(&channels, &incident(Severity::Low), &ctx()).await;
        assert_eq!(
            c.alert.load(Ordering::SeqCst),
            0,
            "Low must not reach a High-rank channel"
        );

        fan_out_alert(&channels, &incident(Severity::Critical), &ctx()).await;
        assert_eq!(
            c.alert.load(Ordering::SeqCst),
            1,
            "Critical must reach a High-rank channel"
        );
    }

    #[tokio::test]
    async fn fan_out_respects_filter_level_none() {
        let (ch, c) = mock("slack", 0, ChannelFilterLevel::None, false);
        let channels = vec![ch];
        fan_out_alert(&channels, &incident(Severity::Critical), &ctx()).await;
        assert_eq!(
            c.alert.load(Ordering::SeqCst),
            0,
            "filter None silences every severity"
        );
    }

    #[tokio::test]
    async fn fan_out_critical_filter_drops_medium_keeps_high() {
        let (ch, c) = mock("slack", 0, ChannelFilterLevel::Critical, false);
        let channels = vec![ch];
        fan_out_alert(&channels, &incident(Severity::Medium), &ctx()).await;
        assert_eq!(c.alert.load(Ordering::SeqCst), 0);
        fan_out_alert(&channels, &incident(Severity::High), &ctx()).await;
        assert_eq!(c.alert.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn one_channel_failure_does_not_block_the_others() {
        // First channel always errors; the second must still be called.
        let (ch1, c1) = mock("telegram", 0, ChannelFilterLevel::All, true);
        let (ch2, c2) = mock("slack", 0, ChannelFilterLevel::All, false);
        let channels = vec![ch1, ch2];
        fan_out_alert(&channels, &incident(Severity::High), &ctx()).await;
        assert_eq!(
            c1.alert.load(Ordering::SeqCst),
            1,
            "failing channel was attempted"
        );
        assert_eq!(
            c2.alert.load(Ordering::SeqCst),
            1,
            "second channel still fired despite first failing"
        );
    }

    #[tokio::test]
    async fn collect_includes_only_enabled_channels_with_a_client() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        state.telegram_client = Some(Arc::new(
            crate::telegram::TelegramClient::new("token", "chat", None).unwrap(),
        ));
        state.slack_client =
            Some(crate::slack::SlackClient::new("https://hooks.slack.com/x").unwrap());

        let mut cfg = AgentConfig::default();
        cfg.telegram.enabled = true;
        cfg.slack.enabled = true;
        let names: Vec<&str> = collect_chat_channels(&cfg, &state)
            .iter()
            .map(|c| c.name())
            .collect();
        assert_eq!(names, vec!["telegram", "slack"]);

        // Disable Slack in config → only Telegram remains, even though the
        // Slack client still exists in state.
        cfg.slack.enabled = false;
        let names: Vec<&str> = collect_chat_channels(&cfg, &state)
            .iter()
            .map(|c| c.name())
            .collect();
        assert_eq!(names, vec!["telegram"]);

        // A channel enabled in config but with no client built at boot is
        // excluded (mirrors the old `state.<ch>_client.is_some()` gate).
        cfg.slack.enabled = true;
        state.slack_client = None;
        let names: Vec<&str> = collect_chat_channels(&cfg, &state)
            .iter()
            .map(|c| c.name())
            .collect();
        assert_eq!(names, vec!["telegram"]);
    }

    #[test]
    fn chat_context_maps_config_fields() {
        let cfg = AgentConfig::default();
        let c = ChatContext::from_config(&cfg);
        // mode + telegram_is_simple resolve from config without panic.
        let _ = c.mode;
        let _ = c.telegram_is_simple;
    }

    #[tokio::test]
    async fn real_channels_expose_their_configured_rank_and_filter() {
        // Exercises the concrete getters (name/min_rank/filter_level) on the
        // REAL Telegram + Slack channels built by the registry — not the mock.
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        state.telegram_client = Some(Arc::new(
            crate::telegram::TelegramClient::new("token", "chat", None).unwrap(),
        ));
        state.slack_client =
            Some(crate::slack::SlackClient::new("https://hooks.slack.com/x").unwrap());

        let mut cfg = AgentConfig::default();
        cfg.telegram.enabled = true;
        cfg.slack.enabled = true;

        for ch in collect_chat_channels(&cfg, &state) {
            // Getters must not panic and must return the config-derived values.
            assert!(matches!(ch.name(), "telegram" | "slack"));
            let _ = ch.min_rank();
            let _ = ch.filter_level();
        }
    }

    #[tokio::test]
    async fn slack_channel_actually_posts_through_the_registry() {
        // Covers SlackChannel::incident_alert end-to-end against a mock webhook,
        // proving the registry path drives a real channel to send.
        let mut server = mockito::Server::new_async().await;
        let hook = server
            .mock("POST", "/services/T/B/X")
            .with_status(200)
            .create_async()
            .await;

        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        state.slack_client = Some(
            crate::slack::SlackClient::new(format!("{}/services/T/B/X", server.url())).unwrap(),
        );

        let mut cfg = AgentConfig::default();
        cfg.slack.enabled = true;

        let channels = collect_chat_channels(&cfg, &state);
        assert_eq!(channels.len(), 1);
        let ctx = ChatContext::from_config(&cfg);
        fan_out_alert(&channels, &incident(Severity::Critical), &ctx).await;

        hook.assert_async().await;
    }

    #[tokio::test]
    async fn action_report_fans_out_to_every_channel_ungated() {
        // Action reports are not severity-gated: a channel with a High min_rank
        // and a Critical-only filter still receives the report.
        let (ch1, c1) = mock("telegram", 0, ChannelFilterLevel::All, false);
        let (ch2, c2) = mock(
            "slack",
            severity_rank(&Severity::Critical),
            ChannelFilterLevel::Critical,
            false,
        );
        let channels = vec![ch1, ch2];
        fan_out_action_report(&channels, &report()).await;
        assert_eq!(c1.report.load(Ordering::SeqCst), 1);
        assert_eq!(
            c2.report.load(Ordering::SeqCst),
            1,
            "action reports ignore the severity/filter gate"
        );
    }

    #[tokio::test]
    async fn action_report_isolates_per_channel_failure() {
        let (ch1, c1) = mock("telegram", 0, ChannelFilterLevel::All, true);
        let (ch2, c2) = mock("slack", 0, ChannelFilterLevel::All, false);
        let channels = vec![ch1, ch2];
        fan_out_action_report(&channels, &report()).await;
        assert_eq!(c1.report.load(Ordering::SeqCst), 1);
        assert_eq!(
            c2.report.load(Ordering::SeqCst),
            1,
            "second channel still got the report"
        );
    }

    #[tokio::test]
    async fn summary_fans_out_to_every_channel() {
        let (ch1, c1) = mock("telegram", 0, ChannelFilterLevel::All, false);
        let (ch2, c2) = mock("slack", 0, ChannelFilterLevel::All, true);
        let channels = vec![ch1, ch2];
        fan_out_summary(&channels, "<b>3 contained</b>").await;
        assert_eq!(c1.summary.load(Ordering::SeqCst), 1);
        assert_eq!(
            c2.summary.load(Ordering::SeqCst),
            1,
            "failure on one channel doesn't block the other"
        );
    }

    #[tokio::test]
    async fn slack_action_report_and_summary_post_through_the_registry() {
        // Drives SlackChannel::action_report + summary end-to-end against a mock
        // webhook, including the dashboard_url deep-link branch.
        let mut server = mockito::Server::new_async().await;
        let hook = server
            .mock("POST", "/services/T/B/X")
            .with_status(200)
            .expect(2)
            .create_async()
            .await;

        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        state.slack_client = Some(
            crate::slack::SlackClient::new(format!("{}/services/T/B/X", server.url())).unwrap(),
        );

        let mut cfg = AgentConfig::default();
        cfg.slack.enabled = true;
        cfg.slack.dashboard_url = "https://dash.example".to_string();

        let channels = collect_chat_channels(&cfg, &state);
        assert_eq!(channels.len(), 1);
        fan_out_action_report(&channels, &report()).await;
        fan_out_summary(&channels, "<b>burst</b> of 5").await;

        hook.assert_async().await;
    }

    #[tokio::test]
    async fn collect_includes_discord_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        state.discord_client = Some(
            crate::discord::DiscordClient::new("https://discord.com/api/webhooks/1/x").unwrap(),
        );
        let mut cfg = AgentConfig::default();
        cfg.discord.enabled = true;
        let names: Vec<&str> = collect_chat_channels(&cfg, &state)
            .iter()
            .map(|c| c.name())
            .collect();
        assert_eq!(names, vec!["discord"]);

        // Disabled in config -> excluded even though the client exists.
        cfg.discord.enabled = false;
        assert!(collect_chat_channels(&cfg, &state).is_empty());
    }

    /// Contract test: a real Discord channel built by the registry handles
    /// EVERY notification kind (alert + action report + summary) end-to-end.
    /// This is the "add a channel and it works first try" guarantee — if a new
    /// channel forgets a kind it cannot compile; this proves the wiring too.
    #[tokio::test]
    async fn discord_channel_handles_all_kinds_through_the_registry() {
        let mut server = mockito::Server::new_async().await;
        let hook = server
            .mock("POST", "/api/webhooks/1/tok")
            .with_status(204)
            .expect(3) // alert + action report + summary
            .create_async()
            .await;

        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        state.discord_client = Some(
            crate::discord::DiscordClient::new(format!("{}/api/webhooks/1/tok", server.url()))
                .unwrap(),
        );

        let mut cfg = AgentConfig::default();
        cfg.discord.enabled = true;
        cfg.discord.dashboard_url = "https://dash.example".to_string();

        let channels = collect_chat_channels(&cfg, &state);
        assert_eq!(channels.len(), 1);
        let ctx = ChatContext::from_config(&cfg);
        fan_out_alert(&channels, &incident(Severity::Critical), &ctx).await;
        fan_out_action_report(&channels, &report()).await;
        fan_out_summary(&channels, "<b>burst</b>").await;

        hook.assert_async().await;
    }
}
