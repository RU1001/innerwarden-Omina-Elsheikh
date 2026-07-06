mod burst;
mod client;
mod commands;
mod formatting;
mod templates;

/// Operating mode of the InnerWarden agent - drives notification style.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GuardianMode {
    /// Responder enabled, live - agent acts autonomously and reports decisions.
    Guard,
    /// Responder enabled, dry-run - simulates actions, asks for confirmation.
    DryRun,
    /// Responder disabled - monitors and asks operator what to do.
    Watch,
}

impl GuardianMode {
    pub fn label(&self) -> &'static str {
        match self {
            GuardianMode::Guard => "🟢 GUARD",
            GuardianMode::DryRun => "🟡 DRY-RUN",
            GuardianMode::Watch => "🔵 WATCH",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            GuardianMode::Guard => "Threats are blocked automatically. You receive reports.",
            GuardianMode::DryRun => "Test mode - shows what would be blocked, no real changes.",
            GuardianMode::Watch => "Monitor only - all actions require your approval.",
        }
    }
}

/// An approval result received from the operator via Telegram.
#[derive(Debug, Clone)]
pub struct ApprovalResult {
    pub incident_id: String,
    pub approved: bool,
    pub operator_name: String,
    /// If true, the operator wants this detector+action pair to always auto-execute.
    pub always: bool,
    /// The action chosen by the operator (for multi-choice keyboards).
    /// Values: "honeypot", "block", "monitor", "ignore", or empty (binary approve/reject).
    pub chosen_action: String,
}

/// Tracks a pending confirmation while waiting for the operator's response.
#[derive(Debug, Clone)]
pub struct PendingConfirmation {
    #[allow(dead_code)]
    pub incident_id: String,
    pub telegram_message_id: i64,
    #[allow(dead_code)]
    pub action_description: String,
    #[allow(dead_code)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Detector that triggered this incident (for trust-rule creation on "Always").
    pub detector: String,
    /// Action name (for trust-rule creation on "Always").
    pub action_name: String,
}

pub use burst::{format_daily_briefing, format_simple_status, BlockedSource, DailyBriefingData};
pub use client::TelegramClient;
pub use commands::{
    append_to_allowlist, log_allowlist_change, log_false_positive, read_undoable_allowlist_entries,
    remove_from_allowlist,
};
pub(crate) use formatting::friendly_detector_name;
pub use formatting::{escape_html_pub, extract_detector_pub, truncate_callback_pub};

#[allow(dead_code)]
pub fn format_daily_digest(
    incidents_today: u32,
    blocks_today: u32,
    critical_count: u32,
    high_count: u32,
    top_detector: &str,
    top_count: u32,
    is_simple: bool,
) -> String {
    burst::format_daily_digest(
        incidents_today,
        blocks_today,
        critical_count,
        high_count,
        top_detector,
        top_count,
        is_simple,
    )
}

pub fn explain_detector(detector: &str) -> String {
    templates::explain_detector(detector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guardian_mode_labels() {
        assert_eq!(GuardianMode::Guard.label(), "🟢 GUARD");
        assert_eq!(GuardianMode::DryRun.label(), "🟡 DRY-RUN");
        assert_eq!(GuardianMode::Watch.label(), "🔵 WATCH");
    }

    #[test]
    fn test_guardian_mode_descriptions() {
        assert!(GuardianMode::Guard
            .description()
            .contains("blocked automatically"));
        assert!(GuardianMode::DryRun.description().contains("Test mode"));
        assert!(GuardianMode::Watch.description().contains("Monitor only"));
    }
}
