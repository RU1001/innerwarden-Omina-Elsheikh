//! Centralized notification gate. ALL automated Telegram messages must pass
//! through this gate. Only real, uncontained threats get immediate notification.
//! Everything else goes to daily briefing or is dropped entirely.
//!
//! Bot command responses (operator asked for info) and daily briefings are
//! exempt — they bypass this gate.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tracing::info;

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// What the gate decides for a given notification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotificationVerdict {
    /// Send immediately to Telegram.
    SendNow,
    /// Accumulate for daily briefing (do not send now).
    DailyBriefingOnly,
    /// Drop entirely (not even in briefing).
    Drop,
}

// ---------------------------------------------------------------------------
// Context — callers build this from whatever data they have
// ---------------------------------------------------------------------------

/// Describes the notification being considered. Callers populate from incident
/// data, kill chain output, honeypot session, etc.
pub(crate) struct NotificationContext {
    #[allow(dead_code)]
    pub severity: String,
    pub detector: String,
    /// "blocked", "killed", "contained", "suspended", "monitoring", "open", etc.
    #[allow(dead_code)]
    pub outcome: String,
    pub is_contained: bool,
    pub is_active_intrusion: bool,
    pub is_compromise: bool,
    pub is_honeypot_probe: bool,
}

impl NotificationContext {
    /// Build from a core Incident (used by the main incident pipeline path).
    pub fn from_incident(incident: &innerwarden_core::incident::Incident) -> Self {
        let detector = incident
            .incident_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();

        let severity_str = format!("{:?}", incident.severity).to_lowercase();

        // Determine outcome from tags / evidence.
        let outcome = Self::extract_outcome(incident);
        let is_contained = Self::check_contained(&outcome);

        // is_compromise: kill chain reached data_exfil or persistence AND Critical.
        let is_compromise = matches!(
            incident.severity,
            innerwarden_core::event::Severity::Critical
        ) && incident.tags.iter().any(|t| {
            t == "data_exfiltration"
                || t == "persistence"
                || t == "data_exfil"
                || t == "exfiltration"
                || t == "rootkit"
        });

        // is_active_intrusion: Critical AND kill chain with 3+ stages or
        // combination of privesc + persistence + lateral_movement.
        let is_active_intrusion = matches!(
            incident.severity,
            innerwarden_core::event::Severity::Critical
        ) && {
            let has_multi_stage = incident.tags.iter().any(|t| t.contains("killchain"))
                || detector.starts_with("killchain");
            let has_privesc = incident
                .tags
                .iter()
                .any(|t| t == "privesc" || t == "privilege_escalation");
            let has_persistence = incident.tags.iter().any(|t| t == "persistence");
            let has_lateral = incident.tags.iter().any(|t| t == "lateral_movement");
            has_multi_stage || (has_privesc && has_persistence) || (has_privesc && has_lateral)
        };

        let is_honeypot_probe = detector == "honeypot"
            && incident
                .tags
                .iter()
                .any(|t| t == "probe" || t == "probe_only");

        Self {
            severity: severity_str,
            detector,
            outcome,
            is_contained,
            is_active_intrusion,
            is_compromise,
            is_honeypot_probe,
        }
    }

    /// Build from a kill chain JSON incident (killchain_inline produces JSON values).
    pub fn from_killchain_json(inc: &serde_json::Value) -> Self {
        let severity = inc
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("medium")
            .to_string();

        let pattern = inc
            .get("evidence")
            .and_then(|e| e.get("pattern"))
            .and_then(|p| p.as_str())
            .unwrap_or("unknown");

        let detector = format!("killchain.{}", pattern);

        let outcome = inc
            .get("outcome")
            .and_then(|o| o.as_str())
            .unwrap_or("open")
            .to_string();
        let is_contained = Self::check_contained(&outcome);

        // Kill chain data_exfil pattern at critical = compromise.
        let is_compromise =
            severity == "critical" && (pattern == "data_exfil" || pattern == "full_exploit");

        // Kill chain with 3+ bit stages is active intrusion (reverse_shell=3,
        // bind_shell=4, full_exploit=3, exploit_shell=3).
        let stage_count = inc
            .get("evidence")
            .and_then(|e| e.get("flags"))
            .and_then(|f| f.as_u64())
            .map(|f| (f as u32).count_ones())
            .unwrap_or(0);
        let is_active_intrusion = severity == "critical" && stage_count >= 3;

        Self {
            severity,
            detector,
            outcome,
            is_contained,
            is_active_intrusion,
            is_compromise,
            is_honeypot_probe: false,
        }
    }

    /// Build for a shield (DDoS) incident.
    pub fn from_shield_json(inc: &serde_json::Value) -> Self {
        let severity = inc
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("low")
            .to_string();

        let detector = "shield".to_string();

        let outcome = inc
            .get("outcome")
            .and_then(|o| o.as_str())
            .unwrap_or("blocked")
            .to_string();
        let is_contained = Self::check_contained(&outcome);
        let is_active_intrusion = severity == "critical" && !is_contained;

        Self {
            severity,
            detector,
            outcome,
            is_contained,
            // DDoS is not intrusion unless it escalated past mitigation.
            is_active_intrusion,
            is_compromise: false,
            is_honeypot_probe: false,
        }
    }

    /// Build for a firmware/hypervisor tick incident.
    pub fn from_firmware_or_hypervisor(
        inc: &innerwarden_core::incident::Incident,
        detector_label: &str,
    ) -> Self {
        let severity_str = format!("{:?}", inc.severity).to_lowercase();

        // Firmware/hypervisor alerts about trust degradation are informational
        // unless they indicate active rootkit/compromise.
        let is_compromise = matches!(inc.severity, innerwarden_core::event::Severity::Critical)
            && inc.tags.iter().any(|t| {
                t == "rootkit" || t == "firmware_tampering" || t == "msr_write" || t == "spi_flash"
            });

        Self {
            severity: severity_str,
            detector: detector_label.to_string(),
            outcome: "monitoring".to_string(),
            is_contained: false,
            is_active_intrusion: false,
            is_compromise,
            is_honeypot_probe: false,
        }
    }

    /// Build for a mesh network block notification.
    pub fn for_mesh_block() -> Self {
        Self {
            severity: "medium".to_string(),
            detector: "mesh".to_string(),
            outcome: "blocked".to_string(),
            is_contained: true,
            is_active_intrusion: false,
            is_compromise: false,
            is_honeypot_probe: false,
        }
    }

    /// Build for an advisory-ignored notification.
    pub fn for_advisory_ignored(risk_score: u32) -> Self {
        Self {
            severity: if risk_score >= 80 {
                "critical".to_string()
            } else if risk_score >= 60 {
                "high".to_string()
            } else {
                "medium".to_string()
            },
            detector: "advisory".to_string(),
            outcome: "open".to_string(),
            is_contained: false,
            // Advisory ignored is serious but not intrusion per se.
            is_active_intrusion: risk_score >= 80,
            is_compromise: false,
            is_honeypot_probe: false,
        }
    }

    /// Build for a honeypot session report.
    pub fn for_honeypot_session(is_probe_only: bool, auto_blocked: bool) -> Self {
        Self {
            severity: "low".to_string(),
            detector: "honeypot".to_string(),
            outcome: if auto_blocked {
                "blocked".to_string()
            } else {
                "monitoring".to_string()
            },
            is_contained: auto_blocked,
            is_active_intrusion: false,
            is_compromise: false,
            is_honeypot_probe: is_probe_only,
        }
    }

    /// Build for an auto-FP suggestion.
    pub fn for_autofp_suggestion() -> Self {
        Self {
            severity: "info".to_string(),
            detector: "autofp".to_string(),
            outcome: "monitoring".to_string(),
            is_contained: false,
            is_active_intrusion: false,
            is_compromise: false,
            is_honeypot_probe: false,
        }
    }

    fn extract_outcome(incident: &innerwarden_core::incident::Incident) -> String {
        // Check tags for action outcomes.
        for tag in &incident.tags {
            match tag.as_str() {
                "blocked" | "killed" | "contained" | "suspended" => return tag.clone(),
                _ => {}
            }
        }
        // Check evidence for outcome field.
        if let Some(outcome) = incident.evidence.get("outcome").and_then(|o| o.as_str()) {
            return outcome.to_string();
        }
        if let Some(arr) = incident.evidence.as_array() {
            for e in arr {
                if let Some(outcome) = e.get("outcome").and_then(|o| o.as_str()) {
                    return outcome.to_string();
                }
            }
        }
        "open".to_string()
    }

    fn check_contained(outcome: &str) -> bool {
        matches!(
            outcome,
            "blocked" | "killed" | "contained" | "suspended" | "auto_blocked"
        )
    }
}

// ---------------------------------------------------------------------------
// Gate decision
// ---------------------------------------------------------------------------

/// Evaluate notification policy. Returns what the caller should do.
pub(crate) fn should_notify(ctx: &NotificationContext) -> NotificationVerdict {
    evaluate_verdict(ctx)
}

/// Evaluate notification policy and increment a monotonic suppression counter
/// whenever the verdict is not `SendNow`.
pub(crate) fn should_notify_with_counter(
    ctx: &NotificationContext,
    gate_suppressed_total: &AtomicU64,
) -> NotificationVerdict {
    let verdict = evaluate_verdict(ctx);
    if matches!(
        verdict,
        NotificationVerdict::DailyBriefingOnly | NotificationVerdict::Drop
    ) {
        gate_suppressed_total.fetch_add(1, Ordering::Relaxed);
    }
    verdict
}

fn evaluate_verdict(ctx: &NotificationContext) -> NotificationVerdict {
    // Rule 1: Server compromise NOT contained -> always send.
    //
    // 2026-05-06 fix: pre-fix this was unconditional `is_compromise -> SendNow`,
    // which produced the operator-hit Telegram noise where the same
    // `kill_chain:detected:DATA_EXFIL` Critical incident pinged the
    // operator 3x for IP 20.26.156.215 even though killchain inline
    // had already killed the process and blocked the IP. The body of
    // the message even read "Handled automatically — no action
    // needed". A compromise that's already CONTAINED (process killed,
    // IP blocked, kill chain interrupted) is exactly what the daily
    // briefing exists for: post-mortem record without paging the
    // operator. Compromise + NOT contained still pages — that's a
    // breach in flight.
    if ctx.is_compromise && !ctx.is_contained {
        return NotificationVerdict::SendNow;
    }

    // Rule 2: Active intrusion NOT contained -> send immediately.
    if ctx.is_active_intrusion && !ctx.is_contained {
        return NotificationVerdict::SendNow;
    }

    // Rule 3: Already contained -> daily briefing only.
    if ctx.is_contained {
        return NotificationVerdict::DailyBriefingOnly;
    }

    // Rule 4: Honeypot probe-only -> drop entirely.
    if ctx.is_honeypot_probe {
        return NotificationVerdict::Drop;
    }

    // Rule 5: Everything else -> daily briefing.
    NotificationVerdict::DailyBriefingOnly
}

// ---------------------------------------------------------------------------
// Burst summary counter
// ---------------------------------------------------------------------------

/// A snapshot of the burst taken at the moment the threshold is crossed.
///
/// It carries the breakdown of what was auto-blocked *so far in the window*
/// (not the final total — the window keeps counting after this fires) so the
/// operator-facing message can say WHICH server, WHAT kind of attack, and
/// FROM how many sources, instead of a bare "50 threats blocked".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BurstSummary {
    /// Host identity. Filled by the caller/formatter (the tracker is host-agnostic).
    pub host: String,
    /// Number of contained threats counted when the threshold was crossed.
    pub total: u64,
    /// Coarse plain-language buckets, sorted by count descending, top 3.
    pub top_categories: Vec<(String, u64)>,
    /// Count of distinct attacker source IPs seen in the window so far.
    pub distinct_sources: usize,
}

/// Tracks contained-threat count + breakdown for burst summary notifications.
/// When 50+ threats are auto-blocked in one hour, a single enriched summary
/// is sent (once per window) describing what was blocked.
pub(crate) struct BurstTracker {
    /// Count of contained threats since last summary or window reset.
    contained_count: AtomicU64,
    /// Per-category counts (coarse plain-language buckets) for the window.
    categories: std::sync::Mutex<HashMap<String, u64>>,
    /// Distinct attacker source IPs seen in the window.
    sources: std::sync::Mutex<HashSet<String>>,
    /// Timestamp when the current counting window started.
    window_start: std::sync::Mutex<DateTime<Utc>>,
    /// Whether a burst summary has already been sent for this window.
    summary_sent: std::sync::atomic::AtomicBool,
}

const BURST_THRESHOLD: u64 = 50;
const BURST_WINDOW_SECS: i64 = 3600;

impl BurstTracker {
    pub fn new() -> Self {
        Self {
            contained_count: AtomicU64::new(0),
            categories: std::sync::Mutex::new(HashMap::new()),
            sources: std::sync::Mutex::new(HashSet::new()),
            window_start: std::sync::Mutex::new(Utc::now()),
            summary_sent: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Record a contained threat with its coarse category and (optional)
    /// attacker source IP. Accumulates the breakdown over the window.
    ///
    /// Returns `Some(BurstSummary)` exactly once per window — the first time
    /// the running total crosses the threshold — carrying the breakdown of
    /// what has been blocked so far. The `host` field of the returned summary
    /// is left empty for the caller/formatter to fill.
    pub fn record_contained(
        &self,
        category: &str,
        source_ip: Option<&str>,
    ) -> Option<BurstSummary> {
        let now = Utc::now();

        // Check if window expired — reset everything if so.
        {
            let mut start = self.window_start.lock().unwrap();
            if (now - *start).num_seconds() >= BURST_WINDOW_SECS {
                *start = now;
                self.contained_count.store(0, Ordering::Relaxed);
                self.summary_sent.store(false, Ordering::Relaxed);
                self.categories.lock().unwrap().clear();
                self.sources.lock().unwrap().clear();
            }
        }

        // Accumulate the breakdown for this event.
        {
            let mut cats = self.categories.lock().unwrap();
            *cats.entry(category.to_string()).or_insert(0) += 1;
        }
        if let Some(ip) = source_ip {
            if !ip.is_empty() {
                self.sources.lock().unwrap().insert(ip.to_string());
            }
        }

        let count = self.contained_count.fetch_add(1, Ordering::Relaxed) + 1;

        if count >= BURST_THRESHOLD && !self.summary_sent.swap(true, Ordering::Relaxed) {
            Some(self.snapshot(count))
        } else {
            None
        }
    }

    /// Build a `BurstSummary` snapshot of the current window state.
    fn snapshot(&self, total: u64) -> BurstSummary {
        let mut top_categories: Vec<(String, u64)> = self
            .categories
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        // Sort by count desc, then name asc for a stable, deterministic order.
        top_categories.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top_categories.truncate(3);

        let distinct_sources = self.sources.lock().unwrap().len();

        BurstSummary {
            host: String::new(),
            total,
            top_categories,
            distinct_sources,
        }
    }

    /// Get current contained count (for testing/telemetry).
    #[cfg(test)]
    pub fn count(&self) -> u64 {
        self.contained_count.load(Ordering::Relaxed)
    }
}

/// Map a detector / incident kind to a coarse plain-language bucket for the
/// burst summary. Deterministic and substring-based so kill-chain patterns
/// (`killchain.reverse_shell`), shield kinds (`shield`), and raw detector
/// names all collapse to the same ~7 human buckets the operator reads.
pub(crate) fn burst_category(detector: &str) -> &'static str {
    let d = detector.to_ascii_lowercase();
    let has = |needle: &str| d.contains(needle);

    // Order matters: more specific intent before generic.
    if has("data_exfil") || has("exfiltration") || has("exfil") {
        "Data-exfiltration attempts"
    } else if has("container_escape")
        || has("privesc")
        || has("privilege_escalation")
        || has("setns")
        || has("kernel_module")
        || has("escape")
    {
        "Privilege-escalation / escape"
    } else if has("reverse_shell")
        || has("web_shell")
        || has("exploit_c2")
        || has("c2_")
        || has("c2")
        || has("process_injection")
        || has("fileless")
        || has("exploit")
    {
        "Exploit / C2 attempts"
    } else if has("ssh_bruteforce")
        || has("credential_stuffing")
        || has("distributed_ssh")
        || has("brute")
    {
        "Password-guessing (brute force)"
    } else if has("port_scan")
        || has("web_scan")
        || has("nmap")
        || has("wordlist")
        || has("user_agent_scanner")
        || has("discovery")
        || has("scan")
    {
        "Scans & probes"
    } else if has("flood")
        || has("syn")
        || has("packet")
        || has("shield")
        || has("ddos")
        || has("rate")
    {
        "DDoS / flood"
    } else {
        "Other suspicious activity"
    }
}

/// Format the burst summary message as well-explained HTML for Telegram.
///
/// Names the server, breaks down WHAT kind of attack hit (top categories),
/// HOW many distinct sources, and reassures (honestly) that everything was
/// auto-contained. Uses `{total}+` because the summary fires the moment the
/// count crosses the threshold, not at the final window total.
pub(crate) fn format_burst_summary(host: &str, s: &BurstSummary) -> String {
    let mut out = String::with_capacity(512);

    // Header — name the server if we have one.
    let prefix = if host.is_empty() {
        String::new()
    } else {
        format!("[{}] ", crate::telegram::escape_html_pub(host))
    };
    out.push_str(&format!(
        "\u{1f6e1}\u{fe0f} <b>{prefix}Under attack \u{2014} auto-contained</b>\n\n"
    ));

    out.push_str(&format!(
        "Blocked <b>{}+</b> attack attempts in the last hour \u{2014} all stopped \
         automatically, nothing got through.\n\n",
        s.total
    ));

    // What hit you — only render categories we actually have a count for.
    if !s.top_categories.is_empty() {
        out.push_str("<b>What hit you</b>\n");
        for (cat, n) in &s.top_categories {
            out.push_str(&format!(
                "\u{2022} {} \u{2014} {}\n",
                crate::telegram::escape_html_pub(cat),
                n
            ));
        }
        if s.distinct_sources > 0 {
            out.push_str(&format!("From ~{} different IPs.\n", s.distinct_sources));
        }
        out.push('\n');
    }

    out.push_str(
        "<b>Should you worry?</b> No \u{2014} your defenses caught all of it. This is the \
         normal background noise of any internet-facing server: automated bots constantly \
         scan and probe the whole internet; it is almost never aimed at you specifically.\n\n",
    );

    out.push_str(
        "You only get this alert when blocks spike past 50/hour. The full list of IPs + \
         detectors is in the daily briefing.",
    );

    out
}

// ---------------------------------------------------------------------------
// Host identity resolution
// ---------------------------------------------------------------------------

/// Resolve the operator-facing "which server" identity for notifications.
///
/// Priority order:
///   (a) first entry of `[agent] tags` (spec-058 per-host tags) if non-empty;
///   (b) the knowledge-graph system-node label (the hostname);
///   (c) `/etc/hostname`;
///   (d) the literal "this server" as a last resort.
///
/// Cheap by design — resolve once and store/clone the result; do NOT call it
/// per-event. The graph label is read under a short read-lock.
pub(crate) fn resolve_host_id(
    tags: &[String],
    graph: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
) -> String {
    // (a) operator-set asset tag wins (e.g. "env=prod", "web-01").
    if let Some(first) = tags.iter().find(|t| !t.trim().is_empty()) {
        return first.trim().to_string();
    }

    // (b) knowledge-graph system-node label (same source slow_loop uses).
    if let Ok(g) = graph.read() {
        if let Some(label) = g
            .system_node()
            .and_then(|id| g.get_node(id))
            .map(|n| n.label())
        {
            let label = label.trim();
            if !label.is_empty() && label != "unknown" {
                return label.to_string();
            }
        }
    }

    // (c) /etc/hostname, then (d) a friendly fallback.
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "this server".to_string())
}

// ---------------------------------------------------------------------------
// Convenience: gate + send for common patterns
// ---------------------------------------------------------------------------

/// Gate an automated alert through the notification policy. If `SendNow`,
/// sends via `send_fn`. If `DailyBriefingOnly`, increments the deferred
/// counter and records in burst tracker. Returns the verdict.
#[allow(dead_code)]
pub(crate) async fn gate_and_send<F, Fut>(
    ctx: &NotificationContext,
    tg: &Arc<crate::telegram::TelegramClient>,
    burst_tracker: &BurstTracker,
    deferred: &mut std::collections::HashMap<String, u32>,
    send_fn: F,
) -> NotificationVerdict
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let verdict = should_notify(ctx);

    match verdict {
        NotificationVerdict::SendNow => {
            send_fn().await;
        }
        NotificationVerdict::DailyBriefingOnly => {
            *deferred.entry(ctx.detector.clone()).or_insert(0) += 1;
            info!(
                detector = %ctx.detector,
                severity = %ctx.severity,
                "notification gate: deferred to daily briefing"
            );
            if ctx.is_contained {
                let category = burst_category(&ctx.detector);
                if let Some(summary) = burst_tracker.record_contained(category, None) {
                    let msg = format_burst_summary("", &summary);
                    let tg = tg.clone();
                    tokio::spawn(async move {
                        let _ = tg.send_alert_html(&msg).await;
                    });
                }
            }
        }
        NotificationVerdict::Drop => {
            info!(
                detector = %ctx.detector,
                "notification gate: dropped (noise)"
            );
        }
    }

    verdict
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(
        severity: &str,
        detector: &str,
        is_contained: bool,
        is_active_intrusion: bool,
        is_compromise: bool,
        is_honeypot_probe: bool,
    ) -> NotificationContext {
        NotificationContext {
            severity: severity.to_string(),
            detector: detector.to_string(),
            outcome: if is_contained {
                "blocked".to_string()
            } else {
                "open".to_string()
            },
            is_contained,
            is_active_intrusion,
            is_compromise,
            is_honeypot_probe,
        }
    }

    #[test]
    fn compromise_uncontained_sends() {
        // Real attack in progress, agent has not yet contained it →
        // page the operator immediately.
        let ctx = make_ctx(
            "critical",
            "killchain.data_exfil",
            false,
            false,
            true,
            false,
        );
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    /// 2026-05-06 anchor: the operator-observed bug. A
    /// `kill_chain:detected:DATA_EXFIL` Critical incident pinged the
    /// operator 3x for IP 20.26.156.215 even though killchain inline
    /// had already killed the process and blocked the IP. The body of
    /// the message read "Handled automatically — no action needed",
    /// directly contradicting the SendNow decision. Pre-fix Rule 1
    /// was unconditional `is_compromise → SendNow`. Post-fix it
    /// requires `!is_contained` — a compromise that's already been
    /// handled goes to the daily briefing where post-mortem records
    /// belong.
    #[test]
    fn compromise_contained_defers_to_daily_briefing() {
        let ctx = make_ctx(
            "critical",
            "killchain.data_exfil",
            true, // is_contained — killchain inline already blocked
            false,
            true, // is_compromise — Critical + data_exfil tag
            false,
        );
        assert_eq!(
            should_notify(&ctx),
            NotificationVerdict::DailyBriefingOnly,
            "compromise + contained must NOT page the operator (it's already handled)"
        );
    }

    #[test]
    fn active_intrusion_not_contained_sends() {
        let ctx = make_ctx(
            "critical",
            "killchain.reverse_shell",
            false,
            true,
            false,
            false,
        );
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn active_intrusion_contained_defers() {
        let ctx = make_ctx(
            "critical",
            "killchain.reverse_shell",
            true,
            true,
            false,
            false,
        );
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn contained_threat_defers() {
        let ctx = make_ctx("high", "ssh_bruteforce", true, false, false, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn honeypot_probe_drops() {
        let ctx = make_ctx("low", "honeypot", false, false, false, true);
        assert_eq!(should_notify(&ctx), NotificationVerdict::Drop);
    }

    #[test]
    fn regular_scan_defers() {
        let ctx = make_ctx("medium", "port_scan", false, false, false, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn shield_blocked_defers() {
        let ctx = make_ctx("high", "shield", true, false, false, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn firmware_monitoring_defers() {
        let ctx = make_ctx("medium", "firmware", false, false, false, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn firmware_rootkit_compromise_sends() {
        let ctx = make_ctx("critical", "firmware", false, false, true, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn mesh_block_defers() {
        let ctx = NotificationContext::for_mesh_block();
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn autofp_suggestion_defers() {
        let ctx = NotificationContext::for_autofp_suggestion();
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn honeypot_session_blocked_defers() {
        let ctx = NotificationContext::for_honeypot_session(false, true);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn honeypot_session_probe_only_drops() {
        let ctx = NotificationContext::for_honeypot_session(true, false);
        assert_eq!(should_notify(&ctx), NotificationVerdict::Drop);
    }

    #[test]
    fn advisory_high_risk_sends() {
        let ctx = NotificationContext::for_advisory_ignored(85);
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn advisory_low_risk_defers() {
        let ctx = NotificationContext::for_advisory_ignored(50);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    // -- Burst tracker tests --

    #[test]
    fn burst_tracker_fires_at_threshold() {
        let tracker = BurstTracker::new();
        for _ in 0..49 {
            assert!(tracker
                .record_contained("DDoS / flood", Some("1.1.1.1"))
                .is_none());
        }
        // 50th should trigger.
        let result = tracker.record_contained("DDoS / flood", Some("1.1.1.1"));
        assert!(result.is_some());
        assert_eq!(result.unwrap().total, 50);
    }

    #[test]
    fn burst_tracker_fires_only_once() {
        let tracker = BurstTracker::new();
        for _ in 0..50 {
            tracker.record_contained("Scans & probes", Some("2.2.2.2"));
        }
        // Additional records should not fire again (fire-once-per-window).
        assert!(tracker
            .record_contained("Scans & probes", Some("2.2.2.2"))
            .is_none());
        assert!(tracker
            .record_contained("Scans & probes", Some("2.2.2.2"))
            .is_none());
    }

    #[test]
    fn burst_tracker_count() {
        let tracker = BurstTracker::new();
        tracker.record_contained("Scans & probes", None);
        tracker.record_contained("Scans & probes", None);
        tracker.record_contained("Scans & probes", None);
        assert_eq!(tracker.count(), 3);
    }

    /// The whole point of this PR: feeding 50 mixed-category contained
    /// threats returns a summary whose breakdown is correct — total, the
    /// top categories sorted by count descending, and distinct sources.
    #[test]
    fn burst_tracker_breakdown_is_correct_on_fire() {
        let tracker = BurstTracker::new();
        // 30 scans (from 3 IPs), 15 brute force (from 2 IPs), 5 ddos (no IP).
        // Mixed interleaving so the threshold lands on event 50 regardless.
        for i in 0..30 {
            let ip = format!("10.0.0.{}", i % 3); // 3 distinct scan IPs
            assert!(tracker
                .record_contained("Scans & probes", Some(&ip))
                .is_none());
        }
        for i in 0..15 {
            let ip = format!("10.1.1.{}", i % 2); // 2 distinct brute IPs
            assert!(tracker
                .record_contained("Password-guessing (brute force)", Some(&ip))
                .is_none());
        }
        // events 46..49 are ddos (no IP), the 50th fires.
        for _ in 0..4 {
            assert!(tracker.record_contained("DDoS / flood", None).is_none());
        }
        let summary = tracker
            .record_contained("DDoS / flood", None)
            .expect("50th contained threat fires the burst summary");

        assert_eq!(summary.total, 50);
        // Sorted desc by count: scans(30) > brute(15) > ddos(5).
        assert_eq!(
            summary.top_categories,
            vec![
                ("Scans & probes".to_string(), 30),
                ("Password-guessing (brute force)".to_string(), 15),
                ("DDoS / flood".to_string(), 5),
            ]
        );
        // 3 scan IPs + 2 brute IPs = 5 distinct (ddos had no IP).
        assert_eq!(summary.distinct_sources, 5);
        // The tracker is host-agnostic; the caller fills host.
        assert!(summary.host.is_empty());

        // 51st returns None (fire-once-per-window).
        assert!(tracker.record_contained("DDoS / flood", None).is_none());
    }

    #[test]
    fn burst_tracker_top_categories_capped_at_three() {
        let tracker = BurstTracker::new();
        // 5 distinct categories, decreasing counts so the order is unambiguous.
        let plan = [
            ("Scans & probes", 20),
            ("DDoS / flood", 15),
            ("Exploit / C2 attempts", 8),
            ("Password-guessing (brute force)", 4),
            ("Other suspicious activity", 3),
        ];
        let mut fired = None;
        for (cat, n) in plan {
            for _ in 0..n {
                if let Some(s) = tracker.record_contained(cat, None) {
                    fired = Some(s);
                }
            }
        }
        let summary = fired.expect("threshold crossed");
        // Only the top 3 by count survive.
        assert_eq!(summary.top_categories.len(), 3);
        assert_eq!(summary.top_categories[0].0, "Scans & probes");
        assert_eq!(summary.top_categories[1].0, "DDoS / flood");
        assert_eq!(summary.top_categories[2].0, "Exploit / C2 attempts");
    }

    #[test]
    fn burst_tracker_window_reset_clears_breakdown() {
        let tracker = BurstTracker::new();
        for _ in 0..10 {
            tracker.record_contained("Scans & probes", Some("9.9.9.9"));
        }
        assert_eq!(tracker.count(), 10);
        // Force the window to have started > BURST_WINDOW_SECS ago.
        {
            let mut start = tracker.window_start.lock().unwrap();
            *start = Utc::now() - chrono::Duration::seconds(BURST_WINDOW_SECS + 1);
        }
        // Next record sees the expired window, resets count + categories + sources.
        let _ = tracker.record_contained("DDoS / flood", Some("8.8.8.8"));
        assert_eq!(tracker.count(), 1);
        assert_eq!(
            tracker.categories.lock().unwrap().get("Scans & probes"),
            None
        );
        assert_eq!(
            tracker.categories.lock().unwrap().get("DDoS / flood"),
            Some(&1)
        );
        assert!(!tracker.sources.lock().unwrap().contains("9.9.9.9"));
        assert!(tracker.sources.lock().unwrap().contains("8.8.8.8"));
    }

    // -- burst_category classifier tests --

    #[test]
    fn burst_category_buckets() {
        // DDoS / flood
        assert_eq!(burst_category("packet_flood"), "DDoS / flood");
        assert_eq!(burst_category("shield"), "DDoS / flood");
        assert_eq!(burst_category("syn_flood"), "DDoS / flood");
        assert_eq!(burst_category("ddos"), "DDoS / flood");

        // Password-guessing (brute force)
        assert_eq!(
            burst_category("ssh_bruteforce"),
            "Password-guessing (brute force)"
        );
        assert_eq!(
            burst_category("credential_stuffing"),
            "Password-guessing (brute force)"
        );
        assert_eq!(
            burst_category("distributed_ssh"),
            "Password-guessing (brute force)"
        );

        // Scans & probes
        assert_eq!(burst_category("port_scan"), "Scans & probes");
        assert_eq!(burst_category("web_scan"), "Scans & probes");
        assert_eq!(burst_category("nmap_scan"), "Scans & probes");
        assert_eq!(burst_category("wordlist_scan"), "Scans & probes");
        assert_eq!(burst_category("user_agent_scanner"), "Scans & probes");

        // Exploit / C2 attempts (incl. killchain.* patterns)
        assert_eq!(
            burst_category("killchain.reverse_shell"),
            "Exploit / C2 attempts"
        );
        assert_eq!(burst_category("web_shell"), "Exploit / C2 attempts");
        assert_eq!(
            burst_category("killchain.exploit_c2"),
            "Exploit / C2 attempts"
        );
        assert_eq!(burst_category("process_injection"), "Exploit / C2 attempts");
        assert_eq!(burst_category("fileless"), "Exploit / C2 attempts");

        // Data-exfiltration attempts (must win over the generic c2/exploit bucket)
        assert_eq!(
            burst_category("killchain.data_exfil"),
            "Data-exfiltration attempts"
        );
        assert_eq!(
            burst_category("data_exfiltration"),
            "Data-exfiltration attempts"
        );

        // Privilege-escalation / escape
        assert_eq!(
            burst_category("container_escape"),
            "Privilege-escalation / escape"
        );
        assert_eq!(burst_category("privesc"), "Privilege-escalation / escape");
        assert_eq!(
            burst_category("setns_owner"),
            "Privilege-escalation / escape"
        );
        assert_eq!(
            burst_category("kernel_module_load"),
            "Privilege-escalation / escape"
        );

        // Default bucket
        assert_eq!(burst_category("honeypot"), "Other suspicious activity");
        assert_eq!(burst_category("something_new"), "Other suspicious activity");
    }

    #[test]
    fn burst_category_is_deterministic_and_case_insensitive() {
        assert_eq!(burst_category("PORT_SCAN"), burst_category("port_scan"));
        assert_eq!(
            burst_category("KillChain.Reverse_Shell"),
            "Exploit / C2 attempts"
        );
    }

    // -- format_burst_summary tests --

    fn sample_summary(host: &str) -> BurstSummary {
        BurstSummary {
            host: host.to_string(),
            total: 50,
            top_categories: vec![
                ("Scans & probes".to_string(), 30),
                ("Password-guessing (brute force)".to_string(), 15),
                ("DDoS / flood".to_string(), 5),
            ],
            distinct_sources: 12,
        }
    }

    #[test]
    fn format_burst_summary_renders_host_total_categories_and_sources() {
        let s = sample_summary("web-01");
        let msg = format_burst_summary("web-01", &s);

        // Host prefix present in the header.
        assert!(msg.contains("[web-01] Under attack"), "msg was: {msg}");
        // {total}+ (honest — fires at the threshold, not the final total).
        assert!(msg.contains("<b>50+</b>"), "msg was: {msg}");
        // Each category line with its count.
        assert!(msg.contains("\u{2022} Scans &amp; probes \u{2014} 30"));
        assert!(msg.contains("\u{2022} Password-guessing (brute force) \u{2014} 15"));
        assert!(msg.contains("\u{2022} DDoS / flood \u{2014} 5"));
        // Source count.
        assert!(msg.contains("From ~12 different IPs."));
        // Reassurance section present.
        assert!(msg.contains("<b>Should you worry?</b> No"));
    }

    #[test]
    fn format_burst_summary_escapes_host_html() {
        let s = sample_summary("<b>evil</b>&host");
        let msg = format_burst_summary("<b>evil</b>&host", &s);
        // The raw host markup must be escaped, never injected as live HTML.
        assert!(
            msg.contains("[&lt;b&gt;evil&lt;/b&gt;&amp;host]"),
            "msg was: {msg}"
        );
        assert!(!msg.contains("[<b>evil</b>&host]"));
    }

    #[test]
    fn format_burst_summary_empty_host_omits_prefix() {
        let s = sample_summary("");
        let msg = format_burst_summary("", &s);
        // No leading "[...] " bracket when host is unknown.
        assert!(
            msg.starts_with("\u{1f6e1}\u{fe0f} <b>Under attack"),
            "msg was: {msg}"
        );
        assert!(!msg.contains("[] "));
    }

    #[test]
    fn format_burst_summary_renders_only_present_categories() {
        let mut s = sample_summary("h");
        s.top_categories = vec![("DDoS / flood".to_string(), 50)];
        s.distinct_sources = 0;
        let msg = format_burst_summary("h", &s);
        assert!(msg.contains("\u{2022} DDoS / flood \u{2014} 50"));
        assert!(!msg.contains("Scans &amp; probes"));
        // distinct_sources == 0 -> no "From ~N IPs" line.
        assert!(!msg.contains("different IPs"));
    }

    // -- NotificationContext builder tests --

    #[test]
    fn from_incident_detects_compromise() {
        let incident = innerwarden_core::incident::Incident {
            ts: Utc::now(),
            host: "test".into(),
            incident_id: "data_exfil:1.2.3.4:abc".into(),
            severity: innerwarden_core::event::Severity::Critical,
            title: "Data exfiltration".into(),
            summary: "".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["data_exfiltration".into()],
            entities: vec![],
        };
        let ctx = NotificationContext::from_incident(&incident);
        assert!(ctx.is_compromise);
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn from_incident_contained_defers() {
        let incident = innerwarden_core::incident::Incident {
            ts: Utc::now(),
            host: "test".into(),
            incident_id: "ssh_bruteforce:1.2.3.4:abc".into(),
            severity: innerwarden_core::event::Severity::High,
            title: "SSH brute force".into(),
            summary: "".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["blocked".into()],
            entities: vec![],
        };
        let ctx = NotificationContext::from_incident(&incident);
        assert!(ctx.is_contained);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    #[test]
    fn from_killchain_json_active_intrusion() {
        let inc = serde_json::json!({
            "severity": "critical",
            "evidence": {
                "pattern": "reverse_shell",
                "flags": 7  // socket + dup_stdin + dup_stdout = 3 bits
            }
        });
        let ctx = NotificationContext::from_killchain_json(&inc);
        assert!(ctx.is_active_intrusion);
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn from_killchain_json_data_exfil_compromise() {
        let inc = serde_json::json!({
            "severity": "critical",
            "evidence": {
                "pattern": "data_exfil",
                "flags": 257  // sensitive_read + socket
            }
        });
        let ctx = NotificationContext::from_killchain_json(&inc);
        assert!(ctx.is_compromise);
        assert_eq!(should_notify(&ctx), NotificationVerdict::SendNow);
    }

    #[test]
    fn from_shield_blocked_defers() {
        let inc = serde_json::json!({
            "severity": "high",
            "outcome": "blocked"
        });
        let ctx = NotificationContext::from_shield_json(&inc);
        assert!(ctx.is_contained);
        assert_eq!(should_notify(&ctx), NotificationVerdict::DailyBriefingOnly);
    }

    // ─── Spec 024 contract tests ───────────────────────────────────────
    //
    // The notification_gate contract:
    //
    //   should_notify(ctx) ∈ { SendNow, DailyBriefingOnly, Drop }
    //
    // — the set is closed. No I/O, no side effects, no async, no state. Any
    // new verdict variant is a breaking change to downstream consumers and
    // must be reflected here. Keeping this contract explicit is the sole
    // reason the gate exists as a separate module: callers can reason about
    // the space of possible outcomes without reading implementation.
    //
    // Every matrix cell below represents one logical branch of the gate;
    // adding or removing a branch without updating this table means the
    // gate's behavioural envelope shifted and downstream callers
    // (Telegram, briefing, burst tracker) may silently drift.

    #[test]
    fn contract_verdict_is_one_of_three_enum_variants_exhaustive_match() {
        // Compile-time proof: an exhaustive match covers exactly the three
        // verdicts. If a fourth is added, this test stops compiling and
        // forces the author to explicitly update callers.
        let ctx = make_ctx("low", "noop", false, false, false, false);
        let verdict = should_notify(&ctx);
        match verdict {
            NotificationVerdict::SendNow
            | NotificationVerdict::DailyBriefingOnly
            | NotificationVerdict::Drop => {}
        }
    }

    #[test]
    fn contract_pure_function_no_mutation_of_context() {
        // The gate MUST NOT mutate its context. Downstream callers share
        // the context across verdicts and can observe drift if the gate
        // modifies flags. We assert structural equality pre/post.
        let ctx_before = make_ctx(
            "critical",
            "killchain.reverse_shell",
            true,
            true,
            false,
            false,
        );
        let ctx_after = make_ctx(
            "critical",
            "killchain.reverse_shell",
            true,
            true,
            false,
            false,
        );
        let _ = should_notify(&ctx_before);
        assert_eq!(ctx_before.detector, ctx_after.detector);
        assert_eq!(ctx_before.is_contained, ctx_after.is_contained);
        assert_eq!(
            ctx_before.is_active_intrusion,
            ctx_after.is_active_intrusion
        );
        assert_eq!(ctx_before.is_compromise, ctx_after.is_compromise);
        assert_eq!(ctx_before.is_honeypot_probe, ctx_after.is_honeypot_probe);
    }

    #[test]
    fn contract_full_precedence_table() {
        // Full Cartesian precedence table. Each row is (compromise, active,
        // contained, probe) → verdict. Redundant-by-design with the
        // narrower tests above; lives here as the single-place rulebook
        // an operator can point at when asking "why did this fire?".
        type Row = ((bool, bool, bool, bool), NotificationVerdict);
        let rows: &[Row] = &[
            // 2026-05-06 fix (Bug A — notification noise): compromise
            // ALONE no longer forces SendNow. We require
            // `compromise && !contained`, because the prod operator
            // received 3 Critical pings for the same `kill_chain:
            // detected:DATA_EXFIL` incident even though killchain inline
            // had already auto-blocked the IP. The contained branch
            // defers to the daily briefing.
            ((true, false, false, false), NotificationVerdict::SendNow),
            ((true, true, false, false), NotificationVerdict::SendNow),
            // compromise + contained: defer (the kill chain already ran).
            (
                (true, false, true, false),
                NotificationVerdict::DailyBriefingOnly,
            ),
            ((true, false, false, true), NotificationVerdict::SendNow),
            // active + not-contained: send.
            ((false, true, false, false), NotificationVerdict::SendNow),
            // active + contained: defer.
            (
                (false, true, true, false),
                NotificationVerdict::DailyBriefingOnly,
            ),
            // contained alone: defer.
            (
                (false, false, true, false),
                NotificationVerdict::DailyBriefingOnly,
            ),
            // probe only (not contained): drop. This is the noise floor.
            ((false, false, false, true), NotificationVerdict::Drop),
            // nothing special: defer.
            (
                (false, false, false, false),
                NotificationVerdict::DailyBriefingOnly,
            ),
        ];
        for &((compromise, active, contained, probe), want) in rows {
            let ctx = make_ctx("medium", "test", contained, active, compromise, probe);
            let got = should_notify(&ctx);
            assert_eq!(
                got, want,
                "contract regression: (compromise={compromise}, active={active}, contained={contained}, probe={probe}) expected {want:?} got {got:?}"
            );
        }
    }

    #[test]
    fn should_notify_with_counter_increments_only_for_suppressed_verdicts() {
        let counter = AtomicU64::new(0);

        let send_now = make_ctx("critical", "killchain.data_exfil", false, true, true, false);
        let deferred = make_ctx("high", "ssh_bruteforce", true, false, false, false);
        let dropped = make_ctx("low", "honeypot", false, false, false, true);

        assert_eq!(
            should_notify_with_counter(&send_now, &counter),
            NotificationVerdict::SendNow
        );
        assert_eq!(counter.load(Ordering::Relaxed), 0);

        assert_eq!(
            should_notify_with_counter(&deferred, &counter),
            NotificationVerdict::DailyBriefingOnly
        );
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        assert_eq!(
            should_notify_with_counter(&dropped, &counter),
            NotificationVerdict::Drop
        );
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }
}
