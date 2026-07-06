use super::formatting::{escape_html, friendly_detector_name};
use crate::detector_catalog;

/// A blocked-source line for the briefing: an IP, how many times it was
/// blocked today, and whether it is still contained at send time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedSource {
    pub ip: String,
    pub block_count: u32,
    /// Live-verified: the firewall/XDP rule for this IP is still active.
    pub still_contained: bool,
    /// 2-letter country code if cheaply known (geo cache hit); else None.
    pub country_code: Option<String>,
}

/// Everything the redesigned Daily Security Briefing needs, assembled by
/// `narrative_daily_summary::build_daily_digest_text` from canonical state.
///
/// Spec (2026-06): the briefing is a diligent employee's daily report to a
/// non-technical boss who must still learn enough TECHNICALLY to ask for the
/// right fix. Every number is explained, every category line is boss-readable
/// with a one-clause "why it matters", and the "Needs review" count is the
/// LIVE dashboard number — never a stale grouped counter.
pub struct DailyBriefingData {
    /// Total events the agent analysed today (`incidents_today`).
    pub events: u32,
    /// Decisions the agent recorded today (can exceed `events`: one event may
    /// yield several decisions).
    pub decisions: u32,
    /// Post-posture Critical compromises.
    pub critical: u32,
    /// Post-posture High-severity threats.
    pub high: u32,
    /// LIVE "Needs review" count — the SAME number the dashboard "Needs review"
    /// tile shows (open cases whose most-recent decision is still needs_review).
    /// NOT the transient grouped counter.
    pub needs_review_live: u32,
    /// Threat groups the agent auto-resolved (informational only).
    pub auto_resolved_groups: u32,
    /// Per-category counts (detector -> count), already merged from the
    /// deferred breakdown + the day's incident detector tally.
    pub categories: Vec<(String, u32)>,
    /// Top blocked source IPs today, highest block-count first.
    pub blocked_sources: Vec<BlockedSource>,
    /// Total unique IPs blocked today.
    pub unique_blocked_ips: u32,
    /// How many of those are still contained at send time.
    pub still_contained: u32,
    /// Optional one-line proactive suggestion (e.g. key-only SSH).
    pub proactive: Option<String>,
}

/// Convert a 2-letter ISO country code to a flag emoji (reused locally so the
/// briefing body can render `🇨🇳` next to a blocked IP). Empty on bad input.
fn flag(code: &str) -> String {
    super::formatting::country_flag_emoji_pub(code)
}

/// How many category lines to show before collapsing the long tail.
const MAX_CATEGORY_LINES: usize = 8;
/// How many blocked-source IPs to show before collapsing.
const MAX_BLOCKED_SOURCES: usize = 5;

/// Plain bottom-line verdict in the confident guardian voice. The boss reads
/// ONE sentence and knows whether to relax or act. A real compromise drops the
/// jokes entirely; everything else stays cocky-but-competent.
fn verdict_line(d: &DailyBriefingData) -> String {
    // Override 1: a real compromise lands. No jokes — the boss is needed.
    if d.critical > 0 {
        return "\u{1f6a8} <b>Okay, no jokes. Someone landed a hit. Details below, and I need \
                you on it.</b>"
            .to_string();
    }
    // Override 2: calls are the operator's to make.
    if d.needs_review_live > 0 {
        let call = if d.needs_review_live == 1 {
            "call"
        } else {
            "call(s)"
        };
        return format!(
            "\u{26a0}\u{fe0f} <b>Mostly handled, but {} {call} are yours to make.</b>",
            d.needs_review_live
        );
    }
    // Quiet night: nothing worth the boss's time.
    if d.events == 0 {
        return "\u{2705} <b>Quiet night. Walked the perimeter, found nothing worth your time. \
                We're good.</b>"
            .to_string();
    }
    // Busy but all contained: a lot of knocking, nobody got in.
    if d.high > 0 || d.unique_blocked_ips > 5 {
        return "\u{2705} <b>Busy night on the wall. A lot of knocking. Nobody got in, not in \
                my house.</b>"
            .to_string();
    }
    // Everything handled automatically.
    "\u{2705} <b>Handled the whole night myself. Nobody got in. You're welcome.</b>".to_string()
}

/// The actionable "Needs review" block. Always points at something real: when
/// the live count is 0 it reassures instead of sending the operator to an empty
/// queue.
fn needs_review_block(n: u32) -> String {
    if n == 0 {
        "\u{2705} <b>Nothing for you tonight. I'm a professional. Go back to sleep.</b>".to_string()
    } else {
        let thing = if n == 1 { "thing" } else { "thing(s)" };
        format!(
            "\u{26a0}\u{fe0f} <b>{n} {thing} have your name on them.</b> I could guess, but \
             then you'd yell at me. Open InnerWarden \u{2192} Cases \u{2192} \"Needs review\" and \
             hit Block, Dismiss, or Monitor. (Live count. Already sorted them? It says 0 and we \
             never speak of this again.)"
        )
    }
}

/// Render the redesigned Daily Security Briefing. Boss-readable for EVERY
/// profile; `technical` just appends the raw counters power users want at the
/// end, it does not switch to jargon.
pub fn format_daily_briefing(d: &DailyBriefingData, technical: bool) -> String {
    let mut msg = String::new();

    // 1. Header + plain bottom-line verdict.
    msg.push_str("\u{1f6e1}\u{fe0f} <b>Daily Security Briefing</b>\n\n");
    msg.push_str(&verdict_line(d));

    // 2. Explained headline numbers in the guardian voice. One clause each
    // (kills the "more decisions than events?" confusion + the cryptic jargon).
    msg.push_str(&format!(
        "\n\nOh hey, you're awake. While you were off doing whatever it is you do, I worked the \
         door all night. Here's the night shift:\n\
         \u{00a0}\u{00a0}\u{2022} <b>{decisions}</b> calls made across <b>{events}</b> security \
         events (block, babysit, or \"yeah fine, come in\"). One event can take a few calls, \
         don't @ me.\n\
         \u{00a0}\u{00a0}\u{2022} Break-ins: <b>{critical}</b>. Serious attempts: <b>{high}</b>, \
         all face-planted into the wall (and that's after I grade on a curve for how locked down \
         this box already is).",
        decisions = d.decisions,
        events = d.events,
        critical = d.critical,
        high = d.high,
    ));

    // 3. Blocked sources: what a real daily report leads with.
    if d.unique_blocked_ips > 0 {
        msg.push_str(&format!(
            "\n\n\u{1f6ab} <b>Bouncer count: {} IP(s) shown the door</b> ({} still contained):",
            d.unique_blocked_ips, d.still_contained
        ));
        for src in d.blocked_sources.iter().take(MAX_BLOCKED_SOURCES) {
            let flag_str = src
                .country_code
                .as_deref()
                .map(|c| {
                    let f = flag(c);
                    if f.is_empty() {
                        String::new()
                    } else {
                        format!(" {f}")
                    }
                })
                .unwrap_or_default();
            let contained = if src.still_contained {
                ""
            } else {
                " <i>(block expired)</i>"
            };
            msg.push_str(&format!(
                "\n\u{00a0}\u{00a0}\u{2022} <code>{ip}</code>{flag_str} \u{00d7}{n}{contained}",
                ip = escape_html(&src.ip),
                n = src.block_count,
            ));
        }
        let shown = d.blocked_sources.len().min(MAX_BLOCKED_SOURCES);
        if d.blocked_sources.len() > shown {
            msg.push_str(&format!(
                "\n\u{00a0}\u{00a0}\u{2022} … and {} more (see dashboard)",
                d.blocked_sources.len() - shown
            ));
        }
    }

    // 4. What InnerWarden handled, by category. Each line stays boss-readable
    // with a one-clause "why it matters", routed through the catalog. No raw
    // names. The personality lives in the header, not the factual glosses.
    if !d.categories.is_empty() {
        msg.push_str("\n\n\u{1f916} <b>What I shut down (and why you'd care):</b>");
        for (detector, count) in d.categories.iter().take(MAX_CATEGORY_LINES) {
            let gloss = escape_html(&detector_catalog::digest_gloss(detector));
            msg.push_str(&format!(
                "\n\u{00a0}\u{00a0}\u{2022} <b>{count}\u{00d7}</b> {gloss}"
            ));
        }
        if d.categories.len() > MAX_CATEGORY_LINES {
            let tail: u32 = d
                .categories
                .iter()
                .skip(MAX_CATEGORY_LINES)
                .map(|(_, c)| *c)
                .sum();
            let more = d.categories.len() - MAX_CATEGORY_LINES;
            msg.push_str(&format!(
                "\n\u{00a0}\u{00a0}\u{2022} … and {tail} more across {more} other categor{} (see dashboard)",
                if more == 1 { "y" } else { "ies" }
            ));
        }
    }

    // 5. Auto-resolved (informational only).
    if d.auto_resolved_groups > 0 {
        msg.push_str(&format!(
            "\n\n\u{2705} {} threat group(s) sorted automatically. You're welcome.",
            d.auto_resolved_groups
        ));
    }

    // 6. The actionable needs-review block: never points at nothing.
    msg.push_str("\n\n");
    msg.push_str(&needs_review_block(d.needs_review_live));

    // 7. Optional proactive suggestion. The tip stays factual/actionable; only
    // the label carries the persona.
    if let Some(tip) = &d.proactive {
        msg.push_str(&format!(
            "\n\n\u{1f4a1} <b>Real talk:</b> {}",
            escape_html(tip)
        ));
    }

    // 8. Technical profile: append the raw counters power users asked for.
    // Additive, still boss-readable above.
    if technical {
        msg.push_str(&format!(
            "\n\n\u{1f4ca} <i>Technical: {events} events · {decisions} decisions · \
             {critical} critical · {high} high · {blocked} IPs blocked · \
             {review} needs-review (live)</i>",
            events = d.events,
            decisions = d.decisions,
            critical = d.critical,
            high = d.high,
            blocked = d.unique_blocked_ips,
            review = d.needs_review_live,
        ));
    }

    // 9. Closer (once, at the very end): the guardian signing off.
    msg.push_str("\n\nGo on, I've got the place. As usual.");

    msg
}

/// Format the daily digest message.
/// Simple mode: friendly, non-technical. Technical mode: concise stats.
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
    if is_simple {
        // Spec 044 Phase 1 (2026-05-09): the legacy `100 − critical*20 − high*5` "Health" score
        // clamped to 0 whenever the day saw more than ~5 high-severity incidents — even when
        // every one of those was auto-resolved silently. The score lied about effective host
        // health, so it is removed. Posture-aware severity (Phase 3) replaces the intent.
        let footer = if critical_count == 0 && high_count == 0 {
            "All clear. Nothing needs you."
        } else {
            "Auto-handled \u{2014} review when convenient."
        };

        format!(
            "\u{2600}\u{fe0f} Good morning! Your server in the last 24h:\n\
             \n\
             \u{00a0}\u{00a0}{blocks_today} attacks blocked\n\
             \u{00a0}\u{00a0}{critical_count} critical threats\n\
             \n\
             {footer}"
        )
    } else {
        let date = chrono::Local::now().format("%Y-%m-%d");
        format!(
            "\u{1f4ca} Daily digest ({date}):\n\
             \u{00a0}\u{00a0}Total: {incidents_today} incidents, {blocks_today} blocks\n\
             \u{00a0}\u{00a0}{top_detector}: {top_count}\n\
             \u{00a0}\u{00a0}Critical: {critical_count} | High: {high_count}",
            top_detector = escape_html(top_detector),
        )
    }
}

/// Pipeline digest stats for enriched daily digest.
///
/// Superseded 2026-06 by [`DailyBriefingData`] + [`format_daily_briefing`]
/// (the boss-readable redesign). Kept with `#[allow(dead_code)]` because its
/// regression anchors (health-score removal, the "All clear" honesty gate, the
/// "Made N decisions" wording) still document hard-won copy decisions; mirrors
/// how the pre-enriched [`format_daily_digest`] above was retired.
#[allow(dead_code)]
pub struct PipelineDigestStats {
    pub suppressed_count: u32,
    pub auto_resolved_groups: u32,
    pub needs_review_groups: u32,
    /// Incidents deferred from immediate Telegram (per-detector counts).
    pub deferred: Vec<(String, u32)>,
}

/// Format an enriched daily digest with pipeline grouping stats.
///
/// Superseded 2026-06 by [`format_daily_briefing`]; retained `#[allow(dead_code)]`
/// for its copy-regression anchors (see [`PipelineDigestStats`]).
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn format_daily_digest_enriched(
    incidents_today: u32,
    blocks_today: u32,
    critical_count: u32,
    high_count: u32,
    top_detector: &str,
    top_count: u32,
    is_simple: bool,
    pipeline: &PipelineDigestStats,
) -> String {
    // Spec 044 Phase 1 (2026-05-09): "Server health: X/100" line removed. The formula
    // (100 − critical*20 − high*5, clamp 0..100) clamped to 0 whenever the day saw more than
    // ~5 high-severity incidents, even when every one was auto-resolved silently — the same
    // briefing that read "🔴 0/100" listed "✅ 160 threat groups auto-resolved" two lines
    // below it. The score did not credit auto-resolution, did not subtract for hardening
    // posture, and so was anti-informative. Phase 3 of spec 044 introduces posture-aware
    // severity to fix the underlying signal-vs-noise problem; this phase just stops lying.
    if is_simple {
        // Spec 044 Phase 4 (2026-05-09): "real compromises" wording. The
        // counts here are POST-downgrade (see narrative_daily_summary.rs::
        // maybe_write_daily_summary_and_digest, which routes every
        // incident through posture::downgrade::effective_severity before
        // tallying). So a "high" count of 0 with 60 silent SSH
        // bruteforces below means "60 attempts, none would have worked
        // given the host's posture", not "no high-severity detections
        // happened today". The wording reflects what the count means.
        // Header counter rename 2026-05-24: "Blocked N attacks" was
        // operator-misleading because `blocks_today` counts ALL
        // decisions (block + monitor + honeypot + suspend + dismiss
        // + ignore + …), not just blocks. Operators saw the body list
        // "282 SSH brute force attempts blocked / 105 credential
        // stuffing attempts blocked" right under "Blocked 4 attacks"
        // and the arithmetic obviously did not add up. The accurate
        // framing is: this is the number of times the agent reached a
        // decision (which the body then breaks down per detector).
        let mut msg = format!(
            "\u{1f6e1}\u{fe0f} <b>Daily Security Briefing</b>\n\
             \n\
             While you were away, InnerWarden:\n\
             \u{00a0}\u{00a0}\u{2022} Made <b>{blocks_today}</b> autonomous decisions\n\
             \u{00a0}\u{00a0}\u{2022} Analyzed <b>{incidents_today}</b> security events\n\
             \u{00a0}\u{00a0}\u{2022} Detected <b>{critical_count}</b> real compromises, <b>{high_count}</b> high-severity threats (post-posture)"
        );

        // Deferred incident breakdown — the bulk of silent work.
        if !pipeline.deferred.is_empty() {
            msg.push_str("\n\n\u{1f916} <b>Handled silently:</b>");
            for (detector, count) in &pipeline.deferred {
                let label = escape_html(friendly_detector_name(detector));
                msg.push_str(&format!("\n\u{00a0}\u{00a0}\u{2022} {count} {label}"));
            }
        }

        if pipeline.auto_resolved_groups > 0 {
            msg.push_str(&format!(
                "\n\n\u{2705} {} threat groups auto-resolved",
                pipeline.auto_resolved_groups
            ));
        }

        if pipeline.needs_review_groups > 0 {
            msg.push_str(&format!(
                "\n\n\u{26a0}\u{fe0f} <b>{} groups need your review</b>",
                pipeline.needs_review_groups
            ));
        } else if critical_count > 0 || high_count > 0 || !pipeline.deferred.is_empty() {
            // Bug 5 (2026-05-06): the same briefing announced
            // "Detected N critical, M high severity threats" + listed
            // deferred detectors under "Handled silently:" — saying
            // "All clear. Nothing needs you." right after lied to the
            // operator. Operator-honesty hard rule: only emit "All
            // clear" when there is genuinely nothing to acknowledge.
            // Auto-resolved is fine on its own; high+ activity or any
            // deferred entry means the briefing must say so honestly.
            msg.push_str("\n\n\u{2705} Auto-handled \u{2014} review when convenient.");
        } else {
            msg.push_str("\n\n\u{2705} All clear. Nothing needs you.");
        }

        msg
    } else {
        let date = chrono::Local::now().format("%Y-%m-%d");
        let mut msg = format!(
            "\u{1f4ca} <b>Daily Digest</b> ({date})\n\
             \n\
             Incidents: {incidents_today} | Blocks: {blocks_today}\n\
             Critical: {critical_count} | High: {high_count}\n\
             Top: {top_detector} ({top_count})",
            top_detector = escape_html(top_detector),
        );

        if pipeline.suppressed_count > 0 || pipeline.auto_resolved_groups > 0 {
            msg.push_str(&format!(
                "\nPipeline: {} grouped, {} auto-resolved, {} need review",
                pipeline.suppressed_count,
                pipeline.auto_resolved_groups,
                pipeline.needs_review_groups,
            ));
        }

        if !pipeline.deferred.is_empty() {
            msg.push_str("\nDeferred:");
            for (detector, count) in &pipeline.deferred {
                let detector = escape_html(detector);
                msg.push_str(&format!(" {detector}={count}"));
            }
        }

        msg
    }
}

// ---------------------------------------------------------------------------
// Simple /status
// ---------------------------------------------------------------------------

/// Format a simple /status response.
/// Returns the semaphore status message for non-technical users.
pub fn format_simple_status(
    has_critical_last_24h: bool,
    has_high_last_hour: bool,
    has_critical_last_hour: bool,
    uptime_days: u64,
    total_blocked: u64,
    last_threat_ago: &str,
) -> String {
    let (semaphore, status_word) = if has_critical_last_hour {
        ("\u{1f534}", "needs attention") // 🔴
    } else if has_high_last_hour {
        ("\u{1f7e1}", "under watch") // 🟡
    } else {
        ("\u{1f7e2}", "safe") // 🟢
    };

    // Suppress "no critical" label when there are none
    let _ = has_critical_last_24h;

    format!(
        "{semaphore} <b>Server is {status_word}</b>\n\
         \n\
         \u{1f6e1}\u{fe0f} Protected for <b>{uptime_days}</b> days\n\
         \u{1f6ab} <b>{total_blocked}</b> attacks blocked\n\
         \u{23f1}\u{fe0f} Last threat: {last_threat_ago}",
        last_threat_ago = escape_html(last_threat_ago),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_pipeline() -> PipelineDigestStats {
        PipelineDigestStats {
            suppressed_count: 0,
            auto_resolved_groups: 0,
            needs_review_groups: 0,
            deferred: Vec::new(),
        }
    }

    #[test]
    fn format_daily_digest_simple_zero_incidents_is_all_clear() {
        let msg = format_daily_digest(0, 0, 0, 0, "n/a", 0, true);
        assert!(msg.contains("Good morning"));
        assert!(msg.contains("0 attacks blocked"));
        assert!(msg.contains("0 critical threats"));
        assert!(msg.contains("All clear"));
    }

    /// Spec 044 Phase 1 anchor (2026-05-09): the legacy `Health: X/100` line was
    /// removed because the underlying formula (`100 − critical*20 − high*5`, clamped)
    /// reported `🔴 0/100` whenever the day saw more than ~5 high-severity incidents,
    /// even when every one was auto-resolved silently. Pin the absence so a future
    /// "let's add a score back" change forces an explicit conversation rather than
    /// regressing the briefing copy.
    #[test]
    fn format_daily_digest_omits_health_score() {
        let cases = [
            // Zero state.
            format_daily_digest(0, 0, 0, 0, "n/a", 0, true),
            format_daily_digest(0, 0, 0, 0, "n/a", 0, false),
            // The exact production shape the operator hit on 2026-05-09 (1 critical + 61 high
            // → legacy formula clamps to 0).
            format_daily_digest(316, 47, 1, 61, "proto_anomaly", 169, true),
            format_daily_digest(316, 47, 1, 61, "proto_anomaly", 169, false),
        ];
        for msg in &cases {
            assert!(!msg.contains("Health:"), "found Health: in: {msg}");
            assert!(!msg.contains("/100"), "found /100 in: {msg}");
            assert!(
                !msg.contains("\u{1f7e2}"),
                "found 🟢 (health emoji) in: {msg}"
            );
            assert!(
                !msg.contains("\u{1f7e1}"),
                "found 🟡 (health emoji) in: {msg}"
            );
            assert!(
                !msg.contains("\u{1f534}"),
                "found 🔴 (health emoji) in: {msg}"
            );
        }
    }

    #[test]
    fn format_daily_digest_technical_includes_counts_and_top_detector() {
        let msg = format_daily_digest(7, 3, 1, 2, "WAF/cve-2025-1234", 4, false);
        assert!(msg.contains("Daily digest"));
        assert!(msg.contains("Total: 7 incidents, 3 blocks"));
        assert!(msg.contains("WAF/cve-2025-1234: 4"));
        assert!(msg.contains("Critical: 1 | High: 2"));
        // Technical mode does NOT include the simple-mode greeting.
        assert!(!msg.contains("Good morning"));
    }

    #[test]
    fn format_daily_digest_simple_vs_technical_differs() {
        let simple = format_daily_digest(5, 2, 1, 0, "rule_X", 1, true);
        let technical = format_daily_digest(5, 2, 1, 0, "rule_X", 1, false);
        assert_ne!(simple, technical);
        assert!(simple.contains("Good morning"));
        assert!(technical.contains("Daily digest"));
    }

    #[test]
    fn format_daily_digest_technical_html_escapes_top_detector() {
        let msg = format_daily_digest(0, 0, 0, 0, "evil<script>&", 0, false);
        assert!(msg.contains("evil&lt;script&gt;&amp;"));
        assert!(!msg.contains("evil<script>&:"));
    }

    #[test]
    fn format_daily_digest_enriched_zero_state_does_not_panic() {
        let msg = format_daily_digest_enriched(0, 0, 0, 0, "n/a", 0, true, &empty_pipeline());
        // Empty deferred + zero auto-resolved + zero needs-review -> ends with "All clear".
        assert!(msg.contains("Daily Security Briefing"));
        assert!(msg.contains("All clear. Nothing needs you."));
        assert!(!msg.contains("Handled silently:"));
        assert!(!msg.contains("threat groups auto-resolved"));
        assert!(!msg.contains("groups need your review"));
    }

    #[test]
    fn format_daily_digest_enriched_renders_deferred_entries() {
        let pipeline = PipelineDigestStats {
            suppressed_count: 4,
            auto_resolved_groups: 2,
            needs_review_groups: 0,
            deferred: vec![
                ("waf.path_traversal".to_string(), 12),
                ("waf.sql_injection".to_string(), 5),
            ],
        };

        let simple = format_daily_digest_enriched(20, 17, 0, 1, "waf", 12, true, &pipeline);
        assert!(simple.contains("Handled silently:"));
        // friendly_detector_name is exercised here; both counts must appear.
        assert!(simple.contains("12"));
        assert!(simple.contains("5"));
        assert!(simple.contains("2 threat groups auto-resolved"));
        // Bug 5 anchor (2026-05-06): with high_count=1 AND deferred non-empty,
        // the briefing MUST NOT say "All clear" — it must use the honest
        // "Auto-handled" copy instead.
        assert!(!simple.contains("All clear. Nothing needs you."));
        assert!(simple.contains("Auto-handled \u{2014} review when convenient."));

        let technical = format_daily_digest_enriched(20, 17, 0, 1, "waf", 12, false, &pipeline);
        assert!(technical.contains("Daily Digest"));
        assert!(technical.contains("Pipeline: 4 grouped, 2 auto-resolved, 0 need review"));
        assert!(technical.contains("Deferred:"));
        assert!(technical.contains("waf.path_traversal=12"));
        assert!(technical.contains("waf.sql_injection=5"));
    }

    #[test]
    fn format_daily_digest_enriched_simple_renders_needs_review_warning() {
        let pipeline = PipelineDigestStats {
            suppressed_count: 0,
            auto_resolved_groups: 0,
            needs_review_groups: 3,
            deferred: Vec::new(),
        };

        let msg = format_daily_digest_enriched(2, 1, 1, 0, "n/a", 0, true, &pipeline);
        assert!(msg.contains("3 groups need your review"));
        // "All clear" is replaced by the review warning when needs_review_groups > 0.
        assert!(!msg.contains("All clear. Nothing needs you."));
    }

    #[test]
    fn format_daily_digest_enriched_technical_html_escapes_top_detector() {
        let pipeline = empty_pipeline();
        let msg = format_daily_digest_enriched(1, 0, 0, 0, "evil<script>&", 1, false, &pipeline);
        assert!(msg.contains("evil&lt;script&gt;&amp;"));
    }

    /// Bug 5 anchor (2026-05-06 prod observation): operator saw the
    /// briefing emit "Detected 0 critical, 3 high severity threats"
    /// and immediately after "✅ All clear. Nothing needs you." That
    /// contradicted the same paragraph the operator had just read.
    /// The fix gates "All clear" on critical+high+deferred; this test
    /// pins the high_count > 0 branch.
    #[test]
    fn format_daily_digest_enriched_high_count_suppresses_all_clear() {
        let pipeline = empty_pipeline();
        let msg = format_daily_digest_enriched(5, 0, 0, 3, "n/a", 0, true, &pipeline);
        assert!(
            !msg.contains("All clear. Nothing needs you."),
            "high_count > 0 must suppress \"All clear\""
        );
        assert!(
            msg.contains("Auto-handled \u{2014} review when convenient."),
            "high_count > 0 must emit the honest auto-handled copy"
        );
    }

    /// Bug 5 anchor: critical_count > 0 must also suppress "All clear".
    #[test]
    fn format_daily_digest_enriched_critical_count_suppresses_all_clear() {
        let pipeline = empty_pipeline();
        let msg = format_daily_digest_enriched(5, 0, 1, 0, "n/a", 0, true, &pipeline);
        assert!(
            !msg.contains("All clear. Nothing needs you."),
            "critical_count > 0 must suppress \"All clear\""
        );
        assert!(msg.contains("Auto-handled \u{2014} review when convenient."));
    }

    /// Bug 5 anchor: any deferred entry (incident silently routed to
    /// "Handled silently:" list) must suppress "All clear" because the
    /// briefing already announces those detectors as something the
    /// operator can review.
    #[test]
    fn format_daily_digest_enriched_deferred_entry_suppresses_all_clear() {
        let pipeline = PipelineDigestStats {
            suppressed_count: 0,
            auto_resolved_groups: 0,
            needs_review_groups: 0,
            deferred: vec![("crontab_persistence".to_string(), 1)],
        };
        let msg = format_daily_digest_enriched(1, 0, 0, 0, "n/a", 0, true, &pipeline);
        assert!(
            !msg.contains("All clear. Nothing needs you."),
            "non-empty deferred must suppress \"All clear\""
        );
        assert!(msg.contains("Auto-handled \u{2014} review when convenient."));
        assert!(msg.contains("crontab_persistence") || msg.contains("Persistence"));
    }

    /// Bug 5 anchor: positive case — when there is genuinely no
    /// activity (zero counts AND empty deferred AND zero needs-review),
    /// "All clear" is still the right copy.
    #[test]
    fn format_daily_digest_enriched_truly_quiet_day_keeps_all_clear() {
        let pipeline = empty_pipeline();
        let msg = format_daily_digest_enriched(0, 0, 0, 0, "n/a", 0, true, &pipeline);
        assert!(msg.contains("All clear. Nothing needs you."));
        assert!(!msg.contains("Auto-handled"));
    }

    /// Spec 044 Phase 1 anchor (2026-05-09 prod observation): operator received
    /// `🔴 Server health: 0/100` while the same briefing reported `✅ 160 threat
    /// groups auto-resolved` immediately below — the score did not credit
    /// auto-resolution. This test reproduces the exact production input shape
    /// (1 critical + 61 high) plus a couple of representative cases and pins
    /// that the enriched briefing no longer contains the score line.
    #[test]
    fn format_daily_digest_enriched_omits_health_score() {
        let big_pipeline = PipelineDigestStats {
            suppressed_count: 30,
            auto_resolved_groups: 160,
            needs_review_groups: 30,
            deferred: vec![
                ("proto_anomaly".to_string(), 169),
                ("crontab_persistence".to_string(), 2),
            ],
        };
        let cases = [
            // Zero state, simple + technical.
            format_daily_digest_enriched(0, 0, 0, 0, "n/a", 0, true, &empty_pipeline()),
            format_daily_digest_enriched(0, 0, 0, 0, "n/a", 0, false, &empty_pipeline()),
            // The exact prod observation: 316 events, 47 blocks, 1 critical, 61 high — legacy
            // formula clamped to 0/100 with the 🔴 emoji.
            format_daily_digest_enriched(316, 47, 1, 61, "proto_anomaly", 169, true, &big_pipeline),
            format_daily_digest_enriched(
                316,
                47,
                1,
                61,
                "proto_anomaly",
                169,
                false,
                &big_pipeline,
            ),
        ];
        for msg in &cases {
            assert!(
                !msg.contains("Server health"),
                "found 'Server health' in: {msg}"
            );
            assert!(!msg.contains("Health:"), "found 'Health:' in: {msg}");
            assert!(!msg.contains("/100"), "found '/100' in: {msg}");
            assert!(
                !msg.contains("\u{1f7e2}"),
                "found 🟢 (health emoji) in: {msg}"
            );
            assert!(
                !msg.contains("\u{1f7e1}"),
                "found 🟡 (health emoji) in: {msg}"
            );
            assert!(
                !msg.contains("\u{1f534}"),
                "found 🔴 (health emoji) in: {msg}"
            );
        }
    }

    /// Spec 044 Phase 4 anchor (2026-05-09): the `Detected X critical, Y
    /// high severity threats` wording was renamed to "real compromises"
    /// after the Phase 3 downgrade engine landed. The counts are now
    /// post-downgrade — a high count of 0 alongside 60 silent SSH
    /// bruteforces means "60 attempts, none would have worked given
    /// posture", not "no high-severity detections happened today". The
    /// wording must reflect what the count means, otherwise the
    /// briefing is back to lying about what 'high' is. This anchor pins
    /// the new copy so future edits to this template trigger an
    /// explicit conversation.
    #[test]
    fn format_daily_digest_enriched_uses_real_compromises_wording() {
        let pipeline = PipelineDigestStats {
            suppressed_count: 30,
            auto_resolved_groups: 160,
            needs_review_groups: 30,
            deferred: vec![("proto_anomaly".to_string(), 60)],
        };
        let msg = format_daily_digest_enriched(
            316,
            47,
            1,  // critical (post-downgrade)
            61, // high (post-downgrade)
            "proto_anomaly",
            60,
            true,
            &pipeline,
        );
        assert!(
            msg.contains("real compromises"),
            "Phase 4 wording missing in: {msg}"
        );
        assert!(
            msg.contains("post-posture"),
            "Phase 4 hint about post-downgrade meaning missing in: {msg}"
        );
        // The previous "high severity threats" wording is retained
        // (with "high-severity" hyphenated) so the operator still sees
        // the high-count line — the change is the *meaning*, not the
        // disappearance of the high count.
        assert!(msg.contains("61"), "high count must still be visible");
        assert!(msg.contains("1"), "critical count must still be visible");
    }

    #[test]
    fn format_daily_digest_enriched_html_escapes_deferred_detector_names() {
        let pipeline = PipelineDigestStats {
            suppressed_count: 1,
            auto_resolved_groups: 0,
            needs_review_groups: 0,
            deferred: vec![("evil<script>&".to_string(), 2)],
        };

        let simple = format_daily_digest_enriched(2, 1, 0, 0, "safe", 1, true, &pipeline);
        assert!(simple.contains("evil&lt;script&gt;&amp;"));
        assert!(!simple.contains("evil<script>&"));

        let technical = format_daily_digest_enriched(2, 1, 0, 0, "safe", 1, false, &pipeline);
        assert!(technical.contains("evil&lt;script&gt;&amp;=2"));
        assert!(!technical.contains("evil<script>&=2"));
    }

    /// 2026-05-24 anchor: the "Blocked N attacks" header was renamed to
    /// "Made N autonomous decisions" because `blocks_today` counts ALL
    /// decisions (block + monitor + honeypot + suspend + dismiss + ignore
    /// + …), not just blocks. The operator received a briefing where the
    /// header said "Blocked 4 attacks" while the body listed "282 SSH
    /// brute force attempts blocked + 105 credential stuffing blocked
    /// + …" — a flagrant contradiction. Pin the new wording so a future
    /// "let's tighten this copy" PR cannot quietly revert to the
    /// misleading label.
    #[test]
    fn enriched_header_uses_autonomous_decisions_wording() {
        let pipeline = empty_pipeline();
        let msg = format_daily_digest_enriched(50, 7, 1, 2, "ssh_bruteforce", 5, true, &pipeline);
        assert!(
            msg.contains("Made <b>7</b> autonomous decisions"),
            "expected new 'Made N autonomous decisions' wording in: {msg}"
        );
        assert!(
            !msg.contains("Blocked <b>7</b> attacks"),
            "must not regress to misleading 'Blocked N attacks' label"
        );
    }

    // -----------------------------------------------------------------------
    // format_daily_briefing — the boss-readable redesign (2026-06)
    // -----------------------------------------------------------------------

    fn sample_briefing() -> DailyBriefingData {
        DailyBriefingData {
            events: 55,
            decisions: 259,
            critical: 0,
            high: 10,
            needs_review_live: 0,
            auto_resolved_groups: 41,
            categories: vec![
                ("ssh_bruteforce".to_string(), 168),
                ("proto_anomaly".to_string(), 96),
                ("kernel_devnode_exposed".to_string(), 7),
                ("telemetry.stream_silence".to_string(), 2),
            ],
            blocked_sources: vec![
                BlockedSource {
                    ip: "45.155.205.108".to_string(),
                    block_count: 38,
                    still_contained: true,
                    country_code: Some("ru".to_string()),
                },
                BlockedSource {
                    ip: "159.223.44.17".to_string(),
                    block_count: 21,
                    still_contained: false,
                    country_code: None,
                },
            ],
            unique_blocked_ips: 2,
            still_contained: 1,
            proactive: None,
        }
    }

    #[test]
    fn briefing_explains_headline_numbers_and_kills_post_posture_jargon() {
        // FIX 3 (guardian voice): the "N calls across M events" clause renders
        // with the data wired, the curve/hardening clause is present, and the
        // cryptic "(post-posture)" token is gone.
        let msg = format_daily_briefing(&sample_briefing(), false);
        assert!(
            msg.contains("<b>259</b> calls made across <b>55</b> security events"),
            "calls-across-events clause: {msg}"
        );
        assert!(
            msg.contains("grade on a curve for how locked down this box already is"),
            "hardening curve wording: {msg}"
        );
        assert!(
            !msg.contains("(post-posture)"),
            "jargon must be gone: {msg}"
        );
    }

    #[test]
    fn briefing_leads_with_a_plain_verdict() {
        // FIX 3 (guardian voice): a bottom-line verdict the boss reads first.
        // Busy but all contained → "Busy night on the wall".
        let busy = format_daily_briefing(&sample_briefing(), false);
        assert!(
            busy.contains("Busy night on the wall"),
            "busy verdict: {busy}"
        );

        // Quiet day (no events) → "Quiet night" verdict.
        let mut quiet = sample_briefing();
        quiet.events = 0;
        quiet.high = 0;
        quiet.categories.clear();
        quiet.blocked_sources.clear();
        quiet.unique_blocked_ips = 0;
        quiet.auto_resolved_groups = 0;
        let q = format_daily_briefing(&quiet, false);
        assert!(
            q.contains("Quiet night. Walked the perimeter"),
            "quiet verdict: {q}"
        );

        // Everything handled, no high / no big block burst → "Handled the
        // whole night myself".
        let mut handled = sample_briefing();
        handled.high = 0;
        handled.unique_blocked_ips = 1;
        handled.still_contained = 1;
        let h = format_daily_briefing(&handled, false);
        assert!(
            h.contains("Handled the whole night myself"),
            "all-handled verdict: {h}"
        );

        // Needs-review present → verdict leads with the "yours to make" ask.
        let mut review = sample_briefing();
        review.needs_review_live = 3;
        let r = format_daily_briefing(&review, false);
        assert!(
            r.contains("3 call(s) are yours to make"),
            "review verdict: {r}"
        );

        // A real compromise overrides everything and drops the jokes.
        let mut breach = sample_briefing();
        breach.critical = 1;
        breach.needs_review_live = 2; // critical override wins over needs-review.
        let b = format_daily_briefing(&breach, false);
        assert!(
            b.contains("Okay, no jokes. Someone landed a hit"),
            "compromise verdict drops the jokes: {b}"
        );
    }

    #[test]
    fn briefing_renders_blocked_sources_with_count_and_containment() {
        // FIX 4: top blocked IPs + unique count + still-contained count.
        let msg = format_daily_briefing(&sample_briefing(), false);
        assert!(
            msg.contains("Bouncer count: 2 IP(s) shown the door"),
            "unique count: {msg}"
        );
        assert!(
            msg.contains("(1 still contained)"),
            "containment count: {msg}"
        );
        assert!(msg.contains("45.155.205.108"), "top IP: {msg}");
        assert!(msg.contains("\u{00d7}38"), "block multiplier: {msg}");
        assert!(
            msg.contains("\u{1f1f7}\u{1f1fa}"),
            "country flag (RU): {msg}"
        );
        // The expired block is flagged honestly.
        assert!(
            msg.contains("(block expired)"),
            "expired block flagged: {msg}"
        );
    }

    #[test]
    fn briefing_category_lines_are_glossed_never_raw_snake_case() {
        // FIX 2: every category line is boss-readable with a "why it matters"
        // clause; no raw snake_case / dotted detector name survives.
        let msg = format_daily_briefing(&sample_briefing(), false);
        assert!(msg.contains("What I shut down"), "category header: {msg}");
        // Each gloss carries a "why it matters" clause: a factual label, then a
        // period, then the plain-language reason (e.g. "...blocked. Attackers
        // guess passwords...").
        assert!(
            msg.contains("guess passwords at scale"),
            "lines carry a factual why clause: {msg}"
        );
        for raw in [
            "ssh_bruteforce",
            "proto_anomaly",
            "kernel_devnode_exposed",
            "telemetry.stream_silence",
        ] {
            assert!(
                !msg.contains(raw),
                "raw detector name leaked ({raw}): {msg}"
            );
        }
        // The humanised + glossed forms are present.
        assert!(
            msg.contains("Kernel Devnode Exposed"),
            "humanised label: {msg}"
        );
        assert!(
            msg.contains("Telemetry Stream Silence"),
            "humanised label: {msg}"
        );
    }

    #[test]
    fn briefing_needs_review_block_never_points_at_nothing() {
        // FIX 1 render contract (guardian voice): 0 → reassurance, N>0 →
        // actionable copy that points at Cases → Needs review.
        let mut d = sample_briefing();
        d.needs_review_live = 0;
        let zero = format_daily_briefing(&d, false);
        assert!(
            zero.contains("Nothing for you tonight. I'm a professional"),
            "zero reassurance: {zero}"
        );
        assert!(
            !zero.contains("have your name on them"),
            "zero must not nag about review: {zero}"
        );

        d.needs_review_live = 2;
        let some = format_daily_briefing(&d, false);
        assert!(
            some.contains("2 thing(s) have your name on them"),
            "actionable count: {some}"
        );
        assert!(
            some.contains("Cases \u{2192} \"Needs review\""),
            "points at Cases: {some}"
        );
    }

    #[test]
    fn briefing_long_tail_categories_collapse() {
        let mut d = sample_briefing();
        d.categories = (0..12)
            .map(|i| (format!("port_scan_{i}"), (12 - i) as u32))
            .collect();
        let msg = format_daily_briefing(&d, false);
        // 8 shown, the remaining 4 collapse into the tail line.
        assert!(
            msg.contains("4 other categories (see dashboard)"),
            "tail collapse: {msg}"
        );
    }

    #[test]
    fn briefing_technical_profile_appends_raw_counters_but_stays_boss_readable() {
        let msg = format_daily_briefing(&sample_briefing(), true);
        // The boss-readable body is unchanged; the raw footer is additive.
        assert!(msg.contains("What I shut down"), "boss body present: {msg}");
        assert!(msg.contains("Technical:"), "technical footer: {msg}");
        assert!(
            msg.contains("259 decisions") && msg.contains("55 events"),
            "raw counters: {msg}"
        );
        // The closer is appended once, after the technical footer.
        assert!(
            msg.contains("Go on, I've got the place. As usual."),
            "closer present: {msg}"
        );
        assert_eq!(
            msg.matches("Go on, I've got the place. As usual.").count(),
            1,
            "closer must appear exactly once: {msg}"
        );
    }

    #[test]
    fn briefing_renders_proactive_suggestion_when_present() {
        let mut d = sample_briefing();
        d.proactive = Some("consider key-only SSH".to_string());
        let msg = format_daily_briefing(&d, false);
        assert!(
            msg.contains("\u{1f4a1} <b>Real talk:</b>"),
            "proactive label: {msg}"
        );
        assert!(msg.contains("key-only SSH"), "proactive text: {msg}");
    }

    /// HARD RULE: the rendered briefing must contain zero em dashes (U+2014).
    /// The framing switched to the guardian voice with no em dashes anywhere;
    /// this pins that the live renderer never emits one again.
    #[test]
    fn briefing_contains_no_em_dash() {
        // Exercise every branch: busy, quiet, all-handled, needs-review,
        // real-compromise, technical footer, proactive tip.
        let mut d = sample_briefing();
        d.proactive = Some("consider key-only SSH".to_string());
        for technical in [false, true] {
            let msg = format_daily_briefing(&d, technical);
            assert!(!msg.contains('\u{2014}'), "em dash in briefing: {msg}");
        }

        let mut quiet = sample_briefing();
        quiet.events = 0;
        quiet.high = 0;
        quiet.categories.clear();
        quiet.blocked_sources.clear();
        quiet.unique_blocked_ips = 0;
        quiet.auto_resolved_groups = 0;
        assert!(!format_daily_briefing(&quiet, false).contains('\u{2014}'));

        let mut review = sample_briefing();
        review.needs_review_live = 2;
        assert!(!format_daily_briefing(&review, true).contains('\u{2014}'));

        let mut breach = sample_briefing();
        breach.critical = 1;
        assert!(!format_daily_briefing(&breach, true).contains('\u{2014}'));
    }
}
