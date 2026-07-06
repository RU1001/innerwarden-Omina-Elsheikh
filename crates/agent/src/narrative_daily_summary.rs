use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::Timelike as _;
use tracing::{info, warn};

use crate::{config, narrative, telegram, AgentState};

/// Incident IDs the agent auto-resolved as benign today, read from the
/// canonical decisions log. Spec 044 honesty fix (2026-05-31): the daily
/// digest's "real compromises" / "high-severity threats" counts iterate
/// incidents by posture-adjusted severity but, before this, ignored the
/// *decision* — so an incident the agent had already DISMISSED as a false
/// positive (the host's own `imds_ssrf` metadata polling, `dns_tunneling` to
/// its own VCN DNS, `kill_chain` apt/wget DATA_EXFIL — all dismissed but still
/// Critical/High by raw severity) was counted as a "real compromise". That
/// inflated the headline and buried any genuine breach in the noise.
///
/// A `dismiss` or `ignore` decision means the agent judged the incident
/// benign; those are excluded from the threat counts (they already feed the
/// separate "auto-resolved" line). Incidents with no decision yet, or with a
/// real action (block/monitor/honeypot/needs_review), are NOT excluded — a
/// genuinely pending or actioned threat must still be counted.
///
/// This is the SAFE, comprehensive FP fix: it changes no detector and can
/// never hide a real attack — it only declines to call "compromise" what the
/// agent itself already decided was not one.
fn auto_resolved_incident_ids(data_dir: &Path, today: &str) -> HashSet<String> {
    let path = data_dir.join(format!("decisions-{today}.jsonl"));
    let mut ids = HashSet::new();
    let Ok(content) = std::fs::read_to_string(&path) else {
        return ids;
    };
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let action = v.get("action_type").and_then(|a| a.as_str()).unwrap_or("");
        if action == "dismiss" || action == "ignore" {
            if let Some(id) = v.get("incident_id").and_then(|i| i.as_str()) {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

/// Regenerate daily markdown summary and send Telegram digest when due.
pub(crate) async fn maybe_write_daily_summary_and_digest(
    data_dir: &Path,
    today: &str,
    events_count: usize,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    // Regenerate daily summary when there are new events, subject to a minimum
    // rewrite interval to avoid thrashing on busy hosts.
    const NARRATIVE_MIN_INTERVAL_SECS: u64 = 300; // 5 minutes
    const NARRATIVE_MAX_STALE_SECS: u64 = 1800; // 30 minutes
    if cfg.narrative.enabled && events_count > 0 {
        let elapsed = state
            .last_narrative_at
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(u64::MAX); // None → never written → always write
        let should_write =
            elapsed >= NARRATIVE_MIN_INTERVAL_SECS || elapsed >= NARRATIVE_MAX_STALE_SECS;
        if should_write {
            // Generate synthetic events from accumulated counters (no file I/O)
            let all_events_synthetic = state.narrative_acc.synthetic_events();
            let all_incidents_ref = &state.narrative_acc.incidents;

            let host = all_incidents_ref
                .first()
                .map(|i| i.host.as_str())
                .unwrap_or("unknown");

            let responder_hint = narrative::ResponderHint {
                enabled: cfg.responder.enabled,
                dry_run: cfg.responder.dry_run,
                has_block_ip: cfg
                    .responder
                    .allowed_skills
                    .iter()
                    .any(|s| s.starts_with("block-ip")),
            };
            let md = narrative::generate_with_responder(
                today,
                host,
                &all_events_synthetic,
                all_incidents_ref,
                cfg.correlation.window_seconds,
                responder_hint,
            );
            if let Err(e) = narrative::write(data_dir, today, &md) {
                state.telemetry.observe_error("narrative_writer");
                warn!("failed to write daily summary: {e:#}");
            } else {
                state.last_narrative_at = Some(std::time::Instant::now());
                info!(date = today, "daily summary updated");

                // Daily digest ("Daily Security Briefing") — fans out to every
                // operator chat channel (Telegram + Slack + Discord), not just
                // Telegram. Spec 078 migrated alerts/action-reports/burst
                // summaries to the registry; this is the daily report doing the
                // same so Slack-only boxes (and shared channels) get it too.
                if let Some(hour) = cfg.telegram.daily_summary_hour {
                    let now_local = chrono::Local::now();
                    let today_naive = now_local.date_naive();
                    let already_sent = state.last_daily_summary_telegram == Some(today_naive);
                    if !already_sent && now_local.hour() >= u32::from(hour) {
                        let text = build_daily_digest_text(cfg, state, data_dir, today);
                        let mut sent_any = false;

                        // Telegram keeps its own send_text_message path: unlike
                        // send_alert_html (used by the registry summary), it has
                        // no per-hour alert cap, so a busy day can never drop the
                        // daily digest.
                        if let Some(tg) = state.telegram_client.clone() {
                            match tg.send_text_message(&text).await {
                                Ok(()) => {
                                    sent_any = true;
                                    info!(date = today, "daily Telegram digest sent");
                                }
                                Err(e) => warn!("failed to send daily Telegram digest: {e:#}"),
                            }
                        }

                        // Slack / Discord via the chat-channel registry; Telegram
                        // is already handled above (skip it to avoid a double send).
                        let channels =
                            crate::notification_channels::collect_chat_channels(cfg, state);
                        for ch in channels.iter().filter(|c| c.name() != "telegram") {
                            match ch.summary(&text).await {
                                Ok(()) => {
                                    sent_any = true;
                                    info!(channel = ch.name(), date = today, "daily digest sent");
                                }
                                Err(e) => {
                                    warn!(channel = ch.name(), "failed to send daily digest: {e:#}")
                                }
                            }
                        }

                        // Mark sent once it reached at least one channel, so a
                        // restart after the hour does not re-fire (pre-2026-05-09
                        // bug: in-memory-only marker re-emitted "Daily Security
                        // Briefing" on every restart) and a transient
                        // single-channel failure does not loop all day.
                        if sent_any {
                            state.last_daily_summary_telegram = Some(today_naive);
                            state.store.set_last_daily_briefing_date(today_naive);
                        }
                    }
                }
            }
        }
    }
}

fn build_daily_digest_text(
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    data_dir: &Path,
    today: &str,
) -> String {
    // `technical` profile gets the extra raw-counter footer; every profile is
    // now boss-readable (spec 2026-06 — make ALL profiles boss-readable).
    let technical = !cfg.telegram.is_simple_profile();
    // Incidents the agent already dismissed/ignored as benign — excluded from
    // the "real compromises" / "high-severity" threat counts so a false
    // positive the agent auto-resolved is not reported as a compromise.
    let auto_resolved = auto_resolved_incident_ids(data_dir, today);
    // Count incidents by severity and per-detector category.
    let mut incidents_today: u32 = 0;
    let mut critical_count: u32 = 0;
    let mut high_count: u32 = 0;
    let mut detector_counts: HashMap<String, u32> = HashMap::new();
    for inc in &state.narrative_acc.incidents {
        incidents_today += 1;
        let det = telegram::extract_detector_pub(&inc.incident_id);
        *detector_counts.entry(det.to_string()).or_insert(0) += 1;
        // A dismissed/ignored incident is, by the agent's own decision, not a
        // threat — it feeds the "auto-resolved" line, not "real compromises".
        if auto_resolved.contains(&inc.incident_id) {
            continue;
        }
        // Effective severity: posture-aware downgrade (spec 044 Phase 3).
        let (effective, _reason) =
            crate::posture::downgrade::effective_severity(inc, det, &state.host_posture);
        match effective {
            innerwarden_core::event::Severity::Critical => {
                critical_count += 1;
            }
            innerwarden_core::event::Severity::High => {
                high_count += 1;
            }
            _ => {}
        }
    }
    // "Automatic decisions" = the count of decisions the agent actually
    // recorded today, read from the canonical hash-chained decisions log
    // (NUMBER_CONSISTENCY: "decisions made today"). Restart-robust (the old
    // in-memory KG count collapsed toward 0 after a restart).
    let decisions_today = crate::decisions::count_decisions_for_date(data_dir, today) as u32;

    // FIX 1 (2026-06): the "Needs review" count MUST equal the LIVE dashboard
    // number, computed from the SAME canonical source the dashboard tile reads
    // (open cases whose most-recent decision is still needs_review). The old
    // grouped counter (`grouping_engine.drain_digest_stats().needs_review_groups`)
    // diverges — e.g. a Low/Medium needs_review incident auto-dismissed by the
    // spec-062 24h timeout is still counted there but has already dropped out of
    // the live attention count. We still DRAIN the grouped stats (auto_resolved
    // is informational; draining keeps the per-window accumulator from leaking),
    // but we RECONCILE: if the live source says 0, we report 0 and never tell
    // the operator to review something already closed.
    let pipeline_stats = state.grouping_engine.drain_digest_stats();
    let needs_review_live = state
        .sqlite_store
        .as_ref()
        .map(|store| crate::dashboard::live_needs_review_count(store, today) as u32)
        // No SQLite store (rare degraded path): fall back to the grouped
        // counter so a real backlog is not silently hidden, but it is the
        // pessimistic fallback only.
        .unwrap_or(pipeline_stats.needs_review_groups);

    // FIX 2: per-category lines. Merge the deferred ("handled silently")
    // breakdown with the day's incident detector tally so the boss sees the
    // full picture, then sort by count. Every line is glossed downstream.
    let deferred: Vec<(String, u32)> = state.telegram_deferred.drain().collect();
    let categories = merge_categories(&detector_counts, &deferred);

    // FIX 4: top blocked source IPs today + how many are still contained.
    let blocked = blocked_sources_today(state, data_dir, today);

    // Persona: one proactive suggestion when a pattern clearly warrants it.
    let proactive = proactive_suggestion(&categories);

    let data = telegram::DailyBriefingData {
        events: incidents_today,
        decisions: decisions_today,
        critical: critical_count,
        high: high_count,
        needs_review_live,
        auto_resolved_groups: pipeline_stats.auto_resolved_groups,
        categories,
        blocked_sources: blocked.sources,
        unique_blocked_ips: blocked.unique_ips,
        still_contained: blocked.still_contained,
        proactive,
    };

    // Host header so a shared chat channel (Telegram / Slack / Discord across
    // several boxes) shows which server the briefing is from. Prefer the host
    // the incidents are stamped with (sensor `host_id`, same label real alerts
    // carry); fall back to the system hostname.
    let host = state
        .narrative_acc
        .incidents
        .first()
        .map(|i| i.host.clone())
        .filter(|h| !h.is_empty() && h != "unknown")
        .unwrap_or_else(daily_digest_host_fallback);

    let digest = telegram::format_daily_briefing(&data, technical);
    format!("🖥 <b>{}</b>\n{digest}", html_escape_host(&host))
}

/// Merge the deferred ("handled silently") per-detector breakdown with the
/// day's incident detector tally into a single sorted category list. Counts are
/// taken from the larger of the two for a given detector (the deferred list is
/// a subset routed away from immediate Telegram; the incident tally is the
/// full day), so a category is never double-counted or under-reported.
fn merge_categories(
    detector_counts: &HashMap<String, u32>,
    deferred: &[(String, u32)],
) -> Vec<(String, u32)> {
    let mut merged: HashMap<String, u32> = detector_counts.clone();
    for (det, count) in deferred {
        let entry = merged.entry(det.clone()).or_insert(0);
        *entry = (*entry).max(*count);
    }
    let mut out: Vec<(String, u32)> = merged.into_iter().collect();
    // Sort by count desc, then detector name asc for a stable render.
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}

/// Blocked-source rollup for the briefing.
struct BlockedRollup {
    sources: Vec<telegram::BlockedSource>,
    unique_ips: u32,
    still_contained: u32,
}

/// Read today's `decisions-<date>.jsonl` for `block_ip` actions, count unique
/// blocked IPs + per-IP block frequency, and cross-reference the live response
/// lifecycle for "still contained". Country is included only on a cheap geo
/// cache hit; never fabricated and never an HTTP call from the digest path.
fn blocked_sources_today(state: &AgentState, data_dir: &Path, today: &str) -> BlockedRollup {
    let path = data_dir.join(format!("decisions-{today}.jsonl"));
    let mut counts: HashMap<String, u32> = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let action = v.get("action_type").and_then(|a| a.as_str()).unwrap_or("");
            if action != "block_ip" {
                continue;
            }
            let Some(ip) = v.get("target_ip").and_then(|i| i.as_str()) else {
                continue;
            };
            if ip.is_empty() {
                continue;
            }
            *counts.entry(ip.to_string()).or_insert(0) += 1;
        }
    }

    // Live containment set (firewall/XDP rule still active at send time).
    let now = chrono::Utc::now();
    let contained: std::collections::HashSet<String> = state
        .response_lifecycle
        .active_block_ip_targets(now)
        .into_iter()
        .map(|(ip, _backend)| ip)
        .collect();

    let mut sources: Vec<telegram::BlockedSource> = counts
        .iter()
        .map(|(ip, n)| telegram::BlockedSource {
            ip: ip.clone(),
            block_count: *n,
            still_contained: contained.contains(ip),
            country_code: None, // geo is async/cached-elsewhere; skip gracefully
        })
        .collect();
    // Highest block-count first, then IP for a stable order.
    sources.sort_by(|a, b| {
        b.block_count
            .cmp(&a.block_count)
            .then_with(|| a.ip.cmp(&b.ip))
    });

    let still_contained = sources.iter().filter(|s| s.still_contained).count() as u32;
    BlockedRollup {
        unique_ips: counts.len() as u32,
        still_contained,
        sources,
    }
}

/// One optional proactive suggestion when the day's shape clearly warrants it.
/// Conservative: only fires on an unambiguous, high-volume pattern so the boss
/// is not nagged. Returns `None` otherwise.
fn proactive_suggestion(categories: &[(String, u32)]) -> Option<String> {
    // Constant SSH password-guessing → recommend key-only logins.
    let ssh = categories
        .iter()
        .find(|(d, _)| {
            d == "ssh_bruteforce" || d == "credential_stuffing" || d == "distributed_ssh"
        })
        .map(|(_, c)| *c)
        .unwrap_or(0);
    if ssh >= 20 {
        return Some(
            "Heavy SSH password-guessing today. Consider switching to key-only SSH logins \
             (disable password auth) so these attempts can never succeed."
                .to_string(),
        );
    }
    None
}

/// System hostname for the digest header when no incident carries a host.
fn daily_digest_host_fallback() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Minimal HTML escape for the host label in the Telegram-HTML digest header.
fn html_escape_host(h: &str) -> String {
    h.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn cfg_with_narrative() -> config::AgentConfig {
        let mut cfg = config::AgentConfig::default();
        cfg.narrative.enabled = true;
        cfg
    }

    #[tokio::test]
    async fn daily_summary_writes_once_and_honors_minimum_rewrite_interval() {
        let dir = TempDir::new().expect("tempdir");
        let cfg = cfg_with_narrative();
        let mut state = crate::tests::triage_test_state(dir.path());
        state
            .narrative_acc
            .events_by_kind
            .insert("ssh.login_failed".to_string(), 3);
        state
            .narrative_acc
            .ingest_incidents(&[crate::tests::test_incident("203.0.113.10")]);

        maybe_write_daily_summary_and_digest(dir.path(), "2026-05-13", 3, &cfg, &mut state).await;

        let summary_path = dir.path().join("summary-2026-05-13.md");
        let first = std::fs::read_to_string(&summary_path).expect("summary should be written");
        assert!(first.contains("test-host"));
        assert!(state.last_narrative_at.is_some());

        std::fs::write(&summary_path, "sentinel").expect("overwrite summary");
        maybe_write_daily_summary_and_digest(dir.path(), "2026-05-13", 3, &cfg, &mut state).await;
        assert_eq!(
            std::fs::read_to_string(&summary_path).expect("summary should still exist"),
            "sentinel"
        );
    }

    #[tokio::test]
    async fn daily_digest_fans_out_to_slack_when_due() {
        // No telegram client (the Azure / Slack-only case) — the digest must
        // still reach Slack through the chat-channel registry.
        let mut server = mockito::Server::new_async().await;
        let hook = server
            .mock("POST", "/services/T/B/X")
            .with_status(200)
            .create_async()
            .await;

        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        cfg.telegram.daily_summary_hour = Some(0); // hour gate: now >= 0 → due
        cfg.slack.enabled = true;

        let mut state = crate::tests::triage_test_state(dir.path());
        state.slack_client = Some(
            crate::slack::SlackClient::new(format!("{}/services/T/B/X", server.url())).unwrap(),
        );
        state.last_daily_summary_telegram = None;
        state
            .narrative_acc
            .events_by_kind
            .insert("ssh.login_failed".to_string(), 3);
        state
            .narrative_acc
            .ingest_incidents(&[crate::tests::test_incident("203.0.113.10")]);

        maybe_write_daily_summary_and_digest(dir.path(), "2026-05-13", 3, &cfg, &mut state).await;

        hook.assert_async().await;
        // Dedup marker set → won't re-fire today.
        assert!(state.last_daily_summary_telegram.is_some());
    }

    #[tokio::test]
    async fn daily_summary_skips_when_disabled_or_no_events() {
        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        let mut state = crate::tests::triage_test_state(dir.path());

        maybe_write_daily_summary_and_digest(dir.path(), "2026-05-13", 0, &cfg, &mut state).await;
        assert!(!dir.path().join("summary-2026-05-13.md").exists());

        cfg.narrative.enabled = false;
        maybe_write_daily_summary_and_digest(dir.path(), "2026-05-13", 5, &cfg, &mut state).await;
        assert!(!dir.path().join("summary-2026-05-13.md").exists());
    }

    #[test]
    fn build_daily_digest_text_counts_effective_severity_and_drains_deferred() {
        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        cfg.telegram.user_profile = "technical".to_string();
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut critical = crate::tests::test_incident_with_kind("203.0.113.20", "kernel_panic");
        critical.severity = innerwarden_core::event::Severity::Critical;
        let high = crate::tests::test_incident_with_kind("203.0.113.21", "ssh_bruteforce");
        state.narrative_acc.ingest_incidents(&[critical, high]);
        state.telegram_deferred.insert("port_scan".to_string(), 4);
        state
            .telegram_deferred
            .insert("ssh_bruteforce".to_string(), 2);

        let text = build_daily_digest_text(&cfg, &mut state, dir.path(), "2026-05-13");

        // Host header (from the incident host) so a shared channel shows which box.
        assert!(text.starts_with("🖥"), "digest leads with a host header");
        assert!(text.contains("test-host"));
        assert!(text.contains("Daily Security Briefing"));
        // FIX 3 (guardian voice): the "N calls across M events" clause renders
        // (kills the "more decisions than events?" confusion).
        assert!(
            text.contains("across <b>2</b> security events"),
            "events clause must render: {text}"
        );
        // The deferred categories are drained and rendered as boss-readable
        // glossed lines, NOT raw snake_case / `=` machine syntax.
        assert!(
            text.contains("What I shut down"),
            "category section: {text}"
        );
        assert!(!text.contains("port_scan=4"), "no machine syntax: {text}");
        assert!(!text.contains("port_scan"), "no raw detector name: {text}");
        assert!(state.telegram_deferred.is_empty());
    }

    #[test]
    fn digest_excludes_dismissed_incidents_from_threat_counts() {
        // Honesty fix (2026-05-31): an incident the agent DISMISSED as a false
        // positive (e.g. imds_ssrf / dns_tunneling / kill_chain self-traffic)
        // must NOT inflate "real compromises" / "high-severity" even though its
        // raw severity is Critical/High. It still counts toward total incidents
        // (and the auto-resolved line), just not the threat headline.
        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        cfg.telegram.user_profile = "technical".to_string();
        let mut state = crate::tests::triage_test_state(dir.path());

        let mut dismissed_crit = crate::tests::test_incident_with_kind("203.0.113.30", "imds_ssrf");
        dismissed_crit.severity = innerwarden_core::event::Severity::Critical;
        let mut real_crit = crate::tests::test_incident_with_kind("203.0.113.31", "reverse_shell");
        real_crit.severity = innerwarden_core::event::Severity::Critical;
        let dismissed_id = dismissed_crit.incident_id.clone();
        state
            .narrative_acc
            .ingest_incidents(&[dismissed_crit, real_crit]);

        // The agent dismissed the imds_ssrf one as a false positive.
        let line = format!(
            r#"{{"ts":"2026-05-13T00:00:00Z","incident_id":"{dismissed_id}","host":"h","ai_provider":"orphan-recovery","action_type":"dismiss","confidence":1.0,"auto_executed":true,"dry_run":false,"reason":"fp","estimated_threat":"none","execution_result":"dismissed"}}"#
        );
        std::fs::write(dir.path().join("decisions-2026-05-13.jsonl"), line).unwrap();

        let text = build_daily_digest_text(&cfg, &mut state, dir.path(), "2026-05-13");

        // 2 incidents seen, but only the non-dismissed Critical is a compromise.
        assert!(
            text.contains("across <b>2</b> security events"),
            "total events unchanged: {text}"
        );
        // Guardian-voice rundown: "Break-ins: <b>1</b>." — the dismissed
        // Critical must be excluded from the break-in count.
        assert!(
            text.contains("Break-ins: <b>1</b>."),
            "dismissed Critical must be excluded from the threat count: {text}"
        );
    }

    #[test]
    fn digest_decisions_reads_canonical_log_not_kg() {
        // Regression for the 2026-05-29 operator report: the briefing showed
        // "Made 0 autonomous decisions" while decisions-<date>.jsonl held 726
        // (the number was read from the restart-fragile KG, not the log).
        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        cfg.telegram.user_profile = "simple".to_string();
        let mut state = crate::tests::triage_test_state(dir.path());
        // Five real decisions persisted for the day; the KG stays empty.
        let line = r#"{"ts":"2026-05-13T00:00:00Z","incident_id":"i","host":"h","ai_provider":"x","action_type":"block_ip","target_ip":"203.0.113.9","confidence":1.0,"auto_executed":true,"dry_run":false,"reason":"r","estimated_threat":"high","execution_result":"ok"}"#;
        std::fs::write(
            dir.path().join("decisions-2026-05-13.jsonl"),
            format!("{line}\n{line}\n{line}\n{line}\n{line}\n"),
        )
        .unwrap();

        let text = build_daily_digest_text(&cfg, &mut state, dir.path(), "2026-05-13");
        assert!(
            text.contains("<b>5</b> calls made across"),
            "briefing must reflect the 5 decisions in the log, got: {text}"
        );
    }

    #[test]
    fn digest_blocked_sources_line_renders_top_ips_and_unique_count() {
        // FIX 4: the briefing leads with blocked source IPs + unique count.
        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        cfg.telegram.user_profile = "simple".to_string();
        let mut state = crate::tests::triage_test_state(dir.path());
        // Two block_ip decisions on .9 (×2) and one on .8.
        let mk = |ip: &str| {
            format!(
                r#"{{"ts":"2026-05-13T00:00:00Z","incident_id":"ssh_bruteforce:{ip}:x","host":"h","ai_provider":"x","action_type":"block_ip","target_ip":"{ip}","confidence":1.0,"auto_executed":true,"dry_run":false,"reason":"r","estimated_threat":"high","execution_result":"ok"}}"#
            )
        };
        std::fs::write(
            dir.path().join("decisions-2026-05-13.jsonl"),
            format!(
                "{}\n{}\n{}\n",
                mk("203.0.113.9"),
                mk("203.0.113.9"),
                mk("203.0.113.8")
            ),
        )
        .unwrap();

        let text = build_daily_digest_text(&cfg, &mut state, dir.path(), "2026-05-13");
        assert!(
            text.contains("Bouncer count: 2 IP(s) shown the door"),
            "unique blocked IP count must render: {text}"
        );
        // The busiest source (.9 ×2) renders first with its multiplier.
        assert!(
            text.contains("203.0.113.9"),
            "top blocked IP must render: {text}"
        );
        assert!(
            text.contains("\u{00d7}2"),
            "block multiplier must render: {text}"
        );
    }

    // -----------------------------------------------------------------------
    // FIX 1 — needs_review reconciliation against the LIVE dashboard number
    // -----------------------------------------------------------------------

    /// Helper: persist an incident to the SQLite store with the given
    /// severity + an external IP entity, then write a `needs_review` decision
    /// for it (mirrored to SQLite via `append_chained`). This is exactly the
    /// state the live `attention_count`/dashboard "Needs review" tile reads.
    fn seed_needs_review_incident(
        store: &std::sync::Arc<innerwarden_store::Store>,
        data_dir: &Path,
        ip: &str,
        kind: &str,
        severity: innerwarden_core::event::Severity,
        decision_ts: chrono::DateTime<chrono::Utc>,
    ) -> String {
        let mut inc = crate::tests::test_incident_with_kind(ip, kind);
        inc.severity = severity;
        let id = inc.incident_id.clone();
        store.insert_incident(&inc).expect("insert incident");
        let entry = crate::decisions::DecisionEntry {
            ts: decision_ts,
            incident_id: id.clone(),
            host: "test-host".to_string(),
            ai_provider: "gate".to_string(),
            action_type: "needs_review".to_string(),
            target_ip: Some(ip.to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.5,
            auto_executed: false,
            dry_run: false,
            reason: "ambiguous".to_string(),
            estimated_threat: "medium".to_string(),
            execution_result: "pending".to_string(),
            prev_hash: None,
            decision_layer: Some("gate".to_string()),
        };
        crate::decisions::append_chained(data_dir, &entry, Some(store))
            .expect("append needs_review decision");
        id
    }

    #[test]
    fn briefing_needs_review_equals_live_dashboard_attention_count() {
        // The briefing's review count MUST equal the dashboard `attention_count`
        // for the SAME snapshot — both read the canonical live source
        // (`dashboard::live_needs_review_count` → `compute_overview_counts_from_sqlite`).
        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        cfg.telegram.user_profile = "simple".to_string();
        let store = crate::tests::test_sqlite_store(dir.path());
        let mut state = crate::tests::triage_test_state(dir.path());
        state.sqlite_store = Some(store.clone());

        // Use the actual local date so the SQLite `ts LIKE date%` filter and the
        // `decisions-<date>.jsonl` writer (which `append_chained` keys to local
        // date) line up.
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let now = chrono::Utc::now();

        // Three open needs_review cases, three distinct attacker IPs.
        seed_needs_review_incident(
            &store,
            dir.path(),
            "203.0.113.40",
            "suspicious_login",
            innerwarden_core::event::Severity::High,
            now,
        );
        seed_needs_review_incident(
            &store,
            dir.path(),
            "203.0.113.41",
            "proto_anomaly",
            innerwarden_core::event::Severity::Medium,
            now,
        );
        seed_needs_review_incident(
            &store,
            dir.path(),
            "203.0.113.42",
            "port_scan",
            innerwarden_core::event::Severity::Low,
            now,
        );
        // Ingest the same incidents into the accumulator so the briefing has a
        // non-empty events count (mirrors the production fast-loop path).
        let incs: Vec<_> = ["203.0.113.40", "203.0.113.41", "203.0.113.42"]
            .iter()
            .zip(["suspicious_login", "proto_anomaly", "port_scan"])
            .map(|(ip, kind)| crate::tests::test_incident_with_kind(ip, kind))
            .collect();
        state.narrative_acc.ingest_incidents(&incs);

        // The canonical dashboard number for this same snapshot.
        let dashboard_count = crate::dashboard::live_needs_review_count(&store, &today);
        assert_eq!(dashboard_count, 3, "three distinct attackers still open");

        let text = build_daily_digest_text(&cfg, &mut state, dir.path(), &today);

        // The briefing renders that EXACT live number, as actionable copy in
        // the guardian voice. dashboard_count == 3 (plural).
        assert!(
            text.contains(&format!(
                "{dashboard_count} thing(s) have your name on them"
            )),
            "briefing review count must equal dashboard attention_count={dashboard_count}: {text}"
        );
        assert!(
            text.contains("Cases \u{2192} \"Needs review\""),
            "review block must be actionable (point at Cases): {text}"
        );
    }

    #[test]
    fn spec_062_timeout_dismissal_does_not_inflate_briefing_review_count() {
        // Anti-regression: a Low/Medium needs_review incident auto-dismissed by
        // the spec-062 24h timeout MUST NOT appear in / inflate the briefing's
        // review count when the briefing is generated AFTER the sweep. The old
        // grouped counter would still count it; the live source (which the
        // briefing now uses) correctly drops it because its most-recent decision
        // is the timeout `dismiss`.
        let dir = TempDir::new().expect("tempdir");
        let mut cfg = cfg_with_narrative();
        cfg.telegram.user_profile = "simple".to_string();
        let store = crate::tests::test_sqlite_store(dir.path());
        let mut state = crate::tests::triage_test_state(dir.path());
        state.sqlite_store = Some(store.clone());

        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        let now = chrono::Utc::now();
        // One Medium case whose needs_review decision is older than the 24h
        // timeout → the sweep will auto-dismiss it.
        let stale_ts = now
            - chrono::Duration::seconds(
                crate::needs_review_timeout::NEEDS_REVIEW_TIMEOUT_SECS + 3600,
            );
        seed_needs_review_incident(
            &store,
            dir.path(),
            "203.0.113.50",
            "proto_anomaly",
            innerwarden_core::event::Severity::Medium,
            stale_ts,
        );
        // One fresh High case that must STILL count (high never auto-dismisses,
        // and it is not stale anyway).
        seed_needs_review_incident(
            &store,
            dir.path(),
            "203.0.113.51",
            "suspicious_login",
            innerwarden_core::event::Severity::High,
            now,
        );

        // Before the sweep: both cases are open → live count is 2.
        assert_eq!(
            crate::dashboard::live_needs_review_count(&store, &today),
            2,
            "both needs_review cases open before the sweep"
        );

        // Run the real spec-062 timeout sweep — the Medium one auto-dismisses.
        let resolved = crate::needs_review_timeout::run_sweep(&mut state, dir.path());
        assert_eq!(
            resolved, 1,
            "exactly the stale Medium case is auto-dismissed"
        );

        // After the sweep the live count is 1 (only the High case remains).
        let after = crate::dashboard::live_needs_review_count(&store, &today);
        assert_eq!(after, 1, "timed-out Medium drops out of the live count");

        // Ingest for a non-empty events count, then build the briefing.
        let incs: Vec<_> = ["203.0.113.50", "203.0.113.51"]
            .iter()
            .zip(["proto_anomaly", "suspicious_login"])
            .map(|(ip, kind)| crate::tests::test_incident_with_kind(ip, kind))
            .collect();
        state.narrative_acc.ingest_incidents(&incs);

        let text = build_daily_digest_text(&cfg, &mut state, dir.path(), &today);

        // The briefing reflects 1, NOT 2: the auto-dismissed item is gone.
        // (Guardian voice: "1 thing have your name on them".)
        assert!(
            text.contains("1 thing have your name on them"),
            "briefing must show the post-sweep live count of 1: {text}"
        );
        assert!(
            !text.contains("2 thing(s) have your name on them"),
            "auto-dismissed Medium must NOT inflate the review count: {text}"
        );
    }
}

// 2026-05-09 spec 044 Phase 3: the previous in-file `effective_severity`
// function assumed `PasswordAuthentication=no` globally and demoted every
// `ssh_bruteforce` regardless of the host's actual sshd config. That
// assumption was right on this prod host but wrong as a generic policy.
// The replacement lives in `crates/agent/src/posture/downgrade.rs` and
// reads the live posture snapshot via `state.host_posture`. Tests moved
// with it (see posture::downgrade::tests). The pre-spec-044 commit
// history preserves the original rule reasoning if you need to see it.
