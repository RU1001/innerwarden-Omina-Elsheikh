use std::io::Write;
use std::path::Path;
use std::sync::atomic::AtomicU64;

use tracing::{info, warn};

use innerwarden_shield::attack_classifier::AttackClassifier;
use innerwarden_shield::cloudflare_failover::{CloudflareFailover, CloudflareFailoverConfig};
use innerwarden_shield::escalation::{EscalationConfig, EscalationEngine, EscalationState};
use innerwarden_shield::origin_lockdown::OriginLockdown;
use innerwarden_shield::rate_limiter::{IpRateLimiter, RateLimitDecision, RateLimiterConfig};
use innerwarden_shield::store::Store;
use innerwarden_shield::syn_tracker::{SynFloodConfig, SynFloodDetector};
use innerwarden_shield::tcp_fingerprint::{ConnectionPattern, TcpFingerprinter};
use innerwarden_shield::xdp_manager::XdpManager;

use crate::config::{ShieldCloudflareFailoverConfig, ShieldOriginLockdownConfig};

/// Shield state held in the agent.
#[allow(dead_code)]
pub(crate) struct ShieldState {
    pub rate_limiter: IpRateLimiter,
    pub syn_detector: SynFloodDetector,
    pub escalation: EscalationEngine,
    pub classifier: AttackClassifier,
    pub fingerprinter: TcpFingerprinter,
    /// IPs already reported as a TCP-fingerprint bot/botnet this session — so the
    /// classifier emits ONE incident per IP, not one every tick. Pruned when the
    /// IP goes stale (falls out of the fingerprinter), so a returning bot re-alerts.
    fingerprint_alerted: std::collections::HashSet<String>,
    pub xdp: XdpManager,
    pub store: Store,
    pub tick_counter: u64,
    default_rl_config: RateLimiterConfig,
    /// Cloudflare DNS proxy auto-toggle. `None` when disabled in config.
    cloudflare_failover: Option<CloudflareFailover>,
    /// True when the failover is wired but should only log, not call
    /// the Cloudflare API. New deploys default to true; flip to false
    /// after a week of clean state-transition logs.
    cf_failover_dry_run: bool,
    /// iptables CF-only origin lockdown. `None` when disabled in config.
    origin_lockdown: Option<OriginLockdown>,
    /// Same dry-run gate for the lockdown — a misconfigured CIDR set
    /// can lock the operator out of their own host, so this stays true
    /// until the operator explicitly opts in.
    lockdown_dry_run: bool,
}

impl ShieldState {
    pub fn new(
        shield_dir: &Path,
        bpf_path: &str,
        dry_run: bool,
        cf_failover_cfg: &ShieldCloudflareFailoverConfig,
        lockdown_cfg: &ShieldOriginLockdownConfig,
    ) -> Self {
        std::fs::create_dir_all(shield_dir).ok();
        let store = Store::new(shield_dir);
        let xdp = XdpManager::new(bpf_path).with_dry_run(dry_run);

        // Load persisted state
        let saved = store.load_state().ok();
        let escalation_config = EscalationConfig::default();
        let mut escalation = EscalationEngine::new(escalation_config);
        if let Some(ref state) = saved {
            let entered_at = state
                .state_entered_at
                .parse()
                .unwrap_or_else(|_| chrono::Utc::now());
            let ddos_history = store.load_ddos_history().unwrap_or_default();
            escalation.restore(state.escalation_state, entered_at, ddos_history);
        }

        let rl_config = RateLimiterConfig::default();

        // 2026-05-21: instantiate Cloudflare auto-failover when configured.
        // The crate already encapsulates the API call + min-duration
        // hysteresis; `dry_run` is enforced at the call site below so the
        // pre-roll-out audit window still produces real state-transition
        // logs.
        let cloudflare_failover = if cf_failover_cfg.enabled
            && !cf_failover_cfg.api_token.is_empty()
            && !cf_failover_cfg.zone_id.is_empty()
            && !cf_failover_cfg.record_id.is_empty()
        {
            Some(CloudflareFailover::new(CloudflareFailoverConfig {
                enabled: true,
                api_token: cf_failover_cfg.api_token.clone(),
                zone_id: cf_failover_cfg.zone_id.clone(),
                record_id: cf_failover_cfg.record_id.clone(),
                activate_on: cf_failover_cfg.activate_on.clone(),
                min_proxy_duration_secs: cf_failover_cfg.min_proxy_duration_secs,
            }))
        } else {
            None
        };

        // Origin lockdown: kept inert (no init, no iptables touches) when
        // disabled. `OriginLockdown::new` does not call into iptables on
        // its own; the activate/deactivate methods do, and we gate them
        // behind `lockdown_dry_run` below.
        let origin_lockdown = if lockdown_cfg.enabled {
            Some(OriginLockdown::new())
        } else {
            None
        };

        Self {
            rate_limiter: IpRateLimiter::new(rl_config.clone()),
            syn_detector: SynFloodDetector::new(SynFloodConfig::default()),
            escalation,
            classifier: AttackClassifier::new(),
            fingerprinter: TcpFingerprinter::new(),
            fingerprint_alerted: std::collections::HashSet::new(),
            xdp,
            store,
            tick_counter: 0,
            default_rl_config: rl_config,
            cloudflare_failover,
            cf_failover_dry_run: cf_failover_cfg.dry_run,
            origin_lockdown,
            lockdown_dry_run: lockdown_cfg.dry_run,
        }
    }
}

/// A newly-classified TCP-fingerprint bot/botnet, snapshotted from the
/// fingerprinter so the incident is built without holding a borrow on it.
struct BotHit {
    ip: String,
    pattern: ConnectionPattern,
    count: u64,
    variance: f64,
    win: Option<u16>,
    ttl: Option<u8>,
}

/// Classify tracked IPs by TCP fingerprint and push one incident per newly-seen
/// bot/botnet into `incidents`. A SIGNAL, not an auto-block: a low-timing-variance
/// client can be a legitimate crawler/monitor (and a rDNS-verified crawler is
/// already tagged `bot:known` and exempt), so the AI/operator decides; Shield
/// never XDP-drops on a fingerprint alone. De-duped per IP via `fingerprint_alerted`.
fn classify_and_emit_bots(shield: &mut ShieldState, incidents: &mut Vec<serde_json::Value>) {
    shield.fingerprinter.classify_all();
    let new_bots: Vec<BotHit> = shield
        .fingerprinter
        .get_bots()
        .into_iter()
        .filter(|fp| !shield.fingerprint_alerted.contains(&fp.ip))
        .map(|fp| BotHit {
            ip: fp.ip.clone(),
            pattern: fp.connection_pattern.clone(),
            count: fp.connection_count,
            variance: fp.timing_variance_ms(),
            win: fp.dominant_window_size(),
            ttl: fp.dominant_ttl(),
        })
        .collect();
    if new_bots.is_empty() {
        return;
    }
    let host = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();
    for BotHit {
        ip,
        pattern,
        count,
        variance,
        win,
        ttl,
    } in new_bots
    {
        shield.fingerprint_alerted.insert(ip.clone());
        let (severity, kind, title, why) = match pattern {
            ConnectionPattern::Botnet => (
                "high",
                "botnet",
                format!("Botnet TCP fingerprint from {ip}"),
                "many source IPs share one TCP stack fingerprint (window/TTL) — a coordinated botnet",
            ),
            _ => (
                "low",
                "bot",
                format!("Automated bot TCP fingerprint from {ip}"),
                "connections arrive at near-constant intervals (very low timing variance) — an automated client, not a human",
            ),
        };
        info!(
            ip,
            ?pattern,
            count,
            variance,
            "shield: TCP-fingerprint bot classified"
        );
        incidents.push(serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": host,
            "incident_id": format!("shield:tcp_fingerprint:{kind}:{ip}"),
            "severity": severity,
            "title": title,
            "summary": format!(
                "{why}. {count} connections, timing variance {variance:.0} ms\u{00b2}, \
                 dominant window {}, TTL {}. Signal only — verify (a rDNS-verified crawler \
                 is tagged bot:known and exempt); not auto-blocked.",
                win.map(|w| w.to_string()).unwrap_or_else(|| "?".into()),
                ttl.map(|t| t.to_string()).unwrap_or_else(|| "?".into()),
            ),
            "tags": ["shield", "bot", "tcp_fingerprint", kind],
            "entities": [{"kind": "ip", "value": ip}],
        }));
    }
}

/// Process a batch of sensor events through the shield pipeline.
/// Returns the number of drops, any new incidents, and IPs that were blocked by the shield.
/// `ip_risk_scores` provides attacker intel risk scores (0-100) for known IPs;
/// IPs with risk > 60 get 2x tighter rate limits (pre-emptive defense).
///
/// 2026-05-21: became `async` so the Cloudflare DNS-proxy auto-toggle
/// (`CloudflareFailover::check_and_toggle`) can `.await` the
/// `PATCH /zones/{zone_id}/dns_records/{record_id}` call inline on
/// escalation transitions. The toggle is gated behind a dry-run flag
/// (default `true`) so the first deploys only log the would-be
/// flips — see `ShieldCloudflareFailoverConfig`.
pub(crate) async fn process_events(
    shield: &mut ShieldState,
    events: &[innerwarden_core::event::Event],
    ip_risk_scores: &std::collections::HashMap<String, u8>,
) -> (u64, Vec<serde_json::Value>, Vec<String>) {
    let mut drops = 0u64;
    let mut incidents = Vec::new();
    let mut blocked_ips = Vec::new();
    let now = chrono::Utc::now();

    for event in events {
        // Extract source IP from event.
        // Spec 037 I-15: trim + filter empty/whitespace so an
        // unactionable "" never reaches the SYN-flood ring buffer or
        // the Cloudflare edge push.
        let Some(ip) = event
            .details
            .get("src_ip")
            .or_else(|| event.details.get("ip"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };

        // Skip non-network events
        let is_network = event.kind.starts_with("network.")
            || event.kind.starts_with("ssh.")
            || event.kind.starts_with("http.")
            || event.kind.starts_with("dns.")
            || event.kind == "port_scan"
            || event.kind == "web_scan"
            || event.kind == "credential_stuffing";

        if !is_network {
            continue;
        }

        // Known high-risk IPs get tighter rate limits (pre-emptive defense).
        // Reduces effective bytes by 2x so they hit the limit faster.
        let risk = ip_risk_scores.get(ip).copied().unwrap_or(0);
        let effective_bytes = {
            let raw = event
                .details
                .get("bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(64);
            if risk > 60 {
                raw * 2
            } else {
                raw
            }
        };

        // Feed rate limiter
        let decision = shield.rate_limiter.process_packet(ip, effective_bytes, now);

        if matches!(decision, RateLimitDecision::Drop) {
            drops += 1;
            // Add to XDP blocklist
            let reason = format!("shield:rate_limit:{}", event.kind);
            if let Err(e) = shield.xdp.add_to_blocklist(ip, &reason) {
                warn!(ip, error = %e, "shield: failed to add to XDP blocklist");
            } else {
                blocked_ips.push(ip.to_string());
            }
        }

        // Track SYN/ACK for SYN flood detection
        if event.kind == "network.syn" || event.kind.contains("syn") {
            shield.syn_detector.record_syn(ip, now);
        }
        if event.kind == "network.ack" || event.kind.contains("established") {
            shield.syn_detector.record_ack(ip, now);
        }

        // TCP fingerprinting. `window_size`/`ttl` are L4 header fields that no
        // current collector captures (they default to 0), so we DO NOT gate on
        // them: the behavioural bot signal is the CONNECTION TIMING variance, which
        // needs only the timestamps that every network event carries. Recording
        // with window 0 keeps the per-IP timing-variance detection live now; the
        // botnet (shared-L4-fingerprint) path stays dormant until a collector
        // supplies a real window/ttl (classify_all skips the window-0 bucket, so
        // absent fingerprints never false-cluster into a botnet).
        //
        // Record with the EVENT's timestamp (`event.ts` = when the request was
        // captured), NOT the slow-loop `now`: the whole point is to measure the
        // client's real inter-connection cadence. Using `now` would timestamp every
        // event in a tick's batch identically (variance 0 → everything looks like a
        // bot) and split a burst across two 30s ticks into a fake 30s gap (variance
        // huge → a real bot looks human). Found live 2026-07-02.
        {
            let window_size = event
                .details
                .get("window_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16;
            let ttl = event
                .details
                .get("ttl")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u8;
            shield
                .fingerprinter
                .record_connection(ip, window_size, ttl, event.ts);
        }
    }

    // TCP-fingerprint bot/botnet classification — run EVERY tick, not gated to the
    // 5-tick escalation cadence. The narrative-tick body is slow (AI/KG/correlation),
    // so a 5-tick gate is ~10 min between classifications, which loses to the 5-min
    // `cleanup_stale`: a bot's fingerprint was purged before it was ever classified
    // (found live 2026-07-02 — a sustained flood never fired). Classifying each tick
    // catches it while it is still tracked. Signal only, de-duped per IP.
    classify_and_emit_bots(shield, &mut incidents);

    // Escalation tick (every 5 ticks = 10s at 2s poll)
    shield.tick_counter += 1;
    if shield.tick_counter.is_multiple_of(5) {
        let syn_flagged = shield.syn_detector.get_flagged_ips();
        let rl_metrics = shield.rate_limiter.get_metrics();

        let metrics = shield.escalation.build_metrics(
            drops / 2, // per-second rate (2s window)
            rl_metrics.blocked_ips,
            !syn_flagged.is_empty(),
            false, // udp_flood
            false, // http_flood
            rl_metrics.total_dropped,
            rl_metrics.total_allowed,
            rl_metrics.total_dropped, // simplified peak_pps
        );

        if let Some(transition) = shield.escalation.update(&metrics) {
            info!(
                from = %transition.from,
                to = %transition.to,
                "shield: escalation state changed"
            );

            // Apply rate limit factor for new state
            let factor = transition.to.rate_limit_factor();
            let mut config = shield.default_rl_config.clone();
            config.bucket_max_tokens *= factor;
            config.bucket_refill_rate *= factor;
            config.window_max_rate = (config.window_max_rate as f64 * factor).max(1.0) as u64;
            shield.rate_limiter.reset_config(config);

            // 2026-05-21: drive the panic-mode responses that were
            // dead code before the inline migration shipped without
            // wiring them.
            //
            // 1. Cloudflare DNS proxy toggle (orange-cloud the site
            //    on UnderAttack / Critical, grey-cloud back on calm).
            //    Honours `min_proxy_duration_secs` internally so a
            //    flap does not produce two API calls within seconds.
            if let Some(cf) = shield.cloudflare_failover.as_mut() {
                if shield.cf_failover_dry_run {
                    info!(
                        state = %transition.to,
                        "shield: cloudflare_failover DRY_RUN — would toggle proxy"
                    );
                } else {
                    let toggled = cf.check_and_toggle(transition.to).await;
                    if toggled {
                        info!(
                            state = %transition.to,
                            "shield: cloudflare_failover proxy state changed"
                        );
                    }
                }
            }

            // 2. iptables CF-only origin lockdown (drops direct-to-origin
            //    HTTP/HTTPS while shield is UnderAttack/Critical, so an
            //    attacker who knows the real origin IP cannot bypass
            //    the Cloudflare edge).
            if let Some(ld) = shield.origin_lockdown.as_mut() {
                if shield.lockdown_dry_run {
                    info!(
                        state = %transition.to,
                        "shield: origin_lockdown DRY_RUN — would toggle iptables CF-only rules"
                    );
                } else {
                    ld.check_and_toggle(transition.to);
                }
            }

            // Create incident for the transition
            let severity = match transition.to {
                EscalationState::Critical => "critical",
                EscalationState::UnderAttack => "high",
                EscalationState::Elevated => "medium",
                _ => "low",
            };

            let host = std::fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "unknown".to_string())
                .trim()
                .to_string();

            let incident = serde_json::json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "host": host,
                "incident_id": format!("shield:escalation:{}:{}",
                    format!("{:?}", transition.to).to_lowercase(),
                    chrono::Utc::now().format("%Y-%m-%dT%H:%MZ")),
                "severity": severity,
                "title": format!("Shield escalation: {} \u{2192} {}", transition.from, transition.to),
                "summary": format!(
                    "DDoS protection escalated. Drops/sec: {}, Attackers: {}, SYN flood: {}",
                    drops / 2, rl_metrics.blocked_ips, !syn_flagged.is_empty()
                ),
                "tags": ["shield", "ddos", "escalation"],
                "entities": [],
            });
            incidents.push(incident);
        }

        // Persist state every 30s (every 6 escalation ticks = 30 main ticks)
        if shield.tick_counter.is_multiple_of(30) {
            let state = innerwarden_shield::store::ShieldState {
                escalation_state: shield.escalation.state(),
                state_entered_at: shield.escalation.state_entered_at().to_rfc3339(),
                blocked_ips: shield.xdp.get_blocklist_entries().to_vec(),
                last_saved: chrono::Utc::now().to_rfc3339(),
            };
            shield.store.save_state(&state).ok();
            shield
                .store
                .save_ddos_history(shield.escalation.incidents())
                .ok();
            // Cleanup stale entries
            shield
                .rate_limiter
                .cleanup_stale(std::time::Duration::from_secs(300), now);
            shield.syn_detector.expire_all(now);
            shield
                .fingerprinter
                .cleanup_stale(std::time::Duration::from_secs(300), now);
            // Drop alerted IPs the fingerprinter no longer tracks (went stale), so
            // the set stays bounded and a bot that returns later re-alerts.
            let fpr = &shield.fingerprinter;
            shield
                .fingerprint_alerted
                .retain(|ip| fpr.get_pattern(ip) != ConnectionPattern::Unknown);
        }
    }

    (drops, incidents, blocked_ips)
}

/// Write shield incidents to the daily JSONL file.
pub(crate) fn write_incidents(data_dir: &Path, incidents: &[serde_json::Value]) {
    if incidents.is_empty() {
        return;
    }

    let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
    let path = data_dir.join(format!("incidents-{today}.jsonl"));

    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            for inc in incidents {
                if let Ok(line) = serde_json::to_string(inc) {
                    let _ = writeln!(f, "{line}");
                }
            }
            info!(count = incidents.len(), "shield: emitted incidents");
        }
        Err(e) => warn!(error = %e, "shield: failed to write incidents"),
    }
}

/// Notify via Telegram for shield escalation events.
/// Gated through the centralized notification gate.
pub(crate) fn notify_telegram(
    telegram_client: &Option<std::sync::Arc<crate::telegram::TelegramClient>>,
    incidents: &[serde_json::Value],
    burst_tracker: &crate::notification_gate::BurstTracker,
    deferred: &mut std::collections::HashMap<String, u32>,
    gate_suppressed_counter: &AtomicU64,
    host: &str,
) {
    let Some(tg) = telegram_client else { return };

    for inc in incidents {
        let severity = inc
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("low");
        if severity != "critical" && severity != "high" {
            continue;
        }

        // Gate through notification policy.
        let ctx = crate::notification_gate::NotificationContext::from_shield_json(inc);
        let verdict =
            crate::notification_gate::should_notify_with_counter(&ctx, gate_suppressed_counter);

        match verdict {
            crate::notification_gate::NotificationVerdict::SendNow => {
                let title = inc
                    .get("title")
                    .and_then(|t| t.as_str())
                    .unwrap_or("Shield alert");
                let summary = inc.get("summary").and_then(|s| s.as_str()).unwrap_or("");

                let emoji = if severity == "critical" {
                    "\u{1f534}"
                } else {
                    "\u{1f7e0}"
                };
                let host_prefix = if host.is_empty() {
                    String::new()
                } else {
                    format!("[{}] ", crate::telegram::escape_html_pub(host))
                };
                let msg = format!(
                    "\u{1f6e1}\u{fe0f} <b>{host_prefix}DDoS Shield</b>\n\n\
                     {emoji} {}\n\
                     <b>{title}</b>\n\
                     {summary}",
                    severity.to_uppercase(),
                );
                let tg = tg.clone();
                tokio::spawn(async move {
                    let _ = tg.send_alert_html(&msg).await;
                });
            }
            crate::notification_gate::NotificationVerdict::DailyBriefingOnly => {
                *deferred.entry(ctx.detector.clone()).or_insert(0) += 1;
                if ctx.is_contained {
                    // Shield escalation is an aggregate DDoS event (no single
                    // attacker IP at the incident level), so source_ip is None.
                    let category = crate::notification_gate::burst_category(&ctx.detector);
                    if let Some(mut summary) = burst_tracker.record_contained(category, None) {
                        summary.host = host.to_string();
                        let msg = crate::notification_gate::format_burst_summary(host, &summary);
                        let tg = tg.clone();
                        tokio::spawn(async move {
                            let _ = tg.send_alert_html(&msg).await;
                        });
                    }
                }
            }
            crate::notification_gate::NotificationVerdict::Drop => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    fn rl_config(
        bucket_max_tokens: f64,
        bucket_refill_rate: f64,
        window_secs: i64,
        window_max_rate: u64,
    ) -> RateLimiterConfig {
        RateLimiterConfig {
            bucket_max_tokens,
            bucket_refill_rate,
            window_secs,
            sub_window_count: 1,
            window_max_rate,
            ema_alpha: 0.3,
            ema_alpha_var: 0.1,
            ema_threshold_multiplier: 3.0,
            // Keep EMA effectively out of the way for deterministic matrix tests.
            ema_min_samples: 10_000,
        }
    }

    fn make_shield_state(config: RateLimiterConfig) -> (tempfile::TempDir, ShieldState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut shield = ShieldState::new(
            dir.path(),
            "/sys/fs/bpf/innerwarden",
            true,
            &ShieldCloudflareFailoverConfig::default(),
            &ShieldOriginLockdownConfig::default(),
        );
        shield.rate_limiter.reset_config(config);
        (dir, shield)
    }

    fn network_event(ip: &str, kind: &str, bytes: u64) -> innerwarden_core::event::Event {
        innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "unit-host".to_string(),
            source: "unit-test".to_string(),
            kind: kind.to_string(),
            severity: innerwarden_core::event::Severity::Info,
            summary: format!("test event {kind}"),
            details: serde_json::json!({
                "src_ip": ip,
                "bytes": bytes,
                "window_size": 1024,
                "ttl": 64
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    /// Drive the classifier: feed `events` (tick 1) then idle-tick to the next
    /// multiple-of-5 tick where `classify_all` runs, returning every incident
    /// produced along the way.
    async fn run_to_classify_tick(
        shield: &mut ShieldState,
        events: &[innerwarden_core::event::Event],
    ) -> Vec<serde_json::Value> {
        let risk = HashMap::new();
        let mut out = Vec::new();
        let (_d, inc, _b) = process_events(shield, events, &risk).await;
        out.extend(inc);
        // tick_counter is now 1; classify runs at every 5th tick.
        while !shield.tick_counter.is_multiple_of(5) {
            let (_d, inc, _b) = process_events(shield, &[], &risk).await;
            out.extend(inc);
        }
        out
    }

    #[tokio::test]
    async fn tcp_fingerprint_bot_classified_and_emitted_as_signal() {
        // A client hammering with >= bot_conn_threshold (100) near-constant-interval
        // connections (variance ~0) is classified Bot and emits a LOW signal
        // incident — never an auto-block (a legit crawler/monitor can look like this).
        let (_dir, mut shield) = make_shield_state(rl_config(1e9, 1e9, 60, u64::MAX));
        let events: Vec<_> = (0..120)
            .map(|_| network_event("203.0.113.7", "network.connect", 100))
            .collect();
        let incidents = run_to_classify_tick(&mut shield, &events).await;
        let bot = incidents
            .iter()
            .find(|i| {
                i["tags"]
                    .as_array()
                    .is_some_and(|t| t.iter().any(|x| x == "tcp_fingerprint"))
            })
            .expect("a tcp_fingerprint bot incident");
        assert!(bot["incident_id"]
            .as_str()
            .unwrap()
            .contains("tcp_fingerprint:bot:203.0.113.7"));
        assert_eq!(bot["severity"], "low", "single-IP bot is a low signal");
        assert!(bot["summary"]
            .as_str()
            .unwrap()
            .contains("not auto-blocked"));

        // Idempotent: a second classify tick must NOT re-emit for the same IP.
        let again = run_to_classify_tick(&mut shield, &[]).await;
        assert!(
            !again.iter().any(|i| i["tags"]
                .as_array()
                .is_some_and(|t| t.iter().any(|x| x == "tcp_fingerprint"))),
            "already-alerted bot must not re-fire every tick"
        );
    }

    #[tokio::test]
    async fn tcp_fingerprint_bot_detected_without_l4_window_the_prod_case() {
        // The real prod condition: NO collector emits window_size/ttl, so the
        // fingerprint has no L4 data. The timing-variance bot detection must still
        // fire from the connection TIMESTAMPS alone (window 0), and such an IP must
        // NOT be mistaken for a botnet (window-0 bucket is skipped).
        let (_dir, mut shield) = make_shield_state(rl_config(1e9, 1e9, 60, u64::MAX));
        let no_l4 = |ip: &str| innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "unit-host".to_string(),
            source: "unit-test".to_string(),
            kind: "network.connect".to_string(),
            severity: innerwarden_core::event::Severity::Info,
            summary: "no-l4".to_string(),
            details: serde_json::json!({ "src_ip": ip, "bytes": 100 }), // no window_size/ttl
            tags: vec![],
            entities: vec![],
        };
        let events: Vec<_> = (0..120).map(|_| no_l4("203.0.113.9")).collect();
        let incidents = run_to_classify_tick(&mut shield, &events).await;
        let bot = incidents.iter().find(|i| {
            i["tags"]
                .as_array()
                .is_some_and(|t| t.iter().any(|x| x == "tcp_fingerprint"))
        });
        let bot = bot.expect("timing-variance bot must fire without any L4 fingerprint");
        assert!(bot["tags"].as_array().unwrap().iter().any(|x| x == "bot"));
        assert!(
            !bot["tags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x == "botnet"),
            "a window-0 (no-L4) IP must never be classed a botnet"
        );
    }

    #[tokio::test]
    async fn tcp_fingerprint_uses_event_ts_regular_is_bot_jittery_is_human() {
        // Proves the fix: classification uses each EVENT's timestamp, not the
        // slow-loop tick time. Regular 50ms intervals -> ~0 variance -> Bot; the
        // same count with heavy jitter -> high variance -> Human (no incident).
        let base = chrono::Utc::now();
        let ev_at = |ip: &str, ms: i64| {
            let mut e = network_event(ip, "network.connect", 100);
            e.ts = base + chrono::Duration::milliseconds(ms);
            e.details["window_size"] = serde_json::json!(0); // no L4 -> pure timing
            e
        };
        // Regular cadence: 120 connections exactly 50ms apart.
        let (_d1, mut sh1) = make_shield_state(rl_config(1e9, 1e9, 60, u64::MAX));
        let regular: Vec<_> = (0..120).map(|i| ev_at("203.0.113.20", i * 50)).collect();
        let inc = run_to_classify_tick(&mut sh1, &regular).await;
        assert!(
            inc.iter().any(|i| i["tags"]
                .as_array()
                .is_some_and(|t| t.iter().any(|x| x == "tcp_fingerprint"))),
            "regular 50ms cadence must classify as Bot"
        );
        // Jittery cadence: 120 connections at pseudo-random-ish intervals.
        let (_d2, mut sh2) = make_shield_state(rl_config(1e9, 1e9, 60, u64::MAX));
        let jittery: Vec<_> = (0..120)
            .map(|i| ev_at("203.0.113.21", i * 500 + (i * i * 37) % 4000))
            .collect();
        let inc2 = run_to_classify_tick(&mut sh2, &jittery).await;
        assert!(
            !inc2.iter().any(|i| i["tags"]
                .as_array()
                .is_some_and(|t| t.iter().any(|x| x == "tcp_fingerprint"))),
            "jittery human-like cadence must NOT be classed a bot"
        );
    }

    #[tokio::test]
    async fn tcp_fingerprint_botnet_rates_high() {
        // >= botnet_ip_threshold (10) IPs sharing one TCP fingerprint (window/TTL)
        // is a coordinated botnet -> High.
        let (_dir, mut shield) = make_shield_state(rl_config(1e9, 1e9, 60, u64::MAX));
        let mut events = Vec::new();
        for i in 1..=12 {
            let ip = format!("198.51.100.{i}");
            for _ in 0..3 {
                events.push(network_event(&ip, "network.connect", 100));
            }
        }
        let incidents = run_to_classify_tick(&mut shield, &events).await;
        let botnet: Vec<_> = incidents
            .iter()
            .filter(|i| {
                i["tags"]
                    .as_array()
                    .is_some_and(|t| t.iter().any(|x| x == "botnet"))
            })
            .collect();
        assert!(
            !botnet.is_empty(),
            "shared fingerprint across 12 IPs = botnet"
        );
        assert_eq!(botnet[0]["severity"], "high");
    }

    #[test]
    fn new_restores_persisted_escalation_state() {
        // Invariant: shield initialization must restore previously persisted escalation state.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::new(dir.path());
        let entered_at = chrono::Utc::now() - chrono::Duration::minutes(5);
        let persisted = innerwarden_shield::store::ShieldState {
            escalation_state: EscalationState::Elevated,
            state_entered_at: entered_at.to_rfc3339(),
            blocked_ips: vec![],
            last_saved: chrono::Utc::now().to_rfc3339(),
        };
        store.save_state(&persisted).expect("save shield state");
        store.save_ddos_history(&[]).expect("save ddos history");

        let shield = ShieldState::new(
            dir.path(),
            "/sys/fs/bpf/innerwarden",
            true,
            &ShieldCloudflareFailoverConfig::default(),
            &ShieldOriginLockdownConfig::default(),
        );
        assert_eq!(shield.escalation.state(), EscalationState::Elevated);
        assert_eq!(shield.tick_counter, 0);
    }

    #[tokio::test]
    async fn process_events_under_limit_allows_without_block_mutation() {
        // Invariant: traffic under both limiters must be allowed and keep block state untouched.
        let (_dir, mut shield) = make_shield_state(rl_config(10.0, 0.0, 10, 10));
        let events = vec![network_event("198.51.100.10", "network.tcp", 128)];

        let (drops, incidents, blocked_ips) =
            process_events(&mut shield, &events, &HashMap::new()).await;

        assert_eq!(drops, 0);
        assert!(incidents.is_empty());
        assert!(blocked_ips.is_empty());
        assert_eq!(shield.rate_limiter.get_metrics().total_allowed, 1);
        assert_eq!(shield.tick_counter, 1);
    }

    #[tokio::test]
    async fn process_events_at_limit_keeps_boundary_packet_allowed() {
        // Invariant: packets that land exactly on configured limits should still be allowed.
        let (_dir, mut shield) = make_shield_state(rl_config(2.0, 0.0, 10, 2));
        let events = vec![
            network_event("198.51.100.11", "network.tcp", 64),
            network_event("198.51.100.11", "network.tcp", 64),
        ];

        let (drops, incidents, blocked_ips) =
            process_events(&mut shield, &events, &HashMap::new()).await;

        let metrics = shield.rate_limiter.get_metrics();
        assert_eq!(drops, 0);
        assert!(incidents.is_empty());
        assert!(blocked_ips.is_empty());
        assert_eq!(metrics.total_allowed, 2);
        assert_eq!(metrics.total_challenged, 0);
        assert_eq!(metrics.total_dropped, 0);
    }

    #[tokio::test]
    async fn process_events_burst_eligible_returns_challenge_without_drop() {
        // Invariant: a single-tripped limiter (burst-only pressure) must challenge, not drop.
        let (_dir, mut shield) = make_shield_state(rl_config(1.0, 0.0, 10, 10));
        let events = vec![
            network_event("198.51.100.12", "network.tcp", 64),
            network_event("198.51.100.12", "network.tcp", 64),
        ];

        let (drops, _incidents, blocked_ips) =
            process_events(&mut shield, &events, &HashMap::new()).await;

        let metrics = shield.rate_limiter.get_metrics();
        assert_eq!(drops, 0);
        assert!(blocked_ips.is_empty());
        assert_eq!(metrics.total_allowed, 1);
        assert_eq!(metrics.total_challenged, 1);
        assert_eq!(metrics.total_dropped, 0);
        assert!(shield.xdp.get_blocklist_entries().is_empty());
    }

    #[tokio::test]
    async fn process_events_window_rollover_resets_window_pressure() {
        // Invariant: once the sliding window expires, new traffic should be evaluated fresh.
        let (_dir, mut shield) = make_shield_state(rl_config(5_000.0, 5_000.0, 1, 1));
        let ip = "198.51.100.13";
        let burst: Vec<_> = (0..1_200)
            .map(|_| network_event(ip, "network.tcp", 64))
            .collect();
        process_events(&mut shield, &burst, &HashMap::new()).await;
        let before_rollover = shield.rate_limiter.get_metrics();
        assert!(
            before_rollover.total_challenged > 0,
            "window pressure should produce at least one challenge before rollover"
        );
        assert_eq!(before_rollover.total_dropped, 0);

        std::thread::sleep(std::time::Duration::from_millis(2_100));
        let later = vec![network_event(ip, "network.tcp", 64)];
        process_events(&mut shield, &later, &HashMap::new()).await;

        let after_rollover = shield.rate_limiter.get_metrics();
        assert_eq!(
            after_rollover.total_allowed,
            before_rollover.total_allowed + 1
        );
        assert_eq!(
            after_rollover.total_challenged,
            before_rollover.total_challenged
        );
        assert_eq!(after_rollover.total_dropped, before_rollover.total_dropped);
    }

    #[tokio::test]
    async fn process_events_drop_path_blocks_ip_and_updates_drop_counters() {
        // Invariant: when both limiters fail, the packet is dropped and the IP is blocklisted.
        let (_dir, mut shield) = make_shield_state(rl_config(1.0, 0.0, 10, 0));
        let ip = "198.51.100.14";
        let events = vec![
            network_event(ip, "network.tcp", 64),
            network_event(ip, "network.tcp", 64),
        ];

        let (drops, _incidents, blocked_ips) =
            process_events(&mut shield, &events, &HashMap::new()).await;

        let metrics = shield.rate_limiter.get_metrics();
        assert_eq!(drops, 1);
        assert_eq!(blocked_ips, vec![ip.to_string()]);
        assert_eq!(metrics.total_dropped, 1);
        assert_eq!(metrics.blocked_ips, 1);
        assert!(shield.xdp.is_blocked(ip));

        // Already-blocked traffic must continue to count as dropped.
        let follow_up = vec![network_event(ip, "network.tcp", 64)];
        let (second_drops, _incidents, _blocked_ips) =
            process_events(&mut shield, &follow_up, &HashMap::new()).await;
        assert_eq!(second_drops, 1);
        assert_eq!(shield.rate_limiter.get_metrics().total_dropped, 2);
    }

    #[test]
    fn write_incidents_empty_input_does_not_create_daily_file() {
        // Invariant: empty incident batches must be a no-op and not create output artifacts.
        let dir = tempfile::tempdir().expect("tempdir");
        write_incidents(dir.path(), &[]);

        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let path = dir.path().join(format!("incidents-{today}.jsonl"));
        assert!(!path.exists());
    }

    #[test]
    fn write_incidents_non_empty_batch_appends_jsonl_lines() {
        // Invariant: each emitted incident must be persisted as one JSONL line.
        let dir = tempfile::tempdir().expect("tempdir");
        let incidents = vec![
            serde_json::json!({"severity": "high", "title": "first"}),
            serde_json::json!({"severity": "critical", "title": "second"}),
        ];
        write_incidents(dir.path(), &incidents);

        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let path = dir.path().join(format!("incidents-{today}.jsonl"));
        let content = std::fs::read_to_string(path).expect("read incidents file");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).expect("first line json");
        let second: serde_json::Value = serde_json::from_str(lines[1]).expect("second line json");
        assert_eq!(first["title"], "first");
        assert_eq!(second["title"], "second");
    }

    #[test]
    fn notify_telegram_without_client_is_noop() {
        // Invariant: no Telegram client means no gate/deferred mutations and no side effects.
        let incidents = vec![serde_json::json!({
            "severity": "high",
            "title": "Shield escalation",
            "summary": "blocked"
        })];
        let burst_tracker = crate::notification_gate::BurstTracker::new();
        let mut deferred = HashMap::new();
        let counter = AtomicU64::new(0);

        notify_telegram(
            &None,
            &incidents,
            &burst_tracker,
            &mut deferred,
            &counter,
            "test-host",
        );

        assert!(deferred.is_empty());
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        assert_eq!(burst_tracker.count(), 0);
    }

    #[test]
    fn notify_telegram_daily_briefing_path_increments_deferred_and_counter() {
        // Invariant: contained high/critical shield events must defer to daily briefing, not send now.
        let telegram_client = Some(Arc::new(
            crate::telegram::TelegramClient::new("token", "123", None).expect("telegram client"),
        ));
        let incidents = vec![serde_json::json!({
            "severity": "high",
            "title": "Shield escalation",
            "summary": "contained attack"
        })];
        let burst_tracker = crate::notification_gate::BurstTracker::new();
        let mut deferred = HashMap::new();
        let counter = AtomicU64::new(0);

        notify_telegram(
            &telegram_client,
            &incidents,
            &burst_tracker,
            &mut deferred,
            &counter,
            "test-host",
        );

        assert_eq!(deferred.get("shield").copied(), Some(1));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert_eq!(burst_tracker.count(), 1);
    }

    /// 2026-05-21 anchor: ShieldState wires `CloudflareFailover` whenever the
    /// operator supplied API token + zone + record. Pre-fix the inline
    /// shield migration shipped without instantiating the failover at all
    /// (the crate's `cloudflare_failover` module was dead code), so a
    /// volumetric DDoS escalation never reached for the orange-cloud
    /// API. This test pins the instantiation contract.
    #[test]
    fn shield_state_constructs_cloudflare_failover_when_credentials_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cf = ShieldCloudflareFailoverConfig {
            enabled: true,
            dry_run: true,
            api_token: "t".into(),
            zone_id: "z".into(),
            record_id: "r".into(),
            activate_on: vec!["Critical".into()],
            min_proxy_duration_secs: 300,
        };
        let lockdown = ShieldOriginLockdownConfig::default();
        let shield = ShieldState::new(dir.path(), "/sys/fs/bpf/innerwarden", true, &cf, &lockdown);
        assert!(
            shield.cloudflare_failover.is_some(),
            "failover must be wired when token+zone+record are set"
        );
        assert!(
            shield.cf_failover_dry_run,
            "dry-run flag must propagate into ShieldState"
        );
    }

    /// 2026-05-21 anchor: missing credentials silently disable the failover
    /// (`None`), so the dry-run audit window cannot accidentally call into
    /// the Cloudflare API with empty config and surface a 401.
    #[test]
    fn shield_state_skips_cloudflare_failover_when_credentials_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Enabled, but token + record_id empty — must NOT instantiate.
        let cf = ShieldCloudflareFailoverConfig {
            enabled: true,
            dry_run: true,
            api_token: String::new(),
            zone_id: "z".into(),
            record_id: String::new(),
            activate_on: vec![],
            min_proxy_duration_secs: 0,
        };
        let lockdown = ShieldOriginLockdownConfig::default();
        let shield = ShieldState::new(dir.path(), "/sys/fs/bpf/innerwarden", true, &cf, &lockdown);
        assert!(
            shield.cloudflare_failover.is_none(),
            "failover must not instantiate without API token + record_id"
        );
    }

    /// 2026-05-21 anchor: `origin_lockdown.enabled = true` must wire the
    /// OriginLockdown into ShieldState; the dry-run gate is enforced at
    /// the call site, not at construction time.
    #[test]
    fn shield_state_constructs_origin_lockdown_when_enabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lockdown = ShieldOriginLockdownConfig {
            enabled: true,
            dry_run: true,
        };
        let shield = ShieldState::new(
            dir.path(),
            "/sys/fs/bpf/innerwarden",
            true,
            &ShieldCloudflareFailoverConfig::default(),
            &lockdown,
        );
        assert!(shield.origin_lockdown.is_some());
        assert!(shield.lockdown_dry_run);
    }

    #[test]
    fn shield_state_skips_origin_lockdown_when_disabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shield = ShieldState::new(
            dir.path(),
            "/sys/fs/bpf/innerwarden",
            true,
            &ShieldCloudflareFailoverConfig::default(),
            &ShieldOriginLockdownConfig::default(),
        );
        assert!(shield.origin_lockdown.is_none());
    }
}
