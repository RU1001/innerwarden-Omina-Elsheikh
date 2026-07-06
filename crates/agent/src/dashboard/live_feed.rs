// Auto-extracted from mod.rs — dashboard live_feed handlers

use super::*;
use std::sync::atomic::Ordering;

// ---------------------------------------------------------------------------
// Public live-feed endpoints (CORS-enabled, no auth)
// ---------------------------------------------------------------------------

/// Per-IP local reputation summary included in live-feed responses.
#[derive(Serialize, Deserialize, Clone)]
pub(super) struct LiveFeedReputation {
    total_incidents: u32,
    total_blocks: u32,
    reputation_score: f32,
    first_seen: String,
    last_seen: String,
}

/// MITRE ATT&CK annotation attached to live-feed items.
#[derive(Serialize, Clone)]
pub(super) struct LiveFeedMitre {
    tactic: String,
    technique_id: String,
    technique_name: String,
}

/// Item returned by the public live feed.
#[derive(Serialize)]
pub(super) struct LiveFeedItem {
    ts: String,
    severity: String,
    title: String,
    ip: Option<String>,
    action: Option<String>,
    /// Resolution outcome: "blocked", "monitored", "ignored", "open", etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    confidence: Option<f32>,
    reason: Option<String>,
    /// Local IP reputation data (present when the IP has been seen before).
    #[serde(skip_serializing_if = "Option::is_none")]
    reputation: Option<LiveFeedReputation>,
    /// MITRE ATT&CK mapping derived from the detector name.
    #[serde(skip_serializing_if = "Option::is_none")]
    mitre: Option<LiveFeedMitre>,
    /// Detector that triggered this incident (e.g. "ssh_bruteforce").
    #[serde(skip_serializing_if = "Option::is_none")]
    detector: Option<String>,
}

/// On-disk representation of LocalIpReputation (written by agent main loop).
#[derive(Deserialize)]
pub(super) struct StoredIpReputation {
    total_incidents: u32,
    total_blocks: u32,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    reputation_score: f32,
}

/// Load the `ip-reputation.json` file written by the agent's slow loop.
pub(super) fn load_ip_reputation_map(data_dir: &Path) -> HashMap<String, StoredIpReputation> {
    let path = data_dir.join("ip-reputation.json");
    // Resolve symlinks and verify the path stays within the data directory (CWE-22).
    let Ok(canonical) = path.canonicalize() else {
        return HashMap::new();
    };
    let Ok(canonical_dir) = data_dir.canonicalize() else {
        return HashMap::new();
    };
    if !canonical.starts_with(&canonical_dir) {
        return HashMap::new();
    }
    let Ok(content) = std::fs::read_to_string(&canonical) else {
        return HashMap::new();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

/// 2026-05-03 (Wave 6a): one row in the `sources` array of
/// `LiveFeedResponse`. Carries the geo data already attached so the
/// frontend can render the attack-origins map without a follow-up
/// `/api/live-feed/geoip` round-trip per IP.
///
/// `incidents` is the count of distinct incidents this IP triggered
/// in the response window — drives the marker size/heat on the map.
#[derive(Serialize, Clone, Debug)]
pub(super) struct LiveFeedSource {
    pub ip: String,
    /// 2-letter or full country name from ip-api. Empty when the
    /// cache miss has not been backfilled yet.
    pub country: String,
    pub lat: f64,
    pub lon: f64,
    pub incidents: u32,
}

/// Live feed response with totals, items, and pre-enriched origin map.
#[derive(Serialize)]
pub(super) struct LiveFeedResponse {
    total_today: usize,
    total_blocked: usize,
    total_high: usize,
    /// Number of unique source IPs across all real incidents today.
    unique_sources: usize,
    /// 2026-05-03 (Wave 6a): per-IP geo enrichment for the map. One
    /// entry per unique source IP (deduped). Geo fields are populated
    /// from the on-disk `geo-cache.json` — IPs not yet in the cache
    /// arrive with `country=""` / `lat=lon=0.0` and the frontend
    /// either renders them at lat=0/lon=0 OR (preferred) skips them
    /// from the map until the next slow_loop tick backfills the
    /// cache. Bounded at 200 (matches `items`) so a 10k-IP day cannot
    /// blow the response size.
    sources: Vec<LiveFeedSource>,
    items: Vec<LiveFeedItem>,
}

impl LiveFeedResponse {
    #[cfg(test)]
    pub(super) fn total_blocked(&self) -> usize {
        self.total_blocked
    }
}

/// Count **unique IPs** blocked today, not raw block decisions.
///
/// Without dedup, a single attacker blocked N times (retries, new
/// incidents, lifecycle re-entries) shows up N times, which is why the
/// "Blocked" KPI on the site and the dashboard Home KPI used to report
/// different numbers for the same traffic. The semantic this function
/// pins is "how many distinct IPs did the agent contain today"; it is
/// shared by `/api/live-feed` here and `/api/agent/security-context` in
/// `agent_api.rs` so every surface that reads "Blocked Today" agrees.
///
/// # Wave 10b (AUDIT-WAVE10B-NON-INCIDENT-BLOCKS, 2026-05-05)
///
/// Pre-Wave-10b a block decision was counted only if its `incident_id`
/// matched an entry in `real_ids` (today's real-incident IDs). On
/// 2026-05-05 the operator hit `total_blocked: 0` while
/// `decisions-2026-05-05.jsonl` had 450 `block_ip` decisions —
/// because today's blocks all came from non-incident paths whose
/// `incident_id` shape never appears in `incidents-*.jsonl`:
///
///   * `honeypot:always-on:abuseipdb:<ip>` — honeypot AbuseIPDB submits
///   * `repeat-offender:<ip>:<ts>`         — repeat-offender ladder
///   * `proto_anomaly:SshVersionAnomaly:*` — direct decisions w/o incident
///
/// These are legitimate auto-blocks that the public site SHOULD count.
/// The fix accepts a decision as public-eligible when EITHER:
///   1. its `incident_id` matches a real incident, OR
///   2. its `incident_id` starts with one of the known
///      non-incident-pipeline prefixes (`is_public_block_decision`).
///
/// The classifier is conservative: any decision shape we don't
/// recognise still requires `real_ids` membership, so a future
/// internal/research-only block path can't accidentally inflate the
/// public count.
pub(super) fn count_unique_ips_blocked(
    decisions: &[DecisionEntry],
    real_ids: &std::collections::HashSet<&str>,
) -> usize {
    let mut ips: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for d in decisions {
        if d.action_type != "block_ip" {
            continue;
        }
        if !is_public_block_decision(d, real_ids) {
            continue;
        }
        if let Some(ip) = d.target_ip.as_deref().filter(|s| !s.is_empty()) {
            ips.insert(ip);
        }
    }
    ips.len()
}

/// Wave 10b classifier: is this `block_ip` decision public-eligible?
///
/// Returns true when the decision either references a real incident
/// (the existing pipeline path) OR carries one of the well-known
/// non-incident-pipeline incident_id shapes that the production agent
/// emits for auto-blocks (honeypot AbuseIPDB submits, repeat-offender
/// ladder, direct proto-anomaly decisions). The list is allow-list
/// not regex — adding a new auto-block path is a small, deliberate
/// change to this function with a matching anchor test.
pub(super) fn is_public_block_decision(
    d: &DecisionEntry,
    real_ids: &std::collections::HashSet<&str>,
) -> bool {
    if real_ids.contains(d.incident_id.as_str()) {
        return true;
    }
    // Wave 10b: known non-incident-pipeline auto-block paths.
    // Each prefix corresponds to a distinct production code path
    // that emits `block_ip` decisions without going through the
    // standard incident-creation flow.
    const PUBLIC_NON_INCIDENT_PREFIXES: &[&str] = &[
        "honeypot:always-on:abuseipdb:",
        "honeypot:abuseipdb:",
        "repeat-offender:",
        "proto_anomaly:",
        "suspicious_archive:",
        "logging_config_change:",
    ];
    let id = d.incident_id.as_str();
    PUBLIC_NON_INCIDENT_PREFIXES
        .iter()
        .any(|prefix| id.starts_with(prefix))
}

/// `GET /api/live-feed` - last 200 incidents with totals for the day (public).
///
/// 2026-05-15: source is the canonical SQLite store when available
/// (matches the post-spec-049 architecture that moved
/// `/api/overview` + `/api/sensors` to SQLite). The in-memory
/// knowledge-graph path is retained as a fallback when no store is
/// configured (test fixtures, dev mode). Pre-2026-05-15 this read
/// exclusively from KG + JSONL, which produced ~1h staleness after
/// an agent restart because the post-restart KG hydrates from the
/// last graph_snapshot rather than from incoming events.
///
/// Heavy work runs on the blocking pool — `tokio::task::spawn_blocking`
/// keeps async workers responsive when SQLite reads stretch the
/// response (`RECURRING_BUGS.md` "Dashboard handlers block tokio
/// worker threads").
pub(super) async fn api_live_feed(State(state): State<DashboardState>) -> Json<LiveFeedResponse> {
    let kg = std::sync::Arc::clone(&state.knowledge_graph);
    let data_dir = state.data_dir.clone();
    let store = state.sqlite_store.clone();
    let resp = tokio::task::spawn_blocking(move || {
        build_live_feed_response(&kg, &data_dir, store.as_deref())
    })
    .await
    .unwrap_or_else(|_| LiveFeedResponse {
        total_today: 0,
        total_blocked: 0,
        total_high: 0,
        unique_sources: 0,
        sources: Vec::new(),
        items: Vec::new(),
    });
    Json(resp)
}

/// 2026-05-03 (Wave 5c PR-5): load incidents from
/// `incidents-{date}.jsonl` for a list of dates. JSONL is the canonical
/// historical record (the agent appends but never rewrites); the
/// in-memory KG is a hot tier capped by TTL eviction. Live-feed reads
/// BOTH and merges so the operator sees the full daily history even
/// for entries that have been evicted from the graph.
///
/// I/O failures are swallowed (file missing, bad permissions) so a
/// partial degradation never takes down the public live-feed endpoint.
pub(super) fn load_jsonl_incidents(data_dir: &Path, dates: &[String]) -> Vec<Incident> {
    let mut out = Vec::new();
    for date in dates {
        let path = data_dir.join(format!("incidents-{date}.jsonl"));
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(inc) = serde_json::from_str::<Incident>(line) {
                out.push(inc);
            }
        }
    }
    out
}

/// 2026-05-03 (Wave 5c PR-5): load decisions from
/// `decisions-{date}.jsonl` for a list of dates. Same rationale as
/// `load_jsonl_incidents` — KG retains a Decision summary on the
/// matching Incident node but only for incidents still in the graph.
/// JSONL is the canonical record for the count surfaces (e.g.
/// "Blocks today" KPI on the site live feed).
pub(super) fn load_jsonl_decisions(data_dir: &Path, dates: &[String]) -> Vec<DecisionEntry> {
    let mut out = Vec::new();
    for date in dates {
        let path = data_dir.join(format!("decisions-{date}.jsonl"));
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(dec) = serde_json::from_str::<DecisionEntry>(line) {
                out.push(dec);
            }
        }
    }
    out
}

/// 2026-05-03 (Wave 5c PR-5): merge KG-derived and JSONL-derived
/// incident lists, preferring the KG entry when both are present.
/// KG carries richer context (entity links, decision metadata) than
/// the on-disk JSONL line, so preferring KG keeps the operator-facing
/// item list as informative as possible. JSONL fills in entries the
/// KG has evicted under TTL pressure.
///
/// Pure function; takes ownership of the two vecs and returns one.
/// Tested directly so the dedup contract stays pinned.
pub(super) fn merge_incidents_prefer_kg(
    kg_incidents: Vec<Incident>,
    jsonl_incidents: Vec<Incident>,
) -> Vec<Incident> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(kg_incidents.len() + jsonl_incidents.len());
    for inc in kg_incidents {
        seen.insert(inc.incident_id.clone());
        out.push(inc);
    }
    for inc in jsonl_incidents {
        if seen.insert(inc.incident_id.clone()) {
            out.push(inc);
        }
    }
    out
}

/// Same dedup contract as `merge_incidents_prefer_kg` but for
/// decisions. KG-derived decisions arrive first in `kg_decisions`;
/// JSONL fills in decisions whose incident has aged out of the graph.
pub(super) fn merge_decisions_prefer_kg(
    kg_decisions: Vec<DecisionEntry>,
    jsonl_decisions: Vec<DecisionEntry>,
) -> Vec<DecisionEntry> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(kg_decisions.len() + jsonl_decisions.len());
    for d in kg_decisions {
        seen.insert(d.incident_id.clone());
        out.push(d);
    }
    for d in jsonl_decisions {
        if seen.insert(d.incident_id.clone()) {
            out.push(d);
        }
    }
    out
}

/// Pure helper extracted from `api_live_feed` so the heavy work runs on the
/// blocking pool and stays unit-testable. Same logic as before — only the
/// scope of the read lock changed.
pub(super) fn build_live_feed_response(
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    data_dir: &std::path::Path,
    store: Option<&innerwarden_store::Store>,
) -> LiveFeedResponse {
    // Wave 10 (label honesty, 2026-05-05): the public site renders
    // "(24h)" next to every count on this response. Pre-fix the
    // builder honoured no time window and read every incident the KG
    // retained — anywhere from minutes to days, depending on KG
    // eviction state. The "(24h)" label was therefore a lie under any
    // hot-tier load. Clipping incidents to `now - 24h` here makes the
    // label match the data, and downstream surfaces (`total_today`,
    // `total_blocked`, `total_high`, `unique_sources`) stay
    // consistent because they all derive from `real_incidents`.
    let now = chrono::Utc::now();
    let cutoff_24h = now - chrono::Duration::hours(24);
    let reputation_map = load_ip_reputation_map(data_dir);

    // 2026-05-15: SQLite-first read. Pre-fix the live-feed read
    // exclusively from the in-memory KG, which hydrates from the
    // last graph_snapshot on agent restart. Post-restart, new
    // incidents went straight to SQLite (the canonical store from
    // spec 016 onwards) but the KG only grew via the slow_loop's
    // snapshot save → reload cycle, producing ~1h of staleness on
    // the public site. The SQLite path queries the canonical store
    // directly. The KG path stays as a fallback for fixtures and
    // dev-mode (no Store configured).
    let (incidents, decisions) = if let Some(s) = store {
        load_live_feed_data_from_sqlite(s, cutoff_24h)
    } else {
        load_live_feed_data_from_kg_with_jsonl_fallback(kg, data_dir, cutoff_24h)
    };
    build_live_feed_from_lists(incidents, decisions, cutoff_24h, data_dir, reputation_map)
}

/// 2026-05-15: SQLite-first source. Reads incidents within the last
/// 24h via `Store::incidents_since_ts` + their decisions for today
/// and yesterday (cross-midnight). Same shape the legacy KG path
/// produces — downstream filtering / mapping is identical.
fn load_live_feed_data_from_sqlite(
    store: &innerwarden_store::Store,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> (Vec<Incident>, Vec<DecisionEntry>) {
    // Hard upper bound on rows pulled per request. Loose enough that no
    // honest workload truncates; tight enough that a pathological day
    // cannot pin the response thread (same envelope cases_from_sqlite
    // uses for the Cases tab).
    const LIVE_FEED_SQLITE_LIMIT: usize = 100_000;

    let cutoff_str = cutoff.to_rfc3339();
    let incidents = store
        .incidents_since_ts(&cutoff_str, LIVE_FEED_SQLITE_LIMIT)
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "live_feed: SQLite incidents query failed; returning empty");
            Vec::new()
        });

    // Pull decisions for today and yesterday so the cross-midnight
    // window catches the previous day's tail.
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let yesterday = (chrono::Local::now() - chrono::Duration::days(1))
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let mut decisions: Vec<DecisionEntry> = Vec::new();
    for date in [today, yesterday] {
        match store.decisions_for_date(&date, LIVE_FEED_SQLITE_LIMIT) {
            Ok(rows) => {
                for (_ts, _incident_id, data_json) in rows {
                    if let Ok(d) = serde_json::from_str::<DecisionEntry>(&data_json) {
                        decisions.push(d);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "live_feed: SQLite decisions query failed for {date}");
            }
        }
    }

    (incidents, decisions)
}

/// Legacy path — used when no Store is configured. Same logic that
/// shipped before 2026-05-15: walk the in-memory KG, augment with
/// JSONL on-disk records (best-effort), merge preferring the KG entry.
/// Kept for test fixtures that build a `DashboardState` without a
/// SQLite store; never reached on prod.
fn load_live_feed_data_from_kg_with_jsonl_fallback(
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    data_dir: &std::path::Path,
    _cutoff: chrono::DateTime<chrono::Utc>,
) -> (Vec<Incident>, Vec<DecisionEntry>) {
    use crate::knowledge_graph::types::{Node, NodeType, Relation};
    let graph = kg.read().unwrap();
    let mut incidents: Vec<Incident> = Vec::new();
    let mut decisions: Vec<DecisionEntry> = Vec::new();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident {
            incident_id,
            severity,
            title,
            summary,
            ts,
            mitre_ids,
            decision,
            confidence,
            decision_reason,
            decision_target,
            auto_executed,
            detector: _,
            research_only,
            ..
        }) = graph.get_node(id)
        {
            // Spec 015 follow-up: hide research_only incidents from the
            // operator live feed. They still live in the graph (neural
            // training + investigation views still see them) but don't
            // pollute the Threats tab with self-traffic to Telegram,
            // Cloudflare, AWS, Oracle peers, etc.
            if *research_only {
                continue;
            }
            // Collect entities from TriggeredBy edges
            let entities: Vec<innerwarden_core::entities::EntityRef> = graph
                .outgoing_edges(id)
                .iter()
                .filter(|e| e.relation == Relation::TriggeredBy)
                .filter_map(|e| match graph.get_node(e.to) {
                    Some(Node::Ip { addr, .. }) => {
                        Some(innerwarden_core::entities::EntityRef::ip(addr))
                    }
                    Some(Node::User { name, .. }) => {
                        Some(innerwarden_core::entities::EntityRef::user(name))
                    }
                    _ => None,
                })
                .collect();

            let sev = match severity.to_lowercase().as_str() {
                "critical" => innerwarden_core::event::Severity::Critical,
                "high" => innerwarden_core::event::Severity::High,
                "medium" => innerwarden_core::event::Severity::Medium,
                "low" => innerwarden_core::event::Severity::Low,
                _ => innerwarden_core::event::Severity::Info,
            };

            incidents.push(Incident {
                ts: *ts,
                host: String::new(),
                incident_id: incident_id.clone(),
                severity: sev,
                title: title.clone(),
                summary: summary.clone(),
                evidence: serde_json::json!({}),
                recommended_checks: vec![],
                tags: mitre_ids.clone(),
                entities,
            });

            if let Some(action) = decision {
                decisions.push(DecisionEntry {
                    ts: *ts,
                    incident_id: incident_id.clone(),
                    host: String::new(),
                    ai_provider: String::new(),
                    action_type: action.clone(),
                    target_ip: decision_target.clone(),
                    target_user: None,
                    skill_id: None,
                    confidence: confidence.unwrap_or(0.0),
                    auto_executed: *auto_executed,
                    dry_run: false,
                    reason: decision_reason.clone().unwrap_or_default(),
                    execution_result: if *auto_executed {
                        "ok".into()
                    } else {
                        "skipped".into()
                    },
                    estimated_threat: String::new(),
                    prev_hash: None,
                    decision_layer: None,
                });
            }
        }
    }

    // 2026-05-03 (Wave 5c PR-5): drop the KG read lock before doing
    // the JSONL augmentation. The on-disk read can take 10–50 ms on
    // hot files; holding the read lock that long would block the
    // slow_loop's KG mutations (cleanup_expired / enforce_memory_limit
    // / save_to_store) which run under a write lock.
    drop(graph);

    // JSONL augmentation (best-effort; usually empty after spec 016).
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let yesterday = (chrono::Local::now() - chrono::Duration::days(1))
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let dates = vec![today, yesterday];
    let jsonl_incidents = load_jsonl_incidents(data_dir, &dates);
    let jsonl_decisions = load_jsonl_decisions(data_dir, &dates);
    let incidents = merge_incidents_prefer_kg(incidents, jsonl_incidents);
    let decisions = merge_decisions_prefer_kg(decisions, jsonl_decisions);

    (incidents, decisions)
}

/// 2026-05-15: pure transform from (incidents, decisions) to the
/// LiveFeedResponse shape. Both source paths (SQLite + legacy KG/JSONL)
/// feed this helper, so the filter / clip-to-24h / per-IP grouping /
/// title-and-reason rendering logic lives in one place and is
/// unit-testable without spinning up a Store or a KG.
fn build_live_feed_from_lists(
    incidents: Vec<Incident>,
    decisions: Vec<DecisionEntry>,
    cutoff_24h: chrono::DateTime<chrono::Utc>,
    data_dir: &std::path::Path,
    reputation_map: HashMap<String, StoredIpReputation>,
) -> LiveFeedResponse {
    let decision_map: HashMap<String, &DecisionEntry> = decisions
        .iter()
        .map(|d| (d.incident_id.clone(), d))
        .collect();

    // Filter real attacks only (exclude internal noise) AND clip to
    // the rolling 24h window the public site labels claim. Same Wave-10
    // contract whether the source is SQLite or the legacy KG path.
    let real_incidents: Vec<&Incident> = incidents
        .iter()
        .filter(|i| !is_internal(i) && i.ts >= cutoff_24h)
        .collect();

    // Build incident IDs set for matching decisions to real attacks only.
    let real_ids: std::collections::HashSet<&str> = real_incidents
        .iter()
        .map(|i| i.incident_id.as_str())
        .collect();

    let total_today = real_incidents.len();
    let total_blocked = count_unique_ips_blocked(&decisions, &real_ids);
    let total_high = real_incidents
        .iter()
        .filter(|i| matches!(i.severity, Severity::High | Severity::Critical))
        .count();
    // 2026-05-03 (Wave 6a): build the per-IP source list with geo
    // attached. Counting incidents per IP first so the map can size
    // markers by activity. Geo lookup is cache-only (load_cache reads
    // `geo-cache.json`) — no API hit at request time. Cache misses
    // arrive at the frontend with `country=""` so the JS can decide
    // to either skip the marker or render it at the equator until
    // the slow_loop tick backfills it.
    let mut incidents_per_ip: HashMap<String, u32> = HashMap::new();
    for inc in &real_incidents {
        for e in &inc.entities {
            if e.r#type == EntityType::Ip {
                *incidents_per_ip.entry(e.value.clone()).or_insert(0) += 1;
            }
        }
    }
    let unique_sources = incidents_per_ip.len();
    let geo_cache = crate::geo_cache::load_cache(data_dir);
    let now_secs = chrono::Utc::now().timestamp();
    let mut sources: Vec<LiveFeedSource> = incidents_per_ip
        .into_iter()
        .map(|(ip, incidents)| {
            let geo = geo_cache.get_fresh(&ip, now_secs);
            LiveFeedSource {
                ip,
                country: geo.map(|g| g.country.clone()).unwrap_or_default(),
                lat: geo.map(|g| g.lat).unwrap_or(0.0),
                lon: geo.map(|g| g.lon).unwrap_or(0.0),
                incidents,
            }
        })
        .collect();
    // Sort: most-active first so a 200-cap keeps the busiest IPs.
    sources.sort_by(|a, b| b.incidents.cmp(&a.incidents));
    sources.truncate(200);

    let mut items: Vec<LiveFeedItem> = real_incidents
        .iter()
        .rev()
        .take(200)
        .map(|inc| {
            let ip = inc
                .entities
                .iter()
                .find(|e| e.r#type == EntityType::Ip)
                .map(|e| e.value.clone());
            let dec = decision_map.get(&inc.incident_id);
            let reputation = ip.as_ref().and_then(|ip_val| {
                reputation_map.get(ip_val).map(|r| LiveFeedReputation {
                    total_incidents: r.total_incidents,
                    total_blocks: r.total_blocks,
                    reputation_score: r.reputation_score,
                    first_seen: r.first_seen.to_rfc3339(),
                    last_seen: r.last_seen.to_rfc3339(),
                })
            });
            let detector = mitre::detector_from_incident_id(&inc.incident_id);
            let mitre_info = mitre::map_detector(detector).map(|m| LiveFeedMitre {
                tactic: m.tactic.to_string(),
                technique_id: m.technique_id.to_string(),
                technique_name: m.technique_name.to_string(),
            });
            let outcome = dec.map(|d| {
                match d.action_type.as_str() {
                    "block_ip" => "blocked",
                    "suspend_user_sudo" => "suspended",
                    "kill_process" => "killed",
                    "block_container" => "contained",
                    "monitor" => "monitored",
                    "honeypot" => "honeypot",
                    "ignore" => "ignored",
                    _ => "resolved",
                }
                .to_string()
            });
            let det_name = if detector.is_empty() {
                None
            } else {
                Some(detector.to_string())
            };
            LiveFeedItem {
                ts: inc.ts.to_rfc3339(),
                severity: format!("{:?}", inc.severity).to_lowercase(),
                title: live_feed_title(detector, &inc.severity),
                ip,
                action: dec.map(|d| d.action_type.clone()),
                outcome,
                confidence: dec.map(|d| d.confidence),
                reason: dec.map(|d| live_feed_reason(detector, &d.action_type)),
                reputation,
                mitre: mitre_info,
                detector: det_name,
            }
        })
        .collect();
    items.reverse();

    LiveFeedResponse {
        total_today,
        total_blocked,
        total_high,
        unique_sources,
        sources,
        items,
    }
}

/// Sanitized title for public live feed. No paths, PIDs, UIDs, usernames.
/// Replaces with fun hacker-protector personality messages.
pub(super) fn live_feed_title(detector: &str, severity: &Severity) -> String {
    match detector {
        "ssh_bruteforce" => "Brute force in progress. Tracking attempt count and origin.".into(),
        "credential_stuffing" => {
            "Credential spray detected. Someone's trying stolen passwords.".into()
        }
        "port_scan" => "Port scan detected. Someone's knocking on every door.".into(),
        "packet_flood" => "Traffic spike detected. Looks like someone brought friends.".into(),
        "data_exfil" | "data_exfil_cmd" | "data_exfil_ebpf" => {
            "Data exfiltration attempt caught. Nice try.".into()
        }
        "reverse_shell" => "Reverse shell blocked. Not today.".into(),
        "privesc" => "Privilege escalation attempt detected and flagged.".into(),
        "rootkit" => "Kernel anomaly detected. Running deep inspection.".into(),
        "ransomware" => {
            "Ransomware behavior detected. Encryption blocked, process terminated.".into()
        }
        "dns_tunneling" | "dns_tunneling_ebpf" => {
            "DNS tunneling detected. Hidden channel exposed.".into()
        }
        "c2_callback" => "C2 beacon detected. Communication channel disrupted.".into(),
        "crypto_miner" => "Cryptominer detected. Your CPU is not for rent.".into(),
        "container_escape" => "Container escape attempt blocked.".into(),
        "lateral_movement" => "Lateral movement detected. Containment in progress.".into(),
        "web_shell" => "Web shell detected and neutralized.".into(),
        "process_injection" => "Process injection blocked. Code integrity maintained.".into(),
        "fileless" => "Fileless malware detected in memory. Cleaned.".into(),
        "log_tampering" => "Log tampering attempt. Someone tried to erase their tracks.".into(),
        "ssh_key_injection" => "SSH key injection blocked. Unauthorized access denied.".into(),
        "crontab_persistence" | "systemd_persistence" => {
            "Persistence mechanism detected and flagged.".into()
        }
        "kernel_module_load" => "New kernel module detected. Under review.".into(),
        "discovery_burst" => "Reconnaissance sweep detected. Target is mapping the system.".into(),
        "sigma" => "Known attack pattern matched by community rules.".into(),
        "process_tree" => "Suspicious process chain detected.".into(),
        "neural_anomaly" => "AI detected unusual behavior pattern.".into(),
        "masquerading" => "Binary masquerading detected. Fake identity exposed.".into(),
        "suspicious_execution" => "Suspicious process execution flagged for review.".into(),
        "io_uring_create" => "io_uring syscall bypass attempt detected.".into(),
        // Previously these fell through to the generic severity line, which made
        // the public feed read "High severity threat detected." on a large share
        // of real catches. Each gets a specific, sanitized headline (no paths,
        // rules, or thresholds) so a visitor sees what actually happened.
        "proto_anomaly" => {
            "Protocol anomaly. Something on this port is lying about what it is.".into()
        }
        "threat_intel" => "Known-bad address recognized on sight. Reputation said no.".into(),
        "honeypot" => "Took the honeypot bait. Every keystroke recorded.".into(),
        "suspicious_login" => "A login that does not add up. Flagged and watched.".into(),
        "data_exfiltration" => "Data exfiltration attempt caught. Nice try.".into(),
        "credential_harvest" => "Someone reached for the credentials. Caught in the act.".into(),
        "sudo_abuse" => "Sudo aimed at the locks, not the work. Flagged.".into(),
        "setns_owner" => "Root walked into a namespace it never created.".into(),
        "untrusted_root_exec" => "Root ran code from a place attackers can write.".into(),
        "provenance" => "Root power, used down a path that cannot justify it.".into(),
        "nmap_scan" => "Port scan detected. Someone is knocking on every door.".into(),
        _ => match severity {
            Severity::Critical => "Critical threat detected and handled.".into(),
            Severity::High => "High severity threat detected.".into(),
            _ => "Suspicious activity detected and logged.".into(),
        },
    }
}

/// Sanitized reason for public live feed with personality.
pub(super) fn live_feed_reason(detector: &str, action: &str) -> String {
    let action_verb = match action {
        "block_ip" => "IP blocked",
        "kill_process" => "Process terminated",
        "suspend_user_sudo" => "Access suspended",
        "honeypot" => "Redirected to honeypot",
        "monitor" => "Monitoring",
        _ => "Handled",
    };

    match detector {
        "ssh_bruteforce" => format!("Brute force detected and blocked. {action_verb}."),
        "credential_stuffing" => format!("Credential spray neutralized. {action_verb}."),
        "packet_flood" => format!("DDoS mitigated at wire speed. {action_verb}."),
        "data_exfil" | "data_exfil_cmd" | "data_exfil_ebpf" => {
            format!("Data theft attempt stopped cold. {action_verb}.")
        }
        "reverse_shell" => format!("Reverse shell terminated before execution. {action_verb}."),
        "ransomware" => format!("Ransomware killed before encryption. {action_verb}."),
        "c2_callback" => format!("C2 communication severed. {action_verb}."),
        "web_shell" => format!("Backdoor removed. {action_verb}."),
        "threat_intel" => format!("Known-bad IP shut out on reputation. {action_verb}."),
        "proto_anomaly" => format!("Disguised traffic exposed. {action_verb}."),
        "data_exfiltration" => format!("Data theft attempt stopped cold. {action_verb}."),
        _ => format!("{action_verb}."),
    }
}

#[cfg(test)]
pub(super) fn incident_priority(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

#[cfg(test)]
pub(super) fn enforce_feed_max_size<T>(items: Vec<T>, max: usize) -> Vec<T> {
    items.into_iter().take(max).collect()
}

/// `GET /api/live-feed/stream` - SSE stream of alerts for public live page.
pub(super) async fn api_live_feed_stream(
    State(state): State<DashboardState>,
) -> Result<
    Sse<impl futures_core::Stream<Item = Result<SseEvent, std::convert::Infallible>>>,
    StatusCode,
> {
    let current = SSE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    if current >= MAX_SSE_CONNECTIONS {
        SSE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let rx = state.event_tx.subscribe();
    let guard = SseGuard;
    let stream = BroadcastStream::new(rx).filter_map(move |msg: Result<SsePayload, _>| {
        let _keep = &guard;
        let payload = msg.ok()?;
        // Only forward alert and heartbeat events to the public feed
        if payload.kind != "alert" && payload.kind != "heartbeat" {
            return None;
        }
        let data = serde_json::to_string(&payload).unwrap_or_default();
        Some(Ok(SseEvent::default().event(&payload.kind).data(data)))
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// `GET /api/live-feed/geoip?ips=1.2.3.4,5.6.7.8` - batch GeoIP lookup (public proxy).
///
/// 2026-05-03 (Wave 6a): cache-first. Each IP is checked against
/// `geo-cache.json` (TTL 7 days). Hits return immediately with no
/// network call. Misses fall through to ip-api.com (rate-limited at
/// 45 req/min on the free tier) and the result is written back to
/// the cache so a subsequent page load is instant.
///
/// The cache is shared with `build_live_feed_response`'s `sources`
/// enrichment — once a frontend request triggers a lookup for an
/// IP, the next /api/live-feed call carries it pre-attached.
pub(super) async fn api_live_feed_geoip(
    State(state): State<DashboardState>,
    Query(query): Query<GeoIpQuery>,
) -> Json<Vec<GeoIpResult>> {
    let ips: Vec<String> = query
        .ips
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .take(30)
        .collect();

    let data_dir = state.data_dir.clone();
    let mut cache = crate::geo_cache::load_cache(&data_dir);
    let now_secs = chrono::Utc::now().timestamp();

    let mut results = Vec::new();
    let mut to_fetch: Vec<String> = Vec::new();

    // Cache pass: collect hits; queue misses.
    for ip in &ips {
        if let Some(entry) = cache.get_fresh(ip, now_secs) {
            results.push(GeoIpResult {
                ip: ip.clone(),
                lat: entry.lat,
                lon: entry.lon,
                country: entry.country.clone(),
            });
        } else {
            to_fetch.push(ip.clone());
        }
    }

    // Network pass: only for cache misses. Bounded by the 30-IP cap
    // above so a single request can spend at most 30 / 45 of the
    // ip-api budget.
    if !to_fetch.is_empty() {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        let mut cache_dirty = false;
        for ip in &to_fetch {
            // ip-api.com free tier returns 403 on HTTPS; HTTPS requires the paid
            // plan. The IPs queried here are public attacker addresses already
            // observed on the server's public interfaces, so plaintext transit
            // adds no material disclosure. See also `crate::geoip`.
            let url = format!(
                "http://ip-api.com/json/{}?fields=status,lat,lon,country",
                ip
            );
            if let Ok(resp) = client.get(&url).send().await {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if data.get("status").and_then(|s| s.as_str()) == Some("success") {
                        let lat = data.get("lat").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let lon = data.get("lon").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let country = data
                            .get("country")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        cache.put(
                            ip.clone(),
                            crate::geo_cache::GeoEntry {
                                country: country.clone(),
                                lat,
                                lon,
                                ts: now_secs,
                            },
                        );
                        cache_dirty = true;
                        results.push(GeoIpResult {
                            ip: ip.clone(),
                            lat,
                            lon,
                            country,
                        });
                    }
                }
            }
        }
        if cache_dirty {
            if let Err(e) = crate::geo_cache::save_cache(&data_dir, &cache) {
                tracing::warn!("failed to persist geo-cache.json: {e:#}");
            }
        }
    }

    Json(results)
}

/// Honeypot session summary for the live feed.
#[derive(Serialize)]
pub(super) struct HoneypotSession {
    ts: String,
    ip: String,
    session_id: String,
    auth_attempts: Vec<serde_json::Value>,
    commands: Vec<String>,
}

/// `GET /api/live-feed/honeypot` - recent honeypot sessions (public).
pub(super) async fn api_live_feed_honeypot(
    State(state): State<DashboardState>,
) -> Json<Vec<HoneypotSession>> {
    let honeypot_dir = state.data_dir.join("honeypot");
    let mut sessions = Vec::new();

    // Resolve symlinks and verify the path stays within data_dir (CWE-22).
    let Ok(canonical_dir) = honeypot_dir.canonicalize() else {
        return Json(sessions);
    };
    let Ok(canonical_data) = state.data_dir.canonicalize() else {
        return Json(sessions);
    };
    if !canonical_dir.starts_with(&canonical_data) {
        return Json(sessions);
    }

    let entries = match std::fs::read_dir(&canonical_dir) {
        Ok(e) => e,
        Err(_) => return Json(sessions),
    };

    let mut files: Vec<std::path::PathBuf> = entries
        .flatten()
        .filter(|e| {
            e.path()
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("listener-session-") && n.ends_with(".jsonl"))
        })
        .map(|e| e.path())
        .collect();
    files.sort_by(|a, b| {
        b.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .cmp(
                &a.metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            )
    });

    for path in files.into_iter().take(10) {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            if line.is_empty() || !line.starts_with('{') {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let commands: Vec<String> = v["shell_commands"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|c| c["command"].as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            sessions.push(HoneypotSession {
                ts: v["ts"].as_str().unwrap_or("").to_string(),
                ip: v["peer_ip"].as_str().unwrap_or("").to_string(),
                session_id: v["session_id"].as_str().unwrap_or("").to_string(),
                auth_attempts: v["auth_attempts"].as_array().cloned().unwrap_or_default(),
                commands,
            });
        }
    }

    Json(sessions)
}

// ─── MITRE ATT&CK summary endpoint ─────────────────────────────────────────

/// A single technique entry inside a tactic summary.
#[derive(Serialize)]
pub(super) struct MitreTechniqueSummary {
    id: String,
    name: String,
    count: usize,
}

/// A tactic summary with aggregated technique counts.
#[derive(Serialize)]
pub(super) struct MitreTacticSummary {
    tactic: String,
    count: usize,
    techniques: Vec<MitreTechniqueSummary>,
}

/// Top-level response for `/api/live-feed/mitre`.
#[derive(Serialize)]
pub(super) struct MitreSummaryResponse {
    tactics: Vec<MitreTacticSummary>,
}

/// `GET /api/live-feed/mitre` - MITRE ATT&CK tactic/technique summary for today (Phase 6A: graph-only).
pub(super) async fn api_live_feed_mitre(
    State(state): State<DashboardState>,
) -> Json<MitreSummaryResponse> {
    use crate::knowledge_graph::types::{Node, NodeType};
    let graph = state.knowledge_graph.read().unwrap();

    // tactic -> (technique_id, technique_name) -> count
    let mut tactic_map: BTreeMap<String, BTreeMap<(String, String), usize>> = BTreeMap::new();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident { detector, .. }) = graph.get_node(id) {
            if let Some(m) = mitre::map_detector(detector) {
                let techniques = tactic_map.entry(m.tactic.to_string()).or_default();
                *techniques
                    .entry((m.technique_id.to_string(), m.technique_name.to_string()))
                    .or_insert(0) += 1;
            }
        }
    }

    let tactics: Vec<MitreTacticSummary> = tactic_map
        .into_iter()
        .map(|(tactic, techniques_map)| {
            let mut techniques: Vec<MitreTechniqueSummary> = techniques_map
                .into_iter()
                .map(|((id, name), count)| MitreTechniqueSummary { id, name, count })
                .collect();
            techniques.sort_by(|a, b| b.count.cmp(&a.count));
            let count = techniques.iter().map(|t| t.count).sum();
            MitreTacticSummary {
                tactic,
                count,
                techniques,
            }
        })
        .collect();

    Json(MitreSummaryResponse { tactics })
}

#[derive(Deserialize)]
pub(super) struct GeoIpQuery {
    #[serde(default)]
    ips: String,
}

#[derive(Serialize)]
pub(super) struct GeoIpResult {
    ip: String,
    lat: f64,
    lon: f64,
    country: String,
}

// ── Safe data file reading (CWE-22 path traversal protection) ──────
//
// All endpoints that read JSON files from data_dir MUST use this helper.
// It canonicalizes both base and target paths and verifies the target
// stays within the data directory, preventing path traversal attacks.

// Public feed: only show real external attacks (with attacker IP).
// Filter out internal detections, system noise, and advisory-only detectors.
//
// 2026-05-15: pre-fix `has_external_ip` was testing only that an IP
// entity existed on the incident — NOT that the IP was actually
// external. Operator reported public-site FPs surfacing 127.0.0.1,
// 10.0.0.0/8 RFC1918 hosts, and Cloudflare-edge IPs with titles like
// "DNS tunneling detected" and "Suspicious activity detected and
// logged." The fix routes each IP entity through the two canonical
// helpers — `incident_auto_rules::is_internal_ip_pub` covers loopback
// + RFC1918, `cloud_safelist::is_self_traffic_ip` covers Cloudflare +
// the operator's own cloud edge ranges. An incident has a real
// external IP only if AT LEAST ONE of its entities passes BOTH
// checks; otherwise it's self-traffic noise that does not belong on
// the public sales-demo live feed.
pub(super) fn is_internal(inc: &innerwarden_core::incident::Incident) -> bool {
    let det = inc.incident_id.split(':').next().unwrap_or("");
    let has_external_ip = inc.entities.iter().any(|e| {
        e.r#type == innerwarden_core::entities::EntityType::Ip
            && !crate::incident_auto_rules::is_internal_ip_pub(&e.value)
            && !crate::cloud_safelist::is_self_traffic_ip(&e.value)
    });
    is_internal_incident_fields(det, &inc.title, has_external_ip)
}

/// Field-level "internal noise" predicate, shared by `is_internal`
/// (which takes a full `Incident`) and the agent_api / dashboard code
/// that walks `knowledge_graph::Node::Incident` directly. Pulled out
/// so the public Live Feed and the operator dashboard agree on what
/// counts as a "real" incident — without it, `Home → Detections` and
/// `Site → Events (24h)` reported wildly different numbers (126 vs
/// 22 was the surfacing report on 2026-04-22).
pub(super) fn is_internal_incident_fields(
    detector: &str,
    title: &str,
    has_external_ip: bool,
) -> bool {
    // Advisory-only detectors (observe, never block).
    if matches!(
        detector,
        "neural_anomaly" | "host_drift" | "network_sniffing" | "discovery_burst"
    ) {
        return true;
    }
    // No external IP = internal noise.
    if !has_external_ip {
        return true;
    }
    let t = title.to_lowercase();
    // Inner Warden processes doing setuid for skills.
    t.contains("(en-agent)")
        || t.contains("(n-shield)")
        || t.contains("(en-sensor)")
        || t.contains("innerwarden")
        // System daemons that legitimately do setuid.
        || t.contains("(timesyncd)")
        || t.contains("(systemd)")
        || t.contains("(networkd)")
        || t.contains("(resolved)")
        || t.contains("(sshd)")
        || t.contains("(cron)")
        || t.contains("(polkitd)")
        || t.contains("(dbus-daem")
        || t.contains("(login)")
        || t.contains("(su)")
        || t.contains("(sudo)")
        || t.contains("(pkexec)")
        || t.contains("(fwupdmgr)")
        || t.contains("(mandb)")
        || t.contains("(find)")
        || t.contains("(install)")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Wave 5c PR-5 (2026-05-03) — JSONL fallback for live_feed ───
    //
    // Operator hit on 2026-05-03: site reported `4 events / 0 blocks
    // (24h)` while prod JSONL had 42 incidents and 647 block decisions
    // for the same window. Root cause was that `build_live_feed_response`
    // only read in-memory KG (hot tier, TTL-capped). JSONL is the cold
    // tier with full daily history; the fix merges both. These anchors
    // pin the dedup contract + the IO-failure fallback so a refactor
    // that drops either layer ships red.

    fn make_incident(id: &str, ts: chrono::DateTime<chrono::Utc>) -> Incident {
        Incident {
            ts,
            host: String::new(),
            incident_id: id.to_string(),
            severity: Severity::High,
            title: format!("test incident {id}"),
            summary: String::new(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        }
    }

    fn make_decision(id: &str, ts: chrono::DateTime<chrono::Utc>) -> DecisionEntry {
        DecisionEntry {
            ts,
            incident_id: id.to_string(),
            host: String::new(),
            ai_provider: String::new(),
            action_type: "block_ip".into(),
            target_ip: Some("1.2.3.4".into()),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: String::new(),
            estimated_threat: String::new(),
            execution_result: "ok".into(),
            prev_hash: None,
            decision_layer: None,
        }
    }

    #[test]
    fn merge_incidents_prefers_kg_and_dedups_by_incident_id() {
        let now = chrono::Utc::now();
        let kg = vec![make_incident("a", now), make_incident("b", now)];
        let jsonl = vec![
            make_incident("b", now), // dup with KG → skipped
            make_incident("c", now), // new → kept
            make_incident("d", now), // new → kept
        ];
        let merged = merge_incidents_prefer_kg(kg, jsonl);
        let ids: Vec<&str> = merged.iter().map(|i| i.incident_id.as_str()).collect();
        // KG entries first, JSONL fills in the rest, no duplicates.
        assert_eq!(ids, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn merge_decisions_prefers_kg_and_dedups_by_incident_id() {
        let now = chrono::Utc::now();
        let kg = vec![make_decision("inc-1", now)];
        let jsonl = vec![
            make_decision("inc-1", now), // dup → skipped
            make_decision("inc-2", now), // new → kept
        ];
        let merged = merge_decisions_prefer_kg(kg, jsonl);
        let ids: Vec<&str> = merged.iter().map(|d| d.incident_id.as_str()).collect();
        assert_eq!(ids, vec!["inc-1", "inc-2"]);
    }

    /// 2026-05-03 (Wave 5c PR-5 anchor): the canonical operator-hit
    /// case. KG has 0 incidents (TTL evicted everything), JSONL on
    /// disk has 3. The merged total must be 3, NOT 0. This is the
    /// site/dashboard count discrepancy at its smallest reproducible
    /// shape. Anti-regression for any refactor that drops the JSONL
    /// read or short-circuits when the KG is empty.
    #[test]
    fn jsonl_fallback_recovers_count_when_kg_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let path = dir.path().join(format!("incidents-{today}.jsonl"));
        let now = chrono::Utc::now();
        let lines: Vec<String> = (0..3)
            .map(|n| {
                serde_json::to_string(&make_incident(&format!("ssh_bruteforce:{n}"), now)).unwrap()
            })
            .collect();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let dates = vec![today.clone(), "1970-01-01".to_string()];
        let loaded = load_jsonl_incidents(dir.path(), &dates);
        assert_eq!(loaded.len(), 3, "JSONL load must surface every line");

        // KG empty + JSONL has 3 → merged has 3.
        let merged = merge_incidents_prefer_kg(Vec::new(), loaded);
        assert_eq!(
            merged.len(),
            3,
            "fallback must surface JSONL entries when KG is empty (operator's 2026-05-03 case)"
        );
    }

    /// 2026-05-03 (Wave 5c PR-5): degraded-IO path. If
    /// `incidents-{date}.jsonl` is missing or unreadable, the helper
    /// returns an empty vec and the merge still works — the public
    /// endpoint never crashes on file-system glitches.
    #[test]
    fn load_jsonl_incidents_returns_empty_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let dates = vec!["1970-01-01".to_string()];
        let loaded = load_jsonl_incidents(dir.path(), &dates);
        assert!(loaded.is_empty());
    }

    /// Same shape for decisions — pinned because the count surfaces
    /// (`total_blocked`) feed off this loader and a missing file
    /// must NOT break the response.
    #[test]
    fn load_jsonl_decisions_returns_empty_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let dates = vec!["1970-01-01".to_string()];
        let loaded = load_jsonl_decisions(dir.path(), &dates);
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_live_feed_title_formatting_rules() {
        assert_eq!(
            live_feed_title("ssh_bruteforce", &Severity::Critical),
            "Brute force in progress. Tracking attempt count and origin."
        );
        assert_eq!(
            live_feed_title("container_escape", &Severity::High),
            "Container escape attempt blocked."
        );
        assert_eq!(
            live_feed_title("unknown_detector", &Severity::Critical),
            "Critical threat detected and handled."
        );
        assert_eq!(
            live_feed_title("unknown_detector", &Severity::Low),
            "Suspicious activity detected and logged."
        );
        // Detectors that previously fell through to the generic line now get a
        // specific, sanitized headline (no paths/rules/thresholds leaked).
        for (det, expected) in [
            (
                "proto_anomaly",
                "Protocol anomaly. Something on this port is lying about what it is.",
            ),
            (
                "threat_intel",
                "Known-bad address recognized on sight. Reputation said no.",
            ),
            (
                "honeypot",
                "Took the honeypot bait. Every keystroke recorded.",
            ),
            (
                "suspicious_login",
                "A login that does not add up. Flagged and watched.",
            ),
            (
                "setns_owner",
                "Root walked into a namespace it never created.",
            ),
        ] {
            assert_eq!(
                live_feed_title(det, &Severity::High),
                expected,
                "detector {det}"
            );
            // None of these leak an internal token a probing visitor could use.
            for banned in ["/etc", "threshold", "rule ", "spec "] {
                assert!(
                    !live_feed_title(det, &Severity::High)
                        .to_lowercase()
                        .contains(banned),
                    "{det} headline leaked {banned}"
                );
            }
        }
    }

    #[test]
    fn test_live_feed_reason_formatting_rules() {
        assert_eq!(
            live_feed_reason("ssh_bruteforce", "block_ip"),
            "Brute force detected and blocked. IP blocked."
        );
        assert_eq!(
            live_feed_reason("ransomware", "kill_process"),
            "Ransomware killed before encryption. Process terminated."
        );
        assert_eq!(
            live_feed_reason("unknown_detector", "monitor"),
            "Monitoring."
        );
        assert_eq!(
            live_feed_reason("threat_intel", "block_ip"),
            "Known-bad IP shut out on reputation. IP blocked."
        );
        assert_eq!(
            live_feed_reason("proto_anomaly", "monitor"),
            "Disguised traffic exposed. Monitoring."
        );
    }

    #[test]
    fn test_live_feed_item_serialization() {
        let mitre = LiveFeedMitre {
            tactic: "T0000".to_string(),
            technique_id: "T1234".to_string(),
            technique_name: "Magic Attack".to_string(),
        };

        let item = LiveFeedItem {
            ts: "2023-01-01T00:00:00Z".to_string(),
            severity: "high".to_string(),
            title: "Threat".to_string(),
            ip: Some("1.2.3.4".to_string()),
            action: Some("monitor".to_string()),
            outcome: Some("monitored".to_string()),
            confidence: Some(0.9),
            reason: Some("Monitoring.".to_string()),
            reputation: None,
            mitre: Some(mitre),
            detector: Some("magic_detector".to_string()),
        };

        let val = serde_json::to_value(&item).unwrap();
        assert_eq!(val["severity"], "high");
        assert_eq!(val["ip"], "1.2.3.4");
        assert_eq!(val["outcome"], "monitored");
        assert!(val.get("reputation").is_none()); // skip serialization if none
        assert_eq!(val["mitre"]["tactic"], "T0000");
    }

    #[test]
    fn test_live_feed_item_serialization_empty() {
        let item = LiveFeedItem {
            ts: "2023-01-01T00:00:00Z".to_string(),
            severity: "low".to_string(),
            title: "Threat".to_string(),
            ip: None,
            action: None,
            outcome: None,
            confidence: None,
            reason: None,
            reputation: None,
            mitre: None,
            detector: None,
        };
        let val = serde_json::to_value(&item).unwrap();
        // Optional fields skipped serialization if none
        assert!(val.get("outcome").is_none());
        assert!(val.get("detector").is_none());
        assert!(val.get("mitre").is_none());
        assert!(val["action"].is_null());
    }

    #[test]
    fn test_is_internal_filter() {
        // Filters internal/system noise while keeping real external attacks.
        use innerwarden_core::entities::EntityRef;
        // Real IP based threat => external
        let ext_inc = Incident {
            ts: Utc::now(),
            host: String::new(),
            incident_id: "ssh_bruteforce:123".into(),
            severity: Severity::High,
            title: "External threat".into(),
            summary: "xyz".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        assert_eq!(is_internal(&ext_inc), false);

        // System daemon title => internal
        let daemon_inc = Incident {
            title: "Setuid execution (sudo)".into(),
            ..ext_inc.clone()
        };
        assert_eq!(is_internal(&daemon_inc), true);

        // Advisory detector => internal
        let adv_inc = Incident {
            incident_id: "neural_anomaly:123".into(),
            ..ext_inc.clone()
        };
        assert_eq!(is_internal(&adv_inc), true);

        // No IP => internal
        let no_ip_inc = Incident {
            entities: vec![EntityRef::user("root")],
            ..ext_inc.clone()
        };
        assert_eq!(is_internal(&no_ip_inc), true);
    }

    #[test]
    fn test_feed_max_size_enforcement_truncates_entries() {
        // Ensures feed result is truncated when it exceeds configured max entries.
        let source: Vec<usize> = (0..250).collect();
        let truncated = enforce_feed_max_size(source, 200);
        assert_eq!(truncated.len(), 200);
        assert_eq!(truncated.first(), Some(&0));
        assert_eq!(truncated.last(), Some(&199));
    }

    #[test]
    fn test_critical_priority_higher_than_low() {
        // Confirms severity priority ordering used by feed ranking.
        assert!(incident_priority("critical") > incident_priority("low"));
    }

    #[test]
    fn test_feed_with_zero_entries_returns_empty_list() {
        // Verifies empty feed serialization remains an empty list.
        let empty: Vec<LiveFeedItem> = Vec::new();
        let response = LiveFeedResponse {
            total_today: 0,
            total_blocked: 0,
            total_high: 0,
            unique_sources: 0,
            sources: Vec::new(),
            items: empty,
        };
        assert!(response.items.is_empty());
    }

    /// 2026-05-03 (Wave 6a anchor): the `sources` array on the
    /// LiveFeedResponse must be populated from the on-disk
    /// `geo-cache.json` so the public site map can render markers
    /// without making N follow-up calls to /api/live-feed/geoip.
    /// Pinned because the operator-visible bug shape is "map shows
    /// 4 dots even though there are 138 attackers" — the
    /// `unique_sources` count would already be right but the map
    /// would be empty until the frontend completed N geo round-trips
    /// (and ip-api throttles at 45 req/min so 138 IPs ≈ 3+ minutes
    /// of cold-start lag). Anti-regression for any refactor that
    /// drops the cache-attached `sources` field or its disk
    /// roundtrip.
    #[test]
    fn live_feed_sources_carry_geo_from_disk_cache() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = crate::geo_cache::GeoCache::new();
        let now = chrono::Utc::now().timestamp();
        cache.put(
            "1.2.3.4".into(),
            crate::geo_cache::GeoEntry {
                country: "RU".into(),
                lat: 55.7,
                lon: 37.6,
                ts: now,
            },
        );
        cache.put(
            "5.6.7.8".into(),
            crate::geo_cache::GeoEntry {
                country: "BR".into(),
                lat: -23.5,
                lon: -46.6,
                ts: now,
            },
        );
        crate::geo_cache::save_cache(dir.path(), &cache).unwrap();
        // Reload + sanity check: the disk shape must be loadable
        // by the same helper `build_live_feed_response` calls.
        let loaded = crate::geo_cache::load_cache(dir.path());
        assert_eq!(loaded.len(), 2);
        let ru = loaded
            .get_fresh("1.2.3.4", now)
            .expect("RU IP must be in cache");
        assert_eq!(ru.country, "RU");
        assert!((ru.lat - 55.7).abs() < 1e-6);
        // Unknown IP returns None — the live_feed populator turns
        // this into `country=""` so the frontend can decide
        // whether to plot at lat=0/lon=0 or skip the marker.
        assert!(loaded.get_fresh("9.9.9.9", now).is_none());
    }

    #[test]
    fn test_geoip_query_deserialization_empty_params() {
        // Fix #152: ensure GeoIpQuery works without 'ips' parameter by defaulting to empty string.
        let query: GeoIpQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(query.ips, "");

        let query: GeoIpQuery =
            serde_json::from_value(serde_json::json!({"ips": "1.2.3.4"})).unwrap();
        assert_eq!(query.ips, "1.2.3.4");
    }

    // ── count_unique_ips_blocked (block-count consistency) ───────────

    fn mk_decision(incident_id: &str, action: &str, ip: Option<&str>) -> DecisionEntry {
        DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_id.to_string(),
            host: String::new(),
            ai_provider: String::new(),
            action_type: action.to_string(),
            target_ip: ip.map(|s| s.to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: String::new(),
            execution_result: "ok".into(),
            estimated_threat: String::new(),
            prev_hash: None,
            decision_layer: None,
        }
    }

    #[test]
    fn count_unique_ips_blocked_dedups_repeated_ip() {
        // Same IP blocked three times across three incidents -> counted once.
        let real: std::collections::HashSet<&str> = ["i1", "i2", "i3"].into_iter().collect();
        let decisions = vec![
            mk_decision("i1", "block_ip", Some("10.0.0.1")),
            mk_decision("i2", "block_ip", Some("10.0.0.1")),
            mk_decision("i3", "block_ip", Some("10.0.0.1")),
        ];
        assert_eq!(count_unique_ips_blocked(&decisions, &real), 1);
    }

    #[test]
    fn count_unique_ips_blocked_counts_distinct_ips() {
        let real: std::collections::HashSet<&str> = ["i1", "i2", "i3"].into_iter().collect();
        let decisions = vec![
            mk_decision("i1", "block_ip", Some("10.0.0.1")),
            mk_decision("i2", "block_ip", Some("10.0.0.2")),
            mk_decision("i3", "block_ip", Some("10.0.0.3")),
        ];
        assert_eq!(count_unique_ips_blocked(&decisions, &real), 3);
    }

    #[test]
    fn count_unique_ips_blocked_skips_non_block_actions() {
        let real: std::collections::HashSet<&str> = ["i1", "i2"].into_iter().collect();
        let decisions = vec![
            mk_decision("i1", "monitor", Some("10.0.0.1")),
            mk_decision("i2", "ignore", Some("10.0.0.2")),
        ];
        assert_eq!(count_unique_ips_blocked(&decisions, &real), 0);
    }

    #[test]
    fn count_unique_ips_blocked_skips_decisions_not_in_real_set() {
        // Research-only / internal incidents get filtered out of the
        // "real" set upstream; their block decisions must not inflate
        // the public counter.
        let real: std::collections::HashSet<&str> = ["i1"].into_iter().collect();
        let decisions = vec![
            mk_decision("i1", "block_ip", Some("10.0.0.1")),
            mk_decision("research", "block_ip", Some("10.0.0.99")),
        ];
        assert_eq!(count_unique_ips_blocked(&decisions, &real), 1);
    }

    #[test]
    fn is_internal_incident_fields_flags_advisory_only_detectors() {
        for det in [
            "neural_anomaly",
            "host_drift",
            "network_sniffing",
            "discovery_burst",
        ] {
            assert!(
                is_internal_incident_fields(det, "anything", true),
                "{det} must be classified as internal/advisory"
            );
        }
    }

    #[test]
    fn is_internal_incident_fields_requires_external_ip() {
        assert!(is_internal_incident_fields(
            "ssh_bruteforce",
            "ssh brute force",
            false
        ));
        assert!(!is_internal_incident_fields(
            "ssh_bruteforce",
            "ssh brute force",
            true
        ));
    }

    #[test]
    fn is_internal_incident_fields_strips_self_traffic_titles() {
        for title in [
            "ssh_bruteforce: bash (en-agent)",
            "exec.privesc (innerwarden)",
            "network connection (sshd)",
            "file modify (cron)",
        ] {
            assert!(
                is_internal_incident_fields("ssh_bruteforce", title, true),
                "{title} should be classified as internal noise"
            );
        }
    }

    #[test]
    fn count_unique_ips_blocked_ignores_missing_and_empty_target_ip() {
        let real: std::collections::HashSet<&str> = ["i1", "i2", "i3"].into_iter().collect();
        let decisions = vec![
            mk_decision("i1", "block_ip", None),
            mk_decision("i2", "block_ip", Some("")),
            mk_decision("i3", "block_ip", Some("10.0.0.1")),
        ];
        assert_eq!(count_unique_ips_blocked(&decisions, &real), 1);
    }

    // ── Wave 10b anchors (AUDIT-WAVE10B-NON-INCIDENT-BLOCKS) ──────────
    //
    // 2026-05-05: site live page showed `0 IPs blocked (24h)` while
    // `decisions-2026-05-05.jsonl` had 450 `block_ip` decisions. Cause:
    // today's blocks all came from non-incident paths whose
    // `incident_id` shape doesn't appear in `incidents-*.jsonl`
    // (`honeypot:always-on:abuseipdb:*`, `repeat-offender:*`,
    // `proto_anomaly:*`, etc.). Pre-Wave-10b
    // `count_unique_ips_blocked` required `real_ids` membership and
    // dropped every one of those 450 decisions.

    #[test]
    fn count_unique_ips_blocked_counts_honeypot_abuseipdb_blocks() {
        // The headline anchor: a quiet day where every block decision
        // is a honeypot AbuseIPDB submit and `real_ids` is empty must
        // STILL produce a non-zero count. Pre-Wave-10b returned 0.
        let real: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let decisions = vec![
            mk_decision(
                "honeypot:always-on:abuseipdb:103.117.203.203",
                "block_ip",
                Some("103.117.203.203"),
            ),
            mk_decision(
                "honeypot:always-on:abuseipdb:118.145.104.105",
                "block_ip",
                Some("118.145.104.105"),
            ),
            mk_decision(
                "honeypot:abuseipdb:128.14.225.253",
                "block_ip",
                Some("128.14.225.253"),
            ),
        ];
        assert_eq!(
            count_unique_ips_blocked(&decisions, &real),
            3,
            "honeypot AbuseIPDB block decisions must count as public-eligible blocks even with no matching incident_id in real_ids"
        );
    }

    #[test]
    fn count_unique_ips_blocked_counts_repeat_offender_and_proto_anomaly() {
        // The other two non-incident-pipeline shapes the operator hit:
        // repeat-offender ladder + direct proto-anomaly decisions.
        let real: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let decisions = vec![
            mk_decision(
                "repeat-offender:119.203.251.187:1777939320",
                "block_ip",
                Some("119.203.251.187"),
            ),
            mk_decision(
                "proto_anomaly:SshVersionAnomaly:92.118.39.235:2026-05-05T00:00Z",
                "block_ip",
                Some("92.118.39.235"),
            ),
            mk_decision(
                "suspicious_archive:unknown:2026-05-05T00:00Z",
                "block_ip",
                Some("203.0.113.7"),
            ),
            mk_decision(
                "logging_config_change:unknown:2026-05-05T00:00Z",
                "block_ip",
                Some("203.0.113.8"),
            ),
        ];
        assert_eq!(
            count_unique_ips_blocked(&decisions, &real),
            4,
            "repeat-offender + proto_anomaly + suspicious_archive + logging_config_change shapes must each count"
        );
    }

    #[test]
    fn count_unique_ips_blocked_still_dedupes_across_incident_and_non_incident_paths() {
        // Anti-regression for double-counting: an attacker that
        // appears via BOTH paths (e.g. blocked via incident pipeline
        // AND via repeat-offender ladder for the same IP) must count
        // exactly once. The dedup is on target_ip, not on
        // incident_id, so this should hold.
        let real: std::collections::HashSet<&str> = ["i1"].into_iter().collect();
        let decisions = vec![
            mk_decision("i1", "block_ip", Some("198.51.100.7")),
            mk_decision(
                "repeat-offender:198.51.100.7:1777940000",
                "block_ip",
                Some("198.51.100.7"),
            ),
        ];
        assert_eq!(
            count_unique_ips_blocked(&decisions, &real),
            1,
            "same IP via incident + repeat-offender must dedupe to 1"
        );
    }

    #[test]
    fn count_unique_ips_blocked_still_rejects_unknown_non_incident_shape() {
        // Defensive bound: a decision with an unrecognised
        // incident_id shape (no real_ids match, no known prefix)
        // must NOT count. This pins the conservative classifier so a
        // future internal/research-only block path can't accidentally
        // inflate the public counter.
        let real: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let decisions = vec![mk_decision(
            "internal:probe:noise:7",
            "block_ip",
            Some("203.0.113.99"),
        )];
        assert_eq!(
            count_unique_ips_blocked(&decisions, &real),
            0,
            "unknown incident_id shape with no real_ids match must be rejected"
        );
    }

    #[test]
    fn is_public_block_decision_recognises_all_known_prefixes() {
        // Every prefix in the allow-list must classify correctly. If
        // a future PR adds a new auto-block path it adds a prefix +
        // a row here in the same change.
        let real: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for id in [
            "honeypot:always-on:abuseipdb:1.2.3.4",
            "honeypot:abuseipdb:1.2.3.4",
            "repeat-offender:1.2.3.4:1234567890",
            "proto_anomaly:SshVersionAnomaly:1.2.3.4:2026-05-05T00:00Z",
            "suspicious_archive:unknown:2026-05-05T00:00Z",
            "logging_config_change:unknown:2026-05-05T00:00Z",
        ] {
            let d = mk_decision(id, "block_ip", Some("1.2.3.4"));
            assert!(
                is_public_block_decision(&d, &real),
                "incident_id {id:?} must classify as public-eligible"
            );
        }
    }

    // ── 2026-05-15: live-feed SQLite-first path ─────────────────────
    //
    // Operator-reported 2026-05-15: public site `live.innerwarden.com`
    // was ~1h behind reality after an agent restart. Root cause: the
    // live-feed read exclusively from in-memory KG + JSONL fallback.
    // Post-restart the KG hydrates from the last graph_snapshot
    // (typically 30-60min old) and new incidents go straight to
    // SQLite (the canonical store from spec 016 onwards). The KG
    // stays stuck on snapshot-time data until the next slow_loop
    // snapshot cycle.
    //
    // Fix: route `build_live_feed_response` through SQLite when a
    // Store is present. Same source the rest of the dashboard
    // (overview, sensors, cases) uses since PR30. Anchored here.

    fn mk_sqlite_incident(
        store: &innerwarden_store::Store,
        id: &str,
        ts: chrono::DateTime<chrono::Utc>,
        ip: &str,
    ) {
        let inc = Incident {
            ts,
            host: "h".into(),
            incident_id: id.into(),
            severity: Severity::High,
            title: "test".into(),
            summary: String::new(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![innerwarden_core::entities::EntityRef {
                r#type: innerwarden_core::entities::EntityType::Ip,
                value: ip.into(),
            }],
        };
        store.insert_incident(&inc).expect("insert incident");
    }

    #[test]
    fn live_feed_reads_from_sqlite_when_store_present() {
        // PR-fix: when a Store is configured, the live-feed reads
        // incidents directly from SQLite instead of the KG. This
        // closes the post-restart staleness gap on the public site.
        let store = innerwarden_store::Store::open_memory().expect("open_memory");
        let now = chrono::Utc::now();

        // Seed 3 fresh incidents in SQLite at staggered times. NONE
        // are in the KG — that's exactly the post-restart scenario.
        mk_sqlite_incident(
            &store,
            "fresh:1",
            now - chrono::Duration::minutes(2),
            "203.0.113.1",
        );
        mk_sqlite_incident(
            &store,
            "fresh:2",
            now - chrono::Duration::minutes(5),
            "203.0.113.2",
        );
        mk_sqlite_incident(
            &store,
            "fresh:3",
            now - chrono::Duration::minutes(10),
            "203.0.113.3",
        );

        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let tmp = tempfile::tempdir().expect("tempdir");
        let resp = build_live_feed_response(&kg, tmp.path(), Some(&store));

        assert_eq!(
            resp.total_today, 3,
            "SQLite-first live-feed must surface ALL 3 incidents — even though the KG is empty"
        );
        assert_eq!(
            resp.items.len(),
            3,
            "items list must include each SQLite incident"
        );
        assert_eq!(
            resp.unique_sources, 3,
            "unique_sources must reflect SQLite-sourced entity IPs"
        );
        // Items are timestamps, all within 24h.
        for item in &resp.items {
            assert!(item.ts.contains("2026") || item.ts.contains("T"));
        }
    }

    #[test]
    fn live_feed_sqlite_path_clips_to_24h_window() {
        // The Wave-10 (24h) label contract must survive the SQLite
        // migration. Seed one incident inside the window and one
        // outside; only the inside one shows up.
        let store = innerwarden_store::Store::open_memory().expect("open_memory");
        let now = chrono::Utc::now();
        mk_sqlite_incident(
            &store,
            "in-window",
            now - chrono::Duration::hours(2),
            "203.0.113.1",
        );
        mk_sqlite_incident(
            &store,
            "outside-window",
            now - chrono::Duration::hours(48),
            "203.0.113.2",
        );

        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let tmp = tempfile::tempdir().expect("tempdir");
        let resp = build_live_feed_response(&kg, tmp.path(), Some(&store));

        assert_eq!(
            resp.total_today, 1,
            "only the in-window incident should count toward total_today (Wave-10 24h contract)"
        );
        assert_eq!(resp.unique_sources, 1);
    }

    #[test]
    fn live_feed_fallback_to_kg_when_no_store() {
        // Dev/test fixtures don't always carry a Store. When None is
        // passed, the function must fall back to the legacy
        // KG-plus-JSONL path so older test scaffolding keeps working.
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let tmp = tempfile::tempdir().expect("tempdir");
        let resp = build_live_feed_response(&kg, tmp.path(), None);
        assert_eq!(
            resp.total_today, 0,
            "empty KG + no JSONL + no Store → empty feed"
        );
        assert!(resp.items.is_empty());
    }

    #[test]
    fn live_feed_sqlite_independent_of_kg_state() {
        // Anti-regression for the prod symptom: KG with stale
        // contents that disagree with SQLite. If a future change
        // re-introduces a merge that lets stale KG entries leak in,
        // this test catches it.
        let store = innerwarden_store::Store::open_memory().expect("open_memory");
        let now = chrono::Utc::now();
        mk_sqlite_incident(
            &store,
            "fresh:from-sqlite",
            now - chrono::Duration::minutes(1),
            "203.0.113.1",
        );

        // KG starts empty — same as post-restart prod.
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let tmp = tempfile::tempdir().expect("tempdir");
        let resp = build_live_feed_response(&kg, tmp.path(), Some(&store));
        assert_eq!(
            resp.total_today, 1,
            "SQLite source must NOT depend on KG state — KG empty here, SQLite has 1, response = 1"
        );
        // Identify by title prefix the helper writes.
        assert!(
            resp.items.iter().any(|it| it.title.contains("threat")
                || it.title.contains("attack")
                || it.title.contains("Suspicious")
                || it.title.contains("severity")),
            "item must contain the rendered title for an unknown detector"
        );
    }
}
