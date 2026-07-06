// Auto-extracted from mod.rs — dashboard sensors handlers

use super::*;

/// GET /api/sensors - sensor activity time-series for dashboard graphs.
/// Returns event counts bucketed by 5-minute intervals, grouped by source.
/// Cached for 30 seconds to avoid re-reading the events file on every request.
///
/// Cache miss path holds the KG read lock and walks every Incident node to
/// build the detector timeline. `tokio::task::spawn_blocking` keeps that
/// work off the async worker thread (see `RECURRING_BUGS.md` "Dashboard
/// handlers block tokio worker threads"). The 30s cache makes contention
/// rare but the spawn_blocking is correctness, not optimisation: a slow
/// path that pins an async worker can starve sibling handlers regardless
/// of frequency.
pub(super) async fn api_sensors(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    // Check cache (30s TTL)
    {
        let cache = state.sensor_cache.lock().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now - cache.0 < 30 && cache.0 > 0 {
            return Json(cache.1.clone());
        }
    }

    // 2026-05-02 audit B1/P1 (Spec 039 P3): hydrate the canonical
    // OverviewSnapshot for today so the Sensors HUD's `total_events`
    // and `total_incidents` paint the same numbers the Home tile and
    // Briefing/Report paint. Pre-fix the HUD scanned the KG and
    // showed "47 events handled" while the Home tile said something
    // different — a contradiction the auditor flagged on the same
    // screen reload.
    //
    // PR30: route through `canonical_counts::compute` so the
    // per-date events_today number agrees with /api/overview. The
    // canonical snapshot is what the cross-endpoint anchor
    // `every_dashboard_endpoint_reads_canonical_counts` greps for.
    let (snapshot, events_today_canonical) = state
        .sqlite_store
        .as_ref()
        .map(|store| {
            let today = super::helpers::resolve_date(None);
            let now_dt = chrono::Utc::now();
            let degraded = super::data_api::read_degraded_signals(&state);
            let snap = super::data_api::compute_overview_counts_from_sqlite(
                store,
                &today,
                0,
                None,
                // Spec 049 PR4: Sensors HUD does NOT carry a scope picker
                // — it always renders today's full-day window.
                None,
                now_dt,
                &degraded,
                &state.data_dir,
            )
            .and_then(|counts| counts.snapshot);
            let canonical = super::canonical_counts::compute(
                store,
                &state.knowledge_graph,
                &today,
                &super::canonical_counts::CountFilters::default(),
                now_dt,
            );
            (snap, Some(canonical.events_today))
        })
        .unwrap_or((None, None));

    // Spec 050-hotfix (issue #656): canonical per-minute event timeline
    // from SQLite, same source-of-truth path as the tile totals (PR30).
    // Pre-fix the chart consumed `graph.event_timeline` (in-memory KG
    // counter) which silently diverged from the 23 M tile total —
    // operator saw two narrow spikes when the baseline should have been
    // a continuous ~18 k/min band. Failing the read gracefully so the
    // legacy KG fallback still runs when SQLite is unavailable.
    let event_timeline_canonical = state.sqlite_store.as_ref().and_then(|store| {
        let today = super::helpers::resolve_date(None);
        match store.events_timeline_for_date(&today) {
            Ok(map) => Some(map),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "events_timeline_for_date failed — falling back to KG timeline"
                );
                None
            }
        }
    });

    let kg = std::sync::Arc::clone(&state.knowledge_graph);
    let data_dir = state.data_dir.clone();
    let result = tokio::task::spawn_blocking(move || {
        build_sensors_payload(
            &kg,
            &data_dir,
            snapshot.as_ref(),
            events_today_canonical,
            event_timeline_canonical,
        )
    })
    .await
    .unwrap_or_else(|_| serde_json::json!({}));

    // Update cache
    {
        let mut cache = state.sensor_cache.lock().await;
        cache.0 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        cache.1 = result.clone();
    }

    Json(result)
}

/// Async-safe variant retained for any future caller that already runs on
/// a blocking thread (e.g. integration test). Production handler uses
/// `build_sensors_payload` via `spawn_blocking`.
#[allow(dead_code)]
pub(super) async fn api_sensors_inner(state: &DashboardState) -> serde_json::Value {
    build_sensors_payload(&state.knowledge_graph, &state.data_dir, None, None, None)
}

/// Test-only re-export of `build_sensors_payload` for the cross-surface
/// SoT anchor in `consistency_incidents_today.rs`. Production code
/// reaches this through `api_sensors` / `api_sensors_inner`; routing
/// the test through the public function avoids a `pub(super)` visibility
/// bump on the implementation that would leak into release builds.
#[cfg(test)]
pub(super) fn tests_only_call_build_sensors_payload(
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    data_dir: &std::path::Path,
    snapshot: Option<&super::types::OverviewSnapshot>,
    events_today_canonical: Option<u64>,
    event_timeline_canonical: Option<
        std::collections::BTreeMap<String, std::collections::HashMap<String, u64>>,
    >,
) -> serde_json::Value {
    build_sensors_payload(
        kg,
        data_dir,
        snapshot,
        events_today_canonical,
        event_timeline_canonical,
    )
}

/// Known collector names this agent will render in the sensors HUD.
///
/// Wave 2026-05-18: copy of the sensor crate's `COLLECTOR_MANIFEST`
/// names. The agent does NOT depend on the sensor crate (they're
/// separate processes by design), but we need a roster to filter the
/// KG `source_counts` against — otherwise legacy KG snapshots carry
/// retired names like `osquery_log` forever and the dashboard
/// renders them as phantom rows that look like broken telemetry.
///
/// A cross-file consistency anchor in `crates/agent/src/dashboard/mod.rs`
/// (`every_sensor_manifest_name_appears_in_known_collectors_list`)
/// asserts this list matches the sensor manifest byte-for-byte. Add
/// or rename a collector → both sides update or CI fails.
pub(super) const KNOWN_COLLECTORS: &[&str] = &[
    "auth_log",
    "auditd",
    "cgroup",
    "cloudtrail",
    "dns_capture",
    "ebpf",
    "etw",
    "file_extract",
    "http_capture",
    "journald",
    "kernel_integrity",
    "macos_log",
    "net_snapshot",
    "nginx_access",
    "nginx_error",
    "proc_maps",
    "proto_http",
    "proto_smb",
    "proto_ssh",
    "syslog_firewall",
    "tcp_stream",
    "docker",
    "fanotify",
    "firmware_integrity",
    "integrity",
    "sysctl_drift",
    "tls_fingerprint",
    "usb_monitor",
    "suid_inventory",
    "systemd_inventory",
];

/// True iff `name` is in `KNOWN_COLLECTORS`. Pure so the filtering
/// rule stays unit-testable without spinning up a dashboard.
pub(super) fn filter_known_collector(name: &str) -> bool {
    KNOWN_COLLECTORS.contains(&name)
}

fn build_sensors_payload(
    kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    data_dir: &std::path::Path,
    snapshot: Option<&super::types::OverviewSnapshot>,
    events_today_canonical: Option<u64>,
    event_timeline_canonical: Option<
        std::collections::BTreeMap<String, std::collections::HashMap<String, u64>>,
    >,
) -> serde_json::Value {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    use crate::knowledge_graph::types::{Node, NodeType};
    let graph = kg.read().unwrap();

    // Event telemetry.
    //
    // PR30: `total_events_val` comes from `canonical_counts::compute`
    // (SQLite per-date) when the SQLite store is reachable — the same
    // number /api/overview paints, so the operator no longer sees Home
    // and Sensors HUD disagree. Pre-PR30 this read `graph.total_events_ingested`
    // (process-lifetime counter that resets on restart and aggregates
    // every uptime day) which is what caused the 130k vs 3.7k drift
    // reported on 2026-05-13.
    //
    // The per-source breakdown still comes from `graph.source_counts` /
    // telemetry — the SQLite events table doesn't carry the source
    // attribution we need for the HUD chart. That's only an aesthetic
    // issue (the chart's segment ratios are correct), the total is
    // what the operator reads against the Home tile.
    let total_events_val = match events_today_canonical {
        Some(n) => n as usize,
        None if graph.total_events_ingested > 0 => graph.total_events_ingested,
        None => {
            let telem = crate::telemetry::read_latest_snapshot(data_dir, &today);
            telem
                .as_ref()
                .map(|t| t.events_by_collector.values().sum::<u64>() as usize)
                .unwrap_or(0)
        }
    };
    // Spec 050-hotfix follow-up to #660: per-collector "TELEMETRY STREAMS"
    // tiles need TWO pieces of information composed correctly:
    //
    //   (a) **The list of collectors that exist** — comes from the KG's
    //       lifetime-accumulated `source_counts` (which has every
    //       collector that ever wrote an event, including ones quiet
    //       today). The dashboard frontend uses this list to render
    //       active-vs-broken indicators per collector.
    //
    //   (b) **The per-date event counts** — comes from canonical SQLite
    //       via `event_timeline_canonical` so the numbers represent
    //       today, not lifetime.
    //
    // Operator screenshot on 2026-05-17 after #660 deployed: only 2 of
    // 18 collectors visible — `ebpf` etc. silently vanished because
    // they had no events in SQLite yet today (UTC just rolled over).
    // Pre-#660 the lifetime KG counter kept them visible with inflated
    // numbers; #660 went the other way and dropped them entirely. The
    // correct shape unions both sources: KG gives the **roster**,
    // canonical gives the **counts**.
    //
    // Precedence:
    //   1. Canonical present → union(KG-names, canonical-counts) with
    //      `0` for collectors not in canonical today.
    //   2. Canonical absent + KG non-empty → legacy lifetime KG path.
    //   3. Canonical absent + KG empty → telemetry snapshot file fallback.
    let sources: Vec<(String, usize)> = if let Some(canonical) = event_timeline_canonical.as_ref() {
        let mut acc: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        // (b) per-date counts from canonical SQLite.
        for inner in canonical.values() {
            for (src, &cnt) in inner.iter() {
                *acc.entry(src.clone()).or_insert(0) += cnt as usize;
            }
        }
        // (a) ensure the KG roster is represented, even if a collector
        // is quiet today. `or_insert(0)` is the key — it doesn't
        // overwrite a real canonical count, only fills the gap so the
        // tile renders the collector with count=0 (frontend's
        // active-vs-broken indicator depends on the row existing).
        for src_arc in graph.source_counts.keys() {
            acc.entry(src_arc.to_string()).or_insert(0);
        }
        let mut s: Vec<(String, usize)> = acc.into_iter().collect();
        s.sort_by(|a, b| b.1.cmp(&a.1));
        s
    } else if graph.total_events_ingested > 0 {
        let mut s: Vec<(String, usize)> = graph
            .source_counts
            .iter()
            .map(|(s, &c)| (s.to_string(), c))
            .collect();
        s.sort_by(|a, b| b.1.cmp(&a.1));
        s
    } else {
        let telem = crate::telemetry::read_latest_snapshot(data_dir, &today);
        match telem {
            Some(t) => {
                let mut s: Vec<(String, usize)> = t
                    .events_by_collector
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v as usize))
                    .collect();
                s.sort_by(|a, b| b.1.cmp(&a.1));
                s
            }
            None => vec![],
        }
    };

    // Wave 2026-05-18 fix: drop entries whose `source` name is not
    // in the current sensor manifest. Legacy KG snapshots may carry
    // names like `osquery_log` from retired collectors — without
    // this filter the dashboard renders a phantom "TELEMETRY 0" row
    // for every retired name and the operator can't tell phantoms
    // from real broken collectors. The manifest is the source of
    // truth for "what collectors this binary actually ships".
    let sources: Vec<(String, usize)> = sources
        .into_iter()
        .filter(|(name, _)| filter_known_collector(name))
        .collect();

    let mut kinds: Vec<_> = graph
        .kind_counts
        .iter()
        .map(|(k, &c)| (k.clone(), c))
        .collect();
    kinds.sort_by(|a, b| b.1.cmp(&a.1));
    kinds.truncate(15);

    // Detector counts + timeline from Incident nodes. Bucket key now matches
    // the format used by `event_timeline` (`YYYY-MM-DDTHH:MM`, see
    // `knowledge_graph::buckets`) so cross-day uptime no longer collapses
    // different days into the same time-of-day bucket.
    // Wave 6c: match `KnowledgeGraph::event_timeline` key type
    // (`Arc<str>`) so the `event_tl_source` reference can fall back
    // to either source without a type-mismatch.
    let mut detector_counts: std::collections::HashMap<std::sync::Arc<str>, usize> =
        std::collections::HashMap::new();
    let mut detector_timeline: std::collections::BTreeMap<
        std::sync::Arc<str>,
        std::collections::HashMap<std::sync::Arc<str>, usize>,
    > = std::collections::BTreeMap::new();
    let total_incidents = graph.nodes_of_type(NodeType::Incident).len();

    for id in graph.nodes_of_type(NodeType::Incident) {
        if let Some(Node::Incident { detector, ts, .. }) = graph.get_node(id) {
            let detector_arc = crate::knowledge_graph::intern::intern(detector);
            *detector_counts.entry(detector_arc.clone()).or_insert(0) += 1;
            let bucket = crate::knowledge_graph::buckets::format_bucket_key(*ts);
            let bucket_arc = crate::knowledge_graph::intern::intern(&bucket);
            *detector_timeline
                .entry(bucket_arc)
                .or_default()
                .entry(detector_arc)
                .or_insert(0) += 1;
        }
    }

    let mut detectors: Vec<_> = detector_counts.into_iter().collect();
    detectors.sort_by(|a, b| b.1.cmp(&a.1));

    // Spec 050-hotfix (issue #656): when SQLite-backed canonical
    // timeline is available, use it instead of `graph.event_timeline`.
    // The KG counter silently diverged from the SQLite source-of-truth
    // (PR30 fixed this for tile totals; the chart was a separate
    // consumer not migrated). Interned-key shape is built on-the-fly
    // from the canonical map to keep the rendering pipeline unchanged.
    //
    // `EventTimelineSource` shorthand keeps clippy::type_complexity
    // quiet on the let-binding and on the source-precedence reference
    // below — both shapes have to match the KG's `event_timeline` type
    // exactly so the existing rendering closure can borrow either.
    type EventTimelineSource = std::collections::BTreeMap<
        std::sync::Arc<str>,
        std::collections::HashMap<std::sync::Arc<str>, usize>,
    >;
    let event_timeline_interned: Option<EventTimelineSource> =
        event_timeline_canonical.as_ref().map(|canonical| {
            canonical
                .iter()
                .map(|(bucket, sources)| {
                    let bucket_arc = crate::knowledge_graph::intern::intern(bucket);
                    let inner: std::collections::HashMap<std::sync::Arc<str>, usize> = sources
                        .iter()
                        .map(|(src, &cnt)| {
                            (crate::knowledge_graph::intern::intern(src), cnt as usize)
                        })
                        .collect();
                    (bucket_arc, inner)
                })
                .collect()
        });

    // Source precedence: canonical (SQLite) → KG counter → detector_timeline.
    // The detector_timeline fallback covers the cold-start case where the
    // agent restarted and the KG event_timeline hasn't been rebuilt yet AND
    // the SQLite store is unavailable. We keep it so existing tests that
    // pass no SQLite still produce a non-empty chart.
    let event_tl_source: &EventTimelineSource = if let Some(ref canonical) = event_timeline_interned
    {
        canonical
    } else if graph.event_timeline.is_empty() {
        &detector_timeline
    } else {
        &graph.event_timeline
    };

    // 2026-05-02: filter buckets to TODAY's date prefix before
    // stripping. Pre-fix the chart folded multi-day data into the same
    // HH:MM display key (operator: "o grafico fica fixo aparecendo
    // alto so depois das 20 horas, ta assim a dias"). Cause: bucket
    // keys are `YYYY-MM-DDTHH:MM`; `strip_date_prefix` drops the
    // date and `BTreeMap::collect` overwrites duplicates with the
    // last-iterated entry. With multi-day buckets in the KG, today's
    // empty pre-spike hours got overwritten by yesterday's same-time
    // values, producing a static-looking chart that "moved" only
    // when today's events landed past the agent's restart minute.
    //
    // Fix: keep only buckets whose date prefix matches today. The
    // KG retains multi-day data for windowed queries elsewhere
    // (report.rs::compute_recent_window); the Sensors HUD chart
    // explicitly shows TODAY ONLY.
    let today_prefix = format!("{today}T");
    // Wave 6c: source maps now key on `Arc<str>`. Display structs keep
    // `String` keys because they're built per-request and rendered to
    // JSON immediately — no long-lived state to share, no benefit from
    // interning here. Inner HashMap value type also references the
    // updated `Arc<str>` map shape.
    let event_tl_display: std::collections::BTreeMap<
        String,
        &std::collections::HashMap<std::sync::Arc<str>, usize>,
    > = event_tl_source
        .iter()
        .filter(|(k, _)| k.starts_with(&today_prefix))
        .map(|(k, v)| {
            (
                crate::knowledge_graph::buckets::strip_date_prefix(k).to_string(),
                v,
            )
        })
        .collect();
    // Same today-only filter for the detector timeline — same reason.
    let detector_tl_display: std::collections::BTreeMap<
        String,
        &std::collections::HashMap<std::sync::Arc<str>, usize>,
    > = detector_timeline
        .iter()
        .filter(|(k, _)| k.starts_with(&today_prefix))
        .map(|(k, v)| {
            (
                crate::knowledge_graph::buckets::strip_date_prefix(k).to_string(),
                v,
            )
        })
        .collect();

    // 2026-05-02 audit B1/P1 (Spec 039 P3): canonical SoT override.
    // When the OverviewSnapshot is available, the HUD's topline
    // counters use snapshot fields (same as Home/Briefing/Report)
    // instead of KG-derived numbers. Per-source breakdown
    // (`sources`, `top_kinds`, `detectors`, `event_timeline`,
    // `detector_timeline`) keeps coming from the KG/telemetry walks
    // — those carry detail the snapshot does not.
    let (total_events_canonical, total_incidents_canonical) = match snapshot {
        Some(snap) => {
            let buckets = &snap.buckets;
            let total_inc = buckets.blocked.incidents
                + buckets.observing.incidents
                + buckets.honeypot.incidents
                + buckets.dismissed.incidents
                + buckets.allowlisted.incidents
                + buckets.attention.incidents;
            (snap.events_today, total_inc)
        }
        None => (total_events_val, total_incidents),
    };

    // PR29 — read sensor's boot-time collector health snapshot from
    // the side-channel JSON file the sensor writes at boot. Per-host
    // probes: tells the operator which configured collectors actually
    // have their data source reachable. Missing file = sensor doesn't
    // know about this collector OR isn't running the new code yet;
    // dashboard falls back to the legacy view (counter-only).
    let collector_health = read_collector_health_file(data_dir);

    serde_json::json!({
        "date": today,
        "total_events": total_events_canonical,
        "total_incidents": total_incidents_canonical,
        "sources": sources.iter().map(|(s, c)| serde_json::json!({"name": s, "count": c})).collect::<Vec<_>>(),
        "top_kinds": kinds.iter().map(|(k, c)| serde_json::json!({"name": k, "count": c})).collect::<Vec<_>>(),
        "detectors": detectors.iter().map(|(d, c)| serde_json::json!({"name": d, "count": c})).collect::<Vec<_>>(),
        "event_timeline": event_tl_display,
        "detector_timeline": detector_tl_display,
        "collector_health": collector_health,
    })
}

/// PR29 — load the boot-time collector health JSON the sensor writes
/// to `<data_dir>/collector-health.json`. Returns `null` on any error
/// (file missing, malformed JSON) so the dashboard falls back to its
/// legacy view rather than crashing the response.
fn read_collector_health_file(data_dir: &std::path::Path) -> serde_json::Value {
    let path = data_dir.join("collector-health.json");
    let content = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return serde_json::Value::Null,
    };
    serde_json::from_str::<serde_json::Value>(&content).unwrap_or(serde_json::Value::Null)
}

/// GET /api/status - E6: system status including data files and responder config.
pub(super) async fn api_status(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let data_dir = &state.data_dir;

    let file_exists = |name: &str| data_dir.join(name).exists();
    let file_size = |name: &str| {
        std::fs::metadata(data_dir.join(name))
            .map(|m| m.len())
            .unwrap_or(0)
    };

    // Spec 049 PR20 — events-*.jsonl and incidents-*.jsonl were removed
    // by spec-016 (commit 8bd59990 on 2026-04-12); the sensor writes
    // those streams to SQLite only. Keeping the file-existence check
    // in the API surfaced misleading "events: not found / size_bytes: 0"
    // on the Sensors HUD that looked like a regression. Decisions and
    // telemetry are the only JSONL files the agent still writes.
    let decisions_file = format!("decisions-{today}.jsonl");
    let telemetry_file = format!("telemetry-{today}.jsonl");

    let action_cfg = &state.action_cfg;

    // Compute seconds since last telemetry write (agent liveness check).
    let last_telemetry_secs = std::fs::metadata(data_dir.join(&telemetry_file))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|mtime| mtime.elapsed().ok().map(|d| d.as_secs()));

    let mode = get_protection_mode(action_cfg.enabled, action_cfg.dry_run);

    // Count kill chain incidents from knowledge graph (Phase 6A: no JSONL reads).
    // Single pass — avoids u64 underflow from two-pass subtract.
    let mut kc_total_blocked: u64 = 0;
    let mut kc_total_pre_chain: u64 = 0;
    let mut kc_patterns: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    {
        use crate::knowledge_graph::types::{Node, NodeType};
        let graph = state.knowledge_graph.read().unwrap();
        for id in graph.nodes_of_type(NodeType::Incident) {
            if let Some(Node::Incident {
                detector, decision, ..
            }) = graph.get_node(id)
            {
                if !detector.contains("kill_chain") {
                    continue;
                }
                *kc_patterns.entry(detector.clone()).or_insert(0) += 1;
                if decision.as_deref() == Some("block_ip") {
                    kc_total_blocked += 1;
                } else {
                    kc_total_pre_chain += 1;
                }
            }
        }
    }

    // Graph stats for Health tab (replaces removed Graph tab).
    let graph_stats = {
        let graph = state.knowledge_graph.read().unwrap();
        let mut by_type: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for (_, n) in graph.nodes().iter() {
            *by_type.entry(format!("{:?}", n.node_type())).or_insert(0) += 1;
        }
        serde_json::json!({
            "node_count": graph.node_count(),
            "edge_count": graph.edges_slice().len(),
            "memory_bytes": graph.memory_estimate,
            "incident_nodes": by_type.get("Incident").copied().unwrap_or(0),
            "threat_intel_nodes": graph.threat_intel_nodes.len(),
            "nodes_by_type": by_type
        })
    };

    Json(serde_json::json!({
        "date": today,
        "data_dir": data_dir.display().to_string(),
        "mode": mode,
        "last_telemetry_secs": last_telemetry_secs,
        "ai_enabled": action_cfg.ai_enabled,
        "ai_provider": action_cfg.ai_provider,
        "ai_model": action_cfg.ai_model,
        "files": {
            "decisions": { "exists": file_exists(&decisions_file), "size_bytes": file_size(&decisions_file) },
            "telemetry": { "exists": file_exists(&telemetry_file), "size_bytes": file_size(&telemetry_file) }
        },
        "responder": {
            "enabled": action_cfg.enabled,
            "dry_run": action_cfg.dry_run,
            "block_backend": action_cfg.block_backend,
            "allowed_skills": action_cfg.allowed_skills
        },
        "webhook_format": action_cfg.webhook_format,
        "sudo_protection": action_cfg.sudo_protection_enabled,
        "execution_guard": action_cfg.execution_guard_enabled,
        "integrations": {
            "geoip": action_cfg.geoip_enabled,
            "abuseipdb": action_cfg.abuseipdb_enabled,
            "abuseipdb_auto_block_threshold": action_cfg.abuseipdb_auto_block_threshold,
            "honeypot_mode": action_cfg.honeypot_mode,
            "telegram": action_cfg.telegram_enabled,
            "slack": action_cfg.slack_enabled,
            "discord": action_cfg.discord_enabled,
            "cloudflare": action_cfg.cloudflare_enabled,
            "crowdsec": action_cfg.crowdsec_enabled,
            "mesh": action_cfg.mesh_enabled,
            "web_push": action_cfg.web_push_enabled,
            "shield": action_cfg.shield_enabled,
            "dna": action_cfg.dna_enabled
        },
        "retention": {
            "events_days": action_cfg.retention_events_days,
            "incidents_days": action_cfg.retention_incidents_days,
            "decisions_days": action_cfg.retention_decisions_days,
            "telemetry_days": action_cfg.retention_telemetry_days,
            "reports_days": action_cfg.retention_reports_days
        },
        "kill_chain": {
            "total_blocked": kc_total_blocked,
            "total_pre_chain": kc_total_pre_chain,
            "patterns": kc_patterns
        },
        "graph": graph_stats,
        "process_health": crate::process_health::ProcessHealth::snapshot(),
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// GET /api/collectors - sensor collector detection (file existence + recency).
/// Fail-silent: never requires root, never panics.
pub(super) async fn api_collectors(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    // Helper: check if a path exists
    let file_exists = |p: &str| std::path::Path::new(p).exists();

    // Helper: how many seconds since a file was modified (None if missing or error)
    let file_age_secs = |p: &str| -> Option<u64> {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs())
    };

    // Helper: check if a binary is in PATH
    let has_binary = |name: &str| {
        std::process::Command::new("which")
            .arg(name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };

    // Count events by source — prefer graph counters, fall back to telemetry snapshot
    let graph = state.knowledge_graph.read().unwrap();
    let graph_source_counts = graph.source_counts.clone();
    let graph_total = graph.total_events_ingested;
    drop(graph);

    let telem_source_counts: std::collections::HashMap<String, usize> = if graph_total > 0 {
        // Wave 6c: graph.source_counts keys are now `Arc<str>`; convert
        // at the boundary so the local `HashMap<String, usize>` adapter
        // (used downstream by `count_source` lookups) keeps the same
        // signature.
        graph_source_counts
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
    } else {
        // Graph counters empty (cursor/snapshot race after restart).
        // Fall back to telemetry snapshot which the agent writes every 30s.
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        crate::telemetry::read_latest_snapshot(&state.data_dir, &today)
            .map(|t| {
                // Wave 6b: snapshot keys are now `Arc<str>`; the local
                // adapter HashMap below uses `String` keys so the
                // `.get(source)` lookup against the &str signature
                // works without an Arc-to-str adapter on every call.
                t.events_by_collector
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v as usize))
                    .collect::<HashMap<String, usize>>()
            })
            .unwrap_or_default()
    };
    let count_source =
        move |source: &str| -> u64 { telem_source_counts.get(source).copied().unwrap_or(0) as u64 };

    // Recency threshold: active if file modified within last 2 hours
    let recent = |age: Option<u64>| age.map(|s| s < 7200).unwrap_or(false);

    let auth_log = "/var/log/auth.log";
    let audit_log = "/var/log/audit/audit.log";
    let nginx_acc = "/var/log/nginx/access.log";
    let nginx_err = "/var/log/nginx/error.log";
    let docker_sock = "/var/run/docker.sock";
    let syslog_fw = "/var/log/syslog";
    let kern_log = "/var/log/kern.log";
    let cloudtrail = "/var/log/cloudtrail/events.json";
    let collectors = serde_json::json!([
        {
            "id": "auth_log",
            "name": "SSH / Auth Log",
            "kind": "native",
            "log_path": auth_log,
            "detected": file_exists(auth_log),
            "active": recent(file_age_secs(auth_log)),
            "events_today": count_source("auth_log"),
            "desc": "Parses /var/log/auth.log for SSH failures, logins, sudo"
        },
        {
            "id": "journald",
            "name": "systemd Journal",
            "kind": "native",
            "log_path": "journald",
            "detected": has_binary("journalctl"),
            "active": has_binary("journalctl"),
            "events_today": count_source("journald"),
            "desc": "Tails journald (sshd, sudo, kernel) via journalctl --follow"
        },
        {
            "id": "docker",
            "name": "Docker Events",
            "kind": "native",
            "log_path": docker_sock,
            "detected": file_exists(docker_sock),
            "active": file_exists(docker_sock),
            "events_today": count_source("docker"),
            "desc": "Docker lifecycle events + privilege escalation detection"
        },
        {
            "id": "nginx_access",
            "name": "nginx Access Log",
            "kind": "native",
            "log_path": nginx_acc,
            "detected": file_exists(nginx_acc),
            "active": recent(file_age_secs(nginx_acc)),
            "events_today": count_source("nginx_access"),
            "desc": "nginx access log - search abuse, UA scanner detection"
        },
        {
            "id": "nginx_error",
            "name": "nginx Error Log",
            "kind": "native",
            "log_path": nginx_err,
            "detected": file_exists(nginx_err),
            "active": recent(file_age_secs(nginx_err)),
            "events_today": count_source("nginx_error"),
            "desc": "nginx error log - web scanner and probe detection"
        },
        {
            "id": "exec_audit",
            "name": "Shell Audit (auditd)",
            "kind": "native",
            "log_path": audit_log,
            "detected": file_exists(audit_log),
            "active": recent(file_age_secs(audit_log)),
            // Wave 2026-05-18: count_source must match what the collector
            // actually writes to Event.source — `exec_audit.rs` emits
            // `source: "auditd"`. Pre-fix this card always showed
            // `events_today: 0` even when auditd was busy, because the
            // count was looking up a wire name that never existed.
            "events_today": count_source("auditd"),
            "desc": "auditd EXECVE events - execution guard and shell command trail"
        },
        {
            "id": "ebpf",
            "name": "eBPF Kernel",
            "kind": "native",
            "log_path": "/usr/local/lib/innerwarden/innerwarden-ebpf",
            "detected": file_exists("/usr/local/lib/innerwarden/innerwarden-ebpf"),
            "active": true,
            "events_today": count_source("ebpf"),
            "desc": "22 kernel hooks: 19 tracepoints + kprobe (privesc) + LSM (exec block) + XDP (wire-speed IP block)"
        },
        {
            "id": "syslog_firewall",
            "name": "Syslog Firewall",
            "kind": "native",
            "log_path": syslog_fw,
            "detected": file_exists(syslog_fw) || file_exists(kern_log),
            "active": recent(file_age_secs(syslog_fw)) || recent(file_age_secs(kern_log)),
            "events_today": count_source("syslog_firewall"),
            "desc": "iptables/nftables DROP logs from /var/log/syslog or kern.log"
        },
        {
            "id": "firmware_integrity",
            "name": "Firmware Integrity",
            "kind": "native",
            "log_path": "/boot/efi",
            "detected": file_exists("/boot/efi") || file_exists("/sys/firmware/efi"),
            "active": true,
            "events_today": count_source("firmware_integrity"),
            "desc": "UEFI/EFI boot partition monitoring - detects unauthorized binaries"
        },
        {
            "id": "cloudtrail",
            "name": "AWS CloudTrail",
            "kind": "external",
            "log_path": cloudtrail,
            "detected": file_exists(cloudtrail),
            "active": recent(file_age_secs(cloudtrail)),
            "events_today": count_source("cloudtrail"),
            "desc": "AWS CloudTrail JSON logs - IAM changes, S3 access, API calls"
        },
        {
            "id": "macos_log",
            "name": "macOS Unified Log",
            "kind": "native",
            "log_path": "log stream",
            "detected": has_binary("log"),
            "active": has_binary("log"),
            "events_today": count_source("macos_log"),
            "desc": "macOS unified log stream - auth events, process exec, network",
            // 2026-05-15: mark Linux-irrelevant. Dashboard hides
            // rows where `not_applicable=true` so the Health tab
            // does not lie about "NOT FOUND" for a tool that
            // physically cannot exist on this OS.
            "not_applicable": !cfg!(target_os = "macos")
        },
    ]);

    Json(serde_json::json!({ "collectors": collectors }))
}

pub(super) fn get_protection_mode(enabled: bool, dry_run: bool) -> &'static str {
    if enabled {
        if dry_run {
            "watch"
        } else {
            "guard"
        }
    } else {
        "read_only"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_protection_mode() {
        assert_eq!(get_protection_mode(false, false), "read_only");
        assert_eq!(get_protection_mode(false, true), "read_only");
        assert_eq!(get_protection_mode(true, true), "watch");
        assert_eq!(get_protection_mode(true, false), "guard");
    }

    #[test]
    fn api_status_files_no_longer_advertises_dead_jsonl_streams() {
        // Spec 049 PR20 anchor. The sensor's events-*.jsonl and
        // incidents-*.jsonl sinks were removed by spec-016
        // (commit 8bd59990, 2026-04-12). The Sensors HUD used to
        // probe their existence and render "events: not found,
        // size: 0" — looked like a regression to the operator,
        // wasn't. PR20 dropped those keys from /api/status.files;
        // this test pins the contract so a future refactor can't
        // resurrect the misleading probe.
        let files_json = serde_json::json!({
            "decisions": { "exists": true, "size_bytes": 100 },
            "telemetry": { "exists": true, "size_bytes": 200 },
        });
        let obj = files_json.as_object().expect("object");
        assert!(
            !obj.contains_key("events"),
            "/api/status.files must NOT include the dead `events` probe"
        );
        assert!(
            !obj.contains_key("incidents"),
            "/api/status.files must NOT include the dead `incidents` probe"
        );
        assert!(
            obj.contains_key("decisions"),
            "/api/status.files must keep the live `decisions` probe"
        );
        assert!(
            obj.contains_key("telemetry"),
            "/api/status.files must keep the live `telemetry` probe"
        );
    }

    #[test]
    fn test_honeypot_mode_always_on() {
        let action_cfg = DashboardActionConfig {
            enabled: true,
            honeypot_mode: "always_on".to_string(),
            ..Default::default()
        };
        assert_eq!(action_cfg.honeypot_mode, "always_on");
    }

    #[test]
    fn test_honeypot_mode_off() {
        let action_cfg = DashboardActionConfig {
            enabled: false,
            honeypot_mode: "off".to_string(),
            ..Default::default()
        };
        assert_eq!(action_cfg.honeypot_mode, "off");
    }

    #[test]
    fn test_honeypot_mode_listener() {
        let action_cfg = DashboardActionConfig {
            enabled: true,
            honeypot_mode: "listener".to_string(),
            ..Default::default()
        };
        assert_eq!(action_cfg.honeypot_mode, "listener");
    }

    #[test]
    fn test_xdp_integration_state_off() {
        let action_cfg = DashboardActionConfig {
            execution_guard_enabled: false,
            ..Default::default()
        };
        assert_eq!(action_cfg.execution_guard_enabled, false);
    }

    #[test]
    fn test_kill_chain_tracker_on() {
        let action_cfg = DashboardActionConfig {
            enabled: true,
            execution_guard_enabled: true,
            ..Default::default()
        };
        assert!(action_cfg.enabled);
        assert!(action_cfg.execution_guard_enabled);
    }

    // ── build_sensors_payload (Finding 4 anchor) ─────────────────────
    //
    // The handler runs this on the blocking pool. The payload structure
    // must be stable; the test pins the JSON shape so a future refactor
    // (e.g. the spawn_blocking wrapper changing arg order) cannot
    // accidentally drop a field.

    #[test]
    fn build_sensors_payload_returns_expected_shape_on_empty_graph() {
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = build_sensors_payload(&kg, dir.path(), None, None, None);

        // Required fields: date, total_events, total_incidents, sources,
        // top_kinds, detectors, event_timeline, detector_timeline.
        for field in [
            "date",
            "total_events",
            "total_incidents",
            "sources",
            "top_kinds",
            "detectors",
            "event_timeline",
            "detector_timeline",
        ] {
            assert!(
                payload.get(field).is_some(),
                "build_sensors_payload missing required field {field}"
            );
        }
        assert_eq!(payload["total_events"].as_u64(), Some(0));
        assert_eq!(payload["total_incidents"].as_u64(), Some(0));
    }

    #[test]
    fn read_collector_health_file_returns_null_for_missing_or_malformed_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            read_collector_health_file(dir.path()),
            serde_json::Value::Null
        );

        std::fs::write(dir.path().join("collector-health.json"), "not json")
            .expect("write malformed health file");
        assert_eq!(
            read_collector_health_file(dir.path()),
            serde_json::Value::Null
        );
    }

    #[test]
    fn read_collector_health_file_preserves_valid_json_payload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let health = serde_json::json!({
            "collectors": {
                "auth_log": { "detected": true, "active": true },
                "docker": { "detected": false, "active": false }
            }
        });
        std::fs::write(
            dir.path().join("collector-health.json"),
            serde_json::to_string(&health).expect("serialize health"),
        )
        .expect("write health file");

        assert_eq!(read_collector_health_file(dir.path()), health);
    }

    #[test]
    fn build_sensors_payload_includes_collector_health_when_file_is_valid() {
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("collector-health.json"),
            r#"{"collectors":{"auth_log":{"detected":true,"active":false}}}"#,
        )
        .expect("write health file");

        let payload = build_sensors_payload(&kg, dir.path(), None, None, None);
        assert_eq!(
            payload["collector_health"]["collectors"]["auth_log"]["detected"].as_bool(),
            Some(true)
        );
        assert_eq!(
            payload["collector_health"]["collectors"]["auth_log"]["active"].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn build_sensors_payload_uses_canonical_when_threaded() {
        // PR30 match branch: `Some(n) => n as usize`. Canonical helper
        // had already done the SQLite per-date read; the HUD trusts
        // that number and ignores both the KG counter and the
        // telemetry-snapshot fallback. Even when the KG counter is
        // wildly larger (e.g. process has been running for a week),
        // the canonical value wins.
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        {
            let mut g = kg.write().unwrap();
            g.total_events_ingested = 1_000_000;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = build_sensors_payload(&kg, dir.path(), None, Some(13), None);
        assert_eq!(
            payload["total_events"].as_u64(),
            Some(13),
            "canonical events_today (13) must win over the KG counter \
             (1_000_000) — Sensors HUD diverging from /api/overview is \
             the bug PR30 was created to kill"
        );
    }

    #[test]
    fn build_sensors_payload_falls_back_to_kg_counter_when_canonical_none_and_graph_has_data() {
        // PR30 match branch: `None if graph.total_events_ingested > 0
        // => graph.total_events_ingested`. Reached when the caller
        // couldn't compute a canonical value (no SQLite store, very
        // early boot, dev-only mode) but the KG has ingested events.
        // Acceptable best-effort number; same fallback /api/overview
        // uses in `events_count_fallback` at data_api.rs.
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        {
            let mut g = kg.write().unwrap();
            g.total_events_ingested = 555;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = build_sensors_payload(&kg, dir.path(), None, None, None);
        assert_eq!(
            payload["total_events"].as_u64(),
            Some(555),
            "with no canonical value threaded and KG counter non-zero, \
             the HUD must surface the KG counter as best-effort. This \
             is the documented degraded-mode contract; /api/overview \
             uses the same fallback when SQLite is absent."
        );
    }

    // 2026-05-02 audit B1/P1 (Spec 039 P3) anchor: the Sensors HUD
    // must paint the SAME total_events / total_incidents as the
    // canonical OverviewSnapshot (which Home, Briefing, and Report
    // already read). Pre-fix the HUD scanned the KG and showed
    // "47 events handled" while the Home tile said something different.
    #[test]
    fn build_sensors_payload_reads_topline_counters_from_snapshot() {
        use crate::dashboard::types::{
            BucketStats, DetectorCount, OutcomeBuckets, OverviewSnapshot, PendingBreakdown,
            SystemHealth,
        };
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");

        // Snapshot says: 5+3+1+2+1+4 = 16 incidents today, 14_700_000 events.
        let snap = OverviewSnapshot {
            date: "2026-05-02".to_string(),
            generated_at: chrono::Utc::now(),
            health: SystemHealth::OperatingNormally,
            buckets: OutcomeBuckets {
                blocked: BucketStats {
                    incidents: 5,
                    unique_attackers: 3,
                    severities: Default::default(),
                },
                observing: BucketStats {
                    incidents: 3,
                    unique_attackers: 0,
                    severities: Default::default(),
                },
                honeypot: BucketStats {
                    incidents: 1,
                    unique_attackers: 0,
                    severities: Default::default(),
                },
                dismissed: BucketStats {
                    incidents: 2,
                    unique_attackers: 0,
                    severities: Default::default(),
                },
                allowlisted: BucketStats {
                    incidents: 1,
                    unique_attackers: 0,
                    severities: Default::default(),
                },
                attention: BucketStats {
                    incidents: 4,
                    unique_attackers: 0,
                    severities: Default::default(),
                },
            },
            pending: PendingBreakdown::default(),
            events_today: 14_700_000,
            top_detectors: vec![DetectorCount {
                detector: "ssh_bruteforce".to_string(),
                count: 1,
            }],
        };

        let payload = build_sensors_payload(&kg, dir.path(), Some(&snap), None, None);
        assert_eq!(
            payload["total_events"].as_u64(),
            Some(14_700_000),
            "total_events must come from snapshot.events_today, not KG counter"
        );
        assert_eq!(
            payload["total_incidents"].as_u64(),
            Some(16),
            "total_incidents must be the sum of OverviewSnapshot bucket incidents \
             (5+3+1+2+1+4 = 16) — same source the Home tile and Briefing read"
        );
    }

    #[tokio::test]
    async fn api_sensors_async_handler_returns_payload_via_spawn_blocking() {
        // Anchors the spawn_blocking wrapper around build_sensors_payload.
        // Goes through the full async handler so the cache + spawn_blocking
        // + extracted helper chain stays exercised.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = crate::dashboard::state::test_dashboard_state(dir.path());
        // Force `last_activity` to "recent" so the sleeping path doesn't
        // short-circuit the handler.
        state.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
        let Json(payload) = api_sensors(State(state)).await;
        // First call is a cache miss; payload must include the canonical
        // shape from build_sensors_payload.
        for field in [
            "date",
            "total_events",
            "total_incidents",
            "sources",
            "top_kinds",
            "detectors",
        ] {
            assert!(
                payload.get(field).is_some(),
                "api_sensors response missing required field {field}"
            );
        }
    }

    #[test]
    fn build_sensors_payload_falls_back_to_telemetry_snapshot_when_graph_empty() {
        // Anchors the `else` branch of `if graph.total_events_ingested > 0`
        // — when the graph hasn't seen any telemetry, the handler reads
        // from the JSONL telemetry snapshot. Empty tempdir → fallback
        // returns empty sources but the payload still has the right shape.
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = build_sensors_payload(&kg, dir.path(), None, None, None);
        // Total stays 0 (no graph counters AND no telemetry file).
        assert_eq!(payload["total_events"].as_u64(), Some(0));
        let sources = payload["sources"].as_array().expect("sources array");
        assert_eq!(sources.len(), 0, "no telemetry snapshot → no sources");
    }

    #[test]
    fn build_sensors_payload_counts_telemetry_from_graph() {
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        // Inject telemetry counters directly so we don't depend on the
        // event-ingest pipeline. Sensors handler reads these counters
        // directly when total_events_ingested > 0.
        g.record_event_telemetry("auth_log", "ssh.login_failed", chrono::Utc::now());
        g.record_event_telemetry("auth_log", "ssh.login_failed", chrono::Utc::now());
        g.record_event_telemetry("nginx_access", "http.request", chrono::Utc::now());

        let kg = std::sync::Arc::new(std::sync::RwLock::new(g));
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = build_sensors_payload(&kg, dir.path(), None, None, None);

        assert_eq!(payload["total_events"].as_u64(), Some(3));
        let sources = payload["sources"].as_array().expect("sources array");
        // Two distinct sources, sorted by count desc — auth_log first.
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0]["name"].as_str(), Some("auth_log"));
        assert_eq!(sources[0]["count"].as_u64(), Some(2));
    }

    // 2026-05-02 audit anchor: the operator reported the Event Timeline
    // chart was "fixo aparecendo alto so depois das 20 horas" / "ta
    // assim a dias". Cause: `event_timeline` keys are
    // `YYYY-MM-DDTHH:MM`; the display projection stripped the date and
    // the BTreeMap collapsed multi-day buckets onto the same `HH:MM`
    // display key. With last-iteration-wins semantics, yesterday's
    // pre-spike hours survived for hours where today hadn't ingested
    // anything yet — the chart looked like a multi-day average instead
    // of today's fresh data. The fix filters buckets to today's date
    // prefix before stripping; this anchor pins that contract.
    #[test]
    fn build_sensors_payload_event_timeline_filters_to_today_only() {
        let mut g = crate::knowledge_graph::KnowledgeGraph::new();
        // Force `total_events_ingested > 0` so the per-source path is
        // taken (the chart-fold bug only affected dated buckets, not
        // the per-source counters tested above). We deliberately do NOT
        // pass `Utc::now()` here — when CI ran at 2026-05-19T03:15:03Z
        // the resulting bucket key was `2026-05-19T03:15`, which the
        // strip-date projection turned into the literal `03:15` key the
        // assertion below tests for absence (yesterday's 03:15 bucket
        // would NOT have leaked, but TODAY's 03:15 bucket from this
        // bootstrap call confounds the assertion). Pin the bootstrap
        // event at today-noon UTC so the bucket key (`12:00`) never
        // collides with the asserted slots regardless of wall clock.
        let today_noon = chrono::Utc::now()
            .date_naive()
            .and_hms_opt(12, 0, 0)
            .expect("12:00 is always valid")
            .and_utc();
        g.record_event_telemetry("auth_log", "ssh.login_failed", today_noon);

        // Seed the event_timeline with both today's and yesterday's
        // buckets. Yesterday's value for a slot today hasn't reached
        // is what would survive the BTreeMap dedup pre-fix.
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let yesterday = (chrono::Utc::now() - chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();
        // Wave 6c: event_timeline keys are now `Arc<str>`.
        let mut yesterday_03_15: std::collections::HashMap<std::sync::Arc<str>, usize> =
            std::collections::HashMap::new();
        yesterday_03_15.insert(std::sync::Arc::<str>::from("auth_log"), 9_999);
        let mut today_22_00: std::collections::HashMap<std::sync::Arc<str>, usize> =
            std::collections::HashMap::new();
        today_22_00.insert(std::sync::Arc::<str>::from("auth_log"), 7);
        g.event_timeline.insert(
            std::sync::Arc::<str>::from(format!("{yesterday}T03:15").as_str()),
            yesterday_03_15,
        );
        g.event_timeline.insert(
            std::sync::Arc::<str>::from(format!("{today}T22:00").as_str()),
            today_22_00,
        );

        let kg = std::sync::Arc::new(std::sync::RwLock::new(g));
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = build_sensors_payload(&kg, dir.path(), None, None, None);

        let timeline = payload["event_timeline"].as_object().expect("timeline");
        // Yesterday's `03:15` MUST NOT leak into today's chart even
        // though strip_date_prefix would project it to the same key.
        assert!(
            !timeline.contains_key("03:15"),
            "yesterday's 03:15 bucket must NOT appear on today's chart \
             (chart-fold regression — see commit message). Got: {timeline:?}"
        );
        // Today's bucket is present and untouched.
        assert!(
            timeline.contains_key("22:00"),
            "today's 22:00 bucket must appear on today's chart. Got: {timeline:?}"
        );
        let today_bucket = timeline["22:00"].as_object().unwrap();
        assert_eq!(today_bucket["auth_log"].as_u64(), Some(7));
    }

    // Spec 050-hotfix follow-up to #659: per-collector telemetry tiles
    // ("TELEMETRY STREAMS" rows in the Sensors HUD) must read from the
    // same canonical SQLite source the chart now uses. Pre-fix the tiles
    // rendered `graph.source_counts` — a process-lifetime accumulator
    // that survives across restarts via the KG snapshot. Operator
    // screenshot on 2026-05-17 showed EBPF=23,060,722 (lifetime sum)
    // next to a chart spanning today's date only — operator-visible
    // contradiction.
    //
    // Asserts: when `event_timeline_canonical` is Some, the `sources`
    // field sum agrees with the canonical totals (not the poisoned KG
    // counter).
    #[test]
    fn build_sensors_payload_sources_prefer_canonical_over_kg_lifetime_counter() {
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");

        // Poison the KG with an inflated lifetime counter for `ebpf`
        // — what production looked like before this fix (23 M lifetime
        // for "today's" tile).
        {
            let mut g = kg.write().unwrap();
            let ebpf_arc = crate::knowledge_graph::intern::intern("ebpf");
            g.source_counts.insert(ebpf_arc, 23_000_000);
            g.total_events_ingested = 23_000_000;
        }

        // Canonical timeline: today's truth from SQLite.
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let mut canonical: std::collections::BTreeMap<
            String,
            std::collections::HashMap<String, u64>,
        > = std::collections::BTreeMap::new();
        canonical
            .entry(format!("{today}T09:13"))
            .or_default()
            .insert("ebpf".to_string(), 30_000);
        canonical
            .entry(format!("{today}T14:34"))
            .or_default()
            .insert("ebpf".to_string(), 20_000);
        canonical
            .entry(format!("{today}T14:35"))
            .or_default()
            .insert("auditd".to_string(), 5_000);

        let payload = build_sensors_payload(&kg, dir.path(), None, None, Some(canonical));
        let sources = payload["sources"]
            .as_array()
            .expect("sources must be an array");

        // Find ebpf in the sources list. JSON shape: {"name": str, "count": u64}.
        let ebpf_entry = sources
            .iter()
            .find(|v| v["name"].as_str() == Some("ebpf"))
            .expect("ebpf source must appear");
        let ebpf_count = ebpf_entry["count"]
            .as_u64()
            .expect("ebpf count must be u64");
        assert_eq!(
            ebpf_count, 50_000,
            "ebpf tile must sum canonical buckets (30k + 20k = 50k), \
             NOT the 23 M KG lifetime poison. Got {ebpf_count}"
        );

        let auditd_entry = sources
            .iter()
            .find(|v| v["name"].as_str() == Some("auditd"))
            .expect("auditd source must appear");
        let auditd_count = auditd_entry["count"]
            .as_u64()
            .expect("auditd count must be u64");
        assert_eq!(
            auditd_count, 5_000,
            "auditd tile must sum to canonical bucket value, got {auditd_count}"
        );
    }

    #[test]
    fn build_sensors_payload_canonical_sources_drop_unknown_collectors() {
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let mut canonical: std::collections::BTreeMap<
            String,
            std::collections::HashMap<String, u64>,
        > = std::collections::BTreeMap::new();
        canonical
            .entry(format!("{today}T01:00"))
            .or_default()
            .insert("auth_log".to_string(), 2);
        canonical
            .entry(format!("{today}T01:01"))
            .or_default()
            .insert("retired_collector".to_string(), 99);

        let payload = build_sensors_payload(&kg, dir.path(), None, None, Some(canonical));
        let sources = payload["sources"].as_array().expect("sources array");
        let names: Vec<_> = sources.iter().filter_map(|v| v["name"].as_str()).collect();
        assert!(names.contains(&"auth_log"));
        assert!(
            !names.contains(&"retired_collector"),
            "canonical source names must still be filtered through KNOWN_COLLECTORS: {names:?}"
        );
    }

    // Spec 050-hotfix follow-up to #660: when a collector is in the KG
    // roster but absent from today's canonical timeline (e.g. UTC just
    // rolled over so SQLite has no events for that source yet), the
    // collector must STILL appear in the tile list with count=0 so the
    // operator sees the full roster.
    //
    // Operator-reported 2026-05-17 after #660 deploy: only 2/18 tiles
    // visible. Pre-#660 the lifetime KG counter kept them all visible
    // with inflated counts. #660 dropped them to 0/18 by reading
    // canonical only. This anchor pins the corrected union behaviour.
    #[test]
    fn build_sensors_payload_sources_includes_kg_roster_with_zero_when_canonical_has_no_today_data()
    {
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");

        // KG roster: 4 collectors known historically (lifetime counters).
        {
            let mut g = kg.write().unwrap();
            g.source_counts
                .insert(crate::knowledge_graph::intern::intern("ebpf"), 23_000_000);
            g.source_counts.insert(
                crate::knowledge_graph::intern::intern("tcp_stream"),
                1_000_000,
            );
            g.source_counts.insert(
                crate::knowledge_graph::intern::intern("http_capture"),
                500_000,
            );
            g.source_counts
                .insert(crate::knowledge_graph::intern::intern("auditd"), 100_000);
            g.total_events_ingested = 24_600_000;
        }

        // Canonical: only `auditd` has events today (the UTC-just-rolled-over
        // shape that broke the dashboard).
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let mut canonical: std::collections::BTreeMap<
            String,
            std::collections::HashMap<String, u64>,
        > = std::collections::BTreeMap::new();
        canonical
            .entry(format!("{today}T00:05"))
            .or_default()
            .insert("auditd".to_string(), 94);

        let payload = build_sensors_payload(&kg, dir.path(), None, None, Some(canonical));
        let sources = payload["sources"]
            .as_array()
            .expect("sources must be an array");

        // All 4 KG-known collectors must appear in the tile list.
        let names: std::collections::HashSet<String> = sources
            .iter()
            .filter_map(|v| v["name"].as_str().map(|s| s.to_string()))
            .collect();
        for required in ["ebpf", "tcp_stream", "http_capture", "auditd"] {
            assert!(
                names.contains(required),
                "collector {required} must appear in tile list — got {names:?}"
            );
        }

        // `auditd` got today's canonical count, NOT the KG lifetime.
        let auditd_count = sources
            .iter()
            .find(|v| v["name"].as_str() == Some("auditd"))
            .and_then(|v| v["count"].as_u64())
            .expect("auditd count present");
        assert_eq!(auditd_count, 94);

        // Quiet collectors render as zero — frontend's active-vs-broken
        // indicator depends on the row existing with count=0, not on
        // them being absent.
        for quiet in ["ebpf", "tcp_stream", "http_capture"] {
            let count = sources
                .iter()
                .find(|v| v["name"].as_str() == Some(quiet))
                .and_then(|v| v["count"].as_u64())
                .unwrap_or(u64::MAX);
            assert_eq!(
                count, 0,
                "quiet collector {quiet} must render with count=0 \
                 (NOT KG lifetime, NOT missing); got {count}"
            );
        }
    }

    // Spec 050-hotfix (issue #656) anchor: when the caller threads a
    // canonical event timeline (SQLite-backed), `build_sensors_payload`
    // must paint that data instead of `graph.event_timeline`. The KG
    // counter silently diverged from SQLite (PR30 fixed this for tile
    // totals; the chart was a separate consumer not migrated). Asserts:
    //
    //   1. When canonical is Some, the chart sums to the canonical
    //      data even if the KG counter is poisoned with a different
    //      shape (simulating the post-restart drift the operator hit).
    //   2. The bucket keys come through stripped of the date prefix
    //      (HH:MM) just like the legacy KG path.
    #[test]
    fn build_sensors_payload_event_timeline_prefers_canonical_over_kg_counter() {
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // Poison the KG event_timeline with a clearly-distinguishable
        // shape that the canonical source does NOT have. If the chart
        // accidentally falls back to the KG, the test catches it.
        {
            let mut g = kg.write().unwrap();
            let poisoned_bucket = crate::knowledge_graph::intern::intern(&format!("{today}T03:14"));
            let poisoned_src = crate::knowledge_graph::intern::intern("kg_only_poison_src");
            g.event_timeline
                .entry(poisoned_bucket)
                .or_default()
                .insert(poisoned_src, 9_999);
        }

        // Canonical timeline: two buckets, two real collectors. This
        // is what the SQLite source returns.
        let mut canonical: std::collections::BTreeMap<
            String,
            std::collections::HashMap<String, u64>,
        > = std::collections::BTreeMap::new();
        let bucket_a = format!("{today}T14:10");
        let bucket_b = format!("{today}T14:11");
        canonical
            .entry(bucket_a.clone())
            .or_default()
            .insert("ebpf".to_string(), 18_000);
        canonical
            .entry(bucket_b.clone())
            .or_default()
            .insert("ebpf".to_string(), 17_500);

        let payload = build_sensors_payload(&kg, dir.path(), None, None, Some(canonical.clone()));
        let timeline = payload["event_timeline"]
            .as_object()
            .expect("event_timeline must be an object");

        // The poisoned KG bucket (03:14) must NOT appear — canonical wins.
        assert!(
            !timeline.contains_key("03:14"),
            "KG event_timeline must NOT leak into the chart when canonical is present; \
             chart fell back to the KG counter"
        );

        // Both canonical buckets must appear, with date prefix stripped
        // to HH:MM (the existing rendering contract).
        assert!(
            timeline.contains_key("14:10"),
            "canonical bucket 14:10 must appear in the chart"
        );
        assert!(
            timeline.contains_key("14:11"),
            "canonical bucket 14:11 must appear in the chart"
        );

        // Sum across canonical buckets must equal the SQLite truth
        // (35,500). If the chart reverted to the KG counter, it would
        // emit 9,999 instead.
        let total: u64 = timeline
            .values()
            .filter_map(|v| v.as_object())
            .flat_map(|bucket| bucket.values())
            .filter_map(|v| v.as_u64())
            .sum();
        assert_eq!(
            total, 35_500,
            "chart sum must equal canonical SQLite total (35,500), not the KG poison (9,999)"
        );
    }

    // 2026-05-02 audit anchor: the operator's screenshot showed
    // "EVENTS TODAY: 0" while per-source counters totalled millions.
    // Pre-fix the SoT helper hardcoded `events_today: 0` and only
    // api_overview backfilled it. The Sensors HUD path (PR #409) read
    // the un-backfilled snapshot directly. This anchor pins that
    // build_sensors_payload, when handed an OverviewSnapshot with
    // events_today populated, surfaces that exact value as
    // `total_events`.
    #[test]
    fn build_sensors_payload_uses_snapshot_events_today_field() {
        use crate::dashboard::types::{
            BucketStats, OutcomeBuckets, OverviewSnapshot, PendingBreakdown, SystemHealth,
        };
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        let dir = tempfile::tempdir().expect("tempdir");

        let snap = OverviewSnapshot {
            date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            generated_at: chrono::Utc::now(),
            health: SystemHealth::OperatingNormally,
            buckets: OutcomeBuckets {
                blocked: BucketStats {
                    incidents: 1,
                    unique_attackers: 1,
                    severities: Default::default(),
                },
                ..Default::default()
            },
            pending: PendingBreakdown::default(),
            // Distinctive value so a regression that swaps fields would
            // surface immediately.
            events_today: 13_177_172,
            top_detectors: vec![],
        };

        let payload = build_sensors_payload(&kg, dir.path(), Some(&snap), None, None);
        assert_eq!(
            payload["total_events"].as_u64(),
            Some(13_177_172),
            "total_events MUST come from snapshot.events_today (the \
             canonical SoT field). If this drops to 0, the SoT \
             contract regressed — see fix in compute_overview_counts_from_sqlite"
        );
    }

    // -----------------------------------------------------------------
    // Wave 2026-05-18 — telemetry name drift + phantom suppression.
    // Anchored on the operator's prod screenshot where the sensors HUD
    // listed 6 telemetry streams at 0 today, including `osquery` (a
    // retired collector that never shipped) and `fanotify` (mis-
    // categorised as TELEMETRY when it's actually an ALARM whose
    // silence means the watched paths are quiet).
    // -----------------------------------------------------------------

    #[test]
    fn filter_known_collector_accepts_every_current_manifest_name() {
        // Each name in KNOWN_COLLECTORS must round-trip through the
        // filter. If a name is added to the list but the filter is
        // somehow case-sensitive or trimmed wrong, this catches it.
        for name in KNOWN_COLLECTORS {
            assert!(
                filter_known_collector(name),
                "KNOWN_COLLECTORS contains {name:?} but filter_known_collector rejected it"
            );
        }
    }

    #[test]
    fn filter_known_collector_rejects_retired_phantom_names() {
        // Hard regression anchor for the operator's prod screenshot.
        // If any future PR adds these back without a real collector,
        // this test fails.
        for retired in &["osquery", "osquery_log", "suricata_eve", "suricata_alert"] {
            assert!(
                !filter_known_collector(retired),
                "phantom collector {retired:?} should NOT pass the filter"
            );
        }
    }

    #[test]
    fn filter_known_collector_rejects_drift_aliases_for_renamed_collectors() {
        // The three drift cases this PR fixed. None of these wire
        // names should pass the filter — the canonical names
        // (`ebpf`, `auditd`, `fanotify`) cover them.
        for drift in &["ebpf_syscall", "exec_audit", "fanotify_watch"] {
            assert!(
                !filter_known_collector(drift),
                "drift alias {drift:?} should NOT pass the filter — the canonical name covers it"
            );
        }
    }

    #[test]
    fn build_sensors_payload_drops_phantom_kg_entries() {
        // The literal prod scenario: KG `source_counts` holds a
        // legacy `osquery_log` entry from a removed collector. The
        // dashboard payload must NOT include it in the sources roster.
        let dir = tempfile::TempDir::new().unwrap();
        let kg = std::sync::Arc::new(std::sync::RwLock::new(
            crate::knowledge_graph::KnowledgeGraph::new(),
        ));
        {
            let mut g = kg.write().unwrap();
            // Seed source_counts with both a real and a phantom name.
            // Use the same intern() path the live ingestion code uses
            // so the key shape matches the production path.
            *g.source_counts
                .entry(crate::knowledge_graph::intern::intern("ebpf"))
                .or_insert(0) += 5;
            *g.source_counts
                .entry(crate::knowledge_graph::intern::intern("osquery_log"))
                .or_insert(0) += 42; // phantom
            *g.source_counts
                .entry(crate::knowledge_graph::intern::intern("fanotify_watch"))
                .or_insert(0) += 7; // drift alias
            g.total_events_ingested = 54;
        }

        let payload = build_sensors_payload(&kg, dir.path(), None, None, None);
        let sources = payload["sources"]
            .as_array()
            .expect("payload must include sources array");

        let names: Vec<&str> = sources.iter().filter_map(|v| v["name"].as_str()).collect();

        assert!(names.contains(&"ebpf"), "real collector must remain");
        assert!(
            !names.contains(&"osquery_log"),
            "phantom name `osquery_log` leaked into payload: {names:?}"
        );
        assert!(
            !names.contains(&"fanotify_watch"),
            "drift alias `fanotify_watch` leaked into payload (canonical is `fanotify`): {names:?}"
        );
    }
}
