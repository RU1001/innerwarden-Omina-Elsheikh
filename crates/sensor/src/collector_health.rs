//! Collector health metadata + categorization.
//!
//! ## Why this exists
//!
//! Pre-2026-05-14 the Sensors HUD showed a flat list of "collector → event
//! count today". Operators (and the engineer writing PR15-PR24 in May
//! 2026) kept misreading low-count entries as "broken collector". The
//! root cause was that the HUD mixed two fundamentally different kinds
//! of collector:
//!
//! * **Telemetry collectors** (auditd, ebpf, dns_capture, tcp_stream, …)
//!   are always-on and should always be growing. Low count → broken.
//! * **Alarm collectors** (tls_fingerprint, fanotify_watch, integrity,
//!   sysctl_drift, …) are event-driven — they ONLY emit when something
//!   interesting happens (malicious JA3, file hash drift, sysctl
//!   change). Low count → healthy system.
//! * **Snapshot collectors** (suid_inventory, systemd_inventory) emit
//!   periodically at boot or scheduled ticks. Count = number of ticks.
//! * **External-source collectors** (nginx_access) need a service
//!   the host may not have installed.
//!   Missing source → "disabled: source unavailable", not "broken".
//!
//! ## Portability contract
//!
//! The CATEGORIZATION is hardcoded — every collector knows what it is
//! by design. The HEALTH is probed at boot per-host: if a file path
//! doesn't exist on this host (no nginx installed, no Suricata, etc.),
//! the collector reports `SourceUnavailable` and the HUD says so
//! plainly. The same agent binary on different hosts will surface
//! different health states; the operator never has to guess.
//!
//! PR25 landed the foundation (types + manifest + probe helper +
//! unit tests). PR29 wires it: sensor main.rs calls
//! `build_status` + `write_status_file` at boot, dashboard reads
//! the JSON. Methods on `CollectorCategory` / `CollectorHealth`
//! remain unused by the binary (consumed via serde JSON on the agent
//! side) and stay as readable code for ops / future telemetry
//! integrations — hence the targeted allows below.

use std::path::PathBuf;

use serde::Serialize;

/// Operational class of a collector. Determines how the Sensors HUD
/// should interpret a low event count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorCategory {
    /// Always-on data feed. Sensor pipeline ingests continuously; low
    /// count means the collector stopped or its data source died.
    Telemetry,
    /// Event-driven detector. Only emits when something interesting
    /// happens (malicious JA3, file drift, anomaly). Silence is the
    /// healthy steady state.
    Alarm,
    /// Periodic point-in-time snapshot (host inventory, suid scan).
    /// Count = number of snapshot cycles completed.
    Snapshot,
}

impl CollectorCategory {
    // Frontend has its own JS copy of this mapping; kept Rust-side so
    // future server-rendered surfaces (e.g. `innerwarden ctl health`)
    // can reuse a single definition.
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Telemetry => "telemetry",
            Self::Alarm => "alarm",
            Self::Snapshot => "snapshot",
        }
    }

    /// Operator-readable description of why a low count is or is not
    /// concerning for this category. Goes into the HUD tooltip so
    /// operators stop misreading silence as broken.
    #[allow(dead_code)]
    pub fn silence_meaning(self) -> &'static str {
        match self {
            Self::Telemetry => {
                "Telemetry stream — low count signals the collector or its source is broken."
            }
            Self::Alarm => {
                "Event-driven detector — low count means the system is healthy. Silence is good."
            }
            Self::Snapshot => {
                "Periodic snapshot — count reflects scheduled cycles, not detected items."
            }
        }
    }
}

/// Per-host health state for a single collector. Probed at boot and
/// optionally refreshed at periodic ticks.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CollectorHealth {
    /// Collector started successfully and its data source is reachable.
    Active,
    /// Collector is enabled in config but the data source path does
    /// not exist on this host. Operator-actionable: install the
    /// upstream service (Suricata, Osquery) or disable the collector.
    SourceUnavailable { path: String },
    /// Collector is enabled and the data source path exists, but the
    /// file is empty AND has not been written to in 24+ hours.
    /// Indicates the upstream service stopped writing (broken
    /// nginx config, log rotation lost the live file, etc.).
    SourceEmpty {
        path: String,
        last_write_iso: String,
    },
    /// Collector ran but lacks OS-level capability (CAP_NET_RAW,
    /// CAP_SYS_ADMIN). Operator-actionable: check the systemd unit's
    /// `AmbientCapabilities` or run with the right user.
    // Reserved for capability-probe wiring (phase 3); kept in the enum
    // so the JSON schema is stable across phases.
    #[allow(dead_code)]
    PermissionDenied,
    /// Collector is enabled in config but not supported on this host's
    /// platform (e.g. fanotify on macOS, ebpf without recent kernel).
    // Reserved for platform-probe wiring (phase 3).
    #[allow(dead_code)]
    Unsupported { reason: String },
    /// Collector is disabled in config — explicit operator choice,
    /// not a fault.
    DisabledByConfig,
}

impl CollectorHealth {
    /// Short single-word status for the HUD. Maps each variant to a
    /// stable string the frontend keys on.
    // Frontend renders the badge from the serde-tagged JSON `state`
    // field directly; this method is kept for symmetric Rust callers
    // (e.g. `innerwarden ctl health`, future tests).
    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::SourceUnavailable { .. } => "source_unavailable",
            Self::SourceEmpty { .. } => "source_empty",
            Self::PermissionDenied => "permission_denied",
            Self::Unsupported { .. } => "unsupported",
            Self::DisabledByConfig => "disabled",
        }
    }

    /// Operator-readable explanation of WHY the collector is in this
    /// state. Renders in the HUD tooltip next to the badge.
    // Frontend builds tooltips from the JSON `path` / `reason` fields
    // directly; kept Rust-side for parity with `label()`.
    #[allow(dead_code)]
    pub fn reason(&self) -> String {
        match self {
            Self::Active => "Running normally.".to_string(),
            Self::SourceUnavailable { path } => format!(
                "Configured source file does not exist on this host: {path}. \
                 Install the upstream service or remove this collector from config."
            ),
            Self::SourceEmpty {
                path,
                last_write_iso,
            } => format!(
                "Source file {path} exists but is empty and has not been \
                 written to since {last_write_iso}. Verify the upstream \
                 service is still writing logs here."
            ),
            Self::PermissionDenied => {
                "Lacks OS-level capability. Check the systemd unit's AmbientCapabilities."
                    .to_string()
            }
            Self::Unsupported { reason } => format!("Unsupported on this host: {reason}"),
            Self::DisabledByConfig => "Disabled in config — operator choice.".to_string(),
        }
    }
}

/// Full status report for one collector, emitted at boot and read by
/// the Sensors HUD. Combines static metadata (category) with
/// per-host probed state (health).
#[derive(Debug, Clone, Serialize)]
pub struct CollectorStatus {
    pub name: String,
    pub category: CollectorCategory,
    pub health: CollectorHealth,
    /// Optional source path the collector reads from (for
    /// file-backed collectors). `None` for socket-based collectors
    /// (AF_PACKET, eBPF perf buffers).
    pub source: Option<String>,
}

/// Compile-time manifest mapping collector name → category. The
/// classification is intrinsic to the collector's design, so it
/// lives next to the type definition rather than in config.
///
/// Add a new collector → add a row here in the same commit. The
/// build will fail if any code path references a collector name
/// not in this table.
pub const COLLECTOR_MANIFEST: &[(&str, CollectorCategory)] = &[
    // ── Telemetry: always-on, high-volume feeds. ────────────────────
    //
    // Wave 2026-05-18: names here MUST match what the corresponding
    // collector writes into `Event.source`. Three drift cases were
    // fixed in this wave:
    //
    //   * `ebpf_syscall` was a duplicate slot — the collector emits
    //     `source: "ebpf"`, never `"ebpf_syscall"`. Dashboard
    //     dutifully rendered the slot at 0 events lifetime, making
    //     operators think the syscall feed was broken when it was
    //     just the wrong name.
    //
    //   * `exec_audit` was a duplicate slot — the collector emits
    //     `source: "auditd"`. Same symptom.
    //
    //   * `fanotify_watch` was a real name drift — the collector
    //     emits `source: "fanotify"`. Renaming the manifest entry to
    //     match the wire format makes the dashboard's category
    //     lookup actually succeed (previously it defaulted to
    //     Telemetry because the wire name wasn't in the manifest).
    //
    // A cross-file consistency test in `crates/agent/src/dashboard/mod.rs`
    // and the `source_name_matches_manifest` anchors below guard this
    // alignment going forward.
    ("auth_log", CollectorCategory::Telemetry),
    ("auditd", CollectorCategory::Telemetry),
    ("cgroup", CollectorCategory::Telemetry),
    ("cloudtrail", CollectorCategory::Telemetry),
    ("dns_capture", CollectorCategory::Telemetry),
    ("ebpf", CollectorCategory::Telemetry),
    // Windows ETW / Event Log collector (spec 085). Emits `source: "etw"`;
    // always-on log stream, so a low count means the feed is broken.
    ("etw", CollectorCategory::Telemetry),
    ("file_extract", CollectorCategory::Telemetry),
    ("http_capture", CollectorCategory::Telemetry),
    ("journald", CollectorCategory::Telemetry),
    ("kernel_integrity", CollectorCategory::Telemetry),
    ("macos_log", CollectorCategory::Telemetry),
    ("net_snapshot", CollectorCategory::Telemetry),
    ("nginx_access", CollectorCategory::Telemetry),
    ("nginx_error", CollectorCategory::Telemetry),
    ("proc_maps", CollectorCategory::Telemetry),
    ("proto_http", CollectorCategory::Telemetry),
    ("proto_smb", CollectorCategory::Telemetry),
    ("proto_ssh", CollectorCategory::Telemetry),
    ("syslog_firewall", CollectorCategory::Telemetry),
    ("tcp_stream", CollectorCategory::Telemetry),
    // ── Alarm: event-driven detectors. Silence = healthy. ───────────
    ("docker", CollectorCategory::Alarm),
    ("fanotify", CollectorCategory::Alarm),
    ("firmware_integrity", CollectorCategory::Alarm),
    ("integrity", CollectorCategory::Alarm),
    ("sysctl_drift", CollectorCategory::Alarm),
    ("tls_fingerprint", CollectorCategory::Alarm),
    ("usb_monitor", CollectorCategory::Alarm),
    // ── Snapshot: periodic point-in-time inventory. ─────────────────
    ("suid_inventory", CollectorCategory::Snapshot),
    ("systemd_inventory", CollectorCategory::Snapshot),
];

/// Look up a collector's category by its event-stream `source` name.
/// Returns `Telemetry` as the default when an unknown source comes
/// through — better to mis-classify as Telemetry (low count = broken
/// hint) than to silently hide the unknown collector from the HUD.
pub fn category_for(name: &str) -> CollectorCategory {
    COLLECTOR_MANIFEST
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, c)| *c)
        .unwrap_or(CollectorCategory::Telemetry)
}

/// Probe a file-backed collector's source at boot. Returns the
/// concrete `CollectorHealth` to report in the HUD.
///
/// `path` is the source file the collector reads. `now` is taken as
/// a parameter so unit tests can pin the "is empty and stale" cutoff
/// deterministically.
pub fn probe_file_source(path: &str, now: chrono::DateTime<chrono::Utc>) -> CollectorHealth {
    let p = PathBuf::from(path);
    let meta = match std::fs::metadata(&p) {
        Ok(m) => m,
        Err(_) => {
            return CollectorHealth::SourceUnavailable {
                path: path.to_string(),
            };
        }
    };
    // Empty file + no writes in 24h → flag as broken. Empty file with
    // recent writes is fine (just no activity yet).
    if meta.len() == 0 {
        let modified = meta.modified().ok().and_then(|t| {
            let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
            chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        });
        let stale = match modified {
            Some(m) => (now - m).num_hours() > 24,
            None => true,
        };
        if stale {
            let last_write_iso = modified
                .map(|m| m.to_rfc3339())
                .unwrap_or_else(|| "unknown".to_string());
            return CollectorHealth::SourceEmpty {
                path: path.to_string(),
                last_write_iso,
            };
        }
    }
    CollectorHealth::Active
}

/// Spec PR29 — write the boot-time collector health snapshot to a
/// well-known side-channel JSON file the agent dashboard reads from.
///
/// File path: `<data_dir>/collector-health.json`. Schema:
///
/// ```json
/// {
///   "generated_at": "2026-05-15T03:00:00+00:00",
///   "host": "instance-x",
///   "statuses": [
///     {
///       "name": "auth_log",
///       "category": "telemetry",
///       "health": { "state": "active" },
///       "source": "/var/log/auth.log"
///     },
///     {
///       "name": "suricata_eve",
///       "category": "telemetry",
///       "health": { "state": "source_unavailable", "path": "/var/log/suricata/eve.json" },
///       "source": "/var/log/suricata/eve.json"
///     }
///   ]
/// }
/// ```
///
/// Atomic write: `<file>.tmp` → rename. Errors are logged and
/// swallowed; a missing health file means "agent shows the legacy
/// view", not a crash.
pub fn write_status_file(
    data_dir: &std::path::Path,
    host: &str,
    statuses: &[CollectorStatus],
) -> std::io::Result<()> {
    let payload = serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "host": host,
        "statuses": statuses,
    });
    let final_path = data_dir.join("collector-health.json");
    let tmp_path = data_dir.join("collector-health.json.tmp");
    let body = serde_json::to_string_pretty(&payload).map_err(std::io::Error::other)?;
    std::fs::write(&tmp_path, body)?;
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

/// PR29 — convenience builder for a single status row. Probes the
/// file if `source` is `Some`, otherwise reports Active (the
/// collector doesn't have a file-backed source so we can't probe;
/// telemetry counters will surface a broken collector via low
/// event count).
pub fn build_status(
    name: &'static str,
    enabled_in_config: bool,
    source: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> CollectorStatus {
    let category = category_for(name);
    let health = if !enabled_in_config {
        CollectorHealth::DisabledByConfig
    } else if let Some(path) = source {
        probe_file_source(path, now)
    } else {
        CollectorHealth::Active
    };
    CollectorStatus {
        name: name.to_string(),
        category,
        health,
        source: source.map(|s| s.to_string()),
    }
}

/// Build the health row for the eBPF syscall collector. Unlike
/// file-backed collectors there is no path to probe; eBPF health is a
/// platform/kernel question answered by
/// `ebpf_syscall::ebpf_unavailability_reason` (kernel >= 5.8, BTF,
/// bytecode). `unavailability_reason` is `None` when eBPF can load, or
/// the specific cause otherwise.
///
/// This wires the `CollectorHealth::Unsupported` variant that has sat
/// reserved "for ebpf without recent kernel" since PR25 but was never
/// emitted, so the Sensors HUD now shows the kernel feed as
/// `unsupported` with a reason instead of silently appearing healthy
/// while ~44 eBPF programs are dark.
///
/// Two failure modes, both surfaced here instead of a false "active":
/// - **static** (`unavailability_reason`): kernel too old / no BTF / no
///   bytecode — eBPF cannot load at all.
/// - **runtime** (`runtime_attached`): eBPF loaded but 0 programs actually
///   attached (e.g. under a restrictive systemd sandbox), leaving the sensor
///   host-blind. `None` = attach count not known yet (treated as active, not
///   yet blind); `Some(0)` = confirmed blind; `Some(n>0)` = healthy.
pub fn build_ebpf_status(
    enabled_in_config: bool,
    unavailability_reason: Option<String>,
    runtime_attached: Option<usize>,
    _now: chrono::DateTime<chrono::Utc>,
) -> CollectorStatus {
    let health = if !enabled_in_config {
        CollectorHealth::DisabledByConfig
    } else {
        match unavailability_reason {
            Some(reason) => CollectorHealth::Unsupported { reason },
            None => match runtime_attached {
                Some(0) => CollectorHealth::Unsupported {
                    reason: "eBPF loaded but 0 programs attached at runtime - \
                             host syscall detection is off (check systemd \
                             sandboxing and capabilities)"
                        .to_string(),
                },
                _ => CollectorHealth::Active,
            },
        }
    };
    CollectorStatus {
        // Matches the wire `source` the collector emits and the dashboard
        // SENSOR_COLLECTORS id (see COLLECTOR_MANIFEST note on the ebpf row).
        name: "ebpf".to_string(),
        category: category_for("ebpf"),
        health,
        source: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_status_file_round_trips_through_json() {
        // PR29 hot-path: the sensor writes this file at boot and the
        // agent reads it on every /api/sensors request. Round-trip
        // anchor pins the JSON shape so a future schema drift fails
        // CI before reaching prod.
        let dir = tempfile::tempdir().expect("tempdir");
        let now = chrono::Utc::now();
        let statuses = vec![
            build_status("auth_log", true, Some("/var/log/auth.log"), now),
            // Wave 2026-05-17: switched from `suricata_eve` (phantom
            // collector — never shipped, removed from registry) to
            // `nginx_access`, which IS a real collector that
            // legitimately has source_unavailable on hosts without nginx.
            build_status(
                "nginx_access",
                true,
                Some("/var/log/does-not-exist.json"),
                now,
            ),
            build_status("ebpf", true, None, now),
        ];
        write_status_file(dir.path(), "test-host", &statuses).expect("write");

        let path = dir.path().join("collector-health.json");
        let body = std::fs::read_to_string(&path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");

        assert_eq!(parsed["host"], "test-host");
        let arr = parsed["statuses"].as_array().expect("statuses array");
        assert_eq!(arr.len(), 3);
        // nginx_access probe must yield source_unavailable for a
        // missing-on-this-host file. That's the operator-visible
        // signal the dashboard renders as "SOURCE MISSING".
        let nginx = arr
            .iter()
            .find(|s| s["name"] == "nginx_access")
            .expect("nginx_access row");
        assert_eq!(nginx["health"]["state"], "source_unavailable");
        // ebpf has no file source — probe defaults to Active.
        let ebpf = arr.iter().find(|s| s["name"] == "ebpf").expect("ebpf row");
        assert_eq!(ebpf["health"]["state"], "active");
    }

    #[test]
    fn registry_does_not_contain_phantom_collectors() {
        // Wave 2026-05-17 anchor: prior versions listed `osquery_log`
        // and `suricata_eve` here as if they existed, but the
        // corresponding source files never shipped — the dashboard
        // therefore rendered ghost rows that sat at 0 events forever.
        // This test fails CI if either name (or any other known phantom)
        // returns to the registry without also shipping a real collector.
        for phantom in &[
            "osquery_log",
            "osquery_anomaly",
            "suricata_eve",
            "suricata_alert",
            "falco_log",
            "wazuh_alerts",
        ] {
            // `category_for` defaults to Telemetry for unknown names;
            // an exact registry lookup is what we want here.
            let listed = COLLECTOR_MANIFEST.iter().any(|(name, _)| name == phantom);
            assert!(
                !listed,
                "phantom collector `{phantom}` is in the registry \
                 but no source file ships under crates/sensor/src/collectors/"
            );
        }
    }

    #[test]
    fn build_status_disabled_in_config_reports_disabled_health() {
        // Operator who explicitly disables a collector in config
        // must see "DISABLED" on the HUD, not "SOURCE MISSING".
        // Anti-regression for confusing the two cases.
        let now = chrono::Utc::now();
        let status = build_status("auth_log", false, Some("/var/log/auth.log"), now);
        assert!(matches!(status.health, CollectorHealth::DisabledByConfig));
    }

    #[test]
    fn category_for_known_telemetry_collectors() {
        // Spot-check: a high-volume collector must classify as
        // Telemetry so the HUD treats a low count as a fault signal.
        assert_eq!(category_for("ebpf"), CollectorCategory::Telemetry);
        assert_eq!(category_for("auditd"), CollectorCategory::Telemetry);
        assert_eq!(category_for("dns_capture"), CollectorCategory::Telemetry);
        assert_eq!(category_for("http_capture"), CollectorCategory::Telemetry);
        assert_eq!(category_for("tcp_stream"), CollectorCategory::Telemetry);
    }

    #[test]
    fn category_for_known_alarm_collectors() {
        // Anti-regression for the operator-driven 2026-05-14
        // classification: tls_fingerprint, fanotify, integrity,
        // sysctl_drift are alarm-style and their low counts mean the
        // host is healthy, NOT that the collector is broken.
        //
        // 2026-05-18: `fanotify_watch` renamed to `fanotify` to match
        // the wire `source` name the collector actually writes (see
        // crates/sensor/src/collectors/fanotify_watch.rs:163). The
        // old name now correctly returns the unknown-default
        // Telemetry, which is what `source_name_drift_no_longer_in_manifest`
        // pins below.
        assert_eq!(category_for("tls_fingerprint"), CollectorCategory::Alarm);
        assert_eq!(category_for("fanotify"), CollectorCategory::Alarm);
        assert_eq!(category_for("integrity"), CollectorCategory::Alarm);
        assert_eq!(category_for("sysctl_drift"), CollectorCategory::Alarm);
    }

    #[test]
    fn source_name_drift_no_longer_in_manifest() {
        // Regression anchor for the 2026-05-18 wire-name drift fix.
        // These three names used to be in COLLECTOR_MANIFEST but
        // didn't match what the collectors actually wrote to
        // Event.source — `ebpf_syscall.rs` emits "ebpf",
        // `exec_audit.rs` emits "auditd", `fanotify_watch.rs` emits
        // "fanotify". The dashboard mis-rendered them as TELEMETRY 0
        // forever. Now the manifest has the canonical names only;
        // the drift aliases must NOT come back.
        assert!(
            !COLLECTOR_MANIFEST
                .iter()
                .any(|(name, _)| *name == "ebpf_syscall"),
            "drift alias `ebpf_syscall` re-added to manifest — collector emits `ebpf`"
        );
        assert!(
            !COLLECTOR_MANIFEST
                .iter()
                .any(|(name, _)| *name == "exec_audit"),
            "drift alias `exec_audit` re-added to manifest — collector emits `auditd`"
        );
        assert!(
            !COLLECTOR_MANIFEST
                .iter()
                .any(|(name, _)| *name == "fanotify_watch"),
            "drift alias `fanotify_watch` re-added to manifest — collector emits `fanotify`"
        );
        // Canonical names that DO match Event.source.
        assert!(
            COLLECTOR_MANIFEST.iter().any(|(name, _)| *name == "ebpf"),
            "manifest must keep `ebpf` (the wire name)"
        );
        assert!(
            COLLECTOR_MANIFEST.iter().any(|(name, _)| *name == "auditd"),
            "manifest must keep `auditd` (the wire name)"
        );
        assert!(
            COLLECTOR_MANIFEST
                .iter()
                .any(|(name, _)| *name == "fanotify"),
            "manifest must keep `fanotify` (the wire name)"
        );
    }

    #[test]
    fn category_for_known_snapshot_collectors() {
        assert_eq!(category_for("suid_inventory"), CollectorCategory::Snapshot);
        assert_eq!(
            category_for("systemd_inventory"),
            CollectorCategory::Snapshot
        );
    }

    #[test]
    fn category_for_unknown_source_defaults_to_telemetry() {
        // Safer default: a new collector that ships without a
        // manifest entry shows up as Telemetry. A "low count =
        // broken" hint is more discoverable than silently hiding
        // the unknown collector from the HUD.
        assert_eq!(
            category_for("some_future_collector"),
            CollectorCategory::Telemetry
        );
    }

    #[test]
    fn probe_file_source_returns_unavailable_when_path_missing() {
        // Hot-path operator promise: a new install on a host without
        // nginx sees "source_unavailable" for nginx_access, NOT a
        // silent zero on the HUD.
        let now = chrono::Utc::now();
        let health = probe_file_source("/var/log/does-not-exist.json", now);
        match health {
            CollectorHealth::SourceUnavailable { path } => {
                assert_eq!(path, "/var/log/does-not-exist.json");
            }
            other => panic!("expected SourceUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn probe_file_source_returns_active_for_non_empty_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("active.log");
        std::fs::write(&path, b"some logs\n").expect("write");
        let health = probe_file_source(path.to_str().unwrap(), chrono::Utc::now());
        match health {
            CollectorHealth::Active => {}
            other => panic!("expected Active, got {other:?}"),
        }
    }

    #[test]
    fn probe_file_source_returns_source_empty_when_stale_and_zero_bytes() {
        // Operator-actionable for the 2026-05-14 prod nginx_access
        // case: file exists, size 0, no writes in 6 weeks. The HUD
        // shows "source_empty" + the last_write timestamp so the
        // operator sees exactly why and can decide.
        use std::time::{Duration, SystemTime};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stale.log");
        std::fs::write(&path, b"").expect("write empty");
        // Backdate the file mtime so it counts as stale.
        let old = SystemTime::now() - Duration::from_secs(60 * 60 * 48);
        filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(old))
            .expect("set mtime");
        let health = probe_file_source(path.to_str().unwrap(), chrono::Utc::now());
        match health {
            CollectorHealth::SourceEmpty { .. } => {}
            other => panic!("expected SourceEmpty for stale-empty file, got {other:?}"),
        }
    }

    #[test]
    fn probe_file_source_keeps_active_for_recently_touched_empty_file() {
        // Edge case: nginx just started, log file truthy-empty but
        // freshly touched. Don't false-positive into "broken".
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fresh.log");
        std::fs::write(&path, b"").expect("write");
        let health = probe_file_source(path.to_str().unwrap(), chrono::Utc::now());
        match health {
            CollectorHealth::Active => {}
            other => panic!("expected Active for fresh empty file, got {other:?}"),
        }
    }

    #[test]
    fn silence_meaning_distinguishes_categories_in_operator_text() {
        // The HUD tooltip text must make the difference between
        // "broken" (telemetry) and "healthy" (alarm) unambiguous to
        // the operator. Pin the literal strings so a future copy
        // refactor doesn't accidentally collapse the two meanings.
        assert!(CollectorCategory::Telemetry
            .silence_meaning()
            .contains("broken"));
        assert!(CollectorCategory::Alarm
            .silence_meaning()
            .contains("healthy"));
        assert!(CollectorCategory::Alarm
            .silence_meaning()
            .contains("Silence is good"));
    }

    #[test]
    fn manifest_has_no_duplicate_entries() {
        // A typo that double-registers a name would silently shadow.
        // Use a HashSet to enforce uniqueness.
        let mut seen = std::collections::HashSet::new();
        for (name, _) in COLLECTOR_MANIFEST {
            assert!(
                seen.insert(*name),
                "duplicate collector name in manifest: {name}"
            );
        }
    }

    #[test]
    fn build_ebpf_status_maps_disabled_active_and_unsupported() {
        let now = chrono::Utc::now();

        // Disabled in config -> not a fault.
        let disabled = build_ebpf_status(false, Some("kernel too old".into()), None, now);
        assert_eq!(disabled.name, "ebpf");
        assert_eq!(disabled.category, CollectorCategory::Telemetry);
        assert!(disabled.source.is_none());
        assert!(matches!(disabled.health, CollectorHealth::DisabledByConfig));

        // Enabled, available, programs attached -> Active.
        let active = build_ebpf_status(true, None, Some(44), now);
        assert!(matches!(active.health, CollectorHealth::Active));

        // Enabled, available, attach count not yet known -> still Active
        // (do not flag blind until we actually observe 0 attached).
        let unknown = build_ebpf_status(true, None, None, now);
        assert!(matches!(unknown.health, CollectorHealth::Active));

        // Enabled but unavailable -> Unsupported carrying the reason, so
        // the HUD shows WHY the kernel feed is dark instead of nothing.
        let unsupported = build_ebpf_status(
            true,
            Some("/sys/kernel/btf/vmlinux missing".into()),
            None,
            now,
        );
        match unsupported.health {
            // The reason is preserved verbatim so the HUD can show it.
            CollectorHealth::Unsupported { reason } => {
                assert_eq!(reason, "/sys/kernel/btf/vmlinux missing")
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn build_ebpf_status_flags_runtime_host_blind() {
        // The gap that let iw-k7 look healthy: eBPF loads (no static reason)
        // but 0 programs attach at runtime -> the sensor is host-blind and must
        // NOT report Active.
        let now = chrono::Utc::now();
        let blind = build_ebpf_status(true, None, Some(0), now);
        match blind.health {
            CollectorHealth::Unsupported { reason } => {
                assert!(reason.contains("0 programs attached"), "reason: {reason}");
            }
            other => panic!("expected Unsupported (host-blind), got {other:?}"),
        }
    }

    #[test]
    fn build_ebpf_status_serializes_with_state_and_reason() {
        // The dashboard keys on the serde-tagged `state` field + reason.
        let now = chrono::Utc::now();
        let status = build_ebpf_status(
            true,
            Some("kernel 4.18 is older than 5.8".into()),
            None,
            now,
        );
        let json = serde_json::to_value(&status).expect("serialize");
        assert_eq!(json["name"], "ebpf");
        assert_eq!(json["health"]["state"], "unsupported");
        assert!(json["health"]["reason"].as_str().unwrap().contains("5.8"));
    }
}
