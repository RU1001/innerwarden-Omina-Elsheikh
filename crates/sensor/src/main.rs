mod boot;
mod btf_offsets;
mod cloud_platform;
mod collector_health;
mod collectors;
mod config;
mod detector_set;
mod detectors;
mod event_channels;
mod event_dispatch;
mod event_pipeline;
mod incident_builders;
mod kernel_promote;
mod main_helpers;
mod path_trust;
mod seccomp;
mod sensor;
mod sinks;
mod tracing_init;

use anyhow::Result;
use clap::Parser;
// All collector type imports (AuthLogCollector / CloudTrailCollector /
// DockerCollector / ExecAuditCollector / IntegrityCollector /
// JournaldCollector / MacosLogCollector / NginxAccessCollector /
// NginxErrorCollector / SyslogFirewallCollector) moved to
// crates/sensor/src/boot/spawn_collectors.rs as part of the 2026-05-25
// main.rs decomposition PR5b2 — they're only constructed inside that
// module's spawn fn.
//
// All detector type imports (35 of them: SshBruteforceDetector,
// CredentialStuffingDetector, PortScanDetector, …) moved to
// crates/sensor/src/detector_set.rs as part of follow-up #2 of the
// post-PR-F3 punch list (2026-05-26). They're only mentioned inside
// the DetectorSet struct, which now lives next to them.

#[derive(Parser)]
#[command(
    name = "innerwarden-sensor",
    version,
    about = "Lightweight host observability sensor"
)]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: String,
}

// DetectorSet moved to crates/sensor/src/detector_set.rs as part of
// follow-up #2 of the post-PR-F3 punch list (2026-05-26). It pulled
// 35 detector type imports + ~100 LoC of fields out of main.rs;
// callers that previously imported `crate::DetectorSet` now import
// `crate::detector_set::DetectorSet`.

#[derive(Default)]
pub(crate) struct WriteStats {
    pub(crate) events_written: u64,
    pub(crate) events_dropped: u64,
    pub(crate) incidents_written: u64,
    // Container scope of the event currently being processed, set at the top of
    // each `process_event` (None for host events and the emergency-lane signal).
    // It rides here so the single incident sink (`write_incident`) can attribute
    // an incident to its Kubernetes tenant without threading the event through
    // every detector emit site. Request-scoped, overwritten each event. (spec 084)
    pub(crate) current_container_id: Option<String>,
    pub(crate) current_pod_uid: Option<String>,
}

fn load_config_for_cli(cli: &Cli) -> Result<config::Config> {
    config::load(&cli.config)
}

async fn run_cli(cli: Cli) -> Result<()> {
    tracing_init::init_tracing()?;
    let cfg = load_config_for_cli(&cli)?;
    sensor::run(cfg).await
}

/// Number of tokio worker threads to size the runtime with, given the detected
/// CPU parallelism (`None` if undetectable). A FLOOR of 4 is applied instead of
/// the `#[tokio::main]` num_cpus default: a few collectors (AF_PACKET dns/http
/// capture) do blocking `recv` loops on the runtime, and on a 2-vCPU cloud VM the
/// default 2 workers were BOTH consumed by those blocking calls, starving the
/// eBPF ring-drain task so kernel events were captured in-ring but never read to
/// userspace (observed on Azure k7.0, 2 vCPU: kprobes fired, ring filled, 0
/// events surfaced). The floor keeps spare workers; larger hosts still scale up.
fn sensor_worker_threads(available: Option<usize>) -> usize {
    available.unwrap_or(2).max(4)
}

fn main() -> Result<()> {
    let workers = sensor_worker_threads(std::thread::available_parallelism().ok().map(|n| n.get()));
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?
        .block_on(async { run_cli(Cli::parse()).await })
}

// 11 small helpers (load_blocked_ips, state_path_for, blocked_ips_path_for,
// parse_blocked_ips, should_spawn_integrity_collector, should_enable_syslog_sink,
// parse_syslog_port, choose_syslog_protocol, severity_rank, is_passthrough_source,
// should_use_blocked_ip_hint) moved to crates/sensor/src/main_helpers.rs as part
// of the 2026-05-25 main.rs decomposition PR2. The previous `/// Load blocked
// IPs from the file written by the agent.` doc comment moved with `load_blocked_ips`
// — its body is in main_helpers.rs.

// apply_seccomp_profile + bpf_stmt + bpf_jump + syscall_name_to_nr
// moved to crates/sensor/src/seccomp.rs as part of the 2026-05-25
// main.rs decomposition PR3. The whole module is Linux-gated and
// carries byte-level anchor tests for the `struct sock_filter`
// packing that ARE the seccomp policy.

#[cfg(test)]
mod tests {
    use super::*;

    // (parse_blocked_ips / helper_paths_resolve_inside_data_dir /
    //  should_spawn_integrity_collector / parse_syslog_port /
    //  choose_syslog_protocol / severity_rank anchors moved to
    //  crates/sensor/src/main_helpers.rs as part of the 2026-05-25
    //  main.rs decomposition PR2.)

    // (6 incident-builder anchors moved to
    //  crates/sensor/src/incident_builders.rs as part of the 2026-05-25
    //  main.rs decomposition PR4 — page_cache_mismatch_event_promotes_to_critical_incident,
    //  devnode_exposed_event_promotes_to_medium_incident, and the four
    //  build_devnode_watchlist_* tests.)

    // (passthrough_sources_are_disabled_by_default moved to main_helpers.rs
    //  as `is_passthrough_source_returns_false_for_all_known_sources` — same
    //  contract, broader source coverage.)

    #[test]
    fn sensor_worker_threads_applies_a_floor_of_four() {
        // Below the floor (incl. the 2-vCPU Azure case that starved the drain) is
        // raised to 4 so blocking capture collectors can't consume every worker.
        assert_eq!(sensor_worker_threads(Some(1)), 4);
        assert_eq!(sensor_worker_threads(Some(2)), 4);
        assert_eq!(sensor_worker_threads(Some(4)), 4);
        // Larger hosts still scale up with their CPU count.
        assert_eq!(sensor_worker_threads(Some(8)), 8);
        assert_eq!(sensor_worker_threads(Some(64)), 64);
        // Undetectable parallelism falls back to the floor, never below.
        assert_eq!(sensor_worker_threads(None), 4);
    }

    #[test]
    fn cli_parses_default_and_custom_config_path() {
        let default_cli =
            Cli::try_parse_from(["innerwarden-sensor"]).expect("default CLI should parse");
        assert_eq!(default_cli.config, "config.toml");

        let custom_cli = Cli::try_parse_from([
            "innerwarden-sensor",
            "--config",
            "/etc/innerwarden/sensor.toml",
        ])
        .expect("custom config CLI should parse");
        assert_eq!(custom_cli.config, "/etc/innerwarden/sensor.toml");
    }

    #[test]
    fn load_config_for_cli_reads_the_selected_config_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_path = tmp.path().join("sensor.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[agent]
host_id = "main-test-host"

[output]
data_dir = "{}"
"#,
                tmp.path().display()
            ),
        )
        .expect("write config");
        let cli = Cli {
            config: config_path.to_string_lossy().into_owned(),
        };

        let cfg = load_config_for_cli(&cli).expect("config should load");

        assert_eq!(cfg.agent.host_id, "main-test-host");
        assert_eq!(cfg.output.data_dir, tmp.path().to_string_lossy());
    }

    #[tokio::test]
    async fn run_cli_with_all_collectors_disabled_returns_cleanly() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let datasets_dir = tmp.path().join("datasets");
        std::fs::create_dir_all(&datasets_dir).expect("mkdir datasets");
        std::fs::write(datasets_dir.join("feodo-ips.txt"), "203.0.113.1\n").expect("seed datasets");
        let config_path = tmp.path().join("sensor.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"
[agent]
host_id = "main-test-host"

[output]
data_dir = "{}"
write_events = true

[event_pipeline]
enabled = false

[collectors.auth_log]
enabled = false

[collectors.integrity]
enabled = false

[collectors.journald]
enabled = false

[collectors.docker]
enabled = false

[collectors.exec_audit]
enabled = false

[collectors.nginx_access]
enabled = false

[collectors.nginx_error]
enabled = false

[collectors.macos_log]
enabled = false

[collectors.syslog_firewall]
enabled = false

[collectors.cloudtrail]
enabled = false

[collectors.ebpf_syscall]
enabled = false

[collectors.firmware_integrity]
enabled = false

[collectors.proc_maps]
enabled = false

[collectors.fanotify_watch]
enabled = false

[collectors.kernel_integrity]
enabled = false

[collectors.cgroup_abuse]
enabled = false

[collectors.dns_capture]
enabled = false

[collectors.http_capture]
enabled = false

[collectors.net_snapshot]
enabled = false

[collectors.usb_monitor]
enabled = false

[collectors.suid_inventory]
enabled = false

[collectors.sysctl_drift]
enabled = false

[collectors.systemd_inventory]
enabled = false

[collectors.tcp_stream]
enabled = false

[collectors.audit_state]
enabled = false

[collectors.tunnel_iface]
enabled = false

[detectors.suid_page_cache_integrity]
enabled = false

[detectors.kernel_devnode_exposed]
enabled = false
"#,
                tmp.path().display()
            ),
        )
        .expect("write config");
        let cli = Cli {
            config: config_path.to_string_lossy().into_owned(),
        };

        tokio::time::timeout(std::time::Duration::from_secs(10), run_cli(cli))
            .await
            .expect("run_cli timed out")
            .expect("run_cli should return Ok");

        assert!(tmp.path().join("state.json").exists());
    }

    // (5 helper unit tests moved to main_helpers.rs as part of PR2:
    //  parse_blocked_ips_deduplicates_and_keeps_comment_lines_as_tokens,
    //  load_blocked_ips_returns_empty_for_missing_feedback_file,
    //  load_blocked_ips_reads_agent_feedback_file,
    //  should_enable_syslog_sink_requires_non_empty_host,
    //  parse_syslog_port_rejects_out_of_range_values.)

    // ── Wave 9f anchors (2026-05-04) — journald-detection contract ───────
    //
    // AUDIT-009 root: tracing-subscriber writes plain text to stdout which
    // journald captures with no `PRIORITY=` field. `journalctl -p warning`
    // then silently drops every WARN this crate emits. The fix routes
    // tracing through `tracing-journald` when the binary runs under
    // systemd (detected via JOURNAL_STREAM env var). These anchors pin
    // the detection logic so a future refactor that breaks the env-var
    // contract is caught at test time rather than by the operator one
    // morning when their `journalctl -p warning` query goes silent.

    // (use_journald_layer anchors moved to crates/sensor/src/tracing_init.rs
    //  as part of the 2026-05-25 main.rs decomposition PR1.)

    // (blocked_ip_hint_returns_true_but_does_not_imply_skip + its 2026-05-23
    //  early-return-removal anchor moved to crates/sensor/src/event_dispatch.rs
    //  as part of the 2026-05-25 main.rs decomposition PR5a, alongside
    //  process_event itself. The `include_str!` source-grep target moved
    //  with it from "main.rs" to "event_dispatch.rs".)

    // (build_tracing_env_filter anchor moved to crates/sensor/src/tracing_init.rs
    //  as part of the 2026-05-25 main.rs decomposition PR1.)
}
