//! Spawn every enabled collector + polling-detector as a tokio task.
//!
//! Extracted from `main.rs` on 2026-05-25 as PR5b2 of the main.rs
//! decomposition (see SESSION_LOG.md). Pure code motion — zero
//! behaviour change. ~411 LoC moved.
//!
//! ## Why this is grouped together
//!
//! Phase G of the pre-decomposition `async fn main` was a long
//! sequence of `if cfg.collectors.X.enabled { tokio::spawn(...) }`
//! blocks plus two `if cfg.detectors.Y.enabled { tokio::spawn(...) }`
//! blocks for the polling detectors (`suid_page_cache_integrity` and
//! `kernel_devnode_exposed`) that run as their own tasks rather than
//! per-event handlers. The whole thing reads cursors from `State`,
//! clones the `tx: mpsc::Sender` per task, and updates the shared
//! `Arc<AtomicU64>` / `Arc<Mutex<...>>` cursors as it goes. Once
//! every task is spawned, the original `tx` is dropped so the consumer
//! side's `rx.recv()` returns `None` once every collector task exits.
//!
//! ## Why this is the second-hardest piece of `async fn main` to extract
//!
//! `spawn_collectors` takes 12 parameters because it has to thread
//! every shared cursor through to the per-collector tokio::spawn
//! closures. A future PR could bundle those into a `SharedCursors`
//! struct, but introducing that abstraction inside a pure-code-motion
//! PR would muddy the diff. The next refactor pass (after PR5b3
//! lands) is the right time to consolidate.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use innerwarden_core::event::Event;
use tokio::sync::mpsc;
use tracing::info;

use crate::boot::cursors::SharedCursors;
use crate::collectors;
use crate::collectors::{
    auth_log::AuthLogCollector, cloudtrail::CloudTrailCollector, docker::DockerCollector,
    exec_audit::ExecAuditCollector, integrity::IntegrityCollector, journald::JournaldCollector,
    macos_log::MacosLogCollector, nginx_access::NginxAccessCollector,
    nginx_error::NginxErrorCollector, syslog_firewall::SyslogFirewallCollector,
    windows_etw::WindowsEtwCollector,
};
use crate::config::Config;
use crate::detectors;
use crate::incident_builders::build_devnode_watchlist;
use crate::main_helpers::should_spawn_integrity_collector;
use crate::sinks::state::State;

/// Spawn every enabled collector + every polling detector as its own
/// tokio task. Each collector clones `tx` so when all tasks exit the
/// consumer's `rx.recv()` returns `None`. Drops the original `tx`
/// after spawning so the consumer side does NOT keep a sender alive
/// indefinitely (any leftover would block shutdown forever).
///
/// InnerWarden's own config files, always integrity-monitored regardless of
/// user config. The prefix is platform-specific: `/etc/innerwarden` on Linux,
/// `/usr/local/etc/innerwarden` on macOS (where the installer writes them). The
/// old hardcoded `/etc/innerwarden/*` list produced `cannot hash file: No such
/// file` warnings on every macOS boot and monitored nothing real there (F8).
pub(crate) fn self_monitor_config_paths() -> [&'static str; 3] {
    self_monitor_config_paths_for(cfg!(target_os = "macos"))
}

/// Pure inner (tested for both platforms on the Linux CI host).
pub(crate) fn self_monitor_config_paths_for(mac: bool) -> [&'static str; 3] {
    if mac {
        [
            "/usr/local/etc/innerwarden/config.toml",
            "/usr/local/etc/innerwarden/agent.toml",
            "/usr/local/etc/innerwarden/agent.env",
        ]
    } else {
        [
            "/etc/innerwarden/config.toml",
            "/etc/innerwarden/agent.toml",
            "/etc/innerwarden/agent.env",
        ]
    }
}

/// 2026-05-25 (PR-F2): signature collapsed from 12 params to 5 by
/// taking `&SharedCursors` instead of 8 individual cursor Arcs. The
/// `shared_X` locals destructured below preserve the original body
/// verbatim — pure mechanical refactor, zero behaviour change.
pub(crate) fn spawn_collectors(
    cfg: &Config,
    _data_dir: &Path, // reserved for future per-collector data-dir routing
    state: &State,
    tx: mpsc::Sender<Event>,
    ebpf_tx: crate::event_channels::EbpfTx,
    cursors: &SharedCursors,
) {
    let SharedCursors {
        auth_offset: shared_auth_offset,
        integrity_hashes: shared_integrity_hashes,
        journald_cursor: shared_journald_cursor,
        docker_since: shared_docker_since,
        exec_audit_offset: shared_exec_audit_offset,
        nginx_offset: shared_nginx_offset,
        nginx_error_offset: shared_nginx_error_offset,
        syslog_firewall_offset: shared_syslog_firewall_offset,
    } = cursors.clone();
    // Spawn auth_log collector
    if cfg.collectors.auth_log.enabled {
        let offset = state
            .get_cursor("auth_log")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_auth_offset.store(offset, Ordering::Relaxed);

        let collector =
            AuthLogCollector::new(&cfg.collectors.auth_log.path, &cfg.agent.host_id, offset);
        info!(path = %cfg.collectors.auth_log.path, offset, "starting auth_log collector");
        let tx2 = tx.clone();
        let shared = Arc::clone(&shared_auth_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx2, shared).await {
                tracing::error!("auth_log collector error: {e:#}");
            }
        });
    }

    // Spawn integrity collector
    if should_spawn_integrity_collector(
        cfg.collectors.integrity.enabled,
        &cfg.collectors.integrity.paths,
    ) {
        let ic = &cfg.collectors.integrity;
        let known_hashes: HashMap<String, String> = state
            .get_cursor("integrity")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        // Seed shared hashes with whatever we loaded from state
        *shared_integrity_hashes.lock().unwrap() = known_hashes.clone();

        // Always monitor Inner Warden's own config files for tampering,
        // regardless of user configuration (platform-aware prefix — F8).
        let self_monitor_paths = self_monitor_config_paths();
        let mut all_paths: Vec<std::path::PathBuf> =
            ic.paths.iter().map(|p| Path::new(p).to_owned()).collect();
        for sp in &self_monitor_paths {
            let p = Path::new(sp).to_owned();
            if !all_paths.contains(&p) {
                all_paths.push(p);
            }
        }

        let collector = IntegrityCollector::new(
            all_paths.clone(),
            &cfg.agent.host_id,
            ic.poll_seconds,
            known_hashes,
        );
        info!(
            paths = all_paths.len(),
            poll_secs = ic.poll_seconds,
            "starting integrity collector (includes self-monitoring)"
        );
        let tx3 = tx.clone();
        let shared = Arc::clone(&shared_integrity_hashes);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx3, shared).await {
                tracing::error!("integrity collector error: {e:#}");
            }
        });
    }

    // Spawn journald collector
    if cfg.collectors.journald.enabled {
        let jc = &cfg.collectors.journald;
        let cursor: Option<String> = state
            .get_cursor("journald")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        *shared_journald_cursor.lock().unwrap() = cursor.clone();
        let collector = JournaldCollector::new(&cfg.agent.host_id, jc.units.clone(), cursor);
        info!(units = ?jc.units, "starting journald collector");
        let tx4 = tx.clone();
        let shared = Arc::clone(&shared_journald_cursor);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx4, shared).await {
                tracing::error!("journald collector error: {e:#}");
            }
        });
    }

    // Spawn docker collector
    if cfg.collectors.docker.enabled {
        let since: Option<String> = state
            .get_cursor("docker")
            .and_then(|v| v.as_str().map(str::to_string));
        *shared_docker_since.lock().unwrap() = since.clone();
        let collector = DockerCollector::new(&cfg.agent.host_id, since);
        info!("starting docker collector");
        let tx5 = tx.clone();
        let shared = Arc::clone(&shared_docker_since);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx5, shared).await {
                tracing::error!("docker collector error: {e:#}");
            }
        });
    }

    // Spawn exec_audit collector
    if cfg.collectors.exec_audit.enabled {
        let ec = &cfg.collectors.exec_audit;
        let offset = state
            .get_cursor("exec_audit")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_exec_audit_offset.store(offset, Ordering::Relaxed);
        let collector =
            ExecAuditCollector::new(&ec.path, &cfg.agent.host_id, offset, ec.include_tty);
        info!(
            path = %ec.path,
            include_tty = ec.include_tty,
            offset,
            "starting exec_audit collector"
        );
        let tx6 = tx.clone();
        let shared = Arc::clone(&shared_exec_audit_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx6, shared).await {
                tracing::error!("exec_audit collector error: {e:#}");
            }
        });
    }

    // Spawn nginx_access collector
    if cfg.collectors.nginx_access.enabled {
        let nc = &cfg.collectors.nginx_access;
        let offset = state
            .get_cursor("nginx_access")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_nginx_offset.store(offset, Ordering::Relaxed);
        let collector = NginxAccessCollector::new(&nc.path, &cfg.agent.host_id, offset);
        info!(path = %nc.path, offset, "starting nginx_access collector");
        let tx7 = tx.clone();
        let shared = Arc::clone(&shared_nginx_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx7, shared).await {
                tracing::error!("nginx_access collector error: {e:#}");
            }
        });
    }

    // Spawn nginx_error collector
    if cfg.collectors.nginx_error.enabled {
        let nec = &cfg.collectors.nginx_error;
        let offset = state
            .get_cursor("nginx_error")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_nginx_error_offset.store(offset, Ordering::Relaxed);
        let collector = NginxErrorCollector::new(&nec.path, &cfg.agent.host_id, offset);
        info!(path = %nec.path, offset, "starting nginx_error collector");
        let tx_nginx_error = tx.clone();
        let shared = Arc::clone(&shared_nginx_error_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_nginx_error, shared).await {
                tracing::error!("nginx_error collector error: {e:#}");
            }
        });
    }

    // Spawn macos_log collector
    if cfg.collectors.macos_log.enabled {
        let collector = MacosLogCollector::new(&cfg.agent.host_id);
        info!("starting macos_log collector");
        let tx_macos = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_macos).await {
                tracing::error!("macos_log collector error: {e:#}");
            }
        });
    }

    // Spawn windows_etw collector (spec 085). Belt-and-suspenders: gated on
    // BOTH `cfg!(target_os = "windows")` (the collector only does useful work
    // there; its `wevtutil` probe fails open elsewhere) AND the opt-in config
    // flag. The `cfg!` macro is a runtime bool (same idiom as line ~64), so
    // the block still COMPILES on every platform - keeping `WindowsEtwCollector`
    // referenced (no dead-code) - while only ever SPAWNING on Windows.
    if cfg!(target_os = "windows") && cfg.collectors.windows_etw.enabled {
        let wc = &cfg.collectors.windows_etw;
        let collector = WindowsEtwCollector::new(&cfg.agent.host_id)
            .with_channels(wc.channels.clone())
            .with_poll_seconds(wc.poll_seconds)
            .with_batch_cap(wc.batch_cap);
        info!(channels = ?wc.channels, "starting windows_etw collector");
        let tx_etw = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_etw).await {
                tracing::error!("windows_etw collector error: {e:#}");
            }
        });
    }

    // Spawn syslog_firewall collector
    if cfg.collectors.syslog_firewall.enabled {
        let sc = &cfg.collectors.syslog_firewall;
        let offset = state
            .get_cursor("syslog_firewall")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        shared_syslog_firewall_offset.store(offset, Ordering::Relaxed);
        let collector = SyslogFirewallCollector::new(&sc.path, &cfg.agent.host_id, offset);
        info!(path = %sc.path, offset, "starting syslog_firewall collector");
        let tx_syslog = tx.clone();
        let shared = Arc::clone(&shared_syslog_firewall_offset);
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_syslog, shared).await {
                tracing::error!("syslog_firewall collector error: {e:#}");
            }
        });
    }

    // Spawn cloudtrail collector
    if cfg.collectors.cloudtrail.enabled {
        let cc = &cfg.collectors.cloudtrail;
        let collector = CloudTrailCollector::new(&cc.dir, &cfg.agent.host_id);
        info!(dir = %cc.dir, "starting cloudtrail collector");
        let tx_cloudtrail = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = collector.run(tx_cloudtrail).await {
                tracing::error!("cloudtrail collector error: {e:#}");
            }
        });
    }

    // Spawn eBPF collector (optional - requires Linux 5.8+, CAP_BPF).
    // The ring reader is the flood source, so it gets the non-blocking
    // multi-lane `ebpf_tx` (spec 069 follow-up #1, Option C) rather than the
    // plain bulk Sender. When disabled, `ebpf_tx` simply drops here, closing
    // the prio/emergency lanes while the bulk lane stays open for file
    // collectors.
    if cfg.collectors.ebpf_syscall.enabled {
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::ebpf_syscall::run(ebpf_tx, host_id).await;
        });
    } else {
        drop(ebpf_tx);
    }

    // Spawn firmware integrity collector (monitors ESP, UEFI vars, ACPI, DMI, tainted)
    if cfg.collectors.firmware_integrity.enabled {
        let tx_firmware = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::firmware_integrity::run(tx_firmware, host_id).await;
        });
    }

    // Spawn proc_maps collector (memory forensics: RWX, deleted files, LD_PRELOAD)
    if cfg.collectors.proc_maps.enabled {
        let tx_maps = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::proc_maps::run(tx_maps, host_id, 60).await;
        });
    }

    // Spawn fanotify filesystem monitor (real-time file modification + ransomware detection)
    if cfg.collectors.fanotify_watch.enabled {
        let tx_fan = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        let watch_paths = cfg
            .collectors
            .integrity
            .paths
            .iter()
            .map(|p| p.to_string())
            .collect();
        tokio::spawn(async move {
            collectors::fanotify_watch::run(tx_fan, host_id, watch_paths, 5).await;
        });
    }

    // Spawn kernel integrity monitor (syscall table + eBPF inventory + module baseline)
    if cfg.collectors.kernel_integrity.enabled {
        let tx_kern = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::kernel_integrity::run(tx_kern, host_id, 120).await;
        });
    }

    // Spawn cgroup resource abuse detector (CPU/memory abuse, cryptominer detection)
    if cfg.collectors.cgroup_abuse.enabled {
        let tx_cg = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            detectors::cgroup_abuse::run(tx_cg, host_id, 30).await;
        });
    }

    // Spawn TLS fingerprint collector (JA3/JA4 — requires CAP_NET_RAW + libc).
    // No config gate yet — feature flag is the only off-switch. If we
    // want this in test_default-quiet mode, add an AlwaysOnCollectorConfig
    // here too. Today the feature is off in test builds, so it doesn't
    // spawn during cargo test regardless.
    #[cfg(feature = "ebpf")]
    {
        let tx_tls = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::tls_fingerprint::run(tx_tls, host_id, 0).await;
        });
    }

    // DNS query capture (AF_PACKET raw socket, captures UDP:53)
    if cfg.collectors.dns_capture.enabled {
        let tx_dns = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::dns_capture::run(tx_dns, host_id).await;
        });
    }

    // HTTP request capture (AF_PACKET raw socket, captures TCP:80/8080/8787/etc.)
    if cfg.collectors.http_capture.enabled {
        let tx_http = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::http_capture::run(tx_http, host_id).await;
        });
    }

    // Network snapshot: periodic /proc/net/tcp scan with PID resolution
    if cfg.collectors.net_snapshot.enabled {
        let tx_net = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::net_snapshot::run(tx_net, host_id, 30).await;
        });
    }

    // USB device monitoring: detects BadUSB, rubber ducky, unauthorized storage
    if cfg.collectors.usb_monitor.enabled {
        let tx_usb = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::usb_monitor::run(tx_usb, host_id, 5).await;
        });
    }

    // SUID binary inventory: baseline + drift detection
    if cfg.collectors.suid_inventory.enabled {
        let tx_suid = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::suid_inventory::run(tx_suid, host_id, 300).await;
        });
    }

    // Sysctl drift: monitors 20 security-critical kernel parameters
    if cfg.collectors.sysctl_drift.enabled {
        let tx_sysctl = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::sysctl_drift::run(tx_sysctl, host_id, 60).await;
        });
    }

    // audit_state (spec 074): polls the kernel audit `enabled` flag every 60s
    // and emits `audit.disabled` when it is found off — method-independent,
    // unlike the command-watching auditd_disable detector routes.
    if cfg.collectors.audit_state.enabled {
        let tx_audit_state = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::audit_state::run(tx_audit_state, host_id, 60).await;
        });
    }

    // tunnel_iface: behavioural mesh/overlay-VPN persistence detection — watches
    // for a NEW tun/WireGuard interface appearing at runtime (rename-proof,
    // complements the c2_web_tunnel exec-name detector). Baselines startup
    // interfaces; 30s poll.
    if cfg.collectors.tunnel_iface.enabled {
        let tx_tunnel = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::tunnel_iface::run(tx_tunnel, host_id, 30).await;
        });
    }

    // SUID page-cache integrity: detects Copy Fail / Dirty Frag / Fragnesia-style
    // page-cache poisoning by comparing cached reads with direct-I/O disk reads.
    if cfg.detectors.suid_page_cache_integrity.enabled {
        let d = &cfg.detectors.suid_page_cache_integrity;
        let tx_suid_cache = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        let allowlist: Vec<PathBuf> = d.allowlist.iter().map(PathBuf::from).collect();
        let poll_interval_secs = d.poll_interval_secs;
        info!(
            paths = allowlist.len(),
            poll_interval_secs, "starting suid_page_cache_integrity detector"
        );
        tokio::spawn(async move {
            detectors::suid_page_cache_integrity::run(
                tx_suid_cache,
                host_id,
                poll_interval_secs,
                allowlist,
            )
            .await;
        });
    }

    // Kernel devnode exposure: catches sensitive /dev/* nodes whose
    // permissions are more permissive than the documented safe-default.
    // Motivated by Azure mana_ib shipping `/dev/infiniband/uverbs*` mode
    // 0666 by default — see crates/sensor/src/detectors/kernel_devnode_exposed.rs
    // for the full architectural reasoning.
    if cfg.detectors.kernel_devnode_exposed.enabled {
        let d = &cfg.detectors.kernel_devnode_exposed;
        let tx_devnode = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        let poll_interval_secs = d.poll_interval_secs;
        let allowlist = d.allowlist.clone();
        let watchlist = build_devnode_watchlist(&d.overrides);
        info!(
            patterns = watchlist.len(),
            poll_interval_secs, "starting kernel_devnode_exposed detector"
        );
        tokio::spawn(async move {
            detectors::kernel_devnode_exposed::run(
                tx_devnode,
                host_id,
                poll_interval_secs,
                watchlist,
                allowlist,
            )
            .await;
        });
    }

    // Systemd unit inventory: detects new/suspicious services
    if cfg.collectors.systemd_inventory.enabled {
        let tx_sysd = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::systemd_inventory::run(tx_sysd, host_id, 300).await;
        });
    }

    // TCP stream reassembly engine (AF_PACKET, all TCP traffic)
    // Reassembles bidirectional streams, detects protocols on any port,
    // enables deep packet inspection for HTTP, SSH, SMB, etc.
    if cfg.collectors.tcp_stream.enabled {
        let tx_tcp = tx.clone();
        let host_id = cfg.agent.host_id.clone();
        tokio::spawn(async move {
            collectors::tcp_stream::run(tx_tcp, host_id).await;
        });
    }

    // Drop the original tx - each collector holds its own clone.
    // When all collector tasks finish, all senders drop and rx.recv() returns None.
    drop(tx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// F8 anchor (2026-07-01): the self-monitored config paths follow the
    /// platform install prefix, so macOS watches the real `/usr/local/etc`
    /// files instead of nonexistent `/etc/innerwarden/*`.
    #[test]
    fn self_monitor_config_paths_are_platform_prefixed() {
        let paths = self_monitor_config_paths();
        let want_prefix = if cfg!(target_os = "macos") {
            "/usr/local/etc/innerwarden/"
        } else {
            "/etc/innerwarden/"
        };
        assert!(paths.iter().all(|p| p.starts_with(want_prefix)));
        assert!(paths.iter().any(|p| p.ends_with("config.toml")));
        assert!(paths.iter().any(|p| p.ends_with("agent.toml")));
        assert!(paths.iter().any(|p| p.ends_with("agent.env")));
    }

    #[test]
    fn self_monitor_config_paths_for_both_platforms() {
        assert!(self_monitor_config_paths_for(true)
            .iter()
            .all(|p| p.starts_with("/usr/local/etc/innerwarden/")));
        assert!(self_monitor_config_paths_for(false)
            .iter()
            .all(|p| p.starts_with("/etc/innerwarden/")));
    }

    fn write_temp_file(dir: &std::path::Path, name: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, "seed\n").expect("write temp file");
        path.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn spawn_collectors_all_disabled_closes_the_channel() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = Config::test_default();
        let state = State::default();
        let cursors = SharedCursors::new();
        let (tx, mut rx) = mpsc::channel(1);
        let (ebpf_tx, _erx, _ctr) = crate::event_channels::channels();

        spawn_collectors(&cfg, tmp.path(), &state, tx, ebpf_tx, &cursors);

        assert!(
            rx.recv().await.is_none(),
            "with every collector disabled, dropping the original sender should close rx"
        );
    }

    #[tokio::test]
    async fn spawn_collectors_seeds_resume_cursors_for_enabled_collectors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut cfg = Config::test_default();
        cfg.agent.host_id = "spawn-test-host".to_string();
        cfg.collectors.auth_log.enabled = true;
        cfg.collectors.auth_log.path = write_temp_file(tmp.path(), "auth.log");
        cfg.collectors.integrity.enabled = true;
        cfg.collectors.integrity.paths = vec![write_temp_file(tmp.path(), "watched.conf")];
        cfg.collectors.journald.enabled = true;
        cfg.collectors.docker.enabled = true;
        cfg.collectors.exec_audit.enabled = true;
        cfg.collectors.exec_audit.path = write_temp_file(tmp.path(), "exec.log");
        cfg.collectors.nginx_access.enabled = true;
        cfg.collectors.nginx_access.path = write_temp_file(tmp.path(), "access.log");
        cfg.collectors.nginx_error.enabled = true;
        cfg.collectors.nginx_error.path = write_temp_file(tmp.path(), "error.log");
        cfg.collectors.macos_log.enabled = true;
        cfg.collectors.syslog_firewall.enabled = true;
        cfg.collectors.syslog_firewall.path = write_temp_file(tmp.path(), "syslog.log");
        cfg.collectors.cloudtrail.enabled = true;
        cfg.collectors.cloudtrail.dir =
            tmp.path().join("cloudtrail").to_string_lossy().into_owned();
        cfg.collectors.ebpf_syscall.enabled = true;
        cfg.collectors.firmware_integrity.enabled = true;
        cfg.collectors.proc_maps.enabled = true;
        cfg.collectors.fanotify_watch.enabled = true;
        cfg.collectors.kernel_integrity.enabled = true;
        cfg.collectors.cgroup_abuse.enabled = true;
        cfg.collectors.dns_capture.enabled = true;
        cfg.collectors.http_capture.enabled = true;
        cfg.collectors.net_snapshot.enabled = true;
        cfg.collectors.usb_monitor.enabled = true;
        cfg.collectors.suid_inventory.enabled = true;
        cfg.collectors.sysctl_drift.enabled = true;
        cfg.collectors.systemd_inventory.enabled = true;
        cfg.collectors.tcp_stream.enabled = true;
        cfg.collectors.tunnel_iface.enabled = true;
        cfg.detectors.suid_page_cache_integrity.enabled = true;
        cfg.detectors.kernel_devnode_exposed.enabled = true;

        let mut state = State::default();
        state.set_cursor("auth_log", serde_json::json!(17));
        state.set_cursor(
            "integrity",
            serde_json::json!({"/etc/innerwarden/config.toml": "hash-a"}),
        );
        state.set_cursor("journald", serde_json::json!("s=journal-cursor"));
        state.set_cursor("docker", serde_json::json!("2026-05-28T00:00:00Z"));
        state.set_cursor("exec_audit", serde_json::json!(23));
        state.set_cursor("nginx_access", serde_json::json!(31));
        state.set_cursor("nginx_error", serde_json::json!(37));
        state.set_cursor("syslog_firewall", serde_json::json!(41));

        let cursors = SharedCursors::new();
        let (tx, _rx) = mpsc::channel(32);
        let (ebpf_tx, _erx, _ctr) = crate::event_channels::channels();

        spawn_collectors(&cfg, tmp.path(), &state, tx, ebpf_tx, &cursors);

        assert_eq!(cursors.auth_offset.load(Ordering::Relaxed), 17);
        assert_eq!(cursors.exec_audit_offset.load(Ordering::Relaxed), 23);
        assert_eq!(cursors.nginx_offset.load(Ordering::Relaxed), 31);
        assert_eq!(cursors.nginx_error_offset.load(Ordering::Relaxed), 37);
        assert_eq!(cursors.syslog_firewall_offset.load(Ordering::Relaxed), 41);
        assert_eq!(
            cursors.journald_cursor.lock().unwrap().as_deref(),
            Some("s=journal-cursor")
        );
        assert_eq!(
            cursors.docker_since.lock().unwrap().as_deref(),
            Some("2026-05-28T00:00:00Z")
        );
        assert_eq!(
            cursors
                .integrity_hashes
                .lock()
                .unwrap()
                .get("/etc/innerwarden/config.toml")
                .map(String::as_str),
            Some("hash-a")
        );
    }
}
