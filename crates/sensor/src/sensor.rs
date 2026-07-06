//! Sensor top-level orchestration extracted from `async fn main`.
//!
//! Created 2026-05-25 as PR-F3 of the test-foundations series. Before
//! this PR `async fn main` held the entire boot+run pipeline inline,
//! which made integration testing impossible (the only way to exercise
//! the boot sequence was to spawn the real binary in a subprocess).
//!
//! After this PR:
//!
//! - `main.rs::async fn main` is ~10 lines: init tracing, parse CLI,
//!   load config, call `sensor::run(cfg).await`. That's it.
//! - This module owns the full orchestration: state load, sinks,
//!   channel + cursor setup, DetectorSet construction, threat
//!   datasets, collector spawn, collector-health snapshot, optional
//!   seccomp gate, event loop, shutdown persistence.
//! - Integration tests can call `run(Config::test_default())` and
//!   assert end-to-end behaviour (sinks created, state file written,
//!   collector-health.json written, run returns cleanly when no
//!   collectors are enabled).

use std::path::{Path, PathBuf};

use anyhow::Result;
use innerwarden_core::event::Event;
use tokio::sync::mpsc;
use tracing::info;
#[cfg(target_os = "linux")]
use tracing::warn;

use crate::boot;
use crate::boot::cursors::SharedCursors;
use crate::collector_health;
use crate::config::Config;
use crate::detector_set::DetectorSet;
use crate::detectors;
use crate::detectors::datasets::Datasets;
use crate::main_helpers::{
    choose_syslog_protocol, parse_syslog_port, should_enable_syslog_sink, state_path_for,
};
#[cfg(target_os = "linux")]
use crate::seccomp;
use crate::sinks::{self, sqlite::SqliteWriter, state::State};

/// Container for every piece of boot-time state. Returned by
/// [`boot_init`] and consumed by [`run_loop`].
///
/// 2026-05-26 (follow-up #1): introduced to make the boot pipeline
/// testable. The pre-PR shape `async fn run(cfg)` was end-to-end
/// untestable because [`boot::spawn_collectors`] starts a handful of
/// always-on tokio tasks (eBPF syscall, firmware_integrity, proc_maps,
/// fanotify_watch, kernel_integrity, …) that hold clones of `tx`
/// alive forever — so `rx.recv()` in [`boot::event_loop::run_event_loop`]
/// never returns `None` and the function never exits without a
/// signal. Splitting into `boot_init` (no tokio spawn) + `run_loop`
/// (the spawn + loop) lets integration tests assert "boot succeeded,
/// sinks were created, collector-health snapshot was written" without
/// having to drive the consumer side to completion.
pub(crate) struct SensorContext {
    cfg: Config,
    data_dir: PathBuf,
    state_path: PathBuf,
    state: State,
    sqlite_writer: SqliteWriter,
    syslog_writer: Option<sinks::syslog_cef::SyslogCefWriter>,
    // Spec 069 follow-up #1: three-lane channels (Option C). `bulk_tx` is
    // the plain bulk Sender handed to the low-rate file collectors; `ebpf_tx`
    // is the non-blocking multi-lane handle for the eBPF ring reader (the
    // flood source); `event_rx` is the biased prio→emergency→bulk drain.
    ebpf_tx: crate::event_channels::EbpfTx,
    bulk_tx: mpsc::Sender<Event>,
    event_rx: crate::event_channels::EventRx,
    drop_counters: std::sync::Arc<crate::event_channels::DropCounters>,
    cursors: SharedCursors,
    detectors: DetectorSet,
    threat_datasets: Datasets,
    #[cfg(unix)]
    sigterm: tokio::signal::unix::Signal,
}

/// Run the sensor pipeline end-to-end. Thin wrapper: boot + loop.
/// Returns when the event loop exits — either because every collector
/// task dropped its sender (channel close) or because SIGINT / SIGTERM
/// fired.
pub(crate) async fn run(cfg: Config) -> Result<()> {
    let ctx = boot_init(cfg).await?;
    run_loop(ctx).await
}

/// Run the boot-time half of `run`: load state, construct sinks, build
/// the DetectorSet, load threat datasets, write the collector-health
/// snapshot, set up the SIGTERM listener. Returns a fully-populated
/// [`SensorContext`]. **Does NOT spawn any tokio tasks** — no collector
/// is started yet, so the returned context can be dropped without
/// leaking background work. Used by integration tests to assert boot
/// invariants (sinks exist, collector-health.json written) without
/// driving the consumer side.
pub(crate) async fn boot_init(cfg: Config) -> Result<SensorContext> {
    info!(
        host = %cfg.agent.host_id,
        data_dir = %cfg.output.data_dir,
        "innerwarden-sensor v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    let data_dir: PathBuf = Path::new(&cfg.output.data_dir).to_path_buf();
    let state_path = state_path_for(&data_dir);

    let state = State::load(&state_path)?;
    info!(cursors = state.cursors.len(), "state loaded");

    let write_events = cfg.output.write_events;

    // SQLite is the primary and only event/incident sink.
    let sqlite_writer = SqliteWriter::new(&data_dir, write_events)?;
    info!(path = %data_dir.join("innerwarden.db").display(), "sqlite sink enabled");
    // Optional syslog CEF output (configured via env or future config section)
    let syslog_writer: Option<sinks::syslog_cef::SyslogCefWriter> = {
        let syslog_host = std::env::var("INNERWARDEN_SYSLOG_HOST").unwrap_or_default();
        if !should_enable_syslog_sink(&syslog_host) {
            None
        } else {
            let syslog_port = std::env::var("INNERWARDEN_SYSLOG_PORT").ok();
            let port = parse_syslog_port(syslog_port.as_deref());
            let protocol = choose_syslog_protocol(std::env::var("INNERWARDEN_SYSLOG_TCP").is_ok());
            info!(host = %syslog_host, port, "Syslog CEF output enabled");
            Some(sinks::syslog_cef::SyslogCefWriter::new(
                sinks::syslog_cef::SyslogCefConfig {
                    host: syslog_host,
                    port,
                    protocol,
                },
                env!("CARGO_PKG_VERSION"),
            ))
        }
    };
    // Spec 069 follow-up #1: three-lane channels replace the single
    // mpsc(1024). The eBPF ring reader emits non-blocking through `ebpf_tx`
    // (prio/emergency/bulk); the low-rate file collectors keep their plain
    // blocking `Sender` on the bulk lane via `bulk_tx`.
    let (ebpf_tx, event_rx, drop_counters) = crate::event_channels::channels();
    let bulk_tx = ebpf_tx.bulk_sender();

    // Shared state - updated by collectors, read on shutdown for persistence.
    // Bundled into SharedCursors in PR-F1 (#810); adopted here in PR-F2.
    let cursors = boot::cursors::SharedCursors::new();

    // Initialise process-wide static state (OWN_IPS, TEST_EXTERNAL_IPS,
    // SENSOR_START) BEFORE constructing the DetectorSet. Hoisted out of
    // build_detector_set on 2026-05-28 because the side-effecting init was
    // breaking test isolation across the sensor binary's test suite.
    boot::build_detectors::init_global_static_state_for_production(&data_dir);

    // Build the full DetectorSet (every per-detector cfg.enabled.then(...)
    // block + dynamic allowlist load + blocked-IP feedback file). Moved
    // to crates/sensor/src/boot/build_detectors.rs in PR5b1 (2026-05-25).
    let detectors = boot::build_detectors::build_detector_set(&cfg, &data_dir);

    // Load threat intelligence datasets (IPs, domains, JA3, hashes, URLs).
    // Downloads public feeds on first run, reloads from disk every 60 min.
    let datasets_dir = data_dir.join("datasets");
    let mut threat_datasets = detectors::datasets::Datasets::load(&datasets_dir, 3600);
    if !threat_datasets.is_loaded() {
        info!("downloading threat intelligence feeds for the first time...");
        let (ok, total) = detectors::datasets::update_all_feeds(&datasets_dir);
        info!(
            feeds_updated = ok,
            total_entries = total,
            "initial feed download complete"
        );
        threat_datasets.reload();
    }

    // SIGTERM listener (Unix only). Set up here in boot_init so the
    // Signal handle lives in SensorContext and is plumbed straight into
    // run_event_loop's `tokio::select!`. Pre-split this happened after
    // spawn_collectors; the move is safe — `signal()` only registers a
    // handler with tokio's runtime, it does not depend on any spawned
    // collector being live.
    #[cfg(unix)]
    let sigterm = {
        use tokio::signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate())?
    };

    // PR29 — write the boot-time collector health snapshot. Probes
    // each file-backed collector's source path, records whether the
    // path exists / is stale / is missing, and writes the result to
    // `<data_dir>/collector-health.json` for the agent dashboard to
    // read. Errors are logged and swallowed: a missing health file
    // means the dashboard shows the legacy view (per-collector count
    // only), not a crash.
    {
        let now = chrono::Utc::now();
        let statuses = vec![
            // eBPF is the highest-value telemetry feed (~44 kernel programs
            // + LSM enforcement). It fails OPEN on kernels without BTF / too
            // old / lacking caps, so report its real availability here: the
            // Sensors HUD shows `unsupported` + reason instead of the feed
            // silently appearing healthy while the kernel layer is dark.
            collector_health::build_ebpf_status(
                cfg.collectors.ebpf_syscall.enabled,
                crate::collectors::ebpf_syscall::ebpf_unavailability_reason(),
                crate::collectors::ebpf_syscall::ebpf_progs_attached(),
                now,
            ),
            collector_health::build_status(
                "auth_log",
                cfg.collectors.auth_log.enabled,
                Some(&cfg.collectors.auth_log.path),
                now,
            ),
            collector_health::build_status("journald", cfg.collectors.journald.enabled, None, now),
            collector_health::build_status(
                "exec_audit",
                cfg.collectors.exec_audit.enabled,
                Some(&cfg.collectors.exec_audit.path),
                now,
            ),
            collector_health::build_status("docker", cfg.collectors.docker.enabled, None, now),
            collector_health::build_status(
                "integrity",
                cfg.collectors.integrity.enabled,
                None,
                now,
            ),
            collector_health::build_status(
                "syslog_firewall",
                cfg.collectors.syslog_firewall.enabled,
                Some(&cfg.collectors.syslog_firewall.path),
                now,
            ),
            collector_health::build_status(
                "nginx_access",
                cfg.collectors.nginx_access.enabled,
                Some(&cfg.collectors.nginx_access.path),
                now,
            ),
            collector_health::build_status(
                "nginx_error",
                cfg.collectors.nginx_error.enabled,
                Some(&cfg.collectors.nginx_error.path),
                now,
            ),
            // NOTE: suricata_eve and osquery_log appear in some
            // operator config files but are NOT in the sensor's
            // CollectorsConfig struct. serde silently ignores those
            // keys, so the sensor never spawns them. Don't include
            // them in the probe; they aren't collectors this binary
            // runs. The right operator action is to remove those
            // sections from config.toml (or open a tracking PR to
            // add proper Suricata/Osquery collectors).
        ];
        if let Err(e) =
            collector_health::write_status_file(&data_dir, &cfg.agent.host_id, &statuses)
        {
            tracing::warn!(error = %e, "failed to write collector-health.json");
        } else {
            info!("collector-health.json written ({} entries)", statuses.len());
        }
    }

    Ok(SensorContext {
        cfg,
        data_dir,
        state_path,
        state,
        sqlite_writer,
        syslog_writer,
        ebpf_tx,
        bulk_tx,
        event_rx,
        drop_counters,
        cursors,
        detectors,
        threat_datasets,
        #[cfg(unix)]
        sigterm,
    })
}

/// Run the loop-time half of `run`: spawn every enabled collector,
/// apply the seccomp profile (Linux), then drain the event channel
/// until shutdown. Consumes the [`SensorContext`] produced by
/// [`boot_init`].
///
/// Testable end-to-end via [`run`] with [`Config::test_default`] —
/// every collector defaults to disabled in `Config::test_default`'s
/// [`CollectorsConfig::all_disabled`], so `spawn_collectors` returns
/// after spawning zero tasks, `tx` drops at the bottom of that
/// function, and `rx.recv()` returns `None` on first poll. See
/// `run_*` tests in the `tests` module below.
pub(crate) async fn run_loop(ctx: SensorContext) -> Result<()> {
    let SensorContext {
        cfg,
        data_dir,
        state_path,
        mut state,
        sqlite_writer,
        mut syslog_writer,
        ebpf_tx,
        bulk_tx,
        event_rx,
        drop_counters,
        cursors,
        mut detectors,
        mut threat_datasets,
        #[cfg(unix)]
        sigterm,
    } = ctx;

    // Spawn every enabled collector + polling-detector as a tokio task.
    // Moved to crates/sensor/src/boot/spawn_collectors.rs in PR5b2
    // (2026-05-25). After this returns, the original `tx` has been
    // dropped — only the per-collector clones hold the sender side,
    // so when every collector task exits the consumer's `rx.recv()`
    // returns `None` and the event loop shuts down cleanly.
    boot::spawn_collectors::spawn_collectors(&cfg, &data_dir, &state, bulk_tx, ebpf_tx, &cursors);

    // Apply seccomp profile if configured (Active Defence feature).
    // MUST be after all eBPF programs are loaded and sockets are opened,
    // since seccomp restricts future syscalls. The profile blocks execve,
    // connect, and other syscalls the sensor doesn't need post-startup.
    #[cfg(target_os = "linux")]
    {
        let seccomp_path = data_dir.join("sensor.seccomp.json");
        if seccomp_path.exists() {
            match seccomp::apply_seccomp_profile(&seccomp_path) {
                Ok(count) => info!(
                    syscalls_allowed = count,
                    "seccomp profile applied — sensor hardened"
                ),
                Err(e) => warn!("seccomp profile failed to apply: {e:#} — continuing without"),
            }
        }
    }

    // Main loop + shutdown. Moved to crates/sensor/src/boot/event_loop.rs
    // in PR5b3 (2026-05-25). Drains rx until the channel closes or a
    // signal fires, then snapshots every shared-cursor Arc into the
    // State and writes it to disk.
    boot::event_loop::run_event_loop(
        event_rx,
        drop_counters,
        &sqlite_writer,
        &mut detectors,
        &mut syslog_writer,
        &mut threat_datasets,
        &mut state,
        &state_path,
        #[cfg(unix)]
        sigterm,
        &cursors,
    )
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn seed_datasets(data_dir: &std::path::Path) {
        // is_loaded() returns true if any feed file has at least one
        // non-empty / non-comment line. Skipping the HTTP feed download
        // is essential — without this seed the test would block on
        // `update_all_feeds` trying to reach abuse.ch / Blocklist.de.
        let datasets_dir = data_dir.join("datasets");
        std::fs::create_dir_all(&datasets_dir).expect("mkdir datasets");
        std::fs::write(datasets_dir.join("feodo-ips.txt"), "203.0.113.1\n").expect("seed feodo");
    }

    /// Common test setup: tempdir + Config with every collector/detector
    /// disabled + seeded datasets so the boot path doesn't hit HTTP.
    fn test_cfg(tmp: &tempfile::TempDir) -> Config {
        seed_datasets(tmp.path());
        let mut cfg = Config::test_default();
        cfg.output.data_dir = tmp.path().to_string_lossy().into_owned();
        cfg
    }

    /// Every anchor below wraps the function under test in
    /// `tokio::time::timeout` so a regression that causes the boot
    /// pipeline to hang fails loudly with "timed out after Xs" instead
    /// of stalling the whole `cargo test` run.
    ///
    /// Anchors come in two flavours:
    ///
    /// - **`boot_init_*`** — call `boot_init(cfg).await`, assert the
    ///   returned `SensorContext` carries the expected boot state,
    ///   then drop it. No tokio tasks are spawned at this point.
    /// - **`run_*`** — call `run(cfg).await` end-to-end. With
    ///   `Config::test_default` every collector is disabled (see
    ///   `CollectorsConfig::all_disabled`), so `spawn_collectors`
    ///   returns immediately, `tx` drops, and `rx.recv()` returns
    ///   `None` on first poll — `run` exits via the "all collectors
    ///   stopped" branch of `run_event_loop`. The whole call resolves
    ///   in well under a second; the 10-second timeout is the loud-
    ///   failure tripwire for any future change that re-introduces an
    ///   ungated `tokio::spawn` in the always-on collector path.
    const BOOT_TIMEOUT: Duration = Duration::from_secs(10);

    #[tokio::test]
    async fn boot_init_with_no_collectors_completes_within_timeout() {
        // Anchor: with every collector disabled (Config::test_default
        // baseline), `boot_init` must complete cleanly — no HTTP feed
        // downloads (datasets are seeded), no spawned tasks, just
        // synchronous state/sink/detector construction + the
        // collector-health snapshot. Far under a second in practice;
        // the 10-second timeout is the loud-failure tripwire.
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = test_cfg(&tmp);

        let started = std::time::Instant::now();
        let result = tokio::time::timeout(BOOT_TIMEOUT, boot_init(cfg)).await;
        let elapsed = started.elapsed();

        match result {
            Ok(Ok(_ctx)) => {
                // Healthy: boot_init returned a SensorContext within
                // the timeout. Dropping _ctx here closes tx + rx with
                // no leaked tasks — there are none, because boot_init
                // never spawns.
            }
            Ok(Err(e)) => panic!("boot_init() returned error: {e:#}"),
            Err(_) => panic!(
                "boot_init() hung for {elapsed:?} (>{BOOT_TIMEOUT:?}). \
                 Some part of the boot path is doing blocking I/O \
                 (HTTP fetch, sync sleep, file lock) that should not \
                 happen when every collector is disabled."
            ),
        }
    }

    #[tokio::test]
    async fn boot_init_creates_sqlite_database_in_data_dir() {
        // Anchor: `SqliteWriter::new(data_dir, ...)` must create
        // `<data_dir>/innerwarden.db` on first boot. A future refactor
        // that delays sink construction or moves the file path would
        // be caught here.
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = test_cfg(&tmp);

        let _ctx = tokio::time::timeout(BOOT_TIMEOUT, boot_init(cfg))
            .await
            .expect("boot_init timed out")
            .expect("boot_init errored");

        let db_path = tmp.path().join("innerwarden.db");
        assert!(
            db_path.exists(),
            "innerwarden.db must be created at <data_dir>/innerwarden.db"
        );
    }

    #[tokio::test]
    async fn boot_init_writes_collector_health_snapshot() {
        // Anchor: the collector-health snapshot (dashboard's source of
        // truth for the Sensors HUD per-collector tile) must be written
        // to `<data_dir>/collector-health.json` even when no collectors
        // are enabled — the dashboard relies on the file existing to
        // know it can render the "all disabled" baseline rather than
        // the "agent has no telemetry" warning.
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = test_cfg(&tmp);

        let _ctx = tokio::time::timeout(BOOT_TIMEOUT, boot_init(cfg))
            .await
            .expect("boot_init timed out")
            .expect("boot_init errored");

        let health_path = tmp.path().join("collector-health.json");
        assert!(
            health_path.exists(),
            "collector-health.json must be written to <data_dir>"
        );
        let content = std::fs::read_to_string(&health_path).expect("read");
        assert!(
            !content.is_empty(),
            "collector-health.json must not be empty"
        );
        // B5: the eBPF feed must be reported (it fails open silently
        // otherwise). On a disabled-collector test cfg it shows as
        // disabled; on a BTF-less / non-Linux host it would be
        // `unsupported` with a reason. Either way the row exists.
        assert!(
            content.contains("\"name\": \"ebpf\""),
            "collector-health.json must include the ebpf row, got: {content}"
        );
    }

    #[tokio::test]
    async fn run_with_no_collectors_returns_within_timeout() {
        // Anchor: end-to-end run(cfg) — boot + spawn + loop — must
        // exit cleanly when every collector is disabled. With
        // `CollectorsConfig::all_disabled` (called inside
        // `Config::test_default`), spawn_collectors spawns zero
        // tasks, drops `tx`, and rx.recv() returns None on first
        // poll. run_event_loop logs "all collectors stopped" and
        // returns Ok.
        //
        // This is the regression tripwire that PR-F3 (#813) could
        // not write: any future change that adds a `tokio::spawn(…)`
        // without a config gate in boot/spawn_collectors.rs will
        // make this test hit the 10-second timeout and fail loudly,
        // since the orphan task will hold a clone of `tx` and rx
        // will never close.
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = test_cfg(&tmp);

        let started = std::time::Instant::now();
        let result = tokio::time::timeout(BOOT_TIMEOUT, run(cfg)).await;
        let elapsed = started.elapsed();

        match result {
            Ok(Ok(())) => {
                // Healthy: full pipeline returned cleanly.
            }
            Ok(Err(e)) => panic!("run() returned error: {e:#}"),
            Err(_) => panic!(
                "run() hung for {elapsed:?} (>{BOOT_TIMEOUT:?}). \
                 Some part of boot/spawn_collectors.rs spawned a \
                 task without a config gate — the orphan is holding \
                 a clone of `tx`, so rx.recv() never returns None. \
                 Find the new ungated `tokio::spawn(...)` and either \
                 gate it on `cfg.collectors.X.enabled` or add an \
                 `AlwaysOnCollectorConfig` field for the collector \
                 and disable it in `CollectorsConfig::all_disabled`."
            ),
        }
    }

    #[tokio::test]
    async fn run_persists_state_file_on_shutdown() {
        // Anchor: run_event_loop's shutdown branch must call
        // `state.save(state_path)`. State persistence is how the
        // sensor resumes log tailing across restarts — losing it
        // means the next boot starts every log from byte 0 and the
        // operator sees a flood of duplicate events. Asserting the
        // state file exists post-`run` proves the shutdown branch
        // executes; without spawned tasks dropping `tx`, the
        // shutdown branch is the only way `run` can reach this
        // point.
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = test_cfg(&tmp);

        tokio::time::timeout(BOOT_TIMEOUT, run(cfg))
            .await
            .expect("run timed out")
            .expect("run errored");

        let state_path = tmp.path().join("state.json");
        assert!(
            state_path.exists(),
            "state.json must be written on shutdown so the \
             next boot can resume log cursors instead of restarting \
             from byte 0"
        );
    }

    #[tokio::test]
    async fn run_does_not_leak_temp_files_when_all_disabled() {
        // Anchor: after `run(cfg)` returns cleanly, the data_dir
        // should contain exactly the artefacts boot writes
        // (innerwarden.db + collector-health.json + state.json
        // + the seeded datasets/ dir) and nothing else. Catches a
        // future regression where a collector starts opening
        // tempfiles unconditionally in module init — that would
        // leak filesystem state even when the collector is disabled.
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = test_cfg(&tmp);

        tokio::time::timeout(BOOT_TIMEOUT, run(cfg))
            .await
            .expect("run timed out")
            .expect("run errored");

        // Expected entries — anything else is suspicious.
        let expected: std::collections::HashSet<&str> = [
            "innerwarden.db",
            "innerwarden.db-shm",
            "innerwarden.db-wal",
            "collector-health.json",
            "state.json",
            "datasets",
        ]
        .into_iter()
        .collect();

        let entries: Vec<String> = std::fs::read_dir(tmp.path())
            .expect("readdir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();

        for entry in &entries {
            assert!(
                expected.contains(entry.as_str()),
                "unexpected file in data_dir after run with all collectors \
                 disabled: {entry} (expected one of: {expected:?}). \
                 A collector probably created this file in module init \
                 even though it was disabled — file I/O belongs inside \
                 the spawned task body, not at module / new() level."
            );
        }
    }
}
