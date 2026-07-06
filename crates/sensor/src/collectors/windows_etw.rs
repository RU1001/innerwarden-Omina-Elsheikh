//! Windows ETW / Event Log telemetry collector (spec 085 Phase 1).
//!
//! ## What it does
//!
//! Polls the Windows Event Log via the built-in `wevtutil qe ... /f:xml`
//! subprocess (no FFI, no `windows`/`winapi` dependency) and maps the
//! high-value security channels onto the SAME `Event.kind` strings the
//! Linux/macOS detectors already consume, so existing detectors fire
//! unchanged:
//!
//! | Windows source                       | emit `kind`                 |
//! |--------------------------------------|-----------------------------|
//! | Security 4625 (failed logon)         | `ssh.login_failed`          |
//! | Security 4624 (successful logon)     | `ssh.login_success`         |
//! | Sysmon 1 / Security 4688 (proc exec) | `shell.command_exec`        |
//! | Sysmon 3 (outbound connection)       | `network.outbound_connect`  |
//!
//! `Event.source` is `"etw"` for every record. Detectors filter on
//! `Event.kind`, not `source` (verified against ssh_bruteforce.rs:31,
//! credential_stuffing.rs:30, suspicious_login.rs:58, process_tree.rs:166,
//! reverse_shell.rs:464/475, imds_ssrf.rs:221), so the mapping above lets
//! the whole detector pipeline light up on Windows telemetry.
//!
//! ## Shape (mirrors `macos_log.rs`)
//!
//! Three stages, exactly like the macOS unified-log collector:
//!
//! 1. **PROBE** availability once (`wevtutil /?`); on failure `warn!` +
//!    `return Ok(())`. This is what makes the collector inert on
//!    Linux/macOS: `wevtutil` does not exist there, the probe fails, and
//!    the collector fails open without ever touching the pipeline. The
//!    spawn site additionally gates on `cfg!(target_os = "windows")`.
//! 2. **PARSE** each `<Event>..</Event>` XML record with the PURE,
//!    OS-independent [`parse_win_event`] function - unit-tested on any
//!    host with the committed fixtures under
//!    `crates/sensor/testdata/windows_etw/`.
//! 3. **EMIT** `Event { source: "etw", kind, .. }` down the shared
//!    `mpsc::Sender<Event>`; on `send` error the receiver is gone, so we
//!    return `Ok(())` (fail-open shutdown).
//!
//! ## Why subprocess polling (Approach 2) and not native EvtSubscribe
//!
//! The whole architecture is a subprocess poll so the entire parser +
//! its watermark math is a set of pure functions runnable and testable on
//! a Mac dev box - no Windows box, no `windows-sys` FFI, no unsafe handle
//! discipline. The native `EvtSubscribe`/`EvtRenderEventXml` push path is
//! the documented Phase-2 upgrade for sub-poll latency; because
//! `EvtRender`'s Event-XML is byte-identical to `wevtutil /f:xml`, that
//! future swap reuses THIS parser and THESE fixtures verbatim.
//!
//! ## No silent event loss (in-memory `EventRecordID` watermark)
//!
//! Each channel keeps a plain `u64` high-water mark of the last
//! `EventRecordID` seen (a local in `run`, NOT persisted across restarts -
//! like `macos_log`'s `-n 0`, we tail from now). Every poll FULLY drains
//! the channel (`EventRecordID > watermark`, oldest-first, batched) until
//! a batch returns fewer than `batch_cap` rows, so a burst larger than one
//! batch can never jump the filter. If a channel's max RecordID drops
//! BELOW the watermark (Security log cleared - EID 1102 - or the channel
//! was recreated and RecordID restarted at 1) the watermark is
//! re-baselined instead of filtering forever against a stale-high value.

use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::Utc;
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Defaults (kept in lockstep with `config::WindowsEtwConfig` defaults).
// ---------------------------------------------------------------------------

const DEFAULT_POLL_SECONDS: u64 = 5;
const DEFAULT_BATCH_CAP: u32 = 200;

/// A monitored Windows Event Log channel plus the static EventID set used
/// as a source-side XPath pre-filter (mirrors `macos_log`'s `--predicate`:
/// cut parse volume before it ever reaches the parser).
#[derive(Clone)]
struct EtwChannel {
    name: String,
    event_ids: Vec<u32>,
}

/// The built-in default channel set: Windows Security auditing + Sysmon.
fn default_channels() -> Vec<EtwChannel> {
    vec![
        EtwChannel {
            name: "Security".to_string(),
            event_ids: vec![4625, 4624, 4688],
        },
        EtwChannel {
            name: "Microsoft-Windows-Sysmon/Operational".to_string(),
            event_ids: vec![1, 3],
        },
    ]
}

/// Static EventID pre-filter for an operator-configured channel name.
/// Unknown channels get NO EventID filter (query everything; the parser
/// dispatches or ignores by EventID) so a custom channel still works.
fn event_ids_for_channel(name: &str) -> Vec<u32> {
    if name.eq_ignore_ascii_case("Security") {
        vec![4625, 4624, 4688]
    } else if name.contains("Sysmon") {
        vec![1, 3]
    } else {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

/// Windows ETW / Event Log collector. Built with [`WindowsEtwCollector::new`]
/// from just the host id; the channel set / poll interval / batch cap start
/// from the built-in defaults and can be overridden from config via the
/// `with_*` builders (see `boot::spawn_collectors`).
pub struct WindowsEtwCollector {
    host: String,
    channels: Vec<EtwChannel>,
    poll_seconds: u64,
    batch_cap: u32,
}

impl WindowsEtwCollector {
    /// Construct from the host id, using the default channel set / poll /
    /// cap. Signature mirrors `MacosLogCollector::new`.
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            channels: default_channels(),
            poll_seconds: DEFAULT_POLL_SECONDS,
            batch_cap: DEFAULT_BATCH_CAP,
        }
    }

    /// Override the monitored channels (from `[collectors.windows_etw]
    /// channels`). Empty input keeps the defaults. Each name is paired with
    /// its static EventID pre-filter via [`event_ids_for_channel`].
    pub fn with_channels(mut self, names: Vec<String>) -> Self {
        if !names.is_empty() {
            self.channels = names
                .into_iter()
                .map(|name| {
                    let event_ids = event_ids_for_channel(&name);
                    EtwChannel { name, event_ids }
                })
                .collect();
        }
        self
    }

    /// Override the poll interval (seconds). Zero keeps the default.
    pub fn with_poll_seconds(mut self, secs: u64) -> Self {
        if secs > 0 {
            self.poll_seconds = secs;
        }
        self
    }

    /// Override the per-drain batch cap. Zero keeps the default.
    pub fn with_batch_cap(mut self, cap: u32) -> Self {
        if cap > 0 {
            self.batch_cap = cap;
        }
        self
    }

    /// Poll the configured Windows Event Log channels and emit mapped
    /// `Event`s. Fail-open: never panics, never `?`-propagates a per-poll
    /// read error past the loop (a bad poll just skips that channel for the
    /// tick and retries next interval).
    pub async fn run(self, tx: mpsc::Sender<Event>) -> Result<()> {
        // 1. PROBE. `wevtutil` only exists on Windows; on Linux/macOS the
        //    spawn errors and we disable ourselves cleanly (fail-open),
        //    mirroring `macos_log`'s `log --help` gate.
        let probe = Command::new("wevtutil").arg("/?").output().await;
        if !probe_says_usable(&probe) {
            warn!("wevtutil unavailable - windows_etw collector disabled");
            return Ok(());
        }

        info!(host = %self.host, channels = self.channels.len(), "windows_etw collector starting");

        // 2. Baseline each channel's watermark to its current max RecordID so
        //    the first poll tails-from-now (no historical backfill flood).
        //    Per-channel fail-open: a channel we cannot read (Security needs
        //    admin; Sysmon may be absent) is skipped but never disables the
        //    whole collector.
        let mut watermarks: Vec<u64> = Vec::with_capacity(self.channels.len());
        let mut readable: Vec<bool> = Vec::with_capacity(self.channels.len());
        for chan in &self.channels {
            match query_channel_max(&chan.name).await {
                Ok(max) => {
                    watermarks.push(max.unwrap_or(0));
                    readable.push(true);
                }
                Err(e) => {
                    warn!(
                        channel = %chan.name,
                        error = %e,
                        "windows_etw channel unreadable at baseline - skipping (fail-open)"
                    );
                    watermarks.push(0);
                    readable.push(false);
                }
            }
        }

        // 3. Poll loop.
        let poll = std::time::Duration::from_secs(self.poll_seconds);
        loop {
            if tx.is_closed() {
                return Ok(());
            }

            for (idx, chan) in self.channels.iter().enumerate() {
                if !readable[idx] {
                    continue;
                }

                // FULL DRAIN forward: repeat `EventRecordID > watermark`
                // (oldest-first, capped) until a short batch proves we caught
                // up. A burst larger than one batch cannot silently jump the
                // `> watermark` filter.
                let mut rows_this_tick: u64 = 0;
                loop {
                    let watermark_before = watermarks[idx];
                    let args = wevtutil_query_args(
                        &chan.name,
                        watermarks[idx],
                        self.batch_cap,
                        &chan.event_ids,
                    );
                    let stdout = match run_wevtutil(&args).await {
                        Ok(out) => out,
                        Err(e) => {
                            // Access-denied / channel-not-found / transient.
                            // Fail-open: skip this channel for this tick and
                            // retry next poll. NEVER `?`-propagate.
                            warn!(
                                channel = %chan.name,
                                error = %e,
                                "windows_etw query failed - skipping channel this tick"
                            );
                            break;
                        }
                    };

                    let records = split_event_records(&stdout);
                    let n = records.len() as u32;
                    for rec in &records {
                        let parsed = parse_win_event(rec, &self.host);
                        advance_watermark(&parsed, &mut watermarks[idx]);
                        if let Some(event) = parsed.and_then(|p| p.event) {
                            if tx.send(event).await.is_err() {
                                // Receiver gone: shut down cleanly.
                                return Ok(());
                            }
                        }
                    }
                    rows_this_tick += u64::from(n);
                    // Stop when caught up (short batch), OR when a FULL batch
                    // failed to advance the watermark - otherwise the same
                    // `> watermark` batch would repeat forever.
                    if !drain_should_continue(n, self.batch_cap, watermark_before, watermarks[idx])
                    {
                        if n >= self.batch_cap && watermarks[idx] <= watermark_before {
                            warn!(
                                channel = %chan.name,
                                "windows_etw drain made no progress on a full batch - breaking to next tick"
                            );
                        }
                        break;
                    }
                }

                // Reset / re-baseline: if the drain produced nothing, the
                // channel may have been cleared (RecordID restarted below our
                // stale-high watermark) - the `> watermark` filter would then
                // match forever-nothing. Probe the true current max and, if it
                // regressed, re-baseline.
                if rows_this_tick == 0 {
                    if let Ok(true_max) = query_channel_max(&chan.name).await {
                        rebaseline_watermark_on_reset(true_max, &mut watermarks[idx]);
                    }
                }
            }

            // Sleep until the next tick, but wake immediately if the receiver
            // is dropped so shutdown is responsive.
            tokio::select! {
                _ = tokio::time::sleep(poll) => {}
                _ = tx.closed() => return Ok(()),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// wevtutil argument builders (pure, unit-tested)
// ---------------------------------------------------------------------------

/// Build the drain query args:
/// `wevtutil qe <channel> /q:*[System[(<eid clause>) and (EventRecordID><wm>)]]
///  /f:xml /rd:false /c:<cap> /e:Events`.
///
/// `/rd:false` = oldest-first, which is REQUIRED for a correct forward
/// drain: with `> watermark` filtering, oldest-first + `/c:cap` returns the
/// OLDEST `cap` unread records so repeated batches march forward. (Newest-
/// first would return the newest `cap` and silently skip everything older.)
///
/// Only our own `u64` watermark is interpolated; the EventID set is static.
/// Nothing attacker-controlled ever reaches the command line (no wevtutil
/// argument injection).
pub(crate) fn wevtutil_query_args(
    channel: &str,
    after_record_id: u64,
    cap: u32,
    event_ids: &[u32],
) -> Vec<String> {
    let system_clause = if event_ids.is_empty() {
        format!("EventRecordID>{after_record_id}")
    } else {
        format!(
            "({}) and (EventRecordID>{after_record_id})",
            xpath_event_id_clause(event_ids)
        )
    };
    vec![
        "qe".to_string(),
        channel.to_string(),
        format!("/q:*[System[{system_clause}]]"),
        "/f:xml".to_string(),
        "/rd:false".to_string(),
        format!("/c:{cap}"),
        "/e:Events".to_string(),
    ]
}

/// `EventID=4625 or EventID=4624 or EventID=4688` for the static pre-filter.
fn xpath_event_id_clause(event_ids: &[u32]) -> String {
    event_ids
        .iter()
        .map(|id| format!("EventID={id}"))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// Build the "current max RecordID" probe args: newest single record, no
/// EventID filter (`/c:1 /rd:true`). Used to baseline-from-now and to detect
/// a cleared channel.
fn wevtutil_max_probe_args(channel: &str) -> Vec<String> {
    vec![
        "qe".to_string(),
        channel.to_string(),
        "/c:1".to_string(),
        "/rd:true".to_string(),
        "/f:xml".to_string(),
        "/e:Events".to_string(),
    ]
}

// ---------------------------------------------------------------------------
// wevtutil subprocess helpers (Windows-only at runtime; compile everywhere)
// ---------------------------------------------------------------------------

/// Spawn `wevtutil` with `args`, returning captured stdout. A non-zero exit
/// (access denied, channel not found) becomes an `Err` so the caller can
/// fail-open per-channel.
async fn run_wevtutil(args: &[String]) -> Result<String> {
    let out = Command::new("wevtutil")
        .args(args)
        .output()
        .await
        .context("failed to spawn wevtutil")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("wevtutil exited {:?}: {}", out.status.code(), err.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Query a channel's current maximum `EventRecordID` (newest record).
/// `Ok(None)` = channel readable but empty. `Err` = unreadable.
async fn query_channel_max(channel: &str) -> Result<Option<u64>> {
    let stdout = run_wevtutil(&wevtutil_max_probe_args(channel)).await?;
    let max = split_event_records(&stdout)
        .iter()
        .filter_map(|r| element_text(r, "EventRecordID").and_then(parse_u64_dec))
        .max();
    Ok(max)
}

// ---------------------------------------------------------------------------
// Availability probe (pure, unit-tested) - mirrors macos_log::probe_says_usable
// ---------------------------------------------------------------------------

/// Whether the `wevtutil /?` output is the real Windows Events CLI. We check
/// for the tool name / the `query-events` verb rather than the exit code,
/// mirroring `macos_log`'s `stream`-subcommand check.
fn wevtutil_usable(spawned: bool, help_output: &str) -> bool {
    let t = help_output.to_lowercase();
    spawned && (t.contains("query-events") || t.contains("wevtutil"))
}

/// Decide usability from the `wevtutil /?` probe result: a spawn error means
/// "not Windows / not installed" (unusable); otherwise combine stdout+stderr
/// and look for the tool's own usage banner. Pure over the injected `Output`.
pub(crate) fn probe_says_usable(probe: &std::io::Result<std::process::Output>) -> bool {
    match probe {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            wevtutil_usable(true, &text)
        }
        Err(_) => wevtutil_usable(false, ""),
    }
}

// ---------------------------------------------------------------------------
// In-memory EventRecordID watermark (pure, unit-tested)
// ---------------------------------------------------------------------------

/// Monotonically advance the watermark from a drained record. Higher wins;
/// equal / lower / `None` are no-ops (never regress on an out-of-order or
/// uninteresting record). The cleared-log RESET case is handled separately
/// by [`rebaseline_watermark_on_reset`] so a single stale record can never
/// drag the watermark backwards.
pub(crate) fn advance_watermark(parsed: &Option<ParsedEtw>, current: &mut u64) {
    if let Some(p) = parsed {
        if p.record_id > *current {
            *current = p.record_id;
        }
    }
}

/// Re-baseline the watermark when a channel's true current max RecordID has
/// regressed BELOW it (the log was cleared - EID 1102 - or recreated and
/// RecordID restarted at 1). Returns `true` when it re-baselined. Only ever
/// LOWERS the watermark, so it can never skip past undrained records.
pub(crate) fn rebaseline_watermark_on_reset(channel_max: Option<u64>, current: &mut u64) -> bool {
    if let Some(max) = channel_max {
        if max < *current {
            *current = max;
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Pure parser
// ---------------------------------------------------------------------------

/// Result of parsing one `<Event>` record. `record_id` always advances the
/// watermark (even for uninteresting events); `event` is `Some` only for a
/// mapped, emit-worthy record.
pub(crate) struct ParsedEtw {
    pub record_id: u64,
    pub event: Option<Event>,
}

/// Which process-create schema we are reading (field names + PID radix
/// differ between Sysmon EID 1 and Security EID 4688).
#[derive(Clone, Copy)]
enum ProcSource {
    /// Sysmon EID 1: decimal `ProcessId`, `Image`, `User`.
    Sysmon,
    /// Security EID 4688: hex `NewProcessId`/`ProcessId`, `NewProcessName`,
    /// `SubjectUserName`/`SubjectUserSid`.
    Security4688,
}

/// Parse one Windows Event-XML `<Event>..</Event>` record into a
/// [`ParsedEtw`]. Returns:
/// - `None` - malformed / no `EventRecordID` (cannot advance a watermark, skip).
/// - `Some { event: None }` - valid record but not mapped (advance watermark).
/// - `Some { event: Some(_) }` - mapped, emit-worthy.
///
/// Pure and OS-independent: unit-tested on any host with committed fixtures.
pub(crate) fn parse_win_event(xml: &str, host: &str) -> Option<ParsedEtw> {
    // No RecordID => we cannot even advance a watermark: treat as malformed.
    let record_id = element_text(xml, "EventRecordID").and_then(parse_u64_dec)?;
    let event_id = element_text(xml, "EventID").and_then(parse_u64_dec);
    let provider = provider_name(xml).unwrap_or_default();
    let is_sysmon = provider.contains("Sysmon");
    let data = event_data_map(xml);

    let event = match event_id {
        Some(4625) => parse_logon_failed(&data, host),
        Some(4624) => parse_logon_success(&data, host),
        Some(1) if is_sysmon => parse_process_create(&data, host, ProcSource::Sysmon),
        Some(4688) => parse_process_create(&data, host, ProcSource::Security4688),
        Some(3) if is_sysmon => parse_network(&data, host),
        // 4720 / 4732 / anything else: advance the watermark, emit nothing.
        _ => None,
    };

    Some(ParsedEtw { record_id, event })
}

/// Security 4625 -> `ssh.login_failed`. `ip` + `user` are REQUIRED by the
/// consuming detectors (ssh_bruteforce.rs:35, credential_stuffing.rs:34/38,
/// distributed_ssh.rs:39, suspicious_login.rs:50); a local-console record
/// (`IpAddress` empty / `-` / `::1`) is dropped like macos_log drops an
/// unparseable line.
fn parse_logon_failed(data: &HashMap<String, String>, host: &str) -> Option<Event> {
    let ip = data.get("IpAddress").map(String::as_str).unwrap_or("");
    if ip.is_empty() || ip == "-" || ip == "::1" {
        return None;
    }
    let user = data.get("TargetUserName").map(String::as_str).unwrap_or("");
    if user.is_empty() {
        return None;
    }
    let reason = logon_failure_reason(data);

    let mut details = serde_json::json!({ "ip": ip, "user": user });
    if let Some(r) = &reason {
        details["reason"] = serde_json::Value::String(r.clone());
    }

    Some(Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "etw".to_string(),
        kind: "ssh.login_failed".to_string(),
        severity: Severity::Info,
        summary: format!("Failed logon for {user} from {ip}"),
        details,
        tags: vec!["auth".to_string(), "etw".to_string()],
        entities: vec![EntityRef::ip(ip)],
    })
}

/// Security 4624 -> `ssh.login_success`. Requires a real remote `IpAddress`
/// (suspicious_login.rs:50 bails without it). Only human logon types
/// (2/3/7/10/11) are emitted; service (5) / SYSTEM (0) and machine accounts
/// (`...$`) are dropped to avoid flooding.
fn parse_logon_success(data: &HashMap<String, String>, host: &str) -> Option<Event> {
    let ip = data.get("IpAddress").map(String::as_str).unwrap_or("");
    if ip.is_empty() || ip == "-" || ip == "::1" {
        return None;
    }
    let user = data.get("TargetUserName").map(String::as_str).unwrap_or("");
    if user.is_empty() || user.ends_with('$') {
        return None;
    }
    let logon_type = data
        .get("LogonType")
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
    if !matches!(logon_type, 2 | 3 | 7 | 10 | 11) {
        return None;
    }
    let method = match logon_type {
        2 => Some("password"),
        3 => Some("network"),
        10 => Some("rdp"),
        _ => None,
    };

    let mut details = serde_json::json!({ "ip": ip, "user": user });
    if let Some(m) = method {
        details["method"] = serde_json::Value::String(m.to_string());
    }

    Some(Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "etw".to_string(),
        kind: "ssh.login_success".to_string(),
        severity: Severity::Info,
        summary: format!("Successful logon for {user} from {ip}"),
        details,
        tags: vec!["auth".to_string(), "etw".to_string()],
        entities: vec![EntityRef::ip(ip), EntityRef::user(user)],
    })
}

/// Sysmon 1 / Security 4688 -> `shell.command_exec`. Mirrors the eBPF exec
/// emit schema (ebpf_syscall.rs:487-514) so process_tree / reverse_shell /
/// system_user_interactive / user_creation consume it unchanged.
fn parse_process_create(
    data: &HashMap<String, String>,
    host: &str,
    src: ProcSource,
) -> Option<Event> {
    let (image, pid_raw, ppid_raw, parent_image, user, sid) = match src {
        ProcSource::Sysmon => (
            data.get("Image"),
            data.get("ProcessId"),
            data.get("ParentProcessId"),
            data.get("ParentImage"),
            data.get("User"),
            None,
        ),
        ProcSource::Security4688 => (
            data.get("NewProcessName"),
            data.get("NewProcessId"),
            data.get("ProcessId"),
            data.get("ParentProcessName"),
            data.get("SubjectUserName"),
            data.get("SubjectUserSid"),
        ),
    };

    let image = image.map(String::as_str).unwrap_or("");
    let cmdline = data.get("CommandLine").map(String::as_str).unwrap_or("");
    // 4688 without command-line auditing has no CommandLine: fall back to the
    // image path so reverse_shell / process_tree still get something real.
    let command = if !cmdline.is_empty() { cmdline } else { image };
    if command.is_empty() {
        return None;
    }

    let comm = win_basename(image).to_string();
    let ppid_comm = parent_image
        .map(|p| win_basename(p).to_string())
        .unwrap_or_default();
    let user = user.map(String::as_str).unwrap_or("");
    let uid = synth_uid(sid.map(String::as_str), user);

    let mut argv = split_command_line(command);
    if argv.is_empty() {
        argv.push(image.to_string());
    }

    // `ppid` defaults to 0 when unresolvable (process_tree treats 0 as
    // "unknown parent"). `parent_comm` duplicates `ppid_comm` for eBPF parity
    // (ebpf_syscall.rs emits parent_comm; user_creation reads ppid_comm).
    let ppid = ppid_raw.and_then(|s| parse_pid(s)).unwrap_or(0);
    let mut details = serde_json::json!({
        "comm": comm,
        "command": command,
        "argv": argv,
        "ppid": ppid,
        "ppid_comm": ppid_comm,
        "parent_comm": ppid_comm,
        "uid": uid,
        "user": user,
        "username": user,
        "has_tty": false,
    });
    // pid is REQUIRED as a JSON NUMBER by process_tree.rs:170 (`as_u64()?`).
    // 4688 gives it in hex (`0x1a4`); Sysmon in decimal. Emit it as a number
    // when parseable; when absent, process_tree simply skips (it `?`-bails),
    // while reverse_shell's command scan still fires.
    if let Some(pid) = pid_raw.and_then(|s| parse_pid(s)) {
        details["pid"] = serde_json::json!(pid);
    }

    let mut entities = Vec::new();
    if !user.is_empty() {
        entities.push(EntityRef::user(user));
    }

    Some(Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "etw".to_string(),
        kind: "shell.command_exec".to_string(),
        severity: Severity::Info,
        summary: format!("Process created: {command}"),
        details,
        tags: vec!["process".to_string(), "etw".to_string()],
        entities,
    })
}

/// Sysmon 3 -> `network.outbound_connect`. Only OUTBOUND (`Initiated=true`)
/// connections to non-loopback/non-link-local destinations are emitted.
/// Mirrors the eBPF net emit (ebpf_syscall.rs:541-578): `exe_path` carries
/// the non-forgeable full image path imds_ssrf keys on.
fn parse_network(data: &HashMap<String, String>, host: &str) -> Option<Event> {
    let initiated = data
        .get("Initiated")
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    if initiated != "true" {
        return None; // inbound / listen: dropped (no native inbound analog)
    }
    let dst_ip = data.get("DestinationIp").map(String::as_str).unwrap_or("");
    if dst_ip.is_empty() || is_local_dest(dst_ip) {
        return None;
    }

    let image = data.get("Image").map(String::as_str).unwrap_or("");
    let comm = win_basename(image).to_string();
    let user = data.get("User").map(String::as_str).unwrap_or("");
    let uid = synth_uid(None, user);
    let dst_port = data
        .get("DestinationPort")
        .and_then(|s| s.trim().parse::<u64>().ok());

    let mut details = serde_json::json!({
        "comm": comm,
        "dst_ip": dst_ip,
        "uid": uid,
        "exe_path": image,
        "user": user,
    });
    if let Some(pid) = data.get("ProcessId").and_then(|s| parse_pid(s)) {
        details["pid"] = serde_json::json!(pid);
    }
    if let Some(port) = dst_port {
        details["dst_port"] = serde_json::json!(port);
    }

    // reverse_shell severity-scans the classic implant ports.
    let severity = match dst_port {
        Some(4444) | Some(1337) | Some(31337) => Severity::High,
        _ => Severity::Info,
    };
    let uid_name = if user.is_empty() {
        format!("uid-{uid}")
    } else {
        user.to_string()
    };
    let port_str = dst_port
        .map(|p| p.to_string())
        .unwrap_or_else(|| "?".to_string());

    Some(Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "etw".to_string(),
        kind: "network.outbound_connect".to_string(),
        severity,
        summary: format!("{comm} connecting to {dst_ip}:{port_str}"),
        details,
        tags: vec!["network".to_string(), "etw".to_string()],
        entities: vec![EntityRef::ip(dst_ip), EntityRef::user(uid_name)],
    })
}

// ---------------------------------------------------------------------------
// Field mapping helpers (pure)
// ---------------------------------------------------------------------------

/// Map 4625 `Status`/`SubStatus` NTSTATUS codes to a coarse reason,
/// mirroring the `auth_log` `reason` field. `SubStatus` carries the precise
/// cause on 4625.
fn logon_failure_reason(data: &HashMap<String, String>) -> Option<String> {
    let sub = data
        .get("SubStatus")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let status = data
        .get("Status")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let joined = format!("{sub} {status}");
    if joined.contains("0xc0000064") {
        Some("invalid_user".to_string())
    } else if joined.contains("0xc000006a") {
        Some("bad_password".to_string())
    } else {
        None
    }
}

/// Synthetic UID: 0 for SYSTEM (`SubjectUserSid == S-1-5-18`, or a
/// `...\SYSTEM` user string when no SID is present, e.g. Sysmon), else 1000.
fn synth_uid(sid: Option<&str>, user: &str) -> u64 {
    let is_system = match sid {
        Some(s) => s.trim() == "S-1-5-18",
        None => {
            let u = user.to_uppercase();
            u == "SYSTEM" || u.ends_with("\\SYSTEM") || u.contains("NT AUTHORITY\\SYSTEM")
        }
    };
    if is_system {
        0
    } else {
        1000
    }
}

/// Basename of a Windows (or Unix) path: everything after the last `\` or `/`.
fn win_basename(path: &str) -> &str {
    let after_backslash = path.trim().rsplit('\\').next().unwrap_or(path);
    after_backslash
        .rsplit('/')
        .next()
        .unwrap_or(after_backslash)
}

/// Parse a PID that may be hex (`0x1a4`, from Security 4688) or decimal
/// (`6321`, from Sysmon).
fn parse_pid(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

/// Plain decimal `u64` (EventID, EventRecordID, ports).
fn parse_u64_dec(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok()
}

/// True for loopback / link-local destinations that must never be reported as
/// an outbound C2 connection.
fn is_local_dest(ip: &str) -> bool {
    // 169.254.169.254 is the cloud instance-metadata endpoint (AWS/Azure); it is
    // link-local by range but a real SSRF/exfil target that imds_ssrf consumes,
    // so it is deliberately NOT treated as local.
    if ip == "169.254.169.254" {
        return false;
    }
    let low = ip.to_lowercase();
    ip.starts_with("127.") || low == "::1" || ip.starts_with("169.254.") || low.starts_with("fe80")
}

/// Whether the channel drain should pull another batch: only when the last batch
/// was FULL (`n >= batch_cap`, so more may remain) AND the watermark actually
/// advanced. A full batch that did not advance the watermark (all records at or
/// below it, or unparseable) would otherwise repeat the same `> watermark` query
/// forever - the no-progress guard breaks it to the next poll tick.
fn drain_should_continue(n: u32, batch_cap: u32, before: u64, after: u64) -> bool {
    n >= batch_cap && after > before
}

/// Quote-aware tokeniser for a Windows command line into an argv array
/// (double-quotes group; system_user_interactive.rs:149 needs an array).
fn split_command_line(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut has_token = false;
    for c in cmd.chars() {
        match c {
            // A double-quote toggles grouping and contributes no character,
            // but marks that a (possibly empty) token has begun.
            '"' => {
                in_quote = !in_quote;
                has_token = true;
            }
            c if c.is_whitespace() && !in_quote => {
                if has_token {
                    out.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        out.push(cur);
    }
    out
}

// ---------------------------------------------------------------------------
// Minimal, adversarial-input-safe Event-XML extraction (pure, zero-dep)
// ---------------------------------------------------------------------------
//
// Windows Event-XML is regular and shallow; we extract exactly three shapes:
//   * `<EventID>..</EventID>` / `<EventRecordID>..</EventRecordID>` (System)
//   * `<Provider Name='..' .../>` (attribute)
//   * `<Data Name='X'>value</Data>` (EventData, attacker-controlled values)
// Values are XML-entity-unescaped (`&amp;`, `&lt;`, `&#..;`) because
// CommandLine/Image are attacker-controlled and reverse_shell.rs scans that
// text for `nc -e` / `/dev/tcp`, so correct unescaping is load-bearing.

/// Segment a `wevtutil /f:xml` stream (a concatenation, optionally wrapped in
/// `<Events>`) into individual `<Event ...>..</Event>` records. Distinguishes
/// the event element from the `<Events>` wrapper by the char after `<Event`.
pub(crate) fn split_event_records(stream: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = stream[i..].find("<Event") {
        let start = i + rel;
        let after = start + "<Event".len();
        // The event root opens `<Event ` or `<Event>`; the wrapper is
        // `<Events>` (next char is 's'). Only accept a real event boundary.
        let boundary = stream[after..].chars().next();
        if !matches!(
            boundary,
            Some(' ') | Some('>') | Some('\t') | Some('\r') | Some('\n')
        ) {
            i = after; // e.g. "<Events>": keep scanning past it
            continue;
        }
        if let Some(erel) = stream[start..].find("</Event>") {
            let end = start + erel + "</Event>".len();
            out.push(&stream[start..end]);
            i = end;
        } else {
            break; // truncated tail
        }
    }
    out
}

/// Raw inner text of the first `<tag ...>..</tag>` element (attributes
/// allowed). Returns the still-escaped slice; callers unescape as needed.
/// System scalars (EventID/EventRecordID) are plain digits, so no unescape is
/// required for them.
fn element_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}");
    let mut search = 0;
    loop {
        let rel = xml[search..].find(&open)?;
        let at = search + rel;
        let after = at + open.len();
        let boundary = xml[after..].chars().next();
        if matches!(
            boundary,
            Some(' ') | Some('>') | Some('\t') | Some('\r') | Some('\n') | Some('/')
        ) {
            let gt_rel = xml[after..].find('>')?;
            let gt_at = after + gt_rel;
            // Self-closing `<tag .../>` has no text.
            if xml.as_bytes().get(gt_at.wrapping_sub(1)) == Some(&b'/') {
                return Some("");
            }
            let content_start = gt_at + 1;
            let close = format!("</{tag}>");
            let crel = xml[content_start..].find(&close)?;
            return Some(&xml[content_start..content_start + crel]);
        }
        // False prefix (e.g. `<EventID` vs `<EventIDX`): keep scanning.
        search = after;
    }
}

/// `Name='...'` (or `"..."`) attribute value of the `<Provider ...>` element,
/// unescaped.
fn provider_name(xml: &str) -> Option<String> {
    let p = xml.find("<Provider")?;
    let rest = &xml[p..];
    let end = rest.find('>')?; // handles `/>` and `>`
    attr_value(&rest[..end], "Name")
}

/// Value of `attr='...'` / `attr="..."` inside a start-tag slice, unescaped.
/// Requires a non-alphanumeric char before `attr=` so `Name=` does not match
/// inside `EventSourceName=`.
fn attr_value(tag: &str, attr: &str) -> Option<String> {
    let key = format!("{attr}=");
    let mut from = 0;
    while let Some(rel) = tag[from..].find(&key) {
        let at = from + rel;
        let ok_before = at == 0
            || !tag[..at]
                .chars()
                .next_back()
                .map(|c| c.is_alphanumeric())
                .unwrap_or(false);
        if ok_before {
            let after = &tag[at + key.len()..];
            let q = after.chars().next()?;
            if q == '\'' || q == '"' {
                let body = &after[1..];
                if let Some(endq) = body.find(q) {
                    return Some(xml_unescape(&body[..endq]));
                }
            }
            return None;
        }
        from = at + key.len();
    }
    None
}

/// Extract every `<Data Name='X'>value</Data>` inside `<EventData>` into a
/// map `X -> unescaped(value)`. Self-closing `<Data Name='X'/>` maps to "".
fn event_data_map(xml: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    // Scope to the EventData block when present; fall back to the whole doc
    // (some providers use <UserData>).
    let block = match (xml.find("<EventData"), xml.find("</EventData>")) {
        (Some(s), Some(e)) if e > s => &xml[s..e],
        _ => xml,
    };

    let mut search = 0;
    while let Some(rel) = block[search..].find("<Data") {
        let at = search + rel;
        let after = at + "<Data".len();
        let boundary = block[after..].chars().next();
        if !matches!(
            boundary,
            Some(' ') | Some('\t') | Some('/') | Some('>') | Some('\r') | Some('\n')
        ) {
            search = after; // e.g. `<DataX`
            continue;
        }
        let Some(gt_rel) = block[after..].find('>') else {
            break;
        };
        let gt_at = after + gt_rel;
        let open_tag = &block[at..=gt_at];
        let name = attr_value(open_tag, "Name");

        // Self-closing `<Data Name='X'/>`.
        if block.as_bytes().get(gt_at.wrapping_sub(1)) == Some(&b'/') {
            if let Some(n) = name {
                map.entry(n).or_default();
            }
            search = gt_at + 1;
            continue;
        }

        let content_start = gt_at + 1;
        let Some(crel) = block[content_start..].find("</Data>") else {
            break;
        };
        if let Some(n) = name {
            map.insert(n, xml_unescape(&block[content_start..content_start + crel]));
        }
        search = content_start + crel + "</Data>".len();
    }
    map
}

/// Unescape the five XML predefined entities plus numeric character
/// references (`&#60;`, `&#x3c;`). Invalid entities are passed through
/// literally so we never lose attacker-controlled text.
fn xml_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        if let Some(semi) = tail.find(';') {
            let ent = &tail[1..semi];
            let repl = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                    u32::from_str_radix(&ent[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
                _ => None,
            };
            if let Some(c) = repl {
                out.push(c);
                rest = &tail[semi + 1..];
                continue;
            }
        }
        // Not a valid entity: emit the '&' and continue after it.
        out.push('&');
        rest = &tail[1..];
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// Tests (pure parser + helpers, runnable on any OS)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const F_4625_FAILED: &str = include_str!("../../testdata/windows_etw/4625_failed_logon.xml");
    const F_4625_CONSOLE: &str = include_str!("../../testdata/windows_etw/4625_local_console.xml");
    const F_4624_RDP: &str = include_str!("../../testdata/windows_etw/4624_success_rdp.xml");
    const F_4624_SVC: &str = include_str!("../../testdata/windows_etw/4624_service_type5.xml");
    const F_4624_MACHINE: &str =
        include_str!("../../testdata/windows_etw/4624_machine_account.xml");
    const F_4688: &str = include_str!("../../testdata/windows_etw/4688_process_create.xml");
    const F_SYSMON1: &str = include_str!("../../testdata/windows_etw/sysmon1_process_create.xml");
    const F_SYSMON3_OUT: &str = include_str!("../../testdata/windows_etw/sysmon3_outbound.xml");
    const F_SYSMON3_IN: &str = include_str!("../../testdata/windows_etw/sysmon3_inbound.xml");
    const F_SYSMON3_LOOP: &str = include_str!("../../testdata/windows_etw/sysmon3_loopback.xml");
    const F_4720: &str = include_str!("../../testdata/windows_etw/4720_user_created.xml");

    fn parse(xml: &str) -> ParsedEtw {
        parse_win_event(xml, "WIN-TEST").expect("record has an EventRecordID")
    }

    // ── 4625 failed logon ────────────────────────────────────────────────

    #[test]
    fn parse_4625_emits_ssh_login_failed() {
        let p = parse(F_4625_FAILED);
        assert_eq!(p.record_id, 229886);
        let ev = p.event.expect("4625 with a real IP must emit");
        assert_eq!(ev.kind, "ssh.login_failed");
        assert_eq!(ev.source, "etw");
        assert_eq!(ev.details["ip"], "203.0.113.66");
        assert_eq!(ev.details["user"], "administrator");
        // SubStatus 0xC000006A -> bad_password.
        assert_eq!(ev.details["reason"], "bad_password");
        assert_eq!(ev.entities, vec![EntityRef::ip("203.0.113.66")]);
        assert!(ev.tags.contains(&"etw".to_string()));
    }

    #[test]
    fn parse_4625_drops_local_console() {
        // IpAddress '-' (interactive console) -> advance watermark, emit nothing.
        let p = parse(F_4625_CONSOLE);
        assert_eq!(p.record_id, 229887);
        assert!(p.event.is_none());
    }

    // ── 4624 successful logon ────────────────────────────────────────────

    #[test]
    fn parse_4624_emits_ssh_login_success() {
        let p = parse(F_4624_RDP);
        assert_eq!(p.record_id, 500123);
        let ev = p.event.expect("RDP logon must emit");
        assert_eq!(ev.kind, "ssh.login_success");
        assert_eq!(ev.source, "etw");
        assert_eq!(ev.details["ip"], "198.51.100.23");
        assert_eq!(ev.details["user"], "Administrator");
        assert_eq!(ev.details["method"], "rdp"); // LogonType 10
        assert!(ev.entities.contains(&EntityRef::ip("198.51.100.23")));
        assert!(ev.entities.contains(&EntityRef::user("Administrator")));
    }

    #[test]
    fn parse_4624_drops_service_type5() {
        // LogonType 5 (service) is not a human logon -> dropped.
        let p = parse(F_4624_SVC);
        assert_eq!(p.record_id, 500124);
        assert!(p.event.is_none());
    }

    #[test]
    fn parse_4624_drops_machine_account() {
        // TargetUserName ends with '$' (machine account) -> dropped.
        let p = parse(F_4624_MACHINE);
        assert_eq!(p.record_id, 500125);
        assert!(p.event.is_none());
    }

    // ── Process create (4688 hex pid + Sysmon 1 decimal pid) ─────────────

    #[test]
    fn parse_4688_shell_command_exec_hex_pid() {
        let p = parse(F_4688);
        assert_eq!(p.record_id, 771001);
        let ev = p.event.expect("4688 must emit");
        assert_eq!(ev.kind, "shell.command_exec");
        assert_eq!(ev.source, "etw");
        // NewProcessId 0x1a4 = 420 -> pid MUST be a JSON number (as_u64()).
        assert_eq!(ev.details["pid"].as_u64(), Some(420));
        // ProcessId (creator) 0x4d8 = 1240 -> ppid.
        assert_eq!(ev.details["ppid"].as_u64(), Some(1240));
        assert_eq!(ev.details["comm"], "net.exe");
        assert_eq!(ev.details["ppid_comm"], "cmd.exe");
        assert_eq!(ev.details["parent_comm"], "cmd.exe");
        assert!(ev.details["command"]
            .as_str()
            .unwrap()
            .contains("net  user hacker"));
        // Non-SYSTEM SID -> uid 1000.
        assert_eq!(ev.details["uid"].as_u64(), Some(1000));
    }

    #[test]
    fn parse_sysmon1_shell_command_exec() {
        let p = parse(F_SYSMON1);
        assert_eq!(p.record_id, 88231);
        let ev = p.event.expect("Sysmon 1 must emit");
        assert_eq!(ev.kind, "shell.command_exec");
        // Decimal ProcessId 6321.
        assert_eq!(ev.details["pid"].as_u64(), Some(6321));
        assert_eq!(ev.details["ppid"].as_u64(), Some(6100));
        assert_eq!(ev.details["comm"], "powershell.exe");
        assert_eq!(ev.details["user"], "WIN-WKS01\\alice");
        assert_eq!(ev.details["username"], "WIN-WKS01\\alice");
        // argv MUST be a non-empty array (system_user_interactive.rs:149).
        let argv = ev.details["argv"].as_array().expect("argv is an array");
        assert!(!argv.is_empty());
        assert_eq!(argv[0], "powershell.exe");
        // Entity-escaped '&amp;' in the CommandLine must be unescaped so
        // reverse_shell's text scan sees the real operators.
        let command = ev.details["command"].as_str().unwrap();
        assert!(!command.contains("&amp;"), "entity must be unescaped");
        assert!(command.contains("&&"), "unescaped '&&' expected in command");
    }

    // ── Sysmon 3 outbound network ────────────────────────────────────────

    #[test]
    fn parse_sysmon3_network_outbound_connect() {
        let p = parse(F_SYSMON3_OUT);
        assert_eq!(p.record_id, 88240);
        let ev = p.event.expect("initiated outbound must emit");
        assert_eq!(ev.kind, "network.outbound_connect");
        assert_eq!(ev.details["dst_ip"], "203.0.113.9");
        // dst_port MUST be a JSON number (c2_callback.rs:148 as_u64()).
        assert_eq!(ev.details["dst_port"].as_u64(), Some(4444));
        // Full image path preserved for imds_ssrf's non-forgeable identity.
        assert!(ev.details["exe_path"]
            .as_str()
            .unwrap()
            .ends_with("evil.exe"));
        assert_eq!(ev.details["pid"].as_u64(), Some(6321));
        // Port 4444 is a classic implant port -> High.
        assert_eq!(ev.severity, Severity::High);
        assert!(ev.entities.contains(&EntityRef::ip("203.0.113.9")));
        assert!(ev.entities.contains(&EntityRef::user("WIN-WKS01\\alice")));
    }

    #[test]
    fn parse_sysmon3_drops_inbound() {
        // Initiated=false (inbound) -> no outbound event.
        let p = parse(F_SYSMON3_IN);
        assert_eq!(p.record_id, 88241);
        assert!(p.event.is_none());
    }

    #[test]
    fn parse_sysmon3_drops_loopback() {
        // DestinationIp 127.0.0.1 -> dropped even though Initiated=true.
        let p = parse(F_SYSMON3_LOOP);
        assert_eq!(p.record_id, 88242);
        assert!(p.event.is_none());
    }

    #[test]
    fn is_local_dest_drops_loopback_linklocal_but_keeps_imds() {
        // Dropped (never reported as an outbound C2 connection):
        assert!(is_local_dest("127.0.0.1"));
        assert!(is_local_dest("::1"));
        assert!(is_local_dest("169.254.1.5")); // generic link-local
        assert!(is_local_dest("fe80::1"));
        // NOT dropped: 169.254.169.254 is the cloud IMDS endpoint, a real
        // SSRF/exfil target that imds_ssrf consumes.
        assert!(!is_local_dest("169.254.169.254"));
        // Ordinary routable addresses pass through.
        assert!(!is_local_dest("203.0.113.9"));
    }

    #[test]
    fn drain_should_continue_guards_progress() {
        // Short batch -> caught up, stop.
        assert!(!drain_should_continue(5, 256, 100, 200));
        // Full batch that advanced the watermark -> keep draining.
        assert!(drain_should_continue(256, 256, 100, 200));
        // Full batch that did NOT advance (all records at/below the watermark)
        // -> stop; the no-progress guard prevents an infinite loop.
        assert!(!drain_should_continue(256, 256, 100, 100));
    }

    // ── Uninteresting / malformed ────────────────────────────────────────

    #[test]
    fn parse_unknown_eid_advances_only() {
        // 4720 (user created) has no zero-change consumer: advance the
        // watermark, emit nothing.
        let p = parse(F_4720);
        assert_eq!(p.record_id, 771050);
        assert!(p.event.is_none());
    }

    #[test]
    fn parse_malformed_returns_none() {
        // No EventRecordID -> cannot advance a watermark -> None.
        assert!(parse_win_event(
            "<Event><System><EventID>4625</EventID></System></Event>",
            "h"
        )
        .is_none());
        assert!(parse_win_event("not xml at all <broken", "h").is_none());
        assert!(parse_win_event("", "h").is_none());
    }

    #[test]
    fn parse_missing_ip_drops_but_advances() {
        // 4625 without IpAddress: valid record (advance) but nothing to emit.
        let xml = "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/>\
                   <EventID>4625</EventID><EventRecordID>42</EventRecordID></System>\
                   <EventData><Data Name='TargetUserName'>bob</Data></EventData></Event>";
        let p = parse(xml);
        assert_eq!(p.record_id, 42);
        assert!(p.event.is_none());
    }

    // ── split_event_records ──────────────────────────────────────────────

    #[test]
    fn split_event_records_segments_stream() {
        let stream = "<?xml version='1.0'?><Events>\
            <Event xmlns='urn:x'><System><EventRecordID>1</EventRecordID></System>A</Event>\
            <Event xmlns='urn:x'><System><EventRecordID>2</EventRecordID></System>B</Event>\
            </Events>";
        let recs = split_event_records(stream);
        assert_eq!(recs.len(), 2, "the <Events> wrapper must not be counted");
        assert!(recs[0].contains(">A<") || recs[0].contains("A</Event>"));
        assert!(recs[1].contains("B</Event>"));
        // The wrapper token itself is never emitted as a record.
        assert!(recs.iter().all(|r| r.starts_with("<Event ")));
    }

    #[test]
    fn split_event_records_handles_empty_and_truncated() {
        assert!(split_event_records("").is_empty());
        assert!(split_event_records("<Events></Events>").is_empty());
        // Truncated tail (no closing tag) yields nothing rather than panicking.
        assert!(split_event_records("<Event xmlns='x'>no close").is_empty());
    }

    // ── wevtutil arg builders ────────────────────────────────────────────

    #[test]
    fn wevtutil_query_args_builds_static_xpath_and_watermark() {
        let args = wevtutil_query_args("Security", 500, 200, &[4625, 4624, 4688]);
        assert_eq!(args[0], "qe");
        assert_eq!(args[1], "Security");
        let query = &args[2];
        assert!(query.starts_with("/q:*[System["));
        assert!(query.contains("EventID=4625"));
        assert!(query.contains("EventID=4624"));
        assert!(query.contains("EventID=4688"));
        assert!(query.contains("EventRecordID>500"));
        assert!(args.contains(&"/f:xml".to_string()));
        assert!(args.contains(&"/rd:false".to_string())); // oldest-first forward drain
        assert!(args.contains(&"/c:200".to_string()));
    }

    #[test]
    fn wevtutil_query_args_without_eids_filters_only_on_record_id() {
        let args = wevtutil_query_args("Application", 10, 50, &[]);
        let query = &args[2];
        assert!(query.contains("EventRecordID>10"));
        assert!(!query.contains("EventID="));
    }

    #[test]
    fn wevtutil_max_probe_args_is_newest_single_record() {
        let args = wevtutil_max_probe_args("Security");
        assert_eq!(args[0], "qe");
        assert_eq!(args[1], "Security");
        assert!(args.contains(&"/c:1".to_string()));
        assert!(args.contains(&"/rd:true".to_string())); // newest first
    }

    // ── watermark math ───────────────────────────────────────────────────

    #[test]
    fn advance_watermark_higher_lower_reset_and_noop() {
        let mut wm = 100;
        // Higher -> advances.
        advance_watermark(
            &Some(ParsedEtw {
                record_id: 150,
                event: None,
            }),
            &mut wm,
        );
        assert_eq!(wm, 150);
        // Lower -> never regresses (out-of-order guard).
        advance_watermark(
            &Some(ParsedEtw {
                record_id: 120,
                event: None,
            }),
            &mut wm,
        );
        assert_eq!(wm, 150);
        // Equal -> no-op.
        advance_watermark(
            &Some(ParsedEtw {
                record_id: 150,
                event: None,
            }),
            &mut wm,
        );
        assert_eq!(wm, 150);
        // Malformed (None) -> no-op.
        advance_watermark(&None, &mut wm);
        assert_eq!(wm, 150);
        // RESET: a fresh max BELOW the watermark (log cleared) re-baselines.
        assert!(rebaseline_watermark_on_reset(Some(10), &mut wm));
        assert_eq!(wm, 10);
        // A fresh max at/above the watermark does NOT reset (would skip records).
        assert!(!rebaseline_watermark_on_reset(Some(50), &mut wm));
        assert_eq!(wm, 10);
        assert!(!rebaseline_watermark_on_reset(None, &mut wm));
        assert_eq!(wm, 10);
    }

    // ── availability probe ───────────────────────────────────────────────

    #[test]
    fn wevtutil_usable_maps_banner_and_spawn() {
        assert!(wevtutil_usable(
            true,
            "Windows Events Command Line Utility.\nUsage: wevtutil COMMAND ...\n\
             qe | query-events ...",
        ));
        assert!(!wevtutil_usable(true, "some unrelated tool output"));
        assert!(!wevtutil_usable(false, "")); // did not spawn
    }

    // Constructs an ExitStatus via the unix from_raw; gate to unix so a future
    // `cargo test` on Windows still compiles (probe_says_usable itself is
    // OS-independent and covered on the unix runners).
    #[cfg(unix)]
    #[test]
    fn probe_says_usable_maps_output_and_spawn_error() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::{ExitStatus, Output};
        // Real wevtutil usage (nonzero exit for `/?` is fine; we ignore it).
        let real = Ok(Output {
            status: ExitStatus::from_raw(0),
            stdout: b"wevtutil: query-events (qe)\n".to_vec(),
            stderr: Vec::new(),
        });
        assert!(probe_says_usable(&real));
        // Some foreign binary on PATH.
        let foreign = Ok(Output {
            status: ExitStatus::from_raw(0),
            stdout: b"usage: something else\n".to_vec(),
            stderr: Vec::new(),
        });
        assert!(!probe_says_usable(&foreign));
        // Not Windows / not installed -> spawn error.
        let missing: std::io::Result<Output> =
            Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(!probe_says_usable(&missing));
    }

    // ── low-level pure helpers ───────────────────────────────────────────

    #[test]
    fn xml_unescape_handles_entities_and_numeric_refs() {
        assert_eq!(xml_unescape("a &amp; b"), "a & b");
        assert_eq!(xml_unescape("&lt;x&gt;"), "<x>");
        assert_eq!(xml_unescape("&quot;q&apos;"), "\"q'");
        assert_eq!(xml_unescape("&#60;&#x3e;"), "<>");
        // Malformed entity is preserved literally (never lose attacker text).
        assert_eq!(xml_unescape("100% & rising"), "100% & rising");
        assert_eq!(xml_unescape("no entities"), "no entities");
    }

    #[test]
    fn win_basename_splits_backslash_and_slash() {
        assert_eq!(win_basename("C:\\Windows\\System32\\cmd.exe"), "cmd.exe");
        assert_eq!(win_basename("/usr/bin/whoami"), "whoami");
        assert_eq!(win_basename("bare.exe"), "bare.exe");
    }

    #[test]
    fn parse_pid_handles_hex_and_decimal() {
        assert_eq!(parse_pid("0x1a4"), Some(420));
        assert_eq!(parse_pid("0X4D8"), Some(1240));
        assert_eq!(parse_pid("6321"), Some(6321));
        assert_eq!(parse_pid("not-a-pid"), None);
    }

    #[test]
    fn split_command_line_is_quote_aware() {
        let argv = split_command_line("cmd.exe /c \"echo hi there\" tail");
        assert_eq!(argv, vec!["cmd.exe", "/c", "echo hi there", "tail"]);
        assert!(split_command_line("").is_empty());
    }

    #[test]
    fn event_data_map_extracts_named_data_and_unescapes() {
        let xml = "<EventData><Data Name='IpAddress'>1.2.3.4</Data>\
                   <Data Name='Cmd'>a &amp;&amp; b</Data>\
                   <Data Name='Empty'/></EventData>";
        let m = event_data_map(xml);
        assert_eq!(m.get("IpAddress").map(String::as_str), Some("1.2.3.4"));
        assert_eq!(m.get("Cmd").map(String::as_str), Some("a && b"));
        assert_eq!(m.get("Empty").map(String::as_str), Some(""));
    }

    #[test]
    fn provider_name_reads_name_not_eventsourcename() {
        let xml = "<Provider Name='Microsoft-Windows-Sysmon' Guid='{x}'/>";
        assert_eq!(
            provider_name(xml).as_deref(),
            Some("Microsoft-Windows-Sysmon")
        );
        // `Name=` must not be captured from inside `EventSourceName=`.
        let tricky = "<Provider EventSourceName='Foo' Name='Real'/>";
        assert_eq!(provider_name(tricky).as_deref(), Some("Real"));
    }

    #[test]
    fn synth_uid_system_vs_user() {
        assert_eq!(synth_uid(Some("S-1-5-18"), ""), 0);
        assert_eq!(synth_uid(Some("S-1-5-21-1-2-3-500"), ""), 1000);
        assert_eq!(synth_uid(None, "NT AUTHORITY\\SYSTEM"), 0);
        assert_eq!(synth_uid(None, "WIN-WKS01\\alice"), 1000);
    }
}
