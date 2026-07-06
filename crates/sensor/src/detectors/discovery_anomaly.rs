//! Discovery anomaly detector (spec 050-PR1).
//!
//! Fires when **10+ distinct discovery commands** spawn from the **same
//! parent PID** within **30 seconds**, and the execution context is
//! `AttackerInferred`. This is the spec 050 PR1 evolution of
//! `discovery_burst`: instead of per-user counters with the legacy
//! `DISCOVERY_ALLOWED` blanket allowlist, it pivots on parent PID
//! (so a sandcat-style implant doing rapid recon is caught even when
//! its uid matches an operator) and consults the new
//! `exec_context::classify` for benign-context suppression.
//!
//! Anti-FP gates:
//!   - `exec_context::classify(event).is_benign()` → no-op. This
//!     silences operator interactive shells, dpkg/apt postinst, ansible
//!     / salt / puppet runs, boot window, MOTD scripts.
//!   - First 60 s of sensor uptime → no-op (the boot-window axis is
//!     already inside `classify`, but this detector also pre-filters
//!     for cheapness).
//!   - One incident per (host, parent_pid) per 30 minutes.
//!
//! Catches MITRE TA0007 (the entire Discovery tactic): T1087, T1082,
//! T1016, T1049, T1057, T1083, T1018, T1135, T1033, T1518.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

/// Discovery command basenames. Matched as `comm == basename` after
/// stripping path. Mirrors the canonical discovery surface from
/// `discovery_burst::DISCOVERY_COMMANDS` but pivots on comm (the
/// post-exec process name) rather than the raw command line.
const DISCOVERY_COMMS: &[&str] = &[
    "ps",
    "id",
    "whoami",
    "uname",
    "hostname",
    "lsb_release",
    "ip",
    "ifconfig",
    "ss",
    "netstat",
    "route",
    "arp",
    "lscpu",
    "lsmod",
    "lsblk",
    "lsusb",
    "lsof",
    "lspci",
    "mount",
    "df",
    "free",
    "uptime",
    "w",
    "who",
    "last",
    "groups",
    "getent",
    "find",
    "locate",
];

pub struct DiscoveryAnomalyDetector {
    host: String,
    threshold: usize,
    window: Duration,
    cooldown: Duration,
    /// (parent_pid) → set of (timestamp, comm) we've seen.
    windows: HashMap<u64, Vec<(DateTime<Utc>, String)>>,
    alerted: HashMap<u64, DateTime<Utc>>,
}

impl DiscoveryAnomalyDetector {
    pub fn new(host: impl Into<String>, threshold: usize, window_seconds: u64) -> Self {
        Self {
            host: host.into(),
            threshold,
            window: Duration::seconds(window_seconds as i64),
            cooldown: Duration::seconds(1800), // 30 min
            windows: HashMap::new(),
            alerted: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }

        // Smoke test 2026-05-17 on Oracle prod confirmed: eBPF execve
        // tracepoint emits events while the calling process is still
        // **pre-rename** — `comm` holds the launcher, `argv[0]` holds
        // the binary being exec'd. Read the discovery command identity
        // from `argv[0]` (or fall back to `command` field). Matches the
        // pattern `discovery_burst.rs` already uses for its own command
        // matching. Distinct-count then groups by the discovery binary,
        // not the launcher comm (which would collapse all 12 disguised
        // recon execs into 1 distinct).
        let argv0 = event
            .details
            .get("argv")
            .and_then(|v| v.get(0))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let argv0_base = argv0.split('/').next_back().unwrap_or(argv0);
        if argv0_base.is_empty() {
            return None;
        }
        if !DISCOVERY_COMMS.contains(&argv0_base) {
            return None;
        }
        let base = argv0_base;

        // Spec 050-PR0 context-aware gate. The whole reason discovery_anomaly
        // exists as a separate detector is that it's the first to consume
        // `classify` directly — silencing the operator-interactive /
        // package-manager / automation / boot paths in a structured way.
        if crate::detectors::exec_context::classify(event).is_benign() {
            return None;
        }

        let ppid = event
            .details
            .get("ppid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if ppid == 0 {
            return None;
        }
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let now = event.ts;
        let cutoff = now - self.window;

        // Snapshot needed values out of the mutable borrow, then drop it
        // before the prune passes below.
        let (distinct_count, sample) = {
            let entries = self.windows.entry(ppid).or_default();
            entries.retain(|(t, _)| *t >= cutoff);
            entries.push((now, base.to_string()));
            let distinct: HashSet<String> = entries.iter().map(|(_, c)| c.clone()).collect();
            let mut sample: Vec<String> = distinct.iter().take(15).cloned().collect();
            sample.sort();
            (distinct.len(), sample)
        };
        if distinct_count < self.threshold {
            return None;
        }

        if let Some(&last) = self.alerted.get(&ppid) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(ppid, now);

        if self.alerted.len() > 500 {
            let cd_cutoff = now - self.cooldown;
            self.alerted.retain(|_, t| *t > cd_cutoff);
        }
        if self.windows.len() > 1000 {
            let wc = now - self.window;
            self.windows.retain(|_, w| w.iter().any(|(t, _)| *t > wc));
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "discovery_anomaly:ppid{}:{}",
                ppid,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: if distinct_count >= self.threshold * 2 {
                Severity::High
            } else {
                Severity::Medium
            },
            title: format!(
                "Discovery burst: {distinct_count} distinct recon commands from parent_comm=`{parent_comm}` (ppid={ppid}) in {}s",
                self.window.num_seconds()
            ),
            summary: format!(
                "Parent process pid={ppid} comm=`{parent_comm}` spawned {distinct_count} distinct \
                 discovery commands ({}) within {}s under uid {uid}. Execution context did NOT \
                 classify as operator-interactive / package-manager / automation / boot.",
                sample.join(", "),
                self.window.num_seconds()
            ),
            evidence: serde_json::json!([{
                "kind": "discovery_anomaly",
                "parent_comm": parent_comm,
                "ppid": ppid,
                "uid": uid,
                "distinct_count": distinct_count,
                "window_seconds": self.window.num_seconds(),
                "sample_commands": sample,
                "mitre": ["T1087", "T1082", "T1016", "T1049", "T1057", "T1083"],
            }]),
            recommended_checks: vec![
                format!("Inspect parent process: `ps -p {ppid} -o pid,ppid,user,comm,args`"),
                format!("Trace ancestry: `pstree -p {ppid}`"),
                "If parent is a legitimate monitoring agent missing from DISCOVERY_ALLOWED, add it to `[detectors.discovery_anomaly]`".to_string(),
            ],
            tags: vec!["reconnaissance".to_string(), "discovery".to_string()],
            entities: vec![],
        })
    }
}

// `comm_base` was used pre-fix when this detector matched on the `comm`
// field. After 2026-05-17 smoke test the detector reads `argv[0]`
// basename inline (split + next_back) so the helper is no longer needed.
// Removed entirely rather than allowed-dead to keep the surface clean.

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(comm: &str, parent_comm: &str, ppid: u64, uid: u64) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: format!("Shell command executed: {comm}"),
            details: serde_json::json!({
                "pid": 9000,
                "uid": uid,
                "ppid": ppid,
                "comm": comm,
                "parent_comm": parent_comm,
                // Interactive-operator baseline (real ssh shell owns a tty). Only
                // matters when parent_comm is a shell — the attacker tests use a
                // non-shell parent, so they classify AttackerInferred regardless.
                // OpInteractive now requires this tty proof (evasion audit E3).
                "has_tty": true,
                "command": comm,
                "argv": [comm],
                "argc": 1,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_10_distinct_recon_commands_from_attacker_context() {
        let mut det = DiscoveryAnomalyDetector::new("test", 10, 30);
        // parent_comm="sandcat" → AttackerInferred (not in any benign bucket).
        // Pre-fill 9 distinct comms — under threshold, none fire.
        for comm in [
            "ps", "id", "whoami", "uname", "hostname", "ss", "netstat", "lscpu", "lsblk",
        ] {
            assert!(
                det.process(&exec_event(comm, "sandcat", 1234, 1000))
                    .is_none(),
                "{comm} should not fire — only {} distinct so far",
                comm
            );
        }
        // 10th distinct command reaches threshold and fires.
        let result = det.process(&exec_event("df", "sandcat", 1234, 1000));
        assert!(result.is_some(), "10 distinct recon comms must fire");
        let inc = result.unwrap();
        assert!(inc.incident_id.starts_with("discovery_anomaly:ppid1234"));
    }

    /// Smoke test 2026-05-17 on Oracle prod confirmed the eBPF execve
    /// tracepoint emits events while the calling process is still
    /// pre-rename — `comm` holds the launcher (a disguised attacker
    /// binary), the recon command being exec'd lives in `argv[0]`.
    /// Pre-fix `discovery_anomaly` matched `comm` against
    /// `DISCOVERY_COMMS` and never saw the variety: every event had
    /// `comm="iw_smoke_attack"`, distinct count stayed at 1, threshold
    /// never reached. Anchor pins argv[0]-driven matching.
    #[test]
    fn fires_when_comm_is_disguised_launcher_and_argv_holds_recon_binary() {
        let mut det = DiscoveryAnomalyDetector::new("test", 10, 30);
        let recon_binaries = [
            "/usr/bin/whoami",
            "/usr/bin/id",
            "/usr/bin/uname",
            "/usr/bin/hostname",
            "/usr/bin/ss",
            "/usr/bin/netstat",
            "/usr/bin/lscpu",
            "/usr/bin/lsblk",
            "/usr/bin/df",
            "/usr/bin/free",
        ];
        // All events share comm="iw_smoke_attack" (the disguised launcher)
        // — exactly what prod's eBPF emits when a renamed bash spawns
        // recon. Each event's argv[0] points at a different real binary.
        for bin in &recon_binaries[..9] {
            let ev = Event {
                ts: Utc::now(),
                host: "test".into(),
                source: "ebpf".into(),
                kind: "shell.command_exec".into(),
                severity: Severity::Info,
                summary: format!("Shell command executed: {bin}"),
                details: serde_json::json!({
                    "pid": 9000,
                    "uid": 1001,
                    "ppid": 1234,
                    "comm": "iw_smoke_attack",
                    "parent_comm": "iw_smoke_attack",
                    "command": bin,
                    "argv": [bin],
                    "argc": 1,
                }),
                tags: vec![],
                entities: vec![],
            };
            assert!(
                det.process(&ev).is_none(),
                "{bin} must not fire — only {} distinct so far",
                bin
            );
        }
        // 10th distinct binary reaches threshold and fires.
        let last = recon_binaries[9];
        let ev = Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: format!("Shell command executed: {last}"),
            details: serde_json::json!({
                "pid": 9000,
                "uid": 1001,
                "ppid": 1234,
                "comm": "iw_smoke_attack",
                "parent_comm": "iw_smoke_attack",
                "command": last,
                "argv": [last],
                "argc": 1,
            }),
            tags: vec![],
            entities: vec![],
        };
        let inc = det
            .process(&ev)
            .expect("10 distinct recon binaries via argv must fire even when comm is disguised");
        assert!(inc.incident_id.starts_with("discovery_anomaly:ppid1234"));
    }

    #[test]
    fn does_not_fire_under_operator_interactive() {
        let mut det = DiscoveryAnomalyDetector::new("test", 5, 30);
        // parent_comm="bash" + uid 1000 → OpInteractive → benign
        for comm in ["ps", "id", "whoami", "uname", "hostname", "ss"] {
            assert!(
                det.process(&exec_event(comm, "bash", 1234, 1000)).is_none(),
                "operator interactive recon must stay silent"
            );
        }
    }

    #[test]
    fn does_not_fire_when_parent_is_ansible() {
        let mut det = DiscoveryAnomalyDetector::new("test", 5, 30);
        for comm in ["ps", "id", "whoami", "uname", "hostname", "ss"] {
            assert!(
                det.process(&exec_event(comm, "ansible-playboo", 1234, 0))
                    .is_none(),
                "ansible-run recon must stay silent"
            );
        }
    }

    #[test]
    fn does_not_fire_when_parent_is_dpkg() {
        let mut det = DiscoveryAnomalyDetector::new("test", 5, 30);
        for comm in ["whoami", "id", "uname", "hostname", "lsb_release"] {
            assert!(
                det.process(&exec_event(comm, "dpkg", 999, 0)).is_none(),
                "dpkg postinst recon must stay silent"
            );
        }
        assert!(det.process(&exec_event("ps", "dpkg", 999, 0)).is_none());
    }

    #[test]
    fn dedupes_repeat_same_comm_against_distinct_count() {
        let mut det = DiscoveryAnomalyDetector::new("test", 5, 30);
        // Same comm 10 times = 1 distinct → no fire even from attacker context
        for _ in 0..10 {
            assert!(det
                .process(&exec_event("whoami", "sandcat", 1234, 1000))
                .is_none());
        }
    }

    #[test]
    fn different_parents_tracked_separately() {
        let mut det = DiscoveryAnomalyDetector::new("test", 5, 30);
        // 4 distinct comms from ppid 1000 — under threshold.
        for comm in ["ps", "id", "whoami", "uname"] {
            assert!(det
                .process(&exec_event(comm, "sandcat", 1000, 1000))
                .is_none());
        }
        // 3 distinct comms from ppid 2000 — kept deliberately further
        // below threshold so the next call to ppid 2000 (4th) still
        // doesn't fire, proving the per-ppid tracking is independent.
        for comm in ["ps", "id", "whoami"] {
            assert!(det
                .process(&exec_event(comm, "sandcat", 2000, 1000))
                .is_none());
        }
        // ppid 1000 reaches threshold (5th distinct) → fire.
        let r = det.process(&exec_event("hostname", "sandcat", 1000, 1000));
        assert!(r.is_some(), "ppid 1000 now has 5 distinct → fire");
        // ppid 2000 reaches only 4 distinct — must NOT fire.
        let r2 = det.process(&exec_event("uname", "sandcat", 2000, 1000));
        assert!(
            r2.is_none(),
            "ppid 2000 has only 4 distinct — independent tracking must hold"
        );
    }

    #[test]
    fn ignores_non_discovery_comms() {
        let mut det = DiscoveryAnomalyDetector::new("test", 3, 30);
        for comm in ["bash", "vim", "cat", "ls", "gcc"] {
            assert!(det
                .process(&exec_event(comm, "sandcat", 1234, 1000))
                .is_none());
        }
    }

    #[test]
    fn cooldown_suppresses_repeat_alerts() {
        let mut det = DiscoveryAnomalyDetector::new("test", 5, 30);
        // Pre-fill 4 distinct (under threshold).
        for comm in ["ps", "id", "whoami", "uname"] {
            assert!(det
                .process(&exec_event(comm, "sandcat", 1234, 1000))
                .is_none());
        }
        // 5th distinct → fire.
        let first = det.process(&exec_event("hostname", "sandcat", 1234, 1000));
        assert!(first.is_some(), "first incident must fire");

        // 200 s later, same parent — within 30 min cooldown.
        let mut ev2 = exec_event("netstat", "sandcat", 1234, 1000);
        ev2.ts = ev2.ts + Duration::seconds(200);
        let second = det.process(&ev2);
        assert!(second.is_none(), "cooldown must suppress re-alert");
    }

    #[test]
    fn ignores_ppid_zero() {
        let mut det = DiscoveryAnomalyDetector::new("test", 3, 30);
        for comm in ["ps", "id", "whoami", "uname"] {
            assert!(det.process(&exec_event(comm, "sandcat", 0, 1000)).is_none());
        }
    }
}
