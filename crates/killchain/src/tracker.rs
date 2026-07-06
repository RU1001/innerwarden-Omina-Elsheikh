//! PID chain tracker — mirrors kernel PID_CHAIN in userspace.
//! Processes eBPF events, accumulates bit flags per PID, and emits
//! pre-chain warnings and full-match incidents.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info};

use crate::bridge;
use crate::patterns::*;
use crate::types::{ChainEvent, PidChainState};

/// True when a read path is a genuine credential/secret whose exfiltration
/// matters, for the DATA_EXFIL chain (`sensitive_read + socket`).
///
/// Deliberately tight. The previous list included `/etc/passwd` and the whole
/// `.ssh/` directory, which made every download tool trip DATA_EXFIL:
/// `/etc/passwd` is world-readable, holds no secrets since `/etc/shadow`
/// exists, and is read by virtually every process via glibc nss
/// (`getpwuid`/`getpwnam`); `.ssh/known_hosts` and `.ssh/config` are read by
/// git/ssh on every connection. Combined with any outbound connect (e.g. apt,
/// snap, curl, rustup fetching from a CDN/mirror) that produced a flood of
/// false-positive DATA_EXFIL incidents. The real exfil signal is the shadow
/// hashes, private keys, and cloud/app credentials kept here; reading
/// `/etc/passwd` alone is account *discovery* (T1087), handled elsewhere, not
/// exfil.
pub(crate) fn is_sensitive_read_path(path: &str) -> bool {
    path.contains("/etc/shadow") // also matches /etc/shadow-
        || path.contains("/etc/gshadow")
        || path.contains("/etc/sudoers")
        || path.contains(".ssh/id_") // private keys (id_rsa/id_ed25519/...)
        || path.contains(".ssh/authorized_keys")
        || path.contains("/.env") // dotenv secrets; "/.env" excludes *.env files
        || path.contains(".gnupg/")
        || path.contains(".netrc")
        // Cloud / cluster credentials — explicit files, not the bare
        // "credentials" substring (which matched benign credentials-cache
        // dirs). Each is the canonical secret for its provider.
        || path.contains(".aws/credentials")
        || path.contains(".docker/config.json")
        || path.contains("gcloud/application_default_credentials.json")
        || path.contains(".azure/accessTokens.json")
        || path.contains(".kube/config")
        || path.contains("/var/run/secrets/kubernetes.io/serviceaccount/token")
    // KNOWN LIMITATIONS (out of scope for substring matching — do not try to
    // close them here):
    //   - copy/hardlink/symlink-to-tmp: `cp /etc/shadow /tmp/x` then read
    //     `/tmp/x` evades any path match. Needs inode-identity tracking in the
    //     eBPF file_open hook, not this list.
    //   - fd re-open / `/proc/self/fd/N` / `/proc/self/root/...` aliases.
    //   - This is the userspace kill-chain trigger ONLY. The sensor's eBPF
    //     openat emits `file.read_access` for the much broader `/etc`,`/root`,
    //     `/home` set (rate-limited telemetry) and sets its own in-kernel
    //     CHAIN_SENSITIVE_READ; that broader bit is a separate code path with
    //     a separate FP profile and is NOT changed here.
}

// ---------------------------------------------------------------------------
// PidTracker
// ---------------------------------------------------------------------------

pub struct PidTracker {
    pids: HashMap<u32, PidChainState>,
    session_timeout_secs: i64,
    /// Fraction of bits that must be set before emitting a pre-chain warning.
    /// Default: 0.67 (i.e. 2 out of 3 bits).
    pre_chain_threshold: f32,
    /// Process names (`comm`) whose events are ignored entirely. Used to
    /// prevent the platform from flagging its own threads (e.g. the agent's
    /// `tokio-rt-worker` threads read credentials + call outbound APIs, which
    /// trivially matches DATA_EXFIL even though there is no attack).
    excluded_comms: HashSet<String>,
}

impl PidTracker {
    pub fn new() -> Self {
        Self {
            pids: HashMap::new(),
            session_timeout_secs: 300, // 5 minutes
            pre_chain_threshold: 0.6,
            excluded_comms: HashSet::new(),
        }
    }

    pub fn with_timeout(mut self, secs: i64) -> Self {
        self.session_timeout_secs = secs;
        self
    }

    pub fn with_pre_chain_threshold(mut self, threshold: f32) -> Self {
        self.pre_chain_threshold = threshold;
        self
    }

    /// Replace the set of `comm` names whose events are ignored. Typical
    /// callers pass their own platform/infra thread names so they are not
    /// treated as attackers.
    pub fn with_excluded_comms<I, S>(mut self, comms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.excluded_comms = comms.into_iter().map(Into::into).collect();
        self
    }

    /// Returns true if the given `comm` is in the exclusion set.
    pub fn is_excluded_comm(&self, comm: &str) -> bool {
        self.excluded_comms.contains(comm)
    }

    /// Insert a pre-built PidChainState (used in tests).
    #[cfg(test)]
    pub fn insert_state(&mut self, state: crate::types::PidChainState) {
        self.pids.insert(state.pid, state);
    }

    // ------------------------------------------------------------------
    // Core event processing
    // ------------------------------------------------------------------

    /// Process a single eBPF event JSON and return zero or more incidents.
    ///
    /// Expected event shape:
    /// ```json
    /// {
    ///   "kind": "network.outbound_connect",
    ///   "ts": "2026-03-26T14:23:01Z",
    ///   "host": "production",
    ///   "details": { "pid": 1234, "uid": 1000, "comm": "python3", ... }
    /// }
    /// ```
    pub fn process_event(&mut self, event: &Value) -> Vec<Value> {
        // 1. Extract fields from the event JSON
        let kind = match event.get("kind").and_then(|v| v.as_str()) {
            Some(k) => k.to_string(),
            None => return vec![],
        };

        let details = match event.get("details") {
            Some(d) => d,
            None => return vec![],
        };

        let pid = match details.get("pid").and_then(|v| v.as_u64()) {
            Some(p) => p as u32,
            None => return vec![],
        };

        let uid = details.get("uid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        let comm = details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Skip events from processes the caller explicitly excluded (e.g. the
        // platform's own threads). Without this, long-running daemons that
        // legitimately mix outbound I/O with sensitive file reads trip DATA_EXFIL
        // against themselves.
        if self.excluded_comms.contains(&comm) {
            return vec![];
        }

        let ts_str = event.get("ts").and_then(|v| v.as_str()).unwrap_or("");

        let ts: DateTime<Utc> = ts_str.parse().unwrap_or_else(|_| Utc::now());

        let host = event
            .get("host")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // 2. Handle clone/fork — propagate parent's chain flags to child
        if kind == "process.clone" {
            // The PID in the clone event is the parent.
            // When we later see events from a child PID that shares the same
            // uid/comm, we check if the parent had chain flags and propagate.
            // For now, we store the parent's flags so get_state can return them.
            // The child will inherit when its first event arrives (see below).
            if let Some(parent_state) = self.pids.get(&pid) {
                if parent_state.flags != 0 {
                    debug!(
                        parent_pid = pid,
                        flags = format!("0x{:02x}", parent_state.flags),
                        "clone detected — parent has chain flags, child will inherit"
                    );
                }
            }
            return vec![];
        }

        // 2b. Map event kind to bit flag.
        //
        // `captured_sensitive_path` carries the file path out of the
        // `file.open`/`file.read_access` arm so it can be recorded on the
        // per-PID state below and surfaced into the DATA_EXFIL incident
        // evidence (`sensitive_file`). Spec-081: the kernel-block managed-agent
        // verifier needs to know WHAT was read to apply its own-config gate.
        let mut captured_sensitive_path: Option<String> = None;
        let flag = match kind.as_str() {
            "network.outbound_connect" => CHAIN_SOCKET,
            "network.bind_listen" => CHAIN_BIND,
            "network.listen" => CHAIN_LISTEN,
            "process.ptrace_attach" => CHAIN_PTRACE,
            "process.fd_redirect" => {
                let newfd = details
                    .get("newfd")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(u64::MAX);
                match newfd {
                    0 => CHAIN_DUP_STDIN,
                    1 => CHAIN_DUP_STDOUT,
                    2 => CHAIN_DUP_STDERR,
                    _ => return vec![],
                }
            }
            "memory.mprotect_exec" => {
                let rwx = details
                    .get("rwx")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !rwx {
                    return vec![];
                }
                CHAIN_MPROTECT
            }
            // Sensitive file access (openat on /etc/shadow, private keys, creds).
            "file.open" | "file.read_access" => {
                let path = details
                    .get("filename")
                    .or_else(|| details.get("path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !is_sensitive_read_path(path) {
                    return vec![];
                }
                captured_sensitive_path = Some(path.to_string());
                CHAIN_SENSITIVE_READ
            }
            _ => return vec![],
        };

        // 3. Create or update PidChainState
        let state = self
            .pids
            .entry(pid)
            .or_insert_with(|| PidChainState::new(pid, uid, comm.clone(), host.clone(), ts));

        // Build chain event and merge flag
        let chain_event = ChainEvent {
            ts,
            syscall: kind.clone(),
            details: details.clone(),
            flag_set: flag,
        };
        state.add_flag(flag, chain_event);
        state.comm = comm.clone();

        // Store C2 connection info for outbound connects
        if kind == "network.outbound_connect" {
            if let Some(ip) = details.get("dst_ip").and_then(|v| v.as_str()) {
                state.last_connect_ip = Some(ip.to_string());
            }
            if let Some(port) = details.get("dst_port").and_then(|v| v.as_u64()) {
                state.last_connect_port = Some(port as u16);
            }
        }

        // Remember the sensitive file that set CHAIN_SENSITIVE_READ so the
        // DATA_EXFIL incident can carry it (spec-081 own-config gate).
        if let Some(path) = captured_sensitive_path {
            state.last_sensitive_read_path = Some(path);
        }

        // 4. Check proximity across all patterns
        let mut incidents: Vec<Value> = Vec::new();
        let current_flags = state.flags;

        for &(pattern_name, pattern_mask) in ALL_PATTERNS.iter() {
            let prox = proximity(current_flags, pattern_mask);

            // 5. Pre-chain warning (>= threshold, < 1.0)
            if prox >= self.pre_chain_threshold
                && prox < 1.0
                && !state.emitted_pre_chain.contains(&pattern_name.to_string())
            {
                state.emitted_pre_chain.push(pattern_name.to_string());

                let c2 = bridge::extract_c2(state);
                let (c2_ip, c2_port) = c2
                    .as_ref()
                    .map(|(ip, port)| (ip.as_str(), *port))
                    .unwrap_or(("unknown", 0));

                let matched = matched_flag_names(current_flags, pattern_mask);
                let missing = missing_flag_names(current_flags, pattern_mask);
                let total = pattern_mask.count_ones() as usize;
                let matched_count = matched.len();

                let incident_id = format!(
                    "kill_chain:pre_chain:{}:{}:{}",
                    pattern_name.to_uppercase(),
                    pid,
                    ts.format("%Y-%m-%dT%H:%MZ")
                );

                let timeline_json: Vec<Value> = state
                    .events
                    .iter()
                    .map(|e| {
                        json!({
                            "ts": e.ts.to_rfc3339(),
                            "kind": e.syscall,
                            "flag": flag_names(e.flag_set).first().copied().unwrap_or("unknown")
                        })
                    })
                    .collect();

                let pattern_upper = pattern_name.to_uppercase();

                let mut evidence = json!({
                    "kind": "pre_chain_warning",
                    "pattern": pattern_upper,
                    "proximity": prox,
                    "matched_bits": matched,
                    "missing_bits": missing,
                    "timeline": timeline_json,
                    // Phase 11 (audit RC-2 / Slice C+): expose the
                    // process identity in structured form so the
                    // agent's self-traffic filter can dismiss
                    // false positives where the "attacker" is
                    // actually the operator's own ssh / scp / apt /
                    // snap. Pre-Phase-11 these fields lived only in
                    // the title and recommended_checks strings,
                    // forcing string parsing in the filter.
                    "pid": pid,
                    "comm": state.comm,
                    "uid": state.uid,
                });

                if c2.is_some() {
                    evidence["c2_ip"] = json!(c2_ip);
                    evidence["c2_port"] = json!(c2_port);
                }

                // Surface the sensitive file (spec-081): the managed-agent
                // verifier's own-config gate runs on this in the kernel-block
                // path, identically to the userspace IP-block path.
                if let Some(path) = state.last_sensitive_read_path.as_deref() {
                    evidence["sensitive_file"] = json!(path);
                }

                let mut recommended = vec![
                    format!("Investigate PID {} ({}) immediately", pid, comm),
                    format!("Review process tree: ps auxf | grep {}", pid),
                ];
                if c2.is_some() {
                    recommended.insert(
                        0,
                        format!("Block C2 IP preemptively: innerwarden block {}", c2_ip),
                    );
                }

                let mut entities: Vec<Value> = Vec::new();
                if c2.is_some() {
                    entities.push(json!({"type": "ip", "value": c2_ip}));
                }

                let incident = json!({
                    "ts": ts.to_rfc3339(),
                    "host": host,
                    "incident_id": incident_id,
                    "severity": "medium",
                    "title": format!(
                        "Kill chain forming: {} ({}/{} bits, PID {})",
                        pattern_upper, matched_count, total, pid
                    ),
                    "summary": format!(
                        "PID {} ({}) has accumulated {} of {} syscall categories for {}. \
                         Next syscall may trigger kernel LSM block.",
                        pid, comm, matched_count, total, pattern_upper
                    ),
                    "evidence": [evidence],
                    "recommended_checks": recommended,
                    "tags": ["kill_chain", "pre_chain", pattern_name],
                    "entities": entities
                });

                info!(
                    pid,
                    pattern = pattern_name,
                    proximity = prox,
                    "pre-chain warning emitted"
                );
                incidents.push(incident);
            }

            // 6. Full match (proximity == 1.0)
            if (prox - 1.0).abs() < f32::EPSILON
                && !state.emitted_full_match.contains(&pattern_name.to_string())
            {
                state.emitted_full_match.push(pattern_name.to_string());

                let c2 = bridge::extract_c2(state);
                let (c2_ip, c2_port) = c2
                    .as_ref()
                    .map(|(ip, port)| (ip.as_str(), *port))
                    .unwrap_or(("unknown", 0));

                let matched = flag_names(pattern_mask);
                let pattern_upper = pattern_name.to_uppercase();

                let incident_id = format!(
                    "kill_chain:detected:{}:{}:{}",
                    pattern_upper,
                    pid,
                    ts.format("%Y-%m-%dT%H:%MZ")
                );

                let timeline_json: Vec<Value> = state
                    .events
                    .iter()
                    .map(|e| {
                        json!({
                            "ts": e.ts.to_rfc3339(),
                            "kind": e.syscall,
                            "flag": flag_names(e.flag_set).first().copied().unwrap_or("unknown")
                        })
                    })
                    .collect();

                let chain_flags_hex = format!("0x{:02x}", pattern_mask);
                let bits_desc = matched.join(" + ");

                let mut evidence = json!({
                    "kind": "kill_chain_detected",
                    "pattern": pattern_upper,
                    "chain_flags": chain_flags_hex,
                    "chain_bits": matched,
                    "timeline": timeline_json,
                    // Phase 11 (audit RC-2 / Slice C+): structured
                    // process identity so downstream filters (self-
                    // traffic FP, operator-session FP) can act on
                    // typed fields instead of parsing the title.
                    "pid": pid,
                    "comm": state.comm,
                    "uid": uid,
                });

                if c2.is_some() {
                    evidence["c2_ip"] = json!(c2_ip);
                    evidence["c2_port"] = json!(c2_port);
                }

                // Surface the sensitive file (spec-081): the managed-agent
                // verifier's own-config gate runs on this in the kernel-block
                // path, identically to the userspace IP-block path.
                if let Some(path) = state.last_sensitive_read_path.as_deref() {
                    evidence["sensitive_file"] = json!(path);
                }

                let mut recommended = vec![
                    format!("Kill PID {} immediately: kill -9 {}", pid, pid),
                    format!("Audit process: ps auxf | grep {}", pid),
                    format!("Check for persistence: crontab -l -u {}", uid),
                ];
                if c2.is_some() {
                    recommended.insert(0, format!("Block C2 IP: innerwarden block {}", c2_ip));
                }

                let mut entities: Vec<Value> = Vec::new();
                if c2.is_some() {
                    entities.push(json!({"type": "ip", "value": c2_ip}));
                }

                let incident = json!({
                    "ts": ts.to_rfc3339(),
                    "host": host,
                    "incident_id": incident_id,
                    "severity": "critical",
                    "title": format!(
                        "Kill chain detected: {} (PID {}, {})",
                        pattern_upper, pid, comm
                    ),
                    "summary": format!(
                        "PID {} ({}) completed {} pattern ({}). \
                         Kernel LSM will block next execve().",
                        pid, comm, pattern_upper, bits_desc
                    ),
                    "evidence": [evidence],
                    "recommended_checks": recommended,
                    "tags": ["kill_chain", "detected", pattern_name],
                    "entities": entities
                });

                info!(
                    pid,
                    pattern = pattern_name,
                    "kill chain detected — full match"
                );
                incidents.push(incident);
            }
        }

        debug!(
            pid,
            flags = current_flags,
            events = incidents.len(),
            "event processed"
        );
        incidents
    }

    // ------------------------------------------------------------------
    // Maintenance
    // ------------------------------------------------------------------

    /// Remove PIDs whose `last_seen` is older than `session_timeout_secs`.
    pub fn cleanup_stale(&mut self) {
        let now = Utc::now();
        let timeout = self.session_timeout_secs;
        self.pids.retain(|pid, state| {
            let keep = !state.is_stale(now, timeout);
            if !keep {
                debug!(pid, "stale PID removed");
            }
            keep
        });
    }

    /// Retrieve the chain state for a specific PID (used by detector enrichment).
    pub fn get_state(&self, pid: u32) -> Option<&PidChainState> {
        self.pids.get(&pid)
    }

    /// Returns `(tracked_pids, pre_chains_emitted, full_matches_emitted)`.
    pub fn stats(&self) -> (usize, usize, usize) {
        let tracked = self.pids.len();
        let mut pre_chains = 0usize;
        let mut full_matches = 0usize;
        for state in self.pids.values() {
            pre_chains += state.emitted_pre_chain.len();
            full_matches += state.emitted_full_match.len();
        }
        (tracked, pre_chains, full_matches)
    }
}

impl Default for PidTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers — compute matched/missing flag names for a pattern
// ---------------------------------------------------------------------------

/// Returns the names of flags that are set in `current_flags` AND required by `pattern_mask`.
fn matched_flag_names(current_flags: u32, pattern_mask: u32) -> Vec<&'static str> {
    flag_names(current_flags & pattern_mask)
}

/// Returns the names of flags required by `pattern_mask` that are NOT set in `current_flags`.
fn missing_flag_names(current_flags: u32, pattern_mask: u32) -> Vec<&'static str> {
    flag_names(pattern_mask & !current_flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;

    fn ts() -> String {
        "2026-03-26T14:23:01Z".to_string()
    }

    fn make_event(kind: &str, pid: u32, details_extra: Value) -> Value {
        let mut details = json!({
            "pid": pid,
            "uid": 1000,
            "comm": "python3"
        });
        if let Value::Object(map) = details_extra {
            for (k, v) in map {
                details[k] = v;
            }
        }
        json!({
            "kind": kind,
            "ts": ts(),
            "host": "production",
            "details": details
        })
    }

    // ---------------------------------------------------------------
    // Reverse shell: connect -> dup2(0) -> dup2(1) -> pre + full
    // ---------------------------------------------------------------

    #[test]
    fn reverse_shell_sequence() {
        let mut tracker = PidTracker::new();

        // Step 1: outbound connect
        let connect = make_event(
            "network.outbound_connect",
            1234,
            json!({"dst_ip": "185.234.1.1", "dst_port": 4444}),
        );
        let incidents = tracker.process_event(&connect);
        assert!(
            incidents.is_empty(),
            "single flag should not trigger anything"
        );

        // Step 2: dup2(stdin) — this is 2/3 for reverse_shell -> pre-chain
        let dup_stdin = make_event("process.fd_redirect", 1234, json!({"newfd": 0}));
        let incidents = tracker.process_event(&dup_stdin);
        // Should have at least one pre-chain incident
        let pre_chains: Vec<&Value> = incidents
            .iter()
            .filter(|i| i["severity"] == "medium")
            .collect();
        assert!(
            !pre_chains.is_empty(),
            "should emit at least one pre-chain warning"
        );
        // Verify reverse shell pre-chain is among them
        let rs_pre: Vec<&&Value> = pre_chains
            .iter()
            .filter(|i| {
                i["incident_id"]
                    .as_str()
                    .map(|s| s.contains("pre_chain:REVERSE_SHELL"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(!rs_pre.is_empty(), "reverse shell pre-chain expected");
        assert!(rs_pre[0]["title"]
            .as_str()
            .unwrap()
            .contains("Kill chain forming"));

        // Step 3: dup2(stdout) — this is 3/3 -> full match
        let dup_stdout = make_event("process.fd_redirect", 1234, json!({"newfd": 1}));
        let incidents = tracker.process_event(&dup_stdout);
        let full_matches: Vec<&Value> = incidents
            .iter()
            .filter(|i| i["severity"] == "critical")
            .collect();
        assert!(
            !full_matches.is_empty(),
            "should emit at least one full match"
        );
        let rs_full: Vec<&&Value> = full_matches
            .iter()
            .filter(|i| {
                i["incident_id"]
                    .as_str()
                    .map(|s| s.contains("detected:REVERSE_SHELL"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(!rs_full.is_empty(), "reverse shell full match expected");
        assert!(rs_full[0]["title"]
            .as_str()
            .unwrap()
            .contains("Kill chain detected"));
    }

    // ---------------------------------------------------------------
    // Bind shell: bind -> listen -> dup2(0) -> dup2(1) -> full match
    // ---------------------------------------------------------------

    #[test]
    fn bind_shell_sequence() {
        let mut tracker = PidTracker::new();

        let bind = make_event("network.bind_listen", 2000, json!({}));
        let listen = make_event("network.listen", 2000, json!({}));
        let dup0 = make_event("process.fd_redirect", 2000, json!({"newfd": 0}));
        let dup1 = make_event("process.fd_redirect", 2000, json!({"newfd": 1}));

        tracker.process_event(&bind);
        tracker.process_event(&listen);
        tracker.process_event(&dup0);
        let incidents = tracker.process_event(&dup1);

        // Should have a full-match incident for BIND_SHELL
        let full_matches: Vec<&Value> = incidents
            .iter()
            .filter(|i| i["severity"] == "critical")
            .collect();
        assert!(
            !full_matches.is_empty(),
            "bind shell should produce a full match"
        );
        let bs_full: Vec<&&Value> = full_matches
            .iter()
            .filter(|i| {
                i["incident_id"]
                    .as_str()
                    .map(|s| s.contains("detected:BIND_SHELL"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(!bs_full.is_empty(), "bind shell full match expected");
    }

    // ---------------------------------------------------------------
    // Code injection: ptrace -> mprotect(rwx) -> full match
    // ---------------------------------------------------------------

    #[test]
    fn code_inject_sequence() {
        let mut tracker = PidTracker::new();

        let ptrace = make_event("process.ptrace_attach", 3000, json!({}));
        let mprotect = make_event("memory.mprotect_exec", 3000, json!({"rwx": true}));

        tracker.process_event(&ptrace);
        let incidents = tracker.process_event(&mprotect);

        let full_matches: Vec<&Value> = incidents
            .iter()
            .filter(|i| i["severity"] == "critical")
            .collect();
        assert!(
            !full_matches.is_empty(),
            "code inject should produce a full match"
        );
        let ci_full: Vec<&&Value> = full_matches
            .iter()
            .filter(|i| {
                i["incident_id"]
                    .as_str()
                    .map(|s| s.contains("detected:CODE_INJECT"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(!ci_full.is_empty(), "code inject full match expected");
    }

    // ---------------------------------------------------------------
    // Different PIDs don't interfere
    // ---------------------------------------------------------------

    #[test]
    fn different_pids_isolated() {
        let mut tracker = PidTracker::new();

        // PID 100: connect
        let connect = make_event(
            "network.outbound_connect",
            100,
            json!({"dst_ip": "8.8.8.8", "dst_port": 53}),
        );
        tracker.process_event(&connect);

        // PID 200: dup2(stdin)
        let dup0 = make_event("process.fd_redirect", 200, json!({"newfd": 0}));
        let incidents = tracker.process_event(&dup0);

        // Neither PID should have triggered anything — only 1 bit each
        assert!(incidents.is_empty());

        let state100 = tracker.get_state(100).unwrap();
        assert_eq!(state100.flags, CHAIN_SOCKET);

        let state200 = tracker.get_state(200).unwrap();
        assert_eq!(state200.flags, CHAIN_DUP_STDIN);
    }

    // ---------------------------------------------------------------
    // Stale PID cleanup works
    // ---------------------------------------------------------------

    #[test]
    fn stale_pid_cleanup() {
        let mut tracker = PidTracker::new().with_timeout(60);

        // Insert an event — this PID will have last_seen = now
        let event = make_event(
            "network.outbound_connect",
            500,
            json!({"dst_ip": "1.2.3.4", "dst_port": 80}),
        );
        tracker.process_event(&event);
        assert!(tracker.get_state(500).is_some());

        // Manually backdate last_seen to trigger cleanup
        if let Some(state) = tracker.pids.get_mut(&500) {
            state.last_seen = Utc::now() - Duration::seconds(120);
        }

        tracker.cleanup_stale();
        assert!(
            tracker.get_state(500).is_none(),
            "stale PID should be removed"
        );
    }

    // ---------------------------------------------------------------
    // Duplicate pre-chain alerts suppressed
    // ---------------------------------------------------------------

    #[test]
    fn duplicate_pre_chain_suppressed() {
        let mut tracker = PidTracker::new();

        // Trigger pre-chain for reverse_shell: connect + dup2(stdin)
        let connect = make_event(
            "network.outbound_connect",
            600,
            json!({"dst_ip": "185.234.1.1", "dst_port": 4444}),
        );
        let dup0 = make_event("process.fd_redirect", 600, json!({"newfd": 0}));

        tracker.process_event(&connect);
        let first = tracker.process_event(&dup0);
        // At least one pre-chain should have been emitted (may include others)
        let rs_pre_first: Vec<&Value> = first
            .iter()
            .filter(|i| {
                i["incident_id"]
                    .as_str()
                    .map(|s| s.contains("pre_chain:REVERSE_SHELL"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            !rs_pre_first.is_empty(),
            "first pre-chain for REVERSE_SHELL should emit"
        );

        // Send dup2(stderr) — adds a bit but REVERSE_SHELL pre-chain was already emitted
        let dup2 = make_event("process.fd_redirect", 600, json!({"newfd": 2}));
        let second = tracker.process_event(&dup2);

        // Check that no duplicate pre-chain for REVERSE_SHELL was emitted
        let rs_pre_dup: Vec<&Value> = second
            .iter()
            .filter(|i| {
                i["incident_id"]
                    .as_str()
                    .map(|s| s.contains("pre_chain:REVERSE_SHELL"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            rs_pre_dup.is_empty(),
            "duplicate pre-chain for same pattern should be suppressed"
        );
    }

    // ---------------------------------------------------------------
    // Connect stores C2 IP correctly
    // ---------------------------------------------------------------

    #[test]
    fn connect_stores_c2_ip() {
        let mut tracker = PidTracker::new();

        let connect = make_event(
            "network.outbound_connect",
            700,
            json!({"dst_ip": "203.45.67.89", "dst_port": 9999}),
        );
        tracker.process_event(&connect);

        let state = tracker.get_state(700).unwrap();
        assert_eq!(state.last_connect_ip, Some("203.45.67.89".to_string()));
        assert_eq!(state.last_connect_port, Some(9999));
    }

    // ---------------------------------------------------------------
    // mprotect without rwx=true is ignored
    // ---------------------------------------------------------------

    #[test]
    fn mprotect_without_rwx_ignored() {
        let mut tracker = PidTracker::new();

        let mprotect_no_rwx = make_event("memory.mprotect_exec", 800, json!({"rwx": false}));
        let incidents = tracker.process_event(&mprotect_no_rwx);
        assert!(incidents.is_empty());
        assert!(
            tracker.get_state(800).is_none(),
            "no state should be created for ignored event"
        );

        // Also test missing rwx field
        let mprotect_missing = make_event("memory.mprotect_exec", 801, json!({}));
        let incidents = tracker.process_event(&mprotect_missing);
        assert!(incidents.is_empty());
        assert!(tracker.get_state(801).is_none());
    }

    // ---------------------------------------------------------------
    // Stats
    // ---------------------------------------------------------------

    // ---------------------------------------------------------------
    // Self-exclusion: platform can suppress its own threads
    // ---------------------------------------------------------------

    fn make_event_with_comm(kind: &str, pid: u32, comm: &str, details_extra: Value) -> Value {
        let mut details = json!({"pid": pid, "uid": 1000, "comm": comm});
        if let Value::Object(map) = details_extra {
            for (k, v) in map {
                details[k] = v;
            }
        }
        json!({
            "kind": kind,
            "ts": ts(),
            "host": "production",
            "details": details
        })
    }

    #[test]
    fn excluded_comm_is_skipped_entirely() {
        let mut tracker = PidTracker::new().with_excluded_comms(["tokio-rt-worker"]);
        assert!(tracker.is_excluded_comm("tokio-rt-worker"));

        // DATA_EXFIL = outbound_connect + sensitive_read. Both arrive for the
        // excluded comm — neither should be tracked nor emit anything.
        let connect = make_event_with_comm(
            "network.outbound_connect",
            1234,
            "tokio-rt-worker",
            json!({"dst_ip": "1.2.3.4", "dst_port": 443}),
        );
        let read = make_event_with_comm(
            "file.read_access",
            1234,
            "tokio-rt-worker",
            json!({"filename": "/root/.ssh/id_rsa"}),
        );

        let incidents1 = tracker.process_event(&connect);
        let incidents2 = tracker.process_event(&read);
        assert!(incidents1.is_empty());
        assert!(incidents2.is_empty());
        assert!(
            tracker.get_state(1234).is_none(),
            "excluded comm must not create tracker state"
        );
        assert_eq!(tracker.stats(), (0, 0, 0));
    }

    #[test]
    fn excluded_comm_does_not_affect_other_processes() {
        let mut tracker = PidTracker::new().with_excluded_comms(["innerwarden-age"]);

        // Different comm: full DATA_EXFIL chain must still fire.
        let connect = make_event_with_comm(
            "network.outbound_connect",
            4444,
            "attacker",
            json!({"dst_ip": "185.234.1.1", "dst_port": 9999}),
        );
        let read = make_event_with_comm(
            "file.read_access",
            4444,
            "attacker",
            json!({"filename": "/etc/shadow"}),
        );

        tracker.process_event(&connect);
        let incidents = tracker.process_event(&read);
        let fulls: Vec<&Value> = incidents
            .iter()
            .filter(|i| i["severity"] == "critical")
            .collect();
        assert!(
            !fulls.is_empty(),
            "attacker DATA_EXFIL must still fire when a different comm is excluded"
        );
    }

    #[test]
    fn is_sensitive_read_path_is_tight() {
        // Real secrets whose exfiltration matters.
        for p in [
            "/etc/shadow",
            "/etc/shadow-",
            "/etc/gshadow",
            "/etc/sudoers",
            "/home/u/.ssh/id_rsa",
            "/home/u/.ssh/id_ed25519",
            "/root/.ssh/authorized_keys",
            "/app/.env",
            "/app/.env.production",
            "/home/u/.gnupg/secring.gpg",
            "/home/u/.netrc",
            "/home/u/.aws/credentials",
            "/root/.docker/config.json",
            "/home/u/.config/gcloud/application_default_credentials.json",
            "/home/u/.azure/accessTokens.json",
            "/home/u/.kube/config",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        ] {
            assert!(is_sensitive_read_path(p), "{p} must be sensitive");
        }
        // Benign reads that previously produced false-positive DATA_EXFIL:
        // world-readable / nss / TLS-trust / ssh-bookkeeping / config files
        // that download tools and cloud CLIs touch on every run.
        for p in [
            "/etc/passwd",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/nsswitch.conf",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/ld.so.cache",
            "/home/u/.ssh/known_hosts",
            "/home/u/.ssh/config",
            "/home/u/.aws/config",              // aws cli reads this every call
            "/app/config.env",                  // *.env extension, not a .env dotfile
            "/var/cache/app/credentials-cache", // bare "credentials" no longer matches
        ] {
            assert!(!is_sensitive_read_path(p), "{p} must NOT be sensitive");
        }
    }

    #[test]
    fn data_exfil_does_not_fire_on_etc_passwd() {
        // The Oracle false positive: curl reads /etc/passwd via nss and
        // connects to a CDN (54.230.x = CloudFront). Must NOT trip DATA_EXFIL.
        let mut tracker = PidTracker::new();
        tracker.process_event(&make_event_with_comm(
            "file.read_access",
            5000,
            "curl",
            json!({"filename": "/etc/passwd"}),
        ));
        let incidents = tracker.process_event(&make_event_with_comm(
            "network.outbound_connect",
            5000,
            "curl",
            json!({"dst_ip": "54.230.201.25", "dst_port": 443}),
        ));
        assert!(
            incidents.iter().all(|i| i["severity"] != "critical"),
            "/etc/passwd read + connect must not produce a critical DATA_EXFIL incident"
        );
    }

    #[test]
    fn data_exfil_still_fires_on_etc_shadow() {
        // Regression guard: tightening the list must NOT weaken real exfil.
        let mut tracker = PidTracker::new();
        tracker.process_event(&make_event_with_comm(
            "network.outbound_connect",
            6000,
            "attacker",
            json!({"dst_ip": "185.234.1.1", "dst_port": 9999}),
        ));
        let incidents = tracker.process_event(&make_event_with_comm(
            "file.read_access",
            6000,
            "attacker",
            json!({"filename": "/etc/shadow"}),
        ));
        assert!(
            incidents.iter().any(|i| i["severity"] == "critical"),
            "shadow read + connect must still fire DATA_EXFIL"
        );
    }

    #[test]
    fn data_exfil_evidence_carries_sensitive_file() {
        // Spec-081: the DATA_EXFIL incident must surface the sensitive file
        // that set CHAIN_SENSITIVE_READ as `sensitive_file`, so the kernel-block
        // managed-agent verifier can apply its own-config gate (it can only
        // exempt a read of the agent's OWN config, never /etc/shadow).
        let mut tracker = PidTracker::new();
        tracker.process_event(&make_event_with_comm(
            "file.read_access",
            6100,
            "node",
            json!({"filename": "/etc/shadow"}),
        ));
        let incidents = tracker.process_event(&make_event_with_comm(
            "network.outbound_connect",
            6100,
            "node",
            json!({"dst_ip": "185.234.1.1", "dst_port": 9999}),
        ));
        let exfil = incidents
            .iter()
            .find(|i| i["severity"] == "critical")
            .expect("shadow read + connect must fire a critical DATA_EXFIL incident");
        assert_eq!(
            exfil["evidence"][0]["sensitive_file"], "/etc/shadow",
            "DATA_EXFIL evidence must carry the sensitive file path"
        );
    }

    #[test]
    fn data_exfil_fires_on_ssh_private_key_not_known_hosts() {
        // Private key + connect = real exfil.
        let mut t1 = PidTracker::new();
        t1.process_event(&make_event_with_comm(
            "file.read_access",
            7000,
            "attacker",
            json!({"filename": "/home/u/.ssh/id_ed25519"}),
        ));
        let fires = t1.process_event(&make_event_with_comm(
            "network.outbound_connect",
            7000,
            "attacker",
            json!({"dst_ip": "185.234.1.1", "dst_port": 9999}),
        ));
        assert!(fires.iter().any(|i| i["severity"] == "critical"));

        // known_hosts (git/ssh bookkeeping) + connect = benign, no fire.
        let mut t2 = PidTracker::new();
        t2.process_event(&make_event_with_comm(
            "file.read_access",
            7001,
            "git",
            json!({"filename": "/home/u/.ssh/known_hosts"}),
        ));
        let benign = t2.process_event(&make_event_with_comm(
            "network.outbound_connect",
            7001,
            "git",
            json!({"dst_ip": "140.82.112.3", "dst_port": 443}),
        ));
        assert!(benign.iter().all(|i| i["severity"] != "critical"));
    }

    #[test]
    fn with_excluded_comms_replaces_previous_set() {
        let tracker = PidTracker::new()
            .with_excluded_comms(["a", "b"])
            .with_excluded_comms(["c"]);
        assert!(!tracker.is_excluded_comm("a"));
        assert!(!tracker.is_excluded_comm("b"));
        assert!(tracker.is_excluded_comm("c"));
    }

    #[test]
    fn empty_exclusion_set_by_default() {
        let tracker = PidTracker::new();
        assert!(!tracker.is_excluded_comm("tokio-rt-worker"));
        assert!(!tracker.is_excluded_comm(""));
    }

    #[test]
    fn excluded_comm_blocks_pre_chain_too() {
        // 2/3 bits would normally emit a pre-chain warning. Exclusion must
        // short-circuit before the pre-chain check fires.
        let mut tracker = PidTracker::new().with_excluded_comms(["infra-thread"]);

        let connect = make_event_with_comm(
            "network.outbound_connect",
            9000,
            "infra-thread",
            json!({"dst_ip": "10.0.0.1", "dst_port": 443}),
        );
        let dup = make_event_with_comm(
            "process.fd_redirect",
            9000,
            "infra-thread",
            json!({"newfd": 0}),
        );
        tracker.process_event(&connect);
        let incidents = tracker.process_event(&dup);
        assert!(
            incidents.is_empty(),
            "excluded comm must suppress pre-chain"
        );
    }

    #[test]
    fn stats_reflect_state() {
        let mut tracker = PidTracker::new();

        let (pids, pre, full) = tracker.stats();
        assert_eq!((pids, pre, full), (0, 0, 0));

        // Trigger a full reverse shell
        let connect = make_event(
            "network.outbound_connect",
            900,
            json!({"dst_ip": "185.234.1.1", "dst_port": 4444}),
        );
        let dup0 = make_event("process.fd_redirect", 900, json!({"newfd": 0}));
        let dup1 = make_event("process.fd_redirect", 900, json!({"newfd": 1}));

        tracker.process_event(&connect);
        tracker.process_event(&dup0);
        tracker.process_event(&dup1);

        let (pids, pre, full) = tracker.stats();
        assert_eq!(pids, 1);
        assert!(pre >= 1, "should have at least 1 pre-chain");
        assert!(full >= 1, "should have at least 1 full match");
    }
}
