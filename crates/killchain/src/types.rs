//! Core types for kill chain tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// State of a single PID's kill chain progression.
#[derive(Debug, Clone)]
pub struct PidChainState {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub host: String,
    pub flags: u32,
    pub events: Vec<ChainEvent>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_connect_ip: Option<String>,
    pub last_connect_port: Option<u16>,
    /// The most recent sensitive file path that set the `CHAIN_SENSITIVE_READ`
    /// flag (e.g. `/etc/shadow`, `/home/lab/.env`). Surfaced into the DATA_EXFIL
    /// incident evidence as `sensitive_file` so the spec-081 managed-agent
    /// verifier can apply its OWN-CONFIG gate on the kernel-block path, exactly
    /// like the userspace IP-block path already does. Without it the kernel path
    /// could only verify identity, never WHAT was read — a subverted-but-genuine
    /// managed agent reading `/etc/shadow` would wrongly buy the execve-deny
    /// exemption. `None` until a sensitive read is observed.
    pub last_sensitive_read_path: Option<String>,
    /// Track which pre-chain alerts have been emitted (to avoid duplicates)
    pub emitted_pre_chain: Vec<String>,
    /// Track which full-match alerts have been emitted
    pub emitted_full_match: Vec<String>,
}

/// A single syscall event in the kill chain timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEvent {
    pub ts: DateTime<Utc>,
    pub syscall: String,
    pub details: serde_json::Value,
    pub flag_set: u32,
}

impl PidChainState {
    /// Create a new PID chain state with no flags set.
    pub fn new(pid: u32, uid: u32, comm: String, host: String, ts: DateTime<Utc>) -> Self {
        Self {
            pid,
            uid,
            comm,
            host,
            flags: 0,
            events: Vec::new(),
            first_seen: ts,
            last_seen: ts,
            last_connect_ip: None,
            last_connect_port: None,
            last_sensitive_read_path: None,
            emitted_pre_chain: Vec::new(),
            emitted_full_match: Vec::new(),
        }
    }

    /// Merge a new flag into the chain bitmask, record the event, and update last_seen.
    pub fn add_flag(&mut self, flag: u32, event: ChainEvent) {
        self.flags |= flag;
        self.last_seen = event.ts;
        self.events.push(event);
    }

    /// Returns true if the chain has not been updated within `timeout_secs` of `now`.
    pub fn is_stale(&self, now: DateTime<Utc>, timeout_secs: i64) -> bool {
        let elapsed = now.signed_duration_since(self.last_seen);
        elapsed.num_seconds() > timeout_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_pid_chain_state_new() {
        let ts = Utc::now();
        let state = PidChainState::new(1234, 1000, "bash".to_string(), "host1".to_string(), ts);

        assert_eq!(state.pid, 1234);
        assert_eq!(state.uid, 1000);
        assert_eq!(state.comm, "bash");
        assert_eq!(state.host, "host1");
        assert_eq!(state.flags, 0);
        assert!(state.events.is_empty());
        assert_eq!(state.first_seen, ts);
        assert_eq!(state.last_seen, ts);
    }

    #[test]
    fn test_add_flag_updates_state() {
        let ts1 = Utc::now();
        let mut state = PidChainState::new(1, 0, "test".to_string(), "host".to_string(), ts1);

        let ts2 = ts1 + Duration::seconds(10);
        let event = ChainEvent {
            ts: ts2,
            syscall: "execve".to_string(),
            details: serde_json::json!({}),
            flag_set: 0x1,
        };

        state.add_flag(0x1, event);
        assert_eq!(state.flags, 0x1);
        assert_eq!(state.last_seen, ts2);
        assert_eq!(state.events.len(), 1);
    }

    #[test]
    fn test_is_stale() {
        let ts = Utc::now();
        let state = PidChainState::new(1, 0, "test".to_string(), "host".to_string(), ts);

        assert!(!state.is_stale(ts + Duration::seconds(5), 10));
        assert!(state.is_stale(ts + Duration::seconds(15), 10));
    }
}
