// tcp_fingerprint.rs — Bot Detection via TCP Stack Fingerprinting
//
// Based on halb.it/posts/ebpf-fingerprinting-2/
//
// Classifies IPs as Human / Bot / Botnet by analysing TCP window sizes,
// TTL values, and connection timing patterns.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Connection pattern classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionPattern {
    Human,
    Bot,
    Botnet,
    Unknown,
}

// ---------------------------------------------------------------------------
// Per-IP fingerprint
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprint {
    pub ip: String,
    pub window_sizes: Vec<u16>,
    pub ttl_values: Vec<u8>,
    pub connection_times: Vec<DateTime<Utc>>,
    pub connection_pattern: ConnectionPattern,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub connection_count: u64,
}

impl TcpFingerprint {
    fn new(ip: &str, now: DateTime<Utc>) -> Self {
        Self {
            ip: ip.to_string(),
            window_sizes: Vec::new(),
            ttl_values: Vec::new(),
            connection_times: Vec::new(),
            connection_pattern: ConnectionPattern::Unknown,
            first_seen: now,
            last_seen: now,
            connection_count: 0,
        }
    }

    /// Dominant (most frequent) window size, if any.
    pub fn dominant_window_size(&self) -> Option<u16> {
        if self.window_sizes.is_empty() {
            return None;
        }
        let mut freq: HashMap<u16, usize> = HashMap::new();
        for &w in &self.window_sizes {
            *freq.entry(w).or_default() += 1;
        }
        freq.into_iter().max_by_key(|&(_, c)| c).map(|(w, _)| w)
    }

    /// Dominant TTL value.
    pub fn dominant_ttl(&self) -> Option<u8> {
        if self.ttl_values.is_empty() {
            return None;
        }
        let mut freq: HashMap<u8, usize> = HashMap::new();
        for &t in &self.ttl_values {
            *freq.entry(t).or_default() += 1;
        }
        freq.into_iter().max_by_key(|&(_, c)| c).map(|(t, _)| t)
    }

    /// Timing variance in milliseconds across connection intervals.
    pub fn timing_variance_ms(&self) -> f64 {
        if self.connection_times.len() < 2 {
            return f64::MAX; // not enough data → treat as human-like
        }
        let mut intervals: Vec<f64> = Vec::new();
        for pair in self.connection_times.windows(2) {
            let diff = (pair[1] - pair[0]).num_milliseconds() as f64;
            intervals.push(diff);
        }
        if intervals.is_empty() {
            return f64::MAX;
        }
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance =
            intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        variance
    }
}

// ---------------------------------------------------------------------------
// Known bot signature
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotSignature {
    pub name: String,
    pub window_size: Option<u16>,
    pub ttl: Option<u8>,
    pub description: String,
}

// ---------------------------------------------------------------------------
// Fingerprinter
// ---------------------------------------------------------------------------

pub struct TcpFingerprinter {
    fingerprints: HashMap<String, TcpFingerprint>,
    bot_signatures: Vec<BotSignature>,
    /// Min connections for bot classification.
    bot_conn_threshold: u64,
    /// Max timing variance (ms^2) for bot pattern.
    bot_timing_variance_max: f64,
    /// Min IPs sharing a fingerprint to declare botnet.
    botnet_ip_threshold: usize,
}

impl TcpFingerprinter {
    pub fn new() -> Self {
        Self {
            fingerprints: HashMap::new(),
            bot_signatures: Vec::new(),
            bot_conn_threshold: 100,
            bot_timing_variance_max: 10_000.0, // 100ms std → 10000 variance
            botnet_ip_threshold: 10,
        }
    }

    pub fn with_bot_conn_threshold(mut self, t: u64) -> Self {
        self.bot_conn_threshold = t;
        self
    }

    pub fn with_bot_timing_variance_max(mut self, v: f64) -> Self {
        self.bot_timing_variance_max = v;
        self
    }

    pub fn with_botnet_ip_threshold(mut self, t: usize) -> Self {
        self.botnet_ip_threshold = t;
        self
    }

    pub fn add_bot_signature(&mut self, sig: BotSignature) {
        self.bot_signatures.push(sig);
    }

    /// Record a connection from `ip` with TCP parameters.
    pub fn record_connection(&mut self, ip: &str, window_size: u16, ttl: u8, ts: DateTime<Utc>) {
        let fp = self
            .fingerprints
            .entry(ip.to_string())
            .or_insert_with(|| TcpFingerprint::new(ip, ts));

        fp.last_seen = ts;
        fp.connection_count += 1;
        fp.window_sizes.push(window_size);
        fp.ttl_values.push(ttl);
        fp.connection_times.push(ts);

        // Cap stored history to 500 entries.
        if fp.window_sizes.len() > 500 {
            fp.window_sizes.drain(0..250);
        }
        if fp.ttl_values.len() > 500 {
            fp.ttl_values.drain(0..250);
        }
        if fp.connection_times.len() > 500 {
            fp.connection_times.drain(0..250);
        }
    }

    /// Classify all tracked IPs. Updates their `connection_pattern`.
    pub fn classify_all(&mut self) {
        // Phase 1: per-IP bot detection.
        for fp in self.fingerprints.values_mut() {
            if fp.connection_count >= self.bot_conn_threshold
                && fp.timing_variance_ms() < self.bot_timing_variance_max
            {
                fp.connection_pattern = ConnectionPattern::Bot;
            } else {
                fp.connection_pattern = ConnectionPattern::Human;
            }
        }

        // Phase 2: botnet detection — shared fingerprint across many IPs.
        // Group by (dominant_window_size, dominant_ttl).
        let mut groups: HashMap<(u16, u8), Vec<String>> = HashMap::new();
        for fp in self.fingerprints.values() {
            if let (Some(w), Some(t)) = (fp.dominant_window_size(), fp.dominant_ttl()) {
                // Skip the "unknown L4 fingerprint" bucket (window 0 = no captured
                // TCP window; timestamp-only tracking records 0). Without this,
                // every IP whose window/ttl was never captured would share (0, 0)
                // and >= botnet_ip_threshold of them would falsely cluster into a
                // botnet. Botnet detection therefore requires a real L4 fingerprint;
                // the per-IP timing-variance bot detection above needs none.
                if w == 0 {
                    continue;
                }
                groups.entry((w, t)).or_default().push(fp.ip.clone());
            }
        }

        for (_key, ips) in &groups {
            if ips.len() >= self.botnet_ip_threshold {
                for ip in ips {
                    if let Some(fp) = self.fingerprints.get_mut(ip) {
                        fp.connection_pattern = ConnectionPattern::Botnet;
                    }
                }
            }
        }
    }

    /// Get the pattern for a specific IP.
    pub fn get_pattern(&self, ip: &str) -> ConnectionPattern {
        self.fingerprints
            .get(ip)
            .map(|fp| fp.connection_pattern.clone())
            .unwrap_or(ConnectionPattern::Unknown)
    }

    /// All IPs classified as Bot or Botnet.
    pub fn get_bots(&self) -> Vec<&TcpFingerprint> {
        self.fingerprints
            .values()
            .filter(|fp| {
                fp.connection_pattern == ConnectionPattern::Bot
                    || fp.connection_pattern == ConnectionPattern::Botnet
            })
            .collect()
    }

    /// Check a connection against known bot signatures.
    pub fn matches_signature(&self, window_size: u16, ttl: u8) -> Option<&BotSignature> {
        for sig in &self.bot_signatures {
            let ws_match = sig.window_size.map_or(true, |w| w == window_size);
            let ttl_match = sig.ttl.map_or(true, |t| t == ttl);
            if ws_match && ttl_match {
                return Some(sig);
            }
        }
        None
    }

    pub fn tracked_count(&self) -> usize {
        self.fingerprints.len()
    }

    /// Remove IPs not seen within `max_age`.
    pub fn cleanup_stale(&mut self, max_age: std::time::Duration, now: DateTime<Utc>) {
        let cutoff_ms = max_age.as_millis() as i64;
        self.fingerprints
            .retain(|_, fp| (now - fp.last_seen).num_milliseconds() < cutoff_ms);
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as CDur;

    fn ts(offset_ms: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(1_700_000_000_000 + offset_ms).unwrap()
    }

    #[test]
    fn human_traffic_classified_correctly() {
        let mut fp = TcpFingerprinter::new().with_bot_conn_threshold(50);
        let now = ts(0);
        // 10 connections with variable timing — should be Human.
        for i in 0..10 {
            let t = now + CDur::milliseconds(i * 1000 + (i * 137) % 500);
            fp.record_connection("10.0.0.1", 65535, 64, t);
        }
        fp.classify_all();
        assert_eq!(fp.get_pattern("10.0.0.1"), ConnectionPattern::Human);
    }

    #[test]
    fn bot_detected_regular_timing() {
        let mut fp = TcpFingerprinter::new()
            .with_bot_conn_threshold(20)
            .with_bot_timing_variance_max(50.0);
        let now = ts(0);
        // 50 connections at exact 100ms intervals → very low variance.
        for i in 0..50 {
            let t = now + CDur::milliseconds(i * 100);
            fp.record_connection("10.0.0.2", 29200, 128, t);
        }
        fp.classify_all();
        assert_eq!(fp.get_pattern("10.0.0.2"), ConnectionPattern::Bot);
    }

    #[test]
    fn botnet_detected_shared_fingerprint() {
        let mut fp = TcpFingerprinter::new()
            .with_bot_conn_threshold(1000) // high threshold so individual bot detection doesn't fire
            .with_botnet_ip_threshold(5);
        let now = ts(0);
        // 10 IPs all with same window size + TTL.
        for i in 0..10u32 {
            let ip = format!("10.0.0.{}", i + 1);
            for j in 0..5 {
                let t = now + CDur::milliseconds((i as i64) * 1000 + j * 200);
                fp.record_connection(&ip, 8192, 64, t);
            }
        }
        fp.classify_all();
        // All should be classified as Botnet.
        for i in 1..=10 {
            assert_eq!(
                fp.get_pattern(&format!("10.0.0.{}", i)),
                ConnectionPattern::Botnet
            );
        }
    }

    #[test]
    fn signature_matching() {
        let mut fp = TcpFingerprinter::new();
        fp.add_bot_signature(BotSignature {
            name: "Mirai".to_string(),
            window_size: Some(1024),
            ttl: Some(64),
            description: "Mirai botnet default TCP stack".to_string(),
        });
        assert!(fp.matches_signature(1024, 64).is_some());
        assert!(fp.matches_signature(65535, 128).is_none());
    }

    #[test]
    fn cleanup_stale_removes_old() {
        let mut fp = TcpFingerprinter::new();
        let now = ts(0);
        fp.record_connection("10.0.0.1", 65535, 64, now);
        assert_eq!(fp.tracked_count(), 1);

        let future = now + CDur::seconds(600);
        fp.cleanup_stale(std::time::Duration::from_secs(300), future);
        assert_eq!(fp.tracked_count(), 0);
    }

    #[test]
    fn unknown_pattern_for_unseen_ip() {
        let fp = TcpFingerprinter::new();
        assert_eq!(fp.get_pattern("10.0.0.99"), ConnectionPattern::Unknown);
    }
}
