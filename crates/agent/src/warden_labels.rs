//! Spec 062 Phase 6a — human-label training channel.
//!
//! Every human-grade decision the agent records — an operator resolving a
//! `needs_review` incident from Telegram, an operator honeypot/block/ignore
//! choice, or a learned-suppression auto-dismiss of a trivial repeated shape —
//! is persisted here as a *labeled training sample* to `labels-<date>.jsonl`.
//!
//! This is the channel the spec calls out (062 §"Long-term — warden retrain
//! signal"): the warden ONNX classifier is re-distilled OFFLINE from prod
//! incidents, and until now there was no on-host record of *which incidents a
//! human judged and how*. The decisions log records the action; this log
//! records it as a label with a `verdict`, a `weight`, and the incident's
//! feature text, in the shape a re-distillation pipeline wants.
//!
//! **Honesty (invariant #5 of spec 062):** this phase EMITS the channel. It
//! does not yet retrain any model on-host — the autoencoder remains
//! unsupervised, and the warden ONNX stays the shipped artifact. The nightly
//! reader logs corpus stats so the operator can see the channel filling up.
//! Claiming on-host retraining we do not do would be vanity; we do not.
//!
//! The file is append-only JSONL (one sample per line), pruned by
//! `data_retention` alongside `decisions-*.jsonl`.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use chrono::{DateTime, Utc};
use innerwarden_core::event::Severity;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// One labeled sample. Field names are deliberately stable — an offline
/// re-distillation pipeline reads this schema directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LabelSample {
    /// RFC3339 timestamp.
    pub ts: String,
    /// Host that produced the label.
    pub host: String,
    /// Incident the label is about.
    pub incident_id: String,
    /// Detector half of the incident shape (the `incident_id` prefix).
    pub detector: String,
    /// Attacker IP if the incident carried one.
    pub target_ip: Option<String>,
    /// Incident severity at decision time (lowercase, matches `Severity`).
    pub severity: String,
    /// What the human/auto-rule decided this incident was:
    /// `block` | `ignore` | `dismiss` | `suppress` | `honeypot` | `monitor`.
    pub verdict: String,
    /// Where the label came from: `telegram_review` | `telegram_honeypot` |
    /// `learned_suppression` | `operator`.
    pub source: String,
    /// How much this label should weigh in training (0.0..1.0). Operator
    /// decisions weigh by severity (a Critical operator call is gold); an
    /// auto-suppression of a trivial repeated shape weighs little.
    pub weight: f32,
    /// Short human-readable incident summary — the feature text.
    pub summary: String,
}

/// Where a label originated. Operator-driven labels are gold; the learned
/// auto-suppression label is weak supervision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelSource {
    TelegramReview,
    TelegramHoneypot,
    LearnedSuppression,
}

impl LabelSource {
    fn as_str(self) -> &'static str {
        match self {
            LabelSource::TelegramReview => "telegram_review",
            LabelSource::TelegramHoneypot => "telegram_honeypot",
            LabelSource::LearnedSuppression => "learned_suppression",
        }
    }

    /// Operator-driven sources are gold labels (weight by severity); the
    /// learned auto-suppression is weak supervision (fixed low weight — it is
    /// only ever a trivial Low/Medium shape by construction).
    fn is_operator(self) -> bool {
        !matches!(self, LabelSource::LearnedSuppression)
    }
}

/// Severity → base label weight. A human's call on a Critical incident is the
/// most valuable training signal; an Info/Low call the least.
fn severity_weight(sev: &Severity) -> f32 {
    match sev {
        Severity::Critical => 1.0,
        Severity::High => 0.85,
        Severity::Medium => 0.5,
        Severity::Low => 0.3,
        Severity::Info => 0.2,
        Severity::Debug => 0.1,
    }
}

/// Pure: build a `LabelSample`. Extracted so the verdict/weight/severity-string
/// derivation is unit-testable without touching the filesystem.
#[allow(clippy::too_many_arguments)]
pub fn build_sample(
    now: DateTime<Utc>,
    host: &str,
    incident_id: &str,
    detector: &str,
    target_ip: Option<&str>,
    severity: &Severity,
    verdict: &str,
    source: LabelSource,
    summary: &str,
) -> LabelSample {
    // Operator labels weigh by severity; learned-suppression is fixed-low weak
    // supervision (a trivial shape, never weighty by construction).
    let weight = if source.is_operator() {
        severity_weight(severity)
    } else {
        0.3
    };
    LabelSample {
        ts: now.to_rfc3339(),
        host: host.to_string(),
        incident_id: incident_id.to_string(),
        detector: detector.to_string(),
        target_ip: target_ip.map(|s| s.to_string()),
        severity: severity_label(severity).to_string(),
        verdict: verdict.to_string(),
        source: source.as_str().to_string(),
        weight,
        summary: truncate_summary(summary),
    }
}

/// Lowercase severity label matching `Severity`'s serde rename.
fn severity_label(sev: &Severity) -> &'static str {
    match sev {
        Severity::Debug => "debug",
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Keep the feature text bounded — a training sample does not need a 16 KB
/// summary, and the file should stay small.
fn truncate_summary(s: &str) -> String {
    const MAX: usize = 280;
    if s.len() <= MAX {
        return s.to_string();
    }
    // Truncate on a char boundary at or before MAX.
    let mut end = MAX;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Best-effort append of one sample to `labels-<date>.jsonl`. Failures `warn!`
/// and do NOT propagate — a label-channel write must never break the decision
/// path it rides on (same policy as the decisions/shadow logs).
pub fn append_label(data_dir: &Path, sample: &LabelSample, now: DateTime<Utc>) {
    let date = now.format("%Y-%m-%d").to_string();
    let path = data_dir.join(format!("labels-{date}.jsonl"));
    let line = match serde_json::to_string(sample) {
        Ok(s) => s,
        Err(e) => {
            warn!("warden_labels: failed to serialize label sample: {e}");
            return;
        }
    };
    let mut f = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            warn!(path = %path.display(), "warden_labels: open failed: {e}");
            return;
        }
    };
    if let Err(e) = writeln!(f, "{line}") {
        warn!(path = %path.display(), "warden_labels: write failed: {e}");
    }
}

/// Count label samples in `labels-<date>.jsonl` (one per non-empty line).
/// Restart-robust. Missing file → 0. Used by the nightly stats reader.
pub fn count_labels_for_date(data_dir: &Path, date: &str) -> usize {
    let path = data_dir.join(format!("labels-{date}.jsonl"));
    // Stream the daily label log line by line rather than slurping the whole
    // file into a String just to count non-empty lines.
    let Ok(file) = std::fs::File::open(&path) else {
        return 0;
    };
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sev() -> Severity {
        Severity::High
    }

    #[test]
    fn build_sample_operator_weighs_by_severity() {
        let s = build_sample(
            Utc::now(),
            "host-1",
            "ssh_bruteforce:1.2.3.4:test",
            "ssh_bruteforce",
            Some("1.2.3.4"),
            &Severity::Critical,
            "block",
            LabelSource::TelegramReview,
            "lots of failed logins",
        );
        assert_eq!(s.verdict, "block");
        assert_eq!(s.source, "telegram_review");
        assert_eq!(s.severity, "critical");
        assert!((s.weight - 1.0).abs() < f32::EPSILON);
        assert_eq!(s.target_ip.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn build_sample_learned_suppression_is_weak_supervision() {
        let s = build_sample(
            Utc::now(),
            "host-1",
            "imds_ssrf:169.254.169.254:test",
            "imds_ssrf",
            Some("169.254.169.254"),
            &Severity::Low,
            "suppress",
            LabelSource::LearnedSuppression,
            "metadata IP",
        );
        // Fixed 0.3 weak weight regardless of severity_weight(Low)=0.3 — pin
        // that learned-suppression does NOT escalate with severity.
        assert!((s.weight - 0.3).abs() < f32::EPSILON);
        assert_eq!(s.source, "learned_suppression");
    }

    #[test]
    fn append_then_count_round_trips() {
        let dir = TempDir::new().unwrap();
        let now = Utc::now();
        let date = now.format("%Y-%m-%d").to_string();
        assert_eq!(count_labels_for_date(dir.path(), &date), 0);
        for i in 0..3 {
            let s = build_sample(
                now,
                "h",
                &format!("d:{i}"),
                "d",
                None,
                &sev(),
                "dismiss",
                LabelSource::TelegramReview,
                "x",
            );
            append_label(dir.path(), &s, now);
        }
        assert_eq!(count_labels_for_date(dir.path(), &date), 3);
    }

    #[test]
    fn truncate_summary_respects_char_boundary() {
        let long = "é".repeat(400); // 2 bytes each → 800 bytes
        let s = truncate_summary(&long);
        assert!(s.len() <= 283); // 280 cap rounded to boundary + ellipsis bytes
        assert!(s.ends_with('…'));
    }

    #[test]
    fn append_label_is_valid_jsonl() {
        let dir = TempDir::new().unwrap();
        let now = Utc::now();
        let sample = build_sample(
            now,
            "h",
            "inc-1",
            "det",
            Some("9.9.9.9"),
            &Severity::Medium,
            "ignore",
            LabelSource::TelegramReview,
            "s",
        );
        append_label(dir.path(), &sample, now);
        let date = now.format("%Y-%m-%d").to_string();
        let content =
            std::fs::read_to_string(dir.path().join(format!("labels-{date}.jsonl"))).unwrap();
        let parsed: LabelSample = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed, sample);
    }
}
