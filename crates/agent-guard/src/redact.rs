//! Secret / PII redaction transform (OWASP Agentic **ASI07 — Memory Leakage**).
//!
//! An AI agent that reads a tool response, a retrieved document, or a file and
//! carries it into its context window leaks whatever secrets/PII that content
//! held into the model's short-term memory (and often into downstream logs and
//! replies). This transform scrubs the primary leakage vector — obvious secrets
//! and PII — from any text crossing INTO the agent's context, so injected
//! credentials never become part of what the model remembers.
//!
//! Scope note (honest): this covers the primary vector (secrets/PII in
//! text-crossing-the-boundary). It is NOT a full memory-store scrubber; a
//! persistent long-term memory store needs its own turn-level scrubbing.

use std::sync::OnceLock;

use regex::Regex;

/// Result of redacting a blob: the scrubbed text and how many spans were masked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redaction {
    pub text: String,
    pub count: usize,
}

struct Pattern {
    re: Regex,
    /// When set, only this capture group is masked (keeps the `key=` prefix so
    /// the shape is still readable); otherwise the whole match is masked.
    group: Option<usize>,
}

fn patterns() -> &'static [Pattern] {
    static P: OnceLock<Vec<Pattern>> = OnceLock::new();
    P.get_or_init(|| {
        let mk = |re: &str, group: Option<usize>| Pattern {
            re: Regex::new(re).expect("static redaction regex"),
            group,
        };
        vec![
            // PEM private keys (whole block header — enough to flag+mask).
            mk(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", None),
            // AWS access key id.
            mk(r"AKIA[0-9A-Z]{16}", None),
            // Bearer / authorization tokens.
            mk(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}", None),
            // key=value secrets: password / passwd / token / secret / api[_-]key.
            mk(
                r#"(?i)(password|passwd|token|secret|api[_-]?key|access[_-]?key)\s*[=:]\s*['"]?([^\s'"]{6,})"#,
                Some(2),
            ),
            // JWT (three base64url segments).
            mk(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}", None),
            // US SSN.
            mk(r"\b\d{3}-\d{2}-\d{4}\b", None),
            // 16-digit card number (grouped or not).
            mk(r"\b(?:\d[ -]?){15}\d\b", None),
        ]
    })
}

const MASK: &str = "[REDACTED]";

/// Scrub obvious secrets and PII from `input`, returning the redacted text and
/// the number of spans masked. Deterministic and allocation-light on the common
/// (nothing-to-redact) path.
pub fn redact_secrets(input: &str) -> Redaction {
    let mut text = input.to_string();
    let mut count = 0usize;
    for p in patterns() {
        // Collect matches first (mutating while iterating a live regex is awkward);
        // replace group-or-whole, right-to-left so byte offsets stay valid.
        let spans: Vec<(usize, usize)> =
            p.re.captures_iter(&text)
                .filter_map(|c| match p.group {
                    Some(g) => c.get(g).map(|m| (m.start(), m.end())),
                    None => c.get(0).map(|m| (m.start(), m.end())),
                })
                .collect();
        for (start, end) in spans.into_iter().rev() {
            text.replace_range(start..end, MASK);
            count += 1;
        }
    }
    Redaction { text, count }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_common_secrets_and_pii() {
        let raw =
            "here is my key AKIA1234567890ABCDEF and password=hunter2secret and ssn 123-45-6789";
        let r = redact_secrets(raw);
        assert!(r.count >= 3, "expected >=3 redactions, got {}", r.count);
        assert!(!r.text.contains("AKIA1234567890ABCDEF"));
        assert!(!r.text.contains("hunter2secret"));
        assert!(!r.text.contains("123-45-6789"));
        // The key= prefix stays so the shape is still readable.
        assert!(r.text.contains("password=[REDACTED]"));
    }

    #[test]
    fn leaves_clean_text_untouched() {
        let r = redact_secrets("ls -la /home/user/project && git status");
        assert_eq!(r.count, 0);
        assert_eq!(r.text, "ls -la /home/user/project && git status");
    }

    #[test]
    fn masks_pem_private_key_and_jwt() {
        let raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\ntoken: eyJhbGciOi.eyJzdWIiOiI.SflKxwRJ";
        let r = redact_secrets(raw);
        assert!(!r.text.contains("BEGIN RSA PRIVATE KEY"));
        assert!(r.count >= 2);
    }
}
