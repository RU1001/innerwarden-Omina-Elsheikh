/// Allowlist - trusted IPs, CIDRs, and users that skip automated AI response.
///
/// Incidents involving allowlisted entities are still logged, still sent to
/// webhook/Telegram/Slack, but are not forwarded to the AI gate and will
/// never trigger an automatic skill execution.
///
/// Sources (merged at check time):
/// 1. Static config: `[allowlist]` in agent.toml
/// 2. YAML rules: `suppress_response` rules in /etc/innerwarden/rules/event_pipeline/
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

/// Returns true if `ip` matches any entry in `trusted_ips`.
/// Entries may be exact IPs ("1.2.3.4") or CIDR notation ("192.168.0.0/24").
pub fn is_ip_allowlisted(ip: &str, trusted_ips: &[String]) -> bool {
    trusted_ips.iter().any(|entry| ip_matches(ip, entry))
}

/// Returns true if `user` matches any entry in `trusted_users`.
pub fn is_user_allowlisted(user: &str, trusted_users: &[String]) -> bool {
    trusted_users.iter().any(|u| u == user)
}

fn ip_matches(ip_str: &str, entry: &str) -> bool {
    // Exact match
    if ip_str == entry {
        return true;
    }

    // CIDR match
    let Some((base_str, prefix_str)) = entry.split_once('/') else {
        return false;
    };
    let Ok(prefix_len) = prefix_str.parse::<u32>() else {
        return false;
    };
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    let Ok(base) = base_str.parse::<IpAddr>() else {
        return false;
    };

    match (ip, base) {
        (IpAddr::V4(ip4), IpAddr::V4(base4)) if prefix_len <= 32 => {
            let shift = 32u32.saturating_sub(prefix_len);
            // When prefix_len == 0, mask is 0 → matches all
            let mask = if shift >= 32 { 0u32 } else { !0u32 << shift };
            (u32::from(ip4) & mask) == (u32::from(base4) & mask)
        }
        (IpAddr::V6(ip6), IpAddr::V6(base6)) if prefix_len <= 128 => {
            let shift = 128u32.saturating_sub(prefix_len);
            let mask = if shift >= 128 { 0u128 } else { !0u128 << shift };
            (u128::from(ip6) & mask) == (u128::from(base6) & mask)
        }
        _ => false,
    }
}

/// YAML-sourced response suppressions loaded from /etc/innerwarden/rules/event_pipeline/.
/// Merged with static config at check time.
pub struct YamlResponseRules {
    pub trusted_ips: Vec<String>,
    pub trusted_users: Vec<String>,
    pub trusted_processes: Vec<String>,
    pub suppress_detectors: std::collections::HashMap<String, HashSet<String>>,
}

impl YamlResponseRules {
    pub fn load(rules_dir: &Path) -> Self {
        Self::load_at(rules_dir, chrono::Utc::now())
    }

    /// `load` with an injectable clock so time-boxed rules (`expires_at`) are
    /// testable. A rule whose `expires_at` (RFC3339) is at/before `now` is
    /// skipped — this is how the dashboard "Trust IP" TTL lapses on its own.
    /// An unparseable `expires_at` is treated as "no expiry" (lenient, matching
    /// the loader's skip-what-you-can't-parse style); the dashboard always
    /// writes a valid RFC3339 timestamp.
    pub fn load_at(rules_dir: &Path, now: chrono::DateTime<chrono::Utc>) -> Self {
        let mut rules = Self {
            trusted_ips: Vec::new(),
            trusted_users: Vec::new(),
            trusted_processes: Vec::new(),
            suppress_detectors: std::collections::HashMap::new(),
        };

        if !rules_dir.is_dir() {
            return rules;
        }

        let Ok(entries) = std::fs::read_dir(rules_dir) else {
            return rules;
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if (!name.ends_with(".yml") && !name.ends_with(".yaml"))
                || !entry.file_type().is_ok_and(|t| t.is_file())
            {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
                continue;
            };
            let Some(rule_list) = doc.get("rules").and_then(|v| v.as_sequence()) else {
                continue;
            };

            for rule_val in rule_list {
                let disabled = rule_val
                    .get("disabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if disabled {
                    continue;
                }

                // Time-boxed rules: skip when expired so dashboard "Trust IP"
                // TTL entries lapse on the next reload with no manual cleanup.
                if let Some(exp) = rule_val.get("expires_at").and_then(|v| v.as_str()) {
                    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(exp) {
                        if now >= parsed.with_timezone(&chrono::Utc) {
                            continue;
                        }
                    }
                }

                let action = rule_val
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                match action {
                    "suppress_response" => {
                        let Some(suppress) = rule_val.get("suppress") else {
                            continue;
                        };
                        let scope = suppress.get("scope").and_then(|v| v.as_str()).unwrap_or("");
                        let values: Vec<String> = suppress
                            .get("values")
                            .and_then(|v| v.as_sequence())
                            .map(|seq| {
                                seq.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();

                        match scope {
                            "ip" => rules.trusted_ips.extend(values),
                            "user" => rules.trusted_users.extend(values),
                            "process" => rules.trusted_processes.extend(values),
                            _ => {}
                        }
                    }
                    "suppress_incident" => {
                        let Some(suppress) = rule_val.get("suppress") else {
                            continue;
                        };
                        let detector = suppress
                            .get("detector")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if detector.is_empty() {
                            continue;
                        }
                        let values: Vec<String> = suppress
                            .get("values")
                            .and_then(|v| v.as_sequence())
                            .map(|seq| {
                                seq.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let entry = rules
                            .suppress_detectors
                            .entry(detector.to_string())
                            .or_default();
                        for v in values {
                            entry.insert(v);
                        }
                    }
                    _ => {}
                }
            }
        }

        rules
    }

    #[allow(dead_code)]
    pub fn empty() -> Self {
        Self {
            trusted_ips: Vec::new(),
            trusted_users: Vec::new(),
            trusted_processes: Vec::new(),
            suppress_detectors: std::collections::HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_ipv4_match() {
        assert!(ip_matches("1.2.3.4", "1.2.3.4"));
        assert!(!ip_matches("1.2.3.5", "1.2.3.4"));
    }

    #[test]
    fn cidr_v4_slash24() {
        assert!(ip_matches("192.168.1.1", "192.168.1.0/24"));
        assert!(ip_matches("192.168.1.254", "192.168.1.0/24"));
        assert!(!ip_matches("192.168.2.1", "192.168.1.0/24"));
    }

    #[test]
    fn cidr_v4_slash16() {
        assert!(ip_matches("10.0.255.1", "10.0.0.0/16"));
        assert!(!ip_matches("10.1.0.1", "10.0.0.0/16"));
    }

    #[test]
    fn cidr_v4_slash32() {
        assert!(ip_matches("1.2.3.4", "1.2.3.4/32"));
        assert!(!ip_matches("1.2.3.5", "1.2.3.4/32"));
    }

    #[test]
    fn cidr_v4_slash0_matches_all() {
        assert!(ip_matches("1.2.3.4", "0.0.0.0/0"));
        assert!(ip_matches("255.255.255.255", "0.0.0.0/0"));
    }

    #[test]
    fn ipv6_exact() {
        assert!(ip_matches("::1", "::1"));
        assert!(!ip_matches("::2", "::1"));
    }

    #[test]
    fn ipv6_cidr() {
        assert!(ip_matches("2001:db8::1", "2001:db8::/32"));
        assert!(!ip_matches("2001:db9::1", "2001:db8::/32"));
    }

    #[test]
    fn invalid_cidr_does_not_panic() {
        assert!(!ip_matches("1.2.3.4", "not-a-cidr"));
        assert!(!ip_matches("1.2.3.4", "1.2.3.0/abc"));
    }

    #[test]
    fn is_ip_allowlisted_returns_true_when_matched() {
        let list = vec!["192.168.1.0/24".to_string(), "10.0.0.1".to_string()];
        assert!(is_ip_allowlisted("192.168.1.50", &list));
        assert!(is_ip_allowlisted("10.0.0.1", &list));
        assert!(!is_ip_allowlisted("1.2.3.4", &list));
    }

    #[test]
    fn is_ip_allowlisted_empty_list() {
        assert!(!is_ip_allowlisted("1.2.3.4", &[]));
    }

    #[test]
    fn is_user_allowlisted_matches() {
        let list = vec!["deploy".to_string(), "backup".to_string()];
        assert!(is_user_allowlisted("deploy", &list));
        assert!(!is_user_allowlisted("root", &list));
    }

    #[test]
    fn is_user_allowlisted_empty_list() {
        assert!(!is_user_allowlisted("root", &[]));
    }

    #[test]
    fn yaml_rules_load_suppress_response() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: protect-docker
    action: suppress_response
    suppress:
      scope: ip
      values: ["172.18.0.0/16", "10.0.0.0/8"]
  - id: protect-deploy
    action: suppress_response
    suppress:
      scope: user
      values: [deploy, backup]
  - id: protect-sshd
    action: suppress_response
    suppress:
      scope: process
      values: [sshd]
"#;
        std::fs::write(dir.path().join("30-response-rules.yml"), yaml).unwrap();
        let rules = YamlResponseRules::load(dir.path());
        assert_eq!(rules.trusted_ips, vec!["172.18.0.0/16", "10.0.0.0/8"]);
        assert_eq!(rules.trusted_users, vec!["deploy", "backup"]);
        assert_eq!(rules.trusted_processes, vec!["sshd"]);
    }

    #[test]
    fn yaml_rules_load_suppress_incident() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: allow-bcache
    action: suppress_incident
    suppress:
      detector: kernel_module_load
      values: [bcache, dm_raid]
"#;
        std::fs::write(dir.path().join("20-suppress.yml"), yaml).unwrap();
        let rules = YamlResponseRules::load(dir.path());
        assert!(rules
            .suppress_detectors
            .get("kernel_module_load")
            .unwrap()
            .contains("bcache"));
    }

    #[test]
    fn yaml_rules_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let rules = YamlResponseRules::load(dir.path());
        assert!(rules.trusted_ips.is_empty());
        assert!(rules.trusted_users.is_empty());
    }

    #[test]
    fn yaml_rules_nonexistent_dir() {
        let rules = YamlResponseRules::load(std::path::Path::new("/nonexistent"));
        assert!(rules.trusted_ips.is_empty());
    }

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn yaml_rules_expired_rule_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: operator-trust-temp
    action: suppress_response
    suppress:
      scope: ip
      values: ["203.0.113.10"]
    expires_at: "2026-06-13T10:00:00Z"
"#;
        std::fs::write(dir.path().join("70-operator-trust.yml"), yaml).unwrap();
        // before expiry → present
        let before = YamlResponseRules::load_at(dir.path(), at("2026-06-13T09:59:59Z"));
        assert_eq!(before.trusted_ips, vec!["203.0.113.10"]);
        // at/after expiry → gone
        let after = YamlResponseRules::load_at(dir.path(), at("2026-06-13T10:00:00Z"));
        assert!(after.trusted_ips.is_empty());
    }

    #[test]
    fn yaml_rules_unparseable_expiry_is_lenient() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: bad-expiry
    action: suppress_response
    suppress:
      scope: ip
      values: ["10.0.0.1"]
    expires_at: "not-a-date"
"#;
        std::fs::write(dir.path().join("10-bad.yml"), yaml).unwrap();
        let rules = YamlResponseRules::load_at(dir.path(), at("2026-06-13T10:00:00Z"));
        assert_eq!(rules.trusted_ips, vec!["10.0.0.1"]);
    }

    #[test]
    fn yaml_rules_disabled_rule_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: disabled-rule
    action: suppress_response
    suppress:
      scope: ip
      values: ["1.2.3.4"]
    disabled: true
"#;
        std::fs::write(dir.path().join("10-disabled.yml"), yaml).unwrap();
        let rules = YamlResponseRules::load(dir.path());
        assert!(rules.trusted_ips.is_empty());
    }

    #[test]
    fn yaml_rules_merged_with_static_config() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
version: 1
rules:
  - id: protect-yaml-ip
    action: suppress_response
    suppress:
      scope: ip
      values: ["10.0.0.0/8"]
"#;
        std::fs::write(dir.path().join("10-test.yml"), yaml).unwrap();
        let rules = YamlResponseRules::load(dir.path());

        // Merge: static config has 192.168.1.0/24, YAML has 10.0.0.0/8
        let mut all_ips = vec!["192.168.1.0/24".to_string()];
        all_ips.extend(rules.trusted_ips);

        assert!(is_ip_allowlisted("192.168.1.50", &all_ips));
        assert!(is_ip_allowlisted("10.0.0.1", &all_ips));
        assert!(!is_ip_allowlisted("1.2.3.4", &all_ips));
    }
}
