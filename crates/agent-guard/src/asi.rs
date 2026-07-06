//! OWASP Agentic Top 10 (ASI01-ASI10, December 2025) taxonomy and mapping.
//!
//! InnerWarden's AI-agent guardrail detects concrete behaviours (ATR rule
//! categories + built-in command signals + injection patterns). This module
//! maps each of those to the OWASP Agentic threat it mitigates, so a guard
//! verdict can report *which* agentic threat class it caught (the "reason chain"
//! on a deny), and so the product's OWASP coverage can be **derived from the
//! code that actually fires** rather than asserted in marketing copy.
//!
//! Reference: OWASP Top 10 for Agentic Applications — <https://genai.owasp.org>.

/// One OWASP Agentic Top 10 threat class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct AsiThreat {
    pub id: &'static str,
    pub name: &'static str,
}

/// The ten OWASP Agentic threat classes, in order.
pub const ASI_TOP_10: [AsiThreat; 10] = [
    AsiThreat {
        id: "ASI01",
        name: "Agent Goal Hijack",
    },
    AsiThreat {
        id: "ASI02",
        name: "Tool Misuse",
    },
    AsiThreat {
        id: "ASI03",
        name: "Delegated Trust",
    },
    AsiThreat {
        id: "ASI04",
        name: "Data Exfiltration",
    },
    AsiThreat {
        id: "ASI05",
        name: "Privilege Escalation",
    },
    AsiThreat {
        id: "ASI06",
        name: "Inter-Agent / Cross-Boundary",
    },
    AsiThreat {
        id: "ASI07",
        name: "Memory Leakage",
    },
    AsiThreat {
        id: "ASI08",
        name: "Operator Control",
    },
    AsiThreat {
        id: "ASI09",
        name: "Cost / Quota Abuse",
    },
    AsiThreat {
        id: "ASI10",
        name: "Rogue Agents",
    },
];

/// Look up an [`AsiThreat`] by its id (`"ASI02"`), if valid.
pub fn threat(id: &str) -> Option<&'static AsiThreat> {
    ASI_TOP_10.iter().find(|t| t.id == id)
}

/// Map an ATR rule category to its primary OWASP Agentic threat id. Unknown
/// categories return `None` (honest: an unmapped category claims no ASI).
pub fn category_to_asi(category: &str) -> Option<&'static str> {
    Some(match category.trim().to_ascii_lowercase().as_str() {
        // Injected/manipulated intent → the model does something it was told to
        // by untrusted content, not the operator.
        "prompt-injection"
        | "agent-manipulation"
        | "agent-identity-spoofing"
        | "cjk-social-engineering"
        | "consensus-poisoning"
        | "consensus-sybil-attack"
        | "consent-bypass-instruction"
        | "data-poisoning" => "ASI01",
        // Using a legitimate tool for an illegitimate call.
        "tool-poisoning" | "skill-compromise" | "model-security" => "ASI02",
        // Acting beyond delegated authority / bypassing the approval a human owes.
        "excessive-autonomy" | "approval-fatigue" => "ASI03",
        // Reading/leaking secrets or context out of the boundary.
        "context-exfiltration" | "credential-exposure" => "ASI04",
        // Gaining more privilege than granted.
        "privilege-escalation" => "ASI05",
        // Hiding the trail / defeating the operator's oversight.
        "audit-evasion" => "ASI08",
        // A compromised agent cascading into destructive/rogue behaviour.
        "cascading-failure" => "ASI10",
        _ => return None,
    })
}

/// Map a built-in command signal label (from `analyze_command`) to its primary
/// OWASP Agentic threat id.
pub fn signal_to_asi(signal: &str) -> Option<&'static str> {
    Some(match signal {
        // Injection / evasion of the model's intent.
        "obfuscated_command" => "ASI01",
        // Misusing the shell tool to fetch+run or run untrusted code.
        "download_and_execute"
        | "download_chmod_execute"
        | "tmp_execution"
        | "dangerous_command" => "ASI02",
        // Reading secrets / credentials out of the environment.
        "credential_access" => "ASI04",
        // Escalating privilege.
        "insecure_permissions" => "ASI05",
        // Tampering with the security layer that gives the operator control.
        "security_tooling_tamper" => "ASI08",
        // Rogue-agent behaviour: reverse shells, destruction, persistence.
        "reverse_shell" | "destructive_command" | "persistence_attempt" => "ASI10",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top10_is_complete_and_unique() {
        assert_eq!(ASI_TOP_10.len(), 10);
        for (i, t) in ASI_TOP_10.iter().enumerate() {
            assert_eq!(t.id, format!("ASI{:02}", i + 1));
            assert!(!t.name.is_empty());
        }
    }

    #[test]
    fn mappings_only_yield_valid_ids() {
        for c in [
            "prompt-injection",
            "tool-poisoning",
            "excessive-autonomy",
            "context-exfiltration",
            "privilege-escalation",
            "audit-evasion",
            "cascading-failure",
        ] {
            assert!(
                threat(category_to_asi(c).unwrap()).is_some(),
                "category {c}"
            );
        }
        for s in [
            "reverse_shell",
            "download_and_execute",
            "insecure_permissions",
            "security_tooling_tamper",
            "obfuscated_command",
        ] {
            assert!(threat(signal_to_asi(s).unwrap()).is_some(), "signal {s}");
        }
        assert!(category_to_asi("not-a-real-category").is_none());
        assert!(signal_to_asi("not_a_signal").is_none());
    }
}
