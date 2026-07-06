//! Spec 071 Part A — deterministic Context Gate around the Warden classifier.
//!
//! The on-device Warden ONNX is fed only `detector | severity | title |
//! summary` (see [`crate::ai::local_classifier`]). It cannot see the actor's
//! provenance, so it (a) punts benign self/build activity into the review queue
//! and (b) occasionally under-rates a real high-severity threat with a
//! low-confidence dismiss. This deterministic wrapper corrects both, WITHOUT
//! retraining the model, using only the context the agent already holds.
//!
//! # Hard safety boundary (red-team driven, spec 071)
//!
//! The only provenance signal available here is the actor's `comm` (process
//! name), and `comm` is **attacker-forgeable** (`bpf_get_current_comm` is the
//! basename of the binary, settable via argv0 / `prctl(PR_SET_NAME)`). A
//! 2026-06-08 adversarial review proved that auto-dismissing on `comm` turns
//! real attacks into silence — naming a malicious binary `innerwarden` or
//! `cargo` would have laundered a Critical privesc, a `/tmp` exec, or a
//! credential exfil into a confident dismiss, and even undone spec-070's
//! NON-forgeable exe-path provenance. Therefore:
//!
//!   * **High/Critical incidents are NEVER auto-dismissed here.** A forgeable
//!     signal must never blind the system to a serious incident. At most, the
//!     gate *surfaces* them (Monitor / RequestConfirmation) — never buries them.
//!   * **The provenance dismiss is restricted to Medium/Low severity** AND to a
//!     tiny allowlist of detector classes that are benign-by-construction for a
//!     self/build actor and that an attacker inhabiting a spoofed process name
//!     gains nothing from (file-churn noise like `suspicious_archive`). Every
//!     High/Critical-capable attack class (privesc, host_drift, data_exfil*) is
//!     deliberately EXCLUDED.
//!   * **A correct enforcement verdict is never laundered into a dismiss.** On a
//!     High/Critical incident with a (forgeable) benign-provenance match, an
//!     enforcement action is downgraded to a human-veto surface, not silenced.
//!
//! The escalation half (surfacing an under-rated High/Critical) is protective:
//! it can only make the system MORE cautious, never hide an attack.
//!
//! The durable fix for benign-self/build FPs is either at the detector (where
//! the class is precisely scoped — see spec 071 Part B) or NON-forgeable
//! exe-path / uid provenance plumbed into `DecisionContext` (spec 071 Part D).
//! This gate intentionally does the minimum that is provably safe on a
//! forgeable signal.

use crate::ai::{AiAction, AiDecision, DecisionContext};
use innerwarden_core::event::Severity;

/// Passive-close confidence at or below which a High/Critical verdict is
/// treated as "the classifier was not sure" and surfaced rather than trusted.
const ESCALATE_FLOOR: f32 = 0.85;

/// AbuseIPDB confidence (0-100) at or above which the community has near-certain
/// consensus that an IP is a malicious actor. Deliberately high: a cloud-range
/// safelist (`safelist=Google Cloud`, etc.) must not buy such an IP a free
/// passive close, but a borderline score should not flood the operator with
/// surfaces. Escalate-only (surface, never block), so even a noisy shared-cloud
/// IP at this score only gets Monitored, never auto-blocked.
const ABUSE_CONFIRMED_FLOOR: u8 = 90;

/// Process names (`comm`) of InnerWarden's own components. Matched by EXACT
/// base-name equality (never prefix — `comm` is forgeable and a prefix match
/// let `innerwarden9` / `ccminer` impersonate a component). Linux truncates
/// `comm` at 15 chars, so the truncated forms are listed explicitly.
const SELF_COMPONENT_COMMS: &[&str] = &[
    "innerwarden-agent",
    "innerwarden-sensor",
    "innerwarden-ctl",
    "innerwarden-watchdog",
    "innerwarden-supervisor",
    // 15-char comm truncations of the above:
    "innerwarden-age",
    "innerwarden-sen",
    "innerwarden-ctl",
    "innerwarden-wat",
    "innerwarden-sup",
];

/// Compiler / linker / build-script process names (exact base-name match).
const BUILD_TOOLCHAIN_COMMS: &[&str] = &[
    "cargo",
    "rustc",
    "rust-lld",
    "build-script-build",
    "build-script-bu",
    "zig",
    "cc",
    "cc1",
    "cc1plus",
    "gcc",
    "g++",
    "clang",
    "collect2",
    "ld",
    "as",
    "lto-wrapper",
    "make",
    "cmake",
    "ninja",
];

/// Detector classes an InnerWarden component / build tool trips benignly AND
/// only ever at Medium/Low severity. DELIBERATELY EXCLUDES every
/// High/Critical-capable attack class (privesc, host_drift, data_exfil*,
/// data_exfiltration): on a forgeable `comm` those must never be dismissed
/// (red-team B1-B3). `suspicious_archive` is file-churn an attacker gains
/// nothing from spoofing into.
const SELF_NOISY_DETECTORS: &[&str] = &["suspicious_archive"];
const BUILD_NOISY_DETECTORS: &[&str] = &["suspicious_archive"];

/// Positively-identified provenance of the actor. Anything uncertain is
/// `Unknown`; the gate takes no dismiss action on `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActorProvenance {
    SelfComponent,
    BuildToolchain,
    Unknown,
}

/// Extract the actor's `comm` from context (recent_events, then `comm=` in the
/// summary, then the `<detector>:<comm>:...` incident_id form). All three are
/// forgeable — see the module-level safety boundary; provenance is only ever
/// used to DISMISS Medium/Low or to SURFACE High/Critical, never to silence.
fn actor_comm(ctx: &DecisionContext<'_>) -> Option<String> {
    for ev in &ctx.recent_events {
        if let Some(c) = ev.details.get("comm").and_then(|v| v.as_str()) {
            if !c.is_empty() && c != "unknown" {
                return Some(c.to_string());
            }
        }
    }
    if let Some(rest) = ctx.incident.summary.split("comm=").nth(1) {
        let c: String = rest
            .chars()
            .take_while(|ch| !ch.is_whitespace() && *ch != ',' && *ch != ')')
            .collect();
        if !c.is_empty() {
            return Some(c);
        }
    }
    let parts: Vec<&str> = ctx.incident.incident_id.split(':').collect();
    if parts.len() >= 2 && !parts[1].is_empty() {
        return Some(parts[1].to_string());
    }
    None
}

/// EXACT base-name match against an allowlist (no prefix matching).
fn comm_matches(comm: &str, list: &[&str]) -> bool {
    let base = comm.rsplit('/').next().unwrap_or(comm);
    list.contains(&base)
}

/// Detector class = the substring of `incident_id` before the first `:`.
fn detector_class<'a>(ctx: &DecisionContext<'a>) -> &'a str {
    ctx.incident
        .incident_id
        .split(':')
        .next()
        .unwrap_or("unknown")
}

/// Classify the actor. Fail-closed: `Unknown` unless a self/build process name
/// is positively (exact-)matched.
pub(crate) fn classify_provenance(ctx: &DecisionContext<'_>) -> ActorProvenance {
    let Some(comm) = actor_comm(ctx) else {
        return ActorProvenance::Unknown;
    };
    if comm_matches(&comm, SELF_COMPONENT_COMMS) {
        return ActorProvenance::SelfComponent;
    }
    if comm_matches(&comm, BUILD_TOOLCHAIN_COMMS) {
        return ActorProvenance::BuildToolchain;
    }
    ActorProvenance::Unknown
}

fn is_passive_close(action: &AiAction) -> bool {
    matches!(action, AiAction::Dismiss { .. } | AiAction::Ignore { .. })
}

/// True when AbuseIPDB reports near-certain malice for this IP. Like the DShield
/// signal this is an externally-sourced, non-forgeable reputation: it is used
/// ONLY to refuse a passive close (escalate-only), never to relax an
/// enforcement verdict. Closes the prod blind spot where a cloud-range safelist
/// (e.g. `safelist=Google Cloud`) let the classifier `ignore` an
/// `abuseipdb=100` IP, a free pass an attacker buys by renting cloud.
fn ip_abuse_confirmed(ctx: &DecisionContext<'_>) -> bool {
    ctx.ip_reputation
        .as_ref()
        .is_some_and(|r| r.confidence_score >= ABUSE_CONFIRMED_FLOOR)
}

fn is_high_severity(sev: &Severity) -> bool {
    matches!(sev, Severity::High | Severity::Critical)
}

/// True if any evidence object carries the spec-070 NON-forgeable provenance tag
/// `provenance:illegitimate` (the sensor proved an untrusted exe-path lineage).
fn evidence_provenance_is_illegitimate(ctx: &DecisionContext<'_>) -> bool {
    let is_illegit = |v: &serde_json::Value| {
        v.get("provenance").and_then(|p| p.as_str()) == Some("provenance:illegitimate")
    };
    let ev = &ctx.incident.evidence;
    match ev.as_array() {
        Some(arr) => arr.iter().any(is_illegit),
        None => is_illegit(ev),
    }
}

fn primary_ip(ctx: &DecisionContext<'_>) -> Option<String> {
    ctx.incident
        .entities
        .iter()
        .find(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Ip))
        .map(|e| e.value.clone())
}

/// Surface (do not bury) a High/Critical incident: Monitor the IP if present,
/// else request operator confirmation. Never auto-executes.
fn surface(ctx: &DecisionContext<'_>, why: String, threat: String) -> AiDecision {
    let action = match primary_ip(ctx) {
        Some(ip) => AiAction::Monitor { ip },
        None => AiAction::RequestConfirmation {
            summary: why.clone(),
        },
    };
    AiDecision {
        action,
        confidence: ESCALATE_FLOOR,
        auto_execute: false,
        reason: why,
        alternatives: vec![],
        estimated_threat: threat,
    }
}

/// Apply the Context Gate to the Warden classifier's decision. Pure, no I/O.
pub(crate) fn apply(ctx: &DecisionContext<'_>, decision: AiDecision) -> AiDecision {
    let detector = detector_class(ctx);
    let provenance = classify_provenance(ctx);
    let high_sev = is_high_severity(&ctx.incident.severity);

    // Spec 072 Phase 2: a detector's NON-forgeable provenance verdict overrides
    // the text-only classifier. If the sensor proved illegitimate lineage
    // (spec-070 exe-path provenance, recorded in `evidence.provenance`) but the
    // classifier wants to close the incident, refuse it — surface regardless of
    // the classifier's confidence. Symmetric to the comm rule: a forgeable comm
    // can never DISMISS High/Critical; a non-forgeable `illegitimate` verdict can
    // never BE dismissed.
    if is_passive_close(&decision.action) && evidence_provenance_is_illegitimate(ctx) {
        return surface(
            ctx,
            format!(
                "context gate: a detector proved illegitimate provenance (non-forgeable \
                 exe-path lineage); refusing the classifier's {} ({:.2}) and surfacing it.",
                decision.action.name(),
                decision.confidence
            ),
            "high".to_string(),
        );
    }

    // DShield (ISC) signal: the community has confirmed this IP attacking the
    // internet (reports > 0 or active threat-feed membership). A passive close
    // (dismiss/monitor) on a confirmed global attacker is never allowed to
    // stand — surface it, regardless of severity or the classifier's
    // confidence. Escalate-only by construction: a block/contain verdict is not
    // a passive close, so this can only raise a weak dismiss/monitor, never
    // relax an enforcement verdict. This is how the DShield enrichment becomes a
    // real decision signal on the classifier path (the gate wraps the
    // classifier) without touching the trained model's text input.
    if ctx.ip_dshield_attacker && is_passive_close(&decision.action) {
        return surface(
            ctx,
            format!(
                "context gate: refusing a {} ({:.2}) on a DShield-confirmed global attacker \
                 (ISC reports this IP attacking the internet); surfaced, not closed.",
                decision.action.name(),
                decision.confidence
            ),
            "high".to_string(),
        );
    }

    // AbuseIPDB signal: same escalate-only shape as DShield. A near-certain
    // malicious IP (score >= ABUSE_CONFIRMED_FLOOR) must not be passively closed
    // even when a cloud-range safelist nudged the classifier toward ignore. This
    // closes the prod blind spot (`safelist=Google Cloud, abuseipdb=100` -> the
    // classifier ignored it): the cloud safelist can no longer bury a
    // community-confirmed attacker. Surfaces (Monitor / RequestConfirmation),
    // never blocks, so a shared-cloud IP at this score is at worst watched.
    if ip_abuse_confirmed(ctx) && is_passive_close(&decision.action) {
        return surface(
            ctx,
            format!(
                "context gate: refusing a {} ({:.2}) on an AbuseIPDB-confirmed attacker \
                 (score {}/100); a cloud-range safelist must not free-pass a confirmed \
                 attacker. Surfaced, not closed.",
                decision.action.name(),
                decision.confidence,
                ctx.ip_reputation
                    .as_ref()
                    .map(|r| r.confidence_score)
                    .unwrap_or(0),
            ),
            "high".to_string(),
        );
    }

    let provenance_benign = match provenance {
        ActorProvenance::SelfComponent => SELF_NOISY_DETECTORS.contains(&detector),
        ActorProvenance::BuildToolchain => BUILD_NOISY_DETECTORS.contains(&detector),
        ActorProvenance::Unknown => false,
    };

    // 1. Provenance dismiss — Medium/Low ONLY. A forgeable `comm` must never
    //    auto-dismiss a High/Critical incident (red-team must-fix #1). Also never
    //    provenance-dismiss a DShield- or AbuseIPDB-confirmed attacker, even at
    //    low severity with benign-looking lineage (the overrides above only catch
    //    an incoming passive close; this guards the provenance-driven dismiss too).
    if provenance_benign && !high_sev && !ctx.ip_dshield_attacker && !ip_abuse_confirmed(ctx) {
        let label = match provenance {
            ActorProvenance::SelfComponent => "an InnerWarden component",
            _ => "the local build toolchain",
        };
        return AiDecision {
            action: AiAction::Dismiss {
                reason: format!("context gate: low-severity `{detector}` from {label}"),
            },
            confidence: 0.9,
            auto_execute: true,
            reason: format!(
                "context gate: `{detector}` ({:?}) attributed to {label}; dismissed as benign \
                 file-churn. (Forgeable-comm provenance — only applied below High severity.)",
                ctx.incident.severity
            ),
            alternatives: decision.alternatives,
            estimated_threat: "low".to_string(),
        };
    }

    // 2. Never launder a High/Critical enforcement verdict on a forgeable
    //    benign-provenance match into silence: downgrade to a human-veto
    //    surface instead (red-team must-fix #2 / B4).
    if high_sev && provenance_benign && decision.action.is_high_impact() {
        return surface(
            ctx,
            format!(
                "context gate: {} proposed on a {:?} `{detector}` whose actor name looks like a \
                 trusted process (forgeable) — surfacing for operator veto rather than \
                 auto-executing or dismissing.",
                decision.action.name(),
                ctx.incident.severity
            ),
            decision.estimated_threat,
        );
    }

    // 3. Protective escalation — a low-confidence passive close on a
    //    High/Critical incident is surfaced, never allowed to bury a serious
    //    signal. Evaluated for ALL High/Critical (provenance can no longer
    //    short-circuit this — red-team must-fix #3). `<=` so the 0.85 edge
    //    surfaces (B9).
    if high_sev && is_passive_close(&decision.action) && decision.confidence <= ESCALATE_FLOOR {
        return surface(
            ctx,
            format!(
                "context gate: escalated a low-confidence {} ({:.2}) on a {:?} `{detector}` so a \
                 weak verdict cannot bury a serious signal.",
                decision.action.name(),
                decision.confidence,
                ctx.incident.severity
            ),
            decision.estimated_threat,
        );
    }

    // 4. Otherwise unchanged.
    decision
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Event;
    use innerwarden_core::incident::Incident;

    fn inc(id: &str, sev: Severity, summary: &str, ips: &[&str]) -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "t".into(),
            incident_id: id.into(),
            severity: sev,
            title: id.into(),
            summary: summary.into(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: ips.iter().map(|ip| EntityRef::ip(*ip)).collect(),
        }
    }

    fn ctx<'a>(incident: &'a Incident, recent: Vec<&'a Event>) -> DecisionContext<'a> {
        DecisionContext {
            incident,
            recent_events: recent,
            related_incidents: vec![],
            already_blocked: vec![],
            available_skills: vec![],
            ip_reputation: None,
            ip_geo: None,
            ip_dshield: None,
            ip_dshield_attacker: false,
            host_posture: None,
            prior_decisions: None,
            graph_context: None,
            graph_subgraph: None,
            playbook_outcome: None,
        }
    }

    fn dismiss(conf: f32) -> AiDecision {
        AiDecision {
            action: AiAction::Dismiss {
                reason: "orig".into(),
            },
            confidence: conf,
            auto_execute: false,
            reason: "orig".into(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        }
    }

    fn block(conf: f32) -> AiDecision {
        AiDecision {
            action: AiAction::BlockIp {
                ip: "9.9.9.9".into(),
                skill_id: "block-ip-ufw".into(),
            },
            confidence: conf,
            auto_execute: true,
            reason: "orig".into(),
            alternatives: vec![],
            estimated_threat: "high".into(),
        }
    }

    fn ev_comm(comm: &str) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: "t".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({ "comm": comm }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn is_dismiss(d: &AiDecision) -> bool {
        matches!(d.action, AiAction::Dismiss { .. })
    }

    #[test]
    fn dshield_attacker_passive_close_is_surfaced() {
        // A DShield-confirmed global attacker must never be passively closed,
        // even at low severity with a confident classifier dismiss.
        let i = inc("d1", Severity::Low, "ssh probe", &["9.9.9.9"]);
        let mut c = ctx(&i, vec![]);
        c.ip_dshield_attacker = true;
        let out = apply(&c, dismiss(0.97));
        assert!(
            !is_dismiss(&out),
            "DShield-confirmed attacker must not be dismissed"
        );
        assert_eq!(out.confidence, ESCALATE_FLOOR);
        assert!(out.reason.contains("DShield-confirmed"));
    }

    #[test]
    fn dshield_attacker_block_left_intact() {
        // Escalate-only: DShield raises a passive close but never touches an
        // enforcement verdict.
        let i = inc("d2", Severity::High, "c2 beacon", &["9.9.9.9"]);
        let mut c = ctx(&i, vec![]);
        c.ip_dshield_attacker = true;
        let out = apply(&c, block(0.6));
        assert!(
            matches!(out.action, AiAction::BlockIp { .. }),
            "block must survive"
        );
        assert_eq!(out.confidence, 0.6);
    }

    #[test]
    fn no_dshield_low_sev_dismiss_unchanged() {
        // DShield off (default) must not change prior behavior: a low-sev,
        // non-attacker, confident dismiss stays a dismiss.
        let i = inc("d3", Severity::Low, "noise", &["9.9.9.9"]);
        let c = ctx(&i, vec![]); // ip_dshield_attacker = false
        let out = apply(&c, dismiss(0.95));
        assert!(
            is_dismiss(&out),
            "non-DShield low-sev dismiss must be unchanged"
        );
    }

    fn rep(score: u8) -> crate::abuseipdb::IpReputation {
        crate::abuseipdb::IpReputation {
            confidence_score: score,
            total_reports: 10,
            distinct_users: 5,
            country_code: Some("BE".into()),
            isp: Some("Google Cloud".into()),
            is_tor: false,
        }
    }

    #[test]
    fn abuseipdb_confirmed_passive_close_is_surfaced() {
        // The prod blind spot: a cloud-safelisted IP with abuseipdb=100 was
        // ignored. The veto must surface it instead of closing it.
        let i = inc("a1", Severity::Low, "proto anomaly", &["9.9.9.9"]);
        let mut c = ctx(&i, vec![]);
        c.ip_reputation = Some(rep(100));
        let out = apply(&c, dismiss(0.97));
        assert!(
            !is_dismiss(&out),
            "AbuseIPDB-confirmed attacker must not be passively closed"
        );
        assert_eq!(out.confidence, ESCALATE_FLOOR);
        assert!(out.reason.contains("AbuseIPDB-confirmed"), "{}", out.reason);
    }

    #[test]
    fn abuseipdb_confirmed_block_left_intact() {
        // Escalate-only: a high-abuse IP with a block verdict is untouched.
        let i = inc("a2", Severity::High, "c2", &["9.9.9.9"]);
        let mut c = ctx(&i, vec![]);
        c.ip_reputation = Some(rep(100));
        let out = apply(&c, block(0.6));
        assert!(
            matches!(out.action, AiAction::BlockIp { .. }),
            "block must survive"
        );
        assert_eq!(out.confidence, 0.6);
    }

    #[test]
    fn abuseipdb_below_floor_dismiss_unchanged() {
        // A borderline score (< floor) must NOT trigger the veto: avoids
        // flooding the operator with surfaces on noisy-but-not-confirmed IPs.
        let i = inc("a3", Severity::Low, "noise", &["9.9.9.9"]);
        let mut c = ctx(&i, vec![]);
        c.ip_reputation = Some(rep(ABUSE_CONFIRMED_FLOOR - 1));
        let out = apply(&c, dismiss(0.95));
        assert!(is_dismiss(&out), "below-floor abuse score must not veto");
        assert_eq!(out.reason, "orig");
    }

    #[test]
    fn abuseipdb_confirmed_blocks_provenance_self_dismiss() {
        // Symmetric to the DShield guard: the gate's own provenance-dismiss path
        // (Medium self/build allowlisted detector) must NOT fire when the IP is
        // an AbuseIPDB-confirmed attacker. Drive it with a non-passive-close
        // incoming so the escalate-only branch above does not short-circuit, and
        // assert the gate did not synthesise a dismiss. Without the guard, branch
        // 1 would turn this into a Dismiss regardless of the incoming verdict.
        let i = inc(
            "suspicious_archive:innerwarden-agent:x",
            Severity::Medium,
            "comm=innerwarden-agent",
            &["9.9.9.9"],
        );
        let mut c = ctx(&i, vec![]);
        c.ip_reputation = Some(rep(100));
        let out = apply(&c, block(0.4));
        assert!(
            !is_dismiss(&out),
            "confirmed-attacker provenance self-dismiss must be refused: {:?}",
            out.action
        );
    }

    #[test]
    fn benign_self_provenance_dismiss_still_works_without_abuse() {
        // Regression: with NO abuse reputation the Medium self-noise dismiss path
        // is unchanged (the guard only bites on a confirmed attacker).
        let i = inc(
            "suspicious_archive:innerwarden-agent:x",
            Severity::Medium,
            "comm=innerwarden-agent",
            &[],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(0.4));
        assert!(is_dismiss(&out));
        assert!(out.reason.contains("context gate"), "{}", out.reason);
    }

    // ============================================================
    // ADVERSARIAL regressions — these pin the red-team must-fixes.
    // A failure here means a real attack can be silenced.
    // ============================================================

    #[test]
    fn adversarial_self_spoofed_critical_privesc_is_never_dismissed() {
        // B1: naming the binary `innerwarden-agent` must NOT dismiss a Critical
        // privesc (privesc is off the allowlist AND High/Critical can't be
        // provenance-dismissed). It must surface instead.
        let i = inc(
            "privesc:innerwarden-agent:x",
            Severity::Critical,
            "comm=innerwarden-agent uid 1000 -> 0",
            &[],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(0.4));
        assert!(
            !is_dismiss(&out),
            "Critical privesc must never be dismissed: {:?}",
            out.action
        );
        assert!(matches!(out.action, AiAction::RequestConfirmation { .. }));
    }

    #[test]
    fn adversarial_self_spoof_does_not_launder_block_to_dismiss() {
        // B4: a block_ip on a Critical incident with a spoofed trusted comm must
        // NOT become a silent dismiss. (privesc off allowlist -> block stands;
        // even if it were on the allowlist, must-fix #2 surfaces, never dismiss.)
        let i = inc(
            "privesc:innerwarden-agent:x",
            Severity::Critical,
            "comm=innerwarden-agent",
            &["9.9.9.9"],
        );
        let out = apply(&ctx(&i, vec![]), block(0.95));
        assert!(
            !is_dismiss(&out),
            "a real block must never be laundered into dismiss"
        );
    }

    #[test]
    fn adversarial_build_spoofed_critical_host_drift_tmp_is_never_dismissed() {
        // B2: comm=rust-lld on a Critical host_drift (/tmp exec) must not be
        // dismissed (host_drift is off both allowlists).
        let i = inc(
            "host_drift:rust-lld:x",
            Severity::Critical,
            "comm=rust-lld /tmp/payload",
            &[],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(0.3));
        assert!(
            !is_dismiss(&out),
            "Critical /tmp host_drift must never be dismissed: {:?}",
            out.action
        );
    }

    #[test]
    fn adversarial_self_spoofed_high_data_exfil_is_never_dismissed() {
        // B3: comm=innerwarden-ctl on a High data_exfil_cmd must not be dismissed.
        let i = inc(
            "data_exfil_cmd:innerwarden-ctl:x",
            Severity::High,
            "comm=innerwarden-ctl tar /etc/shadow | curl",
            &[],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(0.5));
        assert!(
            !is_dismiss(&out),
            "High data_exfil must never be dismissed: {:?}",
            out.action
        );
    }

    #[test]
    fn adversarial_overbroad_comm_does_not_impersonate() {
        // B6: exact base-name match — innerwarden9 / ccminer must NOT match.
        let i1 = inc(
            "suspicious_archive:innerwarden9:x",
            Severity::Medium,
            "comm=innerwarden9",
            &[],
        );
        assert_eq!(
            classify_provenance(&ctx(&i1, vec![])),
            ActorProvenance::Unknown
        );
        let i2 = inc(
            "suspicious_archive:ccminer:x",
            Severity::Medium,
            "comm=ccminer",
            &[],
        );
        assert_eq!(
            classify_provenance(&ctx(&i2, vec![])),
            ActorProvenance::Unknown
        );
    }

    // ============================================================
    // The narrow SAFE provenance dismiss (Medium/Low only).
    // ============================================================

    #[test]
    fn medium_suspicious_archive_from_self_is_dismissed() {
        let i = inc(
            "suspicious_archive:innerwarden-agent:x",
            Severity::Medium,
            "comm=innerwarden-agent",
            &[],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(0.4));
        assert!(is_dismiss(&out));
        assert!(out.reason.contains("context gate"), "{}", out.reason);
    }

    #[test]
    fn medium_suspicious_archive_from_build_is_dismissed() {
        let i = inc(
            "suspicious_archive:cargo:x",
            Severity::Medium,
            "comm=cargo",
            &[],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(0.4));
        assert!(is_dismiss(&out));
    }

    #[test]
    fn unknown_actor_low_severity_passes_through() {
        let i = inc(
            "suspicious_archive:python3:x",
            Severity::Low,
            "comm=python3",
            &[],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(0.2));
        assert!(is_dismiss(&out));
        assert_eq!(
            out.reason, "orig",
            "unidentified actor must pass through untouched"
        );
    }

    #[test]
    fn unlisted_detector_from_self_not_dismissed_even_at_medium() {
        // A Medium incident from a self comm but on a detector NOT on the
        // allowlist passes through unchanged (allowlist is tight).
        let i = inc(
            "port_scan:innerwarden-agent:x",
            Severity::Medium,
            "comm=innerwarden-agent",
            &[],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(0.4));
        assert_eq!(out.reason, "orig");
    }

    // ============================================================
    // Protective escalation (surfacing) — never buries High/Critical.
    // ============================================================

    #[test]
    fn low_conf_dismiss_on_critical_with_ip_surfaces_as_monitor() {
        let i = inc(
            "c2_callback:bash:x",
            Severity::Critical,
            "comm=bash",
            &["7.7.7.7"],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(0.42));
        match out.action {
            AiAction::Monitor { ip } => assert_eq!(ip, "7.7.7.7"),
            other => panic!("expected Monitor, got {other:?}"),
        }
        assert!(!out.auto_execute);
    }

    #[test]
    fn low_conf_dismiss_on_critical_no_ip_requests_confirmation() {
        let i = inc(
            "fileless:systemd:x",
            Severity::Critical,
            "comm=systemd",
            &[],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(0.42));
        assert!(
            matches!(out.action, AiAction::RequestConfirmation { .. }),
            "{:?}",
            out.action
        );
    }

    #[test]
    fn escalation_fires_on_exact_floor_boundary() {
        // B9: <= floor — a passive close sitting exactly on 0.85 surfaces.
        let i = inc(
            "fileless:systemd:x",
            Severity::Critical,
            "comm=systemd",
            &[],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(ESCALATE_FLOOR));
        assert!(matches!(out.action, AiAction::RequestConfirmation { .. }));
    }

    #[test]
    fn high_conf_dismiss_on_critical_is_trusted() {
        let i = inc(
            "fileless:systemd:x",
            Severity::Critical,
            "comm=systemd",
            &[],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(0.95));
        assert!(is_dismiss(&out));
        assert_eq!(out.reason, "orig");
    }

    #[test]
    fn low_severity_dismiss_not_escalated() {
        let i = inc(
            "discovery_anomaly:bash:x",
            Severity::Low,
            "comm=bash",
            &["1.1.1.1"],
        );
        let out = apply(&ctx(&i, vec![]), dismiss(0.2));
        assert!(is_dismiss(&out));
        assert_eq!(out.reason, "orig");
    }

    #[test]
    fn confident_block_on_critical_unknown_actor_unchanged() {
        // The gate never touches a confident enforcement verdict from an
        // unidentified actor.
        let i = inc(
            "c2_callback:python3:x",
            Severity::Critical,
            "comm=python3",
            &["8.8.8.8"],
        );
        let out = apply(&ctx(&i, vec![]), block(0.9));
        assert!(matches!(out.action, AiAction::BlockIp { .. }));
    }

    // ============================================================
    // provenance extraction sources + exact-match semantics.
    // ============================================================

    #[test]
    fn provenance_from_recent_event_comm_exact() {
        let i = inc(
            "suspicious_archive:unknown:x",
            Severity::Medium,
            "no comm token",
            &[],
        );
        let e = ev_comm("cargo");
        assert_eq!(
            classify_provenance(&ctx(&i, vec![&e])),
            ActorProvenance::BuildToolchain
        );
    }

    #[test]
    fn provenance_truncated_self_comm_matches_exact() {
        let i = inc(
            "suspicious_archive:x",
            Severity::Medium,
            "comm=innerwarden-age",
            &[],
        );
        assert_eq!(
            classify_provenance(&ctx(&i, vec![])),
            ActorProvenance::SelfComponent
        );
    }

    #[test]
    fn provenance_unknown_when_no_actor() {
        let i = inc("rootkit:spoof:x", Severity::High, "no actor info", &[]);
        assert_eq!(
            classify_provenance(&ctx(&i, vec![])),
            ActorProvenance::Unknown
        );
    }

    // --- Phase 2: non-forgeable `provenance:illegitimate` overrides the classifier ---

    fn inc_illegit(id: &str, sev: Severity) -> Incident {
        let mut i = inc(id, sev, "comm=sudo", &[]);
        i.evidence = serde_json::json!([{ "provenance": "provenance:illegitimate" }]);
        i
    }

    #[test]
    fn illegitimate_provenance_refuses_even_high_confidence_dismiss() {
        // The sensor proved illegitimate exe-path lineage; the text-only
        // classifier's confident dismiss must NOT close it — surface instead.
        let i = inc_illegit("privesc:sudo:x", Severity::Critical);
        let out = apply(&ctx(&i, vec![]), dismiss(0.97));
        assert!(
            !is_dismiss(&out),
            "illegitimate provenance must never be dismissed: {:?}",
            out.action
        );
        assert!(matches!(out.action, AiAction::RequestConfirmation { .. }));
    }

    #[test]
    fn illegitimate_provenance_does_not_touch_enforcement() {
        // The guard only refuses passive closes; a block stands.
        let i = inc_illegit("privesc:sudo:x", Severity::Critical);
        let out = apply(&ctx(&i, vec![]), block(0.9));
        assert!(matches!(out.action, AiAction::BlockIp { .. }));
    }

    #[test]
    fn non_illegitimate_provenance_unaffected_by_guard() {
        // A trusted/absent provenance tag does not trigger the guard; a
        // high-confidence dismiss on a Low-severity incident still stands.
        let mut i = inc("discovery_anomaly:bash:x", Severity::Low, "comm=bash", &[]);
        i.evidence = serde_json::json!([{ "provenance": "provenance:trusted" }]);
        let out = apply(&ctx(&i, vec![]), dismiss(0.9));
        assert!(is_dismiss(&out));
        assert_eq!(out.reason, "orig");
    }

    #[test]
    fn evidence_provenance_is_illegitimate_parses_array_and_object() {
        let mut arr = inc("x:y:z", Severity::High, "", &[]);
        arr.evidence = serde_json::json!([{ "provenance": "provenance:illegitimate" }]);
        assert!(evidence_provenance_is_illegitimate(&ctx(&arr, vec![])));
        let mut obj = inc("x:y:z", Severity::High, "", &[]);
        obj.evidence = serde_json::json!({ "provenance": "provenance:illegitimate" });
        assert!(evidence_provenance_is_illegitimate(&ctx(&obj, vec![])));
        let mut trusted = inc("x:y:z", Severity::High, "", &[]);
        trusted.evidence = serde_json::json!([{ "provenance": "provenance:trusted" }]);
        assert!(!evidence_provenance_is_illegitimate(&ctx(&trusted, vec![])));
    }
}
