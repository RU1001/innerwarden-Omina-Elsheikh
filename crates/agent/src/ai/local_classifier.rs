//! Local Warden Model — ONNX classifier (distilled student of a SecureBERT teacher).
//!
//! Operator-facing name: **Local Warden Model** (TOML key `[ai.warden]`,
//! provider id `local_warden`). Internal symbols keep the
//! `local_classifier` / `LocalClassifier` names for audit-trail
//! continuity and to keep diffs minimal.
//!
//! Runs inference in-process using `tract-onnx` (pure Rust ONNX runtime) and
//! HuggingFace `tokenizers`. Output: {dismiss, ignore, block_ip, monitor} +
//! confidence.
//!
//! No network calls, no external dependency beyond the crate graph; entire
//! inference happens locally in ~50-200 ms per incident on a typical server
//! CPU.
//!
//! Build with `--features local-classifier`. Requires a `model.onnx` plus
//! `tokenizer.json` on disk. Default path: `/var/lib/innerwarden/models/classifier/`.

#![cfg(feature = "local-classifier")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use innerwarden_core::entities::EntityType;
use tokenizers::Tokenizer;
use tracing::debug;
use tract_onnx::prelude::*;

use super::{AiAction, AiDecision, AiProvider, DecisionContext};

/// Label order must match the model's training (fine_tune.py LABELS).
const LABELS: [&str; 4] = ["dismiss", "ignore", "block_ip", "monitor"];
const MAX_LEN: usize = 256;

type OnnxModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

pub struct LocalClassifier {
    model: Arc<OnnxModel>,
    tokenizer: Arc<Tokenizer>,
    auto_exec_threshold: f32,
    model_path: PathBuf,
    /// Operator-configured block backend (`ufw` / `iptables` / `nftables`
    /// / `pf` / `xdp`). Threaded through from `cfg.responder.block_backend`
    /// at provider build time so the classifier emits the same `skill_id`
    /// shape as every other auto-block path. Pre-fix this was hardcoded
    /// to `"ufw"` (Top-5 #3 — AUDIT-WAVE-T5-3, 2026-05-06): on a host
    /// running the iptables / nftables / pf backend the classifier would
    /// emit `skill_id="block-ip-ufw"`, which the executor either rejects
    /// or — worse — runs ufw in parallel to the operator's real backend.
    block_backend: String,
}

impl LocalClassifier {
    pub fn from_dir(dir: &Path, auto_exec_threshold: f32, block_backend: &str) -> Result<Self> {
        let model_path = dir.join("model.onnx");
        let tokenizer_path = dir.join("tokenizer.json");
        if !model_path.exists() {
            bail!(
                "classifier model.onnx not found at {}",
                model_path.display()
            );
        }
        if !tokenizer_path.exists() {
            bail!(
                "classifier tokenizer.json not found at {}",
                tokenizer_path.display()
            );
        }

        let model = tract_onnx::onnx()
            .model_for_path(&model_path)
            .with_context(|| format!("loading ONNX model {}", model_path.display()))?
            .with_input_fact(
                0,
                InferenceFact::dt_shape(i64::datum_type(), tvec!(1, MAX_LEN)),
            )?
            .with_input_fact(
                1,
                InferenceFact::dt_shape(i64::datum_type(), tvec!(1, MAX_LEN)),
            )?
            .into_optimized()?
            .into_runnable()?;

        let tokenizer =
            Tokenizer::from_file(&tokenizer_path).map_err(|e| anyhow!("loading tokenizer: {e}"))?;

        Ok(Self {
            model: Arc::new(model),
            tokenizer: Arc::new(tokenizer),
            auto_exec_threshold,
            model_path: dir.to_path_buf(),
            block_backend: block_backend.to_string(),
        })
    }

    fn build_text(ctx: &DecisionContext<'_>) -> String {
        let inc = ctx.incident;
        let detector = inc.incident_id.split(':').next().unwrap_or("unknown");
        let mut parts = vec![
            format!("detector: {}", detector),
            format!("severity: {:?}", inc.severity).to_lowercase(),
            format!("title: {}", truncate(&inc.title, 200)),
        ];
        if !inc.summary.is_empty() {
            parts.push(format!("summary: {}", truncate(&inc.summary, 400)));
        }
        parts.join(" | ")
    }

    fn run_inference(&self, text: &str) -> Result<[f32; 4]> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow!("tokenize: {e}"))?;

        let mut ids: Vec<i64> = encoding.get_ids().iter().map(|&x| x as i64).collect();
        let mut mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&x| x as i64)
            .collect();
        pad_or_truncate(&mut ids, MAX_LEN, 0);
        pad_or_truncate(&mut mask, MAX_LEN, 0);

        let ids_tensor: Tensor = tract_ndarray::Array2::from_shape_vec((1, MAX_LEN), ids)?.into();
        let mask_tensor: Tensor = tract_ndarray::Array2::from_shape_vec((1, MAX_LEN), mask)?.into();

        let outputs = self
            .model
            .run(tvec!(ids_tensor.into(), mask_tensor.into()))?;

        let probs_tensor = outputs
            .first()
            .ok_or_else(|| anyhow!("model produced no outputs"))?;
        let probs_view = probs_tensor.to_array_view::<f32>()?;
        let slice = probs_view
            .as_slice()
            .ok_or_else(|| anyhow!("output not contiguous"))?;
        if slice.len() < LABELS.len() {
            bail!(
                "classifier returned {} probs, expected at least {}",
                slice.len(),
                LABELS.len()
            );
        }
        let mut out = [0.0f32; 4];
        out.copy_from_slice(&slice[..LABELS.len()]);
        Ok(out)
    }

    fn primary_ip(ctx: &DecisionContext<'_>) -> Option<String> {
        ctx.incident
            .entities
            .iter()
            .find(|e| matches!(e.r#type, EntityType::Ip))
            .map(|e| e.value.clone())
    }

    fn clone_handles(&self) -> Self {
        Self {
            model: Arc::clone(&self.model),
            tokenizer: Arc::clone(&self.tokenizer),
            auto_exec_threshold: self.auto_exec_threshold,
            model_path: self.model_path.clone(),
            block_backend: self.block_backend.clone(),
        }
    }
}

#[async_trait]
impl AiProvider for LocalClassifier {
    fn name(&self) -> &'static str {
        "local_classifier"
    }

    /// Spec 029: only declare `Decide`. The current `Classify`
    /// call sites (batch triage, ambiguous verification) dispatch
    /// via `chat()` with a prompt asking for a label, which this
    /// classifier cannot serve (no decoder). Declaring only `Decide`
    /// keeps the router honest: Classify requests fall through to
    /// the llm slot where `chat()` actually works, and this provider
    /// is only invoked for the one path it was trained for (incident
    /// triage -> block_ip/monitor/ignore/dismiss).
    fn capabilities(&self) -> super::capability::AiCapabilities {
        super::capability::AiCapabilities::from_slice(&[super::capability::Capability::Decide])
    }

    async fn decide(&self, ctx: &DecisionContext<'_>) -> Result<AiDecision> {
        let text = Self::build_text(ctx);
        debug!(
            model = %self.model_path.display(),
            len = text.len(),
            "running local classifier",
        );

        let this = self.clone_handles();
        let probs: [f32; 4] = tokio::task::spawn_blocking(move || this.run_inference(&text))
            .await
            .map_err(|e| anyhow!("inference task join: {e}"))??;

        let (idx, &conf) = probs
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .ok_or_else(|| anyhow!("empty probs"))?;

        let action_name = LABELS[idx];
        let target_ip = Self::primary_ip(ctx);

        let action =
            build_action_from_prediction(action_name, target_ip.clone(), conf, &self.block_backend);

        let alternatives: Vec<String> = LABELS
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != idx)
            .map(|(i, l)| format!("{} ({:.2})", l, probs[i]))
            .collect();

        let estimated_threat = match conf {
            c if c >= 0.9 => "high",
            c if c >= 0.75 => "medium",
            _ => "low",
        }
        .to_string();

        let markers = build_decision_markers(ctx, target_ip.as_deref());
        let markers_section = if markers.is_empty() {
            String::new()
        } else {
            format!(" Markers: {}.", markers.join(", "))
        };

        let decision = AiDecision {
            action,
            confidence: conf,
            auto_execute: conf >= self.auto_exec_threshold,
            reason: format!(
                "Local Warden decided {} with confidence {:.3}.{} Alternatives: {}.",
                action_name,
                conf,
                markers_section,
                alternatives.join(", ")
            ),
            alternatives,
            estimated_threat,
        };

        // Spec 071 Part A: deterministic Context Gate. The ONNX sees only
        // detector/severity/title/summary; this corrects the two failure modes
        // that flow from that (benign self/build activity punted to review, and
        // a real high-severity threat buried under a low-confidence dismiss)
        // using the provenance the agent already holds. Fail-closed: an
        // unidentified actor passes through unchanged.
        Ok(crate::warden_context_gate::apply(ctx, decision))
    }

    async fn chat(&self, _system_prompt: &str, _user_message: &str) -> Result<String> {
        bail!("Local Warden does not support free-form chat (classification only)")
    }
}

fn pad_or_truncate(v: &mut Vec<i64>, len: usize, pad: i64) {
    if v.len() > len {
        v.truncate(len);
    } else {
        v.resize(len, pad);
    }
}

/// Build human-meaningful disclosure markers for the Local Warden's
/// decision reason field. The on-device classifier is a black-box
/// transformer that outputs probabilities; this helper surfaces the
/// *heuristic context* the operator can verify by eye:
///
///   - `safelist=<provider>` — cloud-safelist hit (Cloudflare, AWS, etc.).
///     This is the single most common reason for `dismiss`/`ignore` on
///     real prod traffic, so surfacing it short-circuits "why did it
///     dismiss?" investigations.
///   - `abuseipdb=<score>` — AbuseIPDB confidence score 0-100 if enrichment
///     ran. Operator sees at a glance whether a third-party reputation
///     hit shaped the decision.
///   - `country=<XX>` — two-letter country code from GeoIP enrichment.
///   - `already_blocked=true` — the target IP is already on the agent's
///     blocklist. Common reason for `monitor`/`ignore` (no point blocking
///     twice).
///   - `recent_events=N` — count of recent events from this entity. Helps
///     operator distinguish "first time" from "repeat offender".
///   - `related_incidents=N` — count of temporally correlated incidents
///     sharing pivot(s).
///   - `incident_tags=[...]` — concise list of incident tags (capped at 3)
///     so the operator can verify the incident shape the classifier saw.
///
/// Returns markers in fixed insertion order so the audit string is
/// stable across runs (test-friendly + dashboard-grep-friendly).
/// Skips markers whose value would be uninformative (e.g. zero counts,
/// missing enrichment) so the reason field stays compact when nothing
/// notable is present.
fn build_decision_markers(ctx: &DecisionContext<'_>, target_ip: Option<&str>) -> Vec<String> {
    let mut markers = Vec::new();

    if let Some(ip) = target_ip {
        if let Some(provider) = crate::cloud_safelist::safelist_label(ip) {
            markers.push(format!("safelist={provider}"));
        }
        if ctx.already_blocked.iter().any(|b| b == ip) {
            markers.push("already_blocked=true".to_string());
        }
    }

    if let Some(rep) = &ctx.ip_reputation {
        // AbuseIPDB enrichment present — even a 0 score is signal
        // ("checked + clean"), so emit unconditionally when the field is Some.
        markers.push(format!("abuseipdb={}", rep.confidence_score));
    }

    if let Some(geo) = &ctx.ip_geo {
        if !geo.country_code.is_empty() {
            markers.push(format!("country={}", geo.country_code));
        }
    }

    if !ctx.recent_events.is_empty() {
        markers.push(format!("recent_events={}", ctx.recent_events.len()));
    }

    if !ctx.related_incidents.is_empty() {
        markers.push(format!("related_incidents={}", ctx.related_incidents.len()));
    }

    let tags: Vec<&str> = ctx
        .incident
        .tags
        .iter()
        .take(3)
        .map(String::as_str)
        .collect();
    if !tags.is_empty() {
        markers.push(format!("incident_tags=[{}]", tags.join(",")));
    }

    markers
}

/// Build an `AiAction` from the classifier's predicted action name + the
/// optional IP entity extracted from the incident context. Pure logic so the
/// downgrade behaviour can be unit-tested without an ONNX runtime.
///
/// Wave 9g (AUDIT-016 anchor): the `"block_ip"` arm matches `target_ip`
/// and downgrades to `Ignore` when no IP is present. Pre-demotion the
/// downgrade emitted a WARN; now it logs at DEBUG because the safety net
/// works as designed and there is no operator action.
///
/// Top-5 #3 (AUDIT-WAVE-T5-3, 2026-05-06): `block_backend` is the
/// operator-configured firewall backend (`ufw`/`iptables`/`nftables`/
/// `pf`/`xdp`) threaded through `cfg.responder.block_backend`. Pre-fix
/// the skill_id was hardcoded to `"block-ip-ufw"` here, which made the
/// classifier the only auto-block path that ignored the operator's
/// backend choice — every other site (`incident_obvious`, `bot_actions`,
/// `correlation_response`, etc.) already used `format!("block-ip-{}", cfg.responder.block_backend)`.
fn build_action_from_prediction(
    action_name: &str,
    target_ip: Option<String>,
    conf: f32,
    block_backend: &str,
) -> AiAction {
    match action_name {
        "block_ip" => match target_ip {
            Some(ip) => AiAction::BlockIp {
                ip,
                skill_id: format!("block-ip-{}", block_backend),
            },
            None => {
                debug!(
                    "classifier predicted block_ip but incident has no IP entity, downgrading to ignore (safety net)"
                );
                AiAction::Ignore {
                    reason: "block_ip predicted but no target IP".to_string(),
                }
            }
        },
        "monitor" => AiAction::Monitor {
            ip: target_ip.unwrap_or_else(|| "unknown".to_string()),
        },
        "ignore" => AiAction::Ignore {
            reason: format!("classifier: ignore (confidence {:.3})", conf),
        },
        "dismiss" => AiAction::Dismiss {
            reason: format!("classifier: dismiss (confidence {:.3})", conf),
        },
        _ => AiAction::Ignore {
            reason: format!("unknown classifier action: {}", action_name),
        },
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_shorter() {
        let mut v = vec![1i64, 2, 3];
        pad_or_truncate(&mut v, 8, 0);
        assert_eq!(v, vec![1, 2, 3, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn truncate_longer() {
        let mut v: Vec<i64> = (0..10).collect();
        pad_or_truncate(&mut v, 5, 0);
        assert_eq!(v, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn truncate_handles_utf8() {
        let s = "áéíóú".repeat(10);
        let t = truncate(&s, 12);
        assert!(t.len() <= 12);
    }

    // ── Wave 9g anchors (2026-05-04) — classifier safety net ─────────────
    //
    // AUDIT-016 (audit tick 7): the classifier emitted block_ip predictions
    // on incidents that had no IP entity. The agent downgrades to Ignore
    // (correct) but pre-Wave-9g it WARN-logged the event, suggesting an
    // operator-actionable problem - there is none, the safety net is the
    // intended behaviour. These anchors pin the downgrade contract so
    // future refactors do not (a) actually block on a missing IP, or
    // (b) re-promote the log to a level that asks the operator to act.

    #[test]
    fn block_ip_without_ip_entity_is_downgraded_to_ignore() {
        // The exact AUDIT-016 prod failure shape: classifier said block_ip
        // but the incident had no IP entity to act on. Result must be
        // Ignore (NOT BlockIp), with a stable reason string the audit log
        // can grep for.
        let action = build_action_from_prediction("block_ip", None, 0.95, "ufw");
        match action {
            AiAction::Ignore { reason } => {
                assert!(
                    reason.contains("no target IP"),
                    "downgrade reason must mention the missing IP; got: {reason}"
                );
            }
            other => panic!("expected Ignore, got {other:?}"),
        }
    }

    #[test]
    fn block_ip_with_ip_entity_produces_block_ip() {
        // Anti-regression for over-coercing the downgrade: when the IP IS
        // present, the action MUST be BlockIp, not Ignore.
        let action =
            build_action_from_prediction("block_ip", Some("203.0.113.42".to_string()), 0.92, "ufw");
        match action {
            AiAction::BlockIp { ip, skill_id } => {
                assert_eq!(ip, "203.0.113.42");
                assert_eq!(skill_id, "block-ip-ufw");
            }
            other => panic!("expected BlockIp, got {other:?}"),
        }
    }

    #[test]
    fn monitor_without_ip_uses_unknown_placeholder() {
        // Document the existing fallback so future contributors cannot
        // remove the unwrap_or without changing the public action shape.
        let action = build_action_from_prediction("monitor", None, 0.7, "ufw");
        match action {
            AiAction::Monitor { ip } => assert_eq!(ip, "unknown"),
            other => panic!("expected Monitor, got {other:?}"),
        }
    }

    #[test]
    fn unknown_action_name_falls_back_to_ignore() {
        // If a future model adds a new label LABELS[i] we don't yet
        // recognise, the agent must fall back to Ignore (not panic, not
        // execute a partial decision). Confidence stays in the reason
        // string for audit visibility.
        let action = build_action_from_prediction("frobnicate", None, 0.66, "ufw");
        match action {
            AiAction::Ignore { reason } => {
                assert!(reason.contains("unknown classifier action"));
                assert!(reason.contains("frobnicate"));
            }
            other => panic!("expected Ignore, got {other:?}"),
        }
    }

    #[test]
    fn dismiss_includes_confidence_in_reason_string() {
        // Audit-trail anchor: the reason must include the confidence so
        // the operator can grep `dismiss (confidence 0.` for low-confidence
        // dismisses without re-querying the inference batch.
        let action = build_action_from_prediction("dismiss", None, 0.123, "ufw");
        match action {
            AiAction::Dismiss { reason } => {
                assert!(reason.contains("0.123"), "got: {reason}");
            }
            other => panic!("expected Dismiss, got {other:?}"),
        }
    }

    // ── Top-5 #3 anchors (2026-05-06) — operator-configured backend ──────
    //
    // AUDIT-WAVE-T5-3: pre-fix the classifier hardcoded `block-ip-ufw`,
    // ignoring `cfg.responder.block_backend`. Every other auto-block path
    // (`incident_obvious`, `bot_actions`, `correlation_response`,
    // `incident_abuseipdb`, `incident_crowdsec`, `correlation_response`,
    // dashboard `actions.rs`, `honeypot_*`) already used
    // `format!("block-ip-{}", cfg.responder.block_backend)`. The
    // classifier was the lone outlier, which on a host configured for
    // iptables / nftables / pf / xdp would emit a skill_id the
    // executor would reject — or worse, run ufw in parallel to the
    // operator's real backend.
    //
    // These anchors pin one parametric variant per supported backend so
    // the format string contract cannot silently regress to a hardcoded
    // value via well-meaning refactor.
    #[test]
    fn block_ip_skill_id_uses_operator_configured_backend_iptables() {
        let action = build_action_from_prediction(
            "block_ip",
            Some("203.0.113.42".to_string()),
            0.95,
            "iptables",
        );
        match action {
            AiAction::BlockIp { skill_id, .. } => assert_eq!(skill_id, "block-ip-iptables"),
            other => panic!("expected BlockIp, got {other:?}"),
        }
    }

    #[test]
    fn block_ip_skill_id_uses_operator_configured_backend_nftables() {
        let action = build_action_from_prediction(
            "block_ip",
            Some("203.0.113.43".to_string()),
            0.95,
            "nftables",
        );
        match action {
            AiAction::BlockIp { skill_id, .. } => assert_eq!(skill_id, "block-ip-nftables"),
            other => panic!("expected BlockIp, got {other:?}"),
        }
    }

    #[test]
    fn block_ip_skill_id_uses_operator_configured_backend_pf() {
        let action =
            build_action_from_prediction("block_ip", Some("203.0.113.44".to_string()), 0.95, "pf");
        match action {
            AiAction::BlockIp { skill_id, .. } => assert_eq!(skill_id, "block-ip-pf"),
            other => panic!("expected BlockIp, got {other:?}"),
        }
    }

    #[test]
    fn block_ip_skill_id_uses_operator_configured_backend_xdp() {
        let action =
            build_action_from_prediction("block_ip", Some("203.0.113.45".to_string()), 0.95, "xdp");
        match action {
            AiAction::BlockIp { skill_id, .. } => assert_eq!(skill_id, "block-ip-xdp"),
            other => panic!("expected BlockIp, got {other:?}"),
        }
    }

    // ── 2026-05-20 anchors: decision-marker disclosure ───────────────────
    //
    // The on-device classifier is a black-box transformer; the `reason`
    // field used to carry only `action + confidence + alternatives`. PR
    // (this one) adds heuristic markers — cloud_safelist hit, AbuseIPDB
    // score, country, recent_events count, related_incidents count,
    // incident tags — so the operator can verify by eye WHY the model
    // decided what it did without spelunking the incident detail. These
    // tests pin the disclosure contract.

    fn minimal_incident(
        incident_id: &str,
        tags: Vec<String>,
    ) -> innerwarden_core::incident::Incident {
        innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: incident_id.to_string(),
            severity: innerwarden_core::event::Severity::Info,
            title: "test".to_string(),
            summary: "test".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags,
            entities: vec![],
        }
    }

    fn ctx_with<'a>(
        incident: &'a innerwarden_core::incident::Incident,
        already_blocked: Vec<String>,
        ip_reputation: Option<crate::abuseipdb::IpReputation>,
        ip_geo: Option<crate::geoip::GeoInfo>,
    ) -> DecisionContext<'a> {
        DecisionContext {
            incident,
            recent_events: vec![],
            related_incidents: vec![],
            already_blocked,
            available_skills: vec![],
            ip_reputation,
            ip_geo,
            ip_dshield: None,
            ip_dshield_attacker: false,
            host_posture: None,
            prior_decisions: None,
            graph_context: None,
            graph_subgraph: None,
            playbook_outcome: None,
        }
    }

    #[test]
    fn build_decision_markers_returns_empty_when_no_context_signal() {
        // A bare incident with no IP, no enrichment, no recent events,
        // and no tags should produce no markers. Without this anchor a
        // future refactor that always emits "incident_tags=[]" or
        // "recent_events=0" would silently bloat every reason string.
        let incident = minimal_incident("test:1", vec![]);
        let ctx = ctx_with(&incident, vec![], None, None);
        let markers = build_decision_markers(&ctx, None);
        assert!(
            markers.is_empty(),
            "no input signal should produce no markers; got {markers:?}"
        );
    }

    #[test]
    fn build_decision_markers_labels_cloudflare_ip_via_cloud_safelist() {
        // The most operator-visible marker: when local_classifier
        // dismisses something, the #1 question is "was this just a
        // cloud-safelisted IP?". safelist=Cloudflare answers it in one
        // line. Picks 104.16.0.1 because it's inside Cloudflare's
        // canonical /13 range published at cloud_safelist.rs:79.
        crate::cloud_safelist::init();
        let incident = minimal_incident("test:cf", vec![]);
        let ctx = ctx_with(&incident, vec![], None, None);
        let markers = build_decision_markers(&ctx, Some("104.16.0.1"));
        assert!(
            markers.iter().any(|m| m.starts_with("safelist=")),
            "expected safelist marker for Cloudflare IP, got {markers:?}"
        );
    }

    #[test]
    fn build_decision_markers_emits_already_blocked_only_for_target_ip_match() {
        // Pins the exact-string match contract. If the target IP is
        // 203.0.113.10 and the blocklist contains 203.0.113.10, the
        // marker fires. If the blocklist contains a DIFFERENT IP
        // (203.0.113.11), the marker must NOT fire.
        crate::cloud_safelist::init();
        let incident = minimal_incident("test:blocked", vec![]);

        let ctx_hit = ctx_with(&incident, vec!["203.0.113.10".to_string()], None, None);
        let markers_hit = build_decision_markers(&ctx_hit, Some("203.0.113.10"));
        assert!(
            markers_hit.contains(&"already_blocked=true".to_string()),
            "expected already_blocked=true when target IP is in blocklist; got {markers_hit:?}"
        );

        let ctx_miss = ctx_with(&incident, vec!["203.0.113.11".to_string()], None, None);
        let markers_miss = build_decision_markers(&ctx_miss, Some("203.0.113.10"));
        assert!(
            !markers_miss.iter().any(|m| m == "already_blocked=true"),
            "already_blocked must NOT fire when target IP differs from blocklist entry; got {markers_miss:?}"
        );
    }

    #[test]
    fn build_decision_markers_includes_abuseipdb_score_and_country_when_enriched() {
        // Even a 0-score AbuseIPDB hit is signal ("checked + clean").
        // Emit when the enrichment field is Some, regardless of score.
        let incident = minimal_incident("test:enriched", vec![]);
        let rep = crate::abuseipdb::IpReputation {
            confidence_score: 87,
            total_reports: 42,
            distinct_users: 8,
            country_code: Some("RU".to_string()),
            isp: Some("Bulletproof VPS".to_string()),
            is_tor: false,
        };
        let geo = crate::geoip::GeoInfo {
            country: "Russia".to_string(),
            country_code: "RU".to_string(),
            city: "Moscow".to_string(),
            isp: "Bulletproof VPS".to_string(),
            asn: "AS12345".to_string(),
        };
        let ctx = ctx_with(&incident, vec![], Some(rep), Some(geo));
        let markers = build_decision_markers(&ctx, Some("185.234.1.1"));
        assert!(
            markers.contains(&"abuseipdb=87".to_string()),
            "expected abuseipdb=87 in {markers:?}"
        );
        assert!(
            markers.contains(&"country=RU".to_string()),
            "expected country=RU in {markers:?}"
        );
    }

    #[test]
    fn build_decision_markers_caps_incident_tags_at_three() {
        // The reason field is rendered verbatim in the audit JSONL +
        // operator dashboard. A 20-tag incident must not produce a
        // 200-char tag list. Cap at 3 — enough to identify the
        // incident class, short enough to keep `reason` readable.
        let incident = minimal_incident(
            "test:many-tags",
            vec![
                "tag1".to_string(),
                "tag2".to_string(),
                "tag3".to_string(),
                "tag4".to_string(),
                "tag5".to_string(),
            ],
        );
        let ctx = ctx_with(&incident, vec![], None, None);
        let markers = build_decision_markers(&ctx, None);
        let tags_marker = markers
            .iter()
            .find(|m| m.starts_with("incident_tags="))
            .expect("incident_tags marker must be present");
        // Counts commas inside the bracketed list — 3 tags == 2 commas.
        let commas = tags_marker.matches(',').count();
        assert_eq!(
            commas, 2,
            "incident_tags must be capped at 3 elements (2 commas); got {tags_marker:?}"
        );
        assert!(
            tags_marker.contains("tag1")
                && tags_marker.contains("tag2")
                && tags_marker.contains("tag3"),
            "expected first 3 tags preserved in {tags_marker:?}"
        );
        assert!(
            !tags_marker.contains("tag4") && !tags_marker.contains("tag5"),
            "expected tag4/tag5 to be dropped beyond the cap in {tags_marker:?}"
        );
    }
}
