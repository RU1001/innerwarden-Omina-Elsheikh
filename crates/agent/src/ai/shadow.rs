//! Shadow-mode AI provider wrapper.
//!
//! Runs a primary provider and a shadow provider in parallel on each decision.
//! The primary's decision is returned to the caller (the agent acts on it).
//! The shadow's decision is logged to a JSONL file so operators can audit
//! agreement before promoting the shadow to primary.
//!
//! Intended use: deploy a new provider (e.g. a freshly distilled local
//! classifier) as shadow while the known-good provider (e.g. Azure OpenAI)
//! continues to drive production. After 1-2 weeks of logs showing high
//! agreement the operator can flip the config and promote the shadow.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use serde::Serialize;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::{AiAction, AiDecision, AiProvider, DecisionContext};

pub struct ShadowProvider {
    primary: Box<dyn AiProvider>,
    shadow: Box<dyn AiProvider>,
    log_path: PathBuf,
    /// Serializes writes to the JSONL file across concurrent decisions.
    write_lock: Arc<Mutex<()>>,
    /// Fraction of `decide()` calls that exercise the shadow path.
    /// `1.0` means every call (legacy behaviour from the initial 028-b
    /// validation window); `0.1` runs the shadow ~10% of the time and
    /// skips both the shadow request and the JSONL append for the
    /// other 90% — keeps a drift-detection sample at a fraction of
    /// the Azure latency + API spend per incident.
    /// Validated by `ShadowConfig::validate` to be in `[0.0, 1.0]`.
    sample_rate: f32,
}

#[derive(Serialize)]
struct ShadowLogEntry<'a> {
    ts: String,
    incident_id: &'a str,
    primary_provider: &'a str,
    primary_action: &'a str,
    primary_confidence: f32,
    primary_latency_ms: u64,
    shadow_provider: &'a str,
    shadow_action: Option<&'a str>,
    shadow_confidence: Option<f32>,
    shadow_latency_ms: Option<u64>,
    shadow_error: Option<String>,
    action_match: Option<bool>,
}

impl ShadowProvider {
    /// Construct a shadow-mode wrapper. `sample_rate=1.0` preserves
    /// the legacy "run shadow on every decide()" behaviour from the
    /// initial 028-b validation window; `sample_rate=0.1` is the
    /// post-validation drift-detection setting (see RESULTS_V3
    /// 2026-05-11). Range is `[0.0, 1.0]`; values outside that clamp
    /// defensively — the canonical gate is `ShadowConfig::validate`
    /// at startup.
    pub fn with_sample_rate(
        primary: Box<dyn AiProvider>,
        shadow: Box<dyn AiProvider>,
        log_path: impl AsRef<Path>,
        sample_rate: f32,
    ) -> Self {
        // Caller is expected to validate via `ShadowConfig::validate`
        // before reaching here; clamp defensively as a belt-and-suspenders
        // in case a future caller forgets, so a misconfig can never cause
        // shadow to run never (when intended) or always (when not).
        let sample_rate = sample_rate.clamp(0.0, 1.0);
        Self {
            primary,
            shadow,
            log_path: log_path.as_ref().to_path_buf(),
            write_lock: Arc::new(Mutex::new(())),
            sample_rate,
        }
    }

    /// Returns true when this `decide()` call should exercise the shadow.
    /// `1.0` always runs, `0.0` never runs, anything in between is a
    /// per-call uniform random draw. Extracted so tests can pin the
    /// boundary behaviour without seeding the global RNG.
    fn should_sample(sample_rate: f32) -> bool {
        if sample_rate >= 1.0 {
            return true;
        }
        if sample_rate <= 0.0 {
            return false;
        }
        rand::random::<f32>() < sample_rate
    }

    async fn append_log(&self, entry: &ShadowLogEntry<'_>) {
        let Ok(mut line) = serde_json::to_string(entry) else {
            warn!("failed to serialize shadow log entry");
            return;
        };
        line.push('\n');

        let _guard = self.write_lock.lock().await;
        let open = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await;
        match open {
            Ok(mut f) => {
                if let Err(e) = f.write_all(line.as_bytes()).await {
                    warn!(err = %e, path = %self.log_path.display(), "shadow log write failed");
                    return;
                }
                // Explicit flush so operators tailing the file (or tests
                // reading it synchronously) observe the write immediately.
                if let Err(e) = f.flush().await {
                    warn!(err = %e, path = %self.log_path.display(), "shadow log flush failed");
                }
            }
            Err(e) => warn!(err = %e, path = %self.log_path.display(), "shadow log open failed"),
        }
    }
}

#[async_trait]
impl AiProvider for ShadowProvider {
    fn name(&self) -> &'static str {
        // Report the primary's name so existing telemetry/metrics keep their
        // labels. The shadow is internal detail.
        self.primary.name()
    }

    /// Spec 029: delegate to the wrapped primary. The shadow does not
    /// add capabilities of its own - it audits whatever the primary
    /// can do. Without this override the router would see a
    /// shadow-wrapped classifier as having every capability (trait
    /// default `ALL`) and route `Classify` or `Generate` calls to the
    /// wrapper's `chat()`, which forwards to the primary and fails
    /// because the real classifier has no decoder.
    fn capabilities(&self) -> crate::ai::capability::AiCapabilities {
        self.primary.capabilities()
    }

    async fn decide(&self, ctx: &DecisionContext<'_>) -> Result<AiDecision> {
        let incident_id = ctx.incident.incident_id.clone();

        // Probabilistic sampling (2026-05-11 RESULTS_V3): when
        // `sample_rate < 1.0`, skip the shadow path entirely on the
        // non-sampled fraction. The skipped calls don't touch the
        // shadow provider, don't append to the JSONL log, and don't
        // emit the per-decision info log line. Net effect: at
        // `sample_rate = 0.1` the shadow infra runs 10% as often,
        // preserving drift-detection signal at 1/10 the Azure latency
        // + API spend.
        if !Self::should_sample(self.sample_rate) {
            return self.primary.decide(ctx).await;
        }

        // Run both concurrently and time each provider independently so
        // shadow_latency_ms reflects the shadow's own inference time, not the
        // wall-clock of the joined call. Primary error fails the whole call
        // (same behavior as without shadow). Shadow error is logged, not
        // propagated.
        let primary_fut = async {
            let t = Instant::now();
            let res = self.primary.decide(ctx).await;
            (res, t.elapsed().as_millis() as u64)
        };
        let shadow_fut = async {
            let t = Instant::now();
            let res = self.shadow.decide(ctx).await;
            (res, t.elapsed().as_millis() as u64)
        };
        let ((primary_res, primary_latency), (shadow_res, shadow_latency)) =
            tokio::join!(primary_fut, shadow_fut);

        let primary = primary_res?;

        let primary_action = primary.action.name();
        match shadow_res {
            Ok(shadow) => {
                let shadow_action = shadow.action.name();
                let match_ = primary_action == shadow_action;
                let entry = ShadowLogEntry {
                    ts: Utc::now().to_rfc3339(),
                    incident_id: &incident_id,
                    primary_provider: self.primary.name(),
                    primary_action,
                    primary_confidence: primary.confidence,
                    primary_latency_ms: primary_latency,
                    shadow_provider: self.shadow.name(),
                    shadow_action: Some(shadow_action),
                    shadow_confidence: Some(shadow.confidence),
                    shadow_latency_ms: Some(shadow_latency),
                    shadow_error: None,
                    action_match: Some(match_),
                };
                self.append_log(&entry).await;
                info!(
                    incident_id = %incident_id,
                    primary = %primary_action,
                    shadow = %shadow_action,
                    agreement = match_,
                    "shadow decision"
                );
            }
            Err(e) => {
                let entry = ShadowLogEntry {
                    ts: Utc::now().to_rfc3339(),
                    incident_id: &incident_id,
                    primary_provider: self.primary.name(),
                    primary_action,
                    primary_confidence: primary.confidence,
                    primary_latency_ms: primary_latency,
                    shadow_provider: self.shadow.name(),
                    shadow_action: None,
                    shadow_confidence: None,
                    shadow_latency_ms: Some(shadow_latency),
                    shadow_error: Some(e.to_string()),
                    action_match: None,
                };
                self.append_log(&entry).await;
                warn!(
                    incident_id = %incident_id,
                    err = %e,
                    "shadow provider errored (primary decision unaffected)"
                );
            }
        }

        Ok(primary)
    }

    async fn chat(&self, system_prompt: &str, user_message: &str) -> Result<String> {
        // Chat is only routed to the primary. Shadow is for triage decisions only.
        self.primary.chat(system_prompt, user_message).await
    }
}

// AiAction::name exists in mod.rs; ensure it is in scope here.
impl AiAction {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeProvider {
        name: &'static str,
        action: AiAction,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl AiProvider for FakeProvider {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn decide(&self, _ctx: &DecisionContext<'_>) -> Result<AiDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(AiDecision {
                action: self.action.clone(),
                confidence: 0.9,
                auto_execute: false,
                reason: String::new(),
                alternatives: vec![],
                estimated_threat: "medium".into(),
            })
        }
        async fn chat(&self, _s: &str, _u: &str) -> Result<String> {
            Ok(format!("{} chat", self.name))
        }
    }

    fn dummy_incident() -> innerwarden_core::incident::Incident {
        use innerwarden_core::{event::Severity, incident::Incident};
        Incident {
            ts: chrono::Utc::now(),
            host: "test".into(),
            incident_id: "ssh_bruteforce:1.2.3.4:shadow-test".into(),
            severity: Severity::High,
            title: "test".into(),
            summary: "test".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        }
    }

    #[tokio::test]
    async fn shadow_writes_log_on_agreement() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let shadow_calls = Arc::new(AtomicUsize::new(0));
        let primary = Box::new(FakeProvider {
            name: "prim",
            action: AiAction::Ignore { reason: "p".into() },
            calls: Arc::clone(&primary_calls),
        });
        let shadow = Box::new(FakeProvider {
            name: "shad",
            action: AiAction::Ignore { reason: "s".into() },
            calls: Arc::clone(&shadow_calls),
        });
        let sp = ShadowProvider::with_sample_rate(primary, shadow, tmp.path(), 1.0);

        let inc = dummy_incident();
        let ctx = DecisionContext {
            incident: &inc,
            recent_events: vec![],
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
        };
        let d = sp.decide(&ctx).await.unwrap();
        assert!(matches!(d.action, AiAction::Ignore { .. }));
        assert_eq!(primary_calls.load(Ordering::SeqCst), 1);
        assert_eq!(shadow_calls.load(Ordering::SeqCst), 1);

        let logged = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(logged.contains("\"action_match\":true"));
        assert!(logged.contains("\"primary_action\":\"ignore\""));
        assert!(logged.contains("\"shadow_action\":\"ignore\""));
    }

    #[tokio::test]
    async fn shadow_logs_disagreement() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let primary = Box::new(FakeProvider {
            name: "prim",
            action: AiAction::BlockIp {
                ip: "1.2.3.4".into(),
                skill_id: "block-ip-ufw".into(),
            },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let shadow = Box::new(FakeProvider {
            name: "shad",
            action: AiAction::Monitor {
                ip: "1.2.3.4".into(),
            },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let sp = ShadowProvider::with_sample_rate(primary, shadow, tmp.path(), 1.0);

        let inc = dummy_incident();
        let ctx = DecisionContext {
            incident: &inc,
            recent_events: vec![],
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
        };
        let _ = sp.decide(&ctx).await.unwrap();
        let logged = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(logged.contains("\"action_match\":false"));
    }

    #[tokio::test]
    async fn primary_error_propagates_shadow_does_not() {
        struct Erroring;
        #[async_trait]
        impl AiProvider for Erroring {
            fn name(&self) -> &'static str {
                "err"
            }
            async fn decide(&self, _ctx: &DecisionContext<'_>) -> Result<AiDecision> {
                anyhow::bail!("boom")
            }
            async fn chat(&self, _s: &str, _u: &str) -> Result<String> {
                anyhow::bail!("boom")
            }
        }

        let tmp = tempfile::NamedTempFile::new().unwrap();

        // Primary errors -> overall error
        let primary = Box::new(Erroring);
        let shadow = Box::new(FakeProvider {
            name: "s",
            action: AiAction::Ignore { reason: "x".into() },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let sp = ShadowProvider::with_sample_rate(primary, shadow, tmp.path(), 1.0);
        let inc = dummy_incident();
        let ctx = DecisionContext {
            incident: &inc,
            recent_events: vec![],
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
        };
        assert!(sp.decide(&ctx).await.is_err());

        // Primary OK, shadow errors -> primary returned, shadow_error logged
        let primary = Box::new(FakeProvider {
            name: "p",
            action: AiAction::Ignore {
                reason: "ok".into(),
            },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let shadow = Box::new(Erroring);
        let sp = ShadowProvider::with_sample_rate(primary, shadow, tmp.path(), 1.0);
        let d = sp.decide(&ctx).await.unwrap();
        assert!(matches!(d.action, AiAction::Ignore { .. }));
        let logged = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(logged.contains("\"shadow_error\""));
    }

    #[tokio::test]
    async fn chat_passes_through_to_primary_only() {
        // Shadow.chat() must never invoke the shadow provider — only primary
        // observation chat reaches production, shadow is decision-only.
        let shadow_calls = Arc::new(AtomicUsize::new(0));
        let primary = Box::new(FakeProvider {
            name: "prim",
            action: AiAction::Ignore { reason: "p".into() },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let shadow = Box::new(FakeProvider {
            name: "shad",
            action: AiAction::Ignore { reason: "s".into() },
            calls: Arc::clone(&shadow_calls),
        });
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sp = ShadowProvider::with_sample_rate(primary, shadow, tmp.path(), 1.0);

        let reply = sp.chat("system", "user").await.unwrap();
        assert_eq!(reply, "prim chat");
        assert_eq!(
            shadow_calls.load(Ordering::SeqCst),
            0,
            "chat must not hit shadow provider"
        );
    }

    #[tokio::test]
    async fn capabilities_delegates_to_primary() {
        use crate::ai::capability::{AiCapabilities, Capability};

        // Narrow "classifier-like" primary that only claims Decide.
        struct DecideOnly;
        #[async_trait]
        impl AiProvider for DecideOnly {
            fn name(&self) -> &'static str {
                "decide-only"
            }
            fn capabilities(&self) -> AiCapabilities {
                AiCapabilities::from_slice(&[Capability::Decide])
            }
            async fn decide(&self, _ctx: &DecisionContext<'_>) -> Result<AiDecision> {
                Ok(AiDecision {
                    action: AiAction::Ignore {
                        reason: "ok".into(),
                    },
                    confidence: 0.9,
                    auto_execute: false,
                    reason: "t".into(),
                    alternatives: vec![],
                    estimated_threat: "low".into(),
                })
            }
            async fn chat(&self, _s: &str, _u: &str) -> Result<String> {
                anyhow::bail!("DecideOnly has no decoder")
            }
        }

        let primary = Box::new(DecideOnly);
        let shadow = Box::new(FakeProvider {
            name: "shad",
            action: AiAction::Ignore { reason: "s".into() },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sp = ShadowProvider::with_sample_rate(primary, shadow, tmp.path(), 1.0);

        let caps = sp.capabilities();
        assert!(caps.has(Capability::Decide));
        assert!(!caps.has(Capability::Classify));
        assert!(!caps.has(Capability::Generate));
        assert!(!caps.has(Capability::Explain));
        assert!(!caps.has(Capability::SimulateShell));
    }

    #[tokio::test]
    async fn name_delegates_to_primary() {
        let primary = Box::new(FakeProvider {
            name: "primary-name",
            action: AiAction::Ignore { reason: "p".into() },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let shadow = Box::new(FakeProvider {
            name: "shadow-name",
            action: AiAction::Ignore { reason: "s".into() },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sp = ShadowProvider::with_sample_rate(primary, shadow, tmp.path(), 1.0);
        assert_eq!(sp.name(), "primary-name");
    }

    #[tokio::test]
    async fn shadow_latency_measured_independently_from_primary() {
        // Regression guard: shadow_latency_ms must reflect the shadow
        // provider's own inference time, not the wall-clock of the joined
        // call (which is dominated by the slower side). Use a slow shadow
        // and a fast primary and assert the logged shadow latency is larger.
        struct SleepyProvider {
            name: &'static str,
            delay_ms: u64,
        }
        #[async_trait]
        impl AiProvider for SleepyProvider {
            fn name(&self) -> &'static str {
                self.name
            }
            async fn decide(&self, _ctx: &DecisionContext<'_>) -> Result<AiDecision> {
                tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
                Ok(AiDecision {
                    action: AiAction::Ignore {
                        reason: self.name.into(),
                    },
                    confidence: 0.9,
                    auto_execute: false,
                    reason: String::new(),
                    alternatives: vec![],
                    estimated_threat: "low".into(),
                })
            }
            async fn chat(&self, _s: &str, _u: &str) -> Result<String> {
                Ok(String::new())
            }
        }

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let primary = Box::new(SleepyProvider {
            name: "fast-primary",
            delay_ms: 0,
        });
        let shadow = Box::new(SleepyProvider {
            name: "slow-shadow",
            delay_ms: 80,
        });
        let sp = ShadowProvider::with_sample_rate(primary, shadow, tmp.path(), 1.0);

        let inc = dummy_incident();
        let ctx = DecisionContext {
            incident: &inc,
            recent_events: vec![],
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
        };
        let _ = sp.decide(&ctx).await.unwrap();

        let logged = std::fs::read_to_string(tmp.path()).unwrap();
        let entry: serde_json::Value = serde_json::from_str(logged.trim()).unwrap();
        let primary_ms = entry["primary_latency_ms"].as_u64().unwrap();
        let shadow_ms = entry["shadow_latency_ms"].as_u64().unwrap();
        assert!(
            shadow_ms >= 70,
            "shadow latency should reflect the 80ms sleep, got {shadow_ms}ms"
        );
        assert!(
            primary_ms + 20 < shadow_ms,
            "primary ({primary_ms}ms) should be materially faster than shadow ({shadow_ms}ms)"
        );
    }

    #[tokio::test]
    async fn decide_returns_primary_when_log_write_fails() {
        // Unwriteable log path must not break the primary decision. The open
        // failure is logged via tracing and the primary decision still flows
        // back to the caller.
        let primary = Box::new(FakeProvider {
            name: "prim",
            action: AiAction::Ignore {
                reason: "primary ok".into(),
            },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let shadow = Box::new(FakeProvider {
            name: "shad",
            action: AiAction::Ignore { reason: "s".into() },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let sp =
            ShadowProvider::with_sample_rate(primary, shadow, "/nonexistent/dir/shadow.jsonl", 1.0);

        let inc = dummy_incident();
        let ctx = DecisionContext {
            incident: &inc,
            recent_events: vec![],
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
        };
        let d = sp.decide(&ctx).await.unwrap();
        assert!(matches!(d.action, AiAction::Ignore { .. }));
    }

    // ─────────────────────────────────────────────────────────────────
    // Sample-rate behaviour (RESULTS_V3, 2026-05-11). The boundary
    // cases (0.0 / 1.0) are deterministic; the intermediate cases use
    // the static helper which does call the global RNG. Tests pin
    // boundaries to avoid flakiness from random draws.
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn should_sample_one_point_oh_always_runs() {
        // sample_rate=1.0 is the legacy behaviour and the default. Every
        // call must run the shadow path so the JSONL log keeps growing
        // at the existing rate for existing deployments.
        for _ in 0..100 {
            assert!(ShadowProvider::should_sample(1.0));
        }
    }

    #[test]
    fn should_sample_zero_never_runs() {
        // sample_rate=0.0 is the operator's "shadow off but stay
        // wrapped" mode (useful when toggling at runtime via config
        // reload without restarting). The shadow path must skip
        // unconditionally so no Azure calls fire and the JSONL log
        // stays unchanged.
        for _ in 0..100 {
            assert!(!ShadowProvider::should_sample(0.0));
        }
    }

    #[test]
    fn should_sample_intermediate_does_not_panic() {
        // Probabilistic; we don't assert on the boolean outcome (it's
        // random) but we DO assert that calling it many times never
        // panics — the rand::random::<f32>() path is well-formed.
        let mut hits = 0;
        let mut total = 0;
        for _ in 0..2000 {
            total += 1;
            if ShadowProvider::should_sample(0.1) {
                hits += 1;
            }
        }
        // 0.1 over 2000 draws: expected ~200, allow generous 50..400
        // band so the test stays green across the rand crate's internal
        // PRNG variations and CI noise. Tighter would flake.
        assert!(
            (50..=400).contains(&hits),
            "expected ~200 sampled out of 2000 at rate 0.1, got {hits} / {total}"
        );
    }

    #[tokio::test]
    async fn decide_skips_shadow_when_sample_rate_zero() {
        // Hard zero: shadow provider must NEVER be called, JSONL log
        // must stay empty. This is the operator's "keep wrapping for
        // hot-reload to flip later, but no live shadow traffic" mode.
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let shadow_calls = Arc::new(AtomicUsize::new(0));
        let primary = Box::new(FakeProvider {
            name: "prim",
            action: AiAction::Ignore { reason: "p".into() },
            calls: primary_calls.clone(),
        });
        let shadow = Box::new(FakeProvider {
            name: "shad",
            action: AiAction::Ignore { reason: "s".into() },
            calls: shadow_calls.clone(),
        });
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sp = ShadowProvider::with_sample_rate(primary, shadow, tmp.path(), 0.0);

        let inc = dummy_incident();
        let ctx = DecisionContext {
            incident: &inc,
            recent_events: vec![],
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
        };

        // 5 calls is plenty to make any deterministic-bug stand out.
        for _ in 0..5 {
            let _ = sp.decide(&ctx).await.unwrap();
        }

        assert_eq!(
            primary_calls.load(Ordering::SeqCst),
            5,
            "primary must always run"
        );
        assert_eq!(
            shadow_calls.load(Ordering::SeqCst),
            0,
            "shadow must never run at rate 0"
        );
        let log = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(
            log.is_empty(),
            "JSONL log must stay empty when shadow is skipped: {log}"
        );
    }

    #[tokio::test]
    async fn decide_always_runs_shadow_when_sample_rate_one() {
        // Sanity check the legacy behaviour wasn't broken by the
        // refactor. With rate=1.0 the shadow must run on every call
        // and the JSONL log must grow by one line per call.
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let shadow_calls = Arc::new(AtomicUsize::new(0));
        let primary = Box::new(FakeProvider {
            name: "prim",
            action: AiAction::Ignore { reason: "p".into() },
            calls: primary_calls.clone(),
        });
        let shadow = Box::new(FakeProvider {
            name: "shad",
            action: AiAction::Ignore { reason: "s".into() },
            calls: shadow_calls.clone(),
        });
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sp = ShadowProvider::with_sample_rate(primary, shadow, tmp.path(), 1.0);

        let inc = dummy_incident();
        let ctx = DecisionContext {
            incident: &inc,
            recent_events: vec![],
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
        };
        for _ in 0..3 {
            let _ = sp.decide(&ctx).await.unwrap();
        }

        assert_eq!(primary_calls.load(Ordering::SeqCst), 3);
        assert_eq!(
            shadow_calls.load(Ordering::SeqCst),
            3,
            "shadow must run on every call at rate 1.0"
        );
        let log = std::fs::read_to_string(tmp.path()).unwrap();
        assert_eq!(log.lines().count(), 3, "one JSONL line per call");
    }

    #[test]
    fn with_sample_rate_clamps_out_of_range_values() {
        // Defensive belt-and-suspenders: ShadowConfig::validate is
        // the canonical gate at startup, but if a future caller
        // forgets to validate the constructor must not panic or
        // produce a degenerate state. Negative clamps to 0
        // (effectively "never sample"), > 1 clamps to 1 ("always").
        // This pins the contract so refactors of `clamp` cannot
        // silently regress to a behaviour where, say, a typo'd
        // `-0.1` would loop forever on `rand::random::<f32>() < -0.1`.
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let shadow_calls = Arc::new(AtomicUsize::new(0));
        let primary = Box::new(FakeProvider {
            name: "prim",
            action: AiAction::Ignore { reason: "p".into() },
            calls: primary_calls.clone(),
        });
        let shadow = Box::new(FakeProvider {
            name: "shad",
            action: AiAction::Ignore { reason: "s".into() },
            calls: shadow_calls.clone(),
        });
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sp_neg = ShadowProvider::with_sample_rate(primary, shadow, tmp.path(), -0.5);
        assert_eq!(sp_neg.sample_rate, 0.0);

        let primary2 = Box::new(FakeProvider {
            name: "prim",
            action: AiAction::Ignore { reason: "p".into() },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let shadow2 = Box::new(FakeProvider {
            name: "shad",
            action: AiAction::Ignore { reason: "s".into() },
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let tmp2 = tempfile::NamedTempFile::new().unwrap();
        let sp_high = ShadowProvider::with_sample_rate(primary2, shadow2, tmp2.path(), 2.5);
        assert_eq!(sp_high.sample_rate, 1.0);
    }
}
