use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tracing::debug;

use super::{AiDecision, AiProvider, DecisionContext};
use crate::ai::openai::{build_prompt_pub, parse_decision_pub, system_prompt};

// ---------------------------------------------------------------------------
// Ollama provider - cloud API or local instance
// ---------------------------------------------------------------------------
//
// Supports two modes:
//
// 1. Ollama Cloud (recommended) - https://ollama.com free tier
//    - Set base_url = "https://api.ollama.com"
//    - Set api_key  = your Ollama API key (or OLLAMA_API_KEY env var)
//    - Recommended model: qwen3-coder:480b (100% accuracy in benchmarks)
//    - No local GPU required; no model download needed
//
// 2. Local instance - http://localhost:11434 (self-hosted)
//    - Leave api_key empty; no authentication required
//    - Compatible models: llama3.2, mistral, gemma2, qwen2.5, etc.
//    - Install a model locally: `ollama pull <model>`
//
// Both modes use the same /api/chat endpoint and response schema.

pub struct OllamaProvider {
    base_url: String,
    model: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl OllamaProvider {
    pub fn new(base_url: String, model: String, api_key: Option<String>) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            // Cloud inference can occasionally be slower for large models
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build HTTP client for ollama: {e}"))?;
        Ok(Self {
            base_url,
            model,
            api_key,
            client,
        })
    }
}

#[async_trait]
impl AiProvider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn chat(&self, system_prompt: &str, user_message: &str) -> Result<String> {
        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));

        debug!(model = %self.model, url = %url, "calling Ollama API for chat");

        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": system_prompt },
                { "role": "user",   "content": user_message }
            ],
            "stream": false,
        });

        let mut req = self.client.post(&url).json(&body);

        if let Some(ref key) = self.api_key {
            req = req.bearer_auth(key);
        }

        let resp = req.send().await.with_context(|| {
            if self.api_key.is_some() {
                format!("Ollama cloud chat request to {url} failed - check network connectivity")
            } else {
                format!(
                    "Ollama chat request to {url} failed - is Ollama running? \
                     Start it with: ollama serve"
                )
            }
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!(
                "Ollama chat returned {status}: {}",
                text.chars().take(300).collect::<String>()
            );
        }

        let completion: OllamaResponse = resp
            .json()
            .await
            .context("failed to parse Ollama chat response")?;

        let content = completion.message.content;
        if content.is_empty() {
            bail!(
                "Ollama chat returned an empty response for model {}",
                self.model
            );
        }

        Ok(content)
    }

    async fn decide(&self, ctx: &DecisionContext<'_>) -> Result<AiDecision> {
        let prompt = build_prompt_pub(ctx);
        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));

        debug!(model = %self.model, url = %url, "calling Ollama API");

        let body = json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": system_prompt() },
                { "role": "user",   "content": prompt }
            ],
            "stream": false,
            "format": "json",
            "options": {
                "temperature": 0.2,
                "num_predict": 512,
            }
        });

        let mut req = self.client.post(&url).json(&body);

        if let Some(ref key) = self.api_key {
            req = req.bearer_auth(key);
        }

        let resp = req.send().await.with_context(|| {
            if self.api_key.is_some() {
                format!("Ollama cloud request to {url} failed - check network connectivity")
            } else {
                format!(
                    "Ollama request to {url} failed - is Ollama running? \
                         Start it with: ollama serve"
                )
            }
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if status.as_u16() == 401 || status.as_u16() == 403 {
                bail!(
                    "Ollama returned {status}: authentication failed.\n\
                     Check your OLLAMA_API_KEY or api_key in agent.toml.\n\
                     Get a key at: https://ollama.com/settings/api-keys"
                );
            }
            // Surface a helpful message for the most common local error: model not pulled
            if (status.as_u16() == 404 || text.contains("model")) && self.api_key.is_none() {
                bail!(
                    "Ollama returned {status}: {}\n\
                     Hint: pull the model first with: ollama pull {}",
                    text.chars().take(200).collect::<String>(),
                    self.model
                );
            }
            bail!(
                "Ollama returned {status}: {}",
                text.chars().take(300).collect::<String>()
            );
        }

        let completion: OllamaResponse = resp
            .json()
            .await
            .context("failed to parse Ollama response")?;

        let content = completion.message.content;
        if content.is_empty() {
            bail!("Ollama returned an empty response for model {}", self.model);
        }

        // Some models wrap the JSON in prose despite format:json.
        // extract_json handles that gracefully.
        let json_str = extract_json(&content)
            .with_context(|| format!("Ollama response contained no JSON object: {content}"))?;

        parse_decision_pub(json_str)
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct OllamaResponse {
    message: OllamaMessage,
}

#[derive(Deserialize)]
struct OllamaMessage {
    content: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the first `{...}` JSON object from text that may contain prose.
fn extract_json(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end >= start {
        Some(&text[start..=end])
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::ai::AiAction;

    use super::*;
    use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};
    use serde_json::json;

    #[test]
    fn extract_json_bare_object() {
        let s = r#"{"action":"ignore","confidence":0.5}"#;
        assert_eq!(extract_json(s), Some(s));
    }

    #[test]
    fn extract_json_strips_prose() {
        let s = r#"Sure! Here is my answer: {"action":"ignore","confidence":0.5} Hope that helps."#;
        assert_eq!(
            extract_json(s),
            Some(r#"{"action":"ignore","confidence":0.5}"#)
        );
    }

    #[test]
    fn extract_json_returns_none_for_no_braces() {
        assert_eq!(extract_json("no json here"), None);
    }

    #[test]
    fn new_uses_supplied_values() {
        let p = OllamaProvider::new("http://192.168.1.10:11434".into(), "mistral".into(), None)
            .unwrap();
        assert_eq!(p.base_url, "http://192.168.1.10:11434");
        assert_eq!(p.model, "mistral");
        assert!(p.api_key.is_none());
    }

    #[test]
    fn new_stores_api_key() {
        let p = OllamaProvider::new(
            "https://api.ollama.com".into(),
            "qwen3-coder:480b".into(),
            Some("test-key".into()),
        )
        .unwrap();
        assert_eq!(p.api_key.as_deref(), Some("test-key"));
    }

    #[test]
    fn url_construction_strips_trailing_slash() {
        let p =
            OllamaProvider::new("http://localhost:11434/".into(), "llama3.2".into(), None).unwrap();
        let url = format!("{}/api/chat", p.base_url.trim_end_matches('/'));
        assert_eq!(url, "http://localhost:11434/api/chat");
    }

    fn provider(base_url: String, api_key: Option<&str>) -> OllamaProvider {
        OllamaProvider::new(
            base_url,
            "llama3.2".into(),
            api_key.map(ToString::to_string),
        )
        .unwrap()
    }

    fn ollama_response(content: &str) -> String {
        json!({ "message": { "content": content } }).to_string()
    }

    fn decision_json() -> &'static str {
        r#"{
            "action": "block_ip",
            "target_ip": "203.0.113.10",
            "target_user": null,
            "duration_secs": null,
            "skill_id": "block-ip-ufw",
            "confidence": 0.91,
            "auto_execute": true,
            "reason": "credential stuffing from a hostile host",
            "alternatives": ["monitor"],
            "estimated_threat": "high"
        }"#
    }

    fn test_incident() -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "test-host".into(),
            incident_id: "ssh_bruteforce:203.0.113.10:test-host".into(),
            severity: Severity::High,
            title: "SSH brute force".into(),
            summary: "Repeated failed SSH login attempts".into(),
            evidence: json!({ "source_ip": "203.0.113.10" }),
            recommended_checks: vec![],
            tags: vec!["ssh".into()],
            entities: vec![EntityRef::ip("203.0.113.10")],
        }
    }

    fn test_context(incident: &Incident) -> DecisionContext<'_> {
        DecisionContext {
            incident,
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
        }
    }

    #[tokio::test]
    async fn chat_posts_to_api_chat_and_returns_message_content() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/chat")
            .match_header(
                "content-type",
                mockito::Matcher::Regex("application/json.*".to_string()),
            )
            .match_body(mockito::Matcher::PartialJson(json!({
                "model": "llama3.2",
                "stream": false
            })))
            .with_status(200)
            .with_body(ollama_response("analysis complete"))
            .create_async()
            .await;
        let provider = provider(format!("{}/", server.url()), None);

        let content = provider.chat("system", "user").await.unwrap();

        assert_eq!(content, "analysis complete");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn chat_sends_bearer_auth_when_api_key_is_configured() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/chat")
            .match_header("authorization", "Bearer test-key")
            .with_status(200)
            .with_body(ollama_response("authenticated"))
            .create_async()
            .await;
        let provider = provider(server.url(), Some("test-key"));

        let content = provider.chat("system", "user").await.unwrap();

        assert_eq!(content, "authenticated");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn chat_non_success_includes_status_and_response_body() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/chat")
            .with_status(503)
            .with_body("downstream unavailable")
            .create_async()
            .await;
        let provider = provider(server.url(), None);

        let err = provider.chat("system", "user").await.unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("Ollama chat returned 503"), "got: {msg}");
        assert!(msg.contains("downstream unavailable"), "got: {msg}");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn chat_rejects_empty_message_content() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/chat")
            .with_status(200)
            .with_body(ollama_response(""))
            .create_async()
            .await;
        let provider = provider(server.url(), None);

        let err = provider.chat("system", "user").await.unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("Ollama chat returned an empty response"),
            "got: {msg}"
        );
        m.assert_async().await;
    }

    #[tokio::test]
    async fn decide_extracts_json_decision_from_prose_response() {
        let mut server = mockito::Server::new_async().await;
        let content = format!("Sure, here is the decision:\n{}\nDone.", decision_json());
        let m = server
            .mock("POST", "/api/chat")
            .match_body(mockito::Matcher::PartialJson(json!({
                "model": "llama3.2",
                "stream": false,
                "format": "json",
                "options": {
                    "temperature": 0.2,
                    "num_predict": 512
                }
            })))
            .with_status(200)
            .with_body(ollama_response(&content))
            .create_async()
            .await;
        let provider = provider(server.url(), None);
        let incident = test_incident();
        let ctx = test_context(&incident);

        let decision = provider.decide(&ctx).await.unwrap();

        assert!(matches!(
            decision.action,
            AiAction::BlockIp {
                ref ip,
                ref skill_id
            } if ip == "203.0.113.10" && skill_id == "block-ip-ufw"
        ));
        assert_eq!(decision.confidence, 0.91);
        assert!(decision.auto_execute);
        assert_eq!(decision.estimated_threat, "high");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn decide_auth_failure_includes_cloud_api_key_hint() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/chat")
            .match_header("authorization", "Bearer bad-key")
            .with_status(401)
            .with_body("invalid token")
            .create_async()
            .await;
        let provider = provider(server.url(), Some("bad-key"));
        let incident = test_incident();
        let ctx = test_context(&incident);

        let err = provider.decide(&ctx).await.unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("authentication failed"), "got: {msg}");
        assert!(msg.contains("OLLAMA_API_KEY"), "got: {msg}");
        assert!(
            msg.contains("https://ollama.com/settings/api-keys"),
            "got: {msg}"
        );
        m.assert_async().await;
    }

    #[tokio::test]
    async fn decide_local_model_not_found_includes_pull_hint() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/chat")
            .with_status(404)
            .with_body(r#"{"error":"model 'llama3.2' not found"}"#)
            .create_async()
            .await;
        let provider = provider(server.url(), None);
        let incident = test_incident();
        let ctx = test_context(&incident);

        let err = provider.decide(&ctx).await.unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("model 'llama3.2' not found"), "got: {msg}");
        assert!(msg.contains("ollama pull llama3.2"), "got: {msg}");
        m.assert_async().await;
    }
}
