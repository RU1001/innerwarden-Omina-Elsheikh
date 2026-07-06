use std::path::Path;

use crate::{bot_helpers, config, knowledge_graph, telegram};

pub(crate) fn incident_detector(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or("unknown")
}

/// Returns the guardian mode implied by the current responder configuration.
/// Because `/mode` mutates the owned `cfg` in place, this always reflects the
/// live mode (there is no separate override to consult).
pub(crate) fn guardian_mode(cfg: &config::AgentConfig) -> telegram::GuardianMode {
    mode_from_responder(cfg.responder.enabled, cfg.responder.dry_run)
}

/// The single source of truth mapping `(enabled, dry_run)` to a guardian mode.
/// Watch = responder off; DryRun = on but simulated; Guard = on and live.
pub(crate) fn mode_from_responder(enabled: bool, dry_run: bool) -> telegram::GuardianMode {
    if !enabled {
        telegram::GuardianMode::Watch
    } else if dry_run {
        telegram::GuardianMode::DryRun
    } else {
        telegram::GuardianMode::Guard
    }
}

/// Apply a guardian mode to the responder config in place. The Telegram `/mode`
/// command mutates the agent's owned `cfg` through this so EVERY downstream
/// `cfg.responder.{enabled,dry_run}` read (the ~60 enforcement + record sites)
/// sees the new mode immediately and consistently. There is no config
/// hot-reload, so this in-place mutation IS the runtime actuation; `/mode` also
/// persists the same two keys to agent.toml for restart durability.
///   Watch  = responder off (passive monitor)
///   DryRun = on but simulated
///   Guard  = on and live (auto-defend)
pub(crate) fn apply_guardian_mode(cfg: &mut config::AgentConfig, mode: telegram::GuardianMode) {
    match mode {
        telegram::GuardianMode::Watch => {
            cfg.responder.enabled = false;
        }
        telegram::GuardianMode::DryRun => {
            cfg.responder.enabled = true;
            cfg.responder.dry_run = true;
        }
        telegram::GuardianMode::Guard => {
            cfg.responder.enabled = true;
            cfg.responder.dry_run = false;
        }
    }
}

/// Persist the responder mode (the two keys `/mode` changes) to agent.toml,
/// format-preserving + atomic, so a phone mode flip survives a restart. The
/// in-memory `cfg` mutation already took effect; this is best-effort durability
/// (callers log on error, never fail the loop). Creates the `[responder]` table
/// and the file if missing.
pub(crate) fn persist_responder_mode(
    path: &std::path::Path,
    enabled: bool,
    dry_run: bool,
) -> std::io::Result<()> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut doc = content
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    doc["responder"]["enabled"] = toml_edit::value(enabled);
    doc["responder"]["dry_run"] = toml_edit::value(dry_run);
    // Atomic replace: write a sibling temp file then rename (same dir = same fs).
    let tmp = path.with_extension("toml.iwtmp");
    std::fs::write(&tmp, doc.to_string())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Map a Telegram sensitivity word to the bot channel's notification filter.
/// Returns None for an unknown word (caller leaves the level unchanged).
pub(crate) fn sensitivity_to_filter(level: &str) -> Option<crate::config::ChannelFilterLevel> {
    use crate::config::ChannelFilterLevel as L;
    match level.trim().to_ascii_lowercase().as_str() {
        "quiet" => Some(L::Critical),
        "normal" => Some(L::Actionable),
        "verbose" => Some(L::All),
        _ => None,
    }
}

/// The lowercase TOML token for a filter level (matches its serde repr).
fn filter_level_token(l: crate::config::ChannelFilterLevel) -> &'static str {
    use crate::config::ChannelFilterLevel::*;
    match l {
        All => "all",
        Actionable => "actionable",
        Critical => "critical",
        None => "none",
    }
}

/// Apply a queued Settings change to `cfg` in place + persist it to
/// `config_path`. Returns the human label of what changed for logging/reply, or
/// None if the change was invalid (e.g. an unknown sensitivity word). The
/// `[telegram]` reads (alert language via `user_profile`, alert noise via
/// `channel_notifications.notification_level`) all see the new value because we
/// mutate the owned `cfg`, same single-source-of-truth approach as `/mode`.
pub(crate) fn apply_setting_change(
    cfg: &mut config::AgentConfig,
    change: &crate::SettingChange,
    config_path: Option<&std::path::Path>,
) -> Option<String> {
    match change {
        crate::SettingChange::Profile(simple) => {
            cfg.telegram.user_profile = if *simple { "simple" } else { "technical" }.to_string();
            if let Some(path) = config_path {
                let _ =
                    persist_telegram_string(path, &["user_profile"], &cfg.telegram.user_profile);
            }
            Some(format!("profile={}", cfg.telegram.user_profile))
        }
        crate::SettingChange::Sensitivity(level) => {
            let filter = sensitivity_to_filter(level)?;
            cfg.telegram.channel_notifications.notification_level = filter;
            if let Some(path) = config_path {
                let _ = persist_telegram_string(
                    path,
                    &["channel_notifications", "notification_level"],
                    filter_level_token(filter),
                );
            }
            Some(format!("sensitivity={level}"))
        }
    }
}

/// Write a string key under `[telegram]` (or a nested sub-table) to agent.toml,
/// format-preserving + atomic. `key_path` is the dotted path under `telegram`.
fn persist_telegram_string(
    path: &std::path::Path,
    key_path: &[&str],
    value: &str,
) -> std::io::Result<()> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut doc = content
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let mut item = &mut doc["telegram"];
    for seg in &key_path[..key_path.len() - 1] {
        item = &mut item[*seg];
    }
    item[key_path[key_path.len() - 1]] = toml_edit::value(value);
    let tmp = path.with_extension("toml.iwtmp");
    std::fs::write(&tmp, doc.to_string())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Take a queued `/mode` change (if any), apply it to `cfg` in place, and
/// persist it to `config_path` (best-effort). Returns the applied mode so the
/// caller can log it. Pure of the run loop so the glue is unit-testable.
pub(crate) fn take_and_apply_pending_mode(
    cfg: &mut config::AgentConfig,
    pending: &mut Option<telegram::GuardianMode>,
    config_path: Option<&std::path::Path>,
) -> Option<telegram::GuardianMode> {
    let mode = pending.take()?;
    apply_guardian_mode(cfg, mode);
    if let Some(path) = config_path {
        if let Err(e) = persist_responder_mode(path, cfg.responder.enabled, cfg.responder.dry_run) {
            tracing::warn!(
                error = %e,
                "failed to persist /mode change to agent.toml (in-memory flip still active)"
            );
        }
    }
    Some(mode)
}

/// Builds a rich system-state context string injected into every AI chat call.
/// The AI uses this to answer self-awareness questions accurately and give
/// correct configuration advice.
pub(crate) fn build_agent_context(
    cfg: &config::AgentConfig,
    data_dir: &Path,
    kg: &std::sync::Arc<std::sync::RwLock<knowledge_graph::KnowledgeGraph>>,
) -> String {
    let mode = guardian_mode(cfg);
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let incident_count = bot_helpers::graph_count(kg, "incidents");
    // Canonical decisions-today count (restart-robust); the KG decision
    // count resets on reboot. See NUMBER_CONSISTENCY "decisions made today".
    let decision_count = crate::decisions::count_decisions_for_date(data_dir, &today);
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string());

    let skills_list = cfg.responder.allowed_skills.join(", ");
    let block_backend = &cfg.responder.block_backend;
    let ai_status = if cfg.ai.enabled {
        format!(
            "ENABLED - provider={}, model={}",
            cfg.ai.provider, cfg.ai.model
        )
    } else {
        "DISABLED".to_string()
    };
    let responder_status = if !cfg.responder.enabled {
        "DISABLED (watch-only mode)".to_string()
    } else if cfg.responder.dry_run {
        "ENABLED - dry-run (simulates actions, no real execution)".to_string()
    } else {
        format!("ENABLED - live mode (backend={block_backend})")
    };
    let telegram_status = if cfg.telegram.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let abuseipdb_status = if cfg.abuseipdb.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let geoip_status = if cfg.geoip.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let slack_status = if cfg.slack.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };
    let cloudflare_status = if cfg.cloudflare.enabled {
        "ENABLED"
    } else {
        "DISABLED"
    };

    format!(
        "=== INNERWARDEN SYSTEM STATE ===\n\
         Host: {host}\n\
         Version: {version}\n\
         Mode: {mode_label} - {mode_desc}\n\
         Data dir: {data_dir}\n\
         \n\
         Today ({today}): {incident_count} intrusion attempts, {decision_count} actions taken\n\
         \n\
         === ACTIVE CONFIGURATION ===\n\
         Responder: {responder_status}\n\
         Allowed skills: {skills_list}\n\
         AI analysis: {ai_status}\n\
         Telegram bot: {telegram_status}\n\
         AbuseIPDB enrichment: {abuseipdb_status}\n\
         GeoIP enrichment: {geoip_status}\n\
         Slack notifications: {slack_status}\n\
         Cloudflare edge blocking: {cloudflare_status}\n\
         \n\
         Capabilities are managed with `innerwarden enable/disable <id>`; `innerwarden status` shows the full overview. (The live server pulse follows below.)\n\
         ",
        host = host,
        version = env!("CARGO_PKG_VERSION"),
        mode_label = mode.label(),
        mode_desc = mode.description(),
        data_dir = data_dir.display(),
    )
}

/// The live server "pulse" injected into the chat context (spec 067 Phase 4)
/// so the AI answers with the authority of something that lives on the box, not
/// a config recital. Carries the host's actual defensive posture and who is
/// attacking right now. Empty when there is nothing live to report.
pub(crate) fn live_server_context(
    posture: &crate::posture::HostPosture,
    attacker_profiles: &std::collections::HashMap<String, crate::attacker_intel::AttackerProfile>,
    baseline: &crate::baseline::BaselineStore,
) -> String {
    let mut body = String::new();
    if let Some(p) = crate::posture::ai_context_line(posture) {
        body.push_str(&format!("Host posture: {p}\n"));
    }
    let mut atk: Vec<(&str, u8)> = attacker_profiles
        .iter()
        .map(|(ip, p)| (ip.as_str(), p.risk_score))
        .filter(|(_, r)| *r > 0)
        .collect();
    atk.sort_by(|a, b| b.1.cmp(&a.1));
    let top: Vec<String> = atk
        .iter()
        .take(5)
        .map(|(ip, r)| format!("{ip} (risk {r})"))
        .collect();
    if !top.is_empty() {
        body.push_str(&format!(
            "Top attackers tracked right now: {}\n",
            top.join(", ")
        ));
    }

    // Baseline: what is normal for THIS host, and what stood out lately. The
    // resident's "this is unusual for us" sense. Skipped on a brand-new store
    // with nothing learned and no anomalies, so the pulse stays empty until
    // there is something real to report.
    if baseline.is_mature()
        || baseline.total_observations() > 0
        || !baseline.recent_anomalies.is_empty()
    {
        let maturity = if baseline.is_mature() {
            "trained".to_string()
        } else {
            format!("learning (day {})", baseline.training_days())
        };
        body.push_str(&format!(
            "Baseline: {maturity}, {} events learned",
            baseline.total_observations()
        ));
        let unusual: Vec<String> = baseline
            .recent_anomalies
            .iter()
            .rev()
            .take(3)
            .map(|a| a.description.clone())
            .collect();
        if !unusual.is_empty() {
            body.push_str(&format!(
                "; unusual for this host lately: {}",
                unusual.join("; ")
            ));
        }
        body.push('\n');
    }

    if body.is_empty() {
        String::new()
    } else {
        format!("=== LIVE SERVER PULSE ===\n{}", body.trim_end())
    }
}

/// Answer-style guide prepended to the persona for operator chat (spec 067
/// Phase 5). The chat context already carries the live pulse + cases, but even
/// a capable model (gpt-5.x) answered "just the usual scanners" because nothing
/// told it HOW to answer. This makes it reply like the warden that lives on the
/// box: specific, evidence-led, never vague filler.
pub(crate) const CHAT_ANSWER_GUIDE: &str = "You are the Inner Warden security agent that lives on this server. Answer the operator like the resident who watches this exact box, not a generic assistant.\n\
- Be specific and concrete: cite the real data below by name. When asked how the server is, name the actual top attacker IPs and their risk scores, state the host's real posture, and call out anything unusual versus this host's baseline.\n\
- If it is quiet, say WHY it is quiet (for example: the scanners are low-risk SSH probes the host's PasswordAuthentication=no already refuses; nothing touched a real service; baseline normal). Quiet is a conclusion you justify, not a shrug.\n\
- Never answer with vague filler like \"just the usual scanners\" without the specifics behind it. Lead with the bottom line, then the evidence.\n\
- Be confident and brief.";

/// Build the chat persona: the answer-style guide, plus the operator's
/// configured personality when one is set.
pub(crate) fn chat_persona(personality: &str) -> String {
    if personality.trim().is_empty() {
        CHAT_ANSWER_GUIDE.to_string()
    } else {
        format!("{CHAT_ANSWER_GUIDE}\n\n{}", personality.trim())
    }
}

/// Merge a persona string, the runtime snapshot, recent incidents, and recent
/// decisions into one system prompt. Empty-string inputs are skipped so the
/// prompt never carries dangling "RECENT INCIDENTS:" headers with no body.
/// Centralised here so every chat surface (Telegram bot, dashboard briefing,
/// dashboard explain) composes the same prompt shape.
pub(crate) fn compose_system_prompt(
    persona: &str,
    runtime_snapshot: &str,
    recent_incidents: &str,
    recent_decisions: &str,
) -> String {
    let mut out = String::with_capacity(
        persona.len()
            + runtime_snapshot.len()
            + recent_incidents.len()
            + recent_decisions.len()
            + 128,
    );
    out.push_str(persona.trim_end());
    if !runtime_snapshot.is_empty() {
        out.push_str("\n\n");
        out.push_str(runtime_snapshot.trim_end());
    }
    if !recent_incidents.is_empty() {
        out.push_str("\n\nRECENT INCIDENTS:\n");
        out.push_str(recent_incidents.trim_end());
    }
    if !recent_decisions.is_empty() {
        out.push_str("\n\nRECENT DECISIONS:\n");
        out.push_str(recent_decisions.trim_end());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::types::Node;

    #[test]
    fn incident_detector_parses_prefix() {
        assert_eq!(
            incident_detector("ssh_bruteforce:1.2.3.4:abc"),
            "ssh_bruteforce"
        );
        assert_eq!(incident_detector("singleword"), "singleword");
    }

    #[test]
    fn guardian_mode_maps_responder_state() {
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = false;
        assert!(matches!(guardian_mode(&cfg), telegram::GuardianMode::Watch));

        cfg.responder.enabled = true;
        cfg.responder.dry_run = true;
        assert!(matches!(
            guardian_mode(&cfg),
            telegram::GuardianMode::DryRun
        ));

        cfg.responder.dry_run = false;
        assert!(matches!(guardian_mode(&cfg), telegram::GuardianMode::Guard));
    }

    #[test]
    fn apply_guardian_mode_sets_responder_flags() {
        let mut cfg = config::AgentConfig::default();

        apply_guardian_mode(&mut cfg, telegram::GuardianMode::Guard);
        assert!(
            cfg.responder.enabled && !cfg.responder.dry_run,
            "Guard = on + live"
        );
        // round-trip through guardian_mode confirms consistency
        assert!(matches!(guardian_mode(&cfg), telegram::GuardianMode::Guard));

        apply_guardian_mode(&mut cfg, telegram::GuardianMode::DryRun);
        assert!(
            cfg.responder.enabled && cfg.responder.dry_run,
            "DryRun = on + simulated"
        );
        assert!(matches!(
            guardian_mode(&cfg),
            telegram::GuardianMode::DryRun
        ));

        apply_guardian_mode(&mut cfg, telegram::GuardianMode::Watch);
        assert!(!cfg.responder.enabled, "Watch = responder off");
        assert!(matches!(guardian_mode(&cfg), telegram::GuardianMode::Watch));
    }

    #[test]
    fn persist_responder_mode_is_format_preserving_and_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        // A config with a comment + an unrelated section that must survive.
        std::fs::write(
            &path,
            "# my agent\n[responder]\nenabled = false\ndry_run = true\nblock_backend = \"ufw\"\n\n[ai]\nenabled = true\n",
        )
        .unwrap();

        persist_responder_mode(&path, true, false).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("# my agent"),
            "comment preserved: {written}"
        );
        assert!(
            written.contains("block_backend = \"ufw\""),
            "sibling key preserved"
        );
        assert!(written.contains("[ai]"), "unrelated section preserved");

        // Re-parse and confirm the two keys flipped.
        let reparsed: config::AgentConfig = toml::from_str(&written).unwrap();
        assert!(reparsed.responder.enabled);
        assert!(!reparsed.responder.dry_run);
    }

    #[test]
    fn apply_setting_change_actuates_profile_and_sensitivity() {
        use crate::config::ChannelFilterLevel;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        std::fs::write(&path, "# cfg\n[telegram]\nuser_profile = \"technical\"\n").unwrap();
        let mut cfg = config::AgentConfig::default();

        // Profile flips the key + persists.
        let label =
            apply_setting_change(&mut cfg, &crate::SettingChange::Profile(true), Some(&path));
        assert_eq!(label.as_deref(), Some("profile=simple"));
        assert_eq!(cfg.telegram.user_profile, "simple");
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("# cfg"), "comment preserved");
        assert!(
            written.contains("user_profile = \"simple\""),
            "persisted: {written}"
        );

        // Sensitivity maps quiet->Critical + persists the lowercase token.
        let l2 = apply_setting_change(
            &mut cfg,
            &crate::SettingChange::Sensitivity("quiet".to_string()),
            Some(&path),
        );
        assert_eq!(l2.as_deref(), Some("sensitivity=quiet"));
        assert_eq!(
            cfg.telegram.channel_notifications.notification_level,
            ChannelFilterLevel::Critical
        );
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("notification_level = \"critical\""));

        // Unknown sensitivity word changes nothing (returns None).
        let before = cfg.telegram.channel_notifications.notification_level;
        let l3 = apply_setting_change(
            &mut cfg,
            &crate::SettingChange::Sensitivity("loud".to_string()),
            Some(&path),
        );
        assert!(l3.is_none(), "unknown sensitivity is rejected");
        assert_eq!(
            cfg.telegram.channel_notifications.notification_level,
            before
        );
    }

    #[test]
    fn sensitivity_to_filter_maps_the_three_words() {
        use crate::config::ChannelFilterLevel as L;
        assert_eq!(sensitivity_to_filter("quiet"), Some(L::Critical));
        assert_eq!(sensitivity_to_filter("NORMAL"), Some(L::Actionable));
        assert_eq!(sensitivity_to_filter("verbose"), Some(L::All));
        assert_eq!(sensitivity_to_filter("nonsense"), Option::None);
    }

    #[test]
    fn take_and_apply_pending_mode_applies_persists_and_noops_when_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        std::fs::write(&path, "[responder]\nenabled = false\ndry_run = true\n").unwrap();
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = false;
        cfg.responder.dry_run = true;

        // Empty queue → no-op, returns None, file untouched logic.
        let mut pending: Option<telegram::GuardianMode> = None;
        assert!(take_and_apply_pending_mode(&mut cfg, &mut pending, Some(&path)).is_none());

        // Queued Guard → applied to cfg, persisted, queue drained.
        pending = Some(telegram::GuardianMode::Guard);
        let applied = take_and_apply_pending_mode(&mut cfg, &mut pending, Some(&path));
        assert!(matches!(applied, Some(telegram::GuardianMode::Guard)));
        assert!(pending.is_none(), "queue drained");
        assert!(
            cfg.responder.enabled && !cfg.responder.dry_run,
            "cfg flipped to Guard"
        );
        let reparsed: config::AgentConfig =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(
            reparsed.responder.enabled && !reparsed.responder.dry_run,
            "persisted"
        );

        // No config path → applies in memory, skips persist (no panic).
        pending = Some(telegram::GuardianMode::Watch);
        assert!(take_and_apply_pending_mode(&mut cfg, &mut pending, None).is_some());
        assert!(
            !cfg.responder.enabled,
            "Watch applied without a config path"
        );
    }

    #[test]
    fn persist_responder_mode_creates_section_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        std::fs::write(&path, "[ai]\nenabled = true\n").unwrap();
        persist_responder_mode(&path, true, true).unwrap();
        let reparsed: config::AgentConfig =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(reparsed.responder.enabled && reparsed.responder.dry_run);
    }

    #[test]
    fn build_agent_context_includes_runtime_snapshot() {
        let mut cfg = config::AgentConfig::default();
        cfg.ai.enabled = true;
        cfg.ai.provider = "openai".to_string();
        cfg.ai.model = "gpt-5".to_string();
        cfg.responder.enabled = true;
        cfg.responder.dry_run = false;
        cfg.responder.block_backend = "ufw".to_string();
        cfg.responder.allowed_skills = vec!["block-ip-ufw".to_string(), "honeypot".to_string()];
        cfg.telegram.enabled = true;
        cfg.abuseipdb.enabled = true;
        cfg.geoip.enabled = true;
        cfg.slack.enabled = true;
        cfg.cloudflare.enabled = true;

        let mut graph = knowledge_graph::KnowledgeGraph::new();
        let now = chrono::Utc::now();
        graph.add_node(Node::Incident {
            incident_id: "ssh_bruteforce:198.51.100.10:1".to_string(),
            detector: "ssh_bruteforce".to_string(),
            severity: "high".to_string(),
            title: "SSH brute-force".to_string(),
            summary: "many attempts".to_string(),
            ts: now,
            mitre_ids: vec![],
            decision: Some("block_ip".to_string()),
            confidence: Some(0.95),
            decision_reason: Some("clear brute force".to_string()),
            decision_target: Some("198.51.100.10".to_string()),
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        graph.add_node(Node::Incident {
            incident_id: "port_scan:198.51.100.11:2".to_string(),
            detector: "port_scan".to_string(),
            severity: "medium".to_string(),
            title: "Port scan".to_string(),
            summary: "multiple ports".to_string(),
            ts: now,
            mitre_ids: vec![],
            decision: None,
            confidence: None,
            decision_reason: None,
            decision_target: None,
            auto_executed: false,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        });
        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));

        // "actions taken" now reads the canonical decisions log (not the KG
        // node count), so seed one decision for today's date.
        let dir = tempfile::tempdir().expect("tempdir");
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        std::fs::write(
            dir.path().join(format!("decisions-{today}.jsonl")),
            "{\"action_type\":\"block_ip\"}\n",
        )
        .expect("write decisions log");

        let context = build_agent_context(&cfg, dir.path(), &kg);

        assert!(context.contains("INNERWARDEN SYSTEM STATE"));
        assert!(context.contains("Mode: 🟢 GUARD"));
        assert!(context.contains("intrusion attempts, 1 actions taken"));
        assert!(context.contains("AI analysis: ENABLED - provider=openai, model=gpt-5"));
        assert!(context.contains("Telegram bot: ENABLED"));
        assert!(context.contains("Cloudflare edge blocking: ENABLED"));
        assert!(context.contains("Allowed skills: block-ip-ufw, honeypot"));
    }

    #[test]
    fn compose_system_prompt_includes_persona_only_when_others_empty() {
        let out = compose_system_prompt("persona-body", "", "", "");
        assert_eq!(out, "persona-body");
    }

    #[test]
    fn compose_system_prompt_appends_runtime_when_present() {
        let out = compose_system_prompt("p", "SNAP", "", "");
        assert!(out.starts_with("p"));
        assert!(out.contains("SNAP"));
        assert!(!out.contains("RECENT INCIDENTS"));
        assert!(!out.contains("RECENT DECISIONS"));
    }

    #[test]
    fn compose_system_prompt_labels_recent_sections() {
        let out = compose_system_prompt(
            "p",
            "SNAP",
            "[high] title - summary",
            "- block_ip 1.2.3.4 (auto)",
        );
        assert!(out.contains("RECENT INCIDENTS:\n[high] title - summary"));
        assert!(out.contains("RECENT DECISIONS:\n- block_ip 1.2.3.4 (auto)"));
        // Sections must appear in the stable order persona -> snapshot -> incidents -> decisions.
        let idx_snap = out.find("SNAP").unwrap();
        let idx_inc = out.find("RECENT INCIDENTS").unwrap();
        let idx_dec = out.find("RECENT DECISIONS").unwrap();
        assert!(idx_snap < idx_inc && idx_inc < idx_dec);
    }

    #[test]
    fn compose_system_prompt_omits_headers_for_empty_sections() {
        // An empty decisions string should not leave a dangling "RECENT
        // DECISIONS:" header in the prompt.
        let out = compose_system_prompt("p", "", "[high] x - y", "");
        assert!(out.contains("RECENT INCIDENTS"));
        assert!(!out.contains("RECENT DECISIONS"));
    }

    #[test]
    fn test_incident_detector_edge_cases() {
        assert_eq!(incident_detector(""), "");
        assert_eq!(incident_detector(":"), "");
        assert_eq!(incident_detector("ssh:brute:force"), "ssh");
    }

    #[test]
    fn test_guardian_mode_default_state() {
        let cfg = config::AgentConfig::default();
        // default responder.enabled is false
        assert!(matches!(guardian_mode(&cfg), telegram::GuardianMode::Watch));
    }

    #[test]
    fn test_build_agent_context_all_disabled() {
        let mut cfg = config::AgentConfig::default();
        // Explicitly disable things that might be enabled by default in AgentConfig::default()
        cfg.firmware.enabled = false;
        cfg.hypervisor.enabled = false;
        cfg.killchain.enabled = false;
        cfg.dna.enabled = false;
        cfg.shield.enabled = false;
        cfg.narrative.enabled = false;
        cfg.briefing.enabled = false;

        let graph = knowledge_graph::KnowledgeGraph::new();
        let kg = std::sync::Arc::new(std::sync::RwLock::new(graph));

        let context = build_agent_context(&cfg, std::path::Path::new("/var/lib/innerwarden"), &kg);

        assert!(context.contains("Mode: 🔵 WATCH"));
        assert!(context.contains("AI analysis: DISABLED"));
        assert!(context.contains("Telegram bot: DISABLED"));
        assert!(context.contains("AbuseIPDB enrichment: DISABLED"));
        assert!(context.contains("GeoIP enrichment: DISABLED"));
        assert!(context.contains("Slack notifications: DISABLED"));
        assert!(context.contains("Cloudflare edge blocking: DISABLED"));
    }

    #[test]
    fn live_server_context_carries_posture_and_top_attackers_sorted() {
        use crate::posture::{sshd, HostPosture};
        let mut p = HostPosture::default();
        p.sshd.probe_state = sshd::ProbeState::Ok;
        p.sshd.password_authentication = sshd::SshdToggle::No;

        let mut profiles = std::collections::HashMap::new();
        let mut hi = crate::attacker_intel::new_profile("45.148.10.99", chrono::Utc::now());
        hi.risk_score = 90;
        profiles.insert("45.148.10.99".to_string(), hi);
        let mut lo = crate::attacker_intel::new_profile("1.2.3.4", chrono::Utc::now());
        lo.risk_score = 50;
        profiles.insert("1.2.3.4".to_string(), lo);

        let ctx = live_server_context(&p, &profiles, &crate::baseline::BaselineStore::new());
        assert!(ctx.contains("LIVE SERVER PULSE"));
        assert!(
            ctx.contains("PasswordAuthentication=No"),
            "posture must be carried"
        );
        assert!(ctx.contains("45.148.10.99 (risk 90)"));
        let pos_hi = ctx.find("45.148.10.99").unwrap();
        let pos_lo = ctx.find("1.2.3.4").unwrap();
        assert!(pos_hi < pos_lo, "higher-risk attacker listed first");
    }

    #[test]
    fn live_server_context_empty_when_nothing_live() {
        // Default posture (Pending probe), no attackers, fresh baseline.
        let p = crate::posture::HostPosture::default();
        let profiles = std::collections::HashMap::new();
        let baseline = crate::baseline::BaselineStore::new();
        assert!(live_server_context(&p, &profiles, &baseline).is_empty());
    }

    #[test]
    fn live_server_context_surfaces_baseline_anomalies() {
        // Spec 067 Phase 4b: the pulse carries "what is unusual for THIS host".
        let p = crate::posture::HostPosture::default();
        let profiles = std::collections::HashMap::new();
        let mut baseline = crate::baseline::BaselineStore::new();
        let report = crate::baseline::AnomalyReport {
            anomaly_type: crate::baseline::AnomalyType::ProcessLineage,
            description: "nginx spawned a shell (never seen before)".to_string(),
            expected: "nginx -> worker".to_string(),
            observed: "nginx -> sh".to_string(),
            confidence: 0.9,
            severity: innerwarden_core::event::Severity::High,
        };
        baseline.record_anomaly(&report, None);

        let ctx = live_server_context(&p, &profiles, &baseline);
        assert!(ctx.contains("LIVE SERVER PULSE"));
        assert!(ctx.contains("Baseline:"), "baseline line missing");
        assert!(
            ctx.contains("unusual for this host lately: nginx spawned a shell"),
            "baseline anomaly must surface; got:\n{ctx}"
        );
    }

    #[test]
    fn chat_persona_uses_guide_alone_when_personality_empty() {
        let p = chat_persona("   ");
        assert!(p.contains("lives on this server"), "guide must be present");
        assert!(
            p.contains("just the usual scanners"),
            "guide must forbid vague filler"
        );
    }

    #[test]
    fn chat_persona_combines_guide_and_personality() {
        let p = chat_persona("Speak like a laconic ops engineer.");
        assert!(p.contains("lives on this server"), "guide must be present");
        assert!(
            p.contains("laconic ops engineer"),
            "configured personality must be kept"
        );
    }
}
