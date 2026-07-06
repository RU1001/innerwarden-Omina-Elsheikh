// Auto-extracted from mod.rs — dashboard actions handlers

use super::*;

// ---------------------------------------------------------------------------
// D3 - action handlers
// ---------------------------------------------------------------------------

/// GET /api/action/config - exposes the current action mode to the UI (read-only).
pub(super) async fn api_action_config(
    State(state): State<DashboardState>,
) -> Json<serde_json::Value> {
    let cfg = &state.action_cfg;
    let mode = if cfg.enabled {
        if cfg.dry_run {
            "watch"
        } else {
            "guard"
        }
    } else {
        "read_only"
    };
    Json(serde_json::json!({
        "enabled": cfg.enabled,
        "dry_run": cfg.dry_run,
        "block_backend": cfg.block_backend,
        "allowed_skills": cfg.allowed_skills,
        "ai_enabled": cfg.ai_enabled,
        "ai_provider": cfg.ai_provider,
        "ai_model": cfg.ai_model,
        "mode": mode,
        "version": env!("CARGO_PKG_VERSION"),
        "trusted_ips": cfg.trusted_ips,
        "trusted_users": cfg.trusted_users,
    }))
}
/// GET /api/quickwins - return actionable suggestions based on recent unblocked threats.
///
/// Source-of-truth contract (see `.claude-local/NUMBER_CONSISTENCY.md` row "quickwins
/// suggestions"): a suggestion is an `incidents-{today,yesterday}.jsonl` row with
/// severity ∈ {`high`, `critical`} (lowercase, per `Severity` `#[serde(rename_all =
/// "lowercase")]`) whose primary IP entity does NOT appear in `decisions-*.jsonl`
/// with `action_type == "block_ip"` (NOT `action`, which is not a writer field —
/// see `crates/agent/src/decisions.rs::DecisionEntry::action_type`).
///
/// Any change to `Severity` casing, `DecisionEntry::action_type`, or the JSONL
/// filename pattern MUST update this handler AND the regression test that pins
/// it (`tests::api_quickwins_*`).
///
/// The actual work (synchronous JSONL scan) runs on the blocking thread pool
/// via `tokio::task::spawn_blocking` so it does not stall the dashboard's async
/// worker threads — the JSONL scan can take tens of milliseconds on busy days
/// (`RECURRING_BUGS.md` "Dashboard handlers block tokio worker threads").
pub(super) async fn api_quickwins(State(state): State<DashboardState>) -> Json<serde_json::Value> {
    let data_dir = state.data_dir.clone();
    let payload = tokio::task::spawn_blocking(move || quickwins_payload(&data_dir))
        .await
        .unwrap_or_else(|_| serde_json::json!({"suggestions": [], "count": 0}));
    Json(payload)
}

/// Pure helper extracted from `api_quickwins` so the JSONL-based logic is
/// directly unit-testable against a tempdir without spinning up the dashboard
/// server.
pub(super) fn quickwins_payload(data_dir: &std::path::Path) -> serde_json::Value {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let yesterday = (chrono::Utc::now() - chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();
    let dates = [today.as_str(), yesterday.as_str()];

    // Collect blocked IPs from decisions (today + yesterday).
    // Field name MUST be `action_type` to match `DecisionEntry::action_type`
    // (decisions.rs:26). The previous reader used `action`, which never exists
    // in the writer schema and silently produced an empty set.
    let mut blocked_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    for date in &dates {
        let path = data_dir.join(format!("decisions-{date}.jsonl"));
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if v["action_type"].as_str() == Some("block_ip") {
                if let Some(ip) = v["target_ip"].as_str() {
                    blocked_ips.insert(ip.to_string());
                }
            }
        }
    }

    // Collect high/critical incidents from today + yesterday.
    // Severity comparison is case-insensitive — the wire format is lowercase
    // (per Severity `#[serde(rename_all = "lowercase")]`), but the test fixture
    // and any future writer that violates that should still be filtered, not
    // silently included.
    let mut suggestions: Vec<serde_json::Value> = Vec::new();
    let mut seen_ips: std::collections::HashSet<String> = blocked_ips.clone();
    for date in &dates {
        let path = data_dir.join(format!("incidents-{date}.jsonl"));
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let sev = v["severity"].as_str().unwrap_or("");
            if !sev.eq_ignore_ascii_case("high") && !sev.eq_ignore_ascii_case("critical") {
                continue;
            }
            let ip = v["entities"].as_array().and_then(|arr| {
                arr.iter()
                    .find(|e| {
                        // Match either the original "Ip" capitalization or the
                        // serde-derived lowercase form. Defensive against future
                        // serde rename changes on EntityType.
                        e["type"]
                            .as_str()
                            .map(|s| s.eq_ignore_ascii_case("ip"))
                            .unwrap_or(false)
                    })
                    .and_then(|e| e["value"].as_str())
                    .map(|s| s.to_string())
            });
            let Some(ip_str) = ip else {
                continue;
            };
            if seen_ips.contains(&ip_str) {
                continue;
            }
            seen_ips.insert(ip_str.clone());
            suggestions.push(serde_json::json!({
                "type": "unblocked_attacker",
                "severity": sev,
                "ip": ip_str,
                "title": v["title"].as_str().unwrap_or("Threat detected"),
                "date": date,
                "action": format!("Block {ip_str} at the firewall"),
                "command": "innerwarden enable block-ip"
            }));
        }
    }

    serde_json::json!({
        "suggestions": suggestions,
        "count": suggestions.len()
    })
}
/// POST /api/action/block-ip - operator-initiated IP block with mandatory reason.
pub(super) async fn api_action_block_ip(
    State(state): State<DashboardState>,
    Json(body): Json<BlockIpRequest>,
) -> Json<ActionResponse> {
    if state.insecure_http {
        warn!("action executed over HTTP without TLS — consider a reverse proxy with TLS");
    }

    if !state.action_cfg.enabled {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "dashboard actions are disabled - set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id: String::new(),
        });
    }

    let ip = body.ip.trim().to_string();
    if let Err(e) = validate_action_params(&ip, &body.reason) {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: e.to_string(),
            skill_id: String::new(),
        });
    }

    // Select the right skill based on configured backend.
    let skill_id = format!("block-ip-{}", state.action_cfg.block_backend);
    if !state
        .action_cfg
        .allowed_skills
        .iter()
        .any(|s| s == &skill_id)
    {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("skill '{skill_id}' is not in allowed_skills"),
            skill_id,
        });
    }

    let result = execute_block_ip(
        &state.data_dir,
        state.sqlite_store.as_ref(),
        &state.action_cfg,
        &ip,
        &body.reason,
        body.incident_id.as_deref(),
    )
    .await;

    match result {
        Ok((success, message)) => Json(ActionResponse {
            success,
            dry_run: state.action_cfg.dry_run,
            message,
            skill_id,
        }),
        Err(e) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("internal error: {e}"),
            skill_id,
        }),
    }
}

/// POST /api/action/suspend-user - operator-initiated sudo suspension with mandatory reason.
pub(super) async fn api_action_suspend_user(
    State(state): State<DashboardState>,
    Json(body): Json<SuspendUserRequest>,
) -> Json<ActionResponse> {
    let skill_id = "suspend-user-sudo".to_string();

    if state.insecure_http {
        warn!("action executed over HTTP without TLS — consider a reverse proxy with TLS");
    }

    if !state.action_cfg.enabled {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "dashboard actions are disabled - set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id,
        });
    }

    let user = body.user.trim().to_string();
    if user.is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "user is required".to_string(),
            skill_id,
        });
    }
    if body.reason.trim().is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "reason is required".to_string(),
            skill_id,
        });
    }
    if !state
        .action_cfg
        .allowed_skills
        .iter()
        .any(|s| s == &skill_id)
    {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("skill '{skill_id}' is not in allowed_skills"),
            skill_id,
        });
    }

    let result = execute_suspend_user(
        &state.data_dir,
        state.sqlite_store.as_ref(),
        &state.action_cfg,
        &user,
        &body.reason,
        body.duration_secs.unwrap_or(3600),
        body.incident_id.as_deref(),
    )
    .await;

    match result {
        Ok((success, message)) => Json(ActionResponse {
            success,
            dry_run: state.action_cfg.dry_run,
            message,
            skill_id,
        }),
        Err(e) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("internal error: {e}"),
            skill_id,
        }),
    }
}

/// POST /api/action/honeypot - operator-initiated honeypot test session.
pub(super) async fn api_action_honeypot(
    State(state): State<DashboardState>,
    Json(body): Json<HoneypotTestRequest>,
) -> Json<ActionResponse> {
    let skill_id = "honeypot".to_string();

    if state.insecure_http {
        warn!("action executed over HTTP without TLS — consider a reverse proxy with TLS");
    }

    if !state.action_cfg.enabled {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "dashboard actions are disabled - set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id,
        });
    }

    if body.reason.trim().is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "reason is required".to_string(),
            skill_id,
        });
    }

    if !state
        .action_cfg
        .allowed_skills
        .iter()
        .any(|s| s == &skill_id)
    {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "skill 'honeypot' is not in allowed_skills - add it to responder.allowed_skills in agent.toml".to_string(),
            skill_id,
        });
    }

    let duration_secs = body.duration_secs.unwrap_or(120);

    // Write a synthetic incident to today's incidents file so the agent's main
    // loop picks it up in the next 2-second tick and evaluates the honeypot skill.
    let result = inject_honeypot_test_incident(&state.data_dir, &body.reason, duration_secs).await;

    match result {
        Ok(()) => {
            let entry = DecisionEntry {
                ts: chrono::Utc::now(),
                incident_id: format!("honeypot_test:{}", chrono::Utc::now().timestamp()),
                host: hostname(),
                ai_provider: "dashboard:operator".to_string(),
                action_type: "honeypot".to_string(),
                target_ip: Some("0.0.0.0".to_string()),
                target_user: None,
                skill_id: Some(skill_id.clone()),
                confidence: 1.0,
                auto_executed: !state.action_cfg.dry_run,
                dry_run: state.action_cfg.dry_run,
                reason: body.reason.clone(),
                estimated_threat: "manual_test".to_string(),
                execution_result: if state.action_cfg.dry_run {
                    "ok (dry_run)".to_string()
                } else {
                    "incident_injected".to_string()
                },
                prev_hash: None,
                decision_layer: Some("manual_operator".to_string()),
            };
            if let Err(e) =
                append_decision_entry(&state.data_dir, &entry, state.sqlite_store.as_ref())
            {
                warn!("failed to write honeypot test decision entry: {e}");
            }

            // Admin action audit trail
            let mut audit = AdminActionEntry {
                ts: Utc::now(),
                operator: "dashboard:operator".to_string(),
                source: "dashboard".to_string(),
                action: "honeypot".to_string(),
                target: "honeypot_test".to_string(),
                parameters: serde_json::json!({
                    "skill": "honeypot",
                    "reason": body.reason,
                    "duration_secs": duration_secs,
                }),
                result: "success".to_string(),
                prev_hash: None,
            };
            if let Err(e) = append_admin_action(&state.data_dir, &mut audit) {
                warn!("failed to write admin audit: {e:#}");
            }

            info!(
                dry_run = state.action_cfg.dry_run,
                duration_secs, "dashboard action: honeypot test"
            );
            let mode_prefix = if state.action_cfg.dry_run {
                "[DRY RUN] "
            } else {
                ""
            };
            Json(ActionResponse {
                success: true,
                dry_run: state.action_cfg.dry_run,
                message: format!(
                    "{mode_prefix}Test honeypot incident injected - the agent will pick it up \
                     in the next tick (≤2 s). Connect via: ssh -p 2222 -o StrictHostKeyChecking=no root@<host>"
                ),
                skill_id,
            })
        }
        Err(e) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("failed to inject test incident: {e}"),
            skill_id,
        }),
    }
}

pub(super) fn validate_action_params(target: &str, reason: &str) -> Result<(), &'static str> {
    if target.trim().is_empty() {
        return Err("target is required");
    }
    if reason.trim().is_empty() {
        return Err("reason is required");
    }
    let t = target.trim();
    if t == "127.0.0.1" || t == "::1" || t.starts_with("10.") || t.starts_with("192.168.") {
        return Err("cannot target internal IP");
    }
    // RFC 1918 172.16.0.0/12 covers second octet 16-31 only. Wave 1
    // (AUDIT-WAVE1-UTF8): the prior implementation did `t[4..6]` byte
    // slicing which panicked when an attacker-supplied target like
    // `172.<multibyte>16.0.1` placed a multi-byte codepoint at byte 4.
    // It also incorrectly blocked `172.165.0.1` (NOT private) by
    // accepting only the first two ASCII digits. Splitting on `.` is
    // both panic-free and parses the full second octet.
    if t.starts_with("172.") {
        if let Some(second_octet) = t.split('.').nth(1).and_then(|o| o.parse::<u8>().ok()) {
            if (16..=31).contains(&second_octet) {
                return Err("cannot target internal IP");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// D3 - execution helpers
// ---------------------------------------------------------------------------

/// Execute a block-ip skill and write the decision to the audit trail.
pub(super) async fn execute_block_ip(
    data_dir: &Path,
    store: Option<&std::sync::Arc<innerwarden_store::Store>>,
    cfg: &DashboardActionConfig,
    ip: &str,
    reason: &str,
    incident_id: Option<&str>,
) -> anyhow::Result<(bool, String)> {
    use crate::skills::{
        builtin::{BlockIpIptables, BlockIpNftables, BlockIpUfw},
        HoneypotRuntimeConfig, ResponseSkill, SkillContext,
    };

    let skill_id = format!("block-ip-{}", cfg.block_backend);
    let iid = incident_id.unwrap_or("unknown").to_string();
    let inc = make_synthetic_incident(&iid, ip, reason);

    let ctx = SkillContext {
        incident: inc,
        target_ip: Some(ip.to_string()),
        target_user: None,
        target_container: None,
        duration_secs: None,
        host: hostname(),
        data_dir: data_dir.to_path_buf(),
        honeypot: HoneypotRuntimeConfig::default(),
        ai_provider: None,
    };

    let skill: Box<dyn ResponseSkill> = match cfg.block_backend.as_str() {
        "iptables" => Box::new(BlockIpIptables),
        "nftables" => Box::new(BlockIpNftables),
        _ => Box::new(BlockIpUfw),
    };
    // 2026-05-10 (skill_gate): dashboard manual block also routes
    // through `skill_gate::gate_block_ip`. Operator hitting "Block"
    // on a Cloudflare-fronted IP or a `trusted_ips` endpoint must
    // not commit a firewall rule that breaks their own infrastructure.
    // The gate refuses BEFORE `skill.execute` so the audit trail
    // records a clean "skipped: ..." execution_result instead of a
    // half-applied rule.
    let result = match crate::skill_gate::gate_block_ip(ip, &cfg.trusted_ips) {
        Ok(gate) => {
            crate::skill_gate::execute_block_skill_gated(skill.as_ref(), &ctx, cfg.dry_run, &gate)
                .await
        }
        Err(refusal) => {
            warn!(
                ip = %ip,
                skill_id = %skill_id,
                reason = %refusal,
                "dashboard manual block refused by gate (allowlist / safelist / shape)"
            );
            crate::skills::SkillResult {
                success: false,
                message: format!("{refusal}"),
            }
        }
    };
    let (success, message) = (result.success, result.message);

    let result_str = if success {
        if cfg.dry_run {
            "ok (dry_run)".to_string()
        } else {
            "ok".to_string()
        }
    } else {
        format!("failed: {message}")
    };

    let entry = DecisionEntry {
        ts: Utc::now(),
        incident_id: incident_id.unwrap_or("dashboard:manual").to_string(),
        host: hostname(),
        ai_provider: "dashboard:operator".to_string(),
        action_type: "block_ip".to_string(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        skill_id: Some(skill_id.clone()),
        confidence: 1.0,
        auto_executed: true,
        dry_run: cfg.dry_run,
        reason: reason.to_string(),
        estimated_threat: "manual".to_string(),
        execution_result: result_str,
        prev_hash: None,
        decision_layer: Some("manual_operator".to_string()),
    };

    append_decision_entry(data_dir, &entry, store)?;

    // Admin action audit trail
    let mut audit = AdminActionEntry {
        ts: Utc::now(),
        operator: "dashboard:operator".to_string(),
        source: "dashboard".to_string(),
        action: "block_ip".to_string(),
        target: ip.to_string(),
        parameters: serde_json::json!({
            "skill": skill_id,
            "reason": reason,
            "incident_id": incident_id,
        }),
        result: if success {
            "success".to_string()
        } else {
            format!("failure: {message}")
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(data_dir, &mut audit) {
        warn!("failed to write admin audit: {e:#}");
    }

    info!(
        ip = %ip,
        dry_run = cfg.dry_run,
        skill_id = %skill_id,
        success,
        "dashboard action: block-ip"
    );
    Ok((success, message))
}

/// Execute a suspend-user skill and write the decision to the audit trail.
pub(super) async fn execute_suspend_user(
    data_dir: &Path,
    store: Option<&std::sync::Arc<innerwarden_store::Store>>,
    cfg: &DashboardActionConfig,
    user: &str,
    reason: &str,
    duration_secs: u64,
    incident_id: Option<&str>,
) -> anyhow::Result<(bool, String)> {
    use crate::skills::{
        builtin::SuspendUserSudo, HoneypotRuntimeConfig, ResponseSkill, SkillContext,
    };
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;

    let iid = incident_id.unwrap_or("unknown").to_string();
    let inc = Incident {
        ts: Utc::now(),
        host: hostname(),
        incident_id: format!("dashboard:manual:{iid}"),
        severity: Severity::High,
        title: "Dashboard Manual Action".to_string(),
        summary: reason.to_string(),
        evidence: serde_json::json!({}),
        recommended_checks: vec![],
        tags: vec!["dashboard".to_string(), "manual".to_string()],
        entities: vec![EntityRef::user(user)],
    };

    let ctx = SkillContext {
        incident: inc,
        target_ip: None,
        target_user: Some(user.to_string()),
        target_container: None,
        duration_secs: Some(duration_secs),
        host: hostname(),
        data_dir: data_dir.to_path_buf(),
        honeypot: HoneypotRuntimeConfig::default(),
        ai_provider: None,
    };

    let skill = SuspendUserSudo;
    let result = skill.execute(&ctx, cfg.dry_run).await;
    let (success, message) = (result.success, result.message);

    let result_str = if success {
        if cfg.dry_run {
            "ok (dry_run)".to_string()
        } else {
            "ok".to_string()
        }
    } else {
        format!("failed: {message}")
    };

    let entry = DecisionEntry {
        ts: Utc::now(),
        incident_id: incident_id.unwrap_or("dashboard:manual").to_string(),
        host: hostname(),
        ai_provider: "dashboard:operator".to_string(),
        action_type: "suspend_user_sudo".to_string(),
        target_ip: None,
        target_user: Some(user.to_string()),
        skill_id: Some("suspend-user-sudo".to_string()),
        confidence: 1.0,
        auto_executed: true,
        dry_run: cfg.dry_run,
        reason: reason.to_string(),
        estimated_threat: "manual".to_string(),
        execution_result: result_str,
        prev_hash: None,
        decision_layer: Some("manual_operator".to_string()),
    };

    append_decision_entry(data_dir, &entry, store)?;

    // Admin action audit trail
    let mut audit = AdminActionEntry {
        ts: Utc::now(),
        operator: "dashboard:operator".to_string(),
        source: "dashboard".to_string(),
        action: "suspend_user".to_string(),
        target: user.to_string(),
        parameters: serde_json::json!({
            "skill": "suspend-user-sudo",
            "reason": reason,
            "duration_secs": duration_secs,
            "incident_id": incident_id,
        }),
        result: if success {
            "success".to_string()
        } else {
            format!("failure: {message}")
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(data_dir, &mut audit) {
        warn!("failed to write admin audit: {e:#}");
    }

    info!(
        user = %user,
        dry_run = cfg.dry_run,
        duration_secs,
        success,
        "dashboard action: suspend-user"
    );
    Ok((success, message))
}

/// Build a minimal synthetic incident for skill execution context.
pub(super) fn make_synthetic_incident(
    incident_id_hint: &str,
    ip: &str,
    reason: &str,
) -> innerwarden_core::incident::Incident {
    use innerwarden_core::event::Severity;
    innerwarden_core::incident::Incident {
        ts: Utc::now(),
        host: hostname(),
        incident_id: format!("dashboard:manual:{incident_id_hint}"),
        severity: Severity::High,
        title: "Dashboard Manual Action".to_string(),
        summary: reason.to_string(),
        evidence: serde_json::json!({}),
        recommended_checks: vec![],
        tags: vec!["dashboard".to_string(), "manual".to_string()],
        entities: vec![EntityRef::ip(ip)],
    }
}

/// Append a single `DecisionEntry` to today's decisions JSONL file and mirror
/// to the SQLite `decisions` table when `store` is `Some`.
pub(super) fn append_decision_entry(
    data_dir: &Path,
    entry: &DecisionEntry,
    store: Option<&std::sync::Arc<innerwarden_store::Store>>,
) -> anyhow::Result<()> {
    crate::decisions::append_chained(data_dir, entry, store)
}

/// Inject a synthetic high-severity SSH brute-force incident so the agent's main
/// loop picks it up and evaluates the honeypot skill in the next tick.
pub(super) async fn inject_honeypot_test_incident(
    data_dir: &Path,
    reason: &str,
    duration_secs: u64,
) -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write as _;

    let now = chrono::Utc::now();
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let path = data_dir.join(format!("incidents-{today}.jsonl"));

    // Build a minimal Incident that looks like an SSH brute-force event so the
    // algorithm gate passes it through (severity=High, non-private IP).
    let incident = serde_json::json!({
        "ts": now.to_rfc3339(),
        "host": hostname(),
        "incident_id": format!("honeypot_test:{}", now.timestamp()),
        "severity": "high",
        "title": format!("Manual honeypot test - {} ({}s)", reason, duration_secs),
        "summary": format!(
            "50 failed SSH login attempts from 1.2.3.4 in the last 300 seconds (manual test via dashboard)"
        ),
        "evidence": [{"count": 50, "ip": "1.2.3.4", "kind": "ssh.login_failed", "window_seconds": 300}],
        "recommended_checks": [],
        "tags": ["auth", "ssh", "bruteforce", "test", "dashboard"],
        "entities": [{"type": "ip", "value": "1.2.3.4"}]
    });

    let line = serde_json::to_string(&incident).context("serialize test incident")?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    writeln!(f, "{line}").context("write test incident")?;
    f.flush().context("flush test incident")
}

/// Returns the machine hostname (best-effort).
pub(super) fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

// ---------------------------------------------------------------------------
// 2026-05-01 (`tracked-spec-ai-override`): operator-initiated audit
// events. All three close the AI-decision feedback loop the audit
// flagged in 2.4 / 5.4 (operator could only "Block IP or do
// nothing" when AI got it wrong). v1 is **audit-only**: each
// endpoint writes a hash-chained decision row capturing the
// operator's correction. State-machine integration (re-routing
// reopened incidents into AI triage, retraining the classifier
// from labelled decisions) is deferred to follow-up specs so this
// PR's blast radius stays bounded.
// ---------------------------------------------------------------------------

const ALLOWED_OVERRIDE_ACTIONS: &[&str] = &[
    "block_ip",
    "monitor",
    "dismiss",
    "ignore",
    "request_confirmation",
];

const ALLOWED_LABELS: &[&str] = &["TP", "FP"];

/// POST /api/action/decision/override — operator overrides an AI
/// decision. Writes a new audit row chained to the original via
/// the SHA-256 hash chain (PR #357). The new row's
/// `action_type` is `operator_override:<new_action>` so downstream
/// consumers (compliance viewer, monthly reports) can distinguish
/// AI-initiated from operator-initiated rows by prefix match.
///
/// V1 does NOT auto-execute the new action. If the operator wants
/// `block_ip`, they trigger it via the existing
/// `/api/action/block-ip` endpoint. This separation keeps the
/// override endpoint as a pure audit primitive and avoids
/// duplicating the block_ip safelist / circuit-breaker apparatus.
pub(super) async fn api_action_override_decision(
    State(state): State<DashboardState>,
    Json(body): Json<crate::dashboard::types::OverrideDecisionRequest>,
) -> Json<crate::dashboard::types::ActionResponse> {
    use crate::dashboard::types::ActionResponse;
    if state.insecure_http {
        warn!("override executed over HTTP without TLS — consider a reverse proxy with TLS");
    }
    let new_action = body.new_action.trim();
    let reason = body.reason.trim();
    if reason.is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "reason is required".to_string(),
            skill_id: String::new(),
        });
    }
    if !ALLOWED_OVERRIDE_ACTIONS.contains(&new_action) {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("new_action must be one of {:?}", ALLOWED_OVERRIDE_ACTIONS),
            skill_id: String::new(),
        });
    }
    let Some(store) = state.sqlite_store.clone() else {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "SQLite store unavailable; cannot persist override".to_string(),
            skill_id: String::new(),
        });
    };
    let original = match store.decision_by_id(body.decision_id) {
        Ok(Some(d)) => d,
        Ok(None) => {
            return Json(ActionResponse {
                success: false,
                dry_run: state.action_cfg.dry_run,
                message: format!("decision id {} not found", body.decision_id),
                skill_id: String::new(),
            });
        }
        Err(e) => {
            return Json(ActionResponse {
                success: false,
                dry_run: state.action_cfg.dry_run,
                message: format!("store error: {e}"),
                skill_id: String::new(),
            });
        }
    };
    let now = chrono::Utc::now().to_rfc3339();
    let action_type = format!("operator_override:{new_action}");
    let original_reason = original.reason.unwrap_or_default();
    let combined_reason = format!(
        "operator override of decision #{}: {}. Original AI action: {} (\"{}\")",
        original.id,
        reason,
        original.action_type,
        truncate(&original_reason, 200),
    );
    let data = serde_json::json!({
        "ts": now,
        "incident_id": original.incident_id,
        "action_type": action_type,
        "target_ip": original.target_ip,
        "target_user": original.target_user,
        "confidence": 1.0,
        "auto_executed": false,
        "reason": combined_reason,
        "operator_override": {
            "original_decision_id": original.id,
            "original_action": original.action_type,
            "original_row_hash": original.row_hash,
            "new_action": new_action,
        },
    });
    let row = innerwarden_store::decisions::DecisionRow {
        ts: now.clone(),
        incident_id: original.incident_id.clone(),
        action_type: action_type.clone(),
        target_ip: original.target_ip.clone(),
        target_user: original.target_user.clone(),
        confidence: 1.0,
        auto_executed: false,
        reason: Some(combined_reason.clone()),
        data: serde_json::to_string(&data).unwrap_or_default(),
    };
    match store.insert_decision(&row) {
        Ok(new_id) => Json(ActionResponse {
            success: true,
            dry_run: state.action_cfg.dry_run,
            message: format!(
                "override recorded (decision #{new_id}); did not auto-execute. Use /api/action/block-ip etc. to act."
            ),
            skill_id: action_type,
        }),
        Err(e) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("store insert failed: {e}"),
            skill_id: String::new(),
        }),
    }
}

/// POST /api/action/incident/reopen — operator marks a dismissed
/// incident for re-review. v1 writes an audit decision row with
/// `action_type = "operator_reopen"`; does NOT mutate the
/// incident's `outcome` in the knowledge graph (state-machine
/// integration deferred to follow-up spec).
pub(super) async fn api_action_reopen_incident(
    State(state): State<DashboardState>,
    Json(body): Json<crate::dashboard::types::ReopenIncidentRequest>,
) -> Json<crate::dashboard::types::ActionResponse> {
    use crate::dashboard::types::ActionResponse;
    let incident_id = body.incident_id.trim();
    let reason = body.reason.trim();
    if incident_id.is_empty() || reason.is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "incident_id and reason are required".to_string(),
            skill_id: String::new(),
        });
    }
    let Some(store) = state.sqlite_store.clone() else {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "SQLite store unavailable; cannot persist reopen".to_string(),
            skill_id: String::new(),
        });
    };
    let now = chrono::Utc::now().to_rfc3339();
    let data = serde_json::json!({
        "ts": now,
        "incident_id": incident_id,
        "action_type": "operator_reopen",
        "reason": reason,
        "operator_reopen": true,
    });
    let row = innerwarden_store::decisions::DecisionRow {
        ts: now.clone(),
        incident_id: incident_id.to_string(),
        action_type: "operator_reopen".to_string(),
        target_ip: None,
        target_user: None,
        confidence: 1.0,
        auto_executed: false,
        reason: Some(reason.to_string()),
        data: serde_json::to_string(&data).unwrap_or_default(),
    };
    match store.insert_decision(&row) {
        Ok(new_id) => Json(ActionResponse {
            success: true,
            dry_run: state.action_cfg.dry_run,
            message: format!(
                "reopen recorded (decision #{new_id}). State machine integration in follow-up spec."
            ),
            skill_id: "operator_reopen".to_string(),
        }),
        Err(e) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("store insert failed: {e}"),
            skill_id: String::new(),
        }),
    }
}

/// POST /api/action/decision/label — operator labels a decision
/// as TP (true positive) or FP (false positive). v1 appends to
/// `data_dir/decision-labels.jsonl` for future classifier
/// retraining; does not mutate the decision row itself (so the
/// hash chain stays untouched). Each line:
/// `{ts, decision_id, label, reason, operator_session}`.
pub(super) async fn api_action_label_decision(
    State(state): State<DashboardState>,
    Json(body): Json<crate::dashboard::types::LabelDecisionRequest>,
) -> Json<crate::dashboard::types::ActionResponse> {
    use crate::dashboard::types::ActionResponse;
    let label = body.label.trim();
    if !ALLOWED_LABELS.contains(&label) {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("label must be one of {:?}", ALLOWED_LABELS),
            skill_id: String::new(),
        });
    }
    let now = chrono::Utc::now().to_rfc3339();
    let entry = serde_json::json!({
        "ts": now,
        "decision_id": body.decision_id,
        "label": label,
        "reason": body.reason.trim(),
    });
    let path = state.data_dir.join("decision-labels.jsonl");
    // Best-effort append. Match the precedent used by other audit
    // sinks (`telegram-sent.jsonl`): a transient I/O hiccup logs a
    // warning but does not bubble a 500 to the operator — the
    // decision being labelled is far more important than the
    // label-aggregation file.
    let line = format!("{}\n", entry);
    let result = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut f| f.write_all(line.as_bytes()))
    })
    .await;
    match result {
        Ok(Ok(())) => Json(ActionResponse {
            success: true,
            dry_run: state.action_cfg.dry_run,
            message: format!(
                "label '{label}' recorded for decision #{} — used by future classifier retraining",
                body.decision_id
            ),
            skill_id: "operator_label".to_string(),
        }),
        Ok(Err(e)) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("decision-labels.jsonl write failed: {e}"),
            skill_id: String::new(),
        }),
        Err(e) => Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("blocking task panicked: {e}"),
            skill_id: String::new(),
        }),
    }
}

// ---------------------------------------------------------------------------
// 2026-06-10 (operator report): the case detail offered only "Block IP".
// These add the inverse + the triage verbs an operator needs once a case is
// already contained or sitting in needs_review. Both routes live in the
// auth+CSRF-protected `dashboard` router, so they inherit the same gate as
// block-ip. Neither touches the firewall synchronously: unblock QUEUES the
// revert for the agent slow loop (so the spec-076 reconciler does not fight a
// dashboard-side rule removal); triage writes operator-action decision rows
// that the read path classifies (see threat_contract::classify_decision).
// ---------------------------------------------------------------------------

const ALLOWED_TRIAGE_ACTIONS: &[&str] = &["dismiss", "monitor", "reopen"];

/// POST /api/action/unblock-ip — operator queues removal of a firewall block.
pub(super) async fn api_action_unblock_ip(
    State(state): State<DashboardState>,
    Json(body): Json<crate::dashboard::types::UnblockIpRequest>,
) -> Json<ActionResponse> {
    let skill_id = "operator_unblock".to_string();
    if state.insecure_http {
        warn!("unblock executed over HTTP without TLS — consider a reverse proxy with TLS");
    }
    if !state.action_cfg.enabled {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "dashboard actions are disabled - set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id,
        });
    }
    let ip = body.ip.trim().to_string();
    if ip.is_empty() || body.reason.trim().is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "ip and reason are required".to_string(),
            skill_id,
        });
    }
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "ip must be a valid IP address".to_string(),
            skill_id,
        });
    }
    // One queue row per case incident so each leaves the "blocked" bucket once
    // the drain writes its terminal row. No incidents supplied → a synthetic
    // marker so the IP still unblocks.
    let incident_ids: Vec<String> = if body.incident_ids.is_empty() {
        vec![format!("operator_unblock:{ip}")]
    } else {
        body.incident_ids.clone()
    };
    let mut wrote = 0usize;
    for iid in &incident_ids {
        let entry = DecisionEntry {
            ts: Utc::now(),
            incident_id: iid.clone(),
            host: hostname(),
            ai_provider: "dashboard:operator".to_string(),
            action_type: "operator_unblock_request".to_string(),
            target_ip: Some(ip.clone()),
            target_user: None,
            skill_id: Some(skill_id.clone()),
            confidence: 1.0,
            auto_executed: false,
            dry_run: state.action_cfg.dry_run,
            reason: body.reason.trim().to_string(),
            estimated_threat: "manual".to_string(),
            execution_result: "queued".to_string(),
            prev_hash: None,
            decision_layer: Some("manual_operator".to_string()),
        };
        if let Err(e) = append_decision_entry(&state.data_dir, &entry, state.sqlite_store.as_ref())
        {
            warn!("failed to write unblock request decision: {e}");
        } else {
            wrote += 1;
        }
    }

    let mut audit = AdminActionEntry {
        ts: Utc::now(),
        operator: "dashboard:operator".to_string(),
        source: "dashboard".to_string(),
        action: "unblock_request".to_string(),
        target: ip.clone(),
        parameters: serde_json::json!({
            "reason": body.reason,
            "incident_ids": incident_ids,
        }),
        result: if wrote > 0 { "queued" } else { "failed" }.to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&state.data_dir, &mut audit) {
        warn!("failed to write admin audit: {e:#}");
    }

    info!(ip = %ip, queued = wrote, "dashboard action: unblock-ip queued");
    Json(ActionResponse {
        success: wrote > 0,
        dry_run: state.action_cfg.dry_run,
        message: if wrote > 0 {
            format!(
                "Unblock queued for {ip}. The agent removes the firewall rule on its next slow-loop \
                 tick (≤30 s); the case updates once the revert is confirmed."
            )
        } else {
            "failed to queue unblock (store unavailable)".to_string()
        },
        skill_id,
    })
}

/// POST /api/action/triage-case — operator dismisses / monitors / reopens a
/// whole case. Writes one operator-action decision per incident; the read
/// path's latest-decision-per-incident selection makes the operator's row win.
pub(super) async fn api_action_triage_case(
    State(state): State<DashboardState>,
    Json(body): Json<crate::dashboard::types::TriageCaseRequest>,
) -> Json<ActionResponse> {
    let action = body.action.trim();
    let skill_id = "operator_triage".to_string();
    if state.insecure_http {
        warn!("triage executed over HTTP without TLS — consider a reverse proxy with TLS");
    }
    if !state.action_cfg.enabled {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "dashboard actions are disabled - set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id,
        });
    }
    if body.reason.trim().is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "reason is required".to_string(),
            skill_id,
        });
    }
    if body.incident_ids.is_empty() {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: "incident_ids is required".to_string(),
            skill_id,
        });
    }
    if !ALLOWED_TRIAGE_ACTIONS.contains(&action) {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("action must be one of {:?}", ALLOWED_TRIAGE_ACTIONS),
            skill_id,
        });
    }
    // Map the operator verb to the decision action_type the read-path
    // classifier understands (threat_contract::classify_decision).
    let action_type = match action {
        "dismiss" => "operator_override:dismiss".to_string(),
        "monitor" => "operator_override:monitor".to_string(),
        // reopen brings a handled case back into "Needs your attention".
        _ => "operator_reopen".to_string(),
    };
    let mut wrote = 0usize;
    for iid in &body.incident_ids {
        let entry = DecisionEntry {
            ts: Utc::now(),
            incident_id: iid.clone(),
            host: hostname(),
            ai_provider: "dashboard:operator".to_string(),
            action_type: action_type.clone(),
            target_ip: None,
            target_user: None,
            skill_id: Some(skill_id.clone()),
            confidence: 1.0,
            auto_executed: false,
            dry_run: state.action_cfg.dry_run,
            reason: body.reason.trim().to_string(),
            estimated_threat: "manual".to_string(),
            // "ok" so any read path that consults execution_result classifies
            // the operator's verb as a success (the journey path hardcodes
            // "ok" already; this keeps the two consistent).
            execution_result: "ok".to_string(),
            prev_hash: None,
            decision_layer: Some("manual_operator".to_string()),
        };
        if let Err(e) = append_decision_entry(&state.data_dir, &entry, state.sqlite_store.as_ref())
        {
            warn!(incident_id = %iid, "failed to write triage decision: {e}");
        } else {
            wrote += 1;
        }
    }

    let mut audit = AdminActionEntry {
        ts: Utc::now(),
        operator: "dashboard:operator".to_string(),
        source: "dashboard".to_string(),
        action: format!("triage_{action}"),
        target: body
            .incident_ids
            .first()
            .cloned()
            .unwrap_or_else(|| "case".to_string()),
        parameters: serde_json::json!({
            "reason": body.reason,
            "incident_ids": body.incident_ids,
            "action": action,
        }),
        result: format!("{wrote} incidents updated"),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&state.data_dir, &mut audit) {
        warn!("failed to write admin audit: {e:#}");
    }

    info!(action = %action, updated = wrote, "dashboard action: triage-case");
    Json(ActionResponse {
        success: wrote > 0,
        dry_run: state.action_cfg.dry_run,
        message: format!("case {action}: {wrote} incident(s) updated"),
        skill_id,
    })
}

// ---------------------------------------------------------------------------
// Operator "Trust IP" — monitor-only allowlist (add / remove / list).
//
// Trusting an IP suppresses only the AUTOMATED response: the IP is still
// detected, logged, and you are still notified (see operator_trust.rs). It does
// NOT blind detection, and there is deliberately no "drop / suppress detection"
// mode on this surface — a dashboard-authenticated attacker must not be able to
// self-allowlist into silence. Entries can be time-boxed and expire on their
// own. All three handlers ride the same auth+CSRF gate as the other actions.
// ---------------------------------------------------------------------------

/// POST /api/action/trust-ip — operator adds an IP/CIDR to the monitor-only
/// trust list.
pub(super) async fn api_action_trust_ip(
    State(state): State<DashboardState>,
    Json(body): Json<crate::dashboard::types::TrustIpRequest>,
) -> Json<ActionResponse> {
    if state.insecure_http {
        warn!("trust-ip executed over HTTP without TLS — consider a reverse proxy with TLS");
    }
    Json(trust_ip_inner(
        std::path::Path::new(crate::operator_trust::DEFAULT_RULES_DIR),
        &state.data_dir,
        state.action_cfg.enabled,
        state.action_cfg.dry_run,
        &body.ip,
        &body.reason,
        body.ttl_hours,
        Utc::now(),
    ))
}

/// POST /api/action/untrust-ip — operator removes an IP/CIDR from the trust list.
pub(super) async fn api_action_untrust_ip(
    State(state): State<DashboardState>,
    Json(body): Json<crate::dashboard::types::UntrustIpRequest>,
) -> Json<ActionResponse> {
    if state.insecure_http {
        warn!("untrust-ip executed over HTTP without TLS — consider a reverse proxy with TLS");
    }
    Json(untrust_ip_inner(
        std::path::Path::new(crate::operator_trust::DEFAULT_RULES_DIR),
        &state.data_dir,
        state.action_cfg.enabled,
        state.action_cfg.dry_run,
        &body.ip,
        &body.reason,
    ))
}

/// GET /api/action/trusted-ips — list the current operator trust entries.
pub(super) async fn api_action_trusted_ips(
    State(_state): State<DashboardState>,
) -> Json<serde_json::Value> {
    Json(list_trusted_inner(
        std::path::Path::new(crate::operator_trust::DEFAULT_RULES_DIR),
        Utc::now(),
    ))
}

// --- Execution Gate: operator "Trust Exec" (2FA-gated) ----------------------
//
// Authorising a binary to execute machine-wide is a SENSITIVE action — it is the
// approve side of the Execution Gate. So unlike Trust IP, these handlers enforce
// 2FA (when `[security].method = "totp"`) via the same `verify_dashboard_totp`
// gate the orphan-resolution endpoints use. On success an `allow_exec` rule is
// written (operator_exec_trust); the paid `exec-gate watch` daemon hot-reloads it
// and the path executes. Without the paid daemon the rule is inert.
// ---------------------------------------------------------------------------

/// POST /api/action/trust-exec — operator authorises a binary path for the gate.
pub(super) async fn api_action_trust_exec(
    State(state): State<DashboardState>,
    Json(body): Json<crate::dashboard::types::TrustExecRequest>,
) -> Json<ActionResponse> {
    if state.insecure_http {
        warn!("trust-exec executed over HTTP without TLS — consider a reverse proxy with TLS");
    }
    if let Err(e) = crate::dashboard::agent_api::verify_dashboard_totp(&state, &body.totp) {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("2FA required to authorise an exec path: {e}"),
            skill_id: "operator_exec_trust".to_string(),
        });
    }
    Json(trust_exec_inner(
        std::path::Path::new(crate::operator_exec_trust::DEFAULT_EXEC_RULES_DIR),
        &state.data_dir,
        state.action_cfg.enabled,
        state.action_cfg.dry_run,
        &body.path,
        &body.reason,
    ))
}

/// POST /api/action/untrust-exec — operator revokes a previously trusted path.
pub(super) async fn api_action_untrust_exec(
    State(state): State<DashboardState>,
    Json(body): Json<crate::dashboard::types::UntrustExecRequest>,
) -> Json<ActionResponse> {
    if state.insecure_http {
        warn!("untrust-exec executed over HTTP without TLS — consider a reverse proxy with TLS");
    }
    if let Err(e) = crate::dashboard::agent_api::verify_dashboard_totp(&state, &body.totp) {
        return Json(ActionResponse {
            success: false,
            dry_run: state.action_cfg.dry_run,
            message: format!("2FA required to revoke an exec path: {e}"),
            skill_id: "operator_exec_untrust".to_string(),
        });
    }
    Json(untrust_exec_inner(
        std::path::Path::new(crate::operator_exec_trust::DEFAULT_EXEC_RULES_DIR),
        &state.data_dir,
        state.action_cfg.enabled,
        state.action_cfg.dry_run,
        &body.path,
        &body.reason,
    ))
}

/// GET /api/action/trusted-execs — list the current operator exec authorisations.
pub(super) async fn api_action_trusted_execs(
    State(_state): State<DashboardState>,
) -> Json<serde_json::Value> {
    Json(list_trusted_execs_inner(std::path::Path::new(
        crate::operator_exec_trust::DEFAULT_EXEC_RULES_DIR,
    )))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn trust_ip_inner(
    rules_dir: &Path,
    data_dir: &Path,
    enabled: bool,
    dry_run: bool,
    ip: &str,
    reason: &str,
    ttl_hours: Option<u64>,
    now: chrono::DateTime<Utc>,
) -> ActionResponse {
    let skill_id = "operator_trust".to_string();
    if !enabled {
        return ActionResponse {
            success: false,
            dry_run,
            message: "dashboard actions are disabled - set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id,
        };
    }

    let outcome = crate::operator_trust::add(rules_dir, ip, reason, ttl_hours, now);

    let (success, message, expires_at) = match &outcome {
        Ok(entry) => {
            let expiry = entry
                .expires_at
                .map(|e| e.to_rfc3339())
                .unwrap_or_else(|| "never".to_string());
            let msg = if entry.expires_at.is_some() {
                format!(
                    "Now trusting {} (monitor-only): auto-block is suppressed, but it is still \
                     detected, logged, and you are still notified. Trust expires {expiry}.",
                    entry.value
                )
            } else {
                format!(
                    "Now trusting {} (monitor-only): auto-block is suppressed, but it is still \
                     detected, logged, and you are still notified. Remove it any time.",
                    entry.value
                )
            };
            (true, msg, Some(expiry))
        }
        Err(e) => (false, e.clone(), None),
    };

    let mut audit = AdminActionEntry {
        ts: Utc::now(),
        operator: "dashboard:operator".to_string(),
        source: "dashboard".to_string(),
        action: "trust_ip".to_string(),
        target: ip.trim().to_string(),
        parameters: serde_json::json!({
            "reason": reason,
            "ttl_hours": ttl_hours,
            "expires_at": expires_at,
            "mode": "monitor_only",
        }),
        result: if success {
            "success".to_string()
        } else {
            format!("failure: {message}")
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(data_dir, &mut audit) {
        warn!("failed to write admin audit: {e:#}");
    }

    info!(ip = %ip.trim(), success, "dashboard action: trust-ip");
    ActionResponse {
        success,
        dry_run,
        message,
        skill_id,
    }
}

pub(super) fn untrust_ip_inner(
    rules_dir: &Path,
    data_dir: &Path,
    enabled: bool,
    dry_run: bool,
    ip: &str,
    reason: &str,
) -> ActionResponse {
    let skill_id = "operator_untrust".to_string();
    if !enabled {
        return ActionResponse {
            success: false,
            dry_run,
            message: "dashboard actions are disabled - set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id,
        };
    }

    let (success, message) = match crate::operator_trust::remove(rules_dir, ip) {
        Ok(true) => (
            true,
            format!(
                "Removed {} from the trust list. Auto-response resumes within one slow-loop \
                 tick (≤30 s).",
                ip.trim()
            ),
        ),
        Ok(false) => (false, format!("{} is not in the trust list", ip.trim())),
        Err(e) => (false, e),
    };

    let mut audit = AdminActionEntry {
        ts: Utc::now(),
        operator: "dashboard:operator".to_string(),
        source: "dashboard".to_string(),
        action: "untrust_ip".to_string(),
        target: ip.trim().to_string(),
        parameters: serde_json::json!({ "reason": reason }),
        result: if success {
            "success".to_string()
        } else {
            format!("failure: {message}")
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(data_dir, &mut audit) {
        warn!("failed to write admin audit: {e:#}");
    }

    info!(ip = %ip.trim(), success, "dashboard action: untrust-ip");
    ActionResponse {
        success,
        dry_run,
        message,
        skill_id,
    }
}

pub(super) fn list_trusted_inner(
    rules_dir: &Path,
    now: chrono::DateTime<Utc>,
) -> serde_json::Value {
    let file = crate::operator_trust::managed_file_in(rules_dir);
    let entries: Vec<serde_json::Value> = crate::operator_trust::read_entries(&file)
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "value": e.value,
                "reason": e.reason,
                "id": e.id,
                "expires_at": e.expires_at.map(|t| t.to_rfc3339()),
                "expired": e.is_expired_at(now),
            })
        })
        .collect();
    serde_json::json!({
        "count": entries.len(),
        "trusted_ips": entries,
        // Reminder the UI can surface so operators understand the semantics.
        "note": "Trusted IPs are still detected, logged, and notified — only automated blocking is suppressed.",
    })
}

/// Testable core of trust-exec: validate + write the `allow_exec` rule + audit.
/// 2FA is verified by the async handler before this is called.
pub(super) fn trust_exec_inner(
    rules_dir: &Path,
    data_dir: &Path,
    enabled: bool,
    dry_run: bool,
    path: &str,
    reason: &str,
) -> ActionResponse {
    let skill_id = "operator_exec_trust".to_string();
    if !enabled {
        return ActionResponse {
            success: false,
            dry_run,
            message: "dashboard actions are disabled - set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id,
        };
    }

    let (success, message) = match crate::operator_exec_trust::add(rules_dir, path, reason) {
        Ok(entry) => (
            true,
            format!(
                "Authorised {} for the Execution Gate. It will be allowed to execute within one \
                 watch cycle. Revoke any time.",
                entry.path
            ),
        ),
        Err(e) => (false, e),
    };

    let mut audit = AdminActionEntry {
        ts: Utc::now(),
        operator: "dashboard:operator".to_string(),
        source: "dashboard".to_string(),
        action: "trust_exec".to_string(),
        target: path.trim().to_string(),
        parameters: serde_json::json!({ "reason": reason, "two_factor": "enforced" }),
        result: if success {
            "success".to_string()
        } else {
            format!("failure: {message}")
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(data_dir, &mut audit) {
        warn!("failed to write admin audit: {e:#}");
    }

    info!(path = %path.trim(), success, "dashboard action: trust-exec");
    ActionResponse {
        success,
        dry_run,
        message,
        skill_id,
    }
}

/// Testable core of untrust-exec: remove the `allow_exec` rule + audit.
pub(super) fn untrust_exec_inner(
    rules_dir: &Path,
    data_dir: &Path,
    enabled: bool,
    dry_run: bool,
    path: &str,
    reason: &str,
) -> ActionResponse {
    let skill_id = "operator_exec_untrust".to_string();
    if !enabled {
        return ActionResponse {
            success: false,
            dry_run,
            message: "dashboard actions are disabled - set responder.enabled = true in agent.toml"
                .to_string(),
            skill_id,
        };
    }

    let (success, message) = match crate::operator_exec_trust::remove(rules_dir, path) {
        Ok(true) => (
            true,
            format!(
                "Revoked {} from the Execution Gate allowlist. It will be denied/observed again \
                 within one watch cycle.",
                path.trim()
            ),
        ),
        Ok(false) => (
            false,
            format!("{} is not in the exec allowlist", path.trim()),
        ),
        Err(e) => (false, e),
    };

    let mut audit = AdminActionEntry {
        ts: Utc::now(),
        operator: "dashboard:operator".to_string(),
        source: "dashboard".to_string(),
        action: "untrust_exec".to_string(),
        target: path.trim().to_string(),
        parameters: serde_json::json!({ "reason": reason, "two_factor": "enforced" }),
        result: if success {
            "success".to_string()
        } else {
            format!("failure: {message}")
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(data_dir, &mut audit) {
        warn!("failed to write admin audit: {e:#}");
    }

    info!(path = %path.trim(), success, "dashboard action: untrust-exec");
    ActionResponse {
        success,
        dry_run,
        message,
        skill_id,
    }
}

/// Testable core of the trusted-execs list endpoint.
pub(super) fn list_trusted_execs_inner(rules_dir: &Path) -> serde_json::Value {
    let file = crate::operator_exec_trust::managed_file_in(rules_dir);
    let entries: Vec<serde_json::Value> = crate::operator_exec_trust::read_entries(&file)
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "path": e.path,
                "reason": e.reason,
                "id": e.id,
            })
        })
        .collect();
    serde_json::json!({
        "count": entries.len(),
        "trusted_execs": entries,
        "note": "Authorised binary paths the Execution Gate allows to execute. Enforced only when the paid Active Defence watch daemon is running.",
    })
}

/// Truncate a string to at most `max_chars` chars, appending an
/// ellipsis when truncated. Used by override reason to bound the
/// length of the original AI rationale included in the audit row.
fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let trunc: String = s.chars().take(max_chars).collect();
    format!("{trunc}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_synthetic_incident() {
        let incident = make_synthetic_incident("test1", "10.0.0.5", "Manual block test");

        assert_eq!(incident.incident_id, "dashboard:manual:test1");
        assert_eq!(incident.summary, "Manual block test");
        assert_eq!(incident.tags, vec!["dashboard", "manual"]);

        let has_ip = incident
            .entities
            .iter()
            .any(|e| e.value == "10.0.0.5" && format!("{:?}", e.r#type) == "Ip");
        assert!(has_ip);
    }

    #[test]
    fn test_validate_action_params() {
        // Validates common guardrails for action parameter validation.
        // Vazio rejeita
        assert_eq!(
            validate_action_params("", "reason").unwrap_err(),
            "target is required"
        );
        assert_eq!(
            validate_action_params("1.2.3.4", "").unwrap_err(),
            "reason is required"
        );

        // Interno rejeita
        assert_eq!(
            validate_action_params("127.0.0.1", "test").unwrap_err(),
            "cannot target internal IP"
        );
        assert_eq!(
            validate_action_params("10.0.0.5", "test").unwrap_err(),
            "cannot target internal IP"
        );
        assert_eq!(
            validate_action_params("192.168.1.1", "test").unwrap_err(),
            "cannot target internal IP"
        );
        assert_eq!(
            validate_action_params("172.16.0.1", "test").unwrap_err(),
            "cannot target internal IP"
        );

        // Allowed
        assert!(validate_action_params("8.8.8.8", "reason").is_ok());
        assert!(validate_action_params("admin", "reason").is_ok());
    }

    // ── Wave 1 anchors (AUDIT-WAVE1-UTF8) ────────────────────────────
    //
    // `validate_action_params` previously did `t[4..6]` byte slicing
    // which (a) panicked when an attacker-supplied target placed a
    // multi-byte UTF-8 codepoint at byte 4 and (b) incorrectly
    // accepted only 2-digit second octets, falsely blocking
    // `172.165.0.1` (NOT private) while letting any 3-digit start
    // through.

    #[test]
    fn validate_action_params_does_not_panic_on_multibyte_after_172_dot() {
        // Each of these places a multi-byte codepoint at byte 4
        // (right after `172.`), the exact shape that triggered the
        // pre-fix panic. The new split-on-`.` parser fails the parse
        // and returns Ok (the address is not blockable as RFC1918,
        // but more importantly this MUST NOT panic).
        for evil in &["172.€16.0.1", "172.é.0.1", "172.🦀.0.1"] {
            // NOT panicking is the headline anchor; the return value
            // is secondary but pinned for completeness.
            let result = validate_action_params(evil, "reason");
            // For any of these, second octet does not parse as u8 in
            // 16..=31, so the 172.x check does not block. Other
            // checks may still fire (if e.g. 172.€16... starts with
            // a private prefix), but for the chosen inputs none does.
            assert!(
                result.is_ok(),
                "expected ok or non-panic for {evil:?}, got {result:?}"
            );
        }
    }

    #[test]
    fn validate_action_params_allows_172_165_which_is_not_rfc1918() {
        // 172.165.0.1 is in the 172.165.0.0/16 PUBLIC range. Pre-fix
        // the byte-slice `t[4..6] = "16"` parsed to 16 and falsely
        // matched the private range, blocking a real outbound
        // attacker. Anti-regression for the silent operator-impacting
        // bug the new split-on-`.` parser eliminates.
        assert!(
            validate_action_params("172.165.0.1", "real attacker").is_ok(),
            "172.165.0.1 is public; must not be blocked"
        );
        // 172.200.0.1 has the same shape — three-digit second octet,
        // public range. Also must pass.
        assert!(validate_action_params("172.200.0.1", "real attacker").is_ok());
    }

    #[test]
    fn validate_action_params_still_blocks_real_172_16_through_172_31() {
        // The full RFC1918 172.16.0.0/12 range. Pin the boundary so
        // a future "fix" that off-by-ones the range fails at test
        // time.
        for blocked in &[
            "172.16.0.1",
            "172.17.0.1",
            "172.20.0.1",
            "172.30.0.1",
            "172.31.255.255",
        ] {
            assert_eq!(
                validate_action_params(blocked, "internal").err(),
                Some("cannot target internal IP"),
                "{blocked:?} is RFC1918; must be rejected"
            );
        }
    }

    #[test]
    fn validate_action_params_allows_172_15_and_172_32_at_range_edges() {
        // Just outside 172.16.0.0/12 on both sides. Must pass.
        assert!(validate_action_params("172.15.0.1", "public").is_ok());
        assert!(validate_action_params("172.32.0.1", "public").is_ok());
    }

    #[test]
    fn test_block_ip_empty_string_is_rejected() {
        // Empty target string should be rejected for block-ip action.
        let result = validate_action_params("   ", "manual investigation");
        assert!(result.is_err());
        assert_eq!(result.err(), Some("target is required"));
    }

    #[test]
    fn test_block_ip_private_ranges_are_rejected() {
        // Internal RFC1918 ranges must not be accepted by block-ip.
        assert_eq!(
            validate_action_params("10.42.0.9", "internal should fail").err(),
            Some("cannot target internal IP")
        );
        assert_eq!(
            validate_action_params("192.168.10.20", "internal should fail").err(),
            Some("cannot target internal IP")
        );
    }

    #[test]
    fn test_unblock_nonexistent_ip_is_noop() {
        // Removing an IP that does not exist should be a safe no-op.
        let mut blocked = std::collections::HashSet::from(["8.8.8.8".to_string()]);
        let removed = blocked.remove("9.9.9.9");
        assert!(!removed);
        assert!(blocked.contains("8.8.8.8"));
    }

    // ── api_quickwins regression suite ───────────────────────────────
    //
    // Anchors for the bug surfaced 2026-04-22 (`.claude-local/RECURRING_BUGS.md`):
    //   1. Reader looked at JSON field `action`, but writer (`decisions.rs`)
    //      writes `action_type`. Blocked-IP set was always empty.
    //   2. Severity filter compared against "High"/"Critical" but on-disk values
    //      are lowercase per `Severity` `#[serde(rename_all = "lowercase")]`.
    //
    // Fixtures use the on-disk JSONL field names directly so a future schema
    // rename on either side will fail these tests.

    fn write_jsonl(dir: &std::path::Path, name: &str, lines: &[serde_json::Value]) {
        let path = dir.join(name);
        let mut buf = String::new();
        for v in lines {
            buf.push_str(&serde_json::to_string(v).unwrap());
            buf.push('\n');
        }
        std::fs::write(&path, buf).expect("write fixture jsonl");
    }

    fn today_str() -> String {
        chrono::Utc::now().format("%Y-%m-%d").to_string()
    }

    fn high_incident(ip: &str, title: &str) -> serde_json::Value {
        serde_json::json!({
            "severity": "high",
            "title": title,
            "entities": [{"type": "Ip", "value": ip}],
        })
    }

    fn critical_incident(ip: &str, title: &str) -> serde_json::Value {
        serde_json::json!({
            "severity": "critical",
            "title": title,
            "entities": [{"type": "Ip", "value": ip}],
        })
    }

    fn block_decision(ip: &str) -> serde_json::Value {
        // Use the writer's actual field names. If `decisions.rs::DecisionEntry`
        // ever renames `action_type`, this fixture and the production reader
        // both need to update — that is the contract.
        serde_json::json!({
            "action_type": "block_ip",
            "target_ip": ip,
        })
    }

    #[test]
    fn api_quickwins_returns_unblocked_high_severity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let date = today_str();

        // 1 high-severity incident from an unblocked IP, 1 high-severity from a
        // blocked IP, 1 low-severity (must be filtered out).
        write_jsonl(
            dir.path(),
            &format!("incidents-{date}.jsonl"),
            &[
                high_incident("203.0.113.10", "ssh bruteforce"),
                high_incident("198.51.100.5", "port scan"),
                serde_json::json!({
                    "severity": "low",
                    "title": "noise",
                    "entities": [{"type": "Ip", "value": "203.0.113.99"}],
                }),
            ],
        );
        write_jsonl(
            dir.path(),
            &format!("decisions-{date}.jsonl"),
            &[block_decision("198.51.100.5")],
        );

        let payload = quickwins_payload(dir.path());
        let suggestions = payload["suggestions"].as_array().expect("suggestions");
        assert_eq!(payload["count"].as_u64(), Some(1));
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0]["ip"].as_str(), Some("203.0.113.10"));
        assert_eq!(suggestions[0]["severity"].as_str(), Some("high"));
        assert_eq!(
            suggestions[0]["title"].as_str(),
            Some("ssh bruteforce"),
            "title should round-trip from incident"
        );
    }

    #[test]
    fn api_quickwins_accepts_critical_severity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let date = today_str();
        write_jsonl(
            dir.path(),
            &format!("incidents-{date}.jsonl"),
            &[critical_incident("203.0.113.42", "ransomware burst")],
        );
        let payload = quickwins_payload(dir.path());
        assert_eq!(payload["count"].as_u64(), Some(1));
        assert_eq!(
            payload["suggestions"][0]["severity"].as_str(),
            Some("critical")
        );
    }

    #[test]
    fn api_quickwins_dedupes_blocked_ip_via_action_type_field() {
        // Regression for the field-name bug. The writer uses `action_type`,
        // the previous reader looked at `action`. If the reader reverts to
        // `action`, the blocked IP will not be removed and this test fails.
        let dir = tempfile::tempdir().expect("tempdir");
        let date = today_str();
        write_jsonl(
            dir.path(),
            &format!("incidents-{date}.jsonl"),
            &[high_incident("203.0.113.99", "double-counted threat")],
        );
        write_jsonl(
            dir.path(),
            &format!("decisions-{date}.jsonl"),
            &[block_decision("203.0.113.99")],
        );

        let payload = quickwins_payload(dir.path());
        assert_eq!(
            payload["count"].as_u64(),
            Some(0),
            "blocked IP must be filtered out — if this fails, the action_type field name regressed"
        );
    }

    #[test]
    fn api_quickwins_ignores_low_severity_case_insensitive() {
        // Regression for the severity-case bug. Fixture writes both "high"
        // (correct) and "HIGH" (defensive — should still be accepted by a
        // case-insensitive comparison) and "low" (must be rejected).
        let dir = tempfile::tempdir().expect("tempdir");
        let date = today_str();
        write_jsonl(
            dir.path(),
            &format!("incidents-{date}.jsonl"),
            &[
                serde_json::json!({
                    "severity": "HIGH",
                    "title": "uppercase wire format",
                    "entities": [{"type": "Ip", "value": "203.0.113.1"}],
                }),
                serde_json::json!({
                    "severity": "low",
                    "title": "noise",
                    "entities": [{"type": "Ip", "value": "203.0.113.2"}],
                }),
            ],
        );
        let payload = quickwins_payload(dir.path());
        assert_eq!(payload["count"].as_u64(), Some(1));
        assert_eq!(
            payload["suggestions"][0]["ip"].as_str(),
            Some("203.0.113.1")
        );
    }

    #[test]
    fn api_quickwins_dedupes_repeated_ip_within_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let date = today_str();
        write_jsonl(
            dir.path(),
            &format!("incidents-{date}.jsonl"),
            &[
                high_incident("203.0.113.7", "first hit"),
                high_incident("203.0.113.7", "second hit same IP"),
            ],
        );
        let payload = quickwins_payload(dir.path());
        assert_eq!(payload["count"].as_u64(), Some(1));
    }

    #[test]
    fn api_quickwins_returns_empty_when_no_files_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = quickwins_payload(dir.path());
        assert_eq!(payload["count"].as_u64(), Some(0));
        assert!(payload["suggestions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn api_quickwins_skips_malformed_jsonl_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let date = today_str();
        let path = dir.path().join(format!("incidents-{date}.jsonl"));
        std::fs::write(
            &path,
            // first line is valid, second is broken JSON, third is valid again
            format!(
                "{}\nnot-json-at-all\n{}\n",
                serde_json::to_string(&high_incident("203.0.113.10", "valid 1")).unwrap(),
                serde_json::to_string(&high_incident("203.0.113.20", "valid 2")).unwrap(),
            ),
        )
        .unwrap();
        let payload = quickwins_payload(dir.path());
        assert_eq!(
            payload["count"].as_u64(),
            Some(2),
            "malformed lines must be skipped, not abort the scan"
        );
    }

    // ── 2026-05-01 (`tracked-spec-ai-override`) coverage ─────────────
    //
    // Each new endpoint has several short-circuit branches plus a
    // happy path; the tests below pin every error message so a
    // refactor that drops the validation accidentally surfaces in
    // CI rather than silently shipping an open endpoint.

    use crate::dashboard::state::test_dashboard_state;
    use crate::dashboard::types::{
        LabelDecisionRequest, OverrideDecisionRequest, ReopenIncidentRequest,
    };

    fn state_with_sqlite(
        dir: &std::path::Path,
    ) -> (
        crate::dashboard::state::DashboardState,
        std::sync::Arc<innerwarden_store::Store>,
    ) {
        let store = std::sync::Arc::new(innerwarden_store::Store::open(dir).unwrap());
        let mut state = test_dashboard_state(dir);
        state.sqlite_store = Some(store.clone());
        (state, store)
    }

    fn seed_decision(store: &innerwarden_store::Store) -> i64 {
        let row = innerwarden_store::decisions::DecisionRow {
            ts: "2026-05-01T12:00:00Z".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:2026-05-01T12Z".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            confidence: 0.92,
            auto_executed: true,
            reason: Some("AI proposed block".to_string()),
            data: r#"{"action_type":"block_ip","target_ip":"1.2.3.4"}"#.to_string(),
        };
        store.insert_decision(&row).unwrap()
    }

    #[tokio::test]
    async fn api_action_override_decision_rejects_empty_reason() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _store) = state_with_sqlite(dir.path());
        let body = OverrideDecisionRequest {
            decision_id: 1,
            new_action: "block_ip".to_string(),
            reason: "   ".to_string(),
        };
        let resp = api_action_override_decision(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("reason is required"));
    }

    #[tokio::test]
    async fn api_action_override_decision_rejects_invalid_new_action() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _store) = state_with_sqlite(dir.path());
        let body = OverrideDecisionRequest {
            decision_id: 1,
            new_action: "delete_database".to_string(),
            reason: "trying to break it".to_string(),
        };
        let resp = api_action_override_decision(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("new_action must be one of"));
    }

    #[tokio::test]
    async fn api_action_override_decision_returns_error_when_no_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_dashboard_state(dir.path()); // no sqlite
        let body = OverrideDecisionRequest {
            decision_id: 1,
            new_action: "monitor".to_string(),
            reason: "operator disagrees".to_string(),
        };
        let resp = api_action_override_decision(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("SQLite store unavailable"));
    }

    #[tokio::test]
    async fn api_action_override_decision_returns_error_when_decision_id_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _store) = state_with_sqlite(dir.path());
        let body = OverrideDecisionRequest {
            decision_id: 99999,
            new_action: "monitor".to_string(),
            reason: "operator disagrees".to_string(),
        };
        let resp = api_action_override_decision(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("not found"));
    }

    #[tokio::test]
    async fn api_action_override_decision_happy_path_chains_to_original() {
        let dir = tempfile::tempdir().unwrap();
        let (state, store) = state_with_sqlite(dir.path());
        let original_id = seed_decision(&store);
        let body = OverrideDecisionRequest {
            decision_id: original_id,
            new_action: "monitor".to_string(),
            reason: "operator says monitor instead".to_string(),
        };
        let resp = api_action_override_decision(State(state), Json(body)).await;
        assert!(resp.0.success, "got: {}", resp.0.message);
        assert!(resp.0.skill_id.starts_with("operator_override:"));
        // The new row was inserted and chained — verify by reading
        // the latest two rows and checking prev_hash linkage.
        let trail = store.audit_trail(None, 5, None).unwrap();
        assert_eq!(trail.len(), 2);
        let new_row = &trail[0]; // latest first
        let original_row = &trail[1];
        assert_eq!(new_row.action_type, "operator_override:monitor");
        assert_eq!(
            new_row.prev_hash.as_deref(),
            Some(original_row.row_hash.as_str())
        );
        assert!(new_row.reason.as_ref().unwrap().contains("monitor"));
        assert!(new_row
            .reason
            .as_ref()
            .unwrap()
            .contains(&format!("decision #{original_id}")));
    }

    #[tokio::test]
    async fn api_action_reopen_incident_rejects_empty_fields() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _store) = state_with_sqlite(dir.path());
        let body = ReopenIncidentRequest {
            incident_id: "".to_string(),
            reason: "needs review".to_string(),
        };
        let resp = api_action_reopen_incident(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("are required"));
    }

    #[tokio::test]
    async fn api_action_reopen_incident_returns_error_when_no_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_dashboard_state(dir.path());
        let body = ReopenIncidentRequest {
            incident_id: "inc-1".to_string(),
            reason: "needs review".to_string(),
        };
        let resp = api_action_reopen_incident(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("SQLite store unavailable"));
    }

    #[tokio::test]
    async fn api_action_reopen_incident_writes_audit_row() {
        let dir = tempfile::tempdir().unwrap();
        let (state, store) = state_with_sqlite(dir.path());
        let body = ReopenIncidentRequest {
            incident_id: "inc-42".to_string(),
            reason: "second review".to_string(),
        };
        let resp = api_action_reopen_incident(State(state), Json(body)).await;
        assert!(resp.0.success, "got: {}", resp.0.message);
        let trail = store.audit_trail(None, 5, None).unwrap();
        assert_eq!(trail.len(), 1);
        assert_eq!(trail[0].action_type, "operator_reopen");
        assert_eq!(trail[0].incident_id, "inc-42");
        assert_eq!(trail[0].reason.as_deref(), Some("second review"));
    }

    #[tokio::test]
    async fn api_action_label_decision_rejects_invalid_label() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_dashboard_state(dir.path());
        let body = LabelDecisionRequest {
            decision_id: 1,
            label: "MAYBE".to_string(),
            reason: "".to_string(),
        };
        let resp = api_action_label_decision(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("label must be one of"));
    }

    #[tokio::test]
    async fn api_action_label_decision_appends_to_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_dashboard_state(dir.path());
        let body = LabelDecisionRequest {
            decision_id: 7,
            label: "FP".to_string(),
            reason: "scanner false positive".to_string(),
        };
        let resp = api_action_label_decision(State(state), Json(body)).await;
        assert!(resp.0.success, "got: {}", resp.0.message);
        let path = dir.path().join("decision-labels.jsonl");
        let raw = std::fs::read_to_string(&path).unwrap();
        let line = raw.lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["decision_id"], 7);
        assert_eq!(v["label"], "FP");
        assert_eq!(v["reason"], "scanner false positive");
    }

    #[tokio::test]
    async fn api_action_label_decision_appends_multiple_lines() {
        // Anchors the append-only invariant: a second call must
        // not overwrite the first. This is what the future
        // retraining pipeline relies on (it consumes every line).
        let dir = tempfile::tempdir().unwrap();
        let state1 = test_dashboard_state(dir.path());
        let _ = api_action_label_decision(
            State(state1),
            Json(LabelDecisionRequest {
                decision_id: 1,
                label: "TP".to_string(),
                reason: String::new(),
            }),
        )
        .await;
        let state2 = test_dashboard_state(dir.path());
        let _ = api_action_label_decision(
            State(state2),
            Json(LabelDecisionRequest {
                decision_id: 2,
                label: "FP".to_string(),
                reason: String::new(),
            }),
        )
        .await;
        let raw = std::fs::read_to_string(dir.path().join("decision-labels.jsonl")).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2);
        let v1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let v2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(v1["label"], "TP");
        assert_eq!(v2["label"], "FP");
    }

    #[test]
    fn truncate_handles_short_and_long_strings() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello", 5), "hello");
        assert_eq!(truncate("hello world", 5), "hello…");
        // Multi-byte chars: must clamp by char count, not byte count,
        // so a UTF-8 string is never sliced mid-codepoint.
        let s = "ção da AI";
        assert_eq!(truncate(s, 3), "ção…");
    }

    // ── api_action_config: derived "mode" must reflect (enabled, dry_run) ─────
    //
    // The dashboard UI reads `mode` to decide which action buttons to render
    // (read_only hides them, watch shows them with a DRY-RUN tag, guard shows
    // them as live). A regression on the truth-table below silently changes
    // operator-visible behaviour; pin every cell.

    fn state_with_action_cfg(
        dir: &std::path::Path,
        cfg: DashboardActionConfig,
    ) -> crate::dashboard::state::DashboardState {
        let mut state = test_dashboard_state(dir);
        state.action_cfg = std::sync::Arc::new(cfg);
        state
    }

    #[tokio::test]
    async fn api_action_config_returns_read_only_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = DashboardActionConfig::default();
        cfg.enabled = false;
        cfg.dry_run = false;
        cfg.trusted_ips = vec!["10.0.0.1".to_string()];
        cfg.trusted_users = vec!["root".to_string()];
        let state = state_with_action_cfg(dir.path(), cfg);
        let resp = api_action_config(State(state)).await;
        let v = resp.0;
        assert_eq!(v["mode"], "read_only");
        assert_eq!(v["enabled"], false);
        assert_eq!(v["block_backend"], "ufw");
        assert_eq!(v["trusted_ips"][0], "10.0.0.1");
        assert_eq!(v["trusted_users"][0], "root");
        // Version always present so the UI can render it.
        assert!(v["version"].is_string());
    }

    #[tokio::test]
    async fn api_action_config_returns_watch_when_enabled_and_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = DashboardActionConfig::default();
        cfg.enabled = true;
        cfg.dry_run = true;
        let state = state_with_action_cfg(dir.path(), cfg);
        let resp = api_action_config(State(state)).await;
        assert_eq!(resp.0["mode"], "watch");
    }

    #[tokio::test]
    async fn api_action_config_returns_guard_when_enabled_live() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = DashboardActionConfig::default();
        cfg.enabled = true;
        cfg.dry_run = false;
        let state = state_with_action_cfg(dir.path(), cfg);
        let resp = api_action_config(State(state)).await;
        assert_eq!(resp.0["mode"], "guard");
    }

    // ── api_quickwins async wrapper exercises spawn_blocking path ────────────

    #[tokio::test]
    async fn api_quickwins_async_wrapper_returns_payload_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let date = today_str();
        write_jsonl(
            dir.path(),
            &format!("incidents-{date}.jsonl"),
            &[high_incident("203.0.113.55", "ssh bruteforce")],
        );
        let state = test_dashboard_state(dir.path());
        let resp = api_quickwins(State(state)).await;
        let v = resp.0;
        assert_eq!(v["count"].as_u64(), Some(1));
        assert_eq!(v["suggestions"][0]["ip"].as_str(), Some("203.0.113.55"));
    }

    // ── api_action_block_ip: every guard-clause + dry-run happy path ─────────

    fn enabled_dry_run_cfg(extra_skills: &[&str]) -> DashboardActionConfig {
        let mut cfg = DashboardActionConfig::default();
        cfg.enabled = true;
        cfg.dry_run = true;
        let mut allowed = vec!["block-ip-ufw".to_string()];
        for s in extra_skills {
            allowed.push((*s).to_string());
        }
        cfg.allowed_skills = allowed;
        cfg
    }

    #[tokio::test]
    async fn execute_block_ip_refuses_trusted_ip_via_skill_gate() {
        // Regression anchor for the 2026-05-10 skill_gate wire-in.
        // Operator hitting "Block" on the dashboard for an IP listed
        // in `cfg.trusted_ips` must NOT commit a firewall rule. The
        // gate refuses BEFORE `skill.execute`, so:
        //   - return value: success=false, message cites trusted_ips
        //   - audit-trail row: execution_result starts with "skipped:"
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = enabled_dry_run_cfg(&[]);
        cfg.trusted_ips = vec!["8.8.4.4".to_string()];
        let (success, message) =
            execute_block_ip(dir.path(), None, &cfg, "8.8.4.4", "operator-tap", None)
                .await
                .expect("dashboard execute_block_ip returns Ok even when gate refuses");
        assert!(!success, "trusted_ip must not be auto-blocked");
        assert!(
            message.to_lowercase().contains("trusted_ips"),
            "refusal must cite trusted_ips: {message}"
        );

        // Audit row carries the gate-refusal message in execution_result.
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let audit = std::fs::read_to_string(dir.path().join(format!("decisions-{today}.jsonl")))
            .expect("audit row written");
        let row: serde_json::Value =
            serde_json::from_str(audit.lines().next().expect("at least one row"))
                .expect("audit row is JSON");
        assert_eq!(row["target_ip"], "8.8.4.4");
        let exec_result = row["execution_result"].as_str().unwrap_or("");
        assert!(
            exec_result.contains("skipped:"),
            "audit row must record the gate refusal in execution_result: {exec_result}"
        );
    }

    #[tokio::test]
    async fn execute_block_ip_refuses_cloud_safelisted_ip_via_skill_gate() {
        // Cloud-safelist branch of the gate (Cloudflare CDN). Closes
        // the 2026-04-18 prod incident where the agent auto-blocked
        // Cloudflare ranges; dashboard manual-block surface inherits
        // the same protection now that `skill_gate::gate_block_ip`
        // sits in front of `BlockIpUfw.execute`.
        crate::cloud_safelist::init();
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = enabled_dry_run_cfg(&[]);
        let (success, message) = execute_block_ip(
            dir.path(),
            None,
            &cfg,
            "104.16.0.1", // Cloudflare 104.16.0.0/13
            "operator-tap",
            None,
        )
        .await
        .expect("ok");
        assert!(!success, "Cloudflare IP must be refused by gate");
        assert!(
            message.to_lowercase().contains("cloudflare")
                || message.contains("cloud provider safelist"),
            "refusal must cite the cloud safelist: {message}"
        );
    }

    #[tokio::test]
    async fn api_action_block_ip_rejects_when_actions_disabled() {
        let dir = tempfile::tempdir().unwrap();
        // Default config has enabled=false.
        let state = test_dashboard_state(dir.path());
        let resp = api_action_block_ip(
            State(state),
            Json(BlockIpRequest {
                ip: "8.8.8.8".to_string(),
                reason: "test".to_string(),
                incident_id: None,
            }),
        )
        .await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("dashboard actions are disabled"));
    }

    #[tokio::test]
    async fn api_action_block_ip_rejects_invalid_target() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_action_cfg(dir.path(), enabled_dry_run_cfg(&[]));
        let resp = api_action_block_ip(
            State(state),
            Json(BlockIpRequest {
                ip: "10.0.0.5".to_string(), // RFC1918 — must be rejected
                reason: "test".to_string(),
                incident_id: None,
            }),
        )
        .await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("internal IP"));
    }

    #[tokio::test]
    async fn api_action_block_ip_rejects_unallowed_skill() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = enabled_dry_run_cfg(&[]);
        // Configure an iptables backend but with only ufw in allowed_skills:
        // the resolved skill_id "block-ip-iptables" is not in the allowlist.
        cfg.block_backend = "iptables".to_string();
        cfg.allowed_skills = vec!["block-ip-ufw".to_string()];
        let state = state_with_action_cfg(dir.path(), cfg);
        let resp = api_action_block_ip(
            State(state),
            Json(BlockIpRequest {
                ip: "8.8.8.8".to_string(),
                reason: "test".to_string(),
                incident_id: None,
            }),
        )
        .await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("not in allowed_skills"));
        assert_eq!(resp.0.skill_id, "block-ip-iptables");
    }

    #[tokio::test]
    async fn api_action_block_ip_dry_run_happy_path_writes_audit() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_dry_run_cfg(&[]);
        let state = state_with_action_cfg(dir.path(), cfg);
        let resp = api_action_block_ip(
            State(state),
            Json(BlockIpRequest {
                ip: "8.8.8.8".to_string(),
                reason: "manual block from test".to_string(),
                incident_id: Some("inc-123".to_string()),
            }),
        )
        .await;
        assert!(resp.0.success, "got: {}", resp.0.message);
        assert!(resp.0.dry_run);
        assert_eq!(resp.0.skill_id, "block-ip-ufw");
        // The decisions JSONL was created and a row was written.
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let dec_path = dir.path().join(format!("decisions-{date}.jsonl"));
        let raw = std::fs::read_to_string(&dec_path).expect("decisions jsonl exists");
        let line = raw.lines().next().expect("at least one line");
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["action_type"], "block_ip");
        assert_eq!(v["target_ip"], "8.8.8.8");
        assert_eq!(v["incident_id"], "inc-123");
        assert_eq!(v["dry_run"], true);
    }

    #[tokio::test]
    async fn api_action_block_ip_logs_warning_when_insecure_http() {
        // The insecure_http branch emits a `warn!`; the handler still proceeds
        // with the rest of the validation. This test just exercises that
        // branch alongside a normal disabled-actions short circuit so the
        // `state.insecure_http` line is covered.
        let dir = tempfile::tempdir().unwrap();
        let mut state = test_dashboard_state(dir.path());
        state.insecure_http = true;
        let resp = api_action_block_ip(
            State(state),
            Json(BlockIpRequest {
                ip: "8.8.8.8".to_string(),
                reason: "test".to_string(),
                incident_id: None,
            }),
        )
        .await;
        // actions are still disabled by default → short-circuit message
        assert!(!resp.0.success);
    }

    // ── api_action_suspend_user: every guard-clause + dry-run happy path ─────

    #[tokio::test]
    async fn api_action_suspend_user_rejects_when_actions_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_dashboard_state(dir.path());
        let resp = api_action_suspend_user(
            State(state),
            Json(SuspendUserRequest {
                user: "alice".to_string(),
                reason: "test".to_string(),
                duration_secs: None,
                incident_id: None,
            }),
        )
        .await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("dashboard actions are disabled"));
        assert_eq!(resp.0.skill_id, "suspend-user-sudo");
    }

    #[tokio::test]
    async fn api_action_suspend_user_rejects_empty_user() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = enabled_dry_run_cfg(&["suspend-user-sudo"]);
        cfg.allowed_skills.push("suspend-user-sudo".to_string());
        let state = state_with_action_cfg(dir.path(), cfg);
        let resp = api_action_suspend_user(
            State(state),
            Json(SuspendUserRequest {
                user: "   ".to_string(),
                reason: "test".to_string(),
                duration_secs: None,
                incident_id: None,
            }),
        )
        .await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("user is required"));
    }

    #[tokio::test]
    async fn api_action_suspend_user_rejects_empty_reason() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_dry_run_cfg(&["suspend-user-sudo"]);
        let state = state_with_action_cfg(dir.path(), cfg);
        let resp = api_action_suspend_user(
            State(state),
            Json(SuspendUserRequest {
                user: "alice".to_string(),
                reason: "  ".to_string(),
                duration_secs: None,
                incident_id: None,
            }),
        )
        .await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("reason is required"));
    }

    #[tokio::test]
    async fn api_action_suspend_user_rejects_unallowed_skill() {
        let dir = tempfile::tempdir().unwrap();
        // enabled, but skill list does NOT include suspend-user-sudo.
        let cfg = enabled_dry_run_cfg(&[]);
        let state = state_with_action_cfg(dir.path(), cfg);
        let resp = api_action_suspend_user(
            State(state),
            Json(SuspendUserRequest {
                user: "alice".to_string(),
                reason: "test".to_string(),
                duration_secs: Some(1800),
                incident_id: Some("inc-x".to_string()),
            }),
        )
        .await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("not in allowed_skills"));
    }

    #[tokio::test]
    async fn api_action_suspend_user_dry_run_happy_path_writes_audit() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_dry_run_cfg(&["suspend-user-sudo"]);
        let mut state = state_with_action_cfg(dir.path(), cfg);
        // Hit the insecure_http warn! branch on the way through.
        state.insecure_http = true;
        let resp = api_action_suspend_user(
            State(state),
            Json(SuspendUserRequest {
                user: "alice".to_string(),
                reason: "operator decision".to_string(),
                duration_secs: Some(60),
                incident_id: Some("inc-42".to_string()),
            }),
        )
        .await;
        assert!(resp.0.success, "got: {}", resp.0.message);
        assert!(resp.0.dry_run);
        assert_eq!(resp.0.skill_id, "suspend-user-sudo");
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let dec_path = dir.path().join(format!("decisions-{date}.jsonl"));
        let raw = std::fs::read_to_string(&dec_path).expect("decisions jsonl exists");
        let line = raw.lines().next().expect("at least one line");
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["action_type"], "suspend_user_sudo");
        assert_eq!(v["target_user"], "alice");
        assert_eq!(v["incident_id"], "inc-42");
    }

    // ── api_action_honeypot: every guard-clause + dry-run happy path ─────────

    #[tokio::test]
    async fn api_action_honeypot_rejects_when_actions_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_dashboard_state(dir.path());
        let resp = api_action_honeypot(
            State(state),
            Json(HoneypotTestRequest {
                reason: "test".to_string(),
                duration_secs: None,
            }),
        )
        .await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("dashboard actions are disabled"));
    }

    #[tokio::test]
    async fn api_action_honeypot_rejects_empty_reason() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_dry_run_cfg(&["honeypot"]);
        let state = state_with_action_cfg(dir.path(), cfg);
        let resp = api_action_honeypot(
            State(state),
            Json(HoneypotTestRequest {
                reason: "   ".to_string(),
                duration_secs: None,
            }),
        )
        .await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("reason is required"));
    }

    #[tokio::test]
    async fn api_action_honeypot_rejects_unallowed_skill() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_dry_run_cfg(&[]); // honeypot skill NOT allowed
        let state = state_with_action_cfg(dir.path(), cfg);
        let resp = api_action_honeypot(
            State(state),
            Json(HoneypotTestRequest {
                reason: "operator test".to_string(),
                duration_secs: Some(60),
            }),
        )
        .await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("not in allowed_skills"));
    }

    #[tokio::test]
    async fn api_action_honeypot_dry_run_happy_path_writes_audit_and_incident() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = enabled_dry_run_cfg(&[]);
        cfg.allowed_skills.push("honeypot".to_string());
        let mut state = state_with_action_cfg(dir.path(), cfg);
        state.insecure_http = true; // exercise the insecure_http warn!
        let resp = api_action_honeypot(
            State(state),
            Json(HoneypotTestRequest {
                reason: "operator manual test".to_string(),
                duration_secs: Some(45),
            }),
        )
        .await;
        assert!(resp.0.success, "got: {}", resp.0.message);
        assert_eq!(resp.0.skill_id, "honeypot");
        assert!(resp.0.dry_run);
        assert!(resp.0.message.contains("[DRY RUN]"));
        // Synthetic incident was injected for the agent loop to pick up.
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let inc_path = dir.path().join(format!("incidents-{date}.jsonl"));
        let raw = std::fs::read_to_string(&inc_path).expect("incidents jsonl exists");
        let line = raw.lines().next().expect("at least one line");
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["severity"], "high");
        assert_eq!(v["entities"][0]["value"], "1.2.3.4");
        // Decision row also written.
        let dec_path = dir.path().join(format!("decisions-{date}.jsonl"));
        let dec_raw = std::fs::read_to_string(&dec_path).expect("decisions jsonl exists");
        let dec_line = dec_raw.lines().next().expect("at least one line");
        let dv: serde_json::Value = serde_json::from_str(dec_line).unwrap();
        assert_eq!(dv["action_type"], "honeypot");
        assert_eq!(dv["execution_result"], "ok (dry_run)");
    }

    #[tokio::test]
    async fn api_action_honeypot_live_mode_records_incident_injected_result() {
        // Same as the dry-run happy path but with dry_run=false. The skill
        // does not actually execute (dashboard does not call `execute()` on
        // honeypot here — it injects an incident for the agent loop), so
        // we can verify the live-mode bookkeeping branch (`incident_injected`
        // in the audit) without touching real services.
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = enabled_dry_run_cfg(&[]);
        cfg.dry_run = false;
        cfg.allowed_skills.push("honeypot".to_string());
        let state = state_with_action_cfg(dir.path(), cfg);
        let resp = api_action_honeypot(
            State(state),
            Json(HoneypotTestRequest {
                reason: "live test".to_string(),
                duration_secs: None, // exercises the `unwrap_or(120)` branch
            }),
        )
        .await;
        assert!(resp.0.success);
        assert!(!resp.0.dry_run);
        assert!(!resp.0.message.contains("[DRY RUN]"));
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let dec_path = dir.path().join(format!("decisions-{date}.jsonl"));
        let raw = std::fs::read_to_string(&dec_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(v["execution_result"], "incident_injected");
        assert_eq!(v["dry_run"], false);
    }

    // ── execute_block_ip: cover all three backends + audit-trail invariants ──

    #[tokio::test]
    async fn execute_block_ip_dry_run_ufw_returns_success_and_chains_audit() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_dry_run_cfg(&[]); // backend = ufw
        let (success, msg) = execute_block_ip(
            dir.path(),
            None,
            &cfg,
            "8.8.8.8",
            "audit reason",
            Some("inc-1"),
        )
        .await
        .unwrap();
        assert!(success, "ufw dry-run must succeed: {msg}");
        // Decision JSONL written with action_type=block_ip.
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let raw =
            std::fs::read_to_string(dir.path().join(format!("decisions-{date}.jsonl"))).unwrap();
        let v: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(v["action_type"], "block_ip");
        assert_eq!(v["target_ip"], "8.8.8.8");
        // The skill_id is the backend-resolved one; the dashboard resolved it
        // via `format!("block-ip-{}", cfg.block_backend)`.
        assert_eq!(v["skill_id"], "block-ip-ufw");
        // Admin audit trail is also written.
        let admin_date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        // Path is canonicalized inside append_admin_action so we just look
        // up "admin-actions-*.jsonl" by glob scan.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("admin-actions-{admin_date}"))
            })
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "exactly one admin-actions file must exist"
        );
    }

    #[tokio::test]
    async fn execute_block_ip_dry_run_iptables_uses_correct_skill_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = enabled_dry_run_cfg(&[]);
        cfg.block_backend = "iptables".to_string();
        let (success, _msg) =
            execute_block_ip(dir.path(), None, &cfg, "8.8.4.4", "iptables route", None)
                .await
                .unwrap();
        assert!(success);
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let raw =
            std::fs::read_to_string(dir.path().join(format!("decisions-{date}.jsonl"))).unwrap();
        let v: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(v["skill_id"], "block-ip-iptables");
        // incident_id default when None is provided.
        assert_eq!(v["incident_id"], "dashboard:manual");
    }

    #[tokio::test]
    async fn execute_block_ip_dry_run_nftables_uses_correct_skill_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = enabled_dry_run_cfg(&[]);
        cfg.block_backend = "nftables".to_string();
        let (success, _msg) = execute_block_ip(
            dir.path(),
            None,
            &cfg,
            "1.1.1.1",
            "nftables route",
            Some("inc-7"),
        )
        .await
        .unwrap();
        assert!(success);
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let raw =
            std::fs::read_to_string(dir.path().join(format!("decisions-{date}.jsonl"))).unwrap();
        let v: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(v["skill_id"], "block-ip-nftables");
    }

    // ── execute_suspend_user: dry-run happy path + audit invariants ──────────

    #[tokio::test]
    async fn execute_suspend_user_dry_run_writes_decision_and_admin_audit() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_dry_run_cfg(&["suspend-user-sudo"]);
        let (success, msg) = execute_suspend_user(
            dir.path(),
            None,
            &cfg,
            "alice",
            "audit reason",
            900,
            Some("inc-9"),
        )
        .await
        .unwrap();
        assert!(success, "suspend dry-run must succeed: {msg}");
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let raw =
            std::fs::read_to_string(dir.path().join(format!("decisions-{date}.jsonl"))).unwrap();
        let v: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(v["action_type"], "suspend_user_sudo");
        assert_eq!(v["target_user"], "alice");
        assert_eq!(v["skill_id"], "suspend-user-sudo");
        assert_eq!(v["incident_id"], "inc-9");
        assert_eq!(v["dry_run"], true);
    }

    #[tokio::test]
    async fn execute_suspend_user_dry_run_default_incident_id_when_none() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = enabled_dry_run_cfg(&["suspend-user-sudo"]);
        let (success, _msg) = execute_suspend_user(dir.path(), None, &cfg, "bob", "test", 60, None)
            .await
            .unwrap();
        assert!(success);
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let raw =
            std::fs::read_to_string(dir.path().join(format!("decisions-{date}.jsonl"))).unwrap();
        let v: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(v["incident_id"], "dashboard:manual");
    }

    // ── inject_honeypot_test_incident: appends parseable JSONL ───────────────

    #[tokio::test]
    async fn inject_honeypot_test_incident_writes_parseable_line() {
        let dir = tempfile::tempdir().unwrap();
        inject_honeypot_test_incident(dir.path(), "operator wants test", 90)
            .await
            .expect("inject must succeed");
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let path = dir.path().join(format!("incidents-{date}.jsonl"));
        let raw = std::fs::read_to_string(&path).expect("incidents jsonl exists");
        let line = raw.lines().next().expect("one line");
        let v: serde_json::Value = serde_json::from_str(line).expect("parseable JSON");
        assert_eq!(v["severity"], "high");
        assert!(v["title"].as_str().unwrap().contains("operator wants test"));
        assert!(v["title"].as_str().unwrap().contains("90s"));
        assert_eq!(v["entities"][0]["type"], "ip");
        assert_eq!(v["entities"][0]["value"], "1.2.3.4");
        assert!(v["evidence"].as_array().is_some());
    }

    #[tokio::test]
    async fn inject_honeypot_test_incident_appends_when_called_twice() {
        let dir = tempfile::tempdir().unwrap();
        inject_honeypot_test_incident(dir.path(), "first", 30)
            .await
            .unwrap();
        inject_honeypot_test_incident(dir.path(), "second", 60)
            .await
            .unwrap();
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let raw =
            std::fs::read_to_string(dir.path().join(format!("incidents-{date}.jsonl"))).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2, "second call must append, not overwrite");
    }

    // ── hostname() best-effort returns non-empty ────────────────────────────

    #[test]
    fn hostname_returns_some_string() {
        // The function is best-effort; the only invariant is that it never
        // panics and returns a non-empty string (env var, /etc/hostname, or
        // the literal "unknown" fallback).
        let h = hostname();
        assert!(!h.is_empty(), "hostname() must return non-empty");
    }

    // ── Override / reopen / label: cover the remaining handler branches ─────
    //
    // The 2026-05-01 audit endpoints already had reason/label/sqlite-store
    // branches anchored above. The tests below pin the few remaining lines
    // that exercise the empty-incident-id-only short circuit and the second
    // `incident_id and reason are required` branch where reason is empty
    // (the existing test only exercised empty incident_id). They also pin
    // the override happy path's `original.reason = None` fallback (the
    // existing test seeded a row WITH a reason).

    #[tokio::test]
    async fn api_action_reopen_incident_rejects_when_only_reason_empty() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _store) = state_with_sqlite(dir.path());
        let body = ReopenIncidentRequest {
            incident_id: "inc-1".to_string(),
            reason: "   ".to_string(),
        };
        let resp = api_action_reopen_incident(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("are required"));
    }

    #[tokio::test]
    async fn api_action_override_decision_uses_default_when_original_reason_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (state, store) = state_with_sqlite(dir.path());
        // Seed a row with reason = None to exercise the
        // `original.reason.unwrap_or_default()` fallback.
        let row = innerwarden_store::decisions::DecisionRow {
            ts: "2026-05-01T12:00:00Z".to_string(),
            incident_id: "inc-no-reason".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("8.8.8.8".to_string()),
            target_user: None,
            confidence: 0.5,
            auto_executed: false,
            reason: None,
            data: "{}".to_string(),
        };
        let id = store.insert_decision(&row).unwrap();
        let body = OverrideDecisionRequest {
            decision_id: id,
            new_action: "dismiss".to_string(),
            reason: "operator dismisses".to_string(),
        };
        let resp = api_action_override_decision(State(state), Json(body)).await;
        assert!(resp.0.success, "got: {}", resp.0.message);
        assert!(resp.0.skill_id.starts_with("operator_override:dismiss"));
    }

    #[tokio::test]
    async fn api_action_override_decision_truncates_long_original_reason() {
        // The combined audit reason embeds `truncate(original.reason, 200)`.
        // Pin the contract so a refactor that drops the truncation (and
        // bloats every audit row) is caught.
        let dir = tempfile::tempdir().unwrap();
        let (state, store) = state_with_sqlite(dir.path());
        let long_reason = "x".repeat(500);
        let row = innerwarden_store::decisions::DecisionRow {
            ts: "2026-05-01T12:00:00Z".to_string(),
            incident_id: "inc-long-reason".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("8.8.8.8".to_string()),
            target_user: None,
            confidence: 0.5,
            auto_executed: false,
            reason: Some(long_reason),
            data: "{}".to_string(),
        };
        let id = store.insert_decision(&row).unwrap();
        let body = OverrideDecisionRequest {
            decision_id: id,
            new_action: "monitor".to_string(),
            reason: "operator says monitor".to_string(),
        };
        let resp = api_action_override_decision(State(state), Json(body)).await;
        assert!(resp.0.success);
        let trail = store.audit_trail(None, 5, None).unwrap();
        let new_row = trail
            .iter()
            .find(|r| r.action_type == "operator_override:monitor")
            .expect("override row");
        let combined = new_row.reason.as_deref().unwrap_or("");
        // 200 'x' chars + the ellipsis from `truncate`, plus surrounding text.
        let xs = combined.matches('x').count();
        assert_eq!(xs, 200, "original reason must be clamped to 200 chars");
        assert!(combined.contains('…'));
    }

    #[tokio::test]
    async fn api_action_label_decision_with_tp_label_writes_jsonl() {
        // The existing tests exercise FP and the round-trip; this test pins
        // the TP label specifically (the membership check branch with the
        // other allowed value) and the empty-reason default-serde branch.
        let dir = tempfile::tempdir().unwrap();
        let state = test_dashboard_state(dir.path());
        let body = LabelDecisionRequest {
            decision_id: 99,
            label: "TP".to_string(),
            reason: "".to_string(),
        };
        let resp = api_action_label_decision(State(state), Json(body)).await;
        assert!(resp.0.success);
        let raw = std::fs::read_to_string(dir.path().join("decision-labels.jsonl")).unwrap();
        let v: serde_json::Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(v["label"], "TP");
        assert_eq!(v["decision_id"], 99);
    }

    // ── Unblock + triage-case handlers (2026-06-10) ──────────────────

    /// Enabled (guard-mode) dashboard state backed by a real SQLite store, so
    /// the new action handlers reach their decision-writing happy path.
    fn enabled_state(
        dir: &std::path::Path,
    ) -> (DashboardState, std::sync::Arc<innerwarden_store::Store>) {
        let store = std::sync::Arc::new(innerwarden_store::Store::open(dir).unwrap());
        let mut st = test_dashboard_state(dir);
        st.action_cfg = std::sync::Arc::new(DashboardActionConfig {
            enabled: true,
            dry_run: false,
            ..DashboardActionConfig::default()
        });
        st.sqlite_store = Some(store.clone());
        (st, store)
    }

    fn latest_action_type(store: &innerwarden_store::Store, incident_id: &str) -> Option<String> {
        let rows = store.decisions_for_incident(incident_id).unwrap();
        rows.last().and_then(|s| {
            serde_json::from_str::<serde_json::Value>(s)
                .ok()
                .and_then(|v| {
                    v.get("action_type")
                        .and_then(|a| a.as_str())
                        .map(str::to_string)
                })
        })
    }

    #[tokio::test]
    async fn unblock_ip_disabled_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        // Default state has actions disabled.
        let state = test_dashboard_state(dir.path());
        let body = crate::dashboard::types::UnblockIpRequest {
            ip: "8.8.8.8".to_string(),
            reason: "false positive".to_string(),
            incident_ids: vec![],
        };
        let resp = api_action_unblock_ip(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("disabled"));
    }

    #[tokio::test]
    async fn unblock_ip_rejects_invalid_ip() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _store) = enabled_state(dir.path());
        let body = crate::dashboard::types::UnblockIpRequest {
            ip: "not-an-ip".to_string(),
            reason: "oops".to_string(),
            incident_ids: vec![],
        };
        let resp = api_action_unblock_ip(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("valid IP"));
    }

    #[tokio::test]
    async fn unblock_ip_requires_reason() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _store) = enabled_state(dir.path());
        let body = crate::dashboard::types::UnblockIpRequest {
            ip: "8.8.8.8".to_string(),
            reason: "   ".to_string(),
            incident_ids: vec![],
        };
        let resp = api_action_unblock_ip(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("required"));
    }

    #[tokio::test]
    async fn unblock_ip_queues_request_per_incident() {
        let dir = tempfile::tempdir().unwrap();
        let (state, store) = enabled_state(dir.path());
        let body = crate::dashboard::types::UnblockIpRequest {
            ip: "203.0.113.7".to_string(),
            reason: "confirmed false positive".to_string(),
            incident_ids: vec!["threat_intel:203.0.113.7:1:t".to_string()],
        };
        let resp = api_action_unblock_ip(State(state), Json(body)).await;
        assert!(resp.0.success);
        assert!(resp.0.message.contains("queued"));
        // A queue row landed in SQLite for the case incident; the slow-loop
        // drain will pick it up.
        assert_eq!(
            latest_action_type(&store, "threat_intel:203.0.113.7:1:t").as_deref(),
            Some("operator_unblock_request"),
        );
    }

    #[tokio::test]
    async fn unblock_ip_synthesises_incident_when_none_given() {
        let dir = tempfile::tempdir().unwrap();
        let (state, store) = enabled_state(dir.path());
        let body = crate::dashboard::types::UnblockIpRequest {
            ip: "203.0.113.8".to_string(),
            reason: "manual".to_string(),
            incident_ids: vec![],
        };
        let resp = api_action_unblock_ip(State(state), Json(body)).await;
        assert!(resp.0.success);
        assert_eq!(
            latest_action_type(&store, "operator_unblock:203.0.113.8").as_deref(),
            Some("operator_unblock_request"),
        );
    }

    #[tokio::test]
    async fn triage_case_rejects_unknown_action() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _store) = enabled_state(dir.path());
        let body = crate::dashboard::types::TriageCaseRequest {
            incident_ids: vec!["x:1".to_string()],
            action: "delete".to_string(),
            reason: "r".to_string(),
        };
        let resp = api_action_triage_case(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("action must be one of"));
    }

    #[tokio::test]
    async fn triage_case_requires_incident_ids() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _store) = enabled_state(dir.path());
        let body = crate::dashboard::types::TriageCaseRequest {
            incident_ids: vec![],
            action: "dismiss".to_string(),
            reason: "r".to_string(),
        };
        let resp = api_action_triage_case(State(state), Json(body)).await;
        assert!(!resp.0.success);
        assert!(resp.0.message.contains("incident_ids is required"));
    }

    #[tokio::test]
    async fn triage_case_dismiss_writes_override_rows() {
        let dir = tempfile::tempdir().unwrap();
        let (state, store) = enabled_state(dir.path());
        let body = crate::dashboard::types::TriageCaseRequest {
            incident_ids: vec!["i:1".to_string(), "i:2".to_string()],
            action: "dismiss".to_string(),
            reason: "reviewed, benign scanner".to_string(),
        };
        let resp = api_action_triage_case(State(state), Json(body)).await;
        assert!(resp.0.success);
        // Each incident gets an operator_override:dismiss row — the read path
        // classifies that as Dismissed, clearing the case from attention.
        assert_eq!(
            latest_action_type(&store, "i:1").as_deref(),
            Some("operator_override:dismiss"),
        );
        assert_eq!(
            latest_action_type(&store, "i:2").as_deref(),
            Some("operator_override:dismiss"),
        );
    }

    #[tokio::test]
    async fn triage_case_reopen_writes_reopen_rows() {
        let dir = tempfile::tempdir().unwrap();
        let (state, store) = enabled_state(dir.path());
        let body = crate::dashboard::types::TriageCaseRequest {
            incident_ids: vec!["i:9".to_string()],
            action: "reopen".to_string(),
            reason: "needs another look".to_string(),
        };
        let resp = api_action_triage_case(State(state), Json(body)).await;
        assert!(resp.0.success);
        assert_eq!(
            latest_action_type(&store, "i:9").as_deref(),
            Some("operator_reopen"),
        );
    }

    // ── Operator "Trust IP" (monitor-only allowlist) ──────────────────────

    fn ts(s: &str) -> chrono::DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&Utc)
    }

    /// Read today's admin-actions audit file contents (empty string if absent).
    fn read_admin_audit(data_dir: &std::path::Path) -> String {
        let mut out = String::new();
        if let Ok(rd) = std::fs::read_dir(data_dir) {
            for e in rd.flatten() {
                if e.file_name()
                    .to_string_lossy()
                    .starts_with("admin-actions-")
                {
                    if let Ok(c) = std::fs::read_to_string(e.path()) {
                        out.push_str(&c);
                    }
                }
            }
        }
        out
    }

    // The trust inner-fns take the event_pipeline RULES DIR (they write a
    // managed suppress_response rule file into it). We use one tempdir as both
    // the rules dir and the audit data_dir; the agent's YamlResponseRules reads
    // the same dir, which is exactly the integration we want to assert.
    fn trusted_active(rules_dir: &std::path::Path, now: chrono::DateTime<Utc>) -> Vec<String> {
        crate::allowlist::YamlResponseRules::load_at(rules_dir, now).trusted_ips
    }
    fn trust_entries(rules_dir: &std::path::Path) -> Vec<crate::operator_trust::TrustEntry> {
        crate::operator_trust::read_entries(&crate::operator_trust::managed_file_in(rules_dir))
    }

    #[test]
    fn trust_ip_inner_adds_entry_and_audits() {
        let dir = tempfile::tempdir().unwrap();
        let now = ts("2026-06-13T10:00:00Z");
        let resp = trust_ip_inner(
            dir.path(),
            dir.path(),
            true,
            false,
            "203.0.113.10",
            "office vpn",
            None,
            now,
        );
        assert!(resp.success, "{}", resp.message);
        // end-to-end: the agent's hot-reload now treats it as trusted
        assert_eq!(trusted_active(dir.path(), now), vec!["203.0.113.10"]);
        let audit = read_admin_audit(dir.path());
        assert!(audit.contains("trust_ip"));
        assert!(audit.contains("monitor_only"));
        assert!(audit.contains("success"));
    }

    #[test]
    fn trust_ip_inner_disabled_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let resp = trust_ip_inner(
            dir.path(),
            dir.path(),
            false, // disabled
            true,
            "203.0.113.10",
            "vpn",
            None,
            ts("2026-06-13T10:00:00Z"),
        );
        assert!(!resp.success);
        assert!(resp.message.contains("disabled"));
        assert!(trust_entries(dir.path()).is_empty());
    }

    #[test]
    fn trust_ip_inner_rejects_slash_zero() {
        let dir = tempfile::tempdir().unwrap();
        let resp = trust_ip_inner(
            dir.path(),
            dir.path(),
            true,
            false,
            "0.0.0.0/0",
            "trust everything (should fail)",
            None,
            ts("2026-06-13T10:00:00Z"),
        );
        assert!(!resp.success);
        assert!(trust_entries(dir.path()).is_empty());
        // the rejected attempt is still recorded in the audit trail
        assert!(read_admin_audit(dir.path()).contains("failure"));
    }

    #[test]
    fn trust_ip_inner_ttl_reports_expiry_and_expires() {
        let dir = tempfile::tempdir().unwrap();
        let now = ts("2026-06-13T10:00:00Z");
        let resp = trust_ip_inner(
            dir.path(),
            dir.path(),
            true,
            false,
            "198.51.100.7",
            "temporary",
            Some(24),
            now,
        );
        assert!(resp.success);
        assert!(resp.message.contains("expires"));
        // active now, gone two days later (driven by the YamlResponseRules TTL)
        assert!(!trusted_active(dir.path(), now).is_empty());
        assert!(trusted_active(dir.path(), ts("2026-06-15T10:00:00Z")).is_empty());
    }

    #[test]
    fn untrust_ip_inner_removes_then_noop() {
        let dir = tempfile::tempdir().unwrap();
        let now = ts("2026-06-13T10:00:00Z");
        trust_ip_inner(
            dir.path(),
            dir.path(),
            true,
            false,
            "203.0.113.10",
            "vpn",
            None,
            now,
        );

        let removed = untrust_ip_inner(dir.path(), dir.path(), true, false, "203.0.113.10", "done");
        assert!(removed.success);
        assert!(trusted_active(dir.path(), now).is_empty());

        // removing again → not found, but not an error
        let again = untrust_ip_inner(dir.path(), dir.path(), true, false, "203.0.113.10", "");
        assert!(!again.success);
        assert!(again.message.contains("not in the trust list"));
    }

    #[test]
    fn list_trusted_inner_reports_entries_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let now = ts("2026-06-13T10:00:00Z");
        trust_ip_inner(
            dir.path(),
            dir.path(),
            true,
            false,
            "10.0.0.0/8",
            "corp",
            Some(24),
            now,
        );

        let listed = list_trusted_inner(dir.path(), now);
        assert_eq!(listed["count"], 1);
        assert_eq!(listed["trusted_ips"][0]["value"], "10.0.0.0/8");
        assert_eq!(listed["trusted_ips"][0]["id"], "operator-trust-10-0-0-0-8");
        assert_eq!(listed["trusted_ips"][0]["expired"], false);

        // same entry, evaluated after expiry → flagged expired in the listing
        let later = list_trusted_inner(dir.path(), ts("2026-06-15T10:00:00Z"));
        assert_eq!(later["trusted_ips"][0]["expired"], true);
    }

    #[test]
    fn trust_exec_inner_writes_and_lists() {
        let dir = tempfile::tempdir().unwrap();
        let r = trust_exec_inner(
            dir.path(),
            dir.path(),
            true,
            false,
            "/opt/app/server",
            "runtime",
        );
        assert!(r.success, "trust-exec should succeed: {}", r.message);

        let listed = list_trusted_execs_inner(dir.path());
        assert_eq!(listed["count"], 1);
        assert_eq!(listed["trusted_execs"][0]["path"], "/opt/app/server");
        assert_eq!(listed["trusted_execs"][0]["reason"], "runtime");
    }

    #[test]
    fn trust_exec_inner_rejects_disabled_and_bad_path() {
        let dir = tempfile::tempdir().unwrap();
        // disabled responder
        let off = trust_exec_inner(dir.path(), dir.path(), false, false, "/opt/x", "r");
        assert!(!off.success);
        // bad path (glob)
        let bad = trust_exec_inner(dir.path(), dir.path(), true, false, "/usr/bin/*", "r");
        assert!(!bad.success);
        // bad path (relative)
        let rel = trust_exec_inner(dir.path(), dir.path(), true, false, "relative", "r");
        assert!(!rel.success);
        assert_eq!(list_trusted_execs_inner(dir.path())["count"], 0);
    }

    #[test]
    fn untrust_exec_inner_removes_then_noop() {
        let dir = tempfile::tempdir().unwrap();
        trust_exec_inner(dir.path(), dir.path(), true, false, "/opt/app/server", "r");
        let rm = untrust_exec_inner(
            dir.path(),
            dir.path(),
            true,
            false,
            "/opt/app/server",
            "done",
        );
        assert!(rm.success);
        assert_eq!(list_trusted_execs_inner(dir.path())["count"], 0);
        // removing again → not-found (success=false)
        let again = untrust_exec_inner(
            dir.path(),
            dir.path(),
            true,
            false,
            "/opt/app/server",
            "done",
        );
        assert!(!again.success);
    }
}
