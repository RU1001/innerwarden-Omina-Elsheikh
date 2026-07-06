use std::path::Path;

use tracing::{info, warn};

use crate::{
    abuseipdb, ai, config,
    response_lifecycle::{ResponseBackend, ResponseType},
    skills, AgentState,
};

/// Outcome of the standalone `block-ip-xdp` skill, captured so the
/// shield-vs-standalone decision can defer the XDP-unavailable WARN.
///
/// Pre-2026-05-08 the shield-path failure called `mark_failed`
/// inline, which fired the operator-facing "XDP firewall unavailable"
/// WARN immediately. The standalone fallback that ran milliseconds
/// later might succeed (the prod regression on 2026-05-08 was exactly
/// this — the operator saw "XDP unavailable" + "blocked via XDP" on
/// the same timestamp). The fix collects both outcomes and only
/// emits the WARN when no XDP path succeeded.
pub(crate) enum StandaloneXdpOutcome {
    /// Standalone path was not run (gate skipped, shield already
    /// succeeded, or no `block-ip-xdp` skill registered).
    NotAttempted,
    /// Standalone path ran and the bpftool map update succeeded.
    Succeeded,
    /// Standalone path ran and the bpftool map update failed; carries
    /// the error message destined for `mark_failed`.
    Failed(String),
}

/// Stricter target validator for AUTOMATED block paths
/// (repeat-offender, multi-technique, AI router output).
///
/// `is_valid_block_target` deliberately accepts CIDRs because operators
/// can manually run `innerwarden block 10.0.0.0/24` to ban a botnet
/// network. But automated paths must NEVER emit CIDRs — a single
/// hallucinated `/16` from the AI router or a CIDR slipping into
/// `ip_reputations` from a downstream upstream feed creates a
/// self-reinforcing loop: the repeat-offender path reads the key,
/// re-emits BlockIp on the CIDR, the safeguards bump its block_count,
/// and on the next tick the same CIDR re-fires. Operator's prod
/// 2026-05-08 had `136.216.0.0/16` cycling every 2h since 2026-05-07
/// (15 historical "blocks", same target_ip = a /16 CIDR — that would
/// have been a UFW rule banning a /16 of public IP space).
///
/// 2026-05-08 (fix/automated-block-paths-reject-cidr): this helper is
/// the gate at the entry of every automated block emitter. Manual
/// operator commands keep using `is_valid_block_target` so the
/// `innerwarden block` CLI path is unchanged.
pub(crate) fn is_single_ip_block_target(ip: &str) -> bool {
    if ip.contains('/') {
        return false;
    }
    is_valid_block_target(ip)
}

/// Decide whether the XDP-unavailable WARN should fire given the
/// outcomes of both XDP attempts in a single block decision.
///
/// Returns:
/// - `None` when no WARN should fire — either no path failed, or at
///   least one path succeeded (the gate is healthy from the operator's
///   perspective even if one of the two attempts errored).
/// - `Some((context, details))` to pass to
///   `xdp_availability::mark_failed` when ALL XDP paths failed. The
///   standalone failure wins precedence because it's the path-of-last
///   -resort; if shield ALSO failed its details are folded in.
pub(crate) fn xdp_failure_to_warn(
    shield_failure: Option<(&'static str, String)>,
    standalone: StandaloneXdpOutcome,
) -> Option<(&'static str, String)> {
    match standalone {
        StandaloneXdpOutcome::Succeeded => None,
        StandaloneXdpOutcome::Failed(msg) => Some((
            "block-ip-xdp skill",
            // Fold the shield error into the message if both failed —
            // operator's recovery work then sees the full picture.
            match shield_failure {
                Some((_, shield_err)) => {
                    format!("{msg}; shield xdp_manager also failed: {shield_err}")
                }
                None => msg,
            },
        )),
        StandaloneXdpOutcome::NotAttempted => shield_failure,
    }
}

/// Extract the source-process identity `(pid, comm, read_path)` from an
/// incident's `evidence`, tolerating both the array-of-one shape the eBPF
/// detectors + killchain tracker emit (`evidence: [{...}]`) and a bare object.
///
/// For `data_exfil_ebpf` the evidence keys are `comm`, `pid`, `sensitive_file`
/// (per `crates/sensor/src/detectors/data_exfil_ebpf.rs`); for the killchain
/// tracker they are `comm`, `pid`, `pattern` (no read path). Returns `None`
/// when there is no pid to attribute (then there is no source to verify and the
/// block proceeds).
fn incident_source_identity(
    incident: &innerwarden_core::incident::Incident,
) -> Option<(u32, String, Option<String>)> {
    let ev = match &incident.evidence {
        serde_json::Value::Array(arr) => arr.first()?,
        obj @ serde_json::Value::Object(_) => obj,
        _ => return None,
    };
    let pid = ev.get("pid").and_then(|p| p.as_u64())? as u32;
    let comm = ev
        .get("comm")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    let read_path = ev
        .get("sensitive_file")
        .and_then(|p| p.as_str())
        .map(|s| s.to_string());
    Some((pid, comm, read_path))
}

/// Spec 081 — consult the managed-agent verifier for the incident's source
/// process. Returns `Some((agent_id, name))` ONLY when the source is a
/// positively-verified, IW-managed agent acting on its own services (the caller
/// then downgrades to monitor); `None` in every other case (no attributable
/// source, registry miss, forged identity, recycled pid, …) so the block
/// proceeds normally. Fail-closed by construction.
///
/// Clones the shared registry + signature-index `Arc`s up front so the registry
/// lock does not conflict with the `&mut state` borrow of other fields.
///
/// This thin wrapper performs the AgentState-dependent steps (non-blocking
/// `try_lock` of the shared registry, clone of the signature index, the
/// destination-reputation lookup) and then delegates the verdict to the pure-of
/// -AgentState [`evaluate_managed_agent_downgrade`] with the production
/// [`crate::managed_agent_guard::SystemProc`] resolver. Behaviour is IDENTICAL
/// to the pre-refactor inline body; the split only lets the wiring be tested
/// without a live `/proc` or a full `AgentState`.
fn managed_agent_downgrade(
    incident: &innerwarden_core::incident::Incident,
    state: &AgentState,
) -> Option<(String, String)> {
    let registry = state.agent_registry.clone();
    let sigindex = state.signature_index.clone();
    // Non-blocking try_lock: the registry mutex is only contended for the brief
    // window of an `agent connect`. If it is momentarily held, fail closed
    // (block proceeds) rather than await inside the block-decision hot path.
    let reg = registry.try_lock().ok()?;
    let resolver = crate::managed_agent_guard::SystemProc;
    evaluate_managed_agent_downgrade(
        incident,
        &reg,
        &sigindex,
        &resolver,
        // Destination-reputation refinement: when the destination IP is
        // independently known-malicious, force the block regardless of source.
        // This is a BLOCK override only — never a destination EXEMPTION.
        destination_is_known_bad(incident, state),
    )
}

/// Pure-of-`AgentState` core of the managed-agent downgrade decision (spec 081).
/// Given the incident, an already-locked registry, the signature index, a
/// `/proc` resolver, and the precomputed destination-known-bad flag, returns
/// `Some((agent_id, name))` when the incident's source is a positively-verified
/// IW-managed agent on its own services (downgrade to monitor) and `None`
/// otherwise (block proceeds).
///
/// `incident_source_identity` is the first step: with no attributable pid there
/// is no source to verify, so the block proceeds (`None`). Identical behaviour
/// to the former inline body of [`managed_agent_downgrade`]; extracting it lets
/// the wiring be exercised with a stub resolver + a hand-built registry without
/// constructing a full `AgentState`.
fn evaluate_managed_agent_downgrade(
    incident: &innerwarden_core::incident::Incident,
    registry: &innerwarden_agent_guard::registry::Registry,
    sigindex: &innerwarden_agent_guard::signatures::SignatureIndex,
    resolver: &dyn crate::managed_agent_guard::ProcResolver,
    destination_known_bad: bool,
) -> Option<(String, String)> {
    let (pid, comm, read_path) = incident_source_identity(incident)?;
    let verdict = crate::managed_agent_guard::verify_managed_agent_self_activity(
        pid,
        &comm,
        read_path.as_deref(),
        registry,
        sigindex,
        resolver,
        destination_known_bad,
    );
    match verdict {
        crate::managed_agent_guard::ManagedAgentVerdict::Managed { agent_id, name } => {
            Some((agent_id, name))
        }
        crate::managed_agent_guard::ManagedAgentVerdict::NotManaged => None,
    }
}

/// Destination-reputation hook (spec 081). Returns true when the incident's
/// destination IP is independently known-malicious, which forces the block even
/// for an otherwise-managed agent. Today this consults the in-memory local IP
/// reputation (a destination the agent itself previously confirmed bad). It is
/// deliberately conservative: a miss returns false (no block override), so the
/// managed-agent downgrade still applies for unknown destinations. NEVER turns
/// a known-bad destination into an exemption.
fn destination_is_known_bad(
    incident: &innerwarden_core::incident::Incident,
    state: &AgentState,
) -> bool {
    dst_known_bad_from(&incident.entities, &state.ip_reputations)
}

/// Pure core of [`destination_is_known_bad`]: true when any IP entity of the
/// incident has a local reputation with `total_blocks > 0` (a destination the
/// agent itself previously confirmed bad). Split from the `AgentState`-bound
/// wrapper so the lookup is unit-testable with a hand-built entity slice +
/// reputation map. Identical behaviour to the former inline body.
fn dst_known_bad_from(
    entities: &[innerwarden_core::entities::EntityRef],
    reputations: &std::collections::HashMap<String, crate::ip_reputation::LocalIpReputation>,
) -> bool {
    use innerwarden_core::entities::EntityType;
    entities
        .iter()
        .filter(|e| e.r#type == EntityType::Ip)
        .any(|e| {
            reputations
                .get(&e.value)
                .is_some_and(|r| r.total_blocks > 0)
        })
}

/// Execute the layered `BlockIp` decision path (XDP + firewall + Cloudflare + AbuseIPDB report).
pub(crate) async fn execute_block_ip_decision(
    ip: &str,
    skill_id: &str,
    decision: &ai::AiDecision,
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    // Purge stale entries BEFORE eligibility check so rate limit uses accurate count.
    let now_utc = chrono::Utc::now();
    state
        .recent_blocks
        .retain(|ts| *ts > now_utc - chrono::Duration::seconds(60));
    // Spec 037 I-07 slice 2: mirror the in-memory retain to SQLite so
    // the persisted namespace tracks the same window. Failure is
    // logged at `warn!` inside the helper and never blocks the
    // decision path.
    state
        .store
        .prune_recent_blocks_before((now_utc - chrono::Duration::seconds(60)).timestamp_millis());

    // Spec 081 — managed-agent coexistence. BEFORE we block the destination IP,
    // check whether the incident's SOURCE process is a positively-verified,
    // IW-managed AI agent acting on its OWN config / services (the OpenClaw
    // class: reads its own .env, connects to its own Slack/Azure endpoint, which
    // matches the generic sensitive-read → outbound-connect exfil/C2 signature).
    // If so, DOWNGRADE to monitor/notify — do NOT block the destination IP (a
    // shared service IP that other users depend on, and which the agent needs to
    // keep working when it rotates). The relaxation is SOURCE-based (the agent
    // identity), never destination-based, and AGENT-agnostic (any agent-guard
    // signature). The verifier fails closed, and a known-bad destination still
    // forces the block. Detection is untouched: the incident already fired and
    // was notified; this only withholds the automatic IP-block.
    if let Some((agent_id, name)) = managed_agent_downgrade(incident, state) {
        warn!(
            ip,
            incident_id = %incident.incident_id,
            agent_id = %agent_id,
            agent = %name,
            "withheld_ip_block: managed-agent-self-activity — destination {ip} block WITHHELD; \
             source is verified managed agent {agent_id} ({name}) on its own services. \
             Downgraded to monitor (incident + notification still fired). Detection unchanged."
        );
        return (
            format!(
                "downgraded to monitor: source is managed agent {agent_id} ({name}) on its \
                 own services — destination IP {ip} not blocked (spec 081)"
            ),
            false,
        );
    }

    // Circuit breaker: hard ceiling on auto-blocks per UTC hour. Catches
    // the CL-008 *class* of regression — any future correlation rule that
    // starts cascading against unrelated IPs trips this pause regardless
    // of signal source. Runs BEFORE per-minute rate limit and safelist so
    // the counter reflects attempts, not just survivors.
    if let Some(ref sq) = state.sqlite_store {
        if let Some(reason) = consult_circuit_breaker(
            sq.as_ref(),
            chrono::Utc::now(),
            ip,
            cfg.responder.max_blocks_per_hour,
            &cfg.responder.circuit_breaker_mode,
        ) {
            return (reason, false);
        }
    }

    // Safeguard: pure eligibility checks (empty IP, operator session, rate
    // limit) + cloud-provider / CDN safelist. Operator incident 2026-04-18:
    // `correlation:CL-008` + `repeat-offender` were auto-blocking Cloudflare
    // ranges (104.16.0.0/12, 104.26.0.0/15, 172.66.0.0/15, …) as a cascade —
    // a file read followed by any outbound connect within 60s triggered
    // CL-008, the response targeted the outbound IP, and the repeat-offender
    // loop multiplied the damage. The global guard here catches every block
    // path (correlation, repeat-offender, auto-rule, AbuseIPDB, AI triage,
    // honeypot) with a single check.
    if let Err(reason) = check_block_eligibility_with_safelist(
        ip,
        &state.operator_ips,
        state.recent_blocks.len(),
        crate::MAX_BLOCKS_PER_MINUTE,
        // 2026-05-08 (fix/repeat-offender-safelist-bypass): use the
        // CIDR-accurate `safelist_label`, not the first-octet
        // heuristic `identify_provider`. The heuristic missed
        // 208.95.112.0/24 (ip-api.com), 91.189.88.0/21 (Canonical),
        // 199.232.0.0/16 (Fastly) — all in CLOUD_RANGES but with
        // first octets the heuristic didn't tag — so the gate
        // returned None and the block proceeded against the agent's
        // own infrastructure.
        crate::cloud_safelist::safelist_label,
    ) {
        if reason.starts_with("skipped:") {
            info!(ip, "{}", reason);
        } else {
            warn!(ip, "{}", reason);
        }
        // Stop the repeat-offender cascade: if we ever bumped this IP's
        // reputation by mistake (pre-fix production data), wipe it so the
        // next correlation burst doesn't escalate based on stale counts.
        if reason.contains("cloud provider safelist") {
            state.ip_reputations.remove(ip);
        }
        return (reason, false);
    }

    // Redundant re-block guard. If this IP already has a live (TTL-valid)
    // firewall block, the rule is already in effect — re-running the block
    // path re-adds an existing ufw/XDP rule every time a correlation rule
    // (multi-technique), repeat-offender loop, or re-fired detector targets
    // the same IP. Field evidence (oneroom Hetzner 2026-05-31): one already-
    // blocked threat-feed IP was re-blocked 9× in a day from these non-
    // incident-flow sources. Skip the redundant firewall write but report it
    // as handled (the block IS active), so the caller records a terminal
    // decision rather than a "skipped" no-op that would re-orphan. This runs
    // AFTER the safety gates (allowlist/safelist/circuit-breaker) so it can
    // never widen what gets blocked — it only suppresses a duplicate.
    // …but only skip when the firewall rule is VERIFIABLY live. The lifecycle
    // record can diverge from the actual firewall: a TTL removal that did not
    // clear the record, an agent restart that reloaded a stale set, or an
    // externally-flushed rule. Skipping on a stale record gives a repeat
    // attacker a free pass — prod 2026-06-10: hundreds of known-bad IPs were
    // "actively blocked" per the record yet absent from ufw, so every new hit
    // was skipped and never re-blocked. Verify against the live backend first.
    if state.response_lifecycle.is_ip_actively_blocked(ip, now_utc) {
        if is_ip_live_blocked(ip, skill_id).await {
            info!(
                ip,
                "already actively blocked (verified live) — skipping redundant re-block"
            );
            return (
                "already blocked: live firewall rule verified active for this IP".to_string(),
                true,
            );
        }
        warn!(
            ip,
            "lifecycle marks this IP actively blocked but no live firewall rule found — re-applying (stale record / dropped rule)"
        );
        // fall through: re-apply so a still-attacking IP never gets a free pass.
    }

    state.recent_blocks.push_back(now_utc);
    // Spec 037 I-07 slice 2: persist for warm-cache on next boot so a
    // restart does not let a `MAX_BLOCKS_PER_MINUTE` burst land in the
    // first second after recovery. Mirror runs after the in-memory
    // push_back so a SQLite failure cannot drop the rate-limit count.
    state.store.set_recent_block(now_utc);

    // Adaptive TTL: use local IP reputation to escalate block duration.
    let block_ttl_secs = {
        let total_blocks = state
            .ip_reputations
            .get(ip)
            .map(|r| r.total_blocks)
            .unwrap_or(0);
        crate::adaptive_block_ttl_secs(total_blocks)
    };

    let ctx = skills::SkillContext {
        incident: incident.clone(),
        target_ip: Some(ip.to_string()),
        target_user: None,
        target_container: None,
        duration_secs: Some(block_ttl_secs as u64),
        host: incident.host.clone(),
        data_dir: data_dir.to_path_buf(),
        honeypot: crate::honeypot_runtime(cfg),
        ai_provider: state.ai_router.any_llm(),
    };

    let mut layers_applied = Vec::new();
    let mut any_success = false;

    // Layer 1: XDP wire-speed drop (if available).
    // Prefer shield's XdpManager (unified blocklist) over standalone skill.
    //
    // 2026-05-03 (Wave 5b PR-2): both XDP attempts are gated by
    // `xdp_availability::should_attempt_xdp`. After one observed
    // failure the gate skips XDP for `RECHECK_INTERVAL_SECS` (5 min)
    // and emits exactly one operator-actionable WARN with the
    // recovery recipe. Without the gate, prod was emitting two WARN
    // lines per block decision while bpffs was unmounted, drowning
    // out real warnings.
    // 2026-05-08: collect failures from both XDP paths and only call
    // `xdp_availability::mark_failed` if NEITHER succeeded. Pre-fix,
    // the shield path's failure called `mark_failed` immediately,
    // which fired the operator-facing "XDP firewall unavailable" WARN
    // — even when the standalone skill that ran milliseconds later
    // succeeded. Operator's prod logs showed the WARN and "blocked
    // via XDP (wire-speed drop)" on the same timestamp, which is
    // straight up dishonest: XDP was working, the warning lied.
    //
    // The gate state must still record a failure when ALL XDP paths
    // fail, so `should_attempt_xdp` skips the next ~5 min and the
    // fallback (UFW/iptables) takes over silently. But a single-path
    // failure with a parallel success is no longer operator-visible.
    let xdp_should_try = crate::xdp_availability::should_attempt_xdp();
    let mut shield_failure: Option<(&'static str, String)> = None;
    let mut standalone_xdp_outcome = StandaloneXdpOutcome::NotAttempted;
    let xdp_blocked = if !xdp_should_try {
        false
    } else if let Some(ref mut shield) = state.shield_state {
        let reason = format!("agent:block:{}", incident.incident_id);
        match shield.xdp.add_to_blocklist(ip, &reason) {
            Ok(()) => {
                layers_applied.push("XDP");
                any_success = true;
                crate::xdp_availability::mark_succeeded();
                // Spec 037 PR-1: runtime first (immediate protection),
                // persist second (SQLite canonical for warm-cache on
                // restart). `set_xdp_block_time` already swallows
                // errors with a `warn!` — a persistence failure
                // degrades to pre-I-02 behaviour (TTL accounting lost
                // on restart) but never derruba the block itself.
                let blocked_at = chrono::Utc::now();
                state
                    .xdp_block_times
                    .insert(ip.to_string(), (blocked_at, block_ttl_secs));
                state
                    .store
                    .set_xdp_block_time(ip, blocked_at, block_ttl_secs);
                true
            }
            Err(e) => {
                shield_failure = Some(("shield xdp_manager", format!("{e}")));
                false
            }
        }
    } else {
        false
    };
    // Fallback: use standalone XDP skill if shield is not active AND
    // the gate still allows attempts.
    if !xdp_blocked && xdp_should_try {
        if let Some(xdp_skill) = state.skill_registry.get("block-ip-xdp") {
            let xdp_result = xdp_skill.execute(&ctx, cfg.responder.dry_run).await;
            if xdp_result.success {
                layers_applied.push("XDP");
                any_success = true;
                crate::xdp_availability::mark_succeeded();
                // Spec 037 PR-1: same ordering as the shield path —
                // runtime first, persist second with swallowed errors.
                let blocked_at = chrono::Utc::now();
                state
                    .xdp_block_times
                    .insert(ip.to_string(), (blocked_at, block_ttl_secs));
                state
                    .store
                    .set_xdp_block_time(ip, blocked_at, block_ttl_secs);
                standalone_xdp_outcome = StandaloneXdpOutcome::Succeeded;
            } else {
                standalone_xdp_outcome = StandaloneXdpOutcome::Failed(xdp_result.message);
            }
        }
    }
    if let Some((context, details)) = xdp_failure_to_warn(shield_failure, standalone_xdp_outcome) {
        crate::xdp_availability::mark_failed(context, &details);
    }

    // Layer 2: Firewall rule (ufw/iptables/nftables - configured backend).
    // The configured block_backend is always allowed, regardless of allowed_skills.
    let effective_id: String = if cfg.responder.allowed_skills.iter().any(|id| id == skill_id) {
        skill_id.to_string()
    } else {
        format!("block-ip-{}", cfg.responder.block_backend)
    };
    // Don't double-execute if the configured backend IS xdp.
    if effective_id != "block-ip-xdp" {
        if let Some(fw_skill) = state.skill_registry.get(&effective_id).or_else(|| {
            state
                .skill_registry
                .block_skill_for_backend(&cfg.responder.block_backend)
        }) {
            let fw_result = fw_skill.execute(&ctx, cfg.responder.dry_run).await;
            if fw_result.success {
                let backend = cfg.responder.block_backend.as_str();
                layers_applied.push(match backend {
                    "iptables" => "iptables",
                    "nftables" => "nftables",
                    _ => "ufw",
                });
                any_success = true;
            } else {
                warn!(
                    ip,
                    skill = effective_id,
                    reason = fw_result.message,
                    "firewall block skill execution failed"
                );
            }
        } else {
            warn!(
                ip,
                skill = effective_id,
                "firewall block skill not found in registry"
            );
        }
    }

    if any_success {
        state.blocklist.insert(ip.to_string());

        // Register firewall blocks in the response lifecycle for TTL-based auto-revert.
        // XDP is already tracked via xdp_block_times; the lifecycle tracks ufw/iptables/nftables
        // which previously had no auto-revert (rules persisted until reboot).
        for layer in &layers_applied {
            let backend = match *layer {
                "ufw" => Some(ResponseBackend::Ufw),
                "iptables" => Some(ResponseBackend::Iptables),
                "nftables" => Some(ResponseBackend::Nftables),
                "XDP" => Some(ResponseBackend::Xdp),
                _ => None,
            };
            if let Some(backend) = backend {
                if !state.response_lifecycle.is_tracked(ip, &backend) {
                    state.response_lifecycle.register(
                        ResponseType::BlockIp,
                        backend,
                        ip,
                        &incident.incident_id,
                        block_ttl_secs,
                        None, // TODO: store nftables handle when available
                    );
                }
            }
        }

        // Feedback loop: write blocked IP to file so the sensor can
        // skip events from this IP, reducing noise.
        crate::append_blocked_ip(data_dir, ip);

        // Layer 2.5: Mesh broadcast -- share with peer nodes.
        if let Some(ref mesh) = state.mesh {
            let detector = incident.incident_id.split(':').next().unwrap_or("unknown");
            let evidence = decision.reason.as_bytes();
            mesh.broadcast_local_block(
                ip,
                detector,
                decision.confidence,
                evidence,
                block_ttl_secs as u64,
            )
            .await;
            layers_applied.push("Mesh");
        }
    }

    // Layer 3: Cloudflare edge block.
    let mut cf_pushed = false;
    if any_success && cfg.cloudflare.enabled && cfg.cloudflare.auto_push_blocks {
        if let Some(ref cf) = state.cloudflare_client {
            let reason = format!("{}: {}", incident.incident_id, decision.reason);
            if let Some(rule_id) = cf.push_block(ip, &reason).await {
                info!(ip, rule_id, "Cloudflare edge block pushed");
                layers_applied.push("Cloudflare");
                cf_pushed = true;
            }
        }
    }

    // Layer 4: AbuseIPDB community report (delayed - 5 min grace period).
    // Reports are queued and sent after ABUSEIPDB_REPORT_DELAY_SECS to allow
    // false-positive correction before permanently marking an IP as malicious.
    if any_success && cfg.abuseipdb.enabled && cfg.abuseipdb.report_blocks {
        let detector = incident.incident_id.split(':').next().unwrap_or("unknown");
        let categories = abuseipdb::detector_to_categories(detector);
        let comment = format!(
            "InnerWarden auto-block: {} (confidence {:.0}%)",
            decision.reason,
            decision.confidence * 100.0
        );
        state.abuseipdb_report_queue.push((
            ip.to_string(),
            comment,
            categories.to_string(),
            chrono::Utc::now(),
        ));
        layers_applied.push("AbuseIPDB(queued)");
    }

    if any_success {
        let layers = layers_applied.join(" + ");
        (format!("Blocked {ip} via {layers}"), cf_pushed)
    } else {
        (format!("skipped: no block skill available for {ip}"), false)
    }
}

/// Returns true if `s` is a single IPv4/IPv6 address **or** a valid
/// CIDR (`<ip>/<prefix>`) that ufw / iptables / nftables will accept.
///
/// Must be called at every boundary where external data (configs,
/// ip-reputation cache, correlation decisions, AI output) could deliver a
/// string to the firewall skills. A single missed boundary reintroduces the
/// "zombie active response" bug where an invalid rule gets registered in
/// the lifecycle but cannot be reverted.
pub(crate) fn is_valid_block_target(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    match s.split_once('/') {
        Some((ip_part, prefix_part)) => match (
            ip_part.parse::<std::net::IpAddr>(),
            prefix_part.parse::<u8>(),
        ) {
            (Ok(std::net::IpAddr::V4(_)), Ok(p)) => p <= 32,
            (Ok(std::net::IpAddr::V6(_)), Ok(p)) => p <= 128,
            _ => false,
        },
        None => s.parse::<std::net::IpAddr>().is_ok(),
    }
}

/// Pure-predicate variant used by the in-tree test suite to exercise
/// eligibility rules without constructing a cloud-safelist closure. Prod
/// code routes through `check_block_eligibility_with_safelist`.
#[allow(dead_code)]
/// Consult the block-rate circuit breaker. Returns `None` when the block
/// may proceed, `Some(reason)` when it must be refused (breaker tripped,
/// already tripped this hour, or log-only mode silently counting).
///
/// Pulled out of `execute_block_ip_decision` so the decision table + all
/// four `Decision` branches are covered by plain sync unit tests below —
/// the full `execute_block_ip_decision` is async + depends on shield,
/// skills, firewall, mesh, Cloudflare, which makes direct testing of the
/// wire-in impractical.
pub(crate) fn consult_circuit_breaker(
    store: &innerwarden_store::Store,
    now: chrono::DateTime<chrono::Utc>,
    ip: &str,
    limit: u64,
    mode_label: &str,
) -> Option<String> {
    let mode = crate::circuit_breaker::Mode::from_str_or_default(mode_label);
    let decision = crate::circuit_breaker::check_and_record(store, now, limit, mode);
    match &decision {
        crate::circuit_breaker::Decision::TripAndRefuse { count, limit, hour } => {
            warn!(
                ip,
                count,
                limit,
                hour = %hour,
                mode = mode.as_label(),
                "circuit breaker tripped. Block pipeline paused until next UTC hour (or run `innerwarden system circuit-reset`)."
            );
        }
        crate::circuit_breaker::Decision::RefuseAfterTrip { count, limit, hour } => {
            info!(
                ip,
                count,
                limit,
                hour = %hour,
                "circuit breaker still tripped. Block refused silently."
            );
        }
        crate::circuit_breaker::Decision::AutoRearm { count, limit, hour } => {
            info!(
                ip,
                count,
                limit,
                hour = %hour,
                "circuit breaker auto-rearmed. New UTC hour, counters reset."
            );
        }
        crate::circuit_breaker::Decision::Allow { .. } => {}
    }
    if decision.should_block() {
        None
    } else {
        Some(format!(
            "skipped: circuit breaker tripped (blocks this hour exceed {limit})",
            limit = limit
        ))
    }
}

#[cfg(test)]
pub(crate) fn check_block_eligibility(
    ip: &str,
    operator_ips: &std::collections::HashMap<String, std::time::Instant>,
    recent_blocks_len: usize,
    max_blocks_per_min: usize,
) -> Result<(), String> {
    check_block_eligibility_with_safelist(
        ip,
        operator_ips,
        recent_blocks_len,
        max_blocks_per_min,
        |_| None,
    )
}

/// Variant that also consults a cloud-provider / CDN safelist. The safelist
/// predicate receives the candidate IP and returns `Some(provider_label)` when
/// the IP is part of a known CDN / cloud range (Cloudflare, AWS, Oracle, …);
/// in that case the block is refused outright. Keeps the base eligibility
/// check pure-testable while every production code path that routes through
/// `execute_block_ip_decision` inherits the guard.
pub(crate) fn check_block_eligibility_with_safelist<F>(
    ip: &str,
    operator_ips: &std::collections::HashMap<String, std::time::Instant>,
    recent_blocks_len: usize,
    max_blocks_per_min: usize,
    safelist_provider: F,
) -> Result<(), String>
where
    F: Fn(&str) -> Option<&'static str>,
{
    if ip.is_empty() {
        return Err("skipped: block decision has empty IP".to_string());
    }
    // Reject malformed targets — prevents ufw/iptables "Bad source address"
    // errors that otherwise leak into the response lifecycle as zombie
    // "active" entries that can never be reverted.
    if !is_valid_block_target(ip) {
        return Err(format!("skipped: {ip} is not a valid IP address"));
    }
    if let Some(provider) = safelist_provider(ip) {
        return Err(format!(
            "skipped: {ip} is in cloud provider safelist ({provider})"
        ));
    }
    if operator_ips.contains_key(ip) {
        return Err(format!("skipped: {ip} is an active operator session"));
    }
    if recent_blocks_len >= max_blocks_per_min {
        return Err(format!(
            "rate-limited: {ip} (>{max_blocks_per_min} blocks/min)"
        ));
    }
    Ok(())
}

/// The status command for the firewall backend behind a block skill. `None`
/// for backends we cannot cheaply introspect (xdp/pf/unknown) — the caller then
/// re-applies (idempotent) rather than risk a free pass.
fn backend_status_cmd(skill_id: &str) -> Option<(&'static str, &'static [&'static str])> {
    if skill_id.contains("ufw") {
        Some(("ufw", &["status"]))
    } else if skill_id.contains("nft") {
        Some(("nft", &["list", "ruleset"]))
    } else if skill_id.contains("iptables") {
        Some(("iptables", &["-S"]))
    } else if skill_id.contains("firewalld") {
        Some(("firewall-cmd", &["--list-all"]))
    } else {
        None
    }
}

/// True when `ip` appears as a whole token in firewall status output. Splits on
/// any char that cannot be part of an IP/CIDR so `1.2.3.4` never matches inside
/// `11.2.3.4` or `1.2.3.40`.
fn rule_present_in(status_output: &str, ip: &str) -> bool {
    status_output
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == ':' || c == '/'))
        .any(|tok| tok == ip)
}

/// Best-effort check of whether `ip` is in the LIVE firewall ruleset for the
/// backend behind `skill_id`. Returns `false` when the backend is not
/// introspectable or the query fails — callers treat `false` as "re-apply",
/// which is idempotent and never opens a gap. Uses the same `sudo` path the
/// block skills use to apply rules.
async fn is_ip_live_blocked(ip: &str, skill_id: &str) -> bool {
    let (prog, args) = match backend_status_cmd(skill_id) {
        Some(c) => c,
        None => return false,
    };
    match tokio::process::Command::new("sudo")
        .arg(prog)
        .args(args)
        .output()
        .await
    {
        Ok(o) if o.status.success() => rule_present_in(&String::from_utf8_lossy(&o.stdout), ip),
        _ => false,
    }
}

/// Status dump + (optional) apply command for the reconciler, keyed on the
/// record's backend. `apply` is `None` for backends whose rules are table/chain
/// specific (nft/firewalld) or kernel-map based (xdp/pf) — those are verify-only
/// here; their standalone paths own re-application. Prod uses ufw.
#[allow(clippy::type_complexity)]
fn reconcile_cmds(
    backend: &ResponseBackend,
    ip: &str,
) -> Option<(
    (&'static str, Vec<String>),
    Option<(&'static str, Vec<String>)>,
)> {
    match backend {
        ResponseBackend::Ufw => Some((
            ("ufw", vec!["status".to_string()]),
            Some((
                "ufw",
                vec![
                    "deny".into(),
                    "from".into(),
                    ip.to_string(),
                    "to".into(),
                    "any".into(),
                ],
            )),
        )),
        ResponseBackend::Iptables => Some((
            ("iptables", vec!["-S".to_string()]),
            Some((
                "iptables",
                vec![
                    "-I".into(),
                    "INPUT".into(),
                    "-s".into(),
                    ip.to_string(),
                    "-j".into(),
                    "DROP".into(),
                ],
            )),
        )),
        ResponseBackend::Nftables => Some((("nft", vec!["list".into(), "ruleset".into()]), None)),
        _ => None,
    }
}

async fn run_sudo_stdout(prog: &str, args: &[String]) -> Option<String> {
    match tokio::process::Command::new("sudo")
        .arg(prog)
        .args(args)
        .output()
        .await
    {
        Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).into_owned()),
        _ => None,
    }
}

async fn run_sudo_ok(prog: &str, args: &[String]) -> bool {
    matches!(
        tokio::process::Command::new("sudo").arg(prog).args(args).output().await,
        Ok(o) if o.status.success()
    )
}

/// What the reconciler should do for one active block, given the live dump for
/// its backend. The pure, testable core of the reconcile loop.
#[derive(Debug, PartialEq, Eq)]
enum ReconcileAction {
    /// Rule is live in the dump — just stamp it verified.
    Present,
    /// Rule is gone and the backend has an apply command — re-apply it.
    Reapply,
    /// Rule is gone but the backend has no hand-built apply (verify-only).
    MissingNoReapply,
    /// Backend we do not introspect (xdp/pf/firewalld) — its own path owns it.
    Unsupported,
    /// No dump available for this backend this tick — skip, retry next tick.
    NoDump,
}

fn classify_for_reconcile(
    backend: &ResponseBackend,
    ip: &str,
    dump: Option<&str>,
) -> ReconcileAction {
    let apply_available = match reconcile_cmds(backend, ip) {
        Some((_, apply)) => apply.is_some(),
        None => return ReconcileAction::Unsupported,
    };
    let dump = match dump {
        Some(d) => d,
        None => return ReconcileAction::NoDump,
    };
    if rule_present_in(dump, ip) {
        ReconcileAction::Present
    } else if apply_available {
        ReconcileAction::Reapply
    } else {
        ReconcileAction::MissingNoReapply
    }
}

/// Slow-loop block-enforcement reconciler (spec 076 phase 2). Makes the live
/// firewall match intent: for every active, TTL-valid block whose rule is
/// missing from the live ruleset, re-apply it; for every block confirmed present
/// (or just re-applied), stamp `last_verified_live` so the dashboard reflects
/// reality instead of the TTL alone. This is the proactive counterpart to the
/// decision-time guard in `execute_block_ip_decision` — it closes the idle
/// window between a rule silently dropping and the IP's next attack. Returns
/// `(verified, reapplied)`.
pub(crate) async fn reconcile_block_enforcement(state: &mut AgentState) -> (usize, usize) {
    let now = chrono::Utc::now();
    let targets = state.response_lifecycle.active_block_ip_targets(now);
    if targets.is_empty() {
        return (0, 0);
    }

    // Dump each distinct backend status program ONCE, not per IP.
    let mut dumps: std::collections::HashMap<&'static str, String> =
        std::collections::HashMap::new();
    for (_ip, backend) in &targets {
        if let Some(((sprog, sargs), _)) = reconcile_cmds(backend, "0.0.0.0") {
            if !dumps.contains_key(sprog) {
                if let Some(out) = run_sudo_stdout(sprog, &sargs).await {
                    dumps.insert(sprog, out);
                }
            }
        }
    }

    let mut verified = 0usize;
    let mut reapplied = 0usize;
    for (ip, backend) in &targets {
        let dump = reconcile_cmds(backend, ip)
            .and_then(|((sprog, _), _)| dumps.get(sprog).map(String::as_str));
        match classify_for_reconcile(backend, ip, dump) {
            ReconcileAction::Present => {
                state.response_lifecycle.mark_verified_live(ip, now);
                verified += 1;
            }
            ReconcileAction::Reapply => {
                if let Some((_, Some((aprog, aargs)))) = reconcile_cmds(backend, ip) {
                    if run_sudo_ok(aprog, &aargs).await {
                        warn!(
                            ip = %ip,
                            backend = ?backend,
                            "reconciler restored a dropped firewall block (was missing from the live ruleset)"
                        );
                        state.response_lifecycle.mark_verified_live(ip, now);
                        reapplied += 1;
                    } else {
                        warn!(ip = %ip, "reconciler failed to re-apply a dropped block");
                    }
                }
            }
            ReconcileAction::MissingNoReapply => {
                warn!(
                    ip = %ip,
                    backend = ?backend,
                    "reconciler: block missing from live ruleset and backend has no auto-reapply (verify-only)"
                );
            }
            ReconcileAction::Unsupported | ReconcileAction::NoDump => {}
        }
    }
    if verified + reapplied > 0 {
        info!(verified, reapplied, "block-enforcement reconcile complete");
    }
    (verified, reapplied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Instant;

    #[test]
    fn backend_status_cmd_maps_known_backends() {
        assert_eq!(
            backend_status_cmd("block-ip-ufw"),
            Some(("ufw", &["status"][..]))
        );
        assert_eq!(
            backend_status_cmd("block-ip-nftables"),
            Some(("nft", &["list", "ruleset"][..]))
        );
        assert_eq!(
            backend_status_cmd("block-ip-iptables"),
            Some(("iptables", &["-S"][..]))
        );
        assert_eq!(
            backend_status_cmd("block-ip-firewalld"),
            Some(("firewall-cmd", &["--list-all"][..]))
        );
        // Backends we cannot cheaply introspect -> None -> caller re-applies.
        assert_eq!(backend_status_cmd("block-ip-xdp"), None);
        assert_eq!(backend_status_cmd("block-ip-pf"), None);
        assert_eq!(backend_status_cmd("monitor-ip"), None);
    }

    #[test]
    fn reconcile_cmds_maps_backends() {
        use crate::response_lifecycle::ResponseBackend;
        // ufw + iptables: status dump + an apply command carrying the IP.
        let (s, a) = reconcile_cmds(&ResponseBackend::Ufw, "1.2.3.4").unwrap();
        assert_eq!(s.0, "ufw");
        assert!(a.unwrap().1.contains(&"1.2.3.4".to_string()));
        let (s, a) = reconcile_cmds(&ResponseBackend::Iptables, "1.2.3.4").unwrap();
        assert_eq!(s.0, "iptables");
        assert!(a.unwrap().1.contains(&"1.2.3.4".to_string()));
        // nftables: verify-only (status, no hand-built apply).
        let (s, a) = reconcile_cmds(&ResponseBackend::Nftables, "1.2.3.4").unwrap();
        assert_eq!(s.0, "nft");
        assert!(a.is_none());
        // xdp: standalone path owns it -> reconciler skips.
        assert!(reconcile_cmds(&ResponseBackend::Xdp, "1.2.3.4").is_none());
    }

    #[test]
    fn classify_for_reconcile_decides_actions() {
        use crate::response_lifecycle::ResponseBackend;
        let ufw = "Status: active\n[1] Anywhere   DENY IN   1.2.3.4\n";
        // present -> verify; missing + has apply -> reapply
        assert_eq!(
            classify_for_reconcile(&ResponseBackend::Ufw, "1.2.3.4", Some(ufw)),
            ReconcileAction::Present
        );
        assert_eq!(
            classify_for_reconcile(&ResponseBackend::Ufw, "9.9.9.9", Some(ufw)),
            ReconcileAction::Reapply
        );
        // nft missing -> verify-only (no hand-built apply command)
        assert_eq!(
            classify_for_reconcile(
                &ResponseBackend::Nftables,
                "9.9.9.9",
                Some("table inet f {}")
            ),
            ReconcileAction::MissingNoReapply
        );
        // xdp -> unsupported (own path); no dump -> skip this tick
        assert_eq!(
            classify_for_reconcile(&ResponseBackend::Xdp, "1.2.3.4", Some("x")),
            ReconcileAction::Unsupported
        );
        assert_eq!(
            classify_for_reconcile(&ResponseBackend::Ufw, "1.2.3.4", None),
            ReconcileAction::NoDump
        );
    }

    #[test]
    fn rule_present_in_matches_whole_ip_token_only() {
        let ufw = "Status: active\n[2419] Anywhere   DENY IN   45.148.10.121\n";
        assert!(rule_present_in(ufw, "45.148.10.121"));
        // No false positive on a substring / neighbouring IP.
        assert!(!rule_present_in(ufw, "45.148.10.12"));
        assert!(!rule_present_in(ufw, "145.148.10.121"));
        assert!(!rule_present_in(ufw, "45.148.10.1"));
        // Absent IP.
        assert!(!rule_present_in(ufw, "8.8.8.8"));
        // CIDR token preserved.
        assert!(rule_present_in(
            "-A INPUT -s 10.0.0.0/8 -j DROP",
            "10.0.0.0/8"
        ));
        // Empty output.
        assert!(!rule_present_in("", "1.2.3.4"));
    }

    fn mem_store() -> innerwarden_store::Store {
        innerwarden_store::Store::open_memory().expect("memory store")
    }

    fn ts(iso: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(iso)
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn consult_circuit_breaker_allows_under_threshold() {
        let store = mem_store();
        let out =
            consult_circuit_breaker(&store, ts("2026-04-19T12:00:00Z"), "1.2.3.4", 100, "pause");
        assert!(out.is_none(), "fresh breaker must allow");
    }

    #[test]
    fn consult_circuit_breaker_refuses_after_trip_with_reason() {
        // Drive the breaker to trip then verify the next call refuses with
        // a reason the audit trail can use verbatim.
        let store = mem_store();
        let now = ts("2026-04-19T12:00:00Z");
        for _ in 0..100 {
            let _ = consult_circuit_breaker(&store, now, "1.2.3.4", 100, "pause");
        }
        let tripped = consult_circuit_breaker(&store, now, "1.2.3.4", 100, "pause")
            .expect("101st attempt must trip");
        assert!(tripped.contains("circuit breaker tripped"));
        assert!(tripped.contains("100"), "reason must carry the limit");

        let silent = consult_circuit_breaker(&store, now, "5.6.7.8", 100, "pause")
            .expect("subsequent attempts stay refused");
        assert!(silent.contains("circuit breaker tripped"));
    }

    #[test]
    fn consult_circuit_breaker_log_only_never_refuses() {
        // Calibration mode: breaker counts but must NOT refuse even far
        // above the nominal threshold.
        let store = mem_store();
        let now = ts("2026-04-19T12:00:00Z");
        for _ in 0..1000 {
            assert!(
                consult_circuit_breaker(&store, now, "1.2.3.4", 100, "log_only").is_none(),
                "log_only must always allow"
            );
        }
    }

    #[test]
    fn consult_circuit_breaker_unknown_mode_falls_back_to_pause() {
        // Garbage value in `responder.circuit_breaker_mode` must not disable
        // the breaker — `Mode::from_str_or_default` treats unknown tokens
        // as pause so the operator never ends up with a no-op breaker from
        // a typo.
        let store = mem_store();
        let now = ts("2026-04-19T12:00:00Z");
        for _ in 0..101 {
            let _ = consult_circuit_breaker(&store, now, "1.2.3.4", 100, "garbage-token");
        }
        let refused = consult_circuit_breaker(&store, now, "1.2.3.4", 100, "garbage-token");
        assert!(refused.is_some(), "unknown mode must still enforce pause");
    }

    #[test]
    fn consult_circuit_breaker_auto_rearm_allows_on_hour_rollover() {
        // Trip the breaker in hour A, confirm hour B's first call allows.
        let store = mem_store();
        let hour_a = ts("2026-04-19T12:00:00Z");
        for _ in 0..101 {
            let _ = consult_circuit_breaker(&store, hour_a, "1.2.3.4", 100, "pause");
        }
        let hour_b = ts("2026-04-19T13:05:00Z");
        let after = consult_circuit_breaker(&store, hour_b, "9.9.9.9", 100, "pause");
        assert!(after.is_none(), "new hour must rearm and allow the block");
    }

    #[test]
    fn consult_circuit_breaker_dry_run_mode_refuses_after_trip() {
        // Dry-run refuses at the executor layer same as pause; the
        // audit trail (decision_writer) still runs upstream — this test
        // verifies the executor-side signal.
        let store = mem_store();
        let now = ts("2026-04-19T12:00:00Z");
        for _ in 0..100 {
            let _ = consult_circuit_breaker(&store, now, "1.2.3.4", 100, "dry_run");
        }
        let refused = consult_circuit_breaker(&store, now, "1.2.3.4", 100, "dry_run");
        assert!(refused.is_some());
    }

    #[test]
    fn test_check_block_eligibility() {
        let mut operator_ips = HashMap::new();
        operator_ips.insert("10.0.0.5".to_string(), Instant::now());

        // 1. empty ip
        assert_eq!(
            check_block_eligibility("", &operator_ips, 0, 20),
            Err("skipped: block decision has empty IP".to_string())
        );

        // 2. operator ip
        assert_eq!(
            check_block_eligibility("10.0.0.5", &operator_ips, 0, 20),
            Err("skipped: 10.0.0.5 is an active operator session".to_string())
        );

        // 3. rate limited
        assert_eq!(
            check_block_eligibility("1.2.3.4", &operator_ips, 20, 20),
            Err("rate-limited: 1.2.3.4 (>20 blocks/min)".to_string())
        );

        // 4. normal
        assert_eq!(
            check_block_eligibility("8.8.8.8", &operator_ips, 5, 20),
            Ok(())
        );

        // 5. invalid IP (octet > 255) — must reject
        assert_eq!(
            check_block_eligibility("129.950.5.0", &operator_ips, 0, 20),
            Err("skipped: 129.950.5.0 is not a valid IP address".to_string())
        );

        // 6. garbage string — must reject
        assert_eq!(
            check_block_eligibility("not-an-ip", &operator_ips, 0, 20),
            Err("skipped: not-an-ip is not a valid IP address".to_string())
        );

        // 7. valid IPv6
        assert_eq!(
            check_block_eligibility("2001:db8::1", &operator_ips, 0, 20),
            Ok(())
        );

        // 8. valid IPv4 CIDR — ufw accepts these and revert is symmetric
        assert_eq!(
            check_block_eligibility("10.0.0.0/8", &operator_ips, 0, 20),
            Ok(())
        );
        assert_eq!(
            check_block_eligibility("136.216.0.0/16", &operator_ips, 0, 20),
            Ok(())
        );
        assert_eq!(
            check_block_eligibility("192.168.1.1/32", &operator_ips, 0, 20),
            Ok(())
        );

        // 9. valid IPv6 CIDR
        assert_eq!(
            check_block_eligibility("2001:db8::/48", &operator_ips, 0, 20),
            Ok(())
        );

        // 10. CIDR with invalid IP part must fail
        assert_eq!(
            check_block_eligibility("129.950.5.0/24", &operator_ips, 0, 20),
            Err("skipped: 129.950.5.0/24 is not a valid IP address".to_string())
        );

        // 11. CIDR with out-of-range prefix must fail
        assert_eq!(
            check_block_eligibility("10.0.0.0/33", &operator_ips, 0, 20),
            Err("skipped: 10.0.0.0/33 is not a valid IP address".to_string())
        );
        assert_eq!(
            check_block_eligibility("2001:db8::/129", &operator_ips, 0, 20),
            Err("skipped: 2001:db8::/129 is not a valid IP address".to_string())
        );

        // 12. CIDR with malformed prefix
        assert_eq!(
            check_block_eligibility("10.0.0.0/abc", &operator_ips, 0, 20),
            Err("skipped: 10.0.0.0/abc is not a valid IP address".to_string())
        );
    }

    #[test]
    fn check_block_eligibility_with_safelist_refuses_cloud_ranges() {
        // Regression guard for the operator incident on 2026-04-18:
        // correlation:CL-008 + repeat-offender kept auto-blocking Cloudflare
        // CIDRs. With the safelist predicate in play every eligibility check
        // refuses a matching IP with an explanatory reason before the
        // firewall skill ever sees it.
        let operator_ips: HashMap<String, Instant> = HashMap::new();
        let safelist = |ip: &str| -> Option<&'static str> {
            if ip.starts_with("104.26.") || ip.starts_with("172.66.") {
                Some("Cloudflare")
            } else {
                None
            }
        };

        let err =
            check_block_eligibility_with_safelist("104.26.12.38", &operator_ips, 0, 20, &safelist)
                .expect_err("cloudflare IP must be refused");
        assert!(err.contains("cloud provider safelist"), "got {err}");
        assert!(err.contains("Cloudflare"), "got {err}");

        // IP outside the safelist still passes (sanity).
        assert_eq!(
            check_block_eligibility_with_safelist("198.51.100.7", &operator_ips, 0, 20, &safelist,),
            Ok(())
        );
    }

    #[test]
    fn check_block_eligibility_with_safelist_wraps_non_safelist_gates() {
        // The safelist predicate only refuses matches; empty / invalid /
        // operator / rate-limit checks must keep working exactly like the
        // pure `check_block_eligibility` variant. Using a never-match
        // predicate makes the wrapper behaviourally identical.
        let mut operator_ips: HashMap<String, Instant> = HashMap::new();
        operator_ips.insert("10.0.0.5".to_string(), Instant::now());
        let no_match = |_: &str| None;

        assert!(
            check_block_eligibility_with_safelist("", &operator_ips, 0, 20, &no_match)
                .unwrap_err()
                .contains("empty IP")
        );
        assert!(
            check_block_eligibility_with_safelist("bad-ip", &operator_ips, 0, 20, &no_match)
                .unwrap_err()
                .contains("not a valid IP")
        );
        assert!(
            check_block_eligibility_with_safelist("10.0.0.5", &operator_ips, 0, 20, &no_match)
                .unwrap_err()
                .contains("operator session")
        );
        assert!(
            check_block_eligibility_with_safelist("1.2.3.4", &operator_ips, 20, 20, &no_match)
                .unwrap_err()
                .contains("rate-limited")
        );
        assert_eq!(
            check_block_eligibility_with_safelist("8.8.8.8", &operator_ips, 0, 20, &no_match),
            Ok(())
        );
    }

    // Exhaustive validation of `is_valid_block_target` at the helper level so
    // future callers don't have to synthesize HashMap<operator_ips> just to
    // probe target parsing behaviour.
    #[test]
    fn is_valid_block_target_accepts_plain_ips() {
        assert!(is_valid_block_target("1.2.3.4"));
        assert!(is_valid_block_target("255.255.255.255"));
        assert!(is_valid_block_target("0.0.0.0"));
        assert!(is_valid_block_target("::1"));
        assert!(is_valid_block_target("2001:db8::1"));
    }

    #[test]
    fn is_valid_block_target_accepts_valid_cidrs() {
        assert!(is_valid_block_target("10.0.0.0/8"));
        assert!(is_valid_block_target("192.168.0.0/16"));
        assert!(is_valid_block_target("192.168.1.1/32"));
        assert!(is_valid_block_target("172.16.0.0/12"));
        assert!(is_valid_block_target("::/0"));
        assert!(is_valid_block_target("2001:db8::/32"));
        assert!(is_valid_block_target("fe80::/10"));
    }

    /// 2026-05-08 anchor (fix/automated-block-paths-reject-cidr):
    /// `is_single_ip_block_target` accepts plain IPv4 / IPv6 but
    /// rejects every CIDR — single-IP-only contract for automated
    /// block emitters. Operator's prod 2026-05-08 had `136.216.0.0/16`
    /// cycling every 2h via the repeat-offender path because
    /// `is_valid_block_target` accepted CIDRs. The new helper is the
    /// gate that prevents the automated paths from ever pushing a
    /// CIDR to the firewall.
    #[test]
    fn is_single_ip_block_target_rejects_cidrs_and_accepts_plain_ips() {
        // Plain IPs: still accepted (manual operator-tier operations
        // can still run through the legacy `is_valid_block_target`
        // when they specifically need CIDR support).
        assert!(is_single_ip_block_target("203.0.113.42"));
        assert!(is_single_ip_block_target("2001:db8::1"));
        assert!(is_single_ip_block_target("::1"));

        // CIDRs: rejected (the prod regression IP).
        assert!(
            !is_single_ip_block_target("136.216.0.0/16"),
            "the exact prod CIDR that cycled every 2h MUST be rejected"
        );
        assert!(!is_single_ip_block_target("10.0.0.0/8"));
        assert!(!is_single_ip_block_target("192.168.1.1/32"));
        assert!(!is_single_ip_block_target("2001:db8::/32"));

        // Garbage: still rejected.
        assert!(!is_single_ip_block_target(""));
        assert!(!is_single_ip_block_target("not-an-ip"));
    }

    #[test]
    fn is_valid_block_target_rejects_empty_and_garbage() {
        assert!(!is_valid_block_target(""));
        assert!(!is_valid_block_target("not-an-ip"));
        assert!(!is_valid_block_target("abc"));
        assert!(!is_valid_block_target(" "));
        assert!(!is_valid_block_target("/"));
    }

    #[test]
    fn is_valid_block_target_rejects_out_of_range_octets() {
        // Exact production samples that generated the orphaned-response alerts.
        assert!(!is_valid_block_target("129.950.5.0"));
        assert!(!is_valid_block_target("129.525.8.0"));
        assert!(!is_valid_block_target("130.890.9.0"));
        assert!(!is_valid_block_target("130.932.0.0"));
        assert!(!is_valid_block_target("130.806.3.0"));
        assert!(!is_valid_block_target("130.806.1.17"));
        assert!(!is_valid_block_target("129.491.8.0"));
        assert!(!is_valid_block_target("129.952.2.0"));
        assert!(!is_valid_block_target("129.950.5.15"));
        assert!(!is_valid_block_target("129.950.5.5"));
    }

    #[test]
    fn is_valid_block_target_rejects_short_and_long_ipv4() {
        assert!(!is_valid_block_target("137.274.6")); // 3 octets
        assert!(!is_valid_block_target("1.2.3"));
        assert!(!is_valid_block_target("1.2.3.4.5"));
    }

    #[test]
    fn is_valid_block_target_rejects_invalid_cidr() {
        assert!(!is_valid_block_target("129.950.5.0/24")); // bad IP
        assert!(!is_valid_block_target("10.0.0.0/33")); // prefix > 32 on v4
        assert!(!is_valid_block_target("2001:db8::/129")); // prefix > 128 on v6
        assert!(!is_valid_block_target("10.0.0.0/")); // empty prefix
        assert!(!is_valid_block_target("10.0.0.0/-1")); // negative prefix
        assert!(!is_valid_block_target("10.0.0.0/abc")); // non-numeric
        assert!(!is_valid_block_target("/16")); // empty IP
    }

    /// 2026-05-08 anchor (fix/xdp-infra-honesty): when the standalone
    /// XDP path succeeds, ANY shield-path failure must be silently
    /// dropped. Pre-fix, the agent emitted "XDP firewall unavailable"
    /// to the operator's journal even when the parallel standalone
    /// fallback succeeded — the warning + the success message hit
    /// the journal on the same timestamp, which made the "unavailable"
    /// claim a straight lie. The healthy gate state is "at least one
    /// XDP path succeeded".
    #[test]
    fn xdp_failure_to_warn_suppresses_shield_failure_when_standalone_succeeds() {
        let shield_failure = Some(("shield xdp_manager", "EPERM".to_string()));
        let result = xdp_failure_to_warn(shield_failure, StandaloneXdpOutcome::Succeeded);
        assert!(
            result.is_none(),
            "standalone success must suppress shield-path failure WARN"
        );
    }

    /// Mirror anchor: when neither path attempted XDP (gate skipped
    /// or no shield + no standalone skill), no WARN should fire. Pins
    /// the cheap-exit contract — `xdp_failure_to_warn` is only called
    /// once per decision so the no-op path matters.
    #[test]
    fn xdp_failure_to_warn_returns_none_when_nothing_was_attempted() {
        assert!(xdp_failure_to_warn(None, StandaloneXdpOutcome::NotAttempted).is_none());
    }

    /// When the standalone path failed and shield was not configured
    /// (or also failed), the WARN must fire with the standalone's
    /// failure context. The standalone is the path-of-last-resort
    /// when shield is unavailable; surfacing its error to the operator
    /// gives the actionable signal.
    #[test]
    fn xdp_failure_to_warn_returns_standalone_failure_when_no_path_succeeded() {
        let result = xdp_failure_to_warn(
            None,
            StandaloneXdpOutcome::Failed("bpftool stderr: Operation not permitted".into()),
        );
        let (context, details) = result.expect("must warn when no path succeeded");
        assert_eq!(context, "block-ip-xdp skill");
        assert!(details.contains("Operation not permitted"));
    }

    /// When BOTH paths failed, the WARN message folds the shield
    /// error into the standalone's so the operator sees the full
    /// picture in a single log line. Anti-regression for accidentally
    /// dropping one of the two error messages.
    #[test]
    fn xdp_failure_to_warn_combines_both_errors_when_neither_path_succeeds() {
        let shield_failure = Some(("shield xdp_manager", "shield: ENOENT".to_string()));
        let result = xdp_failure_to_warn(
            shield_failure,
            StandaloneXdpOutcome::Failed("standalone: EACCES".into()),
        );
        let (_context, details) = result.expect("both-failed must warn");
        assert!(details.contains("standalone: EACCES"));
        assert!(details.contains("shield: ENOENT"));
    }

    /// Shield failure with no standalone attempt (e.g. the
    /// `block-ip-xdp` skill is not registered) must surface the
    /// shield error verbatim. Pins the path where shield is the
    /// only XDP backend.
    #[test]
    fn xdp_failure_to_warn_surfaces_shield_failure_when_standalone_not_attempted() {
        let shield_failure = Some(("shield xdp_manager", "shield: ENOENT".to_string()));
        let result = xdp_failure_to_warn(shield_failure, StandaloneXdpOutcome::NotAttempted);
        let (context, details) = result.expect("shield-only failure must warn");
        assert_eq!(context, "shield xdp_manager");
        assert_eq!(details, "shield: ENOENT");
    }

    // ── Spec 081 — managed-agent downgrade wiring (decision_block_ip side) ──
    //
    // These cover the extracted, AgentState-free helpers:
    //   - `incident_source_identity` (evidence-shape parsing)
    //   - `dst_known_bad_from` (destination-reputation lookup)
    //   - `evaluate_managed_agent_downgrade` (the userspace IP-block downgrade
    //     decision, against a stub `/proc` resolver + hand-built registry)
    // plus the CROSS test that proves the SAME incident is spared on BOTH the
    // userspace IP-block path AND the kernel-block path.

    use innerwarden_agent_guard::registry::Registry;
    use innerwarden_agent_guard::signatures::SignatureIndex;
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;

    /// Prod-realistic OpenClaw interpreter (`/proc/<pid>/exe`) + identity script
    /// (argv[1]) + the `interpreter|script` fingerprint the hardened `connect()`
    /// records. Mirrors the fixtures in `managed_agent_guard::tests`.
    const OC_INTERP: &str = "/usr/bin/node";
    const OC_SCRIPT: &str = "/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js";

    fn oc_fingerprint() -> String {
        format!("{OC_INTERP}|{OC_SCRIPT}")
    }

    fn oc_resolved(uid: u32) -> crate::managed_agent_guard::ResolvedProcess {
        crate::managed_agent_guard::ResolvedProcess {
            argv: vec![
                OC_INTERP.to_string(),
                OC_SCRIPT.to_string(),
                "gateway".to_string(),
            ],
            exe_path: Some(OC_INTERP.to_string()),
            uid: Some(uid),
        }
    }

    /// Registry that vouches for OpenClaw at `pid` with the hardened facts
    /// captured exactly as production `connect()` would.
    fn registry_with_openclaw(pid: u32) -> Registry {
        let mut reg = Registry::new();
        reg.connect_with_facts(
            "OpenClaw",
            pid,
            Some("ag-x"),
            Some(OC_INTERP.to_string()),
            Some(1000),
            Some(oc_fingerprint()),
        )
        .expect("connect");
        reg
    }

    /// Build a realistic exfil/C2 incident: evidence carries `pid`/`comm`/
    /// `sensitive_file`/`pattern` (the `data_exfil_ebpf` shape) AND an Ip
    /// entity for the outbound destination.
    fn openclaw_exfil_incident(pid: u32, dst_ip: &str) -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "azure-dogfood".to_string(),
            incident_id: format!("data_exfil:detected:{pid}:2026-06-18T00:00Z"),
            severity: Severity::Critical,
            title: "Data exfiltration".to_string(),
            summary: "sensitive read → outbound connect".to_string(),
            evidence: serde_json::json!([{
                "pid": pid,
                "comm": "MainThread",
                "sensitive_file": "/home/lab/.env",
                "pattern": "data_exfil",
            }]),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    /// Build a realistic reverse_shell incident: the eBPF connect+dup2 shape
    /// emitted by `crates/sensor/src/detectors/reverse_shell.rs` (the
    /// `ebpf_sequence` branch). Evidence carries `pid`/`comm`/`source_comm`/
    /// `target_ip`/`target_port` but **no `sensitive_file`** — a pure outbound
    /// connect with no prior sensitive read, so `incident_source_identity`
    /// resolves `read_path = None`. The outbound destination is an Ip entity.
    /// This is the FirstHit shape that protects the AI-agent wedge: a managed
    /// agent multiplexing a socket (connect → dup2 stdio) looks exactly like a
    /// reverse shell, and must downgrade to monitor — NOT auto-block the
    /// destination IP a shared service depends on.
    fn openclaw_reverse_shell_incident(pid: u32, dst_ip: &str) -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "azure-dogfood".to_string(),
            incident_id: format!("reverse_shell:bash_dup2:{pid}:2026-06-29T00:00Z"),
            severity: Severity::Critical,
            title: "Reverse shell detected via eBPF".to_string(),
            summary: "connect → fd redirect to socket".to_string(),
            // Mirrors the real detector evidence keys (no `sensitive_file`).
            evidence: serde_json::json!([{
                "kind": "reverse_shell",
                "pattern": "bash_dup2",
                "detection": "ebpf_sequence",
                "comm": "MainThread",
                "source_comm": "MainThread",
                "pid": pid,
                "target_ip": dst_ip,
                "target_port": 443,
                "redirected_fd": 1,
            }]),
            recommended_checks: vec![],
            tags: vec!["reverse_shell".to_string(), "ebpf".to_string()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    #[test]
    fn incident_source_identity_parses_array_evidence() {
        let inc = openclaw_exfil_incident(4242, "1.2.3.4");
        let (pid, comm, read_path) =
            incident_source_identity(&inc).expect("array evidence must parse");
        assert_eq!(pid, 4242);
        assert_eq!(comm, "MainThread");
        assert_eq!(read_path.as_deref(), Some("/home/lab/.env"));
    }

    #[test]
    fn incident_source_identity_parses_object_evidence() {
        let mut inc = openclaw_exfil_incident(7, "1.2.3.4");
        // Collapse the array-of-one into a bare object — the killchain forward
        // -compat shape.
        inc.evidence = serde_json::json!({
            "pid": 7,
            "comm": "node",
            "sensitive_file": "/home/lab/.env",
        });
        let (pid, comm, read_path) =
            incident_source_identity(&inc).expect("object evidence must parse");
        assert_eq!(pid, 7);
        assert_eq!(comm, "node");
        assert_eq!(read_path.as_deref(), Some("/home/lab/.env"));
    }

    #[test]
    fn incident_source_identity_returns_none_without_pid() {
        let mut inc = openclaw_exfil_incident(1, "1.2.3.4");
        // Evidence present but no pid → no attributable source → None.
        inc.evidence = serde_json::json!([{ "comm": "node" }]);
        assert!(incident_source_identity(&inc).is_none());
        // A non-array/object evidence shape → None too.
        inc.evidence = serde_json::json!("not-an-object");
        assert!(incident_source_identity(&inc).is_none());
    }

    #[test]
    fn dst_known_bad_from_true_when_ip_entity_has_blocks() {
        let mut reps = HashMap::new();
        let mut rep = crate::ip_reputation::LocalIpReputation::new();
        rep.total_blocks = 3;
        reps.insert("1.2.3.4".to_string(), rep);
        let entities = vec![EntityRef::ip("1.2.3.4")];
        assert!(dst_known_bad_from(&entities, &reps));
    }

    #[test]
    fn dst_known_bad_from_false_when_unknown_or_no_blocks() {
        let mut reps = HashMap::new();
        // Present but zero blocks → not known-bad.
        reps.insert(
            "1.2.3.4".to_string(),
            crate::ip_reputation::LocalIpReputation::new(),
        );
        let entities = vec![EntityRef::ip("1.2.3.4")];
        assert!(!dst_known_bad_from(&entities, &reps));
        // Unknown IP → not known-bad.
        let other = vec![EntityRef::ip("9.9.9.9")];
        assert!(!dst_known_bad_from(&other, &reps));
        // A non-IP entity (user) is ignored.
        let user = vec![EntityRef::user("lab")];
        assert!(!dst_known_bad_from(&user, &reps));
    }

    #[test]
    fn evaluate_managed_agent_downgrade_managed_for_real_openclaw() {
        let pid = 4242;
        let reg = registry_with_openclaw(pid);
        let sigindex = SignatureIndex::new();
        let stub = crate::managed_agent_guard::test_support::StubProc::default()
            .with_proc(pid, oc_resolved(1000))
            .with_owner("/home/lab/.env", 1000);
        let inc = openclaw_exfil_incident(pid, "1.2.3.4");
        let out = evaluate_managed_agent_downgrade(&inc, &reg, &sigindex, &stub, false);
        let (agent_id, name) = out.expect("real OpenClaw self-activity must downgrade");
        assert_eq!(name, "OpenClaw");
        assert!(agent_id.starts_with("ag-"));
    }

    #[test]
    fn evaluate_managed_agent_downgrade_none_when_unregistered() {
        let pid = 4242;
        let reg = Registry::new(); // nobody registered
        let sigindex = SignatureIndex::new();
        let stub = crate::managed_agent_guard::test_support::StubProc::default()
            .with_proc(pid, oc_resolved(1000))
            .with_owner("/home/lab/.env", 1000);
        let inc = openclaw_exfil_incident(pid, "1.2.3.4");
        assert!(
            evaluate_managed_agent_downgrade(&inc, &reg, &sigindex, &stub, false).is_none(),
            "an unregistered source must NOT downgrade — block proceeds"
        );
    }

    #[test]
    fn evaluate_managed_agent_downgrade_none_when_no_pid_in_evidence() {
        let reg = registry_with_openclaw(4242);
        let sigindex = SignatureIndex::new();
        let stub = crate::managed_agent_guard::test_support::StubProc::default();
        let mut inc = openclaw_exfil_incident(4242, "1.2.3.4");
        inc.evidence = serde_json::json!([{ "comm": "MainThread" }]); // no pid
        assert!(
            evaluate_managed_agent_downgrade(&inc, &reg, &sigindex, &stub, false).is_none(),
            "no attributable pid → None (block proceeds)"
        );
    }

    #[test]
    fn evaluate_managed_agent_downgrade_none_when_destination_known_bad() {
        // Even a perfect managed agent is blocked when the destination is
        // independently known-malicious (reputation override).
        let pid = 4242;
        let reg = registry_with_openclaw(pid);
        let sigindex = SignatureIndex::new();
        let stub = crate::managed_agent_guard::test_support::StubProc::default()
            .with_proc(pid, oc_resolved(1000))
            .with_owner("/home/lab/.env", 1000);
        let inc = openclaw_exfil_incident(pid, "1.2.3.4");
        assert!(
            evaluate_managed_agent_downgrade(&inc, &reg, &sigindex, &stub, true).is_none(),
            "destination_known_bad=true forces the block even for a managed agent"
        );
    }

    // ── REVERSE_SHELL (connect-only, read_path=None) DOWNGRADE — wedge guard ──
    //
    // Regression guard for the AI-agent wedge. A reverse_shell incident from a
    // verified managed agent carries NO `sensitive_file` (`read_path = None`),
    // unlike the exfil shape. The own-config gate in `decide()` is conditional
    // (`if let Some(read_path)`), so read_path=None still reaches `Managed` once
    // the identity gates pass. If a future refactor makes a read_path REQUIRED,
    // every managed-agent socket-multiplex would auto-block its destination IP —
    // the exact wedge-demo FP storm. This test pins the downgrade.

    #[test]
    fn evaluate_managed_agent_downgrade_managed_for_reverse_shell_shape() {
        let pid = 4242;
        let reg = registry_with_openclaw(pid);
        let sigindex = SignatureIndex::new();
        // No `.with_owner(...)`: a connect-only incident never stats a read_path,
        // so the verdict must not depend on file ownership.
        let stub = crate::managed_agent_guard::test_support::StubProc::default()
            .with_proc(pid, oc_resolved(1000));
        let inc = openclaw_reverse_shell_incident(pid, "203.0.113.7");
        // Sanity: this shape has no read_path.
        let (_, _, read_path) =
            incident_source_identity(&inc).expect("reverse_shell evidence carries a pid");
        assert!(
            read_path.is_none(),
            "reverse_shell evidence has no sensitive_file → read_path must be None"
        );
        let out = evaluate_managed_agent_downgrade(&inc, &reg, &sigindex, &stub, false);
        let (agent_id, name) =
            out.expect("connect-only managed-agent activity (read_path=None) must downgrade");
        assert_eq!(name, "OpenClaw");
        assert!(agent_id.starts_with("ag-"));
    }

    #[test]
    fn reverse_shell_to_known_bad_dest_still_blocks_for_managed_agent() {
        // Anti-evasion: the connect-only downgrade NEVER becomes a destination
        // exemption. A managed agent connecting to an independently known-bad IP
        // is still blocked — the reputation override fires regardless of the
        // missing read_path.
        let pid = 4242;
        let reg = registry_with_openclaw(pid);
        let sigindex = SignatureIndex::new();
        let stub = crate::managed_agent_guard::test_support::StubProc::default()
            .with_proc(pid, oc_resolved(1000));
        let inc = openclaw_reverse_shell_incident(pid, "203.0.113.7");
        assert!(
            evaluate_managed_agent_downgrade(&inc, &reg, &sigindex, &stub, true).is_none(),
            "known-bad destination forces the block even on the connect-only shape"
        );
    }

    // ── CROSS / INTEGRATION TEST (incident → response, BOTH paths) ─────────
    //
    // The SAME realistic OpenClaw incident must be spared on BOTH response
    // paths: the userspace IP-block (`evaluate_managed_agent_downgrade`) AND
    // the kernel PID-block (`killchain_inline::evaluate_kernel_block_withhold`).
    // The negative variant (unregistered pid) must block on BOTH. This proves
    // the end-to-end incident→response wiring, not just the unit `decide()`.

    #[test]
    fn cross_managed_openclaw_spared_on_both_response_paths() {
        let pid = 4242;
        let reg = registry_with_openclaw(pid);
        let sigindex = SignatureIndex::new();
        // Prod-realistic OpenClaw: exe=/usr/bin/node, argv carries the script,
        // uid 1000, owner of /home/lab/.env = 1000.
        let stub = crate::managed_agent_guard::test_support::StubProc::default()
            .with_proc(pid, oc_resolved(1000))
            .with_owner("/home/lab/.env", 1000);

        // (1) Userspace IP-block path — downgrade (Some).
        let inc = openclaw_exfil_incident(pid, "1.2.3.4");
        let userspace = evaluate_managed_agent_downgrade(&inc, &reg, &sigindex, &stub, false);
        assert!(
            userspace.is_some(),
            "userspace IP-block must be downgraded for the managed OpenClaw"
        );

        // (2) Kernel-block path — withhold (Some). Build the killchain evidence
        // object shape the kernel path reads (pid + pattern=data_exfil + comm +
        // the `sensitive_file` the tracker now emits). The read is the agent's
        // OWN /home/lab/.env (owner uid 1000), so the own-config gate passes on
        // the kernel path exactly like the userspace path.
        let kc_ev = serde_json::json!({
            "pid": pid,
            "pattern": "data_exfil",
            "comm": "MainThread",
            "sensitive_file": "/home/lab/.env",
        });
        let kernel =
            crate::killchain_inline::evaluate_kernel_block_withhold(&kc_ev, &reg, &sigindex, &stub);
        assert!(
            kernel.is_some(),
            "kernel PID-block must be WITHHELD for the managed OpenClaw"
        );

        // Same agent identity surfaced on both paths.
        assert_eq!(userspace.unwrap().1, "OpenClaw");
        assert_eq!(kernel.unwrap().1, "OpenClaw");
    }

    #[test]
    fn cross_unregistered_pid_blocks_on_both_response_paths() {
        let pid = 4242;
        let reg = Registry::new(); // EMPTY registry — nobody vouched
        let sigindex = SignatureIndex::new();
        let stub = crate::managed_agent_guard::test_support::StubProc::default()
            .with_proc(pid, oc_resolved(1000))
            .with_owner("/home/lab/.env", 1000);

        // (1) Userspace IP-block path — proceeds (None).
        let inc = openclaw_exfil_incident(pid, "1.2.3.4");
        assert!(
            evaluate_managed_agent_downgrade(&inc, &reg, &sigindex, &stub, false).is_none(),
            "unregistered source → userspace block proceeds"
        );

        // (2) Kernel-block path — proceeds (None).
        let kc_ev = serde_json::json!({
            "pid": pid,
            "pattern": "data_exfil",
            "comm": "MainThread",
        });
        assert!(
            crate::killchain_inline::evaluate_kernel_block_withhold(&kc_ev, &reg, &sigindex, &stub)
                .is_none(),
            "unregistered source → kernel block proceeds"
        );
    }
}
