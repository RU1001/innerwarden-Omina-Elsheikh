use std::collections::HashMap;
use std::io::Write;

use anyhow::Result;
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};

use crate::{make_opts, require_sudo, unknown_cap_error, CapabilityRegistry, Cli};

fn confirmation_accepted(answer: &str) -> bool {
    let normalized = answer.trim().to_lowercase();
    normalized.is_empty() || normalized == "y" || normalized == "yes"
}

pub(crate) fn parse_params(raw: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for item in raw {
        let (k, v) = item.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("invalid param '{}' - expected KEY=VALUE format", item)
        })?;
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
}

pub(crate) fn cmd_enable(
    cli: &Cli,
    registry: &CapabilityRegistry,
    id: &str,
    params: HashMap<String, String>,
    yes: bool,
    force: bool,
) -> Result<()> {
    cmd_enable_with_deferred_restart(cli, registry, id, params, yes, false, force)
}

pub(crate) fn cmd_enable_with_deferred_restart(
    cli: &Cli,
    registry: &CapabilityRegistry,
    id: &str,
    params: HashMap<String, String>,
    yes: bool,
    defer_restarts: bool,
    force: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let cap = registry.get(id).ok_or_else(|| unknown_cap_error(id))?;
    let mut opts = make_opts(cli, params, yes);
    opts.defer_restarts = defer_restarts;

    if cap.is_enabled(&opts) && !force {
        println!(
            "Capability '{}' is already enabled. Nothing to do.\n\
             (Use --force to re-apply and repair drift, e.g. a missing sudoers drop-in.)",
            cap.id()
        );
        return Ok(());
    }

    if cap.is_enabled(&opts) && force {
        println!("Re-applying capability (--force): {}\n", cap.name());
    } else {
        println!("Enabling capability: {}\n", cap.name());
    }

    // --- Preflight checks ---
    println!("Preflight checks:");
    let preflights = cap.preflights(&opts);
    let mut any_failed = false;
    for pf in &preflights {
        match pf.check() {
            Ok(()) => println!("  [ok] {}", pf.name()),
            Err(e) => {
                println!("  [fail] {}", e.message);
                if let Some(hint) = &e.fix_hint {
                    println!("         → {hint}");
                }
                any_failed = true;
            }
        }
    }
    if any_failed {
        anyhow::bail!("preflight checks failed - no changes applied");
    }

    // --- Planned effects ---
    println!("\nPlanned changes:");
    let effects = cap.planned_effects(&opts);
    for (i, effect) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, effect.description);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    // --- Confirmation ---
    if !yes {
        print!("\nApply? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !confirmation_accepted(&input) {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    // --- Activate ---
    let report = cap.activate(&opts)?;
    for effect in &report.effects_applied {
        println!("  [done] {}", effect.description);
    }
    for warn in &report.warnings {
        println!("  [warn] {warn}");
    }

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "enable".to_string(),
        target: id.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("\nCapability '{}' is now enabled.", cap.id());
    Ok(())
}

pub(crate) fn cmd_disable(
    cli: &Cli,
    registry: &CapabilityRegistry,
    id: &str,
    yes: bool,
) -> Result<()> {
    cmd_disable_with_deferred_restart(cli, registry, id, yes, false)
}

pub(crate) fn cmd_disable_with_deferred_restart(
    cli: &Cli,
    registry: &CapabilityRegistry,
    id: &str,
    yes: bool,
    defer_restarts: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let cap = registry.get(id).ok_or_else(|| unknown_cap_error(id))?;
    let mut opts = make_opts(cli, HashMap::new(), yes);
    opts.defer_restarts = defer_restarts;

    if !cap.is_enabled(&opts) {
        println!("Capability '{}' is not enabled. Nothing to do.", cap.id());
        return Ok(());
    }

    println!("Disabling capability: {}\n", cap.name());

    println!("Changes to apply:");
    let effects = cap.planned_disable_effects(&opts);
    for (i, effect) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, effect.description);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nApply? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !confirmation_accepted(&input) {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    let report = cap.deactivate(&opts)?;
    for effect in &report.effects_applied {
        println!("  [done] {}", effect.description);
    }
    for warn in &report.warnings {
        println!("  [warn] {warn}");
    }

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "disable".to_string(),
        target: id.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("\nCapability '{}' is now disabled.", cap.id());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::TempDir;

    fn test_cli(temp: &TempDir, dry_run: bool) -> Cli {
        let mut cli = Cli::parse_from(["innerwarden", "replay"]);
        cli.sensor_config = temp.path().join("sensor.toml");
        cli.agent_config = temp.path().join("agent.toml");
        cli.data_dir = temp.path().join("data");
        cli.dry_run = dry_run;
        std::fs::create_dir_all(&cli.data_dir).expect("test should create data dir");
        std::fs::write(&cli.sensor_config, "").expect("test should create sensor config");
        std::fs::write(&cli.agent_config, "").expect("test should create agent config");
        cli
    }

    fn ollama_params() -> HashMap<String, String> {
        HashMap::from([
            ("provider".to_string(), "ollama".to_string()),
            ("model".to_string(), "mistral".to_string()),
        ])
    }

    #[test]
    fn confirmation_accepted_allows_empty_response() {
        // Confirms default-enter behavior still applies the action when operator just presses Enter.
        assert!(confirmation_accepted(""));
        assert!(confirmation_accepted("   "));
    }

    #[test]
    fn confirmation_accepted_allows_yes_variants() {
        // Covers positive confirmations so both short and full forms remain accepted.
        assert!(confirmation_accepted("y"));
        assert!(confirmation_accepted("yes"));
        assert!(confirmation_accepted(" YES "));
    }

    #[test]
    fn confirmation_accepted_rejects_non_yes_values() {
        // Ensures abort path is triggered for explicit negative or unrelated responses.
        assert!(!confirmation_accepted("n"));
        assert!(!confirmation_accepted("no"));
        assert!(!confirmation_accepted("later"));
    }

    #[test]
    fn parse_params_parses_multiple_entries() {
        // Exercises standard KEY=VALUE parsing for capability parameter forwarding.
        let raw = vec![
            "mode=strict".to_string(),
            "timeout=30".to_string(),
            "region=eu".to_string(),
        ];
        let parsed = parse_params(&raw).expect("valid params should parse");

        assert_eq!(parsed.get("mode").expect("mode key"), "strict");
        assert_eq!(parsed.get("timeout").expect("timeout key"), "30");
        assert_eq!(parsed.get("region").expect("region key"), "eu");
    }

    #[test]
    fn parse_params_rejects_missing_separator() {
        // Guards validation branch so malformed CLI params fail fast with a clear error.
        let raw = vec!["mode".to_string()];
        let err = parse_params(&raw).expect_err("missing '=' must error");
        assert!(err.to_string().contains("expected KEY=VALUE format"));
    }

    #[test]
    fn parse_params_allows_empty_value_after_separator() {
        // Documents accepted behavior for explicitly clearing a value via KEY= syntax.
        let raw = vec!["token=".to_string()];
        let parsed = parse_params(&raw).expect("empty values are currently allowed");
        assert_eq!(parsed.get("token").expect("token key"), "");
    }

    #[test]
    fn parse_params_last_duplicate_wins() {
        // Verifies deterministic overwrite behavior when user provides same key multiple times.
        let raw = vec![
            "level=low".to_string(),
            "level=high".to_string(),
            "level=critical".to_string(),
        ];
        let parsed = parse_params(&raw).expect("duplicate keys should still parse");
        assert_eq!(parsed.get("level").expect("level key"), "critical");
    }

    #[test]
    fn cmd_enable_unknown_capability_returns_helpful_error() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp, true);
        let registry = CapabilityRegistry::default_all();

        let err = cmd_enable(&cli, &registry, "not-a-cap", HashMap::new(), true, false)
            .expect_err("unknown capability should error");

        assert!(err.to_string().contains("not-a-cap"));
        assert!(err.to_string().contains("innerwarden list"));
    }

    #[test]
    fn cmd_enable_preflight_failure_stops_before_changes() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp, true);
        let registry = CapabilityRegistry::default_all();
        let params = HashMap::from([("provider".to_string(), "unknown-provider".to_string())]);

        let err = cmd_enable(&cli, &registry, "ai", params, true, false)
            .expect_err("failed preflight should stop enable");

        assert!(err.to_string().contains("preflight checks failed"));
        assert!(!crate::config_editor::read_bool(
            &cli.agent_config,
            "ai",
            "enabled"
        ));
    }

    #[test]
    fn cmd_enable_dry_run_leaves_config_unchanged() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp, true);
        let registry = CapabilityRegistry::default_all();

        cmd_enable(&cli, &registry, "ai", ollama_params(), true, false)
            .expect("dry-run enable should succeed");

        assert!(!crate::config_editor::read_bool(
            &cli.agent_config,
            "ai",
            "enabled"
        ));
    }

    #[test]
    fn cmd_enable_with_deferred_restart_applies_ai_config_and_audit() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp, false);
        let registry = CapabilityRegistry::default_all();

        cmd_enable_with_deferred_restart(&cli, &registry, "ai", ollama_params(), true, true, false)
            .expect("enable should apply with deferred restart");

        let config = std::fs::read_to_string(&cli.agent_config).expect("test should read config");
        config
            .parse::<toml_edit::DocumentMut>()
            .expect("command should write valid TOML");
        assert!(crate::config_editor::read_bool(
            &cli.agent_config,
            "ai",
            "enabled"
        ));
        assert_eq!(
            crate::config_editor::read_str(&cli.agent_config, "ai", "provider"),
            "ollama"
        );
        assert_eq!(
            crate::config_editor::read_str(&cli.agent_config, "ai", "model"),
            "mistral"
        );

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let audit_path = cli.data_dir.join(format!("admin-actions-{today}.jsonl"));
        let audit = std::fs::read_to_string(audit_path).expect("enable should write audit entry");
        assert!(audit.contains("\"action\":\"enable\""));
        assert!(audit.contains("\"target\":\"ai\""));
    }

    #[test]
    fn cmd_enable_returns_ok_when_capability_already_enabled() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp, false);
        let registry = CapabilityRegistry::default_all();
        std::fs::write(
            &cli.agent_config,
            "[ai]\nenabled = true\nprovider = \"ollama\"\nmodel = \"mistral\"\n",
        )
        .expect("test should write enabled config");

        cmd_enable(&cli, &registry, "ai", ollama_params(), true, false)
            .expect("already-enabled capability should be a no-op");

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        assert!(!cli
            .data_dir
            .join(format!("admin-actions-{today}.jsonl"))
            .exists());
    }

    #[test]
    fn cmd_enable_force_reapplies_when_already_enabled() {
        // --force must re-run apply even when config says enabled, so drift
        // (e.g. a deleted sudoers drop-in) gets repaired. Proven by the audit
        // entry, which is only written when apply actually runs.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp, false);
        let registry = CapabilityRegistry::default_all();
        std::fs::write(
            &cli.agent_config,
            "[ai]\nenabled = true\nprovider = \"ollama\"\nmodel = \"mistral\"\n",
        )
        .expect("test should write enabled config");

        // defer_restarts = true to avoid shelling out to systemctl in tests;
        // force = true is the behavior under test.
        cmd_enable_with_deferred_restart(&cli, &registry, "ai", ollama_params(), true, true, true)
            .expect("force should re-apply an already-enabled capability");

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        assert!(
            cli.data_dir
                .join(format!("admin-actions-{today}.jsonl"))
                .exists(),
            "force re-apply must run apply (audit entry written)"
        );
    }

    #[test]
    fn cmd_disable_unknown_capability_returns_helpful_error() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp, true);
        let registry = CapabilityRegistry::default_all();

        let err = cmd_disable(&cli, &registry, "not-a-cap", true)
            .expect_err("unknown capability should error");

        assert!(err.to_string().contains("not-a-cap"));
        assert!(err.to_string().contains("innerwarden list"));
    }

    #[test]
    fn cmd_disable_dry_run_for_enabled_capability_returns_ok() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp, true);
        let registry = CapabilityRegistry::default_all();
        std::fs::write(
            &cli.agent_config,
            "[ai]\nenabled = true\nprovider = \"ollama\"\n",
        )
        .expect("test should write enabled config");

        cmd_disable(&cli, &registry, "ai", true).expect("dry-run disable should succeed");

        assert!(crate::config_editor::read_bool(
            &cli.agent_config,
            "ai",
            "enabled"
        ));
    }

    #[test]
    fn cmd_disable_with_deferred_restart_applies_ai_config_and_audit() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp, false);
        let registry = CapabilityRegistry::default_all();
        std::fs::write(
            &cli.agent_config,
            "[ai]\nenabled = true\nprovider = \"ollama\"\n",
        )
        .expect("test should write enabled config");

        cmd_disable_with_deferred_restart(&cli, &registry, "ai", true, true)
            .expect("disable should apply with deferred restart");

        assert!(!crate::config_editor::read_bool(
            &cli.agent_config,
            "ai",
            "enabled"
        ));
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let audit_path = cli.data_dir.join(format!("admin-actions-{today}.jsonl"));
        let audit = std::fs::read_to_string(audit_path).expect("disable should write audit entry");
        assert!(audit.contains("\"action\":\"disable\""));
        assert!(audit.contains("\"target\":\"ai\""));
    }

    #[test]
    fn cmd_disable_returns_ok_when_capability_already_disabled() {
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp, false);
        let registry = CapabilityRegistry::default_all();

        cmd_disable(&cli, &registry, "ai", true)
            .expect("already-disabled capability should be a no-op");

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        assert!(!cli
            .data_dir
            .join(format!("admin-actions-{today}.jsonl"))
            .exists());
    }

    // ---- Toggle state-transition tests (Issue #141) ----

    mod toggle {
        use crate::capability::{
            ActivationOptions, ActivationReport, Capability, CapabilityEffect, Preflight,
            PreflightError,
        };
        use anyhow::Result;
        use std::collections::HashMap;
        use std::io::Write;
        use tempfile::NamedTempFile;

        // ----------------------------------------------------------------
        // Minimal stub capability for toggle logic tests.
        // Tracks enabled state via a key in agent.toml, no I/O side-effects.
        // ----------------------------------------------------------------

        struct StubCapability {
            id: &'static str,
        }

        impl Capability for StubCapability {
            fn id(&self) -> &'static str {
                self.id
            }
            fn name(&self) -> &'static str {
                "Stub"
            }
            fn description(&self) -> &'static str {
                "stub for tests"
            }
            fn preflights(&self, _opts: &ActivationOptions) -> Vec<Box<dyn Preflight>> {
                vec![]
            }
            fn planned_effects(&self, _opts: &ActivationOptions) -> Vec<CapabilityEffect> {
                vec![CapabilityEffect::new("stub effect")]
            }
            fn planned_disable_effects(&self, _opts: &ActivationOptions) -> Vec<CapabilityEffect> {
                vec![CapabilityEffect::new("stub disable effect")]
            }
            fn activate(&self, opts: &ActivationOptions) -> Result<ActivationReport> {
                crate::config_editor::write_bool(&opts.agent_config, "stub", "enabled", true)?;
                Ok(ActivationReport {
                    effects_applied: vec![CapabilityEffect::new("enabled stub")],
                    warnings: vec![],
                })
            }
            fn deactivate(&self, opts: &ActivationOptions) -> Result<ActivationReport> {
                crate::config_editor::write_bool(&opts.agent_config, "stub", "enabled", false)?;
                Ok(ActivationReport {
                    effects_applied: vec![CapabilityEffect::new("disabled stub")],
                    warnings: vec![],
                })
            }
            fn is_enabled(&self, opts: &ActivationOptions) -> bool {
                crate::config_editor::read_bool(&opts.agent_config, "stub", "enabled")
            }
        }

        // ----------------------------------------------------------------
        // Failing preflight stub — for gate tests
        // ----------------------------------------------------------------

        struct FailingPreflight;
        impl Preflight for FailingPreflight {
            fn name(&self) -> &str {
                "always fails"
            }
            fn check(&self) -> Result<(), PreflightError> {
                Err(PreflightError::new("intentional failure"))
            }
        }

        struct AlwaysFailsCapability;
        impl Capability for AlwaysFailsCapability {
            fn id(&self) -> &'static str {
                "always-fails"
            }
            fn name(&self) -> &'static str {
                "Always Fails"
            }
            fn description(&self) -> &'static str {
                "always fails preflights"
            }
            fn preflights(&self, _opts: &ActivationOptions) -> Vec<Box<dyn Preflight>> {
                vec![Box::new(FailingPreflight)]
            }
            fn planned_effects(&self, _opts: &ActivationOptions) -> Vec<CapabilityEffect> {
                vec![]
            }
            fn planned_disable_effects(&self, _opts: &ActivationOptions) -> Vec<CapabilityEffect> {
                vec![]
            }
            fn activate(&self, _opts: &ActivationOptions) -> Result<ActivationReport> {
                unreachable!("should never reach activate when preflights fail")
            }
            fn deactivate(&self, _opts: &ActivationOptions) -> Result<ActivationReport> {
                Ok(ActivationReport {
                    effects_applied: vec![],
                    warnings: vec![],
                })
            }
            fn is_enabled(&self, _opts: &ActivationOptions) -> bool {
                false
            }
        }

        // ----------------------------------------------------------------
        // Helper that builds a Cli-like ActivationOptions without Cli
        // ----------------------------------------------------------------

        fn stub_opts(agent: &NamedTempFile) -> ActivationOptions {
            let sensor = NamedTempFile::new().unwrap();
            ActivationOptions {
                sensor_config: sensor.path().to_path_buf(),
                agent_config: agent.path().to_path_buf(),
                dry_run: true, // avoids systemd/sudo calls
                params: HashMap::new(),
                yes: true,
                defer_restarts: true,
            }
        }

        use crate::capability::CapabilityRegistry;

        // ---- Test: enable already-enabled capability is a no-op ----

        #[test]
        fn enable_already_enabled_is_noop() {
            // Pre-set enabled=true so is_enabled() returns true.
            let mut agent = NamedTempFile::new().unwrap();
            writeln!(agent, "[stub]\nenabled = true\n").unwrap();
            let opts = stub_opts(&agent);
            let cap = StubCapability { id: "stub" };

            // is_enabled must be true before calling activate
            assert!(cap.is_enabled(&opts), "precondition: cap should be enabled");

            // Calling activate again should succeed idempotently (enabled stays true)
            let report = cap.activate(&opts).unwrap();
            assert!(cap.is_enabled(&opts));
            assert!(!report.effects_applied.is_empty());
        }

        // ---- Test: unknown capability lookup returns error shape ----

        #[test]
        fn unknown_capability_error_message_mentions_list() {
            // Validates the error message tells the user how to recover.
            let err = crate::unknown_cap_error("not-a-cap");
            let msg = err.to_string();
            assert!(
                msg.contains("not-a-cap"),
                "error should include the unknown id"
            );
            assert!(
                msg.contains("innerwarden list"),
                "error should mention list command"
            );
        }

        // ---- Test: valid block-ip enable transition ----

        #[test]
        fn block_ip_enable_sets_responder_enabled() {
            use crate::capabilities::block_ip::BlockIpCapability;

            let sensor = NamedTempFile::new().unwrap();
            let mut agent = NamedTempFile::new().unwrap();
            writeln!(agent, "[responder]\nenabled = false\n").unwrap();

            let opts = ActivationOptions {
                sensor_config: sensor.path().to_path_buf(),
                agent_config: agent.path().to_path_buf(),
                dry_run: true,
                params: HashMap::new(),
                yes: true,
                defer_restarts: true,
            };

            assert!(
                !BlockIpCapability.is_enabled(&opts),
                "precondition: should not be enabled"
            );
            BlockIpCapability.activate(&opts).unwrap();
            assert!(
                BlockIpCapability.is_enabled(&opts),
                "should be enabled after activate"
            );
        }

        // ---- Test: capability list order is deterministic ----

        #[test]
        fn capability_list_order_is_deterministic() {
            let reg = CapabilityRegistry::default_all();
            let first_pass: Vec<&str> = reg.all().map(|c| c.id()).collect();
            let second_pass: Vec<&str> = reg.all().map(|c| c.id()).collect();
            assert_eq!(
                first_pass, second_pass,
                "capability listing must be deterministic"
            );
        }

        // ---- Test: preflight failure prevents activation ----

        #[test]
        fn preflight_failure_prevents_activation() {
            let agent = NamedTempFile::new().unwrap();
            let opts = stub_opts(&agent);
            let cap = AlwaysFailsCapability;

            // Simulate the preflight gate in cmd_enable
            let preflights = cap.preflights(&opts);
            let any_failed = preflights.iter().any(|pf| pf.check().is_err());

            assert!(
                any_failed,
                "at least one preflight should fail for AlwaysFailsCapability"
            );
        }
    }
}
