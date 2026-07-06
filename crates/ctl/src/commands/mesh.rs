use std::io::Write;

use anyhow::Result;
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};

use crate::{require_sudo, Cli};

fn is_mesh_enabled(content: &str) -> bool {
    content.contains("[mesh]") && content.contains("enabled = true")
}

fn is_mesh_disabled_or_missing(content: &str) -> bool {
    !content.contains("[mesh]") || content.contains("enabled = false")
}

fn mesh_enable_block() -> &'static str {
    "\n[mesh]\nenabled = true\nbind = \"0.0.0.0:8790\"\npoll_secs = 30\nauto_broadcast = true"
}

fn build_mesh_peer_block(endpoint: &str, label: Option<&str>) -> String {
    if let Some(lbl) = label {
        format!("\n[[mesh.peers]]\nendpoint = \"{endpoint}\"\npublic_key = \"\"\nlabel = \"{lbl}\"")
    } else {
        format!("\n[[mesh.peers]]\nendpoint = \"{endpoint}\"\npublic_key = \"\"")
    }
}

fn peer_already_configured(content: &str, endpoint: &str) -> bool {
    content.contains(endpoint)
}

fn shorten_node_id(node_id: &str) -> &str {
    if node_id.len() > 16 {
        &node_id[..16]
    } else {
        node_id
    }
}

fn format_peer_reputation_line(node_id: &str, trust: f64, sent: u64, confirmed: u64) -> String {
    format!(
        "  Peer {}...  trust={:.2}  signals={}/{}confirmed",
        shorten_node_id(node_id),
        trust,
        sent,
        confirmed
    )
}

pub(crate) fn cmd_mesh_enable(cli: &Cli) -> Result<()> {
    let agent_cfg = cli.agent_config.clone();
    let content = std::fs::read_to_string(&agent_cfg).unwrap_or_default();

    if is_mesh_enabled(&content) {
        println!("Mesh network is already enabled.");
        return Ok(());
    }

    if content.contains("[mesh]") {
        let updated = content.replace("enabled = false", "enabled = true");
        std::fs::write(&agent_cfg, updated)?;
    } else {
        let mut f = std::fs::OpenOptions::new().append(true).open(&agent_cfg)?;
        writeln!(f, "{}", mesh_enable_block())?;
    }

    println!("✅ Mesh network enabled.");
    println!("   Listening on port 8790 for peer connections.");
    println!("   Add peers: innerwarden mesh add-peer https://peer:8790");
    println!("   Restart agent to apply: sudo systemctl restart innerwarden-agent");

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "mesh_enable".to_string(),
        target: "mesh".to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

pub(crate) fn cmd_mesh_disable(cli: &Cli) -> Result<()> {
    let agent_cfg = cli.agent_config.clone();
    let content = std::fs::read_to_string(&agent_cfg).unwrap_or_default();

    if is_mesh_disabled_or_missing(&content) {
        println!("Mesh network is already disabled.");
        return Ok(());
    }

    let updated = content.replace("enabled = true", "enabled = false");
    std::fs::write(&agent_cfg, updated)?;

    println!("✅ Mesh network disabled.");
    println!("   Restart agent to apply: sudo systemctl restart innerwarden-agent");

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "mesh_disable".to_string(),
        target: "mesh".to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

pub(crate) fn cmd_mesh_add_peer(cli: &Cli, endpoint: &str, label: Option<&str>) -> Result<()> {
    let agent_cfg = cli.agent_config.clone();
    let content = std::fs::read_to_string(&agent_cfg).unwrap_or_default();

    if !content.contains("[mesh]") {
        println!("Mesh not configured. Run 'innerwarden mesh enable' first.");
        return Ok(());
    }

    if peer_already_configured(&content, endpoint) {
        println!("Peer {} already configured.", endpoint);
        return Ok(());
    }

    let mut f = std::fs::OpenOptions::new().append(true).open(&agent_cfg)?;
    writeln!(f, "{}", build_mesh_peer_block(endpoint, label))?;

    println!("✅ Peer added: {}", endpoint);
    if let Some(lbl) = label {
        println!("   Label: {}", lbl);
    }
    println!("   Identity will be discovered automatically via ping.");
    println!("   Restart agent to apply: sudo systemctl restart innerwarden-agent");

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "mesh_add_peer".to_string(),
        target: endpoint.to_string(),
        parameters: serde_json::json!({ "label": label }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

pub(crate) fn cmd_mesh_status(cli: &Cli) -> Result<()> {
    let data_dir = cli.data_dir.clone();
    let state_path = data_dir.join("mesh-state.json");

    if !state_path.exists() {
        println!("Mesh network: not initialized");
        println!("Run 'innerwarden mesh enable' to get started.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&state_path)?;
    let state: serde_json::Value = if content.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&content).unwrap_or_else(|_| {
            println!("  (state file unreadable; showing a fresh view — it will be rewritten on next save)");
            serde_json::json!({})
        })
    };

    let identity_path = data_dir.join("mesh-identity.key");
    let has_identity = identity_path.exists();

    println!("═══════════════════════════════════════════════════");
    println!("  MESH NETWORK STATUS");
    println!("═══════════════════════════════════════════════════");
    println!();
    println!(
        "  Identity: {}",
        if has_identity {
            "active"
        } else {
            "not generated"
        }
    );

    let peers = state["peers"].as_array().map(|a| a.len()).unwrap_or(0);
    let reputations = state["reputations"].as_array();

    println!("  Peers: {}", peers);
    println!();

    if let Some(reps) = reputations {
        for rep in reps {
            let node_id = rep["node_id"].as_str().unwrap_or("?");
            let trust = rep["trust_score"].as_f64().unwrap_or(0.0);
            let sent = rep["signals_sent"].as_u64().unwrap_or(0);
            let confirmed = rep["signals_confirmed"].as_u64().unwrap_or(0);
            println!(
                "{}",
                format_peer_reputation_line(node_id, trust, sent, confirmed)
            );
        }
    }

    println!();
    println!("═══════════════════════════════════════════════════");
    Ok(())
}

/// Default mesh port (matches `mesh_enable_block`'s bind).
const DEFAULT_MESH_PORT: u16 = 8790;

/// Normalize a user-supplied peer into (canonical endpoint URL, host, port).
///
/// Accepts `host`, `host:port`, `http://host:port`, or `https://host:port`.
/// The mesh server speaks plain HTTP, so the canonical endpoint is always
/// `http://host:port` regardless of the scheme typed (a `https://` peer would
/// never connect to the HTTP listener).
fn normalize_endpoint(input: &str, default_port: u16) -> (String, String, u16) {
    let trimmed = input.trim();
    let without_scheme = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    let (host, port) = match without_scheme.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() && !h.is_empty() => {
            (h.to_string(), p.parse().unwrap())
        }
        _ => (without_scheme.to_string(), default_port),
    };
    (format!("http://{host}:{port}"), host, port)
}

/// Build the firewall command that allows inbound `port` from `source` (the
/// peer). `source` is only used to scope the rule when it is a literal IP;
/// hostnames cannot be expressed as a firewall source, so the rule opens the
/// port without a source restriction (the caller warns about that).
fn firewall_open_command(tool: &str, source: &str, port: u16) -> Option<Vec<String>> {
    let is_ip = source.parse::<std::net::IpAddr>().is_ok();
    match tool {
        "ufw" if is_ip => Some(vec![
            "ufw".into(),
            "allow".into(),
            "from".into(),
            source.into(),
            "to".into(),
            "any".into(),
            "port".into(),
            port.to_string(),
            "proto".into(),
            "tcp".into(),
        ]),
        "ufw" => Some(vec![
            "ufw".into(),
            "allow".into(),
            format!("{port}/tcp"),
        ]),
        "firewalld" if is_ip => Some(vec![
            "firewall-cmd".into(),
            "--permanent".into(),
            format!(
                "--add-rich-rule=rule family=ipv4 source address={source} port port={port} protocol=tcp accept"
            ),
        ]),
        "firewalld" => Some(vec![
            "firewall-cmd".into(),
            "--permanent".into(),
            format!("--add-port={port}/tcp"),
        ]),
        _ => None,
    }
}

/// Detect the active host firewall, if any (`ufw` / `firewalld`).
fn detect_firewall() -> Option<&'static str> {
    let ufw_active = std::process::Command::new("ufw")
        .arg("status")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("Status: active"))
        .unwrap_or(false);
    if ufw_active {
        return Some("ufw");
    }
    let firewalld_active = std::process::Command::new("firewall-cmd")
        .arg("--state")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "running")
        .unwrap_or(false);
    if firewalld_active {
        return Some("firewalld");
    }
    None
}

/// One-command connect: enable mesh, add the peer, and open the local firewall
/// for the mesh port. Composes the existing enable/add-peer steps so the
/// operator does not have to run three commands plus a manual firewall edit.
pub(crate) fn cmd_mesh_connect(cli: &Cli, endpoint: &str, label: Option<&str>) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let (url, host, port) = normalize_endpoint(endpoint, DEFAULT_MESH_PORT);
    println!("Connecting to mesh peer {url}...");

    // 1 + 2: ensure mesh is enabled, then register the peer.
    cmd_mesh_enable(cli)?;
    cmd_mesh_add_peer(cli, &url, label)?;

    // 3: open the local firewall so the peer can reach our listener.
    if cli.dry_run {
        println!("  [dry-run] would open firewall for tcp/{port} from {host}");
    } else {
        match detect_firewall() {
            Some(tool) => match firewall_open_command(tool, &host, port) {
                Some(cmd) => {
                    let status = std::process::Command::new(&cmd[0]).args(&cmd[1..]).status();
                    let reloaded = if tool == "firewalld" {
                        std::process::Command::new("firewall-cmd")
                            .arg("--reload")
                            .status()
                            .map(|s| s.success())
                            .unwrap_or(false)
                    } else {
                        true
                    };
                    match status {
                        Ok(s) if s.success() && reloaded => {
                            println!("  [ok] {tool}: opened tcp/{port} from {host}");
                        }
                        _ => println!(
                            "  [warn] could not open firewall automatically. Run: sudo ufw allow {port}/tcp"
                        ),
                    }
                }
                None => println!("  [warn] unsupported firewall; open tcp/{port} manually"),
            },
            None => println!(
                "  [note] no active host firewall detected (ufw/firewalld). If one is added later, allow tcp/{port}."
            ),
        }
        if host.parse::<std::net::IpAddr>().is_err() {
            println!("  [note] peer is a hostname; firewall rule is not source-scoped to an IP");
        }
    }

    println!();
    println!("✅ Mesh peer connected: {url}");
    println!("   Cloud firewall (AWS SG / Azure NSG / Oracle VCN) must also allow tcp/{port} inbound from the peer.");
    println!("   Restart the agent to apply: sudo systemctl restart innerwarden-agent");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_cli(dir: &TempDir, agent_config: &str) -> Cli {
        let agent_path = dir.path().join("agent.toml");
        std::fs::write(&agent_path, agent_config).unwrap();
        Cli {
            sensor_config: dir.path().join("config.toml"),
            agent_config: agent_path,
            data_dir: dir.path().to_path_buf(),
            dry_run: true,
            command: None,
        }
    }

    #[test]
    fn normalize_endpoint_accepts_host_hostport_and_schemes() {
        // Bare host -> default port, canonical http scheme.
        assert_eq!(
            normalize_endpoint("203.0.113.7", 8790),
            ("http://203.0.113.7:8790".into(), "203.0.113.7".into(), 8790)
        );
        // host:port.
        assert_eq!(
            normalize_endpoint("10.0.1.5:9000", 8790),
            ("http://10.0.1.5:9000".into(), "10.0.1.5".into(), 9000)
        );
        // https:// is normalized to http:// (the mesh server is plain HTTP).
        assert_eq!(
            normalize_endpoint("https://peer.example:8790/", 8790),
            (
                "http://peer.example:8790".into(),
                "peer.example".into(),
                8790
            )
        );
    }

    #[test]
    fn firewall_open_command_scopes_to_ip_or_opens_port() {
        // IP source -> source-scoped ufw rule.
        let ip = firewall_open_command("ufw", "203.0.113.7", 8790).unwrap();
        assert!(ip.contains(&"from".to_string()) && ip.contains(&"203.0.113.7".to_string()));
        // Hostname -> port-only ufw rule (no source scoping possible).
        let host = firewall_open_command("ufw", "peer.example", 8790).unwrap();
        assert_eq!(host, vec!["ufw", "allow", "8790/tcp"]);
        // firewalld IP rich-rule.
        let fw = firewall_open_command("firewalld", "203.0.113.7", 8790).unwrap();
        assert!(fw.iter().any(|a| a.contains("source address=203.0.113.7")));
        // Unknown tool -> None.
        assert!(firewall_open_command("pf", "203.0.113.7", 8790).is_none());
    }

    #[test]
    fn is_mesh_enabled_requires_section_and_true_flag() {
        // Confirms mesh is only considered active when both section and enabled=true are present.
        assert!(is_mesh_enabled("[mesh]\nenabled = true"));
        assert!(!is_mesh_enabled("[mesh]\nenabled = false"));
        assert!(!is_mesh_enabled("enabled = true"));
    }

    #[test]
    fn is_mesh_disabled_or_missing_covers_both_short_circuits() {
        // Covers disable guard conditions so command avoids unnecessary file writes.
        assert!(is_mesh_disabled_or_missing(""));
        assert!(is_mesh_disabled_or_missing("[mesh]\nenabled = false"));
        assert!(!is_mesh_disabled_or_missing("[mesh]\nenabled = true"));
    }

    #[test]
    fn mesh_enable_block_contains_default_runtime_values() {
        // Ensures generated block keeps expected defaults that operators rely on.
        let block = mesh_enable_block();
        assert!(block.contains("enabled = true"));
        assert!(block.contains("bind = \"0.0.0.0:8790\""));
        assert!(block.contains("poll_secs = 30"));
    }

    #[test]
    fn build_mesh_peer_block_with_label_includes_metadata() {
        // Verifies labeled peer serialization keeps endpoint and optional label fields.
        let rendered = build_mesh_peer_block("https://peer:8790", Some("edge-a"));
        assert!(rendered.contains("endpoint = \"https://peer:8790\""));
        assert!(rendered.contains("label = \"edge-a\""));
    }

    #[test]
    fn build_mesh_peer_block_without_label_omits_label_field() {
        // Guards the unlabeled peer path so no empty label key is emitted.
        let rendered = build_mesh_peer_block("https://peer:8790", None);
        assert!(rendered.contains("endpoint = \"https://peer:8790\""));
        assert!(!rendered.contains("label = "));
    }

    #[test]
    fn peer_already_configured_uses_endpoint_substring_match() {
        // Documents current duplicate-detection behavior before any parser refactor.
        let cfg = "[mesh]\n[[mesh.peers]]\nendpoint = \"https://peer:8790\"";
        assert!(peer_already_configured(cfg, "https://peer:8790"));
        assert!(!peer_already_configured(cfg, "https://other:8790"));
    }

    #[test]
    fn shorten_node_id_truncates_only_long_values() {
        // Covers truncation logic used in mesh status rendering.
        assert_eq!(shorten_node_id("1234567890abcdef"), "1234567890abcdef");
        assert_eq!(shorten_node_id("1234567890abcdefXYZ"), "1234567890abcdef");
    }

    #[test]
    fn format_peer_reputation_line_formats_values_consistently() {
        // Verifies trust and signal counters are rendered with stable precision and ordering.
        let line = format_peer_reputation_line("1234567890abcdefXYZ", 0.625, 8, 5);
        assert_eq!(
            line,
            "  Peer 1234567890abcdef...  trust=0.62  signals=8/5confirmed"
        );
    }

    #[test]
    fn cmd_mesh_enable_appends_mesh_section_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, "[agent]\nname = \"node-a\"\n");

        cmd_mesh_enable(&cli).unwrap();

        let updated = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(updated.contains("[mesh]"));
        assert!(updated.contains("enabled = true"));
        assert!(updated.contains("bind = \"0.0.0.0:8790\""));
    }

    #[test]
    fn cmd_mesh_enable_flips_disabled_mesh_section() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, "[mesh]\nenabled = false\n");

        cmd_mesh_enable(&cli).unwrap();

        let updated = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(updated.contains("enabled = true"));
        assert!(!updated.contains("enabled = false"));
    }

    #[test]
    fn cmd_mesh_enable_is_noop_when_already_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let original = "[mesh]\nenabled = true\n";
        let cli = test_cli(&dir, original);

        cmd_mesh_enable(&cli).unwrap();

        assert_eq!(
            std::fs::read_to_string(&cli.agent_config).unwrap(),
            original
        );
    }

    #[test]
    fn cmd_mesh_disable_flips_enabled_mesh_section() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, "[mesh]\nenabled = true\n");

        cmd_mesh_disable(&cli).unwrap();

        let updated = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(updated.contains("enabled = false"));
        assert!(!updated.contains("enabled = true"));
    }

    #[test]
    fn cmd_mesh_disable_is_noop_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let original = "[agent]\nname = \"node-a\"\n";
        let cli = test_cli(&dir, original);

        cmd_mesh_disable(&cli).unwrap();

        assert_eq!(
            std::fs::read_to_string(&cli.agent_config).unwrap(),
            original
        );
    }

    #[test]
    fn cmd_mesh_add_peer_appends_peer_block() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, "[mesh]\nenabled = true\n");

        cmd_mesh_add_peer(&cli, "https://peer-a:8790", Some("edge-a")).unwrap();

        let updated = std::fs::read_to_string(&cli.agent_config).unwrap();
        assert!(updated.contains("[[mesh.peers]]"));
        assert!(updated.contains("endpoint = \"https://peer-a:8790\""));
        assert!(updated.contains("label = \"edge-a\""));
    }

    #[test]
    fn cmd_mesh_add_peer_is_noop_when_mesh_missing() {
        let dir = tempfile::tempdir().unwrap();
        let original = "[agent]\nname = \"node-a\"\n";
        let cli = test_cli(&dir, original);

        cmd_mesh_add_peer(&cli, "https://peer-a:8790", Some("edge-a")).unwrap();

        assert_eq!(
            std::fs::read_to_string(&cli.agent_config).unwrap(),
            original
        );
    }

    #[test]
    fn cmd_mesh_add_peer_is_noop_for_duplicate_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let original = "\
[mesh]
enabled = true

[[mesh.peers]]
endpoint = \"https://peer-a:8790\"
public_key = \"\"
";
        let cli = test_cli(&dir, original);

        cmd_mesh_add_peer(&cli, "https://peer-a:8790", Some("edge-a")).unwrap();

        assert_eq!(
            std::fs::read_to_string(&cli.agent_config).unwrap(),
            original
        );
    }

    #[test]
    fn cmd_mesh_status_handles_missing_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, "[mesh]\nenabled = true\n");

        cmd_mesh_status(&cli).unwrap();
    }

    #[test]
    fn cmd_mesh_status_renders_state_and_identity() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, "[mesh]\nenabled = true\n");
        std::fs::write(cli.data_dir.join("mesh-identity.key"), "secret").unwrap();
        std::fs::write(
            cli.data_dir.join("mesh-state.json"),
            r#"{
                "peers": [{"endpoint": "https://peer-a:8790"}],
                "reputations": [{
                    "node_id": "1234567890abcdefXYZ",
                    "trust_score": 0.875,
                    "signals_sent": 12,
                    "signals_confirmed": 10
                }]
            }"#,
        )
        .unwrap();

        cmd_mesh_status(&cli).unwrap();
    }
}
