//! `innerwarden dashboard` — easy + secure dashboard access.
//!
//! The dashboard binds to loopback by default (secure: no admin panel open on
//! the internet). Exposing it used to mean editing the systemd unit (or the
//! watchdog `--agent-arg`), reloading, restarting, and setting up a firewall by
//! hand — fiddly and easy to get wrong. This command does it in one step,
//! securely:
//!
//!   innerwarden dashboard            # status: how to reach it (URL, login, tunnel)
//!   innerwarden dashboard open       # expose it (password-protected, firewall-locked to your IP)
//!   innerwarden dashboard close      # back to localhost only
//!   innerwarden dashboard tunnel     # print the exact SSH-tunnel command (no exposure)
//!
//! Bind is stored in `[dashboard] bind` in agent.toml (config-driven, so no
//! systemd surgery). Exposing is always password-protected: the agent refuses
//! to start a non-loopback bind without credentials (SEC-005), so `open`
//! generates a login first if none is set.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::config_editor;

const DEFAULT_PORT: u16 = 8787;
const LOCAL_BIND: &str = "127.0.0.1:8787";
const PUBLIC_BIND: &str = "0.0.0.0:8787";

#[derive(Debug, Clone, clap::Subcommand)]
pub enum DashboardAction {
    /// Show how to reach the dashboard: current bind, URL, login, SSH tunnel.
    Status,
    /// Open the dashboard to the network — securely. Generates a login if none
    /// exists, sets the bind, and (by default) locks the firewall to the IP you
    /// are connected from. Use `--public` to allow any IP (less safe), or
    /// `--allow <ip>` to lock to a specific IP.
    Open {
        /// Allow any source IP (no firewall lock). You should have a reason.
        #[arg(long)]
        public: bool,
        /// Lock firewall access to this IP (CIDR ok). Defaults to your current
        /// SSH client IP.
        #[arg(long)]
        allow: Option<String>,
    },
    /// Close remote access: bind back to localhost only.
    Close,
    /// Print the exact SSH-tunnel command for remote access without exposing
    /// the dashboard on the network (the safest way in).
    Tunnel,
}

// ── pure helpers (unit-tested) ───────────────────────────────────────────

/// The client IP from a `$SSH_CONNECTION` value
/// (`"<client_ip> <client_port> <server_ip> <server_port>"`).
pub fn parse_ssh_client_ip(ssh_connection: &str) -> Option<String> {
    let ip = ssh_connection.split_whitespace().next()?;
    if ip.is_empty() {
        None
    } else {
        Some(ip.to_string())
    }
}

/// The server IP from a `$SSH_CONNECTION` value (the 3rd field).
pub fn parse_ssh_server_ip(ssh_connection: &str) -> Option<String> {
    ssh_connection
        .split_whitespace()
        .nth(2)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Port from a `host:port` bind string; falls back to the dashboard default.
pub fn port_of_bind(bind: &str) -> u16 {
    bind.rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// True when the bind is loopback-only (not reachable off the box).
pub fn is_loopback_bind(bind: &str) -> bool {
    bind.starts_with("127.")
        || bind.starts_with("localhost")
        || bind.starts_with("[::1]")
        || bind.starts_with("::1")
}

/// `https://<host>:<port>` for the dashboard (always HTTPS — self-signed).
pub fn dashboard_url(host: &str, port: u16) -> String {
    format!("https://{host}:{port}")
}

/// The exact SSH local-forward command to reach a loopback dashboard.
pub fn tunnel_command(user: &str, host: &str, port: u16) -> String {
    format!("ssh -L {port}:localhost:{port} {user}@{host}")
}

/// The effective bind: `[dashboard] bind` from config, else the loopback
/// default. (Mirrors the agent's precedence so `status` is truthful.)
fn effective_bind(agent_config: &Path) -> String {
    let b = config_editor::read_str(agent_config, "dashboard", "bind");
    if b.is_empty() {
        LOCAL_BIND.to_string()
    } else {
        b
    }
}

/// agent.env sits next to agent.toml.
fn agent_env_path(agent_config: &Path) -> std::path::PathBuf {
    agent_config
        .parent()
        .unwrap_or(Path::new("/etc/innerwarden"))
        .join("agent.env")
}

/// Whether dashboard login credentials are configured.
fn has_credentials(agent_config: &Path) -> bool {
    let env = agent_env_path(agent_config);
    std::fs::read_to_string(&env)
        .map(|s| {
            s.lines()
                .any(|l| l.trim_start().starts_with("INNERWARDEN_DASHBOARD_USER="))
        })
        .unwrap_or(false)
}

// ── dispatch ─────────────────────────────────────────────────────────────

pub fn run(action: &DashboardAction, agent_config: &Path, dry_run: bool) -> Result<()> {
    match action {
        DashboardAction::Status => status(agent_config),
        DashboardAction::Tunnel => {
            print_tunnel(agent_config);
            Ok(())
        }
        DashboardAction::Open { public, allow } => {
            open(agent_config, *public, allow.clone(), dry_run)
        }
        DashboardAction::Close => close(agent_config, dry_run),
    }
}

/// Best display host for a bind: `localhost` for loopback, else the server IP
/// we were reached on (from `$SSH_CONNECTION`), else a placeholder.
fn host_for_display(bind: &str) -> String {
    if is_loopback_bind(bind) {
        return "localhost".to_string();
    }
    std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|c| parse_ssh_server_ip(&c))
        .unwrap_or_else(|| "<SERVER-IP>".to_string())
}

fn status(agent_config: &Path) -> Result<()> {
    let bind = effective_bind(agent_config);
    let port = port_of_bind(&bind);
    let loopback = is_loopback_bind(&bind);
    let creds = has_credentials(agent_config);

    println!("Dashboard");
    println!("  bind:        {bind}");
    println!(
        "  exposure:    {}",
        if loopback {
            "localhost only (secure default)"
        } else {
            "reachable on the network"
        }
    );
    println!(
        "  login:       {}",
        if creds {
            "set (password required)"
        } else {
            "NOT set"
        }
    );
    println!();
    if loopback {
        println!("To open it from your computer (recommended — nothing exposed):");
        print_tunnel(agent_config);
        println!("  then browse:  {}", dashboard_url("localhost", port));
        println!();
        println!("Or expose it on the network (password + firewall):  innerwarden dashboard open");
    } else {
        let host = host_for_display(&bind);
        println!("Reachable at:  {}", dashboard_url(&host, port));
        if !creds {
            println!(
                "  ⚠ no login set — the agent will REFUSE to serve a non-loopback bind without one."
            );
            println!("    Run `innerwarden dashboard open` to set a password, or `... close` to lock down.");
        }
        println!("(self-signed cert: accept the browser warning)");
    }
    Ok(())
}

fn print_tunnel(agent_config: &Path) {
    let bind = effective_bind(agent_config);
    let port = port_of_bind(&bind);
    let (user, host) = ssh_user_host();
    println!("  {}", tunnel_command(&user, &host, port));
}

/// Best-effort SSH user@host for the tunnel hint.
fn ssh_user_host() -> (String, String) {
    let user = std::env::var("USER").unwrap_or_else(|_| "YOUR_USER".to_string());
    let host = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|c| parse_ssh_server_ip(&c))
        .unwrap_or_else(|| "YOUR_SERVER".to_string());
    (user, host)
}

fn open(agent_config: &Path, public: bool, allow: Option<String>, dry_run: bool) -> Result<()> {
    let port = port_of_bind(&effective_bind(agent_config));

    // 1) Ensure a login exists (the agent refuses a non-loopback bind without
    //    one). Generate one if missing — this is what makes it lay-friendly.
    if !has_credentials(agent_config) {
        ensure_credentials(agent_config, dry_run)?;
    } else {
        println!("[ok] dashboard login already set.");
    }

    // 2) Decide firewall scope.
    let allow_ip = if public {
        None
    } else {
        allow.or_else(|| {
            std::env::var("SSH_CONNECTION")
                .ok()
                .and_then(|c| parse_ssh_client_ip(&c))
        })
    };

    // 3) Set the bind in config (config-driven, no systemd edit).
    if dry_run {
        println!(
            "[dry-run] would set [dashboard] bind = \"{PUBLIC_BIND}\" in {}",
            agent_config.display()
        );
    } else {
        config_editor::write_str(agent_config, "dashboard", "bind", PUBLIC_BIND)
            .with_context(|| "failed to set [dashboard] bind")?;
        println!(
            "[ok] bind set to {PUBLIC_BIND} in {}",
            agent_config.display()
        );
    }

    // 4) Firewall: lock to the IP unless --public.
    match &allow_ip {
        Some(ip) => apply_ufw_allow(ip, port, dry_run),
        None => {
            println!("⚠ --public: NOT adding a firewall rule. The dashboard will be reachable from ANY IP (password-protected, but consider a firewall).");
        }
    }

    // 5) Restart so the new bind takes effect.
    restart_agent(dry_run)?;

    // 6) Tell the user exactly how to get in.
    let host = host_for_display(PUBLIC_BIND);
    println!();
    println!("✅ Dashboard open.");
    println!("   Open in your browser:  {}", dashboard_url(&host, port));
    println!("   Username: admin");
    match &allow_ip {
        Some(ip) => println!("   Reachable only from your IP: {ip}"),
        None => println!("   Reachable from any IP (password required)."),
    }
    println!("   (self-signed cert: accept the browser warning)");
    Ok(())
}

fn close(agent_config: &Path, dry_run: bool) -> Result<()> {
    if dry_run {
        println!("[dry-run] would set [dashboard] bind = \"{LOCAL_BIND}\" (localhost only)");
    } else {
        config_editor::write_str(agent_config, "dashboard", "bind", LOCAL_BIND)
            .with_context(|| "failed to set [dashboard] bind")?;
        println!("[ok] bind set to {LOCAL_BIND} (localhost only).");
    }
    restart_agent(dry_run)?;
    println!("✅ Dashboard closed to the network. Reach it via SSH tunnel:");
    print_tunnel(agent_config);
    Ok(())
}

/// Generate a random login and persist it (argon2 hash via the agent binary).
fn ensure_credentials(agent_config: &Path, dry_run: bool) -> Result<()> {
    let password = generate_password();
    let env = agent_env_path(agent_config);
    if dry_run {
        println!(
            "[dry-run] would generate a dashboard login (admin / <random>) into {}",
            env.display()
        );
        return Ok(());
    }
    let hash = argon2_hash_via_agent(&password)?;
    write_env_key(&env, "INNERWARDEN_DASHBOARD_USER", "admin")?;
    write_env_key(&env, "INNERWARDEN_DASHBOARD_PASSWORD_HASH", &hash)?;
    println!("[ok] dashboard login created — SAVE THIS, it is shown once:");
    println!("       username: admin");
    println!("       password: {password}");
    Ok(())
}

fn generate_password() -> String {
    // 24 url-safe chars from the OS RNG. Avoids ambiguous chars.
    use std::io::Read;
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut buf = [0u8; 24];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

/// Hash a password with the agent's argon2 (`--dashboard-generate-password-hash`
/// reads from stdin), so the hashing stays identical to the agent's verifier.
fn argon2_hash_via_agent(password: &str) -> Result<String> {
    use std::io::Write;
    let bin = find_agent_bin()
        .ok_or_else(|| anyhow::anyhow!("innerwarden-agent binary not found; set a login manually with `innerwarden notify dashboard`"))?;
    let mut child = std::process::Command::new(&bin)
        .arg("--dashboard-generate-password-hash")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("failed to run {}", bin))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{password}");
    }
    let out = child.wait_with_output().context("agent hash failed")?;
    if !out.status.success() {
        bail!("password hashing failed");
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.starts_with("$argon2"))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| anyhow::anyhow!("agent returned no hash"))
}

fn find_agent_bin() -> Option<String> {
    for p in [
        "/usr/local/bin/innerwarden-agent",
        "/usr/bin/innerwarden-agent",
    ] {
        if Path::new(p).exists() {
            return Some(p.to_string());
        }
    }
    None
}

/// Append-or-replace a `KEY=value` line in an env file (0600).
fn write_env_key(path: &Path, key: &str, value: &str) -> Result<()> {
    let mut lines: Vec<String> = std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim_start().starts_with(&format!("{key}=")))
        .map(String::from)
        .collect();
    lines.push(format!("{key}={value}"));
    let body = lines.join("\n") + "\n";
    std::fs::write(path, body).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn apply_ufw_allow(ip: &str, port: u16, dry_run: bool) {
    let rule = format!("from {ip} to any port {port}");
    if dry_run {
        println!("[dry-run] would run: ufw allow {rule} comment innerwarden-dashboard");
        return;
    }
    let status = std::process::Command::new("ufw")
        .args(["allow", "from", ip, "to", "any", "port", &port.to_string()])
        .arg("comment")
        .arg("innerwarden-dashboard")
        .status();
    match status {
        Ok(s) if s.success() => println!("[ok] firewall: allowed {ip} → port {port} (ufw)."),
        Ok(_) => println!(
            "⚠ ufw rule not applied (is ufw installed/enabled?). Add manually: ufw allow {rule}"
        ),
        Err(_) => {
            println!("⚠ ufw not found. If you use a firewall, allow {ip} → port {port} yourself.")
        }
    }
}

/// Restart whichever unit actually supervises the agent.
fn restart_agent(dry_run: bool) -> Result<()> {
    let unit = if matches!(
        crate::systemd::service_status("innerwarden-watchdog"),
        crate::systemd::ServiceStatus::Active
    ) {
        "innerwarden-watchdog"
    } else {
        "innerwarden-agent"
    };
    println!("[..] restarting {unit} to apply the change");
    crate::systemd::restart_service(unit, dry_run)
        .with_context(|| format!("failed to restart {unit}; restart it manually"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssh_client_and_server_ip() {
        let c = "203.0.113.9 51763 10.0.0.5 22";
        assert_eq!(parse_ssh_client_ip(c).as_deref(), Some("203.0.113.9"));
        assert_eq!(parse_ssh_server_ip(c).as_deref(), Some("10.0.0.5"));
        assert_eq!(parse_ssh_client_ip(""), None);
        assert_eq!(parse_ssh_server_ip("only one"), None);
    }

    #[test]
    fn port_and_loopback_detection() {
        assert_eq!(port_of_bind("127.0.0.1:8787"), 8787);
        assert_eq!(port_of_bind("0.0.0.0:9000"), 9000);
        assert_eq!(port_of_bind("garbage"), DEFAULT_PORT);
        assert!(is_loopback_bind("127.0.0.1:8787"));
        assert!(is_loopback_bind("localhost:8787"));
        assert!(is_loopback_bind("[::1]:8787"));
        assert!(!is_loopback_bind("0.0.0.0:8787"));
        assert!(!is_loopback_bind("10.0.0.5:8787"));
    }

    #[test]
    fn url_and_tunnel_strings() {
        assert_eq!(dashboard_url("localhost", 8787), "https://localhost:8787");
        assert_eq!(dashboard_url("10.0.0.5", 8787), "https://10.0.0.5:8787");
        assert_eq!(
            tunnel_command("alice", "10.0.0.5", 8787),
            "ssh -L 8787:localhost:8787 alice@10.0.0.5"
        );
    }

    #[test]
    fn generated_password_is_strong_enough() {
        let p = generate_password();
        assert_eq!(p.len(), 24);
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
