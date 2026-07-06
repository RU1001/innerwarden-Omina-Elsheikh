use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::{systemd, Cli};

pub(crate) fn write_env_key(env_path: &Path, key: &str, value: &str) -> Result<()> {
    let existing = std::fs::read_to_string(env_path).unwrap_or_default();
    let mut lines: Vec<String> = existing
        .lines()
        .filter(|l| {
            // Remove existing setting (active or commented)
            let l = l.trim_start_matches('#').trim_start();
            !l.starts_with(&format!("{key}="))
        })
        .map(|l| l.to_string())
        .collect();
    lines.push(format!("{key}={value}"));
    let new_content = lines.join("\n") + "\n";
    // Atomic write via temp file in same directory
    let tmp = env_path.with_extension("env.tmp");
    std::fs::write(&tmp, &new_content)
        .with_context(|| format!("cannot write {}", tmp.display()))?;
    std::fs::rename(&tmp, env_path)
        .with_context(|| format!("cannot update {}", env_path.display()))?;
    // Ensure readable by innerwarden service user (chmod 640 + chgrp innerwarden).
    // Fail-silent - best-effort in case the group doesn't exist (e.g. local dev).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(env_path, std::fs::Permissions::from_mode(0o640));
        let _ = std::process::Command::new("chgrp")
            .arg("innerwarden")
            .arg(env_path)
            .output();
    }
    Ok(())
}

pub(crate) fn prompt(label: &str) -> Result<String> {
    print!("{label}: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub(crate) fn prompt_with_hint(label: &str, hint: &str) -> Result<String> {
    print!("{label} ({hint}): ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub(crate) fn hostname() -> String {
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim().to_string();
        if !h.is_empty() {
            return h;
        }
    }
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}

/// The label this host's incidents are stamped with, for display in operator
/// messages. Prefers the sensor's `[agent] host_id` — that's exactly what real
/// incidents (and their Telegram/Slack alerts) carry, so a test alert shows the
/// same name and the operator can tell which box it came from. Falls back to the
/// system hostname.
pub(crate) fn host_label(sensor_config: &Path) -> String {
    if let Ok(content) = std::fs::read_to_string(sensor_config) {
        if let Ok(doc) = content.parse::<toml_edit::DocumentMut>() {
            if let Some(h) = doc
                .get("agent")
                .and_then(|a| a.get("host_id"))
                .and_then(|v| v.as_str())
            {
                let h = h.trim();
                if !h.is_empty() && h != "test-host" {
                    return h.to_string();
                }
            }
        }
    }
    hostname()
}

/// Load key=value pairs from an env file (silently ignores missing file).
pub(crate) fn load_env_file(path: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
            }
        }
    }
    map
}

/// Mask a secret for display: "123456789:ABC" → "123***ABC".
pub(crate) fn mask_secret(s: &str) -> String {
    if s.len() <= 6 {
        "***".to_string()
    } else {
        format!("{}***{}", &s[..3], &s[s.len() - 3..])
    }
}

/// Send a plain Telegram message (MarkdownV2).
pub(crate) fn send_telegram_message_md(token: &str, chat_id: &str, text: &str) -> Result<()> {
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    let body = serde_json::json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "MarkdownV2"
    });
    let resp = ureq::post(&url)
        .header("Content-Type", "application/json")
        .send(body.to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let json: serde_json::Value = resp.into_body().read_json()?;
    if json["ok"].as_bool() != Some(true) {
        anyhow::bail!(
            "{}",
            json["description"].as_str().unwrap_or("unknown error")
        );
    }
    Ok(())
}

pub(crate) fn looks_like_ip(s: &str) -> bool {
    // Accept IPv4 (digits and dots) or IPv6 (hex, colons, optional /)
    let s = s.split('/').next().unwrap_or(s); // strip CIDR
    let v4 = s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok());
    let v6 = s.contains(':') && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
    v4 || v6
}

pub(crate) fn restart_agent(cli: &Cli) {
    if cli.dry_run {
        return;
    }
    let is_macos = std::env::consts::OS == "macos";
    if is_macos {
        let _ = systemd::restart_launchd("com.innerwarden.agent", false);
        println!("  [ok] innerwarden-agent restarted");
    } else {
        let _ = systemd::restart_service("innerwarden-agent", false);
        println!("  [ok] innerwarden-agent restarted");
    }
}

/// Check whether the current process can write to the InnerWarden config directory.
/// If not, print a clear hint and exit - avoids failing mid-operation.
pub(crate) fn require_sudo(cli: &Cli) {
    let config_dir = cli
        .agent_config
        .parent()
        .unwrap_or_else(|| Path::new("/etc/innerwarden"));

    // Try creating a temp file in the directory as the write test
    let test_path = config_dir.join(".innerwarden-write-test");
    match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&test_path)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&test_path);
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "Permission denied: cannot write to {}",
                config_dir.display()
            );
            eprintln!();
            // Reconstruct the original command to show the sudo hint
            let args: Vec<String> = std::env::args().collect();
            let cmd_args = args[1..].join(" ");
            eprintln!("Run with sudo:");
            eprintln!("  sudo innerwarden {cmd_args}");
            std::process::exit(1);
        }
        Err(_) => {} // some other error; let the real operation surface it
    }
}

pub(crate) fn resolve_data_dir(cli: &Cli, data_dir: &Path) -> PathBuf {
    if data_dir == Path::new("/var/lib/innerwarden") {
        std::fs::read_to_string(&cli.agent_config)
            .ok()
            .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
            .and_then(|v| {
                v.get("output")
                    .and_then(|o| o.get("data_dir"))
                    .and_then(|d| d.as_str())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| data_dir.to_path_buf())
    } else {
        data_dir.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- host_label --

    #[test]
    fn host_label_reads_sensor_host_id() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(
            &cfg,
            "[agent]\nhost_id = \"azure-spot\"\ndata_dir = \"/x\"\n",
        )
        .unwrap();
        assert_eq!(host_label(&cfg), "azure-spot");
    }

    #[test]
    fn host_label_ignores_test_host_and_empty_then_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        // sentinel "test-host" is treated as unset → fall back to system hostname
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "[agent]\nhost_id = \"test-host\"\n").unwrap();
        assert_ne!(host_label(&cfg), "test-host");
        // missing file → fall back too (does not panic)
        let _ = host_label(&dir.path().join("nope.toml"));
    }

    // -- mask_secret --

    #[test]
    fn mask_secret_short_string() {
        assert_eq!(mask_secret("abc"), "***");
        assert_eq!(mask_secret(""), "***");
        assert_eq!(mask_secret("123456"), "***");
    }

    #[test]
    fn mask_secret_long_string() {
        assert_eq!(mask_secret("1234567890:AAAA"), "123***AAA");
    }

    #[test]
    fn mask_secret_exactly_7_chars() {
        assert_eq!(mask_secret("abcdefg"), "abc***efg");
    }

    // -- looks_like_ip --

    #[test]
    fn looks_like_ip_valid_ipv4() {
        assert!(looks_like_ip("192.168.1.1"));
        assert!(looks_like_ip("10.0.0.1"));
        assert!(looks_like_ip("255.255.255.255"));
    }

    #[test]
    fn looks_like_ip_valid_ipv4_cidr() {
        assert!(looks_like_ip("10.0.0.0/8"));
        assert!(looks_like_ip("192.168.1.0/24"));
    }

    #[test]
    fn looks_like_ip_valid_ipv6() {
        assert!(looks_like_ip("2001:db8::1"));
        assert!(looks_like_ip("::1"));
    }

    #[test]
    fn looks_like_ip_rejects_hostnames() {
        assert!(!looks_like_ip("example.com"));
        assert!(!looks_like_ip("localhost"));
        assert!(!looks_like_ip(""));
    }

    #[test]
    fn looks_like_ip_rejects_partial() {
        assert!(!looks_like_ip("192.168.1"));
        assert!(!looks_like_ip("999.999.999.999"));
    }

    // -- load_env_file --

    #[test]
    fn load_env_file_parses_key_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.env");
        std::fs::write(
            &path,
            "KEY1=value1\nKEY2=value2\n# comment\n\nKEY3=\"quoted\"\n",
        )
        .unwrap();
        let map = load_env_file(&path);
        assert_eq!(map.get("KEY1").unwrap(), "value1");
        assert_eq!(map.get("KEY2").unwrap(), "value2");
        assert_eq!(map.get("KEY3").unwrap(), "quoted");
        assert!(!map.contains_key("# comment"));
    }

    #[test]
    fn load_env_file_missing_returns_empty() {
        let map = load_env_file(Path::new("/nonexistent/path.env"));
        assert!(map.is_empty());
    }

    // -- write_env_key --

    #[test]
    fn write_env_key_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.env");
        write_env_key(&path, "MY_KEY", "my_value").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("MY_KEY=my_value"));
    }

    #[test]
    fn write_env_key_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.env");
        std::fs::write(&path, "MY_KEY=old\nOTHER=keep\n").unwrap();
        write_env_key(&path, "MY_KEY", "new").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("MY_KEY=new"));
        assert!(content.contains("OTHER=keep"));
        assert!(!content.contains("MY_KEY=old"));
    }

    #[test]
    fn write_env_key_replaces_commented_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commented.env");
        std::fs::write(&path, "#MY_KEY=old_commented\nOTHER=keep\n").unwrap();
        write_env_key(&path, "MY_KEY", "active").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("MY_KEY=active"));
        assert!(!content.contains("old_commented"));
    }
}
