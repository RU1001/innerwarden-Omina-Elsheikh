use anyhow::Result;
use chrono::Utc;
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::auth_log::parse_sshd_message;

/// Whether the host `log` binary is the real macOS unified-logging tool that
/// can stream. `spawned` is whether `log --help` executed at all; `help_output`
/// is its combined stdout+stderr. We check for the `stream` subcommand rather
/// than the exit code because Apple's `log` returns 64 for usage output
/// (finding F10: the old `log version` gate exited 64 and wrongly disabled the
/// collector on every macOS).
fn log_tool_usable(spawned: bool, help_output: &str) -> bool {
    spawned && help_output.contains("stream")
}

/// Decide usability from the `log --help` probe result: map a spawn error to
/// "unusable", otherwise combine stdout+stderr and check for the `stream`
/// subcommand (ignoring the exit code, since Apple's `log` exits 64 for usage).
/// Pure over the injected `Output` so the probe branch is unit-tested.
fn probe_says_usable(probe: &std::io::Result<std::process::Output>) -> bool {
    match probe {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            log_tool_usable(true, &text)
        }
        Err(_) => log_tool_usable(false, ""),
    }
}

pub struct MacosLogCollector {
    host: String,
}

impl MacosLogCollector {
    pub fn new(host: impl Into<String>) -> Self {
        Self { host: host.into() }
    }

    /// Stream macOS system log events via `log stream`.
    /// Parses SSH and sudo events from the output.
    pub async fn run(self, tx: mpsc::Sender<Event>) -> Result<()> {
        // Confirm the host `log` binary is the real macOS unified-logging tool.
        //
        // The old probe ran `log version`, but `version` is NOT a valid
        // subcommand (`log: Unknown subcommand 'version'`, exit 64), so the
        // check ALWAYS failed and this collector disabled itself on every
        // modern macOS (2026-07-01 finding F10 — the sensor's primary macOS
        // log source never ran). `log --help` ALSO exits 64 (Apple returns 64
        // for usage), so we must ignore the exit code entirely and instead
        // confirm the usage output advertises the `stream` subcommand we need.
        let probe = Command::new("log").arg("--help").output().await;
        if !probe_says_usable(&probe) {
            warn!("macOS `log` tool unavailable (no `stream` subcommand) - macos_log collector disabled");
            return Ok(());
        }

        info!(host = %self.host, "macos_log collector starting");

        // Restart loop - if `log stream` exits unexpectedly, restart it.
        loop {
            let mut cmd = Command::new("log");
            cmd.args([
                "stream",
                "--predicate",
                "process == \"sshd\" OR process == \"sudo\"",
                "--style",
                "syslog",
                "--info",
            ])
            .stdout(std::process::Stdio::piped());

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    warn!("failed to spawn log stream: {e}");
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            let stdout = child.stdout.take().expect("stdout piped");
            let mut lines = BufReader::new(stdout).lines();

            loop {
                tokio::select! {
                    result = lines.next_line() => {
                        match result {
                            Ok(Some(line)) => {
                                if let Some(event) = parse_macos_log_line(&line, &self.host) {
                                    if tx.send(event).await.is_err() {
                                        let _ = child.kill().await;
                                        return Ok(());
                                    }
                                }
                            }
                            Ok(None) => break, // log stream exited
                            Err(e) => {
                                warn!("macos_log read error: {e}");
                                break;
                            }
                        }
                    }
                    // Poll for shutdown every second even when no entries arrive
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                        if tx.is_closed() {
                            let _ = child.kill().await;
                            return Ok(());
                        }
                    }
                }
            }

            if tx.is_closed() {
                return Ok(());
            }

            warn!("log stream exited unexpectedly - restarting in 5s");
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse one line from `log stream --style syslog` output.
///
/// The syslog format looks like:
///   Jan 15 15:00:01.123 hostname sshd[1234]: <message>
///   Jan 15 15:00:01.123 hostname sudo[5678]: <message>
///
/// Returns `None` if the line is not an SSH or sudo event we care about.
fn parse_macos_log_line(line: &str, host: &str) -> Option<Event> {
    // Must contain a process marker we care about
    if line.contains("sshd[") {
        // Extract message after "sshd[pid]: "
        let msg = line.split_once("]: ")?.1.trim();
        return parse_sshd_message(msg, host, "macos_log");
    }

    if line.contains("sudo[") {
        return parse_macos_sudo_line(line, host);
    }

    None
}

/// Parse a sudo log line from macOS log stream output.
/// Example:
///   Jan 15 15:00:01.123 hostname sudo[1234]: deploy : TTY=ttys001 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id
fn parse_macos_sudo_line(line: &str, host: &str) -> Option<Event> {
    // Must contain USER= and COMMAND= to be a command execution entry
    if !line.contains("USER=") || !line.contains("COMMAND=") {
        return None;
    }

    // Extract message after "sudo[pid]: "
    let msg = line.split_once("]: ")?.1.trim();

    let sudo_user = msg.split(':').next()?.trim();
    let run_as = field_after(msg, "USER=")?;
    let command = field_after(msg, "COMMAND=")?;

    Some(Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "macos_log".to_string(),
        kind: "sudo.command".to_string(),
        severity: Severity::Info,
        summary: format!("{sudo_user} ran sudo as {run_as}: {command}"),
        details: serde_json::json!({
            "user": sudo_user,
            "run_as": run_as,
            "command": command,
        }),
        tags: vec!["auth".to_string(), "sudo".to_string()],
        entities: vec![EntityRef::user(sudo_user)],
    })
}

/// Extract the value of a `KEY=value` field (stops at ';' or end of string).
fn field_after<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let pos = s.find(key)?;
    let rest = &s[pos + key.len()..];
    let end = rest.find(';').unwrap_or(rest.len());
    Some(rest[..end].trim())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// F10 anchor (2026-07-01): the availability probe must accept the real
    /// Apple `log` usage output (which advertises `stream`) EVEN THOUGH `log`
    /// exits 64 for `--help`. The old `log version` gate keyed on the exit code
    /// and disabled the collector on every modern macOS.
    #[test]
    fn log_tool_usable_accepts_apple_log_usage_output() {
        // Trimmed real `log --help` output — note it has no zero exit but does
        // list the `stream` subcommand.
        let usage = "usage:\n    log <command>\ncommands:\n    show\n    stream\n    stats\n";
        assert!(log_tool_usable(true, usage));
    }

    #[test]
    fn log_tool_usable_rejects_missing_binary_or_foreign_tool() {
        // Binary did not spawn at all.
        assert!(!log_tool_usable(false, ""));
        // Some other `log` on PATH that has no `stream` subcommand.
        assert!(!log_tool_usable(true, "usage: log [--rotate] <file>\n"));
    }

    #[test]
    fn probe_says_usable_maps_output_and_spawn_error() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::{ExitStatus, Output};
        // Real Apple `log --help`: nonzero exit (64) but usage advertises stream.
        let apple = Ok(Output {
            status: ExitStatus::from_raw(64 << 8),
            stdout: b"usage:\n    log <command>\n    stream\n".to_vec(),
            stderr: Vec::new(),
        });
        assert!(probe_says_usable(&apple));
        // Foreign `log` with no stream subcommand.
        let foreign = Ok(Output {
            status: ExitStatus::from_raw(0),
            stdout: b"usage: log [--rotate]\n".to_vec(),
            stderr: Vec::new(),
        });
        assert!(!probe_says_usable(&foreign));
        // Binary absent → spawn error.
        let missing: std::io::Result<Output> =
            Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(!probe_says_usable(&missing));
    }

    #[test]
    fn line_with_sshd_is_recognized() {
        let line = "Jan 15 15:00:01.123 mymac sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 55123 ssh2";
        let ev = parse_macos_log_line(line, "mymac").expect("should parse SSH event");
        assert_eq!(ev.kind, "ssh.login_failed");
        assert_eq!(ev.source, "macos_log");
        assert_eq!(ev.details["ip"], "1.2.3.4");
        assert_eq!(ev.details["user"], "admin");
    }

    #[test]
    fn line_without_sshd_returns_none() {
        let line = "Jan 15 15:00:01.123 mymac kernel[0]: Some random kernel message";
        assert!(parse_macos_log_line(line, "mymac").is_none());
    }

    #[test]
    fn line_with_sshd_accepted_is_recognized() {
        let line = "Jan 15 15:00:01.123 mymac sshd[1234]: Accepted publickey for ubuntu from 10.0.0.1 port 54321 ssh2: RSA SHA256:abc";
        let ev = parse_macos_log_line(line, "mymac").expect("should parse SSH event");
        assert_eq!(ev.kind, "ssh.login_success");
        assert_eq!(ev.details["user"], "ubuntu");
        assert_eq!(ev.details["method"], "publickey");
    }

    #[test]
    fn line_with_sshd_missing_separator() {
        let line = "Jan 15 15:00:01.123 mymac sshd[1234] some other format";
        assert!(parse_macos_log_line(line, "mymac").is_none());
    }

    #[test]
    fn sudo_line_missing_user_returns_none() {
        let line = "Jan 15 15:00:01.123 mymac sudo[5678]: deploy : TTY=ttys001 ; PWD=/home/deploy ; COMMAND=/usr/bin/id";
        assert!(parse_macos_log_line(line, "mymac").is_none());
    }

    #[test]
    fn sudo_line_missing_colon_separator() {
        let line = "Jan 15 15:00:01.123 mymac sudo[5678]: USER=root ; COMMAND=/usr/bin/id";
        let ev = parse_macos_log_line(line, "mymac").unwrap();
        // Without colon, the whole message prefix is treated as the user.
        assert!(ev.details["user"]
            .as_str()
            .unwrap()
            .starts_with("USER=root"));
    }

    #[test]
    fn test_field_after() {
        assert_eq!(field_after("A=1 ; B=2", "A="), Some("1"));
        assert_eq!(field_after("A=1 ; B=2", "B="), Some("2"));
        assert_eq!(field_after("A=1 ; B=2 ; C=3", "B="), Some("2"));
        assert_eq!(field_after("A=1", "C="), None);
    }

    #[test]
    fn sudo_line_is_recognized() {
        let line = "Jan 15 15:00:01.123 mymac sudo[5678]: deploy : TTY=ttys001 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id";
        let ev = parse_macos_log_line(line, "mymac").expect("should parse sudo event");
        assert_eq!(ev.kind, "sudo.command");
        assert_eq!(ev.source, "macos_log");
        assert_eq!(ev.details["user"], "deploy");
        assert_eq!(ev.details["run_as"], "root");
        assert!(ev.details["command"]
            .as_str()
            .unwrap()
            .contains("/usr/bin/id"));
    }
}
