//! eBPF-based data exfiltration detector.
//!
//! Correlates sensitive file reads (`file.read_access` on /etc/shadow,
//! /etc/passwd, .ssh/*, etc.) with subsequent outbound network connections
//! (`network.outbound_connect`) from the same PID within a short window.
//!
//! This catches the pattern: read sensitive data → send it out, which is
//! invisible to single-event detectors.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Sensitive file paths that trigger tracking. Matched case-insensitively
/// via a `contains` check (see [`is_sensitive_path`]) so trailing chrome
/// profile paths and per-user expansions are caught without enumeration.
///
/// 2026-05-25 (Cyber Defense Benchmark audit): added cloud-credential and
/// browser-credential paths to close the gaps the Simbian AI benchmark
/// identifies as "tactic blind spots" — Credential Access and Collection
/// where LLM threat hunters consistently miss the evidence. The
/// read-then-outbound co-occurrence requirement plus the
/// `is_browser_self_access` and `BACKUP_TOOLS` allowlists keep this
/// FP-safe — Chrome reading its own Login Data and rclone uploading a
/// home-dir backup both pass through without alert.
// SPECIFIC credential paths — distinctive enough that a match is a real
// credential read REGARDLESS of file extension or location (e.g. even a key
// named `id_rsa` planted under node_modules still counts). These are NEVER
// relaxed by the source-file guard below, so an attacker cannot evade by
// staging a real credential at a .js path.
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/.ssh/",
    "/authorized_keys",
    "/id_rsa",
    "/id_ed25519",
    "/id_ecdsa",
    "/.env",
    "/.aws/credentials",
    "/.kube/config",
    // ── Cloud credentials (Credential Access, T1552.001) ──────────────
    // Docker Hub auth tokens: `docker login` writes a base64'd
    // username:password (or registry token) into config.json.
    "/.docker/config.json",
    // gcloud OAuth refresh tokens + access token cache. Either file
    // alone is enough to impersonate the user across all GCP services
    // the account can reach.
    "/.config/gcloud/credentials.db",
    "/.config/gcloud/access_tokens.db",
    "/.config/gcloud/application_default_credentials.json",
    // rclone stores SSH keys, cloud-storage tokens, and S3 secrets
    // in a single file (optionally encrypted, often not).
    "/.config/rclone/rclone.conf",
    // ── Browser credentials (Collection, T1555.003 / T1539) ───────────
    // Chrome / Chromium / Edge save logins in a SQLite called
    // literally "Login Data" (capitalised, space). Lowercase-match
    // via `is_sensitive_path` catches it under every profile path.
    "/login data",
    // Firefox: key4.db holds the NSS master key, logins.json the
    // encrypted credentials, cookies.sqlite the session cookies.
    // Stealing all three = full account takeover for any site the
    // user is logged into.
    "/key4.db",
    "/logins.json",
    "/cookies.sqlite",
];

/// GENERIC credential keywords — high recall, but they also appear in ordinary
/// source/package file paths (`dist/secret-contract-api.js` contains `/secret`,
/// `.../token/const.mjs` contains `/token`). These match ONLY when the file is
/// not a source/package artifact, so loading a JS module never looks like a
/// credential read. They never gate the SPECIFIC list above, so a genuine
/// credential is still caught even if its path also looks code-like.
const SENSITIVE_GENERIC_TOKENS: &[&str] = &["/secret", "/token", "/credentials"];

/// Browser process names (truncated to 15 chars by Linux's TASK_COMM_LEN
/// where applicable). Reading browser-data paths from a browser process
/// is the browser doing its job; we skip those reads entirely so the
/// detector never fires on Chrome auto-syncing its own Login Data over
/// HTTPS.
///
/// Matched with `starts_with`: covers `google-chrome`, `google-chrom`
/// (the truncated comm), `chromium-browse`, `firefox-bin`,
/// `MainThread` (Chrome's worker thread comm), etc.
const BROWSER_PROCESS_PREFIXES: &[&str] = &[
    "chrome",
    "chromium",
    "google-chrom",
    "firefox",
    "MainThread", // Chrome renderer/utility process comm
    "brave",
    "msedge",
    "microsoft-edge",
    "opera",
    "vivaldi",
    "thunderbird", // also uses logins.json + key4.db
];

/// Browser-data path substrings. Reads of these paths by a
/// `BROWSER_PROCESS_PREFIXES` process are skipped — see
/// [`is_browser_self_access`].
const BROWSER_DATA_PATH_HINTS: &[&str] = &[
    "/login data",
    "/key4.db",
    "/logins.json",
    "/cookies.sqlite",
    "/google-chrome/",
    "/chromium/",
    "/.mozilla/firefox/",
    "/brave-browser/",
    "/microsoft-edge/",
];

/// Backup tools that legitimately read everything under $HOME (including
/// cloud creds, browser data, SSH keys) and upload to a remote target as
/// part of their job. They cannot be distinguished from exfil by the
/// read-then-outbound pattern alone — the operator's intent (backup vs
/// exfil) is in the tool's config file, not in the kernel events.
///
/// Allowlisting here means the detector NEVER fires for these comms.
/// Operators who run backup tools they don't trust should remove the
/// entry locally; the trade-off is documented in the wiki Operations
/// page.
const BACKUP_TOOLS: &[&str] = &[
    "rclone",
    "restic",
    "borg",
    "borgmatic",
    "duplicity",
    "duplicati",
    "kopia",
    "tarsnap",
];

/// Per-PID tracking of sensitive file access.
struct SensitiveRead {
    ts: DateTime<Utc>,
    filename: String,
    comm: String,
}

/// Detects data exfiltration by correlating sensitive file reads with
/// outbound network connections from the same process.
pub struct DataExfilEbpfDetector {
    host: String,
    /// Window in which a connect after a sensitive read is suspicious.
    window: Duration,
    /// Recent sensitive file reads by PID.
    pending_reads: HashMap<u32, SensitiveRead>,
    /// Cooldown: suppress re-alerts per PID.
    alerted: HashMap<u32, DateTime<Utc>>,
    cooldown: Duration,
}

impl DataExfilEbpfDetector {
    pub fn new(host: impl Into<String>, window_seconds: u64, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            window: Duration::seconds(window_seconds as i64),
            pending_reads: HashMap::new(),
            alerted: HashMap::new(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        let pid = event.details.get("pid").and_then(|v| v.as_u64())? as u32;
        let now = event.ts;

        // Skip InnerWarden's own processes — the sensor legitimately reads
        // /etc/ssh/sshd_config and makes outbound API calls (AbuseIPDB, GeoIP).
        let ev_uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX);
        let ev_comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if super::allowlists::is_innerwarden_process(ev_uid, ev_comm) {
            return None;
        }

        // Cloud guest-agent downgrade: the platform's own management agent
        // (Azure WALinuxAgent / ExtHandler) reads /etc/passwd (getpwuid) then
        // connects to the control plane — a read-then-connect shape that cannot
        // be told from exfil at the kernel layer. Observed as a persistent FP
        // from `ExtHandler` on an Azure VM. The short-lived `ExtHandler` child
        // often EXITS before this detector runs (its `/proc` is gone), so fall
        // back to its LONG-LIVED PARENT (`WALinuxAgent ... -run-exthandlers`,
        // carried as `ppid`) whose `/proc` lineage still resolves. NON-FORGEABLE
        // (real /proc lineage), gated on a DMI-detected cloud VM + uid 0.
        // Downgrade-only: a real process from /tmp, or any non-root, still fires.
        let guest_uid = if ev_uid == u64::MAX { 0 } else { ev_uid };
        let ev_ppid = event.details.get("ppid").and_then(|v| v.as_u64());
        let is_guest = crate::cloud_platform::is_guest_agent(pid, guest_uid as u32)
            || ev_ppid.is_some_and(|pp| {
                pp != 0 && crate::cloud_platform::is_guest_agent(pp as u32, guest_uid as u32)
            });
        if is_guest {
            return None;
        }

        // BLANKET-exempt processes: server DAEMONS that read /etc/passwd for
        // NSS uid→name resolution on every request/session and are always
        // making outbound calls as part of their job (CrowdSec bouncers, web
        // servers, MTAs). Their read-then-connect shape cannot be distinguished
        // from exfil at the kernel layer, so they are allowed for ALL files.
        //
        // 2026-07-02 (agent-runtime blind spot, found by a live red-team):
        // the interpreter/agent runtimes `python`, `python3`, `node`, `ruby`,
        // `java`, `php`, `openclaw`, `libuv-worker` used to be in THIS blanket
        // list. That silently exempted every AI coding agent (which runs as
        // exactly those comms) from this detector: a compromised python/node/
        // openclaw agent reading `~/.aws/credentials` / `~/.ssh/id_rsa` / `.env`
        // and connecting out was dropped here before it was ever tracked — the
        // exact threat the product exists to catch. They are now handled by the
        // NARROW `/etc/passwd`-only NSS-init gate below (their only benign
        // read-then-connect is the getpwuid_r startup read of /etc/passwd), so
        // their reads of REAL secrets now fire again.
        const PASSWD_READERS: &[&str] = &[
            "http",
            "https",
            "nginx",
            "apache",
            "httpd",
            "crowdsec",
            "cscli",
            "cs-",
            "bouncer",
            "sshd",
            "login",
            "su",
            "sudo",
            "cron",
            "crond",
            "atd",
            "postfix",
            "dovecot",
            "sendmail",
            "systemd",
            "dbus-daemon",
            "polkitd",
        ];
        if PASSWD_READERS.iter().any(|p| ev_comm.starts_with(p)) {
            // `comm` is attacker-forgeable (prctl/argv0), so `cp evil /tmp/sshd`
            // would otherwise inherit sshd's blanket credential-read exemption and
            // exfiltrate `~/.aws/credentials` undetected (found by a live red-team,
            // 2026-07-02). Only honour the daemon exemption when the NON-forgeable
            // kernel-captured exe path is OS-trusted (a real daemon under
            // /usr/sbin etc.). A comm-spoofed reader from an untrusted path (/tmp,
            // /home, /dev/shm) is NOT exempt and its secret reads fire. exe_path
            // absent (a daemon whose execve predates the sensor, so it was never
            // cached) → fall back to the comm exemption to avoid a FP on legitimate
            // long-running daemons.
            let comm_spoofed_from_untrusted_path = event
                .details
                .get("exe_path")
                .and_then(|v| v.as_str())
                .map(|exe| !crate::path_trust::is_trusted_system_path(exe))
                .unwrap_or(false);
            if !comm_spoofed_from_untrusted_path {
                return None;
            }
        }

        // 2026-05-25: backup tools (rclone, restic, borg, …) read
        // everything under $HOME and upload to a remote target as
        // their job. The read-then-outbound shape is indistinguishable
        // from exfil at the kernel layer — the operator's intent is
        // in the tool's config file, not in eBPF. Allowlist them.
        if BACKUP_TOOLS.iter().any(|t| ev_comm.starts_with(t)) {
            return None;
        }

        // Phase 1: Track sensitive file reads
        if event.kind == "file.read_access" || event.kind == "file.write_access" {
            let filename = event
                .details
                .get("filename")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if is_sensitive_path(filename) {
                let comm = event
                    .details
                    .get("comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                // 2026-05-25: skip browsers reading their own data.
                // Chrome auto-syncs Login Data over HTTPS continuously;
                // Firefox writes logins.json on every saved password.
                // Either pattern would fire Critical for every browser
                // session if we didn't gate here.
                if is_browser_self_access(&comm, filename) {
                    return None;
                }
                self.pending_reads.insert(
                    pid,
                    SensitiveRead {
                        ts: now,
                        filename: filename.to_string(),
                        comm,
                    },
                );
            }
            return None;
        }

        // Phase 2: Check if outbound connect follows a sensitive read
        if event.kind == "network.outbound_connect" {
            // Expire old reads
            let cutoff = now - self.window;
            self.pending_reads.retain(|_, r| r.ts > cutoff);

            // Peek dst_port BEFORE consuming the pending read: port 0 means
            // eBPF never observed a real TCP handshake (connect error, NSS
            // probe, AF_UNIX upgrade). Drop the event and keep the pending
            // read in the map so a later real connect can still correlate.
            let dst_port = event
                .details
                .get("dst_port")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16;
            if dst_port == 0 {
                return None;
            }

            // Correlate the connect to a pending sensitive read: same PID first,
            // then (split-pid evasion, 2026-07-02) the connecting process's PARENT.
            // An attacker who reads the secret in a parent and forks a child to do
            // the outbound connect would otherwise slip the same-PID correlation.
            // The parent read must itself be a genuinely sensitive file (only those
            // are in `pending_reads`), so a shell that read `~/.aws/credentials`
            // then forked a `curl` to send it out is caught — a legitimately
            // suspicious shape, not a broad heuristic.
            let ppid = event
                .details
                .get("ppid")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
                .filter(|&pp| pp != 0 && pp != pid);
            let matched = self
                .pending_reads
                .remove(&pid)
                .map(|r| (pid, r))
                .or_else(|| ppid.and_then(|pp| self.pending_reads.remove(&pp).map(|r| (pp, r))));
            if let Some((read_pid, read)) = matched {
                let split_pid = read_pid != pid;
                // Same PID read a sensitive file then made outbound connection
                let dst_ip = event
                    .details
                    .get("dst_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let comm = event
                    .details
                    .get("comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&read.comm);

                // Skip internal IPs
                if super::is_internal_ip(dst_ip) {
                    return None;
                }

                // Targeted NSS-init suppression.
                //
                // Every dynamically linked C program calls `getpwuid_r` /
                // `getpwnam_r` at startup, which opens `/etc/passwd`. CLI
                // tools like wget, curl, git, apt that ALSO make outbound
                // connections trivially trip "read sensitive file →
                // connect" in the first milliseconds of startup. Observed
                // 2026-04-11: Critical FP on `wget read /etc/passwd then
                // connected to 34.244.58.147:0` — 6ms between read and
                // connect, port 0 (never established) — pure NSS init.
                //
                // The suppression is INTENTIONALLY NARROW:
                //   - file must be exactly "/etc/passwd" (NSS file), AND
                //   - comm must be a known CLI network tool whose NSS
                //     lookup is legitimate.
                //
                // Reads of `/etc/shadow`, `~/.ssh/*`, `id_rsa`, `.env`,
                // `/credentials`, `.kube/config` by wget/curl/git/etc. are
                // NOT NSS init and STILL fire Critical alerts. A real
                // exfil of shadow hashes or SSH keys by a renamed-to-wget
                // attacker is caught unchanged.
                // 2026-04-30: added `ssh` after operator hit FP on
                // `git fetch origin` -> ssh git@github.com (the
                // github.com SSH endpoint resolves to Azure 20.x).
                // ssh client always reads /etc/passwd at startup for
                // NSS uid->name resolution then opens the outbound
                // connection — exact NSS-init signature.
                //
                // Why this is safe (the analysis the operator
                // explicitly asked for):
                //
                //   1. The suppression triggers ONLY when:
                //      a) sensitive_file == "/etc/passwd" (exact)
                //      b) read.comm starts with one of these prefixes
                //
                //   2. /etc/passwd is world-readable, contains no
                //      secrets — only `username:x:uid:gid:gecos:home:shell`.
                //      An attacker exfiltrating it gets nothing they
                //      cannot already learn via `id`, `who`, `last`.
                //
                //   3. Real exfil paths still fire Critical alerts:
                //      ssh reading /etc/shadow, ~/.ssh/id_*, .env,
                //      .kube/config, /credentials, GPG keyrings. The
                //      filename match is `==`, not prefix, so
                //      anything other than the literal /etc/passwd
                //      path is not covered.
                //
                //   4. Attacker bypass requires BOTH (a) renaming
                //      their malicious binary's comm to start with
                //      "ssh" / "git" / etc, AND (b) only reading
                //      /etc/passwd before connecting out. Real
                //      exfil that wants to send anything useful
                //      reads secrets — those still fire.
                //
                // Did NOT whitelist by destination IP / hostname (no
                // 20.x range trust, no github.com hostname trust).
                // That class of whitelist is the dangerous one
                // because attackers rent Azure VMs ($1/day, instant
                // 20.x IP) and use github.com as legitimate-looking
                // C2 (Octopus Scanner, GitHub C2 TTPs).
                const NSS_INIT_CLI_TOOLS: &[&str] = &[
                    "wget",
                    "curl",
                    "git",
                    "git-remote",
                    "ssh",
                    "scp",
                    "sftp",
                    "rsync",
                    "apt",
                    "apt-get",
                    "apt-check",
                    "dpkg",
                    "snap",
                    "snapd",
                    "pip",
                    "pip3",
                    "npm",
                    "yarn",
                    "cargo",
                    "rustup",
                    "gem",
                    "composer",
                    "mvn",
                    "gradle",
                    // Interpreter / AI-agent runtimes. They also getpwuid_r at
                    // startup (reads /etc/passwd) then connect to their LLM/API,
                    // so their /etc/passwd read-then-connect is benign NSS init
                    // and is suppressed HERE — but, unlike the old blanket gate,
                    // their reads of REAL secrets (.aws/.ssh/.env) are NOT
                    // covered by this `== "/etc/passwd"` match and now fire
                    // (2026-07-02 agent-runtime blind-spot fix).
                    "python",
                    "python3",
                    "node",
                    "ruby",
                    "java",
                    "php",
                    "openclaw",
                    "libuv-worker",
                ];
                let is_nss_init = read.filename == "/etc/passwd"
                    && NSS_INIT_CLI_TOOLS.iter().any(|p| read.comm.starts_with(p));
                if is_nss_init {
                    return None;
                }

                // Cooldown check
                if let Some(&last) = self.alerted.get(&pid) {
                    if now - last < self.cooldown {
                        return None;
                    }
                }
                self.alerted.insert(pid, now);

                let elapsed = (now - read.ts).num_seconds();

                return Some(Incident {
                    ts: now,
                    host: self.host.clone(),
                    incident_id: format!("data_exfil_ebpf:{pid}:{}", now.format("%Y-%m-%dT%H:%MZ")),
                    severity: Severity::Critical,
                    title: format!(
                        "Data exfiltration: {comm} read {} then connected to {dst_ip}:{dst_port}",
                        read.filename
                    ),
                    summary: format!(
                        "Process {comm} (pid={pid}){} read sensitive file {} then made outbound \
                         connection to {dst_ip}:{dst_port} within {elapsed}s. This pattern \
                         indicates data exfiltration — the file content may have been sent \
                         to the remote host.",
                        if split_pid {
                            format!(" (child of the reader pid={read_pid})")
                        } else {
                            String::new()
                        },
                        read.filename
                    ),
                    evidence: serde_json::json!([{
                        "kind": "data_exfil_ebpf",
                        "detection": if split_pid { "parent_read_child_connect" } else { "read_then_connect" },
                        "comm": comm,
                        "pid": pid,
                        "reader_pid": read_pid,
                        "split_pid": split_pid,
                        "sensitive_file": read.filename,
                        "file_read_ts": read.ts.to_rfc3339(),
                        "connect_ts": now.to_rfc3339(),
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "elapsed_seconds": elapsed,
                    }]),
                    recommended_checks: vec![
                        format!("Kill process: kill -9 {pid}"),
                        format!("Block destination: {dst_ip}"),
                        format!(
                            "Check if {} was exfiltrated — rotate credentials if so",
                            read.filename
                        ),
                        "Review process tree for attack origin".to_string(),
                    ],
                    tags: vec![
                        "data_exfiltration".to_string(),
                        "ebpf".to_string(),
                        "sensitive_file".to_string(),
                    ],
                    entities: vec![EntityRef::ip(dst_ip), EntityRef::path(&read.filename)],
                });
            }
        }

        // Prune stale data
        if self.pending_reads.len() > 5000 {
            let cutoff = now - self.window;
            self.pending_reads.retain(|_, r| r.ts > cutoff);
        }
        if self.alerted.len() > 1000 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        None
    }
}

fn is_sensitive_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    // SPECIFIC credential paths ALWAYS count — distinctive enough that an
    // attacker can't evade by giving a real key a code-like name or hiding it
    // under node_modules. /etc/shadow, id_rsa, .aws/credentials, etc. are
    // credentials wherever they appear.
    if SENSITIVE_PATHS.iter().any(|s| lower.contains(s)) {
        return true;
    }
    // GENERIC keyword matches (/secret, /token, /credentials) are relaxed ONLY
    // for source/package artifacts, because those words routinely appear in
    // ordinary JS/TS module paths. This was the dominant false positive: an AI
    // agent loading its own `node_modules/.../dist/secret-contract-api.js` then
    // calling an API was flagged CRITICAL "data exfiltration". A read of a
    // non-code file whose path contains a generic keyword is still sensitive.
    // (`.json` is NOT treated as code — gcloud credentials.json is genuine.)
    if is_source_or_package_artifact(&lower) {
        return false;
    }
    SENSITIVE_GENERIC_TOKENS.iter().any(|t| lower.contains(t))
}

/// True for JS/TS source and package artifacts (or anything under
/// `node_modules/`) — module code, never a real credential.
fn is_source_or_package_artifact(lower_path: &str) -> bool {
    lower_path.contains("/node_modules/")
        || lower_path.ends_with(".js")
        || lower_path.ends_with(".mjs")
        || lower_path.ends_with(".cjs")
        || lower_path.ends_with(".ts")
        || lower_path.ends_with(".tsx")
        || lower_path.ends_with(".jsx")
        || lower_path.ends_with(".map")
}

/// True when a browser process is reading its own credential store.
///
/// The check requires BOTH (a) the comm matches a known browser prefix
/// AND (b) the path looks like browser-managed data. A non-browser
/// process reading the same path is NOT covered by this allowlist —
/// it still flows into `pending_reads` and fires Critical on outbound,
/// which is the entire point of adding browser data to `SENSITIVE_PATHS`.
fn is_browser_self_access(comm: &str, filename: &str) -> bool {
    let f_lower = filename.to_lowercase();
    let path_is_browser_data = BROWSER_DATA_PATH_HINTS.iter().any(|h| f_lower.contains(h));
    if !path_is_browser_data {
        return false;
    }
    BROWSER_PROCESS_PREFIXES
        .iter()
        .any(|prefix| comm.starts_with(prefix))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn read_event(pid: u32, filename: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".into(),
            source: "ebpf".into(),
            kind: "file.read_access".into(),
            severity: Severity::Medium,
            summary: format!("read {filename}"),
            details: serde_json::json!({
                "pid": pid, "uid": 0, "comm": "cat",
                "filename": filename,
            }),
            tags: vec!["ebpf".into()],
            entities: vec![],
        }
    }

    fn connect_event(pid: u32, dst_ip: &str, dst_port: u16, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".into(),
            source: "ebpf".into(),
            kind: "network.outbound_connect".into(),
            severity: Severity::Info,
            summary: format!("connect {dst_ip}:{dst_port}"),
            details: serde_json::json!({
                "pid": pid, "uid": 0, "comm": "cat",
                "dst_ip": dst_ip, "dst_port": dst_port,
            }),
            tags: vec!["ebpf".into()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    #[test]
    fn skips_innerwarden_process() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        // InnerWarden uid=998 reading sensitive files is legitimate
        let iw_read = Event {
            ts: now,
            host: "test".into(),
            source: "ebpf".into(),
            kind: "file.read_access".into(),
            severity: Severity::Medium,
            summary: "read /etc/ssh/sshd_config".into(),
            details: serde_json::json!({
                "pid": 9999, "uid": 998, "comm": "tokio-rt-worker",
                "filename": "/etc/ssh/sshd_config",
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&iw_read).is_none());

        // Even if followed by outbound connect, should not trigger
        let iw_connect = Event {
            ts: now + Duration::seconds(2),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "network.outbound_connect".into(),
            severity: Severity::Info,
            summary: "connect 5.6.7.8:443".into(),
            details: serde_json::json!({
                "pid": 9999, "uid": 998, "comm": "tokio-rt-worker",
                "dst_ip": "5.6.7.8", "dst_port": 443,
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&iw_connect).is_none());
    }

    /// The cloud guest-agent gate is DOWNGRADE-ONLY: a real credential exfil (a
    /// non-guest-agent process reading a secret then connecting out) still fires.
    /// Uses a pid above the kernel pid_max ceiling so `/proc` has no lineage and
    /// `is_guest_agent` is reliably inert on cloud CI runners (GitHub runners are
    /// Azure); the guest-agent suppression itself is unit-tested in
    /// `crate::cloud_platform`.
    #[test]
    fn guest_agent_gate_does_not_suppress_real_exfil() {
        const DEAD_PID: u32 = 4_000_000_001;
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        assert!(det
            .process(&read_event(DEAD_PID, "/etc/shadow", now))
            .is_none());
        let inc = det.process(&connect_event(
            DEAD_PID,
            "185.220.101.44",
            4444,
            now + Duration::seconds(1),
        ));
        assert!(
            inc.is_some(),
            "a real (non-guest-agent) shadow-read-then-connect must still fire"
        );
    }

    fn read_event_with_comm(pid: u32, filename: &str, comm: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test".into(),
            source: "ebpf".into(),
            kind: "file.read_access".into(),
            severity: Severity::Medium,
            summary: format!("read {filename}"),
            details: serde_json::json!({
                "pid": pid, "uid": 1001, "comm": comm,
                "filename": filename,
            }),
            tags: vec!["ebpf".into()],
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
            host: "test".into(),
            source: "ebpf".into(),
            kind: "network.outbound_connect".into(),
            severity: Severity::Info,
            summary: format!("connect {dst_ip}:{dst_port}"),
            details: serde_json::json!({
                "pid": pid, "uid": 1001, "comm": comm,
                "dst_ip": dst_ip, "dst_port": dst_port,
            }),
            tags: vec!["ebpf".into()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    // Same as the *_with_comm helpers but stamped with a (non-forgeable)
    // exe_path — for the comm-rename evasion tests.
    fn read_event_exe(pid: u32, filename: &str, comm: &str, exe: &str, ts: DateTime<Utc>) -> Event {
        let mut ev = read_event_with_comm(pid, filename, comm, ts);
        ev.details["exe_path"] = serde_json::Value::String(exe.to_string());
        ev
    }
    fn connect_event_exe(
        pid: u32,
        dst_ip: &str,
        dst_port: u16,
        comm: &str,
        exe: &str,
        ts: DateTime<Utc>,
    ) -> Event {
        let mut ev = connect_event_with_comm(pid, dst_ip, dst_port, comm, ts);
        ev.details["exe_path"] = serde_json::Value::String(exe.to_string());
        ev
    }

    // A connect event stamped with a parent pid — for the split-pid tests.
    fn connect_event_ppid(
        pid: u32,
        ppid: u32,
        dst_ip: &str,
        dst_port: u16,
        comm: &str,
        ts: DateTime<Utc>,
    ) -> Event {
        let mut ev = connect_event_with_comm(pid, dst_ip, dst_port, comm, ts);
        ev.details["ppid"] = serde_json::Value::from(ppid);
        ev
    }

    #[test]
    fn ssh_reading_passwd_then_connecting_outbound_does_not_alert() {
        // 2026-04-30: Operator hit a Critical FP on `git fetch`
        // because the github.com SSH endpoint resolves to Azure
        // 20.x.156.215. The ssh client always reads /etc/passwd
        // for NSS uid->name lookup and then opens the outbound
        // connection — exact NSS-init signature. Adding `ssh` to
        // NSS_INIT_CLI_TOOLS suppresses that exact shape.
        //
        // Anchor: this test reproduces the prod incident as
        // captured by the eBPF evidence (comm=ssh, file=/etc/passwd,
        // dst_port=22, uid=1001) and asserts NO incident is
        // emitted. Pre-fix this returned Some(Critical Incident).
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(7000, "/etc/passwd", "ssh", now));
        let inc = det.process(&connect_event_with_comm(
            7000,
            "20.26.156.215",
            22,
            "ssh",
            now + Duration::milliseconds(3),
        ));
        assert!(
            inc.is_none(),
            "ssh + /etc/passwd + outbound :22 must be suppressed (NSS-init pattern)"
        );
    }

    #[test]
    fn ssh_reading_shadow_still_alerts_critical() {
        // Counterpart to the test above — the suppression is
        // INTENTIONALLY narrow. ssh reading /etc/shadow (or any
        // file other than the literal /etc/passwd) is real exfil
        // territory and MUST still fire Critical. If a future
        // refactor accidentally widens the suppression to "any
        // sensitive file" this test catches it.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(7001, "/etc/shadow", "ssh", now));
        let inc = det.process(&connect_event_with_comm(
            7001,
            "20.26.156.215",
            22,
            "ssh",
            now + Duration::milliseconds(3),
        ));
        let inc = inc.expect("ssh reading /etc/shadow MUST still fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("/etc/shadow"));
    }

    #[test]
    fn ssh_reading_ssh_keys_still_alerts_critical() {
        // Same shape as the shadow test: ssh reading
        // ~/.ssh/id_ed25519 then connecting outbound is the
        // canonical SSH-key exfil pattern. The NSS-init exception
        // does NOT cover it because the filename is not exactly
        // /etc/passwd.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            7002,
            "/home/ubuntu/.ssh/id_ed25519",
            "ssh",
            now,
        ));
        let inc = det.process(&connect_event_with_comm(
            7002,
            "8.8.8.8",
            22,
            "ssh",
            now + Duration::milliseconds(3),
        ));
        let inc = inc.expect("ssh reading id_ed25519 MUST still fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("id_ed25519"));
    }

    #[test]
    fn python_agent_reading_aws_credentials_then_connecting_fires_critical() {
        // 2026-07-02 agent-runtime blind-spot regression anchor.
        //
        // `python3` (and `node`, `openclaw`, ...) used to be in the BLANKET
        // PASSWD_READERS exemption, which `return None`-d for EVERY file
        // before Phase-1 read tracking. That silently exempted every AI
        // coding agent (which runs as exactly those comms) from this
        // detector: a compromised python agent reading ~/.aws/credentials
        // and connecting out was dropped before it was ever tracked — the
        // exact threat the product exists to catch. Proven live on test001
        // (0.15.32): comm=python3 read=~/.aws/credentials + outbound :443
        // both captured, NO incident. The fix moves those runtimes to the
        // NARROW /etc/passwd-only NSS-init gate. This test locks the catch.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8100,
            "/home/test001/.aws/credentials",
            "python3",
            now,
        ));
        let inc = det.process(&connect_event_with_comm(
            8100,
            "8.8.8.8",
            443,
            "python3",
            now + Duration::milliseconds(3),
        ));
        let inc = inc.expect("python3 reading .aws/credentials MUST fire (agent blind spot)");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("credentials"));
    }

    #[test]
    fn openclaw_agent_reading_dotenv_then_connecting_fires_critical() {
        // Same class as the python test, for the openclaw runtime and a
        // `.env` secret. Confirms the fix is not python-specific.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8101,
            "/home/test001/project/.env",
            "openclaw",
            now,
        ));
        let inc = det.process(&connect_event_with_comm(
            8101,
            "5.6.7.8",
            443,
            "openclaw",
            now + Duration::milliseconds(3),
        ));
        let inc = inc.expect("openclaw reading .env MUST fire (agent blind spot)");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains(".env"));
    }

    #[test]
    fn python_agent_reading_etc_passwd_then_connecting_stays_suppressed() {
        // Counterpart: the runtimes were moved to the NARROW NSS-init gate,
        // NOT removed entirely. Their one benign read-then-connect shape is
        // the getpwuid_r startup read of the literal /etc/passwd before they
        // dial their LLM/API. That must STILL be suppressed, otherwise every
        // python/node process start becomes a Critical false positive.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(8102, "/etc/passwd", "python3", now));
        let inc = det.process(&connect_event_with_comm(
            8102,
            "8.8.8.8",
            443,
            "python3",
            now + Duration::milliseconds(3),
        ));
        assert!(
            inc.is_none(),
            "python3 + /etc/passwd + outbound must stay suppressed (NSS-init pattern)"
        );
    }

    #[test]
    fn comm_spoofed_daemon_from_untrusted_path_still_fires() {
        // 2026-07-02 comm-rename evasion anchor. `cp evil /tmp/sshd` gives comm=sshd
        // (in the PASSWD_READERS daemon blanket), but the NON-forgeable exe_path is
        // /tmp/sshd (untrusted). It must NOT inherit sshd's exemption: reading
        // ~/.aws/credentials then connecting out fires Critical.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_exe(
            8200,
            "/home/u/.aws/credentials",
            "sshd",
            "/tmp/sshd",
            now,
        ));
        let inc = det.process(&connect_event_exe(
            8200,
            "8.8.8.8",
            443,
            "sshd",
            "/tmp/sshd",
            now + Duration::milliseconds(3),
        ));
        let inc = inc.expect("comm=sshd from /tmp (untrusted exe) reading creds MUST fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("credentials"));
    }

    #[test]
    fn real_daemon_from_trusted_path_stays_exempt() {
        // Counterpart: a REAL sshd (exe under /usr/sbin) keeps the blanket
        // exemption — reading a cred file then connecting out must NOT fire (it
        // does NSS lookups + serves connections; this is its job, indistinguishable
        // from exfil at this layer).
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_exe(
            8201,
            "/home/u/.aws/credentials",
            "sshd",
            "/usr/sbin/sshd",
            now,
        ));
        let inc = det.process(&connect_event_exe(
            8201,
            "8.8.8.8",
            443,
            "sshd",
            "/usr/sbin/sshd",
            now + Duration::milliseconds(3),
        ));
        assert!(
            inc.is_none(),
            "trusted /usr/sbin/sshd must keep its exemption"
        );
    }

    #[test]
    fn daemon_comm_without_exe_path_falls_back_to_exemption() {
        // A daemon whose execve predates the sensor has no cached exe_path. We must
        // fall back to the comm exemption (no exe evidence to prove spoofing) rather
        // than FP on every long-running daemon. No incident.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8202,
            "/home/u/.aws/credentials",
            "sshd",
            now,
        ));
        let inc = det.process(&connect_event_with_comm(
            8202,
            "8.8.8.8",
            443,
            "sshd",
            now + Duration::milliseconds(3),
        ));
        assert!(
            inc.is_none(),
            "comm=sshd with no exe_path must fall back to the exemption (no FP)"
        );
    }

    #[test]
    fn split_pid_parent_read_child_connect_fires() {
        // 2026-07-02 split-pid evasion anchor. The PARENT (pid 9000) reads
        // ~/.aws/credentials; a forked CHILD (pid 9001, ppid 9000) does the
        // outbound connect. The same-PID correlation would miss it; the parent-pid
        // fallback catches it and marks it split_pid.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            9000,
            "/home/u/.aws/credentials",
            "bash",
            now,
        ));
        let inc = det.process(&connect_event_ppid(
            9001,
            9000,
            "8.8.8.8",
            443,
            "curl",
            now + Duration::milliseconds(5),
        ));
        let inc = inc.expect("parent-read + child-connect MUST fire (split-pid)");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.summary.contains("child of the reader pid=9000"));
        assert_eq!(inc.evidence[0]["detection"], "parent_read_child_connect");
        assert_eq!(inc.evidence[0]["split_pid"], true);
    }

    #[test]
    fn unrelated_child_connect_does_not_borrow_a_stranger_read() {
        // The ppid fallback must only match the connecting process's OWN parent. A
        // child whose parent never read a secret does not fire just because some
        // unrelated pid has a pending read.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            9100,
            "/home/u/.aws/credentials",
            "bash",
            now,
        ));
        // Child 9201's parent is 9200 (NOT the reader 9100) — no correlation.
        let inc = det.process(&connect_event_ppid(
            9201,
            9200,
            "8.8.8.8",
            443,
            "curl",
            now + Duration::milliseconds(5),
        ));
        assert!(
            inc.is_none(),
            "a child whose parent did not read must not borrow an unrelated pending read"
        );
    }

    #[test]
    fn detects_read_then_connect() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        // Step 1: read /etc/shadow
        assert!(det.process(&read_event(1234, "/etc/shadow", now)).is_none());

        // Step 2: connect to external IP
        let inc = det
            .process(&connect_event(
                1234,
                "5.6.7.8",
                443,
                now + Duration::seconds(5),
            ))
            .unwrap();
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("/etc/shadow"));
        assert!(inc.title.contains("5.6.7.8"));
    }

    #[test]
    fn requires_same_pid() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        // PID 1234 reads file
        det.process(&read_event(1234, "/etc/shadow", now));

        // Different PID 5678 connects → should NOT trigger
        let inc = det.process(&connect_event(
            5678,
            "5.6.7.8",
            443,
            now + Duration::seconds(5),
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_non_sensitive_files() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        // Read a normal file
        det.process(&read_event(1234, "/var/log/syslog", now));

        // Connect → should NOT trigger (file was not sensitive)
        let inc = det.process(&connect_event(
            1234,
            "5.6.7.8",
            443,
            now + Duration::seconds(5),
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn ignores_internal_destinations() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        det.process(&read_event(1234, "/etc/shadow", now));

        // Connect to internal IP → should NOT trigger
        let inc = det.process(&connect_event(
            1234,
            "192.168.1.1",
            443,
            now + Duration::seconds(5),
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn expires_after_window() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        det.process(&read_event(1234, "/etc/shadow", now));

        // Connect 61 seconds later → window expired
        let inc = det.process(&connect_event(
            1234,
            "5.6.7.8",
            443,
            now + Duration::seconds(61),
        ));
        assert!(inc.is_none());
    }

    #[test]
    fn detects_ssh_key_exfil() {
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();

        det.process(&read_event(1234, "/home/admin/.ssh/id_rsa", now));

        let inc = det
            .process(&connect_event(
                1234,
                "8.8.8.8",
                80,
                now + Duration::seconds(2),
            ))
            .unwrap();
        assert!(inc.title.contains("id_rsa"));
    }

    #[test]
    fn sensitive_path_detection() {
        assert!(is_sensitive_path("/etc/shadow"));
        assert!(is_sensitive_path("/etc/passwd"));
        assert!(is_sensitive_path("/home/user/.ssh/id_rsa"));
        assert!(is_sensitive_path("/home/user/.ssh/authorized_keys"));
        assert!(is_sensitive_path("/app/.env"));
        assert!(is_sensitive_path("/home/user/.kube/config"));
        assert!(!is_sensitive_path("/var/log/syslog"));
        assert!(!is_sensitive_path("/usr/bin/ls"));
    }

    #[test]
    fn source_and_node_modules_files_are_not_sensitive() {
        // Regression: an AI agent loading its own package code was flagged as
        // credential access because the path contained the generic words
        // "secret"/"token" (only the GENERIC tokens are relaxed for code).
        assert!(!is_sensitive_path(
            "/home/lab/.openclaw/npm/projects/openclaw-slack-x/node_modules/@openclaw/slack/dist/secret-contract-api.js"
        ));
        assert!(!is_sensitive_path(
            "/home/lab/.openclaw/npm/projects/x/node_modules/typebox/build/type/script/token/const.mjs"
        ));
        assert!(!is_sensitive_path("/srv/app/src/secret-utils.ts"));
        // Genuine credentials are still sensitive (incl. the gcloud .json).
        assert!(is_sensitive_path(
            "/home/u/.config/gcloud/application_default_credentials.json"
        ));
        assert!(is_sensitive_path("/home/u/secrets/api.key.env"));
    }

    #[test]
    fn specific_credentials_cannot_be_evaded_by_code_naming() {
        // Anti-evasion (advanced-attacker thinking): a SPECIFIC credential path
        // is detected regardless of extension or location — an attacker cannot
        // hide a real key by naming it `.js` or stashing it under node_modules.
        assert!(is_sensitive_path("/srv/app/node_modules/evil/id_rsa"));
        assert!(is_sensitive_path("/tmp/loot/id_rsa.js"));
        assert!(is_sensitive_path(
            "/home/u/proj/node_modules/x/.aws/credentials"
        ));
        assert!(is_sensitive_path("/etc/shadow"));
    }

    // ---------------------------------------------------------------------
    // 2026-05-25 anchors — Cyber Defense Benchmark blind-spot coverage
    // ---------------------------------------------------------------------
    //
    // The Simbian AI Cyber Defense Benchmark (arXiv:2604.19533) showed
    // frontier LLMs near-universally miss Credential Access and Collection
    // tactics when hunting. We don't rely on LLM hunting — these tests
    // pin that the deterministic eBPF detector catches the same patterns
    // the LLMs miss: Chrome / Firefox credential theft, Docker auth token
    // exfil, gcloud OAuth refresh-token exfil, rclone backup-tool false
    // positive avoidance.

    #[test]
    fn cloud_creds_docker_config_then_outbound_fires_critical() {
        // T1552.001 (Credentials in Files) — Docker Hub auth tokens.
        // `docker login` writes username:password (base64) into
        // ~/.docker/config.json. Attacker reads it, uploads it. The
        // detector must catch this exactly like SSH key exfil.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8100,
            "/home/dev/.docker/config.json",
            "cat",
            now,
        ));
        let inc = det
            .process(&connect_event_with_comm(
                8100,
                "5.6.7.8",
                443,
                "cat",
                now + Duration::seconds(2),
            ))
            .expect("docker config.json read + outbound must fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("config.json"));
    }

    #[test]
    fn cloud_creds_gcloud_oauth_then_outbound_fires_critical() {
        // T1552.001 — gcloud OAuth refresh tokens in
        // ~/.config/gcloud/credentials.db. Stealing this gives the
        // attacker every GCP API the user can reach for the lifetime
        // of the refresh token (often weeks).
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8101,
            "/home/dev/.config/gcloud/credentials.db",
            "exfil",
            now,
        ));
        let inc = det
            .process(&connect_event_with_comm(
                8101,
                "5.6.7.8",
                443,
                "exfil",
                now + Duration::seconds(1),
            ))
            .expect("gcloud credentials.db read + outbound must fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("credentials.db"));
    }

    #[test]
    fn cloud_creds_rclone_conf_then_outbound_fires_critical() {
        // T1552.001 — rclone.conf often holds SSH keys, S3 secrets,
        // and cloud-storage tokens in a single file. A non-rclone
        // process reading it then connecting out is exfil. (Real
        // rclone is allowlisted in BACKUP_TOOLS — see the
        // `backup_tool_rclone_is_allowlisted` test below.)
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8102,
            "/home/dev/.config/rclone/rclone.conf",
            "curl",
            now,
        ));
        let inc = det
            .process(&connect_event_with_comm(
                8102,
                "5.6.7.8",
                443,
                "curl",
                now + Duration::seconds(1),
            ))
            .expect("rclone.conf read by non-rclone process + outbound must fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("rclone.conf"));
    }

    #[test]
    fn browser_data_read_by_attacker_then_outbound_fires_critical() {
        // T1555.003 (Credentials from Web Browsers) — Chrome's
        // "Login Data" SQLite is the canonical browser-credential
        // theft target. A non-browser process reading it then
        // connecting out is exfil.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8200,
            "/home/user/.config/google-chrome/Default/Login Data",
            "stealer",
            now,
        ));
        let inc = det
            .process(&connect_event_with_comm(
                8200,
                "5.6.7.8",
                443,
                "stealer",
                now + Duration::seconds(1),
            ))
            .expect("non-browser reading Chrome Login Data + outbound must fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.to_lowercase().contains("login data"));
    }

    #[test]
    fn browser_data_firefox_logins_json_then_outbound_fires_critical() {
        // Firefox saved-logins exfil counterpart. logins.json is
        // encrypted with the key in key4.db — stealing both is
        // sufficient for offline decryption.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8201,
            "/home/user/.mozilla/firefox/abc123.default/logins.json",
            "stealer",
            now,
        ));
        let inc = det
            .process(&connect_event_with_comm(
                8201,
                "5.6.7.8",
                443,
                "stealer",
                now + Duration::seconds(1),
            ))
            .expect("non-Firefox reading logins.json + outbound must fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("logins.json"));
    }

    #[test]
    fn browser_self_access_chrome_reading_own_login_data_is_silent() {
        // Negative control — Chrome auto-syncs Login Data over HTTPS
        // constantly. If this detector fired every time Chrome wrote
        // a saved password and then synced it, the operator would get
        // a Critical alert per browser session. Anchor: the
        // is_browser_self_access skip MUST hold.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8300,
            "/home/user/.config/google-chrome/Default/Login Data",
            "chrome",
            now,
        ));
        let inc = det.process(&connect_event_with_comm(
            8300,
            "142.250.190.78", // www.google.com
            443,
            "chrome",
            now + Duration::seconds(1),
        ));
        assert!(
            inc.is_none(),
            "chrome reading its own Login Data + outbound must NOT fire"
        );
    }

    #[test]
    fn browser_self_access_firefox_reading_own_key4_is_silent() {
        // Firefox writes key4.db on every saved-password add and reads
        // it on every form autofill. Same FP shape as Chrome.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8301,
            "/home/user/.mozilla/firefox/abc.default/key4.db",
            "firefox",
            now,
        ));
        let inc = det.process(&connect_event_with_comm(
            8301,
            "34.107.221.82", // mozilla.org telemetry
            443,
            "firefox",
            now + Duration::seconds(1),
        ));
        assert!(
            inc.is_none(),
            "firefox reading its own key4.db + outbound must NOT fire"
        );
    }

    #[test]
    fn browser_self_access_truncated_comm_chrome_is_silent() {
        // Linux TASK_COMM_LEN truncates comm to 15 chars, so
        // `google-chrome` becomes `google-chrom` in eBPF events.
        // BROWSER_PROCESS_PREFIXES includes both — verify the
        // truncated form is covered.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8302,
            "/home/user/.config/google-chrome/Profile 1/Login Data",
            "google-chrom",
            now,
        ));
        let inc = det.process(&connect_event_with_comm(
            8302,
            "142.250.190.78",
            443,
            "google-chrom",
            now + Duration::seconds(1),
        ));
        assert!(
            inc.is_none(),
            "google-chrom (truncated comm) reading own Login Data + outbound must NOT fire"
        );
    }

    #[test]
    fn backup_tool_rclone_is_allowlisted() {
        // rclone legitimately reads everything under $HOME (including
        // SSH keys, cloud creds, browser data) and uploads to the
        // configured backup target. Kernel events cannot distinguish
        // backup from exfil — operator's intent is in the tool's
        // config file. Allowlist is the FP-safe choice.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8400,
            "/home/user/.ssh/id_ed25519",
            "rclone",
            now,
        ));
        let inc = det.process(&connect_event_with_comm(
            8400,
            "5.6.7.8",
            443,
            "rclone",
            now + Duration::seconds(1),
        ));
        assert!(
            inc.is_none(),
            "rclone reading SSH key + outbound must be allowlisted as backup activity"
        );
    }

    #[test]
    fn backup_tool_restic_is_allowlisted() {
        // Anti-regression: BACKUP_TOOLS contains restic too — same
        // logic. Anchor pins the entry so a future cleanup that
        // narrows the list cannot silently drop restic.
        let mut det = DataExfilEbpfDetector::new("test", 60, 300);
        let now = Utc::now();
        det.process(&read_event_with_comm(
            8401,
            "/home/user/.docker/config.json",
            "restic",
            now,
        ));
        let inc = det.process(&connect_event_with_comm(
            8401,
            "5.6.7.8",
            443,
            "restic",
            now + Duration::seconds(1),
        ));
        assert!(
            inc.is_none(),
            "restic reading docker config + outbound must be allowlisted"
        );
    }

    #[test]
    fn is_browser_self_access_path_alone_is_insufficient() {
        // A non-browser comm reading a browser path is NOT
        // self-access — it's the attack signature. Tests the
        // both-must-match logic in `is_browser_self_access`.
        assert!(!is_browser_self_access(
            "stealer",
            "/home/user/.config/google-chrome/Default/Login Data"
        ));
        // Browser comm reading a non-browser path is also not
        // browser self-access (correctly; would fall through to
        // the normal sensitive-path check).
        assert!(!is_browser_self_access("chrome", "/etc/shadow"));
    }

    #[test]
    fn is_browser_self_access_both_match_returns_true() {
        assert!(is_browser_self_access(
            "chrome",
            "/home/user/.config/google-chrome/Default/Login Data"
        ));
        assert!(is_browser_self_access(
            "firefox",
            "/home/user/.mozilla/firefox/abc.default/logins.json"
        ));
        assert!(is_browser_self_access(
            "google-chrom",
            "/home/user/.config/google-chrome/Profile 1/key4.db"
        ));
    }
}
