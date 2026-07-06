//! Centralized allowlists for false positive suppression.
//!
//! Built from production-hardened runtime security allowlists.
//! Instead of each detector maintaining its own ad-hoc list, all detectors
//! reference these shared lists.
//!
//! Categories:
//!   - INNERWARDEN_SELF: our own processes (uid 998, tokio-rt-worker, etc.)
//!   - SYSTEM_DAEMONS: root-level system services
//!   - PACKAGE_MANAGERS: apt, dpkg, snap, etc.
//!   - LOGIN_BINARIES: sshd, login, su, sudo, etc.
//!   - DISCOVERY_ALLOWED: processes that legitimately run recon commands
//!   - SENSITIVE_FILE_READERS: processes allowed to read /etc/shadow, etc.
//!   - TRUNCATE_ALLOWED: processes that legitimately truncate files

/// InnerWarden's own service user ID.
pub const INNERWARDEN_UID: u64 = 998;

/// Returns true if the event is from InnerWarden's own processes.
/// Checks uid, comm prefix, and tokio runtime threads.
pub fn is_innerwarden_process(uid: u64, comm: &str) -> bool {
    // Strip kernel task parentheses: (innerwarden) -> innerwarden
    let comm = comm.trim_matches(|c: char| c == '(' || c == ')');
    uid == INNERWARDEN_UID
        || comm.starts_with("innerwarden")
        || comm == "tokio-rt-worker"
        || comm.contains("warden")
}

// ---------------------------------------------------------------------------
// System daemons (uid=0, legitimate system operations)
// ---------------------------------------------------------------------------

/// Root daemons that legitimately perform file operations, network connections,
/// and process management. Filtering these prevents the most common FPs.
pub const SYSTEM_DAEMONS: &[&str] = &[
    // Init and service management
    "systemd",
    "systemd-logind",
    "systemd-journal",
    "systemd-resolve",
    "systemd-timesyn",
    "systemd-network",
    "systemd-udevd",
    "systemd-tmpfile",
    "systemd-machine",
    "systemd-sysuser",
    // SSH
    "sshd",
    "sshd-session",
    "ssh-agent",
    "ssh-keygen",
    // Cron
    "cron",
    "crond",
    "atd",
    "anacron",
    // Auth and policy
    "polkitd",
    "pkexec",
    "dbus-daemon",
    "dbus-daemon-lau",
    // Log management
    "logrotate",
    "rsyslogd",
    "syslog-ng",
    "journalctl",
    // Network
    "irqbalance",
    "ufw",
    "iptables",
    "nftables",
    "fail2ban-serve",
    "fail2ban-client",
    "dhclient",
    "networkd-dispat",
    "NetworkManager",
    // System maintenance
    "unattended-upgr",
    "update-notifier",
    "apt-check",
    "landscape-sysi",
    "50-landscape-sy",
    "update-motd",
    "fwupdmgr",
    "snapd",
    "chronyd",
    "ntpd",
    "multipathd",
    "accounts-daemon",
    "udisksd",
    "thermald",
];

// ---------------------------------------------------------------------------
// Package managers (may read sensitive files, run discovery commands)
// ---------------------------------------------------------------------------

/// Package management binaries — these legitimately read config files,
/// run post-install scripts, and execute system commands.
pub const PACKAGE_MANAGERS: &[&str] = &[
    // Debian/Ubuntu
    "dpkg",
    "dpkg-preconfigu",
    "dpkg-reconfigur",
    "dpkg-divert",
    "apt",
    "apt-get",
    "apt-cache",
    "apt-key",
    "apt-listchanges",
    "apt-auto-remova",
    "apt-add-reposit",
    "apt.systemd.dai",
    "aptitude",
    "unattended-upgr",
    "needrestart",
    // RPM
    "rpm",
    "yum",
    "dnf",
    "dnf-automatic",
    // Snap
    "snap",
    "snapd",
    // Python/Node/Ruby
    "pip",
    "pip3",
    "npm",
    "gem",
    "conda",
    "uv",
    // Rust/Go
    "cargo",
    "rustup",
    "go",
];

// ---------------------------------------------------------------------------
// Login and auth binaries (legitimately change uid, read shadow)
// ---------------------------------------------------------------------------

/// Processes that legitimately perform privilege escalation or read auth files.
pub const LOGIN_BINARIES: &[&str] = &[
    "login",
    "su",
    "sudo",
    "suexec",
    "sshd",
    "sshd-session",
    "cron",
    "crond",
    "atd",
    "polkitd",
    "pkexec",
    "newgrp",
    "sg",
    "dbus-daemon",
    "gdm",
    "lightdm",
    "sddm",
    "systemd",
    "systemd-logind",
    "run-parts",
    "runuser",
];

/// Password/shadow management binaries.
pub const PASSWD_BINARIES: &[&str] = &[
    "passwd",
    "chsh",
    "chfn",
    "chage",
    "gpasswd",
    "usermod",
    "useradd",
    "userdel",
    "groupadd",
    "groupdel",
    "groupmod",
    "adduser",
    "addgroup",
    "deluser",
    "delgroup",
    "shadowconfig",
    "grpck",
    "pwck",
    "vipw",
    "vigr",
    "newusers",
    "chpasswd",
    "unix_chkpwd",
];

// ---------------------------------------------------------------------------
// Discovery commands — processes that legitimately run recon-like commands
// ---------------------------------------------------------------------------

/// Processes that legitimately execute discovery commands (ps, id, uname, etc.)
/// and should not trigger discovery burst alerts.
pub const DISCOVERY_ALLOWED: &[&str] = &[
    // Security / monitoring tools
    "innerwarden",
    "osqueryd",
    "ossec-syscheckd",
    "telegraf",
    "prometheus",
    "node_exporter",
    "zabbix",
    "nagios",
    "collectd",
    "datadog",
    "newrelic",
    "aide",
    "rkhunter",
    "logcheck",
    // Config management
    "ansible",
    "puppet",
    "chef",
    "chef-client",
    "salt",
    "salt-call",
    "salt-minion",
    // CI/CD and dev tools (including compiler sub-processes)
    "cargo",
    "rustc",
    "git",
    "make",
    "cmake",
    "gcc",
    "g++",
    "cc",
    "cc1",
    "ld",
    "collect2",
    "lto-wrapper",
    "go",
    "node",
    "python",
    "python3",
    // grep variants (build scripts, overlayroot checks, cron health)
    "egrep",
    "fgrep",
    // System tools that run discovery commands
    "journalctl",
    "systemctl",
    "bpftool",
    "bpf_inspect",
    "landscape-sysi",
    "update-motd",
    // Cloud-init (Oracle Cloud, AWS, GCP, Azure — runs discovery on boot/reboot)
    "cloud-init",
    "cloud-init-gene",
    "ds-identify",
    // Ubuntu MOTD scripts (run uname, id, etc. on every SSH login)
    "00-header",
    "10-help-text",
    "50-motd-news",
    "60-unminimize",
    "91-release-upgr",
    "release-upgrade",
    "run-parts",
    // Package managers (post-install scripts run discovery)
    "apt-check",
    "unattended-upgr",
    "dpkg",
    "dpkg-preconfigu",
    "needrestart",
    "snap",
    "snapd",
];

// ---------------------------------------------------------------------------
// Sensitive file readers — processes allowed to read /etc/shadow, etc.
// ---------------------------------------------------------------------------

/// Processes that legitimately read sensitive files (/etc/shadow, /etc/sudoers,
/// /etc/pam.conf, SSH keys, etc.) and should not trigger Sigma rules or alerts.
pub const SENSITIVE_FILE_READERS: &[&str] = &[
    // Auth
    "sshd",
    "sshd-session",
    "login",
    "su",
    "sudo",
    "polkitd",
    "systemd",
    "systemd-logind",
    "cron",
    "crond",
    "atd",
    // Password management
    "passwd",
    "chage",
    "chsh",
    "chfn",
    "adduser",
    "useradd",
    "usermod",
    "newusers",
    "chpasswd",
    "unix_chkpwd",
    // Security tools
    "innerwarden",
    "osqueryd",
    "ossec-syscheckd",
    "rkhunter",
    "aide",
    "logcheck",
    // System tools
    "iptables",
    "lsb_release",
    "check-new-relea",
    "dumpe2fs",
    "accounts-daemon",
    "pam-auth-update",
    "pam-config",
    "cockpit-session",
    // Package managers
    "dpkg",
    "apt",
    "apt-get",
    "snap",
    "needrestart",
];

// ---------------------------------------------------------------------------
// Truncate/timestomp allowlist — processes that legitimately truncate files
// ---------------------------------------------------------------------------

/// System processes (uid=0) that legitimately call do_truncate or vfs_utimes.
/// These are filtered from eBPF truncate/timestomp events.
pub const TRUNCATE_ALLOWED: &[&str] = &[
    "systemd-journal",
    "logrotate",
    "rsyslogd",
    "syslog-ng",
    "systemd",
    "systemd-tmpfile",
    "sshd",
    "sshd-session",
    "irqbalance",
    "ufw",
    "fail2ban-serve",
    "fail2ban-client",
    "50-landscape-sy",
    "landscape-sysi",
];

// ---------------------------------------------------------------------------
// Privilege escalation allowlist
// ---------------------------------------------------------------------------

/// Processes that legitimately trigger commit_creds (uid changes).
/// Combined from common login/password-management binaries plus InnerWarden additions.
pub const PRIVESC_ALLOWED: &[&str] = &[
    // Standard login/auth
    "sudo",
    "su",
    "login",
    "sshd",
    "sshd-session",
    "cron",
    "crond",
    "atd",
    "polkitd",
    "pkexec",
    "systemd",
    "systemd-logind",
    "dbus-daemon",
    "dbus-daemon-lau",
    "gdm",
    "lightdm",
    "sddm",
    "newgrp",
    // Password management
    "passwd",
    "chsh",
    "chfn",
    "chage",
    "gpasswd",
    "usermod",
    "useradd",
    "groupadd",
    // Package managers
    "install",
    "dpkg",
    "apt",
    "apt-get",
    "apt-check",
    "snap",
    "snapd",
    "unattended-upg",
    "update-notifier",
    // System tools with SUID
    "at",
    "find",
    "mandb",
    "man",
    "fusermount",
    "mount",
    "umount",
    "ping",
    "traceroute",
    "ssh-agent",
    "gpg-agent",
    "gpg",
    "ntpd",
    "chronyd",
    "logrotate",
    "run-parts",
    "anacron",
    "fwupdmgr",
    // InnerWarden
    "innerwarden",
    "innerwarden-ag",
    "innerwarden-se",
    "innerwarden-ct",
];

// ---------------------------------------------------------------------------
// C2 callback allowlist — processes with legitimate outbound connections
// ---------------------------------------------------------------------------

/// Processes that make regular outbound HTTP/HTTPS connections and should
/// not be flagged as C2 beaconing.
pub const C2_OUTBOUND_ALLOWED: &[&str] = &[
    // InnerWarden (GeoIP, AbuseIPDB, CrowdSec, Cloudflare lookups)
    "innerwarden",
    "tokio-rt-worker",
    // System updates
    "apt",
    "apt-get",
    "snap",
    "snapd",
    "unattended-upgr",
    "dpkg",
    // Cloud agents
    "oracle-cloud-ag",
    "google_guest_ag",
    "waagent",
    "amazon-ssm-agen",
    // Monitoring
    "telegraf",
    "prometheus",
    "datadog-agent",
    "newrelic-infra",
    "zabbix_agentd",
    "node_exporter",
    "gomon",
    "updater",
    // Security tools
    "osqueryd",
    "crowdsec",
    "fail2ban-serve",
    // Web servers (make outbound requests for plugins, APIs)
    "nginx",
    "apache2",
    "httpd",
    "php-fpm",
    "php",
    "ruby",
    "puma",
    "unicorn",
    "gunicorn",
    "uwsgi",
    // Databases (replication, cluster comms)
    "mysqld",
    "postgres",
    "mongod",
    "redis-server",
    // Node.js / runtime workers / AI agents
    "libuv-worker",
    "node",
    "openclaw",
    "DelayedTaskSche",
    // Container runtime
    "dockerd",
    "containerd",
    "containerd-shim",
    "runc",
];

// ---------------------------------------------------------------------------
// Helper: check if a process is in a given allowlist
// ---------------------------------------------------------------------------

/// Check if comm matches any entry in the allowlist using starts_with.
/// Handles kernel comm truncation (16 char limit).
pub fn comm_in_allowlist(comm: &str, allowlist: &[&str]) -> bool {
    let comm_base = comm.split('/').next_back().unwrap_or(comm);
    // Strip kernel task parentheses: (install) -> install
    let comm_base = comm_base.trim_matches(|c: char| c == '(' || c == ')');
    allowlist.iter().any(|p| comm_base.starts_with(p))
}

// ---------------------------------------------------------------------------
// Dynamic allowlist — loaded from /etc/innerwarden/allowlist.toml at runtime.
// No rebuild needed. Sensor re-reads on reload_if_changed().
// ---------------------------------------------------------------------------

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Runtime-configurable allowlist loaded from TOML file.
/// Supplements the static const lists above — if a process/IP is in either
/// the static OR dynamic list, it's considered allowed.
pub struct DynamicAllowlist {
    /// Processes to skip (starts_with matching, same as static lists)
    pub processes: HashSet<String>,
    /// IPs or CIDRs to treat as trusted
    pub ips: HashSet<String>,
    /// Destination ports to ignore in outbound anomaly
    pub ignored_ports: HashSet<u16>,
    /// Per-detector process suppressions: detector_name → set of comms
    pub per_detector: std::collections::HashMap<String, HashSet<String>>,
    /// DNS domains to exclude from dns_tunneling detection.
    pub dns_allowed_domains: HashSet<String>,
    /// IPs that are technically private but should be treated as external
    /// for testing purposes (e.g., Mac on local network running attacks).
    pub test_external_ips: HashSet<String>,
    /// Sigma rule IDs to suppress entirely (no alerts).
    pub suppress_sigma_rules: HashSet<String>,
    /// Path to the TOML file
    path: PathBuf,
    /// Last modification time (for reload detection)
    last_modified: Option<SystemTime>,
}

impl DynamicAllowlist {
    /// Load from file. Returns empty allowlist if file doesn't exist (not an error).
    pub fn load(path: &Path) -> Self {
        let mut al = Self {
            processes: HashSet::new(),
            ips: HashSet::new(),
            ignored_ports: HashSet::new(),
            per_detector: std::collections::HashMap::new(),
            dns_allowed_domains: HashSet::new(),
            test_external_ips: HashSet::new(),
            suppress_sigma_rules: HashSet::new(),
            path: path.to_path_buf(),
            last_modified: None,
        };
        al.reload();
        al
    }

    /// Reload from disk if the file has changed.
    /// Returns true if the file was reloaded.
    pub fn reload_if_changed(&mut self) -> bool {
        let current_mtime = std::fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());

        if current_mtime != self.last_modified {
            self.reload();
            true
        } else {
            false
        }
    }

    fn reload(&mut self) {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(_) => return, // File doesn't exist yet — that's fine
        };

        // Parse TOML manually (sensor doesn't depend on toml crate for this)
        // Simple key = "value" format per section
        self.processes.clear();
        self.ips.clear();
        self.ignored_ports.clear();
        self.per_detector.clear();
        self.dns_allowed_domains.clear();
        self.test_external_ips.clear();
        self.suppress_sigma_rules.clear();

        let mut section = String::new();
        let mut detector_section: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Section header
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].to_string();
                detector_section = if section.starts_with("detectors.") {
                    Some(section.strip_prefix("detectors.").unwrap().to_string())
                } else {
                    None
                };
                continue;
            }

            // Key = "value" or key = value
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().trim_matches('"');
                let value = value.trim().trim_matches('"');

                match section.as_str() {
                    "processes" => {
                        self.processes.insert(key.to_string());
                    }
                    "ips" => {
                        self.ips.insert(key.to_string());
                    }
                    "dns_domains" => {
                        self.dns_allowed_domains.insert(key.to_string());
                    }
                    "test_external_ips" => {
                        self.test_external_ips.insert(key.to_string());
                    }
                    "ports" => {
                        // Parse comma-separated port list: ignored = 0, 9, 67
                        for part in value.split(',') {
                            if let Ok(port) = part.trim().parse::<u16>() {
                                self.ignored_ports.insert(port);
                            }
                        }
                    }
                    "suppress" => {
                        // sigma_rules = "id1", "id2", ...
                        if key == "sigma_rules" {
                            for part in value.split(',') {
                                let id = part.trim().trim_matches('"').trim();
                                if !id.is_empty() {
                                    self.suppress_sigma_rules.insert(id.to_string());
                                }
                            }
                        }
                    }
                    _ => {
                        if let Some(ref det) = detector_section {
                            let entries = self.per_detector.entry(det.clone()).or_default();
                            entries.insert(key.to_string());
                        }
                    }
                }
            }
        }

        self.last_modified = std::fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());

        tracing::info!(
            processes = self.processes.len(),
            ips = self.ips.len(),
            ports = self.ignored_ports.len(),
            dns = self.dns_allowed_domains.len(),
            test_external = self.test_external_ips.len(),
            detectors = self.per_detector.len(),
            suppress_sigma = self.suppress_sigma_rules.len(),
            path = %self.path.display(),
            "Dynamic allowlist loaded"
        );
    }

    /// Check if a process comm is dynamically allowlisted (global or per-detector).
    pub fn is_process_allowed(&self, comm: &str, detector: Option<&str>) -> bool {
        let comm_base = comm.split('/').next_back().unwrap_or(comm);
        let comm_base = comm_base.trim_matches(|c: char| c == '(' || c == ')');

        // Global process allowlist
        if self
            .processes
            .iter()
            .any(|p| comm_base.starts_with(p.as_str()))
        {
            return true;
        }

        // Per-detector allowlist
        if let Some(det) = detector {
            if let Some(entries) = self.per_detector.get(det) {
                if entries.iter().any(|p| comm_base.starts_with(p.as_str())) {
                    return true;
                }
            }
        }

        false
    }

    /// Returns true when an incident should be suppressed based on the
    /// per-detector allowlist (`[detectors.<NAME>]` section in
    /// `allowlist.toml`). The post-emit hook lets detectors that don't
    /// thread the allowlist into their own `process()` body still honour
    /// `[detectors.<NAME>]` entries — operator-reported on 2026-05-16
    /// after `apt upgrade` lit up `kernel_module_load`,
    /// `systemd_persistence`, `sudo_abuse`, and `mitre_hunt::destructive_dd`
    /// for completely legitimate boot / maintenance activity.
    ///
    /// Field-extraction rules per detector:
    ///   - `kernel_module_load`: `module` (e.g. `bcache`, `dm_raid`),
    ///     then `comm` (e.g. `kmod`, `modprobe`).
    ///   - `sudo_abuse`: `user` (e.g. `ubuntu`).
    ///   - `systemd_persistence`: `comm` (e.g. `systemctl`).
    ///   - `mitre_hunt`: `comm` (covers `destructive_dd` — operator can
    ///     allowlist `dd` if they need to image disks during maintenance).
    ///
    /// Any non-empty match against `per_detector[<name>]` suppresses the
    /// incident. `starts_with` matching mirrors `is_process_allowed`, so
    /// `kmod` allowlists everything starting with `kmod` and `systemctl`
    /// suppresses every `systemctl …` invocation.
    pub fn extract_evidence_candidates(
        incident: &innerwarden_core::incident::Incident,
        detector_name: &str,
    ) -> Vec<String> {
        let Some(first) = incident.evidence.get(0) else {
            return Vec::new();
        };
        let pick = |key: &str| -> Option<String> {
            first
                .get(key)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };
        let mut candidates: Vec<String> = Vec::new();
        let push_if_some = |candidates: &mut Vec<String>, value: Option<String>| match value {
            Some(v) if !v.is_empty() => candidates.push(v),
            _ => {}
        };
        match detector_name {
            "kernel_module_load" => {
                push_if_some(&mut candidates, pick("module"));
                push_if_some(&mut candidates, pick("comm"));
            }
            "sudo_abuse" => {
                push_if_some(&mut candidates, pick("user"));
            }
            "mitre_hunt" => {
                push_if_some(&mut candidates, pick("kind"));
                push_if_some(&mut candidates, pick("comm"));
            }
            "integrity_alert" => {
                push_if_some(&mut candidates, pick("path"));
            }
            "crontab_persistence" => {
                push_if_some(&mut candidates, pick("comm"));
                push_if_some(&mut candidates, pick("path"));
            }
            "sensitive_write" => {
                push_if_some(&mut candidates, pick("comm"));
                push_if_some(&mut candidates, pick("filename"));
            }
            "ssh_key_injection" => {
                push_if_some(&mut candidates, pick("comm"));
                push_if_some(&mut candidates, pick("target"));
            }
            "rootkit" => {
                push_if_some(&mut candidates, pick("comm"));
                push_if_some(&mut candidates, pick("binary_path"));
                push_if_some(&mut candidates, pick("filename"));
            }
            _ => {
                push_if_some(&mut candidates, pick("comm"));
            }
        }
        candidates
    }

    pub fn suppress_incident_for_detector(
        &self,
        incident: &innerwarden_core::incident::Incident,
        detector_name: &str,
    ) -> bool {
        let Some(entries) = self.per_detector.get(detector_name) else {
            return false;
        };
        if entries.is_empty() {
            return false;
        }

        let candidates = Self::extract_evidence_candidates(incident, detector_name);

        // Each candidate is tested two ways:
        //   - **basename-startswith** so comm-style entries like `sd-pam`
        //     match `(sd-pam)` / `/usr/sbin/sd-pam`;
        //   - **full-startswith** so path-style entries like
        //     `/etc/ld.so.conf.d/` or `/usr/lib/systemd/` match the entire
        //     evidence path. Picking only basename, as the comm-only path
        //     did, silently broke every path-based allowlist entry.
        for cand in &candidates {
            let full = cand.as_str();
            let base = full
                .split('/')
                .next_back()
                .unwrap_or(full)
                .trim_matches(|c: char| c == '(' || c == ')');
            if entries.iter().any(|e| {
                let entry = e.as_str();
                full.starts_with(entry) || base.starts_with(entry)
            }) {
                return true;
            }
        }
        false
    }

    /// Spec 050-PR0 context-aware allowlist gate. Returns `true` when
    /// a `shell.command_exec` (or `process.exec`) event should be
    /// silenced for discovery-style detectors.
    ///
    /// Three layered gates; **any** match silences:
    ///
    /// 1. Legacy comm allowlist (`DISCOVERY_ALLOWED`) — monitoring
    ///    tools, build systems, boot scripts. Kept as-is to preserve
    ///    pre-050 behaviour; these comms historically had blanket
    ///    silence and we cannot regress that without a shadow window.
    /// 2. Operator-extensible `[detectors.discovery_anomaly]` TOML
    ///    list — wired through `is_process_allowed`. Lets the operator
    ///    add their own service-account comms without recompile.
    /// 3. Execution context (`exec_context::classify`) — the new
    ///    half. Catches the 2026-05-16 Caldera gap: an operator
    ///    running `whoami` under `bash` with uid 1000 classifies as
    ///    `OpInteractive` and is silenced; sandcat running the same
    ///    `whoami` with parent `sandcat` classifies as
    ///    `AttackerInferred` and falls through.
    ///
    /// Operator quote (2026-05-16): "se o user normal faz, o allow
    /// list deveria pegar o user normal não o caldeira."
    pub fn is_benign_discovery(&self, event: &innerwarden_core::event::Event) -> bool {
        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return false;
        }
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if comm.is_empty() {
            return false;
        }

        // Gate 1: legacy DISCOVERY_ALLOWED comm list.
        if comm_in_allowlist(comm, DISCOVERY_ALLOWED) {
            return true;
        }

        // Gate 2: operator-extensible per-detector TOML list.
        if self.is_process_allowed(comm, Some("discovery_anomaly")) {
            return true;
        }

        // Gate 3: 050-PR0 context-aware classifier.
        crate::detectors::exec_context::classify(event).is_benign()
    }

    /// Check if an IP is dynamically allowlisted.
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        if self.ips.contains(ip) {
            return true;
        }
        // CIDR check
        self.ips.iter().any(|entry| {
            if entry.contains('/') {
                crate::detectors::allowlists::cidr_matches(ip, entry)
            } else {
                false
            }
        })
    }

    /// Check if a destination port should be ignored.
    pub fn is_port_ignored(&self, port: u16) -> bool {
        self.ignored_ports.contains(&port)
    }

    /// Check if a DNS domain should be excluded from tunneling detection.
    pub fn is_dns_domain_allowed(&self, domain: &str) -> bool {
        self.dns_allowed_domains
            .iter()
            .any(|d| domain.ends_with(d.as_str()))
    }

    /// Check if a Sigma rule ID is suppressed via config.
    pub fn is_sigma_rule_suppressed(&self, rule_id: &str) -> bool {
        self.suppress_sigma_rules.contains(rule_id)
    }

    /// Check if an IP should be treated as external even though it's technically
    /// private. Used for testing from local networks (e.g., Mac attacking VM).
    pub fn is_test_external(&self, ip: &str) -> bool {
        self.test_external_ips.contains(ip)
    }
}

/// CIDR match helper (reusable).
pub fn cidr_matches(ip_str: &str, cidr: &str) -> bool {
    let Some((base_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix_len) = prefix_str.parse::<u32>() else {
        return false;
    };
    let Ok(ip) = ip_str.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(base) = base_str.parse::<std::net::IpAddr>() else {
        return false;
    };
    match (ip, base) {
        (std::net::IpAddr::V4(ip4), std::net::IpAddr::V4(base4)) if prefix_len <= 32 => {
            let shift = 32u32.saturating_sub(prefix_len);
            let mask = if shift >= 32 { 0u32 } else { !0u32 << shift };
            (u32::from(ip4) & mask) == (u32::from(base4) & mask)
        }
        (std::net::IpAddr::V6(ip6), std::net::IpAddr::V6(base6)) if prefix_len <= 128 => {
            let shift = 128u32.saturating_sub(prefix_len);
            let mask = if shift >= 128 { 0u128 } else { !0u128 << shift };
            (u128::from(ip6) & mask) == (u128::from(base6) & mask)
        }
        _ => false,
    }
}

/// Check if an IP is internal, respecting test_external_ips overrides.
/// Returns false (= treat as external) if the IP is in the test_external list,
/// even if it's technically a private IP.
pub fn is_internal_ip_with_overrides(ip: &str, dynamic: &DynamicAllowlist) -> bool {
    if dynamic.is_test_external(ip) {
        return false; // Treat as external for testing
    }
    super::is_internal_ip(ip)
}

/// Combined check: static const list OR dynamic allowlist.
pub fn comm_in_any_allowlist(
    comm: &str,
    static_list: &[&str],
    dynamic: &DynamicAllowlist,
    detector: Option<&str>,
) -> bool {
    comm_in_allowlist(comm, static_list) || dynamic.is_process_allowed(comm, detector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn innerwarden_detection() {
        assert!(is_innerwarden_process(998, "anything")); // uid match
        assert!(is_innerwarden_process(0, "innerwarden-sensor")); // comm prefix
        assert!(is_innerwarden_process(0, "tokio-rt-worker")); // tokio runtime
        assert!(is_innerwarden_process(998, "en-agent")); // uid 998 = innerwarden
        assert!(!is_innerwarden_process(0, "en-agent")); // not uid 998, no warden in comm
        assert!(!is_innerwarden_process(1000, "bash"));
    }

    #[test]
    fn comm_matching() {
        assert!(comm_in_allowlist("systemd-journal", SYSTEM_DAEMONS));
        assert!(comm_in_allowlist("dpkg-preconfigu", PACKAGE_MANAGERS));
        assert!(comm_in_allowlist("00-header", DISCOVERY_ALLOWED));
        assert!(!comm_in_allowlist("evil-script", SYSTEM_DAEMONS));
    }

    #[test]
    fn parenthesized_comm_matching() {
        // Kernel task format: (install) instead of install
        assert!(comm_in_allowlist("(install)", PRIVESC_ALLOWED));
        assert!(comm_in_allowlist("(find)", PRIVESC_ALLOWED));
        assert!(comm_in_allowlist("(mandb)", PRIVESC_ALLOWED));
        assert!(comm_in_allowlist("(fwupdmgr)", PRIVESC_ALLOWED));
        assert!(!comm_in_allowlist("(evil-exploit)", PRIVESC_ALLOWED));
        // is_innerwarden_process with parentheses
        assert!(is_innerwarden_process(0, "(innerwarden-sensor)"));
        assert!(is_innerwarden_process(0, "(tokio-rt-worker)"));
        assert!(!is_innerwarden_process(0, "(bash)"));
    }

    #[test]
    fn no_duplicates() {
        fn check(name: &str, list: &[&str]) {
            let mut seen = std::collections::HashSet::new();
            for entry in list {
                assert!(seen.insert(entry), "Duplicate in {}: {}", name, entry);
            }
        }
        check("SYSTEM_DAEMONS", SYSTEM_DAEMONS);
        check("PACKAGE_MANAGERS", PACKAGE_MANAGERS);
        check("LOGIN_BINARIES", LOGIN_BINARIES);
        check("DISCOVERY_ALLOWED", DISCOVERY_ALLOWED);
        check("PRIVESC_ALLOWED", PRIVESC_ALLOWED);
        check("C2_OUTBOUND_ALLOWED", C2_OUTBOUND_ALLOWED);
    }

    #[test]
    fn dynamic_allowlist_empty_file() {
        let al = DynamicAllowlist::load(Path::new("/nonexistent/allowlist.toml"));
        assert!(al.processes.is_empty());
        assert!(al.ips.is_empty());
        assert!(!al.is_process_allowed("evil", None));
    }

    #[test]
    fn dynamic_allowlist_parse() {
        let dir = std::env::temp_dir().join("iw_test_allowlist");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
# Dynamic allowlist for testing
[processes]
"gomon" = "Go monitor"
"updater" = "System updater"

[ips]
"172.18.0.0/16" = "Docker network"
"10.0.0.5" = "Build server"

[ports]
ignored = 0, 9, 67

[detectors.outbound_anomaly]
"my_custom_app" = "Internal tool"
"#,
        )
        .unwrap();

        let al = DynamicAllowlist::load(&path);
        assert!(al.is_process_allowed("gomon", None));
        assert!(al.is_process_allowed("updater", None));
        assert!(!al.is_process_allowed("evil", None));
        assert!(al.is_process_allowed("my_custom_app", Some("outbound_anomaly")));
        assert!(!al.is_process_allowed("my_custom_app", Some("ssh_bruteforce")));
        assert!(al.is_ip_allowed("172.18.0.6"));
        assert!(al.is_ip_allowed("10.0.0.5"));
        assert!(!al.is_ip_allowed("1.2.3.4"));
        assert!(al.is_port_ignored(9));
        assert!(!al.is_port_ignored(80));

        // Cleanup
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    fn make_incident(
        detector: &str,
        evidence: serde_json::Value,
    ) -> innerwarden_core::incident::Incident {
        innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            incident_id: format!("{detector}:test"),
            severity: innerwarden_core::event::Severity::High,
            title: "test".to_string(),
            summary: "test".to_string(),
            evidence,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn suppress_incident_for_detector_kernel_module_matches_module_name() {
        // Operator-reported FP: apt upgrade triggers kernel_module_load
        // for bcache / dm_raid / iscsi_* / cxgb*. Allowlisting any of these
        // as a per-detector entry suppresses the incident.
        let dir = std::env::temp_dir().join("iw_test_allowlist_suppress_kmod");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
[detectors.kernel_module_load]
"bcache" = "Ubuntu boot — block-layer cache"
"dm_raid" = "Ubuntu boot — software RAID"
"iscsi_" = "Ubuntu boot — iSCSI subsystem"
"#,
        )
        .unwrap();
        let al = DynamicAllowlist::load(&path);

        let incident = make_incident(
            "kernel_module_load",
            serde_json::json!([{ "module": "bcache", "comm": "kmod" }]),
        );
        assert!(al.suppress_incident_for_detector(&incident, "kernel_module_load"));

        // prefix match
        let incident = make_incident(
            "kernel_module_load",
            serde_json::json!([{ "module": "iscsi_tcp", "comm": "kmod" }]),
        );
        assert!(al.suppress_incident_for_detector(&incident, "kernel_module_load"));

        // non-allowlisted module still fires
        let incident = make_incident(
            "kernel_module_load",
            serde_json::json!([{ "module": "evil_rootkit", "comm": "kmod" }]),
        );
        assert!(!al.suppress_incident_for_detector(&incident, "kernel_module_load"));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn suppress_incident_for_detector_kernel_module_matches_loader_comm() {
        let dir = std::env::temp_dir().join("iw_test_allowlist_suppress_kmod_comm");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
[detectors.kernel_module_load]
"kmod" = "kernel built-in loader"
"#,
        )
        .unwrap();
        let al = DynamicAllowlist::load(&path);

        let incident = make_incident(
            "kernel_module_load",
            serde_json::json!([{ "module": "any_module", "comm": "kmod" }]),
        );
        assert!(al.suppress_incident_for_detector(&incident, "kernel_module_load"));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn suppress_incident_for_detector_sudo_abuse_matches_user() {
        // Operator-reported FP: apt upgrade by ubuntu user trips the
        // sudo_abuse counter. Allowlisting the user suppresses.
        let dir = std::env::temp_dir().join("iw_test_allowlist_suppress_sudo");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
[detectors.sudo_abuse]
"ubuntu" = "Operator user — apt upgrades and maintenance"
"#,
        )
        .unwrap();
        let al = DynamicAllowlist::load(&path);

        let incident = make_incident(
            "sudo_abuse",
            serde_json::json!([{ "user": "ubuntu", "count": 3 }]),
        );
        assert!(al.suppress_incident_for_detector(&incident, "sudo_abuse"));

        let incident = make_incident(
            "sudo_abuse",
            serde_json::json!([{ "user": "attacker", "count": 3 }]),
        );
        assert!(!al.suppress_incident_for_detector(&incident, "sudo_abuse"));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn suppress_incident_for_detector_systemd_persistence_matches_comm() {
        // Operator-reported FP: `systemctl daemon-reload` (needrestart
        // hits this on every apt upgrade) and `systemctl --quiet
        // is-enabled crowdsec` trip systemd_persistence.
        let dir = std::env::temp_dir().join("iw_test_allowlist_suppress_systemd");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
[detectors.systemd_persistence]
"systemctl" = "Operator-driven systemctl invocations"
"#,
        )
        .unwrap();
        let al = DynamicAllowlist::load(&path);

        let incident = make_incident(
            "systemd_persistence",
            serde_json::json!([{ "comm": "systemctl", "kind": "exec.command" }]),
        );
        assert!(al.suppress_incident_for_detector(&incident, "systemd_persistence"));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn suppress_incident_for_detector_mitre_hunt_matches_kind() {
        // mitre_hunt's evidence carries the sub-detector identity in
        // `kind` (e.g. `destructive_dd`). Operators allowlist by kind so
        // they can keep mitre_hunt enabled for everything else while
        // silencing the one sub-detector that fires on legitimate `dd`
        // use during maintenance.
        let dir = std::env::temp_dir().join("iw_test_allowlist_suppress_mitre");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
[detectors.mitre_hunt]
"destructive_dd" = "Operator uses dd for legit disk imaging"
"#,
        )
        .unwrap();
        let al = DynamicAllowlist::load(&path);

        let incident = make_incident(
            "mitre_hunt",
            serde_json::json!([{ "kind": "destructive_dd", "command": "dd if=/dev/zero of=/dev/sdc bs=1M" }]),
        );
        assert!(al.suppress_incident_for_detector(&incident, "mitre_hunt"));

        // Other mitre_hunt sub-detections still fire.
        let incident = make_incident(
            "mitre_hunt",
            serde_json::json!([{ "kind": "credential_dump", "command": "cat /etc/shadow" }]),
        );
        assert!(!al.suppress_incident_for_detector(&incident, "mitre_hunt"));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn suppress_incident_for_detector_returns_false_when_no_entries() {
        let al = DynamicAllowlist::load(Path::new("/nonexistent/allowlist.toml"));
        let incident = make_incident(
            "kernel_module_load",
            serde_json::json!([{ "module": "anything", "comm": "kmod" }]),
        );
        assert!(!al.suppress_incident_for_detector(&incident, "kernel_module_load"));
    }

    #[test]
    fn suppress_incident_for_detector_integrity_alert_matches_path_prefix() {
        // FP scenario: apt upgrade rewrites /etc/cloud/cloud.cfg or
        // /etc/ld.so.conf.d/*. Operator allowlists the directory prefix.
        let dir = std::env::temp_dir().join("iw_test_allowlist_integrity");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
[detectors.integrity_alert]
"/etc/ld.so.conf.d/" = "apt-upgrade rewrites these"
"#,
        )
        .unwrap();
        let al = DynamicAllowlist::load(&path);
        let inc = make_incident(
            "integrity_alert",
            serde_json::json!([{ "kind": "file.changed", "path": "/etc/ld.so.conf.d/libc.conf" }]),
        );
        assert!(al.suppress_incident_for_detector(&inc, "integrity_alert"));
        let inc2 = make_incident(
            "integrity_alert",
            serde_json::json!([{ "kind": "file.changed", "path": "/etc/shadow" }]),
        );
        assert!(!al.suppress_incident_for_detector(&inc2, "integrity_alert"));
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn suppress_incident_for_detector_sensitive_write_matches_filename_or_comm() {
        let dir = std::env::temp_dir().join("iw_test_allowlist_sensitive_write");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
[detectors.sensitive_write]
"dpkg" = "apt-internal config writer"
"/etc/cron.d/" = "package-installed cron jobs"
"#,
        )
        .unwrap();
        let al = DynamicAllowlist::load(&path);
        // matched by comm
        let inc = make_incident(
            "sensitive_write",
            serde_json::json!([{ "comm": "dpkg", "filename": "/etc/sudoers.d/foo" }]),
        );
        assert!(al.suppress_incident_for_detector(&inc, "sensitive_write"));
        // matched by filename prefix
        let inc2 = make_incident(
            "sensitive_write",
            serde_json::json!([{ "comm": "nano", "filename": "/etc/cron.d/postgresql" }]),
        );
        assert!(al.suppress_incident_for_detector(&inc2, "sensitive_write"));
        // attacker-style write still fires
        let inc3 = make_incident(
            "sensitive_write",
            serde_json::json!([{ "comm": "bash", "filename": "/etc/shadow" }]),
        );
        assert!(!al.suppress_incident_for_detector(&inc3, "sensitive_write"));
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn suppress_incident_for_detector_ssh_key_injection_matches_target_path() {
        let dir = std::env::temp_dir().join("iw_test_allowlist_ssh_key");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
[detectors.ssh_key_injection]
"/home/ubuntu/.ssh/authorized_keys" = "operator manages own key file"
"#,
        )
        .unwrap();
        let al = DynamicAllowlist::load(&path);
        let inc = make_incident(
            "ssh_key_injection",
            serde_json::json!([{
                "comm": "ssh-keygen",
                "target": "/home/ubuntu/.ssh/authorized_keys",
                "pattern": "AAAAB3..."
            }]),
        );
        assert!(al.suppress_incident_for_detector(&inc, "ssh_key_injection"));
        // attacker writing to a different user
        let inc2 = make_incident(
            "ssh_key_injection",
            serde_json::json!([{
                "comm": "bash",
                "target": "/root/.ssh/authorized_keys",
                "pattern": "AAAAB3..."
            }]),
        );
        assert!(!al.suppress_incident_for_detector(&inc2, "ssh_key_injection"));
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn suppress_incident_for_detector_rootkit_matches_binary_path() {
        let dir = std::env::temp_dir().join("iw_test_allowlist_rootkit");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
[detectors.rootkit]
"/usr/lib/systemd/" = "legitimate systemd-internal binaries"
"#,
        )
        .unwrap();
        let al = DynamicAllowlist::load(&path);
        let inc = make_incident(
            "rootkit",
            serde_json::json!([{
                "kind": "hidden_process",
                "comm": "(sd-pam)",
                "binary_path": "/usr/lib/systemd/systemd"
            }]),
        );
        assert!(al.suppress_incident_for_detector(&inc, "rootkit"));
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn suppress_incident_for_detector_crontab_persistence_matches_comm_or_path() {
        let dir = std::env::temp_dir().join("iw_test_allowlist_cron");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
[detectors.crontab_persistence]
"dpkg" = "apt installs ship cron jobs"
"/etc/cron.daily/" = "Ubuntu maintenance jobs"
"#,
        )
        .unwrap();
        let al = DynamicAllowlist::load(&path);
        // matched by comm
        let inc = make_incident(
            "crontab_persistence",
            serde_json::json!([{
                "kind": "crontab_write",
                "comm": "dpkg",
                "path": "/etc/cron.d/postgresql"
            }]),
        );
        assert!(al.suppress_incident_for_detector(&inc, "crontab_persistence"));
        // matched by path prefix
        let inc2 = make_incident(
            "crontab_persistence",
            serde_json::json!([{
                "kind": "crontab_write",
                "comm": "rsyslog-rotate",
                "path": "/etc/cron.daily/logrotate"
            }]),
        );
        assert!(al.suppress_incident_for_detector(&inc2, "crontab_persistence"));
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn suppress_incident_for_detector_handles_empty_evidence() {
        let dir = std::env::temp_dir().join("iw_test_allowlist_suppress_empty");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
[detectors.kernel_module_load]
"bcache" = "test"
"#,
        )
        .unwrap();
        let al = DynamicAllowlist::load(&path);

        // No evidence elements — must not panic and must return false.
        let incident = make_incident("kernel_module_load", serde_json::json!([]));
        assert!(!al.suppress_incident_for_detector(&incident, "kernel_module_load"));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn cidr_matches_works() {
        assert!(cidr_matches("172.18.0.6", "172.18.0.0/16"));
        assert!(!cidr_matches("172.19.0.6", "172.18.0.0/16"));
        assert!(cidr_matches("10.0.0.1", "10.0.0.0/24"));
        assert!(!cidr_matches("10.0.1.1", "10.0.0.0/24"));
    }

    #[test]
    fn comm_in_any_works() {
        let al = DynamicAllowlist::load(Path::new("/nonexistent"));
        // Static only
        assert!(comm_in_any_allowlist(
            "systemd-journal",
            SYSTEM_DAEMONS,
            &al,
            None
        ));
        // Neither
        assert!(!comm_in_any_allowlist(
            "evil-script",
            SYSTEM_DAEMONS,
            &al,
            None
        ));
    }

    // -----------------------------------------------------------------
    // Spec 050-PR0: is_benign_discovery — 3-gate context-aware allowlist
    // -----------------------------------------------------------------

    fn discovery_event(comm: &str, parent_comm: &str, uid: u64) -> innerwarden_core::event::Event {
        innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            source: "ebpf".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: innerwarden_core::event::Severity::Info,
            summary: format!("Shell command executed: {comm}"),
            details: serde_json::json!({
                "pid": 1234,
                "uid": uid,
                "ppid": 999,
                "comm": comm,
                "parent_comm": parent_comm,
                // Interactive-operator baseline: a real ssh shell owns a tty.
                // The OpInteractive free-pass now requires this (evasion audit E3).
                "has_tty": true,
                "command": comm,
                "argv": [comm],
                "argc": 1,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn is_benign_discovery_silences_operator_in_interactive_shell() {
        // Canonical 2026-05-16 operator-flagged case: a logged-in
        // operator running `whoami` from their ssh shell must be
        // silenced. parent_comm="bash" + uid>999 → OpInteractive.
        let al = DynamicAllowlist::load(Path::new("/nonexistent"));
        let ev = discovery_event("whoami", "bash", 1000);
        assert!(al.is_benign_discovery(&ev));
    }

    #[test]
    fn is_benign_discovery_surfaces_caldera_sandcat_recon() {
        // Counterpart to the test above: sandcat (no interactive
        // shell parent) running the same `whoami` must fall through
        // to AttackerInferred and be surfaced. This is the gap the
        // pre-050 blanket allowlist could not close.
        let al = DynamicAllowlist::load(Path::new("/nonexistent"));
        let ev = discovery_event("whoami", "sandcat", 1000);
        assert!(!al.is_benign_discovery(&ev));
    }

    #[test]
    fn is_benign_discovery_gate1_legacy_comm_allowlist_silences_innerwarden() {
        // Gate 1: comm is in DISCOVERY_ALLOWED. Catches monitoring
        // tools that don't fit the 5 context buckets (innerwarden,
        // osqueryd, aide, telegraf, prometheus). Preserves pre-050
        // behaviour for these.
        let al = DynamicAllowlist::load(Path::new("/nonexistent"));
        let ev = discovery_event("innerwarden-sensor", "systemd", 998);
        assert!(al.is_benign_discovery(&ev));
    }

    #[test]
    fn is_benign_discovery_gate2_operator_toml_extension() {
        // Gate 2: operator-extensible per-detector list. Operators
        // who run their own service-account comm add it to
        // `[detectors.discovery_anomaly]` and the same benign
        // treatment applies — without recompile.
        //
        // Comm choice: `myservicecheck` deliberately avoids any
        // prefix match in `DISCOVERY_ALLOWED` (which catches `node`,
        // `aide`, `logcheck`, etc. via starts_with). Parent
        // `systemd` keeps gate 3 firmly in `AttackerInferred`, so
        // the only path to a benign verdict is gate 2.
        let dir = std::env::temp_dir().join("iw_test_benign_discovery_gate2");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.toml");
        std::fs::write(
            &path,
            r#"
[detectors.discovery_anomaly]
"myservicecheck" = "Operator monitoring agent"
"#,
        )
        .unwrap();
        let al = DynamicAllowlist::load(&path);

        let ev = discovery_event("myservicecheck", "systemd", 998);
        assert!(al.is_benign_discovery(&ev));

        // Without the TOML entry, the same event would NOT be
        // silenced — proves the test is exercising gate 2.
        let al_empty = DynamicAllowlist::load(Path::new("/nonexistent"));
        assert!(!al_empty.is_benign_discovery(&ev));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn is_benign_discovery_gate3_package_manager_parent() {
        // Gate 3: context classifier. dpkg/apt postinst scripts run
        // discovery commands legitimately. The 2026-05-16 FP wave
        // (kernel_module, sudo_abuse, etc.) had `dpkg` as parent.
        let al = DynamicAllowlist::load(Path::new("/nonexistent"));
        let ev = discovery_event("uname", "dpkg", 0);
        assert!(al.is_benign_discovery(&ev));
    }

    #[test]
    fn is_benign_discovery_gate3_automation_parent() {
        // Gate 3 cont.: ansible / salt / puppet runs.
        let al = DynamicAllowlist::load(Path::new("/nonexistent"));
        let ev = discovery_event("ss", "ansible-playboo", 0);
        assert!(al.is_benign_discovery(&ev));
    }

    #[test]
    fn is_benign_discovery_ignores_non_exec_events() {
        // The gate is only meaningful for exec events; everything
        // else returns false. Prevents stray network/file events
        // from accidentally invoking discovery suppression.
        let al = DynamicAllowlist::load(Path::new("/nonexistent"));
        let mut ev = discovery_event("whoami", "bash", 1000);
        ev.kind = "network.outbound_connect".to_string();
        assert!(!al.is_benign_discovery(&ev));
    }

    #[test]
    fn is_benign_discovery_handles_missing_comm() {
        // Auditd-only events lack `comm`. The gate should not panic
        // and should return false (falls through to detector logic).
        let al = DynamicAllowlist::load(Path::new("/nonexistent"));
        let ev = innerwarden_core::event::Event {
            ts: chrono::Utc::now(),
            host: "test".into(),
            source: "auditd".into(),
            kind: "shell.command_exec".into(),
            severity: innerwarden_core::event::Severity::Info,
            summary: "auditd EXECVE".into(),
            details: serde_json::json!({
                "audit_id": "42",
                "command": "whoami",
                "argv": ["whoami"],
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(!al.is_benign_discovery(&ev));
    }

    #[test]
    fn is_benign_discovery_accepts_process_exec_kind() {
        // Some detectors emit `process.exec` instead of
        // `shell.command_exec`; the gate must accept both so the
        // semantics are uniform across the pipeline.
        let al = DynamicAllowlist::load(Path::new("/nonexistent"));
        let mut ev = discovery_event("whoami", "bash", 1000);
        ev.kind = "process.exec".to_string();
        assert!(al.is_benign_discovery(&ev));
    }

    // ===== reload_if_changed (operator-facing hot-reload behaviour) =====

    #[test]
    fn reload_if_changed_picks_up_new_processes_after_mtime_change() {
        // Hot-reload contract: when the operator edits allowlist.toml the
        // sensor must read the new content on the next 60 s poll. We assert
        // both halves: (1) mtime change triggers reload_if_changed = true,
        // (2) the parsed state reflects the edit.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("allowlist.toml");
        std::fs::write(&path, "[processes]\n\"original\" = \"comment\"\n").expect("write initial");
        let mut al = DynamicAllowlist::load(&path);
        assert!(al.is_process_allowed("original", None));
        assert!(!al.is_process_allowed("added-later", None));

        // mtime granularity on some filesystems is coarse; bump it
        // explicitly so the reload predicate cannot tie.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
        std::fs::write(
            &path,
            "[processes]\n\"original\" = \"comment\"\n\"added-later\" = \"comment\"\n",
        )
        .expect("write update");
        filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(later))
            .expect("bump mtime");

        assert!(
            al.reload_if_changed(),
            "mtime change must drive reload_if_changed to return true"
        );
        assert!(al.is_process_allowed("added-later", None));
        assert!(al.is_process_allowed("original", None));
    }

    #[test]
    fn reload_if_changed_returns_false_when_file_untouched() {
        // Anti-flake: reload_if_changed must NOT report a reload when the
        // file mtime is the same as the last successful load. Otherwise
        // every 60 s tick re-parses, log spam grows, and noise hides real
        // operator edits.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("allowlist.toml");
        std::fs::write(&path, "[processes]\n\"steady\" = \"\"\n").expect("write");
        let mut al = DynamicAllowlist::load(&path);
        assert!(al.is_process_allowed("steady", None));

        // No mtime change → no reload.
        assert!(!al.reload_if_changed());
        assert!(!al.reload_if_changed());
    }

    // ===== is_internal_ip_with_overrides (free function) =====

    #[test]
    fn is_internal_ip_with_overrides_demotes_test_external_to_external() {
        // Lab override path: an operator marks 10.0.0.5 as
        // `test_external` so `is_internal_ip_with_overrides` treats it as
        // external even though it is technically RFC1918. This is how
        // sensor tests use the Mac (10.0.0.x) as if it were an internet
        // attacker against the VM.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("allowlist.toml");
        std::fs::write(
            &path,
            "[test_external_ips]\n\"10.0.0.5\" = \"mac under test\"\n",
        )
        .expect("write");
        let al = DynamicAllowlist::load(&path);
        assert!(
            !is_internal_ip_with_overrides("10.0.0.5", &al),
            "test_external override must demote a private IP to external"
        );
        // Sibling RFC1918 IPs without override stay internal.
        assert!(is_internal_ip_with_overrides("10.0.0.6", &al));
    }

    #[test]
    fn is_internal_ip_with_overrides_passes_public_ips_to_baseline_classifier() {
        // Without any overrides, the function delegates to the static
        // `is_internal_ip` classifier — public IPs return false, RFC1918
        // returns true. This is the production happy path.
        let al = DynamicAllowlist::load(Path::new("/nonexistent"));
        assert!(!is_internal_ip_with_overrides("8.8.8.8", &al));
        assert!(is_internal_ip_with_overrides("192.168.1.1", &al));
        assert!(is_internal_ip_with_overrides("172.16.0.10", &al));
    }
}
