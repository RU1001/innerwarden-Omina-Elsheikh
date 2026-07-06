//! Cloud-metadata SSRF detector — flags outbound connections to
//! Instance Metadata Service (IMDS) endpoints from processes that have
//! no business querying them.
//!
//! ## Why this exists
//!
//! IMDS at `169.254.169.254` (and `fd00:ec2::254` for AWS IPv6) is the
//! cloud-provider endpoint that hands out short-lived IAM /
//! service-account credentials valid for the host. Every major cloud
//! (AWS, GCP, Azure, Oracle, Alibaba) uses the same link-local address.
//!
//! An attacker who lands SSRF in a webapp:
//!
//! ```text
//! GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
//! ```
//!
//! can lift those credentials and pivot from the compromised app to
//! the entire cloud account.
//!
//! ## Why the existing pipeline misses this
//!
//! The agent's `cloud_safelist.rs` explicitly permits the
//! `169.254.0.0/16` range so that legitimate cloud-init / SSM-agent /
//! kubelet IMDS traffic does not trip the regular outbound and C2
//! detectors. That choice is correct for those tools — and exactly
//! what an SSRF exploit hides behind. This detector is the targeted
//! exception: it specifically watches IMDS and fires when the
//! accessing process is NOT in the legitimate-tool allowlist.
//!
//! ## FP defences — keyed on the NON-FORGEABLE executable path
//!
//! 2026-05-31 redesign. The earlier version allowlisted by `comm`, which is
//! **forgeable** (`prctl(PR_SET_NAME)`, `argv[0]`, renaming the binary). That
//! turned the allowlist into a BYPASS: an attacker who named their SSRF tool
//! `cloud-init` had their IMDS cred-theft silently ignored on every host that
//! ships InnerWarden. Comm is no longer a legitimacy gate.
//!
//! Legitimacy is now decided by the accessing process's real **executable
//! path** (`exe_path`), captured at execve by the collector (non-forgeable, no
//! race) or read from `/proc/<pid>/exe` (canonical) as a fallback:
//!
//! 1. `is_innerwarden_process(uid, comm)` — our own processes, skipped.
//! 2. `IMDS_LEGITIMATE_EXE_PREFIXES` — built-in trusted vendor exe-path
//!    prefixes, all in **root-owned** dirs (`/usr`, `/snap`, `/opt`,
//!    `/var/lib`). An attacker who can run from there already has root, so the
//!    cred-theft threat model is moot. Covers AWS / GCP / Azure / Oracle Cloud
//!    / k8s agents.
//! 3. `allowlist_exe_prefixes` (config) — operator extension, also path-based.
//!
//! `comm` survives only to ESCALATE: a `WEBSERVER_RUNTIME_PREFIXES` comm
//! (`nginx`, `php-fpm`, …) hitting IMDS = **Critical** (the SSRF signature).
//! Forging comm to look like nginx only makes you MORE suspicious, so this
//! direction is safe. Everything else not from a trusted exe = **High**. When
//! the exe cannot be resolved at all, the detector does NOT skip — it alerts
//! (fail toward detection).
//!
//! A per-(comm) cooldown of 10 minutes prevents alert floods.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

/// Default IMDS IPv4 endpoint shared by AWS, GCP, Azure, Oracle, Alibaba.
const IMDS_IPV4: &str = "169.254.169.254";

/// AWS IPv6 IMDS endpoint (RFC 7793 / ULA-style address that AWS reuses
/// for the same role as the IPv4 169.254.169.254).
const IMDS_IPV6: &str = "fd00:ec2::254";

/// Cooldown applied per accessing comm. Even an SSRF loop should not
/// emit more than one incident per (comm) per 10 minutes — the first
/// one is enough to wake the operator.
pub const DEFAULT_COOLDOWN_SECONDS: u64 = 600;

/// Built-in legitimacy allowlist keyed on the accessing process's real
/// **executable path** (`exe_path`), NOT its `comm`.
///
/// Why path, not comm (2026-05-31 redesign): `comm` is forgeable
/// (`prctl(PR_SET_NAME)`, `argv[0]`, renaming the binary). A comm allowlist
/// was therefore a BYPASS — an attacker who renamed their SSRF tool
/// `cloud-init` had IMDS access silently ignored. The executable path is
/// non-forgeable in the way that matters: every entry below lives in a
/// **root-owned** directory (`/usr`, `/snap`, `/opt`, `/var/lib`). An
/// attacker who can place a binary there already has root — at which point
/// the IMDS-cred-theft threat model is moot (they own the host).
///
/// Directory entries carry a trailing `/` so `/snap/oracle-cloud-agent-evil/`
/// does NOT match `/snap/oracle-cloud-agent/`. File entries are exact program
/// paths in root-owned `bin` dirs.
///
/// Coverage (Oracle paths verified on prod 2026-05-31):
const IMDS_LEGITIMATE_EXE_PREFIXES: &[&str] = &[
    // AWS
    "/usr/bin/cloud-init",
    "/usr/local/bin/cloud-init",
    "/usr/lib/python3/dist-packages/cloudinit/",
    "/snap/amazon-ssm-agent/",
    "/usr/bin/amazon-ssm-agent",
    "/opt/aws/",
    "/opt/amazon/",
    // GCP
    "/usr/bin/google_",
    "/usr/bin/gke-metadata-server",
    "/snap/google-cloud-cli/",
    "/usr/lib/python3/dist-packages/google/",
    // Azure
    "/usr/sbin/waagent",
    "/var/lib/waagent/",
    "/opt/microsoft/",
    // Oracle Cloud (OCI) — verified on prod
    "/snap/oracle-cloud-agent/",
    "/usr/libexec/oracle-cloud-agent/",
    "/var/lib/oracle-cloud-agent/",
    "/opt/unified-monitoring-agent/",
    // Kubernetes / container runtimes
    "/usr/bin/kubelet",
    "/usr/local/bin/kubelet",
    "/usr/bin/dockerd",
    "/usr/bin/containerd",
    "/var/lib/rancher/",
    "/snap/microk8s/",
    // Base-OS system daemons that touch the metadata IP for non-cred reasons
    // (e.g. systemd-resolved forwards DNS to the cloud resolver, which on many
    // clouds shares 169.254.169.254). Root-owned system binaries that take no
    // untrusted URL input, so they are not an SSRF vector. Verified on prod
    // 2026-05-31. Both the merged (/usr/lib) and Debian (/lib) unit paths.
    "/usr/lib/systemd/systemd-resolved",
    "/lib/systemd/systemd-resolved",
];

/// Comms whose IMDS access is treated as the canonical SSRF signature
/// and promoted to Critical. These are HTTP-serving frontends and
/// app-server workers — none of them call IAM as part of their job.
///
/// Deliberately conservative: this list does NOT include generic
/// language runtimes (`python`, `node`, `ruby`, `java`) because those
/// comms are also used for CLI tools and worker daemons that may
/// legitimately consume IAM via the cloud SDKs. Such processes still
/// fire a HIGH-tier alert (worth one human look) and the operator can
/// allowlist them per-comm if the access is legitimate.
const WEBSERVER_RUNTIME_PREFIXES: &[&str] = &[
    "nginx",
    "apache2",
    "apache",
    "httpd",
    "caddy",
    "lighttpd",
    "openresty",
    "php-fpm",
    "uwsgi",
    "gunicorn",
    "puma",
    "unicorn",
    "passenger",
];

pub struct ImdsSsrfDetector {
    host: String,
    /// Operator-extended legitimacy allowlist of trusted executable-path
    /// prefixes, on top of `IMDS_LEGITIMATE_EXE_PREFIXES`. Non-forgeable
    /// (unlike the deprecated comm allowlist).
    allowlist_exe_prefixes: Vec<String>,
    /// Cooldown gate: per-(comm) timestamp of last emitted incident.
    alerted: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl ImdsSsrfDetector {
    pub fn new(
        host: impl Into<String>,
        allowlist_exe_prefixes: Vec<String>,
        cooldown_seconds: u64,
    ) -> Self {
        Self {
            host: host.into(),
            allowlist_exe_prefixes,
            alerted: HashMap::new(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
        }
    }

    /// Resolve the accessing process's real executable path. Prefers the
    /// `exe_path` the collector captured at execve (non-forgeable, no race);
    /// falls back to a best-effort `/proc/<pid>/exe` realpath for a long-lived
    /// daemon that started before the sensor (alive at connect time, so the
    /// read is reliable). Returns `None` only when both are unavailable
    /// (e.g. a transient pid already reaped) — the caller then fails toward
    /// alerting.
    fn resolve_exe_path(event: &Event, pid: u32) -> Option<String> {
        if let Some(e) = event.details.get("exe_path").and_then(|v| v.as_str()) {
            if !e.is_empty() {
                return Some(e.to_string());
            }
        }
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|p| p.to_str().map(str::to_string))
    }

    /// True if `exe` is a legitimate IMDS caller by executable path. Rejects
    /// non-absolute paths and any `..` traversal (a raw execve filename could
    /// carry `/usr/bin/../../tmp/evil` — `/proc/<pid>/exe` is already
    /// canonical, but the cached filename may not be). Matching is prefix
    /// based against the built-in + operator lists.
    fn is_trusted_exe(&self, exe: &str) -> bool {
        if !exe.starts_with('/') || exe.contains("/../") || exe.ends_with("/..") {
            return false;
        }
        IMDS_LEGITIMATE_EXE_PREFIXES
            .iter()
            .any(|p| exe.starts_with(p))
            || self
                .allowlist_exe_prefixes
                .iter()
                .any(|p| exe.starts_with(p.as_str()))
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "network.outbound_connect" {
            return None;
        }
        let dst_ip = event.details.get("dst_ip").and_then(|v| v.as_str())?;
        if dst_ip != IMDS_IPV4 && dst_ip != IMDS_IPV6 {
            return None;
        }

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX);

        if super::allowlists::is_innerwarden_process(uid, comm) {
            return None;
        }

        // Legitimacy is decided by the NON-FORGEABLE executable path, never by
        // `comm`. A process reaching IMDS is benign only when it runs from a
        // trusted root-owned vendor path (cloud-init / SSM / Oracle Cloud Agent
        // / kubelet / …). An attacker who renames their tool `cloud-init` but
        // runs from `/tmp` is NOT skipped — that bypass is closed. When the exe
        // cannot be resolved at all, we do NOT skip (fail toward detection).
        let exe_path = Self::resolve_exe_path(event, pid);
        if let Some(ref exe) = exe_path {
            if self.is_trusted_exe(exe) {
                return None;
            }
        }

        // Cloud-platform guest-agent gate (NON-IP), covers the INTERPRETER case
        // the exe-prefix list above misses: on Azure the guest agent runs as
        // `python3 -u /usr/sbin/waagent` and its extension-handler children run
        // a RELATIVE WALinuxAgent egg path, so `exe=/usr/bin/python3.12` is not
        // a trusted prefix. `cloud_platform::is_guest_agent` resolves the real
        // identity from the script arg (root-owned /usr/sbin/waagent) and the
        // parent lineage. Gated on a detected cloud VM + uid 0; downgrade-only,
        // so a webserver runtime (uid != 0) hitting IMDS still escalates to
        // Critical below. Closes the Azure IMDS needs_review flood (869/7d,
        // prod audit 2026-06-26).
        if uid != u64::MAX && crate::cloud_platform::is_guest_agent(pid, uid as u32) {
            return None;
        }

        let now = event.ts;
        if let Some(&last) = self.alerted.get(comm) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(comm.to_string(), now);

        // Memory bound — keep the cooldown map from growing unboundedly
        // if a long-running SSRF loop cycles through many synthetic
        // comm names. 4096 distinct comms is well beyond any realistic
        // host.
        if self.alerted.len() > 4096 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, ts| *ts > cutoff);
        }

        // `comm` is used ONLY to ESCALATE (webserver -> Critical), never to
        // allowlist. Forging comm to look like nginx is self-incriminating, so
        // this direction is safe.
        let is_webserver = WEBSERVER_RUNTIME_PREFIXES
            .iter()
            .any(|p| comm.starts_with(p));
        let severity = if is_webserver {
            Severity::Critical
        } else {
            Severity::High
        };
        let exe_display = exe_path.as_deref().unwrap_or("<unresolved>");
        let exe_unverified = exe_path.is_none();

        let title = if is_webserver {
            format!("Cloud metadata SSRF: webserver process {comm} (pid={pid}) reached IMDS at {dst_ip}")
        } else {
            format!("Cloud metadata access by unexpected process: {comm} (pid={pid}, exe={exe_display}) reached IMDS at {dst_ip}")
        };

        let summary = format!(
            "{comm} (pid={pid}, exe={exe_display}) made an outbound connection to \
             the cloud metadata endpoint {dst_ip}. IMDS hands out short-lived \
             IAM / service-account credentials valid for this host. {}",
            if is_webserver {
                "Webserver runtimes (nginx / apache / php-fpm / uwsgi / \
                 gunicorn) don't call IAM in normal operation, so this \
                 pattern is the canonical SSRF-to-cred-theft signature. \
                 Treat as a likely SSRF exploit against the webapp; check \
                 request logs for the URL that triggered the IMDS request \
                 and rotate any IAM credentials the metadata server returned."
            } else if exe_unverified {
                "The executable path could not be verified (transient process), \
                 so legitimacy could not be confirmed — alerting to be safe."
            } else {
                "This executable is not under a built-in trusted cloud-agent \
                 path. Investigate whether it is a legitimate vendor agent (then \
                 allowlist via `[detectors.imds_ssrf] allowlist_exe_prefixes`) \
                 or an attacker tool stealing IAM credentials."
            }
        );

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("imds_ssrf:{pid}:{}", now.format("%Y-%m-%dT%H:%MZ")),
            severity,
            title,
            summary,
            evidence: serde_json::json!([{
                "kind": "imds_ssrf",
                "detection": "metadata_endpoint_access",
                "comm": comm,
                "exe_path": exe_path,
                "exe_unverified": exe_unverified,
                "pid": pid,
                "dst_ip": dst_ip,
                "is_webserver_runtime": is_webserver,
            }]),
            recommended_checks: vec![
                format!(
                    "Identify the URL or input that caused {comm} (pid={pid}) to query IMDS"
                ),
                "Rotate any IAM / service-account credentials that may have been returned".to_string(),
                "Patch SSRF in the application — typically a request-forwarding or webhook feature".to_string(),
                format!(
                    "If {exe_display} is a legitimate vendor agent, allowlist via `[detectors.imds_ssrf] allowlist_exe_prefixes = [\"<dir prefix>/\"]`"
                ),
            ],
            tags: vec![
                "credential_access".to_string(),
                "imds".to_string(),
                "ssrf".to_string(),
                if is_webserver {
                    "webserver_runtime".to_string()
                } else {
                    "unexpected_process".to_string()
                },
            ],
            entities: vec![EntityRef::ip(dst_ip)],
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn imds_connect_exe(
        pid: u32,
        comm: &str,
        exe: Option<&str>,
        dst_ip: &str,
        ts: DateTime<Utc>,
    ) -> Event {
        let mut details = serde_json::json!({
            "pid": pid,
            "uid": 33, // www-data
            "comm": comm,
            "dst_ip": dst_ip,
            "dst_port": 80,
        });
        if let Some(e) = exe {
            details["exe_path"] = serde_json::Value::String(e.to_string());
        }
        Event {
            ts,
            host: "test".into(),
            source: "ebpf".into(),
            kind: "network.outbound_connect".into(),
            severity: Severity::Info,
            summary: format!("connect {dst_ip}:80"),
            details,
            tags: vec!["ebpf".into()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    // Backstop: an unresolvable exe (no exe_path field + a pid that does not
    // exist, so the /proc fallback misses) — used by the webserver-escalation
    // tests where comm alone decides Critical.
    fn imds_connect(pid: u32, comm: &str, dst_ip: &str, ts: DateTime<Utc>) -> Event {
        imds_connect_exe(pid, comm, None, dst_ip, ts)
    }

    #[test]
    fn nginx_to_imds_fires_critical() {
        // The canonical SSRF signature: an HTTP-serving frontend
        // (nginx / php-fpm / uwsgi) makes an outbound connect to
        // 169.254.169.254. There is no legitimate reason for nginx
        // to call IAM — this IS the SSRF-to-cred-theft pattern.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det
            .process(&imds_connect(9100, "nginx", IMDS_IPV4, Utc::now()))
            .expect("nginx → IMDS must fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("SSRF"));
        assert!(inc.tags.contains(&"webserver_runtime".to_string()));
    }

    #[test]
    fn php_fpm_to_imds_fires_critical() {
        // PHP-FPM workers are the classic SSRF vector: a vulnerable
        // PHP app that takes URLs as input (avatar uploaders, SSRF
        // in image-proxy features) gets weaponised by appending
        // `http://169.254.169.254/latest/meta-data/iam/...`.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det
            .process(&imds_connect(9101, "php-fpm", IMDS_IPV4, Utc::now()))
            .expect("php-fpm → IMDS must fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn unknown_exe_to_imds_fires_high_not_critical() {
        // A non-webserver process from an untrusted path hitting IMDS is
        // suspicious — attacker tool or a legit app using boto3. Fire HIGH.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det
            .process(&imds_connect_exe(
                9102,
                "python3",
                Some("/usr/bin/python3"),
                IMDS_IPV4,
                Utc::now(),
            ))
            .expect("unknown exe → IMDS must fire");
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.tags.contains(&"unexpected_process".to_string()));
    }

    #[test]
    fn cloud_init_from_trusted_exe_is_silent() {
        // cloud-init queries IMDS every boot. Silent ONLY because it runs
        // from a root-owned vendor path — not because of its comm.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det.process(&imds_connect_exe(
            9103,
            "cloud-init",
            Some("/usr/bin/cloud-init"),
            IMDS_IPV4,
            Utc::now(),
        ));
        assert!(inc.is_none(), "cloud-init from /usr/bin must be silent");
    }

    #[test]
    fn ssm_agent_from_snap_path_is_silent() {
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det.process(&imds_connect_exe(
            9104,
            "amazon-ssm-agen",
            Some("/snap/amazon-ssm-agent/7993/amazon-ssm-agent"),
            IMDS_IPV4,
            Utc::now(),
        ));
        assert!(inc.is_none(), "ssm-agent from /snap must be silent");
    }

    #[test]
    fn oracle_cloud_agent_from_snap_path_is_silent() {
        // The exact prod 2026-05-31 false positive: the Oracle Cloud Agent's
        // unified-monitoring plugin polling IMDS. comm `unifiedmonitori` is
        // NOT in any list — silence comes from the verified vendor exe path.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det.process(&imds_connect_exe(
            1569,
            "unifiedmonitori",
            Some("/snap/oracle-cloud-agent/95/plugins/unifiedmonitoring/unifiedmonitoring"),
            IMDS_IPV4,
            Utc::now(),
        ));
        assert!(
            inc.is_none(),
            "Oracle Cloud Agent from /snap must be silent"
        );
    }

    #[test]
    fn systemd_resolved_from_system_path_is_silent() {
        // systemd-resolved forwards DNS to the cloud resolver, which on many
        // clouds shares 169.254.169.254. Root-owned system binary, not an SSRF
        // vector. Verified on prod 2026-05-31.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det.process(&imds_connect_exe(
            793,
            "systemd-resolve",
            Some("/usr/lib/systemd/systemd-resolved"),
            IMDS_IPV4,
            Utc::now(),
        ));
        assert!(inc.is_none(), "systemd-resolved must be silent");
    }

    #[test]
    fn spoofed_comm_from_untrusted_path_still_fires() {
        // THE BYPASS THIS REDESIGN CLOSES: an attacker names their SSRF tool
        // `cloud-init` (forging comm) but runs it from /tmp. The old comm
        // allowlist would have ignored it; the exe-path gate does NOT.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det
            .process(&imds_connect_exe(
                9200,
                "cloud-init", // forged comm
                Some("/tmp/cloud-init"),
                IMDS_IPV4,
                Utc::now(),
            ))
            .expect("forged comm from /tmp must STILL fire — bypass closed");
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn path_traversal_in_exe_is_not_trusted() {
        // `/snap/oracle-cloud-agent/../../tmp/evil` lexically starts with a
        // trusted prefix but resolves outside it. Reject `..` paths.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det.process(&imds_connect_exe(
            9201,
            "x",
            Some("/snap/oracle-cloud-agent/../../tmp/evil"),
            IMDS_IPV4,
            Utc::now(),
        ));
        assert!(inc.is_some(), "path-traversal exe must not be trusted");
    }

    #[test]
    fn operator_allowlist_exe_prefix_silences() {
        // Operator runs a legit boto3 worker from /opt/myapp; allowlist its
        // vendor dir by EXE PREFIX (non-forgeable), not comm.
        let mut det = ImdsSsrfDetector::new(
            "test",
            vec!["/opt/myapp/".to_string()],
            DEFAULT_COOLDOWN_SECONDS,
        );
        let inc = det.process(&imds_connect_exe(
            9106,
            "python3",
            Some("/opt/myapp/worker"),
            IMDS_IPV4,
            Utc::now(),
        ));
        assert!(inc.is_none(), "operator exe-prefix allowlist must silence");
    }

    #[test]
    fn cooldown_blocks_repeated_alerts_within_window() {
        // An SSRF loop hammering IMDS once a second would produce a
        // flood of identical alerts without a cooldown. Pin that the
        // second alert from the same comm within the cooldown
        // window is suppressed.
        let mut det = ImdsSsrfDetector::new("test", vec![], 600);
        let now = Utc::now();
        let first = det.process(&imds_connect(9200, "nginx", IMDS_IPV4, now));
        assert!(first.is_some());
        let second = det.process(&imds_connect(
            9200,
            "nginx",
            IMDS_IPV4,
            now + Duration::seconds(30),
        ));
        assert!(
            second.is_none(),
            "second alert within 30s must be suppressed"
        );
    }

    #[test]
    fn cooldown_expires_after_window() {
        // After the cooldown elapses, a fresh attack from the same
        // comm should fire again — otherwise an operator who acks an
        // alert and forgets to fix the SSRF would never get
        // re-paged when the attacker resumes the next day.
        let mut det = ImdsSsrfDetector::new("test", vec![], 60);
        let now = Utc::now();
        det.process(&imds_connect(9201, "nginx", IMDS_IPV4, now));
        let later = det.process(&imds_connect(
            9201,
            "nginx",
            IMDS_IPV4,
            now + Duration::seconds(61),
        ));
        assert!(later.is_some(), "alert after cooldown must fire");
    }

    #[test]
    fn ipv6_imds_endpoint_is_covered() {
        // AWS exposes IMDS at fd00:ec2::254 on IPv6-only instances.
        // Skipping IPv6 would let attackers bypass detection by
        // crafting a URL that uses the IPv6 endpoint.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det
            .process(&imds_connect(9300, "nginx", IMDS_IPV6, Utc::now()))
            .expect("IMDS over IPv6 must fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn non_imds_outbound_is_ignored() {
        // Sanity check: an outbound connect to a non-IMDS address
        // must NOT enter the detector's hot path even when the
        // process is otherwise interesting. The whole point of this
        // detector being separate from c2_callback / outbound_anomaly
        // is that it ONLY watches IMDS.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let inc = det.process(&imds_connect(9400, "nginx", "8.8.8.8", Utc::now()));
        assert!(inc.is_none());
    }

    #[test]
    fn innerwarden_own_process_is_silent() {
        // Defensive symmetry with data_exfil_ebpf: if some future
        // refactor of the agent's cloud_safelist init queries IMDS,
        // do not self-page.
        let mut det = ImdsSsrfDetector::new("test", vec![], DEFAULT_COOLDOWN_SECONDS);
        let now = Utc::now();
        let ev = Event {
            ts: now,
            host: "test".into(),
            source: "ebpf".into(),
            kind: "network.outbound_connect".into(),
            severity: Severity::Info,
            summary: "connect".into(),
            details: serde_json::json!({
                "pid": 9500,
                "uid": 998, // innerwarden uid (see allowlists::is_innerwarden_process)
                "comm": "tokio-rt-worker",
                "dst_ip": IMDS_IPV4,
                "dst_port": 80,
            }),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&ev).is_none());
    }
}
