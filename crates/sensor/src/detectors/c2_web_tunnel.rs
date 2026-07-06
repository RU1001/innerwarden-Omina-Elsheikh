//! Web-tunnel C2 detection (spec 050-PR3).
//!
//! Catches the operator-friendly tunneling tools attackers love
//! because they punch through NAT/firewalls without infrastructure:
//! `ngrok`, `cloudflared` (tunnel mode), `localtunnel`, `pinggy`,
//! `bore`, `serveo`, `frpc`.
//!
//! Two detection paths:
//!   1. `shell.command_exec` of one of the tunneling binaries.
//!   2. `dns.query` for a known tunnel-service domain — catches
//!      the tunneled session even when the binary was renamed.
//!
//! Also catches **mesh / overlay VPN** remote-access tools (`tailscale`,
//! `zerotier`, `netbird`, `nebula`) — the modern "install a legit mesh VPN on a
//! compromised host, then SSH in over the tunnel" persistence technique. These
//! are far more commonly legitimate than the tunnel binaries, so they fire at
//! **High** (not Critical), exec-only (their coordination DNS is constant on a
//! legit host and would be pure noise), deduped, and explicitly allowlistable.
//!
//! Anti-FP gates:
//!   - `cloudflared` running as the `cloudflared.service` systemd
//!     unit silenced via operator allowlist `[detectors.c2_web_tunnel]`
//!     (operators who legitimately deploy Cloudflare tunnels must
//!     add `cloudflared` there).
//!   - mesh-VPN exec deduped (10 min cooldown) + allowlistable — a host that
//!     always runs Tailscale is allowlisted once; the signal is a host that did
//!     NOT before. Note: a RENAMED mesh-VPN binary evades the exec-name match
//!     (behavioural TUN/WireGuard detection is a tracked follow-up).
//!
//! MITRE: T1572 (Protocol Tunneling) / T1090.003 (Multi-hop Proxy) /
//! T1219 (Remote Access Software).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const TUNNEL_BINARIES: &[&str] = &[
    "ngrok",
    "cloudflared",
    "localtunnel",
    "lt", // localtunnel CLI shorthand
    "pinggy",
    "bore",
    "serveo",
    "frpc",
    "frps",
    "chisel",
    "gost",
];

/// Mesh / overlay VPN remote-access tools. These are a real attacker
/// persistence channel (install a mesh VPN on a compromised host, then SSH in
/// over the tunnel — stable, encrypted, NAT-traversing, and it looks like legit
/// infrastructure). But they are MUCH more commonly legitimate than the tunnel
/// binaries above (operators run Tailscale for ordinary admin), so they fire at
/// HIGH (not Critical), exec-only (no coordination-DNS match — that traffic is
/// constant on a legit host and would be pure noise), deduped, and explicitly
/// allowlistable. A host that did not run a mesh VPN before suddenly running one
/// is the signal; a host that always does, the operator allowlists once.
const MESH_VPN_BINARIES: &[&str] = &[
    "tailscale",
    "tailscaled",
    "zerotier-one",
    "zerotier-cli",
    "netbird",
    "nebula",
];

/// Suffix-match against the FQDN in the DNS query. Order matters —
/// longer / more-specific suffixes are checked first by virtue of
/// being checked via `ends_with` per entry.
const TUNNEL_DOMAIN_SUFFIXES: &[&str] = &[
    ".devtunnels.ms",
    ".trycloudflare.com",
    ".ngrok-free.app",
    ".ngrok.io",
    ".ngrok.app",
    ".serveo.net",
    ".localtunnel.me",
    ".loca.lt",
    ".pinggy.io",
    ".pinggy.link",
    ".bore.pub",
    ".lhr.life",
];

pub struct C2WebTunnelDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl C2WebTunnelDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(600),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        match event.kind.as_str() {
            "shell.command_exec" | "process.exec" => self.process_exec(event),
            "dns.query" => self.process_dns(event),
            "network.tunnel_interface_created" => self.process_tunnel_iface(event),
            _ => None,
        }
    }

    /// Behavioural mesh-VPN signal: the `tunnel_iface` collector saw a new
    /// tun/WireGuard interface appear. This is rename-proof — an attacker can
    /// rename the binary, but the tunnel still needs the interface — so it
    /// fires at High (allowlistable) regardless of process name.
    fn process_tunnel_iface(&mut self, event: &Event) -> Option<Incident> {
        let ifname = event
            .details
            .get("ifname")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let iface_kind = event
            .details
            .get("iface_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("tunnel");
        if ifname.is_empty() {
            return None;
        }
        self.emit(
            event,
            Severity::High,
            "mesh_vpn_iface",
            ifname,
            iface_kind,
            "",
            ifname,
            0,
            0,
        )
    }

    fn process_exec(&mut self, event: &Event) -> Option<Incident> {
        let argv0 = event
            .details
            .get("argv")
            .and_then(|v| v.get(0))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let argv0_base = argv0.split('/').next_back().unwrap_or(argv0);
        // Tunnel binaries (ngrok/cloudflared/…) → Critical; mesh VPNs
        // (tailscale/zerotier/…) → High (more commonly legit, allowlistable).
        let (severity, sub_kind) = if is_tunnel_binary(argv0_base) {
            (Severity::Critical, "exec")
        } else if is_mesh_vpn_binary(argv0_base) {
            (Severity::High, "mesh_vpn")
        } else {
            return None;
        };
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let command = event
            .details
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        self.emit(
            event,
            severity,
            sub_kind,
            argv0_base,
            comm,
            parent_comm,
            command,
            pid,
            uid,
        )
    }

    fn process_dns(&mut self, event: &Event) -> Option<Incident> {
        let qname = event
            .details
            .get("query")
            .or_else(|| event.details.get("name"))
            .or_else(|| event.details.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let qname = qname.trim_end_matches('.').to_lowercase();
        if qname.is_empty() {
            return None;
        }
        if !TUNNEL_DOMAIN_SUFFIXES.iter().any(|s| qname.ends_with(*s)) {
            return None;
        }
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        self.emit(
            event,
            Severity::Critical,
            "dns",
            &qname,
            comm,
            "",
            &qname,
            pid,
            uid,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        event: &Event,
        severity: Severity,
        sub_kind: &str,
        target: &str,
        comm: &str,
        parent_comm: &str,
        command: &str,
        pid: u64,
        uid: u64,
    ) -> Option<Incident> {
        let now = event.ts;
        let key = format!("{sub_kind}:{target}");
        if let Some(&last) = self.last_fired.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.last_fired.insert(key.clone(), now);
        // `mesh_vpn` = exec-name match; `mesh_vpn_iface` = behavioural (a new
        // tun/wg interface appeared). Both get the mesh dual-use framing, tags,
        // and checks; only the title/summary differ.
        let iface = sub_kind == "mesh_vpn_iface";
        let mesh = sub_kind == "mesh_vpn" || iface;
        let title = if iface {
            format!("Remote-access tunnel interface appeared: {target} ({comm})")
        } else if mesh {
            format!("Remote-access mesh VPN started: {target}")
        } else {
            format!("Web-tunnel C2 indicator ({sub_kind}): {target}")
        };
        let summary = if iface {
            format!(
                "A new {comm} tunnel interface `{target}` appeared on this host (it was not \
                 present at startup). This is the rename-proof signal of a mesh/overlay VPN \
                 (Tailscale/ZeroTier/NetBird/WireGuard/OpenVPN) being brought up: the binary \
                 can be renamed, but the tunnel still has to create a tun/wg interface. \
                 LEGITIMATE if you (or a service) just started a VPN — allowlist it. If you did \
                 NOT, it is a common attacker-persistence channel: a stable, encrypted, \
                 NAT-traversing way back into a compromised host (T1572 / T1219)."
            )
        } else if mesh {
            format!(
                "A mesh/overlay VPN remote-access tool `{target}` ran (comm=`{comm}`, \
                 parent_comm=`{parent_comm}`, pid={pid}, uid={uid}, command=`{command}`). \
                 This is LEGITIMATE if you use it for admin access — allowlist it. If you \
                 did NOT install it, it is a common attacker-persistence channel: an \
                 implant installs a mesh VPN on a compromised host and connects back in \
                 over the encrypted tunnel (stable, NAT-traversing, looks like normal \
                 infrastructure) (T1572 / T1219)."
            )
        } else {
            format!(
                "Sub-detector `{sub_kind}` matched target `{target}` (comm=`{comm}`, \
                 parent_comm=`{parent_comm}`, pid={pid}, uid={uid}, command=`{command}`). \
                 Operator-friendly tunneling tools are a common C2 channel; the same \
                 binary that lets a developer expose a local port to the internet lets \
                 an attacker exfiltrate over an attacker-controlled relay (T1572)."
            )
        };
        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "c2_web_tunnel:{sub_kind}:{}:{}",
                target,
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity,
            title,
            summary,
            evidence: serde_json::json!([{
                "kind": "c2_web_tunnel",
                "sub_kind": sub_kind,
                "target": target,
                "comm": comm,
                "parent_comm": parent_comm,
                "command": command,
                "pid": pid,
                "uid": uid,
                "mitre": ["T1572", "T1090.003"],
            }]),
            recommended_checks: vec![
                if iface {
                    format!("Inspect the tunnel interface and find what created it: ip -d link show {target}; ss -tup | grep -i wireguard")
                } else {
                    format!("Inspect process tree: pstree -p {pid}")
                },
                if mesh {
                    "If you legitimately use this mesh VPN (Tailscale/ZeroTier/…) for admin, allowlist it via [detectors.c2_web_tunnel]; otherwise treat as attacker persistence and investigate who installed it".to_string()
                } else {
                    "If the operator legitimately runs Cloudflare tunnels / ngrok, allowlist via [detectors.c2_web_tunnel]".to_string()
                },
                "Correlate with the host's outbound connections in the last 5 minutes".to_string(),
            ],
            tags: if mesh {
                vec![
                    "c2".to_string(),
                    "tunnel".to_string(),
                    "remote_access".to_string(),
                    "persistence".to_string(),
                ]
            } else {
                vec!["c2".to_string(), "tunnel".to_string()]
            },
            entities: vec![],
        })
    }
}

fn is_tunnel_binary(base: &str) -> bool {
    TUNNEL_BINARIES.contains(&base)
}

fn is_mesh_vpn_binary(base: &str) -> bool {
    MESH_VPN_BINARIES.contains(&base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(argv0_path: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: format!("exec {argv0_path}"),
            details: serde_json::json!({
                "pid": 4242,
                "uid": 1000,
                "ppid": 4241,
                "comm": "bash",
                "parent_comm": "bash",
                "command": argv0_path,
                "argv": [argv0_path],
                "argc": 1,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn dns_event(qname: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "dns_capture".into(),
            kind: "dns.query".into(),
            severity: Severity::Info,
            summary: format!("dns query {qname}"),
            details: serde_json::json!({
                "query": qname,
                "pid": 4242,
                "uid": 1000,
                "comm": "curl",
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn tunnel_iface_event(ifname: &str, kind: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "tunnel_iface".into(),
            kind: "network.tunnel_interface_created".into(),
            severity: Severity::Medium,
            summary: format!("new tunnel interface {ifname} ({kind})"),
            details: serde_json::json!({ "ifname": ifname, "iface_kind": kind }),
            tags: vec![],
            entities: vec![],
        }
    }

    /// Behavioural mesh-VPN: a new tun/wg interface fires High with the
    /// rename-proof framing (sub_kind mesh_vpn_iface + persistence tag), even
    /// though no process name was involved.
    #[test]
    fn fires_high_on_new_tunnel_interface() {
        let mut det = C2WebTunnelDetector::new("test");
        let inc = det
            .process(&tunnel_iface_event("wg0", "wireguard"))
            .expect("new tunnel interface should fire");
        assert_eq!(inc.severity, Severity::High);
        assert!(inc.incident_id.contains(":mesh_vpn_iface:"));
        assert!(inc.tags.contains(&"persistence".to_string()));
        assert!(inc.summary.contains("wg0"));
        assert!(inc.summary.contains("rename-proof"));
    }

    #[test]
    fn tunnel_interface_without_ifname_does_not_fire() {
        let mut det = C2WebTunnelDetector::new("test");
        let mut ev = tunnel_iface_event("wg0", "tun");
        ev.details = serde_json::json!({ "iface_kind": "tun" }); // no ifname
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn fires_on_known_tunnel_binaries() {
        for bin in [
            "/usr/local/bin/ngrok",
            "cloudflared",
            "/usr/bin/bore",
            "frpc",
            "chisel",
        ] {
            let mut det = C2WebTunnelDetector::new("test");
            assert!(det.process(&exec_event(bin)).is_some(), "{bin} should fire");
        }
    }

    /// Mesh / overlay VPN remote-access tools (the "install Tailscale on a
    /// compromised host + SSH in over the tunnel" persistence technique) fire at
    /// HIGH (not Critical — they are commonly legit) with the mesh_vpn sub_kind.
    #[test]
    fn fires_high_on_mesh_vpn_binaries() {
        for bin in [
            "/usr/bin/tailscale",
            "tailscaled",
            "/usr/sbin/tailscaled",
            "zerotier-one",
            "zerotier-cli",
            "netbird",
            "nebula",
        ] {
            let mut det = C2WebTunnelDetector::new("test");
            let inc = det
                .process(&exec_event(bin))
                .unwrap_or_else(|| panic!("{bin} should fire"));
            assert_eq!(
                inc.severity,
                Severity::High,
                "{bin} mesh VPN is High, not Critical"
            );
            assert!(
                inc.incident_id.contains(":mesh_vpn:"),
                "{bin} → mesh_vpn sub_kind"
            );
            assert!(inc.tags.contains(&"persistence".to_string()));
        }
    }

    /// Regression: the existing tunnel binaries stay Critical (not downgraded).
    #[test]
    fn tunnel_binaries_stay_critical() {
        let mut det = C2WebTunnelDetector::new("test");
        let inc = det.process(&exec_event("/usr/local/bin/ngrok")).unwrap();
        assert_eq!(inc.severity, Severity::Critical);
    }

    /// A mainstream binary that merely contains a substring must NOT fire — exact
    /// basename match only, so `tailscale-status-helper` / `nebula-graph` etc. and
    /// ordinary tools stay quiet (no UX noise).
    #[test]
    fn does_not_fire_on_unrelated_or_substring_binaries() {
        let mut det = C2WebTunnelDetector::new("test");
        for bin in ["/usr/bin/curl", "tailscale-helper", "my-nebula-app", "ssh"] {
            assert!(
                det.process(&exec_event(bin)).is_none(),
                "{bin} must not fire"
            );
        }
    }

    /// Mesh-VPN exec is deduped (cooldown) — a host that runs `tailscale` many
    /// times in the window does not spam incidents.
    #[test]
    fn mesh_vpn_exec_is_deduped_within_cooldown() {
        let mut det = C2WebTunnelDetector::new("test");
        assert!(det.process(&exec_event("tailscale")).is_some());
        assert!(
            det.process(&exec_event("tailscale")).is_none(),
            "second tailscale exec within cooldown must be suppressed"
        );
    }

    #[test]
    fn fires_on_dns_query_to_tunnel_suffix() {
        for q in [
            "abcd1234.ngrok-free.app",
            "deadbeef.trycloudflare.com",
            "user42.serveo.net",
            "x.loca.lt",
            "y.pinggy.io",
        ] {
            let mut det = C2WebTunnelDetector::new("test");
            assert!(det.process(&dns_event(q)).is_some(), "{q} should fire");
        }
    }

    #[test]
    fn ignores_unrelated_binaries() {
        let mut det = C2WebTunnelDetector::new("test");
        for bin in ["ssh", "scp", "curl", "wget"] {
            assert!(
                det.process(&exec_event(bin)).is_none(),
                "{bin} should not fire"
            );
        }
    }

    #[test]
    fn ignores_unrelated_dns() {
        let mut det = C2WebTunnelDetector::new("test");
        for q in [
            "google.com",
            "github.com",
            "innerwarden.com",
            "cdn.example.org",
        ] {
            assert!(det.process(&dns_event(q)).is_none());
        }
    }

    #[test]
    fn dns_suffix_match_is_anchored() {
        // Attacker-controlled domain that ENDs with "ngrok-free.app"
        // legitimately is what we want to catch. But a string that just
        // CONTAINS "ngrok" without the full suffix must NOT fire.
        let mut det = C2WebTunnelDetector::new("test");
        assert!(det
            .process(&dns_event("ngrok-impostor-domain.com"))
            .is_none());
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = C2WebTunnelDetector::new("test");
        let ev = exec_event("ngrok");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(30);
        assert!(det.process(&ev2).is_none());
    }
}
