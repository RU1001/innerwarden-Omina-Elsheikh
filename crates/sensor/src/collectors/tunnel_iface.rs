//! Tunnel interface monitor collector.
//!
//! Detects a NEW tun / WireGuard network interface appearing at runtime — the
//! rename-proof signal that a mesh / overlay VPN (Tailscale, ZeroTier, NetBird,
//! WireGuard, OpenVPN) has been brought up. This complements the exec-name
//! mesh-VPN detection in the `c2_web_tunnel` detector: an attacker can rename
//! the binary (`tailscale` -> `nginx-worker`), but the tunnel still has to
//! create a `tun`/`wg` interface to route traffic, and the *kind* of interface
//! is set by the kernel regardless of the name. We classify by TYPE
//! (`uevent: DEVTYPE=wireguard` or the presence of `tun_flags`), not by name,
//! so a renamed interface is still caught.
//!
//! Interfaces already present at startup are treated as the operator's own
//! (their VPN/mesh) and baselined — only a tunnel that appears LATER is the
//! signal. The `c2_web_tunnel` detector turns the emitted event into an
//! allowlistable High incident.

use std::collections::HashSet;

use chrono::Utc;
use innerwarden_core::event::{Event, Severity};
use tokio::sync::mpsc;
use tracing::info;

/// Linux interface metadata root.
const SYS_CLASS_NET: &str = "/sys/class/net";

pub async fn run(tx: mpsc::Sender<Event>, host_id: String, interval_secs: u64) {
    info!("tunnel_iface: starting (interval: {interval_secs}s)");

    // Baseline: tunnel interfaces present at startup are pre-existing
    // (operator's own VPN/mesh). Only a tunnel appearing later is alerted.
    let mut known: HashSet<String> = scan_tunnel_interfaces(SYS_CLASS_NET)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    info!("tunnel_iface: baseline {} tunnel interface(s)", known.len());

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

        let now = Utc::now();
        for (name, kind) in scan_tunnel_interfaces(SYS_CLASS_NET) {
            if known.contains(&name) {
                continue;
            }
            known.insert(name.clone());
            let event = build_tunnel_event(&host_id, now, &name, kind);
            let _ = tx.send(event).await;
        }
    }
}

/// Classify one interface as a tunnel by its kernel-set TYPE, not its name.
/// Returns `Some("wireguard")` / `Some("tun")` or `None`. `base` is the
/// `/sys/class/net` root (parameterised for tests).
fn classify_interface(base: &str, name: &str) -> Option<&'static str> {
    let dir = format!("{base}/{name}");
    // WireGuard: the kernel writes `DEVTYPE=wireguard` into uevent regardless
    // of the interface name an attacker picks.
    if let Ok(uevent) = std::fs::read_to_string(format!("{dir}/uevent")) {
        if uevent.lines().any(|l| l.trim() == "DEVTYPE=wireguard") {
            return Some("wireguard");
        }
    }
    // TUN/TAP: the `tun_flags` attribute exists only on TUN devices (OpenVPN,
    // Tailscale's userspace tun, etc.), whatever the interface is named.
    if std::path::Path::new(&format!("{dir}/tun_flags")).exists() {
        return Some("tun");
    }
    None
}

/// Enumerate every tunnel interface currently present under `base`.
fn scan_tunnel_interfaces(base: &str) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(base) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(kind) = classify_interface(base, &name) {
            out.push((name, kind));
        }
    }
    out
}

fn build_tunnel_event(host_id: &str, now: chrono::DateTime<Utc>, name: &str, kind: &str) -> Event {
    Event {
        ts: now,
        host: host_id.to_string(),
        source: "tunnel_iface".into(),
        kind: "network.tunnel_interface_created".into(),
        // Informative; the c2_web_tunnel detector promotes it to a High
        // (allowlistable) incident with the mesh-VPN dual-use framing.
        severity: Severity::Medium,
        summary: format!("New tunnel interface appeared: {name} ({kind})"),
        details: serde_json::json!({
            "ifname": name,
            "iface_kind": kind,
        }),
        tags: vec!["tunnel".into(), "network".into(), "persistence".into()],
        entities: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a fake `/sys/class/net` with the given (name, files) interfaces.
    fn fake_sysnet(ifaces: &[(&str, &[(&str, &str)])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, files) in ifaces {
            let ifdir = dir.path().join(name);
            fs::create_dir_all(&ifdir).unwrap();
            for (fname, content) in *files {
                fs::write(ifdir.join(fname), content).unwrap();
            }
        }
        dir
    }

    #[test]
    fn classifies_wireguard_by_uevent_devtype_regardless_of_name() {
        // A renamed WireGuard interface ("nginx0") is still caught via DEVTYPE.
        let d = fake_sysnet(&[(
            "nginx0",
            &[("uevent", "INTERFACE=nginx0\nDEVTYPE=wireguard\n")],
        )]);
        assert_eq!(
            classify_interface(d.path().to_str().unwrap(), "nginx0"),
            Some("wireguard")
        );
    }

    #[test]
    fn classifies_tun_by_tun_flags_presence() {
        let d = fake_sysnet(&[("tun0", &[("tun_flags", "0x1002")])]);
        assert_eq!(
            classify_interface(d.path().to_str().unwrap(), "tun0"),
            Some("tun")
        );
    }

    #[test]
    fn plain_interface_is_not_a_tunnel() {
        let d = fake_sysnet(&[("eth0", &[("uevent", "INTERFACE=eth0\n")])]);
        assert_eq!(classify_interface(d.path().to_str().unwrap(), "eth0"), None);
    }

    #[test]
    fn scan_returns_only_tunnel_interfaces() {
        let d = fake_sysnet(&[
            ("eth0", &[("uevent", "INTERFACE=eth0\n")]),
            ("lo", &[("uevent", "INTERFACE=lo\n")]),
            ("wg0", &[("uevent", "DEVTYPE=wireguard\n")]),
            ("tun0", &[("tun_flags", "0x1002")]),
        ]);
        let mut found: Vec<String> = scan_tunnel_interfaces(d.path().to_str().unwrap())
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        found.sort();
        assert_eq!(found, vec!["tun0".to_string(), "wg0".to_string()]);
    }

    #[test]
    fn event_carries_ifname_and_kind() {
        let ev = build_tunnel_event("h", Utc::now(), "wg0", "wireguard");
        assert_eq!(ev.kind, "network.tunnel_interface_created");
        assert_eq!(ev.details["ifname"], "wg0");
        assert_eq!(ev.details["iface_kind"], "wireguard");
        assert!(ev.tags.contains(&"persistence".to_string()));
    }
}
