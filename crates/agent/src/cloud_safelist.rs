//! Cloud provider IP safelist — IPs that should NOT be auto-blocked.
//!
//! Major cloud providers (Google Cloud, AWS, Cloudflare, Azure, Oracle) publish
//! their IP ranges. Attackers can use these, but auto-blocking them risks
//! blocking legitimate traffic (Googlebot, CDN, APIs).
//!
//! Policy: DETECT but DON'T AUTO-BLOCK. Let AI evaluate with context.
//! The AI can still decide to block if the evidence is strong enough.

use std::net::IpAddr;
use std::sync::OnceLock;
use tracing::info;

/// Parsed CIDR range for fast matching.
struct CidrRange {
    base: u32,
    mask: u32,
}

impl CidrRange {
    fn from_str(cidr: &str) -> Option<Self> {
        let (base_str, prefix_str) = cidr.split_once('/')?;
        let prefix_len: u32 = prefix_str.parse().ok()?;
        if prefix_len > 32 {
            return None;
        }
        let base: IpAddr = base_str.parse().ok()?;
        let base_u32 = match base {
            IpAddr::V4(v4) => u32::from(v4),
            _ => return None,
        };
        let shift = 32u32.saturating_sub(prefix_len);
        let mask = if shift >= 32 { 0u32 } else { !0u32 << shift };
        Some(Self {
            base: base_u32 & mask,
            mask,
        })
    }

    fn contains(&self, ip: u32) -> bool {
        (ip & self.mask) == self.base
    }
}

/// Cloud provider safelist — loaded once, checked on every auto-block decision.
static CLOUD_RANGES: OnceLock<Vec<CidrRange>> = OnceLock::new();
static CLOUD_PROVIDER_COUNT: OnceLock<usize> = OnceLock::new();

/// Wave 9 (AUDIT-WAVE9-CF-ATTRIBUTION): Cloudflare-only ranges,
/// pre-parsed for the per-event CF-edge check. The general
/// `CLOUD_RANGES` mixes CF, AWS, Azure, Telegram, Oracle peer ranges
/// — the CF-attribution gate must NOT trust a `CF-Connecting-IP`
/// header from an AWS or Telegram peer (they're not running CF
/// edge proxies). A separate static keeps the trust narrow and
/// audit-clear.
static CLOUDFLARE_EDGE_RANGES: OnceLock<Vec<CidrRange>> = OnceLock::new();

/// Local interface IPs of the host the agent runs on (eth0, bond0, etc.).
/// Populated at startup via `init_local_interface_ips()`. Traffic with
/// src_ip == one of these is the host itself talking to the outside world,
/// which in incidents like "Packet flood from 10.0.0.238" is the server's
/// own VPC IP misclassified as an attacker.
static LOCAL_INTERFACE_IPS: OnceLock<Vec<u32>> = OnceLock::new();

/// Operator-configured "your own infrastructure" ranges, loaded at startup
/// from `[allowlist] self_infra_ips` via `init_operator_self_infra()`. These
/// are OTHER boxes the operator runs (a sibling server, a CI runner) that the
/// feed-serving agent sees as a remote source. Treated as self-traffic so the
/// incidents are flagged `research_only` (kept for detection/training, hidden
/// from the operator + public feeds). EMPTY by default - nothing is hardcoded
/// into the product; every deployment lists only its own addresses.
static OPERATOR_SELF_INFRA: OnceLock<Vec<CidrRange>> = OnceLock::new();

/// Cloudflare IPv4 ranges (from https://www.cloudflare.com/ips-v4).
/// Updated 2026-04-01. These rarely change.
const CLOUDFLARE_RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
];

/// Agent-owned service endpoints — IPs the agent itself talks to for its
/// notification, enrichment, and threat-intel pipelines. Traffic to these
/// destinations is *self-traffic* and MUST NOT fire data-exfil / C2-beacon
/// style detectors in the operator view. Added after spec 015 surfaced the
/// self-detection pattern (see the dashboard flood on 2026-04-11 where the
/// agent was flagging its own Telegram calls as "Data Exfil → CRITICAL").
const AGENT_SERVICE_RANGES: &[&str] = &[
    // Telegram (Bot API + MTProto) — AS62041
    "149.154.160.0/20",
    "91.108.0.0/16",
    "91.108.4.0/22",
    "91.108.56.0/22",
    "95.161.64.0/20",
    // CrowdSec CAPI (cloud threat intelligence API) — hosted on AWS
    // eu-west-1. The local CrowdSec agent (pid crowdsec, uid 0) polls
    // these IPs for community blocklists and pushes local decisions.
    // Observed 2026-04-12: 6 AWS eu-west-1 IPs appearing as
    // "Cross-layer chain: Cryptominer Deployment Chain" because the
    // correlation engine saw crowdsec outbound + CPU spike = CL-014 FP.
    // CrowdSec uses an ELB that rotates across the /16, so we safelist
    // the ranges that the eu-west-1 ELBs live in.
    "52.48.0.0/14",  // AWS eu-west-1 ELB range (covers 52.48-51.x)
    "63.32.0.0/14",  // AWS eu-west-1 ELB range (covers 63.32-35.x)
    "18.200.0.0/14", // AWS eu-west-1 ELB range (covers 18.200-203.x)
    "3.248.0.0/13",  // AWS eu-west-1 ELB range (covers 3.248-255.x)
    // ip-api.com (GeoIP enrichment used by crate::geoip)
    "208.95.112.0/24",
    // Canonical / Ubuntu archive + snapcraft + livepatch.
    // 2026-05-08 (fix/repeat-offender-safelist-bypass): widened
    // 185.125.188.0/23 → /22 so it covers .190 + .191 too. Operator's
    // prod 2026-05-08 had `185.125.190.48` auto-blocked 7x by the
    // repeat-offender path because the /23 only covered .188 + .189.
    // Canonical's actual RIPE allocation is `185.125.188.0/22`.
    "185.125.188.0/22",
    "91.189.88.0/21",
    "162.213.32.0/22",
];

/// Oracle Cloud peer ranges not already covered by CLOUD_PROVIDER_RANGES.
/// These are the infrastructure peers of OCI instances (metadata, NTP,
/// internal DNS, OKE control plane, etc.) that an OCI-hosted agent will
/// regularly connect to. Keeping them separate from the main cloud list
/// makes it obvious *why* they're in the safelist — they're the agent's
/// own home provider, not some random customer workload.
const ORACLE_PEER_RANGES: &[&str] = &[
    "138.1.16.0/22",    // OCI peer range
    "140.91.0.0/16",    // OCI London peers
    "147.154.224.0/19", // OCI peer /19 — covers gomon (147.154.245.65) + other OCI infra
    "193.122.0.0/15",   // OCI EU-London
];

/// Link-local and cloud instance metadata ranges. Every major cloud uses
/// 169.254.169.254 for instance metadata (IMDS); Oracle, AWS, GCP, Azure
/// all share the convention. 169.254.0.0/16 is the IPv4 link-local range
/// (RFC 3927). Traffic to any of these is self-infrastructure by definition
/// — the operator never cares about "exfil to 169.254.169.254" or
/// "slowloris on metadata endpoint". Observed 2026-04-11 as
/// "Slow HTTP connection (possible slowloris)" FP fired by agent host
/// polling the OCI metadata service.
const LINK_LOCAL_RANGES: &[&str] = &[
    "169.254.0.0/16", // IPv4 link-local (RFC 3927), includes all IMDS endpoints
    "127.0.0.0/8",    // loopback — never operator-relevant as a remote dst
    "224.0.0.0/4",    // multicast
];

/// Major cloud provider CIDR ranges that should not be auto-blocked.
/// These are broad ranges — individual IPs may still be malicious,
/// but auto-blocking risks collateral damage.
const CLOUD_PROVIDER_RANGES: &[&str] = &[
    // Google Cloud Platform (major allocations)
    "34.0.0.0/9",      // 34.0-127.x — GCE
    "35.184.0.0/13",   // 35.184-191.x — GCE
    "35.192.0.0/12",   // 35.192-207.x — GCE
    "35.208.0.0/12",   // 35.208-223.x — GCE
    "35.224.0.0/12",   // 35.224-239.x — GCE
    "35.240.0.0/13",   // 35.240-247.x — GCE
    "130.211.0.0/16",  // GCE load balancers
    "142.250.0.0/15",  // Google services
    "172.217.0.0/16",  // Google services
    "216.58.192.0/19", // Google services
    "209.85.128.0/17", // Google mail/services
    // AWS (major allocations)
    "3.0.0.0/9",   // 3.0-127.x — EC2
    "13.0.0.0/8",  // 13.x — EC2 various
    "15.0.0.0/11", // 15.0-31.x — EC2
    "18.0.0.0/10", // 18.0-63.x — EC2
    // 2026-05-08 (fix/abuseipdb-telegram-honesty): operator's prod hit
    // an `Instant kill - AbuseIPDB reputation gate` Telegram alert on
    // 34.253.181.30 (Score 8/100, Amazon Technologies Inc., Ireland
    // eu-west-1). The gap: 34.0.0.0/9 above is GCP, AWS owns
    // 34.192.0.0/10 (covers 34.192-34.255 = eu-west-1, eu-west-2,
    // ap-northeast-1 EC2 + ELB) and we never listed it. So the
    // safelist let through every AWS IP starting with 34.128+,
    // and with `auto_block_threshold = 1` in agent.toml the
    // reputation gate auto-blocked any AWS IP with even a single
    // historical report. Source: AWS-published ip-ranges.json
    // (service=EC2, region=eu-west-1) — `34.240.0.0/13` and
    // `34.248.0.0/13` are explicit, this /10 covers both plus the
    // 34.192-239 chunks for ap-northeast-1/us-east-2.
    "34.192.0.0/10", // 34.192-255.x — EC2 (eu-west-1/2, ap-northeast-1, us-east-2)
    "44.192.0.0/11", // 44.192-223.x — EC2
    "52.0.0.0/11",   // 52.0-31.x — EC2
    "54.0.0.0/8",    // 54.x — EC2
    "99.80.0.0/12",  // 99.80-95.x — EC2
    // Azure (major allocations)
    "20.0.0.0/11",    // 20.0-31.x — Azure
    "40.64.0.0/10",   // 40.64-127.x — Azure
    "52.128.0.0/10",  // 52.128-191.x — Azure
    "104.40.0.0/13",  // 104.40-47.x — Azure
    "168.61.0.0/16",  // Azure
    "191.232.0.0/13", // Azure
    // Oracle Cloud
    "129.146.0.0/16", // OCI
    "130.35.0.0/16",  // OCI
    "130.61.0.0/16",  // OCI
    "132.145.0.0/16", // OCI
    "134.70.0.0/16",  // OCI
    "140.204.0.0/16", // OCI
    "140.238.0.0/16", // OCI
    "144.24.0.0/14",  // OCI
    "150.136.0.0/13", // OCI
    "152.67.0.0/16",  // OCI
    "152.70.0.0/15",  // OCI
    // DigitalOcean
    "64.227.0.0/16",
    "134.209.0.0/16",
    "157.230.0.0/16",
    "159.65.0.0/16",
    "159.89.0.0/16",
    "161.35.0.0/16",
    "164.90.0.0/16",
    "165.22.0.0/16",
    "165.227.0.0/16",
    "167.71.0.0/16",
    "167.172.0.0/16",
    "174.138.0.0/16",
    "178.128.0.0/16",
    "188.166.0.0/16",
    "206.189.0.0/16",
    "209.97.0.0/16",
    "209.122.0.0/16",
    // Hetzner
    "49.12.0.0/14",
    "78.46.0.0/15",
    "88.198.0.0/16",
    "88.99.0.0/16",
    "95.216.0.0/15",
    "116.202.0.0/15",
    "116.203.0.0/16",
    "128.140.0.0/16",
    "135.181.0.0/16",
    "136.243.0.0/16",
    "138.201.0.0/16",
    "142.132.0.0/16",
    "148.251.0.0/16",
    "157.90.0.0/16",
    "159.69.0.0/16",
    "162.55.0.0/16",
    "167.235.0.0/16",
    "168.119.0.0/16",
    "176.9.0.0/16",
    "178.63.0.0/16",
    "195.201.0.0/16",
    "213.133.96.0/19",
    "213.239.192.0/18",
    // Akamai (CDN edge — major allocations covering ~95% of edge
    // traffic). Source: Akamai-published origin-IP ACL guidance plus
    // public ARIN allocations to AS20940 / AS16625. Operator's
    // 2026-05-06 question: "se fosse Akamai funcionaria também?" —
    // adding here so a customer fronted by Akamai produces the same
    // CDN-noise suppression CF / AWS get.
    "23.0.0.0/12",  // 23.0-15.x
    "23.32.0.0/11", // 23.32-63.x
    "23.64.0.0/14", // 23.64-67.x
    "23.72.0.0/13", // 23.72-79.x
    "95.100.64.0/18",
    "96.6.0.0/15",
    "96.16.0.0/15",
    "104.64.0.0/10", // 104.64-127.x — large Akamai allocation
    "184.24.0.0/13", // 184.24-31.x
    "184.50.0.0/15",
    // Fastly (CDN edge — official public-IP-list endpoint
    // https://api.fastly.com/public-ip-list, 2026-04 snapshot).
    "23.235.32.0/20",
    "43.249.72.0/22",
    "103.244.50.0/24",
    "103.245.222.0/23",
    "103.245.224.0/24",
    "104.156.80.0/20",
    "140.248.64.0/18",
    "140.248.128.0/17",
    "146.75.0.0/17",
    "151.101.0.0/16",
    "157.52.64.0/18",
    "167.82.0.0/17",
    "172.111.64.0/18",
    "185.31.16.0/22",
    "199.27.72.0/21",
    "199.232.0.0/16",
    // CloudFront (AWS CDN). Most CloudFront prefixes overlap the
    // broader AWS ranges already in this list; these are the
    // CloudFront-specific blocks that fall OUTSIDE the standard AWS
    // 3/13/15/18/44/52/54/99 allocations. Source: AWS-published
    // ip-ranges.json filtered by service=CLOUDFRONT.
    "64.252.64.0/18",
    "64.252.128.0/18",
    "130.176.0.0/16", // covers all 130.176.x CloudFront blocks
    "143.204.0.0/16",
    "144.220.0.0/16",
    "205.251.192.0/19", // covers 192-223 (rest of /16 is too broad)
    "216.137.32.0/19",
];

/// Initialize the cloud safelist. Call once at agent startup.
pub fn init() {
    let mut ranges = Vec::new();

    for cidr in CLOUDFLARE_RANGES
        .iter()
        .chain(CLOUD_PROVIDER_RANGES.iter())
        .chain(AGENT_SERVICE_RANGES.iter())
        .chain(ORACLE_PEER_RANGES.iter())
        .chain(LINK_LOCAL_RANGES.iter())
    {
        if let Some(r) = CidrRange::from_str(cidr) {
            ranges.push(r);
        }
    }

    let count = ranges.len();
    let _ = CLOUD_RANGES.set(ranges);
    let _ = CLOUD_PROVIDER_COUNT.set(count);
    info!(ranges = count, "Cloud provider safelist loaded");

    // Wave 9: parse CF-only ranges into a separate static so the
    // per-event CF-edge check is O(N_cf) instead of walking every
    // cloud-provider range (CF + AWS + Telegram + Oracle).
    let cf_ranges: Vec<CidrRange> = CLOUDFLARE_RANGES
        .iter()
        .filter_map(|c| CidrRange::from_str(c))
        .collect();
    info!(
        cf_ranges = cf_ranges.len(),
        "Cloudflare edge ranges loaded for CF-attribution"
    );
    let _ = CLOUDFLARE_EDGE_RANGES.set(cf_ranges);

    // Best-effort: read the host's own IPv4 interface addresses so
    // incidents with src/dst == own IP can be recognized as self-traffic.
    // Falls back to an empty list if /proc/net/fib_trie is unreadable;
    // that just means the own-IP detection is a no-op, not a crash.
    init_local_interface_ips();
}

/// Populate `LOCAL_INTERFACE_IPS` from `/proc/net/fib_trie`. This file
/// exposes every locally-bound IPv4 address (loopback, eth0, docker0, etc.)
/// as `|-- <ip>` lines followed by `/32 host LOCAL`. Parsing is deliberately
/// forgiving — any unexpected format just yields an empty list.
fn init_local_interface_ips() {
    let content = match std::fs::read_to_string("/proc/net/fib_trie") {
        Ok(c) => c,
        Err(_) => {
            let _ = LOCAL_INTERFACE_IPS.set(Vec::new());
            return;
        }
    };

    let mut ips: Vec<u32> = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        // Each local address appears as "|-- <ip>" with the next non-empty
        // line containing "/32 host LOCAL". We accept any line whose next
        // line mentions "host LOCAL" — the routing table can tag as
        // "host BROADCAST" or "host LINK" too, which we ignore.
        if let Some(rest) = trimmed.strip_prefix("|-- ") {
            if let Some(next) = lines.get(i + 1) {
                if next.contains("host LOCAL") {
                    if let Ok(std::net::IpAddr::V4(v4)) = rest.trim().parse::<IpAddr>() {
                        ips.push(u32::from(v4));
                    }
                }
            }
        }
    }

    ips.sort_unstable();
    ips.dedup();
    let n = ips.len();
    let _ = LOCAL_INTERFACE_IPS.set(ips);
    info!(
        local_ips = n,
        "Local interface IPs loaded for self-traffic detection"
    );
}

/// Returns true if the IP should be treated as *self-traffic* — either a
/// known cloud provider, the agent's own notification / enrichment
/// endpoints (Telegram, GeoIP), the OCI peer ranges of the host the
/// agent runs on, link-local / metadata IPs, OR one of the host's own
/// IPv4 interface addresses.
///
/// Callers that generate operator-facing incidents should use this to
/// flag the incident as `research_only` instead of surfacing it in the
/// threats feed.
pub fn is_self_traffic_ip(ip_str: &str) -> bool {
    is_cloud_provider_ip(ip_str)
        || is_local_interface_ip(ip_str)
        || is_operator_self_infra_ip(ip_str)
}

/// Load the operator's own-infrastructure ranges from config
/// (`[allowlist] self_infra_ips`). Idempotent (first call wins, like the
/// other `OnceLock` loaders). Bare IPs are treated as `/32`. Invalid entries
/// are skipped with a warning so one typo never silences the whole list.
/// Empty input is valid and the common case (nothing hardcoded in-product).
pub fn init_operator_self_infra(entries: &[String]) {
    let ranges = build_self_infra_ranges(entries);
    let n = ranges.len();
    let _ = OPERATOR_SELF_INFRA.set(ranges);
    if n > 0 {
        info!(
            self_infra_ranges = n,
            "Operator self-infrastructure ranges loaded (hidden from feeds, still detected)"
        );
    }
}

/// Pure parse of the config entries into ranges. A bare IP is `/32`; an empty
/// entry is dropped; an invalid one is skipped with a warning (not fatal).
/// Extracted from `init_operator_self_infra` so it is testable without touching
/// the process-global `OPERATOR_SELF_INFRA` (which would poison parallel tests
/// that share the `is_self_traffic_ip` gate).
fn build_self_infra_ranges(entries: &[String]) -> Vec<CidrRange> {
    entries
        .iter()
        .filter_map(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return None;
            }
            let normalized = if trimmed.contains('/') {
                trimmed.to_string()
            } else {
                format!("{trimmed}/32")
            };
            match CidrRange::from_str(&normalized) {
                Some(r) => Some(r),
                None => {
                    tracing::warn!(entry = %raw, "self_infra_ips: skipping invalid IP/CIDR");
                    None
                }
            }
        })
        .collect()
}

/// Pure membership test against a parsed range list. Non-IPv4 input is false.
fn ip_in_ranges(ranges: &[CidrRange], ip_str: &str) -> bool {
    let Ok(IpAddr::V4(v4)) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    let ip = u32::from(v4);
    ranges.iter().any(|r| r.contains(ip))
}

/// True if `ip_str` is in the operator-configured own-infrastructure list.
/// Returns false when the list is unset/empty (the default).
pub fn is_operator_self_infra_ip(ip_str: &str) -> bool {
    OPERATOR_SELF_INFRA
        .get()
        .is_some_and(|ranges| ip_in_ranges(ranges, ip_str))
}

/// Number of local interface IPs loaded (for boot self-test).
pub fn local_ip_count() -> usize {
    LOCAL_INTERFACE_IPS.get().map_or(0, |v| v.len())
}

/// Number of cloud IP ranges loaded (for boot self-test).
pub fn cloud_range_count() -> usize {
    CLOUD_RANGES.get().map_or(0, |v| v.len())
}

/// Returns true if `ip_str` is one of the host's own locally-bound IPv4
/// addresses (populated at startup from `/proc/net/fib_trie`). This
/// catches the case where a sensor detector emits an incident whose
/// only IP entity is the server's own VPC/eth0 address — observed
/// 2026-04-11 as "Packet flood → 10.0.0.238" and "Slow HTTP from
/// 10.0.0.238 → 169.254.169.254" FPs. Returns false if the local-IP
/// list could not be loaded (best-effort).
pub fn is_local_interface_ip(ip_str: &str) -> bool {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    let ip_u32 = match ip {
        IpAddr::V4(v4) => u32::from(v4),
        _ => return false,
    };
    match LOCAL_INTERFACE_IPS.get() {
        Some(list) => list.binary_search(&ip_u32).is_ok(),
        None => false,
    }
}

/// Returns true if `comm` is the agent itself or one of its spawned
/// workers. Matches the graph detector convention (`detect_network_sniffing`)
/// used in spec 015.
#[allow(dead_code)] // reserved for future process-side self-filter unification
pub fn is_agent_process(comm: &str) -> bool {
    matches!(
        comm,
        "innerwarden-agent"
            | "innerwarden-sensor"
            | "innerwarden-watchdog"
            | "tokio-rt-worker"
            | "openclaw-gatewa"
            | "crowdsec"
            | "gomon"
    )
}

/// Check if an IP belongs to a known cloud provider.
/// Wave 9 (AUDIT-WAVE9-CF-ATTRIBUTION): true when `ip_str` is a
/// Cloudflare edge IP (one of the published CF CIDR ranges).
///
/// This is the trust gate for honouring the `CF-Connecting-IP`
/// header during ingest: only requests whose **socket peer** is a
/// Cloudflare edge can have their attribution rewritten. A non-CF
/// peer setting `CF-Connecting-IP: 1.2.3.4` is spoofing — the
/// attacker controls the header but not the routing.
///
/// Pre-Wave-9 the agent had `is_cloud_provider_ip` (CF + AWS +
/// Telegram + Oracle), which was too broad for this gate — an AWS
/// peer is not running a CF edge.
pub fn is_cloudflare_edge_ip(ip_str: &str) -> bool {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    let ip_u32 = match ip {
        IpAddr::V4(v4) => u32::from(v4),
        // IPv6 not yet supported by the parsed CIDR cache (CF
        // publishes IPv6 ranges too — TODO if prod ever needs it).
        _ => return false,
    };
    if let Some(ranges) = CLOUDFLARE_EDGE_RANGES.get() {
        ranges.iter().any(|r| r.contains(ip_u32))
    } else {
        // `init()` not called yet — fail closed (no rewrite).
        // Production calls `init()` before any event is ingested.
        false
    }
}

/// Returns true if the IP should NOT be auto-blocked.
/// CIDR-accurate label for IPs the agent must NEVER auto-block.
///
/// Returns:
/// - `Some(provider_label)` when the IP falls in any safelisted CIDR
///   (`CLOUDFLARE_RANGES`, `CLOUD_PROVIDER_RANGES`, `AGENT_SERVICE_RANGES`,
///   `ORACLE_PEER_RANGES`, `LINK_LOCAL_RANGES`). The label is best-effort:
///   it favours the granular `identify_provider` heuristic when that
///   heuristic agrees with the CIDR walk, and falls back to a generic
///   "Cloud Safelist" / "Agent Service" / "Link-local" tag otherwise.
/// - `None` when the IP is not in any safelist.
///
/// 2026-05-08 (fix/repeat-offender-safelist-bypass): operator's prod
/// audit found `208.95.112.1` (ip-api.com — the agent's OWN GeoIP
/// service), `91.189.91.{102,104}` (Canonical Ubuntu archive), and
/// `199.232.58.137` (Fastly) auto-blocked dozens of times each by
/// the repeat-offender path. Root cause: both
/// `decision_block_ip::execute_block_ip_decision` and
/// `correlation_response::check_repeat_offenders` were gating on
/// `identify_provider` — the FIRST-OCTET HEURISTIC, not the CIDR
/// walk. First-octet 208 / 91 / 199 are not in the heuristic's
/// match arms, so the gate returned None and the block proceeded
/// even though `is_cloud_provider_ip` (the CIDR walker that powers
/// `CLOUD_RANGES`) would have returned `true`.
///
/// This helper is the canonical gate predicate. Callers that need
/// just the boolean keep using `is_cloud_provider_ip`; callers that
/// need a label for the audit log + the gate together use this.
pub fn safelist_label(ip_str: &str) -> Option<&'static str> {
    if !is_cloud_provider_ip(ip_str) {
        return None;
    }
    // Prefer the granular heuristic label when it agrees that the IP
    // is provider-tagged. For first octets the heuristic doesn't cover
    // (208 / 91 / 199 / etc) the CIDR walk above already proved
    // safelisted, so fall back to a generic "Cloud Safelist" label.
    identify_provider(ip_str).or(Some("Cloud Safelist"))
}

pub fn is_cloud_provider_ip(ip_str: &str) -> bool {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    let ip_u32 = match ip {
        IpAddr::V4(v4) => u32::from(v4),
        _ => return false,
    };

    if let Some(ranges) = CLOUD_RANGES.get() {
        ranges.iter().any(|r| r.contains(ip_u32))
    } else {
        false
    }
}

/// Get the provider name for logging (best-effort, broad match).
pub fn identify_provider(ip_str: &str) -> Option<&'static str> {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return None;
    };
    let (ip_u32, octets) = match ip {
        IpAddr::V4(v4) => (u32::from(v4), v4.octets()),
        _ => return None,
    };
    let first_octet = octets[0];
    let second_octet = octets[1];

    // Authoritative Cloudflare-first check. The first-octet heuristic below
    // misclassifies large Cloudflare blocks (104.16.0.0/13, 104.24.0.0/14,
    // 172.64.0.0/13) as Azure / Google because 104 and 172 are shared with
    // other providers. Operator incident 2026-04-18 showed top auto-blocked
    // IPs were all Cloudflare ranges (104.26.x, 172.66.x, 172.67.x). Walking
    // CLOUDFLARE_RANGES keeps the guard correct regardless of heuristic drift.
    for cidr in CLOUDFLARE_RANGES {
        if let Some(r) = CidrRange::from_str(cidr) {
            if r.contains(ip_u32) {
                return Some("Cloudflare");
            }
        }
    }

    // Broad heuristic based on first octet for the other providers (still
    // fine-grained enough for operator-facing labels, and any false label
    // is harmless — the block is refused either way).
    //
    // 2026-05-06 (operator question "Akamai também?"): added Akamai,
    // Fastly, CloudFront-specific labels. First-octet 23 is shared
    // between Akamai (most of /11) and Cloudflare (no — wait, actually
    // 23 is mostly Akamai). 151 is overwhelmingly Fastly. 64 / 130 /
    // 143 / 144 / 216 are added for CloudFront edges that don't fall
    // in the standard AWS allocations.
    //
    // 2026-05-08 (fix/abuseipdb-telegram-honesty): the 34.x first-octet
    // is split between GCP (34.0-127) and AWS (34.128-255 — eu-west-1/2,
    // ap-northeast-1, us-east-2 EC2 + ELB). Pre-fix the operator's
    // alert about 34.253.181.30 (AWS Ireland, Score 8/100) showed
    // "Amazon Technologies Inc." in the WHOIS panel but every safelist
    // log line tagged the IP "Google Cloud", which made the warning
    // even more confusing.
    match first_octet {
        23 | 96 | 184 => Some("Akamai"),
        151 => Some("Fastly"),
        64 | 130 | 143 | 144 => Some("CloudFront"),
        34 => {
            if second_octet < 128 {
                Some("Google Cloud")
            } else {
                Some("AWS")
            }
        }
        35 | 142 | 172 | 209 => Some("Google Cloud"),
        3 | 13 | 15 | 18 | 44 | 52 | 54 | 99 => Some("AWS"),
        20 | 40 | 168 | 191 => Some("Azure"),
        129 | 132 | 134 | 140 | 150 | 152 => Some("Oracle Cloud"),
        157 | 159 | 161 | 164 | 165 | 167 | 174 | 178 | 188 | 206 => Some("DigitalOcean"),
        173 | 108 | 190 | 162 | 141 | 197 | 198 | 216 => Some("Cloudflare"),
        49 | 78 | 88 | 95 | 116 | 128 | 135 | 136 | 138 | 148 | 176 | 195 | 213 => Some("Hetzner"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_detected() {
        init();
        assert!(is_cloud_provider_ip("104.16.0.1"));
        assert!(is_cloud_provider_ip("172.64.1.1"));
        assert!(is_cloud_provider_ip("104.23.217.2"));
    }

    #[test]
    fn google_detected() {
        init();
        assert!(is_cloud_provider_ip("34.95.197.36"));
        assert!(is_cloud_provider_ip("35.200.190.223"));
        assert!(is_cloud_provider_ip("142.250.1.1"));
    }

    #[test]
    fn aws_detected() {
        init();
        assert!(is_cloud_provider_ip("3.5.1.1"));
        assert!(is_cloud_provider_ip("52.1.1.1"));
        assert!(is_cloud_provider_ip("54.200.1.1"));
    }

    #[test]
    fn regression_guard_production_cloudflare_ips_get_identified() {
        // Operator incident 2026-04-18: correlation:CL-008 +
        // repeat-offender auto-blocked these IPs in production (top by
        // block count: 53, 49, 46, 45, 41, ...). All are Cloudflare. If
        // the safelist ever stops covering any of them the cascade comes
        // right back — fail loud here before it can leak into a release.
        init();
        for cloudflare_ip in [
            "104.26.12.38",
            "172.66.0.243",
            "162.159.140.245",
            "104.19.192.29",
            "172.67.70.74",
            "104.26.13.38",
            "104.19.192.176",
            "104.19.192.174",
            "104.19.193.29",
        ] {
            assert!(
                is_cloud_provider_ip(cloudflare_ip),
                "{cloudflare_ip} (Cloudflare) must be in the safelist"
            );
            assert_eq!(
                identify_provider(cloudflare_ip),
                Some("Cloudflare"),
                "{cloudflare_ip} must resolve to provider=Cloudflare"
            );
        }
    }

    /// 2026-05-08 anchor (fix/abuseipdb-telegram-honesty): the
    /// AWS allocation `34.192.0.0/10` (eu-west-1, eu-west-2,
    /// ap-northeast-1, us-east-2) was missing from
    /// `CLOUD_PROVIDER_RANGES`, so AWS Ireland IPs starting with
    /// 34.x leaked through `is_cloud_provider_ip` returning false
    /// and reached the AbuseIPDB autoblock gate — exactly the
    /// shape that produced the operator's prod alert about
    /// 34.253.181.30 (Score 8/100 + Amazon Technologies Inc.). The
    /// anchor uses the actual prod IP plus the boundary endpoints
    /// of the new CIDR so a future "tighten allocations" refactor
    /// can't silently re-open the gap.
    #[test]
    fn aws_eu_west_1_range_is_in_safelist() {
        init();
        // The exact prod IP from the 2026-05-07 alert.
        assert!(
            is_cloud_provider_ip("34.253.181.30"),
            "34.253.181.30 (AWS Ireland eu-west-1, the prod IP that \
             triggered this fix) must be in the safelist"
        );
        // Boundary endpoints of 34.192.0.0/10.
        assert!(
            is_cloud_provider_ip("34.192.0.0"),
            "34.192.0.0 (low end of AWS 34.192/10) must be in the safelist"
        );
        assert!(
            is_cloud_provider_ip("34.255.255.255"),
            "34.255.255.255 (high end of AWS 34.192/10) must be in the safelist"
        );
        // GCP 34.0.0.0/9 must still match — that range was already
        // in the safelist and this PR must not regress it.
        assert!(
            is_cloud_provider_ip("34.95.197.36"),
            "34.95.197.36 (GCP) must remain in the safelist"
        );
    }

    /// 2026-05-08 anchor (fix/repeat-offender-safelist-bypass): the
    /// exact prod-audit IPs that were blocked dozens of times each
    /// because the gate predicate used the first-octet heuristic
    /// instead of the CIDR walk. `safelist_label` is the canonical
    /// gate predicate — it walks `CLOUD_RANGES` (which includes
    /// `AGENT_SERVICE_RANGES`) and falls back to the heuristic only
    /// when the CIDR walk already proved safelisted.
    ///
    /// Pin the four IPs the operator's prod was wrongly blocking:
    ///   - 208.95.112.1 (ip-api.com — the agent's OWN GeoIP service,
    ///     blocked 37x in prod)
    ///   - 91.189.91.102 (Canonical Ubuntu archive, blocked 6x)
    ///   - 199.232.58.137 (Fastly CDN, blocked 7x)
    ///   - 185.125.190.48 (Canonical livepatch, blocked 7x — this
    ///     also pinned the AGENT_SERVICE_RANGES /23 → /22 widening)
    #[test]
    fn safelist_label_returns_some_for_prod_audit_ips_that_were_wrongly_blocked() {
        init();
        // ip-api.com — first octet 208 not in heuristic, but
        // 208.95.112.0/24 is in AGENT_SERVICE_RANGES.
        assert!(
            safelist_label("208.95.112.1").is_some(),
            "208.95.112.1 (ip-api.com — agent's own GeoIP) MUST be safelisted"
        );
        // Canonical Ubuntu archive — first octet 91 not in heuristic,
        // but 91.189.88.0/21 is in AGENT_SERVICE_RANGES.
        assert!(
            safelist_label("91.189.91.102").is_some(),
            "91.189.91.102 (Canonical archive) MUST be safelisted"
        );
        // Fastly — first octet 199 not in heuristic, but
        // 199.232.0.0/16 is in CLOUD_PROVIDER_RANGES.
        assert!(
            safelist_label("199.232.58.137").is_some(),
            "199.232.58.137 (Fastly) MUST be safelisted"
        );
        // Canonical livepatch — was outside the /23, now in the /22.
        // This anchors the AGENT_SERVICE_RANGES widening.
        assert!(
            safelist_label("185.125.190.48").is_some(),
            "185.125.190.48 (Canonical livepatch) MUST be safelisted \
             (anchors the /23 → /22 widening)"
        );
        assert!(
            safelist_label("185.125.191.255").is_some(),
            "185.125.191.255 (top of Canonical /22) MUST be safelisted"
        );
    }

    /// Mirror anchor: a real-attacker IP outside any safelist range
    /// must return `None` from `safelist_label`. Pins the cheap-exit
    /// contract so the new gate doesn't accidentally tag everything.
    #[test]
    fn safelist_label_returns_none_for_real_attacker_ips() {
        init();
        // TEST-NET-3 (RFC 5737) — never on a CDN, never in any safelist.
        assert!(safelist_label("203.0.113.42").is_none());
        // Random unassigned-to-major-cloud space.
        assert!(safelist_label("1.2.3.4").is_none());
    }

    /// Mirror anchor: `identify_provider` for the same prod IP must
    /// label it "AWS", not "Google Cloud" (the pre-fix first-octet
    /// heuristic blanket-tagged 34.x as Google). Operator-honesty:
    /// the journal log line that says "skipped: ip belongs to AWS"
    /// has to match the WHOIS panel the operator sees in the same
    /// dashboard, otherwise the suppression looks wrong even when
    /// it is correct.
    #[test]
    fn aws_eu_west_1_identifies_as_aws_not_google() {
        // Below the 34.128 boundary: GCP. Above: AWS.
        assert_eq!(identify_provider("34.95.197.36"), Some("Google Cloud"));
        assert_eq!(identify_provider("34.127.255.255"), Some("Google Cloud"));
        assert_eq!(identify_provider("34.128.0.0"), Some("AWS"));
        assert_eq!(
            identify_provider("34.253.181.30"),
            Some("AWS"),
            "34.253.181.30 (the prod alert IP) must label as AWS"
        );
        assert_eq!(identify_provider("34.255.255.255"), Some("AWS"));
    }

    #[test]
    fn random_ip_not_cloud() {
        init();
        assert!(!is_cloud_provider_ip("93.152.217.51")); // real attacker
        assert!(!is_cloud_provider_ip("1.2.3.4"));
        assert!(!is_cloud_provider_ip("185.143.223.100"));
    }

    #[test]
    fn provider_identified() {
        assert_eq!(identify_provider("34.95.197.36"), Some("Google Cloud"));
        assert_eq!(identify_provider("52.1.1.1"), Some("AWS"));
        assert_eq!(identify_provider("20.12.41.6"), Some("Azure"));
    }

    #[test]
    fn telegram_detected() {
        // Spec 015 follow-up: Telegram Bot API must be recognized as
        // self-traffic. Without this, 222+ false positives per day from
        // the agent's own notification channel (149.154.166.110:443).
        init();
        assert!(is_self_traffic_ip("149.154.160.1"));
        assert!(is_self_traffic_ip("149.154.166.110"));
        assert!(is_self_traffic_ip("149.154.175.255"));
        assert!(is_self_traffic_ip("91.108.4.200"));
    }

    #[test]
    fn ip_api_com_detected() {
        // GeoIP enrichment endpoint used by crate::geoip.
        init();
        assert!(is_self_traffic_ip("208.95.112.1"));
    }

    #[test]
    fn canonical_detected() {
        // Ubuntu apt archive + snapcraft + livepatch.
        init();
        assert!(is_self_traffic_ip("185.125.188.58"));
        assert!(is_self_traffic_ip("91.189.88.1"));
    }

    #[test]
    fn operator_self_infra_parse_and_match_pure() {
        // Pure helpers, so this does NOT set the process-global
        // OPERATOR_SELF_INFRA. Setting it would poison parallel tests that use
        // TEST-NET IPs as fake attackers and share the is_self_traffic_ip gate
        // (that is exactly what an earlier version of this test did). A bare IP
        // is /32, a CIDR matches its block, an empty/typo entry is skipped.
        let ranges = build_self_infra_ranges(&[
            "203.0.113.34".to_string(),
            "203.0.113.64/26".to_string(),
            "  ".to_string(),
            "definitely-not-an-ip".to_string(),
        ]);
        assert_eq!(ranges.len(), 2, "valid entries kept, blank + typo dropped");
        assert!(ip_in_ranges(&ranges, "203.0.113.34"), "exact /32 own box");
        assert!(ip_in_ranges(&ranges, "203.0.113.99"), "inside the /26");
        assert!(!ip_in_ranges(&ranges, "203.0.113.10"), "outside the /26");
        // A real external attacker, in no list, never matches.
        assert!(!ip_in_ranges(&ranges, "198.51.100.7"));
        // Non-IPv4 input is safely false, never a panic.
        assert!(!ip_in_ranges(&ranges, "not-an-ip"));
    }

    #[test]
    fn operator_self_infra_empty_config_adds_nothing() {
        // The default/empty config is the only init we exercise in tests:
        // setting the global to an EMPTY list is safe (it can never make another
        // test's IP self-traffic), unlike loading real ranges which would poison
        // the shared is_self_traffic_ip gate. Covers init + the Some(empty) arm.
        init_operator_self_infra(&[]);
        assert!(!is_operator_self_infra_ip("198.51.100.42"));
        assert!(!is_self_traffic_ip("198.51.100.42"));
    }

    #[test]
    fn oracle_peer_range_detected() {
        // OCI London peer ranges outside the main CLOUD_PROVIDER_RANGES
        // list. These are the /20 the server peers with on its internal
        // network, not random Oracle customer IPs.
        init();
        assert!(is_self_traffic_ip("147.154.225.94"));
        assert!(is_self_traffic_ip("138.1.16.172"));
        assert!(is_self_traffic_ip("140.91.26.100"));
    }

    #[test]
    fn real_attacker_still_detected() {
        // Safety net: random external IPs that are NOT cloud providers or
        // agent services must still be reported to the operator.
        init();
        assert!(!is_self_traffic_ip("147.185.132.13")); // dashboard shows this as an attacker
        assert!(!is_self_traffic_ip("198.235.24.154"));
        assert!(!is_self_traffic_ip("185.113.139.51"));
    }

    #[test]
    fn agent_process_recognition() {
        assert!(is_agent_process("innerwarden-agent"));
        assert!(is_agent_process("innerwarden-sensor"));
        assert!(is_agent_process("tokio-rt-worker"));
        assert!(is_agent_process("openclaw-gatewa"));
        assert!(!is_agent_process("sshd"));
        assert!(!is_agent_process("bash"));
    }

    // ── CDN coverage anchors (operator question 2026-05-06) ────────────
    //
    // Operator asked: "se fosse Akamai funcionaria também?". Pre-fix
    // ONLY Cloudflare + AWS + Azure + GCP + OCI + DO + Hetzner were
    // covered; Akamai, Fastly, and CloudFront-specific edge IPs would
    // have escaped both `is_cloud_provider_ip` (used by the CDN-noise
    // suppression added in PR #475) AND `identify_provider` (used by
    // operator-facing block-decision labels). These anchors pin the
    // new coverage so a future "let's prune CIDRs to save memory"
    // refactor cannot silently regress.

    #[test]
    fn akamai_edge_detected() {
        init();
        // Major Akamai allocations
        assert!(is_cloud_provider_ip("23.0.0.1"), "23.0.0.0/12 (Akamai)");
        assert!(is_cloud_provider_ip("23.40.50.60"), "23.32.0.0/11 (Akamai)");
        assert!(
            is_cloud_provider_ip("104.96.10.20"),
            "104.64.0.0/10 (Akamai)"
        );
        assert!(
            is_cloud_provider_ip("184.25.10.20"),
            "184.24.0.0/13 (Akamai)"
        );
        // identify_provider labels them
        assert_eq!(identify_provider("23.0.0.1"), Some("Akamai"));
        assert_eq!(identify_provider("96.7.10.20"), Some("Akamai"));
    }

    #[test]
    fn fastly_edge_detected() {
        init();
        assert!(
            is_cloud_provider_ip("151.101.1.1"),
            "151.101.0.0/16 (Fastly)"
        );
        assert!(
            is_cloud_provider_ip("199.232.10.20"),
            "199.232.0.0/16 (Fastly)"
        );
        assert!(
            is_cloud_provider_ip("146.75.10.20"),
            "146.75.0.0/17 (Fastly)"
        );
        assert_eq!(identify_provider("151.101.1.1"), Some("Fastly"));
    }

    #[test]
    fn cloudfront_specific_edge_detected() {
        init();
        // CloudFront prefixes that fall OUTSIDE the standard AWS
        // 3/13/15/18/44/52/54/99 allocations — these would have
        // escaped pre-fix.
        assert!(is_cloud_provider_ip("64.252.65.1"), "64.252.64.0/18");
        assert!(is_cloud_provider_ip("130.176.10.20"), "130.176.0.0/16");
        assert!(is_cloud_provider_ip("143.204.10.20"), "143.204.0.0/16");
        assert!(is_cloud_provider_ip("144.220.10.20"), "144.220.0.0/16");
        assert_eq!(identify_provider("64.252.65.1"), Some("CloudFront"));
    }

    #[test]
    fn cdn_coverage_does_not_widen_to_real_attackers() {
        // Anti-regression bound: TEST-NET-3 (RFC 5737) and other
        // explicitly-allocated non-CDN ranges MUST still be detected
        // as non-cloud (i.e. real attacker territory). Pre-fix the
        // first-octet heuristic handled this; the anti-regression
        // anchor is to make sure adding CDN entries didn't accidentally
        // widen the safelist to swallow real attacker ranges.
        init();
        assert!(!is_cloud_provider_ip("203.0.113.1"), "TEST-NET-3");
        assert!(!is_cloud_provider_ip("198.51.100.1"), "TEST-NET-2");
        assert!(!is_cloud_provider_ip("192.0.2.1"), "TEST-NET-1");
        // Random APNIC + RIPE allocations that are NOT CDN
        assert!(!is_cloud_provider_ip("1.2.3.4"));
        assert!(!is_cloud_provider_ip("210.50.50.50"));
    }
}
