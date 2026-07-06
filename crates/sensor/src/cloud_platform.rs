//! Non-IP cloud-platform awareness for false-positive suppression.
//!
//! A cloud VM's OWN management agents (Azure WALinuxAgent, AWS SSM agent /
//! cloud-init, GCP guest agent, OCI cloud agent) generate high-volume, periodic
//! management traffic to the platform's control plane (WireServer, IMDS, the
//! platform DNS resolver). To the generic detectors this looks like C2
//! beaconing, connection floods, and IMDS-by-an-unexpected-process - and on
//! Azure it even fed a cross-layer correlation that auto-blocked the platform's
//! WireServer IP, which can sever the VM from its management plane.
//!
//! # Why this is NOT an IP allowlist
//!
//! Platform IPs change and an IP allowlist is a blunt, evadable instrument. This
//! module never trusts an IP. It recognises the platform's agents by their
//! **process identity**, proven from NON-FORGEABLE `/proc` facts:
//!
//!   * which cloud we are on, from SMBIOS/DMI (`/sys/class/dmi/id/*`) - strings
//!     the firmware sets, not anything a userspace attacker can change;
//!   * the agent's real executable (`/proc/<pid>/exe`, the kernel symlink) being
//!     a known compiled agent binary; OR
//!   * a trusted interpreter (`python3` under a system path) whose **script
//!     argument** is a known agent path that actually exists on disk as a
//!     root-owned file under a trusted system directory (so `argv` spoofing a
//!     fake `/usr/sbin/waagent` string does not earn trust - the file must be
//!     real and root-owned, which already implies root).
//!
//! Extension-handler children (e.g. `python3 .../WALinuxAgent...egg`, launched
//! by `waagent` with a *relative* script path) are recognised by walking a few
//! hops up the parent lineage to the real agent.
//!
//! # Downgrade-only contract (anti-evasion)
//!
//! Callers use [`is_guest_agent`] to suppress FP-prone *heuristics* (beaconing /
//! flood / IMDS-by-unexpected-process) for the platform's own agents. It is NOT
//! a blanket free pass: SPECIFIC strong signals (a known-bad threat-intel
//! destination, a real credential-path read, an explicit exploit primitive)
//! must keep firing regardless. The predicate also requires the actor to be
//! `uid 0` and the host to be a recognised cloud VM, so on bare metal it is
//! always `false`.

use std::sync::OnceLock;

/// The cloud platform the host runs on, detected from DMI/SMBIOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudPlatform {
    Azure,
    Aws,
    Gcp,
    Oci,
    /// A cloud we don't have an agent profile for, or bare metal - no agent
    /// identities are trusted.
    None,
}

/// Canonical Azure chassis asset tag, identical across every Azure VM and
/// distinct from on-prem Hyper-V (which shares the `Microsoft Corporation`
/// vendor but not this tag). Documented by Microsoft as the Azure detection
/// signal.
const AZURE_ASSET_TAG: &str = "7783-7084-3265-9085-8269-3286-77";

/// How many parent hops to walk when deciding whether a process belongs to a
/// guest-agent lineage (covers `systemd -> waagent -> exthandler -> plugin`).
const MAX_LINEAGE_HOPS: u32 = 4;

static PLATFORM: OnceLock<CloudPlatform> = OnceLock::new();

/// Pure DMI classification. Kept separate from the filesystem read so it is
/// unit-testable without `/sys`.
pub fn detect_from_dmi(
    sys_vendor: &str,
    product_name: &str,
    chassis_asset_tag: &str,
) -> CloudPlatform {
    let sv = sys_vendor.trim();
    let pn = product_name.trim();
    let tag = chassis_asset_tag.trim();

    // Azure: the asset tag is the reliable signal. Vendor `Microsoft
    // Corporation` + `Virtual Machine` alone would also match on-prem Hyper-V,
    // so we do NOT use it for Azure (a mis-detect there is harmless anyway -
    // the waagent paths would not exist - but the tag keeps it exact).
    if tag == AZURE_ASSET_TAG {
        return CloudPlatform::Azure;
    }
    if sv.contains("Amazon") || pn.contains("Amazon EC2") || tag.contains("Amazon") {
        return CloudPlatform::Aws;
    }
    if sv.contains("Google") || pn.contains("Google Compute Engine") {
        return CloudPlatform::Gcp;
    }
    if sv.contains("Oracle") || tag.contains("OracleCloud") {
        return CloudPlatform::Oci;
    }
    CloudPlatform::None
}

fn read_dmi(field: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/dmi/id/{field}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// The detected (and cached) cloud platform, from DMI/SMBIOS. Zero-config: every
/// install auto-recognises its host. Cached for the process lifetime.
pub fn platform() -> CloudPlatform {
    *PLATFORM.get_or_init(|| {
        detect_from_dmi(
            &read_dmi("sys_vendor"),
            &read_dmi("product_name"),
            &read_dmi("chassis_asset_tag"),
        )
    })
}

/// Platform-specific management-agent exe / script paths. A trailing `/` is a
/// directory prefix; otherwise the entry is an exact file path. All live under
/// root-owned system directories. These are stable process identities, never
/// IPs.
fn guest_agent_paths(platform: CloudPlatform) -> &'static [&'static str] {
    match platform {
        CloudPlatform::Azure => &[
            "/usr/sbin/waagent",
            "/var/lib/waagent/", // extension handlers + the WALinuxAgent egg run from here
            "/opt/microsoft/",
            "/usr/lib/linux-tools/", // hv_kvp_daemon ships under linux-tools/<ver>/
        ],
        CloudPlatform::Aws => &[
            "/snap/amazon-ssm-agent/",
            "/usr/bin/amazon-ssm-agent",
            "/opt/aws/",
            "/opt/amazon/",
        ],
        CloudPlatform::Gcp => &[
            "/usr/bin/google_guest_agent",
            "/usr/bin/google_osconfig_agent",
            "/usr/bin/google_metadata_script_runner",
            "/usr/bin/google_network_daemon",
            "/usr/bin/gke-metadata-server",
        ],
        CloudPlatform::Oci => &[
            "/snap/oracle-cloud-agent/",
            "/usr/libexec/oracle-cloud-agent/",
            "/var/lib/oracle-cloud-agent/",
            "/opt/unified-monitoring-agent/",
        ],
        CloudPlatform::None => &[],
    }
}

/// Agents present on essentially any cloud VM, regardless of provider.
const COMMON_GUEST_AGENT_PATHS: &[&str] = &[
    "/usr/bin/cloud-init",
    "/usr/local/bin/cloud-init",
    "/usr/lib/python3/dist-packages/cloudinit/",
];

/// True when `path` matches any pattern: a trailing-`/` pattern is a directory
/// prefix, otherwise an exact file match. Exact-match (not bare `starts_with`)
/// means `/usr/sbin/waagent` does NOT match a planted `/usr/sbin/waagent-evil`.
fn path_matches(path: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| {
        if p.ends_with('/') {
            path.starts_with(p)
        } else {
            path == *p
        }
    })
}

/// True when `path` is one of the platform's (or a common) agent paths.
fn is_guest_agent_path(platform: CloudPlatform, path: &str) -> bool {
    path_matches(path, guest_agent_paths(platform)) || path_matches(path, COMMON_GUEST_AGENT_PATHS)
}

/// True when `exe` is a trusted script interpreter living under a system path.
/// For these the SCRIPT decides identity, not the interpreter.
fn is_trusted_interpreter(exe: &str) -> bool {
    if !crate::path_trust::is_trusted_system_path(exe) {
        return false;
    }
    let base = exe.rsplit('/').next().unwrap_or("");
    base.starts_with("python")
        || base.starts_with("perl")
        || base.starts_with("ruby")
        || base == "node"
}

/// The script a trusted interpreter is running: the first non-flag argument
/// after `argv[0]`. `python3 -u /usr/sbin/waagent -daemon` -> `/usr/sbin/waagent`;
/// `python3 /tmp/evil.py /usr/sbin/waagent` -> `/tmp/evil.py` (the trailing
/// guest-agent-looking arg is ignored - only the actual script counts).
pub fn script_arg(argv: &[String]) -> Option<&str> {
    argv.iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
}

/// Decide guest-agent identity from one process's OWN non-forgeable facts.
///
/// `exe` is `readlink /proc/<pid>/exe`; `argv` is the cmdline split on NUL;
/// `file_is_trusted_root_owned` stats a candidate interpreter-script path (so
/// the heavy fs check is injected and the rest is unit-testable).
fn process_is_guest_agent(
    platform: CloudPlatform,
    exe: &str,
    argv: &[String],
    file_is_trusted_root_owned: &dyn Fn(&str) -> bool,
) -> bool {
    // 1. Compiled agent: the real running binary IS a guest-agent. The exe is
    //    the kernel symlink, so this is non-forgeable on its own.
    if is_guest_agent_path(platform, exe) {
        return true;
    }
    // 2. Interpreter agent (waagent / cloud-init run via python): the
    //    interpreter is trusted AND the script it runs is a guest-agent path
    //    that exists as a root-owned file under a trusted dir. The fs check
    //    defeats an argv that merely *contains* `/usr/sbin/waagent` while
    //    actually executing something else.
    if is_trusted_interpreter(exe) {
        if let Some(script) = script_arg(argv) {
            if script.starts_with('/')
                && !script.contains("/../")
                && is_guest_agent_path(platform, script)
                && file_is_trusted_root_owned(script)
            {
                return true;
            }
        }
    }
    false
}

/// `readlink /proc/<pid>/exe`, with the ` (deleted)` suffix stripped. None for
/// kernel threads / exited processes / EACCES.
fn read_exe(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .map(|s| {
            s.strip_suffix(" (deleted)")
                .map(str::to_string)
                .unwrap_or(s)
        })
}

/// `/proc/<pid>/cmdline` split on NUL into argv (trailing empties dropped).
fn read_cmdline(pid: u32) -> Vec<String> {
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(bytes) => bytes
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Parent pid from `/proc/<pid>/status` (`PPid:`). 0 when unavailable. Uses
/// `status` rather than `stat` so a comm containing spaces/parens can't break
/// the parse.
fn read_ppid(pid: u32) -> u32 {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// stat-based check used for interpreter SCRIPT paths: the file exists, is owned
/// by root, is not group/other writable, and lives under a trusted system path.
/// An unprivileged user cannot satisfy all four, so an argv that names
/// `/usr/sbin/waagent` only earns trust when it really is the root-owned agent.
#[cfg(target_os = "linux")]
fn file_is_trusted_root_owned(path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    if !crate::path_trust::is_trusted_system_path(path) {
        return false;
    }
    match std::fs::metadata(path) {
        Ok(m) => m.uid() == 0 && (m.mode() & 0o022) == 0,
        Err(_) => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn file_is_trusted_root_owned(_path: &str) -> bool {
    false
}

/// True when `pid` (a `uid`-`0` process on a recognised cloud VM) is one of the
/// platform's management agents, or a descendant of one within
/// [`MAX_LINEAGE_HOPS`] - proven entirely from non-forgeable `/proc` facts.
///
/// Returns `false` on a non-cloud host, for non-root processes, when the
/// lineage cannot be resolved, or when nothing in it matches. See the module
/// docs for the downgrade-only contract.
pub fn is_guest_agent(pid: u32, uid: u32) -> bool {
    let platform = platform();
    if platform == CloudPlatform::None || uid != 0 {
        return false;
    }
    is_guest_agent_lineage(
        platform,
        pid,
        MAX_LINEAGE_HOPS,
        &|p| read_exe(p),
        &|p| read_cmdline(p),
        &|p| read_ppid(p),
        &file_is_trusted_root_owned,
    )
}

/// Lineage walk, with `/proc` readers + the fs check injected so the control
/// flow (including the parent-hop logic) is unit-testable without a live agent.
#[allow(clippy::too_many_arguments)]
fn is_guest_agent_lineage(
    platform: CloudPlatform,
    start_pid: u32,
    max_hops: u32,
    read_exe_fn: &dyn Fn(u32) -> Option<String>,
    read_cmdline_fn: &dyn Fn(u32) -> Vec<String>,
    read_ppid_fn: &dyn Fn(u32) -> u32,
    file_is_trusted_root_owned_fn: &dyn Fn(&str) -> bool,
) -> bool {
    let mut pid = start_pid;
    let mut hops = 0;
    while pid > 1 && hops < max_hops {
        if let Some(exe) = read_exe_fn(pid) {
            let argv = read_cmdline_fn(pid);
            if process_is_guest_agent(platform, &exe, &argv, file_is_trusted_root_owned_fn) {
                return true;
            }
        }
        let ppid = read_ppid_fn(pid);
        if ppid == 0 || ppid == pid {
            break;
        }
        pid = ppid;
        hops += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    // ── DMI detection ────────────────────────────────────────────────

    #[test]
    fn detect_azure_by_asset_tag() {
        // Exact prod values from the Azure box.
        assert_eq!(
            detect_from_dmi(
                "Microsoft Corporation",
                "Virtual Machine",
                "7783-7084-3265-9085-8269-3286-77"
            ),
            CloudPlatform::Azure
        );
    }

    #[test]
    fn onprem_hyperv_is_not_azure() {
        // Same vendor + product as Azure but no Azure asset tag → NOT Azure
        // (would otherwise mis-trust waagent paths on on-prem Hyper-V).
        assert_eq!(
            detect_from_dmi("Microsoft Corporation", "Virtual Machine", ""),
            CloudPlatform::None
        );
    }

    #[test]
    fn detect_aws_gcp_oci() {
        assert_eq!(
            detect_from_dmi("Amazon EC2", "t3.medium", "i-0abc"),
            CloudPlatform::Aws
        );
        assert_eq!(
            detect_from_dmi("Google", "Google Compute Engine", ""),
            CloudPlatform::Gcp
        );
        assert_eq!(
            detect_from_dmi("Oracle", "", "OracleCloud.com"),
            CloudPlatform::Oci
        );
    }

    #[test]
    fn detect_bare_metal_is_none() {
        assert_eq!(
            detect_from_dmi("Dell Inc.", "PowerEdge R740", "abc123"),
            CloudPlatform::None
        );
    }

    // ── script_arg extraction ────────────────────────────────────────

    #[test]
    fn script_arg_skips_interpreter_and_flags() {
        // The exact waagent daemon cmdline.
        assert_eq!(
            script_arg(&argv(&[
                "/usr/bin/python3",
                "-u",
                "/usr/sbin/waagent",
                "-daemon"
            ])),
            Some("/usr/sbin/waagent")
        );
        // First non-flag is the script - a trailing guest-agent-looking arg is
        // ignored (anti-spoof).
        assert_eq!(
            script_arg(&argv(&[
                "/usr/bin/python3",
                "/tmp/evil.py",
                "/usr/sbin/waagent"
            ])),
            Some("/tmp/evil.py")
        );
        // No script (only flags) → None.
        assert_eq!(script_arg(&argv(&["/usr/bin/python3", "-c", "-u"])), None);
    }

    // ── process_is_guest_agent (own facts) ───────────────────────────

    fn always_root_owned(_p: &str) -> bool {
        true
    }
    fn never_root_owned(_p: &str) -> bool {
        false
    }

    #[test]
    fn compiled_agent_exe_matches_without_stat() {
        // GCP guest agent is a compiled binary - exe alone (kernel symlink) is
        // enough, no script/stat needed.
        assert!(process_is_guest_agent(
            CloudPlatform::Gcp,
            "/usr/bin/google_guest_agent",
            &argv(&["/usr/bin/google_guest_agent"]),
            &never_root_owned,
        ));
        // AWS SSM agent under /snap.
        assert!(process_is_guest_agent(
            CloudPlatform::Aws,
            "/snap/amazon-ssm-agent/7993/amazon-ssm-agent",
            &argv(&["amazon-ssm-agent"]),
            &never_root_owned,
        ));
    }

    #[test]
    fn interpreter_waagent_matches_when_script_real() {
        // The exact waagent daemon: python interpreter + absolute /usr/sbin/waagent
        // script that stats as a root-owned trusted file.
        assert!(process_is_guest_agent(
            CloudPlatform::Azure,
            "/usr/bin/python3.12",
            &argv(&["/usr/bin/python3", "-u", "/usr/sbin/waagent", "-daemon"]),
            &always_root_owned,
        ));
    }

    #[test]
    fn interpreter_argv_spoof_rejected_when_file_not_root_owned() {
        // ANTI-EVASION: argv claims /usr/sbin/waagent but the fs check says it
        // is not a root-owned trusted file (planted / wrong owner) → not trusted.
        assert!(!process_is_guest_agent(
            CloudPlatform::Azure,
            "/usr/bin/python3.12",
            &argv(&["/usr/bin/python3", "/usr/sbin/waagent"]),
            &never_root_owned,
        ));
    }

    #[test]
    fn interpreter_running_tmp_script_not_trusted() {
        // ANTI-EVASION: python (trusted interpreter) running an attacker script
        // from /tmp, even with a trailing /usr/sbin/waagent arg → the SCRIPT is
        // /tmp/evil.py, not a guest-agent path → not trusted.
        assert!(!process_is_guest_agent(
            CloudPlatform::Azure,
            "/usr/bin/python3.12",
            &argv(&["/usr/bin/python3", "/tmp/evil.py", "/usr/sbin/waagent"]),
            &always_root_owned,
        ));
    }

    #[test]
    fn untrusted_interpreter_path_not_trusted() {
        // ANTI-EVASION: a python copied to /tmp is not a trusted interpreter,
        // even running the real waagent path.
        assert!(!process_is_guest_agent(
            CloudPlatform::Azure,
            "/tmp/python3",
            &argv(&["/tmp/python3", "/usr/sbin/waagent"]),
            &always_root_owned,
        ));
    }

    #[test]
    fn relative_script_not_self_matched() {
        // The exthandler child runs a RELATIVE script path; on its own it must
        // NOT match (it is recognised via its waagent parent in the lineage).
        assert!(!process_is_guest_agent(
            CloudPlatform::Azure,
            "/usr/bin/python3.12",
            &argv(&[
                "/usr/bin/python3",
                "-u",
                "bin/WALinuxAgent-2.15.2.1-py3.12.egg",
                "-run-exthandlers",
            ]),
            &always_root_owned,
        ));
    }

    #[test]
    fn exact_path_not_prefix_evasion() {
        // ANTI-EVASION: a planted /usr/sbin/waagent-evil binary must not match
        // the exact-file pattern /usr/sbin/waagent.
        assert!(!is_guest_agent_path(
            CloudPlatform::Azure,
            "/usr/sbin/waagent-evil"
        ));
        // but the dir-prefix entry /var/lib/waagent/ does cover children
        assert!(is_guest_agent_path(
            CloudPlatform::Azure,
            "/var/lib/waagent/Microsoft.Azure.Extensions/foo"
        ));
    }

    #[test]
    fn agent_paths_are_platform_scoped() {
        // waagent is only an agent identity on Azure, not AWS.
        assert!(is_guest_agent_path(
            CloudPlatform::Azure,
            "/usr/sbin/waagent"
        ));
        assert!(!is_guest_agent_path(
            CloudPlatform::Aws,
            "/usr/sbin/waagent"
        ));
        // cloud-init is common to all clouds.
        assert!(is_guest_agent_path(
            CloudPlatform::Aws,
            "/usr/bin/cloud-init"
        ));
        assert!(is_guest_agent_path(
            CloudPlatform::Gcp,
            "/usr/bin/cloud-init"
        ));
    }

    // ── lineage walk ─────────────────────────────────────────────────

    #[test]
    fn lineage_matches_exthandler_via_waagent_parent() {
        // pid 1204 = WALinuxAgent exthandler (relative script, no self-match);
        // its parent 715 = waagent (absolute /usr/sbin/waagent). The walk finds
        // the agent one hop up. Mirrors the exact prod process tree.
        let exe = |_p: u32| Some("/usr/bin/python3.12".to_string());
        let cmd = |p: u32| {
            if p == 1204 {
                argv(&[
                    "/usr/bin/python3",
                    "-u",
                    "bin/WALinuxAgent-2.15.2.1-py3.12.egg",
                    "-run-exthandlers",
                ])
            } else {
                argv(&["/usr/bin/python3", "-u", "/usr/sbin/waagent", "-daemon"])
            }
        };
        let ppid = |p: u32| if p == 1204 { 715 } else { 1 };
        assert!(is_guest_agent_lineage(
            CloudPlatform::Azure,
            1204,
            MAX_LINEAGE_HOPS,
            &exe,
            &cmd,
            &ppid,
            &always_root_owned,
        ));
    }

    #[test]
    fn lineage_stops_and_is_false_for_unrelated_process() {
        // A normal root process (bash) with a systemd parent → no agent in the
        // lineage → false. Anti-evasion: lineage does not blanket-trust root.
        let exe = |p: u32| {
            Some(match p {
                100 => "/usr/bin/bash".to_string(),
                _ => "/usr/lib/systemd/systemd".to_string(),
            })
        };
        let cmd = |_p: u32| argv(&["bash"]);
        let ppid = |p: u32| if p == 100 { 1 } else { 0 };
        assert!(!is_guest_agent_lineage(
            CloudPlatform::Azure,
            100,
            MAX_LINEAGE_HOPS,
            &exe,
            &cmd,
            &ppid,
            &always_root_owned,
        ));
    }

    #[test]
    fn lineage_respects_hop_budget() {
        // Agent is 5 hops up but the budget is 4 → not found (bounded walk).
        let exe = |p: u32| {
            Some(if p == 600 {
                "/usr/bin/python3".to_string()
            } else {
                "/usr/bin/bash".to_string()
            })
        };
        let cmd = |p: u32| {
            if p == 600 {
                argv(&["/usr/bin/python3", "/usr/sbin/waagent"])
            } else {
                argv(&["bash"])
            }
        };
        // 100 -> 200 -> 300 -> 400 -> 500 -> 600(agent)
        let ppid = |p: u32| match p {
            100 => 200,
            200 => 300,
            300 => 400,
            400 => 500,
            500 => 600,
            _ => 1,
        };
        assert!(!is_guest_agent_lineage(
            CloudPlatform::Azure,
            100,
            MAX_LINEAGE_HOPS,
            &exe,
            &cmd,
            &ppid,
            &always_root_owned,
        ));
    }

    #[test]
    fn none_platform_has_no_agents() {
        // On bare metal nothing is a guest agent, even a real-looking path.
        assert!(!process_is_guest_agent(
            CloudPlatform::None,
            "/usr/sbin/waagent",
            &argv(&["/usr/sbin/waagent"]),
            &always_root_owned,
        ));
    }

    #[test]
    fn live_is_guest_agent_self_is_false_and_no_panic() {
        // The test process is not a guest agent; also drives the live /proc
        // readers (read_exe/read_cmdline/read_ppid) without panicking. On a
        // non-cloud CI host platform() is None so this is trivially false; on a
        // cloud CI host the test binary still is not an agent.
        let me = std::process::id();
        assert!(!is_guest_agent(me, 0));
        // uid != 0 is always false regardless of platform.
        assert!(!is_guest_agent(me, 1000));
        // A pid that cannot exist resolves to no lineage.
        assert!(!is_guest_agent(u32::MAX, 0));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn live_proc_readers_work_on_self() {
        // Exercise the real /proc readers directly so they are covered
        // regardless of whether the CI runner's DMI auto-detects a cloud
        // (is_guest_agent short-circuits to false off-cloud before using them).
        let me = std::process::id();
        let exe = read_exe(me).expect("own /proc/<pid>/exe must resolve");
        assert!(exe.starts_with('/'), "exe should be an absolute path");
        assert!(
            !read_cmdline(me).is_empty(),
            "own cmdline must be non-empty"
        );
        assert!(read_ppid(me) > 0, "own parent pid must resolve");
        // A pid above pid_max never exists → readers return empty/zero.
        assert!(read_exe(u32::MAX).is_none());
        assert!(read_cmdline(u32::MAX).is_empty());
        assert_eq!(read_ppid(u32::MAX), 0);
        // The fs trust check: a path outside trusted dirs is rejected before any
        // stat; a real system binary just drives the stat branch (owner varies
        // across CI, so we do not assert its boolean).
        assert!(!file_is_trusted_root_owned("/tmp/definitely-not-here-xyz"));
        let _ = file_is_trusted_root_owned("/bin/sh");
    }
}
