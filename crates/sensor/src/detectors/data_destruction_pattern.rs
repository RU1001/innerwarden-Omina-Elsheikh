//! Data destruction pattern detection (spec 050-PR6).
//!
//! Covers the **Impact** tactic of the MITRE Linux matrix — the last
//! step of the kill chain where the attacker erases data, wipes
//! disks, or denies recovery. These shapes are the smoking-gun
//! signature of ransomware-without-encryption, wiper malware, and
//! revenge-deletion by insiders.
//!
//! Sub-detections:
//!
//! 1. `rm_rf_user_data`: exec of `rm -rf` (or `rm -fr` / `rm --recursive --force`)
//!    against a path under user-data prefixes
//!    (`/home/`, `/var/lib/`, `/etc/`, `/root/`, `/srv/`, `/var/www/`,
//!    `/opt/`, `/data/`, `/mnt/`).
//!    Single-file `rm` of a path NOT under those prefixes → silenced.
//!    Operator-allowlisted parents (backup tools, ansible, terraform) → silenced.
//!
//! 2. `disk_wipe`: exec of `dd if=/dev/zero` or `dd if=/dev/urandom`
//!    with `of=/dev/sd[a-z]*` or `of=/dev/nvme*` or `of=/dev/xvd*`.
//!    Writing zeros/random to a block device is the textbook wipe.
//!
//! 3. `shred_burst`: exec of `shred` with the `-u` flag (deletes after
//!    overwrite) AND 3+ target paths.
//!
//! 3b. `find_delete_bulk`: exec of `find <user-data-path> ... -delete` with no
//!    name/path/regex filter. The GuardFall class-E destructive tool a
//!    `rm`-watching text blocklist misses; the sensor catches it on the REAL
//!    post-shell-rewrite argv the kernel exec'd. Filtered cleanups
//!    (`find . -name '*.tmp' -delete`), `/tmp`, and build-cache dirs stay silent.
//!
//! 4. `mkfs_on_running_volume`: exec of `mkfs.*` against a block device
//!    (`/dev/sd*`, `/dev/nvme*`, `/dev/xvd*`, `/dev/mapper/*`). Always
//!    suspicious post-boot since legit filesystem creation happens
//!    once during install.
//!
//! 5. `cryptsetup_luksformat`: exec of `cryptsetup luksFormat` against
//!    a block device. Attackers use LUKS to encrypt-then-throw-key
//!    (poor-man's wiper).
//!
//! All sub-detections share a 5-minute per-target cooldown and the
//! same anti-FP gates:
//!   - Parent comm in `{borgmatic, restic, duplicity, rclone, kopia,
//!     rdiff-backup, rsnapshot, ansible, salt-call, puppet,
//!     chef-client, terraform, packer}` → silenced.
//!   - Operator-extensible `[detectors.data_destruction_pattern]` TOML.
//!
//! MITRE: T1485 (Data Destruction), T1561.001 (Disk Content Wipe),
//!        T1486 (Data Encrypted for Impact, when LUKS variant).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const USER_DATA_PATH_PREFIXES: &[&str] = &[
    "/home/",
    "/var/lib/",
    "/etc/",
    "/root/",
    "/srv/",
    "/var/www/",
    "/opt/",
    "/data/",
    "/mnt/",
    "/var/log/",
];

/// Filesystem roots we will NEVER fire on for `rm -rf` regardless of
/// other args — these are the catastrophic argv0 patterns that match
/// other detectors (process_injection, log_tampering).
const RM_SAFE_EXACT_PATHS: &[&str] = &["/tmp/", "/var/tmp/", "/var/cache/", "/dev/shm/"];

/// Path segments that, when present anywhere in an `rm -rf` target,
/// indicate a build cache / package cache rather than user data.
/// Match is whole-segment (split on `/`) so `/home/me/targetdata/`
/// does NOT match `target` here — only `/home/me/project/target/...`
/// does.
///
/// Wave 2026-05-18: the FP that triggered this list. Every
/// `cargo build --release` on Oracle prod ran `rm -rf
/// /home/ubuntu/innerwarden/target/release/incremental` (cargo's
/// own incremental cache cleanup), which the detector correctly
/// flagged as `rm -rf` of a `/home/` path but is in fact routine
/// build noise. Five critical alerts in one day, all from the
/// operator's own deploys. The same FP would hit any host doing
/// node / python / go / java builds in the user's home dir.
const RM_BUILD_CACHE_SEGMENTS: &[&str] = &[
    // Rust
    "target",
    ".cargo",
    ".rustup",
    // Node / JS
    "node_modules",
    ".npm",
    ".pnpm-store",
    ".next",
    ".turbo",
    // Python
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".venv",
    "venv",
    // Go
    ".gopath",
    // Java / JVM
    ".gradle",
    // Cross-language
    ".cache",
    ".local",
    "dist",
];

/// True iff any `/`-separated segment of `path` exactly equals one of
/// the build-cache names. Pure for unit testing.
fn path_has_build_cache_segment(path: &str) -> bool {
    path.split('/')
        .any(|seg| RM_BUILD_CACHE_SEGMENTS.contains(&seg))
}

/// Package-manager state/temp dirs are managed by the package tooling, which
/// routinely `rm -rf`s its own scratch dirs (e.g. dpkg's `/var/lib/dpkg/tmp.ci`
/// during an upgrade, apt list/cache rebuilds). They live under `/var/lib/`,
/// which is otherwise a user-data prefix, so they need an explicit exclusion.
/// Anchored on the package-manager state ROOT so a user dir merely containing
/// "dpkg"/"apt" elsewhere still fires. Distro-universal, not host-specific.
/// Deliberately does NOT exclude `/var/lib/mysql`, `/var/lib/postgresql`,
/// `/var/lib/docker`, etc. — those hold real data and a wipe IS destruction.
fn is_pkg_manager_state_path(path: &str) -> bool {
    const PM_PREFIXES: &[&str] = &[
        "/var/lib/dpkg/",
        "/var/lib/apt/",
        "/var/lib/yum/",
        "/var/lib/dnf/",
        "/var/lib/pacman/",
        "/var/lib/rpm/",
    ];
    PM_PREFIXES.iter().any(|p| path.starts_with(p))
}

const BLOCK_DEVICE_PREFIXES: &[&str] = &[
    "/dev/sd",
    "/dev/nvme",
    "/dev/xvd",
    "/dev/vd",
    "/dev/mapper/",
    "/dev/disk/",
];

const BACKUP_PARENTS: &[&str] = &[
    "borgmatic",
    "borg",
    "restic",
    "duplicity",
    "duplicacy",
    "rclone",
    "kopia",
    "rdiff-backup",
    "rsnapshot",
    "burp",
    "bacula-fd",
    "bareos-fd",
];

const AUTOMATION_PARENTS: &[&str] = &[
    "ansible",
    "ansible-playboo",
    "salt-call",
    "salt-minion",
    "puppet",
    "chef-client",
    "cfengine",
    "terraform",
    "packer",
];

pub struct DataDestructionPatternDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl DataDestructionPatternDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(300),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }
        let argv: Vec<String> = event
            .details
            .get("argv")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        if argv.is_empty() {
            return None;
        }
        let argv0_base = argv[0].split('/').next_back().unwrap_or(&argv[0]);
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let parent_base = parent_comm.split('/').next_back().unwrap_or(parent_comm);
        let parent_base = parent_base.trim_matches(|c: char| c == '(' || c == ')');
        if BACKUP_PARENTS.iter().any(|p| parent_base.starts_with(p))
            || AUTOMATION_PARENTS
                .iter()
                .any(|p| parent_base.starts_with(p))
        {
            return None;
        }

        let (sub_kind, target) = match argv0_base {
            "rm" => match detect_rm_rf_user_data(&argv) {
                Some(t) => ("rm_rf_user_data", t),
                None => return None,
            },
            "dd" => match detect_disk_wipe(&argv) {
                Some(t) => ("disk_wipe", t),
                None => return None,
            },
            "shred" => match detect_shred_burst(&argv) {
                Some(t) => ("shred_burst", t),
                None => return None,
            },
            "find" => match detect_find_delete(&argv) {
                Some(t) => ("find_delete_bulk", t),
                None => return None,
            },
            "cryptsetup" => match detect_luksformat(&argv) {
                Some(t) => ("cryptsetup_luksformat", t),
                None => return None,
            },
            _ if argv0_base.starts_with("mkfs") => match detect_mkfs_on_block(&argv) {
                Some(t) => ("mkfs_on_running_volume", t),
                None => return None,
            },
            _ => return None,
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

        let now = event.ts;
        let key = format!("{uid}:{sub_kind}:{target}");
        if let Some(&last) = self.last_fired.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.last_fired.insert(key, now);

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "data_destruction_pattern:{sub_kind}:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::Critical,
            title: format!(
                "Data destruction: {sub_kind} (target=`{target}`, comm=`{comm}`, parent=`{parent_base}`, uid={uid})"
            ),
            summary: format!(
                "Process `{comm}` (parent=`{parent_base}`, pid={pid}, uid={uid}) ran \
                 `{command}` — matched the `{sub_kind}` Impact pattern. This is the last step \
                 of the kill chain: wiper malware, ransomware-without-encryption, or insider \
                 deletion (T1485 / T1561.001 / T1486). Investigate IMMEDIATELY — recovery \
                 window is small."
            ),
            evidence: serde_json::json!([{
                "kind": "data_destruction_pattern",
                "sub_kind": sub_kind,
                "target": target,
                "uid": uid,
                "comm": comm,
                "parent_comm": parent_comm,
                "pid": pid,
                "argv": argv,
                "mitre": mitre_ids(sub_kind),
            }]),
            recommended_checks: vec![
                "If this is in progress, kill the pid NOW: `kill -9 <pid>`".to_string(),
                format!("Inspect process tree of pid {pid}: pstree -p {pid}"),
                "Cross-check against backup snapshots — last good backup timestamp".to_string(),
                "Snapshot current disk state with dd or filesystem snapshot before further forensics".to_string(),
                "If planned operator action (decommissioning, reformat), allowlist via [detectors.data_destruction_pattern]".to_string(),
            ],
            tags: vec!["impact".to_string(), "data_destruction".to_string()],
            entities: vec![],
        })
    }
}

fn detect_rm_rf_user_data(argv: &[String]) -> Option<String> {
    // Need at least the recursive+force flags AND a target under user data.
    let mut has_recursive = false;
    let mut has_force = false;
    let mut targets: Vec<&String> = Vec::new();
    for a in argv.iter().skip(1) {
        if a.starts_with("--") {
            if a == "--recursive" {
                has_recursive = true;
            } else if a == "--force" {
                has_force = true;
            }
            continue;
        }
        if a.starts_with('-') {
            for c in a.chars().skip(1) {
                match c {
                    'r' | 'R' => has_recursive = true,
                    'f' => has_force = true,
                    _ => {}
                }
            }
            continue;
        }
        targets.push(a);
    }
    if !has_recursive || !has_force {
        return None;
    }
    for t in &targets {
        // Exact-match exclusion: rm -rf /tmp/something stays silent.
        if RM_SAFE_EXACT_PATHS.iter().any(|p| t.starts_with(p)) {
            continue;
        }
        // Build-cache exclusion: rm -rf /home/me/proj/target/release stays
        // silent because cargo / npm / pip / etc. routinely wipe their
        // own cache dirs during build. Whole-segment match so
        // `/home/me/target-data/` (user data dir that happens to contain
        // "target") still fires. See `RM_BUILD_CACHE_SEGMENTS`.
        if path_has_build_cache_segment(t) {
            continue;
        }
        // Package-manager state/temp dirs under /var/lib/ are tool-managed
        // scratch space, not user data (e.g. `rm -rf /var/lib/dpkg/tmp.ci`).
        if is_pkg_manager_state_path(t) {
            continue;
        }
        if USER_DATA_PATH_PREFIXES.iter().any(|p| t.starts_with(p)) {
            return Some(t.to_string());
        }
        // Special-case: `rm -rf /` or `rm -rf /*` is a wipe regardless.
        if *t == "/" || *t == "/*" {
            return Some(t.to_string());
        }
    }
    None
}

/// `find <path> -delete` is the GuardFall class-E destructive tool a text
/// blocklist watching for `rm` misses, but the sensor sees the REAL argv the
/// kernel exec'd (post shell-rewrite: `r''m`, `$IFS`, `$(...)` are already
/// resolved by the time execve fires), so it is caught here regardless of how
/// the command was obfuscated in the shell.
///
/// Fires only on an UNFILTERED bulk delete under a user-data prefix. A
/// name/path/regex filter (`find . -name '*.tmp' -delete`) is the ubiquitous
/// targeted cleanup and stays silent, as do build-cache dirs, `/tmp`, and
/// package-manager scratch space - the same target discrimination the `rm -rf`
/// path uses. The parent process is deliberately NOT the discriminator: a
/// malicious `make test` that wipes `/home/user` fires, while a legit `make
/// clean` that deletes `target/` is silenced by the build-cache exclusion.
fn detect_find_delete(argv: &[String]) -> Option<String> {
    let mut has_delete = false;
    let mut has_name_filter = false;
    let mut paths: Vec<&String> = Vec::new();
    let mut in_expression = false;
    for a in argv.iter().skip(1) {
        if a == "-delete" {
            has_delete = true;
            in_expression = true;
            continue;
        }
        // A name/path/regex predicate makes this a targeted cleanup, not an
        // indiscriminate bulk wipe. (`-type`/`-mtime` restrict but do not
        // target by name, so they do NOT exempt.)
        if matches!(
            a.as_str(),
            "-name" | "-iname" | "-path" | "-ipath" | "-regex" | "-iregex" | "-wholename"
        ) {
            has_name_filter = true;
            in_expression = true;
            continue;
        }
        if a.starts_with('-') {
            // Any other predicate (-type, -mtime, -exec, ...) begins the
            // expression; nothing after it is a starting path.
            in_expression = true;
            continue;
        }
        // A non-flag token before the expression is a find starting path.
        if !in_expression {
            paths.push(a);
        }
    }
    if !has_delete || has_name_filter {
        return None;
    }
    for t in &paths {
        if RM_SAFE_EXACT_PATHS.iter().any(|p| t.starts_with(p)) {
            continue;
        }
        if path_has_build_cache_segment(t) {
            continue;
        }
        if is_pkg_manager_state_path(t) {
            continue;
        }
        if USER_DATA_PATH_PREFIXES.iter().any(|p| t.starts_with(p)) {
            return Some(t.to_string());
        }
        if *t == "/" || *t == "/*" {
            return Some(t.to_string());
        }
    }
    None
}

fn detect_disk_wipe(argv: &[String]) -> Option<String> {
    let mut input_is_zero_or_random = false;
    let mut output_block_dev: Option<String> = None;
    for a in argv.iter().skip(1) {
        if let Some(rest) = a.strip_prefix("if=") {
            if rest == "/dev/zero" || rest == "/dev/urandom" || rest == "/dev/random" {
                input_is_zero_or_random = true;
            }
        } else if let Some(rest) = a.strip_prefix("of=") {
            if BLOCK_DEVICE_PREFIXES.iter().any(|p| rest.starts_with(p)) {
                output_block_dev = Some(rest.to_string());
            }
        }
    }
    if input_is_zero_or_random {
        output_block_dev
    } else {
        None
    }
}

fn detect_shred_burst(argv: &[String]) -> Option<String> {
    let mut has_unlink = false;
    let mut targets: Vec<&String> = Vec::new();
    for a in argv.iter().skip(1) {
        if a == "--remove" || a == "--remove=wipe" || a == "--remove=wipesync" {
            has_unlink = true;
            continue;
        }
        if a.starts_with("--remove=") {
            has_unlink = true;
            continue;
        }
        if let Some(stripped) = a.strip_prefix('-') {
            if !stripped.starts_with('-') {
                for c in stripped.chars() {
                    if c == 'u' {
                        has_unlink = true;
                    }
                }
                continue;
            }
        }
        targets.push(a);
    }
    if has_unlink && targets.len() >= 3 {
        Some(format!(
            "{} paths starting with {}",
            targets.len(),
            targets.first().map(|s| s.as_str()).unwrap_or("")
        ))
    } else {
        None
    }
}

fn detect_mkfs_on_block(argv: &[String]) -> Option<String> {
    for a in argv.iter().skip(1) {
        if BLOCK_DEVICE_PREFIXES.iter().any(|p| a.starts_with(p)) {
            return Some(a.clone());
        }
    }
    None
}

fn detect_luksformat(argv: &[String]) -> Option<String> {
    if !argv.iter().any(|a| a == "luksFormat") {
        return None;
    }
    for a in argv.iter().skip(1) {
        if BLOCK_DEVICE_PREFIXES.iter().any(|p| a.starts_with(p)) {
            return Some(a.clone());
        }
    }
    None
}

fn mitre_ids(sub_kind: &str) -> Vec<&'static str> {
    match sub_kind {
        "rm_rf_user_data" => vec!["T1485"],
        "disk_wipe" => vec!["T1561.001"],
        "shred_burst" => vec!["T1485"],
        "find_delete_bulk" => vec!["T1485"],
        "mkfs_on_running_volume" => vec!["T1561.001"],
        "cryptsetup_luksformat" => vec!["T1486", "T1561.001"],
        _ => vec!["T1485"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(argv: &[&str], parent_comm: &str) -> Event {
        let argv_owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: argv.join(" "),
            details: serde_json::json!({
                "argv": argv_owned,
                "argc": argv.len() as u32,
                "command": argv.join(" "),
                "pid": 4242,
                "uid": 1000,
                "comm": "bash",
                "parent_comm": parent_comm,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_rm_rf_home() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/home/ubuntu/work"], "bash");
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn fires_on_unfiltered_find_delete_under_user_data() {
        let mut det = DataDestructionPatternDetector::new("test");
        // GuardFall class-E: a rm-watching blocklist misses find -delete.
        let ev = exec_event(
            &["find", "/home/ubuntu/work", "-type", "f", "-delete"],
            "bash",
        );
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Critical);
        assert!(inc.title.contains("find_delete_bulk"));
    }

    #[test]
    fn find_delete_silent_on_filtered_cleanup_and_safe_targets() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // The ubiquitous filtered cleanup - a name filter means targeted, not bulk.
        assert_eq!(
            detect_find_delete(&s(&["find", ".", "-name", "*.tmp", "-delete"])),
            None
        );
        assert_eq!(
            detect_find_delete(&s(&[
                "find",
                "/home/me/logs",
                "-path",
                "*/cache/*",
                "-delete"
            ])),
            None
        );
        // /tmp and build caches stay silent (same target discrimination as rm -rf).
        assert_eq!(
            detect_find_delete(&s(&["find", "/tmp/scratch", "-delete"])),
            None
        );
        assert_eq!(
            detect_find_delete(&s(&["find", "/home/me/project/target", "-delete"])),
            None
        );
        // No -delete at all = a plain search, not destruction.
        assert_eq!(
            detect_find_delete(&s(&["find", "/home/me", "-type", "f"])),
            None
        );
    }

    #[test]
    fn find_delete_fires_on_bulk_user_data() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            detect_find_delete(&s(&["find", "/home/ubuntu/docs", "-type", "f", "-delete"])),
            Some("/home/ubuntu/docs".to_string())
        );
        // Unfiltered delete from filesystem root.
        assert_eq!(
            detect_find_delete(&s(&["find", "/", "-delete"])),
            Some("/".to_string())
        );
    }

    /// The runtime layer is inherently GuardFall-resistant: whatever shell
    /// obfuscation the agent used (`r''m -rf /home/user`, `rm$IFS-rf$IFS...`,
    /// `$(echo rm) -rf ...`), the kernel exec'd the REAL, already-resolved argv,
    /// which is exactly what the eBPF collector puts in `argv`. So the detector
    /// fires on the real command the static text-check would have been fooled by.
    #[test]
    fn fires_on_guardfall_rewritten_command_real_argv() {
        let mut det = DataDestructionPatternDetector::new("test");
        // What the kernel/eBPF sees after the shell resolved `r''m -rf ...`.
        let ev = exec_event(&["rm", "-rf", "/home/user/data"], "make");
        assert!(
            det.process(&ev).is_some(),
            "runtime must catch the post-rewrite real command regardless of shell obfuscation"
        );
        // And the malicious-repo vector: make spawns an unfiltered find -delete.
        let mut det2 = DataDestructionPatternDetector::new("test");
        let ev2 = exec_event(&["find", "/home/user", "-type", "f", "-delete"], "make");
        assert!(
            det2.process(&ev2).is_some(),
            "make-spawned bulk delete must fire"
        );
    }

    #[test]
    fn rm_rf_skips_pkg_manager_state_and_toolchain() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // dpkg's own temp cleanup + apt lists rebuild during an upgrade.
        assert_eq!(
            detect_rm_rf_user_data(&s(&["rm", "-rf", "--", "/var/lib/dpkg/tmp.ci"])),
            None
        );
        assert_eq!(
            detect_rm_rf_user_data(&s(&["rm", "-rf", "/var/lib/apt/lists/partial"])),
            None
        );
        // rust toolchain dirs (.rustup was the gap; .cargo already covered).
        assert_eq!(
            detect_rm_rf_user_data(&s(&[
                "rm",
                "-rf",
                "/home/ubuntu/.rustup",
                "/home/ubuntu/.cargo"
            ])),
            None
        );
        // Real user-data / database wipes still fire.
        assert_eq!(
            detect_rm_rf_user_data(&s(&["rm", "-rf", "/var/www/html"])),
            Some("/var/www/html".to_string())
        );
        assert_eq!(
            detect_rm_rf_user_data(&s(&["rm", "-rf", "/var/lib/mysql"])),
            Some("/var/lib/mysql".to_string())
        );
        assert_eq!(
            detect_rm_rf_user_data(&s(&["rm", "-rf", "/home/user/documents"])),
            Some("/home/user/documents".to_string())
        );
    }

    #[test]
    fn fires_on_rm_rf_root_glob() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/*"], "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_rm_long_flags() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(
            &["rm", "--recursive", "--force", "/var/lib/postgres"],
            "bash",
        );
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn ignores_rm_rf_tmp() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/tmp/build/"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_rm_without_recursive_or_force() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "/home/ubuntu/file.log"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn fires_on_dd_zero_to_sda() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["dd", "if=/dev/zero", "of=/dev/sda", "bs=1M"], "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_dd_urandom_to_nvme() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["dd", "if=/dev/urandom", "of=/dev/nvme0n1"], "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn ignores_dd_to_regular_file() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["dd", "if=/dev/zero", "of=/tmp/junk.img"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn fires_on_shred_burst_three_files() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(
            &["shred", "-u", "/home/x/a", "/home/x/b", "/home/x/c"],
            "bash",
        );
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn ignores_shred_single_file() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["shred", "-u", "/home/x/secret.txt"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_shred_without_unlink() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["shred", "/home/x/a", "/home/x/b", "/home/x/c"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn fires_on_mkfs_ext4_on_sdb() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["mkfs.ext4", "/dev/sdb1"], "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn fires_on_cryptsetup_luksformat() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["cryptsetup", "luksFormat", "/dev/sda2"], "bash");
        assert!(det.process(&ev).is_some());
    }

    #[test]
    fn ignores_cryptsetup_status_query() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["cryptsetup", "status", "luks-vol"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_parent_is_ansible() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/var/lib/old"], "ansible-playboo");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_parent_is_borgmatic() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/var/lib/staging"], "borgmatic");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/home/ubuntu/work"], "bash");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }

    // -----------------------------------------------------------------
    // Wave 2026-05-18 — build cache allowlist. Five critical alerts
    // fired on Oracle prod within the first day of this detector
    // because every `cargo build --release` deploy wiped
    // `/home/ubuntu/innerwarden/target/release/incremental`. The
    // allowlist below silences those without weakening detection
    // for real user-data wipes.
    // -----------------------------------------------------------------

    #[test]
    fn path_has_build_cache_segment_matches_known_caches() {
        for path in &[
            "/home/ubuntu/innerwarden/target/release/incremental",
            "/home/me/project/target",
            "/home/me/project/target/",
            "/home/me/web/node_modules",
            "/home/me/web/node_modules/some-pkg",
            "/home/me/py/__pycache__/foo.cpython-310.pyc",
            "/home/me/.cache/cargo",
            "/home/me/proj/.gradle/caches",
            "/home/me/py/.venv",
            "/home/me/py/.tox/py310",
            "/root/.cargo/registry",
            "/home/me/.npm/_logs",
        ] {
            assert!(
                path_has_build_cache_segment(path),
                "should detect build-cache segment in {path:?}"
            );
        }
    }

    #[test]
    fn path_has_build_cache_segment_does_not_substring_match() {
        // Whole-segment match: a path that *contains* the cache name
        // as a substring inside a real user-data dir name must NOT
        // be silenced. This guards real attacks like
        // `rm -rf /home/me/target-data/` from being misclassified.
        for path in &[
            "/home/me/targetdata",
            "/home/me/target-data",
            "/home/me/notmytarget/file",
            "/home/me/distillery",
            "/home/me/important/.cachefile",
            "/home/me/venv-thing",
            "/etc/passwd",
            "/etc",
        ] {
            assert!(
                !path_has_build_cache_segment(path),
                "should NOT match {path:?} as a build cache"
            );
        }
    }

    #[test]
    fn rm_rf_of_cargo_incremental_cache_does_not_fire() {
        // Regression anchor for the exact prod scenario: every
        // `cargo build --release` ran this command and the detector
        // emitted a critical incident.
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(
            &[
                "rm",
                "-rf",
                "/home/ubuntu/innerwarden/target/release/incremental",
            ],
            "rustc",
        );
        assert!(
            det.process(&ev).is_none(),
            "cargo incremental cache cleanup must not fire data_destruction_pattern"
        );
    }

    #[test]
    fn rm_rf_of_node_modules_does_not_fire() {
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/home/me/web/node_modules"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn rm_rf_of_full_target_dir_does_not_fire() {
        // Common operator workflow: full clean rebuild = `rm -rf target`.
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/home/me/project/target"], "cargo");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn rm_rf_of_user_data_named_like_target_still_fires() {
        // Guard against the allowlist being too loose: a real attack
        // wiping a directory whose name *contains* `target` (but
        // isn't exactly `target` as a path segment) must still trip
        // the detector.
        let mut det = DataDestructionPatternDetector::new("test");
        let ev = exec_event(&["rm", "-rf", "/home/me/important-target-data"], "bash");
        let out = det.process(&ev).expect(
            "rm -rf of a user-data dir whose name merely contains 'target' as substring \
             (not as a `/`-separated segment) MUST still fire — this is the false-negative \
             guard that keeps the build-cache allowlist tight.",
        );
        assert_eq!(out.severity, Severity::Critical);
    }
}
