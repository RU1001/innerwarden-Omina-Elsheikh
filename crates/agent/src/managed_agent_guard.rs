//! Spec 081 — Managed-Agent Coexistence verifier.
//!
//! InnerWarden is both a host EDR **and** an AI-agent guardrail. When a legit,
//! IW-managed AI agent (e.g. OpenClaw running as
//! `node .../node_modules/openclaw/dist/index.js`, comm `MainThread`) runs on
//! the same host, its NORMAL startup behaviour — reading its own `.env`, opening
//! a persistent socket to its own Slack / Azure endpoint — matches the generic
//! `sensitive_read → outbound_connect` exfil/C2 signature. IW then takes
//! HOST-perimeter responses (block the destination IP, kernel-deny the agent's
//! next execve) that are wrong, harmful, and weak.
//!
//! This module is the **response-side** gate consulted by BOTH harmful response
//! paths (the userspace destination-IP block and the kernel PID-block). It does
//! NOT touch DETECTION: the incident still fires, the operator is still
//! notified; only the automatic block/kernel-deny RESPONSE is withheld.
//!
//! Hard constraints (operator, security-engineer-no-gaps — see
//! `.specify/features/081-managed-agent-coexistence/spec.md`):
//!
//! 1. **Never relax DETECTION of specific credential paths.** `.env/.aws/.ssh/
//!    shadow/...` stay fully detected + the incident still fires. We only change
//!    the automatic BLOCK/KERNEL-DENY RESPONSE.
//! 2. **Never exempt by destination** (cloud/Slack/AWS/Azure). The relaxation
//!    axis is the SOURCE process, never the destination — attackers use cloud
//!    for C2, and the agent keeps working when its destination IP rotates.
//! 3. **Positive, multi-signal, live-verified identity.** A single forgeable
//!    signal (comm `MainThread`, a registry pid hit alone, an exe-path string)
//!    is NOT enough. Require an AND of independent signals, re-verified LIVE at
//!    decision time, **fail-closed** (cannot verify → block).
//! 4. **Downgrade, never silence.** Even when relaxed, the incident is recorded
//!    and the operator is notified. The only thing removed is the automatic
//!    IP-block / kernel-deny.
//!
//! The verifier is split into a pure [`decide`] core (which operates on already-
//! resolved facts) and a thin `/proc` resolver ([`ProcResolver`] /
//! [`SystemProc`]). This keeps the no-hole property fully unit-testable without
//! a real `/proc` — the 7 anti-evasion tests inject [`ResolvedProcess`] facts.

use innerwarden_agent_guard::registry::Registry;
use innerwarden_agent_guard::signatures::{Kind, SignatureIndex};

/// Verdict returned by the verifier. `Managed` carries the agent identity so the
/// caller can log a truthful audit line ("withheld: managed agent <id> self-
/// activity"); `NotManaged` is the fail-closed default that drives the FULL
/// response (block + kernel-deny).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ManagedAgentVerdict {
    /// The activity is a verified, IW-managed agent acting on its OWN config /
    /// services. The auto-block + kernel-deny are WITHHELD; the incident and
    /// notification still fire.
    Managed { agent_id: String, name: String },
    /// Not a managed agent (or could not be proven to be one). The full
    /// response proceeds. This is the fail-closed default for ANY error.
    NotManaged,
}

impl ManagedAgentVerdict {
    /// Test-only convenience predicate. Production call sites `match` on the
    /// variant directly so they can use the `agent_id`/`name` payload.
    #[cfg(test)]
    pub(crate) fn is_managed(&self) -> bool {
        matches!(self, ManagedAgentVerdict::Managed { .. })
    }
}

/// Facts resolved LIVE from `/proc/<pid>` at decision time. Injectable so the
/// decision logic is testable without a real `/proc`.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedProcess {
    /// `/proc/<pid>/cmdline` split on NUL, empty entries dropped. Empty when the
    /// pid is gone / unreadable.
    pub argv: Vec<String>,
    /// `/proc/<pid>/exe` readlink target. `None` when the pid is gone /
    /// unreadable (fail-closed).
    pub exe_path: Option<String>,
    /// Effective/real uid parsed from `/proc/<pid>/status` `Uid:`. `None` on any
    /// read/parse failure (fail-closed).
    pub uid: Option<u32>,
}

/// Resolves live `/proc` facts for a pid. The pure [`decide`] core never touches
/// the filesystem; this trait is the only `/proc` boundary, so the anti-evasion
/// tests inject a stub.
pub(crate) trait ProcResolver {
    /// Read live facts for `pid`. Returns `None` when the pid is gone (TOCTOU /
    /// recycled) so the caller fails closed.
    fn resolve(&self, pid: u32) -> Option<ResolvedProcess>;
    /// Owner uid of a file at `path` (stat). `None` on any failure.
    fn file_owner_uid(&self, path: &str) -> Option<u32>;
}

/// Production `/proc` + stat resolver. Mirrors `agent-guard::detect::read_cmdline`
/// (NUL-split cmdline) and `sensor::detectors::is_verified_infra_process`
/// (`/proc/<pid>/exe` readlink) but lives here so the module owns its own
/// resolver and the pure core stays test-only-injectable.
pub(crate) struct SystemProc;

impl ProcResolver for SystemProc {
    fn resolve(&self, pid: u32) -> Option<ResolvedProcess> {
        let base = format!("/proc/{pid}");

        // cmdline: NUL-separated argv. A missing/empty cmdline means the pid is
        // gone or is a kernel thread → treat argv as empty (decide() rejects).
        let argv = match std::fs::read(format!("{base}/cmdline")) {
            Ok(bytes) => bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>(),
            // pid gone / unreadable → fail closed (no facts at all).
            Err(_) => return None,
        };

        // exe: readlink. None when the pid exited between the incident and now.
        let exe_path = std::fs::read_link(format!("{base}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        // uid: first field of the `Uid:` line in /proc/<pid>/status (real uid).
        let uid = std::fs::read_to_string(format!("{base}/status"))
            .ok()
            .and_then(|s| parse_status_uid(&s));

        Some(ResolvedProcess {
            argv,
            exe_path,
            uid,
        })
    }

    fn file_owner_uid(&self, path: &str) -> Option<u32> {
        // Owner uid is a unix/proc concept. On Windows (spec 085 Phase 0)
        // return None ("owner unknown"), which the coexistence verifier
        // already handles fail-closed. Real owner-SID resolution is a later phase.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(path).ok().map(|m| m.uid())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            None
        }
    }
}

/// Parse the real uid (first field) from a `/proc/<pid>/status` `Uid:` line.
/// Format: `Uid:\t<real>\t<effective>\t<saved>\t<fs>`.
fn parse_status_uid(status: &str) -> Option<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }
    None
}

/// Roots a verified-infra SCRIPT may resolve into. Mirrors
/// `sensor::detectors::is_verified_infra_process`: accept system + package
/// dirs, REJECT attacker-writable locations (`/tmp`, `/dev/shm`,
/// `/home/*/Downloads`). npm-global agent installs land under the user's home
/// (e.g. `/home/lab/.npm-global/...`) so a home path is accepted ONLY when it
/// matches the registered install dir (see [`exe_root_trusted`]).
const TRUSTED_EXE_ROOTS: &[&str] = &["/usr/", "/opt/", "/snap/", "/sbin/", "/bin/"];

/// Roots the INTERPRETER binary (`/proc/<pid>/exe`) must sit in. For an
/// interpreter-launched agent (`node X.js`, `python -m foo`) `/proc/<pid>/exe`
/// readlinks to the interpreter (`/usr/bin/node`), NOT the script. The script
/// path is where the agent identity + own-config live (derived from argv); the
/// interpreter exe is only a defense-in-depth check that the interpreter itself
/// is a system binary, never an attacker-dropped `/tmp/node`.
const TRUSTED_INTERPRETER_ROOTS: &[&str] = &["/usr/", "/bin/", "/sbin/", "/opt/", "/snap/"];

/// Credential sub-path fragments that are the USER'S secrets, never the agent's
/// own config. Reading any of these is `NotManaged` (still blocked) EVEN within
/// the agent's own home + same uid. A compromised managed agent (same uid)
/// harvesting `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.gnupg/...`, the kube /
/// docker / gcloud / gh configs, or the various dotfile token files must not buy
/// the response relaxation by virtue of running under the agent's identity. The
/// agent's own `.env` in the home root stays Managed (it does not match any
/// fragment below). Checked AFTER the own-home/install gate (see
/// [`read_path_is_own`]).
const CREDENTIAL_SUBPATH_FRAGMENTS: &[&str] = &[
    "/.ssh/",
    "/.aws/",
    "/.gnupg/",
    "/.kube/",
    "/.docker/",
    "/.config/gcloud/",
    "/.config/gh/",
    "/.netrc",
    "/.npmrc",
    "/.pypirc",
    "/.git-credentials",
];

/// True when `read_path` touches one of the high-value credential sub-paths
/// ([`CREDENTIAL_SUBPATH_FRAGMENTS`]) — the user's secrets, not the agent's
/// config. These stay `NotManaged` (blocked) even inside the agent's own home
/// with a matching uid. The `.netrc`/`.npmrc`/`.pypirc`/`.git-credentials`
/// fragments are matched as a `/`-delimited final component OR as a contained
/// fragment so both `/home/lab/.netrc` and a nested `/.netrc` hit.
fn is_credential_subpath(read_path: &str) -> bool {
    CREDENTIAL_SUBPATH_FRAGMENTS.iter().any(|frag| {
        if frag.ends_with('/') {
            // Directory fragment like `/.ssh/` — must appear as a path segment.
            read_path.contains(frag)
        } else {
            // File fragment like `/.netrc` — match the contained fragment OR a
            // trailing component (`/home/lab/.netrc`). `contains` covers both
            // since the leading `/` anchors it to a component boundary.
            read_path.contains(frag)
        }
    })
}

/// Locations an exe must NEVER resolve into, even if a later check would
/// otherwise accept it. Belt-and-braces against a registered install dir that
/// itself sits somewhere attacker-writable.
const UNTRUSTED_EXE_ROOTS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"];

/// True when `exe` resolves into a non-attacker-writable root. `install_dir` is
/// the agent's own registered install dir (from the registry `exe_path` captured
/// at connect) — a home-dir npm-global install is trusted ONLY when the live exe
/// is under that exact dir. A `/home/*/Downloads` (or any home path NOT under the
/// install dir) is rejected.
fn exe_root_trusted(exe: &str, install_dir: Option<&str>) -> bool {
    // Hard reject the always-untrusted roots first — these can never be trusted
    // regardless of what the registry recorded.
    if UNTRUSTED_EXE_ROOTS.iter().any(|r| exe.starts_with(r)) {
        return false;
    }
    // Explicit attacker-writable home sub-dir reject (Downloads, Desktop, tmp).
    if is_untrusted_home_subdir(exe) {
        return false;
    }
    // System / package roots are always trusted.
    if TRUSTED_EXE_ROOTS.iter().any(|r| exe.starts_with(r)) {
        return true;
    }
    // Otherwise the only acceptable location is UNDER the registered install
    // dir (covers npm-global home installs like /home/lab/.npm-global/...).
    if let Some(dir) = install_dir {
        if !dir.is_empty() {
            // Normalise the install dir to a directory prefix so a sibling like
            // `/home/lab/.npm-global-evil` cannot match `/home/lab/.npm-global`.
            let dir_prefix = if dir.ends_with('/') {
                dir.to_string()
            } else {
                format!("{dir}/")
            };
            return exe == dir || exe.starts_with(&dir_prefix);
        }
    }
    false
}

/// True for clearly attacker-writable home sub-dirs (`~/Downloads`, `~/Desktop`,
/// `~/tmp`). Case-insensitive on the leaf so `Downloads`/`downloads` both reject.
fn is_untrusted_home_subdir(exe: &str) -> bool {
    if !exe.starts_with("/home/") && !exe.starts_with("/root/") {
        return false;
    }
    let lower = exe.to_lowercase();
    lower.contains("/downloads/") || lower.contains("/desktop/") || lower.contains("/tmp/")
}

/// True when `read_path` is the agent's OWN config: under the agent's own home /
/// install dir AND not one of the user's high-value credential sub-paths. Both
/// the home and install dir are derived from the agent's SCRIPT path (the argv
/// token `identify_cmdline` matched), never from `/proc/<pid>/exe` (which for an
/// interpreter-launched agent is the interpreter, e.g. `/usr/bin/node`).
///
/// Reading `/etc/shadow` or `/home/other/.ssh/id_rsa` fails the own-home gate →
/// NotManaged. Reading the user's secrets EVEN within the agent's own home
/// (`/home/lab/.ssh/id_rsa`, `/home/lab/.aws/credentials`, …) is rejected by the
/// credential-subdir denylist → NotManaged. Only the agent's own `.env` /
/// install dir / own dotdir is own-config.
fn read_path_is_own(read_path: &str, home_dir: Option<&str>, install_dir: Option<&str>) -> bool {
    let under = |base: Option<&str>| -> bool {
        match base {
            Some(b) if !b.is_empty() => {
                let prefix = if b.ends_with('/') {
                    b.to_string()
                } else {
                    format!("{b}/")
                };
                read_path == b || read_path.starts_with(&prefix)
            }
            _ => false,
        }
    };
    if !(under(home_dir) || under(install_dir)) {
        return false;
    }
    // Defect 2: even within the agent's own home + same uid, the user's
    // high-value credential sub-paths are NOT the agent's config. A compromised
    // managed agent reading `~/.ssh/id_rsa`, `~/.aws/credentials`, etc. must
    // still block. `.env` in the home root passes (matches no fragment).
    !is_credential_subpath(read_path)
}

/// Derive the agent user's home dir (`/home/<user>` or `/root`) from a path.
/// Applied to the agent's SCRIPT path (the argv token, e.g.
/// `/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js`), NOT
/// `/proc/<pid>/exe` — for an interpreter-launched agent the exe is the
/// interpreter (`/usr/bin/node`), whose home is `None`, which would lose the
/// own-config binding. `None` when the script is not under a home (e.g. a `/usr`
/// install — then the own-config gate falls back to the install dir alone).
fn home_dir_from_exe(exe: &str) -> Option<String> {
    if let Some(rest) = exe.strip_prefix("/home/") {
        // `/home/<user>/...` → `/home/<user>`
        let user = rest.split('/').next().filter(|s| !s.is_empty())?;
        return Some(format!("/home/{user}"));
    }
    if exe == "/root" || exe.starts_with("/root/") {
        return Some("/root".to_string());
    }
    None
}

/// Extract the agent's identity SCRIPT PATH from live argv: the first token
/// AFTER argv[0] (the interpreter) that contains a `/`. For
/// `node /home/.../openclaw/dist/index.js gateway` that is argv[1] (the script).
/// For a directly-launched binary (`/usr/local/bin/agent serve`) argv[0] is the
/// binary itself and there is usually no later `/`-token, so this returns None —
/// in that case the caller falls back to argv[0] / the registered exe.
///
/// For `python -m <module>` agents there is no `/`-bearing script token at all →
/// None → the own-config binding cannot be derived from a script and the caller
/// fails closed when a read_path is present (acceptable per spec 081 Defect 1).
fn script_path_from_argv(argv: &[String]) -> Option<String> {
    argv.iter()
        .skip(1)
        .find(|t| t.contains('/'))
        .map(|t| t.to_string())
}

/// True when the INTERPRETER binary (`/proc/<pid>/exe`) sits in a trusted system
/// root. This is the defense-in-depth check that an interpreter-launched agent's
/// interpreter is a real system binary (`/usr/bin/node`), never a `/tmp/node`
/// the attacker dropped. The script path carries identity + own-config; the
/// interpreter only has to be trustworthy as a launcher.
fn interpreter_root_trusted(exe: &str) -> bool {
    if UNTRUSTED_EXE_ROOTS.iter().any(|r| exe.starts_with(r)) {
        return false;
    }
    if is_untrusted_home_subdir(exe) {
        return false;
    }
    TRUSTED_INTERPRETER_ROOTS.iter().any(|r| exe.starts_with(r))
}

/// True when a STANDALONE agent binary (`argv[0]`/`/proc/<pid>/exe` is the tool
/// itself, e.g. Claude Code's `~/.local/bin/claude` or
/// `~/.local/share/claude/versions/X`) sits in a trustworthy root. Unlike an
/// interpreter (which MUST be a system binary), a standalone CLI tool is
/// commonly user-installed under the home dir (`~/.local/...`, `~/.npm-global/...`,
/// `~/.bun/...`); that is trusted because the binary path is the
/// fingerprint-pinned identity (gate 2b in [`decide`]). Transient /
/// attacker-writable roots (`/tmp`, `/dev/shm`, `/var/tmp`, `~/Downloads`,
/// `~/Desktop`, `~/tmp`) are ALWAYS rejected — the same denylist the
/// interpreter/script checks use.
fn standalone_binary_root_trusted(exe: &str) -> bool {
    if UNTRUSTED_EXE_ROOTS.iter().any(|r| exe.starts_with(r)) {
        return false;
    }
    if is_untrusted_home_subdir(exe) {
        return false;
    }
    // System / package roots are always trusted.
    if TRUSTED_EXE_ROOTS.iter().any(|r| exe.starts_with(r)) {
        return true;
    }
    // A standalone tool installed under the user's home (the common case for a
    // per-user CLI). The untrusted-home-subdir reject above already excludes
    // Downloads/Desktop/tmp; the binary path itself is the pinned identity.
    exe.starts_with("/home/") || exe.starts_with("/root/")
}

/// All the inputs the pure [`decide`] core needs, already resolved. Keeping this
/// a plain struct (no `/proc`, no registry) makes every branch of the no-hole
/// logic unit-testable.
#[derive(Debug, Clone)]
pub(crate) struct DecideInputs<'a> {
    /// Registry hit: `Some(RegisteredFacts)` when `registry.by_pid(pid)` returned
    /// a ConnectedAgent. `None` = registry miss.
    pub registered: Option<RegisteredFacts>,
    /// Live `/proc` facts. `None` = pid gone / unreadable → fail closed.
    pub live: Option<ResolvedProcess>,
    /// Live signature name from `identify_cmdline(live.argv)`. `None` when the
    /// live cmdline does not identify a known agent.
    pub live_sig_name: Option<&'a str>,
    /// Live cmdline fingerprint recomputed the SAME way `capture_proc_facts`
    /// does at connect: the first-2-argv tokens joined by `|`
    /// (e.g. `/usr/bin/node|/home/lab/.../openclaw/dist/index.js`). The strong,
    /// non-forgeable backbone: it must EQUAL the registered `cmdline_fingerprint`
    /// (defeats PID-reuse and a different node app at the same pid). `None` when
    /// the live argv has no tokens (pid gone).
    pub live_cmdline_fingerprint: Option<String>,
    /// The sensitive path read by the source (incident evidence). `None` when
    /// the incident has no read-path (e.g. a pure C2 connect with no prior
    /// sensitive read). When `Some`, it must be own-config.
    pub read_path: Option<&'a str>,
    /// Owner uid of `read_path` (stat). `None` when there is no read path or the
    /// stat failed (fail closed if a read_path is present).
    pub read_path_owner_uid: Option<u32>,
    /// Destination-reputation refinement hook. When the destination is
    /// independently known-malicious (threat-feed / high-reputation), force
    /// NotManaged so the block still lands. NEVER a destination EXEMPTION — only
    /// a destination-based BLOCK override. Default false.
    pub destination_known_bad: bool,
    /// True when the live process is a STANDALONE-BINARY agent launch — argv[0]
    /// is itself a known tool binary (e.g. Claude Code's `~/.local/bin/claude`),
    /// not an interpreter+script. Computed via
    /// `SignatureIndex::is_standalone_binary_launch`. When set, the no-script
    /// branch of [`decide`] binds own-config to the agent user's HOME (from the
    /// binary path) instead of failing closed for lack of a script.
    pub live_is_standalone_binary: bool,
}

/// Registry-captured identity facts for a pid.
#[derive(Debug, Clone)]
pub(crate) struct RegisteredFacts {
    pub agent_id: String,
    pub kind: Kind,
    /// `cmdline_fingerprint` captured at connect (`interpreter|script`, the
    /// first-2-argv joined by `|`). The STRONG cross-check: the live fingerprint
    /// must EQUAL this. `None` for a pre-hardening snapshot entry — then a live
    /// fingerprint equality cannot be proven, so the verifier fails closed.
    ///
    /// (The registry also captures `exe_path` = `/proc/<pid>/exe` (the
    /// interpreter), but the verifier no longer uses it: identity is keyed on the
    /// fingerprint, and the live interpreter root is checked from the live
    /// `ResolvedProcess::exe_path`. The own-config install dir + home derive from
    /// the SCRIPT path in the live argv, not the registered exe.)
    pub cmdline_fingerprint: Option<String>,
}

/// The PURE no-hole core. Returns `Managed` ONLY if ALL signals agree; ANY
/// missing/mismatched/erroring signal → `NotManaged` (fail-closed). No `/proc`,
/// no registry, no filesystem here — every input is a resolved fact, so the 7
/// anti-evasion tests exercise it directly.
pub(crate) fn decide(inputs: &DecideInputs) -> ManagedAgentVerdict {
    // Destination-reputation override: a known-bad destination forces the block
    // regardless of source identity. This is a BLOCK override, not an exemption.
    if inputs.destination_known_bad {
        return ManagedAgentVerdict::NotManaged;
    }

    // (1) Operator-vouched: registry must have this pid as an Agent or Tool.
    let Some(reg) = inputs.registered.as_ref() else {
        return ManagedAgentVerdict::NotManaged;
    };
    if !matches!(reg.kind, Kind::Agent | Kind::Tool) {
        return ManagedAgentVerdict::NotManaged;
    }

    // (5 / fail-closed): live /proc facts must exist. pid gone / recycled →
    // block. This is the TOCTOU guard.
    let Some(live) = inputs.live.as_ref() else {
        return ManagedAgentVerdict::NotManaged;
    };

    // (2) Live cmdline re-ID: the live argv MUST identify a KNOWN agent signature
    // (defeats comm-forgery — comm=MainThread set by malware with no matching
    // cmdline). We do NOT require the resolved signature name to equal the
    // registry's stored `name`: `innerwarden agent connect <pid>` records the
    // process COMM as the name (e.g. "MainThread" for a node-launched agent),
    // while `identify_cmdline` resolves the SIGNATURE name ("OpenClaw"), so a
    // strict equality wrongly rejected a CORRECTLY-registered agent (found on the
    // Azure box: ag-0001 stored name="MainThread"). Identity is pinned instead by
    // the EXACT cmdline-fingerprint match below (2b) — which already defeats
    // pid-reuse / a different agent landing on the same pid — so the name match
    // was redundant. `live_name` (the resolved signature) becomes the audit name.
    let Some(live_name) = inputs.live_sig_name else {
        return ManagedAgentVerdict::NotManaged;
    };

    // (2b) Fingerprint equality — the STRONG, non-forgeable backbone. The live
    // `interpreter|script` fingerprint, recomputed exactly as `capture_proc_facts`
    // did at connect, must EQUAL the registered fingerprint. This defeats
    // PID-reuse and a DIFFERENT node app landing on the same pid (a recycled pid
    // running another `node X.js` re-IDs as a known signature but its fingerprint
    // differs). Fail closed if either side is missing (a pre-hardening registry
    // entry with no recorded fingerprint cannot be proven).
    let (Some(reg_fp), Some(live_fp)) = (
        reg.cmdline_fingerprint.as_deref(),
        inputs.live_cmdline_fingerprint.as_deref(),
    ) else {
        return ManagedAgentVerdict::NotManaged;
    };
    if reg_fp.is_empty() || reg_fp != live_fp {
        return ManagedAgentVerdict::NotManaged;
    }

    // Interpreter / binary path for the trusted-root checks. Prefer the
    // kernel-truth `/proc/<pid>/exe`, but FALL BACK to argv[0] when it is
    // unreadable. A NON-ROOT InnerWarden agent cannot `readlink` the
    // `/proc/<pid>/exe` of a managed agent running as a DIFFERENT user (EACCES),
    // so `exe_path` is None there — and without this fallback spec-081 silently
    // failed closed and blocked the agent's own activity (observed live on Azure:
    // IW runs as uid `innerwarden`, OpenClaw as uid `lab` → exe unreadable →
    // OpenClaw's own Azure-OpenAI endpoint got auto-blocked). The fallback is safe
    // ONLY because gate (2b) above already proved the live cmdline fingerprint
    // (argv[0]|argv[1]) EQUALS the operator-registered fingerprint, so argv[0] is
    // the vouched path, not an attacker's free-form claim. (Grant the agent
    // CAP_SYS_PTRACE to restore strict /proc/exe verification — see the unit file.)
    let interp_path: Option<&str> = live
        .exe_path
        .as_deref()
        .or_else(|| live.argv.first().map(String::as_str));

    // (S) Standalone-binary tool launch (e.g. Claude Code): argv[0] IS the
    // agent's own native binary, pinned by the (2b) fingerprint equality. There
    // is no interpreter+script, so own-config binds to the agent user's HOME
    // derived from the binary path. Handled BEFORE script extraction because a
    // flag/prompt token (`-p "edit /etc/hosts"`) may incidentally contain a `/`
    // and would otherwise be mis-read as a script path. The binary must sit in a
    // trusted root (system, or a user-install dir under the home), never a
    // transient/attacker-writable root. This is the only path that may stay
    // Managed WITH a read_path present yet without an interpreter script.
    if inputs.live_is_standalone_binary {
        let Some(exe) = interp_path else {
            return ManagedAgentVerdict::NotManaged;
        };
        if !standalone_binary_root_trusted(exe) {
            return ManagedAgentVerdict::NotManaged;
        }
        if let Some(read_path) = inputs.read_path {
            // Own-config bound to the agent user's HOME (from the binary path).
            // The credential-subpath denylist inside `read_path_is_own` still
            // blocks `~/.ssh`, `~/.aws`, … even within the agent's own home.
            let home_dir = home_dir_from_exe(exe);
            if !read_path_is_own(read_path, home_dir.as_deref(), None) {
                return ManagedAgentVerdict::NotManaged;
            }
            // The file must be owned by the SAME uid as the process.
            let (Some(proc_uid), Some(file_uid)) = (live.uid, inputs.read_path_owner_uid) else {
                return ManagedAgentVerdict::NotManaged;
            };
            if proc_uid != file_uid {
                return ManagedAgentVerdict::NotManaged;
            }
        }
        return ManagedAgentVerdict::Managed {
            agent_id: reg.agent_id.clone(),
            name: live_name.to_string(),
        };
    }

    // Identity SCRIPT PATH (Defect 1): the argv token `identify_cmdline` matched
    // — for `node X.js` it is argv[1] (the first later `/`-token). This, NOT
    // `/proc/<pid>/exe` (the interpreter), is the basis for the untrusted-root
    // rejection + home/install derivation + own-config check. A `python -m foo`
    // agent has no script token → None → fail closed when a read_path is present.
    let script_path = script_path_from_argv(&live.argv);

    // (3) Untrusted-root rejection on the SCRIPT (Defect 1): a script under
    // /tmp, /dev/shm, ~/Downloads → block even when the fingerprint+cmdline match
    // and the interpreter is trusted. The install dir is derived from the script
    // so a home npm-global install is still trusted.
    let Some(script) = script_path.as_deref() else {
        // No script path (e.g. `python -m module`): identity is the module, but
        // there is no on-disk script to root-check or to bind own-config to. The
        // interpreter must be a trusted system root, and a read_path cannot bind
        // to a script → fail closed when one is present.
        let Some(exe) = interp_path else {
            return ManagedAgentVerdict::NotManaged;
        };
        if !interpreter_root_trusted(exe) {
            return ManagedAgentVerdict::NotManaged;
        }
        if inputs.read_path.is_some() {
            return ManagedAgentVerdict::NotManaged;
        }
        return ManagedAgentVerdict::Managed {
            agent_id: reg.agent_id.clone(),
            name: live_name.to_string(),
        };
    };
    let install_dir = registered_install_dir(Some(script));
    if !exe_root_trusted(script, install_dir.as_deref()) {
        return ManagedAgentVerdict::NotManaged;
    }

    // (3b) Interpreter provenance (defense-in-depth, Defect 1): the interpreter
    // binary itself must sit in a trusted system root — never a `/tmp/node` the
    // attacker dropped. Uses `interp_path` (/proc/exe, or argv[0] when exe is
    // unreadable cross-uid — safe because the (2b) fingerprint already pinned it).
    let Some(exe) = interp_path else {
        return ManagedAgentVerdict::NotManaged;
    };
    if !interpreter_root_trusted(exe) {
        return ManagedAgentVerdict::NotManaged;
    }

    // (4) Own-config: when the incident carries a read_path it MUST be the
    // agent's own config — under the agent's own home / install dir (derived from
    // the SCRIPT path), NOT one of the user's credential sub-paths, AND owned by
    // the agent's uid. Reading /etc/shadow, another user's ~/.ssh/id_rsa, or the
    // agent-user's OWN ~/.ssh / ~/.aws / ~/.gnupg / ... → block. This is the gate
    // that keeps real credential-harvesting fully blocked.
    if let Some(read_path) = inputs.read_path {
        // Own dirs derived from the SCRIPT path: home (`/home/<user>`) + the
        // install dir (npm-global root). The interpreter exe is irrelevant here.
        let home_dir = home_dir_from_exe(script);
        if !read_path_is_own(read_path, home_dir.as_deref(), install_dir.as_deref()) {
            return ManagedAgentVerdict::NotManaged;
        }
        // Ownership: the file must be owned by the SAME uid as the process. A
        // missing process uid or missing/!= file uid → fail closed.
        let (Some(proc_uid), Some(file_uid)) = (live.uid, inputs.read_path_owner_uid) else {
            return ManagedAgentVerdict::NotManaged;
        };
        if proc_uid != file_uid {
            return ManagedAgentVerdict::NotManaged;
        }
    }

    ManagedAgentVerdict::Managed {
        agent_id: reg.agent_id.clone(),
        name: live_name.to_string(),
    }
}

/// Derive the install DIRECTORY from the agent's SCRIPT path (the argv token,
/// e.g. `/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js`). We
/// want the npm-global root so a home install is trusted. We take the path up to
/// and including the `.../node_modules/<pkg>` segment, else fall back to the
/// script's parent dir.
fn registered_install_dir(registered_exe: Option<&str>) -> Option<String> {
    let exe = registered_exe?;
    if exe.is_empty() {
        return None;
    }
    // Prefer the `.../node_modules/<pkg>` root when present (npm agents).
    if let Some(idx) = exe.find("/node_modules/") {
        // include `/node_modules/<pkg>`
        let after = &exe[idx + "/node_modules/".len()..];
        let pkg = after.split('/').next().unwrap_or("");
        if !pkg.is_empty() {
            return Some(format!("{}/node_modules/{pkg}", &exe[..idx]));
        }
        return Some(format!("{}/node_modules", &exe[..idx]));
    }
    // Otherwise use the parent directory of the exe.
    exe.rfind('/').map(|i| exe[..i].to_string())
}

/// Top-level verifier: resolves live `/proc` facts via `resolver`, cross-checks
/// the registry + signature index, then delegates to the pure [`decide`] core.
/// `destination_known_bad` is the reputation refinement hook (see [`DecideInputs`]).
///
/// Fail-closed: any resolver miss, registry miss, or signature miss yields
/// `NotManaged`. The caller withholds the auto-block / kernel-deny ONLY on
/// `Managed`.
pub(crate) fn verify_managed_agent_self_activity(
    pid: u32,
    _source_comm: &str,
    read_path: Option<&str>,
    registry: &Registry,
    sigindex: &SignatureIndex,
    resolver: &dyn ProcResolver,
    destination_known_bad: bool,
) -> ManagedAgentVerdict {
    // (1) Registry hit by pid.
    let registered = registry.by_pid(pid).map(|a| RegisteredFacts {
        agent_id: a.id.clone(),
        kind: a.kind,
        cmdline_fingerprint: a.cmdline_fingerprint.clone(),
    });

    // (5) Live /proc facts.
    let live = resolver.resolve(pid);

    // (2) Live cmdline re-ID.
    let live_sig_name = live.as_ref().and_then(|p| {
        let argv_refs: Vec<&str> = p.argv.iter().map(String::as_str).collect();
        sigindex.identify_cmdline(&argv_refs).map(|s| s.name)
    });

    // (2b) Live cmdline fingerprint — recomputed the SAME way
    // `registry::capture_proc_facts` does (first-2-argv joined by `|`). Equality
    // with the registered fingerprint is the strong non-forgeable cross-check.
    let live_cmdline_fingerprint = live.as_ref().map(|p| live_cmdline_fingerprint(&p.argv));

    // (4) Own-config owner uid (stat) when a read_path is present.
    let read_path_owner_uid = read_path.and_then(|p| resolver.file_owner_uid(p));

    // Standalone-binary launch (argv[0] is the tool itself, e.g. Claude Code).
    let live_is_standalone_binary = live
        .as_ref()
        .map(|p| {
            let argv_refs: Vec<&str> = p.argv.iter().map(String::as_str).collect();
            sigindex.is_standalone_binary_launch(&argv_refs)
        })
        .unwrap_or(false);

    let inputs = DecideInputs {
        registered,
        live,
        live_sig_name,
        live_cmdline_fingerprint,
        read_path,
        read_path_owner_uid,
        destination_known_bad,
        live_is_standalone_binary,
    };

    decide(&inputs)
}

/// Recompute the cmdline fingerprint from live argv EXACTLY as
/// `registry::capture_proc_facts` does at connect: the first two argv tokens
/// joined by `|` (e.g. `/usr/bin/node|/home/lab/.../openclaw/dist/index.js`).
/// Must stay byte-for-byte in lock-step with the registry capture, or the
/// equality cross-check in [`decide`] would never match a legit agent.
fn live_cmdline_fingerprint(argv: &[String]) -> String {
    argv.iter().take(2).cloned().collect::<Vec<_>>().join("|")
}

/// Test-only shared `/proc` stub. Promoted to `pub(crate)` (behind `cfg(test)`)
/// so the response-side wiring tests in `decision_block_ip.rs` and
/// `killchain_inline.rs` can build a prod-realistic OpenClaw resolver without
/// reaching into this module's private `tests` submodule. Seeded with per-pid
/// facts and per-path owner uids so the no-hole logic runs without a real
/// `/proc`.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{ProcResolver, ResolvedProcess};
    use std::collections::HashMap;

    /// Injectable `/proc` resolver for the anti-evasion + cross-path tests.
    #[derive(Default)]
    pub(crate) struct StubProc {
        procs: HashMap<u32, ResolvedProcess>,
        owners: HashMap<String, u32>,
    }

    impl StubProc {
        pub(crate) fn with_proc(mut self, pid: u32, p: ResolvedProcess) -> Self {
            self.procs.insert(pid, p);
            self
        }
        pub(crate) fn with_owner(mut self, path: &str, uid: u32) -> Self {
            self.owners.insert(path.to_string(), uid);
            self
        }
    }

    impl ProcResolver for StubProc {
        fn resolve(&self, pid: u32) -> Option<ResolvedProcess> {
            self.procs.get(&pid).cloned()
        }
        fn file_owner_uid(&self, path: &str) -> Option<u32> {
            self.owners.get(path).copied()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::StubProc;
    use super::*;
    use innerwarden_agent_guard::signatures::SignatureIndex;

    /// The exact live OpenClaw cmdline from the Azure dogfooding VM. argv[0] is
    /// the INTERPRETER (`/usr/bin/node`), argv[1] is the identity SCRIPT — this
    /// is what `/proc/<pid>/cmdline` really looks like in production.
    const OPENCLAW_ARGV: &[&str] = &[
        "/usr/bin/node",
        "/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js",
        "gateway",
        "--port",
        "18789",
    ];

    /// What `/proc/<pid>/exe` REALLY readlinks to in production: the node
    /// interpreter, NOT the script. (The prior tests faked this as the script
    /// path, which never happens for an interpreter-launched agent.)
    const OPENCLAW_INTERP: &str = "/usr/bin/node";

    /// The identity SCRIPT path (argv[1]). Home/install-dir + own-config derive
    /// from THIS, not from `/proc/<pid>/exe`.
    const OPENCLAW_SCRIPT: &str = "/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js";

    /// The cmdline fingerprint the hardened `connect()` records: the first-2-argv
    /// (`interpreter|script`) joined by `|`. The verifier recomputes the live
    /// fingerprint the same way and requires equality.
    fn openclaw_fingerprint() -> String {
        format!("{OPENCLAW_INTERP}|{OPENCLAW_SCRIPT}")
    }

    fn openclaw_proc(uid: u32) -> ResolvedProcess {
        ResolvedProcess {
            argv: OPENCLAW_ARGV.iter().map(|s| s.to_string()).collect(),
            // REAL prod: /proc/<pid>/exe is the interpreter.
            exe_path: Some(OPENCLAW_INTERP.to_string()),
            uid: Some(uid),
        }
    }

    /// A registry that vouches for OpenClaw at `pid` with the hardened
    /// exe_path (interpreter) / owner_uid / cmdline_fingerprint captured exactly
    /// as production `connect()` would.
    fn registry_with_openclaw(pid: u32) -> Registry {
        let mut reg = Registry::new();
        reg.connect_with_facts(
            "OpenClaw",
            pid,
            Some("ag-test"),
            Some(OPENCLAW_INTERP.to_string()),
            Some(1000),
            Some(openclaw_fingerprint()),
        )
        .expect("connect");
        reg
    }

    fn verify(
        pid: u32,
        read_path: Option<&str>,
        reg: &Registry,
        proc: &StubProc,
    ) -> ManagedAgentVerdict {
        let sigindex = SignatureIndex::new();
        verify_managed_agent_self_activity(
            pid,
            "MainThread",
            read_path,
            reg,
            &sigindex,
            proc,
            false,
        )
    }

    /// A registry whose stored `name` is the process COMM ("MainThread"), kind
    /// Tool — EXACTLY what `innerwarden agent connect <pid>` records for a
    /// node-launched agent in production (verified on the Azure box: ag-0001).
    fn registry_with_comm_named_openclaw(pid: u32) -> Registry {
        let mut reg = Registry::new();
        reg.connect_with_facts(
            "MainThread", // ← the COMM, not the signature name
            pid,
            Some("ag-0001"),
            Some(OPENCLAW_INTERP.to_string()),
            Some(1000),
            Some(openclaw_fingerprint()),
        )
        .expect("connect");
        reg
    }

    /// Regression (found deploying 0.15.16 to the Azure box, 2026-06-18):
    /// `agent connect <pid>` stores the process COMM ("MainThread") as the
    /// registry `name`, while `identify_cmdline` resolves the SIGNATURE name
    /// ("OpenClaw"). The earlier verifier required `live_sig_name == reg.name`,
    /// which wrongly BLOCKED a correctly-registered OpenClaw (the prior tests used
    /// `connect_with_facts("OpenClaw", …)` and masked it). The verifier must now
    /// resolve it as Managed — identity is pinned by the cmdline-fingerprint, not
    /// the stored name — and surface the RESOLVED signature name in the audit.
    #[test]
    fn comm_named_registry_entry_is_still_managed() {
        let pid = 4242;
        let reg = registry_with_comm_named_openclaw(pid);
        let stub = StubProc::default()
            .with_proc(pid, openclaw_proc(1000))
            .with_owner("/home/lab/.env", 1000);
        match verify(pid, Some("/home/lab/.env"), &reg, &stub) {
            ManagedAgentVerdict::Managed { name, agent_id } => {
                assert_eq!(name, "OpenClaw", "audit name must resolve to the signature");
                assert!(
                    agent_id.starts_with("ag-"),
                    "agent_id is the registry-minted id, got {agent_id}"
                );
            }
            other => panic!("comm-named registry entry must be Managed, got {other:?}"),
        }
    }

    /// Regression (FP found LIVE on Azure, 2026-06-21): a NON-ROOT InnerWarden
    /// agent (uid `innerwarden`) cannot `readlink /proc/<pid>/exe` of a managed
    /// agent running as a DIFFERENT user (OpenClaw as uid `lab`) — EACCES → the
    /// resolver returns `exe_path: None`. The verifier required `/proc/exe` for the
    /// interpreter-root check and silently failed closed → OpenClaw read its own
    /// `.env` then called its own Azure-OpenAI endpoint and InnerWarden BLOCKED the
    /// endpoint. With the argv[0] fallback (safe because the cmdline fingerprint
    /// already matched the registered one), the verified agent is Managed.
    #[test]
    fn cross_uid_unreadable_exe_falls_back_to_argv0_and_is_managed() {
        let pid = 4242;
        let reg = registry_with_openclaw(pid);
        let proc_no_exe = ResolvedProcess {
            argv: OPENCLAW_ARGV.iter().map(|s| s.to_string()).collect(),
            exe_path: None, // non-root IW agent cannot readlink another uid's /proc/exe
            uid: Some(1000),
        };
        let stub = StubProc::default()
            .with_proc(pid, proc_no_exe)
            .with_owner("/home/lab/.env", 1000);
        assert!(
            verify(pid, Some("/home/lab/.env"), &reg, &stub).is_managed(),
            "registered agent with a matching fingerprint must be Managed even when \
             /proc/exe is unreadable (cross-uid, non-root IW) — argv[0] fallback"
        );
    }

    /// The argv[0] fallback must NOT weaken the trusted-root gate: an untrusted
    /// interpreter path (e.g. argv[0]=/tmp/node) still BLOCKS even with exe None.
    /// (In practice the (2b) fingerprint would already differ, but guard the gate.)
    #[test]
    fn cross_uid_unreadable_exe_with_untrusted_argv0_still_blocks() {
        let pid = 4242;
        let mut reg = Registry::new();
        // Register with a /tmp interpreter fingerprint so (2b) matches the live one.
        reg.connect_with_facts(
            "OpenClaw",
            pid,
            Some("ag-test"),
            None,
            Some(1000),
            Some(format!("/tmp/node|{OPENCLAW_SCRIPT}")),
        )
        .expect("connect");
        let proc = ResolvedProcess {
            argv: vec!["/tmp/node".into(), OPENCLAW_SCRIPT.into(), "gateway".into()],
            exe_path: None,
            uid: Some(1000),
        };
        let stub = StubProc::default()
            .with_proc(pid, proc)
            .with_owner("/home/lab/.env", 1000);
        assert_eq!(
            verify(pid, Some("/home/lab/.env"), &reg, &stub),
            ManagedAgentVerdict::NotManaged,
            "an untrusted interpreter (argv[0]=/tmp/node) must still BLOCK"
        );
    }

    /// The name-equality was redundant with the fingerprint pin, NOT a relaxation:
    /// even with the comm-named entry, a DIFFERENT script at the same pid (still
    /// identifies as OpenClaw by path component, but a different fingerprint) must
    /// still BLOCK. Proves the cmdline-fingerprint — not the name — is the pin.
    #[test]
    fn comm_named_entry_with_wrong_fingerprint_blocks() {
        let pid = 4242;
        let reg = registry_with_comm_named_openclaw(pid);
        let evil = ResolvedProcess {
            argv: vec![
                "/usr/bin/node".into(),
                // identifies as OpenClaw (path component) but a DIFFERENT script
                "/home/lab/.npm-global/lib/node_modules/openclaw/dist/evil.js".into(),
            ],
            exe_path: Some("/usr/bin/node".into()),
            uid: Some(1000),
        };
        let stub = StubProc::default().with_proc(pid, evil);
        assert_eq!(
            verify(pid, None, &reg, &stub),
            ManagedAgentVerdict::NotManaged,
            "comm-named entry must still BLOCK when the live fingerprint differs"
        );
    }

    // ── 7 required anti-evasion tests (spec 081) ──────────────────────────

    /// (1) Registered pid but live cmdline does NOT match the signature → BLOCKS.
    /// PID-reuse / spoof: the registry still vouches for the pid, but the live
    /// process is now `node /srv/evil.js` which does not identify as OpenClaw.
    #[test]
    fn t1_registered_pid_but_live_cmdline_mismatch_blocks() {
        let pid = 4001;
        let reg = registry_with_openclaw(pid);
        // Live process at the same pid is now an UNRELATED node app.
        let evil = ResolvedProcess {
            argv: vec!["/usr/bin/node".into(), "/srv/app/server.js".into()],
            exe_path: Some("/usr/bin/node".into()),
            uid: Some(1000),
        };
        let proc = StubProc::default().with_proc(pid, evil);
        let verdict = verify(pid, None, &reg, &proc);
        assert_eq!(
            verdict,
            ManagedAgentVerdict::NotManaged,
            "live cmdline that does not re-identify the registered agent must BLOCK"
        );
    }

    /// (2) Registered agent reads a NON-own path (/etc/shadow, other user's
    /// .ssh) → BLOCKS. This is the gate that keeps real credential-harvesting
    /// fully blocked even for a genuinely-running managed agent.
    #[test]
    fn t2_registered_agent_reads_non_own_path_blocks() {
        let pid = 4002;
        let reg = registry_with_openclaw(pid);
        let proc = StubProc::default()
            .with_proc(pid, openclaw_proc(1000))
            // /etc/shadow is owned by root (uid 0), not the agent.
            .with_owner("/etc/shadow", 0)
            .with_owner("/home/other/.ssh/id_rsa", 1001);

        // /etc/shadow — not under the agent's own dir AND not owned by it.
        assert_eq!(
            verify(pid, Some("/etc/shadow"), &reg, &proc),
            ManagedAgentVerdict::NotManaged,
            "managed agent reading /etc/shadow must BLOCK"
        );
        // Another user's SSH key — outside the agent's home, owned by uid 1001.
        assert_eq!(
            verify(pid, Some("/home/other/.ssh/id_rsa"), &reg, &proc),
            ManagedAgentVerdict::NotManaged,
            "managed agent reading another user's SSH key must BLOCK"
        );
    }

    /// (3) Unregistered `node evil.js` reads `.env` → BLOCKS. No registry hit at
    /// all, so the operator never vouched for it.
    #[test]
    fn t3_unregistered_node_reads_env_blocks() {
        let pid = 4003;
        let reg = Registry::new(); // nobody registered.
        let proc = StubProc::default()
            .with_proc(
                pid,
                ResolvedProcess {
                    argv: vec!["/usr/bin/node".into(), "/tmp/evil.js".into()],
                    exe_path: Some("/usr/bin/node".into()),
                    uid: Some(1000),
                },
            )
            .with_owner("/home/lab/.env", 1000);
        assert_eq!(
            verify(pid, Some("/home/lab/.env"), &reg, &proc),
            ManagedAgentVerdict::NotManaged,
            "unregistered process must BLOCK regardless of what it reads"
        );
    }

    /// (4) pid recycled / exited between incident and `/proc` read → fail-closed
    /// BLOCKS. The registry still has the entry, but the live resolver returns
    /// None (TOCTOU).
    #[test]
    fn t4_pid_recycled_or_gone_fails_closed_blocks() {
        let pid = 4004;
        let reg = registry_with_openclaw(pid);
        // Resolver has NO facts for this pid → resolve() returns None.
        let proc = StubProc::default();
        assert_eq!(
            verify(pid, None, &reg, &proc),
            ManagedAgentVerdict::NotManaged,
            "a pid with no live /proc facts must fail closed and BLOCK"
        );
    }

    /// (5) malware sets `comm=MainThread`, no matching cmdline/exe → BLOCKS.
    /// comm is forgeable; the live cmdline does not identify a known agent and
    /// there is no registry hit, so the multi-signal AND rejects it.
    #[test]
    fn t5_forged_comm_no_matching_cmdline_blocks() {
        let pid = 4005;
        let reg = Registry::new(); // not registered.
                                   // comm would be "MainThread" (passed to verify) but the cmdline is a
                                   // bare malicious binary that identify_cmdline cannot match.
        let proc = StubProc::default().with_proc(
            pid,
            ResolvedProcess {
                argv: vec!["/tmp/.x/stealer".into()],
                exe_path: Some("/tmp/.x/stealer".into()),
                uid: Some(1000),
            },
        );
        assert_eq!(
            verify(pid, None, &reg, &proc),
            ManagedAgentVerdict::NotManaged,
            "forged comm with no matching cmdline/exe and no registry hit must BLOCK"
        );
    }

    /// (6) SCRIPT in `/tmp` even though the INTERPRETER exe is the trusted
    /// `/usr/bin/node` → BLOCKS (Defect 1: the untrusted-root rejection is on the
    /// SCRIPT, not the interpreter). The attacker copied a script under /tmp and
    /// launches it with the real node binary; the cmdline re-IDs OpenClaw and the
    /// registry fingerprint matches, so the ONLY thing that rejects is the
    /// script-root gate. This is the realistic prod shape — previously the test
    /// faked exe=script which made the gate trivially fire on the interpreter.
    #[test]
    fn t6_script_in_untrusted_root_blocks_even_with_trusted_interpreter() {
        let pid = 4006;
        let tmp_script = "/tmp/openclaw/dist/index.js";
        // Registry fingerprint MUST match the live cmdline so we get PAST the
        // fingerprint cross-check and actually exercise the script-root gate.
        let mut reg = Registry::new();
        reg.connect_with_facts(
            "OpenClaw",
            pid,
            Some("ag-test"),
            // /proc/exe is the trusted interpreter — NOT the attacker's script.
            Some(OPENCLAW_INTERP.to_string()),
            Some(1000),
            Some(format!("/usr/bin/node|{tmp_script}")),
        )
        .expect("connect");
        // Live cmdline: trusted interpreter, but the SCRIPT (argv[1]) is /tmp.
        let proc = StubProc::default().with_proc(
            pid,
            ResolvedProcess {
                argv: vec!["/usr/bin/node".into(), tmp_script.into(), "gateway".into()],
                exe_path: Some(OPENCLAW_INTERP.to_string()), // trusted interpreter
                uid: Some(1000),
            },
        );
        assert_eq!(
            verify(pid, None, &reg, &proc),
            ManagedAgentVerdict::NotManaged,
            "a SCRIPT under /tmp must BLOCK even when the interpreter is the trusted /usr/bin/node \
             and the cmdline re-identifies the agent (untrusted-root check is on the script)"
        );
    }

    /// Also reject a SCRIPT under /dev/shm (trusted interpreter, matching
    /// fingerprint, /dev/shm script) explicitly.
    #[test]
    fn t6b_script_in_dev_shm_blocks() {
        let pid = 4016;
        let shm_script = "/dev/shm/openclaw/dist/index.js";
        let mut reg = Registry::new();
        reg.connect_with_facts(
            "OpenClaw",
            pid,
            Some("ag-test"),
            Some(OPENCLAW_INTERP.to_string()),
            Some(1000),
            Some(format!("/usr/bin/node|{shm_script}")),
        )
        .expect("connect");
        let proc = StubProc::default().with_proc(
            pid,
            ResolvedProcess {
                argv: vec!["/usr/bin/node".into(), shm_script.into()],
                exe_path: Some(OPENCLAW_INTERP.to_string()),
                uid: Some(1000),
            },
        );
        assert_eq!(
            verify(pid, None, &reg, &proc),
            ManagedAgentVerdict::NotManaged,
            "a SCRIPT under /dev/shm must BLOCK even with a trusted interpreter"
        );
    }

    /// Defect 1 defense-in-depth: even if the SCRIPT path is trusted and the
    /// fingerprint matches, an attacker-dropped INTERPRETER (`/tmp/node`) must
    /// BLOCK. The interpreter-root check rejects a non-system launcher.
    #[test]
    fn t6c_untrusted_interpreter_blocks_even_with_trusted_script() {
        let pid = 4026;
        let mut reg = Registry::new();
        reg.connect_with_facts(
            "OpenClaw",
            pid,
            Some("ag-test"),
            Some("/tmp/node".to_string()),
            Some(1000),
            Some(format!("/tmp/node|{OPENCLAW_SCRIPT}")),
        )
        .expect("connect");
        let proc = StubProc::default().with_proc(
            pid,
            ResolvedProcess {
                argv: vec!["/tmp/node".into(), OPENCLAW_SCRIPT.into(), "gateway".into()],
                exe_path: Some("/tmp/node".into()), // attacker-dropped interpreter
                uid: Some(1000),
            },
        );
        assert_eq!(
            verify(pid, None, &reg, &proc),
            ManagedAgentVerdict::NotManaged,
            "an interpreter under /tmp must BLOCK even when the script path is trusted"
        );
    }

    /// (7) Positive: real OpenClaw (registered, live cmdline matches, exe in
    /// npm-global home install, reads its OWN /home/lab/.env owned by its uid) →
    /// Managed → IP-block + kernel-block WITHHELD; incident + notify still fire.
    #[test]
    fn t7_real_registered_openclaw_reading_own_env_is_managed() {
        let pid = 4007;
        let reg = registry_with_openclaw(pid);
        let proc = StubProc::default()
            .with_proc(pid, openclaw_proc(1000))
            // The agent's own .env in its home, owned by the agent's uid 1000.
            .with_owner("/home/lab/.env", 1000);

        let verdict = verify(pid, Some("/home/lab/.env"), &reg, &proc);
        match verdict {
            ManagedAgentVerdict::Managed { name, agent_id } => {
                assert_eq!(name, "OpenClaw");
                // `agent_id` is the registry-minted id (ag-NNNN), not the
                // instance label — assert the shape so the audit line is keyed
                // on the real agent id the operator sees in the dashboard.
                assert!(
                    agent_id.starts_with("ag-"),
                    "agent_id should be the minted registry id, got {agent_id}"
                );
            }
            other => panic!("expected Managed for real OpenClaw self-activity, got {other:?}"),
        }
    }

    /// Defect 1 — PROD-REALISTIC positive: the REAL OpenClaw exactly as it runs
    /// on the box. `/proc/<pid>/exe` = `/usr/bin/node` (the interpreter), the
    /// identity script lives in argv[1], the registry fingerprint is
    /// `/usr/bin/node|<script>`, and the live fingerprint matches. It reads its
    /// OWN `/home/lab/.env`. This is the case the prior tests faked (exe=script)
    /// and so passed while production stayed BROKEN. It MUST be Managed now.
    #[test]
    fn t7b_prod_realistic_openclaw_exe_is_node_reads_own_env_is_managed() {
        let pid = 4017;
        let reg = registry_with_openclaw(pid);
        // Prove the fixture is the real prod shape: exe is the interpreter.
        let proc = openclaw_proc(1000);
        assert_eq!(
            proc.exe_path.as_deref(),
            Some("/usr/bin/node"),
            "prod /proc/exe must be the node interpreter, not the script"
        );
        let stub = StubProc::default()
            .with_proc(pid, proc)
            .with_owner("/home/lab/.env", 1000);
        let verdict = verify(pid, Some("/home/lab/.env"), &reg, &stub);
        assert!(
            verdict.is_managed(),
            "the REAL OpenClaw (exe=/usr/bin/node, script in argv) reading its own \
             /home/lab/.env must be Managed — was BROKEN in prod before Defect 1 fix"
        );
    }

    /// Defect 2 — credential sub-path denylist: a registered, live-verified
    /// OpenClaw (own uid) reading the USER'S high-value secrets inside its own
    /// home must STILL BLOCK. `~/.ssh/id_rsa`, `~/.aws/credentials`,
    /// `~/.gnupg/...`, `~/.kube/config`, `~/.docker/config.json`,
    /// `~/.config/gcloud/...`, `~/.netrc`, `~/.git-credentials` are the user's
    /// secrets, not the agent's config. `/home/lab/.env` (home-root) stays
    /// Managed.
    #[test]
    fn t_credential_subdir_within_own_home_blocks() {
        let pid = 4018;
        let reg = registry_with_openclaw(pid);
        let cred_paths = [
            "/home/lab/.ssh/id_rsa",
            "/home/lab/.aws/credentials",
            "/home/lab/.gnupg/secring.gpg",
            "/home/lab/.kube/config",
            "/home/lab/.docker/config.json",
            "/home/lab/.config/gcloud/credentials.db",
            "/home/lab/.config/gh/hosts.yml",
            "/home/lab/.netrc",
            "/home/lab/.npmrc",
            "/home/lab/.pypirc",
            "/home/lab/.git-credentials",
        ];
        for p in cred_paths {
            // Every credential file is owned by the agent's OWN uid (1000) — the
            // own-uid gate passes; ONLY the credential-subdir denylist rejects.
            let stub = StubProc::default()
                .with_proc(pid, openclaw_proc(1000))
                .with_owner(p, 1000);
            assert_eq!(
                verify(pid, Some(p), &reg, &stub),
                ManagedAgentVerdict::NotManaged,
                "managed agent (own uid) reading its user's secret {p} must BLOCK \
                 (credential-subdir denylist), even inside its own home"
            );
        }

        // Control: the agent's own `.env` in the home root is NOT a credential
        // sub-path → stays Managed.
        let env_stub = StubProc::default()
            .with_proc(pid, openclaw_proc(1000))
            .with_owner("/home/lab/.env", 1000);
        assert!(
            verify(pid, Some("/home/lab/.env"), &reg, &env_stub).is_managed(),
            "/home/lab/.env (the agent's own config) must stay Managed"
        );
    }

    /// Pure-helper coverage for the credential-subdir predicate.
    #[test]
    fn is_credential_subpath_matches_user_secrets_not_env() {
        assert!(is_credential_subpath("/home/lab/.ssh/id_rsa"));
        assert!(is_credential_subpath("/home/lab/.aws/credentials"));
        assert!(is_credential_subpath("/home/lab/.config/gcloud/x"));
        assert!(is_credential_subpath("/home/lab/.config/gh/hosts.yml"));
        assert!(is_credential_subpath("/home/lab/.netrc"));
        assert!(is_credential_subpath("/home/lab/.git-credentials"));
        // The agent's own config files are NOT credential sub-paths.
        assert!(!is_credential_subpath("/home/lab/.env"));
        assert!(!is_credential_subpath("/home/lab/.openclaw/config.json"));
        assert!(!is_credential_subpath(
            "/home/lab/.npm-global/lib/node_modules/openclaw/dist/index.js"
        ));
        // A non-gcloud .config path is fine (only gcloud/gh are credential dirs).
        assert!(!is_credential_subpath(
            "/home/lab/.config/openclaw/settings"
        ));
    }

    /// Defect 1 — `python -m <module>` agent has no script path: when a read_path
    /// is present, own-config cannot be bound → fail closed (BLOCK). Reflects the
    /// spec note that this is acceptable.
    #[test]
    fn python_dash_m_module_with_read_path_fails_closed() {
        let pid = 4019;
        let mut reg = Registry::new();
        // Aider via `python -m aider` — identity is the module, no script token.
        let fp = "/usr/bin/python3|-m";
        reg.connect_with_facts(
            "Aider",
            pid,
            Some("ag-aider"),
            Some("/usr/bin/python3".to_string()),
            Some(1000),
            Some(fp.to_string()),
        )
        .expect("connect");
        let proc = ResolvedProcess {
            argv: vec!["/usr/bin/python3".into(), "-m".into(), "aider".into()],
            exe_path: Some("/usr/bin/python3".into()),
            uid: Some(1000),
        };
        let stub = StubProc::default()
            .with_proc(pid, proc)
            .with_owner("/home/lab/.env", 1000);
        // A read_path is present but there is no script to bind own-config to.
        assert_eq!(
            verify(pid, Some("/home/lab/.env"), &reg, &stub),
            ManagedAgentVerdict::NotManaged,
            "python -m module agent with a read_path must fail closed (no script binding)"
        );
    }

    /// Defect 1 — a DIFFERENT node app recycled onto the same pid (re-IDs a known
    /// signature, trusted interpreter, but fingerprint differs from the
    /// registered one) must BLOCK on the fingerprint cross-check.
    #[test]
    fn t_fingerprint_mismatch_different_node_app_blocks() {
        let pid = 4020;
        let reg = registry_with_openclaw(pid);
        // A DIFFERENT openclaw-named script path at the same pid: identify_cmdline
        // still re-IDs OpenClaw (the `openclaw` path component), interpreter is
        // trusted, but the fingerprint (`/usr/bin/node|/opt/openclaw/other.js`)
        // does NOT equal the registered one → block.
        let proc = ResolvedProcess {
            argv: vec![
                "/usr/bin/node".into(),
                "/opt/openclaw/other.js".into(),
                "gateway".into(),
            ],
            exe_path: Some("/usr/bin/node".into()),
            uid: Some(1000),
        };
        let stub = StubProc::default().with_proc(pid, proc);
        assert_eq!(
            verify(pid, None, &reg, &stub),
            ManagedAgentVerdict::NotManaged,
            "a different node app at the same pid (fingerprint mismatch) must BLOCK"
        );
    }

    /// Defect 1 — a pre-hardening registry entry with NO cmdline_fingerprint
    /// cannot prove fingerprint equality → fail closed (BLOCK), even for an
    /// otherwise-perfect live OpenClaw.
    #[test]
    fn t_no_registered_fingerprint_fails_closed() {
        let pid = 4021;
        let mut reg = Registry::new();
        reg.connect_with_facts(
            "OpenClaw",
            pid,
            Some("ag-test"),
            Some(OPENCLAW_INTERP.to_string()),
            Some(1000),
            None, // pre-hardening: no fingerprint recorded
        )
        .expect("connect");
        let stub = StubProc::default().with_proc(pid, openclaw_proc(1000));
        assert_eq!(
            verify(pid, None, &reg, &stub),
            ManagedAgentVerdict::NotManaged,
            "a registry entry without a cmdline_fingerprint must fail closed"
        );
    }

    // ── Supporting unit coverage for the pure helpers + refinement hook ───

    /// The positive case with NO read_path (pure C2 connect after the agent
    /// opens its own socket) is still Managed — the own-config gate only applies
    /// when a read_path is present.
    #[test]
    fn managed_when_no_read_path_present() {
        let pid = 4008;
        let reg = registry_with_openclaw(pid);
        let proc = StubProc::default().with_proc(pid, openclaw_proc(1000));
        assert!(verify(pid, None, &reg, &proc).is_managed());
    }

    /// Own-config path present but file owned by a DIFFERENT uid than the
    /// process → BLOCK (defeats a symlink/owner mismatch).
    #[test]
    fn own_path_but_wrong_owner_uid_blocks() {
        let pid = 4009;
        let reg = registry_with_openclaw(pid);
        let proc = StubProc::default()
            .with_proc(pid, openclaw_proc(1000))
            // .env lives under the agent home but is owned by root (planted).
            .with_owner("/home/lab/.env", 0);
        assert_eq!(
            verify(pid, Some("/home/lab/.env"), &reg, &proc),
            ManagedAgentVerdict::NotManaged,
            "own-dir path owned by a different uid must BLOCK"
        );
    }

    /// destination_known_bad forces NotManaged even for an otherwise-perfect
    /// managed agent — the reputation refinement hook. NOT a destination
    /// exemption; a BLOCK override.
    #[test]
    fn destination_known_bad_forces_block_even_for_managed_agent() {
        let pid = 4010;
        let reg = registry_with_openclaw(pid);
        let proc = StubProc::default()
            .with_proc(pid, openclaw_proc(1000))
            .with_owner("/home/lab/.env", 1000);
        let sigindex = SignatureIndex::new();
        let verdict = verify_managed_agent_self_activity(
            pid,
            "MainThread",
            Some("/home/lab/.env"),
            &reg,
            &sigindex,
            &proc,
            true, // destination known-malicious
        );
        assert_eq!(
            verdict,
            ManagedAgentVerdict::NotManaged,
            "a known-bad destination must force the block even for a managed agent"
        );
    }

    /// A registry entry whose kind is `Runtime` (e.g. Ollama) is NOT eligible —
    /// only operator-installed Agent/Tool kinds get the response relaxation.
    #[test]
    fn runtime_kind_is_not_eligible() {
        let pid = 4011;
        let mut reg = Registry::new();
        // ollama is Kind::Runtime.
        reg.connect_with_facts(
            "ollama",
            pid,
            Some("ag-rt"),
            Some("/usr/local/bin/ollama".to_string()),
            Some(1000),
            None,
        )
        .expect("connect");
        let proc = StubProc::default().with_proc(
            pid,
            ResolvedProcess {
                argv: vec!["/usr/local/bin/ollama".into(), "serve".into()],
                exe_path: Some("/usr/local/bin/ollama".into()),
                uid: Some(1000),
            },
        );
        // Even though ollama is a known signature, Runtime kind is rejected.
        assert_eq!(
            verify(pid, None, &reg, &proc),
            ManagedAgentVerdict::NotManaged
        );
    }

    // ── Standalone-binary agent (Claude Code) — spec 081 coexistence ─────────
    // Claude Code 2.x ships as a NATIVE binary launched directly. The real
    // cmdline observed on a host: `/home/lab/.local/bin/claude -p "..."`, with
    // `/proc/<pid>/exe` -> `/home/lab/.local/share/claude/versions/X`. There is
    // no interpreter+script, so identity binds to the binary path + the home.
    const CLAUDE_BIN: &str = "/home/lab/.local/bin/claude";
    const CLAUDE_EXE: &str = "/home/lab/.local/share/claude/versions/2.1.195";

    /// first-2-argv joined by `|`, exactly as `capture_proc_facts` records.
    fn claude_fingerprint() -> String {
        format!("{CLAUDE_BIN}|-p")
    }

    /// `exe_readable=false` models the common cross-uid case: IW (uid
    /// `innerwarden`) cannot readlink a `lab`-owned `/proc/<pid>/exe`, so
    /// `exe_path` is None and the verifier falls back to argv[0].
    fn claude_proc(uid: u32, exe_readable: bool) -> ResolvedProcess {
        ResolvedProcess {
            argv: vec![CLAUDE_BIN.into(), "-p".into(), "do a task".into()],
            exe_path: exe_readable.then(|| CLAUDE_EXE.to_string()),
            uid: Some(uid),
        }
    }

    fn registry_with_claude(pid: u32) -> Registry {
        let mut reg = Registry::new();
        reg.connect_with_facts(
            "Claude Code",
            pid,
            Some("ag-cc"),
            Some(CLAUDE_BIN.to_string()),
            Some(1000),
            Some(claude_fingerprint()),
        )
        .expect("connect claude");
        reg
    }

    /// THE FP THIS PR KILLS: Claude Code reads its OWN config then calls its LLM
    /// endpoint; IW sees sensitive_read -> outbound_connect and would auto-block.
    /// The verifier must return Managed (withhold the block, keep the incident).
    /// Cross-uid case: `/proc/<pid>/exe` unreadable -> argv[0] fallback.
    #[test]
    fn standalone_claude_reading_own_config_is_managed() {
        let pid = 7001;
        let reg = registry_with_claude(pid);
        let proc = StubProc::default()
            .with_proc(pid, claude_proc(1000, false))
            .with_owner("/home/lab/.claude/settings.json", 1000);
        // agent_id is an auto-generated, test-order-volatile `ag-xxxx`; assert the
        // verdict + the resolved signature name, not the id.
        assert!(matches!(
            verify(pid, Some("/home/lab/.claude/settings.json"), &reg, &proc),
            ManagedAgentVerdict::Managed { ref name, .. } if name == "Claude Code"
        ));
    }

    /// Same, with a readable exe under `~/.local/share/claude/versions/...`.
    #[test]
    fn standalone_claude_readable_exe_own_config_is_managed() {
        let pid = 7002;
        let reg = registry_with_claude(pid);
        let proc = StubProc::default()
            .with_proc(pid, claude_proc(1000, true))
            .with_owner("/home/lab/.config/innerwarden/agent.env", 1000);
        assert!(matches!(
            verify(
                pid,
                Some("/home/lab/.config/innerwarden/agent.env"),
                &reg,
                &proc
            ),
            ManagedAgentVerdict::Managed { .. }
        ));
    }

    /// Pure C2-connect (no read_path) from a trusted standalone binary -> Managed.
    #[test]
    fn standalone_claude_no_read_path_is_managed() {
        let pid = 7003;
        let reg = registry_with_claude(pid);
        let proc = StubProc::default().with_proc(pid, claude_proc(1000, false));
        assert!(matches!(
            verify(pid, None, &reg, &proc),
            ManagedAgentVerdict::Managed { .. }
        ));
    }

    // ── Anti-evasion: a standalone binary must NEVER buy these exemptions ────

    /// Reading the user's SSH key (credential subpath) stays BLOCKED even though
    /// it is under the agent's own home + same uid.
    #[test]
    fn standalone_claude_reading_ssh_key_blocks() {
        let pid = 7004;
        let reg = registry_with_claude(pid);
        let proc = StubProc::default()
            .with_proc(pid, claude_proc(1000, false))
            .with_owner("/home/lab/.ssh/id_rsa", 1000);
        assert_eq!(
            verify(pid, Some("/home/lab/.ssh/id_rsa"), &reg, &proc),
            ManagedAgentVerdict::NotManaged,
        );
    }

    /// A `claude`-named binary dropped in /tmp (transient root) is NEVER trusted.
    #[test]
    fn standalone_claude_binary_in_tmp_blocks() {
        let pid = 7005;
        let mut reg = Registry::new();
        reg.connect_with_facts(
            "Claude Code",
            pid,
            Some("ag-cc"),
            Some("/tmp/claude".to_string()),
            Some(1000),
            Some("/tmp/claude|-p".to_string()),
        )
        .expect("connect");
        let proc = StubProc::default().with_proc(
            pid,
            ResolvedProcess {
                argv: vec!["/tmp/claude".into(), "-p".into(), "x".into()],
                exe_path: None,
                uid: Some(1000),
            },
        );
        assert_eq!(
            verify(pid, None, &reg, &proc),
            ManagedAgentVerdict::NotManaged
        );
    }

    /// Reading ANOTHER user's home fails the own-home gate.
    #[test]
    fn standalone_claude_reading_other_home_blocks() {
        let pid = 7006;
        let reg = registry_with_claude(pid);
        let proc = StubProc::default()
            .with_proc(pid, claude_proc(1000, false))
            .with_owner("/home/victim/.config/x", 1000);
        assert_eq!(
            verify(pid, Some("/home/victim/.config/x"), &reg, &proc),
            ManagedAgentVerdict::NotManaged,
        );
    }

    /// Own-home read but the file is owned by a DIFFERENT uid -> BLOCK (a planted
    /// file / symlink-owner mismatch).
    #[test]
    fn standalone_claude_own_config_wrong_owner_blocks() {
        let pid = 7007;
        let reg = registry_with_claude(pid);
        let proc = StubProc::default()
            .with_proc(pid, claude_proc(1000, false))
            .with_owner("/home/lab/.claude/settings.json", 0); // root-owned
        assert_eq!(
            verify(pid, Some("/home/lab/.claude/settings.json"), &reg, &proc),
            ManagedAgentVerdict::NotManaged,
        );
    }

    /// A fingerprint mismatch (pid-reuse / a different launch on the same pid)
    /// -> BLOCK, even for a standalone binary.
    #[test]
    fn standalone_claude_fingerprint_mismatch_blocks() {
        let pid = 7008;
        let reg = registry_with_claude(pid); // registered fp = ".../claude|-p"
                                             // Live argv differs (argv[1] is `mcp`, not `-p`) so live fp != registered.
        let proc = StubProc::default().with_proc(
            pid,
            ResolvedProcess {
                argv: vec![CLAUDE_BIN.into(), "mcp".into(), "serve".into()],
                exe_path: None,
                uid: Some(1000),
            },
        );
        assert_eq!(
            verify(pid, None, &reg, &proc),
            ManagedAgentVerdict::NotManaged
        );
    }

    /// destination_known_bad forces the block even for a perfect standalone agent.
    #[test]
    fn standalone_claude_known_bad_destination_blocks() {
        let pid = 7009;
        let reg = registry_with_claude(pid);
        let proc = StubProc::default().with_proc(pid, claude_proc(1000, false));
        let sigindex = SignatureIndex::new();
        assert_eq!(
            verify_managed_agent_self_activity(pid, "claude", None, &reg, &sigindex, &proc, true),
            ManagedAgentVerdict::NotManaged,
        );
    }

    /// pid gone (live None) -> fail closed.
    #[test]
    fn standalone_claude_pid_gone_blocks() {
        let pid = 7010;
        let reg = registry_with_claude(pid);
        let proc = StubProc::default(); // no proc registered for pid
        assert_eq!(
            verify(pid, None, &reg, &proc),
            ManagedAgentVerdict::NotManaged
        );
    }

    /// Registry MISS (claude not auto-registered) -> BLOCK (membership gate).
    #[test]
    fn standalone_claude_not_registered_blocks() {
        let pid = 7011;
        let reg = Registry::new(); // empty
        let proc = StubProc::default().with_proc(pid, claude_proc(1000, false));
        assert_eq!(
            verify(pid, None, &reg, &proc),
            ManagedAgentVerdict::NotManaged
        );
    }

    #[test]
    fn standalone_binary_root_trusted_policy() {
        assert!(standalone_binary_root_trusted(CLAUDE_BIN));
        assert!(standalone_binary_root_trusted(CLAUDE_EXE));
        assert!(standalone_binary_root_trusted("/usr/local/bin/claude"));
        assert!(!standalone_binary_root_trusted("/tmp/claude"));
        assert!(!standalone_binary_root_trusted("/dev/shm/claude"));
        assert!(!standalone_binary_root_trusted(
            "/home/lab/Downloads/claude"
        ));
    }

    /// Live exe under a home dir that does NOT match the registered install dir
    /// (e.g. ~/Downloads) → BLOCK.
    #[test]
    fn home_downloads_exe_is_untrusted() {
        assert!(!exe_root_trusted(
            "/home/lab/Downloads/openclaw/dist/index.js",
            Some("/home/lab/.npm-global/lib/node_modules/openclaw")
        ));
    }

    #[test]
    fn npm_global_home_install_script_is_trusted() {
        // The real npm-global home install SCRIPT path must be trusted when the
        // install dir derived from it matches.
        assert!(exe_root_trusted(
            OPENCLAW_SCRIPT,
            registered_install_dir(Some(OPENCLAW_SCRIPT)).as_deref()
        ));
    }

    #[test]
    fn system_root_exe_always_trusted() {
        assert!(exe_root_trusted("/usr/bin/node", None));
        assert!(exe_root_trusted("/opt/foo/bin/agent", None));
        assert!(!exe_root_trusted("/tmp/x", None));
    }

    #[test]
    fn registered_install_dir_extracts_node_modules_root() {
        assert_eq!(
            registered_install_dir(Some(OPENCLAW_SCRIPT)).as_deref(),
            Some("/home/lab/.npm-global/lib/node_modules/openclaw")
        );
        // Non-npm exe → parent dir.
        assert_eq!(
            registered_install_dir(Some("/usr/local/bin/agent")).as_deref(),
            Some("/usr/local/bin")
        );
        assert_eq!(registered_install_dir(None), None);
        assert_eq!(registered_install_dir(Some("")), None);
    }

    #[test]
    fn home_dir_from_exe_parses_user_home() {
        assert_eq!(
            home_dir_from_exe("/home/lab/.npm-global/lib/x").as_deref(),
            Some("/home/lab")
        );
        assert_eq!(home_dir_from_exe("/root/bin/x").as_deref(), Some("/root"));
        assert_eq!(home_dir_from_exe("/usr/bin/node"), None);
    }

    #[test]
    fn read_path_is_own_requires_dir_prefix_not_sibling() {
        // A sibling dir sharing a prefix must NOT count as own.
        assert!(!read_path_is_own(
            "/home/lab-evil/.env",
            Some("/home/lab"),
            None
        ));
        assert!(read_path_is_own("/home/lab/.env", Some("/home/lab"), None));
    }

    #[test]
    fn read_path_is_own_rejects_credential_subdirs_even_in_own_home() {
        // Defect 2: within the agent's own home, the user's secrets are NOT own
        // config.
        assert!(!read_path_is_own(
            "/home/lab/.ssh/id_rsa",
            Some("/home/lab"),
            None
        ));
        assert!(!read_path_is_own(
            "/home/lab/.aws/credentials",
            Some("/home/lab"),
            None
        ));
        // …but the agent's own .env stays own.
        assert!(read_path_is_own("/home/lab/.env", Some("/home/lab"), None));
    }

    #[test]
    fn script_path_from_argv_returns_first_slash_token_after_argv0() {
        let argv: Vec<String> = OPENCLAW_ARGV.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            script_path_from_argv(&argv).as_deref(),
            Some(OPENCLAW_SCRIPT)
        );
        // python -m module: no `/`-bearing token after argv[0] → None.
        let m = vec![
            "/usr/bin/python3".to_string(),
            "-m".to_string(),
            "aider".to_string(),
        ];
        assert_eq!(script_path_from_argv(&m), None);
        // A directly-launched binary with no later `/`-token → None.
        let direct = vec!["/usr/local/bin/agent".to_string(), "serve".to_string()];
        assert_eq!(script_path_from_argv(&direct), None);
        // Empty argv → None.
        assert_eq!(script_path_from_argv(&[]), None);
    }

    #[test]
    fn interpreter_root_trusted_accepts_system_rejects_tmp() {
        assert!(interpreter_root_trusted("/usr/bin/node"));
        assert!(interpreter_root_trusted("/bin/python3"));
        assert!(interpreter_root_trusted("/snap/node/current/bin/node"));
        assert!(!interpreter_root_trusted("/tmp/node"));
        assert!(!interpreter_root_trusted("/dev/shm/node"));
        assert!(!interpreter_root_trusted("/home/lab/Downloads/node"));
        // A home install is NOT a trusted INTERPRETER root (interpreters live in
        // system dirs; only scripts live under home).
        assert!(!interpreter_root_trusted("/home/lab/.npm-global/bin/node"));
    }

    #[test]
    fn live_cmdline_fingerprint_matches_registry_capture() {
        // Must be byte-for-byte what registry::capture_proc_facts produces:
        // first-2-argv joined by `|`.
        let argv: Vec<String> = OPENCLAW_ARGV.iter().map(|s| s.to_string()).collect();
        assert_eq!(live_cmdline_fingerprint(&argv), openclaw_fingerprint());
        // Single-token argv → just that token.
        assert_eq!(
            live_cmdline_fingerprint(&["/usr/local/bin/agent".to_string()]),
            "/usr/local/bin/agent"
        );
        assert_eq!(live_cmdline_fingerprint(&[]), "");
    }

    #[test]
    fn parse_status_uid_reads_real_uid() {
        let status = "Name:\tnode\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\n";
        assert_eq!(parse_status_uid(status), Some(1000));
        assert_eq!(parse_status_uid("no uid line here"), None);
    }

    // ── Live `/proc` resolver (SystemProc) coverage ──────────────────────
    //
    // The pure `decide` core + the `verify_managed_agent_self_activity`
    // wrapper are exercised above via the StubProc. These tests cover the
    // PRODUCTION `/proc` boundary itself, against the test binary's own live
    // process so the reads succeed on any Linux CI host. On non-Linux the
    // `/proc` reads fail and the resolver fails closed (asserted accordingly).

    /// `SystemProc::resolve(own pid)` reads live `/proc` facts for the running
    /// test process: a non-empty argv, an `exe_path`, and a uid. On a real
    /// Linux box (CI + prod) all three are `Some`/non-empty; the assertion is
    /// gated on Linux because `/proc` does not exist elsewhere.
    #[test]
    fn system_proc_resolves_own_pid() {
        let sysproc = SystemProc;
        let resolved = sysproc.resolve(std::process::id());
        if cfg!(target_os = "linux") {
            let r = resolved.expect("own pid must resolve on Linux");
            assert!(!r.argv.is_empty(), "own argv must be non-empty");
            assert!(r.exe_path.is_some(), "own /proc/self/exe must resolve");
            assert!(r.uid.is_some(), "own /proc/self/status Uid must parse");
            // argv[0] is the test binary path — it contains a path separator.
            assert!(
                r.argv[0].contains('/') || !r.argv[0].is_empty(),
                "argv[0] should be the test binary"
            );
        } else {
            // No /proc on non-Linux — fail closed (no facts).
            assert!(resolved.is_none());
        }
    }

    /// `SystemProc::resolve` of a pid that does not exist must fail closed
    /// (return `None`) because the `/proc/<pid>/cmdline` read errors. This is
    /// the TOCTOU guard at the production boundary.
    #[test]
    fn system_proc_resolve_missing_pid_is_none() {
        let sysproc = SystemProc;
        // u32::MAX is not a live pid on any sane host.
        assert!(sysproc.resolve(u32::MAX).is_none());
    }

    /// `SystemProc::file_owner_uid` stats a real file and returns its owner uid.
    /// We write a tempfile and assert the resolver reports SOME uid for it and
    /// `None` for a path that does not exist.
    #[test]
    fn system_proc_file_owner_uid_reads_real_file() {
        let sysproc = SystemProc;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("owned.txt");
        std::fs::write(&path, b"x").expect("write tempfile");
        let owner = sysproc.file_owner_uid(path.to_str().unwrap());
        if cfg!(unix) {
            assert!(owner.is_some(), "a real file must report an owner uid");
        }
        // A non-existent path stats-fails → None.
        assert!(sysproc
            .file_owner_uid(dir.path().join("does-not-exist").to_str().unwrap())
            .is_none());
    }

    /// End-to-end through the PRODUCTION resolver: the running test process is
    /// (obviously) not a registered managed agent, so the live-/proc path must
    /// reach the registry-miss fail-closed branch and return `NotManaged`. This
    /// exercises `verify_managed_agent_self_activity` with `SystemProc` (not a
    /// stub), covering the wrapper's live-resolve + live-sig + live-fingerprint
    /// computation against real `/proc` data.
    #[test]
    fn verify_with_system_proc_unregistered_self_is_not_managed() {
        let reg = Registry::new(); // nothing registered
        let sigindex = SignatureIndex::new();
        let sysproc = SystemProc;
        let verdict = verify_managed_agent_self_activity(
            std::process::id(),
            "test-runner",
            None,
            &reg,
            &sigindex,
            &sysproc,
            false,
        );
        assert_eq!(
            verdict,
            ManagedAgentVerdict::NotManaged,
            "the unregistered test process must fail closed via the live /proc path"
        );
    }

    /// Defect 1 — `python -m <module>` agent with NO read_path is Managed: the
    /// no-script branch of `decide` returns `Managed` as long as the interpreter
    /// root is trusted (a pure C2-connect with no prior sensitive read). The
    /// complementary read-path-present case (fail closed) is covered by
    /// `python_dash_m_module_with_read_path_fails_closed` above.
    #[test]
    fn python_dash_m_module_without_read_path_is_managed() {
        let pid = 4022;
        let mut reg = Registry::new();
        let fp = "/usr/bin/python3|-m";
        reg.connect_with_facts(
            "Aider",
            pid,
            Some("ag-aider"),
            Some("/usr/bin/python3".to_string()),
            Some(1000),
            Some(fp.to_string()),
        )
        .expect("connect");
        let proc = ResolvedProcess {
            argv: vec!["/usr/bin/python3".into(), "-m".into(), "aider".into()],
            exe_path: Some("/usr/bin/python3".into()),
            uid: Some(1000),
        };
        let stub = StubProc::default().with_proc(pid, proc);
        // No read_path → the no-script branch returns Managed (trusted interp).
        assert!(
            verify(pid, None, &reg, &stub).is_managed(),
            "python -m module with NO read_path + trusted interpreter must be Managed"
        );
    }

    /// Defect 1 — `python -m <module>` with no script token AND a missing
    /// interpreter exe (`/proc/<pid>/exe` unreadable) must fail closed even with
    /// no read_path. Covers the `exe_path = None` arm of the no-script branch.
    #[test]
    fn python_dash_m_module_with_no_exe_and_untrusted_interpreter_fails_closed() {
        // python -m module: no script token. With /proc/exe unreadable the
        // interpreter check falls back to argv[0] — so it must still BLOCK when
        // argv[0] is an UNTRUSTED interpreter the attacker dropped (/tmp/python3).
        // (A TRUSTED argv[0] no-exe case is Managed — see the cross-uid test above
        // and the 2026-06-21 Azure FP fix; the fingerprint + module signature pin
        // identity, the argv[0] root-trust is the remaining gate.)
        let pid = 4023;
        let mut reg = Registry::new();
        let fp = "/tmp/python3|-m";
        reg.connect_with_facts(
            "Aider",
            pid,
            Some("ag-aider"),
            None,
            Some(1000),
            Some(fp.to_string()),
        )
        .expect("connect");
        let proc = ResolvedProcess {
            argv: vec!["/tmp/python3".into(), "-m".into(), "aider".into()],
            exe_path: None, // /proc/<pid>/exe unreadable
            uid: Some(1000),
        };
        let stub = StubProc::default().with_proc(pid, proc);
        assert_eq!(
            verify(pid, None, &reg, &stub),
            ManagedAgentVerdict::NotManaged,
            "untrusted interpreter (argv[0]=/tmp/python3) must fail closed even with matching fingerprint"
        );
    }

    /// `registered_install_dir` parent-dir fallback for a directly-launched
    /// binary (no `/node_modules/` segment) — explicit coverage of the
    /// `rfind('/')` branch separate from the npm-modules branch.
    #[test]
    fn registered_install_dir_falls_back_to_parent_dir() {
        assert_eq!(
            registered_install_dir(Some("/opt/agent/bin/serve")).as_deref(),
            Some("/opt/agent/bin")
        );
        // node_modules with an empty package segment → `.../node_modules`.
        assert_eq!(
            registered_install_dir(Some("/x/node_modules/")).as_deref(),
            Some("/x/node_modules")
        );
    }
}
