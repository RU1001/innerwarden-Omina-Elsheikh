// Clippy 1.95 promotes `unnecessary_sort_by` to a default-deny lint, but
// the existing codebase uses the explicit `sort_by(|a,b| b.x.cmp(&a.x))`
// pattern for reverse-sort leaderboards in status/scan output. The
// `sort_by_key(|x| Reverse(...))` alternative is less readable here.
#![allow(clippy::unnecessary_sort_by)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod banner;
mod calibrate;
mod capabilities;
mod capability;
mod commands;
mod config_editor;
mod harden;
mod helpers;
mod module_manifest;
mod module_package;
mod module_validator;
mod preflight;
mod scan;
mod sudoers;
mod systemd;
mod upgrade;
mod welcome;

use capability::{ActivationOptions, CapabilityRegistry};
pub(crate) use helpers::{
    hostname, load_env_file, looks_like_ip, mask_secret, prompt, prompt_with_hint, require_sudo,
    resolve_data_dir, restart_agent, send_telegram_message_md, write_env_key,
};
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};
// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "innerwarden",
    // `--version` / `-V` print the workspace version. Operators kept hitting
    // `innerwarden --version` and getting "unexpected argument" — clap only
    // wires the flag when `version = ...` is set on the parent command.
    version = env!("CARGO_PKG_VERSION"),
    about = "InnerWarden. self-defending security for Linux and macOS.",
    long_about = "8 commands to protect your server:\n\n\
                  \x20 get       Query status, incidents, decisions, reports\n\
                  \x20 stream    Monitor events in real-time\n\
                  \x20 action    Block or unblock IPs\n\
                  \x20 trust     Manage trusted IPs, users, and suppressions\n\
                  \x20 config    Configure AI, notifications, integrations\n\
                  \x20 system    Diagnostics, hardening, tuning, data export\n\
                  \x20 module    Install and manage security modules\n\
                  \x20 agent     Connect and manage AI agents\n\n\
                  Getting started:  innerwarden setup"
)]
struct Cli {
    /// Path to sensor config (config.toml)
    #[arg(long, default_value = "/etc/innerwarden/config.toml")]
    sensor_config: PathBuf,

    /// Path to agent config (agent.toml)
    #[arg(long, default_value = "/etc/innerwarden/agent.toml")]
    agent_config: PathBuf,

    /// Directory where InnerWarden data files are stored
    #[arg(long, default_value = "/var/lib/innerwarden", global = true)]
    data_dir: PathBuf,

    /// Show what would happen without applying any changes
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    // =======================================================================
    // New grouped commands (primary UX)
    // =======================================================================
    /// Query status, incidents, decisions, reports, and metrics.
    ///
    /// All read-only operations that fetch data without changing state.
    ///
    /// Examples:
    ///   innerwarden get status
    ///   innerwarden get incidents --days 2
    ///   innerwarden get decisions --action block_ip
    ///   innerwarden get report --date yesterday
    ///   innerwarden get metrics
    ///   innerwarden get sensors
    Get {
        #[command(subcommand)]
        command: Option<GetCommand>,
    },

    /// Stream new incidents and events in real time.
    ///
    /// Polls JSONL files and prints new entries as they arrive. Ctrl-C to stop.
    ///
    /// Examples:
    ///   innerwarden stream
    ///   innerwarden stream --type events
    ///   innerwarden stream --interval 5
    Stream {
        /// What to stream: incidents or events (default: incidents)
        #[arg(long, default_value = "incidents")]
        r#type: String,

        /// Poll interval in seconds (default: 2)
        #[arg(long, default_value = "2")]
        interval: u64,
    },

    /// Manual response actions (block/unblock IPs).
    ///
    /// Examples:
    ///   innerwarden action block 1.2.3.4 --reason "investigation"
    ///   innerwarden action unblock 1.2.3.4 --reason "false positive"
    Action {
        #[command(subcommand)]
        command: Option<ActionCommand>,
    },

    /// Manage trusted entities and suppression rules.
    ///
    /// Examples:
    ///   innerwarden trust add --ip 10.0.0.1
    ///   innerwarden trust remove --user deploy
    ///   innerwarden trust list
    ///   innerwarden trust suppress firmware:trust_degraded
    ///   innerwarden trust unsuppress firmware:trust_degraded
    ///   innerwarden trust suppressions
    Trust {
        #[command(subcommand)]
        command: Option<TrustCommand>,
    },

    /// Configure AI, notifications, integrations, and mesh.
    ///
    /// Run without arguments for an interactive menu.
    ///
    /// Examples:
    ///   innerwarden config ai
    ///   innerwarden config telegram
    ///   innerwarden config cloudflare
    ///   innerwarden config mesh enable
    Config {
        #[command(subcommand)]
        command: Option<ConfigAllCommand>,
    },

    /// System health, tuning, security, and data management.
    ///
    /// Examples:
    ///   innerwarden system doctor
    ///   innerwarden system harden
    ///   innerwarden system test
    ///   innerwarden system export incidents
    ///   innerwarden system backup
    System {
        #[command(subcommand)]
        command: Option<SystemCommand>,
    },

    /// Manage detection rules (event_pipeline, sigma, yara, atr, correlation, playbooks).
    ///
    /// Rules are YAML files under /etc/innerwarden/rules/, hot-reloaded every
    /// 60s. Cross-layer correlation rule IDs (CL-NNN) route to the correlation
    /// subdir automatically. SOC playbook IDs (pb-*) live under playbooks/.
    ///
    /// Examples:
    ///   innerwarden rule list
    ///   innerwarden rule list --type correlation
    ///   innerwarden rule disable drop-service-daemon-file-ops
    ///   innerwarden rule disable CL-024
    ///   innerwarden rule enable CL-024
    Rule {
        #[command(subcommand)]
        command: RuleCommand,
    },

    /// Execution Gate (spec 083): arm the in-kernel exec gate around your AI
    /// agent's process — observe first, then enforce. Agent-scoped, so the host
    /// itself is never gated.
    ///
    /// Examples:
    ///   innerwarden exec-gate status
    ///   innerwarden exec-gate arm --pid 1234 --observe --path /usr/bin/python3
    ///   innerwarden exec-gate disarm
    #[command(name = "exec-gate")]
    ExecGate {
        #[command(subcommand)]
        command: ExecGateCommand,
    },

    /// Decision-log external-anchor integrity audit.
    ///
    /// The hash chain proves the log is internally consistent, but cannot detect
    /// the whole log being deleted or rolled back and re-grown from a fresh root.
    /// `anchor` prints a compact commitment to the log's tip that you store
    /// OUTSIDE this host; `verify` later proves the log still contains that exact
    /// committed history (Intact / Truncated / Rewritten). The paid tier signs
    /// the anchor (Ed25519) via `innerwarden-config-sign audit`.
    ///
    /// Examples:
    ///   innerwarden audit anchor --json > anchor.json
    ///   innerwarden audit verify --file anchor.json
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },

    /// Internal: privileged helper for the `suspend-user-sudo` response. Invoked
    /// only via a narrow sudoers grant; generates + installs a deny-all sudoers
    /// drop-in for a user (no arbitrary-content primitive). Not for direct use.
    #[clap(name = "__sudo-suspend", hide = true)]
    SudoSuspend {
        /// Username to suspend sudo for (validated; `root` refused).
        #[arg(long)]
        user: String,
        /// Informational expiry recorded in the drop-in (RFC 3339). sudo does
        /// not enforce it; the agent's cleanup loop removes the file.
        #[arg(long)]
        expires: String,
    },

    /// Internal: privileged helper that removes a `suspend-user-sudo` deny
    /// drop-in for a user. Invoked only via the narrow sudoers grant.
    #[clap(name = "__sudo-restore", hide = true)]
    SudoRestore {
        /// Username to restore sudo for (validated; `root` refused).
        #[arg(long)]
        user: String,
    },

    /// SOC playbook tools (spec 056).
    ///
    /// Examples:
    ///   innerwarden playbook test pb-data-exfil-default --incident-file last.jsonl
    Playbook {
        #[command(subcommand)]
        command: PlaybookCommand,
    },

    /// Module management commands
    Module {
        #[command(subcommand)]
        command: ModuleCommand,
    },

    /// AI agent management. Install, scan, connect, monitor agents.
    ///
    /// Run without arguments for an interactive menu.
    ///
    /// Examples:
    ///   innerwarden agent                    (interactive menu)
    ///   innerwarden agent add <name>         (install an agent)
    ///   innerwarden agent scan               (find running agents)
    ///   innerwarden agent status             (view connected agents)
    ///   innerwarden agent connect            (auto-detect and connect)
    ///   innerwarden agent connect 1234       (connect a specific PID)
    ///   innerwarden agent disconnect ag-0001 (disconnect an agent)
    Agent {
        #[command(subcommand)]
        command: Option<AgentCommand>,
    },

    // =======================================================================
    // Top-level commands (not grouped)
    // =======================================================================
    /// First-time setup wizard.
    ///
    /// Scans your machine, configures AI, Telegram notifications, the
    /// responder, and enables the most relevant modules for your setup.
    ///
    /// Examples:
    ///   innerwarden setup
    ///   innerwarden setup --mode advanced
    Setup {
        /// Setup mode: basic (default) or advanced
        #[arg(long, default_value = "basic", value_parser = ["basic", "advanced"])]
        mode: String,
    },

    /// Replay JSONL event fixtures through detectors and validate output.
    ///
    /// Reads event fixtures, runs them through the registered detectors, and
    /// compares produced incidents against expected.json. Exits non-zero if any
    /// detector fails its assertion. Custom fixtures let operators validate
    /// detector behaviour on their own log samples without writing Bash.
    ///
    /// Examples:
    ///   innerwarden replay
    ///   innerwarden replay --fixture testdata/fixtures/ --expected testdata/expected.json
    ///   innerwarden replay --fixture /tmp/my-logs/ --expected /tmp/my-expected.json
    Replay {
        /// Directory containing .jsonl fixture files. The default path is relative to the
        /// repo root — run this command from the repository root or pass an absolute path.
        #[arg(long, default_value = "testdata/fixtures")]
        fixture: PathBuf,

        /// JSON file describing expected detector output. The default path is relative to the
        /// repo root — run this command from the repository root or pass an absolute path.
        #[arg(long, default_value = "testdata/expected.json")]
        expected: PathBuf,
    },

    /// Check for a newer release and optionally upgrade all binaries.
    ///
    /// Examples:
    ///   innerwarden upgrade
    ///   innerwarden upgrade --check
    ///   innerwarden upgrade --yes
    Upgrade {
        /// Only check if an update is available; do not install
        #[arg(long)]
        check: bool,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,

        /// Send a Telegram notification if a new version is available
        #[arg(long)]
        notify: bool,

        /// Directory where binaries are installed
        #[arg(long, default_value = "/usr/local/bin")]
        install_dir: PathBuf,

        /// Spec 048 escape hatch. Allow stable releases that ship without
        /// a .sig file. NOT recommended; defeats supply-chain verification.
        /// Use only when migrating from a pre-spec-048 release that lacks
        /// signatures, or in air-gapped builds without GitHub access.
        #[arg(long)]
        allow_unsigned_stable: bool,

        /// Spec 048 escape hatch. Allow canary/prerelease tags that ship
        /// without .sig files. Canary signing is on the spec 048 follow-up
        /// roadmap; until then this flag is required to install any canary.
        #[arg(long)]
        allow_unsigned_canary: bool,
    },

    /// Generate shell completions for bash, zsh, or fish.
    ///
    /// Examples:
    ///   innerwarden completions bash >> ~/.bashrc
    ///   innerwarden completions zsh  >> ~/.zshrc
    Completions {
        /// Shell to generate completions for: bash, zsh, or fish
        shell: String,
    },

    /// Activate a capability
    Enable {
        /// Capability ID (run 'innerwarden list' to see options)
        capability: String,

        /// Capability-specific parameters as KEY=VALUE
        #[arg(long = "param", value_name = "KEY=VALUE", action = clap::ArgAction::Append)]
        params: Vec<String>,

        /// Skip interactive confirmation prompts (e.g. privacy gate)
        #[arg(long)]
        yes: bool,

        /// Re-apply even if already enabled. Repairs drift such as a missing
        /// sudoers drop-in (the side effect that makes block-ip actually work).
        #[arg(long)]
        force: bool,
    },

    /// Deactivate a capability
    Disable {
        /// Capability ID (run 'innerwarden list' to see options)
        capability: String,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// List all capabilities with their current status
    List,

    // =======================================================================
    // Hidden backward-compatibility aliases (old command names still work)
    // =======================================================================
    #[clap(hide = true)]
    Status {
        target: Option<String>,
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,
        #[arg(long, default_value = "3")]
        days: u64,
    },

    #[clap(hide = true)]
    #[command(visible_aliases = ["quick", "day"])]
    Daily {
        #[command(subcommand)]
        command: Option<DailyCommand>,
    },

    #[clap(hide = true)]
    Harden {
        #[arg(long)]
        verbose: bool,
    },

    #[clap(hide = true)]
    Doctor,

    #[clap(hide = true)]
    Scan {
        #[arg(long, default_value = "")]
        modules_dir: String,
    },

    /// Open or check the security dashboard — easy + secure access.
    ///
    /// The dashboard binds to localhost by default (secure). This sets it up in
    /// one step instead of editing systemd units + firewall by hand.
    ///
    /// Examples:
    ///   innerwarden dashboard            # how to reach it (URL, login, SSH tunnel)
    ///   innerwarden dashboard open       # expose securely (password + firewall-locked to your IP)
    ///   innerwarden dashboard close      # back to localhost only
    ///   innerwarden dashboard tunnel     # print the exact SSH-tunnel command
    Dashboard {
        #[command(subcommand)]
        action: Option<commands::dashboard::DashboardAction>,
    },

    /// Uninstall InnerWarden — stop + remove services, binaries, eBPF maps,
    /// sudoers + firewall rules. Keeps config + data unless --purge.
    ///
    /// Examples:
    ///   innerwarden uninstall            # remove the software, keep config/data
    ///   innerwarden uninstall --purge    # also remove config, data, logs + the user
    ///   innerwarden uninstall --yes      # no confirmation prompt
    Uninstall {
        /// Also remove /etc/innerwarden, /var/lib/innerwarden, logs, and the user.
        #[arg(long)]
        purge: bool,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },

    #[clap(hide = true)]
    Welcome,

    #[clap(hide = true)]
    Navigator {
        #[arg(short, long)]
        output: Option<String>,
    },

    #[clap(hide = true)]
    Notify {
        #[command(subcommand)]
        command: Option<NotifyCommand>,
    },

    #[clap(hide = true)]
    Configure {
        #[command(subcommand)]
        command: Option<ConfigureCommand>,
    },

    #[clap(hide = true)]
    Integrate {
        #[command(subcommand)]
        command: Option<IntegrateCommand>,
    },

    #[clap(hide = true)]
    Mesh {
        #[command(subcommand)]
        command: MeshCommand,
    },

    #[clap(hide = true)]
    Report {
        #[arg(long, default_value = "today")]
        date: String,
    },

    #[clap(hide = true)]
    Watchdog {
        #[arg(long, default_value = "300")]
        threshold: u64,
        #[arg(long)]
        notify: bool,
        #[arg(long)]
        status: bool,
    },

    #[clap(hide = true)]
    Tune {
        #[arg(long, default_value = "7")]
        days: u64,
        #[arg(long)]
        yes: bool,
    },

    #[clap(hide = true, name = "sensor-status")]
    SensorStatus,

    #[clap(hide = true)]
    Export {
        #[arg(default_value = "incidents")]
        kind: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },

    #[clap(hide = true)]
    Tail {
        #[arg(long, default_value = "incidents")]
        r#type: String,
        #[arg(long, default_value = "2")]
        interval: u64,
    },

    #[clap(hide = true)]
    Incidents {
        #[arg(long, default_value = "1")]
        days: u64,
        #[arg(long, default_value = "low")]
        severity: String,
        #[arg(long)]
        live: bool,
    },

    #[clap(hide = true)]
    Block {
        ip: String,
        #[arg(long)]
        reason: String,
    },

    #[clap(hide = true)]
    Unblock {
        ip: String,
        #[arg(long)]
        reason: String,
    },

    #[clap(hide = true)]
    Decisions {
        #[arg(long, default_value = "1")]
        days: u64,
        #[arg(long)]
        action: Option<String>,
    },

    #[clap(hide = true)]
    Entity {
        target: String,
        #[arg(long, default_value = "3")]
        days: u64,
    },

    #[clap(hide = true)]
    Allowlist {
        #[command(subcommand)]
        command: AllowlistCommand,
    },

    #[clap(hide = true, name = "test")]
    PipelineTest {
        #[arg(long, default_value = "12")]
        wait: u64,
    },

    #[clap(hide = true)]
    Backup {
        #[arg(long)]
        output: Option<PathBuf>,
    },

    #[clap(hide = true)]
    Metrics,

    #[clap(hide = true)]
    Gdpr {
        #[command(subcommand)]
        action: GdprCommand,
    },

    #[clap(hide = true)]
    Suppress {
        #[command(subcommand)]
        command: SuppressCommand,
    },

    /// Install the Local Warden Model (distilled SecureBERT) used by
    /// the agent's `local_warden` AI provider.
    ///
    /// Downloads `model.onnx` and `tokenizer.json` from the configured
    /// GitHub release artifact and installs them under
    /// `/var/lib/innerwarden/models/classifier/`. The Local Warden
    /// provider activates automatically when the agent restarts and
    /// the operator has set `[ai.warden].provider = "local_warden"`
    /// in `agent.toml` (the `configure` wizard does that for you).
    ///
    /// 2026-05-03 rename: previously `install-classifier` —
    /// `install-classifier` is preserved as a visible alias so
    /// existing automation continues to work.
    ///
    /// Examples:
    ///   innerwarden install-warden
    ///   innerwarden install-warden --model minilm-l6 --yes
    ///   innerwarden install-warden --url https://github.com/InnerWarden/innerwarden/releases/download/classifier-v1/minilm-l6.tar.gz
    #[command(name = "install-warden", visible_alias = "install-classifier")]
    InstallClassifier {
        /// Model variant to install. Supported: `minilm-l6` (87 MB,
        /// distilled, default) and `roberta-v1` (478 MB, full
        /// precision validated 0.975).
        #[arg(long, default_value = "minilm-l6")]
        model: String,

        /// Override the default release URL. Only needed for
        /// air-gapped installs or self-hosted artifact mirrors.
        #[arg(long)]
        url: Option<String>,

        /// SHA-256 of the downloaded archive. When omitted, uses the
        /// pinned hash for the chosen model variant. Override only
        /// for `--url` mirror installs.
        #[arg(long)]
        sha256: Option<String>,

        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,

        /// After installing, also write the `[ai.warden]` section into
        /// agent.toml so the agent selects the on-device model on its next
        /// restart. Used by `install.sh` for hands-off provisioning.
        #[arg(long)]
        configure: bool,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Install a new agent (OpenClaw, ZeroClaw, and others in `agent list`)
    Add {
        /// Agent name (run 'innerwarden agent add' without args to see options)
        name: Option<String>,
    },

    /// Scan for agents already running on this server
    Scan,

    /// View connected agents and detected tools
    Status,

    /// Connect a running agent.
    ///
    /// If PID is omitted, InnerWarden auto-detects running agents and:
    /// - connects automatically when only one is found
    /// - offers a guided selection when multiple are found
    Connect {
        /// Optional process ID of the agent to connect
        pid: Option<u32>,

        /// Match an agent by name/command (avoids manual PID lookup)
        #[arg(long)]
        name: Option<String>,

        /// Optional label for this instance (e.g., "personal", "work")
        #[arg(long)]
        label: Option<String>,
    },

    /// Disconnect an agent by ID
    Disconnect {
        /// Agent ID (e.g., ag-0001) or PID
        id: String,
    },

    /// List available agents for installation
    List,

    /// Run an inspecting MCP proxy in front of a real MCP server.
    ///
    /// Wraps the server's stdio, scanning `tools/call` arguments and
    /// `tools/list` / tool results for threats (prompt injection, credential
    /// leaks, dangerous commands, ATR rules). Default mode is advisory (alert
    /// only); `guard`/`kill` block disallowed calls. Example:
    ///   innerwarden agent proxy --mode guard -- npx -y some-mcp-server --flag
    Proxy {
        /// Enforcement mode: advisory (default), warn, guard, or kill.
        #[arg(long, default_value = "advisory")]
        mode: String,

        /// Optional label for audit / alerts.
        #[arg(long)]
        label: Option<String>,

        /// Return denials as a JSON-RPC error instead of an isError result.
        #[arg(long)]
        error_response: bool,

        /// The real MCP server command and its arguments (everything after `--`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        server_cmd: Vec<String>,
    },

    /// Expose InnerWarden as an MCP server over stdio (spec 082 Phase 2).
    ///
    /// The advisory front door: an AI coding agent can wire this as an MCP
    /// server and ask InnerWarden, before acting, whether a command is safe
    /// (`innerwarden_check_command`), whether an IP is a known threat
    /// (`innerwarden_check_ip`), or what the host threat level is
    /// (`innerwarden_security_context`). A thin adapter over the loopback Agent
    /// API; stdio only (no network listener); returns capability-level answers
    /// (deny/review/allow) without exposing detection internals. The host's
    /// enforcement (the `proxy` MCP guard + eBPF) is unchanged: this is
    /// additive, for a cooperating agent.
    McpServe {
        /// Optional label for audit / alerts.
        #[arg(long)]
        label: Option<String>,
    },

    /// Install InnerWarden's in-path command guard into an AI coding agent.
    ///
    /// Writes a small guard script and a PreToolUse hook so every shell command
    /// the agent proposes is POSTed to the loopback `check-command` brain and
    /// BLOCKED before it runs when dangerous, failing closed if the agent is not
    /// reachable. Unlike `mcp-serve`/`check-command` (advisory), this enforces
    /// even when the agent uses its raw shell tool. Currently supports Claude
    /// Code. Example:
    ///   innerwarden agent install-hook    # claude-code, ~/.claude/settings.json
    #[command(name = "install-hook")]
    InstallHook {
        /// AI agent to wire up (currently only "claude-code").
        #[arg(long, default_value = "claude-code")]
        agent: String,

        /// Path to the agent's settings.json (default ~/.claude/settings.json).
        #[arg(long)]
        settings: Option<String>,

        /// InnerWarden dashboard base URL (default https://127.0.0.1:8787).
        #[arg(long)]
        url: Option<String>,

        /// Also block "review" verdicts, not just "deny".
        #[arg(long)]
        block_review: bool,

        /// Tenant id to stamp on every guard check (spec 084 P0 1D), so a
        /// multi-tenant fleet attributes per-container guard activity per
        /// tenant. Bake it into the agent's container image / pod template.
        #[arg(long)]
        tenant: Option<String>,
    },
}

#[derive(Subcommand)]
enum DailyCommand {
    /// Quick system overview (services, capabilities, modules, today's activity).
    Status,

    /// Show recent threats (default: High/Critical from today).
    Threats {
        /// How many days back to look (default: 1)
        #[arg(long, default_value = "1")]
        days: u64,

        /// Minimum severity: low, medium, high, critical (default: high)
        #[arg(long, default_value = "high")]
        severity: String,

        /// Stream new incidents in real time
        #[arg(long)]
        live: bool,
    },

    /// Show recent actions taken by InnerWarden.
    Actions {
        /// How many days back to look (default: 1)
        #[arg(long, default_value = "1")]
        days: u64,
    },

    /// Print daily security report.
    Report {
        /// Date: today, yesterday, or YYYY-MM-DD
        #[arg(long, default_value = "today")]
        date: String,
    },

    /// Run diagnostics and print fix hints.
    Doctor,

    /// Inject synthetic incident and verify end-to-end pipeline.
    Test {
        /// Maximum seconds to wait for the agent to respond
        #[arg(long, default_value = "12")]
        wait: u64,
    },

    /// Agent connection and protection commands (basic flow).
    ///
    /// Examples:
    ///   innerwarden daily agent
    ///   innerwarden daily agent scan
    ///   innerwarden daily agent status
    ///   innerwarden daily agent connect
    ///   innerwarden daily agent connect 1234
    Agent {
        #[command(subcommand)]
        command: Option<AgentCommand>,
    },
}

/// System configuration sub-commands.
#[derive(Subcommand)]
enum ConfigureCommand {
    /// Configure AI provider and model.
    ///
    /// Run without arguments for an interactive wizard that lists providers,
    /// validates your API key, and fetches available models from the provider.
    ///
    /// Examples:
    ///   innerwarden configure ai
    ///   innerwarden configure ai openai --key sk-...
    ///   innerwarden configure ai groq --key gsk-... --model llama-3.3-70b-versatile
    Ai {
        /// Provider name: openai, anthropic, groq, deepseek, mistral, xai, gemini, ollama, etc.
        provider: Option<String>,

        /// API key for the provider
        #[arg(long)]
        key: Option<String>,

        /// Model to use (if omitted, the wizard fetches available models)
        #[arg(long)]
        model: Option<String>,

        /// Custom base URL for OpenAI-compatible APIs
        #[arg(long)]
        base_url: Option<String>,
    },

    /// Configure responder mode (enable/disable, dry-run).
    ///
    /// Examples:
    ///   innerwarden configure responder --enable --dry-run false
    Responder {
        /// Enable the responder (allow skill execution)
        #[arg(long)]
        enable: bool,

        /// Dry-run mode: true = log only, false = execute for real
        #[arg(long)]
        dry_run: Option<bool>,
    },

    /// Set notification sensitivity level.
    ///
    /// Controls how often you get alerts:
    ///   quiet   - only Critical (server compromised, privesc)
    ///   normal  - High + Critical (confirmed attacks, blocks)
    ///   verbose - everything Medium+ (includes mesh signals, watchlist)
    ///
    /// Examples:
    ///   innerwarden configure sensitivity quiet
    ///   innerwarden configure sensitivity normal
    Sensitivity {
        /// Level: quiet, normal, or verbose
        level: String,
    },

    /// Configure two-factor authentication for sensitive actions.
    ///
    /// Protects allowlist changes, mode switches, and detector disable
    /// with TOTP (Google Authenticator, Authy, 1Password).
    ///
    /// Examples:
    ///   innerwarden configure 2fa
    #[command(name = "2fa")]
    TwoFa,
}

/// Notification channel setup sub-commands.
#[derive(Subcommand)]
enum NotifyCommand {
    /// Set up Telegram notifications (interactive wizard).
    ///
    /// Walks you through creating a bot and getting your chat ID.
    /// Credentials are saved to agent.env (never in plain TOML).
    ///
    /// Examples:
    ///   innerwarden notify telegram
    ///   innerwarden notify telegram --token 123:ABC --chat-id 456789
    Telegram {
        /// Bot token from @BotFather (skips the wizard prompt)
        #[arg(long)]
        token: Option<String>,

        /// Your Telegram chat ID (skips the wizard prompt)
        #[arg(long)]
        chat_id: Option<String>,

        /// Skip the test message after configuring
        #[arg(long)]
        no_test: bool,
    },

    /// Set up Slack notifications (interactive wizard).
    ///
    /// Walks you through creating an Incoming Webhook in your Slack workspace.
    /// The webhook URL is saved to agent.env.
    ///
    /// Examples:
    ///   innerwarden notify slack
    ///   innerwarden notify slack --webhook-url https://hooks.slack.com/services/...
    Slack {
        /// Slack Incoming Webhook URL (skips the wizard prompt)
        #[arg(long)]
        webhook_url: Option<String>,

        /// Minimum severity to notify: low, medium, high, critical (default: high)
        #[arg(long, default_value = "high")]
        min_severity: String,

        /// Skip the test message after configuring
        #[arg(long)]
        no_test: bool,
    },

    /// Set up Discord notifications (interactive wizard).
    ///
    /// Walks you through creating an Incoming Webhook in your Discord server.
    /// The webhook URL is saved to agent.env.
    ///
    /// Examples:
    ///   innerwarden notify discord
    ///   innerwarden notify discord --webhook-url https://discord.com/api/webhooks/...
    Discord {
        /// Discord Incoming Webhook URL (skips the wizard prompt)
        #[arg(long)]
        webhook_url: Option<String>,

        /// Minimum severity to notify: low, medium, high, critical (default: high)
        #[arg(long, default_value = "high")]
        min_severity: String,

        /// Skip the test message after configuring
        #[arg(long)]
        no_test: bool,
    },

    /// Set up HTTP webhook notifications (sends alerts to any HTTP endpoint).
    ///
    /// Examples:
    ///   innerwarden notify webhook
    ///   innerwarden notify webhook --url https://hooks.example.com/notify
    ///   innerwarden notify webhook --url https://hooks.example.com/notify --min-severity medium
    Webhook {
        /// Webhook URL (skips the wizard prompt)
        #[arg(long)]
        url: Option<String>,

        /// Minimum severity to forward: low, medium, high, critical (default: high)
        #[arg(long, default_value = "high")]
        min_severity: String,

        /// Skip the test request after configuring
        #[arg(long)]
        no_test: bool,
    },

    /// Set up the local security dashboard (generates login credentials).
    ///
    /// Creates a secure password hash and writes credentials to agent.env.
    /// The dashboard is then available at http://localhost:8787 after agent restart.
    ///
    /// Examples:
    ///   innerwarden notify dashboard
    ///   innerwarden notify dashboard --user admin --password mysecretpassword
    Dashboard {
        /// Dashboard username (default: admin)
        #[arg(long, default_value = "admin")]
        user: String,

        /// Dashboard password (skips the interactive prompt)
        #[arg(long)]
        password: Option<String>,
    },

    /// Send a test alert to all configured notification channels.
    ///
    /// Verifies that Telegram, Slack, and webhook notifications are working
    /// end-to-end. Useful after first setup or after changing credentials.
    ///
    /// Examples:
    ///   innerwarden notify test
    ///   innerwarden notify test --channel telegram
    Test {
        /// Only test a specific channel: telegram, slack, or webhook
        #[arg(long)]
        channel: Option<String>,
    },

    /// Set up browser Web Push notifications (RFC 8291 / VAPID).
    ///
    /// Generates a VAPID key pair and writes the configuration to agent.toml.
    /// After setup, open the InnerWarden dashboard and click "Enable notifications"
    /// to subscribe your browser.
    ///
    /// Examples:
    ///   innerwarden notify web-push
    ///   innerwarden notify web-push --subject mailto:admin@example.com
    #[clap(name = "web-push")]
    WebPush {
        /// VAPID subject - "mailto:..." contact address for the push service (default: mailto:admin@example.com)
        #[arg(long)]
        subject: Option<String>,
    },

    /// Configure the daily Telegram digest hour.
    ///
    /// Sets the time (0-23, local time) when InnerWarden sends a daily
    /// summary of everything that happened. Use "off" to disable.
    ///
    /// Examples:
    ///   innerwarden notify digest 9       # daily digest at 9 AM
    ///   innerwarden notify digest 20      # daily digest at 8 PM
    ///   innerwarden notify digest off     # disable daily digest
    Digest {
        /// Hour (0-23) for daily digest, or "off" to disable
        hour: String,
    },

    /// Configure the daily Telegram notification budget.
    ///
    /// Maximum immediate notifications per day. Only real threats count
    /// against the budget. Critical severity always breaks the budget.
    /// Everything else goes to the daily digest.
    ///
    /// Examples:
    ///   innerwarden notify budget 5       # max 5 pings/day
    ///   innerwarden notify budget 20      # more permissive
    Budget {
        /// Max immediate notifications per day (default: 10)
        max: u32,
    },
}

/// Allowlist sub-commands.
#[derive(Subcommand)]
enum AllowlistCommand {
    /// Add a trusted IP, CIDR, or user to the allowlist.
    ///
    /// Examples:
    ///   innerwarden allowlist add --ip 10.0.0.1 --reason "office NAT"
    ///   innerwarden allowlist add --ip 192.168.0.0/24 --reason "internal LAN"
    ///   innerwarden allowlist add --user deploy --reason "CI/CD service account"
    Add {
        /// IP address or CIDR range to trust (e.g. 10.0.0.1 or 192.168.0.0/24)
        #[arg(long)]
        ip: Option<String>,

        /// Username to trust
        #[arg(long)]
        user: Option<String>,

        /// Why this entry is being trusted. Recorded in the admin audit
        /// log so a future operator can answer "why is 147.154.0.0/16
        /// here?" without guessing. Optional today (Wave 8e, 2026-05-04)
        /// to preserve backwards compat with existing scripts; a missing
        /// reason emits a warning suggesting the operator add one.
        #[arg(long)]
        reason: Option<String>,
    },

    /// Remove an IP, CIDR, or user from the allowlist.
    ///
    /// Examples:
    ///   innerwarden allowlist remove --ip 10.0.0.1
    ///   innerwarden allowlist remove --user deploy
    Remove {
        /// IP address or CIDR to remove
        #[arg(long)]
        ip: Option<String>,

        /// Username to remove
        #[arg(long)]
        user: Option<String>,
    },

    /// Show all currently trusted IPs, CIDRs, and users.
    List,
}

#[derive(Subcommand)]
enum SuppressCommand {
    /// Suppress an incident pattern from alerting.
    Add {
        /// Pattern to match against incident IDs (substring match).
        /// Examples: "firmware:trust_degraded", "ssh_bruteforce:10.0.0"
        pattern: String,
    },

    /// Remove a suppression pattern (re-enable alerting).
    Remove {
        /// Pattern to remove
        pattern: String,
    },

    /// Show all active suppression patterns.
    List,
}

#[derive(Subcommand)]
enum MeshCommand {
    /// Enable the mesh collaborative defense network.
    ///
    /// Starts sharing threat signals with other Inner Warden nodes.
    /// Disabled by default. Safe - blocks are staged with TTL, never permanent.
    Enable,

    /// Disable the mesh network.
    Disable,

    /// Add a peer node to the mesh.
    ///
    /// The peer's identity will be discovered automatically via ping.
    ///
    /// Examples:
    ///   innerwarden mesh add-peer https://peer-server:8790
    ///   innerwarden mesh add-peer https://10.0.1.5:8790 --label prod-eu
    AddPeer {
        /// Peer endpoint URL (e.g., https://peer:8790)
        endpoint: String,

        /// Human-friendly label for this peer
        #[arg(long)]
        label: Option<String>,
    },

    /// Connect to a peer in one step: enable mesh, add the peer, and open the
    /// local firewall for the mesh port. The smooth path — one command and the
    /// two nodes can reach each other (then restart the agent to apply).
    ///
    /// Examples:
    ///   innerwarden mesh connect 203.0.113.7
    ///   innerwarden mesh connect http://10.0.1.5:8790 --label prod-eu
    Connect {
        /// Peer host or endpoint. Accepts `host`, `host:port`, or
        /// `http://host:port` (defaults to port 8790).
        endpoint: String,

        /// Human-friendly label for this peer
        #[arg(long)]
        label: Option<String>,
    },

    /// Show mesh network status.
    Status,
}

/// External integration setup sub-commands.
#[derive(Subcommand)]
enum IntegrateCommand {
    /// Enable GeoIP country/ISP enrichment (no API key needed).
    ///
    /// Uses ip-api.com (free, 45 req/min) to add country and ISP context
    /// to AI analysis. No account or API key required.
    ///
    /// Examples:
    ///   innerwarden integrate geoip
    Geoip,

    /// Set up AbuseIPDB IP reputation enrichment.
    ///
    /// AbuseIPDB checks each attacker IP's abuse history before AI analysis,
    /// making decisions more accurate. Free tier: 1,000 lookups/day.
    ///
    /// Get a free API key at https://www.abuseipdb.com/register
    ///
    /// Examples:
    ///   innerwarden integrate abuseipdb
    ///   innerwarden integrate abuseipdb --api-key <key>
    Abuseipdb {
        /// AbuseIPDB API key (skips the wizard prompt)
        #[arg(long)]
        api_key: Option<String>,
        /// Auto-block IPs with abuse confidence score >= this threshold without calling AI (0 = disabled)
        #[arg(long)]
        auto_block_threshold: Option<u8>,
    },

    /// Push blocked IPs to Cloudflare edge via IP Access Rules API.
    ///
    /// After every successful block-ip action, the IP is also added to your
    /// Cloudflare zone's IP Access Rules - blocking it at the CDN edge before
    /// traffic even reaches your server.
    ///
    /// Requires a Cloudflare API token with Zone > Firewall Services > Edit permission.
    /// Zone ID is on the right panel of your domain in the Cloudflare dashboard.
    ///
    /// Examples:
    ///   innerwarden integrate cloudflare
    ///   innerwarden integrate cloudflare --zone-id <id> --api-token <token>
    Cloudflare {
        /// Cloudflare Zone ID (from your domain's dashboard page)
        #[arg(long)]
        zone_id: Option<String>,
        /// Cloudflare API token with Firewall Services Edit permission
        #[arg(long)]
        api_token: Option<String>,
    },

    /// Set up automatic health monitoring via cron (watchdog).
    ///
    /// Adds a cron entry that runs `innerwarden watchdog --notify` every N minutes.
    /// Sends a Telegram alert if the agent stops writing telemetry.
    ///
    /// Examples:
    ///   innerwarden integrate watchdog
    ///   innerwarden integrate watchdog --interval 5
    Watchdog {
        /// How often to check (minutes, default: 10)
        #[arg(long, default_value = "10")]
        interval: u64,
    },
}

#[derive(Subcommand)]
enum ExecGateCommand {
    /// Show the live gate: mode, scope, and allowlist / scope-cgroup counts.
    Status,
    /// Arm the gate around a process's cgroup. `--observe` logs would-be denials
    /// but allows them (the safe onboarding mode). To then enforce, run
    /// `exec-gate rehearse` and `exec-gate enforce` — enforce flips to DENY only
    /// after a clean rehearsal (observe-armed, scoped, zero would-block), never
    /// a blind flip.
    Arm {
        /// PID of the AI agent process to scope the gate to.
        #[arg(long)]
        pid: u32,
        /// Observe mode: log what the gate WOULD block but allow it. Required
        /// today (the only safe, non-bricking mode without a rehearsal).
        #[arg(long)]
        observe: bool,
        /// A binary path to allowlist (repeatable). Observe tolerates an empty
        /// allowlist — it simply learns what the agent runs.
        #[arg(long = "path")]
        paths: Vec<String>,
    },
    /// Rehearse: show what the gate WOULD block for a pid's cgroup over a recent
    /// window (read-only). Run before `enforce` to confirm zero would-block and to
    /// see which binaries still need allowlisting.
    Rehearse {
        /// PID of the AI agent process whose cgroup to inspect.
        #[arg(long)]
        pid: u32,
        /// Lookback window in seconds (default 300).
        #[arg(long)]
        window: Option<u64>,
    },
    /// Enforce: flip the gate to DENY unknown execs in the pid's cgroup. Succeeds
    /// only after a clean rehearsal (observe-armed, scoped to the pid, zero
    /// would-block in the window) — never a blind flip.
    Enforce {
        /// PID of the AI agent process to enforce around.
        #[arg(long)]
        pid: u32,
        /// Rehearsal window in seconds to require clean (default 300).
        #[arg(long)]
        window: Option<u64>,
    },
    /// Disarm: return the gate to inert. Always safe, no preconditions.
    Disarm,
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Compute and print a publishable anchor over the decision log's tip.
    ///
    /// Record the output OUTSIDE this host (a second box, a ticket, a
    /// transparency log). Human-readable by default; `--json` emits a single
    /// line that round-trips into `audit verify --anchor`. Prints nothing to
    /// anchor when the log is empty.
    Anchor {
        /// Emit the anchor as a single-line JSON object.
        #[arg(long)]
        json: bool,
    },
    /// Verify the live decision log against a previously-published anchor.
    ///
    /// Exit code is non-zero on tamper (Truncated / Rewritten), so this can gate
    /// CI or a monitoring probe. Provide the anchor via `--file` or `--anchor`.
    Verify {
        /// Path to a JSON anchor file (as written by `audit anchor --json`).
        #[arg(long)]
        file: Option<PathBuf>,
        /// The anchor as an inline JSON string (alternative to `--file`).
        #[arg(long)]
        anchor: Option<String>,
        /// Emit the verdict as JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum RuleCommand {
    /// List rules. Shows all types by default
    /// (event_pipeline, sigma, yara, atr, correlation, playbooks).
    ///
    /// Examples:
    ///   innerwarden rule list
    ///   innerwarden rule list --type sigma
    ///   innerwarden rule list --type correlation
    ///   innerwarden rule list --type playbooks
    List {
        /// Filter by rule type: event_pipeline, sigma, yara, atr, correlation, playbooks
        #[arg(long, short = 't')]
        r#type: Option<String>,
    },

    /// Disable a rule by ID (adds `disabled: true` to the YAML file).
    ///
    /// CL-NNN IDs route to /etc/innerwarden/rules/correlation/; other IDs
    /// route to the event pipeline rules directory.
    Disable {
        /// Rule ID to disable (e.g. drop-service-daemon-file-ops or CL-024)
        id: String,
    },

    /// Enable a previously disabled rule by ID.
    ///
    /// CL-NNN IDs route to /etc/innerwarden/rules/correlation/.
    Enable {
        /// Rule ID to enable (e.g. drop-service-daemon-file-ops or CL-024)
        id: String,
    },

    /// Convert allowlist.toml to event pipeline YAML rules.
    ///
    /// Convert allowlist.toml to event pipeline YAML rules.
    ///
    /// Process entries become drop rules; per-detector entries become
    /// suppress_incident rules. IPs/ports remain as comments (not yet
    /// in the pipeline DSL).
    ///
    /// Examples:
    ///   innerwarden rule migrate-allowlist
    ///   innerwarden rule migrate-allowlist --output /etc/innerwarden/rules/event_pipeline/20-migrated.yml
    MigrateAllowlist {
        /// Path to allowlist.toml (defaults to /etc/innerwarden/allowlist.toml)
        #[arg(long, default_value = "/etc/innerwarden/allowlist.toml")]
        input: PathBuf,

        /// Write output to file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PlaybookCommand {
    /// Dry-run a playbook against a captured incident (no skills fire, no
    /// audit written). Talks to the running agent's dashboard API.
    ///
    /// Examples:
    ///   innerwarden playbook test pb-data-exfil-default --incident-file last.jsonl
    ///   innerwarden playbook test pb-x -f inc.json --url http://10.0.0.5:8787 --user admin --password s3cret
    Test {
        /// Playbook ID (e.g. pb-data-exfil-default)
        id: String,

        /// Path to a captured incident: a JSON object or a line copied
        /// from incidents-<date>.jsonl (first non-empty line is used).
        #[arg(long, short = 'f')]
        incident_file: PathBuf,

        /// Dashboard base URL (default http://127.0.0.1:8787).
        #[arg(long)]
        url: Option<String>,

        /// Basic-auth user (or INNERWARDEN_DASHBOARD_USER).
        #[arg(long)]
        user: Option<String>,

        /// Basic-auth password (or INNERWARDEN_DASHBOARD_PASSWORD).
        #[arg(long)]
        password: Option<String>,

        /// Skip TLS certificate verification. The agent dashboard serves
        /// HTTPS with a self-signed cert, so `--url https://...` otherwise
        /// fails with `UnknownIssuer`. Do NOT use over an untrusted network.
        #[arg(long)]
        insecure: bool,
    },
}

#[derive(Subcommand)]
enum ModuleCommand {
    /// Validate a module package (manifest, structure, security, docs, tests)
    Validate {
        /// Path to the module directory
        path: PathBuf,

        /// Enable stricter security checks (unsafe blocks, etc.)
        #[arg(long)]
        strict: bool,
    },

    /// Enable a module (patch configs, install sudoers, restart services)
    Enable {
        /// Path to the module directory containing module.toml
        path: PathBuf,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Disable a module (revert config patches, remove sudoers, restart services)
    Disable {
        /// Path to the module directory containing module.toml
        path: PathBuf,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// List all modules found in the modules directory
    List {
        /// Directory to scan for module packages (each subdirectory with a module.toml)
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,
    },

    /// Show the status of a specific module by ID
    Status {
        /// Module ID (e.g. "search-protection")
        id: String,

        /// Directory to scan for module packages
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,
    },

    /// Search available modules from the InnerWarden registry
    ///
    /// Fetches the live registry from the repository and lists all modules,
    /// optionally filtering by name, tag, or description.
    ///
    /// Examples:
    ///   innerwarden module search
    ///   innerwarden module search ssh
    ///   innerwarden module search honeypot
    Search {
        /// Filter by name, tag, or description (case-insensitive)
        query: Option<String>,
    },

    /// Install a module by name, URL, or local path
    ///
    /// Accepts:
    ///   - A module name from the registry:  innerwarden module install ssh-protection
    ///   - An HTTPS URL to a .tar.gz:        innerwarden module install https://...
    ///   - A local file or directory path:   innerwarden module install ./my-module
    ///
    /// Built-in modules are enabled directly without downloading anything.
    Install {
        /// Module name (registry), HTTPS URL, or local path to a .tar.gz / directory
        source: String,

        /// Directory where modules are installed
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,

        /// Enable the module immediately after installing
        #[arg(long)]
        enable: bool,

        /// Overwrite if the module ID is already installed
        #[arg(long)]
        force: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Remove an installed module (disables it first if needed)
    Uninstall {
        /// Module ID to remove
        id: String,

        /// Directory where modules are installed
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Package a module directory into a distributable .tar.gz
    Publish {
        /// Path to the module directory
        path: PathBuf,

        /// Output file (defaults to <id>-v<version>.tar.gz in current directory)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Check installed modules for updates and apply them
    UpdateAll {
        /// Directory where modules are installed
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,

        /// Only report available updates without installing
        #[arg(long)]
        check: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

/// GDPR data subject sub-commands.
#[derive(Subcommand)]
enum GdprCommand {
    /// Export all data matching an entity (IP or username).
    ///
    /// Scans events, incidents, decisions, admin-actions, and telemetry files
    /// for any record referencing the given entity and outputs matching lines.
    ///
    /// Examples:
    ///   innerwarden gdpr export --entity 203.0.113.10
    ///   innerwarden gdpr export --entity root --output /tmp/root-data.jsonl
    Export {
        /// IP address or username to search for
        #[arg(long)]
        entity: String,
        /// Output file path (default: stdout)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Erase all data matching an entity (right to erasure, GDPR Art. 17).
    ///
    /// Removes all matching records from JSONL data files via atomic rewrite.
    /// Hash-chained files (decisions, admin-actions) are recomputed after erasure.
    /// The erase itself is recorded in the admin-actions audit trail.
    ///
    /// Examples:
    ///   innerwarden gdpr erase --entity 203.0.113.10
    ///   innerwarden gdpr erase --entity root --yes
    Erase {
        /// IP address or username to erase
        #[arg(long)]
        entity: String,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

// ---------------------------------------------------------------------------
// New grouped command enums (UX refactor: 8 top-level groups)
// ---------------------------------------------------------------------------

/// Read and query operations — everything that fetches data without changing state.
#[derive(Subcommand)]
enum GetCommand {
    /// Global system overview (services, capabilities, modules, today's activity).
    ///
    /// With no arguments: global overview.
    /// With a target: chronological timeline for that IP or user.
    ///
    /// Examples:
    ///   innerwarden get status
    ///   innerwarden get status 203.0.113.10
    ///   innerwarden get status root --days 7
    Status {
        /// IP address or username to inspect (omit for global overview)
        target: Option<String>,

        /// Directory to scan for installed modules (used in global overview)
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,

        /// How many days back to search when looking up an entity (default: 3)
        #[arg(long, default_value = "3")]
        days: u64,
    },

    /// List recent security incidents detected on this host.
    ///
    /// Examples:
    ///   innerwarden get incidents
    ///   innerwarden get incidents --days 2
    ///   innerwarden get incidents --severity high
    Incidents {
        /// How many days back to look (default: 1 = today only)
        #[arg(long, default_value = "1")]
        days: u64,

        /// Filter by minimum severity: low, medium, high, critical
        #[arg(long, default_value = "low")]
        severity: String,

        /// Stream new incidents in real time (Ctrl-C to stop)
        #[arg(long)]
        live: bool,
    },

    /// Show recent decisions made by InnerWarden (blocks, suspensions, ignores).
    ///
    /// Examples:
    ///   innerwarden get decisions
    ///   innerwarden get decisions --days 7
    ///   innerwarden get decisions --action block_ip
    Decisions {
        /// How many days back to look (default: 1 = today only)
        #[arg(long, default_value = "1")]
        days: u64,

        /// Filter by action: block_ip, suspend_user_sudo, ignore, monitor, honeypot
        #[arg(long)]
        action: Option<String>,
    },

    /// Show response (enforcement) audit log: active blocks + recent reverts.
    ///
    /// Reads the agent's `responses.json` on disk (the same source that drove
    /// the dashboard's Responses tab before it was removed in 2026-05-15). For
    /// the live dashboard view, open Cases → "View all enforcement". For
    /// per-attacker enforcement, click the attacker on Cases.
    ///
    /// Examples:
    ///   innerwarden get responses
    ///   innerwarden get responses --history --since-days 7
    ///   innerwarden get responses --ip 1.2.3.4
    Responses {
        /// Include the recent revert history (off by default — active blocks only)
        #[arg(long)]
        history: bool,

        /// When --history is set, how many days back to include (default: 7)
        #[arg(long, default_value = "7")]
        since_days: u64,

        /// Filter both active list and history to one target IP
        #[arg(long)]
        ip: Option<String>,
    },

    /// Print the daily security report in the terminal.
    ///
    /// Examples:
    ///   innerwarden get report
    ///   innerwarden get report --date yesterday
    Report {
        /// Date to show: today, yesterday, or YYYY-MM-DD (default: today)
        #[arg(long, default_value = "today")]
        date: String,
    },

    /// Show detailed metrics from today's telemetry snapshot.
    ///
    /// Examples:
    ///   innerwarden get metrics
    Metrics,

    /// Show which collectors are active and their event counts today.
    ///
    /// Examples:
    ///   innerwarden get sensors
    Sensors,

    /// Show the host posture snapshot (sshd / services / sudo / firewall).
    ///
    /// Read-only view of the snapshot the agent uses for severity
    /// downgrade (spec 044 Phase 2). Refreshed by the agent every
    /// 10 min — this command just pretty-prints `data_dir/posture.json`.
    ///
    /// Examples:
    ///   innerwarden get posture
    Posture,

    /// Show the full activity history for an IP or user.
    ///
    /// Examples:
    ///   innerwarden get entity 203.0.113.10
    ///   innerwarden get entity root --days 7
    #[clap(hide = true)]
    Entity {
        /// IP address or username to look up
        target: String,

        /// How many days back to search (default: 3)
        #[arg(long, default_value = "3")]
        days: u64,
    },
}

/// Manual response actions — block or unblock IPs.
#[derive(Subcommand)]
enum ActionCommand {
    /// Block an IP address at the firewall and record it in the audit trail.
    ///
    /// Examples:
    ///   innerwarden action block 1.2.3.4 --reason "manual block after investigation"
    Block {
        /// IP address to block
        ip: String,

        /// Reason for the block (required - kept in audit trail)
        #[arg(long)]
        reason: String,
    },

    /// Remove a previously blocked IP from the firewall.
    ///
    /// Examples:
    ///   innerwarden action unblock 1.2.3.4 --reason "false positive"
    Unblock {
        /// IP address to unblock
        ip: String,

        /// Reason for removing the block (required - kept in audit trail)
        #[arg(long)]
        reason: String,
    },
}

/// Trust management — allowlist and suppression operations.
#[derive(Subcommand)]
enum TrustCommand {
    /// Add a trusted IP, CIDR, or user to the allowlist.
    ///
    /// Examples:
    ///   innerwarden trust add --ip 10.0.0.1 --reason "office NAT"
    ///   innerwarden trust add --user deploy --reason "CI/CD service account"
    Add {
        /// IP address or CIDR range to trust
        #[arg(long)]
        ip: Option<String>,

        /// Username to trust
        #[arg(long)]
        user: Option<String>,

        /// Why this entry is being trusted. Recorded in the admin audit
        /// log for future-operator forensics. See `allowlist add` docs.
        #[arg(long)]
        reason: Option<String>,
    },

    /// Remove an IP, CIDR, or user from the allowlist.
    ///
    /// Examples:
    ///   innerwarden trust remove --ip 10.0.0.1
    Remove {
        /// IP address or CIDR to remove
        #[arg(long)]
        ip: Option<String>,

        /// Username to remove
        #[arg(long)]
        user: Option<String>,
    },

    /// Show all currently trusted IPs, CIDRs, and users.
    List,

    /// Suppress an incident pattern from alerting.
    ///
    /// Examples:
    ///   innerwarden trust suppress firmware:trust_degraded
    Suppress {
        /// Pattern to match against incident IDs (substring match)
        pattern: String,
    },

    /// Remove a suppression pattern (re-enable alerting).
    ///
    /// Examples:
    ///   innerwarden trust unsuppress firmware:trust_degraded
    Unsuppress {
        /// Pattern to remove
        pattern: String,
    },

    /// Show all active suppression patterns.
    Suppressions,
}

/// All configuration — AI, responder, notifications, integrations, mesh.
#[derive(Subcommand)]
enum ConfigAllCommand {
    /// Configure AI provider and model.
    ///
    /// Examples:
    ///   innerwarden config ai
    ///   innerwarden config ai openai --key sk-...
    Ai {
        /// Provider name: openai, anthropic, groq, deepseek, mistral, xai, gemini, ollama, etc.
        provider: Option<String>,

        /// API key for the provider
        #[arg(long)]
        key: Option<String>,

        /// Model to use (if omitted, the wizard fetches available models)
        #[arg(long)]
        model: Option<String>,

        /// Custom base URL for OpenAI-compatible APIs
        #[arg(long)]
        base_url: Option<String>,
    },

    /// Configure responder mode (enable/disable, dry-run).
    ///
    /// Examples:
    ///   innerwarden config responder --enable --dry-run false
    Responder {
        /// Enable the responder
        #[arg(long)]
        enable: bool,

        /// Dry-run mode: true = log only, false = execute for real
        #[arg(long)]
        dry_run: Option<bool>,
    },

    /// Set notification sensitivity level.
    ///
    /// Examples:
    ///   innerwarden config sensitivity quiet
    Sensitivity {
        /// Level: quiet, normal, or verbose
        level: String,
    },

    /// Configure two-factor authentication for sensitive actions.
    ///
    /// Examples:
    ///   innerwarden config 2fa
    #[command(name = "2fa")]
    TwoFa,

    /// Set up Telegram notifications.
    ///
    /// Examples:
    ///   innerwarden config telegram
    ///   innerwarden config telegram --token 123:ABC --chat-id 456789
    Telegram {
        /// Bot token from @BotFather
        #[arg(long)]
        token: Option<String>,

        /// Your Telegram chat ID
        #[arg(long)]
        chat_id: Option<String>,

        /// Skip the test message after configuring
        #[arg(long)]
        no_test: bool,
    },

    /// Set up Slack notifications.
    ///
    /// Examples:
    ///   innerwarden config slack
    ///   innerwarden config slack --webhook-url https://hooks.slack.com/services/...
    Slack {
        /// Slack Incoming Webhook URL
        #[arg(long)]
        webhook_url: Option<String>,

        /// Minimum severity to notify: low, medium, high, critical
        #[arg(long, default_value = "high")]
        min_severity: String,

        /// Skip the test message after configuring
        #[arg(long)]
        no_test: bool,
    },

    /// Set up Discord notifications.
    ///
    /// Examples:
    ///   innerwarden config discord
    ///   innerwarden config discord --webhook-url https://discord.com/api/webhooks/...
    Discord {
        /// Discord Incoming Webhook URL
        #[arg(long)]
        webhook_url: Option<String>,

        /// Minimum severity to notify: low, medium, high, critical
        #[arg(long, default_value = "high")]
        min_severity: String,

        /// Skip the test message after configuring
        #[arg(long)]
        no_test: bool,
    },

    /// Set up HTTP webhook notifications.
    ///
    /// Examples:
    ///   innerwarden config webhook --url https://hooks.example.com/notify
    Webhook {
        /// Webhook URL
        #[arg(long)]
        url: Option<String>,

        /// Minimum severity to forward
        #[arg(long, default_value = "high")]
        min_severity: String,

        /// Skip the test request after configuring
        #[arg(long)]
        no_test: bool,
    },

    /// Set up the local security dashboard.
    ///
    /// Examples:
    ///   innerwarden config dashboard
    Dashboard {
        /// Dashboard username (default: admin)
        #[arg(long, default_value = "admin")]
        user: String,

        /// Dashboard password
        #[arg(long)]
        password: Option<String>,
    },

    /// Set up browser Web Push notifications.
    ///
    /// Examples:
    ///   innerwarden config web-push
    #[clap(name = "web-push")]
    WebPush {
        /// VAPID subject
        #[arg(long)]
        subject: Option<String>,
    },

    /// Configure the daily Telegram digest hour.
    ///
    /// Examples:
    ///   innerwarden config digest 9
    ///   innerwarden config digest off
    Digest {
        /// Hour (0-23) for daily digest, or "off" to disable
        hour: String,
    },

    /// Configure the daily Telegram notification budget.
    ///
    /// Examples:
    ///   innerwarden config budget 5
    Budget {
        /// Max immediate notifications per day
        max: u32,
    },

    /// Send a test alert to all configured notification channels.
    ///
    /// Examples:
    ///   innerwarden config test-alert
    #[clap(name = "test-alert")]
    TestAlert {
        /// Only test a specific channel: telegram, slack, or webhook
        #[arg(long)]
        channel: Option<String>,
    },

    /// Enable GeoIP country/ISP enrichment.
    ///
    /// Examples:
    ///   innerwarden config geoip
    Geoip,

    /// Set up AbuseIPDB IP reputation enrichment.
    ///
    /// Examples:
    ///   innerwarden config abuseipdb --api-key <key>
    Abuseipdb {
        /// AbuseIPDB API key
        #[arg(long)]
        api_key: Option<String>,

        /// Auto-block IPs with abuse confidence score >= this threshold
        #[arg(long)]
        auto_block_threshold: Option<u8>,
    },

    /// Push blocked IPs to Cloudflare edge via IP Access Rules API.
    ///
    /// Examples:
    ///   innerwarden config cloudflare --zone-id <id> --api-token <token>
    Cloudflare {
        /// Cloudflare Zone ID
        #[arg(long)]
        zone_id: Option<String>,

        /// Cloudflare API token
        #[arg(long)]
        api_token: Option<String>,
    },

    /// Set up automatic health monitoring via cron (watchdog).
    ///
    /// Examples:
    ///   innerwarden config watchdog --interval 5
    Watchdog {
        /// How often to check (minutes, default: 10)
        #[arg(long, default_value = "10")]
        interval: u64,
    },

    /// Collaborative defense mesh network sub-commands.
    ///
    /// Examples:
    ///   innerwarden config mesh enable
    ///   innerwarden config mesh add-peer https://peer:8790
    ///   innerwarden config mesh status
    Mesh {
        #[command(subcommand)]
        command: MeshCommand,
    },

    /// Validate `agent.toml` against the strict AgentConfig schema.
    ///
    /// Wave 9e (2026-05-04): every nested config struct now has
    /// `#[serde(deny_unknown_fields)]`. Typo'd or invented keys produce a
    /// loud error at agent boot - this command surfaces those errors
    /// BEFORE the deploy so the operator can fix them without bricking
    /// prod.
    ///
    /// Run before every deploy. `scripts/deploy-prod.sh` calls this in
    /// step `[-1/4]` automatically; use it manually when editing
    /// `agent.toml` to verify the change parses cleanly.
    ///
    /// Examples:
    ///   innerwarden config validate
    ///   innerwarden config validate --path /etc/innerwarden/agent.toml
    ///   innerwarden config validate --path ./my-test-agent.toml
    Validate {
        /// Path to agent.toml. Defaults to /etc/innerwarden/agent.toml.
        #[arg(long, default_value = "/etc/innerwarden/agent.toml")]
        path: PathBuf,
    },
}

/// System health, tuning, security, and data management.
#[derive(Subcommand)]
enum SystemCommand {
    /// Run system diagnostics and print fix hints for any issues found.
    Doctor,

    /// Inject a synthetic incident and verify the full pipeline responds.
    ///
    /// Examples:
    ///   innerwarden system test
    ///   innerwarden system test --wait 20
    #[clap(name = "test")]
    PipelineTest {
        /// Maximum seconds to wait for the agent to respond (default: 12)
        #[arg(long, default_value = "12")]
        wait: u64,
    },

    /// Scan system configuration and suggest security hardening improvements.
    ///
    /// Examples:
    ///   innerwarden system harden
    ///   innerwarden system harden --verbose
    Harden {
        /// Show all passed checks in addition to findings
        #[arg(long)]
        verbose: bool,
    },

    /// Interactively tune detector thresholds based on recent noise and signal.
    ///
    /// Examples:
    ///   innerwarden system tune
    ///   innerwarden system tune --days 14
    Tune {
        /// How many days of history to analyse (default: 7)
        #[arg(long, default_value = "7")]
        days: u64,

        /// Apply suggested changes without interactive prompts
        #[arg(long)]
        yes: bool,
    },

    /// Discover running services, open ports, and outbound connections.
    /// Generates a calibration report the operator can review and approve.
    ///
    /// Examples:
    ///   innerwarden system calibrate
    Calibrate,

    /// Scan this machine and recommend the best modules for your setup.
    ///
    /// Examples:
    ///   innerwarden system scan
    Scan {
        /// Directory to look for module docs
        #[arg(long, default_value = "")]
        modules_dir: String,
    },

    /// Check agent health and alert via Telegram if it appears stuck.
    ///
    /// Examples:
    ///   innerwarden system watchdog
    ///   innerwarden system watchdog --threshold 600
    Watchdog {
        /// How many seconds of silence before reporting unhealthy (default: 300)
        #[arg(long, default_value = "300")]
        threshold: u64,

        /// Send a Telegram alert when the agent appears unhealthy
        #[arg(long)]
        notify: bool,

        /// Show watchdog cron schedule and last-run info
        #[arg(long)]
        status: bool,
    },

    /// Export events, incidents, or decisions to CSV or JSON.
    ///
    /// Examples:
    ///   innerwarden system export incidents
    ///   innerwarden system export decisions --from 2026-03-01
    Export {
        /// What to export: events, incidents, or decisions
        #[arg(default_value = "incidents")]
        kind: String,

        /// Start date (YYYY-MM-DD)
        #[arg(long)]
        from: Option<String>,

        /// End date inclusive (YYYY-MM-DD)
        #[arg(long)]
        to: Option<String>,

        /// Output format: json or csv
        #[arg(long, default_value = "json")]
        format: String,

        /// Output file (default: stdout)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Back up InnerWarden configuration files to a tar.gz archive.
    ///
    /// Examples:
    ///   innerwarden system backup
    Backup {
        /// Output path for the archive
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// GDPR data subject operations (export & erase).
    ///
    /// Examples:
    ///   innerwarden system gdpr export --entity 203.0.113.10
    ///   innerwarden system gdpr erase --entity root --yes
    Gdpr {
        #[command(subcommand)]
        action: GdprCommand,
    },

    /// Export MITRE ATT&CK Navigator layer showing detection coverage.
    ///
    /// Examples:
    ///   innerwarden system navigator > coverage.json
    Navigator {
        /// Write to file instead of stdout.
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Audit Ring -2 firmware security (SMM, MSR, UEFI, TPM, ACPI, SPI).
    ///
    /// Examples:
    ///   innerwarden system smm
    ///   innerwarden system smm --json
    ///   innerwarden system smm --baseline
    ///   innerwarden system smm --drift
    Smm {
        /// Output as JSON instead of human-readable format.
        #[arg(long)]
        json: bool,

        /// Capture firmware baseline for drift detection.
        #[arg(long)]
        baseline: bool,

        /// Show what changed since the last baseline.
        #[arg(long)]
        drift: bool,
    },

    /// Audit Ring -1 hypervisor integrity (VM detection, KVM monitoring).
    ///
    /// Examples:
    ///   innerwarden system hypervisor
    ///   innerwarden system hypervisor --json
    Hypervisor {
        /// Output as JSON instead of human-readable format.
        #[arg(long)]
        json: bool,
    },

    /// Show the block-rate circuit breaker state for the current UTC hour.
    ///
    /// When `responder.circuit_breaker_mode = "pause"` the agent refuses
    /// every auto-block once the hourly cap is crossed, to stop cascade
    /// incidents (see operator incident 2026-04-18). This command lets
    /// you inspect the current hour's counter and trip marker.
    ///
    /// Examples:
    ///   innerwarden system circuit-status
    ///   innerwarden system circuit-status --json
    #[clap(name = "circuit-status")]
    CircuitStatus {
        /// Output as JSON instead of human-readable format.
        #[arg(long)]
        json: bool,
    },

    /// Clear the circuit breaker for the current UTC hour. Use this once
    /// you have diagnosed the cascade source and want to resume autonomous
    /// blocking without waiting for the next hour boundary.
    ///
    /// Examples:
    ///   innerwarden system circuit-reset
    ///   innerwarden system circuit-reset --json
    #[clap(name = "circuit-reset")]
    CircuitReset {
        /// Output as JSON instead of human-readable format.
        #[arg(long)]
        json: bool,
    },

    /// Cross-check firewall DENY rules against the cloud provider
    /// safelist and release any that now fall inside a known safe range.
    ///
    /// Motivating case: the CL-008 cascade in April 2026 installed ufw
    /// rules blocking Cloudflare and Oracle OCI peer ranges before the
    /// safelist existed. New blocks are refused by the safelist, but the
    /// old rules rot until their 7-day TTL expires. This command walks
    /// the current firewall state and offers a cleanup plan.
    ///
    /// Dry-run by default; pass --apply to actually unblock.
    ///
    /// Examples:
    ///   innerwarden system reconcile-blocks
    ///   innerwarden system reconcile-blocks --apply
    #[clap(name = "reconcile-blocks")]
    ReconcileBlocks {
        /// Release every matching rule. Without this flag the command is
        /// a dry run and only prints what it would do.
        #[arg(long)]
        apply: bool,
    },

    /// Document or list intentional breaks in the decisions hash chain.
    ///
    /// The agent's hourly maintenance verifier walks the decisions
    /// table SHA-256 chain. A row whose hash does not match its prev
    /// triggers a "DATABASE SECURITY ALERT — HASH CHAIN BROKEN"
    /// Telegram message — meant to catch tampering. But manual SQL
    /// recovery (orphan sweeps, bulk imports, schema rewrites) also
    /// breaks the chain legitimately, and without registration the
    /// alert fires every hour forever.
    ///
    /// `register` documents an intentional break so the verifier
    /// stops alerting for that range. `list` shows what is on file.
    ///
    /// Examples:
    ///   innerwarden chain-break register --start 9876 --end 14577 \
    ///       --operator alice --reason "manual orphan recovery 2026-04-29"
    ///   innerwarden chain-break list
    ///   innerwarden chain-break list --json
    #[clap(name = "chain-break")]
    ChainBreak {
        #[command(subcommand)]
        command: ChainBreakCommand,
    },
}

#[derive(Subcommand)]
enum ChainBreakCommand {
    /// Register a documented break for rowid range [--start, --end].
    Register {
        /// First decisions.id in the documented break range.
        #[arg(long)]
        start: i64,
        /// Last decisions.id in the documented break range (inclusive).
        #[arg(long)]
        end: i64,
        /// Operator name — recorded for audit. Free text; pick something
        /// the next maintainer will recognize ("alice", "ops-2026-05-01").
        #[arg(long)]
        operator: String,
        /// Why the break exists. Required — undocumented breaks are
        /// the only thing that should ever fire the security alert,
        /// so registrations must be self-explanatory.
        #[arg(long)]
        reason: String,
        /// Output as JSON instead of human-readable format.
        #[arg(long)]
        json: bool,
    },
    /// List every registered chain break.
    List {
        /// Output as JSON instead of human-readable format.
        #[arg(long)]
        json: bool,
    },
}

// ---------------------------------------------------------------------------
// Dispatch helpers (extracted to avoid bloating main match)
// ---------------------------------------------------------------------------

fn dispatch_config(cli: &Cli, command: &Option<ConfigAllCommand>) -> Result<()> {
    match command {
        None => commands::ops::cmd_configure_menu(cli),
        Some(ConfigAllCommand::Ai {
            ref provider,
            ref key,
            ref model,
            ref base_url,
        }) => {
            if provider.is_none() {
                commands::ai::cmd_configure_ai_interactive(cli)
            } else {
                commands::ai::cmd_configure_ai(
                    cli,
                    provider.as_deref().unwrap(),
                    key.as_deref(),
                    model.as_deref(),
                    base_url.as_deref(),
                )
            }
        }
        Some(ConfigAllCommand::Responder { enable, dry_run }) => {
            commands::responder::cmd_configure_responder(cli, *enable, false, *dry_run)
        }
        Some(ConfigAllCommand::Sensitivity { ref level }) => {
            commands::ops::cmd_configure_sensitivity(cli, level)
        }
        Some(ConfigAllCommand::TwoFa) => commands::ops::cmd_configure_2fa(cli),
        Some(ConfigAllCommand::Telegram {
            ref token,
            ref chat_id,
            no_test,
        }) => commands::notify::cmd_configure_telegram(
            cli,
            token.as_deref(),
            chat_id.as_deref(),
            *no_test,
        ),
        Some(ConfigAllCommand::Slack {
            ref webhook_url,
            ref min_severity,
            no_test,
        }) => commands::notify::cmd_configure_slack(
            cli,
            webhook_url.as_deref(),
            min_severity,
            *no_test,
        ),
        Some(ConfigAllCommand::Discord {
            ref webhook_url,
            ref min_severity,
            no_test,
        }) => commands::notify::cmd_configure_discord(
            cli,
            webhook_url.as_deref(),
            min_severity,
            *no_test,
        ),
        Some(ConfigAllCommand::Webhook {
            ref url,
            ref min_severity,
            no_test,
        }) => commands::notify::cmd_configure_webhook(cli, url.as_deref(), min_severity, *no_test),
        Some(ConfigAllCommand::Dashboard {
            ref user,
            ref password,
        }) => commands::notify::cmd_configure_dashboard(cli, user, password.as_deref()),
        Some(ConfigAllCommand::WebPush { ref subject }) => {
            commands::notify::cmd_notify_web_push_setup(cli, subject.as_deref())
        }
        Some(ConfigAllCommand::Digest { ref hour }) => {
            commands::notify::cmd_configure_digest(cli, hour)
        }
        Some(ConfigAllCommand::Budget { max }) => commands::notify::cmd_configure_budget(cli, *max),
        Some(ConfigAllCommand::TestAlert { ref channel }) => {
            commands::notify::cmd_test_alert(cli, channel.as_deref())
        }
        Some(ConfigAllCommand::Geoip) => commands::integrations::cmd_configure_geoip(cli),
        Some(ConfigAllCommand::Abuseipdb {
            ref api_key,
            auto_block_threshold,
        }) => commands::integrations::cmd_configure_abuseipdb(
            cli,
            api_key.as_deref(),
            *auto_block_threshold,
        ),
        Some(ConfigAllCommand::Cloudflare {
            ref zone_id,
            ref api_token,
        }) => commands::integrations::cmd_configure_cloudflare(
            cli,
            zone_id.as_deref(),
            api_token.as_deref(),
        ),
        Some(ConfigAllCommand::Watchdog { interval }) => {
            commands::integrations::cmd_configure_watchdog(cli, *interval)
        }
        Some(ConfigAllCommand::Mesh { ref command }) => match command {
            MeshCommand::Enable => commands::mesh::cmd_mesh_enable(cli),
            MeshCommand::Disable => commands::mesh::cmd_mesh_disable(cli),
            MeshCommand::AddPeer {
                ref endpoint,
                ref label,
            } => commands::mesh::cmd_mesh_add_peer(cli, endpoint, label.as_deref()),
            MeshCommand::Connect {
                ref endpoint,
                ref label,
            } => commands::mesh::cmd_mesh_connect(cli, endpoint, label.as_deref()),
            MeshCommand::Status => commands::mesh::cmd_mesh_status(cli),
        },
        Some(ConfigAllCommand::Validate { ref path }) => cmd_config_validate(path),
    }
}

/// `innerwarden config validate <path>` — shells out to
/// `innerwarden-agent --validate-config-only --config <path>`. The agent
/// owns the canonical schema, so duplicating the parser here would create
/// a drift surface (the same class of bug AUDIT-002 caught for TOML
/// section names). The shell-out runs in milliseconds because the agent's
/// validate path early-returns BEFORE booting any of run_agent.
///
/// Looks for the agent binary in this order:
///
///   1. `target/release/innerwarden-agent` (dev: post-`cargo build --release`)
///   2. `target/debug/innerwarden-agent` (dev fallback)
///   3. `/usr/local/bin/innerwarden-agent` (standard prod install)
///
/// First match wins. Workspace builds are preferred over `/usr/local/bin/`
/// so a dev that just rebuilt the agent immediately exercises the fresh
/// binary instead of whatever stale copy `make install` once dropped in
/// `/usr/local/bin/`. Production hosts have `target/release` pruned by the
/// deploy script (or never built it locally) so they fall through cleanly.
fn cmd_config_validate(path: &Path) -> Result<()> {
    // Prefer in-workspace builds over /usr/local/bin/ so a dev running
    // `cargo build --release -p innerwarden-agent` then `innerwarden config
    // validate` picks up the freshly-compiled binary, not whatever stale
    // copy is in /usr/local/bin/. Production hosts have target/release
    // pruned by the deploy script (or never built it locally), so they
    // fall through to /usr/local/bin/ as expected.
    let agent_binary = [
        "target/release/innerwarden-agent",
        "target/debug/innerwarden-agent",
        "/usr/local/bin/innerwarden-agent",
    ]
    .into_iter()
    .map(Path::new)
    .find(|p| p.exists())
    .ok_or_else(|| {
        anyhow::anyhow!(
            "innerwarden-agent binary not found. Tried target/release/, target/debug/, /usr/local/bin/.\n\
             Build with `cargo build --release -p innerwarden-agent` or install via deploy-prod.sh."
        )
    })?;

    let status = std::process::Command::new(agent_binary)
        .arg("--validate-config-only")
        .arg("--config")
        .arg(path)
        .status()
        .with_context(|| format!("failed to invoke {}", agent_binary.display()))?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn dispatch_module(cli: &Cli, command: &ModuleCommand) -> Result<()> {
    match command {
        ModuleCommand::Validate { ref path, strict } => {
            commands::module::cmd_module_validate(path, *strict)
        }
        ModuleCommand::Enable { ref path, yes } => {
            commands::module::cmd_module_enable(cli, path, *yes)
        }
        ModuleCommand::Disable { ref path, yes } => {
            commands::module::cmd_module_disable(cli, path, *yes)
        }
        ModuleCommand::Search { ref query } => {
            commands::module::cmd_module_search(query.as_deref())
        }
        ModuleCommand::List { ref modules_dir } => {
            commands::module::cmd_module_list(cli, modules_dir)
        }
        ModuleCommand::Status {
            ref id,
            ref modules_dir,
        } => commands::module::cmd_module_status(cli, id, modules_dir),
        ModuleCommand::Install {
            ref source,
            ref modules_dir,
            enable,
            force,
            yes,
        } => commands::module::cmd_module_install(cli, source, modules_dir, *enable, *force, *yes),
        ModuleCommand::Uninstall {
            ref id,
            ref modules_dir,
            yes,
        } => commands::module::cmd_module_uninstall(cli, id, modules_dir, *yes),
        ModuleCommand::Publish {
            ref path,
            ref output,
        } => commands::module::cmd_module_publish(path, output.as_deref()),
        ModuleCommand::UpdateAll {
            ref modules_dir,
            check,
            yes,
        } => commands::module::cmd_module_update_all(cli, modules_dir, *check, *yes),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Check if we have write access to the config directory.
fn am_root() -> bool {
    // On Windows (spec 085 Phase 0) return false: treat self as non-elevated,
    // so ctl warns / offers a re-exec instead of writing config as if
    // privileged (fail-closed). Real IsUserAnAdmin/token-elevation is a later phase.
    #[cfg(unix)]
    {
        let config_dir = Path::new("/etc/innerwarden");
        if config_dir.exists() {
            // Try to check write permission
            std::fs::metadata(config_dir)
                .map(|m| {
                    use std::os::unix::fs::MetadataExt;
                    m.uid() == 0 && unsafe { libc_geteuid() } == 0
                })
                .unwrap_or(false)
        } else {
            // Config dir doesn't exist yet - need root to create it
            unsafe { libc_geteuid() == 0 }
        }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Safe wrapper for geteuid without libc dep.
#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    // geteuid is always available on Linux/macOS
    extern "C" {
        fn geteuid() -> u32;
    }
    geteuid()
}

/// Re-execute the current command with sudo, with clear user messaging.
fn reexec_with_sudo() -> Result<()> {
    eprintln!("┌─────────────────────────────────────────────────────────┐");
    eprintln!("│  InnerWarden needs root access to write configuration. │");
    eprintln!("│  Your password may be requested by sudo.               │");
    eprintln!("└─────────────────────────────────────────────────────────┘");
    eprintln!();
    let exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let status = std::process::Command::new("sudo")
        .arg(exe)
        .args(&args)
        .status()?;
    std::process::exit(status.code().unwrap_or(1));
}

fn dispatch_install_classifier(
    cli: &Cli,
    model: &str,
    url: Option<&str>,
    sha256: Option<&str>,
    yes: bool,
    configure: bool,
) -> Result<()> {
    commands::ai::cmd_install_classifier(cli, model, url, sha256, yes, configure)
}

fn main() -> Result<()> {
    run_cli(Cli::parse())
}

fn run_cli(mut cli: Cli) -> Result<()> {
    let registry = CapabilityRegistry::default_all();

    // macOS uses /usr/local/etc instead of /etc for config files
    if cfg!(target_os = "macos") {
        let macos_cfg = Path::new("/usr/local/etc/innerwarden");
        if cli.sensor_config == Path::new("/etc/innerwarden/config.toml") {
            cli.sensor_config = macos_cfg.join("config.toml");
        }
        if cli.agent_config == Path::new("/etc/innerwarden/agent.toml") {
            cli.agent_config = macos_cfg.join("agent.toml");
        }
    }

    let Some(command) = cli.command.take() else {
        banner::render(env!("CARGO_PKG_VERSION"), &mut std::io::stdout()).ok();
        use clap::CommandFactory;
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };

    match command {
        // ===================================================================
        // New grouped commands
        // ===================================================================
        Command::Get { command: None } => {
            use clap::CommandFactory;
            let mut app = Cli::command();
            let sub = app.find_subcommand_mut("get").unwrap();
            sub.print_help()?;
            println!();
            Ok(())
        }
        Command::Get {
            command: Some(ref command),
        } => match command {
            GetCommand::Status {
                ref target,
                ref modules_dir,
                days,
            } => match target {
                None => commands::status::cmd_status_global(&cli, &registry, modules_dir),
                Some(ref t) => {
                    if registry.get(t).is_some() {
                        commands::status::cmd_status(&cli, &registry, t)
                    } else {
                        commands::history::cmd_entity(&cli, t, *days, &cli.data_dir.clone())
                    }
                }
            },
            GetCommand::Incidents {
                days,
                ref severity,
                live,
            } => {
                if *live {
                    commands::history::cmd_incidents_live(&cli, severity, &cli.data_dir.clone())
                } else {
                    commands::history::cmd_incidents(&cli, *days, severity, &cli.data_dir.clone())
                }
            }
            GetCommand::Decisions { days, ref action } => commands::history::cmd_decisions(
                &cli,
                *days,
                action.as_deref(),
                &cli.data_dir.clone(),
            ),
            GetCommand::Responses {
                history,
                since_days,
                ref ip,
            } => commands::response::cmd_responses(
                &cli,
                *history,
                *since_days,
                ip.as_deref(),
                &cli.data_dir.clone(),
            ),
            GetCommand::Report { ref date } => {
                commands::status::cmd_report(&cli, date, &cli.data_dir.clone())
            }
            GetCommand::Metrics => commands::status::cmd_metrics(&cli, &cli.data_dir.clone()),
            GetCommand::Sensors => commands::status::cmd_sensor_status(&cli, &cli.data_dir.clone()),
            GetCommand::Posture => commands::status::cmd_posture(&cli, &cli.data_dir.clone()),
            GetCommand::Entity { ref target, days } => {
                commands::history::cmd_entity(&cli, target, *days, &cli.data_dir.clone())
            }
        },
        Command::Stream {
            ref r#type,
            interval,
        } => commands::history::cmd_tail(&cli, r#type, interval, &cli.data_dir.clone()),
        Command::Action { command: None } => {
            use clap::CommandFactory;
            let mut app = Cli::command();
            let sub = app.find_subcommand_mut("action").unwrap();
            sub.print_help()?;
            println!();
            Ok(())
        }
        Command::Action {
            command: Some(ref command),
        } => match command {
            ActionCommand::Block { ref ip, ref reason } => {
                commands::response::cmd_block(&cli, ip, reason, &cli.data_dir.clone())
            }
            ActionCommand::Unblock { ref ip, ref reason } => {
                commands::response::cmd_unblock(&cli, ip, reason, &cli.data_dir.clone())
            }
        },
        Command::Trust { command: None } => {
            use clap::CommandFactory;
            let mut app = Cli::command();
            let sub = app.find_subcommand_mut("trust").unwrap();
            sub.print_help()?;
            println!();
            Ok(())
        }
        Command::Trust {
            command: Some(ref command),
        } => match command {
            TrustCommand::Add {
                ref ip,
                ref user,
                ref reason,
            } => commands::response::cmd_allowlist_add(
                &cli,
                ip.as_deref(),
                user.as_deref(),
                reason.as_deref(),
            ),
            TrustCommand::Remove { ref ip, ref user } => {
                commands::response::cmd_allowlist_remove(&cli, ip.as_deref(), user.as_deref())
            }
            TrustCommand::List => commands::response::cmd_allowlist_list(&cli),
            TrustCommand::Suppress { ref pattern } => {
                commands::response::cmd_suppress_add(&cli, pattern)
            }
            TrustCommand::Unsuppress { ref pattern } => {
                commands::response::cmd_suppress_remove(&cli, pattern)
            }
            TrustCommand::Suppressions => commands::response::cmd_suppress_list(&cli),
        },
        Command::Config { ref command } => dispatch_config(&cli, command),
        Command::System { command: None } => {
            use clap::CommandFactory;
            let mut app = Cli::command();
            let sub = app.find_subcommand_mut("system").unwrap();
            sub.print_help()?;
            println!();
            Ok(())
        }
        Command::System {
            command: Some(ref command),
        } => match command {
            SystemCommand::Doctor => commands::ops::cmd_doctor(&cli, &registry),
            SystemCommand::PipelineTest { wait } => {
                commands::ops::cmd_pipeline_test(&cli, *wait, &cli.data_dir.clone())
            }
            SystemCommand::Harden { verbose } => harden::cmd_harden(*verbose),
            SystemCommand::Tune { days, yes } => {
                commands::ops::cmd_tune(&cli, *days, *yes, &cli.data_dir.clone())
            }
            SystemCommand::Calibrate => calibrate::cmd_calibrate(),
            SystemCommand::Scan { ref modules_dir } => scan::cmd_scan(modules_dir),
            SystemCommand::Watchdog {
                threshold,
                notify,
                status,
            } => {
                if *status {
                    commands::watchdog::cmd_watchdog_status(&cli, &cli.data_dir.clone())
                } else {
                    commands::watchdog::cmd_watchdog(
                        &cli,
                        *threshold,
                        *notify,
                        &cli.data_dir.clone(),
                    )
                }
            }
            SystemCommand::Export {
                ref kind,
                ref from,
                ref to,
                ref format,
                ref output,
            } => commands::history::cmd_export(
                &cli,
                kind,
                from.as_deref(),
                to.as_deref(),
                format,
                output.as_deref(),
                &cli.data_dir.clone(),
            ),
            SystemCommand::Backup { ref output } => {
                commands::ops::cmd_backup(&cli, output.as_deref())
            }
            SystemCommand::Gdpr { ref action } => match action {
                GdprCommand::Export {
                    ref entity,
                    ref output,
                } => commands::history::cmd_gdpr_export(&cli.data_dir, entity, output.as_deref()),
                GdprCommand::Erase { ref entity, yes } => {
                    commands::history::cmd_gdpr_erase(&cli.data_dir, entity, *yes)
                }
            },
            SystemCommand::Navigator { ref output } => {
                commands::status::cmd_navigator(output.as_deref())
            }
            SystemCommand::Smm {
                json,
                baseline,
                drift,
            } => {
                if *baseline {
                    commands::firmware::cmd_smm_baseline()
                } else if *drift {
                    commands::firmware::cmd_smm_drift()
                } else {
                    commands::firmware::cmd_smm(*json)
                }
            }
            SystemCommand::Hypervisor { json } => commands::firmware::cmd_hypervisor(*json),
            SystemCommand::CircuitStatus { json } => {
                commands::circuit::cmd_circuit_status(&cli.agent_config, &cli.data_dir, *json)
            }
            SystemCommand::CircuitReset { json } => {
                commands::circuit::cmd_circuit_reset(&cli.agent_config, &cli.data_dir, *json)
            }
            SystemCommand::ReconcileBlocks { apply } => {
                commands::reconcile::cmd_reconcile_blocks(&cli, &cli.data_dir.clone(), *apply)
            }
            SystemCommand::ChainBreak { ref command } => match command {
                ChainBreakCommand::Register {
                    start,
                    end,
                    operator,
                    reason,
                    json,
                } => commands::chain_break::cmd_chain_break_register(
                    &cli.agent_config,
                    &cli.data_dir,
                    *start,
                    *end,
                    operator,
                    reason,
                    *json,
                ),
                ChainBreakCommand::List { json } => commands::chain_break::cmd_chain_break_list(
                    &cli.agent_config,
                    &cli.data_dir,
                    *json,
                ),
            },
        },

        // ===================================================================
        // Top-level commands (not grouped)
        // ===================================================================
        Command::Setup { ref mode } => commands::setup::cmd_setup(&cli, mode),
        Command::Replay {
            ref fixture,
            ref expected,
        } => commands::replay::cmd_replay(fixture, expected),
        Command::Upgrade {
            check,
            yes,
            notify,
            ref install_dir,
            allow_unsigned_stable,
            allow_unsigned_canary,
        } => commands::update::cmd_upgrade(
            &cli,
            check,
            yes,
            notify,
            install_dir,
            allow_unsigned_stable,
            allow_unsigned_canary,
        ),
        Command::Completions { ref shell } => commands::ops::cmd_completions(shell),
        Command::Enable {
            ref capability,
            ref params,
            yes,
            force,
        } => {
            let params = commands::capability::parse_params(params)?;
            commands::capability::cmd_enable(&cli, &registry, capability, params, yes, force)
        }
        Command::Disable {
            ref capability,
            yes,
        } => commands::capability::cmd_disable(&cli, &registry, capability, yes),
        Command::List => commands::core::cmd_list(&cli, &registry),
        Command::ExecGate { ref command } => match command {
            ExecGateCommand::Status => commands::exec_gate::cmd_status(),
            ExecGateCommand::Arm {
                pid,
                observe,
                ref paths,
            } => commands::exec_gate::cmd_arm(*pid, *observe, paths),
            ExecGateCommand::Rehearse { pid, window } => commands::exec_gate::cmd_rehearse(
                *pid,
                *window,
                &resolve_data_dir(&cli, &cli.data_dir),
            ),
            ExecGateCommand::Enforce { pid, window } => commands::exec_gate::cmd_enforce(
                *pid,
                *window,
                &resolve_data_dir(&cli, &cli.data_dir),
            ),
            ExecGateCommand::Disarm => commands::exec_gate::cmd_disarm(),
        },
        Command::Audit { ref command } => match command {
            AuditCommand::Anchor { json } => {
                commands::audit::cmd_audit_anchor(&cli.agent_config, &cli.data_dir, *json)
            }
            AuditCommand::Verify {
                ref file,
                ref anchor,
                json,
            } => commands::audit::cmd_audit_verify(
                &cli.agent_config,
                &cli.data_dir,
                file.as_deref(),
                anchor.as_deref(),
                *json,
            ),
        },
        Command::SudoSuspend {
            ref user,
            ref expires,
        } => commands::sudo_guard::cmd_sudo_suspend(user, expires),
        Command::SudoRestore { ref user } => commands::sudo_guard::cmd_sudo_restore(user),
        Command::Rule { ref command } => match command {
            RuleCommand::List { ref r#type } => {
                commands::rule::cmd_rule_list_all(&cli.sensor_config, r#type.as_deref())
            }
            RuleCommand::Disable { ref id } => {
                commands::rule::cmd_rule_disable(&cli.data_dir, &cli.sensor_config, id)
            }
            RuleCommand::Enable { ref id } => {
                commands::rule::cmd_rule_enable(&cli.data_dir, &cli.sensor_config, id)
            }
            RuleCommand::MigrateAllowlist {
                ref input,
                ref output,
            } => commands::rule::cmd_migrate_allowlist(input, output.as_deref()),
        },
        Command::Playbook { ref command } => match command {
            PlaybookCommand::Test {
                ref id,
                ref incident_file,
                ref url,
                ref user,
                ref password,
                insecure,
            } => commands::playbook::cmd_playbook_test(
                id,
                incident_file,
                url.as_deref(),
                user.as_deref(),
                password.as_deref(),
                *insecure,
            ),
        },
        Command::Module { ref command } => dispatch_module(&cli, command),
        Command::Agent { ref command } => commands::agent::cmd_agent(&cli, command.as_ref()),

        // ===================================================================
        // Hidden backward-compatibility aliases
        // ===================================================================
        Command::Daily { ref command } => {
            commands::core::cmd_daily(&cli, &registry, command.as_ref())
        }
        Command::Harden { verbose } => harden::cmd_harden(verbose),
        Command::Doctor => commands::ops::cmd_doctor(&cli, &registry),
        Command::Welcome => commands::core::cmd_welcome(),
        Command::Navigator { ref output } => commands::status::cmd_navigator(output.as_deref()),
        Command::Scan { ref modules_dir } => scan::cmd_scan(modules_dir),
        Command::Dashboard { ref action } => {
            let act = action
                .clone()
                .unwrap_or(commands::dashboard::DashboardAction::Status);
            commands::dashboard::run(&act, &cli.agent_config, cli.dry_run)
        }
        Command::Uninstall { purge, yes } => commands::uninstall::cmd_uninstall(&cli, purge, yes),
        Command::Status {
            ref target,
            ref modules_dir,
            days,
        } => match target {
            None => commands::status::cmd_status_global(&cli, &registry, modules_dir),
            Some(ref t) => {
                if registry.get(t).is_some() {
                    commands::status::cmd_status(&cli, &registry, t)
                } else {
                    commands::history::cmd_entity(&cli, t, days, &cli.data_dir.clone())
                }
            }
        },
        Command::Configure { ref command } => match command {
            None => commands::ops::cmd_configure_menu(&cli),
            Some(ConfigureCommand::Ai {
                ref provider,
                ref key,
                ref model,
                ref base_url,
            }) => {
                if provider.is_none() {
                    commands::ai::cmd_configure_ai_interactive(&cli)
                } else {
                    commands::ai::cmd_configure_ai(
                        &cli,
                        provider.as_deref().unwrap(),
                        key.as_deref(),
                        model.as_deref(),
                        base_url.as_deref(),
                    )
                }
            }
            Some(ConfigureCommand::Responder { enable, dry_run }) => {
                commands::responder::cmd_configure_responder(&cli, *enable, false, *dry_run)
            }
            Some(ConfigureCommand::Sensitivity { ref level }) => {
                commands::ops::cmd_configure_sensitivity(&cli, level)
            }
            Some(ConfigureCommand::TwoFa) => commands::ops::cmd_configure_2fa(&cli),
        },
        Command::Notify { ref command } => match command {
            None => commands::ops::cmd_configure_menu(&cli),
            Some(NotifyCommand::Telegram {
                ref token,
                ref chat_id,
                no_test,
            }) => commands::notify::cmd_configure_telegram(
                &cli,
                token.as_deref(),
                chat_id.as_deref(),
                *no_test,
            ),
            Some(NotifyCommand::Slack {
                ref webhook_url,
                ref min_severity,
                no_test,
            }) => commands::notify::cmd_configure_slack(
                &cli,
                webhook_url.as_deref(),
                min_severity,
                *no_test,
            ),
            Some(NotifyCommand::Discord {
                ref webhook_url,
                ref min_severity,
                no_test,
            }) => commands::notify::cmd_configure_discord(
                &cli,
                webhook_url.as_deref(),
                min_severity,
                *no_test,
            ),
            Some(NotifyCommand::Webhook {
                ref url,
                ref min_severity,
                no_test,
            }) => commands::notify::cmd_configure_webhook(
                &cli,
                url.as_deref(),
                min_severity,
                *no_test,
            ),
            Some(NotifyCommand::Dashboard {
                ref user,
                ref password,
            }) => commands::notify::cmd_configure_dashboard(&cli, user, password.as_deref()),
            Some(NotifyCommand::Test { ref channel }) => {
                commands::notify::cmd_test_alert(&cli, channel.as_deref())
            }
            Some(NotifyCommand::WebPush { ref subject }) => {
                commands::notify::cmd_notify_web_push_setup(&cli, subject.as_deref())
            }
            Some(NotifyCommand::Digest { ref hour }) => {
                commands::notify::cmd_configure_digest(&cli, hour)
            }
            Some(NotifyCommand::Budget { max }) => {
                commands::notify::cmd_configure_budget(&cli, *max)
            }
        },
        Command::Integrate { ref command } => match command {
            None => commands::ops::cmd_configure_menu(&cli),
            Some(IntegrateCommand::Geoip) => commands::integrations::cmd_configure_geoip(&cli),
            Some(IntegrateCommand::Abuseipdb {
                ref api_key,
                auto_block_threshold,
            }) => commands::integrations::cmd_configure_abuseipdb(
                &cli,
                api_key.as_deref(),
                *auto_block_threshold,
            ),
            Some(IntegrateCommand::Cloudflare {
                ref zone_id,
                ref api_token,
            }) => commands::integrations::cmd_configure_cloudflare(
                &cli,
                zone_id.as_deref(),
                api_token.as_deref(),
            ),
            Some(IntegrateCommand::Watchdog { interval }) => {
                commands::integrations::cmd_configure_watchdog(&cli, *interval)
            }
        },
        Command::Mesh { ref command } => match command {
            MeshCommand::Enable => commands::mesh::cmd_mesh_enable(&cli),
            MeshCommand::Disable => commands::mesh::cmd_mesh_disable(&cli),
            MeshCommand::AddPeer {
                ref endpoint,
                ref label,
            } => commands::mesh::cmd_mesh_add_peer(&cli, endpoint, label.as_deref()),
            MeshCommand::Connect {
                ref endpoint,
                ref label,
            } => commands::mesh::cmd_mesh_connect(&cli, endpoint, label.as_deref()),
            MeshCommand::Status => commands::mesh::cmd_mesh_status(&cli),
        },
        Command::Incidents {
            days,
            ref severity,
            live,
        } => {
            if live {
                commands::history::cmd_incidents_live(&cli, severity, &cli.data_dir.clone())
            } else {
                commands::history::cmd_incidents(&cli, days, severity, &cli.data_dir.clone())
            }
        }
        Command::Block { ref ip, ref reason } => {
            commands::response::cmd_block(&cli, ip, reason, &cli.data_dir.clone())
        }
        Command::Unblock { ref ip, ref reason } => {
            commands::response::cmd_unblock(&cli, ip, reason, &cli.data_dir.clone())
        }
        Command::Report { ref date } => {
            commands::status::cmd_report(&cli, date, &cli.data_dir.clone())
        }
        Command::Watchdog {
            threshold,
            notify,
            status,
        } => {
            if status {
                commands::watchdog::cmd_watchdog_status(&cli, &cli.data_dir.clone())
            } else {
                commands::watchdog::cmd_watchdog(&cli, threshold, notify, &cli.data_dir.clone())
            }
        }
        Command::Tune { days, yes } => {
            commands::ops::cmd_tune(&cli, days, yes, &cli.data_dir.clone())
        }
        Command::SensorStatus => commands::status::cmd_sensor_status(&cli, &cli.data_dir.clone()),
        Command::Export {
            ref kind,
            ref from,
            ref to,
            ref format,
            ref output,
        } => commands::history::cmd_export(
            &cli,
            kind,
            from.as_deref(),
            to.as_deref(),
            format,
            output.as_deref(),
            &cli.data_dir.clone(),
        ),
        Command::Tail {
            ref r#type,
            interval,
        } => commands::history::cmd_tail(&cli, r#type, interval, &cli.data_dir.clone()),
        Command::Decisions { days, ref action } => {
            commands::history::cmd_decisions(&cli, days, action.as_deref(), &cli.data_dir.clone())
        }
        Command::Entity { ref target, days } => {
            commands::history::cmd_entity(&cli, target, days, &cli.data_dir.clone())
        }
        Command::Allowlist { ref command } => match command {
            AllowlistCommand::Add {
                ref ip,
                ref user,
                ref reason,
            } => commands::response::cmd_allowlist_add(
                &cli,
                ip.as_deref(),
                user.as_deref(),
                reason.as_deref(),
            ),
            AllowlistCommand::Remove { ref ip, ref user } => {
                commands::response::cmd_allowlist_remove(&cli, ip.as_deref(), user.as_deref())
            }
            AllowlistCommand::List => commands::response::cmd_allowlist_list(&cli),
        },
        Command::Suppress { ref command } => match command {
            SuppressCommand::Add { ref pattern } => {
                commands::response::cmd_suppress_add(&cli, pattern)
            }
            SuppressCommand::Remove { ref pattern } => {
                commands::response::cmd_suppress_remove(&cli, pattern)
            }
            SuppressCommand::List => commands::response::cmd_suppress_list(&cli),
        },
        Command::PipelineTest { wait } => {
            commands::ops::cmd_pipeline_test(&cli, wait, &cli.data_dir.clone())
        }
        Command::Backup { ref output } => commands::ops::cmd_backup(&cli, output.as_deref()),
        Command::Metrics => commands::status::cmd_metrics(&cli, &cli.data_dir.clone()),
        Command::Gdpr { ref action } => match action {
            GdprCommand::Export {
                ref entity,
                ref output,
            } => commands::history::cmd_gdpr_export(&cli.data_dir, entity, output.as_deref()),
            GdprCommand::Erase { ref entity, yes } => {
                commands::history::cmd_gdpr_erase(&cli.data_dir, entity, *yes)
            }
        },
        Command::InstallClassifier {
            ref model,
            ref url,
            ref sha256,
            yes,
            configure,
        } => dispatch_install_classifier(
            &cli,
            model,
            url.as_deref(),
            sha256.as_deref(),
            yes,
            configure,
        ),
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

pub(crate) fn today_date_string() -> String {
    // Use SystemTime → seconds since epoch → compute date
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    epoch_secs_to_date_string(secs)
}

/// Return yesterday's date as YYYY-MM-DD.
pub(crate) fn yesterday_date_string() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().saturating_sub(86400))
        .unwrap_or(0);
    epoch_secs_to_date_string(secs)
}

/// Convert Unix timestamp (seconds) to YYYY-MM-DD string (UTC).
pub(crate) fn epoch_secs_to_date_string(secs: u64) -> String {
    // Days since Unix epoch
    let days = secs / 86400;
    // Gregorian calendar calculation
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Count lines in a JSONL file (returns 0 if file doesn't exist).
pub(crate) fn count_jsonl_lines(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
}

/// Read the last incident from a JSONL file and return (title, time_str).
pub(crate) fn read_last_incident_summary(path: &std::path::Path) -> Option<(String, String)> {
    let content = std::fs::read_to_string(path).ok()?;
    let last_line = content.lines().rfind(|l| !l.trim().is_empty())?;
    let v: serde_json::Value = serde_json::from_str(last_line).ok()?;
    let title = v["title"].as_str()?.to_string();
    let ts = v["ts"].as_str()?;

    // Calculate "time ago"
    let time_ago = if let Ok(incident_time) = chrono::DateTime::parse_from_rfc3339(ts) {
        let diff = chrono::Utc::now() - incident_time.with_timezone(&chrono::Utc);
        let mins = diff.num_minutes();
        if mins < 1 {
            "just now".to_string()
        } else if mins < 60 {
            format!("{mins}m ago")
        } else if mins < 1440 {
            format!("{}h ago", mins / 60)
        } else {
            format!("{}d ago", mins / 1440)
        }
    } else if ts.len() >= 16 {
        format!("{} UTC", &ts[11..16])
    } else {
        ts.to_string()
    };

    Some((title, time_ago))
}

// ---------------------------------------------------------------------------
// Configure AI
// ---------------------------------------------------------------------------

// innerwarden configure (interactive menu)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// innerwarden configure fail2ban
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// innerwarden test-alert
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// innerwarden tune
// ---------------------------------------------------------------------------

pub(crate) fn epoch_secs_to_date(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

// ---------------------------------------------------------------------------
// innerwarden block / unblock
// ---------------------------------------------------------------------------

fn write_manual_decision(
    data_dir: &Path,
    ip: &str,
    action: &str,
    reason: &str,
    provider: &str,
) -> Result<()> {
    let today = epoch_secs_to_date(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    let path = data_dir.join(format!("decisions-{today}.jsonl"));
    let now_iso = chrono::Utc::now().to_rfc3339();
    let entry = serde_json::json!({
        "ts": now_iso,
        "action": action,
        "target_ip": ip,
        "reason": reason,
        "ai_provider": provider,
        "confidence": 1.0,
        "executed": true,
        "dry_run": false,
    });
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    use std::io::Write;
    writeln!(file, "{}", entry)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn make_opts(
    cli: &Cli,
    params: HashMap<String, String>,
    yes: bool,
) -> ActivationOptions {
    ActivationOptions {
        sensor_config: cli.sensor_config.clone(),
        agent_config: cli.agent_config.clone(),
        dry_run: cli.dry_run,
        params,
        yes,
        defer_restarts: false,
    }
}

/// 2026-05-04 (Wave 7b): the registry.toml that ships at the repo
/// root, embedded at compile time so we can suggest `module install`
/// from inside the capability error path WITHOUT making a network
/// request. Keeps the suggestion offline-friendly and always in sync
/// with the source-of-truth registry.
const EMBEDDED_REGISTRY: &str = include_str!("../../../registry.toml");

/// 2026-05-04 (Wave 7b): does the given name match a built-in module
/// declared in `registry.toml`? Used by `unknown_cap_error` to point
/// the operator at the correct surface (`module install`) instead of
/// leaving them to grep through `innerwarden list` output.
///
/// Implementation is a deliberately stupid line scan against the
/// embedded registry. We only care about `id = "..."` declarations
/// and the registry has fewer than 20 entries, so a full TOML parser
/// would be overkill for this error path. Tolerates any whitespace
/// between `id` and `=` so registry reformatting does not silently
/// break the helpful suggestion.
fn known_module_id(name: &str) -> bool {
    let target = format!("\"{name}\"");
    EMBEDDED_REGISTRY.lines().any(|line| {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("id") {
            return false;
        }
        let rest = trimmed[2..].trim_start();
        rest.starts_with('=') && rest[1..].trim_start().starts_with(&target)
    })
}

pub(crate) fn unknown_cap_error(id: &str) -> anyhow::Error {
    if known_module_id(id) {
        // Bug-class fix from 2026-05-04: operator runs
        // `sudo innerwarden enable openclaw-protection` and the old
        // error left them to grep through `innerwarden list` (which
        // does not show modules at all). Now we point them at the
        // module surface directly.
        anyhow::anyhow!(
            "no capability '{id}', but '{id}' is a registered module.\n\
             Try: sudo innerwarden module install {id}\n\
             \n\
             Modules and capabilities are different surfaces. Capabilities \
             are toggled with `enable`/`disable`; modules are installed and \
             enabled separately. Run `innerwarden module list` to see \
             installed modules, or `innerwarden module search` to browse \
             the registry."
        )
    } else {
        anyhow::anyhow!(
            "unknown capability '{}' - run 'innerwarden list' to see available capabilities",
            id
        )
    }
}

// ---------------------------------------------------------------------------
// innerwarden allowlist
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// innerwarden notify web-push setup
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::setup::{
        ai_provider_defaults, count_failed_setup_checks, setup_remediation_command, setup_verdict,
        SetupCheck,
    };
    use clap::Parser;
    use tempfile::TempDir;

    fn make_cli(data_dir: &std::path::Path) -> Cli {
        Cli {
            sensor_config: data_dir.join("config.toml"),
            agent_config: data_dir.join("agent.toml"),
            data_dir: data_dir.to_path_buf(),
            dry_run: false,
            command: Some(Command::Decisions {
                days: 1,
                action: None,
            }),
        }
    }

    fn write_minimal_cli_configs(data_dir: &std::path::Path) {
        std::fs::write(
            data_dir.join("config.toml"),
            format!(
                r#"
[agent]
host_id = "ctl-test-host"

[output]
data_dir = "{}"
"#,
                data_dir.display()
            ),
        )
        .expect("write sensor config");
        std::fs::write(
            data_dir.join("agent.toml"),
            format!(
                r#"
data_dir = "{}"

[dashboard]
bind_addr = "127.0.0.1:8787"
"#,
                data_dir.display()
            ),
        )
        .expect("write agent config");
        let today = epoch_secs_to_date(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        std::fs::write(data_dir.join(format!("telemetry-{today}.jsonl")), "\n")
            .expect("write empty telemetry");
    }

    fn runnable_cli(args: &[&str], data_dir: &std::path::Path) -> Cli {
        let mut cli = Cli::try_parse_from(args).expect("parse runnable cli");
        cli.sensor_config = data_dir.join("config.toml");
        cli.agent_config = data_dir.join("agent.toml");
        cli.data_dir = data_dir.to_path_buf();
        cli.dry_run = true;
        cli
    }

    // Anchor (Wave 7b, 2026-05-03): `known_module_id` must recognise
    // module IDs declared in the workspace `registry.toml`, regardless
    // of how the file is whitespace-formatted. The substring scan it
    // replaced was tied to a specific 10-space indent. See
    // RECURRING_BUGS.md: 'CLI: modules vs capabilities confusion'.
    #[test]
    fn known_module_id_recognises_registry_modules() {
        assert!(known_module_id("openclaw-protection"));
        assert!(known_module_id("claude-code-protection"));
        assert!(known_module_id("cloudflare-integration"));
        assert!(known_module_id("ssh-protection"));
        assert!(known_module_id("container-security"));
    }

    #[test]
    fn known_module_id_rejects_capabilities_and_typos() {
        // Real capabilities are NOT modules.
        assert!(!known_module_id("block-ip"));
        assert!(!known_module_id("shell-audit"));
        // Typos and partial matches must not pass.
        assert!(!known_module_id("openclaw"));
        assert!(!known_module_id("ssh-protect"));
        assert!(!known_module_id(""));
    }

    // Anchor (Wave 7b): when an operator types
    // `sudo innerwarden enable openclaw-protection` (a module),
    // the error MUST point them at `module install`. The original
    // bug left them grepping `innerwarden list` output that did
    // not contain the module at all.
    #[test]
    fn unknown_cap_error_suggests_module_install_for_modules() {
        let err = unknown_cap_error("openclaw-protection");
        let msg = format!("{err}");
        assert!(
            msg.contains("module install openclaw-protection"),
            "expected module-install hint, got: {msg}"
        );
    }

    #[test]
    fn unknown_cap_error_falls_back_for_typos() {
        let err = unknown_cap_error("definitely-not-a-thing");
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown capability"),
            "expected generic fallback for non-module typos, got: {msg}"
        );
        assert!(
            !msg.contains("module install"),
            "non-modules must not get the module-install hint, got: {msg}"
        );
    }

    // Wave 8e: clap exposes the new `--reason` flag on both
    // `allowlist add` and `trust add` (alias). Cover the parse path so
    // codecov sees the new struct fields and the dispatch arms in
    // main.rs's match. These are pure parse tests; the persistence
    // behaviour is covered by anchor tests in commands::response.
    #[test]
    fn cli_parses_allowlist_add_with_reason() {
        let cli = Cli::try_parse_from([
            "innerwarden",
            "allowlist",
            "add",
            "--ip",
            "147.154.0.0/16",
            "--reason",
            "Oracle Cloud London",
        ])
        .expect("parse cli");
        match cli.command {
            Some(Command::Allowlist {
                command: AllowlistCommand::Add { ip, user, reason },
            }) => {
                assert_eq!(ip.as_deref(), Some("147.154.0.0/16"));
                assert!(user.is_none());
                assert_eq!(reason.as_deref(), Some("Oracle Cloud London"));
            }
            _ => panic!("expected allowlist add command"),
        }
    }

    #[test]
    fn cli_parses_allowlist_add_without_reason_keeps_compat() {
        // Wave 8e: --reason is optional; existing scripts must keep
        // working without it. Reason parses as None.
        let cli = Cli::try_parse_from(["innerwarden", "allowlist", "add", "--ip", "10.0.0.1"])
            .expect("parse cli");
        match cli.command {
            Some(Command::Allowlist {
                command: AllowlistCommand::Add { reason, .. },
            }) => {
                assert!(reason.is_none(), "missing --reason must parse as None");
            }
            _ => panic!("expected allowlist add command"),
        }
    }

    #[test]
    fn cli_parses_trust_add_with_reason_alias() {
        // Wave 8e: `innerwarden trust add` is the visible alias of
        // `allowlist add`; same --reason support.
        let cli = Cli::try_parse_from([
            "innerwarden",
            "trust",
            "add",
            "--user",
            "deploy",
            "--reason",
            "CI/CD service account",
        ])
        .expect("parse cli");
        match cli.command {
            Some(Command::Trust {
                command: Some(TrustCommand::Add { ip, user, reason }),
            }) => {
                assert!(ip.is_none());
                assert_eq!(user.as_deref(), Some("deploy"));
                assert_eq!(reason.as_deref(), Some("CI/CD service account"));
            }
            _ => panic!("expected trust add command"),
        }
    }

    #[test]
    fn cli_global_flags_apply_across_grouped_commands() {
        let cli = Cli::try_parse_from([
            "innerwarden",
            "--data-dir",
            "/tmp/iw-data",
            "--dry-run",
            "get",
            "decisions",
            "--days",
            "5",
            "--action",
            "block_ip",
        ])
        .expect("parse cli");

        assert_eq!(cli.data_dir, PathBuf::from("/tmp/iw-data"));
        assert!(cli.dry_run);
        match cli.command {
            Some(Command::Get {
                command:
                    Some(GetCommand::Decisions {
                        days,
                        action: Some(action),
                    }),
            }) => {
                assert_eq!(days, 5);
                assert_eq!(action, "block_ip");
            }
            _ => panic!("expected get decisions command"),
        }
    }

    #[test]
    fn cli_parses_stream_defaults_and_overrides() {
        let default_cli = Cli::try_parse_from(["innerwarden", "stream"]).expect("parse cli");
        match default_cli.command {
            Some(Command::Stream { r#type, interval }) => {
                assert_eq!(r#type, "incidents");
                assert_eq!(interval, 2);
            }
            _ => panic!("expected stream command"),
        }

        let custom_cli = Cli::try_parse_from([
            "innerwarden",
            "stream",
            "--type",
            "events",
            "--interval",
            "9",
        ])
        .expect("parse cli");
        match custom_cli.command {
            Some(Command::Stream { r#type, interval }) => {
                assert_eq!(r#type, "events");
                assert_eq!(interval, 9);
            }
            _ => panic!("expected stream command"),
        }
    }

    #[test]
    fn cli_parses_action_block_and_requires_reason() {
        let cli = Cli::try_parse_from([
            "innerwarden",
            "action",
            "block",
            "203.0.113.10",
            "--reason",
            "operator investigation",
        ])
        .expect("parse cli");
        match cli.command {
            Some(Command::Action {
                command: Some(ActionCommand::Block { ip, reason }),
            }) => {
                assert_eq!(ip, "203.0.113.10");
                assert_eq!(reason, "operator investigation");
            }
            _ => panic!("expected action block command"),
        }

        let err = match Cli::try_parse_from(["innerwarden", "action", "block", "203.0.113.10"]) {
            Ok(_) => panic!("missing reason should fail"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn cli_parses_enable_with_force_flag() {
        let cli =
            Cli::try_parse_from(["innerwarden", "enable", "block-ip", "--force"]).expect("parse");
        match cli.command {
            Some(Command::Enable {
                capability, force, ..
            }) => {
                assert_eq!(capability, "block-ip");
                assert!(force, "--force must parse to true");
            }
            _ => panic!("expected enable command"),
        }
        // Default: force is false.
        let cli2 = Cli::try_parse_from(["innerwarden", "enable", "block-ip"]).expect("parse");
        match cli2.command {
            Some(Command::Enable { force, .. }) => assert!(!force),
            _ => panic!("expected enable command"),
        }
    }

    #[test]
    fn cli_parses_config_nested_commands() {
        let ai_cli = Cli::try_parse_from([
            "innerwarden",
            "config",
            "ai",
            "openrouter",
            "--model",
            "qwen/qwen3",
            "--base-url",
            "https://openrouter.ai/api",
        ])
        .expect("parse cli");
        match ai_cli.command {
            Some(Command::Config {
                command:
                    Some(ConfigAllCommand::Ai {
                        provider: Some(provider),
                        model: Some(model),
                        base_url: Some(base_url),
                        key: None,
                    }),
            }) => {
                assert_eq!(provider, "openrouter");
                assert_eq!(model, "qwen/qwen3");
                assert_eq!(base_url, "https://openrouter.ai/api");
            }
            _ => panic!("expected config ai command"),
        }

        let mesh_cli =
            Cli::try_parse_from(["innerwarden", "config", "mesh", "status"]).expect("parse cli");
        match mesh_cli.command {
            Some(Command::Config {
                command:
                    Some(ConfigAllCommand::Mesh {
                        command: MeshCommand::Status,
                    }),
            }) => {}
            _ => panic!("expected config mesh status command"),
        }
    }

    #[test]
    fn cli_parses_representative_commands_across_every_surface() {
        let cases = vec![
            vec!["innerwarden", "get", "status", "root", "--days", "7"],
            vec![
                "innerwarden",
                "get",
                "responses",
                "--history",
                "--ip",
                "1.2.3.4",
            ],
            vec!["innerwarden", "get", "metrics"],
            vec!["innerwarden", "get", "sensors"],
            vec!["innerwarden", "get", "posture"],
            vec!["innerwarden", "system", "doctor"],
            vec!["innerwarden", "system", "test", "--wait", "3"],
            vec!["innerwarden", "system", "harden", "--verbose"],
            vec!["innerwarden", "system", "tune", "--days", "14", "--yes"],
            vec!["innerwarden", "system", "calibrate"],
            vec![
                "innerwarden",
                "system",
                "scan",
                "--modules-dir",
                "/tmp/modules",
            ],
            vec![
                "innerwarden",
                "system",
                "watchdog",
                "--threshold",
                "600",
                "--status",
            ],
            vec![
                "innerwarden",
                "system",
                "export",
                "events",
                "--format",
                "csv",
            ],
            vec![
                "innerwarden",
                "system",
                "backup",
                "--output",
                "/tmp/iw.tar.gz",
            ],
            vec![
                "innerwarden",
                "system",
                "gdpr",
                "export",
                "--entity",
                "root",
            ],
            vec![
                "innerwarden",
                "system",
                "navigator",
                "--output",
                "/tmp/nav.json",
            ],
            vec!["innerwarden", "system", "smm", "--json", "--baseline"],
            vec!["innerwarden", "system", "hypervisor", "--json"],
            vec!["innerwarden", "system", "circuit-status", "--json"],
            vec!["innerwarden", "system", "circuit-reset", "--json"],
            vec!["innerwarden", "system", "reconcile-blocks", "--apply"],
            vec![
                "innerwarden",
                "system",
                "chain-break",
                "register",
                "--start",
                "10",
                "--end",
                "20",
                "--operator",
                "ops",
                "--reason",
                "manual repair",
            ],
            vec!["innerwarden", "system", "chain-break", "list", "--json"],
            vec![
                "innerwarden",
                "module",
                "validate",
                "/tmp/module",
                "--strict",
            ],
            vec!["innerwarden", "module", "enable", "/tmp/module", "--yes"],
            vec!["innerwarden", "module", "disable", "/tmp/module", "--yes"],
            vec![
                "innerwarden",
                "module",
                "list",
                "--modules-dir",
                "/tmp/modules",
            ],
            vec!["innerwarden", "module", "status", "ssh-protection"],
            vec!["innerwarden", "module", "search", "ssh"],
            vec![
                "innerwarden",
                "module",
                "install",
                "ssh-protection",
                "--enable",
                "--yes",
            ],
            vec![
                "innerwarden",
                "module",
                "uninstall",
                "ssh-protection",
                "--yes",
            ],
            vec!["innerwarden", "module", "publish", "/tmp/module"],
            vec!["innerwarden", "module", "update-all", "--check"],
            vec!["innerwarden", "agent", "add", "openclaw"],
            vec!["innerwarden", "agent", "scan"],
            vec!["innerwarden", "agent", "status"],
            vec![
                "innerwarden",
                "agent",
                "connect",
                "1234",
                "--name",
                "codex",
                "--label",
                "dev",
            ],
            vec!["innerwarden", "agent", "disconnect", "ag-0001"],
            vec!["innerwarden", "agent", "list"],
            vec!["innerwarden", "daily", "status"],
            vec!["innerwarden", "daily", "threats", "--days", "2", "--live"],
            vec!["innerwarden", "daily", "actions", "--days", "3"],
            vec!["innerwarden", "daily", "report", "--date", "yesterday"],
            vec!["innerwarden", "daily", "doctor"],
            vec!["innerwarden", "daily", "test", "--wait", "5"],
            vec!["innerwarden", "daily", "agent", "connect", "1234"],
            vec![
                "innerwarden",
                "notify",
                "telegram",
                "--token",
                "t",
                "--chat-id",
                "c",
            ],
            vec![
                "innerwarden",
                "notify",
                "slack",
                "--webhook-url",
                "https://hooks.example.invalid",
                "--min-severity",
                "medium",
            ],
            vec![
                "innerwarden",
                "notify",
                "webhook",
                "--url",
                "https://example.invalid/hook",
            ],
            vec!["innerwarden", "notify", "dashboard", "--user", "ops"],
            vec!["innerwarden", "notify", "test", "--channel", "telegram"],
            vec![
                "innerwarden",
                "notify",
                "web-push",
                "--subject",
                "mailto:ops@example.com",
            ],
            vec!["innerwarden", "notify", "digest", "9"],
            vec!["innerwarden", "notify", "budget", "5"],
            vec![
                "innerwarden",
                "config",
                "responder",
                "--enable",
                "--dry-run",
                "false",
            ],
            vec!["innerwarden", "config", "sensitivity", "quiet"],
            vec!["innerwarden", "config", "2fa"],
            vec![
                "innerwarden",
                "config",
                "test-alert",
                "--channel",
                "webhook",
            ],
            vec!["innerwarden", "config", "geoip"],
            vec!["innerwarden", "config", "abuseipdb", "--api-key", "abc"],
            vec![
                "innerwarden",
                "config",
                "cloudflare",
                "--zone-id",
                "z",
                "--api-token",
                "t",
            ],
            vec!["innerwarden", "config", "watchdog", "--interval", "5"],
            vec![
                "innerwarden",
                "config",
                "mesh",
                "add-peer",
                "https://peer",
                "--label",
                "prod",
            ],
            vec!["innerwarden", "integrate", "geoip"],
            vec![
                "innerwarden",
                "integrate",
                "abuseipdb",
                "--auto-block-threshold",
                "90",
            ],
            vec!["innerwarden", "integrate", "cloudflare", "--zone-id", "z"],
            vec!["innerwarden", "integrate", "watchdog", "--interval", "15"],
            vec!["innerwarden", "mesh", "enable"],
            vec!["innerwarden", "mesh", "disable"],
            vec!["innerwarden", "mesh", "status"],
            vec!["innerwarden", "rule", "list", "--type", "sigma"],
            vec!["innerwarden", "rule", "disable", "CL-024"],
            vec!["innerwarden", "rule", "enable", "CL-024"],
            vec![
                "innerwarden",
                "rule",
                "migrate-allowlist",
                "--output",
                "/tmp/rules.yml",
            ],
            vec!["innerwarden", "completions", "zsh"],
            vec![
                "innerwarden",
                "replay",
                "--fixture",
                "/tmp/fixtures",
                "--expected",
                "/tmp/expected.json",
            ],
            vec!["innerwarden", "upgrade", "--check", "--notify"],
            vec!["innerwarden", "enable", "shell-audit", "--yes"],
            vec!["innerwarden", "disable", "shell-audit", "--yes"],
            vec!["innerwarden", "list"],
            vec!["innerwarden", "status", "root", "--days", "3"],
            vec!["innerwarden", "scan", "--modules-dir", "/tmp/modules"],
            vec!["innerwarden", "welcome"],
            vec!["innerwarden", "navigator", "--output", "/tmp/nav.json"],
            vec!["innerwarden", "report", "--date", "today"],
            vec!["innerwarden", "watchdog", "--threshold", "300", "--notify"],
            vec!["innerwarden", "sensor-status"],
            vec!["innerwarden", "export", "incidents", "--format", "json"],
            vec!["innerwarden", "tail", "--type", "events", "--interval", "1"],
            vec!["innerwarden", "incidents", "--severity", "medium"],
            vec![
                "innerwarden",
                "block",
                "203.0.113.10",
                "--reason",
                "coverage",
            ],
            vec![
                "innerwarden",
                "unblock",
                "203.0.113.10",
                "--reason",
                "coverage",
            ],
            vec!["innerwarden", "entity", "root", "--days", "5"],
            vec!["innerwarden", "test", "--wait", "1"],
            vec!["innerwarden", "backup", "--output", "/tmp/backup.tar.gz"],
            vec!["innerwarden", "metrics"],
            vec!["innerwarden", "gdpr", "erase", "--entity", "root", "--yes"],
            vec!["innerwarden", "suppress", "add", "firmware:trust_degraded"],
        ];

        for args in cases {
            Cli::try_parse_from(&args)
                .unwrap_or_else(|err| panic!("expected CLI parse to succeed for {args:?}: {err}"));
        }
    }

    #[test]
    fn run_cli_dispatches_safe_readonly_and_dry_run_commands() {
        let cases = vec![
            vec!["innerwarden"],
            vec!["innerwarden", "get"],
            vec!["innerwarden", "get", "decisions"],
            vec!["innerwarden", "get", "incidents"],
            vec!["innerwarden", "get", "report"],
            vec!["innerwarden", "get", "metrics"],
            vec!["innerwarden", "get", "sensors"],
            vec!["innerwarden", "get", "posture"],
            vec!["innerwarden", "action"],
            vec![
                "innerwarden",
                "action",
                "block",
                "203.0.113.10",
                "--reason",
                "coverage",
            ],
            vec![
                "innerwarden",
                "action",
                "unblock",
                "203.0.113.10",
                "--reason",
                "coverage",
            ],
            vec!["innerwarden", "trust"],
            vec!["innerwarden", "trust", "list"],
            vec!["innerwarden", "trust", "suppressions"],
            vec!["innerwarden", "system"],
            vec!["innerwarden", "system", "watchdog", "--status"],
            vec!["innerwarden", "system", "export", "incidents"],
            vec![
                "innerwarden",
                "system",
                "gdpr",
                "export",
                "--entity",
                "root",
            ],
            vec!["innerwarden", "system", "navigator"],
            vec!["innerwarden", "system", "circuit-status", "--json"],
            vec!["innerwarden", "system", "circuit-reset", "--json"],
            vec![
                "innerwarden",
                "system",
                "chain-break",
                "register",
                "--start",
                "1",
                "--end",
                "2",
                "--operator",
                "coverage",
                "--reason",
                "dispatch smoke",
            ],
            vec!["innerwarden", "system", "chain-break", "list", "--json"],
            vec!["innerwarden", "rule", "list"],
            vec!["innerwarden", "agent", "list"],
            vec!["innerwarden", "daily", "actions"],
            vec!["innerwarden", "daily", "report"],
            vec!["innerwarden", "status", "root"],
            vec!["innerwarden", "decisions"],
            vec!["innerwarden", "entity", "root"],
            vec!["innerwarden", "allowlist", "list"],
            vec!["innerwarden", "suppress", "list"],
            vec!["innerwarden", "metrics"],
            vec!["innerwarden", "gdpr", "export", "--entity", "root"],
        ];

        for args in cases {
            let tmp = TempDir::new().expect("tempdir");
            write_minimal_cli_configs(tmp.path());
            let cli = runnable_cli(&args, tmp.path());
            run_cli(cli)
                .unwrap_or_else(|err| panic!("expected run_cli to succeed for {args:?}: {err:#}"));
        }
    }

    #[test]
    fn cli_parses_setup_mode_and_rejects_unknown_mode() {
        let cli =
            Cli::try_parse_from(["innerwarden", "setup", "--mode", "advanced"]).expect("parse cli");
        match cli.command {
            Some(Command::Setup { mode }) => assert_eq!(mode, "advanced"),
            _ => panic!("expected setup command"),
        }

        let err = match Cli::try_parse_from(["innerwarden", "setup", "--mode", "expert"]) {
            Ok(_) => panic!("invalid setup mode should fail"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn cli_parses_install_warden_defaults() {
        let cli = Cli::try_parse_from(["innerwarden", "install-warden"]).expect("parse cli");
        match cli.command {
            Some(Command::InstallClassifier {
                model,
                url,
                sha256,
                yes,
                configure,
            }) => {
                assert_eq!(model, "minilm-l6");
                assert!(url.is_none());
                assert!(sha256.is_none());
                assert!(!yes);
                assert!(!configure, "--configure defaults off");
            }
            _ => panic!("expected install-warden command"),
        }
    }

    // 2026-05-03 anchor: `install-classifier` must still work as a
    // visible alias so existing operator automation (cron, ansible,
    // shell history) is not broken by the rename.
    #[test]
    fn cli_accepts_legacy_install_classifier_alias() {
        let cli = Cli::try_parse_from(["innerwarden", "install-classifier"]).expect("parse cli");
        match cli.command {
            Some(Command::InstallClassifier { model, .. }) => {
                assert_eq!(model, "minilm-l6");
            }
            _ => panic!("expected install-classifier alias to dispatch to install-warden"),
        }
    }

    #[test]
    fn cli_parses_install_warden_overrides() {
        let cli = Cli::try_parse_from([
            "innerwarden",
            "install-warden",
            "--model",
            "roberta-v1",
            "--url",
            "https://example.invalid/roberta.tar.gz",
            "--sha256",
            "abc123",
            "--yes",
        ])
        .expect("parse cli");
        match cli.command {
            Some(Command::InstallClassifier {
                model,
                url,
                sha256,
                yes,
                configure,
            }) => {
                assert!(!configure);
                assert_eq!(model, "roberta-v1");
                assert_eq!(
                    url.as_deref(),
                    Some("https://example.invalid/roberta.tar.gz")
                );
                assert_eq!(sha256.as_deref(), Some("abc123"));
                assert!(yes);
            }
            _ => panic!("expected install-warden command"),
        }
    }

    #[test]
    fn dispatch_install_classifier_routes_to_ai_command() {
        let tmp = TempDir::new().expect("tempdir");
        let mut cli = make_cli(tmp.path());
        cli.dry_run = true;

        let ok = dispatch_install_classifier(
            &cli,
            "minilm-l6",
            Some("https://example.invalid/minilm.tar.gz"),
            Some("deadbeef"),
            true,
            false,
        );
        assert!(ok.is_ok(), "dry-run dispatch should succeed: {ok:#?}");

        let err =
            dispatch_install_classifier(&cli, "unknown-model", None, Some("deadbeef"), true, false)
                .expect_err("unknown model should fail");
        assert!(err.to_string().contains("unknown classifier variant"));
    }

    #[test]
    fn parse_selection_indices_all_and_csv() {
        assert_eq!(
            crate::commands::agent::parse_selection_indices("all", 3),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            crate::commands::agent::parse_selection_indices("1,3,3,2", 3),
            Some(vec![1, 3, 2])
        );
    }

    #[test]
    fn parse_selection_indices_rejects_invalid_values() {
        assert_eq!(crate::commands::agent::parse_selection_indices("", 3), None);
        assert_eq!(
            crate::commands::agent::parse_selection_indices("0", 3),
            None
        );
        assert_eq!(
            crate::commands::agent::parse_selection_indices("4", 3),
            None
        );
        assert_eq!(
            crate::commands::agent::parse_selection_indices("x", 3),
            None
        );
    }

    #[test]
    fn ai_provider_defaults_cover_known_and_custom_providers() {
        let (model, key_var, base_url) = ai_provider_defaults("openrouter");
        assert_eq!(model, "meta-llama/llama-3.3-70b-instruct");
        assert_eq!(key_var.as_deref(), Some("OPENROUTER_API_KEY"));
        assert_eq!(base_url.as_deref(), Some("https://openrouter.ai/api"));

        let (_model, key_var, base_url) = ai_provider_defaults("acme");
        assert_eq!(key_var.as_deref(), Some("ACME_API_KEY"));
        assert!(base_url.is_none());
    }

    #[test]
    fn count_failed_setup_checks_only_counts_critical_failures() {
        let checks = vec![
            SetupCheck {
                label: "AI".to_string(),
                detail: "not configured".to_string(),
                ok: false,
                critical: true,
            },
            SetupCheck {
                label: "Dashboard".to_string(),
                detail: "not reachable".to_string(),
                ok: false,
                critical: false,
            },
            SetupCheck {
                label: "Protection".to_string(),
                detail: "watch only".to_string(),
                ok: true,
                critical: true,
            },
        ];

        assert_eq!(count_failed_setup_checks(&checks), 1);
    }

    #[test]
    fn setup_verdict_reports_ready_and_gaps() {
        assert_eq!(setup_verdict(0), "READY");
        assert_eq!(setup_verdict(1), "READY_WITH_GAPS");
        assert_eq!(setup_verdict(3), "READY_WITH_GAPS");
    }

    #[test]
    fn setup_remediation_command_restarts_agent_for_single_service_gap() {
        let checks = vec![SetupCheck {
            label: "Agent service".to_string(),
            detail: "not running".to_string(),
            ok: false,
            critical: true,
        }];

        assert_eq!(
            setup_remediation_command(&checks, false).as_deref(),
            Some("sudo systemctl restart innerwarden-agent")
        );
        assert_eq!(
            setup_remediation_command(&checks, true).as_deref(),
            Some("sudo launchctl kickstart -k system/com.innerwarden.agent")
        );
    }

    #[test]
    fn setup_remediation_command_falls_back_to_advanced_setup() {
        let checks = vec![
            SetupCheck {
                label: "AI".to_string(),
                detail: "not configured".to_string(),
                ok: false,
                critical: true,
            },
            SetupCheck {
                label: "Alerts".to_string(),
                detail: "not ready".to_string(),
                ok: false,
                critical: true,
            },
        ];

        assert_eq!(
            setup_remediation_command(&checks, false).as_deref(),
            Some("innerwarden setup --mode advanced")
        );
    }

    #[test]
    fn decisions_empty_data_dir() {
        let dir = TempDir::new().unwrap();
        let cli = make_cli(dir.path());
        // Should return Ok even with no JSONL files present
        let result = crate::commands::history::cmd_decisions(&cli, 1, None, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn decisions_reads_jsonl() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("decisions-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"action\":\"block_ip\",\"target_ip\":\"1.2.3.4\",\"confidence\":0.95,\"dry_run\":false,\"ai_provider\":\"openai\"}\n",
        ).unwrap();
        let cli = make_cli(dir.path());
        let result = crate::commands::history::cmd_decisions(&cli, 1, None, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn decisions_action_filter() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("decisions-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"action\":\"ignore\",\"target_ip\":\"1.2.3.4\",\"confidence\":0.3,\"dry_run\":false,\"ai_provider\":\"openai\"}\n",
        ).unwrap();
        let cli = make_cli(dir.path());
        // Filter for block_ip - should return Ok (0 matching)
        let result = crate::commands::history::cmd_decisions(&cli, 1, Some("block_ip"), dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn entity_no_data() {
        let dir = TempDir::new().unwrap();
        let cli = make_cli(dir.path());
        let result = crate::commands::history::cmd_entity(&cli, "1.2.3.4", 3, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn entity_finds_ip_in_incident() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("incidents-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"title\":\"SSH Brute Force\",\"severity\":\"High\",\"summary\":\"8 failures\",\"entities\":[{\"type\":\"Ip\",\"value\":\"5.6.7.8\"}]}\n",
        ).unwrap();
        let cli = make_cli(dir.path());
        let result = crate::commands::history::cmd_entity(&cli, "5.6.7.8", 1, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn entity_finds_user_in_decision() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("decisions-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"action\":\"suspend_user_sudo\",\"target_user\":\"alice\",\"confidence\":0.9,\"dry_run\":true,\"ai_provider\":\"openai\"}\n",
        ).unwrap();
        let cli = make_cli(dir.path());
        let result = crate::commands::history::cmd_entity(&cli, "alice", 1, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn watchdog_status_no_data() {
        let dir = TempDir::new().unwrap();
        let cli = make_cli(dir.path());
        // Should return Ok even with no telemetry files
        let result = crate::commands::watchdog::cmd_watchdog_status(&cli, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn tune_no_data() {
        let dir = TempDir::new().unwrap();
        let cli = make_cli(dir.path());
        // No JSONL files - should return Ok with a "no data" message
        let result = crate::commands::ops::cmd_tune(&cli, 7, true, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn tune_no_suggestions_when_calibrated() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        // Write a modest event count that matches default thresholds - no suggestion expected
        let events_path = dir.path().join(format!("events-{today}.jsonl"));
        let mut content = String::new();
        for _ in 0..5 {
            content.push_str("{\"ts\":\"2026-03-16T10:00:00Z\",\"kind\":\"ssh.login_failed\",\"severity\":\"Low\",\"summary\":\"failed\",\"source\":\"auth_log\",\"host\":\"h\",\"entities\":[],\"tags\":[]}\n");
        }
        std::fs::write(&events_path, &content).unwrap();
        let cli = make_cli(dir.path());
        let result = crate::commands::ops::cmd_tune(&cli, 1, true, dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn completions_invalid_shell_errors() {
        let result = crate::commands::ops::cmd_completions("powershell");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported shell"));
    }

    #[test]
    fn completions_bash_succeeds() {
        // Just verify it doesn't panic/error - output goes to stdout
        let result = crate::commands::ops::cmd_completions("bash");
        assert!(result.is_ok());
    }

    // -- GDPR tests --

    #[test]
    fn matches_entity_finds_ip_in_entities_array() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","entities":[{"type":"Ip","value":"1.2.3.4"}]}"#;
        assert!(crate::commands::history::matches_entity(line, "1.2.3.4"));
        assert!(!crate::commands::history::matches_entity(line, "5.6.7.8"));
    }

    #[test]
    fn matches_entity_finds_target_ip() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","action":"block_ip","target_ip":"1.2.3.4"}"#;
        assert!(crate::commands::history::matches_entity(line, "1.2.3.4"));
    }

    #[test]
    fn matches_entity_finds_target_user() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","action":"suspend","target_user":"alice"}"#;
        assert!(crate::commands::history::matches_entity(line, "alice"));
        assert!(!crate::commands::history::matches_entity(line, "bob"));
    }

    #[test]
    fn matches_entity_finds_operator() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","operator":"admin","action":"enable"}"#;
        assert!(crate::commands::history::matches_entity(line, "admin"));
    }

    #[test]
    fn matches_entity_finds_target() {
        let line = r#"{"ts":"2026-03-16T10:00:00Z","target":"1.2.3.4","action":"gdpr_erase"}"#;
        assert!(crate::commands::history::matches_entity(line, "1.2.3.4"));
    }

    #[test]
    fn matches_entity_no_match_on_invalid_json() {
        assert!(!crate::commands::history::matches_entity(
            "not json", "anything"
        ));
    }

    #[test]
    fn gdpr_export_empty_dir() {
        let dir = TempDir::new().unwrap();
        let result = crate::commands::history::cmd_gdpr_export(dir.path(), "1.2.3.4", None);
        assert!(result.is_ok());
    }

    #[test]
    fn gdpr_export_finds_matching_records() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("incidents-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"title\":\"Brute Force\",\"entities\":[{\"type\":\"Ip\",\"value\":\"9.8.7.6\"}]}\n\
             {\"ts\":\"2026-03-16T11:00:00Z\",\"title\":\"Port Scan\",\"entities\":[{\"type\":\"Ip\",\"value\":\"5.5.5.5\"}]}\n",
        ).unwrap();

        let out_path = dir.path().join("export.jsonl");
        let result =
            crate::commands::history::cmd_gdpr_export(dir.path(), "9.8.7.6", Some(&out_path));
        assert!(result.is_ok());

        let exported = std::fs::read_to_string(&out_path).unwrap();
        assert!(exported.contains("9.8.7.6"));
        assert!(!exported.contains("5.5.5.5"));
        assert_eq!(exported.lines().count(), 1);
    }

    #[test]
    fn gdpr_erase_no_matching_records() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("events-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"entities\":[{\"type\":\"Ip\",\"value\":\"5.5.5.5\"}]}\n",
        ).unwrap();
        let result = crate::commands::history::cmd_gdpr_erase(dir.path(), "9.9.9.9", true);
        assert!(result.is_ok());

        // File should be unchanged
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("5.5.5.5"));
    }

    #[test]
    fn gdpr_erase_removes_matching_records() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("events-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"entities\":[{\"type\":\"Ip\",\"value\":\"1.2.3.4\"}]}\n\
             {\"ts\":\"2026-03-16T11:00:00Z\",\"entities\":[{\"type\":\"Ip\",\"value\":\"5.5.5.5\"}]}\n",
        ).unwrap();

        let result = crate::commands::history::cmd_gdpr_erase(dir.path(), "1.2.3.4", true);
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("1.2.3.4"));
        assert!(content.contains("5.5.5.5"));
        assert_eq!(content.lines().count(), 1);
    }

    #[test]
    fn gdpr_erase_recomputes_hash_chain_for_decisions() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("decisions-{today}.jsonl"));
        std::fs::write(
            &path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"action\":\"block_ip\",\"target_ip\":\"1.2.3.4\",\"prev_hash\":null}\n\
             {\"ts\":\"2026-03-16T11:00:00Z\",\"action\":\"block_ip\",\"target_ip\":\"5.5.5.5\",\"prev_hash\":\"abc123\"}\n\
             {\"ts\":\"2026-03-16T12:00:00Z\",\"action\":\"block_ip\",\"target_ip\":\"6.6.6.6\",\"prev_hash\":\"def456\"}\n",
        ).unwrap();

        let result = crate::commands::history::cmd_gdpr_erase(dir.path(), "1.2.3.4", true);
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("1.2.3.4"));
        // Remaining lines should have recomputed prev_hash - first line should have null
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert!(first.get("prev_hash").unwrap().is_null());
        // Second line should have a proper SHA-256 hash (64 hex chars)
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        let hash = second.get("prev_hash").unwrap().as_str().unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn gdpr_erase_creates_audit_entry() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let events_path = dir.path().join(format!("events-{today}.jsonl"));
        std::fs::write(
            &events_path,
            "{\"ts\":\"2026-03-16T10:00:00Z\",\"entities\":[{\"type\":\"Ip\",\"value\":\"1.2.3.4\"}]}\n",
        ).unwrap();

        let result = crate::commands::history::cmd_gdpr_erase(dir.path(), "1.2.3.4", true);
        assert!(result.is_ok());

        // An admin-actions file should now exist with a gdpr_erase entry
        let audit_path = dir.path().join(format!("admin-actions-{today}.jsonl"));
        assert!(audit_path.exists());
        let audit_content = std::fs::read_to_string(&audit_path).unwrap();
        assert!(audit_content.contains("gdpr_erase"));
        assert!(audit_content.contains("1.2.3.4"));
    }
}
