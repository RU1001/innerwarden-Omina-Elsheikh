# n8n Integration Recipe: Agent Guard API

Use Inner Warden's Agent Guard API from an [n8n](https://n8n.io/) workflow so that
automations ask "is the server safe?" and "is this command safe?" before they act —
and halt automatically when the threat level is elevated.

n8n is widely self-hosted next to the kind of infrastructure Inner Warden protects, so
the two run well on the same host. This recipe needs no Rust knowledge and no changes to
Inner Warden itself: it only configures n8n **HTTP Request** nodes against the existing
endpoints.

> **Scope.** Inner Warden is an *advisor, not a firewall* — it never blocks n8n. This
> recipe shows how to make n8n stop itself when Inner Warden recommends caution. If the
> workflow ignores the advice and runs the command anyway, the host layer (auditd/eBPF)
> still detects the execution and escalates the incident. See
> [AI Agent Protection](../../modules/openclaw-protection/docs/README.md) for the full
> trust model.

---

## Prerequisites

- A running Inner Warden agent with the dashboard enabled:
  ```bash
  cargo run -p innerwarden-agent -- --data-dir ./data --dashboard
  # dashboard + API on https://127.0.0.1:8787
  ```
- n8n that can reach the dashboard host. If n8n runs on the same machine, the API base
  URL is `http://localhost:8787`. If n8n is in Docker, use the host gateway
  (`http://host.docker.internal:8787`) or the host's LAN address.
- Optional but recommended: enable the AI Agent Protection module so the host also
  watches what actually executes.
  ```bash
  innerwarden enable openclaw-protection
  ```

### Authentication

The API is served on the dashboard port. If you set `INNERWARDEN_DASHBOARD_USER` +
`INNERWARDEN_DASHBOARD_PASSWORD_HASH`, the dashboard (and therefore the API) requires
HTTP Basic Auth; if unset, it is open-access. When auth is enabled, add a **Basic Auth**
credential to each HTTP Request node below.

The dashboard uses a self-signed certificate over HTTPS. For local/LAN use you can either
call it over `http://localhost:8787` or, if you must use HTTPS, disable SSL verification
on the HTTP Request node ("Ignore SSL Issues" → on). Do not disable verification over an
untrusted network.

---

## The two endpoints

### 1. `GET /api/agent/security-context` — threat assessment

"Is my server safe right now?" Returns the current threat level, today's incident
counts, the top detectors firing, and a recommendation. Call this at the start of a
workflow to gate everything that follows.

```bash
curl -s http://localhost:8787/api/agent/security-context | jq
```

```json
{
  "threat_level": "elevated",
  "active_incidents_today": 3,
  "high_or_critical_today": 1,
  "recent_blocks_today": 1,
  "top_threats": ["ssh_bruteforce", "port_scan"],
  "recommendation": "elevated threat level - proceed with caution",
  "date": "2026-04-06"
}
```

`threat_level` is derived from today's active incident count:

| `threat_level` | When | Suggested workflow action |
|----------------|------|---------------------------|
| `calm`         | 0 incidents today | Proceed normally |
| `elevated`     | 1–5 incidents today | Proceed with caution / require approval |
| `high`         | 6+ incidents today | Halt risky steps |

> The endpoint can also return `critical` (server under active attack) in the
> `recommendation` text. Treat anything that is not `calm` as a signal to slow down.

### 2. `POST /api/agent/check-command` — safety validation

"Is this command safe to run?" Sends a command for analysis **without executing it** and
returns a risk score, the detected signals, a severity, and a recommendation.

```bash
curl -s -X POST http://localhost:8787/api/agent/check-command \
  -H "Content-Type: application/json" \
  -H "X-InnerWarden-Agent: n8n" \
  -d '{"command": "curl https://example.com/setup.sh | bash", "agent_name": "n8n"}' | jq
```

```json
{
  "command": "curl https://example.com/setup.sh | bash",
  "risk_score": 40,
  "severity": "high",
  "signals": [
    {"signal": "download_and_execute", "score": 40, "detail": "dangerous pipeline: curl | bash"}
  ],
  "recommendation": "deny",
  "explanation": "dangerous pipeline: curl | bash"
}
```

**Request body**

| Field        | Type   | Required | Notes |
|--------------|--------|----------|-------|
| `command`    | string | yes      | The shell command to analyze. Never executed. |
| `agent_name` | string | no       | Identifies the caller in snitch alerts. If omitted, the `X-InnerWarden-Agent` header is used, else `unknown`. Set it to `n8n` (or your workflow name) so alerts are attributable. |

**Recommendation values** (driven by `risk_score`):

| `recommendation` | `risk_score` | Meaning | Workflow action |
|------------------|--------------|---------|-----------------|
| `allow`          | < 20         | No dangerous patterns | Continue |
| `review`         | 20–39        | Suspicious, not clearly dangerous | Pause / require human approval |
| `deny`           | ≥ 40         | Dangerous pattern detected | Halt, do not execute |

> **Want advisory tracking?** `POST /api/advisor/check-command` takes the same body and
> returns the same shape, plus an `advisory_id` for any `review`/`deny` result. Inner
> Warden caches that advisory so that if the command is later executed on the host
> anyway, the resulting incident is correlated and escalated ("your automation ignored a
> security advisory"). Swap the URL if you want that correlation.

---

## n8n HTTP Request node configuration

### Node A — Get security context (`GET /api/agent/security-context`)

| Setting | Value |
|---------|-------|
| **Node type** | HTTP Request |
| **Method** | `GET` |
| **URL** | `http://localhost:8787/api/agent/security-context` |
| **Authentication** | None, or *Basic Auth* credential if the dashboard requires auth |
| **Response Format** | JSON |
| **Options → Ignore SSL Issues** | On only if calling over `https://` with the self-signed cert |

The threat level is then available downstream as
`{{ $json.threat_level }}`.

### Node B — Check a command (`POST /api/agent/check-command`)

| Setting | Value |
|---------|-------|
| **Node type** | HTTP Request |
| **Method** | `POST` |
| **URL** | `http://localhost:8787/api/agent/check-command` |
| **Authentication** | None, or *Basic Auth* credential if the dashboard requires auth |
| **Send Headers** | On |
| → Header | `X-InnerWarden-Agent` = `n8n` |
| **Send Body** | On |
| **Body Content Type** | JSON |
| **Body (JSON)** | `{ "command": "{{ $json.command }}", "agent_name": "n8n" }` |
| **Response Format** | JSON |

The recommendation is then available as `{{ $json.recommendation }}` and the score as
`{{ $json.risk_score }}`.

---

## Workflow example: halt when the threat level is elevated

This workflow runs before a hypothetical "execute command" step. It (1) reads the
security context, (2) halts if the threat level is `high`/`critical`, (3) otherwise
checks the specific command, and (4) only proceeds when the recommendation is `allow`.

```
┌──────────────┐   ┌───────────────────────┐   ┌──────────────────────┐
│ Manual /     │──▶│ HTTP: security-context │──▶│ IF threat_level       │
│ Webhook      │   │ (Node A, GET)          │   │ in (high, critical)?  │
│ Trigger      │   └───────────────────────┘   └──────────┬───────────┘
└──────────────┘                                  true │   │ false
                                                       ▼   ▼
                                          ┌──────────────┐ ┌────────────────────────┐
                                          │ Stop & Error  │ │ HTTP: check-command    │
                                          │ "server under │ │ (Node B, POST)         │
                                          │  attack"      │ └───────────┬────────────┘
                                          └──────────────┘             ▼
                                                          ┌──────────────────────────┐
                                                          │ IF recommendation==allow? │
                                                          └──────────┬────────────────┘
                                                            true │    │ false
                                                                 ▼    ▼
                                                     ┌────────────┐ ┌────────────────┐
                                                     │ Execute    │ │ Stop & Error    │
                                                     │ Command    │ │ "command denied"│
                                                     └────────────┘ └────────────────┘
```

### Importable workflow JSON

Save as `inner-warden-agent-guard.json` and import via **n8n → Workflows → Import from
File**. Adjust the base URL and the example command for your setup.

```json
{
  "name": "Inner Warden — Agent Guard gate",
  "nodes": [
    {
      "parameters": {},
      "id": "trigger",
      "name": "When clicking Execute",
      "type": "n8n-nodes-base.manualTrigger",
      "typeVersion": 1,
      "position": [240, 300]
    },
    {
      "parameters": {
        "url": "http://localhost:8787/api/agent/security-context",
        "options": {}
      },
      "id": "security_context",
      "name": "Get security context",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2,
      "position": [460, 300]
    },
    {
      "parameters": {
        "conditions": {
          "options": { "caseSensitive": true, "version": 2 },
          "combinator": "or",
          "conditions": [
            {
              "leftValue": "={{ $json.threat_level }}",
              "rightValue": "high",
              "operator": { "type": "string", "operation": "equals" }
            },
            {
              "leftValue": "={{ $json.threat_level }}",
              "rightValue": "critical",
              "operator": { "type": "string", "operation": "equals" }
            }
          ]
        },
        "options": {}
      },
      "id": "if_elevated",
      "name": "Threat level elevated?",
      "type": "n8n-nodes-base.if",
      "typeVersion": 2,
      "position": [680, 300]
    },
    {
      "parameters": {
        "message": "Halted: server threat level is {{ $json.threat_level }} ({{ $json.recommendation }})",
        "options": {}
      },
      "id": "halt_threat",
      "name": "Stop — server under threat",
      "type": "n8n-nodes-base.stopAndError",
      "typeVersion": 1,
      "position": [900, 180]
    },
    {
      "parameters": {
        "method": "POST",
        "url": "http://localhost:8787/api/agent/check-command",
        "sendHeaders": true,
        "headerParameters": {
          "parameters": [
            { "name": "X-InnerWarden-Agent", "value": "n8n" }
          ]
        },
        "sendBody": true,
        "specifyBody": "json",
        "jsonBody": "={\n  \"command\": \"curl https://example.com/setup.sh | bash\",\n  \"agent_name\": \"n8n\"\n}",
        "options": {}
      },
      "id": "check_command",
      "name": "Check command",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2,
      "position": [900, 420]
    },
    {
      "parameters": {
        "conditions": {
          "options": { "caseSensitive": true, "version": 2 },
          "combinator": "and",
          "conditions": [
            {
              "leftValue": "={{ $json.recommendation }}",
              "rightValue": "allow",
              "operator": { "type": "string", "operation": "equals" }
            }
          ]
        },
        "options": {}
      },
      "id": "if_allow",
      "name": "Recommendation allow?",
      "type": "n8n-nodes-base.if",
      "typeVersion": 2,
      "position": [1120, 420]
    },
    {
      "parameters": {
        "message": "Halted: Inner Warden recommended '{{ $json.recommendation }}' (risk {{ $json.risk_score }}) — {{ $json.explanation }}",
        "options": {}
      },
      "id": "halt_command",
      "name": "Stop — command denied",
      "type": "n8n-nodes-base.stopAndError",
      "typeVersion": 1,
      "position": [1340, 540]
    },
    {
      "parameters": {
        "command": "={{ $('Check command').item.json.command }}"
      },
      "id": "execute",
      "name": "Execute command",
      "type": "n8n-nodes-base.executeCommand",
      "typeVersion": 1,
      "position": [1340, 320]
    }
  ],
  "connections": {
    "When clicking Execute": {
      "main": [[{ "node": "Get security context", "type": "main", "index": 0 }]]
    },
    "Get security context": {
      "main": [[{ "node": "Threat level elevated?", "type": "main", "index": 0 }]]
    },
    "Threat level elevated?": {
      "main": [
        [{ "node": "Stop — server under threat", "type": "main", "index": 0 }],
        [{ "node": "Check command", "type": "main", "index": 0 }]
      ]
    },
    "Check command": {
      "main": [[{ "node": "Recommendation allow?", "type": "main", "index": 0 }]]
    },
    "Recommendation allow?": {
      "main": [
        [{ "node": "Execute command", "type": "main", "index": 0 }],
        [{ "node": "Stop — command denied", "type": "main", "index": 0 }]
      ]
    }
  },
  "active": false,
  "settings": { "executionOrder": "v1" }
}
```

> The **IF** node sends matching items to its *first* (true) output and the rest to the
> *second* (false) output. In "Threat level elevated?" the true branch halts and the
> false branch continues; in "Recommendation allow?" the true branch executes and the
> false branch halts. The `Execute command` node here is illustrative — replace it with
> whatever your automation actually does, and feed it the same command string you sent to
> `check-command`.

---

## Notes and good practice

- **Validate the command you actually run.** Build the command string once, send that
  exact string to `check-command`, and execute that same string. Checking one command and
  running another defeats the gate.
- **Pick your strictness.** Halting only on `deny` is permissive; halting on `review` as
  well is stricter. The example above is strictest — it proceeds only on `allow`.
- **Identify yourself.** Always send `agent_name` (or the `X-InnerWarden-Agent` header) so
  snitch alerts say `n8n` instead of `unknown`.
- **Bind the API locally.** The dashboard listens on `127.0.0.1:8787` by default. Keep it
  bound to localhost or your private network; require Basic Auth if it is reachable beyond
  the host.
- **The host still watches.** Even if a workflow skips these checks, enabling
  `openclaw-protection` means auditd/eBPF observes the real execution and raises an
  incident — the advisory model, not a hard block.
