# InnerWarden × OWASP Agentic Top 10

How InnerWarden's AI-agent guardrail maps to the **OWASP Top 10 for Agentic
Applications (ASI01–ASI10, December 2025)**. Every row points at a real control
and the test that proves it fires. This table is *derived from the code that
runs*, not asserted in marketing copy. The mapping itself lives in
[`crates/agent-guard/src/asi.rs`](src/asi.rs); the
guard-layer controls are proven by
[`crates/agent-guard/tests/owasp_asi.rs`](tests/owasp_asi.rs).

> Reference: OWASP Top 10 for Agentic Applications: <https://genai.owasp.org>.

## The distinction

Most "agent safety" filters what the model *says*. InnerWarden governs what the
agent is allowed to *do*: every command an agent runs is screened by
`check-command` before it executes (the free/advisory layer), and the
enforcement-critical calls are refused **in the kernel** by the execution gate
(the paid Active Defence layer): a jailbroken agent cannot talk its way out of
a kernel `-EPERM`.

## Coverage matrix

| ASI | Threat | InnerWarden control | Layer | Status | Proof |
|---|---|---|---|---|---|
| **ASI01** | Agent Goal Hijack | Prompt-injection detection (24 patterns + ATR `prompt-injection`/`agent-manipulation` rules) on every command/arg/response; obfuscation flagged | Detect (free) | ✅ Covered | `owasp_asi::asi01…` |
| **ASI02** | Tool Misuse | `check-command` denies dangerous tool calls (ATR `tool-poisoning` + built-in signals: download-and-execute, tmp-exec, dangerous); kernel exec-gate enforces | Detect (free) + Enforce (paid) | ✅ Covered | `owasp_asi::asi02…` |
| **ASI03** | Delegated Trust | Customer/operator-facing + block actions require human approval (`skill_gate`, Telegram/Slack/dashboard); ATR `excessive-autonomy` | Detect + Approve (free) | ✅ Covered | `skill_gate` tests (agent) |
| **ASI04** | Data Exfiltration | ATR `context-exfiltration` + credential-file read detection (sensor eBPF) + secret/PII redaction transform | Detect (free) | ✅ Covered | `owasp_asi::asi04…` |
| **ASI05** | Privilege Escalation | `privesc` detector + **kernel execution gate** (untrusted-root-exec, setns-owner, spec 070), non-forgeable | Detect (free) + **Enforce (paid, kernel)** | ✅ Covered (deep) | `owasp_asi::asi05…` + sensor spec-070 tests |
| **ASI06** | Inter-Agent / Cross-Boundary | Per-tenant attribution read from the kernel cgroup (spec 084), unspoofable; paid per-pod containment | Detect (free) + Enforce (paid) | ✅ Covered | spec-084 tenant tests (sensor) |
| **ASI07** | Memory Leakage | Secret/PII redaction transform scrubs the primary leakage vector (tokens, keys, `password=`, SSN, card) before untrusted content enters the agent's context | Detect (free) | ⚠️ Covered (primary vector) | `owasp_asi::asi07…` |
| **ASI08** | Operator Control | Watchdog ("cachorro louco") + exec-gate `disarm` kill-switch + security-tooling-tamper detection | Detect + Kill (free/paid) | ✅ Covered | watchdog/supervisor tests |
| **ASI09** | Cost / Quota Abuse | Per-session circuit breaker: identical-tool-call loop guard in the MCP proxy + a cost ceiling at the model-billing boundary | Detect + Halt (free) | ✅ Covered | `owasp_asi::asi09…` |
| **ASI10** | Rogue Agents | `check-command` deny + **kernel execution gate** blocks unauthorized exec (reverse shells, miners, destruction) + fleet rogue-agent signal | Detect (free) + **Enforce (paid, kernel)** | ✅ Covered (deep) | `owasp_asi::asi10…` |

## Honest scope notes

- **ASI07 (Memory Leakage)** is marked *primary vector*: the redaction transform
  removes obvious secrets/PII from text crossing into the agent's context. It is
  not a full persistent-memory-store scrubber; a long-term memory store needs
  its own turn-level scrubbing. Memory leakage is a broad surface; this covers
  the vector an agent actually leaks through most (credentials in retrieved
  content), not the entire surface.
- **Free vs paid.** The free tier *detects and advises* across all ten (an agent
  that respects the verdict is fully guarded). The paid Active Defence tier adds
  **kernel enforcement** for ASI02/05/10 (unbypassable even by a jailbroken,
  non-cooperative agent) and per-pod containment for ASI06.

## The reason chain

Because every guard verdict maps to its ASI class, a deny does not just say "no"
it says *which agentic threat it caught*. `POST /api/agent/check-command`
returns `asi_ids` (e.g. `["ASI02","ASI10"]`) alongside the verdict, so a security
team sees the deny in the framework they evaluate against.
