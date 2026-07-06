# Fleet observability (Prometheus + Grafana)

Watch an entire fleet of AI agents in one place. Each host runs an InnerWarden
agent that exposes Prometheus metrics on `https://<host>:8787/metrics`; point
Prometheus at every node and load the Grafana dashboard to see, across the whole
fleet: per-tenant agent activity (each Claude Code = a tenant), decisions and
responses, and the host-level detection underneath.

This is the recommended way to give a team dashboards over many agents —
InnerWarden's built-in dashboard is per-host; Prometheus + Grafana is the
multi-host, multi-tenant view.

## Files

| File | What it is |
|------|------------|
| `grafana-dashboard-fleet.json` | The Grafana dashboard (import it, pick your Prometheus datasource) |
| `prometheus.yml` | Scrape config: a static demo list + a commented Kubernetes SD job |
| `servicemonitor.yaml` | Prometheus Operator `ServiceMonitor` + headless `Service` for a k8s cluster |

## Quick start (single box / demo)

```bash
# 1. Run Prometheus with the scrape config (Docker, or the binary).
docker run -d --name prometheus --network host \
  -v "$PWD/prometheus.yml:/etc/prometheus/prometheus.yml" \
  prom/prometheus

# 2. Run Grafana.
docker run -d --name grafana --network host grafana/grafana

# 3. In Grafana (http://localhost:3000, admin/admin):
#    - add a Prometheus datasource → http://localhost:9090
#    - Dashboards → Import → upload grafana-dashboard-fleet.json → pick the datasource
```

The agent serves `/metrics` over HTTPS with a self-signed cert, so the scrape
config uses `scheme: https` + `insecure_skip_verify`. The agent binds the
dashboard/metrics port to loopback by default; to scrape it from an off-box
Prometheus, expose `:8787` to the monitoring network (or front it with a
metrics reverse-proxy / proper cert).

## Kubernetes (production shape)

Run the InnerWarden agent as a DaemonSet (one per node) exposing a `metrics`
port, then:

```bash
kubectl apply -f servicemonitor.yaml   # requires Prometheus Operator / kube-prometheus-stack
```

`instance` becomes the node name and `tenant` is the per-pod attribution
(spec 084: read from the kernel cgroup, so an agent cannot spoof it). The
dashboard's tenant panels then break down activity per Claude Code pod /
employee automatically as the fleet scales.

## Incident investigation (Loki — "what actually happened")

Metrics tell you *how much* and *trending*; a security team also needs *what
happened, who, which command, why* — per incident, drill-down. That is the wrong
shape for Prometheus (it aggregates). The incident layer adds **Loki** (event
store) + **Alloy** (log shipper): one Alloy per node tails the InnerWarden
agent's JSONL — `incidents-*.jsonl`, `agent-guard-events-*.jsonl`,
`decisions-*.jsonl` — and ships them to Loki. Grafana then queries Loki with
LogQL for the investigation panels:

- **Command review journal** — the verbatim command each agent ran through the
  guard, the verdict (allow/review/deny), and the ATR rules that fired. The
  "what did they try, and what got blocked" view.
- **Live incident feed** — every incident across the fleet, newest first,
  severity + title + tags; click a line to expand the full record for evidence.

Labels are kept low-cardinality (`kind`, `host`, `job`); the high-cardinality
fields (tenant, command text, ATR ids) stay in the log line and are parsed on
read by LogQL — the correct Loki pattern. Alloy runs a secret-redaction pass
before shipping (tokens, private keys, `password=`), and Loki retention
defaults to 14 days (configurable in `loki-config.yaml` — the customer owns it).

```bash
# Loki (single binary) + Alloy (shipper). Both are standard, customer-run,
# deployed alongside Prometheus/Grafana (not inside the agent).
./loki -config.file=loki-config.yaml &
sudo ./alloy run config.alloy --storage.path=./alloy-data &   # root: reads /var/lib/innerwarden (0750)
# In Grafana: add a Loki datasource → http://localhost:3100, then the
# "Incident investigation" panels light up (the dashboard already includes them).
```

`config.alloy` tails the default `/var/lib/innerwarden/*.jsonl` paths; adjust if
your data dir differs. On Kubernetes, run Alloy as a DaemonSet with a hostPath
mount of the agent data dir (same low-cardinality labels).

### If incidents live in SQLite (current default): use the bridge

Current InnerWarden binaries persist incidents to the **unified SQLite store**
(`<data_dir>/innerwarden.db`, table `incidents`), not the legacy
`incidents-*.jsonl` sink — so an Alloy setup that tails the JSONL sees nothing.
Use `sqlite-loki-bridge.py` instead: it reads new `incidents` rows by rowid
cursor and pushes them to Loki with the same labels the panels expect
(`{kind="incident"|"guard", host, job}`), attributing agent-guard incidents to
their tenant. Run it on a short timer:

```bash
sudo install -Dm755 sqlite-loki-bridge.py /opt/innerwarden/observability/sqlite-loki-bridge.py
sudo cp iw-loki-bridge.{service,timer} /etc/systemd/system/
sudo systemctl enable --now iw-loki-bridge.timer   # runs every 20s
# env overrides (drop-in): IW_DB, LOKI_URL, CURSOR, BATCH
```

`kind` is `guard` for agent-guard incidents (detector `agent_guard:*`) and
`incident` otherwise, so the Command review journal and Live incident feed both
fill from the live store. Use the JSONL/Alloy path above only if your build
still writes the JSONL sink.

## Cost & tokens per agent (optional)

InnerWarden is a **security** layer — it screens what an agent runs, it does
not sit in the agent's LLM request path, so it does not measure token spend.
That data lives in the **LLM gateway** a fleet fronts its agents with (for rate
limits and cost caps). Point the same Prometheus at that gateway and the
dashboard's "Cost & tokens per agent" row lights up next to the security
panels — one pane for **what each agent did, what got blocked, and what it
cost**, per employee.

The panels use LiteLLM's metric names (`litellm_total_tokens`,
`litellm_spend_metric`) and alias the gateway's `team`/`key` label to `tenant`
so cost lines up with the security panels. If the gateway is not LiteLLM, adjust
the two panel queries to that gateway's token/spend metric names. Until a
gateway is scraped, the row shows "No data" (it is deliberately included so the
unified view is ready the moment a gateway is added).

## Demo / smoke data (`demo/populate-demo.sh`)

To fill every panel with lifelike data — for a walkthrough, a screenshot, or an
end-to-end smoke test — run the scenario generator on the agent host:

```bash
deploy/observability/demo/populate-demo.sh [BASE_URL] [WAVES]   # defaults: https://127.0.0.1:8787  3
```

It drives the agent's `check-command` API as a realistic multi-tenant fleet:
four tenants (each Claude Code = one employee/pod) where `acme-corp`,
`initech`, `umbrella` do benign engineering work and `globex-inc` is a
compromised/rogue agent running a full kill chain (recon → credential access →
exfil → C2 → destruction). `check-command` only *analyses* a command (it never
executes it), so this is safe against a live box; every denied command also
becomes an agent_guard incident, so the incident feed, rogue-agent signal, and
command review journal all populate from one run. The rogue tenant lights the
rogue-agent panel deep red (~96% deny share) while the benign tenants stay
green — the "one agent went rogue, spot it instantly" story, reproducibly.

For the **Cost & tokens** row without a real gateway, `demo/gateway-sim.py`
stands in for a LiteLLM gateway: it exposes `litellm_total_tokens` /
`litellm_spend_metric` per team (monotonic counters, so `increase()` renders
real curves). Run it and add a scrape target so the cost panels light up:

```bash
python3 deploy/observability/demo/gateway-sim.py 9101 &   # DEMO ONLY, not a product component
# then add a Prometheus job:  - job_name: 'llm-gateway'  static_configs: [{ targets: ['127.0.0.1:9101'] }]
```

It is clearly a stand-in — do not ship it in place of a real gateway.

## Metrics the dashboard uses

`innerwarden_incidents_by_tenant{tenant}` · `innerwarden_incidents_total{detector}`
· `innerwarden_decisions_total{action}` · `innerwarden_events_total{collector}`
· `innerwarden_executions_total{mode}` · `innerwarden_ai_latency_avg_ms` ·
`innerwarden_agent_guard_atr_rules_loaded` · `innerwarden_errors_total{component}`
· `innerwarden_responses_active` · `up`.
