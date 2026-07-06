#!/usr/bin/env bash
# Spec 024 — scenario volume tests.
#
# For each directory under testdata/scenarios/, run the full sensor → agent
# pipeline against a fixed input, then assert that:
#
#   - number of incidents        (sqlite / incidents-*.jsonl)
#   - number of telegram messages (mock telegram outbox JSONL)
#   - number of block_ip decisions (decisions-*.jsonl)
#   - number of auto-executed decisions
#
# all fall inside the envelope declared in `expected.json`. Drift outside the
# envelope fails CI — whether intentional ("I lowered the threshold, of course
# more incidents fire") or accidental (the whack-a-mole class of bug that this
# spec was motivated by).
#
# Determinism levers:
#   - Stub AI provider (`[ai].provider = "stub"`) returns fixed decisions.
#   - Mock Telegram (`INNERWARDEN_MOCK_TELEGRAM=1`) writes to JSONL instead
#     of hitting api.telegram.org.
#   - dry_run responder — decisions are logged, nothing touches the system
#     firewall. "Blocks" here means "block decisions", not "applied rules".
#
# expected.json layout:
#   {
#     "status": "ready" | "wip" | "skip",
#     "description": "...",
#     "last_reviewed": "YYYY-MM-DD",
#     "incidents":              { "min": N, "max": M },
#     "telegram_msgs":          { "min": N, "max": M },
#     "blocks":                 { "min": N, "max": M },
#     "honeypot_sessions":      { "min": N, "max": M },   // optional
#     "decisions_auto_executed":{ "min": N, "max": M }    // optional
#   }
#
#   status=ready ⇒ failure blocks CI.
#   status=wip   ⇒ failure is printed but does not fail the run (scaffolding
#                  for scenarios whose fixtures still need calibration).
#   status=skip  ⇒ scenario is not executed at all.
#
# Per-scenario wall time is bounded; a scenario that hangs cannot poison CI.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_BIN="${CARGO:-$HOME/.cargo/bin/cargo}"
PYTHON_BIN="${PYTHON:-python3}"
SCENARIOS_DIR="$ROOT_DIR/testdata/scenarios"
KEEP_TMP="${KEEP_TMP:-0}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "error: python3 is required (install python3 or set PYTHON)" >&2
  exit 2
fi

if [[ ! -x "$CARGO_BIN" ]]; then
  echo "error: cargo not found at $CARGO_BIN" >&2
  exit 2
fi

if [[ ! -d "$SCENARIOS_DIR" ]]; then
  echo "error: no scenarios directory at $SCENARIOS_DIR" >&2
  exit 2
fi

echo "[scenario-qa] building sensor + agent (debug)"
"$CARGO_BIN" build -p innerwarden-sensor -p innerwarden-agent >/dev/null

SENSOR_BIN="$ROOT_DIR/target/debug/innerwarden-sensor"
AGENT_BIN="$ROOT_DIR/target/debug/innerwarden-agent"

if [[ ! -x "$SENSOR_BIN" || ! -x "$AGENT_BIN" ]]; then
  echo "error: expected debug binaries were not built" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

render_configs() {
  # Use Python to deep-merge defaults with the scenario overrides and emit
  # two deduplicated TOML files. Shell-level concatenation produced duplicate
  # [collectors.*] tables which the sensor parser treats as undefined
  # behaviour. Going through a single merge step keeps the final file a
  # valid TOML document.
  local scenario_dir="$1"
  local data_dir="$2"
  local auth_log="$3"
  local sensor_out="$4"
  local agent_out="$5"

  "$PYTHON_BIN" - \
    "$scenario_dir" "$data_dir" "$auth_log" "$sensor_out" "$agent_out" <<'PY'
import sys
import re

scenario_dir, data_dir, auth_log, sensor_out, agent_out = sys.argv[1:6]

# ---- minimal TOML reader/writer ----
# Scope: handles the subset of TOML actually used by sensor/agent configs —
# dotted section headers, `key = value` scalars, and inline arrays of
# strings. Everything else is passed through as raw lines keyed on section.

def parse(path):
    out = {}
    current = out
    section_key = None
    with open(path) as f:
        text = f.read()
    text = text.replace("{{DATA_DIR}}", data_dir).replace("{{AUTH_LOG}}", auth_log)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"\[([^\]]+)\]\s*(?:#.*)?$", line)
        if m:
            section_key = m.group(1).strip()
            node = out.setdefault(section_key, {})
            current = node
            continue
        # key = value
        if "=" in line:
            key, _, value = line.partition("=")
            current[key.strip()] = value.strip()
    return out

def merge(base, override):
    for section, kv in override.items():
        dst = base.setdefault(section, {})
        for k, v in kv.items():
            dst[k] = v
    return base

def dump(obj, path, comment):
    with open(path, "w") as f:
        f.write(f"# {comment}\n")
        first = True
        # Stable order: agent/output first, then alphabetical.
        priority = ["agent", "output", "narrative", "webhook", "ai", "correlation",
                    "telemetry", "honeypot", "responder", "telegram", "data"]
        keys = sorted(obj.keys(), key=lambda s: (
            priority.index(s) if s in priority else len(priority),
            s,
        ))
        for section in keys:
            if not first:
                f.write("\n")
            first = False
            f.write(f"[{section}]\n")
            for k, v in obj[section].items():
                f.write(f"{k} = {v}\n")

# Defaults for sensor.
sensor_defaults = {
    "agent": {
        "host_id": '"scenario-default"',
    },
    "output": {
        "data_dir": f'"{data_dir}"',
        "write_events": "true",
    },
    "collectors.auth_log": {
        "enabled": "false",
        "path": '""',
    },
    "collectors.journald": {
        "enabled": "false",
        "units": "[]",
    },
    "collectors.docker": {
        "enabled": "false",
    },
    "collectors.integrity": {
        "enabled": "false",
        "poll_seconds": "60",
        "paths": "[]",
    },
    "detectors.ssh_bruteforce": {
        "enabled": "false",
        "threshold": "5",
        "window_seconds": "300",
    },
    "detectors.credential_stuffing": {
        "enabled": "false",
        "threshold": "3",
        "window_seconds": "300",
    },
    "detectors.port_scan": {
        "enabled": "false",
        "threshold": "12",
        "window_seconds": "60",
    },
    # kernel_devnode_exposed defaults to enabled=true in prod because
    # the whole point is to surface misconfigured /dev nodes without
    # operator action. Scenario QA runners (GitHub Actions ubuntu hosts)
    # typically have /dev/kvm and /dev/vhost-* world-or-group-accessible
    # by default, which would emit Medium "integrity.devnode_exposed"
    # events on every scenario run and break the tight expected.json
    # incident envelopes (every scenario would be over by 2-4 incidents
    # depending on the CI runner's /dev inventory). Force it off here
    # exactly like every other detector — scenarios opt-in via their
    # own overrides.toml when they want to test the detector itself.
    "detectors.kernel_devnode_exposed": {
        "enabled": "false",
    },
}

agent_defaults = {
    "narrative": {"enabled": "false", "keep_days": "1"},
    "webhook": {
        "enabled": "false",
        "url": '""',
        "min_severity": '"medium"',
        "timeout_secs": "5",
    },
    "ai": {
        "enabled": "true",
        "provider": '"stub"',
        "model": '"stub"',
        "context_events": "10",
        "confidence_threshold": "0.5",
        "incident_poll_secs": "1",
    },
    "telemetry": {"enabled": "false"},
    "responder": {
        "enabled": "true",
        "dry_run": "true",
        "block_backend": '"ufw"',
        "allowed_skills": '["block-ip-ufw", "monitor-ip"]',
    },
    "telegram": {
        "enabled": "true",
        "bot_token": '"scenario-qa-fake"',
        "chat_id": '"scenario-qa-chat"',
        "min_severity": '"low"',
    },
}

overrides_path = f"{scenario_dir}/input/overrides.toml"
all_overrides = {}
try:
    all_overrides = parse(overrides_path)
except FileNotFoundError:
    pass

sensor_over = {}
agent_over = {}
for section, kv in all_overrides.items():
    if section.startswith("sensor."):
        sensor_over[section[len("sensor."):]] = kv
    elif section.startswith("agent."):
        agent_over[section[len("agent."):]] = kv
    # Anything else is ignored.

merge(sensor_defaults, sensor_over)
merge(agent_defaults, agent_over)

dump(sensor_defaults, sensor_out, "scenario-qa sensor config (auto-generated)")
dump(agent_defaults, agent_out, "scenario-qa agent config (auto-generated)")
PY
}

count_lines() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo 0
    return
  fi
  # grep -c returns 1 when nothing matches; funnel to 0 without echoing twice.
  local n
  n=$(grep -c '.' "$file" 2>/dev/null) || n=0
  echo "$n"
}

wait_for_pid_exit() {
  local pid="$1"
  local timeout_s="${2:-3}"
  local polls=$((timeout_s * 10))
  local i
  for ((i = 0; i < polls; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    return 1
  fi
  return 0
}

evaluate_envelope() {
  # $1 = expected.json, $2..N = pairs of (field count)
  "$PYTHON_BIN" - "$@" <<'PY'
import json, sys
path = sys.argv[1]
pairs = sys.argv[2:]
with open(path) as f:
    expected = json.load(f)
failures = []
for i in range(0, len(pairs), 2):
    field, count_s = pairs[i], pairs[i + 1]
    if field not in expected:
        continue
    envelope = expected[field]
    lo = int(envelope.get("min", 0))
    hi = int(envelope.get("max", 10**9))
    count = int(count_s)
    if count < lo or count > hi:
        failures.append(f"  {field}: got {count}, expected [{lo}..{hi}]")
for f in failures:
    print(f)
sys.exit(1 if failures else 0)
PY
}

# ---------------------------------------------------------------------------
# Per-scenario runner
# ---------------------------------------------------------------------------

run_scenario() {
  local scenario_dir="$1"
  local scenario="$2"
  local scenario_status="${3:-ready}"
  local work_dir
  work_dir="$(mktemp -d "${TMPDIR:-/tmp}/scenario-${scenario}.XXXXXX")"
  local data_dir="$work_dir/data"
  mkdir -p "$data_dir"

  local auth_log_src="$scenario_dir/input/auth.log"
  local auth_log="$work_dir/auth.log"
  if [[ -f "$auth_log_src" ]]; then
    cp "$auth_log_src" "$auth_log"
  else
    # Scenarios without auth.log get an empty placeholder to avoid path-not-found
    # warnings from the collector (which is disabled for those scenarios anyway).
    : > "$auth_log"
  fi

  local sensor_cfg="$work_dir/sensor.toml"
  local agent_cfg="$work_dir/agent.toml"
  render_configs "$scenario_dir" "$data_dir" "$auth_log" "$sensor_cfg" "$agent_cfg"

  local outbox="$data_dir/telegram-outbox.jsonl"
  : > "$outbox"

  local sensor_log="$work_dir/sensor.log"
  local agent_log="$work_dir/agent.log"

  # Sensor runs for a bounded window, then we send SIGINT and wait.
  "$SENSOR_BIN" --config "$sensor_cfg" > "$sensor_log" 2>&1 &
  local sensor_pid=$!
  sleep 3
  # Flake guard: on a loaded CI runner the sensor may not finish reading
  # auth.log + running the detectors within the 3s base window, so SIGINT lands
  # mid-detection and the scenario sees too few (or zero) incidents.
  #
  # Two failure shapes this guards against:
  #   1. 01-ssh-brute-single: the single incident fires late -> SIGINT before
  #      it lands -> 0 incidents.
  #   2. 02-ssh-brute-coordinated: the auth.log is round-robin across 10 IPs, so
  #      the FIRST incident only fires near the end of the file and the other 9
  #      land on the last handful of lines. Breaking on the FIRST incident (the
  #      old `COUNT>0 && break`) SIGINT'd the sensor before IPs 2-10 crossed
  #      threshold -> partial counts; a slow runner could even SIGINT before any
  #      incident -> 0.
  #
  # So instead of bailing on the first incident, wait until the incident count
  # has APPEARED and then QUIESCED (held steady across several polls = the
  # sensor has drained auth.log and all detectors have fired), capped well above
  # the worst-case debug-build read time. Seeded scenarios (empty auth.log) just
  # consume the base window and are unaffected.
  if [[ -s "$auth_log" ]]; then
    local _sqa_db="$data_dir/innerwarden.db"
    local _w _n _prev=-1 _stable=0
    for ((_w = 0; _w < 80; _w++)); do
      _n=$("$PYTHON_BIN" - "$_sqa_db" <<'PY' 2>/dev/null || echo 0
import sqlite3, sys
try:
    print(sqlite3.connect(sys.argv[1]).execute("SELECT COUNT(*) FROM incidents").fetchone()[0])
except Exception:
    print(0)
PY
)
      if [[ "${_n:-0}" -gt 0 ]]; then
        if [[ "${_n}" -eq "${_prev}" ]]; then
          _stable=$((_stable + 1))
          # Count non-zero and unchanged for 3 consecutive polls (~0.9s) =>
          # the sensor has quiesced; safe to SIGINT without truncating.
          [[ "$_stable" -ge 3 ]] && break
        else
          _stable=0
        fi
        _prev="$_n"
      fi
      sleep 0.3
    done
  fi
  kill -INT "$sensor_pid" 2>/dev/null || true
  if ! wait_for_pid_exit "$sensor_pid" 3; then
    kill -TERM "$sensor_pid" 2>/dev/null || true
    if ! wait_for_pid_exit "$sensor_pid" 2; then
      kill -KILL "$sensor_pid" 2>/dev/null || true
    fi
  fi
  wait "$sensor_pid" 2>/dev/null || true

  # Seed pre-formed incidents / honeypot sessions for scenarios that cannot be
  # driven through the sensor on this runner (no eBPF, no root listener, no
  # packet generator). See scripts/scenario_seed.py for fixture format.
  local seed_log="$work_dir/seed.log"
  if ! "$PYTHON_BIN" "$ROOT_DIR/scripts/scenario_seed.py" \
        --scenario-dir "$scenario_dir" \
        --data-dir "$data_dir" > "$seed_log" 2>&1; then
    echo "[scenario-qa] seed failed for $scenario" >&2
    cat "$seed_log" >&2
    if [[ "$KEEP_TMP" != "1" ]]; then
      rm -rf "$work_dir"
    fi
    return 1
  fi

  local agent_exit_code=0
  set +e
  INNERWARDEN_MOCK_TELEGRAM=1 \
  INNERWARDEN_MOCK_TELEGRAM_PATH="$outbox" \
  "$AGENT_BIN" --data-dir "$data_dir" --config "$agent_cfg" --once \
    > "$agent_log" 2>&1
  agent_exit_code=$?
  set -e
  if (( agent_exit_code != 0 )); then
    if [[ "$scenario_status" == "ready" ]]; then
      echo "[scenario-qa] ready scenario agent exited with code ${agent_exit_code}: $scenario" >&2
      cat "$agent_log" >&2
      if [[ "$KEEP_TMP" != "1" ]]; then
        rm -rf "$work_dir"
      else
        echo "[scenario-qa] kept work dir: $work_dir"
      fi
      return 1
    fi
    echo "[scenario-qa] wip scenario agent exited with code ${agent_exit_code}: $scenario (non-blocking)" >&2
  fi

  # Collect metrics. Spec 016 moved incidents to the unified SQLite store
  # (innerwarden.db); treat the sqlite count as authoritative. JSONL remains
  # for telegram and decisions which are still file-based.
  local today
  today=$(date +%F)
  local decisions_file="$data_dir/decisions-${today}.jsonl"
  local sqlite_db="$data_dir/innerwarden.db"

  local incidents_count=0
  if [[ -f "$sqlite_db" ]]; then
    incidents_count=$("$PYTHON_BIN" - "$sqlite_db" <<'PY'
import sqlite3, sys
try:
    con = sqlite3.connect(sys.argv[1])
    cur = con.execute("SELECT COUNT(DISTINCT incident_id) FROM incidents")
    print(int(cur.fetchone()[0]))
except Exception:
    # Table may not exist if the scenario produced nothing.
    print(0)
PY
)
  fi

  local telegram_count
  telegram_count=$(count_lines "$outbox")

  local block_count=0
  local auto_exec_count=0
  if [[ -f "$decisions_file" ]]; then
    block_count=$("$PYTHON_BIN" - "$decisions_file" <<'PY'
import json, sys
n = 0
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        if o.get("action_type") == "block_ip":
            n += 1
print(n)
PY
)
    auto_exec_count=$("$PYTHON_BIN" - "$decisions_file" <<'PY'
import json, sys
n = 0
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        if o.get("auto_executed") is True:
            n += 1
print(n)
PY
)
  fi

  local honeypot_count=0
  local honeypot_file="$data_dir/honeypot-sessions-${today}.jsonl"
  if [[ -f "$honeypot_file" ]]; then
    honeypot_count=$(count_lines "$honeypot_file")
  fi

  local report_line
  report_line="incidents=${incidents_count} telegram_msgs=${telegram_count} blocks=${block_count} honeypot_sessions=${honeypot_count} decisions_auto_executed=${auto_exec_count}"

  local expected="$scenario_dir/expected.json"
  local ok=0
  if ! evaluate_envelope "$expected" \
      incidents "$incidents_count" \
      telegram_msgs "$telegram_count" \
      blocks "$block_count" \
      honeypot_sessions "$honeypot_count" \
      decisions_auto_executed "$auto_exec_count"; then
    ok=1
  fi

  if (( ok == 0 )); then
    printf "[scenario-qa] PASS  %-32s %s\n" "$scenario" "$report_line"
    if [[ "$KEEP_TMP" != "1" ]]; then
      rm -rf "$work_dir"
    else
      echo "[scenario-qa] kept work dir: $work_dir"
    fi
    return 0
  else
    printf "[scenario-qa] FAIL  %-32s %s\n" "$scenario" "$report_line"
    # re-run to capture diff lines (evaluate_envelope already printed them to stdout)
    evaluate_envelope "$expected" \
      incidents "$incidents_count" \
      telegram_msgs "$telegram_count" \
      blocks "$block_count" \
      honeypot_sessions "$honeypot_count" \
      decisions_auto_executed "$auto_exec_count" || true
    echo "  work dir: $work_dir"
    echo "  agent log tail:"
    tail -20 "$agent_log" 2>/dev/null | sed 's/^/    /'
    if [[ "$KEEP_TMP" != "1" ]]; then
      rm -rf "$work_dir"
    fi
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

overall_rc=0
for dir in "$SCENARIOS_DIR"/*/; do
  [[ -d "$dir" ]] || continue
  scenario=$(basename "$dir")
  expected="$dir/expected.json"
  if [[ ! -f "$expected" ]]; then
    echo "[scenario-qa] SKIP  $scenario (no expected.json)"
    continue
  fi

  status=$("$PYTHON_BIN" -c '
import json, sys
with open(sys.argv[1]) as f:
    o = json.load(f)
print(o.get("status", "ready"))
' "$expected")

  case "$status" in
    skip)
      echo "[scenario-qa] SKIP  $scenario (status=skip)"
      continue
      ;;
    wip)
      if ! run_scenario "$dir" "$scenario" "$status"; then
        echo "[scenario-qa] WIP-FAIL $scenario (status=wip — not blocking CI)"
      fi
      ;;
    ready|*)
      if ! run_scenario "$dir" "$scenario" "$status"; then
        overall_rc=1
      fi
      ;;
  esac
done

if (( overall_rc == 0 )); then
  echo "[scenario-qa] all ready scenarios passed"
fi
exit $overall_rc
