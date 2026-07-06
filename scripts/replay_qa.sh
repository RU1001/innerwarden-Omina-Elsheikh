#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_BIN="${CARGO:-$HOME/.cargo/bin/cargo}"

if [[ ! -x "$CARGO_BIN" ]]; then
  echo "error: cargo not found at $CARGO_BIN"
  exit 1
fi

TMP_DIR="${1:-$(mktemp -d "${TMPDIR:-/tmp}/innerwarden-replay.XXXXXX")}"
KEEP_TMP="${KEEP_TMP:-0}"

cleanup() {
  local status=$?
  if [[ "$KEEP_TMP" == "1" ]]; then
    echo "Replay workspace kept at: $TMP_DIR"
  else
    rm -rf "$TMP_DIR"
  fi
  exit "$status"
}
trap cleanup EXIT

DATA_DIR="$TMP_DIR/data"
mkdir -p "$DATA_DIR"

SENSOR_CFG="$TMP_DIR/sensor-replay.toml"
AGENT_CFG="$TMP_DIR/agent-replay.toml"
AUTH_FIXTURE="$TMP_DIR/replay-auth.log"

SENSOR_LOG="$TMP_DIR/sensor.log"
AGENT_LOG="$TMP_DIR/agent.log"
REPORT_LOG="$TMP_DIR/report.log"

DATE="$(date +%F)"
SQLITE_DB="$DATA_DIR/innerwarden.db"
TELEMETRY_FILE="$DATA_DIR/telemetry-$DATE.jsonl"
SUMMARY_FILE="$DATA_DIR/summary-$DATE.md"
REPORT_MD="$DATA_DIR/trial-report-$DATE.md"
REPORT_JSON="$DATA_DIR/trial-report-$DATE.json"
STATE_FILE="$DATA_DIR/state.json"
SENSOR_BIN="$ROOT_DIR/target/debug/innerwarden-sensor"
AGENT_BIN="$ROOT_DIR/target/debug/innerwarden-agent"

assert_file_nonempty() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "assertion failed: missing file $path"
    exit 1
  fi
  if [[ ! -s "$path" ]]; then
    echo "assertion failed: empty file $path"
    exit 1
  fi
}

assert_json_metric_positive() {
  local path="$1"
  local metric="$2"
  if ! grep -Eq "\"${metric}\"[[:space:]]*:[[:space:]]*[1-9][0-9]*" "$path"; then
    echo "assertion failed: ${metric} should be > 0 in $path"
    exit 1
  fi
}

# assert_events_contain_source removed: events are now in SQLite, not JSONL.
# The report JSON metrics (total_events > 0) validate that events were written.

echo "[replay] preparing fixture logs"

# sample-auth.log uses TEST-NET ranges that are filtered by the AI gate.
# Replace with routable IPs so decision/audit paths are exercised deterministically.
sed \
  -e 's/203\.0\.113\.10/1.2.3.4/g' \
  -e 's/198\.51\.100\.5/5.6.7.8/g' \
  "$ROOT_DIR/testdata/sample-auth.log" > "$AUTH_FIXTURE"

cat > "$SENSOR_CFG" <<EOF
[agent]
host_id = "replay-host"

[output]
data_dir = "$DATA_DIR"
write_events = true

[collectors.auth_log]
enabled = true
path = "$AUTH_FIXTURE"

[collectors.journald]
enabled = false
units = ["sshd", "sudo", "kernel"]

[collectors.docker]
enabled = false

[collectors.integrity]
enabled = false
poll_seconds = 60
paths = []

[detectors.ssh_bruteforce]
enabled = true
threshold = 5
window_seconds = 300

[detectors.credential_stuffing]
enabled = true
threshold = 3
window_seconds = 300

[detectors.port_scan]
enabled = false
threshold = 12
window_seconds = 60
EOF

cat > "$AGENT_CFG" <<EOF
[narrative]
enabled = true
keep_days = 7

[webhook]
enabled = false
url = ""
min_severity = "medium"
timeout_secs = 5

[ai]
enabled = true
provider = "anthropic"
model = "claude-stub"
context_events = 20
confidence_threshold = 0.8
incident_poll_secs = 2

[telemetry]
enabled = true

[responder]
enabled = false
dry_run = true
block_backend = "ufw"
allowed_skills = ["block-ip-ufw"]
EOF

echo "[replay] building binaries"
"$CARGO_BIN" build -p innerwarden-sensor -p innerwarden-agent > /dev/null
if [[ ! -x "$SENSOR_BIN" || ! -x "$AGENT_BIN" ]]; then
  echo "assertion failed: expected debug binaries were not built"
  exit 1
fi

echo "[replay] running sensor from fixture logs (graceful stop)"
"$SENSOR_BIN" --config "$SENSOR_CFG" > "$SENSOR_LOG" 2>&1 &
SENSOR_PID=$!
# Quiesce-wait before SIGINT: a fixed `sleep` then kill is a flake on a loaded
# CI runner — the debug sensor may not have read the auth fixture + run the
# detectors + WRITTEN its events to SQLite within the window, so SIGINT lands
# early, the `events` table is empty, and the agent's slow loop sees
# events_count=0 -> the `events_count > 0` gate in maybe_write_daily_summary
# skips the summary -> `assert_file_nonempty summary-$DATE.md` fails (the 2026-06
# post-merge replay-qa flake; same class as the scenario-qa fix). Wait until the
# sensor has written events and the count has QUIESCED (held steady), capped, so
# the agent's first --once pass deterministically reads a non-empty event set.
sleep 2
if command -v sqlite3 > /dev/null 2>&1; then
  _rq_prev=-1
  _rq_stable=0
  for _ in $(seq 1 80); do
    _rq_n=$(sqlite3 "$SQLITE_DB" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo 0)
    _rq_n=${_rq_n:-0}
    if [[ "$_rq_n" -gt 0 ]]; then
      if [[ "$_rq_n" -eq "$_rq_prev" ]]; then
        _rq_stable=$((_rq_stable + 1))
        [[ "$_rq_stable" -ge 3 ]] && break
      else
        _rq_stable=0
      fi
      _rq_prev="$_rq_n"
    fi
    sleep 0.3
  done
else
  # No sqlite3 (rare; ubuntu-latest ships it): fall back to the fixed window.
  sleep 2
fi
kill -INT "$SENSOR_PID" 2>/dev/null || true
for _ in $(seq 1 20); do
  if ! kill -0 "$SENSOR_PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if kill -0 "$SENSOR_PID" 2>/dev/null; then
  kill -TERM "$SENSOR_PID" 2>/dev/null || true
fi
wait "$SENSOR_PID" || true

echo "[replay] running agent once (AI stub + audit)"
"$AGENT_BIN" --data-dir "$DATA_DIR" --config "$AGENT_CFG" --once > "$AGENT_LOG" 2>&1
if [[ ! -s "$SUMMARY_FILE" ]]; then
  echo "[replay] daily summary missing after first pass; retrying agent once"
  # GitHub runners can release the sensor SQLite writer a moment later than
  # the process exit is observed. The first pass sometimes finishes
  # before all sensor-written events are visible to the agent's reader.
  #
  # The retry must re-read the same events: slow_loop advances the
  # `events` cursor in `agent_cursors` after every read, so without
  # resetting it the retry sees 0 new events and the
  # `events_count > 0` gate in `narrative_daily_summary::maybe_write_*`
  # blocks the summary write — the failure mode CI hit on PR #404.
  #
  # Resetting the cursor is safe because the agent uses a baseline
  # to dedupe re-processed events; correctness is preserved while the
  # summary write becomes deterministic.
  if command -v sqlite3 > /dev/null 2>&1; then
    sqlite3 "$SQLITE_DB" "DELETE FROM agent_cursors WHERE name = 'events';" 2>/dev/null || true
  fi
  sleep 0.2
  "$AGENT_BIN" --data-dir "$DATA_DIR" --config "$AGENT_CFG" --once >> "$AGENT_LOG" 2>&1
fi

echo "[replay] generating operational report"
"$AGENT_BIN" --report --data-dir "$DATA_DIR" > "$REPORT_LOG" 2>&1

echo "[replay] validating artifacts"
assert_file_nonempty "$SQLITE_DB"
assert_file_nonempty "$TELEMETRY_FILE"
assert_file_nonempty "$SUMMARY_FILE"
assert_file_nonempty "$STATE_FILE"
assert_file_nonempty "$REPORT_MD"
assert_file_nonempty "$REPORT_JSON"

if ! grep -Eq '"state_json_readable"[[:space:]]*:[[:space:]]*true' "$REPORT_JSON"; then
  echo "assertion failed: state_json_readable should be true"
  exit 1
fi
if ! grep -Eq '"available"[[:space:]]*:[[:space:]]*true' "$REPORT_JSON"; then
  echo "assertion failed: operational telemetry should be available"
  exit 1
fi

assert_json_metric_positive "$REPORT_JSON" "total_events"
assert_json_metric_positive "$REPORT_JSON" "total_incidents"
assert_json_metric_positive "$REPORT_JSON" "total_decisions"
assert_json_metric_positive "$REPORT_JSON" "ai_decision_count"

echo "[replay] success"
echo "  data_dir:   $DATA_DIR"
echo "  sqlite_db:  $SQLITE_DB ($(du -h "$SQLITE_DB" | cut -f1))"
echo "  telemetry:  $(wc -l < "$TELEMETRY_FILE" | tr -d ' ')"
echo "  report:     $REPORT_MD"
