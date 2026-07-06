#!/usr/bin/env python3
"""Bridge new InnerWarden incidents from the SQLite store to Loki.

Current InnerWarden binaries persist incidents to the UNIFIED SQLite store
(``$DATA_DIR/innerwarden.db``, table ``incidents``), not the legacy
``incidents-*.jsonl`` sink. So an Alloy/promtail setup that tails the JSONL sees
nothing. This bridge reads new ``incidents`` rows by rowid cursor and pushes
them to Loki with the labels the fleet dashboard's incident panels expect
(``{kind="incident"|"guard", host, job="innerwarden"}``), so the "Live incident
feed" and "Command review journal" render from the live store. Idempotent via a
cursor file; safe to run on a short systemd timer.

Config (env):
  IW_DB       default /var/lib/innerwarden/innerwarden.db
  LOKI_URL    default http://127.0.0.1:3100/loki/api/v1/push
  CURSOR      default /var/lib/innerwarden/loki-bridge.cursor
  BATCH       default 2000   (max rows pushed per run)

Not a product component; ships in deploy/observability as the recommended way to
feed the Loki incident panels until the agent exposes a live JSONL/OTLP stream.
"""
import datetime
import json
import os
import sqlite3
import time
import urllib.request

DB = os.environ.get("IW_DB", "/var/lib/innerwarden/innerwarden.db")
LOKI = os.environ.get("LOKI_URL", "http://127.0.0.1:3100/loki/api/v1/push")
CURSOR = os.environ.get("CURSOR", "/var/lib/innerwarden/loki-bridge.cursor")
BATCH = int(os.environ.get("BATCH", "2000"))
HOST = os.uname().nodename


def _last_id():
    try:
        with open(CURSOR) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 0


def _tenant(data):
    for t in data.get("tags") or []:
        if isinstance(t, str) and t.startswith("tenant:"):
            return t.split(":", 1)[1]
    return ""


def _ns(ts):
    try:
        t = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return str(int(t.timestamp() * 1e9))
    except (ValueError, AttributeError):
        return str(int(time.time() * 1e9))


def _line(ts, sev, det, title, summary, data):
    ev = data.get("evidence")
    ev0 = ev[0] if isinstance(ev, list) and ev else (ev if isinstance(ev, dict) else {})
    rec = "deny" if "blocked" in (title or "") else "review" if "flagged" in (title or "") else ""
    return json.dumps({
        "ts": ts, "severity": sev, "detector": det, "title": title,
        "summary": summary, "tags": data.get("tags", []),
        "tenant": data.get("tenant") or _tenant(data) or ev0.get("tenant", ""),
        "recommendation": data.get("recommendation") or ev0.get("recommendation") or rec,
        "command": data.get("command") or ev0.get("command", ""),
        "risk_score": data.get("risk_score") or ev0.get("risk_score", ""),
        "atr_rule_ids": data.get("atr_rule_ids") or ev0.get("atr_rule_ids", []),
    })


def _push(streams):
    body = json.dumps({"streams": streams}).encode()
    req = urllib.request.Request(LOKI, data=body, headers={"content-type": "application/json"})
    urllib.request.urlopen(req, timeout=10).read()


def main():
    since = _last_id()
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=10)
    rows = con.execute(
        "select id, ts, severity, detector, title, summary, data from incidents "
        "where id > ? order by id asc limit ?", (since, BATCH),
    ).fetchall()
    if not rows:
        return
    buckets = {"incident": [], "guard": []}
    max_id = since
    for rid, ts, sev, det, title, summary, data in rows:
        max_id = max(max_id, rid)
        kind = "guard" if (det or "").startswith("agent_guard") else "incident"
        try:
            d = json.loads(data) if data else {}
        except (ValueError, TypeError):
            d = {}
        buckets[kind].append([_ns(ts), _line(ts, sev, det, title, summary, d)])
    streams = [
        {"stream": {"kind": k, "host": HOST, "job": "innerwarden"}, "values": v}
        for k, v in buckets.items() if v
    ]
    if streams:
        _push(streams)
        with open(CURSOR, "w") as f:
            f.write(str(max_id))


if __name__ == "__main__":
    main()
