#!/usr/bin/env python3
"""Simulated LLM-gateway metrics exporter (DEMO ONLY).

InnerWarden is a security layer and does not measure LLM token spend — that
data comes from the LLM gateway a fleet fronts its agents with (LiteLLM). For a
demo without a real gateway, this stands in for one: it exposes LiteLLM-shaped
metrics (`litellm_total_tokens`, `litellm_spend_metric`) per team so the
dashboard's "Cost & tokens per agent" row lights up next to the security panels.
The token counters increase monotonically with wall-clock time so
`increase()`/rate() render real curves. NOT a product component — do not ship
in place of a real gateway.

Run:  python3 gateway-sim.py [PORT]   (default 9101, path /metrics)
"""
import http.server, sys, time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9101
START = time.monotonic()

# team -> (tokens/sec, model). Benign agents do more real work (more tokens);
# the rogue does less legitimate work. Blended price ~ $0.012 / 1k tokens.
TEAMS = {
    "platform-eng":  (42.0, "claude-sonnet-4-6"),
    "payments-team":    (28.0, "claude-sonnet-4-6"),
    "data-science":   (35.0, "claude-opus-4-8"),
    "growth-team": (14.0, "claude-sonnet-4-6"),
}
PRICE_PER_1K = 0.012

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        elapsed = time.monotonic() - START
        out = []
        out.append("# HELP litellm_total_tokens Total LLM tokens per team (simulated gateway)")
        out.append("# TYPE litellm_total_tokens counter")
        for team, (rate, model) in TEAMS.items():
            toks = int(rate * elapsed)
            out.append(f'litellm_total_tokens{{team="{team}",model="{model}"}} {toks}')
        out.append("# HELP litellm_spend_metric Total LLM spend (USD) per team (simulated gateway)")
        out.append("# TYPE litellm_spend_metric counter")
        for team, (rate, _model) in TEAMS.items():
            spend = rate * elapsed / 1000.0 * PRICE_PER_1K
            out.append(f'litellm_spend_metric{{team="{team}"}} {spend:.4f}')
        body = ("\n".join(out) + "\n").encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain; version=0.0.4")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", PORT), H).serve_forever()
