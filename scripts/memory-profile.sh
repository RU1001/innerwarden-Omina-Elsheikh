#!/usr/bin/env bash
# memory-profile.sh — report InnerWarden resident memory (RSS) per process.
#
# This is the methodology behind the README memory figure: run it on a host
# where the sensor + agent are active and it prints the per-process RSS plus
# the full-stack total, the same numbers `ps`/`free` show a reviewer.
#
# RSS includes the on-device AI classifier (~150 MB when the Local Warden
# model is loaded) and jemalloc's retained arenas, so it is an upper bound on
# live heap. Detection-only (AI disabled) stays near the sensor footprint.
#
# Usage:  ./scripts/memory-profile.sh
set -euo pipefail

printf '%-26s %12s\n' "process" "RSS (MB)"
printf '%-26s %12s\n' "--------------------------" "-----------"

ps -eo rss,comm,args 2>/dev/null \
  | grep -iE 'innerwarden' | grep -v grep \
  | awk '{printf "%-26s %12.1f\n", $2, $1/1024}'

total="$(ps -eo rss,args 2>/dev/null \
  | grep -iE 'innerwarden' | grep -v grep \
  | awk '{s+=$1} END {printf "%.1f", s/1024}')"

printf '%-26s %12s\n' "--------------------------" "-----------"
printf '%-26s %12s\n' "TOTAL (full stack)" "${total:-0.0}"
