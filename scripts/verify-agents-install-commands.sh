#!/usr/bin/env bash
# verify-agents-install-commands.sh - keeps the install-facing agent guide honest.
#
# Why this exists: agents-install.md is the install-facing AGENTS.md (spec 082).
# It ships with the binary (install.sh drops it at /etc/innerwarden/AGENTS.md) and is
# published at innerwarden.com/agents.md, so an AI coding agent reads it to install,
# configure, and operate InnerWarden. If it names a command that does not exist, or
# pins a stale version, the agent runs garbage. This gate fails CI on either drift.
#
# Two layers (scope stated honestly):
#   Part A - VERSION: the "Guide matches InnerWarden `X.Y.Z`" token must equal the
#            workspace version in Cargo.toml. Catches a guide left stale on a release.
#   Part B - NO PHANTOM COMMANDS: every runnable `innerwarden <token> ...` example in
#            the guide must reference a token that exists in the real CLI source
#            (crates/ctl/src/main.rs), either as an explicit clap `name = "kebab"` or as
#            the CamelCase enum variant clap kebab-cases. Both the first token (group /
#            top-level command) AND the second token (subcommand) are checked.
#
# Scope limit (no silent over-claim): Part B validates the inline `innerwarden ...`
# examples (the lines an agent copy-pastes), not the prose reference table, and it
# checks presence-in-source, not the full group->subcommand nesting. A phantom command
# is caught; a real command placed under the wrong group is not. Tighten in a follow-up
# if that becomes a real failure mode.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUIDE="${ROOT}/agents-install.md"
CARGO="${ROOT}/Cargo.toml"
MAIN="${ROOT}/crates/ctl/src/main.rs"

fail=0
err() { printf '  ✗ %s\n' "$1" >&2; fail=1; }
ok()  { printf '  ✓ %s\n' "$1"; }

for f in "$GUIDE" "$CARGO" "$MAIN"; do
  [ -f "$f" ] || { echo "FATAL: missing $f" >&2; exit 2; }
done

echo "verify-agents-install-commands: agents-install.md vs CLI + Cargo.toml"

# ---------------------------------------------------------------------------
# Part A - version token
# ---------------------------------------------------------------------------
cargo_ver="$(grep -m1 -E '^version[[:space:]]*=' "$CARGO" | sed -E 's/.*"([^"]+)".*/\1/')"
guide_ver="$(grep -m1 -oE 'Guide matches InnerWarden `[0-9]+\.[0-9]+\.[0-9]+`' "$GUIDE" \
              | sed -E 's/.*`([0-9.]+)`.*/\1/')"

if [ -z "$guide_ver" ]; then
  err "guide is missing the 'Guide matches InnerWarden \`X.Y.Z\`' version token"
elif [ "$guide_ver" != "$cargo_ver" ]; then
  err "guide version ($guide_ver) != Cargo.toml workspace version ($cargo_ver) - bump the guide"
else
  ok "version token matches Cargo.toml ($cargo_ver)"
fi

# ---------------------------------------------------------------------------
# Part B - no phantom commands
# ---------------------------------------------------------------------------
# kebab-or-CamelCase identifier -> 1 if present in main.rs, else 0.
present_in_main() {
  local tok="$1"
  # explicit clap name = "tok"
  if grep -qE "name[[:space:]]*=[[:space:]]*\"${tok}\"" "$MAIN"; then return 0; fi
  # CamelCase enum variant clap would kebab-case to tok (install-warden -> InstallWarden)
  local camel
  camel="$(printf '%s' "$tok" | awk '{n=split($0,a,"-"); s=""; for(i=1;i<=n;i++){s=s toupper(substr(a[i],1,1)) substr(a[i],2)}; print s}')"
  if grep -qE "\b${camel}\b" "$MAIN"; then return 0; fi
  return 1
}

# Pull `innerwarden ...` examples ONLY from runnable contexts so prose cannot bleed
# a following English word in as a fake subcommand:
#   (a) inline code spans:  `innerwarden config responder --dry-run`
#   (b) fenced code blocks:  lines that start with `innerwarden ` between ``` fences
# Then take the first two non-flag, non-placeholder tokens of each example.
spans="$(grep -oE '`innerwarden [^`]*`' "$GUIDE" | tr -d '`' || true)"
fenced="$(awk '/^```/{f=!f; next} f' "$GUIDE" | grep -E '^[[:space:]]*innerwarden ' || true)"
tokens="$(printf '%s\n%s\n' "$spans" "$fenced" \
  | sed -E 's/^[[:space:]]*innerwarden +//' \
  | grep -oE '^[a-z0-9][a-z0-9-]*([ ]+[a-z0-9][a-z0-9-]*)?' \
  | tr ' ' '\n' \
  | grep -vE '^(-|<|$)' \
  | sort -u)"

# Tokens that are real CLI verbs but also second-level args we should still verify.
checked=0
while IFS= read -r tok; do
  [ -z "$tok" ] && continue
  checked=$((checked + 1))
  if present_in_main "$tok"; then
    :
  else
    err "guide references 'innerwarden ... $tok' but no such command/subcommand exists in main.rs"
  fi
done <<EOF
$tokens
EOF
ok "checked $checked command tokens from runnable examples against crates/ctl/src/main.rs"

if [ "$fail" -ne 0 ]; then
  echo "verify-agents-install-commands: FAIL" >&2
  exit 1
fi
echo "verify-agents-install-commands: OK"
