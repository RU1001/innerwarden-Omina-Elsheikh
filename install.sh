#!/usr/bin/env bash
set -euo pipefail

# Inner Warden installer (production trial profile)
#
# Default mode: downloads pre-built binaries from GitHub Releases (~10 s).
# Source mode:  INNERWARDEN_BUILD_FROM_SOURCE=1 - builds from source with cargo.
#
# One-liner:
#   curl -fsSL https://github.com/InnerWarden/innerwarden/releases/latest/download/install.sh | sudo bash
#
# Flow test only (no install/no service changes):
#   bash install.sh --simulate
#   bash install.sh --simulate --simulate-mode=advanced
#
# What this script does:
# - Downloads (or builds) sensor + agent + ctl binaries
# - Validates SHA-256 of downloaded binaries
# - Installs binaries to /usr/local/bin
# - Creates /etc/innerwarden/{config.toml,agent.toml,agent.env}
# - Creates systemd units for sensor + agent
# - Configures a SAFE trial mode:
#   * OpenAI analysis enabled
#   * responder.enabled = false (no skill execution)
#   * dry_run = true
#   * only block-ip-ufw in allowed_skills

GITHUB_REPO="InnerWarden/innerwarden"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"

IW_USER="innerwarden"

# Parse flags
WITH_INTEGRATIONS=0
CANARY=0
VERBOSE=0
SIMULATE=0
SIMULATE_MODE="basic"
# Supervised mode is opt-in (see the supervisor-unit block below). It MUST be
# declared here: it is referenced under `set -u` later, so a missing default
# aborts the whole install with "SUPERVISED: unbound variable". Override via the
# --supervised flag or the SUPERVISED env var.
SUPERVISED="${SUPERVISED:-false}"
for arg in "$@"; do
  case "$arg" in
    --with-integrations) WITH_INTEGRATIONS=1 ;;
    --canary) CANARY=1 ;;
    --verbose) VERBOSE=1 ;;
    --simulate) SIMULATE=1 ;;
    --simulate-mode=basic) SIMULATE_MODE="basic" ;;
    --simulate-mode=advanced) SIMULATE_MODE="advanced" ;;
    --supervised) SUPERVISED=true ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
  esac
done
UNINSTALL="${UNINSTALL:-0}"
PURGE="${PURGE:-0}"

# BASH_SOURCE[0] is unset when the script is piped through `curl | bash` —
# `set -u` then aborts before we even print the banner. Fall back to $0
# (which is the empty string under bash -c but at least won't crash) and
# default to PWD when that also yields nothing useful.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"

# Detect OS + arch + distro
OS_TYPE="$(uname -s)"   # Linux | Darwin
ARCH="$(uname -m)"      # x86_64 | aarch64 | arm64
KERNEL="$(uname -r)"
DISTRO=""
if [[ -f /etc/os-release ]]; then
  DISTRO="$(. /etc/os-release && echo "$NAME $VERSION_ID" 2>/dev/null)"
fi

# ── Sudo handling ────────────────────────────────────────────────────────
# Instead of re-execing the entire script with sudo (which kills stdin/tty),
# we validate sudo once and prefix privileged commands with $SUDO.
# This keeps the terminal attached so innerwarden setup can prompt the user.
if [[ "${SIMULATE}" -eq 1 ]]; then
  SUDO=""
else
  if [[ "$(id -u)" -ne 0 ]]; then
    # Check if user has passwordless sudo (common on cloud VMs)
    if sudo -n true 2>/dev/null; then
      SUDO="sudo"
    else
      echo ""
      echo "  Root access needed."
      echo ""
      sudo -v || { echo "  sudo failed."; exit 1; }
      SUDO="sudo"
    fi
  else
    SUDO=""
  fi
fi

BIN_DIR="/usr/local/bin"

if [[ "$OS_TYPE" == "Darwin" ]]; then
  CONFIG_DIR="/usr/local/etc/innerwarden"
  DATA_DIR="/usr/local/var/lib/innerwarden"
  PLIST_DIR="/Library/LaunchDaemons"
  SENSOR_PLIST="$PLIST_DIR/com.innerwarden.sensor.plist"
  AGENT_PLIST="$PLIST_DIR/com.innerwarden.agent.plist"
  LOG_DIR="/usr/local/var/log/innerwarden"
  INSTALL_USER="root"
  INSTALL_GROUP="wheel"
else
  CONFIG_DIR="/etc/innerwarden"
  DATA_DIR="/var/lib/innerwarden"
  INSTALL_USER="root"
  INSTALL_GROUP="root"
fi

SENSOR_BIN="${BIN_DIR}/innerwarden-sensor"
AGENT_BIN="${BIN_DIR}/innerwarden-agent"

SENSOR_CONFIG="${CONFIG_DIR}/config.toml"
AGENT_CONFIG="${CONFIG_DIR}/agent.toml"
AGENT_ENV="${CONFIG_DIR}/agent.env"

SENSOR_UNIT="/etc/systemd/system/innerwarden-sensor.service"
AGENT_UNIT="/etc/systemd/system/innerwarden-agent.service"
AUDIT_RULE_FILE="/etc/audit/rules.d/innerwarden-shell-audit.rules"

log() {
  if [[ "${VERBOSE:-0}" -eq 1 ]]; then
    printf '  · %s\n' "$*"
  fi
}

vlog() {
  # Always visible log
  printf '  · %s\n' "$*"
}

fail() {
  printf '[innerwarden-install] ERROR: %s\n' "$*" >&2
  exit 1
}

# ── Uninstall path ─────────────────────────────────────────────────────────
# `curl -fsSL <installer> | sudo bash -s -- --uninstall [--purge]` mirrors the
# install entrypoint for removal. Prefers the installed `innerwarden uninstall`
# command (single source of truth for the teardown). If that binary is missing
# or broken, falls back to an inline teardown so a half-installed box can still
# be cleaned. Keeps config + data unless --purge.
uninstall_inline() {
  vlog "innerwarden binary not usable — running inline fallback teardown"
  local units="innerwarden-watchdog innerwarden-supervisor innerwarden-agent innerwarden-sensor"
  for u in $units; do
    $SUDO systemctl stop "$u" 2>/dev/null || true
    $SUDO systemctl disable "$u" 2>/dev/null || true
    $SUDO rm -f "/etc/systemd/system/${u}.service" 2>/dev/null || true
    $SUDO rm -rf "/etc/systemd/system/${u}.service.d" 2>/dev/null || true
  done
  $SUDO systemctl daemon-reload 2>/dev/null || true
  $SUDO systemctl reset-failed 2>/dev/null || true
  for b in innerwarden innerwarden-ctl innerwarden-agent innerwarden-sensor \
           innerwarden-watchdog innerwarden-supervisor; do
    $SUDO rm -f "${BIN_DIR}/${b}" 2>/dev/null || true
  done
  $SUDO rm -rf /usr/local/lib/innerwarden /sys/fs/bpf/innerwarden /run/innerwarden 2>/dev/null || true
  $SUDO rm -f /etc/sudoers.d/innerwarden* 2>/dev/null || true
  if [[ "${PURGE}" -eq 1 ]]; then
    $SUDO rm -rf "${CONFIG_DIR}" "${DATA_DIR}" /var/log/innerwarden 2>/dev/null || true
    $SUDO userdel innerwarden 2>/dev/null || true
  fi
}

if [[ "${UNINSTALL}" -eq 1 ]]; then
  echo ""
  echo "  InnerWarden uninstall"
  echo ""
  args="--yes"
  [[ "${PURGE}" -eq 1 ]] && args="${args} --purge"
  if command -v innerwarden >/dev/null 2>&1 && innerwarden --version >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    $SUDO innerwarden uninstall ${args}
  else
    uninstall_inline
    echo ""
    echo "  ✅ InnerWarden removed."
    [[ "${PURGE}" -eq 0 ]] && echo "  Config + data kept (re-run with --purge to remove)."
  fi
  exit 0
fi

normalize_bool() {
  local normalized
  normalized="$(printf '%s' "${1}" | tr '[:upper:]' '[:lower:]')"
  case "${normalized}" in
    1|true|yes|y|on)
      echo "true"
      ;;
    *)
      echo "false"
      ;;
  esac
}

term_cols() {
  local cols=""
  if command -v tput >/dev/null 2>&1; then
    cols="$(tput cols 2>/dev/null || true)"
  fi
  if [[ -z "${cols}" || ! "${cols}" =~ ^[0-9]+$ || "${cols}" -lt 20 ]]; then
    cols="${COLUMNS:-80}"
  fi
  if [[ ! "${cols}" =~ ^[0-9]+$ || "${cols}" -lt 20 ]]; then
    cols=80
  fi
  echo "${cols}"
}

term_rows() {
  local rows=""
  if command -v tput >/dev/null 2>&1; then
    rows="$(tput lines 2>/dev/null || true)"
  fi
  if [[ -z "${rows}" || ! "${rows}" =~ ^[0-9]+$ || "${rows}" -lt 10 ]]; then
    rows="${LINES:-24}"
  fi
  if [[ ! "${rows}" =~ ^[0-9]+$ || "${rows}" -lt 10 ]]; then
    rows=24
  fi
  echo "${rows}"
}

print_centered_line() {
  local cols="$1"
  local line="$2"
  local width visible
  # Strip ANSI escape sequences before measuring so coloured lines still
  # centre correctly. Without this, an 8-char "\033[1;32m...\033[0m" wrap
  # adds 12 phantom columns and the wordmark drifts left.
  visible="$(printf '%s' "${line}" | sed -E 's/\x1b\[[0-9;]*m//g')"
  width="$(printf '%s' "${visible}" | wc -m | tr -d ' ')"
  local pad=0
  if (( cols > width )); then
    pad=$(( (cols - width) / 2 ))
  fi
  printf "%*s%s\n" "${pad}" "" "${line}"
}

print_install_banner() {
  local cols rows top_pad i
  cols="$(term_cols)"
  rows="$(term_rows)"

  local platform_line
  local os_lower
  os_lower="$(printf '%s' "${OS_TYPE}" | tr '[:upper:]' '[:lower:]')"
  platform_line="$(printf "%s %s  |  kernel %s%s" "${os_lower}" "${ARCH}" "${KERNEL}" "${DISTRO:+  |  ${DISTRO}}")"

  # ANSI green for retro-terminal feel; gated on isatty to keep CI logs clean.
  local g='' d=''
  if [[ -t 1 ]]; then
    g=$'\033[1;32m'
    d=$'\033[0m'
  fi

  # Retro-game wordmark — ASCII-only (no unicode/box-drawing) so it renders
  # the same on every terminal, including journald and curl|bash pipes.
  local banner_lines=(
"${g}================================================================================${d}"
"${g} ___ _   _ _   _ _____ ____   __        ___    ____  ____  _____ _   _ ${d}"
"${g}|_ _| \\ | | \\ | | ____|  _ \\  \\ \\      / / \\  |  _ \\|  _ \\| ____| \\ | |${d}"
"${g} | ||  \\| |  \\| |  _| | |_) |  \\ \\ /\\ / / _ \\ | |_) | | | |  _| |  \\| |${d}"
"${g} | || |\\  | |\\  | |___|  _ <    \\ V  V / ___ \\|  _ <| |_| | |___| |\\  |${d}"
"${g}|___|_| \\_|_| \\_|_____|_| \\_\\    \\_/\\_/_/   \\_\\_| \\_\\____/|_____|_| \\_|${d}"
"${g}================================================================================${d}"
""
"your server's immune system  ::  installer"
"${platform_line}"
  )

  if [[ -t 1 ]]; then
    printf '\033[2J\033[H'
  fi

  top_pad=1
  if (( rows > ${#banner_lines[@]} + 2 )); then
    top_pad=$(( (rows - ${#banner_lines[@]}) / 2 ))
  fi

  for ((i = 0; i < top_pad; i++)); do
    echo ""
  done

  for line in "${banner_lines[@]}"; do
    print_centered_line "${cols}" "${line}"
  done
  echo ""
}

run_simulated_setup_flow() {
  echo "  [SIMULATION] No files will be written. No services will be changed."
  echo "  [SIMULATION] Running setup flow in dry-run mode (${SIMULATE_MODE})."
  echo ""

  if command -v innerwarden >/dev/null 2>&1; then
    innerwarden setup --dry-run --mode "${SIMULATE_MODE}"
  else
    echo "  [SIMULATION] innerwarden binary not found."
    echo "  [SIMULATION] Run the installer without --simulate first, then:"
    echo "    innerwarden setup --dry-run --mode ${SIMULATE_MODE}"
  fi
  return 0
}

# ── Banner (only after sudo, so it shows once) ──────────────────────────
print_install_banner

if [[ "$OS_TYPE" != "Linux" && "$OS_TYPE" != "Darwin" ]]; then
  fail "this installer supports Linux and macOS (Darwin) hosts only"
fi

if [[ "${SIMULATE}" -eq 1 ]]; then
  run_simulated_setup_flow
  exit 0
fi

if [[ "$OS_TYPE" != "Darwin" ]]; then
  if ! command -v systemctl >/dev/null 2>&1; then
    fail "systemctl not found; this installer requires systemd on Linux"
  fi
fi

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  fail "sudo not found and current user is not root"
fi

run_root() {
  if [[ -n "${SUDO}" ]]; then
    "${SUDO}" "$@"
  else
    "$@"
  fi
}

backup_if_exists() {
  local path="$1"
  if run_root test -f "$path"; then
    local backup
    backup="${path}.bak.$(date +%Y%m%d%H%M%S)"
    run_root cp "$path" "$backup"
    log "backup created: ${backup}"
  fi
}

install_from_stdin() {
  local target="$1"
  local mode="$2"
  local owner="$3"
  local group="$4"

  local tmp
  tmp="$(mktemp)"
  cat > "${tmp}"

  backup_if_exists "${target}"
  run_root install -o "${owner}" -g "${group}" -m "${mode}" "${tmp}" "${target}"
  rm -f "${tmp}"
}

# AI provider is optional - can be configured after install.
# Supported: openai (cloud), anthropic (cloud), ollama (local, no key needed).
OPENAI_API_KEY="${OPENAI_API_KEY:-}"
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"
AI_ENABLED="false"
AI_PROVIDER="openai"
AI_MODEL="gpt-4o-mini"

if [[ -n "${OPENAI_API_KEY}" ]]; then
  AI_ENABLED="true"
  AI_PROVIDER="openai"
  AI_MODEL="gpt-4o-mini"
elif [[ -n "${ANTHROPIC_API_KEY}" ]]; then
  AI_ENABLED="true"
  AI_PROVIDER="anthropic"
  AI_MODEL="claude-haiku-4-5-20251001"
fi

ENABLE_EXEC_AUDIT="${INNERWARDEN_ENABLE_EXEC_AUDIT:-}"
ENABLE_EXEC_AUDIT_TTY="${INNERWARDEN_ENABLE_EXEC_AUDIT_TTY:-}"

if [[ -z "${ENABLE_EXEC_AUDIT}" ]]; then
  if [[ "${OS_TYPE}" == "Linux" ]]; then
    ENABLE_EXEC_AUDIT="true"
  else
    ENABLE_EXEC_AUDIT="false"
  fi
fi

ENABLE_EXEC_AUDIT="$(normalize_bool "${ENABLE_EXEC_AUDIT:-false}")"

if [[ "${ENABLE_EXEC_AUDIT}" == "true" ]]; then
  ENABLE_EXEC_AUDIT_TTY="$(normalize_bool "${ENABLE_EXEC_AUDIT_TTY:-false}")"
else
  ENABLE_EXEC_AUDIT_TTY="false"
fi

BUILD_FROM_SOURCE="${INNERWARDEN_BUILD_FROM_SOURCE:-0}"

# ── Detect architecture ──────────────────────────────────────────────────────
detect_arch() {
  case "$(uname -m)" in
    x86_64)        echo "x86_64"  ;;
    aarch64|arm64) echo "aarch64" ;;
    *)
      ISSUE_URL="https://github.com/InnerWarden/innerwarden/issues/new?template=platform_support.yml&title=Platform+support+request:+$(uname -m)+on+$(uname -s)&labels=platform-support"
      echo ""
      echo "  Your platform ($(uname -m) on $(uname -s)) is not yet supported by pre-built binaries."
      echo "  Please request support here (takes 30 seconds):"
      echo "  $ISSUE_URL"
      echo ""
      echo "  To build from source instead: INNERWARDEN_BUILD_FROM_SOURCE=1 bash install.sh"
      fail "unsupported architecture: $(uname -m)"
      ;;
  esac
}

# ── Detect OS platform prefix for asset names ─────────────────────────────────
detect_platform() {
  case "$OS_TYPE" in
    Darwin) echo "macos" ;;
    *)      echo "linux" ;;
  esac
}

# ── Spec 048 — Ed25519 release public key (PEM, embedded inline) ─────────────
#
# Same key as crates/ctl/src/upgrade.rs::RELEASE_PUBLIC_KEY_B64. The DER
# prefix `MCowBQYDK2VwAyEA` is the standard Ed25519 SubjectPublicKeyInfo
# header (12 bytes = `30 2a 30 05 06 03 2b 65 70 03 21 00`); appending the
# 32-byte raw key gives a valid PEM that openssl pkeyutl can verify.
#
# SHA-256 of the raw 32-byte key (operator-facing fingerprint):
#   9cba21f2d6a45e7f58edd9b840e152b5c7d0ee6e511bb6835037088c6a89143f
#
# Documented at /docs/supply-chain-security.md and on the public release
# page. Rotating this key requires a coordinated installer + ctl release.
INNERWARDEN_RELEASE_PEM=$'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAyf58o+MQluj7MwTlW+hB9tfLQk9df0iUeGxPbmAIFM8=\n-----END PUBLIC KEY-----\n'

# ── Spec 048 — check that openssl can verify Ed25519 signatures ──────────────
#
# Ed25519 in `openssl pkeyutl -verify -rawin` requires openssl >= 3.0.
# Ubuntu 22.04+, Rocky 9+, Fedora 36+, Debian 12+ all have it. Older
# distros (Ubuntu 20.04 stock 1.1.x) hit this precondition and get a
# clear actionable error instead of silently falling back to SHA-only.
check_openssl_ed25519_support() {
  if ! command -v openssl >/dev/null 2>&1; then
    return 1
  fi
  # `openssl version` prints e.g. `OpenSSL 3.0.2 15 Mar 2022`.
  # We only accept 3.x or LibreSSL >= 3.5 (untested but plausible).
  local v
  v="$(openssl version 2>/dev/null | awk '{print $2}')"
  case "$v" in
    3.*) return 0 ;;
    *)   return 1 ;;
  esac
}

# ── Spec 048 — verify Ed25519 signature for a binary ─────────────────────────
#
# Args: binary_path, sig_b64_string
# Returns 0 on valid signature, non-zero otherwise.
#
# IMPORTANT: the release workflow signs SHA-256(binary), NOT the raw
# binary. See `.github/workflows/release.yml` (the signing step uses
# `key.sign(hashlib.sha256(...).digest())`) and `crates/ctl/src/upgrade.rs::verify_signature`
# (which calls `verifying_key.verify(&Sha256::digest(binary_bytes), &sig)`).
# Verification has to mirror that — feed the 32-byte digest to openssl,
# NOT the binary itself. Caught by CodeRabbit on PR #512 review;
# pre-fix the installer would have rejected every valid stable
# signature.
#
# Uses openssl pkeyutl with -rawin (Ed25519 native pure-EdDSA mode).
# .sig files on releases are base64-encoded raw 64-byte Ed25519 sigs;
# we base64-decode then feed as binary.
verify_ed25519_signature() {
  local binary="$1"
  local sig_b64="$2"
  local tmp_pem tmp_sig tmp_digest
  tmp_pem="$(mktemp)" || return 1
  tmp_sig="$(mktemp)" || { rm -f "$tmp_pem"; return 1; }
  tmp_digest="$(mktemp)" || { rm -f "$tmp_pem" "$tmp_sig"; return 1; }
  printf '%s' "$INNERWARDEN_RELEASE_PEM" > "$tmp_pem"
  printf '%s' "$sig_b64" | base64 -d > "$tmp_sig" 2>/dev/null || {
    rm -f "$tmp_pem" "$tmp_sig" "$tmp_digest"
    return 1
  }
  # Compute SHA-256(binary) → 32 raw bytes. openssl is already
  # required (we just used it via pkeyutl), so use openssl dgst
  # rather than depending on `xxd` (not always present on minimal
  # images) or platform-specific `sha256sum` vs `shasum`.
  if ! openssl dgst -sha256 -binary "$binary" > "$tmp_digest" 2>/dev/null; then
    rm -f "$tmp_pem" "$tmp_sig" "$tmp_digest"
    return 1
  fi
  if openssl pkeyutl -verify -pubin -inkey "$tmp_pem" \
      -rawin -in "$tmp_digest" -sigfile "$tmp_sig" >/dev/null 2>&1; then
    rm -f "$tmp_pem" "$tmp_sig" "$tmp_digest"
    return 0
  fi
  rm -f "$tmp_pem" "$tmp_sig" "$tmp_digest"
  return 1
}

# ── Download a binary from GitHub Releases and validate its SHA-256 ──────────
download_asset() {
  local binary="$1"    # e.g. innerwarden-sensor
  local dest="$2"      # destination file path
  local version="$3"   # e.g. v0.2.0
  local arch="$4"      # x86_64 | aarch64
  local platform="$5"  # linux | macos

  local asset="${binary}-${platform}-${arch}"
  local base_url="https://github.com/${GITHUB_REPO}/releases/download/${version}"

  if [[ "${VERBOSE}" -eq 1 ]]; then
    log "Downloading ${asset}..."
  fi
  if ! curl -fsSL --output "${dest}" "${base_url}/${asset}"; then
    fail "Download failed: ${asset}. The release may not exist yet.\nTry: curl -fsSL https://innerwarden.com/install | bash   (stable version)"
  fi
  # Verify file is not empty
  if [[ ! -s "${dest}" ]]; then
    fail "Downloaded file is empty: ${asset}. The release may be corrupted."
  fi

  local sha_tmpfile
  sha_tmpfile="$(mktemp)" || fail "failed to create secure temporary file"
  trap 'rm -f "${sha_tmpfile}"' RETURN
  if curl -fsSL "${base_url}/${asset}.sha256" | awk '{print $1}' > "${sha_tmpfile}" 2>/dev/null; then
    local expected actual
    expected="$(cat "${sha_tmpfile}")"
    # Use shasum on macOS, sha256sum on Linux
    if command -v sha256sum >/dev/null 2>&1; then
      actual="$(sha256sum "${dest}" | awk '{print $1}')"
    else
      actual="$(shasum -a 256 "${dest}" | awk '{print $1}')"
    fi
    rm -f "${sha_tmpfile}"
    if [[ "${expected}" != "${actual}" ]]; then
      fail "SHA-256 mismatch for ${asset}:\n  expected: ${expected}\n  got:      ${actual}"
    fi
    log "SHA-256 ok"
  else
    rm -f "${sha_tmpfile}"
    log "warning: no SHA-256 sidecar for ${asset} - skipping integrity check"
  fi

  # Spec 048 — Ed25519 signature verification (fail-closed for stable).
  # Pre-Spec-048 the installer claimed "signed binary" without verifying
  # signatures; this branch closes the gap. Stable: signature MUST verify.
  # Canary: signature is best-effort because canary signing infrastructure
  # is not yet in place. Override via env vars (deliberately scary names).
  if [[ "${INNERWARDEN_INSECURE_SKIP_SIG_VERIFY:-0}" == "1" ]]; then
    log "WARN: INNERWARDEN_INSECURE_SKIP_SIG_VERIFY=1 — bypassing Ed25519 signature check for ${asset}"
    log "  This defeats supply-chain verification. Only use during emergency migration."
    return 0
  fi
  local sig_tmpfile
  sig_tmpfile="$(mktemp)" || fail "failed to create temp file for sig"
  if curl -fsSL "${base_url}/${asset}.sig" -o "${sig_tmpfile}" 2>/dev/null && [[ -s "${sig_tmpfile}" ]]; then
    if ! check_openssl_ed25519_support; then
      rm -f "${sig_tmpfile}"
      fail "openssl >= 3.0 is required to verify Ed25519 signatures.\n  Detected: $(openssl version 2>/dev/null || echo 'openssl missing')\n  On Ubuntu 20.04, upgrade to 22.04+ or set INNERWARDEN_INSECURE_SKIP_SIG_VERIFY=1 (not recommended).\n  See https://github.com/${GITHUB_REPO}/blob/main/docs/supply-chain-security.md"
    fi
    local sig_b64
    sig_b64="$(cat "${sig_tmpfile}")"
    rm -f "${sig_tmpfile}"
    if verify_ed25519_signature "${dest}" "${sig_b64}"; then
      log "Ed25519 signature ok"
    else
      fail "Ed25519 signature verification FAILED for ${asset}.\n  This means the binary or signature was tampered with, or the release was published with a different key.\n  Expected key fingerprint: 9cba21f2...c6a89143f\n  See https://github.com/${GITHUB_REPO}/blob/main/docs/supply-chain-security.md"
    fi
  else
    rm -f "${sig_tmpfile}"
    if [[ "${version}" == "canary" ]]; then
      if [[ "${INNERWARDEN_ALLOW_UNSIGNED_CANARY:-0}" == "1" ]]; then
        log "WARN: canary release has no .sig for ${asset} — proceeding because INNERWARDEN_ALLOW_UNSIGNED_CANARY=1"
      else
        fail "canary release has no .sig for ${asset}.\n  Canary signing is on the spec 048 follow-up roadmap.\n  Set INNERWARDEN_ALLOW_UNSIGNED_CANARY=1 to proceed (not recommended)."
      fi
    else
      fail "stable release ${version} has no .sig for ${asset}.\n  Spec 048 requires every stable release to ship Ed25519 signatures.\n  If you are migrating from a pre-spec-048 release, set INNERWARDEN_INSECURE_SKIP_SIG_VERIFY=1 (not recommended; logged as a deliberate override).\n  See https://github.com/${GITHUB_REPO}/blob/main/docs/supply-chain-security.md"
    fi
  fi
}

if [[ "${BUILD_FROM_SOURCE}" == "1" ]]; then
  # ── Build from source (development / unsupported arch) ──────────────────
  # Same curl|bash safety fallback as SCRIPT_DIR above (BASH_SOURCE[0] unset).
  ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"
  if ! command -v cargo >/dev/null 2>&1; then
    log "cargo not found. Installing rustup (user install)..."
    curl -sSf https://sh.rustup.rs | sh -s -- -y
  fi
  # shellcheck disable=SC1090
  source "${HOME}/.cargo/env"
  log "ensuring stable Rust toolchain..."
  rustup toolchain install stable >/dev/null
  rustup default stable >/dev/null
  cd "${ROOT_DIR}"
  log "building innerwarden-sensor + innerwarden-agent + innerwarden-ctl (release)..."
  cargo build --release -p innerwarden-sensor -p innerwarden-agent -p innerwarden-ctl
  IW_SENSOR_BIN="${ROOT_DIR}/target/release/innerwarden-sensor"
  IW_AGENT_BIN="${ROOT_DIR}/target/release/innerwarden-agent"
  IW_CTL_BIN="${ROOT_DIR}/target/release/innerwarden-ctl"
  if [[ "${SUPERVISED}" == "true" ]]; then
    log "building innerwarden-supervisor (release)..."
    cargo build --release -p innerwarden-supervisor
    IW_SUPERVISOR_BIN="${ROOT_DIR}/target/release/innerwarden-supervisor"
  fi
else
  # ── Download pre-built binaries from GitHub Releases (~10 s) ────────────
  if ! command -v curl >/dev/null 2>&1; then
    fail "curl is required to download binaries (apt install curl / brew install curl)"
  fi
  # Require sha256sum (Linux) or shasum (macOS)
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    fail "sha256sum or shasum is required for integrity checks"
  fi

  ARCH="$(detect_arch)"
  PLATFORM="$(detect_platform)"

  # Resolve version: canary, env override, or latest stable
  if [[ "${CANARY}" -eq 1 ]]; then
    # Check if canary release actually exists
    if curl -fsSL -o /dev/null "https://github.com/${GITHUB_REPO}/releases/download/canary/innerwarden-sensor-linux-x86_64" 2>/dev/null; then
      IW_VERSION="canary"
      log "Using canary channel (develop branch)"
    else
      echo "  ⚠ Canary build not ready yet. Installing latest stable instead."
      echo ""
      CANARY=0
    fi
  fi
  if [[ "${CANARY}" -eq 0 ]] && [[ -n "${INNERWARDEN_VERSION:-}" ]]; then
    IW_VERSION="${INNERWARDEN_VERSION}"
  else
    log "Fetching latest stable release..."
    IW_VERSION="$(curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      "${GITHUB_API}/releases/latest" \
      | grep '"tag_name"' | head -1 \
      | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    [[ -n "${IW_VERSION}" ]] || fail "could not determine latest release version from GitHub API"
  fi

  if [[ "${VERBOSE}" -eq 1 ]]; then
    log "Version: ${IW_VERSION} (${PLATFORM}/${ARCH})"
  fi

  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT

  download_asset "innerwarden-sensor" "${TMP_DIR}/innerwarden-sensor" "${IW_VERSION}" "${ARCH}" "${PLATFORM}"
  download_asset "innerwarden-agent"  "${TMP_DIR}/innerwarden-agent"  "${IW_VERSION}" "${ARCH}" "${PLATFORM}"
  download_asset "innerwarden-ctl"    "${TMP_DIR}/innerwarden-ctl"    "${IW_VERSION}" "${ARCH}" "${PLATFORM}"

  IW_SENSOR_BIN="${TMP_DIR}/innerwarden-sensor"
  IW_AGENT_BIN="${TMP_DIR}/innerwarden-agent"
  IW_CTL_BIN="${TMP_DIR}/innerwarden-ctl"
fi

if [[ "$OS_TYPE" == "Darwin" ]]; then
  # macOS: create group via dscl if it doesn't exist
  if ! dscl . list /Groups PrimaryGroupID | grep -w "${IW_USER}" >/dev/null 2>&1; then
    log "creating service group: ${IW_USER}"
    # Find an unused GID in the system range
    NEXT_GID=300
    while dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | grep -q "^${NEXT_GID}$"; do
      NEXT_GID=$((NEXT_GID + 1))
    done
    run_root dscl . -create /Groups/"${IW_USER}"
    run_root dscl . -create /Groups/"${IW_USER}" RealName "Inner Warden"
    run_root dscl . -create /Groups/"${IW_USER}" PrimaryGroupID "${NEXT_GID}"
  else
    # Group exists — resolve its GID for user creation below
    NEXT_GID=$(dscl . -read /Groups/"${IW_USER}" PrimaryGroupID | awk '{print $2}')
  fi
  # macOS: create user via dscl if it doesn't exist
  if ! id "${IW_USER}" >/dev/null 2>&1; then
    log "creating service user: ${IW_USER}"
    # Find an unused UID in the system range
    NEXT_UID=300
    while dscl . -list /Users UniqueID | awk '{print $2}' | grep -q "^${NEXT_UID}$"; do
      NEXT_UID=$((NEXT_UID + 1))
    done
    run_root dscl . -create /Users/"${IW_USER}"
    run_root dscl . -create /Users/"${IW_USER}" UserShell /usr/bin/false
    run_root dscl . -create /Users/"${IW_USER}" RealName "Inner Warden"
    run_root dscl . -create /Users/"${IW_USER}" UniqueID "${NEXT_UID}"
    run_root dscl . -create /Users/"${IW_USER}" PrimaryGroupID "${NEXT_GID}"
    run_root dscl . -create /Users/"${IW_USER}" NFSHomeDirectory /var/empty
  fi
  # macOS: add user to group via dscl if it doesn't exist
  if ! dscl . read /Groups/"${IW_USER}" GroupMembership 2>/dev/null | grep -w "${IW_USER}" >/dev/null 2>&1; then
    run_root dscl . append /Groups/"${IW_USER}" GroupMembership "${IW_USER}"
  fi
  run_root mkdir -p "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
  run_root chown "${INSTALL_USER:-root}":"${IW_USER}" "${CONFIG_DIR}"
  run_root chmod 750 "${CONFIG_DIR}"
  run_root chown "${IW_USER}:${IW_USER}" "${DATA_DIR}"
  run_root chmod 750 "${DATA_DIR}"
  run_root chown "${IW_USER}:${IW_USER}" "${LOG_DIR}"
  run_root chmod 750 "${LOG_DIR}"
else
  NOLOGIN_BIN="$(command -v nologin || echo /usr/sbin/nologin)"
  if ! id "${IW_USER}" >/dev/null 2>&1; then
    log "creating service user: ${IW_USER}"
    run_root useradd -r -s "${NOLOGIN_BIN}" "${IW_USER}"
  fi

  for grp in adm systemd-journal docker audit; do
    if getent group "${grp}" >/dev/null 2>&1; then
      run_root usermod -aG "${grp}" "${IW_USER}"
    fi
  done

  run_root mkdir -p "${CONFIG_DIR}" "${DATA_DIR}"
  # Allow the service user to traverse/read config files without making them world-readable.
  run_root chown "${INSTALL_USER:-root}":"${IW_USER}" "${CONFIG_DIR}"
  run_root chmod 750 "${CONFIG_DIR}"
  run_root chown "${IW_USER}:${IW_USER}" "${DATA_DIR}"
  run_root chmod 750 "${DATA_DIR}"
fi

log "installing binaries to ${BIN_DIR}"
run_root install -o "${INSTALL_USER:-root}" -g "${INSTALL_GROUP:-root}" -m 755 "${IW_SENSOR_BIN}" "${SENSOR_BIN}"
run_root install -o "${INSTALL_USER:-root}" -g "${INSTALL_GROUP:-root}" -m 755 "${IW_AGENT_BIN}"  "${AGENT_BIN}"
run_root install -o "${INSTALL_USER:-root}" -g "${INSTALL_GROUP:-root}" -m 755 "${IW_CTL_BIN}"    "${BIN_DIR}/innerwarden-ctl"
run_root install -o "${INSTALL_USER:-root}" -g "${INSTALL_GROUP:-root}" -m 755 "${IW_CTL_BIN}"    "${BIN_DIR}/innerwarden"

# ── Drop the install-facing agent guide (spec 082) ───────────────────────
# /etc/innerwarden/AGENTS.md is the playbook an AI coding agent reads to
# configure and operate InnerWarden on this box (what the CLI is, the safe
# observe->verify->allowlist workflow, the loopback check-command contract).
# Best-effort and version-matched: fetched at the SAME ref we are installing
# (raw repo content at the release tag), so the on-box guide matches the
# binary's command surface. Never fails the install if it cannot be fetched.
AGENTS_MD_DEST="${CONFIG_DIR}/AGENTS.md"
agents_md_tmp="${TMP_DIR}/AGENTS.md"
agents_md_path="agents-install.md"
agents_md_ok=0
for ref in "${IW_VERSION}" "main"; do
  [[ -z "${ref}" || "${ref}" == "canary" ]] && ref="main"
  if curl -fsSL --output "${agents_md_tmp}" \
       "https://raw.githubusercontent.com/${GITHUB_REPO}/${ref}/${agents_md_path}" 2>/dev/null \
       && [[ -s "${agents_md_tmp}" ]]; then
    agents_md_ok=1
    break
  fi
done
if [[ "${agents_md_ok}" == "1" ]]; then
  run_root install -o "${INSTALL_USER:-root}" -g "${IW_USER}" -m 644 "${agents_md_tmp}" "${AGENTS_MD_DEST}"
  log "agent guide installed: ${AGENTS_MD_DEST} (point your coding agent at it)"
else
  log "note: could not fetch the agent guide; see https://innerwarden.com/agents.md"
fi

# ── Install bpftool for eBPF support (Linux only) ────────────────────────
# bpftool is required for XDP firewall and LSM enforcement management.
# The sensor works without it (graceful fallback) but advanced features need it.
if [[ "$OS_TYPE" == "Linux" ]]; then
  if ! command -v bpftool >/dev/null 2>&1; then
    log "installing bpftool for eBPF support..."
    if command -v apt-get >/dev/null 2>&1; then
      run_root apt-get install -y -qq linux-tools-common linux-tools-"$(uname -r)" 2>/dev/null \
        || run_root apt-get install -y -qq bpftool 2>/dev/null \
        || log "warning: could not install bpftool (XDP/LSM management unavailable)"
    elif command -v dnf >/dev/null 2>&1; then
      run_root dnf install -y -q bpftool 2>/dev/null \
        || log "warning: could not install bpftool (XDP/LSM management unavailable)"
    elif command -v yum >/dev/null 2>&1; then
      run_root yum install -y -q bpftool 2>/dev/null \
        || log "warning: could not install bpftool (XDP/LSM management unavailable)"
    else
      log "warning: could not detect package manager - install bpftool manually for XDP/LSM support"
    fi
  fi
  if command -v bpftool >/dev/null 2>&1; then
    log "bpftool available: $(bpftool version 2>/dev/null | head -1)"
  fi
fi

HOST_ID="$(hostname -f 2>/dev/null || hostname)"

# ── Preserve existing configs on upgrade ──────────────────────────────────
# If config files already exist, this is an upgrade - skip overwriting.
# Only binaries and systemd units are updated.
EXISTING_INSTALL=false
if [[ -f "${SENSOR_CONFIG}" && -f "${AGENT_CONFIG}" ]]; then
  EXISTING_INSTALL=true
  BAKSUFFIX="$(date +%Y%m%d%H%M%S)"
  log "existing installation detected - preserving configs"
  run_root cp "${SENSOR_CONFIG}" "${SENSOR_CONFIG}.bak.${BAKSUFFIX}"
  log "backup created: ${SENSOR_CONFIG}.bak.${BAKSUFFIX}"
  run_root cp "${AGENT_CONFIG}" "${AGENT_CONFIG}.bak.${BAKSUFFIX}"
  log "backup created: ${AGENT_CONFIG}.bak.${BAKSUFFIX}"
  if [ -f "${AGENT_ENV}" ]; then
    run_root cp "${AGENT_ENV}" "${AGENT_ENV}.bak.${BAKSUFFIX}"
    log "backup created: ${AGENT_ENV}.bak.${BAKSUFFIX}"
  fi
fi

if [[ "${EXISTING_INSTALL}" == "true" ]]; then
  log "configs preserved - skipping config overwrite (upgrade mode)"
else
log "writing sensor config: ${SENSOR_CONFIG}"
if [[ "$OS_TYPE" == "Darwin" ]]; then
  install_from_stdin "${SENSOR_CONFIG}" 640 "${INSTALL_USER:-root}" "${IW_USER}" <<EOF
[agent]
host_id = "${HOST_ID}"

[output]
data_dir = "${DATA_DIR}"
write_events = true

[collectors.auth_log]
enabled = false

[collectors.macos_log]
enabled = true

[collectors.journald]
enabled = false

[collectors.exec_audit]
enabled = false
path = "/var/log/audit/audit.log"
include_tty = false

[collectors.docker]
enabled = false

[collectors.integrity]
enabled = true
poll_seconds = 60
paths = ["/etc/ssh/sshd_config", "/etc/sudoers"]

[detectors.ssh_bruteforce]
enabled = true
threshold = 8
window_seconds = 300

[detectors.sudo_abuse]
enabled = false
threshold = 3
window_seconds = 300
EOF
else
  install_from_stdin "${SENSOR_CONFIG}" 640 "${INSTALL_USER:-root}" "${IW_USER}" <<EOF
[agent]
host_id = "${HOST_ID}"

[output]
data_dir = "${DATA_DIR}"
write_events = true

[collectors.auth_log]
enabled = true
path = "/var/log/auth.log"

[collectors.journald]
enabled = true
units = ["sshd", "sudo"]

[collectors.exec_audit]
enabled = ${ENABLE_EXEC_AUDIT}
path = "/var/log/audit/audit.log"
include_tty = ${ENABLE_EXEC_AUDIT_TTY}

[collectors.docker]
enabled = false

[collectors.integrity]
enabled = true
poll_seconds = 60
paths = ["/etc/ssh/sshd_config", "/etc/sudoers"]

[detectors.ssh_bruteforce]
enabled = true
threshold = 8
window_seconds = 300

[detectors.sudo_abuse]
enabled = false
threshold = 3
window_seconds = 300
EOF
fi

if [[ "${ENABLE_EXEC_AUDIT}" == "true" ]]; then
  log "shell command audit enabled (include_tty=${ENABLE_EXEC_AUDIT_TTY})"
  # 2026-05-25: auto-install auditd when missing. Pre-fix the entire
  # exec_audit block was skipped silently if /etc/audit/rules.d did not
  # exist, leaving the operator's shell-command trail blind on every
  # fresh Linux box (auditd is NOT installed by default on Ubuntu cloud
  # images). The installation is conservative — apt / dnf only, no
  # auto-enable; we just put the package on disk so the rules file can
  # be written and `augenrules --load` can succeed.
  if ! run_root test -d /etc/audit/rules.d; then
    if command -v apt-get >/dev/null 2>&1; then
      log "auditd not present; installing via apt-get"
      DEBIAN_FRONTEND=noninteractive run_root apt-get install -y auditd >/dev/null 2>&1 \
        || log "WARNING: apt-get install auditd failed; exec audit will remain disabled"
    elif command -v dnf >/dev/null 2>&1; then
      log "auditd not present; installing via dnf"
      run_root dnf install -y audit >/dev/null 2>&1 \
        || log "WARNING: dnf install audit failed; exec audit will remain disabled"
    elif command -v yum >/dev/null 2>&1; then
      log "auditd not present; installing via yum"
      run_root yum install -y audit >/dev/null 2>&1 \
        || log "WARNING: yum install audit failed; exec audit will remain disabled"
    else
      log "WARNING: no supported package manager (apt-get / dnf / yum) found; auditd cannot be auto-installed"
    fi
    if run_root systemctl enable --now auditd >/dev/null 2>&1; then
      log "auditd service enabled and started"
    fi
  fi
  if run_root test -d /etc/audit/rules.d; then
    log "writing auditd rules: ${AUDIT_RULE_FILE}"
    install_from_stdin "${AUDIT_RULE_FILE}" 640 "${INSTALL_USER:-root}" "${INSTALL_GROUP:-root}" <<'EOF'
# Inner Warden shell command trail (installed with explicit consent)
-a always,exit -F arch=b64 -S execve -k innerwarden-shell-exec
-a always,exit -F arch=b32 -S execve -k innerwarden-shell-exec
EOF
    if command -v augenrules >/dev/null 2>&1; then
      if run_root augenrules --load >/dev/null 2>&1; then
        log "auditd rules loaded via augenrules"
      else
        log "WARNING: failed to load auditd rules via augenrules"
      fi
    elif command -v auditctl >/dev/null 2>&1; then
      if run_root auditctl -R "${AUDIT_RULE_FILE}" >/dev/null 2>&1; then
        log "auditd rules loaded via auditctl"
      else
        log "WARNING: failed to load auditd rules via auditctl"
      fi
    else
      log "WARNING: augenrules/auditctl not found; exec trail may remain disabled until auditd is configured"
    fi
  else
    log "WARNING: /etc/audit/rules.d not found; cannot install exec audit rules automatically"
  fi

  if [[ "${ENABLE_EXEC_AUDIT_TTY}" == "true" ]]; then
    log "TTY ingestion enabled in sensor config; host must emit auditd type=TTY records (e.g. via pam_tty_audit policy)"
  fi
fi

# Detect the host firewall backend so block-ip works out of the box on
# any distro: Rocky/RHEL/CentOS/Fedora ship firewalld (no ufw), so the
# old hardcoded `block_backend = "ufw"` meant a fresh install there could
# detect but never block. Order favours the distro-native, persistence-
# capable tool. The responder still ships disabled + dry_run (monitor-only
# default), so this only picks WHICH backend activates when the operator
# turns response on.
detect_block_backend() {
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    echo firewalld
  elif command -v ufw >/dev/null 2>&1; then
    echo ufw
  elif command -v nft >/dev/null 2>&1; then
    echo nftables
  elif command -v iptables >/dev/null 2>&1; then
    echo iptables
  else
    echo ufw  # nothing detected; keep the historical default
  fi
}
BLOCK_BACKEND="$(detect_block_backend)"
BLOCK_SKILL="block-ip-${BLOCK_BACKEND}"
log "detected firewall backend for block-ip: ${BLOCK_BACKEND}"

log "writing agent config: ${AGENT_CONFIG}"
# Wave 8d (2026-05-04): agent.toml carries API keys (OpenAI / Anthropic /
# Telegram bot tokens / AbuseIPDB) so it must NOT be group-readable on
# multi-tenant hosts. Owner is the agent's own service user (not root)
# so that `chmod 600` works without breaking the agent on next restart.
# Pre-fix: owner=root group=innerwarden mode=640. Operators following
# the agent's own "consider chmod 600" WARN naively then made the file
# unreadable by the agent process. See `crates/agent/src/config.rs`
# loader for the matching warning text.
install_from_stdin "${AGENT_CONFIG}" 600 "${IW_USER}" "${IW_USER}" <<EOF
[narrative]
enabled = true
keep_days = 7

[webhook]
enabled = false

[ai]
enabled = ${AI_ENABLED}
provider = "${AI_PROVIDER}"
model = "${AI_MODEL}"
context_events = 20
# confidence_threshold: minimum AI confidence (0.0-1.0) for auto-execution.
# Trial safety comes from [responder] enabled = false below, NOT from this
# value. The agent clamps any threshold > 1.0 back to the 0.85 default on load
# (a >1.0 "never executes" sentinel once silently disabled ALL autonomous
# response, because AI confidence is always in [0.0, 1.0]).
confidence_threshold = 0.85
incident_poll_secs = 2
# base_url = "http://localhost:11434"  # Ollama only - override endpoint

[honeypot]
mode = "demo"
bind_addr = "127.0.0.1"
port = 2222
http_port = 8080
duration_secs = 300
services = ["ssh"]
strict_target_only = true
allow_public_listener = false
max_connections = 64
max_payload_bytes = 512
isolation_profile = "strict_local"
require_high_ports = true
forensics_keep_days = 7
forensics_max_total_mb = 128
transcript_preview_bytes = 96
lock_stale_secs = 1800

[honeypot.sandbox]
enabled = false
runner_path = ""
clear_env = true

[honeypot.pcap_handoff]
enabled = false
timeout_secs = 15
max_packets = 120

[honeypot.containment]
mode = "process"
require_success = false
namespace_runner = "unshare"
namespace_args = ["--fork", "--pid", "--mount-proc"]
jail_runner = "bwrap"
jail_args = []
jail_profile = "standard"
allow_namespace_fallback = true

[honeypot.external_handoff]
enabled = false
command = "/usr/local/bin/iw-handoff"
args = ["--session-id", "{session_id}", "--target", "{target_ip}", "--metadata", "{metadata_path}", "--evidence", "{evidence_path}", "--pcap", "{pcap_path}"]
timeout_secs = 20
require_success = false
clear_env = true
allowed_commands = ["/usr/local/bin/iw-handoff"]
enforce_allowlist = false
signature_enabled = false
signature_key_env = "INNERWARDEN_HANDOFF_SIGNING_KEY"
attestation_enabled = false
attestation_key_env = "INNERWARDEN_HANDOFF_ATTESTATION_KEY"
attestation_prefix = "IW_ATTEST"
attestation_expected_receiver = ""

[honeypot.redirect]
enabled = false
backend = "iptables"

[responder]
enabled = false
dry_run = true
block_backend = "${BLOCK_BACKEND}"
allowed_skills = ["${BLOCK_SKILL}"]
EOF

log "writing environment file: ${AGENT_ENV}"
tmp_env="$(mktemp)"
if [[ -n "${OPENAI_API_KEY}" ]]; then
  printf 'OPENAI_API_KEY=%s\n' "${OPENAI_API_KEY}" > "${tmp_env}"
elif [[ -n "${ANTHROPIC_API_KEY}" ]]; then
  printf 'ANTHROPIC_API_KEY=%s\n' "${ANTHROPIC_API_KEY}" > "${tmp_env}"
else
  cat > "${tmp_env}" <<'ENVEOF'
# AI provider - uncomment and fill ONE option, then restart innerwarden-agent.
#
# Option 1: OpenAI (cloud)
#   OPENAI_API_KEY=sk-...
#   (provider and model in agent.toml are already set to openai / gpt-4o-mini)
#
# Option 2: Anthropic (cloud)
#   ANTHROPIC_API_KEY=sk-ant-...
#   Also set in agent.toml: provider = "anthropic"
#                            model = "claude-haiku-4-5-20251001"
#
# Option 3: Ollama (local, no key needed)
#   1. Install:  curl -fsSL https://ollama.ai/install.sh | sh
#   2. Pull:     ollama pull llama3.2
#   3. Set in agent.toml: provider = "ollama"
#                          model   = "llama3.2"
#   No changes needed in this file for Ollama.
ENVEOF
fi
backup_if_exists "${AGENT_ENV}"
run_root install -o "${INSTALL_USER:-root}" -g "${IW_USER}" -m 640 "${tmp_env}" "${AGENT_ENV}"
rm -f "${tmp_env}"

fi  # end of "if not EXISTING_INSTALL" config block

if [[ "$OS_TYPE" == "Darwin" ]]; then
  log "writing launchd plist: ${SENSOR_PLIST}"
  run_root mkdir -p "${PLIST_DIR}"
  install_from_stdin "${SENSOR_PLIST}" 644 "${INSTALL_USER:-root}" "${INSTALL_GROUP:-root}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.innerwarden.sensor</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/innerwarden-sensor</string>
    <string>--config</string>
    <string>${CONFIG_DIR}/config.toml</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${LOG_DIR}/sensor.log</string>
  <key>StandardErrorPath</key><string>${LOG_DIR}/sensor.log</string>
</dict>
</plist>
EOF

  # 2026-06-29: emit EVERY provider API key the operator actually set, not just
  # OpenAI. Pre-fix the plist hardcoded only OPENAI_API_KEY, so a Mac user who
  # exported ANTHROPIC_API_KEY (and not OPENAI) got a plist with an empty OpenAI
  # key and the agent's AI silently never initialised — a "works on Linux,
  # broken on macOS" cross-platform bug. Mirror the documented providers the
  # Linux env-file path handles.
  MACOS_AI_ENV=""
  for _k in OPENAI_API_KEY ANTHROPIC_API_KEY; do
    _v="${!_k:-}"
    if [[ -n "${_v}" ]]; then
      MACOS_AI_ENV+="    <key>${_k}</key><string>${_v}</string>"$'\n'
    fi
  done

  log "writing launchd plist: ${AGENT_PLIST}"
  install_from_stdin "${AGENT_PLIST}" 644 "${INSTALL_USER:-root}" "${INSTALL_GROUP:-root}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.innerwarden.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/innerwarden-agent</string>
    <string>--data-dir</string>
    <string>${DATA_DIR}</string>
    <string>--config</string>
    <string>${CONFIG_DIR}/agent.toml</string>
    <string>--dashboard</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
${MACOS_AI_ENV}  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${LOG_DIR}/agent.log</string>
  <key>StandardErrorPath</key><string>${LOG_DIR}/agent.log</string>
</dict>
</plist>
EOF
else
  log "writing systemd unit: ${SENSOR_UNIT}"
  # 2026-05-25: the sensor unit MUST grant the capabilities its core
  # collectors need, otherwise the operator gets a working install that
  # does almost nothing. Pre-fix this unit ran as User=innerwarden with
  # zero AmbientCapabilities and ProtectSystem=strict — result: eBPF
  # never loaded (needs CAP_BPF), AF_PACKET DNS/HTTP/TLS captures
  # silently failed (need CAP_NET_RAW), exec_audit was deaf to the
  # audit netlink (needs CAP_AUDIT_READ), /sys/fs/bpf could not be
  # written so XDP firewall pinning never happened. The "trial profile"
  # safety gate (no AI, responder disabled, dry_run) lives in the
  # agent.toml below — those are what prevent harm. Capabilities here
  # only enable OBSERVATION; removing them just blinds the sensor.
  install_from_stdin "${SENSOR_UNIT}" 644 "${INSTALL_USER:-root}" "${INSTALL_GROUP:-root}" <<'EOF'
[Unit]
Description=Inner Warden - Sensor (host observability)
After=network.target syslog.target
Documentation=https://github.com/InnerWarden/innerwarden

[Service]
Type=simple
User=root
# Group=innerwarden so files created by the sensor are group-owned by
# the agent's user, allowing both sensor (root) and agent (innerwarden)
# to write to incidents-*.jsonl without permission conflicts.
Group=innerwarden
SupplementaryGroups=adm systemd-journal
# UMask 0007 makes new files mode 660 and directories 770. Group write
# (combined with Group=innerwarden above) lets the agent append to files
# created by the sensor. Without this, killchain_inline incidents are
# silently lost with "Permission denied" errors.
UMask=0007
ExecStart=/usr/local/bin/innerwarden-sensor --config /etc/innerwarden/config.toml
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
KillSignal=SIGTERM
SendSIGKILL=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=innerwarden-sensor

# ── Hardening ──
# The sensor runs as root because eBPF requires CAP_BPF + CAP_SYS_ADMIN.
# We lock down everything else to minimize pivot risk if compromised.
#
# Capability rationale:
#   CAP_BPF           — load eBPF programs (49 kernel programs)
#   CAP_PERFMON       — required alongside CAP_BPF on kernels ≥5.8
#   CAP_SYS_ADMIN     — bpf() syscall + perf_event_open + ringbuf
#   CAP_NET_RAW       — AF_PACKET sockets for dns_capture /
#                       http_capture / tls_fingerprint native captures
#   CAP_AUDIT_READ    — read /var/log/audit/audit.log for exec_audit
#                       (T1059 detection); auditd writes mode 0640
#   CAP_SYS_PTRACE    — read /proc/<pid>/maps of other processes
#                       (proc_maps collector — RWX / LD_PRELOAD
#                       detection); without this YAMA blocks the read
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_RAW CAP_AUDIT_READ CAP_SYS_PTRACE
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
# /sys/fs/bpf MUST be writable so the sensor can create
# /sys/fs/bpf/innerwarden/ and pin the BLOCKLIST + ALLOWLIST + LSM
# policy maps. Putting it in ReadOnlyPaths breaks XDP firewall pinning
# silently — the agent then emits "XDP firewall unavailable" warnings
# with a misleading "mount bpffs" hint (bpffs is fine, the issue is
# this systemd path constraint).
ReadWritePaths=/var/lib/innerwarden /sys/fs/bpf
ReadOnlyPaths=/var/log /etc/innerwarden /proc
ProtectHome=yes
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
LockPersonality=yes
MemoryDenyWriteExecute=no

[Install]
WantedBy=multi-user.target
EOF

  log "writing systemd unit: ${AGENT_UNIT}"
  install_from_stdin "${AGENT_UNIT}" 644 "${INSTALL_USER:-root}" "${INSTALL_GROUP:-root}" <<'EOF'
[Unit]
Description=Inner Warden - Agent (AI analysis and audit)
After=network-online.target innerwarden-sensor.service
Wants=network-online.target
Requires=innerwarden-sensor.service
Documentation=https://github.com/InnerWarden/innerwarden

[Service]
Type=simple
User=innerwarden
Group=innerwarden
EnvironmentFile=-/etc/innerwarden/agent.env
ExecStart=/usr/local/bin/innerwarden-agent --data-dir /var/lib/innerwarden --config /etc/innerwarden/agent.toml --dashboard
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
KillSignal=SIGTERM
SendSIGKILL=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=innerwarden-agent
PrivateTmp=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
fi

# Supervised mode (opt-in): write the supervisor unit. It runs as the same
# unprivileged user as the agent unit and SPAWNS the agent as its child, so
# the spawned agent is identical to the standalone agent unit's child. The
# enable block below starts THIS unit and leaves innerwarden-agent.service
# disabled so the two never fight over port 8787.
SUPERVISOR_UNIT="/etc/systemd/system/innerwarden-supervisor.service"
if [[ "${SUPERVISED}" == "true" ]] && { [[ ! -f "${SUPERVISOR_UNIT}" ]] || [[ "${FORCE}" -eq 1 ]]; }; then
  log "writing supervisor unit: ${SUPERVISOR_UNIT}"
  install_from_stdin "${SUPERVISOR_UNIT}" 644 root root <<EOF
[Unit]
Description=Inner Warden - Supervisor (health-probe + smart restart for the agent)
After=network-online.target innerwarden-sensor.service
Wants=network-online.target
Requires=innerwarden-sensor.service
Documentation=https://github.com/InnerWarden/innerwarden/wiki/Operations

[Service]
Type=simple
User=innerwarden
Group=innerwarden
EnvironmentFile=-/etc/innerwarden/agent.env
ExecStart=/usr/local/bin/innerwarden-supervisor \\
  --agent-binary /usr/local/bin/innerwarden-agent \\
  --agent-arg --data-dir --agent-arg /var/lib/innerwarden \\
  --agent-arg --config --agent-arg /etc/innerwarden/agent.toml \\
  --agent-arg --dashboard \\
  --agent-api http://127.0.0.1:8787 \\
  --health-interval 30 \\
  --max-restarts-per-hour 10
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=innerwarden-supervisor
PrivateTmp=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
fi

install_integrations() {
  echo
  log "=== Integration setup (--with-integrations) ==="
  echo "  External security-tool integrations are no longer bundled."
  echo "  This flag is kept as a no-op for backward compatibility."
  echo
  log "Nothing to install."
}

if [[ "$OS_TYPE" == "Darwin" ]]; then
  log "loading launchd services..."
  # Unload first if already loaded (idempotent install)
  run_root launchctl unload "${SENSOR_PLIST}" 2>/dev/null || true
  run_root launchctl unload "${AGENT_PLIST}" 2>/dev/null || true
  run_root launchctl load "${SENSOR_PLIST}"
  run_root launchctl load "${AGENT_PLIST}"

  # Give services a moment to start
  sleep 2

  if ! run_root launchctl list com.innerwarden.sensor 2>/dev/null | grep -q '"PID"'; then
    fail "innerwarden-sensor failed to start. Check: sudo tail -50 ${LOG_DIR}/sensor.log"
  fi

  if ! run_root launchctl list com.innerwarden.agent 2>/dev/null | grep -q '"PID"'; then
    fail "innerwarden-agent failed to start. Check: sudo tail -50 ${LOG_DIR}/agent.log"
  fi
else
  log "reloading systemd and starting services..."
  run_root systemctl daemon-reload
  run_root systemctl restart innerwarden-sensor
  if ! run_root systemctl is-active --quiet innerwarden-sensor; then
    fail "innerwarden-sensor failed to start. Check: sudo journalctl -u innerwarden-sensor -n 200"
  fi

  if [[ "${SUPERVISED}" == "true" ]]; then
    # The supervisor owns the agent lifecycle (spawns it as a child), so the
    # standalone agent unit must NOT also run or both fight over port 8787.
    run_root systemctl enable innerwarden-sensor innerwarden-supervisor >/dev/null
    run_root systemctl disable innerwarden-agent >/dev/null 2>&1 || true
    run_root systemctl stop innerwarden-agent >/dev/null 2>&1 || true
    run_root systemctl restart innerwarden-supervisor
    if ! run_root systemctl is-active --quiet innerwarden-supervisor; then
      fail "innerwarden-supervisor failed to start. Check: sudo journalctl -u innerwarden-supervisor -n 200"
    fi
    log "supervised mode: agent runs under innerwarden-supervisor (innerwarden-agent.service left disabled)."
  else
    run_root systemctl enable innerwarden-sensor innerwarden-agent >/dev/null
    run_root systemctl restart innerwarden-agent
    if ! run_root systemctl is-active --quiet innerwarden-agent; then
      fail "innerwarden-agent failed to start. Check: sudo journalctl -u innerwarden-agent -n 200"
    fi
  fi

  if [[ "${WITH_INTEGRATIONS}" -eq 1 ]]; then
    install_integrations
  fi
fi

# If canary was requested but fell back to stable, try to upgrade just the CTL
# binary from canary release (has latest setup UX)
if [[ "${CANARY}" -eq 1 ]] && [[ "${IW_VERSION}" != "canary" ]]; then
  CANARY_CTL="https://github.com/${GITHUB_REPO}/releases/download/canary/innerwarden-ctl-linux-${ARCH}"
  if $SUDO curl -fsSL --output "${BIN_DIR}/innerwarden" "${CANARY_CTL}" 2>/dev/null; then
    $SUDO chmod +x "${BIN_DIR}/innerwarden"
  fi
fi

# Install telemetry is opt-OUT (default on, anonymous). Disable with:
#   export INNERWARDEN_NO_TELEMETRY=1
# The data is anonymous + minimal enough that an opt-out default with a
# clear notice (printed above the ping) is the policy; see /privacy.
#
# What we collect:
#   - the release version you are installing (e.g. v0.15.12)
#   - the OS family (uname -s — Linux or Darwin)
#   - the CPU arch (uname -m — x86_64 / aarch64 / arm64)
#   - whether this was a fresh install or an upgrade (event=install|upgrade)
#
# What we never collect:
#   - your IP. The server hashes (ip + UTC day + a server-side secret)
#     into a one-way installation_id and discards the raw IP. The hash
#     is used only to dedup multiple pings from the same host on the
#     same day so the install count is not inflated by retries.
#   - any host identifier, agent state, config, license, or runtime data
#
# Server side: /api/ping is a public endpoint that returns 204 and
# writes one row into the app_events table. Aggregations live behind
# the admin DB_ADMIN_TOKEN. Source:
# https://github.com/InnerWarden/innerwarden-site/blob/master/pages/api/ping.ts
#
# The curl is backgrounded with a 5 s timeout and `-fsS` so it never
# blocks the install or writes to stdout. If the request fails (DNS,
# network, server down), the install completes silently regardless.
# Skip the ping in CI / automation. Installer smoke-tests run on ephemeral
# runners (GitHub Actions et al.), each a fresh machine-id from a US x86_64 box,
# so without this guard they flood the install telemetry and make adoption look
# busier than it is. The install itself still runs and is still verified in CI;
# only the ping is suppressed.
_iw_in_ci() {
  case "${CI:-}" in true | TRUE | 1) return 0 ;; esac
  [[ -n "${GITHUB_ACTIONS:-}${GITLAB_CI:-}${JENKINS_URL:-}${BUILDKITE:-}${CIRCLECI:-}${TF_BUILD:-}${TEAMCITY_VERSION:-}${DRONE:-}" ]]
}

if _iw_in_ci; then
  log "CI/automation detected, skipping the install telemetry ping."
elif [[ "${INNERWARDEN_NO_TELEMETRY:-0}" != "1" ]]; then
  # Anonymous install ping (opt-OUT). One-line notice + how to opt out, so the
  # default-on collection is transparent (informed consent, not silent).
  log "Sending an anonymous install ping (version + OS + CPU arch only — no IP, no host data)."
  log "Opt out any time: re-run with INNERWARDEN_NO_TELEMETRY=1. Details: https://www.innerwarden.com/privacy"
  # Use the canonical www host and follow redirects (-L): the apex
  # innerwarden.com 308-redirects to www, and `curl -fsS` without -L drops
  # the request — so the ping was silently lost. (Found 2026-06-11: the
  # app_events install_ping stream went dry; the endpoint was healthy, the
  # installer just never followed the redirect.)
  curl -fsSL \
    -m 5 \
    "https://www.innerwarden.com/api/ping?v=${IW_VERSION}&os=${OS_TYPE}&arch=${ARCH}&event=${IW_PING_EVENT:-install}" \
    >/dev/null 2>&1 &
fi

# Show welcome, then auto-run setup
if ! innerwarden welcome 2>/dev/null; then
  echo "  ✓ Downloaded ${IW_VERSION}"
  echo "  ✓ Installed"
  echo "  ✓ Services running"
  echo ""
fi

# Provision the Local Warden Model (on-device AI) BEFORE the interactive
# setup, so it lands even on headless / no-TTY installs (cloud-init,
# Ansible, golden images - i.e. how a SOC mass-installs at client boxes).
# `--configure` also wires `[ai.warden]` so the agent selects the local
# Decide head on next restart. One-time ~87 MB download, pinned SHA-256.
# The agent transparently falls back to cloud AI if this step fails.
# Opt out (cloud-AI-only deployments) with INNERWARDEN_NO_WARDEN=1.
if [[ "${INNERWARDEN_NO_WARDEN:-0}" != "1" ]]; then
  vlog "Provisioning Local Warden Model (on-device AI, no per-call API cost)..."
  if ! $SUDO innerwarden install-warden --yes --configure; then
    vlog "WARN: Local Warden provisioning failed - agent will use the configured cloud AI."
    vlog "      Retry later: sudo innerwarden install-warden --configure"
  fi
fi

# Auto-run setup with terminal input via /dev/tty (curl pipe consumes stdin).
# Headless installs (no /dev/tty: cloud-init, CI, Ansible) must NOT abort
# here - warden + its config were already provisioned above, so just skip
# the interactive wizard and tell the operator how to finish later.
# `[[ -r /dev/tty ]]` only tests the device node's permission bits — it passes
# even when there is NO controlling terminal (curl|sudo bash from a pipe, SSH
# non-interactive, cloud-init, CI), and then `< /dev/tty` aborts the whole
# install with "No such device or address". Probe by actually OPENING it, and
# keep the wizard non-fatal so a clean install never exits non-zero on this step.
if (: < /dev/tty) 2>/dev/null; then
  $SUDO innerwarden setup < /dev/tty \
    || vlog "interactive setup exited non-zero — run 'sudo innerwarden setup' to finish."
else
  vlog "No usable TTY (headless/piped install) - skipping interactive setup."
  vlog "Run 'sudo innerwarden setup' later to configure AI provider / notifications."
fi

# Make the enforcement posture explicit. The agent ships safe-by-default
# (responder disabled), so it WATCHES but does not block. Operators kept
# missing this and wondered why "the self-defending agent" never acted.
# This wording mirrors EnforcementPosture::cta() in crates/core so the CLI,
# the boot log, and this installer all say the same thing.
echo ""
echo "  InnerWarden is running in MONITOR-ONLY mode: it watches and alerts,"
echo "  but takes NO action on threats yet (the safe default)."
echo "  To enable autonomous response, set \`[responder] enabled = true\`"
echo "  (and \`dry_run = false\`) in ${AGENT_CONFIG} and restart innerwarden-agent."
echo "  Check posture any time with: innerwarden get status"
echo ""
