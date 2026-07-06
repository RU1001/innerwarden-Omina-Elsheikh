#!/usr/bin/env bash
# verify-lsm-hooks.sh — anchor that pins the LSM hook surface area.
#
# Spec 052/053 + PR-A/B/C/D shipped 5 minimal LSM hooks in
# `crates/sensor-ebpf/src/main.rs`. Each emits its own ELF section in
# the compiled eBPF object. If someone renames a hook, drops the
# `#[lsm(...)]` macro, accidentally cfg-gates one out, or changes the
# sleepable attribute on a hook that NEEDS to load via `lsm/X`
# (non-sleepable) vs `lsm.s/X` (sleepable), this script catches it
# before deploy.
#
# Inspects the built .o via `readelf -S` and asserts every expected
# section is present with the expected attribute (lsm/ vs lsm.s/).
#
# Pre-PR-A/B/C/D the .o had only 3 lsm sections (Spec 052 + legacy).
# After PR-D the count is 7 (3 minimal + 2 legacy + 2 PR-B/D? no —
# actually 5 minimal: exec_min, create_user_ns, ptrace_access,
# bpf_prog_load, mmap_file + 2 legacy = 7). See the EXPECTED array
# below for the canonical list.
#
# Usage:
#   ./scripts/verify-lsm-hooks.sh           # exit 0 if all hooks present
#   ./scripts/verify-lsm-hooks.sh --strict  # also fail if extra hooks
#                                            (catch unannounced new hooks)
#
# Exit codes:
#   0 — all expected LSM sections present
#   1 — missing or wrong-attribute section
#   2 — .o not built (skip silently for local dev; CI builds first)

set -eu

EBPF_OBJ="${EBPF_OBJ:-crates/sensor-ebpf/target/bpfel-unknown-none/release/innerwarden-ebpf}"

if [ ! -f "$EBPF_OBJ" ]; then
    echo "skip: eBPF object not built at $EBPF_OBJ" >&2
    echo "      (build with: cd crates/sensor-ebpf && cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release)" >&2
    exit 2
fi

if ! command -v readelf >/dev/null 2>&1; then
    echo "skip: readelf not available (install binutils)" >&2
    exit 2
fi

# Canonical list of LSM hook sections this binary MUST contain.
# Format: "section_name:expected_section_prefix"
#   - lsm/   → non-sleepable (kernel hook not in sleepable allow-list)
#   - lsm.s/ → sleepable (kernel hook is in the allow-list)
#
# When adding a new hook in sensor-ebpf/src/main.rs:
#   1. Add the entry here.
#   2. Update the EXPECTED_COUNT below.
#   3. Update memory file project_lsm_aya_kernel_64.md.
EXPECTED=(
    "lsm.s/bprm_check_security:Spec 052 — exec block (innerwarden_lsm_exec_min + innerwarden_lsm_exec_gate)"
    "lsm.s/userns_create:PR-A — container escape (innerwarden_lsm_create_user_ns)"
    "lsm/ptrace_access_check:PR-B — process injection (innerwarden_lsm_ptrace_access, NOT sleepable per kernel allow-list)"
    "lsm.s/bpf_prog:PR-C — VoidLink rootkit (innerwarden_lsm_bpf_prog_load)"
    "lsm.s/mmap_file:PR-D — real-time RWX (innerwarden_lsm_mmap_file)"
    "lsm.s/file_open:legacy"
    "lsm.s/bpf:legacy"
)

# Get all sections from the .o that start with lsm/ or lsm.s/
ACTUAL=$(readelf -W -S "$EBPF_OBJ" 2>/dev/null | awk '/PROGBITS/ { for (i=1; i<=NF; i++) if ($i ~ /^lsm(\.s)?\//) print $i }')

MISSING=0
echo "=== expected LSM sections in $EBPF_OBJ ==="
for entry in "${EXPECTED[@]}"; do
    section="${entry%%:*}"
    note="${entry#*:}"
    if echo "$ACTUAL" | grep -qFx "$section"; then
        echo "  ✅ $section — $note"
    else
        echo "  ❌ MISSING: $section — $note" >&2
        MISSING=$((MISSING + 1))
    fi
done

if [ "$MISSING" -gt 0 ]; then
    echo >&2
    echo "FAIL: $MISSING expected LSM hook(s) missing from $EBPF_OBJ" >&2
    echo "      Either restore them in crates/sensor-ebpf/src/main.rs OR update EXPECTED[] in this script if intentional." >&2
    echo >&2
    echo "All actual lsm sections found:" >&2
    echo "$ACTUAL" | sed 's/^/  /' >&2
    exit 1
fi

if [ "${1:-}" = "--strict" ]; then
    UNEXPECTED=0
    for section in $ACTUAL; do
        if ! printf '%s\n' "${EXPECTED[@]}" | grep -q "^${section}:"; then
            echo "  ⚠️  UNEXPECTED: $section (not in EXPECTED[])" >&2
            UNEXPECTED=$((UNEXPECTED + 1))
        fi
    done
    if [ "$UNEXPECTED" -gt 0 ]; then
        echo >&2
        echo "STRICT FAIL: $UNEXPECTED unannounced LSM hook(s) in .o" >&2
        echo "             Add them to EXPECTED[] in this script and document in memory." >&2
        exit 1
    fi
fi

# ── Per-program FUNC symbol check ──────────────────────────────────────
# bpf-linker FOLDS programs sharing a hook into ONE section (e.g.
# innerwarden_lsm_exec, _exec_min and _exec_gate all live in
# lsm.s/bprm_check_security), so the section check above cannot see a
# dropped PROGRAM — only a dropped HOOK. The symbol table can: every LSM
# program is a GLOBAL FUNC symbol. This pins the program surface itself.
EXPECTED_FUNCS=(
    "innerwarden_lsm_exec:full exec hook (kernels < 6.4 only; fails verifier on >= 6.4)"
    "innerwarden_lsm_exec_min:Spec 052 — minimal exec block (BLOCKED_PIDS)"
    "innerwarden_lsm_exec_gate:Execution Gate — allowlist pre-authz, inert unless LSM_POLICY key3=1"
    "innerwarden_lsm_create_user_ns:PR-A — container escape"
    "innerwarden_lsm_ptrace_access:PR-B — process injection"
    "innerwarden_lsm_bpf_prog_load:PR-C — VoidLink rootkit"
    "innerwarden_lsm_mmap_file:PR-D — real-time RWX"
    "innerwarden_lsm_file_open:legacy"
    "innerwarden_lsm_bpf:legacy"
)

ACTUAL_FUNCS=$(readelf -sW "$EBPF_OBJ" 2>/dev/null | awk '$4 == "FUNC" { print $NF }')

MISSING_FUNCS=0
echo
echo "=== expected LSM program FUNC symbols in $EBPF_OBJ ==="
for entry in "${EXPECTED_FUNCS[@]}"; do
    func="${entry%%:*}"
    note="${entry#*:}"
    if echo "$ACTUAL_FUNCS" | grep -qFx "$func"; then
        echo "  ✅ $func — $note"
    else
        echo "  ❌ MISSING: $func — $note" >&2
        MISSING_FUNCS=$((MISSING_FUNCS + 1))
    fi
done

if [ "$MISSING_FUNCS" -gt 0 ]; then
    echo >&2
    echo "FAIL: $MISSING_FUNCS expected LSM program symbol(s) missing from $EBPF_OBJ" >&2
    echo "      Either restore them in crates/sensor-ebpf/src/main.rs OR update EXPECTED_FUNCS[] if intentional." >&2
    exit 1
fi

echo
echo "OK: ${#EXPECTED[@]} expected LSM hook sections + ${#EXPECTED_FUNCS[@]} program symbols present in $EBPF_OBJ"
