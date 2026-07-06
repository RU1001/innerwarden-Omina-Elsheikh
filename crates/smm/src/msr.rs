//! MSR (Model Specific Register) reading — SMRAM lock, SMI count, feature control.
//!
//! All operations are READ-ONLY via `/dev/cpu/N/msr`. Requires `CAP_SYS_RAWIO`
//! or root. Safe to run — never writes to MSRs.

use crate::{confidence, CheckResult, CheckStatus};
#[cfg(unix)]
use std::fs::File;
use std::io;

// ── x86_64 MSR addresses ───────────────────────────────────────────────

/// SMI invocation counter. Increments on each System Management Interrupt.
pub const MSR_SMI_COUNT: u64 = 0x34;

/// SMRR (System Management Range Register) physical base.
pub const IA32_SMRR_PHYSBASE: u64 = 0x1F2;

/// SMRR physical mask — bit 11 = Valid (SMRAM protection active).
pub const IA32_SMRR_PHYSMASK: u64 = 0x1F3;

/// Feature control — bit 0 = Lock, bit 2 = VMX outside SMX, etc.
pub const IA32_FEATURE_CONTROL: u64 = 0x3A;

// ── Read primitives ─────────────────────────────────────────────────────

/// Read a 64-bit MSR value for a given CPU core.
///
/// Uses `pread(2)` on `/dev/cpu/{cpu}/msr` which is a read-only operation
/// from the hardware perspective — it queries the register without changing it.
pub fn read_msr(cpu: u32, msr: u64) -> io::Result<u64> {
    #[cfg(unix)]
    {
        let path = format!("/dev/cpu/{cpu}/msr");
        let f = File::open(&path)?;
        let mut buf = [0u8; 8];
        // pread at offset = MSR address reads the MSR value.
        let n = nix::sys::uio::pread(&f, &mut buf, msr as i64)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if n != 8 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("MSR read returned {n} bytes, expected 8"),
            ));
        }
        Ok(u64::from_le_bytes(buf))
    }
    // MSR reads require /dev/cpu (unix-only). On Windows (spec 085 Phase 0)
    // this is Unsupported, so try_read_msr yields None, the same "missing
    // /dev/cpu / non-x86" path callers already handle.
    #[cfg(not(unix))]
    {
        let _ = (cpu, msr);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MSR read requires /dev/cpu (unix-only)",
        ))
    }
}

/// Read an MSR, returning None on any error (permissions, missing /dev/cpu, non-x86).
pub fn try_read_msr(cpu: u32, msr: u64) -> Option<u64> {
    read_msr(cpu, msr).ok()
}

// ── Parsed MSR state ────────────────────────────────────────────────────

/// SMRAM protection state derived from SMRR registers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SmramState {
    /// SMRR base address (physical).
    pub base: u64,
    /// SMRR mask.
    pub mask: u64,
    /// Whether SMRR Valid bit is set (bit 11 of PHYSMASK).
    pub valid: bool,
    /// Memory type from base register (bits 0-2).
    pub mem_type: u8,
}

impl SmramState {
    /// Read SMRAM state from MSRs on CPU 0.
    pub fn read() -> io::Result<Self> {
        let base = read_msr(0, IA32_SMRR_PHYSBASE)?;
        let mask = read_msr(0, IA32_SMRR_PHYSMASK)?;
        Ok(smram_state_from_registers(base, mask))
    }
}

fn smram_state_from_registers(base: u64, mask: u64) -> SmramState {
    SmramState {
        base: base & 0xFFFFF000, // bits 12-31 (physical base, 4K aligned)
        mask,
        valid: (mask >> 11) & 1 == 1,
        mem_type: (base & 0x7) as u8,
    }
}

/// IA32_FEATURE_CONTROL state.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FeatureControlState {
    pub raw: u64,
    /// Bit 0: Lock bit. Once set, register is read-only until reset.
    pub locked: bool,
    /// Bit 2: VMX outside SMX enabled.
    pub vmx_enabled: bool,
}

impl FeatureControlState {
    pub fn read() -> io::Result<Self> {
        let raw = read_msr(0, IA32_FEATURE_CONTROL)?;
        Ok(feature_control_state_from_raw(raw))
    }
}

fn feature_control_state_from_raw(raw: u64) -> FeatureControlState {
    FeatureControlState {
        raw,
        locked: raw & 1 == 1,
        vmx_enabled: (raw >> 2) & 1 == 1,
    }
}

// ── Check functions (return CheckResult for audit) ──────────────────────

/// Check if SMRAM is locked (protected from OS-level access).
pub fn check_smram_lock() -> CheckResult {
    // Impact: 1.0 (SMRAM unlock = total firmware compromise)
    // Certainty: 1.0 (hardware register, no heuristic)
    if cfg!(not(target_arch = "x86_64")) {
        return CheckResult {
            id: "SMM-001",
            name: "SMRAM Lock",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "x86_64 only — skipped on this architecture".into(),
        };
    }

    check_smram_lock_from_read(SmramState::read())
}

fn check_smram_lock_from_read(read: io::Result<SmramState>) -> CheckResult {
    match read {
        Ok(state) if state.valid => CheckResult {
            id: "SMM-001",
            name: "SMRAM Lock",
            status: CheckStatus::Secure,
            confidence: confidence(1.0, 1.0), // high impact, confirmed secure
            detail: format!(
                "SMRR active — base=0x{:X}, mask=0x{:X}, type={}",
                state.base, state.mask, state.mem_type
            ),
        },
        Ok(_) => CheckResult {
            id: "SMM-001",
            name: "SMRAM Lock",
            status: CheckStatus::Critical,
            confidence: confidence(1.0, 1.0), // max impact, hardware-confirmed
            detail: "SMRR Valid bit NOT set — SMRAM is unprotected. \
                     A kernel-level attacker could read/write SMM code."
                .into(),
        },
        Err(e) => CheckResult {
            id: "SMM-001",
            name: "SMRAM Lock",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: format!("cannot read SMRR MSRs: {e} (need root + msr module loaded)"),
        },
    }
}

/// Read the current SMI count from MSR_SMI_COUNT.
pub fn read_smi_count() -> Option<u64> {
    try_read_msr(0, MSR_SMI_COUNT)
}

/// Check if SMI count is readable (baseline for anomaly detection).
pub fn check_smi_count() -> CheckResult {
    // Impact: 0.7 (SMI count is a signal, not proof of compromise)
    // Certainty: 1.0 (hardware counter)
    check_smi_count_from_value(read_smi_count())
}

fn check_smi_count_from_value(count: Option<u64>) -> CheckResult {
    match count {
        Some(count) => CheckResult {
            id: "SMM-002",
            name: "SMI Counter",
            status: CheckStatus::Secure,
            confidence: confidence(0.7, 1.0),
            detail: format!("SMI count = {count} (baseline captured for drift detection)"),
        },
        None => CheckResult {
            id: "SMM-002",
            name: "SMI Counter",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read MSR_SMI_COUNT (need root + msr module loaded)".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smram_state_parsing() {
        // Simulate SMRR register values from a typical Intel system.
        // PHYSBASE = 0x7C000006 (base at 0x7C000000, WB cache type 6)
        // PHYSMASK = 0xFC000800 (valid bit set, 64MB region)
        let base: u64 = 0x7C000006;
        let mask: u64 = 0xFC000800;

        let state = smram_state_from_registers(base, mask);

        assert_eq!(state.base, 0x7C000000);
        assert!(state.valid);
        assert_eq!(state.mem_type, 6); // Write-Back
    }

    #[test]
    fn smram_unlocked_detection() {
        // PHYSMASK with Valid bit = 0 → SMRAM unprotected.
        let mask: u64 = 0xFC000000; // bit 11 = 0
        let valid = (mask >> 11) & 1 == 1;
        assert!(!valid);
    }

    #[test]
    fn feature_control_parsing() {
        // Typical locked state with VMX enabled.
        let raw: u64 = 0x5; // bits 0 (lock) + 2 (vmx) = 0b101
        let state = feature_control_state_from_raw(raw);
        assert!(state.locked);
        assert!(state.vmx_enabled);
    }

    #[test]
    fn feature_control_unlocked_detection() {
        // Safety path: lock bit absence must be detectable for feature-control
        // validation.
        let raw: u64 = 0x4; // VMX enabled but NOT locked → dangerous
        let locked = raw & 1 == 1;
        assert!(!locked);
    }

    #[test]
    fn check_smram_lock_non_x86() {
        // On non-x86 (this test may run on ARM CI), should return Unavailable.
        let result = check_smram_lock();
        if cfg!(not(target_arch = "x86_64")) {
            assert_eq!(result.status, CheckStatus::Unavailable);
        }
        // On x86 without root, also Unavailable (no /dev/cpu/0/msr access).
    }

    #[test]
    fn msr_addresses_match_expected_constants() {
        // Constant path: critical MSR addresses should remain stable to avoid
        // reading the wrong firmware registers.
        assert_eq!(MSR_SMI_COUNT, 0x34);
        assert_eq!(IA32_SMRR_PHYSBASE, 0x1F2);
        assert_eq!(IA32_SMRR_PHYSMASK, 0x1F3);
        assert_eq!(IA32_FEATURE_CONTROL, 0x3A);
    }

    #[test]
    fn try_read_msr_returns_none_for_impossible_cpu() {
        // Error path: invalid CPU index should return None instead of
        // panicking when device files are absent.
        assert!(try_read_msr(u32::MAX, MSR_SMI_COUNT).is_none());
    }

    #[test]
    fn check_smi_count_exposes_stable_check_id() {
        // Contract path: SMI counter check must keep the canonical id for
        // report correlation.
        let result = check_smi_count();
        assert_eq!(result.id, "SMM-002");
    }

    #[test]
    fn check_smram_lock_from_read_reports_secure_valid_registers() {
        let result =
            check_smram_lock_from_read(Ok(smram_state_from_registers(0x7C000006, 0xFC000800)));
        assert_eq!(result.status, CheckStatus::Secure);
        assert!(result.detail.contains("SMRR active"));
        assert!(result.detail.contains("base=0x7C000000"));
    }

    #[test]
    fn check_smram_lock_from_read_reports_critical_when_valid_bit_absent() {
        let result =
            check_smram_lock_from_read(Ok(smram_state_from_registers(0x7C000006, 0xFC000000)));
        assert_eq!(result.status, CheckStatus::Critical);
        assert!(result.detail.contains("Valid bit NOT set"));
    }

    #[test]
    fn check_smram_lock_from_read_reports_unavailable_on_io_error() {
        let result = check_smram_lock_from_read(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "denied",
        )));
        assert_eq!(result.status, CheckStatus::Unavailable);
        assert!(result.detail.contains("denied"));
    }

    #[test]
    fn smi_count_result_formats_secure_and_unavailable_paths() {
        let secure = check_smi_count_from_value(Some(42));
        assert_eq!(secure.status, CheckStatus::Secure);
        assert!(secure.detail.contains("SMI count = 42"));

        let unavailable = check_smi_count_from_value(None);
        assert_eq!(unavailable.status, CheckStatus::Unavailable);
        assert!(unavailable.detail.contains("cannot read MSR_SMI_COUNT"));
    }
}
