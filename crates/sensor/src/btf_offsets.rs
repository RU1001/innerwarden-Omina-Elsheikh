//! Spec 069 #6 — load-time `pt_regs` offset self-check.
//!
//! The eBPF programs read syscall-argument registers out of `pt_regs` at
//! **compile-time-literal** byte offsets. aya 0.13 does no CO-RE field
//! relocation, and the spec-069 read path *requires* a literal offset (a
//! runtime offset mis-reads on the BPF target — see the `syscall_arg!` macro),
//! so the offsets are baked into the object. They are correct on every current
//! kernel, but a future kernel that reorders `pt_regs` would make the reads
//! return **garbage, silently** — exactly the failure class spec-069 fought.
//!
//! aya's public API does not expose BTF struct member offsets
//! (`aya_obj::btf::Struct::members` is `pub(crate)`), so this is a small,
//! self-contained BTF reader: it parses `/sys/kernel/btf/vmlinux`, finds the
//! `pt_regs` struct, and compares the running kernel's member byte-offsets
//! against the hardcoded values the eBPF object assumes. On mismatch it logs
//! **loudly** (fail-open — the sensor still runs, but the operator sees it).
//!
//! Format reference: `uapi/linux/btf.h`. BTF is stored in native endianness;
//! `/sys/kernel/btf/vmlinux` therefore matches the host, so we read
//! little-endian (every arch InnerWarden targets is LE).

// The self-check's only non-test caller is the `--features ebpf` ring reader
// (`collectors::ebpf_syscall::run`); in the default no-`ebpf` build it is dead.
// Same convention as `event_channels` / `collectors::ebpf_syscall`.
#![allow(dead_code)]

use tracing::{info, warn};

const BTF_MAGIC: u16 = 0xEB9F;
const BTF_KIND_INT: u32 = 1;
const BTF_KIND_ARRAY: u32 = 3;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_VAR: u32 = 14;
const BTF_KIND_DATASEC: u32 = 15;
const BTF_KIND_DECL_TAG: u32 = 17;
const BTF_KIND_ENUM64: u32 = 19;

/// The byte offsets the eBPF object assumes for syscall args, mirrored from
/// the `__sc_off!` macro in `crates/sensor-ebpf/src/main.rs`. On x86_64 these
/// are `pt_regs` register fields (rdi/rsi/rdx/r10/r8/r9); on aarch64 the args
/// live in `regs[0..5]`, so validating that the `regs` array starts at offset
/// 0 covers all six (`regs[n]` is `0 + n*8`).
///
/// **If `__sc_off!` ever changes, update this in lockstep** (the
/// `expected_offsets_match_sc_off_macro` test grep-checks the macro source).
#[cfg(target_arch = "x86_64")]
pub fn expected_offsets() -> &'static [(&'static str, u32)] {
    &[
        ("di", 112),
        ("si", 104),
        ("dx", 96),
        ("r10", 56),
        ("r8", 72),
        ("r9", 64),
    ]
}
#[cfg(target_arch = "aarch64")]
pub fn expected_offsets() -> &'static [(&'static str, u32)] {
    &[("regs", 0)]
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn expected_offsets() -> &'static [(&'static str, u32)] {
    &[]
}

/// Parse a raw BTF blob and return the byte offsets of `struct_name`'s
/// members as `(member_name, byte_offset)`. `None` if the blob is not valid
/// BTF or the struct is absent.
pub fn struct_member_offsets(btf: &[u8], struct_name: &str) -> Option<Vec<(String, u32)>> {
    // btf_header: magic(u16) version(u8) flags(u8) hdr_len(u32)
    //             type_off(u32) type_len(u32) str_off(u32) str_len(u32)
    if btf.len() < 24 {
        return None;
    }
    let u16_at = |o: usize| u16::from_le_bytes([btf[o], btf[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes([btf[o], btf[o + 1], btf[o + 2], btf[o + 3]]);
    if u16_at(0) != BTF_MAGIC {
        return None;
    }
    let hdr_len = u32_at(4) as usize;
    let type_start = hdr_len.checked_add(u32_at(8) as usize)?;
    let type_end = type_start.checked_add(u32_at(12) as usize)?;
    let str_start = hdr_len.checked_add(u32_at(16) as usize)?;
    let str_end = str_start.checked_add(u32_at(20) as usize)?;
    if type_end > btf.len() || str_end > btf.len() || type_start < hdr_len {
        return None;
    }

    let str_at = |name_off: u32| -> Option<&str> {
        let s = str_start.checked_add(name_off as usize)?;
        if s >= str_end {
            return None;
        }
        let bytes = &btf[s..str_end];
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        core::str::from_utf8(&bytes[..end]).ok()
    };

    let mut off = type_start;
    while off + 12 <= type_end {
        let name_off = u32_at(off);
        let info = u32_at(off + 4);
        let vlen = (info & 0xffff) as usize;
        let kind = (info >> 24) & 0x1f;
        let kind_flag = (info >> 31) & 1;
        let after_common = off + 12;

        // Per-kind trailing bytes after the 12-byte common header.
        let trailing = match kind {
            BTF_KIND_INT => 4,
            BTF_KIND_ARRAY => 12,
            BTF_KIND_STRUCT | BTF_KIND_UNION => vlen.saturating_mul(12),
            BTF_KIND_ENUM => vlen.saturating_mul(8),
            BTF_KIND_FUNC_PROTO => vlen.saturating_mul(8),
            BTF_KIND_VAR => 4,
            BTF_KIND_DATASEC => vlen.saturating_mul(12),
            BTF_KIND_DECL_TAG => 4,
            BTF_KIND_ENUM64 => vlen.saturating_mul(12),
            // PTR/FWD/TYPEDEF/VOLATILE/CONST/RESTRICT/FUNC/FLOAT/TYPE_TAG: no trailing.
            _ => 0,
        };

        if (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION)
            && str_at(name_off) == Some(struct_name)
        {
            let mut out = Vec::with_capacity(vlen);
            let mut moff = after_common;
            for _ in 0..vlen {
                if moff + 12 > type_end {
                    return None;
                }
                // btf_member: name_off(u32) type(u32) offset(u32)
                let m_name_off = u32_at(moff);
                let m_offset = u32_at(moff + 8);
                // With kind_flag set, the low 24 bits are the bit offset and the
                // top 8 are the bitfield size; otherwise the whole word is the
                // bit offset. pt_regs has no bitfields, but handle both.
                let bit_off = if kind_flag == 1 {
                    m_offset & 0x00ff_ffff
                } else {
                    m_offset
                };
                if let Some(name) = str_at(m_name_off) {
                    out.push((name.to_string(), bit_off / 8));
                }
                moff += 12;
            }
            return Some(out);
        }

        off = after_common.checked_add(trailing)?;
    }
    None
}

/// Byte offset of a single `member` inside `struct_name`, from a raw BTF blob.
/// `None` if the blob is not valid BTF, the struct is absent, or the member is
/// not a direct member. The Execution Gate uses this for
/// `linux_binprm.filename` (CO-RE: the offset differs across kernels — 96 on
/// 6.8, where the old hardcoded 72 was actually `cred`).
pub fn member_offset(btf: &[u8], struct_name: &str, member: &str) -> Option<u32> {
    struct_member_offsets(btf, struct_name)?
        .into_iter()
        .find(|(name, _)| name == member)
        .map(|(_, off)| off)
}

/// Compare `expected` against the kernel's `actual` members. Returns
/// `(wrong, absent)`:
/// - `wrong` — an expected member that IS present but at a **different**
///   offset. A real, alarm-worthy mismatch: the eBPF reads would be garbage.
/// - `absent` — an expected member not found as a **direct** member of
///   `pt_regs`. Often **inconclusive**, not wrong: on aarch64 the register
///   array `pt_regs.regs[31]` lives inside an anonymous union, so a flat
///   top-level scan never sees a member literally named `regs` even though the
///   layout (regs at offset 0) is correct. Treated as inconclusive, not a
///   failure — a flat BTF reader cannot verify nested offsets.
pub fn offset_check(
    actual: &[(String, u32)],
    expected: &[(&str, u32)],
) -> (Vec<String>, Vec<String>) {
    let mut wrong = Vec::new();
    let mut absent = Vec::new();
    for (name, want) in expected {
        match actual.iter().find(|(n, _)| n == name) {
            Some((_, got)) if got == want => {}
            Some((_, got)) => {
                wrong.push(format!(
                    "pt_regs.{name}: kernel BTF offset {got} != hardcoded {want}"
                ));
            }
            None => absent.push(format!("pt_regs.{name}")),
        }
    }
    (wrong, absent)
}

/// Pure self-check over a raw BTF blob. `None` = `pt_regs` struct absent
/// (nothing to check); `Some((wrong, absent))` = found (see [`offset_check`]).
pub fn pt_regs_check_in_btf(btf: &[u8]) -> Option<(Vec<String>, Vec<String>)> {
    let actual = struct_member_offsets(btf, "pt_regs")?;
    Some(offset_check(&actual, expected_offsets()))
}

/// Read `/sys/kernel/btf/vmlinux` and self-check the `pt_regs` syscall-arg
/// offsets against the values the eBPF object hardcodes. Fail-open: logs and
/// returns on any problem. Returns the number of real (wrong-offset) mismatches
/// (0 = OK / inconclusive / could-not-check) for callers/tests that want it.
pub fn verify_pt_regs_offsets() -> usize {
    verify_from(std::path::Path::new("/sys/kernel/btf/vmlinux"))
}

/// Inner of [`verify_pt_regs_offsets`] parameterised by BTF path so a test can
/// drive the read-Ok + check + report path with a synthetic blob (CI runners
/// have no readable `/sys/kernel/btf/vmlinux`).
fn verify_from(path: &std::path::Path) -> usize {
    if expected_offsets().is_empty() {
        return 0; // arch without eBPF syscall-arg reads
    }
    let btf = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            info!(error = %e, "pt_regs offset self-check skipped (no kernel BTF)");
            return 0;
        }
    };
    report_check(pt_regs_check_in_btf(&btf))
}

/// Log the outcome of a `pt_regs` check and return the count of real
/// (wrong-offset) mismatches. Absent fields are logged as inconclusive, not
/// as failures (e.g. aarch64's nested `regs`). Split from the I/O wrapper so
/// every arm is unit-testable.
fn report_check(result: Option<(Vec<String>, Vec<String>)>) -> usize {
    // `match` rather than `let ... else` — tarpaulin does not attribute the
    // `let-else` arm, which silently drops it from coverage (see
    // RECURRING_BUGS / tarpaulin-coverage-patterns).
    let (wrong, absent) = match result {
        Some(r) => r,
        None => {
            info!("pt_regs offset self-check skipped (pt_regs struct not found in kernel BTF)");
            return 0;
        }
    };
    if !wrong.is_empty() {
        for x in &wrong {
            warn!(
                "eBPF pt_regs offset MISMATCH — syscall args may read GARBAGE on this kernel: {x}"
            );
        }
        wrong.len()
    } else if !absent.is_empty() {
        // e.g. aarch64's `regs[]` is nested in an anonymous union, so a flat
        // top-level scan can't find it — inconclusive, NOT a failure.
        info!(
            fields = %absent.join(", "),
            "pt_regs offset self-check inconclusive — expected fields are not direct pt_regs \
             members (nested layout, e.g. aarch64 regs[]); not flat-verifiable on this arch"
        );
        0
    } else {
        info!("eBPF pt_regs syscall-arg offsets validated against kernel BTF");
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal valid BTF blob from a string table and a type section.
    fn build_btf(strings: &[u8], types: &[u8]) -> Vec<u8> {
        let hdr_len: u32 = 24;
        let type_off: u32 = 0;
        let type_len = types.len() as u32;
        let str_off = type_len;
        let str_len = strings.len() as u32;
        let mut b = Vec::new();
        b.extend_from_slice(&BTF_MAGIC.to_le_bytes()); // magic
        b.push(1); // version
        b.push(0); // flags
        b.extend_from_slice(&hdr_len.to_le_bytes());
        b.extend_from_slice(&type_off.to_le_bytes());
        b.extend_from_slice(&type_len.to_le_bytes());
        b.extend_from_slice(&str_off.to_le_bytes());
        b.extend_from_slice(&str_len.to_le_bytes());
        b.extend_from_slice(types);
        b.extend_from_slice(strings);
        b
    }

    fn btf_type_common(name_off: u32, kind: u32, vlen: u32, size_or_type: u32) -> Vec<u8> {
        let info = (kind << 24) | (vlen & 0xffff);
        let mut v = Vec::new();
        v.extend_from_slice(&name_off.to_le_bytes());
        v.extend_from_slice(&info.to_le_bytes());
        v.extend_from_slice(&size_or_type.to_le_bytes());
        v
    }

    fn btf_member(name_off: u32, type_id: u32, bit_offset: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&name_off.to_le_bytes());
        v.extend_from_slice(&type_id.to_le_bytes());
        v.extend_from_slice(&bit_offset.to_le_bytes());
        v
    }

    // Build a BTF blob with a `pt_regs` struct carrying the given members at
    // the given BYTE offsets (arch-agnostic — drive it from `expected_offsets`).
    fn build_pt_regs_btf(members: &[(&str, u32)]) -> Vec<u8> {
        build_struct_btf("pt_regs", members)
    }

    // Build a BTF blob with one named struct carrying the given members at the
    // given BYTE offsets. Generalised from `build_pt_regs_btf` so the same
    // primitives can exercise `member_offset` against any struct name (e.g.
    // `task_struct` for the execve ppid fix).
    fn build_struct_btf(struct_name: &str, members: &[(&str, u32)]) -> Vec<u8> {
        let mut strings = vec![0u8]; // index 0 = empty name
        let struct_off = strings.len() as u32;
        strings.extend_from_slice(struct_name.as_bytes());
        strings.push(0);
        let mut name_offs = Vec::new();
        for (name, _) in members {
            name_offs.push(strings.len() as u32);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        // type 1: an INT (exercises the skip table); type 2: the struct.
        let mut types = btf_type_common(0, BTF_KIND_INT, 0, 8);
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&btf_type_common(
            struct_off,
            BTF_KIND_STRUCT,
            members.len() as u32,
            512,
        ));
        for (i, (_, byte_off)) in members.iter().enumerate() {
            types.extend_from_slice(&btf_member(name_offs[i], 1, byte_off * 8));
        }
        build_btf(&strings, &types)
    }

    #[test]
    fn member_offset_resolves_task_struct_fields() {
        // Anchors the EXACT struct + member names `populate_task_offsets`
        // queries for the execve in-kernel ppid fix. The live offsets on a
        // 6.x x86_64 kernel (validated on test001) were real_parent=2504,
        // tgid=2492; the test uses those so a rename of either member (which
        // would silently re-inert the fileless parent-lineage gate) fails here.
        let blob = build_struct_btf("task_struct", &[("real_parent", 2504), ("tgid", 2492)]);
        assert_eq!(
            member_offset(&blob, "task_struct", "real_parent"),
            Some(2504)
        );
        assert_eq!(member_offset(&blob, "task_struct", "tgid"), Some(2492));
        // A wrong member name resolves to None (so the loader leaves ppid=0 and
        // falls back to /proc rather than reading a guessed offset).
        assert_eq!(member_offset(&blob, "task_struct", "parent"), None);
        // A wrong struct name also resolves to None.
        assert_eq!(member_offset(&blob, "mm_struct", "tgid"), None);
    }

    #[test]
    fn pt_regs_check_in_btf_covers_match_absent_and_wrong() {
        // pt_regs matching the build-arch expected offsets -> (no wrong, no absent).
        let good = build_pt_regs_btf(expected_offsets());
        assert_eq!(pt_regs_check_in_btf(&good), Some((vec![], vec![])));

        // No pt_regs struct -> None.
        let other = build_btf(b"\0other\0", &btf_type_common(1, BTF_KIND_STRUCT, 0, 0));
        assert!(pt_regs_check_in_btf(&other).is_none());

        // Every member present but at a wrong offset -> non-empty WRONG, empty absent.
        let wrong: Vec<(&str, u32)> = expected_offsets()
            .iter()
            .map(|(n, o)| (*n, o + 8))
            .collect();
        let bad = build_pt_regs_btf(&wrong);
        let (w, a) = pt_regs_check_in_btf(&bad).unwrap();
        assert!(
            !w.is_empty(),
            "wrong-offset members must be flagged as wrong"
        );
        assert!(
            a.is_empty(),
            "members present (wrong offset) are not absent"
        );

        // pt_regs present but WITHOUT the expected members (e.g. aarch64's nested
        // regs) -> empty wrong, non-empty ABSENT (inconclusive, not a failure).
        let empty_struct = build_pt_regs_btf(&[]);
        let (w2, a2) = pt_regs_check_in_btf(&empty_struct).unwrap();
        assert!(w2.is_empty());
        assert_eq!(a2.len(), expected_offsets().len());
    }

    // Emit one BTF type of `kind` with `vlen` and `trailing` zero bytes after
    // the 12-byte common header (sized to match the parser's skip table).
    fn emit_type(kind: u32, vlen: u32, trailing: usize) -> Vec<u8> {
        let mut v = btf_type_common(0, kind, vlen, 0);
        v.resize(v.len() + trailing, 0);
        v
    }

    #[test]
    fn parser_skips_every_type_kind_before_the_struct() {
        // One type of each kind that carries trailing data (exercising every
        // skip-table arm), then pt_regs. The parser must skip them all and
        // still locate pt_regs at the correct member offset.
        let mut strings = vec![0u8];
        let ptregs_off = strings.len() as u32;
        strings.extend_from_slice(b"pt_regs\0");
        let m_off = strings.len() as u32;
        strings.extend_from_slice(b"x\0");

        let mut types = Vec::new();
        types.extend(emit_type(BTF_KIND_INT, 0, 4));
        types.extend(emit_type(BTF_KIND_ARRAY, 0, 12));
        types.extend(emit_type(BTF_KIND_ENUM, 1, 8));
        types.extend(emit_type(BTF_KIND_FUNC_PROTO, 1, 8));
        types.extend(emit_type(BTF_KIND_VAR, 0, 4));
        types.extend(emit_type(BTF_KIND_DATASEC, 1, 12));
        types.extend(emit_type(BTF_KIND_DECL_TAG, 0, 4));
        types.extend(emit_type(BTF_KIND_ENUM64, 1, 12));
        types.extend(emit_type(
            2, /* PTR — default arm, no trailing */
            0, 0,
        ));
        types.extend_from_slice(&btf_type_common(ptregs_off, BTF_KIND_STRUCT, 1, 16));
        types.extend_from_slice(&btf_member(m_off, 1, 8 * 8));

        let blob = build_btf(&strings, &types);
        let got = struct_member_offsets(&blob, "pt_regs").expect("pt_regs after skips");
        assert_eq!(got, vec![("x".to_string(), 8)]);
    }

    #[test]
    fn parser_decodes_bitfield_member_offset() {
        // kind_flag=1: member offset word is (bitfield_size << 24) | bit_offset.
        let strings = b"\0pt_regs\0b\0"; // pt_regs@1, b@9
        let info = (BTF_KIND_STRUCT << 24) | 1u32 | (1u32 << 31); // kind_flag set, vlen 1
        let mut types = Vec::new();
        types.extend_from_slice(&1u32.to_le_bytes()); // name_off: pt_regs
        types.extend_from_slice(&info.to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes()); // size
        types.extend_from_slice(&9u32.to_le_bytes()); // member name_off: b
        types.extend_from_slice(&1u32.to_le_bytes()); // member type
        types.extend_from_slice(&((3u32 << 24) | 64).to_le_bytes()); // size=3, bit_off=64
        let blob = build_btf(strings, &types);
        assert_eq!(
            struct_member_offsets(&blob, "pt_regs").unwrap(),
            vec![("b".to_string(), 8)] // bit 64 -> byte 8
        );
    }

    #[test]
    fn parser_drops_member_with_out_of_range_name() {
        // A struct member whose name_off points past the string section is
        // skipped (the `if let Some(name)` else path).
        let strings = b"\0pt_regs\0";
        let mut types = btf_type_common(1, BTF_KIND_STRUCT, 1, 8);
        types.extend_from_slice(&btf_member(9999, 1, 0)); // name_off out of range
        let blob = build_btf(strings, &types);
        assert_eq!(struct_member_offsets(&blob, "pt_regs"), Some(vec![]));
    }

    #[test]
    fn parser_rejects_malformed_blobs() {
        // too short for a header
        assert!(struct_member_offsets(&[0u8; 10], "pt_regs").is_none());
        // valid header but type_len runs past the buffer
        let mut b = Vec::new();
        b.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        b.push(1);
        b.push(0);
        b.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
        b.extend_from_slice(&0u32.to_le_bytes()); // type_off
        b.extend_from_slice(&9999u32.to_le_bytes()); // type_len -> type_end > len
        b.extend_from_slice(&0u32.to_le_bytes()); // str_off
        b.extend_from_slice(&0u32.to_le_bytes()); // str_len
        b.resize(40, 0);
        assert!(struct_member_offsets(&b, "pt_regs").is_none());
        // struct claims 2 members but the type section is truncated to 1
        let strings = b"\0pt_regs\0";
        let mut types = btf_type_common(1, BTF_KIND_STRUCT, 2, 8);
        types.extend_from_slice(&btf_member(1, 1, 0)); // only 1 member present
        let blob = build_btf(strings, &types);
        assert!(struct_member_offsets(&blob, "pt_regs").is_none());
    }

    #[test]
    fn member_offset_finds_member_and_misses_absent() {
        // Reuse the pt_regs builder with linux_binprm-shaped members: the
        // Execution Gate looks up `filename` (96 on kernel 6.8; 72 is `cred`).
        let blob = build_pt_regs_btf(&[("cred", 72), ("filename", 96)]);
        assert_eq!(member_offset(&blob, "pt_regs", "filename"), Some(96));
        assert_eq!(member_offset(&blob, "pt_regs", "cred"), Some(72));
        // member absent from the struct
        assert_eq!(member_offset(&blob, "pt_regs", "interp"), None);
        // struct absent from the blob
        assert_eq!(member_offset(&blob, "linux_binprm", "filename"), None);
        // not BTF at all
        assert_eq!(member_offset(b"junk", "pt_regs", "filename"), None);
    }

    #[test]
    fn report_check_covers_all_arms() {
        // none / validated / wrong (alarm) / inconclusive(absent, no alarm)
        assert_eq!(report_check(None), 0);
        assert_eq!(report_check(Some((vec![], vec![]))), 0);
        assert_eq!(
            report_check(Some((vec!["pt_regs.di: ...".to_string()], vec![]))),
            1
        );
        assert_eq!(
            report_check(Some((vec!["a".into(), "b".into()], vec![]))),
            2
        );
        // absent-only (e.g. aarch64 nested regs) → inconclusive, returns 0.
        assert_eq!(report_check(Some((vec![], vec!["pt_regs.regs".into()]))), 0);
    }

    #[test]
    fn verify_from_covers_read_check_and_missing_paths() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let write = |name: &str, bytes: &[u8]| {
            let p = dir.path().join(name);
            std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
            p
        };
        // matching pt_regs → validated → 0 real mismatches
        let good = write("good.btf", &build_pt_regs_btf(expected_offsets()));
        assert_eq!(verify_from(&good), 0);
        // every member at a wrong offset → real mismatches counted
        let wrong: Vec<(&str, u32)> = expected_offsets()
            .iter()
            .map(|(n, o)| (*n, o + 8))
            .collect();
        let bad = write("bad.btf", &build_pt_regs_btf(&wrong));
        assert_eq!(verify_from(&bad), expected_offsets().len());
        // missing file → fail-open Err branch → 0
        assert_eq!(verify_from(&dir.path().join("nope.btf")), 0);
    }

    #[test]
    fn verify_pt_regs_offsets_runs_clean_on_this_host() {
        // Exercises the I/O wrapper end to end. With kernel BTF (Linux CI) it
        // validates the real layout and returns 0; without it (macOS dev) it
        // takes the fail-open skip and returns 0. Must never panic, and a normal
        // kernel reports no mismatch.
        assert_eq!(verify_pt_regs_offsets(), 0);
    }

    #[test]
    fn parses_struct_member_byte_offsets_and_skips_other_types() {
        // strings: \0 "di"\0 "pt_regs"\0  -> offsets: di@1, pt_regs@4
        let strings = b"\0di\0pt_regs\0";
        let di_off = 1u32;
        let ptregs_off = 4u32;

        // type 1: an INT (to exercise the skip table), 4 trailing bytes.
        let mut types = btf_type_common(0, BTF_KIND_INT, 0, 8);
        types.extend_from_slice(&0u32.to_le_bytes()); // int encoding word

        // type 2: struct pt_regs { di @ byte 112 } -> bit offset 112*8 = 896
        types.extend_from_slice(&btf_type_common(ptregs_off, BTF_KIND_STRUCT, 1, 256));
        types.extend_from_slice(&btf_member(di_off, 1, 112 * 8));

        let blob = build_btf(strings, &types);
        let got = struct_member_offsets(&blob, "pt_regs").expect("pt_regs parsed");
        assert_eq!(got, vec![("di".to_string(), 112)]);
    }

    #[test]
    fn missing_struct_returns_none_and_bad_magic_returns_none() {
        let strings = b"\0other\0";
        let types = btf_type_common(1, BTF_KIND_STRUCT, 0, 0);
        let blob = build_btf(strings, &types);
        assert!(struct_member_offsets(&blob, "pt_regs").is_none());

        let mut bad = blob.clone();
        bad[0] = 0; // corrupt magic
        bad[1] = 0;
        assert!(struct_member_offsets(&bad, "pt_regs").is_none());
        assert!(struct_member_offsets(&[], "pt_regs").is_none());
    }

    #[test]
    fn offset_check_splits_wrong_from_absent() {
        let expected: &[(&str, u32)] = &[("di", 112), ("si", 104)];
        // exact match -> no wrong, no absent
        let ok = vec![("di".to_string(), 112), ("si".to_string(), 104)];
        assert_eq!(offset_check(&ok, expected), (vec![], vec![]));
        // di present but wrong offset; si missing -> 1 wrong, 1 absent
        let bad = vec![("di".to_string(), 999)];
        let (wrong, absent) = offset_check(&bad, expected);
        assert_eq!(wrong.len(), 1);
        assert!(wrong[0].contains("999"));
        assert_eq!(absent, vec!["pt_regs.si".to_string()]);
    }

    // Real-kernel validation: on a host with kernel BTF (Linux CI, test001),
    // the parser must agree with the actual `pt_regs` layout. Skips gracefully
    // where there is no BTF (e.g. the macOS dev host) or no `pt_regs` type.
    #[test]
    fn pt_regs_offsets_match_real_kernel_btf_if_present() {
        // `match` not `let-else` — keep tarpaulin attribution (the else arm runs
        // on CI runners that have no /sys/kernel/btf/vmlinux).
        let btf = match std::fs::read("/sys/kernel/btf/vmlinux") {
            Ok(b) => b,
            Err(_) => return,
        };
        let actual = match struct_member_offsets(&btf, "pt_regs") {
            Some(a) => a,
            None => return,
        };
        // Only a WRONG offset is a failure. An absent field is inconclusive,
        // not wrong — on aarch64 `regs` is nested in an anonymous union and is
        // never a direct member, yet the layout (regs at 0) is correct.
        let (wrong, _absent) = offset_check(&actual, expected_offsets());
        assert!(
            wrong.is_empty(),
            "hardcoded pt_regs offsets disagree with the running kernel BTF: {wrong:?}"
        );
    }

    // Guard: the hardcoded expected offsets must match the `__sc_off!` macro
    // literals in the eBPF source — if someone retunes one, this fails.
    #[test]
    fn expected_offsets_match_sc_off_macro() {
        let src = include_str!("../../sensor-ebpf/src/main.rs");
        // Whitespace-normalise so the anchor survives rustfmt (which expands
        // `(0) => { 112 };` into a multi-line arm).
        let normalized: String = src.split_whitespace().collect();
        for (name, off) in expected_offsets() {
            // x86_64 macro arms normalise to `(0)=>{112};`; aarch64 `(0)=>{0};`.
            // We just assert the offset literal appears in the macro block.
            let _ = name;
            assert!(
                normalized.contains(&format!("=>{{{off}}}")) || *off == 0,
                "offset {off} not found as a __sc_off! literal in sensor-ebpf/src/main.rs"
            );
        }
    }
}
