//! `innerwarden audit` subcommands — decision-log external-anchor integrity.
//!
//! The decisions hash chain (`row_hash = SHA-256(prev_hash || data)` per row)
//! proves the log is internally CONSISTENT, but an attacker with write access
//! can delete the whole log, or roll it back and re-grow a fresh
//! internally-consistent chain from a new root — tamper the chain alone cannot
//! detect (the rebuilt chain still verifies). An external anchor closes that
//! gap: `anchor` prints a compact commitment to the log's current tip that the
//! operator records OUTSIDE this host; `verify` later proves the live log still
//! contains that exact committed history.
//!
//! This is the FREE, unsigned form wrapping [`Store::compute_anchor`] /
//! [`Store::verify_against_anchor`]. The paid `innerwarden-config-sign audit
//! anchor/verify` wraps the same store primitives with an Ed25519 signature so
//! the anchor is itself tamper-evident off-host.

use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};
use innerwarden_store::decisions::{AnchorVerdict, DecisionAnchor};
use innerwarden_store::Store;

use super::circuit::resolve_store_dir;

/// Compute and print a publishable anchor over the decision log's current tip.
///
/// Human-readable by default; `--json` emits a single-line object that
/// round-trips straight back into `audit verify --anchor`. Prints nothing to
/// anchor when the log is empty.
pub(crate) fn cmd_audit_anchor(agent_config: &Path, data_dir: &Path, json: bool) -> Result<()> {
    let dir = resolve_store_dir(agent_config, data_dir);
    let store =
        Store::open(&dir).with_context(|| format!("open sqlite store at {}", dir.display()))?;
    let anchor = store
        .compute_anchor()
        .context("compute decision-log anchor")?;
    let mut out = std::io::stdout();
    match anchor {
        None => {
            if json {
                writeln!(out, "null")?;
            } else {
                writeln!(out, "Decision log is empty — nothing to anchor yet.")?;
            }
        }
        Some(a) => {
            let inline = serde_json::to_string(&a)?;
            if json {
                writeln!(out, "{inline}")?;
            } else {
                writeln!(out, "Decision-log anchor (record this OUTSIDE this host):")?;
                writeln!(out, "  seq:      {}", a.seq)?;
                writeln!(out, "  row_hash: {}", a.row_hash)?;
                writeln!(out, "  count:    {}", a.count)?;
                writeln!(out)?;
                writeln!(
                    out,
                    "Later, prove the log still contains this exact history with:"
                )?;
                writeln!(out, "  innerwarden audit verify --anchor '{inline}'")?;
            }
        }
    }
    Ok(())
}

/// Verify the live decision log against a previously-published anchor.
///
/// The anchor comes from `--file <path>` (a file written by `audit anchor
/// --json`) or `--anchor <json>` (inline). Returns `Ok(())` on
/// [`AnchorVerdict::Intact`]; a hard error on `Truncated` / `Rewritten` so the
/// process exit code gates CI / monitoring. In `--json` mode the verdict is
/// printed to stdout before any tamper error propagates.
pub(crate) fn cmd_audit_verify(
    agent_config: &Path,
    data_dir: &Path,
    file: Option<&Path>,
    inline: Option<&str>,
    json: bool,
) -> Result<()> {
    let raw = match (file, inline) {
        (Some(p), None) => std::fs::read_to_string(p)
            .with_context(|| format!("read anchor file {}", p.display()))?,
        (None, Some(s)) => s.to_string(),
        (None, None) => bail!("provide the anchor with --file <path> or --anchor <json>"),
        (Some(_), Some(_)) => bail!("--file and --anchor are mutually exclusive"),
    };
    let anchor: DecisionAnchor = serde_json::from_str(raw.trim())
        .context("parse anchor JSON (expected the output of `audit anchor --json`)")?;

    let dir = resolve_store_dir(agent_config, data_dir);
    let store =
        Store::open(&dir).with_context(|| format!("open sqlite store at {}", dir.display()))?;
    let verdict = store
        .verify_against_anchor(&anchor)
        .context("verify decision log against anchor")?;

    let mut out = std::io::stdout();
    if json {
        writeln!(
            out,
            "{}",
            serde_json::json!({
                "verdict": verdict,
                "seq": anchor.seq,
                "row_hash": anchor.row_hash,
                "count": anchor.count,
            })
        )?;
    }

    match verdict {
        AnchorVerdict::Intact => {
            if !json {
                writeln!(
                    out,
                    "INTACT — the decision log still contains the anchored history \
                     (tip seq {}, {} rows at anchor time). No deletion or rollback.",
                    anchor.seq, anchor.count
                )?;
            }
            Ok(())
        }
        AnchorVerdict::Truncated => {
            if !json {
                writeln!(
                    out,
                    "TRUNCATED — the anchored tip row (seq {}) is GONE. The log was \
                     deleted, truncated, or rolled back past it.",
                    anchor.seq
                )?;
            }
            bail!("decision-log anchor verify: TRUNCATED (tamper)")
        }
        AnchorVerdict::Rewritten => {
            if !json {
                writeln!(
                    out,
                    "REWRITTEN — the anchored tip row (seq {}) exists but its hash \
                     changed. The committed history was rewritten.",
                    anchor.seq
                )?;
            }
            bail!("decision-log anchor verify: REWRITTEN (tamper)")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_store::decisions::DecisionRow;
    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, std::path::PathBuf) {
        let td = TempDir::new().unwrap();
        let cfg = td.path().join("agent.toml");
        (td, cfg)
    }

    fn seed_decision(dir: &Path, incident: &str) {
        let store = Store::open(dir).unwrap();
        store
            .insert_decision(&DecisionRow {
                ts: "2026-07-03T00:00:00Z".to_string(),
                incident_id: incident.to_string(),
                action_type: "monitor".to_string(),
                target_ip: None,
                target_user: None,
                confidence: 1.0,
                auto_executed: false,
                reason: None,
                data: format!("{{\"incident\":\"{incident}\"}}"),
            })
            .unwrap();
    }

    fn current_anchor_json(dir: &Path) -> String {
        let store = Store::open(dir).unwrap();
        let a = store.compute_anchor().unwrap().expect("non-empty log");
        serde_json::to_string(&a).unwrap()
    }

    #[test]
    fn anchor_empty_log_does_not_error() {
        let (td, cfg) = temp_paths();
        // Both modes must succeed on a fresh (empty) log.
        cmd_audit_anchor(&cfg, td.path(), false).unwrap();
        cmd_audit_anchor(&cfg, td.path(), true).unwrap();
    }

    #[test]
    fn anchor_then_verify_intact() {
        let (td, cfg) = temp_paths();
        seed_decision(td.path(), "inc-1");
        let anchor = current_anchor_json(td.path());
        // Intact → Ok.
        cmd_audit_verify(&cfg, td.path(), None, Some(&anchor), false).unwrap();
        cmd_audit_verify(&cfg, td.path(), None, Some(&anchor), true).unwrap();
    }

    #[test]
    fn verify_appended_rows_still_intact() {
        let (td, cfg) = temp_paths();
        seed_decision(td.path(), "inc-1");
        let anchor = current_anchor_json(td.path());
        // Appending newer rows must NOT invalidate an earlier anchor.
        seed_decision(td.path(), "inc-2");
        cmd_audit_verify(&cfg, td.path(), None, Some(&anchor), false).unwrap();
    }

    #[test]
    fn verify_truncated_log_errors() {
        let (td, cfg) = temp_paths();
        seed_decision(td.path(), "inc-1");
        // Anchor points at seq 1; a rebuilt-from-scratch DB has no seq 1.
        let anchor = DecisionAnchor {
            seq: 999,
            row_hash: "deadbeef".to_string(),
            count: 1,
        };
        let inline = serde_json::to_string(&anchor).unwrap();
        let err = cmd_audit_verify(&cfg, td.path(), None, Some(&inline), false).unwrap_err();
        assert!(
            format!("{err:#}").contains("TRUNCATED"),
            "expected TRUNCATED, got: {err:#}"
        );
    }

    #[test]
    fn verify_rewritten_row_errors() {
        let (td, cfg) = temp_paths();
        seed_decision(td.path(), "inc-1");
        let mut anchor: DecisionAnchor =
            serde_json::from_str(&current_anchor_json(td.path())).unwrap();
        // Same seq, different hash = the committed history was rewritten.
        anchor.row_hash = "0".repeat(64);
        let inline = serde_json::to_string(&anchor).unwrap();
        let err = cmd_audit_verify(&cfg, td.path(), None, Some(&inline), false).unwrap_err();
        assert!(
            format!("{err:#}").contains("REWRITTEN"),
            "expected REWRITTEN, got: {err:#}"
        );
    }

    #[test]
    fn verify_requires_exactly_one_source() {
        let (td, cfg) = temp_paths();
        seed_decision(td.path(), "inc-1");
        // Neither source → error.
        assert!(cmd_audit_verify(&cfg, td.path(), None, None, false).is_err());
        // Both sources → error.
        let anchor = current_anchor_json(td.path());
        let p = td.path().join("a.json");
        std::fs::write(&p, &anchor).unwrap();
        assert!(cmd_audit_verify(&cfg, td.path(), Some(&p), Some(&anchor), false).is_err());
    }

    #[test]
    fn verify_reads_anchor_from_file() {
        let (td, cfg) = temp_paths();
        seed_decision(td.path(), "inc-1");
        let anchor = current_anchor_json(td.path());
        let p = td.path().join("anchor.json");
        std::fs::write(&p, &anchor).unwrap();
        cmd_audit_verify(&cfg, td.path(), Some(&p), None, false).unwrap();
    }

    #[test]
    fn anchor_non_empty_log_prints_in_both_modes() {
        let (td, cfg) = temp_paths();
        seed_decision(td.path(), "inc-1");
        // Both the human-readable and JSON Some-branch paths must succeed on a
        // non-empty log (the empty-log test only exercises the None branch).
        cmd_audit_anchor(&cfg, td.path(), false).unwrap();
        cmd_audit_anchor(&cfg, td.path(), true).unwrap();
    }

    #[test]
    fn verify_tamper_in_json_mode_still_errors() {
        let (td, cfg) = temp_paths();
        seed_decision(td.path(), "inc-1");
        // JSON mode prints the verdict to stdout, then still exits non-zero on
        // tamper (Truncated here) so a monitoring probe can gate on it.
        let anchor = DecisionAnchor {
            seq: 999,
            row_hash: "deadbeef".to_string(),
            count: 1,
        };
        let inline = serde_json::to_string(&anchor).unwrap();
        assert!(cmd_audit_verify(&cfg, td.path(), None, Some(&inline), true).is_err());
    }
}
