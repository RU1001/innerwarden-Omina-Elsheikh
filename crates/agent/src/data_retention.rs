use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{Local, NaiveDate};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use tracing::{debug, warn};

use crate::config::DataRetentionConfig;

/// File patterns that `data_retention::cleanup` and the warm-tier
/// gzip sweep know about. Tuple: (prefix, suffix). Order matters
/// only for `cleanup`'s "first match wins" branch and for the gzip
/// sweep (same prefixes reappear).
fn warm_jsonl_patterns() -> &'static [(&'static str, &'static str)] {
    &[
        ("events-", ".jsonl"),
        ("incidents-", ".jsonl"),
        ("decisions-", ".jsonl"),
        ("labels-", ".jsonl"),
        ("telemetry-", ".jsonl"),
        ("admin-actions-", ".jsonl"),
        ("agent-guard-events-", ".jsonl"),
    ]
}

/// Read the data directory for the monthly-file cleanup pass, surfacing
/// genuine I/O failure via `warn!` while staying silent on `NotFound`
/// (steady state on a fresh install before the data dir is created).
/// Replaces the silent `if let Ok(entries) = fs::read_dir(data_dir)`
/// site in the monthly cleanup branch (Spec 037 I-13 follow-up #2).
///
/// On a real I/O error (perms, FS error) the operator's monthly-file
/// retention pass is skipped silently and old reports accumulate on
/// disk indefinitely. The warn carries path + error so the operator
/// can fix permissions and restore retention.
fn read_data_dir_for_monthly_cleanup_or_warn(data_dir: &Path) -> Option<fs::ReadDir> {
    match fs::read_dir(data_dir) {
        Ok(it) => Some(it),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(
                path = %data_dir.display(),
                error = %e,
                "data retention monthly cleanup read_dir failed (old reports not pruned)"
            );
            None
        }
    }
}

/// Remove old data files from `data_dir` according to retention config.
///
/// Runs on agent startup and in the slow loop (once per day).
/// Never removes today's files regardless of keep_days.
/// Returns number of files deleted.
pub fn cleanup(data_dir: &Path, cfg: &DataRetentionConfig) -> usize {
    let today = Local::now().date_naive();

    // (prefix, suffix, keep_days)
    // Spec 030: include `graph-snapshot-` so daily knowledge-graph
    // snapshots do not accumulate at ~40 MB/day. `.jsonl.gz` variants
    // of warm-tier files are pruned alongside the raw `.jsonl`.
    let patterns: &[(&str, &str, usize)] = &[
        ("events-", ".jsonl", cfg.events_keep_days),
        ("events-", ".jsonl.gz", cfg.events_keep_days),
        ("incidents-", ".jsonl", cfg.incidents_keep_days),
        ("incidents-", ".jsonl.gz", cfg.incidents_keep_days),
        ("decisions-", ".jsonl", cfg.decisions_keep_days),
        ("decisions-", ".jsonl.gz", cfg.decisions_keep_days),
        // Spec 062 Phase 6a warden-label corpus — retained like decisions
        // (low volume; only human decisions + learned suppressions land here).
        ("labels-", ".jsonl", cfg.decisions_keep_days),
        ("labels-", ".jsonl.gz", cfg.decisions_keep_days),
        // Spec 062 Phase 6b mesh suppression-advisory audit.
        (
            "mesh_advisory_suppressions-",
            ".jsonl",
            cfg.decisions_keep_days,
        ),
        (
            "mesh_advisory_suppressions-",
            ".jsonl.gz",
            cfg.decisions_keep_days,
        ),
        // Mesh signal forensic log (innerwarden-mesh `append_signal_log`):
        // a write-only audit trail, never loaded on restart and read by no
        // query surface, so it stays JSONL (SQLite buys nothing without a
        // reader) — but it was accumulating unbounded because it was absent
        // from this sweep while its sibling advisory-audit was pruned. Low
        // volume (forensic), so retained on the decisions horizon.
        ("mesh-signals-", ".jsonl", cfg.decisions_keep_days),
        ("mesh-signals-", ".jsonl.gz", cfg.decisions_keep_days),
        ("telemetry-", ".jsonl", cfg.telemetry_keep_days),
        ("telemetry-", ".jsonl.gz", cfg.telemetry_keep_days),
        ("admin-actions-", ".jsonl", cfg.decisions_keep_days),
        ("admin-actions-", ".jsonl.gz", cfg.decisions_keep_days),
        ("agent-guard-events-", ".jsonl", cfg.decisions_keep_days),
        ("agent-guard-events-", ".jsonl.gz", cfg.decisions_keep_days),
        ("trial-report-", ".json", cfg.reports_keep_days),
        ("trial-report-", ".md", cfg.reports_keep_days),
        ("summary-", ".md", cfg.reports_keep_days),
        ("graph-snapshot-", ".json", cfg.graph_snapshot_keep_days),
    ];

    // Monthly files: prefix-YYYY-MM.ext (different date format)
    let monthly_patterns: &[(&str, &str, usize)] = &[
        ("monthly-report-", ".json", cfg.reports_keep_days),
        ("monthly-report-", ".md", cfg.reports_keep_days),
    ];

    let entries = match fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("data_retention: failed to read data_dir: {e:#}");
            return 0;
        }
    };

    let mut removed = 0usize;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();

        for (prefix, suffix, keep_days) in patterns {
            let Some(mid) = name
                .strip_prefix(prefix)
                .and_then(|s| s.strip_suffix(*suffix))
            else {
                continue;
            };
            let Ok(file_date) = NaiveDate::parse_from_str(mid, "%Y-%m-%d") else {
                continue;
            };
            let age_days = (today - file_date).num_days();
            if age_days <= 0 || age_days <= *keep_days as i64 {
                break; // within retention window
            }
            let path = entry.path();
            match fs::remove_file(&path) {
                Ok(()) => {
                    debug!(
                        path = %path.display(),
                        age_days,
                        keep_days,
                        "data_retention: removed old file"
                    );
                    removed += 1;
                }
                Err(e) => {
                    warn!(path = %path.display(), "data_retention: failed to remove: {e:#}");
                }
            }
            break; // matched this pattern, no need to check other patterns for same file
        }
    }

    // Monthly file cleanup: monthly-report-YYYY-MM.{json,md}
    if let Some(entries) = read_data_dir_for_monthly_cleanup_or_warn(data_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();

            for (prefix, suffix, keep_days) in monthly_patterns {
                let Some(mid) = name
                    .strip_prefix(prefix)
                    .and_then(|s| s.strip_suffix(*suffix))
                else {
                    continue;
                };
                // Parse YYYY-MM format: treat as 1st of that month
                let Ok(file_date) = NaiveDate::parse_from_str(&format!("{mid}-01"), "%Y-%m-%d")
                else {
                    continue;
                };
                let age_days = (today - file_date).num_days();
                if age_days <= 0 || age_days <= *keep_days as i64 {
                    break;
                }
                let path = entry.path();
                match fs::remove_file(&path) {
                    Ok(()) => {
                        debug!(
                            path = %path.display(),
                            age_days,
                            keep_days,
                            "data_retention: removed old monthly file"
                        );
                        removed += 1;
                    }
                    Err(e) => {
                        warn!(path = %path.display(), "data_retention: failed to remove: {e:#}");
                    }
                }
                break;
            }
        }
    }

    removed
}

/// Prune `filestore/extracted/<shard>/<sha256>.<ext>` forensic
/// artifacts captured by the sensor's HTTP body extractor. Files are
/// content-hashed, so filenames carry no date; age comes from mtime.
///
/// Two passes:
/// 1. Drop every file with `now - mtime > keep_days` (skipped when
///    `keep_days == 0`).
/// 2. If the surviving tree still exceeds `max_size_mb`, delete the
///    oldest files until the total is back under the cap (skipped
///    when `max_size_mb == 0`).
///
/// Empty shard directories are removed at the end. Returns
/// `(files_removed, bytes_freed)`.
pub fn cleanup_filestore(data_dir: &Path, cfg: &DataRetentionConfig) -> (usize, u64) {
    let root = data_dir.join("filestore").join("extracted");
    if !root.exists() {
        return (0, 0);
    }

    let now = SystemTime::now();
    let keep = Duration::from_secs((cfg.filestore_keep_days as u64).saturating_mul(86400));
    let cap_bytes = cfg.filestore_max_size_mb.saturating_mul(1024 * 1024);

    // (path, size, mtime) for files that survive pass 1.
    let mut alive: Vec<(PathBuf, u64, SystemTime)> = Vec::new();
    let mut files_removed = 0usize;
    let mut bytes_freed: u64 = 0;

    let shards = match fs::read_dir(&root) {
        Ok(iter) => iter,
        Err(e) => {
            warn!(path = %root.display(), "cleanup_filestore: read_dir failed: {e:#}");
            return (0, 0);
        }
    };

    for shard in shards.flatten() {
        let shard_path = shard.path();
        let Ok(md) = shard.metadata() else {
            continue;
        };
        if !md.is_dir() {
            continue;
        }
        let files = match fs::read_dir(&shard_path) {
            Ok(iter) => iter,
            Err(e) => {
                warn!(path = %shard_path.display(), "cleanup_filestore: shard read_dir failed: {e:#}");
                continue;
            }
        };
        for entry in files.flatten() {
            let Ok(fmd) = entry.metadata() else { continue };
            if !fmd.is_file() {
                continue;
            }
            let path = entry.path();
            let size = fmd.len();
            let mtime = fmd.modified().unwrap_or(now);

            let should_age_prune = cfg.filestore_keep_days > 0
                && now.duration_since(mtime).map(|d| d > keep).unwrap_or(false);

            if should_age_prune {
                match fs::remove_file(&path) {
                    Ok(()) => {
                        files_removed += 1;
                        bytes_freed += size;
                    }
                    Err(e) => {
                        warn!(path = %path.display(), "cleanup_filestore: remove failed: {e:#}");
                        alive.push((path, size, mtime));
                    }
                }
            } else {
                alive.push((path, size, mtime));
            }
        }
    }

    // Pass 2: size cap (oldest first).
    if cap_bytes > 0 {
        let total: u64 = alive.iter().map(|(_, s, _)| *s).sum();
        if total > cap_bytes {
            alive.sort_by_key(|(_, _, mtime)| *mtime);
            let mut to_free = total - cap_bytes;
            for (path, size, _) in &alive {
                if to_free == 0 {
                    break;
                }
                match fs::remove_file(path) {
                    Ok(()) => {
                        files_removed += 1;
                        bytes_freed += size;
                        to_free = to_free.saturating_sub(*size);
                    }
                    Err(e) => {
                        warn!(path = %path.display(), "cleanup_filestore: cap remove failed: {e:#}");
                    }
                }
            }
        }
    }

    // Remove shard dirs that became empty.
    if files_removed > 0 {
        if let Ok(iter) = fs::read_dir(&root) {
            for shard in iter.flatten() {
                let p = shard.path();
                let is_empty = fs::read_dir(&p)
                    .map(|mut it| it.next().is_none())
                    .unwrap_or(false);
                if is_empty {
                    let _ = fs::remove_dir(&p);
                }
            }
        }
    }

    if files_removed > 0 {
        debug!(
            files_removed,
            bytes_freed,
            keep_days = cfg.filestore_keep_days,
            cap_mb = cfg.filestore_max_size_mb,
            "cleanup_filestore: pruned extracted artifacts"
        );
    }

    (files_removed, bytes_freed)
}

/// Spec 030: compress warm-tier JSONL files older than
/// `cfg.warm_gzip_days` with gzip. The original file is replaced by
/// a `.jsonl.gz` sibling, then removed. Today's file is never
/// compressed (writers may still be appending). Already-compressed
/// files are skipped.
///
/// Returns `(compressed_count, bytes_saved)`.
pub fn gzip_warm_jsonl(data_dir: &Path, cfg: &DataRetentionConfig) -> (usize, i64) {
    if cfg.warm_gzip_days == 0 {
        return (0, 0);
    }
    let today = Local::now().date_naive();
    let mut compressed = 0usize;
    let mut saved: i64 = 0;

    let entries = match fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("data_retention: failed to read data_dir for gzip sweep: {e:#}");
            return (0, 0);
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy().to_string();

        let Some((prefix, suffix)) = warm_jsonl_patterns()
            .iter()
            .find(|(p, s)| name.starts_with(p) && name.ends_with(s))
        else {
            continue;
        };

        let Some(mid) = name
            .strip_prefix(prefix)
            .and_then(|s| s.strip_suffix(suffix))
        else {
            continue;
        };
        let Ok(file_date) = NaiveDate::parse_from_str(mid, "%Y-%m-%d") else {
            continue;
        };
        let age_days = (today - file_date).num_days();
        if age_days < cfg.warm_gzip_days as i64 {
            continue;
        }
        let src = entry.path();
        let gz_path = src.with_extension("jsonl.gz");
        if gz_path.exists() {
            // Already compressed from a previous sweep; remove the
            // stale raw copy defensively in case it lingered.
            if let Err(e) = fs::remove_file(&src) {
                warn!(
                    path = %src.display(),
                    "data_retention: failed to remove stale raw file: {e:#}"
                );
            }
            continue;
        }
        match gzip_file_atomic(&src, &gz_path) {
            Ok((before, after)) => {
                saved += before as i64 - after as i64;
                compressed += 1;
                debug!(
                    path = %src.display(),
                    before, after,
                    ratio = format!("{:.2}", after as f64 / before as f64),
                    "data_retention: compressed warm-tier file"
                );
                if let Err(e) = fs::remove_file(&src) {
                    warn!(
                        path = %src.display(),
                        "data_retention: compressed but failed to remove original: {e:#}"
                    );
                }
            }
            Err(e) => {
                warn!(
                    path = %src.display(),
                    "data_retention: gzip failed, leaving raw file in place: {e:#}"
                );
                // Best-effort cleanup of the partial `.gz` so the next
                // sweep retries from a clean slate.
                let _ = fs::remove_file(&gz_path);
            }
        }
    }

    (compressed, saved)
}

/// Compress `src` to `dst` with gzip (default level 6 — matches
/// `gzip -6` which is the best tradeoff between CPU and ratio for
/// JSONL logs). Writes to a temp file next to `dst` and atomically
/// renames into place so a crash mid-compress does not leave a
/// truncated `.gz`.
fn gzip_file_atomic(src: &Path, dst: &Path) -> io::Result<(u64, u64)> {
    let before = fs::metadata(src)?.len();
    let dir = dst.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "gzip destination has no parent",
        )
    })?;
    let tmp = tempfile::Builder::new()
        .prefix(".data_retention-")
        .suffix(".gz.tmp")
        .tempfile_in(dir)?;
    {
        let mut src_f = BufReader::new(fs::File::open(src)?);
        let mut enc = GzEncoder::new(BufWriter::new(tmp.as_file()), Compression::default());
        io::copy(&mut src_f, &mut enc)?;
        let mut writer = enc.finish()?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }
    let (_file, tmp_path) = tmp.keep().map_err(|e| e.error)?;
    fs::rename(&tmp_path, dst)?;
    let after = fs::metadata(dst)?.len();
    Ok((before, after))
}

/// Spec 030: open a JSONL file regardless of whether it is raw or
/// gzipped. Tries `path` first (the common case: today's files are
/// uncompressed). Falls back to `path.with_extension("jsonl.gz")` if
/// the raw file is missing. Returns `None` when neither exists.
///
/// Callers iterate the returned reader with `BufRead::read_line`. The
/// trait object erases the decoder choice so downstream code does
/// not branch on file extension.
///
/// Used by downstream reader modules (reader.rs, future dashboard
/// warm-tier fallback). `#[allow(dead_code)]` scopes the warning to
/// the current release window - wiring into `reader::read_new_entries`
/// is a separate PR because that path uses byte offsets which gzip
/// streams do not support.
#[allow(dead_code)]
pub fn open_jsonl_or_gz(path: &Path) -> io::Result<Option<Box<dyn BufRead>>> {
    if path.exists() {
        let f = fs::File::open(path)?;
        return Ok(Some(Box::new(BufReader::new(f))));
    }
    let gz_path: PathBuf = if path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e == "jsonl")
        .unwrap_or(false)
    {
        path.with_extension("jsonl.gz")
    } else {
        let mut p = path.as_os_str().to_os_string();
        p.push(".gz");
        PathBuf::from(p)
    };
    if gz_path.exists() {
        let f = fs::File::open(&gz_path)?;
        let reader: Box<dyn Read> = Box::new(GzDecoder::new(f));
        return Ok(Some(Box::new(BufReader::new(reader))));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DataRetentionConfig;
    use chrono::Duration;
    use std::fs::File;
    use std::io::Write;

    fn write_dated_file(dir: &Path, prefix: &str, suffix: &str, date: NaiveDate) {
        let name = format!("{prefix}{}{suffix}", date.format("%Y-%m-%d"));
        let mut f = File::create(dir.join(name)).unwrap();
        writeln!(f, "test").unwrap();
    }

    #[test]
    fn removes_files_beyond_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();

        // events: keep 7 days - write one 8 days old (should be removed)
        let old = today - Duration::days(8);
        write_dated_file(tmp.path(), "events-", ".jsonl", old);

        // events: write one 6 days old (should be kept)
        let recent = today - Duration::days(6);
        write_dated_file(tmp.path(), "events-", ".jsonl", recent);

        let cfg = DataRetentionConfig::default();
        let removed = cleanup(tmp.path(), &cfg);

        assert_eq!(removed, 1, "only the 8-day-old file should be removed");
        assert!(!tmp
            .path()
            .join(format!("events-{}.jsonl", old.format("%Y-%m-%d")))
            .exists());
        assert!(tmp
            .path()
            .join(format!("events-{}.jsonl", recent.format("%Y-%m-%d")))
            .exists());
    }

    #[test]
    fn respects_decisions_longer_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();

        // decisions: default keep 90 days - write one 60 days old (should be kept)
        let recent = today - Duration::days(60);
        write_dated_file(tmp.path(), "decisions-", ".jsonl", recent);

        let cfg = DataRetentionConfig::default();
        let removed = cleanup(tmp.path(), &cfg);

        assert_eq!(removed, 0);
        assert!(tmp
            .path()
            .join(format!("decisions-{}.jsonl", recent.format("%Y-%m-%d")))
            .exists());
    }

    #[test]
    fn prunes_old_mesh_signals_forensic_log() {
        // Regression: mesh-signals-<date>.jsonl (innerwarden-mesh
        // `append_signal_log` forensic trail) was absent from the retention
        // sweep and accumulated unbounded on prod (observed 18 days / 1.3MB)
        // while its sibling mesh_advisory_suppressions- was pruned. It is a
        // write-only forensic log (no reader → stays JSONL, not SQLite),
        // retained on the decisions horizon; a file past that must be removed.
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        let cfg = DataRetentionConfig::default();
        let old = today - Duration::days(cfg.decisions_keep_days as i64 + 5);
        write_dated_file(tmp.path(), "mesh-signals-", ".jsonl", old);

        let removed = cleanup(tmp.path(), &cfg);

        assert_eq!(removed, 1);
        assert!(!tmp
            .path()
            .join(format!("mesh-signals-{}.jsonl", old.format("%Y-%m-%d")))
            .exists());
    }

    #[test]
    fn never_removes_todays_files() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        write_dated_file(tmp.path(), "events-", ".jsonl", today);

        let cfg = DataRetentionConfig {
            events_keep_days: 0, // even with keep=0, today must survive
            ..Default::default()
        };

        let removed = cleanup(tmp.path(), &cfg);
        assert_eq!(removed, 0);
    }

    // ── Spec 030: graph-snapshot file pruning ────────────────────────

    #[test]
    fn removes_old_graph_snapshot_files() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();

        // default: keep 3 days. Write files at 0, 2, 4, 6 days old.
        for d in [0, 2, 4, 6] {
            write_dated_file(
                tmp.path(),
                "graph-snapshot-",
                ".json",
                today - Duration::days(d),
            );
        }

        let cfg = DataRetentionConfig::default();
        let removed = cleanup(tmp.path(), &cfg);

        assert_eq!(removed, 2, "files at 4 and 6 days old should be removed");
        assert!(tmp
            .path()
            .join(format!("graph-snapshot-{}.json", today.format("%Y-%m-%d")))
            .exists());
        assert!(tmp
            .path()
            .join(format!(
                "graph-snapshot-{}.json",
                (today - Duration::days(2)).format("%Y-%m-%d")
            ))
            .exists());
    }

    // ── Spec 030: gzip compression + transparent read ────────────────

    fn write_dated_file_with_content(
        dir: &Path,
        prefix: &str,
        suffix: &str,
        date: NaiveDate,
        content: &str,
    ) {
        let name = format!("{prefix}{}{suffix}", date.format("%Y-%m-%d"));
        let mut f = File::create(dir.join(name)).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn gzip_sweep_compresses_old_jsonl_and_removes_raw() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        let old_date = today - Duration::days(10);

        let content = "line-1\nline-2\nline-3\n".repeat(100); // compressible
        write_dated_file_with_content(tmp.path(), "events-", ".jsonl", old_date, &content);

        let cfg = DataRetentionConfig {
            warm_gzip_days: 7,
            ..Default::default()
        };
        let (compressed, saved) = gzip_warm_jsonl(tmp.path(), &cfg);

        assert_eq!(compressed, 1);
        assert!(saved > 0, "gzip should reduce size");

        let raw = tmp
            .path()
            .join(format!("events-{}.jsonl", old_date.format("%Y-%m-%d")));
        let gz = tmp
            .path()
            .join(format!("events-{}.jsonl.gz", old_date.format("%Y-%m-%d")));
        assert!(!raw.exists(), "raw file must be removed after compress");
        assert!(gz.exists(), "gz file must exist");
    }

    #[test]
    fn gzip_sweep_leaves_recent_jsonl_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        let recent = today - Duration::days(2);

        write_dated_file_with_content(tmp.path(), "events-", ".jsonl", recent, "line\n");

        let cfg = DataRetentionConfig {
            warm_gzip_days: 7,
            ..Default::default()
        };
        let (compressed, _) = gzip_warm_jsonl(tmp.path(), &cfg);

        assert_eq!(compressed, 0, "recent file must not be compressed");
        assert!(tmp
            .path()
            .join(format!("events-{}.jsonl", recent.format("%Y-%m-%d")))
            .exists());
    }

    #[test]
    fn gzip_sweep_disabled_when_warm_gzip_days_is_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        write_dated_file_with_content(
            tmp.path(),
            "events-",
            ".jsonl",
            today - Duration::days(30),
            "line\n",
        );
        let cfg = DataRetentionConfig {
            warm_gzip_days: 0,
            ..Default::default()
        };
        let (compressed, _) = gzip_warm_jsonl(tmp.path(), &cfg);
        assert_eq!(compressed, 0);
    }

    #[test]
    fn open_jsonl_or_gz_reads_raw_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("events-2026-04-01.jsonl");
        let mut f = File::create(&path).unwrap();
        writeln!(f, "raw-line-1").unwrap();
        writeln!(f, "raw-line-2").unwrap();
        drop(f);

        let reader = open_jsonl_or_gz(&path)
            .unwrap()
            .expect("reader must be Some");
        let lines: Vec<String> = reader.lines().collect::<Result<_, _>>().unwrap();
        assert_eq!(lines, vec!["raw-line-1", "raw-line-2"]);
    }

    #[test]
    fn open_jsonl_or_gz_falls_back_to_gz() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        let old_date = today - Duration::days(10);
        let raw_path = tmp
            .path()
            .join(format!("events-{}.jsonl", old_date.format("%Y-%m-%d")));
        let mut f = File::create(&raw_path).unwrap();
        writeln!(f, "gz-line-a").unwrap();
        writeln!(f, "gz-line-b").unwrap();
        drop(f);

        // Run the sweep to produce the .gz and delete the raw.
        let cfg = DataRetentionConfig {
            warm_gzip_days: 7,
            ..Default::default()
        };
        let (compressed, _) = gzip_warm_jsonl(tmp.path(), &cfg);
        assert_eq!(compressed, 1);
        assert!(!raw_path.exists());

        // open_jsonl_or_gz is passed the raw path; it must transparently
        // fall back to the `.gz` sibling and decompress on the fly.
        let reader = open_jsonl_or_gz(&raw_path)
            .unwrap()
            .expect("reader must be Some");
        let lines: Vec<String> = reader.lines().collect::<Result<_, _>>().unwrap();
        assert_eq!(lines, vec!["gz-line-a", "gz-line-b"]);
    }

    #[test]
    fn open_jsonl_or_gz_returns_none_when_neither_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("events-2026-04-01.jsonl");
        assert!(open_jsonl_or_gz(&path).unwrap().is_none());
    }

    #[test]
    fn gzip_sweep_cleans_up_stale_raw_when_gz_already_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        let old_date = today - Duration::days(10);

        // Simulate a mid-flight interruption: both raw and gz exist.
        write_dated_file_with_content(tmp.path(), "events-", ".jsonl", old_date, "line\n");
        let gz_path = tmp
            .path()
            .join(format!("events-{}.jsonl.gz", old_date.format("%Y-%m-%d")));
        let mut gz = File::create(&gz_path).unwrap();
        gz.write_all(b"existing-gz").unwrap();
        drop(gz);

        let cfg = DataRetentionConfig {
            warm_gzip_days: 7,
            ..Default::default()
        };
        let (compressed, _) = gzip_warm_jsonl(tmp.path(), &cfg);

        // No new compression happened; the stale raw was cleaned up.
        assert_eq!(compressed, 0);
        assert!(!tmp
            .path()
            .join(format!("events-{}.jsonl", old_date.format("%Y-%m-%d")))
            .exists());
        assert!(gz_path.exists());
    }

    #[test]
    fn cleanup_prunes_both_raw_and_gz_past_retention() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        let old = today - Duration::days(40); // past default events_keep_days=7

        write_dated_file(tmp.path(), "events-", ".jsonl", old);
        write_dated_file(tmp.path(), "events-", ".jsonl.gz", old);

        let cfg = DataRetentionConfig::default();
        let removed = cleanup(tmp.path(), &cfg);

        assert_eq!(removed, 2, "both raw and gz should be pruned together");
    }

    // ── Error / edge paths ───────────────────────────────────────────

    #[test]
    fn cleanup_returns_zero_when_data_dir_does_not_exist() {
        // Non-existent data_dir must not panic; the function should
        // log a warning and return 0. This covers the `read_dir` err
        // branch at the top of `cleanup`.
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let cfg = DataRetentionConfig::default();
        assert_eq!(cleanup(&missing, &cfg), 0);
    }

    #[test]
    fn gzip_sweep_returns_zero_when_data_dir_does_not_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let cfg = DataRetentionConfig {
            warm_gzip_days: 1,
            ..Default::default()
        };
        assert_eq!(gzip_warm_jsonl(&missing, &cfg), (0, 0));
    }

    #[test]
    fn gzip_sweep_ignores_files_that_do_not_match_any_pattern() {
        let tmp = tempfile::tempdir().unwrap();
        let today = Local::now().date_naive();
        let old_date = today - Duration::days(30);

        // Non-warm-tier filename (no matching prefix): the sweep
        // should skip it entirely even though the date is "old".
        let name = format!("random-{}.log", old_date.format("%Y-%m-%d"));
        let mut f = File::create(tmp.path().join(&name)).unwrap();
        f.write_all(b"not a warm-tier file\n").unwrap();

        let cfg = DataRetentionConfig {
            warm_gzip_days: 7,
            ..Default::default()
        };
        let (compressed, _) = gzip_warm_jsonl(tmp.path(), &cfg);
        assert_eq!(compressed, 0);
        assert!(tmp.path().join(&name).exists());
    }

    #[test]
    fn gzip_sweep_ignores_files_with_unparseable_date() {
        let tmp = tempfile::tempdir().unwrap();
        // events-foo.jsonl matches the prefix+suffix but "foo" is
        // not a YYYY-MM-DD date; the parse_from_str branch returns
        // Err and the iteration continues without compressing.
        let path = tmp.path().join("events-foo.jsonl");
        let mut f = File::create(&path).unwrap();
        f.write_all(b"line\n").unwrap();
        let cfg = DataRetentionConfig {
            warm_gzip_days: 7,
            ..Default::default()
        };
        let (compressed, _) = gzip_warm_jsonl(tmp.path(), &cfg);
        assert_eq!(compressed, 0);
        assert!(path.exists());
    }

    #[test]
    fn open_jsonl_or_gz_handles_non_jsonl_suffix_fallback() {
        // When the caller passes a path whose extension is not
        // ".jsonl", the fallback appends ".gz" to the full path
        // rather than replacing the extension. This covers the
        // non-jsonl branch of `open_jsonl_or_gz`.
        let tmp = tempfile::tempdir().unwrap();
        let raw = tmp.path().join("telemetry.log");
        let gz = tmp.path().join("telemetry.log.gz");

        // Only the `.gz` exists; the raw `.log` is missing.
        let mut gz_writer = GzEncoder::new(File::create(&gz).unwrap(), Compression::default());
        gz_writer.write_all(b"log-line-1\nlog-line-2\n").unwrap();
        gz_writer.finish().unwrap();

        let reader = open_jsonl_or_gz(&raw).unwrap().expect("fallback found");
        let lines: Vec<String> = reader.lines().collect::<Result<_, _>>().unwrap();
        assert_eq!(lines, vec!["log-line-1", "log-line-2"]);
    }

    // ── filestore retention ────────────────────────────────────────

    fn write_shard_file(root: &Path, shard: &str, name: &str, bytes: &[u8], age_days: u64) {
        let dir = root.join(shard);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        // `chrono::Duration` shadows `std::time::Duration` inside this
        // test module, so qualify the std variant explicitly.
        let mtime = SystemTime::now()
            - std::time::Duration::from_secs(age_days.saturating_mul(86400).saturating_add(60));
        filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(mtime)).unwrap();
    }

    #[test]
    fn filestore_age_prune_removes_old_files_only() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("filestore").join("extracted");

        write_shard_file(&root, "aa", "aa_old.bin", &[0u8; 1024], 40);
        write_shard_file(&root, "bb", "bb_fresh.bin", &[0u8; 1024], 5);

        let cfg = DataRetentionConfig {
            filestore_keep_days: 30,
            filestore_max_size_mb: 0, // size cap disabled
            ..Default::default()
        };
        let (removed, bytes) = cleanup_filestore(tmp.path(), &cfg);

        assert_eq!(removed, 1);
        assert_eq!(bytes, 1024);
        assert!(!root.join("aa").exists(), "empty shard should be pruned");
        assert!(root.join("bb").join("bb_fresh.bin").exists());
    }

    #[test]
    fn filestore_size_cap_evicts_oldest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("filestore").join("extracted");

        // Three 1 MB files, all within keep window. Cap at 2 MB.
        write_shard_file(&root, "aa", "oldest.bin", &vec![1u8; 1_048_576], 3);
        write_shard_file(&root, "bb", "middle.bin", &vec![2u8; 1_048_576], 2);
        write_shard_file(&root, "cc", "newest.bin", &vec![3u8; 1_048_576], 1);

        let cfg = DataRetentionConfig {
            filestore_keep_days: 0, // age pass disabled
            filestore_max_size_mb: 2,
            ..Default::default()
        };
        let (removed, _) = cleanup_filestore(tmp.path(), &cfg);

        assert_eq!(removed, 1, "only one file needed to get under 2 MB cap");
        assert!(
            !root.join("aa").join("oldest.bin").exists(),
            "oldest file evicted first"
        );
        assert!(root.join("bb").join("middle.bin").exists());
        assert!(root.join("cc").join("newest.bin").exists());
    }

    #[test]
    fn filestore_noop_when_root_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = DataRetentionConfig::default();
        let (removed, bytes) = cleanup_filestore(tmp.path(), &cfg);
        assert_eq!(removed, 0);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn filestore_zero_values_disable_both_passes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("filestore").join("extracted");
        write_shard_file(&root, "aa", "ancient.bin", &[0u8; 1024], 999);

        let cfg = DataRetentionConfig {
            filestore_keep_days: 0,
            filestore_max_size_mb: 0,
            ..Default::default()
        };
        let (removed, _) = cleanup_filestore(tmp.path(), &cfg);
        assert_eq!(removed, 0);
        assert!(root.join("aa").join("ancient.bin").exists());
    }

    // Spec 037 I-13 follow-up #2: read_data_dir_for_monthly_cleanup_or_warn

    #[test]
    fn read_data_dir_for_monthly_cleanup_or_warn_returns_some_silently_on_real_dir() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let result = read_data_dir_for_monthly_cleanup_or_warn(dir.path());
        assert!(result.is_some(), "real directory must yield Some");

        let captured = crate::test_util::drain_capture();
        assert!(
            !captured.contains("data retention monthly cleanup read_dir failed"),
            "happy path must not emit warn, got: {captured}"
        );
    }

    #[test]
    fn read_data_dir_for_monthly_cleanup_or_warn_returns_none_and_warns_on_io_failure() {
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let blocking_file = dir.path().join("blocker");
        std::fs::write(&blocking_file, b"i am a regular file").expect("seed blocker");
        // read_dir on a regular file path returns NotADirectory (Linux)
        // which is non-NotFound and triggers the warn arm.
        let result = read_data_dir_for_monthly_cleanup_or_warn(&blocking_file);
        assert!(result.is_none(), "io-failure must yield None");

        let captured = crate::test_util::drain_capture();
        assert!(
            captured.contains("data retention monthly cleanup read_dir failed"),
            "io-failure warn missing, got: {captured}"
        );
        assert!(
            captured.contains("error="),
            "error field missing, got: {captured}"
        );
    }
}
