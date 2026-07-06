# Contributing to InnerWarden

Welcome — and thank you for considering a contribution. InnerWarden is a Linux/macOS security agent built in Rust; the project is open to detectors, integrations, dashboard polish, documentation, and test coverage. This guide gets you from "I want to help" to "my PR is merged" without surprises.

If you have a question that isn't answered below, open a [Discussion](https://github.com/InnerWarden/innerwarden/discussions) or comment on an existing issue.

---

## Quick start

```bash
# 1. Fork + clone
gh repo fork InnerWarden/innerwarden --clone --remote
cd innerwarden

# 2. Toolchain (rustup picks the pinned version from rust-toolchain.toml if present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup component add rustfmt clippy

# 3. Build + test
make test       # all unit + integration tests
make build      # debug binaries for sensor / agent / ctl

# 4. Try the dashboard locally
cargo run -p innerwarden-agent -- --data-dir ./data --dashboard
# open https://127.0.0.1:8787 (self-signed HTTPS; set INNERWARDEN_DASHBOARD_USER + INNERWARDEN_DASHBOARD_PASSWORD_HASH to require auth, open-access if unset)
```

If `make test` passes on a fresh clone, your environment is good to go.

---

## Where to find your first task

We label issues so you can find work that matches your time and experience:

- [**`good first issue`**](https://github.com/InnerWarden/innerwarden/labels/good%20first%20issue) — well-scoped, no architectural decisions required, mentor-friendly. Most are test-coverage tasks (one file, ~50–500 lines, follow an existing pattern). **Start here.**
- [**`help wanted`**](https://github.com/InnerWarden/innerwarden/labels/help%20wanted) — larger work, may need design discussion in the issue first.
- [**`test`**](https://github.com/InnerWarden/innerwarden/labels/test) — coverage / regression-test work. Often overlaps with `good first issue`.
- [**`documentation`**](https://github.com/InnerWarden/innerwarden/labels/documentation) — wiki pages, README sections, integration recipes.
- [**`enhancement`**](https://github.com/InnerWarden/innerwarden/labels/enhancement) — new features. Open a discussion or comment on the issue before writing code so we can avoid wasted effort.

If you find an issue you want to work on, **leave a comment** so we can avoid two people building the same thing.

---

## What kind of contributions are most useful

In rough order of how often we merge them:

1. **Test coverage** — every PR that raises a file from <80% to ≥80% closes a labelled issue. Patterns to follow are the inline `#[cfg(test)] mod tests` blocks throughout `crates/*/src/`. The `[help wanted, good first issue, test]` triple-label issues are pre-scoped for you.
2. **New detectors** — `crates/sensor/src/detectors/` accepts new detection rules. Read [Module Authoring](https://github.com/InnerWarden/innerwarden/wiki/Module-Authoring) for the full template.
3. **Integration recipes** — see `integrations/README.md` for the format. None ship in-tree yet, so new recipes (Slack, Telegram, PagerDuty, ...) are a well-scoped place to start.
4. **Dashboard polish** — UX improvements, accessibility fixes, lucide icon standardization. Frontend lives in `crates/agent/src/dashboard/frontend/` (vanilla JS + CSS, no framework).
5. **Documentation** — wiki pages, README clarifications, code-level rustdoc.
6. **Bug fixes** — small fixes welcome; for non-trivial bugs include a regression test.

---

## Project values

InnerWarden is a *defensive* security tool. Please optimise for:

- **Deterministic sensor behaviour** — no HTTP, no LLM, no AI in the sensor crate. Detectors fail-open on errors and never crash the process.
- **Conservative defaults** — `dry_run = true`, observe-only, audit-everything. Auto-execution is opt-in.
- **Bounded, reversible, audited responses** — every skill has a TTL, a revert path, and a hash-chained decision log entry.
- **Explicit documentation for behavioural changes** — anything user-visible gets a note in `CHANGELOG.md` plus a wiki page update if applicable.

---

## Development workflow

Our pipeline rejects PRs that fail any of these gates, so run them locally first:

```bash
make test                               # all unit + integration tests
cargo fmt --check                       # rustfmt with default settings
cargo clippy --tests -- -D warnings     # no new warnings allowed
```

For dashboard frontend changes there is no JS test runner, but every visible behaviour gets a **Rust anchor test** that does substring-grep on the bundled HTML/CSS/JS via `include_str!`. See `crates/agent/src/dashboard/mod.rs` test module for the pattern. **A bundle-anchor regression test is required for any dashboard contract you don't want a future refactor to silently break.**

For detectors and response skills there are scenario-replay tests in `testdata/scenarios/`. New detectors should land with a fixture that exercises both the positive (true positive) and negative (regression / false positive) paths.

---

## Code style

Most things are enforced by `rustfmt` and `clippy`; the conventions below are project-specific:

- **Commits in English**, [Conventional Commits](https://www.conventionalcommits.org/) format: `feat(area): description`, `fix(area): description`, `test(area): description`, `docs: description`. Area is a crate or subsystem (`agent`, `sensor`, `ctl`, `dashboard`, etc.).
- **Branches**: short slug, e.g. `feat/splunk-hec-sink`, `test/ctl-mesh-coverage`, `fix/dashboard-blocked-count`.
- **I/O errors in sinks**: log with `warn!`, do not propagate with `?`. Sinks are best-effort.
- **`spawn_blocking`** for any synchronous file I/O inside Tokio tasks.
- **Comments**: only when the *why* is non-obvious. Don't restate what the code does.
- **No emoji in source files** — the dashboard uses inline lucide SVGs from `crates/agent/src/dashboard/frontend/js/icons.js`. Add a new icon to that module and reuse it.

Detailed rules live in the wiki: [Sensor Capabilities](https://github.com/InnerWarden/innerwarden/wiki/Sensor-Capabilities), [Agent Capabilities](https://github.com/InnerWarden/innerwarden/wiki/Agent-Capabilities), [Module Authoring](https://github.com/InnerWarden/innerwarden/wiki/Module-Authoring).

---

## Pull request checklist

Before opening a PR, confirm:

- [ ] Branch is rebased on the latest `main`.
- [ ] `make test` passes locally.
- [ ] `cargo fmt --check` reports no diffs.
- [ ] `cargo clippy --tests -- -D warnings` has no new warnings.
- [ ] If you touched user-visible behaviour, you added a regression test that would fail without the change.
- [ ] If you touched the dashboard frontend, you added a bundle-anchor test in `dashboard/mod.rs`.
- [ ] If your change affects detection or response capabilities, configuration, or operational safety guidance, the corresponding doc/wiki page is updated.
- [ ] PR description references the issue (`Closes #123`) so it auto-closes on merge.
- [ ] PR title uses Conventional Commits format.
- [ ] Every commit is signed off (`git commit -s`) per the [DCO](DCO).

---

## Documentation rule

If a change affects any of the following, update docs in the same PR:

- detection or response capabilities
- generated artifacts (events, incidents, decisions schemas)
- configuration (`agent.toml`, `sensor.toml`)
- deployment / update flow
- operational safety guidance

In practice that often means updating `README.md`, `CHANGELOG.md`, `CLAUDE.md`, or a wiki page.

---

## Reviewer expectations

- A maintainer will respond within 2–3 business days. If your PR has been open longer with no review, ping it; it has probably scrolled off the top of the queue.
- Most PRs go through 1–2 review rounds. We optimise for "small, focused, anchored" — large PRs that mix concerns get split.
- CI must be green before merge. If a check is flaky (it happens), a maintainer will rerun it; you don't need to push noop commits.

---

## Scope guidance

**Good contributions:**

- new detectors or detector improvements
- new response skills (bounded, reversible, audited)
- operational safety improvements
- test coverage and replay coverage
- documentation and setup guides
- module authoring
- dashboard UX / accessibility fixes

**Changes that need extra care — open an issue first:**

- auto-execution defaults
- new privileged response skills
- privacy-sensitive data collection
- schema-breaking output changes
- architectural rewrites (storage layer, event pipeline, AI router)
- new top-level CLI commands

If you are unsure whether a change fits the project's current direction, open an issue or draft PR first.

---

## Reporting security vulnerabilities

**Do not open a public issue for a vulnerability.** Email disclosures to the address listed in [SECURITY.md](SECURITY.md) (or, if absent, to the maintainer email on the repo profile) with details and reproduction steps. We aim to respond within 48 hours.

---

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE), the same as the rest of the project. The only in-tree crate under a different license is `crates/shield` (BUSL-1.1); every other crate is Apache-2.0.

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by:` line certifying the [Developer Certificate of Origin](DCO) — the same lightweight mechanism the Linux kernel uses. It states that you wrote the change (or have the right to submit it) under the project's license. No CLA, no paperwork: just sign your commits.

```bash
git commit -s -m "feat(sensor): my change"      # adds Signed-off-by automatically
git commit --amend -s                            # fix the last commit
git rebase --signoff origin/main                 # fix a whole branch
```

The `DCO` CI check fails any PR containing a human-authored commit without a sign-off. Bot commits (dependabot etc.) are exempt.

---

## Maintainer contact

- Lead: [@esteves-uk](https://github.com/esteves-uk)
- Discussions: https://github.com/InnerWarden/innerwarden/discussions
- Issues: https://github.com/InnerWarden/innerwarden/issues

Thank you for helping make Linux & macOS security infrastructure more accessible.
