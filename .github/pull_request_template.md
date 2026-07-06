## Summary

## Type

- [ ] Bug fix
- [ ] New feature / capability
- [ ] New module (fill in the Module section below)
- [ ] Refactor / cleanup
- [ ] Docs / config only

## Validation

- [ ] All commits signed off (`git commit -s`) — see [DCO](../DCO)
- [ ] `make check`
- [ ] `make test`
- [ ] `make scenario-qa` — if this PR touches anything that could change incident / telegram / block volumes

## Risk

- [ ] No config or schema changes
- [ ] Includes config or schema changes
- [ ] Includes responder or privileged behavior changes
- [ ] Includes dashboard or investigation UX changes

## Spec 024 regression gate

If this PR changes a gate threshold, cooldown, responder behaviour, notification policy, or any code on the incident → decision → notification → block path, it can silently drift the volumes asserted in `testdata/scenarios/`. Before merging:

- [ ] I ran `make scenario-qa` locally; all 7 scenarios still pass (or I updated the matching `expected.json` envelope and explained why in the PR body)
- [ ] OR this PR is docs / tests / CI only and cannot affect scenario volumes (tick this and skip the one above)

## Documentation

- [ ] No documentation updates needed
- [ ] Updated public docs
- [ ] Updated maintainer docs

---

## Module submission (fill in only for new modules)

**Module ID:** `my-module`
**Tier:** open / premium

### Checklist

- [ ] `modules/<id>/module.toml` - valid TOML, all required fields present, kebab-case ID
- [ ] `modules/<id>/docs/README.md` - has `## Overview`, `## Configuration`, `## Security` sections
- [ ] `modules/<id>/tests/` - at least one `.rs` test file (or `builtin = true` with tests in `crates/`)
- [ ] `[[rules]]` entries have `auto_execute = false` (default safe posture)
- [ ] Skills use separate `.arg()` calls - no `.arg(format!(...))` interpolation
- [ ] Skills check `dry_run` before executing any privileged command
- [ ] `[security].allowed_commands` lists every binary the module invokes
- [ ] `innerwarden module validate --strict modules/<id>` passes locally
