# Integration Recipes

This directory contains **integration recipes** - declarative specifications
that describe how to connect an external security tool to InnerWarden.

A recipe is precise enough that a human, or an AI assistant, can generate a
working InnerWarden collector from it without reading the external tool's
source code.

For the full specification, generation guide, and community contribution flow,
see [`docs/integration-recipes.md`](../docs/integration-recipes.md).

## Available Recipes

There are currently no bundled external security-tool *collector* recipes in
this directory.

For **integration recipes that drive Inner Warden's Agent Guard API from an
external automation tool**, see [`docs/integration-recipes/`](../docs/integration-recipes/):

- [n8n](../docs/integration-recipes/n8n-agent-guard.md) — call
  `GET /api/agent/security-context` and `POST /api/agent/check-command` from an
  n8n workflow, with an importable example that halts when the threat level is
  elevated.
- [Claude Code](../docs/integration-recipes/claude-code-agent-guard.md) — wire a
  fail-closed PreToolUse hook so every shell command Claude Code proposes is
  screened by `POST /api/agent/check-command` before it runs, paired with the
  [`claude-code-protection`](../modules/claude-code-protection/docs/README.md)
  module for kernel-level execution monitoring.

## Adding a Recipe

You do not need to write Rust code to add a recipe. A recipe alone - describing
the tool's output format, field mappings, and entity extraction - is a
valuable contribution that lets anyone generate the collector later.

See [`docs/integration-recipes.md`](../docs/integration-recipes.md) for the
recipe format reference.
