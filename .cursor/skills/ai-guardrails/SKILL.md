---
name: ai-guardrails
description: Edit or sync this repository's AI guardrails. Use when changing ai/guardrails.md, the Cursor rule, Copilot instructions, or scripts/sync_ai_guardrails.py.
---

# AI guardrails

Cursor and VS Code already load the startup guardrail. Do not paste it into this skill, and do not read `ai/quality-sources.md` during an ordinary task.

When the guardrail changes, edit `ai/guardrails.md`, then run `python scripts/sync_ai_guardrails.py`. Use `--check` to confirm the generated copies match. Do not hand-edit `.cursor/rules/ai-guardrails.mdc` or `.github/copilot-instructions.md`. Do not add a root `AGENTS.md` that repeats the startup text.
