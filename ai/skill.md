---
name: ai-guardrails
description: Edit or sync this repository's AI guardrails. Use when changing ai/guardrails.md, the Cursor rule, Copilot instructions, or scripts/sync_ai_guardrails.py.
---

# AI guardrails

Cursor and VS Code already load the startup guardrail. Do not paste it into this skill, and do not read `ai/quality-sources.md` during an ordinary task.

Edit only the sources in `ai/`: `guardrails.md` (startup guardrail), `skill.md` (this skill), and `agent.md` (the custom agent). Then run `python scripts/sync_ai_guardrails.py` with the checkout's `.venv` interpreter. Use `--check` to confirm the generated copies match. The script overwrites `.github/copilot-instructions.md`, `.cursor/rules/ai-guardrails.mdc`, both `ai-guardrails` agent files, and both `ai-guardrails/SKILL.md` files, so never hand-edit them. Then run `tests/test_ai_guardrails.py`, which checks the sync and phrases the guardrail must keep. Keep each rule stated once, verify any command or code fact against the repository before writing it, and do not add a root `AGENTS.md` that repeats the startup text.
