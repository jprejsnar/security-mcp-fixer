---
name: ai-guardrails
description: Sync this repository's AI guardrails after ai/guardrails.md changes. Use only while those instruction files are being edited.
---

# AI guardrails

The startup guardrail is already loaded. Do not restate it.

Edit `ai/guardrails.md`, `ai/skill.md`, or `ai/agent.md`, then run `python scripts/sync_ai_guardrails.py` with the checkout's `.venv` interpreter and confirm with `--check`. Never hand-edit a generated copy: the Cursor rule, the Copilot instructions, the skill copies, or this agent. Run `tests/test_ai_guardrails.py`. State each rule once, verify every command or code fact against the repository, and do not add a root `AGENTS.md` that repeats the startup text.
