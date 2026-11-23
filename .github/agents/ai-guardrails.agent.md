---
name: ai-guardrails
description: Sync this repository's AI guardrails after ai/guardrails.md changes. Use only while those instruction files are being edited.
---

# AI guardrails

The startup guardrail is already loaded. Do not restate it.

Edit `ai/guardrails.md`, then run `python scripts/sync_ai_guardrails.py`. Do not hand-edit the generated Cursor rule, the Copilot instructions, or this agent. Do not add a root `AGENTS.md` that repeats the startup text.
