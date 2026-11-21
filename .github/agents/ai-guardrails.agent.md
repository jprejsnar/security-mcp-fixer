---
name: ai-guardrails
description: Repository AI guardrails for compaction and code quality. Apply to every task in this repository.
---

# AI guardrails

These rules load at startup for Cursor and Copilot. Change them only in `ai/guardrails.md`, then run `python scripts/sync_ai_guardrails.py`. The copies under `.cursor/` and `.github/` must stay identical to this file.

## Compaction

- Keep the session small. Do not re-read a file, repeat a tool result, or restate work already in context.
- Search first. Read only the lines a change needs.
- Do not paste logs, diffs, or reports into the reply.
- Do not call `get_run_status` with `include_audit_details=True` except to recover a lost audit.
- Do not add another always-on rule, skill, agent, or plugin that repeats this text.
- Read `ai/quality-sources.md` once before the first code change in a session. Do not read it again.

## This repository

- Stay on the Python 3.11 syntax floor. Follow `pyproject.toml` and the Arrange-Act-Assert test comments.
- This server is the Python package `gitlab_security_mcp` on stdio. Do not rewrite it as a Node or LiteMCP server.
- stdout is the MCP protocol. Logs go to stderr.
- Do not commit, push, or dismiss a GitLab finding unless the user asks. Human checkboxes start unchecked.
- Before changing a Python API, read its current page on https://docs.python.org.
- Do not leave magic numbers or magic strings in code. Name a constant for a limit, timeout, status, path fragment, or message. A literal that is only its own value, such as `0`, `1`, or `""`, can stay inline.
