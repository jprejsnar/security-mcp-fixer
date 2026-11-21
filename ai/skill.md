---
name: ai-guardrails
description: Applies repository compaction and code-quality guardrails. Use at the start of every session and before writing, reviewing, or refactoring code in this repository.
---

# AI guardrails

The startup rule is already loaded. Before the first code change in a session, read `ai/quality-sources.md` and apply it. Do not read that file again, and do not copy it into the chat.

Use a named constant instead of a magic number or magic string. Put limits, timeouts, statuses, path fragments, and error messages in constants. Leave a literal inline only when it is the value itself, such as `0`, `1`, or `""`.

Never call a deprecated or scheduled-for-removal MCP, Python, or GitLab API. Use the current replacement from the MCP Python SDK docs, https://docs.python.org, or https://docs.gitlab.com.

Write dates and times as ISO 8601 only. Use `date.isoformat()` or a timezone-aware `datetime.isoformat()`. In a file or branch name, use `YYYY-MM-DD` or basic `YYYY-MM-DDTHHMMSSZ` because a colon is not a legal Windows file name.
