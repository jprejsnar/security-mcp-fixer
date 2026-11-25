# Quality sources

This file lists the public sources behind the startup guardrail. Cursor and VS Code do not load it. Follow the live page when it disagrees with that guardrail.

## Python

Sites: https://www.python.org/ and https://docs.python.org/

- Prefer the obvious, readable form. Explicit is better than implicit. Simple is better than nested. An error may stay out of the log only when the startup guardrail already records it in the result or in a warning. If a fact is ambiguous, look it up instead of guessing. That is PEP 20: https://peps.python.org/pep-0020/
- Match this repository's Ruff settings. Do not restyle unrelated code to satisfy a general style page. PEP 8 is the public baseline: https://peps.python.org/pep-0008/
- Use the standard library and current language docs for the module you touch. Check the versionchanged notes. Do not adopt syntax or APIs that need a newer interpreter than 3.11.
- Name exceptions you handle. Close files you open. Pass `encoding` for text. Keep public behavior stable when a cleanup is possible without a rewrite.
- Do not call a deprecated or scheduled-for-removal Python API. Use the current replacement on https://docs.python.org.
- Write dates and times as ISO 8601. `date.isoformat()` and timezone-aware `datetime.isoformat()` are the normal forms. A file or branch name may use `YYYY-MM-DD` or the basic form `YYYY-MM-DDTHHMMSSZ` when a colon is not legal.

## MCP servers

Site: https://github.com/helopilot18/cursor-mcp-servers/blob/main/MCP_SERVER_GUIDE.md

- An MCP server exposes tools, and may expose resources and prompts. This repository's product is its Python tools.
- A tool needs a stable name, a description of what it returns, validated inputs, and a structured error. Do not catch an error and return success.
- The client launches the server with an absolute command. stdio traffic stays on stdout. Diagnostics stay on stderr.
- Do not call a deprecated or scheduled-for-removal MCP API. Use the current Python SDK surface, including `MCPServer` rather than the removed `FastMCP` import.
- The linked guide demonstrates a TypeScript LiteMCP sample. Use it for those protocol rules only. Do not port this server to Node, add a second transport, or replace the Python SDK because that sample uses LiteMCP.

## GitLab

Site: https://docs.gitlab.com/

- Read findings and dismiss false positives through the current GraphQL vulnerability API. Do not call the deprecated vulnerability REST API or a removed dismissal mutation.

## Cursor plugins and Copilot

Sites: https://cursor.com/docs/plugins and https://cursor.com/docs/reference/plugins

- Persistent guidance belongs in `.cursor/rules/ai-guardrails.mdc` (`alwaysApply: true`) and in `.github/copilot-instructions.md`. Both are generated from `ai/guardrails.md`; the skill and agent copies are generated from `ai/skill.md` and `ai/agent.md`. Do not also put that text in a root `AGENTS.md`; Cursor and VS Code would load the extra copy on top of the file each editor already applies.
- Skills and custom agents explain how to edit the guardrail. They are not a second startup copy.
- A plugin may bundle rules, skills, agents, commands, and MCP servers. Do not publish secrets in a plugin manifest. Declare names only, and let the user supply values.
- Do not install another plugin that repeats this repository's guardrails.
