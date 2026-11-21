# Quality sources

Read this once before the first code change. It distills the sites the project requires. Follow the live page when it disagrees with this summary.

## Python

Sites: https://www.python.org/ and https://docs.python.org/

- Prefer the obvious, readable form. Explicit is better than implicit. Simple is better than nested. Errors must not disappear unless the code silences them on purpose. If a fact is ambiguous, look it up instead of guessing. That is PEP 20: https://peps.python.org/pep-0020/
- Match this repository's Ruff settings. Do not restyle unrelated code to satisfy a general style page. PEP 8 is the public baseline: https://peps.python.org/pep-0008/
- Use the standard library and current language docs for the module you touch. Check the versionchanged notes. Do not adopt syntax or APIs that need a newer interpreter than 3.11.
- Name exceptions you handle. Close files you open. Pass `encoding` for text. Keep public behavior stable when a cleanup is possible without a rewrite.

## MCP servers

Site: https://github.com/helopilot18/cursor-mcp-servers/blob/main/MCP_SERVER_GUIDE.md

- An MCP server exposes tools, and may expose resources and prompts. This repository's product is its Python tools.
- A tool needs a stable name, a description of what it returns, validated inputs, and a structured error. Do not catch an error and return success.
- The client launches the server with an absolute command. stdio traffic stays on stdout. Diagnostics stay on stderr.
- The linked guide demonstrates a TypeScript LiteMCP sample. Use it for those protocol rules only. Do not port this server to Node, add a second transport, or replace the Python SDK because that sample uses LiteMCP.

## Cursor plugins and Copilot

Sites: https://cursor.com/docs/plugins and https://cursor.com/docs/reference/plugins

- Persistent guidance belongs in an always-apply rule and in `.github/copilot-instructions.md`. Those two copies are generated from `ai/guardrails.md`.
- Skills and agents carry the same policy, but they are not a second startup copy of a long document. Keep a skill short and point it here.
- A plugin may bundle rules, skills, agents, commands, and MCP servers. Do not publish secrets in a plugin manifest. Declare names only, and let the user supply values.
- Do not install another plugin that repeats this repository's guardrails.
