# AI guardrails

This is the startup guardrail. Change it only in `ai/guardrails.md`, then run `python scripts/sync_ai_guardrails.py`. Cursor injects `.cursor/rules/ai-guardrails.mdc` on every chat because `alwaysApply` is true. VS Code Copilot injects `.github/copilot-instructions.md` on every chat. Do not add a root `AGENTS.md` with this text: Cursor would inject it beside that rule, and VS Code would inject it beside the Copilot file. Skills and custom agents are not injected at startup. `ai/quality-sources.md` is the bibliography and is not injected.

## Compaction

- Keep the session small. Do not re-read a file, repeat a tool result, or restate work already in context.
- Search first. Read only the lines a change needs.
- Do not paste logs, diffs, or reports into the reply.
- Do not call `get_run_status` with `include_audit_details=True` except to recover a lost audit.
- Do not add another always-on rule, skill, agent, or plugin that repeats this text.

## This repository

- Stay on the Python 3.11 syntax floor. Follow `pyproject.toml` and the Arrange-Act-Assert test comments. Before using a Python API, read its current page, including versionchanged notes. Do not adopt an API that needs a newer interpreter than 3.11.
- This server is the Python package `gitlab_security_mcp` on stdio. Do not rewrite it as a Node or LiteMCP server.
- stdout is the MCP protocol. Logs go to stderr. The editor must launch this server with an absolute command.
- Do not commit, push, or dismiss a GitLab finding unless the user asks. Human checkboxes start unchecked.
- Never call a deprecated or scheduled-for-removal API in MCP, Python, or GitLab. Use the current replacement from the MCP Python SDK docs, https://docs.python.org, or https://docs.gitlab.com. When a live page disagrees with this file, follow the live page.
- Silence an error only when the returned result already reports it, or when it is expected and a warning names the operation. Keep public behavior stable when a smaller cleanup can do that.
- Do not leave magic numbers or magic strings in code. Name a constant for a limit, timeout, status, path fragment, or message. A literal that is only its own value, such as `0`, `1`, or `""`, can stay inline.
- Write dates and times as ISO 8601 only. Use `date.isoformat()` or a timezone-aware `datetime.isoformat()`. In a file or branch name, use `YYYY-MM-DD` or basic `YYYY-MM-DDTHHMMSSZ` because a colon is not a legal Windows file name.
- Name the exceptions you handle. Close files you open. Pass `encoding` when you read or write text. Do not restyle unrelated code.
- An MCP tool needs a stable name, a description of what it returns, validated inputs, and a structured error. Do not catch an error and return success. Use `MCPServer`. Do not import the removed `FastMCP`, add a second transport, or publish a secret in a plugin manifest.
- Read GitLab findings and dismiss false positives with the current GraphQL vulnerability API. Do not call the deprecated vulnerability REST API or a removed dismissal mutation.
- After a code change, fix, or enhancement, update `README.md` in the same change so its current-operation text, diagrams, and artifact tables match the code. Leave dated historical release notes as history.

## Do not reintroduce

These defects were fixed in this repository. A change that brings one back is a bug.

- One MCP process per editor window. Key engines by the resolved checkout `Path`. A tool call with no `repo_root` is an error when more than one checkout is active. The checkout that contains the process wins over a user-level `REPO_ROOT`. Git origin names the GitLab project; a blank `GITLAB_PROJECT_ID` or a blank tool `project_id` is not a project id.
- `Engine.repo_root` is a `Path`. Progress tasks are keyed by that `Path`. `drop_checkout` must receive the same path object the publisher used. Close owned HTTP clients, then drop that checkout's in-memory progress. Cancel audit heartbeats before closing engines, and remove the heartbeat when the audit is no longer active. Do not close an injected client. Do not close a command pipe while a reader is blocked in `os.read`.
- Logs go to stderr only. There is no home log file. The same redacted lines are kept in a process temp spool and copied into the end-of-run zip as `server.log`, beside `audit.jsonl`, `http-timings.jsonl`, and the command logs. `log_unexpected` writes a warning with the operation, the exception text, and the traceback for every failure a handler turns into a result, including `OSError`, `ValueError`, `RuntimeError`, `SubprocessError`, and `httpx.HTTPError`. Dedicated warnings still cover command failures and their log paths, reader failures, an unreadable Git revision, an HTTP timing write, stderr setup, corporate DNS, checkout of `main`, a pull of `main`, pnpm preparation, an unreadable git diff, Git work-tree verification, security-branch preparation, and the first process-memory probe failure.
- Keep editor identification and progress-extension install in separate handlers. Install on a daemon thread so the MCP handshake is not blocked by the install lock. Skip install under pytest. Support Windows, macOS, and Linux, and both VS Code and Cursor: `/proc` or `ps`, `msvcrt` or `fcntl`, and `cli.js` beside the binary, in `Contents/Resources`, or above a `bin` directory. Keep every named process in the parent map. Store an image only for an editor with a path. Do not cut `Code - Insiders` or any other editor path at the first space. Strip one pair of shell quotes around a `ps` executable. Match the longest macOS editor basename.
- The progress view must not call `realpath` on an arbitrary checkout, a UNC path, or an empty path. A disconnected mapped drive blocks the extension host. Resolve only the open workspace folder. Strip a Windows `\\?\` or `\\?\UNC\` prefix before comparing paths. Compare Linux paths with their original case. Lowercase Windows and macOS keys. A trailing separator must still match. After a stale mirror is dropped, still render. Record a final-report preview before showing it, and do not delete that key when the preview fails.
- The status bar uses the `RUNNING` job number from the jobs array. Use `completed + 1` only when `completed` is an integer and the result is at most 7. A null count is not job 1.
- `editor-progress` is the checkout source. `gitlab_security_mcp/editor_progress` is the packaged copy. Tests compare file bytes. Do not treat the hyphen and the underscore as a packaging bug. After editing `editor-progress/extension.js` or its README, copy those bytes into the package tree.
- Token compaction stays on. Do not add a file watcher or a VS Code task watcher to sync these AI files. This script is the sync. Do not add a recursive audit loop or an automatic second pass. Human checkboxes start unchecked. Package-only remediation does not run unit or integration tests.
