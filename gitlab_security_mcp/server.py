"""MCP tools for the local GitLab security remediation workflow."""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import json
import logging
import os
import subprocess
import sys
import threading
from collections import deque
from copy import deepcopy
from functools import partial
from pathlib import Path
from time import gmtime
from typing import Any
from uuid import uuid4

from mcp.server import MCPServer
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.elicitation import (
    AcceptedElicitation,
    CancelledElicitation,
    DeclinedElicitation,
    ElicitationResult,
    render_elicitation_schema,
)
from mcp.server.mcpserver import Context
from mcp.shared.exceptions import MCPError
from mcp.types import (
    CallToolResult,
    ElicitRequest,
    ElicitRequestFormParams,
    ElicitResult,
    InputRequiredResult,
    TextContent,
    ToolAnnotations,
)
from pydantic import BaseModel, Field, create_model

from gitlab_security_mcp import __version__, desktop_approval
from gitlab_security_mcp.ai_source_review import SourceEvidence, cited_lines
from gitlab_security_mcp.commands import progress_sink
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.util import logged_lock, redact
from gitlab_security_mcp.versions import is_major_upgrade

logger = logging.getLogger("gitlab_security_mcp")

INSTRUCTIONS = """
Local-only GitLab security remediation. One checkout per run. Pass the same
absolute repo_root when more than one checkout is active. ${workspaceFolder}
is not a path. Do not construct a separate Engine or resume from saved JSON.
A request to run gitlab-security on this repo uses this order and stops on a blocker.
Each tool description is the procedure for that step.
1. run_prechecks
2. pull_main_twice
3. create_security_branch
4. list_security_findings
5. verify_security_finding for every finding. Open the file and line GitLab
   already reported and read that code. A false-positive reason is at most
   2 everyday sentences about why the warning does not apply.
6. select_security_fixes before any remediation edit. For Windows package
   checkboxes, first collect the exact-target documentation/API/framework/license
   evidence described by qualify_package_update. Supply package_reviews keyed by
   finding ID. PACKAGE_REVIEW_REQUIRED means finish that read-only AI review and
   repeat selection with the evidence; do not invent evidence or approval.
7. qualify_package_update for each selected package update
8. apply_minimal_fix for each selected eligible fix, with no build between edits
9. generate_aaa_test only for a supported base-image change
10. run_validation_matrix once for the batch
11. complete_security_run, which offers the human approval checkboxes once
If select_security_fixes returns AWAITING_HUMAN, stop and wait. The Windows
window has no review deadline. On submission the server automatically qualifies,
applies and production-build validates only the selected package updates, saves
reports, then offers separate false-positive approvals. No second continue request
is needed for packages. REMEDIATION_RUNNING also means wait, never duplicate work.
Selected source-code fixes still require the host AI to continue its scoped work.
Do not reopen approved selections or start completion, edits or validation while
selection or server-owned package execution is pending.
Apply all human-approved, qualified package security updates for Node, .NET/C#
and Java, including supported transitive dependency overrides. Retain updates
only after production builds, resolved-version proof and test-free configured
policy checks pass. Never run unit/integration tests. If a batch fails, isolate
and revert offending updates while retaining passing updates. Missing tools are not success;
an already-failing baseline requires explicit investigation, not a green claim.
Do not modify source, unit tests or check scripts to make a package update pass.
For a non-major update, unknown transitive caller behavior is not a proven
incompatibility. After reading current package/manager docs and license terms,
use review.validation_mode="build_only", compatible=null,
compatible_without_code_changes=null, known_incompatibilities=[] and
compatibility_limitations describing what remains unverified. Keep all normal
documentation, api_changes, frameworks, license and source_fixes=[] evidence.
Disclose the trial before human approval; retain only after production builds
and exact dependency checks pass. This does not verify runtime/test compatibility.
Never use this mode for a known incompatibility, required source changes or a
major upgrade. Assess the exact finding: an unrelated advisory on the same
package may still need code changes and must remain unresolved independently.
Blocked packages are disabled in the form, not selectable promises of an update.
Do not open an approval form during finding verification. Only the human may
select or submit. Do not infer approval, poll AWAITING_HUMAN, or commit, push,
or open a merge request. Only the human form may dismiss a finding. Unknown
reachability is not a false positive, and a missing CVE does not prove safety.
Do not invent a version, a corporate approval, or a source patch. Do not weaken
code or tests to make an update pass. Missing advisory data does not block a
concrete GitLab package recommendation; failed validation rejects that fix.
Fuzzing needs local reproduction and must not be replayed against the remote
host. Copy final_summary_markdown once. Completed source review is not a
GitLab dismissal. Count a dismissal as confirmed only after independent GitLab
read-back verifies DISMISSED with FALSE_POSITIVE reason. A mutation acknowledgement
alone is not proof; do not retry an uncertain write automatically. Do not change
GitLab project tags, notes, labels or remote branches. The approved vulnerability
dismissal still records its displayed reason in GitLab's vulnerability audit.
On corporate DNS failure, ask the user to connect to VPN
and stop.
"""


class _CurrentStderr:
    """Write logs to whichever stderr the process is using now.

    Cursor and VS Code Copilot both capture the process stderr pipe. A handler
    bound to an earlier stream would keep writing to a buffer the host never
    reads. Rich formatting is not used; control codes do not show up as log lines.
    """

    def write(self, text: str) -> int:
        """Write one log record to the current stderr."""
        return sys.stderr.write(text)

    def flush(self) -> None:
        """Push the line to the host before the next protocol message."""
        sys.stderr.flush()


def _thread_exception(args: threading.ExceptHookArgs) -> None:
    """Record an exception that escaped a worker thread."""
    if args.exc_type is SystemExit:
        return
    logger.error(
        "Uncaught thread exception %s",
        args.exc_type.__name__ if args.exc_type is not None else "unknown",
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )


def _prepare_stderr() -> None:
    """Make stderr UTF-8 and line-buffered for IDE pipes."""
    try:
        sys.stderr.reconfigure(
            encoding="utf-8", errors="backslashreplace", line_buffering=True
        )
    except (AttributeError, OSError, ValueError):
        return


class _StderrFormatter(logging.Formatter):
    """Keep diagnostic context while redacting the server's environment credentials."""

    converter = gmtime

    def format(self, record: logging.LogRecord) -> str:
        """Redact the complete rendered record, including chained tracebacks."""
        return redact(
            super().format(record),
            [
                os.environ.get(name)
                for name in (
                    "GITLAB_TOKEN",
                    "GITLAB_PERSONAL_ACCESS_TOKEN",
                    "GITHUB_TOKEN",
                    "GH_TOKEN",
                    "NVD_API_KEY",
                )
            ],
        )


def _stderr_handler() -> logging.Handler:
    """Build one plain-text handler that writes to the current stderr."""
    handler = logging.StreamHandler(_CurrentStderr())
    handler.setFormatter(
        _StderrFormatter(
            "%(asctime)sZ %(levelname)s %(name)s [%(threadName)s]: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    return handler


def _configure_logging() -> None:
    """Send this server's logs to stderr so they cannot corrupt MCP stdout.

    The MCP SDK installs Rich on the root logger when that package is present.
    That call is skipped once a handler exists. Both IDE output panels then
    receive plain text lines. Level and propagate are applied on every call,
    including when a handler is already attached.
    """
    threading.excepthook = _thread_exception
    root = logging.getLogger()
    if not any(isinstance(handler, logging.StreamHandler) for handler in root.handlers):
        root.addHandler(_stderr_handler())
    root.setLevel(logging.INFO)
    if not logger.handlers:
        logger.addHandler(_stderr_handler())
    logger.setLevel(logging.INFO)
    logger.propagate = False


def _install_host_logging() -> None:
    """Prepare stderr, then attach handlers that write to that stream."""
    _prepare_stderr()
    _configure_logging()


_install_host_logging()

mcp = MCPServer(
    "gitlab-security-mcp",
    instructions=INSTRUCTIONS,
    version=__version__,
)

_CONSOLE_READER = """
import ctypes
import sys
ctypes.windll.kernel32.SetConsoleTitleW("GitLab Security Progress")
ctypes.windll.kernel32.SetConsoleOutputCP(65001)
with open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1) as console:
    for line in sys.stdin:
        console.write(line)
"""


class _ProgressConsole:
    """Own an isolated Windows console without inheriting MCP's stdio handles."""

    def __init__(self, process: subprocess.Popen[str]):
        """Serialize short writes and retain only the child owned by this server."""
        self.process = process
        self._lock = threading.Lock()
        self._closed = False

    def write(self, text: str) -> None:
        """Flush a live message; a closed console must not interrupt a tool."""
        with self._lock:
            if self._closed:
                return
            try:
                self.process.stdin.write(text + "\n")
                self.process.stdin.flush()
            except (OSError, ValueError):
                logger.warning(
                    "Progress console closed; stderr and tool transcripts remain available."
                )
                self._closed = True

    def close(self) -> None:
        """Close stdin to end the reader and reap the owned child on shutdown."""
        with self._lock:
            self._closed = True
            process = self.process
        if process.stdin is not None:
            with contextlib.suppress(OSError, ValueError):
                process.stdin.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                process.kill()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                logger.warning(
                    "Progress console could not be reaped after kill; pid=%s",
                    process.pid,
                )
        for pipe in (process.stdout, process.stderr):
            if pipe is not None and not pipe.closed:
                with contextlib.suppress(OSError):
                    pipe.close()


def _open_progress_console() -> _ProgressConsole | None:
    """Open visible output for a Windows stdio host unless explicitly disabled."""
    mode = os.environ.get("PROGRESS_CONSOLE", "auto").lower()
    if sys.platform != "win32" or mode in {"0", "off", "false"}:
        return None
    if mode == "auto" and sys.stderr.isatty():
        return None
    try:
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", _CONSOLE_READER],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10),
        )
    except OSError:
        logger.warning(
            "Could not open progress console; stderr and tool transcripts remain available."
        )
        return None
    console = _ProgressConsole(process)
    console.write("GitLab Security Progress: waiting for tool calls.")
    return console


_progress_console: _ProgressConsole | None = None
_progress_console_lock = threading.Lock()
_progress_console_attempted = False
_progress_console_enabled = False
_progress_calls = 0
_progress_close_pending = False


def _console_for_progress() -> _ProgressConsole | None:
    """Lazily open one owned console per run, including after an earlier run ended."""
    global _progress_console, _progress_console_attempted
    with _progress_console_lock:
        if not _progress_console_enabled:
            return _progress_console
        if _progress_console is None and not _progress_console_attempted:
            _progress_console_attempted = True
            _progress_console = _open_progress_console()
        return _progress_console


def _finish_progress_call(terminal: bool) -> _ProgressConsole | None:
    """Detach the owned console when a run ends and active writers have drained."""
    global _progress_console, _progress_console_attempted
    global _progress_console_enabled
    global _progress_calls, _progress_close_pending
    with _progress_console_lock:
        _progress_calls -= 1
        _progress_close_pending |= terminal
        if _progress_calls or not _progress_close_pending:
            return None
        console = _progress_console
        _progress_console = None
        _progress_console_attempted = False
        _progress_console_enabled = False
        _progress_close_pending = False
        return console


def _compact_tool_text(result: CallToolResult) -> None:
    """Remove only formatting from canonical SDK JSON, never evidence or prose."""
    for item in result.content:
        if not isinstance(item, TextContent) or not item.text.startswith(
            ("{\n", "[\n")
        ):
            continue
        try:
            payload = json.loads(item.text)
        except (ValueError, RecursionError):
            continue
        # Round-trip equality protects custom JSON number spellings and precision.
        if json.dumps(payload, ensure_ascii=False, indent=2) == item.text:
            item.text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


async def _progress_middleware(
    context: ServerRequestContext[Any, Any], call_next: CallNext
) -> HandlerResult:
    """Deliver live text bars to the active MCP request without crossing checkouts."""
    if context.method != "tools/call":
        return await call_next(context)
    global _progress_calls, _progress_console_enabled
    with _progress_console_lock:
        _progress_calls += 1
        name = (getattr(context, "params", None) or {}).get("name")
        if name is not None and name not in {
            "get_run_status",
            "review_false_positives",
            "complete_security_run",
            "generate_local_report",
            "submit_false_positive_approvals",
        }:
            _progress_console_enabled = True
    loop = asyncio.get_running_loop()
    messages: asyncio.Queue[str] = asyncio.Queue(maxsize=64)
    transcript: deque[str] = deque(maxlen=64)
    finished = threading.Event()

    def enqueue(text: str) -> None:
        """Keep the most recent updates if a client consumes notifications slowly."""
        if finished.is_set():
            return
        transcript.append(text)
        if messages.full():
            messages.get_nowait()
            messages.task_done()
        messages.put_nowait(text)

    def publish(text: str) -> None:
        """Schedule updates from either command reader thread onto the MCP loop."""
        if finished.is_set():
            return
        text = str(text)[:2000]
        console = _console_for_progress()
        if console is not None:
            console.write(text)
        try:
            loop.call_soon_threadsafe(enqueue, text)
        except RuntimeError:
            logger.warning("Could not queue progress: the MCP event loop has closed.")

    async def deliver() -> None:
        """Send monotonic notification sequence numbers with count-based text bars."""
        sequence = 0
        while True:
            text = await messages.get()
            try:
                sequence += 1
                await context.session.report_progress(sequence, None, text)
            except Exception:
                logger.warning("Could not send MCP progress", exc_info=True)
            finally:
                messages.task_done()

    token = progress_sink.set(publish)
    sender = asyncio.create_task(deliver())
    terminal = True
    try:
        result = await call_next(context)
        if (
            isinstance(result, dict)
            and "content" in result
            and result.get("resultType", "complete") == "complete"
        ):
            result = CallToolResult.model_validate(result)
        if isinstance(result, CallToolResult):
            _compact_tool_text(result)
        payload = (
            result.structured_content if isinstance(result, CallToolResult) else result
        )
        status = payload.get("status", "") if isinstance(payload, dict) else ""
        terminal = (isinstance(result, CallToolResult) and result.is_error) or (
            isinstance(status, str)
            and (
                status in {"REPORT_GENERATED", "ERROR"}
                or status.endswith(("_FAILED", "_INCOMPLETE"))
            )
        )
    finally:
        progress_sink.reset(token)
        try:
            async with asyncio.timeout(1):
                await asyncio.sleep(0)
                await messages.join()
        except TimeoutError:
            logger.warning(
                "MCP progress delivery timed out; the bounded tool transcript remains available."
            )
        finally:
            finished.set()
            sender.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sender
            console = _finish_progress_call(terminal)
            if console is not None:
                await asyncio.to_thread(console.close)
    if transcript:
        output = list(transcript)
        if isinstance(result, dict):
            result["progress_output"] = output
        elif isinstance(result, CallToolResult):
            if isinstance(result.structured_content, dict):
                result.structured_content["progress_output"] = output
            result.content.insert(
                0,
                TextContent(
                    text="## Execution Progress\n```text\n"
                    + "\n".join(output)
                    + "\n```"
                ),
            )
    return result


mcp.middleware.append(_progress_middleware)
# One engine per checkout. The registry lock covers only map updates.
# Tool work uses the engine's own lock, so two repositories can proceed together.
_engines: dict[Path, Engine] = {}
_registry_lock = threading.Lock()


def _close_engine() -> None:
    """Close every checkout engine. A second call does nothing."""
    with logged_lock(_registry_lock, "registry"):
        engines = list(_engines.values())
        _engines.clear()
    failures: list[Exception] = []
    for item in engines:
        try:
            item.close()
        except Exception as exc:
            logger.exception("Could not close the engine for %s", item.repo_root)
            failures.append(exc)
    if failures:
        raise failures[0]


atexit.register(_close_engine)


def _engine_for(repo_root: str | None) -> Engine:
    """Return the engine for one checkout, creating it on first use.

    The registry lock is not held while the tool runs. Each engine serializes
    its own checkout, and different checkouts do not share that lock.
    """
    with logged_lock(_registry_lock, "registry"):
        if repo_root is None:
            if len(_engines) > 1:
                raise ValueError(
                    "More than one repository is active. Pass repo_root to select the checkout."
                )
            if len(_engines) == 1:
                return next(iter(_engines.values()))
            created = Engine.from_env(None)
        else:
            requested = Path(repo_root).expanduser().resolve()
            existing = _engines.get(requested)
            if existing is not None:
                return existing
            created = Engine.from_env(repo_root)
            existing = _engines.get(created.repo_root)
            if existing is not None:
                created.close()
                return existing
        _engines[created.repo_root] = created
        return created


def _run(
    tool_name: str, *args, repo_root: str | None = None, **kwargs
) -> dict[str, Any]:
    """Log tool exceptions and return errors without crashing MCP stdio."""
    selected: Engine | None = None
    try:
        selected = _engine_for(repo_root)
        if tool_name in {
            "qualify_package_update",
            "apply_minimal_fix",
            "generate_aaa_test",
            "run_validation_matrix",
        }:
            return selected.run_approved_fix(tool_name, *args, **kwargs)
        return getattr(selected, tool_name)(*args, **kwargs)
    except Exception as exc:
        logger.exception("%s failed", tool_name)
        return {
            "status": "ERROR",
            "stage": "configuration" if selected is None else tool_name,
            "error": str(exc),
            "repo_root": str(selected.repo_root) if selected is not None else None,
            "server_cwd": os.getcwd(),
            "action": "Call the tool with repo_root=<absolute application checkout path>. "
            "Each checkout keeps its own run. Check server stderr for diagnostic details.",
        }


@mcp.tool(
    annotations=ToolAnnotations(
        title="Run prechecks", read_only_hint=True, open_world_hint=True
    )
)
def run_prechecks(repo_root: str | None = None) -> dict[str, Any]:
    """Require corporate DNS and clean main or today's exact security branch.

    Pass the absolute application repo_root. On DNS failure, connect to VPN and retry.
    """
    return _run("run_prechecks", repo_root=repo_root)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Pull main twice and prepare pnpm",
        read_only_hint=False,
        destructive_hint=True,
        open_world_hint=True,
    )
)
def pull_main_twice(repo_root: str | None = None) -> dict[str, Any]:
    """Pull main twice and prepare pnpm projects; failures stop this run.

    Dependency preparation is deferred until an approved update requires it.
    """
    return _run("pull_main_twice", repo_root=repo_root)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Create or reuse today's security branch",
        read_only_hint=False,
        destructive_hint=True,
        open_world_hint=True,
    )
)
def create_security_branch(repo_root: str | None = None) -> dict[str, Any]:
    """Create today's branch or safely reuse its exact dated name.

    Clean only recognized untracked run artifacts; preserve policies and user files.
    """
    return _run("create_security_branch", repo_root=repo_root)


@mcp.tool(
    annotations=ToolAnnotations(
        title="List security findings", read_only_hint=True, open_world_hint=True
    )
)
def list_security_findings(
    project_id: str | None = None, repo_root: str | None = None
) -> dict[str, Any]:
    """Phase 3. Read GitLab findings on main; infer project from origin unless overridden.

    A finding resolved on the default branch is not proof that this older branch is safe.
    """
    return _run("list_security_findings", project_id, repo_root=repo_root)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Verify security finding", read_only_hint=True, open_world_hint=True
    )
)
async def verify_security_finding(
    finding_id: str,
    repo_root: str | None = None,
    source_review: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assess a finding read-only; follow its source or reproduction workflow.

    GitLab already names the file and line. Open that code, read it, and trace
    callers and inputs. source_review.reason is the non-developer explanation:
    at most 2 sentences and 400 characters. HOST_REVIEW_REQUIRED is unfinished.
    """
    result = await asyncio.to_thread(
        _run,
        "verify_security_finding",
        finding_id,
        repo_root=repo_root,
        source_review=source_review,
    )
    if source_review is not None or result.get("decision") != "SOURCE_REVIEW_REQUIRED":
        return result
    if not (result.get("source_workflow") or {}).get("source"):
        result["ai_source_review"] = {"status": "FAILED", "reason": result["reason"]}
        return result
    selected = await asyncio.to_thread(_engine_for, repo_root)
    evidence = SourceEvidence(selected.repo_root)
    try:
        request = result["source_review_request"]
        cited = await asyncio.to_thread(evidence.read, request["location"]["file"])
        reason = (
            "The host AI must open the file and line GitLab already reported, "
            "read the cited file in the checkout, and call verify_security_finding "
            "with source_review. Write reason in everyday words, at most 2 "
            "sentences and 400 characters: what was flagged and why that code "
            "does not do it. cited_source only locates the line. "
            "No false-positive conclusion has been recorded."
        )
        result.update(
            await asyncio.to_thread(
                selected.record_source_review_blocker, finding_id, reason
            )
        )
        result["ai_source_review"] = {
            "status": "HOST_REVIEW_REQUIRED",
            "reason": reason,
            "cited_source": cited_lines(cited, cited["content"]),
            "next_tool": "verify_security_finding",
        }
        return result
    except (OSError, ValueError) as exc:
        reason = (
            f"AI source review could not complete: {selected.gitlab._clean(str(exc))}. "
            "The host AI must examine the source and submit an evidence-backed "
            "source_review. No false-positive conclusion or GitLab change was made."
        )
        logger.warning("AI source review blocked for %s: %s", finding_id, reason)
        result.update(
            await asyncio.to_thread(
                selected.record_source_review_blocker, finding_id, reason
            )
        )
        result["ai_source_review"] = {"status": "FAILED", "reason": reason}
        return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Qualify package update",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=True,
    )
)
def qualify_package_update(
    finding_id: str, review: dict[str, Any], repo_root: str | None = None
) -> dict[str, Any]:
    """Qualify a human-selected exact package/target; no production/test caller adaptations.

    review: ecosystem,package,target,documentation {complete,sources,summary},
    compatible=true,compatible_without_code_changes=true (or explicit build_only
    per workflow),api_changes,
    frameworks [{name,version,source_url,assessment}],source_fixes=[].
    Production builds/resolution after edits; never unit/integration tests.
    Without corporate policy: license {expression,sources,
    commercial_use_permitted:true,no_license_fees:true,obligations,assessment}.
    If proposed major_upgrade=true: major_upgrade {scan_id from
    proposed_fix.caller_scan,compatible_without_code_changes:true,
    caller_breakages_found:false,migration_sources:[official HTTPS URLs],
    api_comparison,caller_assessment,dependency_assessment,
    reviewed_files:[{path,sha256,assessment}]}.
    """
    return _run("qualify_package_update", finding_id, review, repo_root=repo_root)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Apply minimal fix",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=True,
    )
)
def apply_minimal_fix(finding_id: str, repo_root: str | None = None) -> dict[str, Any]:
    """Apply a human-selected, fresh qualified plan; resolution needs post-checks.

    Reads cited language/manifest and named CVE/CWE docs.
    """
    return _run("apply_minimal_fix", finding_id, repo_root=repo_root)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Generate AAA test",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=False,
    )
)
def generate_aaa_test(finding_id: str, repo_root: str | None = None) -> dict[str, Any]:
    """Add an Arrange-Act-Assert test for a supported human-selected base-image fix."""
    return _run("generate_aaa_test", finding_id, repo_root=repo_root)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Run validation matrix",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=True,
    )
)
def run_validation_matrix(repo_root: str | None = None) -> dict[str, Any]:
    """Validate pending updates with production builds, resolution and test-free policy checks.

    Read isolation_trials/rejected_updates; stop on incomplete recovery or cleanup.
    """
    return _run("run_validation_matrix", repo_root=repo_root)


def _checkbox_model(name: str, candidates: list[dict], text) -> type[BaseModel]:
    """Build one unchecked box per finding. ``text`` returns its title and description."""
    fields = {}
    for index, item in enumerate(candidates):
        title, description = text(item)
        fields[f"finding_{index}"] = (
            bool,
            Field(default=False, strict=True, title=title, description=description),
        )
    return create_model(name, **fields)


def _checked(candidates: list[dict], values: dict) -> list[dict]:
    """Return the findings whose boxes were explicitly checked."""
    return [
        item
        for index, item in enumerate(candidates)
        if values.get(f"finding_{index}") is True
    ]


def _form_supported(ctx: Context) -> bool:
    """Return whether this host can display an MCP checkbox form."""
    capabilities = ctx.session.client_capabilities
    if capabilities is None or capabilities.elicitation is None:
        return False
    elicitation = capabilities.elicitation
    return elicitation.form is not None or not elicitation.model_dump(exclude_none=True)


async def _fix_form_response(
    ctx: Context, message: str, schema: type[BaseModel], request_id: str
) -> ElicitationResult[BaseModel] | InputRequiredResult:
    """Use modern input rounds or the legacy back-channel without AI consent inputs."""
    protocol = ctx.protocol_version
    if not isinstance(protocol, str) or protocol < "2026-07-28":
        return await ctx.elicit(message, schema)
    if ctx.input_responses is None:
        return InputRequiredResult(
            input_requests={
                "fix_selection": ElicitRequest(
                    params=ElicitRequestFormParams(
                        message=message,
                        requested_schema=render_elicitation_schema(schema),
                    )
                )
            },
            request_state=request_id,
        )
    if (
        ctx.request_state != request_id
        or set(ctx.input_responses) != {"fix_selection"}
        or not isinstance(
            response := ctx.input_responses["fix_selection"], ElicitResult
        )
    ):
        raise ValueError(
            "The human fix-selection response does not match the live request."
        )
    if response.action == "accept":
        return AcceptedElicitation(data=schema.model_validate(response.content))
    if response.action == "decline":
        return DeclinedElicitation()
    return CancelledElicitation()


def _fix_choice_text(item: dict) -> tuple[str, str]:
    """Present decision facts without exposing Python dictionaries as form text."""
    plan = item["proposed_fix"]
    location = item["location"]
    path = location.get("file") or location.get("path") or "Not provided"
    line = location.get("start_line") or location.get("line")
    where = f"{path}:{line}" if line else str(path)
    scope = ", ".join(str(path) for path in plan.get("files") or []) or where
    title = f"{str(item.get('severity') or 'unknown').upper()} | {item.get('title') or item['id']}"
    facts = [f"Finding: {item['id']}", f"Location: {where}"]
    if plan.get("package") and plan.get("target"):
        current = item.get("current_version") or "Not established"
        title += f" | {plan['package']}: {current} -> {plan['target']}"
        facts.extend(
            [
                f"Package: {plan['package']} ({plan.get('ecosystem') or 'unknown ecosystem'})",
                f"Current version: {current} ({item['current_version_source']})",
                f"Proposed version: {plan['target']}",
                f"Change: {plan.get('description') or plan.get('strategy') or 'Version update'}",
                f"Scope: {scope}",
                "Risk: Major-version change; requires API/caller compatibility review."
                if plan.get("major_upgrade")
                or is_major_upgrade(item.get("current_version"), plan["target"])
                else "Risk: Compatibility and license review still required; a version number alone does not prove safety.",
                "Keep only if production builds, resolution and test-free policy checks pass; unit/integration tests are disabled. "
                "Isolate and revert offending updates; retain passing updates. Do not adapt source or tests to force acceptance.",
            ]
        )
    else:
        facts.extend(
            [
                f"Proposed code change: {plan.get('description') or 'No verified edit plan yet; source review or local reproduction is still required.'}",
                f"Scope: {scope}",
                "Approve a scoped, evidence-backed security fix for this issue only. "
                "An annotation must enforce security, not suppress a warning. No invented fixes, major rewrites or API adaptations.",
            ]
        )
    facts.append(
        f"Why address this: {item.get('reason') or 'Assessment details are not established.'}"
    )
    return title, "\n".join(facts)


_desktop_fix_selection_tasks: dict[str, asyncio.Task] = {}


def _desktop_task_done(
    task: asyncio.Task,
    *,
    tasks: dict[str, asyncio.Task],
    request_id: str,
    repo_root: Path,
) -> None:
    """Release ownership and retrieve failures that escaped background cleanup."""
    if tasks.get(request_id) is task:
        tasks.pop(request_id)
    if task.cancelled():
        return
    error = task.exception()
    if error is not None:
        logger.error(
            "Desktop task failed repo=%s request=%s",
            repo_root,
            request_id,
            exc_info=(type(error), error, error.__traceback__),
        )


async def _finish_desktop_fix_selection(
    ctx: Context,
    selected: Engine,
    request_id: str,
    candidates: list[dict],
    schema: type[BaseModel],
    dialog: desktop_approval.DesktopApproval,
    started: asyncio.Event,
    prepared: dict,
) -> None:
    """Execute reviewed package choices after physical approval, outside the host deadline."""
    closed = False
    work = None
    cancelled = threading.Event()
    try:
        started.set()
        response = await dialog.wait()
        await dialog.close()
        closed = True
        values = (
            schema.model_validate(response.get("content")).model_dump()
            if response["action"] == "accept"
            else {}
        )
        chosen = _checked(candidates, values)
        if any(
            prepared["reviews"].get(item["id"], {}).get("blocked_reason")
            for item in chosen
        ):
            raise ValueError(
                "A blocked update cannot be selected; obtain a new review before approval."
            )
        ids = [item["id"] for item in chosen]
        result = await asyncio.to_thread(
            selected.record_fix_selection,
            candidates,
            ids,
            "APPROVED" if ids else "SKIPPED",
            "" if ids else "The human did not approve any code fixes.",
            request_id=request_id,
            presentation="WINDOWS_DIALOG",
        )
        logger.info(
            "Desktop fix selection finished: %s; %s approved for local edits.",
            result["status"],
            len(result.get("selected_ids", [])),
        )
        if result["status"] == "APPROVED" and any(
            finding_id in prepared["reviews"] for finding_id in ids
        ):
            work = asyncio.get_running_loop().run_in_executor(
                None,
                partial(
                    selected.execute_selected_package_updates,
                    request_id,
                    prepared["reviews"],
                    prepared["tree"],
                    cancelled,
                ),
            )
            execution = await asyncio.shield(work)
            logger.info("Approved package execution finished: %s", execution["status"])
            if execution.get("finish_run") is True:
                await complete_security_run(ctx, str(selected.repo_root))
    except asyncio.CancelledError:
        if work is not None:
            cancelled.set()
            await work
        await asyncio.shield(
            asyncio.to_thread(
                selected.record_fix_selection,
                candidates,
                [],
                "UNAVAILABLE",
                "The server stopped before a human response. No edits were authorized.",
                request_id=request_id,
                presentation="WINDOWS_DIALOG",
            )
        )
        raise
    except Exception as exc:
        logger.exception(
            "Desktop fix selection failed repo=%s request=%s",
            selected.repo_root,
            request_id,
        )
        await asyncio.to_thread(
            selected.record_fix_selection,
            candidates,
            [],
            "INVALID",
            str(exc),
            request_id=request_id,
            presentation="WINDOWS_DIALOG",
        )
    finally:
        if not closed:
            await dialog.close()


async def _open_fix_selection(
    ctx: Context,
    selected: Engine,
    candidates: list[dict],
    schema: type[BaseModel],
    prepared: dict,
) -> dict:
    """Reserve one owned Windows window and return before the human finishes reading."""
    pending = await asyncio.to_thread(
        selected.record_fix_selection,
        candidates,
        [],
        "REQUESTED",
        presentation="WINDOWS_DIALOG",
    )
    if pending.get("created") is not True:
        return pending
    request_id = pending["request_id"]
    dialog = None
    task = None
    started = asyncio.Event()
    try:
        properties = schema.model_json_schema()["properties"]
        for index, item in enumerate(candidates):
            field = properties[f"finding_{index}"]
            blocked = prepared["reviews"].get(item["id"], {}).get("blocked_reason")
            if blocked:
                field["enabled"] = False
                field["title"] = "BLOCKED | " + field["title"]
                field["description"] = (
                    f"No automatic update: {blocked}\n\n" + field["description"]
                )
            elif (
                prepared["reviews"].get(item["id"], {}).get("validation_mode")
                == "build_only"
            ):
                review = prepared["reviews"][item["id"]]
                field["title"] = "BUILD-ONLY TRIAL | " + field["title"]
                field["description"] = (
                    "Compatibility is not proven. Retain only after production build and exact-version resolution pass; runtime/test compatibility remains unverified.\n"
                    + review["compatibility_limitations"]
                    + "\n\n"
                    + field["description"]
                )
            field["summary"] = field["description"]
        dialog = await desktop_approval.open_dialog(
            f"Repository: {selected.repo_root}\r\n"
            "Select only the package updates or scoped code fixes you authorize. All boxes start unchecked. "
            "Review current/proposed versions, file scope, risk and acceptance requirements. "
            "There is no selection deadline. Cancel or close authorizes nothing. "
            "After submission, the server applies checked package updates and runs production builds/dependency checks, never unit/integration tests. "
            "Keep the server running; no second continue request is needed for packages. Source-code fixes still require your IDE agent.",
            properties,
            title="GitLab security: choose updates and code fixes",
            detail_header="Proposed change and decision details",
            submit_label="Approve checked fixes",
        )
        result = await asyncio.to_thread(
            selected.record_fix_selection,
            candidates,
            [],
            "AWAITING_HUMAN",
            request_id=request_id,
            presentation="WINDOWS_DIALOG",
        )
        if result["status"] != "AWAITING_HUMAN":
            return result
        task = asyncio.create_task(
            _finish_desktop_fix_selection(
                ctx, selected, request_id, candidates, schema, dialog, started, prepared
            )
        )
        _desktop_fix_selection_tasks[request_id] = task
        task.add_done_callback(
            partial(
                _desktop_task_done,
                tasks=_desktop_fix_selection_tasks,
                request_id=request_id,
                repo_root=selected.repo_root,
            )
        )
        await started.wait()
        return {
            **result,
            "blocked_updates": [
                {
                    "finding_id": item["id"],
                    "reason": prepared["reviews"][item["id"]]["blocked_reason"],
                }
                for item in candidates
                if prepared["reviews"].get(item["id"], {}).get("blocked_reason")
            ],
            "message": "The Windows selection window is open with no review timeout. "
            "This tool call is complete. Do not poll, reopen selection, start fixes or complete the run. "
            "After submission the server automatically qualifies, edits and validates selected package updates, then saves reports and offers separate false-positive approvals. "
            "Keep the server running. Only selected source-code fixes require the IDE agent to continue.",
        }
    except asyncio.CancelledError:
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await asyncio.shield(
            asyncio.to_thread(
                selected.record_fix_selection,
                candidates,
                [],
                "UNAVAILABLE",
                "The host interrupted window startup. No edits were authorized.",
                request_id=request_id,
                presentation="WINDOWS_DIALOG",
            )
        )
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        logger.warning("Could not display Windows fix-selection window: %s", exc)
        return await asyncio.to_thread(
            selected.record_fix_selection,
            candidates,
            [],
            "UNAVAILABLE",
            str(exc),
            request_id=request_id,
            presentation="WINDOWS_DIALOG",
        )
    finally:
        if dialog is not None and not started.is_set():
            await dialog.close()


@mcp.tool(
    annotations=ToolAnnotations(
        title="Select security issues to fix",
        read_only_hint=False,
        destructive_hint=True,
        open_world_hint=True,
    )
)
async def select_security_fixes(
    ctx: Context,
    repo_root: str | None = None,
    package_reviews: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any] | InputRequiredResult:
    """Human-only selection; cancel/empty/unavailable skips edits.

    Windows package_reviews[id]: exact qualification evidence before checkboxes.
    Submission applies selected packages, builds without tests and isolates failures.
    blocked_reason disables the choice; build_only trials disclose uncertainty.
    """
    selected = await asyncio.to_thread(_engine_for, repo_root)
    protocol = ctx.protocol_version
    if (
        isinstance(protocol, str)
        and protocol >= "2026-07-28"
        and ctx.request_state is not None
    ):
        snapshot = await asyncio.to_thread(
            selected.pending_fix_selection, ctx.request_state
        )
    else:
        snapshot = await asyncio.to_thread(selected.fix_selection_candidates)
    if snapshot["status"] not in {"OK", "REQUESTED"}:
        return snapshot
    candidates = snapshot["candidates"]
    native = desktop_approval.available()
    if not candidates or (not native and not _form_supported(ctx)):
        return await asyncio.to_thread(
            selected.record_fix_selection,
            candidates,
            [],
            "SKIPPED" if not candidates else "UNAVAILABLE",
            "No evidenced fix candidates."
            if not candidates
            else "The host does not advertise human form support; no code edits are authorized.",
        )
    schema = _checkbox_model("SecurityFixSelection", candidates, _fix_choice_text)
    if native:
        prepared = await asyncio.to_thread(
            selected.prepare_package_updates, candidates, package_reviews or {}
        )
        if prepared["status"] != "READY":
            return prepared
        return await _open_fix_selection(ctx, selected, candidates, schema, prepared)
    pending = (
        snapshot
        if snapshot["status"] == "REQUESTED"
        else await asyncio.to_thread(
            selected.record_fix_selection, candidates, [], "REQUESTED"
        )
    )
    if pending["status"] != "REQUESTED":
        return pending
    try:
        response = await _fix_form_response(
            ctx,
            f"Choose which security issues may be fixed in {selected.repo_root}. "
            "All boxes start unchecked. Select only the issues you authorize. "
            "An annotation must actually enforce security, not hide a warning. "
            "Only precise, evidence-backed fixes are allowed. Dependency updates may incidentally "
            "resolve other findings sharing that dependency; no separate edits for unchecked issues are authorized. "
            "Submit with no boxes checked, decline or cancel to skip code fixes and proceed to "
            "independently assessed false positives. Skipping does not make an issue a false positive.",
            schema,
            pending["request_id"],
        )
        if isinstance(response, InputRequiredResult):
            return response
    except (ValueError, MCPError) as exc:
        logger.warning("Security fix selection unavailable or invalid: %s", exc)
        return await asyncio.to_thread(
            selected.record_fix_selection,
            candidates,
            [],
            "INVALID" if isinstance(exc, ValueError) else "UNAVAILABLE",
            str(exc),
            request_id=pending["request_id"],
        )
    chosen = (
        response.data.model_dump()
        if response.action == "accept" and response.data is not None
        else {}
    )
    ids = [item["id"] for item in _checked(candidates, chosen)]
    return await asyncio.to_thread(
        selected.record_fix_selection,
        candidates,
        ids,
        "APPROVED" if ids else "SKIPPED",
        ""
        if ids
        else "The human did not approve any code fixes; proceed to false-positive review.",
        request_id=pending["request_id"],
    )


async def _approval_result(selected: Engine, receipt: dict, result: dict) -> dict:
    """Keep observable form outcomes without treating diagnostics as consent."""
    recorded = await asyncio.to_thread(
        selected.record_false_positive_approval_form,
        {
            **receipt,
            "status": result["status"],
            **({"reason": result["reason"]} if result.get("reason") else {}),
        },
    )
    return result if recorded["status"] == "OK" else recorded


_desktop_approval_tasks: dict[str, asyncio.Task] = {}


async def _interrupt_desktop_startup(selected: Engine, receipt: dict) -> None:
    """Persist interrupted startup only if it still belongs to this live run."""
    await asyncio.to_thread(
        selected.resolve_desktop_approval,
        receipt["request_id"],
        None,
        status="APPROVAL_INTERRUPTED",
        reason="The host cancelled during approval-window startup. No dismissal was authorized.",
    )


async def _finish_desktop_approval(
    selected: Engine,
    request_id: str,
    candidates: list[dict],
    schema: type,
    dialog: desktop_approval.DesktopApproval,
) -> None:
    """Wait outside the tool request; only physical checkbox selections authorize writes."""
    try:
        response = await dialog.wait()
        approved = None
        if response["action"] == "accept":
            values = schema.model_validate(response.get("content")).model_dump()
            approved = _checked(candidates, values)
        result = await asyncio.to_thread(
            selected.resolve_desktop_approval, request_id, approved
        )
        logger.info(
            "Desktop false-positive approval finished: %s; independently confirmed %s of %s selections",
            result["status"],
            result.get("confirmed_dismissals", 0),
            result.get("selected_count", 0),
        )
    except asyncio.CancelledError:
        await asyncio.shield(
            asyncio.to_thread(
                selected.resolve_desktop_approval,
                request_id,
                None,
                status="APPROVAL_INTERRUPTED",
                reason="The server stopped before a human response. No new dismissal was authorized.",
            )
        )
        raise
    except Exception as exc:
        logger.exception(
            "Desktop false-positive approval failed repo=%s request=%s",
            selected.repo_root,
            request_id,
        )
        await asyncio.to_thread(
            selected.resolve_desktop_approval,
            request_id,
            None,
            status="APPROVAL_INVALID",
            reason=str(exc),
        )
    finally:
        await dialog.close()


@mcp.tool(
    annotations=ToolAnnotations(
        title="Finding Assessments: list false positives for verification",
        read_only_hint=True,
        destructive_hint=False,
        open_world_hint=False,
    )
)
async def review_false_positives(
    ctx: Context, repo_root: str | None = None
) -> dict[str, Any]:
    """Return eligible false positives for human verification without opening a form.

    Read-only inspection; standard completion offers the human form automatically.
    """
    selected = await asyncio.to_thread(_engine_for, repo_root)
    snapshot = await asyncio.to_thread(selected.false_positive_candidates)
    if snapshot["status"] != "OK":
        return snapshot
    candidates = snapshot["candidates"]
    queue = snapshot["source_review_queue"]
    if not candidates:
        excluded = snapshot["excluded"]
        already_dismissed = sum(
            item["reason"] == "ALREADY_DISMISSED" for item in excluded
        )
        if excluded and already_dismissed == len(excluded):
            status = "ALREADY_DISMISSED"
            message = (
                f"All {already_dismissed} findings were previously confirmed dismissed "
                "in GitLab. No repeat approval is needed. No GitLab changes were made by this call."
            )
        elif queue["finding_count"]:
            status = "SOURCE_REVIEW_REQUIRED"
            message = (
                f"{queue['finding_count']} SAST findings still require host AI code review. "
                "Some findings are unverified or still need a completed source review. "
                "No false-positive conclusion can be inferred. Follow source_review_queue, record evidence, "
                "then request approval again. No GitLab changes were made by this call."
            )
        else:
            status = "ASSESSMENT_REQUIRED"
            message = (
                "No eligible false-positive assessments to approve. "
                f"{already_dismissed} findings were previously confirmed dismissed. "
                "See excluded for each finding's blocker and next action. "
                "No GitLab changes were made by this call."
            )
            if not excluded:
                message = (
                    "No findings are loaded. List and verify findings in this process "
                    "before requesting approval. No GitLab changes were made by this call."
                )
        return {
            "status": status,
            "repo_root": str(selected.repo_root),
            "results": [],
            "excluded": excluded,
            "source_review_queue": queue,
            "message": message,
        }
    if not desktop_approval.available() and not _form_supported(ctx):
        return {
            "status": "APPROVAL_UNAVAILABLE",
            "reason": "This MCP host does not advertise form elicitation. No GitLab changes were made. Use a form-capable host or dismiss manually in GitLab.",
            "candidates": candidates,
            "source_review_queue": queue,
        }
    return {
        "status": "REVIEW_READY",
        "repo_root": str(selected.repo_root),
        "results": [],
        "candidates": candidates,
        "excluded": snapshot["excluded"],
        "source_review_queue": queue,
        "next_tool": "submit_false_positive_approvals",
        "message": (
            "These findings are ready for human verification. Take as long as needed; "
            "this result does not keep a form open and does not expire. "
            "No GitLab changes were made. Standard completion automatically offers "
            "submit_false_positive_approvals after saving the report. Only the human "
            "may select checkboxes and submit; cancel to continue reviewing."
        ),
    }


@mcp.tool(
    annotations=ToolAnnotations(
        title="Submit false-positive approvals",
        read_only_hint=False,
        destructive_hint=True,
        open_world_hint=True,
    )
)
async def submit_false_positive_approvals(
    ctx: Context, repo_root: str | None = None
) -> dict[str, Any]:
    """Open unchecked human-only dismissal approvals; no AI consent arguments.

    Completion calls once; reopen only on explicit human request after cancellation.
    """
    selected = await asyncio.to_thread(_engine_for, repo_root)
    previous = selected.state.false_positive_approval_form
    if previous.get("request_id") in _desktop_approval_tasks:
        return {
            "status": "AWAITING_HUMAN",
            "message": "The existing Windows checkbox window is still open. No duplicate window or GitLab change was made.",
        }
    snapshot = await asyncio.to_thread(selected.false_positive_candidates)
    if snapshot["status"] != "OK":
        return snapshot
    candidates = snapshot["candidates"]
    queue = snapshot["source_review_queue"]
    if not candidates:
        review = await review_false_positives(ctx, repo_root)
        review.pop("candidates", None)
        return review
    capabilities = ctx.session.client_capabilities
    receipt = {
        "candidate_ids": [item["id"] for item in candidates],
        "elicitation_capability": (
            capabilities.elicitation.model_dump(exclude_none=True)
            if capabilities is not None and capabilities.elicitation is not None
            else None
        ),
    }
    if not desktop_approval.available() and not _form_supported(ctx):
        return await _approval_result(
            selected,
            receipt,
            {
                "status": "APPROVAL_UNAVAILABLE",
                "reason": "This MCP host does not advertise form elicitation. No GitLab changes were made. Use a form-capable host or dismiss manually in GitLab.",
                "source_review_queue": queue,
            },
        )
    schema = _checkbox_model(
        "FalsePositiveApprovals",
        candidates,
        lambda item: (
            f"{item['id']}: {item['title']}",
            "Why this is a false positive: "
            f"{item['description']}\n\n"
            f"Dismiss as FALSE_POSITIVE with comment:\n{item['reason']}",
        ),
    )
    if desktop_approval.available():
        receipt.update(request_id=uuid4().hex, presentation="WINDOWS_DIALOG")
        try:
            pending = await asyncio.to_thread(selected.begin_desktop_approval, receipt)
            if pending.get("created") is not True:
                return pending
            properties = schema.model_json_schema()["properties"]
            for index, item in enumerate(candidates):
                properties[f"finding_{index}"]["summary"] = item["description"]
            dialog = await desktop_approval.open_dialog(
                f"Repository: {selected.repo_root}\r\n"
                "Check only the false positives you approve. All boxes start unchecked. "
                "Both columns wrap; each row expands to show the issue and explanation. "
                "Full audit comments and supporting evidence remain in the saved reports. "
                "Dismiss checked items submits only checked findings to GitLab. "
                "Cancel or close changes nothing. There is no selection deadline.",
                properties,
            )
        except asyncio.CancelledError:
            logger.warning("Windows approval startup interrupted before delivery")
            await asyncio.shield(_interrupt_desktop_startup(selected, receipt))
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            logger.warning("Could not display Windows approval window: %s", exc)
            return await _approval_result(
                selected,
                receipt,
                {"status": "APPROVAL_UNAVAILABLE", "reason": str(exc)},
            )
        try:
            result = await _approval_result(
                selected,
                receipt,
                {
                    "status": "AWAITING_HUMAN",
                    "message": (
                        "The Windows checkbox approval window is open. This MCP call is complete; "
                        "the window has no selection timeout. Only checked human submissions can "
                        "dismiss findings. Saved reports update after submission or cancellation. "
                        "Do not repeat completion or poll while the human is reviewing."
                    ),
                },
            )
        except asyncio.CancelledError:
            await dialog.close()
            await asyncio.shield(_interrupt_desktop_startup(selected, receipt))
            raise
        except BaseException:
            await dialog.close()
            raise
        if result["status"] != "AWAITING_HUMAN":
            await dialog.close()
            return result
        task = asyncio.create_task(
            _finish_desktop_approval(
                selected, receipt["request_id"], candidates, schema, dialog
            )
        )
        _desktop_approval_tasks[receipt["request_id"]] = task
        task.add_done_callback(
            partial(
                _desktop_task_done,
                tasks=_desktop_approval_tasks,
                request_id=receipt["request_id"],
                repo_root=selected.repo_root,
            )
        )
        return result
    await asyncio.to_thread(
        selected.record_false_positive_approval_form,
        {**receipt, "status": "REQUESTED"},
    )
    report_note = (
        f"Saved report: {selected.state.report_path}. "
        if selected.state.report_path
        else ""
    )
    try:
        response = await ctx.elicit(
            f"Human approval required for {selected.repo_root} ({candidates[0]['project_path']}). "
            f"{report_note}{queue['finding_count']} findings still require source review and are excluded from this form. "
            "Select only the false positives you approve. Submit to immediately dismiss selected GitLab vulnerabilities with the displayed reasons. Unchecked findings stay unchanged. "
            "Cancel to continue reviewing the saved local report and explicitly reopen this form later.",
            schema,
        )
    except asyncio.CancelledError:
        logger.warning("False-positive form interrupted before a human response")
        await asyncio.shield(
            _approval_result(
                selected,
                receipt,
                {
                    "status": "APPROVAL_INTERRUPTED",
                    "reason": "The host cancelled or timed out before returning human selections. No new dismissal was authorized.",
                },
            )
        )
        await asyncio.shield(asyncio.to_thread(selected.generate_local_report))
        raise
    except ValueError as exc:
        logger.warning("Invalid false-positive approval response: %s", exc)
        return await _approval_result(
            selected,
            receipt,
            {
                "status": "APPROVAL_INVALID",
                "reason": str(exc),
                "message": "No GitLab changes were made. Submit a valid human checkbox form.",
            },
        )
    except MCPError as exc:
        logger.warning("False-positive approval form unavailable: %s", exc)
        return await _approval_result(
            selected,
            receipt,
            {
                "status": "APPROVAL_UNAVAILABLE",
                "reason": str(exc),
                "message": "The host could not open the human approval form. No GitLab changes were made by this call.",
                "source_review_queue": queue,
            },
        )
    if response.action != "accept" or response.data is None:
        return await _approval_result(
            selected,
            receipt,
            {
                "status": "CANCELLED",
                "results": [],
                "message": "No GitLab changes were made.",
            },
        )
    approved = _checked(candidates, response.data.model_dump())
    result = await asyncio.to_thread(selected.dismiss_false_positives, approved)
    result["source_review_queue"] = queue
    result["excluded"] = snapshot["excluded"]
    return await _approval_result(
        selected, {**receipt, "selected_ids": [item["id"] for item in approved]}, result
    )


def _generate_local_report(repo_root: str | None = None) -> CallToolResult:
    """Write and format the report without recursively invoking human approval."""
    result = _run("generate_local_report", repo_root=repo_root)
    return CallToolResult(
        content=[
            TextContent(
                text=result.get("final_summary_markdown")
                or (f"Report generation failed: {result.get('error', 'unknown error')}")
            )
        ],
        structuredContent=result,
        isError=result.get("status") == "ERROR",
    )


@mcp.tool(
    annotations=ToolAnnotations(
        title="Generate local report and offer false-positive approvals",
        read_only_hint=False,
        destructive_hint=True,
        open_world_hint=True,
    )
)
async def generate_local_report(
    ctx: Context, repo_root: str | None = None
) -> CallToolResult:
    """Legacy alias for complete_security_run, including human dismissal approvals."""
    return await complete_security_run(ctx, repo_root)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Complete security run: report and human approval checkboxes",
        read_only_hint=False,
        destructive_hint=True,
        open_world_hint=True,
    )
)
async def complete_security_run(
    ctx: Context, repo_root: str | None = None
) -> CallToolResult:
    """Save reports and automatically offer native human approval checkboxes once.

    Call after assessments and approved fixes/validation; never poll AWAITING_HUMAN.
    """
    selected = await asyncio.to_thread(_engine_for, repo_root)
    selected_root = str(selected.repo_root)
    selection = deepcopy(selected.state.fix_selection)
    if (selection.get("package_execution") or {}).get("status") in {
        "QUEUED",
        "RUNNING",
    }:
        message = "The server is executing the approved package batch. Do not duplicate its edits, checks or completion."
        return CallToolResult(
            content=[TextContent(text=message)],
            structuredContent={"status": "REMEDIATION_RUNNING", "message": message},
        )
    if selection.get("presentation") == "WINDOWS_DIALOG" and selection.get(
        "status"
    ) in {"REQUESTED", "AWAITING_HUMAN"}:
        message = "Wait for the human's open fix-selection window. Approved, reviewed packages continue automatically; selected source fixes remain host-led. Do not poll or reopen."
        return CallToolResult(
            content=[TextContent(text=message)],
            structuredContent={
                "status": "AWAITING_HUMAN",
                "fix_selection": selection,
                "message": message,
            },
        )
    review = await review_false_positives(ctx, repo_root=selected_root)
    report = await asyncio.to_thread(_generate_local_report, repo_root=selected_root)
    if report.structured_content is None:
        raise RuntimeError("The local report did not return structured report data")
    if not report.is_error and review["status"] in {
        "REVIEW_READY",
        "APPROVAL_UNAVAILABLE",
    }:
        if selected.state.false_positive_approval_form:
            review["previous_form"] = deepcopy(
                selected.state.false_positive_approval_form
            )
            review["message"] = (
                "The approval form was already offered or unavailable in this run. "
                "No automatic retry was made. Only an explicit human request may reopen it."
            )
        else:
            review = await submit_false_positive_approvals(ctx, repo_root=selected_root)
            report = await asyncio.to_thread(
                _generate_local_report, repo_root=selected_root
            )
            if report.structured_content is None:
                raise RuntimeError(
                    "The refreshed report did not return structured report data"
                )
    note = f"False-positive review: {review['status']}."
    for key in ("message", "reason"):
        if review.get(key):
            note += f"\n{review[key]}"
    return CallToolResult(
        content=[TextContent(text=note), *report.content],
        structuredContent={
            **report.structured_content,
            "false_positive_review": review,
        },
        isError=report.is_error
        or review["status"] in {"ERROR", "PARTIAL_FAILURE", "APPROVAL_INVALID"},
    )


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get run status", read_only_hint=True, open_world_hint=False
    )
)
def get_run_status(repo_root: str | None = None) -> dict[str, Any]:
    """Return the current phase, branch, and counts for one checkout."""
    return _run("get_run_status", repo_root=repo_root)


def main() -> None:
    """Serve MCP tools over stdio until the client disconnects."""
    global _progress_console
    _install_host_logging()
    logger.info("gitlab-security-mcp %s serving stdio", __version__)
    try:
        mcp.run(transport="stdio")
    finally:
        try:
            _close_engine()
        except Exception:
            logger.exception("Could not close the engine during server shutdown")
        finally:
            if _progress_console is not None:
                _progress_console.close()
                _progress_console = None


if __name__ == "__main__":
    main()
