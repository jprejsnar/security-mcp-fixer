"""MCP tools for the local GitLab security remediation workflow."""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
from collections import deque
from copy import deepcopy
from datetime import UTC, datetime
from functools import partial, wraps
from pathlib import Path
from time import gmtime, monotonic
from typing import Any, Literal
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

from gitlab_security_mcp import __version__, desktop_approval, workflow
from gitlab_security_mcp.ai_source_review import SourceEvidence, cited_lines
from gitlab_security_mcp.commands import progress_sink
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.progress import publish as publish_editor_progress
from gitlab_security_mcp.progress_extension import install_progress_extension
from gitlab_security_mcp.report import write_unresolved_report
from gitlab_security_mcp.security_artifacts import archive_run_logs
from gitlab_security_mcp.software_audit import (
    REVIEW_PHASES,
    audit_coverage_gaps,
    audit_has_no_findings,
    audit_inventory,
    audit_items,
    audit_report_is_draft,
    audit_report_path,
    choice_labels,
    normalize_choice,
    persist_audit_draft,
    project_file_name,
    record_audit_coverage,
    render_audit_prompt,
)
from gitlab_security_mcp.util import (
    PROGRESS_PUBLISH_FAILURES,
    attach_server_log,
    environment_secrets,
    logged_lock,
    redact,
)
from gitlab_security_mcp.versions import is_major_upgrade
from gitlab_security_mcp.workflow import (
    JOB_AUDIT,
    JOB_COUNT,
    JOB_DOWNLOAD,
    JOB_FALSE_POSITIVES,
    JOB_PACKAGES,
    JOB_PRECHECKS,
    JOB_REPORT,
    JOB_SOURCE,
)

_RAISE_UNEXPECTED_WORKFLOW_JOB = "Unexpected workflow job"
_RAISE_THE_HUMAN_FIX_SELECTION_RESPONSE_DOES_NOT_MATCH = (
    "The human fix-selection response does not match the live request."
)
_RAISE_THE_LOCAL_REPORT_DID_NOT_RETURN_STRUCTURED_REPORT = (
    "The local report did not return structured report data"
)
_RAISE_AUDIT_APPROVAL_NEEDS_A_KNOWN_STAGE_AND_THE = (
    "Audit approval needs a known stage and the prepared findings."
)
_RAISE_A_BLOCKED_UPDATE_CANNOT_BE_SELECTED_OBTAIN_A = (
    "A blocked update cannot be selected; obtain a new review before approval."
)
_RAISE_DUPLICATE_CODE_FIX_OUTCOME_IDS = "Duplicate code-fix outcome IDs."
_RAISE_THIS_AUDIT_APPROVAL_BELONGS_TO_A_REPLACED_RUN = (
    "This audit approval belongs to a replaced run or request."
)
_RAISE_THE_AUDIT_APPROVAL_BELONGS_TO_A_REPLACED_RUN = (
    "The audit approval belongs to a replaced run."
)
_RAISE_THE_SOFTWARE_AUDIT_WINDOW_RETURNED_AN_UNKNOWN_CHOICE = (
    "The software-audit window returned an unknown choice: {!r}"
)
_RAISE_THE_AUDIT_HANDOFF_BELONGED_TO_A_REPLACED_RUN = (
    "The audit handoff belonged to a replaced run. No audit action was authorized."
)
_RAISE_MORE_THAN_ONE_REPOSITORY_IS_ACTIVE_PASS_REPO = (
    "More than one repository is active. Pass repo_root to select the checkout."
)
_RAISE_IS_NOT_A_SELECTED_FIX_OR_LACKS_ITS = (
    "{} is not a selected fix or lacks its outcome reason."
)
_RAISE_NEEDS_THE_ACTUAL_VALIDATION_COMMAND_RESULT_BEFORE_REPORTING = (
    "{} needs the actual validation command/result before reporting fixed."
)
_RAISE_THE_REFRESHED_REPORT_DID_NOT_RETURN_STRUCTURED_REPORT = (
    "The refreshed report did not return structured report data"
)
_RAISE_THE_AUDIT_FIX_APPROVAL_SCHEMA_IS_MISSING = (
    "The audit-fix approval schema is missing."
)
_RAISE_AUDIT_FINDINGS_ARE_REQUIRED_FOR_FIX_SELECTION = (
    "Audit findings are required for fix selection."
)

logger = logging.getLogger("gitlab_security_mcp")

INSTRUCTIONS = """
Local-only GitLab security remediation. One checkout per run. Pass the same
absolute repo_root when more than one checkout is active. ${workspaceFolder}
is not a path. Do not construct a separate Engine or resume from saved JSON.
A request to run gitlab-security on this repo uses seven sequential jobs:
1. Pre-checks: run_prechecks, pull_main_twice, create_security_branch.
2. Download: list_security_findings.
3. Package updates: assess package findings, select_package_version, then
   select_security_fixes shows only frontend/backend package updates. Execute
   only human selections and validate before complete_security_run.
4. False positives: finish source/finding verification, then offer separate
   unchecked dismissal boxes with the evidence-backed reasons uploaded to GitLab.
5. GitLab source fixes: a NEW unchecked select_security_fixes form shows only
   source/config findings. Fix only selected IDs, then complete_security_run with
   code_results=[{id,status:fixed|failed,reason,validation}]. Failed attempts need
   the real blocker; fixed outcomes need actual validation evidence.
6. Ask the human YES/NO before a deep-dive software audit. No means skip the
   audit, not the final report. Yes generates the complete coverage-checked report,
   THEN opens unchecked audit-fix boxes. Complete selected audit fixes with the
   same code_results schema. Send current item/stage via progress.message.
7. Generate and display the final unresolved-remediation Markdown, including
   package current/target versions and blockers, plus unsuccessful code attempts.
Use complete_security_run to advance one job at a time; it returns the next
handoff. Never combine package and source selections or overlap jobs.
A precheck, branch,
or execution blocker stops edits, not reporting. A package with no safe release
stays unresolved; continue other findings, save reports, and offer the audit.
Each tool description is the procedure for that step.
Use verify_security_finding for every finding. Open the file and line GitLab
   already reported and read that code. A false-positive reason is at most
   2 everyday sentences about why the warning does not apply.
For every npm, NuGet (.NET 10), or Maven/Gradle Java package fix, call
   select_package_version to read the public stable-release catalog, then again
   with documented support/runtime exclusions. Choose the latest supported stable
   release compatible with the actual project runtime, including major upgrades.
   The advisory's minimum fix is not the final target. Never skip a newer release
   merely to minimize the version bump. Flag all paid releases for user
   investigation; never automatically upgrade to paid terms. Unverified licensing
   is allowed only with an explicit warning; configured corporate policy may be stricter.
   Then select_security_fixes before any remediation edit. For Windows package
   checkboxes, first collect the exact-target documentation/API/framework/license
   evidence described by qualify_package_update. Supply package_reviews keyed by
   finding ID. PACKAGE_REVIEW_REQUIRED means finish that read-only AI review and
   repeat selection with the evidence; do not invent evidence or approval.
   Release review schema: target:<exact reviewed eligible version or null if none>,
   supported:true,runtime_compatible:true,sources:[official
   HTTPS URLs],assessment,excluded_releases:[{version,reason:unsupported|
   runtime_incompatible|paid,sources:[official HTTPS URLs],assessment}].
   Qualification review schema: ecosystem,package,target,documentation
   {complete:true,sources,summary},compatible:true,
   compatible_without_code_changes:true,api_changes,frameworks
   [{name,version,source_url,assessment}],source_fixes:[].
   Without corporate policy, license:{expression,sources,
   commercial_use_permitted:true,no_license_fees:true,obligations,assessment}.
   Explicit null permits unknown license permissions/fees with warnings; false blocks.
   For proposed major_upgrade=true also provide major_upgrade:
   {scan_id:proposed_fix.caller_scan.scan_id,compatible_without_code_changes:true,
   caller_breakages_found:false,migration_sources:[official HTTPS URLs],
   api_comparison,caller_assessment,dependency_assessment,
   reviewed_files:[{path,sha256,assessment}]}.
Call qualify_package_update for each selected package update, apply_minimal_fix
for each selected eligible fix with no build between package edits, and
run_validation_matrix once for that package batch. generate_aaa_test applies
only to a selected supported base-image change in the source/config job.
Call complete_security_run after each approved batch, even when every finding
    is blocked or no fix is selected. Follow the seven jobs above; source
    selection follows false-positive review. Audit generation needs human consent.
If the human accepts the audit, generate the complete report BEFORE its fixes.
   Never reuse a previous run's report or skip unreviewed application areas.
   Follow the inventory and submit per-file hash/assessment receipts and completed
   review phases via progress. AUDIT_INCOMPLETE means continue the read-only review.
   After report_ready=True, show unchecked findings from the completed report.
   Fix mode starts
   with every checkbox unchecked and fixes only the checked items. Do not
   choose for the human. Do not commit, push, or open a merge request.
   GENERATE_AUDIT_REPORT and AUDIT_IN_PROGRESS require the host AI to scan
   repo_root now; the server cannot run that AI scan itself. Report progress
   with choose_software_audit_action(progress={message:...,
   files:[{path:<inventory-relative>,sha256:<current full-file hash>,assessment:...}],
   completed_phases:[entry_points|data_access|errors_logs|resource_lifetime|ui_siblings]})
   after each small batch. Complete every inventory file and all five phases;
   record non-applicable phases honestly. Counts are derived from receipts.
   After writing the exact output_path,
   call choose_software_audit_action(report_ready=True) to open the fix checklist
   when requested. Finish selected fixes with complete_security_run(code_results=...).
   Do not stop at a generation request or skip that continuation.
If select_security_fixes returns AWAITING_HUMAN or REMEDIATION_RUNNING, do not
edit or poll. Call choose_software_audit_action with repo_root only: it waits for
the owned background work and returns its audit handoff to this active AI turn.
Follow that result; otherwise a background choice cannot start a host AI scan.
The Windows windows have no review deadline. In job 3 the server qualifies,
applies and production-build validates selected package updates, then offers
separate false-positive approvals. In job 5 it can apply selected documented
Dockerfile, nginx or GitLab CI line fixes. Other source fixes are host-led.
Never duplicate server-owned work while that handoff call waits.
SOURCE_FIXES_REQUIRED returns only human-selected GitLab source findings.
The host AI must implement those scoped code fixes, validate and call
complete_security_run with outcomes before offering the general audit. Never treat a completed
package batch as completion of selected source work.
Do not reopen approved selections or start completion, edits or validation while
selection or server-owned package execution is pending.
Apply all human-approved, qualified package security updates for Node, .NET/C#
and Java, including supported transitive dependency overrides. Retain updates
only after production builds, resolved-version proof and test-free configured
policy checks pass. Never run unit/integration tests for package-only remediation.
If a batch fails, isolate
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


_STDERR_PREPARE_FAILED = "Could not make stderr UTF-8 and line-buffered: %s"
_LOG_PROGRESS_CONSOLE_CLOSED = (
    "Progress console closed; stderr and tool transcripts remain available: %s"
)
_LOG_PROGRESS_CONSOLE_NOT_REAPED = (
    "Progress console could not be reaped after kill; pid=%s"
)
_LOG_PROGRESS_CONSOLE_OPEN_FAILED = (
    "Could not open progress console; stderr and tool transcripts remain available: %s"
)
_LOG_FORMAT = "%(asctime)sZ %(levelname)s %(name)s [%(threadName)s]: %(message)s"
_LOG_DATEFMT = "%Y-%m-%dT%H:%M:%S"


def _prepare_stderr() -> Exception | None:
    """Make stderr UTF-8 and line-buffered for IDE pipes."""
    try:
        sys.stderr.reconfigure(
            encoding="utf-8", errors="backslashreplace", line_buffering=True
        )
    except (AttributeError, OSError, ValueError) as exc:
        return exc
    return None


class _StderrFormatter(logging.Formatter):
    """Keep diagnostic context while redacting the server's environment credentials."""

    converter = gmtime

    def format(self, record: logging.LogRecord) -> str:
        """Redact the complete rendered record, including chained tracebacks."""
        return redact(
            super().format(record),
            environment_secrets(),
        )


def _log_formatter() -> _StderrFormatter:
    """Build one redacting formatter. Handlers must not share an instance."""
    return _StderrFormatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT)


def _stderr_handler() -> logging.Handler:
    """Build one plain-text handler that writes to the current stderr."""
    handler = logging.StreamHandler(_CurrentStderr())
    handler.setFormatter(_log_formatter())
    return handler


def _configure_logging() -> None:
    """Send this server's logs to stderr so they cannot corrupt MCP stdout.

    The MCP SDK installs Rich on the root logger when that package is present.
    That call is skipped once a handler exists. Both IDE output panels then
    receive plain text lines. Level and propagate are applied on every call,
    including when a handler is already attached. A second handler keeps the
    same text for the end-of-run zip.
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
    attach_server_log(_log_formatter())


def _install_host_logging() -> None:
    """Prepare stderr, then attach handlers that write to that stream."""
    failure = _prepare_stderr()
    _configure_logging()
    if isinstance(failure, (OSError, ValueError)):
        logger.warning(_STDERR_PREPARE_FAILED, failure, exc_info=failure)


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
            except (OSError, ValueError) as exc:
                logger.warning(_LOG_PROGRESS_CONSOLE_CLOSED, exc, exc_info=True)
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
                    _LOG_PROGRESS_CONSOLE_NOT_REAPED, process.pid, exc_info=True
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
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10),
        )
    except OSError as exc:
        logger.warning(_LOG_PROGRESS_CONSOLE_OPEN_FAILED, exc, exc_info=True)
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
_audit_progress_roots: set[Path] = set()


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
        if _progress_calls or _audit_progress_roots or not _progress_close_pending:
            return None
        console = _progress_console
        _progress_console = None
        _progress_console_attempted = False
        _progress_console_enabled = False
        _progress_close_pending = False
        return console


_background_status: dict[tuple[Path, str], dict[str, Any]] = {}
_background_status_lock = threading.Lock()
_BACKGROUND_HEARTBEAT_SECONDS = 5
# Returned transcripts are re-read by the host AI; live notifications stay unbounded.
_TRANSCRIPT_LINES = 32
_TRANSCRIPT_CHARS = 500
_AUDIT_PENDING = {
    "AWAITING_HUMAN",
    "CONSENT_REQUIRED",
    "REQUESTED",
    "CHOICE_REQUIRED",
    "CHOICE_UNAVAILABLE",
    "GENERATE_AUDIT_REPORT",
    "AUDIT_IN_PROGRESS",
    "SELECTION_REQUIRED",
    "ITEMS_REQUIRED",
    "AUDIT_INCOMPLETE",
}


def _editor_progress(
    root: Path, task_id: str, label: str, message: str, **details
) -> None:
    """Make editor-delivery failures explicit without cancelling approved remediation."""
    try:
        publish_editor_progress(root, task_id, label, message, **details)
    except (OSError, ValueError):
        logger.warning("Could not publish editor progress for %s", root, exc_info=True)


_audit_activity_tasks: dict[Path, tuple[object, asyncio.Task]] = {}
_desktop_audit_tasks: dict[str, asyncio.Task] = {}


def _seconds_since(stamp: str) -> int | None:
    """Return whole seconds since an ISO time, treating a naive stamp as UTC.

    ``datetime.fromisoformat`` leaves a stamp without an offset naive. Subtracting
    that from an aware UTC clock raises ``TypeError``. An unreadable stamp returns
    ``None`` so the audit heartbeat keeps running.
    """
    try:
        moment = datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return max(0, int((datetime.now(UTC) - moment).total_seconds()))


def _publish_audit_activity(selected: Engine) -> bool:
    """Distinguish a responsive server from unobserved host-AI work."""
    audit = selected.state.software_audit
    status = audit.get("status")
    if status in {
        "AWAITING_HUMAN",
        "REQUESTED",
        "CONSENT_REQUIRED",
        "SELECTION_REQUIRED",
        "CHOICE_REQUIRED",
    }:
        message = (
            audit.get("message")
            or "Waiting for software-audit consent; no scan has started."
        )
        activity_status = "WAITING_FOR_HUMAN"
        reviewed = total = None
        label = "Software audit: approval"
    elif status in {
        "GENERATE_AUDIT_REPORT",
        "AUDIT_IN_PROGRESS",
        "AUDIT_INCOMPLETE",
        "FIX_FROM_AUDIT_REPORT",
    }:
        progress = audit.get("fix_progress") or audit.get("progress") or {}
        coverage = audit.get("coverage") or {}
        reviewed, total = (
            len(coverage.get("reviews", {})),
            len(coverage.get("files", [])),
        )
        stage = (
            "Selected audit fixes"
            if status == "FIX_FROM_AUDIT_REPORT"
            else f"Software audit: {reviewed}/{total} files reviewed"
        )
        message = f"{stage}. {progress.get('message') or 'Approved; waiting for the host AI to report its work.'}"
        updated = progress.get("updated_at") or audit.get("requested_at")
        age = _seconds_since(updated) if isinstance(updated, str) else None
        if age is not None:
            message += f" Last AI update {age}s ago; MCP server responsive."
        activity_status = "WAITING_FOR_AI"
        label = (
            "Software audit: selected fixes"
            if status == "FIX_FROM_AUDIT_REPORT"
            else "Software audit: reviewing"
        )
        if status == "FIX_FROM_AUDIT_REPORT":
            reviewed = total = None
    else:
        return False
    _editor_progress(
        selected.repo_root,
        "software-audit",
        label,
        message,
        status=activity_status,
        completed=reviewed,
        total=total,
    )
    workflow.activity(selected, message, status=activity_status)
    return True


def _keep_audit_visible(selected: Engine) -> None:
    """Own a heartbeat after a tool returns, without inventing AI file progress."""
    previous = _audit_activity_tasks.get(selected.repo_root)
    active = _publish_audit_activity(selected)
    if previous and (not active or previous[0] is not selected.state):
        previous[1].cancel()
    if not active:
        _audit_activity_tasks.pop(selected.repo_root, None)
        return
    if previous and previous[0] is selected.state and not previous[1].done():
        return
    state = selected.state

    async def pulse() -> None:
        """Report server liveness and time since the last actual host update."""
        while True:
            await asyncio.sleep(_BACKGROUND_HEARTBEAT_SECONDS)
            if selected.state is not state or not _publish_audit_activity(selected):
                return

    task = asyncio.create_task(pulse())
    _audit_activity_tasks[selected.repo_root] = (state, task)


def _with_audit_activity(function):
    """Maintain the audit owner independently of short-lived host requests."""

    @wraps(function)
    async def call(ctx, repo_root=None, *args, **kwargs):
        """Publish the saved audit phase even if the request is interrupted."""
        selected = await asyncio.to_thread(_engine_for, repo_root)
        try:
            return await function(ctx, repo_root, *args, **kwargs)
        finally:
            _keep_audit_visible(selected)

    return call


def _with_background_progress(label: str):
    """Keep owned worker progress alive independently of an ended MCP request."""

    def decorate(function):
        """Bind one native callback to its own console lifetime and status."""

        @wraps(function)
        async def run(ctx, selected: Engine, request_id: str, *args, **kwargs):
            """Publish current activity and a truthful heartbeat until callback cleanup."""
            global _progress_calls, _progress_console_enabled
            key = (selected.repo_root, request_id)
            owner_state = selected.state
            owner_job = owner_state.workflow.get("current")
            started = monotonic()
            with _background_status_lock:
                # Completed receipts are diagnostic only, never reusable authorization.
                for old in list(_background_status):
                    if old[0] == selected.repo_root and _background_status[old][
                        "status"
                    ] not in {"RUNNING", "WAITING_FOR_HUMAN", "WAITING_FOR_AI"}:
                        del _background_status[old]
                _background_status[key] = {
                    "task": label,
                    "request_id": request_id,
                    "status": "WAITING_FOR_HUMAN",
                    "current_step": "Waiting for the unchecked selection window.",
                    "started_at": datetime.now(UTC).isoformat(),
                    "updated_at": datetime.now(UTC).isoformat(),
                }
            with _progress_console_lock:
                _progress_calls += 1
                if progress_sink.get() is not None:
                    _progress_console_enabled = True
            ended = threading.Event()

            def publish(text: str) -> None:
                """Never reuse the original request's progress token from a worker."""
                if ended.is_set():
                    return
                text = " ".join(str(text).split())[:2000]
                status = next(
                    (
                        state
                        for state in ("WAITING_FOR_HUMAN", "WAITING_FOR_AI")
                        if text.startswith(state)
                    ),
                    "RUNNING",
                )
                with _background_status_lock:
                    _background_status[key].update(
                        status=status,
                        current_step=text,
                        updated_at=datetime.now(UTC).isoformat(),
                    )
                logger.info(
                    "Background repo=%s task=%s: %s", selected.repo_root, label, text
                )
                _editor_progress(
                    selected.repo_root, request_id, label, text, status=status
                )
                if (
                    selected.state is owner_state
                    and owner_state.workflow.get("current") == owner_job
                ):
                    if not _publish_audit_activity(selected):
                        workflow.activity(selected, text, status=status)
                console = _console_for_progress()
                if console is not None:
                    console.write(f"{selected.repo_root} | {label} | {text}")

            async def heartbeat() -> None:
                """Show elapsed activity, not an invented overall completion percentage."""
                while True:
                    await asyncio.sleep(_BACKGROUND_HEARTBEAT_SECONDS)
                    with _background_status_lock:
                        _background_status[key].update(
                            heartbeat_at=datetime.now(UTC).isoformat(),
                            elapsed_seconds=round(monotonic() - started, 1),
                        )
                        snapshot = dict(_background_status[key])
                    execution = (
                        selected.state.fix_selection.get("package_execution") or {}
                    )
                    steps = len(execution.get("results") or [])
                    text = f"{selected.repo_root} | {label} | {snapshot['status']} | {int(monotonic() - started)}s elapsed | {steps} execution steps finished; overall total unknown | {snapshot['current_step']}"
                    logger.info("%s", text)
                    _editor_progress(
                        selected.repo_root,
                        request_id,
                        label,
                        text,
                        status=snapshot["status"],
                    )
                    if (
                        selected.state is owner_state
                        and owner_state.workflow.get("current") == owner_job
                    ):
                        workflow.activity(
                            selected,
                            snapshot["current_step"],
                            status=snapshot["status"],
                        )
                    console = _console_for_progress()
                    if console is not None:
                        console.write(text)

            token = progress_sink.set(publish)
            ticker = asyncio.create_task(heartbeat())
            outcome = "FINISHED"
            try:
                publish(
                    "WAITING_FOR_HUMAN | Selection window is open; no response deadline."
                )
                return await function(ctx, selected, request_id, *args, **kwargs)
            except asyncio.CancelledError:
                outcome = "CANCELLED"
                raise
            except Exception:
                outcome = "FAILED"
                raise
            finally:
                ticker.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await ticker
                execution = selected.state.fix_selection.get("package_execution") or {}
                selection = selected.state.fix_selection
                approval = selected.state.false_positive_approval_form
                detail = (
                    selected.state.software_audit.get("status")
                    if label == "Software audit approval"
                    else (
                        execution.get("status") or selection.get("status")
                        if selection.get("request_id") == request_id
                        else approval.get("status")
                    )
                )
                if outcome == "FINISHED" and detail in {
                    "INVALID",
                    "UNAVAILABLE",
                    "APPROVAL_INVALID",
                    "APPROVAL_INTERRUPTED",
                    "PARTIAL_FAILURE",
                    "BLOCKED",
                    "INTERRUPTED",
                }:
                    outcome = detail
                publish(
                    f"{outcome} | callback outcome: {detail or 'see run status'}; this is not an overall run-success claim."
                )
                ended.set()
                with _background_status_lock:
                    _background_status[key].update(
                        status=outcome,
                        outcome=detail,
                        elapsed_seconds=round(monotonic() - started, 1),
                    )
                progress_sink.reset(token)
                _editor_progress(
                    selected.repo_root,
                    request_id,
                    label,
                    f"{outcome}: {detail}",
                    status=outcome,
                )
                console = _finish_progress_call(
                    selected.state.software_audit.get("status") not in _AUDIT_PENDING
                )
                if console is not None:
                    await asyncio.to_thread(console.close)

        return run

    return decorate


def _background_for(selected: Engine) -> list[dict[str, Any]]:
    """Read worker activity without waiting behind a long-running engine mutation."""
    with _background_status_lock:
        return [
            dict(value)
            for (root, _), value in _background_status.items()
            if root == selected.repo_root
        ]


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
    transcript: deque[str] = deque(maxlen=_TRANSCRIPT_LINES)
    finished = threading.Event()
    editor_task = uuid4().hex
    latest = "Starting " + str(name or "MCP task")

    def editor_update(text: str, status: str = "RUNNING") -> None:
        """Resolve registered checkouts without constructing an engine for UI output."""
        arguments = (getattr(context, "params", None) or {}).get("arguments") or {}
        root = arguments.get("repo_root")
        with _registry_lock:
            selected = (
                _engines.get(Path(root).expanduser().resolve())
                if root
                else next(iter(_engines.values()))
                if len(_engines) == 1
                else None
            )
        if selected is not None and name != "get_run_status":
            _editor_progress(
                selected.repo_root, editor_task, str(name), text, status=status
            )
            if status == "RUNNING":
                if not _publish_audit_activity(selected):
                    workflow.activity(selected, text)
        elif root and name == "run_prechecks":
            _editor_progress(
                Path(root).expanduser().resolve(),
                editor_task,
                f"Job {JOB_PRECHECKS}/{JOB_COUNT}: Pre-checks",
                text,
                status=status,
            )

    def enqueue(text: str) -> None:
        """Keep the most recent updates if a client consumes notifications slowly."""
        if finished.is_set():
            return
        line = text[:_TRANSCRIPT_CHARS]
        if not transcript or transcript[-1] != line:
            transcript.append(line)
        if messages.full():
            messages.get_nowait()
            messages.task_done()
        messages.put_nowait(text)

    def publish(text: str) -> None:
        """Schedule updates from either command reader thread onto the MCP loop."""
        nonlocal latest
        if finished.is_set():
            return
        text = str(text)[:2000]
        latest = text
        editor_update(text)
        console = _console_for_progress()
        if console is not None:
            console.write(text)
        try:
            loop.call_soon_threadsafe(enqueue, text)
        except RuntimeError as exc:
            logger.warning(
                "Could not queue progress: the MCP event loop has closed: %s",
                exc,
                exc_info=True,
            )

    async def deliver() -> None:
        """Send monotonic notification sequence numbers with count-based text bars."""
        sequence = 0
        while True:
            text = await messages.get()
            try:
                sequence += 1
                await context.session.report_progress(sequence, None, text)
            except (*PROGRESS_PUBLISH_FAILURES, MCPError):
                logger.warning("Could not send MCP progress", exc_info=True)
            finally:
                messages.task_done()

    token = progress_sink.set(publish)
    sender = asyncio.create_task(deliver())

    async def pulse() -> None:
        """Keep silent tool calls visible without elapsed-time completion estimates."""
        while True:
            await asyncio.sleep(_BACKGROUND_HEARTBEAT_SECONDS)
            editor_update(latest)

    ticker = asyncio.create_task(pulse())
    terminal = True
    tool_outcome = "FAILED"
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
        tool_outcome = (
            "FAILED"
            if status == "ERROR"
            or (isinstance(result, CallToolResult) and result.is_error)
            else "FINISHED"
        )
        terminal = (isinstance(result, CallToolResult) and result.is_error) or (
            isinstance(status, str)
            and (
                status in {"REPORT_GENERATED", "ERROR"}
                or status.endswith(("_FAILED", "_INCOMPLETE"))
            )
        )
        if isinstance(payload, dict):
            audit = payload.get("software_audit") or {}
            review = payload.get("false_positive_review") or {}
            if (
                audit.get("status") in _AUDIT_PENDING
                or review.get("status") == "AWAITING_HUMAN"
            ):
                terminal = False
            if name == "choose_software_audit_action" and status in {
                "DONE",
                "NONE_SELECTED",
                "NO_FINDINGS",
                "AUDIT_REPORT_GENERATED",
            }:
                terminal = True
    except asyncio.CancelledError:
        tool_outcome = "CANCELLED"
        raise
    finally:
        ticker.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await ticker
        editor_update(latest, tool_outcome)
        progress_sink.reset(token)
        try:
            async with asyncio.timeout(1):
                await asyncio.sleep(0)
                await messages.join()
        except TimeoutError:
            logger.warning(
                "MCP progress delivery timed out; the bounded tool transcript remains available.",
                exc_info=True,
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
    for _state, task in list(_audit_activity_tasks.values()):
        task.cancel()
    _audit_activity_tasks.clear()
    with logged_lock(_registry_lock, "registry"):
        engines = list(_engines.values())
        _engines.clear()
    with _progress_console_lock:
        _audit_progress_roots.clear()
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
                raise ValueError(_RAISE_MORE_THAN_ONE_REPOSITORY_IS_ACTIVE_PASS_REPO)
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
        if tool_name == "get_run_status":
            return _live_run_status(selected, **kwargs)
        stages = {
            "pull_main_twice": (JOB_PRECHECKS,),
            "create_security_branch": (JOB_PRECHECKS,),
            "list_security_findings": (JOB_DOWNLOAD,),
            "verify_security_finding": (JOB_PACKAGES, JOB_FALSE_POSITIVES),
            "select_package_version": (JOB_PACKAGES,),
            "qualify_package_update": (JOB_PACKAGES,),
            "apply_minimal_fix": (JOB_PACKAGES, JOB_SOURCE),
            "generate_aaa_test": (JOB_SOURCE,),
            "run_validation_matrix": (JOB_PACKAGES, JOB_SOURCE),
        }
        blocked = (
            workflow.require(selected, *stages[tool_name])
            if tool_name in stages
            else None
        )
        if blocked:
            return blocked
        if (
            tool_name == "run_prechecks"
            and selected.state.workflow
            and selected.state.workflow["current"] not in {JOB_PRECHECKS, JOB_REPORT}
        ):
            return workflow.require(selected, JOB_PRECHECKS, JOB_REPORT)
        if tool_name in {
            "qualify_package_update",
            "apply_minimal_fix",
            "generate_aaa_test",
            "run_validation_matrix",
        }:
            return selected.run_approved_fix(tool_name, *args, **kwargs)
        result = getattr(selected, tool_name)(*args, **kwargs)
        if tool_name == "run_prechecks" and result["status"] != "REMEDIATION_RUNNING":
            workflow.start(selected)
            if result["status"] != "PRECHECK_PASSED":
                selected.state.workflow["blocked"] = (
                    result.get("reason") or result.get("error") or result["status"]
                )
                selected._remember()
                workflow.activity(
                    selected, selected.state.workflow["blocked"], status="FAILED"
                )
        elif selected.state.workflow:
            if (
                tool_name == "create_security_branch"
                and result["status"] == "BRANCH_CREATED"
            ):
                workflow.advance(selected)
            elif tool_name == "list_security_findings" and result["status"] == "OK":
                workflow.advance(selected)
            elif tool_name in {
                "pull_main_twice",
                "create_security_branch",
                "list_security_findings",
            } and (result["status"] == "ERROR" or result["status"].endswith("_FAILED")):
                selected.state.workflow["blocked"] = (
                    result.get("reason") or result.get("error") or result["status"]
                )
                selected._remember()
        return result
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
        title="Select latest supported package version",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=True,
    )
)
def select_package_version(
    finding_id: str, review: dict[str, Any] | None = None, repo_root: str | None = None
) -> dict[str, Any]:
    """Read releases; submit workflow-schema review to select the latest eligible target before approval."""
    return _run("select_package_version", finding_id, review, repo_root=repo_root)


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
    """Job 2: download GitLab findings; infer project from origin. Verify branch-resolution claims locally."""
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
    """Assess read-only. Read the cited code, callers and inputs. source_review.reason: <=2 everyday sentences, <=400 chars. HOST_REVIEW_REQUIRED is unfinished."""
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
    """Qualify the selected latest target using the workflow schema. Paid terms block; unknown fees warn."""
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
        raise ValueError(_RAISE_THE_HUMAN_FIX_SELECTION_RESPONSE_DOES_NOT_MATCH)
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


@_with_background_progress("Security fix selection and execution")
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
    """Execute reviewed package and configuration choices after physical approval."""
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
            raise ValueError(_RAISE_A_BLOCKED_UPDATE_CANNOT_BE_SELECTED_OBTAIN_A)
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
        if result["status"] == "SKIPPED":
            await complete_security_run(ctx, str(selected.repo_root))
        if result["status"] == "APPROVED" and result.get("server_execution_queued"):
            work = asyncio.create_task(
                asyncio.to_thread(
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
            warnings = prepared.get("warnings", {}).get(item["id"], [])
            if warnings:
                field["description"] = (
                    "\n".join(warnings) + "\n\n" + field["description"]
                )
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
            + (
                f"Job {JOB_PACKAGES}/{JOB_COUNT} - PACKAGE UPDATES ONLY (frontend and backend). Source fixes have a separate later selection.\r\n"
                if selected.state.workflow.get("current") == JOB_PACKAGES
                else f"Job {JOB_SOURCE}/{JOB_COUNT} - SOURCE/CONFIG FIXES ONLY. Package selection and false-positive review are finished.\r\n"
                if selected.state.workflow.get("current") == JOB_SOURCE
                else ""
            )
            + "Select only the package updates or scoped code fixes you authorize. All boxes start unchecked. "
            "Review current/proposed versions, file scope, risk and acceptance requirements. "
            "There is no selection deadline. Cancel or close authorizes nothing. "
            "After submission, the server applies checked package updates and documented Dockerfile, nginx or GitLab CI line fixes, "
            "            then runs production builds/dependency checks, never unit/integration tests. "
            "Keep the server running; no second continue request is needed for these. Other source-code fixes still require your IDE agent.",
            properties,
            title=(
                "GitLab security: choose package updates"
                if selected.state.workflow.get("current") == JOB_PACKAGES
                else "GitLab security: choose source fixes"
                if selected.state.workflow.get("current") == JOB_SOURCE
                else "GitLab security: choose updates and code fixes"
            ),
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
            "After submission the server automatically qualifies, edits and validates selected package updates, applies and validates "
            "selected documented Dockerfile, nginx or GitLab CI line fixes, then saves reports and offers separate false-positive approvals. "
            "Keep the server running. Only other selected source-code fixes require the IDE agent to continue.",
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
        logger.warning(
            "Could not display Windows fix-selection window: %s", exc, exc_info=True
        )
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
    """Unchecked human GUI: job 3 packages, job 5 source. package_reviews[id] uses workflow evidence; blocked_reason disables unsafe updates."""
    selected = await asyncio.to_thread(_engine_for, repo_root)
    blocked = workflow.require(selected, JOB_PACKAGES, JOB_SOURCE)
    if blocked:
        return blocked
    job = selected.state.workflow.get("current")
    if job == JOB_PACKAGES:
        missing = [
            item["id"]
            for item in selected.state.findings
            if item.get("category")
            not in {
                "sast",
                "secret_detection",
                "dast",
                "coverage_fuzzing",
                "api_fuzzing",
            }
            and item["id"] not in selected.state.decisions
        ]
        if missing:
            return {
                "status": "FINDING_REVIEW_REQUIRED",
                "finding_ids": missing,
                "next_tool": "verify_security_finding",
            }
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
        if job == JOB_PACKAGES:
            selected.state.workflow["package_reviews"] = deepcopy(prepared["reviews"])
            selected._remember()
        if prepared.get("all_blocked"):
            result = await asyncio.to_thread(
                selected.record_fix_selection,
                candidates,
                [],
                "SKIPPED",
                "Every proposed update is blocked by its documented review; no edits are authorized.",
            )
            completion = await complete_security_run(ctx, str(selected.repo_root))
            return {
                **result,
                "blocked_updates": [
                    {"finding_id": key, "reason": review["blocked_reason"]}
                    for key, review in prepared["reviews"].items()
                ],
                "completion": completion.structured_content,
            }
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
            (
                f"Job {JOB_PACKAGES}/{JOB_COUNT}: Select frontend/backend PACKAGE UPDATES only. Source choices come after false-positive review. "
                if job == JOB_PACKAGES
                else f"Job {JOB_SOURCE}/{JOB_COUNT}: Select GitLab SOURCE/CONFIG fixes only. Package updates and false-positive review are finished. "
                if job == JOB_SOURCE
                else ""
            )
            + f"Choose which security issues may be fixed in {selected.repo_root}. "
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
        logger.warning(
            "Security fix selection unavailable or invalid: %s", exc, exc_info=True
        )
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


@_with_background_progress("False-positive approval")
async def _finish_desktop_approval(
    ctx: Context,
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
    if selected.state.workflow:
        if selected.state.false_positive_approval_form.get("request_id") == request_id:
            await complete_security_run(ctx, str(selected.repo_root))
    elif (
        selected.state.false_positive_approval_form.get("request_id") == request_id
        and _software_audit_blocked(selected) is None
    ):
        await _offer_software_audit(ctx, selected)


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
    blocked = workflow.require(selected, JOB_FALSE_POSITIVES)
    if blocked:
        return blocked
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
            logger.warning(
                "Could not display Windows approval window: %s", exc, exc_info=True
            )
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
                ctx, selected, receipt["request_id"], candidates, schema, dialog
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
        logger.warning(
            "Invalid false-positive approval response: %s", exc, exc_info=True
        )
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
        logger.warning(
            "False-positive approval form unavailable: %s", exc, exc_info=True
        )
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
        title="Continue security workflow (legacy name)",
        read_only_hint=False,
        destructive_hint=True,
        open_world_hint=True,
    )
)
async def generate_local_report(
    ctx: Context, repo_root: str | None = None
) -> CallToolResult:
    """Alias for complete_security_run; follow the current ordered job."""
    return await complete_security_run(ctx, repo_root)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Advance ordered security jobs",
        read_only_hint=False,
        destructive_hint=True,
        open_world_hint=True,
    )
)
@_with_audit_activity
async def complete_security_run(
    ctx: Context,
    repo_root: str | None = None,
    code_results: list[dict[str, Any]] | None = None,
    progress: dict[str, Any] | None = None,
) -> CallToolResult:
    """Advance jobs; code_results use workflow outcome schema; progress={id,message}."""
    selected = await asyncio.to_thread(_engine_for, repo_root)
    if not selected.state.workflow:
        return await _complete_legacy(ctx, repo_root)
    lock = _workflow_locks.setdefault(selected.repo_root, asyncio.Lock())
    async with lock:
        result = await _continue_workflow(ctx, selected, code_results, progress)
    return CallToolResult(
        content=[
            TextContent(
                text=result.get("final_summary_markdown")
                or result.get("message")
                or result.get("reason")
                or result["status"]
            )
        ],
        structuredContent=result,
        isError=result["status"] == "ERROR",
    )


_workflow_locks: dict[Path, asyncio.Lock] = {}


class CodeFixResult(BaseModel):
    """An explicit host attestation, not independent proof of a successful code fix."""

    id: str = Field(min_length=1, strict=True)
    status: Literal["fixed", "failed"]
    reason: str = Field(min_length=1, strict=True)
    validation: str = Field(default="", strict=True)


def _record_code_results(selected: Engine, results: list[dict] | None) -> dict | None:
    """Require a result for each approved host-led fix before leaving its job."""
    state = selected.state
    audit = state.workflow["current"] == JOB_AUDIT
    ids = (
        [item["id"] for item in state.software_audit.get("selected_items", [])]
        if audit
        else _workflow_source_ids(state.fix_selection)
    )
    prefix = "audit" if audit else "gitlab"
    stored = state.workflow["code_results"]
    if not audit:
        execution = state.fix_selection.get("package_execution") or {}
        for finding_id in execution.get("config_ids", []):
            change = next(
                (
                    item
                    for item in reversed(state.changes)
                    if item.get("finding_id") == finding_id
                    and item.get("status") != "TEST_ADDED"
                ),
                {},
            )
            fixed = (
                change.get("status") == "APPLIED"
                and not change.get("validation_pending")
                and state.validation_status == "VALIDATION_COMPLETE"
            )
            stored[f"gitlab:{finding_id}"] = {
                "id": finding_id,
                "origin": "gitlab",
                "status": "fixed" if fixed else "failed",
                "reason": change.get("detail")
                or execution.get("reason")
                or (
                    "Applied and validated configuration fix."
                    if fixed
                    else "Configuration fix did not pass the recorded execution/validation checks."
                ),
                "validation": str(state.validation_status or "Not completed"),
                "evidence": "MCP execution/validation receipts",
            }
    try:
        parsed = [CodeFixResult.model_validate(item) for item in results or []]
        if len({item.id for item in parsed}) != len(parsed):
            raise ValueError(_RAISE_DUPLICATE_CODE_FIX_OUTCOME_IDS)
        for item in parsed:
            if item.id not in ids or not item.reason.strip():
                raise ValueError(
                    _RAISE_IS_NOT_A_SELECTED_FIX_OR_LACKS_ITS.format(item.id)
                )
            if item.status == "fixed" and not item.validation.strip():
                raise ValueError(
                    _RAISE_NEEDS_THE_ACTUAL_VALIDATION_COMMAND_RESULT_BEFORE_REPORTING.format(
                        item.id
                    )
                )
    except ValueError as exc:
        logger.warning("Code outcome rejected: %s", exc, exc_info=True)
        return {"status": "ERROR", "reason": str(exc)}
    for item in parsed:
        stored[f"{prefix}:{item.id}"] = {
            **item.model_dump(),
            "origin": prefix,
            "evidence": "Host-reported; not independently verified by MCP",
        }
    selected._remember()
    missing = [item for item in ids if f"{prefix}:{item}" not in stored]
    if missing:
        workflow.activity(
            selected,
            f"Waiting for code-fix outcomes: {', '.join(missing)}",
            status="WAITING_FOR_AI",
        )
        return {
            "status": "CODE_FIX_RESULTS_REQUIRED",
            "selected_ids": missing,
            "message": "Fix only selected items, then call complete_security_run(code_results=[{id,status:fixed|failed,reason,validation}]). Report real failures, not success-shaped fallbacks. Send progress={id,message} while working.",
        }
    return None


async def _continue_workflow(
    ctx: Context,
    selected: Engine,
    code_results: list[dict] | None,
    progress: dict | None,
) -> dict:
    """Run only the next job, returning host work instead of overlapping jobs."""
    state = selected.state
    job = state.workflow["current"]
    if progress is not None:
        if (
            code_results is not None
            or job not in {JOB_SOURCE, JOB_AUDIT}
            or not isinstance(progress.get("message"), str)
            or not progress["message"].strip()
        ):
            return {
                "status": "ERROR",
                "reason": "Code progress needs a message in job 5 or 6; do not combine it with outcomes.",
            }
        ids = (
            [item["id"] for item in state.software_audit.get("selected_items", [])]
            if job == JOB_AUDIT
            else state.fix_selection.get("selected_ids", [])
        )
        if progress.get("id") not in ids:
            return {
                "status": "ERROR",
                "reason": "Progress must identify a human-selected code finding.",
            }
        workflow.activity(
            selected,
            f"{progress['id']}: {progress['message']}",
            status="WAITING_FOR_AI",
        )
        if job == JOB_AUDIT:
            state.software_audit["fix_progress"] = {
                "message": f"{progress['id']}: {progress['message']}",
                "updated_at": datetime.now(UTC).isoformat(),
            }
            selected._remember()
        return {"status": "CODE_FIX_IN_PROGRESS", "current_job": job}
    if code_results is not None and job not in {JOB_SOURCE, JOB_AUDIT}:
        return {
            "status": "ERROR",
            "reason": "Code outcomes require the selected source or audit-fix job.",
        }
    blocked = _software_audit_blocked(selected)
    if blocked:
        return blocked
    if state.manual_cleanup_required:
        state.workflow["blocked"] = (
            "Manual checkout cleanup is required after remediation. Further edits and audit fixes were stopped; inspect the full security report."
        )
    if state.workflow.get("blocked"):
        first = state.workflow["current"]
        while state.workflow["current"] < JOB_COUNT:
            workflow.advance(
                selected,
                status="FAILED" if state.workflow["current"] == first else "SKIPPED",
                message=state.workflow["blocked"],
            )
        job = JOB_REPORT
    if job in {JOB_PRECHECKS, JOB_DOWNLOAD}:
        return {
            "status": "JOB_ORDER_REQUIRED",
            "current_job": job,
            "message": "Finish pre-checks/branch preparation, then download GitLab findings.",
        }
    if job == JOB_PACKAGES:
        selection = state.fix_selection
        if not selection or selection.get("status") in {"REQUESTED", "AWAITING_HUMAN"}:
            return {
                "status": "PACKAGE_SELECTION_REQUIRED",
                "next_tool": "select_security_fixes",
            }
        pending = [
            item["finding_id"]
            for item in state.changes
            if item.get("validation_pending")
        ]
        if pending and not state.manual_cleanup_required:
            return {
                "status": "VALIDATION_REQUIRED",
                "finding_ids": pending,
                "next_tool": "run_validation_matrix",
            }
        attempted = {item.get("finding_id") for item in state.changes}
        missing = [
            item
            for item in selection.get("selected_ids", [])
            if item not in attempted
            and not (selected._finding(item) or {}).get("packageQualification")
            and not any(row["id"] == item for row in state.no_solution)
        ]
        if missing:
            return {
                "status": "PACKAGE_FIXES_REQUIRED",
                "selected_ids": missing,
                "next_tool": "qualify_package_update",
                "message": "Apply the approved package updates and validate, or record their actual blockers before advancing.",
            }
        state.workflow["package_selection"] = deepcopy(selection)
        state.fix_selection = {}
        selected._fix_selection_snapshot = None
        workflow.advance(
            selected,
            message="Package job finished; unresolved updates remain in the final report.",
        )
        job = JOB_FALSE_POSITIVES
    if job == JOB_FALSE_POSITIVES:
        missing = [
            item["id"]
            for item in state.findings
            if item["id"] not in state.decisions
            or state.decisions[item["id"]].get("decision") == "SOURCE_REVIEW_REQUIRED"
        ]
        if missing:
            workflow.activity(
                selected,
                f"Review finding {missing[0]} for a real vulnerability or false-positive evidence.",
                status="WAITING_FOR_AI",
            )
            return {
                "status": "FINDING_REVIEW_REQUIRED",
                "finding_ids": missing,
                "next_tool": "verify_security_finding",
                "message": "Read the GitLab-cited code and callers; submit evidence, then complete_security_run. Unknown reachability is not a false positive.",
            }
        if not state.false_positive_approval_form:
            review = await submit_false_positive_approvals(ctx, str(selected.repo_root))
            if review["status"] == "AWAITING_HUMAN":
                return review
            state.workflow["false_positive_result"] = deepcopy(review)
        workflow.advance(
            selected,
            message="False-positive review finished; only human-checked findings were submitted.",
        )
        job = JOB_SOURCE
    if job == JOB_SOURCE:
        if not state.fix_selection:
            return {
                "status": "SOURCE_SELECTION_REQUIRED",
                "next_tool": "select_security_fixes",
                "message": "Call select_security_fixes now to display a NEW unchecked source-only human form. Package choices are not source permission.",
            }
        missing = _record_code_results(selected, code_results)
        if missing:
            if missing["status"] == "ERROR":
                return missing
            handoff = _selected_source_handoff(selected)
            return {**missing, **(handoff or {})}
        workflow.advance(
            selected,
            message="Selected GitLab source work finished; asking whether to run the audit.",
        )
        job = JOB_AUDIT
    if job == JOB_AUDIT:
        audit = state.software_audit
        if not audit or audit.get("status") in {
            "REQUESTED",
            "CONSENT_REQUIRED",
            "CONSENT_UNAVAILABLE",
        }:
            return await _offer_software_audit(ctx, selected)
        if audit.get("status") == "FIX_FROM_AUDIT_REPORT":
            missing = _record_code_results(selected, code_results)
            if missing:
                return missing
        elif audit.get("status") not in {"DONE", "NONE_SELECTED", "NO_FINDINGS"}:
            return _compact_audit(audit)
        workflow.advance(
            selected,
            status="SKIPPED" if not audit.get("output_path") else "FINISHED",
            message="Software audit job finished.",
        )
    if state.workflow["current"] == JOB_REPORT:
        if state.workflow.get("final_report"):
            return deepcopy(state.workflow["final_result"])
        await asyncio.to_thread(selected.generate_local_report)
        result = await asyncio.to_thread(
            write_unresolved_report, selected.repo_root, state
        )
        try:
            result["log_archive"] = await asyncio.to_thread(
                archive_run_logs,
                selected.repo_root,
                project_file_name(state.gitlab_project_path, selected.repo_root.name),
                datetime.now(UTC),
            )
        except (OSError, ValueError) as exc:
            logger.exception("Could not archive run logs")
            result["log_archive"] = {"status": "ERROR", "path": None, "error": str(exc)}
        state.workflow["final_report"] = True
        state.workflow["final_result"] = result
        workflow.advance(
            selected,
            message="Final unresolved report is ready; opening Markdown preview.",
        )
        workflow.activity(selected, result["message"], status="FINISHED")
        return result
    raise RuntimeError(_RAISE_UNEXPECTED_WORKFLOW_JOB)


async def _complete_legacy(
    ctx: Context, repo_root: str | None = None
) -> CallToolResult:
    """Save GitLab reports, then request the full audit before Select fixes / Exit.

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
    if selection.get("status") in {"REQUESTED", "AWAITING_HUMAN"}:
        message = "Wait for the human's open fix-selection window. Approved, reviewed packages and documented configuration line fixes continue automatically; other selected source fixes remain host-led. Do not poll or reopen."
        return CallToolResult(
            content=[TextContent(text=message)],
            structuredContent={
                "status": "AWAITING_HUMAN",
                "fix_selection": selection,
                "message": message,
            },
        )
    if _selected_source_ids(selection):
        _editor_progress(
            selected.repo_root,
            "gitlab-source-fixes",
            "Selected GitLab source fixes",
            "The host requested final reporting after its scoped code work; see the report for validation and unresolved issues.",
            status="HOST_REPORTED_COMPLETE",
        )
    review = await review_false_positives(ctx, repo_root=selected_root)
    report = await asyncio.to_thread(_generate_local_report, repo_root=selected_root)
    if report.structured_content is None:
        raise RuntimeError(_RAISE_THE_LOCAL_REPORT_DID_NOT_RETURN_STRUCTURED_REPORT)
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
                    _RAISE_THE_REFRESHED_REPORT_DID_NOT_RETURN_STRUCTURED_REPORT
                )
    note = f"False-positive review: {review['status']}."
    for key in ("message", "reason"):
        if review.get(key):
            note += f"\n{review[key]}"
    audit = None
    if review["status"] == "AWAITING_HUMAN":
        note += "\nThe software-audit choice is offered automatically after this window closes."
    elif not report.is_error:
        audit = await _offer_software_audit(ctx, selected)
        note += f"\nSoftware audit: {audit['status']}."
        if audit.get("message"):
            note += f"\n{audit['message']}"
    return CallToolResult(
        content=[TextContent(text=note), *report.content],
        structuredContent={
            **report.structured_content,
            "false_positive_review": review,
            "software_audit": audit,
            "software_audit_next_tool": "choose_software_audit_action",
        },
        isError=report.is_error
        or review["status"] in {"ERROR", "PARTIAL_FAILURE", "APPROVAL_INVALID"},
    )


class AuditReviewedFile(BaseModel):
    """Bind a host review assessment to a named file and its actual content."""

    path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    assessment: str = Field(min_length=1)


class AuditGeneratedExclusion(BaseModel):
    """Bind a generated output path to the project's current generator evidence."""

    path: str = Field(min_length=1)
    evidence: AuditReviewedFile


class SoftwareAuditProgress(BaseModel):
    """Validate host file counts without coercing booleans or negative counts."""

    message: str = Field(min_length=1, strict=True)
    reviewed_files: int | None = Field(default=None, ge=0, strict=True)
    total_files: int | None = Field(default=None, ge=0, strict=True)
    files: list[AuditReviewedFile] = Field(default_factory=list)
    generated_exclusions: list[AuditGeneratedExclusion] = Field(default_factory=list)
    completed_phases: list[str] = Field(default_factory=list)


class SoftwareAuditChoice(BaseModel):
    """One closing action chosen by the human."""

    action: Literal["fix_from_report", "done"] = Field(
        description=(
            "fix_from_report selects issues from the completed report. "
            "done stops without code changes."
        )
    )


class SoftwareAuditConsent(BaseModel):
    """Ask before performing the optional read-only deep dive."""

    run_audit: bool = Field(
        default=False,
        strict=True,
        description="Run the deep-dive software audit? No skips to the final unresolved report.",
    )


@_with_background_progress("Software audit approval")
async def _finish_audit_approval(
    ctx: Context,
    selected: Engine,
    request_id: str,
    stage: str,
    dialog: desktop_approval.DesktopApproval,
    prepared: dict,
    schema: type[BaseModel] | None,
) -> None:
    """Keep human approval alive when the initiating host request ends or times out."""
    state = selected.state
    try:
        response = await dialog.wait()
        if (
            selected.state is not state
            or state.software_audit.get("request_id") != request_id
        ):
            raise ValueError(_RAISE_THIS_AUDIT_APPROVAL_BELONGS_TO_A_REPLACED_RUN)
        if stage == "CONSENT":
            await asyncio.to_thread(
                _software_audit_result, selected, response["choice"]
            )
            if response["choice"] == "done":
                await complete_security_run(ctx, str(selected.repo_root))
        else:
            if schema is None:
                raise ValueError(_RAISE_THE_AUDIT_FIX_APPROVAL_SCHEMA_IS_MISSING)
            values = (
                schema.model_validate(response.get("content")).model_dump()
                if response["action"] == "accept"
                else {}
            )
            checked = [item["id"] for item in _checked(prepared["items"], values)]
            result = await asyncio.to_thread(
                _software_audit_fix,
                selected,
                checked,
                expected_report_hash=prepared["report_hash"],
            )
            await _finish_empty_audit(ctx, selected, result)
    except asyncio.CancelledError:
        if (
            selected.state is state
            and state.software_audit.get("request_id") == request_id
        ):
            _record_audit_result(
                selected,
                {
                    "status": "CONSENT_UNAVAILABLE"
                    if stage == "CONSENT"
                    else "SELECTION_REQUIRED",
                    "message": "The server interrupted the audit approval. No new permission was recorded.",
                },
            )
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        logger.exception("Software-audit approval failed")
        if (
            selected.state is state
            and state.software_audit.get("request_id") == request_id
        ):
            _record_audit_result(
                selected,
                {
                    "status": "CONSENT_UNAVAILABLE"
                    if stage == "CONSENT"
                    else "SELECTION_REQUIRED",
                    "reason": str(exc),
                    "message": "No new audit permission was recorded; review the error and retry approval.",
                },
            )
    finally:
        await dialog.close()
        _keep_audit_visible(selected)


async def _open_audit_approval(
    ctx: Context,
    selected: Engine,
    stage: str,
    prepared: dict | None = None,
) -> dict:
    """Reserve and show one owned native window, returning before the human decides."""
    if stage not in {"CONSENT", "FIX_SELECTION"} or (
        stage == "FIX_SELECTION" and prepared is None
    ):
        raise ValueError(_RAISE_AUDIT_APPROVAL_NEEDS_A_KNOWN_STAGE_AND_THE)
    state = selected.state
    request_id = uuid4().hex
    pending = {
        "status": "AWAITING_HUMAN",
        "request_id": request_id,
        "approval_stage": stage,
        "message": "The audit approval window is open with no selection deadline. No AI scan or fix starts without human approval. Call choose_software_audit_action once with repo_root only to collect its handoff; do not reopen the window.",
    }
    _record_audit_result(selected, pending)
    dialog = None
    try:
        schema = None
        if stage == "CONSENT":
            dialog = await desktop_approval.open_choice(
                "Run software audit?",
                "Run a deep-dive software audit now? Yes generates the complete report before unchecked fix choices. No skips to the final unresolved report.",
                [
                    {"id": "generate_report", "label": "Yes - run software audit"},
                    {"id": "done", "label": "No - final report"},
                ],
            )
        else:
            if prepared is None:
                raise ValueError(_RAISE_AUDIT_FINDINGS_ARE_REQUIRED_FOR_FIX_SELECTION)
            schema = _checkbox_model(
                "SoftwareAuditFixes",
                prepared["items"],
                lambda item: (
                    f"{item['id']}: {item['problem']}",
                    f"{item['severity']} at {item['location']}",
                ),
            )
            properties = schema.model_json_schema()["properties"]
            for value in properties.values():
                value["summary"] = value["description"]
            dialog = await desktop_approval.open_dialog(
                "Check only the audit items to fix. Every box starts unchecked. Cancel fixes nothing.",
                properties,
                title="Software audit fixes",
                detail_header="Finding",
                submit_label="Fix checked items",
            )
        if (
            selected.state is not state
            or state.software_audit.get("request_id") != request_id
        ):
            raise ValueError(_RAISE_THE_AUDIT_APPROVAL_BELONGS_TO_A_REPLACED_RUN)
        task = asyncio.create_task(
            _finish_audit_approval(
                ctx, selected, request_id, stage, dialog, prepared or {}, schema
            )
        )
        _desktop_audit_tasks[request_id] = task
        task.add_done_callback(
            partial(
                _desktop_task_done,
                tasks=_desktop_audit_tasks,
                request_id=request_id,
                repo_root=selected.repo_root,
            )
        )
        return pending
    except BaseException:
        if dialog is not None:
            await dialog.close()
        if (
            selected.state is state
            and state.software_audit.get("request_id") == request_id
        ):
            _record_audit_result(
                selected,
                {
                    "status": "CONSENT_UNAVAILABLE"
                    if stage == "CONSENT"
                    else "SELECTION_REQUIRED",
                    "message": "Audit approval startup was interrupted. No new scan or fix was authorized.",
                },
            )
        raise


async def _offer_software_audit(ctx: Context, selected: Engine) -> dict[str, Any]:
    """Request a fresh post-remediation report before offering audit fixes."""
    if selected.state.workflow:
        blocked = workflow.require(selected, JOB_AUDIT)
        if blocked:
            return blocked
        previous = selected.state.software_audit
        if previous.get("status") not in {
            None,
            "REQUESTED",
            "CONSENT_REQUIRED",
            "CONSENT_UNAVAILABLE",
        }:
            return _compact_audit(previous)
        state = selected.state
        workflow.activity(
            selected,
            "Run a deep-dive software audit? Waiting for Yes or No.",
            status="WAITING_FOR_HUMAN",
        )
        try:
            if desktop_approval.available():
                return await _open_audit_approval(ctx, selected, "CONSENT")
            elif _form_supported(ctx):
                _record_audit_result(
                    selected,
                    {
                        "status": "REQUESTED",
                        "message": "Waiting for human audit consent. No scan has started.",
                    },
                )
                response = await ctx.elicit(
                    "Run the deep-dive software audit? No or Cancel skips to the final unresolved report.",
                    SoftwareAuditConsent,
                )
                answer = (
                    "generate_report"
                    if response.action == "accept"
                    and response.data is not None
                    and response.data.run_audit
                    else "done"
                )
            else:
                return _record_audit_result(
                    selected,
                    {
                        "status": "CONSENT_REQUIRED",
                        "message": "Ask the human whether to run the software audit. Call choose_software_audit_action(choice='generate_report' for Yes or 'done' for No). Do not choose for the human.",
                    },
                )
            if selected.state is not state:
                return {
                    "status": "ERROR",
                    "reason": "Audit consent belongs to a replaced run.",
                }
            result = await asyncio.to_thread(_software_audit_result, selected, answer)
            if answer == "done":
                return await _continue_workflow(ctx, selected, None, None)
            return result
        except asyncio.CancelledError:
            if selected.state is state:
                await asyncio.shield(
                    asyncio.to_thread(
                        _record_audit_result,
                        selected,
                        {
                            "status": "CONSENT_UNAVAILABLE",
                            "message": "The host interrupted audit consent. No scan was authorized or started; request consent again.",
                        },
                    )
                )
                workflow.activity(
                    selected,
                    "Audit consent was interrupted; no audit is running.",
                    status="INTERRUPTED",
                )
            raise
        except (OSError, RuntimeError, ValueError, MCPError) as exc:
            logger.warning("Audit consent unavailable: %s", exc, exc_info=True)
            return _record_audit_result(
                selected,
                {
                    "status": "CONSENT_UNAVAILABLE",
                    "reason": str(exc),
                    "message": "No audit started. Ask the human for audit consent before retrying.",
                },
            )
    pending = await asyncio.to_thread(selected.begin_software_audit)
    if not pending.pop("created"):
        return _compact_audit(pending)
    return await asyncio.to_thread(_software_audit_result, selected, "generate_report")


async def _offer_audit_choices(ctx: Context, selected: Engine) -> dict[str, Any]:
    """Offer only select-fixes or exit after the current report passed coverage checks."""
    state = selected.state
    try:
        choice = await _ask_software_audit_choice(ctx)
        if selected.state is not state:
            logger.warning("Ignoring a software-audit response from a previous run")
            return {
                "status": "CHOICE_UNAVAILABLE",
                "reason": "The software-audit choice belonged to a previous run. No action was authorized for the current run.",
            }
        if choice is not None:
            return await choose_software_audit_action(
                ctx, str(selected.repo_root), choice=choice
            )
        result = {
            "status": "CHOICE_REQUIRED",
            "choices": choice_labels(),
            "message": (
                "The report is complete. Ask select fixes or exit, then call "
                "choose_software_audit_action with that choice. Do not choose for the human."
            ),
        }
    except asyncio.CancelledError:
        if selected.state is state:
            await asyncio.shield(
                asyncio.to_thread(
                    _record_audit_result,
                    selected,
                    {
                        "status": "CHOICE_UNAVAILABLE",
                        "choices": choice_labels(),
                        "reason": "The host interrupted the software-audit choice. No audit action was authorized.",
                    },
                )
            )
        raise
    except (OSError, RuntimeError, ValueError, MCPError) as exc:
        logger.warning(
            "Software-audit choice was not collected: %s", exc, exc_info=True
        )
        result = {
            "status": "CHOICE_UNAVAILABLE",
            "choices": choice_labels(),
            "reason": str(exc),
            "message": (
                "No code was changed. Ask the human using these choices, then call "
                "choose_software_audit_action with the human's choice."
            ),
        }
    return await asyncio.to_thread(_record_audit_result, selected, result)


def _audit_revision(engine: Engine) -> str:
    """Return the current branch and commit, or an explicit unverified marker."""
    try:
        return f"{engine.git.current_branch()} {engine.git.head()}"
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        logger.warning(
            "Could not read the Git revision for the audit prompt: %s",
            exc,
            exc_info=True,
        )
        return "unverified"


def _audit_project_name(engine: Engine) -> str:
    """Return the file-safe GitLab project name for the active checkout."""
    return project_file_name(engine.state.gitlab_project_path, engine.repo_root.name)


def _compact_audit(audit: dict[str, Any]) -> dict[str, Any]:
    """Summarize saved audit state; resending its prompt and receipts multiplies AI tokens."""
    if audit.get("status") == "GENERATE_AUDIT_REPORT":
        # Its message tells the host to follow audit_prompt and coverage.files.
        return deepcopy(audit)
    compact = {
        key: deepcopy(value)
        for key, value in audit.items()
        if key not in {"audit_prompt", "coverage", "coverage_gaps"}
    }
    coverage = audit.get("coverage") or {}
    if coverage:
        compact["coverage_summary"] = {
            "reviewed_files": len(coverage.get("reviews", {})),
            "total_files": len(coverage.get("files", [])),
            "completed_phases": list(coverage.get("completed_phases", [])),
            "truncated": bool(coverage.get("truncated")),
        }
    gaps = audit.get("coverage_gaps") or {}
    if gaps:
        remaining = gaps.get("remaining_files") or []
        compact["coverage_gaps"] = {
            **deepcopy(gaps),
            "remaining_files": remaining[:20],
            "remaining_file_count": len(remaining),
            "remaining_files_truncated": len(remaining) > 20,
        }
    if coverage or "audit_prompt" in audit:
        compact["full_details"] = (
            "Omitted to save tokens. Only after context loss call "
            "get_run_status(repo_root=..., include_audit_details=True)."
        )
    return compact


def _software_audit_blocked(engine: Engine) -> dict[str, Any] | None:
    """Return a wait result while a human window or package batch is still open."""
    if engine.state.software_audit.get("status") == "AWAITING_HUMAN":
        return _compact_audit(engine.state.software_audit)
    selection = engine.state.fix_selection or {}
    if (selection.get("package_execution") or {}).get("status") in {
        "QUEUED",
        "RUNNING",
    }:
        return {
            "status": "REMEDIATION_RUNNING",
            "message": "Wait until the approved package batch finishes. Do not start the software audit yet.",
        }
    if (
        engine.state.workflow or selection.get("presentation") == "WINDOWS_DIALOG"
    ) and selection.get("status") in {"REQUESTED", "AWAITING_HUMAN"}:
        return {
            "status": "AWAITING_HUMAN",
            "message": "Wait for the open fix-selection window before choosing a software audit action.",
        }
    approval = engine.state.false_positive_approval_form or {}
    if approval.get("presentation") == "WINDOWS_DIALOG" and approval.get("status") in {
        "REQUESTED",
        "AWAITING_HUMAN",
    }:
        return {
            "status": "AWAITING_HUMAN",
            "message": "Wait for the open false-positive window before choosing a software audit action.",
        }
    return None


def _audit_review_handoff(result: dict[str, Any], coverage: dict) -> dict[str, Any]:
    """Return bounded continuation context without discarding recoverable evidence."""
    gaps = (
        result.get("coverage_gaps") if result["status"] == "AUDIT_INCOMPLETE" else None
    )
    remaining = (
        gaps["remaining_files"]
        if gaps is not None
        else [
            path
            for path in coverage.get("files", [])
            if path not in coverage.get("reviews", {})
        ]
    )
    response = {
        key: value
        for key, value in result.items()
        if key not in {"audit_prompt", "coverage", "coverage_gaps"}
    }
    if result["status"] == "GENERATE_AUDIT_REPORT":
        response.update(
            {key: result[key] for key in ("audit_prompt", "coverage") if key in result}
        )
    if gaps is not None:
        response["coverage_gaps"] = {
            **gaps,
            "remaining_files": remaining[:20],
            "remaining_file_count": len(remaining),
            "remaining_files_truncated": len(remaining) > 20,
        }
    return deepcopy(
        {
            **response,
            "continue_review": True,
            "generated_exclusions": coverage.get("generated_exclusions", []),
            "remaining_file_count": len(remaining),
            "next_files": remaining[:20],
            "remaining_phases": gaps["remaining_phases"]
            if gaps is not None
            else sorted(REVIEW_PHASES - set(coverage.get("completed_phases", [])))
            if coverage.get("files")
            else [],
            "context_recovery_tool": "get_run_status",
            "next_action": (
                "Continue the read-only audit now, including after delegated reviews finish. "
                "A progress receipt is not a completed job: do not end the turn with a "
                "partial findings summary or ask the developer to type continue. "
                "Persist actual findings incrementally to output_path, replacing the "
                "server's explicitly incomplete progress draft. "
                "Read the next unreviewed non-generated files and submit "
                "their real progress.files receipts. Finish every remaining file and "
                "phase, write output_path, then call choose_software_audit_action with "
                "the same repo_root and report_ready=True. That call opens the unchecked "
                "fix-selection GUI. Wait for its human selection before any code changes. "
                "Reuse audit_prompt and evidence already read. Only after context loss, "
                "call get_run_status with the same repo_root and include_audit_details=True "
                "to recover software_audit's full prompt, inventory, receipts and coverage gaps."
            ),
        }
    )


def _show_audit_prompt(engine: Engine, prompt: str) -> None:
    """Show the exact prompt to the developer; console and log never enter AI context."""
    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    header = (
        f"===== Software audit prompt for {engine.repo_root} "
        f"({len(prompt)} characters, sha256 {digest}) ====="
    )
    text = f"{header}\n{prompt}\n===== End of software audit prompt ====="
    logger.info("%s", text)
    console = _console_for_progress()
    if console is not None:
        console.write(text)


def _software_audit_result(
    engine: Engine, choice: str, *, select_after_report: bool = False
) -> dict[str, Any]:
    """Prepare the automatic read-only audit or retain the human's exit choice."""
    when = datetime.now(UTC)
    project_name = _audit_project_name(engine)
    if choice == "generate_report" or select_after_report:
        destination = audit_report_path(project_name, when, engine.repo_root)
        coverage = audit_inventory(engine.repo_root)
        result = {
            "status": "GENERATE_AUDIT_REPORT",
            "choice": choice,
            "select_after_report": select_after_report,
            "repo_root": str(engine.repo_root),
            "output_path": str(destination),
            "audit_prompt": render_audit_prompt(when, _audit_revision(engine)),
            "coverage": coverage,
            "requested_at": datetime.now(UTC).isoformat(),
            "message": (
                "Write the software audit markdown to output_path and nowhere else. "
                "Follow audit_prompt exactly, including its selectable-findings section. "
                "Resolve source links from the directory containing output_path to files "
                "under repo_root, with #L<line> fragments for VS Code and Cursor. "
                "One checkbox is shown later for each of those lines. "
                "Do not change application code, tests, dependencies, CI, or GitLab. "
                "Do not commit or push. "
                "The host AI must scan repo_root now; this server does not run an AI scan. "
                "The home-directory progress draft already exists. Replace it with "
                "actual report content incrementally, not only after the final file. "
                "Do not ask the developer to type continue for this approved audit. "
                "After each small batch call choose_software_audit_action with the same "
                "repo_root and per-file progress receipts. Counts describe reviewed files, "
                "not successful fixes. Inventory paths are in coverage.files. "
                "Submit progress.files=[{path,sha256,assessment}] for every file and "
                "progress.completed_phases for all five review phases. Partial scans "
                "cannot be accepted as complete. Never inflate the finding count. "
                "After saving the exact output_path, call "
                "choose_software_audit_action(repo_root=..., report_ready=True). "
                "Do not end the workflow before that call; it opens unchecked findings "
                "only after coverage passes. Report selected fix outcomes with complete_security_run to finish the final unresolved report."
            ),
        }
        _show_audit_prompt(engine, result["audit_prompt"])
    else:
        result = {
            "status": "DONE",
            "choice": "done",
            "message": "No further action. Do not change code, commit, or push.",
        }
    return _record_audit_result(engine, result)


def _audit_fix_from_report(
    report: Path,
    selected_ids: list[str] | None,
    expected_report_hash: str | None = None,
) -> dict[str, Any]:
    """Return the human-checked audit items, or ask for that selection first."""
    try:
        text = report.read_text(encoding="utf-8")
        if audit_report_is_draft(text):
            return {
                "status": "ITEMS_REQUIRED",
                "choice": "fix_from_report",
                "report_path": str(report),
                "message": "Replace the incomplete progress draft with the complete audit findings report before report_ready. No fixes are authorized by a draft.",
            }
        report_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if expected_report_hash is not None and report_hash != expected_report_hash:
            return {
                "status": "ERROR",
                "reason": "The audit report changed while the selection window was open. No fixes were authorized; review the new report first.",
            }
        items = audit_items(text)
    except (OSError, UnicodeError) as exc:
        return {
            "status": "ERROR",
            "choice": "fix_from_report",
            "reason": f"The software audit report could not be read: {exc}",
        }
    if not items and audit_has_no_findings(text):
        return {
            "status": "NO_FINDINGS",
            "choice": "fix_from_report",
            "report_path": str(report),
            "selected_items": [],
            "message": "The report explicitly lists no selectable findings. No fixes were authorized.",
        }
    if not items:
        return {
            "status": "ITEMS_REQUIRED",
            "choice": "fix_from_report",
            "report_path": str(report),
            "message": (
                "The report has no selectable-findings lines. Regenerate it with one "
                "`- ID | severity | location | problem` line per finding. "
                "Do not invent items and do not change code."
            ),
        }
    if selected_ids is None:
        return {
            "status": "SELECTION_REQUIRED",
            "choice": "fix_from_report",
            "report_path": str(report),
            "items": items,
            "report_hash": report_hash,
            "message": (
                "Show one unchecked checkbox per item. Call choose_software_audit_action "
                "again with choice fix_from_report and selected_ids set to the checked ids only. "
                "An empty selection fixes nothing. Do not choose for the human."
            ),
        }
    known = {item["id"] for item in items}
    unknown = [item_id for item_id in selected_ids if item_id not in known]
    if unknown:
        return {
            "status": "ERROR",
            "choice": "fix_from_report",
            "reason": "selected_ids includes an id that is not in the audit report: "
            + ", ".join(unknown),
        }
    selected = [item for item in items if item["id"] in set(selected_ids)]
    if not selected:
        return {
            "status": "NONE_SELECTED",
            "choice": "fix_from_report",
            "report_path": str(report),
            "selected_items": [],
            "message": "No audit items were checked. Do not change code, commit, or push.",
        }
    return {
        "status": "FIX_FROM_AUDIT_REPORT",
        "choice": "fix_from_report",
        "report_path": str(report),
        "selected_items": selected,
        "message": (
            "Fix only selected_items. Leave every unchecked audit item unchanged. "
            "Investigate each selected item before editing. Apply a change only for a "
            "reproduced root cause, with an Arrange-Act-Assert test that fails before "
            "the change and passes after it. Follow the repo's declared language "
            "version and its current official docs. Do not retarget Java, .NET, "
            "TypeScript, or JavaScript. The change adds no compiler errors and no "
            "new warnings. On every changed code, Dockerfile, nginx.conf, or "
            "build/script line, add a comment in that file's normal syntax that "
            "states what the change corrects and why. Leave the code unchanged "
            "when the reproduction, the test, or that comment is missing, or when "
            "the change would make the code less correct or less stable. Never "
            "guess or invent a cause, a line, or a test result. "
            "When investigation shows the reported defect is absent, leave the code "
            "unchanged and record the item as a false positive with the evidence. "
            "Unknown reachability is not a false positive. After the selected work, "
            "show unchecked boxes for those false positives. Record each box the "
            "human checks in that item's failed result. Do not call "
            "submit_false_positive_approvals from this job; it is accepted only "
            "in job 4, and only for the same downloaded GitLab vulnerability. "
            "Report each "
            "unfixed false positive as failed, with the evidence in reason and the "
            "investigation in validation. Before editing, read the current public "
            "guidance for this repository's languages and frameworks. "
            "Do not commit, push, or open a merge request. "
            "The human reviews the diff and decides whether it is committed."
        ),
    }


def _software_audit_fix(
    engine: Engine,
    selected_ids: list[str] | None,
    *,
    expected_report_hash: str | None = None,
) -> dict[str, Any]:
    """Resolve a fix choice to checked report items. This writes no repository file."""
    pending = engine.state.software_audit
    destination = pending.get("output_path")
    existing = Path(destination) if destination else None
    if existing is None:
        return _software_audit_result(
            engine, "fix_from_report", select_after_report=True
        )
    if not pending.get("report_complete"):
        return _compact_audit(pending)
    result = _audit_fix_from_report(existing, selected_ids, expected_report_hash)
    if destination:
        result.update(
            output_path=destination,
            select_after_report=pending.get("select_after_report", False),
        )
    return _record_audit_result(engine, result)


def _record_audit_result(engine: Engine, result: dict[str, Any]) -> dict[str, Any]:
    """Store the closing choice and return the same result."""
    previous = engine.state.software_audit
    details = dict(result)
    if result["status"] != "GENERATE_AUDIT_REPORT" and previous.get("output_path"):
        details = {
            **{
                key: previous[key]
                for key in (
                    "repo_root",
                    "audit_prompt",
                    "output_path",
                    "coverage",
                    "report_complete",
                    "items",
                    "requested_at",
                )
                if key in previous
            },
            **details,
        }
    if details.get("output_path") and result["status"] in {
        "GENERATE_AUDIT_REPORT",
        "AUDIT_IN_PROGRESS",
        "AUDIT_INCOMPLETE",
    }:
        persist_audit_draft(
            Path(details["output_path"]),
            engine.repo_root,
            details.get("coverage") or {},
            details.get("progress"),
        )
    engine.record_software_audit(
        {
            **details,
            "choice": result.get("choice"),
            "status": result["status"],
            "report_path": details.get("report_path") or details.get("output_path"),
        }
    )
    progress = result.get("progress") or {}
    status = result["status"]
    _editor_progress(
        engine.repo_root,
        "software-audit",
        "Software audit",
        progress.get("message") or result.get("message") or status,
        status="WAITING_FOR_AI"
        if status
        in {
            "GENERATE_AUDIT_REPORT",
            "AUDIT_IN_PROGRESS",
            "AUDIT_INCOMPLETE",
            "FIX_FROM_AUDIT_REPORT",
        }
        else "WAITING_FOR_HUMAN"
        if status
        in {
            "AUDIT_REPORT_GENERATED",
            "CHOICE_REQUIRED",
            "CHOICE_UNAVAILABLE",
            "SELECTION_REQUIRED",
        }
        else status,
        completed=progress.get("reviewed_files"),
        total=progress.get("total_files"),
    )
    with _progress_console_lock:
        if result["status"] in _AUDIT_PENDING:
            if _progress_console_enabled:
                _audit_progress_roots.add(engine.repo_root)
        else:
            _audit_progress_roots.discard(engine.repo_root)
    if result["status"] in {
        "GENERATE_AUDIT_REPORT",
        "SELECTION_REQUIRED",
        "ITEMS_REQUIRED",
    }:
        sink = progress_sink.get()
        if sink is not None:
            sink(
                f"WAITING_FOR_AI | Software audit: {result['status']} | {result.get('message', '')}"
            )
    if not _publish_audit_activity(engine) and status in {
        "ERROR",
        "CONSENT_UNAVAILABLE",
    }:
        workflow.activity(
            engine,
            result.get("reason") or result.get("message") or status,
            status="INTERRUPTED" if status == "CONSENT_UNAVAILABLE" else "FAILED",
        )
    return result


async def _ask_software_audit_choice(ctx: Context) -> str | None:
    """Ask the human for one closing action. Cancel means stop."""
    sink = progress_sink.get()
    if sink is not None:
        sink("WAITING_FOR_HUMAN | Choose the software audit action.")
    if desktop_approval.available():
        selected = await asyncio.to_thread(
            desktop_approval.ask_choice,
            "Software audit",
            "The audit report is complete. Select findings to fix, or exit and keep the report.",
            choice_labels(),
        )
        choice = normalize_choice(selected)
        if choice is None:
            raise ValueError(
                _RAISE_THE_SOFTWARE_AUDIT_WINDOW_RETURNED_AN_UNKNOWN_CHOICE.format(
                    selected
                )
            )
        return choice
    if not _form_supported(ctx):
        return None
    response = await ctx.elicit(
        "The audit report is complete. Select findings to fix, or exit. "
        "Cancel stops without code changes. Nothing is committed or pushed.",
        SoftwareAuditChoice,
    )
    if response.action != "accept" or response.data is None:
        return "done"
    return normalize_choice(response.data.action)


async def _ask_audit_items(
    ctx: Context, items: list[dict[str, str]]
) -> list[str] | None:
    """Show one unchecked box per audit item. None means the host must show them."""
    sink = progress_sink.get()
    if sink is not None:
        sink(
            f"WAITING_FOR_HUMAN | Software audit findings: {len(items)} unchecked items; no fixes authorized yet."
        )
    schema = _checkbox_model(
        "SoftwareAuditFixes",
        items,
        lambda item: (
            f"{item['id']}: {item['problem']}",
            f"{item['severity']} at {item['location']}",
        ),
    )
    if desktop_approval.available():
        properties = schema.model_json_schema()["properties"]
        for index, item in enumerate(items):
            properties[f"finding_{index}"]["summary"] = (
                f"{item['severity']} at {item['location']}"
            )
        response = await asyncio.to_thread(
            desktop_approval.ask_checkboxes,
            "Check only the audit items to fix. Every box starts unchecked. "
            "Fix checked items changes only those items. Cancel fixes nothing.",
            properties,
            title="Software audit fixes",
            detail_header="Finding",
            submit_label="Fix checked items",
        )
        if response.get("action") != "accept":
            return []
        return [item["id"] for item in _checked(items, response.get("content") or {})]
    if not _form_supported(ctx):
        return None
    response = await ctx.elicit(
        "Check only the audit items to fix. Every box starts unchecked. "
        "Submit fixes only the checked items. Cancel fixes nothing.",
        schema,
    )
    if response.action != "accept" or response.data is None:
        return []
    return [item["id"] for item in _checked(items, response.data.model_dump())]


async def _wait_for_audit_handoff(selected: Engine) -> None:
    """Keep an active host request attached until owned native work hands back control."""
    state = selected.state
    while True:
        tasks = {
            task
            for task in (
                _desktop_fix_selection_tasks.get(state.fix_selection.get("request_id")),
                _desktop_approval_tasks.get(
                    state.false_positive_approval_form.get("request_id")
                ),
                _desktop_audit_tasks.get(state.software_audit.get("request_id")),
            )
            if task is not None
            and task is not asyncio.current_task()
            and not task.done()
        }
        if not tasks:
            return
        done, _ = await asyncio.wait(tasks, timeout=_BACKGROUND_HEARTBEAT_SECONDS)
        for task in done:
            task.result()
        if selected.state is not state:
            raise RuntimeError(_RAISE_THE_AUDIT_HANDOFF_BELONGED_TO_A_REPLACED_RUN)
        if not done:
            sink = progress_sink.get()
            if sink is not None:
                sink(
                    "Waiting for owned background work/human approval; the host AI will receive the audit handoff when it finishes."
                )
        # Done callbacks normally release these entries on the next loop iteration.
        await asyncio.sleep(0)


def _selected_source_ids(selection: dict) -> list[str]:
    """Separate human-approved host code work from server-owned package/config edits."""
    identities = selection.get("approved_findings") or {}
    return [
        item
        for item in selection.get("selected_ids", [])
        if item in identities
        and not any(
            key in identities[item] for key in ("package_update", "config_edit")
        )
    ]


def _workflow_source_ids(selection: dict) -> list[str]:
    """Include configuration code fixes in job five, never package updates."""
    identities = selection.get("approved_findings") or {}
    return [
        item
        for item in selection.get("selected_ids", [])
        if item in identities and "package_update" not in identities[item]
    ]


def _selected_source_handoff(selected: Engine) -> dict[str, Any] | None:
    """Do not lose human-selected source fixes when a mixed package batch ends."""
    selection = selected.state.fix_selection
    ids = (
        _workflow_source_ids(selection)
        if selected.state.workflow
        else _selected_source_ids(selection)
    )
    ids = [
        item
        for item in ids
        if f"gitlab:{item}" not in selected.state.workflow.get("code_results", {})
    ]
    if not ids or selection.get("status") != "APPROVED":
        return None
    result = {
        "status": "SOURCE_FIXES_REQUIRED",
        "selected_ids": ids,
        "findings": [
            deepcopy(item) for item in selected.state.findings if item["id"] in ids
        ],
        "message": "Implement only these human-selected GitLab source fixes. Leave unchecked issues unchanged. Report the current finding with complete_security_run(progress={id,message}). Validate, then call complete_security_run(code_results=[{id,status:fixed|failed,reason,validation}]) for every selected host fix. This offers audit consent, not an automatic scan. Do not commit or push.",
    }
    _editor_progress(
        selected.repo_root,
        "gitlab-source-fixes",
        "Selected GitLab source fixes",
        result["message"],
        status="WAITING_FOR_AI",
    )
    return result


@mcp.tool(
    annotations=ToolAnnotations(
        title="Continue jobs or choose software audit action",
        read_only_hint=False,
        open_world_hint=False,
    )
)
@_with_audit_activity
async def choose_software_audit_action(
    ctx: Context,
    repo_root: str | None = None,
    choice: str | None = None,
    selected_ids: list[str] | None = None,
    report_ready: bool = False,
    progress: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Await the next job; obtain audit consent, then coverage-check report_ready before unchecked audit fixes."""
    selected = await asyncio.to_thread(_engine_for, repo_root)
    if (
        choice is None
        and selected_ids is None
        and not report_ready
        and progress is None
    ):
        await _wait_for_audit_handoff(selected)
    blocked = _software_audit_blocked(selected)
    if blocked is not None:
        return blocked
    if selected.state.workflow:
        job = selected.state.workflow["current"]
        if job != JOB_AUDIT:
            if (
                choice is not None
                or selected_ids is not None
                or report_ready
                or progress is not None
            ):
                return workflow.require(selected, JOB_AUDIT) or {"status": "ERROR"}
            result = await complete_security_run(ctx, str(selected.repo_root))
            return result.structured_content
    previous = selected.state.software_audit
    if (
        choice is None
        and selected_ids is None
        and not report_ready
        and progress is None
        and previous.get("status") in {"FIX_FROM_AUDIT_REPORT", "ERROR"}
    ):
        return _compact_audit(previous)
    if (
        selected.state.workflow
        and normalize_choice(choice) == "fix_from_report"
        and not previous.get("report_complete")
    ):
        return {
            "status": "AUDIT_REPORT_REQUIRED",
            "message": "Obtain human audit consent, generate the complete report, then select findings. A fix choice cannot authorize a scan.",
        }
    if progress is not None:
        try:
            details = SoftwareAuditProgress.model_validate(progress)
        except ValueError as exc:
            return {"status": "ERROR", "reason": f"Invalid audit progress: {exc}"}
        reviewed_files, total_files = details.reviewed_files, details.total_files
        if (
            report_ready
            or choice is not None
            or selected_ids is not None
            or not previous.get("output_path")
            or previous.get("status")
            not in {"GENERATE_AUDIT_REPORT", "AUDIT_IN_PROGRESS", "AUDIT_INCOMPLETE"}
            or not details.message.strip()
            or (reviewed_files is None) != (total_files is None)
            or (
                reviewed_files is not None
                and total_files is not None
                and total_files < reviewed_files
            )
        ):
            return {
                "status": "ERROR",
                "reason": "Audit progress requires an active scan, a message, and valid paired file counts; do not combine it with a choice or report_ready.",
            }
        try:
            coverage = await asyncio.to_thread(
                record_audit_coverage,
                selected.repo_root,
                previous.get("coverage") or audit_inventory(selected.repo_root),
                [item.model_dump() for item in details.files],
                details.completed_phases,
                generated_exclusions=[
                    item.model_dump() for item in details.generated_exclusions
                ],
            )
        except (OSError, ValueError) as exc:
            return {"status": "ERROR", "reason": str(exc)}
        if coverage["files"]:
            reviewed_files, total_files = (
                len(coverage["reviews"]),
                len(coverage["files"]),
            )
        progress = {
            "message": " ".join(details.message.split())[:500],
            "reviewed_files": reviewed_files,
            "total_files": total_files,
            "updated_at": datetime.now(UTC).isoformat(),
        }
        result = await asyncio.to_thread(
            _record_audit_result,
            selected,
            {
                **previous,
                "status": "AUDIT_IN_PROGRESS",
                "progress": progress,
                "coverage": coverage,
            },
        )
        _publish_audit_progress(result)
        return _audit_review_handoff(
            {key: result[key] for key in ("status", "output_path", "progress")},
            coverage,
        )
    if report_ready:
        if (
            choice is not None
            or selected_ids is not None
            or not previous.get("output_path")
            or previous.get("status")
            not in {
                "GENERATE_AUDIT_REPORT",
                "AUDIT_IN_PROGRESS",
                "ITEMS_REQUIRED",
                "ERROR",
                "AUDIT_INCOMPLETE",
            }
        ):
            return {
                "status": "ERROR",
                "reason": "report_ready requires a pending generated report; it cannot authorize selected_ids or another choice.",
            }
        report = Path(previous["output_path"])
        if not await asyncio.to_thread(report.is_file):
            return {
                "status": "ERROR",
                "reason": f"Write the requested report before report_ready: {report}",
            }
        coverage = previous.get("coverage") or await asyncio.to_thread(
            audit_inventory, selected.repo_root
        )
        gaps = await asyncio.to_thread(
            audit_coverage_gaps, selected.repo_root, coverage
        )
        if gaps["remaining_files"] or gaps["remaining_phases"] or gaps["truncated"]:
            incomplete = await asyncio.to_thread(
                _record_audit_result,
                selected,
                {
                    "status": "AUDIT_INCOMPLETE",
                    "choice": "generate_report",
                    "coverage_gaps": gaps,
                    "message": "Continue the read-only audit: review every remaining file and phase, refresh changed-file receipts, and update the report before report_ready. Do not add speculative findings to fill a quota.",
                },
            )
            return _audit_review_handoff(incomplete, coverage)
        result = await asyncio.to_thread(_audit_fix_from_report, report, None)
        if result["status"] in {"ERROR", "ITEMS_REQUIRED"}:
            return await asyncio.to_thread(_record_audit_result, selected, result)
        await asyncio.to_thread(
            _record_audit_result,
            selected,
            {
                "status": "AUDIT_REPORT_GENERATED",
                "choice": None,
                "report_path": str(report),
                "report_complete": True,
            },
        )
        if selected.state.workflow:
            return await choose_software_audit_action(
                ctx, str(selected.repo_root), choice="fix_from_report"
            )
        return await _offer_audit_choices(ctx, selected)
    elif previous.get("status") in {
        "GENERATE_AUDIT_REPORT",
        "AUDIT_IN_PROGRESS",
        "AUDIT_INCOMPLETE",
    } and (choice is None or normalize_choice(choice) == previous.get("choice")):
        return _audit_review_handoff(previous, previous.get("coverage") or {})
    selected_choice = normalize_choice(choice)
    if choice is None:
        previous = selected.state.software_audit
        if selected.state.workflow and not previous:
            return await _offer_software_audit(ctx, selected)
        if previous and previous.get("choice") != "fix_from_report":
            return _compact_audit(previous)
        if not previous:
            source_work = _selected_source_handoff(selected)
            if source_work is not None:
                return source_work
            return await _offer_software_audit(ctx, selected)
        selected_choice = "fix_from_report"
    if choice is not None and selected_choice is None:
        return {
            "status": "ERROR",
            "reason": "choice must be generate_report, fix_from_report, or done.",
        }
    if selected_choice != "fix_from_report" or selected_ids is not None:
        if selected_choice == "fix_from_report":
            result = await asyncio.to_thread(
                _software_audit_fix, selected, selected_ids
            )
            return await _finish_empty_audit(ctx, selected, result)
        result = await asyncio.to_thread(
            _software_audit_result, selected, selected_choice
        )
        if selected.state.workflow and result["status"] == "DONE":
            completed = await complete_security_run(ctx, str(selected.repo_root))
            return completed.structured_content
        return result
    prepared = await asyncio.to_thread(_software_audit_fix, selected, None)
    if prepared["status"] != "SELECTION_REQUIRED":
        return await _finish_empty_audit(ctx, selected, prepared)
    if selected.state.workflow and desktop_approval.available():
        return await _open_audit_approval(ctx, selected, "FIX_SELECTION", prepared)
    audit_state = selected.state
    try:
        checked = await _ask_audit_items(ctx, prepared["items"])
    except (OSError, RuntimeError, ValueError, MCPError) as exc:
        logger.warning(
            "Audit-item checkboxes were not collected: %s", exc, exc_info=True
        )
        return prepared
    if checked is None:
        return prepared
    if (
        selected.state is not audit_state
        or selected.state.software_audit.get("output_path") != prepared["report_path"]
    ):
        return {
            "status": "ERROR",
            "reason": "The audit selection belongs to a replaced run. No fixes were authorized.",
        }
    result = await asyncio.to_thread(
        _software_audit_fix,
        selected,
        checked,
        expected_report_hash=prepared["report_hash"],
    )
    return await _finish_empty_audit(ctx, selected, result)


async def _finish_empty_audit(ctx: Context, selected: Engine, result: dict) -> dict:
    """Skipping audit fixes still produces the final unresolved report."""
    if selected.state.workflow and result["status"] in {"NONE_SELECTED", "NO_FINDINGS"}:
        completed = await complete_security_run(ctx, str(selected.repo_root))
        return completed.structured_content
    return result


def _publish_audit_progress(result: dict[str, Any]) -> None:
    """Label actual reviewed-file counts separately from the unfinished audit."""
    progress = result.get("progress") or {}
    completed, total = progress.get("reviewed_files"), progress.get("total_files")
    counts = (
        f"{completed}/{total} planned files reviewed"
        if total is not None
        else "file total unknown"
    )
    text = f"Software audit | {counts} | {progress.get('message') or result['status']} | report/selection still pending"
    logger.info("%s", text)
    sink = progress_sink.get()
    if sink is not None:
        sink(text)


def _live_run_status(
    selected: Engine, *, include_audit_details: bool = False
) -> dict[str, Any]:
    """Return live activity without waiting behind long engine mutations."""
    audit = (
        deepcopy(selected.state.software_audit)
        if include_audit_details
        else _compact_audit(selected.state.software_audit)
    )
    background = _background_for(selected)
    if any(
        item["status"] in {"RUNNING", "WAITING_FOR_HUMAN", "WAITING_FOR_AI"}
        for item in background
    ):
        state = selected.state
        execution = state.fix_selection.get("package_execution") or {}
        return {
            "status": "BACKGROUND_ACTIVE",
            "server_version": __version__,
            "repo_root": str(selected.repo_root),
            "background_tasks": background,
            "software_audit": audit,
            "workflow": deepcopy(state.workflow),
            "package_execution": {
                "status": execution.get("status"),
                "results": list(execution.get("results") or []),
            },
            "message": "Live activity snapshot; the engine is still working or waiting. Completed steps are not a successful-validation claim.",
        }
    return {
        **selected.get_run_status(),
        "software_audit": audit,
        "background_tasks": background,
    }


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get run status", read_only_hint=True, open_world_hint=False
    )
)
def get_run_status(
    repo_root: str | None = None, include_audit_details: bool = False
) -> dict[str, Any]:
    """Return phase, branch and counts; audit prompt/receipts only on explicit recovery."""
    return _run(
        "get_run_status",
        repo_root=repo_root,
        include_audit_details=include_audit_details,
    )


_PROGRESS_INSTALL_THREAD = "progress-extension-install"


def main() -> None:
    """Serve MCP tools over stdio until the client disconnects."""
    global _progress_console
    _install_host_logging()
    logger.info("gitlab-security-mcp %s serving stdio", __version__)
    # A second window must speak MCP while another window still holds the install lock.
    threading.Thread(
        target=install_progress_extension,
        name=_PROGRESS_INSTALL_THREAD,
        daemon=True,
    ).start()
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
