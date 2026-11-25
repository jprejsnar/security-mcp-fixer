"""Ordered, inspection-only receipts for the seven human-controlled jobs."""

from __future__ import annotations

import logging
from copy import deepcopy
from typing import TYPE_CHECKING

from gitlab_security_mcp.progress import publish

if TYPE_CHECKING:
    from gitlab_security_mcp.engine import Engine

logger = logging.getLogger("gitlab_security_mcp")
_LOG_OUT_OF_ORDER_WORKFLOW_CALL_CURRENT_JOB = (
    "Out-of-order workflow call: current job %s, expected %s"
)
_LOG_COULD_NOT_PUBLISH_WORKFLOW_PROGRESS = "Could not publish workflow progress"

JOB_LABELS = (
    "Pre-checks",
    "Download GitLab security findings",
    "Select and apply package updates",
    "Review and upload false positives",
    "Select and fix GitLab source findings",
    "Optional deep-dive software audit and selected fixes",
    "Display unresolved remediation report",
)
(
    JOB_PRECHECKS,
    JOB_DOWNLOAD,
    JOB_PACKAGES,
    JOB_FALSE_POSITIVES,
    JOB_SOURCE,
    JOB_AUDIT,
    JOB_REPORT,
) = range(1, len(JOB_LABELS) + 1)
JOB_COUNT = len(JOB_LABELS)
# Job 1 finishes only when the branch exists, so its unfinished steps name their own tool.
_PRECHECK_NEXT_TOOL = {
    "PRECHECK_PASSED": "pull_main_twice",
    "PULLS_SUCCEEDED": "create_security_branch",
}
_DEFAULT_NEXT_TOOL = "complete_security_run"
_JOB_ORDER_MESSAGE = (
    "Finish the current job before starting another. Call {} to continue."
)


def start(engine: Engine) -> None:
    """Create one sequential run; disk receipts are never loaded as permission."""
    with engine._lock:
        engine.state.workflow = {
            "current": 1,
            "jobs": [
                {
                    "number": index,
                    "label": label,
                    "status": "RUNNING" if index == 1 else "PENDING",
                }
                for index, label in enumerate(JOB_LABELS, 1)
            ],
            "code_results": {},
        }
        engine._remember()
        activity(engine, "Checking checkout, branch and prerequisites.")


def activity(engine: Engine, message: str, *, status: str = "RUNNING") -> None:
    """Expose the current job and actual completed-job count, not a time estimate."""
    workflow = engine.state.workflow
    if not workflow:
        return
    number = workflow["current"]
    if workflow.get("final_report") and workflow["jobs"][-1]["status"] == "FINISHED":
        status = "FINISHED"
        message = workflow["final_result"]["message"]
    finished = sum(
        job["status"] in {"FINISHED", "SKIPPED", "FAILED"} for job in workflow["jobs"]
    )
    try:
        publish(
            engine.repo_root,
            "workflow",
            f"Job {number}/{JOB_COUNT}: {JOB_LABELS[number - 1]}",
            message,
            status=status,
            completed=finished,
            total=JOB_COUNT,
            unit="jobs finished",
            jobs=deepcopy(workflow["jobs"]),
            final_report=workflow.get("final_report", False),
        )
    except (OSError, ValueError):
        logger.warning(_LOG_COULD_NOT_PUBLISH_WORKFLOW_PROGRESS, exc_info=True)


def advance(engine: Engine, *, status: str = "FINISHED", message: str = "") -> None:
    """Finish exactly one job and activate its immediate successor."""
    with engine._lock:
        workflow = engine.state.workflow
        job = workflow["jobs"][workflow["current"] - 1]
        job.update(status=status, message=message)
        if workflow["current"] < JOB_COUNT:
            workflow["current"] += 1
            workflow["jobs"][workflow["current"] - 1]["status"] = "RUNNING"
        engine._remember()
        activity(engine, message or "Starting next job.")


def require(engine: Engine, *numbers: int) -> dict | None:
    """Reject out-of-order work without creating edit or dismissal permission."""
    workflow = engine.state.workflow
    if not workflow or workflow["current"] in numbers:
        return None
    current = workflow["current"]
    logger.warning(_LOG_OUT_OF_ORDER_WORKFLOW_CALL_CURRENT_JOB, current, numbers)
    next_tool = (
        _PRECHECK_NEXT_TOOL.get(engine.state.status, _DEFAULT_NEXT_TOOL)
        if current == JOB_PRECHECKS
        else _DEFAULT_NEXT_TOOL
    )
    return {
        "status": "JOB_ORDER_REQUIRED",
        "current_job": current,
        "job": JOB_LABELS[current - 1],
        "message": _JOB_ORDER_MESSAGE.format(next_tool),
        "next_tool": next_tool,
    }
