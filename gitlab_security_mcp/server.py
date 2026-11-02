"""MCP tools for the local GitLab security remediation workflow."""

from __future__ import annotations

import atexit
import logging
from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from gitlab_security_mcp import __version__
from gitlab_security_mcp.engine import Engine

logger = logging.getLogger("gitlab_security_mcp")

INSTRUCTIONS = """
Local-only GitLab security remediation. Call the tools in this order:
1. run_prechecks
2. pull_main_twice
3. create_security_branch
4. list_security_findings
5. verify_security_finding for every finding
6. apply_minimal_fix only when that finding is eligible
7. generate_aaa_test when a fix changes runtime behavior
8. run_validation_matrix
9. generate_local_report
Do not commit, push, open a merge request, or dismiss GitLab findings.
This server refuses those actions. Findings that cannot be resolved from
OSV, the GitHub Advisory Database, or NVD are skipped and listed for the user.
Unknown reachability is not a false positive.
"""

mcp = MCPServer(
    "gitlab-security-mcp",
    instructions=INSTRUCTIONS,
    version=__version__,
)
engine = Engine.from_env()
atexit.register(engine.close)


def _run(tool_name: str, func, *args, **kwargs) -> dict[str, Any]:
    try:
        return func(*args, **kwargs)
    except Exception as exc:  # surfaced to the client as a tool result, not a crashed server
        logger.exception("%s failed", tool_name)
        return {"status": "ERROR", "error": str(exc)}


@mcp.tool(annotations=ToolAnnotations(title="Run prechecks", read_only_hint=True, open_world_hint=False))
def run_prechecks() -> dict[str, Any]:
    """Phase 0. Fail closed unless the repo is on main, clean, and not mid-merge."""
    return _run("run_prechecks", engine.run_prechecks)


@mcp.tool(annotations=ToolAnnotations(title="Pull main twice", read_only_hint=False, destructive_hint=False, open_world_hint=True))
def pull_main_twice() -> dict[str, Any]:
    """Phase 1. Fast-forward main twice. Any failure stops the run."""
    return _run("pull_main_twice", engine.pull_main_twice)


@mcp.tool(annotations=ToolAnnotations(title="Create security branch", read_only_hint=False, destructive_hint=False, open_world_hint=False))
def create_security_branch() -> dict[str, Any]:
    """Phase 2. Create security-fixes-Month-dd-YYYY. Stop if that name already exists."""
    return _run("create_security_branch", engine.create_security_branch)


@mcp.tool(annotations=ToolAnnotations(title="List security findings", read_only_hint=True, open_world_hint=True))
def list_security_findings(project_id: str | None = None) -> dict[str, Any]:
    """Phase 3. Read GitLab findings from the latest successful default-branch pipeline."""
    return _run("list_security_findings", engine.list_security_findings, project_id)


@mcp.tool(annotations=ToolAnnotations(title="Verify security finding", read_only_hint=True, open_world_hint=True))
def verify_security_finding(finding_id: str) -> dict[str, Any]:
    """Phase 4. Verify one finding with local evidence and online advisories before any edit."""
    return _run("verify_security_finding", engine.verify_security_finding, finding_id)


@mcp.tool(annotations=ToolAnnotations(title="Apply minimal fix", read_only_hint=False, destructive_hint=False, open_world_hint=True))
def apply_minimal_fix(finding_id: str) -> dict[str, Any]:
    """Phase 5. Apply the smallest eligible fix. Skip findings that need user input."""
    return _run("apply_minimal_fix", engine.apply_minimal_fix, finding_id)


@mcp.tool(annotations=ToolAnnotations(title="Generate AAA test", read_only_hint=False, destructive_hint=False, open_world_hint=False))
def generate_aaa_test(finding_id: str) -> dict[str, Any]:
    """Phase 5. Add an Arrange-Act-Assert test when the fix changes runtime behavior."""
    return _run("generate_aaa_test", engine.generate_aaa_test, finding_id)


@mcp.tool(annotations=ToolAnnotations(title="Run validation matrix", read_only_hint=False, destructive_hint=False, open_world_hint=True))
def run_validation_matrix() -> dict[str, Any]:
    """Phase 6. Run Node, .NET, Java 17, NGINX, and container checks that apply to this repo."""
    return _run("run_validation_matrix", engine.run_validation_matrix)


@mcp.tool(annotations=ToolAnnotations(title="Generate local report", read_only_hint=False, destructive_hint=False, open_world_hint=False))
def generate_local_report() -> dict[str, Any]:
    """Phase 7. Write the human and JSON report, including false positives and skipped findings."""
    return _run("generate_local_report", engine.generate_local_report)


@mcp.tool(annotations=ToolAnnotations(title="Get run status", read_only_hint=True, open_world_hint=False))
def get_run_status() -> dict[str, Any]:
    """Return the current phase, branch, and counts for this run."""
    return _run("get_run_status", engine.get_run_status)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
