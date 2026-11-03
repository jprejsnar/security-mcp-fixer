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
6. For Node/npm, NuGet/.NET, and Maven/Gradle/Java candidates, fully read the
    exact target package's official docs, release notes, API/migration guides,
    runtime/peer requirements, framework support tables, and license terms.
    Inspect the actual product runtime/framework versions, including Angular,
    Crystal, Quarkus platform/BOM alignment, and .NET target frameworks.
    Same-major upgrades are not proof of compatibility. Never upgrade a
    framework/BOM/runtime, weaken tests, or force incompatible peer resolution
    just to make a security package install. Unsupported/uncertain candidates
    require manual review, not a guessed compatibility claim.
7. qualify_package_update with the exact version-bound documentation review.
    Corporate approvers must provision PACKAGE_UPDATE_POLICY independently.
    Do not create, edit, or invent license approvals. Free commercial use,
    redistribution rights, and obligations must be approved for the target.
    Repository-owned license checks must approve the entire resolved graph,
    including new transitive packages. Missing approval/checks blocks editing.
8. apply_minimal_fix only when eligible. For API changes, make only the
    declared surgical source fixes and meaningful AAA regression tests using
    the host's editor. At most 5 source/test files and 200 added/deleted lines;
    larger migrations require manual review. No broad product rewrite.
9. generate_aaa_test for supported base-image changes; it does not invent
    arbitrary API tests. Dependency-only fixes retain the product unit suite.
10. run_validation_matrix after each package update. Required baseline and
     post-update build, unit tests, terminating runtime smoke tests, and full
     dependency/license checks must pass. No passing marker for skipped tests.
     Fix only declared API adaptations and rerun checks; failures remain
     unresolved and local/uncommitted. Validate before the next package edit.
11. generate_local_report, showing qualification and unresolved findings.
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
    """Log tool exceptions and return errors without crashing MCP stdio."""
    try:
        return func(*args, **kwargs)
    except (
        Exception
    ) as exc:  # surfaced to the client as a tool result, not a crashed server
        logger.exception("%s failed", tool_name)
        return {"status": "ERROR", "error": str(exc)}


@mcp.tool(
    annotations=ToolAnnotations(
        title="Run prechecks", read_only_hint=True, open_world_hint=False
    )
)
def run_prechecks() -> dict[str, Any]:
    """Phase 0. Fail closed unless the repo is on main, clean, and not mid-merge."""
    return _run("run_prechecks", engine.run_prechecks)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Pull main twice",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=True,
    )
)
def pull_main_twice() -> dict[str, Any]:
    """Phase 1. Fast-forward main twice. Any failure stops the run."""
    return _run("pull_main_twice", engine.pull_main_twice)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Create security branch",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=False,
    )
)
def create_security_branch() -> dict[str, Any]:
    """Phase 2. Create security-fixes-Month-dd-YYYY. Stop if that name already exists."""
    return _run("create_security_branch", engine.create_security_branch)


@mcp.tool(
    annotations=ToolAnnotations(
        title="List security findings", read_only_hint=True, open_world_hint=True
    )
)
def list_security_findings(project_id: str | None = None) -> dict[str, Any]:
    """Phase 3. Read the still-detected GitLab vulnerability report on main."""
    return _run("list_security_findings", engine.list_security_findings, project_id)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Verify security finding", read_only_hint=True, open_world_hint=True
    )
)
def verify_security_finding(finding_id: str) -> dict[str, Any]:
    """Phase 4. Verify one finding with local evidence and online advisories before any edit."""
    return _run("verify_security_finding", engine.verify_security_finding, finding_id)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Qualify package update",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=True,
    )
)
def qualify_package_update(finding_id: str, review: dict[str, Any]) -> dict[str, Any]:
    """Qualify a package target with reviewed docs, corporate approval, and checks.

    review must identify ecosystem, package, and target exactly. Include
    documentation {complete, sources, summary}, compatible=true, api_changes,
    frameworks [{name, version, source_url, assessment}], and source_fixes
    [{path, reason}] (or []). Read complete official target-version docs;
    attestations are audited, not independent proof of documentation reading.
    Corporate approval comes only from the configured policy file. This tool
    runs the product baseline and all policy checks before permitting an edit.
    """
    return _run(
        "qualify_package_update", engine.qualify_package_update, finding_id, review
    )


@mcp.tool(
    annotations=ToolAnnotations(
        title="Apply minimal fix",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=True,
    )
)
def apply_minimal_fix(finding_id: str) -> dict[str, Any]:
    """Apply only a fresh qualified package plan; resolution requires post-checks."""
    return _run("apply_minimal_fix", engine.apply_minimal_fix, finding_id)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Generate AAA test",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=False,
    )
)
def generate_aaa_test(finding_id: str) -> dict[str, Any]:
    """Phase 5. Add an Arrange-Act-Assert test when the fix changes runtime behavior."""
    return _run("generate_aaa_test", engine.generate_aaa_test, finding_id)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Run validation matrix",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=True,
    )
)
def run_validation_matrix() -> dict[str, Any]:
    """Phase 6. Run Node, .NET, Java 17, NGINX, and container checks that apply to this repo."""
    return _run("run_validation_matrix", engine.run_validation_matrix)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Generate local report",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=False,
    )
)
def generate_local_report() -> dict[str, Any]:
    """Phase 7. Write the human and JSON report, including false positives and skipped findings.

    Display unresolved_issues_table at the end of the final response. It lists
    issues not safely addressed by package or code updates and the reasons.
    """
    return _run("generate_local_report", engine.generate_local_report)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get run status", read_only_hint=True, open_world_hint=False
    )
)
def get_run_status() -> dict[str, Any]:
    """Return the current phase, branch, and counts for this run."""
    return _run("get_run_status", engine.get_run_status)


def main() -> None:
    """Serve MCP tools over stdio until the client disconnects."""
    try:
        mcp.run()
    finally:
        try:
            engine.close()
        except Exception:
            logger.exception("Could not close the engine during server shutdown")


if __name__ == "__main__":
    main()
