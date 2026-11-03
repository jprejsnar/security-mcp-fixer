"""MCP tools for the local GitLab security remediation workflow."""

from __future__ import annotations

import atexit
import logging
import os
import threading
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from gitlab_security_mcp import __version__
from gitlab_security_mcp.engine import Engine

logger = logging.getLogger("gitlab_security_mcp")

INSTRUCTIONS = """
Local-only GitLab security remediation. Call the tools in this order:
1. run_prechecks(repo_root=<absolute application checkout path>). Always pass
    the active application's path when the host starts this server elsewhere.
    Unresolved ${workspaceFolder} values are not repository paths.
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
    Do not skip a package merely because its major version changes. Use the
    proposed caller_scan as a starting point, read the old/target APIs and
    migration guides, and inspect actual application and installed dependency
    callers (including wrappers, dynamic calls, options and return values).
    No direct imports does not establish transitive compatibility. Record
    concrete caller breakages when found; distinguish incomplete evidence
    from proven breakage. Never claim 100% runtime compatibility from a scan.
7. qualify_package_update with the exact version-bound documentation review.
    Without a configured/existing policy, provide review.license {expression,
    sources:[official target-version HTTPS URLs], commercial_use_permitted:true,
    no_license_fees:true, obligations, assessment}. Read actual terms; do not
    invent corporate approval. A missing default policy file is not a blocker.
    PACKAGE_UPDATE_POLICY, when set, or an existing default policy remains
    mandatory and must be independently provisioned. Never fabricate or edit
    corporate approvals. All checks defined by that policy remain required.
8. apply_minimal_fix only when eligible. Every major, minor, revision or build
    package update requires compatible_without_code_changes=true and
    source_fixes=[]. Neither production nor unit-test callers may require API
    adaptations. Never add, edit or weaken production code, tests, frameworks,
    or check scripts to make any package version pass. Major candidates also
    require major_upgrade caller/API evidence. Skip incompatible callers with
    their concrete API evidence, not just a version-number warning.
9. generate_aaa_test for supported base-image changes; it does not invent
    arbitrary API tests. Dependency-only fixes retain the product unit suite.
10. Qualification runs lint before permitting the version edit and records
    every emitted warning, informational and unknown diagnostic. Run
    run_validation_matrix after each package update. Accept only with no lint
    errors, a successful production build, and built/executed unit tests with
    no failures, plus all configured corporate checks. Warnings/info/unknown
    output alone are not lint failures. Missing/skipped or truncated checks
    cannot pass. Failed attempted updates are rejected and updater-owned
    dependency edits are restored when unchanged since application. Later user
    edits are preserved and require manual cleanup. Report the exact failures;
    never adapt production/tests to fix them. Validate before the next edit.
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
engine: Engine | None = None
_engine_lock = threading.RLock()


def _close_engine() -> None:
    """Release the engine if configuration succeeded and tools initialized it."""
    with _engine_lock:
        if engine is not None:
            engine.close()


atexit.register(_close_engine)


def _run(
    tool_name: str, *args, repo_root: str | None = None, **kwargs
) -> dict[str, Any]:
    """Log tool exceptions and return errors without crashing MCP stdio."""
    global engine
    with _engine_lock:
        try:
            if engine is not None and repo_root is not None:
                requested = Path(repo_root).expanduser().resolve()
                if requested != engine.repo_root:
                    if engine.state.status not in {"NOT_STARTED", "PRECHECK_FAILED"}:
                        raise ValueError(
                            "Cannot change repositories during an active run. "
                            "Restart the MCP server to select another checkout."
                        )
                    replacement = Engine.from_env(repo_root)
                    engine.close()
                    engine = replacement
            if engine is None:
                engine = Engine.from_env(repo_root)
            return getattr(engine, tool_name)(*args, **kwargs)
        except Exception as exc:
            logger.exception("%s failed", tool_name)
            return {
                "status": "ERROR",
                "stage": "configuration" if engine is None else tool_name,
                "error": str(exc),
                "repo_root": str(engine.repo_root) if engine is not None else None,
                "server_cwd": os.getcwd(),
                "action": "Call run_prechecks(repo_root=<absolute application checkout path>). "
                "For persistent configuration, set REPO_ROOT to that absolute path "
                "and restart the MCP server. Check server stderr for diagnostic details.",
            }


@mcp.tool(
    annotations=ToolAnnotations(
        title="Run prechecks", read_only_hint=True, open_world_hint=False
    )
)
def run_prechecks(repo_root: str | None = None) -> dict[str, Any]:
    """Select the absolute application checkout; require clean main and no merge.

    Pass the active workspace path explicitly when REPO_ROOT is unset or contains
    an unresolved host placeholder. Selection is locked after prechecks pass.
    """
    return _run("run_prechecks", repo_root=repo_root)


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
    return _run("pull_main_twice")


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
    return _run("create_security_branch")


@mcp.tool(
    annotations=ToolAnnotations(
        title="List security findings", read_only_hint=True, open_world_hint=True
    )
)
def list_security_findings(project_id: str | None = None) -> dict[str, Any]:
    """Phase 3. Read the still-detected GitLab vulnerability report on main."""
    return _run("list_security_findings", project_id)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Verify security finding", read_only_hint=True, open_world_hint=True
    )
)
def verify_security_finding(finding_id: str) -> dict[str, Any]:
    """Phase 4. Verify one finding with local evidence and online advisories before any edit."""
    return _run("verify_security_finding", finding_id)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Qualify package update",
        read_only_hint=False,
        destructive_hint=False,
        open_world_hint=True,
    )
)
def qualify_package_update(finding_id: str, review: dict[str, Any]) -> dict[str, Any]:
    """Qualify a package target with reviewed APIs, license terms, and checks.

    review must identify ecosystem, package, and target exactly. Include
    documentation {complete, sources, summary}, compatible=true,
    compatible_without_code_changes=true, api_changes,
    frameworks [{name, version, source_url, assessment}], and source_fixes=[].
    Production AND unit-test callers must need no API adaptations for every
    major/minor/revision/build version. Read official target-version docs;
    attestations are audited, not independent proof of documentation reading.
    Corporate approval comes only from the configured policy file. This tool
    records baseline lint diagnostics, builds and unit tests, and all policy
    checks before permitting an edit. Missing checks never count as passing.
    If no corporate policy is configured/present, include license {expression,
    sources, commercial_use_permitted:true, no_license_fees:true, obligations,
    assessment}. No corporate approval JSON file is required in that mode.
    For proposed major_upgrade=true also provide major_upgrade {scan_id from
    proposed_fix.caller_scan, compatible_without_code_changes:true,
    caller_breakages_found:false, migration_sources:[official HTTPS URLs],
    api_comparison, caller_assessment, dependency_assessment,
    reviewed_files:[{path, sha256, assessment}]}. Read every source reference
    and relevant installed dependency callers. All source_fixes must be [].
    This is reviewed evidence, not a mathematical compatibility guarantee.
    """
    return _run("qualify_package_update", finding_id, review)


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
    return _run("apply_minimal_fix", finding_id)


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
    return _run("generate_aaa_test", finding_id)


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
    return _run("run_validation_matrix")


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
    return _run("generate_local_report")


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get run status", read_only_hint=True, open_world_hint=False
    )
)
def get_run_status() -> dict[str, Any]:
    """Return the current phase, branch, and counts for this run."""
    return _run("get_run_status")


def main() -> None:
    """Serve MCP tools over stdio until the client disconnects."""
    try:
        mcp.run()
    finally:
        try:
            _close_engine()
        except Exception:
            logger.exception("Could not close the engine during server shutdown")


if __name__ == "__main__":
    main()
