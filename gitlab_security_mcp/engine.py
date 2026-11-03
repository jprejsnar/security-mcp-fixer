"""Phase machine for one local remediation run."""

from __future__ import annotations

import functools
import logging
import os
import shutil
import threading
from collections.abc import Callable
from copy import deepcopy
from datetime import date
from pathlib import Path

from gitlab_security_mcp.aaa import generate_aaa_test
from gitlab_security_mcp.advisory import (
    PACKAGE_MISMATCH,
    AdvisoryClient,
    AdvisoryLookup,
)
from gitlab_security_mcp.commands import CommandRunner
from gitlab_security_mcp.git_ops import GitOps, branch_name_for
from gitlab_security_mcp.gitlab_client import GitLabClient
from gitlab_security_mcp.manifests import (
    iter_files,
    locate_package,
    manifests_were_parsed,
)
from gitlab_security_mcp.remediate import Plan, apply_plan, plan_remediation
from gitlab_security_mcp.report import write_report
from gitlab_security_mcp.state import RunState
from gitlab_security_mcp.util import resolve_inside
from gitlab_security_mcp.validate import run_validation
from gitlab_security_mcp.versions import is_major_upgrade, parse_version

logger = logging.getLogger("gitlab_security_mcp")

AFTER_BRANCH = {"BRANCH_CREATED", "FINDINGS_LISTED", "FIXES_IN_PROGRESS", "VALIDATION_COMPLETE", "VALIDATION_INCOMPLETE", "VALIDATION_FAILED", "REPORT_GENERATED"}


def _serialized(method):
    """Hold the engine lock for one public tool call.

    MCP may run sync tools on different threads. The lock is re-entrant
    so a tool can call another tool method without deadlocking.
    Copy results before unlocking so callers cannot mutate active state.
    """

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        """Reject calls after close and detach results while holding the lock."""
        with self._lock:
            if self._closed:
                return {"status": "ERROR", "reason": "Engine is closed"}
            return deepcopy(method(self, *args, **kwargs))

    return wrapper


class Engine:
    """Coordinate one local run through serialized public tool methods.

    The state attribute holds active decisions, changes, and validation.
    Call prechecks, branch creation, retrieval, verification, remediation,
    validation, and reporting in phase order. Close ends the run and
    releases owned HTTP clients, but never injected dependencies.
    """

    def __init__(
        self,
        repo_root: Path,
        *,
        gitlab: GitLabClient | None = None,
        advisory: AdvisoryClient | None = None,
        runner: CommandRunner | None = None,
        which: Callable[[str], str | None] | None = None,
        today: date | None = None,
        project_id: str | None = None,
        validation_timeout: int = 600,
        gitlab_token: str | None = None,
        gitlab_api_url: str = "https://gitlab.com/api/v4",
        github_token: str | None = None,
        nvd_api_key: str | None = None,
    ):
        """Initialize state and optionally create HTTP clients and a runner.

        repo_root bounds all local operations. Callers retain ownership of
        injected clients; close releases only clients created here.
        which and today can replace environment-dependent lookup and time.
        Initialization errors propagate after owned-client cleanup.
        """
        self.repo_root = Path(repo_root).resolve()
        self._lock = threading.RLock()
        self.runner = runner if runner is not None else CommandRunner(self.repo_root)
        self.git = GitOps(self.repo_root, self.runner)
        self._owns_gitlab = gitlab is None
        self._owns_advisory = advisory is None
        self.gitlab = gitlab if gitlab is not None else GitLabClient(gitlab_token, gitlab_api_url)
        try:
            self.advisory = advisory if advisory is not None else AdvisoryClient(github_token=github_token, nvd_api_key=nvd_api_key)
        except BaseException:
            if self._owns_gitlab:
                try:
                    self.gitlab.close()
                except Exception:
                    logger.exception("Could not close GitLab client after initialization failure")
            raise
        self.which = which if which is not None else shutil.which
        self.today = today or date.today()
        self.project_id = project_id
        self.validation_timeout = validation_timeout
        self.state = RunState()
        self._files: list[Path] | None = None
        self._files_truncated = False
        self._closed = False

    def close(self) -> None:
        """Wait for active tools and close each owned HTTP client once.

        Injected clients stay open. Cleanup failures propagate after both
        owned clients are attempted; later tool calls return an error.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                if self._owns_gitlab:
                    self.gitlab.close()
            finally:
                if self._owns_advisory:
                    self.advisory.close()

    @classmethod
    def from_env(cls) -> Engine:
        """Build an engine from repository, API, and credential settings.

        REPO_ROOT defaults to the current directory. GitLab and advisory
        credentials are optional until their services are needed.
        VALIDATION_TIMEOUT_SEC defaults to 600 and must parse as an integer.
        """
        root = Path(os.environ.get("REPO_ROOT") or os.getcwd()).resolve()
        timeout = int(os.environ.get("VALIDATION_TIMEOUT_SEC", "600"))
        return cls(
            root,
            project_id=os.environ.get("GITLAB_PROJECT_ID"),
            gitlab_token=os.environ.get("GITLAB_TOKEN") or os.environ.get("GITLAB_PERSONAL_ACCESS_TOKEN"),
            gitlab_api_url=os.environ.get("GITLAB_API_URL", "https://gitlab.com/api/v4"),
            github_token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
            nvd_api_key=os.environ.get("NVD_API_KEY"),
            validation_timeout=timeout,
        )

    def _remember(self) -> None:
        """Persist the current run snapshot; let storage failures propagate."""
        self.state.save(self.repo_root)

    def _snapshot(self) -> tuple[list[Path], bool]:
        """Reuse one pruned file list until a fix changes the tree."""
        if self._files is None:
            self._files, self._files_truncated = iter_files(self.repo_root)
        return self._files, self._files_truncated

    def _drop_snapshot(self) -> None:
        """Invalidate cached file discovery after local changes."""
        self._files = None

    @_serialized
    def run_prechecks(self) -> dict:
        """Fail closed unless the tree is on a clean main with no merge in progress."""
        try:
            self.git.ensure_work_tree()
            branch = self.git.current_branch()
            if branch != "main":
                return self._stop(
                    "PRECHECK_FAILED",
                    "precheck",
                    {"status": "PRECHECK_FAILED", "reason": f"Not on main (current: {branch or 'detached'}). Switch to main first.", "no_changes_attempted": True},
                )
            in_progress = self.git.in_progress_operation()
            if in_progress:
                return self._stop(
                    "PRECHECK_FAILED",
                    "precheck",
                    {"status": "PRECHECK_FAILED", "reason": f"A git {in_progress} operation is in progress.", "no_changes_attempted": True},
                )
            dirty = self.git.dirty_lines()
            if dirty:
                return self._stop(
                    "PRECHECK_FAILED",
                    "precheck",
                    {"status": "PRECHECK_FAILED", "reason": "Working tree not clean.", "dirty_paths": dirty, "no_changes_attempted": True},
                )
        except Exception as exc:
            logger.exception("precheck failed")
            return self._stop(
                "PRECHECK_FAILED",
                "precheck",
                {"status": "PRECHECK_FAILED", "error": str(exc), "no_changes_attempted": True},
            )
        self.state.status = "PRECHECK_PASSED"
        self.state.stop_stage = None
        self._remember()
        return {"status": "PRECHECK_PASSED", "branch": "main", "clean": True}

    @_serialized
    def pull_main_twice(self) -> dict:
        """Fast-forward main twice. Either failure stops the run."""
        if self.state.status != "PRECHECK_PASSED":
            return {"status": "PULL_FAILED", "reason": "Precheck not passed"}
        results = []
        for number in (1, 2):
            try:
                if self.git.current_branch() != "main":
                    return self._stop("PULL_FAILED", f"pull_{number}", {"status": "PULL_FAILED", "reason": "Branch changed away from main before the pull finished."})
                start = self.git.head()
                result = self.git.run(["pull", "--ff-only"], check=False)
                end = self.git.head()
                results.append(
                    {
                        "pull": number,
                        "exit_code": result.exit_code,
                        "stdout": result.stdout[-500:],
                        "stderr": result.stderr[-500:],
                        "start_head": start,
                        "end_head": end,
                    }
                )
                if result.exit_code != 0:
                    return self._stop("PULL_FAILED", f"pull_{number}", {"status": "PULL_FAILED", "failed_pull": number, "results": results})
            except Exception as exc:
                return self._stop("PULL_FAILED", f"pull_{number}", {"status": "PULL_FAILED", "failed_pull": number, "error": str(exc), "results": results})
        dirty = self.git.dirty_lines()
        if dirty:
            return self._stop("PULL_FAILED", "pull_clean", {"status": "PULL_FAILED", "reason": "Working tree dirty after pulls.", "dirty_paths": dirty, "results": results})
        self.state.status = "PULLS_SUCCEEDED"
        self.state.pulls = results
        self._remember()
        return {"status": "PULLS_SUCCEEDED", "results": results}

    @_serialized
    def create_security_branch(self) -> dict:
        """Create the dated security branch only when that name is unused."""
        if self.state.status == "BRANCH_CREATED" and self.state.branch_name:
            return {"status": "BRANCH_CREATED", "branch": self.state.branch_name, "note": "Branch was already created for this run."}
        if self.state.status != "PULLS_SUCCEEDED":
            return {"status": "BRANCH_CREATION_FAILED", "reason": "Pulls not succeeded"}
        name = branch_name_for(self.today)
        try:
            if self.git.branch_exists_locally(name) or self.git.branch_exists_on_origin(name):
                return self._stop(
                    "BRANCH_CREATION_FAILED",
                    "branch",
                    {"status": "BRANCH_CREATION_FAILED", "reason": f"Branch {name} already exists. Delete or rename it manually.", "branch": name},
                )
            self.git.run(["checkout", "-b", name])
            current = self.git.current_branch()
            if current != name:
                raise RuntimeError(f"Checkout verification failed. Current branch is {current}.")
        except Exception as exc:
            return self._stop("BRANCH_CREATION_FAILED", "branch", {"status": "BRANCH_CREATION_FAILED", "error": str(exc), "branch": name})
        self.state.branch_name = name
        self.state.status = "BRANCH_CREATED"
        self._remember()
        return {"status": "BRANCH_CREATED", "branch": name}

    @_serialized
    def list_security_findings(self, project_id: str | None = None) -> dict:
        """Read findings once. A second list after decisions would drop them."""
        if self.state.status not in {"BRANCH_CREATED", "FINDINGS_LISTED"}:
            return {"status": "ERROR", "reason": "Branch not created yet"}
        if self.state.decisions or self.state.changes:
            return {
                "status": "ERROR",
                "reason": "Findings were already verified or changed. Listing again would discard those decisions.",
            }
        pid = project_id or self.project_id
        fetched = self.gitlab.fetch(pid or "")
        if not fetched.ok:
            return {"status": "ERROR", "reason": fetched.error}
        self.state.findings = fetched.findings
        self.state.findings_truncated = fetched.truncated
        self.state.pipeline = fetched.pipeline
        self.state.excluded_findings = fetched.excluded or {}
        self.state.decisions = {}
        self.state.false_positives = []
        self.state.no_solution = []
        self.state.skipped_user_prompt = []
        self.state.status = "FINDINGS_LISTED"
        self._remember()
        return {
            "status": "OK",
            "count": len(fetched.findings),
            "truncated": fetched.truncated,
            "excluded": fetched.excluded or {},
            "project_path": fetched.project_path,
            "pipeline": fetched.pipeline,
            "findings": fetched.findings,
            "note": "Read-only GraphQL from the project vulnerability report. Filters: Needs triage or Confirmed; tracked branch main; Still detected. Pipeline provenance is recorded per finding.",
        }

    @_serialized
    def verify_security_finding(self, finding_id: str) -> dict:
        """Compare one finding with the tree and with public advisories."""
        if self.state.status not in AFTER_BRANCH:
            return {"status": "ERROR", "reason": "Findings have not been listed yet"}
        finding = self._finding(finding_id)
        if finding is None:
            return {"status": "ERROR", "reason": "Finding not found"}
        try:
            decision, reason, evidence, proposed, prompt = self._decide(finding)
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            reason = f"Finding evidence could not be read safely: {exc}"
            decision, evidence, proposed = "MANUAL_REVIEW", [reason], None
            prompt = self._prompt(finding, None, reason)
        self.state.forget(finding_id)
        assessment = {"decision": decision, "reason": reason, "evidence": evidence}
        finding["remediationDecision"] = decision
        finding["assessment"] = assessment
        finding["proposedFix"] = proposed
        finding["evidence"] = evidence
        self.state.decisions[finding_id] = assessment
        component = finding.get("component")
        if decision == "FALSE_POSITIVE":
            self.state.false_positives.append({"id": finding_id, "component": component, "reason": reason, "evidence": evidence})
        elif decision == "NO_SAFE_FIX":
            self.state.no_solution.append({"id": finding_id, "component": component, "reason": reason})
        elif decision == "MANUAL_REVIEW":
            self.state.skipped_user_prompt.append({"id": finding_id, "component": component, "reason": reason, "prompt": prompt})
        self._remember()
        return {
            "finding_id": finding_id,
            "decision": decision,
            "reason": reason,
            "evidence": evidence,
            "eligible_for_auto_fix": decision == "CHANGE_REQUIRED",
            "proposed_fix": proposed,
            "user_prompt": prompt,
        }

    @_serialized
    def apply_minimal_fix(self, finding_id: str) -> dict:
        """Apply one already-verified plan. Incomplete plans are refused."""
        finding = self._finding(finding_id)
        if finding is None:
            return {"status": "ERROR", "reason": "Finding not found"}
        if any(item["id"] == finding_id for item in self.state.skipped_user_prompt):
            prompt = next(item["prompt"] for item in self.state.skipped_user_prompt if item["id"] == finding_id)
            return {
                "status": "SKIPPED_USER_PROMPT",
                "finding_id": finding_id,
                "reason": "Requires user input because online lookups did not produce a fix. Skipped; continuing with other findings.",
                "user_prompt": prompt,
            }
        if finding.get("remediationDecision") != "CHANGE_REQUIRED":
            return {"status": "SKIPPED", "reason": "Not eligible for automated fix", "finding_id": finding_id}
        proposed = finding.get("proposedFix") or {}
        required = ("strategy", "score", "ecosystem", "package", "target")
        if any(key not in proposed for key in required):
            return {"status": "ERROR", "reason": "Proposed fix is incomplete.", "finding_id": finding_id}
        plan = Plan(
            strategy=proposed["strategy"],
            score=proposed["score"],
            ecosystem=proposed["ecosystem"],
            package=proposed["package"],
            installed=proposed.get("installed"),
            target=proposed["target"],
            files=list(proposed.get("files") or []),
            manager=proposed.get("manager"),
            description=proposed.get("description") or "",
            oracle=proposed.get("oracle"),
        )
        outcome = apply_plan(self.repo_root, plan, self.runner, self.which)
        change = {
            "finding_id": finding_id,
            "status": outcome["status"],
            "files": outcome.get("files") or [],
            "type": plan.strategy,
            "strategy": plan.strategy,
            "description": outcome.get("description"),
            "commands": outcome.get("commands") or [],
            "oracle": plan.oracle,
            "detail": outcome.get("detail"),
        }
        self.state.changes.append(change)
        self._drop_snapshot()
        if outcome["status"] == "APPLIED":
            self.state.status = "FIXES_IN_PROGRESS"
        elif outcome["status"] in {"FIX_FAILED", "FIX_FAILED_LOCKFILE"}:
            self.state.no_solution.append(
                {
                    "id": finding_id,
                    "component": finding.get("component"),
                    "reason": outcome.get("detail") or "The planned fix could not be applied.",
                }
            )
        self._remember()
        return {
            "status": outcome["status"],
            "finding_id": finding_id,
            "change": change,
            "note": "Local uncommitted change only. Review the diff before committing.",
        }

    @_serialized
    def generate_aaa_test(self, finding_id: str) -> dict:
        """Add an AAA test only when the change has an oracle and a known framework."""
        finding = self._finding(finding_id)
        if finding is None:
            return {"status": "ERROR", "reason": "Finding not found"}
        change = next((item for item in reversed(self.state.changes) if item.get("finding_id") == finding_id and item.get("status") == "APPLIED"), None)
        result = generate_aaa_test(self.repo_root, finding, change)
        self._drop_snapshot()
        if result.get("status") == "GENERATED":
            self.state.changes.append(
                {
                    "finding_id": finding_id,
                    "status": "TEST_ADDED",
                    "files": [result["path"]],
                    "type": "aaa_test",
                    "strategy": "aaa_test",
                    "description": f"Added an AAA test asserting {result.get('oracle')}.",
                }
            )
        self._remember()
        return result

    @_serialized
    def run_validation_matrix(self) -> dict:
        """Run the detected stack's checks. A missing branch blocks this."""
        if self.state.status not in AFTER_BRANCH:
            return {"status": "ERROR", "reason": "Create the security branch before validation."}
        outcome = run_validation(self.repo_root, self.runner, self.which, timeout=self.validation_timeout)
        self.state.validation_results = outcome["results"]
        self.state.validation_status = outcome["status"]
        if outcome["status"] == "VALIDATION_FAILED":
            self.state.status = "VALIDATION_FAILED"
            self.state.stop_stage = "validation"
        else:
            self.state.status = outcome["status"]
            self.state.stop_stage = None
        self._remember()
        return outcome

    @_serialized
    def generate_local_report(self) -> dict:
        """Write the markdown and JSON reports under .security-mcp/reports."""
        staged: list[str] | None = None
        diff_stat = ""
        diff_files = ""
        try:
            self.git.ensure_work_tree()
            staged = self.git.staged_names()
            summary = self.git.diff_summary()
            diff_stat = summary["stat"]
            diff_files = summary["files"]
        except (OSError, RuntimeError, PermissionError) as exc:
            diff_stat = f"Could not read git diff: {exc}"
        written = write_report(self.repo_root, self.state, staged=staged, diff_stat=diff_stat, diff_files=diff_files)
        self.state.report_path = written["human_report"]
        self.state.json_report_path = written["json_report"]
        self.state.status = "REPORT_GENERATED"
        self._remember()
        return written

    @_serialized
    def get_run_status(self) -> dict:
        """Return counts for the current run without changing it."""
        return {
            "status": self.state.status,
            "stop_stage": self.state.stop_stage,
            "branch": self.state.branch_name,
            "findings_count": len(self.state.findings),
            "changes_count": len(self.state.changes),
            "false_positives_count": len(self.state.false_positives),
            "no_solution_count": len(self.state.no_solution),
            "skipped_user_prompt_count": len(self.state.skipped_user_prompt),
            "report_path": self.state.report_path,
        }

    def _decide(self, finding: dict) -> tuple[str, str, list[str], dict | None, str | None]:
        """Combine local evidence and advisories without guessing safe edits.

        Return a decision, reason, evidence, optional plan, and optional
        review prompt. Unknown reachability never proves a false positive.
        Major upgrades and unresolved transitive dependencies need review.
        """
        evidence = [
            "Reachability of the vulnerable code path was not determined. Unknown reachability is not treated as a false positive."
        ]
        category = finding.get("category") or ""
        component = finding.get("component")
        if finding.get("falsePositiveFlag") is True:
            evidence.append("GitLab marked falsePositive=true. That flag alone is not sufficient; local evidence is required.")
        location_file = (finding.get("location") or {}).get("file")
        if location_file and category in {"sast", "secret_detection"}:
            resolved = resolve_inside(self.repo_root, location_file)
            if resolved is None:
                reason = f"{location_file} is outside the repository, so it was not treated as a false positive."
                evidence.append(reason)
                return "MANUAL_REVIEW", reason, evidence, None, self._prompt(finding, None, reason)
            if not resolved.is_file():
                evidence.append(f"{location_file} is not in the working tree.")
                return "FALSE_POSITIVE", f"{location_file} is not present in the repository.", evidence, None, None

        if category in {"secret_detection", "dast"}:
            reason = "Secret and DAST findings are not safe to rewrite automatically. Rotate the credential or fix the request with a reviewer."
            return "MANUAL_REVIEW", reason, evidence, None, self._prompt(finding, None, reason)

        files, files_truncated = self._snapshot()
        hit, truncated = locate_package(
            self.repo_root,
            component,
            finding.get("installedVersion"),
            files,
            truncated=files_truncated,
        )
        if hit:
            evidence.append(
                f"Local {hit.ecosystem} {hit.manager} package {hit.name} version {hit.version or 'unknown'} "
                f"in {hit.manifest or hit.lockfile}; direct={hit.direct}."
            )
            if hit.version and not finding.get("installedVersion"):
                finding["installedVersion"] = hit.version
            finding["dependencyPath"] = ["direct" if hit.direct else "transitive"]
        elif truncated:
            evidence.append("Manifest search hit the file cap, so absence is not evidence of a false positive.")
        elif category == "dependency_scanning" and component and manifests_were_parsed(self.repo_root, files):
            if any(path.suffix.lower() in {".csproj", ".fsproj", ".vbproj"} or path.name in {"pom.xml", "build.gradle", "build.gradle.kts", "libs.versions.toml", "Directory.Packages.props"} for path in files):
                reason = "The package was not resolved locally. Java and NuGet manifests do not enumerate every transitive dependency; manual dependency-tree review is required."
                return "MANUAL_REVIEW", reason, [*evidence, reason], None, self._prompt(finding, None, reason)
            evidence.append(f"{component} was not found in the parsed manifests or lockfiles.")
            return "FALSE_POSITIVE", f"{component} is not present in the parsed dependency files.", evidence, None, None

        installed = (hit.version if hit else None) or finding.get("installedVersion")
        ecosystem = hit.ecosystem if hit else None
        package_name = hit.name if hit else component
        looked_up = self.advisory.lookup(finding, ecosystem or (hit.manager if hit else None), package_name, installed)
        evidence.append(looked_up.summary or "No advisory summary.")
        if looked_up.ranges:
            finding["affectedRange"] = ", ".join(looked_up.ranges)
            evidence.append("Affected range: " + finding["affectedRange"])
        if looked_up.sources:
            evidence.append("Sources: " + ", ".join(looked_up.sources))
        if looked_up.errors:
            evidence.append("Lookup errors: " + "; ".join(looked_up.errors))

        if looked_up.outcome in {"lookup_failed", "not_found", PACKAGE_MISMATCH}:
            reason = looked_up.summary
            return "MANUAL_REVIEW", reason, evidence, None, self._prompt(finding, looked_up, reason)
        if looked_up.affected is False:
            return "FALSE_POSITIVE", looked_up.summary, evidence, None, None
        if looked_up.outcome == "no_fix_published" or not looked_up.lowest_fixed_version:
            reason = looked_up.summary if looked_up.outcome == "no_fix_published" else "No fixed version is newer than the installed version."
            if looked_up.affected is None and looked_up.fixed_versions:
                reason = "Online records were found, but the installed version could not be compared to the affected range."
                return "MANUAL_REVIEW", reason, evidence, None, self._prompt(finding, looked_up, reason)
            return "NO_SAFE_FIX", reason, evidence, None, None
        if looked_up.affected is None:
            reason = "Online records were found, but the installed version could not be compared to the affected range."
            return "MANUAL_REVIEW", reason, evidence, None, self._prompt(finding, looked_up, reason)

        image_only = category == "container_scanning" and hit is None
        fixed = looked_up.lowest_fixed_version
        plan, plan_reason = plan_remediation(self.repo_root, finding, None if image_only else hit, fixed, files)
        if plan is None and category == "container_scanning":
            plan, plan_reason = plan_remediation(self.repo_root, finding, None, fixed, files)
        if plan is None and "already at or above" in plan_reason:
            return "FALSE_POSITIVE", plan_reason, evidence, None, None
        if plan is None:
            if category == "sast":
                reason = "SAST findings do not get a guessed source edit. " + plan_reason
                return "MANUAL_REVIEW", reason, evidence, None, self._prompt(finding, looked_up, reason)
            return "NO_SAFE_FIX", plan_reason, evidence, None, None
        evidence.append(f"Minimal fix score {plan.score}: {plan.description}")
        if is_major_upgrade(plan.installed or installed, plan.target):
            reason = (
                f"The lowest fixed version {plan.target} is a major upgrade from {plan.installed or installed}. "
                "That can break callers, so it was not applied automatically."
            )
            return "MANUAL_REVIEW", reason, evidence, None, self._prompt(finding, looked_up, reason)
        if parse_version(installed) is None and plan.strategy != "image_tag":
            reason = "The installed version could not be parsed, so the fix was not applied automatically."
            return "MANUAL_REVIEW", reason, evidence, None, self._prompt(finding, looked_up, reason)
        return "CHANGE_REQUIRED", plan.description, evidence, plan.as_dict(), None

    def _prompt(self, finding: dict, looked_up: AdvisoryLookup | None, reason: str) -> str:
        """Explain why human review is needed without endorsing GitLab hints."""
        solution = finding.get("solution") or "none"
        mentioned = ", ".join(finding.get("fixedVersions") or []) or "none"
        return (
            f"Finding {finding.get('id')} ({finding.get('component') or 'unknown component'}) needs your decision. {reason} "
            f"GitLab solution: {solution}. Versions mentioned by GitLab: {mentioned}. "
            "Tell the agent the fixed version to apply, or confirm that this is a false positive. "
            "This finding is skipped and the remaining findings continue."
        )

    def _finding(self, finding_id: str) -> dict | None:
        """Return the active finding matching an id, or None if absent."""
        return next((item for item in self.state.findings if item.get("id") == finding_id), None)

    def _stop(self, status: str, stage: str, payload: dict) -> dict:
        """Record and persist the failed phase before returning its details."""
        self.state.status = status
        self.state.stop_stage = stage
        self._remember()
        return payload
