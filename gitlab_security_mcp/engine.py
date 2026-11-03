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
from gitlab_security_mcp.qualification import (
    PACKAGE_ECOSYSTEMS,
    backup_dependency_files,
    dependency_file_hashes,
    load_policy,
    package_script_hashes,
    review_major_upgrade,
    review_package,
    reviewed_license_policy,
    rollback_dependency_files,
    run_checks,
    scan_package_callers,
    tree_snapshot,
    validate_edits,
)
from gitlab_security_mcp.remediate import Plan, apply_plan, plan_remediation
from gitlab_security_mcp.report import write_report
from gitlab_security_mcp.state import RunState
from gitlab_security_mcp.util import resolve_inside
from gitlab_security_mcp.validate import run_validation
from gitlab_security_mcp.versions import is_major_upgrade, parse_version

logger = logging.getLogger("gitlab_security_mcp")

AFTER_BRANCH = {
    "BRANCH_CREATED",
    "FINDINGS_LISTED",
    "FIXES_IN_PROGRESS",
    "VALIDATION_COMPLETE",
    "VALIDATION_INCOMPLETE",
    "VALIDATION_FAILED",
    "REPORT_GENERATED",
}


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
        self._package_policy_required = bool(os.environ.get("PACKAGE_UPDATE_POLICY"))
        self.package_policy_path = Path(
            os.environ.get("PACKAGE_UPDATE_POLICY")
            or self.repo_root / ".security-mcp" / "package-update-policy.json"
        ).resolve()
        self._lock = threading.RLock()
        self.runner = runner if runner is not None else CommandRunner(self.repo_root)
        self.git = GitOps(self.repo_root, self.runner)
        self._owns_gitlab = gitlab is None
        self._owns_advisory = advisory is None
        self.gitlab = (
            gitlab if gitlab is not None else GitLabClient(gitlab_token, gitlab_api_url)
        )
        try:
            self.advisory = (
                advisory
                if advisory is not None
                else AdvisoryClient(github_token=github_token, nvd_api_key=nvd_api_key)
            )
        except BaseException:
            if self._owns_gitlab:
                try:
                    self.gitlab.close()
                except Exception:
                    logger.exception(
                        "Could not close GitLab client after initialization failure"
                    )
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
    def from_env(cls, repo_root: str | None = None) -> Engine:
        """Build an engine from repository, API, and credential settings.

        An explicit repository overrides REPO_ROOT, which defaults to cwd.
        Unexpanded host placeholders and missing directories are rejected.
        GitLab and advisory
        credentials are optional until their services are needed.
        VALIDATION_TIMEOUT_SEC defaults to 600 and must parse as an integer.
        """
        configured = repo_root if repo_root is not None else os.environ.get("REPO_ROOT")
        configured = configured or os.getcwd()
        if "${" in configured:
            raise ValueError(
                "REPO_ROOT contains an unresolved host placeholder. Set REPO_ROOT "
                "to the absolute application checkout path, or call "
                "run_prechecks(repo_root=<absolute checkout path>). Restart the MCP "
                "server after changing its configuration."
            )
        root = Path(configured).expanduser().resolve()
        if not root.is_dir():
            raise ValueError(
                f"Repository directory does not exist: {root}. Set REPO_ROOT or "
                "call run_prechecks(repo_root=<absolute checkout path>)."
            )
        timeout = int(os.environ.get("VALIDATION_TIMEOUT_SEC", "600"))
        return cls(
            root,
            project_id=os.environ.get("GITLAB_PROJECT_ID"),
            gitlab_token=os.environ.get("GITLAB_TOKEN")
            or os.environ.get("GITLAB_PERSONAL_ACCESS_TOKEN"),
            gitlab_api_url=os.environ.get(
                "GITLAB_API_URL", "https://gitlab.com/api/v4"
            ),
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
        except Exception as exc:
            self.state.status = "PRECHECK_FAILED"
            self.state.stop_stage = "precheck"
            return {
                "status": "PRECHECK_FAILED",
                "error": str(exc),
                "repo_root": str(self.repo_root),
                "server_cwd": os.getcwd(),
                "reason": "Git could not verify the configured application checkout. "
                "Check that Git is installed and REPO_ROOT points to the Git checkout, "
                "not the MCP installation or a literal ${workspaceFolder}.",
                "action": "Call run_prechecks(repo_root=<absolute application checkout path>) "
                "or update REPO_ROOT and restart the MCP server.",
                "no_changes_attempted": True,
            }
        try:
            branch = self.git.current_branch()
            if branch != "main":
                return self._stop(
                    "PRECHECK_FAILED",
                    "precheck",
                    {
                        "status": "PRECHECK_FAILED",
                        "reason": f"Not on main (current: {branch or 'detached'}). Switch to main first.",
                        "no_changes_attempted": True,
                    },
                )
            in_progress = self.git.in_progress_operation()
            if in_progress:
                return self._stop(
                    "PRECHECK_FAILED",
                    "precheck",
                    {
                        "status": "PRECHECK_FAILED",
                        "reason": f"A git {in_progress} operation is in progress.",
                        "no_changes_attempted": True,
                    },
                )
            dirty = self.git.dirty_lines()
            if dirty:
                return self._stop(
                    "PRECHECK_FAILED",
                    "precheck",
                    {
                        "status": "PRECHECK_FAILED",
                        "reason": "Working tree not clean.",
                        "dirty_paths": dirty,
                        "no_changes_attempted": True,
                    },
                )
        except Exception as exc:
            logger.exception("precheck failed")
            return self._stop(
                "PRECHECK_FAILED",
                "precheck",
                {
                    "status": "PRECHECK_FAILED",
                    "error": str(exc),
                    "no_changes_attempted": True,
                },
            )
        self.state.status = "PRECHECK_PASSED"
        self.state.stop_stage = None
        self._remember()
        return {
            "status": "PRECHECK_PASSED",
            "repo_root": str(self.repo_root),
            "branch": "main",
            "clean": True,
        }

    @_serialized
    def pull_main_twice(self) -> dict:
        """Fast-forward main twice. Either failure stops the run."""
        if self.state.status != "PRECHECK_PASSED":
            return {"status": "PULL_FAILED", "reason": "Precheck not passed"}
        results = []
        for number in (1, 2):
            try:
                if self.git.current_branch() != "main":
                    return self._stop(
                        "PULL_FAILED",
                        f"pull_{number}",
                        {
                            "status": "PULL_FAILED",
                            "reason": "Branch changed away from main before the pull finished.",
                        },
                    )
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
                    return self._stop(
                        "PULL_FAILED",
                        f"pull_{number}",
                        {
                            "status": "PULL_FAILED",
                            "failed_pull": number,
                            "results": results,
                        },
                    )
            except Exception as exc:
                return self._stop(
                    "PULL_FAILED",
                    f"pull_{number}",
                    {
                        "status": "PULL_FAILED",
                        "failed_pull": number,
                        "error": str(exc),
                        "results": results,
                    },
                )
        dirty = self.git.dirty_lines()
        if dirty:
            return self._stop(
                "PULL_FAILED",
                "pull_clean",
                {
                    "status": "PULL_FAILED",
                    "reason": "Working tree dirty after pulls.",
                    "dirty_paths": dirty,
                    "results": results,
                },
            )
        self.state.status = "PULLS_SUCCEEDED"
        self.state.pulls = results
        self._remember()
        return {"status": "PULLS_SUCCEEDED", "results": results}

    @_serialized
    def create_security_branch(self) -> dict:
        """Create the dated security branch only when that name is unused."""
        if self.state.status == "BRANCH_CREATED" and self.state.branch_name:
            return {
                "status": "BRANCH_CREATED",
                "branch": self.state.branch_name,
                "note": "Branch was already created for this run.",
            }
        if self.state.status != "PULLS_SUCCEEDED":
            return {"status": "BRANCH_CREATION_FAILED", "reason": "Pulls not succeeded"}
        name = branch_name_for(self.today)
        try:
            if self.git.branch_exists_locally(name) or self.git.branch_exists_on_origin(
                name
            ):
                return self._stop(
                    "BRANCH_CREATION_FAILED",
                    "branch",
                    {
                        "status": "BRANCH_CREATION_FAILED",
                        "reason": f"Branch {name} already exists. Delete or rename it manually.",
                        "branch": name,
                    },
                )
            self.git.run(["checkout", "-b", name])
            current = self.git.current_branch()
            if current != name:
                raise RuntimeError(
                    f"Checkout verification failed. Current branch is {current}."
                )
        except Exception as exc:
            return self._stop(
                "BRANCH_CREATION_FAILED",
                "branch",
                {"status": "BRANCH_CREATION_FAILED", "error": str(exc), "branch": name},
            )
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
        if any(
            change["finding_id"] == finding_id for change in self._package_changes()
        ):
            return {
                "status": "ERROR",
                "reason": "Retain the applied package's original evidence; run post-update validation instead",
            }
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
        finding.pop("packageQualification", None)
        finding["evidence"] = evidence
        self.state.decisions[finding_id] = assessment
        component = finding.get("component")
        if decision == "FALSE_POSITIVE":
            self.state.false_positives.append(
                {
                    "id": finding_id,
                    "component": component,
                    "reason": reason,
                    "evidence": evidence,
                }
            )
        elif decision == "NO_SAFE_FIX":
            self.state.no_solution.append(
                {"id": finding_id, "component": component, "reason": reason}
            )
        elif decision == "MANUAL_REVIEW":
            self.state.skipped_user_prompt.append(
                {
                    "id": finding_id,
                    "component": component,
                    "reason": reason,
                    "prompt": prompt,
                }
            )
        self._remember()
        return {
            "finding_id": finding_id,
            "decision": decision,
            "reason": reason,
            "evidence": evidence,
            "eligible_for_auto_fix": decision == "CHANGE_REQUIRED"
            and not (proposed and proposed.get("ecosystem") in PACKAGE_ECOSYSTEMS),
            "qualification_required": bool(
                proposed and proposed.get("ecosystem") in PACKAGE_ECOSYSTEMS
            ),
            "proposed_fix": proposed,
            "user_prompt": prompt,
        }

    @_serialized
    def qualify_package_update(self, finding_id: str, review: dict) -> dict:
        """Require reviewed APIs/license terms and a passing product baseline.

        The hosting AI supplies its complete official-documentation review
        without production or unit-test adaptations. Configured/existing corporate
        policies remain mandatory; otherwise documented license review is
        used without inventing corporate approval. Requalify after changes.
        """
        finding = self._finding(finding_id)
        if (
            self.state.status not in AFTER_BRANCH
            or finding is None
            or finding.get("remediationDecision") != "CHANGE_REQUIRED"
        ):
            return {
                "status": "ERROR",
                "reason": "Verify a supported package finding before qualification",
            }
        plan = finding.get("proposedFix") or {}
        if plan.get("ecosystem") not in PACKAGE_ECOSYSTEMS:
            return {
                "status": "ERROR",
                "reason": "This plan is not a supported package update",
            }
        if any(
            change.get("finding_id") == finding_id for change in self._package_changes()
        ):
            return {
                "status": "ERROR",
                "reason": "An applied update must retain its original qualification; run post-update validation",
            }
        finding.pop("packageQualification", None)
        baseline = {"results": []}
        checks = []
        try:
            if not isinstance(review, dict) or any(
                review.get(key) != plan.get(key)
                for key in ("ecosystem", "package", "target")
            ):
                raise ValueError(
                    "Documentation review must identify the exact ecosystem, package, and target"
                )
            source_before = review_package(self.repo_root, review)
            major_review = review_major_upgrade(self.repo_root, plan, review)
            policy = self._package_policy(plan, review)
            tree = tree_snapshot(self.repo_root)
            scripts = package_script_hashes(self.repo_root, tree)
            baseline = run_validation(
                self.repo_root,
                self.runner,
                self.which,
                timeout=self.validation_timeout,
                package_checks=True,
            )
            if baseline["status"] != "VALIDATION_COMPLETE":
                raise ValueError(
                    "Package update not applied: baseline checks failed or are incomplete. "
                    + "; ".join(
                        f"{row.get('kind') or row.get('command') or 'validation'}: {row.get('detail', row['status'])}"
                        for row in baseline["results"]
                        if row.get("required") and row["status"] != "PASSED"
                    )
                )
            checks = run_checks(
                self.repo_root,
                policy["checks"],
                self.runner,
                self.which,
                self.validation_timeout,
                plan=plan,
            )
            if any(row["status"] != "PASSED" for row in checks):
                raise ValueError(
                    "Configured baseline product-check evidence is failed/incomplete"
                )
            if major_review is not None:
                major_review = review_major_upgrade(self.repo_root, plan, review)
            validate_edits(
                self.repo_root,
                {"tree": tree, "source_before": {}, "package_script_hashes": scripts},
                [],
            )
            receipt = {
                "check_contract": "lint-build-unit-no-code-v1",
                "status": "QUALIFIED",
                "plan": deepcopy(plan),
                "review": deepcopy(review),
                "major_review": major_review,
                **policy,
                "source_before": source_before,
                "tree": tree,
                "package_script_hashes": scripts,
                "baseline_results": baseline["results"] + checks,
            }
        except (OSError, ValueError, TypeError, AttributeError, RuntimeError) as exc:
            finding["packageQualification"] = {
                "status": "BLOCKED",
                "reason": str(exc),
                "baseline_results": baseline["results"] + checks,
            }
            if plan.get("major_upgrade") and isinstance(review, dict):
                finding["packageQualification"].update(
                    plan=deepcopy(plan), review=deepcopy(review)
                )
            self._remember()
            return {
                "status": "QUALIFICATION_REQUIRED",
                "finding_id": finding_id,
                "reason": str(exc),
                "eligible_for_auto_fix": False,
                "baseline_results": baseline["results"] + checks,
            }
        finding["packageQualification"] = receipt
        self._remember()
        return {
            "status": "QUALIFIED",
            "finding_id": finding_id,
            "eligible_for_auto_fix": True,
            "approval": policy["approval"],
            "policy_mode": policy["policy_mode"],
            "baseline_results": receipt["baseline_results"],
            "note": "Apply only the reviewed dependency version edits. Do not change production code, unit tests, or check scripts. Lint, builds and unit tests must pass again before acceptance.",
        }

    @_serialized
    def apply_minimal_fix(self, finding_id: str) -> dict:
        """Apply a verified plan only after package qualification passes."""
        finding = self._finding(finding_id)
        if finding is None:
            return {"status": "ERROR", "reason": "Finding not found"}
        if any(item["id"] == finding_id for item in self.state.skipped_user_prompt):
            prompt = next(
                item["prompt"]
                for item in self.state.skipped_user_prompt
                if item["id"] == finding_id
            )
            return {
                "status": "SKIPPED_USER_PROMPT",
                "finding_id": finding_id,
                "reason": "Requires user input because online lookups did not produce a fix. Skipped; continuing with other findings.",
                "user_prompt": prompt,
            }
        if finding.get("remediationDecision") != "CHANGE_REQUIRED":
            return {
                "status": "SKIPPED",
                "reason": "Not eligible for automated fix",
                "finding_id": finding_id,
            }
        proposed = finding.get("proposedFix") or {}
        required = ("strategy", "score", "ecosystem", "package", "target")
        if any(key not in proposed for key in required):
            return {
                "status": "ERROR",
                "reason": "Proposed fix is incomplete.",
                "finding_id": finding_id,
            }
        package_update = proposed["ecosystem"] in PACKAGE_ECOSYSTEMS
        if package_update:
            self._refresh_package_validation()
            if any(
                change.get("qualification_status") != "VALIDATED"
                for change in self._package_changes()
            ):
                return {
                    "status": "VALIDATION_REQUIRED",
                    "reason": "Validate the previous package update before another edit",
                    "finding_id": finding_id,
                }
            receipt = finding.get("packageQualification") or {}
            try:
                if (
                    receipt.get("status") != "QUALIFIED"
                    or receipt.get("plan") != proposed
                    or receipt.get("check_contract") != "lint-build-unit-no-code-v1"
                ):
                    raise ValueError(
                        "Call qualify_package_update with documentation, license review or configured policy, and passing checks before this edit"
                    )
                policy = self._package_policy(proposed, receipt["review"])
                if receipt["policy_sha256"] != policy["policy_sha256"] or receipt[
                    "tree"
                ] != tree_snapshot(self.repo_root):
                    raise ValueError(
                        "Checkout or qualification policy changed; requalify the exact plan"
                    )
                review_major_upgrade(self.repo_root, proposed, receipt["review"])
                receipt["dependency_before"] = backup_dependency_files(
                    self.repo_root, proposed
                )
            except (
                OSError,
                ValueError,
                TypeError,
                AttributeError,
                RuntimeError,
            ) as exc:
                return {
                    "status": "QUALIFICATION_REQUIRED",
                    "finding_id": finding_id,
                    "reason": str(exc),
                }
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
        if package_update:
            receipt["applied_dependency_hashes"] = dependency_file_hashes(
                self.repo_root, receipt["dependency_before"]
            )
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
            "package_update": package_update,
            "ecosystem": plan.ecosystem,
            "package": plan.package,
            "target": plan.target,
            "qualification_status": "PENDING_VALIDATION" if package_update else None,
        }
        self.state.changes.append(change)
        self._drop_snapshot()
        if outcome["status"] == "APPLIED":
            self.state.status = "FIXES_IN_PROGRESS"
            self.state.validation_status = None
            if package_update:
                finding["packageQualification"]["status"] = "PENDING_VALIDATION"
                for applied in self._package_changes():
                    applied["qualification_status"] = "PENDING_VALIDATION"
                    self._finding(applied["finding_id"])["packageQualification"][
                        "status"
                    ] = "PENDING_VALIDATION"
        elif outcome["status"] in {"FIX_FAILED", "FIX_FAILED_LOCKFILE"}:
            self.state.no_solution.append(
                {
                    "id": finding_id,
                    "component": finding.get("component"),
                    "reason": outcome.get("detail")
                    or "The planned fix could not be applied.",
                }
            )
        self._remember()
        return {
            "status": outcome["status"],
            "finding_id": finding_id,
            "change": change,
            "note": "Not accepted until post-update lint has no errors, production builds and unit tests pass, and configured policy checks pass. Production/unit-test code and check scripts must remain unchanged for every version increment.",
        }

    @_serialized
    def generate_aaa_test(self, finding_id: str) -> dict:
        """Add an AAA test only when the change has an oracle and a known framework."""
        finding = self._finding(finding_id)
        if finding is None:
            return {"status": "ERROR", "reason": "Finding not found"}
        if (finding.get("proposedFix") or {}).get("ecosystem") in PACKAGE_ECOSYSTEMS:
            return {
                "status": "NOT_REQUIRED",
                "finding_id": finding_id,
                "reason": "Package version updates cannot add or modify production code or unit tests, including generated AAA tests.",
            }
        change = next(
            (
                item
                for item in reversed(self.state.changes)
                if item.get("finding_id") == finding_id
                and item.get("status") == "APPLIED"
            ),
            None,
        )
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
            return {
                "status": "ERROR",
                "reason": "Create the security branch before validation.",
            }
        package_changes = self._package_changes()
        outcome = run_validation(
            self.repo_root,
            self.runner,
            self.which,
            timeout=self.validation_timeout,
            package_checks=bool(package_changes),
        )
        allowed_files = [
            path for change in self.state.changes for path in change.get("files") or []
        ]
        expected_dependencies = {
            path: digest
            for change in package_changes
            for path, digest in (
                (self._finding(change["finding_id"]) or {}).get("packageQualification")
                or {}
            )
            .get("applied_dependency_hashes", {})
            .items()
        }
        for change in package_changes:
            finding = self._finding(change["finding_id"])
            receipt = (finding or {}).get("packageQualification") or {}
            allowed_files.extend(receipt.get("source_before") or [])
        for change in package_changes:
            finding = self._finding(change["finding_id"])
            receipt = (finding or {}).get("packageQualification") or {}
            try:
                if not receipt.get("plan"):
                    raise ValueError("Package qualification is missing")
                if receipt.get("check_contract") != "lint-build-unit-no-code-v1":
                    raise ValueError(
                        "Package qualification predates mandatory lint/no-code checks; requalification is required"
                    )
                receipt["post_results"] = deepcopy(outcome["results"])
                policy = self._package_policy(receipt["plan"], receipt["review"])
                if policy["policy_sha256"] != receipt["policy_sha256"]:
                    raise ValueError(
                        "Qualification policy changed after application; re-review required"
                    )
                validate_edits(
                    self.repo_root,
                    receipt,
                    allowed_files,
                    expected_dependencies=expected_dependencies,
                )
                checks = run_checks(
                    self.repo_root,
                    policy["checks"],
                    self.runner,
                    self.which,
                    self.validation_timeout,
                    plan=receipt["plan"],
                )
                receipt["post_results"].extend(checks)
                outcome["results"].extend(checks)
                if any(row["status"] != "PASSED" for row in checks):
                    raise ValueError(
                        "Post-update configured product checks did not pass"
                    )
                validated_tree = validate_edits(
                    self.repo_root,
                    receipt,
                    allowed_files,
                    expected_dependencies=expected_dependencies,
                )
                if outcome["status"] == "VALIDATION_COMPLETE":
                    receipt["validated_tree"] = validated_tree
            except (
                OSError,
                ValueError,
                TypeError,
                AttributeError,
                RuntimeError,
            ) as exc:
                change["detail"] = str(exc)
                outcome["status"] = "VALIDATION_FAILED"
                outcome["results"].append(
                    {
                        "status": "FAILED",
                        "required": True,
                        "kind": "package_qualification",
                        "detail": str(exc),
                        "finding_id": change["finding_id"],
                    }
                )
        for change in package_changes:
            receipt = self._finding(change["finding_id"])["packageQualification"]
            status = (
                "VALIDATED"
                if outcome["status"] == "VALIDATION_COMPLETE"
                else "PENDING_VALIDATION"
            )
            change["qualification_status"] = receipt["status"] = status
            if status == "VALIDATED":
                change["detail"] = (
                    "Accepted: no production/unit-test API changes, no lint errors, production build and unit tests passed; all configured policy checks passed"
                )
            else:
                failures = [
                    row
                    for row in outcome["results"]
                    if row.get("required") and row["status"] != "PASSED"
                ]
                change["detail"] = "Package update rejected: " + "; ".join(
                    f"{row.get('kind') or row.get('command') or 'validation'}: {row.get('detail', row['status'])}"
                    for row in failures
                )
        self.state.validation_results = outcome["results"]
        if package_changes and outcome["status"] != "VALIDATION_COMPLETE":
            outcome["reason"] = (
                "Package updates are not accepted: lint errors, missing/incomplete checks, build or unit-test failures, or prohibited code changes require rejecting the update, not adapting production or unit tests. See results for each failed check."
            )
            outcome["rollbacks"] = []
            for change in reversed(package_changes):
                receipt = self._finding(change["finding_id"])["packageQualification"]
                if receipt.get("validated_tree") is not None:
                    continue
                rollback = rollback_dependency_files(self.repo_root, receipt)
                receipt["rollback"] = change["rollback"] = rollback
                receipt["status"] = change["qualification_status"] = "REJECTED"
                if rollback["status"] == "ROLLED_BACK":
                    change["status"] = "ROLLED_BACK"
                change["detail"] += " " + rollback["detail"]
                outcome["rollbacks"].append(
                    {"finding_id": change["finding_id"], **rollback}
                )
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
        self._refresh_package_validation()
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
        written = write_report(
            self.repo_root,
            self.state,
            staged=staged,
            diff_stat=diff_stat,
            diff_files=diff_files,
        )
        self.state.report_path = written["human_report"]
        self.state.json_report_path = written["json_report"]
        self.state.status = "REPORT_GENERATED"
        self._remember()
        return written

    @_serialized
    def get_run_status(self) -> dict:
        """Return current counts and retract stale package-validation results."""
        self._refresh_package_validation()
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
            "package_updates": [
                {
                    "finding_id": change["finding_id"],
                    "package": change["package"],
                    "target": change["target"],
                    "qualification_status": change["qualification_status"],
                }
                for change in self._package_changes()
            ],
        }

    def _package_changes(self) -> list[dict]:
        """Return applied package changes whose product guarantees need checks."""
        return [
            change
            for change in self.state.changes
            if change.get("package_update") and change.get("status") == "APPLIED"
        ]

    def _package_policy(self, plan: dict, review: dict) -> dict:
        """Enforce configured/existing policy, otherwise require license review."""
        if self._package_policy_required or self.package_policy_path.exists():
            return load_policy(self.repo_root, self.package_policy_path, plan)
        return reviewed_license_policy(self.repo_root, plan, review)

    def _refresh_package_validation(self) -> None:
        """Invalidate green evidence when the checkout or approval policy moves."""
        snapshot = None
        snapshot_checked = False
        for change in self._package_changes():
            if change.get("qualification_status") != "VALIDATED":
                continue
            receipt = (self._finding(change["finding_id"]) or {}).get(
                "packageQualification"
            ) or {}
            try:
                if not snapshot_checked:
                    snapshot_checked = True
                    snapshot = tree_snapshot(self.repo_root)
                policy = self._package_policy(
                    receipt.get("plan") or {}, receipt.get("review") or {}
                )
                valid = (
                    snapshot is not None
                    and receipt.get("check_contract") == "lint-build-unit-no-code-v1"
                    and receipt.get("validated_tree") == snapshot
                    and receipt.get("policy_sha256") == policy["policy_sha256"]
                )
            except (
                OSError,
                ValueError,
                TypeError,
                AttributeError,
                RuntimeError,
                KeyError,
            ):
                valid = False
            if not valid:
                change["qualification_status"] = receipt["status"] = (
                    "PENDING_VALIDATION"
                )
                change["detail"] = (
                    "Checkout or approval changed after validation; rerun/review required"
                )
                self.state.validation_status = "VALIDATION_INCOMPLETE"
                self.state.status = "VALIDATION_INCOMPLETE"

    def _decide(
        self, finding: dict
    ) -> tuple[str, str, list[str], dict | None, str | None]:
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
            evidence.append(
                "GitLab marked falsePositive=true. That flag alone is not sufficient; local evidence is required."
            )
        location_file = (finding.get("location") or {}).get("file")
        if location_file and category in {"sast", "secret_detection"}:
            resolved = resolve_inside(self.repo_root, location_file)
            if resolved is None:
                reason = f"{location_file} is outside the repository, so it was not treated as a false positive."
                evidence.append(reason)
                return (
                    "MANUAL_REVIEW",
                    reason,
                    evidence,
                    None,
                    self._prompt(finding, None, reason),
                )
            if not resolved.is_file():
                evidence.append(f"{location_file} is not in the working tree.")
                return (
                    "FALSE_POSITIVE",
                    f"{location_file} is not present in the repository.",
                    evidence,
                    None,
                    None,
                )

        if category in {"secret_detection", "dast"}:
            reason = "Secret and DAST findings are not safe to rewrite automatically. Rotate the credential or fix the request with a reviewer."
            return (
                "MANUAL_REVIEW",
                reason,
                evidence,
                None,
                self._prompt(finding, None, reason),
            )

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
            evidence.append(
                "Manifest search hit the file cap, so absence is not evidence of a false positive."
            )
        elif (
            category == "dependency_scanning"
            and component
            and manifests_were_parsed(self.repo_root, files)
        ):
            if any(
                path.suffix.lower() in {".csproj", ".fsproj", ".vbproj"}
                or path.name
                in {
                    "pom.xml",
                    "build.gradle",
                    "build.gradle.kts",
                    "libs.versions.toml",
                    "Directory.Packages.props",
                }
                for path in files
            ):
                reason = "The package was not resolved locally. Java and NuGet manifests do not enumerate every transitive dependency; manual dependency-tree review is required."
                return (
                    "MANUAL_REVIEW",
                    reason,
                    [*evidence, reason],
                    None,
                    self._prompt(finding, None, reason),
                )
            evidence.append(
                f"{component} was not found in the parsed manifests or lockfiles."
            )
            return (
                "FALSE_POSITIVE",
                f"{component} is not present in the parsed dependency files.",
                evidence,
                None,
                None,
            )

        installed = (hit.version if hit else None) or finding.get("installedVersion")
        ecosystem = hit.ecosystem if hit else None
        package_name = hit.name if hit else component
        looked_up = self.advisory.lookup(
            finding,
            ecosystem or (hit.manager if hit else None),
            package_name,
            installed,
        )
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
            return (
                "MANUAL_REVIEW",
                reason,
                evidence,
                None,
                self._prompt(finding, looked_up, reason),
            )
        if looked_up.affected is False:
            return "FALSE_POSITIVE", looked_up.summary, evidence, None, None
        if (
            looked_up.outcome == "no_fix_published"
            or not looked_up.lowest_fixed_version
        ):
            reason = (
                looked_up.summary
                if looked_up.outcome == "no_fix_published"
                else "No fixed version is newer than the installed version."
            )
            if looked_up.affected is None and looked_up.fixed_versions:
                reason = "Online records were found, but the installed version could not be compared to the affected range."
                return (
                    "MANUAL_REVIEW",
                    reason,
                    evidence,
                    None,
                    self._prompt(finding, looked_up, reason),
                )
            return "NO_SAFE_FIX", reason, evidence, None, None
        if looked_up.affected is None:
            reason = "Online records were found, but the installed version could not be compared to the affected range."
            return (
                "MANUAL_REVIEW",
                reason,
                evidence,
                None,
                self._prompt(finding, looked_up, reason),
            )

        image_only = category == "container_scanning" and hit is None
        fixed = looked_up.lowest_fixed_version
        plan, plan_reason = plan_remediation(
            self.repo_root, finding, None if image_only else hit, fixed, files
        )
        if plan is None and category == "container_scanning":
            plan, plan_reason = plan_remediation(
                self.repo_root, finding, None, fixed, files
            )
        if plan is None and "already at or above" in plan_reason:
            return "FALSE_POSITIVE", plan_reason, evidence, None, None
        if plan is None:
            if category == "sast":
                reason = (
                    "SAST findings do not get a guessed source edit. " + plan_reason
                )
                return (
                    "MANUAL_REVIEW",
                    reason,
                    evidence,
                    None,
                    self._prompt(finding, looked_up, reason),
                )
            return "NO_SAFE_FIX", plan_reason, evidence, None, None
        evidence.append(f"Minimal fix score {plan.score}: {plan.description}")
        major_upgrade = is_major_upgrade(plan.installed or installed, plan.target)
        if major_upgrade and plan.ecosystem not in PACKAGE_ECOSYSTEMS:
            reason = (
                f"The lowest fixed version {plan.target} is a major upgrade from {plan.installed or installed}. "
                "That can break callers, so it was not applied automatically."
            )
            return (
                "MANUAL_REVIEW",
                reason,
                evidence,
                None,
                self._prompt(finding, looked_up, reason),
            )
        if parse_version(installed) is None and plan.strategy != "image_tag":
            reason = "The installed version could not be parsed, so the fix was not applied automatically."
            return (
                "MANUAL_REVIEW",
                reason,
                evidence,
                None,
                self._prompt(finding, looked_up, reason),
            )
        if plan.ecosystem in PACKAGE_ECOSYSTEMS:
            evidence.append(
                "Candidate only: version numbering does not establish framework/API compatibility or license suitability. qualify_package_update requires documented license review or a configured corporate policy, and passing before/after checks."
            )
            if major_upgrade:
                evidence.append(
                    "Major-version candidate: review target APIs and actual callers before deciding compatibility. No source/test adjustments are permitted for an automatic major update."
                )
        proposed = plan.as_dict()
        if major_upgrade and plan.ecosystem in PACKAGE_ECOSYSTEMS:
            proposed["major_upgrade"] = True
            proposed["caller_scan"] = scan_package_callers(self.repo_root, proposed)
        return "CHANGE_REQUIRED", plan.description, evidence, proposed, None

    def _prompt(
        self, finding: dict, looked_up: AdvisoryLookup | None, reason: str
    ) -> str:
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
        return next(
            (item for item in self.state.findings if item.get("id") == finding_id), None
        )

    def _stop(self, status: str, stage: str, payload: dict) -> dict:
        """Record and persist the failed phase before returning its details."""
        self.state.status = status
        self.state.stop_stage = stage
        self._remember()
        return payload
