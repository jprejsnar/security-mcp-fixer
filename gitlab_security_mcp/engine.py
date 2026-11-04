"""Phase machine for one local remediation run."""

from __future__ import annotations

import functools
import json
import logging
import os
import shutil
import threading
from collections.abc import Callable
from copy import deepcopy
from dataclasses import fields
from datetime import date
from inspect import signature
from pathlib import Path
from time import monotonic
from urllib.parse import urlsplit

from gitlab_security_mcp.aaa import generate_aaa_test
from gitlab_security_mcp.advisory import (
    PACKAGE_MISMATCH,
    AdvisoryClient,
    AdvisoryLookup,
)
from gitlab_security_mcp.commands import CommandRunner, progress_sink, resolve_tool
from gitlab_security_mcp.config_findings import assess_config, config_kind
from gitlab_security_mcp.git_ops import GitOps, branch_name_for
from gitlab_security_mcp.gitlab_client import GitLabClient
from gitlab_security_mcp.manifests import (
    detect_stack,
    iter_files,
    locate_package,
    manifests_were_parsed,
)
from gitlab_security_mcp.official_docs import OfficialDocs
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
from gitlab_security_mcp.util import atomic_write_text, resolve_inside
from gitlab_security_mcp.validate import lint_rule_inventory, run_validation
from gitlab_security_mcp.versions import (
    is_major_upgrade,
    lowest_fixed,
    parse_fixed_versions,
    parse_version,
)

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
    parameters = signature(method)

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        """Reject calls after close and detach results while holding the lock."""
        with self._lock:
            if self._closed:
                return {"status": "ERROR", "reason": "Engine is closed"}
            finding_id = parameters.bind(self, *args, **kwargs).arguments.get(
                "finding_id"
            )
            started = monotonic()
            self._progress(finding_id, f"{method.__name__} started")
            try:
                result = method(self, *args, **kwargs)
            except BaseException as exc:
                self._progress(
                    finding_id, f"{method.__name__} failed ({type(exc).__name__})"
                )
                raise
            result = deepcopy(result)
            outcome = result.get("decision") or result.get("status") or "complete"
            self._progress(
                finding_id,
                f"{method.__name__} finished: {outcome} ({monotonic() - started:.2f}s)",
            )
            return result

    return wrapper


class _ValidationRunner:
    """Share exact command evidence across detected checks and corporate policy."""

    def __init__(self, runner, root: Path):
        """Limit cached results to one validation of one checkout state."""
        self.runner = runner
        self.root = root
        self.results = {}

    def run(self, argv, **kwargs):
        """Execute each exact command once per working directory."""
        key = (tuple(argv), Path(kwargs.get("cwd", self.root)).resolve())
        if key not in self.results:
            self.results[key] = self.runner.run(argv, **kwargs)
        return self.results[key]


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
        docs: OfficialDocs | None = None,
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
        self.http_log_path = self.repo_root / ".security-mcp" / "http-timings.jsonl"
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
        self._owns_docs = docs is None
        self.gitlab = (
            gitlab
            if gitlab is not None
            else GitLabClient(
                gitlab_token, gitlab_api_url, http_log_path=self.http_log_path
            )
        )
        try:
            self.advisory = (
                advisory
                if advisory is not None
                else AdvisoryClient(
                    github_token=github_token,
                    nvd_api_key=nvd_api_key,
                    http_log_path=self.http_log_path,
                )
            )
            # The documentation client opens only when an edit needs it, so
            # a run that never writes does not keep an unused connection.
            self.docs = docs
        except BaseException:
            if self._owns_gitlab:
                try:
                    self.gitlab.close()
                except Exception:
                    logger.exception(
                        "Could not close GitLab client after initialization failure"
                    )
            if self._owns_advisory and hasattr(self, "advisory"):
                try:
                    self.advisory.close()
                except Exception:
                    logger.exception(
                        "Could not close advisory client after initialization failure"
                    )
            raise
        self.which = which if which is not None else shutil.which
        self.today = today or date.today()
        self.project_id = project_id
        self.validation_timeout = validation_timeout
        self.state = RunState()
        self._files: list[Path] | None = None
        self._files_truncated = False
        self._product_baseline: dict | None = None
        self._closed = False

    def _documentation(self) -> OfficialDocs:
        """Return the injected documentation client or open one on first use."""
        if self.docs is None:
            self.docs = OfficialDocs(http_log_path=self.http_log_path)
        return self.docs

    def close(self) -> None:
        """Wait for active tools and close each owned HTTP client once.

        Injected clients stay open. Cleanup failures propagate after every
        owned client is attempted; later tool calls return an error.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                if self._owns_gitlab:
                    self.gitlab.close()
            finally:
                try:
                    if self._owns_advisory:
                        self.advisory.close()
                finally:
                    if self._owns_docs and self.docs is not None:
                        self.docs.close()

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
        """Fast-forward main twice, then clean/install pnpm before security checks."""
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
        self.state.pulls = results
        self._drop_snapshot()
        try:
            preparation = self._prepare_pnpm()
        except (OSError, ValueError, RuntimeError) as exc:
            self._drop_snapshot()
            return self._stop(
                "PREPARATION_FAILED",
                "pnpm_preparation",
                {
                    "status": "PREPARATION_FAILED",
                    "reason": str(exc),
                    "results": results,
                },
            )
        self._drop_snapshot()
        if preparation and preparation[-1]["exit_code"] != 0:
            return self._stop(
                "PREPARATION_FAILED",
                "pnpm_preparation",
                {
                    "status": "PREPARATION_FAILED",
                    "reason": "pnpm preparation failed; security checks were not started.",
                    "failed_command": preparation[-1]["argv"],
                    "results": results,
                    "preparation": preparation,
                },
            )
        self.state.status = "PULLS_SUCCEEDED"
        self._remember()
        return {
            "status": "PULLS_SUCCEEDED",
            "results": results,
            "preparation": preparation,
        }

    def _prepare_pnpm(self) -> list[dict]:
        """Clean then install each pnpm project, once per workspace root."""
        files, truncated = self._snapshot()
        if truncated:
            raise RuntimeError(
                "Cannot prepare pnpm projects: checkout file discovery was truncated"
            )
        roots = sorted({path.parent for path in files if path.name == "package.json"})
        pnpm_roots = [
            root
            for root in roots
            if detect_stack(
                root, [path for path in files if path.parent == root]
            ).node_manager
            == "pnpm"
            or (root / "pnpm-workspace.yaml").is_file()
        ]
        results = []
        for root in pnpm_roots:
            if any(
                parent in pnpm_roots and (parent / "pnpm-workspace.yaml").is_file()
                for parent in root.parents
            ):
                continue
            tool = resolve_tool("pnpm", self.which)
            if not tool:
                raise RuntimeError(
                    "pnpm is required for post-pull clean/install but is not on PATH"
                )
            for step in ("clean", "install"):
                self._progress(
                    None, f"Post-pull pnpm {step} in {root.relative_to(self.repo_root)}"
                )
                result = self.runner.run(
                    [tool, step], timeout=self.validation_timeout, check=False, cwd=root
                )
                results.append(
                    {
                        "argv": list(result.argv),
                        "cwd": str(root),
                        "exit_code": result.exit_code,
                        "stdout": result.stdout[-500:],
                        "stderr": result.stderr[-500:],
                        "stdout_log_path": result.stdout_log_path,
                        "stderr_log_path": result.stderr_log_path,
                    }
                )
                if result.exit_code != 0:
                    return results
        return results

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
            self._progress(finding_id, "Assessing scanner category and local evidence")
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
            "security_validation_sites": list(
                finding.get("securityValidationSites") or []
            ),
            "eligible_for_auto_fix": decision == "CHANGE_REQUIRED"
            and not (proposed and proposed.get("ecosystem") in PACKAGE_ECOSYSTEMS),
            "qualification_required": bool(
                proposed and proposed.get("ecosystem") in PACKAGE_ECOSYSTEMS
            ),
            "proposed_fix": proposed,
            "user_prompt": prompt,
            "fuzzing_workflow": finding.get("fuzzingWorkflow"),
        }

    @_serialized
    def qualify_package_update(self, finding_id: str, review: dict) -> dict:
        """Require reviewed APIs/license terms; defer product checks to the batch.

        The hosting AI supplies its complete official-documentation review
        without production or unit-test adaptations. Configured/existing corporate
        policies remain mandatory; otherwise documented license review is
        used without inventing corporate approval. Requalify after changes.
        """
        if self.state.manual_cleanup_required:
            return {
                "status": "MANUAL_REVIEW_REQUIRED",
                "reason": "Restore or review preserved edits, then run validation before continuing",
            }
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
        try:
            if not isinstance(review, dict) or any(
                review.get(key) != plan.get(key)
                for key in ("ecosystem", "package", "target")
            ):
                raise ValueError(
                    "Documentation review must identify the exact ecosystem, package, and target"
                )
            self._progress(
                finding_id, "Reviewing exact-target APIs, callers, and license policy"
            )
            source_before = review_package(self.repo_root, review)
            major_review = review_major_upgrade(self.repo_root, plan, review)
            policy = self._package_policy(plan, review)
            tree = tree_snapshot(self.repo_root)
            scripts = package_script_hashes(self.repo_root, tree)
            lint_recorded = self.state.lint_baseline is not None
            if not lint_recorded:
                self._progress(
                    finding_id,
                    "Recording informational lint only; build and all unit tests run after the complete batch",
                )
                baseline = run_validation(
                    self.repo_root,
                    self.runner,
                    self.which,
                    timeout=self.validation_timeout,
                    package_checks=True,
                    record_lint=True,
                    lint_only=True,
                )
                self._capture_lint_baseline(finding_id, baseline["results"])
            self._progress(
                finding_id,
                "Configured product checks are deferred to final batch validation",
            )
            if major_review is not None:
                major_review = review_major_upgrade(self.repo_root, plan, review)
            validate_edits(
                self.repo_root,
                {"tree": tree, "source_before": {}, "package_script_hashes": scripts},
                [],
            )
            receipt = {
                "check_contract": "lint-baseline-build-unit-no-code-v2",
                "status": "QUALIFIED",
                "plan": deepcopy(plan),
                "review": deepcopy(review),
                "major_review": major_review,
                **policy,
                "source_before": source_before,
                "tree": tree,
                "package_script_hashes": scripts,
                "baseline_results": baseline["results"],
            }
        except (OSError, ValueError, TypeError, AttributeError, RuntimeError) as exc:
            finding["packageQualification"] = {
                "status": "BLOCKED",
                "reason": str(exc),
                "baseline_results": baseline["results"],
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
                "baseline_results": baseline["results"],
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
            "lint_issues_path": str(
                self.repo_root / ".security-mcp" / "lint-issues.json"
            ),
            "lint_rules_path": str(
                self.repo_root / ".security-mcp" / "lint-rules.json"
            ),
            "note": "Apply all reviewed package updates, then run one final production build and all unit tests. Existing lint issues are informational. Failed batches require isolation and guarded rollback.",
        }

    @_serialized
    def apply_minimal_fix(self, finding_id: str) -> dict:
        """Apply a verified plan only after package qualification passes."""
        if self.state.manual_cleanup_required:
            return {
                "status": "MANUAL_REVIEW_REQUIRED",
                "reason": "Manual cleanup and validation are required before another edit",
            }
        finding = self._finding(finding_id)
        if finding is None:
            return {"status": "ERROR", "reason": "Finding not found"}
        if finding.get("category") in {"api_fuzzing", "coverage_fuzzing"}:
            return {
                "status": "REPRODUCTION_REQUIRED",
                "finding_id": finding_id,
                "reason": "Fuzzing requires reviewed local reproduction and host-applied source fixes, not an automatic package edit.",
                "fuzzing_workflow": finding.get("fuzzingWorkflow"),
            }
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
        if any(
            change.get("validation_pending") and not change.get("package_update")
            for change in self.state.changes
            if change.get("status") == "APPLIED"
        ):
            return {
                "status": "VALIDATION_REQUIRED",
                "reason": "Validate the single pending security fix before applying another",
                "finding_id": finding_id,
            }
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
            receipt = finding.get("packageQualification") or {}
            try:
                if (
                    receipt.get("status") != "QUALIFIED"
                    or receipt.get("plan") != proposed
                    or receipt.get("check_contract")
                    != "lint-baseline-build-unit-no-code-v2"
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
        self._progress(
            finding_id, "Reading required official documentation before editing"
        )
        if self.state.lint_baseline is None:
            files, _truncated = self._snapshot()
            stack = detect_stack(self.repo_root, files)
            applicable = bool(stack.node or stack.dotnet or stack.java)
            baseline = (
                run_validation(
                    self.repo_root,
                    self.runner,
                    self.which,
                    timeout=self.validation_timeout,
                    package_checks=True,
                    record_lint=True,
                    lint_only=True,
                )
                if applicable
                else {"status": "VALIDATION_COMPLETE", "results": []}
            )
            self._capture_lint_baseline(
                finding_id, baseline["results"], applicable=applicable
            )
        atomic_write_text(
            self.repo_root / ".security-mcp" / "lint-issues.json",
            json.dumps(self.state.lint_baseline, indent=2),
        )
        atomic_write_text(
            self.repo_root / ".security-mcp" / "lint-rules.json",
            json.dumps(
                lint_rule_inventory(self.state.lint_baseline["results"]), indent=2
            ),
        )
        review = self._documentation().read_before_fix(
            finding, proposed.get("doc_pages") or []
        )
        self._record_validation_sites(
            finding, [item["url"] for item in review.as_list()]
        )
        if not review.complete or (
            proposed.get("strategy") == "config_line" and not proposed.get("doc_pages")
        ):
            return {
                "status": "DOCS_REQUIRED",
                "finding_id": finding_id,
                "reason": review.reason(),
                "documentation": review.as_list(),
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
            line=proposed.get("line"),
            expected_line=proposed.get("expected_line"),
            replacement_line=proposed.get("replacement_line"),
            doc_pages=tuple(proposed.get("doc_pages") or ()),
        )
        self._progress(
            finding_id,
            "Applying reviewed dependency/configuration edit and lockfile refresh",
        )
        if not package_update:
            finding["localFixAttempt"] = {
                "tree": tree_snapshot(self.repo_root),
                "dependency_before": backup_dependency_files(self.repo_root, proposed),
            }
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
            "documentation": review.as_list(),
            "package_update": package_update,
            "ecosystem": plan.ecosystem,
            "package": plan.package,
            "target": plan.target,
            "qualification_status": "PENDING_VALIDATION" if package_update else None,
            "validation_pending": outcome["status"] == "APPLIED",
        }
        if not package_update:
            finding["localFixAttempt"]["applied_dependency_hashes"] = (
                dependency_file_hashes(
                    self.repo_root, finding["localFixAttempt"]["dependency_before"]
                )
            )
        self.state.changes.append(change)
        self._drop_snapshot()
        if outcome["status"] == "APPLIED":
            self.state.status = "FIXES_IN_PROGRESS"
            self.state.validation_status = None
            if package_update:
                finding["packageQualification"]["status"] = "PENDING_VALIDATION"
        elif outcome["status"] in {"FIX_FAILED", "FIX_FAILED_LOCKFILE"}:
            attempt = receipt if package_update else finding["localFixAttempt"]
            rollback = rollback_dependency_files(self.repo_root, attempt)
            change["rollback"] = rollback
            safe = (
                rollback["status"] == "ROLLED_BACK"
                and tree_snapshot(self.repo_root) == attempt["tree"]
            )
            outcome["continue_with_next_finding"] = safe
            self.state.manual_cleanup_required = not safe
            self._product_baseline = None
            if package_update:
                receipt["status"] = change["qualification_status"] = "REJECTED"
            change["detail"] = (
                (outcome.get("detail") or "The planned fix could not be applied.")
                + " "
                + rollback["detail"]
            )
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
            "continue_with_next_finding": outcome.get("continue_with_next_finding"),
            "note": "Initial lint issues are recorded separately. Not accepted until production builds, all unit tests, and configured policy checks pass. Production/unit-test code and check scripts must remain unchanged.",
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
        """Validate the batch once; isolate failed updates only after a failure."""
        self._refresh_package_validation()
        pending = [
            change
            for change in self._package_changes()
            if change.get("qualification_status") != "VALIDATED"
        ]
        if (
            not pending
            and self._product_baseline is not None
            and not any(
                change.get("validation_pending")
                for change in self.state.changes
                if change.get("status") == "APPLIED"
            )
            and self._product_baseline["tree"] == tree_snapshot(self.repo_root)
        ):
            return {**deepcopy(self._product_baseline["validation"]), "cached": True}
        outcome = self._validate_current_batch()
        if outcome["status"] == "VALIDATION_COMPLETE":
            self._product_baseline = {
                "tree": tree_snapshot(self.repo_root),
                "validation": deepcopy(outcome),
            }
            return outcome
        if not pending:
            return outcome
        try:
            return self._isolate_package_batch(pending, outcome)
        except (OSError, ValueError, RuntimeError, TypeError) as exc:
            self.state.manual_cleanup_required = True
            self.state.status = self.state.validation_status = "VALIDATION_FAILED"
            self.state.stop_stage = "batch_isolation"
            for change in pending:
                change["qualification_status"] = "REJECTED"
                self._finding(change["finding_id"])["packageQualification"].update(
                    status="REJECTED", reason=str(exc)
                )
            outcome.update(
                status="VALIDATION_FAILED",
                reason="Package updates are not accepted: " + str(exc),
                continue_with_next_finding=False,
                rollbacks=[
                    {"finding_id": change["finding_id"], **change["rollback"]}
                    for change in pending
                    if change.get("rollback")
                ],
            )
            self._remember()
            return outcome

    def _isolate_package_batch(self, changes: list[dict], initial: dict) -> dict:
        """Split failed groups, retain passing combinations, and guard every restore."""
        templates = {
            change["finding_id"]: deepcopy(
                self._finding(change["finding_id"])["packageQualification"]
            )
            for change in changes
        }
        by_id = {change["finding_id"]: change for change in changes}
        identifiers = list(by_id)
        baseline_tree = templates[identifiers[0]]["tree"]
        originals = {}
        expected = {}
        for receipt in templates.values():
            for path, text in receipt["dependency_before"].items():
                originals.setdefault(path, text)
            expected.update(receipt["applied_dependency_hashes"])
        active = tuple(identifiers)
        cache = {active: deepcopy(initial)}
        trials = []
        self.state.batch_isolation = trials
        rejected = {}

        def record(selected: tuple[str, ...], result: dict) -> None:
            """Retain failed commands and log paths without losing final green evidence."""
            trials.append(
                {
                    "finding_ids": list(selected),
                    "status": result["status"],
                    "failures": [
                        deepcopy(row)
                        for row in result.get("results", [])
                        if row.get("required") and row["status"] != "PASSED"
                    ],
                }
            )

        record(active, initial)

        def activate(selected: tuple[str, ...]) -> None:
            """Restore the baseline, then replay only previously reviewed dependency plans."""
            nonlocal expected, active
            for receipt in templates.values():
                policy = self._package_policy(receipt["plan"], receipt["review"])
                if policy["policy_sha256"] != receipt["policy_sha256"]:
                    raise ValueError(
                        "Qualification policy changed; isolation requires a fresh review"
                    )
            rollback = rollback_dependency_files(
                self.repo_root,
                {"dependency_before": originals, "applied_dependency_hashes": expected},
            )
            for change in changes:
                change["rollback"] = deepcopy(rollback)
                if rollback["status"] == "ROLLED_BACK":
                    change.update(status="ROLLED_BACK", validation_pending=False)
            if (
                rollback["status"] != "ROLLED_BACK"
                or tree_snapshot(self.repo_root) != baseline_tree
            ):
                raise ValueError(
                    "Batch isolation stopped: later edits were preserved; manual cleanup is required. "
                    + rollback["detail"]
                )
            for finding_id, change in by_id.items():
                receipt = deepcopy(templates[finding_id])
                receipt.pop("validated_tree", None)
                receipt["status"] = "REJECTED"
                self._finding(finding_id)["packageQualification"] = receipt
                change.update(
                    status="ROLLED_BACK",
                    qualification_status="REJECTED",
                    validation_pending=False,
                )
            expected = dependency_file_hashes(self.repo_root, originals)
            active = ()
            for finding_id in selected:
                receipt = self._finding(finding_id)["packageQualification"]
                proposed = receipt["plan"]
                review = self._documentation().read_before_fix(
                    self._finding(finding_id), proposed.get("doc_pages") or []
                )
                if not review.complete:
                    raise ValueError(review.reason())
                receipt["tree"] = tree_snapshot(self.repo_root)
                receipt["dependency_before"] = backup_dependency_files(
                    self.repo_root, proposed
                )
                plan = Plan(
                    **{
                        item.name: proposed[item.name]
                        for item in fields(Plan)
                        if item.name in proposed
                    }
                )
                outcome = apply_plan(self.repo_root, plan, self.runner, self.which)
                expected = dependency_file_hashes(self.repo_root, originals)
                receipt["applied_dependency_hashes"] = dependency_file_hashes(
                    self.repo_root, receipt["dependency_before"]
                )
                if outcome["status"] != "APPLIED":
                    raise ValueError(
                        "Reviewed subset could not be reapplied: "
                        + str(outcome.get("detail") or outcome["status"])
                    )
                receipt["status"] = "PENDING_VALIDATION"
                by_id[finding_id].update(
                    status="APPLIED",
                    qualification_status="PENDING_VALIDATION",
                    validation_pending=True,
                )
            active = selected
            self._drop_snapshot()

        def trial(selected: tuple[str, ...], *, force: bool = False) -> dict:
            """Avoid duplicate diagnostic selections; always validate the final active tree."""
            if not force and selected in cache:
                return cache[selected]
            self._progress(
                None,
                "Diagnosing failed batch: testing subset "
                + ", ".join(selected or ("original baseline",)),
            )
            activate(selected)
            result = self._validate_current_batch(
                require_package_checks=True,
                baseline_policies=list(templates.values()) if not selected else None,
            )
            cache[selected] = deepcopy(result)
            record(selected, result)
            return result

        accepted = []

        def retain(group: list[str]) -> None:
            """Try a whole group before splitting so one offender costs logarithmic probes."""
            selected = tuple(accepted + group)
            result = trial(selected)
            if result["status"] == "VALIDATION_COMPLETE":
                accepted.extend(group)
            elif len(group) > 1:
                middle = len(group) // 2
                retain(group[:middle])
                retain(group[middle:])
            else:
                rejected[group[0]] = (
                    "Rejected after build/test or policy failure with retained updates "
                    + repr(accepted)
                    + ": "
                    + "; ".join(
                        str(row.get("detail") or row.get("command"))
                        for row in result.get("results", [])
                        if row.get("required") and row["status"] != "PASSED"
                    )
                )

        retain(identifiers)
        selected = tuple(accepted)
        final = trial(
            selected,
            force=active != selected
            or cache.get(selected, {}).get("status") != "VALIDATION_COMPLETE",
        )
        for finding_id, reason in rejected.items():
            change = by_id[finding_id]
            change.update(
                status="ROLLED_BACK",
                qualification_status="REJECTED",
                validation_pending=False,
                detail="Package update rejected: " + reason,
            )
            receipt = self._finding(finding_id)["packageQualification"]
            receipt.update(
                status="REJECTED",
                reason=reason,
                rollback=deepcopy(change.get("rollback")),
            )
        self.state.batch_isolation = trials
        final.update(
            isolation_trials=trials,
            retained_updates=accepted,
            rejected_updates=[
                {"finding_id": finding_id, "reason": reason}
                for finding_id, reason in rejected.items()
            ],
            rollbacks=[
                {"finding_id": finding_id, **by_id[finding_id]["rollback"]}
                for finding_id in rejected
                if by_id[finding_id].get("rollback")
            ],
        )
        if final["status"] == "VALIDATION_COMPLETE":
            self.state.manual_cleanup_required = False
            self._product_baseline = {
                "tree": tree_snapshot(self.repo_root),
                "validation": deepcopy(final),
            }
            if not accepted:
                final.update(
                    status="FIX_REJECTED",
                    continue_with_next_finding=True,
                    reason="All candidates rejected; the restored baseline build and all unit tests passed.",
                )
                self.state.status = "FIXES_IN_PROGRESS"
        else:
            final.update(
                reason="The restored subset or original baseline still fails; no green checkout is claimed.",
                continue_with_next_finding=False,
            )
            self.state.manual_cleanup_required = True
        self._remember()
        return final

    def _validate_current_batch(
        self,
        *,
        require_package_checks: bool = False,
        baseline_policies: list[dict] | None = None,
    ) -> dict:
        """Run the detected stack's checks. A missing branch blocks this."""
        if self.state.status not in AFTER_BRANCH:
            return {
                "status": "ERROR",
                "reason": "Create the security branch before validation.",
            }
        package_changes = self._package_changes()
        local_changes = [
            change
            for change in self.state.changes
            if change.get("status") == "APPLIED"
            and change.get("validation_pending")
            and not change.get("package_update")
        ]
        pending = [
            change
            for change in package_changes
            if change.get("qualification_status") != "VALIDATED"
        ]
        accepted_before = {
            change["finding_id"]: (
                deepcopy(change),
                deepcopy(self._finding(change["finding_id"])["packageQualification"]),
            )
            for change in package_changes
            if change not in pending
        }
        for change in package_changes:
            self._progress(
                change["finding_id"], "Running post-update build and all unit tests"
            )
        validation_runner = _ValidationRunner(self.runner, self.repo_root)
        outcome = run_validation(
            self.repo_root,
            validation_runner,
            self.which,
            timeout=self.validation_timeout,
            package_checks=bool(package_changes) or require_package_checks,
            skip_lint=True,
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
        for receipt in baseline_policies or []:
            checks = run_checks(
                self.repo_root,
                receipt["checks"],
                validation_runner,
                self.which,
                self.validation_timeout,
                plan=receipt["plan"],
            )
            outcome["results"].extend(checks)
            if any(row["status"] != "PASSED" for row in checks):
                outcome["status"] = "VALIDATION_FAILED"
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
                if (
                    receipt.get("check_contract")
                    != "lint-baseline-build-unit-no-code-v2"
                ):
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
                if outcome["status"] != "VALIDATION_COMPLETE":
                    raise ValueError(
                        "Product build/unit validation failed or is incomplete; candidate cannot be accepted"
                    )
                checks = run_checks(
                    self.repo_root,
                    policy["checks"],
                    validation_runner,
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
            change["validation_pending"] = status != "VALIDATED"
            self._progress(change["finding_id"], f"Post-update validation: {status}")
            if status == "VALIDATED":
                change["detail"] = (
                    "Accepted: no production/unit-test API changes; initial lint issues recorded separately; production build and all unit tests passed; configured policy checks passed"
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
        for change in local_changes:
            if outcome["status"] == "VALIDATION_COMPLETE":
                change["validation_pending"] = False
                continue
            attempt = self._finding(change["finding_id"])["localFixAttempt"]
            rollback = rollback_dependency_files(self.repo_root, attempt)
            change["rollback"] = rollback
            failures = [
                row
                for row in outcome["results"]
                if row.get("required") and row["status"] != "PASSED"
            ]
            change["detail"] = (
                "Security fix rejected: "
                + "; ".join(
                    str(row.get("detail") or row.get("command")) for row in failures
                )
                + " "
                + rollback["detail"]
            )
            safe = (
                rollback["status"] == "ROLLED_BACK"
                and tree_snapshot(self.repo_root) == attempt["tree"]
            )
            if rollback["status"] == "ROLLED_BACK":
                change["status"] = "ROLLED_BACK"
                change["validation_pending"] = False
            outcome["continue_with_next_finding"] = safe
            outcome.setdefault("rollbacks", []).append(
                {"finding_id": change["finding_id"], **rollback}
            )
            if safe:
                for package_change in package_changes:
                    if package_change["finding_id"] in accepted_before:
                        previous_change, previous_receipt = accepted_before[
                            package_change["finding_id"]
                        ]
                        package_change.clear()
                        package_change.update(previous_change)
                        self._finding(package_change["finding_id"])[
                            "packageQualification"
                        ] = previous_receipt
                self._refresh_package_validation()
                safe = all(
                    item.get("qualification_status") == "VALIDATED"
                    for item in self._package_changes()
                )
                outcome["continue_with_next_finding"] = safe
            if safe:
                outcome["status"] = "FIX_REJECTED"
        if outcome.get("continue_with_next_finding") is False:
            self.state.manual_cleanup_required = True
        elif outcome["status"] == "VALIDATION_COMPLETE":
            self.state.manual_cleanup_required = False
        self.state.validation_status = (
            "VALIDATION_FAILED"
            if outcome["status"] == "FIX_REJECTED"
            else outcome["status"]
        )
        if outcome["status"] == "FIX_REJECTED":
            self.state.status = "FIXES_IN_PROGRESS"
            self.state.stop_stage = None
        elif outcome["status"] == "VALIDATION_FAILED":
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
            "manual_cleanup_required": self.state.manual_cleanup_required,
            "branch": self.state.branch_name,
            "findings_count": len(self.state.findings),
            "changes_count": len(self.state.changes),
            "false_positives_count": len(self.state.false_positives),
            "no_solution_count": len(self.state.no_solution),
            "skipped_user_prompt_count": len(self.state.skipped_user_prompt),
            "report_path": self.state.report_path,
            "lint_issues_path": str(
                self.repo_root / ".security-mcp" / "lint-issues.json"
            )
            if self.state.lint_baseline is not None
            else None,
            "lint_rules_path": str(self.repo_root / ".security-mcp" / "lint-rules.json")
            if self.state.lint_baseline is not None
            else None,
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

    def _capture_lint_baseline(
        self, finding_id: str | None, results: list[dict], *, applicable: bool = True
    ) -> None:
        """Publish best-effort pre-change lint evidence without gating security fixes."""
        rows = [deepcopy(row) for row in results if row.get("kind") == "lint"]
        baseline = {
            "schema_version": 1,
            "phase": "before_changes",
            "tree": tree_snapshot(self.repo_root),
            "finding_id": finding_id,
            "complete": not applicable
            or (bool(rows) and all(row.get("output_complete") for row in rows)),
            "applicable": applicable,
            "results": rows,
        }
        atomic_write_text(
            self.repo_root / ".security-mcp" / "lint-issues.json",
            json.dumps(baseline, indent=2),
        )
        atomic_write_text(
            self.repo_root / ".security-mcp" / "lint-rules.json",
            json.dumps(lint_rule_inventory(rows), indent=2),
        )
        self.state.lint_baseline = baseline

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
        if any(
            change.get("qualification_status") == "PENDING_VALIDATION"
            for change in self._package_changes()
        ) or any(
            change.get("validation_pending")
            for change in self.state.changes
            if change.get("status") == "APPLIED"
        ):
            return
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
                    and receipt.get("check_contract")
                    == "lint-baseline-build-unit-no-code-v2"
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
        if category in {"api_fuzzing", "coverage_fuzzing"}:
            reason = (
                "Fuzzing describes observed application behavior, not a package advisory. "
                "Reproduce the scanner case locally and review the responsible code; "
                "missing CVE or advisory records do not justify skipping or dismissing it. "
                "No application defect or safe source fix has been verified yet."
            )
            steps = [
                "Obtain the original scanner artifact: affected operation or fuzz target, "
                "mutator, original and mutated input, request/response or crash evidence, "
                "and the expected API or target contract. Keep credentials out of reports.",
                "Inspect the matching local handler, parser, validation and error handling. "
                "An API URL path is not a source-file path. Do not infer SQL injection or "
                "a false positive solely from a scanner title, status code or missing file.",
                "Use only an explicitly approved local test environment and synthetic data. "
                "Do not replay fuzz payloads against the reported remote hostname. "
                "Add a focused regression test that fails for the same security behavior "
                "before the fix; a setup failure does not count as reproduction.",
                "After reproduction and review, propose a minimal source fix tied to the "
                "documented input/response contract. Preserve valid requests, authentication "
                "and authorization; do not suppress the scanner or mask the defect.",
                "Apply reviewed source and regression-test edits through the host only in "
                "the approved checkout, separately from dependency updates. This server's "
                "apply_minimal_fix cannot apply arbitrary application-code patches.",
                "Rerun the identical reproduction and boundary/valid-input cases, lint, "
                "production build and executed unit tests. Retain before/after evidence. "
                "Keep the finding unresolved until those checks have passed; do not "
                "fabricate evidence, dismiss GitLab findings, commit or push.",
            ]
            finding["fuzzingWorkflow"] = {
                "status": "REPRODUCTION_REQUIRED",
                "category": category,
                "location": finding.get("location") or {},
                "scanner_evidence": finding.get("scannerEvidence"),
                "scanner_details": finding.get("scannerDetails") or [],
                "steps": steps,
                "source_edits_applied_by": "host_after_reproduction_and_review",
            }
            scanner = finding.get("scannerEvidence") or {}
            request = scanner.get("request") or {}
            response = scanner.get("response") or {}
            evidence.append(
                "GraphQL scanner evidence: "
                f"request body {'captured' if request.get('body') is not None else 'missing'}, "
                f"response body {'captured' if response.get('body') is not None else 'missing'}. "
                "Read scanner_evidence and scanner_details in fuzzing_workflow; "
                "HTTP errors or missing evidence alone do not prove a real defect or a false positive."
            )
            evidence.append(reason)
            prompt = (
                f"Finding {finding.get('id')} requires local fuzzing reproduction. "
                + " ".join(steps)
            )
            return "REPRODUCTION_REQUIRED", reason, evidence, None, prompt
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
        kind = config_kind(location_file if isinstance(location_file, str) else None)
        if kind and category != "container_scanning":
            return self._decide_config(finding, evidence)
        if kind == "dockerfile":
            evidence.append(
                "Dockerfile container findings keep the image-tag plan. Writing it still requires a fresh read of the official documentation."
            )

        self._progress(
            finding.get("id"), "Inspecting local dependency manifests and lockfiles"
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
        self._progress(finding.get("id"), "Checking public advisory evidence")
        looked_up = self.advisory.lookup(
            finding,
            ecosystem or (hit.manager if hit else None),
            package_name,
            installed,
        )
        self._record_validation_sites(finding, looked_up.validation_sites)
        evidence.append(looked_up.summary or "No advisory summary.")
        if looked_up.ranges:
            finding["affectedRange"] = ", ".join(looked_up.ranges)
            evidence.append("Affected range: " + finding["affectedRange"])
        if looked_up.sources:
            evidence.append("Sources: " + ", ".join(looked_up.sources))
        if looked_up.errors:
            evidence.append("Lookup errors: " + "; ".join(looked_up.errors))

        if (
            category == "dependency_scanning"
            and hit is not None
            and component == hit.name
            and parse_version(installed) is not None
            and (
                not finding.get("installedVersion")
                or parse_version(finding["installedVersion"])
                == parse_version(installed)
            )
            and looked_up.affected is not False
            and (
                looked_up.outcome != "resolved"
                or looked_up.affected is None
                or not looked_up.lowest_fixed_version
            )
        ):
            gitlab_fixed = lowest_fixed(
                installed,
                finding.get("fixedVersions")
                or parse_fixed_versions(finding.get("solution")),
            )
            if gitlab_fixed:
                self._progress(
                    finding.get("id"),
                    f"Checking GitLab-recommended target {gitlab_fixed} against public advisories",
                )
                target_lookup = self.advisory.lookup(
                    finding, ecosystem or hit.manager, package_name, gitlab_fixed
                )
                self._record_validation_sites(finding, target_lookup.validation_sites)
                evidence.append(
                    f"GitLab recommends {package_name} {gitlab_fixed}; the finding matches "
                    f"the local dependency at {installed}. Target advisory check: "
                    + (target_lookup.summary or target_lookup.outcome)
                )
                if target_lookup.sources:
                    evidence.append(
                        "Target sources: " + ", ".join(target_lookup.sources)
                    )
                if target_lookup.errors:
                    evidence.append(
                        "Target lookup errors: " + "; ".join(target_lookup.errors)
                    )
                if target_lookup.affected is True:
                    reason = (
                        f"GitLab recommends {gitlab_fixed}, but public advisory evidence "
                        "marks that target as affected."
                    )
                    return (
                        "MANUAL_REVIEW",
                        reason,
                        evidence,
                        None,
                        self._prompt(finding, target_lookup, reason),
                    )
                looked_up = AdvisoryLookup(
                    outcome="resolved",
                    affected=True,
                    fixed_versions=[gitlab_fixed],
                    lowest_fixed_version=gitlab_fixed,
                    summary=f"Using GitLab's explicit fix {gitlab_fixed}; public advisory metadata is incomplete.",
                )
                evidence.append(looked_up.summary)

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
        self._progress(
            finding.get("id"), f"Planning minimal dependency change to {fixed}"
        )
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
                "Candidate only: version numbering does not establish framework/API compatibility or license suitability. qualify_package_update requires documented license review or a configured corporate policy. Apply all reviewed updates, then require a passing final build, all unit tests and configured checks."
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

    def _decide_config(
        self, finding: dict, evidence: list[str]
    ) -> tuple[str, str, list[str], dict | None, str | None]:
        """Decide a Dockerfile, nginx, or GitLab CI finding from its cited line.

        A matching directive is only proposed after the current publisher
        pages still document it. Other cited lines stay on manual review.
        """
        assessment = assess_config(self.repo_root, finding)
        evidence.append(assessment.reason)
        if assessment.decision == "missing":
            return "FALSE_POSITIVE", assessment.reason, evidence, None, None
        if assessment.decision != "plan" or assessment.plan is None:
            return (
                "MANUAL_REVIEW",
                assessment.reason,
                evidence,
                None,
                self._prompt(finding, None, assessment.reason),
            )
        proposed = assessment.plan.as_dict()
        review = self._documentation().read_before_fix(finding, proposed["doc_pages"])
        self._record_validation_sites(
            finding, [item["url"] for item in review.as_list()]
        )
        evidence.append(review.reason())
        evidence.extend(
            f"Read {item['name']} {item['url']}"
            + (f" sha256={item['sha256']}" if item.get("sha256") else "")
            for item in review.as_list()
        )
        if not review.complete:
            reason = review.reason()
            return (
                "MANUAL_REVIEW",
                reason,
                evidence,
                None,
                self._prompt(finding, None, reason),
            )
        evidence.append(
            f"Minimal fix score {assessment.plan.score}: {assessment.plan.description}"
        )
        return "CHANGE_REQUIRED", assessment.plan.description, evidence, proposed, None

    def _record_validation_sites(self, finding: dict, urls: list[str]) -> None:
        """Keep the distinct sites actually used to assess this finding."""
        sites = set(finding.get("securityValidationSites") or [])
        for url in urls:
            parsed = urlsplit(url)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                sites.add(f"{parsed.scheme}://{parsed.netloc}")
        finding["securityValidationSites"] = sorted(sites)

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

    def _progress(self, finding_id: str | None, step: str) -> None:
        """Emit bounded, single-line progress without scanner payloads or review contents."""
        finding = self._finding(finding_id) if finding_id else None
        label = " ".join(str(finding_id or "run").split())[:200]
        package = " ".join(str((finding or {}).get("component") or "N/A").split())[:200]
        repository = " ".join(str(self.repo_root).split())[:500]
        step = " ".join(step.split())[:500]
        logger.info(
            "Progress repo=%s finding=%s package=%s: %s",
            repository,
            label,
            package,
            step,
        )
        sink = progress_sink.get()
        if sink is not None:
            bar = "#" * 20 if " finished:" in step else "?" * 20
            try:
                sink(f"[{bar}] {package} / {label}: {step}")
            except Exception:
                logger.warning("Could not publish step progress", exc_info=True)

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
