"""Phase machine for one local remediation run."""

from __future__ import annotations

import functools
import json
import logging
import os
import re
import shutil
import threading
from collections.abc import Callable, Generator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import fields
from datetime import date
from inspect import signature
from pathlib import Path
from socket import SOCK_STREAM, gaierror, getaddrinfo
from subprocess import SubprocessError
from time import monotonic
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from gitlab_security_mcp.aaa import generate_aaa_test
from gitlab_security_mcp.advisory import (
    PACKAGE_MISMATCH,
    AdvisoryClient,
    AdvisoryLookup,
)
from gitlab_security_mcp.commands import (
    CommandRunner,
    progress_sink,
    resolve_tool,
    tool_name,
)
from gitlab_security_mcp.config_findings import assess_config, config_kind
from gitlab_security_mcp.fanout import MAX_WORKERS
from gitlab_security_mcp.git_ops import GitOps, branch_name_for
from gitlab_security_mcp.gitlab_client import GitLabClient, dismissal_is_confirmed
from gitlab_security_mcp.manifests import (
    GradleReport,
    PackageHit,
    detect_stack,
    gradle_report_package,
    iter_files,
    java_project_root,
    locate_package,
    manifests_were_parsed,
    parse_gradle_report,
)
from gitlab_security_mcp.official_docs import (
    DocReview,
    OfficialDocs,
    cited_security_pages_ok,
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
from gitlab_security_mcp.security_artifacts import review_security_artifacts
from gitlab_security_mcp.source_findings import (
    assess_source,
    audit_false_positive_comment,
    pending_source_reviews,
)
from gitlab_security_mcp.state import RunState
from gitlab_security_mcp.util import (
    atomic_write_text,
    log_task,
    logged_lock,
    resolve_inside,
    utc_now_iso,
)
from gitlab_security_mcp.validate import (
    java_wrapper,
    lint_rule_inventory,
    run_validation,
)
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

PROGRESS_SEVERITIES = {
    "critical": "criticals",
    "high": "highs",
    "medium": "mediums",
    "low": "lows",
    "info": "infos",
    "unknown": "unknown-severity findings",
}


def _progress_severity(finding: dict) -> str:
    """Group display counts without changing the scanner's severity."""
    severity = str(finding.get("severity") or "unknown").strip().lower()
    if severity == "informational":
        severity = "info"
    return severity if severity in PROGRESS_SEVERITIES else "unknown"


def _serialized(method):
    """Serialize mutations while allowing independent finding evidence reads.

    Verification reserves its finding until its detached assessment is committed.
    Other tools retain exclusive access, including re-entrant nested calls.
    """
    parameters = signature(method)

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        """Reject calls after close and return detached results."""
        finding_id = parameters.bind(self, *args, **kwargs).arguments.get("finding_id")
        with self._tool_access(
            finding_id, verification=method.__name__ == "verify_security_finding"
        ):
            if self._closed:
                return {"status": "ERROR", "reason": "Engine is closed"}
            started = monotonic()
            self._progress(finding_id, f"{method.__name__} started")
            try:
                with log_task(method.__name__):
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
        if (
            key not in self.results
            and tool_name(argv[0]) in {"gradle", "gradlew"}
            and argv[1:]
            in (
                ["--no-daemon", "assemble"],
                ["--no-daemon", "test", "--rerun-tasks"],
            )
        ):
            combined = self.results.get(
                (
                    (argv[0], "--no-daemon", "assemble", "test", "--rerun"),
                    key[1],
                )
            )
            if (
                combined is not None
                and combined.exit_code == 0
                and combined.unit_tests_verified
            ):
                self.results[key] = combined
        if key not in self.results:
            self.results[key] = self.runner.run(argv, **kwargs)
        return self.results[key]


class Engine:
    """Coordinate one local run with exclusive edits and concurrent evidence reads.

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
        self._verification_done = threading.Condition(self._lock)
        self._verifying: set[str | None] = set()
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
        self._today_override = today
        self._run_day: date | None = None
        self.project_id = project_id
        self.validation_timeout = validation_timeout
        self.state = RunState()
        self._source_documentation_key = object()
        self._fix_selection_snapshot: list[dict] | None = None
        self._finding_progress: dict[str, tuple[str, int]] = {}
        self._files: list[Path] | None = None
        self._files_truncated = False
        self._gradle_lock = threading.Lock()
        self._gradle_reports: dict[
            tuple[Path, str], tuple[dict, GradleReport, dict, set[str]]
        ] = {}
        self._product_baseline: dict | None = None
        self._closed = False
        self._reuse_branch_name: str | None = None

    def _documentation(self) -> OfficialDocs:
        """Return the injected documentation client or open one on first use."""
        with self._lock:
            if self.docs is None:
                self.docs = OfficialDocs(http_log_path=self.http_log_path)
            return self.docs

    @contextmanager
    def _tool_access(
        self, finding_id: str | None = None, *, verification: bool = False
    ) -> Generator[None, None, None]:
        """Exclude mutations until all reserved finding assessments finish."""
        with logged_lock(self._lock, "engine"):
            self._verification_done.wait_for(
                lambda: (
                    (
                        finding_id not in self._verifying
                        and len(self._verifying) < MAX_WORKERS
                    )
                    if verification
                    else not self._verifying
                )
            )
            if not verification:
                yield
                return
            self._verifying.add(finding_id)
        try:
            yield
        finally:
            with self._verification_done:
                self._verifying.remove(finding_id)
                self._verification_done.notify_all()

    @property
    def today(self) -> date:
        """Use the current local date, including after a long-lived server crosses midnight."""
        return self._today_override or date.today()

    def close(self) -> None:
        """Wait for active tools and close each owned HTTP client once.

        Injected clients stay open. Cleanup failures propagate after every
        owned client is attempted; later tool calls return an error.
        """
        with self._tool_access():
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
        with self._lock:
            if self._files is None:
                self._files, self._files_truncated = iter_files(self.repo_root)
            return self._files, self._files_truncated

    def _drop_snapshot(self) -> None:
        """Invalidate cached file discovery after local changes."""
        self._files = None

    def _check_corporate_dns(self, failure_status: str) -> dict | None:
        """Stop in memory if corporate DNS is unavailable, without changing files."""
        self._progress(None, "Checking corporate DNS for nexus.ert.com")
        try:
            if not getaddrinfo("nexus.ert.com", 443, type=SOCK_STREAM):
                raise gaierror("No DNS addresses returned")
        except OSError as exc:
            reason = (
                "Cannot resolve nexus.ert.com. Connect to corporate VPN first, "
                "then rerun run_prechecks."
            )
            self._progress(None, reason)
            self.state.status = failure_status
            self.state.stop_stage = "corporate_dns"
            return {
                "status": failure_status,
                "reason": reason,
                "error": str(exc),
                "action": "Connect to corporate VPN first, then rerun run_prechecks.",
                "hostname": "nexus.ert.com",
            }
        return None

    @_serialized
    def run_prechecks(self) -> dict:
        """Require DNS and a clean main/today branch before a guarded fresh start."""
        if (self.state.fix_selection.get("package_execution") or {}).get("status") in {
            "QUEUED",
            "RUNNING",
        }:
            return {
                "status": "REMEDIATION_RUNNING",
                "reason": "Wait for the server-owned approved package batch before starting another run.",
                "no_changes_attempted": True,
            }
        dns_failure = self._check_corporate_dns("PRECHECK_FAILED")
        if dns_failure is not None:
            return {**dns_failure, "no_changes_attempted": True}
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
            run_day = self.today
            name = branch_name_for(run_day)
            if branch not in {"main", name}:
                return self._stop(
                    "PRECHECK_FAILED",
                    "precheck",
                    {
                        "status": "PRECHECK_FAILED",
                        "reason": f"Not on main or today's security branch (current: {branch or 'detached'}). Switch to main first.",
                        "no_changes_attempted": True,
                    },
                )
            exists = (
                branch == name
                or self.git.branch_exists_locally(name)
                or self.git.branch_exists_on_origin(name)
            )
            self._reuse_branch_name = name if exists else None
            if exists:
                review = review_security_artifacts(self.repo_root)
                if not review["filesystem_safe"]:
                    return self._security_log_failure("PRECHECK_FAILED", review)
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
        self.state = RunState()
        self._source_documentation_key = object()
        self._fix_selection_snapshot = None
        self.state.status = "PRECHECK_PASSED"
        self._run_day = run_day
        self.state.stop_stage = None
        self._remember()
        return {
            "status": "PRECHECK_PASSED",
            "repo_root": str(self.repo_root),
            "branch": branch,
            "reuse_branch": self._reuse_branch_name,
            "clean": True,
        }

    @_serialized
    def pull_main_twice(self) -> dict:
        """Fast-forward main twice, then clean/install pnpm before security checks."""
        if self.state.status != "PRECHECK_PASSED":
            return {"status": "PULL_FAILED", "reason": "Precheck not passed"}
        if self._run_day is not None and self._run_day != self.today:
            return self._stop(
                "PULL_FAILED",
                "run_date",
                {
                    "status": "PULL_FAILED",
                    "reason": "The local date changed after prechecks. Rerun run_prechecks before selecting a security branch.",
                },
            )
        if (
            self._reuse_branch_name
            and self.git.current_branch() == self._reuse_branch_name
        ):
            if self.git.dirty_lines() or self.git.in_progress_operation():
                return self._stop(
                    "PULL_FAILED",
                    "pull_clean",
                    {
                        "status": "PULL_FAILED",
                        "reason": "Working tree or Git operation changed after prechecks; no branch switch was attempted.",
                    },
                )
            try:
                self.git.run(["checkout", "main"])
            except (OSError, RuntimeError) as exc:
                return self._stop(
                    "PULL_FAILED",
                    "pull_main",
                    {"status": "PULL_FAILED", "error": str(exc)},
                )
        results = []
        for number in (1, 2):
            dns_failure = self._check_corporate_dns("PULL_FAILED")
            if dns_failure is not None:
                return {**dns_failure, "results": results}
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
        dns_failure = self._check_corporate_dns("PREPARATION_FAILED")
        if dns_failure is not None:
            return {**dns_failure, "results": results}
        try:
            preparation = [] if self._reuse_branch_name else self._prepare_pnpm()
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
            "preparation_deferred_to_reused_branch": bool(self._reuse_branch_name),
        }

    def _security_log_failure(self, status: str, review: dict) -> dict:
        """Stop in memory without overwriting prior artifacts that explain failure."""
        self.state.status = status
        self.state.stop_stage = "security_log_review"
        logger.error(
            "Security log review blocked branch reuse: %s error(s)",
            review["error_count"],
        )
        return {
            "status": status,
            "reason": "Prior security artifacts could not be safely inspected or cleaned. All remaining artifacts were preserved.",
            "security_artifacts": review,
            "action": "Resolve the reported filesystem/snapshot safety errors before retrying cleanup.",
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
        """Create today's branch, or reuse it after guarded generated-artifact cleanup."""
        if self.state.status == "BRANCH_CREATED" and self.state.branch_name:
            return {
                "status": "BRANCH_CREATED",
                "branch": self.state.branch_name,
                "note": "Branch was already created for this run.",
            }
        if self.state.status != "PULLS_SUCCEEDED":
            return {"status": "BRANCH_CREATION_FAILED", "reason": "Pulls not succeeded"}
        if self._run_day is not None and self._run_day != self.today:
            return self._stop(
                "BRANCH_CREATION_FAILED",
                "run_date",
                {
                    "status": "BRANCH_CREATION_FAILED",
                    "reason": "The local date changed after prechecks. Rerun run_prechecks before selecting a security branch.",
                },
            )
        name = branch_name_for(self.today)
        reused = False
        cleanup = None
        preparation = []
        try:
            local = self.git.branch_exists_locally(name)
            remote = False if local else self.git.branch_exists_on_origin(name)
            reused = local or remote
            if reused:
                if self.git.dirty_lines() or self.git.in_progress_operation():
                    raise RuntimeError(
                        "Cannot reuse a branch with a dirty working tree or Git operation in progress"
                    )
                if local:
                    self.git.run(["checkout", name])
                else:
                    self.git.run(
                        [
                            "fetch",
                            "origin",
                            f"refs/heads/{name}:refs/remotes/origin/{name}",
                        ]
                    )
                    self.git.run(["checkout", "-b", name, "--track", f"origin/{name}"])
            else:
                self.git.run(["checkout", "-b", name])
            current = self.git.current_branch()
            if current != name:
                raise RuntimeError(
                    f"Checkout verification failed. Current branch is {current}."
                )
            if reused:
                tracked = self.git.tracked_security_paths()
                cleanup = review_security_artifacts(
                    self.repo_root, tracked, fresh_start=True
                )
                if cleanup["status"] != "OK":
                    return self._security_log_failure("BRANCH_CREATION_FAILED", cleanup)
                self._drop_snapshot()
                dns_failure = self._check_corporate_dns("PREPARATION_FAILED")
                if dns_failure is not None:
                    return dns_failure
                preparation = self._prepare_pnpm()
                self._drop_snapshot()
                if preparation and preparation[-1]["exit_code"] != 0:
                    return self._stop(
                        "PREPARATION_FAILED",
                        "pnpm_preparation",
                        {
                            "status": "PREPARATION_FAILED",
                            "reason": "pnpm preparation on the reused branch failed; security checks were not started.",
                            "preparation": preparation,
                            "failed_command": preparation[-1]["argv"],
                        },
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
        return {
            "status": "BRANCH_CREATED",
            "branch": name,
            "reused": reused,
            "security_artifacts": cleanup,
            "preparation": preparation,
        }

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
        project_source = "explicit" if pid else "git_origin"
        if not pid:
            try:
                pid = self.git.gitlab_project_path(self.gitlab.api_url)
            except (OSError, RuntimeError, ValueError) as exc:
                logger.warning("GitLab project discovery failed: %s", exc)
                return {
                    "status": "ERROR",
                    "stage": "project_discovery",
                    "reason": str(exc),
                    "action": "Check the selected repo_root and Git origin. For automatic per-repository selection, leave GITLAB_PROJECT_ID unset and configure only the trusted GitLab API host and your own token.",
                }
        fetched = self.gitlab.fetch(pid)
        if not fetched.ok:
            return {"status": "ERROR", "reason": fetched.error}
        self.state.findings = fetched.findings
        self._finding_progress.clear()
        self.state.gitlab_project_path = fetched.project_path
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
            "project_source": project_source,
            "pipeline": fetched.pipeline,
            "findings": fetched.findings,
            "note": "Read-only project vulnerability reports: active main findings plus non-main branch findings explicitly reported resolved on default main. Branch-resolution candidates require verification against the pulled main commit and human checkbox approval.",
        }

    @_serialized
    def verify_security_finding(
        self, finding_id: str, *, source_review: dict | None = None
    ) -> dict:
        """Assess source findings locally, or compare dependencies with advisories."""
        with self._lock:
            if self.state.status not in AFTER_BRANCH:
                return {
                    "status": "ERROR",
                    "reason": "Findings have not been listed yet",
                }
            current = self._finding(finding_id)
            if current is None:
                return {"status": "ERROR", "reason": "Finding not found"}
            if any(
                change["finding_id"] == finding_id for change in self._package_changes()
            ):
                return {
                    "status": "ERROR",
                    "reason": "Retain the applied package's original evidence; run post-update validation instead",
                }
            finding = deepcopy(current)
        finding.pop("sourceWorkflow", None)
        finding.pop("dependencyResolution", None)
        try:
            self._progress(finding_id, "Assessing scanner category and local evidence")
            decision, reason, evidence, proposed, prompt = self._decide(
                finding, source_review
            )
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            reason = f"Finding evidence could not be read safely: {exc}"
            decision, evidence, proposed = "MANUAL_REVIEW", [reason], None
            prompt = self._prompt(finding, None, reason)
        assessment = {"decision": decision, "reason": reason, "evidence": evidence}
        finding["remediationDecision"] = decision
        finding["assessment"] = assessment
        finding["proposedFix"] = proposed
        finding.pop("packageQualification", None)
        finding["evidence"] = evidence
        finding.pop("sourceReview", None)
        if isinstance(source_review, dict) and (
            finding.get("sourceWorkflow") or {}
        ).get("status") == source_review.get("decision"):
            finding["sourceReview"] = deepcopy(source_review)
        component = finding.get("component")
        with self._lock:
            current.clear()
            current.update(finding)
            self.state.forget(finding_id)
            self.state.decisions[finding_id] = assessment
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
            elif decision in {"MANUAL_REVIEW", "CONFIRMED_VULNERABILITY"}:
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
            "source_workflow": finding.get("sourceWorkflow"),
            "source_review_request": {
                key: deepcopy(finding.get(key))
                for key in ("id", "title", "description", "identifiers", "location")
            }
            if decision == "SOURCE_REVIEW_REQUIRED"
            else None,
        }

    @_serialized
    def record_source_review_blocker(self, finding_id: str, reason: str) -> dict:
        """Persist why AI review is incomplete instead of reporting a verdict."""
        finding = self._finding(finding_id)
        assessment = self.state.decisions.get(finding_id)
        if (
            finding is None
            or not assessment
            or assessment["decision"] != "SOURCE_REVIEW_REQUIRED"
        ):
            return {
                "status": "ERROR",
                "reason": "Source assessment changed while AI review was running",
            }
        assessment["reason"] = reason
        assessment["evidence"].append(reason)
        finding["assessment"] = deepcopy(assessment)
        self._remember()
        return {
            "decision": assessment["decision"],
            "reason": reason,
            "evidence": deepcopy(assessment["evidence"]),
        }

    @_serialized
    def fix_selection_candidates(self) -> dict:
        """List real assessed issues without inventing edit plans or authorizing writes."""
        if (self.state.fix_selection.get("package_execution") or {}).get("status") in {
            "QUEUED",
            "RUNNING",
        }:
            return {
                "status": "REMEDIATION_RUNNING",
                "message": "The approved package batch is queued or running. Do not reopen selection, duplicate edits or poll.",
                "next_tool": "wait_for_completion",
            }
        if self.state.status not in AFTER_BRANCH:
            return {"status": "ERROR", "reason": "Verify findings in this run first"}
        if self.state.changes:
            return {
                "status": "SELECTION_LOCKED",
                "reason": "Edits already exist. Validate this authorized batch before starting a fresh clean run.",
            }
        candidates = []
        for finding in self.state.findings:
            assessment = self.state.decisions.get(finding["id"]) or {}
            if assessment.get("decision") not in {
                "CHANGE_REQUIRED",
                "CONFIRMED_VULNERABILITY",
                "REPRODUCTION_REQUIRED",
            }:
                continue
            plan = finding.get("proposedFix") or {}
            resolved = finding.get("dependencyResolution") or {}
            current_version = (
                plan.get("installed")
                or (
                    resolved.get("version")
                    if resolved.get("status") == "RESOLVED"
                    else None
                )
                or finding.get("installedVersion")
            )
            candidates.append(
                {
                    "identity": self._fix_identity(finding),
                    "id": finding["id"],
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "location": deepcopy(finding.get("location") or {}),
                    "decision": assessment["decision"],
                    "reason": assessment.get("reason"),
                    "current_version": current_version,
                    "current_version_source": (
                        "Verified local plan"
                        if plan.get("installed")
                        else "Resolved dependency"
                        if resolved.get("status") == "RESOLVED"
                        and resolved.get("version")
                        else "Finding reports"
                        if finding.get("installedVersion")
                        else "Not established"
                    ),
                    "proposed_fix": {
                        key: value
                        for key, value in (finding.get("proposedFix") or {}).items()
                        if key
                        in {
                            "ecosystem",
                            "package",
                            "target",
                            "installed",
                            "strategy",
                            "description",
                            "file",
                            "files",
                            "manager",
                            "major_upgrade",
                        }
                    },
                }
            )
        return {"status": "OK", "candidates": candidates}

    @staticmethod
    def _fix_identity(finding: dict) -> dict:
        """Bind permission to the actual issue, not mutable qualification receipts."""
        identity = {
            key: deepcopy(finding.get(key))
            for key in (
                "id",
                "vulnerabilityId",
                "findingUuid",
                "title",
                "category",
                "identifiers",
                "location",
                "trackedRef",
                "mainBranchResolution",
                "installedVersion",
            )
        }
        plan = finding.get("proposedFix") or {}
        if plan.get("ecosystem") in PACKAGE_ECOSYSTEMS:
            identity["package_update"] = {
                key: deepcopy(plan.get(key))
                for key in (
                    "ecosystem",
                    "package",
                    "installed",
                    "target",
                    "strategy",
                    "files",
                    "manager",
                )
            }
        return identity

    @_serialized
    def pending_fix_selection(self, request_id: str) -> dict:
        """Resume only the live human question against its original evidence."""
        snapshot = self._fix_selection_snapshot
        current = self.fix_selection_candidates()
        if (
            self.state.fix_selection.get("request_id") != request_id
            or self.state.fix_selection.get("status")
            not in {"REQUESTED", "AWAITING_HUMAN"}
            or snapshot is None
            or current.get("status") != "OK"
            or current["candidates"] != snapshot
        ):
            logger.warning("Fix selection retry rejected: request or evidence changed")
            return {
                "status": "SELECTION_CHANGED",
                "reason": "The original live selection request or its evidence changed. No edit permission was recorded.",
                "next_tool": "get_run_status",
            }
        return {
            "status": "REQUESTED",
            "request_id": request_id,
            "candidates": snapshot,
        }

    @_serialized
    def record_fix_selection(
        self,
        candidates: list[dict],
        selected_ids: list[str],
        status: str,
        reason: str = "",
        *,
        request_id: str | None = None,
        presentation: str = "HOST_FORM",
    ) -> dict:
        """Record only host-form selections against an unchanged candidate snapshot."""
        current = self.fix_selection_candidates()
        if current["status"] != "OK":
            return current
        previous = self.state.fix_selection
        if (
            status == "REQUESTED"
            and presentation == "WINDOWS_DIALOG"
            and previous.get("presentation") == "WINDOWS_DIALOG"
            and previous.get("status") in {"REQUESTED", "AWAITING_HUMAN"}
        ):
            return {
                "status": previous["status"],
                "request_id": previous["request_id"],
                "created": False,
                "next_tool": "wait_for_human",
                "message": "The selection window is starting or open. Wait for the human; do not reopen or poll.",
            }
        stale_request = request_id is not None and (
            self.state.fix_selection.get("request_id") != request_id
            or self.state.fix_selection.get("status")
            not in {"REQUESTED", "AWAITING_HUMAN"}
        )
        if (
            stale_request
            or (
                (status in {"REQUESTED", "AWAITING_HUMAN"} or selected_ids)
                and current["candidates"] != candidates
            )
            or not set(selected_ids).issubset(item["id"] for item in candidates)
        ):
            logger.warning("Fix selection rejected: finding evidence changed")
            if request_id is not None and not stale_request:
                self.state.fix_selection = {
                    **self.state.fix_selection,
                    "status": "INVALID",
                    "selected_ids": [],
                    "approved_findings": [],
                    "reason": "The reviewed findings or proposed versions changed. No edits are authorized; request a fresh selection.",
                }
                self._fix_selection_snapshot = None
                self._remember()
            return {
                "status": "SELECTION_CHANGED",
                "reason": "Findings changed while the form was open. No new edit permission was recorded.",
                "next_tool": "get_run_status"
                if stale_request
                else "select_security_fixes",
            }
        candidates = current["candidates"]
        approved = {
            item["id"]: item["identity"]
            for item in candidates
            if item["id"] in selected_ids
        }
        self.state.fix_selection = {
            "request_id": uuid4().hex if status == "REQUESTED" else request_id,
            "status": status,
            "presentation": presentation,
            "candidate_ids": [item["id"] for item in candidates],
            "selected_ids": selected_ids,
            "approved_findings": approved,
            "reason": reason,
        }
        if (
            status == "APPROVED"
            and presentation == "WINDOWS_DIALOG"
            and any("package_update" in identity for identity in approved.values())
        ):
            self.state.fix_selection["package_execution"] = {"status": "QUEUED"}
        self._fix_selection_snapshot = (
            deepcopy(candidates) if status in {"REQUESTED", "AWAITING_HUMAN"} else None
        )
        if not self.state.validation_results:
            self.state.validation_status = (
                "NOT_RUN_NO_APPROVED_FIXES"
                if status in {"SKIPPED", "UNAVAILABLE", "INVALID"}
                else None
            )
        self._remember()
        return {
            "status": status,
            "created": status == "REQUESTED",
            "request_id": self.state.fix_selection["request_id"],
            "selected_ids": selected_ids,
            "skipped_ids": [
                item["id"] for item in candidates if item["id"] not in approved
            ],
            "reason": reason,
            "next_tool": "wait_for_human"
            if status in {"REQUESTED", "AWAITING_HUMAN"}
            else "qualify_package_update or approved scoped host edits"
            if selected_ids
            else "complete_security_run",
            "message": (
                "Only selected issues authorize remediation edits. Authorization is not proof of a safe fix. "
                "Skipped issues remain unresolved, not false positives. False-positive dismissal requires separate human approval."
            ),
        }

    @_serialized
    def run_approved_fix(
        self, operation: str, *args, _selection_request_id: str | None = None, **kwargs
    ) -> dict:
        """Atomically guard MCP editing and validation entry points with human selection."""
        if operation not in {
            "qualify_package_update",
            "apply_minimal_fix",
            "generate_aaa_test",
            "run_validation_matrix",
        }:
            return {
                "status": "ERROR",
                "reason": "Not a supported remediation operation",
            }
        selection = self.state.fix_selection
        if (selection.get("package_execution") or {}).get("status") in {
            "QUEUED",
            "RUNNING",
        } and _selection_request_id != selection.get("request_id"):
            return {
                "status": "REMEDIATION_RUNNING",
                "reason": "The server owns the approved package batch. Do not duplicate its edits or checks.",
                "next_tool": "wait_for_completion",
            }
        if selection.get("presentation") == "WINDOWS_DIALOG" and selection.get(
            "status"
        ) in {"REQUESTED", "AWAITING_HUMAN"}:
            return {
                "status": "AWAITING_HUMAN",
                "message": "Wait for the human selection. No edits or builds are authorized; do not poll or reopen the form.",
                "next_tool": "wait_for_human",
            }
        approved = selection.get("approved_findings") or {}
        if operation == "run_validation_matrix":
            if (
                not approved
                and not self.state.changes
                and selection.get("status")
                in {
                    "SKIPPED",
                    "UNAVAILABLE",
                    "INVALID",
                }
            ):
                return {
                    "status": "SKIPPED_NO_APPROVED_FIXES",
                    "reason": "No code fixes were approved. Continue to independently assessed false positives.",
                    "next_tool": "complete_security_run",
                }
            ids = {item["finding_id"] for item in self.state.changes} or set(approved)
        else:
            ids = {args[0]} if args else set()
        authorized = selection.get("status") == "APPROVED" and bool(ids)
        for finding_id in ids:
            finding = self._finding(finding_id)
            if finding is None or self._fix_identity(finding) != approved.get(
                finding_id
            ):
                authorized = False
                break
        if not authorized:
            logger.warning(
                "Remediation blocked without current human permission: %s", operation
            )
            return {
                "status": "FIX_APPROVAL_REQUIRED",
                "reason": "The human has not approved these exact findings for edits in this run.",
                "next_tool": "select_security_fixes",
                "operation": operation,
            }
        return getattr(self, operation)(*args, **kwargs)

    @_serialized
    def prepare_package_updates(self, candidates: list[dict], reviews: dict) -> dict:
        """Require target-specific AI evidence before opening an autonomous package form."""
        current = self.fix_selection_candidates()
        if current["status"] != "OK":
            return current
        previous = self.state.fix_selection
        if previous.get("presentation") == "WINDOWS_DIALOG" and previous.get(
            "status"
        ) in {"REQUESTED", "AWAITING_HUMAN"}:
            return {
                "status": previous["status"],
                "request_id": previous["request_id"],
                "next_tool": "wait_for_human",
                "message": "The selection window is starting or open. Wait for the human; do not reopen or poll.",
            }
        if current.get("candidates") != candidates:
            return {"status": "SELECTION_CHANGED", "next_tool": "get_run_status"}
        prepared = {}
        required = []
        for item in candidates:
            plan = (self._finding(item["id"]) or {}).get("proposedFix") or {}
            if plan.get("ecosystem") not in PACKAGE_ECOSYSTEMS:
                continue
            review = reviews.get(item["id"])
            try:
                if not isinstance(review, dict) or any(
                    review.get(key) != plan.get(key)
                    for key in ("ecosystem", "package", "target")
                ):
                    raise ValueError(
                        "Provide the complete compatibility/license review for this exact package and target."
                    )
                if "blocked_reason" in review:
                    if (
                        not isinstance(review["blocked_reason"], str)
                        or not review["blocked_reason"].strip()
                    ):
                        raise ValueError(
                            "A blocked package requires an explicit evidence-based reason."
                        )
                    prepared[item["id"]] = deepcopy(review)
                    continue
                review_package(review)
                review_major_upgrade(self.repo_root, plan, review)
                self._package_policy(plan, review)
            except (OSError, ValueError, TypeError, RuntimeError) as exc:
                required.append(
                    {
                        "finding_id": item["id"],
                        "plan": deepcopy(plan),
                        "reason": str(exc),
                    }
                )
            else:
                prepared[item["id"]] = deepcopy(review)
        if required:
            return {
                "status": "PACKAGE_REVIEW_REQUIRED",
                "required_reviews": required,
                "next_tool": "select_security_fixes",
                "message": "Before opening the Windows checkboxes, the host AI must review the official docs, actual framework/API compatibility and license terms. "
                "Use the qualify_package_update review schema, then call select_security_fixes with package_reviews keyed by finding ID. "
                "For a package that cannot safely qualify, provide its exact ecosystem/package/target and an honest blocked_reason; it will be labeled blocked, never edited, and will not prevent other updates. "
                "Collect evidence only; do not call qualification or edit files before human selection. Never invent missing evidence or approvals.",
            }
        return {
            "status": "READY",
            "reviews": prepared,
            "tree": tree_snapshot(self.repo_root) if prepared else {},
        }

    def execute_selected_package_updates(
        self,
        request_id: str,
        reviews: dict,
        expected_tree: dict,
        cancelled: threading.Event,
    ) -> dict:
        """Qualify, edit and validate the live human-selected batch without another AI turn."""
        with self._lock:
            selection = self.state.fix_selection
            if (
                selection.get("request_id") != request_id
                or selection.get("status") != "APPROVED"
            ):
                return {"status": "STALE_SELECTION"}
            execution = selection.get("package_execution") or {}
            if execution.get("status") != "QUEUED":
                return {"status": "ALREADY_EXECUTED"}
            selected_ids = selection["selected_ids"]
            package_ids = [
                finding_id for finding_id in selected_ids if finding_id in reviews
            ]
            source_ids = [
                finding_id for finding_id in selected_ids if finding_id not in reviews
            ]
            execution.update(status="RUNNING", results=[], source_ids=source_ids)
            selection["package_execution"] = execution
            self._remember()

        def step(operation: str, *args) -> dict:
            """Bind each serialized step to this run and the last owned checkout snapshot."""
            nonlocal expected_tree
            with self._lock:
                if cancelled.is_set():
                    raise InterruptedError(
                        "Server shutdown interrupted the approved package batch."
                    )
                if self.state.fix_selection.get("request_id") != request_id:
                    raise RuntimeError(
                        "The approved package batch belongs to a replaced run."
                    )
                if tree_snapshot(self.repo_root) != expected_tree:
                    raise ValueError(
                        "Checkout changed outside the approved batch. Review the changes and obtain fresh documentation evidence."
                    )
                started_at = utc_now_iso()
                started = monotonic()
                result = self.run_approved_fix(
                    operation, *args, _selection_request_id=request_id
                )
                expected_tree = tree_snapshot(self.repo_root)
                execution["results"].append(
                    {
                        "finding_id": args[0] if args else None,
                        "stage": operation,
                        "status": result["status"],
                        "reason": result.get("reason"),
                        "started_at": started_at,
                        "duration_ms": round((monotonic() - started) * 1000, 3),
                    }
                )
                self._remember()
                return result

        failed = False
        reason = ""
        try:
            for finding_id in package_ids:
                if reviews[finding_id].get("blocked_reason"):
                    with self._lock:
                        execution["results"].append(
                            {
                                "finding_id": finding_id,
                                "stage": "documentation_review",
                                "status": "BLOCKED",
                                "reason": reviews[finding_id]["blocked_reason"],
                            }
                        )
                    failed = True
                    continue
                qualified = step(
                    "qualify_package_update", finding_id, reviews[finding_id]
                )
                if qualified["status"] != "QUALIFIED":
                    failed = True
                    continue
                applied = step("apply_minimal_fix", finding_id)
                if applied["status"] != "APPLIED":
                    failed = True
                    if (
                        applied.get("continue_with_next_finding") is False
                        or self.state.manual_cleanup_required
                    ):
                        break
            with self._lock:
                pending = any(
                    change.get("validation_pending")
                    for change in self._package_changes()
                )
            validation = step("run_validation_matrix") if pending else None
            if validation is not None:
                failed |= validation["status"] != "VALIDATION_COMPLETE" or bool(
                    validation.get("rejected_updates")
                )
            if cancelled.is_set():
                raise InterruptedError(
                    "Server shutdown interrupted the approved package batch."
                )
            status = "PARTIAL_FAILURE" if failed else "COMPLETED"
        except InterruptedError as exc:
            status, reason = "INTERRUPTED", str(exc)
            logger.warning("%s", reason)
        except (OSError, ValueError, TypeError, RuntimeError, SubprocessError) as exc:
            status, reason = "BLOCKED", str(exc)
            logger.exception("Approved package execution blocked")
        with self._lock:
            if self.state.fix_selection.get("request_id") != request_id:
                return {"status": "STALE_SELECTION"}
            if status in {"INTERRUPTED", "BLOCKED"} and any(
                change.get("validation_pending") for change in self._package_changes()
            ):
                self.state.manual_cleanup_required = True
            execution.update(
                status=status,
                reason=reason,
                validation_status=self.state.validation_status,
            )
            self._remember()
            self.generate_local_report()
            return {
                **deepcopy(execution),
                "finish_run": not source_ids
                and status not in {"INTERRUPTED", "BLOCKED"},
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
            review_package(review)
            major_review = review_major_upgrade(self.repo_root, plan, review)
            policy = self._package_policy(plan, review)
            tree = tree_snapshot(self.repo_root)
            scripts = package_script_hashes(self.repo_root, tree)
            lint_recorded = self.state.lint_baseline is not None
            if not lint_recorded:
                self._progress(
                    finding_id,
                    "Recording initial informational lint before editing (Gradle may compile sources); file writing has not started. Builds and unit tests follow the complete batch.",
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
                {"tree": tree, "package_script_hashes": scripts},
                [],
            )
            receipt = {
                "check_contract": "lint-baseline-build-unit-tests-no-code-v4",
                "status": "QUALIFIED",
                "plan": deepcopy(plan),
                "review": deepcopy(review),
                "major_review": major_review,
                **policy,
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
            "note": "Apply all reviewed package updates, then run production builds and unit tests. Both must pass to retain updates. Existing lint issues are informational. Failed batches isolate and revert offending updates while retaining passing updates.",
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
        reviewed_config_fix = (
            (finding.get("sourceReview") or {}).get("decision")
            == "CONFIRMED_VULNERABILITY"
            and (finding.get("sourceWorkflow") or {}).get("status")
            == "CONFIRMED_VULNERABILITY"
            and finding.get("remediationDecision") == "CHANGE_REQUIRED"
            and (finding.get("proposedFix") or {}).get("strategy") == "config_line"
        )
        if finding.get("sourceWorkflow") and not reviewed_config_fix:
            return {
                "status": "SKIPPED"
                if finding.get("remediationDecision") == "FALSE_POSITIVE"
                else "SOURCE_REVIEW_REQUIRED",
                "finding_id": finding_id,
                "reason": (finding.get("assessment") or {}).get("reason"),
                "source_workflow": finding["sourceWorkflow"],
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
        reused_change = None
        if package_update:
            self._refresh_package_validation()
            receipt = finding.get("packageQualification") or {}
            try:
                if (
                    receipt.get("status") != "QUALIFIED"
                    or receipt.get("plan") != proposed
                    or receipt.get("check_contract")
                    != "lint-baseline-build-unit-tests-no-code-v4"
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
                reused_change = self._matching_package_change(proposed)
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
        review = (
            self._documentation().read_for_existing_fix(
                finding, reused_change["documentation"], proposed.get("doc_pages") or []
            )
            if reused_change
            else self._documentation().read_before_fix(
                finding, proposed.get("doc_pages") or []
            )
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
        if reviewed_config_fix:
            source_review = finding["sourceReview"]
            if (
                assess_source(self.repo_root, finding, source_review)["decision"]
                != "CONFIRMED_VULNERABILITY"
            ):
                refreshed = self.verify_security_finding(
                    finding_id, source_review=source_review
                )
                return {
                    "status": "SOURCE_REVIEW_REQUIRED",
                    "finding_id": finding_id,
                    "reason": refreshed["reason"],
                    "source_workflow": refreshed["source_workflow"],
                }
        if not package_update:
            finding["localFixAttempt"] = {
                "tree": tree_snapshot(self.repo_root),
                "dependency_before": backup_dependency_files(self.repo_root, proposed),
            }
        edit_started = monotonic()
        outcome = (
            {
                "status": "APPLIED",
                "files": list(reused_change["files"]),
                "commands": [],
                "description": plan.description,
                "detail": f"Shares the unchanged dependency edit from {reused_change['finding_id']}; no files rewritten or package commands rerun. Final validation is still required.",
            }
            if reused_change
            else apply_plan(self.repo_root, plan, self.runner, self.which)
        )
        edit_duration_ms = round((monotonic() - edit_started) * 1000, 3)
        self._progress(
            finding_id,
            f"Dependency/configuration edit and lockfile refresh finished in {edit_duration_ms:.1f} ms; build/unit-test validation is a separate phase.",
        )
        if package_update:
            receipt["applied_dependency_hashes"] = dependency_file_hashes(
                self.repo_root, receipt["dependency_before"]
            )
        change = {
            "finding_id": finding_id,
            "status": outcome["status"],
            "edit_duration_ms": edit_duration_ms,
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
        if reused_change:
            change["reused_from"] = reused_change["finding_id"]
        if not package_update:
            finding["localFixAttempt"]["applied_dependency_hashes"] = (
                dependency_file_hashes(
                    self.repo_root, finding["localFixAttempt"]["dependency_before"]
                )
            )
        self.state.changes.append(change)
        self._drop_snapshot()
        if outcome["status"] == "APPLIED":
            if reviewed_config_fix:
                change["source_review"] = finding.pop("sourceReview")
                change["source_workflow"] = finding.pop("sourceWorkflow")
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
            "note": "Initial lint issues are recorded separately. Not accepted until production builds, unit tests and configured policy checks pass. Failed updates are isolated and reverted; passing updates remain. Production/unit-test code and check scripts must remain unchanged.",
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
                    "Rejected after build, unit-test or policy failure with retained updates "
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
                    reason="All candidates rejected; the restored baseline build, unit tests and configured policy checks passed.",
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
                change["finding_id"],
                "Running post-update production builds and unit tests",
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
            try:
                if not receipt.get("plan"):
                    raise ValueError("Package qualification is missing")
                if (
                    receipt.get("check_contract")
                    != "lint-baseline-build-unit-tests-no-code-v4"
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
                        "Product build/unit-test validation failed or is incomplete; candidate cannot be accepted"
                    )
                plan = receipt["plan"]
                if (
                    plan.get("strategy") == "override"
                    and plan.get("manager") == "gradle"
                ):
                    resolved = self._resolve_gradle_package(
                        finding, self._snapshot()[0]
                    )
                    versions = (
                        {
                            version
                            for values in (
                                resolved.configuration_versions or {}
                            ).values()
                            for version in values
                        }
                        if resolved
                        else set()
                    )
                    if (
                        not resolved
                        or resolved.version != plan["target"]
                        or versions != {plan["target"]}
                    ):
                        raise ValueError(
                            "Gradle override did not resolve the exact fixed version in every reported configuration"
                        )
                if (
                    plan.get("strategy") == "override"
                    and plan.get("manager") == "maven"
                ):
                    component = java_project_root(
                        self.repo_root, plan["files"][0], "maven"
                    )
                    trees = [
                        row
                        for row in outcome["results"]
                        if row.get("kind") == "dependency_tree"
                        and row.get("cwd") == str(component)
                    ]
                    versions = {
                        match[1]
                        for row in trees
                        for match in re.finditer(
                            rf"(?<![\w.-]){re.escape(plan['package'])}:[^:\s]+:(?:[^:\s]+:)?([^:\s]+):(?:compile|runtime|test|provided|system)\b",
                            row.get("stdout", "") + row.get("stderr", ""),
                        )
                    }
                    if versions != {plan["target"]}:
                        raise ValueError(
                            "Maven dependency tree did not confirm the exact overridden fixed version"
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
                    "Accepted: no production/unit-test API changes; initial lint issues recorded separately; production builds, unit tests and configured policy checks passed."
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
    def false_positive_candidates(self) -> dict:
        """Snapshot current, evidenced false positives for human approval."""
        self._refresh_source_reviews()
        if self.state.status not in AFTER_BRANCH or not self.state.gitlab_project_path:
            return {
                "status": "ERROR",
                "reason": "List and verify findings in this process before requesting approval",
            }
        dismissed = {
            item["id"]
            for item in self.state.gitlab_dismissals
            if dismissal_is_confirmed(item)
        }
        candidates = []
        excluded = []
        for finding in self.state.findings:
            assessment = self.state.decisions.get(finding["id"]) or {}
            reason = assessment.get("reason")
            if finding["id"] in dismissed:
                exclusion = "ALREADY_DISMISSED"
                action = "Previously confirmed dismissed in GitLab; no repeat approval is needed."
            elif assessment.get("decision") == "SOURCE_REVIEW_REQUIRED":
                exclusion = "SOURCE_REVIEW_REQUIRED"
                action = "The host AI must complete the local code review and submit source_review through verify_security_finding; reading an excerpt alone is not an assessment."
            elif assessment.get("decision") != "FALSE_POSITIVE":
                exclusion = "ASSESSMENT_REQUIRED"
                action = (
                    "Call verify_security_finding for this finding in this process. "
                    "Only an evidenced FALSE_POSITIVE assessment is eligible."
                )
            elif (
                not isinstance(reason, str) or not reason.strip() or len(reason) > 50000
            ):
                exclusion = "INVALID_REASON"
                action = "Reassess with a nonempty reason of at most 50,000 characters."
            elif not finding.get("vulnerabilityId"):
                exclusion = "MISSING_VULNERABILITY_ID"
                action = (
                    "This finding lacks its GitLab vulnerability global ID. "
                    "Retrieve and verify findings in a fresh run with the updated server."
                )
            else:
                description = reason.strip()
                source_review = finding.get("sourceReview")
                resolution = finding.get("mainBranchResolution")
                if resolution:
                    description = (
                        f"GitLab confirms this finding on branch {resolution['branch']} "
                        f"is already resolved on main at {resolution['main_sha']}. "
                        "It is stale for this main-branch review; this does not prove "
                        "the older branch is safe."
                    )
                elif isinstance(source_review, dict):
                    description = source_review["reason"].strip()
                candidates.append(
                    {
                        "id": finding["id"],
                        "vulnerability_id": finding["vulnerabilityId"],
                        "project_path": self.state.gitlab_project_path,
                        "title": finding.get("title"),
                        "location": finding.get("location") or {},
                        "description": description,
                        "reason": reason,
                        "assessment": deepcopy(assessment),
                        "source_review": deepcopy(finding.get("sourceReview")),
                        **(
                            {
                                "main_resolution": deepcopy(
                                    finding["mainBranchResolution"]
                                ),
                                "finding_uuid": finding.get("findingUuid"),
                            }
                            if finding.get("mainBranchResolution")
                            else {}
                        ),
                    }
                )
                continue
            excluded.append(
                {
                    "id": finding["id"],
                    "reason": exclusion,
                    "decision": assessment.get("decision"),
                    "action": action,
                }
            )
        return {
            "status": "OK",
            "candidates": candidates,
            "excluded": excluded,
            "source_review_queue": pending_source_reviews(
                self.state.findings, self.state.decisions
            ),
        }

    @_serialized
    def dismiss_false_positives(self, approved: list[dict]) -> dict:
        """Apply only unchanged, individually approved assessment snapshots."""
        current = self.false_positive_candidates()
        if current["status"] != "OK":
            return current
        candidates = {item["id"]: item for item in current["candidates"]}
        if len({item["id"] for item in approved}) != len(approved) or any(
            candidates.get(item["id"]) != item for item in approved
        ):
            return {
                "status": "ERROR",
                "reason": "Assessments changed while approval was open; request a fresh approval form",
            }
        results = []
        findings_by_id = {finding["id"]: finding for finding in self.state.findings}
        for index, item in enumerate(approved, 1):
            started = monotonic()
            self._progress(
                item["id"],
                f"Verifying GitLab false-positive dismissal {index} of {len(approved)}",
            )
            record = {
                "id": item["id"],
                "vulnerability_id": item["vulnerability_id"],
                "project_path": item["project_path"],
                "reason": item["reason"],
                "dismissal_reason": "FALSE_POSITIVE",
                "tracked_ref": findings_by_id[item["id"]].get("trackedRef"),
                "status": "PENDING",
                "requested_at": utc_now_iso(),
            }
            self.state.gitlab_dismissals.append(record)
            self._remember()
            try:
                outcome = self.gitlab.dismiss_false_positive(
                    item["vulnerability_id"],
                    item.get("finding_uuid") or item["id"],
                    item["project_path"],
                    item["reason"],
                    **(
                        {"main_resolution": item["main_resolution"]}
                        if item.get("main_resolution")
                        else {}
                    ),
                )
                if (
                    not dismissal_is_confirmed(outcome)
                    or outcome.get("vulnerability_id") != item["vulnerability_id"]
                ):
                    raise RuntimeError(
                        "GitLab dismissal has no matching independent read-back proof"
                    )
                record.update(outcome)
                findings_by_id[item["id"]]["status"] = "dismissed"
            except (
                httpx.HTTPError,
                RuntimeError,
                ValueError,
                TypeError,
                AttributeError,
            ) as exc:
                record.update(
                    status="ERROR",
                    error=self.gitlab._clean(str(exc)),
                    action="Check GitLab before retrying; a failed response does not prove no remote change occurred.",
                )
                logger.warning(
                    "GitLab false-positive dismissal failed for %s: %s",
                    item["id"],
                    record["error"],
                )
            record["finished_at"] = utc_now_iso()
            record["duration_ms"] = round((monotonic() - started) * 1000, 3)
            self._remember()
            results.append(deepcopy(record))
            self._progress(
                item["id"],
                f"GitLab dismissal {index} of {len(approved)}: {record['status']}",
            )
        return {
            "status": "PARTIAL_FAILURE"
            if any(item["status"] != "DISMISSED" for item in results)
            else "OK",
            "results": results,
            "selected_count": len(approved),
            "confirmed_dismissals": sum(
                dismissal_is_confirmed(item) for item in results
            ),
            "unconfirmed_dismissals": sum(
                not dismissal_is_confirmed(item) for item in results
            ),
        }

    @_serialized
    def begin_desktop_approval(self, details: dict) -> dict:
        """Reserve one window for this checkout before asynchronous native startup."""
        previous = self.state.false_positive_approval_form
        if previous.get("presentation") == "WINDOWS_DIALOG" and previous.get(
            "status"
        ) in {"REQUESTED", "AWAITING_HUMAN"}:
            return {
                "status": previous["status"],
                "request_id": previous["request_id"],
                "message": "A Windows approval window is already starting or open for this run. No duplicate window was launched.",
            }
        self.record_false_positive_approval_form({**details, "status": "REQUESTED"})
        return {"status": "REQUESTED", "created": True}

    @_serialized
    def record_false_positive_approval_form(self, details: dict) -> dict:
        """Persist form diagnostics, never reusable authorization for a mutation."""
        if (
            details.get("presentation") == "WINDOWS_DIALOG"
            and details.get("status") != "REQUESTED"
        ):
            previous = self.state.false_positive_approval_form
            if previous.get("request_id") != details.get("request_id") or previous.get(
                "status"
            ) not in {"REQUESTED", "AWAITING_HUMAN"}:
                logger.warning("Ignoring a stale desktop approval status update")
                return {
                    "status": "ERROR",
                    "reason": "The approval window belongs to a different or completed run.",
                }
        self.state.false_positive_approval_form = deepcopy(details)
        self._remember()
        return {"status": "OK"}

    @_serialized
    def resolve_desktop_approval(
        self,
        request_id: str,
        approved: list[dict] | None,
        *,
        status: str = "CANCELLED",
        reason: str = "",
    ) -> dict:
        """Resolve only this live run's owned window, then refresh saved outcomes."""
        receipt = self.state.false_positive_approval_form
        if receipt.get("request_id") != request_id or receipt.get("status") not in {
            "REQUESTED",
            "AWAITING_HUMAN",
        }:
            logger.warning("Ignoring a stale desktop approval response")
            return {
                "status": "ERROR",
                "reason": "The approval window belongs to a different or completed run.",
            }
        result = (
            self.dismiss_false_positives(approved)
            if approved is not None
            else {"status": status, "reason": reason, "results": []}
        )
        self.record_false_positive_approval_form(
            {
                **receipt,
                "status": result["status"],
                "selected_ids": [item["id"] for item in approved or []],
                **({"reason": result["reason"]} if result.get("reason") else {}),
            }
        )
        self.generate_local_report()
        return result

    @_serialized
    def generate_local_report(self) -> dict:
        """Write the markdown and JSON reports under .security-mcp/reports."""
        self._refresh_source_reviews()
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
        self._refresh_source_reviews()
        self._refresh_package_validation()
        review_queue = pending_source_reviews(self.state.findings, self.state.decisions)
        attempted = {item["id"] for item in self.state.gitlab_dismissals}
        confirmed = {
            item["id"]
            for item in self.state.gitlab_dismissals
            if dismissal_is_confirmed(item)
        }
        return {
            "status": self.state.status,
            "server_version": self.state.server_version,
            "stop_stage": self.state.stop_stage,
            "manual_cleanup_required": self.state.manual_cleanup_required,
            "branch": self.state.branch_name,
            "findings_count": len(self.state.findings),
            "changes_count": len(self.state.changes),
            "false_positives_count": len(self.state.false_positives),
            "no_solution_count": len(self.state.no_solution),
            "skipped_user_prompt_count": len(self.state.skipped_user_prompt),
            "source_review_required_count": review_queue["finding_count"],
            "source_review_queue": review_queue,
            "gitlab_dismissal_counts": {
                "attempted": len(attempted),
                "confirmed": len(confirmed),
                "not_confirmed": len(attempted - confirmed),
            },
            "false_positive_approval_form": deepcopy(
                self.state.false_positive_approval_form
            ),
            "fix_selection": deepcopy(self.state.fix_selection),
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

    def _refresh_source_reviews(self) -> None:
        """Retract source conclusions when reviewed files change or disappear."""
        for finding in self.state.findings:
            review = finding.get("sourceReview")
            if review and assess_source(self.repo_root, finding, review)[
                "decision"
            ] != review.get("decision"):
                self.verify_security_finding(finding["id"], source_review=review)

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

    def _matching_package_change(self, proposed: dict) -> dict | None:
        """Reuse only an identical reviewed plan whose updater-owned bytes still match."""
        for change in self._package_changes():
            receipt = (self._finding(change["finding_id"]) or {}).get(
                "packageQualification"
            ) or {}
            expected = receipt.get("applied_dependency_hashes")
            if (
                receipt.get("plan") == proposed
                and expected
                and dependency_file_hashes(self.repo_root, expected) == expected
            ):
                return change
        return None

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
                    == "lint-baseline-build-unit-tests-no-code-v4"
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

    def _resolve_maven_package(
        self, finding: dict, files: list[Path]
    ) -> PackageHit | None:
        """Resolve Maven transitives from a complete, checkout-bound dependency tree."""
        location = (finding.get("location") or {}).get("file")
        builds = [path for path in files if path.name == "pom.xml"]
        manifest = (
            resolve_inside(self.repo_root, location)
            if isinstance(location, str)
            else None
        )
        if manifest not in builds:
            manifest = builds[0] if not location and len(builds) == 1 else None
        if manifest is None:
            return None
        row = {
            "manager": "maven",
            "manifest": manifest.relative_to(self.repo_root).as_posix(),
            "status": "UNRESOLVED",
        }
        try:
            tool = java_wrapper(
                manifest.parent, self.repo_root, "mvnw"
            ) or resolve_tool("mvn", self.which)
            if not tool:
                raise ValueError(
                    "Maven wrapper and mvn are unavailable; dependency tree not inspected"
                )
            with self._gradle_lock:
                before = tree_snapshot(self.repo_root)
                key = (manifest.parent, tool)
                cached = self._gradle_reports.get(key)
                if cached and cached[0] == before:
                    parsed, row = cached[1], dict(cached[2])
                else:
                    result = self.runner.run(
                        [tool, "--batch-mode", "dependency:tree"],
                        timeout=min(self.validation_timeout, 120),
                        check=False,
                        cwd=manifest.parent,
                    )
                    row.update(
                        command=result.display(),
                        stdout_log_path=result.stdout_log_path,
                        stderr_log_path=result.stderr_log_path,
                    )
                    if result.exit_code:
                        raise ValueError(
                            f"Maven dependency inspection exited {result.exit_code}: {(result.stderr or result.stdout)[-500:]}"
                        )
                    output = result.stdout
                    if result.truncated:
                        log = (
                            resolve_inside(self.repo_root, result.stdout_log_path)
                            if result.stdout_log_path
                            else None
                        )
                        if log is None or not log.is_relative_to(
                            self.repo_root / ".security-mcp" / "command-logs"
                        ):
                            raise ValueError(
                                "Truncated Maven dependency output has no complete local log"
                            )
                        with log.open("rb") as stream:
                            raw = stream.read(8 * 1024 * 1024 + 1)
                        if len(raw) > 8 * 1024 * 1024:
                            raise ValueError(
                                "Maven dependency log exceeds the 8 MiB inspection limit"
                            )
                        output = raw.decode("utf-8")
                    parsed = GradleReport()
                    for match in re.finditer(
                        r"(?<![\w.-])([\w.+-]+:[\w.+-]+):[^:\s]+:(?:[^:\s]+:)?([^:\s]+):(compile|runtime|test|provided|system)\b",
                        output,
                    ):
                        parsed.versions.setdefault(match[1], {}).setdefault(
                            match[3], set()
                        ).add(match[2])
                    if tree_snapshot(self.repo_root) != before:
                        raise ValueError(
                            "Checkout changed during Maven dependency inspection"
                        )
                    self._gradle_reports[key] = (before, parsed, dict(row), set())
                    if len(self._gradle_reports) > MAX_WORKERS:
                        self._gradle_reports.pop(next(iter(self._gradle_reports)))
            package = finding["component"].replace("/", ":")
            configurations = parsed.versions.get(package, {})
            versions = {
                version for values in configurations.values() for version in values
            }
            if not versions:
                raise ValueError(
                    "Maven did not report this coordinate as resolved; absence is not a false positive"
                )
            known = {
                version: parsed
                for version in versions
                if (parsed := parse_version(version)) is not None
            }
            if len(known) != len(versions):
                raise ValueError("Maven reported an unsupported resolved version")
            version = finding.get("installedVersion")
            if version not in versions:
                version = min(known, key=known.__getitem__)
            row.update(
                status="RESOLVED",
                version=version,
                configuration_versions={
                    key: sorted(values) for key, values in configurations.items()
                },
            )
            finding["dependencyResolution"] = row
            return PackageHit(
                "Maven",
                "maven",
                package,
                version,
                None,
                row["manifest"],
                None,
                False,
                configuration_versions=row["configuration_versions"],
            )
        except (OSError, ValueError, RuntimeError, SubprocessError) as exc:
            row.update(status="FAILED", detail=str(exc))
            finding["dependencyResolution"] = row
            logger.warning("Maven dependency inspection unavailable: %s", exc)
            return None

    def _resolve_gradle_package(
        self, finding: dict, files: list[Path]
    ) -> PackageHit | None:
        """Share a complete, tree-bound dependency inspection across finding workers."""
        location = (finding.get("location") or {}).get("file")
        manifest = (
            resolve_inside(self.repo_root, location)
            if isinstance(location, str)
            else None
        )
        builds = [
            path for path in files if path.name in {"build.gradle", "build.gradle.kts"}
        ]
        if manifest not in builds:
            manifest = builds[0] if not location and len(builds) == 1 else None
        if manifest is None:
            return None
        row = {
            "manager": "gradle",
            "manifest": manifest.relative_to(self.repo_root).as_posix(),
            "status": "UNRESOLVED",
        }
        entry = None
        try:
            tool = java_wrapper(
                manifest.parent, self.repo_root, "gradlew"
            ) or resolve_tool("gradle", self.which)
            if not tool:
                raise ValueError(
                    "Gradle wrapper and gradle are unavailable; dependency tree not inspected."
                )
            with self._gradle_lock:
                before = tree_snapshot(self.repo_root)
                key = (manifest.parent, tool)
                cached = self._gradle_reports.get(key)
                # Share failures across findings, but let the same finding retry.
                if cached and cached[0] == before and finding["id"] not in cached[3]:
                    entry = cached
                    parsed, row = cached[1], dict(cached[2])
                else:
                    result = self.runner.run(
                        [tool, "--no-daemon", "dependencies"],
                        timeout=min(self.validation_timeout, 120),
                        check=False,
                        **(
                            {"cwd": manifest.parent}
                            if manifest.parent != self.repo_root
                            else {}
                        ),
                    )
                    row.update(
                        command=result.display(),
                        stdout_log_path=result.stdout_log_path,
                        stderr_log_path=result.stderr_log_path,
                    )
                    report = result.stdout
                    if result.exit_code:
                        row.update(
                            status="FAILED",
                            detail=f"Gradle dependency inspection exited {result.exit_code}: "
                            + (result.stderr or result.stdout)[-500:],
                        )
                    elif result.truncated:
                        log = (
                            resolve_inside(self.repo_root, result.stdout_log_path)
                            if result.stdout_log_path
                            else None
                        )
                        directory = self.repo_root / ".security-mcp" / "command-logs"
                        if log is None or not log.is_relative_to(directory):
                            row.update(
                                status="FAILED",
                                detail="Gradle dependency output is truncated and has no complete local log.",
                            )
                        else:
                            with log.open("rb") as stream:
                                raw = stream.read(8 * 1024 * 1024 + 1)
                            if len(raw) > 8 * 1024 * 1024:
                                row.update(
                                    status="FAILED",
                                    detail="Gradle dependency log exceeds the 8 MiB inspection limit.",
                                )
                            else:
                                report = raw.decode("utf-8")
                    if tree_snapshot(self.repo_root) != before:
                        raise ValueError(
                            "Checkout changed during Gradle dependency inspection; retry against a stable tree."
                        )
                    parsed = (
                        parse_gradle_report(report)
                        if row["status"] != "FAILED"
                        else GradleReport()
                    )
                    if parsed.warnings:
                        row["warnings"] = parsed.warnings
                    entry = (before, parsed, dict(row), set())
                    self._gradle_reports[key] = entry
                    if len(self._gradle_reports) > MAX_WORKERS:
                        self._gradle_reports.pop(next(iter(self._gradle_reports)))
            if row["status"] == "FAILED":
                raise ValueError(row["detail"])
            hit = gradle_report_package(
                self.repo_root,
                manifest,
                finding["component"],
                parsed,
                hinted=finding.get("installedVersion"),
            )
            if hit:
                row.update(status="RESOLVED", version=hit.version)
                row["configuration_versions"] = hit.configuration_versions
            else:
                row["detail"] = (
                    "Gradle did not report this coordinate as a resolved dependency; absence is not a false positive."
                )
                with self._gradle_lock:
                    entry[3].add(finding["id"])
            finding["dependencyResolution"] = row
            return hit
        except (OSError, ValueError, RuntimeError, SubprocessError) as exc:
            if entry is not None:
                with self._gradle_lock:
                    entry[3].add(finding["id"])
            row.update(status="FAILED", detail=str(exc))
            logger.warning("Gradle dependency inspection unavailable: %s", exc)
            finding["dependencyResolution"] = row
            return None

    def _decide(
        self, finding: dict, source_review: dict | None = None
    ) -> tuple[str, str, list[str], dict | None, str | None]:
        """Combine local evidence and advisories without guessing safe edits.

        Return a decision, reason, evidence, optional plan, and optional
        review prompt. Unknown reachability never proves a false positive.
        Major upgrades and unresolved transitive dependencies need review.
        """
        evidence = [
            "Reachability of the vulnerable code path was not determined. Unknown reachability is not treated as a false positive."
        ]
        resolution = finding.get("mainBranchResolution")
        if resolution is not None:
            pulled_sha = (self.state.pulls or [{}])[-1].get("end_head")
            if (
                resolution.get("verified") is not True
                or not pulled_sha
                or resolution.get("main_sha") != pulled_sha
            ):
                reason = (
                    "The non-main finding is not proven resolved on the current pulled main: "
                    "GitLab resolution/ref evidence is incomplete, conflicts with main, or main changed. "
                    "No local fix or false-positive dismissal is authorized."
                )
                return "MANUAL_REVIEW", reason, [reason], None, reason
            reason = (
                f"Finding {finding['id']} ({finding.get('title')}) was reported on "
                f"non-main branch {resolution['branch']} (tracked ref {resolution['tracked_ref_id']}). "
                f"GitLab explicitly reports resolvedOnDefaultBranch=true; its default branch was "
                f"verified as main at {pulled_sha}, matching this run's pulled main commit. "
                f"Location: {finding.get('location')}; identifiers: {finding.get('identifiers') or []}. "
                "This is an already-resolved-on-main finding for this main remediation run, "
                "not proof that the older branch is safe. No code change is proposed. "
                "Dismiss as FALSE_POSITIVE only if a human approves this exact branch-scoped description; "
                "GitLab main/ref/resolution evidence is rechecked immediately before dismissal."
            )
            return "FALSE_POSITIVE", reason, [reason], None, None
        category = finding.get("category") or ""
        component = finding.get("component")
        location_file = (finding.get("location") or {}).get("file")
        kind = config_kind(location_file if isinstance(location_file, str) else None)
        if category == "sast" or (kind and category == "iac_scanning"):
            self._progress(
                finding.get("id"), "Reading cited source/configuration evidence"
            )
            assessment = assess_source(self.repo_root, finding, source_review)
            config_confirm = bool(
                kind and assessment["decision"] == "CONFIRMED_VULNERABILITY"
            )
            if (
                source_review is not None
                and assessment["decision"] == source_review.get("decision")
                and not config_confirm
            ):
                doc_review = self._documentation().read_for_source(
                    finding, run_key=self._source_documentation_key
                )
                publishers_ok = (
                    isinstance(doc_review, DocReview) and doc_review.complete
                )
                cited_ok = isinstance(
                    doc_review, DocReview
                ) and cited_security_pages_ok(doc_review, finding)
                assessment["evidence"].append(
                    doc_review.reason()
                    if isinstance(doc_review, DocReview)
                    else "Official documentation was not read."
                )
                block = not publishers_ok or (
                    assessment["decision"] == "FALSE_POSITIVE" and not cited_ok
                )
                if block:
                    assessment["decision"] = "SOURCE_REVIEW_REQUIRED"
                    assessment["reason"] = (
                        "Language, Dockerfile, nginx, CVE, or CWE documentation "
                        "was not read, so the source conclusion was not accepted."
                        if not publishers_ok
                        else "CVE/CWE record documentation is incomplete: a required record "
                        "receipt is missing, failed, or outside the bounded fetch limit. "
                        "The source conclusion was not accepted."
                    )
                    assessment["workflow"] = {
                        **assessment["workflow"],
                        "status": "SOURCE_REVIEW_REQUIRED",
                    }
                assessment["workflow"]["documentation"] = (
                    doc_review.as_list() if isinstance(doc_review, DocReview) else []
                )
                if assessment["decision"] == "FALSE_POSITIVE":
                    try:
                        assessment["reason"] = audit_false_positive_comment(
                            finding,
                            source_review,
                            assessment["workflow"]["documentation"],
                        )
                    except ValueError as exc:
                        assessment["decision"] = "SOURCE_REVIEW_REQUIRED"
                        assessment["reason"] = (
                            f"{exc}. The source conclusion was not accepted."
                        )
                        assessment["workflow"] = {
                            **assessment["workflow"],
                            "status": "SOURCE_REVIEW_REQUIRED",
                        }
            finding["sourceWorkflow"] = assessment["workflow"]
            if kind and assessment["decision"] == "CONFIRMED_VULNERABILITY":
                return self._decide_config(finding, assessment["evidence"])
            return (
                assessment["decision"],
                assessment["reason"],
                assessment["evidence"],
                None,
                "Follow source_workflow.steps for this finding."
                if assessment["decision"]
                in {
                    "SOURCE_REVIEW_REQUIRED",
                    "MANUAL_REVIEW",
                    "CONFIRMED_VULNERABILITY",
                }
                else None,
            )
        if source_review is not None:
            raise ValueError(
                "source_review is only supported for source/configuration SAST or IaC findings"
            )
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
                "production builds and unit tests. Both must pass; "
                "isolate and revert only offending package updates. Retain before/after evidence. "
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
                "Follow fuzzing_workflow.steps. Do not replay payloads against the remote host."
            )
            return "REPRODUCTION_REQUIRED", reason, evidence, None, prompt
        if finding.get("falsePositiveFlag") is True:
            evidence.append(
                "GitLab marked falsePositive=true. That flag alone is not sufficient; local evidence is required."
            )
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
                    "MANUAL_REVIEW",
                    f"{location_file} is not present in the repository. Missing source alone does not establish a false positive.",
                    evidence,
                    None,
                    self._prompt(
                        finding,
                        None,
                        "The cited source is missing; the finding remains unresolved.",
                    ),
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
        if hit is None and category == "dependency_scanning" and component:
            self._progress(
                finding.get("id"), "Inspecting the resolved Gradle dependency tree"
            )
            hit = self._resolve_gradle_package(finding, files)
            if (
                hit is None
                and (finding.get("dependencyResolution") or {}).get("manager")
                != "gradle"
            ):
                hit = self._resolve_maven_package(finding, files)
            if resolution := finding.get("dependencyResolution"):
                evidence.append(
                    f"{'Maven' if resolution['manager'] == 'maven' else 'Gradle'} dependency inspection: {resolution['status']}. "
                    + (
                        resolution.get("detail")
                        or f"Selected version {resolution.get('version')}."
                    )
                )
        local_review_reason = None
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
                local_review_reason = "The package was not resolved locally. Java and NuGet manifests do not enumerate every transitive dependency; manual dependency-tree review is required."
            else:
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
        if local_review_reason and component:
            if Path(str(location_file or "")).suffix.lower() in {
                ".csproj",
                ".fsproj",
                ".vbproj",
            }:
                ecosystem = "NuGet"
            elif (
                ":" in component or ("/" in component and not component.startswith("@"))
            ) and any(
                path.name in {"build.gradle", "build.gradle.kts", "pom.xml"}
                for path in files
            ):
                ecosystem, package_name = "Maven", component.replace("/", ":")
            elif any(
                path.suffix.lower() in {".csproj", ".fsproj", ".vbproj"}
                for path in files
            ):
                ecosystem = "NuGet"
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

        if re.search(
            r"\bupgrad(?:e|ing)\s+alone\s+(?:does\s+not|will\s+not|won't)\s+(?:fix|resolve|remediate)\b",
            " ".join((finding.get("description") or "", finding.get("solution") or "")),
            flags=re.IGNORECASE,
        ):
            reason = "The advisory explicitly warns that upgrading alone does not fix affected code. Review actual callers and required source changes; a version-only update cannot establish remediation."
            return (
                "MANUAL_REVIEW",
                reason,
                [*evidence, reason],
                None,
                self._prompt(finding, looked_up, reason),
            )
        if local_review_reason:
            return (
                "MANUAL_REVIEW",
                local_review_reason,
                [*evidence, local_review_reason],
                None,
                self._prompt(finding, looked_up, local_review_reason),
            )

        if (
            category == "dependency_scanning"
            and hit is not None
            and (component.replace("/", ":") if ecosystem == "Maven" else component)
            == hit.name
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

        if (
            looked_up.affected is False
            and hit is not None
            and len(
                {
                    version
                    for versions in (hit.configuration_versions or {}).values()
                    for version in versions
                }
            )
            > 1
        ):
            reason = "The scanner version is reported unaffected, but other configuration versions have not been assessed. Review every resolved classpath before dismissing this package finding."
            return (
                "MANUAL_REVIEW",
                reason,
                [*evidence, reason],
                None,
                self._prompt(finding, looked_up, reason),
            )
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
            if looked_up.affected is None:
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
            if hit and hit.manager == "gradle" and not hit.direct:
                reason = f"The resolved transitive dependency {hit.name} at {installed} has fixed target {fixed}, but no supported coordinate-specific edit could be planned."
                return (
                    "MANUAL_REVIEW",
                    reason,
                    [*evidence, reason],
                    None,
                    self._prompt(finding, looked_up, reason),
                )
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
                "Candidate only: version numbering does not establish framework/API compatibility or license suitability. qualify_package_update requires documented license review or a configured corporate policy. Apply all reviewed updates, then require passing production builds, unit tests and configured policy checks. Isolate and revert offending updates; retain passing updates."
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
            return (
                "MANUAL_REVIEW",
                assessment.reason
                + " A missing configuration file alone does not establish a false positive.",
                evidence,
                None,
                self._prompt(finding, None, assessment.reason),
            )
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
            + (
                f"Public advisory fixed target: {looked_up.lowest_fixed_version}. "
                if looked_up and looked_up.lowest_fixed_version
                else ""
            )
            + "Tell the agent the fixed version to apply, or confirm that this is a false positive. "
            "This finding is skipped and the remaining findings continue."
        )

    def _progress(self, finding_id: str | None, step: str) -> None:
        """Emit bounded, single-line progress without scanner payloads or review contents."""
        with self._lock:
            self._progress_locked(finding_id, step)

    def _progress_locked(self, finding_id: str | None, step: str) -> None:
        """Assign progress ordinals while holding the engine's state lock."""
        finding = self._finding(finding_id) if finding_id else None
        label = " ".join(str(finding_id or "run").split())[:200]
        package = " ".join(str((finding or {}).get("component") or "N/A").split())[:200]
        repository = " ".join(str(self.repo_root).split())[:500]
        step = " ".join(step.split())[:500]
        if (
            finding_id is not None
            and finding is not None
            and self.state.status in AFTER_BRANCH
        ):
            severity = _progress_severity(finding)
            if finding_id not in self._finding_progress:
                ordinal = 1 + sum(
                    group == severity for group, _ in self._finding_progress.values()
                )
                self._finding_progress[finding_id] = (severity, ordinal)
            severity, ordinal = self._finding_progress[finding_id]
            total = sum(
                _progress_severity(item) == severity for item in self.state.findings
            )
            step = f"Processing {ordinal} of {total} {PROGRESS_SEVERITIES[severity]} | {step}"
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
