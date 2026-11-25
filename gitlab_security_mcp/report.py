"""Human and JSON reports. The false-positive, no-solution, and skip sections are mandatory."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.parse import quote

from gitlab_security_mcp.gitlab_client import dismissal_is_confirmed
from gitlab_security_mcp.software_audit import project_file_name
from gitlab_security_mcp.source_findings import pending_source_reviews
from gitlab_security_mcp.state import RunState, summarize_trees
from gitlab_security_mcp.util import atomic_write_text
from gitlab_security_mcp.workflow import JOB_REPORT

_NO_OTHER_UNRESOLVED_ROW = (
    "| None reported | No other unresolved or unattempted code findings |"
)
_AUDIT_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_BLOCKED_TARGET = "None eligible (blocked)"
_BLOCKED_TARGET_WITH_FLOOR = "None eligible (blocked; advisory floor {})"
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_PATH_LINE = re.compile(r"(?P<path>[^:\s][^:]*?):(?P<line>\d+)(?:-\d+)?")
_AUDIT_NOT_SELECTED = "Not selected for an AI fix; still needs a fix."
_AUDIT_SECTION_INTRO = (
    "The software audit confirmed these findings, but they were not selected "
    "for an AI fix, so no code was changed. Each one still needs a fix."
)
_AUDIT_REPORT_LINK = (
    "Evidence, affected lines and the recommended change for each finding are in "
    "the [software audit report]({})."
)
UNRESOLVED_REPORT_NAME = "unresolved-remediation.md"
REMEDIATION_REPORT_STEM = "security-remediation-report-"
_REPORT_PREFIX_SEPARATOR = "-"


def report_prefix(root: Path, state: RunState) -> str:
    """Name reports after the GitLab project, falling back to the checkout folder."""
    return (
        project_file_name(state.gitlab_project_path, root.name)
        + _REPORT_PREFIX_SEPARATOR
    )


def _audit_location_cell(root: Path, report_dir: Path, location: str) -> str:
    """Link an audit location to its checkout file from the unresolved report.

    Audit reports link relative to the home-directory audit report, so their
    targets break here; rebuild the link from the label's path and line. A
    location that does not name an existing checkout file stays plain text.
    """
    linked = _MARKDOWN_LINK.fullmatch(location.strip())
    label = linked.group(1) if linked else location.strip()
    parsed = _PATH_LINE.fullmatch(label)
    if parsed is None:
        return _table_cell(location)
    target = (root / parsed.group("path")).resolve()
    if not target.is_file() or not target.is_relative_to(root.resolve()):
        return _table_cell(label)
    relative = Path(os.path.relpath(target, report_dir.resolve())).as_posix()
    return f"[{_table_cell(label)}]({quote(relative)}#L{parsed.group('line')})"


def _unselected_audit_section(root: Path, state: RunState) -> list[str]:
    """List every confirmed audit finding the human did not select, with its fix target."""
    audit = state.software_audit
    selected = {item["id"] for item in audit.get("selected_items", [])}
    items = sorted(
        (item for item in audit.get("items", []) if item["id"] not in selected),
        key=lambda item: _AUDIT_SEVERITY_ORDER.get(
            str(item.get("severity", "")).lower(), len(_AUDIT_SEVERITY_ORDER)
        ),
    )
    if not items:
        return []
    lines = ["", "## Software audit findings not fixed", "", _AUDIT_SECTION_INTRO]
    if audit.get("output_path"):
        lines.append(
            _AUDIT_REPORT_LINK.format(Path(audit["output_path"]).resolve().as_uri())
        )
    lines.extend(
        [
            "",
            "| Finding | Severity | Location | Problem | Status |",
            "|---|---|---|---|---|",
        ]
    )
    report_dir = root / ".security-mcp" / "reports"
    for item in items:
        cells = (
            _table_cell(item["id"]),
            _table_cell(item.get("severity") or "Not stated"),
            _audit_location_cell(root, report_dir, item["location"])
            if item.get("location")
            else "Not stated",
            _table_cell(item.get("problem") or "Not stated"),
            _AUDIT_NOT_SELECTED,
        )
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def _table_cell(value: object) -> str:
    """Escape pipes and line breaks so evidence stays in one table cell."""
    return " ".join(str(value if value is not None else "N/A").splitlines()).replace(
        "|", "\\|"
    )


def _finding_label(finding: dict) -> str:
    """Keep same-title findings distinct by identifier and scanner location."""
    location = finding.get("location") or {}
    source = location.get("file") or location.get("path")
    if source and location.get("startLine"):
        source = f"{source}:{location['startLine']}"
    return f"{finding.get('id')}: {finding.get('title') or 'Untitled finding'}" + (
        f" ({source})" if source else ""
    )


def _dismissal_summary(item: dict) -> str:
    """Separate persisted GitLab proof from an old mutation acknowledgement."""
    confirmed = dismissal_is_confirmed(item)
    status = (
        "DISMISSED (independently verified)"
        if confirmed
        else "UNVERIFIED"
        if item.get("status") == "DISMISSED"
        else item.get("status")
    )
    text = f"- {_table_cell(item['id'])}: {_table_cell(status)}; FALSE_POSITIVE."
    if confirmed:
        text += f" Verified at {_table_cell(item['verification']['verified_at'])}."
    if item.get("tracked_ref"):
        text += f" Tracked ref: {_table_cell(item['tracked_ref'].get('name'))}."
    if item.get("vulnerability_url"):
        text += f" [GitLab vulnerability]({item['vulnerability_url']})."
    if item.get("error"):
        text += f" Error: {_table_cell(item['error'])}"
    if not confirmed:
        text += " Check GitLab before retrying; the remote outcome may be unknown."
    return text


def _unit_test_validation(state: RunState) -> dict:
    """Report only the current batch's observed unit-test evidence."""
    rows = [
        row
        for row in state.validation_results
        if row.get("kind") in {"unit_tests", "build_and_unit_tests"}
    ]
    if not rows:
        return {
            "status": "NOT_RUN",
            "reason": "MCP-managed validation does not run unit/integration tests. This server has no test evidence; checks run separately by the host or developer are outside this result. Test compatibility was not verified by MCP.",
        }
    if any(row["status"] == "FAILED" for row in rows):
        return {
            "status": "FAILED",
            "reason": "Unit-test validation failed; affected package updates are not accepted.",
        }
    if any(row["status"] != "PASSED" for row in rows):
        return {
            "status": "INCOMPLETE",
            "reason": "Unit-test evidence is incomplete. Test compatibility was not verified.",
        }
    return {
        "status": "PASSED",
        "reason": "Executed unit tests passed for the validated checkout.",
    }


def _validation_caveats(state: RunState) -> list[dict]:
    """Keep non-green checks and inspection warnings separate from product acceptance."""
    caveats = []
    for phase, rows in (
        ("Pre-change lint", (state.lint_baseline or {}).get("results") or []),
        ("Optional check", state.validation_results),
    ):
        for row in rows:
            if row.get("status") == "PASSED" or (
                phase == "Optional check" and row.get("required", True)
            ):
                continue
            item = {"phase": phase}
            for key in (
                "status",
                "command",
                "detail",
                "exit_code",
                "stdout_log_path",
                "stderr_log_path",
            ):
                if key in row:
                    item[key] = row[key]
            if row.get("diagnostics"):
                item["diagnostic_counts"] = {
                    kind: len(entries) for kind, entries in row["diagnostics"].items()
                }
            caveats.append(item)
    seen = set()
    for finding in state.findings:
        inspection = finding.get("dependencyResolution") or {}
        for warning in inspection.get("warnings") or []:
            identity = (
                inspection.get("command"),
                inspection.get("stdout_log_path"),
                warning,
            )
            if identity in seen:
                continue
            seen.add(identity)
            item = {
                "phase": "Dependency inspection",
                "status": "WARNING",
                "detail": warning,
            }
            for key in ("command", "stdout_log_path", "stderr_log_path"):
                if inspection.get(key):
                    item[key] = inspection[key]
            caveats.append(item)
    return caveats


def _unresolved_issues(state: RunState) -> list[dict]:
    """Collect unique unresolved findings using the latest fix outcomes."""
    reasons = {
        item["id"]: item for item in [*state.no_solution, *state.skipped_user_prompt]
    }
    outcomes = {}
    for change in state.changes:
        if change.get("status") != "TEST_ADDED":
            outcomes[change.get("finding_id")] = change
    unresolved = []
    seen = set()
    for finding in state.findings:
        finding_id = finding.get("id")
        if finding_id in seen:
            continue
        seen.add(finding_id)
        assessment = state.decisions.get(finding_id) or finding.get("assessment") or {}
        host_result = (
            state.workflow.get("code_results", {}).get(f"gitlab:{finding_id}") or {}
        )
        if host_result.get("status") == "fixed":
            continue
        decision = assessment.get("decision") or finding.get("remediationDecision")
        outcome = outcomes.get(finding_id) or {}
        qualification = finding.get("packageQualification") or {}
        release = (finding.get("proposedFix") or {}).get("release_selection") or {}
        advisory_warning = (
            release.get("advisory_warning")
            if outcome.get("status") == "APPLIED"
            else None
        )
        pending = (
            outcome.get("package_update")
            and outcome.get("qualification_status") != "VALIDATED"
        ) or outcome.get("validation_pending", False)
        required = (finding.get("proposedFix") or {}).get("qualifiers") and outcome.get(
            "status"
        ) != "APPLIED"
        unapplied = decision == "CHANGE_REQUIRED" and outcome.get("status") != "APPLIED"
        if decision == "FALSE_POSITIVE" or (
            outcome.get("status") == "APPLIED" and not pending and not advisory_warning
        ):
            continue
        failed = (
            outcome.get("status")
            in {"FIX_FAILED", "FIX_FAILED_LOCKFILE", "ROLLED_BACK"}
            or qualification.get("status") == "REJECTED"
        )
        if (
            decision
            not in {
                "NO_SAFE_FIX",
                "MANUAL_REVIEW",
                "REPRODUCTION_REQUIRED",
                "SOURCE_REVIEW_REQUIRED",
                "CONFIRMED_VULNERABILITY",
                "CHANGE_REQUIRED",
            }
            and finding_id not in reasons
            and not failed
            and not pending
            and not required
        ):
            continue
        detail = reasons.get(finding_id) or {}
        selection = (
            state.workflow.get("package_selection", {})
            if "ecosystem" in (finding.get("proposedFix") or {})
            else state.fix_selection
        ) or state.fix_selection
        unselected = (
            selection.get("status") in {"APPROVED", "SKIPPED", "UNAVAILABLE", "INVALID"}
            and finding_id in selection.get("candidate_ids", [])
            and finding_id not in selection.get("selected_ids", [])
        )
        unresolved.append(
            {
                "id": finding_id,
                "severity": finding.get("severity") or "unknown",
                "component": finding.get("component"),
                "installed_version": finding.get("installedVersion"),
                "title": finding.get("title") or finding_id,
                "identifiers": finding.get("identifiers") or [],
                "security_validation_sites": sorted(
                    set(finding.get("securityValidationSites") or [])
                ),
                "location": finding.get("location") or {},
                "decision": outcome.get("status") if failed else decision,
                "reason": host_result.get("reason")
                or (outcome.get("detail") if failed or pending else None)
                or advisory_warning
                or (
                    "No remediation edit was authorized for this finding. "
                    + (
                        selection.get("reason")
                        or "The human did not select this issue."
                    )
                    if unselected
                    else None
                )
                or qualification.get("reason")
                or (
                    "The verified fix candidate has not been applied. Qualification and successful post-update validation are still required."
                    if unapplied
                    else None
                )
                or (
                    "Security fix requires reviewed evidence and successful post-update product checks."
                    if pending or required
                    else None
                )
                or detail.get("reason")
                or assessment.get("reason")
                or "No safe package or code update was identified.",
            }
        )
    return unresolved


def write_unresolved_report(root: Path, state: RunState) -> dict:
    """Write the final job's package blockers and explicit unsuccessful code outcomes."""
    unresolved = _unresolved_issues(state)
    findings = {item["id"]: item for item in state.findings}
    reviews = state.workflow.get("package_reviews") or {}
    lines = [
        "# Unresolved remediation",
        "",
        "Local results only. Nothing was committed or pushed. Host code-fix outcomes are attestations, not independent MCP validation or GitLab resolution.",
        "",
        "## Unresolved package updates",
        "| Finding / package | Current | Proposed target | Blocker or verification limitation |",
        "|---|---|---|---|",
    ]
    package_ids = set()
    for item in unresolved:
        finding = findings[item["id"]]
        plan = finding.get("proposedFix") or {}
        if not (
            plan.get("ecosystem")
            or finding.get("category") in {"dependency_scanning", "container_scanning"}
        ):
            continue
        package_ids.add(item["id"])
        version_review = finding.get("packageVersionSelection") or {}
        reason = reviews.get(item["id"], {}).get("blocked_reason")
        blocked = bool(reason) or version_review.get("status") == "BLOCKED"
        if not reason and version_review.get("status") == "BLOCKED":
            reason = (version_review.get("review") or {}).get("assessment")
        target = plan.get("target")
        if blocked:
            # The plan keeps the advisory floor; a blocked review rejected it as a target.
            target = (
                _BLOCKED_TARGET_WITH_FLOOR.format(target) if target else _BLOCKED_TARGET
            )
        cells = (
            f"{item['id']}: {plan.get('package') or finding.get('component') or finding.get('title')}",
            plan.get("installed")
            or finding.get("installedVersion")
            or item["installed_version"]
            or "Not established",
            target or "No verified eligible target",
            reason or item["reason"],
        )
        lines.append("| " + " | ".join(_table_cell(cell) for cell in cells) + " |")
    if not package_ids:
        lines.append(
            "| None recorded | - | - | No unresolved package updates recorded; this is not a guarantee of no vulnerabilities. |"
        )
    lines.extend(
        [
            "",
            "## Code fixes attempted but not completed",
            "| Origin / finding | Outcome | Why it could not be fixed | Validation |",
            "|---|---|---|---|",
        ]
    )
    results = state.workflow.get("code_results") or {}
    failed = [item for item in results.values() if item["status"] == "failed"]
    for item in failed:
        lines.append(
            "| "
            + " | ".join(
                _table_cell(cell)
                for cell in (
                    f"{item['origin']}: {item['id']}",
                    "Failed",
                    item["reason"],
                    item.get("validation") or "Not reached; see blocker",
                )
            )
            + " |"
        )
    if not failed:
        lines.append("| None reported | - | No failed code attempts recorded | - |")
    lines.extend(
        [
            "",
            "## Other unresolved or unattempted code findings",
            "| Finding | Reason |",
            "|---|---|",
        ]
    )
    failed_ids = {item["id"] for item in failed if item["origin"] == "gitlab"}
    other_rows = len(lines)
    for item in unresolved:
        if item["id"] not in package_ids | failed_ids:
            lines.append(
                f"| {_table_cell(item['id'])} | {_table_cell(item['reason'])} |"
            )
    if len(lines) == other_rows:
        lines.append(_NO_OTHER_UNRESOLVED_ROW)
    lines.extend(_unselected_audit_section(root, state))
    lines.extend(["", "## Workflow jobs"])
    for job in state.workflow.get("jobs", []):
        status = "FINISHED" if job["number"] == JOB_REPORT else job["status"]
        lines.append(f"- {job['number']}. {job['label']}: {status}")
    if state.workflow.get("blocked"):
        lines.extend(["", f"Run blocker: {_table_cell(state.workflow['blocked'])}"])
    if state.report_path:
        lines.extend(["", f"[Full security report]({Path(state.report_path).name})"])
    path = (
        root
        / ".security-mcp"
        / "reports"
        / f"{report_prefix(root, state)}{UNRESOLVED_REPORT_NAME}"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    markdown = "\n".join(lines) + "\n"
    atomic_write_text(path, markdown)
    return {
        "status": "WORKFLOW_COMPLETE",
        "report_path": str(path),
        "final_summary_markdown": markdown,
        "message": f"Display this Markdown report to the developer: {path}. Package blockers and unsuccessful code attempts remain unresolved.",
    }


def render(
    state: RunState, *, staged: list[str] | None, diff_stat: str, diff_files: str
) -> tuple[dict, str]:
    """Build the JSON payload and markdown text for one run.

    ``staged`` is None when git could not be read. The report then says the
    index state is unknown instead of claiming that nothing is staged.
    """
    cached_empty = None if staged is None else staged == []
    review_queue = pending_source_reviews(state.findings, state.decisions)
    assessed_false_positives = {
        finding["id"]
        for finding in state.findings
        if state.decisions.get(finding["id"], {}).get("decision") == "FALSE_POSITIVE"
    }
    dismissed = {
        item["id"] for item in state.gitlab_dismissals if dismissal_is_confirmed(item)
    }
    pending_dismissals = assessed_false_positives - dismissed
    dismissal_review = {
        "status": "PENDING_HUMAN_REVIEW" if pending_dismissals else "NONE_PENDING",
        "assessed_false_positives": len(assessed_false_positives),
        "previously_confirmed_dismissals": len(assessed_false_positives & dismissed),
        "not_confirmed_dismissed": len(pending_dismissals),
        "next_tool": "submit_false_positive_approvals" if pending_dismissals else None,
    }
    approval_notice = (
        f"{len(pending_dismissals)} locally assessed false positives have no confirmed GitLab dismissal. "
        "Completion automatically offers the human checkbox form after saving this report. "
        "Cancel to continue reviewing; explicitly request submit_false_positive_approvals to reopen it later. "
        "Local assessment is not dismissal; only the human can approve remote changes."
    )
    unverified = [
        item.get("id")
        for item in state.findings
        if item.get("id") not in state.decisions
    ]
    false_positive_bullets = [
        f"- {item['id']} — {item.get('component') or 'N/A'}: false positive because {item['reason']}"
        for item in state.false_positives
    ] or ["False positives: none identified."]
    no_solution_bullets = [
        f"- {item['id']} — {item.get('component') or 'N/A'}: {item['reason']}"
        for item in state.no_solution
    ] or ["No-solution issues: none."]
    skipped_bullets = [
        f"- {item['id']}: {item['reason']}" for item in state.skipped_user_prompt
    ] or ["None."]
    unresolved = _unresolved_issues(state)
    unresolved_lines = [
        "| Severity | Package | Version | Issue | Reason Not Addressed | Security Validation Sites |",
        "|---|---|---|---|---|---|",
    ]
    for item in unresolved:
        identifiers = ", ".join(
            identifier
            for identifier in item["identifiers"]
            if identifier.upper().startswith(("CVE-", "GHSA-"))
        )
        label = _finding_label(item)
        issue = f"{identifiers}: {label}" if identifiers else label
        cells = [
            item["severity"],
            item["component"],
            item["installed_version"],
            issue,
            item["reason"],
            ", ".join(item["security_validation_sites"]) or "Not recorded",
        ]
        unresolved_lines.append(
            "| " + " | ".join(_table_cell(cell) for cell in cells) + " |"
        )
    unresolved_table = (
        "\n".join(unresolved_lines)
        if unresolved
        else "No verified findings are currently recorded as unresolved. Unverified findings, if any, are listed above."
    )
    unresolved_by_id = {item["id"]: item for item in unresolved}
    false_positives_by_id = {item["id"]: item for item in state.false_positives}
    latest_changes = {
        item.get("finding_id"): item
        for item in state.changes
        if item.get("status") != "TEST_ADDED"
    }
    assessments = []
    seen = set()
    for finding in state.findings:
        finding_id = finding.get("id")
        if finding_id in seen:
            continue
        seen.add(finding_id)
        assessment = (
            unresolved_by_id.get(finding_id)
            or state.decisions.get(finding_id)
            or finding.get("assessment")
            or {}
        )
        decision = assessment.get("decision") or "NOT_VERIFIED"
        reason = (
            assessment.get("reason")
            or false_positives_by_id.get(finding_id, {}).get("reason")
            or "No verification evidence recorded; not established as resolved."
        )
        change = latest_changes.get(finding_id) or {}
        if finding_id not in unresolved_by_id and change.get("status") == "APPLIED":
            decision = "APPLIED"
            reason = change.get("detail") or (
                "Applied locally; consult the recorded validation results. "
                "GitLab finding status was not changed."
            )
        assessments.append(
            {
                "id": finding_id,
                "issue": _finding_label(finding),
                "severity": finding.get("severity") or "unknown",
                "decision": decision,
                "reason": reason,
            }
        )
    assessment_lines = [
        "| Finding / Location | Severity | Decision | Reason |",
        "|---|---|---|---|",
        *(
            "| "
            + " | ".join(
                _table_cell(item[key])
                for key in ("issue", "severity", "decision", "reason")
            )
            + " |"
            for item in assessments
        ),
    ]
    assessments_table = "\n".join(assessment_lines) if assessments else "No findings."
    finding_pipelines = {
        finding["id"]: finding["pipeline"]
        for finding in state.findings
        if finding.get("pipeline")
    }
    payload = {
        "run_status": state.status,
        "server_version": state.server_version,
        "stop_stage": state.stop_stage,
        "branch": state.branch_name,
        "pipeline": state.pipeline,
        "finding_pipelines": finding_pipelines,
        "findings_total": len(state.findings),
        "review_status": review_queue["status"],
        "source_review_queue": review_queue,
        "http_timings_file": ".security-mcp/http-timings.jsonl",
        "findings_truncated": state.findings_truncated,
        "security_validation_sites": {
            finding["id"]: sorted(set(finding.get("securityValidationSites") or []))
            for finding in state.findings
        },
        "dependency_resolutions": {
            finding["id"]: finding["dependencyResolution"]
            for finding in state.findings
            if finding.get("dependencyResolution")
        },
        "unverified_findings": unverified,
        "excluded_findings": state.excluded_findings,
        "decisions": {
            key: value.get("decision") for key, value in state.decisions.items()
        },
        "changes_made": state.changes,
        "fix_selection": state.fix_selection,
        "validation_status": state.validation_status,
        "unit_test_validation": _unit_test_validation(state),
        "validation": state.validation_results,
        "validation_caveats": _validation_caveats(state),
        "batch_isolation": state.batch_isolation,
        "lint_baseline": summarize_trees(state.lint_baseline),
        "lint_issues_file": ".security-mcp/lint-issues.json"
        if state.lint_baseline is not None
        else None,
        "lint_rules_file": ".security-mcp/lint-rules.json"
        if state.lint_baseline is not None
        else None,
        "package_qualifications": {
            finding.get("id"): {
                key: qualification.get(key)
                for key in (
                    "status",
                    "reason",
                    "plan",
                    "review",
                    "major_review",
                    "approval",
                    "policy_mode",
                    "license_review",
                    "warnings",
                    "policy_sha256",
                    "baseline_results",
                    "post_results",
                    "rejection_diagnostics",
                    "check_contract",
                    "rollback",
                    "version_alignment_files",
                )
            }
            for finding in state.findings
            if (qualification := finding.get("packageQualification"))
        },
        "package_version_selections": {
            finding.get("id"): finding["packageVersionSelection"]
            for finding in state.findings
            if finding.get("packageVersionSelection")
        },
        "license_investigations": {
            finding.get("id"): finding["licenseInvestigation"]
            for finding in state.findings
            if finding.get("licenseInvestigation")
        },
        "false_positives": false_positive_bullets,
        "false_positive_details": state.false_positives,
        "no_solution_issues": no_solution_bullets,
        "no_solution_details": state.no_solution,
        "user_prompt_skipped": skipped_bullets,
        "user_prompt_details": state.skipped_user_prompt,
        "fuzzing_workflows": {
            finding.get("id"): finding["fuzzingWorkflow"]
            for finding in state.findings
            if finding.get("fuzzingWorkflow")
        },
        "source_workflows": {
            finding.get("id"): finding["sourceWorkflow"]
            for finding in state.findings
            if finding.get("sourceWorkflow")
        },
        "source_reviews": {
            finding.get("id"): finding["sourceReview"]
            for finding in state.findings
            if finding.get("sourceReview")
        },
        "false_positive_audits": {
            finding.get("id"): finding["falsePositiveAudit"]
            for finding in state.findings
            if finding.get("falsePositiveAudit")
        },
        "finding_assessments": assessments,
        "finding_assessments_table": assessments_table,
        "gitlab_dismissals": state.gitlab_dismissals,
        "false_positive_review_tool": "submit_false_positive_approvals",
        "false_positive_approval": dismissal_review,
        "false_positive_approval_form": state.false_positive_approval_form,
        "unresolved_issues": unresolved,
        "unresolved_issues_table": unresolved_table,
        "git_diff_cached_empty": cached_empty,
        "staged_paths": staged,
        "diff_stat": diff_stat,
        "diff_files": diff_files,
        "developer_next_steps": [
            "Review the unstaged diff. This server did not run git add, commit, or push.",
            "Confirm the validation results.",
            "Manually stage, commit, and push if the diff is acceptable.",
            "Use submit_false_positive_approvals for human-approved false-positive dismissals, or update GitLab manually. Local assessments alone do not change GitLab.",
        ],
    }
    lines = [
        "# Security remediation report",
        "",
        f"Server version: {state.server_version}",
        f"Status: {state.status}",
        f"Stop stage: {state.stop_stage or 'none'}",
        f"Branch: {state.branch_name or 'not created'}",
        (
            "Pipeline: recorded per finding (see Pipeline provenance)."
            if not state.pipeline and finding_pipelines
            else f"Pipeline: {(state.pipeline or {}).get('id') or 'unknown'} @ {(state.pipeline or {}).get('sha') or 'unknown'}"
        ),
        f"Findings considered: {len(state.findings)}",
        "",
        "## Human Code-Fix Selection",
        f"Status: {_table_cell(state.fix_selection.get('status') or 'NOT_REQUESTED')}",
        f"Selected issue IDs: {_table_cell(', '.join(state.fix_selection.get('selected_ids', [])) or 'none')}",
        f"Automatic package execution: {_table_cell((state.fix_selection.get('package_execution') or {}).get('status') or 'NOT_STARTED')}",
        *(
            [
                f"Execution blocker: {_table_cell(state.fix_selection['package_execution']['reason'])}",
            ]
            if (state.fix_selection.get("package_execution") or {}).get("reason")
            else []
        ),
        *(
            [
                f"- {_table_cell(item.get('finding_id') or 'batch')}: {_table_cell(item['stage'])} = {_table_cell(item['status'])}"
                + (
                    f" ({_table_cell(item['duration_ms'])} ms)"
                    if "duration_ms" in item
                    else ""
                )
                + (f": {_table_cell(item['reason'])}" if item.get("reason") else "")
                for item in (state.fix_selection.get("package_execution") or {}).get(
                    "results", []
                )
            ]
        ),
        "Only human-selected issues authorize remediation edits. Unselected issues are not thereby false positives.",
        "",
        *(
            [
                "Warning: GitLab returned more findings than this run fetched. The list is incomplete."
            ]
            if state.findings_truncated
            else []
        ),
        *(
            [f"Not verified: {', '.join(str(item) for item in unverified)}"]
            if unverified
            else []
        ),
        "",
        (
            "Nothing was staged, committed, or pushed. GitLab dismissal attempts and confirmed outcomes are listed below."
            if state.gitlab_dismissals
            else "This run is local only. Nothing was staged, committed, pushed, or changed in GitLab."
        ),
        *(
            [
                "",
                "## Pipeline provenance",
                "| Finding | Pipeline | SHA | Ref |",
                "|---|---|---|---|",
                *(
                    "| "
                    + " | ".join(
                        _table_cell(value)
                        for value in (
                            finding_id,
                            pipeline.get("id"),
                            pipeline.get("sha"),
                            pipeline.get("ref"),
                        )
                    )
                    + " |"
                    for finding_id, pipeline in finding_pipelines.items()
                ),
            ]
            if finding_pipelines
            else []
        ),
        "",
        "## False positives",
        *([approval_notice, ""] if pending_dismissals else []),
        *false_positive_bullets,
        "",
        "## Issues with no solution at this time",
        *no_solution_bullets,
        "",
        "## Skipped (require user input / not resolved by online lookups)",
        *skipped_bullets,
        "",
        "## Fuzzing findings requiring reproduction",
        *(
            [
                f"- {_table_cell(finding_id)}: {_table_cell(workflow['status'])}. "
                "Local reproduction, source review and before/after checks are required."
                for finding_id, workflow in payload["fuzzing_workflows"].items()
            ]
            or ["None."]
        ),
        "",
        "## Changes",
    ]
    if state.changes:
        for change in state.changes:
            lines.append(
                f"- {change.get('finding_id')}: {change.get('status')} — {change.get('description')} "
                f"({', '.join(change.get('files') or []) or 'no files'})"
            )
            if "edit_duration_ms" in change:
                lines.append(
                    f"  Edit/reuse and lockfile refresh: {change['edit_duration_ms']} ms "
                    "(excludes documentation review, pre-edit lint and subsequent validation)."
                )
            if change.get("reused_from"):
                lines.append(
                    f"  Shares the unchanged edit from {change['reused_from']}; no additional dependency write or install."
                )
    else:
        lines.append(
            "No MCP-managed remediation edits were recorded. "
            "Any host/manual working-tree changes are listed under Working tree."
        )
    lines.extend(
        [
            "",
            "## Pre-change Lint Issues",
            ".security-mcp/lint-issues.json"
            if state.lint_baseline is not None
            else "Not recorded.",
            "Observed rule names: .security-mcp/lint-rules.json"
            if state.lint_baseline is not None
            else "No rule inventory recorded.",
            "Existing lint issues are recorded separately from final batch build acceptance.",
        ]
    )
    if payload["dependency_resolutions"]:
        lines.extend(["", "## Gradle Dependency Inspections"])
        for finding_id, inspection in payload["dependency_resolutions"].items():
            lines.append(
                f"- {finding_id}: {inspection['status']}; {inspection.get('version') or inspection.get('detail') or 'version unknown'}."
            )
            for scope, versions in (
                inspection.get("configuration_versions") or {}
            ).items():
                lines.append(f"  {scope}: {', '.join(versions)}")
            for key in ("command", "stdout_log_path", "stderr_log_path"):
                if inspection.get(key):
                    lines.append(f"  {key}: {inspection[key]}")
    lines.extend(["", "## Package Release and Licensing Investigation"])
    for finding_id, investigation in payload["license_investigations"].items():
        lines.append(
            f"- {finding_id}: {investigation['package']} {investigation['target']}; "
            f"{investigation['reason']} {investigation.get('assessment') or ''} "
            f"Sources: {', '.join(investigation['sources'])}."
        )
    for finding_id, selection in payload["package_version_selections"].items():
        lines.append(
            f"- {finding_id}: selected {selection.get('target') or 'no eligible release'}; {selection['source']}."
        )
        if selection.get("advisory_warning"):
            lines.append(f"  WARNING: {selection['advisory_warning']}")
        for paid in selection.get("paid_releases", []):
            lines.append(
                f"  PAID VERSION {paid['version']}: blocked; user investigation required. "
                f"{paid['assessment']} Sources: {', '.join(paid['sources'])}."
            )
    lines.extend(["", "## Package Update Qualifications"])
    if payload["package_qualifications"]:
        for finding_id, qualification in payload["package_qualifications"].items():
            approval = qualification.get("approval") or {}
            plan = qualification.get("plan") or {}
            license_review = qualification.get("license_review") or {}
            if qualification.get("policy_mode") == "documentation_review":
                lines.append(
                    f"- {finding_id}: {plan.get('package')} -> {plan.get('target')}; {qualification['status']}; license {license_review.get('expression') or 'unknown'}; documented license review, not corporate approval."
                )
            else:
                lines.append(
                    f"- {finding_id}: {plan.get('package') or 'unknown'} -> {plan.get('target') or 'unknown'}; {qualification['status']}; license {approval.get('license_expression') or 'unapproved'}; approval {approval.get('approval_reference') or 'missing'} by {approval.get('approved_by') or 'unknown'}."
                )
            lines.append(
                f"  Obligations: {approval.get('obligations') or license_review.get('obligations') or 'not recorded'}."
            )
            for warning in qualification.get("warnings") or []:
                lines.append(f"  WARNING: {warning}")
            rejection = qualification.get("rejection_diagnostics")
            if rejection:
                lines.append(f"  Rejected update: {rejection['summary']}")
            documentation = (qualification.get("review") or {}).get(
                "documentation"
            ) or {}
            lines.append(
                f"  Reviewed sources: {', '.join(documentation.get('sources') or []) or 'missing'}."
            )
            if qualification.get("version_alignment_files"):
                lines.append(
                    "  Version-only AI alignment documents: "
                    + ", ".join(qualification["version_alignment_files"])
                    + "."
                )
            review = qualification.get("review") or {}
            if review.get("validation_mode") == "build_only":
                lines.append(
                    "  Build-only trial: runtime/test compatibility was not verified. "
                    + _table_cell(review.get("compatibility_limitations"))
                )
    else:
        lines.append("No package qualification evidence recorded.")
    lines.extend(
        [
            "",
            "## Validation",
            f"Status: {state.validation_status or 'not run'}",
            "HTTP timing log: .security-mcp/http-timings.jsonl (new HTTP requests only).",
        ]
    )
    for item in state.validation_results:
        lines.append(
            f"- {item.get('status')}: {item.get('command') or item.get('detail')}"
        )
        if item.get("command") and item.get("detail"):
            lines.append(f"  Detail: {item['detail']}")
        for key in ("stdout_log_path", "stderr_log_path"):
            if item.get(key):
                lines.append(f"  {key}: {item[key]}")
    if state.batch_isolation:
        lines.extend(["", "## Batch Isolation"])
        for trial in state.batch_isolation:
            selected = ", ".join(trial["finding_ids"]) or "original baseline"
            lines.append(f"- {trial['status']}: {selected}")
            validation = trial.get("validation") or {}
            if validation:
                lines.append(
                    f"  Production build: {validation['build_status']}. "
                    + validation["unit_tests"]["reason"]
                )
                for check in validation["build_checks"]:
                    lines.append(
                        f"  Build: {check.get('command')}; {check['status']}; exit {check.get('exit_code')}."
                    )
                    for key in ("stdout_log_path", "stderr_log_path"):
                        if check.get(key):
                            lines.append(f"  {key}: {check[key]}")
            for failure in trial["failures"]:
                lines.append(
                    f"  Failure: {failure.get('detail') or failure.get('command')}"
                )
                for key in ("stdout_log_path", "stderr_log_path"):
                    if failure.get(key):
                        lines.append(f"  {key}: {failure[key]}")
    payload["final_summary_markdown"] = "\n".join(
        [
            "## Unit-test validation",
            payload["unit_test_validation"]["reason"],
            "",
            *(
                [
                    "## Validation caveats",
                    "Passing required product checks is not a clean security audit. "
                    "Pre-existing lint issues and unavailable optional checks remain separate:",
                    *(
                        f"- {_table_cell(item['phase'])}: {_table_cell(item.get('command') or item.get('detail'))}; "
                        f"{_table_cell(item.get('status'))}"
                        + (
                            f"; {_table_cell(item['detail'])}"
                            if item.get("command") and item.get("detail")
                            else ""
                        )
                        + (
                            "; diagnostics: "
                            + ", ".join(
                                f"{count} {kind}"
                                for kind, count in item["diagnostic_counts"].items()
                            )
                            if item.get("diagnostic_counts")
                            else ""
                        )
                        for item in payload["validation_caveats"]
                    ),
                    "",
                ]
                if payload["validation_caveats"]
                else []
            ),
            *(
                ["## False-Positive Approval Pending", approval_notice, ""]
                if pending_dismissals
                else []
            ),
            *(
                [
                    "## False-Positive Approval Form",
                    f"Recorded status: {_table_cell(state.false_positive_approval_form['status'])}. "
                    "This diagnostic is not reusable approval; only confirmed GitLab outcomes establish dismissal.",
                    *(
                        [_table_cell(state.false_positive_approval_form["reason"])]
                        if state.false_positive_approval_form.get("reason")
                        else []
                    ),
                    "",
                ]
                if state.false_positive_approval_form
                else []
            ),
            *(
                [
                    "## Source Review Incomplete",
                    f"{review_queue['finding_count']} SAST findings still require host AI code review. "
                    "Reading scanner-cited excerpts is not a completed assessment. "
                    "No false-positive decision or dismissal approval exists for these findings.",
                    review_queue["action"],
                    "",
                ]
                if review_queue["finding_count"]
                else []
            ),
            "## Finding Assessments",
            payload["finding_assessments_table"],
            "",
            "Completion automatically offers unchecked approvals for eligible false positives. Only a human checkbox submission authorizes dismissal. Cancel to continue reviewing, then explicitly request `submit_false_positive_approvals` to reopen the form. Markdown reports do not submit approvals.",
            *(
                [
                    "",
                    "## GitLab False-Positive Dismissals",
                    "Only independent GitLab read-back counts as confirmation. "
                    "Use the project Vulnerability report's Dismissed / False positive "
                    "filter and the matching tracked ref. Scanner falsePositive flags "
                    "and saved pipeline scan artifacts are not user dismissal status. "
                    "Approved reasons remain in Finding Assessments and the JSON audit.",
                    *(_dismissal_summary(item) for item in state.gitlab_dismissals),
                ]
                if state.gitlab_dismissals
                else []
            ),
            "",
            "## Unresolved Security Issues",
            payload["unresolved_issues_table"],
        ]
    )
    lines.extend(
        [
            "",
            "## Working tree",
            f"git diff --cached empty: {'unknown' if cached_empty is None else cached_empty}",
            "```",
            diff_stat or "(no unstaged diff stat)",
            "```",
            "Changed paths:",
            "```",
            diff_files or "(none)",
            "```",
            "",
            "## What you do next",
            "- Review the diff.",
            "- Confirm validation.",
            "- Commit and push yourself if you are satisfied.",
            "",
            payload["final_summary_markdown"],
            "",
        ]
    )
    return payload, "\n".join(lines)


def write_report(
    root: Path,
    state: RunState,
    *,
    staged: list[str] | None,
    diff_stat: str,
    diff_files: str,
) -> dict:
    """Write the markdown and JSON reports and return their paths and key sections."""
    payload, markdown = render(
        state, staged=staged, diff_stat=diff_stat, diff_files=diff_files
    )
    directory = root / ".security-mcp" / "reports"
    directory.mkdir(parents=True, exist_ok=True)
    stem = (
        f"{report_prefix(root, state)}{REMEDIATION_REPORT_STEM}"
        f"{state.branch_name or 'unbranched'}"
    )
    json_path = directory / f"{stem}.json"
    human_path = directory / f"{stem}.md"
    atomic_write_text(json_path, json.dumps(payload, indent=2, ensure_ascii=False))
    atomic_write_text(human_path, markdown)
    return {
        "status": "REPORT_GENERATED",
        "server_version": payload["server_version"],
        "review_status": payload["review_status"],
        "source_review_queue": payload["source_review_queue"],
        "final_summary_markdown": payload["final_summary_markdown"],
        "unit_test_validation": payload["unit_test_validation"],
        "human_report": str(human_path),
        "json_report": str(json_path),
        "http_timings_path": str(root / payload["http_timings_file"]),
        "false_positives": payload["false_positives"],
        "no_solution": payload["no_solution_issues"],
        "user_prompt_skipped": payload["user_prompt_skipped"],
        "unresolved_issues": payload["unresolved_issues"],
        "unresolved_issues_table": payload["unresolved_issues_table"],
        "finding_assessments": payload["finding_assessments"],
        "finding_assessments_table": payload["finding_assessments_table"],
        "finding_pipelines": payload["finding_pipelines"],
        "gitlab_dismissals": payload["gitlab_dismissals"],
        "false_positive_review_tool": payload["false_positive_review_tool"],
        "false_positive_approval": payload["false_positive_approval"],
        "false_positive_approval_form": payload["false_positive_approval_form"],
        "fix_selection": payload["fix_selection"],
        "lint_baseline": payload["lint_baseline"],
        "lint_issues_path": str(root / ".security-mcp" / "lint-issues.json")
        if state.lint_baseline is not None
        else None,
        "lint_rules_path": str(root / ".security-mcp" / "lint-rules.json")
        if state.lint_baseline is not None
        else None,
        "git_diff_cached_empty": payload["git_diff_cached_empty"],
        "note": "All changes remain uncommitted. Review the report, then commit manually if you are satisfied.",
    }
