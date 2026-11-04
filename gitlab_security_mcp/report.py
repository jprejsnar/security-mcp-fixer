"""Human and JSON reports. The false-positive, no-solution, and skip sections are mandatory."""

from __future__ import annotations

import json
from pathlib import Path

from gitlab_security_mcp.state import RunState
from gitlab_security_mcp.util import atomic_write_text


def _table_cell(value: object) -> str:
    """Escape pipes and line breaks so evidence stays in one table cell."""
    return " ".join(str(value if value is not None else "N/A").splitlines()).replace(
        "|", "\\|"
    )


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
        decision = assessment.get("decision") or finding.get("remediationDecision")
        outcome = outcomes.get(finding_id) or {}
        qualification = finding.get("packageQualification") or {}
        pending = (
            outcome.get("package_update")
            and outcome.get("qualification_status") != "VALIDATED"
        ) or outcome.get("validation_pending", False)
        required = (finding.get("proposedFix") or {}).get("qualifiers") and outcome.get(
            "status"
        ) != "APPLIED"
        if decision == "FALSE_POSITIVE" or (
            outcome.get("status") == "APPLIED" and not pending
        ):
            continue
        failed = (
            outcome.get("status")
            in {"FIX_FAILED", "FIX_FAILED_LOCKFILE", "ROLLED_BACK"}
            or qualification.get("status") == "REJECTED"
        )
        if (
            decision not in {"NO_SAFE_FIX", "MANUAL_REVIEW", "REPRODUCTION_REQUIRED"}
            and finding_id not in reasons
            and not failed
            and not pending
            and not required
        ):
            continue
        detail = reasons.get(finding_id) or {}
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
                "reason": (outcome.get("detail") if failed or pending else None)
                or qualification.get("reason")
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


def render(
    state: RunState, *, staged: list[str] | None, diff_stat: str, diff_files: str
) -> tuple[dict, str]:
    """Build the JSON payload and markdown text for one run.

    ``staged`` is None when git could not be read. The report then says the
    index state is unknown instead of claiming that nothing is staged.
    """
    cached_empty = None if staged is None else staged == []
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
        issue = f"{identifiers}: {item['title']}" if identifiers else item["title"]
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
    payload = {
        "run_status": state.status,
        "stop_stage": state.stop_stage,
        "branch": state.branch_name,
        "pipeline": state.pipeline,
        "findings_total": len(state.findings),
        "http_timings_file": ".security-mcp/http-timings.jsonl",
        "findings_truncated": state.findings_truncated,
        "security_validation_sites": {
            finding["id"]: sorted(set(finding.get("securityValidationSites") or []))
            for finding in state.findings
        },
        "unverified_findings": unverified,
        "excluded_findings": state.excluded_findings,
        "decisions": {
            key: value.get("decision") for key, value in state.decisions.items()
        },
        "changes_made": state.changes,
        "validation_status": state.validation_status,
        "validation": state.validation_results,
        "batch_isolation": state.batch_isolation,
        "lint_baseline": state.lint_baseline,
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
                    "policy_sha256",
                    "baseline_results",
                    "post_results",
                    "check_contract",
                    "rollback",
                )
            }
            for finding in state.findings
            if (qualification := finding.get("packageQualification"))
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
            "Update GitLab findings yourself if you want them dismissed or resolved. This server does not mutate them.",
        ],
    }
    lines = [
        "# Security remediation report",
        "",
        f"Status: {state.status}",
        f"Stop stage: {state.stop_stage or 'none'}",
        f"Branch: {state.branch_name or 'not created'}",
        f"Pipeline: {(state.pipeline or {}).get('id') or 'unknown'} @ {(state.pipeline or {}).get('sha') or 'unknown'}",
        f"Findings considered: {len(state.findings)}",
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
        "This run is local only. Nothing was staged, committed, pushed, or changed in GitLab.",
        "",
        "## False positives",
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
    else:
        lines.append("No files were changed.")
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
            "Existing lint issues are recorded separately from final batch build and unit-test acceptance.",
        ]
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
            documentation = (qualification.get("review") or {}).get(
                "documentation"
            ) or {}
            lines.append(
                f"  Reviewed sources: {', '.join(documentation.get('sources') or []) or 'missing'}."
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
            for failure in trial["failures"]:
                lines.append(
                    f"  Failure: {failure.get('detail') or failure.get('command')}"
                )
                for key in ("stdout_log_path", "stderr_log_path"):
                    if failure.get(key):
                        lines.append(f"  {key}: {failure[key]}")
    payload["final_summary_markdown"] = "\n".join(
        [
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
    stem = f"security-remediation-report-{state.branch_name or 'unbranched'}"
    json_path = directory / f"{stem}.json"
    human_path = directory / f"{stem}.md"
    atomic_write_text(json_path, json.dumps(payload, indent=2, ensure_ascii=False))
    atomic_write_text(human_path, markdown)
    return {
        "status": "REPORT_GENERATED",
        "final_summary_markdown": payload["final_summary_markdown"],
        "human_report": str(human_path),
        "json_report": str(json_path),
        "http_timings_path": str(root / payload["http_timings_file"]),
        "false_positives": payload["false_positives"],
        "no_solution": payload["no_solution_issues"],
        "user_prompt_skipped": payload["user_prompt_skipped"],
        "unresolved_issues": payload["unresolved_issues"],
        "unresolved_issues_table": payload["unresolved_issues_table"],
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
