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
        )
        required = (finding.get("proposedFix") or {}).get("qualifiers") and outcome.get(
            "status"
        ) != "APPLIED"
        if decision == "FALSE_POSITIVE" or (
            outcome.get("status") == "APPLIED" and not pending
        ):
            continue
        failed = outcome.get("status") in {"FIX_FAILED", "FIX_FAILED_LOCKFILE"}
        if (
            decision not in {"NO_SAFE_FIX", "MANUAL_REVIEW"}
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
                "location": finding.get("location") or {},
                "decision": outcome.get("status") if failed else decision,
                "reason": (outcome.get("detail") if failed or pending else None)
                or qualification.get("reason")
                or (
                    "Package update requires passing compatibility, corporate approval, and before/after product checks."
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
        "| Severity | Package | Version | Issue | Reason Not Addressed |",
        "|---|---|---|---|---|",
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
        "findings_truncated": state.findings_truncated,
        "unverified_findings": unverified,
        "excluded_findings": state.excluded_findings,
        "decisions": {
            key: value.get("decision") for key, value in state.decisions.items()
        },
        "changes_made": state.changes,
        "validation_status": state.validation_status,
        "validation": state.validation_results,
        "package_qualifications": {
            finding.get("id"): {
                key: qualification.get(key)
                for key in (
                    "status",
                    "reason",
                    "plan",
                    "review",
                    "approval",
                    "policy_sha256",
                    "baseline_results",
                    "post_results",
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
    lines.extend(["", "## Package Update Qualifications"])
    if payload["package_qualifications"]:
        for finding_id, qualification in payload["package_qualifications"].items():
            approval = qualification.get("approval") or {}
            plan = qualification.get("plan") or {}
            lines.append(
                f"- {finding_id}: {plan.get('package') or 'unknown'} -> {plan.get('target') or 'unknown'}; {qualification['status']}; license {approval.get('license_expression') or 'unapproved'}; approval {approval.get('approval_reference') or 'missing'} by {approval.get('approved_by') or 'unknown'}."
            )
            lines.append(
                f"  Obligations: {approval.get('obligations') or 'not approved'}."
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
        ["", "## Validation", f"Status: {state.validation_status or 'not run'}"]
    )
    for item in state.validation_results:
        lines.append(
            f"- {item.get('status')}: {item.get('command') or item.get('detail')}"
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
            "## Unresolved Security Issues",
            unresolved_table,
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
        "human_report": str(human_path),
        "json_report": str(json_path),
        "false_positives": payload["false_positives"],
        "no_solution": payload["no_solution_issues"],
        "user_prompt_skipped": payload["user_prompt_skipped"],
        "unresolved_issues": payload["unresolved_issues"],
        "unresolved_issues_table": payload["unresolved_issues_table"],
        "git_diff_cached_empty": payload["git_diff_cached_empty"],
        "note": "All changes remain uncommitted. Review the report, then commit manually if you are satisfied.",
    }
