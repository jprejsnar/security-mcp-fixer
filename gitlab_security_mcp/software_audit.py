"""Prepare the closing software-audit choice without changing the checkout."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

_CHOICES = {
    "generate_report": (
        "1. Generate the software audit report and copy it to the home directory."
    ),
    "fix_from_report": (
        "2. Fix only confirmed issues from that report, with the smallest change and an AAA test for each fix."
    ),
    "done": "3. Do nothing. This run is finished.",
}
_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{6}Z$")
_UNSAFE_NAME = re.compile(r'[<>:"/\\|?*\[\]\x00-\x1f]')
_SELECTABLE = re.compile(r"^###\s+(?:\d+\.\s+)?selectable findings$", re.IGNORECASE)
_ITEM = re.compile(
    r"^-\s+([A-Z][A-Z0-9]{1,8})\s+\|\s+([^|]+?)\s+\|\s+([^|]+?)\s+\|\s+(.+?)\s*$"
)


def audit_prompt() -> str:
    """Return the shipped meta-audit prompt, including its placeholders."""
    return (
        files("gitlab_security_mcp")
        .joinpath("software_audit_prompt.md")
        .read_text(encoding="utf-8")
    )


def render_audit_prompt(when: datetime, revision: str) -> str:
    """Fill the prompt's date and revision placeholders."""
    text = audit_prompt()
    return text.replace(
        "{{CURRENT_DATE}}", when.astimezone(UTC).date().isoformat()
    ).replace("{{GIT_COMMIT_SHA_OR_BRANCH}}", revision)


def project_file_name(project_path: str | None, fallback: str) -> str:
    """Return the last GitLab project segment, safe for a Windows file name."""
    raw = (project_path or "").strip().replace("\\", "/").strip("/")
    segment = raw.rsplit("/", 1)[-1] if raw else fallback
    cleaned = _UNSAFE_NAME.sub("-", segment).strip(" .")
    return cleaned or "gitlab-project"


def audit_report_path(project_name: str, when: datetime) -> Path:
    """Return the home-directory report path for one project and UTC moment.

    The clock portion uses ``YYYY-MM-DDTHHMMSSZ``. That is ISO 8601 basic time,
    and it is a legal Windows file name because it contains no colons.
    """
    stamp = when.astimezone(UTC).strftime("%Y-%m-%dT%H%M%SZ")
    if _STAMP.fullmatch(stamp) is None:
        raise ValueError(f"Audit timestamp is not usable in a file name: {stamp}")
    return Path.home() / f"{project_name}_{stamp}_software_audit_report.md"


def latest_audit_report(project_name: str) -> Path | None:
    """Return the newest home-directory audit report for one project, if one exists."""
    matches = sorted(
        Path.home().glob(f"{project_name}_*_software_audit_report.md"),
        key=lambda path: path.stat().st_mtime,
    )
    return matches[-1] if matches else None


def audit_items(text: str) -> list[dict[str, str]]:
    """Return the checkbox rows from the report's selectable-findings section.

    Lines outside that section are ignored, so prose and tables cannot add a fix.
    """
    items: list[dict[str, str]] = []
    seen: set[str] = set()
    collecting = False
    for raw in text.splitlines():
        line = raw.strip()
        if _SELECTABLE.fullmatch(line):
            collecting = True
            continue
        if not collecting:
            continue
        if line.startswith("### "):
            break
        matched = _ITEM.match(line)
        if matched is None:
            continue
        item_id, severity, location, problem = (
            part.strip() for part in matched.groups()
        )
        if item_id in seen:
            continue
        seen.add(item_id)
        items.append(
            {
                "id": item_id,
                "severity": severity,
                "location": location,
                "problem": problem,
            }
        )
    return items


def choice_labels() -> list[dict[str, str]]:
    """Return the three closing questions in display order."""
    return [{"id": key, "label": label} for key, label in _CHOICES.items()]


def normalize_choice(value: str | None) -> str | None:
    """Return a known choice id, or None when the value is absent or unknown."""
    if value in _CHOICES:
        return value
    return None
