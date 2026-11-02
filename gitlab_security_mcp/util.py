"""Shared helpers for redaction and repository path checks."""

from __future__ import annotations

import re
from pathlib import Path


def redact(text: str, secrets: list[str | None]) -> str:
    """Remove known secrets from text that may be logged or returned."""
    redacted = text
    for secret in secrets:
        if secret and secret in redacted:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def resolve_inside(root: Path, raw: str | Path) -> Path | None:
    """Resolve ``raw`` and return it only when it stays inside ``root``.

    Symlinks are resolved before the check, so a link that points outside
    the repository is rejected.
    """
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return resolved


def safe_token(value: str, *, label: str) -> str:
    """Reject values that must never be interpolated into a command line."""
    if not value or not isinstance(value, str):
        raise ValueError(f"Missing {label}")
    if len(value) > 300 or any(char in value for char in "\r\n\t|&;<>`$\\\"'"):
        raise ValueError(f"Unsafe {label}")
    if value.startswith("-") or ".." in value:
        raise ValueError(f"Unsafe {label}")
    if not re.fullmatch(r"[A-Za-z0-9_@./+:-]{1,300}", value):
        raise ValueError(f"Unsafe {label}")
    return value
