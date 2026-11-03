"""Validate metadata, redact secrets, bound paths, and publish local text."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path


def json_object(text: str) -> dict:
    """Parse JSON metadata and reject null, array, and scalar roots."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    return data


def atomic_write_text(path: Path, text: str, *, exclusive: bool = False) -> None:
    """Publish UTF-8 text atomically without translating line endings.

    The parent directory must exist. Normal writes preserve existing file
    permissions; exclusive writes use a hard link and raise FileExistsError
    rather than replacing a user's file. Temporary storage is cleaned up
    on exit. Filesystem errors propagate; this is a per-file operation,
    not a multi-file transaction or cross-process editing lock.
    """
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}-", suffix=".tmp"
    )
    try:
        try:
            stream = os.fdopen(descriptor, "w", encoding="utf-8", newline="")
        except BaseException:
            os.close(descriptor)
            raise
        with stream:
            stream.write(text)
        if not exclusive and path.exists():
            shutil.copymode(path, temporary)
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


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
