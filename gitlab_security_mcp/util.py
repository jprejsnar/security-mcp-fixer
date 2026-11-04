"""Validate metadata, redact secrets, bound paths, and publish local text."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

import httpx

_HTTP_LOG_LOCK = threading.Lock()
logger = logging.getLogger("gitlab_security_mcp")


def _http_log_url(url: str | httpx.URL) -> str:
    """Keep the endpoint without user credentials, query values or fragments."""
    try:
        return str(
            httpx.URL(url).copy_with(
                username="", password="", query=None, fragment=None
            )
        )
    except (httpx.InvalidURL, ValueError):
        return "[invalid URL]"


@contextmanager
def timed_http_stream(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    source: str,
    log_path: Path | None = None,
    **kwargs,
) -> Iterator[httpx.Response]:
    """Time a request through body consumption and log safe concurrent spans.

    Only the final append is serialized. Network and body work stay concurrent.
    Transport failures retain their exception class, never exception messages,
    request headers, payloads, query strings or response bodies.
    """
    started_at = datetime.now(UTC).isoformat()
    started = perf_counter()
    response = None
    error = None
    try:
        with client.stream(method, url, **kwargs) as response:
            yield response
    except Exception as exc:
        error = type(exc).__name__
        raise
    finally:
        duration_ms = round((perf_counter() - started) * 1000, 3)
        record = {
            "event": "http_request",
            "source": source,
            "method": method.upper(),
            "url": _http_log_url(url),
            "final_url": _http_log_url(response.url) if response is not None else None,
            "started_at": started_at,
            "finished_at": datetime.now(UTC).isoformat(),
            "duration_ms": duration_ms,
            "status_code": response.status_code if response is not None else None,
            "error": error,
            "worker": threading.current_thread().name,
        }
        text = json.dumps(record, ensure_ascii=True)
        logger.info("HTTP timing %s", text)
        if log_path is not None:
            try:
                with _HTTP_LOG_LOCK:
                    log_path.parent.mkdir(parents=True, exist_ok=True)
                    with log_path.open("a", encoding="utf-8") as handle:
                        handle.write(text + "\n")
            except OSError as exc:
                logger.warning(
                    "Could not write HTTP timing log: %s", type(exc).__name__
                )


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
