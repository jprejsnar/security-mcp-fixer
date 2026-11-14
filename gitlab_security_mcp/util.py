"""Validate metadata, redact secrets, bound paths, and publish local text."""

from __future__ import annotations

import gc
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter, process_time
from urllib.parse import quote

import httpx

_HTTP_LOG_LOCK = threading.Lock()
logger = logging.getLogger("gitlab_security_mcp")


def _memory_bytes() -> int | None:
    """Return this process's working set, or None when the OS will not report it."""
    try:
        if os.name == "nt":
            return _windows_working_set()
        import resource

        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(rss) if sys.platform == "darwin" else int(rss) * 1024
    except (OSError, AttributeError, ValueError, OverflowError):
        return None


def _windows_working_set() -> int | None:
    """Read the Windows working set without failing the task when the API is absent."""
    import ctypes
    from ctypes import wintypes

    class _Counters(ctypes.Structure):
        """Windows process-memory counters used only for the working-set field."""

        _fields_ = (
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        )

    counters = _Counters()
    counters.cb = ctypes.sizeof(counters)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    query = getattr(kernel, "K32GetProcessMemoryInfo", None)
    if query is None:
        query = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
    query.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Counters), wintypes.DWORD]
    query.restype = wintypes.BOOL
    if not query(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        return None
    return int(counters.WorkingSetSize)


def _performance_sample() -> dict:
    """Capture wall time, process CPU, memory and per-generation collection counts."""
    stats = gc.get_stats()
    return {
        "wall": perf_counter(),
        "cpu": process_time(),
        "memory_bytes": _memory_bytes(),
        "gc_collections": [int(item["collections"]) for item in stats],
        "gc_collected": [int(item["collected"]) for item in stats],
        "gc_uncollectable": [int(item["uncollectable"]) for item in stats],
    }


def _log_performance(name: str, before: dict) -> None:
    """Write one performance record. A logging failure must not fail the task."""
    try:
        after = _performance_sample()
        wall = after["wall"] - before["wall"]
        cpu = after["cpu"] - before["cpu"]
        error = sys.exc_info()[0]
        record = {
            "event": "task_performance",
            "task": name,
            "duration_ms": round(wall * 1000, 3),
            "cpu_seconds": round(cpu, 6),
            "cpu_percent": round((cpu / wall) * 100, 2) if wall else 0.0,
            "memory_bytes": after["memory_bytes"],
            "memory_delta_bytes": (
                None
                if after["memory_bytes"] is None or before["memory_bytes"] is None
                else after["memory_bytes"] - before["memory_bytes"]
            ),
            "gc_collections": [
                end - start
                for start, end in zip(
                    before["gc_collections"], after["gc_collections"], strict=False
                )
            ],
            "gc_collected": [
                end - start
                for start, end in zip(
                    before["gc_collected"], after["gc_collected"], strict=False
                )
            ],
            "gc_uncollectable": [
                end - start
                for start, end in zip(
                    before["gc_uncollectable"],
                    after["gc_uncollectable"],
                    strict=False,
                )
            ],
            "error": None if error is None else error.__name__,
            "worker": threading.current_thread().name,
        }
        logger.info("Task performance %s", json.dumps(record, ensure_ascii=True))
    except Exception:
        logger.warning("Could not write task performance log", exc_info=True)


@contextmanager
def log_task(name: str) -> Iterator[None]:
    """Log how long a task took and the CPU, memory and GC it used.

    The record is one stderr JSON line. It has no arguments, source, or secrets.
    Process CPU can exceed one core when several threads run. Child-process CPU
    is not included; the wall-clock duration still covers a waited-for command.
    """
    before = _performance_sample()
    try:
        yield
    finally:
        _log_performance(name, before)


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
        if not secret:
            continue
        redacted = redacted.replace(secret, "[REDACTED]")
        encoded = quote(secret, safe="")
        if encoded != secret:
            redacted = redacted.replace(encoded, "[REDACTED]")
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
