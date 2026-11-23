"""Validate metadata, redact secrets, bound paths, and publish local text."""

from __future__ import annotations

import atexit
import gc
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET
import xml.parsers.expat as expat
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from subprocess import SubprocessError
from time import perf_counter, process_time
from urllib.parse import quote

import httpx

_RAISE_EXPECTED_A_JSON_OBJECT = "Expected a JSON object"
_RAISE_XML_ENTITY_DECLARATIONS_ARE_NOT_ALLOWED = (
    "XML entity declarations are not allowed"
)
_RAISE_EXTERNAL_XML_ENTITIES_ARE_NOT_ALLOWED = "External XML entities are not allowed"
_RAISE_MISSING = "Missing {}"
_RAISE_UNSAFE = "Unsafe {}"

_HTTP_LOG_LOCK = threading.Lock()
_LOG_PROCESS_MEMORY_UNAVAILABLE = "Could not read process memory: %s"
_LOG_CONVERTED_FAILURE = (
    "Converted %s into a failed result during %s: %s; traceback follows"
)
_LOG_RESOLVE_INSIDE = "Could not resolve %s inside %s: %s"
_SERVER_LOG_DIRECTORY = "gitlab-security-mcp"
_server_log_handler: logging.Handler | None = None
_WINDOWS_MEMORY_QUERY_FAILED = "Windows process memory query failed"
_memory_log_lock = threading.Lock()
_memory_unavailable_logged = False
logger = logging.getLogger("gitlab_security_mcp")
GIT_OPERATION_FAILURES = (OSError, RuntimeError, ValueError, SubprocessError)
CONVERTED_DEFECTS = (AttributeError, LookupError, TypeError)
ADVISORY_READ_FAILURES = (
    OSError,
    RuntimeError,
    ValueError,
    json.JSONDecodeError,
    httpx.HTTPError,
    *CONVERTED_DEFECTS,
)
PROGRESS_PUBLISH_FAILURES = (OSError, RuntimeError, ValueError, TypeError)


class _ServerLogHandler(logging.Handler):
    """Append redacted server diagnostics for the end-of-run archive."""

    def __init__(self, path: Path):
        """Open the process spool. It is not a home log file."""
        super().__init__()
        self.path = path
        self._stream = path.open("a", encoding="utf-8", newline="\n")

    def emit(self, record: logging.LogRecord) -> None:
        """Write one formatted line and flush it before the next record."""
        try:
            self._stream.write(self.format(record) + "\n")
            self._stream.flush()
        except OSError:
            self.handleError(record)

    def flush(self) -> None:
        """Push buffered lines to disk so the archive reads a complete log."""
        self.acquire()
        try:
            self._stream.flush()
        except OSError:
            pass
        finally:
            self.release()

    def close(self) -> None:
        """Close the spool. The archive already holds its own copy."""
        self.acquire()
        try:
            self._stream.close()
        except OSError:
            pass
        finally:
            self.release()
            super().close()


def attach_server_log(formatter: logging.Formatter) -> None:
    """Copy server diagnostics into a process spool and keep writing stderr.

    The package logger does not propagate, so the spool has to sit on that
    logger and on the root logger. One handler instance receives each record
    once. The file lives in the temp directory and is removed when the
    process exits.
    """
    global _server_log_handler
    if _server_log_handler is None:
        directory = Path(tempfile.gettempdir()) / _SERVER_LOG_DIRECTORY
        directory.mkdir(parents=True, exist_ok=True)
        handler = _ServerLogHandler(directory / f"{os.getpid()}.log")
        handler.setFormatter(formatter)
        handler.setLevel(logging.INFO)
        _server_log_handler = handler
        atexit.register(_close_server_log)
    handler = _server_log_handler
    for target in (logging.getLogger("gitlab_security_mcp"), logging.getLogger()):
        if handler not in target.handlers:
            target.addHandler(handler)


def read_server_log() -> str:
    """Return the redacted server log captured so far, or an empty string."""
    handler = _server_log_handler
    if not isinstance(handler, _ServerLogHandler):
        return ""
    handler.flush()
    try:
        return handler.path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _close_server_log() -> None:
    """Drop the process spool after the archive has copied what it needs."""
    handler = _server_log_handler
    if not isinstance(handler, _ServerLogHandler):
        return
    path = handler.path
    handler.close()
    path.unlink(missing_ok=True)


CHECKOUT_FILE_ID_LENGTH = 12


def checkout_file_id(root: Path) -> str:
    """Return a stable file-name token for one checkout, not its folder name.

    Two repositories can share a folder name. Home reports and log archives
    include this token so those checkouts do not write the same file.
    """
    text = os.path.normcase(str(root.resolve()))
    return hashlib.sha256(text.encode()).hexdigest()[:CHECKOUT_FILE_ID_LENGTH]


def utc_now_iso() -> str:
    """Return the current UTC time as one ISO 8601 string."""
    return datetime.now(UTC).isoformat()


def _log_memory_unavailable(exc: BaseException) -> None:
    """Record the first memory-probe failure without repeating it on every task."""
    global _memory_unavailable_logged
    with _memory_log_lock:
        if _memory_unavailable_logged:
            return
        _memory_unavailable_logged = True
    logger.warning(_LOG_PROCESS_MEMORY_UNAVAILABLE, exc)


def _memory_bytes() -> int | None:
    """Return this process's working set, or None when the OS will not report it."""
    try:
        if os.name == "nt":
            return _windows_working_set()
        import resource

        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(rss) if sys.platform == "darwin" else int(rss) * 1024
    except (OSError, AttributeError, ValueError, OverflowError) as exc:
        _log_memory_unavailable(exc)
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
        raise OSError(_WINDOWS_MEMORY_QUERY_FAILED)
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


def log_unexpected(exc: BaseException, context: str) -> None:
    """Record every failure a handler converts into a result, with its stack.

    The returned result keeps the message. The warning adds the operation and
    the traceback so a later reader can find the file and line. Malformed
    external data can raise the same types as a defect, so the record is a
    warning rather than an error.
    """
    logger.warning(
        _LOG_CONVERTED_FAILURE,
        type(exc).__name__,
        context,
        exc,
        exc_info=exc,
    )


def log_concurrency(kind: str, name: str, **fields: object) -> None:
    """Record one lock, fan-out, or worker event without payloads or secrets."""
    record = {
        "event": "concurrency",
        "kind": kind,
        "name": name,
        "thread": threading.current_thread().name,
    }
    record.update(fields)
    try:
        logger.info("Concurrency %s", json.dumps(record, ensure_ascii=True))
    except Exception:
        logger.warning("Could not write concurrency log", exc_info=True)


@contextmanager
def logged_lock(
    lock: threading.Lock | threading.RLock, name: str
) -> Generator[None, None, None]:
    """Acquire a lock and log only when another thread already held it.

    The wait is measured before the critical section. The record is written
    after release so logging cannot extend the hold.
    """
    started = perf_counter()
    lock.acquire()
    waited_ms = (perf_counter() - started) * 1000
    try:
        yield
    finally:
        lock.release()
        if waited_ms >= 1:
            log_concurrency("lock_wait", name, wait_ms=round(waited_ms, 3))


@contextmanager
def log_task(name: str) -> Generator[None, None, None]:
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
    operation: str | None = None,
    **kwargs,
) -> Generator[httpx.Response, None, None]:
    """Time a request through body consumption and log safe concurrent spans.

    Only the final append is serialized. Network and body work stay concurrent.
    Transport failures retain their exception class, never exception messages,
    request headers, payloads, query strings or response bodies.
    """
    started_at = utc_now_iso()
    started = perf_counter()
    response = None
    error = None
    try:
        with client.stream(method, url, **kwargs) as response:
            yield response
    except BaseException as exc:
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
            "finished_at": utc_now_iso(),
            "duration_ms": duration_ms,
            "status_code": response.status_code if response is not None else None,
            "error": error,
            "worker": threading.current_thread().name,
        }
        if operation is not None:
            record["operation"] = operation
        text = json.dumps(record, ensure_ascii=True)
        logger.info("HTTP timing %s", text)
        if log_path is not None:
            try:
                with _HTTP_LOG_LOCK:
                    log_path.parent.mkdir(parents=True, exist_ok=True)
                    with log_path.open("a", encoding="utf-8") as handle:
                        handle.write(text + "\n")
            except OSError as exc:
                logger.warning("Could not write HTTP timing log %s: %s", log_path, exc)


def json_object(text: str) -> dict:
    """Parse JSON metadata and reject null, array, and scalar roots."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(_RAISE_EXPECTED_A_JSON_OBJECT)
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


def environment_secrets() -> list[str | None]:
    """Share environment credential redaction between logs and editor progress."""
    return [
        os.environ.get(name)
        for name in (
            "GITLAB_TOKEN",
            "GITLAB_PERSONAL_ACCESS_TOKEN",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "NVD_API_KEY",
        )
    ]


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


def parse_xml(source: str | bytes | bytearray) -> ET.Element:
    """Parse XML without expanding entity declarations.

    The standard parser expands internal entities, so a short document can
    become a very large tree. Maven files, release catalogs, and JUnit reports
    use this parser. A document type that declares no entities is still read.
    """
    data = source.encode("utf-8") if isinstance(source, str) else bytes(source)
    parser = expat.ParserCreate(None, "}")
    builder = ET.TreeBuilder()
    names: dict[str, str] = {}

    def fixname(key: str) -> str:
        """Return the ElementTree form of one Expat name."""
        name = names.get(key)
        if name is None:
            name = "{" + key if "}" in key else key
            names[key] = name
        return name

    def start(tag: str, attributes: list[str]) -> None:
        """Record one opening tag and its attributes."""
        fields = {
            fixname(attributes[index]): attributes[index + 1]
            for index in range(0, len(attributes), 2)
        }
        builder.start(fixname(tag), fields)

    def reject_entity(*_args: object) -> None:
        """Stop parsing when the document declares an entity."""
        raise expat.ExpatError(_RAISE_XML_ENTITY_DECLARATIONS_ARE_NOT_ALLOWED)

    def reject_external(*_args: object) -> None:
        """Stop parsing when the document requests an external entity."""
        raise expat.ExpatError(_RAISE_EXTERNAL_XML_ENTITIES_ARE_NOT_ALLOWED)

    parser.ordered_attributes = 1
    parser.buffer_text = 1
    parser.StartElementHandler = start
    parser.EndElementHandler = lambda tag: builder.end(fixname(tag))
    parser.CharacterDataHandler = builder.data
    parser.EntityDeclHandler = reject_entity
    parser.UnparsedEntityDeclHandler = reject_entity
    parser.ExternalEntityRefHandler = reject_external
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise ET.ParseError(str(exc)) from exc
    return builder.close()


def read_bounded(path: Path, limit: int) -> bytes | None:
    """Read a file that must fit in ``limit`` bytes, or return None when it does not.

    The extra byte distinguishes a file at the limit from a file past it.
    The caller keeps its own error text. The file is closed before that check.
    """
    with path.open("rb") as stream:
        contents = stream.read(limit + 1)
    if len(contents) > limit:
        return None
    return contents


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
    except ValueError:
        return None
    except OSError as exc:
        logger.warning(_LOG_RESOLVE_INSIDE, raw, root, exc, exc_info=True)
        return None
    return resolved


def safe_token(value: str, *, label: str) -> str:
    """Reject values that must never be interpolated into a command line."""
    if not value or not isinstance(value, str):
        raise ValueError(_RAISE_MISSING.format(label))
    if len(value) > 300 or any(char in value for char in "\r\n\t|&;<>`$\\\"'"):
        raise ValueError(_RAISE_UNSAFE.format(label))
    if value.startswith("-") or ".." in value:
        raise ValueError(_RAISE_UNSAFE.format(label))
    if not re.fullmatch(r"[A-Za-z0-9_@./+:-]{1,300}", value):
        raise ValueError(_RAISE_UNSAFE.format(label))
    return value
