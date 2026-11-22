"""Review old security logs before removing known generated, untracked artifacts."""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

_RAISE_SECURITY_ARTIFACTS_CONTAIN_A_LINK_REPARSE_POINT = (
    "Security artifacts contain a link/reparse point: {}"
)
_RAISE_SECURITY_ARTIFACTS_CHANGED_DURING_LOG_REVIEW_RETRY_WHEN = (
    "Security artifacts changed during log review; retry when no other run is writing"
)
_RAISE_UNSUPPORTED_SECURITY_ARTIFACT_TYPE = "Unsupported security artifact type: {}"
_RAISE_THE_SECURITY_ARTIFACT_ROOT_IS_NOT_A_DIRECTORY = (
    "The security artifact root is not a directory"
)
_RAISE_A_SECURITY_ARTIFACT_CHANGED_BEFORE_CLEANUP_NO_FURTHER = (
    "A security artifact changed before cleanup; no further files were removed"
)
_RAISE_SECURITY_ARTIFACT_DIRECTORIES_CHANGED_BEFORE_CLEANUP = (
    "Security artifact directories changed before cleanup"
)
_RAISE_RUN_STATE_IS_NOT_AN_OBJECT = "Run state is not an object"
_RAISE_DISMISSAL_RECORDS_ARE_MALFORMED = "Dismissal records are malformed"
_RAISE_JSON_LOG_ENTRY_IS_NOT_AN_OBJECT = "JSON log entry is not an object"
_RAISE_ARCHIVE_TIMESTAMP_IS_NOT_ISO_8601 = (
    "Archive timestamp is not ISO 8601 basic time: {}"
)

logger = logging.getLogger("gitlab_security_mcp")
LOG_ARCHIVE_DIRECTORY = "softwareSecurityAuditReports"
_RUN_LOG_NAMES = ("audit.jsonl", "http-timings.jsonl")
_COMMAND_LOG_SUFFIXES = (".stdout.log", ".stderr.log")
_ARCHIVE_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{6}Z$")
_REPARSE_POINT = 0x400

GENERATED_NAMES = {
    "audit.jsonl",
    "http-timings.jsonl",
    "run-state.json",
    "lint-issues.json",
    "lint-rules.json",
}
RUNTIME_ERROR = re.compile(
    r"^\s*(?:\d{4}-\d{2}-\d{2}[T ][\d:.,+Z-]+\s+)?"
    r"(?:Traceback \(most recent call last\):|Exception in thread\b|"
    r"Unhandled exception\b|(?:uncaught|unhandled)\s+(?:\w+\s+)?(?:exception|error)\b|"
    r"(?:\[\s*ERROR\s*\]|ERROR\b|FATAL\b)|"
    r"(?:\w+\.)*(?:TypeError|ReferenceError|SyntaxError|RuntimeError|OSError|"
    r"PermissionError|FileNotFoundError|ValueError|AssertionError):|"
    r"(?:[\w.$]+\.)*\w+Exception:|fail:|"
    r"Error:\s+\S|Caused by:\s+\S|npm ERR!|ERR_PNPM_|"
    r"error (?:TS|CS)\d+:|Build FAILED|Timed out after \d+)",
    re.IGNORECASE,
)


def _snapshot(root: Path) -> dict[Path, tuple[int, int, int]]:
    """List metadata files without following symlinks or Windows reparse points."""
    try:
        root.lstat()
    except FileNotFoundError:
        return {}
    found = {}
    paths = [root]
    while paths:
        path = paths.pop()
        info = path.lstat()
        if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(
                _RAISE_SECURITY_ARTIFACTS_CONTAIN_A_LINK_REPARSE_POINT.format(path.name)
            )
        if path.is_dir():
            paths.extend(path.iterdir())
        elif path.is_file():
            if path == root:
                raise ValueError(_RAISE_THE_SECURITY_ARTIFACT_ROOT_IS_NOT_A_DIRECTORY)
            found[path] = (info.st_size, info.st_mtime_ns, info.st_ino)
        else:
            raise ValueError(
                _RAISE_UNSUPPORTED_SECURITY_ARTIFACT_TYPE.format(path.name)
            )
    return found


def _record_failure(record: dict) -> str | None:
    """Recognize execution failures, not advisory absence or assessment prose."""
    for key in ("exit_code", "returncode"):
        if isinstance(record.get(key), int) and record[key] != 0:
            return f"Command exited with code {record[key]}"
    status = record.get("status_code")
    advisory_miss = record.get("source") == "advisory" and status == 404
    if not advisory_miss:
        if record.get("error"):
            return "Recorded execution/HTTP error"
        if isinstance(status, int) and status >= 400:
            return f"HTTP request failed with status {status}"
    if str(record.get("level", "")).upper() in {"ERROR", "FATAL", "CRITICAL"}:
        return "Error-level log entry"
    if isinstance(record.get("status"), str) and record["status"] in {
        "ERROR",
        "FAILED",
        "TIMED_OUT",
    }:
        return "Recorded failed operation"
    return None


def _generated(relative: str) -> bool:
    """Own only documented outputs, leaving policies/configuration and unknown files."""
    path = Path(relative)
    if len(path.parts) == 1:
        return path.name in GENERATED_NAMES
    if len(path.parts) == 2 and path.parts[0] == "command-logs":
        return path.name.endswith((".stdout.log", ".stderr.log"))
    return (
        len(path.parts) == 2
        and path.parts[0] == "reports"
        and path.name.startswith("security-remediation-report-")
        and path.suffix in {".json", ".md"}
    )


def review_security_artifacts(
    repo_root: Path, tracked: set[str] | None = None, *, fresh_start: bool = False
) -> dict:
    """Scan every log; only a stable, error-free snapshot may be cleaned.

    With no tracked-file inventory, this performs an inspection only. Cleanup
    deletes individual owned files and empty directories, never recursively.
    A fresh start may discard prior execution errors, but not unsafe filesystem state.
    """
    root = repo_root / ".security-mcp"
    errors = []
    deleted = []
    logs_scanned = 0
    error_count = 0
    prior_errors = []
    prior_error_count = 0
    deleted_directories = []
    filesystem_safe = False

    def record(path: Path, line: int, reason: str) -> None:
        """Bound returned diagnostics without stopping the complete log scan."""
        nonlocal error_count
        error_count += 1
        if len(errors) < 100:
            errors.append(
                {
                    "file": str(path.relative_to(repo_root)),
                    "line": line,
                    "reason": reason,
                }
            )

    try:
        snapshot = _snapshot(root)
        for path in sorted(snapshot):
            if path == root / "run-state.json":
                if snapshot[path][0] > 20_000_000:
                    record(path, 0, "Prior run state is too large to verify safely")
                    continue
                try:
                    state = json.loads(path.read_text(encoding="utf-8"))
                    if not isinstance(state, dict):
                        raise ValueError(_RAISE_RUN_STATE_IS_NOT_AN_OBJECT)
                    if any(
                        isinstance(state.get(key), str)
                        and state[key].endswith(("_FAILED", "_INCOMPLETE"))
                        for key in ("status", "validation_status")
                    ) or state.get("manual_cleanup_required"):
                        record(
                            path,
                            0,
                            "Prior run records a failure or incomplete recovery",
                        )
                    dismissals = state.get("gitlab_dismissals", [])
                    if not isinstance(dismissals, list) or not all(
                        isinstance(item, dict) for item in dismissals
                    ):
                        raise ValueError(_RAISE_DISMISSAL_RECORDS_ARE_MALFORMED)
                    if any(item.get("status") != "DISMISSED" for item in dismissals):
                        record(
                            path,
                            0,
                            "Prior run has an unsuccessful or uncertain GitLab dismissal",
                        )
                except (UnicodeError, ValueError, TypeError):
                    record(path, 0, "Prior run state is malformed or unreadable")
                continue
            if path.suffix.lower() not in {".log", ".jsonl"}:
                continue
            logs_scanned += 1
            with path.open("rb") as stream:
                number = 0
                while raw := stream.readline(1_048_577):
                    number += 1
                    if len(raw) > 1_048_576:
                        record(path, number, "Log entry is too large to verify safely")
                        break
                    try:
                        text = raw.decode("utf-8")
                        if path.suffix.lower() == ".jsonl" and text.strip():
                            entry = json.loads(text)
                            if not isinstance(entry, dict):
                                raise ValueError(_RAISE_JSON_LOG_ENTRY_IS_NOT_AN_OBJECT)
                            failure = _record_failure(entry)
                        else:
                            failure = (
                                "Runtime error/exception in command output"
                                if RUNTIME_ERROR.search(text)
                                else None
                            )
                        if failure:
                            record(path, number, failure)
                    except (UnicodeError, ValueError):
                        record(path, number, "Log entry is malformed or unreadable")
        if _snapshot(root) != snapshot:
            raise ValueError(
                _RAISE_SECURITY_ARTIFACTS_CHANGED_DURING_LOG_REVIEW_RETRY_WHEN
            )
        filesystem_safe = True
        if fresh_start and tracked is not None and error_count:
            prior_errors, prior_error_count = errors, error_count
            errors, error_count = [], 0
            logger.warning(
                "Starting a clean reused branch after %s prior log errors; removing only generated untracked artifacts.",
                prior_error_count,
            )
        if not error_count and tracked is not None:
            candidates = [
                path
                for path in sorted(snapshot)
                if _generated(str(path.relative_to(root)))
                and path.relative_to(repo_root).as_posix() not in tracked
            ]
            for path in candidates:
                info = path.lstat()
                if (
                    path.is_symlink()
                    or getattr(info, "st_file_attributes", 0) & 0x400
                    or (info.st_size, info.st_mtime_ns, info.st_ino) != snapshot[path]
                ):
                    raise ValueError(
                        _RAISE_A_SECURITY_ARTIFACT_CHANGED_BEFORE_CLEANUP_NO_FURTHER
                    )
                path.unlink()
                deleted.append(str(path.relative_to(repo_root)))
            directories = {root, root / "command-logs", root / "reports"}
            for path in snapshot:
                directories.update(
                    parent for parent in path.parents if parent.is_relative_to(root)
                )
            for directory in sorted(
                directories, key=lambda path: len(path.parts), reverse=True
            ):
                if not directory.exists():
                    continue
                info = directory.lstat()
                if (
                    directory.is_symlink()
                    or getattr(info, "st_file_attributes", 0) & 0x400
                    or not directory.resolve().is_relative_to(root)
                ):
                    raise ValueError(
                        _RAISE_SECURITY_ARTIFACT_DIRECTORIES_CHANGED_BEFORE_CLEANUP
                    )
                if not any(directory.iterdir()):
                    directory.rmdir()
                    deleted_directories.append(str(directory.relative_to(repo_root)))
    except (OSError, ValueError) as exc:
        filesystem_safe = False
        record(root, 0, f"Security log review/cleanup could not complete: {exc}")
    return {
        "status": "ERROR" if error_count else "OK",
        "filesystem_safe": filesystem_safe,
        "logs_scanned": logs_scanned,
        "error_count": error_count,
        "errors": errors,
        "deleted_files": deleted,
        "deleted_directories": deleted_directories,
        "previous_run_error_count": prior_error_count,
        "previous_run_errors": prior_errors,
        "cleanup_performed": tracked is not None and not error_count,
    }


def _ordinary_file(path: Path) -> bool:
    """Return whether a path is a regular file, not a link or reparse point."""
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        path.is_file()
        and not path.is_symlink()
        and not (getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)
    )


def run_log_files(repo_root: Path) -> list[Path]:
    """Return this run's command and HTTP logs inside the checkout."""
    root = repo_root / ".security-mcp"
    found = [path for name in _RUN_LOG_NAMES if _ordinary_file(path := root / name)]
    command_logs = root / "command-logs"
    try:
        info = command_logs.lstat()
    except OSError:
        info = None
    if (
        info is not None
        and command_logs.is_dir()
        and not command_logs.is_symlink()
        and not (getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)
    ):
        found.extend(
            path
            for path in command_logs.iterdir()
            if path.name.endswith(_COMMAND_LOG_SUFFIXES) and _ordinary_file(path)
        )
    return found


def archive_run_logs(repo_root: Path, project_name: str, when: datetime) -> dict:
    """Zip checkout logs into the home archive folder, then delete those files.

    Reports, run state, policies, and lint evidence stay in the checkout. The
    archive name uses an ISO 8601 basic timestamp because a colon is not a
    legal Windows file name.
    """
    files = run_log_files(repo_root)
    if not files:
        return {"status": "NO_LOGS", "path": None, "removed": []}
    destination = Path.home() / LOG_ARCHIVE_DIRECTORY
    destination.mkdir(parents=True, exist_ok=True)
    stamp = when.astimezone(UTC).strftime("%Y-%m-%dT%H%M%SZ")
    if _ARCHIVE_STAMP.fullmatch(stamp) is None:
        raise ValueError(_RAISE_ARCHIVE_TIMESTAMP_IS_NOT_ISO_8601.format(stamp))
    target = destination / f"{project_name}_{stamp}.zip"
    descriptor, temporary = tempfile.mkstemp(dir=destination, suffix=".zip.tmp")
    os.close(descriptor)
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            for path in files:
                archive.write(
                    path,
                    arcname=path.relative_to(repo_root / ".security-mcp").as_posix(),
                )
        os.replace(temporary, target)
    except (OSError, ValueError):
        Path(temporary).unlink(missing_ok=True)
        raise
    removed = []
    for path in files:
        path.unlink()
        removed.append(path.relative_to(repo_root).as_posix())
    command_logs = repo_root / ".security-mcp" / "command-logs"
    if command_logs.is_dir() and not any(command_logs.iterdir()):
        command_logs.rmdir()
    return {"status": "ARCHIVED", "path": str(target), "removed": removed}
