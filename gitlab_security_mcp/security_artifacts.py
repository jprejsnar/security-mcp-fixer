"""Review old security logs before removing known generated, untracked artifacts."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

logger = logging.getLogger("gitlab_security_mcp")

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
                f"Security artifacts contain a link/reparse point: {path.name}"
            )
        if path.is_dir():
            paths.extend(path.iterdir())
        elif path.is_file():
            if path == root:
                raise ValueError("The security artifact root is not a directory")
            found[path] = (info.st_size, info.st_mtime_ns, info.st_ino)
        else:
            raise ValueError(f"Unsupported security artifact type: {path.name}")
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
                        raise ValueError("Run state is not an object")
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
                        raise ValueError("Dismissal records are malformed")
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
                                raise ValueError("JSON log entry is not an object")
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
                "Security artifacts changed during log review; retry when no other run is writing"
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
                        "A security artifact changed before cleanup; no further files were removed"
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
                        "Security artifact directories changed before cleanup"
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
