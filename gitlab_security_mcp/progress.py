"""Publish inspection-only task activity for the optional editor extension."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path

from gitlab_security_mcp import __version__
from gitlab_security_mcp.util import atomic_write_text, environment_secrets, redact

_RAISE_PROGRESS_NEEDS_VALID_PAIRED_COMPLETION_COUNTS = (
    "Progress needs valid paired completion counts."
)
_WINDOWS_UNC_DEVICE_PREFIX = "\\\\?\\UNC\\"
_WINDOWS_DEVICE_PREFIX = "\\\\?\\"

_lock = threading.Lock()
_tasks: dict[Path, dict[str, dict]] = {}
ACTIVE = {"RUNNING", "WAITING_FOR_HUMAN", "WAITING_FOR_AI"}


def mirror_directory() -> Path:
    """Return the per-user folder the editor reads when the checkout is not open."""
    override = os.environ.get("GITLAB_SECURITY_PROGRESS_DIR")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "gitlab-security-mcp" / "progress"


def editor_repo_root(root: Path) -> str:
    """Return a checkout path VS Code and Cursor can match on every supported OS.

    Windows may store a long path with a device prefix. The editors report the
    same directory without that prefix, including a network share.
    """
    text = str(root)
    if os.name != "nt":
        return text
    if text.startswith(_WINDOWS_UNC_DEVICE_PREFIX):
        return "\\\\" + text[len(_WINDOWS_UNC_DEVICE_PREFIX) :]
    if text.startswith(_WINDOWS_DEVICE_PREFIX):
        return text[len(_WINDOWS_DEVICE_PREFIX) :]
    return text


def drop_checkout(root: Path) -> None:
    """Forget one checkout's in-memory progress after its engine closes."""
    with _lock:
        _tasks.pop(root, None)


def mirror_path(root: Path) -> Path:
    """Name each checkout's mirror by a stable hash of its normalized path."""
    key = hashlib.sha256(os.path.normcase(str(root)).encode()).hexdigest()[:32]
    return mirror_directory() / f"{key}.json"


def publish(
    root: Path,
    task_id: str,
    label: str,
    message: str,
    *,
    status: str = "RUNNING",
    completed: int | None = None,
    total: int | None = None,
    unit: str = "files reviewed",
    jobs: list[dict] | None = None,
    final_report: bool = False,
) -> None:
    """Atomically expose real activity; never reload this file as execution permission."""
    if (completed is None) != (total is None) or (
        completed is not None and total is not None and not 0 <= completed <= total
    ):
        raise ValueError(_RAISE_PROGRESS_NEEDS_VALID_PAIRED_COMPLETION_COUNTS)
    now = datetime.now(UTC).isoformat()
    with _lock:
        tasks = _tasks.setdefault(root, {})
        previous = tasks.get(task_id) or {}
        tasks[task_id] = {
            "id": task_id,
            "label": label,
            "status": status,
            "message": redact(" ".join(str(message).split()), environment_secrets())[
                :1000
            ],
            "completed": completed,
            "total": total,
            "unit": unit,
            "jobs": jobs or [],
            "final_report": final_report,
            "started_at": previous.get("started_at", now)
            if previous.get("status") in ACTIVE or status not in ACTIVE
            else now,
            "updated_at": now,
        }
        finished = sorted(
            (key for key, value in tasks.items() if value["status"] not in ACTIVE),
            key=lambda key: (tasks[key]["updated_at"], key == task_id),
        )
        for key in finished[:-10]:
            del tasks[key]
        text = json.dumps(
            {
                "server_version": __version__,
                "pid": os.getpid(),
                "repo_root": editor_repo_root(root),
                "updated_at": now,
                "tasks": list(tasks.values()),
            },
            ensure_ascii=False,
        )
        path = root / ".security-mcp" / "progress.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, text)
        mirror = mirror_path(root)
        mirror.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(mirror, text)
