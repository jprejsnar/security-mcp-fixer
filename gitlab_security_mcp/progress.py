"""Publish inspection-only task activity for the optional editor extension."""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path

from gitlab_security_mcp import __version__
from gitlab_security_mcp.util import atomic_write_text, environment_secrets, redact

_lock = threading.Lock()
_tasks: dict[Path, dict[str, dict]] = {}
ACTIVE = {"RUNNING", "WAITING_FOR_HUMAN", "WAITING_FOR_AI"}


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
        raise ValueError("Progress needs valid paired completion counts.")
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
        path = root / ".security-mcp" / "progress.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(
            path,
            json.dumps(
                {
                    "server_version": __version__,
                    "pid": os.getpid(),
                    "repo_root": str(root),
                    "updated_at": now,
                    "tasks": list(tasks.values()),
                },
                ensure_ascii=False,
            ),
        )
