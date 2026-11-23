"""Verify editor progress snapshots are truthful inspection data."""

import json
import os
from pathlib import Path

import pytest

from gitlab_security_mcp import progress


def test_background_activity_is_persisted_after_the_initiating_tool_finishes(tmp_path):
    """Keep distinct task owners so a returned request cannot complete its worker."""
    # Arrange
    progress.publish(tmp_path, "request", "Select fixes", "Opening")
    progress.publish(tmp_path, "worker", "Build", "Resolving dependencies")

    # Act
    progress.publish(
        tmp_path, "request", "Select fixes", "Window shown", status="FINISHED"
    )
    snapshot = json.loads(
        (tmp_path / ".security-mcp" / "progress.json").read_text(encoding="utf-8")
    )

    # Assert
    tasks = {item["id"]: item for item in snapshot["tasks"]}
    assert tasks["worker"]["status"] == "RUNNING"
    assert tasks["worker"]["total"] is None
    assert tasks["request"]["status"] == "FINISHED"


def test_invalid_progress_does_not_replace_valid_coverage(tmp_path):
    """Refuse impossible percentages without losing the last valid receipt."""
    # Arrange
    progress.publish(tmp_path, "audit", "Audit", "Read caller", completed=1, total=3)

    # Act
    with pytest.raises(ValueError, match="counts"):
        progress.publish(tmp_path, "audit", "Audit", "Invalid", completed=4, total=3)
    snapshot = json.loads(
        (tmp_path / ".security-mcp" / "progress.json").read_text(encoding="utf-8")
    )

    # Assert
    assert snapshot["tasks"][0]["completed"] == 1
    assert snapshot["tasks"][0]["total"] == 3


def test_final_workflow_receipt_survives_more_than_ten_finished_tool_calls(tmp_path):
    """Keep the newly completed workflow even though its owner was inserted first."""
    # Arrange
    progress.publish(tmp_path, "workflow", "Seven jobs", "Starting")
    for index in range(15):
        progress.publish(tmp_path, str(index), "Tool", "Finished", status="FINISHED")

    # Act
    progress.publish(
        tmp_path,
        "workflow",
        "Seven jobs",
        "Final report ready",
        status="FINISHED",
        completed=7,
        total=7,
        unit="jobs finished",
        final_report=True,
    )
    snapshot = json.loads(
        (tmp_path / ".security-mcp" / "progress.json").read_text(encoding="utf-8")
    )

    # Assert
    assert len(snapshot["tasks"]) == 10
    task = next(item for item in snapshot["tasks"] if item["id"] == "workflow")
    assert task["final_report"] is True
    assert task["completed"] == 7
    progress.publish(
        tmp_path, "workflow", "Seven jobs", "Late cleanup", status="FINISHED"
    )
    repeated = json.loads(
        (tmp_path / ".security-mcp" / "progress.json").read_text(encoding="utf-8")
    )
    assert (
        next(item for item in repeated["tasks"] if item["id"] == "workflow")[
            "started_at"
        ]
        == task["started_at"]
    )


def test_progress_is_mirrored_for_editors_that_did_not_open_the_checkout(
    tmp_path, isolated_progress_mirror
):
    """The GUI must find a run even when the audited checkout is not a workspace folder."""
    # Arrange
    first, second = tmp_path / "one", tmp_path / "two"

    # Act
    progress.publish(first, "audit", "Audit", "Reading", completed=1, total=4)
    progress.publish(second, "audit", "Audit", "Reading")

    # Assert
    local = (first / ".security-mcp" / "progress.json").read_text(encoding="utf-8")
    mirrored = progress.mirror_path(first)
    assert mirrored.parent == isolated_progress_mirror
    assert mirrored.read_text(encoding="utf-8") == local
    assert json.loads(local)["repo_root"] == str(first)
    assert progress.mirror_path(second) != mirrored
    assert len(list(isolated_progress_mirror.glob("*.json"))) == 2


_DEVICE_CHECKOUT = "\\\\?\\C:\\Repo"
_DEVICE_SHARE = "\\\\?\\UNC\\server\\share\\repo"
_OPEN_CHECKOUT = "C:\\Repo"
_OPEN_SHARE = "\\\\server\\share\\repo"


@pytest.mark.skipif(os.name != "nt", reason="Windows device prefixes")
def test_closed_checkout_forgets_in_memory_progress(tmp_path, isolated_progress_mirror):
    """Closing a checkout must not keep its task receipts in the server process."""
    # Arrange
    progress.publish(tmp_path, "audit", "Audit", "Reading", completed=1, total=2)

    # Act
    progress.drop_checkout(tmp_path)
    progress.publish(tmp_path, "other", "Other", "Next")
    snapshot = json.loads(
        (tmp_path / ".security-mcp" / "progress.json").read_text(encoding="utf-8")
    )

    # Assert
    assert {item["id"] for item in snapshot["tasks"]} == {"other"}
    assert progress.mirror_path(tmp_path).read_text(encoding="utf-8") == (
        tmp_path / ".security-mcp" / "progress.json"
    ).read_text(encoding="utf-8")


def test_editor_progress_path_drops_the_windows_device_prefix():
    """Editors open normal paths, not the Windows \\\\?\\ device form."""
    # Arrange
    checkout = Path(_DEVICE_CHECKOUT)
    share = Path(_DEVICE_SHARE)

    # Act
    checkout_text = progress.editor_repo_root(checkout)
    share_text = progress.editor_repo_root(share)

    # Assert
    assert checkout_text == _OPEN_CHECKOUT
    assert share_text == _OPEN_SHARE
