"""Verify editor progress snapshots are truthful inspection data."""

import json

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
