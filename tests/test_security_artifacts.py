"""Verify error-aware cleanup never deletes evidence, policies or tracked files."""

import json

import pytest

from gitlab_security_mcp.security_artifacts import review_security_artifacts


@pytest.mark.parametrize(
    "filename,contents",
    [
        ("audit.jsonl", '{"exit_code": 1}\n'),
        ("http-timings.jsonl", '{"source":"advisory","status_code":503}\n'),
        ("http-timings.jsonl", '{"error":"ReadTimeout","status_code":null}\n'),
        ("audit.jsonl", "{broken\n"),
        ("command-logs/old.stderr.log", "Traceback (most recent call last):\n"),
        ("command-logs/old.stderr.log", "TypeError: Cannot read properties\n"),
        ("nested/server.log", "java.lang.NullPointerException: null\n"),
        ("nested/server.log", "2026-11-13 12:30:00.100 ERROR Request failed\n"),
        ("run-state.json", '{"status":"PREPARATION_FAILED"}'),
        ("run-state.json", '{"gitlab_dismissals":[{"status":"PENDING"}]}'),
    ],
)
def test_prior_runtime_errors_preserve_all_generated_files(
    tmp_path, filename, contents
):
    """Scan nested logs and preserve every artifact when execution failed."""
    # Arrange
    root = tmp_path / ".security-mcp"
    log = root / filename
    log.parent.mkdir(parents=True)
    log.write_text(contents, encoding="utf-8")
    state = root / "run-state.json"
    if not state.exists():
        state.write_text('{"previous":"run"}', encoding="utf-8")
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}

    # Act
    result = review_security_artifacts(tmp_path, tracked=set())

    # Assert
    assert result["status"] == "ERROR"
    assert result["error_count"] > 0
    assert not result["cleanup_performed"]
    assert result["deleted_files"] == []
    assert {path: path.read_bytes() for path in before} == before


def test_error_free_cleanup_removes_only_owned_untracked_outputs(tmp_path):
    """Do not confuse normal diagnostic prose/advisory misses with runtime errors."""
    # Arrange
    root = tmp_path / ".security-mcp"
    files = {
        "audit.jsonl": json.dumps({"exit_code": 0}) + "\n",
        "http-timings.jsonl": json.dumps({"source": "advisory", "status_code": 404})
        + "\n",
        "command-logs/old.stderr.log": "0 errors; no runtime errors found.\n",
        "run-state.json": "{}",
        "lint-issues.json": "{}",
        "reports/security-remediation-report-old.md": "Old generated report.",
        "reports/security-remediation-report-tracked.md": "Tracked evidence.",
        "package-update-policy.json": '{"keep":"policy"}',
        "config.json": '{"keep":"configuration"}',
        "notes.txt": "Unknown files are not ours to delete.",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    outside = tmp_path / "security-test.py"
    outside.write_text("unrelated untracked work", encoding="utf-8")
    tracked = {".security-mcp/reports/security-remediation-report-tracked.md"}

    # Act
    result = review_security_artifacts(tmp_path, tracked)

    # Assert
    assert result["status"] == "OK"
    assert result["logs_scanned"] == 3
    assert len(result["deleted_files"]) == 6
    assert root.is_dir()
    for relative in (
        "reports/security-remediation-report-tracked.md",
        "package-update-policy.json",
        "config.json",
        "notes.txt",
    ):
        assert (root / relative).read_text(encoding="utf-8") == files[relative]
    assert outside.read_text(encoding="utf-8") == "unrelated untracked work"


def test_security_artifact_link_blocks_cleanup(tmp_path):
    """Never follow or delete an artifact link, even when its target is in the repo."""
    # Arrange
    root = tmp_path / ".security-mcp"
    root.mkdir()
    target = tmp_path / "keep.log"
    target.write_text("keep", encoding="utf-8")
    link = root / "audit.jsonl"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("This Windows account cannot create symbolic links")

    # Act
    result = review_security_artifacts(tmp_path, tracked=set())

    # Assert
    assert result["status"] == "ERROR"
    assert result["deleted_files"] == []
    assert link.is_symlink()
    assert target.read_text(encoding="utf-8") == "keep"
