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
    result = review_security_artifacts(tmp_path, tracked=set(), fresh_start=True)

    # Assert
    assert result["status"] == "ERROR"
    assert result["deleted_files"] == []
    assert link.is_symlink()
    assert target.read_text(encoding="utf-8") == "keep"


def test_fresh_cleanup_removes_empty_generated_directories(tmp_path):
    """Remove an empty generated tree without recursively deleting any directory."""
    # Arrange
    root = tmp_path / ".security-mcp"
    (root / "command-logs").mkdir(parents=True)
    (root / "reports").mkdir()
    (root / "audit.jsonl").write_text('{"exit_code":1}\n', encoding="utf-8")

    # Act
    result = review_security_artifacts(tmp_path, tracked=set(), fresh_start=True)

    # Assert
    assert result["status"] == "OK"
    assert result["previous_run_error_count"] == 1
    assert not root.exists()
    assert len(result["deleted_directories"]) == 3


def test_run_logs_are_archived_then_removed_from_the_checkout(tmp_path, monkeypatch):
    """Zip checkout logs into the home folder and leave reports in place."""
    # Arrange
    import zipfile
    from datetime import UTC, datetime
    from pathlib import Path

    from gitlab_security_mcp.security_artifacts import archive_run_logs
    from gitlab_security_mcp.util import checkout_file_id

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "gitlab_security_mcp.security_artifacts.Path.home", lambda: home
    )
    monkeypatch.setattr(
        "gitlab_security_mcp.security_artifacts.read_server_log", lambda: ""
    )
    root = tmp_path / "checkout"
    metadata = root / ".security-mcp"
    (metadata / "command-logs").mkdir(parents=True)
    (metadata / "reports").mkdir()
    (metadata / "audit.jsonl").write_text("audit\n", encoding="utf-8")
    (metadata / "http-timings.jsonl").write_text("http\n", encoding="utf-8")
    (metadata / "command-logs" / "abc.stdout.log").write_text("out\n", encoding="utf-8")
    (metadata / "reports" / "unresolved-remediation.md").write_text(
        "keep\n", encoding="utf-8"
    )
    (metadata / "run-state.json").write_text("{}\n", encoding="utf-8")
    when = datetime(2026, 11, 21, 21, 26, tzinfo=UTC)

    # Act
    result = archive_run_logs(root, "sample-project", when)

    # Assert
    archive = Path(result["path"])
    assert result["status"] == "ARCHIVED"
    assert archive == (
        home
        / "softwareSecurityAuditReports"
        / f"sample-project_2026-11-21T212600Z_{checkout_file_id(root)}.zip"
    )
    with zipfile.ZipFile(result["path"]) as zipped:
        assert zipped.namelist() == [
            "audit.jsonl",
            "http-timings.jsonl",
            "command-logs/abc.stdout.log",
        ]
    assert not (metadata / "audit.jsonl").exists()
    assert not (metadata / "http-timings.jsonl").exists()
    assert not (metadata / "command-logs").exists()
    assert (metadata / "reports" / "unresolved-remediation.md").is_file()
    assert (metadata / "run-state.json").is_file()
    assert archive.is_file()


def test_archive_includes_the_server_diagnostic_log(tmp_path, monkeypatch):
    """The zip keeps stderr text when the checkout has no command logs."""
    # Arrange
    import zipfile
    from datetime import UTC, datetime

    from gitlab_security_mcp.security_artifacts import archive_run_logs

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "gitlab_security_mcp.security_artifacts.Path.home", lambda: home
    )
    server_log = (
        "2026-11-22T02:00:00Z WARNING gitlab_security_mcp [MainThread]: disk failed\n"
    )
    monkeypatch.setattr(
        "gitlab_security_mcp.security_artifacts.read_server_log",
        lambda: server_log,
    )
    root = tmp_path / "checkout"
    root.mkdir()
    when = datetime(2026, 11, 22, 2, 0, tzinfo=UTC)

    # Act
    result = archive_run_logs(root, "sample-project", when)

    # Assert
    assert result["status"] == "ARCHIVED"
    assert result["removed"] == []
    with zipfile.ZipFile(result["path"]) as zipped:
        assert zipped.read("server.log").decode("utf-8") == server_log
