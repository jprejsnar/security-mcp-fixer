"""Verify error-aware cleanup never deletes evidence, policies or tracked files."""

import json

import pytest

from gitlab_security_mcp.security_artifacts import review_security_artifacts


@pytest.fixture
def server_spool(tmp_path, monkeypatch):
    """Provide one isolated process spool without reading the test runner's logs."""
    path = tmp_path / "server-spool.log"
    path.write_bytes(b"")
    monkeypatch.setattr(
        "gitlab_security_mcp.security_artifacts.server_log_snapshot",
        lambda: (path, path.stat().st_size),
    )
    return path


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


def test_fresh_cleanup_keeps_startup_logs_and_removes_empty_directories(tmp_path):
    """Startup already appended command records; keep them until final archival."""
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
    assert (root / "audit.jsonl").read_text(encoding="utf-8") == '{"exit_code":1}\n'
    assert not (root / "command-logs").exists()
    assert not (root / "reports").exists()
    assert len(result["deleted_directories"]) == 2


def test_run_logs_are_archived_then_removed_from_the_checkout(
    tmp_path, monkeypatch, server_spool
):
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
        "gitlab_security_mcp.security_artifacts.LOG_ARCHIVE_DIRECTORY",
        str(home / "softwareSecurityAuditReports"),
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
    generated = {
        "progress.json": '{"status":"FINISHED"}',
        "lint-issues.json": '{"issues":[]}',
        "lint-rules.json": "{}",
        "no-tests-v1.init.gradle": "gradle.taskGraph.whenReady {}\n",
        "reports/security-remediation-report-current.json": "{}",
        "reports/security-remediation-report-current.md": "# Report\n",
    }
    for relative, content in generated.items():
        (metadata / relative).write_text(content, encoding="utf-8")
    (metadata / "package-update-policy.json").write_text(
        "private policy", encoding="utf-8"
    )
    audit_report = home / "sample_software_audit_report.md"
    audit_report.write_text("# Software audit\n", encoding="utf-8")
    when = datetime(2026, 11, 21, 21, 26, tzinfo=UTC)

    # Act
    result = archive_run_logs(root, "sample-project", when, audit_report=audit_report)

    # Assert
    archive = Path(result["path"])
    assert result["status"] == "ARCHIVED"
    assert archive == (
        home
        / "softwareSecurityAuditReports"
        / f"sample-project_2026-11-21T212600Z_{checkout_file_id(root)}.zip"
    )
    with zipfile.ZipFile(result["path"]) as zipped:
        assert sorted(zipped.namelist()) == sorted(
            [
                "audit.jsonl",
                "http-timings.jsonl",
                "command-logs/abc.stdout.log",
                "run-state.json",
                "reports/unresolved-remediation.md",
                "software-audit/sample_software_audit_report.md",
                *generated,
            ]
        )
        for relative in generated:
            assert zipped.read(relative) == (metadata / relative).read_bytes()
        assert (
            zipped.read("software-audit/sample_software_audit_report.md")
            == audit_report.read_bytes()
        )
    assert not (metadata / "audit.jsonl").exists()
    assert not (metadata / "http-timings.jsonl").exists()
    assert not (metadata / "command-logs").exists()
    assert (metadata / "reports" / "unresolved-remediation.md").is_file()
    assert (metadata / "run-state.json").is_file()
    assert all((metadata / relative).is_file() for relative in generated)
    assert (metadata / "package-update-policy.json").is_file()
    assert audit_report.is_file()
    assert archive.is_file()


def test_archive_includes_the_server_diagnostic_log(
    tmp_path, monkeypatch, server_spool
):
    """The zip keeps stderr text when the checkout has no command logs."""
    # Arrange
    import zipfile
    from datetime import UTC, datetime

    from gitlab_security_mcp.security_artifacts import archive_run_logs

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(
        "gitlab_security_mcp.security_artifacts.LOG_ARCHIVE_DIRECTORY",
        str(home / "softwareSecurityAuditReports"),
    )
    server_log = (
        "2026-11-22T02:00:00Z WARNING gitlab_security_mcp [MainThread]: disk failed\n"
    )
    server_spool.write_bytes(server_log.encode("utf-8"))
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


def test_archive_retries_merge_all_nested_logs_into_one_zip(
    tmp_path, monkeypatch, server_spool
):
    """Keep earlier members and include nonstandard logs without retaining checkout logs."""
    # Arrange
    import zipfile
    from datetime import UTC, datetime
    from pathlib import Path

    from gitlab_security_mcp.security_artifacts import archive_run_logs

    metadata = tmp_path / ".security-mcp"
    nested = metadata / "tools" / "build"
    nested.mkdir(parents=True)
    (metadata / "audit.jsonl").write_text("audit\n", encoding="utf-8")
    (nested / "custom.LOG").write_bytes(b"first\n")
    server_spool.write_bytes(b"server\n")
    when = datetime(2026, 11, 23, tzinfo=UTC)
    first = archive_run_logs(tmp_path, "sample", when)
    (metadata / "late.log").write_bytes(b"late\n")

    # Act
    second = archive_run_logs(tmp_path, "sample", when)

    # Assert
    assert first["path"] == second["path"]
    assert len(list(Path(first["path"]).parent.glob("*.zip"))) == 1
    with zipfile.ZipFile(second["path"]) as zipped:
        assert set(zipped.namelist()) == {
            "audit.jsonl",
            "tools/build/custom.LOG",
            "server.log",
            "late.log",
        }
        assert zipped.read("tools/build/custom.LOG") == b"first\n"
        assert zipped.read("late.log") == b"late\n"
        assert zipped.testzip() is None
    assert not list(metadata.rglob("*.log"))
    assert not nested.exists()


def test_archive_streams_a_fixed_server_log_prefix_in_bounded_chunks(
    tmp_path, monkeypatch, server_spool
):
    """Flush the spool, copy all original bytes, and never chase concurrent appends."""
    # Arrange
    import zipfile
    from contextlib import contextmanager
    from datetime import UTC, datetime
    from pathlib import Path
    from unittest.mock import Mock

    from gitlab_security_mcp import security_artifacts, util

    payload = ("trace-\u00e9\n" * 30000).encode("utf-8")
    server_spool.write_bytes(payload)
    handler = util._ServerLogHandler(server_spool)
    handler._stream.write("pending\n")
    payload += b"pending\n"
    monkeypatch.setattr(util, "_server_log_handler", handler)
    monkeypatch.setattr(
        security_artifacts, "server_log_snapshot", util.server_log_snapshot
    )
    original_open = Path.open
    read_sizes = []

    @contextmanager
    def bounded_reader():
        """Reject whole-file reads and append new text after capturing the boundary."""
        with original_open(server_spool, "rb") as stream:
            guarded = Mock(wraps=stream)

            def read(size=-1):
                """Enforce the archive's byte bound on every actual source read."""
                assert 0 < size <= security_artifacts._SERVER_LOG_COPY_BYTES
                if not read_sizes:
                    with original_open(server_spool, "ab") as writer:
                        writer.write(b"late append\n")
                read_sizes.append(size)
                return stream.read(size)

            guarded.read.side_effect = read
            yield guarded

    def open_path(path, mode="r", *args, **kwargs):
        """Guard only the spool reader, not ZIP files or other evidence."""
        if path == server_spool and mode == "rb":
            return bounded_reader()
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_path)

    # Act
    try:
        result = security_artifacts.archive_run_logs(
            tmp_path, "sample", datetime.now(UTC)
        )
    finally:
        handler.close()

    # Assert
    assert len(read_sizes) > 1
    with zipfile.ZipFile(result["path"]) as archive:
        assert archive.read("server.log") == payload
        assert archive.testzip() is None


@pytest.mark.parametrize("failure", ["snapshot", "truncated"])
def test_server_spool_failure_preserves_all_checkout_logs(
    tmp_path, monkeypatch, server_spool, failure
):
    """A missing or shortened spool is an explicit failure, never an incomplete ZIP."""
    # Arrange
    from datetime import UTC, datetime

    from gitlab_security_mcp import security_artifacts

    metadata = tmp_path / ".security-mcp"
    metadata.mkdir()
    log = metadata / "audit.jsonl"
    log.write_bytes(b"evidence\n")
    server_spool.write_bytes(b"server\n")

    def snapshot():
        """Simulate an unreadable spool or a stale byte boundary."""
        if failure == "snapshot":
            raise OSError("spool unavailable")
        return server_spool, server_spool.stat().st_size + 1

    monkeypatch.setattr(security_artifacts, "server_log_snapshot", snapshot)

    # Act
    with pytest.raises(OSError, match="spool unavailable|truncated"):
        security_artifacts.archive_run_logs(tmp_path, "sample", datetime.now(UTC))

    # Assert
    assert log.read_bytes() == b"evidence\n"
    destination = tmp_path / security_artifacts.LOG_ARCHIVE_DIRECTORY
    assert not list(destination.glob("*.zip"))
    assert not list(destination.glob("*.zip.tmp"))


@pytest.mark.parametrize("failure", ["write", "changed"])
def test_archive_failure_preserves_checkout_logs(tmp_path, monkeypatch, failure):
    """Never remove logs when writing fails or a writer changes the snapshot."""
    # Arrange
    from datetime import UTC, datetime

    from gitlab_security_mcp import security_artifacts

    metadata = tmp_path / ".security-mcp"
    metadata.mkdir()
    path = metadata / "audit.jsonl"
    path.write_text("before\n", encoding="utf-8")
    original = security_artifacts.zipfile.ZipFile.write

    def write(archive, *args, **kwargs):
        """Fail or append a new line after the archived bytes were read."""
        if failure == "write":
            raise OSError("disk full")
        original(archive, *args, **kwargs)
        path.write_text("changed after read\n", encoding="utf-8")

    monkeypatch.setattr(security_artifacts.zipfile.ZipFile, "write", write)

    # Act
    with pytest.raises((OSError, ValueError), match="disk full|changed"):
        security_artifacts.archive_run_logs(tmp_path, "sample", datetime.now(UTC))

    # Assert
    assert path.is_file()


def test_archive_tolerates_live_progress_updates_while_zipping(tmp_path, monkeypatch):
    """A background progress rewrite is not a changed log; archival still completes."""
    # Arrange
    from datetime import UTC, datetime

    from gitlab_security_mcp import security_artifacts

    monkeypatch.setattr(security_artifacts.Path, "home", lambda: tmp_path)
    metadata = tmp_path / ".security-mcp"
    metadata.mkdir()
    log = metadata / "audit.jsonl"
    log.write_text('{"exit_code": 0}\n', encoding="utf-8")
    progress = metadata / "progress.json"
    progress.write_text('{"tasks": []}', encoding="utf-8")
    original = security_artifacts.zipfile.ZipFile.write

    def write(archive, *args, **kwargs):
        """Model another task publishing progress after its bytes were read."""
        original(archive, *args, **kwargs)
        progress.write_text('{"tasks": [{"status": "FINISHED"}]}', encoding="utf-8")

    monkeypatch.setattr(security_artifacts.zipfile.ZipFile, "write", write)

    # Act
    result = security_artifacts.archive_run_logs(tmp_path, "sample", datetime.now(UTC))

    # Assert
    assert result["status"] == "ARCHIVED"
    assert not log.exists()
    assert progress.is_file()
