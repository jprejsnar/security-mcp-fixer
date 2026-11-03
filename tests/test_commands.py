"""Verify command boundaries, child cleanup, pipe readers, and audit hashes."""

import json
from datetime import date

import pytest

from gitlab_security_mcp.commands import CommandRunner, assert_allowed
from gitlab_security_mcp.git_ops import branch_name_for, meaningful_status


@pytest.mark.parametrize("failed_start", [1, 2])
def test_reader_start_failure_cleans_up_process(tmp_path, monkeypatch, failed_start):
    # Arrange
    from gitlab_security_mcp import commands

    processes = []
    started_threads = []
    real_popen = commands.subprocess.Popen
    real_start = commands.threading.Thread.start
    attempts = 0

    def recording_popen(*args, **kwargs):
        """Track the tested Git child separately from taskkill helpers."""
        process = real_popen(*args, **kwargs)
        if args[0][0] == "git":
            processes.append(process)
        return process

    def failing_start(thread):
        """Fail one reader start while tracking successfully started threads."""
        nonlocal attempts
        attempts += 1
        if attempts == failed_start:
            raise RuntimeError("Cannot start reader")
        real_start(thread)
        started_threads.append(thread)

    monkeypatch.setattr(commands.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(commands.threading.Thread, "start", failing_start)
    runner = CommandRunner(tmp_path)

    # Act
    with pytest.raises(RuntimeError, match="Cannot start reader"):
        runner.run(["git", "rev-parse", "--is-inside-work-tree"], timeout=30)

    # Assert
    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert processes[0].stdout.closed
    assert processes[0].stderr.closed
    assert all(not thread.is_alive() for thread in started_threads)


def test_fixture_git_processes_have_timeouts(tmp_path, monkeypatch):
    """Bound disposable Git setup processes as well as production commands."""
    # Arrange
    from unittest.mock import Mock

    from tests import conftest

    run = Mock()
    monkeypatch.setattr(conftest.subprocess, "run", run)

    # Act
    conftest.git(tmp_path, "status")
    conftest.commit_all(tmp_path)

    # Assert
    assert run.call_count == 3
    assert all(call.kwargs["timeout"] == 30 for call in run.call_args_list)


def test_pipe_reader_stops_when_descendant_keeps_pipe_open():
    # Arrange
    import os
    import threading

    from gitlab_security_mcp.commands import _read_capped

    read_descriptor, write_descriptor = os.pipe()
    pipe = os.fdopen(read_descriptor, "r", encoding="utf-8")
    os.write(write_descriptor, "output caf\u00e9".encode())
    stop = threading.Event()
    captured = []
    errors = []

    def read():
        """Record reader results without losing thread exceptions."""
        try:
            captured.append(_read_capped(pipe, 100, stop))
        except Exception as exc:
            errors.append(exc)

    reader = threading.Thread(target=read, daemon=True)

    # Act
    reader.start()
    stop.set()
    reader.join(timeout=2)
    finished = not reader.is_alive()
    try:
        # Assert
        assert finished
        assert errors == []
        assert captured == [("output caf\u00e9", False)]
        assert pipe.closed
    finally:
        os.close(write_descriptor)
        reader.join(timeout=2)
        pipe.close()


@pytest.mark.parametrize(
    "argv",
    [["yarn", "up", "-R", "lodash"], ["yarn", "install", "--mode=update-lockfile"]],
)
def test_modern_yarn_remediation_disables_scripts_and_allows_lock_changes(argv):
    # Arrange
    from gitlab_security_mcp.commands import _child_env

    # Act
    environment = _child_env(argv)

    # Assert
    assert environment["YARN_ENABLE_SCRIPTS"] == "false"
    assert environment["YARN_ENABLE_IMMUTABLE_INSTALLS"] == "false"


def test_server_notes_do_not_count_as_a_dirty_tree():
    # Arrange
    metadata = "?? .security-mcp/audit.jsonl"
    source = "?? package.json"

    # Act
    ignored = meaningful_status(metadata)
    dirty = meaningful_status(source)

    # Assert
    assert ignored == []
    assert dirty == ["?? package.json"]


def test_branch_name_uses_english_month():
    # Arrange
    day = date(2026, 11, 1)

    # Act
    name = branch_name_for(day)

    # Assert
    assert name == "security-fixes-November-01-2026"


def test_git_mutations_are_rejected(repo):
    # Arrange
    (repo / "note.txt").write_text("local\n", encoding="utf-8")
    runner = CommandRunner(repo)

    # Act
    with pytest.raises(PermissionError):
        runner.run(["git", "add", "note.txt"], timeout=30)
    with pytest.raises(PermissionError):
        runner.run(["git", "commit", "-m", "nope"], timeout=30)
    with pytest.raises(PermissionError):
        runner.run(["git", "push"], timeout=30)
    with pytest.raises(PermissionError):
        runner.run(["git", "reset", "--hard"], timeout=30)
    with pytest.raises(PermissionError):
        runner.run(["git", "checkout", "-b", "feature"], timeout=30)
    status = runner.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], timeout=30
    )

    # Assert
    assert "note.txt" in status.stdout
    assert "A " not in status.stdout


def test_security_branch_checkout_is_allowed(repo):
    # Arrange
    checkout = ["git", "checkout", "-b", "security-fixes-November-01-2026"]
    refresh = [
        "npm",
        "install",
        "--package-lock-only",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
    ]

    # Act
    assert_allowed(checkout, repo)
    assert_allowed(refresh, repo)

    # Assert
    assert checkout[0] == "git"
    assert refresh[0] == "npm"


def test_shell_metacharacters_are_rejected(repo):
    # Arrange
    argv = ["npm", "ci;calc"]

    # Act / Assert
    with pytest.raises(PermissionError):
        assert_allowed(argv, repo)


def test_relative_executable_paths_are_rejected(repo):
    # Arrange
    argv = ["node_modules/.bin/npm", "ci"]

    # Act / Assert
    with pytest.raises(PermissionError, match="Relative executable"):
        assert_allowed(argv, repo)


def test_children_get_an_empty_stdin_and_no_git_prompt(repo, monkeypatch):
    # Arrange
    import subprocess

    from gitlab_security_mcp import commands

    seen: dict = {}
    real_popen = subprocess.Popen

    def recording_popen(*args, **kwargs):
        """Capture child-launch options while running a real Git probe."""
        seen.update(kwargs)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(commands.subprocess, "Popen", recording_popen)
    runner = CommandRunner(repo)

    # Act
    runner.run(["git", "rev-parse", "--is-inside-work-tree"], timeout=30)

    # Assert
    assert seen["stdin"] is subprocess.DEVNULL
    assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert seen["shell"] is False


def test_timeout_kills_the_command_and_reports_124(repo):
    # Arrange
    runner = CommandRunner(repo)

    # Act
    result = runner.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        timeout=0,
        check=False,
    )

    # Assert
    assert result.exit_code == 124
    assert "Timed out after 0s" in result.stderr


def test_audit_log_stores_hashes_and_truncates(repo):
    # Arrange
    from tests.conftest import commit_all

    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    commit_all(repo)
    runner = CommandRunner(repo, max_output=8)

    # Act
    result = runner.run(["git", "rev-parse", "HEAD"], timeout=30)
    record = json.loads(runner.audit_path.read_text(encoding="utf-8").splitlines()[-1])

    # Assert
    assert result.truncated is True
    assert len(result.stdout) == 8
    assert record["stdout_sha256"] == result.stdout_sha256
    assert "stdout" not in record
    assert record["truncated"] is True
