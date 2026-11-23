"""Verify command boundaries, child cleanup, pipe readers, and audit hashes."""

import gc
import json
import logging
import os
import threading
from datetime import date
from unittest.mock import Mock

import pytest

from gitlab_security_mcp.commands import CommandRunner, _child_env, assert_allowed
from gitlab_security_mcp.git_ops import branch_name_for, meaningful_status


@pytest.mark.parametrize(
    "argv",
    [
        ["dotnet", "format", "--verify-no-changes", "--no-restore"],
        [
            "mvn",
            "--batch-mode",
            "checkstyle:check",
            "-Dcheckstyle.includeTestSourceDirectory=true",
        ],
        ["gradle", "--no-daemon", "checkstyleMain", "checkstyleTest"],
    ],
)
def test_read_only_package_lint_commands_are_allowlisted(tmp_path, argv):
    """Read-only package lint commands are allowlisted."""
    # Arrange
    # The command under test is the argv parameter.

    # Act
    assert_allowed(argv, tmp_path)

    # Assert
    with pytest.raises(PermissionError):
        assert_allowed([*argv, "--fix"], tmp_path)


@pytest.mark.parametrize("step", ["clean", "install"])
def test_unnecessary_pnpm_preparation_cannot_run_hooks(tmp_path, step):
    """Reject unguarded clean/install lifecycle commands during remediation."""
    # Arrange
    argv = ["pnpm", step]

    # Act
    with pytest.raises(PermissionError):
        assert_allowed(argv, tmp_path)

    # Assert
    with pytest.raises(PermissionError):
        assert_allowed([*argv, "--force"], tmp_path)


@pytest.mark.parametrize("failed_start", [1, 2])
@pytest.mark.parametrize("after_start", [False, True])
def test_reader_start_failure_cleans_up_process(
    tmp_path, monkeypatch, failed_start, after_start
):
    """Reap children and join readers even if start raises after launching a thread."""
    # Arrange
    import time

    from gitlab_security_mcp import commands

    processes = []
    started_threads = []
    real_popen = commands.subprocess.Popen
    real_start = commands.threading.Thread.start
    real_read = commands._read_capped
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
        if attempts == failed_start and not after_start:
            raise RuntimeError("Cannot start reader")
        real_start(thread)
        started_threads.append(thread)
        if attempts == failed_start:
            raise RuntimeError("Cannot start reader")

    def delayed_read(pipe, limit, stop, **kwargs):
        """Keep launched readers alive long enough to expose missing joins."""
        stop.wait(timeout=2)
        time.sleep(0.1)
        return real_read(pipe, limit, stop, **kwargs)

    monkeypatch.setattr(commands.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(commands.threading.Thread, "start", failing_start)
    if after_start:
        monkeypatch.setattr(commands, "_read_capped", delayed_read)
    runner = CommandRunner(tmp_path)

    # Act
    with pytest.raises(RuntimeError, match="Cannot start reader"):
        runner.run(["git", "rev-parse", "--is-inside-work-tree"], timeout=30)

    # Assert
    try:
        assert len(processes) == 1
        assert processes[0].poll() is not None
        assert processes[0].stdout.closed
        assert processes[0].stderr.closed
        assert all(not thread.is_alive() for thread in started_threads)
    finally:
        for thread in started_threads:
            thread.join(timeout=3)


def test_progress_cancellation_reaps_child_before_readers_start(tmp_path, monkeypatch):
    """Cancel initial progress without leaving a live child or open pipes."""
    # Arrange
    import sys

    from gitlab_security_mcp import commands

    children = []
    real_popen = commands.subprocess.Popen

    def launch(argv, **kwargs):
        """Substitute a long-lived real process for the Git probe."""
        if argv[0] != "git":
            return real_popen(argv, **kwargs)
        child = real_popen(
            [sys.executable, "-c", "import time; time.sleep(60)"], **kwargs
        )
        children.append(child)
        return child

    def cancel(text):
        """Interrupt the command before output readers have been constructed."""
        raise KeyboardInterrupt("cancel progress")

    monkeypatch.setattr(commands.subprocess, "Popen", launch)
    runner = CommandRunner(tmp_path, progress_callback=cancel)

    # Act
    try:
        with pytest.raises(KeyboardInterrupt, match="cancel progress"):
            runner.run(["git", "rev-parse", "HEAD"], timeout=30)

        # Assert
        assert children[0].poll() is not None
        assert children[0].stdout.closed
        assert children[0].stderr.closed
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            commands._close_pipes(child)


@pytest.mark.parametrize("failure", ["disk", "cancel"])
def test_reader_failure_stops_child_without_waiting_for_timeout(
    tmp_path, monkeypatch, failure
):
    """Reader exceptions and cancellation stop the producer before its timeout."""
    # Arrange
    import sys
    import time

    from gitlab_security_mcp import commands

    children = []
    real_popen = commands.subprocess.Popen
    real_open = commands.Path.open
    log_handles = []

    def launch(argv, **kwargs):
        """Run a real child which would otherwise remain alive for a minute."""
        if argv[0] != "pnpm":
            return real_popen(argv, **kwargs)
        output = (
            "time.sleep(0.4); print('Build output', flush=True); "
            if failure == "cancel"
            else ""
        )
        child = real_popen(
            [sys.executable, "-c", f"import time; {output}time.sleep(60)"],
            **kwargs,
        )
        children.append(child)
        return child

    def fail_log(path, *args, **kwargs):
        """Reproduce a disk failure in an output reader."""
        if path.suffix == ".log" and failure == "disk":
            raise OSError("log disk unavailable")
        handle = real_open(path, *args, **kwargs)
        if path.suffix == ".log":
            log_handles.append(handle)
        return handle

    def cancel_progress(text):
        """Reproduce cancellation raised by a reader's progress callback."""
        if failure == "cancel" and "output bytes received" in text:
            raise KeyboardInterrupt("cancel reader")

    monkeypatch.setattr(commands.subprocess, "Popen", launch)
    monkeypatch.setattr(commands.Path, "open", fail_log)
    runner = CommandRunner(tmp_path, progress_callback=cancel_progress)
    started = time.monotonic()

    # Act
    with pytest.raises(RuntimeError, match="Could not read command output"):
        runner.run(["pnpm", "run", "build"], timeout=4)

    # Assert
    assert time.monotonic() - started < 3
    assert children[0].poll() is not None
    assert children[0].stdout.closed
    assert children[0].stderr.closed
    assert all(handle.closed for handle in log_handles)


def _test_pid_running(pid):
    """Inspect a descendant without sending Windows' destructive signal zero."""
    import os

    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x00100000, False, pid)
        if not handle:
            return False
        try:
            return kernel.WaitForSingleObject(handle, 0) == 258
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    from pathlib import Path

    stat = Path(f"/proc/{pid}/stat")
    return (
        not stat.exists()
        or stat.read_text(encoding="utf-8").split(") ", 1)[1][0] != "Z"
    )


@pytest.mark.parametrize("outcome", ["exit", "immediate-exit", "timeout", "cancel"])
def test_command_cleanup_stops_inherited_pipe_descendants(
    tmp_path, monkeypatch, outcome
):
    """Stop a real descendant even when its direct parent exits successfully."""
    # Arrange
    import os
    import signal
    import sys
    import time

    from gitlab_security_mcp import commands

    gate = tmp_path / "start"
    pid_file = tmp_path / "descendant"
    wait_for_gate = (
        "\nwhile not gate.exists(): time.sleep(0.01)\n"
        if outcome != "immediate-exit"
        else "\n"
    )
    script = (
        "import pathlib, subprocess, sys, time; "
        f"gate = pathlib.Path({str(gate)!r}); {wait_for_gate}"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
        f"path = pathlib.Path({str(pid_file)!r}); pending = path.with_suffix('.pending'); "
        "pending.write_text(str(child.pid)); pending.replace(path); "
        + ("time.sleep(60)" if outcome in {"timeout", "cancel"} else "")
    )
    real_popen = commands.subprocess.Popen
    real_wait = commands.subprocess.Popen.wait
    children = []
    cancelled = False

    def launch(argv, **kwargs):
        """Launch a parent which waits until the runner has established ownership."""
        if argv[0] != "git":
            return real_popen(argv, **kwargs)
        child = real_popen([sys.executable, "-c", script], **kwargs)
        children.append(child)
        return child

    def wait(process, *args, **kwargs):
        """Interrupt only the main wait after the descendant is demonstrably alive."""
        nonlocal cancelled
        if outcome == "cancel" and process in children and not cancelled:
            deadline = time.monotonic() + 5
            while not pid_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            cancelled = True
            raise KeyboardInterrupt("cancel wait")
        return real_wait(process, *args, **kwargs)

    monkeypatch.setattr(commands.subprocess, "Popen", launch)
    monkeypatch.setattr(real_popen, "wait", wait)
    if os.name == "nt" and outcome == "immediate-exit":
        real_attach = commands._WindowsJob.attach

        def delayed_attach(job, process):
            """Expose children escaping the job if the root starts unsuspended."""
            time.sleep(0.25)
            real_attach(job, process)

        monkeypatch.setattr(commands._WindowsJob, "attach", delayed_attach)
    runner = CommandRunner(tmp_path, progress_callback=lambda text: gate.touch())

    # Act
    try:
        if outcome == "cancel":
            with pytest.raises(KeyboardInterrupt, match="cancel wait"):
                runner.run(["git", "rev-parse", "HEAD"], timeout=10)
        else:
            result = runner.run(
                ["git", "rev-parse", "HEAD"],
                timeout=1 if outcome == "timeout" else 10,
                check=False,
            )
            assert result.exit_code == (124 if outcome == "timeout" else 0)
        descendant = int(pid_file.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 3
        while _test_pid_running(descendant) and time.monotonic() < deadline:
            time.sleep(0.01)

        # Assert
        assert not _test_pid_running(descendant)
        assert children[0].poll() is not None
        assert children[0].stdout.closed
        assert children[0].stderr.closed
    finally:
        if pid_file.exists():
            descendant = int(pid_file.read_text(encoding="utf-8"))
            if _test_pid_running(descendant):
                os.kill(descendant, signal.SIGTERM)
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            commands._close_pipes(child)


def test_negative_output_cap_is_rejected(tmp_path):
    """Reject negative caps which otherwise grow the tail buffer without bound."""
    # Arrange
    limit = -2

    # Act
    with pytest.raises(ValueError, match="max_output"):
        CommandRunner(tmp_path, max_output=limit)

    # Assert
    assert not (tmp_path / ".security-mcp").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows job ownership")
def test_job_resume_failure_closes_job_and_child_handles(tmp_path, monkeypatch):
    """Release the Windows job and suspended child when resuming fails."""
    # Arrange
    import ctypes
    import sys
    from ctypes import wintypes

    from gitlab_security_mcp import commands

    real_popen = commands.subprocess.Popen
    children = []
    jobs = []
    handles = []

    def launch(argv, **kwargs):
        """Track the real suspended child without replacing taskkill helpers."""
        if argv[0] != "git":
            return real_popen(argv, **kwargs)
        child = real_popen(
            [sys.executable, "-c", "import time; time.sleep(60)"], **kwargs
        )
        children.append(child)
        return child

    def fail_resume(job, pid):
        """Fail after assignment while the child remains suspended."""
        jobs.append(job)
        handles.append(job._handle)
        raise OSError("resume failed")

    monkeypatch.setattr(commands.subprocess, "Popen", launch)
    monkeypatch.setattr(commands._WindowsJob, "_resume", fail_resume)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetHandleInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.GetHandleInformation.restype = wintypes.BOOL
    flags = wintypes.DWORD()

    # Act
    with pytest.raises(OSError, match="resume failed"):
        CommandRunner(tmp_path).run(["git", "rev-parse", "HEAD"], timeout=30)

    # Assert
    assert jobs[0]._handle is None
    assert not kernel.GetHandleInformation(handles[0], ctypes.byref(flags))
    assert ctypes.get_last_error() == 6  # ERROR_INVALID_HANDLE
    assert children[0].poll() is not None
    assert children[0].stdout.closed
    assert children[0].stderr.closed


@pytest.mark.skipif(os.name != "nt", reason="Windows job ownership")
def test_job_assignment_denial_reaps_suspended_child_and_releases_handles(
    tmp_path, monkeypatch
):
    """Fail closed on assignment denial, releasing the job and assignment handles."""
    # Arrange
    import ctypes
    import sys
    from ctypes import wintypes

    from gitlab_security_mcp import commands

    real_popen = commands.subprocess.Popen
    real_init = commands._WindowsJob.__init__
    real_resume = commands._WindowsJob._resume
    children = []
    jobs = []
    handles = []
    resumed = []
    executed = tmp_path / "executed"
    script = (
        f"from pathlib import Path; Path({str(executed)!r}).touch(); "
        "import time; time.sleep(60)"
    )

    def launch(argv, **kwargs):
        """Track the suspended command, leaving PID-specific cleanup unchanged."""
        if argv[0] != "git":
            return real_popen(argv, **kwargs)
        assert kwargs["creationflags"] & 0x00000004  # CREATE_SUSPENDED
        child = real_popen([sys.executable, "-c", script], **kwargs)
        children.append(child)
        return child

    def deny_assignment(job_handle, process_handle):
        """Simulate a restrictive host job refusing nested containment."""
        handles.extend([job_handle, process_handle])
        ctypes.set_last_error(5)  # ERROR_ACCESS_DENIED
        return False

    def initialize(job):
        """Use a real native job and process handle, denying only assignment."""
        real_init(job)
        jobs.append(job)
        monkeypatch.setattr(job._kernel, "AssignProcessToJobObject", deny_assignment)

    def resume(job, pid):
        """Record any attempt to run an uncontained child."""
        resumed.append(pid)
        real_resume(job, pid)

    monkeypatch.setattr(commands.subprocess, "Popen", launch)
    monkeypatch.setattr(commands._WindowsJob, "__init__", initialize)
    monkeypatch.setattr(commands._WindowsJob, "_resume", resume)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetHandleInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.GetHandleInformation.restype = wintypes.BOOL
    flags = wintypes.DWORD()

    # Act
    with pytest.raises(OSError) as raised:
        CommandRunner(tmp_path).run(["git", "rev-parse", "HEAD"], timeout=1)

    # Assert
    assert raised.value.winerror == 5
    assert len(children) == len(jobs) == 1
    assert resumed == []
    assert not executed.exists()
    assert jobs[0]._handle is None
    assert children[0].poll() is not None
    assert children[0].stdout.closed
    assert children[0].stderr.closed
    assert len(handles) == 2
    for handle in handles:
        assert not kernel.GetHandleInformation(handle, ctypes.byref(flags))
        assert ctypes.get_last_error() == 6  # ERROR_INVALID_HANDLE


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
    """Pipe reader stops when descendant keeps pipe open."""
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
    """Modern yarn remediation disables scripts and allows lock changes."""
    # Arrange
    from gitlab_security_mcp.commands import _child_env

    # Act
    environment = _child_env(argv)

    # Assert
    assert environment["YARN_ENABLE_SCRIPTS"] == "false"
    assert environment["YARN_ENABLE_IMMUTABLE_INSTALLS"] == "false"


def test_server_notes_do_not_count_as_a_dirty_tree():
    """Server notes do not count as a dirty tree."""
    # Arrange
    metadata = "?? .security-mcp/audit.jsonl"
    source = "?? package.json"

    # Act
    ignored = meaningful_status(metadata)
    dirty = meaningful_status(source)

    # Assert
    assert ignored == []
    assert dirty == ["?? package.json"]


def test_modified_tracked_security_files_are_not_ignored():
    """Preserve the clean-branch gate for tracked policies and generated files."""
    # Arrange
    status = (
        " M .security-mcp/package-update-policy.json\nM  .security-mcp/run-state.json"
    )

    # Act
    dirty = meaningful_status(status)

    # Assert
    assert dirty == status.splitlines()


def test_branch_name_uses_an_iso_date():
    """Name the security branch with an ISO 8601 calendar date."""
    # Arrange
    day = date(2026, 11, 1)

    # Act
    name = branch_name_for(day)

    # Assert
    assert name == "security-fixes-2026-11-01"


def test_git_mutations_are_rejected(repo):
    """Git mutations are rejected."""
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


@pytest.mark.parametrize(
    "argv",
    [
        ["git", "push", "origin", "HEAD"],
        ["git", "push", "--tags"],
        ["git", "push", "origin", "--delete", "main"],
        ["git", "commit", "-m", "forbidden"],
        ["git", "tag", "release"],
        ["git", "notes", "add", "-m", "forbidden"],
        ["git", "branch", "-D", "main"],
    ],
)
def test_commits_pushes_tags_notes_and_branch_deletion_are_forbidden(repo, argv):
    """Reject publishing or attribute changes before launching any subprocess."""
    # Arrange
    from unittest.mock import patch

    runner = CommandRunner(repo)

    # Act
    with patch("gitlab_security_mcp.commands.subprocess.Popen") as popen:
        with pytest.raises(PermissionError):
            runner.run(argv, timeout=30)

    # Assert
    popen.assert_not_called()


def test_security_branch_checkout_is_allowed(repo):
    """Security branch checkout is allowed."""
    # Arrange
    checkout = ["git", "checkout", "-b", "security-fixes-2026-11-01"]
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
    """Shell metacharacters are rejected."""
    # Arrange
    argv = ["npm", "ci;calc"]

    # Act
    with pytest.raises(PermissionError) as raised:
        assert_allowed(argv, repo)

    # Assert
    assert isinstance(raised.value, PermissionError)


def test_relative_executable_paths_are_rejected(repo):
    """Relative executable paths are rejected."""
    # Arrange
    argv = ["node_modules/.bin/npm", "ci"]

    # Act
    with pytest.raises(PermissionError, match="Relative executable") as raised:
        assert_allowed(argv, repo)

    # Assert
    assert "Relative executable" in str(raised.value)


def test_children_get_an_empty_stdin_and_no_git_prompt(repo, monkeypatch):
    """Children get an empty stdin and no git prompt."""
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
    """Timeout kills the command and reports 124."""
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


@pytest.mark.parametrize("code", [0, 1])
@pytest.mark.parametrize(
    "tool,operation",
    [
        ("pnpm", ["run", "build"]),
        ("pnpm", ["audit", "--json"]),
        ("gradle", ["--no-daemon", "dependencies"]),
    ],
)
def test_product_logs_preserve_all_output_and_final_summary(
    tmp_path, monkeypatch, code, tool, operation
):
    """Keep complete disk logs and final diagnostics without unbounded RAM previews."""
    # Arrange
    import sys

    from gitlab_security_mcp import commands

    real_popen = commands.subprocess.Popen
    summary = "Tests: 4910 passed, 4910 total\n"
    diagnostic = "AssertionError: expected updated dependency API\n"
    script = f"import sys; sys.stdout.write('a'*200000+{summary!r}); sys.stderr.write('b'*200000+{diagnostic!r}); sys.exit({code})"

    def product_process(argv, **kwargs):
        """Replace only the test's pnpm command with a deterministic noisy child."""
        if tool == "gradle":
            assert argv[:3] == [tool, "--no-daemon", "--init-script"]
            assert argv[4:] == operation[1:]
        else:
            assert argv == [tool, *operation]
        return real_popen([sys.executable, "-c", script], **kwargs)

    monkeypatch.setattr(commands.subprocess, "Popen", product_process)
    updates = []
    runner = CommandRunner(tmp_path, max_output=128, progress_callback=updates.append)

    # Act
    result = runner.run([tool, *operation], timeout=30, check=False)
    record = json.loads(runner.audit_path.read_text(encoding="utf-8").splitlines()[-1])

    # Assert
    assert result.exit_code == code
    assert result.truncated is True
    assert len(result.stdout) <= 128
    assert len(result.stderr) <= 128
    assert result.stdout.replace("\r\n", "\n").endswith(summary)
    assert result.stderr.replace("\r\n", "\n").endswith(diagnostic)
    assert (
        commands.Path(result.stdout_log_path).read_text(encoding="utf-8")
        == "a" * 200000 + summary
    )
    assert (
        commands.Path(result.stderr_log_path).read_text(encoding="utf-8")
        == "b" * 200000 + diagnostic
    )
    assert record["stdout_log_path"] == result.stdout_log_path
    assert record["stderr_log_path"] == result.stderr_log_path
    assert not any("4910/4910 tests" in text for text in updates)
    assert updates[-1].endswith(f"command finished; exit {code}")
    assert ("!" * 20 if code else "#" * 20) in updates[-1]


def test_build_progress_is_emitted_before_command_finishes(tmp_path, monkeypatch):
    """Publish live build output without inventing executed-test counts."""
    # Arrange
    import sys

    from gitlab_security_mcp import commands

    real_popen = commands.subprocess.Popen
    children = []
    updates = []
    acknowledged = False
    script = (
        "import sys, time; time.sleep(0.4); print('Compiled sources', flush=True); "
        "sys.stdin.readline(); print('Build complete', flush=True)"
    )

    def product_process(argv, **kwargs):
        """Let only this synthetic child wait for acknowledgement of live progress."""
        kwargs["stdin"] = commands.subprocess.PIPE
        child = real_popen([sys.executable, "-c", script], **kwargs)
        children.append(child)
        return child

    def record_progress(text):
        """Release the child only after live output was reported."""
        nonlocal acknowledged
        updates.append(text)
        if "output bytes received" in text and not acknowledged:
            acknowledged = True
            assert children[0].poll() is None
            children[0].stdin.write("\n")
            children[0].stdin.flush()

    monkeypatch.setattr(commands.subprocess, "Popen", product_process)
    runner = CommandRunner(tmp_path, progress_callback=record_progress)

    # Act
    result = runner.run(["pnpm", "run", "build"], timeout=10, check=False)
    children[0].stdin.close()

    # Assert
    assert result.exit_code == 0
    assert acknowledged
    assert not any("tests (" in text for text in updates)


@pytest.mark.parametrize(
    "argv",
    [
        ["pnpm", "test"],
        ["npm", "test"],
        ["yarn", "test"],
        ["dotnet", "test", "--configuration", "Release", "--nologo"],
        ["gradle", "--no-daemon", "test"],
        ["gradle", "--no-daemon", "assemble", "test", "--rerun"],
        ["mvn", "--batch-mode", "test"],
        ["mvn", "--batch-mode", "clean", "verify"],
    ],
)
def test_test_commands_never_start_children(tmp_path, monkeypatch, argv):
    """Reject test commands before spawning a runner."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import commands

    launch = Mock()
    monkeypatch.setattr(commands.subprocess, "Popen", launch)

    # Act
    with pytest.raises(PermissionError):
        CommandRunner(tmp_path).run(argv, timeout=10)

    # Assert
    launch.assert_not_called()


@pytest.mark.parametrize(
    "scripts",
    [
        {"test": "jest && jest"},
        {"test": "jest; another-command"},
        {"test": "jest", "pretest": "npm run build"},
        {"test": "jest", "posttest": "npm run build"},
    ],
)
def test_jest_discovery_does_not_repeat_hooks_or_compound_scripts(
    tmp_path, monkeypatch, scripts
):
    """Never add hidden work by listing a compound or lifecycle-managed script."""
    # Arrange
    import sys

    from gitlab_security_mcp import commands

    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": scripts}), encoding="utf-8"
    )
    real_popen = commands.subprocess.Popen
    calls = []

    def product_process(argv, **kwargs):
        """Record commands without running fixture-owned package scripts."""
        calls.append(argv)
        return real_popen(
            [sys.executable, "-c", "print('Tests: 1 passed, 1 total')"], **kwargs
        )

    monkeypatch.setattr(commands.subprocess, "Popen", product_process)

    # Act
    with pytest.raises(PermissionError):
        CommandRunner(tmp_path).run(["pnpm", "test"], timeout=10, check=False)

    # Assert
    assert calls == []


def test_documentation_progress_counts_completed_requests():
    """Publish live completion counts for every concurrently fetched document."""
    # Arrange
    import httpx

    from gitlab_security_mcp.commands import progress_sink
    from gitlab_security_mcp.official_docs import REQUIRED_DOCS, OfficialDocs

    updates = []
    body = " ".join(marker for _name, _url, marker in REQUIRED_DOCS)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text=body))
    token = progress_sink.set(updates.append)

    # Act
    try:
        with httpx.Client(transport=transport) as http:
            with OfficialDocs(http=http) as docs:
                review = docs.read_before_fix({"location": {"file": "widget.py"}})
    finally:
        progress_sink.reset(token)

    # Assert
    total = len(review.sources)
    assert review.complete is True
    assert f"0/{total} requests completed" in updates[0]
    assert f"{total}/{total} requests completed" in updates[-1]
    assert len(updates) == total + 1


def test_audit_log_stores_hashes_and_truncates(repo):
    """Audit log stores hashes and truncates."""
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


def test_child_environment_drops_server_credentials(monkeypatch):
    """Keep registry credentials and drop the tokens this server uses."""
    # Arrange
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-server-token")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp-server-token")
    monkeypatch.setenv("GH_TOKEN", "ghp-alias-token")
    monkeypatch.setenv("NVD_API_KEY", "nvd-server-key")
    monkeypatch.setenv("GITLAB_PERSONAL_ACCESS_TOKEN", "glpat-alias")
    monkeypatch.setenv("NPM_TOKEN", "npm-registry-token")

    # Act
    env = _child_env(["npm", "ci", "--ignore-scripts"])

    # Assert
    assert "GITLAB_TOKEN" not in env
    assert "GITHUB_TOKEN" not in env
    assert "GH_TOKEN" not in env
    assert "NVD_API_KEY" not in env
    assert "GITLAB_PERSONAL_ACCESS_TOKEN" not in env
    assert env["NPM_TOKEN"] == "npm-registry-token"
    assert env["GIT_TERMINAL_PROMPT"] == "0"


def test_redact_removes_percent_encoded_secrets():
    """Remove a token both as stored and as it appears in an encoded URL."""
    # Arrange
    from gitlab_security_mcp.util import redact

    secret = "glpat-abc/def"

    # Act
    text = redact("token=glpat-abc/def url=glpat-abc%2Fdef", [secret])

    # Assert
    assert "glpat-abc/def" not in text
    assert "glpat-abc%2Fdef" not in text
    assert text.count("[REDACTED]") == 2


def test_task_performance_logs_cpu_memory_time_and_gc(caplog):
    """Record wall time, process CPU, working set and collection counts."""
    # Arrange
    from gitlab_security_mcp.util import log_task

    # Act
    with caplog.at_level(logging.INFO, logger="gitlab_security_mcp"):
        with log_task("sample-task"):
            gc.collect()
    record = json.loads(caplog.records[-1].message.removeprefix("Task performance "))

    # Assert
    assert record["event"] == "task_performance"
    assert record["task"] == "sample-task"
    assert record["duration_ms"] >= 0
    assert record["cpu_seconds"] >= 0
    assert record["cpu_percent"] >= 0
    assert isinstance(record["memory_bytes"], int)
    assert isinstance(record["memory_delta_bytes"], int)
    assert sum(record["gc_collections"]) >= 1
    assert len(record["gc_collected"]) == 3
    assert len(record["gc_uncollectable"]) == 3
    assert record["error"] is None


def test_task_performance_keeps_the_original_exception(caplog):
    """Log the exception class and still raise it for the caller."""
    # Arrange
    from gitlab_security_mcp.util import log_task

    # Act
    with caplog.at_level(logging.INFO, logger="gitlab_security_mcp"):
        with pytest.raises(ValueError):
            with log_task("failing-task"):
                raise ValueError("secret token glpat-hidden")
    record = json.loads(caplog.records[-1].message.removeprefix("Task performance "))

    # Assert
    assert record["task"] == "failing-task"
    assert record["error"] == "ValueError"
    assert "glpat-hidden" not in caplog.records[-1].message


def test_contended_lock_logs_the_wait(caplog):
    """Log a lock wait only after another thread has released it."""
    # Arrange
    import time

    from gitlab_security_mcp.util import logged_lock

    lock = threading.Lock()
    lock.acquire()
    started = threading.Event()

    def wait_for_lock():
        """Block until the test releases the lock."""
        started.set()
        with logged_lock(lock, "engine"):
            return

    thread = threading.Thread(target=wait_for_lock)
    thread.start()
    assert started.wait(2)
    time.sleep(0.02)

    # Act
    with caplog.at_level(logging.INFO, logger="gitlab_security_mcp"):
        lock.release()
        thread.join(2)
    record = json.loads(caplog.records[-1].message.removeprefix("Concurrency "))

    # Assert
    assert not thread.is_alive()
    assert record["kind"] == "lock_wait"
    assert record["name"] == "engine"
    assert record["wait_ms"] >= 1


def test_uncaught_thread_exception_is_logged(caplog):
    """Record the class of an exception that escaped a worker thread."""
    # Arrange
    from types import SimpleNamespace

    from gitlab_security_mcp.server import _thread_exception

    exc = RuntimeError("secret glpat-hidden")
    args = SimpleNamespace(
        exc_type=type(exc),
        exc_value=exc,
        exc_traceback=exc.__traceback__,
        thread=threading.current_thread(),
    )

    # Act
    target = logging.getLogger("gitlab_security_mcp")
    previous = target.propagate
    target.propagate = True
    try:
        with caplog.at_level(logging.ERROR, logger="gitlab_security_mcp"):
            _thread_exception(args)
    finally:
        target.propagate = previous

    # Assert
    assert "RuntimeError" in caplog.records[-1].message
    assert caplog.records[-1].exc_info[0] is RuntimeError


def test_progress_console_close_survives_a_child_that_ignores_kill():
    """Release the console child when both the wait and the kill wait time out."""
    # Arrange
    import subprocess

    from gitlab_security_mcp.server import _ProgressConsole

    class Pipe:
        """Record whether cleanup closed this stream."""

        def __init__(self):
            """Start the stream open."""
            self.closed = False

        def close(self):
            """Mark the stream closed."""
            self.closed = True

    class Child:
        """Ignore both waits and record the kill."""

        def __init__(self):
            """Provide streams and start unkilled."""
            self.pid = 123456
            self.stdin = Pipe()
            self.stdout = Pipe()
            self.stderr = None
            self.killed = False

        def wait(self, timeout):
            """Time out so cleanup must not raise."""
            raise subprocess.TimeoutExpired("console", timeout)

        def kill(self):
            """Record the forced stop."""
            self.killed = True

    child = Child()
    console = _ProgressConsole(child)

    # Act
    console.close()

    # Assert
    assert child.killed
    assert child.stdin.closed
    assert child.stdout.closed


_BROKEN_PROGRESS_PIPE = "broken pipe"


def test_progress_console_write_failure_records_the_cause(caplog):
    """Keep the pipe error when the Windows progress console stops accepting text."""
    # Arrange
    from gitlab_security_mcp.server import _ProgressConsole, logger

    process = Mock()
    process.stdin.write.side_effect = OSError(_BROKEN_PROGRESS_PIPE)
    console = _ProgressConsole(process)
    previous = logger.propagate
    logger.propagate = True

    # Act
    try:
        with caplog.at_level(logging.WARNING, logger="gitlab_security_mcp"):
            console.write("hello")
            console.write("again")
    finally:
        logger.propagate = previous

    # Assert
    assert _BROKEN_PROGRESS_PIPE in caplog.text
    assert (
        sum("Progress console closed" in record.message for record in caplog.records)
        == 1
    )
    assert caplog.records[-1].exc_info[0] is OSError


def test_unreaped_command_is_an_explicit_cleanup_failure(monkeypatch, caplog):
    """Do not publish successful cleanup while the owned command is still alive."""
    # Arrange
    import subprocess
    from unittest.mock import Mock

    from gitlab_security_mcp import commands

    process = Mock(pid=123456)
    process.poll.return_value = None
    process.wait.side_effect = subprocess.TimeoutExpired("synthetic", 10)
    monkeypatch.setattr(commands.subprocess, "run", Mock())
    monkeypatch.setattr(commands.os, "killpg", Mock(), raising=False)

    # Act
    with pytest.raises(RuntimeError, match="cleanup is incomplete"):
        commands._kill_tree(process)

    # Assert
    process.kill.assert_called_once()
    assert "not reaped" in caplog.text


def test_failed_command_logs_the_exit_and_checkout(tmp_path, caplog):
    """A non-zero command leaves its tool, exit code and checkout on stderr."""
    # Arrange
    runner = CommandRunner(tmp_path)

    # Act
    with caplog.at_level(logging.WARNING, logger="gitlab_security_mcp"):
        with pytest.raises(RuntimeError, match="rev-parse"):
            runner.run(["git", "rev-parse", "HEAD"], timeout=30)

    # Assert
    record = next(
        row for row in caplog.records if row.message.startswith("Command failed")
    )
    assert "tool=git" in record.message
    assert "exit=128" in record.message
    assert str(tmp_path) in record.message


def test_command_start_failure_has_diagnostic_context(tmp_path, monkeypatch, caplog):
    """Log the safe tool, checkout and traceback when no result can be produced."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import commands

    monkeypatch.setattr(commands, "_WindowsJob", Mock())
    monkeypatch.setattr(
        commands.subprocess,
        "Popen",
        Mock(side_effect=OSError("synthetic spawn failure")),
    )
    runner = CommandRunner(tmp_path)

    # Act
    with pytest.raises(OSError, match="synthetic spawn"):
        runner.run(["git", "rev-parse", "HEAD"], timeout=1)

    # Assert
    record = next(row for row in caplog.records if "before a result" in row.message)
    assert "tool=git" in record.message
    assert str(tmp_path) in record.message
    assert record.exc_info[0] is OSError


def test_stderr_formatter_adds_context_and_redacts_tracebacks(monkeypatch):
    """Preserve UTC/thread context without leaking credential values or encodings."""
    # Arrange
    import sys

    from gitlab_security_mcp.server import _stderr_handler

    secret = "fixture/token"
    monkeypatch.setenv("GITLAB_TOKEN", secret)
    try:
        raise ValueError(f"Synthetic credential {secret}")
    except ValueError:
        record = logging.LogRecord(
            "gitlab_security_mcp",
            logging.ERROR,
            __file__,
            1,
            "Synthetic URL fixture%%2Ftoken and %s",
            (secret,),
            sys.exc_info(),
        )
    record.created = 0

    # Act
    formatted = _stderr_handler().format(record)

    # Assert
    assert formatted.startswith("1970-01-01T00:00:00Z ERROR")
    assert record.threadName in formatted
    assert "ValueError" in formatted
    assert secret not in formatted
    assert "fixture%2Ftoken" not in formatted
    assert formatted.count("[REDACTED]") == 3


def test_parse_xml_rejects_entity_expansion():
    """Keep a declared entity from expanding into the parsed document."""
    # Arrange
    from xml.etree.ElementTree import ParseError

    from gitlab_security_mcp.util import parse_xml

    document = """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>
<r>&lol2;</r>
"""

    # Act
    with pytest.raises(ParseError, match="entity declarations") as raised:
        parse_xml(document)

    # Assert
    assert "lol" not in str(raised.value)


def test_parse_xml_keeps_elementtree_names_without_entities():
    """Read a namespaced document and a document type that declares no entities."""
    # Arrange
    import xml.etree.ElementTree as ET

    from gitlab_security_mcp.util import parse_xml

    namespaced = (
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<dependencies><dependency><artifactId>commons-text</artifactId>"
        "</dependency></dependencies></project>"
    )
    typed = (
        '<?xml version="1.0"?><!DOCTYPE project>'
        "<project><artifactId>ok</artifactId></project>"
    )

    # Act
    parsed = parse_xml(namespaced)
    standard = ET.fromstring(namespaced)
    declared = parse_xml(typed)

    # Assert
    assert parsed.tag == standard.tag
    assert parsed.find(".//{http://maven.apache.org/POM/4.0.0}artifactId").text == (
        "commons-text"
    )
    assert declared.find("artifactId").text == "ok"


def test_utc_now_iso_is_the_shared_timestamp():
    """Produce one UTC ISO 8601 string for every log timestamp."""
    # Arrange
    from datetime import UTC, datetime

    from gitlab_security_mcp.util import utc_now_iso

    before = datetime.now(UTC)

    # Act
    text = utc_now_iso()

    # Assert
    parsed = datetime.fromisoformat(text)
    assert before <= parsed <= datetime.now(UTC)
    assert parsed.utcoffset() == before.utcoffset()


@pytest.mark.parametrize(
    "error,logged",
    [
        (KeyError("missing"), True),
        (AttributeError("absent"), True),
        (OSError("disk"), True),
        (ValueError("bad value"), True),
    ],
)
def test_converted_programming_errors_keep_a_traceback(error, logged, caplog):
    """Keep a traceback for every failure converted into a result."""
    # Arrange
    from gitlab_security_mcp.advisory import AdvisoryClient

    client = AdvisoryClient(http=Mock())
    client._get_json = Mock(side_effect=error)

    # Act
    with caplog.at_level(logging.WARNING, logger="gitlab_security_mcp"):
        ident, payload, message = client._osv_record("CVE-2026-0001")

    # Assert
    assert (ident, payload) == ("CVE-2026-0001", None)
    assert message.startswith("osv:CVE-2026-0001:")
    records = [row for row in caplog.records if "Converted" in row.message]
    assert bool(records) is logged
    if logged:
        assert "OSV advisory read CVE-2026-0001" in records[0].message
        assert records[0].exc_info[1] is error
