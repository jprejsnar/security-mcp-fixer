"""Verify command boundaries, child cleanup, pipe readers, and audit hashes."""

import json
from datetime import date

import pytest

from gitlab_security_mcp.commands import CommandRunner, assert_allowed
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
def test_exact_pnpm_preparation_commands_are_allowlisted(tmp_path, step):
    """Permit the requested preparation commands without allowing force options."""
    # Arrange
    argv = ["pnpm", step]

    # Act
    assert_allowed(argv, tmp_path)

    # Assert
    with pytest.raises(PermissionError):
        assert_allowed([*argv, "--force"], tmp_path)


@pytest.mark.parametrize("failed_start", [1, 2])
def test_reader_start_failure_cleans_up_process(tmp_path, monkeypatch, failed_start):
    """Reader start failure cleans up process."""
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


def test_branch_name_uses_english_month():
    """Branch name uses english month."""
    # Arrange
    day = date(2026, 11, 1)

    # Act
    name = branch_name_for(day)

    # Assert
    assert name == "security-fixes-November-01-2026"


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


def test_security_branch_checkout_is_allowed(repo):
    """Security branch checkout is allowed."""
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
def test_product_logs_preserve_all_output_and_final_summary(
    tmp_path, monkeypatch, code
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
        assert argv == ["pnpm", "test"]
        return real_popen([sys.executable, "-c", script], **kwargs)

    monkeypatch.setattr(commands.subprocess, "Popen", product_process)
    updates = []
    runner = CommandRunner(tmp_path, max_output=128, progress_callback=updates.append)

    # Act
    result = runner.run(["pnpm", "test"], timeout=30, check=False)
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
    assert any("4910/4910 tests (100%)" in text for text in updates)
    assert updates[-1].endswith(f"command finished; exit {code}")
    assert ("!" * 20 if code else "#" * 20) in updates[-1]


def test_test_progress_is_emitted_before_command_finishes(tmp_path, monkeypatch):
    """Publish real completed-test counts while the child is still executing."""
    # Arrange
    import sys

    from gitlab_security_mcp import commands

    real_popen = commands.subprocess.Popen
    children = []
    updates = []
    script = (
        "import sys; print('Tests: 1 passed, 2 total', flush=True); "
        "sys.stdin.readline(); print('Tests: 2 passed, 2 total', flush=True)"
    )

    def product_process(argv, **kwargs):
        """Let only this synthetic child wait for acknowledgement of live progress."""
        kwargs["stdin"] = commands.subprocess.PIPE
        child = real_popen([sys.executable, "-c", script], **kwargs)
        children.append(child)
        return child

    def record_progress(text):
        """Release the child only after its first test result was reported."""
        updates.append(text)
        if "1/2 tests" in text:
            assert children[0].poll() is None
            children[0].stdin.write("\n")
            children[0].stdin.flush()

    monkeypatch.setattr(commands.subprocess, "Popen", product_process)
    runner = CommandRunner(tmp_path, progress_callback=record_progress)

    # Act
    result = runner.run(["pnpm", "test"], timeout=10, check=False)
    children[0].stdin.close()

    # Assert
    assert result.exit_code == 0
    assert any("1/2 tests" in text and "50%" in text for text in updates)
    assert any("2/2 tests" in text and "100%" in text for text in updates)


@pytest.mark.parametrize("suite_count", [2, 3])
def test_jest_progress_uses_current_discovered_suite_total(
    tmp_path, monkeypatch, suite_count
):
    """Use current Jest discovery rather than a stale count or guessed case total."""
    # Arrange
    import sys

    from gitlab_security_mcp import commands

    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"test": "jest --watch=false --coverage"}}),
        encoding="utf-8",
    )
    paths = [f"test-{index}.spec.ts" for index in range(suite_count)]
    calls = []
    updates = []
    real_popen = commands.subprocess.Popen

    def product_process(argv, **kwargs):
        """Return discovery or suite events without launching a real product runner."""
        calls.append(argv)
        output = (
            json.dumps(paths)
            if "--listTests" in argv
            else "\n".join(f"PASS {path}\n  \\u2713 case" for path in paths).replace(
                "\\u2713", "\u2713"
            )
        )
        script = f"import sys; sys.stdout.buffer.write({output.encode('utf-8')!r})"
        return real_popen([sys.executable, "-c", script], **kwargs)

    monkeypatch.setattr(commands.subprocess, "Popen", product_process)
    runner = CommandRunner(tmp_path, progress_callback=updates.append)

    # Act
    result = runner.run(["pnpm", "test"], timeout=10, check=False)

    # Assert
    assert result.exit_code == 0
    assert calls == [["pnpm", "test", "--listTests", "--json"], ["pnpm", "test"]]
    assert any(f"0/{suite_count} test suites" in text for text in updates)
    assert any(
        f"{suite_count}/{suite_count} test suites (100%)" in text for text in updates
    )
    assert any("case total unavailable" in text for text in updates)


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
    result = CommandRunner(tmp_path).run(["pnpm", "test"], timeout=10, check=False)

    # Assert
    assert result.exit_code == 0
    assert calls == [["pnpm", "test"]]


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
                review = docs.read_before_fix({})
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
