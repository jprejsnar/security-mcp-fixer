"""Verify local phase decisions, safe edits, reporting, and shutdown order."""

import hashlib
import json
import logging
import sys
import threading
from datetime import date
from pathlib import Path
from socket import SOCK_STREAM, gaierror

import pytest

from gitlab_security_mcp.advisory import AdvisoryLookup
from gitlab_security_mcp.commands import (
    CommandResult,
    CommandRunner,
    assert_allowed,
    tool_name,
)
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.git_ops import branch_name_for


def test_corporate_dns_failure_blocks_prechecks_without_work(tmp_path, corporate_dns):
    """Fail before Git or file changes, then allow retry after VPN connects."""
    # Arrange
    from unittest.mock import Mock

    engine = Engine(tmp_path, gitlab=Mock(), advisory=Mock())
    engine.git = Mock()
    corporate_dns.side_effect = gaierror("DNS unavailable")

    # Act
    failed = engine.run_prechecks()

    # Assert
    corporate_dns.assert_called_once_with("nexus.ert.com", 443, type=SOCK_STREAM)
    assert failed["status"] == "PRECHECK_FAILED"
    assert "Connect to corporate VPN first" in failed["reason"]
    assert failed["no_changes_attempted"]
    assert engine.state.stop_stage == "corporate_dns"
    assert engine.git.mock_calls == []
    assert not (tmp_path / ".security-mcp").exists()
    assert engine.pull_main_twice()["status"] == "PULL_FAILED"
    corporate_dns.side_effect = None
    engine.git.current_branch.return_value = "main"
    engine.git.in_progress_operation.return_value = None
    engine.git.dirty_lines.return_value = []

    recovered = engine.run_prechecks()

    assert recovered["status"] == "PRECHECK_PASSED"
    assert engine.state.stop_stage is None


@pytest.mark.parametrize("background", [False, True])
def test_default_status_omits_repeated_workflow_evidence(
    tmp_path, monkeypatch, background
):
    """Keep live jobs and blockers while saved evidence is returned only on recovery."""
    # Arrange
    from copy import deepcopy
    from unittest.mock import Mock

    from gitlab_security_mcp import server

    engine = Engine(tmp_path, gitlab=Mock(), advisory=Mock())
    engine.state.workflow = {
        "current": 3,
        "jobs": [{"number": 3, "status": "RUNNING"}],
        "package_reviews": {"one": {"documentation": "Reviewed source. " * 3000}},
        "final_result": {
            "status": "WORKFLOW_COMPLETE",
            "report_path": str(tmp_path / "report.md"),
            "final_summary_markdown": "Report evidence. " * 3000,
            "log_archive": {"status": "ERROR", "error": "disk full"},
        },
    }
    original = deepcopy(engine.state.workflow)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(
        server,
        "_background_for",
        lambda selected: [{"status": "RUNNING"}] if background else [],
    )

    # Act
    compact = server.get_run_status(str(tmp_path))
    recovered = server.get_run_status(str(tmp_path), include_audit_details=True)

    # Assert
    assert compact["workflow"]["current"] == 3
    assert compact["workflow"]["package_review_count"] == 1
    assert compact["workflow"]["jobs"] == original["jobs"]
    assert compact["workflow"]["final_result"]["log_archive"]["error"] == "disk full"
    assert len(json.dumps(compact)) < len(json.dumps(recovered)) * 0.1
    assert recovered["workflow"] == original
    assert engine.state.workflow == original


@pytest.mark.parametrize("failed_check", [1, 2, 3])
def test_dns_loss_blocks_pulls_or_pnpm_preparation(
    tmp_path, corporate_dns, failed_check, caplog
):
    """Recheck DNS after prechecks and prevent any subsequent preparation."""
    # Arrange
    from unittest.mock import Mock

    engine = Engine(tmp_path, gitlab=Mock(), advisory=Mock())
    engine.state.status = "PRECHECK_PASSED"
    engine.git = Mock()
    engine.git.current_branch.return_value = "main"
    engine.git.head.return_value = "unchanged"
    engine.git.dirty_lines.return_value = []
    engine.git.run.return_value = CommandResult(
        ["git", "pull", "--ff-only"], 0, "ok", "", 0, False, "out", "err"
    )
    engine._prepare_pnpm = Mock()
    corporate_dns.side_effect = [
        *[corporate_dns.return_value for _ in range(failed_check - 1)],
        gaierror("VPN disconnected"),
    ]

    # Act
    with caplog.at_level(logging.WARNING, logger="gitlab_security_mcp"):
        result = engine.pull_main_twice()

    # Assert
    assert result["status"] == (
        "PREPARATION_FAILED" if failed_check == 3 else "PULL_FAILED"
    )
    assert "Connect to corporate VPN first" in result["reason"]
    assert "Corporate DNS check failed" in caplog.text
    assert len(result["results"]) == failed_check - 1
    assert engine.git.run.call_count == failed_check - 1
    engine._prepare_pnpm.assert_not_called()
    engine.gitlab.fetch.assert_not_called()
    assert engine.state.stop_stage == "corporate_dns"
    assert engine.create_security_branch()["status"] == "BRANCH_CREATION_FAILED"


def test_open_checkout_wins_over_a_shared_repo_root(tmp_path, monkeypatch):
    """Each editor window uses the checkout it opened, not one shared path."""
    # Arrange
    shared = tmp_path / "shared"
    opened = tmp_path / "opened"
    shared.mkdir()
    opened.mkdir()
    (opened / ".git").mkdir()
    monkeypatch.setenv("REPO_ROOT", str(shared))
    monkeypatch.chdir(opened)

    # Act
    engine = Engine.from_env()
    try:
        selected = engine.repo_root
    finally:
        engine.close()

    # Assert
    assert selected == opened.resolve()


def test_repository_override_recovers_unresolved_host_placeholder(
    cloned_repo, monkeypatch, tmp_path
):
    """Repository override recovers unresolved host placeholder."""
    # Arrange
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("REPO_ROOT", "${workspaceFolder}")

    # Act
    with pytest.raises(ValueError, match="unresolved host placeholder"):
        Engine.from_env()
    engine = Engine.from_env(str(cloned_repo))
    try:
        precheck = engine.run_prechecks()
    finally:
        engine.close()

    # Assert
    assert engine.repo_root == cloned_repo.resolve()
    assert precheck["status"] == "PRECHECK_PASSED"


def test_missing_repository_has_actionable_error(tmp_path, monkeypatch):
    """Missing repository has actionable error."""
    # Arrange
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("REPO_ROOT", str(tmp_path / "missing"))

    # Act
    with pytest.raises(
        ValueError, match="Repository directory does not exist"
    ) as raised:
        Engine.from_env()

    # Assert
    assert "Repository directory does not exist" in str(raised.value)


def test_server_recovers_configuration_error(cloned_repo, monkeypatch, tmp_path):
    """Server recovers configuration error."""
    # Arrange
    from gitlab_security_mcp import server

    server._close_engine()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("REPO_ROOT", "${workspaceFolder}")

    # Act
    failed = server.run_prechecks()
    recovered = server.run_prechecks(repo_root=str(cloned_repo))
    try:
        # Assert
        assert failed["status"] == "ERROR"
        assert failed["stage"] == "configuration"
        assert "unresolved host placeholder" in failed["error"]
        assert "repo_root" in failed["action"]
        assert recovered["status"] == "PRECHECK_PASSED"
        assert recovered["repo_root"] == str(cloned_repo.resolve())
        other = server.run_prechecks(repo_root=str(cloned_repo.parent))
        assert other["status"] == "PRECHECK_FAILED"
        assert (
            server.get_run_status(repo_root=str(cloned_repo))["status"]
            == "PRECHECK_PASSED"
        )
    finally:
        server._close_engine()


def test_two_repositories_run_at_the_same_time(tmp_path):
    """Two repositories run at the same time."""
    # Arrange
    from gitlab_security_mcp import server
    from tests.conftest import git

    server._close_engine()
    first = tmp_path / "one"
    second = tmp_path / "two"
    remote = tmp_path / "origin.git"
    git(tmp_path, "init", "--bare", "-b", "main", str(remote))
    for checkout in (first, second):
        checkout.mkdir()
        git(checkout, "init", "-b", "main")
        git(checkout, "remote", "add", "origin", str(remote))
    barrier = threading.Barrier(2)
    results: dict[str, dict] = {}

    def check(name: str, checkout: Path) -> None:
        """Run prechecks for one checkout once both workers are ready."""
        barrier.wait(timeout=5)
        results[name] = server.run_prechecks(repo_root=str(checkout))

    workers = [
        threading.Thread(target=check, args=("first", first)),
        threading.Thread(target=check, args=("second", second)),
    ]

    # Act
    try:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=30)

        # Assert
        assert results["first"]["status"] == "PRECHECK_PASSED"
        assert results["second"]["status"] == "PRECHECK_PASSED"
        assert results["first"]["repo_root"] != results["second"]["repo_root"]
        ambiguous = server.get_run_status()
        assert ambiguous["status"] == "ERROR"
        assert "Pass repo_root" in ambiguous["error"]
        assert (
            server.get_run_status(repo_root=str(first))["status"] == "PRECHECK_PASSED"
        )
        assert (
            server.get_run_status(repo_root=str(second))["status"] == "PRECHECK_PASSED"
        )
    finally:
        server._close_engine()


def test_unreadable_origin_stops_prechecks_without_assuming_branch_absence(repo):
    """Keep unknown remote state from authorizing branch preparation."""
    # Arrange
    from contextlib import closing
    from unittest.mock import Mock

    with closing(Engine(repo, gitlab=Mock(), advisory=Mock())) as engine:
        # Act
        result = engine.run_prechecks()

        # Assert
        assert result["status"] == "PRECHECK_FAILED"
        assert "branch absence was not inferred" in result["error"]
        assert result["no_changes_attempted"]
        assert engine.git.current_branch() == "main"


def test_server_logs_go_to_stderr(capsys):
    """Server logs go to stderr."""
    # Arrange
    import logging

    from gitlab_security_mcp import server

    server.logger.handlers.clear()

    # Act
    server._configure_logging()
    server._configure_logging()
    server.logger.info("ide-log-marker")

    # Assert
    assert len(server.logger.handlers) == 2
    captured = capsys.readouterr()
    assert "ide-log-marker" in captured.err
    from gitlab_security_mcp.util import read_server_log

    assert "ide-log-marker" in read_server_log()
    assert not any(
        type(handler).__name__ == "RichHandler"
        for handler in logging.getLogger().handlers
    )


def test_configure_logging_sets_level_when_a_handler_exists():
    """Apply level and propagate on a logger that already has a handler."""
    # Arrange
    import logging

    from gitlab_security_mcp import server

    saved_handlers = list(server.logger.handlers)
    saved_level = server.logger.level
    saved_propagate = server.logger.propagate
    server.logger.handlers.clear()
    server.logger.addHandler(logging.NullHandler())
    server.logger.setLevel(logging.NOTSET)
    server.logger.propagate = True

    # Act
    try:
        server._configure_logging()

        # Assert
        assert server.logger.propagate is False
        assert server.logger.level == logging.INFO
        assert not any(
            isinstance(handler, logging.StreamHandler)
            for handler in server.logger.handlers
        )
        assert len(server.logger.handlers) == 2
    finally:
        server.logger.handlers.clear()
        for handler in saved_handlers:
            server.logger.addHandler(handler)
        server.logger.setLevel(saved_level)
        server.logger.propagate = saved_propagate


def test_host_logging_prepares_stderr_before_handlers(monkeypatch):
    """Prepare stderr before any logging handler is attached."""
    # Arrange
    from gitlab_security_mcp import server

    order: list[str] = []
    monkeypatch.setattr(server, "_prepare_stderr", lambda: order.append("prepare"))
    monkeypatch.setattr(server, "_configure_logging", lambda: order.append("configure"))

    # Act
    server._install_host_logging()

    # Assert
    assert order == ["prepare", "configure"]


def test_stdio_server_logs_for_cursor_and_copilot(tmp_path):
    """Answer initialize from Cursor and VS Code Copilot and log on stderr."""
    # Arrange
    import os
    import subprocess

    clients = (
        ("cursor", "2025-11-25"),
        ("vscode-copilot", "2025-03-26"),
    )

    def session(client_name: str, protocol: str) -> tuple[str, str]:
        """Run one stdio handshake and return stdout and stderr text."""
        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": protocol,
                "capabilities": {},
                "clientInfo": {"name": client_name, "version": "1.0"},
            },
        }
        tools = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        messages = (
            initialize,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            tools,
        )
        with subprocess.Popen(
            [sys.executable, "-m", "gitlab_security_mcp.server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "PROGRESS_CONSOLE": "off"},
            cwd=tmp_path,
        ) as process:
            try:
                stdout, stderr = process.communicate(
                    "".join(json.dumps(message) + "\n" for message in messages),
                    timeout=20,
                )
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
        return stdout, stderr

    # Act
    results = [session(name, protocol) for name, protocol in clients]

    # Assert
    for stdout, stderr in results:
        lines = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        assert lines[0]["id"] == 1
        assert "protocolVersion" in lines[0]["result"]
        listed = next(line for line in lines if line.get("id") == 2)
        names = {tool["name"] for tool in listed["result"]["tools"]}
        assert "get_run_status" in names
        assert "complete_security_run" in names
        assert "serving stdio" in stderr
        assert "\x1b[" not in stderr


def test_non_git_precheck_does_not_persist_run_state(tmp_path, caplog):
    """Non git precheck does not persist run state."""
    # Arrange
    engine = Engine(tmp_path, gitlab=FakeGitLab([]), advisory=ScriptedAdvisory())

    # Act
    with caplog.at_level(logging.WARNING, logger="gitlab_security_mcp"):
        result = engine.run_prechecks()

    # Assert
    assert result["status"] == "PRECHECK_FAILED"
    assert "Git work-tree verification failed" in caplog.text
    assert result["repo_root"] == str(tmp_path.resolve())
    assert "REPO_ROOT" in result["reason"]
    assert result["no_changes_attempted"]
    assert not (tmp_path / ".security-mcp" / "run-state.json").exists()


@pytest.mark.parametrize(
    "manifest, contents",
    [
        ("package.json", "not-json"),
        ("package.json", "[]"),
        ("package.json", '{"dependencies":[]}'),
        ("package-lock.json", '{"packages":[]}'),
        ("pom.xml", "<project>"),
        ("libs.versions.toml", 'libraries = ["bad"]'),
    ],
)
def test_unreadable_manifest_requires_review(tmp_path, manifest, contents):
    """Unreadable manifest requires review."""
    # Arrange
    (tmp_path / manifest).write_text(contents, encoding="utf-8")
    finding = _finding("finding", "org.example:lodash", "CVE-TEST")
    engine = Engine(tmp_path, gitlab=FakeGitLab([]), advisory=ScriptedAdvisory())
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    result = engine.verify_security_finding("finding")

    # Assert
    assert result["decision"] == "MANUAL_REVIEW"
    assert not result["eligible_for_auto_fix"]
    assert engine.state.false_positives == []


@pytest.mark.parametrize(
    "failure", [OSError("Executable vanished"), RuntimeError("Output reader failed")]
)
def test_validation_execution_failure_returns_failed_result(tmp_path, failure):
    """Validation execution failure returns failed result."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.validate import run_validation

    (tmp_path / "package.json").write_text(
        '{"scripts":{"test":"test"}}', encoding="utf-8"
    )
    runner = Mock()
    runner.run.side_effect = failure

    # Act
    result = run_validation(tmp_path, runner, lambda name: name, timeout=30)

    # Assert
    assert result["status"] == "VALIDATION_FAILED"
    assert any(
        row["status"] == "FAILED" and row["required"] for row in result["results"]
    )


def test_invalid_policy_path_does_not_allocate_owned_clients(tmp_path, monkeypatch):
    """Validate configuration before acquiring HTTP connection pools."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import engine

    gitlab_factory, advisory_factory = Mock(), Mock()
    monkeypatch.setattr(engine, "GitLabClient", gitlab_factory)
    monkeypatch.setattr(engine, "AdvisoryClient", advisory_factory)
    monkeypatch.setenv("PACKAGE_UPDATE_POLICY", "broken-policy.json")
    original_resolve = Path.resolve

    def resolve_policy(path, *args, **kwargs):
        """Fail only policy resolution, preserving pytest's own path handling."""
        if path.name == "broken-policy.json":
            raise OSError("Policy path cannot be resolved")
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve_policy)

    # Act
    with pytest.raises((OSError, ValueError)):
        Engine(tmp_path)
    # Assert
    gitlab_factory.assert_not_called()
    advisory_factory.assert_not_called()


def test_engine_constructor_failure_closes_owned_client(tmp_path, monkeypatch):
    """Engine constructor failure closes owned client."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import engine as module

    gitlab = Mock()
    monkeypatch.setattr(module, "GitLabClient", lambda *args, **kwargs: gitlab)

    def fail_advisory(**kwargs):
        """Fail construction after the engine has acquired its GitLab client."""
        raise RuntimeError("Advisory initialization failed")

    monkeypatch.setattr(module, "AdvisoryClient", fail_advisory)

    # Act
    with pytest.raises(RuntimeError, match="Advisory initialization failed"):
        Engine(tmp_path)

    # Assert
    gitlab.close.assert_called_once_with()


def test_engine_constructor_preserves_primary_error(tmp_path, monkeypatch):
    """Engine constructor preserves primary error."""
    # Arrange
    from unittest.mock import Mock

    import gitlab_security_mcp.engine as engine_module

    gitlab = Mock()
    gitlab.close.side_effect = OSError("Cleanup failed")
    monkeypatch.setattr(engine_module, "GitLabClient", Mock(return_value=gitlab))
    monkeypatch.setattr(
        engine_module,
        "AdvisoryClient",
        Mock(side_effect=RuntimeError("Initialization failed")),
    )

    # Act
    with pytest.raises(RuntimeError, match="Initialization failed"):
        Engine(tmp_path)

    # Assert
    gitlab.close.assert_called_once_with()


def test_engine_close_attempts_all_owned_clients_once(tmp_path, monkeypatch):
    """Engine close attempts all owned clients once."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import engine as module

    gitlab = Mock()
    advisory = Mock()
    gitlab.close.side_effect = OSError("Close failed")
    monkeypatch.setattr(module, "GitLabClient", lambda *args, **kwargs: gitlab)
    monkeypatch.setattr(module, "AdvisoryClient", lambda **kwargs: advisory)
    engine = Engine(tmp_path)

    # Act
    with pytest.raises(OSError, match="Close failed"):
        engine.close()
    engine.close()
    status = engine.get_run_status()

    # Assert
    gitlab.close.assert_called_once_with()
    advisory.close.assert_called_once_with()
    assert status["status"] == "ERROR"
    assert "closed" in status["reason"].lower()


def test_engine_close_waits_for_active_tool(tmp_path):
    """Engine close waits for active tool."""
    # Arrange
    import threading
    from unittest.mock import Mock

    gitlab = FakeGitLab([_finding("finding", "lodash", "CVE-TEST")])
    engine = Engine(tmp_path, gitlab=gitlab, advisory=ScriptedAdvisory())
    engine.state.status = "BRANCH_CREATED"
    engine._owns_gitlab = True
    gitlab.close = Mock()
    real_fetch = gitlab.fetch
    entered = threading.Event()
    release = threading.Event()
    close_started = threading.Event()
    close_done = threading.Event()
    results = []

    def fetch(*args, **kwargs):
        """Hold the active tool until the test explicitly releases its lock."""
        entered.set()
        if not release.wait(5):
            raise RuntimeError("Test release timed out")
        return real_fetch(*args, **kwargs)

    def close():
        """Signal attempted shutdown and completion from a competing thread."""
        close_started.set()
        engine.close()
        close_done.set()

    gitlab.fetch = fetch
    worker = threading.Thread(
        target=lambda: results.append(engine.list_security_findings("group/app"))
    )
    closer = threading.Thread(target=close)

    # Act
    worker.start()
    try:
        assert entered.wait(5)
        closer.start()
        assert close_started.wait(5)
        closed_early = close_done.wait(0.1)
    finally:
        release.set()
        worker.join(timeout=5)
        if closer.ident is not None:
            closer.join(timeout=5)

    # Assert
    assert not closed_early
    assert not worker.is_alive() and not closer.is_alive()
    assert results[0]["findings"][0]["component"] == "lodash"
    gitlab.close.assert_called_once_with()
    assert engine.get_run_status()["status"] == "ERROR"


def test_engine_results_are_detached_snapshots(tmp_path):
    """Engine results are detached snapshots."""
    # Arrange
    finding = _finding("finding", "lodash", "CVE-TEST")
    engine = Engine(tmp_path, gitlab=FakeGitLab([finding]), advisory=ScriptedAdvisory())
    engine.state.status = "BRANCH_CREATED"

    # Act
    result = engine.list_security_findings("group/project")
    result["findings"][0]["component"] = "tampered"
    result["findings"].clear()

    # Assert
    assert len(engine.state.findings) == 1
    assert engine.state.findings[0]["component"] == "lodash"


def test_falsey_engine_dependencies_are_preserved(tmp_path):
    """Falsey engine dependencies are preserved."""

    # Arrange
    class FalseyDependency:
        """Expose a falsey injected dependency whose ownership stays external."""

        def __bool__(self):
            """Force constructor logic to distinguish falsey values from None."""
            return False

        def close(self):
            """Fail if the engine incorrectly closes an injected dependency."""
            raise AssertionError("Injected dependencies must not be closed")

        def __call__(self, name):
            """Act as an injected executable lookup that finds no tool."""
            return None

    dependency = FalseyDependency()
    arguments = dict.fromkeys(("gitlab", "advisory", "runner", "which"), dependency)

    # Act
    engine = Engine(tmp_path, **arguments)
    engine.close()

    # Assert
    for name in arguments:
        assert getattr(engine, name) is dependency


class HybridRunner(CommandRunner):
    """Run real git commands and record every other allowlisted command."""

    def __init__(self, repo_root):
        """Initialize real Git execution and a record of all routed commands."""
        super().__init__(repo_root)
        self.calls: list[list[str]] = []

    def run(self, argv, *, timeout, check=True, cwd=None):
        """Override execution to simulate non-Git tools after allowlist checks."""
        assert_allowed(argv, self.repo_root)
        self.calls.append(list(argv))
        if tool_name(argv[0]) == "git":
            return super().run(argv, timeout=timeout, check=check, cwd=cwd)
        stdout = "ok"
        if tool_name(argv[0]) in {"gradle", "gradlew"} and "dependencies" in argv:
            stdout = "runtimeClasspath - Runtime graph.\n+--- org.apache.commons:commons-text:1.9\n"
        if "test" in argv or "verify" in argv:
            stdout += "\nTests: 1 passed"
        if argv[1:] in (["--version"], ["-version"]):
            stdout = {
                "node": "24.21.0",
                "dotnet": "10.0.100",
                "java": 'openjdk version "17.0.18"',
            }.get(tool_name(argv[0]), "ok")
        return CommandResult(
            argv=list(argv),
            exit_code=0,
            stdout=stdout,
            stderr="",
            duration_ms=1,
            truncated=False,
            stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
        )


@pytest.mark.parametrize("category", ["api_fuzzing", "coverage_fuzzing"])
@pytest.mark.parametrize(
    "scanner",
    [
        None,
        {
            "request": {"body": ""},
            "response": {"body": "unexpected response", "statusCode": 500},
        },
    ],
)
def test_fuzzing_requires_reproduction_not_package_advisories(
    tmp_path, monkeypatch, category, scanner
):
    """Keep fuzzing unresolved without treating missing advisories as skips."""
    # Arrange
    from gitlab_security_mcp.report import render

    finding = _finding("fuzzing", None, "bucket:param:Query: offset", version=None)
    finding.update(
        category=category, title="Malformed offset causes unexpected response"
    )
    finding["scannerEvidence"] = scanner
    finding["scannerDetails"] = [
        {"__typename": "VulnerabilityDetailDiff", "before": "0", "after": "-1"}
    ]
    finding["location"] = {
        "file": "/service/queues",
        "hostname": "https://example.invalid",
    }
    engine = Engine(tmp_path, gitlab=FakeGitLab([]), advisory=ScriptedAdvisory())
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    def refuse_lookup(*args, **kwargs):
        """Fail if runtime fuzzing is routed through dependency evidence."""
        pytest.fail("Fuzzing must not use package or advisory lookup")

    monkeypatch.setattr(engine.advisory, "lookup", refuse_lookup)
    monkeypatch.setattr(engine, "_snapshot", refuse_lookup)

    # Act
    result = engine.verify_security_finding("fuzzing")
    applied = engine.apply_minimal_fix("fuzzing")
    payload, markdown = render(engine.state, staged=[], diff_stat="", diff_files="")

    # Assert
    assert result["decision"] == "REPRODUCTION_REQUIRED"
    assert not result["eligible_for_auto_fix"]
    assert not result["qualification_required"]
    assert result["proposed_fix"] is None
    assert result["fuzzing_workflow"]["status"] == "REPRODUCTION_REQUIRED"
    assert result["fuzzing_workflow"]["scanner_evidence"] == scanner
    assert result["fuzzing_workflow"]["scanner_details"] == finding["scannerDetails"]
    assert finding["scannerEvidence"] == scanner
    assert any(
        "response body captured" in item if scanner else "response body missing" in item
        for item in result["evidence"]
    )
    assert "local" in result["user_prompt"]
    assert "skipped" not in result["user_prompt"].lower()
    assert engine.state.skipped_user_prompt == []
    assert engine.state.false_positives == []
    assert payload["unresolved_issues"][0]["decision"] == "REPRODUCTION_REQUIRED"
    assert payload["fuzzing_workflows"]["fuzzing"] == result["fuzzing_workflow"]
    assert "## Fuzzing findings requiring reproduction" in markdown
    assert applied["status"] == "REPRODUCTION_REQUIRED"
    assert engine.state.changes == []


def _source_review_case(root):
    """Create a dynamic regex with a fixed local configuration input."""
    from unittest.mock import Mock

    source = root / "watcher.spec.ts"
    source.write_text(
        "const pattern = config.beginsPattern;\nconst begins = new RegExp(pattern);\n",
        encoding="utf-8",
    )
    config = root / "tasks.json"
    config.write_text('{"beginsPattern":"^Watching$"}', encoding="utf-8")
    finding = _finding("sast-regex", None, "detect-non-literal-regexp", None)
    finding.update(category="sast", title="Regular expression with non-literal value")
    finding["location"] = {"file": source.name, "startLine": "2"}
    advisory = Mock()
    from tests.conftest import documentation_client

    engine = Engine(root, gitlab=Mock(), advisory=advisory, docs=documentation_client())
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]
    review = {
        "decision": "FALSE_POSITIVE",
        "reason": "The constructor uses the fixed ^Watching$ pattern from local tasks.json.",
        "input_origin": "The local test fixture loads the checked-in tasks.json.",
        "pattern_analysis": "Anchored literal text; no nested or ambiguous repetition.",
        "reachability_analysis": "Test-only config input; no request-controlled pattern.",
        "reviewed_files": [
            {
                "path": path.name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "assessment": "Traced the constructor and its fixed configuration input.",
            }
            for path in (source, config)
        ],
    }
    return engine, review, config


def test_sast_regex_requires_source_review_then_reports_evidenced_false_positive(
    tmp_path,
):
    """Read source without advisories and retain reviewed false positives in summaries."""
    # Arrange
    from gitlab_security_mcp.report import render

    engine, review, _config = _source_review_case(tmp_path)

    # Act
    pending = engine.verify_security_finding("sast-regex")
    blocked = engine.apply_minimal_fix("sast-regex")
    verified = engine.verify_security_finding("sast-regex", source_review=review)
    payload, _markdown = render(engine.state, staged=[], diff_stat="", diff_files="")

    # Assert
    assert pending["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert pending["source_workflow"]["source"]["line"] == 2
    assert "new RegExp(pattern)" in pending["source_workflow"]["source"]["cited_text"]
    assert not pending["eligible_for_auto_fix"]
    assert blocked["status"] == "SOURCE_REVIEW_REQUIRED"
    engine.advisory.lookup.assert_not_called()
    assert verified["decision"] == "FALSE_POSITIVE"
    assert not verified["qualification_required"]
    assert engine.state.skipped_user_prompt == []
    assert payload["source_reviews"]["sast-regex"] == review
    assert payload["unresolved_issues"] == []
    assert "FALSE_POSITIVE" in payload["final_summary_markdown"]
    assert review["reason"] in payload["final_summary_markdown"]
    assert "watcher.spec.ts:2" in payload["final_summary_markdown"]


@pytest.mark.parametrize(
    "invalid", ["sha", "origin", "cited-file", "outside", "missing"]
)
def test_sast_false_positive_review_rejects_incomplete_or_stale_evidence(
    tmp_path, invalid
):
    """Do not let attestations bypass current source files and complete analysis."""
    # Arrange
    engine, review, config = _source_review_case(tmp_path)
    if invalid == "sha":
        config.write_text('{"beginsPattern":"(a+)+$"}', encoding="utf-8")
    elif invalid == "origin":
        review.pop("input_origin")
    elif invalid == "cited-file":
        review["reviewed_files"] = review["reviewed_files"][1:]
    elif invalid == "outside":
        review["reviewed_files"][1]["path"] = "../outside.json"
    else:
        (tmp_path / "watcher.spec.ts").unlink()

    # Act
    result = engine.verify_security_finding("sast-regex", source_review=review)

    # Assert
    assert result["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert "could not be accepted" in result["reason"]
    assert engine.state.false_positives == []
    engine.advisory.lookup.assert_not_called()


def test_source_false_positive_is_retracted_when_reviewed_config_changes(tmp_path):
    """Invalidate a source assessment if any input file changed after review."""
    # Arrange
    engine, review, config = _source_review_case(tmp_path)
    assert (
        engine.verify_security_finding("sast-regex", source_review=review)["decision"]
        == "FALSE_POSITIVE"
    )

    # Act
    config.write_text('{"beginsPattern":"(a+)+$"}', encoding="utf-8")
    status = engine.get_run_status()

    # Assert
    assert status["false_positives_count"] == 0
    assert status["source_review_required_count"] == 1
    assert "sourceReview" not in engine.state.findings[0]
    assert "changed" in engine.state.decisions["sast-regex"]["reason"]


def test_same_title_findings_have_distinct_summary_rows(tmp_path):
    """Avoid indistinguishable table rows that triggered Cursor's loop detector."""
    # Arrange
    from copy import deepcopy

    from gitlab_security_mcp.report import render

    engine, _review, _config = _source_review_case(tmp_path)
    first = engine.state.findings[0]
    second = deepcopy(first)
    second["id"] = "second-regex"
    second["location"]["startLine"] = "1"
    engine.state.findings.append(second)

    # Act
    for finding in engine.state.findings:
        engine.verify_security_finding(finding["id"])
    payload, _markdown = render(engine.state, staged=[], diff_stat="", diff_files="")

    # Assert
    rows = payload["unresolved_issues_table"].splitlines()[2:]
    assert len(rows) == len(set(rows)) == 2
    assert "sast-regex:" in rows[0] and "watcher.spec.ts:2" in rows[0]
    assert "second-regex:" in rows[1] and "watcher.spec.ts:1" in rows[1]
    assert len(payload["finding_assessments"]) == 2


class FakeGitLab:
    """Return scripted findings without contacting private GitLab services."""

    def __init__(self, findings):
        """Retain the finding list used by retrieval and snapshot tests."""
        self.findings = findings

    def fetch(self, project_id):
        """Return normalized retrieval metadata for the requested project."""
        from gitlab_security_mcp.gitlab_client import FetchResult

        return FetchResult(
            ok=True,
            findings=self.findings,
            pipeline={
                "id": "gid://gitlab/Ci::Pipeline/9",
                "sha": "abc123",
                "ref": "main",
            },
            project_path=project_id,
            excluded={},
        )


class ScriptedAdvisory:
    """Provide deterministic affected, missing, and no-fix advisory outcomes."""

    def lookup(self, finding, ecosystem, package, version):
        """Select the fixture outcome using its synthetic CVE identifier."""
        identifier = (finding.get("identifiers") or [""])[0]
        if identifier == "CVE-FP":
            return AdvisoryLookup(
                outcome="resolved",
                affected=False,
                summary="Installed version is outside the OSV affected range.",
                sources=["osv:CVE-FP"],
            )
        if identifier == "CVE-MANUAL":
            return AdvisoryLookup(
                outcome="not_found",
                summary="No matching record in OSV, the GitHub Advisory Database, or NVD.",
            )
        if identifier == "CVE-NONE":
            return AdvisoryLookup(
                outcome="no_fix_published",
                affected=True,
                summary="OSV lists this package as affected and does not publish a fixed version.",
            )
        return AdvisoryLookup(
            outcome="resolved",
            affected=True,
            fixed_versions=["4.17.21"],
            lowest_fixed_version="4.17.21",
            ranges=[">=0,<4.17.21"],
            summary="OSV lists fixed version(s): 4.17.21.",
            sources=["osv:CVE-FIX"],
        )


def _finding(fid, package, identifier, version="1.0.0"):
    """Build a normalized dependency finding for engine and report tests."""
    return {
        "id": fid,
        "title": f"issue in {package}",
        "description": None,
        "scanner": "Gemnasium",
        "category": "dependency_scanning",
        "severity": "high",
        "confidence": None,
        "identifiers": [identifier],
        "component": package,
        "installedVersion": version,
        "affectedRange": None,
        "fixedVersions": [],
        "dependencyPath": [],
        "location": {"file": "package.json"},
        "status": "detected",
        "falsePositiveFlag": False,
        "solution": None,
        "links": [],
        "pipeline": None,
        "evidence": [],
        "assessment": None,
        "remediationDecision": None,
        "proposedFix": None,
    }


@pytest.mark.parametrize("target_affected", [None, True])
def test_plural_gitlab_fix_reaches_transitive_pnpm_plan(tmp_path, target_affected):
    """Recover the logged undici fix while retaining target-conflict safeguards."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.gitlab_client import normalize_finding

    frontend = tmp_path / "frontend"
    frontend.mkdir()
    manifest = frontend / "package.json"
    manifest.write_text('{"name":"frontend"}', encoding="utf-8")
    (frontend / "pnpm-lock.yaml").write_text(
        "packages:\n  undici@7.30.1: {}\n", encoding="utf-8"
    )
    finding = normalize_finding(
        {
            "uuid": "undici-plural",
            "title": "Origin validation",
            "reportType": "DEPENDENCY_SCANNING",
            "solution": "Upgrade to versions 7.30.2, 8.12.4 or above.",
            "location": {
                "file": "frontend/pnpm-lock.yaml",
                "dependency": {"package": {"name": "undici"}, "version": "7.30.1"},
            },
        },
        None,
    )
    advisory = Mock()
    advisory.lookup.side_effect = [
        AdvisoryLookup(outcome="lookup_failed", summary="Version bounds missing."),
        AdvisoryLookup(
            outcome="resolved" if target_affected else "lookup_failed",
            affected=target_affected,
            summary="Target advisory evidence.",
        ),
    ]
    engine = Engine(tmp_path, gitlab=FakeGitLab([]), advisory=advisory)
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    result = engine.verify_security_finding("undici-plural")

    # Assert
    assert finding["fixedVersions"] == ["7.30.2", "8.12.4"]
    if target_affected:
        assert result["decision"] == "MANUAL_REVIEW"
        assert result["proposed_fix"] is None
    else:
        assert result["decision"] == "CHANGE_REQUIRED"
        assert result["proposed_fix"]["strategy"] == "override"
        assert result["proposed_fix"]["target"] == "7.30.2"
        assert result["qualification_required"] is True
        assert result["eligible_for_auto_fix"] is False
    assert manifest.read_text(encoding="utf-8") == '{"name":"frontend"}'


def test_unknown_affected_version_is_not_a_definitive_no_solution(tmp_path):
    """Incomplete advisory metadata stays actionable as manual review."""
    # Arrange
    from unittest.mock import Mock

    (tmp_path / "package.json").write_text(
        '{"dependencies":{"lodash":"4.17.20"}}', encoding="utf-8"
    )
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="no_fix_published", affected=None, summary="No fixed bound published."
    )
    engine = Engine(tmp_path, gitlab=FakeGitLab([]), advisory=advisory)
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [_finding("unknown", "lodash", "CVE-2021-23337", "4.17.20")]

    # Act
    result = engine.verify_security_finding("unknown")

    # Assert
    assert result["decision"] == "MANUAL_REVIEW"
    assert result["user_prompt"]
    assert engine.state.no_solution == []
    assert engine.state.skipped_user_prompt[0]["id"] == "unknown"


def test_parallel_finding_verification_overlaps_advisories_and_persists_both(tmp_path):
    """Network waits do not serialize unrelated findings or lose committed decisions."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.fanout import map_ordered

    (tmp_path / "package.json").write_text(
        '{"dependencies":{"lodash":"4.17.20"}}', encoding="utf-8"
    )
    rendezvous = threading.Barrier(2)
    advisory = Mock()

    def lookup(*_args):
        """Require both finding assessments to be in flight together."""
        rendezvous.wait(timeout=3)
        return AdvisoryLookup(
            outcome="no_fix_published", affected=True, summary="No fix published."
        )

    advisory.lookup.side_effect = lookup
    engine = Engine(tmp_path, gitlab=FakeGitLab([]), advisory=advisory)
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [
        _finding(fid, "lodash", "CVE-2021-23337", "4.17.20")
        for fid in ("first", "second")
    ]

    # Act
    results = map_ordered(engine.verify_security_finding, ["first", "second"])

    # Assert
    assert [result["decision"] for result in results] == ["NO_SAFE_FIX"] * 2
    saved = json.loads(
        (tmp_path / ".security-mcp" / "run-state.json").read_text(encoding="utf-8")
    )
    assert set(saved["decisions"]) == {"first", "second"}
    assert len(saved["no_solution"]) == 2
    results[0]["evidence"].append("caller mutation")
    assert "caller mutation" not in engine.state.decisions["first"]["evidence"]


@pytest.mark.parametrize(
    "operation", ["get_run_status", "close", "verify_security_finding"]
)
def test_exclusive_tools_and_same_finding_wait_for_verification(tmp_path, operation):
    """Keep shutdown, snapshots, and repeat assessments behind an active finding."""
    # Arrange
    from concurrent.futures import ThreadPoolExecutor
    from unittest.mock import Mock

    (tmp_path / "package.json").write_text(
        '{"dependencies":{"lodash":"4.17.20"}}', encoding="utf-8"
    )
    entered, release, waiting = threading.Event(), threading.Event(), threading.Event()
    advisory = Mock()

    def lookup(*_args):
        """Retain the finding reservation until the test permits its commit."""
        entered.set()
        if not release.wait(5):
            raise RuntimeError("Test release timed out")
        return AdvisoryLookup(
            outcome="no_fix_published", affected=True, summary="No fix published."
        )

    advisory.lookup.side_effect = lookup
    engine = Engine(tmp_path, gitlab=FakeGitLab([]), advisory=advisory)
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [_finding("first", "lodash", "CVE-2021-23337", "4.17.20")]

    def competing_tool():
        """Mark entry before requesting engine access from another thread."""
        waiting.set()
        method = getattr(engine, operation)
        return method("first") if operation == "verify_security_finding" else method()

    # Act
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(engine.verify_security_finding, "first")
        try:
            assert entered.wait(3)
            second = pool.submit(competing_tool)
            assert waiting.wait(3)
            with pytest.raises(TimeoutError):
                second.result(timeout=0.1)
        finally:
            release.set()
        first_result, second_result = first.result(timeout=5), second.result(timeout=5)

    # Assert
    assert first_result["decision"] == "NO_SAFE_FIX"
    if operation == "close":
        assert second_result is None
        assert engine.get_run_status()["status"] == "ERROR"
    elif operation == "get_run_status":
        assert second_result["no_solution_count"] == 1
    else:
        assert second_result["decision"] == "NO_SAFE_FIX"
        assert len(engine.state.no_solution) == 1


def test_report_keeps_pipeline_provenance_and_unapplied_package_candidates():
    """Do not lose per-finding pipelines or omit pending package fixes."""
    # Arrange
    from gitlab_security_mcp.report import render
    from gitlab_security_mcp.state import RunState

    finding = _finding("pending", "lodash", "CVE-2021-23337", "4.17.20")
    finding["pipeline"] = {"id": "pipeline-42", "sha": "abc123", "ref": "main"}
    finding["proposedFix"] = {
        "ecosystem": "npm",
        "package": "lodash",
        "target": "4.17.21",
    }
    state = RunState(
        status="FINDINGS_LISTED",
        findings=[finding],
        decisions={
            "pending": {"decision": "CHANGE_REQUIRED", "reason": "Upgrade lodash."}
        },
    )

    # Act
    payload, markdown = render(state, staged=[], diff_stat="", diff_files="")

    # Assert
    assert payload["finding_pipelines"] == {"pending": finding["pipeline"]}
    assert "pipeline-42" in markdown and "abc123" in markdown
    assert payload["unresolved_issues"][0]["id"] == "pending"
    assert "not been applied" in payload["unresolved_issues"][0]["reason"].lower()


def test_mcp_progress_is_delivered_while_tool_is_running(monkeypatch):
    """Send live bars through the request session before returning a tool result."""
    # Arrange
    import asyncio
    import threading
    from types import SimpleNamespace
    from unittest.mock import Mock

    from mcp.server.mcpserver.server import Context
    from mcp.server.mcpserver.tools.base import Tool

    from gitlab_security_mcp import server
    from gitlab_security_mcp.commands import progress_sink

    updates = []
    console = Mock()
    monkeypatch.setattr(server, "_progress_console", console)

    async def exercise():
        """Keep the fake tool open until its first real notification is received."""
        received = threading.Event()

        async def report(progress, total, message):
            """Capture the MCP notification and unblock the running tool."""
            updates.append(message)
            received.set()

        def work() -> dict:
            """Block SDK tool completion until a live message crosses the MCP loop."""
            sink = progress_sink.get()
            sink("Tests [##########..........] 1/2 tests (50%)")
            console.write.assert_called_once()
            assert received.wait(2)
            return {"status": "DONE"}

        async def call_next(context):
            """Use the real SDK's synchronous-tool dispatch rather than a test shim."""
            return await Tool.from_function(work).run({}, Context())

        context = SimpleNamespace(
            method="tools/call", session=SimpleNamespace(report_progress=report)
        )
        return await server._progress_middleware(context, call_next)

    # Act
    result = asyncio.run(exercise())

    # Assert
    assert result == {"status": "DONE", "progress_output": updates}
    assert updates == ["Tests [##########..........] 1/2 tests (50%)"]
    assert progress_sink.get() is None


def test_progress_is_returned_when_host_drops_notifications():
    """Keep a visible progress transcript when the caller supplied no progress token."""
    # Arrange
    import asyncio
    from types import SimpleNamespace

    from gitlab_security_mcp import server
    from gitlab_security_mcp.commands import progress_sink

    message = "Tests [##########..........] 1/2 test suites (50%)"

    async def report(*args):
        """Model the SDK's no-op when no caller progress token exists."""
        return None

    async def call_next(context):
        """Emit progress before returning ordinary structured tool data."""
        progress_sink.get()(message)
        return {"status": "DONE"}

    context = SimpleNamespace(
        method="tools/call", session=SimpleNamespace(report_progress=report)
    )

    # Act
    result = asyncio.run(server._progress_middleware(context, call_next))

    # Assert
    assert result["progress_output"] == [message]
    assert result["status"] == "DONE"
    assert progress_sink.get() is None


@pytest.mark.parametrize("cancelled", [False, True])
def test_progress_cleanup_does_not_hang_on_an_unresponsive_host(cancelled, caplog):
    """Bound notification draining and reclaim the sender even after cancellation."""
    # Arrange
    import asyncio
    from types import SimpleNamespace

    from gitlab_security_mcp import server
    from gitlab_security_mcp.commands import progress_sink

    publishers = []

    async def exercise():
        """Block host notifications forever, then finish or cancel the tool."""
        reporting = asyncio.Event()

        async def report(*args):
            """Model a connected client that never acknowledges progress."""
            reporting.set()
            await asyncio.Event().wait()

        async def call_next(context):
            """Publish once and optionally wait for the caller's cancellation."""
            publish = progress_sink.get()
            publishers.append(publish)
            publish("Checking findings")
            await reporting.wait()
            if cancelled:
                await asyncio.Event().wait()
            return {"status": "DONE"}

        context = SimpleNamespace(
            method="tools/call", session=SimpleNamespace(report_progress=report)
        )
        task = asyncio.create_task(server._progress_middleware(context, call_next))
        await reporting.wait()
        if cancelled:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
            result = None
        else:
            result = await asyncio.wait_for(task, 2)
        assert not (asyncio.all_tasks() - {asyncio.current_task()})
        return result

    # Act
    previous = server.logger.propagate
    server.logger.propagate = True
    try:
        result = asyncio.run(exercise())
        publishers[0]("A cancelled worker finished after its event loop closed")
    finally:
        server.logger.propagate = previous

    # Assert
    assert "progress delivery timed out" in caplog.text
    assert progress_sink.get() is None
    if not cancelled:
        assert result["progress_output"] == ["Checking findings"]


def test_windows_progress_console_is_isolated_and_cleaned_up(monkeypatch, capsys):
    """Open a separate console without mixing human output into MCP stdout."""
    # Arrange
    import io
    from unittest.mock import Mock

    from gitlab_security_mcp import server

    process = Mock(stdin=io.StringIO())
    launch = Mock(return_value=process)
    monkeypatch.setattr(server.sys, "platform", "win32")
    monkeypatch.setenv("PROGRESS_CONSOLE", "on")
    monkeypatch.setattr(server.subprocess, "Popen", launch)

    # Act
    console = server._open_progress_console()
    console.write("Tests [##########..........] 1/2 test suites (50%)")
    output = process.stdin.getvalue()
    console.close()

    # Assert
    assert "1/2 test suites (50%)" in output
    assert "waiting for tool calls" in output
    assert launch.call_args.kwargs["stdout"] == server.subprocess.DEVNULL
    assert launch.call_args.kwargs["stderr"] == server.subprocess.DEVNULL
    assert launch.call_args.kwargs["creationflags"] == 0x10
    assert process.stdin.closed
    process.wait.assert_called_once_with(timeout=2)
    assert capsys.readouterr().out == ""


def test_progress_mcp_text_is_bounded_and_keeps_report_last():
    """Retain progress without displacing the report or growing results forever."""
    # Arrange
    import asyncio
    from types import SimpleNamespace

    from mcp.types import CallToolResult, TextContent

    from gitlab_security_mcp import server
    from gitlab_security_mcp.commands import progress_sink

    final = "## Unresolved Security Issues\nNone."

    async def report(*args):
        """Model a host that did not opt into live progress."""
        return None

    async def call_next(context):
        """Return the SDK's real result type after many progress updates."""
        for index in range(70):
            progress_sink.get()(f"Progress {index}")
        return CallToolResult(
            content=[TextContent(text=final)],
            structuredContent={"final_summary_markdown": final},
        )

    context = SimpleNamespace(
        method="tools/call", session=SimpleNamespace(report_progress=report)
    )

    # Act
    result = asyncio.run(server._progress_middleware(context, call_next))

    # Assert
    assert result.content[0].text.startswith("## Execution Progress")
    assert result.content[-1].text == final
    assert result.structured_content["final_summary_markdown"] == final
    assert result.structured_content["progress_output"] == [
        f"Progress {index}" for index in range(70 - server._TRANSCRIPT_LINES, 70)
    ]


def test_returned_progress_skips_repeats_and_clips_long_lines():
    """Heartbeat repeats and long log lines must not inflate the result the AI rereads."""
    # Arrange
    import asyncio
    from types import SimpleNamespace

    from gitlab_security_mcp import server
    from gitlab_security_mcp.commands import progress_sink

    delivered = []

    async def report(progress, total, message):
        """Record every live notification the host receives."""
        delivered.append(message)

    async def call_next(context):
        """Emit a repeated heartbeat and one oversized line."""
        for _ in range(10):
            progress_sink.get()("Waiting for Gradle")
        progress_sink.get()("x" * 1800)
        return {"status": "DONE"}

    context = SimpleNamespace(
        method="tools/call", session=SimpleNamespace(report_progress=report)
    )

    # Act
    result = asyncio.run(server._progress_middleware(context, call_next))

    # Assert
    assert result["progress_output"] == [
        "Waiting for Gradle",
        "x" * server._TRANSCRIPT_CHARS,
    ]
    assert len(delivered) == 11


@pytest.mark.parametrize("with_progress", [False, True])
@pytest.mark.parametrize("with_structured", [False, True])
@pytest.mark.parametrize("wire_result", [False, True])
def test_mcp_json_text_is_compact_without_losing_evidence(
    with_progress, with_structured, wire_result
):
    """Reduce actual SDK JSON text without dropping evidence or progress."""
    # Arrange
    import asyncio
    from copy import deepcopy
    from types import SimpleNamespace

    from mcp.server.mcpserver import Context
    from mcp.server.mcpserver.tools.base import Tool

    from gitlab_security_mcp import server
    from gitlab_security_mcp.commands import progress_sink

    payload = {
        "status": "MANUAL_REVIEW",
        "findings": [
            {
                "id": f"finding-{index}",
                "source": 'const message = "caf\u00e9";\n  validate(message);\n',
                "documentation": {"ok": False, "reason": None},
                "evidence": ["First receipt.", "Second receipt."],
            }
            for index in range(20)
        ],
    }

    def work() -> dict[str, object]:
        """Return synthetic evidence through the SDK's real serializer."""
        return deepcopy(payload)

    async def report(*args):
        """Model a host without a live progress subscriber."""
        return None

    async def exercise():
        """Pass typed or serialized SDK results through the actual middleware."""
        original = await Tool.from_function(
            work, structured_output=with_structured
        ).run({}, Context(), convert_result=True)
        original_text = original.content[0].text
        original_structured = deepcopy(original.structured_content)

        async def call_next(context):
            """Represent the SDK handler at either middleware result boundary."""
            if with_progress:
                progress_sink.get()("Reviewing finding evidence")
            if wire_result:
                return original.model_dump(
                    mode="json", by_alias=True, exclude_none=True
                )
            return original

        context = SimpleNamespace(
            method="tools/call", session=SimpleNamespace(report_progress=report)
        )
        result = await server._progress_middleware(context, call_next)
        return result, original_text, original_structured

    # Act
    result, original_text, original_structured = asyncio.run(exercise())
    # Assert
    compact = result.content[-1].text
    assert json.loads(compact) == payload
    assert len(compact) < len(original_text) * 0.8
    if with_progress:
        assert result.content[0].text.startswith("## Execution Progress")
        if original_structured is not None:
            original_structured["progress_output"] = ["Reviewing finding evidence"]
    assert result.structured_content == original_structured
    assert result.is_error is False


@pytest.mark.parametrize(
    "text",
    [
        "## Unresolved Security Issues\n\n| Issue | Reason |\n| --- | --- |\n",
        "{incomplete scanner evidence",
        '"  a JSON string is not a structured tool payload  "',
        '{\n  "value": 0.123456789012345678901234567890\n}',
        '{\n  "id": 1,\n  "id": 2\n}',
        '{\n  "value": ' + "1" * 5000 + "\n}",
        '{\n  "value": ' + "[" * 2000 + "0" + "]" * 2000 + "\n}",
    ],
)
def test_mcp_text_compaction_preserves_custom_text_and_errors(text):
    """Keep Markdown, non-JSON diagnostics and JSON string content unchanged."""
    # Arrange
    import asyncio
    from types import SimpleNamespace

    from mcp.types import CallToolResult, TextContent

    from gitlab_security_mcp import server

    original = CallToolResult(
        content=[TextContent(text=text)],
        structuredContent={"status": "ERROR", "reason": text},
        isError=True,
    )

    async def call_next(context):
        """Return the serialized error envelope used by actual SDK dispatch."""
        return original.model_dump(mode="json", by_alias=True, exclude_none=True)

    context = SimpleNamespace(method="tools/call")
    # Act
    result = asyncio.run(server._progress_middleware(context, call_next))
    # Assert
    assert result.content[0].text == text
    assert result.structured_content == {"status": "ERROR", "reason": text}
    assert result.is_error is True


def test_progress_console_can_be_disabled(monkeypatch):
    """Respect headless and CI launches that opt out of extra console windows."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import server

    launch = Mock()
    monkeypatch.setenv("PROGRESS_CONSOLE", "off")
    monkeypatch.setattr(server.subprocess, "Popen", launch)

    # Act
    console = server._open_progress_console()

    # Assert
    assert console is None
    launch.assert_not_called()


@pytest.mark.parametrize("failed", [False, True])
def test_run_completion_closes_owned_console_and_a_new_run_reopens_it(
    monkeypatch, failed
):
    """Keep the log console during work, then reap it even when a run raises."""
    # Arrange
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import Mock

    from gitlab_security_mcp import server
    from gitlab_security_mcp.commands import progress_sink

    first, second = Mock(), Mock()
    launch = Mock(side_effect=[first, second])
    monkeypatch.setattr(server, "_open_progress_console", launch)
    monkeypatch.setattr(server, "_progress_console", None)
    monkeypatch.setattr(server, "_progress_console_attempted", False)
    monkeypatch.setattr(server, "_progress_console_enabled", False)
    monkeypatch.setattr(server, "_progress_close_pending", False)
    monkeypatch.setattr(server, "_progress_calls", 0)

    async def execute(name, status, raises=False):
        """Exercise the actual middleware lifecycle without starting any process."""

        async def report(*args):
            """Consume progress as a host would."""
            return None

        async def next_call(context):
            """Publish real run progress and optionally fail before returning."""
            progress_sink.get()("fixture progress")
            if raises:
                raise RuntimeError("run failed")
            return {"status": status}

        context = SimpleNamespace(
            method="tools/call",
            params={"name": name},
            session=SimpleNamespace(report_progress=report),
        )
        return await server._progress_middleware(context, next_call)

    async def run():
        """Complete two runs in the same persistent MCP server."""
        await execute("run_prechecks", "PRECHECK_PASSED")
        first.close.assert_not_called()
        if failed:
            with pytest.raises(RuntimeError, match="run failed"):
                await execute("run_validation_matrix", "", raises=True)
        else:
            await execute("complete_security_run", "REPORT_GENERATED")
        first.close.assert_called_once()
        assert server._progress_console is None
        await execute("run_prechecks", "PRECHECK_PASSED")
        second.close.assert_not_called()
        await execute("complete_security_run", "REPORT_GENERATED")

    # Act
    asyncio.run(run())

    # Assert
    assert launch.call_count == 2
    second.close.assert_called_once()


def test_report_tool_delivers_security_report_as_mcp_text(repo, monkeypatch):
    """Deliver the final security report as text, not nested JSON."""
    # Arrange
    import asyncio

    from mcp.server.mcpserver.server import Context
    from mcp.server.mcpserver.tools.base import Tool
    from mcp.types import CallToolResult

    from gitlab_security_mcp import server

    engine = Engine(repo, gitlab=FakeGitLab([]), advisory=ScriptedAdvisory())
    monkeypatch.setattr(server, "_engine_for", lambda _root: engine)

    # Act
    result = asyncio.run(
        Tool.from_function(server.generate_local_report).run(
            {}, Context(), convert_result=True
        )
    )

    # Assert
    assert isinstance(result, CallToolResult)
    text = result.content[-1].text
    assert text == result.structured_content["final_summary_markdown"]
    assert text.startswith("## Unit-test validation")
    assert "Test compatibility was not verified" in text
    assert "## Finding Assessments" in text
    assert text.rstrip().endswith(result.structured_content["unresolved_issues_table"])


def test_report_error_is_visible_as_text(monkeypatch):
    """Retain error signaling and readable failure details when reporting fails."""
    # Arrange
    from gitlab_security_mcp import server

    monkeypatch.setattr(
        server,
        "_run",
        lambda *args, **kwargs: {"status": "ERROR", "error": "Checkout unavailable"},
    )

    # Act
    result = server._generate_local_report()

    # Assert
    assert result.is_error
    assert result.structured_content["status"] == "ERROR"
    assert "Checkout unavailable" in result.content[0].text


def test_finding_progress_identifies_item_and_steps(tmp_path, caplog, monkeypatch):
    """Emit finding-specific progress before and after the advisory decision."""
    # Arrange
    import logging

    from gitlab_security_mcp.engine import logger

    monkeypatch.setattr(logger, "propagate", True)
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "4.17.20"}}), encoding="utf-8"
    )
    finding = _finding("progress-item", "lodash", "CVE-FIX", "4.17.20")
    engine = Engine(tmp_path, gitlab=FakeGitLab([finding]), advisory=ScriptedAdvisory())
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    with caplog.at_level(logging.INFO, logger=logger.name):
        result = engine.verify_security_finding(finding["id"])

    # Assert
    assert result["decision"] == "CHANGE_REQUIRED"
    messages = [row.message for row in caplog.records]
    assert any("progress-item" in text and "started" in text for text in messages)
    assert any(
        "progress-item" in text and "local dependency" in text for text in messages
    )
    assert any("progress-item" in text and "advisory" in text for text in messages)
    assert any(
        "progress-item" in text and "CHANGE_REQUIRED" in text for text in messages
    )


@pytest.mark.parametrize(
    ("severity", "label"),
    [
        ("critical", "criticals"),
        ("HIGH", "highs"),
        ("medium", "mediums"),
        ("low", "lows"),
        ("info", "infos"),
        ("informational", "infos"),
        (None, "unknown-severity findings"),
    ],
)
def test_console_counts_findings_per_severity_in_processing_order(
    tmp_path, monkeypatch, severity, label
):
    """Show distinct-item positions live without counting retries or other severities."""
    # Arrange
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import Mock

    from gitlab_security_mcp import server

    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "4.17.20"}}), encoding="utf-8"
    )
    findings = [
        {
            **_finding(f"item-{index}", "lodash", "CVE-FIX", "4.17.20"),
            "severity": severity,
        }
        for index in range(21)
    ]
    other = {
        **_finding("other", "lodash", "CVE-FIX", "4.17.20"),
        "severity": "low" if severity != "low" else "critical",
    }
    engine = Engine(tmp_path, gitlab=FakeGitLab(findings), advisory=ScriptedAdvisory())
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [*findings, other]
    console = Mock()
    monkeypatch.setattr(server, "_progress_console", console)
    notifications = []

    async def report(progress, total, message):
        """Capture the same messages delivered to the MCP host."""
        notifications.append(message)

    async def exercise(finding_id):
        """Run real finding verification through the console/progress middleware."""

        async def call_next(context):
            """Propagate the request sink to the serialized engine worker."""
            return await asyncio.to_thread(engine.verify_security_finding, finding_id)

        context = SimpleNamespace(
            method="tools/call", session=SimpleNamespace(report_progress=report)
        )
        return await server._progress_middleware(context, call_next)

    # Act
    results = [
        asyncio.run(exercise(fid))
        for fid in (
            "item-20",
            "other",
            "item-1",
            "item-7",
            "item-5",
            "item-0",
            "item-0",
        )
    ]
    invalid = asyncio.run(exercise("not-a-finding"))

    # Assert
    for result, ordinal in zip(
        (results[0], *results[2:]), (1, 2, 3, 4, 5, 5), strict=True
    ):
        assert result["decision"] == "CHANGE_REQUIRED"
        assert all(
            f"Processing {ordinal} of 21 {label}" in text
            for text in result["progress_output"]
        )
    other_label = "lows" if severity != "low" else "criticals"
    assert all(
        f"Processing 1 of 1 {other_label}" in text
        for text in results[1]["progress_output"]
    )
    assert all("Processing " not in text for text in invalid["progress_output"])
    assert [call.args[0] for call in console.write.call_args_list] == notifications


@pytest.mark.parametrize(
    "outcome, affected, fixed, expected",
    [
        ("resolved", True, "4.17.21", "CHANGE_REQUIRED"),
        ("no_fix_published", True, None, "CHANGE_REQUIRED"),
        ("resolved", True, None, "CHANGE_REQUIRED"),
        ("resolved", None, "4.17.21", "CHANGE_REQUIRED"),
        ("resolved", False, "4.17.21", "FALSE_POSITIVE"),
        ("package_mismatch", None, "4.17.21", "CHANGE_REQUIRED"),
        ("lookup_failed", None, None, "CHANGE_REQUIRED"),
        ("not_found", None, None, "CHANGE_REQUIRED"),
        ("resolved", True, "5.0.0", "CHANGE_REQUIRED"),
        ("resolved", True, "not-a-version", "NO_SAFE_FIX"),
    ],
)
def test_solution_reconciles_gitlab_with_advisory_evidence_and_safe_plan(
    tmp_path, monkeypatch, outcome, affected, fixed, expected
):
    """Accept matched GitLab recommendations without ignoring advisory conflicts."""
    # Arrange
    manifest = tmp_path / "package.json"
    original = json.dumps({"dependencies": {"lodash": "4.17.20"}})
    manifest.write_text(original, encoding="utf-8")
    finding = _finding("solution-check", "lodash", "CVE-2021-23337", "4.17.20")
    finding["solution"] = "Upgrade to version 4.17.21."
    finding["fixedVersions"] = ["4.17.21"]
    lookup = AdvisoryLookup(
        outcome=outcome,
        affected=affected,
        fixed_versions=[fixed] if fixed else [],
        lowest_fixed_version=fixed,
        summary="Test advisory evidence.",
        sources=["osv:CVE-2021-23337"],
    )
    advisory = ScriptedAdvisory()
    monkeypatch.setattr(
        advisory,
        "lookup",
        lambda _finding, _ecosystem, _package, version: (
            lookup
            if version == "4.17.20"
            else AdvisoryLookup(outcome="not_found", summary="No target record.")
        ),
    )
    runner = HybridRunner(tmp_path)
    engine = Engine(
        tmp_path, gitlab=FakeGitLab([finding]), advisory=advisory, runner=runner
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    result = engine.verify_security_finding(finding["id"])

    # Assert
    assert result["decision"] == expected
    assert result["eligible_for_auto_fix"] is False
    assert result["qualification_required"] is (expected == "CHANGE_REQUIRED")
    if expected == "CHANGE_REQUIRED":
        assert result["proposed_fix"]["target"] == (fixed or "4.17.21")
        assert result["proposed_fix"]["package"] == "lodash"
        assert result["proposed_fix"]["strategy"] == "manifest_bump"
    else:
        assert result["proposed_fix"] is None
    assert manifest.read_text(encoding="utf-8") == original
    assert runner.calls == []


@pytest.mark.parametrize(
    "outcome",
    ["package_mismatch", "not_found", "no_fix_published", "resolved", "lookup_failed"],
)
@pytest.mark.parametrize("target_outcome", ["not_found", "lookup_failed"])
def test_gitlab_fix_is_candidate_when_public_advisory_lacks_fix(
    tmp_path, outcome, target_outcome
):
    """Use GitLab's qs fix without requiring OSV to repeat its package metadata."""
    # Arrange
    from unittest.mock import Mock

    manifest = tmp_path / "package.json"
    original = json.dumps({"dependencies": {"qs": "6.16.1"}})
    manifest.write_text(original, encoding="utf-8")
    finding = _finding("qs-fix", "qs", "CVE-2026-110910", "6.16.1")
    finding["solution"] = "Upgrade to version 6.16.2."
    finding["fixedVersions"] = ["6.16.2"]
    advisory = Mock()
    advisory.lookup.side_effect = [
        AdvisoryLookup(
            outcome=outcome,
            affected=True if outcome == "no_fix_published" else None,
            summary="Public advisory does not publish a matching package fix.",
            sources=["osv:CVE-2026-110910"],
        ),
        AdvisoryLookup(
            outcome=target_outcome,
            summary="No affected range for the recommended target.",
        ),
    ]
    engine = Engine(tmp_path, gitlab=FakeGitLab([finding]), advisory=advisory)
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    result = engine.verify_security_finding(finding["id"])

    # Assert
    assert result["decision"] == "CHANGE_REQUIRED"
    assert result["proposed_fix"]["target"] == "6.16.2"
    assert result["proposed_fix"]["package"] == "qs"
    assert result["qualification_required"] is True
    assert result["eligible_for_auto_fix"] is False
    assert any("GitLab" in item and "6.16.2" in item for item in result["evidence"])
    advisory.lookup.assert_called_with(finding, "npm", "qs", "6.16.2")
    assert manifest.read_text(encoding="utf-8") == original


@pytest.mark.parametrize(
    "scanner_version, fixed, initial_outcome, target_outcome, target_affected",
    [
        ("6.16.0", "6.16.2", "package_mismatch", "not_found", None),
        ("unknown", "6.16.2", "package_mismatch", "not_found", None),
        ("6.16.1", "6.16.1", "package_mismatch", "not_found", None),
        ("6.16.1", "6.16.0", "package_mismatch", "not_found", None),
        ("6.16.1", "invalid", "package_mismatch", "not_found", None),
        ("6.16.1", "", "package_mismatch", "not_found", None),
        ("6.16.1", "6.16.2", "package_mismatch", "resolved", True),
    ],
)
def test_gitlab_fix_does_not_override_conflicts_or_invalid_evidence(
    tmp_path, scanner_version, fixed, initial_outcome, target_outcome, target_affected
):
    """Block stale scanner versions, non-upgrades, and known-affected targets."""
    # Arrange
    from unittest.mock import Mock

    manifest = tmp_path / "package.json"
    original = json.dumps({"dependencies": {"qs": "6.16.1"}})
    manifest.write_text(original, encoding="utf-8")
    finding = _finding("qs-fix", "qs", "CVE-2026-110910", scanner_version)
    finding["fixedVersions"] = [fixed] if fixed else []
    advisory = Mock()
    advisory.lookup.side_effect = [
        AdvisoryLookup(outcome=initial_outcome),
        AdvisoryLookup(outcome=target_outcome, affected=target_affected),
    ]
    engine = Engine(tmp_path, gitlab=FakeGitLab([finding]), advisory=advisory)
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    result = engine.verify_security_finding(finding["id"])

    # Assert
    assert result["decision"] == "MANUAL_REVIEW"
    assert result["proposed_fix"] is None
    assert manifest.read_text(encoding="utf-8") == original


def test_report_ends_with_unresolved_security_issues_table(tmp_path):
    """Keep unresolved issues unique and end their table with the usage footer."""
    # Arrange
    from gitlab_security_mcp.report import write_report
    from gitlab_security_mcp.state import RunState

    findings = [
        _finding(name, "lodash", "CVE-2021-23337", "4.17.20")
        for name in [
            "no-fix",
            "manual",
            "failed",
            "applied",
            "false-positive",
            "not-verified",
        ]
    ]
    findings[0]["title"] = "Issue | with\na newline"
    findings[0]["securityValidationSites"] = [
        "https://api.osv.dev",
        "https://services.nvd.nist.gov",
        "https://api.osv.dev",
    ]
    state = RunState(
        findings=[*findings, findings[0].copy()],
        decisions={
            "no-fix": {"decision": "NO_SAFE_FIX", "reason": "No patch published."},
            "manual": {
                "decision": "MANUAL_REVIEW",
                "reason": "Code update needs a reviewer.",
            },
            "failed": {"decision": "CHANGE_REQUIRED"},
            "applied": {"decision": "CHANGE_REQUIRED"},
            "false-positive": {"decision": "FALSE_POSITIVE"},
        },
        no_solution=[
            {"id": "no-fix", "reason": "No patch published."},
            {"id": "applied", "reason": "Earlier failure."},
        ],
        skipped_user_prompt=[
            {"id": "manual", "reason": "Code update needs a reviewer."}
        ],
        changes=[
            {
                "finding_id": "failed",
                "status": "FIX_FAILED_LOCKFILE",
                "detail": "Lockfile update failed.",
            },
            {"finding_id": "applied", "status": "APPLIED"},
            {"finding_id": "applied", "status": "TEST_ADDED"},
        ],
    )

    # Act
    result = write_report(tmp_path, state, staged=[], diff_stat="", diff_files="")
    markdown = Path(result["human_report"]).read_text(encoding="utf-8")
    payload = json.loads(Path(result["json_report"]).read_text(encoding="utf-8"))

    # Assert
    assert [item["id"] for item in result["unresolved_issues"]] == [
        "no-fix",
        "manual",
        "failed",
    ]
    assert payload["unresolved_issues"] == result["unresolved_issues"]
    summaries = {item["id"]: item for item in result["finding_assessments"]}
    assert summaries["applied"]["decision"] == "APPLIED"
    assert summaries["false-positive"]["decision"] == "FALSE_POSITIVE"
    assert summaries["not-verified"]["decision"] == "NOT_VERIFIED"
    assert len(summaries) == len(result["finding_assessments"]) == 6
    assert result["final_summary_markdown"] == payload["final_summary_markdown"]
    assert markdown.rstrip().endswith(result["final_summary_markdown"])
    assert result["final_summary_markdown"].endswith(result["unresolved_issues_table"])
    assert markdown.rstrip().endswith(result["unresolved_issues_table"])
    assert markdown.index("## Unresolved Security Issues") > markdown.index(
        "## What you do next"
    )
    assert "Issue \\| with a newline" in result["unresolved_issues_table"]
    assert "Code update needs a reviewer." in result["unresolved_issues_table"]
    assert "Lockfile update failed." in result["unresolved_issues_table"]
    assert "Earlier failure." not in result["unresolved_issues_table"]
    assert (
        "| Reason Not Addressed | Security Validation Sites |"
        in result["unresolved_issues_table"]
    )
    assert result["unresolved_issues"][0]["security_validation_sites"] == [
        "https://api.osv.dev",
        "https://services.nvd.nist.gov",
    ]
    assert (
        "https://api.osv.dev, https://services.nvd.nist.gov"
        in result["unresolved_issues_table"]
    )
    assert "Not recorded" in result["unresolved_issues_table"]
    assert (
        payload["security_validation_sites"]["no-fix"]
        == result["unresolved_issues"][0]["security_validation_sites"]
    )


def test_unresolved_table_does_not_claim_unverified_findings_are_resolved():
    """Distinguish missing verification from confirmed issue resolution."""
    # Arrange
    from gitlab_security_mcp.report import render
    from gitlab_security_mcp.state import RunState

    state = RunState(findings=[_finding("unverified", "lodash", "CVE-2021-23337")])

    # Act
    payload, markdown = render(state, staged=[], diff_stat="", diff_files="")

    # Assert
    assert payload["unresolved_issues"] == []
    assert payload["unverified_findings"] == ["unverified"]
    assert (
        "Unverified findings, if any, are listed above."
        in payload["unresolved_issues_table"]
    )
    assert markdown.rstrip().endswith(payload["unresolved_issues_table"])


@pytest.mark.parametrize(
    "stack, runtime, expected",
    [
        ("node", "v22.20.0", "VALIDATION_COMPLETE"),
        ("dotnet", "10.0.100", "VALIDATION_COMPLETE"),
        ("dotnet", "9.0.305", "VALIDATION_FAILED"),
        ("java", 'openjdk version "17.0.16" 2025-07-15', "VALIDATION_COMPLETE"),
        ("java", 'openjdk version "21.0.8" 2025-07-15', "VALIDATION_COMPLETE"),
        ("java", 'openjdk version "25.0.1" 2026-10-20', "VALIDATION_COMPLETE"),
        ("java", 'openjdk version "11.0.8"', "VALIDATION_FAILED"),
        ("java", "unreadable runtime version", "VALIDATION_FAILED"),
    ],
)
def test_supported_runtime_validation_matrix(tmp_path, stack, runtime, expected):
    """Supported runtime validation matrix."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.commands import assert_allowed
    from gitlab_security_mcp.validate import run_validation

    manifests = {
        "node": ("package.json", '{"scripts":{"test":"node --test"}}'),
        "dotnet": (
            "App.csproj",
            "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>",
        ),
        "java": (
            "pom.xml",
            "<project><properties><maven.compiler.release>17</maven.compiler.release></properties></project>",
        ),
    }
    filename, contents = manifests[stack]
    (tmp_path / filename).write_text(contents, encoding="utf-8")
    calls = []

    def run(argv, **kwargs):
        """Simulate runtime output while checking every emitted command."""
        assert_allowed(argv, tmp_path)
        calls.append(argv)
        return CommandResult(
            argv,
            0,
            runtime
            if argv[1] in {"--version", "-version"}
            else "success\nTests: 1 passed",
            "",
            0,
            False,
            "",
            "",
        )

    runner = Mock()
    runner.run.side_effect = run

    # Act
    result = run_validation(tmp_path, runner, lambda name: name, timeout=30)

    # Assert
    assert result["status"] == expected
    assert calls
    if expected == "VALIDATION_FAILED":
        assert any(
            row["status"] == "FAILED" and row["required"] for row in result["results"]
        )


@pytest.mark.parametrize("filename", ["App.slnx", "App.fsproj", "App.vbproj"])
def test_dotnet_10_project_formats_are_detected_and_validated(tmp_path, filename):
    """Dotnet 10 project formats are detected and validated."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.validate import run_validation

    contents = (
        "<Solution />"
        if filename.endswith(".slnx")
        else "<Project><TargetFramework>net10.0</TargetFramework></Project>"
    )
    (tmp_path / filename).write_text(contents, encoding="utf-8")
    runner = Mock()
    runner.run.return_value = CommandResult(
        ["dotnet", "--version"], 0, "10.0.100\nTests: 1 passed", "", 0, False, "", ""
    )

    # Act
    result = run_validation(tmp_path, runner, lambda name: name, timeout=30)

    # Assert
    assert result["status"] == "VALIDATION_COMPLETE"
    assert runner.run.call_args_list[0].args[0] == ["dotnet", "--version"]
    assert ["dotnet", "restore"] in [call.args[0] for call in runner.run.call_args_list]
    assert ["dotnet", "build", "--configuration", "Release", "--nologo"] in [
        call.args[0] for call in runner.run.call_args_list
    ]
    assert ["dotnet", "test", "--configuration", "Release", "--nologo"] not in [
        call.args[0] for call in runner.run.call_args_list
    ]
    tests = [row for row in result["results"] if row.get("kind") == "unit_tests"]
    assert tests == []


@pytest.mark.parametrize(
    "manager, filename, contents, package, installed, target",
    [
        (
            "npm",
            "package.json",
            '{"dependencies":{"lodash":"4.17.20"}}',
            "lodash",
            "4.17.20",
            "4.17.21",
        ),
        (
            "nuget",
            "App.csproj",
            '<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>',
            "Newtonsoft.Json",
            "13.0.1",
            "13.0.3",
        ),
        (
            "nuget",
            "Directory.Packages.props",
            '<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>',
            "Newtonsoft.Json",
            "13.0.1",
            "13.0.3",
        ),
        (
            "maven",
            "pom.xml",
            "<project><properties><commons.version>1.9</commons.version></properties><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>${commons.version}</version></dependency></dependencies></project>",
            "org.apache.commons:commons-text",
            "1.9",
            "1.10.0",
        ),
        (
            "gradle",
            "build.gradle.kts",
            'dependencies { implementation("org.apache.commons:commons-text:1.9") }',
            "org.apache.commons:commons-text",
            "1.9",
            "1.10.0",
        ),
    ],
)
def test_advisory_verified_dependency_fix_across_stacks(
    tmp_path, monkeypatch, manager, filename, contents, package, installed, target
):
    """Advisory verified dependency fix across stacks."""
    # Arrange
    (tmp_path / filename).write_text(contents, encoding="utf-8")
    finding = _finding("cross-stack", package, "CVE-TEST", installed)
    finding["location"] = {"file": filename}
    advisory = ScriptedAdvisory()
    monkeypatch.setattr(
        advisory,
        "lookup",
        lambda *args: AdvisoryLookup(
            outcome="resolved",
            affected=True,
            lowest_fixed_version=target,
            fixed_versions=[target],
            summary="Verified patched version",
        ),
    )
    runner = HybridRunner(tmp_path)
    from tests.conftest import documentation_client

    engine = Engine(
        tmp_path,
        gitlab=FakeGitLab([finding]),
        advisory=advisory,
        docs=documentation_client(),
        runner=runner,
        which=lambda name: name,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    verified = engine.verify_security_finding("cross-stack")
    from tests.conftest import approve_package_for_test, select_release_for_test

    select_release_for_test(engine, "cross-stack")
    review = approve_package_for_test(tmp_path, verified["proposed_fix"])
    engine.package_policy_path = (
        tmp_path / ".security-mcp" / "package-update-policy.json"
    )
    if manager in {"nuget", "maven"}:
        engine.package_policy_path.unlink()
        review["license"] = {
            "expression": "MIT",
            "sources": ["https://example.test/license"],
            "commercial_use_permitted": True,
            "no_license_fees": True,
            "obligations": "Retain notices",
            "assessment": "Reviewed fixture target license terms",
        }
    qualified = engine.qualify_package_update("cross-stack", review)
    applied = engine.apply_minimal_fix("cross-stack")

    # Assert
    assert verified["decision"] == "CHANGE_REQUIRED"
    assert verified["proposed_fix"]["manager"] == manager
    assert qualified["status"] == "QUALIFIED", qualified
    assert applied["status"] == "APPLIED"
    assert target in (tmp_path / filename).read_text(encoding="utf-8")
    assert installed not in (tmp_path / filename).read_text(encoding="utf-8")
    assert bool(runner.calls) is (manager == "gradle")
    assert all(tool_name(call[0]) != "git" for call in runner.calls)


@pytest.mark.parametrize(
    "package, installed, target, major",
    [
        ("minimatch", "11.0.0", "11.0.1", False),
        ("glob", "14.0.1", "14.0.2", False),
        ("minimatch", "10.2.6", "11.0.1", True),
        ("glob", "10.5.0", "14.0.2", True),
    ],
)
def test_nested_node_finding_reaches_advisory_in_dotnet_repo(
    tmp_path, package, installed, target, major
):
    """Nested node finding reaches advisory in dotnet repo."""
    # Arrange
    from unittest.mock import Mock

    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text('{"name":"frontend"}', encoding="utf-8")
    (frontend / "pnpm-lock.yaml").write_text(
        f"packages:\n  {package}@{installed}: {{}}\n", encoding="utf-8"
    )
    (tmp_path / "Backend.csproj").write_text("<Project />", encoding="utf-8")
    finding = _finding(package, package, "CVE-TEST", installed)
    finding["location"] = {"file": "frontend/pnpm-lock.yaml"}
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved",
        affected=True,
        lowest_fixed_version=target,
        fixed_versions=[target],
        summary="Verified fixed version",
    )
    engine = Engine(tmp_path, gitlab=FakeGitLab([finding]), advisory=advisory)
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    verified = engine.verify_security_finding(package)
    blocked = engine.apply_minimal_fix(package)

    # Assert
    advisory.lookup.assert_called_once_with(finding, "npm", package, installed)
    assert verified["decision"] == "CHANGE_REQUIRED"
    if major:
        assert any("Major-version candidate" in item for item in verified["evidence"])
    assert verified["proposed_fix"]["target"] == target
    assert verified["proposed_fix"]["files"] == [
        "frontend/pnpm-workspace.yaml",
        "frontend/pnpm-lock.yaml",
    ]
    assert blocked["status"] == "QUALIFICATION_REQUIRED"


@pytest.mark.parametrize(
    "mode",
    [
        "resolved",
        "logged",
        "configurations",
        "failed",
        "truncated",
        "conflict",
        "unresolved",
        "mutated",
    ],
)
def test_gradle_transitive_inspection_preserves_advisory_review(tmp_path, mode):
    """Resolve real selected versions once without guessing absent or ambiguous trees."""
    # Arrange
    from unittest.mock import Mock

    (tmp_path / "build.gradle").write_text("dependencies { }\n", encoding="utf-8")
    (tmp_path / "gradle.properties").write_text("platformVersion=1\n", encoding="utf-8")
    finding = _finding("gradle-transitive", "io.example/library", "CVE-TEST", "1.0.0")
    finding["location"] = {"file": "build.gradle"}
    finding["solution"] = "Upgrade to version 1.2.0 or above."
    output = "runtimeClasspath - Application classpath.\n+--- io.example:library:1.0.0 -> 1.1.0\n"
    if mode == "conflict":
        output += "\\--- io.example:library:1.0.0\n"
    if mode == "unresolved":
        output += "\\--- io.example:library:1.0.0 FAILED\n"
    if mode == "configurations":
        finding["installedVersion"] = "1.1.0"
        output = (
            "checkstyle - Tool classpath.\n+--- io.example:library:1.0.0\n"
            "runtimeClasspath - Application classpath.\n+--- io.example:library:1.1.0\n"
        )
    runner = Mock()
    runner.run.return_value = CommandResult(
        ["gradle", "--no-daemon", "dependencies"],
        int(mode == "failed"),
        output,
        "Gradle failed" if mode == "failed" else "",
        0,
        mode == "truncated",
        "out",
        "err",
    )
    if mode == "logged":
        log = tmp_path / ".security-mcp" / "command-logs" / "dependencies.stdout.log"
        log.parent.mkdir(parents=True)
        log.write_bytes(
            b"runtimeClasspath - Application classpath.\r\n"
            b"+--- io.example:library:9.0.0 (c)\r\n"
            b"+--- io.example:library:1.0.0 -> 1.1.0\r\n"
            b"\\--- io.example:library:1.1.0 (*)\r\n"
        )
        runner.run.return_value.stdout = "capped preview"
        runner.run.return_value.truncated = True
        runner.run.return_value.stdout_log_path = str(log)
    if mode == "mutated":

        def mutate_build_inputs(*_args, **_kwargs):
            """Reject tree evidence produced while build inputs are changing."""
            (tmp_path / "gradle.properties").write_text(
                f"platformVersion={runner.run.call_count + 10}\n", encoding="utf-8"
            )
            return runner.run.return_value

        runner.run.side_effect = mutate_build_inputs
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved",
        affected=True,
        lowest_fixed_version="1.2.0",
        fixed_versions=["1.2.0"],
        summary="Fixed in 1.2.0.",
        validation_sites=["https://osv.dev"],
    )
    if mode not in {"resolved", "logged"}:
        advisory.lookup.return_value.affected = False
    engine = Engine(
        tmp_path,
        runner=runner,
        gitlab=Mock(),
        advisory=advisory,
        which=lambda name: "gradle" if name == "gradle" else None,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    first = engine.verify_security_finding(finding["id"])
    again = engine.verify_security_finding(finding["id"])
    before_change = runner.run.call_count
    (tmp_path / "gradle.properties").write_text("platformVersion=2\n", encoding="utf-8")
    engine.verify_security_finding(finding["id"])

    # Assert
    if mode in {"resolved", "logged"}:
        assert first["decision"] == again["decision"] == "CHANGE_REQUIRED"
        assert first["proposed_fix"]["strategy"] == "override"
        assert first["proposed_fix"]["package"] == "io.example:library"
        assert first["proposed_fix"]["target"] == "1.2.0"
    elif mode == "configurations":
        assert first["decision"] == again["decision"] == "FALSE_POSITIVE"
    else:
        assert first["decision"] == again["decision"] == "MANUAL_REVIEW"
        assert first["proposed_fix"] is None
    assert "https://osv.dev" in first["security_validation_sites"]
    successful = mode in {"resolved", "logged", "configurations"}
    reusable_report = successful or mode in {"conflict", "unresolved"}
    assert before_change == (1 if reusable_report else 2)
    assert runner.run.call_count == (2 if reusable_report else 3)
    expected_version = "1.1.0" if successful else "1.0.0"
    assert advisory.lookup.call_args.args[1:] == (
        "Maven",
        "io.example:library",
        expected_version,
    )
    if successful:
        assert finding["dependencyResolution"]["version"] == "1.1.0"
        if mode == "configurations":
            assert (
                finding["dependencyResolution"]["configuration"] == "runtimeClasspath"
            )
        else:
            assert "transitive" in first["reason"].lower()
            assert "1.2.0" in first["reason"]
        from gitlab_security_mcp.report import render

        payload, markdown = render(engine.state, staged=[], diff_stat="", diff_files="")
        assert payload["dependency_resolutions"][finding["id"]]["version"] == "1.1.0"
        assert "Gradle Dependency Inspections" in markdown
    else:
        assert finding["dependencyResolution"]["status"] != "RESOLVED"
        assert any("Gradle" in evidence for evidence in first["evidence"])
    assert bool(engine.state.false_positives) is (mode == "configurations")


def test_nested_gradle_dependency_inspection_finds_enclosing_wrapper(tmp_path):
    """Keep subproject dependency scope while resolving an ancestor's wrapper."""
    # Arrange
    import os
    from unittest.mock import Mock

    backend = tmp_path / "backend"
    module = backend / "api"
    module.mkdir(parents=True)
    (backend / "settings.gradle").write_text("include 'api'\n", encoding="utf-8")
    (module / "build.gradle").write_text("dependencies { }\n", encoding="utf-8")
    wrapper = backend / ("gradlew.bat" if os.name == "nt" else "gradlew")
    wrapper.write_text("", encoding="utf-8")
    finding = _finding("nested", "io.example/library", "CVE-TEST", "1.0.0")
    finding["location"] = {"file": "backend/api/build.gradle"}
    finding["solution"] = "Upgrade to version 1.2.0."
    runner = Mock()
    runner.run.return_value = CommandResult(
        [str(wrapper), "--no-daemon", "dependencies"],
        0,
        "runtimeClasspath - Application classpath.\n+--- io.example:library:1.0.0 -> 1.1.0\n",
        "",
        0,
        False,
        "",
        "",
    )
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved",
        affected=True,
        lowest_fixed_version="1.2.0",
        fixed_versions=["1.2.0"],
        summary="Fixed in 1.2.0.",
    )
    engine = Engine(
        tmp_path,
        runner=runner,
        gitlab=Mock(),
        advisory=advisory,
        which=lambda name: None,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    result = engine.verify_security_finding("nested")

    # Assert
    assert result["decision"] == "CHANGE_REQUIRED"
    assert result["proposed_fix"]["strategy"] == "override"
    assert result["proposed_fix"]["package"] == "io.example:library"
    assert result["proposed_fix"]["target"] == "1.2.0"
    assert finding["dependencyResolution"]["status"] == "RESOLVED"
    assert finding["dependencyResolution"]["version"] == "1.1.0"
    assert runner.run.call_args.args[0][0] == str(wrapper)
    assert runner.run.call_args.kwargs["cwd"] == module
    advisory.lookup.assert_called_once_with(
        finding, "Maven", "io.example:library", "1.1.0"
    )


def test_canonical_maven_coordinate_can_use_explicit_gitlab_target(tmp_path):
    """Slash-separated scanner names do not disable the exact-package fix fallback."""
    # Arrange
    from unittest.mock import Mock

    (tmp_path / "build.gradle").write_text(
        "dependencies { implementation 'io.example:library:1.0.0' }\n",
        encoding="utf-8",
    )
    finding = _finding("canonical", "io.example/library", "CVE-TEST", "1.0.0")
    finding["location"] = {"file": "build.gradle"}
    finding["solution"] = "Upgrade to version 1.2.0 or above."
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="lookup_failed", summary="Public version bounds missing."
    )
    runner = Mock()
    runner.run.return_value = CommandResult(
        [
            "gradle",
            "--no-daemon",
            "dependencies",
            "--configuration",
            "runtimeClasspath",
        ],
        0,
        "runtimeClasspath - Runtime graph.\n+--- io.example:library:1.0.0\n",
        "",
        0,
        False,
        "",
        "",
    )
    engine = Engine(
        tmp_path,
        gitlab=Mock(),
        advisory=advisory,
        runner=runner,
        which=lambda name: name,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    result = engine.verify_security_finding(finding["id"])

    # Assert
    assert result["decision"] == "CHANGE_REQUIRED"
    assert result["proposed_fix"]["package"] == "io.example:library"
    assert result["proposed_fix"]["target"] == "1.2.0"
    assert [call.args[-1] for call in advisory.lookup.call_args_list] == [
        "1.0.0",
        "1.2.0",
    ]


def test_version_only_update_cannot_fix_explicit_source_change_advisory(tmp_path):
    """A fixed release must not mask a scanner's explicit upgrade-alone warning."""
    # Arrange
    from unittest.mock import Mock

    (tmp_path / "package.json").write_text(
        '{"dependencies":{"example":"1.0.0"}}', encoding="utf-8"
    )
    finding = _finding("source-required", "example", "CVE-TEST", "1.0.0")
    finding["description"] = (
        "Version 1.2.0 corrects documentation. Upgrading alone does not fix affected code."
    )
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved",
        affected=True,
        lowest_fixed_version="1.2.0",
        fixed_versions=["1.2.0"],
        summary="Fixed release exists.",
    )
    engine = Engine(tmp_path, gitlab=Mock(), advisory=advisory)
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    result = engine.verify_security_finding(finding["id"])

    # Assert
    assert result["decision"] == "MANUAL_REVIEW"
    assert result["proposed_fix"] is None
    assert "upgrading alone" in result["reason"].lower()
    advisory.lookup.assert_called_once()


def test_unresolved_java_transitive_dependency_is_not_false_positive(tmp_path):
    """Unresolved java transitive dependency is not false positive."""
    # Arrange
    (tmp_path / "pom.xml").write_text("<project />", encoding="utf-8")
    finding = _finding("transitive", "org.example:transitive", "CVE-TEST", "1.0.0")
    finding["location"] = {"file": "pom.xml"}
    engine = Engine(tmp_path, gitlab=FakeGitLab([finding]), advisory=ScriptedAdvisory())
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    verified = engine.verify_security_finding("transitive")

    # Assert
    assert verified["decision"] == "MANUAL_REVIEW"
    assert not verified["eligible_for_auto_fix"]
    assert not engine.state.false_positives


def test_modern_yarn_validation_uses_supported_commands(tmp_path):
    """Modern yarn validation uses supported commands."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.commands import assert_allowed
    from gitlab_security_mcp.validate import run_validation

    (tmp_path / "package.json").write_text(
        '{"packageManager":"yarn@4.9.2","scripts":{"test":"node --test"}}',
        encoding="utf-8",
    )
    (tmp_path / "yarn.lock").write_text("__metadata:\n  version: 8\n", encoding="utf-8")
    calls = []

    def run(argv, **kwargs):
        """Capture Berry validation commands after allowlist enforcement."""
        assert_allowed(argv, tmp_path)
        calls.append(argv)
        return CommandResult(argv, 0, "v22.20.0\nTests: 1 passed", "", 0, False, "", "")

    runner = Mock()
    runner.run.side_effect = run

    # Act
    result = run_validation(tmp_path, runner, lambda name: name, timeout=30)

    # Assert
    assert result["status"] == "VALIDATION_COMPLETE"
    assert ["yarn", "install", "--immutable", "--mode=skip-build"] in calls
    assert ["yarn", "npm", "audit", "--json"] in calls
    assert ["yarn", "install", "--frozen-lockfile"] not in calls


@pytest.mark.parametrize(
    "strategy, expected",
    [
        ("override", ["yarn", "install", "--mode=update-lockfile"]),
        ("lockfile_only", ["yarn", "up", "-R", "lodash"]),
    ],
)
def test_modern_yarn_lockfile_refresh(tmp_path, strategy, expected):
    """Modern yarn lockfile refresh."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.commands import assert_allowed
    from gitlab_security_mcp.remediate import Plan, apply_plan

    (tmp_path / "package.json").write_text(
        '{"packageManager":"yarn@4.9.2"}', encoding="utf-8"
    )
    calls = []

    def run(argv, **kwargs):
        """Record the minimal Berry refresh without performing installs."""
        assert_allowed(argv, tmp_path)
        calls.append(argv)
        return CommandResult(argv, 0, "success", "", 0, False, "", "")

    runner = Mock()
    runner.run.side_effect = run
    plan = Plan(
        strategy,
        3,
        "npm",
        "lodash",
        "4.17.20",
        "4.17.21",
        ["yarn.lock"],
        "yarn",
        "Refresh lodash",
    )

    # Act
    result = apply_plan(tmp_path, plan, runner, lambda name: name)

    # Assert
    assert result["status"] == (
        "APPLIED" if strategy == "override" else "FIX_FAILED_LOCKFILE"
    )
    assert calls == ([expected] if strategy == "override" else [])


@pytest.mark.parametrize(
    "manifest, contents",
    [
        ("package.json", '{"scripts":{"test":"node --test"}}'),
        ("App.csproj", "<Project><TargetFramework>net10.0</TargetFramework></Project>"),
        ("pom.xml", "<project />"),
        ("build.gradle.kts", "plugins { java }"),
    ],
)
def test_missing_required_tool_keeps_validation_incomplete(
    tmp_path, manifest, contents
):
    """Missing required tool keeps validation incomplete."""
    # Arrange
    from unittest.mock import Mock

    (tmp_path / manifest).write_text(contents, encoding="utf-8")
    runner = Mock()
    engine = Engine(
        tmp_path,
        gitlab=FakeGitLab([]),
        advisory=ScriptedAdvisory(),
        runner=runner,
        which=lambda name: None,
    )
    engine.state.status = "BRANCH_CREATED"

    # Act
    result = engine.run_validation_matrix()
    repeated = engine.run_validation_matrix()

    # Assert
    assert result["status"] == "VALIDATION_INCOMPLETE"
    assert repeated["status"] == "VALIDATION_INCOMPLETE"
    assert engine.state.status == "VALIDATION_INCOMPLETE"
    assert engine.state.validation_status == "VALIDATION_INCOMPLETE"
    runner.run.assert_not_called()


def test_split_frontend_backend_validation_uses_component_directories(tmp_path):
    """Split frontend backend validation uses component directories."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.validate import run_validation

    frontend = tmp_path / "frontend"
    backend = tmp_path / "backend"
    library = tmp_path / "libs" / "activity-executor"
    frontend.mkdir()
    backend.mkdir()
    library.mkdir(parents=True)
    (frontend / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n", encoding="utf-8"
    )
    (frontend / "package.json").write_text(
        json.dumps(
            {
                "packageManager": "pnpm@10.0.0",
                "scripts": {"build": "ng build", "test": "jest"},
            }
        ),
        encoding="utf-8",
    )
    (library / "package.json").write_text(
        json.dumps({"scripts": {"build": "tsc"}}),
        encoding="utf-8",
    )
    (backend / "app.slnx").write_text("<Solution />", encoding="utf-8")
    (backend / "App.csproj").write_text(
        "<Project><TargetFramework>net10.0</TargetFramework></Project>",
        encoding="utf-8",
    )
    runner = Mock()
    runner.run.return_value = CommandResult(
        argv=["tool"],
        exit_code=0,
        stdout="10.0.100\nTests: 1 passed",
        stderr="",
        duration_ms=0,
        truncated=False,
        stdout_sha256="",
        stderr_sha256="",
    )

    # Act
    result = run_validation(tmp_path, runner, lambda name: name, timeout=30)

    # Assert
    assert result["status"] == "VALIDATION_COMPLETE"
    calls = runner.run.call_args_list
    install = next(
        call
        for call in calls
        if call.args[0][1:] == ["install", "--frozen-lockfile", "--ignore-scripts"]
    )
    assert install.args[0][0] == "pnpm"
    assert install.kwargs["cwd"] == frontend
    for call in calls:
        if call.args[0][0] == "pnpm":
            assert call.kwargs["cwd"] == frontend
        assert call.args[0][:2] != ["npm", "ci"]
        if call.args[0][0] == "dotnet" and call.args[0][1] != "--version":
            assert call.kwargs["cwd"] == backend


def test_prechecks_fail_closed(repo):
    """Prechecks fail closed."""
    # Arrange
    engine = Engine(
        repo,
        gitlab=FakeGitLab([]),
        advisory=ScriptedAdvisory(),
        which=lambda _name: None,
    )
    (repo / "dirty.txt").write_text("x\n", encoding="utf-8")

    # Act
    failed = engine.run_prechecks()

    # Assert
    assert failed["status"] == "PRECHECK_FAILED"
    assert failed["no_changes_attempted"] is True

    # Arrange
    from tests.conftest import git

    git(repo, "checkout", "-b", "dev")
    (repo / "dirty.txt").unlink()

    # Act
    not_main = engine.run_prechecks()

    # Assert
    assert not_main["status"] == "PRECHECK_FAILED"
    assert "Not on main" in not_main["reason"]


def test_full_local_run_reports_every_required_section(cloned_repo):
    """Full local run reports every required section."""
    # Arrange
    package = {
        "name": "app",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.20",
            "left-pad": "1.0.0",
            "minimist": "1.2.5",
            "ms": "2.0.0",
        },
    }
    (cloned_repo / "package.json").write_text(
        json.dumps(package, indent=2) + "\n", encoding="utf-8"
    )
    from tests.conftest import commit_all, git

    commit_all(cloned_repo, "add dependencies")
    git(cloned_repo, "push", "origin", "main")

    findings = [
        _finding("fix", "lodash", "CVE-FIX", "4.17.20"),
        _finding("fp", "left-pad", "CVE-FP"),
        _finding("ask", "minimist", "CVE-MANUAL"),
        _finding("none", "ms", "CVE-NONE"),
    ]
    runner = HybridRunner(cloned_repo)
    from tests.conftest import documentation_client

    engine = Engine(
        cloned_repo,
        gitlab=FakeGitLab(findings),
        advisory=ScriptedAdvisory(),
        docs=documentation_client(),
        runner=runner,
        which=lambda name: name,
        today=date(2026, 11, 1),
        project_id="group/app",
    )

    # Act
    precheck = engine.run_prechecks()
    pulls = engine.pull_main_twice()
    created = engine.create_security_branch()
    listed = engine.list_security_findings()
    verified = {
        item["id"]: engine.verify_security_finding(item["id"]) for item in findings
    }
    from tests.conftest import approve_package_for_test, select_release_for_test

    select_release_for_test(engine, "fix")
    review = approve_package_for_test(cloned_repo, verified["fix"]["proposed_fix"])
    engine.package_policy_path = (
        cloned_repo / ".security-mcp" / "package-update-policy.json"
    )
    qualified = engine.qualify_package_update("fix", review)
    applied = {item["id"]: engine.apply_minimal_fix(item["id"]) for item in findings}
    aaa = engine.generate_aaa_test("fix")
    validation = engine.run_validation_matrix()
    report = engine.generate_local_report()
    human = Path(report["human_report"]).read_text(encoding="utf-8")
    status = engine.get_run_status()

    # Assert
    assert precheck["status"] == "PRECHECK_PASSED"
    assert pulls["status"] == "PULLS_SUCCEEDED"
    assert len(pulls["results"]) == 2
    assert {key: created[key] for key in ("status", "branch")} == {
        "status": "BRANCH_CREATED",
        "branch": branch_name_for(date(2026, 11, 1)),
    }
    assert listed["count"] == 4
    assert verified["fix"]["decision"] == "CHANGE_REQUIRED"
    assert any("Unknown reachability" in line for line in verified["fix"]["evidence"])
    assert verified["fp"]["decision"] == "FALSE_POSITIVE"
    assert verified["ask"]["decision"] == "MANUAL_REVIEW"
    assert "needs your decision" in verified["ask"]["user_prompt"]
    assert verified["none"]["decision"] == "NO_SAFE_FIX"
    assert qualified["status"] == "QUALIFIED"
    assert applied["fix"]["status"] == "APPLIED"
    assert applied["ask"]["status"] == "SKIPPED_USER_PROMPT"
    assert applied["fp"]["status"] == "SKIPPED"
    assert applied["none"]["status"] == "SKIPPED"
    assert (
        json.loads((cloned_repo / "package.json").read_text(encoding="utf-8"))[
            "dependencies"
        ]["lodash"]
        == "4.17.21"
    )
    assert not any(
        call[1] in {"add", "commit", "push"}
        for call in runner.calls
        if tool_name(call[0]) == "git" or call[0] == "git"
    )
    assert aaa["status"] == "NOT_REQUIRED"
    assert validation["status"] == "VALIDATION_COMPLETE"
    assert "## False positives" in human
    assert "fp — left-pad: false positive because" in human
    assert "## Issues with no solution at this time" in human
    assert "none — ms:" in human
    assert "## Skipped (require user input / not resolved by online lookups)" in human
    assert "ask:" in human
    assert report["git_diff_cached_empty"] is True
    assert status["false_positives_count"] == 1


@pytest.mark.parametrize("component", [".", "frontend", "workspace"])
@pytest.mark.parametrize("failed_step", [None, "clean", "install"])
def test_pnpm_preparation_runs_after_both_pulls_before_security_checks(
    tmp_path, component, failed_step
):
    """Prepare pnpm components in order and never scan after preparation fails."""
    # Arrange
    from unittest.mock import Mock

    root = tmp_path if component == "workspace" else tmp_path / component
    root.mkdir(exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"packageManager": "pnpm@12.15.0", "scripts": {"clean": "fixture"}}),
        encoding="utf-8",
    )
    if component == "workspace":
        (root / "pnpm-workspace.yaml").write_text(
            "packages:\n  - packages/*\n", encoding="utf-8"
        )
        child = root / "packages" / "app"
        child.mkdir(parents=True)
        (child / "package.json").write_text(
            json.dumps({"packageManager": "pnpm@12.15.0"}), encoding="utf-8"
        )
    events = []

    def execute(argv, **kwargs):
        """Record real command boundaries and fail only the selected pnpm step."""
        events.append(argv)
        if argv[0] == "pnpm":
            assert kwargs["cwd"] == root.resolve()
        return CommandResult(
            argv,
            1 if argv == ["pnpm", failed_step] else 0,
            "ok",
            "preparation failed" if argv == ["pnpm", failed_step] else "",
            0,
            False,
            "out",
            "err",
        )

    runner = Mock()
    runner.run.side_effect = execute
    engine = Engine(
        tmp_path, runner=runner, gitlab=Mock(), advisory=Mock(), which=lambda name: name
    )
    engine.git = Mock()
    engine.git.current_branch.return_value = "main"
    engine.git.head.return_value = "unchanged"
    engine.git.dirty_lines.return_value = []
    engine.git.run.side_effect = lambda args, **kwargs: execute(
        ["git", *args], **kwargs
    )
    engine.state.status = "PRECHECK_PASSED"
    engine._files = []

    # Act
    result = engine.pull_main_twice()

    # Assert
    expected = [
        ["git", "pull", "--ff-only"],
        ["git", "pull", "--ff-only"],
    ]
    assert events == expected
    engine.gitlab.fetch.assert_not_called()
    assert result["status"] == "PULLS_SUCCEEDED"
    assert result["preparation"] == []


def test_existing_branch_name_is_reused_after_log_review(cloned_repo):
    """Reuse today's branch instead of stopping when its prior logs are clean."""
    # Arrange
    engine = Engine(
        cloned_repo,
        gitlab=FakeGitLab([]),
        advisory=ScriptedAdvisory(),
        which=lambda name: name,
        today=date(2026, 11, 1),
    )
    assert engine.run_prechecks()["status"] == "PRECHECK_PASSED"
    assert engine.pull_main_twice()["status"] == "PULLS_SUCCEEDED"
    from tests.conftest import git

    git(cloned_repo, "branch", branch_name_for(date(2026, 11, 1)))
    audit_path = cloned_repo / ".security-mcp" / "audit.jsonl"
    startup_commands = audit_path.read_bytes()

    # Act
    reused = engine.create_security_branch()

    # Assert
    assert reused["status"] == "BRANCH_CREATED"
    assert reused["reused"]
    assert reused["security_artifacts"]["cleanup_performed"]
    assert audit_path.read_bytes().startswith(startup_commands)
    assert engine.git.current_branch() == branch_name_for(date(2026, 11, 1))


def test_current_today_branch_reuses_its_own_dependencies_and_preserves_policies(
    cloned_repo,
):
    """Pull main safely, then prepare the reused branch rather than main's manifests."""
    # Arrange
    from unittest.mock import Mock

    from tests.conftest import commit_all, git

    day = date(2026, 11, 1)
    name = branch_name_for(day)
    root = cloned_repo / ".security-mcp"
    root.mkdir()
    policy = root / "package-update-policy.json"
    policy.write_text('{"keep":"policy"}', encoding="utf-8")
    tracked = root / "reports" / "security-remediation-report-tracked.md"
    tracked.parent.mkdir()
    tracked.write_text("Tracked evidence.", encoding="utf-8")
    commit_all(cloned_repo)
    git(cloned_repo, "checkout", "-b", name)
    (cloned_repo / "package.json").write_text(
        '{"packageManager":"pnpm@12.15.0","scripts":{"clean":"fixture"}}',
        encoding="utf-8",
    )
    commit_all(cloned_repo)
    head = git(cloned_repo, "rev-parse", "HEAD").stdout.strip()
    old = root / "reports" / "security-remediation-report-old.md"
    old.write_text("Old generated output.", encoding="utf-8")
    unknown = root / "custom-settings.json"
    unknown.write_text('{"keep":"settings"}', encoding="utf-8")
    executed = []
    real_runner = CommandRunner(cloned_repo)

    def execute(argv, **kwargs):
        """Only stub pnpm; exercise real Git branch, inventory and cleanup commands."""
        if argv[0] == "pnpm":
            executed.append(
                (argv, git(cloned_repo, "branch", "--show-current").stdout.strip())
            )
            return CommandResult(argv, 0, "ok", "", 0, False, "out", "err")
        return real_runner.run(argv, **kwargs)

    runner = Mock()
    runner.run.side_effect = execute
    engine = Engine(
        cloned_repo,
        runner=runner,
        gitlab=FakeGitLab([]),
        advisory=ScriptedAdvisory(),
        which=lambda tool: tool,
        today=day,
    )
    engine.state.status = "REPORT_GENERATED"
    engine.state.decisions = {
        "previous-run": {"decision": "MANUAL_REVIEW", "reason": "Old assessment"}
    }
    engine.state.false_positive_approval_form = {"status": "CANCELLED"}

    # Act
    precheck = engine.run_prechecks()
    pulls = engine.pull_main_twice()
    result = engine.create_security_branch()

    # Assert
    assert precheck["status"] == "PRECHECK_PASSED"
    assert precheck["reuse_branch"] == name
    assert pulls["status"] == "PULLS_SUCCEEDED"
    assert pulls["preparation_deferred_to_reused_branch"]
    assert result["status"] == "BRANCH_CREATED"
    assert result["reused"]
    assert executed == []
    assert engine.git.head() == head
    assert not old.exists()
    assert tracked.read_text(encoding="utf-8") == "Tracked evidence."
    assert policy.read_text(encoding="utf-8") == '{"keep":"policy"}'
    assert unknown.read_text(encoding="utf-8") == '{"keep":"settings"}'
    assert engine.list_security_findings("group/app")["status"] == "OK"
    assert engine.state.false_positive_approval_form == {}


@pytest.mark.parametrize("stage", ["prechecks", "branch"])
def test_clean_branch_reuse_retains_failure_logs_for_final_archive(cloned_repo, stage):
    """Keep earlier diagnostics without letting stale failures block a fresh run."""
    # Arrange
    from tests.conftest import git

    day = date(2026, 11, 1)
    name = branch_name_for(day)
    git(cloned_repo, "branch", name)
    engine = Engine(
        cloned_repo, gitlab=FakeGitLab([]), advisory=ScriptedAdvisory(), today=day
    )
    if stage == "branch":
        assert engine.run_prechecks()["status"] == "PRECHECK_PASSED"
        assert engine.pull_main_twice()["status"] == "PULLS_SUCCEEDED"
    root = cloned_repo / ".security-mcp"
    log = root / "command-logs" / "previous.stderr.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(
        "Traceback (most recent call last):\nRuntimeError: failed\n", encoding="utf-8"
    )
    state = root / "run-state.json"
    state.write_text('{"previous":"evidence"}', encoding="utf-8")
    old_report = root / "reports" / "security-remediation-report-old.md"
    old_report.parent.mkdir(exist_ok=True)
    old_report.write_text("Preserve for diagnosis.", encoding="utf-8")

    # Act
    if stage == "prechecks":
        assert engine.run_prechecks()["status"] == "PRECHECK_PASSED"
        assert engine.pull_main_twice()["status"] == "PULLS_SUCCEEDED"
    result = engine.create_security_branch()

    # Assert
    assert result["status"] == "BRANCH_CREATED"
    assert result["security_artifacts"]["previous_run_error_count"] > 0
    assert not old_report.exists()
    assert log.read_text(encoding="utf-8") == (
        "Traceback (most recent call last):\nRuntimeError: failed\n"
    )
    assert json.loads(state.read_text(encoding="utf-8"))["status"] == "BRANCH_CREATED"


def test_origin_only_today_branch_is_reused(cloned_repo):
    """Fetch the exact remote dated branch without creating unrelated refs."""
    # Arrange
    from tests.conftest import git

    day = date(2026, 11, 1)
    name = branch_name_for(day)
    origin = cloned_repo.parent / "origin"
    git(origin, "branch", name, "main")
    git(origin, "push", "origin", name)
    engine = Engine(
        cloned_repo, gitlab=FakeGitLab([]), advisory=ScriptedAdvisory(), today=day
    )

    # Act
    precheck = engine.run_prechecks()
    pulls = engine.pull_main_twice()
    result = engine.create_security_branch()

    # Assert
    assert precheck["status"] == "PRECHECK_PASSED"
    assert pulls["status"] == "PULLS_SUCCEEDED"
    assert result["status"] == "BRANCH_CREATED"
    assert result["reused"]
    assert engine.git.current_branch() == name
    assert (
        git(
            cloned_repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"
        ).stdout.strip()
        == f"origin/{name}"
    )


def test_branch_reuse_rechecks_date_after_server_crosses_midnight(
    cloned_repo, monkeypatch
):
    """Do not reuse yesterday's branch after a long-lived server changes dates."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import engine as engine_module
    from tests.conftest import git

    clock = Mock(wraps=date)
    clock.today.return_value = date(2026, 11, 1)
    monkeypatch.setattr(engine_module, "date", clock)
    git(cloned_repo, "branch", branch_name_for(date(2026, 11, 1)))
    engine = Engine(cloned_repo, gitlab=FakeGitLab([]), advisory=ScriptedAdvisory())
    assert engine.run_prechecks()["status"] == "PRECHECK_PASSED"
    clock.today.return_value = date(2026, 11, 2)

    # Act
    result = engine.pull_main_twice()

    # Assert
    assert result["status"] == "PULL_FAILED"
    assert "date changed" in result["reason"]
    assert engine.git.current_branch() == "main"


@pytest.mark.parametrize("fixed", ["3.5.8", None])
def test_container_package_fix_without_supported_edit_requires_review(repo, fixed):
    """Keep known container fixes out of the no-solution list without guessing edits."""
    # Arrange
    from contextlib import closing
    from unittest.mock import Mock

    recipe = repo / "Dockerfile"
    original = "FROM flyway/flyway:12.6.2-alpine\n"
    recipe.write_text(original, encoding="utf-8")
    finding = _finding("os-package", "openssl", "CVE-fixture", version="3.5.6-r0")
    finding.update(
        category="container_scanning",
        location={"image": "registry.example.invalid/application:commit-sha"},
        solution="Upgrade openssl to 3.5.8-r0",
    )
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved" if fixed else "no_fix_published",
        affected=True,
        lowest_fixed_version=fixed,
        fixed_versions=[fixed] if fixed else [],
        summary="Fixed bound found." if fixed else "No fixed bound found.",
    )
    with closing(
        Engine(repo, gitlab=FakeGitLab([finding]), advisory=advisory)
    ) as engine:
        engine.state.status = "FINDINGS_LISTED"
        engine.state.findings = [finding]

        # Act
        result = engine.verify_security_finding(finding["id"])

        # Assert
        assert result["decision"] == ("MANUAL_REVIEW" if fixed else "NO_SAFE_FIX")
        assert not result["eligible_for_auto_fix"]
        assert result["proposed_fix"] is None
        if fixed:
            assert "openssl has advisory fix 3.5.8" in result["reason"]
            assert "rebuild and rescan" in result["reason"]
            assert "unrelated image tag" in result["reason"]
            assert result["user_prompt"]
            assert engine.state.no_solution == []
            assert engine.state.skipped_user_prompt[0]["id"] == finding["id"]
        else:
            assert engine.state.no_solution[0]["id"] == finding["id"]
        assert engine.state.changes == []
    assert recipe.read_text(encoding="utf-8") == original


def test_container_os_package_lookup_names_its_distribution(repo):
    """An image OS package is checked as a distribution build, not an upstream release."""
    # Arrange
    from contextlib import closing
    from unittest.mock import Mock

    finding = _finding("os-package", "libkrb5-3", "CVE-fixture", version="1.22.1-2")
    finding.update(
        category="container_scanning",
        location={
            "image": "registry.example.invalid/app:sha",
            "operatingSystem": "ubuntu 26.04",
        },
    )
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(outcome="not_found", summary="None.")
    with closing(
        Engine(repo, gitlab=FakeGitLab([finding]), advisory=advisory)
    ) as engine:
        engine.state.status = "FINDINGS_LISTED"
        engine.state.findings = [finding]

        # Act
        result = engine.verify_security_finding(finding["id"])

    # Assert
    assert result["decision"] == "MANUAL_REVIEW"
    assert advisory.lookup.call_args.kwargs == {"distribution": "ubuntu 26.04"}


def test_image_bump_and_aaa_test(repo):
    """Image bump and aaa test."""
    # Arrange
    (repo / "Dockerfile").write_text("FROM nginx:1.25.1\n", encoding="utf-8")
    (repo / "package.json").write_text(
        json.dumps(
            {
                "name": "app",
                "scripts": {
                    "lint": "fixture",
                    "build": "fixture",
                    "test": "node --test",
                },
            }
        ),
        encoding="utf-8",
    )
    finding = {
        "id": "img",
        "title": "nginx",
        "category": "container_scanning",
        "identifiers": ["CVE-IMG"],
        "component": "nginx",
        "installedVersion": "1.25.1",
        "fixedVersions": [],
        "location": {"image": "nginx:1.25.1", "file": "Dockerfile"},
        "solution": None,
        "falsePositiveFlag": False,
        "status": "detected",
    }

    class ImageAdvisory:
        """Offer a same-major patched image tag for generated-test coverage."""

        def lookup(self, finding, ecosystem, package, version):
            """Return an affected image with a deterministic patched tag."""
            return AdvisoryLookup(
                outcome="resolved",
                affected=True,
                fixed_versions=["1.27.0"],
                lowest_fixed_version="1.27.0",
                summary="Fixed image tag 1.27.0.",
                sources=["osv:CVE-IMG"],
            )

    from tests.conftest import documentation_client

    engine = Engine(
        repo,
        gitlab=FakeGitLab([finding]),
        advisory=ImageAdvisory(),
        docs=documentation_client(),
        runner=HybridRunner(repo),
        which=lambda name: name,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    decision = engine.verify_security_finding("img")
    applied = engine.apply_minimal_fix("img")
    generated = engine.generate_aaa_test("img")
    test_text = (repo / generated["path"]).read_text(encoding="utf-8")

    # Assert
    assert decision["decision"] == "CHANGE_REQUIRED"
    assert decision["proposed_fix"]["strategy"] == "image_tag"
    assert applied["status"] == "APPLIED"
    assert "nginx:1.27.0" in (repo / "Dockerfile").read_text(encoding="utf-8")
    assert all(item["ok"] for item in applied["change"]["documentation"])
    assert any(item["name"] == "docker" for item in applied["change"]["documentation"])
    assert generated["status"] == "GENERATED"
    assert "Arrange" in test_text and "Act" in test_text and "Assert" in test_text


def test_missing_package_is_a_false_positive_without_guessing(repo):
    """Missing package is a false positive without guessing."""
    # Arrange
    (repo / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "1.0.0"}}), encoding="utf-8"
    )
    finding = _finding("gone", "not-a-real-package", "CVE-WHATEVER")
    engine = Engine(
        repo,
        gitlab=FakeGitLab([finding]),
        advisory=ScriptedAdvisory(),
        which=lambda name: None,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    decision = engine.verify_security_finding("gone")

    # Assert
    assert decision["decision"] == "FALSE_POSITIVE"
    assert decision["eligible_for_auto_fix"] is False


def test_path_outside_the_repo_is_not_a_false_positive(repo):
    """Path outside the repo is not a false positive."""
    # Arrange
    finding = _finding("escape", "app", "CVE-SAST")
    finding["category"] = "sast"
    finding["location"] = {"file": "../outside.txt"}
    engine = Engine(
        repo,
        gitlab=FakeGitLab([finding]),
        advisory=ScriptedAdvisory(),
        which=lambda name: None,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    decision = engine.verify_security_finding("escape")

    # Assert
    assert decision["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert "inside the checkout" in decision["reason"]


def test_listing_again_keeps_existing_decisions(repo):
    """Listing again keeps existing decisions."""
    # Arrange
    finding = _finding("gone", "left-pad", "CVE-FP")
    engine = Engine(
        repo,
        gitlab=FakeGitLab([finding]),
        advisory=ScriptedAdvisory(),
        which=lambda name: None,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]
    engine.state.decisions = {"gone": {"decision": "FALSE_POSITIVE"}}

    # Act
    listed = engine.list_security_findings()

    # Assert
    assert listed["status"] == "ERROR"
    assert engine.state.decisions["gone"]["decision"] == "FALSE_POSITIVE"


def test_incomplete_plan_is_refused(repo):
    """Incomplete plan is refused."""
    # Arrange
    finding = _finding("fix", "lodash", "CVE-FIX", "4.17.20")
    finding["remediationDecision"] = "CHANGE_REQUIRED"
    finding["proposedFix"] = {"strategy": "manifest_bump"}
    engine = Engine(
        repo,
        gitlab=FakeGitLab([finding]),
        advisory=ScriptedAdvisory(),
        which=lambda name: None,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    applied = engine.apply_minimal_fix("fix")

    # Assert
    assert applied["status"] == "ERROR"
    assert applied["reason"] == "Proposed fix is incomplete."


def test_major_version_fix_needs_caller_qualification(repo):
    """Major version fix needs caller qualification."""
    # Arrange
    (repo / "package.json").write_text(
        json.dumps({"dependencies": {"minimist": "0.2.1"}}), encoding="utf-8"
    )
    finding = _finding("major", "minimist", "CVE-MAJOR", "0.2.1")

    class MajorAdvisory:
        """Offer a breaking fixed version that must require human review."""

        def lookup(self, finding, ecosystem, package, version):
            """Return a patched major version without authorizing auto-fixing."""
            return AdvisoryLookup(
                outcome="resolved",
                affected=True,
                fixed_versions=["1.2.6"],
                lowest_fixed_version="1.2.6",
                summary="OSV lists fixed version(s): 1.2.6.",
                sources=["osv:CVE-MAJOR"],
            )

    engine = Engine(
        repo,
        gitlab=FakeGitLab([finding]),
        advisory=MajorAdvisory(),
        which=lambda name: None,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    decision = engine.verify_security_finding("major")

    # Assert
    assert decision["decision"] == "CHANGE_REQUIRED"
    assert decision["qualification_required"]
    assert decision["proposed_fix"]["major_upgrade"] is True
    assert decision["proposed_fix"]["caller_scan"]["scan_id"]
    assert not decision["eligible_for_auto_fix"]


def test_generated_test_never_overwrites_an_existing_file(repo):
    """Generated test never overwrites an existing file."""
    # Arrange
    from gitlab_security_mcp.aaa import generate_aaa_test

    (repo / "package.json").write_text(
        json.dumps({"scripts": {"test": "node --test"}}), encoding="utf-8"
    )
    existing = repo / "test" / "security" / "img.test.js"
    existing.parent.mkdir(parents=True)
    existing.write_text("// mine\n", encoding="utf-8")
    change = {
        "strategy": "image_tag",
        "oracle": "nginx:1.27.0",
        "files": ["Dockerfile"],
    }

    # Act
    result = generate_aaa_test(repo, {"id": "img"}, change)

    # Assert
    assert result["status"] == "NOT_GENERATED"
    assert existing.read_text(encoding="utf-8") == "// mine\n"


def test_report_says_unknown_when_the_index_cannot_be_read(tmp_path):
    """Report says unknown when the index cannot be read."""
    # Arrange
    from gitlab_security_mcp.report import render
    from gitlab_security_mcp.state import RunState

    state = RunState(findings=[{"id": "a"}])

    # Act
    payload, markdown = render(state, staged=None, diff_stat="", diff_files="")

    # Assert
    assert payload["git_diff_cached_empty"] is None
    assert "git diff --cached empty: unknown" in markdown
    assert payload["unverified_findings"] == ["a"]


@pytest.mark.parametrize("receipt_key", ["packageQualification", "localFixAttempt"])
@pytest.mark.parametrize(
    "backup_key,manifest_key",
    [
        ("dependency_before", "dependency_backup_manifest"),
        ("version_alignment_before", "version_alignment_backup_manifest"),
    ],
)
def test_inspection_snapshot_keeps_hashes_not_raw_rollback_text(
    tmp_path, receipt_key, backup_key, manifest_key
):
    """Keep original dependency/AI text in memory, not repeated inspection snapshots."""
    # Arrange
    import hashlib

    from gitlab_security_mcp.state import RunState

    original = "lockfile-private-content\u00e9\r\n" * 10000
    receipt = {backup_key: {"original.md": original, "new-file": None}}
    state = RunState(findings=[{"id": "a", receipt_key: receipt}])

    # Act
    state.save(tmp_path)
    raw = (tmp_path / ".security-mcp" / "run-state.json").read_text(encoding="utf-8")
    snapshot = json.loads(raw)["findings"][0][receipt_key]

    # Assert
    assert len(raw) < len(original) // 20
    assert "lockfile-private-content" not in raw
    assert backup_key not in snapshot
    assert snapshot[manifest_key]["original.md"] == {
        "sha256": hashlib.sha256(original.encode()).hexdigest(),
        "bytes": len(original.encode()),
    }
    assert snapshot[manifest_key]["new-file"] is None
    assert receipt[backup_key]["original.md"] == original


def test_saved_state_and_report_summarize_checkout_snapshots(tmp_path):
    """Write each whole-checkout hash map once as a count and digest, not every file."""
    # Arrange
    from gitlab_security_mcp.report import render
    from gitlab_security_mcp.state import RunState

    tree = {f"src/file{index}.java": "a" * 64 for index in range(500)}
    state = RunState(
        findings=[{"id": "a", "packageQualification": {"tree": tree}}],
        lint_baseline={"tree": tree, "results": []},
    )

    # Act
    state.save(tmp_path)
    saved = json.loads(
        (tmp_path / ".security-mcp" / "run-state.json").read_text(encoding="utf-8")
    )
    payload, _markdown = render(state, staged=[], diff_stat="", diff_files="")

    # Assert
    summary = saved["findings"][0]["packageQualification"]["tree"]
    assert summary["files"] == 500
    assert summary == saved["lint_baseline"]["tree"]
    assert payload["lint_baseline"]["tree"] == summary
    assert state.findings[0]["packageQualification"]["tree"] is tree
    assert "src/file0.java" not in json.dumps(saved)


def test_unresolved_report_never_prints_an_empty_code_findings_table(tmp_path):
    """A run with no other unresolved code findings says so instead of a bare header."""
    # Arrange
    from gitlab_security_mcp.report import write_unresolved_report
    from gitlab_security_mcp.state import RunState

    # Act
    result = write_unresolved_report(tmp_path, RunState())

    # Assert
    section = result["final_summary_markdown"].split(
        "## Other unresolved or unattempted code findings"
    )[1]
    assert (
        "| None reported | No other unresolved or unattempted code findings |"
        in (section.split("##")[0])
    )


def test_unresolved_report_lists_declined_audit_findings_with_location_and_problem(
    tmp_path,
):
    """Declining AI fixes still records what the audit found and where to fix it."""
    # Arrange
    from gitlab_security_mcp.report import write_unresolved_report
    from gitlab_security_mcp.state import RunState

    audit_report = tmp_path / "service_software_audit_report.md"
    audit_report.write_text("# audit\n", encoding="utf-8")
    state = RunState(
        software_audit={
            "status": "NONE_SELECTED",
            "output_path": str(audit_report),
            "selected_items": [],
            "items": [
                {
                    "id": "F1",
                    "severity": "Medium",
                    "location": "src/main/java/Auth.java:212",
                    "problem": "A JWT with no audience throws instead of failing validation",
                },
                {
                    "id": "F2",
                    "severity": "High",
                    "location": "src/main/java/Client.java:37",
                    "problem": "Unused method embeds a client credential",
                },
            ],
        }
    )

    # Act
    markdown = write_unresolved_report(tmp_path, state)["final_summary_markdown"]

    # Assert
    section = markdown.split("## Software audit findings not fixed")[1].split("## ")[0]
    assert audit_report.resolve().as_uri() in section
    rows = [
        line for line in section.splitlines() if line.startswith(("| F1 ", "| F2 "))
    ]
    assert rows[0].startswith("| F2 | High | src/main/java/Client.java:37 |")
    assert "A JWT with no audience" in rows[1]
    assert "Not selected; no edit authorized" not in markdown


def test_unresolved_report_links_audit_locations_to_checkout_files(tmp_path):
    """Bare and audit-relative locations become links that work from the report folder."""
    # Arrange
    from gitlab_security_mcp.report import write_unresolved_report
    from gitlab_security_mcp.state import RunState

    source = tmp_path / "src" / "My Auth.java"
    source.parent.mkdir()
    source.write_text("class Auth {}\n", encoding="utf-8")
    items = [
        {
            "id": "F1",
            "severity": "High",
            "location": "src/My Auth.java:3",
            "problem": "a",
        },
        {
            "id": "F2",
            "severity": "Low",
            "location": "[src/My Auth.java:9](./source/repo/src/My%20Auth.java#L9)",
            "problem": "b",
        },
        {
            "id": "F3",
            "severity": "Low",
            "location": "src/Missing.java:1",
            "problem": "c",
        },
    ]
    state = RunState(software_audit={"selected_items": [], "items": items})

    # Act
    markdown = write_unresolved_report(tmp_path, state)["final_summary_markdown"]

    # Assert
    assert (
        "| F1 | High | [src/My Auth.java:3](../../src/My%20Auth.java#L3) |" in markdown
    )
    assert (
        "| F2 | Low | [src/My Auth.java:9](../../src/My%20Auth.java#L9) |" in markdown
    )
    assert "| F3 | Low | src/Missing.java:1 |" in markdown


def test_blocked_package_never_shows_its_rejected_floor_as_the_target(tmp_path):
    """A release review that blocks the only release must not present it as proposed."""
    # Arrange
    from gitlab_security_mcp.report import write_unresolved_report
    from gitlab_security_mcp.state import RunState

    finding = {
        "id": "pkg",
        "category": "dependency_scanning",
        "component": "parse5",
        "installedVersion": "7.3.0",
        "proposedFix": {"ecosystem": "npm", "package": "parse5", "target": "8.1.1"},
        "packageVersionSelection": {
            "status": "BLOCKED",
            "target": None,
            "review": {"assessment": "8.1.1 is ESM-only; jsdom requires parse5 7."},
        },
    }
    state = RunState(
        findings=[finding], decisions={"pkg": {"decision": "CHANGE_REQUIRED"}}
    )

    # Act
    markdown = write_unresolved_report(tmp_path, state)["final_summary_markdown"]

    # Assert
    row = next(line for line in markdown.splitlines() if line.startswith("| pkg:"))
    assert "| None eligible (blocked; advisory floor 8.1.1) |" in row
    assert "| 8.1.1 |" not in row
    assert "ESM-only" in row


def test_final_summary_exposes_baseline_and_optional_validation_gaps():
    """Passing builds/tests do not hide failed lint or unavailable security audits."""
    # Arrange
    from gitlab_security_mcp.report import render
    from gitlab_security_mcp.state import RunState

    state = RunState(
        validation_status="VALIDATION_COMPLETE",
        lint_baseline={"results": [{"status": "FAILED", "command": "pnpm run lint"}]},
        validation_results=[
            {
                "status": "INFORMATIONAL",
                "required": False,
                "exit_code": 1,
                "command": "pnpm audit --json",
                "detail": "ERR_PNPM_AUDIT_BAD_RESPONSE: HTTP 400",
            },
            {"status": "SKIPPED", "required": False, "detail": "docker is not on PATH"},
        ],
    )

    # Act
    payload, markdown = render(state, staged=[], diff_stat="", diff_files="")

    # Assert
    assert payload["validation_status"] == "VALIDATION_COMPLETE"
    assert len(payload["validation_caveats"]) == 3
    summary = payload["final_summary_markdown"]
    assert "Validation caveats" in summary
    assert "pnpm run lint" in summary
    assert "ERR_PNPM_AUDIT_BAD_RESPONSE" in summary
    assert "docker is not on PATH" in summary
    assert "not a clean security audit" in markdown.lower()


def test_state_snapshot_leaves_no_temp_files(tmp_path):
    """State snapshot leaves no temp files."""
    # Arrange
    from gitlab_security_mcp.state import RunState

    state = RunState(status="PRECHECK_PASSED")

    # Act
    state.save(tmp_path)
    state.save(tmp_path)
    written = sorted(path.name for path in (tmp_path / ".security-mcp").iterdir())

    # Assert
    assert written == ["run-state.json"]
    assert (
        json.loads(
            (tmp_path / ".security-mcp" / "run-state.json").read_text(encoding="utf-8")
        )["status"]
        == "PRECHECK_PASSED"
    )


def test_tools_are_registered():
    """Tools are registered."""
    # Arrange
    from gitlab_security_mcp.server import mcp

    # Act
    names = {tool.name for tool in mcp._tool_manager.list_tools()}

    # Assert
    assert names == {
        "run_prechecks",
        "pull_main_twice",
        "create_security_branch",
        "list_security_findings",
        "verify_security_finding",
        "select_package_version",
        "select_security_fixes",
        "qualify_package_update",
        "apply_minimal_fix",
        "generate_aaa_test",
        "run_validation_matrix",
        "review_false_positives",
        "submit_false_positive_approvals",
        "generate_local_report",
        "complete_security_run",
        "choose_software_audit_action",
        "get_run_status",
    }


def test_mcp_discovery_catalog_stays_within_context_budget():
    """Budget the actual advertised tools, including schemas and descriptions."""
    # Arrange
    import asyncio

    from gitlab_security_mcp.server import mcp

    # Act
    tools = asyncio.run(mcp.list_tools())
    catalog = json.dumps(
        [
            tool.model_dump(mode="json", by_alias=True, exclude_none=True)
            for tool in tools
        ],
        ensure_ascii=False,
    )
    # Assert
    assert len(catalog) < 12_000


def test_tool_schema_compaction_preserves_validation_and_explicit_titles():
    """Trim duplicate labels on copies, not human titles or validation requirements."""
    # Arrange
    from gitlab_security_mcp.server import _compact_tool_schema

    schema = {
        "title": "exampleArguments",
        "properties": {
            "repo_root": {"title": "Repo Root", "type": "string"},
            "choice": {"title": "Choose a finding", "enum": ["one", "two"]},
        },
        "required": ["choice"],
    }

    # Act
    compact = _compact_tool_schema(schema, auto_titles=("exampleArguments",))

    # Assert
    assert compact == {
        "properties": {
            "repo_root": {"type": "string"},
            "choice": {"title": "Choose a finding", "enum": ["one", "two"]},
        },
        "required": ["choice"],
    }
    assert schema["title"] == "exampleArguments"
    assert schema["properties"]["repo_root"]["title"] == "Repo Root"
