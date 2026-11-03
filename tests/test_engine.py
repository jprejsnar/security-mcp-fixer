"""Verify local phase decisions, safe edits, reporting, and shutdown order."""

import hashlib
import json
from datetime import date
from pathlib import Path

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


def test_repository_override_recovers_unresolved_host_placeholder(repo, monkeypatch):
    # Arrange
    monkeypatch.setenv("REPO_ROOT", "${workspaceFolder}")

    # Act / Assert
    with pytest.raises(ValueError, match="unresolved host placeholder"):
        Engine.from_env()
    engine = Engine.from_env(str(repo))
    try:
        assert engine.repo_root == repo.resolve()
        assert engine.run_prechecks()["status"] == "PRECHECK_PASSED"
    finally:
        engine.close()


def test_missing_repository_has_actionable_error(tmp_path, monkeypatch):
    # Arrange
    monkeypatch.setenv("REPO_ROOT", str(tmp_path / "missing"))

    # Act / Assert
    with pytest.raises(ValueError, match="Repository directory does not exist"):
        Engine.from_env()


def test_server_recovers_configuration_error(repo, monkeypatch):
    # Arrange
    from gitlab_security_mcp import server

    monkeypatch.setattr(server, "engine", None)
    monkeypatch.setenv("REPO_ROOT", "${workspaceFolder}")

    # Act
    failed = server.run_prechecks()
    recovered = server.run_prechecks(repo_root=str(repo))
    try:
        # Assert
        assert failed["status"] == "ERROR"
        assert failed["stage"] == "configuration"
        assert "unresolved host placeholder" in failed["error"]
        assert "run_prechecks" in failed["action"]
        assert recovered["status"] == "PRECHECK_PASSED"
        assert recovered["repo_root"] == str(repo.resolve())
        refused = server.run_prechecks(repo_root=str(repo.parent))
        assert refused["status"] == "ERROR"
        assert "active run" in refused["error"]
    finally:
        server._close_engine()


def test_non_git_precheck_does_not_persist_run_state(tmp_path):
    # Arrange
    engine = Engine(tmp_path, gitlab=FakeGitLab([]), advisory=ScriptedAdvisory())

    # Act
    result = engine.run_prechecks()

    # Assert
    assert result["status"] == "PRECHECK_FAILED"
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

    # Act / Assert
    with pytest.raises((OSError, ValueError)):
        Engine(tmp_path)
    gitlab_factory.assert_not_called()
    advisory_factory.assert_not_called()


def test_engine_constructor_failure_closes_owned_client(tmp_path, monkeypatch):
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import engine as module

    gitlab = Mock()
    monkeypatch.setattr(module, "GitLabClient", lambda *args: gitlab)

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
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import engine as module

    gitlab = Mock()
    advisory = Mock()
    gitlab.close.side_effect = OSError("Close failed")
    monkeypatch.setattr(module, "GitLabClient", lambda *args: gitlab)
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
        target=lambda: results.append(engine.list_security_findings())
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


@pytest.mark.parametrize(
    "outcome, affected, fixed, expected",
    [
        ("resolved", True, "4.17.21", "CHANGE_REQUIRED"),
        ("no_fix_published", True, None, "NO_SAFE_FIX"),
        ("resolved", True, None, "NO_SAFE_FIX"),
        ("resolved", None, "4.17.21", "MANUAL_REVIEW"),
        ("resolved", False, "4.17.21", "FALSE_POSITIVE"),
        ("package_mismatch", None, "4.17.21", "MANUAL_REVIEW"),
        ("lookup_failed", None, None, "MANUAL_REVIEW"),
        ("not_found", None, None, "MANUAL_REVIEW"),
        ("resolved", True, "5.0.0", "MANUAL_REVIEW"),
        ("resolved", True, "not-a-version", "NO_SAFE_FIX"),
    ],
)
def test_solution_requires_advisory_evidence_and_safe_plan(
    tmp_path, monkeypatch, outcome, affected, fixed, expected
):
    """Require matching, comparable advisory evidence before planning edits."""
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
    monkeypatch.setattr(advisory, "lookup", lambda *args: lookup)
    runner = HybridRunner(tmp_path)
    engine = Engine(
        tmp_path, gitlab=FakeGitLab([finding]), advisory=advisory, runner=runner
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    result = engine.verify_security_finding(finding["id"])

    assert result["decision"] == expected
    assert result["eligible_for_auto_fix"] is False
    assert result["qualification_required"] is (expected == "CHANGE_REQUIRED")
    if expected == "CHANGE_REQUIRED":
        assert result["proposed_fix"]["target"] == "4.17.21"
        assert result["proposed_fix"]["package"] == "lodash"
        assert result["proposed_fix"]["strategy"] == "manifest_bump"
    else:
        assert result["proposed_fix"] is None
    assert manifest.read_text(encoding="utf-8") == original
    assert runner.calls == []


def test_report_ends_with_unresolved_security_issues_table(tmp_path):
    """Keep unresolved issues unique and place their table last in reports."""
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

    result = write_report(tmp_path, state, staged=[], diff_stat="", diff_files="")
    markdown = Path(result["human_report"]).read_text(encoding="utf-8")
    payload = json.loads(Path(result["json_report"]).read_text(encoding="utf-8"))

    assert [item["id"] for item in result["unresolved_issues"]] == [
        "no-fix",
        "manual",
        "failed",
    ]
    assert payload["unresolved_issues"] == result["unresolved_issues"]
    assert markdown.rstrip().endswith(result["unresolved_issues_table"])
    assert markdown.index("## Unresolved Security Issues") > markdown.index(
        "## What you do next"
    )
    assert "Issue \\| with a newline" in result["unresolved_issues_table"]
    assert "Code update needs a reviewer." in result["unresolved_issues_table"]
    assert "Lockfile update failed." in result["unresolved_issues_table"]
    assert "Earlier failure." not in result["unresolved_issues_table"]


def test_unresolved_table_does_not_claim_unverified_findings_are_resolved():
    """Distinguish missing verification from confirmed issue resolution."""
    from gitlab_security_mcp.report import render
    from gitlab_security_mcp.state import RunState

    state = RunState(findings=[_finding("unverified", "lodash", "CVE-2021-23337")])

    payload, markdown = render(state, staged=[], diff_stat="", diff_files="")

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
        ("java", 'openjdk version "21.0.8" 2025-07-15', "VALIDATION_FAILED"),
        ("java", "unreadable runtime version", "VALIDATION_FAILED"),
    ],
)
def test_supported_runtime_validation_matrix(tmp_path, stack, runtime, expected):
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
            runtime if argv[1] in {"--version", "-version"} else "success",
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
        ["dotnet", "--version"], 0, "10.0.100", "", 0, False, "", ""
    )

    # Act
    result = run_validation(tmp_path, runner, lambda name: name, timeout=30)

    # Assert
    assert result["status"] == "VALIDATION_COMPLETE"
    assert runner.run.call_args_list[0].args[0] == ["dotnet", "--version"]
    assert ["dotnet", "restore"] in [call.args[0] for call in runner.run.call_args_list]
    assert ["dotnet", "test", "--configuration", "Release", "--nologo"] in [
        call.args[0] for call in runner.run.call_args_list
    ]


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
    engine = Engine(
        tmp_path,
        gitlab=FakeGitLab([finding]),
        advisory=advisory,
        runner=runner,
        which=lambda name: name,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    verified = engine.verify_security_finding("cross-stack")
    from tests.conftest import approve_package_for_test

    review = approve_package_for_test(tmp_path, verified["proposed_fix"])
    engine.package_policy_path = (
        tmp_path / ".security-mcp" / "package-update-policy.json"
    )
    qualified = engine.qualify_package_update("cross-stack", review)
    applied = engine.apply_minimal_fix("cross-stack")

    # Assert
    assert verified["decision"] == "CHANGE_REQUIRED"
    assert verified["proposed_fix"]["manager"] == manager
    assert qualified["status"] == "QUALIFIED"
    assert applied["status"] == "APPLIED"
    assert target in (tmp_path / filename).read_text(encoding="utf-8")
    assert installed not in (tmp_path / filename).read_text(encoding="utf-8")
    assert runner.calls
    assert all(tool_name(call[0]) != "git" for call in runner.calls)


def test_unresolved_java_transitive_dependency_is_not_false_positive(tmp_path):
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
        return CommandResult(argv, 0, "v22.20.0", "", 0, False, "", "")

    runner = Mock()
    runner.run.side_effect = run

    # Act
    result = run_validation(tmp_path, runner, lambda name: name, timeout=30)

    # Assert
    assert result["status"] == "VALIDATION_COMPLETE"
    assert ["yarn", "install", "--immutable"] in calls
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
    assert result["status"] == "APPLIED"
    assert calls == [expected]


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
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.validate import run_validation

    frontend = tmp_path / "frontend"
    backend = tmp_path / "backend"
    frontend.mkdir()
    backend.mkdir()
    (frontend / "package.json").write_text(
        json.dumps(
            {
                "packageManager": "pnpm@10.0.0",
                "scripts": {"build": "ng build", "test": "jest"},
            }
        ),
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
        stdout="10.0.100",
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
        call for call in calls if call.args[0][1:] == ["install", "--frozen-lockfile"]
    )
    assert install.args[0][0] == "pnpm"
    assert install.kwargs["cwd"] == frontend
    for call in calls:
        if call.args[0][0] == "pnpm":
            assert call.kwargs["cwd"] == frontend
        if call.args[0][0] == "dotnet" and call.args[0][1] != "--version":
            assert call.kwargs["cwd"] == backend


def test_prechecks_fail_closed(repo):
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
    engine = Engine(
        cloned_repo,
        gitlab=FakeGitLab(findings),
        advisory=ScriptedAdvisory(),
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
    from tests.conftest import approve_package_for_test

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
    assert created == {
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


def test_existing_branch_name_stops_the_run(cloned_repo):
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

    # Act
    failed = engine.create_security_branch()

    # Assert
    assert failed["status"] == "BRANCH_CREATION_FAILED"
    assert "already exists" in failed["reason"]


def test_image_bump_and_aaa_test(repo):
    # Arrange
    (repo / "Dockerfile").write_text("FROM nginx:1.25.1\n", encoding="utf-8")
    (repo / "package.json").write_text(
        json.dumps({"name": "app", "scripts": {"test": "node --test"}}),
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

    engine = Engine(
        repo,
        gitlab=FakeGitLab([finding]),
        advisory=ImageAdvisory(),
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
    assert generated["status"] == "GENERATED"
    assert "Arrange" in test_text and "Act" in test_text and "Assert" in test_text


def test_missing_package_is_a_false_positive_without_guessing(repo):
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
    assert decision["decision"] == "MANUAL_REVIEW"
    assert "outside the repository" in decision["reason"]


def test_listing_again_keeps_existing_decisions(repo):
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


def test_major_version_fix_needs_a_person(repo):
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
    assert decision["decision"] == "MANUAL_REVIEW"
    assert "major upgrade" in decision["reason"]
    assert decision["user_prompt"]


def test_generated_test_never_overwrites_an_existing_file(repo):
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


def test_state_snapshot_leaves_no_temp_files(tmp_path):
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
        "qualify_package_update",
        "apply_minimal_fix",
        "generate_aaa_test",
        "run_validation_matrix",
        "generate_local_report",
        "get_run_status",
    }
