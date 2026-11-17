"""Verify build-and-unit-test acceptance and transitive Java remediation."""

import asyncio
from copy import deepcopy
from functools import partial
from unittest.mock import AsyncMock, Mock

import anyio
import pytest
from mcp import ClientSession
from mcp.shared.memory import create_client_server_memory_streams

from gitlab_security_mcp import server
from gitlab_security_mcp.advisory import AdvisoryLookup
from gitlab_security_mcp.commands import CommandResult, assert_allowed
from gitlab_security_mcp.engine import Engine, _ValidationRunner
from gitlab_security_mcp.manifests import PackageHit
from gitlab_security_mcp.qualification import run_checks
from gitlab_security_mcp.remediate import apply_plan, plan_remediation
from gitlab_security_mcp.validate import _product_result, run_validation
from tests.conftest import documentation_client


def _gradle_wrapper(root, version):
    """Declare a wrapper without executing its fixture launchers."""
    for name in ("gradlew", "gradlew.bat"):
        (root / name).write_text("")
    properties = root / "gradle" / "wrapper" / "gradle-wrapper.properties"
    properties.parent.mkdir(parents=True)
    properties.write_text(
        f"distributionUrl=https\\://services.gradle.org/distributions/gradle-{version}-bin.zip\n"
    )


@pytest.mark.parametrize(
    "output",
    [
        "Tests: 1 failed, 4 passed, 5 total",
        "Passed! - Failed: 1, Passed: 4, Total: 5",
        "Tests run: 5, Failures: 1, Errors: 0, Skipped: 0",
        "Tests  1 failed | 4 passed (5)",
        "# pass 4\n# fail 1",
    ],
)
def test_masked_test_failures_cannot_be_accepted(output):
    """Reject failed-test summaries even when a repository script masks the exit code."""
    # Arrange
    result = CommandResult(["npm", "test"], 0, output, "", 0, False, "", "")

    # Act
    row = _product_result(result, "unit_tests")

    # Assert
    assert row["status"] == "FAILED"
    assert not result.unit_tests_verified


@pytest.mark.parametrize("version", [None, "7.5.1", "7.6.4", "9.9.0", "custom"])
def test_gradle_policy_reuses_verified_junit_execution(tmp_path, version):
    """Share one forced unit run while honoring legacy corporate test command forms."""
    # Arrange
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }\n")
    if version is not None:
        _gradle_wrapper(tmp_path, version)
    report = tmp_path / "build" / "test-results" / "test" / "TEST-App.xml"
    report.parent.mkdir(parents=True)

    def execute(argv, **kwargs):
        """Emit fresh JUnit evidence but no console test counts."""
        assert_allowed(argv, tmp_path)
        if "test" in argv:
            report.write_text('<testsuite tests="4" failures="0" errors="0"/>')
        output = 'openjdk version "25.0.1"' if argv[0] == "java" else "BUILD SUCCESSFUL"
        return CommandResult(argv, 0, output, "", 0, False, "", "")

    underlying = Mock()
    underlying.run.side_effect = execute
    runner = _ValidationRunner(underlying, tmp_path)
    validation = run_validation(
        tmp_path,
        runner,
        lambda name: name,
        timeout=30,
        package_checks=True,
        skip_lint=True,
    )

    # Act
    tool = next(
        call.args[0][0]
        for call in underlying.run.call_args_list
        if "assemble" in call.args[0]
    )
    checks = run_checks(
        tmp_path,
        {
            "build": {
                "argv": [tool, "--no-daemon", "assemble"],
                "success_marker": "BUILD SUCCESSFUL",
            },
            "unit_tests": {
                "argv": [tool, "--no-daemon", "test"],
                "success_marker": "BUILD SUCCESSFUL",
            },
        },
        runner,
        lambda name: name,
        30,
    )

    # Assert
    assert validation["status"] == "VALIDATION_COMPLETE"
    assert all(check["status"] == "PASSED" for check in checks)
    assert sum("test" in call.args[0] for call in underlying.run.call_args_list) == 1
    gradle_calls = [
        call.args[0]
        for call in underlying.run.call_args_list
        if call.args[0][0] == tool
    ]
    assert len(gradle_calls) == (1 if version in {"7.6.4", "9.9.0"} else 3)
    if version in {"7.6.4", "9.9.0"}:
        assert gradle_calls[0][1:] == ["--no-daemon", "assemble", "test", "--rerun"]


@pytest.mark.parametrize("mode", ["fresh", "stale", "empty", "failed", "invalid"])
@pytest.mark.parametrize("modern", [False, True])
def test_gradle_tests_require_fresh_successful_reports(tmp_path, mode, modern):
    """Reject stale, empty or failing reports despite a successful task exit."""
    # Arrange
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }\n")
    if modern:
        _gradle_wrapper(tmp_path, "9.9.0")
    report = tmp_path / "build" / "test-results" / "test" / "TEST-App.xml"
    report.parent.mkdir(parents=True)
    if mode == "stale":
        report.write_text('<testsuite tests="4" failures="0" errors="0"/>')

    def execute(argv, **kwargs):
        """Create only the evidence this simulated test command actually produced."""
        assert_allowed(argv, tmp_path)
        if "test" in argv and mode != "stale":
            report.write_text(
                "broken XML"
                if mode == "invalid"
                else f'<testsuite tests="{0 if mode == "empty" else 4}" '
                f'failures="{1 if mode == "failed" else 0}" errors="0"/>'
            )
        output = 'openjdk version "25.0.1"' if argv[0] == "java" else "BUILD SUCCESSFUL"
        return CommandResult(argv, 0, output, "", 0, False, "", "")

    runner = Mock()
    runner.run.side_effect = execute

    # Act
    result = run_validation(
        tmp_path,
        runner,
        lambda name: name,
        timeout=30,
        package_checks=True,
        skip_lint=True,
    )

    # Assert
    assert result["status"] == (
        "VALIDATION_COMPLETE" if mode == "fresh" else "VALIDATION_FAILED"
    )
    assert any("test" in call.args[0] for call in runner.run.call_args_list)


@pytest.mark.parametrize(
    "filename,manager,original,expected",
    [
        (
            "build.gradle",
            "gradle",
            "dependencies { implementation platform('bom:app:1') }\n",
            'resolutionStrategy.force("example:library:1.0.1")',
        ),
        (
            "build.gradle.kts",
            "gradle",
            'dependencies { implementation(platform("bom:app:1")) }\n',
            'resolutionStrategy.force("example:library:1.0.1")',
        ),
        (
            "pom.xml",
            "maven",
            "<project><dependencies><dependency><groupId>bom</groupId><artifactId>app</artifactId><version>1</version></dependency></dependencies></project>",
            "<artifactId>library</artifactId>",
        ),
    ],
)
def test_transitive_java_override_preserves_existing_bom(
    tmp_path, filename, manager, original, expected
):
    """Plan a targeted transitive fix instead of rejecting every BOM-managed update."""
    # Arrange
    path = tmp_path / filename
    path.write_text(original)
    hit = PackageHit(
        "Maven", manager, "example:library", "1.0.0", None, filename, None, False
    )

    # Act
    plan, _reason = plan_remediation(tmp_path, {}, hit, "1.0.1")
    result = apply_plan(tmp_path, plan, Mock(), lambda name: name)

    # Assert
    assert plan.strategy == "override"
    assert result["status"] == "APPLIED"
    assert expected in path.read_text()
    assert (
        ("bom:app:1" in path.read_text())
        if manager == "gradle"
        else ("<artifactId>app</artifactId><version>1</version>" in path.read_text())
    )
    assert result["files"] == [filename]


def _review(package, ecosystem):
    """Supply explicit fixture documentation and license review, not corporate approval."""
    return {
        "ecosystem": ecosystem,
        "package": package,
        "target": "1.0.1",
        "documentation": {
            "complete": True,
            "sources": ["https://example.test/docs"],
            "summary": "Reviewed target API",
        },
        "compatible": True,
        "compatible_without_code_changes": True,
        "api_changes": "No caller changes",
        "source_fixes": [],
        "frameworks": [
            {
                "name": "Fixture",
                "version": "1",
                "source_url": "https://example.test/support",
                "assessment": "Supported",
            }
        ],
        "license": {
            "expression": "MIT",
            "sources": ["https://example.test/license"],
            "commercial_use_permitted": True,
            "no_license_fees": True,
            "obligations": "Retain notices",
            "assessment": "Reviewed fixture license",
        },
    }


@pytest.mark.parametrize("invalid", ["target", "license"])
def test_native_preparation_rejects_unreviewed_target_or_license(tmp_path, invalid):
    """Preparing automatic edits must retain exact-target and license gates."""
    # Arrange
    plan = {
        "ecosystem": "Maven",
        "package": "example:library",
        "target": "1.0.1",
        "manager": "gradle",
    }
    engine = Engine(
        tmp_path, gitlab=Mock(), advisory=Mock(), docs=Mock(), runner=Mock()
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [{"id": "one", "proposedFix": plan}]
    engine.state.decisions = {"one": {"decision": "CHANGE_REQUIRED"}}
    review = _review(plan["package"], "Maven")
    if invalid == "target":
        review["target"] = "9.0.0"
    else:
        review.pop("license")
    candidates = engine.fix_selection_candidates()["candidates"]

    # Act
    result = engine.prepare_package_updates(candidates, {"one": review})

    # Assert
    assert result["status"] == "PACKAGE_REVIEW_REQUIRED"
    assert result["required_reviews"][0]["finding_id"] == "one"
    assert invalid in result["required_reviews"][0]["reason"]
    engine.runner.run.assert_not_called()
    assert not engine.state.changes


@pytest.mark.parametrize(
    "outcome",
    ["success", "mcp", "build", "test", "checkout_changed", "blocked_review", "docs"],
)
@pytest.mark.parametrize("modern", [False, True])
def test_native_approval_automatically_updates_selected_gradle_packages(
    tmp_path, monkeypatch, outcome, modern
):
    """Reproduce three checked findings: edit two coordinates, validate, and save actual outcomes."""
    # Arrange
    manifest = tmp_path / "build.gradle"
    original = "plugins { id 'java' }\ndependencies { }\n"
    manifest.write_text(original)
    if modern:
        _gradle_wrapper(tmp_path, "9.9.0")
    packages = [
        "example:library",
        "example:library",
        "example:codec",
        "example:unchecked",
    ]
    runner = Mock()
    dialog = Mock(close=AsyncMock())

    def execute(argv, **kwargs):
        """Resolve real manifest edits and fail only the offending updated coordinate."""
        assert_allowed(argv, tmp_path)
        text = manifest.read_text()
        bad = "example:library:1.0.1" in text
        failed = bad and (
            (outcome == "build" and "assemble" in argv)
            or (outcome == "test" and "test" in argv)
        )
        output = (
            "runtimeClasspath - runtime\n"
            + "\n".join(
                f"\\--- {package}:{'1.0.1' if package + ':1.0.1' in text else '1.0.0'}"
                for package in dict.fromkeys(packages)
            )
            if "dependencies" in argv
            else 'openjdk version "25.0.1"'
            if argv[0] == "java"
            else "Tests: 2 passed"
        )
        if "assemble" in argv:
            assert dialog.close.await_count == 1
        return CommandResult(
            argv,
            int(failed),
            output,
            "Offending update" if failed else "",
            0,
            False,
            "",
            "",
        )

    runner.run.side_effect = execute
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved",
        affected=True,
        fixed_versions=["1.0.1"],
        lowest_fixed_version="1.0.1",
    )
    engine = Engine(
        tmp_path,
        runner=runner,
        gitlab=Mock(),
        advisory=advisory,
        docs=documentation_client(),
        which=lambda name: name,
    )
    engine.git = Mock()
    engine.git.staged_names.return_value = []
    engine.git.diff_summary.return_value = {
        "stat": "build.gradle",
        "files": "build.gradle",
    }
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [
        {
            "id": str(index),
            "component": package,
            "category": "dependency_scanning",
            "installedVersion": "1.0.0",
            "identifiers": ["CVE-TEST"],
            "location": {"file": "build.gradle"},
        }
        for index, package in enumerate(packages)
    ]
    for finding in engine.state.findings:
        assert (
            engine.verify_security_finding(finding["id"])["decision"]
            == "CHANGE_REQUIRED"
        )
    reviews = {
        str(index): _review(package, "Maven") for index, package in enumerate(packages)
    }
    if outcome == "blocked_review":
        for finding_id in ("0", "1"):
            reviews[finding_id] = {
                "ecosystem": "Maven",
                "package": "example:library",
                "target": "1.0.1",
                "blocked_reason": "Compatibility could not be established for this target.",
            }
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    if outcome == "docs":
        apply = engine.apply_minimal_fix

        def documentation_gate(finding_id):
            """Keep an unavailable publisher receipt from stopping unrelated safe updates."""
            if finding_id in {"0", "1"}:
                return {
                    "status": "DOCS_REQUIRED",
                    "reason": "Publisher receipt unavailable.",
                }
            return apply(finding_id)

        monkeypatch.setattr(engine, "apply_minimal_fix", documentation_gate)
    opened = AsyncMock(return_value=dialog)
    monkeypatch.setattr(server.desktop_approval, "open_dialog", opened)
    ctx = Mock()
    ctx.protocol_version = "2025-11-25"

    async def exercise():
        """Submit the checkbox response without making another host/tool request."""
        answer = asyncio.Event()

        async def wait():
            """Release only after confirming that opening the form made no edits."""
            await answer.wait()
            return {
                "action": "accept",
                "content": {
                    "finding_0": True,
                    "finding_1": True,
                    "finding_2": True,
                },
            }

        async def submit(initial):
            """Release the human response only after the actual tool call has ended."""
            assert initial["status"] == "AWAITING_HUMAN", initial
            task = server._desktop_fix_selection_tasks[initial["request_id"]]
            assert manifest.read_text() == original
            if outcome == "checkout_changed":
                (tmp_path / "Changed.java").write_text("class Changed {}")
            answer.set()
            await task

        dialog.wait = wait
        if outcome == "mcp":
            async with create_client_server_memory_streams() as (client, remote):
                async with anyio.create_task_group() as tasks:
                    lowlevel = server.mcp._lowlevel_server
                    tasks.start_soon(
                        partial(
                            lowlevel.run,
                            *remote,
                            lowlevel.create_initialization_options(),
                        )
                    )
                    async with ClientSession(*client) as session:
                        await session.initialize()
                        initial = await session.call_tool(
                            "select_security_fixes",
                            {"repo_root": str(tmp_path), "package_reviews": reviews},
                        )
                        await submit(initial.structured_content)
                    tasks.cancel_scope.cancel()
        else:
            initial = await server.select_security_fixes(
                ctx, str(tmp_path), package_reviews=reviews
            )
            await submit(initial)

    # Act
    asyncio.run(exercise())

    # Assert
    execution = engine.state.fix_selection["package_execution"]
    assert (
        execution["status"]
        == {
            "success": "COMPLETED",
            "mcp": "COMPLETED",
            "build": "PARTIAL_FAILURE",
            "test": "PARTIAL_FAILURE",
            "checkout_changed": "BLOCKED",
            "blocked_review": "PARTIAL_FAILURE",
            "docs": "PARTIAL_FAILURE",
        }[outcome]
    ), execution
    text = manifest.read_text()
    assert ("example:library:1.0.1" in text) == (outcome in {"success", "mcp"})
    assert ("example:codec:1.0.1" in text) == (outcome != "checkout_changed")
    assert "example:unchecked:1.0.1" not in text
    assert engine.state.json_report_path
    if outcome != "checkout_changed":
        assert engine.state.validation_status == "VALIDATION_COMPLETE"
    if outcome in {"success", "mcp"}:
        calls = [call.args[0] for call in runner.run.call_args_list]
        assert sum("assemble" in argv for argv in calls) == 1
        assert sum("test" in argv for argv in calls) == 1
        assert sum("dependencies" in argv for argv in calls) == (2 if modern else 3)
        assert engine.state.changes[1]["reused_from"] == "0"
        assert all(change["edit_duration_ms"] >= 0 for change in engine.state.changes)
        assert all(step["duration_ms"] >= 0 for step in execution["results"])
        report = next((tmp_path / ".security-mcp" / "reports").glob("*.md")).read_text(
            encoding="utf-8"
        )
        assert "Edit/reuse and lockfile refresh:" in report
        assert " ms)" in report
    opened.assert_awaited_once()
    if outcome == "blocked_review":
        assert opened.call_args.args[1]["finding_0"]["title"].startswith("BLOCKED")
        assert (
            "Compatibility could not be established"
            in opened.call_args.args[1]["finding_0"]["summary"]
        )
    dialog.close.assert_awaited_once()
    engine.gitlab.dismiss_false_positive.assert_not_called()
    assert not server._desktop_fix_selection_tasks


@pytest.mark.parametrize("manager", ["nuget", "gradle", "maven"])
@pytest.mark.parametrize("failed_check", ["build", "test"])
def test_cross_stack_failure_reverts_only_offending_update(
    tmp_path, manager, failed_check
):
    """Keep the other package when an update breaks either the build or unit tests."""
    # Arrange
    packages = (
        ("Example", "Other")
        if manager == "nuget"
        else ("example:library", "other:library")
    )
    filename = {"nuget": "App.csproj", "gradle": "build.gradle", "maven": "pom.xml"}[
        manager
    ]
    original = {
        "nuget": '<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Example" Version="1.0.0"/><PackageReference Include="Other" Version="1.0.0"/></ItemGroup></Project>',
        "gradle": "dependencies {\n implementation 'example:library:1.0.0'\n implementation 'other:library:1.0.0'\n}\n",
        "maven": "<project><dependencies><dependency><groupId>example</groupId><artifactId>library</artifactId><version>1.0.0</version></dependency><dependency><groupId>other</groupId><artifactId>library</artifactId><version>1.0.0</version></dependency></dependencies></project>",
    }[manager]
    manifest = tmp_path / filename
    manifest.write_text(original)
    runner = Mock()

    def execute(argv, **kwargs):
        """Fail only one updated coordinate and the selected validation stage."""
        assert_allowed(argv, tmp_path)
        text = manifest.read_text()
        bad = {
            "nuget": 'Include="Example" Version="1.0.1"' in text,
            "gradle": "'example:library:1.0.1'" in text,
            "maven": "<groupId>example</groupId><artifactId>library</artifactId><version>1.0.1</version>"
            in text,
        }[manager]
        stage = (
            "test"
            if "test" in argv
            else "build"
            if ("build" in argv or "assemble" in argv)
            else None
        )
        if "verify" in argv:
            stage = failed_check
        failed = bad and stage == failed_check
        output = (
            'openjdk version "25.0.1"'
            if argv[0] == "java"
            else "10.0.100\nTests: 2 passed"
        )
        return CommandResult(
            argv,
            int(failed),
            output,
            "Offending update" if failed else "",
            0,
            False,
            "",
            "",
        )

    runner.run.side_effect = execute
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved",
        affected=True,
        fixed_versions=["1.0.1"],
        lowest_fixed_version="1.0.1",
    )
    engine = Engine(
        tmp_path,
        runner=runner,
        gitlab=Mock(),
        advisory=advisory,
        docs=documentation_client(),
        which=lambda name: name,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [
        {
            "id": str(index),
            "component": package,
            "category": "dependency_scanning",
            "installedVersion": "1.0.0",
            "identifiers": ["CVE-TEST"],
            "location": {"file": filename},
        }
        for index, package in enumerate(packages)
    ]
    for index, package in enumerate(packages):
        finding_id = str(index)
        assert (
            engine.verify_security_finding(finding_id)["decision"] == "CHANGE_REQUIRED"
        )
        qualified = engine.qualify_package_update(
            finding_id, _review(package, "NuGet" if manager == "nuget" else "Maven")
        )
        assert qualified["status"] == "QUALIFIED", qualified
        assert engine.apply_minimal_fix(finding_id)["status"] == "APPLIED"

    # Act
    result = engine.run_validation_matrix()

    # Assert
    assert result["status"] == "VALIDATION_COMPLETE", result
    assert result["retained_updates"] == ["1"]
    assert [item["finding_id"] for item in result["rejected_updates"]] == ["0"]
    assert "1.0.0" in manifest.read_text() and "1.0.1" in manifest.read_text()
    assert not engine.state.manual_cleanup_required


@pytest.mark.parametrize("resolved_version", ["1.0.0", "1.0.1"])
@pytest.mark.parametrize("manager", ["gradle", "maven"])
def test_java_override_requires_actual_resolved_fixed_version(
    tmp_path, resolved_version, manager
):
    """Do not accept a passing build/test if the override left the vulnerable dependency."""
    # Arrange
    filename = "build.gradle" if manager == "gradle" else "pom.xml"
    marker = "resolutionStrategy" if manager == "gradle" else "<dependencyManagement>"
    manifest = tmp_path / filename
    manifest.write_text("dependencies { }\n" if manager == "gradle" else "<project/>")
    if manager == "maven":
        manifest.write_text("<project></project>")
    finding = {
        "id": "transitive",
        "component": "example:library",
        "category": "dependency_scanning",
        "installedVersion": "1.0.0",
        "identifiers": ["CVE-TEST"],
        "location": {"file": filename},
    }
    runner = Mock()

    def execute(argv, **kwargs):
        """Resolve the target only when the simulated dependency resolver honors it."""
        assert_allowed(argv, tmp_path)
        version = resolved_version if marker in manifest.read_text() else "1.0.0"
        output = (
            f"[INFO] \\- example:library:jar:{version}:compile\n"
            if "dependency:tree" in argv
            else f"runtimeClasspath - runtime\n\\--- example:library:{version}\n"
            if "dependencies" in argv
            else 'openjdk version "25.0.1"'
            if argv[0] == "java"
            else "Tests: 2 passed"
        )
        return CommandResult(argv, 0, output, "", 0, False, "", "")

    runner.run.side_effect = execute
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved",
        affected=True,
        fixed_versions=["1.0.1"],
        lowest_fixed_version="1.0.1",
    )
    engine = Engine(
        tmp_path,
        runner=runner,
        gitlab=Mock(),
        advisory=advisory,
        docs=documentation_client(),
        which=lambda name: name,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [deepcopy(finding)]
    assert engine.verify_security_finding("transitive")["decision"] == "CHANGE_REQUIRED"
    assert (
        engine.qualify_package_update(
            "transitive", _review("example:library", "Maven")
        )["status"]
        == "QUALIFIED"
    )
    assert engine.apply_minimal_fix("transitive")["status"] == "APPLIED"

    # Act
    result = engine.run_validation_matrix()

    # Assert
    assert result["status"] == (
        "VALIDATION_COMPLETE" if resolved_version == "1.0.1" else "FIX_REJECTED"
    ), result
    assert (marker in manifest.read_text()) == (resolved_version == "1.0.1")
