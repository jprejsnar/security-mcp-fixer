"""Verify build-only acceptance and configuration-proven Java remediation."""

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
from gitlab_security_mcp.commands import CommandResult, CommandRunner, assert_allowed
from gitlab_security_mcp.engine import Engine, _ValidationRunner
from gitlab_security_mcp.manifests import PackageHit
from gitlab_security_mcp.qualification import run_checks
from gitlab_security_mcp.remediate import apply_plan, plan_remediation
from gitlab_security_mcp.validate import _product_result, run_validation
from tests.conftest import documentation_client, manager_doc_sources


@pytest.mark.parametrize(
    "pin",
    [
        "",
        'configurations.configureEach { resolutionStrategy.force("example:library:1.0.1") }\n',
    ],
)
@pytest.mark.parametrize("configuration", [None, "customRuntimeClasspath"])
def test_unmatched_runtime_dependency_cannot_be_fixed_by_a_pin(
    tmp_path, pin, configuration
):
    """Do not confuse a literal force or an unresolved constraint with remediation."""
    # Arrange
    manifest = tmp_path / "build.gradle"
    manifest.write_text("plugins { id 'java' }\n" + pin)
    inspected = configuration or "runtimeClasspath"
    runner = Mock()
    runner.run.side_effect = lambda argv, **kwargs: CommandResult(
        argv,
        0,
        f"{inspected} - runtime\nNo dependencies\n"
        "testRuntimeClasspath - test\n\\--- example:library:1.0.0 (c)\n"
        "tooling - not resolvable (n)\n\\--- example:library:1.0.0 (n)\n",
        "",
        0,
        False,
        "",
        "",
    )
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved", affected=True, lowest_fixed_version="1.0.1"
    )
    engine = Engine(
        tmp_path,
        runner=runner,
        gitlab=Mock(),
        advisory=advisory,
        which=lambda name: name,
    )
    finding = {
        "id": "runtime-missing",
        "component": "example:library",
        "category": "dependency_scanning",
        "installedVersion": "1.0.0",
        "location": {"file": "build.gradle"},
    }
    if configuration:
        finding["location"]["configuration"] = configuration

    # Act
    decision = engine._decide(finding)

    # Assert
    assert decision[0] == "MANUAL_REVIEW"
    assert decision[3] is None
    assert inspected in decision[1]
    assert "all-configuration dependency report" in decision[1]
    assert (
        "does not mean the requested fixed version is unavailable or incompatible"
        in decision[1]
    )
    assert "Next: inspect the scanner's artifact" in decision[1]
    assert "No update was applied" in decision[1]
    assert manifest.read_text() == "plugins { id 'java' }\n" + pin
    assert runner.run.call_count == 2
    assert runner.run.call_args_list[0].args[0][-2:] == ["--configuration", inspected]
    assert runner.run.call_args.args[0][-1] == "dependencies"


@pytest.mark.parametrize("filename", ["build.gradle", "build.gradle.kts"])
def test_existing_gradle_property_and_policy_row_are_preserved(tmp_path, filename):
    """Update an explicit property and its central row without replacing its source expression."""
    # Arrange
    original = (
        'dependencies { implementation("example:library:${libraryMinVersion}") }\n'
    )
    (tmp_path / filename).write_text(original)
    (tmp_path / "gradle.properties").write_text(
        "libraryMinVersion=1.0.0\notherVersion=7.0.0\n"
    )
    policy = tmp_path / ".github" / "versions.md"
    policy.parent.mkdir()
    policy.write_text(
        "| Pin | Value | Source |\n|---|---|---|\n| libraryMinVersion | `1.0.0` | `gradle.properties` |\n"
    )
    hit = PackageHit(
        "Maven",
        "gradle",
        "example:library",
        "1.0.0",
        "${libraryMinVersion}",
        filename,
        None,
        True,
    )
    plan, reason = plan_remediation(tmp_path, {}, hit, "1.0.1")
    assert plan is not None, reason

    # Act
    result = apply_plan(tmp_path, plan, Mock(), lambda name: name)

    # Assert
    assert result["status"] == "APPLIED"
    assert (tmp_path / filename).read_text() == original
    assert (
        tmp_path / "gradle.properties"
    ).read_text() == "libraryMinVersion=1.0.1\notherVersion=7.0.0\n"
    assert "| libraryMinVersion | `1.0.1` | `gradle.properties` |" in policy.read_text()
    assert set(result["files"]) == {
        filename,
        "gradle.properties",
        ".github/versions.md",
    }


def test_catalog_reference_updates_its_existing_central_policy(tmp_path):
    """Keep the catalog reference and synchronize its explicit version-policy key."""
    # Arrange
    catalog = tmp_path / "gradle" / "libs.versions.toml"
    catalog.parent.mkdir()
    catalog.write_text(
        '[versions]\nlibraryFloor = "1.0.0"\n[libraries]\n'
        'library = { module = "example:library", version.ref = "libraryFloor" }\n'
    )
    policy = tmp_path / ".github" / "versions.md"
    policy.parent.mkdir()
    policy.write_text("| Pin | Value | Source |\n|---|---|---|\n")
    hit = PackageHit(
        "Maven",
        "gradle",
        "example:library",
        "1.0.0",
        "1.0.0",
        "gradle/libs.versions.toml",
        None,
        True,
    )
    plan, reason = plan_remediation(tmp_path, {}, hit, "1.0.1")
    assert plan is not None, reason

    # Act
    result = apply_plan(tmp_path, plan, Mock(), lambda name: name)

    # Assert
    assert result["status"] == "APPLIED"
    assert 'libraryFloor = "1.0.1"' in catalog.read_text()
    assert 'version.ref = "libraryFloor"' in catalog.read_text()
    assert (
        "| libraryFloor | `1.0.1` | `gradle/libs.versions.toml` |" in policy.read_text()
    )
    assert set(plan.files) == {"gradle/libs.versions.toml", ".github/versions.md"}


@pytest.mark.parametrize(
    "manager,ecosystem,filename",
    [
        ("gradle", "Maven", "build.gradle"),
        ("pnpm", "npm", "package.json"),
        ("nuget", "NuGet", "app.csproj"),
    ],
)
def test_manager_documentation_outage_blocks_edits(
    tmp_path, manager, ecosystem, filename
):
    """Require each relevant publisher page, not merely language home pages."""
    # Arrange
    from gitlab_security_mcp.official_docs import manager_documentation

    plan = {"manager": manager, "ecosystem": ecosystem, "files": [filename]}
    required = manager_documentation(plan)
    docs = documentation_client({required[0]: "unavailable"})

    # Act
    result = docs.read_before_fix({"proposedFix": plan})

    # Assert
    assert not result.complete
    assert any(
        item.url == required[0] and item.required and not item.ok
        for item in result.sources
    )
    assert set(required) <= {item.url for item in result.sources}


@pytest.mark.parametrize(
    "scripts",
    [
        {"build": "vitest run"},
        {"build": "vite build", "prebuild": "npm test"},
        {"build": "vite build", "postbuild": "node --test"},
        {"build": "pnpm run compile", "compile": "jest --runInBand"},
    ],
)
def test_build_scripts_cannot_sneak_in_test_execution(tmp_path, monkeypatch, scripts):
    """Block known direct, nested and lifecycle test commands before any child starts."""
    # Arrange
    import json

    (tmp_path / "package.json").write_text(json.dumps({"scripts": scripts}))
    launch = Mock()
    monkeypatch.setattr("gitlab_security_mcp.commands.subprocess.Popen", launch)
    runner = CommandRunner(tmp_path)

    # Act
    with pytest.raises(PermissionError, match="Tests are disabled"):
        runner.run(["pnpm", "run", "build"], timeout=30)
    # Assert
    launch.assert_not_called()


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
def test_gradle_policy_reuses_production_build_without_tests(tmp_path, version):
    """Share a production build and explicitly skip legacy unit-check policies."""
    # Arrange
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }\n")
    if version is not None:
        _gradle_wrapper(tmp_path, version)

    def execute(argv, **kwargs):
        """Reject scheduling a test task while permitting its explicit exclusion."""
        assert_allowed(argv, tmp_path)
        assert "test" not in argv or argv[-2:] == ["-x", "test"]
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
                "argv": [tool, "--no-daemon", "assemble", "-x", "test"],
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
    assert checks[0]["status"] == "PASSED"
    assert checks[1]["status"] == "SKIPPED"
    assert not checks[1]["required"]
    gradle_calls = [
        call.args[0]
        for call in underlying.run.call_args_list
        if call.args[0][0] == tool
    ]
    assert len(gradle_calls) == 1
    assert gradle_calls[0][1:] == ["--no-daemon", "assemble", "-x", "test"]


@pytest.mark.parametrize("mode", ["fresh", "stale", "empty", "failed", "invalid"])
@pytest.mark.parametrize("modern", [False, True])
def test_gradle_build_does_not_execute_or_require_tests(tmp_path, mode, modern):
    """Do not execute tests or make production acceptance depend on test reports."""
    # Arrange
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }\n")
    if modern:
        _gradle_wrapper(tmp_path, "9.9.0")
    report = tmp_path / "build" / "test-results" / "test" / "TEST-App.xml"
    report.parent.mkdir(parents=True)
    if mode == "stale":
        report.write_text('<testsuite tests="4" failures="0" errors="0"/>')

    def execute(argv, **kwargs):
        """Produce build results without scheduling any test task."""
        assert_allowed(argv, tmp_path)
        assert "test" not in argv or argv[-2:] == ["-x", "test"]
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
    assert result["status"] == "VALIDATION_COMPLETE"
    assert "DISABLED" in result["test_execution"]


@pytest.mark.parametrize(
    "filename,manager,original,expected",
    [
        (
            "build.gradle",
            "gradle",
            "dependencies { implementation platform('bom:app:1') }\n",
            'add("implementation", "example:library")',
        ),
        (
            "build.gradle.kts",
            "gradle",
            'dependencies { implementation(platform("bom:app:1")) }\n',
            'add("implementation", "example:library")',
        ),
        (
            "pom.xml",
            "maven",
            "<project><dependencies><dependency><groupId>bom</groupId><artifactId>app</artifactId><version>1</version></dependency></dependencies></project>",
            "<artifactId>library</artifactId>",
        ),
        (
            "build.gradle",
            "gradle",
            "dependencies { implementation enforcedPlatform('bom:app:1') }\n",
            "configurations.configureEach",
        ),
        (
            "build.gradle.kts",
            "gradle",
            'dependencies { implementation(enforcedPlatform("bom:app:1")) }\n',
            "configurations.configureEach",
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
    if "enforcedPlatform" in original:
        assert plan.as_dict()["gradle_force"] is True
        assert "resolutionStrategy.force" in path.read_text()
        assert "strictly(" not in path.read_text()
        assert "Runtime compatibility with the platform remains unverified" in plan.description
    assert (
        ("bom:app:1" in path.read_text())
        if manager == "gradle"
        else ("<artifactId>app</artifactId><version>1</version>" in path.read_text())
    )
    assert result["files"] == (
        [filename, "gradle.properties"] if manager == "gradle" else [filename]
    )


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("force", [False, True])
def test_duplicate_gradle_override_preserves_owned_block_and_line_endings(
    tmp_path, newline, force
):
    original = "plugins { id 'java' }\n"
    if force:
        original += 'dependencies { implementation(enforcedPlatform("bom:app:1")) }\n'
    path = tmp_path / "build.gradle"
    path.write_bytes(original.replace("\n", newline).encode())
    hit = PackageHit(
        "Maven", "gradle", "example:library", "1.0.0", None, "build.gradle", None, False
    )
    plan, reason = plan_remediation(tmp_path, {}, hit, "1.0.1")
    assert plan is not None, reason

    assert apply_plan(tmp_path, plan, Mock(), lambda name: name)["status"] == "APPLIED"
    first = path.read_bytes()
    assert apply_plan(tmp_path, plan, Mock(), lambda name: name)["status"] == "APPLIED"

    assert path.read_bytes() == first
    assert first.count(b"// security-mcp:start") == 1
    assert b"\n" not in first.replace(newline.encode(), b"")


@pytest.mark.parametrize(
    "source",
    [
        "// implementation enforcedPlatform('bom:app:1')\n",
        "/* dependencies {\n implementation enforcedPlatform('bom:app:1')\n} */\n",
        'description = "An enforcedPlatform(example) example"\n',
        'description = """\nimplementation enforcedPlatform("bom:app:1")\n"""\n',
        "description = '''\nimplementation enforcedPlatform('bom:app:1')\n'''\n",
    ],
)
def test_quoted_or_commented_platform_does_not_change_override_strategy(tmp_path, source):
    """Do not introduce a broader force because documentation mentions a platform."""
    manifest = tmp_path / "build.gradle"
    manifest.write_text(source)
    hit = PackageHit("Maven", "gradle", "example:library", "1.0.0", None, manifest.name, None, False)

    plan, reason = plan_remediation(tmp_path, {}, hit, "1.0.1")

    assert plan is not None, reason
    assert not plan.gradle_force


def _review(package, ecosystem):
    """Supply explicit fixture documentation and license review, not corporate approval."""
    return {
        "ecosystem": ecosystem,
        "package": package,
        "target": "1.0.1",
        "documentation": {
            "complete": True,
            "sources": ["https://example.test/docs", *manager_doc_sources()],
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


@pytest.mark.parametrize("invalid", ["target", "license", "documentation", "blocked"])
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
    if invalid == "documentation":
        review["documentation"]["sources"] = ["https://example.test/docs"]
    elif invalid == "blocked":
        review = {key: review[key] for key in ("ecosystem", "package", "target")}
        review["blocked_reason"] = "blocked: no supported update is available"
    elif invalid == "target":
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
    "invalid",
    [
        "compatible",
        "compatible_without_code_changes",
        "known_incompatibilities",
        "source_fixes",
        "compatibility_limitations",
    ],
)
def test_build_only_trial_cannot_hide_known_breakage_or_missing_evidence(invalid):
    """Uncertainty permits a disclosed trial, never a known break or missing review."""
    # Arrange
    from gitlab_security_mcp.qualification import review_package

    review = _review("example:library", "Maven")
    review.update(
        validation_mode="build_only",
        compatible=None,
        compatible_without_code_changes=None,
        known_incompatibilities=[],
        compatibility_limitations="Transitive runtime callers are unverified.",
    )
    review[invalid] = (
        False
        if invalid in {"compatible", "compatible_without_code_changes"}
        else ["known caller change"]
        if invalid in {"known_incompatibilities", "source_fixes"}
        else ""
    )

    # Act
    with pytest.raises(ValueError):
        review_package(review)

    # Assert
    assert review["validation_mode"] == "build_only"


@pytest.mark.parametrize("installed,target", [("1.0.0", "2.0.0"), (None, "1.0.1")])
def test_build_only_trial_requires_known_nonmajor_versions(tmp_path, installed, target):
    """Do not bypass major-upgrade review or guess an unknown upgrade size."""
    # Arrange
    from gitlab_security_mcp.qualification import review_major_upgrade

    review = {"validation_mode": "build_only"}
    plan = {"installed": installed, "target": target}

    # Act
    with pytest.raises(ValueError):
        review_major_upgrade(tmp_path, plan, review)

    # Assert
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "outcome",
    [
        "success",
        "mcp",
        "build",
        "codec_build",
        "enforced_platform",
        "resolution",
        "checkout_changed",
        "blocked_review",
        "blocked_tamper",
        "build_only",
        "build_only_failure",
        "docs",
    ],
)
@pytest.mark.parametrize("modern", [False, True])
def test_native_approval_automatically_updates_selected_gradle_packages(
    tmp_path, monkeypatch, outcome, modern
):
    """Reproduce three checked findings: edit two coordinates, validate, and save actual outcomes."""
    # Arrange
    manifest = tmp_path / "build.gradle"
    original = "plugins { id 'java' }\ndependencies { }\n"
    if outcome == "enforced_platform":
        original += 'dependencies { implementation(enforcedPlatform("bom:app:1")) }\n'
    manifest.write_text(original)
    properties = tmp_path / "gradle.properties"
    properties.write_text("unrelatedPin=7.0.0\n")
    policy = tmp_path / ".github" / "versions.md"
    policy.parent.mkdir()
    policy.write_text("| Pin | Value | Source |\n|---|---|---|\n")
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
        pins = properties.read_text()
        bad = "securityMcp.example.library.version=1.0.1" in pins
        failed = "assemble" in argv and (
            (bad and outcome in {"build", "build_only_failure"})
            or (outcome == "codec_build" and "securityMcp.example.codec.version=1.0.1" in pins)
        )
        output = (
            "runtimeClasspath - runtime\n"
            + "\n".join(
                f"\\--- {package}:{'1.0.1' if 'securityMcp.' + package.replace(':', '.') + '.version=1.0.1' in pins and not (outcome == 'resolution' and package == 'example:library') else '1.0.0'}"
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
    if outcome in {"blocked_review", "blocked_tamper"}:
        for finding_id in ("0", "1"):
            reviews[finding_id] = {
                "ecosystem": "Maven",
                "package": "example:library",
                "target": "1.0.1",
                "blocked_reason": "Compatibility could not be established for this target.",
            }
    if outcome in {"build_only", "build_only_failure"}:
        for finding_id in ("0", "1"):
            reviews[finding_id].update(
                validation_mode="build_only",
                compatible=None,
                compatible_without_code_changes=None,
                known_incompatibilities=[],
                compatibility_limitations="Transitive runtime behavior is unverified.",
            )
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
                    "finding_0": outcome != "blocked_review",
                    "finding_1": outcome != "blocked_review",
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
    if outcome == "blocked_tamper":
        assert engine.state.fix_selection["status"] == "INVALID"
        assert engine.state.fix_selection["selected_ids"] == []
        assert not engine.state.changes
        assert manifest.read_text() == original
        assert not any("assemble" in call.args[0] for call in runner.run.call_args_list)
        dialog.close.assert_awaited_once()
        return
    execution = engine.state.fix_selection["package_execution"]
    assert (
        execution["status"]
        == {
            "success": "COMPLETED",
            "mcp": "COMPLETED",
            "build": "PARTIAL_FAILURE",
            "codec_build": "PARTIAL_FAILURE",
            "enforced_platform": "COMPLETED",
            "resolution": "PARTIAL_FAILURE",
            "checkout_changed": "BLOCKED",
            "blocked_review": "COMPLETED",
            "build_only": "COMPLETED",
            "build_only_failure": "PARTIAL_FAILURE",
            "docs": "PARTIAL_FAILURE",
        }[outcome]
    ), execution
    text = manifest.read_text()
    pins = properties.read_text()
    assert ("securityMcp.example.library.version=1.0.1" in pins) == (
        outcome in {"success", "mcp", "build_only", "codec_build", "enforced_platform"}
    )
    assert ("securityMcp.example.codec.version=1.0.1" in pins) == (
        outcome not in {"checkout_changed", "codec_build"}
    )
    assert "example:unchecked" not in text
    assert "unrelatedPin=7.0.0" in pins
    if outcome in {"success", "mcp", "build_only", "codec_build", "enforced_platform"}:
        assert (
            "| securityMcp.example.library.version | `1.0.1` | `gradle.properties` |"
            in policy.read_text()
        )
    assert engine.state.json_report_path
    if outcome != "checkout_changed":
        assert engine.state.validation_status == "VALIDATION_COMPLETE"
    if outcome == "codec_build":
        calls = [call.args[0] for call in runner.run.call_args_list]
        assert sum("assemble" in argv for argv in calls) == 2
        assert engine.state.batch_isolation[-1]["finding_ids"] == ["0", "1"]
        assert [change["status"] for change in engine.state.changes] == ["APPLIED", "APPLIED", "ROLLED_BACK"]
    if outcome == "enforced_platform":
        assert "configurations.configureEach" in text
        assert "resolutionStrategy.force" in text
        assert "strictly(" not in text
    if outcome in {"success", "mcp", "build_only", "enforced_platform"}:
        calls = [call.args[0] for call in runner.run.call_args_list]
        assert sum("assemble" in argv for argv in calls) == 1
        assert all("test" not in argv or argv[-2:] == ["-x", "test"] for argv in calls)
        assert sum("dependencies" in argv for argv in calls) == 2
        assert engine.state.changes[1]["reused_from"] == "0"
        assert all(change["edit_duration_ms"] >= 0 for change in engine.state.changes)
        assert all(step["duration_ms"] >= 0 for step in execution["results"])
        report = next((tmp_path / ".security-mcp" / "reports").glob("*.md")).read_text(
            encoding="utf-8"
        )
        assert "Edit/reuse and lockfile refresh:" in report
        assert " ms)" in report
        if outcome == "build_only":
            assert "runtime/test compatibility was not verified" in report
            assert reviews["0"]["compatible"] is None
    opened.assert_awaited_once()
    if outcome == "blocked_review":
        assert opened.call_args.args[1]["finding_0"]["title"].startswith("BLOCKED")
        assert opened.call_args.args[1]["finding_0"]["enabled"] is False
        assert (
            "Compatibility could not be established"
            in opened.call_args.args[1]["finding_0"]["summary"]
        )
    if outcome == "build_only":
        assert opened.call_args.args[1]["finding_0"]["title"].startswith(
            "BUILD-ONLY TRIAL"
        )
        assert (
            "Transitive runtime behavior is unverified"
            in opened.call_args.args[1]["finding_0"]["summary"]
        )
    dialog.close.assert_awaited_once()
    engine.gitlab.dismiss_false_positive.assert_not_called()
    assert not server._desktop_fix_selection_tasks


@pytest.mark.parametrize("manager", ["nuget", "gradle", "maven"])
@pytest.mark.parametrize("failed_check", ["build"])
def test_cross_stack_failure_reverts_only_offending_update(
    tmp_path, manager, failed_check
):
    """Keep the other package when an update breaks the production build."""
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
            "build"
            if any(task in argv for task in ("build", "assemble", "package"))
            else None
        )
        failed = bad and stage == failed_check
        output = (
            "runtimeClasspath - runtime\n"
            + "\n".join(
                f"\\--- {package}:{'1.0.1' if package + ':1.0.1' in text else '1.0.0'}"
                for package in packages
            )
            if "dependencies" in argv
            else 'openjdk version "25.0.1"'
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


@pytest.mark.parametrize("resolved_version", ["1.0.0", "1.0.1", None])
@pytest.mark.parametrize(
    "manager,filename,configuration",
    [
        ("gradle", "build.gradle", "runtimeClasspath"),
        ("gradle", "build.gradle", "checkstyle"),
        ("gradle", "build.gradle.kts", "checkstyle"),
        ("gradle", "build.gradle", "testRuntimeClasspath"),
        ("maven", "pom.xml", None),
    ],
)
def test_java_override_requires_actual_resolved_fixed_version(
    tmp_path, resolved_version, manager, filename, configuration
):
    """Find non-runtime dependencies and reject ineffective or disappearing overrides."""
    # Arrange
    marker = (
        "// security-mcp:start" if manager == "gradle" else "<dependencyManagement>"
    )
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
        dependencies = f"{configuration} - selected classpath\n" + (
            f"\\--- example:library:{version}\n" if version else "No dependencies\n"
        )
        if configuration not in {None, "runtimeClasspath"}:
            dependencies = (
                "runtimeClasspath - runtime\nNo dependencies\n"
                + dependencies
                + "securityAnalysis - another affected classpath\n"
                + f"\\--- example:library:{version or '1.0.1'}\n"
            )
            if "--configuration" in argv:
                dependencies = "runtimeClasspath - runtime\nNo dependencies\n"
        output = (
            f"[INFO] \\- example:library:jar:{version}:compile\n"
            if "dependency:tree" in argv
            else dependencies
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
    if configuration not in {None, "runtimeClasspath"}:
        assert f'configurations.named("{configuration}")' in manifest.read_text()
        assert 'configurations.named("securityAnalysis")' in manifest.read_text()
        assert "resolutionStrategy.force" in manifest.read_text()
        assert "strictly(" not in manifest.read_text()
        assert (
            "securityMcp.example.library.version=1.0.1"
            in (tmp_path / "gradle.properties").read_text()
        )

    # Act
    result = engine.run_validation_matrix()

    # Assert
    assert result["status"] == (
        "VALIDATION_COMPLETE" if resolved_version == "1.0.1" else "FIX_REJECTED"
    ), result
    assert (marker in manifest.read_text()) == (resolved_version == "1.0.1")


def test_non_runtime_catalog_dependency_overrides_the_owning_build(tmp_path):
    """Keep the catalog intact when a discovered tooling dependency needs a scoped rule."""
    # Arrange
    catalog = tmp_path / "gradle" / "libs.versions.toml"
    catalog.parent.mkdir()
    original = (
        '[versions]\nlibraryFloor = "1.0.0"\n[libraries]\n'
        'library = { module = "example:library", version.ref = "libraryFloor" }\n'
    )
    catalog.write_text(original)
    build = tmp_path / "build.gradle"
    build.write_text("plugins { id 'java' }\n")
    hit = PackageHit(
        "Maven",
        "gradle",
        "example:library",
        "1.0.0",
        "1.0.0",
        "gradle/libs.versions.toml",
        None,
        True,
        configuration_versions={"checkstyle": ["1.0.0"]},
    )
    finding = {"dependencyResolution": {"manifest": "build.gradle"}}
    plan, reason = plan_remediation(tmp_path, finding, hit, "1.0.1")
    assert plan is not None, reason

    # Act
    result = apply_plan(tmp_path, plan, Mock(), lambda name: name)

    # Assert
    assert result["status"] == "APPLIED"
    assert plan.files == ["build.gradle", "gradle.properties"]
    assert plan.as_dict()["gradle_configurations"] == ["checkstyle"]
    assert 'configurations.named("checkstyle")' in build.read_text()
    assert "resolutionStrategy.force" in build.read_text()
    assert catalog.read_text() == original


@pytest.mark.parametrize("failure", ["none", "first", "all"])
def test_version_alignment_follows_selective_package_rollback(tmp_path, failure):
    """Keep AI documentation aligned to retained versions when another update fails."""
    # Arrange
    from gitlab_security_mcp.report import render

    updates = [("bad:library", "1.0.0", "1.0.1"), ("good:library", "2.0.0", "2.0.1")]
    manifest = tmp_path / "build.gradle"
    manifest.write_text(
        "dependencies {\n"
        + "".join(
            f" implementation '{package}:{old}'\n" for package, old, _target in updates
        )
        + "}\n",
        encoding="utf-8",
    )
    document = tmp_path / ".github" / "instructions" / "versions.instructions.md"
    document.parent.mkdir(parents=True)
    document.write_text("bad:library 1.0.0\ngood:library 2.0.0\n", encoding="utf-8")
    runner, advisory = Mock(), Mock()

    def execute(argv, **kwargs):
        """Build the actual edits and reject only the first updated dependency."""
        assert_allowed(argv, tmp_path)
        text = manifest.read_text(encoding="utf-8")
        failed = "assemble" in argv and (
            (failure in {"first", "all"} and "bad:library:1.0.1" in text)
            or (failure == "all" and "good:library:2.0.1" in text)
        )
        output = (
            "runtimeClasspath - runtime\n"
            + "".join(
                f"\\--- {package}:{target if package + ':' + target in text else old}\n"
                for package, old, target in updates
            )
            if "dependencies" in argv
            else 'openjdk version "25.0.1"'
            if argv[0] == "java"
            else "BUILD SUCCESSFUL"
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

    def lookup(finding, *_args):
        """Supply the exact fixed version for each independent package."""
        target = updates[int(finding["id"])][2]
        return AdvisoryLookup(
            outcome="resolved",
            affected=True,
            fixed_versions=[target],
            lowest_fixed_version=target,
        )

    runner.run.side_effect = execute
    advisory.lookup.side_effect = lookup
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
            "installedVersion": old,
            "identifiers": ["CVE-TEST"],
            "location": {"file": "build.gradle"},
        }
        for index, (package, old, _target) in enumerate(updates)
    ]
    for index, (package, _old, target) in enumerate(updates):
        finding_id = str(index)
        assert (
            engine.verify_security_finding(finding_id)["decision"] == "CHANGE_REQUIRED"
        )
        review = {**_review(package, "Maven"), "target": target}
        assert (
            engine.qualify_package_update(finding_id, review)["status"] == "QUALIFIED"
        )
        assert engine.apply_minimal_fix(finding_id)["status"] == "APPLIED"
    document.write_text("bad:library 1.0.1\ngood:library 2.0.1\n", encoding="utf-8")

    # Act
    result = engine.run_validation_matrix()

    # Assert
    assert result["status"] == (
        "FIX_REJECTED" if failure == "all" else "VALIDATION_COMPLETE"
    ), result
    assert document.read_text() == (
        f"bad:library {'1.0.1' if failure == 'none' else '1.0.0'}\n"
        f"good:library {'2.0.0' if failure == 'all' else '2.0.1'}\n"
    )
    assert ("good:library:2.0.1" in manifest.read_text()) == (failure != "all")
    assert ("bad:library:1.0.0" in manifest.read_text()) == (failure != "none")
    assert not engine.state.manual_cleanup_required
    if failure == "first":
        assert result["retained_updates"] == ["1"]
    if failure != "all":
        payload, markdown = render(engine.state, staged=[], diff_stat="", diff_files="")
        assert payload["package_qualifications"]["1"]["version_alignment_files"] == [
            ".github/instructions/versions.instructions.md"
        ]
        assert "Version-only AI alignment documents:" in markdown
