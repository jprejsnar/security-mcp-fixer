"""Check corporate approval, compatibility attestations, and bounded edits."""

import json
from copy import deepcopy
from subprocess import TimeoutExpired

import pytest

from gitlab_security_mcp.advisory import AdvisoryLookup
from gitlab_security_mcp.commands import CommandResult, assert_allowed
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.qualification import (
    load_policy,
    review_package,
    run_checks,
    tree_snapshot,
    validate_edits,
)


@pytest.fixture
def package_policy(tmp_path):
    """Supply a test-only policy, never an actual corporate license approval."""
    policy = {
        "schema_version": 1,
        "approvals": [
            {
                "ecosystem": "npm",
                "package": "example",
                "target": "1.0.1",
                "license_expression": "MIT",
                "approved_by": "Test Legal",
                "approval_reference": "TEST-ONLY",
                "obligations": "Retain notices",
                "commercial_distribution_approved": True,
                "no_license_fees": True,
                "license_sources": ["https://example.test/license"],
            }
        ],
        "checks": {
            "npm": {
                "build": {
                    "argv": ["npm", "run", "build"],
                    "success_marker": "CHECK_PASSED",
                },
                "unit_tests": {
                    "argv": ["npm", "test"],
                    "success_marker": "CHECK_PASSED",
                },
                "runtime": {
                    "argv": ["npm", "run", "security:smoke"],
                    "success_marker": "CHECK_PASSED",
                },
                "license_audit": {
                    "argv": ["npm", "run", "security:licenses"],
                    "success_marker": "CHECK_PASSED",
                },
            }
        },
    }
    path = tmp_path / ".security-mcp" / "package-update-policy.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(policy), encoding="utf-8")
    plan = {
        "ecosystem": "npm",
        "package": "example",
        "target": "1.0.1",
        "manager": "npm",
    }
    return path, policy, plan


@pytest.fixture
def package_engine(tmp_path, package_policy):
    """Use real local edits with mocked product commands and advisory evidence."""
    from unittest.mock import Mock

    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"example": "1.0.0"},
                "scripts": {
                    name: "fixture"
                    for name in ("build", "test", "security:smoke", "security:licenses")
                },
            }
        ),
        encoding="utf-8",
    )
    finding = {
        "id": "package",
        "category": "dependency_scanning",
        "component": "example",
        "installedVersion": "1.0.0",
        "identifiers": ["CVE-TEST"],
    }
    runner = Mock()
    runner.run.return_value = CommandResult(
        [], 0, "CHECK_PASSED", "", 0, False, "out", "err"
    )
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved",
        affected=True,
        fixed_versions=["1.0.1"],
        lowest_fixed_version="1.0.1",
    )
    engine = Engine(
        tmp_path,
        advisory=advisory,
        gitlab=Mock(),
        runner=runner,
        which=lambda name: name,
    )
    engine.package_policy_path = package_policy[0]
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]
    engine.verify_security_finding("package")
    return engine


@pytest.fixture
def package_review():
    """Provide explicit documentation and runtime compatibility attestations."""
    return {
        "ecosystem": "npm",
        "package": "example",
        "target": "1.0.1",
        "documentation": {
            "complete": True,
            "sources": ["https://example.test/docs"],
            "summary": "Reviewed API and release notes",
        },
        "compatible": True,
        "api_changes": "No caller changes required",
        "frameworks": [
            {
                "name": "Node",
                "version": "24",
                "source_url": "https://example.test/support",
                "assessment": "Supported",
            }
        ],
        "source_fixes": [],
    }


@pytest.mark.parametrize(
    "key,value",
    [
        ("target", "1.0.2"),
        ("package", "other"),
        ("ecosystem", "NuGet"),
        ("commercial_distribution_approved", False),
        ("commercial_distribution_approved", "true"),
        ("no_license_fees", False),
        ("license_expression", ""),
        ("approved_by", ""),
        ("approval_reference", ""),
        ("obligations", ""),
        ("license_sources", []),
        ("license_expression", "UNLICENSED"),
        ("license_expression", "UNKNOWN"),
        ("license_sources", ["http://example.test/license"]),
    ],
)
def test_unapproved_license_or_version_is_refused(tmp_path, package_policy, key, value):
    """Require a policy entry rather than advisory or approval placeholders."""
    # Arrange
    path, policy, plan = package_policy
    policy["approvals"][0][key] = value
    path.write_text(json.dumps(policy), encoding="utf-8")

    # Act / Assert
    with pytest.raises(ValueError):
        load_policy(tmp_path, path, plan)


@pytest.mark.parametrize(
    "field,value",
    [
        ("compatible", False),
        ("frameworks", []),
        ("api_changes", ""),
        ("source_fixes", None),
    ],
)
def test_unknown_or_breaking_compatibility_is_refused(
    tmp_path, package_review, field, value
):
    """Never infer framework compatibility from a same-major version bump."""
    # Arrange
    package_review[field] = value

    # Act / Assert
    with pytest.raises(ValueError):
        review_package(tmp_path, package_review)


@pytest.mark.parametrize(
    "failure",
    [
        OSError("Tool disappeared"),
        RuntimeError("Reader failed"),
        TimeoutExpired("npm", 30),
    ],
)
def test_check_execution_errors_retain_all_required_results(
    tmp_path, package_policy, failure
):
    """Record execution failures without losing the remaining check evidence."""
    # Arrange
    from unittest.mock import Mock

    checks = package_policy[1]["checks"]["npm"]
    runner = Mock()
    passed = CommandResult([], 0, "CHECK_PASSED", "", 0, False, "out", "err")
    runner.run.side_effect = [failure, passed, passed, passed]

    # Act
    rows = run_checks(tmp_path, checks, runner, lambda name: name, 30)

    # Assert
    assert [row["status"] for row in rows] == ["FAILED", "PASSED", "PASSED", "PASSED"]
    assert rows[0]["required"] is True
    assert str(failure) in rows[0]["detail"]
    assert rows[0]["kind"] == "build"
    assert runner.run.call_count == 4


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt(), SystemExit()])
def test_qualification_does_not_swallow_process_interrupts(
    tmp_path, package_policy, interrupt
):
    """Let shutdown signals propagate instead of treating them as check failures."""
    # Arrange
    from unittest.mock import Mock

    runner = Mock()
    runner.run.side_effect = interrupt

    # Act / Assert
    with pytest.raises(type(interrupt)):
        run_checks(
            tmp_path, package_policy[1]["checks"]["npm"], runner, lambda name: name, 30
        )
    assert runner.run.call_count == 1


@pytest.mark.parametrize("oversized", [False, True])
def test_bounded_reads_close_streams_and_limit_allocation(
    tmp_path, monkeypatch, oversized
):
    """Bound actual read sizes and close the descriptor before size errors."""
    # Arrange
    from io import BytesIO
    from pathlib import Path

    from gitlab_security_mcp.qualification import _read_bounded

    stream = BytesIO(b"abcde" if oversized else b"abcd")
    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: stream)

    # Act / Assert
    if oversized:
        with pytest.raises(ValueError, match="size limit"):
            _read_bounded(tmp_path / "source.ts", 4)
    else:
        assert _read_bounded(tmp_path / "source.ts", 4) == b"abcd"
    assert stream.closed


@pytest.mark.parametrize("mode", ["unchanged", "localized", "expensive"])
def test_diff_work_is_bounded_without_rejecting_localized_edits(monkeypatch, mode):
    """Keep localized changes fast and reject expensive arbitrary comparisons."""
    # Arrange
    from gitlab_security_mcp import qualification

    monkeypatch.setattr(qualification, "MAX_DIFF_CELLS", 4)
    original = "unchanged();\n" * 5000
    current = original if mode == "unchanged" else original + "newApi();\n"
    if mode == "expensive":
        original, current = "before();\n" * 3, "after();\n" * 3

    # Act / Assert
    if mode == "expensive":
        with pytest.raises(ValueError, match="work limit"):
            qualification._changed_lines(original, current)
    else:
        assert qualification._changed_lines(original, current) == (
            0 if mode == "unchanged" else 1
        )


def test_status_refresh_hashes_checkout_once_for_multiple_packages(
    package_engine, package_review, monkeypatch
):
    """Share one fresh snapshot across all validated package receipts."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import engine

    assert (
        package_engine.qualify_package_update("package", package_review)["status"]
        == "QUALIFIED"
    )
    assert package_engine.apply_minimal_fix("package")["status"] == "APPLIED"
    assert package_engine.run_validation_matrix()["status"] == "VALIDATION_COMPLETE"
    finding = deepcopy(package_engine.state.findings[0])
    finding["id"] = "second"
    change = deepcopy(package_engine.state.changes[0])
    change["finding_id"] = "second"
    package_engine.state.findings.append(finding)
    package_engine.state.changes.append(change)
    snapshot = Mock(wraps=engine.tree_snapshot)
    monkeypatch.setattr(engine, "tree_snapshot", snapshot)

    # Act
    status = package_engine.get_run_status()

    # Assert
    assert len(status["package_updates"]) == 2
    assert all(
        item["qualification_status"] == "VALIDATED"
        for item in status["package_updates"]
    )
    snapshot.assert_called_once_with(package_engine.repo_root)


def test_engine_refuses_unqualified_updates(package_engine):
    """Keep advisories from bypassing licensing and compatibility gates."""
    # Arrange
    path = package_engine.repo_root / "package.json"
    original = path.read_bytes()

    # Act
    result = package_engine.apply_minimal_fix("package")

    # Assert
    assert result["status"] == "QUALIFICATION_REQUIRED"
    assert path.read_bytes() == original
    package_engine.runner.run.assert_not_called()


@pytest.mark.parametrize("change", ["none", "tree", "policy", "plan"])
def test_engine_applies_only_fresh_qualified_plan(
    package_engine, package_review, package_policy, change
):
    """Bind baseline evidence to the exact plan, checkout, and policy."""
    # Arrange
    assert (
        package_engine.qualify_package_update("package", package_review)["status"]
        == "QUALIFIED"
    )
    if change == "tree":
        (package_engine.repo_root / "app.ts").write_text("changed();", encoding="utf-8")
    elif change == "policy":
        path, policy, _plan = package_policy
        policy["approvals"][0]["approval_reference"] = "CHANGED"
        path.write_text(json.dumps(policy), encoding="utf-8")
    elif change == "plan":
        package_engine.state.findings[0]["proposedFix"]["target"] = "1.0.2"

    # Act
    result = package_engine.apply_minimal_fix("package")

    # Assert
    assert result["status"] == (
        "APPLIED" if change == "none" else "QUALIFICATION_REQUIRED"
    )
    if change == "none":
        assert result["change"]["qualification_status"] == "PENDING_VALIDATION"


@pytest.mark.parametrize(
    "failed_kind", [None, "build", "unit_tests", "runtime", "license_audit"]
)
def test_post_update_checks_control_resolution(
    package_engine, package_review, failed_kind
):
    """Require product behavior and graph licensing, not just a package edit."""
    # Arrange
    from gitlab_security_mcp.report import render

    assert (
        package_engine.qualify_package_update("package", package_review)["status"]
        == "QUALIFIED"
    )
    assert package_engine.apply_minimal_fix("package")["status"] == "APPLIED"
    checks = package_engine.state.findings[0]["packageQualification"]["checks"]

    def run(argv, **kwargs):
        """Fail the chosen post-update check after an otherwise good baseline."""
        failed = failed_kind is not None and argv == checks[failed_kind]["argv"]
        return CommandResult(
            argv, 1 if failed else 0, "CHECK_PASSED", "", 0, False, "out", "err"
        )

    package_engine.runner.run.side_effect = run

    # Act
    outcome = package_engine.run_validation_matrix()
    payload, _markdown = render(
        package_engine.state, staged=[], diff_stat="", diff_files=""
    )

    # Assert
    assert outcome["status"] == (
        "VALIDATION_COMPLETE" if failed_kind is None else "VALIDATION_FAILED"
    )
    assert package_engine.state.changes[0]["qualification_status"] == (
        "VALIDATED" if failed_kind is None else "PENDING_VALIDATION"
    )
    if failed_kind is not None:
        assert payload["unresolved_issues"][0]["id"] == "package"


@pytest.mark.parametrize(
    "field,value",
    [("target", "1.0.2"), ("package", "different"), ("ecosystem", "NuGet")],
)
def test_engine_binds_documentation_to_target(
    package_engine, package_review, field, value
):
    """Refuse a review for a different package or target before any command."""
    # Arrange
    package_review[field] = value

    # Act
    outcome = package_engine.qualify_package_update("package", package_review)

    # Assert
    assert outcome["status"] == "QUALIFICATION_REQUIRED"
    package_engine.runner.run.assert_not_called()


def test_applied_evidence_is_retained_and_stale_validation_is_invalidated(
    package_engine, package_review
):
    """Preserve original qualification and retract green results after edits."""
    # Arrange
    assert (
        package_engine.qualify_package_update("package", package_review)["status"]
        == "QUALIFIED"
    )
    assert package_engine.apply_minimal_fix("package")["status"] == "APPLIED"
    receipt = package_engine.state.findings[0]["packageQualification"]

    # Act
    verification = package_engine.verify_security_finding("package")
    validation = package_engine.run_validation_matrix()
    (package_engine.repo_root / "app.ts").write_text(
        "newUnreviewedCode();", encoding="utf-8"
    )
    status = package_engine.get_run_status()

    # Assert
    assert verification["status"] == "ERROR"
    assert package_engine.state.findings[0]["packageQualification"] is receipt
    assert validation["status"] == "VALIDATION_COMPLETE"
    assert status["status"] == "VALIDATION_INCOMPLETE"
    assert status["package_updates"][0]["qualification_status"] == "PENDING_VALIDATION"


@pytest.mark.parametrize(
    "failure",
    ["policy_missing", "baseline", "runtime", "license_audit", "tool_missing"],
)
def test_incomplete_baselines_never_permit_edits(
    package_engine, package_review, package_policy, failure
):
    """Require healthy existing product checks and corporate evidence first."""
    # Arrange
    path, policy, _plan = package_policy
    original = (package_engine.repo_root / "package.json").read_bytes()
    if failure == "policy_missing":
        path.unlink()
    if failure == "tool_missing":
        package_engine.which = lambda name: None

    def run(argv, **kwargs):
        """Fail a baseline check without changing any manifest file."""
        failed = failure == "baseline" or (
            failure in {"runtime", "license_audit"}
            and argv == policy["checks"]["npm"][failure]["argv"]
        )
        return CommandResult(
            argv, 1 if failed else 0, "CHECK_PASSED", "", 0, False, "out", "err"
        )

    package_engine.runner.run.side_effect = run

    # Act
    result = package_engine.qualify_package_update("package", package_review)
    applied = package_engine.apply_minimal_fix("package")

    # Assert
    assert result["status"] == applied["status"] == "QUALIFICATION_REQUIRED"
    assert (package_engine.repo_root / "package.json").read_bytes() == original


@pytest.mark.parametrize(
    "framework", ["Quarkus BOM", "Angular", "Crystal", ".NET target framework"]
)
def test_incompatible_product_framework_requires_review(
    package_engine, package_review, framework
):
    """Refuse framework incompatibility even for an advisory-verified patch."""
    # Arrange
    package_review["frameworks"][0]["name"] = framework
    package_review["frameworks"][0]["assessment"] = (
        "Target is incompatible with the installed framework"
    )
    package_review["compatible"] = False

    # Act
    result = package_engine.qualify_package_update("package", package_review)

    # Assert
    assert result["eligible_for_auto_fix"] is False
    assert result["status"] == "QUALIFICATION_REQUIRED"
    package_engine.runner.run.assert_not_called()


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--filter", "TestCategory=SecurityRuntimeSmoke"),
        ("--filter-trait", "Category=SecurityRuntimeSmoke"),
        ("--treenode-filter", "/*/*/*/*[Category=SecurityRuntimeSmoke]"),
    ],
)
def test_native_dotnet_smoke_filter_variants(tmp_path, flag, value):
    """Allow only known MSTest/NUnit, xUnit v3, and TUnit smoke categories."""
    # Arrange
    from gitlab_security_mcp.qualification import _check_variants

    argv = ["dotnet", "test", "--configuration", "Release", "--nologo", flag, value]

    # Act / Assert
    assert_allowed(argv, tmp_path)
    assert argv[1:] in _check_variants("nuget", "runtime")
    with pytest.raises(PermissionError):
        assert_allowed([*argv[:-1], "AnyArbitraryTest"], tmp_path)


def test_documentation_and_check_definitions_are_required(
    tmp_path, package_policy, package_review
):
    """Refuse incomplete documentation and missing product runtime checks."""
    # Arrange
    path, policy, plan = package_policy
    package_review["documentation"]["complete"] = False
    del policy["checks"]["npm"]["runtime"]
    path.write_text(json.dumps(policy), encoding="utf-8")

    # Act / Assert
    with pytest.raises(ValueError):
        review_package(tmp_path, package_review)
    with pytest.raises(ValueError):
        load_policy(tmp_path, path, plan)


@pytest.mark.parametrize(
    "stdout,truncated,code,expected",
    [
        ("CHECK_PASSED", False, 0, "PASSED"),
        ("", False, 0, "FAILED"),
        ("CHECK_PASSED", True, 0, "FAILED"),
        ("CHECK_PASSED", False, 1, "FAILED"),
    ],
)
def test_checks_require_positive_untruncated_success(
    tmp_path, package_policy, stdout, truncated, code, expected
):
    """Reject missing evidence even when a test command returns exit zero."""
    # Arrange
    from unittest.mock import Mock

    path, _policy, plan = package_policy
    checks = load_policy(tmp_path, path, plan)["checks"]
    runner = Mock()
    runner.run.return_value = CommandResult(
        [], code, stdout, "", 0, truncated, "out", "err"
    )

    # Act
    rows = run_checks(tmp_path, checks, runner, lambda name: name, 30)

    # Assert
    assert len(rows) == 4
    assert all(row["status"] == expected and row["required"] for row in rows)


@pytest.mark.parametrize(
    "mode", ["small", "rewrite", "rewrite_increments", "undeclared", "escape"]
)
def test_only_declared_surgical_source_fixes_are_accepted(
    tmp_path, package_review, mode
):
    """Permit bounded API adaptations but refuse rewrites and scope expansion."""
    # Arrange
    source = tmp_path / "app.ts"
    source.write_text("oldApi();\n", encoding="utf-8")
    package_review["source_fixes"] = [
        {
            "path": "../outside.ts" if mode == "escape" else "app.ts",
            "reason": "Adapt renamed API",
        }
    ]
    if mode == "escape":
        with pytest.raises(ValueError):
            review_package(tmp_path, package_review)
        return
    receipt = {
        "source_before": review_package(tmp_path, package_review),
        "tree": tree_snapshot(tmp_path),
    }
    replacement = "++counter;\n" if mode == "rewrite_increments" else "newApi();\n"
    source.write_text(
        replacement * (201 if mode.startswith("rewrite") else 1), encoding="utf-8"
    )
    if mode == "undeclared":
        (tmp_path / "other.ts").write_text("unreviewed();", encoding="utf-8")

    # Act / Assert
    if mode == "small":
        assert validate_edits(tmp_path, receipt, []) != receipt["tree"]
    else:
        with pytest.raises(ValueError):
            validate_edits(tmp_path, receipt, [])


@pytest.mark.parametrize(
    "ecosystem,manager,tool,commands",
    [
        (
            "NuGet",
            "nuget",
            "dotnet",
            [
                ["build", "--configuration", "Release", "--nologo"],
                ["test", "--configuration", "Release", "--nologo"],
                [
                    "test",
                    "--configuration",
                    "Release",
                    "--nologo",
                    "--filter",
                    "Category=SecurityRuntimeSmoke",
                ],
                [
                    "test",
                    "--configuration",
                    "Release",
                    "--nologo",
                    "--filter",
                    "Category=LicenseCompliance",
                ],
            ],
        ),
        (
            "Maven",
            "maven",
            "mvn",
            [
                ["--batch-mode", "clean", "verify"],
                ["--batch-mode", "test"],
                ["--batch-mode", "-Psecurity-smoke", "verify"],
                ["--batch-mode", "-Psecurity-licenses", "verify"],
            ],
        ),
        (
            "Maven",
            "gradle",
            "gradle",
            [
                ["--no-daemon", task]
                for task in ("build", "test", "securitySmoke", "securityLicenses")
            ],
        ),
    ],
)
def test_other_ecosystems_require_all_allowlisted_checks(
    tmp_path, package_policy, ecosystem, manager, tool, commands
):
    """Enforce equivalent product gates for .NET, Maven, and Gradle updates."""
    # Arrange
    path, original, original_plan = package_policy
    policy, plan = deepcopy(original), deepcopy(original_plan)
    plan.update(ecosystem=ecosystem, manager=manager)
    policy["approvals"][0]["ecosystem"] = ecosystem
    policy["checks"] = {
        ecosystem: {
            kind: {"argv": [tool, *args], "success_marker": "CHECK_PASSED"}
            for kind, args in zip(
                ("build", "unit_tests", "runtime", "license_audit"),
                commands,
                strict=True,
            )
        }
    }
    path.write_text(json.dumps(policy), encoding="utf-8")

    # Act
    qualified = load_policy(tmp_path, path, plan)

    # Assert
    assert len(qualified["checks"]) == 4
    for check in qualified["checks"].values():
        assert_allowed(check["argv"], tmp_path)
