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
    review_major_upgrade,
    review_package,
    run_checks,
    scan_package_callers,
    tree_snapshot,
    validate_edits,
)
from gitlab_security_mcp.validate import _lint_result, _product_result


@pytest.mark.parametrize("truncated,code", [(False, 0), (False, 1), (True, 0)])
def test_lint_records_warnings_information_and_unknowns(truncated, code):
    """Lint records warnings information and unknowns."""
    # Arrange
    result = CommandResult(
        ["npm", "run", "lint"],
        code,
        "warning: existing issue\ninfo: rule disabled\nunrecognized diagnostic\n",
        "",
        0,
        truncated,
        "out",
        "err",
    )

    # Act
    row = _lint_result(result)

    # Assert
    assert row["status"] == ("PASSED" if not truncated and code == 0 else "FAILED")
    assert row["diagnostics"] == {
        "errors": [],
        "warnings": ["warning: existing issue"],
        "info": ["info: rule disabled"],
        "unknown": ["unrecognized diagnostic"],
    }
    assert row["stdout"] == result.stdout


def test_lint_json_errors_fail_even_with_exit_zero():
    """Lint json errors fail even with exit zero."""
    # Arrange
    result = CommandResult(
        ["npm", "run", "lint"],
        0,
        json.dumps(
            [
                {
                    "filePath": "app.ts",
                    "messages": [{"severity": 2, "message": "API error"}],
                }
            ]
        ),
        "",
        0,
        False,
        "out",
        "err",
    )

    # Act
    row = _lint_result(result)

    # Assert
    assert row["status"] == "FAILED"
    assert len(row["diagnostics"]["errors"]) == 1


@pytest.mark.parametrize(
    "output,expected",
    [
        ("0 errors, 2 warnings", "PASSED"),
        ("/src/error.ts\n1:2 warning unused import", "PASSED"),
        ("2 errors, 0 warnings", "FAILED"),
    ],
)
def test_lint_summaries_do_not_confuse_zero_errors_or_source_filenames(
    output, expected
):
    """Lint summaries do not confuse zero errors or source filenames."""
    # Arrange
    result = CommandResult(
        ["npm", "run", "lint"], 0, output, "", 0, False, "out", "err"
    )

    # Act
    row = _lint_result(result)

    # Assert
    assert row["status"] == expected
    assert row["stdout"] == output


@pytest.mark.parametrize(
    "output,expected",
    [
        ("No tests found, exiting with code 0", "FAILED"),
        ("Tests run: 0", "FAILED"),
        ("> Task :test NO-SOURCE", "FAILED"),
        ("Tests run: 0\nTests run: 5, Failures: 0", "PASSED"),
    ],
)
def test_unit_test_checks_require_executed_tests_without_rejecting_empty_modules(
    output, expected
):
    """Unit test checks require executed tests without rejecting empty modules."""
    # Arrange
    result = CommandResult(["npm", "test"], 0, output, "", 0, False, "out", "err")

    # Act
    row = _product_result(result, "unit_tests")

    # Assert
    assert row["status"] == expected


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


def test_nested_node_qualification_checks_use_component_directory(
    tmp_path, package_policy
):
    """Nested node qualification checks use component directory."""
    # Arrange
    from unittest.mock import Mock

    frontend = tmp_path / "frontend"
    frontend.mkdir()
    checks = package_policy[1]["checks"]["npm"]
    runner = Mock()
    runner.run.return_value = CommandResult([], 0, "CHECK_PASSED", "", 0, False, "", "")
    plan = {
        "manager": "npm",
        "files": ["frontend/package.json", "frontend/package-lock.json"],
    }

    # Act
    rows = run_checks(tmp_path, checks, runner, lambda name: name, 30, plan=plan)

    # Assert
    assert len(rows) == 4
    assert all(row["status"] == "PASSED" for row in rows)
    assert all(
        call.kwargs["cwd"] == frontend.resolve() for call in runner.run.call_args_list
    )


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
                    for name in (
                        "lint",
                        "build",
                        "test",
                        "security:smoke",
                        "security:licenses",
                    )
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
    from tests.conftest import documentation_client

    engine = Engine(
        tmp_path,
        advisory=advisory,
        gitlab=Mock(),
        docs=documentation_client(),
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
        "compatible_without_code_changes": True,
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


@pytest.mark.parametrize("target", ["2.0.0", "1.1.0", "1.0.1", "1.0.0.1"])
@pytest.mark.parametrize("source_path", ["app.ts", "app.test.ts"])
def test_every_package_increment_rejects_code_adaptations(
    tmp_path, package_review, target, source_path
):
    """Every package increment rejects code adaptations."""
    # Arrange
    package_review["target"] = target
    package_review["source_fixes"] = [
        {"path": source_path, "reason": "Adapt changed API"}
    ]

    # Act
    with pytest.raises(
        ValueError, match="cannot require production or unit-test code changes"
    ) as raised:
        review_package(tmp_path, package_review)

    # Assert
    assert "cannot require production or unit-test code changes" in str(raised.value)


@pytest.mark.parametrize("missing_script", [None, "lint", "build", "test"])
def test_missing_default_policy_uses_documented_license_review(
    package_engine, package_review, missing_script
):
    """Missing default policy uses documented license review."""
    # Arrange
    from gitlab_security_mcp.report import render

    package_engine.package_policy_path.unlink()
    package_review["license"] = {
        "expression": "MIT",
        "sources": ["https://example.test/license/1.0.1"],
        "commercial_use_permitted": True,
        "no_license_fees": True,
        "obligations": "Retain copyright and license notices",
        "assessment": "Reviewed target-version terms; no license fee required",
    }
    if missing_script:
        path = package_engine.repo_root / "package.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["scripts"].pop(missing_script)
        path.write_text(json.dumps(data), encoding="utf-8")

    # Act
    result = package_engine.qualify_package_update("package", package_review)

    # Assert
    if missing_script:
        assert result["status"] == "QUALIFICATION_REQUIRED"
        assert "existing build and test scripts" in result["reason"]
        package_engine.runner.run.assert_not_called()
        return
    assert result["status"] == "QUALIFIED", result
    receipt = package_engine.state.findings[0]["packageQualification"]
    assert receipt["policy_mode"] == "documentation_review"
    assert receipt["approval"] is None
    assert not package_engine.package_policy_path.exists()
    applied = package_engine.apply_minimal_fix("package")
    validated = package_engine.run_validation_matrix()
    refreshed = package_engine.get_run_status()
    assert applied["status"] == "APPLIED", applied
    assert validated["status"] == "VALIDATION_COMPLETE", validated
    assert package_engine.state.changes[0]["qualification_status"] == "VALIDATED"
    assert refreshed["package_updates"][0]["qualification_status"] == "VALIDATED"
    assert package_engine.state.validation_status == "VALIDATION_COMPLETE"
    assert not package_engine.package_policy_path.exists()
    payload, markdown = render(
        package_engine.state, staged=[], diff_stat="", diff_files=""
    )
    qualification = payload["package_qualifications"]["package"]
    assert qualification["policy_mode"] == "documentation_review"
    assert qualification["approval"] is None
    assert "documented license review, not corporate approval" in markdown


def test_lint_diagnostics_are_retained_before_and_after_update(
    package_engine, package_review
):
    """Lint diagnostics are retained before and after update."""

    # Arrange
    def run(argv, **kwargs):
        """Return nonblocking lint messages and passing product-check evidence."""
        output = (
            "warning: existing issue\ninfo: checked rules\nunknown diagnostic\n"
            if argv[1:] == ["run", "lint"]
            else "CHECK_PASSED"
        )
        return CommandResult(argv, 0, output, "", 0, False, "out", "err")

    package_engine.runner.run.side_effect = run

    # Act
    qualified = package_engine.qualify_package_update("package", package_review)
    applied = package_engine.apply_minimal_fix("package")
    validated = package_engine.run_validation_matrix()

    # Assert
    assert qualified["status"] == "QUALIFIED", qualified
    assert applied["status"] == "APPLIED", applied
    assert validated["status"] == "VALIDATION_COMPLETE", validated
    receipt = package_engine.state.findings[0]["packageQualification"]
    for phase in ("baseline_results", "post_results"):
        lint = next(row for row in receipt[phase] if row.get("kind") == "lint")
        assert lint["status"] == "PASSED"
        assert lint["diagnostics"]["warnings"]
        assert lint["diagnostics"]["info"]
        assert lint["diagnostics"]["unknown"]


def test_lint_baseline_is_retained_when_build_cannot_start(
    package_engine, package_review
):
    """Lint baseline is retained when build cannot start."""

    # Arrange
    def run(argv, **kwargs):
        """Emit lint evidence then fail starting the build command."""
        if argv[1:] == ["run", "build"]:
            raise OSError("Build executable unavailable")
        return CommandResult(
            argv,
            0,
            "warning: existing issue\n"
            if argv[1:] == ["run", "lint"]
            else "CHECK_PASSED",
            "",
            0,
            False,
            "out",
            "err",
        )

    package_engine.runner.run.side_effect = run

    # Act
    result = package_engine.qualify_package_update("package", package_review)

    # Assert
    assert result["status"] == "QUALIFICATION_REQUIRED"
    assert "build" in result["reason"]
    lint = next(row for row in result["baseline_results"] if row.get("kind") == "lint")
    assert lint["diagnostics"]["warnings"] == ["warning: existing issue"]


@pytest.mark.parametrize("stage", ["lint", "build", "test"])
def test_failed_baseline_records_check_and_does_not_apply(
    package_engine, package_review, stage
):
    """Failed baseline records check and does not apply."""
    # Arrange
    before = (package_engine.repo_root / "package.json").read_bytes()

    def run(argv, **kwargs):
        """Fail only the selected product check."""
        failed = argv[1:] == (["test"] if stage == "test" else ["run", stage])
        return CommandResult(
            argv,
            1 if failed else 0,
            "CHECK_PASSED",
            "error: fixture failure" if failed else "",
            0,
            False,
            "out",
            "err",
        )

    package_engine.runner.run.side_effect = run

    # Act
    result = package_engine.qualify_package_update("package", package_review)

    # Assert
    assert result["status"] == "QUALIFICATION_REQUIRED"
    assert ("unit_tests" if stage == "test" else stage) in result["reason"]
    assert any(row["status"] == "FAILED" for row in result["baseline_results"])
    assert (
        package_engine.state.findings[0]["packageQualification"]["baseline_results"]
        == result["baseline_results"]
    )
    assert (package_engine.repo_root / "package.json").read_bytes() == before


@pytest.mark.parametrize("confirmation", [None, False, "true"])
def test_api_changes_or_uncertain_no_code_compatibility_blocks_qualification(
    package_engine, package_review, confirmation
):
    """Api changes or uncertain no code compatibility blocks qualification."""
    # Arrange
    package_review["compatible_without_code_changes"] = confirmation

    # Act
    result = package_engine.qualify_package_update("package", package_review)

    # Assert
    assert result["status"] == "QUALIFICATION_REQUIRED"
    assert (
        "neither production nor unit-test callers need API changes" in result["reason"]
    )
    package_engine.runner.run.assert_not_called()


@pytest.mark.parametrize("stage", ["lint", "build", "test", "source", "scripts"])
def test_failed_post_checks_reject_and_restore_only_dependency_edits(
    package_engine, package_review, stage
):
    """Failed post checks reject and restore only dependency edits."""
    # Arrange
    manifest = package_engine.repo_root / "package.json"
    before = manifest.read_bytes()
    assert (
        package_engine.qualify_package_update("package", package_review)["status"]
        == "QUALIFIED"
    )
    assert package_engine.apply_minimal_fix("package")["status"] == "APPLIED"
    source = package_engine.repo_root / "app.test.ts"
    if stage == "source":
        source.write_text("adaptedApi();\n", encoding="utf-8")
    if stage == "scripts":
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["scripts"]["test"] = "echo bypass tests"
        manifest.write_text(json.dumps(data), encoding="utf-8")

    def run(argv, **kwargs):
        """Fail the selected post-update check without modifying files."""
        failed = argv[1:] == (["test"] if stage == "test" else ["run", stage])
        return CommandResult(
            argv,
            1 if failed else 0,
            "CHECK_PASSED",
            "error: fixture failure" if failed else "",
            0,
            False,
            "out",
            "err",
        )

    package_engine.runner.run.side_effect = run

    # Act
    result = package_engine.run_validation_matrix()

    # Assert
    assert result["status"] == "VALIDATION_FAILED", result
    assert "not accepted" in result["reason"]
    change = package_engine.state.changes[0]
    assert change["qualification_status"] == "REJECTED"
    assert "Package update rejected" in change["detail"]
    if stage == "scripts":
        assert result["rollbacks"][0]["status"] == "MANUAL_REVIEW_REQUIRED"
        assert (
            json.loads(manifest.read_text(encoding="utf-8"))["scripts"]["test"]
            == "echo bypass tests"
        )
    else:
        assert result["rollbacks"][0]["status"] == "ROLLED_BACK"
        assert manifest.read_bytes() == before
    if stage == "source":
        assert source.read_text(encoding="utf-8") == "adaptedApi();\n"


def test_missing_explicit_policy_does_not_fall_back(
    tmp_path, monkeypatch, package_review
):
    """Missing explicit policy does not fall back."""
    # Arrange
    from unittest.mock import Mock

    missing = tmp_path / "corporate-policy.json"
    monkeypatch.setenv("PACKAGE_UPDATE_POLICY", str(missing))
    engine = Engine(tmp_path, gitlab=Mock(), advisory=Mock())
    plan = {"ecosystem": "npm", "package": "example", "target": "1.0.1"}

    # Act
    with pytest.raises(FileNotFoundError):
        engine._package_policy(plan, package_review)
    # Assert
    assert not missing.exists()


def test_missing_default_policy_does_not_fabricate_license_review(
    package_engine, package_review
):
    """Missing default policy does not fabricate license review."""
    # Arrange
    package_engine.package_policy_path.unlink()

    # Act
    result = package_engine.qualify_package_update("package", package_review)

    # Assert
    assert result["status"] == "QUALIFICATION_REQUIRED"
    assert "review.license" in result["reason"]
    assert "No corporate approval file is required" in result["reason"]
    package_engine.runner.run.assert_not_called()


def test_existing_invalid_policy_does_not_fall_back(package_engine, package_review):
    """Existing invalid policy does not fall back."""
    # Arrange
    package_engine.package_policy_path.write_text("{}", encoding="utf-8")

    # Act
    result = package_engine.qualify_package_update("package", package_review)

    # Assert
    assert result["status"] == "QUALIFICATION_REQUIRED"
    assert "schema_version" in result["reason"]
    package_engine.runner.run.assert_not_called()


def test_major_review_requires_hashed_callers_and_no_code_changes(
    tmp_path, package_review
):
    """Major review requires hashed callers and no code changes."""
    # Arrange
    import hashlib

    source = tmp_path / "app.ts"
    source.write_text('import example from "example";\nexample();\n', encoding="utf-8")
    plan = {
        "major_upgrade": True,
        "ecosystem": "npm",
        "package": "example",
        "installed": "1.0.0",
        "target": "2.0.0",
        "strategy": "manifest_bump",
        "files": ["package.json"],
    }
    plan["caller_scan"] = scan_package_callers(tmp_path, plan)
    package_review["major_upgrade"] = {
        "scan_id": plan["caller_scan"]["scan_id"],
        "compatible_without_code_changes": True,
        "caller_breakages_found": False,
        "migration_sources": ["https://example.test/migration/2"],
        "api_comparison": "The used default export is unchanged across versions",
        "caller_assessment": "The app call uses the unchanged signature",
        "dependency_assessment": "No transitive consumer uses this direct dependency",
        "reviewed_files": [
            {
                "path": "app.ts",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "assessment": "Unchanged call signature",
            }
        ],
    }

    # Act
    accepted = review_major_upgrade(tmp_path, plan, package_review)

    # Assert
    assert accepted["scan"]["source_files_scanned"] == 1
    assert accepted["scan"]["references"] == [{"path": "app.ts", "lines": [1, 2]}]
    package_review["source_fixes"] = [{"path": "app.ts", "reason": "Adapt API"}]
    with pytest.raises(ValueError, match="cannot adjust"):
        review_major_upgrade(tmp_path, plan, package_review)
    package_review["source_fixes"] = []
    source.write_text("changed();", encoding="utf-8")
    with pytest.raises(ValueError, match="scan changed"):
        review_major_upgrade(tmp_path, plan, package_review)


def test_caller_scan_does_not_confuse_glob_with_global(tmp_path):
    """Caller scan does not confuse glob with global."""
    # Arrange
    (tmp_path / "app.ts").write_text(
        'globalThis.name;\nconst globalValue = true;\nimport {glob} from "glob";\n',
        encoding="utf-8",
    )

    # Act
    scan = scan_package_callers(tmp_path, {"package": "glob", "target": "14.0.2"})

    # Assert
    assert scan["references"] == [{"path": "app.ts", "lines": [3]}]


@pytest.fixture
def major_package_update(tmp_path, package_engine, package_policy, package_review):
    # Arrange
    import hashlib

    source = tmp_path / "app.ts"
    source.write_text('import example from "example";\nexample();\n', encoding="utf-8")
    package_engine.advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved",
        affected=True,
        lowest_fixed_version="2.0.0",
        fixed_versions=["2.0.0"],
    )
    path, policy, _plan = package_policy
    policy["approvals"][0]["target"] = "2.0.0"
    path.write_text(json.dumps(policy), encoding="utf-8")
    verified = package_engine.verify_security_finding("package")
    package_review["target"] = "2.0.0"
    package_review["major_upgrade"] = {
        "scan_id": verified["proposed_fix"]["caller_scan"]["scan_id"],
        "compatible_without_code_changes": True,
        "caller_breakages_found": False,
        "migration_sources": ["https://example.test/migration/2"],
        "api_comparison": "Used default-export API is unchanged",
        "caller_assessment": "Application call uses the unchanged signature",
        "dependency_assessment": "Direct dependency; no additional callers",
        "reviewed_files": [
            {
                "path": "app.ts",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "assessment": "Used API remains supported",
            }
        ],
    }
    return package_engine, package_review, source


@pytest.mark.parametrize(
    "failure", [None, "build", "unit_tests", "source_edit", "script_edit"]
)
def test_major_update_requires_passing_checks_without_code_adjustments(
    major_package_update, failure
):
    """Major update requires passing checks without code adjustments."""
    # Arrange
    engine, review, source = major_package_update
    original = source.read_bytes()
    qualified = engine.qualify_package_update("package", review)
    assert qualified["status"] == "QUALIFIED", qualified

    # Act
    applied = engine.apply_minimal_fix("package")
    assert applied["status"] == "APPLIED", applied
    if failure == "source_edit":
        source.write_text("adapted();\n", encoding="utf-8")
    elif failure == "script_edit":
        manifest = engine.repo_root / "package.json"
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["scripts"]["test"] = "echo bypassed"
        manifest.write_text(json.dumps(data), encoding="utf-8")
    elif failure:

        def fail_check(argv, **kwargs):
            """Simulate product failures after an otherwise passing baseline."""
            failed = argv[1:] == (["run", "build"] if failure == "build" else ["test"])
            return CommandResult(
                argv, 1 if failed else 0, "CHECK_PASSED", "", 0, False, "", ""
            )

        engine.runner.run.side_effect = fail_check
    result = engine.run_validation_matrix()

    # Assert
    if failure:
        assert result["status"] == "VALIDATION_FAILED"
        assert engine.state.changes[0]["qualification_status"] == "REJECTED"
    else:
        assert result["status"] == "VALIDATION_COMPLETE"
        assert engine.state.changes[0]["qualification_status"] == "VALIDATED"
    if failure != "source_edit":
        assert source.read_bytes() == original


@pytest.mark.parametrize(
    "field, value",
    [
        ("compatible_without_code_changes", False),
        ("caller_breakages_found", True),
        ("migration_sources", []),
        ("reviewed_files", []),
        ("api_comparison", ""),
    ],
)
def test_major_update_refuses_missing_or_breaking_review(
    major_package_update, field, value
):
    """Major update refuses missing or breaking review."""
    # Arrange
    engine, review, _source = major_package_update
    review["major_upgrade"][field] = value

    # Act
    result = engine.qualify_package_update("package", review)

    # Assert
    assert result["status"] == "QUALIFICATION_REQUIRED"
    assert not engine.state.changes
    assert (
        engine.state.findings[0]["packageQualification"]["review"]["major_upgrade"][
            field
        ]
        == value
    )
    engine.runner.run.assert_not_called()


def test_transitive_major_update_requires_dependency_source_review(
    major_package_update,
):
    """Transitive major update requires dependency source review."""
    # Arrange
    engine, review, _source = major_package_update
    plan = engine.state.findings[0]["proposedFix"]
    plan["strategy"] = "override"

    # Act
    with pytest.raises(ValueError, match="installed dependency caller") as raised:
        review_major_upgrade(engine.repo_root, plan, review)

    # Assert
    assert "installed dependency caller" in str(raised.value)


@pytest.mark.parametrize(
    "package, installed, target",
    [("minimatch", "10.2.6", "11.0.1"), ("glob", "10.5.0", "14.0.2")],
)
@pytest.mark.parametrize("corporate_policy", [False, True])
def test_nested_transitive_pnpm_major_update_preserves_callers(
    tmp_path,
    package_policy,
    package_review,
    package,
    installed,
    target,
    corporate_policy,
):
    """Nested transitive pnpm major update preserves callers."""
    # Arrange
    import hashlib
    from unittest.mock import Mock

    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text(
        json.dumps(
            {
                "packageManager": "pnpm@10.0.0",
                "scripts": {"lint": "lint", "build": "build", "test": "test"},
            }
        ),
        encoding="utf-8",
    )
    (frontend / "pnpm-workspace.yaml").write_text(
        f"packages:\n  - .\noverrides:\n  {package}: {installed}\n", encoding="utf-8"
    )
    lock = frontend / "pnpm-lock.yaml"
    lock.write_text(f"packages:\n  {package}@{installed}: {{}}\n", encoding="utf-8")
    source = frontend / "app.ts"
    source.write_text("export const app = true;\n", encoding="utf-8")
    consumer = frontend / "node_modules" / "consumer" / "index.js"
    consumer.parent.mkdir(parents=True)
    consumer.write_text(f'const api = require("{package}");\n', encoding="utf-8")
    original = {path: path.read_bytes() for path in (source, consumer)}
    policy_path, policy, _plan = package_policy
    policy["approvals"][0].update(package=package, target=target)
    for check in policy["checks"]["npm"].values():
        check["argv"][0] = "pnpm"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    if not corporate_policy:
        policy_path.unlink()
    runner = Mock()

    def run(argv, **kwargs):
        """Simulate a locked resolution update and successful real-check markers."""
        assert_allowed(argv, tmp_path)
        if argv[1:] == ["install", "--lockfile-only", "--ignore-scripts"]:
            assert kwargs["cwd"] == frontend.resolve()
            lock.write_text(
                f"packages:\n  {package}@{target}: {{}}\n", encoding="utf-8"
            )
        return CommandResult(argv, 0, "CHECK_PASSED", "", 0, False, "", "")

    runner.run.side_effect = run
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved",
        affected=True,
        lowest_fixed_version=target,
        fixed_versions=[target],
    )
    from tests.conftest import documentation_client

    engine = Engine(
        tmp_path,
        runner=runner,
        advisory=advisory,
        gitlab=Mock(),
        docs=documentation_client(),
        which=lambda name: name,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [
        {
            "id": package,
            "component": package,
            "installedVersion": installed,
            "category": "dependency_scanning",
        }
    ]
    verified = engine.verify_security_finding(package)
    package_review.update(package=package, target=target)
    package_review["license"] = {
        "expression": "MIT",
        "sources": ["https://example.test/target-license"],
        "commercial_use_permitted": True,
        "no_license_fees": True,
        "obligations": "Retain notices",
        "assessment": "Test-only reviewed license terms",
    }
    package_review["major_upgrade"] = {
        "scan_id": verified["proposed_fix"]["caller_scan"]["scan_id"],
        "compatible_without_code_changes": True,
        "caller_breakages_found": False,
        "migration_sources": ["https://example.test/target-api"],
        "api_comparison": "Used dependency API is unchanged",
        "caller_assessment": "No application adaptation required",
        "dependency_assessment": "Installed consumer uses supported exports",
        "reviewed_files": [
            {
                "path": path.relative_to(tmp_path).as_posix(),
                "sha256": hashlib.sha256(contents).hexdigest(),
                "assessment": "Used API remains supported",
            }
            for path, contents in original.items()
        ],
    }

    # Act
    qualified = engine.qualify_package_update(package, package_review)
    applied = engine.apply_minimal_fix(package)
    validated = engine.run_validation_matrix()

    # Assert
    assert qualified["status"] == "QUALIFIED", qualified
    assert applied["status"] == "APPLIED", applied
    assert validated["status"] == "VALIDATION_COMPLETE", validated
    assert engine.state.changes[0]["qualification_status"] == "VALIDATED"
    assert all(path.read_bytes() == contents for path, contents in original.items())
    assert policy_path.exists() is corporate_policy
    receipt = engine.state.findings[0]["packageQualification"]
    assert receipt["policy_mode"] == (
        "corporate_policy" if corporate_policy else "documentation_review"
    )
    if not corporate_policy:
        assert receipt["approval"] is None


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

    # Act
    with pytest.raises(ValueError) as raised:
        load_policy(tmp_path, path, plan)

    # Assert
    assert isinstance(raised.value, ValueError)


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

    # Act
    with pytest.raises(ValueError) as raised:
        review_package(tmp_path, package_review)

    # Assert
    assert isinstance(raised.value, ValueError)


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

    # Act
    with pytest.raises(type(interrupt)):
        run_checks(
            tmp_path, package_policy[1]["checks"]["npm"], runner, lambda name: name, 30
        )
    # Assert
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

    # Act
    if oversized:
        with pytest.raises(ValueError, match="size limit"):
            _read_bounded(tmp_path / "source.ts", 4)
        bounded = None
    else:
        bounded = _read_bounded(tmp_path / "source.ts", 4)

    # Assert
    if not oversized:
        assert bounded == b"abcd"
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

    # Act
    if mode == "expensive":
        with pytest.raises(ValueError, match="work limit"):
            qualification._changed_lines(original, current)
        changed = None
    else:
        changed = qualification._changed_lines(original, current)

    # Assert
    if mode != "expensive":
        assert changed == (0 if mode == "unchanged" else 1)


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
        "VALIDATED" if failed_kind is None else "REJECTED"
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

    # Act
    assert_allowed(argv, tmp_path)
    # Assert
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

    # Act
    with pytest.raises(ValueError):
        review_package(tmp_path, package_review)
    # Assert
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
    "mode", ["small", "rewrite", "rewrite_increments", "undeclared", "delete"]
)
def test_source_changes_are_rejected_even_when_listed_as_allowed(
    tmp_path, package_review, mode
):
    """Reject every source adaptation, including small edits and deletions."""
    # Arrange
    source = tmp_path / "app.ts"
    source.write_text("oldApi();\n", encoding="utf-8")
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
    if mode == "delete":
        source.unlink()

    # Act
    with pytest.raises(
        ValueError, match="production or unit-test code changed"
    ) as raised:
        validate_edits(tmp_path, receipt, ["app.ts", "other.ts"])

    # Assert
    assert "production or unit-test code changed" in str(raised.value)


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
