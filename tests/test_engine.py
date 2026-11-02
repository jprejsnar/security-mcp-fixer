import hashlib
import json
from datetime import date
from pathlib import Path

from gitlab_security_mcp.advisory import AdvisoryLookup
from gitlab_security_mcp.commands import CommandResult, CommandRunner, assert_allowed, tool_name
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.git_ops import branch_name_for


class HybridRunner(CommandRunner):
    """Run real git commands and record every other allowlisted command."""

    def __init__(self, repo_root):
        super().__init__(repo_root)
        self.calls: list[list[str]] = []

    def run(self, argv, *, timeout, check=True, cwd=None):
        assert_allowed(argv, self.repo_root)
        self.calls.append(list(argv))
        if tool_name(argv[0]) == "git":
            return super().run(argv, timeout=timeout, check=check, cwd=cwd)
        stdout = "ok"
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
    def __init__(self, findings):
        self.findings = findings

    def fetch(self, project_id):
        from gitlab_security_mcp.gitlab_client import FetchResult

        return FetchResult(
            ok=True,
            findings=self.findings,
            pipeline={"id": "gid://gitlab/Ci::Pipeline/9", "sha": "abc123", "ref": "main"},
            project_path=project_id,
            excluded={},
        )


class ScriptedAdvisory:
    def lookup(self, finding, ecosystem, package, version):
        identifier = (finding.get("identifiers") or [""])[0]
        if identifier == "CVE-FP":
            return AdvisoryLookup(
                outcome="resolved",
                affected=False,
                summary="Installed version is outside the OSV affected range.",
                sources=["osv:CVE-FP"],
            )
        if identifier == "CVE-MANUAL":
            return AdvisoryLookup(outcome="not_found", summary="No matching record in OSV, the GitHub Advisory Database, or NVD.")
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


def test_prechecks_fail_closed(repo):
    # Arrange
    engine = Engine(repo, gitlab=FakeGitLab([]), advisory=ScriptedAdvisory(), which=lambda _name: None)
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
    (cloned_repo / "package.json").write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
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
    verified = {item["id"]: engine.verify_security_finding(item["id"]) for item in findings}
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
    assert created == {"status": "BRANCH_CREATED", "branch": branch_name_for(date(2026, 11, 1))}
    assert listed["count"] == 4
    assert verified["fix"]["decision"] == "CHANGE_REQUIRED"
    assert any("Unknown reachability" in line for line in verified["fix"]["evidence"])
    assert verified["fp"]["decision"] == "FALSE_POSITIVE"
    assert verified["ask"]["decision"] == "MANUAL_REVIEW"
    assert "needs your decision" in verified["ask"]["user_prompt"]
    assert verified["none"]["decision"] == "NO_SAFE_FIX"
    assert applied["fix"]["status"] == "APPLIED"
    assert applied["ask"]["status"] == "SKIPPED_USER_PROMPT"
    assert applied["fp"]["status"] == "SKIPPED"
    assert applied["none"]["status"] == "SKIPPED"
    assert json.loads((cloned_repo / "package.json").read_text(encoding="utf-8"))["dependencies"]["lodash"] == "4.17.21"
    assert not any(call[1] in {"add", "commit", "push"} for call in runner.calls if tool_name(call[0]) == "git" or call[0] == "git")
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
        def lookup(self, finding, ecosystem, package, version):
            return AdvisoryLookup(
                outcome="resolved",
                affected=True,
                fixed_versions=["1.27.0"],
                lowest_fixed_version="1.27.0",
                summary="Fixed image tag 1.27.0.",
                sources=["osv:CVE-IMG"],
            )

    engine = Engine(repo, gitlab=FakeGitLab([finding]), advisory=ImageAdvisory(), runner=HybridRunner(repo), which=lambda name: name)
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
    (repo / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "1.0.0"}}), encoding="utf-8")
    finding = _finding("gone", "not-a-real-package", "CVE-WHATEVER")
    engine = Engine(repo, gitlab=FakeGitLab([finding]), advisory=ScriptedAdvisory(), which=lambda name: None)
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
    engine = Engine(repo, gitlab=FakeGitLab([finding]), advisory=ScriptedAdvisory(), which=lambda name: None)
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
    engine = Engine(repo, gitlab=FakeGitLab([finding]), advisory=ScriptedAdvisory(), which=lambda name: None)
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
    engine = Engine(repo, gitlab=FakeGitLab([finding]), advisory=ScriptedAdvisory(), which=lambda name: None)
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]

    # Act
    applied = engine.apply_minimal_fix("fix")

    # Assert
    assert applied["status"] == "ERROR"
    assert applied["reason"] == "Proposed fix is incomplete."


def test_major_version_fix_needs_a_person(repo):
    # Arrange
    (repo / "package.json").write_text(json.dumps({"dependencies": {"minimist": "0.2.1"}}), encoding="utf-8")
    finding = _finding("major", "minimist", "CVE-MAJOR", "0.2.1")

    class MajorAdvisory:
        def lookup(self, finding, ecosystem, package, version):
            return AdvisoryLookup(
                outcome="resolved",
                affected=True,
                fixed_versions=["1.2.6"],
                lowest_fixed_version="1.2.6",
                summary="OSV lists fixed version(s): 1.2.6.",
                sources=["osv:CVE-MAJOR"],
            )

    engine = Engine(repo, gitlab=FakeGitLab([finding]), advisory=MajorAdvisory(), which=lambda name: None)
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

    (repo / "package.json").write_text(json.dumps({"scripts": {"test": "node --test"}}), encoding="utf-8")
    existing = repo / "test" / "security" / "img.test.js"
    existing.parent.mkdir(parents=True)
    existing.write_text("// mine\n", encoding="utf-8")
    change = {"strategy": "image_tag", "oracle": "nginx:1.27.0", "files": ["Dockerfile"]}

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
    assert json.loads((tmp_path / ".security-mcp" / "run-state.json").read_text(encoding="utf-8"))["status"] == "PRECHECK_PASSED"


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
        "apply_minimal_fix",
        "generate_aaa_test",
        "run_validation_matrix",
        "generate_local_report",
        "get_run_status",
    }
