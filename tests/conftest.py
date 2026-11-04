"""Git fixtures for the local remediation workflow."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def pytest_addoption(parser):
    """Keep private GitLab integration requests explicitly opt-in."""
    parser.addoption(
        "--patient-web-live",
        action="store_true",
        default=False,
        help="Retrieve patient-web findings and validate solutions against live advisories.",
    )


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run setup or inspection commands in a disposable test repository."""
    cwd = repo if repo.exists() else repo.parent
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
    )


def documentation_client(pages: dict[str, str] | None = None):
    """Serve publisher markers locally so tests can authorize an edit offline."""
    import httpx

    from gitlab_security_mcp.official_docs import REQUIRED_DOCS, OfficialDocs

    known = {url: marker for _name, url, marker in REQUIRED_DOCS}
    known.update(pages or {})

    def handler(request: httpx.Request) -> httpx.Response:
        """Return the prepared page, or the URL when the test did not override it."""
        url = str(request.url)
        if url not in known:
            return httpx.Response(200, text=url)
        return httpx.Response(200, text=known[url])

    return OfficialDocs(http=httpx.Client(transport=httpx.MockTransport(handler)))


def approve_package_for_test(root: Path, plan: dict) -> dict:
    """Write synthetic approval and review evidence only in fixture roots."""
    import json

    from gitlab_security_mcp.qualification import CHECK_KINDS, _check_args

    manager = plan["manager"]
    if manager in {"npm", "pnpm", "yarn"}:
        entry = next(
            (
                path
                for path in plan.get("files", [])
                if Path(path).name == "package.json"
            ),
            "package.json",
        )
        manifest = root / entry
        data = json.loads(manifest.read_text(encoding="utf-8"))
        for kind in ("lint", "build", "test"):
            data.setdefault("scripts", {}).setdefault(kind, "fixture")
        manifest.write_text(json.dumps(data), encoding="utf-8")
    if manager == "nuget" and not list(root.glob("*.csproj")):
        (root / "Fixture.csproj").write_text(
            "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>",
            encoding="utf-8",
        )
    tool = {"nuget": "dotnet", "maven": "mvn"}.get(manager, manager)
    approval = {key: plan[key] for key in ("ecosystem", "package", "target")}
    approval.update(
        license_expression="MIT",
        approved_by="Fixture Legal",
        approval_reference="TEST-ONLY-NOT-A-REAL-APPROVAL",
        obligations="Fixture notices",
        commercial_distribution_approved=True,
        no_license_fees=True,
        license_sources=["https://example.test/license"],
    )
    policy = {
        "schema_version": 1,
        "approvals": [approval],
        "checks": {
            plan["ecosystem"]: {
                kind: {
                    "argv": [tool, *_check_args(manager, kind)],
                    "success_marker": "ok",
                }
                for kind in CHECK_KINDS
            }
        },
    }
    path = root / ".security-mcp" / "package-update-policy.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(policy), encoding="utf-8")
    return {
        **{key: plan[key] for key in ("ecosystem", "package", "target")},
        "documentation": {
            "complete": True,
            "sources": ["https://example.test/docs"],
            "summary": "Fixture API review",
        },
        "compatible": True,
        "compatible_without_code_changes": True,
        "api_changes": "Fixture has no API changes",
        "frameworks": [
            {
                "name": "Fixture runtime",
                "version": "1",
                "source_url": "https://example.test/support",
                "assessment": "Fixture compatibility",
            }
        ],
        "source_fixes": [],
    }


def commit_all(repo: Path, message: str = "init") -> None:
    """Stage and commit fixture files using a local test-only identity."""
    subprocess.run(
        ["git", "add", "-A"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            message,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Create an isolated empty main branch without touching user checkouts."""
    git(tmp_path, "init", "-b", "main")
    return tmp_path


@pytest.fixture
def cloned_repo(tmp_path: Path) -> Path:
    """Create a local bare origin and clean clone for pull workflow tests."""
    remote = tmp_path / "remote.git"
    origin = tmp_path / "origin"
    clone = tmp_path / "clone"
    git(tmp_path, "init", "--bare", "-b", "main", str(remote))
    origin.mkdir()
    git(origin, "init", "-b", "main")
    (origin / "README.md").write_text("hello\n", encoding="utf-8")
    commit_all(origin, "initial")
    git(origin, "remote", "add", "origin", str(remote))
    git(origin, "push", "-u", "origin", "main")
    git(tmp_path, "clone", str(remote), str(clone))
    return clone
