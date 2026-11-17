"""Git fixtures for the local remediation workflow."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def no_interactive_approval_windows(monkeypatch):
    """Keep default regressions on MCP forms; native UI integration tests opt in."""
    monkeypatch.setattr("gitlab_security_mcp.desktop_approval.available", lambda: False)


@pytest.fixture(autouse=True)
def corporate_dns(monkeypatch):
    """Keep corporate DNS deterministic and offline unless a test overrides it."""
    from unittest.mock import Mock

    resolver = Mock(return_value=[(2, 1, 6, "", ("192.0.2.1", 443))])
    monkeypatch.setattr("gitlab_security_mcp.engine.getaddrinfo", resolver)
    return resolver


@pytest.fixture(autouse=True)
def nvd_clock(monkeypatch, request):
    """Virtualize offline NVD timing without bypassing opt-in live API limits."""
    from gitlab_security_mcp import advisory

    if request.node.path.name == "test_patient_web_live.py":
        return None
    now = [0.0]
    waits = []

    def wait(seconds):
        """Advance the virtual rate-limit clock instead of sleeping."""
        waits.append(seconds)
        now[0] += seconds

    monkeypatch.setattr(advisory, "monotonic", lambda: now[0])
    monkeypatch.setattr(advisory, "sleep", wait)
    monkeypatch.setattr(advisory, "_nvd_last_request", None)
    monkeypatch.setattr(advisory, "_nvd_retry_until", 0.0)
    return now, waits


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


@pytest.fixture(autouse=True)
def _close_http_clients(monkeypatch):
    """Close every httpx client a test opens, including clients the product must not own."""
    import httpx

    opened: list[httpx.Client] = []
    client_type = httpx.Client

    class TrackingClient(client_type):
        """Remember clients so the test fixture can close them."""

        def __init__(self, *args, **kwargs):
            """Open the client and retain it for fixture cleanup."""
            super().__init__(*args, **kwargs)
            opened.append(self)

    monkeypatch.setattr(httpx, "Client", TrackingClient)
    yield
    for client in opened:
        client.close()


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

    from gitlab_security_mcp.qualification import _check_args

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
                for kind in ("build", "runtime", "license_audit")
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
