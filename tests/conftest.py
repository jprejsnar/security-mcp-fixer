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
    )


def commit_all(repo: Path, message: str = "init") -> None:
    """Stage and commit fixture files using a local test-only identity."""
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", message],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
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
