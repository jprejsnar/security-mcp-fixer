"""Git fixtures for the local remediation workflow."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    cwd = repo if repo.exists() else repo.parent
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
    )


def commit_all(repo: Path, message: str = "init") -> None:
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
    git(tmp_path, "init", "-b", "main")
    return tmp_path


@pytest.fixture
def cloned_repo(tmp_path: Path) -> Path:
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
