"""Fail-closed git operations. Staging, committing, and pushing are impossible here."""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from urllib.parse import unquote, urlsplit

from gitlab_security_mcp.commands import CommandResult, CommandRunner

MONTHS = (
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)
IN_PROGRESS = (
    "MERGE_HEAD",
    "rebase-merge",
    "rebase-apply",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "BISECT_LOG",
)


def branch_name_for(day: date) -> str:
    """English month name, independent of the machine locale."""
    return f"security-fixes-{MONTHS[day.month - 1]}-{day.day:02d}-{day.year}"


def _porcelain_paths(line: str) -> list[str]:
    """Extract status paths, including both sides of a reported rename."""
    payload = line[3:] if len(line) >= 4 else line
    return [part.strip().strip('"') for part in payload.split(" -> ")]


def is_metadata_path(path: str) -> bool:
    """Return whether a status path is this server's own ``.security-mcp`` output."""
    normalized = path.replace("\\", "/").strip().strip('"')
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized == ".security-mcp" or normalized.startswith(".security-mcp/")


def meaningful_status(porcelain: str) -> list[str]:
    """Ignore untracked metadata outputs, never modified or staged tracked files."""
    dirty: list[str] = []
    for line in porcelain.splitlines():
        if not line.strip():
            continue
        if line.startswith("?? ") and all(
            is_metadata_path(path) for path in _porcelain_paths(line)
        ):
            continue
        dirty.append(line)
    return dirty


def gitlab_project_from_remote(remote: str, api_url: str) -> str:
    """Derive a project path only on the already trusted GitLab API host.

    Remote metadata is not authority to redirect credentials to a new API host.
    SSH transport ports may differ from the API port; web URL origins must match.
    """
    try:
        if any(ord(char) < 32 or ord(char) == 127 for char in remote):
            raise ValueError("Remote contains control characters")
        api = urlsplit(api_url)
        if (
            api.scheme not in {"https", "http"}
            or not api.hostname
            or api.username
            or api.password
        ):
            raise ValueError("Invalid trusted GitLab API URL")
        if api.query or api.fragment or not api.path.rstrip("/").endswith("/api/v4"):
            raise ValueError("Invalid trusted GitLab API URL")
        api_port = api.port or (443 if api.scheme == "https" else 80)
        if "://" in remote:
            parsed = urlsplit(remote)
            if (
                parsed.scheme not in {"https", "http", "ssh", "git"}
                or not parsed.hostname
            ):
                raise ValueError("Unsupported Git remote URL")
            host = parsed.hostname
            path = parsed.path
            remote_port = parsed.port
            web = parsed.scheme in {"https", "http"}
            if parsed.query or parsed.fragment:
                raise ValueError("Remote URL contains query/fragment data")
            if web and (
                parsed.scheme != api.scheme
                or (remote_port or (443 if parsed.scheme == "https" else 80))
                != api_port
            ):
                raise ValueError("Remote and API origins do not match")
        else:
            match = re.fullmatch(r"(?:[^/@:\s]+@)?(\[[^\]]+\]|[^/:\s]+):(.+)", remote)
            if not match:
                raise ValueError("Origin is not a supported network Git remote")
            host, path = match.groups()
            host = host.strip("[]")
            web = False
        if host.lower() != api.hostname.lower():
            raise ValueError("Remote is not on the trusted GitLab API host")
        path = unquote(path).strip("/")
        if web:
            prefix = unquote(api.path.rstrip("/")[: -len("/api/v4")]).strip("/")
            if prefix:
                if not path.startswith(prefix + "/"):
                    raise ValueError(
                        "Remote is outside the configured GitLab URL prefix"
                    )
                path = path[len(prefix) + 1 :]
        path = path.removesuffix(".git")
        parts = path.split("/")
        if len(parts) < 2 or any(
            not part
            or part in {".", ".."}
            or any(char.isspace() or char in "\\%?#\0" for char in part)
            for part in parts
        ):
            raise ValueError("Remote does not identify a namespace/project path")
        return path
    except ValueError:
        raise ValueError(
            "Cannot infer a GitLab project from origin on the configured GitLab API server. "
            "Use a canonical HTTPS/SSH GitLab origin, configure GITLAB_API_URL once "
            "for a trusted self-hosted instance, or supply project_id explicitly. "
            "No credentials were taken from the remote URL."
        ) from None


class GitOps:
    """Read-mostly git helpers. Every call goes through the command allowlist."""

    def __init__(self, repo_root: Path, runner: CommandRunner):
        """Bind Git operations to the repository and its allowlisted runner."""
        self.repo_root = repo_root
        self.runner = runner

    def run(
        self, args: list[str], *, check: bool = True, timeout: int = 120
    ) -> CommandResult:
        """Run one allowlisted git command in this repository."""
        return self._git(args, check=check, timeout=timeout)

    def _git(
        self, args: list[str], *, check: bool = True, timeout: int = 120
    ) -> CommandResult:
        """Route Git through the runner's allowlist and repository boundary."""
        return self.runner.run(["git", *args], timeout=timeout, check=check)

    def ensure_work_tree(self) -> None:
        """Raise unless the repository root is a git working tree."""
        result = self._git(["rev-parse", "--is-inside-work-tree"])
        if result.stdout.strip() != "true":
            raise RuntimeError("This directory is not a git working tree")

    def current_branch(self) -> str:
        """Return the branch name, or an empty string when HEAD is detached."""
        return self._git(["branch", "--show-current"]).stdout.strip()

    def gitlab_project_path(self, api_url: str) -> str:
        """Ask Git for origin so worktrees, submodules and URL rewrites are honored."""
        result = self._git(["remote", "get-url", "--all", "origin"], check=False)
        if result.exit_code != 0 or result.truncated:
            raise RuntimeError(
                "Git origin could not be read completely. Configure a GitLab origin "
                "or supply project_id explicitly to list_security_findings."
            )
        urls = result.stdout.splitlines()
        if len(urls) != 1 or not urls[0].strip():
            raise ValueError(
                "Git origin must have exactly one fetch URL for automatic project discovery"
            )
        return gitlab_project_from_remote(urls[0].strip(), api_url)

    def head(self) -> str:
        """Return the commit id at HEAD."""
        return self._git(["rev-parse", "HEAD"]).stdout.strip()

    def dirty_lines(self) -> list[str]:
        """Return porcelain lines for changes outside ``.security-mcp``."""
        porcelain = self._git(
            ["status", "--porcelain=v1", "--untracked-files=all"]
        ).stdout
        return meaningful_status(porcelain)

    def in_progress_operation(self) -> str | None:
        """Return the marker of a merge, rebase, cherry-pick, revert, or bisect in progress."""
        git_dir_raw = self._git(["rev-parse", "--git-dir"]).stdout.strip()
        git_dir = Path(git_dir_raw)
        if not git_dir.is_absolute():
            git_dir = self.repo_root / git_dir
        for name in IN_PROGRESS:
            if (git_dir / name).exists():
                return name
        return None

    def branch_exists_locally(self, name: str) -> bool:
        """Return whether a local branch with this name exists."""
        result = self._git(["branch", "--list", name], check=False)
        return bool(result.stdout.strip())

    def branch_exists_on_origin(self, name: str) -> bool:
        """Return whether origin has this branch. An unreachable remote counts as no."""
        result = self._git(["ls-remote", "--heads", "origin", name], check=False)
        if result.exit_code != 0:
            return False
        return bool(result.stdout.strip())

    def staged_names(self) -> list[str]:
        """Return staged paths. A git failure raises instead of reporting an empty index."""
        result = self._git(["diff", "--cached", "--name-only"])
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def tracked_security_paths(self) -> set[str]:
        """Protect tracked and staged metadata, including ignored tracked files."""
        result = self._git(["ls-files", "--cached", "-z", "--", ".security-mcp"])
        if result.truncated:
            raise RuntimeError(
                "Tracked security-file inventory was truncated; cleanup is unsafe"
            )
        return set(result.stdout.split("\0")) - {""}

    def diff_summary(self) -> dict[str, str]:
        """Return the tracked diff stat and every changed path, including new files.

        ``git diff`` does not list untracked files, so generated tests would
        be missing from the report without the status listing.
        """
        stat = self._git(["diff", "--stat"])
        return {
            "stat": stat.stdout.strip(),
            "files": "\n".join(self.dirty_lines()),
        }
