"""Save Copilot's per-repository "don't ask again" approval for this MCP server.

The VS Code Copilot harness runs on the Copilot CLI agent host, which reads saved
approvals from ``permissions-config.json`` in the Copilot configuration directory.
An ``mcp`` approval with ``toolName: null`` approves every tool on one server for
one repository, the same decision as answering "don't ask again in this repo".
Schema: https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from gitlab_security_mcp.util import atomic_write_text, json_object

DEFAULT_SERVER_NAME = "gitlab-security"
_COPILOT_HOME_ENV = "COPILOT_HOME"
_COPILOT_DIRECTORY = ".copilot"
_PERMISSIONS_FILE = "permissions-config.json"
_MCP_KIND = "mcp"
_RAISE_NOT_A_GIT_REPOSITORY_ROOT = (
    "{} is not a Git repository root; Copilot keys saved approvals by the Git root."
)
_RAISE_INVALID_PERMISSIONS_FIELD = "Invalid {} in {}"
_LOCATION_FIELD = "location {}"


def copilot_home() -> Path:
    """Follow Copilot's own resolution: COPILOT_HOME, otherwise ~/.copilot."""
    configured = os.environ.get(_COPILOT_HOME_ENV, "").strip()
    return Path(configured) if configured else Path.home() / _COPILOT_DIRECTORY


def approve_server_tools(
    home: Path, repositories: list[Path], server: str = DEFAULT_SERVER_NAME
) -> Path:
    """Merge one whole-server MCP approval per repository and keep other approvals."""
    path = home / _PERMISSIONS_FILE
    config = json_object(path.read_text(encoding="utf-8")) if path.is_file() else {}
    locations = config.setdefault("locations", {})
    if not isinstance(locations, dict):
        raise ValueError(_RAISE_INVALID_PERMISSIONS_FIELD.format("locations", path))
    approval = {"kind": _MCP_KIND, "serverName": server, "toolName": None}
    for repository in repositories:
        root = repository.resolve()
        if not (root / ".git").exists():
            raise ValueError(_RAISE_NOT_A_GIT_REPOSITORY_ROOT.format(root))
        location = locations.setdefault(str(root), {})
        approvals = (
            location.setdefault("tool_approvals", [])
            if isinstance(location, dict)
            else None
        )
        if not isinstance(approvals, list):
            raise ValueError(
                _RAISE_INVALID_PERMISSIONS_FIELD.format(
                    _LOCATION_FIELD.format(root), path
                )
            )
        if approval not in approvals:
            approvals.append(dict(approval))
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(config, indent=2) + "\n")
    return path


def main() -> None:
    """Approve this server's tools for the named repositories, then print the file."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repositories", nargs="+", type=Path)
    parser.add_argument("--server", default=DEFAULT_SERVER_NAME)
    args = parser.parse_args()
    try:
        print(approve_server_tools(copilot_home(), args.repositories, args.server))
    except (OSError, ValueError) as exc:
        print(f"GitLab security tool approval: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
