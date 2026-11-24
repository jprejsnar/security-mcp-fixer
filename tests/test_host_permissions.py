"""Saved Copilot approvals for this server's tools."""

import json

import pytest

from gitlab_security_mcp.host_permissions import approve_server_tools, copilot_home


def test_approval_merges_existing_entries_and_is_idempotent(tmp_path):
    """Keep other saved approvals and add one whole-server MCP approval per repo."""
    # Arrange
    home = tmp_path / "copilot"
    home.mkdir()
    repo = tmp_path / "app"
    (repo / ".git").mkdir(parents=True)
    existing = {"kind": "commands", "commandIdentifiers": ["git status"]}
    (home / "permissions-config.json").write_text(
        json.dumps(
            {"locations": {str(repo.resolve()): {"tool_approvals": [existing]}}}
        ),
        encoding="utf-8",
    )

    # Act
    path = approve_server_tools(home, [repo])
    approve_server_tools(home, [repo])

    # Assert
    approvals = json.loads(path.read_text(encoding="utf-8"))["locations"][
        str(repo.resolve())
    ]["tool_approvals"]
    assert approvals == [
        existing,
        {"kind": "mcp", "serverName": "gitlab-security", "toolName": None},
    ]


def test_approval_requires_a_git_root_and_follows_copilot_home(tmp_path, monkeypatch):
    """A subfolder key would never match Copilot's Git-root lookup."""
    # Arrange
    monkeypatch.setenv("COPILOT_HOME", str(tmp_path / "custom"))

    # Act
    with pytest.raises(ValueError, match="Git repository root"):
        approve_server_tools(copilot_home(), [tmp_path])

    # Assert
    assert copilot_home() == tmp_path / "custom"
    assert not (tmp_path / "custom" / "permissions-config.json").exists()
