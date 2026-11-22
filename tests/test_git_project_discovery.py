"""Project selection from real Git metadata without contacting GitLab."""

import json
from contextlib import closing
from unittest.mock import Mock

import httpx
import pytest

from gitlab_security_mcp.commands import assert_allowed
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.git_ops import gitlab_project_from_remote
from gitlab_security_mcp.gitlab_client import FetchResult, GitLabClient
from tests.conftest import commit_all, git


@pytest.mark.parametrize("exit_code,truncated", [(128, False), (0, True)])
def test_remote_branch_query_failure_is_not_reported_as_absence(
    tmp_path, exit_code, truncated
):
    """Stop branch selection on failed or incomplete remote evidence."""
    # Arrange
    from gitlab_security_mcp.git_ops import GitOps

    runner = Mock()
    runner.run.return_value = Mock(exit_code=exit_code, truncated=truncated, stdout="")
    operations = GitOps(tmp_path, runner)

    # Act
    with pytest.raises(RuntimeError, match="absence was not inferred") as failure:
        operations.branch_exists_on_origin("security-fixes-fixture")

    # Assert
    assert "network/VPN" in str(failure.value)


@pytest.mark.parametrize(
    ("remote", "api", "expected"),
    [
        ("https://gitlab.com/team/app.git", "https://gitlab.com/api/v4", "team/app"),
        (
            "git@gitlab.com:team/subgroup/app.git",
            "https://gitlab.com/api/v4",
            "team/subgroup/app",
        ),
        (
            "ssh://git@gitlab.com:2222/team/app.git",
            "https://gitlab.com/api/v4",
            "team/app",
        ),
        ("https://GITLAB.COM:443/team/app", "https://gitlab.com/api/v4", "team/app"),
        ("https://gitlab.com/team%2Fapp.git", "https://gitlab.com/api/v4", "team/app"),
        (
            "https://user:fixture-secret@gitlab.com/team/app.git",
            "https://gitlab.com/api/v4",
            "team/app",
        ),
        (
            "https://git.example:8443/gitlab/team/app.git",
            "https://git.example:8443/gitlab/api/v4",
            "team/app",
        ),
        (
            "git@git.example:team/app.git",
            "https://git.example/gitlab/api/v4",
            "team/app",
        ),
    ],
)
def test_remote_project_path(remote, api, expected):
    """Resolve supported remote formats against the configured API."""
    # Arrange
    # Act
    actual = gitlab_project_from_remote(remote, api)
    # Assert
    assert actual == expected


@pytest.mark.parametrize(
    "remote",
    [
        r"C:\repos\local.git",
        "file:///tmp/local.git",
        "https://github.com/team/app.git",
        "https://gitlab.com.attacker.test/team/app.git",
        "https://gitlab.com:8443/team/app.git",
        "https://gitlab.com/team/app.git?token=fixture-secret",
        "https://gitlab.com/team/app.git#fixture-secret",
        "https://gitlab.com/team/../app.git",
        "https://gitlab.com/team/%252E%252E/app.git",
        "https://gitlab.com/team//app.git",
        "https://gitlab.com/app.git",
        "https://gitlab.com/team/app%00.git",
        "https://gitlab.com/team/a\npp.git",
        "https://gitlab.com:fixture-secret/team/app.git",
        "https://[malformed/team/app.git",
    ],
)
def test_invalid_or_untrusted_remote_is_rejected_without_credentials(remote):
    """Reject ambiguous targets without exposing embedded credentials."""
    # Arrange
    api = "https://gitlab.com/api/v4"
    # Act
    with pytest.raises(ValueError) as error:
        gitlab_project_from_remote(remote, api)
    # Assert
    assert "fixture-secret" not in str(error.value)


def test_web_remote_must_match_relative_installation_prefix():
    """Keep repository paths within the trusted web installation prefix."""
    # Arrange
    api = "https://git.example/gitlab/api/v4"
    # Act
    with pytest.raises(ValueError) as error:
        gitlab_project_from_remote("https://git.example/team/app.git", api)
    # Assert
    assert "GITLAB_API_URL" in str(error.value)


def _client():
    """Return a scripted client that records the selected project path."""
    client = Mock()
    client.api_url = "https://gitlab.com/api/v4"
    client.fetch.side_effect = lambda project: FetchResult(
        ok=True, findings=[], project_path=project, pipeline={}, excluded={}
    )
    return client


def test_each_checkout_selects_its_own_project(repo, tmp_path):
    """Resolve separate checkouts without retaining another project's selector."""
    # Arrange
    client = _client()
    for name in ("first", "second"):
        checkout = tmp_path / name
        checkout.mkdir()
        git(checkout, "init", "-b", "main")
        git(checkout, "remote", "add", "origin", f"git@gitlab.com:team/{name}.git")
        with closing(Engine(checkout, gitlab=client)) as engine:
            engine.state.status = "BRANCH_CREATED"
            # Act
            result = engine.list_security_findings()
        # Assert
        assert result["status"] == "OK"
        assert result["project_path"] == f"team/{name}"
        assert result["project_source"] == "git_origin"
    assert [call.args[0] for call in client.fetch.call_args_list] == [
        "team/first",
        "team/second",
    ]


@pytest.mark.parametrize("override", [None, "42"])
def test_explicit_project_overrides_do_not_require_origin(repo, override):
    """Preserve configured project selectors and per-call override precedence."""
    # Arrange
    client = _client()
    with closing(Engine(repo, gitlab=client, project_id="configured/app")) as engine:
        engine.state.status = "BRANCH_CREATED"
        # Act
        result = engine.list_security_findings(override)
    # Assert
    assert result["status"] == "OK"
    assert result["project_source"] == "explicit"
    client.fetch.assert_called_once_with(override or "configured/app")


@pytest.mark.parametrize(
    "remotes",
    [
        [],
        ["https://github.com/team/app.git"],
        ["https://user:fixture-secret@attacker.test/team/app.git"],
        ["https://gitlab.com/team/app.git", "https://gitlab.com/team/other.git"],
    ],
)
def test_discovery_errors_never_fetch_another_project(
    repo, remotes, caplog, monkeypatch
):
    """Stop before API access when origin is missing, untrusted or ambiguous."""
    # Arrange
    monkeypatch.delenv("GITLAB_PROJECT_ID", raising=False)
    for remote in remotes:
        git(repo, "config", "--add", "remote.origin.url", remote)
    client = _client()
    with closing(Engine(repo, gitlab=client)) as engine:
        engine.state.status = "BRANCH_CREATED"
        # Act
        result = engine.list_security_findings()
        assert engine.state.status == "BRANCH_CREATED"
    # Assert
    assert result["status"] == "ERROR"
    assert result["stage"] == "project_discovery"
    assert "fixture-secret" not in str(result) + caplog.text
    client.fetch.assert_not_called()


def test_discovery_honors_git_worktree_metadata_and_url_rewrites(repo, tmp_path):
    """Let Git resolve linked-worktree metadata and configured URL rewrites."""
    # Arrange
    (repo / "app.txt").write_text("fixture", encoding="utf-8")
    commit_all(repo)
    git(repo, "remote", "add", "origin", "company:team/app.git")
    git(repo, "config", "url.ssh://git@gitlab.com/.insteadOf", "company:")
    checkout = tmp_path / "linked-checkout"
    git(repo, "worktree", "add", "-b", "linked", str(checkout))
    assert (checkout / ".git").is_file()
    client = _client()
    with closing(Engine(checkout, gitlab=client)) as engine:
        engine.state.status = "BRANCH_CREATED"
        # Act
        result = engine.list_security_findings()
    # Assert
    assert result["project_path"] == "team/app"
    client.fetch.assert_called_once_with("team/app")


def test_from_env_uses_trusted_self_hosted_endpoint_without_project_setting(
    repo, monkeypatch
):
    """Use one self-hosted API configuration with repository-specific origins."""
    # Arrange
    monkeypatch.delenv("GITLAB_PROJECT_ID", raising=False)
    monkeypatch.setenv("GITLAB_API_URL", "https://git.example/gitlab/api/v4")
    git(repo, "remote", "add", "origin", "https://git.example/gitlab/team/app.git")
    with closing(Engine.from_env(repo_root=str(repo))) as engine:
        engine.gitlab.fetch = Mock(
            return_value=FetchResult(ok=True, findings=[], project_path="team/app")
        )
        engine.state.status = "BRANCH_CREATED"
        # Act
        result = engine.list_security_findings()
        engine.gitlab.fetch.assert_called_once_with("team/app")
    # Assert
    assert result["status"] == "OK"


def test_shared_project_setting_does_not_replace_another_checkout_origin(
    repo, monkeypatch
):
    """A user-level project id must not redirect a window opened on another repo."""
    # Arrange
    other_project = "other/project"
    origin_project = "team/app"
    monkeypatch.setenv("GITLAB_PROJECT_ID", other_project)
    git(repo, "remote", "add", "origin", f"git@gitlab.com:{origin_project}.git")
    with closing(Engine.from_env(repo_root=str(repo))) as engine:
        engine.gitlab.fetch = Mock(
            return_value=FetchResult(ok=True, findings=[], project_path=origin_project)
        )
        engine.state.status = "BRANCH_CREATED"
        # Act
        result = engine.list_security_findings()
        engine.gitlab.fetch.assert_called_once_with(origin_project)
    # Assert
    assert result["project_source"] == "git_origin"
    assert result["project_path"] == origin_project


def test_project_setting_applies_only_when_origin_cannot_name_a_project(
    repo, monkeypatch
):
    """Keep the environment project only as a fallback for an unreadable origin."""
    # Arrange
    pinned = "other/project"
    monkeypatch.setenv("GITLAB_PROJECT_ID", pinned)
    with closing(Engine.from_env(repo_root=str(repo))) as engine:
        engine.gitlab.fetch = Mock(
            return_value=FetchResult(ok=True, findings=[], project_path=pinned)
        )
        engine.state.status = "BRANCH_CREATED"
        # Act
        result = engine.list_security_findings()
        engine.gitlab.fetch.assert_called_once_with(pinned)
    # Assert
    assert result["project_source"] == "GITLAB_PROJECT_ID"
    assert result["project_path"] == pinned


def test_only_reading_origin_url_is_allowlisted(repo):
    """Permit origin inspection without permitting remote mutation or other URLs."""
    # Arrange
    command = ["git", "remote", "get-url", "--all", "origin"]
    # Act
    assert_allowed(command, repo)
    # Assert
    for args in (
        ["remote", "set-url", "origin", "https://attacker.test/team/app"],
        ["remote", "get-url", "--push", "origin"],
        ["remote", "get-url", "--all", "other"],
    ):
        with pytest.raises(PermissionError):
            assert_allowed(["git", *args], repo)


def test_discovery_uses_the_clients_trusted_api_and_configured_token(repo):
    """Use the inferred path directly in read-only GraphQL at the trusted API."""
    # Arrange
    git(
        repo,
        "remote",
        "add",
        "origin",
        "https://user:fixture-url-secret@git.example/gitlab/team/app.git",
    )
    requests = []

    def handler(request):
        """Validate API destination and return an empty tracked-main report."""
        requests.append(request)
        assert request.method == "POST"
        assert str(request.url) == "https://git.example/gitlab/api/graphql"
        assert request.headers["Authorization"] == "Bearer fixture-token"
        body = json.loads(request.content)
        assert body["variables"]["fullPath"] == "team/app"
        assert body["query"].strip().startswith("query")
        return httpx.Response(
            200,
            json={
                "data": {
                    "project": {
                        "securityTrackedRefs": {
                            "nodes": [
                                {
                                    "id": "gid://gitlab/Security::ProjectTrackedContext/1",
                                    "name": "main",
                                    "refType": "BRANCH",
                                }
                            ],
                            "pageInfo": {"hasNextPage": False},
                        },
                        "vulnerabilities": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": False},
                        },
                    }
                }
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with GitLabClient(
            "fixture-token", "https://git.example/gitlab/api/v4", http=http
        ) as client:
            with closing(Engine(repo, gitlab=client)) as engine:
                engine.state.status = "BRANCH_CREATED"
                # Act
                result = engine.list_security_findings()
    # Assert
    assert result["status"] == "OK"
    assert result["project_path"] == "team/app"
    assert len(requests) == 2


def test_truncated_remote_output_never_fetches_a_project(repo, monkeypatch):
    """Reject incomplete Git output rather than guessing its omitted contents."""
    # Arrange
    client = _client()
    with closing(Engine(repo, gitlab=client)) as engine:
        monkeypatch.setattr(
            engine.git,
            "_git",
            Mock(
                return_value=Mock(
                    exit_code=0,
                    truncated=True,
                    stdout="https://gitlab.com/team/app.git\n",
                )
            ),
        )
        engine.state.status = "BRANCH_CREATED"
        # Act
        result = engine.list_security_findings()
    # Assert
    assert result["status"] == "ERROR"
    client.fetch.assert_not_called()
