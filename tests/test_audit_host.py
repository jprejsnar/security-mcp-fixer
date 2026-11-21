"""Verify bounded automatic continuation without granting audit or fix authority."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from gitlab_security_mcp.audit_host import handle_event, install_hooks, main


@pytest.fixture
def audit(tmp_path, monkeypatch):
    """Provide an observed read-only audit with no application source to open."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    root = tmp_path / "checkout"
    metadata = root / ".security-mcp"
    metadata.mkdir(parents=True)
    state_path = metadata / "run-state.json"
    report = tmp_path / "project_2026-11-19T221910Z_software_audit_report.md"
    state = {
        "software_audit": {
            "status": "AUDIT_IN_PROGRESS",
            "output_path": str(report),
            "coverage": {
                "files": ["app.py", "other.py"],
                "reviews": {"app.py": {"sha256": "a" * 64}},
                "completed_phases": [],
            },
        },
        "workflow": {"current": 6},
    }
    state_path.write_text(json.dumps(state), encoding="utf-8")
    payload = {
        "cwd": str(root),
        "session_id": "audit-owner",
        "conversation_id": "audit-owner",
        "tool_name": "MCP:choose_software_audit_action",
        "tool_input": {"repo_root": str(root)},
        "status": "completed",
        "stop_hook_active": False,
    }
    return state_path, state, report, payload


@pytest.mark.parametrize("host", ["cursor", "copilot", "vscode-local"])
def test_owned_audit_continues_and_preserves_receipts_and_native_output(audit, host):
    """Continue only the owning session, in each host's native response shape."""
    # Arrange
    state_path, state, report, payload = audit
    before = state_path.read_bytes()
    handle_event(host, "post", payload)

    # Act
    first = handle_event(host, "stop", payload)

    # Assert
    if host == "cursor":
        message = first["followup_message"]
    elif host == "copilot":
        assert first["decision"] == "block"
        message = first["reason"]
    else:
        assert first["hookSpecificOutput"]["decision"] == "block"
        message = first["hookSpecificOutput"]["reason"]
    assert "live in-memory handoff" in message
    assert "non-generated" in message
    assert str(report) in message.replace("\\\\", "\\")
    assert "INCOMPLETE" in report.read_text(encoding="utf-8")
    assert state_path.read_bytes() == before

    state["software_audit"]["coverage"]["reviews"]["other.py"] = {"sha256": "b" * 64}
    state_path.write_text(json.dumps(state), encoding="utf-8")
    assert handle_event(host, "stop", {**payload, "stop_hook_active": True})

    with pytest.raises(RuntimeError, match="no new review"):
        handle_event(host, "stop", {**payload, "stop_hook_active": True})


def test_saved_audit_state_alone_never_starts_continuation(audit):
    """Saved JSON without an observed live tool call grants no continuation."""
    # Arrange
    _, _, report, payload = audit

    # Act
    result = handle_event("cursor", "stop", payload)

    # Assert
    assert result == {}
    assert not report.exists()


def test_other_sessions_cannot_continue_the_owned_audit(audit):
    """Another conversation cannot inherit the owner's continuation."""
    # Arrange
    _, _, _, payload = audit
    handle_event("cursor", "post", payload)

    # Act
    result = handle_event(
        "cursor", "stop", {**payload, "conversation_id": "other-conversation"}
    )

    # Assert
    assert result == {}


@pytest.mark.parametrize("status", ["aborted", "error"])
def test_cancelled_or_failed_turn_is_not_resubmitted(audit, status):
    """An aborted or failed turn deactivates continuation instead of retrying it."""
    # Arrange
    _, _, _, payload = audit
    handle_event("cursor", "post", payload)

    # Act
    stopped = handle_event("cursor", "stop", {**payload, "status": status})

    # Assert
    assert stopped == {}
    assert handle_event("cursor", "stop", payload) == {}


def test_new_user_prompt_does_not_resurrect_a_previous_audit(audit):
    """A new human prompt ends automatic continuation of the earlier audit."""
    # Arrange
    _, _, _, payload = audit
    handle_event("copilot", "post", payload)
    handle_event("copilot", "prompt", {**payload, "prompt": "Explain Rust support."})

    # Act
    result = handle_event("copilot", "stop", payload)

    # Assert
    assert result == {}


def test_failed_or_denied_tool_does_not_trigger_an_automatic_retry(audit):
    """A denied tool call must not be retried by the stop hook."""
    # Arrange
    _, _, _, payload = audit
    handle_event("cursor", "post", payload)
    handle_event("cursor", "failure", {**payload, "failure_type": "permission_denied"})

    # Act
    result = handle_event("cursor", "stop", payload)

    # Assert
    assert result == {}


@pytest.mark.parametrize(
    "status", ["SELECTION_REQUIRED", "FIX_FROM_AUDIT_REPORT", "DONE"]
)
def test_human_selection_and_completed_jobs_are_never_auto_approved(audit, status):
    """Human selection and finished audits are never continued automatically."""
    # Arrange
    state_path, state, _, payload = audit
    handle_event("cursor", "post", payload)
    state["software_audit"]["status"] = status
    state_path.write_text(json.dumps(state), encoding="utf-8")

    # Act
    result = handle_event("cursor", "stop", payload)

    # Assert
    assert result == {}


def test_hook_install_preserves_existing_entries_and_is_idempotent(tmp_path):
    """Merge hooks without replacing user entries, and do not duplicate them."""
    # Arrange
    cursor = tmp_path / ".cursor" / "hooks.json"
    cursor.parent.mkdir()
    existing = {"command": "existing-user-hook", "timeout": 5}
    cursor.write_text(
        json.dumps(
            {
                "version": 1,
                "custom": True,
                "hooks": {"stop": [existing]},
            }
        ),
        encoding="utf-8",
    )
    python = tmp_path / "runtime with spaces" / "python.exe"

    # Act
    paths = install_hooks(tmp_path, python)

    # Assert
    assert install_hooks(tmp_path, python) == paths

    config = json.loads(cursor.read_text(encoding="utf-8"))
    assert config["custom"] is True
    assert config["hooks"]["stop"][0] == existing
    assert len(config["hooks"]["stop"]) == 2
    assert "--host cursor --event stop" in config["hooks"]["stop"][1]["command"]
    copilot = json.loads(paths[1].read_text(encoding="utf-8"))
    assert set(copilot["hooks"]) == {
        "PostToolUse",
        "PostToolUseFailure",
        "UserPromptSubmit",
        "Stop",
    }


def test_install_command_prints_written_hook_paths(tmp_path, monkeypatch, capsys):
    """Successful installation lists each written hook file on stdout."""
    # Arrange
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(sys, "argv", ["audit_host", "--install"])

    # Act
    main()
    captured = capsys.readouterr()

    # Assert
    lines = captured.out.splitlines()
    assert lines
    assert captured.err == ""
    assert [Path(line) for line in lines] == install_hooks(
        tmp_path, Path(sys.executable)
    )


def test_malformed_hook_input_is_reported_instead_of_claiming_success():
    """Invalid hook JSON exits nonzero with a diagnostic and no host instruction."""
    # Arrange
    argv = [
        sys.executable,
        "-m",
        "gitlab_security_mcp.audit_host",
        "--host",
        "cursor",
        "--event",
        "stop",
    ]

    # Act
    result = subprocess.run(
        argv,
        input="not-json",
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=60,
    )

    # Assert
    assert result.returncode == 1
    assert "GitLab security audit hook:" in result.stderr
    assert not result.stdout.strip()


def test_continuation_turns_are_capped_independent_of_repository_size(audit):
    """Each automatic continuation is a paid AI turn; a large inventory must not raise the cap."""
    # Arrange
    from gitlab_security_mcp import audit_host

    state_path, state, _, payload = audit
    files = [f"src/File{index}.java" for index in range(495)]
    state["software_audit"]["coverage"] = {
        "files": files,
        "reviews": {},
        "completed_phases": [],
    }
    state_path.write_text(json.dumps(state), encoding="utf-8")
    handle_event("cursor", "post", payload)
    turns = 0

    # Act
    with pytest.raises(RuntimeError, match="safe turn budget"):
        for name in files:
            state["software_audit"]["coverage"]["reviews"][name] = {"sha256": "a" * 64}
            state_path.write_text(json.dumps(state), encoding="utf-8")
            assert handle_event("cursor", "stop", payload)["followup_message"]
            turns += 1

    # Assert
    assert turns == audit_host._MAX_CONTINUATIONS < len(files)


@pytest.mark.parametrize("host", ["cursor", "copilot", "vscode-local"])
def test_host_differences_come_only_from_its_profile(audit, host):
    """Shared continuation logic is host-agnostic; each profile supplies the native shape."""
    # Arrange
    from gitlab_security_mcp.audit_host import _MAX_CONTINUATIONS, HOSTS, _continuation

    _, _, report, payload = audit
    root = Path(payload["cwd"]).resolve()
    handle_event(host, "post", payload)
    profile = HOSTS[host]

    # Act
    reply = handle_event(host, "stop", payload)

    # Assert
    message = _continuation(root, report)
    assert reply == profile.reply(message)
    assert "choose_software_audit_action" in message
    for rule in (
        "run prechecks or create another run",
        "generator configuration and exclude all generated outputs",
        "finish every file/phase",
        "fix only checked items",
        "Do not commit or push",
    ):
        assert rule in message
    assert profile.max_turns <= _MAX_CONTINUATIONS
