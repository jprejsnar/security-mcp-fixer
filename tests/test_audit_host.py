"""Verify bounded automatic continuation without granting audit or fix authority."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from gitlab_security_mcp.audit_host import handle_event, install_hooks


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
    state_path, state, report, payload = audit
    before = state_path.read_bytes()
    handle_event(host, "post", payload)

    first = handle_event(host, "stop", payload)

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
    _, _, report, payload = audit

    assert handle_event("cursor", "stop", payload) == {}
    assert not report.exists()


def test_other_sessions_cannot_continue_the_owned_audit(audit):
    _, _, _, payload = audit
    handle_event("cursor", "post", payload)

    assert (
        handle_event(
            "cursor", "stop", {**payload, "conversation_id": "other-conversation"}
        )
        == {}
    )


@pytest.mark.parametrize("status", ["aborted", "error"])
def test_cancelled_or_failed_turn_is_not_resubmitted(audit, status):
    _, _, _, payload = audit
    handle_event("cursor", "post", payload)

    assert handle_event("cursor", "stop", {**payload, "status": status}) == {}
    assert handle_event("cursor", "stop", payload) == {}


def test_new_user_prompt_does_not_resurrect_a_previous_audit(audit):
    _, _, _, payload = audit
    handle_event("copilot", "post", payload)
    handle_event("copilot", "prompt", {**payload, "prompt": "Explain Rust support."})

    assert handle_event("copilot", "stop", payload) == {}


def test_failed_or_denied_tool_does_not_trigger_an_automatic_retry(audit):
    _, _, _, payload = audit
    handle_event("cursor", "post", payload)
    handle_event("cursor", "failure", {**payload, "failure_type": "permission_denied"})

    assert handle_event("cursor", "stop", payload) == {}


@pytest.mark.parametrize(
    "status", ["SELECTION_REQUIRED", "FIX_FROM_AUDIT_REPORT", "DONE"]
)
def test_human_selection_and_completed_jobs_are_never_auto_approved(audit, status):
    state_path, state, _, payload = audit
    handle_event("cursor", "post", payload)
    state["software_audit"]["status"] = status
    state_path.write_text(json.dumps(state), encoding="utf-8")

    assert handle_event("cursor", "stop", payload) == {}


def test_hook_install_preserves_existing_entries_and_is_idempotent(tmp_path):
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

    paths = install_hooks(tmp_path, python)
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


def test_malformed_hook_input_is_reported_instead_of_claiming_success():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "gitlab_security_mcp.audit_host",
            "--host",
            "cursor",
            "--event",
            "stop",
        ],
        input="not-json",
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "GitLab security audit hook:" in result.stderr
    assert not result.stdout.strip()
