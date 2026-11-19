"""Verify the closing software-audit choice writes nothing until the host is told to."""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock

import pytest

from gitlab_security_mcp import server
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.software_audit import (
    audit_items,
    audit_report_path,
    project_file_name,
    render_audit_prompt,
)


def _engine(tmp_path):
    """Return one checkout with a known GitLab project path."""
    engine = Engine(tmp_path, gitlab=Mock(), advisory=Mock(), docs=Mock())
    engine.state.status = "FINDINGS_LISTED"
    engine.state.gitlab_project_path = "group/patient-web"
    return engine


def _context():
    """Return a host context whose form is not consulted when a choice is supplied."""
    context = Mock()
    context.elicit = AsyncMock()
    return context


def test_report_path_uses_the_project_and_a_windows_safe_utc_stamp(
    tmp_path, monkeypatch
):
    """Name the home-directory report from the GitLab project and a basic ISO stamp."""
    # Arrange
    monkeypatch.setattr(
        "gitlab_security_mcp.software_audit.Path.home", lambda: tmp_path
    )
    moment = datetime(2026, 11, 18, 19, 56, 7, tzinfo=UTC)

    # Act
    path = audit_report_path(project_file_name("group/patient-web", "fallback"), moment)

    # Assert
    assert path == tmp_path / "patient-web_2026-11-18T195607Z_software_audit_report.md"
    assert ":" not in path.name


@pytest.mark.parametrize(
    "heading",
    ["### 7. Selectable findings", "### Selectable findings"],
)
def test_audit_items_reads_the_prompt_heading(heading):
    """Collect findings under the numbered heading the prompt tells the model to write."""
    # Arrange
    report = "\n".join(
        [
            heading,
            "- R01 | High | src/App.cs:12 | Null on startup",
            "### 8. Later section",
            "- R02 | Low | src/Other.cs:1 | Not in the selectable section",
        ]
    )

    # Act
    items = audit_items(report)

    # Assert
    assert [item["id"] for item in items] == ["R01"]


def test_render_audit_prompt_fills_the_date_and_revision():
    """Replace the prompt placeholders and keep the no-edit instruction."""
    # Arrange
    moment = datetime(2026, 11, 18, tzinfo=UTC)

    # Act
    text = render_audit_prompt(moment, "security-fixes-November-18-2026 abc123")

    # Assert
    assert "{{CURRENT_DATE}}" not in text
    assert "{{GIT_COMMIT_SHA_OR_BRANCH}}" not in text
    assert "2026-11-18" in text
    assert "abc123" in text
    assert "Do **not** apply the fix" in text


def test_generate_report_returns_the_prompt_and_home_path(tmp_path, monkeypatch):
    """Tell the host where to write the report without creating the file."""
    # Arrange
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    context = _context()

    # Act
    result = asyncio.run(
        server.choose_software_audit_action(
            context, str(engine.repo_root), choice="generate_report"
        )
    )

    # Assert
    assert result["status"] == "GENERATE_AUDIT_REPORT"
    assert result["output_path"].startswith(str(home))
    assert result["output_path"].endswith("_software_audit_report.md")
    assert "patient-web_" in result["output_path"]
    assert "Do **not** apply the fix" in result["audit_prompt"]
    assert "Do not commit or push." in result["message"]
    assert not list(home.glob("*.md"))
    assert engine.state.software_audit["choice"] == "generate_report"
    context.elicit.assert_not_called()


def test_fix_choice_requires_an_existing_report(tmp_path, monkeypatch):
    """Do not invent findings when the home directory has no audit report."""
    # Arrange
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    result = asyncio.run(
        server.choose_software_audit_action(
            _context(), str(engine.repo_root), choice="fix_from_report"
        )
    )

    # Assert
    assert result["status"] == "REPORT_REQUIRED"
    assert "Do not invent findings" in result["message"]
    assert engine.state.software_audit["status"] == "REPORT_REQUIRED"


def _report(home, body):
    """Write one project audit report and return its path."""
    report = home / "patient-web_2026-11-18T195607Z_software_audit_report.md"
    report.write_text(body, encoding="utf-8")
    return report


def test_fix_choice_requires_selectable_findings(tmp_path, monkeypatch):
    """Do not invent checkbox rows when the report has no selectable section."""
    # Arrange
    home = tmp_path / "home"
    home.mkdir()
    _report(home, "# Audit\n")
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    result = asyncio.run(
        server.choose_software_audit_action(
            _context(), str(engine.repo_root), choice="fix_from_report"
        )
    )

    # Assert
    assert result["status"] == "ITEMS_REQUIRED"
    assert "Do not invent items" in result["message"]


def test_fix_choice_lists_unchecked_items_before_any_edit(tmp_path, monkeypatch):
    """Offer one checkbox per finding and fix nothing until the human checks one."""
    # Arrange
    home = tmp_path / "home"
    home.mkdir()
    report = _report(
        home,
        "\n".join(
            [
                "| R01 | already in a table |",
                "### 7. Selectable findings",
                "- R01 | High | src/App.cs:12 | Null on startup",
                "- S02 | Conditional | src/Log.cs:4 | Token may be logged",
            ]
        ),
    )
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: False)
    engine = _engine(tmp_path / "checkout")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    context = _context()
    context.session.client_capabilities = None

    # Act
    result = asyncio.run(
        server.choose_software_audit_action(
            context, str(engine.repo_root), choice="fix_from_report"
        )
    )

    # Assert
    assert result["status"] == "SELECTION_REQUIRED"
    assert [item["id"] for item in result["items"]] == ["R01", "S02"]
    assert result["report_path"] == str(report)
    context.elicit.assert_not_called()


def test_fix_choice_keeps_only_checked_items(tmp_path, monkeypatch):
    """Fix the checked finding and leave the unchecked finding unchanged."""
    # Arrange
    home = tmp_path / "home"
    home.mkdir()
    report = _report(
        home,
        "\n".join(
            [
                "### 7. Selectable findings",
                "- R01 | High | src/App.cs:12 | Null on startup",
                "- S02 | Conditional | src/Log.cs:4 | Token may be logged",
            ]
        ),
    )
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    result = asyncio.run(
        server.choose_software_audit_action(
            _context(),
            str(engine.repo_root),
            choice="fix_from_report",
            selected_ids=["R01"],
        )
    )

    # Assert
    assert result["status"] == "FIX_FROM_AUDIT_REPORT"
    assert result["report_path"] == str(report)
    assert [item["id"] for item in result["selected_items"]] == ["R01"]
    assert "Leave every unchecked audit item unchanged." in result["message"]
    assert "Do not commit, push, or open a merge request." in result["message"]


def test_empty_checkbox_selection_fixes_nothing(tmp_path, monkeypatch):
    """Treat a submitted form with no checks as a decision to change nothing."""
    # Arrange
    home = tmp_path / "home"
    home.mkdir()
    _report(
        home,
        "### 7. Selectable findings\n- R01 | High | src/App.cs:12 | Null on startup\n",
    )
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    result = asyncio.run(
        server.choose_software_audit_action(
            _context(),
            str(engine.repo_root),
            choice="fix_from_report",
            selected_ids=[],
        )
    )

    # Assert
    assert result["status"] == "NONE_SELECTED"
    assert result["selected_items"] == []
    assert "Do not change code, commit, or push." in result["message"]


def test_unknown_audit_item_is_rejected(tmp_path, monkeypatch):
    """Reject a checked id that the report did not list."""
    # Arrange
    home = tmp_path / "home"
    home.mkdir()
    _report(
        home,
        "### 7. Selectable findings\n- R01 | High | src/App.cs:12 | Null on startup\n",
    )
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    result = asyncio.run(
        server.choose_software_audit_action(
            _context(),
            str(engine.repo_root),
            choice="fix_from_report",
            selected_ids=["R99"],
        )
    )

    # Assert
    assert result["status"] == "ERROR"
    assert "R99" in result["reason"]


def test_done_choice_changes_nothing(tmp_path, monkeypatch):
    """Stop the run without a report path or a repository edit."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    result = asyncio.run(
        server.choose_software_audit_action(_context(), str(tmp_path), choice="done")
    )

    # Assert
    assert result["status"] == "DONE"
    assert "Do not change code, commit, or push." in result["message"]
    assert "output_path" not in result


def test_unknown_choice_is_rejected(tmp_path, monkeypatch):
    """Reject a choice the human was not offered."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    result = asyncio.run(
        server.choose_software_audit_action(_context(), str(tmp_path), choice="rewrite")
    )

    # Assert
    assert result["status"] == "ERROR"
    assert engine.state.software_audit == {}


def test_open_approval_window_defers_the_audit_choice(tmp_path, monkeypatch):
    """Wait until the false-positive window closes before asking the closing questions."""
    # Arrange
    engine = _engine(tmp_path)
    engine.state.false_positive_approval_form = {
        "presentation": "WINDOWS_DIALOG",
        "status": "AWAITING_HUMAN",
    }
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    result = asyncio.run(
        server.choose_software_audit_action(
            _context(), str(tmp_path), choice="generate_report"
        )
    )

    # Assert
    assert result["status"] == "AWAITING_HUMAN"
    assert engine.state.software_audit == {}
