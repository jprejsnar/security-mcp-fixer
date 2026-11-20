"""Verify the closing software-audit choice writes nothing until the host is told to."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from mcp.types import ClientCapabilities

from gitlab_security_mcp import server, workflow
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.software_audit import (
    REVIEW_PHASES,
    audit_coverage_gaps,
    audit_inventory,
    audit_items,
    audit_report_path,
    project_file_name,
    record_audit_coverage,
    render_audit_prompt,
)


@pytest.fixture(autouse=True)
def isolate_native_choices_and_home(tmp_path, monkeypatch):
    """Keep simulated native flows from opening real windows or writing real home reports."""
    monkeypatch.setattr(
        "gitlab_security_mcp.software_audit.Path.home", lambda: tmp_path
    )
    monkeypatch.setattr(
        server.desktop_approval, "ask_choice", Mock(return_value="fix_from_report")
    )


def _engine(tmp_path, report=None):
    """Return one checkout with a known GitLab project path."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    engine = Engine(tmp_path, gitlab=Mock(), advisory=Mock(), docs=Mock())
    engine.state.status = "FINDINGS_LISTED"
    engine.state.gitlab_project_path = "group/patient-web"
    if report is not None:
        engine.state.software_audit = {
            "status": "AUDIT_REPORT_GENERATED",
            "output_path": str(report),
            "report_complete": True,
        }
    return engine


def _context():
    """Return a host context whose form is not consulted when a choice is supplied."""
    context = Mock()
    context.elicit = AsyncMock()
    context.session.client_capabilities = None
    return context


def test_native_audit_consent_survives_cancelled_host_wait_and_keeps_editor_alive(
    tmp_path, monkeypatch
):
    """Keep the one approval and its eventual audit handoff outside host request deadlines."""
    # Arrange
    engine = _engine(tmp_path / "checkout")
    (engine.repo_root / "app.java").write_text("class App {}", encoding="utf-8")
    workflow.start(engine)
    while engine.state.workflow["current"] < 6:
        workflow.advance(engine)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    monkeypatch.setattr(server, "_BACKGROUND_HEARTBEAT_SECONDS", 0.01)
    monkeypatch.setenv("PROGRESS_CONSOLE", "off")

    async def exercise():
        """Cancel a waiting request, approve later, and observe independent heartbeat snapshots."""
        release = asyncio.Event()

        async def wait():
            """Model a human who takes longer than the original request."""
            await release.wait()
            return {"choice": "generate_report"}

        dialog = SimpleNamespace(wait=wait, close=AsyncMock())
        opened = AsyncMock(return_value=dialog)
        monkeypatch.setattr(server.desktop_approval, "open_choice", opened)
        result = await asyncio.wait_for(
            server.complete_security_run(_context(), str(engine.repo_root)), 1
        )
        assert result.structured_content["status"] == "AWAITING_HUMAN"
        request_id = result.structured_content["request_id"]
        owned = server._desktop_audit_tasks[request_id]
        handoff = asyncio.create_task(
            server.choose_software_audit_action(_context(), str(engine.repo_root))
        )
        await asyncio.sleep(0.02)
        handoff.cancel()
        with pytest.raises(asyncio.CancelledError):
            await handoff
        assert not owned.done()
        repeated = await server.complete_security_run(_context(), str(engine.repo_root))
        assert repeated.structured_content["request_id"] == request_id
        opened.assert_awaited_once()
        release.set()
        audit = await asyncio.wait_for(
            server.choose_software_audit_action(_context(), str(engine.repo_root)), 1
        )
        assert audit["status"] == "GENERATE_AUDIT_REPORT"
        assert audit["coverage"]["files"] == ["app.java"]
        path = engine.repo_root / ".security-mcp" / "progress.json"
        first = await asyncio.to_thread(path.read_text, encoding="utf-8")
        await asyncio.sleep(0.04)
        second = json.loads(await asyncio.to_thread(path.read_text, encoding="utf-8"))
        assert second["updated_at"] != json.loads(first)["updated_at"]
        task = next(item for item in second["tasks"] if item["id"] == "software-audit")
        assert task["status"] == "WAITING_FOR_AI"
        assert (task["completed"], task["total"]) == (0, 1)
        assert "MCP server responsive" in task["message"]
        assert "Last AI update" in task["message"]
        dialog.close.assert_awaited_once()
        return audit

    # Act
    result = asyncio.run(exercise())
    # Assert
    assert result["status"] == "GENERATE_AUDIT_REPORT"
    assert engine.state.software_audit["status"] == "GENERATE_AUDIT_REPORT"


def test_interrupted_host_audit_consent_records_no_scan_instead_of_running(
    tmp_path, monkeypatch
):
    """Make cancellation explicit rather than leaving a generic running job behind."""
    # Arrange
    engine = _engine(tmp_path / "checkout")
    workflow.start(engine)
    while engine.state.workflow["current"] < 6:
        workflow.advance(engine)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: False)
    ctx = _context()
    ctx.session.client_capabilities = ClientCapabilities.model_validate(
        {"elicitation": {}}
    )
    ctx.elicit.side_effect = asyncio.CancelledError

    # Act
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(server.complete_security_run(ctx, str(engine.repo_root)))
    snapshot = json.loads(
        (engine.repo_root / ".security-mcp" / "progress.json").read_text(
            encoding="utf-8"
        )
    )

    # Assert
    assert engine.state.software_audit["status"] == "CONSENT_UNAVAILABLE"
    assert not engine.state.software_audit.get("output_path")
    task = next(item for item in snapshot["tasks"] if item["id"] == "workflow")
    assert task["status"] == "INTERRUPTED"
    assert "no audit is running" in task["message"]


def test_native_audit_fix_checklist_hands_back_checked_items_without_reopening(
    tmp_path, monkeypatch
):
    """Return checked audit work once after the detached native checklist completes."""
    # Arrange
    report = tmp_path / "audit.md"
    report.write_text(
        "### 7. Selectable findings\n- S01 | Medium | app.java:1 | Wrong result\n",
        encoding="utf-8",
    )
    engine = _engine(tmp_path / "checkout", report)
    (engine.repo_root / "app.java").write_text("class App {}", encoding="utf-8")
    (engine.repo_root / "other.java").write_text("class Other {}", encoding="utf-8")
    engine.state.software_audit.update(
        status="AUDIT_IN_PROGRESS",
        report_complete=False,
        coverage=audit_inventory(engine.repo_root),
    )
    workflow.start(engine)
    while engine.state.workflow["current"] < 6:
        workflow.advance(engine)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    monkeypatch.setenv("PROGRESS_CONSOLE", "off")

    async def exercise():
        """Approve the native checkbox after the initiating request has already returned."""
        release = asyncio.Event()

        async def wait():
            """Return only the physically checked item."""
            await release.wait()
            return {"action": "accept", "content": {"finding_0": True}}

        dialog = SimpleNamespace(wait=wait, close=AsyncMock())
        opened = AsyncMock(return_value=dialog)
        monkeypatch.setattr(server.desktop_approval, "open_dialog", opened)
        partial = await server.choose_software_audit_action(
            _context(),
            str(engine.repo_root),
            progress={
                "message": "Read the implemented app path.",
                "files": [
                    {
                        "path": "app.java",
                        "sha256": hashlib.sha256(b"class App {}").hexdigest(),
                        "assessment": "Read the application entry.",
                    }
                ],
            },
        )
        assert partial["continue_review"] is True
        assert partial["remaining_file_count"] == 1
        assert partial["next_files"] == ["other.java"]
        assert set(partial["remaining_phases"]) == REVIEW_PHASES
        assert "do not end the turn" in partial["next_action"]
        incomplete = await server.choose_software_audit_action(
            _context(), str(engine.repo_root), report_ready=True
        )
        assert incomplete["status"] == "AUDIT_INCOMPLETE"
        opened.assert_not_awaited()
        await server.choose_software_audit_action(
            _context(),
            str(engine.repo_root),
            progress={
                "message": "Finished the remaining implementation and five phases.",
                "files": [
                    {
                        "path": "other.java",
                        "sha256": hashlib.sha256(b"class Other {}").hexdigest(),
                        "assessment": "Read the remaining implementation.",
                    }
                ],
                "completed_phases": list(REVIEW_PHASES),
            },
        )
        pending = await server.choose_software_audit_action(
            _context(), str(engine.repo_root), report_ready=True
        )
        assert pending["status"] == "AWAITING_HUMAN"
        assert engine.state.software_audit["report_complete"] is True
        assert opened.call_args.args[1]["finding_0"]["default"] is False
        release.set()
        selected = await asyncio.wait_for(
            server.choose_software_audit_action(_context(), str(engine.repo_root)), 1
        )
        repeated = await server.choose_software_audit_action(
            _context(), str(engine.repo_root)
        )
        opened.assert_awaited_once()
        assert repeated["selected_items"] == selected["selected_items"]
        return selected

    # Act
    result = asyncio.run(exercise())
    # Assert
    assert result["status"] == "FIX_FROM_AUDIT_REPORT"
    assert [item["id"] for item in result["selected_items"]] == ["S01"]


def test_ordered_audit_consent_report_checkboxes_and_failed_fix_report(
    tmp_path, monkeypatch
):
    """Require consent before scanning and outcomes before final reporting."""
    # Arrange
    engine = _engine(tmp_path / "checkout")
    workflow.start(engine)
    while engine.state.workflow["current"] < 6:
        workflow.advance(engine)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: False)
    ctx = _context()
    ctx.session.client_capabilities = ClientCapabilities.model_validate(
        {"elicitation": {}}
    )
    calls = []

    async def elicit(message, schema):
        """Accept scanning first, then approve only one completed-report item."""
        if schema is server.SoftwareAuditConsent:
            assert not engine.state.software_audit.get("output_path")
            calls.append("consent")
            return SimpleNamespace(action="accept", data=schema(run_audit=True))
        assert engine.state.software_audit["report_complete"] is True
        assert all(field.default is False for field in schema.model_fields.values())
        calls.append("audit fixes")
        return SimpleNamespace(action="accept", data=schema(finding_0=True))

    ctx.elicit.side_effect = elicit

    async def exercise():
        """Run audit consent, review completion, human selection and failed-fix reporting."""
        denied = await server.choose_software_audit_action(
            ctx, str(engine.repo_root), choice="fix_from_report"
        )
        assert denied["status"] == "AUDIT_REPORT_REQUIRED"
        request = await server.complete_security_run(ctx, str(engine.repo_root))
        audit = request.structured_content
        assert audit["status"] == "GENERATE_AUDIT_REPORT"
        report = Path(audit["output_path"])
        await asyncio.to_thread(
            report.write_text,
            "### 7. Selectable findings\n- S01 | Medium | src/App.java:12 | Wrong result\n- S02 | Low | src/Other.java:5 | Local defect\n",
            encoding="utf-8",
        )
        await server.choose_software_audit_action(
            ctx,
            str(engine.repo_root),
            progress={
                "message": "All five review phases completed.",
                "completed_phases": list(REVIEW_PHASES),
            },
        )
        selected = await server.choose_software_audit_action(
            ctx, str(engine.repo_root), report_ready=True
        )
        assert [item["id"] for item in selected["selected_items"]] == ["S01"]
        missing = await server.complete_security_run(ctx, str(engine.repo_root))
        assert missing.structured_content["status"] == "CODE_FIX_RESULTS_REQUIRED"
        assert engine.state.workflow["current"] == 6
        return await server.complete_security_run(
            ctx,
            str(engine.repo_root),
            code_results=[
                {
                    "id": "S01",
                    "status": "failed",
                    "reason": "Required database contract cannot be verified.",
                }
            ],
        )

    # Act
    result = asyncio.run(exercise()).structured_content
    # Assert
    assert calls == ["consent", "audit fixes"]
    assert result["status"] == "WORKFLOW_COMPLETE"
    assert (
        "Required database contract cannot be verified."
        in result["final_summary_markdown"]
    )
    assert "S02" in result["final_summary_markdown"]
    assert "Not selected" in result["final_summary_markdown"]


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
@pytest.mark.parametrize(
    "location",
    [
        "src/App.cs:12",
        "[src/App.cs:12](./source/My%20Project/src/App.cs#L12)",
    ],
)
def test_audit_items_reads_the_prompt_heading(heading, location):
    """Collect findings under the numbered heading the prompt tells the model to write."""
    # Arrange
    report = "\n".join(
        [
            heading,
            f"- R01 | High | {location} | Null on startup",
            "### 8. Unfinished work",
            "- R02 | Low | src/Other.cs:1 | No production caller",
            "### 9. Investigated and rejected",
            "- R03 | Low | tests/App.cs:1 | Test-only pattern hit",
        ]
    )

    # Act
    items = audit_items(report)

    # Assert
    assert [item["id"] for item in items] == ["R01"]
    assert items[0]["location"] == location


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
    assert "## File and line links" in text
    assert "#L12" in text
    assert "## Evidence required before a finding" in text
    assert "## Review order" in text
    assert "### 8. Unfinished work" in text
    assert "### 9. Investigated and rejected" in text


def test_generate_report_returns_the_prompt_and_home_path(tmp_path, monkeypatch):
    """Create an honest incomplete report immediately after audit consent."""
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
    assert result["repo_root"] == str(engine.repo_root)
    assert result["output_path"].startswith(str(home))
    assert result["output_path"].endswith("_software_audit_report.md")
    assert "patient-web_" in result["output_path"]
    assert "Do **not** apply the fix" in result["audit_prompt"]
    assert "Do not commit or push." in result["message"]
    report = Path(result["output_path"])
    assert report.is_file()
    assert "INCOMPLETE" in report.read_text(encoding="utf-8")
    assert engine.state.software_audit["choice"] == "generate_report"
    context.elicit.assert_not_called()


@pytest.mark.parametrize("status", ["AUDIT_IN_PROGRESS", "AUDIT_INCOMPLETE"])
def test_audit_continuation_bounds_context_without_losing_recovery(
    tmp_path, monkeypatch, status
):
    """Keep large review histories recoverable without repeating them each turn."""
    # Arrange
    engine = _engine(tmp_path / "checkout")
    paths = [
        f"backend/src/main/java/example/Service{index:03}.java" for index in range(495)
    ]
    coverage = {
        "files": paths,
        "reviews": {
            path: {
                "path": path,
                "sha256": f"{index:064x}",
                "assessment": "Read implementation, caller and handwritten test; traced authorization, persistence, exception output and resource lifetime.",
            }
            for index, path in enumerate(paths[:140])
        },
        "completed_phases": ["entry_points"],
        "generated_exclusions": [],
        "truncated": False,
    }
    original = {
        "status": status,
        "choice": "generate_report",
        "repo_root": str(engine.repo_root),
        "output_path": str(tmp_path / "audit.md"),
        "audit_prompt": render_audit_prompt(datetime.now(UTC), "abc123"),
        "coverage": coverage,
    }
    remaining = paths[140:]
    if status == "AUDIT_INCOMPLETE":
        remaining = [paths[0], *remaining]
        original["coverage_gaps"] = {
            "remaining_files": remaining,
            "total_files": 495,
            "reviewed_files": 139,
            "remaining_phases": [
                "data_access",
                "errors_logs",
                "resource_lifetime",
                "ui_siblings",
            ],
            "truncated": False,
        }
    engine.record_software_audit(original)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setenv("PROGRESS_CONSOLE", "off")

    # Act
    resumed = asyncio.run(
        server.choose_software_audit_action(_context(), str(engine.repo_root))
    )
    recovered = server.get_run_status(str(engine.repo_root), include_audit_details=True)
    default_status = server.get_run_status(str(engine.repo_root))

    # Assert
    assert "audit_prompt" not in resumed
    assert "coverage" not in resumed
    assert resumed["continue_review"] is True
    assert resumed["next_files"] == remaining[:20]
    assert resumed["remaining_file_count"] == len(remaining)
    assert set(resumed["remaining_phases"]) == REVIEW_PHASES - {"entry_points"}
    assert resumed["context_recovery_tool"] == "get_run_status"
    if status == "AUDIT_INCOMPLETE":
        gaps = resumed["coverage_gaps"]
        assert gaps["remaining_files"] == remaining[:20]
        assert gaps["remaining_file_count"] == len(remaining)
        assert gaps["remaining_files_truncated"] is True
    assert recovered["software_audit"] == engine.state.software_audit == original
    compact = default_status["software_audit"]
    assert "audit_prompt" not in compact and "coverage" not in compact
    assert compact["coverage_summary"]["reviewed_files"] == 140
    assert compact["coverage_summary"]["total_files"] == 495
    assert "include_audit_details=True" in compact["full_details"]
    assert len(json.dumps(default_status)) < 5000
    size = len(json.dumps(resumed, separators=(",", ":")))
    assert size < 5000
    assert size < len(json.dumps(original, separators=(",", ":"))) * 0.1


@pytest.mark.parametrize("status", ["FIX_FROM_AUDIT_REPORT", "ERROR", "DONE"])
def test_repeated_audit_polls_do_not_resend_saved_receipts(
    tmp_path, monkeypatch, status
):
    """A host waiting on selected fixes must not receive the full review history each poll."""
    # Arrange
    engine = _engine(tmp_path / "checkout")
    paths = [f"src/Service{index:03}.java" for index in range(495)]
    saved = {
        "status": status,
        "choice": "fix_from_report" if status != "DONE" else "done",
        "output_path": str(tmp_path / "audit.md"),
        "report_complete": True,
        "audit_prompt": render_audit_prompt(datetime.now(UTC), "abc123"),
        "selected_items": [
            {"id": "R01", "severity": "High", "location": "a:1", "problem": "x"}
        ],
        "coverage": {
            "files": paths,
            "reviews": {
                path: {"path": path, "sha256": "a" * 64, "assessment": "x" * 300}
                for path in paths
            },
            "completed_phases": sorted(REVIEW_PHASES),
            "truncated": False,
        },
    }
    engine.record_software_audit(saved)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setenv("PROGRESS_CONSOLE", "off")

    # Act
    polls = [
        asyncio.run(
            server.choose_software_audit_action(_context(), str(engine.repo_root))
        )
        for _ in range(3)
    ]

    # Assert
    for poll in polls:
        assert poll["status"] == status
        assert "coverage" not in poll and "audit_prompt" not in poll
        assert poll["coverage_summary"]["reviewed_files"] == 495
        assert poll["selected_items"] == saved["selected_items"]
        assert len(json.dumps(poll)) < 3000
    assert engine.state.software_audit == saved


def test_progress_draft_is_persisted_but_cannot_be_accepted_as_a_finished_report(
    tmp_path, monkeypatch
):
    """Full file coverage does not turn a progress-only draft into findings."""
    # Arrange
    engine = _engine(tmp_path / "checkout")
    source = engine.repo_root / "app.java"
    source.write_text("class App {}", encoding="utf-8")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    context = _context()
    initial = asyncio.run(
        server.choose_software_audit_action(
            context, str(engine.repo_root), choice="generate_report"
        )
    )
    report = Path(initial["output_path"])
    asyncio.run(
        server.choose_software_audit_action(
            context,
            str(engine.repo_root),
            progress={
                "message": "Read the entry and caller.",
                "files": [
                    {
                        "path": "app.java",
                        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                        "assessment": "Read implemented behavior and callers.",
                    }
                ],
                "completed_phases": sorted(REVIEW_PHASES),
            },
        )
    )
    draft = report.read_text(encoding="utf-8")
    assert "1/1" in draft
    with report.open("a", encoding="utf-8") as stream:
        stream.write("\n### 7. Selectable findings\nNo selectable findings.\n")

    # Act
    result = asyncio.run(
        server.choose_software_audit_action(
            context, str(engine.repo_root), report_ready=True
        )
    )

    # Assert
    assert result["status"] == "ITEMS_REQUIRED"
    assert "draft" in result["message"].lower()
    assert not engine.state.software_audit.get("report_complete")
    context.elicit.assert_not_called()


def test_progress_persistence_never_replaces_host_written_findings(
    tmp_path, monkeypatch
):
    """Keep the AI's report intact when a later progress receipt arrives."""
    # Arrange
    engine = _engine(tmp_path / "checkout")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    initial = asyncio.run(
        server.choose_software_audit_action(
            _context(), str(engine.repo_root), choice="generate_report"
        )
    )
    report = Path(initial["output_path"])
    findings = (
        "# Actual audit findings\n### 7. Selectable findings\nNo selectable findings.\n"
    )
    report.write_text(findings, encoding="utf-8")

    # Act
    asyncio.run(
        server.choose_software_audit_action(
            _context(), str(engine.repo_root), progress={"message": "Review complete."}
        )
    )

    # Assert
    assert report.read_text(encoding="utf-8") == findings


def test_fix_choice_starts_a_scan_when_no_report_exists(tmp_path, monkeypatch):
    """Retain scan-then-select intent instead of stopping at a missing report."""
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
    assert result["status"] == "GENERATE_AUDIT_REPORT"
    assert result["choice"] == "fix_from_report"
    assert result["select_after_report"] is True
    assert "report_ready=True" in result["message"]
    assert engine.state.software_audit["output_path"] == result["output_path"]


def test_scan_progress_then_report_ready_opens_the_exact_report(tmp_path, monkeypatch):
    """Finish the requested scan before offering unchecked native audit findings."""
    # Arrange
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    boxes = Mock(return_value={"action": "accept", "content": {"finding_0": True}})
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    monkeypatch.setattr(server.desktop_approval, "ask_checkboxes", boxes)

    async def exercise():
        """Drive the same continuation the host AI receives after the scan choice."""
        initial = await server.choose_software_audit_action(
            _context(), str(engine.repo_root), choice="fix_from_report"
        )
        pending = await server.choose_software_audit_action(
            _context(), str(engine.repo_root)
        )
        assert pending["output_path"] == initial["output_path"]
        progress = await server.choose_software_audit_action(
            _context(),
            str(engine.repo_root),
            progress={
                "message": "Read controller and caller",
                "reviewed_files": 2,
                "total_files": 4,
            },
        )
        assert progress["progress"]["reviewed_files"] == 2
        assert progress["progress"]["total_files"] == 4
        assert progress["continue_review"] is True
        assert "report_ready=True" in progress["next_action"]
        assert not boxes.called
        await asyncio.to_thread(
            Path(initial["output_path"]).write_text,
            "### 7. Selectable findings\n"
            "- R01 | High | [App.cs:12](./checkout/App.cs#L12) | Null on startup\n",
            encoding="utf-8",
        )
        return await server.choose_software_audit_action(
            _context(), str(engine.repo_root), report_ready=True
        )

    # Act
    result = asyncio.run(exercise())

    # Assert
    assert result["status"] == "FIX_FROM_AUDIT_REPORT"
    assert [item["id"] for item in result["selected_items"]] == ["R01"]
    assert boxes.call_count == 1
    assert boxes.call_args.args[1]["finding_0"]["default"] is False


@pytest.mark.parametrize(
    "body,expected",
    [
        (None, "ERROR"),
        ("# Incomplete audit\n", "ITEMS_REQUIRED"),
        ("### 7. Selectable findings\nNo selectable findings.\n", "CHOICE_REQUIRED"),
    ],
)
def test_report_ready_never_uses_an_unrelated_report(
    tmp_path, monkeypatch, body, expected
):
    """Require the reserved report and distinguish an empty audit from malformed output."""
    # Arrange
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    boxes = AsyncMock()
    monkeypatch.setattr(server, "_ask_audit_items", boxes)

    async def exercise():
        """Create a pending scan, then add a differently named report as a distraction."""
        initial = await server.choose_software_audit_action(
            _context(), str(engine.repo_root), choice="fix_from_report"
        )
        _report(
            home, "### 7. Selectable findings\n- R99 | Low | old.cs:1 | Old finding\n"
        )
        if body is not None:
            await asyncio.to_thread(
                Path(initial["output_path"]).write_text, body, encoding="utf-8"
            )
        else:
            await asyncio.to_thread(Path(initial["output_path"]).unlink)
        return await server.choose_software_audit_action(
            _context(), str(engine.repo_root), report_ready=True
        )

    # Act
    result = asyncio.run(exercise())

    # Assert
    assert result["status"] == expected
    boxes.assert_not_called()


def _report(home, body):
    """Write one project audit report and return its path."""
    report = home / "patient-web_2026-11-18T195607Z_software_audit_report.md"
    report.write_text(body, encoding="utf-8")
    return report


def test_background_handoff_stays_visible_after_the_starting_request(
    tmp_path, monkeypatch
):
    """Deliver worker activity and the scan instruction after the initial tool has returned."""
    # Arrange
    from gitlab_security_mcp.commands import progress_sink

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout")
    engine.state.fix_selection = {"request_id": "owned", "status": "AWAITING_HUMAN"}
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server, "_background_status", {})
    monkeypatch.setattr(server, "_audit_progress_roots", set())
    monkeypatch.setattr(server, "_desktop_fix_selection_tasks", {})
    monkeypatch.setattr(server, "_progress_calls", 0)
    monkeypatch.setattr(server, "_progress_close_pending", False)
    monkeypatch.setattr(server, "_progress_console_enabled", False)
    monkeypatch.setattr(server, "_progress_console_attempted", False)
    monkeypatch.setattr(server, "_progress_console", None)
    monkeypatch.setattr(server, "_BACKGROUND_HEARTBEAT_SECONDS", 0.01)
    console = Mock()
    monkeypatch.setattr(server, "_open_progress_console", Mock(return_value=console))
    engine_status = Mock(
        side_effect=AssertionError("Must not block behind the engine lock")
    )
    monkeypatch.setattr(engine, "get_run_status", engine_status)

    async def exercise():
        """Return the initiating request, keep the worker alive, then collect its handoff."""
        release, started = asyncio.Event(), asyncio.Event()
        waiting = asyncio.Event()
        original_wait = server._wait_for_audit_handoff

        async def wait_for_handoff(selected):
            """Signal only after the handoff has selected its engine and reached the wait."""
            waiting.set()
            await original_wait(selected)

        monkeypatch.setattr(server, "_wait_for_audit_handoff", wait_for_handoff)

        @server._with_background_progress("Fixture background review")
        async def worker(ctx, selected, request_id):
            """Model a human approving work after its original request has returned."""
            started.set()
            await release.wait()
            await asyncio.to_thread(
                progress_sink.get(), "Worker output after original request ended"
            )
            return await asyncio.to_thread(
                server._software_audit_result,
                selected,
                "fix_from_report",
                select_after_report=True,
            )

        async def initiate(context):
            """Create the owned worker and return before the human responds."""
            task = asyncio.create_task(worker(_context(), engine, "owned"))
            server._desktop_fix_selection_tasks["owned"] = task
            task.add_done_callback(
                lambda completed: server._desktop_fix_selection_tasks.pop("owned", None)
            )
            await started.wait()
            return {"status": "AWAITING_HUMAN"}

        request = SimpleNamespace(
            method="tools/call",
            params={"name": "select_security_fixes"},
            session=SimpleNamespace(report_progress=AsyncMock()),
        )
        await server._progress_middleware(request, initiate)
        console.close.assert_not_called()
        live = server.get_run_status(str(engine.repo_root))
        assert live["background_tasks"][0]["status"] == "WAITING_FOR_HUMAN"
        # A silent worker still has a status heartbeat, without a fake percentage.
        await asyncio.sleep(0.03)
        assert any(
            "overall total unknown" in call.args[0]
            for call in console.write.call_args_list
        )
        handoff = asyncio.create_task(
            server.choose_software_audit_action(_context(), str(engine.repo_root))
        )
        await asyncio.wait_for(waiting.wait(), 1)
        assert not handoff.done()
        release.set()
        result = await asyncio.wait_for(handoff, 2)
        console.close.assert_not_called()
        await asyncio.to_thread(
            Path(result["output_path"]).write_text,
            "### 7. Selectable findings\nNo selectable findings.\n",
            encoding="utf-8",
        )

        async def finish(context):
            """Record a completed empty scan through the actual middleware."""
            ready = await server.choose_software_audit_action(
                _context(), str(engine.repo_root), report_ready=True
            )
            assert ready["status"] == "CHOICE_REQUIRED"
            return await server.choose_software_audit_action(
                _context(), str(engine.repo_root), choice="done"
            )

        request.params = {"name": "choose_software_audit_action"}
        completed = await server._progress_middleware(request, finish)
        assert completed["status"] == "DONE"
        console.close.assert_called_once()
        assert not server._audit_progress_roots
        return result

    # Act
    result = asyncio.run(exercise())

    # Assert
    assert result["status"] == "GENERATE_AUDIT_REPORT"
    assert result["select_after_report"] is True
    assert any(
        "Worker output after original request ended" in call.args[0]
        for call in console.write.call_args_list
    )
    assert server._progress_calls == 0
    engine_status.assert_not_called()
    assert not server._desktop_fix_selection_tasks


@pytest.mark.parametrize(
    "progress",
    [
        {"message": "Read caller", "reviewed_files": 2, "total_files": 1},
        {"message": "Read caller", "reviewed_files": -1, "total_files": 1},
        {"message": "Read caller", "reviewed_files": True, "total_files": 1},
        {"message": "Read caller", "reviewed_files": 1},
        {"message": " "},
    ],
)
def test_invalid_audit_progress_does_not_change_the_pending_scan(
    tmp_path, monkeypatch, progress
):
    """Reject invented or malformed counts without losing the generation handoff."""
    # Arrange
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    initial = server._software_audit_result(
        engine, "fix_from_report", select_after_report=True
    )

    # Act
    result = asyncio.run(
        server.choose_software_audit_action(
            _context(),
            str(engine.repo_root),
            progress=progress,
        )
    )

    # Assert
    assert result["status"] == "ERROR"
    assert engine.state.software_audit["status"] == "GENERATE_AUDIT_REPORT"
    assert engine.state.software_audit["output_path"] == initial["output_path"]


def test_fix_choice_requires_selectable_findings(tmp_path, monkeypatch):
    """Do not invent checkbox rows when the report has no selectable section."""
    # Arrange
    home = tmp_path / "home"
    home.mkdir()
    report = _report(home, "# Audit\n")
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout", report=report)
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
    engine = _engine(tmp_path / "checkout", report=report)
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
    engine = _engine(tmp_path / "checkout", report=report)
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
    report = _report(
        home,
        "### 7. Selectable findings\n- R01 | High | src/App.cs:12 | Null on startup\n",
    )
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout", report=report)
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
    report = _report(
        home,
        "### 7. Selectable findings\n- R01 | High | src/App.cs:12 | Null on startup\n",
    )
    monkeypatch.setattr("gitlab_security_mcp.software_audit.Path.home", lambda: home)
    engine = _engine(tmp_path / "checkout", report=report)
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


def test_completion_automatically_offers_the_audit_once(tmp_path, monkeypatch):
    """Prompt after reports even when the security run has no eligible fixes."""
    # Arrange
    engine = _engine(tmp_path)
    engine.git.current_branch = Mock(return_value="security-fixes")
    engine.git.head = Mock(return_value="abc123")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: False)
    context = _context()
    context.session.client_capabilities = ClientCapabilities.model_validate(
        {"elicitation": {"form": {}}}
    )

    # Act
    first = asyncio.run(server.complete_security_run(context, str(tmp_path)))
    second = asyncio.run(server.complete_security_run(context, str(tmp_path)))

    # Assert
    audit = first.structured_content["software_audit"]
    assert audit["status"] == "GENERATE_AUDIT_REPORT"
    assert "## Evidence required before a finding" in audit["audit_prompt"]
    assert (
        second.structured_content["software_audit"]["output_path"]
        == audit["output_path"]
    )
    assert (
        engine.get_run_status()["software_audit"]["status"] == "GENERATE_AUDIT_REPORT"
    )
    context.elicit.assert_not_called()


def test_completion_keeps_audit_choice_available_without_host_forms(
    tmp_path, monkeypatch
):
    """Return actionable choices instead of silently omitting the audit on unsupported hosts."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: False)
    context = _context()
    context.session.client_capabilities = ClientCapabilities.model_validate({})

    # Act
    result = asyncio.run(server.complete_security_run(context, str(tmp_path)))

    # Assert
    audit = result.structured_content["software_audit"]
    assert audit["status"] == "GENERATE_AUDIT_REPORT"
    assert "coverage" in audit
    context.elicit.assert_not_called()


@pytest.mark.parametrize("interrupted", [False, True])
def test_failed_audit_offer_is_explicit_and_does_not_authorize_an_action(
    tmp_path, monkeypatch, interrupted
):
    """Keep host errors and interruptions from stranding a reserved audit choice."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: False)
    context = _context()
    context.session.client_capabilities = ClientCapabilities.model_validate(
        {"elicitation": {"form": {}}}
    )
    context.elicit.side_effect = (
        asyncio.CancelledError() if interrupted else RuntimeError("Host form failed")
    )
    initial = asyncio.run(server.complete_security_run(context, str(tmp_path)))
    Path(initial.structured_content["software_audit"]["output_path"]).write_text(
        "### 7. Selectable findings\n- R01 | Low | App.cs:1 | Local defect\n",
        encoding="utf-8",
    )

    # Act
    if interrupted:
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(
                server.choose_software_audit_action(
                    context, str(tmp_path), report_ready=True
                )
            )
    else:
        report = asyncio.run(
            server.choose_software_audit_action(
                context, str(tmp_path), report_ready=True
            )
        )
        assert report["status"] == "CHOICE_UNAVAILABLE"
    assert engine.state.software_audit["status"] == "CHOICE_UNAVAILABLE"
    assert engine.state.software_audit["choice"] is None
    result = asyncio.run(
        server.choose_software_audit_action(context, str(tmp_path), choice="done")
    )

    # Assert
    assert result["status"] == "DONE"
    context.elicit.assert_awaited_once()
    assert engine.state.changes == []


def test_desktop_approval_offers_audit_only_after_its_window_closes(
    tmp_path, monkeypatch
):
    """Continue the owned Windows workflow without needing another host tool call."""
    # Arrange
    engine = _engine(tmp_path)
    engine.state.false_positive_approval_form = {
        "request_id": "approval-1",
        "status": "AWAITING_HUMAN",
    }
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(
        server,
        "review_false_positives",
        AsyncMock(return_value={"status": "AWAITING_HUMAN"}),
    )
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    context = _context()
    dialog = Mock(wait=AsyncMock(return_value={"action": "cancel"}), close=AsyncMock())

    def choose(*_args):
        """Require the approval process to be closed before opening the next window."""
        dialog.close.assert_awaited_once()
        return "done"

    asked = Mock(side_effect=choose)
    monkeypatch.setattr(server.desktop_approval, "ask_choice", asked)

    async def exercise():
        """Finish a cancelled approval after completion has returned to the host."""
        report = await server.complete_security_run(context, str(tmp_path))
        asked.assert_not_called()
        assert report.structured_content["software_audit"] is None
        await server._finish_desktop_approval(
            context, engine, "approval-1", [], server.SoftwareAuditChoice, dialog
        )

    # Act
    asyncio.run(exercise())

    # Assert
    asked.assert_not_called()
    assert engine.state.software_audit["status"] == "GENERATE_AUDIT_REPORT"
    context.elicit.assert_not_called()


def test_all_blocked_packages_complete_and_offer_audit(tmp_path, monkeypatch):
    """A documented no-safe-release result must not loop back to package review."""
    # Arrange
    engine = _engine(tmp_path)
    plan = {"ecosystem": "Maven", "package": "example:api", "target": "1.67.0"}
    engine.state.findings = [
        {
            "id": "blocked",
            "proposedFix": plan,
            "packageVersionSelection": {
                "status": "BLOCKED",
                "target": None,
                "source": "https://repo.maven.apache.org/maven2/example/api/maven-metadata.xml",
                "review": {
                    "assessment": "All supported releases are incompatible with the installed SDK."
                },
            },
        }
    ]
    engine.state.decisions = {
        "blocked": {
            "decision": "CHANGE_REQUIRED",
            "reason": "A verified advisory floor exists.",
        }
    }
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    asked = Mock(return_value="done")
    monkeypatch.setattr(server.desktop_approval, "ask_choice", asked)
    opened = AsyncMock()
    monkeypatch.setattr(server.desktop_approval, "open_dialog", opened)

    # Act
    result = asyncio.run(server.select_security_fixes(_context(), str(tmp_path)))

    # Assert
    assert result["status"] == "SKIPPED"
    assert result["completion"]["status"] == "REPORT_GENERATED"
    assert result["completion"]["software_audit"]["status"] == "GENERATE_AUDIT_REPORT"
    assert result["blocked_updates"][0]["finding_id"] == "blocked"
    asked.assert_not_called()
    opened.assert_not_called()
    assert engine.state.changes == []


@pytest.mark.parametrize(
    ("name", "content", "encoding"),
    [
        ("src/__generated__/Client.ts", "export class Client {}", "utf-8"),
        ("src/generated-sources/Api.java", "class Api {}", "utf-8"),
        ("src/Model.g.cs", "class Model {}", "utf-8"),
        ("src/client.generated.ts", "export class Client {}", "utf-8"),
        ("src/messages_pb2.py", "DESCRIPTOR = None", "utf-8"),
        ("src/message.pb.go", "package message", "utf-8"),
        (
            "src/Client.java",
            "/*\n * NOTE: This class is auto generated by OpenAPI Generator.\n */\nclass Client {}",
            "utf-8",
        ),
        (
            "src/client.ts",
            "// This file was automatically generated. Do not edit.\nexport {};",
            "utf-8",
        ),
        ("src/Model.cs", "// <auto-generated />\nclass Model {}", "utf-16"),
        (
            "src/schema.sql",
            "-- Generated by schema tool. Do not edit.\nSELECT 1;",
            "utf-8",
        ),
    ],
)
def test_audit_inventory_excludes_generated_source(tmp_path, name, content, encoding):
    """Keep generated outputs out of review even beside handwritten source."""
    # Arrange
    generated = tmp_path / name
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_text(content, encoding=encoding)
    (tmp_path / "app.ts").write_text(
        "// Uses models generated by the schema tool.\n"
        'const note = "This file was automatically generated";\n'
        "// @generated marks an individual member, not this handwritten file.\n",
        encoding="utf-8",
    )

    # Act
    inventory = audit_inventory(tmp_path)

    # Assert
    assert inventory["files"] == ["app.ts"]
    assert not inventory["truncated"]


@pytest.mark.parametrize(
    ("manifest", "content"),
    [
        ("build.gradle", "openApiGenerate { outputDir = 'custom-client' }"),
        (
            "pom.xml",
            "<configuration><output>custom-client</output></configuration>",
        ),
        (
            "App.csproj",
            "<Project><PropertyGroup><CompilerGeneratedFilesOutputPath>"
            "custom-client</CompilerGeneratedFilesOutputPath></PropertyGroup></Project>",
        ),
        (
            "codegen.yml",
            "schema: schema.graphql\ngenerates:\n  custom-client/api.ts:\n    plugins: [typescript]",
        ),
    ],
)
def test_project_generated_outputs_are_excluded_with_current_config_evidence(
    tmp_path, manifest, content
):
    """Support custom output paths without hiding handwritten sibling projects."""
    # Arrange
    project = tmp_path / "backend"
    output = project / "custom-client"
    output.mkdir(parents=True)
    generated = output / "Api.java"
    generated.write_text("class Api {}", encoding="utf-8")
    config = project / manifest
    config.write_text(content, encoding="utf-8")
    handwritten = tmp_path / "frontend" / "custom-client" / "app.ts"
    handwritten.parent.mkdir(parents=True)
    handwritten.write_text("export const app = true;", encoding="utf-8")
    evidence = {
        "path": f"backend/{manifest}",
        "sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "assessment": "The project generator writes its output to custom-client.",
    }
    exclusion = {"path": "backend/custom-client", "evidence": evidence}

    # Act
    updated = record_audit_coverage(
        tmp_path, audit_inventory(tmp_path), [], [], generated_exclusions=[exclusion]
    )
    gaps = audit_coverage_gaps(tmp_path, updated)

    # Assert
    assert updated["generated_exclusions"] == [exclusion]
    assert "backend/custom-client/Api.java" not in updated["files"]
    assert f"backend/{manifest}" in updated["files"]
    assert "frontend/custom-client/app.ts" in updated["files"]
    assert gaps["total_files"] == 2
    with pytest.raises(ValueError, match="outside the inventory"):
        record_audit_coverage(
            tmp_path,
            updated,
            [
                {
                    "path": "backend/custom-client/Api.java",
                    "sha256": hashlib.sha256(generated.read_bytes()).hexdigest(),
                    "assessment": "Must not accept a generated-source receipt.",
                }
            ],
            [],
        )
    config.write_text(content + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="current.*evidence"):
        audit_coverage_gaps(tmp_path, updated)


@pytest.mark.parametrize("output", [".", "..", "build.gradle"])
def test_generated_exclusion_cannot_hide_checkout_or_its_evidence(tmp_path, output):
    """A declaration must be bounded and keep its handwritten evidence reviewable."""
    # Arrange
    config = tmp_path / "build.gradle"
    config.write_text(
        "openApiGenerate { outputDir = 'custom-client' }", encoding="utf-8"
    )
    exclusion = {
        "path": output,
        "evidence": {
            "path": "build.gradle",
            "sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
            "assessment": "Generator output declaration.",
        },
    }

    # Act
    with pytest.raises(ValueError) as raised:
        record_audit_coverage(
            tmp_path,
            audit_inventory(tmp_path),
            [],
            [],
            generated_exclusions=[exclusion],
        )

    # Assert
    assert "generated exclusion" in str(raised.value)


def test_generated_exclusion_prunes_folder_before_opening_source(tmp_path, monkeypatch):
    """Inspect project configuration, not the contents of custom generated trees."""
    # Arrange
    output = tmp_path / "custom-client"
    output.mkdir()
    (output / "Api.java").write_text("class Api {}", encoding="utf-8")
    config = tmp_path / "build.gradle"
    config.write_text(
        "openApiGenerate { outputDir = 'custom-client' }", encoding="utf-8"
    )
    exclusion = {
        "path": "custom-client",
        "evidence": {
            "path": "build.gradle",
            "sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
            "assessment": "Generator output declaration.",
        },
    }
    original_open = Path.open

    def checked_open(path, *args, **kwargs):
        """Fail if inventory opens anything inside the excluded output tree."""
        assert not path.is_relative_to(output)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", checked_open)

    # Act
    inventory = audit_inventory(tmp_path, generated_exclusions=[exclusion])

    # Assert
    assert inventory["files"] == ["build.gradle"]


def test_audit_progress_registers_and_retains_project_generated_file_exclusion(
    tmp_path, monkeypatch
):
    """Apply config-backed exclusions through the MCP handoff, not just a local helper."""
    # Arrange
    engine = _engine(tmp_path / "checkout")
    root = engine.repo_root
    (root / "src").mkdir()
    (root / "src" / "Api.java").write_text("class Api {}", encoding="utf-8")
    (root / "src" / "Service.java").write_text("class Service {}", encoding="utf-8")
    config = root / "build.gradle"
    config.write_text(
        "openApiGenerate { outputDir = 'src/Api.java' }", encoding="utf-8"
    )
    exclusion = {
        "path": "src/Api.java",
        "evidence": {
            "path": "build.gradle",
            "sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
            "assessment": "Resolved generator output is the single file src/Api.java.",
        },
    }
    engine.state.software_audit = {
        "status": "GENERATE_AUDIT_REPORT",
        "output_path": str(tmp_path / "report.md"),
        "coverage": audit_inventory(root),
    }
    monkeypatch.setattr(server, "_engine_for", lambda repo_root: engine)
    monkeypatch.setenv("PROGRESS_CONSOLE", "off")

    # Act
    first = asyncio.run(
        server.choose_software_audit_action(
            _context(),
            str(root),
            progress={
                "message": "Read project generation configuration.",
                "generated_exclusions": [exclusion],
            },
        )
    )
    second = asyncio.run(
        server.choose_software_audit_action(
            _context(), str(root), progress={"message": "Continue handwritten review."}
        )
    )

    # Assert
    for result in (first, second):
        assert result["generated_exclusions"] == [exclusion]
        assert result["next_files"] == ["build.gradle", "src/Service.java"]
        assert result["progress"]["total_files"] == 2
    assert engine.state.software_audit["coverage"]["generated_exclusions"] == [
        exclusion
    ]


def test_generated_source_is_removed_from_coverage_and_rejected_as_a_receipt(tmp_path):
    """Exclude regenerated files from both completion counts and review receipts."""
    # Arrange
    source = tmp_path / "Client.java"
    source.write_text("class Client {}", encoding="utf-8")
    coverage = audit_inventory(tmp_path)
    receipt = {
        "path": "Client.java",
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "assessment": "Read implementation and caller.",
    }
    coverage = record_audit_coverage(tmp_path, coverage, [receipt], [])
    source.write_text("// @generated\nclass Client {}", encoding="utf-8")

    # Act
    gaps = audit_coverage_gaps(tmp_path, coverage)
    updated = record_audit_coverage(tmp_path, coverage, [], [])

    # Assert
    assert gaps["total_files"] == gaps["reviewed_files"] == 0
    assert gaps["remaining_files"] == []
    assert updated["files"] == []
    assert updated["reviews"] == {}
    with pytest.raises(ValueError, match="outside the inventory"):
        record_audit_coverage(tmp_path, updated, [receipt], [])


def test_partial_review_is_rejected_but_one_evidenced_finding_is_allowed(
    tmp_path, monkeypatch
):
    """Require actual coverage, not an arbitrary minimum number of defects."""
    # Arrange
    root = tmp_path / "checkout"
    engine = _engine(root)
    (root / "Controller.java").write_text("class Controller {}", encoding="utf-8")
    (root / "Repository.java").write_text("class Repository {}", encoding="utf-8")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    context = _context()
    context.session.client_capabilities = None

    def receipt(name):
        """Bind each test assessment to the actual fixture source content."""
        return {
            "path": name,
            "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
            "assessment": "Read implementation and callers; evaluated the applicable audit categories.",
        }

    async def exercise():
        """Reject the partial report, then accept the same finding after the review completes."""
        initial = await server.choose_software_audit_action(context, str(root))
        report = Path(initial["output_path"])
        await asyncio.to_thread(
            report.write_text,
            "### 7. Selectable findings\n- R01 | Low | Controller.java:1 | Local defect\n",
            encoding="utf-8",
        )
        await server.choose_software_audit_action(
            context,
            str(root),
            progress={
                "message": "Read controller",
                "files": [receipt("Controller.java")],
                "completed_phases": ["entry_points"],
            },
        )
        partial = await server.choose_software_audit_action(
            context, str(root), report_ready=True
        )
        assert partial["status"] == "AUDIT_INCOMPLETE"
        assert partial["coverage_gaps"]["remaining_files"] == ["Repository.java"]
        assert partial["continue_review"] is True
        assert partial["next_files"] == ["Repository.java"]
        assert "audit_prompt" not in partial
        recovered = server.get_run_status(str(root), include_audit_details=True)[
            "software_audit"
        ]
        assert recovered["audit_prompt"] == initial["audit_prompt"]
        assert recovered["repo_root"] == str(root)
        assert recovered["coverage_gaps"]["remaining_files"] == ["Repository.java"]
        context.elicit.assert_not_called()
        await server.choose_software_audit_action(
            context,
            str(root),
            progress={
                "message": "Reviewed data flow and all remaining categories",
                "files": [receipt("Repository.java")],
                "completed_phases": sorted(REVIEW_PHASES),
            },
        )
        return await server.choose_software_audit_action(
            context, str(root), report_ready=True
        )

    # Act
    result = asyncio.run(exercise())

    # Assert
    assert result["status"] == "CHOICE_REQUIRED"
    assert [item["id"] for item in result["choices"]] == ["fix_from_report", "done"]
    assert engine.state.software_audit["report_complete"] is True
    assert len(engine.state.software_audit["coverage"]["reviews"]) == 2


def test_changed_files_invalidate_a_completed_review(tmp_path, monkeypatch):
    """Do not offer fixes based on stale file-review receipts."""
    # Arrange
    root = tmp_path / "checkout"
    engine = _engine(root)
    source = root / "Service.java"
    source.write_text("class Service {}", encoding="utf-8")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    context = _context()

    async def exercise():
        """Review the original file, change it, then request completion."""
        initial = await server.choose_software_audit_action(context, str(root))
        await server.choose_software_audit_action(
            context,
            str(root),
            progress={
                "message": "Read service and callers",
                "files": [
                    {
                        "path": source.name,
                        "sha256": hashlib.sha256(b"class Service {}").hexdigest(),
                        "assessment": "Reviewed implementation and integration contracts.",
                    }
                ],
                "completed_phases": sorted(REVIEW_PHASES),
            },
        )
        await asyncio.to_thread(
            source.write_text, "class Service { int added; }", encoding="utf-8"
        )
        await asyncio.to_thread(
            Path(initial["output_path"]).write_text,
            "### 7. Selectable findings\nNo selectable findings.\n",
            encoding="utf-8",
        )
        return await server.choose_software_audit_action(
            context, str(root), report_ready=True
        )

    # Act
    result = asyncio.run(exercise())

    # Assert
    assert result["status"] == "AUDIT_INCOMPLETE"
    assert result["coverage_gaps"]["remaining_files"] == ["Service.java"]
    context.elicit.assert_not_called()


def test_mixed_selection_returns_approved_source_work_before_the_audit(
    tmp_path, monkeypatch
):
    """Finish the package phase without silently skipping the human's selected source fix."""
    # Arrange
    engine = _engine(tmp_path)
    engine.state.fix_selection = {
        "status": "APPROVED",
        "selected_ids": ["package", "source"],
        "approved_findings": {"package": {"package_update": {}}, "source": {}},
        "package_execution": {"status": "COMPLETED", "source_ids": ["source"]},
    }
    engine.state.findings = [
        {"id": "source", "title": "Selected source defect"},
        {"id": "unchecked", "title": "Leave this issue alone"},
    ]
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    result = asyncio.run(server.choose_software_audit_action(_context(), str(tmp_path)))

    # Assert
    assert result["status"] == "SOURCE_FIXES_REQUIRED"
    assert result["selected_ids"] == ["source"]
    assert [item["id"] for item in result["findings"]] == ["source"]
    assert engine.state.software_audit == {}
