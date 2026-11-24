"""Verify human-only issue selection before MCP remediation operations."""

import asyncio
import json
import threading
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from mcp.types import ClientCapabilities

from gitlab_security_mcp import server, workflow
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.report import render
from gitlab_security_mcp.state import RunState


def _ordered_engine(tmp_path, monkeypatch, job=3):
    """Provide one ordered run with separate package and source candidates."""
    engine = _engine(tmp_path)
    engine.state.findings.append(
        {
            "id": "source",
            "title": "Reachable source issue",
            "severity": "high",
            "category": "sast",
            "location": {"file": "src/App.java", "startLine": 12},
        }
    )
    engine.state.decisions["source"] = {
        "decision": "CONFIRMED_VULNERABILITY",
        "reason": "A reachable caller triggers this issue.",
    }
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: False)
    workflow.start(engine)
    while engine.state.workflow["current"] < job:
        workflow.advance(engine)
    return engine


def test_ordered_jobs_reject_early_dismissal_source_and_audit(tmp_path, monkeypatch):
    """Prevent remote approval and audit work before the package job completes."""
    # Arrange
    engine = _ordered_engine(tmp_path, monkeypatch)
    ctx = _context()

    async def exercise():
        """Attempt two out-of-order jobs."""
        dismissal = await server.submit_false_positive_approvals(ctx, str(tmp_path))
        audit = await server.choose_software_audit_action(
            ctx, str(tmp_path), choice="generate_report"
        )
        return dismissal, audit

    # Act
    dismissal, audit = asyncio.run(exercise())
    # Assert
    assert dismissal["status"] == audit["status"] == "JOB_ORDER_REQUIRED"
    assert [item["id"] for item in engine.fix_selection_candidates()["candidates"]] == [
        "one",
        "two",
    ]
    assert not engine.state.software_audit
    ctx.elicit.assert_not_called()
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_package_job_cannot_finish_before_selected_update_attempt(
    tmp_path, monkeypatch
):
    """Do not silently skip an approved package before any execution attempt."""
    # Arrange
    engine = _ordered_engine(tmp_path, monkeypatch)
    candidates = engine.fix_selection_candidates()["candidates"]
    engine.record_fix_selection(candidates, ["one"], "APPROVED")
    # Act
    result = asyncio.run(server.complete_security_run(_context(), str(tmp_path)))
    # Assert
    assert result.structured_content["status"] == "PACKAGE_FIXES_REQUIRED"
    assert engine.state.workflow["current"] == 3


def test_ordered_background_completion_names_failure_and_next_tool(
    tmp_path, monkeypatch, caplog
):
    """Use the ordered package receipt instead of an unrelated legacy selection."""
    # Arrange
    engine = _ordered_engine(tmp_path, monkeypatch)
    engine.state.workflow["package_selection"] = {
        "request_id": "ordered",
        "status": "APPROVED",
        "package_execution": {"status": "PARTIAL_FAILURE"},
    }
    engine.state.fix_selection = {"request_id": "legacy", "status": "APPROVED"}
    monkeypatch.setattr(server, "_background_status", {})
    monkeypatch.setattr(server, "_progress_calls", 0)
    monkeypatch.setattr(server, "_progress_console_enabled", False)
    monkeypatch.setattr(server, "_console_for_progress", lambda: None)
    monkeypatch.setattr(server, "_finish_progress_call", Mock(return_value=None))

    @server._with_background_progress("Security fix selection and execution")
    async def worker(ctx, selected, request_id):
        """Complete a fixture batch whose unresolved updates are already recorded."""
        return {"status": "PARTIAL_FAILURE"}

    # Act
    asyncio.run(worker(_context(), engine, "ordered"))

    # Assert
    receipt = server._background_for(engine)[0]
    assert receipt["status"] == receipt["outcome"] == "PARTIAL_FAILURE"
    assert receipt["next_tool"] == "complete_security_run"
    assert "Next: complete_security_run" in caplog.text
    assert "see run status" not in receipt["current_step"]


def test_precheck_branch_and_download_tools_start_jobs_in_order(tmp_path, monkeypatch):
    """Verify real MCP entry points initialize and advance the sequential run."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(
        engine, "run_prechecks", Mock(return_value={"status": "PRECHECK_PASSED"})
    )
    monkeypatch.setattr(
        engine, "pull_main_twice", Mock(return_value={"status": "PULLED"})
    )
    monkeypatch.setattr(
        engine,
        "create_security_branch",
        Mock(return_value={"status": "BRANCH_CREATED"}),
    )
    monkeypatch.setattr(
        engine,
        "list_security_findings",
        Mock(return_value={"status": "OK", "findings": engine.state.findings}),
    )

    # Act
    server.run_prechecks(str(tmp_path))
    denied = server.list_security_findings(repo_root=str(tmp_path))
    server.pull_main_twice(str(tmp_path))
    assert engine.state.workflow["current"] == 1
    server.create_security_branch(str(tmp_path))
    assert engine.state.workflow["current"] == 2
    server.list_security_findings(repo_root=str(tmp_path))

    # Assert
    assert denied["status"] == "JOB_ORDER_REQUIRED"
    assert engine.state.workflow["current"] == 3
    assert [item["status"] for item in engine.state.workflow["jobs"]] == [
        "FINISHED",
        "FINISHED",
        "RUNNING",
        "PENDING",
        "PENDING",
        "PENDING",
        "PENDING",
    ]
    engine.list_security_findings.assert_called_once()


def test_source_validation_keeps_prior_package_permission_without_allowing_more_package_edits(
    tmp_path, monkeypatch
):
    """Validate both approved batches, but never let source consent authorize new package edits."""
    # Arrange
    engine = _ordered_engine(tmp_path, monkeypatch)
    engine.record_fix_selection(
        engine.fix_selection_candidates()["candidates"], ["one"], "APPROVED"
    )
    engine.state.workflow["package_selection"] = deepcopy(engine.state.fix_selection)
    engine.state.fix_selection = {}
    workflow.advance(engine)
    workflow.advance(engine)
    engine.record_fix_selection(
        engine.fix_selection_candidates()["candidates"], ["source"], "APPROVED"
    )
    engine.state.changes = [{"finding_id": "one"}, {"finding_id": "source"}]
    validation = Mock(return_value={"status": "VALIDATION_COMPLETE"})
    edits = Mock()
    monkeypatch.setattr(engine, "run_validation_matrix", validation)
    monkeypatch.setattr(engine, "apply_minimal_fix", edits)

    # Act
    checked = engine.run_approved_fix("run_validation_matrix")
    denied = engine.run_approved_fix("apply_minimal_fix", "one")

    # Assert
    assert checked["status"] == "VALIDATION_COMPLETE"
    assert denied["status"] == "FIX_APPROVAL_REQUIRED"
    validation.assert_called_once()
    edits.assert_not_called()


def test_package_completion_then_false_positives_then_new_source_form(
    tmp_path, monkeypatch
):
    """Separate source consent from package consent even after package edits exist."""
    # Arrange
    engine = _ordered_engine(tmp_path, monkeypatch)
    candidates = engine.fix_selection_candidates()["candidates"]
    engine.record_fix_selection(
        candidates, [], "SKIPPED", "Developer skipped package updates."
    )
    engine.state.changes = [
        {"finding_id": "unrelated-previous-config", "status": "APPLIED"}
    ]
    calls = []

    async def dismiss(ctx, root):
        """Model the independent human false-positive window."""
        assert engine.state.workflow["current"] == 4
        calls.append("false positives")
        engine.state.false_positive_approval_form = {"status": "CANCELLED"}
        return {"status": "CANCELLED"}

    monkeypatch.setattr(server, "submit_false_positive_approvals", dismiss)

    async def elicit(message, schema):
        """Approve only the source-only checklist after remote review."""
        assert engine.state.workflow["current"] == 5
        assert "SOURCE/CONFIG" in message
        assert len(schema.model_fields) == 1
        assert "Reachable source issue" in schema.model_fields["finding_0"].title
        assert schema.model_fields["finding_0"].default is False
        calls.append("source checkboxes")
        return SimpleNamespace(action="accept", data=schema(finding_0=True))

    ctx = _context()
    ctx.elicit.side_effect = elicit

    async def exercise():
        """Advance past package work and obtain a fresh source selection."""
        completion = await server.complete_security_run(ctx, str(tmp_path))
        assert completion.structured_content["status"] == "SOURCE_SELECTION_REQUIRED"
        selected = await server.select_security_fixes(ctx, str(tmp_path))
        pending = await server.complete_security_run(ctx, str(tmp_path))
        return selected, pending

    # Act
    selected, pending = asyncio.run(exercise())
    # Assert
    assert selected["selected_ids"] == ["source"]
    assert pending.structured_content["status"] == "SOURCE_FIXES_REQUIRED"
    assert engine.state.workflow["current"] == 5
    assert engine.state.workflow["package_selection"]["selected_ids"] == []
    assert calls == ["false positives", "source checkboxes"]


@pytest.mark.parametrize("source_selected", [None, False, True])
@pytest.mark.parametrize(
    "protocol,request_state",
    [("2025-11-25", None), ("2026-07-28", "ended-package-request")],
)
def test_native_completion_consumes_next_selection_without_another_host_call(
    tmp_path,
    monkeypatch,
    isolate_closing_audit,
    source_selected,
    protocol,
    request_state,
):
    """Continue package consent through fresh source consent or directly to audit."""
    # Arrange
    engine = _ordered_engine(tmp_path, monkeypatch)
    engine.state.findings = [
        item
        for item in engine.state.findings
        if item["id"] != "fp"
        and (source_selected is not None or item["id"] != "source")
    ]
    _native_lifecycle(monkeypatch, engine)
    ctx = _context(supported=False)
    ctx.protocol_version = protocol
    ctx.request_state = request_state
    package_dialog = Mock(close=AsyncMock())
    source_dialog = Mock(
        close=AsyncMock(),
        wait=AsyncMock(
            return_value={
                "action": "accept",
                "content": {"finding_0": bool(source_selected)},
            }
        ),
    )
    opened = AsyncMock(side_effect=[package_dialog, source_dialog])
    monkeypatch.setattr(server.desktop_approval, "open_dialog", opened)
    progress = Mock()
    monkeypatch.setattr(server, "_editor_progress", progress)
    workflow_progress = Mock()
    monkeypatch.setattr(workflow, "publish", workflow_progress)

    async def exercise():
        """Release package consent and await the automatically opened next window."""
        ready = asyncio.Event()

        async def answer():
            """Submit an empty package selection only after the tool returns."""
            await ready.wait()
            return {"action": "accept", "content": {}}

        package_dialog.wait = answer
        pending = await server.select_security_fixes(ctx, str(tmp_path))
        task = server._desktop_fix_selection_tasks[pending["request_id"]]
        ready.set()
        await task
        await asyncio.gather(*tuple(server._desktop_fix_selection_tasks.values()))

    # Act
    asyncio.run(exercise())

    # Assert
    assert engine.state.workflow["package_selection"]["selected_ids"] == []
    assert opened.await_count == (1 if source_selected is None else 2)
    if source_selected is not None:
        properties = opened.call_args_list[1].args[1]
        assert len(properties) == 1
        assert "Reachable source issue" in properties["finding_0"]["title"]
        assert properties["finding_0"]["default"] is False
        source_dialog.close.assert_awaited_once()
    if source_selected:
        assert engine.state.workflow["current"] == server.JOB_SOURCE
        assert engine.state.fix_selection["selected_ids"] == ["source"]
        assert any(
            call.kwargs.get("status") == "WAITING_FOR_AI"
            for call in progress.call_args_list
        )
        assert workflow_progress.call_args.kwargs["status"] == "WAITING_FOR_AI"
        isolate_closing_audit.assert_not_awaited()
    else:
        assert engine.state.workflow["current"] == server.JOB_AUDIT
        isolate_closing_audit.assert_awaited_once()
    ctx.elicit.assert_not_called()
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_native_continuation_rejects_a_replaced_run(tmp_path, monkeypatch):
    """A late window must not open another dialog in a replacement run."""
    # Arrange
    engine = _ordered_engine(tmp_path, monkeypatch)
    owner_state = engine.state
    engine.state = deepcopy(owner_state)
    complete = AsyncMock()
    monkeypatch.setattr(server, "complete_security_run", complete)

    # Act
    with pytest.raises(RuntimeError, match="replaced run"):
        asyncio.run(server._resume_desktop_workflow(_context(), engine, owner_state))

    # Assert
    complete.assert_not_awaited()


def test_failed_source_outcome_and_declined_audit_still_display_final_report(
    tmp_path, monkeypatch
):
    """Record failed source attempts and finish reporting even when audit is declined."""
    # Arrange
    engine = _ordered_engine(tmp_path, monkeypatch, job=5)
    candidates = engine.fix_selection_candidates()["candidates"]
    engine.record_fix_selection(candidates, ["source"], "APPROVED")
    consent = AsyncMock(
        return_value=SimpleNamespace(
            action="accept", data=server.SoftwareAuditConsent(run_audit=False)
        )
    )
    ctx = _context()
    ctx.elicit = consent
    # This fixture normally isolates audit UI; here exercise the real consent path.
    monkeypatch.setattr(server, "_offer_software_audit", _REAL_AUDIT_OFFER)

    async def exercise():
        """Reject an unchecked outcome, then report a real selected-fix blocker."""
        invalid = await server.complete_security_run(
            ctx,
            str(tmp_path),
            code_results=[
                {"id": "unselected", "status": "failed", "reason": "Not approved."}
            ],
        )
        assert invalid.is_error
        assert engine.state.workflow["current"] == 5
        return await server.complete_security_run(
            ctx,
            str(tmp_path),
            code_results=[
                {
                    "id": "source",
                    "status": "failed",
                    "reason": "Required API contract is unavailable.",
                    "validation": "Not run; cannot safely implement.",
                }
            ],
        )

    # Act
    result = asyncio.run(exercise()).structured_content
    # Assert
    assert result["status"] == "WORKFLOW_COMPLETE"
    assert "Required API contract is unavailable." in result["final_summary_markdown"]
    assert "2.0.0" in result["final_summary_markdown"]
    assert not engine.state.software_audit.get("output_path")
    assert engine.state.workflow["jobs"][5]["status"] == "SKIPPED"
    assert engine.state.workflow["jobs"][6]["status"] == "FINISHED"
    consent.assert_awaited_once()
    report = tmp_path / ".security-mcp" / "reports" / "unresolved-remediation.md"
    assert report.read_text(encoding="utf-8") == result["final_summary_markdown"]
    workflow.activity(engine, "Late worker cleanup")
    receipt = json.loads(
        (tmp_path / ".security-mcp" / "progress.json").read_text(encoding="utf-8")
    )
    task = next(item for item in receipt["tasks"] if item["id"] == "workflow")
    assert task["status"] == "FINISHED"
    assert (task["completed"], task["total"], task["unit"]) == (7, 7, "jobs finished")


def test_source_fixed_outcome_uses_the_server_build(tmp_path, monkeypatch):
    """A fixed source outcome leaves validation empty and the server records the build."""
    # Arrange
    engine = _ordered_engine(tmp_path, monkeypatch, job=5)
    engine.record_fix_selection(
        engine.fix_selection_candidates()["candidates"], ["source"], "APPROVED"
    )
    # Act
    result = asyncio.run(
        server.complete_security_run(
            _context(),
            str(tmp_path),
            code_results=[
                {"id": "source", "status": "fixed", "reason": "Changed caller."}
            ],
        )
    )
    # Assert
    stored = engine.state.workflow["code_results"]["gitlab:source"]
    assert stored["validation"].startswith("Server production build")
    assert "unit tests were not run" in stored["validation"]
    assert result.structured_content["status"] != "ERROR"


@pytest.mark.parametrize("interruption", [1, 2])
def test_final_archive_retry_and_late_logs_reuse_one_zip(
    tmp_path, monkeypatch, isolated_log_archives, interruption
):
    """Retry a partial finalization without losing archived logs or leaking late logs."""
    # Arrange
    import zipfile

    engine = _ordered_engine(tmp_path, monkeypatch, job=7)
    monkeypatch.setattr(engine, "generate_local_report", Mock(return_value={}))
    first_log = tmp_path / ".security-mcp" / "first.log"
    first_log.write_bytes(b"first")
    archive = server.archive_run_logs
    timestamps = []

    def interrupted_cleanup(root, project, when):
        """Simulate a cleanup failure after the first ZIP was safely published."""
        timestamps.append(when)
        result = archive(root, project, when)
        if len(timestamps) == interruption:
            raise OSError("cleanup interrupted")
        return result

    monkeypatch.setattr(server, "archive_run_logs", interrupted_cleanup)
    ctx = _context()

    # Act
    first = asyncio.run(
        server.complete_security_run(ctx, str(tmp_path))
    ).structured_content
    late_log = tmp_path / ".security-mcp" / "late.log"
    late_log.write_bytes(b"late")
    second = asyncio.run(
        server.complete_security_run(ctx, str(tmp_path))
    ).structured_content
    late_log.write_bytes(b"later")
    third = asyncio.run(
        server.complete_security_run(ctx, str(tmp_path))
    ).structured_content

    # Assert
    assert first["log_archive"]["status"] == "ERROR"
    assert (
        second["log_archive"]["status"] == third["log_archive"]["status"] == "ARCHIVED"
    )
    assert len(set(timestamps)) == 1
    assert len(list(isolated_log_archives.glob("*.zip"))) == 1
    with zipfile.ZipFile(third["log_archive"]["path"]) as zipped:
        assert zipped.read("first.log") == b"first"
        assert zipped.read("late.log") == b"later"
        assert zipped.testzip() is None
        archived_state = json.loads(zipped.read("run-state.json"))
        assert (
            archived_state["workflow"]["final_result"]
            == engine.state.workflow["final_result"]
        )
        assert "reports/unresolved-remediation.md" in zipped.namelist()
    assert not first_log.exists()
    assert not late_log.exists()
    assert engine.state.workflow["final_result"]["log_archive"] == third["log_archive"]


_REAL_AUDIT_OFFER = server._offer_software_audit


@pytest.fixture(autouse=True)
def isolate_closing_audit(monkeypatch):
    """Keep selection tests from opening the separately tested audit dialog."""
    offered = AsyncMock(return_value={"status": "CHOICE_REQUIRED"})
    monkeypatch.setattr(server, "_offer_software_audit", offered)
    return offered


def _engine(tmp_path):
    """Provide two actual assessed edit candidates and an independent false positive."""
    engine = Engine(tmp_path, gitlab=Mock(), advisory=Mock(), docs=Mock())
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [
        {
            "id": name,
            "title": f"Finding {name}",
            "severity": "high",
            "location": {"file": "package.json"},
            "identifiers": [],
            "proposedFix": {"ecosystem": "npm", "package": name, "target": "2.0.0"},
        }
        for name in ("one", "two", "fp")
    ]
    engine.state.decisions = {
        name: {
            "decision": "FALSE_POSITIVE" if name == "fp" else "CHANGE_REQUIRED",
            "reason": f"Evidence for {name}.",
        }
        for name in ("one", "two", "fp")
    }
    return engine


def _context(action="accept", values=None, supported=True, before_response=None):
    """Exercise the real strict selection model while mocking only the host UI."""
    ctx = Mock()
    ctx.session.client_capabilities = ClientCapabilities.model_validate(
        {"elicitation": {}} if supported else {}
    )

    async def elicit(message, schema):
        """Check human-facing defaults and return the supplied form action."""
        assert "skip code fixes" in message
        assert "false positive" in message
        assert set(schema.model_fields) == {"finding_0", "finding_1"}
        assert all(field.default is False for field in schema.model_fields.values())
        assert "Finding one" in schema.model_fields["finding_0"].title
        if before_response:
            before_response()
        return SimpleNamespace(
            action=action,
            data=schema(**(values or {})) if action == "accept" else None,
        )

    ctx.elicit = AsyncMock(side_effect=elicit)
    return ctx


def _native_lifecycle(monkeypatch, engine):
    """Isolate dialog lifecycle tests from the separately tested package executor."""
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    monkeypatch.setattr(
        server,
        "review_false_positives",
        AsyncMock(return_value={"status": "NO_CANDIDATES"}),
    )
    monkeypatch.setattr(
        engine,
        "prepare_package_updates",
        Mock(
            return_value={
                "status": "READY",
                "reviews": {finding["id"]: {} for finding in engine.state.findings},
                "tree": {},
            }
        ),
    )
    monkeypatch.setattr(
        engine,
        "execute_selected_package_updates",
        Mock(return_value={"status": "COMPLETED"}),
    )


@pytest.mark.parametrize(
    "operation",
    [
        "qualify_package_update",
        "apply_minimal_fix",
        "generate_aaa_test",
        "run_validation_matrix",
    ],
)
def test_mcp_remediation_requires_human_permission(tmp_path, monkeypatch, operation):
    """All exposed remediation entry points reject calls before selection."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    work = Mock(return_value={"status": "DONE"})
    monkeypatch.setattr(engine, operation, work)
    args = () if operation == "run_validation_matrix" else ("one",)

    # Act
    result = server._run(operation, *args, repo_root=str(tmp_path))

    # Assert
    assert result["status"] == "FIX_APPROVAL_REQUIRED"
    assert result["next_tool"] == "select_security_fixes"
    work.assert_not_called()


def test_selection_allows_only_selected_findings_and_rejects_identity_changes(
    tmp_path, monkeypatch
):
    """Human consent permits one issue, not unchecked, new or replaced issues."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    work = Mock(return_value={"status": "APPLIED"})
    monkeypatch.setattr(engine, "apply_minimal_fix", work)

    # Act
    selected = asyncio.run(
        server.select_security_fixes(
            _context(values={"finding_0": True}), str(tmp_path)
        )
    )
    allowed = server.apply_minimal_fix("one", str(tmp_path))
    denied = server.apply_minimal_fix("two", str(tmp_path))
    engine.state.findings[0]["location"] = {"file": "other.json"}
    stale = server.apply_minimal_fix("one", str(tmp_path))

    # Assert
    assert selected["selected_ids"] == ["one"]
    assert selected["skipped_ids"] == ["two"]
    assert allowed["status"] == "APPLIED"
    assert denied["status"] == stale["status"] == "FIX_APPROVAL_REQUIRED"
    work.assert_called_once_with("one")
    engine.gitlab.dismiss_false_positive.assert_not_called()


@pytest.mark.parametrize(
    ("action", "values", "status"),
    [
        ("accept", {"finding_0": True}, "APPROVED"),
        ("accept", {"finding_0": "true"}, "INVALID"),
        ("cancel", None, "SKIPPED"),
        ("decline", None, "SKIPPED"),
    ],
)
def test_modern_protocol_fix_selection_uses_human_input_rounds(
    tmp_path, monkeypatch, action, values, status
):
    """Exercise the actual SDK modern transport, where elicitation/create is forbidden."""
    # Arrange
    from mcp import Client
    from mcp.types import ElicitResult

    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    forms = []

    async def choose(context, params):
        """Answer synthetic forms through the real modern client callback."""
        forms.append(params)
        assert all(
            field["default"] is False
            for field in params.requested_schema["properties"].values()
        )
        return ElicitResult(action=action, content=values)

    async def exercise():
        """Negotiate modern MCP and let the client perform its input retry."""
        async with Client(server.mcp, elicitation_callback=choose) as client:
            assert client.protocol_version >= "2026-07-28"
            return await client.call_tool(
                "select_security_fixes", {"repo_root": str(tmp_path)}
            )

    # Act
    result = asyncio.run(exercise())
    # Assert
    assert result.structured_content["status"] == status
    assert len(forms) == 1
    assert engine.state.fix_selection["selected_ids"] == (
        ["one"] if status == "APPROVED" else []
    )
    engine.gitlab.dismiss_false_positive.assert_not_called()


@pytest.mark.parametrize("change", ["finding", "new_run", "new_request"])
def test_modern_form_retry_cannot_authorize_replaced_evidence(
    tmp_path, monkeypatch, change
):
    """Bind the retried tool call to the original live question and candidate snapshot."""
    # Arrange
    from mcp import Client
    from mcp.types import ElicitResult

    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    async def choose(context, params):
        """Replace evidence or the request while the synthetic form is open."""
        if change == "finding":
            engine.state.findings[0]["title"] = "Replacement issue"
        elif change == "new_run":
            engine.state.fix_selection = {}
        else:
            engine.record_fix_selection(
                engine.fix_selection_candidates()["candidates"], [], "REQUESTED"
            )
        return ElicitResult(action="accept", content={"finding_0": True})

    async def exercise():
        """Submit the old answer using the SDK's opaque request-state echo."""
        async with Client(server.mcp, elicitation_callback=choose) as client:
            return await client.call_tool(
                "select_security_fixes", {"repo_root": str(tmp_path)}
            )

    # Act
    result = asyncio.run(exercise())
    # Assert
    assert result.structured_content["status"] == "SELECTION_CHANGED"
    denied = server.apply_minimal_fix("one", str(tmp_path))
    assert denied["status"] == "FIX_APPROVAL_REQUIRED"
    engine.gitlab.dismiss_false_positive.assert_not_called()


@pytest.mark.parametrize(
    ("action", "values", "supported", "status"),
    [
        ("accept", {}, True, "SKIPPED"),
        ("decline", {"finding_0": True}, True, "SKIPPED"),
        ("cancel", {"finding_0": True}, True, "SKIPPED"),
        ("accept", {"finding_0": True}, False, "UNAVAILABLE"),
        ("accept", {"finding_0": "true"}, True, "INVALID"),
        ("accept", {"finding_0": 1}, True, "INVALID"),
    ],
)
def test_skip_or_invalid_selection_never_authorizes_edits_or_builds(
    tmp_path, monkeypatch, action, values, supported, status
):
    """Unchecked/cancelled/unavailable/invalid forms proceed to separate FP completion."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    work = Mock()
    monkeypatch.setattr(engine, "run_validation_matrix", work)
    ctx = _context(action, values, supported)

    # Act
    result = asyncio.run(server.select_security_fixes(ctx, str(tmp_path)))
    validation = server.run_validation_matrix(str(tmp_path))
    payload, markdown = render(engine.state, staged=[], diff_stat="", diff_files="")

    # Assert
    assert result["status"] == status
    assert result["selected_ids"] == []
    assert result["next_tool"] == "complete_security_run"
    assert validation["status"] == "SKIPPED_NO_APPROVED_FIXES"
    assert engine.state.validation_status == "NOT_RUN_NO_APPROVED_FIXES"
    assert engine.state.decisions["one"]["decision"] == "CHANGE_REQUIRED"
    assert all(
        "No remediation edit was authorized" in item["reason"]
        for item in payload["unresolved_issues"]
    )
    assert "Human Code-Fix Selection" in markdown
    work.assert_not_called()
    engine.gitlab.dismiss_false_positive.assert_not_called()
    if not supported:
        ctx.elicit.assert_not_called()


@pytest.mark.parametrize("change", ["finding", "new_run", "new_request"])
def test_stale_form_cannot_authorize_changed_findings_or_another_run(
    tmp_path, monkeypatch, change
):
    """An old open form is not consent for replaced evidence or a fresh run."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    def replace():
        """Change evidence or the active request before the human response returns."""
        if change == "finding":
            engine.state.findings[0]["title"] = "Different issue"
        elif change == "new_run":
            state = deepcopy(engine.state)
            state.fix_selection = {}
            engine.state = state
        else:
            engine.record_fix_selection(
                engine.fix_selection_candidates()["candidates"], [], "REQUESTED"
            )

    # Act
    result = asyncio.run(
        server.select_security_fixes(
            _context(values={"finding_0": True}, before_response=replace), str(tmp_path)
        )
    )
    denied = server.apply_minimal_fix("one", str(tmp_path))

    # Assert
    assert result["status"] == "SELECTION_CHANGED"
    assert denied["status"] == "FIX_APPROVAL_REQUIRED"


def test_skipping_code_still_offers_separate_false_positive_approval(
    tmp_path, monkeypatch
):
    """Skipping edits does not end the run or implicitly approve GitLab writes."""
    # Arrange
    from tests.test_false_positives import _context as fp_context
    from tests.test_false_positives import _engine as fp_engine

    engine = fp_engine(tmp_path)
    engine.state.decisions["finding-2"]["decision"] = "CHANGE_REQUIRED"
    engine.state.findings.append(deepcopy(engine.state.findings[1]))
    engine.state.findings[-1]["id"] = "finding-3"
    engine.state.decisions["finding-3"] = {
        "decision": "CHANGE_REQUIRED",
        "reason": "Verified.",
    }
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    skip = Mock()
    skip.session.client_capabilities = ClientCapabilities.model_validate(
        {"elicitation": {}}
    )
    skip.elicit = AsyncMock(return_value=SimpleNamespace(action="cancel", data=None))
    approval = fp_context(checked=False)

    # Act
    selection = asyncio.run(server.select_security_fixes(skip, str(tmp_path)))
    completion = asyncio.run(server.complete_security_run(approval, str(tmp_path)))

    # Assert
    assert selection["status"] == "SKIPPED"
    assert completion.structured_content["fix_selection"]["selected_ids"] == []
    approval.elicit.assert_awaited_once()
    engine.gitlab.dismiss_false_positive.assert_not_called()
    assert engine.state.decisions["finding-2"]["decision"] == "CHANGE_REQUIRED"


def test_cancel_remains_a_skip_when_evidence_changes_while_form_is_open(
    tmp_path, monkeypatch
):
    """A cancellation must not trigger a replacement form just because evidence changed."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    def update():
        """Publish a concurrent read-only assessment update."""
        engine.state.decisions["one"]["reason"] = "Updated evidence."

    ctx = _context(action="cancel", before_response=update)

    # Act
    result = asyncio.run(server.select_security_fixes(ctx, str(tmp_path)))

    # Assert
    assert result["status"] == "SKIPPED"
    assert result["next_tool"] == "complete_security_run"
    ctx.elicit.assert_awaited_once()


def test_batch_validation_cannot_replay_an_unapproved_issue(tmp_path, monkeypatch):
    """The validation/isolation entry point rejects changes outside human selection."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    asyncio.run(
        server.select_security_fixes(
            _context(values={"finding_0": True}), str(tmp_path)
        )
    )
    engine.state.changes = [{"finding_id": "two", "status": "APPLIED"}]
    validation = Mock(return_value={"status": "VALIDATION_COMPLETE"})
    monkeypatch.setattr(engine, "run_validation_matrix", validation)

    # Act
    result = server.run_validation_matrix(str(tmp_path))

    # Assert
    assert result["status"] == "FIX_APPROVAL_REQUIRED"
    validation.assert_not_called()


@pytest.mark.parametrize(
    "installed,reported,current,source",
    [
        ("1.4.0", "1.0.0", "1.4.0", "Verified local plan"),
        (None, "1.0.0", "1.0.0", "Finding reports"),
        (None, None, "Not established", "Not established"),
    ],
)
def test_selection_explains_package_versions_and_scoped_code_action(
    tmp_path, monkeypatch, installed, reported, current, source
):
    """Render decision facts clearly, distinguish reported versions and admit unknowns."""
    # Arrange
    engine = _engine(tmp_path)
    package, code = engine.state.findings[:2]
    package["installedVersion"] = reported
    package["proposedFix"].update(
        installed=installed, files=["frontend/package.json"], strategy="override"
    )
    code["location"] = {"file": "backend/Handler.cs", "start_line": 23}
    code["proposedFix"] = {
        "ecosystem": "source",
        "description": "Enforce authorization on the affected handler.",
        "files": ["backend/Handler.cs"],
    }
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    ctx = _context()

    # Act
    asyncio.run(server.select_security_fixes(ctx, str(tmp_path)))
    fields = ctx.elicit.call_args.args[1].model_fields

    # Assert
    details = fields["finding_0"].description
    assert f"Current version: {current} ({source})" in details
    assert "Proposed version: 2.0.0" in details
    assert "Scope: frontend/package.json" in details
    assert "unit/integration tests are disabled" in details
    assert "Evidence for one." in details
    if installed:
        assert "Major-version change" in details
    code_details = fields["finding_1"].description
    assert "backend/Handler.cs:23" in code_details
    assert "Proposed code change: Enforce authorization" in code_details
    assert "not suppress a warning" in code_details
    assert "{" not in details + code_details


@pytest.mark.parametrize(
    "field,replacement",
    [("target", "3.0.0"), ("installed", "1.9.0"), ("files", ["other/package.json"])],
)
def test_selection_cannot_authorize_different_package_versions_or_scope(
    tmp_path, monkeypatch, field, replacement
):
    """Approval binds the displayed update but not later qualification receipts."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    work = Mock(return_value={"status": "APPLIED"})
    monkeypatch.setattr(engine, "apply_minimal_fix", work)
    asyncio.run(
        server.select_security_fixes(
            _context(values={"finding_0": True}), str(tmp_path)
        )
    )
    plan = engine.state.findings[0]["proposedFix"]

    # Act
    plan["qualification_receipt"] = {"status": "APPROVED"}
    allowed = server.apply_minimal_fix("one", str(tmp_path))
    plan[field] = replacement
    denied = server.apply_minimal_fix("one", str(tmp_path))

    # Assert
    assert allowed["status"] == "APPLIED"
    assert denied["status"] == "FIX_APPROVAL_REQUIRED"
    work.assert_called_once_with("one")


@pytest.mark.parametrize("protocol", ["2025-11-25", "2026-07-28"])
@pytest.mark.parametrize(
    "action,checked", [("accept", True), ("accept", False), ("cancel", True)]
)
def test_native_selection_releases_host_request_and_records_only_human_choices(
    tmp_path, monkeypatch, protocol, action, checked
):
    """Both host protocols work without form support or a live timed tool request."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    _native_lifecycle(monkeypatch, engine)
    ctx = _context(supported=False)
    ctx.protocol_version = protocol
    ctx.request_state = None
    dialog = Mock(close=AsyncMock())
    opened = AsyncMock(return_value=dialog)
    monkeypatch.setattr(server.desktop_approval, "open_dialog", opened)
    work = Mock()
    monkeypatch.setattr(engine, "apply_minimal_fix", work)

    async def exercise():
        """Return promptly and leave the human response independently blocked."""
        ready = asyncio.Event()

        async def wait():
            """Model an indefinitely reading human."""
            await ready.wait()
            return {"action": action, "content": {"finding_0": checked}}

        dialog.wait = wait
        result = await asyncio.wait_for(
            server.select_security_fixes(ctx, str(tmp_path)), 5
        )
        task = server._desktop_fix_selection_tasks[result["request_id"]]
        assert result["status"] == "AWAITING_HUMAN"
        assert result["next_tool"] == "wait_for_human"
        assert not task.done()
        assert (
            server.apply_minimal_fix("one", str(tmp_path))["status"] == "AWAITING_HUMAN"
        )
        completion = await server.complete_security_run(ctx, str(tmp_path))
        assert completion.structured_content["status"] == "AWAITING_HUMAN"
        duplicate = await server.select_security_fixes(ctx, str(tmp_path))
        assert duplicate["status"] == "AWAITING_HUMAN"
        ready.set()
        await task

    # Act
    asyncio.run(exercise())

    # Assert
    ctx.elicit.assert_not_called()
    opened.assert_awaited_once()
    assert opened.call_args.kwargs["submit_label"] == "Approve checked fixes"
    assert opened.call_args.args[1]["finding_0"]["default"] is False
    assert "Current version:" in opened.call_args.args[1]["finding_0"]["summary"]
    assert engine.state.fix_selection["selected_ids"] == (
        ["one"] if action == "accept" and checked else []
    )
    assert engine.state.fix_selection["status"] == (
        "APPROVED" if action == "accept" and checked else "SKIPPED"
    )
    work.assert_not_called()
    engine.gitlab.dismiss_false_positive.assert_not_called()
    dialog.close.assert_awaited_once()
    assert not server._desktop_fix_selection_tasks


@pytest.mark.parametrize("job", [workflow.JOB_PACKAGES, workflow.JOB_SOURCE])
def test_ordered_native_selection_routes_host_to_live_audit_handoff(
    tmp_path, monkeypatch, job
):
    """Keep the host attached to later source/audit work after native startup returns."""
    # Arrange
    engine = _ordered_engine(tmp_path, monkeypatch, job=job)
    _native_lifecycle(monkeypatch, engine)
    monkeypatch.setattr(server, "_resume_desktop_workflow", AsyncMock())
    ctx = _context(supported=False)
    dialog = Mock(close=AsyncMock())
    opened = AsyncMock(return_value=dialog)
    monkeypatch.setattr(server.desktop_approval, "open_dialog", opened)

    async def exercise():
        """Collect initial and duplicate handoffs without approving any fix."""
        release = asyncio.Event()

        async def wait():
            """Keep the real native worker waiting for a human response."""
            await release.wait()
            return {"action": "cancel"}

        dialog.wait = wait
        result = await server.select_security_fixes(ctx, str(tmp_path))
        task = server._desktop_fix_selection_tasks[result["request_id"]]
        try:
            duplicate = await server.select_security_fixes(ctx, str(tmp_path))
            for receipt in (result, duplicate):
                assert receipt["status"] == "AWAITING_HUMAN"
                assert receipt["next_tool"] == "choose_software_audit_action"
                assert receipt["repo_root"] == str(engine.repo_root)
                assert "repo_root only" in receipt["message"]
                assert "once" in receipt["message"]
            assert not task.done()
            assert engine.state.fix_selection["selected_ids"] == []
            assert not engine.state.software_audit
        finally:
            release.set()
            await task

    # Act
    asyncio.run(exercise())

    # Assert
    opened.assert_awaited_once()
    dialog.close.assert_awaited_once()
    ctx.elicit.assert_not_called()
    engine.execute_selected_package_updates.assert_not_called()
    assert not server._desktop_fix_selection_tasks


def test_concurrent_native_selection_reserves_only_one_window(tmp_path, monkeypatch):
    """Concurrent tool requests cannot replace a starting window or its snapshot."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    _native_lifecycle(monkeypatch, engine)
    dialog = Mock(close=AsyncMock())

    async def exercise():
        """Block startup until a competing request observes the reservation."""
        starting, release, answer = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def open_dialog(*args, **kwargs):
            """Delay native readiness, not human reading."""
            starting.set()
            await release.wait()
            return dialog

        async def wait():
            """Await a physical selection."""
            await answer.wait()
            return {"action": "accept", "content": {"finding_1": True}}

        dialog.wait = wait
        opened = AsyncMock(side_effect=open_dialog)
        monkeypatch.setattr(server.desktop_approval, "open_dialog", opened)
        first = asyncio.create_task(
            server.select_security_fixes(_context(), str(tmp_path))
        )
        await starting.wait()
        competing = await server.select_security_fixes(_context(), str(tmp_path))
        assert competing["status"] == "REQUESTED"
        release.set()
        result = await first
        task = server._desktop_fix_selection_tasks[result["request_id"]]
        opened.assert_awaited_once()
        answer.set()
        await task
        return result, competing

    # Act
    first, competing = asyncio.run(exercise())

    # Assert
    assert first["request_id"] == competing["request_id"]
    assert engine.state.fix_selection["selected_ids"] == ["two"]
    dialog.close.assert_awaited_once()


@pytest.mark.parametrize(
    "interruption",
    ["shutdown", "new_run", "changed_target", "invalid_boolean", "unexpected"],
)
def test_native_selection_interruptions_never_authorize_or_leak(
    tmp_path, monkeypatch, interruption
):
    """Shutdown, replacement runs, stale proposals and malformed responses fail closed."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    _native_lifecycle(monkeypatch, engine)
    dialog = Mock(close=AsyncMock())
    monkeypatch.setattr(
        server.desktop_approval, "open_dialog", AsyncMock(return_value=dialog)
    )

    async def exercise():
        """Interrupt a shown window before its response is consumed."""
        answer = asyncio.Event()

        async def wait():
            """Wait until the stale or invalid answer is ready."""
            await answer.wait()
            if interruption == "unexpected":
                raise TypeError("Synthetic unexpected selection failure")
            return {
                "action": "accept",
                "content": {
                    "finding_0": "true" if interruption == "invalid_boolean" else True
                },
            }

        dialog.wait = wait
        pending = await server.select_security_fixes(_context(), str(tmp_path))
        task = server._desktop_fix_selection_tasks[pending["request_id"]]
        if interruption == "shutdown":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            if interruption == "new_run":
                engine.state = RunState()
            elif interruption == "changed_target":
                engine.state.findings[0]["proposedFix"]["target"] = "9.0.0"
            answer.set()
            await task
        await asyncio.sleep(0)

    # Act
    asyncio.run(exercise())

    # Assert
    assert engine.state.fix_selection.get("selected_ids", []) == []
    assert (
        engine.state.fix_selection.get("status")
        == {
            "shutdown": "UNAVAILABLE",
            "new_run": None,
            "changed_target": "INVALID",
            "invalid_boolean": "INVALID",
            "unexpected": "INVALID",
        }[interruption]
    )
    dialog.close.assert_awaited_once()
    assert not server._desktop_fix_selection_tasks


@pytest.mark.parametrize(
    "interruption", ["cancel_receipt", "changed_target", "new_run", "open_error"]
)
def test_native_startup_interruption_closes_owned_window_and_releases_selection(
    tmp_path, monkeypatch, interruption
):
    """Failed or stale native startup cannot leave a permanent pending selection."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    _native_lifecycle(monkeypatch, engine)
    dialog = Mock(close=AsyncMock())
    record = engine.record_fix_selection

    def interrupt_receipt(*args, **kwargs):
        """Cancel after readiness is recorded, before ownership transfers."""
        result = record(*args, **kwargs)
        if interruption == "cancel_receipt" and args[2] == "AWAITING_HUMAN":
            raise asyncio.CancelledError
        return result

    async def open_dialog(*args, **kwargs):
        """Change the live run before the window reports ready."""
        if interruption == "open_error":
            raise OSError("Native selection startup failed.")
        if interruption == "changed_target":
            engine.state.findings[0]["proposedFix"]["target"] = "9.0.0"
        elif interruption == "new_run":
            engine.state = RunState()
        return dialog

    monkeypatch.setattr(engine, "record_fix_selection", interrupt_receipt)
    monkeypatch.setattr(server.desktop_approval, "open_dialog", open_dialog)

    async def exercise():
        """Wait for startup, not for a human response."""
        if interruption == "cancel_receipt":
            with pytest.raises(asyncio.CancelledError):
                await server.select_security_fixes(_context(), str(tmp_path))
        else:
            await server.select_security_fixes(_context(), str(tmp_path))

    # Act
    asyncio.run(exercise())

    # Assert
    assert engine.state.fix_selection.get("selected_ids", []) == []
    assert (
        engine.state.fix_selection.get("status")
        == {
            "cancel_receipt": "UNAVAILABLE",
            "changed_target": "INVALID",
            "new_run": None,
            "open_error": "UNAVAILABLE",
        }[interruption]
    )
    assert dialog.close.await_count == int(interruption != "open_error")
    assert not server._desktop_fix_selection_tasks


def test_native_packages_require_real_reviews_before_opening_selection(
    tmp_path, monkeypatch
):
    """A missing AI review must request evidence rather than strand approved choices."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    opened = AsyncMock()
    monkeypatch.setattr(server.desktop_approval, "open_dialog", opened)

    # Act
    result = asyncio.run(server.select_security_fixes(_context(), str(tmp_path)))

    # Assert
    assert result["status"] == "PACKAGE_REVIEW_REQUIRED"
    assert {item["finding_id"] for item in result["required_reviews"]} == {"one", "two"}
    assert "qualify_package_update once" in result["message"]
    assert "Do not invent evidence" in result["message"]
    opened.assert_not_called()
    assert not engine.state.fix_selection
    assert not engine.state.changes


def test_native_shutdown_waits_for_its_owned_package_worker(tmp_path, monkeypatch):
    """Cancellation signals and joins the worker instead of abandoning a live thread."""
    # Arrange
    engine = _engine(tmp_path)
    _native_lifecycle(monkeypatch, engine)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    dialog = Mock(
        close=AsyncMock(),
        wait=AsyncMock(
            return_value={
                "action": "accept",
                "content": {"finding_0": True},
            }
        ),
    )
    monkeypatch.setattr(
        server.desktop_approval, "open_dialog", AsyncMock(return_value=dialog)
    )
    running, stopping, release = threading.Event(), threading.Event(), threading.Event()

    def execute(request_id, reviews, tree, cancelled):
        """Retain ownership until the current bounded operation finishes."""
        from gitlab_security_mcp.commands import progress_sink

        assert callable(progress_sink.get())
        progress_sink.get()("Worker is building the selected package.")
        running.set()
        assert cancelled.wait(5)
        stopping.set()
        assert release.wait(5)
        engine.state.fix_selection["package_execution"] = {"status": "INTERRUPTED"}
        return {"status": "INTERRUPTED"}

    monkeypatch.setattr(engine, "execute_selected_package_updates", execute)

    async def exercise():
        """Cancel after approval and verify cleanup waits for the worker."""
        await server.select_security_fixes(_context(), str(tmp_path))
        assert await asyncio.to_thread(running.wait, 5)
        task = next(iter(server._desktop_fix_selection_tasks.values()))
        task.cancel()
        assert await asyncio.to_thread(stopping.wait, 5)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    # Act
    asyncio.run(exercise())

    # Assert
    assert engine.state.fix_selection["package_execution"]["status"] == "INTERRUPTED"
    dialog.close.assert_awaited_once()
    assert not server._desktop_fix_selection_tasks


def test_queued_batch_blocks_duplicate_edits_completion_and_new_runs(
    tmp_path, monkeypatch
):
    """One human submission owns the batch until its execution reaches a terminal state."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    candidates = engine.fix_selection_candidates()["candidates"]
    pending = engine.record_fix_selection(
        candidates, [], "REQUESTED", presentation="WINDOWS_DIALOG"
    )
    engine.record_fix_selection(
        candidates,
        ["one"],
        "APPROVED",
        request_id=pending["request_id"],
        presentation="WINDOWS_DIALOG",
    )
    work = Mock()
    monkeypatch.setattr(engine, "apply_minimal_fix", work)

    # Act
    prechecks = engine.run_prechecks()
    duplicate = server.apply_minimal_fix("one", str(tmp_path))
    selection = asyncio.run(server.select_security_fixes(_context(), str(tmp_path)))
    completion = asyncio.run(server.complete_security_run(_context(), str(tmp_path)))

    # Assert
    assert (
        prechecks["status"]
        == duplicate["status"]
        == selection["status"]
        == completion.structured_content["status"]
        == "REMEDIATION_RUNNING"
    )
    assert engine.state.fix_selection["request_id"] == pending["request_id"]
    work.assert_not_called()


def test_fix_selection_not_reused_by_new_engine(tmp_path, monkeypatch):
    """An inspection snapshot never restores edit authorization after restart."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    asyncio.run(
        server.select_security_fixes(
            _context(values={"finding_0": True}), str(tmp_path)
        )
    )

    # Act
    restarted = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: restarted)
    denied = server.apply_minimal_fix("one", str(tmp_path))

    # Assert
    assert isinstance(restarted.state, RunState)
    assert restarted.state.fix_selection == {}
    assert denied["status"] == "FIX_APPROVAL_REQUIRED"


def test_native_mcp_selection_edits_only_the_chosen_image(repo, monkeypatch):
    """Prove real SDK form consent gates actual on-disk fixes, not just mock dispatch."""
    # Arrange
    from functools import partial

    import anyio
    from mcp import ClientSession
    from mcp.shared.memory import create_client_server_memory_streams
    from mcp.types import ElicitRequestFormParams, ElicitResult

    from gitlab_security_mcp.advisory import AdvisoryLookup
    from tests.conftest import documentation_client
    from tests.test_engine import HybridRunner

    docs = documentation_client()
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="resolved",
        affected=True,
        fixed_versions=["1.27.0"],
        lowest_fixed_version="1.27.0",
        summary="Synthetic patched image tag.",
        sources=["osv:CVE-IMG"],
    )
    engine = Engine(
        repo,
        gitlab=Mock(),
        advisory=advisory,
        docs=docs,
        runner=HybridRunner(repo),
        which=lambda name: name,
    )
    engine.state.status = "FINDINGS_LISTED"
    (repo / "Dockerfile").write_text(
        "FROM nginx:1.25.1 AS one\nFROM httpd:1.25.1 AS two\n", encoding="utf-8"
    )
    for name in ("one", "two"):
        package = "nginx" if name == "one" else "httpd"
        engine.state.findings.append(
            {
                "id": name,
                "title": f"Image {name}",
                "category": "container_scanning",
                "identifiers": ["CVE-IMG"],
                "component": package,
                "installedVersion": "1.25.1",
                "fixedVersions": [],
                "location": {"image": f"{package}:1.25.1", "file": "Dockerfile"},
                "solution": None,
                "falsePositiveFlag": False,
                "status": "detected",
            }
        )
        assert engine.verify_security_finding(name)["decision"] == "CHANGE_REQUIRED"
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setenv("PROGRESS_CONSOLE", "off")
    forms = []

    async def human_response(_context, params):
        """Return synthetic human consent through the actual MCP protocol."""
        assert isinstance(params, ElicitRequestFormParams)
        forms.append(params)
        properties = params.requested_schema["properties"]
        assert set(properties) == {"finding_0", "finding_1"}
        assert all(
            field["type"] == "boolean" and field["default"] is False
            for field in properties.values()
        )
        selector = next(
            tool
            for tool in await server.mcp.list_tools()
            if tool.name == "select_security_fixes"
        )
        assert set(selector.input_schema["properties"]) == {
            "repo_root",
            "package_reviews",
        }
        return ElicitResult(
            action="accept", content={"finding_0": True, "finding_1": False}
        )

    async def exercise():
        """Use the production MCP tool dispatcher for selection and real edits."""
        async with create_client_server_memory_streams() as (client, remote):
            async with anyio.create_task_group() as tasks:
                lowlevel = server.mcp._lowlevel_server
                tasks.start_soon(
                    partial(
                        lowlevel.run, *remote, lowlevel.create_initialization_options()
                    )
                )
                async with ClientSession(
                    *client, elicitation_callback=human_response
                ) as session:
                    await session.initialize()
                    before = await session.call_tool(
                        "apply_minimal_fix",
                        {"finding_id": "one", "repo_root": str(repo)},
                    )
                    selection = await session.call_tool(
                        "select_security_fixes", {"repo_root": str(repo)}
                    )
                    denied = await session.call_tool(
                        "apply_minimal_fix",
                        {"finding_id": "two", "repo_root": str(repo)},
                    )
                    applied = await session.call_tool(
                        "apply_minimal_fix",
                        {"finding_id": "one", "repo_root": str(repo)},
                    )
                tasks.cancel_scope.cancel()
                return [
                    item.structured_content
                    for item in (before, selection, denied, applied)
                ]

    # Act
    try:
        before, selection, denied, applied = anyio.run(exercise)
    finally:
        docs.close()

    # Assert
    assert before["status"] == denied["status"] == "FIX_APPROVAL_REQUIRED"
    assert selection["selected_ids"] == ["one"]
    assert applied["status"] == "APPLIED", applied
    assert len(forms) == 1
    assert (repo / "Dockerfile").read_text(encoding="utf-8") == (
        "FROM nginx:1.27.0 AS one\nFROM httpd:1.25.1 AS two\n"
    )
    assert server.get_run_status(str(repo))["fix_selection"]["selected_ids"] == ["one"]
    locked = asyncio.run(server.select_security_fixes(Mock(), str(repo)))
    assert locked["status"] == "SELECTION_LOCKED"
