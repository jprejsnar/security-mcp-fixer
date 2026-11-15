"""Verify human-only approval and narrowly scoped GitLab false-positive writes."""

import asyncio
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.tools.base import Tool
from mcp.shared.exceptions import MCPError
from mcp.types import ClientCapabilities

from gitlab_security_mcp import server
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.gitlab_client import (
    DISMISS_FALSE_POSITIVE,
    DISMISSAL_TARGET_QUERY,
    GitLabClient,
    normalize_finding,
)
from gitlab_security_mcp.report import render
from tests.conftest import documentation_client

GID = "gid://gitlab/Vulnerability/123"


def _engine(tmp_path):
    """Provide one eligible assessment and one unresolved finding."""
    client = Mock(spec=GitLabClient)
    client.dismiss_false_positive.return_value = {
        "status": "DISMISSED",
        "vulnerability_id": GID,
    }
    client._clean.side_effect = lambda text: text
    engine = Engine(tmp_path, gitlab=client, advisory=Mock(), docs=Mock())
    engine.state.status = "FINDINGS_LISTED"
    engine.state.gitlab_project_path = "group/app"
    engine.state.findings = [
        normalize_finding(
            {
                "id": GID,
                "uuid": "finding-1",
                "title": "Finding one",
                "state": "DETECTED",
            },
            None,
        ),
        normalize_finding(
            {"id": "gid://gitlab/Vulnerability/124", "uuid": "finding-2"},
            None,
        ),
    ]
    engine.state.decisions = {
        "finding-1": {
            "decision": "FALSE_POSITIVE",
            "reason": "The installed version is outside the affected range.",
        },
        "finding-2": {"decision": "MANUAL_REVIEW", "reason": "Evidence missing."},
    }
    return engine


def _context(
    action="accept", checked=True, supported=True, reason="outside the affected range"
):
    """Model the host returning a validated human boolean form response."""
    ctx = Mock()
    ctx.session.client_capabilities = ClientCapabilities.model_validate(
        {"elicitation": {"form": {}}} if supported else {}
    )

    async def elicit(message, schema):
        """Return the host's approval through the actual generated model."""
        assert "immediately dismiss" in message
        fields = schema.model_fields
        assert list(fields) == ["finding_0"]
        assert fields["finding_0"].default is False
        assert reason in fields["finding_0"].description
        return SimpleNamespace(
            action=action,
            data=schema(finding_0=checked) if action == "accept" else None,
        )

    ctx.elicit = AsyncMock(side_effect=elicit)
    return ctx


@pytest.mark.parametrize("dismissed", [False, True])
def test_complete_assessment_report_distinguishes_pending_gitlab_approval(
    tmp_path, dismissed
):
    """Do not present source-review completion as proof of GitLab dismissal."""
    # Arrange
    engine = _engine(tmp_path)
    if dismissed:
        engine.state.gitlab_dismissals = [
            {
                "id": "finding-1",
                "status": "DISMISSED",
                "reason": "Fixture human approval.",
            }
        ]

    # Act
    payload, markdown = render(engine.state, staged=[], diff_stat="", diff_files="")

    # Assert
    assert payload["review_status"] == "COMPLETE"
    assert payload["false_positive_approval"]["not_confirmed_dismissed"] == (
        0 if dismissed else 1
    )
    assert (
        "## False-Positive Approval Pending" in payload["final_summary_markdown"]
    ) is not dismissed
    if not dismissed:
        assert "no confirmed GitLab dismissal" in markdown
        assert (
            payload["false_positive_approval"]["next_tool"]
            == "submit_false_positive_approvals"
        )
    engine.gitlab.dismiss_false_positive.assert_not_called()


@pytest.mark.parametrize(
    ("action", "checked", "supported", "writes"),
    [
        ("accept", True, True, 1),
        ("accept", False, True, 0),
        ("decline", True, True, 0),
        ("cancel", True, True, 0),
        ("accept", True, False, 0),
    ],
)
def test_checkbox_submission_is_the_only_write_gate(
    tmp_path, monkeypatch, action, checked, supported, writes
):
    """Only a selected checkbox submitted by a capable host authorizes a write."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    ctx = _context(action, checked, supported)

    # Act
    result = asyncio.run(server.submit_false_positive_approvals(ctx, str(tmp_path)))

    # Assert
    assert engine.gitlab.dismiss_false_positive.call_count == writes
    if writes:
        engine.gitlab.dismiss_false_positive.assert_called_once_with(
            GID, "finding-1", "group/app", engine.state.decisions["finding-1"]["reason"]
        )
        assert result["results"][0]["status"] == "DISMISSED"
        assert engine.false_positive_candidates()["candidates"] == []
        saved = json.loads((tmp_path / ".security-mcp" / "run-state.json").read_text())
        assert saved["gitlab_dismissals"][0]["status"] == "DISMISSED"
    if not supported:
        assert result["status"] == "APPROVAL_UNAVAILABLE"
        ctx.elicit.assert_not_called()
    if not writes:
        assert engine.state.gitlab_dismissals == []


@pytest.mark.parametrize("supported", [True, False])
def test_combined_completion_lists_candidates_without_opening_the_form(
    tmp_path, monkeypatch, supported
):
    """Finish the report immediately so verification is not held inside a form."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    ctx = _context(supported=supported)
    tool = Tool.from_function(server.complete_security_run)

    # Act
    result = asyncio.run(
        tool.run({"repo_root": str(tmp_path)}, ctx, convert_result=True)
    )
    payload = result.structured_content
    saved = json.loads(Path(payload["json_report"]).read_text(encoding="utf-8"))

    # Assert
    assert not result.is_error
    assert payload["status"] == "REPORT_GENERATED"
    assert ctx.elicit.await_count == 0
    assert engine.gitlab.dismiss_false_positive.call_count == 0
    assert saved["gitlab_dismissals"] == []
    assert result.content[-1].text == payload["final_summary_markdown"]
    assert saved["final_summary_markdown"] == payload["final_summary_markdown"]
    assert payload["false_positive_review"]["status"] == (
        "APPROVAL_UNAVAILABLE" if not supported else "REVIEW_READY"
    )
    if supported:
        assert payload["false_positive_review"]["candidates"][0]["id"] == "finding-1"
        assert (
            payload["false_positive_review"]["next_tool"]
            == "submit_false_positive_approvals"
        )
    engine.advisory.lookup.assert_not_called()


@pytest.mark.parametrize("failure", ["form", "mutation"])
def test_combined_completion_reports_approval_errors_without_losing_report(
    tmp_path, monkeypatch, failure
):
    """Surface a form or mutation failure while preserving the local report."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    ctx = _context()
    if failure == "form":
        ctx.elicit.side_effect = MCPError(-32601, "Host cannot open the form")
    else:
        engine.gitlab.dismiss_false_positive.side_effect = RuntimeError("Response lost")

    # Act
    report = asyncio.run(server.complete_security_run(ctx, str(tmp_path)))
    result = asyncio.run(server.submit_false_positive_approvals(ctx, str(tmp_path)))

    # Assert
    assert Path(report.structured_content["json_report"]).is_file()
    assert (
        report.structured_content["false_positive_review"]["status"] == "REVIEW_READY"
    )
    assert report.is_error is False
    assert result["status"] == (
        "APPROVAL_UNAVAILABLE" if failure == "form" else "PARTIAL_FAILURE"
    )
    assert ctx.elicit.await_count == 1
    if failure == "form":
        engine.gitlab.dismiss_false_positive.assert_not_called()
        assert "Host cannot open the form" in result["reason"]
    else:
        assert result["results"][0]["status"] == "ERROR"


def test_combined_completion_does_not_prompt_without_eligible_false_positives(
    tmp_path, monkeypatch
):
    """Generate the report directly when no finding can be offered for approval."""
    # Arrange
    engine = _engine(tmp_path)
    engine.state.decisions["finding-1"] = {
        "decision": "MANUAL_REVIEW",
        "reason": "Incomplete evidence.",
    }
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    ctx = _context()

    # Act
    result = asyncio.run(server.complete_security_run(ctx, str(tmp_path)))

    # Assert
    assert result.structured_content["status"] == "REPORT_GENERATED"
    assert (
        result.structured_content["false_positive_review"]["status"]
        == "ASSESSMENT_REQUIRED"
    )
    ctx.elicit.assert_not_called()
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_combined_completion_keeps_checkout_selected_before_the_form(
    tmp_path, monkeypatch
):
    """Do not switch repositories if another checkout becomes active during approval."""
    # Arrange
    first_root, other_root = tmp_path / "first", tmp_path / "other"
    first_root.mkdir()
    other_root.mkdir()
    first, other = _engine(first_root), _engine(other_root)
    active = [first]

    def select(root):
        """Model a changed default checkout while honoring explicit repository paths."""
        return (
            active[0]
            if root is None
            else first
            if Path(root).resolve() == first_root
            else other
        )

    monkeypatch.setattr(server, "_engine_for", select)
    ctx = _context()
    original = ctx.elicit.side_effect

    async def elicit(message, schema):
        """Switch the host's default repository while the form is displayed."""
        active[0] = other
        return await original(message, schema)

    ctx.elicit.side_effect = elicit

    # Act
    report = asyncio.run(server.complete_security_run(ctx))
    asyncio.run(server.submit_false_positive_approvals(ctx))

    # Assert
    assert Path(report.structured_content["json_report"]).is_relative_to(first_root)
    first.gitlab.dismiss_false_positive.assert_called_once()
    other.gitlab.dismiss_false_positive.assert_not_called()
    assert not (other_root / ".security-mcp").exists()


def test_repeat_review_explains_previously_confirmed_dismissals(tmp_path, monkeypatch):
    """Report completed dismissals rather than a misleading empty assessment list."""
    # Arrange
    engine = _engine(tmp_path)
    engine.state.findings = engine.state.findings[:1]
    engine.dismiss_false_positives(engine.false_positive_candidates()["candidates"])
    engine.gitlab.dismiss_false_positive.reset_mock()
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    ctx = _context()

    # Act
    result = asyncio.run(server.review_false_positives(ctx, str(tmp_path)))

    # Assert
    assert result["status"] == "ALREADY_DISMISSED"
    assert "All 1 findings were previously confirmed dismissed" in result["message"]
    assert result["excluded"][0]["reason"] == "ALREADY_DISMISSED"
    ctx.elicit.assert_not_called()
    engine.gitlab.dismiss_false_positive.assert_not_called()


@pytest.mark.parametrize("blocker", ["assessment", "global_id", "reason", "empty"])
def test_empty_approval_reports_blockers_without_writing(
    tmp_path, monkeypatch, blocker
):
    """Explain how to recover missing prerequisites without inventing approvals."""
    # Arrange
    engine = _engine(tmp_path)
    engine.state.findings = engine.state.findings[:1]
    expected = None
    if blocker == "assessment":
        engine.state.decisions.clear()
        expected = "ASSESSMENT_REQUIRED"
    elif blocker == "global_id":
        engine.state.findings[0].pop("vulnerabilityId")
        expected = "MISSING_VULNERABILITY_ID"
    elif blocker == "reason":
        engine.state.decisions["finding-1"]["reason"] = " "
        expected = "INVALID_REASON"
    else:
        engine.state.findings.clear()
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    ctx = _context()

    # Act
    result = asyncio.run(server.review_false_positives(ctx, str(tmp_path)))

    # Assert
    assert result["status"] == "ASSESSMENT_REQUIRED"
    assert result["repo_root"] == str(tmp_path)
    if expected:
        assert result["excluded"][0]["reason"] == expected
        assert result["excluded"][0]["action"]
    else:
        assert result["excluded"] == []
        assert "No findings are loaded" in result["message"]
    ctx.elicit.assert_not_called()
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_changed_or_unassessed_approval_cannot_write(tmp_path):
    """Reject changed reasons and AI-injected unresolved findings before any write."""
    # Arrange
    engine = _engine(tmp_path)
    approved = engine.false_positive_candidates()["candidates"]
    stale = deepcopy(approved)
    engine.state.decisions["finding-1"]["reason"] = "New assessment needs approval."

    # Act
    changed = engine.dismiss_false_positives(stale)
    injected = engine.dismiss_false_positives([{"id": "finding-2"}])

    # Assert
    assert changed["status"] == injected["status"] == "ERROR"
    engine.gitlab.dismiss_false_positive.assert_not_called()


def _source_engine(tmp_path):
    """Model the archive's Java findings without retaining its private source."""
    engine = _engine(tmp_path)
    engine.docs = documentation_client()
    source = tmp_path / "Endpoint.java"
    source.write_text(
        'class Endpoint { String route = "/status"; }\n', encoding="utf-8"
    )
    engine.state.findings = engine.state.findings[:1]
    engine.state.findings[0].update(
        category="sast",
        title="Found Spring endpoint",
        location={"file": source.name, "startLine": "1"},
    )
    engine.state.decisions.clear()
    review = {
        "decision": "FALSE_POSITIVE",
        "reason": "The fixture only declares a literal route, with no executable request handler.",
        "input_origin": "The route is a literal in the reviewed source.",
        "finding_analysis": "An endpoint inventory is not proof of an exploitable defect.",
        "reachability_analysis": "This fixture has no request handler or input processing.",
        "reviewed_files": [
            {
                "path": source.name,
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "assessment": "Read the entire fixture and traced its literal route.",
            }
        ],
    }
    return engine, source, review


def _source_context(sampling=False):
    """Provide an SDK context that forbids deprecated sampling requests."""
    session = Mock()
    session.client_capabilities = ClientCapabilities.model_validate(
        {"sampling": {}} if sampling else {}
    )
    session.create_message = AsyncMock(
        side_effect=AssertionError("Deprecated sampling must not be used")
    )
    return Context(
        request_context=SimpleNamespace(session=session, request_id="verification")
    )


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("Endpoint.java", 'class Endpoint { String route = "/status"; }\n'),
        ("Endpoint.cs", 'class Endpoint { public const string Route = "/status"; }\n'),
        ("endpoint.ts", 'export const route: string = "/status";\n'),
        ("endpoint.js", 'const route = "/status";\n'),
        ("endpoint.py", 'route = "/status"\n'),
        ("Dockerfile", "FROM scratch\n"),
        ("Dockerfile.production", "FROM scratch\n"),
        ("nginx.conf", "server_tokens off;\n"),
        ("nginx/conf.d/site.conf", "server_tokens off;\n"),
    ],
)
@pytest.mark.parametrize("sampling", [True, False])
def test_sdk_reviews_all_supported_source_and_configuration_types(
    tmp_path, monkeypatch, name, content, sampling
):
    """Supply complete cited files to host AI for every requested code/config type."""
    # Arrange
    engine, old_source, review = _source_engine(tmp_path)
    source = tmp_path / name
    if source != old_source:
        old_source.unlink()
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(content, encoding="utf-8")
    engine.state.findings[0]["location"] = {"file": name, "startLine": 1}
    review["reviewed_files"] = [
        {
            "path": name,
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "assessment": "Read the full cited fixture; it does not implement the reported Spring endpoint.",
        }
    ]
    ctx = _source_context(sampling=sampling)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    tool = Tool.from_function(server.verify_security_finding)

    # Act
    initial = asyncio.run(tool.run({"finding_id": "finding-1"}, ctx))
    result = asyncio.run(
        tool.run({"finding_id": "finding-1", "source_review": review}, ctx)
    )

    # Assert
    assert result["decision"] == "FALSE_POSITIVE"
    assert initial["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert initial["ai_source_review"]["status"] == "HOST_REVIEW_REQUIRED"
    cited = initial["ai_source_review"]["cited_source"]
    ctx.session.create_message.assert_not_called()
    assert cited["content"] == source.read_bytes().decode("utf-8")
    assert cited["sha256"] == review["reviewed_files"][0]["sha256"]
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_missing_secret_source_is_not_sufficient_for_false_positive(tmp_path):
    """Keep secret findings unresolved when their cited source cannot be examined."""
    # Arrange
    engine, source, _review = _source_engine(tmp_path)
    engine.state.findings[0]["category"] = "secret_detection"
    source.unlink()

    # Act
    result = engine.verify_security_finding("finding-1")

    # Assert
    assert result["decision"] == "MANUAL_REVIEW"
    assert engine.state.false_positives == []
    engine.gitlab.dismiss_false_positive.assert_not_called()


@pytest.mark.parametrize(
    "decision", ["FALSE_POSITIVE", "CONFIRMED_VULNERABILITY", "MANUAL_REVIEW"]
)
def test_sdk_verification_requests_ai_source_and_input_flow_review(
    tmp_path, monkeypatch, decision
):
    """Run host AI review over full source and a discovered caller, without dismissal."""
    # Arrange
    engine, source, review = _source_engine(tmp_path)
    review["decision"] = decision
    caller = tmp_path / "RequestOrigin.java"
    caller.write_text(
        'class RequestOrigin { String route = "/status"; }\n', encoding="utf-8"
    )
    review["reviewed_files"].append(
        {
            "path": caller.name,
            "sha256": hashlib.sha256(caller.read_bytes()).hexdigest(),
            "assessment": "Traced the caller's literal route.",
        }
    )
    ctx = _source_context()
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    tool = Tool.from_function(server.verify_security_finding)

    # Act
    pending = asyncio.run(
        tool.run({"finding_id": "finding-1", "repo_root": str(tmp_path)}, ctx)
    )
    result = asyncio.run(
        tool.run(
            {
                "finding_id": "finding-1",
                "repo_root": str(tmp_path),
                "source_review": review,
            },
            ctx,
        )
    )

    # Assert
    assert result["decision"] == decision
    assert pending["ai_source_review"]["status"] == "HOST_REVIEW_REQUIRED"
    assert engine.state.findings[0]["sourceReview"] == review
    assert pending["ai_source_review"]["cited_source"][
        "content"
    ] == source.read_bytes().decode("utf-8")
    ctx.session.create_message.assert_not_called()
    engine.gitlab.dismiss_false_positive.assert_not_called()
    assert bool(engine.false_positive_candidates()["candidates"]) is (
        decision == "FALSE_POSITIVE"
    )


def test_host_without_sampling_receives_full_source_and_must_record_review(
    tmp_path, monkeypatch
):
    """Give the calling AI actual source, not a generic terminal placeholder."""
    # Arrange
    engine, source, review = _source_engine(tmp_path)
    ctx = _source_context()
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    tool = Tool.from_function(server.verify_security_finding)

    # Act
    pending = asyncio.run(tool.run({"finding_id": "finding-1"}, ctx))
    recorded = asyncio.run(
        tool.run({"finding_id": "finding-1", "source_review": review}, ctx)
    )

    # Assert
    assert pending["ai_source_review"]["status"] == "HOST_REVIEW_REQUIRED"
    assert pending["ai_source_review"]["cited_source"][
        "content"
    ] == source.read_bytes().decode("utf-8")
    assert "must examine the full cited_source" in pending["reason"]
    assert recorded["decision"] == "FALSE_POSITIVE"
    ctx.session.create_message.assert_not_called()
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_source_review_never_uses_deprecated_sampling(tmp_path, monkeypatch):
    """Keep SDK back-channel requests unused even when sampling is advertised."""
    # Arrange
    engine, _source, review = _source_engine(tmp_path)
    ctx = _source_context(sampling=True)
    ctx.session.send_request = AsyncMock()
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    pending = asyncio.run(
        Tool.from_function(server.verify_security_finding).run(
            {"finding_id": "finding-1"}, ctx
        )
    )
    result = asyncio.run(
        Tool.from_function(server.verify_security_finding).run(
            {"finding_id": "finding-1", "source_review": review}, ctx
        )
    )

    # Assert
    assert result["decision"] == "FALSE_POSITIVE"
    assert pending["ai_source_review"]["status"] == "HOST_REVIEW_REQUIRED"
    ctx.session.send_request.assert_not_called()
    ctx.session.create_message.assert_not_called()
    engine.gitlab.dismiss_false_positive.assert_not_called()


@pytest.mark.parametrize(
    "failure", ["declined", "invalid-hash", "outside", "invalid-review"]
)
def test_ai_review_failures_cannot_become_false_positives(
    tmp_path, monkeypatch, failure
):
    """Keep declined, stale, out-of-checkout and invalid host reviews unresolved."""
    # Arrange
    engine, _source, review = _source_engine(tmp_path)
    if failure == "invalid-hash":
        review["reviewed_files"][0]["sha256"] = "0" * 64
    elif failure == "outside":
        review["reviewed_files"][0]["path"] = "../outside.java"
    elif failure == "invalid-review":
        review = {"execute": "arbitrary command"}
    ctx = _source_context()
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    tool = Tool.from_function(server.verify_security_finding)
    result = asyncio.run(tool.run({"finding_id": "finding-1"}, ctx))
    if failure != "declined":
        result = asyncio.run(
            tool.run({"finding_id": "finding-1", "source_review": review}, ctx)
        )
    saved = json.loads((tmp_path / ".security-mcp" / "run-state.json").read_text())

    # Assert
    assert result["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert saved["decisions"]["finding-1"]["decision"] == "SOURCE_REVIEW_REQUIRED"
    ctx.session.create_message.assert_not_called()
    assert engine.false_positive_candidates()["candidates"] == []
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_ai_review_rejects_source_changed_during_host_review(tmp_path, monkeypatch):
    """Recheck full-byte evidence before storing the calling AI's conclusion."""
    # Arrange
    engine, source, review = _source_engine(tmp_path)
    ctx = _source_context()
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    tool = Tool.from_function(server.verify_security_finding)
    asyncio.run(tool.run({"finding_id": "finding-1"}, ctx))
    source.write_text("class Endpoint { String route = external; }\n", encoding="utf-8")
    result = asyncio.run(
        tool.run({"finding_id": "finding-1", "source_review": review}, ctx)
    )

    # Assert
    assert result["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert "changed" in result["reason"]
    engine.gitlab.dismiss_false_positive.assert_not_called()


@pytest.mark.parametrize("failure", ["missing", "oversized"])
def test_missing_or_oversized_source_is_not_sent_for_ai_review(
    tmp_path, monkeypatch, failure
):
    """Keep unavailable evidence unresolved rather than sending a clipped source."""
    # Arrange
    from gitlab_security_mcp.ai_source_review import MAX_REVIEW_BYTES

    engine, source, _review = _source_engine(tmp_path)
    if failure == "missing":
        source.unlink()
    else:
        source.write_bytes(b"x" * (MAX_REVIEW_BYTES + 1))
    ctx = _source_context()
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    result = asyncio.run(
        Tool.from_function(server.verify_security_finding).run(
            {"finding_id": "finding-1"}, ctx
        )
    )

    # Assert
    assert result["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert result["ai_source_review"]["status"] == "FAILED"
    ctx.session.create_message.assert_not_called()
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_archived_style_pending_reviews_continue_to_human_approval(
    tmp_path, monkeypatch
):
    """Keep 157 excerpt-only findings pending and approve only an evidenced review."""
    # Arrange
    engine, _source, review = _source_engine(tmp_path)
    first = engine.state.findings[0]
    engine.verify_security_finding(first["id"])
    for index in range(1, 157):
        finding = deepcopy(first)
        finding["id"] = f"pending-{index}"
        finding["vulnerabilityId"] = f"gid://gitlab/Vulnerability/{index + 200}"
        engine.state.findings.append(finding)
        engine.state.decisions[finding["id"]] = deepcopy(
            engine.state.decisions[first["id"]]
        )
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    ctx = _context(reason=review["reason"])

    # Act
    pending = asyncio.run(server.review_false_positives(ctx, str(tmp_path)))
    payload, markdown = render(engine.state, staged=[], diff_stat="", diff_files="")
    engine.verify_security_finding(first["id"], source_review=review)
    ready = asyncio.run(server.review_false_positives(ctx, str(tmp_path)))
    approved = asyncio.run(server.submit_false_positive_approvals(ctx, str(tmp_path)))

    # Assert
    assert pending["status"] == "SOURCE_REVIEW_REQUIRED"
    queue = pending["source_review_queue"]
    assert queue["finding_count"] == 157
    assert len(queue["files"]) == 1
    assert len(queue["files"][0]["findings"]) == 157
    assert queue["next_tool"] == "verify_security_finding"
    assert payload["review_status"] == "SOURCE_REVIEW_REQUIRED"
    assert "## Source Review Incomplete" in markdown
    assert "157 SAST findings" in payload["final_summary_markdown"]
    assert ready["status"] == "REVIEW_READY"
    assert ctx.elicit.await_count == 1
    engine.gitlab.dismiss_false_positive.assert_called_once()
    assert approved["results"][0]["status"] == "DISMISSED"
    assert approved["source_review_queue"]["finding_count"] == 156


@pytest.mark.parametrize(
    "decision", ["FALSE_POSITIVE", "CONFIRMED_VULNERABILITY", "MANUAL_REVIEW"]
)
def test_non_regex_source_review_records_conclusion_and_retracts_stale_evidence(
    tmp_path, decision
):
    """Allow rule-specific reviews, keeping confirmed/uncertain findings unresolved."""
    # Arrange
    engine, source, review = _source_engine(tmp_path)
    review["decision"] = decision
    review["reason"] = f"Rule-specific analysis concluded {decision}."

    # Act
    result = engine.verify_security_finding("finding-1", source_review=review)
    payload, _markdown = render(engine.state, staged=[], diff_stat="", diff_files="")
    candidates = engine.false_positive_candidates()["candidates"]
    source.write_text(
        "class Endpoint { String route = externalInput; }\n", encoding="utf-8"
    )
    status = engine.get_run_status()

    # Assert
    assert result["decision"] == decision
    assert payload["source_reviews"]["finding-1"] == review
    assert bool(candidates) is (decision == "FALSE_POSITIVE")
    assert bool(payload["unresolved_issues"]) is (decision != "FALSE_POSITIVE")
    assert status["source_review_queue"]["finding_count"] == 1
    assert "sourceReview" not in engine.state.findings[0]
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_source_review_changed_while_form_open_cannot_write(tmp_path, monkeypatch):
    """Retract a stale source false positive before processing approval."""
    # Arrange
    engine = _engine(tmp_path)
    approved = engine.false_positive_candidates()["candidates"]

    def retract():
        """Simulate the existing source-hash validation retracting the decision."""
        engine.state.decisions["finding-1"]["decision"] = "SOURCE_REVIEW_REQUIRED"

    monkeypatch.setattr(engine, "_refresh_source_reviews", retract)

    # Act
    result = engine.dismiss_false_positives(approved)

    # Assert
    assert result["status"] == "ERROR"
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_partial_failures_are_persisted_and_reported(tmp_path):
    """Preserve pending intent before the request and expose unknown remote outcomes."""
    # Arrange
    engine = _engine(tmp_path)

    def fail(*args):
        """Verify durable intent, then simulate a lost mutation response."""
        saved = json.loads((tmp_path / ".security-mcp" / "run-state.json").read_text())
        assert saved["gitlab_dismissals"][0]["status"] == "PENDING"
        raise httpx.ReadTimeout("Response lost")

    engine.gitlab.dismiss_false_positive.side_effect = fail

    # Act
    result = engine.dismiss_false_positives(
        engine.false_positive_candidates()["candidates"]
    )
    payload, markdown = render(engine.state, staged=[], diff_stat="", diff_files="")

    # Assert
    assert result["status"] == "PARTIAL_FAILURE"
    assert result["results"][0]["status"] == "ERROR"
    assert "Response lost" in payload["final_summary_markdown"]
    assert "remote outcome may be unknown" in payload["final_summary_markdown"]
    assert (
        "Nothing was staged, committed, pushed, or changed in GitLab." not in markdown
    )
    engine.gitlab.dismiss_false_positive.assert_called_once()


@pytest.mark.parametrize(
    (
        "target_override",
        "mutation_errors",
        "returned_state",
        "expected_writes",
        "succeeds",
    ),
    [
        ({}, [], "DISMISSED", 1, True),
        ({"uuid": "other-finding"}, [], "DISMISSED", 0, False),
        ({"project": {"fullPath": "other/project"}}, [], "DISMISSED", 0, False),
        ({"state": "RESOLVED"}, [], "DISMISSED", 0, False),
        ({}, ["Permission denied"], "DISMISSED", 1, False),
        ({}, [], "DETECTED", 1, False),
    ],
)
def test_gitlab_mutation_checks_identity_reason_and_confirmed_outcome(
    target_override, mutation_errors, returned_state, expected_writes, succeeds
):
    """Send only the fixed mutation and require matching remote identity and success."""
    # Arrange
    requests = []
    reason = 'Reviewed reason with "quotes" and\nmultiple lines.'

    def handler(request):
        """Serve the identity query and inspect the single allowed mutation."""
        body = json.loads(request.content)
        requests.append(body)
        if body["query"] == DISMISSAL_TARGET_QUERY:
            target = {
                "id": GID,
                "uuid": "finding-1",
                "state": "DETECTED",
                "project": {"fullPath": "group/app"},
            }
            target.update(target_override)
            return httpx.Response(200, json={"data": {"vulnerability": target}})
        assert body["query"] == DISMISS_FALSE_POSITIVE
        assert body["variables"] == {"id": GID, "comment": reason}
        assert "dismissalReason: FALSE_POSITIVE" in body["query"]
        return httpx.Response(
            200,
            json={
                "data": {
                    "vulnerabilityDismiss": {
                        "errors": mutation_errors,
                        "vulnerability": {"id": GID, "state": returned_state},
                    }
                }
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = GitLabClient("test-token", http=http)

        # Act
        if succeeds:
            result = client.dismiss_false_positive(
                GID, "finding-1", "group/app", reason
            )
        else:
            with pytest.raises(RuntimeError):
                client.dismiss_false_positive(GID, "finding-1", "group/app", reason)

    # Assert
    assert len(requests) == 1 + expected_writes
    if succeeds:
        assert result["status"] == "DISMISSED"


def test_uuid_is_not_used_as_gitlab_mutation_id():
    """Reject finding UUIDs before issuing any network request."""
    # Arrange
    http = Mock(spec=httpx.Client)
    client = GitLabClient("test-token", http=http)

    # Act
    with pytest.raises(ValueError, match="global ID"):
        client.dismiss_false_positive(
            "finding-uuid", "finding-uuid", "group/app", "Reviewed"
        )
    with pytest.raises(RuntimeError, match="Only GitLab GraphQL queries"):
        client._graphql(DISMISS_FALSE_POSITIVE, {})

    # Assert
    assert http.mock_calls == []


def test_mcp_tool_exposes_no_ai_approval_arguments():
    """Use actual SDK registration to keep approvals out of the public input schema."""
    # Arrange
    tools = asyncio.run(server.mcp.list_tools())

    # Act
    review = next(item for item in tools if item.name == "review_false_positives")
    submit = next(
        item for item in tools if item.name == "submit_false_positive_approvals"
    )

    # Assert
    assert set(review.input_schema["properties"]) == {"repo_root"}
    assert set(submit.input_schema["properties"]) == {"repo_root"}
    assert review.annotations.destructive_hint is False
    assert review.annotations.read_only_hint is True
    assert submit.annotations.destructive_hint is True
    assert submit.annotations.read_only_hint is False


@pytest.mark.parametrize("selection", [True, False, "true"])
def test_real_sdk_form_dispatch_selects_only_the_checked_finding(
    tmp_path, monkeypatch, selection
):
    """Exercise SDK context injection and boolean validation, not a mocked elicit."""
    # Arrange
    from mcp.server.mcpserver import Context
    from mcp.server.mcpserver.tools.base import Tool
    from mcp.types import ElicitResult

    engine = _engine(tmp_path)
    engine.state.decisions["finding-2"] = deepcopy(engine.state.decisions["finding-1"])
    engine.gitlab.dismiss_false_positive.side_effect = lambda gid, *args: {
        "status": "DISMISSED",
        "vulnerability_id": gid,
    }
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    session = Mock()
    session.client_capabilities = ClientCapabilities.model_validate(
        {"elicitation": {"form": {}}}
    )
    session.elicit_form = AsyncMock(
        return_value=ElicitResult(
            action="accept", content={"finding_0": False, "finding_1": selection}
        )
    )
    ctx = Context(
        request_context=SimpleNamespace(session=session, request_id="approval")
    )
    tool = Tool.from_function(server.submit_false_positive_approvals)

    # Act
    result = asyncio.run(tool.run({"repo_root": str(tmp_path)}, ctx))

    # Assert
    form = session.elicit_form.call_args.kwargs["requested_schema"]
    assert form["properties"]["finding_0"]["default"] is False
    assert form["properties"]["finding_1"]["type"] == "boolean"
    if isinstance(selection, str):
        assert result["status"] == "APPROVAL_INVALID"
    if selection is True:
        engine.gitlab.dismiss_false_positive.assert_called_once_with(
            "gid://gitlab/Vulnerability/124",
            "finding-2",
            "group/app",
            engine.state.decisions["finding-2"]["reason"],
        )
    else:
        engine.gitlab.dismiss_false_positive.assert_not_called()
