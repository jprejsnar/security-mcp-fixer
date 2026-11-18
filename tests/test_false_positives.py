"""Verify human-only approval and narrowly scoped GitLab false-positive writes."""

import asyncio
import hashlib
import json
import logging
import os
import threading
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

from gitlab_security_mcp import __version__, server
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.gitlab_client import (
    DISMISS_FALSE_POSITIVE,
    DISMISSAL_CONFIRMATION_QUERY,
    DISMISSAL_TARGET_QUERY,
    GitLabClient,
    normalize_finding,
)
from gitlab_security_mcp.official_docs import (
    DocReview,
    DocSource,
    cited_security_pages,
    cited_security_pages_ok,
)
from gitlab_security_mcp.report import render
from tests.conftest import documentation_client

GID = "gid://gitlab/Vulnerability/123"


def _verification():
    """Model the client's independent read-back proof, not a mutation ACK."""
    return {
        "state": "DISMISSED",
        "dismissal_reason": "FALSE_POSITIVE",
        "verified_at": "2026-11-17T13:00:00+00:00",
    }


def _engine(tmp_path):
    """Provide one eligible assessment and one unresolved finding."""
    client = Mock(spec=GitLabClient)
    client.dismiss_false_positive.return_value = {
        "status": "DISMISSED",
        "vulnerability_id": GID,
        "verification": _verification(),
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


@pytest.mark.parametrize(
    ("action", "checked"), [("accept", True), ("accept", False), ("cancel", False)]
)
def test_desktop_approval_returns_before_human_response_and_refreshes_report(
    tmp_path, monkeypatch, action, checked
):
    """Keep human review outside the MCP deadline and mutate only checked snapshots."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    ctx = _context()
    dialog = Mock()
    dialog.close = AsyncMock()
    opened = AsyncMock(return_value=dialog)
    monkeypatch.setattr(server.desktop_approval, "open_dialog", opened)

    async def exercise():
        """Return completion while the human response is still blocked."""
        ready = asyncio.Event()

        async def wait():
            """Model an indefinitely open human dialog, not a timed response."""
            await ready.wait()
            return {"action": action, "content": {"finding_0": checked}}

        dialog.wait = wait
        result = await asyncio.wait_for(
            server.complete_security_run(ctx, str(tmp_path)), 5
        )
        task = next(iter(server._desktop_approval_tasks.values()))
        assert not task.done()
        assert (
            result.structured_content["false_positive_review"]["status"]
            == "AWAITING_HUMAN"
        )
        engine.gitlab.dismiss_false_positive.assert_not_called()
        duplicate = await server.submit_false_positive_approvals(ctx, str(tmp_path))
        assert duplicate["status"] == "AWAITING_HUMAN"
        ready.set()
        await task
        return result

    # Act
    asyncio.run(exercise())
    report = json.loads(Path(engine.state.json_report_path).read_text())

    # Assert
    ctx.elicit.assert_not_called()
    opened.assert_awaited_once()
    properties = opened.call_args.args[1]
    assert properties["finding_0"]["summary"] == (
        "The installed version is outside the affected range."
    )
    assert (
        "Dismiss as FALSE_POSITIVE with comment:"
        in properties["finding_0"]["description"]
    )
    dialog.close.assert_awaited_once()
    assert engine.gitlab.dismiss_false_positive.call_count == int(
        action == "accept" and checked
    )
    assert report["false_positive_approval_form"]["status"] == (
        "OK" if action == "accept" else "CANCELLED"
    )
    assert report["false_positive_approval_form"]["presentation"] == "WINDOWS_DIALOG"
    assert report["false_positive_approval"]["not_confirmed_dismissed"] == int(
        not checked
    )


@pytest.mark.skipif(os.name != "nt", reason="Requires the Windows PowerShell runtime")
@pytest.mark.parametrize(
    "foreground_pid,handles,cycle,area,expected_window,expected_bounds",
    [
        (
            20,
            {"10": 111, "20": 222},
            False,
            [-1920, 0, 1920, 1040],
            999,
            [-1560, 140, 1200, 760],
        ),
        (99, {"20": 222}, False, [1920, 40, 1280, 984], 222, [1960, 152, 1200, 760]),
        (99, {"10": 111}, False, [0, 0, 800, 600], 111, [0, 0, 800, 600]),
        (99, {}, False, [-1280, -1024, 1280, 1024], 0, [-1240, -892, 1200, 760]),
        (99, {}, True, [0, 0, 1201, 761], 0, [0, 0, 1200, 760]),
    ],
)
def test_approval_uses_host_ancestry_and_bounds_without_opening_windows(
    foreground_pid, handles, cycle, area, expected_window, expected_bounds
):
    """Prefer the host monitor, ignore unrelated apps, and fit negative/small screens."""
    # Arrange
    import subprocess

    script = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$data = [Console]::In.ReadToEnd() | ConvertFrom-Json
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($data.script, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw ($errors | Out-String) }
$functions = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in @('Get-ApprovalHostWindow', 'Get-ApprovalBounds')
}, $true))
if ($functions.Count -ne 2) { throw 'Placement functions missing' }
foreach ($function in $functions) { . ([scriptblock]::Create($function.Extent.Text)) }
function Get-Process {
    param([int]$Id, $ErrorAction)
    $value = $data.handles.PSObject.Properties[[string]$Id]
    $handle = if ($null -eq $value) { 0 } else { $value.Value }
    $result = [pscustomobject]@{ MainWindowHandle = [IntPtr][int]$handle }
    $result | Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
    return $result
}
$tree = @(
    [pscustomobject]@{ ProcessId = 30; ParentProcessId = 20 }
    [pscustomobject]@{ ProcessId = 20; ParentProcessId = $(if ($data.cycle) { 30 } else { 10 }) }
    [pscustomobject]@{ ProcessId = 10; ParentProcessId = 0 }
)
$selected = Get-ApprovalHostWindow -HostProcessId 30 -ProcessTree $tree `
    -ForegroundWindow ([IntPtr]999) -ForegroundProcessId $data.foreground_pid
$area = New-Object System.Drawing.Rectangle($data.area[0], $data.area[1], $data.area[2], $data.area[3])
$bounds = Get-ApprovalBounds -WorkingArea $area -RequestedSize (New-Object System.Drawing.Size(1200, 760))
@{ window = $selected.ToInt64(); bounds = @($bounds.X, $bounds.Y, $bounds.Width, $bounds.Height) } |
    ConvertTo-Json -Compress
"""
    # Act
    result = subprocess.run(
        [str(server.desktop_approval.powershell()), "-NoProfile", "-Command", script],
        input=json.dumps(
            {
                "script": server.desktop_approval.SCRIPT,
                "foreground_pid": foreground_pid,
                "handles": handles,
                "cycle": cycle,
                "area": area,
            }
        ),
        text=True,
        capture_output=True,
        timeout=20,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    # Assert
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "window": expected_window,
        "bounds": expected_bounds,
    }


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("SECURITY_MCP_DESKTOP_TESTS") != "1",
    reason="Requires an interactive Windows desktop and SECURITY_MCP_DESKTOP_TESTS=1",
)
@pytest.mark.parametrize("accept", [False, True])
def test_native_approval_wraps_both_columns_and_reflows_without_details_pane(
    monkeypatch, accept
):
    """Measure actual wrapped rows before/after resize and preserve checked-only consent."""
    # Arrange
    desktop = server.desktop_approval
    properties = {
        f"finding_{index}": {
            "title": "TEST ONLY - "
            + (
                "A lengthy synthetic issue title with file path and identifier. " * 8
                if index == 0
                else f"Short issue {index}"
            ),
            "summary": (
                "A synthetic explanation demonstrates a bounded literal input and a reviewed runtime control. "
                * 10
                if index == 0
                else "Short synthetic explanation."
            ),
        }
        for index in range(35)
    }
    test_script = r"""
$script:phase = 0
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 400
$timer.Add_Tick({
    $issue = $table.GetControlFromPosition(0, 1)
    $title = $issue.GetControlFromPosition(1, 0)
    $reason = $table.GetControlFromPosition(1, 1)
    if ($script:phase -eq 0) {
        if (-not $form.Visible -or $table.ColumnCount -ne 2) { throw 'Wrapped table not shown' }
        if ($title.Height -le 2 * $title.Font.Height -or $reason.Height -le 2 * $reason.Font.Height) {
            throw 'Both columns must display multiline text'
        }
        if ($title.Text -ne $choices[0].title -or $reason.Text -ne $choices[0].summary) {
            throw 'Wrapped text was changed or clipped'
        }
        if (@($form.Controls | Where-Object { $_ -is [System.Windows.Forms.TextBox] }).Count -ne 1) {
            throw 'The duplicate lower description pane still exists'
        }
        $script:titleHeight = $title.Height
        $script:reasonHeight = $reason.Height
        $script:phase = 1
        $form.Size = New-Object System.Drawing.Size(760, 500)
        return
    }
    $timer.Stop()
    if ($title.Height -le $script:titleHeight -or $reason.Height -le $script:reasonHeight) {
        throw 'Both columns must reflow and grow after narrowing the window'
    }
    if ($title.Height -lt $title.PreferredSize.Height -or $reason.Height -lt $reason.PreferredSize.Height) {
        throw 'A wrapped cell was clipped'
    }
    $rowHeight = $table.GetRowHeights()[1]
    if ($rowHeight -lt $issue.Height + $issue.Margin.Vertical -or $rowHeight -lt $reason.Height + $reason.Margin.Vertical) {
        throw 'Row height does not fit its wrapped contents'
    }
    if (-not $viewport.VerticalScroll.Visible -or $viewport.HorizontalScroll.Visible) {
        throw 'Rows must scroll vertically without horizontal clipping'
    }
    if (@($checks | Where-Object { $_.Checked }).Count -ne 0) { throw 'An issue was selected automatically' }
    if (-not $submit.Visible -or -not $cancel.Visible) { throw 'Approval buttons are not visible' }
    if (ACCEPT_TEST_RESPONSE) {
        $checks[1].Checked = $true
        $submit.PerformClick()
    } else {
        $cancel.PerformClick()
    }
})
$form.Add_Shown({ $timer.Start() })
$result = $form.ShowDialog()
$timer.Dispose()
""".replace("ACCEPT_TEST_RESPONSE", "$true" if accept else "$false")
    monkeypatch.setattr(
        desktop,
        "SCRIPT",
        desktop.SCRIPT.replace("$result = $form.ShowDialog()", test_script),
    )

    async def exercise():
        """Auto-close a clearly synthetic window; never call a GitLab mutation."""
        dialog = await desktop.open_dialog(
            "TEST ONLY - automated wrapping verification. No GitLab calls. Closes automatically.",
            properties,
        )
        try:
            return await asyncio.wait_for(dialog.wait(), 15)
        finally:
            await dialog.close()

    # Act
    response = asyncio.run(exercise())

    # Assert
    assert response == (
        {
            "action": "accept",
            "content": {
                f"finding_{index}": index == 1 for index in range(len(properties))
            },
        }
        if accept
        else {"action": "cancel"}
    )


def test_desktop_close_reaps_the_process_and_closes_its_pipes():
    """Close stdin, stdout, and stderr when the approval process is stopped."""
    # Arrange
    import sys

    from gitlab_security_mcp.desktop_approval import DesktopApproval

    async def exercise():
        """Stop a live child before it can exit on its own."""
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "import time; time.sleep(30)",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        dialog = DesktopApproval(process)
        await dialog.close()
        return process

    # Act
    process = asyncio.run(exercise())

    # Assert
    def closed(stream: object) -> bool:
        """Return whether the pipe transport has been closed or dropped."""
        transport = getattr(stream, "transport", None)
        if transport is None:
            transport = getattr(stream, "_transport", None)
        return transport is None or transport.is_closing()

    assert process.returncode is not None
    assert closed(process.stdin)
    assert closed(process.stdout)
    assert closed(process.stderr)


def test_desktop_close_after_the_response_closes_pipes_again():
    """Close pipes again after the response reader has already closed them."""
    # Arrange
    import sys

    from gitlab_security_mcp.desktop_approval import DesktopApproval

    async def exercise():
        """Read a cancel response, then close the finished dialog."""
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "import json,sys; sys.stdout.write(json.dumps({'action':'cancel'}))",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        dialog = DesktopApproval(process)
        response = await dialog.wait()
        await dialog.close()
        return response, process

    def closed(stream: object) -> bool:
        """Return whether the pipe transport has been closed or dropped."""
        transport = getattr(stream, "transport", None)
        if transport is None:
            transport = getattr(stream, "_transport", None)
        return transport is None or transport.is_closing()

    # Act
    response, process = asyncio.run(exercise())

    # Assert
    assert response == {"action": "cancel"}
    assert process.returncode == 0
    assert closed(process.stdin)
    assert closed(process.stdout)
    assert closed(process.stderr)


def test_concurrent_desktop_requests_share_one_starting_window(tmp_path, monkeypatch):
    """Reserve a window atomically before awaiting its native startup."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    dialog = Mock(wait=AsyncMock(return_value={"action": "cancel"}), close=AsyncMock())
    snapshot = engine.false_positive_candidates
    rendezvous = threading.Barrier(2)

    def concurrent_snapshot():
        """Make both requests finish their snapshot before either reserves startup."""
        result = snapshot()
        rendezvous.wait(timeout=5)
        return result

    monkeypatch.setattr(engine, "false_positive_candidates", concurrent_snapshot)

    async def exercise():
        """Hold the first launch pending while the second request arrives."""
        entered = asyncio.Event()
        release = asyncio.Event()

        async def open_dialog(*_args):
            """Model a slow but successful native window startup."""
            entered.set()
            await release.wait()
            return dialog

        opened = AsyncMock(side_effect=open_dialog)
        monkeypatch.setattr(server.desktop_approval, "open_dialog", opened)
        first = asyncio.create_task(
            server.submit_false_positive_approvals(_context(), str(tmp_path))
        )
        second = asyncio.create_task(
            server.submit_false_positive_approvals(_context(), str(tmp_path))
        )
        try:
            await asyncio.wait_for(entered.wait(), 2)
            completed, _pending = await asyncio.wait(
                (first, second), timeout=2, return_when=asyncio.FIRST_COMPLETED
            )
            assert len(completed) == 1
            assert completed.pop().result()["status"] == "REQUESTED"
            assert opened.await_count == 1
        finally:
            release.set()
            await asyncio.gather(first, second)
            await asyncio.gather(*list(server._desktop_approval_tasks.values()))

    # Act
    asyncio.run(exercise())

    # Assert
    dialog.close.assert_awaited_once()
    engine.gitlab.dismiss_false_positive.assert_not_called()


@pytest.mark.parametrize(
    "interruption", ["cancel", "receipt", "fresh_run", "fresh_cancel"]
)
def test_desktop_startup_interruption_does_not_leave_or_recreate_pending_receipt(
    tmp_path, monkeypatch, interruption
):
    """Clean cancelled startup and prevent its late response from overwriting a new run."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    dialog = Mock(wait=AsyncMock(return_value={"action": "cancel"}), close=AsyncMock())
    record = server._approval_result

    async def record_response(selected, receipt, result):
        """Model cancellation after native Shown but before the background owner starts."""
        if interruption == "receipt" and result["status"] == "AWAITING_HUMAN":
            raise asyncio.CancelledError
        return await record(selected, receipt, result)

    monkeypatch.setattr(server, "_approval_result", record_response)

    async def open_dialog(*_args):
        """Interrupt startup or replace its run before the window reports ready."""
        if interruption == "cancel":
            raise asyncio.CancelledError
        if interruption in {"fresh_run", "fresh_cancel"}:
            engine.state = deepcopy(engine.state)
            engine.state.false_positive_approval_form = {}
        if interruption == "fresh_cancel":
            raise asyncio.CancelledError
        return dialog

    monkeypatch.setattr(server.desktop_approval, "open_dialog", open_dialog)

    async def exercise():
        """Ensure no background task is left behind by a rejected startup."""
        if interruption != "fresh_run":
            with pytest.raises(asyncio.CancelledError):
                await server.submit_false_positive_approvals(_context(), str(tmp_path))
        else:
            result = await server.submit_false_positive_approvals(
                _context(), str(tmp_path)
            )
            assert result["status"] == "ERROR"
            assert engine.state.false_positive_approval_form == {}
            dialog.close.assert_awaited_once()

    # Act
    asyncio.run(exercise())

    # Assert
    if interruption in {"cancel", "receipt"}:
        assert (
            engine.state.false_positive_approval_form["status"]
            == "APPROVAL_INTERRUPTED"
        )
    if interruption == "receipt":
        dialog.close.assert_awaited_once()
    if interruption == "fresh_cancel":
        assert engine.state.false_positive_approval_form == {}
        assert engine.state.status == "FINDINGS_LISTED"
    assert not server._desktop_approval_tasks
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_interrupted_native_form_is_not_left_requested(tmp_path, monkeypatch):
    """Persist host cancellation explicitly instead of claiming the form was delivered."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    ctx = _context()
    ctx.elicit.side_effect = asyncio.CancelledError()

    # Act
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(server.submit_false_positive_approvals(ctx, str(tmp_path)))

    # Assert
    assert engine.state.false_positive_approval_form["status"] == "APPROVAL_INTERRUPTED"
    report = json.loads(Path(engine.state.json_report_path).read_text())
    assert report["false_positive_approval_form"]["status"] == "APPROVAL_INTERRUPTED"
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_desktop_window_closes_on_server_shutdown_without_authorizing(
    tmp_path, monkeypatch
):
    """Reap the pending window when the server event loop shuts down."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    dialog = Mock()
    dialog.close = AsyncMock()
    monkeypatch.setattr(
        server.desktop_approval, "open_dialog", AsyncMock(return_value=dialog)
    )

    async def exercise():
        """Leave the human response pending until asyncio.run cancels tasks."""
        waiting = asyncio.Event()

        async def wait():
            """Keep the simulated window open indefinitely."""
            waiting.set()
            await asyncio.Event().wait()

        dialog.wait = wait
        await server.complete_security_run(_context(), str(tmp_path))
        await waiting.wait()

    # Act
    asyncio.run(exercise())

    # Assert
    dialog.close.assert_awaited_once()
    assert not server._desktop_approval_tasks
    assert engine.state.false_positive_approval_form["status"] == "APPROVAL_INTERRUPTED"
    report = json.loads(Path(engine.state.json_report_path).read_text())
    assert report["false_positive_approval_form"]["status"] == "APPROVAL_INTERRUPTED"
    engine.gitlab.dismiss_false_positive.assert_not_called()


@pytest.mark.parametrize(
    "failure", ["launch", "invalid_response", "unexpected_response"]
)
def test_desktop_approval_failures_are_reported_without_dismissal(
    tmp_path, monkeypatch, failure
):
    """Expose native UI failures without accepting fallback approvals."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    dialog = Mock()
    dialog.close = AsyncMock()
    dialog.wait = AsyncMock(
        return_value={"action": "accept", "content": {"finding_0": "true"}}
    )
    opened = AsyncMock(return_value=dialog)
    if failure == "launch":
        opened.side_effect = OSError("Synthetic desktop launch failure")
    elif failure == "unexpected_response":
        dialog.wait.side_effect = TypeError("Synthetic unexpected response")
    monkeypatch.setattr(server.desktop_approval, "open_dialog", opened)

    async def exercise():
        """Finish the background validator if the window opened."""
        await server.complete_security_run(_context(), str(tmp_path))
        tasks = list(server._desktop_approval_tasks.values())
        if tasks:
            await asyncio.gather(*tasks)

    # Act
    asyncio.run(exercise())

    # Assert
    assert engine.state.false_positive_approval_form["status"] == (
        "APPROVAL_UNAVAILABLE" if failure == "launch" else "APPROVAL_INVALID"
    )
    report = json.loads(Path(engine.state.json_report_path).read_text())
    assert report["false_positive_approval_form"]["reason"]
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_desktop_termination_failure_still_closes_pipes():
    """Release every pipe even when terminating the owned window fails."""
    # Arrange
    from gitlab_security_mcp.desktop_approval import DesktopApproval

    process = Mock(returncode=None, wait=AsyncMock())
    process.terminate.side_effect = PermissionError("Synthetic termination denial")
    streams = (process.stdin, process.stdout, process.stderr)
    for stream in streams:
        stream.transport.is_closing.return_value = False

    # Act
    with pytest.raises(PermissionError, match="termination denial"):
        asyncio.run(DesktopApproval(process).close())

    # Assert
    for stream in streams:
        stream.transport.close.assert_called_once()
    process.wait.assert_not_awaited()


@pytest.mark.parametrize("stdout", [b'{"action":"cancel"}', b"", b"\xff"])
def test_desktop_dialog_diagnostics_reach_server_logs(stdout, caplog):
    """Log successful-window stderr and give unreadable output process context."""
    # Arrange
    from gitlab_security_mcp.desktop_approval import DesktopApproval

    process = Mock(pid=4321, returncode=0)
    process.communicate = AsyncMock(
        return_value=(stdout, b"Could not locate the MCP host monitor; using active")
    )

    # Act
    with caplog.at_level(logging.INFO, logger="gitlab_security_mcp"):
        if stdout.startswith(b"{"):
            response = asyncio.run(DesktopApproval(process).wait())
        else:
            with pytest.raises(ValueError, match="unreadable output") as failure:
                asyncio.run(DesktopApproval(process).wait())

    # Assert
    assert "pid=4321 reported diagnostics" in caplog.text
    assert "host monitor" in caplog.text
    if stdout.startswith(b"{"):
        assert response == {"action": "cancel"}
        assert "action=cancel" in caplog.text
    else:
        assert "pid=4321" in str(failure.value)
        assert f"{len(stdout)} bytes, exit 0" in str(failure.value)
        assert failure.value.__cause__ is not None


def test_background_cleanup_failure_is_retrieved_and_logged(
    tmp_path, monkeypatch, caplog
):
    """Observe cleanup failures with checkout/request context after saving the outcome."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    dialog = Mock(
        wait=AsyncMock(return_value={"action": "cancel"}),
        close=AsyncMock(side_effect=OSError("Synthetic pipe close failure")),
    )
    monkeypatch.setattr(
        server.desktop_approval, "open_dialog", AsyncMock(return_value=dialog)
    )

    async def exercise():
        """Complete the window owner and give its completion callback a turn."""
        await server.submit_false_positive_approvals(_context(), str(tmp_path))
        tasks = list(server._desktop_approval_tasks.values())
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.sleep(0)

    # Act
    asyncio.run(exercise())

    # Assert
    record = next(row for row in caplog.records if "Desktop task failed" in row.message)
    assert record.exc_info[0] is OSError
    assert str(tmp_path) in record.message
    assert engine.state.false_positive_approval_form["request_id"] in record.message
    assert engine.state.false_positive_approval_form["status"] == "CANCELLED"
    assert not server._desktop_approval_tasks
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_desktop_approval_cannot_apply_to_a_fresh_run(tmp_path):
    """An old window cannot authorize identical findings in a new run."""
    # Arrange
    engine = _engine(tmp_path)
    candidates = engine.false_positive_candidates()["candidates"]
    engine.state.false_positive_approval_form = {
        "request_id": "old",
        "status": "AWAITING_HUMAN",
    }
    engine.state = deepcopy(engine.state)
    engine.state.false_positive_approval_form = {}

    # Act
    result = engine.resolve_desktop_approval("old", candidates)

    # Assert
    assert result["status"] == "ERROR"
    engine.gitlab.dismiss_false_positive.assert_not_called()


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
                "verification": _verification(),
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
@pytest.mark.parametrize(
    "tool_name", ["complete_security_run", "generate_local_report"]
)
def test_combined_completion_automatically_offers_the_form_after_saving_report(
    tmp_path, monkeypatch, supported, tool_name
):
    """Offer real unchecked checkboxes without another ready-to-submit message."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    ctx = _context(supported=supported)
    tool = Tool.from_function(getattr(server, tool_name))
    original = ctx.elicit.side_effect

    async def elicit(message, schema):
        """Ensure reviewable reports exist before the host displays checkboxes."""
        assert list((tmp_path / ".security-mcp" / "reports").glob("*.json"))
        assert engine.state.report_path in message
        engine.gitlab.dismiss_false_positive.assert_not_called()
        return await original(message, schema)

    ctx.elicit.side_effect = elicit

    # Act
    result = asyncio.run(
        tool.run({"repo_root": str(tmp_path)}, ctx, convert_result=True)
    )
    payload = result.structured_content
    saved = json.loads(Path(payload["json_report"]).read_text(encoding="utf-8"))

    # Assert
    assert not result.is_error
    assert payload["status"] == "REPORT_GENERATED"
    assert ctx.elicit.await_count == int(supported)
    assert engine.gitlab.dismiss_false_positive.call_count == int(supported)
    assert len(saved["gitlab_dismissals"]) == int(supported)
    assert result.content[-1].text == payload["final_summary_markdown"]
    assert saved["final_summary_markdown"] == payload["final_summary_markdown"]
    assert payload["false_positive_review"]["status"] == (
        "APPROVAL_UNAVAILABLE" if not supported else "OK"
    )
    assert saved["false_positive_approval_form"]["status"] == (
        "OK" if supported else "APPROVAL_UNAVAILABLE"
    )
    snapshot = json.loads((tmp_path / ".security-mcp" / "run-state.json").read_text())
    assert payload["server_version"] == saved["server_version"] == __version__
    assert (
        snapshot["server_version"]
        == engine.get_run_status()["server_version"]
        == __version__
    )
    if supported:
        assert payload["false_positive_review"]["results"][0]["id"] == "finding-1"
        assert saved["false_positive_approval"]["not_confirmed_dismissed"] == 0
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
    result = report.structured_content["false_positive_review"]

    # Assert
    assert Path(report.structured_content["json_report"]).is_file()
    assert report.is_error is (failure == "mutation")
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

    # Assert
    assert Path(report.structured_content["json_report"]).is_relative_to(first_root)
    first.gitlab.dismiss_false_positive.assert_called_once()
    other.gitlab.dismiss_false_positive.assert_not_called()
    assert not (other_root / ".security-mcp").exists()


@pytest.mark.parametrize("action", ["decline", "cancel", "accept"])
@pytest.mark.parametrize(
    "tool_name", ["complete_security_run", "generate_local_report"]
)
def test_repeated_completion_does_not_repeat_an_unselected_form(
    tmp_path, monkeypatch, action, tool_name
):
    """Do not turn report regeneration into repeated unsolicited approval prompts."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    ctx = _context(action=action, checked=False)

    # Act
    first = asyncio.run(getattr(server, tool_name)(ctx, str(tmp_path)))
    second = asyncio.run(server.complete_security_run(ctx, str(tmp_path)))

    # Assert
    assert first.structured_content["false_positive_review"]["status"] == (
        "OK" if action == "accept" else "CANCELLED"
    )
    assert second.structured_content["false_positive_review"]["previous_form"][
        "status"
    ] == ("OK" if action == "accept" else "CANCELLED")
    ctx.elicit.assert_awaited_once()
    engine.gitlab.dismiss_false_positive.assert_not_called()


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


@pytest.mark.parametrize("receipt", ["valid", "missing", "wrong_url", "over_limit"])
def test_source_record_coverage_requires_every_named_record_receipt(receipt):
    """Missing or capped-away records cannot pass a vacuous all-success check."""
    # Arrange
    finding = {
        "identifiers": (
            [f"CWE-{index}" for index in range(600, 605)]
            if receipt == "over_limit"
            else ["CWE-601"]
        )
    }
    pages = cited_security_pages(finding)
    sources = tuple(
        DocSource(
            page["name"],
            "https://cwe.mitre.org/" if receipt == "wrong_url" else page["url"],
            True,
            200,
            "fixture-hash",
            None,
        )
        for page in pages
    )
    review = DocReview(()) if receipt == "missing" else DocReview(sources)

    # Act
    complete = cited_security_pages_ok(review, finding)

    # Assert
    assert complete is (receipt == "valid")


def test_typed_numeric_cwe_is_checked_and_retained_in_false_positive_audit(tmp_path):
    """Reproduce the latest run's numeric CWE without using its private application code."""
    # Arrange
    engine, source, review = _source_engine(tmp_path)
    engine.state.findings[0] = normalize_finding(
        {
            "id": GID,
            "uuid": "finding-1",
            "reportType": "SAST",
            "title": "Synthetic redirect finding",
            "location": {"file": source.name, "startLine": 1},
            "identifiers": [{"externalType": "cwe", "externalId": "601"}],
        },
        None,
    )
    engine.docs = documentation_client(
        {"https://cwe.mitre.org/data/definitions/601.html": "CWE-601 fixture"}
    )
    review["finding_analysis"] += " CWE-601 does not apply to a literal declaration."

    # Act
    result = engine.verify_security_finding("finding-1", source_review=review)

    # Assert
    assert result["decision"] == "FALSE_POSITIVE"
    assert result["reason"] == review["reason"]
    audit = engine.state.findings[0]["falsePositiveAudit"]
    assert "https://cwe.mitre.org/data/definitions/601.html" in audit
    assert "GitLab did not cite a CVE or CWE" not in audit
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_source_approval_description_uses_reviewed_code_and_preserves_audit(tmp_path):
    """Show the source-backed explanation separately without weakening the GitLab comment."""
    # Arrange
    engine, _source, review = _source_engine(tmp_path)
    engine.verify_security_finding("finding-1", source_review=review)

    # Act
    candidates = engine.false_positive_candidates()["candidates"]
    result = engine.dismiss_false_positives(candidates)

    # Assert
    assert candidates[0]["description"] == review["reason"]
    assert "Files reviewed:" not in candidates[0]["description"]
    comment = candidates[0]["reason"]
    assert review["reason"] in comment
    assert review["finding_analysis"] in comment
    assert review["reviewed_files"][0]["sha256"] in comment
    assert result["status"] == "OK"
    engine.gitlab.dismiss_false_positive.assert_called_once_with(
        GID, "finding-1", "group/app", comment
    )


@pytest.mark.parametrize("reason_length", [400, 401])
def test_false_positive_explanation_length_requires_concise_reassessment(
    tmp_path, reason_length
):
    """Reject rather than silently clip a summary that obscures the actual conclusion."""
    # Arrange
    engine, _source, review = _source_engine(tmp_path)
    prefix = review["reason"] + " Supporting review detail: "
    review["reason"] = prefix + "x" * (reason_length - len(prefix) - 1) + "."

    # Act
    result = engine.verify_security_finding("finding-1", source_review=review)

    # Assert
    assert result["decision"] == (
        "FALSE_POSITIVE" if reason_length == 400 else "SOURCE_REVIEW_REQUIRED"
    )
    candidates = engine.false_positive_candidates()["candidates"]
    if reason_length == 400:
        assert candidates[0]["description"] == review["reason"]
    else:
        assert "400 characters" in result["reason"]
        assert candidates == []
    engine.gitlab.dismiss_false_positive.assert_not_called()


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("Endpoint.java", 'class Endpoint { String route = "/status"; }\n'),
        (
            "backend/src/main/java/Endpoint.java",
            'class Endpoint { String route = "/status"; }\n',
        ),
        ("Endpoint.cs", 'class Endpoint { public const string Route = "/status"; }\n'),
        ("endpoint.ts", 'export const route: string = "/status";\n'),
        ("endpoint.js", 'const route = "/status";\n'),
        ("frontend/endpoint.js", 'const route = "/status";\n'),
        (
            "backend/Endpoint.cs",
            'class Endpoint { public const string Route = "/status"; }\n',
        ),
        ("endpoint.py", 'route = "/status"\n'),
        ("Dockerfile", "FROM scratch\n"),
        ("Dockerfile.production", "FROM scratch\n"),
        ("nginx.conf", "server_tokens off;\n"),
        ("nginx/conf.d/site.conf", "server_tokens off;\n"),
    ],
)
def test_sdk_reviews_all_supported_source_and_configuration_types(
    tmp_path, monkeypatch, name, content
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
    ctx = Context()
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
    assert "content" not in cited
    assert cited["cited_text"] in source.read_text(encoding="utf-8")
    assert cited["path"].replace("\\", "/") == name
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
    ctx = Context()
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
    cited = pending["ai_source_review"]["cited_source"]
    assert "content" not in cited
    assert cited["cited_text"] in source.read_text(encoding="utf-8")
    assert cited["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    engine.gitlab.dismiss_false_positive.assert_not_called()
    assert bool(engine.false_positive_candidates()["candidates"]) is (
        decision == "FALSE_POSITIVE"
    )


def test_host_receives_full_source_and_must_record_review(tmp_path, monkeypatch):
    """Give the calling AI actual source, not a generic terminal placeholder."""
    # Arrange
    engine, source, review = _source_engine(tmp_path)
    ctx = Context()
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    tool = Tool.from_function(server.verify_security_finding)

    # Act
    pending = asyncio.run(tool.run({"finding_id": "finding-1"}, ctx))
    recorded = asyncio.run(
        tool.run({"finding_id": "finding-1", "source_review": review}, ctx)
    )

    # Assert
    assert pending["ai_source_review"]["status"] == "HOST_REVIEW_REQUIRED"
    cited = pending["ai_source_review"]["cited_source"]
    assert "content" not in cited
    assert cited["cited_text"] in source.read_text(encoding="utf-8")
    assert cited["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert "open the file and line GitLab already reported" in pending["reason"]
    assert "read the cited file in the checkout" in pending["reason"]
    assert recorded["decision"] == "FALSE_POSITIVE"
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
    ctx = Context()
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
    assert engine.false_positive_candidates()["candidates"] == []
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_ai_review_rejects_source_changed_during_host_review(tmp_path, monkeypatch):
    """Recheck full-byte evidence before storing the calling AI's conclusion."""
    # Arrange
    engine, source, review = _source_engine(tmp_path)
    ctx = Context()
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
    ctx = Context()
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
    engine.gitlab.dismiss_false_positive.assert_not_called()


def test_archived_style_pending_reviews_continue_to_human_approval(
    tmp_path, monkeypatch
):
    """Keep seven excerpt-only and 150 unverified findings pending without inventing verdicts."""
    # Arrange
    engine, _source, review = _source_engine(tmp_path)
    first = engine.state.findings[0]
    engine.verify_security_finding(first["id"])
    for index in range(1, 157):
        finding = deepcopy(first)
        finding["id"] = f"pending-{index}"
        finding["vulnerabilityId"] = f"gid://gitlab/Vulnerability/{index + 200}"
        engine.state.findings.append(finding)
        if index < 7:
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
    assert engine.get_run_status()["source_review_required_count"] == 156
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
    if decision == "FALSE_POSITIVE":
        audit = payload["false_positive_audits"]["finding-1"]
        assert review["finding_analysis"] in audit
        assert review["reviewed_files"][0]["sha256"] in audit
        assert candidates[0]["reason"] == audit
    else:
        assert payload["false_positive_audits"] == {}
    assert bool(candidates) is (decision == "FALSE_POSITIVE")
    assert bool(payload["unresolved_issues"]) is (decision != "FALSE_POSITIVE")
    assert status["source_review_queue"]["finding_count"] == 1
    assert "sourceReview" not in engine.state.findings[0]
    assert "falsePositiveAudit" not in engine.state.findings[0]
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


def test_parallel_dismissals_keep_consent_durability_and_independent_proof(
    tmp_path, monkeypatch
):
    """Overlap distinct targets, persist each result on the caller, and never retry writes."""
    # Arrange
    from collections import Counter

    from gitlab_security_mcp.fanout import MAX_WORKERS

    engine = _engine(tmp_path)
    findings = [
        normalize_finding(
            {
                "id": f"gid://gitlab/Vulnerability/{index + 1}",
                "uuid": f"finding-{index}",
                "state": "DETECTED",
            },
            None,
        )
        for index in range(MAX_WORKERS + 3)
    ]
    engine.state.findings = findings
    engine.state.decisions = {
        finding["id"]: {
            "decision": "FALSE_POSITIVE",
            "reason": "Synthetic reviewed finding.",
        }
        for finding in findings
    }
    approved = engine.false_positive_candidates()["candidates"][:-1]
    caller = threading.get_ident()
    saves = []
    save = engine._remember

    def remember():
        """Check that completion persistence stays on the caller thread."""
        assert threading.get_ident() == caller
        save()
        saves.append([item["status"] for item in engine.state.gitlab_dismissals])

    monkeypatch.setattr(engine, "_remember", remember)
    barrier = threading.Barrier(MAX_WORKERS, timeout=5)
    lock = threading.Lock()
    inflight = peak = 0
    calls = Counter()

    def handler(request):
        """Coordinate concurrent target checks and simulate one uncertain mutation."""
        nonlocal inflight, peak
        data = json.loads(request.content)
        vulnerability_id = data["variables"]["id"]
        index = int(vulnerability_id.rsplit("/", 1)[-1]) - 1
        query = data["query"]
        operation = (
            "target"
            if query == DISMISSAL_TARGET_QUERY
            else ("confirm" if query == DISMISSAL_CONFIRMATION_QUERY else "mutation")
        )
        with lock:
            calls[(index, operation)] += 1
            inflight += 1
            peak = max(peak, inflight)
        try:
            if operation == "target":
                if index < MAX_WORKERS:
                    saved = json.loads(
                        (tmp_path / ".security-mcp" / "run-state.json").read_text()
                    )
                    assert len(saved["gitlab_dismissals"]) == len(approved)
                    assert all(
                        item["status"] == "PENDING"
                        for item in saved["gitlab_dismissals"]
                    )
                    barrier.wait()
            if operation == "mutation" and index == 2:
                raise httpx.ReadTimeout(
                    "Synthetic lost mutation response", request=request
                )
            node = {
                "id": vulnerability_id,
                "uuid": f"finding-{index}",
                "project": {"fullPath": "group/app"},
                "state": "DETECTED" if operation == "target" else "DISMISSED",
                "dismissalReason": "FALSE_POSITIVE",
            }
            return httpx.Response(
                200,
                json={
                    "data": {
                        "vulnerabilityDismiss": {"errors": [], "vulnerability": node}
                    }
                }
                if operation == "mutation"
                else {"data": {"vulnerability": node}},
            )
        finally:
            with lock:
                inflight -= 1

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with GitLabClient("fixture-token", http=http) as client:
            engine.gitlab = client
            result = engine.dismiss_false_positives(approved)

    # Assert
    assert 2 <= peak <= MAX_WORKERS
    assert result["status"] == "PARTIAL_FAILURE"
    assert result["confirmed_dismissals"] == len(approved) - 1
    assert [item["id"] for item in result["results"]] == [
        item["id"] for item in approved
    ]
    assert saves[0] == ["PENDING"] * len(approved)
    assert any("DISMISSED" in snapshot and "PENDING" in snapshot for snapshot in saves)
    assert all(status != "PENDING" for status in saves[-1])
    assert result["results"][2]["status"] == "ERROR"
    assert not any(index == len(findings) - 1 for index, _operation in calls)
    assert all(count == 1 for count in calls.values())
    assert calls[(2, "confirm")] == 0
    assert client._dismissal_locks == {}


def test_duplicate_gitlab_target_cannot_mutate_concurrently_or_twice():
    """A second call for the same target must observe the first persisted dismissal."""
    # Arrange
    from concurrent.futures import ThreadPoolExecutor

    remote = {"dismissed": False, "writes": 0}
    lock = threading.Lock()
    start = threading.Barrier(2, timeout=5)

    def handler(request):
        """Read or update the simulated remote target under one lock."""
        data = json.loads(request.content)
        with lock:
            if data["query"] == DISMISS_FALSE_POSITIVE:
                remote["writes"] += 1
                remote["dismissed"] = True
            node = {
                "id": GID,
                "uuid": "finding-1",
                "project": {"fullPath": "group/app"},
                "state": "DISMISSED" if remote["dismissed"] else "DETECTED",
                "dismissalReason": "FALSE_POSITIVE" if remote["dismissed"] else None,
            }
        return httpx.Response(
            200,
            json={
                "data": {"vulnerabilityDismiss": {"errors": [], "vulnerability": node}}
            }
            if data["query"] == DISMISS_FALSE_POSITIVE
            else {"data": {"vulnerability": node}},
        )

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with GitLabClient("fixture-token", http=http) as client:

            def dismiss():
                """Start both operations together on one vulnerability."""
                start.wait()
                return client.dismiss_false_positive(
                    GID, "finding-1", "group/app", "Reviewed fixture."
                )

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = [
                    future.result(timeout=5)
                    for future in [pool.submit(dismiss), pool.submit(dismiss)]
                ]

    # Assert
    assert all(item["status"] == "DISMISSED" for item in results)
    assert remote["writes"] == 1
    assert sum(bool(item.get("already_dismissed")) for item in results) == 1


def test_gitlab_close_waits_for_admitted_dismissals_and_rejects_new_ones():
    """Never close an owned HTTP pool while a target is using it."""
    # Arrange
    from concurrent.futures import ThreadPoolExecutor

    entered = threading.Event()
    release = threading.Event()
    http = Mock()
    client = GitLabClient("fixture-token", http=http)
    client._owns_http = True

    def admitted():
        """Hold an admitted operation until the shutdown assertion finishes."""
        with client._dismissal_access(GID):
            entered.set()
            assert release.wait(5)
            http.close.assert_not_called()

    # Act
    with ThreadPoolExecutor(max_workers=2) as pool:
        active = pool.submit(admitted)
        assert entered.wait(3)
        closing = pool.submit(client.close)
        try:
            with client._idle:
                assert client._idle.wait_for(lambda: client._closing, timeout=1)
            assert not closing.done()
            with pytest.raises(RuntimeError, match="closed"):
                client.dismiss_false_positive(
                    GID, "finding-1", "group/app", "Reviewed fixture."
                )
            http.close.assert_not_called()
        finally:
            release.set()
        active.result(timeout=3)
        closing.result(timeout=3)

    # Assert
    http.close.assert_called_once()
    assert client._closed


def test_report_distinguishes_host_changes_and_tests_from_mcp_evidence(tmp_path):
    """Do not contradict the archive's externally edited working tree or test execution."""
    # Arrange
    engine = _engine(tmp_path)
    # Act
    payload, markdown = render(
        engine.state,
        staged=[],
        diff_stat="logback.xml | 2 +-",
        diff_files=" M logback.xml",
    )

    # Assert
    assert "No MCP-managed remediation edits were recorded." in markdown
    assert "No files were changed." not in markdown
    assert "M logback.xml" in markdown
    assert payload["unit_test_validation"]["status"] == "NOT_RUN"
    assert "outside this result" in payload["unit_test_validation"]["reason"]
    assert "not verified by MCP" in payload["unit_test_validation"]["reason"]


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
        if body["query"] == DISMISSAL_CONFIRMATION_QUERY:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "vulnerability": {
                            "id": GID,
                            "uuid": "finding-1",
                            "state": "DISMISSED",
                            "dismissalReason": "FALSE_POSITIVE",
                            "project": {"fullPath": "group/app"},
                        }
                    }
                },
            )
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
    assert len(requests) == 1 + expected_writes + int(succeeds)
    if succeeds:
        assert result["status"] == "DISMISSED"


@pytest.mark.parametrize(
    "mode",
    [
        "confirmed",
        "transition_reason",
        "detected",
        "wrong_reason",
        "wrong_identity",
        "missing_reason",
        "timeout",
        "graphql_error",
    ],
)
def test_dismissal_requires_independent_persisted_state_and_reason(tmp_path, mode):
    """A successful mutation response alone must never count as a dismissal."""
    # Arrange
    queries = []
    path = tmp_path / "http-timings.jsonl"

    def handler(request):
        """Acknowledge the write, then provide independently controlled evidence."""
        body = json.loads(request.content)
        query = body["query"]
        queries.append(query)
        target = {
            "id": GID,
            "uuid": "finding-1",
            "state": "DETECTED",
            "project": {"fullPath": "group/app"},
        }
        if query == DISMISSAL_TARGET_QUERY:
            return httpx.Response(200, json={"data": {"vulnerability": target}})
        if query == DISMISS_FALSE_POSITIVE:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "vulnerabilityDismiss": {
                            "errors": [],
                            "vulnerability": {"id": GID, "state": "DISMISSED"},
                        }
                    }
                },
            )
        assert query == DISMISSAL_CONFIRMATION_QUERY
        if mode == "timeout":
            raise httpx.ReadTimeout("Read-back unavailable", request=request)
        if mode == "graphql_error":
            return httpx.Response(200, json={"errors": [{"message": "Read denied"}]})
        target.update(state="DISMISSED", dismissalReason="FALSE_POSITIVE")
        if mode == "detected":
            target["state"] = "DETECTED"
        elif mode == "wrong_reason":
            target["dismissalReason"] = "ACCEPTABLE_RISK"
        elif mode == "wrong_identity":
            target["uuid"] = "different-finding"
        elif mode in {"transition_reason", "missing_reason"}:
            target["dismissalReason"] = None
            target["stateTransitions"] = {
                "nodes": (
                    [{"toState": "DISMISSED", "dismissalReason": "FALSE_POSITIVE"}]
                    if mode == "transition_reason"
                    else []
                )
            }
        return httpx.Response(200, json={"data": {"vulnerability": target}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = GitLabClient("test-token", http=http, http_log_path=path)

        # Act
        if mode in {"confirmed", "transition_reason"}:
            result = client.dismiss_false_positive(
                GID, "finding-1", "group/app", "Reviewed"
            )
        else:
            with pytest.raises((RuntimeError, httpx.ReadTimeout)):
                client.dismiss_false_positive(GID, "finding-1", "group/app", "Reviewed")

    # Assert
    assert queries == [
        DISMISSAL_TARGET_QUERY,
        DISMISS_FALSE_POSITIVE,
        DISMISSAL_CONFIRMATION_QUERY,
    ]
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["operation"] for row in events] == [
        "DismissalTarget",
        "DismissFalsePositive",
        "ConfirmFalsePositiveDismissal",
    ]
    assert "test-token" not in path.read_text()
    assert "Reviewed" not in path.read_text()
    if mode in {"confirmed", "transition_reason"}:
        assert result["verification"]["dismissal_reason"] == "FALSE_POSITIVE"
        assert result["verification"]["verified_at"]
        assert result["vulnerability_url"].endswith(
            "/group/app/-/security/vulnerabilities/123"
        )


def test_concurrent_dismissal_requests_do_not_repeat_the_write():
    """Keep check/write/read-back atomic per client and reconcile duplicate calls."""
    # Arrange
    from concurrent.futures import ThreadPoolExecutor

    writes = []
    target = {
        "id": GID,
        "uuid": "finding-1",
        "state": "DETECTED",
        "project": {"fullPath": "group/app"},
    }

    def handler(request):
        """Serve the persisted state through each read and the single mutation."""
        body = json.loads(request.content)
        if body["query"] == DISMISS_FALSE_POSITIVE:
            writes.append(body)
            target.update(state="DISMISSED", dismissalReason="FALSE_POSITIVE")
            return httpx.Response(
                200,
                json={
                    "data": {
                        "vulnerabilityDismiss": {
                            "errors": [],
                            "vulnerability": {"id": GID, "state": "DISMISSED"},
                        }
                    }
                },
            )
        return httpx.Response(200, json={"data": {"vulnerability": dict(target)}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = GitLabClient("test-token", http=http)

        # Act
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    client.dismiss_false_positive,
                    GID,
                    "finding-1",
                    "group/app",
                    "Reviewed",
                )
                for _ in range(2)
            ]
            results = [future.result(timeout=5) for future in futures]

    # Assert
    assert len(writes) == 1
    assert all(result["verification"]["state"] == "DISMISSED" for result in results)
    assert sum(result.get("already_dismissed") is True for result in results) == 1


def test_lost_dismissal_response_can_be_reconciled_without_another_write():
    """After an uncertain write, a later human-approved call only confirms it."""
    # Arrange
    writes = []
    target = {
        "id": GID,
        "uuid": "finding-1",
        "state": "DETECTED",
        "project": {"fullPath": "group/app"},
    }

    def handler(request):
        """Persist the mutation remotely even though its HTTP response is lost."""
        body = json.loads(request.content)
        if body["query"] == DISMISS_FALSE_POSITIVE:
            writes.append(body)
            target.update(state="DISMISSED", dismissalReason="FALSE_POSITIVE")
            raise httpx.ReadTimeout("Lost mutation response", request=request)
        assert body["query"] in {DISMISSAL_TARGET_QUERY, DISMISSAL_CONFIRMATION_QUERY}
        return httpx.Response(200, json={"data": {"vulnerability": dict(target)}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = GitLabClient("test-token", http=http)

        # Act
        with pytest.raises(httpx.ReadTimeout):
            client.dismiss_false_positive(GID, "finding-1", "group/app", "Reviewed")
        result = client.dismiss_false_positive(
            GID, "finding-1", "group/app", "Reviewed"
        )

    # Assert
    assert len(writes) == 1
    assert result["already_dismissed"] is True
    assert result["verification"]["state"] == "DISMISSED"


@pytest.mark.parametrize("failed_index", [None, 27])
def test_fifty_five_human_selections_are_verified_individually(
    tmp_path, monkeypatch, failed_index
):
    """Process all selected rows once, leaving unchecked and unverified rows honest."""
    # Arrange
    engine = _engine(tmp_path)
    engine.state.findings = [
        normalize_finding(
            {
                "id": f"gid://gitlab/Vulnerability/{123 + i}",
                "uuid": f"finding-{i}",
                "title": f"Finding {i}",
                "state": "DETECTED",
            },
            None,
        )
        for i in range(57)
    ]
    engine.state.decisions = {
        item["id"]: {"decision": "FALSE_POSITIVE", "reason": f"Reviewed {item['id']}"}
        for item in engine.state.findings
    }
    remote = {
        item["vulnerabilityId"]: {
            "id": item["vulnerabilityId"],
            "uuid": item["id"],
            "state": "DETECTED",
            "project": {"fullPath": "group/app"},
        }
        for item in engine.state.findings
    }
    writes = []
    requests = []

    def handler(request):
        """Reject every operation except identity, fixed dismissal and confirmation."""
        assert request.method == "POST"
        assert request.url.path == "/api/graphql"
        body = json.loads(request.content)
        requests.append(body["query"])
        target = remote[body["variables"]["id"]]
        if body["query"] == DISMISS_FALSE_POSITIVE:
            writes.append(body)
            target.update(state="DISMISSED", dismissalReason="FALSE_POSITIVE")
            return httpx.Response(
                200,
                json={
                    "data": {
                        "vulnerabilityDismiss": {
                            "errors": [],
                            "vulnerability": {"id": target["id"], "state": "DISMISSED"},
                        }
                    }
                },
            )
        assert body["query"] in {DISMISSAL_TARGET_QUERY, DISMISSAL_CONFIRMATION_QUERY}
        result = dict(target)
        if body["query"] == DISMISSAL_CONFIRMATION_QUERY and (
            target["uuid"] == f"finding-{failed_index}"
        ):
            result["state"] = "DETECTED"
        return httpx.Response(200, json={"data": {"vulnerability": result}})

    async def choose(message, schema):
        """Return physical-host form selections, not tool arguments or model consent."""
        assert all(field.default is False for field in schema.model_fields.values())
        return SimpleNamespace(
            action="accept",
            data=schema(**{f"finding_{i}": i < 55 for i in range(57)}),
        )

    ctx = _context()
    ctx.elicit = AsyncMock(side_effect=choose)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        engine.gitlab = GitLabClient("test-token", http=http)

        # Act
        result = asyncio.run(server.submit_false_positive_approvals(ctx, str(tmp_path)))
        payload, markdown = render(engine.state, staged=[], diff_stat="", diff_files="")

    # Assert
    failures = int(failed_index is not None)
    assert result["status"] == ("PARTIAL_FAILURE" if failures else "OK")
    assert result["selected_count"] == 55
    assert result["confirmed_dismissals"] == 55 - failures
    assert result["unconfirmed_dismissals"] == failures
    assert engine.get_run_status()["gitlab_dismissal_counts"] == {
        "attempted": 55,
        "confirmed": 55 - failures,
        "not_confirmed": failures,
    }
    assert len(writes) == len({row["variables"]["id"] for row in writes}) == 55
    assert len(requests) == 55 * 3
    assert (
        payload["false_positive_approval"]["previously_confirmed_dismissals"]
        == 55 - failures
    )
    assert payload["false_positive_approval"]["not_confirmed_dismissed"] == 2 + failures
    assert all(
        remote[f"gid://gitlab/Vulnerability/{123 + i}"]["state"] == "DETECTED"
        for i in (55, 56)
    )
    assert len(engine.state.false_positive_approval_form["selected_ids"]) == 55
    assert engine.state.findings[0]["status"] == "dismissed"
    assert engine.state.findings[55]["status"] == "detected"
    assert "independently verified" in markdown
    assert "pipeline scan artifacts are not user dismissal status" in markdown
    if failures:
        assert result["results"][27]["status"] == "ERROR"
        assert "read-back did not confirm" in result["results"][27]["error"]


@pytest.mark.parametrize(
    ("method", "route", "query"),
    [
        ("POST", "/projects/1/repository/tags", None),
        ("POST", "/projects/1/repository/branches", None),
        ("POST", "/projects/1/issues/1/notes", None),
        ("PUT", "/projects/1", None),
        ("DELETE", "/projects/1/repository/branches/main", None),
        ("PATCH", "/projects/1/labels", None),
        (
            "POST",
            "/api/graphql",
            "mutation UpdateProject { projectUpdate(input: {}) { errors } }",
        ),
        (
            "POST",
            "/api/graphql",
            DISMISS_FALSE_POSITIVE + "\nmutation Other { deleteProject }",
        ),
    ],
)
def test_gitlab_unrelated_write_requests_are_rejected_before_network(
    method, route, query
):
    """No project tag, note, label, branch or unrelated mutation can leave the client."""
    # Arrange
    http = Mock(spec=httpx.Client)
    client = GitLabClient("test-token", http=http)
    body = {"query": query, "variables": {}} if query else None

    # Act
    with pytest.raises(PermissionError, match="project attributes"):
        client._request(method, f"https://gitlab.com{route}", body)

    # Assert
    http.stream.assert_not_called()


def test_mutation_ack_without_readback_proof_is_not_reported_as_success(tmp_path):
    """Never hide pending dismissals behind legacy success-shaped receipts."""
    # Arrange
    engine = _engine(tmp_path)
    engine.gitlab.dismiss_false_positive.return_value.pop("verification")

    # Act
    result = engine.dismiss_false_positives(
        engine.false_positive_candidates()["candidates"]
    )
    payload, markdown = render(engine.state, staged=[], diff_stat="", diff_files="")

    # Assert
    assert result["status"] == "PARTIAL_FAILURE"
    assert payload["false_positive_approval"]["previously_confirmed_dismissals"] == 0
    assert "read-back proof" in markdown


def test_legacy_dismissal_receipts_do_not_hide_unverified_findings(tmp_path):
    """Old success-shaped receipts must not remove findings from approval/reporting."""
    # Arrange
    engine = _engine(tmp_path)
    engine.state.gitlab_dismissals = [
        {
            "id": "finding-1",
            "status": "DISMISSED",
            "reason": "Old mutation ACK",
        }
    ]

    # Act
    payload, markdown = render(engine.state, staged=[], diff_stat="", diff_files="")
    candidates = engine.false_positive_candidates()["candidates"]

    # Assert
    assert payload["false_positive_approval"]["previously_confirmed_dismissals"] == 0
    assert payload["false_positive_approval"]["not_confirmed_dismissed"] == 1
    assert "UNVERIFIED" in markdown
    assert [item["id"] for item in candidates] == ["finding-1"]


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


@pytest.mark.parametrize("capability", [{}, {"form": {}}])
@pytest.mark.parametrize("selection", [True, False, "true"])
def test_real_sdk_form_dispatch_selects_only_the_checked_finding(
    tmp_path, monkeypatch, selection, capability
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
        "verification": _verification(),
    }
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    session = Mock()
    session.client_capabilities = ClientCapabilities.model_validate(
        {"elicitation": capability}
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


def test_url_only_host_is_not_sent_a_checkbox_form(tmp_path, monkeypatch):
    """Do not mistake URL elicitation for native form support."""
    # Arrange
    engine = _engine(tmp_path)
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    ctx = _context()
    ctx.session.client_capabilities = ClientCapabilities.model_validate(
        {"elicitation": {"url": {}}}
    )

    # Act
    result = asyncio.run(server.submit_false_positive_approvals(ctx, str(tmp_path)))

    # Assert
    assert result["status"] == "APPROVAL_UNAVAILABLE"
    ctx.elicit.assert_not_called()
    engine.gitlab.dismiss_false_positive.assert_not_called()


@pytest.mark.parametrize(
    "tool_name", ["complete_security_run", "generate_local_report"]
)
def test_complete_run_sends_native_checkboxes_over_the_mcp_connection(
    tmp_path, monkeypatch, tool_name
):
    """Deliver elicitation through a real MCP client/server exchange, not a mock context."""
    # Arrange
    from functools import partial

    import anyio
    from mcp import ClientSession
    from mcp.shared.memory import create_client_server_memory_streams
    from mcp.types import ElicitRequestFormParams, ElicitResult

    engine = _engine(tmp_path)
    engine.state.decisions["finding-2"] = deepcopy(engine.state.decisions["finding-1"])
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    forms = []
    engine.gitlab.dismiss_false_positive.side_effect = lambda gid, *args: {
        "status": "DISMISSED",
        "vulnerability_id": gid,
        "verification": _verification(),
    }

    async def human_response(_context, params):
        """Return synthetic human selections while GitLab writes remain mocked."""
        assert isinstance(params, ElicitRequestFormParams)
        forms.append(params)
        properties = params.requested_schema["properties"]
        assert set(properties) == {"finding_0", "finding_1"}
        assert all(field["type"] == "boolean" for field in properties.values())
        assert all(field["default"] is False for field in properties.values())
        assert list((tmp_path / ".security-mcp" / "reports").glob("*.json"))
        engine.gitlab.dismiss_false_positive.assert_not_called()
        return ElicitResult(
            action="accept", content={"finding_0": False, "finding_1": True}
        )

    async def complete():
        """Run one actual tool call over paired MCP message streams."""
        async with create_client_server_memory_streams() as (client, remote):
            async with anyio.create_task_group() as tasks:
                lowlevel = server.mcp._lowlevel_server
                tasks.start_soon(
                    partial(
                        lowlevel.run,
                        *remote,
                        lowlevel.create_initialization_options(),
                    )
                )
                async with ClientSession(
                    *client, elicitation_callback=human_response
                ) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        tool_name, {"repo_root": str(tmp_path)}
                    )
                tasks.cancel_scope.cancel()
                return result

    # Act
    result = anyio.run(complete)

    # Assert
    assert not result.is_error
    assert len(forms) == 1
    engine.gitlab.dismiss_false_positive.assert_called_once_with(
        "gid://gitlab/Vulnerability/124",
        "finding-2",
        "group/app",
        engine.state.decisions["finding-2"]["reason"],
    )
    saved = json.loads(Path(result.structured_content["json_report"]).read_text())
    assert saved["false_positive_approval_form"]["selected_ids"] == ["finding-2"]
    assert saved["false_positive_approval"]["not_confirmed_dismissed"] == 1


@pytest.mark.parametrize(
    "change",
    [
        None,
        "main_changed",
        "resolution_changed",
        "default_changed",
        "ref_changed",
        "main_present",
    ],
)
def test_branch_resolution_requires_main_evidence_human_approval_and_freshness(
    tmp_path, monkeypatch, change
):
    """Only approve branch-scoped findings explicitly resolved on unchanged default main."""
    # Arrange
    phase = {"approval": False}
    mutations = []
    sha = "a" * 40
    branch_node = {
        "id": GID,
        "uuid": "finding-1",
        "title": "Already fixed source issue",
        "reportType": "SAST",
        "state": "DETECTED",
        "trackedRef": {"id": "release-id", "name": "release"},
        "resolvedOnDefaultBranch": True,
        "location": {"file": "MissingOnThisCheckout.java", "startLine": 7},
    }

    def handler(request):
        """Serve the real GitLab client without any external request or mutation."""
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "name": "main",
                    "default": not (phase["approval"] and change == "default_changed"),
                    "commit": {
                        "id": "b" * 40
                        if phase["approval"] and change == "main_changed"
                        else sha
                    },
                },
            )
        body = json.loads(request.content)
        if "securityTrackedRefs(" in body["query"]:
            connection = {
                "nodes": [
                    {"id": "main-id", "name": "main", "refType": "BRANCH"},
                    {"id": "release-id", "name": "release", "refType": "BRANCH"},
                ],
                "pageInfo": {"hasNextPage": False},
            }
            return httpx.Response(
                200, json={"data": {"project": {"securityTrackedRefs": connection}}}
            )
        if "vulnerabilities(" in body["query"]:
            resolved = body["variables"]["hasResolution"]
            assert body["variables"]["trackedRefIds"] == (
                ["release-id"] if resolved else ["main-id"]
            )
            nodes = [deepcopy(branch_node)] if resolved else []
            if not resolved and change == "main_present":
                nodes = [
                    {
                        **branch_node,
                        "id": "gid://gitlab/Vulnerability/124",
                        "trackedRef": {"id": "main-id", "name": "main"},
                    }
                ]
            return httpx.Response(
                200,
                json={
                    "data": {
                        "project": {
                            "vulnerabilities": {
                                "nodes": nodes,
                                "pageInfo": {"hasNextPage": False},
                            }
                        }
                    }
                },
            )
        if body["query"] == DISMISSAL_TARGET_QUERY:
            target = {**branch_node, "project": {"fullPath": "group/app"}}
            if change == "resolution_changed":
                target["resolvedOnDefaultBranch"] = False
            if change == "ref_changed":
                target["trackedRef"] = {"id": "different", "name": "different"}
            return httpx.Response(200, json={"data": {"vulnerability": target}})
        if body["query"] == DISMISSAL_CONFIRMATION_QUERY:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "vulnerability": {
                            **branch_node,
                            "project": {"fullPath": "group/app"},
                            "state": "DISMISSED",
                            "dismissalReason": "FALSE_POSITIVE",
                        }
                    }
                },
            )
        assert body["query"] == DISMISS_FALSE_POSITIVE
        mutations.append(body)
        return httpx.Response(
            200,
            json={
                "data": {
                    "vulnerabilityDismiss": {
                        "errors": [],
                        "vulnerability": {"id": GID, "state": "DISMISSED"},
                    }
                }
            },
        )

    engine = _engine(tmp_path)
    ctx = _context(reason="resolvedOnDefaultBranch=true")
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        engine.gitlab = GitLabClient("test-token", http=http)
        fetched = engine.gitlab.fetch("group/app")
        assert fetched.ok, fetched.error
        engine.state.findings = fetched.findings
        engine.state.decisions.clear()
        engine.state.pulls = [{"end_head": sha}]
        decision = engine.verify_security_finding(GID)
        candidates = engine.false_positive_candidates()["candidates"]
        if candidates:
            assert candidates[0]["description"] == (
                "GitLab confirms this finding on branch release "
                f"is already resolved on main at {sha}. "
                "It is stale for this main-branch review; this does not prove "
                "the older branch is safe."
            )
        phase["approval"] = True
        result = asyncio.run(server.submit_false_positive_approvals(ctx, str(tmp_path)))

    # Assert
    engine.advisory.lookup.assert_not_called()
    engine.docs.read_before_fix.assert_not_called()
    if change == "main_present":
        assert decision["decision"] == "MANUAL_REVIEW"
        assert mutations == []
        ctx.elicit.assert_not_called()
    else:
        assert decision["decision"] == "FALSE_POSITIVE"
        assert "not proof that the older branch is safe" in decision["reason"]
        assert sha in decision["reason"]
        ctx.elicit.assert_awaited_once()
        assert len(mutations) == int(change is None)
        assert result["status"] == ("OK" if change is None else "PARTIAL_FAILURE")
        if mutations:
            assert mutations[0]["variables"]["comment"] == decision["reason"]
