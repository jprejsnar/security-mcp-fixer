"""Cover Windows approval transport failures without opening a real dialog."""

import asyncio
import json
import os
import subprocess
from subprocess import CompletedProcess

import pytest

from gitlab_security_mcp.desktop_approval import (
    _CHOICE_SCRIPT,
    SCRIPT,
    DesktopApproval,
    _close_stream,
    ask_checkboxes,
    ask_choice,
    available,
    open_choice,
    open_dialog,
    powershell,
)

PROCESS_PID = 4040
SUCCESS_CODE = 0
FAILURE_CODE = 1
READY = b"READY"
ACCEPT = "accept"
CANCEL = "cancel"
CHOICE_ID = "fix_from_report"
DONE = "done"
TITLE = "Audit"
MESSAGE = "Choose one"
DETAIL = "Why"
SUBMIT = "Apply checked items"
CHOICE_KEY = "finding-1"
CHOICE_TITLE = "Finding"
CHOICE_SUMMARY = "The cited line does not do what the scanner describes."
INVALID_ACTION = "later"
DIAGNOSTIC = "dialog failed"


class _Transport:
    """Stand in for one subprocess pipe transport."""

    def __init__(self):
        """Start the transport open."""
        self.closing = False

    def is_closing(self):
        """Report whether close was already requested."""
        return self.closing

    def close(self):
        """Record the close. A second close stays a no-op."""
        self.closing = True


class _Pipe:
    """Queue the lines a dialog writes and keep the bytes the host sends."""

    def __init__(self, lines):
        """Store the scripted stdout lines."""
        self.lines = list(lines)
        self.transport = _Transport()
        self.written = bytearray()

    def write(self, data):
        """Record stdin without sending it to PowerShell."""
        self.written.extend(data)

    async def drain(self):
        """Finish the scripted write."""

    def close(self):
        """Finish stdin."""

    async def wait_closed(self):
        """Report that stdin is closed."""

    async def readline(self):
        """Return the next scripted line."""
        if not self.lines:
            return b""
        return self.lines.pop(0)


class _Process:
    """Stand in for the PowerShell process the dialog helpers own."""

    def __init__(self, ready=READY + b"\n", stderr=b"", fail_terminate=False):
        """Script readiness, stderr, and whether terminate can find the process."""
        self.pid = PROCESS_PID
        self.returncode = None
        self.stdin = _Pipe([])
        self.stdout = _Pipe([ready])
        self.stderr = _Pipe([])
        self.stderr_bytes = stderr
        self.fail_terminate = fail_terminate
        self.terminated = False

    async def communicate(self):
        """Finish the process with the scripted stderr."""
        self.returncode = FAILURE_CODE
        return b"", self.stderr_bytes

    def terminate(self):
        """Record termination, or report that the process is already gone."""
        if self.fail_terminate:
            raise ProcessLookupError(PROCESS_PID)
        self.terminated = True

    async def wait(self):
        """Reap the scripted process."""
        if self.returncode is None:
            self.returncode = SUCCESS_CODE


def _patch_launch(monkeypatch, process):
    """Replace process creation with one scripted process."""

    async def launch(*_args, **_kwargs):
        """Return the scripted process instead of PowerShell."""
        return process

    monkeypatch.setattr(
        "gitlab_security_mcp.desktop_approval.asyncio.create_subprocess_exec",
        launch,
    )


def _completed(returncode, stdout, stderr=""):
    """Build one finished PowerShell result."""
    return CompletedProcess([], returncode, stdout, stderr)


def test_available_checks_the_windows_powershell_runtime():
    """The dialog helper is available only where its PowerShell runtime exists."""
    # Arrange
    expected = os.name == "nt" and powershell().is_file()

    # Act
    present = available()

    # Assert
    assert present is expected


@pytest.mark.parametrize("action", [ACCEPT, CANCEL])
def test_wait_accepts_only_a_dialog_action(action):
    """A finished dialog must return accept or cancel."""
    # Arrange
    process = _Process()
    process.returncode = SUCCESS_CODE

    async def communicate():
        """Return one valid action and a diagnostic the host still logs."""
        return json.dumps({"action": action}).encode(), DIAGNOSTIC.encode()

    process.communicate = communicate
    dialog = DesktopApproval(process)

    # Act
    response = asyncio.run(dialog.wait())

    # Assert
    assert response["action"] == action


def test_wait_rejects_a_failed_process_and_an_invalid_payload():
    """A non-zero exit or an unexpected action is not a human decision."""
    # Arrange
    failed = _Process(stderr=DIAGNOSTIC.encode())
    invalid = _Process()
    invalid.returncode = SUCCESS_CODE

    async def communicate():
        """Return JSON that is not an accept or cancel action."""
        return json.dumps({"action": INVALID_ACTION}).encode(), b""

    invalid.communicate = communicate

    # Act
    with pytest.raises(RuntimeError):
        asyncio.run(DesktopApproval(failed).wait())
    with pytest.raises(ValueError):
        asyncio.run(DesktopApproval(invalid).wait())

    # Assert
    assert failed.returncode == FAILURE_CODE


def test_close_reaps_a_missing_process_and_ignores_a_closed_pipe():
    """Closing a dialog is safe when the process or a pipe is already gone."""
    # Arrange
    process = _Process(fail_terminate=True)
    dialog = DesktopApproval(process)

    # Act
    asyncio.run(dialog.close())
    _close_stream(None)
    _close_stream(process.stdout)
    _close_stream(process.stdout)

    # Assert
    assert process.returncode == SUCCESS_CODE
    assert process.stdout.transport.closing is True


def test_open_dialog_returns_after_ready_and_closes_when_pipes_fail(monkeypatch):
    """The host returns once the window is visible and closes it on failure."""
    # Arrange
    shown = _Process()
    hidden = _Process(ready=b"FAILED\n", stderr=DIAGNOSTIC.encode())
    pipeless = _Process()
    properties = {CHOICE_KEY: {"title": CHOICE_TITLE, "summary": CHOICE_SUMMARY}}
    _patch_launch(monkeypatch, shown)

    # Act
    dialog = asyncio.run(open_dialog(MESSAGE, properties, title=TITLE))
    sent = shown.stdin.written
    _patch_launch(monkeypatch, hidden)
    with pytest.raises(RuntimeError):
        asyncio.run(open_dialog(MESSAGE, properties, title=TITLE))
    pipeless.stdin = None
    _patch_launch(monkeypatch, pipeless)
    with pytest.raises(RuntimeError):
        asyncio.run(open_dialog(MESSAGE, properties, title=TITLE))

    # Assert
    assert dialog.process is shown
    assert CHOICE_KEY.encode() in sent
    assert json.loads(sent)["host_process_id"] == os.getpid()


def test_open_choice_returns_after_ready(monkeypatch):
    """A choice window is returned only after it writes READY."""
    # Arrange
    shown = _Process()
    hidden = _Process(ready=b"FAILED\n", stderr=DIAGNOSTIC.encode())
    pipeless = _Process()
    pipeless.stdin = None
    choices = [{"id": CHOICE_ID, "label": TITLE}, {"id": DONE, "label": CANCEL}]
    _patch_launch(monkeypatch, shown)

    # Act
    dialog = asyncio.run(open_choice(TITLE, MESSAGE, choices))
    _patch_launch(monkeypatch, hidden)
    with pytest.raises(RuntimeError):
        asyncio.run(open_choice(TITLE, MESSAGE, choices))
    _patch_launch(monkeypatch, pipeless)
    with pytest.raises(RuntimeError):
        asyncio.run(open_choice(TITLE, MESSAGE, choices))

    # Assert
    assert CHOICE_ID in dialog.choice_ids
    assert json.loads(shown.stdin.written)["host_process_id"] == os.getpid()


@pytest.mark.skipif(os.name != "nt", reason="Requires Windows PowerShell")
@pytest.mark.parametrize("window_script", [SCRIPT, _CHOICE_SCRIPT])
@pytest.mark.parametrize("allowed", [False, True])
def test_all_window_handlers_request_foreground_before_ready(window_script, allowed):
    """Execute real Shown handlers with fake windows, including Windows focus denial."""
    # Arrange
    script = r"""
$ErrorActionPreference = 'Stop'
$data = [Console]::In.ReadToEnd() | ConvertFrom-Json
Add-Type @'
using System;
public static class ApprovalWindowHost {
    public static bool Allowed;
    public static IntPtr LastWindow;
    public static bool SetForegroundWindow(IntPtr window) {
        LastWindow = window;
        return Allowed;
    }
    public static IntPtr GetForegroundWindow() {
        return Allowed ? LastWindow : IntPtr.Zero;
    }
}
'@
[ApprovalWindowHost]::Allowed = $data.allowed
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($data.script, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw ($errors | Out-String) }
$focus = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Show-ApprovalForeground'
}, $true)
. ([scriptblock]::Create($focus.Extent.Text))
$shown = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
        $node.Member.Value -eq 'Add_Shown'
}, $true)
$script:events = New-Object 'System.Collections.Generic.List[string]'
$form = [pscustomobject]@{ TopMost = $false; Handle = [IntPtr]4040 }
$form | Add-Member ScriptMethod BringToFront {
    if (-not $this.TopMost) { throw 'Window must already be topmost' }
    $script:events.Add('front')
}
$form | Add-Member ScriptMethod Activate { $script:events.Add('activate') }
$inputData = [pscustomobject]@{ notify_ready = $true }
$body = $shown.Arguments[0].ScriptBlock.Extent.Text
. ([scriptblock]::Create($body.Substring(1, $body.Length - 2)))
if ([ApprovalWindowHost]::LastWindow -ne $form.Handle) { throw 'Wrong foreground handle' }
@{ events = @($script:events); topmost = $form.TopMost } | ConvertTo-Json -Compress
"""

    # Act
    result = subprocess.run(
        [str(powershell()), "-NoProfile", "-Command", script],
        input=json.dumps({"script": window_script, "allowed": allowed}),
        text=True,
        capture_output=True,
        encoding="utf-8",
        timeout=20,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    # Assert
    assert result.returncode == 0, result.stderr
    ready, payload = result.stdout.strip().splitlines()
    assert ready == READY.decode()
    assert json.loads(payload) == {
        "events": ["front", "activate"],
        "topmost": True,
    }
    assert ("Windows denied" in result.stderr) is not allowed


@pytest.mark.parametrize("checkboxes", [False, True])
def test_successful_sync_windows_log_foreground_diagnostics(
    monkeypatch, caplog, checkboxes
):
    """A valid human answer must not discard a failed foreground/placement warning."""
    # Arrange
    payloads = []
    response = {"action": ACCEPT, "content": {}} if checkboxes else {"choice": DONE}

    def run(*_args, **kwargs):
        """Return a successful answer accompanied by a native-window diagnostic."""
        payloads.append(json.loads(kwargs["input"]))
        return _completed(SUCCESS_CODE, json.dumps(response), DIAGNOSTIC)

    monkeypatch.setattr("gitlab_security_mcp.desktop_approval.subprocess.run", run)

    # Act
    if checkboxes:
        ask_checkboxes(
            MESSAGE, {}, title=TITLE, detail_header=DETAIL, submit_label=SUBMIT
        )
    else:
        ask_choice(TITLE, MESSAGE, [{"id": DONE, "label": DONE}])

    # Assert
    assert payloads[0]["host_process_id"] == os.getpid()
    assert DIAGNOSTIC in caplog.text


def test_choice_and_checkbox_helpers_require_a_readable_response(monkeypatch):
    """Synchronous dialogs reject a failed process and unreadable or empty output."""
    # Arrange
    choices = [{"id": CHOICE_ID, "label": TITLE}]
    properties = {CHOICE_KEY: {"title": CHOICE_TITLE, "summary": CHOICE_SUMMARY}}
    results = [
        _completed(FAILURE_CODE, "", DIAGNOSTIC),
        _completed(SUCCESS_CODE, ""),
        _completed(SUCCESS_CODE, json.dumps({"choice": ""})),
        _completed(SUCCESS_CODE, json.dumps({"choice": CHOICE_ID})),
    ]

    def run(*_args, **_kwargs):
        """Return the next scripted PowerShell result."""
        return results.pop(0)

    monkeypatch.setattr("gitlab_security_mcp.desktop_approval.subprocess.run", run)

    # Act
    with pytest.raises(RuntimeError):
        ask_choice(TITLE, MESSAGE, choices)
    with pytest.raises(ValueError):
        ask_choice(TITLE, MESSAGE, choices)
    with pytest.raises(ValueError):
        ask_choice(TITLE, MESSAGE, choices)
    selected = ask_choice(TITLE, MESSAGE, choices)
    checkbox_results = [
        _completed(FAILURE_CODE, "", DIAGNOSTIC),
        _completed(SUCCESS_CODE, "not-json"),
        _completed(SUCCESS_CODE, json.dumps({"action": INVALID_ACTION})),
        _completed(SUCCESS_CODE, json.dumps({"action": ACCEPT, "content": {}})),
    ]

    def run_boxes(*_args, **_kwargs):
        """Return the next scripted checkbox result."""
        return checkbox_results.pop(0)

    monkeypatch.setattr(
        "gitlab_security_mcp.desktop_approval.subprocess.run", run_boxes
    )
    with pytest.raises(RuntimeError):
        ask_checkboxes(
            MESSAGE,
            properties,
            title=TITLE,
            detail_header=DETAIL,
            submit_label=SUBMIT,
        )
    with pytest.raises(ValueError):
        ask_checkboxes(
            MESSAGE,
            properties,
            title=TITLE,
            detail_header=DETAIL,
            submit_label=SUBMIT,
        )
    with pytest.raises(ValueError):
        ask_checkboxes(
            MESSAGE,
            properties,
            title=TITLE,
            detail_header=DETAIL,
            submit_label=SUBMIT,
        )
    accepted = ask_checkboxes(
        MESSAGE,
        properties,
        title=TITLE,
        detail_header=DETAIL,
        submit_label=SUBMIT,
    )

    # Assert
    assert selected == CHOICE_ID
    assert accepted["action"] == ACCEPT
