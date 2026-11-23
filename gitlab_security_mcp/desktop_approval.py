"""Owned Windows checkbox dialogs that do not hold an MCP request open."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

_RAISE_THE_SOFTWARE_AUDIT_CHOICE_WINDOW_EXITED_WITH_CODE = (
    "The software-audit choice window exited with code {}: {}"
)
_RAISE_THE_SOFTWARE_AUDIT_CHOICE_WINDOW_RETURNED_AN_INVALID = (
    "The software-audit choice window returned an invalid response"
)
_RAISE_THE_AUDIT_ITEM_WINDOW_EXITED_WITH_CODE = (
    "The audit-item window exited with code {}: {}"
)
_RAISE_THE_AUDIT_ITEM_WINDOW_RETURNED_AN_INVALID_RESPONSE = (
    "The audit-item window returned an invalid response"
)
_RAISE_APPROVAL_WINDOW_PID_EXITED_WITH_CODE = (
    "Approval window pid={} exited with code {}: {}"
)
_RAISE_APPROVAL_WINDOW_PID_RETURNED_AN_INVALID_RESPONSE = (
    "Approval window pid={} returned an invalid response"
)
_RAISE_APPROVAL_WINDOW_PIPES_WERE_NOT_CREATED = "Approval window pipes were not created"
_RAISE_THE_WINDOWS_APPROVAL_WINDOW_PID_COULD_NOT_BE = (
    "The Windows approval window pid={} could not be shown (exit {}): {}"
)
_RAISE_CHOICE_WINDOW_PIPES_WERE_NOT_CREATED = "Choice window pipes were not created"
_RAISE_CHOICE_WINDOW_PID_COULD_NOT_BE_SHOWN = (
    "Choice window pid={} could not be shown: {}"
)
_RAISE_THE_SOFTWARE_AUDIT_CHOICE_WINDOW_RETURNED_UNREADABLE_OUTPUT = (
    "The software-audit choice window returned unreadable output"
)
_RAISE_THE_AUDIT_ITEM_WINDOW_RETURNED_UNREADABLE_OUTPUT = (
    "The audit-item window returned unreadable output"
)
_RAISE_APPROVAL_WINDOW_PID_RETURNED_UNREADABLE_OUTPUT_BYTES_EXIT = (
    "Approval window pid={} returned unreadable output ({} bytes, exit {})"
)
_RAISE_APPROVAL_WINDOW_PID_RETURNED_AN_INVALID_CHOICE = (
    "Approval window pid={} returned an invalid choice"
)

logger = logging.getLogger("gitlab_security_mcp")
_MAX_DIAGNOSTIC_CHARS = 2000

_WINDOW_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class ApprovalWindowHost {
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetForegroundWindow(IntPtr window);
}
'@
function Get-ApprovalHostWindow {
    param(
        [int]$HostProcessId,
        [object[]]$ProcessTree,
        [IntPtr]$ForegroundWindow,
        [int]$ForegroundProcessId
    )
    $parents = @{}
    foreach ($entry in $ProcessTree) {
        $parents[[int]$entry.ProcessId] = [int]$entry.ParentProcessId
    }
    $ancestors = New-Object 'System.Collections.Generic.List[int]'
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'
    while ($HostProcessId -gt 0 -and $seen.Add($HostProcessId)) {
        $ancestors.Add($HostProcessId)
        if (-not $parents.ContainsKey($HostProcessId)) { break }
        $HostProcessId = $parents[$HostProcessId]
    }
    if ($ForegroundWindow -ne [IntPtr]::Zero -and $ancestors.Contains($ForegroundProcessId)) {
        return $ForegroundWindow
    }
    foreach ($ancestor in $ancestors) {
        try {
            $process = Get-Process -Id $ancestor -ErrorAction Stop
            $handle = $process.MainWindowHandle
            if ($handle -ne [IntPtr]::Zero) { return $handle }
        } catch {
            [Console]::Error.WriteLine("Could not inspect approval host process ${ancestor}: $($_.Exception.Message)")
        } finally {
            if ($null -ne $process) { $process.Dispose(); $process = $null }
        }
    }
    return [IntPtr]::Zero
}
function Get-ApprovalBounds {
    param(
        [System.Drawing.Rectangle]$WorkingArea,
        [System.Drawing.Size]$RequestedSize
    )
    $width = [Math]::Min($RequestedSize.Width, $WorkingArea.Width)
    $height = [Math]::Min($RequestedSize.Height, $WorkingArea.Height)
    $left = $WorkingArea.Left + [int][Math]::Floor(($WorkingArea.Width - $width) / 2)
    $top = $WorkingArea.Top + [int][Math]::Floor(($WorkingArea.Height - $height) / 2)
    return New-Object System.Drawing.Rectangle($left, $top, $width, $height)
}
function Set-ApprovalPlacement {
    param([object]$Window, [int]$HostProcessId)
    $foreground = [ApprovalWindowHost]::GetForegroundWindow()
    [uint32]$foregroundProcessId = 0
    [void][ApprovalWindowHost]::GetWindowThreadProcessId($foreground, [ref]$foregroundProcessId)
    try {
        $processTree = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId -ErrorAction Stop)
        $hostWindow = Get-ApprovalHostWindow -HostProcessId $HostProcessId `
            -ProcessTree $processTree -ForegroundWindow $foreground -ForegroundProcessId $foregroundProcessId
        if ($hostWindow -eq [IntPtr]::Zero) { throw 'No visible window belongs to the MCP host process ancestry.' }
        $screen = [System.Windows.Forms.Screen]::FromHandle($hostWindow)
    } catch {
        [Console]::Error.WriteLine("Could not locate the MCP host monitor; using the active monitor: $($_.Exception.Message)")
        $screen = [System.Windows.Forms.Screen]::FromHandle($foreground)
    }
    $Window.StartPosition = 'Manual'
    $Window.Bounds = Get-ApprovalBounds -WorkingArea $screen.WorkingArea -RequestedSize $Window.Size
    $Window.TopMost = $true
}
function Show-ApprovalForeground {
    param([object]$Window)
    $Window.TopMost = $true
    $Window.BringToFront()
    $Window.Activate()
    if (-not [ApprovalWindowHost]::SetForegroundWindow($Window.Handle) -and
            [ApprovalWindowHost]::GetForegroundWindow() -ne $Window.Handle) {
        [Console]::Error.WriteLine('Windows denied approval-window keyboard activation; the selection remains visible above non-topmost windows.')
    }
}
"""

SCRIPT = (
    _WINDOW_SCRIPT
    + r"""
if (-not [Environment]::UserInteractive) { throw 'No interactive Windows desktop is available.' }
$inputData = [Console]::In.ReadToEnd() | ConvertFrom-Json
$form = New-Object System.Windows.Forms.Form
$form.Text = [string]$inputData.title
$form.Size = New-Object System.Drawing.Size(1200, 760)
Set-ApprovalPlacement -Window $form -HostProcessId $inputData.host_process_id
$message = New-Object System.Windows.Forms.TextBox
$message.Multiline = $true
$message.ReadOnly = $true
$message.ScrollBars = 'Vertical'
$message.Dock = 'Top'
$message.Height = 125
$message.Text = $inputData.message
$viewport = New-Object System.Windows.Forms.Panel
$viewport.Dock = 'Fill'
$viewport.AutoScroll = $true
$table = New-Object System.Windows.Forms.TableLayoutPanel
$table.Dock = 'Top'
$table.AutoSize = $true
$table.AutoSizeMode = 'GrowAndShrink'
$table.ColumnCount = 2
$table.CellBorderStyle = 'Single'
[void]$table.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 35)))
[void]$table.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 65)))
$table.SuspendLayout()
$issueHeader = New-Object System.Windows.Forms.Label
$issueHeader.Text = 'Issue'
$issueHeader.AutoSize = $true
$reasonHeader = New-Object System.Windows.Forms.Label
$reasonHeader.Text = [string]$inputData.detail_header
$reasonHeader.AutoSize = $true
[void]$table.Controls.Add($issueHeader, 0, 0)
[void]$table.Controls.Add($reasonHeader, 1, 0)
$choices = @($inputData.choices)
$checks = @()
for ($i = 0; $i -lt $choices.Count; $i++) {
    $issue = New-Object System.Windows.Forms.TableLayoutPanel
    $issue.Dock = 'Top'
    $issue.AutoSize = $true
    $issue.AutoSizeMode = 'GrowAndShrink'
    $issue.ColumnCount = 2
    [void]$issue.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Absolute', 24)))
    [void]$issue.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    $check = New-Object System.Windows.Forms.CheckBox
    $check.AccessibleName = [string]$choices[$i].title
    $check.Checked = $false
    $check.Enabled = [bool]$choices[$i].enabled
    $check.AutoSize = $true
    $issueText = New-Object System.Windows.Forms.Label
    $issueText.Text = [string]$choices[$i].title
    $issueText.AutoSize = $true
    $issueText.UseMnemonic = $false
    [void]$issue.Controls.Add($check, 0, 0)
    [void]$issue.Controls.Add($issueText, 1, 0)
    $reason = New-Object System.Windows.Forms.Label
    $reason.Text = [string]$choices[$i].summary
    $reason.AutoSize = $true
    $reason.UseMnemonic = $false
    $reason.Anchor = 'Top, Left'
    [void]$table.Controls.Add($issue, 0, $i + 1)
    [void]$table.Controls.Add($reason, 1, $i + 1)
    $checks += $check
}
$script:lastWrapWidth = -1
$table.Add_SizeChanged({
    if ($script:lastWrapWidth -eq $table.ClientSize.Width) { return }
    $script:lastWrapWidth = $table.ClientSize.Width
    $table.SuspendLayout()
    try {
        $widths = $table.GetColumnWidths()
        foreach ($control in $table.Controls) {
            $column = $table.GetColumn($control)
            $width = [Math]::Max(1, $widths[$column] - $control.Margin.Horizontal - 2)
            if ($control.MaximumSize.Width -ne $width) {
                $control.MaximumSize = New-Object System.Drawing.Size($width, 0)
            }
            if ($control -is [System.Windows.Forms.TableLayoutPanel]) {
                $text = $control.GetControlFromPosition(1, 0)
                $textWidth = [Math]::Max(1, $width - 24 - $text.Margin.Horizontal)
                $text.MaximumSize = New-Object System.Drawing.Size($textWidth, 0)
            }
        }
    } finally {
        $table.ResumeLayout($true)
    }
})
[void]$viewport.Controls.Add($table)
$table.ResumeLayout($true)
$buttons = New-Object System.Windows.Forms.FlowLayoutPanel
$buttons.Dock = 'Bottom'
$buttons.Height = 50
$buttons.FlowDirection = 'RightToLeft'
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'Cancel'
$cancel.AutoSize = $true
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$submit = New-Object System.Windows.Forms.Button
$submit.Text = [string]$inputData.submit_label
$submit.AutoSize = $true
$submit.Add_Click({
    $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Close()
})
[void]$buttons.Controls.Add($cancel)
[void]$buttons.Controls.Add($submit)
$form.CancelButton = $cancel
$form.Controls.Add($viewport)
$form.Controls.Add($message)
$form.Controls.Add($buttons)
$form.Add_Shown({
    Show-ApprovalForeground -Window $form
    [Console]::Out.WriteLine('READY')
    [Console]::Out.Flush()
})
$result = $form.ShowDialog()
$response = @{ action = 'cancel' }
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $content = @{}
    for ($i = 0; $i -lt $choices.Count; $i++) {
        $content[[string]$choices[$i].key] = [bool]$checks[$i].Checked
    }
    $response = @{ action = 'accept'; content = $content }
}
$form.Dispose()
[Console]::Out.WriteLine(($response | ConvertTo-Json -Depth 5 -Compress))
"""
)


def available() -> bool:
    """Use a local dialog only on Windows with its standard PowerShell runtime."""
    return os.name == "nt" and powershell().is_file()


def powershell() -> Path:
    """Resolve the OS executable, not a command supplied by repository contents."""
    return Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
        r"System32\WindowsPowerShell\v1.0\powershell.exe"
    )


@dataclass
class DesktopApproval:
    """Own one visible dialog until a human submits or closes it."""

    process: asyncio.subprocess.Process
    choice_ids: frozenset[str] | None = None

    async def wait(self) -> dict:
        """Wait without an approval deadline; validate transport errors explicitly.

        Dialog stderr diagnostics, such as the monitor fallback, are logged
        even when the human response is valid.
        """
        process = self.process
        stdout, stderr = await process.communicate()
        diagnostics = _diagnostic_text(stderr)
        if process.returncode != 0:
            raise RuntimeError(
                _RAISE_APPROVAL_WINDOW_PID_EXITED_WITH_CODE.format(
                    process.pid, process.returncode, diagnostics
                )
            )
        if diagnostics:
            logger.warning(
                "Approval window pid=%s reported diagnostics: %s",
                process.pid,
                diagnostics,
            )
        try:
            response = json.loads(stdout.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                _RAISE_APPROVAL_WINDOW_PID_RETURNED_UNREADABLE_OUTPUT_BYTES_EXIT.format(
                    process.pid, len(stdout), process.returncode
                )
            ) from exc
        if self.choice_ids is not None:
            choice = response.get("choice") if isinstance(response, dict) else None
            if not isinstance(choice, str) or choice not in self.choice_ids:
                raise ValueError(
                    _RAISE_APPROVAL_WINDOW_PID_RETURNED_AN_INVALID_CHOICE.format(
                        process.pid
                    )
                )
            logger.info(
                "Approval window pid=%s closed with choice=%s",
                process.pid,
                response["choice"],
            )
            return response
        if not isinstance(response, dict) or response.get("action") not in {
            "accept",
            "cancel",
        }:
            raise ValueError(
                _RAISE_APPROVAL_WINDOW_PID_RETURNED_AN_INVALID_RESPONSE.format(
                    process.pid
                )
            )
        logger.info(
            "Approval window pid=%s closed with action=%s",
            process.pid,
            response["action"],
        )
        return response

    async def close(self) -> None:
        """Close the dialog pipes and reap only this server-owned process."""
        process = self.process
        try:
            if process.returncode is None:
                logger.info("Closing open approval window pid=%s", process.pid)
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
        finally:
            _close_stream(process.stdin)
            _close_stream(process.stdout)
            _close_stream(process.stderr)
        await process.wait()


def _diagnostic_text(stderr: bytes) -> str:
    """Return the bounded end of dialog stderr, where PowerShell writes the cause."""
    return stderr.decode(errors="replace").strip()[-_MAX_DIAGNOSTIC_CHARS:]


def _close_stream(stream: object) -> None:
    """Close one subprocess pipe transport once. A second close is a no-op."""
    if stream is None:
        return
    transport = getattr(stream, "transport", None)
    if transport is None:
        transport = getattr(stream, "_transport", None)
    if transport is None or transport.is_closing():
        return
    transport.close()


async def open_dialog(
    message: str,
    properties: dict,
    *,
    title: str = "GitLab false-positive approvals",
    detail_header: str = "Why this is a false positive",
    submit_label: str = "Dismiss checked items",
) -> DesktopApproval:
    """Return after the actual checkbox window is shown, not after human selection."""
    process = await asyncio.create_subprocess_exec(
        str(powershell()),
        "-NoProfile",
        "-STA",
        "-Command",
        SCRIPT,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    dialog = DesktopApproval(process)
    logger.info(
        "Starting approval window pid=%s title=%r choices=%s",
        process.pid,
        title,
        len(properties),
    )
    try:
        if process.stdin is None or process.stdout is None:
            raise RuntimeError(_RAISE_APPROVAL_WINDOW_PIPES_WERE_NOT_CREATED)
        payload = {
            "host_process_id": os.getpid(),
            "message": message,
            "title": title,
            "detail_header": detail_header,
            "submit_label": submit_label,
            "choices": [
                {
                    "key": key,
                    "title": value["title"],
                    "summary": value["summary"],
                    "enabled": value.get("enabled", True),
                }
                for key, value in properties.items()
            ],
        }
        process.stdin.write(json.dumps(payload, ensure_ascii=True).encode())
        await process.stdin.drain()
        process.stdin.close()
        await process.stdin.wait_closed()
        if (await process.stdout.readline()).strip() != b"READY":
            _, stderr = await process.communicate()
            raise RuntimeError(
                _RAISE_THE_WINDOWS_APPROVAL_WINDOW_PID_COULD_NOT_BE.format(
                    process.pid, process.returncode, _diagnostic_text(stderr)
                )
            )
        logger.info("Approval window pid=%s is visible", process.pid)
        return dialog
    except BaseException:
        await dialog.close()
        raise


_CHOICE_SCRIPT = (
    _WINDOW_SCRIPT
    + r"""
if (-not [Environment]::UserInteractive) { throw 'No interactive Windows desktop is available.' }
$inputData = [Console]::In.ReadToEnd() | ConvertFrom-Json
$form = New-Object System.Windows.Forms.Form
$form.Text = [string]$inputData.title
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.ClientSize = New-Object System.Drawing.Size(760, 280)
Set-ApprovalPlacement -Window $form -HostProcessId $inputData.host_process_id
$label = New-Object System.Windows.Forms.Label
$label.Text = [string]$inputData.message
$label.AutoSize = $false
$label.SetBounds(16, 16, 728, 72)
$form.Controls.Add($label)
$script:selected = 'done'
$top = 100
foreach ($item in @($inputData.choices)) {
    $button = New-Object System.Windows.Forms.Button
    $button.Text = [string]$item.label
    $button.Tag = [string]$item.id
    $button.SetBounds(16, $top, 728, 36)
    $button.Add_Click({
        $script:selected = [string]$this.Tag
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })
    $form.Controls.Add($button)
    $top += 44
}
$form.CancelButton = $form.Controls[$form.Controls.Count - 1]
$form.Add_Shown({
    Show-ApprovalForeground -Window $form
    if ($inputData.notify_ready) {
        [Console]::Out.WriteLine('READY')
        [Console]::Out.Flush()
    }
})
[void]$form.ShowDialog()
$form.Dispose()
[Console]::Out.WriteLine((@{ choice = $script:selected } | ConvertTo-Json -Compress))
"""
)


async def open_choice(
    title: str, message: str, choices: list[dict[str, str]]
) -> DesktopApproval:
    """Return once a native choice window is visible, without waiting inside the host request."""
    process = await asyncio.create_subprocess_exec(
        str(powershell()),
        "-NoProfile",
        "-STA",
        "-Command",
        _CHOICE_SCRIPT,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    dialog = DesktopApproval(process, frozenset(item["id"] for item in choices))
    try:
        if process.stdin is None or process.stdout is None:
            raise RuntimeError(_RAISE_CHOICE_WINDOW_PIPES_WERE_NOT_CREATED)
        payload = {
            "host_process_id": os.getpid(),
            "title": title,
            "message": message,
            "choices": choices,
            "notify_ready": True,
        }
        process.stdin.write(json.dumps(payload, ensure_ascii=True).encode("utf-8"))
        await process.stdin.drain()
        process.stdin.close()
        await process.stdin.wait_closed()
        if (await process.stdout.readline()).strip() != b"READY":
            _, stderr = await process.communicate()
            raise RuntimeError(
                _RAISE_CHOICE_WINDOW_PID_COULD_NOT_BE_SHOWN.format(
                    process.pid, _diagnostic_text(stderr)
                )
            )
        logger.info("Choice window pid=%s is visible", process.pid)
        return dialog
    except BaseException:
        await dialog.close()
        raise


def ask_choice(title: str, message: str, choices: list[dict[str, str]]) -> str:
    """Show one Windows button per choice and return the selected id.

    Closing the window or choosing the last listed stop action returns ``done``.
    There is no selection deadline.
    """
    completed = subprocess.run(
        [str(powershell()), "-NoProfile", "-STA", "-Command", _CHOICE_SCRIPT],
        input=json.dumps(
            {
                "host_process_id": os.getpid(),
                "title": title,
                "message": message,
                "choices": choices,
            },
            ensure_ascii=True,
        ),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        shell=False,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[-_MAX_DIAGNOSTIC_CHARS:]
        raise RuntimeError(
            _RAISE_THE_SOFTWARE_AUDIT_CHOICE_WINDOW_EXITED_WITH_CODE.format(
                completed.returncode, detail
            )
        )
    if completed.stderr.strip():
        logger.warning(
            "Software-audit choice window reported diagnostics: %s",
            completed.stderr.strip()[-_MAX_DIAGNOSTIC_CHARS:],
        )
    try:
        response = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise ValueError(
            _RAISE_THE_SOFTWARE_AUDIT_CHOICE_WINDOW_RETURNED_UNREADABLE_OUTPUT
        ) from exc
    choice = response.get("choice") if isinstance(response, dict) else None
    if not isinstance(choice, str) or not choice:
        raise ValueError(_RAISE_THE_SOFTWARE_AUDIT_CHOICE_WINDOW_RETURNED_AN_INVALID)
    logger.info("Software-audit choice window closed with choice=%s", choice)
    return choice


def ask_checkboxes(
    message: str,
    properties: dict,
    *,
    title: str,
    detail_header: str,
    submit_label: str,
) -> dict:
    """Show one unchecked box per item and wait until the human submits or cancels.

    The returned action is ``accept`` or ``cancel``. An accept with no checked
    boxes is an empty selection, not a request to fix every item.
    """
    payload = {
        "host_process_id": os.getpid(),
        "message": message,
        "title": title,
        "detail_header": detail_header,
        "submit_label": submit_label,
        "choices": [
            {
                "key": key,
                "title": value["title"],
                "summary": value["summary"],
                "enabled": value.get("enabled", True),
            }
            for key, value in properties.items()
        ],
    }
    completed = subprocess.run(
        [str(powershell()), "-NoProfile", "-STA", "-Command", SCRIPT],
        input=json.dumps(payload, ensure_ascii=True),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        shell=False,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[-_MAX_DIAGNOSTIC_CHARS:]
        raise RuntimeError(
            _RAISE_THE_AUDIT_ITEM_WINDOW_EXITED_WITH_CODE.format(
                completed.returncode, detail
            )
        )
    if completed.stderr.strip():
        logger.warning(
            "Audit-item window reported diagnostics: %s",
            completed.stderr.strip()[-_MAX_DIAGNOSTIC_CHARS:],
        )
    try:
        response = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise ValueError(
            _RAISE_THE_AUDIT_ITEM_WINDOW_RETURNED_UNREADABLE_OUTPUT
        ) from exc
    if not isinstance(response, dict) or response.get("action") not in {
        "accept",
        "cancel",
    }:
        raise ValueError(_RAISE_THE_AUDIT_ITEM_WINDOW_RETURNED_AN_INVALID_RESPONSE)
    logger.info("Audit-item window closed with action=%s", response["action"])
    return response
