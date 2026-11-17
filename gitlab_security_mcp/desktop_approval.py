"""Owned Windows checkbox dialogs that do not hold an MCP request open."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

SCRIPT = r"""
$ErrorActionPreference = 'Stop'
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
if (-not [Environment]::UserInteractive) { throw 'No interactive Windows desktop is available.' }
$inputData = [Console]::In.ReadToEnd() | ConvertFrom-Json
$form = New-Object System.Windows.Forms.Form
$form.Text = [string]$inputData.title
$form.Size = New-Object System.Drawing.Size(1200, 760)
$foreground = [ApprovalWindowHost]::GetForegroundWindow()
[uint32]$foregroundProcessId = 0
[void][ApprovalWindowHost]::GetWindowThreadProcessId($foreground, [ref]$foregroundProcessId)
try {
    $processTree = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId -ErrorAction Stop)
    $hostWindow = Get-ApprovalHostWindow -HostProcessId $inputData.host_process_id `
        -ProcessTree $processTree -ForegroundWindow $foreground -ForegroundProcessId $foregroundProcessId
    if ($hostWindow -eq [IntPtr]::Zero) { throw 'No visible window belongs to the MCP host process ancestry.' }
    $screen = [System.Windows.Forms.Screen]::FromHandle($hostWindow)
} catch {
    [Console]::Error.WriteLine("Could not locate the MCP host monitor; using the active monitor: $($_.Exception.Message)")
    $screen = [System.Windows.Forms.Screen]::FromHandle($foreground)
}
$form.StartPosition = 'Manual'
$form.Bounds = Get-ApprovalBounds -WorkingArea $screen.WorkingArea -RequestedSize $form.Size
$form.TopMost = $true
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
$form.Add_Shown({ $form.Activate(); [Console]::Out.WriteLine('READY'); [Console]::Out.Flush() })
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

    async def wait(self) -> dict:
        """Wait without an approval deadline; validate transport errors explicitly."""
        stdout, stderr = await self.process.communicate()
        if self.process.returncode != 0:
            raise RuntimeError(
                f"Approval window exited with code {self.process.returncode}: "
                f"{stderr.decode(errors='replace')[-2000:]}"
            )
        response = json.loads(stdout.decode("utf-8-sig"))
        if not isinstance(response, dict) or response.get("action") not in {
            "accept",
            "cancel",
        }:
            raise ValueError("The approval window returned an invalid response")
        return response

    async def close(self) -> None:
        """Close the dialog pipes and reap only this server-owned process."""
        process = self.process
        if process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        _close_stream(process.stdin)
        _close_stream(process.stdout)
        _close_stream(process.stderr)
        await process.wait()


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
    try:
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("Approval window pipes were not created")
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
                "The Windows approval window could not be shown: "
                + stderr.decode(errors="replace")[-2000:]
            )
        return dialog
    except BaseException:
        await dialog.close()
        raise
