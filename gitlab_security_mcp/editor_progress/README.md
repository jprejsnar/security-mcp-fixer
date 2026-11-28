# GitLab Security Progress

Reloading the MCP server on Windows, macOS, or Linux installs this extension
into the VS Code or Cursor process that launched it. A manual
**Extensions: Install from VSIX** is needed only when the server is not
launched by the editor. Use MCP server 1.0.47 or newer.

The server writes `.security-mcp/progress.json` in the audited checkout and a
mirror under `~/.cache/gitlab-security-mcp/progress/` (override with
`GITLAB_SECURITY_PROGRESS_DIR`). A window with open folders shows a run only
when that checkout is one of those folders, or a directory inside one of them.
A window with no open folder shows the newest mirror for each checkout.
Mirrors older than 12 hours are deleted and are not polled again.

Version 1.0.48 displays a persistent **GitLab Security Progress** editor tab
with a graphical progress bar, exact counts/percentage, current activity and
seven-job checklist. It opens automatically for an active run without stealing
keyboard focus, even when notifications are muted or collapsed. Click the
status indicator or run **GitLab Security: Show Task Progress** to reveal it.
Closing the tab is respected; the command reopens it.

The status bar also contains a compact meter and percentage. The separate
**GitLab Security: Show Progress Log** command opens the diagnostic output
channel; that text is a log, not the graphical progress bar.

The persistent bar shows the current **Job N/7** when the finished-job count
is known. Without that count it shows the task label, not job 1. It also shows
finished-job counts and the current finding or activity. The tooltip and output
list all seven sequential jobs.
During report generation, **Software audit** takes priority with real
reviewed-file counts and a progress notification. The server keeps this owner
alive between host tool calls. **Waiting for AI**, **Waiting for you**, and
**No recent updates** distinguish approval, host work and stale receipts.
Waiting states use a clock, not a spinner claiming that the host AI is busy.
The heartbeat measures server liveness, not whether the AI is actively reading;
the message also shows time since the last actual AI progress update.
Job counts measure finished jobs, not elapsed time or successful fixes. At the
end the extension opens the newest `.security-mcp/reports/<project>-unresolved-remediation.md` once
in a trusted workspace. It never auto-opens reports in an untrusted workspace.

It watches local `.security-mcp/progress.json` inspection files. It does not send
code or logs anywhere, execute remediation commands, authorize edits, dismiss findings, or resume
a run. Unknown totals stay indeterminate. Reviewed-file percentages do not mean
all findings are fixed. Human/AI waiting states and stale updates are explicit.
Server-side background work updates its heartbeat even when a command is silent.
Host AI activity between progress calls cannot be measured by the server.
The audit-fix checklist cannot appear while the review is incomplete or its
report is absent. Resume a paused audit in the existing AI conversation; do
not restart the MCP and lose its in-memory review receipts. The host must
finish the inventory, save the report, and submit `report_ready=True` to open
unchecked finding choices. Progress and delegated-review summaries are not
completion handoffs.

For development, run `npm test`. Package with
`npx --yes --package @vscode/vsce@4.1.1 vsce package --no-dependencies --skip-license`.
That package requires Node.js 22 or newer.
