"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  activeStates,
  MAX_SNAPSHOT_BYTES,
  parseSnapshot,
  SNAPSHOT_TOO_LARGE,
  taskText,
  WORKFLOW_JOB_COUNT,
} = require("./progress-model");

// Mirrors let the GUI follow a run whose checkout is not an open workspace folder.
const MIRROR_MAX_AGE_MS = 12 * 60 * 60 * 1000;
const POLL_INTERVAL_MS = 5000;
const MAX_INITIAL_PROGRESS_FILES = 100;
const METER_WIDTH = 10;
const REPORTS_DIRECTORY = "reports";
const UNRESOLVED_REPORT_NAME = "unresolved-remediation.md";
const WINDOWS_UNC_DEVICE_PREFIX = "\\\\?\\UNC\\";
const WINDOWS_DEVICE_PREFIX = "\\\\?\\";
const EXTENSION_VERSION = require("./package.json").version;
const UNKNOWN_VERSION = "unknown";

function versionText(serverVersion) {
  const server = typeof serverVersion === "string" && serverVersion ? serverVersion : UNKNOWN_VERSION;
  return `MCP server v${server} | Progress extension v${EXTENSION_VERSION}`;
}

function mirrorDirectory() {
  return process.env.GITLAB_SECURITY_PROGRESS_DIR ||
    path.join(os.homedir(), ".cache", "gitlab-security-mcp", "progress");
}

function withoutWindowsDevicePrefix(value) {
  if (process.platform !== "win32") return value;
  if (value.startsWith(WINDOWS_UNC_DEVICE_PREFIX)) {
    return "\\\\" + value.slice(WINDOWS_UNC_DEVICE_PREFIX.length);
  }
  if (value.startsWith(WINDOWS_DEVICE_PREFIX)) {
    return value.slice(WINDOWS_DEVICE_PREFIX.length);
  }
  return value;
}

function canonical(value) {
  if (!value) return "";
  // Progress files name every checkout. realpath on a disconnected mapped
  // drive blocks the extension host, so only an open workspace folder is resolved.
  let normalized = withoutWindowsDevicePrefix(path.normalize(value));
  while (normalized.length > 1 && normalized.endsWith(path.sep) &&
      !normalized.endsWith(":" + path.sep)) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

const resolvedFolders = new Map();

function resolveOpenFolder(value) {
  if (resolvedFolders.has(value)) return resolvedFolders.get(value);
  const normal = canonical(value);
  let resolved = normal;
  if (normal && path.isAbsolute(normal) && !isUnc(normal)) {
    try {
      resolved = canonical(fs.realpathSync(normal));
    } catch {
      resolved = normal;
    }
  }
  resolvedFolders.set(value, resolved);
  return resolved;
}

function isUnc(value) {
  return process.platform === "win32" && value.startsWith("\\\\");
}

function pathKey(value) {
  const normal = canonical(value);
  // Windows and macOS volumes are case-insensitive. Linux paths are not.
  return process.platform === "linux" ? normal : normal.toLowerCase();
}

function inWorkspace(repoRoot, folders) {
  if (!repoRoot) return false;
  const root = pathKey(repoRoot);
  return (folders || []).some(folder => {
    const folderPath = folder.uri?.fsPath || folder.fsPath || "";
    if (!folderPath) return false;
    const folderName = pathKey(resolveOpenFolder(folderPath));
    const prefix = folderName.endsWith(path.sep) ? folderName : folderName + path.sep;
    return root === folderName || root.startsWith(prefix);
  });
}

function snapshotsForWindow(snapshots, folders, now = Date.now()) {
  // An open workspace follows only its own checkouts, including before its run starts.
  const newest = newestPerRepository(snapshots, now);
  if (!folders?.length) return newest;
  return newest.filter(snapshot => inWorkspace(snapshot.repo_root, folders));
}

function newestPerRepository(snapshots, now = Date.now()) {
  const newest = new Map();
  for (const { snapshot, mirror } of snapshots) {
    const updated = Date.parse(snapshot.updated_at);
    if (!Number.isFinite(updated)) continue;
    if (mirror && now - updated > MIRROR_MAX_AGE_MS) continue;
    const key = pathKey(snapshot.repo_root || "");
    const previous = newest.get(key);
    if (!previous || updated > Date.parse(previous.updated_at)) {
      newest.set(key, snapshot);
    }
  }
  return [...newest.values()];
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[character]));
}

function progressHtml(view) {
  const { current, workflow, state, stale } = view || {};
  const percent = current?.total > 0 ? Math.floor(100 * current.completed / current.total) : null;
  const count = percent == null ? "Total not yet known" :
    `${current.completed} of ${current.total} ${current.unit || "files reviewed"} (${percent}%)`;
  const progress = percent != null ? `max="${current.total}" value="${current.completed}"` :
    stale || !current || !activeStates.has(current.status) ? 'max="1" value="0"' : "";
  const jobs = (workflow?.jobs || []).map(job =>
    `<li><strong>${job.number}. ${escapeHtml(job.label)}</strong>: ${escapeHtml(job.status)}${job.message ? `<br>${escapeHtml(job.message)}` : ""}</li>`
  ).join("");
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GitLab Security Progress</title>
<style>
body { font-family: var(--vscode-font-family); color: var(--vscode-editor-foreground); background: var(--vscode-editor-background); padding: 20px; line-height: 1.5; }
main { max-width: 900px; margin: auto; } h1 { font-size: 24px; }
progress { display: block; width: 100%; height: 28px; accent-color: var(--vscode-progressBar-background); }
progress::-webkit-progress-bar { background: var(--vscode-input-background); border-radius: 4px; }
progress::-webkit-progress-value { background: var(--vscode-progressBar-background); border-radius: 4px; }
.activity { padding: 12px; border-left: 4px solid var(--vscode-progressBar-background); background: var(--vscode-textBlockQuote-background); overflow-wrap: anywhere; }
li { margin-bottom: 12px; }
.version { margin-top: -12px; color: var(--vscode-descriptionForeground); }
</style></head><body><main>
<h1>GitLab Security Progress</h1>
<p class="version">${escapeHtml(versionText(current?.serverVersion))}</p>
<h2>${escapeHtml(current?.label || "No task receipts found")}</h2>
<p role="status">${escapeHtml(state || "Start a GitLab Security run in this workspace.")}</p>
<progress aria-label="${escapeHtml(current?.unit || "Task progress")}" ${progress}></progress>
<p>${escapeHtml(count)}</p>
<p class="activity">${escapeHtml(current?.message || "Waiting for a server progress receipt.")}</p>
${current?.id === "software-audit" && current.label.endsWith(": reviewing") ?
  "<p>The report is not complete. The unchecked fix-selection window opens after every file and review phase is finished and the report is saved. No audit fixes are authorized yet.</p>" : ""}
<p>Server heartbeats do not prove the AI is working. If the last AI update stops changing, resume the audit in the existing agent conversation. Do not start a new MCP run and lose its in-memory review receipts.</p>
${jobs ? `<h2>Sequential jobs</h2><ol style="list-style:none;padding:0">${jobs}</ol>` : ""}
<p>File-review percentages measure review coverage, not successful fixes.</p>
</main></body></html>`;
}

function createPresenter(vscode) {
  const output = vscode.window.createOutputChannel("GitLab Security Progress");
  const bar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  bar.command = "gitlabSecurity.showProgress";
  bar.name = "GitLab Security Progress";
  let notification;
  let lastOutput = "";
  let panel;
  let view;
  const openedRuns = new Set();

  function show(preserveFocus = false) {
    if (!panel) {
      panel = vscode.window.createWebviewPanel(
        "gitlabSecurity.progress", "GitLab Security Progress",
        { viewColumn: vscode.ViewColumn.Active, preserveFocus },
        { retainContextWhenHidden: true }
      );
      panel.onDidDispose(() => { panel = undefined; });
    } else {
      panel.reveal(undefined, preserveFocus);
    }
    panel.webview.html = progressHtml(view);
  }

  function endNotification() {
    if (notification) {
      notification.finish?.();
      notification = undefined;
    }
  }

  function update(snapshots) {
    const tasks = snapshots.flatMap(snapshot => snapshot.tasks.map(task => ({
      ...task,
      workspace: snapshot.repo_root || "",
      serverVersion: snapshot.server_version,
      label: `${(snapshot.repo_root || "").split(/[\\/]/).pop() || "Repository"} / ${task.label}`
    })));
    const active = tasks.filter(task => activeStates.has(task.status));
    const latest = [...tasks].sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at))[0];
    if (!latest) {
      view = undefined;
      if (panel) panel.webview.html = progressHtml(view);
      bar.hide();
      endNotification();
      return;
    }
    const workflow = active.find(task => task.id === "workflow");
    const audit = active.find(task => task.id === "software-audit");
    const current = audit || workflow || [...active].sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at))[0] || latest;
    const text = taskText(current);
    const stale = Date.now() - Date.parse(current.updated_at) > 30000;
    const state = stale && active.length ? "No recent updates" :
      current.status === "WAITING_FOR_AI" ? "Waiting for AI" :
      current.status === "WAITING_FOR_HUMAN" ? "Waiting for you" :
      active.length ? "Running" : current.status;
    const counts = current.total > 0 ? ` | ${current.completed}/${current.total}` : "";
    const percent = current.total > 0 ? Math.floor(100 * current.completed / current.total) : null;
    const filled = percent == null ? 0 : Math.floor(percent * METER_WIDTH / 100);
    const meter = percent == null ? "" : ` [${"#".repeat(filled)}${"-".repeat(METER_WIDTH - filled)}] ${percent}%`;
    const runningJob = (workflow?.jobs || []).find(job =>
      job.status === "RUNNING" && Number.isInteger(job.number) && job.number >= 1 && job.number <= WORKFLOW_JOB_COUNT);
    const reportedJob = Number.isInteger(current.completed) ? current.completed + 1 : null;
    const jobNumber = runningJob ? runningJob.number :
      reportedJob != null && reportedJob <= WORKFLOW_JOB_COUNT ? reportedJob : null;
    const label = current.id === "software-audit" ? current.label :
      workflow && jobNumber != null ? `Job ${jobNumber}/${WORKFLOW_JOB_COUNT}` : current.label;
    bar.text = active.length ? `${stale || current.status !== "RUNNING" ? "$(clock)" : "$(sync~spin)"} Security: ${label}${meter}${counts} | ${state}` : `$(list-unordered) Security: ${current.status}`;
    bar.tooltip = [versionText(current.serverVersion), ...tasks.map(task => taskText(task))].join("\n");
    bar.show();
    view = { current, workflow: tasks.find(task => task.id === "workflow"), state, stale };
    if (panel) panel.webview.html = progressHtml(view);
    const run = workflow || current;
    const runKey = `${run.workspace}:${run.id}:${run.started_at || ""}`;
    if (active.length && !stale && !openedRuns.has(runKey)) {
      openedRuns.add(runKey);
      show(true);
    }
    if (lastOutput !== text) {
      output.appendLine(text);
      lastOutput = text;
    }
    if (!active.length) {
      endNotification();
      return;
    }
    const key = `${current.workspace}:${current.id}:${current.started_at || ""}:${current.label}`;
    if (!notification || notification.key !== key) {
      endNotification();
      notification = { key, percent: 0 };
      const owner = notification;
      vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "GitLab Security",
        cancellable: false
      }, reporter => new Promise(resolve => {
        owner.reporter = reporter;
        owner.finish = resolve;
        if (notification !== owner) {
          resolve();
        } else if (owner.lastReport) {
          reporter.report(owner.lastReport);
          owner.percent = owner.pendingPercent;
        }
      })).then(undefined, error => output.appendLine(`Progress notification failed: ${error.message}`));
    }
    const increment = Math.max(0, (percent ?? 0) - notification.percent);
    notification.lastReport = {
      message: text.split("\n")[0],
      ...(current.total > 0 ? { increment } : {})
    };
    notification.pendingPercent = percent ?? 0;
    notification.reporter?.report(notification.lastReport);
    if (notification.reporter) notification.percent = percent ?? 0;
  }

  return {
    update,
    show: () => show(),
    showLog: () => output.show(true),
    dispose: () => { endNotification(); panel?.dispose(); bar.dispose(); output.dispose(); }
  };
}

async function newestUnresolvedReport(vscode, directory) {
  // The server prefixes the report with the GitLab project name.
  let entries;
  try {
    entries = await vscode.workspace.fs.readDirectory(directory);
  } catch (error) {
    if (error.code === "FileNotFound" || error.code === "ENOENT") return undefined;
    throw error;
  }
  let newest;
  for (const [name, type] of entries) {
    if (type !== vscode.FileType.File || !name.endsWith(UNRESOLVED_REPORT_NAME)) continue;
    const uri = vscode.Uri.joinPath(directory, name);
    const stat = await vscode.workspace.fs.stat(uri);
    if (!newest || stat.mtime > newest.mtime) newest = { uri, mtime: stat.mtime };
  }
  return newest?.uri;
}

async function activate(context, vscode = require("vscode")) {
  const presenter = createPresenter(vscode);
  const snapshots = new Map();
  const known = new Map();
  const mirrors = new Set();
  const failures = new Set();
  const displayedReports = new Set();
  const render = () => presenter.update(snapshotsForWindow(
    [...snapshots].map(([key, snapshot]) => ({ snapshot, mirror: mirrors.has(key) })),
    vscode.workspace?.workspaceFolders || []
  ));

  async function refresh(uri) {
    known.set(uri.toString(), uri);
    try {
      const stat = await vscode.workspace.fs.stat(uri);
      const staleMirror = mirrors.has(uri.toString()) &&
        Date.now() - stat.mtime > MIRROR_MAX_AGE_MS;
      if (staleMirror) {
        snapshots.delete(uri.toString());
        known.delete(uri.toString());
        mirrors.delete(uri.toString());
        if (typeof vscode.workspace.fs.delete === "function") {
          try {
            await vscode.workspace.fs.delete(uri);
          } catch {
            // The file is already gone, or this poll cannot remove it.
          }
        }
      } else {
        if (stat.size > MAX_SNAPSHOT_BYTES) throw new Error(SNAPSHOT_TOO_LARGE);
        const bytes = await vscode.workspace.fs.readFile(uri);
        const next = parseSnapshot(Buffer.from(bytes).toString("utf8"));
        const previous = snapshots.get(uri.toString());
        const accepted = !previous || !(Date.parse(previous.updated_at) > Date.parse(next.updated_at));
        if (accepted) {
          snapshots.set(uri.toString(), next);
        }
        failures.delete(uri.toString());
        const completed = accepted && next.tasks.find(task => task.id === "workflow" &&
          task.status === "FINISHED" && task.final_report === true);
        if (completed && vscode.workspace.isTrusted) {
          const key = `${uri.toString()}:${completed.started_at}`;
          const folder = vscode.workspace.getWorkspaceFolder(uri);
          const reports = folder
            ? vscode.Uri.joinPath(uri, "..", REPORTS_DIRECTORY)
            : next.repo_root
              ? vscode.Uri.joinPath(vscode.Uri.file(next.repo_root), ".security-mcp", REPORTS_DIRECTORY)
              : undefined;
          const report = reports && !displayedReports.has(key) &&
            await newestUnresolvedReport(vscode, reports);
          if (report && !displayedReports.has(key)) {
            displayedReports.add(key);
            try {
              await vscode.commands.executeCommand("markdown.showPreview", report);
            } catch (error) {
              vscode.window.showWarningMessage(`Cannot display final GitLab Security report: ${error.message}`);
            }
          }
        }
      }
    } catch (error) {
      snapshots.delete(uri.toString());
      if (error.code === "FileNotFound" || error.code === "ENOENT") {
        known.delete(uri.toString());
        mirrors.delete(uri.toString());
      } else if (!failures.has(uri.toString())) {
        failures.add(uri.toString());
        vscode.window.showWarningMessage(`Cannot read GitLab Security progress: ${uri.fsPath}: ${error.message}`);
      }
    }
    render();
  }

  async function poll() {
    for (const folder of vscode.workspace.workspaceFolders || []) {
      const uri = vscode.Uri.joinPath(folder.uri, ".security-mcp", "progress.json");
      known.set(uri.toString(), uri);
    }
    for (const [key, uri] of known) {
      if (!mirrors.has(key) && !vscode.workspace.getWorkspaceFolder(uri)) {
        known.delete(key);
        snapshots.delete(key);
      }
    }
    try {
      const directory = vscode.Uri.file(mirrorDirectory());
      for (const [name, type] of await vscode.workspace.fs.readDirectory(directory)) {
        if (type !== vscode.FileType.File || !name.endsWith(".json")) continue;
        const uri = vscode.Uri.joinPath(directory, name);
        mirrors.add(uri.toString());
        known.set(uri.toString(), uri);
      }
    } catch {
      // No mirror directory yet means no run has published outside a workspace.
    }
    await Promise.all([...known.values()].map(refresh));
    render();
  }

  const watcher = vscode.workspace.createFileSystemWatcher("**/.security-mcp/progress.json");
  context.subscriptions.push(
    presenter,
    watcher,
    watcher.onDidCreate(refresh),
    watcher.onDidChange(refresh),
    watcher.onDidDelete(refresh),
    vscode.commands.registerCommand("gitlabSecurity.showProgress", presenter.show),
    vscode.commands.registerCommand("gitlabSecurity.showProgressLog", presenter.showLog)
  );
  const timer = setInterval(poll, POLL_INTERVAL_MS);
  context.subscriptions.push({ dispose: () => clearInterval(timer) });
  const existing = await vscode.workspace.findFiles(
    "**/.security-mcp/progress.json",
    "**/{node_modules,.git,.venv,vendor,coverage}/**",
    MAX_INITIAL_PROGRESS_FILES
  );
  await Promise.all(existing.map(refresh));
  // Direct polling also works when Git ignores or watcher exclusions hide the file.
  await poll();
}

module.exports = { activate, createPresenter, newestPerRepository, snapshotsForWindow };
