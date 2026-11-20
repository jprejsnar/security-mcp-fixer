"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseSnapshot, taskText } = require("../progress-model");
const { activate, createPresenter, newestPerRepository } = require("../extension");

function snapshot(overrides = {}) {
  return {
    repo_root: "C:\\repo",
    tasks: [{
      id: "audit", label: "Software audit", status: "WAITING_FOR_AI",
      message: "Reading controllers", completed: 2, total: 4,
      updated_at: new Date().toISOString(), ...overrides
    }]
  };
}

function harness(delayed = false) {
  const reports = [], pending = [], bars = [], lines = [], panels = [];
  let closed = 0;
  let logsShown = 0;
  const vscode = {
    StatusBarAlignment: { Left: 1 }, ProgressLocation: { Notification: 15 }, ViewColumn: { Active: -1 },
    window: {
      createOutputChannel: () => ({ appendLine: line => lines.push(line), show() { logsShown++; }, dispose() {} }),
      createWebviewPanel: (_id, _title, options) => {
        let disposed;
        const panel = {
          options, webview: { html: "" }, reveals: 0,
          reveal() { this.reveals++; },
          onDidDispose(callback) { disposed = callback; },
          dispose() { disposed?.(); }
        };
        panels.push(panel);
        return panel;
      },
      createStatusBarItem: () => {
        const bar = { show() {}, hide() {}, dispose() {} }; bars.push(bar); return bar;
      },
      withProgress: (_options, run) => {
        const execute = () => run({ report: value => reports.push(value) }).then(() => { closed++; });
        if (delayed) {
          return new Promise(resolve => pending.push(() => execute().then(resolve)));
        }
        return execute();
      }
    }
  };
  return { presenter: createPresenter(vscode), vscode, reports, pending, bars, lines, panels, closed: () => closed, logsShown: () => logsShown };
}

test("in-editor status and progress follow real audit counts, then close", async () => {
  const ui = harness();
  ui.presenter.update([parseSnapshot(JSON.stringify(snapshot()))]);
  assert.match(ui.bars[0].text, /50%.*Waiting for AI/);
  assert.equal(ui.reports[0].increment, 50);
  ui.presenter.update([snapshot({ completed: 3 })]);
  assert.equal(ui.reports[1].increment, 25);
  ui.presenter.update([snapshot({ status: "DONE", completed: 4 })]);
  await Promise.resolve();
  assert.equal(ui.closed(), 1);
  assert.match(ui.bars[0].text, /DONE/);
  ui.presenter.dispose();
});

test("silent commands are indeterminate and stale updates are explicit", () => {
  const ui = harness();
  ui.presenter.update([snapshot({ completed: null, total: null })]);
  assert.equal(ui.reports[0].increment, undefined);
  assert.match(taskText(snapshot().tasks[0], Date.now() + 60000), /awaiting update/);
  ui.presenter.dispose();
});

test("notification startup can be asynchronous without losing actual progress", async () => {
  const ui = harness(true);
  ui.presenter.update([snapshot()]);
  ui.presenter.update([snapshot({ completed: 3 })]);
  ui.pending[0]();
  assert.equal(ui.reports[0].increment, 75);
  ui.presenter.dispose();
  await Promise.resolve();
});

test("malformed file counts are rejected, not rendered as success", () => {
  assert.throws(() => parseSnapshot(JSON.stringify(snapshot({ completed: 8 }))), /counts/);
  assert.throws(() => parseSnapshot('{"tasks":[null]}'), /Invalid/);
});

test("ignored progress files are discovered even without search or watcher events", async () => {
  const ui = harness();
  let reads = 0;
  const uri = { toString: () => "file:///repo/.security-mcp/progress.json" };
  const disposable = { dispose() {} };
  ui.vscode.Uri = { joinPath: () => uri };
  ui.vscode.commands = { registerCommand: () => disposable };
  ui.vscode.workspace = {
    workspaceFolders: [{ uri: {} }],
    getWorkspaceFolder: () => ({}),
    findFiles: async () => [],
    createFileSystemWatcher: () => ({
      ...disposable, onDidCreate: () => disposable,
      onDidChange: () => disposable, onDidDelete: () => disposable
    }),
    fs: {
      stat: async () => ({ size: 1000 }),
      readFile: async () => { reads++; return Buffer.from(JSON.stringify(snapshot())); }
    }
  };
  const context = { subscriptions: [] };
  await activate(context, ui.vscode);
  assert.equal(reads, 1);
  assert.match(ui.bars.at(-1).text, /50%.*Waiting for AI/);
  for (const subscription of context.subscriptions) subscription.dispose();
});

test("the seven-job bar stays visible while command and worker receipts change", () => {
  const ui = harness();
  const workflow = {
    id: "workflow", label: "Job 3/7: Select and apply package updates",
    status: "RUNNING", message: "Updating backend library: 1.0 -> 2.0",
    completed: 2, total: 7, unit: "jobs finished",
    updated_at: new Date().toISOString(),
    jobs: [
      { number: 1, label: "Pre-checks", status: "FINISHED" },
      { number: 2, label: "Download findings", status: "FINISHED" },
      { number: 3, label: "Package updates", status: "RUNNING" },
      { number: 4, label: "False positives", status: "PENDING" }
    ]
  };
  ui.presenter.update([{ repo_root: "C:\\repo", tasks: [workflow, snapshot().tasks[0]] }]);
  assert.match(ui.bars[0].text, /Job 3\/7/);
  assert.equal(ui.reports[0].increment, 28);
  assert.match(ui.reports[0].message, /2\/7 jobs finished/);
  assert.match(ui.reports[0].message, /backend library/);
  assert.match(ui.bars[0].tooltip, /False positives: PENDING/);
  ui.presenter.dispose();
});

test("audit activity is visible in the status bar rather than hidden by workflow or tools", () => {
  const ui = harness();
  const data = snapshot({
    id: "software-audit", label: "Software audit: reviewing",
    message: "Reading controller callers. Last AI update 2s ago; MCP server responsive."
  });
  data.tasks.push({
    ...snapshot().tasks[0], id: "workflow", label: "Job 6/7",
    completed: 5, total: 7, unit: "jobs finished"
  });
  ui.presenter.update([data]);
  assert.match(ui.bars[0].text, /Software audit: reviewing.*50%.*2\/4.*Waiting for AI/);
  assert.equal(ui.reports[0].increment, 50);
  assert.match(ui.reports[0].message, /Reading controller callers/);
  ui.presenter.dispose();
});

test("the progress command reveals a real persistent meter, not the output log", () => {
  const ui = harness();
  ui.presenter.update([snapshot({
    id: "software-audit", label: "Software audit: reviewing",
    completed: 111, total: 495, unit: "files reviewed",
    message: "Reading <controller> & caller"
  })]);
  assert.equal(ui.panels.length, 1);
  assert.equal(ui.panels[0].options.preserveFocus, true);
  assert.match(ui.panels[0].webview.html, /<progress[^>]*max="495" value="111"/);
  assert.match(ui.panels[0].webview.html, /111 of 495 files reviewed \(22%\)/);
  assert.match(ui.panels[0].webview.html, /fix-selection window opens after/);
  assert.match(ui.panels[0].webview.html, /Reading &lt;controller&gt; &amp; caller/);
  assert.doesNotMatch(ui.panels[0].webview.html, /<controller>/);
  ui.presenter.show();
  assert.equal(ui.panels[0].reveals, 1);
  assert.equal(ui.logsShown(), 0);
  ui.presenter.showLog();
  assert.equal(ui.logsShown(), 1);
  ui.panels[0].dispose();
  ui.presenter.update([snapshot({ id: "software-audit", label: "Software audit: reviewing" })]);
  assert.equal(ui.panels.length, 1, "do not reopen a panel the human closed");
  ui.presenter.show();
  assert.equal(ui.panels.length, 2);
  ui.presenter.dispose();
});

test("an abandoned snapshot is not presented as actively running", () => {
  const ui = harness();
  ui.presenter.update([snapshot({
    status: "RUNNING", updated_at: new Date(Date.now() - 60000).toISOString()
  })]);
  assert.match(ui.bars[0].text, /clock/);
  assert.match(ui.bars[0].text, /No recent updates/);
  assert.doesNotMatch(ui.bars[0].text, /sync~spin/);
  ui.presenter.dispose();
});

test("audit fix approval resets the completed review notification", async () => {
  const ui = harness();
  ui.presenter.update([snapshot({
    id: "software-audit", label: "Software audit: reviewing", completed: 4
  })]);
  ui.presenter.update([snapshot({
    id: "software-audit", label: "Software audit: approval",
    completed: null, total: null, status: "WAITING_FOR_HUMAN"
  })]);
  await Promise.resolve();
  assert.equal(ui.closed(), 1);
  assert.equal(ui.reports.at(-1).increment, undefined);
  assert.match(ui.bars[0].text, /Waiting for you/);
  ui.presenter.dispose();
});

for (const trusted of [true, false]) {
  test(`final Markdown preview opens once only in a trusted workspace (trusted=${trusted})`, async () => {
    const ui = harness();
    const opened = [];
    let changed;
    const progressUri = { fsPath: "C:\\repo\\.security-mcp\\progress.json", toString: () => "file:///repo/.security-mcp/progress.json" };
    const reportUri = { fsPath: "C:\\repo\\.security-mcp\\reports\\unresolved-remediation.md" };
    const disposable = { dispose() {} };
    ui.vscode.Uri = { joinPath: (base, ...parts) => parts.includes("unresolved-remediation.md") ? reportUri : progressUri };
    ui.vscode.commands = {
      registerCommand: () => disposable,
      executeCommand: async (...args) => opened.push(args)
    };
    ui.vscode.workspace = {
      isTrusted: trusted, workspaceFolders: [{ uri: {} }],
      getWorkspaceFolder: () => ({ uri: {} }),
      findFiles: async () => [],
      createFileSystemWatcher: () => ({
        ...disposable, onDidCreate: () => disposable,
        onDidChange: callback => { changed = callback; return disposable; },
        onDidDelete: () => disposable
      }),
      fs: {
        stat: async () => ({ size: 1000 }),
        readFile: async () => Buffer.from(JSON.stringify(snapshot({
          id: "workflow", status: "FINISHED", started_at: "2026-11-19T12:00:00Z",
          completed: 7, total: 7, final_report: true
        })))
      }
    };
    const context = { subscriptions: [] };
    await activate(context, ui.vscode);
    await changed(progressUri);
    assert.equal(opened.length, trusted ? 1 : 0);
    if (trusted) assert.deepEqual(opened[0], ["markdown.showPreview", reportUri]);
    for (const subscription of context.subscriptions) subscription.dispose();
  });
}

test("a run in a checkout that is not open still shows the graphical bar", async () => {
  // Arrange
  const ui = harness();
  const disposable = { dispose() {} };
  const uri = name => ({ name, toString: () => `file:///mirror/${name}` });
  ui.vscode.FileType = { File: 1 };
  ui.vscode.Uri = { file: () => uri(""), joinPath: (_base, name) => uri(name) };
  ui.vscode.commands = { registerCommand: () => disposable };
  ui.vscode.workspace = {
    workspaceFolders: [],
    getWorkspaceFolder: () => undefined,
    findFiles: async () => [],
    createFileSystemWatcher: () => ({
      ...disposable, onDidCreate: () => disposable,
      onDidChange: () => disposable, onDidDelete: () => disposable
    }),
    fs: {
      readDirectory: async () => [["run.json", 1], ["notes.txt", 1]],
      stat: async () => ({ size: 1000 }),
      readFile: async () => Buffer.from(JSON.stringify(snapshot()))
    }
  };
  const context = { subscriptions: [] };

  // Act
  await activate(context, ui.vscode);

  // Assert
  assert.match(ui.bars.at(-1).text, /50%.*Waiting for AI/);
  assert.equal(ui.panels.length, 1);
  for (const subscription of context.subscriptions) subscription.dispose();
});

test("workspace and mirror copies of one run are shown once, and old mirrors are ignored", () => {
  // Arrange
  const now = Date.parse("2026-11-20T12:00:00Z");
  const older = { repo_root: "C:\\Repo", updated_at: "2026-11-20T11:00:00Z", tasks: [] };
  const newer = { repo_root: "c:\\repo", updated_at: "2026-11-20T11:59:00Z", tasks: [] };
  const abandoned = { repo_root: "C:\\Other", updated_at: "2026-11-18T00:00:00Z", tasks: [] };

  // Act
  const shown = newestPerRepository([
    { snapshot: older, mirror: false },
    { snapshot: newer, mirror: true },
    { snapshot: abandoned, mirror: true }
  ], now);

  // Assert
  assert.deepEqual(shown, [newer]);
});

test("stale mirror files are not reread on every poll", async () => {
  // Arrange
  const ui = harness();
  let reads = 0;
  const disposable = { dispose() {} };
  const uri = name => ({ name, toString: () => `file:///mirror/${name}` });
  ui.vscode.FileType = { File: 1 };
  ui.vscode.Uri = { file: () => uri(""), joinPath: (_base, name) => uri(name) };
  ui.vscode.commands = { registerCommand: () => disposable };
  ui.vscode.workspace = {
    workspaceFolders: [],
    getWorkspaceFolder: () => undefined,
    findFiles: async () => [],
    createFileSystemWatcher: () => ({
      ...disposable, onDidCreate: () => disposable,
      onDidChange: () => disposable, onDidDelete: () => disposable
    }),
    fs: {
      readDirectory: async () => [["old.json", 1]],
      stat: async () => ({ size: 1000, mtime: Date.now() - 13 * 60 * 60 * 1000 }),
      readFile: async () => { reads++; return Buffer.from(JSON.stringify(snapshot())); }
    }
  };
  const context = { subscriptions: [] };

  // Act
  await activate(context, ui.vscode);

  // Assert
  assert.equal(reads, 0);
  for (const subscription of context.subscriptions) subscription.dispose();
});
