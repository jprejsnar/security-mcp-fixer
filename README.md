# GitLab Security MCP

Local-only MCP server that reads GitLab security findings, checks each one against the repository and public advisories, and applies the smallest safe fix. It does not commit, push, open a merge request, or change anything in GitLab.

The dated branch, the diff, and the report stay on your machine until you review them and commit yourself.

## What it does

The server exposes one tool per phase. A Cursor agent should call them in this order:

1. `run_prechecks` — stop unless the repo is a clean checkout of `main`, with no merge, rebase, cherry-pick, revert, or bisect in progress.
2. `pull_main_twice` — fast-forward `main` twice with `git pull --ff-only`. Either failure stops the run.
3. `create_security_branch` — create `security-fixes-Month-dd-YYYY` (for example `security-fixes-November-01-2026`). If that name already exists locally or on `origin`, the run stops.
4. `list_security_findings` — read findings from the project vulnerability report using GitLab GraphQL. Filters match the UI: Status = Needs triage or Confirmed, Tracked ref = `main`, Activity = Still detected. The client resolves the exact tracked branch ID, requests states `DETECTED`/`CONFIRMED`, and sets `hasResolution: false`. If tracked `main` is unavailable, the client stops instead of fetching unfiltered results. Pipeline provenance is recorded per finding when available.
5. `verify_security_finding` — for every finding, compare the local manifest or lockfile with OSV, the GitHub Advisory Database, and NVD.
6. `apply_minimal_fix` — edit only findings marked `CHANGE_REQUIRED`. Findings that online lookups cannot settle are skipped.
7. `generate_aaa_test` — add an Arrange-Act-Assert test when the fix changes runtime behavior, such as a base-image tag. Dependency-only edits do not get a test.
8. `run_validation_matrix` — run the checks that match the repo: Node, .NET, Java, NGINX, and a Dockerfile check.
9. `generate_local_report` — write a Markdown report and a JSON report.

`get_run_status` shows the current phase at any time.

A finding is auto-fixed only when all of these are true:

- Local evidence shows the vulnerable package or image is present.
- An online advisory confirms it and publishes a fixed version newer than what is installed.
- The edit is a lockfile refresh, a manifest version bump, a package override, or an unpinned `FROM` tag bump.
- The fix stays within the installed major version (or the same minor for `0.x`). A major jump is skipped and listed for you.

An advisory that names the identifier but not the package found in the repo is listed for you to review. It is not reported as a false positive, because the cause may be a naming difference.

Unknown reachability is not treated as a false positive. Secret detection and DAST findings are reported for you to handle. They are not rewritten. SAST findings are not patched by guessing at source changes.

## What it refuses to do

Git commands are allowlisted. `git add`, `commit`, `push`, `merge`, `rebase`, `reset`, and any other branch checkout are rejected. Package-manager commands are allowlisted too, with timeouts, truncated output, and a hash-only audit log at `.security-mcp/audit.jsonl` inside the target repo. The GitLab token is used for queries only.

Reports and the audit log live under `.security-mcp/` in the target repository. They are untracked. The clean-tree check ignores that directory so the server's own notes do not fail the precheck. Do not commit that directory unless you want the report in git.

### Robustness

Engine tools and HTTP client operations are serialized within one process.
Shutdown waits for active operations, closes owned clients once, and rejects
later calls. Tool results are detached snapshots rather than live state.
Malformed advisory responses fail lookup; malformed local evidence requires
manual review instead of being treated as package absence. Validation read or
execution failures produce `VALIDATION_FAILED`.

State, manifests, and individual report files are replaced atomically. Generated
tests are published without replacing existing files. Command readers stop
even when descendants retain inherited pipes. This does not guarantee cleanup
of detached descendant processes, coordinate multiple MCP processes editing
the same checkout, or make the Markdown/JSON report pair a single transaction.

Run the offline AAA regression suite with leak and thread warnings fatal:

```powershell
.\.venv\Scripts\python.exe -W error::DeprecationWarning -W error::ResourceWarning -m pytest -q -W error::pytest.PytestUnhandledThreadExceptionWarning
```

## Requirements

### Repository Compatibility

| Repository | Automatic dependency fixes | Validation |
|---|---|---|
| Node.js | npm, pnpm, Yarn Classic and modern Yarn; direct version bumps, supported lock refreshes, overrides/resolutions | Install, advisory audit, declared lint/build/test scripts |
| .NET 10 | NuGet project references and existing central `Directory.Packages.props` versions | SDK compatibility check, restore, Release build/test; `.sln`, `.slnx`, C#, F#, and VB project detection |
| Java 17 | Maven direct versions/properties and Gradle coordinates/supported version-catalog entries | Java 17 check, Maven verify/dependency tree or Gradle dependencies/test/build; wrappers preferred |

These are safe dependency-remediation paths, not a promise to fix every security
finding. A matching advisory, a published compatible fix, and a supported local
edit are required. Unresolved Java/NuGet transitive dependencies require review;
SAST, DAST, secrets, unsupported dependency formats, and breaking upgrades are
not patched by guessing.

Point `REPO_ROOT` at the build/package-manager entry directory. Arbitrary mixed
monorepo layouts are not automatically orchestrated. Required tools must be on
the server process's PATH. A missing required tool produces
`VALIDATION_INCOMPLETE`; an incompatible Java runtime or an SDK too old for
`net10.0` produces `VALIDATION_FAILED`. Install/configure the required tools and
rerun validation. A .NET SDK 10 or newer is needed for `net10.0`; Java validation
requires a Java 17 toolchain, not merely any installed Java version.

- Windows, macOS, or Linux
- Python 3.11 or newer
- Git
- A GitLab personal access token with the `read_api` scope
- The project path or numeric id, and access to the project's vulnerability report

Node, .NET, Java, NGINX, and Docker are only needed when the target repo uses them and you want that part of the validation matrix to run.

## Install

From this project directory:

**Windows (PowerShell)**

```powershell
cd C:\Users\james\cursor_projects\security-mcp-fixer
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

**macOS or Linux**

```bash
cd /path/to/security-mcp-fixer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Configure Cursor

Cursor starts the server itself. You do not leave `python server.py` running in a terminal.

Create or edit the project file `.cursor/mcp.json` in the repository you want to remediate, or edit your user MCP config at `%USERPROFILE%\.cursor\mcp.json` on Windows (`~/.cursor/mcp.json` on macOS or Linux).

**Windows**

```json
{
  "mcpServers": {
    "gitlab-security": {
      "command": "C:\\Users\\james\\cursor_projects\\security-mcp-fixer\\.venv\\Scripts\\python.exe",
      "args": [
        "C:\\Users\\james\\cursor_projects\\security-mcp-fixer\\server.py"
      ],
      "env": {
        "GITLAB_TOKEN": "glpat-replace-me",
        "GITLAB_PROJECT_ID": "group/project",
        "GITLAB_API_URL": "https://gitlab.com/api/v4",
        "REPO_ROOT": "C:\\path\\to\\the\\repo\\to\\fix"
      }
    }
  }
}
```

**macOS or Linux**

```json
{
  "mcpServers": {
    "gitlab-security": {
      "command": "/path/to/security-mcp-fixer/.venv/bin/python",
      "args": ["/path/to/security-mcp-fixer/server.py"],
      "env": {
        "GITLAB_TOKEN": "glpat-replace-me",
        "GITLAB_PROJECT_ID": "group/project",
        "GITLAB_API_URL": "https://gitlab.com/api/v4",
        "REPO_ROOT": "/path/to/the/repo/to/fix"
      }
    }
  }
}
```

`REPO_ROOT` is the application repository to inspect and edit. It can be a different directory from this MCP project. Use the virtualenv's Python so Cursor does not depend on a global install.

Reload MCP servers in Cursor (Settings → MCP, or the MCP refresh control) and enable `gitlab-security`. The process speaks MCP over stdin and stdout. It waits for Cursor. It does not open a port.

### Reload code changes

Use the source launcher shown above: the virtualenv's Python with the absolute
path to `server.py`. It imports the adjacent `gitlab_security_mcp` source tree,
not an older installed copy. After changing code, restart/reload the
`gitlab-security` MCP server in Cursor to load the changes. No rebuild or package
reinstallation is needed for source-only changes.

This restarts the process, rather than updating an active run in place. Reload
between remediation runs: in-memory state is reset, and a new run must pass
prechecks again. Dependency changes still require installing the updated
requirements into the configured virtual environment before restarting.

### Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `GITLAB_TOKEN` | yes | Personal access token. `GITLAB_PERSONAL_ACCESS_TOKEN` is also accepted. |
| `GITLAB_PROJECT_ID` | yes | Path such as `group/project`, or a numeric id. |
| `REPO_ROOT` | yes in Cursor | Absolute path of the git repo to remediate. Defaults to the process working directory. |
| `GITLAB_API_URL` | no | REST base URL. Defaults to `https://gitlab.com/api/v4`. GraphQL is derived from it. |
| `GITHUB_TOKEN` or `GH_TOKEN` | no | Raises the GitHub Advisory rate limit. |
| `NVD_API_KEY` | no | Raises the NVD rate limit. OSV is tried first and does not need a key. |
| `VALIDATION_TIMEOUT_SEC` | no | Per validation command. Defaults to 600. |

For a self-hosted GitLab instance, set `GITLAB_API_URL` to `https://gitlab.example.com/api/v4`.

Keep the token in the MCP config, not in a committed file.

## Run

1. Install the dependencies and save the MCP config above.
2. Check out `main` in `REPO_ROOT` and make sure `git status` is clean.
3. Reload the `gitlab-security` server in Cursor.
4. In Agent chat, ask it to run the remediation workflow. For example:

```text
Use the gitlab-security MCP tools in order. Run prechecks, pull main twice,
create the security branch, list findings, verify each finding, apply only
eligible fixes, generate AAA tests where behavior changed, run validation,
and generate the local report. Display unresolved_issues_table at the end
of your final response. Stop if a gate fails. Do not commit or push.
```

5. Read `.security-mcp/reports/security-remediation-report-*.md` in the target repo.
6. Review `git diff`. If you agree with it, commit and push that branch yourself.

The report always includes three sections:

- False positives, with the finding id and the evidence-based reason
- Issues with no solution at this time
- Findings skipped because they need your input

Those skipped findings are also returned by `verify_security_finding` and `apply_minimal_fix` as `MANUAL_REVIEW` / `SKIPPED_USER_PROMPT`. Tell the agent how you want them handled. The server will not guess a version when OSV, GitHub Advisory, and NVD do not.

The report ends with an **Unresolved Security Issues** table: severity, package,
installed version, issue identifiers/title, and the reason no package or code
update was applied. It includes no-safe-fix, manual-review, and failed-fix
outcomes, but excludes false positives and successfully applied fixes. The MCP
result returns `unresolved_issues` and `unresolved_issues_table` so the agent can
display the same table at the end of its response. Unverified findings remain
listed separately; they are not assumed to be resolved or unfixable.

### Run the tests

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest
```

#### Python documentation standards

Maintained Python sources follow [PEP 8](https://peps.python.org/pep-0008/),
[PEP 257](https://peps.python.org/pep-0257/), and the official
[documentation-string guidance](https://docs.python.org/3/tutorial/controlflow.html#documentation-strings).
Modules and classes have docstrings. Public APIs describe their purpose and,
where relevant, ownership, side effects, failures, and limits. Private helpers
and nested callbacks have docstrings or leading intent comments. Tests retain
their Arrange-Act-Assert structure rather than adding comments to every line.
Comments explain non-obvious intent, not obvious assignments or control flow.

The standards suite checks Ruff conventions, Python 3.11 source syntax, and
documentation on every named definition in maintained source and test files:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_python_standards.py -q
```

Generated package copies under `build/` are refreshed by building the wheel;
they are not independently edited or used as the documentation source of truth.

#### Patient-web live checks

Live retrieval is an integration test, not an offline unit test. It is skipped
unless `--patient-web-live` is supplied. Set `GITLAB_TOKEN` (or
`GITLAB_PERSONAL_ACCESS_TOKEN`) securely in the test process environment using a
token with `read_api` and access to the patient-web vulnerability report. Never
commit credentials. The project path is fixed to
`clario-clinical/NxT/ecoa-swift/patient-web/patient-web`.

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_patient_web_live.py::test_retrieve_patient_web_security_findings --patient-web-live -v -s

$env:PATIENT_WEB_REPO_ROOT = 'C:\Users\James.Prejsnar\source\repos\patient-web'
.\.venv\Scripts\python.exe -m pytest tests/test_patient_web_live.py --patient-web-live -v -s
```

The first command checks that all active findings are retrieved, without
truncation. The second also checks each finding against the local checkout and
public advisories. It prints each decision and fails if any finding requires
manual review, has no safe fix, or proposes a target that advisories cannot
confirm is unaffected. Evidence-backed false positives do not require a fix.
This deliberately does not assume every vulnerability has a solution. An empty
active report fails the retrieval check; update that expectation once the
project is clean. These tests do not apply fixes, execute Git or package-manager
commands, or write MCP state or reports into patient-web.

### Optional: MCP Inspector

If Node.js is installed:

```powershell
.\.venv\Scripts\Activate.ps1
mcp dev server.py
```

`python server.py` by itself only waits on stdin for an MCP client. That is expected. Cursor is the client.

## Fixes it can apply

| Strategy | When | Score |
| --- | --- | --- |
| Lockfile refresh | The declared npm, pnpm, or Yarn range already allows the fixed version | 1 |
| Manifest bump | `package.json`, `pom.xml`, Gradle, `libs.versions.toml`, or a NuGet `PackageReference` | 2 |
| Override or direct pin | A transitive npm, pnpm, Yarn, or NuGet package | 3 |
| Image tag | An unpinned `FROM image:tag` whose name matches the finding | 3 |

Edits that would rewrite application source, or that score above 3, are not applied. They are listed as needing you, or as having no safe fix.

Lockfile refreshes use the package manager already selected by the repo (`npm`, `pnpm`, or `yarn`) and pass `--ignore-scripts` on that refresh. Validation then runs the project's own install and test commands.

## Validation

| Stack | Commands |
| --- | --- |
| Node | `npm ci` (or the pnpm/Yarn frozen install), `lint` / `build` / `test` when those scripts exist, and `npm audit --json` as information only |
| .NET | `dotnet restore` (`--locked-mode` when `packages.lock.json` exists), `dotnet build`, `dotnet test`. A target framework other than `net10.0` is reported, and the build still runs. |
| Java | `mvnw` or `mvn --batch-mode clean verify` and `dependency:tree`, or the Gradle wrapper's `dependencies`, `test`, and `build`. A JDK other than 17 is reported. |
| NGINX | `nginx -t` when `nginx` is installed and a config file is present |
| Container | `FROM` is required. `docker build --check` runs when Docker is available. A missing daemon is recorded as skipped. |

A failed required command sets the run to `VALIDATION_FAILED` and leaves the edits uncommitted.

## Development layout

### Python standards

The minimum supported version remains Python 3.11. Development checks use
[PEP 8](https://peps.python.org/pep-0008/),
[PEP 257](https://peps.python.org/pep-0257/), and the current
[Python porting guidance](https://docs.python.org/3/whatsnew/3.15.html#porting-to-python-3-15).
Do not introduce newer-only syntax or APIs without changing the support policy.
Text I/O uses explicit UTF-8 encodings, and injected clients remain caller-owned.

Install development dependencies and run the local checks:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m ruff check gitlab_security_mcp server.py tests
.\.venv\Scripts\python.exe -W error::DeprecationWarning -m pytest -q
```

AAA standards tests enforce lint rules and Python 3.11 source syntax alongside
the behavioral regression suite. Ruff checks PEP 8 layout, imports, supported
modernization, common correctness issues, and production PEP 257 docstrings.
Line-length checks are excluded for existing queries and report strings; test
docstrings are optional. Syntax checks do not replace runtime tests on each
supported Python version. Live GitLab tests remain opt-in.

`server.py` is the stdio entry point. The implementation is the `gitlab_security_mcp` package: Git allowlist and audit log, GitLab GraphQL client, advisory lookup, manifest editors, validation, AAA tests, and the report.
