# Codebase Issues Meta Audit Prompt

**Purpose:** Perform a thorough static meta-audit of a GitLab repository and produce a findings report with proposed surgical fixes only. No code, dependency, test, CI, or configuration changes are applied.

**Date:** {{CURRENT_DATE}}  
**Audited revision:** {{GIT_COMMIT_SHA_OR_BRANCH}}  
**Deliverable:** Findings and proposed surgical fixes only.

---

## Scope and interpretation

Review the first-party application code, shared libraries, tests, scripts, Git hooks (if present), configuration, CI, container/deployment files, and package/build manifests relevant to the repository.

**Tech-stack awareness (use what is present):**
- Frontend: Node.js / TypeScript / pnpm / Angular / Crystal / other JS/TS tooling
- Backend: .NET 10 C#, Java 17 OpenJDK (Quarkus), Gradle, RabbitMQ, MongoDB, AWS S3
- Mixed front-end + back-end repositories
- Any other languages or frameworks found in the repo

**Project AI guidance (use only what exists):**
- Look for and load any available AI rules, skills, instructions, AGENT files, Copilot instructions, Cursor rules, `.github/copilot-instructions.md`, `AGENTS.md`, `.cursorrules`, skill files, rule bodies, or similar guidance in the repository root or standard locations.
- Do **not** assume a fixed count of rules, skills, or references. Use whatever is actually present.
- If none exist, proceed with standard engineering best practices for the detected stack(s).

**Out of scope for primary audit targets:**
- All generated source files (including generated clients, interfaces, DTOs, protocol bindings, and designer files), generated coverage, build output, package stores (`node_modules`, `bin`, `obj`, `.gradle`, etc.), vendored third-party source, binaries, and Git internals.
- Lockfiles are not finding targets for this audit.
- Selected dependency code may be inspected only to verify integration contracts.

**Audit categories to cover:**
- Security
- Performance
- Concurrency / threading / async lifetime
- CPU
- Memory
- Unreleased resources
- Uncaught exceptions / error handling
- Language/tooling quality (TypeScript, C#, Java, Crystal, etc. as applicable)

Related symptoms may be grouped. Use the evidence requirements and severity levels below.

This is a repository-wide static review (with selected local reproductions where practical). It is not a penetration test, load test, heap profile, or guarantee that every possible defect has been found.

---

## Evidence required before a finding

Report a confirmed finding only when all of these are true:

1. The code is on a path a user, job, or startup sequence can reach.
2. You opened the writer and at least one caller or template that uses it.
3. You can name the input and what happens on that path today.
4. A smaller change would correct that behavior.

For each finding, add:
- Reachability: entry point, caller, and the input that triggers it.
- Evidence: the lines you read, including the test or template that shows the intended behavior.
- Why the proposed change is enough.

If a path is incomplete on purpose (mock data, TODO, method that throws "not implemented" and has no production caller), list it under Unfinished work. Do not put it in the findings tables.

Conditional security items are the only exception to proven reachability and caller evidence: the dangerous call must exist and be opened, and you must state which caller or reachability evidence could not be established. Keep them in section 3 only, separate from confirmed findings; do not present a hypothetical input as observed behavior.

## Build dependencies and official documentation

Complete this preflight before reviewing application code for the audit categories.

1. Read every build and dependency manifest that is present: `package.json`,
   `pnpm-workspace.yaml`, `.nvmrc`/`engines`, `pom.xml`, `build.gradle(.kts)`,
   `settings.gradle(.kts)`, `gradle/libs.versions.toml`, `gradle.properties`,
   `*.csproj`, `Directory.Packages.props`, `Directory.Build.props`, `global.json`,
   `pyproject.toml`, `requirements*.txt`, Dockerfile base images, and CI
   tool/runtime versions. Read lockfiles only to resolve exact installed versions;
   they remain out of scope as finding targets.
2. List the runtimes, frameworks, and libraries the reviewed code actually uses for
   security, data access, messaging, HTTP, concurrency, resource lifetime, and error
   handling, with their exact resolved versions.
3. For each listed dependency, read the publisher's official online documentation
   for that version: API reference, thread-safety and disposal/lifetime rules,
   configuration defaults, security guidance, release notes, and breaking-change or
   migration notes. Use official publisher or project sources only, not blogs or
   answers. If documentation cannot be retrieved, record that in section 6.
4. Record each source URL and version in section 1. Read each dependency's
   documentation once and keep a concise summary of the facts that apply to this
   code; do not re-read it for every file.

Documentation defines the correct contract; it does not replace code evidence. A
finding still needs every item in "Evidence required before a finding". Do not
report an outdated or vulnerable version alone; dependency upgrades are handled
by the separate GitLab package job.

## Review order

Review in this order and record each entry point you opened:

1. HTTP and message entry points: every controller action, middleware, health check, and background worker. For each action, note the auth scheme and the authorization rule.
2. Data access: repository queries, raw SQL, and values that cross a process boundary. Compare frontend field names and separators with the backend DTO and database value.
3. Error and log output: exception responses, retry logs, and client logs. A finding needs the value that leaves the process.
4. Resource lifetime: subscriptions, transactions, HTTP clients, and timers. A subscription that is tied to destroy, or an HTTP observable that completes, is not a leak.
5. UI behavior that already has a sibling implementation. Read that sibling before calling the other one wrong.

Stop after implemented paths. Do not code-review generated files, generated coverage, lockfiles, or vendored packages for these findings.

## Required coverage and completion

Before opening application source, discover every project and subproject from
the workspace and build manifests. Read each project's generator configuration:
Gradle source sets and generation/Sync tasks, Maven plugins, .NET generated-output
properties/items, npm scripts, OpenAPI/GraphQL/Protobuf configuration, Git
generated-file attributes, and generator output manifests as applicable. Follow
variables and copy destinations; generated outputs can be checked in and can
have arbitrary names. Do not execute generators or build scripts to discover
their outputs. Exclude every identified generated file and output folder before
reviewing application implementations. Keep handwritten siblings, generator
inputs/templates, and generator configuration in scope.

The MCP response supplies `coverage.files`, the candidate first-party inventory
after automatic generated, vendored, build, and lockfile exclusions. Register
additional project-specific generated outputs with
`choose_software_audit_action(repo_root=..., progress={"message": "Project
generation preflight", "generated_exclusions": [{"path":
"backend/custom-client", "evidence": {"path": "backend/build.gradle",
"sha256": "<current configuration SHA-256>", "assessment": "<generator,
output declaration, and resolved destination>"}}]})`.
Paths are concrete checkout-relative files or directories, not glob patterns.
These are host-attested exclusions with current configuration evidence, not
permission to hide uncertain or handwritten code. The server prunes those
outputs, retains the declarations, and removes excluded files from counts and
receipts. If configuration changes, refresh its evidence before continuing.
Never exclude the checkout or the configuration providing the evidence. Record
unresolved generation boundaries as blockers instead of reviewing potentially
generated implementations or claiming completion.

Review every remaining listed file, not just pattern-search hits or a few
representative controllers.
For each application action and worker, trace its caller, authorization rule,
data access, process-boundary inputs/outputs, failure behavior, and lifetime.
Use handwritten callers, generator inputs/templates, and handwritten tests as
supporting evidence. Do not review generated implementations or interfaces,
including as supporting evidence. If an inventoried file is generated but was
not automatically recognized, register its exclusion with the configuration
evidence above; do not invent a review receipt or mark the audit
complete while that inventory mismatch remains unresolved.

After each small batch, call `choose_software_audit_action` with the same
`repo_root` and `progress={"message": "<stage and files>", "files": [{"path":
"<inventory-relative path>", "sha256": "<current full-file SHA-256>",
"assessment": "<what was read and which behavior was traced>"}],
"completed_phases": ["<completed review phase>"]}`.
Phases are `entry_points`, `data_access`, `errors_logs`, `resource_lifetime`,
and `ui_siblings`. Mark non-applicable phases explicitly in the report and
complete their phase receipt only after checking applicability. File counts
are derived from receipts; declaring a numeric total is not evidence of review.
Do not copy an inventory entry as an assessment or claim an unread file was read.

### Context-efficient execution

- Review related files in batches, usually 10-20 when practical. Open bounded,
  line-numbered ranges and expand them wherever a caller, contract, or behavior
  remains unclear; search hits alone never count as a review.
- Reuse unchanged source, guidance, and evidence already read in the current
  context. Reopen changed files or anything needed to resolve uncertainty.
  Do not repeatedly load every rule/skill body or unrelated reference document.
- Compute current full-file hashes together locally for the files actually read.
  Submit only new or refreshed receipts, with concise, file-specific behavioral
  assessments; do not resend previous receipts or echo file contents in progress.
- Initial consent supplies the full prompt and inventory. Later handoffs supply
  the next paths, remaining counts/phases, and registered generated exclusions.
  A bounded path list is not the whole remaining scope: continue until the count
  reaches zero and every phase is complete. After context loss only, recover
  `software_audit` through
  `get_run_status(repo_root=..., include_audit_details=True)`; it retains the full
  prompt, inventory, receipts, and any complete coverage-gap list. Do not poll
  that large snapshot for progress; use the GUI and batch acknowledgments.
- Use context compaction throughout the audit. Compact what you have already
  gathered: file contents, search output, dependency documentation, and tool
  results become concise notes (path, hash, behaviors traced, candidate findings
  with exact line numbers, and the documentation facts that apply). Never compact,
  paraphrase, shorten, or drop this prompt's own instructions, evidence
  requirements, severity rules, output format, or human-approval boundaries.
  After any compaction, follow the original prompt text, not a summary of it; if
  it is no longer in context, recover it as described above before continuing.
- Update only changed report sections after each batch, keeping the report on
  disk. Do not rewrite or repeat the entire report in chat for each update.

A progress receipt and a finished delegated review are intermediate results, not
permission to end the audit turn. Continue opening the remaining inventory and
recording genuine receipts until all coverage and phases are complete. Do not
replace the report/GUI handoff with a chat summary of a partial review.
Never ask the developer to type "continue" for this already approved report.
The server creates a clearly marked INCOMPLETE progress draft in the home
directory at consent and persists progress there. Replace that draft with actual
findings incrementally after each review batch; do not defer all report writing
until the final file. A progress draft is not a completed report, even when all
coverage receipts exist. Remove its incomplete-draft marker only when replacing
it with the actual report. Editor stop hooks can continue a prematurely ended
turn when installed, but must respect cancellation, errors, stalled progress,
human approval boundaries, and the editor's native turn limits.

Before calling `report_ready=True`, finish every inventoried file and all five
phases, then save the complete report at the exact requested output path.
`AUDIT_INCOMPLETE` means continue the read-only review and update the report;
it must not open the fix-selection UI. Changed files need fresh receipts.
Record any genuine review blocker rather than declaring completion.

Ask the developer Yes/No before starting this optional audit, after the separate
GitLab package, false-positive, and source-fix jobs. If accepted, generate the
complete report before opening unchecked audit-fix checkboxes. Cancel or an
empty selection approves no fixes and proceeds to the final unresolved report.
Zero or one finding is valid after complete review; do not invent findings,
lower the evidence bar, or inflate severity to satisfy an expected count.

## Severity

- **High:** A reachable path loses or exposes data, skips an authorization check, or fails a request that production code claims to handle.
- **Medium:** A reachable implemented path returns the wrong result or reports success when it did not save.
- **Low:** A local defect with a named caller and a small fix.
- **Conditional:** The dangerous call exists, and you could not prove a caller. Keep these in the security section only.

An empty High section is a valid result. Do not raise severity to fill the table.

## File and line links

Every source filename in the report, including table cells, evidence, and section 7 locations, must be a clickable Markdown link to the affected file and a 1-based code line. Keep the Line Number table column as well.

- Use the actual audited checkout (`repo_root` in the tool response), not this MCP server's source directory.
- Compute link destinations relative to the directory containing the final report (`output_path` in the tool response), not relative to the checkout or the assistant's working directory. The report is saved in the home directory, outside the checkout.
- Use forward slashes in Markdown link destinations and append `#L<number>` to navigate to the line in VS Code and Cursor. For example, if the checkout is under the home directory at `source/My Project`, use `[src/File.cs:12](./source/My%20Project/src/File.cs#L12)`. The visible filename and line must match the target.
- Percent-encode spaces and other URL-sensitive path characters (such as `#`, `%`, `(`, `)`, and `|`) before adding the line fragment; escape Markdown-special characters in link labels. Do not use a bare `path:line`, a GitLab web URL, or editor-specific `vscode://` or `cursor://` links as a substitute.
- If a relative path cannot span different Windows drives, use a `file:///D:/.../File.cs#L12` URI with the same encoding instead.
- Verify that each target file exists and the cited line is the line you actually read. Do not invent line numbers. Links are local to the audited checkout; moving the report or checkout can require regenerating them.

---

## Output format

Produce the report in this structure:

### 1. Scope summary
Brief note on what was reviewed, which stacks were detected, and which (if any) project AI rules/skills/instructions were loaded.
List each build dependency reviewed with its resolved version and the official documentation URL read for it.
Record every entry point opened in review order, including each action's auth scheme and authorization rule. Mark anything not reviewed as a limitation rather than implying full coverage.

### 2. Functional, reliability, performance, and quality findings

Use a table:

| Issue Type | Filename | Line Number | Problem | Solution |
|------------|----------|-------------|---------|----------|

For each finding include:
- Severity (High / Medium / Low)
- Short ID (e.g. R01, R02…)
- Clear problem description
- Proposed surgical fix
- Reachability, evidence with linked code lines (including the test or template showing intended behavior), and why the proposed change is enough; use an ID-keyed explanation below the table if needed
- Suggested test(s) if relevant
- Do **not** apply the fix

### 3. Security findings and conditional hardening items

Separate table or section for security items (including conditional ones). Include CWE references where appropriate. Note confidence and whether reachability was established.
Use the same file-and-line links and per-finding evidence fields as section 2. Label any unproven caller explicitly for Conditional items.

### 4. Verification performed
List any local checks, commands, or source-level reproductions that were run and their results. Note the local runtime vs. declared CI/runtime if they differ.

### 5. Recommended fix order
Prioritized list of the most important issues to address first.

### 6. Limitations
Note what was not covered (private packages, full transitive CVE review, runtime profiling, deployed environment values, etc.).

### 7. Selectable findings

List only rows from sections 2 and 3, including conditional security items. Unfinished work and rejected leads stay out of this list. One item per line and no other text in this section, except that a report with no selectable findings must contain exactly `No selectable findings.`:

`- R01 | High | [src/File.cs:12](./source/My%20Project/src/File.cs#L12) | One-sentence problem`

Use the same short IDs, severity, and linked locations as the tables, with exactly four pipe-delimited fields and no literal pipes inside a field. Compute the real link for this checkout and report location; do not copy the example path. The human will see one checkbox per line and may leave any of them unchecked.

### 8. Unfinished work

List intentionally incomplete paths (mock data, TODOs, and unimplemented methods without a production caller) separately from findings. Include the linked lines you opened and why they are not implemented reachable defects. These entries are not selectable.

### 9. Investigated and rejected

Add one short line per lead you opened and did not report, with the reason. Include pattern-search hits in tests, already-guarded catches, and unimplemented methods with no production caller (refer to section 8 where applicable). These entries are not selectable.

---

## Guidelines for the auditor

- Prefer surgical, minimal fixes. Do not propose large refactors, new frameworks, or dependency upgrades unless they are the smallest correct fix for a confirmed defect.
- Preserve public contracts and existing behavior unless the current behavior is clearly defective.
- For mixed-stack repos, audit each major part (frontend, backend, infrastructure) appropriately for its language and tooling.
- When project AI rules/skills exist, follow them. When they do not, fall back to language- and framework-specific best practices (Angular/TypeScript quality, .NET resource lifetime, Java/Quarkus concurrency and resource handling, Crystal idioms, etc.).
- Be explicit about what was and was not verified.
- Group related symptoms rather than inflating the count of defects.
- Do not claim security clearance or that a full dependency audit was performed unless it was.

---

## Usage notes

When invoked through MCP, the host AI performs the scan; the server does not run an autonomous AI review. Follow the file/phase receipt protocol above. After writing the exact requested `output_path`, call `choose_software_audit_action(repo_root=..., report_ready=True)`. Coverage is checked before unchecked findings are shown. Fix only human-selected items; report progress with `complete_security_run(progress={id,message})` and finish with `complete_security_run(code_results=[{id,status:"fixed" or "failed",reason,validation}])`. Record an honest failure reason when a selected fix cannot be completed. Fixed outcomes require actual validation evidence. This finishes with the displayed unresolved Markdown report. Do not stop after writing the audit report without making the report-ready call.

Paste this prompt into an AI coding assistant (Copilot, Cursor, Claude, Grok, etc.) while pointed at the target GitLab repository.  
Replace the placeholders (`{{CURRENT_DATE}}`, `{{GIT_COMMIT_SHA_OR_BRANCH}}`) as needed.  
When used outside the MCP tool, establish the audited checkout's absolute path and the final report location before constructing source links.
The AI should discover the actual stacks and any project-specific AI guidance present in that repository.
