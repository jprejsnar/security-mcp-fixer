# Design simplification plan

Measured on `main` on 16 November 2026. Token counts are characters divided by 4. They are planning estimates, not a tokenizer bill.

The design can get simpler, faster, and cheaper to run in a host. The gain is a smaller prompt and a smaller result. A new plugin architecture would not make a run faster.

## What the current design costs

| Item | Size | When it is paid |
| --- | --- | --- |
| Session instructions in `gitlab_security_mcp/server.py` | 20,114 characters, about 5,000 tokens | Every conversation, before the first finding |
| Fifteen tool descriptions | about 700 tokens | Every tool list |
| Cited file embedded in `ai_source_review.cited_source` | up to 256,000 bytes, about 64,000 tokens | Every source finding that reaches host review |
| `REQUIRED_DOCS` download | 17 publisher pages | Every documentation read, including a one-language file |
| `gitlab_security_mcp/engine.py` | 3,392 lines | Editing time, not a token, until a model is asked to read the file |

`read_before_fix` builds a page for every entry in `REQUIRED_DOCS`, then adds named CVE and CWE records. A Python finding therefore waits on Docker, nginx, Java, Node, Angular, Crystal, Microsoft, .NET, TypeScript, JavaScript, C#, and the CVE, CWE, NSA, and NVD home pages.

`SourceEvidence.read` returns the file body. `verify_security_finding` puts that body on `cited_source`. The host already has the checkout.

## What stays

These are correctness and audit constraints. Do not trade them for speed.

- One engine pipeline. Do not split `engine.py` into a plugin registry.
- GitLab cursor pagination stays in order. Advisory lookup stays OSV, then GitHub, then NVD. Validation commands stay one at a time.
- Only a human checkbox may dismiss a finding. Desktop approval and host form elicitation stay outside the hours of source verification.
- A source false positive still records the cited line, the code analysis, input origin, reachability, reviewed-file hashes, and whether each CVE or CWE page GitLab named was available.
- A short label is still rejected. Unknown reachability is still not a false positive. A missing CVE still does not prove safety.
- The full-byte SHA-256 of each reviewed file is still checked. A review of a changed file is still rejected.

## Plan

Do the steps in this order. Each step is independently testable. Stop after a step if its tests fail.

### 1. Cut the session instructions

Keep the phase order and the safety rules in `INSTRUCTIONS`. Delete the repeated procedure. The tool description is the procedure for that step, and it is already sent with the tool list.

The session text should keep only:

1. `run_prechecks`
2. `pull_main_twice`
3. `create_security_branch`
4. `list_security_findings`
5. `verify_security_finding` for every finding
6. `qualify_package_update` for each eligible package update
7. `apply_minimal_fix` for each eligible fix, with no build between edits
8. `generate_aaa_test` only for a supported base-image change
9. `run_validation_matrix` once
10. `complete_security_run`
11. Human approval only through the existing checkbox path

Safety that must remain in the session text:

- Pass the same absolute `repo_root` when more than one checkout is active.
- Do not commit, push, or open a merge request.
- Only the human form may dismiss a finding. Do not infer approval.
- Unknown reachability is not a false positive. A missing CVE does not prove safety.
- Do not invent a version, a corporate approval, or a source patch.
- Do not weaken code or tests to make an update pass.
- Missing advisory data does not block a concrete GitLab package recommendation. Failed validation rejects that fix.
- Fuzzing needs local reproduction and must not be replayed against the remote host.
- Copy `final_summary_markdown` once. Completed source review is not a GitLab dismissal.
- On corporate DNS failure, ask the user to connect to VPN and stop.

Expected result: the session prompt drops by roughly 3,000 tokens. Tool descriptions should not grow by the same amount. If a rule exists only in `INSTRUCTIONS` and a tool needs it at call time, move that one rule onto that tool and delete it from the session text.

### 2. Stop embedding the file body

`verify_security_finding` should return:

- `path`
- full-file `sha256`
- cited line number
- `cited_text`
- the existing short context window

Do not return `content`. The server still reads the file to compute the hash. The host reads the file from the checkout with its own tools, then submits `source_review` with current full-byte hashes.

Update the host reason string that currently says the model must examine the full `cited_source`. Tell it to read the file at `path` and use the hash and cited lines as the receipt.

Expected result: a large source finding no longer costs up to 64,000 tokens. The 256,000-byte evidence budget can remain as a server-side read limit.

Tests that compare `cited_source["content"]` to the file bytes need to assert the hash, the path, the cited text, and the absence of `content`.

### 3. Fetch only the cited publisher pages

`_pages_for` should select from `REQUIRED_DOCS` instead of requesting every entry.

| Cited path | Pages to request |
| --- | --- |
| `.py` | Python |
| `.ts`, `.tsx`, `.mts`, `.cts` | TypeScript and JavaScript |
| `.js`, `.jsx`, `.mjs`, `.cjs` | JavaScript and Node.js |
| `.java`, `.kt` | Java |
| `.cs`, `.fs`, `.vb` | C# and .NET |
| Dockerfile | Docker |
| nginx config | nginx |
| GitLab CI | GitLab |
| `package.json` and npm lockfiles | Node.js |
| Maven or Gradle manifest | Java |
| NuGet manifest or project file | C# and .NET |

Also request each CVE and CWE record the finding names. Do not request the CVE, CWE, NSA, or NVD home pages unless the finding names that record.

A required page that fails still blocks the edit or the false-positive conclusion. A named CVE or CWE page that fails still blocks a false positive. An unrelated publisher is simply not called.

Expected result: a Python finding makes one publisher request instead of seventeen, plus any named CVE or CWE records. Fan-out stays capped at eight and is unchanged for the pages that remain.

Tests that assert `len(review.sources) == len(REQUIRED_DOCS)` for an empty finding need a cited file, and should assert the selected names.

### 4. Leave the engine as one pipeline

Do not split `engine.py` into plugins, handlers, or a new framework. The file is large, which slows edits, but the public methods already share one lock, one phase order, and one state object. Splitting that would add call paths without removing tokens or HTTP calls.

## Verification

After each of steps 1 to 3:

- Run the focused tests for source review, documentation reads, fan-out, config edits, and false-positive approval.
- Run the full unit suite before calling the step done.
- Re-measure `INSTRUCTIONS` and confirm a Python documentation read does not request the Java, Crystal, or Angular URLs.
- Confirm a source tool result has `sha256` and `cited_text` and does not have `content`.

Step 4 has no code change. Its check is that `Engine` is still the single pipeline and that GitLab pagination, advisory order, and command execution were not parallelized.
