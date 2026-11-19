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
- Generated coverage, build output, package stores (`node_modules`, `bin`, `obj`, `.gradle`, etc.), vendored third-party source, binaries, and Git internals.
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

Related symptoms may be grouped. Use these severity levels:

- **High:** Direct production lifecycle, correctness, or UI/runtime failure with a clear code path.
- **Medium:** Correctness/reliability defect or important tooling failure, sometimes requiring a stated trigger.
- **Low:** Local efficiency, test-quality, or minor maintainability defect.
- **Conditional security items:** Unsafe construct or policy gap present, but attacker control/reachability not established. Separate these from confirmed functional findings.

This is a repository-wide static review (with selected local reproductions where practical). It is not a penetration test, load test, heap profile, or guarantee that every possible defect has been found.

---

## Output format

Produce the report in this structure:

### 1. Scope summary
Brief note on what was reviewed, which stacks were detected, and which (if any) project AI rules/skills/instructions were loaded.

### 2. Functional, reliability, performance, and quality findings

Use a table:

| Issue Type | Filename | Line Number | Problem | Solution |
|------------|----------|-------------|---------|----------|

For each finding include:
- Severity (High / Medium / Low)
- Short ID (e.g. R01, R02…)
- Clear problem description
- Proposed surgical fix
- Suggested test(s) if relevant
- Do **not** apply the fix

### 3. Security findings and conditional hardening items

Separate table or section for security items (including conditional ones). Include CWE references where appropriate. Note confidence and whether reachability was established.

### 4. Verification performed
List any local checks, commands, or source-level reproductions that were run and their results. Note the local runtime vs. declared CI/runtime if they differ.

### 5. Recommended fix order
Prioritized list of the most important issues to address first.

### 6. Limitations
Note what was not covered (private packages, full transitive CVE review, runtime profiling, deployed environment values, etc.).

### 7. Selectable findings

List every finding from sections 2 and 3, including conditional security items. One item per line and no other text in this section:

`- R01 | High | src/File.cs:12 | One-sentence problem`

Use the same short IDs as the tables. The human will see one checkbox per line and may leave any of them unchecked.

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

Paste this prompt into an AI coding assistant (Copilot, Cursor, Claude, Grok, etc.) while pointed at the target GitLab repository.  
Replace the placeholders (`{{CURRENT_DATE}}`, `{{GIT_COMMIT_SHA_OR_BRANCH}}`) as needed.  
The AI should discover the actual stacks and any project-specific AI guidance present in that repository.
