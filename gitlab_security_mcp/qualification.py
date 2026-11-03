"""Enforce reviewed compatibility and corporate approval for package updates.

The hosting AI reads official documentation; this module validates its
attestation and executes repository-owned checks. Only the corporation can
approve license terms. An SPDX identifier alone is not legal approval.
"""

from __future__ import annotations

import difflib
import hashlib
from pathlib import Path
from subprocess import SubprocessError
from urllib.parse import urlparse

from gitlab_security_mcp.commands import assert_allowed, resolve_tool, tool_name
from gitlab_security_mcp.manifests import iter_files
from gitlab_security_mcp.util import json_object, resolve_inside
from gitlab_security_mcp.validate import _run_result, _wrapper

PACKAGE_ECOSYSTEMS = {"npm", "NuGet", "Maven"}
CHECK_KINDS = ("build", "unit_tests", "runtime", "license_audit")
ARTIFACT_DIRS = {
    ".gradle",
    ".angular",
    ".cache",
    "coverage",
    ".pytest_cache",
    ".ruff_cache",
}
MAX_TREE_BYTES = 100 * 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024
MAX_SOURCE_FILES = 5
MAX_SOURCE_LINES = 200
MAX_POLICY_BYTES = 1024 * 1024
MAX_DIFF_CELLS = 4_000_000


def _read_bounded(path: Path, limit: int) -> bytes:
    """Read at most limit plus one bytes and close before rejecting growth.

    Bound the actual read rather than trusting a preceding stat result.
    Read and decoding errors propagate to the qualification boundary.
    """
    with path.open("rb") as stream:
        contents = stream.read(limit + 1)
    if len(contents) > limit:
        raise ValueError(f"{path.name} exceeds the qualification size limit")
    return contents


def _text(value: object, label: str) -> str:
    """Require bounded, nonempty evidence rather than truthy placeholders."""
    if not isinstance(value, str) or not value.strip() or len(value) > 32768:
        raise ValueError(f"{label} must be a nonempty evidence string")
    return value


def _sources(value: object, label: str) -> list[str]:
    """Require reviewed HTTPS references without embedded credentials."""
    if not isinstance(value, list) or not value or len(value) > 50:
        raise ValueError(f"{label} requires reviewed official HTTPS sources")
    for source in value:
        parsed = urlparse(_text(source, label))
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError(f"{label} requires HTTPS URLs without credentials")
    return value


def review_package(root: Path, review: dict) -> dict[str, str | None]:
    """Validate a documentation attestation and declared surgical edits.

    Retain pre-edit text only for declared files to bound later migrations.
    This is not independent proof that an AI read every documentation page;
    the audit retains its explicit attestation and source references.
    """
    if not isinstance(review, dict):
        raise ValueError("Package review must be an object")
    documentation = review.get("documentation")
    if not isinstance(documentation, dict) or documentation.get("complete") is not True:
        raise ValueError(
            "Review the complete official package documentation before qualification"
        )
    _sources(documentation.get("sources"), "Documentation")
    _text(documentation.get("summary"), "Documentation summary")
    if review.get("compatible") is not True:
        raise ValueError(
            "Unsupported or uncertain framework/runtime compatibility requires manual review"
        )
    _text(review.get("api_changes"), "API-change analysis")
    frameworks = review.get("frameworks")
    if not isinstance(frameworks, list) or not frameworks:
        raise ValueError(
            "Review the product's actual runtime, framework, and BOM versions"
        )
    for framework in frameworks:
        if not isinstance(framework, dict):
            raise ValueError("Framework evidence must be an object")
        for key in ("name", "version", "assessment"):
            _text(framework.get(key), f"Framework {key}")
        _sources([framework.get("source_url")], "Framework compatibility")
    fixes = review.get("source_fixes")
    if not isinstance(fixes, list) or len(fixes) > MAX_SOURCE_FILES:
        raise ValueError(
            f"Declare at most {MAX_SOURCE_FILES} surgical source fixes; use [] if none"
        )
    before = {}
    for fix in fixes:
        if not isinstance(fix, dict):
            raise ValueError("Source fixes must name a path and rationale")
        relative = _text(fix.get("path"), "Source-fix path")
        _text(fix.get("reason"), "Source-fix rationale")
        path = resolve_inside(root, relative)
        if path is None or path.suffix.lower() not in {
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".cs",
            ".fs",
            ".vb",
            ".java",
            ".kt",
        }:
            raise ValueError(
                "Surgical fixes must be supported source/test files inside the repository"
            )
        relative = path.relative_to(root.resolve()).as_posix()
        if relative in before:
            raise ValueError("Source-fix paths must be unique")
        before[relative] = (
            _read_bounded(path, MAX_SOURCE_BYTES).decode("utf-8")
            if path.exists()
            else None
        )
    return before


def _check_args(manager: str, kind: str) -> list[str]:
    """Select fixed command shapes rather than arbitrary policy scripts."""
    if manager in {"npm", "pnpm", "yarn"}:
        return {
            "build": ["run", "build"],
            "unit_tests": ["test"],
            "runtime": ["run", "security:smoke"],
            "license_audit": ["run", "security:licenses"],
        }[kind]
    if manager == "nuget":
        args = [
            "build" if kind == "build" else "test",
            "--configuration",
            "Release",
            "--nologo",
        ]
        if kind in {"runtime", "license_audit"}:
            args += [
                "--filter",
                "Category=SecurityRuntimeSmoke"
                if kind == "runtime"
                else "Category=LicenseCompliance",
            ]
        return args
    if manager == "maven":
        return {
            "build": ["--batch-mode", "clean", "verify"],
            "unit_tests": ["--batch-mode", "test"],
            "runtime": ["--batch-mode", "-Psecurity-smoke", "verify"],
            "license_audit": ["--batch-mode", "-Psecurity-licenses", "verify"],
        }[kind]
    if manager == "gradle":
        return [
            "--no-daemon",
            {
                "build": "build",
                "unit_tests": "test",
                "runtime": "securitySmoke",
                "license_audit": "securityLicenses",
            }[kind],
        ]
    raise ValueError("Package manager does not support qualification checks")


def _check_variants(manager: str, kind: str) -> list[list[str]]:
    """Permit fixed .NET category filters for VSTest and native MTP."""
    if manager != "nuget" or kind not in {"runtime", "license_audit"}:
        return [_check_args(manager, kind)]
    category = "SecurityRuntimeSmoke" if kind == "runtime" else "LicenseCompliance"
    prefix = ["test", "--configuration", "Release", "--nologo"]
    return [
        prefix + [flag, value]
        for flag, value in (
            ("--filter", f"Category={category}"),
            ("--filter", f"TestCategory={category}"),
            ("--filter-trait", f"Category={category}"),
            ("--treenode-filter", f"/*/*/*/*[Category={category}]"),
        )
    ]


def load_policy(root: Path, policy_path: Path, plan: dict) -> dict:
    """Require exact-version corporate approval and all product checks.

    Read the corporation-managed file without changing it. Its authenticity
    requires corporate access controls, not an AI-provided approval flag.
    Return a content hash so policy changes invalidate prior evidence.
    """
    raw = _read_bounded(policy_path, MAX_POLICY_BYTES)
    policy = json_object(raw.decode("utf-8"))
    if type(policy.get("schema_version")) is not int or policy["schema_version"] != 1:
        raise ValueError("Package approval policy requires schema_version 1")
    approvals = policy.get("approvals")
    if not isinstance(approvals, list):
        raise ValueError("Package approval policy requires an approvals list")
    matching = [
        item
        for item in approvals
        if isinstance(item, dict)
        and all(
            item.get(key) == plan.get(key) for key in ("ecosystem", "package", "target")
        )
    ]
    if len(matching) != 1:
        raise ValueError(
            "Exactly one corporate approval for this package and target version is required"
        )
    approval = matching[0]
    if (
        approval.get("commercial_distribution_approved") is not True
        or approval.get("no_license_fees") is not True
    ):
        raise ValueError(
            "Corporate approval must permit commercial distribution without license fees"
        )
    for key in (
        "license_expression",
        "approved_by",
        "approval_reference",
        "obligations",
    ):
        _text(approval.get(key), key)
    if approval["license_expression"].strip().upper() in {
        "UNLICENSED",
        "UNKNOWN",
        "NOASSERTION",
        "NONE",
    }:
        raise ValueError(
            "Missing or unlicensed terms cannot authorize commercial distribution"
        )
    _sources(approval.get("license_sources"), "License terms")
    all_checks = policy.get("checks")
    checks = all_checks.get(plan["ecosystem"]) if isinstance(all_checks, dict) else None
    if not isinstance(checks, dict) or set(checks) != set(CHECK_KINDS):
        raise ValueError(
            "Policy must require build, unit_tests, runtime, and license_audit checks"
        )
    manager = plan.get("manager")
    tools = {
        "npm": {"npm"},
        "pnpm": {"pnpm"},
        "yarn": {"yarn"},
        "nuget": {"dotnet"},
        "maven": {"mvn", "mvnw"},
        "gradle": {"gradle", "gradlew"},
    }.get(manager, set())
    for kind, check in checks.items():
        if not isinstance(check, dict):
            raise ValueError("Qualification checks must be objects")
        argv = check.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or any(not isinstance(arg, str) for arg in argv)
        ):
            raise ValueError("Qualification commands must be string arrays")
        if tool_name(argv[0]) not in tools or argv[1:] not in _check_variants(
            manager, kind
        ):
            raise ValueError(
                f"{kind} must use the package manager's dedicated allowlisted check"
            )
        _text(check.get("success_marker"), f"{kind} success marker")
        assert_allowed(argv, root)
    return {
        "approval": approval,
        "checks": checks,
        "policy_sha256": hashlib.sha256(raw).hexdigest(),
    }


def run_checks(root: Path, checks: dict, runner, which, timeout: int) -> list[dict]:
    """Require positive, untruncated success evidence from every check.

    Smoke checks must terminate and exercise product behavior. License
    checks must inspect the complete resolved dependency graph, including
    transitive packages and distribution obligations. Configure markers
    that prove actual checks ran rather than accepting empty test runs.
    Record expected execution errors per check; interrupts still propagate.
    """
    rows = []
    for kind in CHECK_KINDS:
        check = checks[kind]
        executable = check["argv"][0]
        try:
            if tool_name(executable) in {"mvnw", "gradlew"}:
                tool = _wrapper(root, tool_name(executable))
            else:
                tool = resolve_tool(executable, which)
            if not tool:
                rows.append(
                    {
                        "status": "SKIPPED",
                        "required": True,
                        "kind": kind,
                        "detail": f"{executable} is unavailable",
                    }
                )
                continue
            result = runner.run(
                [tool, *check["argv"][1:]], timeout=timeout, check=False
            )
        except (OSError, RuntimeError, SubprocessError) as exc:
            rows.append(
                {
                    "command": check["argv"],
                    "status": "FAILED",
                    "required": True,
                    "kind": kind,
                    "detail": f"Check could not execute: {exc}",
                }
            )
            continue
        row = _run_result(result, required=True)
        row["kind"] = kind
        if (
            result.truncated
            or check["success_marker"] not in result.stdout + result.stderr
        ):
            row["status"] = "FAILED"
            row["detail"] = "Positive check evidence is missing or output was truncated"
        rows.append(row)
    return rows


def tree_snapshot(root: Path) -> dict[str, str]:
    """Hash a bounded, pruned checkout to invalidate stale qualification."""
    files, truncated = iter_files(root)
    if truncated:
        raise ValueError(
            "Checkout snapshot is truncated; manual qualification is required"
        )
    hashes = {}
    total = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        if any(part in ARTIFACT_DIRS for part in path.relative_to(root).parts):
            continue
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(65536):
                total += len(block)
                if total > MAX_TREE_BYTES:
                    raise ValueError(
                        "Checkout snapshot exceeds the qualification size limit"
                    )
                digest.update(block)
        hashes[relative] = digest.hexdigest()
    return hashes


def validate_edits(
    root: Path, receipt: dict, allowed_files: list[str]
) -> dict[str, str]:
    """Reject undeclared, oversized, or computationally costly migrations."""
    after = tree_snapshot(root)
    before = receipt["tree"]
    changed = {
        path
        for path in before.keys() | after.keys()
        if before.get(path) != after.get(path)
    }
    allowed = set(allowed_files) | set(receipt["source_before"])
    if changed - allowed:
        raise ValueError(
            "Undeclared checkout changes require re-review: "
            + ", ".join(sorted(changed - allowed)[:10])
        )
    lines = 0
    for relative, original in receipt["source_before"].items():
        path = resolve_inside(root, relative)
        if path is None or not path.is_file():
            raise ValueError(
                "Surgical source file is missing, outside the repo, or too large"
            )
        current = _read_bounded(path, MAX_SOURCE_BYTES).decode("utf-8")
        lines += _changed_lines(original or "", current)
    if lines > MAX_SOURCE_LINES:
        raise ValueError(
            f"Source migration exceeds {MAX_SOURCE_LINES} added/deleted lines; manual review required"
        )
    return after


def _changed_lines(original: str, current: str) -> int:
    """Count edits after trimming equal context and bounding quadratic work.

    Large unchanged files and localized edits keep a linear fast path.
    Reject costly comparisons instead of holding the engine lock while
    SequenceMatcher processes arbitrarily many possible line pairs.
    """
    if original == current:
        return 0
    before, after = original.splitlines(), current.splitlines()
    prefix = 0
    common = min(len(before), len(after))
    while prefix < common and before[prefix] == after[prefix]:
        prefix += 1
    old_end, new_end = len(before), len(after)
    while (
        old_end > prefix
        and new_end > prefix
        and before[old_end - 1] == after[new_end - 1]
    ):
        old_end -= 1
        new_end -= 1
    before, after = before[prefix:old_end], after[prefix:new_end]
    if len(before) * len(after) > MAX_DIFF_CELLS:
        raise ValueError(
            "Source comparison exceeds the work limit; manual review required"
        )
    delta = difflib.SequenceMatcher(a=before, b=after)
    return sum(
        old_end - old_start + new_end - new_start
        for tag, old_start, old_end, new_start, new_end in delta.get_opcodes()
        if tag != "equal"
    )
