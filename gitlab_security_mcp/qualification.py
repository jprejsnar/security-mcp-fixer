"""Enforce reviewed compatibility, license evidence, and configured policies.

The hosting AI reads official documentation; this module validates its
attestation and executes repository-owned checks. Documented license review
is not corporate approval; configured corporate policies remain mandatory.
An SPDX identifier alone is not legal approval.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from pathlib import Path
from subprocess import SubprocessError
from urllib.parse import urlparse

from gitlab_security_mcp.commands import assert_allowed, resolve_tool, tool_name
from gitlab_security_mcp.manifests import iter_files
from gitlab_security_mcp.util import atomic_write_text, json_object, resolve_inside
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
SOURCE_SUFFIXES = {
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".tsx",
    ".cs",
    ".fs",
    ".vb",
    ".java",
    ".kt",
}


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
    """Require compatibility evidence without production or test adaptations."""
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
    if review.get("compatible_without_code_changes") is not True:
        raise ValueError(
            "Package update requires explicit confirmation that neither production nor unit-test callers need API changes"
        )
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
    if fixes != []:
        raise ValueError(
            "Package version updates cannot require production or unit-test code changes; source_fixes must be []"
        )
    return {}


def _package_reference(package: str) -> re.Pattern[str]:
    """Match package tokens without treating names such as global as glob."""
    return re.compile(rf"(?<![\w@/-]){re.escape(package)}(?![\w-])")


def _package_scripts_hash(path: Path) -> str:
    """Fingerprint command definitions without exposing their contents."""
    data = json_object(_read_bounded(path, MAX_SOURCE_BYTES).decode("utf-8"))
    return hashlib.sha256(
        json.dumps(data.get("scripts", {}), sort_keys=True).encode()
    ).hexdigest()


def package_script_hashes(root: Path, snapshot: dict[str, str]) -> dict[str, str]:
    """Protect every existing build/test script from package-update adaptations."""
    return {
        relative: _package_scripts_hash(root / relative)
        for relative in snapshot
        if Path(relative).name == "package.json"
    }


def scan_package_callers(root: Path, plan: dict) -> dict:
    """Record bounded lexical caller hints, not a proof of runtime reachability."""
    snapshot = tree_snapshot(root)
    script_hashes = package_script_hashes(root, snapshot)
    sources = {
        path: digest
        for path, digest in snapshot.items()
        if Path(path).suffix.lower() in SOURCE_SUFFIXES
    }
    references = []
    package = plan["package"]
    reference = _package_reference(package)
    for relative in sorted(sources):
        text = _read_bounded(root / relative, MAX_SOURCE_BYTES).decode("utf-8")
        lines = [
            number
            for number, line in enumerate(text.splitlines(), 1)
            if reference.search(line)
        ]
        if lines:
            if len(references) >= 100 or len(lines) > 100:
                raise ValueError("Caller reference scan exceeds its evidence limit")
            references.append({"path": relative, "lines": lines})
    fingerprint = {
        "package": package,
        "installed": plan.get("installed"),
        "target": plan["target"],
        "sources": sources,
        "package_script_hashes": script_hashes,
        "dependency_files": {
            path: snapshot.get(path) for path in plan.get("files", [])
        },
    }
    return {
        "scan_id": hashlib.sha256(
            json.dumps(fingerprint, sort_keys=True).encode()
        ).hexdigest(),
        "source_files_scanned": len(sources),
        "package_script_hashes": script_hashes,
        "references": references,
        "limitations": "Lexical references are hints only. Review wrappers, dynamic calls, runtime requirements, and installed dependency callers; no direct imports does not prove compatibility.",
    }


def review_major_upgrade(root: Path, plan: dict, review: dict) -> dict | None:
    """Require fresh, explicit API/caller evidence without source adaptations."""
    if not plan.get("major_upgrade"):
        return None
    if review.get("source_fixes") != []:
        raise ValueError("Automatic major updates cannot adjust source or test code")
    evidence = review.get("major_upgrade")
    if not isinstance(evidence, dict):
        raise ValueError(
            "Major update requires API comparison and caller review evidence"
        )
    scan = scan_package_callers(root, plan)
    if evidence.get("scan_id") != scan["scan_id"] or scan != plan.get("caller_scan"):
        raise ValueError(
            "Caller scan changed or is missing; reverify and review current callers"
        )
    if (
        evidence.get("compatible_without_code_changes") is not True
        or evidence.get("caller_breakages_found") is not False
    ):
        raise ValueError(
            "Caller breakages or uncertain API compatibility require review, not an automatic major update"
        )
    _sources(
        evidence.get("migration_sources"), "Major-version API/migration references"
    )
    for key in ("api_comparison", "caller_assessment", "dependency_assessment"):
        _text(evidence.get(key), key)
    reviewed = evidence.get("reviewed_files")
    if not isinstance(reviewed, list) or not reviewed or len(reviewed) > 100:
        raise ValueError(
            "Review actual caller source files, including dependency callers for transitive packages"
        )
    reviewed_paths = set()
    dependency_callers = set()
    for item in reviewed:
        if not isinstance(item, dict):
            raise ValueError(
                "Caller evidence must name a source path, SHA256, and assessment"
            )
        relative = _text(item.get("path"), "Reviewed caller path")
        path = resolve_inside(root, relative)
        if (
            path is None
            or path.suffix.lower() not in SOURCE_SUFFIXES
            or not path.is_file()
        ):
            raise ValueError(
                "Reviewed caller must be an existing source file inside the checkout"
            )
        contents = _read_bounded(path, MAX_SOURCE_BYTES)
        if hashlib.sha256(contents).hexdigest() != item.get("sha256"):
            raise ValueError("Reviewed caller source changed or its SHA256 is missing")
        _text(item.get("assessment"), "Caller API assessment")
        canonical = path.relative_to(root.resolve()).as_posix()
        reviewed_paths.add(canonical)
        if "node_modules" in path.parts and _package_reference(plan["package"]).search(
            contents.decode("utf-8")
        ):
            dependency_callers.add(canonical)
    if not {item["path"] for item in scan["references"]}.issubset(reviewed_paths):
        raise ValueError("Review every source reference identified by the caller scan")
    if (
        plan.get("ecosystem") == "npm"
        and plan.get("strategy") == "override"
        and not dependency_callers
    ):
        raise ValueError(
            "Transitive npm major updates require installed dependency caller source review"
        )
    return {"scan": scan, "evidence": evidence}


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


def reviewed_license_policy(root: Path, plan: dict, review: dict) -> dict:
    """Use documented license terms without inventing corporate approval."""
    license_review = review.get("license")
    if not isinstance(license_review, dict):
        raise ValueError(
            "No corporate policy is configured. Provide review.license with expression, "
            "official sources, commercial_use_permitted=true, no_license_fees=true, "
            "obligations, and assessment. No corporate approval file is required."
        )
    for key in ("expression", "obligations", "assessment"):
        _text(license_review.get(key), f"License {key}")
    if license_review["expression"].strip().upper() in {
        "UNLICENSED",
        "UNKNOWN",
        "NOASSERTION",
        "NONE",
    }:
        raise ValueError("Unknown or unlicensed terms cannot qualify a package update")
    _sources(license_review.get("sources"), "Official target-version license terms")
    if (
        license_review.get("commercial_use_permitted") is not True
        or license_review.get("no_license_fees") is not True
    ):
        raise ValueError(
            "Reviewed license terms must permit commercial use without license fees"
        )
    if plan.get("manager") in {"npm", "pnpm", "yarn"}:
        entry = next(
            (
                path
                for path in plan.get("files", [])
                if Path(path).name
                in {"pnpm-lock.yaml", "yarn.lock", "package-lock.json"}
            ),
            next(iter(plan.get("files", [])), "package.json"),
        )
        resolved = resolve_inside(root, entry)
        if resolved is None:
            raise ValueError("Package checks must stay inside the checkout")
        manifest = resolve_inside(root, resolved.parent / "package.json")
        if manifest is None:
            raise ValueError("Package manifest must stay inside the checkout")
        scripts = json_object(
            _read_bounded(manifest, MAX_SOURCE_BYTES).decode("utf-8")
        ).get("scripts", {})
        if not isinstance(scripts, dict) or any(
            not isinstance(scripts.get(kind), str) or not scripts[kind].strip()
            for kind in ("lint", "build", "test")
        ):
            raise ValueError(
                "Package updates require existing build and test scripts and a lint script; missing checks cannot count as passing"
            )
    fingerprint = {
        "mode": "documentation_review",
        "license": license_review,
        "package": plan.get("package"),
        "target": plan.get("target"),
        "ecosystem": plan.get("ecosystem"),
    }
    return {
        "approval": None,
        "policy_mode": "documentation_review",
        "license_review": license_review,
        "checks": {},
        "policy_sha256": hashlib.sha256(
            json.dumps(fingerprint, sort_keys=True).encode()
        ).hexdigest(),
    }


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
        "policy_mode": "corporate_policy",
        "checks": checks,
        "policy_sha256": hashlib.sha256(raw).hexdigest(),
    }


def run_checks(
    root: Path, checks: dict, runner, which, timeout: int, *, plan: dict | None = None
) -> list[dict]:
    """Require positive, untruncated success evidence from every check.

    Smoke checks must terminate and exercise product behavior. License
    checks must inspect the complete resolved dependency graph, including
    transitive packages and distribution obligations. Configure markers
    that prove actual checks ran rather than accepting empty test runs.
    Record expected execution errors per check; interrupts still propagate.
    """
    workdir = root
    if plan and plan.get("manager") in {"npm", "pnpm", "yarn"}:
        entry = next(
            (
                path
                for path in plan.get("files", [])
                if Path(path).name
                in {"pnpm-lock.yaml", "yarn.lock", "package-lock.json"}
            ),
            next(iter(plan.get("files", [])), "package.json"),
        )
        resolved = resolve_inside(root, entry)
        if resolved is None:
            raise ValueError(
                "Qualification working directory must stay inside the repository"
            )
        workdir = resolved.parent
    rows = []
    for kind in CHECK_KINDS:
        if kind not in checks:
            continue
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
                [tool, *check["argv"][1:]],
                timeout=timeout,
                check=False,
                **({"cwd": workdir} if workdir != root.resolve() else {}),
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


def backup_dependency_files(root: Path, plan: dict) -> dict[str, str | None]:
    """Retain bounded original dependency text, including possibly new lockfiles."""
    paths = set(plan.get("files") or [])
    manager = plan.get("manager")
    if manager in {"npm", "pnpm", "yarn"}:
        entry = next(
            (
                path
                for path in sorted(paths)
                if Path(path).name
                in {"pnpm-lock.yaml", "package-lock.json", "yarn.lock"}
            ),
            next(iter(sorted(paths)), "package.json"),
        )
        parent = Path(entry).parent
        paths.add((parent / "package.json").as_posix())
        paths.add(
            (
                parent
                / {
                    "npm": "package-lock.json",
                    "pnpm": "pnpm-lock.yaml",
                    "yarn": "yarn.lock",
                }[manager]
            ).as_posix()
        )
    originals = {}
    total = 0
    for relative in sorted(paths):
        path = resolve_inside(root, relative)
        if path is None or path.suffix.lower() in SOURCE_SUFFIXES:
            raise ValueError(
                "Package rollback backups must contain dependency files inside the repository, not production/unit-test code"
            )
        raw = _read_bounded(path, MAX_TREE_BYTES) if path.exists() else None
        total += len(raw) if raw is not None else 0
        if total > MAX_TREE_BYTES:
            raise ValueError(
                "Dependency rollback backup exceeds the qualification size limit"
            )
        originals[relative] = raw.decode("utf-8") if raw is not None else None
    return originals


def dependency_file_hashes(root: Path, paths: dict) -> dict[str, str | None]:
    """Fingerprint updater-owned files so rollback never overwrites later edits."""
    hashes = {}
    for relative in paths:
        path = resolve_inside(root, relative)
        if path is None:
            raise ValueError("Dependency file moved outside the repository")
        hashes[relative] = (
            hashlib.sha256(_read_bounded(path, MAX_TREE_BYTES)).hexdigest()
            if path.exists()
            else None
        )
    return hashes


def rollback_dependency_files(root: Path, receipt: dict) -> dict:
    """Restore only updater-owned dependency edits that still match their hashes."""
    restored, preserved = [], []
    originals = receipt.get("dependency_before")
    expected = receipt.get("applied_dependency_hashes")
    if not isinstance(originals, dict) or not isinstance(expected, dict):
        return {
            "status": "MANUAL_REVIEW_REQUIRED",
            "detail": "Rollback evidence is missing; dependency files were left untouched for manual review.",
        }
    for relative, original in originals.items():
        try:
            current = dependency_file_hashes(root, {relative: None})[relative]
            if relative not in expected or current != expected[relative]:
                preserved.append(relative)
                continue
            previous = (
                hashlib.sha256(original.encode("utf-8")).hexdigest()
                if original is not None
                else None
            )
            if current == previous:
                continue
            path = resolve_inside(root, relative)
            if path is None:
                raise ValueError("Dependency path moved outside the repository")
            if original is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write_text(path, original)
            restored.append(relative)
        except (OSError, ValueError, TypeError):
            preserved.append(relative)
    return {
        "status": "MANUAL_REVIEW_REQUIRED" if preserved else "ROLLED_BACK",
        "restored_files": restored,
        "preserved_files": preserved,
        "detail": "Package update rejected. Restored unchanged updater-owned dependency edits; production/unit-test and unrelated edits were not touched."
        + (
            " Later dependency edits were preserved; manual cleanup is required."
            if preserved
            else ""
        ),
    }


def validate_edits(
    root: Path,
    receipt: dict,
    allowed_files: list[str],
    *,
    expected_dependencies: dict | None = None,
) -> dict[str, str]:
    """Reject undeclared, oversized, or computationally costly migrations."""
    after = tree_snapshot(root)
    before = receipt["tree"]
    script_hashes = receipt.get(
        "package_script_hashes",
        receipt.get("plan", {}).get("caller_scan", {}).get("package_script_hashes", {}),
    )
    if package_script_hashes(root, after) != script_hashes and (
        script_hashes or any(Path(path).name == "package.json" for path in after)
    ):
        raise ValueError(
            "Package version updates cannot change package build/test scripts; requalification is required"
        )
    if receipt.get("source_before"):
        raise ValueError(
            "Package version updates cannot authorize production or unit-test code adaptations; requalify without source fixes"
        )
    changed = {
        path
        for path in before.keys() | after.keys()
        if before.get(path) != after.get(path)
    }
    if any(Path(path).suffix.lower() in SOURCE_SUFFIXES for path in changed):
        raise ValueError(
            "Package version update rejected: production or unit-test code changed; API adaptations are not permitted for any version increment"
        )
    expected = (
        receipt.get("applied_dependency_hashes", {})
        if expected_dependencies is None
        else expected_dependencies
    )
    if expected and dependency_file_hashes(root, expected) != expected:
        raise ValueError(
            "Dependency files changed beyond the applied version edit; production/test settings cannot be adapted to support an update"
        )
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
