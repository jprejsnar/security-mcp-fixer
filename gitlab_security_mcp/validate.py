"""Technology validation. Missing tools are skipped. Failing project checks fail the run."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from subprocess import SubprocessError
from xml.etree.ElementTree import ParseError

from gitlab_security_mcp.commands import (
    CommandResult,
    CommandRunner,
    resolve_tool,
    tool_name,
)
from gitlab_security_mcp.manifests import (
    StackInfo,
    _read_json,
    detect_stack,
    is_modern_yarn,
    iter_files,
    java_build_roots,
)
from gitlab_security_mcp.util import log_unexpected, parse_xml, read_bounded

_RAISE_PACKAGE_JSON_SCRIPTS_MUST_CONTAIN_NONEMPTY_COMMAND_STRINGS = (
    "package.json scripts must contain nonempty command strings"
)
_RAISE_JAVA_BUILD_DISCOVERY_WAS_TRUNCATED_MANUAL_REVIEW_IS = (
    "Java build discovery was truncated; manual review is required"
)
_RAISE_GRADLE_TEST_VALIDATION_REQUIRES_A_WORKING_DIRECTORY = (
    "Gradle test validation requires a working directory"
)
_RAISE_JUNIT_REPORT_EXCEEDS_10_MIB = "JUnit report exceeds 10 MiB: {}"
_RAISE_INVALID_JUNIT_REPORT = "Invalid JUnit report {}: {}"
_RAISE_JUNIT_REPORT_CONTAINS_FAILING_TESTS = "JUnit report contains failing tests: {}"
# Corporate proxies such as Nexus often reject the npm bulk-advisory endpoint.
_AUDIT_ENDPOINT_UNSUPPORTED_MARKERS = (
    "ERR_PNPM_AUDIT_BAD_RESPONSE",
    "audit endpoint returned an error",
)
_AUDIT_ENDPOINT_UNSUPPORTED_DETAIL = (
    "The configured registry rejected the advisory audit endpoint earlier in this "
    "server process; the informational audit is not repeated. GitLab findings remain "
    "the advisory source."
)
_audit_endpoint_unsupported: set[Path] = set()
_UNLOCKED_NODE_PROJECT = (
    "{} has no {}; this side library was not changed by package remediation and "
    "a locked install does not apply. Other Node projects in the checkout were validated."
)


def run_validation(
    root: Path,
    runner: CommandRunner,
    which: Callable[[str], str | None],
    *,
    timeout: int,
    package_checks: bool = False,
    record_lint: bool = False,
    skip_lint: bool = False,
    lint_only: bool = False,
) -> dict:
    """Run production builds and dependency checks without executing test suites."""
    try:
        return _run_validation(
            root,
            runner,
            which,
            timeout=timeout,
            package_checks=package_checks,
            record_lint=record_lint,
            skip_lint=skip_lint,
            lint_only=lint_only,
        )
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError) as exc:
        log_unexpected(exc, "validation matrix")
        return {
            "status": "VALIDATION_COMPLETE" if lint_only else "VALIDATION_FAILED",
            "detected": {},
            "results": [
                {
                    **_row(
                        None,
                        "FAILED",
                        not lint_only,
                        f"Validation could not complete: {exc}",
                    ),
                    **({"kind": "lint", "baseline_only": True} if lint_only else {}),
                }
            ],
        }


def _run_validation(
    root: Path,
    runner: CommandRunner,
    which: Callable[[str], str | None],
    *,
    timeout: int,
    package_checks: bool = False,
    record_lint: bool = False,
    skip_lint: bool = False,
    lint_only: bool = False,
) -> dict:
    """Aggregate stack checks without hiding required failures or skips."""
    files, _truncated = iter_files(root)
    stack = detect_stack(root, files)
    results: list[dict] = []
    if not lint_only:
        results.extend(_versions(runner, which, stack, timeout))
    if stack.node:
        node_roots = sorted(
            {path.parent for path in files if path.name == "package.json"}
        )
        components = []
        for component in node_roots:
            if any(parent in node_roots for parent in component.parents):
                continue
            component_files = [path for path in files if path.is_relative_to(component)]
            components.append((component, detect_stack(component, component_files)))
        locked = {
            component
            for component, component_stack in components
            if _node_commands(component, component_stack)[0].is_file()
        }
        for component, component_stack in components:
            results.extend(
                _node(
                    component,
                    component_stack,
                    runner,
                    which,
                    timeout,
                    package_checks=package_checks,
                    record_lint=record_lint,
                    skip_lint=skip_lint,
                    lint_only=lint_only,
                    skip_unlocked=bool(locked - {component}),
                )
            )
    if stack.dotnet:
        solutions = {
            path.parent for path in files if path.suffix.lower() in {".sln", ".slnx"}
        }
        projects = {
            path.parent
            for path in files
            if path.suffix.lower() in {".csproj", ".fsproj", ".vbproj"}
        }
        dotnet_roots = solutions | {
            path
            for path in projects
            if not any(path.is_relative_to(solution) for solution in solutions)
        }
        for component in sorted(dotnet_roots):
            component_files = [path for path in files if path.is_relative_to(component)]
            results.extend(
                _dotnet(
                    component,
                    component_files,
                    runner,
                    which,
                    timeout,
                    package_checks=package_checks,
                    skip_lint=skip_lint,
                    lint_only=lint_only,
                )
            )
    if stack.java:
        results.extend(
            _java(
                root,
                stack,
                runner,
                which,
                timeout,
                package_checks=package_checks,
                skip_lint=skip_lint,
                lint_only=lint_only,
            )
        )
    if stack.nginx_configs and not lint_only:
        results.extend(_nginx(root, stack, runner, which, timeout))
    if stack.dockerfiles and not lint_only:
        results.extend(_docker(root, stack, runner, which, timeout))
    if not any(
        [stack.node, stack.dotnet, stack.java, stack.nginx_configs, stack.dockerfiles]
    ):
        results.append(
            {
                "command": None,
                "status": "SKIPPED",
                "required": False,
                "detail": "No Node, .NET, Java, NGINX, or container stack was detected. Manual validation is required.",
            }
        )
    if package_checks:
        present = {row.get("kind") for row in results}
        kinds = (
            ("lint",) if lint_only else (("build",) if skip_lint else ("lint", "build"))
        )
        for kind in kinds:
            if kind not in present:
                row = _row(
                    None,
                    "SKIPPED",
                    True,
                    f"Required {kind} check was not detected or did not run; package update cannot be accepted.",
                )
                row["kind"] = kind
                results.append(row)
    if record_lint or lint_only:
        for row in results:
            if lint_only:
                row.setdefault("kind", "lint")
            if row.get("kind") == "lint":
                row["required"] = False
                row["baseline_only"] = True
    failed = any(
        item["status"] == "FAILED" and item.get("required", True) for item in results
    )
    incomplete = any(
        item["status"] == "SKIPPED" and item.get("required", True) for item in results
    )
    return {
        "status": "VALIDATION_FAILED"
        if failed
        else "VALIDATION_INCOMPLETE"
        if incomplete
        else "VALIDATION_COMPLETE",
        "detected": {
            "node": stack.node_manager if stack.node else None,
            "dotnet": stack.target_frameworks or None,
            "java": (
                stack.java_builds
                if stack.java_builds and len(stack.java_builds) > 1
                else stack.java_build
            )
            if stack.java
            else None,
            "nginx": stack.nginx_configs or None,
            "docker": stack.dockerfiles or None,
        },
        "results": results,
        "test_execution": "DISABLED: remediation runs production builds and dependency checks, not unit/integration tests.",
    }


def _versions(runner, which, stack: StackInfo, timeout: int) -> list[dict]:
    """Probe runtimes and enforce Java 17+ and net10.0 SDK requirements."""
    probes = []
    if stack.node:
        probes.append(("node", ["--version"]))
    if stack.dotnet:
        probes.append(("dotnet", ["--version"]))
    if stack.java:
        probes.append(("java", ["-version"]))
    found = []
    for name, args in probes:
        tool = resolve_tool(name, which)
        if not tool:
            found.append(_row(None, "SKIPPED", True, f"{name} is not on PATH."))
            continue
        result = runner.run([tool, *args], timeout=min(timeout, 60), check=False)
        text = (result.stdout or result.stderr).strip()
        detail = text.splitlines()[0] if text else f"exit {result.exit_code}"
        requires_net10 = name == "dotnet" and any(
            re.match(r"net10\.0(?:-|$)", item) for item in stack.target_frameworks or []
        )
        compatible = True
        if name == "java" and not _java_major(text, 17):
            compatible = False
            detail = (
                f"{detail}. Java 17 or newer is required for this validation matrix."
            )
        if requires_net10:
            sdk = re.match(r"(\d+)\.\d+\.\d+", text)
            if sdk is None or int(sdk.group(1)) < 10:
                compatible = False
                detail = (
                    f"{detail}. A .NET SDK 10 or newer is required for net10.0 targets."
                )
        if (
            name == "dotnet"
            and stack.target_frameworks
            and not any("net10" in item for item in stack.target_frameworks)
        ):
            detail = f"{detail}. Project target frameworks: {', '.join(stack.target_frameworks)}."
        found.append(
            _row(
                result,
                "PASSED" if result.exit_code == 0 and compatible else "FAILED",
                name == "java" or requires_net10,
                detail,
            )
        )
    return found


def _java_major(text: str, expected: int) -> bool:
    """Require a readable Java version meeting the minimum major."""
    match = re.search(r'version "(?P<major>\d+)', text)
    if not match:
        return False
    return int(match.group("major")) >= expected


def _prepare_node(
    runner, tool: str, install: list[str], audit: list[str], timeout: int, root: Path
) -> list[dict]:
    """Run one locked install, then one informational audit."""
    install_row = _run(runner, [tool, *install], timeout, required=True, cwd=root)
    if root in _audit_endpoint_unsupported:
        audit_row = _row(None, "SKIPPED", False, _AUDIT_ENDPOINT_UNSUPPORTED_DETAIL)
        audit_row["cwd"] = str(root)
        return [install_row, audit_row]
    audit_row = _run(
        runner,
        [tool, *audit],
        timeout,
        required=False,
        informational=True,
        cwd=root,
    )
    if audit_row["status"] == "INFORMATIONAL" and any(
        marker in audit_row["detail"] for marker in _AUDIT_ENDPOINT_UNSUPPORTED_MARKERS
    ):
        _audit_endpoint_unsupported.add(root)
    return [install_row, audit_row]


def _node_commands(root: Path, stack: StackInfo) -> tuple[Path, list[str], list[str]]:
    """Return the manager's lockfile, frozen-install and audit arguments."""
    manager = stack.node_manager or "npm"
    if manager == "npm":
        lock = root / "package-lock.json"
        if not lock.is_file():
            lock = root / "npm-shrinkwrap.json"
        return lock, ["ci", "--ignore-scripts"], ["audit", "--json"]
    if manager == "pnpm":
        return (
            root / "pnpm-lock.yaml",
            ["install", "--frozen-lockfile", "--ignore-scripts"],
            ["audit", "--json"],
        )
    if is_modern_yarn(root):
        return (
            root / "yarn.lock",
            ["install", "--immutable", "--mode=skip-build"],
            ["npm", "audit", "--json"],
        )
    return (
        root / "yarn.lock",
        ["install", "--frozen-lockfile", "--ignore-scripts"],
        ["audit", "--json"],
    )


def _node(
    root: Path,
    stack: StackInfo,
    runner,
    which,
    timeout: int,
    *,
    package_checks: bool = False,
    record_lint: bool = False,
    skip_lint: bool = False,
    lint_only: bool = False,
    skip_unlocked: bool = False,
) -> list[dict]:
    """Install locked Node dependencies, then run declared project checks.

    With skip_unlocked, a project without its manager's lockfile is skipped as a
    side library: package remediation always writes the lockfile it updates, so
    an unlocked project beside locked ones was not changed and cannot `npm ci`.
    """
    manager = stack.node_manager or "npm"
    data = _read_json(root / "package.json") or {}
    scripts = data.get("scripts", {})
    if any(
        not isinstance(script, str) or not script.strip() for script in scripts.values()
    ):
        raise ValueError(
            _RAISE_PACKAGE_JSON_SCRIPTS_MUST_CONTAIN_NONEMPTY_COMMAND_STRINGS
        )
    tool = resolve_tool(manager, which)
    if not tool:
        return [_row(None, "SKIPPED", True, f"{manager} is not on PATH.")]
    if lint_only:
        row = (
            _execute_product_check(runner, [tool, "run", "lint"], timeout, root, "lint")
            if "lint" in scripts
            else _row(
                None,
                "SKIPPED",
                False,
                "No lint script; informational capture unavailable.",
            )
        )
        row.update(kind="lint", cwd=str(root), required=False, baseline_only=True)
        return [row]
    lock, install, audit = _node_commands(root, stack)
    if skip_unlocked and not lock.is_file():
        row = _row(
            None, "SKIPPED", False, _UNLOCKED_NODE_PROJECT.format(root, lock.name)
        )
        row["cwd"] = str(root)
        return [row]
    rows = _prepare_node(runner, tool, install, audit, timeout, root)
    if rows[0]["status"] == "FAILED":
        rows.append(
            _row(
                None,
                "SKIPPED",
                False,
                "Skipped lint and build because install failed.",
            )
        )
        return rows
    blocked = None
    for script in ("lint", "build"):
        kind = script
        if kind == "lint" and skip_lint:
            continue
        if blocked is not None:
            row = _row(
                None,
                "SKIPPED",
                True,
                f"Not run because the required {blocked} check did not pass; validation stopped early.",
            )
            row["kind"] = kind
            row["cwd"] = str(root)
            rows.append(row)
            continue
        if script not in scripts:
            row = _row(
                None,
                "SKIPPED",
                package_checks and not (record_lint and kind == "lint"),
                f"{root / 'package.json'} has no {script} script; "
                + (
                    "informational lint capture unavailable."
                    if record_lint and kind == "lint"
                    else "configure this check before qualifying a package update."
                ),
            )
            row["kind"] = kind
            rows.append(row)
            if row["required"]:
                blocked = kind
            continue
        argv = [tool, "test"] if script == "test" else [tool, "run", script]
        row = _execute_product_check(runner, argv, timeout, root, kind)
        if record_lint and kind == "lint":
            row["required"] = False
            row["baseline_only"] = True
        row["cwd"] = str(root)
        rows.append(row)
        if row["status"] != "PASSED" and row.get("required", True):
            blocked = kind
    return rows


def _dotnet(
    root: Path,
    files: list[Path],
    runner,
    which,
    timeout: int,
    *,
    package_checks: bool = False,
    skip_lint: bool = False,
    lint_only: bool = False,
) -> list[dict]:
    """Restore NuGet dependencies and build Release without running tests."""
    tool = resolve_tool("dotnet", which)
    if not tool:
        return [_row(None, "SKIPPED", True, "dotnet is not on PATH.")]
    if lint_only:
        return [
            _execute_product_check(
                runner,
                [tool, "format", "--verify-no-changes", "--no-restore"],
                timeout,
                root,
                "lint",
            )
        ]
    locked = any(path.name == "packages.lock.json" for path in files)
    restore_args = [tool, "restore", "--locked-mode"] if locked else [tool, "restore"]
    restore = _run(runner, restore_args, timeout, required=True, cwd=root)
    rows = [restore]
    if restore["status"] == "FAILED":
        rows.append(
            _row(None, "SKIPPED", False, "Skipped build because restore failed.")
        )
        return rows
    if package_checks and not skip_lint:
        rows.append(
            _execute_product_check(
                runner,
                [tool, "format", "--verify-no-changes", "--no-restore"],
                timeout,
                root,
                "lint",
            )
        )
    rows.append(
        _run(
            runner,
            [tool, "build", "--configuration", "Release", "--nologo"],
            timeout,
            required=True,
            cwd=root,
        )
    )
    return rows


def _java(
    root: Path,
    stack: StackInfo,
    runner,
    which,
    timeout: int,
    *,
    package_checks: bool = False,
    skip_lint: bool = False,
    lint_only: bool = False,
) -> list[dict]:
    """Validate every detected Maven and Gradle build, wrappers first."""
    builds = list(stack.java_builds or [])
    if not builds and stack.java_build:
        builds = [stack.java_build]
    rows: list[dict] = []
    files, truncated = iter_files(root)
    if truncated:
        raise ValueError(_RAISE_JAVA_BUILD_DISCOVERY_WAS_TRUNCATED_MANUAL_REVIEW_IS)
    for build in builds:
        for component in java_build_roots(root, build, files):
            if build == "gradle":
                rows.extend(
                    _java_gradle(
                        component,
                        runner,
                        which,
                        timeout,
                        package_checks=package_checks,
                        skip_lint=skip_lint,
                        lint_only=lint_only,
                        checkout_root=root,
                    )
                )
            elif build == "maven":
                rows.extend(
                    _java_maven(
                        component,
                        runner,
                        which,
                        timeout,
                        package_checks=package_checks,
                        skip_lint=skip_lint,
                        lint_only=lint_only,
                        checkout_root=root,
                    )
                )
    return rows


def _java_gradle(
    root: Path,
    runner,
    which,
    timeout: int,
    *,
    package_checks: bool = False,
    skip_lint: bool = False,
    lint_only: bool = False,
    checkout_root: Path | None = None,
) -> list[dict]:
    """Run the Gradle wrapper or the installed Gradle tool."""
    wrapper = java_wrapper(root, checkout_root or root, "gradlew")
    tool = wrapper or resolve_tool("gradle", which)
    if not tool:
        return [_row(None, "SKIPPED", True, "gradlew or gradle is not available.")]
    if lint_only:
        return [
            _execute_product_check(
                runner,
                [tool, "--no-daemon", "checkstyleMain", "checkstyleTest"],
                timeout,
                root,
                "lint",
            )
        ]
    rows = []
    if package_checks and not skip_lint:
        rows.append(
            _execute_product_check(
                runner,
                [tool, "--no-daemon", "checkstyleMain", "checkstyleTest"],
                timeout,
                root,
                "lint",
            )
        )
    rows.append(
        _execute_product_check(
            runner,
            [tool, "--no-daemon", "assemble", "-x", "test"],
            timeout,
            root,
            "build",
        )
    )
    return rows


def _java_maven(
    root: Path,
    runner,
    which,
    timeout: int,
    *,
    package_checks: bool = False,
    skip_lint: bool = False,
    lint_only: bool = False,
    checkout_root: Path | None = None,
) -> list[dict]:
    """Run the Maven wrapper or the installed Maven tool."""
    wrapper = java_wrapper(root, checkout_root or root, "mvnw")
    tool = wrapper or resolve_tool("mvn", which)
    if not tool:
        return [_row(None, "SKIPPED", True, "mvnw or mvn is not available.")]
    lint = []
    if lint_only or (package_checks and not skip_lint):
        lint.append(
            _execute_product_check(
                runner,
                [
                    tool,
                    "--batch-mode",
                    "checkstyle:check",
                    "-Dcheckstyle.includeTestSourceDirectory=true",
                ],
                timeout,
                root,
                "lint",
            )
        )
    if lint_only:
        return lint
    rows = [
        _execute_product_check(
            runner,
            [tool, "--batch-mode", "clean", "package", "-Dmaven.test.skip=true"],
            timeout,
            root,
            "build",
        )
    ]
    rows.append(
        _execute_product_check(
            runner,
            [tool, "--batch-mode", "dependency:tree"],
            timeout,
            root,
            "dependency_tree",
        )
    )
    return lint + rows


def _nginx(root: Path, stack: StackInfo, runner, which, timeout: int) -> list[dict]:
    """Check detected NGINX configuration files when the tool is present."""
    tool = resolve_tool("nginx", which)
    if not tool:
        return [
            _row(
                None, "SKIPPED", False, "nginx is not on PATH. Config was not executed."
            )
        ]
    rows = []
    for rel in stack.nginx_configs or []:
        rows.append(
            _run(
                runner,
                [tool, "-t", "-c", str((root / rel).resolve())],
                min(timeout, 60),
                required=True,
            )
        )
    return rows


def _docker(root: Path, stack: StackInfo, runner, which, timeout: int) -> list[dict]:
    """Check FROM instructions and use Docker build checks when available."""
    rows = []
    for rel in stack.dockerfiles or []:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        if not re.search(r"^FROM\s+\S+", text, re.IGNORECASE | re.MULTILINE):
            rows.append(_row(None, "FAILED", True, f"{rel} has no FROM instruction."))
        else:
            rows.append(_row(None, "PASSED", True, f"{rel} has a FROM instruction."))
    tool = resolve_tool("docker", which)
    if not tool:
        rows.append(
            _row(
                None,
                "SKIPPED",
                False,
                "docker is not on PATH. Image build check was not run.",
            )
        )
        return rows
    dockerfile = stack.dockerfiles[0]
    result = runner.run(
        [tool, "build", "--check", "-f", dockerfile, "."],
        timeout=timeout,
        check=False,
        cwd=root,
    )
    text = (result.stderr + result.stdout).lower()
    if result.exit_code != 0 and any(
        token in text
        for token in (
            "unknown flag",
            "cannot connect",
            "docker daemon",
            "npipe",
            "permission denied",
        )
    ):
        rows.append(
            _row(result, "SKIPPED", False, "Docker build check is unavailable.")
        )
    else:
        rows.append(_run_result(result, required=True))
    return rows


def java_wrapper(component: Path, checkout_root: Path, name: str) -> str | None:
    """Find the nearest Java wrapper without searching outside the checkout."""
    component = component.resolve()
    checkout_root = checkout_root.resolve()
    component.relative_to(checkout_root)
    for directory in (component, *component.parents):
        wrapper = _wrapper(directory, name)
        if wrapper:
            return wrapper
        if directory == checkout_root:
            break
    return None


def _wrapper(root: Path, name: str) -> str | None:
    """Find a build wrapper, preferring Windows command-file extensions."""
    if os.name == "nt":
        candidate = root / f"{name}.cmd"
        if candidate.exists():
            return str(candidate)
        bat = root / f"{name}.bat"
        if bat.exists():
            return str(bat)
    candidate = root / name
    return str(candidate) if candidate.exists() else None


def _run(
    runner,
    argv: list[str],
    timeout: int,
    *,
    required: bool,
    informational: bool = False,
    cwd: Path | None = None,
) -> dict:
    """Run one allowlisted check and convert its exit code to a row."""
    if required and "test" in argv:
        return _execute_product_check(runner, argv, timeout, cwd, "unit_tests")
    if required and "build" in argv:
        return _execute_product_check(runner, argv, timeout, cwd, "build")
    if required and "verify" in argv:
        return _execute_product_check(
            runner, argv, timeout, cwd, "build_and_unit_tests"
        )
    options = {"cwd": cwd} if cwd is not None else {}
    try:
        result = runner.run(argv, timeout=timeout, check=False, **options)
    except (OSError, ValueError, RuntimeError, SubprocessError) as exc:
        row = _row(None, "FAILED", required, f"Check could not execute: {exc}")
        row["command"] = argv
        return row
    return _run_result(result, required=required, informational=informational)


def _execute_product_check(
    runner, argv: list[str], timeout: int, cwd: Path | None, kind: str
) -> dict:
    """Keep earlier diagnostics when an individual product command cannot start."""
    gradle_tests = kind in {"unit_tests", "build_and_unit_tests"} and tool_name(
        argv[0]
    ) in {"gradle", "gradlew"}
    reports = _gradle_test_reports(cwd) if gradle_tests else {}
    try:
        result = runner.run(
            argv,
            timeout=timeout,
            check=False,
            **({"cwd": cwd} if cwd is not None else {}),
        )
    except (OSError, ValueError, RuntimeError, SubprocessError) as exc:
        row = _row(None, "FAILED", True, f"{kind} check could not execute: {exc}")
        row.update(command=argv, kind=kind, output_complete=False)
        return row
    row = _lint_result(result) if kind == "lint" else _product_result(result, kind)
    if cwd is not None:
        row["cwd"] = str(cwd)
    if gradle_tests and result.exit_code == 0:
        count = _executed_gradle_tests(cwd, reports)
        if count and not row.get("reported_test_failures"):
            result.unit_tests_verified = True
            row.update(
                status="PASSED",
                detail=f"Gradle JUnit reports confirm {count} executed tests.",
            )
    if kind == "lint" and (result.exit_code == 124 or result.exit_code < 0):
        row["output_complete"] = False
    return row


def _gradle_test_reports(root: Path | None) -> dict[Path, tuple[int, int]]:
    """Fingerprint standard Gradle JUnit reports before running the test task."""
    if root is None:
        raise ValueError(_RAISE_GRADLE_TEST_VALIDATION_REQUIRES_A_WORKING_DIRECTORY)
    pattern = os.path.join("**", "build", "test-results", "test", "TEST-*.xml")
    return {
        path: (stat.st_mtime_ns, stat.st_size)
        for path in root.glob(pattern)
        if (stat := path.stat())
    }


def _executed_gradle_tests(
    root: Path | None, before: dict[Path, tuple[int, int]]
) -> int:
    """Require fresh, nonempty, successful JUnit evidence, not stale build artifacts."""
    count = 0
    for path, stamp in _gradle_test_reports(root).items():
        if before.get(path) == stamp:
            continue
        if stamp[1] > 10 * 1024 * 1024:
            raise ValueError(_RAISE_JUNIT_REPORT_EXCEEDS_10_MIB.format(path))
        try:
            contents = read_bounded(path, 10 * 1024 * 1024)
            if contents is None:
                raise ValueError(_RAISE_JUNIT_REPORT_EXCEEDS_10_MIB.format(path))
            report = parse_xml(contents)
        except ParseError as exc:
            raise ValueError(_RAISE_INVALID_JUNIT_REPORT.format(path, exc)) from exc
        for suite in report.iter("testsuite"):
            tests = int(suite.get("tests", "0"))
            skipped = int(suite.get("skipped", "0"))
            if int(suite.get("failures", "0")) or int(suite.get("errors", "0")):
                raise ValueError(
                    _RAISE_JUNIT_REPORT_CONTAINS_FAILING_TESTS.format(path)
                )
            count += max(0, tests - skipped)
    return count


def _run_result(
    result: CommandResult, *, required: bool, informational: bool = False
) -> dict:
    """Classify command output without making advisory audits fatal."""
    if result.exit_code == 0:
        status = "PASSED"
    elif informational:
        status = "INFORMATIONAL"
    else:
        status = "FAILED"
    detail = (result.stderr or result.stdout).strip()
    if result.truncated:
        detail = (
            (detail[:400] + " (output truncated)") if detail else "output truncated"
        )
    return _row(result, status, required and not informational, detail[:500])


def _lint_result(result: CommandResult) -> dict:
    """Retain all emitted lint diagnostics; incomplete evidence cannot pass."""
    row = _product_result(result, "lint")
    diagnostics = {kind: [] for kind in ("errors", "warnings", "info", "unknown")}
    for stream in (result.stdout, result.stderr):
        try:
            reports = json.loads(stream)
        except (ValueError, TypeError):
            reports = None
        if isinstance(reports, list) and all(
            isinstance(report, dict) and isinstance(report.get("messages"), list)
            for report in reports
        ):
            for report in reports:
                for message in report["messages"]:
                    severity = (
                        message.get("severity") if isinstance(message, dict) else None
                    )
                    kind = (
                        {2: "errors", 1: "warnings", 0: "info"}.get(severity, "unknown")
                        if isinstance(severity, (int, str))
                        else "unknown"
                    )
                    diagnostics[kind].append(
                        {"file": report.get("filePath"), "message": message}
                    )
        else:
            for line in stream.splitlines():
                if not line.strip():
                    continue
                classified = re.sub(
                    r"\b0\s+(?:errors?|warnings?)\b", "", line, flags=re.IGNORECASE
                )
                match = re.search(
                    r"(?<![\w./\\-])(errors?|warnings?|warn|info|information)(?![\w./\\-])",
                    classified,
                    re.IGNORECASE,
                )
                kind = (
                    {
                        "error": "errors",
                        "errors": "errors",
                        "warning": "warnings",
                        "warnings": "warnings",
                        "warn": "warnings",
                        "info": "info",
                        "information": "info",
                    }.get(match.group(1).lower(), "unknown")
                    if match
                    else "unknown"
                )
                diagnostics[kind].append(line)
    row["diagnostics"] = diagnostics
    if diagnostics["errors"]:
        row["status"] = "FAILED"
        row["detail"] = "Lint reported errors."
    return row


def lint_rule_inventory(rows: list[dict]) -> dict:
    """List observed rule IDs without changing the project's linter configuration."""
    rules: dict[str, dict] = {}
    patterns = (
        r"^\s*\d+:\d+\s+(?:error|warning)\s+.*?\s{2,}([@\w][\w@./-]*)\s*$",
        r"\[(?:Error|Warning)/([^\]\s]+)\]\s*$",
        r"\b(?:error|warning|info)\s+([A-Za-z]+\d+)\s*:",
        r"^\[?(?:ERROR|WARN|INFO)\]?.+\s\[([A-Za-z][\w.]*)\]\s*$",
    )
    lint_rows = [row for row in rows if row.get("kind") == "lint"]
    for row in lint_rows:
        for severity, diagnostics in row.get("diagnostics", {}).items():
            for diagnostic in diagnostics:
                rule = None
                if isinstance(diagnostic, dict):
                    message = diagnostic.get("message")
                    if isinstance(message, dict):
                        rule = message.get("ruleId")
                elif isinstance(diagnostic, str):
                    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", diagnostic)
                    for pattern in patterns:
                        match = re.search(pattern, text)
                        if match:
                            rule = match.group(1)
                            break
                if not isinstance(rule, str) or not rule.strip():
                    continue
                entry = rules.setdefault(rule, {"occurrences": 0, "severities": []})
                entry["occurrences"] += 1
                if severity not in entry["severities"]:
                    entry["severities"].append(severity)
    return {
        "schema_version": 1,
        "source": ".security-mcp/lint-issues.json",
        "informational_only": True,
        "complete": bool(lint_rows)
        and all(row.get("output_complete", False) for row in lint_rows),
        "rule_names": sorted(rules),
        "rules": {name: rules[name] for name in sorted(rules)},
    }


def _product_result(result: CommandResult, kind: str) -> dict:
    """Judge product exits and empty test runs, not the size of their output."""
    row = _run_result(result, required=True)
    row.update(
        kind=kind,
        stdout=result.stdout,
        stderr=result.stderr,
        output_complete=not result.truncated,
    )
    if result.truncated and kind == "lint":
        row.update(
            status="FAILED",
            detail=f"{kind} output is truncated; "
            + (
                "available diagnostics are retained."
                if kind == "lint"
                else "complete diagnostics are required before accepting a package update."
            ),
        )
    elif kind in {"unit_tests", "build_and_unit_tests"}:
        output = result.stdout + result.stderr
        counts = re.findall(
            r"(?:passed:|succeeded:|\bpass)\s*(\d+)|"
            r"(\d+)\s+(?:tests?\s+(?:completed|passed)|passing\b)|"
            r"\bTests:?[^\r\n]*?\b(\d+)\s+passed",
            output,
            re.IGNORECASE,
        )
        executed = result.unit_tests_verified or any(
            int(count) > 0 for groups in counts for count in groups if count
        )
        for summary in re.finditer(
            r"Tests run:\s*(\d+)([^\r\n]*)", output, re.IGNORECASE
        ):
            skipped = re.search(r"Skipped:\s*(\d+)", summary[2], re.IGNORECASE)
            executed |= int(summary[1]) > (int(skipped[1]) if skipped else 0)
        failures = re.search(
            r"\b(?:failed|failures|errors|cancelled|canceled):\s*[1-9]\d*\b|"
            r"\b(?:Tests?|Test Suites):?[^\r\n]*\b[1-9]\d*\s+failed\b|"
            r"\b(?:fail|cancelled|canceled)\s+[1-9]\d*\b",
            output,
            re.IGNORECASE,
        )
        if failures:
            row.update(
                status="FAILED",
                reported_test_failures=True,
                detail="Unit-test output reports failures despite the command exit code.",
            )
        elif not executed:
            row.update(
                status="FAILED",
                detail="Unit tests did not run; a successful exit without executed tests is not passing evidence.",
            )
        elif result.exit_code == 0:
            result.unit_tests_verified = True
    if result.exit_code != 0:
        tail = (result.stderr or result.stdout).strip()[-2000:]
        logs = ", ".join(
            path for path in (result.stdout_log_path, result.stderr_log_path) if path
        )
        row["detail"] = (
            f"{kind} command {result.display()} exited {result.exit_code}. {tail}"
            + (f" Full output: {logs}" if logs else "")
        )
    elif result.truncated and row["status"] == "PASSED":
        row["detail"] = (
            f"{kind} command exited 0; only its in-memory output preview was clipped."
        )
    return row


def _row(
    result: CommandResult | None, status: str, required: bool, detail: str
) -> dict:
    """Build a JSON-safe check row with hashes and optional command data."""
    return {
        "command": result.display() if result else None,
        "exit_code": result.exit_code if result else None,
        "status": status,
        "required": required,
        "detail": detail,
        "stdout_sha256": result.stdout_sha256 if result else None,
        "stderr_sha256": result.stderr_sha256 if result else None,
        "stdout_log_path": result.stdout_log_path if result else None,
        "stderr_log_path": result.stderr_log_path if result else None,
    }
