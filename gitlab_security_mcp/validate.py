"""Technology validation. Missing tools are skipped. Failing project checks fail the run."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path

from gitlab_security_mcp.commands import CommandResult, CommandRunner, resolve_tool
from gitlab_security_mcp.manifests import (
    StackInfo,
    _read_json,
    detect_stack,
    is_modern_yarn,
    iter_files,
)


def run_validation(
    root: Path,
    runner: CommandRunner,
    which: Callable[[str], str | None],
    *,
    timeout: int,
) -> dict:
    """Run detected stack checks and return required failures and skipped tools."""
    try:
        return _run_validation(root, runner, which, timeout=timeout)
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError) as exc:
        return {
            "status": "VALIDATION_FAILED",
            "detected": {},
            "results": [
                _row(None, "FAILED", True, f"Validation could not complete: {exc}")
            ],
        }


def _run_validation(
    root: Path,
    runner: CommandRunner,
    which: Callable[[str], str | None],
    *,
    timeout: int,
) -> dict:
    """Aggregate stack checks without hiding required failures or skips."""
    files, _truncated = iter_files(root)
    stack = detect_stack(root, files)
    results: list[dict] = []
    results.extend(_versions(runner, which, stack, timeout))
    if stack.node:
        node_roots = sorted(
            {path.parent for path in files if path.name == "package.json"}
        )
        for component in node_roots:
            if any(parent in node_roots for parent in component.parents):
                continue
            component_files = [path for path in files if path.is_relative_to(component)]
            component_stack = detect_stack(component, component_files)
            results.extend(_node(component, component_stack, runner, which, timeout))
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
            results.extend(_dotnet(component, component_files, runner, which, timeout))
    if stack.java:
        results.extend(_java(root, stack, runner, which, timeout))
    if stack.nginx_configs:
        results.extend(_nginx(root, stack, runner, which, timeout))
    if stack.dockerfiles:
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
            "java": stack.java_build if stack.java else None,
            "nginx": stack.nginx_configs or None,
            "docker": stack.dockerfiles or None,
        },
        "results": results,
    }


def _versions(runner, which, stack: StackInfo, timeout: int) -> list[dict]:
    """Probe runtimes and enforce Java 17 and net10.0 SDK requirements."""
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
            detail = f"{detail}. Expected Java 17 for this validation matrix."
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
    """Require a readable Java version matching the requested major."""
    match = re.search(r'version "(?P<major>\d+)', text)
    if not match:
        return False
    return int(match.group("major")) == expected


def _node(root: Path, stack: StackInfo, runner, which, timeout: int) -> list[dict]:
    """Install locked Node dependencies, then run declared project checks."""
    manager = stack.node_manager or "npm"
    data = _read_json(root / "package.json") or {}
    scripts = data.get("scripts", {})
    if any(
        not isinstance(script, str) or not script.strip() for script in scripts.values()
    ):
        raise ValueError("package.json scripts must contain nonempty command strings")
    tool = resolve_tool(manager, which)
    if not tool:
        return [_row(None, "SKIPPED", True, f"{manager} is not on PATH.")]
    rows = []
    if manager == "npm":
        rows.append(_run(runner, [tool, "ci"], timeout, required=True, cwd=root))
        rows.append(
            _run(
                runner,
                [tool, "audit", "--json"],
                timeout,
                required=False,
                informational=True,
                cwd=root,
            )
        )
    elif manager == "pnpm":
        rows.append(
            _run(
                runner,
                [tool, "install", "--frozen-lockfile"],
                timeout,
                required=True,
                cwd=root,
            )
        )
        rows.append(
            _run(
                runner,
                [tool, "audit", "--json"],
                timeout,
                required=False,
                informational=True,
                cwd=root,
            )
        )
    elif is_modern_yarn(root):
        rows.append(
            _run(
                runner,
                [tool, "install", "--immutable"],
                timeout,
                required=True,
                cwd=root,
            )
        )
        rows.append(
            _run(
                runner,
                [tool, "npm", "audit", "--json"],
                timeout,
                required=False,
                informational=True,
                cwd=root,
            )
        )
    else:
        rows.append(
            _run(
                runner,
                [tool, "install", "--frozen-lockfile"],
                timeout,
                required=True,
                cwd=root,
            )
        )
        rows.append(
            _run(
                runner,
                [tool, "audit", "--json"],
                timeout,
                required=False,
                informational=True,
                cwd=root,
            )
        )
    if rows[0]["status"] == "FAILED":
        rows.append(
            _row(
                None,
                "SKIPPED",
                False,
                "Skipped lint, build, and test because install failed.",
            )
        )
        return rows
    for script in ("lint", "build", "test"):
        if script not in scripts:
            rows.append(
                _row(None, "SKIPPED", False, f"package.json has no {script} script.")
            )
            continue
        if script == "test":
            rows.append(_run(runner, [tool, "test"], timeout, required=True, cwd=root))
        else:
            rows.append(
                _run(runner, [tool, "run", script], timeout, required=True, cwd=root)
            )
    return rows


def _dotnet(root: Path, files: list[Path], runner, which, timeout: int) -> list[dict]:
    """Restore NuGet dependencies and run Release build and test checks."""
    tool = resolve_tool("dotnet", which)
    if not tool:
        return [_row(None, "SKIPPED", True, "dotnet is not on PATH.")]
    locked = any(path.name == "packages.lock.json" for path in files)
    restore_args = [tool, "restore", "--locked-mode"] if locked else [tool, "restore"]
    restore = _run(runner, restore_args, timeout, required=True, cwd=root)
    rows = [restore]
    if restore["status"] == "FAILED":
        rows.append(
            _row(
                None, "SKIPPED", False, "Skipped build and test because restore failed."
            )
        )
        return rows
    rows.append(
        _run(
            runner,
            [tool, "build", "--configuration", "Release", "--nologo"],
            timeout,
            required=True,
            cwd=root,
        )
    )
    rows.append(
        _run(
            runner,
            [tool, "test", "--configuration", "Release", "--nologo"],
            timeout,
            required=True,
            cwd=root,
        )
    )
    return rows


def _java(root: Path, stack: StackInfo, runner, which, timeout: int) -> list[dict]:
    """Prefer repository wrappers for Maven or Gradle validation."""
    if stack.java_build == "gradle":
        wrapper = _wrapper(root, "gradlew")
        tool = wrapper or resolve_tool("gradle", which)
        if not tool:
            return [_row(None, "SKIPPED", True, "gradlew or gradle is not available.")]
        rows = [
            _run(runner, [tool, "--no-daemon", "dependencies"], timeout, required=True)
        ]
        if rows[0]["status"] == "FAILED":
            rows.append(
                _row(
                    None,
                    "SKIPPED",
                    False,
                    "Skipped Gradle test because dependencies failed.",
                )
            )
            return rows
        rows.append(_run(runner, [tool, "--no-daemon", "test"], timeout, required=True))
        rows.append(
            _run(runner, [tool, "--no-daemon", "build"], timeout, required=True)
        )
        return rows
    wrapper = _wrapper(root, "mvnw")
    tool = wrapper or resolve_tool("mvn", which)
    if not tool:
        return [_row(None, "SKIPPED", True, "mvnw or mvn is not available.")]
    rows = [
        _run(runner, [tool, "--batch-mode", "clean", "verify"], timeout, required=True)
    ]
    rows.append(
        _run(runner, [tool, "--batch-mode", "dependency:tree"], timeout, required=True)
    )
    return rows


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
    options = {"cwd": cwd} if cwd is not None else {}
    result = runner.run(argv, timeout=timeout, check=False, **options)
    return _run_result(result, required=required, informational=informational)


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
    }
