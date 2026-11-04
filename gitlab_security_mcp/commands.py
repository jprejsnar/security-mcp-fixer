"""Allowlisted command runner with timeouts, output caps, and hash audit logs."""

from __future__ import annotations

import codecs
import hashlib
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from gitlab_security_mcp.util import safe_token

FORBIDDEN_GIT = {
    "add",
    "commit",
    "push",
    "merge",
    "rebase",
    "reset",
    "tag",
    "clean",
    "stash",
    "cherry-pick",
    "revert",
    "am",
    "switch",
    "filter-branch",
    "update-ref",
    "gc",
    "prune",
}
PATH_TOOLS = {
    "git",
    "npm",
    "pnpm",
    "yarn",
    "dotnet",
    "mvn",
    "gradle",
    "java",
    "node",
    "nginx",
    "docker",
}
REPO_WRAPPERS = {"mvnw", "gradlew"}
ALLOWED_SCRIPTS = {
    "lint",
    "build",
    "test",
    "test:unit",
    "test:ci",
    "check",
    "security:smoke",
    "security:licenses",
}
_SECURITY_BRANCH = re.compile(r"^security-fixes-[A-Z][a-z]+-\d{2}-\d{4}$")
_READ_SIZE = 8192
progress_sink: ContextVar[Callable[[str], None] | None] = ContextVar(
    "security_mcp_progress", default=None
)


def tool_name(argv0: str) -> str:
    """Return the executable name without a Windows extension."""
    name = Path(argv0).name.lower()
    for suffix in (".cmd", ".exe", ".bat"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name


_SHELL_CHARS = "\r\n|&;<>`$"
# Windows runs .cmd and .bat files through cmd.exe, which also expands these.
_CMD_CHARS = _SHELL_CHARS + '%^"!()'


def _bad_argument(arg: str, *, batch: bool = False) -> bool:
    """Reject empty arguments and shell or batch expansion characters."""
    if arg == "":
        return True
    return any(char in arg for char in (_CMD_CHARS if batch else _SHELL_CHARS))


def _package_arg(value: str) -> bool:
    """Require a safe token before adding a package to command arguments."""
    try:
        safe_token(value, label="package")
    except ValueError:
        return False
    return True


def _version_spec(value: str) -> bool:
    """Validate a package name or name@version, including leading @ scopes."""
    if value.startswith("@") and value.count("@") == 1:
        return _package_arg(value)
    if "@" not in value:
        return _package_arg(value)
    name, version = value.rsplit("@", 1)
    return bool(name) and _package_arg(name) and _package_arg(version)


def _security_branch(name: str) -> bool:
    """Accept only the dated branch naming scheme owned by this server."""
    return bool(_SECURITY_BRANCH.fullmatch(name))


def _git_ok(args: list[str]) -> bool:
    """Allow exact Git operations without staging or publishing changes."""
    if not args or args[0] in FORBIDDEN_GIT:
        return False
    command, rest = args[0], args[1:]
    if command == "rev-parse":
        return rest in (
            ["--is-inside-work-tree"],
            ["HEAD"],
            ["--abbrev-ref", "HEAD"],
            ["--show-toplevel"],
            ["--git-dir"],
        )
    if command == "status":
        return rest == ["--porcelain=v1", "--untracked-files=all"]
    if command == "branch":
        if rest == ["--show-current"]:
            return True
        return len(rest) == 2 and rest[0] == "--list" and _security_branch(rest[1])
    if command == "diff":
        return rest in (
            ["--stat"],
            ["--name-only"],
            ["--cached", "--name-only"],
            ["--cached", "--stat"],
        )
    if command == "pull":
        return rest == ["--ff-only"]
    if command == "checkout":
        return len(rest) == 2 and rest[0] == "-b" and _security_branch(rest[1])
    if command == "ls-remote":
        return (
            len(rest) == 3
            and rest[0] == "--heads"
            and rest[1] == "origin"
            and _security_branch(rest[2])
        )
    return False


def _script_run(args: list[str]) -> bool:
    """Allow only known project check scripts rather than arbitrary names."""
    return len(args) == 2 and args[0] == "run" and args[1] in ALLOWED_SCRIPTS


def _npm_ok(args: list[str]) -> bool:
    """Allow npm checks and bounded dependency refresh operations."""
    if args in (
        ["--version"],
        ["ci"],
        ["test"],
        ["test", "--", "--listTests", "--json"],
        ["audit", "--json"],
        [
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ],
    ):
        return True
    if _script_run(args):
        return True
    if (
        len(args) == 5
        and args[0] == "update"
        and args[2:] == ["--ignore-scripts", "--no-audit", "--no-fund"]
    ):
        return _package_arg(args[1])
    return False


def _pnpm_ok(args: list[str]) -> bool:
    """Allow pnpm checks and script-free dependency refresh operations."""
    if args in (
        ["--version"],
        ["clean"],
        ["install"],
        ["install", "--frozen-lockfile"],
        ["install", "--lockfile-only", "--ignore-scripts"],
        ["test"],
        ["test", "--listTests", "--json"],
        ["audit", "--json"],
    ):
        return True
    if _script_run(args):
        return True
    if len(args) == 3 and args[0] == "update" and args[2] == "--ignore-scripts":
        return _package_arg(args[1])
    return False


def _yarn_ok(args: list[str]) -> bool:
    """Allow supported Classic and Berry checks and dependency refreshes."""
    if args in (
        ["--version"],
        ["install", "--frozen-lockfile"],
        ["install", "--immutable"],
        ["install", "--mode=update-lockfile"],
        ["install", "--ignore-scripts"],
        ["test"],
        ["test", "--listTests", "--json"],
        ["audit", "--json"],
        ["npm", "audit", "--json"],
    ):
        return True
    if _script_run(args):
        return True
    if len(args) == 3 and args[:2] == ["up", "-R"]:
        return _package_arg(args[2])
    if len(args) == 3 and args[0] == "upgrade" and args[2] == "--ignore-scripts":
        return _version_spec(args[1])
    return False


def _dotnet_ok(args: list[str]) -> bool:
    """Allow SDK probes, restores, and Release build or test commands."""
    prefix = ["test", "--configuration", "Release", "--nologo"]
    if args[: len(prefix)] == prefix and args[len(prefix) :] in [
        [flag, value]
        for category in ("SecurityRuntimeSmoke", "LicenseCompliance")
        for flag, value in (
            ("--filter", f"Category={category}"),
            ("--filter", f"TestCategory={category}"),
            ("--filter-trait", f"Category={category}"),
            ("--treenode-filter", f"/*/*/*/*[Category={category}]"),
        )
    ]:
        return True
    return args in (
        ["--version"],
        ["restore"],
        ["restore", "--locked-mode"],
        ["format", "--verify-no-changes", "--no-restore"],
        ["build", "--configuration", "Release", "--nologo"],
        ["test", "--configuration", "Release", "--nologo"],
    )


def _maven_ok(args: list[str]) -> bool:
    """Allow noninteractive Maven verification and dependency inspection."""
    return args in (
        ["--version"],
        ["--batch-mode", "clean", "verify"],
        ["--batch-mode", "dependency:tree"],
        [
            "--batch-mode",
            "checkstyle:check",
            "-Dcheckstyle.includeTestSourceDirectory=true",
        ],
        ["--batch-mode", "test"],
        ["--batch-mode", "-Psecurity-smoke", "verify"],
        ["--batch-mode", "-Psecurity-licenses", "verify"],
    )


def _gradle_ok(args: list[str]) -> bool:
    """Allow Gradle checks without leaving a build daemon running."""
    return args in (
        ["--version"],
        ["--no-daemon", "dependencies"],
        ["--no-daemon", "checkstyleMain", "checkstyleTest"],
        ["--no-daemon", "test"],
        ["--no-daemon", "build"],
        ["--no-daemon", "securitySmoke"],
        ["--no-daemon", "securityLicenses"],
    )


def _java_node_ok(args: list[str]) -> bool:
    """Permit runtime version probes, not arbitrary source execution."""
    return args == ["-version"] or args == ["--version"]


def _nginx_ok(args: list[str], repo_root: Path) -> bool:
    """Restrict NGINX validation to configurations inside the repository."""
    if args == ["-v"]:
        return True
    if len(args) == 3 and args[0] == "-t" and args[1] == "-c":
        return _inside_repo(args[2], repo_root)
    return False


def _docker_ok(args: list[str], repo_root: Path) -> bool:
    """Restrict Docker operations to version and local build checks."""
    if args == ["version"]:
        return True
    if len(args) == 5 and args[:3] == ["build", "--check", "-f"] and args[4] == ".":
        return _inside_repo(args[3], repo_root)
    return False


def _inside_repo(raw: str, repo_root: Path) -> bool:
    """Resolve a path and reject traversal or external symlink targets."""
    try:
        path = Path(raw)
        if not path.is_absolute():
            path = repo_root / path
        path.resolve().relative_to(repo_root.resolve())
    except (OSError, ValueError):
        return False
    return True


_CHECKERS = {
    "git": lambda args, _root: _git_ok(args),
    "npm": lambda args, _root: _npm_ok(args),
    "pnpm": lambda args, _root: _pnpm_ok(args),
    "yarn": lambda args, _root: _yarn_ok(args),
    "dotnet": lambda args, _root: _dotnet_ok(args),
    "mvn": lambda args, _root: _maven_ok(args),
    "mvnw": lambda args, _root: _maven_ok(args),
    "gradle": lambda args, _root: _gradle_ok(args),
    "gradlew": lambda args, _root: _gradle_ok(args),
    "java": lambda args, _root: _java_node_ok(args),
    "node": lambda args, _root: _java_node_ok(args),
    "nginx": _nginx_ok,
    "docker": _docker_ok,
}


def assert_allowed(argv: list[str], repo_root: Path) -> None:
    """Raise PermissionError when argv is not an allowlisted command."""
    if len(argv) < 2:
        raise PermissionError("Refusing to run an empty command")
    batch = Path(argv[0]).suffix.lower() in {".cmd", ".bat"}
    if any(_bad_argument(arg) for arg in argv[:1]) or any(
        _bad_argument(arg, batch=batch) for arg in argv[1:]
    ):
        raise PermissionError(
            "Refusing command arguments that contain shell metacharacters"
        )
    name = tool_name(argv[0])
    path = Path(argv[0])
    if not path.is_absolute() and name not in REPO_WRAPPERS and len(path.parts) > 1:
        raise PermissionError(f"Relative executable paths are not allowed: {argv[0]}")
    checker = _CHECKERS.get(name)
    if checker is None or not checker(argv[1:], repo_root):
        shown = " ".join(argv)
        raise PermissionError(f"Command is not on the allowlist: {shown}")
    if path.is_absolute() or name in REPO_WRAPPERS:
        if name in REPO_WRAPPERS and not _inside_repo(argv[0], repo_root):
            raise PermissionError(f"Wrapper must live in the repository: {argv[0]}")
        if name in PATH_TOOLS and path.is_absolute():
            return
        if name in REPO_WRAPPERS:
            return
        if name not in PATH_TOOLS and name not in REPO_WRAPPERS:
            raise PermissionError(f"Unexpected executable: {argv[0]}")


@dataclass
class CommandResult:
    """Exit code and capped output of one finished command."""

    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool
    stdout_sha256: str
    stderr_sha256: str
    stdout_log_path: str | None = None
    stderr_log_path: str | None = None

    def display(self) -> str:
        """Return the command as one quoted string for reports."""
        return subprocess.list2cmdline(self.argv)


class CommandProgress:
    """Publish bounded, output-driven progress without guessing test totals."""

    def __init__(
        self,
        label: str,
        callback: Callable[[str], None],
        *,
        total_suites: int | None = None,
        test_output: bool = True,
    ):
        """Keep separate stream fragments and serialize progress notifications."""
        self.label = label
        self.callback = callback
        self._lock = threading.Lock()
        self._buffers: dict[str, str] = {}
        self.completed = 0
        self.total: int | None = None
        self.suites: set[str] = set()
        self.total_suites = total_suites
        self.test_output = test_output
        self.output_bytes = 0
        self._last = ""
        self._last_emitted = 0.0
        self._emit("[....................] starting; total unavailable")
        if total_suites:
            self._tests(force=True)

    def _emit(self, detail: str, *, force: bool = False) -> None:
        """Publish only changed progress without exposing raw command output."""
        text = f"{self.label}: {detail}"
        now = time.monotonic()
        if text != self._last and (force or now - self._last_emitted >= 0.25):
            self._last = text
            self._last_emitted = now
            try:
                self.callback(text)
            except Exception:
                logging.getLogger("gitlab_security_mcp").warning(
                    "Could not publish command progress", exc_info=True
                )

    def _tests(self, *, force: bool = False) -> None:
        """Render percentages only when the runner supplied a positive total."""
        if self.total:
            filled = min(20, self.completed * 20 // self.total)
            self._emit(
                f"[{'#' * filled}{'.' * (20 - filled)}] "
                f"{self.completed}/{self.total} tests "
                f"({min(100, self.completed * 100 // self.total)}%)",
                force=force,
            )
        elif self.total_suites:
            completed = len(self.suites)
            filled = min(20, completed * 20 // self.total_suites)
            self._emit(
                f"[{'#' * filled}{'.' * (20 - filled)}] "
                f"{completed}/{self.total_suites} test suites "
                f"({min(100, completed * 100 // self.total_suites)}%); "
                f"{self.completed} test cases reported; case total unavailable",
                force=force,
            )
        else:
            self._emit(
                f"[????????????????????] {self.completed}/? tests; total unavailable",
                force=force,
            )

    def feed(self, stream: str, block: str) -> None:
        """Consume live fragments before preview truncation can discard results."""
        with self._lock:
            self.output_bytes += len(block.encode("utf-8", errors="replace"))
            text = self._buffers.get(stream, "") + block.replace("\r", "\n")
            lines = text.split("\n")
            self._buffers[stream] = lines.pop()[-32768:]
            previous = self._last
            for line in lines:
                if not self.test_output:
                    continue
                line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line)
                summary = re.search(r"Tests:\s*(.*)", line)
                if summary:
                    total = re.search(r"([\d,]+)\s+total\b", summary[1])
                    counts = re.findall(
                        r"([\d,]+)\s+(?:passed|failed|skipped|pending|todo)\b",
                        summary[1],
                    )
                    if total and counts:
                        self.total = int(total[1].replace(",", ""))
                        self.completed = sum(
                            int(count.replace(",", "")) for count in counts
                        )
                        self._tests(force=True)
                elif re.match(r"^\s*[\u2713\u221a\u2714\u2715\u2716\u00d7]\s+", line):
                    self.completed += 1
                    self._tests()
                elif re.match(r"^\s*(?:PASS|FAIL)\s+", line):
                    if len(self.suites) < 20000:
                        self.suites.add(line.strip())
                    self._tests()
            if self._last == previous and block:
                if self.completed or self.suites or self.total_suites:
                    self._tests()
                else:
                    self._emit(
                        f"[????????????????????] running; {self.output_bytes} output bytes received; "
                        "total unavailable"
                    )

    def finish(self, exit_code: int) -> None:
        """Flush final partial lines and distinguish command exit from test success."""
        for stream in tuple(self._buffers):
            self.feed(stream, "\n")
        with self._lock:
            if self.completed or self.suites:
                self._tests(force=True)
            self._emit(
                f"[{'#' * 20 if exit_code == 0 else '!' * 20}] "
                f"command finished; exit {exit_code}",
                force=True,
            )


class CommandRunner:
    """Run one allowlisted command at a time and record a hash-only audit line.

    A lock serializes runs so audit lines cannot interleave. Stdout and stderr
    are read on two threads so a full pipe cannot deadlock the child, and each
    stream is capped so a noisy build cannot fill memory.
    """

    def __init__(
        self,
        repo_root: Path,
        *,
        max_output: int = 65536,
        audit_path: Path | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ):
        """Configure the repository boundary, output cap, and local audit path."""
        self.repo_root = repo_root
        self.max_output = max_output
        self.audit_path = audit_path or (repo_root / ".security-mcp" / "audit.jsonl")
        self._lock = threading.Lock()
        self._command_log_paths: dict[str, Path] = {}
        self.progress_callback = progress_callback or self._print_progress
        self._command_progress: CommandProgress | None = None

    @staticmethod
    def _print_progress(text: str) -> None:
        """Keep live text progress off the MCP JSON-RPC stdout stream."""
        print(text, file=sys.stderr, flush=True)

    def run(
        self,
        argv: list[str],
        *,
        timeout: int,
        check: bool = True,
        cwd: Path | None = None,
    ) -> CommandResult:
        """Run argv inside the repository and return capped output."""
        workdir = (cwd or self.repo_root).resolve()
        try:
            workdir.relative_to(self.repo_root.resolve())
        except ValueError as exc:
            raise PermissionError(
                f"Refusing to run outside the repository: {workdir}"
            ) from exc
        assert_allowed(argv, self.repo_root)
        with self._lock:
            return self._run_locked(argv, timeout=timeout, check=check, workdir=workdir)

    def _run_locked(
        self, argv: list[str], *, timeout: int, check: bool, workdir: Path
    ) -> CommandResult:
        """Own child cleanup, cancellable readers, and audit publication."""
        started = time.monotonic()
        total_suites = self._discover_test_suites(argv, timeout, workdir)
        self._command_log_paths = {}
        if tool_name(argv[0]) != "git" and any(
            arg
            in ALLOWED_SCRIPTS
            | {
                "clean",
                "install",
                "verify",
                "format",
                "checkstyle:check",
                "checkstyleMain",
                "checkstyleTest",
            }
            for arg in argv[1:]
        ):
            directory = self.repo_root / ".security-mcp" / "command-logs"
            directory.mkdir(parents=True, exist_ok=True)
            identifier = uuid4().hex
            self._command_log_paths = {
                name: directory / f"{identifier}.{name}.log"
                for name in ("stdout", "stderr")
            }
        # stdin is the MCP JSON-RPC stream. A child that inherits it could
        # consume protocol bytes, so it gets an empty stdin instead.
        process = subprocess.Popen(
            argv,
            cwd=workdir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            env=_child_env(argv),
            **_process_group_options(),
        )
        sink = progress_sink.get()

        def notify(text: str) -> None:
            """Forward reader-thread updates to the request captured by this command."""
            self.progress_callback(text)
            if sink is not None:
                sink(text)

        self._command_progress = CommandProgress(
            subprocess.list2cmdline([tool_name(argv[0]), *argv[1:]]),
            notify,
            total_suites=total_suites,
            test_output=any(
                arg in {"test", "test:unit", "test:ci", "verify"} for arg in argv[1:]
            ),
        )
        captured: dict[str, tuple[str, bool]] = {}
        errors: list[BaseException] = []
        threads: list[threading.Thread] = []
        output_lock = threading.Lock()
        stop_readers = threading.Event()
        timed_out = False
        try:
            self._start_readers(
                process, captured, errors, threads, stop_readers, output_lock
            )
            exit_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree(process)
            exit_code = -1
        finally:
            if process.poll() is None:
                _kill_tree(process)
            stop_readers.set()
            for thread in threads:
                thread.join(timeout=5)
            if not any(thread.is_alive() for thread in threads):
                _close_pipes(process)
        if any(thread.is_alive() for thread in threads):
            raise RuntimeError("Command output readers did not stop")
        if errors:
            raise RuntimeError("Could not read command output") from errors[0]
        stdout, stdout_truncated = captured.get("stdout", ("", False))
        stderr, stderr_truncated = captured.get("stderr", ("", False))
        if timed_out:
            stderr = f"{stderr}\nTimed out after {timeout}s"
            exit_code = 124
        self._command_progress.finish(exit_code)
        duration_ms = int((time.monotonic() - started) * 1000)
        truncated = stdout_truncated or stderr_truncated
        result = self._finish(argv, exit_code, stdout, stderr, duration_ms, truncated)
        result.stdout_log_path = (
            str(self._command_log_paths["stdout"]) if self._command_log_paths else None
        )
        result.stderr_log_path = (
            str(self._command_log_paths["stderr"]) if self._command_log_paths else None
        )
        self._audit(result, workdir)
        if check and result.exit_code != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(
                f"{result.display()} failed ({result.exit_code}): {detail[:500]}"
            )
        return result

    def _discover_test_suites(
        self, argv: list[str], timeout: int, workdir: Path
    ) -> int | None:
        """Ask a plain Jest script for this run's files without executing tests."""
        manager = tool_name(argv[0])
        if manager not in {"npm", "pnpm", "yarn"} or argv[1:] != ["test"]:
            return None
        try:
            manifest = json.loads(
                (workdir / "package.json").read_text(encoding="utf-8")
            )
            scripts = manifest.get("scripts", {})
            script = scripts.get("test", "")
            if (
                not isinstance(script, str)
                or not re.match(r"^\s*jest(?:\s|$)", script)
                or _bad_argument(script)
                or scripts.get("pretest")
                or scripts.get("posttest")
            ):
                return None
            discovery = self._run_locked(
                [*argv, *(["--"] if manager == "npm" else []), "--listTests", "--json"],
                timeout=min(timeout, 30),
                check=False,
                workdir=workdir,
            )
            if discovery.exit_code or discovery.truncated:
                return None
            for line in discovery.stdout.splitlines():
                if not line.strip().startswith("["):
                    continue
                try:
                    paths = json.loads(line)
                except ValueError:
                    continue
                if isinstance(paths, list) and all(
                    isinstance(path, str) for path in paths
                ):
                    return len(set(paths)) or None
        except (OSError, ValueError, RuntimeError):
            return None
        return None

    def _start_readers(
        self,
        process: subprocess.Popen[str],
        captured: dict[str, tuple[str, bool]],
        errors: list[BaseException],
        started: list[threading.Thread],
        stop: threading.Event,
        output_lock: threading.Lock,
    ) -> None:
        """Start one reader per pipe so a full buffer cannot stall the child.

        Readers are daemons so a reader that ignores the stop event cannot
        keep the process alive after its join times out. A finished join
        still happens-before the caller reads the captured output.
        """
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("Command pipes were not opened")

        def read_stream(name: str, pipe) -> None:
            """Capture a capped stream or record its reader exception."""
            try:
                result = _read_capped(
                    pipe,
                    self.max_output,
                    stop,
                    log_path=self._command_log_paths.get(name),
                    on_output=(lambda block: self._command_progress.feed(name, block))
                    if self._command_progress is not None
                    else None,
                )
            except Exception as exc:
                with output_lock:
                    errors.append(exc)
                return
            with output_lock:
                captured[name] = result

        threads = [
            threading.Thread(
                target=read_stream, args=("stdout", process.stdout), daemon=True
            ),
            threading.Thread(
                target=read_stream, args=("stderr", process.stderr), daemon=True
            ),
        ]
        for thread in threads:
            thread.start()
            started.append(thread)

    def _finish(
        self,
        argv: list[str],
        exit_code: int,
        stdout: str,
        stderr: str,
        duration_ms: int,
        truncated: bool,
    ) -> CommandResult:
        """Cap retained output and hash exactly the text returned to callers."""

        def preview(text: str) -> str:
            """Keep the command's start and final summary within the memory cap."""
            if len(text) <= self.max_output:
                return text
            tail = self.max_output // 2
            return text[: self.max_output - tail] + (text[-tail:] if tail else "")

        kept_out = preview(stdout)
        kept_err = preview(stderr)
        return CommandResult(
            argv=list(argv),
            exit_code=exit_code,
            stdout=kept_out,
            stderr=kept_err,
            duration_ms=duration_ms,
            truncated=truncated
            or len(stdout) > self.max_output
            or len(stderr) > self.max_output,
            stdout_sha256=hashlib.sha256(
                kept_out.encode("utf-8", errors="replace")
            ).hexdigest(),
            stderr_sha256=hashlib.sha256(
                kept_err.encode("utf-8", errors="replace")
            ).hexdigest(),
        )

    def _audit(self, result: CommandResult, cwd: Path) -> None:
        """Append command metadata and hashes without storing raw output."""
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "argv": result.argv,
            "cwd": str(cwd),
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "stdout_sha256": result.stdout_sha256,
            "stderr_sha256": result.stderr_sha256,
            "truncated": result.truncated,
            "stdout_log_path": result.stdout_log_path,
            "stderr_log_path": result.stderr_log_path,
            "stdout_bytes_kept": len(result.stdout.encode("utf-8", errors="replace")),
            "stderr_bytes_kept": len(result.stderr.encode("utf-8", errors="replace")),
        }
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")


def _read_capped(
    pipe,
    limit: int,
    stop: threading.Event,
    *,
    log_path: Path | None = None,
    on_output: Callable[[str], None] | None = None,
) -> tuple[str, bool]:
    """Read a pipe while retaining at most ``limit`` characters.

    Drain excess output while the child runs to avoid pipe-buffer deadlock.
    After shutdown, retain ready data and stop without waiting for EOF from
    descendants that inherited the pipe. Always close the reader's pipe.
    """
    chunks: list[str] = []
    kept = 0
    truncated = False
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    tail = ""
    tail_limit = limit // 2
    shutdown_bytes = 0
    log = None
    try:
        if log_path is not None:
            log = log_path.open("w", encoding="utf-8", newline="")
        while True:
            available = _pipe_available(pipe)
            if available is None:
                break
            if not available:
                if stop.is_set():
                    break
                stop.wait(0.02)
                continue
            raw = os.read(pipe.fileno(), min(available, _READ_SIZE))
            if not raw:
                break
            block = decoder.decode(raw)
            if on_output is not None:
                on_output(block)
            if log is not None:
                log.write(block)
            if tail_limit:
                tail = (tail + block)[-tail_limit:]
            if stop.is_set():
                shutdown_bytes += len(raw)
                if shutdown_bytes > 1024 * 1024:
                    raise RuntimeError(
                        "Command descendants continued writing after shutdown; output capture is incomplete"
                    )
            if kept >= limit:
                truncated = True
                continue
            room = limit - kept
            if len(block) <= room:
                chunks.append(block)
                kept += len(block)
            else:
                chunks.append(block[:room])
                kept += room
                truncated = True
        final = decoder.decode(b"", final=True)
        if final:
            if on_output is not None:
                on_output(final)
            if log is not None:
                log.write(final)
            if tail_limit:
                tail = (tail + final)[-tail_limit:]
            chunks.append(final[: max(0, limit - kept)])
            truncated = truncated or kept + len(final) > limit
    finally:
        try:
            if log is not None:
                log.close()
        finally:
            pipe.close()
    prefix = "".join(chunks)
    return (
        prefix[: limit - tail_limit] + tail if truncated and tail_limit else prefix
    ), truncated


def _pipe_available(pipe) -> int | None:
    """Probe readable bytes without blocking; return None on Windows EOF."""
    if os.name != "nt":
        import select

        ready, _, _ = select.select([pipe], [], [], 0)
        return _READ_SIZE if ready else 0
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    peek = kernel.PeekNamedPipe
    peek.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    peek.restype = wintypes.BOOL
    available = wintypes.DWORD()
    if not peek(
        msvcrt.get_osfhandle(pipe.fileno()),
        None,
        0,
        None,
        ctypes.byref(available),
        None,
    ):
        error = ctypes.get_last_error()
        if error == 109:
            return None
        raise ctypes.WinError(error)
    return available.value


def _close_pipes(process: subprocess.Popen[str]) -> None:
    """Close remaining process streams after their readers have stopped."""
    for pipe in (process.stdout, process.stderr, process.stdin):
        if pipe is not None and not pipe.closed:
            pipe.close()


def _child_env(argv: list[str] | None = None) -> dict[str, str]:
    """Copy the environment and stop git or package managers from prompting."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"
    env["CI"] = env.get("CI") or "1"
    if (
        argv
        and tool_name(argv[0]) == "yarn"
        and (argv[1:3] == ["up", "-R"] or "--mode=update-lockfile" in argv)
    ):
        env["YARN_ENABLE_SCRIPTS"] = "false"
        env["YARN_ENABLE_IMMUTABLE_INSTALLS"] = "false"
    return env


def _process_group_options() -> dict:
    """Start the child in its own group so a timeout can stop its children too."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _kill_tree(process: subprocess.Popen[str]) -> None:
    """Stop the child and everything it started, then reap the child."""
    if process.poll() is None:
        if os.name == "nt":
            # npm.cmd and gradlew.bat run under cmd.exe, so killing only the
            # direct child would leave node or java running.
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
        if process.poll() is None:
            process.kill()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def resolve_tool(name: str, which) -> str | None:
    """Find an executable on PATH, including Windows ``.cmd`` shims."""
    found = which(name)
    if found:
        return found
    if os.name == "nt":
        return which(f"{name}.cmd") or which(f"{name}.bat") or which(f"{name}.exe")
    return None
