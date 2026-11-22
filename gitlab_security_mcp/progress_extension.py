"""Install the progress extension into the editor that launched this server."""

from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import subprocess
import sys
import zipfile
from collections.abc import Generator
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path
from tempfile import TemporaryDirectory

logger = logging.getLogger("gitlab_security_mcp")

_INSTALL_SWITCH = "PROGRESS_EXTENSION_INSTALL"
_INSTALL_LOCK_ENV = "GITLAB_SECURITY_INSTALL_LOCK_DIR"
_INSTALL_LOCK_BYTES = 1
_INSTALL_LOCK_ID_LENGTH = 16
_DISABLED = frozenset({"0", "off", "false"})
_INSTALL_TIMEOUT_SECONDS = 60
_MAX_PARENT_PROCESSES = 8
_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_CLI_JS = Path("resources") / "app" / "out" / "cli.js"
_MAC_CLI_JS = Path("Resources") / "app" / "out" / "cli.js"
_MAC_EXECUTABLE_MARKER = "Contents/MacOS/"
_PS_TIMEOUT_SECONDS = 5
_EDITOR_EXECUTABLES = frozenset(
    {
        "cursor.exe",
        "code.exe",
        "code - insiders.exe",
        "cursor",
        "code",
        "code-insiders",
        "electron",
    }
)
_EXTENSION_FILES = (
    "package.json",
    "extension.js",
    "progress-model.js",
    "README.md",
)
_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
<Metadata>
<Identity Language="en-US" Id="{identifier}" Version="{version}" Publisher="{publisher}" />
<DisplayName>{display_name}</DisplayName>
<Description xml:space="preserve">{description}</Description>
<Tags></Tags>
<Categories>Other</Categories>
<GalleryFlags>Public</GalleryFlags>
<Properties>
<Property Id="Microsoft.VisualStudio.Code.Engine" Value="{engine}" />
<Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />
<Property Id="Microsoft.VisualStudio.Code.ExecutesCode" Value="true" />
</Properties>
</Metadata>
<Installation>
<InstallationTarget Id="Microsoft.VisualStudio.Code"/>
</Installation>
<Dependencies/>
<Assets>
<Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
<Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/readme.md" Addressable="true" />
</Assets>
</PackageManifest>
"""
_CONTENT_TYPES = """<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension=".js" ContentType="application/javascript"/><Default Extension=".json" ContentType="application/json"/><Default Extension=".md" ContentType="text/markdown"/><Default Extension=".vsixmanifest" ContentType="text/xml"/></Types>
"""


class _ProcessEntry(ctypes.Structure):
    """One Toolhelp process row, including its parent id and executable name."""

    _fields_ = (
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    )


def extension_directory() -> Path:
    """Return the progress extension source, preferring the checkout copy."""
    checkout = Path(__file__).resolve().parents[1] / "editor-progress"
    if (checkout / "package.json").is_file():
        return checkout
    return Path(__file__).resolve().parent / "editor_progress"


def write_vsix(path: Path) -> None:
    """Write a VSIX from the current extension source."""
    source = extension_directory()
    package = json.loads((source / "package.json").read_text(encoding="utf-8"))
    manifest = _MANIFEST.format(
        identifier=package["name"],
        version=package["version"],
        publisher=package["publisher"],
        display_name=package["displayName"],
        description=package["description"],
        engine=package["engines"]["vscode"],
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _CONTENT_TYPES)
        archive.writestr("extension.vsixmanifest", manifest)
        for name in _EXTENSION_FILES:
            arcname = (
                "extension/readme.md" if name == "README.md" else f"extension/{name}"
            )
            archive.write(source / name, arcname)


def editor_command(
    start: int, parents: dict[int, tuple[int, str]], images: dict[int, Path]
) -> list[str] | None:
    """Return the editor CLI for the nearest Cursor or VS Code ancestor."""
    current = start
    for _ in range(_MAX_PARENT_PROCESSES):
        row = parents.get(current)
        if row is None:
            return None
        parent, name = row
        image = images.get(current)
        if name.lower() in _EDITOR_EXECUTABLES and image is not None:
            cli = _editor_cli(image)
            if cli is not None:
                return [str(image), str(cli)]
        if parent == current:
            return None
        current = parent
    return None


def install_progress_extension() -> None:
    """Install the progress extension into the editor that owns this process.

    A unit test and an explicit off switch do not install anything. Failure
    is logged and does not stop the MCP server.
    """
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return
    if os.environ.get(_INSTALL_SWITCH, "on").lower() in _DISABLED:
        return
    try:
        if sys.platform == "win32":
            tree = _windows_process_tree()
        else:
            tree = _posix_process_tree()
        command = editor_command(os.getppid(), *tree)
    except OSError:
        logger.warning("Could not identify the editor process", exc_info=True)
        return
    if command is None:
        logger.info(
            "Progress extension install skipped; this process is not a VS Code or Cursor child."
        )
        return
    _install_with_command(command)


@contextmanager
def _editor_install_lock(editor: str) -> Generator[None, None, None]:
    """Serialize installs that share one editor's extension directory."""
    override = os.environ.get(_INSTALL_LOCK_ENV)
    directory = (
        Path(override) if override else Path.home() / ".cache" / "gitlab-security-mcp"
    )
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(os.path.normcase(editor).encode()).hexdigest()[
        :_INSTALL_LOCK_ID_LENGTH
    ]
    path = directory / f"progress-install-{digest}.lock"
    handle = os.open(path, os.O_CREAT | os.O_RDWR)
    try:
        _lock_handle(handle)
        try:
            yield
        finally:
            _unlock_handle(handle)
    finally:
        os.close(handle)


def _lock_handle(handle: int) -> None:
    """Block until this process owns the install lock on any supported OS."""
    if sys.platform == "win32":
        import msvcrt

        msvcrt.locking(handle, msvcrt.LK_LOCK, _INSTALL_LOCK_BYTES)
        return
    import fcntl

    fcntl.flock(handle, fcntl.LOCK_EX)


def _unlock_handle(handle: int) -> None:
    """Release the install lock acquired by this process."""
    if sys.platform == "win32":
        import msvcrt

        msvcrt.locking(handle, msvcrt.LK_UNLCK, _INSTALL_LOCK_BYTES)
        return
    import fcntl

    fcntl.flock(handle, fcntl.LOCK_UN)


def _editor_cli(image: Path) -> Path | None:
    """Find cli.js beside a Linux or Windows binary, or inside a macOS app."""
    candidates = (
        image.parent / _CLI_JS,
        image.parent.parent / _MAC_CLI_JS,
    )
    for cli in candidates:
        if cli.is_file():
            return cli
    return None


def _install_with_command(command: list[str]) -> None:
    """Build a temporary VSIX and ask that editor to install it."""
    with _editor_install_lock(command[0]), TemporaryDirectory() as directory:
        vsix = Path(directory) / "gitlab-security-progress.vsix"
        write_vsix(vsix)
        child_env = os.environ.copy()
        child_env.pop("VSCODE_DEV", None)
        child_env["ELECTRON_RUN_AS_NODE"] = "1"
        try:
            completed = subprocess.run(
                [*command, "--install-extension", str(vsix), "--force"],
                check=False,
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_INSTALL_TIMEOUT_SECONDS,
                env=child_env,
            )
        except (OSError, subprocess.TimeoutExpired):
            logger.warning("Could not install the progress extension", exc_info=True)
            return
    if completed.returncode != 0:
        logger.warning(
            "Progress extension install exited %s: %s",
            completed.returncode,
            (completed.stderr or completed.stdout).strip(),
        )
        return
    logger.info("Installed the progress extension into %s", command[0])


def _posix_process_tree() -> tuple[dict[int, tuple[int, str]], dict[int, Path]]:
    """Map processes from Linux /proc, or from ps on macOS."""
    proc = Path("/proc")
    if proc.is_dir():
        return _linux_process_tree(proc)
    completed = subprocess.run(
        ["ps", "-ax", "-o", "pid=,ppid=,command="],
        check=False,
        shell=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=_PS_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise OSError(completed.stderr.strip() or "ps failed")
    return _process_tree_from_ps(completed.stdout)


def _linux_process_tree(
    proc: Path,
) -> tuple[dict[int, tuple[int, str]], dict[int, Path]]:
    """Read parent links and editor executable paths from a /proc tree."""
    parents: dict[int, tuple[int, str]] = {}
    images: dict[int, Path] = {}
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            parsed = _proc_stat((entry / "stat").read_text(encoding="utf-8"))
        except OSError:
            continue
        if parsed is None:
            continue
        name, parent = parsed
        parents[pid] = (parent, name)
        if name.lower() not in _EDITOR_EXECUTABLES:
            continue
        try:
            images[pid] = _linked_executable(entry)
        except OSError:
            continue
    return parents, images


def _linked_executable(entry: Path) -> Path:
    """Return the executable a Linux /proc pid directory points at."""
    return Path(os.readlink(entry / "exe"))


def _proc_stat(text: str) -> tuple[str, int] | None:
    """Return the comm name and parent pid from one /proc stat record."""
    start = text.find("(")
    end = text.rfind(")")
    if start < 0 or end <= start:
        return None
    fields = text[end + 2 :].split()
    if len(fields) < 2:
        return None
    return text[start + 1 : end], int(fields[1])


def _process_tree_from_ps(
    text: str,
) -> tuple[dict[int, tuple[int, str]], dict[int, Path]]:
    """Parse `ps` pid, parent, and command columns into the editor walk."""
    parents: dict[int, tuple[int, str]] = {}
    images: dict[int, Path] = {}
    for line in text.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
            parent = int(parts[1])
        except ValueError:
            continue
        command = parts[2].strip()
        image = _image_from_ps_command(command)
        name = image.name if image is not None else command.split(" ", 1)[0]
        if not name:
            continue
        parents[pid] = (parent, name)
        if image is not None and name.lower() in _EDITOR_EXECUTABLES:
            images[pid] = image
    return parents, images


def _image_from_ps_command(command: str) -> Path | None:
    """Keep the executable path, including a macOS path that contains spaces."""
    marker = command.find(_MAC_EXECUTABLE_MARKER)
    if marker >= 0:
        start = 0 if command.startswith("/") else command.rfind(" ", 0, marker) + 1
        end = command.find(" ", marker + len(_MAC_EXECUTABLE_MARKER))
        text = command[start:] if end < 0 else command[start:end]
        return Path(text)
    token = command.split(" ", 1)[0]
    if token.startswith("/"):
        return Path(token)
    return None


def _windows_process_tree() -> tuple[dict[int, tuple[int, str]], dict[int, Path]]:
    """Map each process to its parent and, for editors, its executable path."""
    kernel = _kernel32()
    snapshot = kernel.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        raise OSError("Process snapshot failed")
    parents: dict[int, tuple[int, str]] = {}
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        if not kernel.Process32FirstW(snapshot, ctypes.byref(entry)):
            raise OSError("Process snapshot was empty")
        while True:
            parents[int(entry.th32ProcessID)] = (
                int(entry.th32ParentProcessID),
                entry.szExeFile,
            )
            if not kernel.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel.CloseHandle(snapshot)
    images = {
        pid: image
        for pid, (_parent, name) in parents.items()
        if name.lower() in _EDITOR_EXECUTABLES
        and (image := _process_image(pid)) is not None
    }
    return parents, images


def _kernel32() -> ctypes.WinDLL:
    """Return kernel32 with the process APIs this installer calls."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
    kernel.Process32FirstW.restype = wintypes.BOOL
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
    kernel.Process32NextW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    return kernel


def _process_image(pid: int) -> Path | None:
    """Return one process executable path, or None when Windows will not say."""
    kernel = _kernel32()
    handle = kernel.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32_768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        return Path(buffer.value)
    finally:
        kernel.CloseHandle(handle)
