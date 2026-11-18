"""Verify Windows installer prechecks without changing an installed environment."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parents[1] / "Install-GitLabSecurityMcp.ps1"
pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows installer")


def _shell(name):
    """Skip a PowerShell runtime only when it is unavailable on the test host."""
    executable = shutil.which(name)
    if executable is None:
        pytest.skip(f"{name} is not installed")
    return executable


def _quote(path):
    """Quote literal fixture paths for both supported PowerShell runtimes."""
    return "'" + str(path).replace("'", "''") + "'"


def _windows_powershell():
    """Return the Windows PowerShell 5.1 executable shipped with Windows."""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    executable = Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not executable.is_file():
        pytest.skip("Windows PowerShell 5.1 is not installed")
    return str(executable)


def _skip_unless_powershell7_available(executable):
    """Success paths need PowerShell 7, either as the host or as pwsh on PATH."""
    if Path(executable).name.lower() == "pwsh.exe":
        return
    if shutil.which("pwsh") is None:
        pytest.skip("PowerShell 7 is not installed")


@pytest.mark.parametrize("shell", ["powershell", "pwsh"])
def test_installer_reports_locked_launcher_before_changing_files(tmp_path, shell):
    """A real Windows sharing violation must explain how to release the server."""
    # Arrange
    executable = _shell(shell)
    _skip_unless_powershell7_available(executable)
    wheel = tmp_path / "gitlab_security_mcp-1.0.2-py3-none-any.whl"
    wheel.write_bytes(b"Preflight fixture; not installed.")
    install = tmp_path / "install directory"
    scripts = install / "Scripts"
    scripts.mkdir(parents=True)
    launcher = scripts / "gitlab-security-mcp.exe"
    launcher.write_bytes(b"Locked launcher fixture.")
    command = (
        f"$lock = [IO.File]::Open({_quote(launcher)}, "
        "[IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None); "
        f"try {{ & {_quote(INSTALLER)} -WheelPath {_quote(wheel)} "
        f"-InstallDirectory {_quote(install)} }} finally {{ $lock.Dispose() }}"
    )

    # Act
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )

    # Assert
    assert result.returncode != 0
    assert "Close ALL instances of VS Code and Cursor" in result.stdout + result.stderr
    assert "standalone PowerShell" in result.stdout + result.stderr
    assert launcher.read_bytes() == b"Locked launcher fixture."
    assert not (scripts / "python.exe").exists()


@pytest.mark.parametrize("shell", ["powershell", "pwsh"])
def test_installer_whatif_does_not_create_an_environment(tmp_path, shell):
    """An unlocked preflight preview must not create a venv or invoke pip."""
    # Arrange
    executable = _shell(shell)
    _skip_unless_powershell7_available(executable)
    wheel = tmp_path / "gitlab_security_mcp-1.0.2-py3-none-any.whl"
    wheel.write_bytes(b"Preflight fixture; not installed.")
    install = tmp_path / "install directory"

    # Act
    result = subprocess.run(
        [
            executable,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALLER),
            "-WheelPath",
            str(wheel),
            "-InstallDirectory",
            str(install),
            "-WhatIf",
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )

    # Assert
    assert result.returncode == 0, result.stdout + result.stderr
    assert "What if:" in result.stdout
    assert not install.exists()


def test_installer_stops_when_powershell_7_is_not_installed(tmp_path):
    """A Windows PowerShell 5.1 launch must not create an environment without pwsh."""
    # Arrange
    executable = _windows_powershell()
    wheel = tmp_path / "gitlab_security_mcp-1.0.2-py3-none-any.whl"
    wheel.write_bytes(b"Preflight fixture; not installed.")
    install = tmp_path / "install directory"
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    command = (
        f"$env:PATH = {_quote(str(Path(system_root) / 'System32'))}; "
        f"& {_quote(INSTALLER)} -WheelPath {_quote(wheel)} "
        f"-InstallDirectory {_quote(install)}"
    )

    # Act
    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )

    # Assert
    combined = result.stdout + result.stderr
    assert result.returncode != 0
    assert "PowerShell 7 (pwsh) is not installed" in combined
    assert not install.exists()


def _restricted_command(path_dirs, wheel, install):
    """Build a launcher command whose PATH contains only the named directories."""
    path_value = ";".join(path_dirs)
    return (
        f"$env:PATH = {_quote(path_value)}; "
        f"& {_quote(INSTALLER)} -WheelPath {_quote(wheel)} "
        f"-InstallDirectory {_quote(install)}"
    )


def _run_restricted(executable, command):
    """Run one installer precheck with a narrowed PATH."""
    return subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )


def test_installer_stops_when_python_311_is_not_installed(tmp_path):
    """PowerShell 7 alone must not create an environment when Python is missing."""
    # Arrange
    executable = _shell("pwsh")
    wheel = tmp_path / "gitlab_security_mcp-1.0.2-py3-none-any.whl"
    wheel.write_bytes(b"Preflight fixture; not installed.")
    install = tmp_path / "install directory"
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    command = _restricted_command(
        [str(Path(executable).parent), str(system32)], wheel, install
    )

    # Act
    result = _run_restricted(executable, command)

    # Assert
    combined = result.stdout + result.stderr
    assert result.returncode != 0
    assert "Python 3.11 or newer is not installed" in combined
    assert not install.exists()


def test_installer_stops_when_git_is_not_installed(tmp_path):
    """Python 3.11 must not create an environment when Git is missing."""
    # Arrange
    executable = _shell("pwsh")
    py = shutil.which("py")
    if py is None:
        pytest.skip("py launcher is not installed")
    wheel = tmp_path / "gitlab_security_mcp-1.0.2-py3-none-any.whl"
    wheel.write_bytes(b"Preflight fixture; not installed.")
    install = tmp_path / "install directory"
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    command = _restricted_command(
        [str(Path(executable).parent), str(Path(py).parent), str(system32)],
        wheel,
        install,
    )

    # Act
    result = _run_restricted(executable, command)

    # Assert
    combined = result.stdout + result.stderr
    assert result.returncode != 0
    assert "Git is not installed" in combined
    assert not install.exists()
