"""Verify Windows installer prechecks without changing an installed environment."""

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


@pytest.mark.parametrize("shell", ["powershell", "pwsh"])
def test_installer_reports_locked_launcher_before_changing_files(tmp_path, shell):
    """A real Windows sharing violation must explain how to release the server."""
    # Arrange
    executable = _shell(shell)
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
