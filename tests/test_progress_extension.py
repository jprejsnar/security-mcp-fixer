"""Install the progress extension into the editor that started the server."""

import json
import logging
import os
import subprocess
import threading
import zipfile
from pathlib import Path

import pytest

from gitlab_security_mcp.progress_extension import (
    _editor_cli,
    _linux_process_tree,
    _posix_process_tree,
    _process_tree_from_ps,
    editor_command,
    extension_directory,
    install_progress_extension,
    reload_required_version,
    write_vsix,
)

CURSOR_PID = 40
PYTHON_PID = 20
SERVER_PID = 10
CURSOR_NAME = "Cursor.exe"
PYTHON_NAME = "python.exe"
INSTALL_ROOT = Path(r"C:\Editors\cursor")
CLI_JS = INSTALL_ROOT / "resources" / "app" / "out" / "cli.js"
EXTENSION_FILES = (
    "package.json",
    "extension.js",
    "progress-model.js",
    "README.md",
)
INSIDERS_EXECUTABLE = (
    "/Applications/Visual Studio Code - Insiders.app/Contents/MacOS/Code - Insiders"
)
INSIDERS_NAME = "Code - Insiders"
_SERVER_START_WAIT_SECONDS = 2
_INSTALL_BLOCK_SECONDS = 5


def test_packaged_extension_matches_the_editor_progress_tree():
    """The wheel copy stays identical to the extension that the tests run."""
    # Arrange
    packaged = (
        Path(__file__).resolve().parents[1] / "gitlab_security_mcp" / "editor_progress"
    )
    source = Path(__file__).resolve().parents[1] / "editor-progress"

    # Act
    pairs = [
        (packaged / name).read_bytes() == (source / name).read_bytes()
        for name in EXTENSION_FILES
    ]

    # Assert
    assert all(pairs)


def test_vsix_contains_the_current_extension(tmp_path):
    """The generated package carries the extension version and its JavaScript."""
    # Arrange
    destination = tmp_path / "progress.vsix"
    package = json.loads(
        (extension_directory() / "package.json").read_text(encoding="utf-8")
    )

    # Act
    write_vsix(destination)

    # Assert
    with zipfile.ZipFile(destination) as archive:
        names = set(archive.namelist())
        manifest = archive.read("extension.vsixmanifest").decode()
        script = archive.read("extension/extension.js")
    assert "extension/extension.js" in names
    assert "extension/progress-model.js" in names
    assert package["version"] in manifest
    assert script == (extension_directory() / "extension.js").read_bytes()


def test_editor_command_uses_the_nearest_cursor_or_vscode_ancestor(tmp_path):
    """A Python parent does not hide the editor that launched the server."""
    # Arrange
    cli = tmp_path / "resources" / "app" / "out" / "cli.js"
    cli.parent.mkdir(parents=True)
    cli.write_text("", encoding="utf-8")
    image = tmp_path / "Cursor.exe"
    image.write_bytes(b"")
    parents = {
        SERVER_PID: (PYTHON_PID, "server.exe"),
        PYTHON_PID: (CURSOR_PID, PYTHON_NAME),
        CURSOR_PID: (1, CURSOR_NAME),
    }
    images = {CURSOR_PID: image}

    # Act
    command = editor_command(PYTHON_PID, parents, images)

    # Assert
    assert command == [str(image), str(cli)]


def test_editor_command_finds_a_macos_app_bundle(tmp_path):
    """A macOS editor keeps cli.js inside Contents, not beside the binary."""
    # Arrange
    image = tmp_path / "Cursor.app" / "Contents" / "MacOS" / "Cursor"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"")
    cli = tmp_path / "Cursor.app" / "Contents" / "Resources" / "app" / "out" / "cli.js"
    cli.parent.mkdir(parents=True)
    cli.write_text("", encoding="utf-8")
    parents = {PYTHON_PID: (CURSOR_PID, PYTHON_NAME), CURSOR_PID: (1, "Cursor")}
    images = {CURSOR_PID: image}

    # Act
    command = editor_command(PYTHON_PID, parents, images)

    # Assert
    assert command == [str(image), str(cli)]


@pytest.mark.parametrize(
    ("executable", "launcher_name"),
    [("Code.exe", "code.cmd"), ("Code - Insiders.exe", "code-insiders.cmd")],
)
def test_editor_command_finds_the_versioned_cli_named_by_its_launcher(
    tmp_path, executable, launcher_name
):
    """Use the installed launcher's active version, not a stale version directory."""
    # Arrange
    image = tmp_path / executable
    image.write_bytes(b"")
    active_version = "8a14f0cc1b"
    for version in (active_version, "0000000000"):
        cli = tmp_path / version / "resources" / "app" / "out" / "cli.js"
        cli.parent.mkdir(parents=True)
        cli.write_text("", encoding="utf-8")
    launcher = tmp_path / "bin" / launcher_name
    launcher.parent.mkdir()
    launcher.write_text(
        f'"%~dp0..\\{executable}" "%~dp0..\\{active_version}\\resources\\app\\out\\cli.js" %*\n',
        encoding="utf-8",
    )
    parents = {PYTHON_PID: (CURSOR_PID, PYTHON_NAME), CURSOR_PID: (1, executable)}

    # Act
    command = editor_command(PYTHON_PID, parents, {CURSOR_PID: image})

    # Assert
    expected = tmp_path / active_version / "resources" / "app" / "out" / "cli.js"
    assert command == [str(image), str(expected)]


@pytest.mark.parametrize("version", [r"..\outside", "not-a-version"])
def test_editor_cli_does_not_follow_unrecognized_launcher_paths(tmp_path, version):
    """Do not execute the wrapper or accept arbitrary paths it contains."""
    # Arrange
    image = tmp_path / "Code.exe"
    cli = tmp_path / version / "resources" / "app" / "out" / "cli.js"
    cli.parent.mkdir(parents=True)
    cli.write_text("", encoding="utf-8")
    launcher = tmp_path / "bin" / "code.cmd"
    launcher.parent.mkdir()
    launcher.write_text(
        f'"%~dp0..\\{version}\\resources\\app\\out\\cli.js"\n', encoding="utf-8"
    )

    # Act
    result = _editor_cli(image)

    # Assert
    assert result is None


def test_editor_cli_reports_an_oversized_launcher(tmp_path, monkeypatch, caplog):
    """Bound startup reads and explain why an oversized launcher cannot be used."""
    # Arrange
    limit = 32
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension._MAX_LAUNCHER_BYTES", limit
    )
    launcher = tmp_path / "bin" / "code.cmd"
    launcher.parent.mkdir()
    launcher.write_bytes(b"x" * (limit + 1))

    # Act
    with caplog.at_level(logging.WARNING, logger="gitlab_security_mcp"):
        result = _editor_cli(tmp_path / "Code.exe")

    # Assert
    assert result is None
    assert "launcher exceeds" in caplog.text
    assert str(launcher) in caplog.text


def test_linux_proc_tree_keeps_the_editor_executable(tmp_path, monkeypatch):
    """Linux parent links come from /proc and point at the editor binary."""
    # Arrange
    proc = tmp_path / "proc"
    record = proc / str(CURSOR_PID)
    record.mkdir(parents=True)
    (record / "stat").write_text(
        f"{CURSOR_PID} (cursor) S {PYTHON_PID} 0\n", encoding="utf-8"
    )
    binary = tmp_path / "cursor"
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension._linked_executable",
        lambda _entry: binary,
    )

    # Act
    parents, images = _linux_process_tree(proc)

    # Assert
    assert parents[CURSOR_PID] == (PYTHON_PID, "cursor")
    assert images[CURSOR_PID] == binary


def test_linux_proc_tree_skips_a_malformed_stat_line(tmp_path, monkeypatch):
    """One unreadable process record does not hide the editor."""
    # Arrange
    proc = tmp_path / "proc"
    record = proc / str(CURSOR_PID)
    broken = proc / "41"
    record.mkdir(parents=True)
    broken.mkdir()
    (record / "stat").write_text(
        f"{CURSOR_PID} (cursor) S {PYTHON_PID} 0\n", encoding="utf-8"
    )
    (broken / "stat").write_text("41 (bad) S not-a-pid\n", encoding="utf-8")
    binary = tmp_path / "cursor"
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension._linked_executable",
        lambda _entry: binary,
    )

    # Act
    parents, images = _linux_process_tree(proc)

    # Assert
    assert 41 not in parents
    assert parents[CURSOR_PID] == (PYTHON_PID, "cursor")
    assert images[CURSOR_PID] == binary


def test_a_stuck_process_list_does_not_stop_the_server(monkeypatch, caplog):
    """A ps timeout is an identification failure and the server still starts."""
    # Arrange
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setattr("gitlab_security_mcp.progress_extension.sys.platform", "darwin")
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension.Path.is_dir", lambda _self: False
    )

    def run(*_args, **_kwargs):
        """Stall the process listing."""
        raise subprocess.TimeoutExpired(["ps"], 5)

    monkeypatch.setattr("gitlab_security_mcp.progress_extension.subprocess.run", run)

    # Act
    with caplog.at_level(logging.WARNING, logger="gitlab_security_mcp"):
        install_progress_extension()

    # Assert
    assert "Could not identify the editor process" in caplog.text
    assert "Could not install the progress extension" not in caplog.text


def test_ps_output_keeps_a_macos_insiders_executable_that_contains_spaces():
    """VS Code Insiders on macOS has spaces inside the executable name."""
    # Arrange
    text = f"{CURSOR_PID} {PYTHON_PID} {INSIDERS_EXECUTABLE} --reuse-window\n"

    # Act
    parents, images = _process_tree_from_ps(text)

    # Assert
    assert parents[CURSOR_PID] == (PYTHON_PID, INSIDERS_NAME)
    assert images[CURSOR_PID] == Path(INSIDERS_EXECUTABLE)


def test_editor_cli_finds_resources_above_a_linux_bin_directory(tmp_path):
    """A Linux editor binary in bin/ still has cli.js in the install root."""
    # Arrange
    image = tmp_path / "bin" / "cursor"
    image.parent.mkdir()
    image.write_bytes(b"")
    cli = tmp_path / "resources" / "app" / "out" / "cli.js"
    cli.parent.mkdir(parents=True)
    cli.write_text("", encoding="utf-8")

    # Act
    found = _editor_cli(image)

    # Assert
    assert found is not None
    assert os.path.normcase(found) == os.path.normcase(cli)


def test_the_server_speaks_mcp_while_the_extension_install_is_still_running(
    monkeypatch,
):
    """One window's install lock must not delay another window's MCP handshake."""
    # Arrange
    from gitlab_security_mcp import server

    release = threading.Event()
    started = threading.Event()
    monkeypatch.setenv("PROGRESS_CONSOLE", "off")

    def install():
        """Block the way a locked install does."""
        release.wait(timeout=_INSTALL_BLOCK_SECONDS)

    def run(*_args, **_kwargs):
        """Record that the protocol started and release the installer."""
        started.set()
        release.set()

    monkeypatch.setattr(server, "install_progress_extension", install)
    monkeypatch.setattr(server.mcp, "run", run)
    worker = threading.Thread(target=server.main)

    # Act
    worker.start()
    try:
        ready = started.wait(timeout=_SERVER_START_WAIT_SECONDS)
    finally:
        release.set()
        worker.join(timeout=_INSTALL_BLOCK_SECONDS)

    # Assert
    assert ready
    assert not worker.is_alive()


def test_ps_output_keeps_a_macos_path_that_contains_spaces():
    """ps command text can name Visual Studio Code.app without dropping it."""
    # Arrange
    image = "/Applications/Visual Studio Code.app/Contents/MacOS/Electron"
    text = f"{CURSOR_PID} {PYTHON_PID} {image} --reuse-window\n"

    # Act
    parents, images = _process_tree_from_ps(text)

    # Assert
    assert parents[CURSOR_PID] == (PYTHON_PID, "Electron")
    assert images[CURSOR_PID] == Path(image)


def test_ps_output_keeps_a_quoted_macos_editor_path():
    """A quoted macOS editor path still names the executable inside the app."""
    # Arrange
    image = "/Applications/Cursor.app/Contents/MacOS/Cursor"
    text = f'{CURSOR_PID} {PYTHON_PID} "{image}" --reuse-window\n'

    # Act
    parents, images = _process_tree_from_ps(text)

    # Assert
    assert parents[CURSOR_PID] == (PYTHON_PID, "Cursor")
    assert images[CURSOR_PID] == Path(image)


def test_ps_output_keeps_an_editor_path_that_contains_spaces(monkeypatch):
    """A POSIX editor installed under a directory with spaces stays addressable."""
    # Arrange
    reported = "/opt/Visual Studio Code/code"
    target = Path(reported)
    real_is_file = Path.is_file

    def is_file(self):
        """Treat the spaced editor path as present without creating it."""
        return self == target or real_is_file(self)

    monkeypatch.setattr(Path, "is_file", is_file)
    text = f"{CURSOR_PID} {PYTHON_PID} {reported} --reuse-window\n"

    # Act
    parents, images = _process_tree_from_ps(text)

    # Assert
    assert parents[CURSOR_PID] == (PYTHON_PID, "code")
    assert images[CURSOR_PID] == target


def test_ps_keeps_a_relative_command_between_the_server_and_the_editor(tmp_path):
    """A parent invoked by name must not hide the editor further up the chain."""
    # Arrange
    reported = "/Applications/Cursor.app/Contents/MacOS/Cursor"
    image = tmp_path / "Cursor"
    cli = tmp_path / "resources" / "app" / "out" / "cli.js"
    cli.parent.mkdir(parents=True)
    cli.write_text("", encoding="utf-8")
    image.write_bytes(b"")
    text = f"{PYTHON_PID} {CURSOR_PID} python3 server.py\n{CURSOR_PID} 1 {reported}\n"

    # Act
    parents, images = _process_tree_from_ps(text)
    parsed = images[CURSOR_PID]
    images[CURSOR_PID] = image
    command = editor_command(PYTHON_PID, parents, images)

    # Assert
    assert parents[PYTHON_PID] == (CURSOR_PID, "python3")
    assert parsed == Path(reported)
    assert PYTHON_PID not in images
    assert command == [str(image), str(cli)]


def test_ps_asks_for_the_full_command_so_a_long_path_is_not_cut(monkeypatch):
    """macOS ps truncates command lines unless wide output is requested."""
    # Arrange
    recorded = {}

    def run(argv, **_kwargs):
        """Capture the process listing command and return no rows."""
        recorded["argv"] = argv
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr("gitlab_security_mcp.progress_extension.subprocess.run", run)
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension.Path.is_dir", lambda _self: False
    )

    # Act
    parents, images = _posix_process_tree()

    # Assert
    assert recorded["argv"][:2] == ["ps", "-axww"]
    assert parents == {}
    assert images == {}


def test_an_unreadable_process_tree_is_not_an_install_failure(monkeypatch, caplog):
    """A missing process list is an identification failure, not an install failure."""
    # Arrange
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setattr("gitlab_security_mcp.progress_extension.sys.platform", "win32")

    def broken():
        """Fail while reading the process list."""
        raise OSError("process snapshot failed")

    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension._windows_process_tree", broken
    )

    # Act
    with caplog.at_level(logging.WARNING, logger="gitlab_security_mcp"):
        install_progress_extension()

    # Assert
    assert "Could not identify the editor process" in caplog.text
    assert "Could not install the progress extension" not in caplog.text


def test_an_install_error_does_not_escape_to_the_server(monkeypatch, tmp_path, caplog):
    """A broken extension package is logged and does not stop MCP startup."""
    # Arrange
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension.editor_command",
        lambda *_args: [str(tmp_path / "Cursor.exe"), str(tmp_path / "cli.js")],
    )
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension._windows_process_tree",
        lambda: ({}, {}),
    )
    monkeypatch.setattr("gitlab_security_mcp.progress_extension.sys.platform", "win32")

    def broken(_path):
        """Fail while building the VSIX."""
        raise ValueError("package.json is missing")

    monkeypatch.setattr("gitlab_security_mcp.progress_extension.write_vsix", broken)

    # Act
    with caplog.at_level(logging.WARNING, logger="gitlab_security_mcp"):
        install_progress_extension()

    # Assert
    assert "Could not install the progress extension" in caplog.text
    assert "package.json is missing" in caplog.text
    assert "Could not identify the editor process" not in caplog.text


def test_editor_command_ignores_an_editor_without_its_cli(tmp_path):
    """Do not launch an editor executable that has no CLI script beside it."""
    # Arrange
    image = tmp_path / "Code.exe"
    image.write_bytes(b"")
    parents = {PYTHON_PID: (CURSOR_PID, PYTHON_NAME), CURSOR_PID: (1, "Code.exe")}
    images = {CURSOR_PID: image}

    # Act
    command = editor_command(PYTHON_PID, parents, images)

    # Assert
    assert command is None


def _editor_with_installed(monkeypatch, tmp_path, listing):
    """Fake an editor CLI whose extension list prints ``listing``; return its calls."""
    calls = []
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension._reload_required_version", None
    )
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension.editor_command",
        lambda *_args: [str(tmp_path / "Cursor.exe"), str(tmp_path / "cli.js")],
    )
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension._windows_process_tree",
        lambda: ({}, {}),
    )

    def run(argv, **_kwargs):
        """Answer the list request and record every editor invocation."""
        calls.append(argv)
        stdout = listing if "--list-extensions" in argv else ""
        return type(
            "Completed", (), {"returncode": 0, "stdout": stdout, "stderr": ""}
        )()

    monkeypatch.setattr("gitlab_security_mcp.progress_extension.subprocess.run", run)
    return calls


def _bundled_version():
    """Read the version of the extension this server ships."""
    package = extension_directory() / "package.json"
    return json.loads(package.read_text(encoding="utf-8"))["version"]


def test_an_already_installed_version_is_not_reinstalled(monkeypatch, tmp_path):
    """Startup skips the slow editor install when the same version is present."""
    # Arrange
    listing = f"other.ext@1.0.0\nlocal-security-tools.gitlab-security-progress@{_bundled_version()}\n"
    calls = _editor_with_installed(monkeypatch, tmp_path, listing)

    # Act
    install_progress_extension()

    # Assert
    assert not any("--install-extension" in argv for argv in calls)
    assert reload_required_version() is None


def test_an_upgraded_extension_asks_open_windows_to_reload(monkeypatch, tmp_path):
    """An open window keeps the old extension, so the new version is announced."""
    # Arrange
    listing = "local-security-tools.gitlab-security-progress@0.0.1\n"
    calls = _editor_with_installed(monkeypatch, tmp_path, listing)

    # Act
    install_progress_extension()

    # Assert
    assert any("--install-extension" in argv for argv in calls)
    assert reload_required_version() == _bundled_version()


def test_each_checkout_is_told_once_to_reload_for_a_new_extension(
    monkeypatch, tmp_path
):
    """The progress panel names the new version once per checkout."""
    # Arrange
    from gitlab_security_mcp import server

    published = []
    monkeypatch.setattr(server, "reload_required_version", lambda: "9.9.9")
    monkeypatch.setattr(server, "_extension_reload_notified", set())
    monkeypatch.setattr(
        server,
        "publish_editor_progress",
        lambda *args, **kwargs: published.append(args),
    )

    # Act
    server._editor_progress(tmp_path, "audit", "Audit", "running")
    server._editor_progress(tmp_path, "audit", "Audit", "running")

    # Assert
    notices = [args for args in published if args[1] == "progress-extension"]
    assert len(notices) == 1
    assert "9.9.9" in notices[0][3]
    assert "Reload Window" in notices[0][3]


def test_server_startup_installs_when_an_editor_launched_it(monkeypatch, tmp_path):
    """Reloading the server installs the extension and keeps MCP stdout empty."""
    # Arrange
    calls = []
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension.editor_command",
        lambda *_args: [str(tmp_path / "Cursor.exe"), str(tmp_path / "cli.js")],
    )
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension._windows_process_tree",
        lambda: ({}, {}),
    )

    def run(argv, **kwargs):
        """Record the editor install invocation."""
        calls.append((argv, kwargs))
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr("gitlab_security_mcp.progress_extension.subprocess.run", run)

    # Act
    install_progress_extension()

    # Assert
    argv, kwargs = calls[-1]
    assert "--install-extension" in argv
    assert argv[-1] == "--force"
    assert Path(argv[-2]).name == "gitlab-security-progress.vsix"
    assert kwargs["shell"] is False
    assert kwargs["env"]["ELECTRON_RUN_AS_NODE"] == "1"


def test_two_windows_install_one_editors_extension_one_at_a_time(monkeypatch, tmp_path):
    """Overlapping reloads must not write the same editor extension together."""
    # Arrange
    state = {"current": 0, "peak": 0}
    counter = threading.Lock()
    first_inside = threading.Event()
    release = threading.Event()
    monkeypatch.setenv("GITLAB_SECURITY_INSTALL_LOCK_DIR", str(tmp_path))
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    editor = tmp_path / "Cursor.exe"
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension.editor_command",
        lambda *_args: [str(editor), str(tmp_path / "cli.js")],
    )
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension._windows_process_tree",
        lambda: ({}, {}),
    )

    def run(_argv, **_kwargs):
        """Count installers that are inside the editor command at once."""
        with counter:
            state["current"] += 1
            state["peak"] = max(state["peak"], state["current"])
            entered = state["current"]
        if entered == 1:
            first_inside.set()
            assert release.wait(timeout=5)
        with counter:
            state["current"] -= 1
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr("gitlab_security_mcp.progress_extension.subprocess.run", run)
    first = threading.Thread(target=install_progress_extension)
    second = threading.Thread(target=install_progress_extension)

    # Act
    first.start()
    assert first_inside.wait(timeout=5)
    second.start()
    release.set()
    first.join(timeout=5)
    second.join(timeout=5)

    # Assert
    assert state["peak"] == 1
    assert not first.is_alive()
    assert not second.is_alive()


def test_unit_tests_do_not_install_the_extension(monkeypatch):
    """The test suite must not call the editor installer."""
    # Arrange
    calls = []
    monkeypatch.setattr(
        "gitlab_security_mcp.progress_extension.subprocess.run",
        lambda *_args, **_kwargs: calls.append(True),
    )

    # Act
    install_progress_extension()

    # Assert
    assert calls == []
