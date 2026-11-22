"""Install the progress extension into the editor that started the server."""

import json
import threading
import zipfile
from pathlib import Path

from gitlab_security_mcp.progress_extension import (
    _linux_process_tree,
    _process_tree_from_ps,
    editor_command,
    extension_directory,
    install_progress_extension,
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
    argv, kwargs = calls[0]
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
