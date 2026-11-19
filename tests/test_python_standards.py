"""Enforce source compatibility, lint conventions, and documentation coverage."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = sorted((ROOT / "gitlab_security_mcp").glob("*.py")) + [
    ROOT / "server.py"
]
PYTHON_FILES = SOURCE_FILES + sorted((ROOT / "tests").glob("*.py"))
SUBPROCESS_CALLS = {"call", "check_call", "check_output", "Popen", "run"}


def implicit_text_encodings(tree: ast.AST) -> list[ast.Call]:
    """Return text I/O and text-mode subprocess calls that omit ``encoding``."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or any(
            keyword.arg == "encoding" for keyword in node.keywords
        ):
            continue
        func = node.func
        name = getattr(func, "attr", getattr(func, "id", None))
        keywords = {keyword.arg: keyword.value for keyword in node.keywords}
        if name in {"read_text", "write_text"}:
            found.append(node)
        elif name == "open" and not (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "tarfile"
        ):
            position = 1 if isinstance(func, ast.Name) else 0
            mode = keywords.get("mode")
            if mode is None and len(node.args) > position:
                mode = node.args[position]
            value = mode.value if isinstance(mode, ast.Constant) else "r"
            if not (isinstance(value, str) and "b" in value):
                found.append(node)
        elif name in SUBPROCESS_CALLS and any(
            isinstance(keywords.get(flag), ast.Constant)
            and keywords[flag].value is True
            for flag in ("text", "universal_newlines")
        ):
            found.append(node)
    return found


@pytest.mark.parametrize(
    "source_path", PYTHON_FILES, ids=lambda path: path.relative_to(ROOT).as_posix()
)
def test_python_objects_are_documented(source_path):
    """Require docstrings or leading intent comments on every named object."""
    # Arrange
    source = source_path.read_text(encoding="utf-8")
    lines = source.splitlines()
    tree = ast.parse(source, filename=str(source_path))
    missing = []

    # Act
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            continue
        if ast.get_docstring(node):
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            leading = lines[node.lineno : node.body[0].lineno - 1]
            if any(line.strip().startswith("# ") for line in leading):
                continue
        missing.append(
            f"{getattr(node, 'name', 'module')}:{getattr(node, 'lineno', 1)}"
        )

    # Assert
    assert not missing, "Missing documentation: " + ", ".join(missing)


@pytest.mark.parametrize(
    "source_path", PYTHON_FILES, ids=lambda path: path.relative_to(ROOT).as_posix()
)
def test_text_io_declares_encoding(source_path):
    """Keep text decoding identical on Python 3.11 and 3.15's UTF-8 default."""
    # Arrange
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))

    # Act
    missing = [
        f"{node.lineno}: {ast.unparse(node.func)}"
        for node in implicit_text_encodings(tree)
    ]

    # Assert
    assert not missing, "Text I/O without encoding: " + ", ".join(missing)


@pytest.mark.parametrize("mode", ["check", "format"])
def test_python_lint_standards(mode):
    """Require both repository lint conventions and stable formatter output."""
    # Arrange
    command = [sys.executable, "-m", "ruff", mode]
    if mode == "format":
        command.append("--check")
    command.extend(["gitlab_security_mcp", "server.py", "tests"])

    # Act
    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )

    # Assert
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "source_path",
    sorted((ROOT / "tests").glob("test_*.py")),
    ids=lambda path: path.name,
)
def test_unit_tests_follow_arrange_act_assert(source_path):
    """Require a docstring and commented Arrange, Act, and Assert sections."""
    # Arrange
    source = source_path.read_text(encoding="utf-8")
    lines = source.splitlines()
    tree = ast.parse(source, filename=str(source_path))
    missing = []

    # Act
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("test_"):
            continue
        if not ast.get_docstring(node):
            missing.append(f"{node.name}: docstring")
        body = lines[node.lineno - 1 : node.end_lineno]
        found = {line.strip() for line in body}
        for label in ("# Arrange", "# Act", "# Assert"):
            if label not in found:
                missing.append(f"{node.name}: {label}")

    # Assert
    assert not missing, "\n".join(missing)


@pytest.mark.parametrize("source_path", SOURCE_FILES, ids=lambda path: path.name)
def test_source_retains_python_311_syntax(source_path):
    """Parse production modules with the Python 3.11 grammar."""
    # Arrange
    source = source_path.read_text(encoding="utf-8")

    # Act
    tree = ast.parse(source, filename=str(source_path), feature_version=(3, 11))

    # Assert
    assert isinstance(tree, ast.Module)
