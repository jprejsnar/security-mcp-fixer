"""Enforce source compatibility, lint conventions, and documentation coverage."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = sorted((ROOT / "gitlab_security_mcp").glob("*.py")) + [ROOT / "server.py"]
PYTHON_FILES = SOURCE_FILES + sorted((ROOT / "tests").glob("*.py"))


@pytest.mark.parametrize("source_path", PYTHON_FILES, ids=lambda path: path.relative_to(ROOT).as_posix())
def test_python_objects_are_documented(source_path):
    """Require docstrings or leading intent comments on every named object."""
    # Arrange
    source = source_path.read_text(encoding="utf-8")
    lines = source.splitlines()
    tree = ast.parse(source, filename=str(source_path))
    missing = []

    # Act
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if ast.get_docstring(node):
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            leading = lines[node.lineno:node.body[0].lineno - 1]
            if any(line.strip().startswith("# ") for line in leading):
                continue
        missing.append(f"{getattr(node, 'name', 'module')}:{getattr(node, 'lineno', 1)}")

    # Assert
    assert not missing, "Missing documentation: " + ", ".join(missing)


def test_python_lint_standards():
    # Arrange
    command = [sys.executable, "-m", "ruff", "check", "gitlab_security_mcp", "server.py", "tests"]

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


@pytest.mark.parametrize("source_path", SOURCE_FILES, ids=lambda path: path.name)
def test_source_retains_python_311_syntax(source_path):
    # Arrange
    source = source_path.read_text(encoding="utf-8")

    # Act
    tree = ast.parse(source, filename=str(source_path), feature_version=(3, 11))

    # Assert
    assert isinstance(tree, ast.Module)
