"""Keep Cursor and Copilot startup guidance on one canonical guardrail."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_CURSOR_RULE = ROOT / ".cursor" / "rules" / "ai-guardrails.mdc"
_COPILOT = ROOT / ".github" / "copilot-instructions.md"
_AGENT = ROOT / ".cursor" / "agents" / "ai-guardrails.md"
_ALWAYS_APPLY = "alwaysApply: true"
_EVERY_TASK = "Apply to every task"
_STARTUP_ONLY_RULE = "Engine.repo_root"
_EDIT_SOURCE = "Change it only in `ai/guardrails.md`"
_README_UPDATE = "update `README.md` in the same change"
_EDIT_THE_COPY = "Edit this file"
_CURSOR_FRONTMATTER = (
    "---\n"
    "description: Compaction and code-quality guardrails for every session\n"
    "alwaysApply: true\n"
    "---\n\n"
)


def test_ai_guardrails_stay_in_sync():
    """Require both hosts to load the same generated startup files."""
    # Arrange
    script = ROOT / "scripts" / "sync_ai_guardrails.py"

    # Act
    completed = subprocess.run(
        [sys.executable, str(script), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )

    # Assert
    assert completed.returncode == 0, completed.stderr


def test_startup_files_load_once_per_editor():
    """Cursor and VS Code each load one full copy, and agents do not repeat it."""
    # Arrange
    body = (ROOT / "ai" / "guardrails.md").read_text(encoding="utf-8")
    rule = _CURSOR_RULE.read_text(encoding="utf-8")
    copilot = _COPILOT.read_text(encoding="utf-8")
    agent = _AGENT.read_text(encoding="utf-8")

    # Act
    cursor_rule = _CURSOR_FRONTMATTER + body

    # Assert
    assert _EDIT_SOURCE in body
    assert _README_UPDATE in body
    assert "Do not spend host AI tokens" in body
    assert "Run the suite once, after the change is finished, at the end." in body
    assert _EDIT_THE_COPY not in body
    assert _ALWAYS_APPLY in rule
    assert rule == cursor_rule
    assert copilot == body
    assert _EVERY_TASK not in agent
    assert _STARTUP_ONLY_RULE not in agent
    assert not (ROOT / "AGENTS.md").exists()
