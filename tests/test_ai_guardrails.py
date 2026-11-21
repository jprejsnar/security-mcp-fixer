"""Keep Cursor and Copilot startup guidance on one canonical guardrail."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
