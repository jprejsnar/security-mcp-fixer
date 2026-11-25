"""Copy the canonical AI guardrail into the Cursor and Copilot startup files.

`ai/common.md` is the shared block. The startup source includes it with
`<!-- include: ai/common.md -->`. Generated files receive that text once.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_COMMON_MARKER = "<!-- include: ai/common.md -->"
_RAISE_COMMON_BLOCK_INCLUDES_ITSELF = "The common AI block cannot include itself"


def expand(text: str) -> str:
    """Insert the shared AI block into a source that marks where it belongs."""
    common = (ROOT / "ai" / "common.md").read_text(encoding="utf-8").strip("\n")
    if _COMMON_MARKER in common:
        raise ValueError(_RAISE_COMMON_BLOCK_INCLUDES_ITSELF)
    return text.replace(_COMMON_MARKER, common)


BODY = expand((ROOT / "ai" / "guardrails.md").read_text(encoding="utf-8"))
SKILL = expand((ROOT / "ai" / "skill.md").read_text(encoding="utf-8"))
AGENT = expand((ROOT / "ai" / "agent.md").read_text(encoding="utf-8"))
RULE = (
    "---\n"
    "description: Compaction and code-quality guardrails for every session\n"
    "alwaysApply: true\n"
    "---\n\n"
    f"{BODY}"
)
TARGETS = {
    ".github/copilot-instructions.md": BODY,
    ".cursor/rules/ai-guardrails.mdc": RULE,
    ".github/agents/ai-guardrails.agent.md": AGENT,
    ".cursor/agents/ai-guardrails.md": AGENT,
    ".github/skills/ai-guardrails/SKILL.md": SKILL,
    ".cursor/skills/ai-guardrails/SKILL.md": SKILL,
}


def main() -> int:
    """Write the shared guardrail, or fail when a generated copy has drifted."""
    check = "--check" in sys.argv[1:]
    drifted = []
    for relative, content in TARGETS.items():
        path = ROOT / relative
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current != content:
            drifted.append(relative)
            if not check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8", newline="\n")
    if check and drifted:
        print("AI guardrail copies differ: " + ", ".join(drifted), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
