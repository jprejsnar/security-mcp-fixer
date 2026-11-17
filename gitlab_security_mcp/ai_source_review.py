"""Supply bounded, read-only source evidence for the calling host AI."""

from __future__ import annotations

from pathlib import Path

from gitlab_security_mcp.config_findings import config_kind
from gitlab_security_mcp.manifests import SKIP_DIRS
from gitlab_security_mcp.source_findings import read_source_evidence
from gitlab_security_mcp.util import resolve_inside

MAX_REVIEW_BYTES = 256_000
SOURCE_SUFFIXES = {
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".cs",
    ".fs",
    ".vb",
    ".java",
    ".kt",
    ".py",
    ".pyw",
    ".pyi",
    ".csproj",
    ".fsproj",
    ".vbproj",
    ".props",
    ".targets",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".properties",
    ".toml",
    ".ini",
    ".cfg",
    ".config",
    ".gradle",
    ".kts",
    ".sql",
    ".html",
    ".cshtml",
    ".razor",
    ".vue",
    ".svelte",
}
SOURCE_NAMES = {"dockerfile", "jenkinsfile", "requirements.txt", "pipfile"}


class SourceEvidence:
    """Keep host AI file access inside source/configuration files in one checkout."""

    def __init__(self, root: Path):
        """Bound the combined complete-file evidence and retain read receipts."""
        self.root = root.resolve()
        self.reads: dict[str, dict] = {}
        self.bytes_read = 0

    def _path(self, relative: str) -> Path:
        """Reject traversal, generated directories, and non-source files."""
        path = resolve_inside(self.root, relative)
        if path is None or not path.is_file():
            raise ValueError(f"Not a file inside the checkout: {relative}")
        parts = path.relative_to(self.root.resolve()).parts
        if any(part.lower() in SKIP_DIRS for part in parts[:-1]) or (
            path.suffix.lower() not in SOURCE_SUFFIXES
            and path.name.lower() not in SOURCE_NAMES
            and config_kind(str(path)) is None
        ):
            raise ValueError(f"Not a permitted source/configuration file: {relative}")
        return path

    def read(self, relative: str) -> dict:
        """Supply a complete file and its hash, never a silently clipped excerpt."""
        path = self._path(relative)
        key = str(path.relative_to(self.root.resolve()))
        if key not in self.reads:
            row = read_source_evidence(self.root, key)
            size = len(row["content"].encode("utf-8"))
            if self.bytes_read + size > MAX_REVIEW_BYTES:
                raise ValueError(
                    "AI source review exceeded its complete-file evidence budget"
                )
            self.bytes_read += size
            self.reads[key] = row
        return self.reads[key]


def cited_lines(row: dict, source: str) -> dict:
    """Return the cited line and a short window, never the whole file body.

    The host reads the checkout itself. The hash still covers the complete
    file the server read, so a changed file cannot reuse this citation.
    """
    cited = row.get("cited_text", "")
    if cited and cited not in source:
        raise ValueError("Cited text is not in the file the server hashed")
    context = row.get("context")
    return {
        "path": row["path"],
        "sha256": row["sha256"],
        "line": row.get("line"),
        "cited_text": cited,
        "context": list(context) if isinstance(context, list) else [],
    }
