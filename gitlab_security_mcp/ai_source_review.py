"""Supply bounded, read-only source evidence for the calling host AI."""

from __future__ import annotations

from pathlib import Path

from gitlab_security_mcp.config_findings import config_kind
from gitlab_security_mcp.manifests import SKIP_DIRS, iter_files
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
        self._files: list[Path] | None = None
        self._truncated = False

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

    def _inventory(self) -> list[Path]:
        """Reuse the repository's pruned, bounded file discovery."""
        if self._files is None:
            files, self._truncated = iter_files(self.root)
            self._files = [
                path
                for path in files
                if path.suffix.lower() in SOURCE_SUFFIXES
                or path.name.lower() in SOURCE_NAMES
                or config_kind(str(path)) is not None
            ]
        return self._files

    def respond(self, action: dict) -> dict:
        """Execute only bounded read, file-discovery, and literal-search actions."""
        if len(action) != 1:
            raise ValueError("AI source review must return exactly one action")
        if "read_files" in action:
            paths = action["read_files"]
            if (
                not isinstance(paths, list)
                or not 1 <= len(paths) <= 10
                or not all(isinstance(path, str) and path for path in paths)
            ):
                raise ValueError("read_files requires 1 to 10 relative paths")
            return {"files": [self.read(path) for path in paths]}
        key = next(iter(action))
        value = action[key]
        if (
            key not in {"list_files", "search_text"}
            or not isinstance(value, str)
            or len(value) > 200
        ):
            raise ValueError("AI source review returned an invalid evidence action")
        rows = []
        searched_bytes = 0
        truncated = self._truncated
        for path in self._inventory():
            relative = str(path.relative_to(self.root))
            if key == "list_files":
                if value.lower() in relative.lower():
                    rows.append(relative)
            else:
                if not value:
                    raise ValueError("search_text must not be empty")
                if path.stat().st_size + searched_bytes > 4_000_000:
                    truncated = True
                    break
                row = read_source_evidence(self.root, relative)
                searched_bytes += len(row["content"].encode("utf-8"))
                for number, line in enumerate(row["content"].splitlines(), 1):
                    if value in line:
                        rows.append(
                            {"path": relative, "line": number, "text": line[:500]}
                        )
                        if len(rows) > 50:
                            break
            if len(rows) > 50:
                truncated = True
                break
        return {"results": rows[:50], "truncated": truncated or self._truncated}

    def validate_review(self, review: dict) -> None:
        """Reject claimed files/hashes that were never supplied in full to the AI."""
        files = review.get("reviewed_files")
        if not isinstance(files, list) or not files:
            raise ValueError("AI source review did not identify its reviewed files")
        for item in files:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise ValueError("AI source review returned an invalid reviewed file")
            path = self._path(item["path"])
            key = str(path.relative_to(self.root.resolve()))
            receipt = self.reads.get(key)
            if receipt is None or item.get("sha256") != receipt["sha256"]:
                raise ValueError(f"AI claimed a file/hash not supplied in full: {key}")
