"""Version comparison, npm range checks, and advisory range evaluation."""

from __future__ import annotations

import re
from collections.abc import Callable

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

_FIXED_IN = re.compile(
    r"\b(?:upgrade(?:d)? to|update to|fixed in|patched in)(?:\s+version)?\s+v?(\d+\.\d+(?:\.\d+)?[0-9A-Za-z.+-]*)",
    re.IGNORECASE,
)


def parse_version(value: str | None) -> Version | None:
    """Parse a version string, accepting a leading ``v``. Return None if unparseable."""
    if not value:
        return None
    text = value.strip()
    if text.startswith("v") and text[1:2].isdigit():
        text = text[1:]
    # Maven timestamps and build metadata are kept when packaging can read them.
    try:
        return Version(text)
    except InvalidVersion:
        return None


def parse_fixed_versions(solution: str | None) -> list[str]:
    """Pull versions out of solution text such as 'Upgrade to version 1.2.3'."""
    if not solution:
        return []
    found: list[str] = []
    for match in _FIXED_IN.finditer(solution):
        version = match.group(1).rstrip(".,);")
        if version not in found:
            found.append(version)
    return found


def lowest_fixed(installed: str | None, fixed_versions: list[str]) -> str | None:
    """Smallest published fix that is strictly newer than the installed version."""
    current = parse_version(installed)
    if current is None:
        # Without a comparable installed version, the lowest parsed fix is the floor.
        parsed = [(parse_version(raw), raw) for raw in fixed_versions]
        usable = [
            (parsed_version, raw)
            for parsed_version, raw in parsed
            if parsed_version is not None
        ]
        if not usable:
            return None
        usable.sort(key=lambda item: item[0])
        return usable[0][1]
    candidates: list[tuple[Version, str]] = []
    for raw in fixed_versions:
        parsed = parse_version(raw)
        if parsed is not None and parsed > current:
            candidates.append((parsed, raw))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1]


def first_unaffected(
    installed: str | None,
    fixed_versions: list[str],
    is_affected: Callable[[str], bool],
) -> str | None:
    """Return the smallest fix newer than ``installed`` that is not itself affected."""
    current = parse_version(installed)
    candidates: list[tuple[Version, str]] = []
    for raw in fixed_versions:
        parsed = parse_version(raw)
        if parsed is not None and (current is None or parsed > current):
            candidates.append((parsed, raw))
    for _parsed, raw in sorted(candidates, key=lambda item: item[0]):
        if not is_affected(raw):
            return raw
    return None


def is_major_upgrade(installed: str | None, target: str | None) -> bool:
    """Return whether moving to ``target`` crosses a major version (or a 0.x minor)."""
    current = parse_version(installed)
    wanted = parse_version(target)
    if current is None or wanted is None:
        return False
    if current.major != wanted.major:
        return True
    return current.major == 0 and current.minor != wanted.minor


def npm_to_specifier(spec: str) -> str | None:
    """Convert a common npm range into a PEP 440 specifier set, if it is one range."""
    text = spec.strip()
    if not text or text.startswith(
        ("workspace:", "file:", "link:", "catalog:", "npm:", "git", "http")
    ):
        return None
    if text.startswith("^"):
        base = parse_version(text[1:])
        if base is None:
            return None
        parts = text[1:].split(".")
        if (
            base.major == 0
            and len(parts) >= 2
            and parts[1].isdigit()
            and int(parts[1]) != 0
        ):
            return f">={text[1:]},<{base.major}.{base.minor + 1}.0"
        if base.major == 0:
            return f">={text[1:]},<{base.major}.{base.minor}.{base.micro + 1}"
        return f">={text[1:]},<{base.major + 1}.0.0"
    if text.startswith("~"):
        base = parse_version(text[1:])
        if base is None:
            return None
        return f">={text[1:]},<{base.major}.{base.minor + 1}.0"
    if text[:1].isdigit():
        if parse_version(text) is None:
            return None
        return f"=={text}"
    if text[:1] in (">", "<", "="):
        return ",".join(part.strip() for part in text.split())
    return None


def range_allows(spec: str | None, version: str) -> bool:
    """Return whether an npm spec already accepts ``version``."""
    if not spec:
        return False
    converted = npm_to_specifier(spec)
    if converted is None:
        return False
    parsed = parse_version(version)
    if parsed is None:
        return False
    try:
        return parsed in SpecifierSet(converted)
    except InvalidSpecifier:
        return False


def bump_npm_spec(old_spec: str, fixed: str) -> str | None:
    """Raise the floor of an npm spec to the fixed version, preserving ^ or ~."""
    text = old_spec.strip()
    if text.startswith(
        ("workspace:", "file:", "link:", "catalog:", "npm:", "git", "http")
    ):
        return None
    if text.startswith("^") or text.startswith("~"):
        return f"{text[0]}{fixed}"
    if text[:1].isdigit():
        return fixed
    if text.startswith(">="):
        replaced, count = re.subn(r">=\s*v?[0-9][^\s,]*", f">={fixed}", text, count=1)
        return replaced if count else None
    return None


def _event_value(event: dict, key: str) -> Version | None:
    """Parse one OSV bound, treating an introduced zero as unbounded."""
    if key not in event:
        return None
    raw = str(event[key])
    if raw in {"0", "0.0.0"} and key == "introduced":
        return Version("0")
    return parse_version(raw)


def range_contains(version: str, events: list[dict]) -> bool | None:
    """OSV range events. None means the version could not be compared."""
    current = parse_version(version)
    if current is None:
        return None
    affected = False
    saw_bound = False
    for event in events:
        introduced = _event_value(event, "introduced")
        fixed = _event_value(event, "fixed")
        last_affected = _event_value(event, "last_affected")
        if "introduced" in event:
            if introduced is None and str(event.get("introduced")) not in {
                "0",
                "0.0.0",
            }:
                return None
            saw_bound = True
            if introduced is not None and current >= introduced:
                affected = True
        elif "fixed" in event:
            if fixed is None:
                return None
            saw_bound = True
            if current >= fixed:
                affected = False
        elif "last_affected" in event:
            if last_affected is None:
                return None
            saw_bound = True
            if current > last_affected:
                affected = False
    if not saw_bound:
        return None
    return affected


def osv_version_affected(version: str | None, affected_entry: dict) -> bool | None:
    """Evaluate one OSV ``affected`` entry. None means it could not be decided."""
    if not version:
        return None
    explicit = [str(item) for item in affected_entry.get("versions") or []]
    if version in explicit or version.lstrip("v") in {
        item.lstrip("v") for item in explicit
    }:
        return True
    ranges = affected_entry.get("ranges") or []
    if not ranges and not explicit:
        return None
    decisions: list[bool] = []
    unknown = False
    for item in ranges:
        if item.get("type") not in {None, "ECOSYSTEM", "SEMVER", "GIT"}:
            continue
        if item.get("type") == "GIT":
            unknown = True
            continue
        result = range_contains(version, item.get("events") or [])
        if result is None:
            unknown = True
        else:
            decisions.append(result)
    if any(decisions):
        return True
    if decisions and not unknown:
        return False
    if explicit and version not in explicit and not ranges:
        return False
    if unknown:
        return None
    if explicit:
        return False
    return None


def collect_fixed_versions(affected_entries: list[dict]) -> list[str]:
    """Return every parseable ``fixed`` event, in first-seen order."""
    found: list[str] = []
    for entry in affected_entries:
        for item in entry.get("ranges") or []:
            for event in item.get("events") or []:
                fixed = event.get("fixed")
                if fixed is None:
                    continue
                text = str(fixed)
                if text and text not in found and parse_version(text) is not None:
                    found.append(text)
    return found


def describe_ranges(affected_entries: list[dict]) -> list[str]:
    """Render OSV ranges as short '>=a,<b' strings for the report."""
    described: list[str] = []
    for entry in affected_entries:
        for item in entry.get("ranges") or []:
            introduced = None
            fixed = None
            last_affected = None
            for event in item.get("events") or []:
                if "introduced" in event:
                    introduced = event.get("introduced")
                if "fixed" in event:
                    fixed = event.get("fixed")
                if "last_affected" in event:
                    last_affected = event.get("last_affected")
            parts: list[str] = []
            if introduced not in (None, ""):
                parts.append(f">={introduced}")
            if fixed not in (None, ""):
                parts.append(f"<{fixed}")
            elif last_affected not in (None, ""):
                parts.append(f"<={last_affected}")
            if parts:
                described.append(",".join(str(part) for part in parts))
    return described
