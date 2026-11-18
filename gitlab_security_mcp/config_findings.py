"""Plan line-bound fixes for Dockerfile, nginx, and GitLab CI findings.

Only the cited instruction can change. A rule applies only when its current
publisher pages are read again before the edit. GitLab solution text is never
written into the file. Unpinned Alpine ``apk add`` packages receive a minimum
version published by the Alpine branch the stage evidently uses.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from gitlab_security_mcp.alpine_packages import AlpineLookupError, ApkPins
from gitlab_security_mcp.remediate import Plan
from gitlab_security_mcp.util import atomic_write_text, resolve_inside

# GitLab documents these as the variables that skip security jobs when "true".
_SECURITY_DISABLED = frozenset(
    {
        "SAST_DISABLED",
        "DEPENDENCY_SCANNING_DISABLED",
        "CONTAINER_SCANNING_DISABLED",
        "SECRET_DETECTION_DISABLED",
        "DAST_DISABLED",
    }
)
_SERVER_TOKENS = re.compile(
    r"^(\s*)server_tokens(\s+)on(\s*;\s*)(#.*)?$", re.IGNORECASE
)
_AUTOINDEX = re.compile(r"^(\s*)autoindex(\s+)on(\s*;\s*)(#.*)?$", re.IGNORECASE)
_SSL_PROTOCOLS = re.compile(
    r"^(\s*ssl_protocols\s+)(.+?)(\s*;\s*(?:#.*)?)?$", re.IGNORECASE
)
_OBSOLETE_TLS = frozenset({"tlsv1", "tlsv1.1"})
_GITLAB_VARIABLE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*:\s*)(.*)$")
_NGINX_CORE = "https://nginx.org/en/docs/http/ngx_http_core_module.html"
_NGINX_AUTOINDEX = "https://nginx.org/en/docs/http/ngx_http_autoindex_module.html"
_NGINX_SSL = "https://nginx.org/en/docs/http/ngx_http_ssl_module.html"
_GITLAB_SCANS = "https://docs.gitlab.com/user/application_security/policies/scan_execution_policies/"
KICS_APK_UNPINNED = "d3499f6d-1651-41bb-a9a7-de925fea487b"
_KICS_APK_TITLE = "unpinned package version in apk add"
_KICS_APK_PAGE = (
    f"https://docs.kics.io/latest/queries/dockerfile-queries/{KICS_APK_UNPINNED}/"
)
_DOCKER_PINNING = "https://docs.docker.com/build/building/best-practices/"
_ALPINE_RELEASES_PAGE = "https://alpinelinux.org/releases/"
_APK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]*")
_APK_PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9+._-]*)=(\S+)")
_APK_MINIMUM = re.compile(
    r"""(["'])[A-Za-z0-9][A-Za-z0-9+._-]*>=[A-Za-z0-9][A-Za-z0-9+._-]*\1"""
)
# A fuzzy ``name~version`` constraint is already restricted; it is neither edited nor evidence.
_APK_RANGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._-]*~\S+")
_SEPARATORS = frozenset({"&&", "||", ";", "|"})
# apk options that consume the following word; any other unknown option stops the edit.
_APK_VALUE_OPTIONS = frozenset(
    {
        "-t",
        "--virtual",
        "-X",
        "--repository",
        "-p",
        "--root",
        "--arch",
        "--keys-dir",
        "--cache-dir",
        "--repositories-file",
        "--cache-max-age",
        "--timeout",
        "--wait",
    }
)
_APK_FLAG_OPTIONS = frozenset(
    {
        "--no-cache",
        "-U",
        "--update-cache",
        "--update",
        "-u",
        "--upgrade",
        "-l",
        "--latest",
        "-q",
        "--quiet",
        "-v",
        "--verbose",
        "-i",
        "--interactive",
        "--no-interactive",
        "--progress",
        "--no-progress",
        "--initdb",
        "--no-network",
        "--allow-untrusted",
        "--force-overwrite",
        "--force-broken-world",
        "--force-non-repository",
        "--force-refresh",
        "--no-scripts",
        "--no-check-certificate",
        "--clean-protected",
        "--usermode",
        "-s",
        "--simulate",
        "--no-logfile",
        "--no-commit-hooks",
    }
)
ApkResolver = Callable[[str | None, dict[str, str], list[str]], ApkPins]


@dataclass(frozen=True)
class ConfigAssessment:
    """A config finding that is missing, needs review, or has a line plan."""

    decision: str
    reason: str
    plan: Plan | None = None
    sources: tuple[str, ...] = ()


def config_kind(file_path: str | None) -> str | None:
    """Classify a finding path as a Dockerfile, nginx config, or GitLab CI file."""
    if not file_path or not isinstance(file_path, str):
        return None
    path = Path(file_path.replace("\\", "/"))
    name = path.name.lower()
    if (
        name == "dockerfile"
        or name.startswith("dockerfile.")
        or name.endswith(".dockerfile")
    ):
        return "dockerfile"
    parents = {part.lower() for part in path.parts}
    if (
        name == "nginx.conf"
        or name.endswith(".nginx")
        or (name.endswith(".conf") and parents & {"nginx", "conf.d", "sites-enabled"})
    ):
        return "nginx"
    if name in {".gitlab-ci.yml", ".gitlab-ci.yaml"} or (
        ".gitlab" in parents and name.endswith((".yml", ".yaml"))
    ):
        return "gitlab_ci"
    return None


def assess_config(
    root: Path, finding: dict, *, apk_versions: ApkResolver | None = None
) -> ConfigAssessment:
    """Match the cited line to a documented edit, or explain why none applies.

    Missing files can support a false positive. A present file with no
    matching documented edit stays on manual review and is not rewritten
    from the scanner title. ``apk_versions`` supplies current Alpine package
    versions for the KICS unpinned apk rule; without it that rule stays manual.
    """
    location = finding.get("location") or {}
    raw = location.get("file")
    kind = config_kind(raw if isinstance(raw, str) else None)
    if kind is None:
        return ConfigAssessment(
            "manual", "The finding is not a recognized configuration file."
        )
    resolved = resolve_inside(root, raw)
    label = _label(kind)
    if resolved is None:
        return ConfigAssessment(
            "manual",
            f"{raw} is outside the repository, so the {label} finding was not changed.",
        )
    if not resolved.is_file():
        return ConfigAssessment(
            "missing",
            f"{raw} is not present in the repository.",
        )
    try:
        with resolved.open(encoding="utf-8", newline="") as stream:
            lines = stream.read().splitlines()
    except OSError as exc:
        return ConfigAssessment("manual", f"The {label} file could not be read: {exc}")
    cited = _cited(lines, location.get("startLine"))
    if cited is None:
        return ConfigAssessment(
            "manual",
            f"The {label} finding does not cite a line, so no configuration edit was guessed.",
        )
    number, line = cited
    if kind == "dockerfile" and _is_apk_pin_finding(finding):
        assessment = _apk_pin_plan(lines, number, apk_versions)
        if assessment.plan is not None:
            assessment.plan.files = [Path(str(raw).replace("\\", "/")).as_posix()]
        return assessment
    edit = _edit(kind, number, line)
    if edit is not None:
        edit.files = [Path(str(raw).replace("\\", "/")).as_posix()]
    if edit is None:
        return ConfigAssessment(
            "manual",
            f"The cited {label} line has no one-line edit that the current official docs describe. "
            "The file was left unchanged.",
        )
    return ConfigAssessment("plan", edit.description, edit)


def apply_config_line(root: Path, plan: Plan) -> list[str]:
    """Replace the planned lines only when every one still matches the review.

    The write preserves line endings. A changed or missing line fails closed
    before anything is written, so a stale plan cannot edit another statement.
    """
    edits = plan.line_edits or (
        {
            "line": plan.line,
            "expected": plan.expected_line,
            "replacement": plan.replacement_line,
        },
    )
    if not plan.files or any(
        edit.get("line") is None
        or edit.get("expected") is None
        or edit.get("replacement") is None
        for edit in edits
    ):
        raise ValueError("The configuration plan does not name exact lines.")
    if any(
        "\n" in edit["replacement"] or "\r" in edit["replacement"] for edit in edits
    ):
        raise ValueError("A configuration replacement cannot add lines.")
    if len({edit["line"] for edit in edits}) != len(edits):
        raise ValueError("A configuration plan cannot edit the same line twice.")
    relative = plan.files[0]
    resolved = resolve_inside(root, relative)
    if resolved is None or not resolved.is_file():
        raise ValueError(f"{relative} is not a file inside the repository.")
    with resolved.open(encoding="utf-8", newline="") as stream:
        text = stream.read()
    ending = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    for edit in edits:
        index = int(edit["line"]) - 1
        if index < 0 or index >= len(lines) or lines[index] != edit["expected"]:
            raise ValueError(
                "The cited line no longer matches the planned configuration."
            )
    for edit in edits:
        lines[int(edit["line"]) - 1] = edit["replacement"]
    updated = ending.join(lines)
    if text.endswith(("\n", "\r\n")):
        updated += ending
    atomic_write_text(resolved, updated)
    return [relative]


def _is_apk_pin_finding(finding: dict) -> bool:
    """Recognize the KICS unpinned apk rule by its query ID or exact title."""
    identifiers = {str(item).lower() for item in finding.get("identifiers") or []}
    title = str(finding.get("title") or "").strip().casefold()
    return KICS_APK_UNPINNED in identifiers or title == _KICS_APK_TITLE


@dataclass(frozen=True)
class _Instruction:
    """One logical Dockerfile instruction and its physical line span."""

    start: int
    end: int
    keyword: str


@dataclass(frozen=True)
class _Word:
    """One shell word with its physical position, so an edit touches only it."""

    line: int
    start: int
    end: int
    text: str


def _instructions(lines: list[str]) -> list[_Instruction] | None:
    """Group continuation lines; None when a non-backslash escape is declared."""
    index = 0
    while index < len(lines):
        directive = re.match(r"\s*#\s*([A-Za-z]+)\s*=\s*(\S+)", lines[index])
        if directive is None:
            break
        if directive.group(1).lower() == "escape" and directive.group(2) != "\\":
            return None
        index += 1
    found = []
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        end = index
        while lines[end].rstrip().endswith("\\"):
            following = end + 1
            while following < len(lines) and (
                not lines[following].strip()
                or lines[following].lstrip().startswith("#")
            ):
                following += 1
            if following >= len(lines):
                break
            end = following
        found.append(_Instruction(index, end, stripped.split(None, 1)[0].upper()))
        index = end + 1
    return found


def _words(lines: list[str], instruction: _Instruction) -> list[_Word]:
    """Split an instruction into positioned words, without its keyword or comments."""
    words = []
    for number in range(instruction.start, instruction.end + 1):
        text = lines[number]
        if number != instruction.start and (
            not text.strip() or text.lstrip().startswith("#")
        ):
            continue
        stripped = text.rstrip()
        limit = len(stripped) - 1 if stripped.endswith("\\") else len(text)
        offset = 0
        if number == instruction.start:
            keyword = re.match(r"\s*\S+", text)
            offset = keyword.end() if keyword else 0
        words.extend(
            _Word(number, match.start(), match.end(), match.group())
            for match in re.finditer(r"\S+", text[:limit])
            if match.start() >= offset
        )
    return words


def _expand(value: str, scope: dict[str, str | None]) -> str | None:
    """Substitute ${NAME} and $NAME from ARG defaults; None when any value is unknown."""
    unknown = False

    def replace(match: re.Match[str]) -> str:
        """Return the known default or mark the whole value unknown."""
        nonlocal unknown
        name = match.group(1) or match.group(2)
        known = scope.get(name)
        if known is None:
            unknown = True
            return ""
        return known

    expanded = re.sub(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", replace, value
    )
    return None if unknown or "$" in expanded else expanded


def _arg_defaults(words: list[_Word]) -> dict[str, str | None]:
    """Read ``ARG NAME[=default]`` declarations, stripping simple quotes."""
    values: dict[str, str | None] = {}
    for word in words:
        name, separator, default = word.text.partition("=")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        if separator:
            values[name] = default.strip("\"'")
        else:
            values[name] = None
    return values


def _apk_packages(
    lines: list[str], instruction: _Instruction
) -> tuple[list[_Word], str | None]:
    """Return package words of every ``apk add`` in one shell-form RUN.

    The second value names why the instruction cannot be edited safely.
    """
    words = _words(lines, instruction)
    while words and words[0].text.startswith("--"):
        words.pop(0)
    if not words:
        return [], "The RUN instruction has no command."
    if words[0].text.startswith("["):
        return [], "Exec-form RUN instructions are not edited automatically."
    text = " ".join(
        word.text for word in words if not _APK_MINIMUM.fullmatch(word.text)
    )
    if re.search(r"[\"'`]|\$\(|<<", text):
        return (
            [],
            "The RUN instruction uses quotes, command substitution or a heredoc, "
            "so its apk packages cannot be identified exactly.",
        )
    segments: list[list[_Word]] = [[]]
    for word in words:
        if word.text in _SEPARATORS:
            segments.append([])
        elif not _APK_MINIMUM.fullmatch(word.text) and re.search(
            r"[;&|<>()]", word.text
        ):
            return (
                [],
                f"The shell word {word.text!r} combines commands, so the apk packages "
                "cannot be identified exactly.",
            )
        else:
            segments[-1].append(word)
    packages: list[_Word] = []
    for segment in segments:
        position = 0
        while position < len(segment) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*=\S*", segment[position].text
        ):
            position += 1
        if (
            position >= len(segment)
            or segment[position].text.rsplit("/", 1)[-1] != "apk"
        ):
            continue
        position += 1
        subcommand = None
        expects_value = False
        for word in segment[position:]:
            if expects_value:
                expects_value = False
                continue
            if word.text.startswith("-"):
                option = word.text.split("=", 1)[0]
                if option in _APK_VALUE_OPTIONS:
                    expects_value = "=" not in word.text
                    continue
                if option in _APK_FLAG_OPTIONS:
                    continue
                return [], f"The apk option {word.text!r} is not recognized."
            if subcommand is None:
                subcommand = word.text
                if subcommand != "add":
                    break
                continue
            if _APK_RANGE.fullmatch(word.text) or _APK_MINIMUM.fullmatch(word.text):
                continue
            if (
                not _APK_PIN.fullmatch(word.text) and not _APK_NAME.fullmatch(word.text)
            ) or word.text.lower().endswith(".apk"):
                return (
                    [],
                    f"The apk add argument {word.text!r} is not a plain package name "
                    "or name=version pin.",
                )
            packages.append(word)
    return packages, None


def _stage_context(
    lines: list[str], instructions: list[_Instruction], target: _Instruction
) -> tuple[str | None, dict[str, str]]:
    """Return the root image and resolved exact apk pins for the target's stage chain."""
    global_args: dict[str, str | None] = {}
    stages: list[dict] = []
    for instruction in instructions:
        if instruction.keyword == "FROM":
            words = [
                word.text
                for word in _words(lines, instruction)
                if not word.text.startswith("--")
            ]
            image = _expand(words[0], global_args) if words else None
            alias = (
                words[2].lower()
                if len(words) >= 3 and words[1].upper() == "AS"
                else None
            )
            parent = next(
                (
                    stage
                    for stage in stages
                    if image and stage["alias"] == image.lower()
                ),
                None,
            )
            stages.append(
                {
                    "alias": alias,
                    "image": parent["image"] if parent else image,
                    "args": {},
                    "pins": dict(parent["pins"]) if parent else {},
                    "instructions": [],
                }
            )
            continue
        if instruction.keyword == "ARG":
            declared = _arg_defaults(_words(lines, instruction))
            if not stages:
                global_args.update(declared)
                continue
            for name, default in declared.items():
                stages[-1]["args"][name] = (
                    default if default is not None else global_args.get(name)
                )
            continue
        if not stages:
            continue
        stages[-1]["instructions"].append(instruction)
        if instruction.keyword != "RUN":
            continue
        packages, reason = _apk_packages(lines, instruction)
        if reason is not None:
            continue
        for word in packages:
            pin = _APK_PIN.fullmatch(word.text)
            if pin is None:
                continue
            version = _expand(pin.group(2), stages[-1]["args"])
            if version and _APK_NAME.fullmatch(version):
                stages[-1]["pins"][pin.group(1)] = version
        if instruction == target:
            return stages[-1]["image"], dict(stages[-1]["pins"])
    return None, {}


def _apk_pin_plan(
    lines: list[str], number: int, resolver: ApkResolver | None
) -> ConfigAssessment:
    """Require at least the current version for each bare package in the cited RUN."""
    instructions = _instructions(lines)
    if instructions is None:
        return ConfigAssessment(
            "manual",
            "The Dockerfile declares a non-default escape character, so apk "
            "instructions were not edited automatically.",
        )
    target = next(
        (item for item in instructions if item.start <= number - 1 <= item.end), None
    )
    if target is None or target.keyword != "RUN":
        return ConfigAssessment(
            "manual",
            "The cited Dockerfile line is not part of a RUN instruction, so no apk "
            "package was pinned.",
        )
    packages, reason = _apk_packages(lines, target)
    if reason is not None:
        return ConfigAssessment(
            "manual", reason + " The Dockerfile was left unchanged."
        )
    unpinned = [word for word in packages if _APK_PIN.fullmatch(word.text) is None]
    if not unpinned:
        return ConfigAssessment(
            "manual",
            "Every apk add package in the cited RUN instruction is already pinned. "
            "The Dockerfile was left unchanged.",
        )
    if resolver is None:
        return ConfigAssessment(
            "manual",
            "Current Alpine package versions could not be looked up, so the apk "
            "packages were not pinned.",
        )
    image, pins = _stage_context(lines, instructions, target)
    names = list(dict.fromkeys(word.text for word in unpinned))
    try:
        found = resolver(image, pins, names)
    except AlpineLookupError as exc:
        return ConfigAssessment(
            "manual",
            f"{exc} The apk packages were not pinned; the Dockerfile was left unchanged.",
        )
    missing = [name for name in names if not found.versions.get(name)]
    if missing:
        return ConfigAssessment(
            "manual",
            f"No current Alpine {found.branch} version was found for "
            f"{', '.join(missing)}; the Dockerfile was left unchanged.",
        )
    edits = []
    for line_number in sorted({word.line for word in unpinned}):
        replacement = lines[line_number]
        for word in sorted(
            (item for item in unpinned if item.line == line_number),
            key=lambda item: item.start,
            reverse=True,
        ):
            replacement = (
                replacement[: word.start]
                + f'"{word.text}>={found.versions[word.text]}"'
                + replacement[word.end :]
            )
        edits.append(
            {
                "line": line_number + 1,
                "expected": lines[line_number],
                "replacement": replacement,
            }
        )
    pairs = ", ".join(f"{name}>={found.versions[name]}" for name in names)
    description = (
        f"Require {pairs} in the cited apk add instruction using the current Alpine "
        f"{found.branch} versions ({found.method}; official x86_64 package index). "
        "Newer versions are allowed; package requirements are quoted to prevent "
        "shell redirection."
    )
    plan = Plan(
        strategy="config_line",
        score=2,
        ecosystem="dockerfile",
        package=", ".join(names),
        installed="unpinned",
        target=pairs,
        files=[],
        manager=None,
        description=description,
        oracle=" ".join(f"{name}>={found.versions[name]}" for name in names),
        line=edits[0]["line"],
        expected_line=edits[0]["expected"],
        replacement_line=edits[0]["replacement"],
        line_edits=tuple(edits),
        doc_pages=(
            {
                "name": "kics_unpinned_apk_add",
                "url": _KICS_APK_PAGE,
                "markers": ["Unpinned Package Version in Apk Add"],
            },
            {
                "name": "docker_version_pinning",
                "url": _DOCKER_PINNING,
                "markers": ["version pinning"],
            },
            {
                "name": "alpine_release_branches",
                "url": _ALPINE_RELEASES_PAGE,
                "markers": ["release branches"],
            },
        ),
    )
    return ConfigAssessment("plan", description, plan, found.sources)


def _edit(kind: str, number: int, line: str) -> Plan | None:
    """Return a plan for a documented directive on this exact line."""
    if line.lstrip().startswith("#"):
        return None
    if kind == "nginx":
        return _nginx(number, line)
    if kind == "gitlab_ci":
        return _gitlab(number, line)
    return None


def _nginx(number: int, line: str) -> Plan | None:
    """Plan nginx directive changes that the current module pages still define."""
    matched = _SERVER_TOKENS.match(line)
    if matched:
        replacement = f"{matched.group(1)}server_tokens{matched.group(2)}off{matched.group(3)}{matched.group(4) or ''}"
        return _plan(
            number,
            line,
            replacement,
            "nginx",
            "server_tokens",
            "on",
            "off",
            "Set server_tokens off so nginx stops emitting its version.",
            "nginx_server_tokens",
            _NGINX_CORE,
            ("server_tokens", "off"),
        )
    matched = _AUTOINDEX.match(line)
    if matched:
        replacement = f"{matched.group(1)}autoindex{matched.group(2)}off{matched.group(3)}{matched.group(4) or ''}"
        return _plan(
            number,
            line,
            replacement,
            "nginx",
            "autoindex",
            "on",
            "off",
            "Set autoindex off so nginx does not list directories.",
            "nginx_autoindex",
            _NGINX_AUTOINDEX,
            ("autoindex", "off"),
        )
    matched = _SSL_PROTOCOLS.match(line)
    if matched:
        kept = [
            token
            for token in matched.group(2).split()
            if token.casefold() not in _OBSOLETE_TLS
        ]
        removed = len(kept) != len(matched.group(2).split())
        if not removed or not kept:
            return None
        suffix = matched.group(3) or ";"
        return _plan(
            number,
            line,
            f"{matched.group(1)}{' '.join(kept)}{suffix}",
            "nginx",
            "ssl_protocols",
            "TLSv1",
            "TLSv1.2",
            "Remove obsolete TLS versions from ssl_protocols and keep the documented current protocols.",
            "nginx_ssl_protocols",
            _NGINX_SSL,
            ("ssl_protocols", "TLSv1.3"),
        )
    return None


def _gitlab(number: int, line: str) -> Plan | None:
    """Re-enable a security job that this line explicitly disables."""
    matched = _GITLAB_VARIABLE.match(line)
    if matched is None:
        return None
    name = matched.group(2)
    if name not in _SECURITY_DISABLED:
        return None
    raw, comment = _split_comment(matched.group(4).strip())
    quoted = raw[:1] in {"'", '"'} and raw[-1:] == raw[:1] and len(raw) >= 2
    value = raw[1:-1] if quoted else raw
    if value.casefold() not in {"true", "1", "yes"}:
        return None
    quote = raw[:1] if quoted else '"'
    replacement = (
        f"{matched.group(1)}{name}{matched.group(3)}{quote}false{quote}{comment}"
    )
    return _plan(
        number,
        line,
        replacement,
        "gitlab_ci",
        name,
        value,
        "false",
        f"Set {name} to false so the GitLab security job is not skipped.",
        "gitlab_security_variable",
        _GITLAB_SCANS,
        (name, "true"),
    )


def _plan(
    number: int,
    line: str,
    replacement: str,
    ecosystem: str,
    package: str,
    installed: str,
    target: str,
    description: str,
    page_name: str,
    url: str,
    markers: tuple[str, ...],
) -> Plan:
    """Build a one-line plan bound to the page that documents it."""
    return Plan(
        strategy="config_line",
        score=2,
        ecosystem=ecosystem,
        package=package,
        installed=installed,
        target=target,
        files=[],
        manager=None,
        description=description,
        oracle=f"{package} {target}",
        line=number,
        expected_line=line,
        replacement_line=replacement,
        doc_pages=({"name": page_name, "url": url, "markers": list(markers)},),
    )


def _cited(lines: list[str], start: object) -> tuple[int, str] | None:
    """Return the 1-based cited line when it falls inside the file."""
    try:
        number = int(start)
    except (TypeError, ValueError):
        return None
    if number < 1 or number > len(lines):
        return None
    return number, lines[number - 1]


def _split_comment(value: str) -> tuple[str, str]:
    """Separate a YAML value from an end-of-line comment."""
    if " #" in value:
        raw, comment = value.split(" #", 1)
        return raw.strip(), " #" + comment
    return value.strip(), ""


def _label(kind: str) -> str:
    """Use the file family name in reviewer-facing reasons."""
    if kind == "dockerfile":
        return "Dockerfile"
    if kind == "nginx":
        return "nginx"
    return "GitLab CI"
