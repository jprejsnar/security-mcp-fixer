"""Plan one-line fixes for Dockerfile, nginx, and GitLab CI findings.

The cited line is the only line that can change. A rule applies only when
its current publisher page still contains the documented directive. GitLab
solution text is never written into the file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

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


@dataclass(frozen=True)
class ConfigAssessment:
    """A config finding that is missing, needs review, or has a line plan."""

    decision: str
    reason: str
    plan: Plan | None = None


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


def assess_config(root: Path, finding: dict) -> ConfigAssessment:
    """Match the cited line to a documented edit, or explain why none applies.

    Missing files can support a false positive. A present file with no
    matching documented edit stays on manual review and is not rewritten
    from the scanner title.
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
    """Replace one cited line when it still matches the planned text.

    The write preserves the line ending. A changed or missing line fails
    closed so a stale plan cannot edit a different statement.
    """
    if (
        plan.line is None
        or not plan.files
        or plan.expected_line is None
        or plan.replacement_line is None
    ):
        raise ValueError("The configuration plan does not name one exact line.")
    if "\n" in plan.replacement_line or "\r" in plan.replacement_line:
        raise ValueError("A configuration replacement cannot add lines.")
    relative = plan.files[0]
    resolved = resolve_inside(root, relative)
    if resolved is None or not resolved.is_file():
        raise ValueError(f"{relative} is not a file inside the repository.")
    with resolved.open(encoding="utf-8", newline="") as stream:
        text = stream.read()
    ending = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    index = plan.line - 1
    if index < 0 or index >= len(lines) or lines[index] != plan.expected_line:
        raise ValueError("The cited line no longer matches the planned configuration.")
    lines[index] = plan.replacement_line
    updated = ending.join(lines)
    if text.endswith(("\n", "\r\n")):
        updated += ending
    atomic_write_text(resolved, updated)
    return [relative]


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
