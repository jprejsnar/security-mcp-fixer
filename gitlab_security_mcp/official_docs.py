"""Read current publisher documentation before any local security edit.

A fix is authorized only after this run retrieves every required page.
Cached or remembered guidance is not enough, and a failed read blocks the
write. Response bodies are hashed and discarded so they are not retained
on the engine.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from dataclasses import dataclass

import httpx

from gitlab_security_mcp.fanout import map_ordered

# Publishers named by the remediation contract. Each marker must appear in
# the live page, which rejects an empty or unrelated response.
REQUIRED_DOCS = (
    ("docker", "https://docs.docker.com/reference/dockerfile/", "Dockerfile"),
    ("nginx", "https://nginx.org/en/docs/", "nginx"),
    (
        "gitlab",
        "https://docs.gitlab.com/user/application_security/",
        "Application security",
    ),
    ("java", "https://docs.oracle.com/en/java/javase/", "Java"),
    ("node", "https://nodejs.org/docs/latest/api/", "Node.js"),
    ("angular", "https://angular.dev/overview", "Angular"),
    ("crystal", "https://crystal-lang.org/reference/", "Crystal"),
    ("microsoft", "https://learn.microsoft.com/en-us/", "Microsoft"),
    (
        "dotnet",
        "https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/overview",
        ".NET 10",
    ),
    ("typescript", "https://www.typescriptlang.org/docs/", "TypeScript"),
    ("cve", "https://www.cve.org/", "CVE"),
    ("cwe", "https://cwe.mitre.org/", "CWE"),
    ("nsa", "https://www.nsa.gov/Cybersecurity/", "Cybersecurity"),
    ("nist", "https://nvd.nist.gov/", "NVD"),
)
ALLOWED_HOSTS = frozenset(
    {
        "docs.docker.com",
        "nginx.org",
        "docs.gitlab.com",
        "docs.oracle.com",
        "nodejs.org",
        "angular.dev",
        "crystal-lang.org",
        "learn.microsoft.com",
        "www.typescriptlang.org",
        "www.cve.org",
        "cwe.mitre.org",
        "www.nsa.gov",
        "nvd.nist.gov",
    }
)
logger = logging.getLogger("gitlab_security_mcp")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE = re.compile(r"CWE-(\d{1,5})", re.IGNORECASE)
_MAX_BODY = 1_000_000
_MAX_IDENTIFIERS = 4


@dataclass(frozen=True)
class DocSource:
    """One retrieved page, without its body."""

    name: str
    url: str
    ok: bool
    status_code: int | None
    sha256: str | None
    error: str | None

    def as_dict(self) -> dict:
        """Return the page result for evidence and reports."""
        return {
            "name": self.name,
            "url": self.url,
            "ok": self.ok,
            "status_code": self.status_code,
            "sha256": self.sha256,
            "error": self.error,
        }


@dataclass(frozen=True)
class DocReview:
    """Whether every required page was read in this call."""

    sources: tuple[DocSource, ...]

    @property
    def complete(self) -> bool:
        """Return whether every requested page passed its marker check."""
        return bool(self.sources) and all(item.ok for item in self.sources)

    def reason(self) -> str:
        """Explain a complete read or name the pages that blocked the edit."""
        failed = [
            f"{item.name} ({item.error or item.status_code})"
            for item in self.sources
            if not item.ok
        ]
        if not failed:
            return "Current official documentation was read before the edit."
        return (
            "Official documentation was not read completely, so nothing was changed: "
            + ", ".join(failed)
        )

    def as_list(self) -> list[dict]:
        """Return page results without response bodies."""
        return [item.as_dict() for item in self.sources]


class OfficialDocs:
    """Fetch the required publisher pages with one owned or injected client.

    Independent pages are requested together. The lock is held for the whole
    read, so close waits until those requests finish and cannot retire the
    client underneath them. Callers discard the review after recording its
    hashes. An injected client stays open.
    """

    def __init__(self, *, http: httpx.Client | None = None):
        """Retain a caller-owned client, or open one with redirects enabled."""
        self._owns_http = http is None
        self.http = (
            http
            if http is not None
            else httpx.Client(timeout=20.0, follow_redirects=True)
        )
        self._lock = threading.RLock()
        self._closed = False

    def close(self) -> None:
        """Close the owned HTTP client once. An injected client stays open."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._owns_http:
                self.http.close()

    def __enter__(self) -> OfficialDocs:
        """Return this client for a context manager."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the owned HTTP client when the context ends."""
        self.close()

    def read_before_fix(
        self, finding: dict, doc_pages: list[dict] | None = None
    ) -> DocReview:
        """Read every required publisher page and any rule-specific page.

        ``doc_pages`` entries supply a name, an https URL, and the phrases
        that must still appear before that rule can change a line. Network
        and response failures become an incomplete review instead of an edit.
        """
        with self._lock:
            if self._closed:
                return DocReview(
                    (
                        DocSource(
                            "documentation",
                            "",
                            False,
                            None,
                            None,
                            "Documentation client is closed",
                        ),
                    )
                )
            pages = _pages_for(finding, doc_pages or [])
            # The lock stays held so close cannot drop the client mid-request.
            # Each page is still fetched on its own worker.
            return DocReview(tuple(map_ordered(self._read_guarded, pages)))

    def _read_guarded(self, page: dict) -> DocSource:
        """Keep one page failure from discarding the other page results."""
        try:
            return self._read_page(page)
        except Exception as exc:
            logger.exception(
                "Could not read official documentation page %s", page.get("url")
            )
            return DocSource(
                str(page.get("name") or "documentation"),
                str(page.get("url") or ""),
                False,
                None,
                None,
                type(exc).__name__,
            )

    def _read_page(self, page: dict) -> DocSource:
        """Fetch one allowlisted page and require each marker in its body."""
        name = str(page["name"])
        url = str(page["url"])
        markers = tuple(str(marker) for marker in page["markers"] if str(marker))
        if not markers:
            return DocSource(
                name, url, False, None, None, "The page has no required phrases"
            )
        try:
            parsed = httpx.URL(url)
        except httpx.HTTPError:
            return DocSource(
                name, url, False, None, None, "URL is not an allowlisted https document"
            )
        if parsed.scheme != "https" or parsed.host not in ALLOWED_HOSTS:
            return DocSource(
                name, url, False, None, None, "URL is not an allowlisted https document"
            )
        try:
            with self.http.stream(
                "GET",
                url,
                headers={
                    "User-Agent": "gitlab-security-mcp",
                    "Accept": "text/html,application/json",
                },
            ) as response:
                digest, body = _hashed_prefix(response)
                final_host = response.url.host
                status_code = response.status_code
        except httpx.HTTPError as exc:
            return DocSource(name, url, False, None, None, type(exc).__name__)
        if status_code != 200:
            return DocSource(
                name,
                url,
                False,
                status_code,
                digest,
                f"HTTP {status_code}",
            )
        if final_host not in ALLOWED_HOSTS:
            return DocSource(
                name,
                url,
                False,
                status_code,
                digest,
                "Redirect left the allowlisted hosts",
            )
        folded = body.casefold()
        missing = [marker for marker in markers if marker.casefold() not in folded]
        if missing:
            return DocSource(
                name,
                url,
                False,
                status_code,
                digest,
                "Page no longer contains: " + ", ".join(missing),
            )
        return DocSource(name, url, True, status_code, digest, None)


def _hashed_prefix(response: httpx.Response) -> tuple[str, str]:
    """Hash every response byte and retain only the marker-search prefix.

    The digest is the change record for the page that authorized an edit.
    Bytes after the retained prefix are included in that digest and then
    dropped, so a change there cannot look like an unchanged page.
    """
    hasher = hashlib.sha256()
    prefix = bytearray()
    for chunk in response.iter_bytes():
        hasher.update(chunk)
        if len(prefix) < _MAX_BODY:
            prefix.extend(chunk[: _MAX_BODY - len(prefix)])
    encoding = response.encoding or "utf-8"
    return hasher.hexdigest(), bytes(prefix).decode(encoding, errors="replace")


def _pages_for(finding: dict, doc_pages: list[dict]) -> list[dict]:
    """Build the always-required pages plus CVE, CWE, and rule pages."""
    pages = [
        {"name": name, "url": url, "markers": (marker,)}
        for name, url, marker in REQUIRED_DOCS
    ]
    text = " ".join(
        str(part)
        for part in (
            finding.get("identifiers") or [],
            finding.get("title"),
            finding.get("description"),
        )
    )
    for ident in _unique(_CVE.findall(text))[:_MAX_IDENTIFIERS]:
        cve = ident.upper()
        pages.append(
            {
                "name": f"cve:{cve}",
                "url": f"https://www.cve.org/CVERecord?id={cve}",
                "markers": (cve,),
            }
        )
        pages.append(
            {
                "name": f"nist:{cve}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "markers": (cve,),
            }
        )
    for number in _unique(_CWE.findall(text))[:_MAX_IDENTIFIERS]:
        cwe = f"CWE-{int(number)}"
        pages.append(
            {
                "name": f"cwe:{cwe}",
                "url": f"https://cwe.mitre.org/data/definitions/{int(number)}.html",
                "markers": (cwe,),
            }
        )
    for page in doc_pages:
        markers = tuple(str(item) for item in page.get("markers") or () if str(item))
        pages.append(
            {
                "name": str(page.get("name") or "rule"),
                "url": str(page.get("url") or ""),
                "markers": markers or ("",),
            }
        )
    return pages


def _unique(values: list[str]) -> list[str]:
    """Keep the first copy of each identifier."""
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        key = value.upper()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(value)
    return ordered
