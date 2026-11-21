"""Online advisories: OSV, GitHub, NVD, then authoritative CVE CNA bounds."""

from __future__ import annotations

import json
import logging
import re
import threading
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from functools import partial
from pathlib import Path
from time import monotonic, sleep
from urllib.parse import unquote

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from gitlab_security_mcp.commands import progress_sink
from gitlab_security_mcp.fanout import map_ordered
from gitlab_security_mcp.util import (
    ADVISORY_READ_FAILURES,
    PROGRESS_PUBLISH_FAILURES,
    log_unexpected,
    redact,
    timed_http_stream,
)
from gitlab_security_mcp.versions import (
    collect_fixed_versions,
    describe_ranges,
    first_unaffected,
    lowest_fixed,
    osv_version_affected,
    parse_version,
)

_RAISE_ADVISORY_RESPONSE_MUST_BE_A_JSON_OBJECT_OR = (
    "Advisory response must be a JSON object or array"
)
_RAISE_NVD_SERVER_COOLDOWN_REQUIRES_1F_S_RETRY_THIS = "NVD server cooldown requires {:.1f}s; retry this lookup later. The per-call wait limit is 60s; no request was sent."
_RAISE_ADVISORY_QUERY_RESPONSE_MUST_BE_A_JSON_OBJECT = (
    "Advisory query response must be a JSON object"
)
_RAISE_ADVISORY_RESPONSE_EXCEEDS_THE_SIZE_LIMIT = (
    "Advisory response exceeds the size limit"
)
_RAISE_CVE_CNA_RESPONSE_DOES_NOT_IDENTIFY = "CVE CNA response does not identify {}"
_RAISE_NVD_REQUESTED_A_1F_S_RETRY_AFTER_COOLDOWN = "NVD requested a {:.1f}s Retry-After cooldown; retry this lookup later rather than ignoring the server limit."

# The advisory exists, but it does not name the package we found locally.
# That can be a GitLab mislabel or a naming mismatch, so a person decides.
PACKAGE_MISMATCH = "package_mismatch"

OSV_VULN = "https://api.osv.dev/v1/vulns/{ident}"
OSV_QUERY = "https://api.osv.dev/v1/query"
GITHUB_ADVISORIES = "https://api.github.com/advisories"
NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_RECORD = "https://cveawg.mitre.org/api/cve/{ident}"
MAX_CACHE_ENTRIES = 256
_MAX_ADVISORY_BYTES = 2_000_000
_NVD_LOCK = threading.Lock()
_nvd_last_request: float | None = None
_nvd_retry_until = 0.0
_NVD_ATTEMPTS = 3
_MAX_NVD_RETRY_WAIT = 60.0
logger = logging.getLogger("gitlab_security_mcp")


def _nvd_wait(has_key: bool) -> None:
    """Space NVD requests across checkout clients, including retries, in this process."""
    global _nvd_last_request
    with _NVD_LOCK:
        interval = 0.61 if has_key else 6.1
        earliest = max(
            _nvd_retry_until,
            (_nvd_last_request + interval) if _nvd_last_request is not None else 0,
        )
        delay = earliest - monotonic()
        if delay > _MAX_NVD_RETRY_WAIT:
            raise httpx.RequestError(
                _RAISE_NVD_SERVER_COOLDOWN_REQUIRES_1F_S_RETRY_THIS.format(delay)
            )
        if delay > 0:
            message = f"NVD API pacing: waiting {delay:.1f}s before the next request."
            logger.info(message)
            sink = progress_sink.get()
            if sink is not None:
                try:
                    sink(message)
                except PROGRESS_PUBLISH_FAILURES:
                    logger.warning(
                        "Could not publish NVD pacing progress", exc_info=True
                    )
            sleep(delay)
        _nvd_last_request = monotonic()


def _nvd_retry_delay(error: httpx.HTTPError, attempt: int) -> float | None:
    """Retry transient reads only; honor bounded Retry-After seconds or HTTP dates."""
    if isinstance(error, httpx.HTTPStatusError):
        if error.response.status_code not in {429, 500, 502, 503, 504}:
            return None
        header = error.response.headers.get("Retry-After")
        if header:
            try:
                delay = float(int(header))
            except ValueError:
                try:
                    date = parsedate_to_datetime(header)
                    if date.tzinfo is None:
                        date = date.replace(tzinfo=UTC)
                    delay = (date - datetime.now(UTC)).total_seconds()
                except (ValueError, TypeError, OverflowError):
                    delay = -1
            if delay >= 0:
                return delay
    elif not isinstance(
        error, (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError)
    ):
        return None
    return float(2**attempt)


ECOSYSTEMS = {
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "maven": "Maven",
    "gradle": "Maven",
    "nuget": "NuGet",
    "pypi": "PyPI",
    "pip": "PyPI",
}

GITHUB_ECOSYSTEMS = {
    "npm": "npm",
    "Maven": "maven",
    "NuGet": "nuget",
    "PyPI": "pip",
}


@dataclass
class AdvisoryLookup:
    """What the online sources say about one finding.

    ``outcome`` is one of resolved, no_fix_published, not_found,
    lookup_failed, or package_mismatch.
    """

    outcome: str
    fixed_versions: list[str] = field(default_factory=list)
    lowest_fixed_version: str | None = None
    affected: bool | None = None
    ranges: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    summary: str = ""
    sources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    validation_sites: list[str] = field(default_factory=list)


class AdvisoryClient:
    """Query public advisory APIs with a bounded process-local cache.

    OSV is tried first because it does not need a token. The owned HTTP
    client is closed by ``close``. An injected client stays open.
    """

    def __init__(
        self,
        *,
        http: httpx.Client | None = None,
        github_token: str | None = None,
        nvd_api_key: str | None = None,
        http_log_path: Path | None = None,
    ):
        """Configure advisory credentials and retain any caller-owned HTTP client."""
        self._owns_http = http is None
        self.http = http if http is not None else httpx.Client(timeout=30.0)
        self.github_token = github_token
        self.nvd_api_key = nvd_api_key
        self.http_log_path = http_log_path
        self._cache: dict[str, dict | list | None] = {}
        self._closed = False
        self._closing = False
        self._lock = threading.RLock()
        self._cache_lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        self._active_lookups = 0
        self._cache_ready = threading.Condition(self._cache_lock)
        self._pending: set[str] = set()
        self._validation_sites: ContextVar[set[str] | None] = ContextVar(
            "advisory_validation_sites", default=None
        )

    def close(self) -> None:
        """Release cached payloads and owned HTTP resources exactly once."""
        with self._lock:
            if self._closing:
                self._idle.wait_for(lambda: self._closed)
                return
            self._closing = True
            self._idle.wait_for(lambda: self._active_lookups == 0)
            try:
                if self._owns_http:
                    self.http.close()
            finally:
                with self._cache_lock:
                    self._cache.clear()
                self._closed = True
                self._idle.notify_all()

    def __enter__(self) -> AdvisoryClient:
        """Return this advisory client for use in a context manager."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close only the HTTP client owned by this advisory client."""
        self.close()

    def lookup(
        self,
        finding: dict,
        ecosystem: str | None,
        package: str | None,
        version: str | None,
    ) -> AdvisoryLookup:
        """Match online advisory evidence to a package and installed version.

        Prefer OSV, then GitHub Advisory Database, then NVD, with authoritative
        CVE CNA bounds when NVD is incomplete or unavailable. Ignore withdrawn
        records without treating withdrawal as proof of safety. Identifiers within
        one source are requested together. Return an AdvisoryLookup with
        affected status, candidate fixes, and sources.
        Failed requests, malformed responses, and calls after close return
        lookup_failed rather than claiming the version is safe. The engine may
        still use an explicit GitLab fix. Coordinate active reads with shutdown and
        retain sites consulted even when no record or fix data is available.
        """
        with self._lock:
            if self._closing:
                return AdvisoryLookup(
                    outcome="lookup_failed",
                    summary="Online advisory data could not be read safely.",
                    errors=["Advisory client is closed"],
                )
            self._active_lookups += 1
        sites: set[str] = set()
        token = self._validation_sites.set(sites)
        try:
            try:
                result = self._lookup(finding, ecosystem, package, version)
            except ADVISORY_READ_FAILURES as exc:
                log_unexpected(exc, "advisory lookup")
                result = AdvisoryLookup(
                    outcome="lookup_failed",
                    summary="Online advisory data could not be read safely.",
                    errors=[self._clean(str(exc))],
                )
            result.validation_sites = sorted(sites)
            return result
        finally:
            self._validation_sites.reset(token)
            with self._idle:
                self._active_lookups -= 1
                self._idle.notify_all()

    def _lookup(
        self,
        finding: dict,
        ecosystem: str | None,
        package: str | None,
        version: str | None,
    ) -> AdvisoryLookup:
        """Resolve identifiers through advisory sources in priority order."""
        identifiers = list(
            dict.fromkeys(
                item for item in finding.get("identifiers") or [] if _advisory_id(item)
            )
        )
        errors: list[str] = []
        sources: list[str] = []
        osv_records: list[dict] = []

        for _ident, payload, error in map_ordered(self._osv_record, identifiers):
            if error:
                errors.append(error)
                continue
            if payload and isinstance(payload, dict) and payload.get("id"):
                osv_records.append(payload)
                sources.append(f"osv:{payload.get('id')}")

        osv_ecosystem = ECOSYSTEMS.get((ecosystem or "").lower())
        if (
            package
            and version
            and osv_ecosystem
            and not _records_match_package(osv_records, package)
        ):
            try:
                queried = self._post_json(
                    OSV_QUERY,
                    {
                        "package": {"ecosystem": osv_ecosystem, "name": package},
                        "version": version,
                    },
                )
            except httpx.HTTPError as exc:
                errors.append(self._clean(f"osv-query:{package}: {exc}"))
                queried = None
            known = {item.get("id") for item in osv_records}
            follow_ups = list(
                dict.fromkeys(
                    summary.get("id")
                    for summary in (queried or {}).get("vulns") or []
                    if summary.get("id") not in known
                    and _overlaps(summary, identifiers, finding)
                )
            )
            for _ident, full, error in map_ordered(self._osv_record, follow_ups):
                if error:
                    errors.append(error)
                    continue
                if full and full.get("id") and full.get("id") not in known:
                    osv_records.append(full)
                    sources.append(f"osv:{full.get('id')}")
                    known.add(full.get("id"))

        mismatch = None
        if osv_records:
            osv_result = _from_osv(osv_records, package, version, sources, errors)
            if osv_result.outcome != PACKAGE_MISMATCH:
                return osv_result
            mismatch = osv_result

        github_record = self._github(
            identifiers, errors, sources, package, osv_ecosystem
        )
        if github_record is not None:
            github_result = _from_github(
                github_record, package, osv_ecosystem, version, sources, errors
            )
            if github_result.outcome != PACKAGE_MISMATCH:
                return github_result
            mismatch = github_result

        cve = next(
            (item for item in identifiers if item.upper().startswith("CVE-")), None
        )
        nvd_fallback = None
        if cve:
            nvd_record = self._nvd(cve, errors, sources)
            if nvd_record is not None:
                nvd_result = _from_nvd(nvd_record, package, version, sources, errors)
                if nvd_result.outcome == "lookup_failed":
                    nvd_fallback = nvd_result
                elif nvd_result.outcome != PACKAGE_MISMATCH:
                    return nvd_result
                else:
                    mismatch = nvd_result
            cna_record = self._cve(cve, errors, sources)
            if cna_record is not None:
                cna_result = _from_cve(
                    cna_record, ecosystem, package, version, sources, errors
                )
                if cna_result.outcome != PACKAGE_MISMATCH:
                    return cna_result
                mismatch = cna_result
        if nvd_fallback is not None:
            return nvd_fallback
        if mismatch is not None:
            return mismatch

        if errors and not sources:
            return AdvisoryLookup(
                outcome="lookup_failed",
                summary="Online advisory lookups failed before a definitive record was found.",
                sources=sources,
                errors=errors,
            )
        return AdvisoryLookup(
            outcome="not_found",
            summary="No matching record in OSV, the GitHub Advisory Database, NVD, or CVE CNA data.",
            sources=sources,
            errors=errors,
        )

    def _github(
        self,
        identifiers: list[str],
        errors: list[str],
        sources: list[str],
        package: str | None,
        ecosystem: str | None,
    ) -> dict | None:
        """Look up CVE or GHSA ids while preserving request error evidence.

        Every eligible id is requested together. The earliest id that names
        this package still wins. A withdrawn advisory or a different package
        in the same response does not hide a later matching record.
        """
        eligible = []
        for ident in identifiers:
            if ident.upper().startswith("GHSA-"):
                eligible.append((ident, {"ghsa_id": ident}))
            elif ident.upper().startswith("CVE-"):
                eligible.append((ident, {"cve_id": ident}))
        headers = self._github_headers()
        for ident, payload, error in map_ordered(
            partial(self._github_one, headers=headers), eligible
        ):
            if error:
                errors.append(error)
                continue
            if not isinstance(payload, list):
                continue
            for record in payload:
                if not isinstance(record, dict) or record.get("withdrawn_at"):
                    continue
                if package and not _github_record_matches(record, package, ecosystem):
                    continue
                sources.append(f"github:{ident}")
                return record
        return None

    def _osv_record(self, ident: str) -> tuple[str, dict | None, str | None]:
        """Fetch one OSV record without aborting the other identifier reads."""
        try:
            payload = self._get_json(OSV_VULN.format(ident=ident))
            if isinstance(payload, dict) and payload.get("withdrawn"):
                return (
                    ident,
                    None,
                    f"osv:{ident}: advisory withdrawn at {payload['withdrawn']}; "
                    "ignored as active evidence. Withdrawal alone does not establish a false positive.",
                )
        except ADVISORY_READ_FAILURES as exc:
            log_unexpected(exc, f"OSV advisory read {ident}")
            return ident, None, self._clean(f"osv:{ident}: {exc}")
        return ident, payload if isinstance(payload, dict) else None, None

    def _cve(self, ident: str, errors: list[str], sources: list[str]) -> dict | None:
        """Read a CVE's authoritative CNA data when NVD cannot supply bounds."""
        try:
            payload = self._get_json(CVE_RECORD.format(ident=ident))
            if payload is None:
                return None
            if (
                not isinstance(payload, dict)
                or (payload.get("cveMetadata") or {}).get("cveId") != ident
            ):
                raise ValueError(
                    _RAISE_CVE_CNA_RESPONSE_DOES_NOT_IDENTIFY.format(ident)
                )
            sources.append(f"cve:{ident}")
            return payload
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(self._clean(f"cve:{ident}: {exc}"))
            return None

    def _github_one(
        self, item: tuple[str, dict], headers: dict[str, str]
    ) -> tuple[str, dict | list | None, str | None]:
        """Fetch one GitHub advisory id without aborting the other reads."""
        ident, params = item
        try:
            payload = self._get_json(GITHUB_ADVISORIES, params=params, headers=headers)
        except ADVISORY_READ_FAILURES as exc:
            log_unexpected(exc, f"GitHub advisory read {ident}")
            return ident, None, self._clean(f"github:{ident}: {exc}")
        return ident, payload, None

    def _nvd(self, cve: str, errors: list[str], sources: list[str]) -> dict | None:
        """Recover bounded transient NVD failures or explicitly retain the final error."""
        global _nvd_retry_until
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
        try:
            for attempt in range(_NVD_ATTEMPTS):
                try:
                    payload = self._get_json(
                        NVD_CVE, params={"cveId": cve}, headers=headers
                    )
                    break
                except httpx.HTTPError as exc:
                    delay = _nvd_retry_delay(exc, attempt)
                    if delay is not None:
                        with _NVD_LOCK:
                            _nvd_retry_until = max(
                                _nvd_retry_until, monotonic() + delay
                            )
                        if delay > _MAX_NVD_RETRY_WAIT:
                            raise httpx.RequestError(
                                _RAISE_NVD_REQUESTED_A_1F_S_RETRY_AFTER_COOLDOWN.format(
                                    delay
                                )
                            ) from exc
                    if delay is None or attempt == _NVD_ATTEMPTS - 1:
                        raise
                    logger.warning(
                        "NVD transient request failure (%s); retrying attempt %s of %s.",
                        type(exc).__name__,
                        attempt + 2,
                        _NVD_ATTEMPTS,
                    )
        except ADVISORY_READ_FAILURES as exc:
            log_unexpected(exc, f"NVD advisory read {cve}")
            errors.append(self._clean(f"nvd:{cve}: {exc}"))
            return None
        vulnerabilities = (payload or {}).get("vulnerabilities") or []
        if not vulnerabilities:
            return None
        sources.append(f"nvd:{cve}")
        return vulnerabilities[0]

    def _github_headers(self) -> dict[str, str]:
        """Set API media/version headers and optional bearer authentication."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def _get_json(
        self, url: str, *, params: dict | None = None, headers: dict | None = None
    ) -> dict | list | None:
        """Cache validated GET payloads and close every HTTP response.

        Cache 404 as None. Other HTTP or JSON errors propagate to lookup's
        failure boundary rather than entering the cache as clean evidence.
        """
        key = (
            url
            + "?"
            + "&".join(
                f"{name}={value}" for name, value in sorted((params or {}).items())
            )
        )
        self._record_site(url)

        def fetch() -> dict | list | None:
            """Read one uncached record after any required NVD pacing."""
            if url == NVD_CVE:
                _nvd_wait(bool(self.nvd_api_key))
            with timed_http_stream(
                self.http,
                "GET",
                url,
                source="advisory",
                log_path=self.http_log_path,
                params=params,
                headers=headers,
            ) as response:
                if response.status_code == 404:
                    return None
                response.raise_for_status()
                return _decode_advisory(response)

        return self._cached_json(key, fetch)

    def _cached_json(
        self, key: str, fetch: Callable[[], dict | list | None]
    ) -> dict | list | None:
        """Share in-flight reads and cache only successfully decoded responses."""
        with self._cache_ready:
            self._cache_ready.wait_for(lambda: key not in self._pending)
            if key in self._cache:
                return self._cache[key]
            self._pending.add(key)
        try:
            payload = fetch()
            with self._cache_ready:
                self._cache[key] = payload
                if len(self._cache) > MAX_CACHE_ENTRIES:
                    self._cache.pop(next(iter(self._cache)))
            return payload
        finally:
            with self._cache_ready:
                self._pending.remove(key)
                self._cache_ready.notify_all()

    def _post_json(self, url: str, body: dict) -> dict | None:
        """Cache repeated package/version queries and close responses after parsing."""
        self._record_site(url)
        key = (
            "POST "
            + url
            + " "
            + json.dumps(body, sort_keys=True, separators=(",", ":"))
        )

        def fetch() -> dict | None:
            """Validate query responses before admitting them to the shared cache."""
            with timed_http_stream(
                self.http,
                "POST",
                url,
                source="advisory",
                log_path=self.http_log_path,
                json=body,
            ) as response:
                if response.status_code == 404:
                    return None
                response.raise_for_status()
                payload = _decode_advisory(response)
            if not isinstance(payload, dict):
                raise ValueError(_RAISE_ADVISORY_QUERY_RESPONSE_MUST_BE_A_JSON_OBJECT)
            return payload

        payload = self._cached_json(key, fetch)
        if payload is not None and not isinstance(payload, dict):
            raise ValueError(_RAISE_ADVISORY_QUERY_RESPONSE_MUST_BE_A_JSON_OBJECT)
        return payload

    def _record_site(self, url: str) -> None:
        """Retain consulted hosts only in the current lookup's request context."""
        with self._cache_lock:
            sites = self._validation_sites.get()
            if sites is not None:
                sites.add(
                    str(httpx.URL(url).copy_with(path="", query=None, fragment=None))
                )

    def _clean(self, text: str) -> str:
        """Redact advisory credentials before returning request details."""
        return redact(text, [self.github_token, self.nvd_api_key])


def _bounded_bytes(response: httpx.Response, limit: int) -> bytes:
    """Read a response without retaining more than ``limit`` bytes."""
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        size += len(chunk)
        if size > limit:
            raise ValueError(_RAISE_ADVISORY_RESPONSE_EXCEEDS_THE_SIZE_LIMIT)
        chunks.append(chunk)
    return b"".join(chunks)


def _decode_advisory(response: httpx.Response) -> dict | list:
    """Parse one advisory JSON body after enforcing the size limit."""
    payload = json.loads(_bounded_bytes(response, _MAX_ADVISORY_BYTES))
    if not isinstance(payload, (dict, list)):
        raise ValueError(_RAISE_ADVISORY_RESPONSE_MUST_BE_A_JSON_OBJECT_OR)
    return payload


def _advisory_id(value: str) -> bool:
    """Recognize vulnerability ids while excluding weakness-class CWE ids."""
    upper = value.upper()
    if upper.startswith("CWE-"):
        return False
    return upper.startswith(("CVE-", "GHSA-", "PYSEC-", "GO-", "RUSTSEC-", "NSWG-"))


def _overlaps(record: dict, identifiers: list[str], finding: dict) -> bool:
    """Match advisory aliases to finding identifiers or their title text."""
    aliases = {record.get("id"), *(record.get("aliases") or [])}
    aliases = {item for item in aliases if item}
    if aliases.intersection(identifiers):
        return True
    title = finding.get("title") or ""
    return any(item and item in title for item in aliases)


def _records_match_package(records: list[dict], package: str) -> bool:
    """Check whether OSV affected entries name the requested package."""
    target = package.lower()
    for record in records:
        for affected in record.get("affected") or []:
            name = ((affected.get("package") or {}).get("name") or "").lower()
            if name == target:
                return True
    return False


def _matching_affected(records: list[dict], package: str | None) -> list[dict]:
    """Select package-specific OSV entries, or all entries without a name."""
    entries: list[dict] = []
    for record in records:
        for affected in record.get("affected") or []:
            name = (affected.get("package") or {}).get("name")
            if package is None or (name or "").lower() == package.lower():
                entries.append(affected)
    if entries or package is None:
        return entries
    return []


def _affected_vote(votes: list[bool | None]) -> bool | None:
    """Collapse range votes: any affected result wins, then a unanimous clear."""
    if any(vote is True for vote in votes):
        return True
    if votes and all(vote is False for vote in votes):
        return False
    return None


def _references(records: list[dict]) -> list[str]:
    """Keep at most five unique advisory reference URLs for reporting."""
    urls: list[str] = []
    for record in records:
        for ref in record.get("references") or []:
            url = ref.get("url") if isinstance(ref, dict) else None
            if url and url not in urls:
                urls.append(url)
            if len(urls) == 5:
                return urls
    return urls


def _from_osv(
    records: list[dict],
    package: str | None,
    version: str | None,
    sources: list[str],
    errors: list[str],
) -> AdvisoryLookup:
    """Combine OSV affected votes and choose a fix outside known ranges."""
    entries = _matching_affected(records, package)
    if package and not entries:
        return AdvisoryLookup(
            outcome=PACKAGE_MISMATCH,
            summary=f"OSV has this identifier, but it does not list package {package}.",
            sources=sources,
            errors=errors,
            references=_references(records),
        )
    affected = _affected_vote(
        [osv_version_affected(version, entry) for entry in entries] if version else []
    )
    fixed = collect_fixed_versions(entries)
    ranges = describe_ranges(entries)
    # The smallest fixed version can sit inside another affected range, so
    # pick the first one that no entry still marks as affected.
    floor = first_unaffected(
        version,
        fixed,
        lambda candidate: any(
            osv_version_affected(candidate, entry) is True for entry in entries
        ),
    )
    if affected is False:
        summary = "Installed version is outside the OSV affected range."
    elif fixed:
        summary = f"OSV lists fixed version(s): {', '.join(fixed)}."
    else:
        summary = (
            "OSV lists this package as affected and does not publish a fixed version."
        )
    outcome = "resolved" if fixed or affected is False else "no_fix_published"
    return AdvisoryLookup(
        outcome=outcome,
        fixed_versions=fixed,
        lowest_fixed_version=floor,
        affected=affected,
        ranges=ranges,
        references=_references(records),
        summary=summary,
        sources=sources,
        errors=errors,
    )


def _from_github(
    record: dict,
    package: str | None,
    ecosystem: str | None,
    version: str | None,
    sources: list[str],
    errors: list[str],
) -> AdvisoryLookup:
    """Match GitHub package ranges and select a comparable patched floor."""
    github_eco = GITHUB_ECOSYSTEMS.get(ecosystem or "")
    vulns = record.get("vulnerabilities") or []
    exact = []
    loose = []
    for item in vulns:
        pkg = item.get("package") or {}
        name = pkg.get("name") or ""
        if github_eco and pkg.get("ecosystem") and pkg.get("ecosystem") != github_eco:
            continue
        if not package:
            exact.append(item)
        elif name.lower() == package.lower():
            exact.append(item)
        elif _names_match(package, name):
            loose.append(item)
    matched = exact or loose
    if package and not matched:
        return AdvisoryLookup(
            outcome=PACKAGE_MISMATCH,
            summary=f"GitHub Advisory has this identifier, but it does not list {package}.",
            sources=sources,
            errors=errors,
        )
    fixed: list[str] = []
    ranges: list[str] = []
    for item in matched:
        patched_value = item.get("first_patched_version")
        if isinstance(patched_value, dict):
            patched_value = patched_value.get("identifier")
        if not patched_value:
            older = item.get("patched_versions") or []
            patched_value = older[0] if isinstance(older, list) and older else ""
        patched = str(patched_value or "").strip()
        vulnerable = (item.get("vulnerable_version_range") or "").strip()
        if vulnerable:
            ranges.append(vulnerable)
        if patched and parse_version(patched) and patched not in fixed:
            fixed.append(patched)
    affected = (
        _affected_vote([_github_range_contains(version, item) for item in ranges])
        if version and ranges
        else None
    )
    floor = first_unaffected(
        version,
        fixed,
        lambda candidate: any(
            _github_range_contains(candidate, item) is True for item in ranges
        ),
    )
    if not fixed and affected is not False:
        outcome = "no_fix_published"
        summary = "GitHub Advisory has no patched version for this package."
    else:
        outcome = "resolved"
        summary = f"GitHub Advisory patched versions: {', '.join(fixed) or 'none'}."
    return AdvisoryLookup(
        outcome=outcome,
        fixed_versions=fixed,
        lowest_fixed_version=floor,
        affected=affected,
        ranges=ranges,
        references=[record.get("html_url")] if record.get("html_url") else [],
        summary=summary,
        sources=sources,
        errors=errors,
    )


def _names_match(wanted: str, found: str) -> bool:
    """Match a package name, including a Maven coordinate and its artifact id.

    A bare artifact matches a ``group:artifact`` name. Two different groups
    that share an artifact id do not match each other.
    """
    left = wanted.strip().lower()
    right = found.strip().lower()
    if not left or not right or left == right:
        return bool(left) and left == right
    if ":" in left and ":" in right:
        return False
    return left.rsplit(":", 1)[-1] == right.rsplit(":", 1)[-1]


def _github_record_matches(record: dict, package: str, ecosystem: str | None) -> bool:
    """Return whether one GitHub advisory names this package and ecosystem."""
    github_eco = GITHUB_ECOSYSTEMS.get(ecosystem or "")
    for item in record.get("vulnerabilities") or []:
        pkg = item.get("package") or {}
        if github_eco and pkg.get("ecosystem") and pkg.get("ecosystem") != github_eco:
            continue
        if _names_match(package, pkg.get("name") or ""):
            return True
    return False


def _github_range_contains(version: str, text: str) -> bool | None:
    """GitHub ranges look like '< 4.17.21', '>= 1.0.0, < 1.2.4', or '= 1.0.0'."""
    current = parse_version(version)
    if current is None:
        return None
    specifier = re.sub(r"(^|,)=(?!=)", r"\1==", text.replace(" ", ""))
    try:
        return current in SpecifierSet(specifier)
    except InvalidSpecifier:
        return None


def _cpe_product(criteria: str) -> str | None:
    """Return the product field of a CPE 2.3 string such as cpe:2.3:a:vendor:product:..."""
    parts = criteria.split(":")
    return parts[4].lower() if len(parts) > 4 else None


def _product_key(package: str) -> str:
    """Reduce a package name to the form NVD uses for products."""
    last = re.split(r"[/:]", package.lower())[-1]
    return last.replace("-", "_").replace(".", "_")


def _cna_matches(entry: dict, ecosystem: str | None, package: str) -> bool:
    """Prefer a CNA package URL; otherwise require an exact product name."""
    purl = entry.get("packageURL")
    if purl:
        kind = {"npm": "npm", "NuGet": "nuget", "Maven": "maven", "PyPI": "pypi"}.get(
            ECOSYSTEMS.get((ecosystem or "").lower())
        )
        coordinate = package.replace(":", "/") if kind == "maven" else package
        expected = f"pkg:{kind}/{coordinate}".lower()
        actual = unquote(str(purl)).split("?", 1)[0].split("#", 1)[0].lower()
        return actual == expected or actual.startswith(expected + "@")
    return str(entry.get("product") or "").casefold() == package.casefold()


def _cna_ranges(entry: dict) -> tuple[dict, bool]:
    """Translate supported structured CNA versions, retaining incomplete-evidence status."""
    converted: dict = {"versions": [], "ranges": []}
    rows = entry.get("versions") or []
    complete = bool(rows) and entry.get("defaultStatus") == "unaffected"
    for row in rows:
        if (
            not isinstance(row, dict)
            or row.get("status") != "affected"
            or row.get("changes")
            or row.get("versionType") not in {None, "semver"}
        ):
            complete = False
            continue
        start = row.get("version")
        upper = row.get("lessThan") or row.get("lessThanOrEqual")
        if start == "*":
            start = "0"
        lower_version = parse_version(start) if isinstance(start, str) else None
        if lower_version is None:
            complete = False
            continue
        if upper is None:
            if row.get("version") == "*":
                converted["ranges"].append(
                    {"type": "SEMVER", "events": [{"introduced": "0"}]}
                )
            else:
                converted["versions"].append(start)
            continue
        upper_version = parse_version(upper) if isinstance(upper, str) else None
        if (
            row.get("versionType") != "semver"
            or upper_version is None
            or upper_version < lower_version
            or (upper_version == lower_version and row.get("lessThan"))
            or (row.get("lessThan") and row.get("lessThanOrEqual"))
        ):
            complete = False
            continue
        end = "fixed" if row.get("lessThan") else "last_affected"
        converted["ranges"].append(
            {
                "type": "SEMVER",
                "events": [{"introduced": start}, {end: upper}],
            }
        )
    return converted, complete


def _from_cve(
    record: dict,
    ecosystem: str | None,
    package: str | None,
    version: str | None,
    sources: list[str],
    errors: list[str],
) -> AdvisoryLookup:
    """Evaluate published, package-matched CNA bounds without mining prose or inventing fixes."""
    if (record.get("cveMetadata") or {}).get("state") != "PUBLISHED":
        return AdvisoryLookup(
            outcome="lookup_failed",
            sources=sources,
            errors=errors,
            summary="The CVE CNA record is not published; independent review is required, not automatic dismissal.",
        )
    cna = (record.get("containers") or {}).get("cna") or {}
    entries = [
        entry
        for entry in cna.get("affected") or []
        if isinstance(entry, dict)
        and package
        and _cna_matches(entry, ecosystem, package)
    ]
    if not entries:
        return AdvisoryLookup(
            outcome=PACKAGE_MISMATCH,
            sources=sources,
            errors=errors,
            summary=f"The CVE CNA record does not identify package {package}.",
        )
    mappings = [_cna_ranges(entry) for entry in entries]

    def affected_at(candidate: str | None) -> bool | None:
        """Do not treat an omitted version as safe unless the CNA explicitly permits it."""
        votes = []
        for converted, complete in mappings:
            vote = osv_version_affected(candidate, converted)
            votes.append(None if vote is False and not complete else vote)
        return _affected_vote(votes)

    affected = affected_at(version)
    converted_entries = [converted for converted, _complete in mappings]
    fixed = collect_fixed_versions(converted_entries)
    floor = first_unaffected(
        version, fixed, lambda candidate: affected_at(candidate) is not False
    )
    if affected is False:
        outcome, summary = (
            "resolved",
            f"Installed {package} {version} is outside the explicit CVE CNA affected versions.",
        )
    elif affected is True:
        outcome = "resolved" if floor else "no_fix_published"
        summary = f"CVE CNA lists {package} {version} as affected; " + (
            f"fixed version bound: {floor}."
            if floor
            else "no verified fixed-version bound is published in this record."
        )
    else:
        outcome, summary = (
            "lookup_failed",
            "The CVE CNA record names this package but its structured versions do not establish the installed version's status.",
        )
    return AdvisoryLookup(
        outcome=outcome,
        affected=affected,
        fixed_versions=fixed,
        lowest_fixed_version=floor,
        ranges=describe_ranges(converted_entries),
        summary=summary,
        sources=sources,
        errors=errors,
        references=_references([cna]),
    )


def _from_nvd(
    record: dict,
    package: str | None,
    version: str | None,
    sources: list[str],
    errors: list[str],
) -> AdvisoryLookup:
    """Use only matching NVD products to infer affected bounds and fixes."""
    cve = record.get("cve") or {}
    fixed: list[str] = []
    ranges: list[str] = []
    affected: bool | None = None
    current = parse_version(version) if version else None
    votes: list[bool] = []
    saw_vulnerable = False
    matched_product = False
    wanted = _product_key(package) if package else None
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                saw_vulnerable = True
                # One CVE can name several products. Only the matching one
                # may supply a fixed version or an affected vote.
                product = _cpe_product(str(match.get("criteria") or ""))
                if wanted and (product is None or product.replace("-", "_") != wanted):
                    continue
                matched_product = True
                end_excluding = match.get("versionEndExcluding")
                end_including = match.get("versionEndIncluding")
                start_including = match.get("versionStartIncluding") or "0"
                end_excluding_version = (
                    parse_version(end_excluding) if end_excluding else None
                )
                end_including_version = (
                    parse_version(end_including) if end_including else None
                )
                if end_excluding_version is not None:
                    fixed.append(end_excluding)
                    ranges.append(f">={start_including},<{end_excluding}")
                elif end_including:
                    ranges.append(f">={start_including},<={end_including}")
                if current is None:
                    continue
                start = parse_version(start_including) or parse_version("0")
                if start is None or current < start:
                    votes.append(False)
                    continue
                if end_excluding_version is not None:
                    votes.append(current < end_excluding_version)
                elif end_including_version is not None:
                    votes.append(current <= end_including_version)
    if wanted and saw_vulnerable and not matched_product:
        return AdvisoryLookup(
            outcome=PACKAGE_MISMATCH,
            summary=f"NVD lists this CVE, but no affected product matches {package}.",
            sources=sources,
            errors=errors,
        )
    if not ranges:
        return AdvisoryLookup(
            outcome="lookup_failed",
            summary="NVD lists this CVE, but usable affected-version bounds for this package are missing. Manual review is required; missing bounds do not establish that no fix exists.",
            sources=sources,
            errors=errors,
        )
    if votes:
        affected = any(votes)
    unique_fixed = []
    for item in fixed:
        if item not in unique_fixed:
            unique_fixed.append(item)
    floor = lowest_fixed(version, unique_fixed)
    if not unique_fixed and affected is not False:
        return AdvisoryLookup(
            outcome="no_fix_published",
            affected=affected,
            ranges=ranges,
            summary="NVD records an affected range but no fixed-version bound for this package. This does not establish that no fix exists in other sources.",
            sources=sources,
            errors=errors,
        )
    return AdvisoryLookup(
        outcome="resolved",
        fixed_versions=unique_fixed,
        lowest_fixed_version=floor,
        affected=affected,
        ranges=ranges,
        summary=(
            f"Installed {package or 'product'} {version} is outside NVD's affected "
            f"ranges: {'; '.join(ranges)}."
            if affected is False
            else f"NVD versionEndExcluding values: {', '.join(unique_fixed) or 'none'}."
        ),
        sources=sources,
        errors=errors,
    )
