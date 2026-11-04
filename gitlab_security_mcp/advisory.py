"""Online advisory lookups. OSV first, then GitHub Advisory, then NVD."""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from gitlab_security_mcp.fanout import map_ordered
from gitlab_security_mcp.util import redact, timed_http_stream
from gitlab_security_mcp.versions import (
    collect_fixed_versions,
    describe_ranges,
    first_unaffected,
    lowest_fixed,
    osv_version_affected,
    parse_version,
)

# The advisory exists, but it does not name the package we found locally.
# That can be a GitLab mislabel or a naming mismatch, so a person decides.
PACKAGE_MISMATCH = "package_mismatch"

OSV_VULN = "https://api.osv.dev/v1/vulns/{ident}"
OSV_QUERY = "https://api.osv.dev/v1/query"
GITHUB_ADVISORIES = "https://api.github.com/advisories"
NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_CACHE_ENTRIES = 256
_MAX_ADVISORY_BYTES = 2_000_000

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
        self._lock = threading.RLock()
        self._cache_lock = threading.Lock()
        self._validation_sites: set[str] = set()

    def close(self) -> None:
        """Release cached payloads and owned HTTP resources exactly once."""
        with self._lock:
            if self._closed:
                return
            try:
                if self._owns_http:
                    self.http.close()
            finally:
                with self._cache_lock:
                    self._cache.clear()
                self._closed = True

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

        Prefer OSV, then GitHub Advisory Database, then NVD. Identifiers within
        one source are requested together; the next source is used only when
        the earlier source has no record. Return an AdvisoryLookup with
        affected status, candidate fixes, and sources.
        Failed requests, malformed responses, and calls after close return
        lookup_failed rather than claiming the version is safe. The engine may
        still use an explicit GitLab fix. Serialize access with shutdown and
        retain sites consulted even when no record or fix data is available.
        """
        with self._lock:
            self._validation_sites = set()
            try:
                if self._closed:
                    raise RuntimeError("Advisory client is closed")
                result = self._lookup(finding, ecosystem, package, version)
            except (
                httpx.HTTPError,
                ValueError,
                TypeError,
                AttributeError,
                RuntimeError,
            ) as exc:
                result = AdvisoryLookup(
                    outcome="lookup_failed",
                    summary="Online advisory data could not be read safely.",
                    errors=[self._clean(str(exc))],
                )
            result.validation_sites = sorted(self._validation_sites)
            return result

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

        if osv_records:
            return _from_osv(osv_records, package, version, sources, errors)

        github_record = self._github(identifiers, errors, sources)
        if github_record is not None:
            return _from_github(
                github_record, package, osv_ecosystem, version, sources, errors
            )

        cve = next(
            (item for item in identifiers if item.upper().startswith("CVE-")), None
        )
        if cve:
            nvd_record = self._nvd(cve, errors, sources)
            if nvd_record is not None:
                return _from_nvd(nvd_record, package, version, sources, errors)

        if errors and not sources:
            return AdvisoryLookup(
                outcome="lookup_failed",
                summary="Online advisory lookups failed before a definitive record was found.",
                sources=sources,
                errors=errors,
            )
        return AdvisoryLookup(
            outcome="not_found",
            summary="No matching record in OSV, the GitHub Advisory Database, or NVD.",
            sources=sources,
            errors=errors,
        )

    def _github(
        self, identifiers: list[str], errors: list[str], sources: list[str]
    ) -> dict | None:
        """Look up CVE or GHSA ids while preserving request error evidence.

        Every eligible id is requested together. The earliest id in the
        finding still wins when more than one record exists.
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
            if isinstance(payload, list) and payload:
                sources.append(f"github:{ident}")
                return payload[0]
        return None

    def _osv_record(self, ident: str) -> tuple[str, dict | None, str | None]:
        """Fetch one OSV record without aborting the other identifier reads."""
        try:
            payload = self._get_json(OSV_VULN.format(ident=ident))
        except Exception as exc:
            return ident, None, self._clean(f"osv:{ident}: {exc}")
        return ident, payload if isinstance(payload, dict) else None, None

    def _github_one(
        self, item: tuple[str, dict], headers: dict[str, str]
    ) -> tuple[str, dict | list | None, str | None]:
        """Fetch one GitHub advisory id without aborting the other reads."""
        ident, params = item
        try:
            payload = self._get_json(GITHUB_ADVISORIES, params=params, headers=headers)
        except Exception as exc:
            return ident, None, self._clean(f"github:{ident}: {exc}")
        return ident, payload, None

    def _nvd(self, cve: str, errors: list[str], sources: list[str]) -> dict | None:
        """Fetch the first matching NVD CVE record or record a lookup error."""
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
        try:
            payload = self._get_json(NVD_CVE, params={"cveId": cve}, headers=headers)
        except Exception as exc:
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
        with self._cache_lock:
            self._validation_sites.add(
                str(httpx.URL(url).copy_with(path="", query=None, fragment=None))
            )
            if key in self._cache:
                return self._cache[key]
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
                payload = None
            else:
                response.raise_for_status()
                payload = _decode_advisory(response)
        with self._cache_lock:
            if key in self._cache:
                return self._cache[key]
            self._cache[key] = payload
            if len(self._cache) > MAX_CACHE_ENTRIES:
                self._cache.pop(next(iter(self._cache)))
        return payload

    def _post_json(self, url: str, body: dict) -> dict | None:
        """Submit an advisory query and close its response after parsing."""
        with self._cache_lock:
            self._validation_sites.add(
                str(httpx.URL(url).copy_with(path="", query=None, fragment=None))
            )
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
            raise ValueError("Advisory query response must be a JSON object")
        return payload

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
            raise ValueError("Advisory response exceeds the size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _decode_advisory(response: httpx.Response) -> dict | list:
    """Parse one advisory JSON body after enforcing the size limit."""
    payload = json.loads(_bounded_bytes(response, _MAX_ADVISORY_BYTES))
    if not isinstance(payload, (dict, list)):
        raise ValueError("Advisory response must be a JSON object or array")
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
    affected_votes = (
        [osv_version_affected(version, entry) for entry in entries] if version else []
    )
    if any(vote is True for vote in affected_votes):
        affected: bool | None = True
    elif affected_votes and all(vote is False for vote in affected_votes):
        affected = False
    else:
        affected = None
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
    matched = []
    for item in vulns:
        pkg = item.get("package") or {}
        if package and (pkg.get("name") or "").lower() != package.lower():
            continue
        if github_eco and pkg.get("ecosystem") and pkg.get("ecosystem") != github_eco:
            continue
        matched.append(item)
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
        patched = str(item.get("first_patched_version") or "").strip()
        vulnerable = (item.get("vulnerable_version_range") or "").strip()
        if vulnerable:
            ranges.append(vulnerable)
        if patched and parse_version(patched) and patched not in fixed:
            fixed.append(patched)
    affected = None
    if version and ranges:
        votes = [_github_range_contains(version, item) for item in ranges]
        if any(vote is True for vote in votes):
            affected = True
        elif votes and all(vote is False for vote in votes):
            affected = False
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
    if wanted and saw_vulnerable and not ranges and not votes:
        return AdvisoryLookup(
            outcome=PACKAGE_MISMATCH,
            summary=f"NVD lists this CVE, but no affected product matches {package}.",
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
            summary="NVD does not publish a versionEndExcluding fix for this CVE.",
            sources=sources,
            errors=errors,
        )
    return AdvisoryLookup(
        outcome="resolved",
        fixed_versions=unique_fixed,
        lowest_fixed_version=floor,
        affected=affected,
        ranges=ranges,
        summary=f"NVD versionEndExcluding values: {', '.join(unique_fixed) or 'none'}.",
        sources=sources,
        errors=errors,
    )
