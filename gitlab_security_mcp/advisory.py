"""Online advisory lookups. OSV first, then GitHub Advisory, then NVD."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from gitlab_security_mcp.util import redact
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


class AdvisoryClient:
    """Query public advisory APIs and cache responses for this process.

    OSV is tried first because it does not need a token. The owned HTTP
    client is closed by ``close``. An injected client stays open.
    """

    def __init__(
        self,
        *,
        http: httpx.Client | None = None,
        github_token: str | None = None,
        nvd_api_key: str | None = None,
    ):
        self._owns_http = http is None
        self.http = http or httpx.Client(timeout=30.0)
        self.github_token = github_token
        self.nvd_api_key = nvd_api_key
        self._cache: dict[str, dict | list | None] = {}
        self._closed = False

    def close(self) -> None:
        """Close the owned HTTP client. Repeated calls do nothing."""
        if self._closed or not self._owns_http:
            self._closed = True
            return
        self.http.close()
        self._closed = True

    def __enter__(self) -> AdvisoryClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def lookup(self, finding: dict, ecosystem: str | None, package: str | None, version: str | None) -> AdvisoryLookup:
        """Decide whether online data can identify a fixed version for this finding."""
        identifiers = [item for item in finding.get("identifiers") or [] if _advisory_id(item)]
        errors: list[str] = []
        sources: list[str] = []
        osv_records: list[dict] = []

        for ident in identifiers:
            try:
                payload = self._get_json(OSV_VULN.format(ident=ident))
            except httpx.HTTPError as exc:
                errors.append(self._clean(f"osv:{ident}: {exc}"))
                continue
            if payload and isinstance(payload, dict) and payload.get("id"):
                osv_records.append(payload)
                sources.append(f"osv:{payload.get('id')}")

        osv_ecosystem = ECOSYSTEMS.get((ecosystem or "").lower())
        if package and version and osv_ecosystem and not _records_match_package(osv_records, package):
            try:
                queried = self._post_json(
                    OSV_QUERY,
                    {"package": {"ecosystem": osv_ecosystem, "name": package}, "version": version},
                )
            except httpx.HTTPError as exc:
                errors.append(self._clean(f"osv-query:{package}: {exc}"))
                queried = None
            for summary in (queried or {}).get("vulns") or []:
                if not _overlaps(summary, identifiers, finding):
                    continue
                try:
                    full = self._get_json(OSV_VULN.format(ident=summary.get("id")))
                except httpx.HTTPError as exc:
                    errors.append(self._clean(f"osv:{summary.get('id')}: {exc}"))
                    continue
                if full and full.get("id") and full.get("id") not in {item.get("id") for item in osv_records}:
                    osv_records.append(full)
                    sources.append(f"osv:{full.get('id')}")

        if osv_records:
            return _from_osv(osv_records, package, version, sources, errors)

        github_record = self._github(identifiers, errors, sources)
        if github_record is not None:
            return _from_github(github_record, package, osv_ecosystem, version, sources, errors)

        cve = next((item for item in identifiers if item.upper().startswith("CVE-")), None)
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

    def _github(self, identifiers: list[str], errors: list[str], sources: list[str]) -> dict | None:
        for ident in identifiers:
            params = {"ghsa_id": ident} if ident.upper().startswith("GHSA-") else None
            if ident.upper().startswith("CVE-"):
                params = {"cve_id": ident}
            if params is None:
                continue
            try:
                payload = self._get_json(GITHUB_ADVISORIES, params=params, headers=self._github_headers())
            except httpx.HTTPError as exc:
                errors.append(self._clean(f"github:{ident}: {exc}"))
                continue
            if isinstance(payload, list) and payload:
                sources.append(f"github:{ident}")
                return payload[0]
        return None

    def _nvd(self, cve: str, errors: list[str], sources: list[str]) -> dict | None:
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
        try:
            payload = self._get_json(NVD_CVE, params={"cveId": cve}, headers=headers)
        except httpx.HTTPError as exc:
            errors.append(self._clean(f"nvd:{cve}: {exc}"))
            return None
        vulnerabilities = (payload or {}).get("vulnerabilities") or []
        if not vulnerabilities:
            return None
        sources.append(f"nvd:{cve}")
        return vulnerabilities[0]

    def _github_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def _get_json(self, url: str, *, params: dict | None = None, headers: dict | None = None) -> dict | list | None:
        key = url + "?" + "&".join(f"{name}={value}" for name, value in sorted((params or {}).items()))
        if key in self._cache:
            return self._cache[key]
        response = self.http.get(url, params=params, headers=headers)
        try:
            if response.status_code == 404:
                self._cache[key] = None
                return None
            response.raise_for_status()
            payload = response.json()
        finally:
            response.close()
        self._cache[key] = payload
        return payload

    def _post_json(self, url: str, body: dict) -> dict | None:
        response = self.http.post(url, json=body)
        try:
            if response.status_code == 404:
                return None
            response.raise_for_status()
            payload = response.json()
        finally:
            response.close()
        return payload if isinstance(payload, dict) else None

    def _clean(self, text: str) -> str:
        return redact(text, [self.github_token, self.nvd_api_key])


def _advisory_id(value: str) -> bool:
    upper = value.upper()
    if upper.startswith("CWE-"):
        return False
    return upper.startswith(("CVE-", "GHSA-", "PYSEC-", "GO-", "RUSTSEC-", "NSWG-"))


def _overlaps(record: dict, identifiers: list[str], finding: dict) -> bool:
    aliases = {record.get("id"), *(record.get("aliases") or [])}
    aliases = {item for item in aliases if item}
    if aliases.intersection(identifiers):
        return True
    title = finding.get("title") or ""
    return any(item and item in title for item in aliases)


def _records_match_package(records: list[dict], package: str) -> bool:
    target = package.lower()
    for record in records:
        for affected in record.get("affected") or []:
            name = ((affected.get("package") or {}).get("name") or "").lower()
            if name == target:
                return True
    return False


def _matching_affected(records: list[dict], package: str | None) -> list[dict]:
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
    urls: list[str] = []
    for record in records:
        for ref in record.get("references") or []:
            url = ref.get("url") if isinstance(ref, dict) else None
            if url and url not in urls:
                urls.append(url)
            if len(urls) == 5:
                return urls
    return urls


def _from_osv(records: list[dict], package: str | None, version: str | None, sources: list[str], errors: list[str]) -> AdvisoryLookup:
    entries = _matching_affected(records, package)
    if package and not entries:
        return AdvisoryLookup(
            outcome=PACKAGE_MISMATCH,
            summary=f"OSV has this identifier, but it does not list package {package}.",
            sources=sources,
            errors=errors,
            references=_references(records),
        )
    affected_votes = [osv_version_affected(version, entry) for entry in entries] if version else []
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
        lambda candidate: any(osv_version_affected(candidate, entry) is True for entry in entries),
    )
    if affected is False:
        summary = "Installed version is outside the OSV affected range."
    elif fixed:
        summary = f"OSV lists fixed version(s): {', '.join(fixed)}."
    else:
        summary = "OSV lists this package as affected and does not publish a fixed version."
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
        lambda candidate: any(_github_range_contains(candidate, item) is True for item in ranges),
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
    cve = (record.get("cve") or {})
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
                end_excluding_version = parse_version(end_excluding) if end_excluding else None
                end_including_version = parse_version(end_including) if end_including else None
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
