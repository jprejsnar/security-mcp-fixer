"""Read public release catalogs and validate reviewed support exclusions."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import quote, urlsplit
from xml.etree.ElementTree import ParseError

import httpx

from gitlab_security_mcp.util import parse_xml, timed_http_stream
from gitlab_security_mcp.versions import parse_version

_RAISE_RELEASE_CATALOG_CONTAINS_VERSIONS_THAT_CANNOT_BE_COMPARED = "Release catalog contains versions that cannot be compared safely; manual version investigation required: {}"
_RAISE_PACKAGE_RELEASE_CATALOG_HAS_NO_VALID_VERSION_LIST = (
    "Package release catalog has no valid version list"
)
_RAISE_PACKAGE_RELEASE_CATALOG_CONTAINS_NO_COMPARABLE_STABLE_RELEASES = (
    "Package release catalog contains no comparable stable releases"
)
_RAISE_PROVIDE_A_RELEASE_REVIEW_FOR_THE_ACTUAL_PROJECT = (
    "Provide a release review for the actual project runtime"
)
_RAISE_CONFIRM_PUBLISHER_SUPPORT_AND_COMPATIBILITY_WITH_THE_ACTUAL = (
    "Confirm publisher support and compatibility with the actual project runtime"
)
_RAISE_EXCLUDED_RELEASES_MUST_BE_A_LIST = "excluded_releases must be a list"
_RAISE_THE_ADVISORY_FIX_FLOOR_IS_NOT_COMPARABLE = (
    "The advisory fix floor is not comparable"
)
_RAISE_RELEASE_EVIDENCE_REQUIRES_AN_ASSESSMENT = (
    "Release evidence requires an assessment"
)
_RAISE_RELEASE_EVIDENCE_REQUIRES_OFFICIAL_SUPPORT_RUNTIME_LICENSE_SOURCES = (
    "Release evidence requires official support/runtime/license sources"
)
_RAISE_MAVEN_RELEASE_CATALOG_DOES_NOT_MATCH_THE_REQUESTED = (
    "Maven release catalog does not match the requested coordinate"
)
_RAISE_PACKAGE_RELEASE_CATALOG_MUST_BE_AN_OBJECT = (
    "Package release catalog must be an object"
)
_RAISE_EXCLUDE_RELEASES_ONLY_FOR_UNSUPPORTED_RUNTIME_INCOMPATIBLE_OR = (
    "Exclude releases only for unsupported, runtime_incompatible, or paid terms"
)
_RAISE_EXCLUDED_RELEASES_MUST_IDENTIFY_DISTINCT_PUBLISHED_STABLE_VERSIONS = (
    "Excluded releases must identify distinct published stable versions"
)
_RAISE_RELEASE_EVIDENCE_SOURCES_MUST_BE_HTTPS_URLS = (
    "Release evidence sources must be HTTPS URLs"
)
_RAISE_RELEASE_EVIDENCE_SOURCES_MUST_BE_CREDENTIAL_FREE_HTTPS = (
    "Release evidence sources must be credential-free HTTPS URLs"
)
_RAISE_NO_SUPPORTED_PUBLIC_RELEASE_CATALOG_FOR_THIS_PACKAGE = (
    "No supported public release catalog for this package coordinate"
)
_RAISE_INVALID_MAVEN_RELEASE_METADATA = "Invalid Maven release metadata: {}"
_RAISE_NPM_RELEASE_CATALOG_DOES_NOT_MATCH_THE_REQUESTED = (
    "npm release catalog does not match the requested package"
)
_RAISE_NPM_RELEASE_CATALOG_HAS_NO_VERSION_METADATA = (
    "npm release catalog has no version metadata"
)
_RAISE_NPM_RELEASE_CATALOG_CONTAINS_INVALID_VERSION_METADATA = (
    "npm release catalog contains invalid version metadata"
)
_RAISE_PACKAGE_RELEASE_CATALOG_EXCEEDS_THE_SIZE_LIMIT = (
    "Package release catalog exceeds the size limit"
)

MAX_RELEASE_BYTES = 20 * 1024 * 1024
_HTTP_TIMEOUT_SECONDS = 30.0
_MAX_REPORTED_UNKNOWN_VERSIONS = 5


def stable_versions(versions: list[str], *, ecosystem: str | None = None) -> list[str]:
    """Return comparable stable releases, newest first, excluding prereleases."""
    candidates = [
        raw
        for raw in versions
        if not (
            (ecosystem in {"npm", "NuGet"} and "-" in raw.split("+", 1)[0])
            or re.search(
                r"[.-](?:snapshot|alpha|beta|preview|rc|cr|m|milestone|dev|next|canary|ci|ea|eap)(?:[.\d-].*)?$",
                raw,
                re.IGNORECASE,
            )
        )
    ]
    parsed = [(parse_version(raw), raw) for raw in candidates]
    unknown = [raw for version, raw in parsed if version is None]
    if unknown:
        raise ValueError(
            _RAISE_RELEASE_CATALOG_CONTAINS_VERSIONS_THAT_CANNOT_BE_COMPARED.format(
                ", ".join(unknown[:_MAX_REPORTED_UNKNOWN_VERSIONS])
            )
        )
    return [
        raw
        for version, raw in sorted(
            ((version, raw) for version, raw in parsed if version is not None),
            reverse=True,
        )
        if not version.is_prerelease and not version.is_devrelease
    ]


def release_catalog(
    ecosystem: str, package: str, *, log_path: Path | None = None
) -> dict:
    """Read published stable versions without sending repository data or credentials."""
    if ecosystem == "npm" and re.fullmatch(
        r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+", package
    ):
        url = f"https://registry.npmjs.org/{quote(package, safe='')}"
    elif ecosystem == "NuGet" and re.fullmatch(r"[A-Za-z0-9._-]+", package):
        url = f"https://api.nuget.org/v3-flatcontainer/{package.lower()}/index.json"
    elif ecosystem == "Maven" and re.fullmatch(
        r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+", package
    ):
        group, artifact = package.split(":")
        url = (
            f"https://repo.maven.apache.org/maven2/{group.replace('.', '/')}/"
            f"{artifact}/maven-metadata.xml"
        )
    else:
        raise ValueError(_RAISE_NO_SUPPORTED_PUBLIC_RELEASE_CATALOG_FOR_THIS_PACKAGE)
    with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS) as client:
        with timed_http_stream(
            client,
            "GET",
            url,
            source="package_releases",
            log_path=log_path,
        ) as response:
            response.raise_for_status()
            content = bytearray()
            for chunk in response.iter_bytes():
                content.extend(chunk)
                if len(content) > MAX_RELEASE_BYTES:
                    raise ValueError(
                        _RAISE_PACKAGE_RELEASE_CATALOG_EXCEEDS_THE_SIZE_LIMIT
                    )
    if ecosystem == "Maven":
        try:
            metadata = parse_xml(content)
        except ParseError as exc:
            raise ValueError(_RAISE_INVALID_MAVEN_RELEASE_METADATA.format(exc)) from exc
        if (
            metadata.findtext("groupId") != group
            or metadata.findtext("artifactId") != artifact
        ):
            raise ValueError(_RAISE_MAVEN_RELEASE_CATALOG_DOES_NOT_MATCH_THE_REQUESTED)
        versions = [
            node.text for node in metadata.findall("./versioning/versions/version")
        ]
    else:
        payload = json.loads(content)
        if not isinstance(payload, dict):
            raise ValueError(_RAISE_PACKAGE_RELEASE_CATALOG_MUST_BE_AN_OBJECT)
        if ecosystem == "npm":
            if payload.get("name") != package:
                raise ValueError(
                    _RAISE_NPM_RELEASE_CATALOG_DOES_NOT_MATCH_THE_REQUESTED
                )
            releases = payload.get("versions")
            if not isinstance(releases, dict):
                raise ValueError(_RAISE_NPM_RELEASE_CATALOG_HAS_NO_VERSION_METADATA)
            if not all(isinstance(metadata, dict) for metadata in releases.values()):
                raise ValueError(
                    _RAISE_NPM_RELEASE_CATALOG_CONTAINS_INVALID_VERSION_METADATA
                )
            versions = [
                version
                for version, metadata in releases.items()
                if not metadata.get("deprecated")
            ]
        else:
            versions = payload.get("versions")
    if not isinstance(versions, list):
        raise ValueError(_RAISE_PACKAGE_RELEASE_CATALOG_HAS_NO_VALID_VERSION_LIST)
    published: list[str] = []
    for raw in versions:
        if not isinstance(raw, str):
            raise ValueError(_RAISE_PACKAGE_RELEASE_CATALOG_HAS_NO_VALID_VERSION_LIST)
        published.append(raw)
    stable = stable_versions(published, ecosystem=ecosystem)
    if not stable:
        raise ValueError(
            _RAISE_PACKAGE_RELEASE_CATALOG_CONTAINS_NO_COMPARABLE_STABLE_RELEASES
        )
    return {"source": url, "versions": stable}


def reviewed_selection(catalog: dict, floor: str, review: dict) -> dict:
    """Choose the newest release not excluded by documented support/runtime/fee evidence.

    The top-level supported/runtime_compatible attestations describe the selected
    target. When the review's exclusions leave no eligible release, there is no
    target to attest, so an honest false or null is accepted and nothing is edited.
    """
    if not isinstance(review, dict):
        raise ValueError(_RAISE_PROVIDE_A_RELEASE_REVIEW_FOR_THE_ACTUAL_PROJECT)
    _evidence(review)
    exclusions = review.get("excluded_releases", [])
    if not isinstance(exclusions, list):
        raise ValueError(_RAISE_EXCLUDED_RELEASES_MUST_BE_A_LIST)
    excluded = {}
    for item in exclusions:
        if not isinstance(item, dict) or item.get("reason") not in {
            "unsupported",
            "runtime_incompatible",
            "paid",
        }:
            raise ValueError(
                _RAISE_EXCLUDE_RELEASES_ONLY_FOR_UNSUPPORTED_RUNTIME_INCOMPATIBLE_OR
            )
        _evidence(item)
        version = item.get("version")
        if version not in catalog["versions"] or version in excluded:
            raise ValueError(
                _RAISE_EXCLUDED_RELEASES_MUST_IDENTIFY_DISTINCT_PUBLISHED_STABLE_VERSIONS
            )
        excluded[version] = item
    minimum = parse_version(floor)
    if minimum is None:
        raise ValueError(_RAISE_THE_ADVISORY_FIX_FLOOR_IS_NOT_COMPARABLE)
    candidates = [
        raw
        for raw in catalog["versions"]
        if raw not in excluded and parse_version(raw) >= minimum
    ]
    if candidates and (
        review.get("supported") is not True
        or review.get("runtime_compatible") is not True
    ):
        raise ValueError(
            _RAISE_CONFIRM_PUBLISHER_SUPPORT_AND_COMPATIBILITY_WITH_THE_ACTUAL
        )
    paid = [item for item in exclusions if item["reason"] == "paid"]
    return {
        "target": candidates[0] if candidates else None,
        "source": catalog["source"],
        "review": review,
        "paid_releases": paid,
    }


def _evidence(review: dict) -> None:
    """Require explicit assessments and credential-free HTTPS publisher citations."""
    if (
        not isinstance(review.get("assessment"), str)
        or not review["assessment"].strip()
    ):
        raise ValueError(_RAISE_RELEASE_EVIDENCE_REQUIRES_AN_ASSESSMENT)
    sources = review.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError(
            _RAISE_RELEASE_EVIDENCE_REQUIRES_OFFICIAL_SUPPORT_RUNTIME_LICENSE_SOURCES
        )
    for source in sources:
        if not isinstance(source, str):
            raise ValueError(_RAISE_RELEASE_EVIDENCE_SOURCES_MUST_BE_HTTPS_URLS)
        parsed = urlsplit(source)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError(
                _RAISE_RELEASE_EVIDENCE_SOURCES_MUST_BE_CREDENTIAL_FREE_HTTPS
            )
