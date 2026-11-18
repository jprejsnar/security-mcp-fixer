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

MAX_RELEASE_BYTES = 20 * 1024 * 1024


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
            "Release catalog contains versions that cannot be compared safely; "
            f"manual version investigation required: {', '.join(unknown[:5])}"
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
        raise ValueError(
            "No supported public release catalog for this package coordinate"
        )
    with httpx.Client(timeout=30.0) as client:
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
                    raise ValueError("Package release catalog exceeds the size limit")
    if ecosystem == "Maven":
        try:
            metadata = parse_xml(content)
        except ParseError as exc:
            raise ValueError(f"Invalid Maven release metadata: {exc}") from exc
        if (
            metadata.findtext("groupId") != group
            or metadata.findtext("artifactId") != artifact
        ):
            raise ValueError(
                "Maven release catalog does not match the requested coordinate"
            )
        versions = [
            node.text for node in metadata.findall("./versioning/versions/version")
        ]
    else:
        payload = json.loads(content)
        if not isinstance(payload, dict):
            raise ValueError("Package release catalog must be an object")
        if ecosystem == "npm":
            if payload.get("name") != package:
                raise ValueError(
                    "npm release catalog does not match the requested package"
                )
            releases = payload.get("versions")
            if not isinstance(releases, dict):
                raise ValueError("npm release catalog has no version metadata")
            if not all(isinstance(metadata, dict) for metadata in releases.values()):
                raise ValueError(
                    "npm release catalog contains invalid version metadata"
                )
            versions = [
                version
                for version, metadata in releases.items()
                if not metadata.get("deprecated")
            ]
        else:
            versions = payload.get("versions")
    if not isinstance(versions, list):
        raise ValueError("Package release catalog has no valid version list")
    published: list[str] = []
    for raw in versions:
        if not isinstance(raw, str):
            raise ValueError("Package release catalog has no valid version list")
        published.append(raw)
    stable = stable_versions(published, ecosystem=ecosystem)
    if not stable:
        raise ValueError(
            "Package release catalog contains no comparable stable releases"
        )
    return {"source": url, "versions": stable}


def reviewed_selection(catalog: dict, floor: str, review: dict) -> dict:
    """Choose the newest release not excluded by documented support/runtime/fee evidence."""
    if not isinstance(review, dict):
        raise ValueError("Provide a release review for the actual project runtime")
    if (
        review.get("supported") is not True
        or review.get("runtime_compatible") is not True
    ):
        raise ValueError(
            "Confirm publisher support and compatibility with the actual project runtime"
        )
    _evidence(review)
    exclusions = review.get("excluded_releases", [])
    if not isinstance(exclusions, list):
        raise ValueError("excluded_releases must be a list")
    excluded = {}
    for item in exclusions:
        if not isinstance(item, dict) or item.get("reason") not in {
            "unsupported",
            "runtime_incompatible",
            "paid",
        }:
            raise ValueError(
                "Exclude releases only for unsupported, runtime_incompatible, or paid terms"
            )
        _evidence(item)
        version = item.get("version")
        if version not in catalog["versions"] or version in excluded:
            raise ValueError(
                "Excluded releases must identify distinct published stable versions"
            )
        excluded[version] = item
    minimum = parse_version(floor)
    if minimum is None:
        raise ValueError("The advisory fix floor is not comparable")
    candidates = [
        raw
        for raw in catalog["versions"]
        if raw not in excluded and parse_version(raw) >= minimum
    ]
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
        raise ValueError("Release evidence requires an assessment")
    sources = review.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError(
            "Release evidence requires official support/runtime/license sources"
        )
    for source in sources:
        if not isinstance(source, str):
            raise ValueError("Release evidence sources must be HTTPS URLs")
        parsed = urlsplit(source)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError(
                "Release evidence sources must be credential-free HTTPS URLs"
            )
