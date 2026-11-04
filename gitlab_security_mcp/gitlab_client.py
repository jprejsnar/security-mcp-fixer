"""Read-only GitLab client. Findings come from GraphQL. Nothing is mutated."""

from __future__ import annotations

import codecs
import re
import threading
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

import httpx

from gitlab_security_mcp.util import redact, timed_http_stream
from gitlab_security_mcp.versions import parse_fixed_versions

FINDINGS_QUERY = """
query SecurityFindings($fullPath: ID!, $trackedRefIds: [SecurityProjectTrackedContextID!]!, $after: String) {
  project(fullPath: $fullPath) {
    vulnerabilities(first: 100, after: $after, state: [DETECTED, CONFIRMED], trackedRefIds: $trackedRefIds, hasResolution: false) {
            pageInfo { hasNextPage endCursor }
      nodes {
        id
                latestDetectedPipeline { id iid sha ref status createdAt }
                uuid
                title
                description
                severity
                state
                trackedRef { id name }
                resolvedOnDefaultBranch
                reportType
                solution
                falsePositive
                scanner { externalId name vendor }
                identifiers { externalType externalId name url }
                links { name url }
                details { ...FuzzingDetail }
                latestSecurityReportFinding {
                    evidence {
                        summary
                        source { identifier name url }
                        request { ...FuzzingRequest }
                        response { ...FuzzingResponse }
                        supportingMessages {
                            name
                            request { ...FuzzingRequest }
                            response { ...FuzzingResponse }
                        }
                    }
                    details { ...FuzzingDetail }
                }
                location {
                    ... on VulnerabilityLocationDependencyScanning {
                        file
                        blobPath
                        dependency { package { name } version }
                    }
                    ... on VulnerabilityLocationContainerScanning {
                        image
                        operatingSystem
                        dependency { package { name } version }
                    }
                    ... on VulnerabilityLocationSast {
                        file
                        startLine
                        endLine
                        vulnerableClass
                        vulnerableMethod
                        blobPath
                    }
                    ... on VulnerabilityLocationSecretDetection {
                        file
                        startLine
                        endLine
                        blobPath
                    }
                    ... on VulnerabilityLocationDast {
                        hostname
                        path
                        param
                        requestMethod
                    }
                }
      }
    }
  }
}
fragment FuzzingRequest on VulnerabilityRequest {
    method url body headers { name value }
}
fragment FuzzingResponse on VulnerabilityResponse {
    statusCode reasonPhrase body headers { name value }
}
fragment FuzzingDetail on VulnerabilityDetail {
    __typename
    ... on VulnerabilityDetailText { fieldName name description value }
    ... on VulnerabilityDetailCode { fieldName name description lang value }
    ... on VulnerabilityDetailMarkdown { fieldName name description value }
    ... on VulnerabilityDetailDiff { fieldName name description before after }
}
""".strip()

TRACKED_REFS_QUERY = """
query SecurityTrackedRefs($fullPath: ID!, $after: String) {
    project(fullPath: $fullPath) {
        securityTrackedRefs(first: 100, after: $after) {
            pageInfo { hasNextPage endCursor }
            nodes { id name refType }
        }
    }
}
""".strip()

_TITLE_PACKAGE = re.compile(r"\bin\s+([A-Za-z0-9_@./+-]+)\s*$")
KEEP_STATES = {"detected", "confirmed"}


MAX_PAGES = 20


@dataclass
class FetchResult:
    """Project vulnerability report findings, or the reason they could not be read."""

    ok: bool
    findings: list[dict] = field(default_factory=list)
    pipeline: dict | None = None
    project_path: str | None = None
    excluded: dict | None = None
    error: str | None = None
    truncated: bool = False


class GitLabClient:
    """GraphQL-only finding retrieval. POST is used because GitLab GraphQL requires it.

    The client keeps one HTTP connection pool for the life of the process.
    Call ``close`` when the server shuts down. An injected ``http`` client
    is left for its owner to close.
    """

    def __init__(
        self,
        token: str | None,
        api_url: str = "https://gitlab.com/api/v4",
        *,
        http: httpx.Client | None = None,
        max_findings: int = 1000,
        http_log_path: Path | None = None,
    ):
        """Configure report retrieval and retain any caller-owned HTTP client."""
        self.token = token
        self.api_url = api_url.rstrip("/")
        self._owns_http = http is None
        self.http = http if http is not None else httpx.Client(timeout=30.0)
        self.max_findings = max_findings
        self.http_log_path = http_log_path
        self._closed = False
        self._lock = threading.RLock()

    def close(self) -> None:
        """Close the owned HTTP client. Repeated calls do nothing."""
        with self._lock:
            if self._closed:
                return
            try:
                if self._owns_http:
                    self.http.close()
            finally:
                self._closed = True

    def __enter__(self) -> GitLabClient:
        """Return this GitLab client for use in a context manager."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close only the HTTP client owned by this GitLab client."""
        self.close()

    def fetch(self, project_id: str) -> FetchResult:
        """Fetch still-detected needs-triage or confirmed findings on main.

        project_id may be a numeric GitLab id or a namespace/project path.
        Return FetchResult with normalized findings, exclusions, and a
        truncation flag. Missing access, malformed data, and closed-client
        calls return an error result; no GitLab mutation is performed.
        """
        with self._lock:
            if self._closed:
                return FetchResult(ok=False, error="GitLab client is closed")
            return self._fetch(project_id)

    def _fetch(self, project_id: str) -> FetchResult:
        """Validate inputs and contain request or normalization failures."""
        if not self.token:
            return FetchResult(ok=False, error="GITLAB_TOKEN is required")
        if not project_id:
            return FetchResult(ok=False, error="GITLAB_PROJECT_ID is required")
        if (
            "mutation" in FINDINGS_QUERY.lower()
            or "mutation" in TRACKED_REFS_QUERY.lower()
        ):
            return FetchResult(
                ok=False, error="Refusing a GitLab query that is not read-only"
            )
        try:
            full_path = self._full_path(project_id)
            pipeline, raw_nodes, truncated = self._findings(full_path)
            normalized = [normalize_finding(node, pipeline) for node in raw_nodes]
            kept, excluded = split_states(normalized)
        except (
            httpx.HTTPError,
            RuntimeError,
            ValueError,
            TypeError,
            AttributeError,
        ) as exc:
            return FetchResult(ok=False, error=self._clean(str(exc)))
        if len(kept) > self.max_findings:
            kept = kept[: self.max_findings]
            truncated = True
        return FetchResult(
            ok=True,
            findings=kept,
            pipeline=pipeline,
            project_path=full_path,
            excluded=excluded,
            truncated=truncated,
        )

    def _full_path(self, project_id: str) -> str:
        """Resolve numeric project ids and normalize encoded project paths."""
        if project_id.isdigit():
            payload = self._request(
                "GET", f"{self.api_url}/projects/{quote(project_id, safe='')}"
            )
            path = payload.get("path_with_namespace")
            if not path:
                raise RuntimeError(
                    "GitLab project lookup did not return path_with_namespace"
                )
            return path
        return unquote(project_id).strip("/")

    def _main_tracked_ref(self, full_path: str) -> str:
        """Resolve tracked main with bounded, advancing pagination.

        Raise if main is unreadable or missing instead of dropping filters.
        """
        after = None
        for _page in range(MAX_PAGES):
            payload = self._graphql(
                TRACKED_REFS_QUERY, {"fullPath": full_path, "after": after}
            )
            project = (payload.get("data") or {}).get("project")
            if not project:
                raise RuntimeError(
                    f"GitLab project '{full_path}' was not found or is not readable"
                )
            connection = _connection(project, "securityTrackedRefs")
            for tracked_ref in connection["nodes"]:
                if (
                    tracked_ref.get("name") == "main"
                    and tracked_ref.get("refType") == "BRANCH"
                    and tracked_ref.get("id")
                ):
                    return tracked_ref["id"]
            page = connection["pageInfo"]
            if not page.get("hasNextPage"):
                raise RuntimeError(
                    "GitLab security tracked branch 'main' was not found; refusing to fetch unfiltered findings"
                )
            if not page.get("endCursor") or page["endCursor"] == after:
                raise RuntimeError("GitLab tracked-ref pagination did not advance")
            after = page["endCursor"]
        raise RuntimeError("GitLab tracked-ref lookup exceeded the page limit")

    def _findings(self, full_path: str) -> tuple[dict | None, list[dict], bool]:
        """Page the persistent filtered report and flag incomplete results."""
        tracked_ref_id = self._main_tracked_ref(full_path)
        after = None
        pipeline = None
        nodes: list[dict] = []
        for _page in range(MAX_PAGES):
            payload = self._graphql(
                FINDINGS_QUERY,
                {
                    "fullPath": full_path,
                    "trackedRefIds": [tracked_ref_id],
                    "after": after,
                },
            )
            project = (payload.get("data") or {}).get("project")
            if not project:
                raise RuntimeError(
                    f"GitLab project '{full_path}' was not found or is not readable"
                )
            connection = _connection(project, "vulnerabilities")
            nodes.extend(connection["nodes"])
            page = connection["pageInfo"]
            if not page.get("hasNextPage"):
                return pipeline, nodes, False
            if not page.get("endCursor") or page["endCursor"] == after:
                raise RuntimeError(
                    "GitLab vulnerability report pagination did not advance"
                )
            after = page["endCursor"]
            if len(nodes) >= self.max_findings:
                return pipeline, nodes, True
        return pipeline, nodes, True

    def _graphql(self, query: str, variables: dict) -> dict:
        """Send only query operations to the GitLab GraphQL endpoint."""
        if not query.strip().lower().startswith("query"):
            raise RuntimeError("Only GitLab GraphQL queries are allowed")
        return self._request(
            "POST",
            self._graphql_url(),
            json_body={"query": query, "variables": variables},
        )

    def _graphql_url(self) -> str:
        """Derive GraphQL routing from GitLab's configured REST base URL."""
        if self.api_url.endswith("/api/v4"):
            return self.api_url[: -len("/api/v4")] + "/api/graphql"
        parsed = urlparse(self.api_url)
        return f"{parsed.scheme}://{parsed.netloc}/api/graphql"

    def _request(self, method: str, url: str, json_body: dict | None = None) -> dict:
        """Authenticate, close responses, and reject HTTP or GraphQL errors."""
        with timed_http_stream(
            self.http,
            method,
            url,
            source="gitlab",
            log_path=self.http_log_path,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
            },
            json=json_body,
        ) as response:
            if response.status_code >= 400:
                detail = self._clean(
                    f"GitLab {method} {url} returned {response.status_code}: "
                    f"{_response_excerpt(response)}"
                )
                raise RuntimeError(detail)
            response.read()
            payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError(f"GitLab {method} {url} did not return a JSON object")
        if payload.get("errors"):
            errors = payload["errors"]
            if not isinstance(errors, list) or any(
                not isinstance(error, dict) for error in errors
            ):
                raise ValueError("GitLab returned malformed GraphQL errors")
            message = "; ".join(
                str(error.get("message") or "unknown GraphQL error") for error in errors
            )
            raise RuntimeError(self._clean(message))
        return payload

    def _clean(self, text: str) -> str:
        """Remove the GitLab token from returned or logged request details."""
        return redact(text, [self.token])


def _response_excerpt(response: httpx.Response, limit: int = 500) -> str:
    """Decode only the first part of an error body.

    The remainder stays on the wire and is discarded when the response
    closes, so a large error page cannot be retained in the failure result.
    """
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    kept: list[str] = []
    count = 0
    for chunk in response.iter_bytes(chunk_size=256):
        text = decoder.decode(chunk)
        room = limit - count
        if room <= 0:
            break
        piece = text[:room]
        kept.append(piece)
        count += len(piece)
        if count >= limit:
            break
    if count < limit:
        kept.append(decoder.decode(b"", final=True)[: limit - count])
    return "".join(kept)


def _connection(project: dict, name: str) -> dict:
    """Reject unreadable GraphQL nodes or pagination instead of emptying them."""
    connection = project.get(name)
    if not isinstance(connection, dict):
        raise RuntimeError(f"GitLab {name} connection is not readable")
    nodes = connection.get("nodes")
    page = connection.get("pageInfo")
    if not isinstance(nodes, list) or any(not isinstance(node, dict) for node in nodes):
        raise ValueError(f"GitLab {name} nodes are malformed")
    if not isinstance(page, dict) or not isinstance(page.get("hasNextPage"), bool):
        raise ValueError(f"GitLab {name} pagination is malformed")
    return connection


def _pipeline_summary(node: dict) -> dict:
    """Keep pipeline provenance fields used in normalized findings."""
    return {
        "id": node.get("id"),
        "iid": node.get("iid"),
        "sha": node.get("sha"),
        "ref": node.get("ref"),
        "status": node.get("status"),
        "createdAt": node.get("createdAt"),
    }


def _identifier(item: dict) -> str | None:
    """Prefer external identifiers and normalize missing CVE prefixes."""
    external_type = (item.get("externalType") or "").lower()
    external_id = (item.get("externalId") or "").strip()
    name = (item.get("name") or "").strip()
    if external_type == "cve" and external_id:
        return (
            external_id
            if external_id.upper().startswith("CVE-")
            else f"CVE-{external_id}"
        )
    if external_id:
        return external_id
    return name or None


def _component_from_title(title: str | None) -> str | None:
    """Extract a package name only when the scanner title matches a pattern."""
    if not title:
        return None
    match = _TITLE_PACKAGE.search(title.strip())
    return match.group(1) if match else None


def normalize_finding(node: dict, pipeline: dict | None) -> dict:
    """Convert one GraphQL finding into the shape the engine and report use."""
    if node.get("latestDetectedPipeline"):
        pipeline = _pipeline_summary(node["latestDetectedPipeline"])
    identifiers = []
    for item in node.get("identifiers") or []:
        identifier = _identifier(item)
        if identifier and identifier not in identifiers:
            identifiers.append(identifier)
    location = node.get("location") or {}
    dependency = location.get("dependency") or {}
    package = dependency.get("package") or {}
    component = package.get("name") or _component_from_title(node.get("title"))
    installed = dependency.get("version")
    solution = node.get("solution")
    file_path = location.get("file") or location.get("path")
    latest = node.get("latestSecurityReportFinding") or {}
    scanner_evidence = _scanner_evidence(latest.get("evidence"))
    scanner_details = deepcopy(latest.get("details") or node.get("details") or [])
    return {
        "id": node.get("uuid")
        or node.get("id")
        or node.get("title")
        or "unknown-finding",
        "title": node.get("title"),
        "description": node.get("description"),
        "scanner": (node.get("scanner") or {}).get("name"),
        "category": (node.get("reportType") or "").lower(),
        "severity": (node.get("severity") or "").lower(),
        "confidence": None,
        "identifiers": identifiers,
        "component": component,
        "installedVersion": installed,
        "affectedRange": None,
        "fixedVersions": parse_fixed_versions(solution),
        "dependencyPath": [],
        "location": {
            "file": file_path,
            "startLine": location.get("startLine"),
            "endLine": location.get("endLine"),
            "image": location.get("image"),
            "operatingSystem": location.get("operatingSystem"),
            "class": location.get("vulnerableClass"),
            "method": location.get("vulnerableMethod"),
            "hostname": location.get("hostname"),
            "path": location.get("path"),
            "param": location.get("param"),
            "requestMethod": location.get("requestMethod"),
        },
        "status": (node.get("state") or "").lower(),
        "trackedRef": node.get("trackedRef"),
        "resolvedOnDefaultBranch": node.get("resolvedOnDefaultBranch"),
        "falsePositiveFlag": node.get("falsePositive"),
        "solution": solution,
        "links": [
            link.get("url") for link in (node.get("links") or []) if link.get("url")
        ],
        "pipeline": pipeline,
        "scannerEvidence": scanner_evidence,
        "scannerDetails": scanner_details,
        "evidence": [],
        "assessment": None,
        "remediationDecision": None,
        "proposedFix": None,
    }


def _scanner_evidence(evidence: dict | None) -> dict | None:
    """Preserve HTTP bodies and payload URLs while masking credential headers."""
    if evidence is None:
        return None
    if not isinstance(evidence, dict):
        raise ValueError("GitLab returned malformed scanner evidence")
    captured = deepcopy(evidence)
    messages = captured.get("supportingMessages") or []
    if not isinstance(messages, list) or any(
        not isinstance(message, dict) for message in messages
    ):
        raise ValueError("GitLab returned malformed supporting messages")
    sensitive = {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
    }
    for message in [captured, *messages]:
        for kind in ("request", "response"):
            exchange = message.get(kind)
            if exchange is None:
                continue
            if not isinstance(exchange, dict):
                raise ValueError("GitLab returned malformed request/response evidence")
            for header in exchange.get("headers") or []:
                if not isinstance(header, dict) or not isinstance(
                    header.get("name"), str
                ):
                    raise ValueError("GitLab returned malformed evidence headers")
                if header["name"].strip().lower() in sensitive:
                    header["value"] = "[REDACTED]"
    return captured


def split_states(findings: list[dict]) -> tuple[list[dict], dict]:
    """Keep detected and confirmed findings and count the rest by state."""
    kept: list[dict] = []
    excluded: dict[str, int] = {}
    for finding in findings:
        status = finding.get("status") or ""
        if status in KEEP_STATES:
            kept.append(finding)
        else:
            excluded[status or "unknown"] = excluded.get(status or "unknown", 0) + 1
    return kept, excluded
