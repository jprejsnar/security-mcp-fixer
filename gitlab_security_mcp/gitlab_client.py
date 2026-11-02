"""Read-only GitLab client. Findings come from GraphQL. Nothing is mutated."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlparse

import httpx

from gitlab_security_mcp.util import redact
from gitlab_security_mcp.versions import parse_fixed_versions

FINDINGS_QUERY = """
query SecurityFindings($fullPath: ID!, $ref: String!, $after: String) {
  project(fullPath: $fullPath) {
    pipelines(first: 1, ref: $ref, status: SUCCESS) {
      nodes {
        id
        iid
        sha
        ref
        status
        createdAt
        securityReportFindings(first: 100, after: $after) {
          pageInfo { hasNextPage endCursor }
          nodes {
            uuid
            title
            description
            severity
            state
            reportType
            solution
            falsePositive
            scanner { externalId name vendor }
            identifiers { externalType externalId name url }
            links { name url }
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
  }
}
""".strip()

ROOT_REF_QUERY = """
query DefaultBranch($fullPath: ID!) {
  project(fullPath: $fullPath) {
    repository { rootRef }
  }
}
""".strip()

_TITLE_PACKAGE = re.compile(r"\bin\s+([A-Za-z0-9_@./+-]+)\s*$")
KEEP_STATES = {"detected", "confirmed", ""}


MAX_PAGES = 20


@dataclass
class FetchResult:
    """Findings from one pipeline, or the reason they could not be read."""

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
    ):
        self.token = token
        self.api_url = api_url.rstrip("/")
        self._owns_http = http is None
        self.http = http or httpx.Client(timeout=30.0)
        self.max_findings = max_findings
        self._closed = False

    def close(self) -> None:
        """Close the owned HTTP client. Repeated calls do nothing."""
        if self._closed or not self._owns_http:
            self._closed = True
            return
        self.http.close()
        self._closed = True

    def __enter__(self) -> GitLabClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def fetch(self, project_id: str) -> FetchResult:
        """Return detected and confirmed findings from the latest successful pipeline."""
        if not self.token:
            return FetchResult(ok=False, error="GITLAB_TOKEN is required")
        if not project_id:
            return FetchResult(ok=False, error="GITLAB_PROJECT_ID is required")
        if "mutation" in FINDINGS_QUERY.lower() or "mutation" in ROOT_REF_QUERY.lower():
            return FetchResult(ok=False, error="Refusing a GitLab query that is not read-only")
        try:
            full_path = self._full_path(project_id)
            root_ref = self._root_ref(full_path)
            pipeline, raw_nodes, truncated = self._findings(full_path, root_ref)
        except (httpx.HTTPError, RuntimeError, ValueError) as exc:
            return FetchResult(ok=False, error=self._clean(str(exc)))
        normalized = [normalize_finding(node, pipeline) for node in raw_nodes]
        kept, excluded = split_states(normalized)
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
        if project_id.isdigit():
            payload = self._request("GET", f"{self.api_url}/projects/{quote(project_id, safe='')}")
            path = payload.get("path_with_namespace")
            if not path:
                raise RuntimeError("GitLab project lookup did not return path_with_namespace")
            return path
        return unquote(project_id).strip("/")

    def _root_ref(self, full_path: str) -> str:
        payload = self._graphql(ROOT_REF_QUERY, {"fullPath": full_path})
        project = (payload.get("data") or {}).get("project")
        if not project:
            raise RuntimeError(f"GitLab project '{full_path}' was not found or is not readable")
        ref = ((project.get("repository") or {}).get("rootRef")) or "main"
        return ref

    def _findings(self, full_path: str, ref: str) -> tuple[dict | None, list[dict], bool]:
        after = None
        pipeline = None
        nodes: list[dict] = []
        for _page in range(MAX_PAGES):
            payload = self._graphql(FINDINGS_QUERY, {"fullPath": full_path, "ref": ref, "after": after})
            project = (payload.get("data") or {}).get("project")
            if not project:
                raise RuntimeError(f"GitLab project '{full_path}' was not found or is not readable")
            pipelines = ((project.get("pipelines") or {}).get("nodes")) or []
            if not pipelines:
                raise RuntimeError(f"No successful pipeline found on the default branch '{ref}'")
            current = _pipeline_summary(pipelines[0])
            # Each page asks for the newest pipeline again. If a newer one
            # finished mid-read, the cursor belongs to a different pipeline.
            if pipeline is not None and current.get("id") != pipeline.get("id"):
                raise RuntimeError("A newer pipeline finished while findings were being read. List the findings again.")
            pipeline = current
            connection = pipelines[0].get("securityReportFindings") or {}
            nodes.extend(connection.get("nodes") or [])
            page = connection.get("pageInfo") or {}
            if not page.get("hasNextPage") or not page.get("endCursor"):
                return pipeline, nodes, False
            after = page["endCursor"]
            if len(nodes) >= self.max_findings:
                return pipeline, nodes, True
        return pipeline, nodes, True

    def _graphql(self, query: str, variables: dict) -> dict:
        if not query.strip().lower().startswith("query"):
            raise RuntimeError("Only GitLab GraphQL queries are allowed")
        return self._request(
            "POST",
            self._graphql_url(),
            json_body={"query": query, "variables": variables},
        )

    def _graphql_url(self) -> str:
        if self.api_url.endswith("/api/v4"):
            return self.api_url[: -len("/api/v4")] + "/api/graphql"
        parsed = urlparse(self.api_url)
        return f"{parsed.scheme}://{parsed.netloc}/api/graphql"

    def _request(self, method: str, url: str, json_body: dict | None = None) -> dict:
        response = self.http.request(
            method,
            url,
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
            json=json_body,
        )
        try:
            if response.status_code >= 400:
                detail = self._clean(f"GitLab {method} {url} returned {response.status_code}: {response.text[:500]}")
                raise RuntimeError(detail)
            payload = response.json()
        finally:
            response.close()
        if not isinstance(payload, dict):
            raise RuntimeError(f"GitLab {method} {url} did not return a JSON object")
        if payload.get("errors"):
            message = "; ".join(error.get("message", "unknown GraphQL error") for error in payload["errors"])
            raise RuntimeError(self._clean(message))
        return payload

    def _clean(self, text: str) -> str:
        return redact(text, [self.token])


def _pipeline_summary(node: dict) -> dict:
    return {
        "id": node.get("id"),
        "iid": node.get("iid"),
        "sha": node.get("sha"),
        "ref": node.get("ref"),
        "status": node.get("status"),
        "createdAt": node.get("createdAt"),
    }


def _identifier(item: dict) -> str | None:
    external_type = (item.get("externalType") or "").lower()
    external_id = (item.get("externalId") or "").strip()
    name = (item.get("name") or "").strip()
    if external_type == "cve" and external_id:
        return external_id if external_id.upper().startswith("CVE-") else f"CVE-{external_id}"
    if external_id:
        return external_id
    return name or None


def _component_from_title(title: str | None) -> str | None:
    if not title:
        return None
    match = _TITLE_PACKAGE.search(title.strip())
    return match.group(1) if match else None


def normalize_finding(node: dict, pipeline: dict | None) -> dict:
    """Convert one GraphQL finding into the shape the engine and report use."""
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
    return {
        "id": node.get("uuid") or node.get("title") or "unknown-finding",
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
        },
        "status": (node.get("state") or "").lower(),
        "falsePositiveFlag": node.get("falsePositive"),
        "solution": solution,
        "links": [link.get("url") for link in (node.get("links") or []) if link.get("url")],
        "pipeline": pipeline,
        "evidence": [],
        "assessment": None,
        "remediationDecision": None,
        "proposedFix": None,
    }


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
