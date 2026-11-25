"""GitLab finding reads and narrowly scoped, explicitly approved dismissals."""

from __future__ import annotations

import codecs
import json
import logging
import re
import threading
from collections.abc import Generator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from time import sleep
from urllib.parse import quote, unquote, urlparse

import httpx

from gitlab_security_mcp.fanout import map_ordered
from gitlab_security_mcp.util import (
    log_unexpected,
    read_bounded_response,
    redact,
    timed_http_stream,
    utc_now_iso,
)
from gitlab_security_mcp.versions import parse_fixed_versions

_RAISE_GITLAB_TRACKED_REF_LOOKUP_EXCEEDED_THE_PAGE_LIMIT = (
    "GitLab tracked-ref lookup exceeded the page limit"
)
_RAISE_GITLAB_CONNECTION_IS_NOT_READABLE = "GitLab {} connection is not readable"
_RAISE_GITLAB_NODES_ARE_MALFORMED = "GitLab {} nodes are malformed"
_RAISE_GITLAB_PAGINATION_IS_MALFORMED = "GitLab {} pagination is malformed"
_RAISE_GITLAB_RETURNED_MALFORMED_SCANNER_EVIDENCE = (
    "GitLab returned malformed scanner evidence"
)
_RAISE_GITLAB_RETURNED_MALFORMED_SUPPORTING_MESSAGES = (
    "GitLab returned malformed supporting messages"
)
_RAISE_GITLAB_READ_BACK_RETURNED_NO_VULNERABILITY_OBJECT = (
    "GitLab read-back returned no vulnerability object"
)
_RAISE_GITLAB_READ_BACK_DID_NOT_CONFIRM_THIS_FINDING = "GitLab read-back did not confirm this finding as DISMISSED / FALSE_POSITIVE (state={!r}, reason={!r}). The mutation may have succeeded; no write was retried. Check the project Vulnerability report, tracked ref and vulnerability details."
_RAISE_CANNOT_PROVE_GITLAB_S_DEFAULT_BRANCH_IS_MAIN = "Cannot prove GitLab's default branch is main at a known commit; branch findings cannot be dismissed"
_RAISE_ONLY_GITLAB_GRAPHQL_QUERIES_ARE_ALLOWED = (
    "Only GitLab GraphQL queries are allowed"
)
_RAISE_ONLY_GITLAB_READS_AND_THE_FIXED_FALSE_POSITIVE = "Only GitLab reads and the fixed false-positive dismissal mutation are allowed; project attributes and repository writes are forbidden"
_RAISE_GITLAB_DID_NOT_RETURN_A_JSON_OBJECT = "GitLab {} {} did not return a JSON object"
_RAISE_GITLAB_CLIENT_IS_CLOSED = "GitLab client is closed"
_RAISE_GITLAB_PROJECT_LOOKUP_DID_NOT_RETURN_PATH_WITH = (
    "GitLab project lookup did not return path_with_namespace"
)
_RAISE_GITLAB_TOKEN_WITH_API_WRITE_PERMISSION_IS_REQUIRED = (
    "GITLAB_TOKEN with API write permission is required"
)
_RAISE_A_GITLAB_VULNERABILITY_GLOBAL_ID_IS_REQUIRED_NOT = (
    "A GitLab Vulnerability global ID is required, not a finding UUID"
)
_RAISE_FINDING_PROJECT_AND_A_REASON_OF_1_50 = (
    "Finding, project and a reason of 1-50,000 characters are required"
)
_RAISE_GITLAB_TARGET_CHANGED_OR_DOES_NOT_MATCH_THE = (
    "GitLab target changed or does not match the approved finding/project"
)
_RAISE_GITLAB_TARGET_IS_NO_LONGER_ACTIVE = "GitLab target is no longer active"
_RAISE_GITLAB_DID_NOT_CONFIRM_THE_REQUESTED_DISMISSAL_INSPECT = (
    "GitLab did not confirm the requested dismissal; inspect GitLab before retrying"
)
_RAISE_GITLAB_PROJECT_WAS_NOT_FOUND_OR_IS_NOT = (
    "GitLab project '{}' was not found or is not readable"
)
_RAISE_GITLAB_SECURITY_TRACKED_BRANCH_MAIN_WAS_NOT_FOUND = "GitLab security tracked branch 'main' was not found; refusing to fetch unfiltered findings"
_RAISE_GITLAB_TRACKED_REF_PAGINATION_DID_NOT_ADVANCE = (
    "GitLab tracked-ref pagination did not advance"
)
_RAISE_GITLAB_VULNERABILITY_REPORT_PAGINATION_DID_NOT_ADVANCE = (
    "GitLab vulnerability report pagination did not advance"
)
_RAISE_GITLAB_RETURNED_MALFORMED_GRAPHQL_ERRORS = (
    "GitLab returned malformed GraphQL errors"
)
_RAISE_GITLAB_RESPONSE_EXCEEDS_THE_SIZE_LIMIT = "GitLab response exceeds the size limit"
_RAISE_GITLAB_RETURNED_MALFORMED_REQUEST_RESPONSE_EVIDENCE = (
    "GitLab returned malformed request/response evidence"
)
_RAISE_MAIN_OR_BRANCH_RESOLUTION_EVIDENCE_CHANGED_AFTER_APPROVAL = "Main or branch-resolution evidence changed after approval; no dismissal was attempted"
_RAISE_GITLAB_RETURNED_MALFORMED_EVIDENCE_HEADERS = (
    "GitLab returned malformed evidence headers"
)

FINDINGS_QUERY = """
query SecurityFindings($fullPath: ID!, $trackedRefIds: [SecurityProjectTrackedContextID!]!, $after: String, $hasResolution: Boolean! = false) {
  project(fullPath: $fullPath) {
    vulnerabilities(first: 100, after: $after, state: [DETECTED, CONFIRMED], trackedRefIds: $trackedRefIds, hasResolution: $hasResolution) {
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

DISMISS_FALSE_POSITIVE = """
mutation DismissFalsePositive($id: VulnerabilityID!, $comment: String!) {
    vulnerabilityDismiss(input: {
        id: $id, dismissalReason: FALSE_POSITIVE, comment: $comment
    }) {
        errors
        vulnerability { id state }
    }
}
""".strip()

DISMISSAL_TARGET_QUERY = """
query DismissalTarget($id: VulnerabilityID!) {
    vulnerability(id: $id) {
        id uuid state project { fullPath }
        trackedRef { id name }
        resolvedOnDefaultBranch
    }
}
""".strip()

DISMISSAL_CONFIRMATION_QUERY = """
query ConfirmFalsePositiveDismissal($id: VulnerabilityID!) {
    vulnerability(id: $id) {
        id uuid state dismissalReason
        project { fullPath }
        stateTransitions(first: 1) {
            nodes { toState dismissalReason }
        }
    }
}
""".strip()

logger = logging.getLogger("gitlab_security_mcp")
_LOG_GITLAB_FALSE_POSITIVE_DISMISSAL_INDEPENDENTLY_CONFIRMED = (
    "GitLab false-positive dismissal independently confirmed: %s"
)
_LOG_TRANSIENT_GITLAB_TRANSPORT_FAILURE_RETRYING_READ_OF = (
    "Transient GitLab transport failure; retrying read %s of %s: %s"
)
_LOG_TRANSIENT_GITLAB_STATUS_RETRYING_READ_OF = (
    "Transient GitLab status %s; retrying read %s of %s"
)


def dismissal_is_confirmed(record: dict) -> bool:
    """Count only independently read-back false-positive dismissal receipts."""
    verification = record.get("verification")
    return (
        record.get("status") == "DISMISSED"
        and isinstance(verification, dict)
        and verification.get("state") == "DISMISSED"
        and verification.get("dismissal_reason") == "FALSE_POSITIVE"
        and bool(verification.get("verified_at"))
    )


_TITLE_PACKAGE = re.compile(r"\bin\s+([A-Za-z0-9_@./+-]+)\s*$")
KEEP_STATES = {"detected", "confirmed"}


MAX_PAGES = 20
MAX_GITLAB_RESPONSE_BYTES = 8 * 1024 * 1024
_GITLAB_READ_ATTEMPTS = 4
_GITLAB_BACKOFF_SECONDS = 1.0
_MAX_GITLAB_RETRY_WAIT = 4.0
_GITLAB_TRANSIENT_STATUS = frozenset({429, 500, 502, 503, 504})
DEFAULT_GITLAB_API_URL = "https://gitlab.com/api/v4"
_DEFAULT_MAX_FINDINGS = 1000
_HTTP_TIMEOUT_SECONDS = 30.0
MAX_DISMISSAL_REASON_LENGTH = 50000
_HTTP_ERROR_STATUS = 400
_ERROR_EXCERPT_LIMIT = 500
_ERROR_EXCERPT_CHUNK_BYTES = 256


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
    """GraphQL retrieval and a separate approved false-positive dismissal operation.

    The client keeps one HTTP connection pool for the life of the process.
    Call ``close`` when the server shuts down. An injected ``http`` client
    is left for its owner to close. Approved dismissals can overlap across
    distinct targets; the same target and client shutdown remain coordinated.
    """

    def __init__(
        self,
        token: str | None,
        api_url: str = DEFAULT_GITLAB_API_URL,
        *,
        http: httpx.Client | None = None,
        max_findings: int = _DEFAULT_MAX_FINDINGS,
        http_log_path: Path | None = None,
    ):
        """Configure report retrieval and retain any caller-owned HTTP client."""
        self.token = token
        self.api_url = api_url.rstrip("/")
        self._owns_http = http is None
        self.http = (
            http if http is not None else httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS)
        )
        self.max_findings = max_findings
        self.http_log_path = http_log_path
        self._closed = False
        self._closing = False
        self._lock = threading.RLock()
        self._idle = threading.Condition(self._lock)
        self._active_dismissals = 0
        self._dismissal_locks: dict[str, tuple[threading.Lock, int]] = {}

    def close(self) -> None:
        """Close the owned HTTP client. Repeated calls do nothing."""
        with self._lock:
            if self._closed:
                return
            if self._closing:
                self._idle.wait_for(lambda: self._closed)
                return
            self._closing = True
            self._idle.wait_for(lambda: self._active_dismissals == 0)
            try:
                if self._owns_http:
                    self.http.close()
            finally:
                self._closed = True
                self._idle.notify_all()

    @contextmanager
    def _dismissal_access(self, vulnerability_id: str) -> Generator[None, None, None]:
        """Overlap distinct targets while serializing each target and owned shutdown."""
        with self._idle:
            if self._closed or self._closing:
                raise RuntimeError(_RAISE_GITLAB_CLIENT_IS_CLOSED)
            lock, users = self._dismissal_locks.get(
                vulnerability_id, (threading.Lock(), 0)
            )
            self._dismissal_locks[vulnerability_id] = (lock, users + 1)
            self._active_dismissals += 1
        try:
            with lock:
                yield
        finally:
            with self._idle:
                _lock, users = self._dismissal_locks[vulnerability_id]
                if users == 1:
                    del self._dismissal_locks[vulnerability_id]
                else:
                    self._dismissal_locks[vulnerability_id] = (lock, users - 1)
                self._active_dismissals -= 1
                self._idle.notify_all()

    def __enter__(self) -> GitLabClient:
        """Return this GitLab client for use in a context manager."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close only the HTTP client owned by this GitLab client."""
        self.close()

    def fetch(self, project_id: str) -> FetchResult:
        """Fetch detected and confirmed findings on main, plus non-main findings resolved there.

        project_id may be a numeric GitLab id or a namespace/project path.
        Return FetchResult with normalized findings, exclusions, and a
        truncation flag. Missing access, malformed data, and closed-client
        calls return an error result; no GitLab mutation is performed.
        """
        with self._lock:
            if self._closed or self._closing:
                return FetchResult(ok=False, error="GitLab client is closed")
            return self._fetch(project_id)

    def _fetch(self, project_id: str) -> FetchResult:
        """Validate inputs and contain request or normalization failures."""
        if not self.token:
            return FetchResult(ok=False, error="GITLAB_TOKEN is required")
        if not project_id:
            return FetchResult(
                ok=False, error="A GitLab project path or numeric ID is required"
            )
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
            log_unexpected(exc, "GitLab vulnerability report retrieval")
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
                    _RAISE_GITLAB_PROJECT_LOOKUP_DID_NOT_RETURN_PATH_WITH
                )
            return path
        return unquote(project_id).strip("/")

    def dismiss_false_positive(
        self,
        vulnerability_id: str,
        finding_id: str,
        project_path: str,
        reason: str,
        *,
        main_resolution: dict | None = None,
    ) -> dict:
        """Check identity, dismiss once, and independently read back the outcome.

        The caller must obtain human approval for this specific assessment first.
        Writes are never retried. A previously completed false-positive dismissal
        can be confirmed without writing another comment or state transition.
        """
        with self._dismissal_access(vulnerability_id):
            if not self.token:
                raise ValueError(
                    _RAISE_GITLAB_TOKEN_WITH_API_WRITE_PERMISSION_IS_REQUIRED
                )
            if not re.fullmatch(
                r"gid://gitlab/Vulnerability/[1-9][0-9]*", vulnerability_id
            ):
                raise ValueError(
                    _RAISE_A_GITLAB_VULNERABILITY_GLOBAL_ID_IS_REQUIRED_NOT
                )
            if (
                not finding_id
                or not project_path
                or not reason.strip()
                or len(reason) > MAX_DISMISSAL_REASON_LENGTH
            ):
                raise ValueError(_RAISE_FINDING_PROJECT_AND_A_REASON_OF_1_50)
            payload = self._graphql(DISMISSAL_TARGET_QUERY, {"id": vulnerability_id})
            target = (payload.get("data") or {}).get("vulnerability") or {}
            if (
                target.get("id") != vulnerability_id
                or target.get("uuid") != finding_id
                or (target.get("project") or {}).get("fullPath") != project_path
            ):
                raise RuntimeError(_RAISE_GITLAB_TARGET_CHANGED_OR_DOES_NOT_MATCH_THE)
            if target.get("state") == "DISMISSED":
                return {
                    **self._confirm_dismissal(
                        vulnerability_id, finding_id, project_path
                    ),
                    "already_dismissed": True,
                }
            if target.get("state") not in {"DETECTED", "CONFIRMED"}:
                raise RuntimeError(_RAISE_GITLAB_TARGET_IS_NO_LONGER_ACTIVE)
            if main_resolution is not None:
                branch = self._main_branch_snapshot(project_path)
                tracked = target.get("trackedRef") or {}
                if (
                    branch["sha"] != main_resolution.get("main_sha")
                    or target.get("resolvedOnDefaultBranch") is not True
                    or tracked.get("id") != main_resolution.get("tracked_ref_id")
                    or tracked.get("name") != main_resolution.get("branch")
                    or tracked.get("name") == "main"
                ):
                    raise RuntimeError(
                        _RAISE_MAIN_OR_BRANCH_RESOLUTION_EVIDENCE_CHANGED_AFTER_APPROVAL
                    )
            payload = self._request(
                "POST",
                self._graphql_url(),
                json_body={
                    "query": DISMISS_FALSE_POSITIVE,
                    "variables": {"id": vulnerability_id, "comment": reason},
                },
            )
            result = (payload.get("data") or {}).get("vulnerabilityDismiss") or {}
            if result.get("errors") != []:
                raise RuntimeError(
                    self._clean(
                        f"GitLab dismissal failed: {result.get('errors', 'missing mutation result')}"
                    )
                )
            vulnerability = result.get("vulnerability") or {}
            if (
                vulnerability.get("id") != vulnerability_id
                or vulnerability.get("state") != "DISMISSED"
            ):
                raise RuntimeError(
                    _RAISE_GITLAB_DID_NOT_CONFIRM_THE_REQUESTED_DISMISSAL_INSPECT
                )
            return self._confirm_dismissal(vulnerability_id, finding_id, project_path)

    def _confirm_dismissal(
        self, vulnerability_id: str, finding_id: str, project_path: str
    ) -> dict:
        """Require persisted identity, state and dismissal reason, not just an ACK."""
        payload = self._graphql(DISMISSAL_CONFIRMATION_QUERY, {"id": vulnerability_id})
        data = payload.get("data")
        target = data.get("vulnerability") if isinstance(data, dict) else None
        if not isinstance(target, dict):
            raise RuntimeError(_RAISE_GITLAB_READ_BACK_RETURNED_NO_VULNERABILITY_OBJECT)
        reason = target.get("dismissalReason")
        reason_source = "dismissalReason"
        if reason is None:
            transitions = target.get("stateTransitions")
            nodes = transitions.get("nodes") if isinstance(transitions, dict) else None
            if (
                isinstance(nodes, list)
                and nodes
                and isinstance(nodes[0], dict)
                and nodes[0].get("toState") == "DISMISSED"
            ):
                reason = nodes[0].get("dismissalReason")
                reason_source = "stateTransitions"
        if (
            target.get("id") != vulnerability_id
            or target.get("uuid") != finding_id
            or not isinstance(target.get("project"), dict)
            or target["project"].get("fullPath") != project_path
            or target.get("state") != "DISMISSED"
            or reason != "FALSE_POSITIVE"
        ):
            raise RuntimeError(
                _RAISE_GITLAB_READ_BACK_DID_NOT_CONFIRM_THIS_FINDING.format(
                    target.get("state"), reason
                )
            )
        result = {
            "status": "DISMISSED",
            "vulnerability_id": vulnerability_id,
            "vulnerability_url": (
                f"{self._graphql_url().removesuffix('/api/graphql')}/"
                f"{quote(project_path, safe='/')}/-/security/vulnerabilities/"
                f"{vulnerability_id.rsplit('/', 1)[-1]}"
            ),
            "verification": {
                "state": "DISMISSED",
                "dismissal_reason": reason,
                "reason_source": reason_source,
                "verified_at": utc_now_iso(),
            },
        }
        logger.info(
            _LOG_GITLAB_FALSE_POSITIVE_DISMISSAL_INDEPENDENTLY_CONFIRMED,
            vulnerability_id,
        )
        return result

    def _tracked_branches(self, full_path: str) -> dict[str, str]:
        """Resolve tracked branches with bounded, advancing pagination.

        Raise if main is unreadable or missing instead of dropping filters.
        """
        after = None
        branches = {}
        for _page in range(MAX_PAGES):
            payload = self._graphql(
                TRACKED_REFS_QUERY, {"fullPath": full_path, "after": after}
            )
            project = (payload.get("data") or {}).get("project")
            if not project:
                raise RuntimeError(
                    _RAISE_GITLAB_PROJECT_WAS_NOT_FOUND_OR_IS_NOT.format(full_path)
                )
            connection = _connection(project, "securityTrackedRefs")
            for tracked_ref in connection["nodes"]:
                if (
                    isinstance(tracked_ref.get("name"), str)
                    and tracked_ref["name"]
                    and tracked_ref.get("refType") == "BRANCH"
                    and tracked_ref.get("id")
                ):
                    branches[tracked_ref["name"]] = tracked_ref["id"]
            page = connection["pageInfo"]
            if not page.get("hasNextPage"):
                if "main" in branches:
                    return branches
                raise RuntimeError(
                    _RAISE_GITLAB_SECURITY_TRACKED_BRANCH_MAIN_WAS_NOT_FOUND
                )
            if not page.get("endCursor") or page["endCursor"] == after:
                raise RuntimeError(_RAISE_GITLAB_TRACKED_REF_PAGINATION_DID_NOT_ADVANCE)
            after = page["endCursor"]
        raise RuntimeError(_RAISE_GITLAB_TRACKED_REF_LOOKUP_EXCEEDED_THE_PAGE_LIMIT)

    def _findings(self, full_path: str) -> tuple[dict | None, list[dict], bool]:
        """Keep main's active report and add explicitly resolved non-main findings.

        The two reports are independent once the tracked branches are known.
        Each report still follows its own cursor. A truncated main report is
        returned alone, matching the previous page limit.
        """
        branches = self._tracked_branches(full_path)
        main_ids = [branches["main"]]
        others = [value for name, value in branches.items() if name != "main"]
        if not others:
            main, truncated = self._report_findings(full_path, main_ids)
            return None, main, truncated

        def load(spec: tuple[list[str], bool]) -> tuple[list[dict], bool]:
            """Page one report without sharing the other report's cursor."""
            tracked_ids, resolved_only = spec
            return self._report_findings(
                full_path, tracked_ids, has_resolution=resolved_only
            )

        (main, truncated), (resolved, branch_truncated) = map_ordered(
            load, [(main_ids, False), (others, True)]
        )
        if truncated:
            return None, main, truncated
        if resolved:
            snapshot = self._main_branch_snapshot(full_path)
            main_uuids = {item.get("uuid") for item in main if item.get("uuid")}
            for item in resolved:
                tracked = item.get("trackedRef") or {}
                item["mainBranchResolution"] = {
                    "main_sha": snapshot["sha"],
                    "branch": tracked.get("name"),
                    "tracked_ref_id": tracked.get("id"),
                    "verified": (
                        item.get("resolvedOnDefaultBranch") is True
                        and isinstance(item.get("uuid"), str)
                        and bool(item["uuid"])
                        and isinstance(item.get("id"), str)
                        and bool(
                            re.fullmatch(
                                r"gid://gitlab/Vulnerability/[1-9][0-9]*", item["id"]
                            )
                        )
                        and tracked.get("name") != "main"
                        and branches.get(tracked.get("name")) == tracked.get("id")
                        and tracked.get("id") in others
                        and item.get("uuid") not in main_uuids
                    ),
                }
        return None, [*main, *resolved], branch_truncated

    def _main_branch_snapshot(self, full_path: str) -> dict:
        """Require that GitLab's default branch really is main and has a commit."""
        branch = self._request(
            "GET",
            f"{self.api_url}/projects/{quote(full_path, safe='')}/repository/branches/main",
        )
        sha = (branch.get("commit") or {}).get("id")
        if (
            branch.get("name") != "main"
            or branch.get("default") is not True
            or not isinstance(sha, str)
            or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", sha)
        ):
            raise RuntimeError(_RAISE_CANNOT_PROVE_GITLAB_S_DEFAULT_BRANCH_IS_MAIN)
        return {"sha": sha}

    def _report_findings(
        self,
        full_path: str,
        tracked_ref_ids: list[str],
        *,
        has_resolution: bool = False,
    ) -> tuple[list[dict], bool]:
        """Page one explicitly scoped activity view without broadening its filters."""
        after = None
        nodes: list[dict] = []
        for _page in range(MAX_PAGES):
            payload = self._graphql(
                FINDINGS_QUERY,
                {
                    "fullPath": full_path,
                    "trackedRefIds": tracked_ref_ids,
                    "hasResolution": has_resolution,
                    "after": after,
                },
            )
            project = (payload.get("data") or {}).get("project")
            if not project:
                raise RuntimeError(
                    _RAISE_GITLAB_PROJECT_WAS_NOT_FOUND_OR_IS_NOT.format(full_path)
                )
            connection = _connection(project, "vulnerabilities")
            nodes.extend(connection["nodes"])
            page = connection["pageInfo"]
            if not page.get("hasNextPage"):
                return nodes, False
            if not page.get("endCursor") or page["endCursor"] == after:
                raise RuntimeError(
                    _RAISE_GITLAB_VULNERABILITY_REPORT_PAGINATION_DID_NOT_ADVANCE
                )
            after = page["endCursor"]
            if len(nodes) >= self.max_findings:
                return nodes, True
        return nodes, True

    def _graphql(self, query: str, variables: dict) -> dict:
        """Send only query operations to the GitLab GraphQL endpoint."""
        if not query.strip().lower().startswith("query"):
            raise RuntimeError(_RAISE_ONLY_GITLAB_GRAPHQL_QUERIES_ARE_ALLOWED)
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
        query = (json_body or {}).get("query", "")
        read_query = (
            isinstance(query, str)
            and query.lstrip().lower().startswith("query")
            and re.search(r"\bmutation\b", query, re.IGNORECASE) is None
        )
        if method != "GET" and not (
            method == "POST"
            and url == self._graphql_url()
            and (read_query or query == DISMISS_FALSE_POSITIVE)
        ):
            raise PermissionError(_RAISE_ONLY_GITLAB_READS_AND_THE_FIXED_FALSE_POSITIVE)
        operation = re.match(r"\s*(?:query|mutation)\s+([A-Za-z_][A-Za-z0-9_]*)", query)
        read = method == "GET" or read_query
        attempts = _GITLAB_READ_ATTEMPTS if read else 1
        for attempt in range(attempts):
            try:
                payload, delay = self._exchange(
                    method,
                    url,
                    json_body,
                    operation.group(1) if operation else None,
                    read=read,
                    attempt=attempt,
                    attempts=attempts,
                )
            except httpx.TransportError as exc:
                if not read or attempt + 1 == attempts:
                    raise
                delay = _GITLAB_BACKOFF_SECONDS * 2**attempt
                logger.warning(
                    _LOG_TRANSIENT_GITLAB_TRANSPORT_FAILURE_RETRYING_READ_OF,
                    attempt + 2,
                    attempts,
                    exc,
                    exc_info=True,
                )
                if delay > 0:
                    sleep(delay)
                continue
            if delay is not None:
                if delay > 0:
                    sleep(delay)
                continue
            break
        if not isinstance(payload, dict):
            raise RuntimeError(
                _RAISE_GITLAB_DID_NOT_RETURN_A_JSON_OBJECT.format(method, url)
            )
        if payload.get("errors"):
            errors = payload["errors"]
            if not isinstance(errors, list) or any(
                not isinstance(error, dict) for error in errors
            ):
                raise ValueError(_RAISE_GITLAB_RETURNED_MALFORMED_GRAPHQL_ERRORS)
            message = "; ".join(
                str(error.get("message") or "unknown GraphQL error") for error in errors
            )
            raise RuntimeError(self._clean(message))
        return payload

    def _exchange(
        self,
        method: str,
        url: str,
        json_body: dict | None,
        operation: str | None,
        *,
        read: bool,
        attempt: int,
        attempts: int,
    ) -> tuple[dict | None, float | None]:
        """Read one bounded response. Reads may ask for a short retry delay."""
        with timed_http_stream(
            self.http,
            method,
            url,
            source="gitlab",
            log_path=self.http_log_path,
            operation=operation,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
            },
            json=json_body,
        ) as response:
            if response.status_code >= _HTTP_ERROR_STATUS:
                detail = self._clean(
                    f"GitLab {method} {url} returned {response.status_code}: "
                    f"{_response_excerpt(response)}"
                )
                if (
                    read
                    and response.status_code in _GITLAB_TRANSIENT_STATUS
                    and attempt + 1 < attempts
                ):
                    delay = _retry_wait(response, attempt)
                    if delay is not None:
                        logger.warning(
                            _LOG_TRANSIENT_GITLAB_STATUS_RETRYING_READ_OF,
                            response.status_code,
                            attempt + 2,
                            attempts,
                        )
                        return None, delay
                raise RuntimeError(detail)
            payload = json.loads(
                read_bounded_response(
                    response,
                    MAX_GITLAB_RESPONSE_BYTES,
                    error=_RAISE_GITLAB_RESPONSE_EXCEEDS_THE_SIZE_LIMIT,
                )
            )
        return payload, None

    def _clean(self, text: str) -> str:
        """Remove the GitLab token from returned or logged request details."""
        return redact(text, [self.token])


def _retry_wait(response: httpx.Response, attempt: int) -> float | None:
    """Return a short read delay, or None when Retry-After is too long to wait."""
    header = response.headers.get("Retry-After")
    if header:
        try:
            delay = float(int(header))
        except ValueError:
            delay = None
        if delay is not None:
            if delay > _MAX_GITLAB_RETRY_WAIT:
                return None
            return delay
    return _GITLAB_BACKOFF_SECONDS * 2**attempt


def _response_excerpt(
    response: httpx.Response, limit: int = _ERROR_EXCERPT_LIMIT
) -> str:
    """Decode only the first part of an error body.

    The remainder stays on the wire and is discarded when the response
    closes, so a large error page cannot be retained in the failure result.
    """
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    kept: list[str] = []
    count = 0
    for chunk in response.iter_bytes(chunk_size=_ERROR_EXCERPT_CHUNK_BYTES):
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
        raise RuntimeError(_RAISE_GITLAB_CONNECTION_IS_NOT_READABLE.format(name))
    nodes = connection.get("nodes")
    page = connection.get("pageInfo")
    if not isinstance(nodes, list) or any(not isinstance(node, dict) for node in nodes):
        raise ValueError(_RAISE_GITLAB_NODES_ARE_MALFORMED.format(name))
    if not isinstance(page, dict) or not isinstance(page.get("hasNextPage"), bool):
        raise ValueError(_RAISE_GITLAB_PAGINATION_IS_MALFORMED.format(name))
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
    """Preserve typed CVE/CWE identifiers, including numeric GitLab weakness IDs."""
    external_type = (item.get("externalType") or "").strip().lower()
    external_id = (item.get("externalId") or "").strip()
    name = (item.get("name") or "").strip()
    if external_type in {"cve", "cwe"} and external_id:
        prefix = external_type.upper() + "-"
        return (
            external_id.upper()
            if external_id.upper().startswith(prefix)
            else f"{prefix}{external_id}"
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
        "id": (node.get("id") if node.get("mainBranchResolution") else None)
        or node.get("uuid")
        or node.get("id")
        or node.get("title")
        or "unknown-finding",
        "vulnerabilityId": node.get("id"),
        "findingUuid": node.get("uuid"),
        "mainBranchResolution": deepcopy(node.get("mainBranchResolution")),
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
        raise ValueError(_RAISE_GITLAB_RETURNED_MALFORMED_SCANNER_EVIDENCE)
    captured = deepcopy(evidence)
    messages = captured.get("supportingMessages") or []
    if not isinstance(messages, list) or any(
        not isinstance(message, dict) for message in messages
    ):
        raise ValueError(_RAISE_GITLAB_RETURNED_MALFORMED_SUPPORTING_MESSAGES)
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
                raise ValueError(
                    _RAISE_GITLAB_RETURNED_MALFORMED_REQUEST_RESPONSE_EVIDENCE
                )
            for header in exchange.get("headers") or []:
                if not isinstance(header, dict) or not isinstance(
                    header.get("name"), str
                ):
                    raise ValueError(_RAISE_GITLAB_RETURNED_MALFORMED_EVIDENCE_HEADERS)
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
