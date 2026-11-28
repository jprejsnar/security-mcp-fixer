"""Check that independent reads overlap and keep their input order."""

import json
import logging
import threading
import time

import httpx
import pytest

from gitlab_security_mcp.advisory import _MAX_ADVISORY_BYTES, AdvisoryClient
from gitlab_security_mcp.fanout import map_ordered
from gitlab_security_mcp.gitlab_client import GitLabClient
from gitlab_security_mcp.official_docs import REQUIRED_DOCS, OfficialDocs
from gitlab_security_mcp.util import (
    read_bounded_response,
    share_in_flight,
    timed_http_stream,
)


@pytest.mark.parametrize("boundary", ["fanout", "http"])
def test_cancellation_is_propagated_and_logged_as_an_error(boundary, caplog):
    """Never describe interrupted HTTP or worker operations as successful spans."""
    # Arrange
    import asyncio

    def interrupt(_item):
        """Model cancellation escaping synchronous work."""
        raise asyncio.CancelledError

    # Act
    with caplog.at_level(logging.INFO, logger="gitlab_security_mcp"):
        with pytest.raises(asyncio.CancelledError):
            if boundary == "fanout":
                map_ordered(interrupt, [1, 2])
            else:
                with httpx.Client(transport=httpx.MockTransport(interrupt)) as client:
                    with timed_http_stream(
                        client, "GET", "https://example.test", source="fixture"
                    ):
                        pytest.fail("No response should be yielded")
    prefix = "HTTP timing " if boundary == "http" else "Concurrency "
    record = json.loads(caplog.records[-1].message.removeprefix(prefix))

    # Assert
    assert record["error"] == "CancelledError"


def test_main_and_branch_reports_overlap_and_keep_main_first():
    """Fetch the main report and the branch report together, then keep main first."""
    # Arrange
    state = {"inflight": 0, "max": 0}
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        """Hold each vulnerability page open so the two reports can overlap."""
        if request.method == "GET":
            return httpx.Response(
                200,
                json={"name": "main", "default": True, "commit": {"id": "a" * 40}},
            )
        body = json.loads(request.content)
        if "securityTrackedRefs(" in body["query"]:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "project": {
                            "securityTrackedRefs": {
                                "nodes": [
                                    {
                                        "id": "main-id",
                                        "name": "main",
                                        "refType": "BRANCH",
                                    },
                                    {
                                        "id": "release-id",
                                        "name": "release",
                                        "refType": "BRANCH",
                                    },
                                ],
                                "pageInfo": {"hasNextPage": False},
                            }
                        }
                    }
                },
            )
        resolved = body["variables"]["hasResolution"]
        node = {
            "id": "gid://gitlab/Vulnerability/9",
            "uuid": "branch-finding" if resolved else "main-finding",
            "title": "branch" if resolved else "main",
            "state": "DETECTED",
            "reportType": "SAST",
            "trackedRef": {
                "id": "release-id" if resolved else "main-id",
                "name": "release" if resolved else "main",
            },
            "resolvedOnDefaultBranch": resolved,
        }
        with lock:
            state["inflight"] += 1
            state["max"] = max(state["max"], state["inflight"])
        try:
            time.sleep(0.05)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "project": {
                            "vulnerabilities": {
                                "nodes": [node],
                                "pageInfo": {"hasNextPage": False},
                            }
                        }
                    }
                },
            )
        finally:
            with lock:
                state["inflight"] -= 1

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http).fetch("group/project")

    # Assert
    assert state["max"] >= 2
    assert fetched.ok is True
    assert [item["id"] for item in fetched.findings] == [
        "main-finding",
        "gid://gitlab/Vulnerability/9",
    ]


def test_existing_fix_reuses_catalog_only_and_actual_edits_still_read_fresh(tmp_path):
    """Avoid repeated publisher transfers only when associating an unchanged edit."""
    # Arrange
    requests = []
    markers = " ".join(marker for _name, _url, marker in REQUIRED_DOCS)
    name, url, marker = REQUIRED_DOCS[0]
    rule_page = {"name": name, "url": url, "markers": [marker]}

    def handler(request):
        """Include catalog and identifier markers without leaving the local transport."""
        requests.append(str(request.url))
        return httpx.Response(200, text=markers + " " + str(request.url))

    path = tmp_path / "http-timings.jsonl"
    dockerfile = {"location": {"file": "Dockerfile"}}
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with OfficialDocs(http=http, http_log_path=path) as docs:
            first = docs.read_before_fix(
                {**dockerfile, "identifiers": ["CVE-2020-0001"]}
            )

            # Act
            second = docs.read_for_existing_fix(
                {**dockerfile, "identifiers": ["CVE-2020-0002"]},
                first.as_list(),
                [rule_page],
            )
            after_shared = list(requests)
            fresh = docs.read_before_fix(
                {**dockerfile, "identifiers": ["CVE-2020-0002"]}
            )

    # Assert
    assert first.complete and second.complete and fresh.complete
    assert after_shared.count(rule_page["url"]) == 2
    assert requests.count(rule_page["url"]) == 3
    assert all(
        after_shared.count(url) == 0 for _name, url, _marker in REQUIRED_DOCS[1:]
    )
    assert all(requests.count(url) == 0 for _name, url, _marker in REQUIRED_DOCS[1:])
    assert any("CVE-2020-0002" in url for url in after_shared)
    assert not any("CVE-2020-0001" in source.url for source in second.sources)
    assert len(path.read_text(encoding="utf-8").splitlines()) == len(requests)


def test_parallel_source_reviews_share_run_receipts_but_edits_stay_fresh():
    """Fetch identical source-review pages once, including across simultaneous calls."""
    # Arrange
    from collections import Counter
    from concurrent.futures import ThreadPoolExecutor

    requests = []
    markers = " ".join(marker for _name, _url, marker in REQUIRED_DOCS) + " CWE-79"
    finding = {"location": {"file": "widget.py"}, "identifiers": ["CWE-79"]}
    scope = object()

    def handler(request):
        """Count real mock-transport transfers for each required reference."""
        requests.append(str(request.url))
        return httpx.Response(200, text=markers + " " + str(request.url))

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with OfficialDocs(http=http) as docs:
            with ThreadPoolExecutor(max_workers=8) as pool:
                reviews = list(
                    pool.map(
                        lambda _: docs.read_for_source(finding, run_key=scope),
                        range(16),
                    )
                )
            after_shared = Counter(requests)
            new_run = docs.read_for_source(finding, run_key=object())
            edit = docs.read_before_fix(finding)

    # Assert
    assert all(review.complete for review in reviews)
    assert len(after_shared) == 2
    assert set(after_shared.values()) == {1}
    assert any(source.as_dict().get("reused") for source in reviews[-1].sources)
    assert not any(source.as_dict().get("reused") for source in new_run.sources)
    assert not any(source.as_dict().get("reused") for source in edit.sources)
    assert set(Counter(requests).values()) == {3}
    assert docs.read_for_source(finding, run_key=scope).sources[0].error == (
        "Documentation client is closed"
    )


@pytest.mark.parametrize("failed", ["python", "cwe:CWE-79"])
def test_source_receipt_reuse_retries_required_and_named_record_failures(failed):
    """Do not pin a failed required page or CVE/CWE record for the entire run."""
    # Arrange
    from collections import Counter

    requests = []
    markers = " ".join(marker for _name, _url, marker in REQUIRED_DOCS) + " CWE-79"
    urls = {name: url for name, url, _marker in REQUIRED_DOCS}
    urls["cwe:CWE-79"] = "https://cwe.mitre.org/data/definitions/79.html"

    def handler(request):
        """Fail one reference once without changing other publisher receipts."""
        url = str(request.url)
        requests.append(url)
        if url == urls[failed] and requests.count(url) == 1:
            return httpx.Response(403, text="Unavailable")
        return httpx.Response(200, text=markers + " " + url)

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with OfficialDocs(http=http) as docs:
            scope = object()
            cited = {"location": {"file": "widget.py"}, "identifiers": ["CWE-79"]}
            first = docs.read_for_source(cited, run_key=scope)
            second = docs.read_for_source(cited, run_key=scope)
    # Assert
    first_source = next(
        source for source in first.sources if source.url == urls[failed]
    )
    second_source = next(
        source for source in second.sources if source.url == urls[failed]
    )
    assert not first_source.ok
    assert second_source.ok
    assert requests.count(urls[failed]) == 2
    assert all(
        count == 1 for url, count in Counter(requests).items() if url != urls[failed]
    )


def test_source_receipt_cache_evicts_old_records_not_frequently_used_catalog(
    monkeypatch,
):
    """Bound cache growth without repeatedly fetching the shared publisher catalog."""
    # Arrange
    from gitlab_security_mcp import official_docs

    monkeypatch.setattr(official_docs, "_MAX_SOURCE_CACHE", 4)
    requests = []
    markers = (
        " ".join(marker for _name, _url, marker in REQUIRED_DOCS)
        + " "
        + " ".join(f"CWE-{number}" for number in range(1, 7))
    )

    def handler(request):
        """Serve the finite catalog and a stream of distinct CWE records."""
        requests.append(str(request.url))
        return httpx.Response(200, text=markers + " " + str(request.url))

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with OfficialDocs(http=http) as docs:
            scope = object()
            for number in range(1, 7):
                docs.read_for_source(
                    {
                        "location": {"file": "widget.py"},
                        "identifiers": [f"CWE-{number}"],
                    },
                    run_key=scope,
                )
            docs.read_for_source(
                {"location": {"file": "widget.py"}, "identifiers": ["CWE-1"]},
                run_key=scope,
            )
    # Assert
    assert requests.count("https://cwe.mitre.org/data/definitions/1.html") == 2
    python_url = next(url for name, url, _marker in REQUIRED_DOCS if name == "python")
    java_url = next(url for name, url, _marker in REQUIRED_DOCS if name == "java")
    assert requests.count(python_url) == 1
    assert requests.count(java_url) == 0


@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize("configuration", ["runtimeClasspath", "checkstyle"])
def test_parallel_gradle_findings_share_one_dependency_inspection(
    tmp_path, monkeypatch, exit_code, configuration
):
    """Parallel findings share both the scoped inspection and any all-configuration fallback."""
    # Arrange
    from concurrent.futures import ThreadPoolExecutor
    from unittest.mock import Mock

    from gitlab_security_mcp import engine as engine_module
    from gitlab_security_mcp.advisory import AdvisoryLookup
    from gitlab_security_mcp.commands import CommandResult
    from gitlab_security_mcp.engine import Engine
    from gitlab_security_mcp.report import render

    parse = Mock(wraps=engine_module.parse_gradle_report)
    monkeypatch.setattr(engine_module, "parse_gradle_report", parse)

    (tmp_path / "build.gradle").write_text("dependencies { }\n", encoding="utf-8")
    barrier = threading.Barrier(5)
    runner = Mock()
    runner.run.return_value = CommandResult(
        ["gradle", "--no-daemon", "dependencies"],
        exit_code,
        "checkstyle - Tool classpath.\r\n"
        "+--- io.example:library:0.9.0\r\n"
        "runtimeClasspath - Application classpath.\r\n"
        f"+--- io.example:{'library' if configuration == 'runtimeClasspath' else 'other'}:1.0.0\r\n"
        "Deprecated Gradle features were used in this build, making it incompatible with Gradle 10.\r\n",
        "",
        0,
        False,
        "out",
        "err",
    )
    advisory = Mock()
    advisory.lookup.return_value = AdvisoryLookup(
        outcome="no_fix_published", affected=True, summary="No fixed version published."
    )
    engine = Engine(
        tmp_path,
        runner=runner,
        gitlab=Mock(),
        advisory=advisory,
        which=lambda name: "gradle" if name == "gradle" else None,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [
        {
            "id": str(index),
            "component": "io.example/library",
            "installedVersion": "1.0.0"
            if configuration == "runtimeClasspath"
            else "0.9.0",
            "category": "dependency_scanning",
            "location": {"file": "build.gradle"},
        }
        for index in range(5)
    ]

    def verify(finding_id):
        """Start all findings together to exercise in-flight sharing."""
        barrier.wait(timeout=5)
        return engine.verify_security_finding(finding_id)

    # Act
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(verify, [str(index) for index in range(5)]))

    # Assert
    inspections = 1 if exit_code or configuration == "runtimeClasspath" else 2
    assert runner.run.call_count == inspections
    assert parse.call_count == (0 if exit_code else inspections)
    assert advisory.lookup.call_count == 5
    expected = "MANUAL_REVIEW" if exit_code else "NO_SAFE_FIX"
    assert all(result["decision"] == expected for result in results)
    assert all(
        finding["dependencyResolution"]["status"]
        == ("FAILED" if exit_code else "RESOLVED")
        for finding in engine.state.findings
    )
    if not exit_code:
        payload, markdown = render(engine.state, staged=[], diff_stat="", diff_files="")
        assert len(payload["validation_caveats"]) == 1
        assert "Gradle 10" in payload["final_summary_markdown"]
        assert configuration in markdown
        assert all(
            list(finding["dependencyResolution"]["configuration_versions"])
            == [configuration]
            for finding in engine.state.findings
        )
        assert engine.state.validation_status is None
    engine.verify_security_finding("0")
    assert runner.run.call_count == inspections + int(bool(exit_code))
    assert parse.call_count == (0 if exit_code else inspections)


def test_advisory_lookups_overlap_without_mixing_validation_sites():
    """Independent findings share connections but not consulted-site evidence."""
    # Arrange
    rendezvous = threading.Barrier(2)

    def handler(request):
        """Require both lookups to enter before allowing either to finish."""
        if request.url.host == "api.osv.dev":
            ident = request.url.path.rsplit("/", 1)[-1]
            if ident == "CVE-2020-0002":
                return httpx.Response(404)
        else:
            ident = "CVE-2020-0002"
        rendezvous.wait(timeout=3)
        record = {
            "id": ident,
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "left-pad"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0"}, {"fixed": "1.2.0"}],
                        }
                    ],
                }
            ],
        }
        if request.url.host == "api.github.com":
            return httpx.Response(
                200,
                json=[
                    {
                        "vulnerabilities": [
                            {
                                "package": {"ecosystem": "npm", "name": "left-pad"},
                                "vulnerable_version_range": "< 1.2.0",
                                "first_patched_version": "1.2.0",
                            }
                        ],
                    }
                ],
            )
        return httpx.Response(200, json=record)

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with AdvisoryClient(http=http) as client:
            results = map_ordered(
                lambda ident: client.lookup(
                    {"identifiers": [ident]}, "npm", "left-pad", None
                ),
                ["CVE-2020-0001", "CVE-2020-0002"],
            )

    # Assert
    assert [result.outcome for result in results] == ["resolved", "resolved"]
    assert results[0].validation_sites == ["https://api.osv.dev"]
    assert results[1].validation_sites == [
        "https://api.github.com",
        "https://api.osv.dev",
    ]


def test_advisory_close_waits_for_active_lookup():
    """Never close the connection pool while a concurrent lookup is reading."""
    # Arrange
    from concurrent.futures import ThreadPoolExecutor

    entered, release, closing = threading.Event(), threading.Event(), threading.Event()

    def handler(_request):
        """Keep an advisory read active until shutdown has attempted to start."""
        entered.set()
        if not release.wait(5):
            raise RuntimeError("Test release timed out")
        return httpx.Response(
            200,
            json={
                "id": "CVE-2020-0001",
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "left-pad"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                    }
                ],
            },
        )

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = AdvisoryClient(http=http)

        def close():
            """Record that the closer thread has begun before requesting shutdown."""
            closing.set()
            client.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            lookup = pool.submit(
                client.lookup,
                {"identifiers": ["CVE-2020-0001"]},
                "npm",
                "left-pad",
                "1.0.0",
            )
            try:
                assert entered.wait(3)
                closer = pool.submit(close)
                assert closing.wait(3)
                with pytest.raises(TimeoutError):
                    closer.result(timeout=0.1)
            finally:
                release.set()
            result = lookup.result(timeout=5)
            closer.result(timeout=5)

        # Assert
        assert result.outcome == "no_fix_published"
        assert client.lookup({}, "npm", "left-pad", "1.0.0").outcome == "lookup_failed"
        assert not http.is_closed


@pytest.mark.parametrize("failure", [503, "invalid_shape"])
def test_failed_package_query_is_not_cached(failure):
    """A failed shared POST does not poison subsequent advisory evidence."""
    # Arrange
    requests = []

    def handler(request):
        """Recover from the first HTTP or response-shape failure."""
        requests.append(request)
        if len(requests) == 1:
            return (
                httpx.Response(503) if failure == 503 else httpx.Response(200, json=[])
            )
        return httpx.Response(200, json={"vulns": []})

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with AdvisoryClient(http=http) as client:
            with pytest.raises((httpx.HTTPStatusError, ValueError)):
                client._post_json("https://api.osv.dev/v1/query", {})
            recovered = client._post_json("https://api.osv.dev/v1/query", {})
            cached = client._post_json("https://api.osv.dev/v1/query", {})

    # Assert
    assert recovered == cached == {"vulns": []}
    assert len(requests) == 2


def test_identical_package_queries_share_one_cached_request():
    """Repeated findings for one installed package reuse its bounded query result."""
    # Arrange
    requests = []

    def handler(request):
        """Count package queries independently of identifier-specific reads."""
        requests.append(request)
        return httpx.Response(200, json={"vulns": []})

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with AdvisoryClient(http=http) as client:
            body = {
                "package": {"ecosystem": "npm", "name": "left-pad"},
                "version": "1.0.0",
            }
            results = map_ordered(
                lambda _: client._post_json("https://api.osv.dev/v1/query", body),
                range(8),
            )
            distinct = client._post_json(
                "https://api.osv.dev/v1/query", {**body, "version": "1.1.0"}
            )

    # Assert
    assert results == [{"vulns": []}] * 8
    assert distinct == {"vulns": []}
    assert len(requests) == 2


@pytest.mark.parametrize("outcome", ["success", "http_error", "timeout", "body_error"])
def test_http_timings_include_body_failures_without_secrets(
    tmp_path, monkeypatch, outcome
):
    """Persist elapsed spans for success and failures without request secrets."""
    # Arrange
    readings = iter([1.0, 1.125])
    monkeypatch.setattr("gitlab_security_mcp.util.perf_counter", lambda: next(readings))
    path = tmp_path / ".security-mcp" / "http-timings.jsonl"

    def handler(request):
        """Return a response or raise a transport error containing private data."""
        if outcome == "timeout":
            raise httpx.ReadTimeout("secret-body", request=request)
        return httpx.Response(
            503 if outcome == "http_error" else 200, text="secret-body"
        )

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        try:
            with timed_http_stream(
                client,
                "GET",
                "https://username:secret-password@example.test/docs?token=secret-query#secret-fragment",
                source="test",
                log_path=path,
                headers={"Authorization": "Bearer secret-header"},
            ) as response:
                response.read()
                response.raise_for_status()
                if outcome == "body_error":
                    raise ValueError("secret-body")
        except (httpx.HTTPError, ValueError):
            assert outcome != "success"

    # Assert
    text = path.read_text(encoding="utf-8")
    record = json.loads(text)
    assert record["url"] == "https://example.test/docs"
    assert record["duration_ms"] == 125.0
    assert record["status_code"] == (
        None if outcome == "timeout" else 503 if outcome == "http_error" else 200
    )
    assert (
        record["error"]
        == {
            "success": None,
            "http_error": "HTTPStatusError",
            "timeout": "ReadTimeout",
            "body_error": "ValueError",
        }[outcome]
    )
    assert record["started_at"] <= record["finished_at"]
    assert record["worker"]
    assert record["thread"] == record["worker"]
    assert record["cpu_seconds"] >= 0
    assert isinstance(record["memory_bytes"], int)
    assert len(record["gc_collections"]) == 3
    assert record["response_bytes"] == (None if outcome == "timeout" else 11)
    assert record["request_bytes"] in {None, 0}
    assert "secret" not in text


@pytest.mark.parametrize("operation", ["advisory_get", "advisory_post", "gitlab"])
def test_http_clients_write_timing_records(tmp_path, operation):
    """Record real client request paths and avoid inventing requests for cache hits."""
    # Arrange
    path = tmp_path / "http-timings.jsonl"

    def handler(_request):
        """Return bounded JSON through the client-owned streaming path."""
        return httpx.Response(200, json={"ok": True})

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        if operation == "gitlab":
            client = GitLabClient(
                "secret-token",
                api_url="https://example.test/api/v4",
                http=http,
                http_log_path=path,
            )
            assert client._request(
                "POST",
                "https://example.test/api/graphql",
                {
                    "query": "query Timing { version }",
                    "variables": {"value": "secret-body"},
                },
            ) == {"ok": True}
        else:
            client = AdvisoryClient(http=http, http_log_path=path)
            if operation == "advisory_get":
                assert client._get_json("https://example.test/advisory") == {"ok": True}
                assert client._get_json("https://example.test/advisory") == {"ok": True}
            else:
                assert client._post_json(
                    "https://example.test/query", {"version": "secret-body"}
                ) == {"ok": True}

    # Assert
    records = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(records) == 1
    assert records[0]["source"] == ("gitlab" if operation == "gitlab" else "advisory")
    assert records[0]["status_code"] == 200
    assert records[0]["duration_ms"] >= 0
    assert records[0]["response_bytes"] > 0
    assert records[0]["thread"]
    assert len(records[0]["gc_collected"]) == 3
    if operation == "gitlab":
        assert records[0]["operation"] == "Timing"
        assert records[0]["request_bytes"] > 0
    assert "secret" not in path.read_text(encoding="utf-8")


def test_http_log_write_failure_preserves_request_result(tmp_path, caplog):
    """Keep successful HTTP work successful when local timing storage is unavailable."""
    # Arrange
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")

    def handler(_request):
        """Return the same response regardless of log storage availability."""
        return httpx.Response(200, text="ok")

    # Act
    with caplog.at_level(logging.WARNING, logger="gitlab_security_mcp"):
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            with timed_http_stream(
                client,
                "GET",
                "https://example.test/",
                source="test",
                log_path=blocked / "timings.jsonl",
            ) as response:
                body = response.read()

    # Assert
    assert body == b"ok"
    assert "Could not write HTTP timing log" in caplog.text
    assert "timings.jsonl" in caplog.text


def _overlap_handler(state: dict, lock: threading.Lock, body: str):
    """Count requests that are in flight at the same time."""

    def handler(_request: httpx.Request) -> httpx.Response:
        """Hold the request open long enough for another worker to enter."""
        with lock:
            state["inflight"] += 1
            state["max"] = max(state["max"], state["inflight"])
        try:
            time.sleep(0.05)
            return httpx.Response(200, text=body)
        finally:
            with lock:
                state["inflight"] -= 1

    return handler


def test_required_docs_are_requested_together_and_stay_in_order(tmp_path):
    """Overlap publisher reads and return them in catalog order."""
    # Arrange
    state = {"inflight": 0, "max": 0}
    markers = " ".join(marker for _name, _url, marker in REQUIRED_DOCS)
    docs = OfficialDocs(
        http_log_path=tmp_path / "http-timings.jsonl",
        http=httpx.Client(
            transport=httpx.MockTransport(
                _overlap_handler(state, threading.Lock(), markers)
            )
        ),
    )

    # Act
    review = docs.read_before_fix({"location": {"file": "widget.ts"}})

    # Assert
    assert state["max"] >= 2
    assert review.complete
    selected = [
        (name, url)
        for name, url, _marker in REQUIRED_DOCS
        if name in {"typescript", "javascript"}
    ]
    assert [item.name for item in review.sources] == [name for name, _url in selected]
    records = [
        json.loads(line)
        for line in (tmp_path / "http-timings.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert len(records) == len(selected)
    assert {record["url"] for record in records} == {url for _name, url in selected}
    assert all(
        record["source"] == "documentation" and record["status_code"] == 200
        for record in records
    )
    assert any(
        first["started_at"] < second["started_at"] < first["finished_at"]
        for first in records
        for second in records
    )


def test_one_doc_failure_keeps_the_other_page_results():
    """Record a failed page without dropping the pages that were read."""
    # Arrange
    markers = " ".join(marker for _name, _url, marker in REQUIRED_DOCS)

    def handler(request: httpx.Request) -> httpx.Response:
        """Fail only the JavaScript reference and serve the other markers."""
        if request.url.host == "developer.mozilla.org":
            return httpx.Response(503, text="down")
        return httpx.Response(200, text=markers)

    docs = OfficialDocs(http=httpx.Client(transport=httpx.MockTransport(handler)))

    # Act
    review = docs.read_before_fix({"location": {"file": "widget.ts"}})

    # Assert
    assert review.complete is False
    assert len(review.sources) == 2
    failed = next(item for item in review.sources if item.name == "javascript")
    assert failed.ok is False
    assert any(item.ok for item in review.sources)


def test_close_waits_until_the_doc_read_finishes():
    """Do not retire the client while publisher requests are still running."""
    # Arrange
    entered = threading.Event()
    finish = threading.Event()
    markers = " ".join(marker for _name, _url, marker in REQUIRED_DOCS)

    def handler(_request: httpx.Request) -> httpx.Response:
        """Block the read until the test releases it."""
        entered.set()
        finish.wait(3)
        return httpx.Response(200, text=markers)

    docs = OfficialDocs(http=httpx.Client(transport=httpx.MockTransport(handler)))
    reader = threading.Thread(
        target=docs.read_before_fix, args=({"location": {"file": "widget.py"}},)
    )
    reader.start()
    assert entered.wait(2)
    closed = threading.Event()

    def wait_for_close():
        """Close the client and record when that call returns."""
        docs.close()
        closed.set()

    # Act
    closer = threading.Thread(target=wait_for_close)
    closer.start()
    time.sleep(0.05)
    still_open = not closed.is_set()
    finish.set()
    reader.join(3)
    closer.join(3)

    # Assert
    assert still_open
    assert closed.is_set()
    assert docs.read_before_fix({}).sources[0].error == "Documentation client is closed"


@pytest.mark.parametrize("repeated", [False, True])
def test_advisory_identifiers_are_requested_together_in_order(repeated):
    """Fetch distinct OSV ids once, concurrently, in first-occurrence order."""
    # Arrange
    state = {"inflight": 0, "max": 0, "requests": 0}
    lock = threading.Lock()
    # Both distinct reads must be in flight together; a sleep only made overlap likely.
    together = threading.Barrier(2, timeout=5)

    def handler(request: httpx.Request) -> httpx.Response:
        """Serve one OSV record per identifier and count overlapping calls."""
        with lock:
            state["requests"] += 1
            state["inflight"] += 1
            state["max"] = max(state["max"], state["inflight"])
        try:
            together.wait()
            ident = request.url.path.rsplit("/", 1)[-1]
            return httpx.Response(
                200,
                json={
                    "id": ident,
                    "affected": [
                        {
                            "package": {"ecosystem": "npm", "name": "left-pad"},
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [{"introduced": "0"}, {"fixed": "1.2.0"}],
                                }
                            ],
                        }
                    ],
                },
            )
        finally:
            with lock:
                state["inflight"] -= 1

    client = AdvisoryClient(http=httpx.Client(transport=httpx.MockTransport(handler)))

    # Act
    result = client.lookup(
        {"identifiers": ["CVE-2020-0001", "CVE-2020-0002"] * (3 if repeated else 1)},
        "npm",
        "left-pad",
        "1.0.0",
    )

    # Assert
    assert state["max"] >= 2
    assert result.outcome == "resolved"
    assert result.sources == ["osv:CVE-2020-0001", "osv:CVE-2020-0002"]
    assert state["requests"] == 2


def test_earlier_github_identifier_wins_when_reads_overlap():
    """Choose the first finding id even when a later id responds first."""
    # Arrange
    seen: list[str] = []
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        """Delay the first CVE so the second response would otherwise win."""
        if request.url.host != "api.github.com":
            return httpx.Response(404)
        cve = request.url.params["cve_id"]
        with lock:
            seen.append(cve)
        if cve.endswith("1111"):
            time.sleep(0.05)
            fixed = "2.0.0"
        else:
            fixed = "3.0.0"
        return httpx.Response(
            200,
            json=[
                {
                    "ghsa_id": cve,
                    "html_url": "https://example.test/advisory",
                    "vulnerabilities": [
                        {
                            "package": {"ecosystem": "npm", "name": "left-pad"},
                            "vulnerable_version_range": "< 9.0.0",
                            "first_patched_version": fixed,
                        }
                    ],
                }
            ],
        )

    client = AdvisoryClient(http=httpx.Client(transport=httpx.MockTransport(handler)))

    # Act
    result = client.lookup(
        {"identifiers": ["CVE-2020-1111", "CVE-2020-2222"]},
        "npm",
        "left-pad",
        "1.0.0",
    )

    # Assert
    assert set(seen) == {"CVE-2020-1111", "CVE-2020-2222"}
    assert result.outcome == "resolved"
    assert result.sources == ["github:CVE-2020-1111"]
    assert result.fixed_versions == ["2.0.0"]


def test_one_oversized_advisory_does_not_drop_the_other_identifier():
    """Keep a valid OSV record when another identifier response is too large."""
    # Arrange
    oversized = b"x" * (_MAX_ADVISORY_BYTES + 1)

    def handler(request: httpx.Request) -> httpx.Response:
        """Return one oversized body and one matching OSV record."""
        ident = request.url.path.rsplit("/", 1)[-1]
        if ident.endswith("0001"):
            return httpx.Response(200, content=oversized)
        return httpx.Response(
            200,
            json={
                "id": ident,
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "left-pad"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "1.2.0"}],
                            }
                        ],
                    }
                ],
            },
        )

    client = AdvisoryClient(http=httpx.Client(transport=httpx.MockTransport(handler)))

    # Act
    result = client.lookup(
        {"identifiers": ["CVE-2020-0001", "CVE-2020-0002"]},
        "npm",
        "left-pad",
        "1.0.0",
    )

    # Assert
    assert result.outcome == "resolved"
    assert result.sources == ["osv:CVE-2020-0002"]
    assert any("size limit" in error for error in result.errors)


def test_unexpected_doc_failure_is_logged_and_recorded(caplog):
    """Record and log a publisher read that raises before a response exists."""

    # Arrange
    def handler(_request: httpx.Request) -> httpx.Response:
        """Fail the transport before any page body is available."""
        raise RuntimeError("publisher unavailable")

    docs = OfficialDocs(http=httpx.Client(transport=httpx.MockTransport(handler)))

    # Act
    with caplog.at_level(logging.ERROR):
        review = docs.read_before_fix({"location": {"file": "widget.py"}})

    # Assert
    assert review.complete is False
    assert {item.error for item in review.sources} == {"RuntimeError"}
    assert "publisher unavailable" in caplog.text


@pytest.mark.parametrize("count", [1, 2])
def test_fanout_persists_completions_on_caller_before_waiting_for_earlier_items(count):
    """Deliver later completions promptly without moving persistence onto worker threads."""
    # Arrange
    caller = threading.get_ident()
    release_first = threading.Event()
    completed = []

    def work(item):
        """Let the later item release the first via its persistence callback."""
        if count > 1 and item == 0:
            assert release_first.wait(3)
        return item * 10

    def persist(index, result):
        """Record a completion on the caller before replenishing workers."""
        assert threading.get_ident() == caller
        completed.append((index, result))
        release_first.set()

    # Act
    result = map_ordered(work, range(count), on_result=persist)

    # Assert
    assert result == [item * 10 for item in range(count)]
    assert completed == ([(0, 0)] if count == 1 else [(1, 10), (0, 0)])


def test_one_item_stays_on_the_caller_and_keeps_order():
    """Avoid a worker pool when there is nothing to overlap."""
    # Arrange
    calls = []

    def record(item: int) -> int:
        """Remember the caller and return the item unchanged."""
        calls.append(threading.get_ident())
        return item

    # Act
    single = map_ordered(record, [7])
    ordered = map_ordered(record, [1, 2, 3])

    # Assert
    assert single == [7]
    assert calls[0] == threading.get_ident()
    assert ordered == [1, 2, 3]


def test_fanout_preserves_request_context_without_sharing_worker_changes():
    """Keep progress callbacks request-local when work enters pool threads."""
    # Arrange
    from contextvars import ContextVar

    marker = ContextVar("request_marker", default="unset")
    marker.set("request")

    def work(item):
        """Read the caller context, then modify only this worker's copy."""
        before = marker.get()
        marker.set(str(item))
        return before, threading.current_thread()

    # Act
    results = map_ordered(work, range(4))

    # Assert
    assert [value for value, _thread in results] == ["request"] * 4
    assert marker.get() == "request"
    assert all(not thread.is_alive() for _value, thread in results)


def test_fanout_bounds_queued_work_as_the_input_is_consumed(monkeypatch):
    """Never materialize a large iterable or queue more than the worker bound."""
    # Arrange
    from gitlab_security_mcp import fanout

    monkeypatch.setattr(fanout, "MAX_WORKERS", 2)
    lock = threading.Lock()
    produced = completed = 0

    def items():
        """Reject eager consumption beyond the bounded in-flight window."""
        nonlocal produced
        for item in range(20):
            with lock:
                produced += 1
                assert produced - completed <= 2
            yield item

    def work(item):
        """Account for completion before returning ordered output."""
        nonlocal completed
        with lock:
            completed += 1
        return item

    # Act
    result = map_ordered(work, items())

    # Assert
    assert result == list(range(20))
    assert produced == completed == 20


def test_fanout_failure_joins_workers_and_does_not_consume_more_input(monkeypatch):
    """Reclaim running workers and propagate failures without starting the tail."""
    # Arrange
    from gitlab_security_mcp import fanout

    monkeypatch.setattr(fanout, "MAX_WORKERS", 2)
    entered = threading.Event()
    release = threading.Event()
    threads = []
    produced = []

    def items():
        """Record how far the work source was consumed."""
        for item in range(20):
            produced.append(item)
            yield item

    def work(item):
        """Fail the first job while the other job is already running."""
        threads.append(threading.current_thread())
        if item == 0:
            assert entered.wait(2)
            release.set()
            raise ValueError("lookup failed")
        entered.set()
        assert release.wait(2)
        return item

    # Act
    with pytest.raises(ValueError, match="lookup failed"):
        map_ordered(work, items())

    # Assert
    assert produced == [0, 1]
    assert all(not thread.is_alive() for thread in threads)


def test_fanout_refills_workers_without_waiting_for_the_first_result(monkeypatch):
    """Keep spare workers busy while an earlier ordered result is still pending."""
    # Arrange
    from gitlab_security_mcp import fanout

    monkeypatch.setattr(fanout, "MAX_WORKERS", 2)
    last_started = threading.Event()

    def work(item):
        """Require the third job to start before the first can finish."""
        if item == 0:
            assert last_started.wait(2)
        if item == 2:
            last_started.set()
        return item

    # Act
    result = map_ordered(work, range(3))

    # Assert
    assert result == [0, 1, 2]
    assert last_started.is_set()


def test_fanout_logs_worker_count_duration_and_failure(caplog):
    """Record a fan-out batch and the exception class when a worker fails."""

    # Arrange
    def succeed(item):
        """Return the item unchanged."""
        return item

    def fail(item):
        """Fail one worker with a message that must not be logged."""
        if item == 1:
            raise RuntimeError("secret glpat-hidden")
        return item

    # Act
    with caplog.at_level(logging.INFO, logger="gitlab_security_mcp"):
        assert map_ordered(succeed, range(3)) == [0, 1, 2]
        with pytest.raises(RuntimeError):
            map_ordered(fail, range(3))
    records = [
        json.loads(record.message.removeprefix("Concurrency "))
        for record in caplog.records
        if record.message.startswith("Concurrency ")
        and '"kind": "fanout"' in record.message
    ]

    # Assert
    assert records[0]["kind"] == "fanout"
    assert records[0]["workers"] == 3
    assert records[0]["items"] == 3
    assert records[0]["duration_ms"] >= 0
    assert records[0]["cpu_seconds"] >= 0
    assert isinstance(records[0]["memory_bytes"], int)
    assert len(records[0]["gc_collections"]) == 3
    assert records[0]["thread"]
    assert records[0]["error"] is None
    assert records[1]["error"] == "RuntimeError"
    assert all("glpat-hidden" not in record.message for record in caplog.records)


class _Chunks:
    """Expose a fixed sequence of body chunks as an HTTP response."""

    def __init__(self, chunks: list[bytes]):
        """Store the chunks ``read_bounded_response`` will pull."""
        self._chunks = chunks

    def iter_bytes(self) -> list[bytes]:
        """Return every chunk, including ones past the caller's limit."""
        return self._chunks


def test_read_bounded_response_keeps_a_short_body_and_rejects_a_longer_one():
    """One reader enforces the byte cap for GitLab and advisory responses."""
    # Arrange
    body = _Chunks([b"abcd", b"efgh"])

    # Act
    kept = read_bounded_response(body, 8, error="too big")

    # Assert
    assert kept == b"abcdefgh"
    with pytest.raises(ValueError, match="too big"):
        read_bounded_response(body, 7, error="too big")


def test_share_in_flight_reuses_one_success_and_drops_a_failed_fetch():
    """Waiters share a stored value, and a failed fetch stays out of the cache."""
    # Arrange
    condition = threading.Condition()
    pending: set[str] = set()
    cache: dict[str, str] = {}
    calls = {"count": 0}

    def fetch() -> str:
        """Count one successful read."""
        calls["count"] += 1
        return "kept"

    def fail() -> str:
        """Fail before a value can be stored."""
        raise RuntimeError("missing")

    # Act
    first = share_in_flight(condition, pending, cache, "a", fetch, max_entries=1)
    second = share_in_flight(condition, pending, cache, "a", fetch, max_entries=1)
    with pytest.raises(RuntimeError, match="missing"):
        share_in_flight(condition, pending, cache, "missing", fail, max_entries=1)
    third = share_in_flight(condition, pending, cache, "b", fetch, max_entries=1)

    # Assert
    assert first == second == "kept"
    assert calls["count"] == 2
    assert third == "kept"
    assert list(cache) == ["b"]
    assert pending == set()


def test_share_in_flight_reject_runs_before_a_fetch_is_marked():
    """A closed client refuses a new key without leaving it in flight."""
    # Arrange
    condition = threading.Condition()
    pending: set[str] = set()
    cache: dict[str, str] = {}

    def reject() -> None:
        """Model a client that has already started to close."""
        raise RuntimeError("closed")

    def fetch() -> str:
        """Fail the test when a rejected key is still fetched."""
        raise AssertionError("fetch")

    # Act
    with pytest.raises(RuntimeError, match="closed"):
        share_in_flight(
            condition,
            pending,
            cache,
            "a",
            fetch,
            max_entries=1,
            reject=reject,
        )

    # Assert
    assert cache == {}
    assert pending == set()
