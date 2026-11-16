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
from gitlab_security_mcp.util import timed_http_stream


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
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with OfficialDocs(http=http, http_log_path=path) as docs:
            first = docs.read_before_fix({"identifiers": ["CVE-2020-0001"]})

            # Act
            second = docs.read_for_existing_fix(
                {"identifiers": ["CVE-2020-0002"]}, first.as_list(), [rule_page]
            )
            after_shared = list(requests)
            fresh = docs.read_before_fix({"identifiers": ["CVE-2020-0002"]})

    # Assert
    assert first.complete and second.complete and fresh.complete
    assert after_shared.count(rule_page["url"]) == 2
    assert requests.count(rule_page["url"]) == 3
    assert all(
        after_shared.count(url) == 1 for _name, url, _marker in REQUIRED_DOCS[1:]
    )
    assert all(requests.count(url) == 2 for _name, url, _marker in REQUIRED_DOCS[1:])
    assert any("CVE-2020-0002" in url for url in after_shared)
    assert not any("CVE-2020-0001" in source.url for source in second.sources)
    assert len(path.read_text().splitlines()) == len(requests)


def test_parallel_source_reviews_share_run_receipts_but_edits_stay_fresh():
    """Fetch identical source-review pages once, including across simultaneous calls."""
    # Arrange
    from collections import Counter
    from concurrent.futures import ThreadPoolExecutor

    requests = []
    markers = " ".join(marker for _name, _url, marker in REQUIRED_DOCS) + " CWE-79"
    finding = {"identifiers": ["CWE-79"]}
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
    assert len(after_shared) == len(REQUIRED_DOCS) + 1
    assert set(after_shared.values()) == {1}
    assert any(source.as_dict().get("reused") for source in reviews[-1].sources)
    assert not any(source.as_dict().get("reused") for source in new_run.sources)
    assert not any(source.as_dict().get("reused") for source in edit.sources)
    assert set(Counter(requests).values()) == {3}
    assert docs.read_for_source(finding, run_key=scope).sources[0].error == (
        "Documentation client is closed"
    )


@pytest.mark.parametrize("failed", ["python", "cwe:CWE-79", "nsa"])
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
            first = docs.read_for_source({"identifiers": ["CWE-79"]}, run_key=scope)
            second = docs.read_for_source({"identifiers": ["CWE-79"]}, run_key=scope)
    # Assert
    first_source = next(
        source for source in first.sources if source.url == urls[failed]
    )
    second_source = next(
        source for source in second.sources if source.url == urls[failed]
    )
    assert not first_source.ok
    assert second_source.ok is (failed != "nsa")
    assert requests.count(urls[failed]) == (1 if failed == "nsa" else 2)
    assert all(
        count == 1 for url, count in Counter(requests).items() if url != urls[failed]
    )


def test_source_receipt_cache_evicts_old_records_not_frequently_used_catalog(
    monkeypatch,
):
    """Bound cache growth without repeatedly fetching the shared publisher catalog."""
    # Arrange
    from gitlab_security_mcp import official_docs

    monkeypatch.setattr(official_docs, "_MAX_SOURCE_CACHE", len(REQUIRED_DOCS) + 3)
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
                docs.read_for_source({"identifiers": [f"CWE-{number}"]}, run_key=scope)
            docs.read_for_source({"identifiers": ["CWE-1"]}, run_key=scope)
    # Assert
    assert requests.count("https://cwe.mitre.org/data/definitions/1.html") == 2
    assert all(requests.count(url) == 1 for _name, url, _marker in REQUIRED_DOCS)


@pytest.mark.parametrize("exit_code", [0, 1])
def test_parallel_gradle_findings_share_one_dependency_inspection(
    tmp_path, monkeypatch, exit_code
):
    """Five parallel findings reuse one complete tree rather than spawning five builds."""
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
        "+--- io.example:library:1.0.0\r\n"
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
            "installedVersion": "1.0.0",
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
    runner.run.assert_called_once()
    assert parse.call_count == (0 if exit_code else 1)
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
        assert "checkstyle" in markdown and "runtimeClasspath" in markdown
        assert engine.state.validation_status is None
    engine.verify_security_finding("0")
    assert runner.run.call_count == (2 if exit_code else 1)
    assert parse.call_count == (0 if exit_code else 1)


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
            client = GitLabClient("secret-token", http=http, http_log_path=path)
            assert client._request(
                "POST", "https://example.test/api/graphql", {"query": "secret-body"}
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
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["source"] == ("gitlab" if operation == "gitlab" else "advisory")
    assert records[0]["status_code"] == 200
    assert records[0]["duration_ms"] >= 0
    assert "secret" not in path.read_text()


def test_http_log_write_failure_preserves_request_result(tmp_path):
    """Keep successful HTTP work successful when local timing storage is unavailable."""
    # Arrange
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory")

    def handler(_request):
        """Return the same response regardless of log storage availability."""
        return httpx.Response(200, text="ok")

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with timed_http_stream(
            client,
            "GET",
            "https://example.test/",
            source="test",
            log_path=blocked / "timings.jsonl",
        ) as response:
            # Assert
            assert response.read() == b"ok"


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
    review = docs.read_before_fix({})

    # Assert
    assert state["max"] >= 2
    assert review.complete
    assert [item.name for item in review.sources] == [
        name for name, _url, _marker in REQUIRED_DOCS
    ]
    records = [
        json.loads(line)
        for line in (tmp_path / "http-timings.jsonl").read_text().splitlines()
    ]
    assert len(records) == len(REQUIRED_DOCS)
    assert {record["url"] for record in records} == {
        url for _name, url, _marker in REQUIRED_DOCS
    }
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
        """Fail only the Docker reference and serve the other markers."""
        if request.url.host == "docs.docker.com":
            return httpx.Response(503, text="down")
        return httpx.Response(200, text=markers)

    docs = OfficialDocs(http=httpx.Client(transport=httpx.MockTransport(handler)))

    # Act
    review = docs.read_before_fix({})

    # Assert
    assert review.complete is False
    assert len(review.sources) == len(REQUIRED_DOCS)
    failed = next(item for item in review.sources if item.name == "docker")
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
    reader = threading.Thread(target=docs.read_before_fix, args=({},))
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

    def handler(request: httpx.Request) -> httpx.Response:
        """Serve one OSV record per identifier and count overlapping calls."""
        with lock:
            state["requests"] += 1
            state["inflight"] += 1
            state["max"] = max(state["max"], state["inflight"])
        try:
            time.sleep(0.05)
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
        review = docs.read_before_fix({})

    # Assert
    assert review.complete is False
    assert {item.error for item in review.sources} == {"RuntimeError"}
    assert "publisher unavailable" in caplog.text


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
    assert records[0]["error"] is None
    assert records[1]["error"] == "RuntimeError"
    assert all("glpat-hidden" not in record.message for record in caplog.records)
