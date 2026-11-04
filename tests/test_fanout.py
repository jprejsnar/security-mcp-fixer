"""Check that independent reads overlap and keep their input order."""

import logging
import threading
import time

import httpx

from gitlab_security_mcp.advisory import _MAX_ADVISORY_BYTES, AdvisoryClient
from gitlab_security_mcp.fanout import map_ordered
from gitlab_security_mcp.official_docs import REQUIRED_DOCS, OfficialDocs


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


def test_required_docs_are_requested_together_and_stay_in_order():
    """Overlap publisher reads and return them in catalog order."""
    # Arrange
    state = {"inflight": 0, "max": 0}
    markers = " ".join(marker for _name, _url, marker in REQUIRED_DOCS)
    docs = OfficialDocs(
        http=httpx.Client(
            transport=httpx.MockTransport(
                _overlap_handler(state, threading.Lock(), markers)
            )
        )
    )

    # Act
    review = docs.read_before_fix({})

    # Assert
    assert state["max"] >= 2
    assert review.complete
    assert [item.name for item in review.sources] == [
        name for name, _url, _marker in REQUIRED_DOCS
    ]


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


def test_advisory_identifiers_are_requested_together_in_order():
    """Fetch every OSV id at once and keep the finding's identifier order."""
    # Arrange
    state = {"inflight": 0, "max": 0}
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        """Serve one OSV record per identifier and count overlapping calls."""
        with lock:
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
        {"identifiers": ["CVE-2020-0001", "CVE-2020-0002"]},
        "npm",
        "left-pad",
        "1.0.0",
    )

    # Assert
    assert state["max"] >= 2
    assert result.outcome == "resolved"
    assert result.sources == ["osv:CVE-2020-0001", "osv:CVE-2020-0002"]


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
