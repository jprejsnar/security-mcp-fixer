"""Verify package matching and patched-version evidence across advisories."""

import httpx
import pytest

from gitlab_security_mcp.advisory import PACKAGE_MISMATCH, AdvisoryClient
from gitlab_security_mcp.versions import (
    first_unaffected,
    is_major_upgrade,
    osv_version_affected,
)

FINDING = {"identifiers": ["CVE-2021-23337"], "title": "lodash"}


@pytest.mark.parametrize("independent_bounds", [True, False])
def test_withdrawn_osv_record_cannot_supply_an_active_range_or_fix(independent_bounds):
    """Continue to independent evidence instead of trusting a withdrawn OSV advisory."""
    # Arrange
    finding = {"identifiers": ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"]}

    def handler(request):
        """Serve the logged withdrawn-record shape and independent NVD bounds."""
        if request.url.path.endswith("GHSA-35jh-r3h4-6jhm"):
            return httpx.Response(
                200,
                json={
                    "id": "GHSA-35jh-r3h4-6jhm",
                    "withdrawn": "2026-11-18T15:38:56Z",
                    "affected": [
                        {
                            "package": {"name": "lodash", "ecosystem": "npm"},
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "99.0.0"},
                                    ],
                                }
                            ],
                        }
                    ],
                },
            )
        if request.url.host == "api.github.com":
            return httpx.Response(200, json=[])
        if independent_bounds and request.url.host == "services.nvd.nist.gov":
            return httpx.Response(
                200,
                json={
                    "vulnerabilities": [
                        {
                            "cve": {
                                "configurations": [
                                    {
                                        "nodes": [
                                            {
                                                "cpeMatch": [
                                                    {
                                                        "criteria": "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*",
                                                        "vulnerable": True,
                                                        "versionEndExcluding": "4.17.21",
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        }
                    ]
                },
            )
        return httpx.Response(404)

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with AdvisoryClient(http=http) as client:
            result = client.lookup(finding, "npm", "lodash", "4.17.20")

    # Assert
    assert result.lowest_fixed_version == ("4.17.21" if independent_bounds else None)
    assert result.affected is (True if independent_bounds else None)
    assert any("withdrawn" in error.lower() for error in result.errors)
    if not independent_bounds:
        assert result.outcome == "lookup_failed"


@pytest.mark.parametrize(
    "versions,default,current,expected",
    [
        (
            [
                {
                    "version": "0",
                    "lessThanOrEqual": "4.4.1",
                    "status": "affected",
                    "versionType": "semver",
                }
            ],
            "unaffected",
            "4.4.1",
            True,
        ),
        (
            [
                {
                    "version": "0",
                    "lessThanOrEqual": "4.4.1",
                    "status": "affected",
                    "versionType": "semver",
                }
            ],
            "unaffected",
            "4.4.2",
            False,
        ),
        (
            [
                {"version": "4.4.0", "status": "affected"},
                {"version": "4.4.1", "status": "affected"},
            ],
            None,
            "4.4.1",
            True,
        ),
        ([{"version": "4.4.0", "status": "affected"}], None, "4.4.1", None),
        (
            [
                {
                    "version": "5.0.0",
                    "lessThanOrEqual": "4.4.1",
                    "status": "affected",
                    "versionType": "semver",
                }
            ],
            "unaffected",
            "4.4.1",
            None,
        ),
        (
            [
                {
                    "version": "0",
                    "lessThanOrEqual": "4.4.1",
                    "status": "affected",
                    "versionType": "git",
                }
            ],
            "unaffected",
            "4.4.1",
            None,
        ),
    ],
)
def test_cna_structured_versions_fill_missing_nvd_bounds(
    versions, default, current, expected
):
    """Use exact CNA package/version evidence without inferring safe versions from omissions."""
    # Arrange
    ident = "CVE-2026-93690"
    entry = {
        "product": "uri-js",
        "packageURL": "pkg:npm/uri-js",
        "versions": versions,
    }
    if default is not None:
        entry["defaultStatus"] = default

    def handler(request):
        """Return incomplete NVD data and a package-bound published CNA record."""
        if request.url.host == "services.nvd.nist.gov":
            return httpx.Response(
                200, json={"vulnerabilities": [{"cve": {"id": ident}}]}
            )
        if request.url.host == "cveawg.mitre.org":
            return httpx.Response(
                200,
                json={
                    "cveMetadata": {"cveId": ident, "state": "PUBLISHED"},
                    "containers": {"cna": {"affected": [entry]}},
                },
            )
        if request.url.host == "api.github.com":
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with AdvisoryClient(http=http) as client:
            result = client.lookup({"identifiers": [ident]}, "npm", "uri-js", current)

    # Assert
    assert result.affected is expected
    assert f"cve:{ident}" in result.sources
    assert result.lowest_fixed_version is None
    if expected is True:
        assert result.outcome == "no_fix_published"
        assert "CNA" in result.summary
    elif expected is None:
        assert result.outcome == "lookup_failed"


@pytest.mark.parametrize(
    "version, affected", [("2.7.5-r0", False), ("2.8.3-r0", True), ("2.8.4-r0", False)]
)
def test_nvd_unaffected_reason_explains_installed_version_and_bounds(version, affected):
    """Explain the archived libexpat decision without mistaking a fix for its cause."""
    # Arrange
    from gitlab_security_mcp.advisory import _from_nvd

    record = {
        "cve": {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:libexpat:libexpat:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "2.8.2",
                                    "versionEndExcluding": "2.8.4",
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    }

    # Act
    result = _from_nvd(record, "libexpat", version, ["nvd:CVE-fixture"], [])

    # Assert
    assert result.affected is affected
    assert result.ranges == [">=2.8.2,<2.8.4"]
    if not affected:
        assert f"Installed libexpat {version} is outside" in result.summary
        assert ">=2.8.2,<2.8.4" in result.summary
    else:
        assert "outside" not in result.summary
        assert result.lowest_fixed_version == "2.8.4"


@pytest.mark.parametrize(
    "configurations",
    [
        [],
        [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ],
    ],
)
def test_nvd_without_version_evidence_requires_review(configurations):
    """Do not convert missing NVD bounds into a definitive no-fix assessment."""

    # Arrange
    def handler(request):
        """Return an identifier record without usable affected-version evidence."""
        if request.url.host == "services.nvd.nist.gov":
            return httpx.Response(
                200,
                json={"vulnerabilities": [{"cve": {"configurations": configurations}}]},
            )
        if request.url.host == "api.github.com":
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with AdvisoryClient(http=http) as client:
            result = client.lookup(FINDING, "npm", "lodash", "4.17.20")

    # Assert
    assert result.outcome == "lookup_failed"
    assert result.affected is None
    assert result.sources == ["nvd:CVE-2021-23337"]
    assert "version" in result.summary.lower()


@pytest.mark.parametrize("failure", [429, 503, "timeout"])
def test_nvd_recovers_transient_failures_without_caching_them(failure, nvd_clock):
    """Retry the archive's transient NVD failures and cache only a valid recovery."""
    # Arrange
    requests = []

    def handler(request):
        """Fail once, then return a complete record without external traffic."""
        requests.append(request)
        if len(requests) == 1:
            if failure == "timeout":
                raise httpx.ReadTimeout("fixture timeout", request=request)
            return httpx.Response(failure, headers={"Retry-After": "9"})
        return httpx.Response(
            200, json={"vulnerabilities": [{"cve": {"id": "CVE-2021-23337"}}]}
        )

    errors, sources = [], []
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with AdvisoryClient(http=http) as client:
            # Act
            result = client._nvd("CVE-2021-23337", errors, sources)
            cached = client._nvd("CVE-2021-23337", errors, sources)

    # Assert
    assert result == cached == {"cve": {"id": "CVE-2021-23337"}}
    assert errors == []
    assert len(requests) == 2
    assert sum(nvd_clock[1]) >= (6.1 if failure == "timeout" else 9)


@pytest.mark.parametrize("status", [401, 403, 404, 429, 503])
def test_nvd_failure_is_bounded_and_never_cached_as_success(status, nvd_clock):
    """Keep outages unresolved and avoid retrying denied access or missing records."""
    # Arrange
    requests = []

    def handler(request):
        """Return the same persistent status for each actual attempt."""
        requests.append(request)
        return httpx.Response(status)

    errors, sources = [], []
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with AdvisoryClient(http=http) as client:
            # Act
            result = client._nvd("CVE-2021-23337", errors, sources)
            cache = dict(client._cache)

    # Assert
    assert result is None
    assert len(requests) == (3 if status in {429, 503} else 1)
    assert bool(errors) is (status != 404)
    assert sources == []
    assert cache == (
        {"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-23337": None}
        if status == 404
        else {}
    )


@pytest.mark.parametrize("key, minimum", [(None, 6), ("fixture-api-key", 0.6)])
def test_nvd_rate_limit_is_shared_across_checkout_clients(nvd_clock, key, minimum):
    """Respect NVD request spacing even when different repositories use separate clients."""
    # Arrange
    starts = []

    def handler(request):
        """Record virtual request start times instead of calling NVD."""
        starts.append(nvd_clock[0][0])
        return httpx.Response(200, json={"vulnerabilities": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with (
            AdvisoryClient(http=http, nvd_api_key=key) as first,
            AdvisoryClient(http=http, nvd_api_key=key) as second,
        ):
            # Act
            first._nvd("CVE-2021-23337", [], [])
            second._nvd("CVE-2021-23338", [], [])

    # Assert
    assert len(starts) == 2
    assert starts[1] - starts[0] >= minimum


def test_nvd_does_not_retry_before_a_long_server_cooldown(nvd_clock):
    """Stop unresolved rather than ignoring Retry-After beyond the bounded wait."""
    # Arrange
    requests = []

    def handler(request):
        """Require a longer server cooldown than this tool call may wait."""
        requests.append(request)
        return httpx.Response(429, headers={"Retry-After": "120"})

    errors = []
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with AdvisoryClient(http=http) as client:
            # Act
            result = client._nvd("CVE-2021-23337", errors, [])
            next_result = client._nvd("CVE-2021-23338", errors, [])

    # Assert
    assert result is None
    assert next_result is None
    assert errors
    assert len(requests) == 1
    assert nvd_clock[1] == []


def test_nvd_retry_honors_http_date_headers(nvd_clock):
    """Translate a server's HTTP-date cooldown into the bounded retry clock."""
    # Arrange
    from datetime import UTC, datetime, timedelta
    from email.utils import format_datetime

    requests = []
    after = format_datetime(datetime.now(UTC) + timedelta(seconds=20), usegmt=True)

    def handler(request):
        """Recover only after the supplied server retry date."""
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(503, headers={"Retry-After": after})
        return httpx.Response(
            200, json={"vulnerabilities": [{"cve": {"id": "CVE-2021-23337"}}]}
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with AdvisoryClient(http=http) as client:
            # Act
            result = client._nvd("CVE-2021-23337", [], [])

    # Assert
    assert result is not None
    assert len(requests) == 2
    assert 18 <= sum(nvd_clock[1]) <= 20


@pytest.mark.parametrize(
    "events, expected_fixed",
    [
        ([{"introduced": "0"}, {"fixed": "4.17.21"}], "4.17.21"),
        (
            [
                {"introduced": "0"},
                {"fixed": "4.17.21"},
                {"introduced": "4.17.21"},
                {"fixed": "4.17.22"},
            ],
            "4.17.22",
        ),
        ([{"introduced": "0"}], None),
    ],
)
def test_solution_version_is_verified_outside_all_affected_ranges(
    events, expected_fixed
):
    """Reject solution hints that are still inside another affected range."""
    # Arrange
    record = {
        "id": "GHSA-35jh-r3h4-6jhm",
        "aliases": ["CVE-2021-23337"],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": events}],
            }
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        """Serve the parametrized OSV record without network requests."""
        assert request.url.host == "api.osv.dev"
        return httpx.Response(200, json=record)

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = AdvisoryClient(http=http)
        finding = {
            **FINDING,
            "solution": "Upgrade to version 4.17.21.",
            "fixedVersions": ["4.17.21"],
        }
        vulnerable = client.lookup(finding, "npm", "lodash", "4.17.20")

        # Assert
        assert vulnerable.affected is True
        assert vulnerable.lowest_fixed_version == expected_fixed
        if expected_fixed:
            assert vulnerable.outcome == "resolved"
            patched = client.lookup(finding, "npm", "lodash", expected_fixed)
            assert patched.affected is False
        else:
            assert vulnerable.outcome == "no_fix_published"


@pytest.mark.parametrize("status", [200, 404])
def test_advisory_cache_is_bounded_and_cleared_on_close(monkeypatch, status):
    """Evict old successful and missing records and release them on shutdown."""
    # Arrange
    from gitlab_security_mcp import advisory

    monkeypatch.setattr(advisory, "MAX_CACHE_ENTRIES", 2)

    def handler(request):
        """Return disposable advisory payloads without network access."""
        return httpx.Response(status, json={"id": request.url.path})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = AdvisoryClient(http=http)

        # Act
        for number in range(3):
            client._get_json(f"https://example.test/{number}")

        # Assert
        assert len(client._cache) == 2
        assert "https://example.test/0?" not in client._cache
        client.close()
        assert client._cache == {}
        assert not http.is_closed


def test_advisory_close_failure_still_releases_cached_payloads(monkeypatch):
    """Release retained evidence even if the owned transport cannot close."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import advisory

    http = Mock()
    http.close.side_effect = OSError("Transport close failed")
    monkeypatch.setattr(advisory.httpx, "Client", lambda **kwargs: http)
    client = AdvisoryClient()
    client._cache["fixture"] = {"evidence": "retained"}

    # Act
    with pytest.raises(OSError, match="Transport close failed"):
        client.close()
    client.close()

    # Assert
    assert client._cache == {}
    assert client._closed
    http.close.assert_called_once()


def _client(handler) -> tuple[httpx.Client, AdvisoryClient]:
    """Bind an advisory wrapper to an injected mock-transport HTTP client."""
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return http, AdvisoryClient(http=http)


def test_github_first_patched_version_is_used():
    """Github first patched version is used."""

    # Arrange
    def handler(request: httpx.Request) -> httpx.Response:
        """Return GitHub evidence after OSV misses the requested finding."""
        if request.url.host == "api.github.com":
            return httpx.Response(
                200,
                json=[
                    {
                        "ghsa_id": "GHSA-35jh-r3h4-6jhm",
                        "html_url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
                        "vulnerabilities": [
                            {
                                "package": {"ecosystem": "npm", "name": "lodash"},
                                "vulnerable_version_range": "< 4.17.21",
                                "first_patched_version": "4.17.21",
                            }
                        ],
                    }
                ],
            )
        return httpx.Response(404)

    http, client = _client(handler)

    # Act
    with http:
        result = client.lookup(FINDING, "npm", "lodash", "4.17.20")

    # Assert
    assert result.outcome == "resolved"
    assert result.affected is True
    assert result.lowest_fixed_version == "4.17.21"


def test_github_skips_another_package_and_a_withdrawn_advisory():
    """Use the GitHub record that names the package, not the first array item."""

    # Arrange
    def handler(request: httpx.Request) -> httpx.Response:
        """Return a withdrawn advisory, a different package, then lodash."""
        if request.url.host != "api.github.com":
            return httpx.Response(404)
        return httpx.Response(
            200,
            json=[
                {
                    "ghsa_id": "GHSA-withdrawn",
                    "withdrawn_at": "2024-01-01T00:00:00Z",
                    "vulnerabilities": [
                        {
                            "package": {"ecosystem": "npm", "name": "lodash"},
                            "first_patched_version": "9.9.9",
                            "vulnerable_version_range": "< 9.9.9",
                        }
                    ],
                },
                {
                    "ghsa_id": "GHSA-other",
                    "vulnerabilities": [
                        {
                            "package": {"ecosystem": "npm", "name": "left-pad"},
                            "first_patched_version": "1.0.0",
                            "vulnerable_version_range": "< 1.0.0",
                        }
                    ],
                },
                {
                    "ghsa_id": "GHSA-lodash",
                    "html_url": "https://github.com/advisories/GHSA-lodash",
                    "vulnerabilities": [
                        {
                            "package": {"ecosystem": "npm", "name": "lodash"},
                            "vulnerable_version_range": "< 4.17.21",
                            "patched_versions": ["4.17.21"],
                        }
                    ],
                },
            ],
        )

    http, client = _client(handler)

    # Act
    with http:
        result = client.lookup(FINDING, "npm", "lodash", "4.17.20")

    # Assert
    assert result.outcome == "resolved"
    assert result.lowest_fixed_version == "4.17.21"
    assert result.sources == ["github:CVE-2021-23337"]


def test_osv_package_mismatch_can_use_the_github_record():
    """Continue to GitHub when OSV names a different package."""

    # Arrange
    def handler(request: httpx.Request) -> httpx.Response:
        """Serve an unrelated OSV record and a matching GitHub advisory."""
        if request.url.host == "api.osv.dev":
            return httpx.Response(
                200,
                json={
                    "id": "CVE-2021-23337",
                    "affected": [
                        {"package": {"ecosystem": "npm", "name": "lodash-es"}}
                    ],
                },
            )
        if request.url.host == "api.github.com":
            return httpx.Response(
                200,
                json=[
                    {
                        "ghsa_id": "GHSA-lodash",
                        "vulnerabilities": [
                            {
                                "package": {
                                    "ecosystem": "maven",
                                    "name": "org.apache.commons:commons-text",
                                },
                                "vulnerable_version_range": "< 1.10.0",
                                "first_patched_version": {"identifier": "1.10.0"},
                            }
                        ],
                    }
                ],
            )
        return httpx.Response(404)

    http, client = _client(handler)

    # Act
    with http:
        result = client.lookup(FINDING, "maven", "commons-text", "1.9")

    # Assert
    assert result.outcome == "resolved"
    assert result.lowest_fixed_version == "1.10.0"
    assert result.sources[-1] == "github:CVE-2021-23337"


def test_osv_record_for_another_package_needs_a_person():
    """Osv record for another package needs a person."""
    # Arrange
    record = {
        "id": "GHSA-other",
        "aliases": ["CVE-2021-23337"],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash-es"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                    }
                ],
            }
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        """Serve an advisory for a different package to test mismatch safety."""
        if request.url.path.endswith("/CVE-2021-23337"):
            return httpx.Response(200, json=record)
        return httpx.Response(200, json={})

    http, client = _client(handler)

    # Act
    with http:
        result = client.lookup(FINDING, "npm", "lodash", "4.17.20")

    # Assert
    assert result.outcome == PACKAGE_MISMATCH
    assert result.affected is None


def test_nvd_ignores_fixes_for_other_products():
    """Nvd ignores fixes for other products."""
    # Arrange
    nvd = {
        "vulnerabilities": [
            {
                "cve": {
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:acme:other_app:*:*:*:*:*:*:*:*",
                                            "versionEndExcluding": "9.0.0",
                                        },
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*",
                                            "versionEndExcluding": "4.17.21",
                                        },
                                    ]
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        """Serve NVD products after the higher-priority advisory sources miss."""
        if request.url.host == "services.nvd.nist.gov":
            return httpx.Response(200, json=nvd)
        if request.url.host == "api.github.com":
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    http, client = _client(handler)

    # Act
    with http:
        result = client.lookup(FINDING, "npm", "lodash", "4.17.20")

    # Assert
    assert result.fixed_versions == ["4.17.21"]
    assert result.lowest_fixed_version == "4.17.21"
    assert result.affected is True


def test_first_unaffected_skips_a_fix_inside_another_range():
    """First unaffected skips a fix inside another range."""
    # Arrange
    entry = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [
                    {"introduced": "0"},
                    {"fixed": "1.5.0"},
                    {"introduced": "1.5.0"},
                    {"fixed": "1.6.0"},
                ],
            }
        ]
    }

    # Act
    chosen = first_unaffected(
        "1.2.0",
        ["1.5.0", "1.6.0"],
        lambda value: osv_version_affected(value, entry) is True,
    )

    # Assert
    assert chosen == "1.6.0"


def test_major_upgrade_detection():
    """Major upgrade detection."""
    # Arrange
    cases = [
        ("4.17.20", "4.17.21"),
        ("1.9.0", "2.0.0"),
        ("0.2.3", "0.3.0"),
        ("0.2.3", "0.2.4"),
    ]

    # Act
    results = [is_major_upgrade(installed, target) for installed, target in cases]

    # Assert
    assert results == [False, True, True, False]
