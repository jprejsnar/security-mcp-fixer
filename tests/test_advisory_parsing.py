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
