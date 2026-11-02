import httpx

from gitlab_security_mcp.advisory import PACKAGE_MISMATCH, AdvisoryClient
from gitlab_security_mcp.versions import first_unaffected, is_major_upgrade, osv_version_affected

FINDING = {"identifiers": ["CVE-2021-23337"], "title": "lodash"}


def _client(handler) -> tuple[httpx.Client, AdvisoryClient]:
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return http, AdvisoryClient(http=http)


def test_github_first_patched_version_is_used():
    # Arrange
    def handler(request: httpx.Request) -> httpx.Response:
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


def test_osv_record_for_another_package_needs_a_person():
    # Arrange
    record = {
        "id": "GHSA-other",
        "aliases": ["CVE-2021-23337"],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash-es"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
            }
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
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
    # Arrange
    entry = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [{"introduced": "0"}, {"fixed": "1.5.0"}, {"introduced": "1.5.0"}, {"fixed": "1.6.0"}],
            }
        ]
    }

    # Act
    chosen = first_unaffected("1.2.0", ["1.5.0", "1.6.0"], lambda value: osv_version_affected(value, entry) is True)

    # Assert
    assert chosen == "1.6.0"


def test_major_upgrade_detection():
    # Arrange
    cases = [("4.17.20", "4.17.21"), ("1.9.0", "2.0.0"), ("0.2.3", "0.3.0"), ("0.2.3", "0.2.4")]

    # Act
    results = [is_major_upgrade(installed, target) for installed, target in cases]

    # Assert
    assert results == [False, True, True, False]
