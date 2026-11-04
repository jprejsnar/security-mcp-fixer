"""Check retrieval filters, advisory evidence, local edits, and HTTP ownership."""

import json

import httpx
import pytest

from gitlab_security_mcp.advisory import AdvisoryClient
from gitlab_security_mcp.gitlab_client import GitLabClient, normalize_finding
from gitlab_security_mcp.manifests import (
    iter_files,
    locate_package,
    update_csproj_version,
    update_gradle_version,
    update_npm_spec,
    update_pom_version,
)
from gitlab_security_mcp.remediate import plan_remediation

OSV = {
    "id": "GHSA-test",
    "aliases": ["CVE-2021-23337"],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                }
            ],
        }
    ],
    "references": [{"url": "https://example.test/advisory"}],
}


@pytest.mark.parametrize("mode", ["resolved", "missing", "unavailable"])
def test_advisory_sites_include_attempts_but_not_unused_providers(mode):
    """Report sites used even when providers return no record or fail."""
    # Arrange
    visited = set()

    def handler(request):
        """Supply advisory data or a deterministic no-record/service failure."""
        visited.add(f"{request.url.scheme}://{request.url.host}")
        if mode == "resolved" and request.url.host == "api.osv.dev":
            return httpx.Response(200, json=OSV)
        return httpx.Response(404 if mode == "missing" else 503)

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        with AdvisoryClient(http=http) as client:
            result = client.lookup(
                {"identifiers": ["CVE-2021-23337"]}, "npm", "lodash", "4.17.20"
            )
            cached = client.lookup(
                {"identifiers": ["CVE-2021-23337"]}, "npm", "lodash", "4.17.20"
            )

    # Assert
    expected = (
        ["https://api.osv.dev"]
        if mode == "resolved"
        else [
            "https://api.github.com",
            "https://api.osv.dev",
            "https://services.nvd.nist.gov",
        ]
    )
    assert result.validation_sites == expected
    assert cached.validation_sites == expected
    assert set(result.validation_sites) == visited
    assert (
        result.outcome
        == {
            "resolved": "resolved",
            "missing": "not_found",
            "unavailable": "lookup_failed",
        }[mode]
    )


def test_gitlab_fetch_preserves_fuzzing_payloads_and_response_bodies():
    """Retain scanner HTTP evidence through streamed GraphQL retrieval."""
    # Arrange
    scanner = {
        "summary": "Unexpected response for mutated offset",
        "request": {
            "method": "POST",
            "url": "https://example.invalid/queues?offset=-7473742310360238467",
            "body": '{"queue":"test"}',
            "headers": [{"name": "Authorization", "value": "secret-token"}],
        },
        "response": {
            "statusCode": 500,
            "reasonPhrase": "Internal Server Error",
            "body": '{"error":"offset out of range"}',
            "headers": [{"name": "Content-Type", "value": "application/json"}],
        },
        "supportingMessages": [
            {
                "name": "original request",
                "request": {
                    "url": "https://example.invalid/queues?offset=0",
                    "body": "",
                },
                "response": {"statusCode": 200, "body": "[]"},
            }
        ],
    }
    details = [
        {
            "__typename": "VulnerabilityDetailDiff",
            "fieldName": "payload",
            "before": "0",
            "after": "-7473742310360238467",
        }
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        """Return unbuffered findings with full scanner evidence."""
        query = json.loads(request.content)["query"]
        assert "latestSecurityReportFinding" in query
        assert "supportingMessages" in query
        assert "VulnerabilityDetailDiff" in query
        node = {
            "uuid": "fuzzing",
            "reportType": "API_FUZZING",
            "state": "DETECTED",
            "location": {"path": "/queues", "param": "offset", "requestMethod": "POST"},
            "latestSecurityReportFinding": {"evidence": scanner, "details": details},
        }
        body = json.dumps(
            {
                "data": {
                    "project": {
                        "vulnerabilities": {
                            "nodes": [node],
                            "pageInfo": {"hasNextPage": False},
                        }
                    }
                }
            }
        ).encode()
        return httpx.Response(200, content=iter([body[:19], body[19:]]))

    # Act
    with httpx.Client(transport=_gitlab_transport(handler)) as http:
        result = GitLabClient("test-token", http=http).fetch("group/project")

    # Assert
    assert result.ok, result.error
    finding = result.findings[0]
    captured = finding["scannerEvidence"]
    assert captured["request"]["body"] == scanner["request"]["body"]
    assert captured["request"]["url"] == scanner["request"]["url"]
    assert captured["response"]["body"] == scanner["response"]["body"]
    assert captured["response"]["statusCode"] == 500
    assert captured["supportingMessages"] == scanner["supportingMessages"]
    assert captured["request"]["headers"][0]["value"] == "[REDACTED]"
    assert scanner["request"]["headers"][0]["value"] == "secret-token"
    assert finding["scannerDetails"] == details
    assert finding["location"]["param"] == "offset"
    assert finding["location"]["requestMethod"] == "POST"
    assert finding["evidence"] == []


@pytest.mark.parametrize("body", [None, ""])
def test_fuzzing_evidence_distinguishes_missing_and_empty_bodies(body):
    """Keep empty bodies intact rather than treating them as missing evidence."""
    # Arrange
    node = {
        "reportType": "API_FUZZING",
        "latestSecurityReportFinding": {
            "evidence": {"request": {"body": body}, "response": {"body": body}}
        },
    }

    # Act
    finding = normalize_finding(node, None)

    # Assert
    assert finding["scannerEvidence"]["request"]["body"] == body
    assert finding["scannerEvidence"]["response"]["body"] == body
    assert (
        normalize_finding({"latestSecurityReportFinding": None}, None)[
            "scannerEvidence"
        ]
        is None
    )


@pytest.mark.parametrize(
    "name",
    ["AUTHORIZATION", "Cookie", "Set-Cookie", "X-Api-Key", "Proxy-Authorization"],
)
def test_fuzzing_evidence_redacts_headers_in_supporting_exchanges(name):
    """Mask authentication headers in primary and supporting HTTP exchanges."""
    # Arrange
    exchange = {
        "body": "preserve this payload",
        "headers": [{"name": name, "value": "secret"}],
    }
    scanner = {
        "request": exchange,
        "response": exchange,
        "supportingMessages": [{"request": exchange, "response": exchange}],
    }

    # Act
    finding = normalize_finding(
        {"latestSecurityReportFinding": {"evidence": scanner}}, None
    )

    # Assert
    captured = finding["scannerEvidence"]
    for message in [captured, *captured["supportingMessages"]]:
        for kind in ("request", "response"):
            assert message[kind]["headers"][0]["value"] == "[REDACTED]"
            assert message[kind]["body"] == "preserve this payload"
    assert exchange["headers"][0]["value"] == "secret"


@pytest.mark.parametrize(
    "package, installed", [("minimatch", "11.0.0"), ("glob", "14.0.1")]
)
def test_nested_pnpm_dependency_retains_component_paths(tmp_path, package, installed):
    """Nested pnpm dependency retains component paths."""
    # Arrange
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text('{"name":"frontend"}', encoding="utf-8")
    (frontend / "pnpm-lock.yaml").write_text(
        f"lockfileVersion: '9.0'\npackages:\n  {package}@1.0.0: {{}}\n  {package}@{installed}: {{}}\n",
        encoding="utf-8",
    )
    (tmp_path / "Backend.csproj").write_text("<Project />", encoding="utf-8")

    # Act
    hit, truncated = locate_package(tmp_path, package, installed)

    # Assert
    assert not truncated
    assert hit is not None
    assert hit.version == installed
    assert hit.manager == "pnpm"
    assert hit.manifest == "frontend/package.json"
    assert hit.lockfile == "frontend/pnpm-lock.yaml"
    assert hit.direct is False


@pytest.mark.parametrize(
    "package, installed, target",
    [("minimatch", "11.0.0", "11.0.1"), ("glob", "14.0.1", "14.0.2")],
)
def test_nested_pnpm_plan_applies_only_in_frontend(
    tmp_path, package, installed, target
):
    """Nested pnpm plan applies only in frontend."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.commands import CommandResult
    from gitlab_security_mcp.remediate import apply_plan

    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text('{"name":"frontend"}', encoding="utf-8")
    (frontend / "pnpm-lock.yaml").write_text(
        f"packages:\n  {package}@{installed}: {{}}\n", encoding="utf-8"
    )
    hit, _truncated = locate_package(tmp_path, package, installed)
    plan, reason = plan_remediation(tmp_path, {}, hit, target)
    assert plan is not None, reason
    runner = Mock()
    runner.run.return_value = CommandResult(["pnpm"], 0, "", "", 0, False, "", "")

    # Act
    result = apply_plan(tmp_path, plan, runner, lambda name: name)

    # Assert
    assert result["status"] == "APPLIED"
    assert plan.files == ["frontend/package.json", "frontend/pnpm-lock.yaml"]
    assert runner.run.call_args.kwargs["cwd"] == frontend.resolve()
    assert runner.run.call_args.args[0] == [
        "pnpm",
        "install",
        "--lockfile-only",
        "--ignore-scripts",
    ]
    data = json.loads((frontend / "package.json").read_text(encoding="utf-8"))
    assert data["pnpm"]["overrides"][package] == target
    assert not (tmp_path / "package.json").exists()


@pytest.mark.parametrize("ecosystem", ["npm", "NuGet", "Maven"])
def test_package_plans_require_version_specific_qualifiers(ecosystem):
    """Attach compatibility, approval, and test obligations to package fixes."""
    # Arrange
    from gitlab_security_mcp.remediate import Plan

    plan = Plan(
        "manifest_bump", 2, ecosystem, "example", "1.0.0", "1.0.1", [], None, "Patch"
    )

    # Act
    qualifiers = plan.as_dict()["qualifiers"]

    # Assert
    assert qualifiers["status"] == "REQUIRED"
    assert qualifiers["package"] == "example"
    assert qualifiers["target"] == "1.0.1"
    assert len(qualifiers["requirements"]) == 4


@pytest.mark.parametrize(
    "manager, lockfile, contents",
    [
        (
            "npm",
            "package-lock.json",
            '{"packages":{"node_modules/example":{"version":"1.0.0"}}}',
        ),
        ("yarn", "yarn.lock", 'example@^1.0.0:\n  version "1.0.0"\n'),
        ("pnpm", "pnpm-lock.yaml", "packages:\n  example@1.0.0: {}\n"),
    ],
)
def test_nested_node_lockfile_uses_its_own_manager(
    tmp_path, manager, lockfile, contents
):
    """Nested node lockfile uses its own manager."""
    # Arrange
    (tmp_path / "package.json").write_text(
        '{"packageManager":"npm@10.0.0"}', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text(
        json.dumps({"packageManager": f"{manager}@10.0.0"}), encoding="utf-8"
    )
    (frontend / lockfile).write_text(contents, encoding="utf-8")

    # Act
    hit, _truncated = locate_package(tmp_path, "example", "1.0.0")

    # Assert
    assert hit is not None
    assert hit.manager == manager
    assert hit.version == "1.0.0"
    assert hit.lockfile == f"frontend/{lockfile}"
    assert hit.manifest == "frontend/package.json"


def test_workspace_dependency_keeps_child_manifest_and_shared_lockfile(tmp_path):
    """Workspace dependency keeps child manifest and shared lockfile."""
    # Arrange
    (tmp_path / "package.json").write_text(
        '{"workspaces":["frontend"]}', encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text(
        '{"packages":{"node_modules/example":{"version":"1.0.0"}}}', encoding="utf-8"
    )
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text(
        '{"dependencies":{"example":"^1.0.0"}}', encoding="utf-8"
    )

    # Act
    hit, _truncated = locate_package(tmp_path, "example", "1.0.0")

    # Assert
    assert hit is not None
    assert hit.direct is True
    assert hit.manifest == "frontend/package.json"
    assert hit.lockfile == "package-lock.json"
    assert hit.version == "1.0.0"


def test_nested_pnpm_workspace_override_preserves_existing_configuration(tmp_path):
    """Nested pnpm workspace override preserves existing configuration."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.commands import CommandResult
    from gitlab_security_mcp.remediate import apply_plan

    frontend = tmp_path / "frontend"
    frontend.mkdir()
    manifest = frontend / "package.json"
    manifest.write_text('{"name":"frontend"}\n', encoding="utf-8")
    original = manifest.read_bytes()
    workspace = frontend / "pnpm-workspace.yaml"
    workspace.write_text(
        'packages:\n  - .\n\n# Corporate pins\noverrides:\n  minimatch: "11.0.0"\n  "glob@10>minimatch": 9.0.9\n',
        encoding="utf-8",
    )
    (frontend / "pnpm-lock.yaml").write_text(
        "packages:\n  minimatch@11.0.0: {}\n", encoding="utf-8"
    )
    hit, _truncated = locate_package(tmp_path, "minimatch", "11.0.0")
    plan, reason = plan_remediation(tmp_path, {}, hit, "11.0.1")
    assert plan is not None, reason
    runner = Mock()
    runner.run.return_value = CommandResult(["pnpm"], 0, "", "", 0, False, "", "")

    # Act
    result = apply_plan(tmp_path, plan, runner, lambda name: name)

    # Assert
    assert result["status"] == "APPLIED"
    assert plan.files == ["frontend/pnpm-workspace.yaml", "frontend/pnpm-lock.yaml"]
    text = workspace.read_text(encoding="utf-8")
    assert "# Corporate pins" in text
    assert 'minimatch: "11.0.1"' in text
    assert '"glob@10>minimatch": 9.0.9' in text
    assert manifest.read_bytes() == original
    assert runner.run.call_args.kwargs["cwd"] == frontend.resolve()


def test_unreadable_walk_cannot_prove_package_absence(tmp_path, monkeypatch):
    """Propagate permission failures rather than returning an empty checkout."""
    # Arrange
    from gitlab_security_mcp import manifests

    failure = PermissionError("Unreadable product directory")

    def walk(root, **kwargs):
        """Emulate os.walk's default suppression unless onerror is supplied."""
        callback = kwargs.get("onerror")
        if callback is not None:
            callback(failure)
        yield str(root), [], []

    monkeypatch.setattr(manifests.os, "walk", walk)

    # Act
    with pytest.raises(PermissionError, match="Unreadable product directory") as raised:
        iter_files(tmp_path)

    # Assert
    assert "Unreadable product directory" in str(raised.value)


def test_normalize_dependency_finding():
    """Normalize dependency finding."""
    # Arrange
    node = {
        "uuid": "abc",
        "title": "Prototype pollution in lodash",
        "severity": "HIGH",
        "state": "DETECTED",
        "reportType": "DEPENDENCY_SCANNING",
        "solution": "Upgrade to version 4.17.21.",
        "falsePositive": False,
        "scanner": {"name": "Gemnasium"},
        "identifiers": [
            {
                "externalType": "cve",
                "externalId": "CVE-2021-23337",
                "name": "CVE-2021-23337",
            }
        ],
        "links": [],
        "location": {
            "file": "package-lock.json",
            "dependency": {"package": {"name": "lodash"}, "version": "4.17.20"},
        },
    }

    # Act
    finding = normalize_finding(node, {"sha": "deadbeef"})

    # Assert
    assert finding["id"] == "abc"
    assert finding["category"] == "dependency_scanning"
    assert finding["component"] == "lodash"
    assert finding["installedVersion"] == "4.17.20"
    assert finding["fixedVersions"] == ["4.17.21"]
    assert finding["identifiers"] == ["CVE-2021-23337"]


def _gitlab_transport(handler):
    """Supply a tracked main branch before delegating vulnerability queries."""

    def route(request: httpx.Request) -> httpx.Response:
        """Route tracked-ref queries locally without counting finding requests."""
        body = json.loads(request.content.decode())
        if "securityTrackedRefs(" in body["query"]:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "project": {
                            "securityTrackedRefs": {
                                "nodes": [
                                    {
                                        "id": "gid://gitlab/Security::ProjectTrackedContext/2",
                                        "name": "main",
                                        "refType": "BRANCH",
                                    }
                                ],
                                "pageInfo": {"hasNextPage": False},
                            }
                        }
                    }
                },
            )
        return handler(request)

    return httpx.MockTransport(route)


@pytest.mark.parametrize("client_type", [GitLabClient, AdvisoryClient])
def test_falsey_injected_http_client_is_preserved(client_type):
    """Falsey injected http client is preserved."""

    # Arrange
    class FalseyHTTPClient(httpx.Client):
        """Retain normal HTTP behavior while testing falsey injection."""

        def __bool__(self):
            """Require ownership checks to use None rather than truthiness."""
            return False

    with FalseyHTTPClient() as http:
        arguments = {"http": http}
        if client_type is GitLabClient:
            arguments["token"] = "test-token"

        # Act
        client = client_type(**arguments)
        client.close()

        # Assert
        assert client.http is http
        assert not http.is_closed


def test_gitlab_graphql_is_read_only(tmp_path):
    """Gitlab graphql is read only."""
    # Arrange
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Reject mutation text and serve mixed active/dismissed findings."""
        body = json.loads(request.content.decode())
        calls.append(body)
        assert body["query"].lstrip().lower().startswith("query")
        assert "mutation" not in body["query"].lower()
        return httpx.Response(
            200,
            json={
                "data": {
                    "project": {
                        "vulnerabilities": {
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                            "nodes": [
                                {
                                    "uuid": "keep",
                                    "title": "issue in lodash",
                                    "severity": "HIGH",
                                    "state": "DETECTED",
                                    "reportType": "DEPENDENCY_SCANNING",
                                    "solution": None,
                                    "falsePositive": None,
                                    "scanner": {"name": "Gemnasium"},
                                    "identifiers": [],
                                    "links": [],
                                    "location": {
                                        "file": "package.json",
                                        "dependency": {
                                            "package": {"name": "lodash"},
                                            "version": "1.0.0",
                                        },
                                    },
                                },
                                {
                                    "uuid": "drop",
                                    "title": "dismissed",
                                    "severity": "LOW",
                                    "state": "DISMISSED",
                                    "reportType": "DEPENDENCY_SCANNING",
                                    "solution": None,
                                    "scanner": {"name": "Gemnasium"},
                                    "identifiers": [],
                                    "links": [],
                                    "location": {"file": "package.json"},
                                },
                            ],
                        }
                    }
                }
            },
        )

    with httpx.Client(transport=_gitlab_transport(handler)) as http:
        client = GitLabClient("glpat-test", http=http)

        # Act
        fetched = client.fetch("group/project")

    # Assert
    assert fetched.ok is True
    assert [item["id"] for item in fetched.findings] == ["keep"]
    assert fetched.excluded == {"dismissed": 1}
    assert len(calls) == 1


def test_report_filters_match_patient_web_ui():
    """Match UI status, tracked main, and still-detected activity filters."""
    # Arrange
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Verify exact filters after returning main's tracked-ref id."""
        body = json.loads(request.content.decode())
        calls.append(body)
        if "securityTrackedRefs(" in body["query"]:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "project": {
                            "securityTrackedRefs": {
                                "nodes": [
                                    {
                                        "id": "gid://gitlab/Security::ProjectTrackedContext/1",
                                        "name": "dev",
                                        "refType": "BRANCH",
                                    },
                                    {
                                        "id": "gid://gitlab/Security::ProjectTrackedContext/2",
                                        "name": "main",
                                        "refType": "BRANCH",
                                    },
                                ],
                                "pageInfo": {"hasNextPage": False},
                            }
                        }
                    }
                },
            )
        assert "state: [DETECTED, CONFIRMED]" in body["query"]
        assert "hasResolution: false" in body["query"]
        assert "trackedRefIds: $trackedRefIds" in body["query"]
        assert body["variables"]["trackedRefIds"] == [
            "gid://gitlab/Security::ProjectTrackedContext/2"
        ]
        return httpx.Response(
            200,
            json={
                "data": {
                    "project": {
                        "vulnerabilities": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": False},
                        }
                    }
                }
            },
        )

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http).fetch("group/project")

    # Assert
    assert fetched.ok is True
    assert len(calls) == 2


def test_project_report_findings_do_not_require_a_successful_pipeline():
    """Retrieve persistent findings independently of successful pipelines."""
    # Arrange
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Serve report findings while rejecting the obsolete pipeline path."""
        body = json.loads(request.content.decode())
        calls.append(body)
        assert "vulnerabilities(" in body["query"]
        assert "securityReportFindings" not in body["query"]
        return httpx.Response(
            200,
            json={
                "data": {
                    "project": {
                        "vulnerabilities": {
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                            "nodes": [
                                {
                                    "id": "gid://gitlab/Vulnerability/123",
                                    "uuid": "report-finding",
                                    "title": "issue in lodash",
                                    "state": "CONFIRMED",
                                    "reportType": "DEPENDENCY_SCANNING",
                                    "location": {"file": "package-lock.json"},
                                }
                            ],
                        },
                    }
                }
            },
        )

    # Act
    with httpx.Client(transport=_gitlab_transport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http).fetch("group/project")

    # Assert
    assert fetched.ok is True
    assert [finding["id"] for finding in fetched.findings] == ["report-finding"]
    assert fetched.pipeline is None
    assert len(calls) == 1


def _vulnerability_page(pipeline_id: str, has_next: bool) -> dict:
    """Build one paginated finding with per-finding pipeline provenance."""
    return {
        "data": {
            "project": {
                "vulnerabilities": {
                    "pageInfo": {
                        "hasNextPage": has_next,
                        "endCursor": "next" if has_next else None,
                    },
                    "nodes": [
                        {
                            "uuid": pipeline_id,
                            "state": "DETECTED",
                            "latestDetectedPipeline": {
                                "id": pipeline_id,
                                "sha": "abc",
                                "ref": "main",
                                "status": "SUCCESS",
                            },
                        }
                    ],
                }
            }
        }
    }


def test_report_pagination_preserves_each_findings_pipeline():
    """Report pagination preserves each findings pipeline."""
    # Arrange
    pages = iter(
        [
            _vulnerability_page("gid://gitlab/Ci::Pipeline/1", True),
            _vulnerability_page("gid://gitlab/Ci::Pipeline/2", False),
        ]
    )
    cursors = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Serve successive pages and capture cursor/filter propagation."""
        body = json.loads(request.content.decode())
        assert body["variables"]["trackedRefIds"] == [
            "gid://gitlab/Security::ProjectTrackedContext/2"
        ]
        assert "state: [DETECTED, CONFIRMED]" in body["query"]
        assert "hasResolution: false" in body["query"]
        cursors.append(body["variables"]["after"])
        return httpx.Response(200, json=next(pages))

    with httpx.Client(transport=_gitlab_transport(handler)) as http:
        client = GitLabClient("glpat-test", http=http)

        # Act
        fetched = client.fetch("group/project")

    # Assert
    assert fetched.ok is True
    assert cursors == [None, "next"]
    assert [finding["pipeline"]["id"] for finding in fetched.findings] == [
        "gid://gitlab/Ci::Pipeline/1",
        "gid://gitlab/Ci::Pipeline/2",
    ]
    assert fetched.pipeline is None


@pytest.mark.parametrize(
    "connection, expected_ok",
    [
        (None, False),
        ({"nodes": [], "pageInfo": {"hasNextPage": False}}, True),
        ({"nodes": [], "pageInfo": {"hasNextPage": True}}, False),
    ],
)
def test_report_empty_unreadable_or_invalid_pagination(connection, expected_ok):
    """Separate a valid empty connection from unreadable report data."""

    # Arrange
    def handler(request: httpx.Request) -> httpx.Response:
        """Inject the parametrized report connection for shape validation."""
        return httpx.Response(
            200, json={"data": {"project": {"vulnerabilities": connection}}}
        )

    # Act
    with httpx.Client(transport=_gitlab_transport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http).fetch("group/project")

    # Assert
    assert fetched.ok is expected_ok
    assert fetched.findings == []


def test_report_findings_limit_marks_results_truncated():
    """Expose truncation when the finding cap stops a multi-page report."""

    # Arrange
    def handler(request: httpx.Request) -> httpx.Response:
        """Serve a page indicating additional findings remain unfetched."""
        return httpx.Response(
            200, json=_vulnerability_page("gid://gitlab/Ci::Pipeline/1", True)
        )

    # Act
    with httpx.Client(transport=_gitlab_transport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http, max_findings=1).fetch(
            "group/project"
        )

    # Assert
    assert fetched.ok is True
    assert len(fetched.findings) == 1
    assert fetched.truncated is True


@pytest.mark.parametrize(
    "connection",
    [
        None,
        {"nodes": [], "pageInfo": {"hasNextPage": False}},
        {
            "nodes": [{"id": "tag-main", "name": "main", "refType": "TAG"}],
            "pageInfo": {"hasNextPage": False},
        },
        {"nodes": [], "pageInfo": {"hasNextPage": True}},
    ],
)
def test_main_tracked_ref_missing_or_unreadable_fails_closed(connection):
    """Refuse unfiltered retrieval when tracked main cannot be resolved."""

    # Arrange
    def handler(request: httpx.Request) -> httpx.Response:
        """Inject invalid main metadata before any finding query is allowed."""
        body = json.loads(request.content.decode())
        assert "securityTrackedRefs(" in body["query"]
        return httpx.Response(
            200, json={"data": {"project": {"securityTrackedRefs": connection}}}
        )

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http).fetch("group/project")

    # Assert
    assert fetched.ok is False
    assert fetched.findings == []


def test_main_tracked_ref_lookup_paginates():
    """Resolve main on a later page before querying filtered findings."""
    # Arrange
    cursors = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Return main only after an advancing tracked-ref cursor."""
        body = json.loads(request.content.decode())
        if "securityTrackedRefs(" in body["query"]:
            after = body["variables"]["after"]
            cursors.append(after)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "project": {
                            "securityTrackedRefs": {
                                "nodes": []
                                if after is None
                                else [
                                    {
                                        "id": "main-id",
                                        "name": "main",
                                        "refType": "BRANCH",
                                    }
                                ],
                                "pageInfo": {
                                    "hasNextPage": after is None,
                                    "endCursor": "next" if after is None else None,
                                },
                            }
                        }
                    }
                },
            )
        assert body["variables"]["trackedRefIds"] == ["main-id"]
        return httpx.Response(
            200,
            json={
                "data": {
                    "project": {
                        "vulnerabilities": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": False},
                        }
                    }
                }
            },
        )

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http).fetch("group/project")

    # Assert
    assert fetched.ok is True
    assert cursors == [None, "next"]


def test_osv_lookup_marks_version_affected():
    """Osv lookup marks version affected."""

    # Arrange
    def handler(request: httpx.Request) -> httpx.Response:
        """Serve matching OSV ranges for a known vulnerable fixture version."""
        if request.url.path.endswith("/CVE-2021-23337"):
            return httpx.Response(200, json=OSV)
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = AdvisoryClient(http=http)

        # Act
        result = client.lookup(
            {"identifiers": ["CVE-2021-23337"], "title": "lodash"},
            "npm",
            "lodash",
            "4.17.20",
        )

    # Assert
    assert result.outcome == "resolved"
    assert result.affected is True
    assert result.lowest_fixed_version == "4.17.21"


def test_maven_pom_gradle_and_nuget_edits(tmp_path):
    """Maven pom gradle and nuget edits."""
    # Arrange
    pom = tmp_path / "pom.xml"
    pom.write_text(
        """
<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>other</artifactId>
      <version>1.0.0</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>${commons.version}</version>
    </dependency>
  </dependencies>
  <properties>
    <commons.version>1.9</commons.version>
  </properties>
</project>
""".strip(),
        encoding="utf-8",
    )

    # Act
    pom_updated = update_pom_version(
        tmp_path, "pom.xml", "org.apache.commons:commons-text", "1.10.0"
    )

    # Assert
    assert pom_updated is True
    text = pom.read_text(encoding="utf-8")
    assert "<commons.version>1.10.0</commons.version>" in text
    assert "<version>1.0.0</version>" in text

    # Arrange
    gradle = tmp_path / "build.gradle"
    gradle.write_text(
        'implementation "org.apache.commons:commons-text:1.9"\n', encoding="utf-8"
    )

    # Act
    gradle_updated = update_gradle_version(
        tmp_path, "build.gradle", "org.apache.commons:commons-text", "1.10.0"
    )

    # Assert
    assert gradle_updated is True
    assert "commons-text:1.10.0" in gradle.read_text(encoding="utf-8")

    # Arrange
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>',
        encoding="utf-8",
    )

    # Act
    project_updated = update_csproj_version(
        tmp_path, "App.csproj", "Newtonsoft.Json", "13.0.3"
    )

    # Assert
    assert project_updated is True
    assert 'Version="13.0.3"' in project.read_text(encoding="utf-8")


def test_plan_picks_lockfile_when_range_already_allows(tmp_path):
    """Plan picks lockfile when range already allows."""
    # Arrange
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.20"}}}),
        encoding="utf-8",
    )

    # Act
    hit, _truncated = locate_package(tmp_path, "lodash", "4.17.20")
    plan, _reason = plan_remediation(
        tmp_path, {"installedVersion": "4.17.20"}, hit, "4.17.21"
    )

    # Assert
    assert plan is not None
    assert plan.strategy == "lockfile_only"
    assert plan.score == 1


@pytest.mark.parametrize("directory", ["node_modules", ".pnpm-store", ".angular"])
def test_dependency_directories_are_not_scanned(tmp_path, directory):
    """Dependency directories are not scanned."""
    # Arrange
    (tmp_path / "package.json").write_text("{}\n", encoding="utf-8")
    nested = tmp_path / directory / "left-pad"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"name": "left-pad"}\n', encoding="utf-8")

    # Act
    files, truncated = iter_files(tmp_path)

    # Assert
    assert truncated is False
    assert all(directory not in path.parts for path in files)


def test_manifest_write_refuses_paths_outside_the_repo(tmp_path):
    """Manifest write refuses paths outside the repo."""
    # Arrange
    outside = tmp_path.parent / "outside-package.json"

    # Act
    with pytest.raises(ValueError, match="outside the repository") as raised:
        update_npm_spec(tmp_path, str(outside), "lodash", "1.2.3")

    # Assert
    assert "outside the repository" in str(raised.value)


@pytest.mark.parametrize(
    "connection",
    [
        {},
        {"nodes": None, "pageInfo": {"hasNextPage": False}},
        {"nodes": [], "pageInfo": None},
        {"nodes": {}, "pageInfo": {"hasNextPage": False}},
        {"nodes": [None], "pageInfo": {"hasNextPage": False}},
        {"nodes": [{"state": 42}], "pageInfo": {"hasNextPage": False}},
        {"nodes": [{"identifiers": [None]}], "pageInfo": {"hasNextPage": False}},
    ],
)
def test_malformed_gitlab_connection_fails_closed(connection):
    """Malformed gitlab connection fails closed."""

    # Arrange
    def handler(request):
        """Inject malformed node or page shapes without making HTTP requests."""
        return httpx.Response(
            200, json={"data": {"project": {"vulnerabilities": connection}}}
        )

    with httpx.Client(transport=_gitlab_transport(handler)) as http:
        client = GitLabClient("test-token", http=http)

        # Act
        result = client.fetch("group/project")

    # Assert
    assert not result.ok
    assert result.findings == []
    assert result.error


@pytest.mark.parametrize("project_id", ["group/project", "123"])
def test_gitlab_reads_streamed_success_responses(project_id):
    """Read real response streams before decoding project and findings JSON."""
    # Arrange
    requests = []
    responses = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Serve split JSON bodies without preloading response content."""
        requests.append(request)
        if request.method == "GET":
            payload = {"path_with_namespace": "group/project"}
        else:
            query = json.loads(request.content)["query"]
            if "securityTrackedRefs(" in query:
                connection = "securityTrackedRefs"
                nodes = [{"id": "tracked-main", "name": "main", "refType": "BRANCH"}]
            else:
                connection = "vulnerabilities"
                nodes = [{"uuid": "streamed-finding", "state": "DETECTED"}]
            payload = {
                "data": {
                    "project": {
                        connection: {
                            "nodes": nodes,
                            "pageInfo": {"hasNextPage": False},
                        }
                    }
                }
            }
        body = json.dumps(payload).encode()
        response = httpx.Response(200, content=iter([body[:17], body[17:]]))
        responses.append(response)
        return response

    # Act
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        result = GitLabClient("test-token", http=http).fetch(project_id)

    # Assert
    assert result.ok, result.error
    assert result.project_path == "group/project"
    assert [finding["id"] for finding in result.findings] == ["streamed-finding"]
    assert len(requests) == (3 if project_id == "123" else 2)
    assert all(response.is_closed for response in responses)


def test_gitlab_http_error_stops_reading_after_the_excerpt():
    """Keep only the first part of a GitLab error body."""
    # Arrange
    read_chunks = 0

    def chunks():
        """Yield the error page one small piece at a time."""
        nonlocal read_chunks
        for _ in range(40):
            read_chunks += 1
            yield b"A" * 100
        read_chunks += 1
        yield b"UNIQUE-TAIL"

    def handler(_request: httpx.Request) -> httpx.Response:
        """Fail every GitLab call with a long streamed error page."""
        return httpx.Response(500, content=chunks())

    client = GitLabClient(
        "glpat-test", http=httpx.Client(transport=httpx.MockTransport(handler))
    )

    # Act
    result = client.fetch("group/project")

    # Assert
    assert result.ok is False
    assert "500" in (result.error or "")
    assert "UNIQUE-TAIL" not in (result.error or "")
    assert read_chunks < 40


@pytest.mark.parametrize(
    "payload", [None, [], {"errors": [None]}, {"data": {"project": []}}]
)
def test_malformed_gitlab_payload_returns_error(payload):
    """Malformed gitlab payload returns error."""
    # Arrange
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    ) as http:
        client = GitLabClient("test-token", http=http)

        # Act
        result = client.fetch("group/project")

    # Assert
    assert not result.ok
    assert result.error


@pytest.mark.parametrize(
    "content",
    [b"not-json", b"null", b"42", b"[null]", b'{"affected":[null],"id":"CVE-TEST"}'],
)
def test_malformed_advisory_returns_lookup_failure(content):
    """Malformed advisory returns lookup failure."""
    # Arrange
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=content)
        )
    ) as http:
        client = AdvisoryClient(http=http)

        # Act
        result = client.lookup({"identifiers": ["CVE-TEST"]}, "npm", "lodash", "1.0.0")

    # Assert
    assert result.outcome == "lookup_failed"
    assert result.affected is None
    assert result.lowest_fixed_version is None
    assert result.errors


@pytest.mark.parametrize("client_type", [GitLabClient, AdvisoryClient])
def test_operation_after_close_returns_failure(client_type):
    """Operation after close returns failure."""
    # Arrange
    with httpx.Client() as http:
        client = (
            GitLabClient("test-token", http=http)
            if client_type is GitLabClient
            else AdvisoryClient(http=http)
        )
        client.close()

        # Act
        result = (
            client.fetch("group/project")
            if client_type is GitLabClient
            else client.lookup({}, None, None, None)
        )

        # Assert
        assert (
            not result.ok
            if client_type is GitLabClient
            else result.outcome == "lookup_failed"
        )
        assert not http.is_closed


@pytest.mark.parametrize("client_type", [GitLabClient, AdvisoryClient])
def test_close_waits_for_active_client_operation(client_type, monkeypatch):
    """Close waits for active client operation."""
    # Arrange
    import threading

    entered = threading.Event()
    release = threading.Event()
    close_started = threading.Event()
    close_done = threading.Event()
    results = []

    def handler(request):
        """Hold a mock response until the shutdown race is measured."""
        entered.set()
        assert release.wait(5)
        if client_type is GitLabClient:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "project": {
                            "vulnerabilities": {
                                "nodes": [],
                                "pageInfo": {"hasNextPage": False},
                            }
                        }
                    }
                },
            )
        return httpx.Response(404)

    transport = (
        _gitlab_transport(handler)
        if client_type is GitLabClient
        else httpx.MockTransport(handler)
    )
    with httpx.Client(transport=transport) as http:
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: http)
        client = (
            GitLabClient("test-token")
            if client_type is GitLabClient
            else AdvisoryClient()
        )

        def operate():
            """Keep the client operation active on its worker thread."""
            result = (
                client.fetch("group/project")
                if client_type is GitLabClient
                else client.lookup(
                    {"identifiers": ["CVE-TEST"]},
                    None,
                    None,
                    None,
                )
            )
            results.append(result)

        def close():
            """Signal shutdown attempts and completion without busy waiting."""
            close_started.set()
            client.close()
            close_done.set()

        worker = threading.Thread(target=operate)
        closer = threading.Thread(target=close)

        # Act
        worker.start()
        try:
            assert entered.wait(5)
            closer.start()
            assert close_started.wait(5)
            closed_while_active = close_done.wait(0.1)
        finally:
            release.set()
            worker.join(5)
            if closer.ident is not None:
                closer.join(5)

        # Assert
        assert not closed_while_active
        assert not worker.is_alive() and not closer.is_alive()
        assert close_done.is_set()
        assert http.is_closed
        assert len(results) == 1


def test_owned_http_clients_close():
    """Owned http clients close."""
    # Arrange
    gitlab = GitLabClient("glpat-test")
    advisory = AdvisoryClient()

    # Act
    gitlab.close()
    gitlab.close()
    advisory.close()
    advisory.close()

    # Assert
    assert gitlab.http.is_closed is True
    assert advisory.http.is_closed is True
