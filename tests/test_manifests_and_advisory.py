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

    # Act / Assert
    with pytest.raises(PermissionError, match="Unreadable product directory"):
        iter_files(tmp_path)


def test_normalize_dependency_finding():
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

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http).fetch("group/project")

    assert fetched.ok is True
    assert len(calls) == 2


def test_project_report_findings_do_not_require_a_successful_pipeline():
    """Retrieve persistent findings independently of successful pipelines."""
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

    with httpx.Client(transport=_gitlab_transport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http).fetch("group/project")

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

    def handler(request: httpx.Request) -> httpx.Response:
        """Inject the parametrized report connection for shape validation."""
        return httpx.Response(
            200, json={"data": {"project": {"vulnerabilities": connection}}}
        )

    with httpx.Client(transport=_gitlab_transport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http).fetch("group/project")

    assert fetched.ok is expected_ok
    assert fetched.findings == []


def test_report_findings_limit_marks_results_truncated():
    """Expose truncation when the finding cap stops a multi-page report."""

    def handler(request: httpx.Request) -> httpx.Response:
        """Serve a page indicating additional findings remain unfetched."""
        return httpx.Response(
            200, json=_vulnerability_page("gid://gitlab/Ci::Pipeline/1", True)
        )

    with httpx.Client(transport=_gitlab_transport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http, max_findings=1).fetch(
            "group/project"
        )

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

    def handler(request: httpx.Request) -> httpx.Response:
        """Inject invalid main metadata before any finding query is allowed."""
        body = json.loads(request.content.decode())
        assert "securityTrackedRefs(" in body["query"]
        return httpx.Response(
            200, json={"data": {"project": {"securityTrackedRefs": connection}}}
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http).fetch("group/project")

    assert fetched.ok is False
    assert fetched.findings == []


def test_main_tracked_ref_lookup_paginates():
    """Resolve main on a later page before querying filtered findings."""
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

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        fetched = GitLabClient("glpat-test", http=http).fetch("group/project")

    assert fetched.ok is True
    assert cursors == [None, "next"]


def test_osv_lookup_marks_version_affected():
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
    # Arrange
    outside = tmp_path.parent / "outside-package.json"

    # Act / Assert
    with pytest.raises(ValueError, match="outside the repository"):
        update_npm_spec(tmp_path, str(outside), "lodash", "1.2.3")


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


@pytest.mark.parametrize(
    "payload", [None, [], {"errors": [None]}, {"data": {"project": []}}]
)
def test_malformed_gitlab_payload_returns_error(payload):
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
