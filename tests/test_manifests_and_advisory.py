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
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        }
    ],
    "references": [{"url": "https://example.test/advisory"}],
}


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
        "identifiers": [{"externalType": "cve", "externalId": "CVE-2021-23337", "name": "CVE-2021-23337"}],
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


def test_gitlab_graphql_is_read_only(tmp_path):
    # Arrange
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        calls.append(body)
        assert body["query"].lstrip().lower().startswith("query")
        assert "mutation" not in body["query"].lower()
        if "rootRef" in body["query"]:
            return httpx.Response(200, json={"data": {"project": {"repository": {"rootRef": "main"}}}})
        return httpx.Response(
            200,
            json={
                "data": {
                    "project": {
                        "pipelines": {
                            "nodes": [
                                {
                                    "id": "gid://gitlab/Ci::Pipeline/1",
                                    "iid": "1",
                                    "sha": "abc",
                                    "ref": "main",
                                    "status": "SUCCESS",
                                    "createdAt": "2026-11-01T00:00:00Z",
                                    "securityReportFindings": {
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
                                                    "dependency": {"package": {"name": "lodash"}, "version": "1.0.0"},
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
                                    },
                                }
                            ]
                        }
                    }
                }
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = GitLabClient("glpat-test", http=http)

        # Act
        fetched = client.fetch("group/project")

    # Assert
    assert fetched.ok is True
    assert [item["id"] for item in fetched.findings] == ["keep"]
    assert fetched.excluded == {"dismissed": 1}
    assert len(calls) == 2


def _pipeline_page(pipeline_id: str, has_next: bool) -> dict:
    return {
        "data": {
            "project": {
                "pipelines": {
                    "nodes": [
                        {
                            "id": pipeline_id,
                            "sha": "abc",
                            "ref": "main",
                            "status": "SUCCESS",
                            "securityReportFindings": {
                                "pageInfo": {"hasNextPage": has_next, "endCursor": "next" if has_next else None},
                                "nodes": [],
                            },
                        }
                    ]
                }
            }
        }
    }


def test_findings_from_two_pipelines_are_not_mixed():
    # Arrange
    pages = iter([_pipeline_page("gid://gitlab/Ci::Pipeline/1", True), _pipeline_page("gid://gitlab/Ci::Pipeline/2", False)])

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        if "rootRef" in body["query"]:
            return httpx.Response(200, json={"data": {"project": {"repository": {"rootRef": "main"}}}})
        return httpx.Response(200, json=next(pages))

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        client = GitLabClient("glpat-test", http=http)

        # Act
        fetched = client.fetch("group/project")

    # Assert
    assert fetched.ok is False
    assert "newer pipeline" in fetched.error


def test_osv_lookup_marks_version_affected():
    # Arrange
    def handler(request: httpx.Request) -> httpx.Response:
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
    pom_updated = update_pom_version(tmp_path, "pom.xml", "org.apache.commons:commons-text", "1.10.0")

    # Assert
    assert pom_updated is True
    text = pom.read_text(encoding="utf-8")
    assert "<commons.version>1.10.0</commons.version>" in text
    assert "<version>1.0.0</version>" in text

    # Arrange
    gradle = tmp_path / "build.gradle"
    gradle.write_text('implementation "org.apache.commons:commons-text:1.9"\n', encoding="utf-8")

    # Act
    gradle_updated = update_gradle_version(tmp_path, "build.gradle", "org.apache.commons:commons-text", "1.10.0")

    # Assert
    assert gradle_updated is True
    assert 'commons-text:1.10.0' in gradle.read_text(encoding="utf-8")

    # Arrange
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>',
        encoding="utf-8",
    )

    # Act
    project_updated = update_csproj_version(tmp_path, "App.csproj", "Newtonsoft.Json", "13.0.3")

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
    plan, _reason = plan_remediation(tmp_path, {"installedVersion": "4.17.20"}, hit, "4.17.21")

    # Assert
    assert plan is not None
    assert plan.strategy == "lockfile_only"
    assert plan.score == 1


def test_dependency_directories_are_not_scanned(tmp_path):
    # Arrange
    (tmp_path / "package.json").write_text("{}\n", encoding="utf-8")
    nested = tmp_path / "node_modules" / "left-pad"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"name": "left-pad"}\n', encoding="utf-8")

    # Act
    files, truncated = iter_files(tmp_path)

    # Assert
    assert truncated is False
    assert all("node_modules" not in path.parts for path in files)


def test_manifest_write_refuses_paths_outside_the_repo(tmp_path):
    # Arrange
    outside = tmp_path.parent / "outside-package.json"

    # Act / Assert
    with pytest.raises(ValueError, match="outside the repository"):
        update_npm_spec(tmp_path, str(outside), "lodash", "1.2.3")


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
