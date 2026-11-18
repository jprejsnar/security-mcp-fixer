"""Verify latest-supported targeting and paid/unknown licensing boundaries."""

from copy import deepcopy
from unittest.mock import Mock

import httpx
import pytest

from gitlab_security_mcp.advisory import AdvisoryLookup
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.package_releases import (
    release_catalog,
    reviewed_selection,
    stable_versions,
)
from gitlab_security_mcp.qualification import reviewed_license_policy
from gitlab_security_mcp.report import render
from tests.conftest import documentation_client, manager_doc_sources


def _support(**changes):
    """Provide explicit fixture support/runtime evidence."""
    return {
        "target": "3.0.0",
        "supported": True,
        "runtime_compatible": True,
        "assessment": "Publisher supports this release on the actual project runtime",
        "sources": ["https://publisher.example/support"],
        "excluded_releases": [],
        **changes,
    }


@pytest.mark.parametrize(
    "ecosystem,package,path,payload",
    [
        (
            "npm",
            "@example/library",
            "/%40example%2Flibrary",
            b'{"name":"@example/library","versions":{"1.0.1":{},"3.0.0":{},'
            b'"4.0.0-beta.1":{},"4.0.0-ci-123":{},"5.0.0":{"deprecated":"unsupported"}}}',
        ),
        (
            "NuGet",
            "Example.Library",
            "/v3-flatcontainer/example.library/index.json",
            b'{"versions":["1.0.1","3.0.0","4.0.0-preview.1","11.0.0-preview.1.26104.118"]}',
        ),
        (
            "Maven",
            "example:library",
            "/maven2/example/library/maven-metadata.xml",
            b"<metadata><groupId>example</groupId><artifactId>library</artifactId>"
            b"<versioning><versions><version>1.0.1</version><version>3.0.0</version>"
            b"<version>4.0.0-rc.1</version></versions></versioning></metadata>",
        ),
    ],
)
def test_catalogs_select_latest_stable_across_major_versions(
    monkeypatch, ecosystem, package, path, payload
):
    """Choose the newest stable release, ignoring deprecated and preview entries."""
    # Arrange
    requests = []

    def respond(request):
        """Serve the public catalog fixture and retain the request."""
        requests.append(request)
        return httpx.Response(200, content=payload)

    client = httpx.Client(transport=httpx.MockTransport(respond))
    monkeypatch.setattr(
        "gitlab_security_mcp.package_releases.httpx.Client", lambda **_: client
    )

    # Act
    catalog = release_catalog(ecosystem, package)
    selected = reviewed_selection(catalog, "1.0.1", _support())

    # Assert
    assert selected["target"] == "3.0.0"
    assert catalog["versions"] == ["3.0.0", "1.0.1"]
    assert requests[0].url.raw_path.decode() == path
    assert client.is_closed


@pytest.mark.parametrize("failure", ["http", "malformed", "coordinate", "oversize"])
def test_registry_failure_never_falls_back_to_an_advisory_floor(monkeypatch, failure):
    """Keep failed or malformed public catalogs out of release selection."""
    # Arrange
    payload = b'{"name":"wrong","versions":{"1.0.1":{}}}'
    if failure == "malformed":
        payload = b"not-json"
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(503 if failure == "http" else 200, content=payload)
        )
    )
    monkeypatch.setattr(
        "gitlab_security_mcp.package_releases.httpx.Client", lambda **_: client
    )
    if failure == "oversize":
        monkeypatch.setattr("gitlab_security_mcp.package_releases.MAX_RELEASE_BYTES", 1)

    # Act
    with pytest.raises((ValueError, httpx.HTTPStatusError)):
        release_catalog("npm", "example")

    # Assert
    assert client.is_closed


def test_supported_runtime_and_paid_exclusions_choose_latest_free_eligible_release():
    """Honor documented support/runtime/fee exclusions without minimizing the bump."""
    # Arrange
    exclusions = [
        {
            "version": version,
            "reason": reason,
            "assessment": assessment,
            "sources": ["https://publisher.example/releases"],
        }
        for version, reason, assessment in [
            (
                "5.0.0",
                "runtime_incompatible",
                "Requires .NET 11; this project uses .NET 10",
            ),
            ("4.0.0", "paid", "Publisher requires a commercial subscription"),
            ("3.0.0", "unsupported", "Publisher ended support for this release"),
        ]
    ]
    catalog = {
        "source": "https://registry.example/releases",
        "versions": ["5.0.0", "4.0.0", "3.0.0", "2.0.0", "1.0.1"],
    }

    # Act
    selected = reviewed_selection(
        catalog, "1.0.1", _support(excluded_releases=exclusions)
    )

    # Assert
    assert selected["target"] == "2.0.0"
    assert selected["paid_releases"] == [exclusions[1]]
    assert (
        reviewed_selection(catalog, "5.0.0", _support(excluded_releases=exclusions))[
            "target"
        ]
        is None
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"supported": None},
        {"runtime_compatible": False},
        {"sources": []},
        {"excluded_releases": [{"version": "2.0.0", "reason": "major_upgrade"}]},
    ],
)
def test_missing_support_or_arbitrary_major_exclusions_are_rejected(changes):
    """Require real support evidence and reject avoiding a version just for its major."""
    # Arrange
    review = _support(**changes)
    # Act
    # Assert
    with pytest.raises(ValueError):
        reviewed_selection(
            {"source": "https://registry.example/releases", "versions": ["2.0.0"]},
            "1.0.1",
            review,
        )


def test_uncomparable_stable_release_never_silently_selects_an_older_version():
    """Report uncomparable stable versions instead of silently choosing older ones."""
    # Arrange
    versions = ["3.0.0.Final", "2.0.0"]
    # Act
    # Assert
    with pytest.raises(ValueError, match="manual version investigation"):
        stable_versions(versions)
    assert stable_versions(["3.0.0-SNAPSHOT", "2.0.0"]) == ["2.0.0"]


@pytest.fixture
def release_engine(tmp_path, monkeypatch, request):
    """Verify an isolated real manifest using offline advisory/catalog fixtures."""
    ecosystem = getattr(request, "param", "npm")
    package, filename, content = {
        "npm": (
            "example",
            "package.json",
            '{"dependencies":{"example":"1.0.0"},"scripts":{"build":"fixture"}}',
        ),
        "NuGet": (
            "Example.Library",
            "App.csproj",
            '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
            "<TargetFramework>net10.0</TargetFramework></PropertyGroup>"
            '<ItemGroup><PackageReference Include="Example.Library" Version="1.0.0" />'
            "</ItemGroup></Project>",
        ),
        "Maven": (
            "example:library",
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>app</groupId>"
            "<artifactId>app</artifactId><version>1.0.0</version><dependencies>"
            "<dependency><groupId>example</groupId><artifactId>library</artifactId>"
            "<version>1.0.0</version></dependency></dependencies></project>",
        ),
    }[ecosystem]
    (tmp_path / filename).write_text(content, encoding="utf-8")
    advisory = Mock()
    advisory.lookup.side_effect = lambda finding, ecosystem, package, version: (
        AdvisoryLookup(
            outcome="resolved",
            affected=version == "1.0.0",
            fixed_versions=["1.0.1"],
            lowest_fixed_version="1.0.1",
        )
    )
    engine = Engine(
        tmp_path,
        gitlab=Mock(),
        advisory=advisory,
        docs=documentation_client(),
        runner=Mock(),
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [
        {
            "id": "one",
            "category": "dependency_scanning",
            "component": package,
            "installedVersion": "1.0.0",
            "identifiers": ["CVE-TEST"],
            "location": {"file": filename},
        }
    ]
    assert engine.verify_security_finding("one")["decision"] == "CHANGE_REQUIRED"
    monkeypatch.setattr(
        "gitlab_security_mcp.engine.release_catalog",
        lambda *args, **kwargs: {
            "source": "https://registry.npmjs.org/example",
            "versions": ["3.0.0", "2.0.0", "1.0.1"],
        },
    )
    yield engine
    engine.close()


@pytest.mark.parametrize("release_engine", ["npm", "NuGet", "Maven"], indirect=True)
def test_selection_replans_latest_target_and_invalidates_old_qualification(
    release_engine,
):
    """Replan across ecosystems and prevent prior-target consent from authorizing it."""
    # Arrange
    engine = release_engine
    finding = engine.state.findings[0]
    manifest = engine.repo_root / finding["location"]["file"]
    original_content = manifest.read_bytes()
    original = deepcopy(finding["proposedFix"])
    with pytest.raises(ValueError, match="select_package_version"):
        engine._require_package_version(original)
    assert engine.select_package_version("one")["status"] == "RELEASE_REVIEW_REQUIRED"
    assert finding["proposedFix"] == original
    engine.record_fix_selection(
        engine.fix_selection_candidates()["candidates"], ["one"], "APPROVED"
    )
    finding["packageQualification"] = {"status": "QUALIFIED", "plan": original}

    # Act
    selected = engine.select_package_version("one", _support())

    # Assert
    assert selected["status"] == "VERSION_SELECTED", selected
    assert selected["proposed_fix"]["target"] == "3.0.0"
    assert selected["proposed_fix"]["advisory_floor"] == "1.0.1"
    assert selected["proposed_fix"]["major_upgrade"] is True
    assert "packageQualification" not in finding
    assert (
        engine.run_approved_fix("apply_minimal_fix", "one")["status"]
        == "FIX_APPROVAL_REQUIRED"
    )
    engine._require_package_version(finding["proposedFix"])
    assert manifest.read_bytes() == original_content


def test_paid_releases_are_reported_without_selecting_them(release_engine):
    """Choose a free eligible release while preserving the paid release for investigation."""
    # Arrange
    paid = {
        "version": "3.0.0",
        "reason": "paid",
        "assessment": "Requires a paid license unlike the installed free version",
        "sources": ["https://publisher.example/pricing"],
    }
    # Act
    selected = release_engine.select_package_version(
        "one", _support(target="2.0.0", excluded_releases=[paid])
    )

    # Assert
    assert selected["status"] == "VERSION_SELECTED", selected
    assert selected["proposed_fix"]["target"] == "2.0.0"
    assert selected["paid_releases"] == [paid]
    payload, report = render(
        release_engine.state, staged=[], diff_stat="", diff_files=""
    )
    assert "PAID VERSION 3.0.0: blocked; user investigation required" in report
    assert payload["package_version_selections"]["one"]["paid_releases"] == [paid]


def test_unverified_or_affected_latest_target_blocks_automatic_fix(release_engine):
    """Invalidate a prior selection when the latest target cannot be proven unaffected."""
    # Arrange
    engine = release_engine
    assert (
        engine.select_package_version("one", _support())["status"] == "VERSION_SELECTED"
    )
    engine.advisory.lookup.side_effect = None
    engine.advisory.lookup.return_value = AdvisoryLookup(
        outcome="lookup_failed", affected=None
    )

    # Act
    blocked = engine.select_package_version("one", _support())

    # Assert
    assert blocked["status"] == "RELEASE_REVIEW_REQUIRED"
    assert "could not be verified" in blocked["reason"]
    with pytest.raises(ValueError, match="select_package_version"):
        engine._require_package_version(engine.state.findings[0]["proposedFix"])


def test_no_free_supported_release_blocks_a_previously_selected_plan(release_engine):
    """Block an earlier plan when all otherwise eligible releases require payment."""
    # Arrange
    engine = release_engine
    assert (
        engine.select_package_version("one", _support())["status"] == "VERSION_SELECTED"
    )
    exclusions = [
        {
            "version": version,
            "reason": "paid",
            "sources": ["https://publisher.example/pricing"],
            "assessment": "Requires a paid license",
        }
        for version in ("3.0.0", "2.0.0", "1.0.1")
    ]

    # Act
    blocked = engine.select_package_version(
        "one", _support(target=None, excluded_releases=exclusions)
    )

    # Assert
    assert blocked["status"] == "NO_SAFE_FIX"
    assert len(blocked["selection"]["paid_releases"]) == 3
    with pytest.raises(ValueError, match="select_package_version"):
        engine._require_package_version(engine.state.findings[0]["proposedFix"])


def _license(**changes):
    """Provide target-specific fixture license evidence with explicit uncertainty overrides."""
    return {
        "expression": "MIT",
        "sources": ["https://publisher.example/license"],
        "commercial_use_permitted": True,
        "no_license_fees": True,
        "obligations": "Retain notices",
        "assessment": "Reviewed target-version terms",
        **changes,
    }


def test_explicit_unknown_license_is_allowed_with_persistent_warnings(release_engine):
    """Allow explicit license uncertainty without calling it free or dropping warnings."""
    # Arrange
    engine = release_engine
    license_review = _license(
        expression="UNKNOWN", no_license_fees=None, commercial_use_permitted=None
    )
    # Act
    policy = reviewed_license_policy(
        engine.repo_root,
        engine.state.findings[0]["proposedFix"],
        {"license": license_review},
    )

    # Assert
    assert len(policy["warnings"]) == 3
    assert all("UNVERIFIED LICENSE" in warning for warning in policy["warnings"])
    plan = engine.state.findings[0]["proposedFix"]
    engine.state.findings[0]["packageQualification"] = {
        "status": "QUALIFIED",
        "plan": plan,
        **policy,
    }
    payload, report = render(engine.state, staged=[], diff_stat="", diff_files="")
    assert "WARNING: UNVERIFIED LICENSE" in report
    assert payload["package_qualifications"]["one"]["warnings"] == policy["warnings"]


def test_unknown_fee_warning_is_present_before_approval_and_after_qualification(
    release_engine,
):
    """Expose unknown fees before selection and retain warnings after qualification."""
    # Arrange
    engine = release_engine
    exclusions = [
        {
            "version": version,
            "reason": "runtime_incompatible",
            "sources": ["https://publisher.example/runtime"],
            "assessment": "Requires a newer runtime than this fixture project",
        }
        for version in ("3.0.0", "2.0.0")
    ]
    assert (
        engine.select_package_version(
            "one", _support(target="1.0.1", excluded_releases=exclusions)
        )["status"]
        == "VERSION_SELECTED"
    )
    review = {
        "ecosystem": "npm",
        "package": "example",
        "target": "1.0.1",
        "documentation": {
            "complete": True,
            "sources": manager_doc_sources(),
            "summary": "Reviewed complete target documentation",
        },
        "compatible": True,
        "compatible_without_code_changes": True,
        "api_changes": "No caller changes",
        "frameworks": [
            {
                "name": "Node.js",
                "version": "24",
                "source_url": "https://publisher.example/support",
                "assessment": "Supported",
            }
        ],
        "source_fixes": [],
        "license": _license(no_license_fees=None),
    }

    # Act
    prepared = engine.prepare_package_updates(
        engine.fix_selection_candidates()["candidates"], {"one": review}
    )
    qualified = engine.qualify_package_update("one", review)

    # Assert
    assert prepared["status"] == "READY", prepared
    assert prepared["warnings"]["one"] == qualified["warnings"]
    assert qualified["status"] == "QUALIFIED", qualified
    assert "UNVERIFIED LICENSE" in qualified["warnings"][0]


def test_new_release_cannot_inherit_an_older_targets_review(release_engine):
    """Require a new review if the catalog changes the latest eligible target."""
    # Arrange
    engine = release_engine
    review = _support(target="2.0.0")
    # Act
    result = engine.select_package_version("one", review)
    # Assert
    assert result["status"] == "RELEASE_REVIEW_REQUIRED"
    assert "latest eligible target is '3.0.0'" in result["reason"]
    with pytest.raises(ValueError, match="select_package_version"):
        engine._require_package_version(engine.state.findings[0]["proposedFix"])


@pytest.mark.parametrize("corporate", [False, True])
def test_known_paid_target_is_blocked_even_with_corporate_policy(
    release_engine, corporate
):
    """Block known paid terms even when corporate policy is enabled."""
    # Arrange
    engine = release_engine
    if corporate:
        engine._package_policy_required = True
    review = {
        "documentation": {"sources": manager_doc_sources()},
        "license": _license(no_license_fees=False),
    }

    # Act
    with pytest.raises(ValueError, match="PAID OR RESTRICTED LICENSE"):
        engine._package_policy(engine.state.findings[0]["proposedFix"], review)
    # Assert
    payload, report = render(engine.state, staged=[], diff_stat="", diff_files="")
    assert payload["license_investigations"]["one"]["target"] == "1.0.1"
    assert "PAID OR RESTRICTED LICENSE" in report
