"""Check configuration findings and the official-documentation gate."""

import hashlib

import httpx
import pytest

from gitlab_security_mcp.config_findings import config_kind
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.official_docs import _MAX_BODY, REQUIRED_DOCS, OfficialDocs
from tests.conftest import documentation_client

_NGINX_CORE = "https://nginx.org/en/docs/http/ngx_http_core_module.html"
_NGINX_AUTOINDEX = "https://nginx.org/en/docs/http/ngx_http_autoindex_module.html"
_NGINX_SSL = "https://nginx.org/en/docs/http/ngx_http_ssl_module.html"
_GITLAB_SCANS = "https://docs.gitlab.com/user/application_security/policies/scan_execution_policies/"


def _ready(tmp_path, finding, docs, name, text, **engine_options):
    """Place one configuration file and a listed finding into an engine."""
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    engine = Engine(
        tmp_path,
        gitlab=object(),
        advisory=object(),
        docs=docs,
        which=lambda _name: None,
        **engine_options,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]
    return engine


def _finding(file_name, line, **extra):
    """Build a SAST finding that cites one configuration line."""
    finding = {
        "id": "config",
        "title": "configuration",
        "category": "sast",
        "identifiers": [],
        "location": {"file": file_name, "startLine": line},
        "solution": "rewrite the file",
        "falsePositiveFlag": False,
    }
    finding.update(extra)
    return finding


def _review(engine, finding_id="config"):
    """Provide explicit source-bound confirmation before testing documented edits."""
    finding = next(item for item in engine.state.findings if item["id"] == finding_id)
    path = engine.repo_root / finding["location"]["file"]
    return {
        "decision": "CONFIRMED_VULNERABILITY",
        "reason": "The reviewed fixture's active configuration contains the reported insecure directive.",
        "input_origin": "Reviewed the complete fixture configuration and its literal directive values.",
        "finding_analysis": "The cited directive matches the fixture finding; its documented replacement addresses that directive.",
        "reachability_analysis": "The fixture configuration is active and has no overriding include or runtime control.",
        "reviewed_files": [
            {
                "path": finding["location"]["file"],
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "assessment": "Read the entire fixture and confirmed the reported configuration.",
            }
        ],
    }


def test_nginx_server_tokens_changes_only_the_cited_line(tmp_path):
    """Turn server_tokens off after the nginx module page still documents it."""
    # Arrange
    text = (
        "events {}\r\nhttp {\r\n    server_tokens on;\r\n    server_tokens on;\r\n}\r\n"
    )
    docs = documentation_client({_NGINX_CORE: "Syntax server_tokens on | off"})
    engine = _ready(
        tmp_path,
        _finding("nginx.conf", 3, identifiers=["CVE-NO-PUBLIC-RECORD"]),
        docs,
        "nginx.conf",
        text,
    )

    # Act
    decision = engine.verify_security_finding("config", source_review=_review(engine))
    applied = engine.apply_minimal_fix("config")
    updated = (tmp_path / "nginx.conf").read_bytes()

    # Assert
    assert decision["decision"] == "CHANGE_REQUIRED"
    assert decision["proposed_fix"]["strategy"] == "config_line"
    assert "https://nginx.org" in decision["security_validation_sites"]
    assert "https://services.nvd.nist.gov" not in decision["security_validation_sites"]
    assert applied["status"] == "APPLIED"
    assert (
        updated
        == b"events {}\r\nhttp {\r\n    server_tokens off;\r\n    server_tokens on;\r\n}\r\n"
    )
    assert "rewrite the file" not in updated.decode("utf-8")
    assert (
        engine.state.changes[0]["source_review"]["decision"]
        == "CONFIRMED_VULNERABILITY"
    )
    assert engine.get_run_status()["source_review_queue"]["finding_count"] == 0
    assert engine.apply_minimal_fix("config")["status"] == "VALIDATION_REQUIRED"


@pytest.mark.parametrize("category", ["sast", "iac_scanning"])
def test_documented_configuration_line_still_requires_ai_review(tmp_path, category):
    """Do not treat a matching directive as sufficient proof of a real defect."""
    # Arrange
    text = "server_tokens on;\n"
    engine = _ready(
        tmp_path,
        _finding("nginx.conf", 1, category=category),
        documentation_client(),
        "nginx.conf",
        text,
    )

    # Act
    result = engine.verify_security_finding("config")
    applied = engine.apply_minimal_fix("config")

    # Assert
    assert result["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert result["proposed_fix"] is None
    assert applied["status"] == "SOURCE_REVIEW_REQUIRED"
    assert (tmp_path / "nginx.conf").read_text(encoding="utf-8") == text


def test_reviewed_configuration_cannot_be_edited_after_related_evidence_changes(
    tmp_path,
):
    """Revalidate all reviewed configuration, not just the scanner-cited line."""
    # Arrange
    text = "server_tokens on;\n"
    engine = _ready(
        tmp_path,
        _finding("nginx.conf", 1),
        documentation_client({_NGINX_CORE: "Syntax server_tokens on | off"}),
        "nginx.conf",
        text,
    )
    included = tmp_path / "nginx" / "conf.d" / "site.conf"
    included.parent.mkdir(parents=True)
    included.write_text("autoindex off;\n", encoding="utf-8")
    review = _review(engine)
    review["reviewed_files"].append(
        {
            "path": "nginx/conf.d/site.conf",
            "sha256": hashlib.sha256(included.read_bytes()).hexdigest(),
            "assessment": "Reviewed the active included server configuration.",
        }
    )
    assert (
        engine.verify_security_finding("config", source_review=review)["decision"]
        == "CHANGE_REQUIRED"
    )
    included.write_text("autoindex on;\n", encoding="utf-8")

    # Act
    applied = engine.apply_minimal_fix("config")

    # Assert
    assert applied["status"] == "SOURCE_REVIEW_REQUIRED"
    assert (tmp_path / "nginx.conf").read_text(encoding="utf-8") == text
    assert engine.state.changes == []


def test_nginx_autoindex_and_obsolete_tls_follow_the_module_pages(tmp_path):
    """Apply autoindex and TLS edits only when those module pages still match."""
    # Arrange
    text = "autoindex on;\nssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
    docs = documentation_client(
        {
            _NGINX_AUTOINDEX: "autoindex on | off",
            _NGINX_SSL: "ssl_protocols TLSv1.2 TLSv1.3",
        }
    )
    engine = _ready(tmp_path, _finding("nginx.conf", 1), docs, "nginx.conf", text)
    second = _finding("nginx.conf", 2, id="tls")
    engine.state.findings.append(second)

    # Act
    autoindex = engine.verify_security_finding("config", source_review=_review(engine))
    applied_autoindex = engine.apply_minimal_fix("config")
    validated_autoindex = engine.run_validation_matrix()
    tls = engine.verify_security_finding("tls", source_review=_review(engine, "tls"))
    applied_tls = engine.apply_minimal_fix("tls")
    updated = (tmp_path / "nginx.conf").read_text(encoding="utf-8")

    # Assert
    assert autoindex["proposed_fix"]["package"] == "autoindex"
    assert tls["proposed_fix"]["package"] == "ssl_protocols"
    assert validated_autoindex["status"] == "VALIDATION_COMPLETE"
    assert applied_autoindex["status"] == applied_tls["status"] == "APPLIED"
    assert updated == "autoindex off;\nssl_protocols TLSv1.2;\n"


@pytest.mark.parametrize("later_edit", [False, True])
def test_failed_configuration_fix_rolls_back_without_overwriting_later_edits(
    tmp_path, monkeypatch, later_edit
):
    """Restore only updater-owned configuration edits and explain rejected checks."""
    # Arrange
    original = "server_tokens on;\n"
    docs = documentation_client({_NGINX_CORE: "Syntax server_tokens on | off"})
    engine = _ready(tmp_path, _finding("nginx.conf", 1), docs, "nginx.conf", original)
    engine.verify_security_finding("config", source_review=_review(engine))
    applied = engine.apply_minimal_fix("config")
    path = tmp_path / "nginx.conf"
    if later_edit:
        path.write_text("user-owned edit\n", encoding="utf-8")
    monkeypatch.setattr(
        "gitlab_security_mcp.engine.run_validation",
        lambda *args, **kwargs: {
            "status": "VALIDATION_FAILED",
            "results": [
                {
                    "status": "FAILED",
                    "required": True,
                    "kind": "build",
                    "detail": "fixture build failed",
                }
            ],
        },
    )

    # Act
    result = engine.run_validation_matrix()

    # Assert
    assert applied["status"] == "APPLIED"
    assert (tmp_path / ".security-mcp" / "lint-issues.json").is_file()
    assert result["continue_with_next_finding"] is not later_edit
    assert result["status"] == ("VALIDATION_FAILED" if later_edit else "FIX_REJECTED")
    assert path.read_text(encoding="utf-8") == (
        "user-owned edit\n" if later_edit else original
    )
    assert "fixture build failed" in engine.state.changes[0]["detail"]


def test_gitlab_ci_reenables_only_the_cited_security_scanner(tmp_path):
    """Set one documented security disable variable to false."""
    # Arrange
    text = 'variables:\n  SAST_DISABLED: "true" # paused\n  CODE_QUALITY_DISABLED: "true"\n'
    docs = documentation_client({_GITLAB_SCANS: "SAST_DISABLED: true skips SAST jobs"})
    engine = _ready(
        tmp_path,
        _finding(".gitlab-ci.yml", 2),
        docs,
        ".gitlab-ci.yml",
        text,
    )
    other = _finding(".gitlab-ci.yml", 3, id="quality")
    engine.state.findings.append(other)

    # Act
    decision = engine.verify_security_finding("config", source_review=_review(engine))
    applied = engine.apply_minimal_fix("config")
    quality = engine.verify_security_finding(
        "quality", source_review=_review(engine, "quality")
    )
    updated = (tmp_path / ".gitlab-ci.yml").read_text(encoding="utf-8")

    # Assert
    assert decision["decision"] == "CHANGE_REQUIRED"
    assert applied["status"] == "APPLIED"
    assert quality["decision"] == "MANUAL_REVIEW"
    assert (
        updated
        == 'variables:\n  SAST_DISABLED: "false" # paused\n  CODE_QUALITY_DISABLED: "true"\n'
    )


def test_dockerfile_finding_is_not_rewritten_without_a_documented_line(tmp_path):
    """Leave a Dockerfile unchanged when the cited line has no documented edit."""
    # Arrange
    text = "FROM nginx:1.25\nUSER root\n"
    engine = _ready(
        tmp_path,
        _finding("Dockerfile", 2),
        documentation_client(),
        "Dockerfile",
        text,
    )

    # Act
    decision = engine.verify_security_finding("config", source_review=_review(engine))

    # Assert
    assert decision["decision"] == "MANUAL_REVIEW"
    assert "Dockerfile" in decision["reason"]
    assert (tmp_path / "Dockerfile").read_text(encoding="utf-8") == text
    assert config_kind("docker/Dockerfile.dev") == "dockerfile"
    assert config_kind(".gitlab/ci/security.yml") == "gitlab_ci"
    assert config_kind("nginx/conf.d/site.conf") == "nginx"


def test_missing_or_outside_nginx_file_requires_evidence_not_a_false_positive(tmp_path):
    """Keep missing and outside files unresolved instead of declaring safety."""
    # Arrange
    missing = _finding("nginx.conf", 1, id="missing")
    escaped = _finding("../nginx.conf", 1, id="escape")
    engine = Engine(
        tmp_path,
        gitlab=object(),
        advisory=object(),
        docs=documentation_client(),
        which=lambda _name: None,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [missing, escaped]

    # Act
    absent = engine.verify_security_finding("missing")
    outside = engine.verify_security_finding("escape")

    # Assert
    assert absent["decision"] == outside["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert "not an existing file inside the checkout" in outside["reason"]
    assert engine.state.false_positives == []


@pytest.mark.parametrize("status", [404, 503])
def test_missing_security_reference_pages_do_not_block_code_edits(tmp_path, status):
    """Apply documented configuration fixes even when all security sites lack data."""
    # Arrange
    security_hosts = {"www.cve.org", "cwe.mitre.org", "nvd.nist.gov"}
    markers = " ".join(marker for _name, _url, marker in REQUIRED_DOCS)

    def handler(request):
        """Keep actual publisher guidance available while security references fail."""
        return (
            httpx.Response(status, text="No security data")
            if request.url.host in security_hosts
            else httpx.Response(200, text=markers + " server_tokens on | off")
        )

    docs = OfficialDocs(http=httpx.Client(transport=httpx.MockTransport(handler)))
    finding = _finding("nginx.conf", 1, identifiers=["CVE-2024-12345", "CWE-79"])
    engine = _ready(tmp_path, finding, docs, "nginx.conf", "server_tokens on;\n")

    # Act
    review = docs.read_before_fix(finding)
    decision = engine.verify_security_finding("config", source_review=_review(engine))
    applied = engine.apply_minimal_fix("config")

    # Assert
    assert review.complete is True
    assert "informational" in review.reason()
    assert all(not source.required for source in review.sources if not source.ok)
    assert decision["decision"] == "CHANGE_REQUIRED"
    assert applied["status"] == "APPLIED"
    assert (tmp_path / "nginx.conf").read_text(
        encoding="utf-8"
    ) == "server_tokens off;\n"
    assert {"https://" + host for host in security_hosts}.issubset(
        finding["securityValidationSites"]
    )


def test_incomplete_documentation_blocks_the_configuration_edit(tmp_path):
    """Do not change nginx when a required publisher page cannot be read."""
    # Arrange
    text = "server_tokens on;\n"

    def handler(_request: httpx.Request) -> httpx.Response:
        """Simulate a publisher outage."""
        return httpx.Response(503, text="down")

    docs = OfficialDocs(http=httpx.Client(transport=httpx.MockTransport(handler)))
    engine = _ready(tmp_path, _finding("nginx.conf", 1), docs, "nginx.conf", text)

    # Act
    decision = engine.verify_security_finding("config", source_review=_review(engine))

    # Assert
    assert decision["decision"] == "MANUAL_REVIEW"
    assert "not read completely" in decision["reason"]
    assert (tmp_path / "nginx.conf").read_text(encoding="utf-8") == text


def test_apply_reads_documentation_again_before_writing(tmp_path):
    """Refuse the write when the pages no longer confirm the directive."""
    # Arrange
    text = "server_tokens on;\n"
    calls = {"count": 0}

    class Once:
        """Accept the first documentation read and fail the read at apply time."""

        def read_before_fix(self, finding, doc_pages=None):
            """Count reads and delegate only the verification read."""
            calls["count"] += 1
            if calls["count"] == 1:
                return documentation_client(
                    {_NGINX_CORE: "server_tokens off"}
                ).read_before_fix(finding, doc_pages)
            failed = documentation_client().read_before_fix(finding, doc_pages)
            return type(failed)(
                tuple(
                    type(item)(
                        item.name,
                        item.url,
                        False,
                        item.status_code,
                        item.sha256,
                        "stale",
                    )
                    for item in failed.sources
                )
            )

        def close(self):
            """Injected clients do not own a connection."""

    engine = _ready(tmp_path, _finding("nginx.conf", 1), Once(), "nginx.conf", text)
    assert (
        engine.verify_security_finding("config", source_review=_review(engine))[
            "decision"
        ]
        == "CHANGE_REQUIRED"
    )

    # Act
    applied = engine.apply_minimal_fix("config")

    # Assert
    assert calls["count"] == 2
    assert applied["status"] == "DOCS_REQUIRED"
    assert (tmp_path / "nginx.conf").read_text(encoding="utf-8") == text


def test_image_edit_waits_for_documentation_and_does_not_write_on_failure(repo):
    """Keep a vulnerable image tag when publisher pages are unavailable."""
    # Arrange
    from gitlab_security_mcp.advisory import AdvisoryLookup

    (repo / "Dockerfile").write_text("FROM nginx:1.25.1\n", encoding="utf-8")
    finding = {
        "id": "img",
        "title": "nginx",
        "category": "container_scanning",
        "identifiers": ["CVE-2024-12345"],
        "component": "nginx",
        "installedVersion": "1.25.1",
        "location": {"image": "nginx:1.25.1", "file": "Dockerfile"},
        "solution": None,
        "falsePositiveFlag": False,
        "status": "detected",
    }

    class ImageAdvisory:
        """Return one patched image tag."""

        def lookup(self, finding, ecosystem, package, version):
            """Report the installed image as affected."""
            return AdvisoryLookup(
                outcome="resolved",
                affected=True,
                fixed_versions=["1.27.0"],
                lowest_fixed_version="1.27.0",
                summary="Fixed image tag 1.27.0.",
            )

    def handler(_request: httpx.Request) -> httpx.Response:
        """Fail every publisher read."""
        return httpx.Response(503, text="down")

    engine = Engine(
        repo,
        gitlab=object(),
        advisory=ImageAdvisory(),
        docs=OfficialDocs(http=httpx.Client(transport=httpx.MockTransport(handler))),
        which=lambda _name: None,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [finding]
    assert engine.verify_security_finding("img")["decision"] == "CHANGE_REQUIRED"

    # Act
    applied = engine.apply_minimal_fix("img")

    # Assert
    assert applied["status"] == "DOCS_REQUIRED"
    assert "CVE-2024-12345" in {
        item["name"].rsplit(":", 1)[-1] for item in applied["documentation"]
    }
    assert (repo / "Dockerfile").read_text(encoding="utf-8") == "FROM nginx:1.25.1\n"


def test_cve_and_cwe_pages_are_read_with_the_publisher_set():
    """Request the CVE record, its NIST detail, and the CWE definition."""
    # Arrange
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Record the URL and include every required marker plus that URL."""
        seen.append(str(request.url))
        markers = " ".join(marker for _name, _url, marker in REQUIRED_DOCS)
        return httpx.Response(200, text=f"{markers} CWE-79 {request.url}")

    docs = OfficialDocs(http=httpx.Client(transport=httpx.MockTransport(handler)))

    # Act
    review = docs.read_before_fix(
        {"identifiers": ["CVE-2024-12345", "CWE-79"], "title": "", "description": ""}
    )

    # Assert
    assert review.complete
    assert "https://www.cve.org/CVERecord?id=CVE-2024-12345" in seen
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-12345" in seen
    assert "https://cwe.mitre.org/data/definitions/79.html" in seen
    assert all(source.sha256 for source in review.sources)


def test_doc_hash_includes_bytes_past_the_retained_prefix():
    """Record a digest of the whole page, including bytes past the prefix."""
    # Arrange
    marker = " ".join(item for _name, _url, item in REQUIRED_DOCS)
    head = (marker + "\n").encode()
    shared = head + b"x" * (_MAX_BODY - len(head))

    def review(tail: bytes):
        """Read the publisher set from one body that continues past the prefix."""
        body = shared + tail

        def handler(_request: httpx.Request) -> httpx.Response:
            """Return the same oversized page for every required URL."""
            return httpx.Response(200, content=body)

        docs = OfficialDocs(http=httpx.Client(transport=httpx.MockTransport(handler)))
        return docs.read_before_fix({"location": {"file": "widget.py"}})

    # Act
    first = review(b"TAIL-ONE")
    second = review(b"TAIL-TWO")

    # Assert
    assert first.complete
    assert second.complete
    assert first.sources[0].sha256 == hashlib.sha256(shared + b"TAIL-ONE").hexdigest()
    assert second.sources[0].sha256 == hashlib.sha256(shared + b"TAIL-TWO").hexdigest()
    assert first.sources[0].sha256 != second.sources[0].sha256


def test_documentation_client_rejects_other_hosts_and_closes_owned_clients():
    """Refuse a non-publisher URL and close only the client this object opened."""
    # Arrange
    injected = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(204))
    )
    docs = OfficialDocs(http=injected)
    owned = OfficialDocs()

    # Act
    review = docs.read_before_fix(
        {},
        [
            {
                "name": "elsewhere",
                "url": "https://example.com/guide",
                "markers": ["guide"],
            }
        ],
    )
    docs.close()
    owned.close()
    owned.close()

    # Assert
    assert review.complete is False
    assert any(
        item.error == "URL is not an allowlisted https document"
        for item in review.sources
    )
    assert injected.is_closed is False
    assert owned._closed is True
    injected.close()


_KICS_APK = (
    "https://docs.kics.io/latest/queries/dockerfile-queries/"
    "d3499f6d-1651-41bb-a9a7-de925fea487b/"
)
_APK_DOCS = {
    _KICS_APK: "Unpinned Package Version in Apk Add",
    "https://docs.docker.com/build/building/best-practices/": "This is known as version pinning.",
    "https://alpinelinux.org/releases/": "Alpine release branches",
}
_STUDY_CONFIG = (
    "# syntax=docker/dockerfile:1\n"
    "ARG ICU_VERSION=78.1-r0\n"
    "ARG GIT_VERSION=2.54.1-r0\n"
    "FROM registry.example/aspnet:10.0-alpine-icu AS base\n"
    "RUN apk add --no-cache wget=1.25.0-r3\n"
    "FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS mig-build\n"
    "ARG GIT_VERSION\n"
    "# Pin add only.\n"
    "RUN apk add --no-cache \\\n"
    "    busybox \\\n"
    "    git=${GIT_VERSION}\n"
    "ENV PATH=/root/.dotnet/tools\n"
)


def _apk_finding(line, **extra):
    """Build the KICS unpinned apk finding that GitLab reports for a Dockerfile."""
    return _finding(
        "backend/Dockerfile",
        line,
        title="Unpinned Package Version in Apk Add",
        identifiers=["d3499f6d-1651-41bb-a9a7-de925fea487b"],
        **extra,
    )


def _resolver(calls, versions=None, error=None):
    """Record each Alpine lookup request and return fixed current versions."""
    from gitlab_security_mcp.alpine_packages import AlpineLookupError, ApkPins

    def resolve(image, pinned, names):
        """Answer like AlpinePackages.latest without network access."""
        calls.append((image, dict(pinned), list(names)))
        if error:
            raise AlpineLookupError(error)
        found = {name: (versions or {}).get(name, "1.0.0-r1") for name in names}
        return ApkPins(
            "v3.24",
            "fixture branch evidence",
            found,
            {name: "main" for name in names},
            ("https://alpinelinux.org/releases.json",),
        )

    return resolve


def test_kics_unpinned_apk_is_pinned_to_the_current_alpine_version(tmp_path):
    """Pin only the bare package after reading the KICS, Docker and Alpine pages."""
    # Arrange
    from tests.test_alpine_packages import alpine_client

    alpine = alpine_client()
    engine = _ready(
        tmp_path,
        _apk_finding(9),
        documentation_client(_APK_DOCS),
        "backend/Dockerfile",
        _STUDY_CONFIG,
        alpine=alpine,
    )

    # Act
    decision = engine.verify_security_finding("config", source_review=_review(engine))
    applied = engine.apply_minimal_fix("config")
    updated = (tmp_path / "backend/Dockerfile").read_text(encoding="utf-8")
    engine.close()

    # Assert
    assert decision["decision"] == "CHANGE_REQUIRED", decision["reason"]
    assert decision["proposed_fix"]["line_edits"] == [
        {
            "line": 10,
            "expected": "    busybox \\",
            "replacement": '    "busybox>=1.37.0-r31" \\',
        }
    ]
    assert "Alpine v3.24" in decision["reason"]
    assert decision["proposed_fix"]["target"] == "busybox>=1.37.0-r31"
    assert decision["proposed_fix"]["oracle"] == "busybox>=1.37.0-r31"
    assert "git=2.54.1-r0" in decision["reason"]
    assert "wget" not in decision["reason"]
    assert {"https://docs.kics.io", "https://alpinelinux.org"} <= set(
        decision["security_validation_sites"]
    )
    assert "https://dl-cdn.alpinelinux.org" in decision["security_validation_sites"]
    assert applied["status"] == "APPLIED"
    assert updated == _STUDY_CONFIG.replace(
        "    busybox \\", '    "busybox>=1.37.0-r31" \\'
    )
    assert not alpine.http.is_closed
    alpine.close()
    alpine.http.close()


@pytest.mark.parametrize("quote", ['"', "'"])
def test_apk_options_chains_and_existing_constraints_are_respected(tmp_path, quote):
    """Pin every bare package across lines without touching option values or pins."""
    # Arrange
    from gitlab_security_mcp.config_findings import apply_config_line, assess_config

    text = (
        "ARG CURL_VERSION=8.0.0-r0\r\n"
        "FROM alpine:3.24 AS tools\r\n"
        "ARG CURL_VERSION\r\n"
        "RUN --mount=type=cache,target=/var/cache/apk apk update && \\\r\n"
        "    apk add --no-cache --virtual .build-deps \\\r\n"
        "    # compilers\r\n"
        "    gcc musl-dev \\\r\n"
        f"    curl=${{CURL_VERSION}} tzdata~2026 {quote}busybox>=1.37.0-r31{quote} && \\\r\n"
        "    rm -rf /tmp/build\r\n"
    )
    (tmp_path / "Dockerfile").write_bytes(text.encode())
    calls = []
    finding = {**_apk_finding(4), "location": {"file": "Dockerfile", "startLine": 7}}

    # Act
    assessment = assess_config(
        tmp_path,
        finding,
        apk_versions=_resolver(calls, {"gcc": "15.2.0-r2", "musl-dev": "1.2.6-r0"}),
    )
    apply_config_line(tmp_path, assessment.plan)

    # Assert
    assert calls == [("alpine:3.24", {"curl": "8.0.0-r0"}, ["gcc", "musl-dev"])]
    assert [edit["line"] for edit in assessment.plan.line_edits] == [7]
    assert (tmp_path / "Dockerfile").read_bytes() == text.replace(
        "    gcc musl-dev \\", '    "gcc>=15.2.0-r2" "musl-dev>=1.2.6-r0" \\'
    ).encode()


def test_stage_chain_supplies_root_image_and_inherited_pins(tmp_path):
    """Resolve FROM <stage> to its root image and carry that stage's exact pins."""
    # Arrange
    from gitlab_security_mcp.config_findings import assess_config

    (tmp_path / "Dockerfile").write_text(
        "FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS base\n"
        "RUN apk add git=2.54.1-r0\n"
        "FROM base AS next\n"
        "RUN apk add busybox ca-certificates\n",
        encoding="utf-8",
    )
    calls = []

    # Act
    assessment = assess_config(
        tmp_path,
        {**_apk_finding(4), "location": {"file": "Dockerfile", "startLine": 4}},
        apk_versions=_resolver(calls),
    )

    # Assert
    assert assessment.decision == "plan"
    assert calls == [
        (
            "mcr.microsoft.com/dotnet/sdk:10.0-alpine",
            {"git": "2.54.1-r0"},
            ["busybox", "ca-certificates"],
        )
    ]
    assert assessment.plan.line_edits[0]["replacement"] == (
        'RUN apk add "busybox>=1.0.0-r1" "ca-certificates>=1.0.0-r1"'
    )


@pytest.mark.parametrize(
    "run,reason",
    [
        ('RUN apk add "busybox"', "quotes"),
        ("RUN apk add $PACKAGES", "not a plain package"),
        ('RUN ["apk", "add", "busybox"]', "Exec-form"),
        ("RUN apk add ./local.apk", "not a plain package"),
        ("RUN apk add busybox.apk", "not a plain package"),
        ("RUN apk add busybox;echo done", "combines commands"),
        ("RUN apk add --foo busybox", "not recognized"),
        ("RUN <<EOF\napk add busybox\nEOF", "heredoc"),
        ("RUN apk add busybox=1.37.0-r31", "already pinned"),
        ('RUN apk add "busybox>=1.37.0-r31"', "already pinned"),
        ("RUN apk add 'busybox>=1.37.0-r31'", "already pinned"),
        ('RUN apk add "busybox>=1.37.0-r31$(id)"', "quotes"),
        ("RUN apk add busybox>=1.37.0-r31", "combines commands"),
        ("COPY busybox /bin/", "not part of a RUN"),
    ],
)
def test_ambiguous_apk_instructions_are_never_rewritten(tmp_path, run, reason):
    """Keep manual review whenever the packages cannot be identified exactly."""
    # Arrange
    from gitlab_security_mcp.config_findings import assess_config

    (tmp_path / "Dockerfile").write_text(f"FROM alpine:3.24\n{run}\n", encoding="utf-8")
    calls = []

    # Act
    assessment = assess_config(
        tmp_path,
        {**_apk_finding(2), "location": {"file": "Dockerfile", "startLine": 2}},
        apk_versions=_resolver(calls),
    )

    # Assert
    assert assessment.decision == "manual"
    assert reason in assessment.reason
    assert calls == []


@pytest.mark.parametrize("variant", ["escape", "other_rule", "lookup_error"])
def test_apk_pinning_requires_the_kics_rule_and_exact_alpine_evidence(
    tmp_path, variant
):
    """Ignore other Dockerfile rules, odd escapes and unproven Alpine branches."""
    # Arrange
    from gitlab_security_mcp.config_findings import assess_config

    prefix = "# escape=`\n" if variant == "escape" else ""
    (tmp_path / "Dockerfile").write_text(
        prefix + "FROM alpine:3.24\nRUN apk add busybox\n", encoding="utf-8"
    )
    line = 3 if variant == "escape" else 2
    finding = {
        **_apk_finding(line),
        "location": {"file": "Dockerfile", "startLine": line},
    }
    if variant == "other_rule":
        finding.update(
            title="Healthcheck Instruction Missing", identifiers=["b03a748a"]
        )
    calls = []

    # Act
    assessment = assess_config(
        tmp_path,
        finding,
        apk_versions=_resolver(
            calls,
            error="Supported Alpine branches publishing x: none."
            if variant == "lookup_error"
            else None,
        ),
    )

    # Assert
    assert assessment.decision == "manual"
    assert (
        (tmp_path / "Dockerfile")
        .read_text(encoding="utf-8")
        .endswith("RUN apk add busybox\n")
    )
    if variant == "lookup_error":
        assert "Supported Alpine branches" in assessment.reason
        assert "left unchanged" in assessment.reason
    else:
        assert calls == []


def test_multi_line_config_plan_is_all_or_nothing(tmp_path):
    """A stale second line blocks the whole edit instead of half-applying it."""
    # Arrange
    from gitlab_security_mcp.config_findings import apply_config_line, assess_config

    path = tmp_path / "Dockerfile"
    path.write_text(
        "FROM alpine:3.24\nRUN apk add \\\n    busybox \\\n    tini\n", encoding="utf-8"
    )
    assessment = assess_config(
        tmp_path,
        {**_apk_finding(2), "location": {"file": "Dockerfile", "startLine": 2}},
        apk_versions=_resolver([]),
    )
    changed = "FROM alpine:3.24\nRUN apk add \\\n    busybox \\\n    tini-static\n"
    path.write_text(changed, encoding="utf-8")

    # Act
    with pytest.raises(ValueError, match="no longer matches"):
        apply_config_line(tmp_path, assessment.plan)

    # Assert
    assert len(assessment.plan.line_edits) == 2
    assert path.read_text(encoding="utf-8") == changed


def test_windows_approval_applies_and_validates_config_fix_without_another_turn(
    tmp_path, monkeypatch
):
    """An approved Dockerfile line fix runs to completion after the window closes."""
    # Arrange
    import asyncio
    from unittest.mock import AsyncMock, Mock

    from gitlab_security_mcp import server
    from tests.test_alpine_packages import alpine_client

    alpine = alpine_client()
    engine = _ready(
        tmp_path,
        _apk_finding(9),
        documentation_client(_APK_DOCS),
        "backend/Dockerfile",
        _STUDY_CONFIG,
        alpine=alpine,
    )
    engine.git = Mock()
    engine.git.staged_names.return_value = []
    engine.git.diff_summary.return_value = {"stat": "", "files": ""}
    assert (
        engine.verify_security_finding("config", source_review=_review(engine))[
            "decision"
        ]
        == "CHANGE_REQUIRED"
    )
    monkeypatch.setattr(server, "_engine_for", lambda root: engine)
    monkeypatch.setattr(server.desktop_approval, "available", lambda: True)
    dialog = Mock(
        wait=AsyncMock(
            return_value={"action": "accept", "content": {"finding_0": True}}
        ),
        close=AsyncMock(),
    )
    monkeypatch.setattr(
        server.desktop_approval, "open_dialog", AsyncMock(return_value=dialog)
    )
    ctx = Mock()
    ctx.session.client_capabilities = None

    async def exercise():
        """Open the window, let the human approve, and await the server-owned work."""
        opened = await server.select_security_fixes(ctx, str(tmp_path))
        await asyncio.gather(*server._desktop_fix_selection_tasks.values())
        return opened

    # Act
    opened = asyncio.run(exercise())
    updated = (tmp_path / "backend/Dockerfile").read_text(encoding="utf-8")
    execution = engine.state.fix_selection["package_execution"]
    engine.close()

    # Assert
    assert opened["status"] == "AWAITING_HUMAN"
    assert "Dockerfile, nginx or GitLab CI line fixes" in opened["message"]
    assert updated == _STUDY_CONFIG.replace(
        "    busybox \\", '    "busybox>=1.37.0-r31" \\'
    )
    assert execution["status"] == "COMPLETED", execution
    assert execution["config_ids"] == ["config"]
    assert execution["source_ids"] == []
    assert [row["stage"] for row in execution["results"]] == [
        "apply_minimal_fix",
        "run_validation_matrix",
    ]
    assert engine.state.changes[0]["status"] == "APPLIED"
    assert engine.state.status == "REPORT_GENERATED"
    assert not server._desktop_fix_selection_tasks
    alpine.close()
    alpine.http.close()


def test_config_approval_is_bound_to_the_displayed_edit(tmp_path):
    """A re-planned version after approval cannot be applied under the old consent."""
    # Arrange
    from tests.test_alpine_packages import alpine_client

    alpine = alpine_client()
    engine = _ready(
        tmp_path,
        _apk_finding(9),
        documentation_client(_APK_DOCS),
        "backend/Dockerfile",
        _STUDY_CONFIG,
        alpine=alpine,
    )
    engine.verify_security_finding("config", source_review=_review(engine))
    candidates = engine.fix_selection_candidates()["candidates"]
    engine.record_fix_selection(candidates, ["config"], "APPROVED")
    engine.state.findings[0]["proposedFix"]["line_edits"][0]["replacement"] = (
        '    "busybox>=9.9.9-r0" \\'
    )

    # Act
    result = engine.run_approved_fix("apply_minimal_fix", "config")
    engine.close()

    # Assert
    assert result["status"] == "FIX_APPROVAL_REQUIRED"
    assert (tmp_path / "backend/Dockerfile").read_text(
        encoding="utf-8"
    ) == _STUDY_CONFIG
    alpine.close()
    alpine.http.close()
