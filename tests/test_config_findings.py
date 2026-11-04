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


def _ready(tmp_path, finding, docs, name, text):
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
    decision = engine.verify_security_finding("config")
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
    autoindex = engine.verify_security_finding("config")
    applied_autoindex = engine.apply_minimal_fix("config")
    validated_autoindex = engine.run_validation_matrix()
    tls = engine.verify_security_finding("tls")
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
    engine.verify_security_finding("config")
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
    decision = engine.verify_security_finding("config")
    applied = engine.apply_minimal_fix("config")
    quality = engine.verify_security_finding("quality")
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
    decision = engine.verify_security_finding("config")

    # Assert
    assert decision["decision"] == "MANUAL_REVIEW"
    assert "Dockerfile" in decision["reason"]
    assert (tmp_path / "Dockerfile").read_text(encoding="utf-8") == text
    assert config_kind("docker/Dockerfile.dev") == "dockerfile"
    assert config_kind(".gitlab/ci/security.yml") == "gitlab_ci"
    assert config_kind("nginx/conf.d/site.conf") == "nginx"


def test_missing_nginx_file_is_a_false_positive_and_escape_is_not(tmp_path):
    """Treat a missing config as absent and refuse a path outside the checkout."""
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
    assert absent["decision"] == "FALSE_POSITIVE"
    assert outside["decision"] == "MANUAL_REVIEW"
    assert "outside the repository" in outside["reason"]


@pytest.mark.parametrize("status", [404, 503])
def test_missing_security_reference_pages_do_not_block_code_edits(tmp_path, status):
    """Apply documented configuration fixes even when all security sites lack data."""
    # Arrange
    security_hosts = {"www.cve.org", "cwe.mitre.org", "www.nsa.gov", "nvd.nist.gov"}
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
    decision = engine.verify_security_finding("config")
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
    decision = engine.verify_security_finding("config")

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
    assert engine.verify_security_finding("config")["decision"] == "CHANGE_REQUIRED"

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
        return docs.read_before_fix({})

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
