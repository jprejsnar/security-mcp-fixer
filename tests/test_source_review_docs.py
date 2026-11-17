"""Verify source conclusions wait for language docs and cited CVE/CWE pages."""

import hashlib
from unittest.mock import Mock

from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.official_docs import REQUIRED_DOCS
from gitlab_security_mcp.source_findings import (
    TYPESCRIPT_UTILITY_REVIEW,
    source_languages,
)
from tests.conftest import documentation_client


def _engine(tmp_path, name, content, identifiers=None):
    """List one SAST finding against a cited fixture file."""
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    engine = Engine(
        tmp_path,
        gitlab=Mock(),
        advisory=Mock(),
        docs=documentation_client(),
        which=lambda _name: None,
    )
    engine.state.status = "FINDINGS_LISTED"
    engine.state.findings = [
        {
            "id": "source",
            "title": "reviewed finding",
            "category": "sast",
            "identifiers": identifiers or [],
            "location": {"file": name, "startLine": 1},
        }
    ]
    review = {
        "decision": "FALSE_POSITIVE",
        "reason": "The fixture does not implement the reported behavior.",
        "input_origin": "The cited file is a literal fixture.",
        "finding_analysis": "The cited line does not reach an exposed input.",
        "reachability_analysis": "Nothing in the fixture accepts external input.",
        "reviewed_files": [
            {
                "path": name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "assessment": "Read the complete fixture.",
            }
        ],
    }
    return engine, review


def test_source_languages_follow_the_cited_file():
    """Select the publisher set for each requested source and configuration type."""
    # Arrange
    cases = {
        "widget.ts": ("typescript", "javascript"),
        "widget.js": ("javascript", "node"),
        "widget.py": ("python",),
        "Widget.java": ("java",),
        "Widget.cs": ("csharp", "dotnet"),
        "Dockerfile": ("docker",),
        "nginx.conf": ("nginx",),
    }

    # Act
    selected = {name: source_languages(name) for name in cases}

    # Assert
    assert selected == cases


def test_repeated_source_assessments_reuse_current_run_documentation(tmp_path):
    """Do not transfer the entire publisher catalog for each read-only assessment."""
    # Arrange
    engine, review = _engine(tmp_path, "widget.py", "ready = True\n")
    reader = Mock(wraps=engine.docs._read_page)
    engine.docs._read_page = reader

    # Act
    first = engine.verify_security_finding("source", source_review=review)
    second = engine.verify_security_finding("source", source_review=review)

    # Assert
    assert first["decision"] == second["decision"] == "FALSE_POSITIVE"
    assert reader.call_count == 1
    assert all(
        source["reused"] for source in second["source_workflow"]["documentation"]
    )


def test_typescript_review_requires_utility_types_and_read_pages(tmp_path):
    """Record the utility-type limits and the fetched publisher pages."""
    # Arrange
    engine, review = _engine(tmp_path, "widget.ts", "export const ready = true;\n")

    # Act
    pending = engine.verify_security_finding("source")
    accepted = engine.verify_security_finding("source", source_review=review)

    # Assert
    assert TYPESCRIPT_UTILITY_REVIEW in pending["source_workflow"]["steps"]
    assert pending["source_workflow"]["languages"] == ("typescript", "javascript")
    assert accepted["decision"] == "FALSE_POSITIVE"
    names = {item["name"] for item in accepted["source_workflow"]["documentation"]}
    assert names == {"typescript", "javascript"}


def test_python_review_does_not_fetch_unrelated_publishers(tmp_path):
    """Request the Python page and leave Java, Crystal, and Angular unread."""
    # Arrange
    engine, review = _engine(tmp_path, "widget.py", "ready = True\n")

    # Act
    accepted = engine.verify_security_finding("source", source_review=review)

    # Assert
    names = {item["name"] for item in accepted["source_workflow"]["documentation"]}
    urls = {item["url"] for item in accepted["source_workflow"]["documentation"]}
    assert accepted["decision"] == "FALSE_POSITIVE"
    assert names == {"python"}
    assert "Crystal" not in " ".join(accepted["source_workflow"]["steps"])
    assert "https://docs.oracle.com/en/java/javase/" not in urls
    assert "https://crystal-lang.org/reference/" not in urls
    assert "https://angular.dev/overview" not in urls


def test_unread_language_page_blocks_the_source_conclusion(tmp_path):
    """Refuse a false positive when the Python publisher page has no marker."""
    # Arrange
    python_url = next(url for name, url, _marker in REQUIRED_DOCS if name == "python")
    engine, review = _engine(tmp_path, "widget.py", "ready = True\n")
    engine.docs = documentation_client({python_url: "unrelated"})

    # Act
    result = engine.verify_security_finding("source", source_review=review)

    # Assert
    assert result["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert "not accepted" in result["reason"]


def test_unread_cve_page_blocks_the_source_conclusion(tmp_path):
    """Refuse a conclusion when the cited CVE page was not actually read."""
    # Arrange
    engine, review = _engine(
        tmp_path,
        "widget.py",
        "ready = True\n",
        identifiers=["CWE-79"],
    )
    cwe_url = "https://cwe.mitre.org/data/definitions/79.html"
    engine.docs = documentation_client({cwe_url: "definition without the identifier"})

    # Act
    result = engine.verify_security_finding("source", source_review=review)

    # Assert
    assert result["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert "not accepted" in result["reason"]


def test_false_positive_comment_records_source_and_missing_cve_cwe(tmp_path):
    """Retain a source description and say when GitLab named no CVE or CWE."""
    # Arrange
    engine, review = _engine(tmp_path, "widget.py", "ready = True\n")

    # Act
    result = engine.verify_security_finding("source", source_review=review)

    # Assert
    assert result["decision"] == "FALSE_POSITIVE"
    assert review["reason"] in result["reason"]
    assert "widget.py:1" in result["reason"]
    assert "Input origin:" in result["reason"]
    assert "Code analysis:" in result["reason"]
    assert "Reachability:" in result["reason"]
    assert "no issue-specific CVE or CWE record page was available" in result["reason"]
    assert "python: available at https://docs.python.org/3/" in result["reason"]


def test_false_positive_comment_records_available_cve_and_cwe_pages(tmp_path):
    """Record each GitLab CVE and CWE page that was actually retrieved."""
    # Arrange
    engine, review = _engine(
        tmp_path,
        "widget.py",
        "ready = True\n",
        identifiers=["CVE-2024-12345", "CWE-79"],
    )
    review["finding_analysis"] = (
        "The cited line does not implement CVE-2024-12345 or CWE-79."
    )
    cwe_url = "https://cwe.mitre.org/data/definitions/79.html"
    engine.docs = documentation_client({cwe_url: "CWE-79 definition"})

    # Act
    result = engine.verify_security_finding("source", source_review=review)

    # Assert
    assert result["decision"] == "FALSE_POSITIVE"
    assert (
        "cve:CVE-2024-12345: available at https://www.cve.org/CVERecord?id=CVE-2024-12345"
        in result["reason"]
    )
    assert (
        "nist:CVE-2024-12345: available at https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
        in result["reason"]
    )
    assert f"cwe:CWE-79: available at {cwe_url}" in result["reason"]


def test_false_positive_without_the_named_cve_is_not_accepted(tmp_path):
    """Refuse a description that never addresses the CVE GitLab named."""
    # Arrange
    engine, review = _engine(
        tmp_path,
        "widget.py",
        "ready = True\n",
        identifiers=["CVE-2024-12345"],
    )

    # Act
    result = engine.verify_security_finding("source", source_review=review)

    # Assert
    assert result["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert "CVE-2024-12345" in result["reason"]
    assert "not accepted" in result["reason"]


def test_short_false_positive_label_is_not_a_description(tmp_path):
    """Refuse a label that does not describe the cited code."""
    # Arrange
    engine, review = _engine(tmp_path, "widget.py", "ready = True\n")
    review["reason"] = "Not a bug."

    # Act
    result = engine.verify_security_finding("source", source_review=review)

    # Assert
    assert result["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert "complete sentence" in result["reason"]
