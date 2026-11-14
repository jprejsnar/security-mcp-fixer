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
    assert {"typescript", "javascript", "python", "csharp"} <= names


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
