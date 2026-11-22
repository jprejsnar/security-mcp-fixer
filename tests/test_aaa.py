"""Cover every generated Arrange-Act-Assert outcome and framework template."""

import json

import pytest

from gitlab_security_mcp.aaa import (
    DEPENDENCY_STRATEGIES,
    generate_aaa_test,
)

FINDING_ID = "img-1"
ORACLE = "nginx:1.27.0"
DOCKERFILE = "Dockerfile"
IMAGE_STRATEGY = "image_tag"
NOT_REQUIRED = "NOT_REQUIRED"
NOT_GENERATED = "NOT_GENERATED"
GENERATED = "GENERATED"
NODE_TEST_SCRIPT = "node --test"
VITEST_PACKAGE = "vitest"
JEST_PACKAGE = "jest"
MOCHA_PACKAGE = "mocha"
MODULE_TYPE = "module"
BROKEN_JSON = "{"
COMMONJS = "commonjs"
JUNIT_MARKER = "junit-jupiter"
XUNIT_MARKER = "xunit"
JAVA_QUOTE = 'nginx:1.27.0 "pinned"'
JAVA_PATH = "docker\\app.Dockerfile"
DIGIT_FINDING = "1-base"


def _package_json(scripts, dependencies=None, package_type=None):
    """Build the package.json text a framework detector reads."""
    document = {"scripts": scripts}
    if dependencies is not None:
        document["devDependencies"] = dependencies
    if package_type is not None:
        document["type"] = package_type
    return json.dumps(document)


def _change(strategy=IMAGE_STRATEGY, oracle=ORACLE, files=None):
    """Build one applied-change record for the generator."""
    change = {"strategy": strategy}
    if oracle is not None:
        change["oracle"] = oracle
    if files is not None:
        change["files"] = files
    return change


def test_missing_change_dependency_and_oracle_are_not_generated(tmp_path):
    """Skip generation when there is no behavior change to encode."""
    # Arrange
    finding = {"id": FINDING_ID}
    dependency = _change(strategy=next(iter(DEPENDENCY_STRATEGIES)), files=[DOCKERFILE])
    without_oracle = _change(oracle=None, files=[DOCKERFILE])

    # Act
    missing = generate_aaa_test(tmp_path, finding, None)
    dependency_result = generate_aaa_test(tmp_path, finding, dependency)
    oracle_result = generate_aaa_test(tmp_path, finding, without_oracle)

    # Assert
    assert missing["status"] == NOT_REQUIRED
    assert dependency_result["status"] == NOT_REQUIRED
    assert oracle_result["status"] == NOT_GENERATED
    assert missing["finding_id"] == FINDING_ID


def test_unknown_project_and_non_dockerfile_change_are_not_generated(tmp_path):
    """Refuse a test when no framework or Dockerfile was recorded."""
    # Arrange
    finding = {"id": FINDING_ID}
    no_dockerfile = _change(files=["README.md"])

    # Act
    unknown = generate_aaa_test(tmp_path, finding, _change(files=[DOCKERFILE]))
    missing_file = generate_aaa_test(tmp_path, finding, no_dockerfile)

    # Assert
    assert unknown["status"] == NOT_GENERATED
    assert missing_file["status"] == NOT_GENERATED


@pytest.mark.parametrize(
    "document, framework, filename",
    [
        (
            _package_json({VITEST_PACKAGE: "vitest"}, {VITEST_PACKAGE: "3.0.0"}),
            VITEST_PACKAGE,
            "img-1.test.js",
        ),
        (
            _package_json({"test": "jest"}, {JEST_PACKAGE: "29.0.0"}),
            JEST_PACKAGE,
            "img-1.test.js",
        ),
        (
            _package_json({"test": "mocha"}, {MOCHA_PACKAGE: "11.0.0"}),
            MOCHA_PACKAGE,
            "img-1.test.js",
        ),
        (
            _package_json({"test": NODE_TEST_SCRIPT}, package_type=MODULE_TYPE),
            "node:test",
            "img-1.test.mjs",
        ),
    ],
)
def test_node_frameworks_receive_an_aaa_base_image_test(
    tmp_path, document, framework, filename
):
    """Write the Node template that matches the detected test runner."""
    # Arrange
    (tmp_path / "package.json").write_text(document, encoding="utf-8")

    # Act
    result = generate_aaa_test(
        tmp_path, {"id": FINDING_ID}, _change(files=[DOCKERFILE])
    )
    published = tmp_path / "test" / "security" / filename

    # Assert
    assert result["status"] == GENERATED
    assert result["framework"] == framework
    assert published.is_file()
    text = published.read_text(encoding="utf-8")
    assert "// Arrange" in text
    assert "// Act" in text
    assert "// Assert" in text
    assert ORACLE in text


def test_package_type_defaults_when_metadata_is_missing_or_invalid(tmp_path):
    """Module syntax falls back to CommonJS when package.json cannot say otherwise."""
    # Arrange
    from gitlab_security_mcp.aaa import _package_type

    missing = tmp_path / "missing"
    invalid = tmp_path / "invalid"
    invalid.mkdir()
    (invalid / "package.json").write_text(BROKEN_JSON, encoding="utf-8")

    # Act
    absent = _package_type(missing)
    broken = _package_type(invalid)

    # Assert
    assert absent == COMMONJS
    assert broken == COMMONJS


def test_junit_and_xunit_templates_escape_literals(tmp_path):
    """Java and C# tests escape the recorded image and live beside the project."""
    # Arrange
    java_root = tmp_path / "java"
    dotnet_root = tmp_path / "dotnet"
    java_root.mkdir()
    dotnet_root.mkdir()
    (java_root / "pom.xml").write_text(
        f"<dependencies>{JUNIT_MARKER}</dependencies>", encoding="utf-8"
    )
    (dotnet_root / "App.csproj").write_text(
        f'<PackageReference Include="{XUNIT_MARKER}" />', encoding="utf-8"
    )
    quoted = _change(oracle=JAVA_QUOTE, files=[JAVA_PATH])

    # Act
    java = generate_aaa_test(java_root, {"id": DIGIT_FINDING}, quoted)
    dotnet = generate_aaa_test(dotnet_root, {"id": DIGIT_FINDING}, quoted)

    # Assert
    java_file = java_root / "src" / "test" / "java" / "security" / "Fix1Base.java"
    dotnet_file = dotnet_root / "Security" / "Fix1BaseTests.cs"
    assert java["status"] == GENERATED
    assert dotnet["status"] == GENERATED
    assert java_file.is_file()
    assert dotnet_file.is_file()
    assert '\\"' in java_file.read_text(encoding="utf-8")
    assert '""' in dotnet_file.read_text(encoding="utf-8")
