"""Arrange-Act-Assert tests for fixes that change runtime behavior."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from gitlab_security_mcp.manifests import _read_json, iter_files
from gitlab_security_mcp.util import atomic_write_text

DEPENDENCY_STRATEGIES = {"lockfile_only", "manifest_bump", "override", "dependency_update"}


def generate_aaa_test(root: Path, finding: dict, change: dict | None) -> dict:
    """Write one Arrange-Act-Assert test that checks the applied change.

    Pure dependency updates do not get a test. An existing file is never
    overwritten.
    """
    try:
        return _generate_aaa_test(root, finding, change)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        return {"status": "NOT_GENERATED", "finding_id": finding.get("id"), "reason": f"Test could not be generated safely: {exc}"}


def _generate_aaa_test(root: Path, finding: dict, change: dict | None) -> dict:
    """Publish an oracle-backed test only for supported behavior changes."""
    finding_id = finding.get("id")
    if not change:
        return {"status": "NOT_REQUIRED", "finding_id": finding_id, "reason": "No applied change to cover."}
    strategy = change.get("strategy") or change.get("type")
    if strategy in DEPENDENCY_STRATEGIES:
        return {
            "status": "NOT_REQUIRED",
            "finding_id": finding_id,
            "reason": "A pure dependency update does not change first-party behavior.",
        }
    oracle = change.get("oracle")
    if not oracle:
        return {
            "status": "NOT_GENERATED",
            "finding_id": finding_id,
            "reason": "The change has no deterministic assertion to encode.",
        }
    detected = _detect_framework(root)
    if detected is None:
        return {
            "status": "NOT_GENERATED",
            "finding_id": finding_id,
            "reason": "No test framework was detected with enough confidence to add a compiling test.",
        }
    framework, project_dir = detected
    target = next((item for item in change.get("files") or [] if _is_dockerfile_name(item)), None)
    if target is None:
        return {
            "status": "NOT_GENERATED",
            "finding_id": finding_id,
            "reason": "The change did not record which Dockerfile it edited.",
        }
    slug = _slug(finding_id or "finding")
    path, contents = _render(root, project_dir, framework, slug, oracle, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        atomic_write_text(path, contents, exclusive=True)
    except FileExistsError:
        return {
            "status": "NOT_GENERATED",
            "finding_id": finding_id,
            "reason": f"{_rel(root, path)} already exists and was not overwritten.",
        }
    return {
        "status": "GENERATED",
        "finding_id": finding_id,
        "framework": framework,
        "path": _rel(root, path),
        "oracle": oracle,
    }


def _rel(root: Path, path: Path) -> str:
    """Return a normalized repository-relative path for result metadata."""
    return path.resolve().relative_to(root.resolve()).as_posix()


def _is_dockerfile_name(value: str) -> bool:
    """Recognize standard and suffixed Dockerfile names in changed paths."""
    name = Path(value).name.lower()
    return name == "dockerfile" or name.endswith(".dockerfile")


def _detect_framework(root: Path) -> tuple[str, Path] | None:
    """Return the test framework and the directory its tests run from."""
    package_json = root / "package.json"
    if package_json.exists():
        data = _read_json(package_json)
        deps: dict = {}
        for key in ("dependencies", "devDependencies"):
            deps.update(data.get(key) or {})
        test_script = str((data.get("scripts") or {}).get("test") or "")
        if "vitest" in deps:
            return "vitest", root
        if "jest" in deps or "jest" in test_script:
            return "jest", root
        if "mocha" in deps:
            return "mocha", root
        # Without a test script nothing would run the generated file.
        if test_script:
            return "node:test", root
    pom = root / "pom.xml"
    if pom.exists() and "junit-jupiter" in pom.read_text(encoding="utf-8", errors="replace"):
        return "junit5", root
    files, _truncated = iter_files(root)
    for path in files:
        if path.suffix.lower() != ".csproj":
            continue
        if "xunit" in path.read_text(encoding="utf-8", errors="replace").lower():
            # SDK-style projects compile every .cs file under their folder,
            # so the test must live next to the test project.
            return "xunit", path.parent
    return None


def _render(
    root: Path,
    project_dir: Path,
    framework: str,
    slug: str,
    oracle: str,
    dockerfile: str,
) -> tuple[Path, str]:
    """Select the framework's test destination and escaped source template."""
    if framework in {"vitest", "jest", "mocha"}:
        return root / "test" / "security" / f"{slug}.test.js", _node_test(oracle, framework, dockerfile)
    if framework == "node:test":
        esm = _package_type(root) == "module"
        path = root / "test" / "security" / f"{slug}.test.{'mjs' if esm else 'js'}"
        return path, _node_builtin(oracle, esm, dockerfile)
    class_name = _class_name(slug)
    if framework == "junit5":
        path = root / "src" / "test" / "java" / "security" / f"{class_name}.java"
        return path, _junit(class_name, oracle, dockerfile)
    # xUnit runs from bin/<config>/<tfm>, so the path is resolved against
    # the repository root, which is fixed when the test is written.
    from_project = Path(os.path.relpath(root / dockerfile, project_dir)).as_posix()
    return project_dir / "Security" / f"{class_name}Tests.cs", _xunit(class_name, oracle, from_project)


def _node_test(oracle: str, framework: str, dockerfile: str) -> str:
    """Render a base-image assertion for Vitest, Jest, or Mocha."""
    expected = json.dumps(oracle)
    source = json.dumps(dockerfile)
    if framework == "vitest":
        header = 'import { describe, it, expect } from "vitest";\nimport { readFileSync } from "node:fs";\n'
        read = f"readFileSync({source}, \"utf8\")"
        check = "expect(patched).toBe(true);"
    elif framework == "jest":
        header = 'const fs = require("node:fs");\n'
        read = f"fs.readFileSync({source}, \"utf8\")"
        check = "expect(patched).toBe(true);"
    else:
        header = 'const fs = require("node:fs");\nconst assert = require("node:assert/strict");\n'
        read = f"fs.readFileSync({source}, \"utf8\")"
        check = "assert.equal(patched, true);"
    return f"""{header}
describe("security fix", () => {{
  it("uses the patched base image", () => {{
    // Arrange
    const dockerfile = {read};
    // Act
    const patched = dockerfile.includes({expected});
    // Assert
    {check}
  }});
}});
"""


def _node_builtin(oracle: str, esm: bool, dockerfile: str) -> str:
    """Render a node:test assertion using the project's module syntax."""
    expected = json.dumps(oracle)
    source = json.dumps(dockerfile)
    if esm:
        header = (
            'import test from "node:test";\n'
            'import assert from "node:assert/strict";\n'
            'import { readFileSync } from "node:fs";\n'
        )
        read = f"readFileSync({source}, \"utf8\")"
    else:
        header = (
            'const test = require("node:test");\n'
            'const assert = require("node:assert/strict");\n'
            'const fs = require("node:fs");\n'
        )
        read = f"fs.readFileSync({source}, \"utf8\")"
    return f"""{header}
test("uses the patched base image", () => {{
  // Arrange
  const dockerfile = {read};
  // Act
  const patched = dockerfile.includes({expected});
  // Assert
  assert.equal(patched, true);
}});
"""


def _java_literal(value: str) -> str:
    """Escape backslashes and quotes for a generated Java string literal."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _junit(class_name: str, oracle: str, dockerfile: str) -> str:
    """Render a JUnit 5 assertion for the recorded Dockerfile and image."""
    return f"""package security;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

public class {class_name} {{
  @Test
  void usesPatchedBaseImage() throws Exception {{
    // Arrange
    String dockerfile = Files.readString(Path.of({_java_literal(dockerfile)}));
    // Act
    boolean patched = dockerfile.contains({_java_literal(oracle)});
    // Assert
    assertTrue(patched);
  }}
}}
"""


def _csharp_literal(value: str) -> str:
    """Escape quotes for a generated C# verbatim string literal."""
    return '@"' + value.replace('"', '""') + '"'


def _xunit(class_name: str, oracle: str, from_project: str) -> str:
    """Render an xUnit assertion that locates its test project at runtime."""
    return f"""using System;
using System.IO;
using Xunit;

public class {class_name}Tests
{{
    [Fact]
    public void UsesPatchedBaseImage()
    {{
        // Arrange
        var projectDir = new DirectoryInfo(AppContext.BaseDirectory);
        while (projectDir != null && projectDir.GetFiles("*.csproj").Length == 0)
        {{
            projectDir = projectDir.Parent;
        }}
        Assert.NotNull(projectDir);
        var dockerfile = File.ReadAllText(Path.Combine(projectDir!.FullName, {_csharp_literal(from_project)}));
        // Act
        var patched = dockerfile.Contains({_csharp_literal(oracle)});
        // Assert
        Assert.True(patched);
    }}
}}
"""


def _package_type(root: Path) -> str:
    """Read Node module syntax, defaulting to CommonJS when unspecified."""
    path = root / "package.json"
    if not path.exists():
        return "commonjs"
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("type") or "commonjs"
    except json.JSONDecodeError:
        return "commonjs"


def _slug(value: str) -> str:
    """Make a bounded filename slug from an externally supplied finding id."""
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").lower()
    return cleaned[:60] or "finding"


def _class_name(slug: str) -> str:
    """Produce an identifier that cannot begin with a digit."""
    parts = [part.capitalize() for part in slug.split("-") if part]
    name = "".join(parts) or "SecurityFix"
    if name[0].isdigit():
        name = "Fix" + name
    return name
