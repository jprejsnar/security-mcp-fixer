"""Check minimal manifest edits, atomic publication, and failure cleanup."""

import json
from pathlib import Path

import pytest

from gitlab_security_mcp.manifests import (
    _pnpm_versions,
    _yarn_versions,
    add_npm_override,
    locate_package,
    update_csproj_version,
    update_dockerfile_tag,
    update_gradle_version,
    update_npm_spec,
)


def test_state_fdopen_failure_closes_descriptor(tmp_path, monkeypatch):
    """State fdopen failure closes descriptor."""
    # Arrange
    from gitlab_security_mcp import state, util

    descriptors = []

    def fail_fdopen(descriptor, *args, **kwargs):
        """Retain the raw descriptor so its cleanup can be asserted."""
        descriptors.append(descriptor)
        raise OSError("Cannot wrap descriptor")

    monkeypatch.setattr(util.os, "fdopen", fail_fdopen)

    # Act
    with pytest.raises(OSError):
        state.RunState().save(tmp_path)

    # Assert
    with pytest.raises(OSError):
        util.os.fstat(descriptors[0])
    assert not list((tmp_path / ".security-mcp").glob("*.tmp"))


def test_manifest_replace_failure_preserves_original(tmp_path, monkeypatch):
    """Manifest replace failure preserves original."""
    # Arrange
    import os

    path = tmp_path / "package.json"
    original = b'{"dependencies":{"lodash":"4.17.20"}}'
    path.write_bytes(original)

    def fail_replace(*args):
        """Simulate a failed atomic rename before the original is replaced."""
        raise OSError("Cannot replace manifest")

    monkeypatch.setattr(os, "replace", fail_replace)

    # Act
    with pytest.raises(OSError, match="Cannot replace manifest"):
        update_npm_spec(tmp_path, "package.json", "lodash", "4.17.21")

    # Assert
    assert path.read_bytes() == original
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize(
    "contents",
    ["null", "[]", '{"scripts":[]}', '{"scripts":{"test":null}}', "bad-json"],
)
def test_invalid_validation_metadata_fails_closed(tmp_path, contents):
    """Invalid validation metadata fails closed."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.commands import CommandResult
    from gitlab_security_mcp.validate import run_validation

    (tmp_path / "package.json").write_text(contents, encoding="utf-8")
    runner = Mock()
    runner.run.return_value = CommandResult(["npm", "ci"], 0, "", "", 0, False, "", "")

    # Act
    result = run_validation(tmp_path, runner, lambda name: name, timeout=30)

    # Assert
    assert result["status"] == "VALIDATION_FAILED"
    assert any(
        row["required"] and row["status"] == "FAILED" for row in result["results"]
    )


@pytest.mark.parametrize(
    ("name", "contents", "expected"),
    [
        (
            "package.json",
            '{"scripts":{"build":"vite build","test":"vitest run"}}',
            ["npm", "run", "build"],
        ),
        (
            "App.csproj",
            "<Project><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>",
            ["dotnet", "build", "--configuration", "Release", "--nologo"],
        ),
        (
            "pom.xml",
            "<project/>",
            ["mvn", "--batch-mode", "clean", "package", "-Dmaven.test.skip=true"],
        ),
        (
            "build.gradle",
            "plugins { id 'java' }",
            ["gradle", "--no-daemon", "assemble", "-x", "test"],
        ),
    ],
)
def test_remediation_requires_production_builds_without_unit_tests(
    tmp_path, name, contents, expected
):
    """Require production builds but never execute unit tests in any supported stack."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.commands import CommandResult, assert_allowed
    from gitlab_security_mcp.validate import run_validation

    (tmp_path / name).write_text(contents, encoding="utf-8")
    runner = Mock()

    def execute(argv, **kwargs):
        """Validate real command shapes without invoking application toolchains."""
        assert_allowed(argv, tmp_path)
        text = (
            'openjdk version "17.0.1"'
            if argv[0] == "java"
            else "10.0.100\nTests: 1 passed"
        )
        return CommandResult(argv, 0, text, "", 0, False, "", "")

    runner.run.side_effect = execute

    # Act
    result = run_validation(
        tmp_path,
        runner,
        lambda name: name,
        timeout=30,
        package_checks=True,
        skip_lint=True,
    )

    # Assert
    commands = [call.args[0] for call in runner.run.call_args_list]
    assert expected in commands
    assert result["status"] == "VALIDATION_COMPLETE", result
    tests = [
        row
        for row in result["results"]
        if row.get("kind") in {"unit_tests", "build_and_unit_tests"}
    ]
    assert tests == []
    assert result["test_execution"].startswith("DISABLED")


@pytest.mark.parametrize(
    "scripts",
    [
        {"build": "npm test"},
        {"build": "vite build", "postbuild": "vitest run"},
        {"build": "pnpm run verify", "verify": "pnpm run ci", "ci": "jest"},
        {"build": "pnpm verify", "verify": "node --test"},
        {"build": "vite build", "postinstall": "npm test"},
    ],
)
def test_node_build_blocks_test_hooks_and_installs_ignore_them(tmp_path, scripts):
    """Reject test-running build chains while disabling dependency install hooks."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.commands import CommandResult, assert_test_free_scripts
    from gitlab_security_mcp.validate import run_validation

    scripts = {**scripts, "test": "vitest run"}
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": scripts}), encoding="utf-8"
    )
    runner = Mock()

    def execute(argv, **kwargs):
        """Use the production script guard without launching application commands."""
        assert_test_free_scripts(argv, tmp_path)
        return CommandResult(argv, 0, "build complete", "", 0, False, "", "")

    runner.run.side_effect = execute

    # Act
    result = run_validation(
        tmp_path,
        runner,
        lambda name: name,
        timeout=30,
        package_checks=True,
        skip_lint=True,
    )

    # Assert
    assert result["status"] == (
        "VALIDATION_COMPLETE" if "postinstall" in scripts else "VALIDATION_FAILED"
    )
    commands = [call.args[0] for call in runner.run.call_args_list]
    assert ["npm", "run", "build"] in commands
    if "postinstall" in scripts:
        assert ["npm", "ci", "--ignore-scripts"] in commands
    assert ["npm", "test"] not in commands


def test_report_discloses_unverified_tests_even_without_validation(tmp_path):
    """Persist the unit-test limitation even when no fixes were approved."""
    # Arrange
    from gitlab_security_mcp.report import write_report
    from gitlab_security_mcp.state import RunState

    state = RunState()
    warning = "Test compatibility was not verified."

    # Act
    report = write_report(tmp_path, state, staged=[], diff_stat="", diff_files="")
    saved = json.loads(Path(report["json_report"]).read_text(encoding="utf-8"))

    # Assert
    assert report["unit_test_validation"]["status"] == "NOT_RUN"
    assert warning in report["final_summary_markdown"]
    assert saved["unit_test_validation"] == report["unit_test_validation"]
    assert warning in Path(report["human_report"]).read_text(encoding="utf-8")


@pytest.mark.parametrize("contents", ["null", "[]", '{"scripts":[]}', "bad-json"])
def test_invalid_test_metadata_returns_not_generated(tmp_path, contents):
    """Invalid test metadata returns not generated."""
    # Arrange
    from gitlab_security_mcp.aaa import generate_aaa_test

    (tmp_path / "package.json").write_text(contents, encoding="utf-8")

    # Act
    result = generate_aaa_test(
        tmp_path,
        {"id": "finding"},
        {"strategy": "image_tag", "oracle": "nginx:2", "files": ["Dockerfile"]},
    )

    # Assert
    assert result["status"] == "NOT_GENERATED"
    assert not list(tmp_path.rglob("*.test.js"))


def test_generated_test_publication_failure_leaves_no_partial_file(
    tmp_path, monkeypatch
):
    """Generated test publication failure leaves no partial file."""
    # Arrange
    import os

    from gitlab_security_mcp.aaa import generate_aaa_test

    (tmp_path / "package.json").write_text(
        '{"scripts":{"test":"node --test"}}', encoding="utf-8"
    )

    def fail_link(*args):
        """Simulate exclusive-publication failure after temporary writing."""
        raise OSError("Cannot publish test")

    monkeypatch.setattr(os, "link", fail_link)

    # Act
    result = generate_aaa_test(
        tmp_path,
        {"id": "finding"},
        {"strategy": "image_tag", "oracle": "nginx:2", "files": ["Dockerfile"]},
    )

    # Assert
    assert result["status"] == "NOT_GENERATED"
    assert not list(tmp_path.rglob("*.test.js"))
    assert not list(tmp_path.rglob("*.tmp"))


@pytest.mark.parametrize("failure", [None, RuntimeError("Server stopped")])
@pytest.mark.parametrize("initialized", [False, True])
def test_server_exit_closes_engine(monkeypatch, failure, initialized):
    """Server exit closes engine."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import server

    monkeypatch.setenv("PROGRESS_CONSOLE", "off")
    engine = Mock() if initialized else None
    if engine is not None:
        engine.repo_root = "checkout"
        monkeypatch.setattr(server, "_engines", {engine.repo_root: engine})
    else:
        monkeypatch.setattr(server, "_engines", {})
    monkeypatch.setattr(server.mcp, "run", Mock(side_effect=failure))

    # Act
    if failure:
        with pytest.raises(RuntimeError, match="Server stopped"):
            server.main()
    else:
        server.main()

    # Assert
    if initialized:
        engine.close.assert_called_once_with()


@pytest.mark.parametrize(
    "contents, strategy",
    [
        ("null", "manifest_bump"),
        ('{"overrides":null}', "override"),
        ('{"pnpm":[]}', "override"),
    ],
)
def test_malformed_manifest_application_returns_failure(tmp_path, contents, strategy):
    """Malformed manifest application returns failure."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.remediate import Plan, apply_plan

    (tmp_path / "package.json").write_text(contents, encoding="utf-8")
    plan = Plan(
        strategy,
        2,
        "npm",
        "lodash",
        "4.17.20",
        "4.17.21",
        ["package.json"],
        "pnpm",
        "Update lodash",
    )

    # Act
    result = apply_plan(tmp_path, plan, Mock(), lambda name: None)

    # Assert
    assert result["status"] == "FIX_FAILED"
    assert (tmp_path / "package.json").read_text(encoding="utf-8") == contents


@pytest.mark.parametrize("writer", ["state", "report"])
def test_failed_metadata_replace_preserves_previous_file(tmp_path, monkeypatch, writer):
    """Failed metadata replace preserves previous file."""
    # Arrange
    import os

    from gitlab_security_mcp.report import write_report
    from gitlab_security_mcp.state import RunState

    state = RunState()

    def write():
        """Use the selected state or report writer under identical failures."""
        if writer == "state":
            state.save(tmp_path)
        else:
            write_report(tmp_path, state, staged=[], diff_stat="", diff_files="")

    write()
    previous = {
        path: path.read_bytes()
        for path in (tmp_path / ".security-mcp").rglob("*")
        if path.is_file()
    }
    state.status = "CHANGED"

    def fail_replace(*args):
        """Reject publication so prior metadata must remain intact."""
        raise OSError("Cannot replace metadata")

    monkeypatch.setattr(os, "replace", fail_replace)

    # Act
    with pytest.raises(OSError, match="Cannot replace metadata"):
        write()

    # Assert
    assert all(path.read_bytes() == contents for path, contents in previous.items())
    assert not list(tmp_path.rglob("*.tmp"))


def test_npm_spec_edit_keeps_crlf_line_endings(tmp_path):
    """Npm spec edit keeps crlf line endings."""
    # Arrange
    original = '{\r\n  "dependencies": {\r\n    "lodash": "4.17.20"\r\n  }\r\n}\r\n'
    (tmp_path / "package.json").write_bytes(original.encode("utf-8"))

    # Act
    updated = update_npm_spec(tmp_path, "package.json", "lodash", "4.17.21")

    # Assert
    assert updated is True
    assert (tmp_path / "package.json").read_bytes().decode("utf-8") == original.replace(
        "4.17.20", "4.17.21"
    )


def test_override_keeps_indent_and_non_ascii(tmp_path):
    """Override keeps indent and non ascii."""
    # Arrange
    (tmp_path / "package.json").write_text(
        '{\n    "author": "Zoë",\n    "dependencies": {}\n}\n',
        encoding="utf-8",
    )

    # Act
    add_npm_override(tmp_path, "minimist", "1.2.6", "npm")
    text = (tmp_path / "package.json").read_text(encoding="utf-8")

    # Assert
    assert '    "author": "Zoë"' in text
    assert json.loads(text)["overrides"] == {"minimist": "1.2.6"}


def test_nested_nuget_version_does_not_borrow_the_next_package(tmp_path):
    """Nested nuget version does not borrow the next package."""
    # Arrange
    project = tmp_path / "App.csproj"
    project.write_text(
        "<Project><ItemGroup>\n"
        '  <PackageReference Include="Serilog" />\n'
        '  <PackageReference Include="Newtonsoft.Json">\n'
        "    <Version>13.0.1</Version>\n"
        "  </PackageReference>\n"
        "</ItemGroup></Project>\n",
        encoding="utf-8",
    )

    # Act
    serilog, _ = locate_package(tmp_path, "Serilog")
    changed = update_csproj_version(tmp_path, "App.csproj", "Serilog", "4.0.0")
    newtonsoft, _ = locate_package(tmp_path, "Newtonsoft.Json")

    # Assert
    assert serilog is None
    assert changed is False
    assert newtonsoft is not None and newtonsoft.version == "13.0.1"


def test_lockfile_parsers_handle_current_formats():
    """Lockfile parsers handle current formats."""
    # Arrange
    pnpm9 = "packages:\n\n  lodash@4.17.20:\n    resolution: {}\n  '@scope/lodash@9.9.9':\n    resolution: {}\n"
    yarn1 = '"lodash@^4.17.0", "lodash@^4.17.15":\n  version "4.17.20"\n'
    berry = '"lodash@npm:^4.17.0":\n  version: 4.17.20\n'

    # Act
    pnpm_found = _pnpm_versions(pnpm9, "lodash")
    yarn_found = _yarn_versions(yarn1, "lodash")
    berry_found = _yarn_versions(berry, "lodash")

    # Assert
    assert pnpm_found == ["4.17.20"]
    assert yarn_found == ["4.17.20"]
    assert berry_found == ["4.17.20"]


def test_dockerfile_tag_moves_every_stage_and_skips_digests(tmp_path):
    """Dockerfile tag moves every stage and skips digests."""
    # Arrange
    (tmp_path / "Dockerfile").write_bytes(
        b"FROM nginx:1.25.1 AS build\r\nRUN true\r\nFROM nginx:1.25.1\r\nFROM nginx:1.25.1@sha256:abc\r\n"
    )

    # Act
    changed = update_dockerfile_tag(tmp_path, "nginx:1.25.1", "1.27.0")
    text = (tmp_path / "Dockerfile").read_bytes().decode("utf-8")

    # Assert
    assert changed == ["Dockerfile"]
    assert (
        text
        == "FROM nginx:1.27.0 AS build\r\nRUN true\r\nFROM nginx:1.27.0\r\nFROM nginx:1.25.1@sha256:abc\r\n"
    )


def test_gradle_catalog_and_map_notation_update_one_coordinate(tmp_path):
    """Update a Gradle catalog reference and a map-style dependency."""
    # Arrange
    catalog = tmp_path / "gradle" / "libs.versions.toml"
    catalog.parent.mkdir()
    catalog.write_text(
        "\n".join(
            [
                "[versions]",
                'commons = "1.9"',
                "",
                "[libraries]",
                'commons-text = { group = "org.apache.commons", name = "commons-text", version.ref = "commons" }',
                "",
            ]
        ),
        encoding="utf-8",
    )
    build = tmp_path / "build.gradle"
    build.write_text(
        "implementation group: 'org.apache.commons', name: 'commons-text', version: '1.9'\n",
        encoding="utf-8",
    )

    # Act
    located, _truncated = locate_package(tmp_path, "org.apache.commons:commons-text")
    catalog_updated = update_gradle_version(
        tmp_path,
        "gradle/libs.versions.toml",
        "org.apache.commons:commons-text",
        "1.10.0",
    )
    map_updated = update_gradle_version(
        tmp_path, "build.gradle", "org.apache.commons:commons-text", "1.10.0"
    )

    # Assert
    assert located is not None and located.manager == "gradle"
    assert catalog_updated is True
    assert 'commons = "1.10.0"' in catalog.read_text(encoding="utf-8")
    assert map_updated is True
    assert "version: '1.10.0'" in build.read_text(encoding="utf-8")


def test_maven_and_gradle_builds_are_both_validated(tmp_path):
    """Run Maven and Gradle checks when the checkout contains both."""
    # Arrange
    from gitlab_security_mcp.commands import CommandResult
    from gitlab_security_mcp.validate import run_validation

    (tmp_path / "pom.xml").write_text("<project></project>", encoding="utf-8")
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
    calls = []

    def run(argv, **_kwargs):
        """Record each validation command and report a successful Java 17 run."""
        calls.append(argv)
        return CommandResult(
            list(argv),
            0,
            'openjdk version "17.0.1"\nTests run: 1',
            "",
            1,
            False,
            "a" * 64,
            "b" * 64,
        )

    runner = type("Runner", (), {"run": staticmethod(run)})()

    # Act
    result = run_validation(tmp_path, runner, lambda name: name, timeout=30)

    # Assert
    tools = [argv[0] for argv in calls]
    assert set(result["detected"]["java"]) == {"maven", "gradle"}
    assert "mvn" in tools
    assert "gradle" in tools
    assert result["status"] == "VALIDATION_COMPLETE"


@pytest.mark.parametrize("manager", ["gradle", "maven"])
@pytest.mark.parametrize("wrapper_at_checkout", [False, True])
def test_nested_java_validation_uses_component_and_available_wrapper(
    tmp_path, manager, wrapper_at_checkout
):
    """Run nested Java builds and dependency inspection in the owning directory."""
    # Arrange
    import os
    from unittest.mock import Mock

    from gitlab_security_mcp.commands import CommandResult, assert_allowed
    from gitlab_security_mcp.validate import run_validation

    component = tmp_path / "services" / "backend"
    component.mkdir(parents=True)
    filename = "build.gradle.kts" if manager == "gradle" else "pom.xml"
    contents = "plugins { java }\n" if manager == "gradle" else "<project />"
    (component / filename).write_text(contents, encoding="utf-8")
    wrapper_dir = tmp_path if wrapper_at_checkout else component
    wrapper_name = "gradlew" if manager == "gradle" else "mvnw"
    suffix = (".bat" if manager == "gradle" else ".cmd") if os.name == "nt" else ""
    wrapper = wrapper_dir / (wrapper_name + suffix)
    wrapper.write_text("", encoding="utf-8")
    runner = Mock()

    def run(argv, **kwargs):
        """Check the real allowlist without executing repository build code."""
        assert_allowed(argv, tmp_path)
        return CommandResult(
            argv, 0, 'openjdk version "17.0.1"\nTests run: 1', "", 0, False, "", ""
        )

    runner.run.side_effect = run

    # Act
    result = run_validation(
        tmp_path,
        runner,
        lambda name: name if name == "java" else None,
        timeout=30,
        package_checks=True,
        skip_lint=True,
    )

    # Assert
    assert result["status"] == "VALIDATION_COMPLETE", result
    calls = [call for call in runner.run.call_args_list if call.args[0][0] != "java"]
    assert len(calls) == (1 if manager == "gradle" else 2)
    assert all(call.args[0][0] == str(wrapper) for call in calls)
    assert all(call.kwargs["cwd"] == component for call in calls)
    if manager == "gradle":
        assert [call.args[0][1:] for call in calls] == [
            ["--no-daemon", "assemble", "-x", "test"],
        ]
    else:
        assert [call.args[0][1:] for call in calls] == [
            ["--batch-mode", "clean", "package", "-Dmaven.test.skip=true"],
            ["--batch-mode", "dependency:tree"],
        ]


@pytest.mark.parametrize("manager", ["gradle", "maven"])
def test_java_reactors_build_once_without_hiding_independent_projects(
    tmp_path, manager
):
    """Build included modules together and independently configured builds separately."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.commands import CommandResult
    from gitlab_security_mcp.validate import run_validation

    component = tmp_path / "backend"
    child = component / "api"
    independent = component / "independent"
    child.mkdir(parents=True)
    independent.mkdir()
    if manager == "gradle":
        (component / "settings.gradle.kts").write_text(
            'include("api")\n', encoding="utf-8"
        )
        (child / "build.gradle.kts").write_text("plugins { java }\n", encoding="utf-8")
        (independent / "settings.gradle.kts").write_text(
            'rootProject.name = "independent"\n', encoding="utf-8"
        )
        (independent / "build.gradle.kts").write_text(
            "plugins { java }\n", encoding="utf-8"
        )
    else:
        (component / "pom.xml").write_text(
            "<project><modules><module>api</module></modules></project>",
            encoding="utf-8",
        )
        (child / "pom.xml").write_text("<project />", encoding="utf-8")
        (independent / "pom.xml").write_text("<project />", encoding="utf-8")
    runner = Mock()
    runner.run.side_effect = lambda argv, **kwargs: CommandResult(
        argv, 0, 'openjdk version "17.0.1"\nTests run: 1', "", 0, False, "", ""
    )

    # Act
    result = run_validation(
        tmp_path,
        runner,
        lambda name: name,
        timeout=30,
        package_checks=True,
        skip_lint=True,
    )

    # Assert
    assert result["status"] == "VALIDATION_COMPLETE", result
    builds = [
        call
        for call in runner.run.call_args_list
        if "assemble" in call.args[0] or "package" in call.args[0]
    ]
    assert [call.kwargs["cwd"] for call in builds] == [component, independent]


def test_gradle_catalog_policy_checks_use_build_root_and_nested_wrapper(tmp_path):
    """A version-catalog edit runs corporate checks from its Gradle settings root."""
    # Arrange
    import os
    from unittest.mock import Mock

    from gitlab_security_mcp.commands import CommandResult
    from gitlab_security_mcp.qualification import run_checks

    component = tmp_path / "backend"
    catalog_dir = component / "gradle"
    catalog_dir.mkdir(parents=True)
    (component / "settings.gradle").write_text("", encoding="utf-8")
    (catalog_dir / "libs.versions.toml").write_text("[versions]\n", encoding="utf-8")
    wrapper = component / ("gradlew.bat" if os.name == "nt" else "gradlew")
    wrapper.write_text("", encoding="utf-8")
    checks = {
        kind: {
            "argv": ["gradlew", "--no-daemon", task],
            "success_marker": "CHECK_PASSED",
        }
        for kind, task in (
            ("build", "assemble"),
            ("runtime", "securitySmoke"),
            ("license_audit", "securityLicenses"),
        )
    }
    runner = Mock()
    runner.run.side_effect = lambda argv, **kwargs: CommandResult(
        argv, 0, "CHECK_PASSED", "", 0, False, "", ""
    )
    plan = {"manager": "gradle", "files": ["backend/gradle/libs.versions.toml"]}

    # Act
    rows = run_checks(tmp_path, checks, runner, lambda name: None, 30, plan=plan)

    # Assert
    assert all(row["status"] == "PASSED" for row in rows), rows
    assert runner.run.call_count == 3
    assert all(call.args[0][0] == str(wrapper) for call in runner.run.call_args_list)
    assert all(call.kwargs["cwd"] == component for call in runner.run.call_args_list)


def test_java_discovery_does_not_hide_cyclic_maven_reactors(tmp_path):
    """Reject an unreachable cyclic reactor even when another build is valid."""
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.validate import run_validation

    for name, module in (("a", "../b"), ("b", "../a"), ("independent", None)):
        directory = tmp_path / name
        directory.mkdir()
        modules = f"<modules><module>{module}</module></modules>" if module else ""
        (directory / "pom.xml").write_text(
            f"<project>{modules}</project>", encoding="utf-8"
        )
    runner = Mock()

    # Act
    result = run_validation(tmp_path, runner, lambda name: None, timeout=30)

    # Assert
    assert result["status"] == "VALIDATION_FAILED"
    assert "cycle" in result["results"][0]["detail"]
    runner.run.assert_not_called()


def test_gradle_plugin_version_updates_one_declaration(tmp_path):
    """Bump one Gradle plugin and leave a neighboring plugin unchanged."""
    # Arrange
    from gitlab_security_mcp.manifests import locate_package, update_gradle_version

    settings = tmp_path / "settings.gradle.kts"
    settings.write_text(
        'plugins { id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0" }\n',
        encoding="utf-8",
    )
    build = tmp_path / "build.gradle"
    build.write_text(
        "plugins {\n"
        "    id 'org.springframework.boot' version '3.2.0'\n"
        "    id 'io.spring.dependency-management' version '1.1.4'\n"
        "}\n",
        encoding="utf-8",
    )
    catalog = tmp_path / "gradle" / "libs.versions.toml"
    catalog.parent.mkdir()
    catalog.write_text(
        '[versions]\nspring-boot = "3.2.0"\n\n'
        "[plugins]\n"
        'spring-boot = { id = "org.springframework.boot", version.ref = "spring-boot" }\n',
        encoding="utf-8",
    )

    # Act
    located, _truncated = locate_package(tmp_path, "org.springframework.boot")
    build_updated = update_gradle_version(
        tmp_path, "build.gradle", "org.springframework.boot", "3.3.5"
    )
    catalog_updated = update_gradle_version(
        tmp_path,
        "gradle/libs.versions.toml",
        "org.springframework.boot",
        "3.3.5",
    )
    settings_updated = update_gradle_version(
        tmp_path,
        "settings.gradle.kts",
        "org.gradle.toolchains.foojay-resolver-convention",
        "0.9.0",
    )

    # Assert
    assert located is not None and located.version == "3.2.0"
    assert build_updated is True
    text = build.read_text(encoding="utf-8")
    assert "id 'org.springframework.boot' version '3.3.5'" in text
    assert "id 'io.spring.dependency-management' version '1.1.4'" in text
    assert catalog_updated is True
    assert 'spring-boot = "3.3.5"' in catalog.read_text(encoding="utf-8")
    assert settings_updated is True
    assert 'version "0.9.0"' in settings.read_text(encoding="utf-8")
