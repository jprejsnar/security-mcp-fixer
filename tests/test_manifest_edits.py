"""Check minimal manifest edits, atomic publication, and failure cleanup."""

import json

import pytest

from gitlab_security_mcp.manifests import (
    _pnpm_versions,
    _yarn_versions,
    add_npm_override,
    locate_package,
    update_csproj_version,
    update_dockerfile_tag,
    update_npm_spec,
)


def test_state_fdopen_failure_closes_descriptor(tmp_path, monkeypatch):
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


@pytest.mark.parametrize("contents", ["null", "[]", '{"scripts":[]}', '{"scripts":{"test":null}}', "bad-json"])
def test_invalid_validation_metadata_fails_closed(tmp_path, contents):
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
    assert any(row["required"] and row["status"] == "FAILED" for row in result["results"])


@pytest.mark.parametrize("contents", ["null", "[]", '{"scripts":[]}', "bad-json"])
def test_invalid_test_metadata_returns_not_generated(tmp_path, contents):
    # Arrange
    from gitlab_security_mcp.aaa import generate_aaa_test

    (tmp_path / "package.json").write_text(contents, encoding="utf-8")

    # Act
    result = generate_aaa_test(tmp_path, {"id": "finding"}, {"strategy": "image_tag", "oracle": "nginx:2", "files": ["Dockerfile"]})

    # Assert
    assert result["status"] == "NOT_GENERATED"
    assert not list(tmp_path.rglob("*.test.js"))


def test_generated_test_publication_failure_leaves_no_partial_file(tmp_path, monkeypatch):
    # Arrange
    import os

    from gitlab_security_mcp.aaa import generate_aaa_test

    (tmp_path / "package.json").write_text('{"scripts":{"test":"node --test"}}', encoding="utf-8")

    def fail_link(*args):
        """Simulate exclusive-publication failure after temporary writing."""
        raise OSError("Cannot publish test")

    monkeypatch.setattr(os, "link", fail_link)

    # Act
    result = generate_aaa_test(tmp_path, {"id": "finding"}, {"strategy": "image_tag", "oracle": "nginx:2", "files": ["Dockerfile"]})

    # Assert
    assert result["status"] == "NOT_GENERATED"
    assert not list(tmp_path.rglob("*.test.js"))
    assert not list(tmp_path.rglob("*.tmp"))


@pytest.mark.parametrize("failure", [None, RuntimeError("Server stopped")])
def test_server_exit_closes_engine(monkeypatch, failure):
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp import server

    owned = server.engine
    owned.close()
    engine = Mock()
    monkeypatch.setattr(server, "engine", engine)
    monkeypatch.setattr(server.mcp, "run", Mock(side_effect=failure))

    # Act
    if failure:
        with pytest.raises(RuntimeError, match="Server stopped"):
            server.main()
    else:
        server.main()

    # Assert
    engine.close.assert_called_once_with()


@pytest.mark.parametrize("contents, strategy", [("null", "manifest_bump"), ('{"overrides":null}', "override"), ('{"pnpm":[]}', "override")])
def test_malformed_manifest_application_returns_failure(tmp_path, contents, strategy):
    # Arrange
    from unittest.mock import Mock

    from gitlab_security_mcp.remediate import Plan, apply_plan

    (tmp_path / "package.json").write_text(contents, encoding="utf-8")
    plan = Plan(strategy, 2, "npm", "lodash", "4.17.20", "4.17.21", ["package.json"], "pnpm", "Update lodash")

    # Act
    result = apply_plan(tmp_path, plan, Mock(), lambda name: None)

    # Assert
    assert result["status"] == "FIX_FAILED"
    assert (tmp_path / "package.json").read_text(encoding="utf-8") == contents


@pytest.mark.parametrize("writer", ["state", "report"])
def test_failed_metadata_replace_preserves_previous_file(tmp_path, monkeypatch, writer):
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
    previous = {path: path.read_bytes() for path in (tmp_path / ".security-mcp").rglob("*") if path.is_file()}
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
    # Arrange
    original = '{\r\n  "dependencies": {\r\n    "lodash": "4.17.20"\r\n  }\r\n}\r\n'
    (tmp_path / "package.json").write_bytes(original.encode("utf-8"))

    # Act
    updated = update_npm_spec(tmp_path, "package.json", "lodash", "4.17.21")

    # Assert
    assert updated is True
    assert (tmp_path / "package.json").read_bytes().decode("utf-8") == original.replace("4.17.20", "4.17.21")


def test_override_keeps_indent_and_non_ascii(tmp_path):
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
    # Arrange
    (tmp_path / "Dockerfile").write_bytes(
        b"FROM nginx:1.25.1 AS build\r\nRUN true\r\nFROM nginx:1.25.1\r\nFROM nginx:1.25.1@sha256:abc\r\n"
    )

    # Act
    changed = update_dockerfile_tag(tmp_path, "nginx:1.25.1", "1.27.0")
    text = (tmp_path / "Dockerfile").read_bytes().decode("utf-8")

    # Assert
    assert changed == ["Dockerfile"]
    assert text == "FROM nginx:1.27.0 AS build\r\nRUN true\r\nFROM nginx:1.27.0\r\nFROM nginx:1.25.1@sha256:abc\r\n"
