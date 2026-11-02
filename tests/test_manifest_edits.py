import json

from gitlab_security_mcp.manifests import (
    _pnpm_versions,
    _yarn_versions,
    add_npm_override,
    locate_package,
    update_csproj_version,
    update_dockerfile_tag,
    update_npm_spec,
)


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
