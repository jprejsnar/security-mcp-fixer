from gitlab_security_mcp.versions import (
    bump_npm_spec,
    lowest_fixed,
    osv_version_affected,
    parse_fixed_versions,
    range_allows,
    range_contains,
)


def test_lowest_fixed_is_the_next_patch():
    # Arrange
    installed = "1.2.3"
    published = ["1.2.4", "1.3.0", "2.0.0"]

    # Act
    chosen = lowest_fixed(installed, published)

    # Assert
    assert chosen == "1.2.4"


def test_lowest_fixed_skips_versions_already_installed():
    # Arrange
    installed = "1.2.4"
    published = ["1.2.4", "1.3.0"]

    # Act
    chosen = lowest_fixed(installed, published)

    # Assert
    assert chosen == "1.3.0"


def test_npm_caret_allows_the_fix_and_bump_preserves_it():
    # Arrange
    declared = "^1.2.0"
    exact = "1.2.3"

    # Act
    caret_allows_patch = range_allows(declared, "1.2.4")
    caret_allows_major = range_allows(declared, "2.0.0")
    bumped_caret = bump_npm_spec(declared, "1.2.4")
    bumped_exact = bump_npm_spec(exact, "1.2.4")

    # Assert
    assert caret_allows_patch is True
    assert caret_allows_major is False
    assert bumped_caret == "^1.2.4"
    assert bumped_exact == "1.2.4"


def test_osv_range_and_solution_text():
    # Arrange
    events = [{"introduced": "0"}, {"fixed": "4.17.21"}]
    affected = {
        "package": {"ecosystem": "npm", "name": "lodash"},
        "ranges": [{"type": "SEMVER", "events": events}],
    }

    # Act
    old_in_range = range_contains("4.17.20", events)
    fixed_in_range = range_contains("4.17.21", events)
    old_affected = osv_version_affected("4.17.20", affected)
    fixed_affected = osv_version_affected("4.17.21", affected)
    parsed = parse_fixed_versions("Upgrade to version 4.17.21 or later.")

    # Assert
    assert old_in_range is True
    assert fixed_in_range is False
    assert old_affected is True
    assert fixed_affected is False
    assert parsed == ["4.17.21"]
