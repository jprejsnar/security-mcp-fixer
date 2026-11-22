"""Check safe fixed-version selection and conservative range evaluation."""

import pytest

from gitlab_security_mcp.versions import (
    bump_npm_spec,
    describe_ranges,
    first_unaffected,
    is_major_upgrade,
    lowest_fixed,
    npm_to_specifier,
    osv_version_affected,
    parse_fixed_versions,
    parse_version,
    range_allows,
    range_contains,
)


@pytest.mark.parametrize("suffix", [".Final", "-final", ".RELEASE", ".GA"])
def test_maven_stable_qualifiers_are_comparable(suffix):
    """Compare Maven final releases without dropping their affected-version bounds."""
    # Arrange
    installed = f"4.2.19{suffix}"
    fixed = f"4.2.20{suffix}"
    events = [{"introduced": "0"}, {"fixed": fixed}]

    # Act
    affected = range_contains(installed, events)
    unaffected = range_contains(fixed, events)

    # Assert
    assert parse_version(fixed) == parse_version("4.2.20")
    assert affected is True
    assert unaffected is False
    assert lowest_fixed(installed, [fixed]) == fixed


@pytest.mark.parametrize(
    "solution, expected",
    [
        ("Upgrade to versions 7.30.2, 8.12.4 or above.", ["7.30.2", "8.12.4"]),
        ("Fixed in versions v1.2.3 and v2.4.0.", ["1.2.3", "2.4.0"]),
        ("Update to 1.2.3, 1.2.3, or 2.0.0.", ["1.2.3", "2.0.0"]),
        ("Patched in version 1.2.3; requires runtime 24.0.0.", ["1.2.3"]),
        ("Affected versions 7.30.1 and 8.12.3. No solution is available.", []),
    ],
)
def test_fixed_version_lists_exclude_unrelated_versions(solution, expected):
    """Keep all explicit fix alternatives without harvesting unrelated prose."""
    # Arrange
    text = solution

    # Act
    parsed = parse_fixed_versions(text)

    # Assert
    assert parsed == expected


def test_lowest_fixed_is_the_next_patch():
    """Lowest fixed is the next patch."""
    # Arrange
    installed = "1.2.3"
    published = ["1.2.4", "1.3.0", "2.0.0"]

    # Act
    chosen = lowest_fixed(installed, published)

    # Assert
    assert chosen == "1.2.4"


def test_lowest_fixed_skips_versions_already_installed():
    """Lowest fixed skips versions already installed."""
    # Arrange
    installed = "1.2.4"
    published = ["1.2.4", "1.3.0"]

    # Act
    chosen = lowest_fixed(installed, published)

    # Assert
    assert chosen == "1.3.0"


def test_npm_caret_allows_the_fix_and_bump_preserves_it():
    """Npm caret allows the fix and bump preserves it."""
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
    """Osv range and solution text."""
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


LEADING_V = "v1.2.3"
UNPARSEABLE_FIX = "not-a-version"
ZERO_INTRODUCED = "0"
PATCH_FLOOR = "1.2.3"
NEXT_PATCH = "1.2.4"
NEXT_MINOR = "1.3.0"
ZERO_MINOR = "0.1.0"
ZERO_NEXT_MINOR = "0.2.0"
CARET_ZERO = "^0.1.2"
CARET_ZERO_PATCH = "^0.0.1"
TILDE = "~1.2.3"
BARE = "1.2.3"
COMPARISON = ">=1.2.3 <2.0.0"
WORKSPACE = "workspace:local"
HTTP_SPEC = "https://example.com/pkg.tgz"
BROKEN_CARET = "^not-a-version"
FLOOR_SPEC = ">=1.0.0"
LAST_AFFECTED = "1.2.3"
BEYOND_LAST = "1.2.4"
GIT_RANGE = "GIT"
UNKNOWN_RANGE = "UNKNOWN"
EXPLICIT_VERSION = "9.9.9"
INSIDE_RANGE = "1.2.0"


def test_leading_v_and_missing_installed_version_use_the_lowest_fix():
    """A missing installed version still selects the lowest comparable fix."""
    # Arrange
    published = [NEXT_MINOR, NEXT_PATCH, UNPARSEABLE_FIX]

    # Act
    stripped = parse_version(LEADING_V)
    chosen = lowest_fixed(None, published)
    empty = lowest_fixed(None, [UNPARSEABLE_FIX])

    # Assert
    assert stripped == parse_version(BARE)
    assert chosen == NEXT_PATCH
    assert empty is None


def test_npm_ranges_convert_only_when_they_are_one_comparable_range():
    """Caret, tilde, exact, and comparison ranges stay inside one specifier."""
    # Arrange
    zero_minor = npm_to_specifier(CARET_ZERO)
    zero_patch = npm_to_specifier(CARET_ZERO_PATCH)
    tilde = npm_to_specifier(TILDE)
    exact = npm_to_specifier(BARE)
    comparison = npm_to_specifier(COMPARISON)

    # Act
    rejected = [
        npm_to_specifier(""),
        npm_to_specifier(WORKSPACE),
        npm_to_specifier(HTTP_SPEC),
        npm_to_specifier(BROKEN_CARET),
        npm_to_specifier("oranges"),
    ]
    allows_patch = range_allows(CARET_ZERO, ZERO_NEXT_MINOR)
    allows_missing = range_allows(None, BARE)
    allows_bad_version = range_allows(BARE, UNPARSEABLE_FIX)
    allows_bad_spec = range_allows(">=", BARE)

    # Assert
    assert zero_minor == f">={CARET_ZERO[1:]},<0.2.0"
    assert zero_patch == f">={CARET_ZERO_PATCH[1:]},<0.0.2"
    assert tilde == f">={TILDE[1:]},<1.3.0"
    assert exact == f"=={BARE}"
    assert comparison == ">=1.2.3,<2.0.0"
    assert rejected == [None, None, None, None, None]
    assert allows_patch is False
    assert allows_missing is False
    assert allows_bad_version is False
    assert allows_bad_spec is False


def test_npm_floor_bump_keeps_the_operator_or_refuses_a_remote_spec():
    """Raise an npm floor without rewriting workspace, file, or URL specs."""
    # Arrange
    greater = f"{FLOOR_SPEC} <2.0.0"

    # Act
    caret = bump_npm_spec(CARET_ZERO, NEXT_PATCH)
    exact = bump_npm_spec(BARE, NEXT_PATCH)
    raised = bump_npm_spec(greater, NEXT_PATCH)
    missing_floor = bump_npm_spec("<2.0.0", NEXT_PATCH)
    remote = bump_npm_spec(WORKSPACE, NEXT_PATCH)

    # Assert
    assert caret == f"^{NEXT_PATCH}"
    assert exact == NEXT_PATCH
    assert raised == f">={NEXT_PATCH} <2.0.0"
    assert missing_floor is None
    assert remote is None


def test_osv_events_stop_when_a_bound_cannot_be_compared():
    """An unreadable introduced, fixed, or last-affected bound is unknown."""
    # Arrange
    introduced = [{"introduced": UNPARSEABLE_FIX}]
    fixed = [{"fixed": UNPARSEABLE_FIX}]
    last_affected = [{"last_affected": UNPARSEABLE_FIX}]
    open_ended = [{"introduced": ZERO_INTRODUCED}, {"last_affected": LAST_AFFECTED}]

    # Act
    unknown_version = range_contains(UNPARSEABLE_FIX, open_ended)
    unknown_introduced = range_contains(PATCH_FLOOR, introduced)
    unknown_fixed = range_contains(PATCH_FLOOR, fixed)
    unknown_last = range_contains(PATCH_FLOOR, last_affected)
    inside = range_contains(PATCH_FLOOR, open_ended)
    after = range_contains(BEYOND_LAST, open_ended)
    unbound = range_contains(PATCH_FLOOR, [{"limit": PATCH_FLOOR}])

    # Assert
    assert unknown_version is None
    assert unknown_introduced is None
    assert unknown_fixed is None
    assert unknown_last is None
    assert inside is True
    assert after is False
    assert unbound is None


def test_osv_entries_prefer_an_explicit_version_and_ignore_git_ranges():
    """A listed version is affected even when a Git range cannot be decided."""
    # Arrange
    entry = {
        "versions": [LEADING_V],
        "ranges": [
            {"type": GIT_RANGE, "events": [{"introduced": ZERO_INTRODUCED}]},
            {"type": UNKNOWN_RANGE, "events": [{"introduced": ZERO_INTRODUCED}]},
            {
                "type": "SEMVER",
                "events": [{"introduced": ZERO_INTRODUCED}, {"fixed": NEXT_PATCH}],
            },
        ],
    }
    explicit_only = {"versions": [EXPLICIT_VERSION]}
    empty = {}

    # Act
    semver_only = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [{"introduced": ZERO_INTRODUCED}, {"fixed": NEXT_PATCH}],
            }
        ]
    }
    skipped_ranges = {
        "versions": [EXPLICIT_VERSION],
        "ranges": [{"type": UNKNOWN_RANGE, "events": []}],
    }
    listed = osv_version_affected(LEADING_V, entry)
    ranged = osv_version_affected(INSIDE_RANGE, entry)
    cleared = osv_version_affected(NEXT_MINOR, semver_only)
    absent = osv_version_affected(PATCH_FLOOR, explicit_only)
    skipped = osv_version_affected(PATCH_FLOOR, skipped_ranges)
    missing_version = osv_version_affected(None, entry)
    undecided = osv_version_affected(PATCH_FLOOR, empty)
    major = is_major_upgrade(PATCH_FLOOR, "2.0.0")
    zero_minor = is_major_upgrade(ZERO_MINOR, ZERO_NEXT_MINOR)
    same = is_major_upgrade(PATCH_FLOOR, NEXT_PATCH)
    incomparable = is_major_upgrade(None, NEXT_PATCH)
    safe = first_unaffected(
        PATCH_FLOOR, [NEXT_PATCH, NEXT_MINOR], lambda raw: raw == NEXT_PATCH
    )
    described = describe_ranges([semver_only])

    # Assert
    assert listed is True
    assert ranged is True
    assert cleared is False
    assert absent is False
    assert skipped is False
    assert missing_version is None
    assert undecided is None
    assert major is True
    assert zero_minor is True
    assert same is False
    assert incomparable is False
    assert safe == NEXT_MINOR
    assert described == [f">={ZERO_INTRODUCED},<{NEXT_PATCH}"]
