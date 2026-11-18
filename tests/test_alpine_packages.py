"""Check Alpine branch selection, bounded index reads and shared downloads."""

import io
import json
import tarfile
import threading
from collections import Counter
from datetime import date

import httpx
import pytest

from gitlab_security_mcp.alpine_packages import (
    INDEX_URL,
    RELEASES_URL,
    AlpineLookupError,
    AlpinePackages,
    branch_from_image,
)

RELEASES = {
    "release_branches": [
        {"rel_branch": "edge"},
        {"rel_branch": "v3.24", "eol_date": "2028-06-01"},
        {"rel_branch": "v3.23", "eol_date": "2027-11-01"},
        {"rel_branch": "v3.21", "eol_date": "2026-11-01"},
    ]
}
INDEXES = {
    ("v3.24", "main"): {"busybox": "1.37.0-r31", "git": "2.54.1-r0"},
    ("v3.24", "community"): {"tini": "0.19.0-r9"},
    ("v3.23", "main"): {"busybox": "1.37.0-r30", "git": "2.52.1-r0"},
    ("v3.23", "community"): {"tini": "0.19.0-r8"},
    ("v3.21", "main"): {"busybox": "1.37.0-r14", "git": "2.54.1-r0"},
}


def apkindex(packages: dict[str, str]) -> bytes:
    """Build a minimal APKINDEX.tar.gz with one record per package."""
    text = "\n\n".join(
        f"C:Q1fixture=\nP:{name}\nV:{version}\nA:x86_64"
        for name, version in packages.items()
    ).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        member = tarfile.TarInfo("APKINDEX")
        member.size = len(text)
        archive.addfile(member, io.BytesIO(text))
    return buffer.getvalue()


def alpine_client(calls: Counter | None = None, gate=None) -> AlpinePackages:
    """Serve fixture releases and indexes through a local transport."""
    urls = {
        INDEX_URL.format(branch=branch, repo=repo, arch="x86_64"): apkindex(packages)
        for (branch, repo), packages in INDEXES.items()
    }

    def handler(request: httpx.Request) -> httpx.Response:
        """Return releases.json or the requested index; unknown URLs are 404."""
        url = str(request.url)
        if calls is not None:
            calls[url] += 1
        if gate is not None:
            gate()
        if url == RELEASES_URL:
            return httpx.Response(200, json=RELEASES)
        if url in urls:
            return httpx.Response(200, content=urls[url])
        return httpx.Response(404)

    return AlpinePackages(
        http=httpx.Client(transport=httpx.MockTransport(handler)),
        today=lambda: date(2026, 11, 18),
    )


@pytest.mark.parametrize(
    "image,branch",
    [
        ("alpine:3.23", "v3.23"),
        ("alpine:3.23.4", "v3.23"),
        ("docker.io/library/alpine:3.24@sha256:abc", "v3.24"),
        ("node:22-alpine3.23", "v3.23"),
        ("mcr.microsoft.com/dotnet/sdk:10.0-alpine3.24", "v3.24"),
        ("mcr.microsoft.com/dotnet/sdk:10.0-alpine", None),
        ("alpine:latest", None),
        ("${REGISTRY}/alpine:3.23", None),
        (None, None),
    ],
)
def test_branch_is_read_only_from_an_explicit_alpine_tag(image, branch):
    """Never derive a release from latest, an unversioned tag or an unresolved ARG."""
    # Arrange
    # The image reference is the parameter under test.

    # Act
    actual = branch_from_image(image)

    # Assert
    assert actual == branch


def test_existing_pins_select_the_single_supported_branch():
    """Use the stage's own exact pins, ignore end-of-life branches, and read main first."""
    # Arrange
    calls = Counter()
    client = alpine_client(calls)

    # Act
    with client:
        found = client.latest(
            "mcr.microsoft.com/dotnet/sdk:10.0-alpine",
            {"git": "2.54.1-r0"},
            ["busybox", "tini"],
        )

    # Assert
    assert found.branch == "v3.24"
    assert found.versions == {"busybox": "1.37.0-r31", "tini": "0.19.0-r9"}
    assert found.repositories == {"busybox": "main", "tini": "community"}
    assert "git=2.54.1-r0" in found.method
    assert not any("v3.21" in url for url in calls)
    assert RELEASES_URL in found.sources


@pytest.mark.parametrize(
    "pinned,match",
    [
        ({}, "cannot be identified"),
        ({"git": "9.9.9-r0"}, "none"),
        ({"tini": "0.19.0-r9", "busybox": "1.37.0-r30"}, "none"),
    ],
)
def test_missing_or_contradictory_evidence_is_refused(pinned, match):
    """Refuse to choose a branch unless exactly one publishes every existing pin."""
    # Arrange
    client = alpine_client()

    # Act
    with client, pytest.raises(AlpineLookupError, match=match):
        client.latest("mcr.microsoft.com/dotnet/sdk:10.0-alpine", pinned, ["busybox"])

    # Assert
    assert client._closed


def test_tagged_branch_needs_no_pins_and_unknown_packages_fail():
    """Honor an explicit tag, but never invent a version for an unpublished package."""
    # Arrange
    client = alpine_client()

    # Act
    with client:
        found = client.latest("alpine:3.23", {}, ["busybox"])
        with pytest.raises(AlpineLookupError, match="not published"):
            client.latest("alpine:3.23", {}, ["not-a-package"])

    # Assert
    assert found.versions == {"busybox": "1.37.0-r30"}
    assert "named by the stage image tag" in found.method


def test_concurrent_lookups_share_each_download_and_respect_client_ownership():
    """Download each index once when callers overlap; close only an owned client."""
    # Arrange
    calls = Counter()
    release = threading.Event()
    client = alpine_client(calls, gate=lambda: release.wait(5))
    owned = AlpinePackages()
    results = []

    def lookup():
        """Ask for the same tagged branch from another thread."""
        results.append(client.latest("alpine:3.24", {}, ["busybox"]))

    workers = [threading.Thread(target=lookup) for _ in range(4)]

    # Act
    for worker in workers:
        worker.start()
    release.set()
    for worker in workers:
        worker.join(10)
    client.close()
    owned.close()

    # Assert
    assert len(results) == 4
    assert {item.versions["busybox"] for item in results} == {"1.37.0-r31"}
    index = INDEX_URL.format(branch="v3.24", repo="main", arch="x86_64")
    assert calls[index] == 1
    assert calls[RELEASES_URL] == 1
    assert not client.http.is_closed
    assert owned.http.is_closed
    with pytest.raises(AlpineLookupError, match="closed"):
        client.latest("alpine:3.23", {}, ["busybox"])
    client.http.close()


@pytest.mark.parametrize("body", [b"not a tar archive", json.dumps({}).encode()])
def test_malformed_official_data_is_an_explicit_lookup_failure(body):
    """Corrupt releases or index data fails closed instead of producing a version."""

    # Arrange
    def handler(request: httpx.Request) -> httpx.Response:
        """Return valid releases only when the test corrupts the index."""
        if str(request.url) == RELEASES_URL and body.startswith(b"not"):
            return httpx.Response(200, json=RELEASES)
        return httpx.Response(200, content=body)

    client = AlpinePackages(
        http=httpx.Client(transport=httpx.MockTransport(handler)),
        today=lambda: date(2026, 11, 18),
    )

    # Act
    with client, pytest.raises(AlpineLookupError):
        client.latest("alpine:3.24", {}, ["busybox"])

    # Assert
    assert not client._pending


def _registry_fixture(history, layer_files=None, challenge=True, tamper=False):
    """Serve one Docker Hub style image: token challenge, index, manifest and blobs."""
    import hashlib

    config = json.dumps(
        {"history": [{"created_by": item} for item in history]}
    ).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, text in (layer_files or {}).items():
            data = text.encode()
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    layer = buffer.getvalue()

    def digest(data):
        """Address a fixture blob by its SHA-256."""
        return "sha256:" + hashlib.sha256(data).hexdigest()

    manifest = json.dumps(
        {"config": {"digest": digest(config)}, "layers": [{"digest": digest(layer)}]}
    ).encode()
    index = json.dumps(
        {
            "manifests": [
                {
                    "digest": "sha256:" + "1" * 64,
                    "platform": {"os": "linux", "architecture": "arm64"},
                },
                {
                    "digest": digest(manifest),
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
            ]
        }
    ).encode()
    base = "https://registry-1.docker.io/v2/library/node"
    blobs = {
        f"{base}/manifests/22-alpine": index,
        f"{base}/manifests/{digest(manifest)}": manifest,
        f"{base}/blobs/{digest(config)}": b"tampered" if tamper else config,
        f"{base}/blobs/{digest(layer)}": layer,
    }
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Require an anonymous pull token before serving registry content."""
        url = str(request.url)
        seen.append((url, request.headers.get("Authorization")))
        if url.startswith("https://auth.docker.io/token"):
            assert "scope=repository%3Alibrary%2Fnode%3Apull" in url
            return httpx.Response(200, json={"token": "anonymous-fixture"})
        if url == RELEASES_URL:
            return httpx.Response(200, json=RELEASES)
        index_urls = {
            INDEX_URL.format(branch=branch, repo=repo, arch="x86_64"): packages
            for (branch, repo), packages in INDEXES.items()
        }
        if url in index_urls:
            return httpx.Response(200, content=apkindex(index_urls[url]))
        if url in blobs:
            if (
                challenge
                and request.headers.get("Authorization") != "Bearer anonymous-fixture"
            ):
                return httpx.Response(
                    401,
                    headers={
                        "WWW-Authenticate": 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"'
                    },
                )
            return httpx.Response(200, content=blobs[url])
        return httpx.Response(404)

    client = AlpinePackages(
        http=httpx.Client(transport=httpx.MockTransport(handler)),
        today=lambda: date(2026, 11, 18),
    )
    return client, seen


@pytest.mark.parametrize("source", ["history", "base_layer"])
def test_stage_image_names_its_alpine_release(source):
    """Use the image's own release, not other pins, to choose the latest compatible version."""
    # Arrange
    history = (
        ["ADD alpine-minirootfs-3.23.3-x86_64.tar.gz / # buildkit", 'CMD ["node"]']
        if source == "history"
        else ['CMD ["node"]']
    )
    files = {
        "etc/apk/repositories": "https://dl-cdn.alpinelinux.org/alpine/v3.23/main\n"
        "https://dl-cdn.alpinelinux.org/alpine/v3.23/community\n"
    }
    client, seen = _registry_fixture(history, files)

    # Act
    with client:
        found = client.latest("node:22-alpine", {"git": "2.54.1-r0"}, ["busybox"])

    # Assert
    assert found.branch == "v3.23"
    assert found.versions == {"busybox": "1.37.0-r30"}
    assert "release" in found.method and "node:22-alpine" in found.method
    assert ("history" in found.method) is (source == "history")
    assert any(auth == "Bearer anonymous-fixture" for _url, auth in seen)
    assert not any("arm64" in url or "1111" in url for url, _auth in seen)
    client.http.close()


def test_unreadable_image_falls_back_to_existing_pins_with_both_reasons():
    """A digest mismatch is never trusted; the stage pins remain the fallback evidence."""
    # Arrange
    client, _seen = _registry_fixture(
        ["ADD alpine-minirootfs-3.23.3-x86_64.tar.gz /"], tamper=True
    )

    # Act
    with client:
        fallback = client.latest("node:22-alpine", {"git": "2.54.1-r0"}, ["busybox"])
        with pytest.raises(AlpineLookupError, match="could not be inspected") as failed:
            client.latest("node:22-alpine", {}, ["busybox"])

    # Assert
    assert fallback.branch == "v3.24"
    assert "does not match" in str(failed.value)
    client.http.close()


@pytest.mark.parametrize(
    "image",
    ["registry.internal.corp/team/app:1", "${CI_REGISTRY}/app:1", "evil.example/x:1"],
)
def test_private_or_unresolved_registries_are_never_contacted(image):
    """Only allowlisted public registries are read; others fall back to pins."""
    # Arrange
    calls = Counter()
    client = alpine_client(calls)

    # Act
    with client:
        found = client.latest(image, {"git": "2.54.1-r0"}, ["busybox"])

    # Assert
    assert found.branch == "v3.24"
    assert not any("/v2/" in url for url in calls)
    client.http.close()


def test_transient_failures_are_retried_then_reported_with_their_cause(monkeypatch):
    """Retry a dropped connection, but stop after the bounded attempts with the cause."""
    # Arrange
    from gitlab_security_mcp import alpine_packages

    delays = []
    monkeypatch.setattr(alpine_packages, "sleep", delays.append)
    failures = {"left": 2}
    index = INDEX_URL.format(branch="v3.24", repo="main", arch="x86_64")

    def handler(request: httpx.Request) -> httpx.Response:
        """Drop the first two index connections, then serve it."""
        if str(request.url) == RELEASES_URL:
            return httpx.Response(200, json=RELEASES)
        if str(request.url) == index and failures["left"]:
            failures["left"] -= 1
            raise httpx.ConnectError("fixture connection reset", request=request)
        return httpx.Response(200, content=apkindex(INDEXES[("v3.24", "main")]))

    flaky = AlpinePackages(
        http=httpx.Client(transport=httpx.MockTransport(handler)),
        today=lambda: date(2026, 11, 18),
    )

    def down(request: httpx.Request) -> httpx.Response:
        """Never connect, so the bounded retry ends with an explicit error."""
        raise httpx.ConnectError("fixture network down", request=request)

    offline = AlpinePackages(http=httpx.Client(transport=httpx.MockTransport(down)))

    # Act
    with flaky:
        found = flaky.latest("alpine:3.24", {}, ["busybox"])
    with offline, pytest.raises(AlpineLookupError) as failed:
        offline.latest("alpine:3.24", {}, ["busybox"])

    # Assert
    assert found.versions == {"busybox": "1.37.0-r31"}
    assert delays[:2] == [1.0, 2.0]
    assert "fixture network down" in str(failed.value)
    assert "after 4 attempts" in str(failed.value)
    flaky.http.close()
    offline.http.close()
