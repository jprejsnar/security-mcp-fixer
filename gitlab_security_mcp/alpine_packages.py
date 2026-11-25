"""Find current Alpine apk package versions compatible with a Dockerfile stage.

Versions come only from Alpine's published ``releases.json`` and the
``APKINDEX.tar.gz`` of one release branch. The branch is, in order:

1. named by an explicit ``alpine:3.x`` or ``*-alpine3.x`` image tag;
2. read from the stage image itself in a public registry: the linux/amd64
   image history's ``alpine-minirootfs-3.x`` entry, or the base layer's
   ``/etc/apk/repositories``;
3. the one supported branch that publishes every exact version the same
   Dockerfile stage already pins.

Nothing is guessed: no evidence, or more than one matching branch, is an error.
Transient network failures of these read-only GETs are retried a bounded
number of times.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import re
import tarfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from time import sleep
from urllib.parse import urlencode

import httpx

from gitlab_security_mcp.fanout import map_ordered
from gitlab_security_mcp.util import share_in_flight, timed_http_stream

_RAISE_DATA_COULD_NOT_BE_READ_FROM = "Data could not be read from {}"
_RAISE_ALPINE_INDEX_EXCEEDS_THE_READ_LIMIT = "Alpine {} {} index exceeds the read limit"
_RAISE_ALPINE_INDEX_LISTS_NO_PACKAGES = "Alpine {} {} index lists no packages"
_RAISE_DOES_NOT_IDENTIFY_EXACTLY_ONE_ALPINE_RELEASE_BASE = "{} does not identify exactly one Alpine release (base-layer /etc/apk/repositories: {})."
_RAISE_RETURNED_AN_UNREADABLE_MANIFEST = "{}/{} returned an unreadable manifest"
_RAISE_UNSUPPORTED_IMAGE_DIGEST_R = "Unsupported image digest {!r}"
_RAISE_BLOB_DOES_NOT_MATCH = "{}/{} blob does not match {}"
_RAISE_THE_REGISTRY_REQUIRES_CREDENTIALS_THE_IMAGE_IS_NOT = (
    "The registry requires credentials; the image is not public"
)
_RAISE_REGISTRY_TOKEN_REALM_R_IS_NOT_ALLOWLISTED = (
    "Registry token realm {!r} is not allowlisted"
)
_RAISE_THE_REGISTRY_DID_NOT_ISSUE_AN_ANONYMOUS_PULL = (
    "The registry did not issue an anonymous pull token"
)
_RAISE_ALPINE_RELEASES_JSON_LISTS_NO_SUPPORTED_BRANCH = (
    "Alpine releases.json lists no supported branch."
)
_RAISE_THE_STAGE_IMAGE_DOES_NOT_NAME_AN_ALPINE = "The stage image does not name an Alpine release and the stage pins no other apk package, so the Alpine branch cannot be identified."
_RAISE_SUPPORTED_ALPINE_BRANCHES_PUBLISHING_EXACTLY_ONE_IS_REQUIRED = "Supported Alpine branches publishing {}: {}. Exactly one is required to choose versions."
_RAISE_ALPINE_INDEX_COULD_NOT_BE_READ = "Alpine {} {} index could not be read: {}"
_RAISE_IS_NOT_PUBLISHED_IN_ALPINE_MAIN_OR_COMMUNITY = (
    "{} is not published in Alpine {} main or community for {}."
)
_RAISE_HAS_AN_UNREADABLE_IMAGE_MANIFEST = "{} has an unreadable image manifest"
_RAISE_HAS_AN_UNREADABLE_IMAGE_CONFIG = "{} has an unreadable image config"
_RAISE_BASE_LAYER_COULD_NOT_BE_READ = "{} base layer could not be read: {}"
_RAISE_THE_REGISTRY_RETURNED_AN_UNREADABLE_TOKEN = (
    "The registry returned an unreadable token"
)
_RAISE_ALPINE_RELEASES_JSON_COULD_NOT_BE_READ = (
    "Alpine releases.json could not be read: {}"
)
_RAISE_ALPINE_PACKAGE_LOOKUP_IS_CLOSED = "Alpine package lookup is closed"
_RAISE_APKINDEX_IS_NOT_A_REGULAR_ARCHIVE_MEMBER = (
    "APKINDEX is not a regular archive member"
)
_RAISE_ALPINE_PUBLISHES_SEVERAL_VERSIONS_NO_SINGLE_LATEST_VERSION = "Alpine {} {} publishes several {} versions ({}); no single latest version was chosen."
_RAISE_HAS_NO_LINUX_AMD64_IMAGE = "{} has no linux/amd64 image"
_RAISE_HTTP = "HTTP {}"
_RAISE_THE_STAGE_IMAGE_COULD_NOT_BE_INSPECTED = (
    "The stage image could not be inspected ({}). {}"
)
_RAISE_EXCEEDS_THE_BYTE_READ_LIMIT = "{} exceeds the {} byte read limit"

logger = logging.getLogger("gitlab_security_mcp")
_LOG_IMAGE_INSPECTION_FOR_FAILED = "Image inspection for %s failed: %s"
_LOG_ALPINE_END_OF_LIFE_STATUS_UNAVAILABLE = "Alpine end-of-life status unavailable: %s"
_LOG_TRANSIENT_READING_RETRYING_ATTEMPT_OF = (
    "Transient %s reading %s (%s); retrying attempt %s of %s"
)
RELEASES_URL = "https://alpinelinux.org/releases.json"
INDEX_URL = (
    "https://dl-cdn.alpinelinux.org/alpine/{branch}/{repo}/{arch}/APKINDEX.tar.gz"
)
ARCH = "x86_64"
REPOSITORIES = ("main", "community")
_MAX_RELEASES = 1024 * 1024
_MAX_ARCHIVE = 16 * 1024 * 1024
_MAX_INDEX = 64 * 1024 * 1024
_MAX_MANIFEST = 4 * 1024 * 1024
_MAX_BASE_LAYER = 64 * 1024 * 1024
_MAX_CACHED_INDEXES = 16
_ATTEMPTS = 4
_BACKOFF_SECONDS = 1.0
_TRANSIENT_STATUS = frozenset({429, 500, 502, 503, 504})
_HTTP_TIMEOUT_SECONDS = 30.0
_MAX_REPOSITORIES_FILE = 64 * 1024
_HTTP_UNAUTHORIZED = 401
_MAX_ERROR_DETAIL = 200
_BRANCH = re.compile(r"v(\d+)\.(\d+)")
_TAG_BRANCH = re.compile(r"alpine-?v?(\d+)\.(\d+)(?:\.\d+)*(?![\d])", re.IGNORECASE)
_PLAIN_VERSION = re.compile(r"v?(\d+)\.(\d+)(?:\.\d+)*")
_MINIROOTFS = re.compile(r"alpine-minirootfs-(\d+)\.(\d+)(?:\.\d+)*-")
_REPOSITORY_LINE = re.compile(r"/alpine/v(\d+)\.(\d+)/(?:main|community)\b")
# Only public registries are contacted for image metadata, never a host taken
# freely from repository content. Token realms must be on these hosts too.
PUBLIC_REGISTRIES = frozenset(
    {
        "registry-1.docker.io",
        "mcr.microsoft.com",
        "ghcr.io",
        "quay.io",
        "public.ecr.aws",
        "gcr.io",
        "registry.k8s.io",
    }
)
_TOKEN_HOSTS = frozenset(
    {"auth.docker.io", "ghcr.io", "quay.io", "public.ecr.aws", "gcr.io"}
)
_MANIFEST_TYPES = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


class AlpineLookupError(ValueError):
    """Alpine release data could not establish one exact current version."""


@dataclass(frozen=True)
class ApkPins:
    """Current versions for unpinned packages and the evidence that chose them."""

    branch: str
    method: str
    versions: dict[str, str]
    repositories: dict[str, str]
    sources: tuple[str, ...]


def branch_from_image(image: str | None) -> str | None:
    """Return ``v3.x`` from an explicit Alpine image tag, never from ``latest``."""
    if not image or "$" in image:
        return None
    reference = image.split("@", 1)[0]
    name, separator, tag = reference.rpartition(":")
    if not separator or "/" in tag:
        return None
    if name.rsplit("/", 1)[-1].lower() == "alpine":
        plain = _PLAIN_VERSION.fullmatch(tag)
        if plain:
            return f"v{plain.group(1)}.{plain.group(2)}"
    matched = _TAG_BRANCH.search(tag)
    return f"v{matched.group(1)}.{matched.group(2)}" if matched else None


def parse_image(image: str | None) -> tuple[str, str, str] | None:
    """Split a public image reference into (registry host, repository, reference).

    Return None for unresolved ARGs, malformed references and registries that
    are not on the public allowlist. Docker Hub short names map to
    ``registry-1.docker.io/library/<name>``.
    """
    if not image or "$" in image or any(char.isspace() for char in image):
        return None
    reference, _at, digest = image.partition("@")
    slash = reference.rfind("/")
    colon = reference.rfind(":")
    if colon > slash:
        name, tag = reference[:colon], reference[colon + 1 :]
    else:
        name, tag = reference, "latest"
    parts = name.split("/")
    if len(parts) > 1 and (
        "." in parts[0] or ":" in parts[0] or parts[0] == "localhost"
    ):
        host, repository = parts[0].lower(), "/".join(parts[1:])
    else:
        host, repository = "registry-1.docker.io", name
    if host in {"docker.io", "index.docker.io"}:
        host = "registry-1.docker.io"
    if host == "registry-1.docker.io" and "/" not in repository:
        repository = f"library/{repository}"
    target = digest or tag
    if (
        host not in PUBLIC_REGISTRIES
        or not re.fullmatch(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*", repository)
        or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}", target)
    ):
        return None
    return host, repository, target


class AlpinePackages:
    """Read Alpine release metadata through one owned or injected HTTP client.

    Indexes are cached per branch and repository for the life of this object,
    and concurrent requests for the same index share one download. An
    injected client stays open; ``close`` releases only an owned client.
    """

    def __init__(
        self,
        *,
        http: httpx.Client | None = None,
        http_log_path: Path | None = None,
        today: Callable[[], date] = date.today,
    ):
        """Retain the client, timing log and clock used to drop end-of-life branches."""
        self._owns_http = http is None
        self.http = (
            http
            if http is not None
            else httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS, follow_redirects=True)
        )
        self.http_log_path = http_log_path
        self._today = today
        self._lock = threading.Lock()
        self._ready = threading.Condition(self._lock)
        self._pending: set[tuple[str, str]] = set()
        self._indexes: dict[tuple[str, str], dict[str, set[str]]] = {}
        self._branches: list[str] | None = None
        self._tokens: dict[tuple[str, str], str] = {}
        self._closed = False

    def close(self) -> None:
        """Drop cached indexes and close an owned HTTP client once."""
        with self._ready:
            if self._closed:
                return
            self._closed = True
            self._ready.wait_for(lambda: not self._pending)
            self._indexes.clear()
        if self._owns_http:
            self.http.close()

    def __enter__(self) -> AlpinePackages:
        """Return this client for a context manager."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the owned HTTP client when the context ends."""
        self.close()

    def latest(
        self, image: str | None, pinned: dict[str, str], names: list[str]
    ) -> ApkPins:
        """Return the current branch version of each name, with its evidence.

        The branch comes from the image tag, then the image itself, then the
        stage's existing pins. Raises AlpineLookupError when the branch cannot be
        identified exactly, a package is not published there, or the official
        data is unreadable after bounded retries.
        """
        sources: list[str] = []
        tagged = branch_from_image(image)
        if tagged is not None:
            branch = tagged
            method = f"Alpine {branch} is named by the stage image tag {image}"
        else:
            inspected = None
            inspection_error = None
            try:
                inspected = self.image_branch(image, sources)
            except AlpineLookupError as exc:
                inspection_error = str(exc)
                logger.warning(
                    _LOG_IMAGE_INSPECTION_FOR_FAILED, image, exc, exc_info=True
                )
            if inspected is not None:
                branch, method = inspected
            else:
                sources.append(RELEASES_URL)
                try:
                    branch, method = self._branch_from_pins(
                        self.supported_branches(), pinned, sources
                    )
                except AlpineLookupError as exc:
                    if inspection_error:
                        raise AlpineLookupError(
                            _RAISE_THE_STAGE_IMAGE_COULD_NOT_BE_INSPECTED.format(
                                inspection_error, exc
                            )
                        ) from exc
                    raise
        versions: dict[str, str] = {}
        repositories: dict[str, str] = {}
        for name in names:
            for repo in REPOSITORIES:
                published = self._index(branch, repo).get(name)
                url = _index_url(branch, repo)
                if url not in sources:
                    sources.append(url)
                if not published:
                    continue
                if len(published) != 1:
                    raise AlpineLookupError(
                        _RAISE_ALPINE_PUBLISHES_SEVERAL_VERSIONS_NO_SINGLE_LATEST_VERSION.format(
                            branch, repo, name, ", ".join(sorted(published))
                        )
                    )
                versions[name] = next(iter(published))
                repositories[name] = repo
                break
            else:
                raise AlpineLookupError(
                    _RAISE_IS_NOT_PUBLISHED_IN_ALPINE_MAIN_OR_COMMUNITY.format(
                        name, branch, ARCH
                    )
                )
        if RELEASES_URL not in sources:
            try:
                if branch not in self.supported_branches():
                    method += "; this branch is past its end-of-life date and receives no updates"
                sources.insert(0, RELEASES_URL)
            except AlpineLookupError as exc:
                logger.warning(
                    _LOG_ALPINE_END_OF_LIFE_STATUS_UNAVAILABLE, exc, exc_info=True
                )
        return ApkPins(branch, method, versions, repositories, tuple(sources))

    def image_branch(
        self, image: str | None, sources: list[str]
    ) -> tuple[str, str] | None:
        """Read the Alpine branch from a public image's linux/amd64 metadata.

        Return None when the reference is not a public registry image. Raise
        AlpineLookupError when the image cannot be read or is not Alpine-based.
        """
        parsed = parse_image(image)
        if parsed is None:
            return None
        host, repository, target = parsed
        manifest = self._registry_json(host, repository, f"manifests/{target}", sources)
        try:
            if "manifests" in manifest:
                platform = next(
                    (
                        item
                        for item in manifest["manifests"]
                        if isinstance(item, dict)
                        and (item.get("platform") or {}).get("os") == "linux"
                        and (item.get("platform") or {}).get("architecture") == "amd64"
                    ),
                    None,
                )
                if platform is None:
                    raise AlpineLookupError(
                        _RAISE_HAS_NO_LINUX_AMD64_IMAGE.format(image)
                    )
                manifest = self._registry_json(
                    host, repository, f"manifests/{platform['digest']}", sources
                )
            config_digest = manifest["config"]["digest"]
            base_digest = manifest["layers"][0]["digest"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AlpineLookupError(
                _RAISE_HAS_AN_UNREADABLE_IMAGE_MANIFEST.format(image)
            ) from exc
        try:
            config = json.loads(
                self._registry_blob(
                    host, repository, config_digest, _MAX_MANIFEST, sources
                )
            )
            history = config.get("history") or []
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
            raise AlpineLookupError(
                _RAISE_HAS_AN_UNREADABLE_IMAGE_CONFIG.format(image)
            ) from exc
        for entry in history if isinstance(history, list) else []:
            matched = _MINIROOTFS.search(
                str((entry if isinstance(entry, dict) else {}).get("created_by") or "")
            )
            if matched:
                branch = f"v{matched.group(1)}.{matched.group(2)}"
                return (
                    branch,
                    f"Alpine {branch} is the release of the stage image {image} "
                    f"(linux/amd64 history: {matched.group(0).rstrip('-')})",
                )
        layer = self._registry_blob(
            host, repository, base_digest, _MAX_BASE_LAYER, sources
        )
        try:
            with tarfile.open(fileobj=io.BytesIO(layer), mode="r:*") as archive:
                member = archive.extractfile("etc/apk/repositories")
                text = (
                    member.read(_MAX_REPOSITORIES_FILE).decode("utf-8", "replace")
                    if member
                    else ""
                )
        except KeyError:
            text = ""
        except (tarfile.TarError, EOFError, OSError) as exc:
            raise AlpineLookupError(
                _RAISE_BASE_LAYER_COULD_NOT_BE_READ.format(image, type(exc).__name__)
            ) from exc
        branches = {f"v{a}.{b}" for a, b in _REPOSITORY_LINE.findall(text)}
        if len(branches) != 1:
            raise AlpineLookupError(
                _RAISE_DOES_NOT_IDENTIFY_EXACTLY_ONE_ALPINE_RELEASE_BASE.format(
                    image, ", ".join(sorted(branches)) or "none"
                )
            )
        branch = branches.pop()
        return (
            branch,
            f"Alpine {branch} is the release in the stage image {image} "
            "(linux/amd64 base layer /etc/apk/repositories)",
        )

    def _registry_json(
        self, host: str, repository: str, path: str, sources: list[str]
    ) -> dict:
        """Read one registry manifest as JSON, answering an anonymous token challenge."""
        body = self._registry_get(
            host, repository, path, _MAX_MANIFEST, {"Accept": _MANIFEST_TYPES}, sources
        )
        try:
            data = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AlpineLookupError(
                _RAISE_RETURNED_AN_UNREADABLE_MANIFEST.format(host, repository)
            ) from exc
        if not isinstance(data, dict):
            raise AlpineLookupError(
                _RAISE_RETURNED_AN_UNREADABLE_MANIFEST.format(host, repository)
            )
        return data

    def _registry_blob(
        self, host: str, repository: str, digest: str, limit: int, sources: list[str]
    ) -> bytes:
        """Read one content-addressed blob and reject bytes that do not match its digest."""
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(digest)):
            raise AlpineLookupError(_RAISE_UNSUPPORTED_IMAGE_DIGEST_R.format(digest))
        body = self._registry_get(
            host, repository, f"blobs/{digest}", limit, {}, sources
        )
        if "sha256:" + hashlib.sha256(body).hexdigest() != digest:
            raise AlpineLookupError(
                _RAISE_BLOB_DOES_NOT_MATCH.format(host, repository, digest)
            )
        return body

    def _registry_get(
        self,
        host: str,
        repository: str,
        path: str,
        limit: int,
        headers: dict[str, str],
        sources: list[str],
    ) -> bytes:
        """GET from a public registry, fetching one anonymous pull token if challenged."""
        url = f"https://{host}/v2/{repository}/{path}"
        if url not in sources:
            sources.append(url)
        token_key = (host, repository)
        with self._lock:
            token = self._tokens.get(token_key)
        request_headers = dict(headers)
        if token:
            request_headers["Authorization"] = f"Bearer {token}"
        status, response_headers, body = self._get(
            url,
            limit,
            source="registry",
            headers=request_headers,
            allow=frozenset({_HTTP_UNAUTHORIZED}),
        )
        if status != _HTTP_UNAUTHORIZED:
            return body
        token = self._anonymous_token(
            response_headers.get("WWW-Authenticate", ""), repository
        )
        with self._lock:
            self._tokens[token_key] = token
        status, _headers, body = self._get(
            url,
            limit,
            source="registry",
            headers={**headers, "Authorization": f"Bearer {token}"},
        )
        return body

    def _anonymous_token(self, challenge: str, repository: str) -> str:
        """Request a pull-only anonymous token from an allowlisted realm."""
        if not challenge.lower().startswith("bearer "):
            raise AlpineLookupError(
                _RAISE_THE_REGISTRY_REQUIRES_CREDENTIALS_THE_IMAGE_IS_NOT
            )
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = httpx.URL(fields.get("realm", ""))
        if (
            realm.scheme != "https"
            or realm.host not in _TOKEN_HOSTS | PUBLIC_REGISTRIES
        ):
            raise AlpineLookupError(
                _RAISE_REGISTRY_TOKEN_REALM_R_IS_NOT_ALLOWLISTED.format(realm.host)
            )
        query = {"scope": f"repository:{repository}:pull"}
        if fields.get("service"):
            query["service"] = fields["service"]
        _status, _headers, body = self._get(
            f"{realm}?{urlencode(query)}", _MAX_RELEASES, source="registry"
        )
        try:
            data = json.loads(body)
            token = data.get("token") or data.get("access_token")
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
            raise AlpineLookupError(
                _RAISE_THE_REGISTRY_RETURNED_AN_UNREADABLE_TOKEN
            ) from exc
        if not isinstance(token, str) or not token:
            raise AlpineLookupError(_RAISE_THE_REGISTRY_DID_NOT_ISSUE_AN_ANONYMOUS_PULL)
        return token

    def supported_branches(self) -> list[str]:
        """Return stable branches that have not reached end of life, newest first."""
        key = ("releases.json", "")
        with self._ready:
            self._ready.wait_for(lambda: key not in self._pending)
            if self._branches is not None:
                return list(self._branches)
            self._pending.add(key)
        try:
            branches = self._read_branches()
            with self._ready:
                self._branches = branches
            return list(branches)
        finally:
            with self._ready:
                self._pending.discard(key)
                self._ready.notify_all()

    def _read_branches(self) -> list[str]:
        """Download releases.json and keep branches whose end of life is in the future."""
        raw = self._download(RELEASES_URL, _MAX_RELEASES)
        try:
            data = json.loads(raw.decode("utf-8"))
            entries = data["release_branches"]
            today = self._today().isoformat()
            branches = [
                entry["rel_branch"]
                for entry in entries
                if isinstance(entry, dict)
                and _BRANCH.fullmatch(str(entry.get("rel_branch")))
                and (not entry.get("eol_date") or str(entry["eol_date"]) >= today)
            ]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AlpineLookupError(
                _RAISE_ALPINE_RELEASES_JSON_COULD_NOT_BE_READ.format(type(exc).__name__)
            ) from exc
        branches.sort(
            key=lambda value: tuple(
                int(part) for part in _BRANCH.fullmatch(value).groups()
            ),
            reverse=True,
        )
        if not branches:
            raise AlpineLookupError(
                _RAISE_ALPINE_RELEASES_JSON_LISTS_NO_SUPPORTED_BRANCH
            )
        return branches

    def _branch_from_pins(
        self, supported: list[str], pinned: dict[str, str], sources: list[str]
    ) -> tuple[str, str]:
        """Choose the one supported branch that publishes every existing pin."""
        if not pinned:
            raise AlpineLookupError(_RAISE_THE_STAGE_IMAGE_DOES_NOT_NAME_AN_ALPINE)

        def matches(branch: str) -> bool:
            """Check every pin against main, then community only when needed."""
            for name, version in pinned.items():
                found = False
                for repo in REPOSITORIES:
                    if version in self._index(branch, repo).get(name, set()):
                        found = True
                        break
                if not found:
                    return False
            return True

        results = map_ordered(matches, supported)
        for branch in supported:
            for repo in REPOSITORIES:
                key = (branch, repo)
                with self._lock:
                    loaded = key in self._indexes
                if loaded and _index_url(branch, repo) not in sources:
                    sources.append(_index_url(branch, repo))
        found = [branch for branch, ok in zip(supported, results, strict=True) if ok]
        evidence = ", ".join(
            f"{name}={version}" for name, version in sorted(pinned.items())
        )
        if len(found) != 1:
            raise AlpineLookupError(
                _RAISE_SUPPORTED_ALPINE_BRANCHES_PUBLISHING_EXACTLY_ONE_IS_REQUIRED.format(
                    evidence, ", ".join(found) or "none"
                )
            )
        return (
            found[0],
            f"Alpine {found[0]} is the only supported branch that publishes the stage's existing pins {evidence}",
        )

    def _index(self, branch: str, repo: str) -> dict[str, set[str]]:
        """Return one parsed index, sharing an in-flight download with other threads."""
        key = (branch, repo)

        def reject() -> None:
            """Stop a new download after close has begun."""
            if self._closed:
                raise AlpineLookupError(_RAISE_ALPINE_PACKAGE_LOOKUP_IS_CLOSED)

        def fetch() -> dict[str, set[str]]:
            """Download and parse this index outside the cache lock."""
            return _parse_index(
                self._download(_index_url(branch, repo), _MAX_ARCHIVE), branch, repo
            )

        return share_in_flight(
            self._ready,
            self._pending,
            self._indexes,
            key,
            fetch,
            max_entries=_MAX_CACHED_INDEXES,
            reject=reject,
        )

    def _download(self, url: str, limit: int) -> bytes:
        """Read one bounded official response and log its timing."""
        _status, _headers, body = self._get(url, limit, source="alpine")
        return body

    def _get(
        self,
        url: str,
        limit: int,
        *,
        source: str,
        headers: dict[str, str] | None = None,
        allow: frozenset[int] = frozenset(),
    ) -> tuple[int, httpx.Headers, bytes]:
        """GET a bounded body, retrying only transient failures of this read.

        Connection errors, timeouts, HTTP 429 and 5xx receive at most four
        attempts with 1, 2 and 4 second backoffs. Other HTTP errors fail
        immediately unless the caller allows that status, such as a registry's
        401 challenge. The underlying error text is logged for diagnosis.
        """
        for attempt in range(_ATTEMPTS):
            if self._closed:
                raise AlpineLookupError(_RAISE_ALPINE_PACKAGE_LOOKUP_IS_CLOSED)
            try:
                with timed_http_stream(
                    self.http,
                    "GET",
                    url,
                    source=source,
                    log_path=self.http_log_path,
                    headers={"User-Agent": "gitlab-security-mcp", **(headers or {})},
                ) as response:
                    if response.status_code in _TRANSIENT_STATUS:
                        raise httpx.HTTPStatusError(
                            _RAISE_HTTP.format(response.status_code),
                            request=response.request,
                            response=response,
                        )
                    if response.status_code not in allow:
                        response.raise_for_status()
                    chunks = []
                    size = 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > limit:
                            raise AlpineLookupError(
                                _RAISE_EXCEEDS_THE_BYTE_READ_LIMIT.format(url, limit)
                            )
                        chunks.append(chunk)
                    return response.status_code, response.headers, b"".join(chunks)
            except httpx.HTTPError as exc:
                transient = isinstance(exc, httpx.TransportError) or (
                    isinstance(exc, httpx.HTTPStatusError)
                    and exc.response.status_code in _TRANSIENT_STATUS
                )
                detail = str(exc)[:_MAX_ERROR_DETAIL] or type(exc).__name__
                if not transient or attempt == _ATTEMPTS - 1:
                    raise AlpineLookupError(
                        f"Data could not be read from {url}: {type(exc).__name__} ({detail})"
                        + (f" after {attempt + 1} attempts" if transient else "")
                        + "."
                    ) from exc
                logger.warning(
                    _LOG_TRANSIENT_READING_RETRYING_ATTEMPT_OF,
                    type(exc).__name__,
                    url,
                    detail,
                    attempt + 2,
                    _ATTEMPTS,
                    exc_info=True,
                )
                sleep(_BACKOFF_SECONDS * 2**attempt)
        raise AlpineLookupError(_RAISE_DATA_COULD_NOT_BE_READ_FROM.format(url))


def _index_url(branch: str, repo: str) -> str:
    """Build the official x86_64 index URL for one branch repository."""
    return INDEX_URL.format(branch=branch, repo=repo, arch=ARCH)


def _parse_index(raw: bytes, branch: str, repo: str) -> dict[str, set[str]]:
    """Map package names to published versions without writing archive members."""
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            member = archive.extractfile("APKINDEX")
            if member is None:
                raise AlpineLookupError(_RAISE_APKINDEX_IS_NOT_A_REGULAR_ARCHIVE_MEMBER)
            text = member.read(_MAX_INDEX + 1)
    except (tarfile.TarError, KeyError, EOFError, OSError) as exc:
        raise AlpineLookupError(
            _RAISE_ALPINE_INDEX_COULD_NOT_BE_READ.format(
                branch, repo, type(exc).__name__
            )
        ) from exc
    if len(text) > _MAX_INDEX:
        raise AlpineLookupError(
            _RAISE_ALPINE_INDEX_EXCEEDS_THE_READ_LIMIT.format(branch, repo)
        )
    packages: dict[str, set[str]] = {}
    for record in text.decode("utf-8", errors="replace").split("\n\n"):
        fields = {
            line[0]: line[2:]
            for line in record.splitlines()
            if len(line) > 2 and line[1] == ":"
        }
        if fields.get("P") and fields.get("V"):
            packages.setdefault(fields["P"], set()).add(fields["V"])
    if not packages:
        raise AlpineLookupError(
            _RAISE_ALPINE_INDEX_LISTS_NO_PACKAGES.format(branch, repo)
        )
    return packages
