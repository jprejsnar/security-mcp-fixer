"""Cover previously untested branches in the smaller library modules."""

import json
import os
import sys
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from xml.etree.ElementTree import ParseError

import httpx
import pytest

from gitlab_security_mcp import package_releases, security_artifacts, util
from gitlab_security_mcp.ai_source_review import SourceEvidence, cited_lines
from gitlab_security_mcp.commands import CommandResult, progress_sink
from gitlab_security_mcp.git_ops import (
    GitOps,
    gitlab_project_from_remote,
    is_metadata_path,
    meaningful_status,
)
from gitlab_security_mcp.gitlab_client import (
    _GITLAB_BACKOFF_SECONDS,
    GitLabClient,
    _response_excerpt,
    _retry_wait,
)
from gitlab_security_mcp.official_docs import (
    DocSource,
    OfficialDocs,
    _unique,
)
from gitlab_security_mcp.package_releases import (
    MAX_RELEASE_BYTES,
    release_catalog,
    reviewed_selection,
)
from gitlab_security_mcp.progress import mirror_directory
from gitlab_security_mcp.report import (
    _dismissal_summary,
    _unit_test_validation,
    _validation_caveats,
    render,
    write_unresolved_report,
)
from gitlab_security_mcp.security_artifacts import (
    _record_failure,
    _snapshot,
    archive_run_logs,
    review_security_artifacts,
)
from gitlab_security_mcp.software_audit import (
    REVIEW_PHASES,
    audit_has_no_findings,
    audit_inventory,
    audit_items,
    audit_report_path,
    persist_audit_draft,
    record_audit_coverage,
)
from gitlab_security_mcp.source_findings import (
    _MAX_APPROVAL_REASON,
    MAX_SOURCE_BYTES,
    _page_line,
    _read_source,
    assess_source,
)
from gitlab_security_mcp.state import RunState

API_URL = "https://gitlab.example/api/v4"
API_WITH_QUERY = "https://gitlab.example/api/v4?token=1"
SSH_REMOTE = "git@gitlab.example:group/project.git"
BROKEN_REMOTE = "gitlab.example/group/project"
METADATA = "./.security-mcp/progress.json"
TRACKED_EDIT = " M src/app.py"
BLANK_STATUS = "\n" + TRACKED_EDIT
NOT_A_TREE = "false"
RELATIVE_GIT = ".git"
MERGE_HEAD = "MERGE_HEAD"
TOKEN = "local-token"
RETRY_HEADER = "soon"
RETRY_SECONDS = "2"
EXCERPT_LIMIT = 8
PAGE_NAME = "Docker"
PAGE_URL = "https://docs.docker.com/reference/"
PAGE_MARKER = "Dockerfile"
OTHER_HOST = "example.com"
PROGRESS_DIR = "progress-override"
PACKAGE = "com.example:demo"
NPM_PACKAGE = "left-pad"
NUGET_PACKAGE = "Newtonsoft.Json"
STABLE = "1.2.3"
FLOOR = "1.2.0"
ASSESSMENT = "The publisher documents this stable release for the project runtime."
SOURCE_URL = "https://docs.example/support"
FINDING_ID = "DEP-1"
SOURCE_ID = "SAST-1"
RELATIVE = "src/App.java"
SOURCE_LINE = "return input;"
SELECTABLE = "### Selectable findings"
NEXT_SECTION = "### Other"
ITEM_ID = "AB"
ITEM_LINE = f"- {ITEM_ID} | high | {RELATIVE} | opens a file"
EMPTY_FINDINGS = "No selectable findings."
UNKNOWN_PHASE = "not-a-phase"
PHASE = "entry_points"
AUDIT_NOTE = "Reviewed the cited method and its callers."
SHORT_STAMP = "not-a-stamp"
TASK_NAME = "catalog"
LOCK_NAME = "state"
KIND = "fanout"
UNSAFE_TOKEN = "../secret"
SAFE_LABEL = "package"
OVERSIZED_STATE = 20_000_001
DISMISSAL_STATUS = "UNCONFIRMED"
FAILURE_STATUS = "FAILED"
ADVISORY_SOURCE = "advisory"
NOT_FOUND = 404
SERVER_ERROR = 500
LOG_LEVEL = "ERROR"


def _result(stdout, truncated=False):
    """Build one allowlisted command result."""
    return CommandResult(
        ["git"],
        0,
        stdout,
        "",
        0,
        truncated,
        "stdout",
        "stderr",
    )


class _Runner:
    """Return one scripted git result."""

    def __init__(self, result):
        """Store the result every git call receives."""
        self.result = result

    def run(self, _args, timeout, check):
        """Ignore the allowlist and return the scripted result."""
        return self.result


class _Clock:
    """Return one file-name stamp instead of the wall clock."""

    def __init__(self, stamp):
        """Store the stamp strftime will return."""
        self.stamp = stamp

    def astimezone(self, _zone):
        """Stay on the scripted clock."""
        return self

    def strftime(self, _fmt):
        """Return the scripted stamp."""
        return self.stamp


class _Bytes:
    """Stand in for an HTTP body the catalog reader consumes."""

    def __init__(self, payload):
        """Store the response bytes."""
        self.payload = payload

    def raise_for_status(self):
        """Report a successful catalog response."""

    def iter_bytes(self):
        """Yield the whole body as one chunk."""
        yield self.payload


@contextmanager
def _catalog(monkeypatch, payload):
    """Serve catalog bytes without opening a network connection."""

    @contextmanager
    def stream(*_args, **_kwargs):
        """Yield the scripted body."""
        yield _Bytes(payload)

    monkeypatch.setattr(package_releases, "timed_http_stream", stream)
    yield


def _review():
    """Build the minimum publisher evidence a selection accepts."""
    return {
        "supported": True,
        "runtime_compatible": True,
        "assessment": ASSESSMENT,
        "sources": [SOURCE_URL],
        "excluded_releases": [],
    }


def test_git_metadata_and_remote_rejection_keep_the_checkout_unchanged():
    """Ignore metadata status and refuse an API URL or remote that is not trusted."""
    # Arrange
    porcelain = BLANK_STATUS + "\n?? " + METADATA

    # Act
    metadata = is_metadata_path(METADATA)
    dirty = meaningful_status(porcelain)
    with pytest.raises(ValueError):
        gitlab_project_from_remote(SSH_REMOTE, API_WITH_QUERY)
    with pytest.raises(ValueError):
        gitlab_project_from_remote(BROKEN_REMOTE, API_URL)

    # Assert
    assert metadata is True
    assert dirty == [TRACKED_EDIT]


def test_git_ops_rejects_a_non_worktree_and_an_in_progress_or_truncated_index(tmp_path):
    """A checkout that is not idle cannot start a security branch."""
    # Arrange
    idle = GitOps(tmp_path, _Runner(_result(NOT_A_TREE)))
    git_dir = tmp_path / RELATIVE_GIT
    git_dir.mkdir()
    (git_dir / MERGE_HEAD).write_text("", encoding="utf-8")
    busy = GitOps(tmp_path, _Runner(_result(RELATIVE_GIT)))
    truncated = GitOps(tmp_path, _Runner(_result("tracked\0", truncated=True)))

    # Act
    with pytest.raises(RuntimeError):
        idle.ensure_work_tree()
    operation = busy.in_progress_operation()
    with pytest.raises(RuntimeError):
        truncated.tracked_security_paths()

    # Assert
    assert operation == MERGE_HEAD


def test_progress_mirror_uses_the_home_cache_without_an_override(monkeypatch):
    """The editor mirror has a home location when no override is configured."""
    # Arrange
    monkeypatch.delenv("GITLAB_SECURITY_PROGRESS_DIR", raising=False)

    # Act
    path = mirror_directory()

    # Assert
    assert path.name == "progress"
    assert "gitlab-security-mcp" in path.parts


def test_audit_inventory_skips_locks_and_records_only_current_hashes(tmp_path):
    """Generated and lock files stay out of the audit, and a stale hash is rejected."""
    # Arrange
    source = tmp_path / RELATIVE
    source.parent.mkdir()
    source.write_text(SOURCE_LINE, encoding="utf-8")
    (tmp_path / "yarn.lock").write_text("lock", encoding="utf-8")
    (tmp_path / "app.min.js").write_text("min", encoding="utf-8")
    coverage = {
        "files": [],
        "reviews": {},
        "completed_phases": [],
        "generated_exclusions": [],
    }
    report = tmp_path / "report.md"
    text = "\n".join(
        [
            SELECTABLE,
            ITEM_LINE,
            ITEM_LINE,
            EMPTY_FINDINGS,
            NEXT_SECTION,
            SELECTABLE,
            EMPTY_FINDINGS,
            NEXT_SECTION,
        ]
    )

    # Act
    inventory = audit_inventory(tmp_path)
    with pytest.raises(ValueError):
        persist_audit_draft(report, tmp_path, coverage)
    with pytest.raises(ValueError):
        record_audit_coverage(tmp_path, coverage, [], [UNKNOWN_PHASE])
    with pytest.raises(ValueError):
        record_audit_coverage(
            tmp_path,
            coverage,
            [{"path": RELATIVE, "sha256": TOKEN, "assessment": AUDIT_NOTE}],
            [PHASE],
        )
    items = audit_items(text)
    empty = audit_has_no_findings(text.split(NEXT_SECTION, 1)[1])
    with pytest.raises(ValueError):
        audit_report_path("project", _Clock(SHORT_STAMP))

    # Assert
    assert UNKNOWN_PHASE not in REVIEW_PHASES
    assert inventory["files"] == [RELATIVE]
    assert items == [
        {
            "id": ITEM_ID,
            "severity": "high",
            "location": RELATIVE,
            "problem": "opens a file",
        }
    ]
    assert empty is True


def test_source_review_rejects_a_missing_oversized_or_incomplete_file(tmp_path):
    """Source review stops when the cited file or the host attestation is unusable."""
    # Arrange
    source = tmp_path / RELATIVE
    source.parent.mkdir()
    source.write_text(SOURCE_LINE + "\n", encoding="utf-8")
    huge = tmp_path / "huge.txt"
    huge.write_bytes(b"x" * (MAX_SOURCE_BYTES + 1))
    missing = {"location": {}}
    bad_line = {"location": {"file": RELATIVE, "startLine": 0}}
    present = {"location": {"file": RELATIVE, "startLine": 1}}
    page = {"ok": False, "error": "offline"}

    # Act
    with pytest.raises(ValueError):
        _read_source(tmp_path, "missing.java")
    with pytest.raises(ValueError):
        _read_source(tmp_path, "huge.txt")
    missing_review = assess_source(tmp_path, missing)
    bad_review = assess_source(tmp_path, bad_line)
    invalid_review = assess_source(tmp_path, present, review="not-an-object")
    available = _page_line(PAGE_NAME, PAGE_URL, {"ok": True, "sha256": TOKEN})
    failed = _page_line(PAGE_NAME, PAGE_URL, page)
    skipped = _page_line(PAGE_NAME, PAGE_URL, None)

    # Assert
    assert missing_review["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert bad_review["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert invalid_review["decision"] == "SOURCE_REVIEW_REQUIRED"
    assert PAGE_URL in available
    assert "offline" in failed
    assert "not retrieved" in skipped
    assert len("x" * (_MAX_APPROVAL_REASON + 1)) > _MAX_APPROVAL_REASON


def test_release_catalog_and_review_reject_mismatched_or_unsupported_evidence(
    monkeypatch,
):
    """A catalog is usable only when it matches the package and the review cites HTTPS."""
    # Arrange
    maven = (
        b"<metadata><groupId>other</groupId><artifactId>demo</artifactId></metadata>"
    )
    npm = json.dumps({"name": "other", "versions": {}}).encode()
    nuget = json.dumps({"versions": [1]}).encode()
    review = _review()
    review["sources"] = ["http://docs.example/support"]

    # Act
    with _catalog(monkeypatch, maven):
        with pytest.raises(ValueError):
            release_catalog("Maven", PACKAGE)
    with _catalog(monkeypatch, npm):
        with pytest.raises(ValueError):
            release_catalog("npm", NPM_PACKAGE)
    with _catalog(monkeypatch, nuget):
        with pytest.raises(ValueError):
            release_catalog("NuGet", NUGET_PACKAGE)
    with pytest.raises(ValueError):
        reviewed_selection(
            {"versions": [STABLE], "source": SOURCE_URL}, "later", _review()
        )
    with pytest.raises(ValueError):
        reviewed_selection({"versions": [STABLE], "source": SOURCE_URL}, FLOOR, review)

    # Assert
    assert MAX_RELEASE_BYTES > 0


def test_catalog_size_and_shape_failures_are_rejected(monkeypatch):
    """Oversized, non-object, and prerelease-only catalogs are not selectable."""
    # Arrange
    oversized = b"{" + b"x" * MAX_RELEASE_BYTES
    array = b"[]"
    preview = json.dumps(
        {"versions": [f"{STABLE}-alpha"], "name": NPM_PACKAGE}
    ).encode()

    # Act
    with _catalog(monkeypatch, oversized):
        with pytest.raises(ValueError):
            release_catalog("NuGet", NUGET_PACKAGE)
    with _catalog(monkeypatch, array):
        with pytest.raises(ValueError):
            release_catalog("NuGet", NUGET_PACKAGE)
    with _catalog(monkeypatch, preview):
        with pytest.raises((ValueError, ParseError)):
            release_catalog("npm", NPM_PACKAGE)
    with pytest.raises(ValueError):
        reviewed_selection({"versions": [STABLE], "source": SOURCE_URL}, FLOOR, [])
    with pytest.raises(ValueError):
        reviewed_selection(
            {"versions": [STABLE], "source": SOURCE_URL},
            FLOOR,
            {**_review(), "supported": False},
        )
    with pytest.raises(ValueError):
        reviewed_selection(
            {"versions": [STABLE], "source": SOURCE_URL},
            FLOOR,
            {**_review(), "excluded_releases": "none"},
        )

    # Assert
    assert preview.startswith(b"{")


def test_security_artifacts_reject_links_and_unreadable_prior_state(
    tmp_path, monkeypatch
):
    """Cleanup stops for a link, a non-file, or a prior run that did not succeed."""
    # Arrange
    root = tmp_path / ".security-mcp"
    root.mkdir()
    state = root / "run-state.json"
    state.write_text(
        json.dumps({"gitlab_dismissals": [{"status": DISMISSAL_STATUS}]}),
        encoding="utf-8",
    )
    log = root / "audit.jsonl"
    log.write_text(json.dumps({"status": FAILURE_STATUS}) + "\n", encoding="utf-8")

    # Act
    missing = _snapshot(tmp_path / "absent")
    try:
        monkeypatch.setattr(Path, "is_symlink", lambda _self: True)
        with pytest.raises(ValueError):
            _snapshot(root)
        monkeypatch.setattr(Path, "is_symlink", lambda _self: False)
        monkeypatch.setattr(Path, "is_dir", lambda _self: False)
        monkeypatch.setattr(Path, "is_file", lambda _self: True)
        with pytest.raises(ValueError):
            _snapshot(root)
        monkeypatch.setattr(Path, "is_file", lambda _self: False)
        with pytest.raises(ValueError):
            _snapshot(root)
    finally:
        monkeypatch.undo()
    command = _record_failure({"exit_code": 1})
    http = _record_failure({"source": ADVISORY_SOURCE, "status_code": NOT_FOUND})
    failed_http = _record_failure({"status_code": SERVER_ERROR})
    logged = _record_failure({"level": LOG_LEVEL})
    reviewed = review_security_artifacts(tmp_path)
    with pytest.raises(ValueError):
        archive_run_logs(tmp_path, "project", _Clock(SHORT_STAMP))

    # Act
    real_zip = security_artifacts.zipfile.ZipFile

    def fail_zip(*_args, **_kwargs):
        """Fail after the temporary archive has been created."""
        raise OSError("disk full")

    monkeypatch.setattr(security_artifacts.zipfile, "ZipFile", fail_zip)
    with pytest.raises(OSError):
        archive_run_logs(tmp_path, "project", datetime.now(UTC))
    monkeypatch.setattr(security_artifacts.zipfile, "ZipFile", real_zip)

    # Assert
    assert missing == {}
    assert command.startswith("Command exited")
    assert http is None
    assert failed_http.startswith("HTTP")
    assert logged.startswith("Error-level")
    assert reviewed["error_count"] >= 1


def test_reports_include_dismissal_details_and_unresolved_blockers(tmp_path):
    """The final report keeps failed tests, caveats, and unselected audit items."""
    # Arrange
    dismissal = {
        "id": FINDING_ID,
        "status": "ERROR",
        "error": "GitLab did not confirm the dismissal",
        "tracked_ref": {"name": "main"},
        "vulnerability_url": API_URL,
    }
    state = RunState(
        findings=[
            {
                "id": FINDING_ID,
                "category": "dependency_scanning",
                "title": NPM_PACKAGE,
                "proposedFix": {"ecosystem": "npm", "package": NPM_PACKAGE},
                "packageVersionSelection": {
                    "status": "BLOCKED",
                    "source": SOURCE_URL,
                    "review": {"assessment": ASSESSMENT},
                },
                "remediationDecision": "NO_SAFE_FIX",
            }
        ],
        decisions={FINDING_ID: {"decision": "NO_SAFE_FIX"}},
        validation_results=[
            {
                "kind": "unit_tests",
                "status": "FAILED",
                "command": "pytest",
                "detail": "1 failed",
            },
            {
                "status": "FAILED",
                "required": False,
                "command": "lint",
                "detail": "warning",
                "stdout_log_path": "out.log",
                "diagnostics": {"warning": ["line"]},
            },
        ],
        batch_isolation=[
            {
                "status": "ROLLED_BACK",
                "finding_ids": [FINDING_ID],
                "failures": [{"detail": "build failed", "stderr_log_path": "err.log"}],
            }
        ],
        workflow={
            "blocked": "prechecks failed",
            "jobs": [{"number": 7, "label": "Report", "status": "RUNNING"}],
            "package_reviews": {},
            "code_results": {
                SOURCE_ID: {
                    "origin": "gitlab",
                    "id": SOURCE_ID,
                    "status": "failed",
                    "reason": "test failed",
                    "validation": "pytest",
                }
            },
        },
        software_audit={
            "selected_items": [],
            "items": [{"id": ITEM_ID}],
        },
        report_path=str(tmp_path / "report.md"),
    )

    # Act
    summary = _dismissal_summary(dismissal)
    tests = _unit_test_validation(state)
    caveats = _validation_caveats(state)
    _payload, markdown = render(state, staged=[], diff_stat="", diff_files="")
    written = write_unresolved_report(tmp_path, state)

    # Assert
    assert "Tracked ref" in summary
    assert tests["status"] == "FAILED"
    assert caveats
    assert "stdout_log_path" in markdown
    assert "stderr_log_path" in markdown
    assert "Run blocker" in written["final_summary_markdown"]
    assert written["status"] == "WORKFLOW_COMPLETE"


def test_documentation_progress_and_page_failures_stay_informational(monkeypatch):
    """A progress-sink failure does not hide a page that could not be read."""
    # Arrange
    http = httpx.Client()
    offline_http = httpx.Client()
    docs = OfficialDocs(http=http)
    page = {
        "name": PAGE_NAME,
        "url": PAGE_URL,
        "markers": (PAGE_MARKER,),
        "catalog": True,
    }
    cached = DocSource(PAGE_NAME, PAGE_URL, True, 200, TOKEN, None)

    def fail(_message):
        """Simulate an editor that cannot publish progress."""
        raise OSError("progress")

    token = progress_sink.set(fail)
    monkeypatch.setattr(
        "gitlab_security_mcp.official_docs._pages_for",
        lambda _finding, pages: pages,
    )

    def fail_stream(*_args, **_kwargs):
        """Simulate a publisher page that cannot be fetched."""
        raise httpx.ConnectError("offline")

    # Act
    try:
        review = docs._review(
            {}, [page], {(PAGE_NAME, PAGE_URL, (PAGE_MARKER,)): cached}
        )
        empty = docs._read_page({"name": PAGE_NAME, "url": PAGE_URL, "markers": ()})
        monkeypatch.setattr(
            "gitlab_security_mcp.official_docs.timed_http_stream", fail_stream
        )
        offline = OfficialDocs(http=offline_http)._read_page(
            {"name": PAGE_NAME, "url": PAGE_URL, "markers": (PAGE_MARKER,)}
        )
        redirected = _redirected_page()
        repeated = _unique(["cve-1", "CVE-1"])
    finally:
        progress_sink.reset(token)
        docs.close()
        http.close()
        offline_http.close()

    # Assert
    assert review.sources[0].reused is True
    assert empty.ok is False
    assert offline.ok is False
    assert redirected.ok is False
    assert repeated == ["cve-1"]


def _redirected_page():
    """Read a page whose final host leaves the allowlist."""

    class _Response:
        """Expose a redirected host and an empty hashed body."""

        url = httpx.URL(f"https://{OTHER_HOST}/moved")
        status_code = 200
        encoding = "utf-8"

        def iter_bytes(self):
            """Return no body bytes."""
            yield b""

    @contextmanager
    def stream(*_args, **_kwargs):
        """Yield the redirected response."""
        yield _Response()

    original = OfficialDocs._read_page

    def read(self, page):
        """Call the real reader with the redirected stream installed."""
        return original(self, page)

    from gitlab_security_mcp import official_docs

    official_docs.timed_http_stream = stream
    client = httpx.Client()
    try:
        return OfficialDocs(http=client)._read_page(
            {"name": PAGE_NAME, "url": PAGE_URL, "markers": (PAGE_MARKER,)}
        )
    finally:
        client.close()
        official_docs.timed_http_stream = util.timed_http_stream


def test_gitlab_retry_and_reentrant_close_stay_bounded():
    """An unreadable Retry-After uses backoff, and a second close waits."""
    # Arrange
    unreadable = httpx.Response(429, headers={"Retry-After": RETRY_HEADER})
    short = httpx.Response(429, headers={"Retry-After": RETRY_SECONDS})
    small = httpx.Response(500, content=b"short")
    client = GitLabClient(TOKEN, API_URL)
    client._closing = True
    client._closed = False
    real_wait = client._idle.wait_for

    def finish():
        """Let the waiting close observe that shutdown completed."""
        with client._lock:
            client._closed = True
            client._idle.notify_all()

    def wait_for(predicate, timeout=None):
        """Release the shutdown waiter after it is inside the condition."""
        threading.Thread(target=finish).start()
        return real_wait(predicate, timeout)

    client._idle.wait_for = wait_for

    # Act
    backoff = _retry_wait(unreadable, 1)
    honored = _retry_wait(short, 0)
    excerpt = _response_excerpt(small, limit=EXCERPT_LIMIT)
    client.close()
    client.http.close()

    # Assert
    assert backoff == _GITLAB_BACKOFF_SECONDS * 2
    assert honored == float(RETRY_SECONDS)
    assert excerpt == "short"


def test_utility_logs_and_tokens_fail_closed(monkeypatch, caplog):
    """Memory, log, URL, and token helpers fail closed instead of raising."""
    # Arrange
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(sys, "platform", "linux")
    resource = SimpleNamespace(
        RUSAGE_SELF=0,
        getrusage=lambda _flag: SimpleNamespace(ru_maxrss=2),
    )
    monkeypatch.setitem(sys.modules, "resource", resource)

    def fail_sample():
        """Make the performance sample itself fail."""
        raise RuntimeError("sample")

    def fail_dumps(*_args, **_kwargs):
        """Make the concurrency record unserializable."""
        raise TypeError("dumps")

    # Act
    memory = util._memory_bytes()
    monkeypatch.setattr(sys, "platform", "darwin")
    darwin = util._memory_bytes()
    resource.getrusage = lambda _flag: (_ for _ in ()).throw(OSError("rss"))
    absent = util._memory_bytes()
    monkeypatch.setattr(util, "_performance_sample", fail_sample)
    util._log_performance(TASK_NAME, {})
    monkeypatch.setattr(util.json, "dumps", fail_dumps)
    util.log_concurrency(KIND, LOCK_NAME)

    class _RejectedURL:
        """Stand in for a URL the HTTP client refuses to parse."""

        def __init__(self, *_args, **_kwargs):
            """Reject every value."""
            raise httpx.InvalidURL("bad")

    monkeypatch.setattr(util.httpx, "URL", _RejectedURL)
    invalid = util._http_log_url(PAGE_URL)
    with pytest.raises(ValueError):
        util.safe_token("", label=SAFE_LABEL)
    with pytest.raises(ValueError):
        util.safe_token(UNSAFE_TOKEN, label=SAFE_LABEL)
    with pytest.raises(ParseError):
        util.parse_xml("<!DOCTYPE a [<!ENTITY e SYSTEM 'file:///secret'>]><a/>")

    # Assert
    assert memory == 2 * 1024
    assert darwin == 2
    assert absent is None
    assert invalid == "[invalid URL]"
    assert caplog.records


def test_source_evidence_rejects_a_non_source_file_and_a_missing_citation(tmp_path):
    """Complete-file evidence stays inside permitted source and the cited text."""
    # Arrange
    evidence = SourceEvidence(tmp_path)
    notes = tmp_path / "notes.txt"
    notes.write_text(SOURCE_LINE, encoding="utf-8")
    row = {"path": "notes.txt", "sha256": TOKEN, "cited_text": "missing citation"}

    # Act
    with pytest.raises(ValueError):
        evidence.read("missing.java")
    with pytest.raises(ValueError):
        evidence.read("notes.txt")
    with pytest.raises(ValueError):
        cited_lines(row, SOURCE_LINE)

    # Assert
    assert evidence.reads == {}
