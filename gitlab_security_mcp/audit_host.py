"""Continue an owned, consented audit through documented editor stop hooks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from gitlab_security_mcp.software_audit import (
    audit_report_is_draft,
    persist_audit_draft,
)
from gitlab_security_mcp.util import atomic_write_text, json_object

_RAISE_AUDIT_CONTINUATION_STOPPED_NO_NEW_REVIEW_RECEIPTS_PHASES = "Audit continuation stopped: no new review receipts, phases or report content. The audit is incomplete; inspect the host blocker instead of repeatedly asking to continue."
_RAISE_AUDIT_CONTINUATION_REACHED_THE_EDITOR_S_SAFE_TURN = "Audit continuation reached the editor's safe turn budget. The report remains incomplete; host limits must not be bypassed."
_RAISE_THE_HOOK_INTERPRETER_PATH_CONTAINS_A_CHARACTER_THE = "The hook interpreter path contains a character the editor shell cannot quote safely."
_RAISE_UNSUPPORTED_HOOK_CONFIGURATION_VERSION = (
    "Unsupported hook configuration version: {}"
)
_RAISE_INVALID_HOOKS_OBJECT = "Invalid hooks object: {}"
_RAISE_INVALID_HOOK_EVENT_LIST = "Invalid hook event list {}: {}"
_RAISE_HOST_AND_EVENT_REQUIRED = "--host and --event are required for hook execution"

_ACTIVE = {
    "GENERATE_AUDIT_REPORT",
    "AUDIT_IN_PROGRESS",
    "AUDIT_INCOMPLETE",
    "ITEMS_REQUIRED",
}
_PREFIX = "[gitlab-security-mcp audit continuation]"
# Each continuation is a paid host turn; never scale the cap with repository size.
_MAX_CONTINUATIONS = 24
# A turn can end mid-file before a new receipt is written; allow a few retries
# without progress before treating the host as blocked.
_MAX_STALLED_CONTINUATIONS = 2
_AUDIT_TOOLS = ("choose_software_audit_action", "complete_security_run")
_STOP_COMPLETED = "completed"
_HOOK_TIMEOUT_SECONDS = 15
# Workflow job 6 is the software audit.
_AUDIT_WORKFLOW_JOB = 6


@dataclass(frozen=True)
class HostProfile:
    """Describe one editor's native hook contract; shared logic stays host-agnostic."""

    reply: Callable[[str], dict]
    max_turns: int = _MAX_CONTINUATIONS
    requires_completed_status: bool = False
    hook_file: tuple[str, ...] = ()
    events: tuple[tuple[str, str], ...] = ()
    entry: Callable[[str, str], dict] | None = None


def _cursor_entry(command: str, event: str) -> dict:
    """Cursor's stop loop limit must be lifted; the turn cap is enforced here instead."""
    entry = {"command": command, "timeout": _HOOK_TIMEOUT_SECONDS}
    if event == "stop":
        entry["loop_limit"] = None
    return entry


def _copilot_entry(command: str, _event: str) -> dict:
    """Copilot selects its shell by key name."""
    shell = "powershell" if os.name == "nt" else "bash"
    return {"type": "command", shell: command, "timeoutSec": _HOOK_TIMEOUT_SECONDS}


HOSTS: dict[str, HostProfile] = {
    "cursor": HostProfile(
        reply=lambda message: {"followup_message": message},
        requires_completed_status=True,
        hook_file=(".cursor", "hooks.json"),
        events=(
            ("afterMCPExecution", "post"),
            ("postToolUseFailure", "failure"),
            ("beforeSubmitPrompt", "prompt"),
            ("stop", "stop"),
        ),
        entry=_cursor_entry,
    ),
    "copilot": HostProfile(
        reply=lambda message: {"decision": "block", "reason": message},
        max_turns=8,
        hook_file=(".copilot", "hooks", "gitlab-security-audit.json"),
        events=(
            ("PostToolUse", "post"),
            ("PostToolUseFailure", "failure"),
            ("UserPromptSubmit", "prompt"),
            ("Stop", "stop"),
        ),
        entry=_copilot_entry,
    ),
    "vscode-local": HostProfile(
        reply=lambda message: {
            "hookSpecificOutput": {
                "hookEventName": "Stop",
                "decision": "block",
                "reason": message,
            }
        },
    ),
}


def _session(payload: dict) -> str | None:
    """Use a native session identity, never a shared checkout as the owner."""
    return (
        payload.get("conversation_id")
        or payload.get("session_id")
        or payload.get("sessionId")
    )


def _checkout(payload: dict) -> Path | None:
    """Locate only workspaces supplied by the editor's hook event."""
    args = payload.get("tool_input", payload.get("toolArgs", {}))
    if isinstance(args, str):
        args = json_object(args)
    candidates = [
        args.get("repo_root") if isinstance(args, dict) else None,
        *payload.get("workspace_roots", []),
        payload.get("cwd"),
    ]
    for candidate in candidates:
        if not isinstance(candidate, str) or not candidate.strip():
            continue
        path = Path(candidate).resolve()
        for root in (path, *path.parents):
            if (root / ".security-mcp" / "run-state.json").is_file():
                return root
    return None


def _binding_path(root: Path) -> Path:
    """Keep continuation metadata outside the audited working tree."""
    key = hashlib.sha256(os.path.normcase(str(root)).encode()).hexdigest()
    return (
        Path.home() / ".cache" / "gitlab-security-mcp" / "audit-hosts" / f"{key}.json"
    )


def _save_binding(path: Path, binding: dict) -> None:
    """Persist only hook ownership and progress guards, never MCP authorization."""
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(binding, indent=2))


def _fingerprint(coverage: dict, report_text: str) -> str:
    """Identify real review progress so a stalled host is not re-prompted."""
    evidence = {
        "reviews": {
            name: item["sha256"] for name, item in coverage.get("reviews", {}).items()
        },
        "phases": sorted(coverage.get("completed_phases", [])),
        "report": None
        if audit_report_is_draft(report_text)
        else hashlib.sha256(report_text.encode()).hexdigest(),
    }
    return hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()


def _continuation(root: Path, report: Path) -> str:
    """Return the per-turn instruction resent on every continuation."""
    return (
        f"{_PREFIX} Continue the EXISTING approved audit; do not ask the developer "
        "to type continue. First call choose_software_audit_action with repo_root="
        f"{json.dumps(str(root))} only, and follow its live in-memory handoff. "
        "Saved JSON is not authorization. Do not restart MCP, run prechecks or "
        "create another run. Preserve existing receipts and review only remaining "
        "non-generated first-party inputs. Inspect each project's generator "
        "configuration and exclude all generated outputs before implementation review. "
        "Read only the returned next_files; do not reread the audit prompt, the draft "
        "or files with receipts. Then finish every file/phase, write the findings once "
        f"to {json.dumps(str(report))}, replacing the marked INCOMPLETE draft, and call "
        "report_ready=True to open the real unchecked findings window. "
        "Do not change source, tests, dependencies or configuration before human "
        "fix selection. Once the developer selects, follow that live MCP handoff "
        "and fix only checked items. Do not commit or push."
    )


def handle_event(host: str, event: str, payload: dict) -> dict:
    """Continue only an audit observed on this session's own live MCP tool call."""
    profile = HOSTS[host]
    owner = _session(payload)
    if not owner or payload.get("agent_id") or payload.get("agentId"):
        return {}
    if event == "post":
        name = payload.get("tool_name", payload.get("toolName", ""))
        if not name.endswith(_AUDIT_TOOLS):
            return {}
    root = _checkout(payload)
    if root is None:
        return {}
    path = _binding_path(root)
    binding = json_object(path.read_text(encoding="utf-8")) if path.is_file() else {}
    owned = binding.get("session") == owner and binding.get("host") == host
    if event == "failure":
        # Cursor sends this event for every failed tool; a failed shell or file
        # read inside the audit must not cancel the continuation.
        name = payload.get("tool_name", payload.get("toolName", ""))
        if owned and name.endswith(_AUDIT_TOOLS):
            _save_binding(path, {**binding, "active": False})
        return {}
    if event == "prompt":
        if owned and not payload.get("prompt", "").startswith(_PREFIX):
            _save_binding(path, {**binding, "active": False})
        return {}
    state = json_object(
        (root / ".security-mcp" / "run-state.json").read_text(encoding="utf-8")
    )
    audit = state.get("software_audit") or {}
    pending = (
        audit.get("status") in _ACTIVE
        and not audit.get("report_complete")
        and (
            not state.get("workflow")
            or state["workflow"].get("current") == _AUDIT_WORKFLOW_JOB
        )
    )
    if event == "post":
        if not pending or not audit.get("output_path"):
            if owned:
                _save_binding(path, {**binding, "active": False})
            return {}
        same_run = (
            owned
            and binding.get("active")
            and binding.get("output_path") == audit["output_path"]
        )
        binding = {
            **(binding if same_run else {}),
            "host": host,
            "session": owner,
            "active": True,
            "output_path": audit["output_path"],
        }
        persist_audit_draft(
            Path(audit["output_path"]),
            root,
            audit.get("coverage") or {},
            audit.get("progress"),
        )
        _save_binding(path, binding)
        return {}
    if event != "stop" or not owned or not binding.get("active") or not pending:
        return {}
    status = payload.get("status")
    stop_reason = payload.get("stop_reason", payload.get("stopReason", "end_turn"))
    binding = {
        **binding,
        "last_stop": {
            "at": datetime.now(UTC).isoformat(),
            "status": status,
            "stop_reason": stop_reason,
        },
    }
    if (
        profile.requires_completed_status and status != _STOP_COMPLETED
    ) or stop_reason != "end_turn":
        _save_binding(path, {**binding, "active": False})
        return {}
    if binding.get("output_path") != audit.get("output_path"):
        return {}
    report = Path(audit["output_path"])
    coverage = audit.get("coverage") or {}
    persist_audit_draft(report, root, coverage, audit.get("progress"))
    fingerprint = _fingerprint(coverage, report.read_text(encoding="utf-8"))
    attempts = binding.get("attempts", 0)
    stalls = (
        binding.get("stalls", 0) + 1 if fingerprint == binding.get("fingerprint") else 0
    )
    if stalls > _MAX_STALLED_CONTINUATIONS:
        _save_binding(path, {**binding, "active": False, "stalls": stalls})
        raise RuntimeError(
            _RAISE_AUDIT_CONTINUATION_STOPPED_NO_NEW_REVIEW_RECEIPTS_PHASES
        )
    if attempts >= profile.max_turns:
        raise RuntimeError(_RAISE_AUDIT_CONTINUATION_REACHED_THE_EDITOR_S_SAFE_TURN)
    _save_binding(
        path,
        {
            **binding,
            "fingerprint": fingerprint,
            "attempts": attempts + 1,
            "stalls": stalls,
        },
    )
    return profile.reply(_continuation(root, report))


_HOOK_PATH_UNSAFE = re.compile(r"[\x00-\x1f'`]")


def _emit_hook(response: dict) -> None:
    """Write one hook response and flush so the editor reads the stream immediately."""
    sys.stdout.write(json.dumps(response, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def _hook_command(python: Path, host: str, event: str) -> str:
    """Quote the interpreter for the platform shell each editor uses."""
    executable = str(python)
    if _HOOK_PATH_UNSAFE.search(executable):
        raise ValueError(_RAISE_THE_HOOK_INTERPRETER_PATH_CONTAINS_A_CHARACTER_THE)
    args = ["-m", "gitlab_security_mcp.audit_host", "--host", host, "--event", event]
    if os.name == "nt":
        return "& '" + executable.replace("'", "''") + "' " + " ".join(args)
    return shlex.join([executable, *args])


def install_hooks(home: Path, python: Path) -> list[Path]:
    """Merge dedicated user hooks without replacing existing editor hooks."""
    written = []
    for host, profile in HOSTS.items():
        if profile.entry is None:
            continue
        path = home.joinpath(*profile.hook_file)
        config = (
            json_object(path.read_text(encoding="utf-8"))
            if path.exists()
            else {"version": 1}
        )
        if config.get("version", 1) != 1:
            raise ValueError(_RAISE_UNSUPPORTED_HOOK_CONFIGURATION_VERSION.format(path))
        hooks = config.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            raise ValueError(_RAISE_INVALID_HOOKS_OBJECT.format(path))
        for name, event in profile.events:
            previous = hooks.setdefault(name, [])
            if not isinstance(previous, list):
                raise ValueError(_RAISE_INVALID_HOOK_EVENT_LIST.format(name, path))
            hooks[name] = [
                item
                for item in previous
                if "gitlab_security_mcp.audit_host" not in json.dumps(item)
            ] + [profile.entry(_hook_command(python, host, event), event)]
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, json.dumps(config, indent=2) + "\n")
        written.append(path)
    return written


def main() -> None:
    """Read one native hook payload or install the opt-in editor integration."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--host", choices=tuple(HOSTS))
    parser.add_argument("--event", choices=("post", "prompt", "stop", "failure"))
    args = parser.parse_args()
    try:
        if args.install:
            for path in install_hooks(Path.home(), Path(sys.executable)):
                print(path)
            return
        if args.host is None or args.event is None:
            parser.error(_RAISE_HOST_AND_EVENT_REQUIRED)
        response = handle_event(args.host, args.event, json_object(sys.stdin.read()))
        _emit_hook(response)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"GitLab security audit hook: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
