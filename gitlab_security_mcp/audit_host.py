"""Continue an owned, consented audit through documented editor stop hooks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import sys
from pathlib import Path

from gitlab_security_mcp.software_audit import (
    audit_report_is_draft,
    persist_audit_draft,
)
from gitlab_security_mcp.util import atomic_write_text, json_object

_ACTIVE = {
    "GENERATE_AUDIT_REPORT",
    "AUDIT_IN_PROGRESS",
    "AUDIT_INCOMPLETE",
    "ITEMS_REQUIRED",
}
_PREFIX = "[gitlab-security-mcp audit continuation]"


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


def handle_event(host: str, event: str, payload: dict) -> dict:
    """Continue only an audit observed on this session's own live MCP tool call."""
    owner = _session(payload)
    if not owner or payload.get("agent_id") or payload.get("agentId"):
        return {}
    if event == "post":
        name = payload.get("tool_name", payload.get("toolName", ""))
        if not name.endswith(("choose_software_audit_action", "complete_security_run")):
            return {}
    root = _checkout(payload)
    if root is None:
        return {}
    path = _binding_path(root)
    binding = json_object(path.read_text(encoding="utf-8")) if path.is_file() else {}
    owned = binding.get("session") == owner and binding.get("host") == host
    if event == "failure":
        if owned:
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
        and (not state.get("workflow") or state["workflow"].get("current") == 6)
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
    if (host == "cursor" and payload.get("status") != "completed") or payload.get(
        "stop_reason", payload.get("stopReason", "end_turn")
    ) != "end_turn":
        _save_binding(path, {**binding, "active": False})
        return {}
    if binding.get("output_path") != audit.get("output_path"):
        return {}
    report = Path(audit["output_path"])
    coverage = audit.get("coverage") or {}
    persist_audit_draft(report, root, coverage, audit.get("progress"))
    text = report.read_text(encoding="utf-8")
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "reviews": {
                    name: item["sha256"]
                    for name, item in coverage.get("reviews", {}).items()
                },
                "phases": sorted(coverage.get("completed_phases", [])),
                "report": None
                if audit_report_is_draft(text)
                else hashlib.sha256(text.encode()).hexdigest(),
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    attempts = binding.get("attempts", 0)
    if fingerprint == binding.get("fingerprint"):
        raise RuntimeError(
            "Audit continuation stopped: no new review receipts, phases or report content. The audit is incomplete; inspect the host blocker instead of repeatedly asking to continue."
        )
    if attempts >= len(coverage.get("files", [])) + 8 or (
        host == "copilot" and attempts >= 8
    ):
        raise RuntimeError(
            "Audit continuation reached the editor's safe turn budget. The report remains incomplete; host limits must not be bypassed."
        )
    _save_binding(
        path, {**binding, "fingerprint": fingerprint, "attempts": attempts + 1}
    )
    message = (
        f"{_PREFIX} Continue the EXISTING approved audit; do not ask the developer "
        "to type continue. First call choose_software_audit_action with repo_root="
        f"{json.dumps(str(root))} only, and follow its live in-memory handoff. "
        "Saved JSON is not authorization. Do not restart MCP, run prechecks or "
        "create another run. Preserve existing receipts and review only remaining "
        "non-generated first-party inputs. Inspect each project's generator "
        "configuration and exclude all generated outputs before implementation review. "
        f"Write actual audit findings incrementally to {json.dumps(str(report))}; "
        "replace the marked INCOMPLETE draft, finish every file/phase, then call "
        "report_ready=True to open the real unchecked findings window. "
        "Do not change source, tests, dependencies or configuration before human "
        "fix selection. Once the developer selects, follow that live MCP handoff "
        "and fix only checked items. Do not commit or push."
    )
    if host == "cursor":
        return {"followup_message": message}
    if host == "vscode-local":
        return {
            "hookSpecificOutput": {
                "hookEventName": "Stop",
                "decision": "block",
                "reason": message,
            }
        }
    return {"decision": "block", "reason": message}


def install_hooks(home: Path, python: Path) -> list[Path]:
    """Merge dedicated user hooks without replacing existing editor hooks."""
    written = []
    for host, path, events in (
        (
            "cursor",
            home / ".cursor" / "hooks.json",
            {
                "afterMCPExecution": "post",
                "postToolUseFailure": "failure",
                "beforeSubmitPrompt": "prompt",
                "stop": "stop",
            },
        ),
        (
            "copilot",
            home / ".copilot" / "hooks" / "gitlab-security-audit.json",
            {
                "PostToolUse": "post",
                "PostToolUseFailure": "failure",
                "UserPromptSubmit": "prompt",
                "Stop": "stop",
            },
        ),
    ):
        config = (
            json_object(path.read_text(encoding="utf-8"))
            if path.exists()
            else {"version": 1}
        )
        if config.get("version", 1) != 1:
            raise ValueError(f"Unsupported hook configuration version: {path}")
        hooks = config.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            raise ValueError(f"Invalid hooks object: {path}")
        for name, event in events.items():
            args = [
                str(python),
                "-m",
                "gitlab_security_mcp.audit_host",
                "--host",
                host,
                "--event",
                event,
            ]
            command = (
                "& '" + str(python).replace("'", "''") + "' " + " ".join(args[1:])
                if os.name == "nt"
                else shlex.join(args)
            )
            entry = (
                {"command": command, "timeout": 15}
                if host == "cursor"
                else {
                    "type": "command",
                    "powershell" if os.name == "nt" else "bash": command,
                    "timeoutSec": 15,
                }
            )
            if host == "cursor" and event == "stop":
                entry["loop_limit"] = None
            previous = hooks.setdefault(name, [])
            if not isinstance(previous, list):
                raise ValueError(f"Invalid hook event list {name}: {path}")
            hooks[name] = [
                item
                for item in previous
                if "gitlab_security_mcp.audit_host" not in json.dumps(item)
            ] + [entry]
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, json.dumps(config, indent=2) + "\n")
        written.append(path)
    return written


def main() -> None:
    """Read one native hook payload or install the opt-in editor integration."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--host", choices=("cursor", "copilot", "vscode-local"))
    parser.add_argument("--event", choices=("post", "prompt", "stop", "failure"))
    args = parser.parse_args()
    try:
        if args.install:
            for path in install_hooks(Path.home(), Path(sys.executable)):
                print(path)
            return
        if args.host is None or args.event is None:
            parser.error("--host and --event are required for hook execution")
        response = handle_event(args.host, args.event, json_object(sys.stdin.read()))
        print(json.dumps(response))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"GitLab security audit hook: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
