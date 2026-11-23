"""In-memory run state and a local untracked snapshot."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, fields
from pathlib import Path

from gitlab_security_mcp import __version__
from gitlab_security_mcp.util import atomic_write_text

_BACKUP_MANIFESTS = {
    "dependency_before": "dependency_backup_manifest",
    "version_alignment_before": "version_alignment_backup_manifest",
}


@dataclass
class RunState:
    """Everything one remediation run has decided so far.

    The snapshot on disk is for the user to inspect. It is never reloaded,
    so a restarted server must pass the prechecks again.
    """

    status: str = "NOT_STARTED"
    stop_stage: str | None = None
    branch_name: str | None = None
    pipeline: dict | None = None
    findings: list[dict] = field(default_factory=list)
    findings_truncated: bool = False
    decisions: dict[str, dict] = field(default_factory=dict)
    changes: list[dict] = field(default_factory=list)
    false_positives: list[dict] = field(default_factory=list)
    no_solution: list[dict] = field(default_factory=list)
    skipped_user_prompt: list[dict] = field(default_factory=list)
    validation_results: list[dict] = field(default_factory=list)
    validation_status: str | None = None
    report_path: str | None = None
    json_report_path: str | None = None
    excluded_findings: dict = field(default_factory=dict)
    pulls: list | None = None
    lint_baseline: dict | None = None
    manual_cleanup_required: bool = False
    batch_isolation: list[dict] = field(default_factory=list)
    gitlab_project_path: str | None = None
    gitlab_dismissals: list[dict] = field(default_factory=list)
    false_positive_approval_form: dict = field(default_factory=dict)
    fix_selection: dict = field(default_factory=dict)
    software_audit: dict = field(default_factory=dict)
    workflow: dict = field(default_factory=dict)
    server_version: str = __version__

    def save(self, repo_root: Path) -> None:
        """Publish an inspection snapshot, not raw in-memory rollback file contents."""
        path = repo_root / ".security-mcp" / "run-state.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        snapshot = {item.name: getattr(self, item.name) for item in fields(self)}
        snapshot["findings"] = []
        for finding in self.findings:
            inspection = dict(finding)
            for key in ("packageQualification", "localFixAttempt"):
                receipt = finding.get(key)
                if receipt:
                    inspection[key] = {
                        name: value
                        for name, value in receipt.items()
                        if name not in _BACKUP_MANIFESTS
                    }
                    for backup, manifest_key in _BACKUP_MANIFESTS.items():
                        if backup not in receipt:
                            continue
                        manifest = {}
                        for name, original in receipt[backup].items():
                            if original is None:
                                manifest[name] = None
                            else:
                                raw = original.encode("utf-8")
                                manifest[name] = {
                                    "sha256": hashlib.sha256(raw).hexdigest(),
                                    "bytes": len(raw),
                                }
                        inspection[key][manifest_key] = manifest
            snapshot["findings"].append(inspection)
        text = json.dumps(snapshot, indent=2, ensure_ascii=False)
        atomic_write_text(path, text)

    def forget(self, finding_id: str) -> None:
        """Drop every earlier decision for one finding before it is verified again."""
        self.false_positives = [
            item for item in self.false_positives if item.get("id") != finding_id
        ]
        self.no_solution = [
            item for item in self.no_solution if item.get("id") != finding_id
        ]
        self.skipped_user_prompt = [
            item for item in self.skipped_user_prompt if item.get("id") != finding_id
        ]
        self.decisions.pop(finding_id, None)
