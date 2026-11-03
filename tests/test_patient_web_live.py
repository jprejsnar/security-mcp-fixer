"""Opt-in, read-only integration checks for the patient-web vulnerability report."""

import os
from pathlib import Path

import pytest

from gitlab_security_mcp.advisory import AdvisoryClient
from gitlab_security_mcp.engine import Engine
from gitlab_security_mcp.gitlab_client import GitLabClient

PATIENT_WEB_PROJECT = "clario-clinical/NxT/ecoa-swift/patient-web/patient-web"


@pytest.fixture(scope="module")
def patient_web_findings(request):
    """Retrieve filtered findings only with explicit live-test credentials.

    Skip ordinary offline runs. Fail rather than silently skip when a live
    run lacks its required token or returns unreadable/incomplete findings.
    """
    if not request.config.getoption("--patient-web-live"):
        pytest.skip("Use --patient-web-live to enable private GitLab and public advisory requests")
    token = os.environ.get("GITLAB_TOKEN") or os.environ.get("GITLAB_PERSONAL_ACCESS_TOKEN")
    if not token:
        pytest.fail("Set GITLAB_TOKEN or GITLAB_PERSONAL_ACCESS_TOKEN in the test process environment", pytrace=False)

    with GitLabClient(token, os.environ.get("GITLAB_API_URL", "https://gitlab.com/api/v4")) as client:
        fetched = client.fetch(PATIENT_WEB_PROJECT)

    assert fetched.ok, fetched.error
    assert fetched.project_path == PATIENT_WEB_PROJECT
    assert not fetched.truncated, "The report was truncated; not all patient-web findings were retrieved"
    assert fetched.findings, "Patient-web returned no detected or confirmed vulnerabilities"
    return fetched.findings


def test_retrieve_patient_web_security_findings(patient_web_findings):
    """Check live ids, report filters, and normalized finding metadata."""
    finding_ids = [finding["id"] for finding in patient_web_findings]
    assert len(set(finding_ids)) == len(finding_ids)
    for finding in patient_web_findings:
        assert finding["status"] in {"detected", "confirmed"}
        assert finding["trackedRef"]["name"] == "main"
        assert finding["resolvedOnDefaultBranch"] is False
        assert finding["title"]
        assert finding["category"]
    print(f"Retrieved {len(patient_web_findings)} active patient-web vulnerabilities")


def test_patient_web_findings_have_verified_safe_solutions(patient_web_findings, monkeypatch):
    """Verify live advisory plans without applying local or GitLab changes."""
    configured_root = os.environ.get("PATIENT_WEB_REPO_ROOT")
    if not configured_root:
        pytest.fail("Set PATIENT_WEB_REPO_ROOT to the local patient-web checkout", pytrace=False)
    root = Path(configured_root).resolve()
    assert root.is_dir() and (root / "package.json").is_file(), "PATIENT_WEB_REPO_ROOT must contain patient-web's package.json"

    def refuse_commands(*args, **kwargs):
        """Fail immediately if verification tries to execute a local command."""
        pytest.fail("Solution verification must not execute Git or package-manager commands")

    unresolved = []
    with AdvisoryClient(
        github_token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
        nvd_api_key=os.environ.get("NVD_API_KEY"),
    ) as advisory:
        engine = Engine(root, advisory=advisory)
        monkeypatch.setattr(engine, "_remember", lambda: None)
        monkeypatch.setattr(engine.runner, "run", refuse_commands)
        engine.state.status = "FINDINGS_LISTED"
        engine.state.findings = patient_web_findings
        try:
            for finding in patient_web_findings:
                result = engine.verify_security_finding(finding["id"])
                decision = result["decision"]
                print(f"{finding['id']} | {finding['title']} | {decision} | {result['reason']}")
                if decision == "FALSE_POSITIVE":
                    continue
                if decision != "CHANGE_REQUIRED":
                    unresolved.append(f"{finding['id']}: {decision}: {result['reason']}")
                    continue
                plan = result["proposed_fix"]
                patched = advisory.lookup(finding, plan["ecosystem"], plan["package"], plan["target"])
                if patched.affected is not False:
                    unresolved.append(f"{finding['id']}: advisory did not verify target {plan['target']} as unaffected")
        finally:
            engine.close()

    assert not unresolved, "Findings without a verified safe solution:\n" + "\n".join(unresolved)
