"""Agent-level behaviour: fail-safe escalation, image findings, baseline check, reporting."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from remediation_agent import agent as agent_mod
from remediation_agent.agent import Agent, RunConfig
from remediation_agent.llm import ModelPolicy
from remediation_agent.models import EscalationReason, Outcome, PackageFinding, Source, TestResult, Vulnerability
from remediation_agent.scanners import pip_audit_executable

from .conftest import FakePublisher, FakeWorkspace
from .test_guardrails import ScriptedModel

ROOT = Path(__file__).resolve().parents[1]


def make_agent(tmp_path, monkeypatch, remediable, image_only=(), ws=None, model=None):
    pub = FakePublisher()
    a = Agent(RunConfig(repo=tmp_path, out_dir=tmp_path / "out"), pub, model)
    monkeypatch.setattr(a, "discover", lambda: (list(remediable), list(image_only)))
    monkeypatch.setattr(a, "_target_python", lambda: "3.12")
    fake = ws or FakeWorkspace()
    fake.cleanup = lambda: None
    monkeypatch.setattr(agent_mod, "Workspace", lambda *args, **kw: fake)
    return a, pub


def test_model_without_decision_is_escalated(tmp_path, monkeypatch, finding, plan_ok):
    a, pub = make_agent(tmp_path, monkeypatch, [finding], model=ScriptedModel([[("plan_upgrade", {})]]))
    report = a.run()
    assert [o.reason for o in report.outcomes] == [EscalationReason.NO_DECISION]
    assert len(pub.issues) == 1 and not pub.prs
    assert (tmp_path / "out" / "transcripts" / "pyjwt.json").exists()


def test_model_api_failure_fails_safe(tmp_path, monkeypatch, finding, plan_ok):
    class Broken:
        def chat(self, *a):
            raise TimeoutError("azure unavailable")

    a, pub = make_agent(tmp_path, monkeypatch, [finding], model=Broken())
    report = a.run()
    assert report.outcomes[0].outcome is Outcome.ESCALATED and "azure unavailable" in report.notes[0]


def test_failing_baseline_blocks_all_changes(tmp_path, monkeypatch, finding, plan_ok):
    ws = FakeWorkspace(result=TestResult(False, "tests", 1, "1 failed", 1.0))
    a, pub = make_agent(tmp_path, monkeypatch, [finding], ws=ws)
    report = a.run()
    assert report.outcomes[0].reason is EscalationReason.BASELINE_FAILING
    assert ws.applied == [] and not pub.prs and "1 failed" in pub.issues[0]["body"]


def test_image_findings_are_escalated_not_patched(tmp_path, monkeypatch):
    os_pkg = PackageFinding(
        "openssl", "3.0.11-1", Source.IMAGE_OS, [Vulnerability("CVE-2024-0001", fix_versions=["3.0.13-1"])], "os"
    )
    stray = PackageFinding(
        "setuptools", "65.5.0", Source.IMAGE_PYTHON, [Vulnerability("CVE-2024-6345", fix_versions=["70.0.0"])]
    )
    a, pub = make_agent(tmp_path, monkeypatch, [], [os_pkg, stray])
    report = a.run()
    assert {o.reason for o in report.outcomes} == {EscalationReason.OS_PACKAGE, EscalationReason.NOT_IN_REQUIREMENTS}
    assert len(pub.issues) == 2 and not pub.prs


def test_fix_with_leftover_unfixable_vuln(tmp_path, monkeypatch):
    from remediation_agent.models import UpgradePlan

    f = PackageFinding(
        "ecdsa",
        "0.18.0",
        Source.REQUIREMENTS,
        [Vulnerability("CVE-2024-23342"), Vulnerability("CVE-2026-33936", fix_versions=["0.19.2"])],
    )
    plan = UpgradePlan("ecdsa", "0.18.0", "0.19.2", "minor", ["CVE-2026-33936"], ["CVE-2024-23342"])
    monkeypatch.setattr("remediation_agent.tools.plan_upgrade", lambda *a, **k: plan)
    a, pub = make_agent(tmp_path, monkeypatch, [f])
    c = a.run().counts()
    assert (c["fixed"], c["escalated"], c["pull_requests"], c["issues"]) == (1, 1, 1, 1)
    assert (tmp_path / "out" / "report.md").read_text().startswith("## Vulnerability remediation")


@pytest.mark.network
@pytest.mark.skipif(pip_audit_executable() is None, reason="pip-audit not installed")
def test_end_to_end_on_fixture(tmp_path):
    """Real pip-audit, PyPI lookups, venvs and pytest on the auth-service fixture."""
    repo = tmp_path / "auth-service"
    shutil.copytree(ROOT / "eval" / "fixtures" / "auth-service", repo)
    for cmd in (["init", "-q"], ["add", "-A"], ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True)
    from remediation_agent.publish import DryRunPublisher

    out = tmp_path / "out"
    report = Agent(RunConfig(repo=repo, out_dir=out, python=sys.executable), DryRunPublisher(out)).run()
    by_pkg = {o.package: o for o in report.outcomes}
    assert by_pkg["pyjwt"].reason is EscalationReason.TESTS_FAILED  # 2.x returns str from encode()
    assert by_pkg["tqdm"].outcome is Outcome.FIXED
    assert (out / "pull-requests").is_dir() and (out / "issues").is_dir()
    assert ModelPolicy  # imported for type coverage
