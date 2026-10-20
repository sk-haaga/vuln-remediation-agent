from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from remediation_agent.models import PackageFinding, Source, TestResult, UpgradePlan, Vulnerability


@dataclass
class FakeWorkspace:
    """Stands in for Workspace: records what was applied, returns a canned test result."""

    result: TestResult = field(default_factory=lambda: TestResult(True, "tests", 0, "3 passed", 1.0))
    applied: list[tuple[str, str]] = field(default_factory=list)
    requirements: Path = Path("requirements.txt")
    requirements_in_repo: Path = Path("requirements.txt")

    def checkout(self, key):
        return Path("/nonexistent") / key

    def path(self, key):
        return Path("/nonexistent") / key

    def apply_upgrade(self, key, package, version):
        self.applied.append((package, version))

    def run_tests(self, key):
        return self.result

    def diff(self, key):
        return ""

    def discard(self, key):
        pass


@dataclass
class FakePublisher:
    prs: list[dict] = field(default_factory=list)
    issues: list[dict] = field(default_factory=list)

    def publish_fix(self, ws, key, package, version, title, body):
        self.prs.append({"package": package, "version": version, "title": title, "body": body})
        return f"https://example.test/pull/{len(self.prs)}"

    def publish_escalation(self, title, body):
        self.issues.append({"title": title, "body": body})
        return f"https://example.test/issues/{len(self.issues)}"


@pytest.fixture
def finding():
    return PackageFinding(
        "pyjwt",
        "1.7.1",
        Source.REQUIREMENTS,
        [
            Vulnerability(
                "CVE-2022-29217",
                ["GHSA-ffqj-6fqr-9h24"],
                ["2.4.0"],
                "Algorithm confusion when all algorithms are allowed.",
            ),
        ],
    )


@pytest.fixture
def plan_ok(monkeypatch):
    plan = UpgradePlan("pyjwt", "1.7.1", "2.4.0", "major", ["CVE-2022-29217"], [])
    monkeypatch.setattr("remediation_agent.tools.plan_upgrade", lambda *a, **k: plan)
    return plan


@pytest.fixture
def plan_none(monkeypatch):
    plan = UpgradePlan("pyjwt", "1.7.1", None, None, [], ["CVE-2022-29217"], reason="no fix")
    monkeypatch.setattr("remediation_agent.tools.plan_upgrade", lambda *a, **k: plan)
    return plan
