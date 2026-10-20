"""Plain data types shared across the agent."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Source(StrEnum):
    REQUIREMENTS = "requirements"  # found by pip-audit in a requirements file
    IMAGE_PYTHON = "image-python"  # Python package found by Trivy in the container image
    IMAGE_OS = "image-os"  # OS package found by Trivy in the container image


class Outcome(StrEnum):
    FIXED = "fixed"  # upgrade passed tests, pull request opened (or prepared in dry-run)
    ESCALATED = "escalated"  # handed to a human via an issue


class EscalationReason(StrEnum):
    TESTS_FAILED = "tests-failed"  # the upgrade broke the test suite
    INSTALL_FAILED = "install-failed"  # the upgrade could not be installed (dependency conflict, build error)
    NO_SAFE_VERSION = "no-safe-version"  # no released version resolves the vulnerability
    BASELINE_FAILING = "baseline-failing"  # tests were already failing before any change
    NOT_IN_REQUIREMENTS = "not-in-requirements"  # found in the image but not pinned in the repo
    OS_PACKAGE = "os-package"  # needs a base-image update, not a dependency bump
    NO_DECISION = "no-decision"  # the model ended without a decision; failed safe
    REVIEWER_JUDGEMENT = "reviewer-judgement"  # model chose to hand a passing fix to a person anyway


@dataclass
class Vulnerability:
    """One vulnerability. ``id`` is canonical; ``aliases`` holds every other id for it."""

    id: str
    aliases: list[str] = field(default_factory=list)
    fix_versions: list[str] = field(default_factory=list)
    summary: str = ""
    link: str = ""
    severity: str = ""

    def all_ids(self) -> set[str]:
        return {self.id, *self.aliases}

    @property
    def cve(self) -> str | None:
        for i in sorted(self.all_ids()):
            if i.startswith("CVE-"):
                return i
        return None

    @property
    def label(self) -> str:
        return self.cve or self.id


@dataclass
class PackageFinding:
    name: str  # normalised distribution name
    version: str
    source: Source
    vulns: list[Vulnerability]
    ecosystem: str = "pypi"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        return d


@dataclass
class UpgradePlan:
    package: str
    current: str
    target: str | None
    bump: str | None  # "patch" | "minor" | "major"
    resolves: list[str]  # vuln labels fixed by moving to target
    unfixable: list[str]  # vuln labels that no released version fixes
    reason: str = ""


@dataclass
class TestResult:
    __test__ = False  # not a pytest test class

    passed: bool
    stage: str  # "install" | "tests"
    returncode: int
    output_tail: str
    duration_s: float


@dataclass
class VulnOutcome:
    package: str
    vuln: str
    outcome: Outcome
    reason: EscalationReason | None = None
    from_version: str = ""
    to_version: str | None = None
    link: str | None = None  # PR / issue URL or dry-run file

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "vuln": self.vuln,
            "outcome": self.outcome.value,
            "reason": self.reason.value if self.reason else None,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "link": self.link,
        }
