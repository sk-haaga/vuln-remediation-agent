"""Top-level run: discover → baseline tests → one episode per package → report."""

from __future__ import annotations

import json
import os
import platform
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from . import explain, requirements_file, scanners
from .llm import ModelPolicy, RulePolicy
from .models import EscalationReason, Outcome, PackageFinding, Source, VulnOutcome
from .publish import Publisher
from .sandbox import Sandbox
from .tools import Episode, ToolRegistry, escalate
from .vulns import merge_vulns
from .workspace import Workspace


@dataclass
class RunConfig:
    repo: Path
    requirements: Path = Path("requirements.txt")  # relative to project_dir
    project_dir: Path = Path(".")  # subfolder of repo holding the Python project
    test_command: str = "python -m pytest -q"
    image: str | None = None
    trivy_report: Path | None = None
    out_dir: Path = Path("vra-output")
    python: str = "python3"
    base_ref: str = "HEAD"
    max_packages: int = 25


@dataclass
class RunReport:
    repo: str
    mode: str
    outcomes: list[VulnOutcome] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def counts(self) -> dict:
        total = len(self.outcomes)
        fixed = sum(o.outcome is Outcome.FIXED for o in self.outcomes)
        by_reason: dict[str, int] = {}
        for o in self.outcomes:
            if o.outcome is Outcome.ESCALATED and o.reason:
                by_reason[o.reason.value] = by_reason.get(o.reason.value, 0) + 1
        prs = len({o.link for o in self.outcomes if o.outcome is Outcome.FIXED})
        issues = len({o.link for o in self.outcomes if o.outcome is Outcome.ESCALATED})
        return {
            "vulnerabilities": total,
            "fixed": fixed,
            "escalated": total - fixed,
            "escalated_by_reason": by_reason,
            "pull_requests": prs,
            "issues": issues,
        }

    def to_dict(self) -> dict:
        return {
            "repo": self.repo,
            "mode": self.mode,
            "summary": self.counts(),
            "notes": self.notes,
            "outcomes": [o.to_dict() for o in self.outcomes],
        }

    def markdown(self) -> str:
        c = self.counts()
        lines = [
            f"## Vulnerability remediation: `{self.repo}`",
            "",
            f"Fixed **{c['fixed']} of {c['vulnerabilities']}** known vulnerabilities automatically "
            f"({c['pull_requests']} pull request(s)); **{c['escalated']}** escalated for review "
            f"({c['issues']} issue(s)).",
            "",
        ]
        if c["escalated_by_reason"]:
            lines += ["Escalations: " + ", ".join(f"{k} ×{v}" for k, v in sorted(c["escalated_by_reason"].items())), ""]
        lines += ["| Package | Vulnerability | Outcome | Change | Link |", "|---|---|---|---|---|"]
        for o in self.outcomes:
            change = f"{o.from_version} → {o.to_version}" if o.to_version else o.from_version
            outcome = o.outcome.value + (f" ({o.reason.value})" if o.reason else "")
            lines.append(f"| {o.package} | {o.vuln} | {outcome} | {change} | {o.link or ''} |")
        if self.notes:
            lines += ["", *[f"- {n}" for n in self.notes]]
        lines += ["", f"_Mode: {self.mode}. The agent never merges; every change waits for a human._"]
        return "\n".join(lines)


class Agent:
    def __init__(self, cfg: RunConfig, publisher: Publisher, model=None):
        self.cfg = cfg
        self.publisher = publisher
        self.model = model
        cfg.out_dir.mkdir(parents=True, exist_ok=True)
        self.audit = cfg.out_dir / "audit.jsonl"
        test_exe = Path(shlex.split(cfg.test_command)[0]).name
        self.sandbox = Sandbox(self.audit, extra_allowed={test_exe})
        self.report = RunReport(
            repo=str(cfg.repo),
            mode=f"model ({os.environ.get('AZURE_OPENAI_DEPLOYMENT', 'azure')})"
            if model
            else "rules (no model configured)",
        )

    # -- discovery --------------------------------------------------------------
    def discover(self) -> tuple[list[PackageFinding], list[PackageFinding]]:
        """Returns (remediable findings pinned in the repo, image-only findings)."""
        req_path = self.cfg.repo / self.cfg.project_dir / self.cfg.requirements
        pins = requirements_file.pinned(req_path)
        by_name = {f.name: f for f in scanners.pip_audit(self.sandbox, req_path)}

        image_findings: list[PackageFinding] = []
        if self.cfg.trivy_report:
            image_findings = scanners.load_trivy_report(self.cfg.trivy_report)
        elif self.cfg.image:
            image_findings = scanners.trivy_image(self.sandbox, self.cfg.image)

        image_only = []
        for f in image_findings:
            if f.source is Source.IMAGE_PYTHON and f.name in pins and pins[f.name] == f.version:
                if f.name in by_name:
                    by_name[f.name].vulns = merge_vulns(by_name[f.name].vulns + f.vulns)
                else:
                    by_name[f.name] = f
            else:
                image_only.append(f)
        return sorted(by_name.values(), key=lambda f: f.name), image_only

    # -- outcomes ---------------------------------------------------------------
    def _record_episode(self, ep: Episode) -> None:
        f = ep.finding
        if ep.decision == "pr" and ep.plan:
            for v in f.vulns:
                if v.label in ep.plan.resolves:
                    self.report.outcomes.append(
                        VulnOutcome(f.name, v.label, Outcome.FIXED, None, f.version, ep.plan.target, ep.link)
                    )
            leftover = [v for v in f.vulns if v.label not in ep.plan.resolves]
            if leftover:
                rest = PackageFinding(f.name, ep.plan.target or f.version, f.source, leftover, f.ecosystem)
                link = escalate(
                    self.publisher,
                    rest,
                    EscalationReason.NO_SAFE_VERSION,
                    f"After upgrading `{f.name}` to {ep.plan.target} (see the pull request {ep.link}), "
                    f"{len(leftover)} known issue(s) remain with no fixed release. Track them here.",
                )
                for v in leftover:
                    self.report.outcomes.append(
                        VulnOutcome(
                            f.name, v.label, Outcome.ESCALATED, EscalationReason.NO_SAFE_VERSION, f.version, None, link
                        )
                    )
        else:
            for v in f.vulns:
                self.report.outcomes.append(
                    VulnOutcome(f.name, v.label, Outcome.ESCALATED, ep.reason, f.version, None, ep.link)
                )

    def _escalate_group(
        self, findings: list[PackageFinding], reason: EscalationReason, title: str, details: str = ""
    ) -> None:
        if not findings:
            return
        rows = ["| Package | Installed | Vulnerability | Severity | Fixed in |", "|---|---|---|---|---|"]
        for f in findings:
            for v in f.vulns:
                rows.append(
                    f"| {f.name} | {f.version} | {v.label} | {v.severity or '-'} | "
                    f"{', '.join(v.fix_versions) or 'no fix'} |"
                )
        body = (
            explain._REASON_TEXT[reason]
            + "\n\n"
            + "\n".join(rows)
            + (f"\n\n{details}" if details else "")
            + explain.FOOTER
        )
        link = self.publisher.publish_escalation(title, body)
        for f in findings:
            for v in f.vulns:
                self.report.outcomes.append(
                    VulnOutcome(f.name, v.label, Outcome.ESCALATED, reason, f.version, None, link)
                )

    # -- run --------------------------------------------------------------------
    def run(self) -> RunReport:
        remediable, image_only = self.discover()
        self._escalate_group(
            [f for f in image_only if f.source is Source.IMAGE_OS],
            EscalationReason.OS_PACKAGE,
            "Security: container base image has vulnerable OS packages",
        )
        self._escalate_group(
            [f for f in image_only if f.source is Source.IMAGE_PYTHON],
            EscalationReason.NOT_IN_REQUIREMENTS,
            "Security: vulnerable Python packages in the image that the repo does not pin",
        )
        if not remediable:
            self.report.notes.append("No vulnerable pinned dependencies found.")
            return self._finish()

        if len(remediable) > self.cfg.max_packages:
            self.report.notes.append(
                f"Only the first {self.cfg.max_packages} of {len(remediable)} packages were handled."
            )
            remediable = remediable[: self.cfg.max_packages]

        ws = Workspace(
            self.cfg.repo,
            self.cfg.requirements,
            self.cfg.test_command,
            self.sandbox,
            python=self.cfg.python,
            base_ref=self.cfg.base_ref,
            project_dir=self.cfg.project_dir,
        )
        try:
            ws.checkout("baseline")
            baseline = ws.run_tests("baseline")
            ws.discard("baseline")
            if not baseline.passed:
                self.report.notes.append(f"Baseline tests failed at the {baseline.stage} step; nothing was changed.")
                self._escalate_group(
                    remediable,
                    EscalationReason.BASELINE_FAILING,
                    "Security: dependency fixes blocked because tests already fail",
                    f"<details><summary>Baseline output ({baseline.stage} step, exit "
                    f"{baseline.returncode})</summary>\n\n```\n{baseline.output_tail[-3000:]}\n```\n"
                    f"</details>",
                )
                return self._finish()

            py = self._target_python()
            for finding in remediable:
                ep = Episode(finding)
                reg = ToolRegistry(ep, ws, self.publisher, self.audit, python_version=py)
                policy = ModelPolicy(self.model) if self.model else RulePolicy()
                try:
                    policy.run(reg)
                except Exception as e:  # model/API failure: fail safe, never fail open
                    self.report.notes.append(f"{finding.name}: decision step errored ({type(e).__name__}: {e})")
                if not reg.done:
                    ep.reason = EscalationReason.NO_DECISION
                    ep.link = escalate(
                        self.publisher,
                        finding,
                        ep.reason,
                        explain.default_escalation_explanation(finding, ep.reason, ep.plan),
                        ep.plan,
                        ep.test,
                    )
                    ep.decision = "escalated"
                if isinstance(policy, ModelPolicy):
                    (self.cfg.out_dir / "transcripts").mkdir(exist_ok=True)
                    (self.cfg.out_dir / "transcripts" / f"{finding.name}.json").write_text(
                        json.dumps(policy.transcript, indent=2, default=str)
                    )
                self._record_episode(ep)
                ws.discard(reg.key)
        finally:
            ws.cleanup()
        return self._finish()

    def _target_python(self) -> str:
        res = self.sandbox.run([self.cfg.python, "-c", "import platform;print(platform.python_version())"])
        return res.stdout.strip() or platform.python_version()

    def _finish(self) -> RunReport:
        (self.cfg.out_dir / "report.json").write_text(json.dumps(self.report.to_dict(), indent=2))
        (self.cfg.out_dir / "report.md").write_text(self.report.markdown())
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as fh:
                fh.write(self.report.markdown() + "\n")
        return self.report
