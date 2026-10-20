"""Plain-language text for pull requests and issues.

The *facts* section (versions, advisories, test result) is always generated
here from tool results, so a model-written explanation can add context but
can never change what the reviewer is told about versions or tests.
"""

from __future__ import annotations

import re

from .models import EscalationReason, PackageFinding, TestResult, UpgradePlan

_BUMP_NOTE = {
    "patch": "This is a patch release, so behaviour changes should be minimal.",
    "minor": "This is a minor release: new features may be added, but it should stay backwards compatible.",
    "major": "This is a major version upgrade, which may change or remove APIs. The tests passed, "
    "but please check the release notes for behaviour the tests do not cover.",
}

_REASON_TEXT = {
    EscalationReason.TESTS_FAILED: "The smallest safe upgrade breaks the test suite, so the agent did not open a pull request.",
    EscalationReason.INSTALL_FAILED: "The smallest safe upgrade could not be installed alongside the other pinned "
    "dependencies (usually a version conflict), so the agent did not open a pull request.",
    EscalationReason.NO_SAFE_VERSION: "No released version fixes this yet, so there is nothing safe to upgrade to.",
    EscalationReason.BASELINE_FAILING: "The test suite was already failing before any change, so the agent could not "
    "check whether an upgrade is safe.",
    EscalationReason.NOT_IN_REQUIREMENTS: "This package is in the container image but is not pinned in the repository, "
    "so a dependency bump here cannot fix it.",
    EscalationReason.OS_PACKAGE: "These are operating-system packages in the container image. They are fixed by "
    "updating the base image, not by a dependency upgrade.",
    EscalationReason.NO_DECISION: "The agent did not reach a decision for this package, so it is handed to a person by default.",
    EscalationReason.REVIEWER_JUDGEMENT: "The upgrade passed the tests, but the agent judged that a person should "
    "decide before a pull request is opened.",
}


_HEADINGS = re.compile(r"^(summary|impact|description|details|overview|vulnerability|background|note)\b[:\s]*", re.I)
_BOILERPLATE = re.compile(
    r"^[\w.\- ]{1,40} (is|provides) (an?|the) .{0,80}"
    r"(library|implementation|framework|package|toolkit|tool|engine|module|client|server)\b",
    re.I,
)


def first_sentence(text: str, limit: int = 220) -> str:
    """The first sentence that actually describes the problem."""
    text = re.sub(r"\[!(NOTE|WARNING|IMPORTANT)\]", " ", text or "")
    text = re.sub(r"\s+", " ", re.sub(r"[#*`>]+", " ", text)).strip()
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]
    chosen = ""
    for s in sentences:
        s = _HEADINGS.sub("", s).strip()
        if len(s) < 25 or s.endswith("?") or _BOILERPLATE.match(s):
            continue
        chosen = s
        break
    chosen = chosen or (sentences[0] if sentences else "")
    return chosen if len(chosen) <= limit else chosen[: limit - 1].rstrip() + "…"


def default_fix_explanation(finding: PackageFinding, plan: UpgradePlan) -> str:
    n = len(plan.resolves)
    lines = [
        f"`{finding.name}` {plan.current} has {len(finding.vulns)} known "
        f"{'vulnerability' if len(finding.vulns) == 1 else 'vulnerabilities'}. "
        f"Upgrading to {plan.target} fixes {n} of them; it is the smallest released version that does.",
        "",
        _BUMP_NOTE.get(plan.bump or "", ""),
    ]
    if plan.unfixable:
        lines += [
            "",
            f"{len(plan.unfixable)} issue(s) have no fixed release yet and remain: " + ", ".join(plan.unfixable) + ".",
        ]
    return "\n".join(lines).strip()


def default_escalation_explanation(finding: PackageFinding, reason: EscalationReason, plan: UpgradePlan | None) -> str:
    text = _REASON_TEXT[reason]
    if plan and plan.target:
        text += f" The smallest safe version is {plan.target} ({plan.bump} upgrade from {plan.current})."
    if reason is EscalationReason.TESTS_FAILED and plan and plan.bump == "major":
        text += " A major upgrade often needs code changes; the test output below shows where."
    return text


def facts(finding: PackageFinding, plan: UpgradePlan | None, test: TestResult | None) -> str:
    rows = ["| Advisory | Summary | Fixed in |", "|---|---|---|"]
    for v in finding.vulns:
        name = f"[{v.label}]({v.link})" if v.link else v.label
        fixed = ", ".join(v.fix_versions) or "no fix released"
        rows.append(f"| {name} | {first_sentence(v.summary).replace('|', '/')} | {fixed} |")
    out = [
        "### Facts (generated from tool results)",
        "",
        f"- Package: `{finding.name}` (found by {finding.source.value})",
        f"- Current version: `{finding.version}`",
    ]
    if plan:
        out.append(
            f"- Proposed version: `{plan.target}` ({plan.bump} upgrade)"
            if plan.target
            else f"- Proposed version: none — {plan.reason}"
        )
    if test:
        verdict = "passed" if test.passed else f"failed at the {test.stage} step (exit {test.returncode})"
        out.append(f"- Tests with the upgrade: **{verdict}** in {test.duration_s:.0f}s")
    out += ["", *rows]
    if test and not test.passed:
        out += [
            "",
            "<details><summary>Test output (last lines)</summary>",
            "",
            "```",
            test.output_tail[-3000:],
            "```",
            "</details>",
        ]
    return "\n".join(out)


FOOTER = "\n\n---\n_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._"
