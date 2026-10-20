"""The approved tools, and the registry that enforces the allowlist.

A remediation *episode* handles one vulnerable package. The model (or the
deterministic policy) can only act through the tools below. Guardrails that
matter live inside the tools, not in the prompt:

* the version comes from ``plan_upgrade``; there is no tool that accepts an
  arbitrary version, so the model cannot pick one;
* ``open_pull_request`` refuses unless tests passed for exactly that change;
* ``flag_for_review`` only accepts a reason that matches what actually happened;
* nothing can merge: no such tool exists, and the GitHub client refuses it.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import explain
from .models import EscalationReason, PackageFinding, TestResult, UpgradePlan
from .publish import Publisher
from .versions import plan_upgrade
from .workspace import Workspace

# The complete list of tools the model can call. Adding a tool means editing
# this line, which is reviewed like any other code change.
APPROVED_TOOLS = frozenset(
    {"lookup_advisory", "plan_upgrade", "apply_upgrade_and_test", "open_pull_request", "flag_for_review"}
)

TERMINAL_TOOLS = frozenset({"open_pull_request", "flag_for_review"})
MAX_EXPLANATION_CHARS = 3000


@dataclass
class Episode:
    finding: PackageFinding
    plan: UpgradePlan | None = None
    test: TestResult | None = None
    tested_version: str | None = None
    decision: str | None = None  # "pr" | "escalated"
    reason: EscalationReason | None = None
    link: str | None = None
    explanation: str | None = None


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    fn: Callable[..., dict[str, Any]]

    def schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {"name": self.name, "description": self.description, "parameters": self.parameters},
        }


def _validate(params: dict[str, Any], args: dict[str, Any]) -> str | None:
    props = params.get("properties", {})
    for req in params.get("required", []):
        if req not in args:
            return f"missing required argument '{req}'"
    for k, v in args.items():
        if k not in props:
            return f"unexpected argument '{k}'"
        spec = props[k]
        if spec.get("type") == "string" and not isinstance(v, str):
            return f"argument '{k}' must be a string"
        if "enum" in spec and v not in spec["enum"]:
            return f"argument '{k}' must be one of {spec['enum']}"
    return None


@dataclass
class ToolRegistry:
    episode: Episode
    workspace: Workspace
    publisher: Publisher
    audit_log: Path | None = None
    python_version: str | None = None
    tools: dict[str, Tool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for tool in self._build():
            if tool.name not in APPROVED_TOOLS:
                raise RuntimeError(f"tool {tool.name} is not on the approved list")
            self.tools[tool.name] = tool

    # -- plumbing -----------------------------------------------------------
    @property
    def key(self) -> str:
        return f"{self.episode.finding.name}"

    @property
    def done(self) -> bool:
        return self.episode.decision is not None

    def schemas(self) -> list[dict[str, Any]]:
        return [t.schema() for t in self.tools.values()]

    def _audit(self, record: dict[str, Any]) -> None:
        if self.audit_log:
            self.audit_log.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_log.open("a") as fh:
                fh.write(json.dumps({"ts": time.time(), "package": self.episode.finding.name, **record}) + "\n")

    def call(self, name: str, args: dict[str, Any] | str | None = None) -> dict[str, Any]:
        if isinstance(args, str):
            try:
                args = json.loads(args or "{}")
            except json.JSONDecodeError:
                return self._refuse(name, "arguments were not valid JSON")
        args = args or {}
        if name not in APPROVED_TOOLS or name not in self.tools:
            return self._refuse(name, f"'{name}' is not an approved tool. Approved: {sorted(APPROVED_TOOLS)}")
        if self.done:
            return self._refuse(name, "this package already has a decision; no further actions are allowed")
        problem = _validate(self.tools[name].parameters, args)
        if problem:
            return self._refuse(name, problem)
        try:
            result = self.tools[name].fn(**args)
        except Exception as e:  # tool errors go back to the model, they don't crash the run
            result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        self._audit({"event": "tool_call", "tool": name, "args": _redact(args), "ok": result.get("ok", True)})
        return result

    def _refuse(self, name: str, why: str) -> dict[str, Any]:
        self._audit({"event": "tool_refused", "tool": name, "why": why})
        return {"ok": False, "refused": True, "error": why}

    # -- tools ----------------------------------------------------------------
    def _build(self) -> list[Tool]:
        return [
            Tool(
                "lookup_advisory",
                "Get the details of one vulnerability affecting the package: summary, "
                "fixed versions, aliases and link.",
                {
                    "type": "object",
                    "properties": {"vuln_id": {"type": "string", "description": "Any id or alias, e.g. a CVE"}},
                    "required": ["vuln_id"],
                    "additionalProperties": False,
                },
                self._lookup_advisory,
            ),
            Tool(
                "plan_upgrade",
                "Compute the smallest released version of the package that leaves no fixable "
                "vulnerability. Returns the target version, the upgrade size, and what it fixes. You cannot choose "
                "a different version.",
                {"type": "object", "properties": {}, "additionalProperties": False},
                self._plan_upgrade,
            ),
            Tool(
                "apply_upgrade_and_test",
                "Apply the planned upgrade in an isolated copy of the repository, install "
                "dependencies in a fresh environment and run the project's tests. Requires plan_upgrade first.",
                {"type": "object", "properties": {}, "additionalProperties": False},
                self._apply_and_test,
            ),
            Tool(
                "open_pull_request",
                "Open a pull request with the tested upgrade for a human to review. Only "
                "allowed after apply_upgrade_and_test passed. Write `explanation` in plain language for a reviewer "
                "who is not a security specialist: what was wrong, what changes, what to check.",
                {
                    "type": "object",
                    "properties": {"explanation": {"type": "string"}},
                    "required": ["explanation"],
                    "additionalProperties": False,
                },
                self._open_pr,
            ),
            Tool(
                "flag_for_review",
                "Hand this package to a person instead of opening a pull request. Use when "
                "there is no safe version, the upgrade failed to install or broke tests, or a person should decide.",
                {
                    "type": "object",
                    "properties": {
                        "reason": {
                            "type": "string",
                            "enum": [
                                r.value
                                for r in (
                                    EscalationReason.NO_SAFE_VERSION,
                                    EscalationReason.INSTALL_FAILED,
                                    EscalationReason.TESTS_FAILED,
                                    EscalationReason.REVIEWER_JUDGEMENT,
                                )
                            ],
                        },
                        "explanation": {"type": "string"},
                    },
                    "required": ["reason", "explanation"],
                    "additionalProperties": False,
                },
                self._flag,
            ),
        ]

    def _lookup_advisory(self, vuln_id: str) -> dict[str, Any]:
        for v in self.episode.finding.vulns:
            if vuln_id in v.all_ids():
                return {
                    "ok": True,
                    "id": v.label,
                    "aliases": sorted(v.all_ids() - {v.label}),
                    "fixed_in": v.fix_versions,
                    "summary": v.summary[:1500],
                    "link": v.link,
                    "severity": v.severity or "unknown",
                }
        return {
            "ok": False,
            "error": f"{vuln_id} does not affect {self.episode.finding.name} {self.episode.finding.version}",
        }

    def _plan_upgrade(self) -> dict[str, Any]:
        f = self.episode.finding
        plan = plan_upgrade(f.name, f.version, f.vulns, python_version=self.python_version)
        self.episode.plan = plan
        return {
            "ok": True,
            "current": plan.current,
            "target": plan.target,
            "bump": plan.bump,
            "resolves": plan.resolves,
            "unfixable": plan.unfixable,
            "reason": plan.reason,
        }

    def _apply_and_test(self) -> dict[str, Any]:
        plan = self.episode.plan
        if plan is None:
            return {"ok": False, "error": "call plan_upgrade first"}
        if plan.target is None:
            return {"ok": False, "error": f"there is no safe version to apply: {plan.reason}"}
        self.workspace.checkout(self.key)
        self.workspace.apply_upgrade(self.key, plan.package, plan.target)
        result = self.workspace.run_tests(self.key)
        self.episode.test, self.episode.tested_version = result, plan.target
        return {
            "ok": True,
            "version": plan.target,
            "passed": result.passed,
            "failed_stage": None if result.passed else result.stage,
            "returncode": result.returncode,
            "output_tail": result.output_tail[-1500:],
        }

    def _open_pr(self, explanation: str) -> dict[str, Any]:
        ep = self.episode
        if not (ep.plan and ep.plan.target and ep.test and ep.test.passed and ep.tested_version == ep.plan.target):
            return {
                "ok": False,
                "refused": True,
                "error": "a pull request can only be opened after apply_upgrade_and_test passed for the planned version",
            }
        explanation = explanation.strip()[:MAX_EXPLANATION_CHARS] or explain.default_fix_explanation(
            ep.finding, ep.plan
        )
        title = (
            f"Upgrade {ep.finding.name} {ep.plan.current} → {ep.plan.target} (fixes {len(ep.plan.resolves)} "
            f"{'vulnerability' if len(ep.plan.resolves) == 1 else 'vulnerabilities'})"
        )
        body = explanation + "\n\n" + explain.facts(ep.finding, ep.plan, ep.test) + explain.FOOTER
        ep.link = self.publisher.publish_fix(self.workspace, self.key, ep.finding.name, ep.plan.target, title, body)
        ep.decision, ep.explanation = "pr", explanation
        return {"ok": True, "pull_request": ep.link}

    def _flag(self, reason: str, explanation: str) -> dict[str, Any]:
        ep = self.episode
        r = EscalationReason(reason)
        # The stated reason must match what the tools observed.
        tested = ep.test is not None and ep.tested_version is not None
        valid = {
            EscalationReason.NO_SAFE_VERSION: ep.plan is not None and ep.plan.target is None,
            EscalationReason.INSTALL_FAILED: tested and not ep.test.passed and ep.test.stage == "install",
            EscalationReason.TESTS_FAILED: tested and not ep.test.passed and ep.test.stage == "tests",
            EscalationReason.REVIEWER_JUDGEMENT: tested and ep.test.passed,
        }[r]
        if not valid:
            return {
                "ok": False,
                "refused": True,
                "error": f"reason '{reason}' does not match the tool results so far; check plan_upgrade / "
                f"apply_upgrade_and_test output",
            }
        explanation = explanation.strip()[:MAX_EXPLANATION_CHARS] or explain.default_escalation_explanation(
            ep.finding, r, ep.plan
        )
        ep.link = escalate(self.publisher, ep.finding, r, explanation, ep.plan, ep.test)
        ep.decision, ep.reason, ep.explanation = "escalated", r, explanation
        return {"ok": True, "issue": ep.link}


def escalate(
    publisher: Publisher,
    finding: PackageFinding,
    reason: EscalationReason,
    explanation: str,
    plan: UpgradePlan | None = None,
    test: TestResult | None = None,
) -> str:
    title = f"Security: {finding.name} {finding.version} needs manual review ({reason.value})"
    body = explanation + "\n\n" + explain.facts(finding, plan, test) + explain.FOOTER
    return publisher.publish_escalation(title, body)


def _redact(args: dict[str, Any]) -> dict[str, Any]:
    return {k: (v[:200] + "…" if isinstance(v, str) and len(v) > 200 else v) for k, v in args.items()}
