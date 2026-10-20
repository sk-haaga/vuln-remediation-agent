"""Decision makers for one remediation episode.

``ModelPolicy`` lets an Azure OpenAI chat model drive the episode through the
approved tools. ``RulePolicy`` runs the same tools in a fixed order with
templated explanations; it is used when no model is configured and as the
reference behaviour in tests. Both go through the same ToolRegistry, so the
guardrails are identical.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

from . import explain
from .models import EscalationReason
from .tools import ToolRegistry

SYSTEM_PROMPT = """You are a dependency-security assistant working on one vulnerable Python package.
Your job: propose the smallest safe upgrade and explain it clearly, while a human keeps the final say.

Procedure:
1. Call plan_upgrade. It computes the smallest safe version; you cannot choose another.
2. If it returns no target, call flag_for_review with reason "no-safe-version".
3. Otherwise call apply_upgrade_and_test.
4. If tests passed, call open_pull_request. If install failed use reason "install-failed";
   if tests failed use reason "tests-failed" with flag_for_review.
5. You may call lookup_advisory to understand a vulnerability before writing.

Writing the explanation (2-6 short sentences, plain language, no marketing):
- what the vulnerability lets an attacker do, in everyday words;
- what changes (from version, to version, patch/minor/major);
- what a reviewer should check, especially for a major upgrade or a failing test.
Never claim tests passed unless apply_upgrade_and_test said so. Never mention merging; a human merges.
Finish by calling exactly one of open_pull_request or flag_for_review."""


class ChatModel(Protocol):
    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        """Return {"content": str|None, "tool_calls": [{"id", "name", "arguments"}]}."""


class AzureChatModel:
    """Azure OpenAI chat completions with tool calling."""

    def __init__(self, endpoint: str, api_key: str, deployment: str, api_version: str = "2024-10-21"):
        from openai import AzureOpenAI  # imported lazily so rule-only runs don't need the SDK configured

        self.client = AzureOpenAI(azure_endpoint=endpoint, api_key=api_key, api_version=api_version)
        self.deployment = deployment

    @classmethod
    def from_env(cls) -> AzureChatModel | None:
        need = ("AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_DEPLOYMENT")
        if not all(os.environ.get(k) for k in need):
            return None
        return cls(
            os.environ["AZURE_OPENAI_ENDPOINT"],
            os.environ["AZURE_OPENAI_API_KEY"],
            os.environ["AZURE_OPENAI_DEPLOYMENT"],
            os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21"),
        )

    def chat(self, messages, tools):
        resp = self.client.chat.completions.create(
            model=self.deployment, messages=messages, tools=tools, tool_choice="auto", temperature=0
        )
        msg = resp.choices[0].message
        calls = [
            {"id": c.id, "name": c.function.name, "arguments": c.function.arguments} for c in (msg.tool_calls or [])
        ]
        return {"content": msg.content, "tool_calls": calls}


@dataclass
class ModelPolicy:
    model: ChatModel
    max_steps: int = 10
    transcript: list[dict[str, Any]] = field(default_factory=list)

    def run(self, reg: ToolRegistry) -> None:
        f = reg.episode.finding
        brief = {
            "package": f.name,
            "version": f.version,
            "found_by": f.source.value,
            "vulnerabilities": [
                {"id": v.label, "fixed_in": v.fix_versions, "summary": explain.first_sentence(v.summary)}
                for v in f.vulns
            ],
        }
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Vulnerable package:\n" + json.dumps(brief, indent=2)},
        ]
        nudged = False
        for _ in range(self.max_steps):
            reply = self.model.chat(messages, reg.schemas())
            calls = reply.get("tool_calls") or []
            messages.append(
                {
                    "role": "assistant",
                    "content": reply.get("content"),
                    **(
                        {
                            "tool_calls": [
                                {
                                    "id": c["id"],
                                    "type": "function",
                                    "function": {"name": c["name"], "arguments": c["arguments"]},
                                }
                                for c in calls
                            ]
                        }
                        if calls
                        else {}
                    ),
                }
            )
            if not calls:
                if nudged:
                    break
                nudged = True
                messages.append({"role": "user", "content": "Finish by calling open_pull_request or flag_for_review."})
                continue
            for c in calls:
                result = reg.call(c["name"], c["arguments"])
                messages.append({"role": "tool", "tool_call_id": c["id"], "content": json.dumps(result)[:6000]})
            if reg.done:
                break
        self.transcript = messages


class RulePolicy:
    """Same tools, fixed order, templated explanations."""

    def run(self, reg: ToolRegistry) -> None:
        plan = reg.call("plan_upgrade", {})
        if not plan.get("target"):
            reg.call("flag_for_review", {"reason": EscalationReason.NO_SAFE_VERSION.value, "explanation": ""})
            return
        test = reg.call("apply_upgrade_and_test", {})
        if not test.get("ok"):
            return  # could not even apply the change; the agent's fail-safe escalates it
        if test["passed"]:
            reg.call("open_pull_request", {"explanation": ""})
        else:
            reason = (
                EscalationReason.INSTALL_FAILED if test["failed_stage"] == "install" else EscalationReason.TESTS_FAILED
            )
            reg.call("flag_for_review", {"reason": reason.value, "explanation": ""})
