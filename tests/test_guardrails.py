"""The rules that keep a human in charge, tested against a scripted model that misbehaves."""

from __future__ import annotations

import json

import pytest

from remediation_agent.github import ForbiddenAction, GitHubClient
from remediation_agent.llm import ModelPolicy, RulePolicy
from remediation_agent.models import EscalationReason, TestResult
from remediation_agent.sandbox import CommandNotAllowed, Sandbox
from remediation_agent.tools import APPROVED_TOOLS, Episode, ToolRegistry

from .conftest import FakePublisher, FakeWorkspace


def registry(finding, ws=None, pub=None):
    return ToolRegistry(Episode(finding), ws or FakeWorkspace(), pub or FakePublisher())


class ScriptedModel:
    """Returns pre-written tool calls, one batch per turn."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.seen_tools = None

    def chat(self, messages, tools):
        self.seen_tools = sorted(t["function"]["name"] for t in tools)
        if not self.turns:
            return {"content": "done", "tool_calls": []}
        calls = self.turns.pop(0)
        return {
            "content": None,
            "tool_calls": [{"id": f"c{i}", "name": n, "arguments": json.dumps(a)} for i, (n, a) in enumerate(calls)],
        }


def test_model_only_sees_approved_tools(finding, plan_ok):
    model = ScriptedModel([])
    ModelPolicy(model).run(registry(finding))
    assert set(model.seen_tools) == APPROVED_TOOLS
    assert not any("merge" in t for t in model.seen_tools)


def test_unapproved_tool_is_refused(finding):
    reg = registry(finding)
    for name in ("run_shell", "merge_pull_request", "write_file"):
        out = reg.call(name, {"cmd": "rm -rf /"})
        assert out["refused"] and "not an approved tool" in out["error"]


def test_model_cannot_choose_its_own_version(finding, plan_ok):
    ws = FakeWorkspace()
    reg = registry(finding, ws)
    reg.call("plan_upgrade", {})
    out = reg.call("apply_upgrade_and_test", {"version": "9.9.9"})
    assert out["refused"] and "unexpected argument" in out["error"]
    reg.call("apply_upgrade_and_test", {})
    assert ws.applied == [("pyjwt", "2.4.0")]


def test_no_pull_request_without_passing_tests(finding, plan_ok):
    pub = FakePublisher()
    ws = FakeWorkspace(result=TestResult(False, "tests", 1, "AttributeError", 1.0))
    reg = registry(finding, ws, pub)
    assert reg.call("open_pull_request", {"explanation": "trust me"})["refused"]  # before planning/testing
    reg.call("plan_upgrade", {})
    reg.call("apply_upgrade_and_test", {})
    assert reg.call("open_pull_request", {"explanation": "tests are fine"})["refused"]  # tests failed
    assert pub.prs == []


def test_escalation_reason_must_match_evidence(finding, plan_ok):
    reg = registry(finding)  # tests will pass
    reg.call("plan_upgrade", {})
    reg.call("apply_upgrade_and_test", {})
    assert reg.call("flag_for_review", {"reason": "tests-failed", "explanation": "x"})["refused"]
    assert reg.call("flag_for_review", {"reason": "no-safe-version", "explanation": "x"})["refused"]
    assert reg.call("flag_for_review", {"reason": "reviewer-judgement", "explanation": "major bump"})["ok"]


def test_no_actions_after_a_decision(finding, plan_ok):
    pub = FakePublisher()
    reg = registry(finding, pub=pub)
    reg.call("plan_upgrade", {})
    reg.call("apply_upgrade_and_test", {})
    assert reg.call("open_pull_request", {"explanation": "Fixes algorithm confusion."})["ok"]
    assert reg.call("open_pull_request", {"explanation": "again"})["refused"]
    assert len(pub.prs) == 1


def test_misbehaving_model_still_ends_safely(finding, plan_ok):
    """The model tries a shell, a premature PR and a version of its choosing, then follows the rules."""
    pub = FakePublisher()
    model = ScriptedModel(
        [
            [("run_shell", {"cmd": "git push origin main"})],
            [("open_pull_request", {"explanation": "skip tests"})],
            [("plan_upgrade", {})],
            [("apply_upgrade_and_test", {"version": "3.0.0"})],
            [("apply_upgrade_and_test", {})],
            [("open_pull_request", {"explanation": "PyJWT 1.7.1 lets an attacker pick the signing algorithm."})],
        ]
    )
    reg = registry(finding, pub=pub)
    policy = ModelPolicy(model)
    policy.run(reg)
    results = [json.loads(m["content"]) for m in policy.transcript if m["role"] == "tool"]
    refusals = [r for r in results if r.get("refused")]
    assert len(refusals) == 3
    assert reg.episode.decision == "pr" and pub.prs[0]["version"] == "2.4.0"
    body = pub.prs[0]["body"]
    assert "attacker pick the signing algorithm" in body  # model's explanation kept
    assert "Tests with the upgrade: **passed**" in body  # facts written by code, not the model


def test_model_that_never_decides_leaves_episode_open(finding, plan_ok):
    reg = registry(finding)
    ModelPolicy(ScriptedModel([[("plan_upgrade", {})]])).run(reg)
    assert not reg.done  # the Agent then escalates it as no-decision (see test_agent.py)


def test_rule_policy_paths(finding, plan_none):
    pub = FakePublisher()
    reg = registry(finding, pub=pub)
    RulePolicy().run(reg)
    assert reg.episode.reason is EscalationReason.NO_SAFE_VERSION and len(pub.issues) == 1


def test_sandbox_allowlist(tmp_path):
    sb = Sandbox(tmp_path / "audit.jsonl")
    for exe in ("bash", "sh", "curl", "/usr/bin/rm"):
        with pytest.raises(CommandNotAllowed):
            sb.run([exe, "-c", "echo hi"])
    assert "command_refused" in (tmp_path / "audit.jsonl").read_text()
    assert sb.run(["python3", "-c", "print(1)"]).stdout.strip() == "1"


@pytest.mark.parametrize(
    "method,path",
    [
        ("PUT", "/repos/o/r/pulls/1/merge"),
        ("POST", "/repos/o/r/merges"),
        ("PUT", "/repos/o/r/pulls/1/ccr/auto_merge"),
        ("POST", "/repos/o/r/pulls/1/reviews"),
        ("DELETE", "/repos/o/r/git/refs/heads/vra/x"),
        ("PATCH", "/repos/o/r/git/refs/heads/main"),
    ],
)
def test_github_client_never_merges(method, path):
    client = GitHubClient("o/r", "token", api="https://invalid.test")
    with pytest.raises(ForbiddenAction):
        client._request(method, path, {})


def test_github_client_has_no_merge_method():
    assert not [m for m in dir(GitHubClient) if "merge" in m.lower() or "approve" in m.lower()]
