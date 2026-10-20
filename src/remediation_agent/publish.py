"""Where results go: GitHub (pull requests and issues) or local files (dry run)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

from .github import ForbiddenAction, GitHubClient
from .sandbox import Sandbox
from .workspace import Workspace

BRANCH_PREFIX = "vra/"
FIX_LABELS = ["security", "dependencies", "automated-fix"]
ESCALATION_LABELS = ["security", "needs-human"]


def branch_name(package: str, version: str) -> str:
    return f"{BRANCH_PREFIX}{re.sub(r'[^A-Za-z0-9._-]', '-', package)}-{version}"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80]


class Publisher(Protocol):
    def publish_fix(self, ws: Workspace, key: str, package: str, version: str, title: str, body: str) -> str: ...
    def publish_escalation(self, title: str, body: str) -> str: ...


class DryRunPublisher:
    """Writes the would-be pull requests and issues to disk for review."""

    def __init__(self, out_dir: Path):
        self.out = out_dir

    def publish_fix(self, ws, key, package, version, title, body) -> str:
        d = self.out / "pull-requests"
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{_slug(package)}-{version}.md"
        diff = ws.diff(key)
        path.write_text(
            f"# {title}\n\nBranch: `{branch_name(package, version)}`\n\n{body}\n"
            + (f"\n<details><summary>Diff</summary>\n\n```diff\n{diff}```\n</details>\n" if diff else "")
        )
        return str(path.relative_to(self.out))

    def publish_escalation(self, title, body) -> str:
        d = self.out / "issues"
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{_slug(title)}.md"
        path.write_text(f"# {title}\n\n{body}\n")
        return str(path.relative_to(self.out))


class GitHubPublisher:
    def __init__(
        self,
        client: GitHubClient,
        sandbox: Sandbox,
        base_branch: str | None = None,
        author: str = "github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>",
    ):
        self.client, self.sandbox = client, sandbox
        self.base = base_branch or client.default_branch()
        self.author = author

    def _git(self, tree: Path, *args: str) -> None:
        res = self.sandbox.run(["git", "-C", str(tree), *args])
        if res.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {res.stderr.strip()[-800:]}")

    def publish_fix(self, ws, key, package, version, title, body) -> str:
        branch = branch_name(package, version)
        if not branch.startswith(BRANCH_PREFIX) or branch in {self.base, "main", "master"}:
            raise ForbiddenAction("the agent only pushes to its own vra/* branches")
        existing = self.client.open_pull_for_branch(branch)
        if existing:
            return existing["html_url"]
        tree = ws.path(key)
        name, email = self.author.rsplit(" <", 1)
        self._git(tree, "checkout", "-b", branch)
        self._git(tree, "add", str(ws.requirements_in_repo))
        self._git(
            tree,
            "-c",
            f"user.name={name}",
            "-c",
            f"user.email={email.rstrip('>')}",
            "commit",
            "-m",
            title,
            "-m",
            "Opened by vuln-remediation-agent. Tests passed before this PR was opened.",
        )
        self._git(tree, "push", "--force", "origin", f"HEAD:refs/heads/{branch}")
        pr = self.client.create_pull_request(head=branch, base=self.base, title=title, body=body, labels=FIX_LABELS)
        return pr["html_url"]

    def publish_escalation(self, title, body) -> str:
        existing = self.client.find_open_issue(title, ESCALATION_LABELS[-1])
        if existing:
            return existing["html_url"]
        return self.client.create_issue(title=title, body=body, labels=ESCALATION_LABELS)["html_url"]
