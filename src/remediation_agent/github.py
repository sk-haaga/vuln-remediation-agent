"""Minimal GitHub REST client: open pull requests and issues. Nothing else.

There is deliberately no merge, approve, or delete method, and ``_request``
refuses any endpoint that could merge or approve, so even a bug elsewhere
cannot make the agent merge its own work. Branch protection on the target
repository is the second layer of the same rule.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"

_FORBIDDEN = re.compile(r"/merge(s)?\b|/auto_merge|/reviews|/approve|/git/refs/heads/(main|master)\b", re.I)
_ALLOWED_METHODS = {"GET", "POST", "PATCH"}


class ForbiddenAction(PermissionError):
    pass


class GitHubClient:
    def __init__(self, repo: str, token: str, api: str = API):
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
            raise ValueError(f"expected owner/name, got {repo!r}")
        self.repo, self._token, self.api = repo, token, api.rstrip("/")

    def _request(self, method: str, path: str, body: dict | None = None) -> dict | list:
        if method not in _ALLOWED_METHODS:
            raise ForbiddenAction(f"HTTP {method} is not permitted")
        if _FORBIDDEN.search(path):
            raise ForbiddenAction(f"{path} is not permitted: the agent never merges or approves")
        req = urllib.request.Request(
            f"{self.api}{path}",
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "vuln-remediation-agent",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"GitHub {method} {path} -> {e.code}: {e.read().decode(errors='replace')[:500]}") from e

    def default_branch(self) -> str:
        return self._request("GET", f"/repos/{self.repo}")["default_branch"]

    def open_pull_for_branch(self, branch: str) -> dict | None:
        owner = self.repo.split("/")[0]
        q = urllib.parse.urlencode({"head": f"{owner}:{branch}", "state": "open"})
        pulls = self._request("GET", f"/repos/{self.repo}/pulls?{q}")
        return pulls[0] if pulls else None

    def create_pull_request(self, *, head: str, base: str, title: str, body: str, labels: list[str]) -> dict:
        pr = self._request(
            "POST",
            f"/repos/{self.repo}/pulls",
            {"head": head, "base": base, "title": title, "body": body, "draft": False, "maintainer_can_modify": True},
        )
        if labels:
            self._request("POST", f"/repos/{self.repo}/issues/{pr['number']}/labels", {"labels": labels})
        return pr

    def find_open_issue(self, title: str, label: str) -> dict | None:
        q = urllib.parse.urlencode({"state": "open", "labels": label, "per_page": 100})
        for issue in self._request("GET", f"/repos/{self.repo}/issues?{q}"):
            if issue.get("title") == title and "pull_request" not in issue:
                return issue
        return None

    def create_issue(self, *, title: str, body: str, labels: list[str]) -> dict:
        return self._request("POST", f"/repos/{self.repo}/issues", {"title": title, "body": body, "labels": labels})
