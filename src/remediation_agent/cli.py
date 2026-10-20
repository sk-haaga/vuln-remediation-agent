"""Command line entry point: ``vra``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .agent import Agent, RunConfig
from .github import GitHubClient
from .llm import AzureChatModel
from .publish import DryRunPublisher, GitHubPublisher
from .sandbox import Sandbox


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vra", description="Find vulnerable dependencies and propose tested fixes.")
    p.add_argument("--repo", type=Path, default=Path("."), help="path to the target repository checkout")
    p.add_argument(
        "--requirements",
        type=Path,
        default=Path("requirements.txt"),
        help="pinned requirements file, relative to --repo",
    )
    p.add_argument("--project-dir", type=Path, default=Path("."), help="subfolder of --repo with the Python project")
    p.add_argument("--test-command", default="python -m pytest -q", help="command that runs the project's tests")
    p.add_argument("--image", help="container image to scan with Trivy")
    p.add_argument("--trivy-report", type=Path, help="use an existing Trivy JSON report instead of running Trivy")
    p.add_argument("--github-repo", help="owner/name for pull requests and issues (default: $GITHUB_REPOSITORY)")
    p.add_argument("--base-branch", help="branch to target (default: the repository's default branch)")
    p.add_argument("--dry-run", action="store_true", help="write pull requests and issues to --out instead of GitHub")
    p.add_argument(
        "--no-model", action="store_true", help="use the rule-based policy even if Azure OpenAI is configured"
    )
    p.add_argument("--python", default=sys.executable, help="interpreter used to build test environments")
    p.add_argument("--out", type=Path, default=Path("vra-output"), help="where reports and the audit log go")
    return p


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    cfg = RunConfig(
        repo=args.repo.resolve(),
        requirements=args.requirements,
        project_dir=args.project_dir,
        test_command=args.test_command,
        image=args.image,
        trivy_report=args.trivy_report,
        out_dir=out,
        python=args.python,
    )
    model = None if args.no_model else AzureChatModel.from_env()

    if args.dry_run:
        publisher = DryRunPublisher(out)
    else:
        repo = args.github_repo or os.environ.get("GITHUB_REPOSITORY")
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not repo or not token:
            p.error("set --github-repo (or GITHUB_REPOSITORY) and GITHUB_TOKEN, or use --dry-run")
        publisher = GitHubPublisher(GitHubClient(repo, token), Sandbox(out / "audit.jsonl"), args.base_branch)

    report = Agent(cfg, publisher, model).run()
    print(report.markdown())
    print("\n" + json.dumps(report.counts()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
