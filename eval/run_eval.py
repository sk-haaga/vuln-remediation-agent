"""Run the agent end to end on every repository in eval/fixtures (dry run).

Each fixture is copied to a temp dir and turned into a git repository, so the
run exercises the same worktree path as a real checkout. Nothing is pushed:
pull requests and issues are written to eval/results/<fixture>/.

    python eval/run_eval.py            # rule-based policy
    AZURE_OPENAI_... python eval/run_eval.py --model   # Azure OpenAI drives the episodes
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from remediation_agent.agent import Agent, RunConfig
from remediation_agent.llm import AzureChatModel
from remediation_agent.publish import DryRunPublisher

HERE = Path(__file__).parent


def git_copy(src: Path, dest: Path) -> None:
    shutil.copytree(src, dest)
    for cmd in (
        ["init", "-q", "-b", "main"],
        ["add", "-A"],
        ["-c", "user.name=eval", "-c", "user.email=eval@example.com", "commit", "-qm", "fixture"],
    ):
        subprocess.run(["git", "-C", str(dest), *cmd], check=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", action="store_true", help="use Azure OpenAI (needs AZURE_OPENAI_* env vars)")
    ap.add_argument("--only", nargs="*", help="fixture names to run")
    args = ap.parse_args()

    model = AzureChatModel.from_env() if args.model else None
    if args.model and model is None:
        sys.exit("AZURE_OPENAI_ENDPOINT / _API_KEY / _DEPLOYMENT are not set")

    results_dir = HERE / "results"
    totals = {"vulnerabilities": 0, "fixed": 0, "escalated": 0, "pull_requests": 0, "issues": 0}
    reasons: dict[str, int] = {}
    rows = []
    for fixture in sorted(p for p in (HERE / "fixtures").iterdir() if p.is_dir()):
        if args.only and fixture.name not in args.only:
            continue
        out = results_dir / fixture.name
        shutil.rmtree(out, ignore_errors=True)
        with tempfile.TemporaryDirectory(prefix="vra-eval-") as tmp:
            repo = Path(tmp) / fixture.name
            git_copy(fixture, repo)
            cfg = RunConfig(repo=repo, out_dir=out, python=sys.executable)
            report = Agent(cfg, DryRunPublisher(out), model).run()
        report.repo = f"eval/fixtures/{fixture.name}"
        (out / "report.md").write_text(report.markdown())
        (out / "report.json").write_text(json.dumps(report.to_dict(), indent=2))
        c = report.counts()
        for k in totals:
            totals[k] += c[k]
        for k, v in c["escalated_by_reason"].items():
            reasons[k] = reasons.get(k, 0) + v
        rows.append((fixture.name, c))
        print(f"{fixture.name}: {json.dumps(c)}", flush=True)

    mode = "model" if model else "rules"
    lines = [
        "# Evaluation results",
        "",
        f"Policy: **{mode}**. Dry run on {len(rows)} test repositories in `eval/fixtures/`; "
        "vulnerabilities are counted once per package after merging CVE/GHSA/PYSEC aliases.",
        "",
        f"**Fixed {totals['fixed']} of {totals['vulnerabilities']} known vulnerabilities automatically** "
        f"({totals['pull_requests']} pull requests, each with passing tests). "
        f"**{totals['escalated']} escalated** for human review ({totals['issues']} issues).",
        "",
        "| Repository | Vulnerabilities | Fixed | Escalated | PRs | Issues |",
        "|---|---|---|---|---|---|",
    ]
    for name, c in rows:
        lines.append(
            f"| {name} | {c['vulnerabilities']} | {c['fixed']} | {c['escalated']} | "
            f"{c['pull_requests']} | {c['issues']} |"
        )
    lines += [
        "",
        "Escalation reasons: " + ", ".join(f"{k} ×{v}" for k, v in sorted(reasons.items())),
        "",
        "Per-repository details, the would-be pull requests and issues, and the audit log are in "
        "`eval/results/<repository>/`.",
    ]
    (results_dir / "summary.md").write_text("\n".join(lines) + "\n")
    (results_dir / "summary.json").write_text(
        json.dumps(
            {"mode": mode, "totals": totals, "escalated_by_reason": reasons, "repositories": dict(rows)}, indent=2
        )
    )
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
