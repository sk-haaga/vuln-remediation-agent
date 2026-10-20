# Evaluation results

Policy: **rules**. Dry run on 3 test repositories in `eval/fixtures/`; vulnerabilities are counted once per package after merging CVE/GHSA/PYSEC aliases.

**Fixed 39 of 67 known vulnerabilities automatically** (11 pull requests, each with passing tests). **28 escalated** for human review (5 issues).

| Repository | Vulnerabilities | Fixed | Escalated | PRs | Issues |
|---|---|---|---|---|---|
| auth-service | 18 | 6 | 12 | 4 | 2 |
| report-renderer | 19 | 15 | 4 | 3 | 1 |
| web-app | 30 | 18 | 12 | 4 | 2 |

Escalation reasons: install-failed ×2, no-safe-version ×1, tests-failed ×25

Per-repository details, the would-be pull requests and issues, and the audit log are in `eval/results/<repository>/`.
