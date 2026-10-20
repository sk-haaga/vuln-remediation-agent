## Vulnerability remediation: `eval/fixtures/auth-service`

Fixed **6 of 18** known vulnerabilities automatically (4 pull request(s)); **12** escalated for review (2 issue(s)).

Escalations: no-safe-version ×1, tests-failed ×11

| Package | Vulnerability | Outcome | Change | Link |
|---|---|---|---|---|
| certifi | CVE-2023-37920 | fixed | 2022.12.7 → 2024.7.4 | pull-requests/certifi-2024.7.4.md |
| certifi | CVE-2024-39689 | fixed | 2022.12.7 → 2024.7.4 | pull-requests/certifi-2024.7.4.md |
| ecdsa | CVE-2026-33936 | fixed | 0.18.0 → 0.19.2 | pull-requests/ecdsa-0.19.2.md |
| ecdsa | CVE-2024-23342 | escalated (no-safe-version) | 0.18.0 | issues/security-ecdsa-0-19-2-needs-manual-review-no-safe-version.md |
| idna | CVE-2024-3651 | fixed | 3.4 → 3.15 | pull-requests/idna-3.15.md |
| idna | CVE-2026-45409 | fixed | 3.4 → 3.15 | pull-requests/idna-3.15.md |
| pyjwt | CVE-2022-29217 | escalated (tests-failed) | 1.7.1 | issues/security-pyjwt-1-7-1-needs-manual-review-tests-failed.md |
| pyjwt | CVE-2025-45768 | escalated (tests-failed) | 1.7.1 | issues/security-pyjwt-1-7-1-needs-manual-review-tests-failed.md |
| pyjwt | CVE-2026-101917 | escalated (tests-failed) | 1.7.1 | issues/security-pyjwt-1-7-1-needs-manual-review-tests-failed.md |
| pyjwt | CVE-2026-102267 | escalated (tests-failed) | 1.7.1 | issues/security-pyjwt-1-7-1-needs-manual-review-tests-failed.md |
| pyjwt | CVE-2026-102268 | escalated (tests-failed) | 1.7.1 | issues/security-pyjwt-1-7-1-needs-manual-review-tests-failed.md |
| pyjwt | CVE-2026-102269 | escalated (tests-failed) | 1.7.1 | issues/security-pyjwt-1-7-1-needs-manual-review-tests-failed.md |
| pyjwt | CVE-2026-102270 | escalated (tests-failed) | 1.7.1 | issues/security-pyjwt-1-7-1-needs-manual-review-tests-failed.md |
| pyjwt | CVE-2026-32597 | escalated (tests-failed) | 1.7.1 | issues/security-pyjwt-1-7-1-needs-manual-review-tests-failed.md |
| pyjwt | CVE-2026-48522 | escalated (tests-failed) | 1.7.1 | issues/security-pyjwt-1-7-1-needs-manual-review-tests-failed.md |
| pyjwt | CVE-2026-48524 | escalated (tests-failed) | 1.7.1 | issues/security-pyjwt-1-7-1-needs-manual-review-tests-failed.md |
| pyjwt | CVE-2026-48526 | escalated (tests-failed) | 1.7.1 | issues/security-pyjwt-1-7-1-needs-manual-review-tests-failed.md |
| tqdm | CVE-2024-34062 | fixed | 4.65.0 → 4.66.3 | pull-requests/tqdm-4.66.3.md |

_Mode: rules (no model configured). The agent never merges; every change waits for a human._