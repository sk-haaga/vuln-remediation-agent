## Vulnerability remediation: `eval/fixtures/web-app`

Fixed **18 of 30** known vulnerabilities automatically (4 pull request(s)); **12** escalated for review (2 issue(s)).

Escalations: install-failed ×2, tests-failed ×10

| Package | Vulnerability | Outcome | Change | Link |
|---|---|---|---|---|
| flask | CVE-2023-30861 | escalated (install-failed) | 2.2.2 | issues/security-flask-2-2-2-needs-manual-review-install-failed.md |
| flask | CVE-2026-27205 | escalated (install-failed) | 2.2.2 | issues/security-flask-2-2-2-needs-manual-review-install-failed.md |
| idna | CVE-2024-3651 | fixed | 3.6 → 3.15 | pull-requests/idna-3.15.md |
| idna | CVE-2026-45409 | fixed | 3.6 → 3.15 | pull-requests/idna-3.15.md |
| jinja2 | CVE-2024-22195 | fixed | 3.1.2 → 3.1.6 | pull-requests/jinja2-3.1.6.md |
| jinja2 | CVE-2024-34064 | fixed | 3.1.2 → 3.1.6 | pull-requests/jinja2-3.1.6.md |
| jinja2 | CVE-2024-56201 | fixed | 3.1.2 → 3.1.6 | pull-requests/jinja2-3.1.6.md |
| jinja2 | CVE-2024-56326 | fixed | 3.1.2 → 3.1.6 | pull-requests/jinja2-3.1.6.md |
| jinja2 | CVE-2025-27516 | fixed | 3.1.2 → 3.1.6 | pull-requests/jinja2-3.1.6.md |
| requests | CVE-2024-35195 | fixed | 2.31.0 → 2.33.0 | pull-requests/requests-2.33.0.md |
| requests | CVE-2024-47081 | fixed | 2.31.0 → 2.33.0 | pull-requests/requests-2.33.0.md |
| requests | CVE-2026-25645 | fixed | 2.31.0 → 2.33.0 | pull-requests/requests-2.33.0.md |
| urllib3 | CVE-2024-37891 | fixed | 1.26.18 → 2.8.0 | pull-requests/urllib3-2.8.0.md |
| urllib3 | CVE-2025-50181 | fixed | 1.26.18 → 2.8.0 | pull-requests/urllib3-2.8.0.md |
| urllib3 | CVE-2025-66418 | fixed | 1.26.18 → 2.8.0 | pull-requests/urllib3-2.8.0.md |
| urllib3 | CVE-2025-66471 | fixed | 1.26.18 → 2.8.0 | pull-requests/urllib3-2.8.0.md |
| urllib3 | CVE-2026-21441 | fixed | 1.26.18 → 2.8.0 | pull-requests/urllib3-2.8.0.md |
| urllib3 | CVE-2026-44431 | fixed | 1.26.18 → 2.8.0 | pull-requests/urllib3-2.8.0.md |
| urllib3 | CVE-2026-97687 | fixed | 1.26.18 → 2.8.0 | pull-requests/urllib3-2.8.0.md |
| urllib3 | CVE-2026-97689 | fixed | 1.26.18 → 2.8.0 | pull-requests/urllib3-2.8.0.md |
| werkzeug | CVE-2023-23934 | escalated (tests-failed) | 2.2.2 | issues/security-werkzeug-2-2-2-needs-manual-review-tests-failed.md |
| werkzeug | CVE-2023-25577 | escalated (tests-failed) | 2.2.2 | issues/security-werkzeug-2-2-2-needs-manual-review-tests-failed.md |
| werkzeug | CVE-2023-46136 | escalated (tests-failed) | 2.2.2 | issues/security-werkzeug-2-2-2-needs-manual-review-tests-failed.md |
| werkzeug | CVE-2024-34069 | escalated (tests-failed) | 2.2.2 | issues/security-werkzeug-2-2-2-needs-manual-review-tests-failed.md |
| werkzeug | CVE-2024-49766 | escalated (tests-failed) | 2.2.2 | issues/security-werkzeug-2-2-2-needs-manual-review-tests-failed.md |
| werkzeug | CVE-2024-49767 | escalated (tests-failed) | 2.2.2 | issues/security-werkzeug-2-2-2-needs-manual-review-tests-failed.md |
| werkzeug | CVE-2025-66221 | escalated (tests-failed) | 2.2.2 | issues/security-werkzeug-2-2-2-needs-manual-review-tests-failed.md |
| werkzeug | CVE-2026-102598 | escalated (tests-failed) | 2.2.2 | issues/security-werkzeug-2-2-2-needs-manual-review-tests-failed.md |
| werkzeug | CVE-2026-21860 | escalated (tests-failed) | 2.2.2 | issues/security-werkzeug-2-2-2-needs-manual-review-tests-failed.md |
| werkzeug | CVE-2026-27199 | escalated (tests-failed) | 2.2.2 | issues/security-werkzeug-2-2-2-needs-manual-review-tests-failed.md |

_Mode: rules (no model configured). The agent never merges; every change waits for a human._