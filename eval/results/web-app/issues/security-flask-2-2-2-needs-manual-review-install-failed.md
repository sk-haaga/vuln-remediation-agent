# Security: flask 2.2.2 needs manual review (install-failed)

The smallest safe upgrade could not be installed alongside the other pinned dependencies (usually a version conflict), so the agent did not open a pull request. The smallest safe version is 3.1.3 (major upgrade from 2.2.2).

### Facts (generated from tool results)

- Package: `flask` (found by requirements)
- Current version: `2.2.2`
- Proposed version: `3.1.3` (major upgrade)
- Tests with the upgrade: **failed at the install step (exit 1)** in 3s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2023-30861 | When all of the following conditions are met, a response containing data intended for one client may be cached and subsequently sent by the proxy to other clients. | 2.2.5, 2.3.2 |
| CVE-2026-27205 | When the session object is accessed, Flask should set the Vary: Cookie header. | 3.1.3 |

<details><summary>Test output (last lines)</summary>

```
ERROR: Cannot install -r requirements.txt (line 1) and itsdangerous==2.1.2 because these package versions have conflicting dependencies.
ERROR: ResolutionImpossible: for help visit https://pip.pypa.io/en/latest/topics/dependency-resolution/#dealing-with-dependency-conflicts

```
</details>

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._
