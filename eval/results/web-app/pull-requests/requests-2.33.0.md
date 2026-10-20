# Upgrade requests 2.31.0 → 2.33.0 (fixes 3 vulnerabilities)

Branch: `vra/requests-2.33.0`

`requests` 2.31.0 has 3 known vulnerabilities. Upgrading to 2.33.0 fixes 3 of them; it is the smallest released version that does.

This is a minor release: new features may be added, but it should stay backwards compatible.

### Facts (generated from tool results)

- Package: `requests` (found by requirements)
- Current version: `2.31.0`
- Proposed version: `2.33.0` (minor upgrade)
- Tests with the upgrade: **passed** in 5s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2024-35195 | When using a requests.Session , if the first request to a given origin is made with verify=False , TLS certificate verification may remain disabled for all subsequent requests to that origin, even if verify=True is expl… | 2.32.0 |
| CVE-2024-47081 | Due to a URL parsing issue, Requests releases prior to 2.32.4 may leak .netrc credentials to third parties for specific maliciously-crafted URLs. | 2.32.4 |
| CVE-2026-25645 | Prior to version 2.33.0, the requests.utils.extract_zipped_paths() utility function uses a predictable filename when extracting files from zip archives into the system temporary directory. | 2.33.0 |

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._

<details><summary>Diff</summary>

```diff
diff --git a/requirements.txt b/requirements.txt
index ebec501..2f041e1 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -4,7 +4,7 @@ jinja2==3.1.2
 markupsafe==2.1.5
 itsdangerous==2.1.2
 click==8.1.7
-requests==2.31.0
+requests==2.33.0
 urllib3==1.26.18
 charset-normalizer==3.3.2
 idna==3.6
```
</details>
