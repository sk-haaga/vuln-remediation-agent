# Upgrade jinja2 3.1.2 → 3.1.6 (fixes 5 vulnerabilities)

Branch: `vra/jinja2-3.1.6`

`jinja2` 3.1.2 has 5 known vulnerabilities. Upgrading to 3.1.6 fixes 5 of them; it is the smallest released version that does.

This is a patch release, so behaviour changes should be minimal.

### Facts (generated from tool results)

- Package: `jinja2` (found by requirements)
- Current version: `3.1.2`
- Proposed version: `3.1.6` (patch upgrade)
- Tests with the upgrade: **passed** in 5s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2024-22195 | The xmlattr filter in affected versions of Jinja accepts keys containing spaces. | 3.1.3 |
| CVE-2024-34064 | The xmlattr filter in affected versions of Jinja accepts keys containing non-attribute characters. | 3.1.4 |
| CVE-2024-56201 | A bug in the Jinja compiler allows an attacker that controls both the content and filename of a template to execute arbitrary Python code, regardless of if Jinja's sandbox is used. | 3.1.5 |
| CVE-2024-56326 | An oversight in how the Jinja sandboxed environment detects calls to str.format allows an attacker that controls the content of a template to execute arbitrary Python code. | 3.1.5 |
| CVE-2025-27516 | An oversight in how the Jinja sandboxed environment interacts with the /attr filter allows an attacker that controls the content of a template to execute arbitrary Python code. | 3.1.6 |

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._

<details><summary>Diff</summary>

```diff
diff --git a/requirements.txt b/requirements.txt
index ebec501..bfadd5e 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,6 +1,6 @@
 flask==2.2.2
 werkzeug==2.2.2
-jinja2==3.1.2
+jinja2==3.1.6
 markupsafe==2.1.5
 itsdangerous==2.1.2
 click==8.1.7
```
</details>
