# Upgrade mako 1.2.1 → 1.3.12 (fixes 2 vulnerabilities)

Branch: `vra/mako-1.3.12`

`mako` 1.2.1 has 2 known vulnerabilities. Upgrading to 1.3.12 fixes 2 of them; it is the smallest released version that does.

This is a minor release: new features may be added, but it should stay backwards compatible.

### Facts (generated from tool results)

- Package: `mako` (found by requirements)
- Current version: `1.2.1`
- Proposed version: `1.3.12` (minor upgrade)
- Tests with the upgrade: **passed** in 5s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2022-40023 | Sqlalchemy mako before 1.2.2 is vulnerable to Regular expression Denial of Service when using the Lexer class to parse. | 1.2.2 |
| CVE-2026-44307 | On Windows, a URI using backslash traversal (e.g. | 1.3.12 |

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._

<details><summary>Diff</summary>

```diff
diff --git a/requirements.txt b/requirements.txt
index 4cfdafc..2f5752c 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,5 +1,5 @@
 jinja2==2.11.3
 markupsafe==2.0.1
-mako==1.2.1
+mako==1.3.12
 pygments==2.7.1
 sqlparse==0.4.1
```
</details>
