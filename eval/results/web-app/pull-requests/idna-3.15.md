# Upgrade idna 3.6 → 3.15 (fixes 2 vulnerabilities)

Branch: `vra/idna-3.15`

`idna` 3.6 has 2 known vulnerabilities. Upgrading to 3.15 fixes 2 of them; it is the smallest released version that does.

This is a minor release: new features may be added, but it should stay backwards compatible.

### Facts (generated from tool results)

- Package: `idna` (found by requirements)
- Current version: `3.6`
- Proposed version: `3.15` (minor upgrade)
- Tests with the upgrade: **passed** in 5s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2024-3651 | A vulnerability was identified in the kjd/idna library, specifically within the idna.encode() function, affecting version 3.6. | 3.7 |
| CVE-2026-45409 | This is the same issue as CVE-2024-3651, however the original remediation in 2024 was not a complete fix. | 3.15 |

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._

<details><summary>Diff</summary>

```diff
diff --git a/requirements.txt b/requirements.txt
index ebec501..473c21e 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -7,5 +7,5 @@ click==8.1.7
 requests==2.31.0
 urllib3==1.26.18
 charset-normalizer==3.3.2
-idna==3.6
+idna==3.15
 certifi==2024.7.4
```
</details>
