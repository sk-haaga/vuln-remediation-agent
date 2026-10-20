# Upgrade certifi 2022.12.7 → 2024.7.4 (fixes 2 vulnerabilities)

Branch: `vra/certifi-2024.7.4`

`certifi` 2022.12.7 has 2 known vulnerabilities. Upgrading to 2024.7.4 fixes 2 of them; it is the smallest released version that does.

This is a major version upgrade, which may change or remove APIs. The tests passed, but please check the release notes for behaviour the tests do not cover.

### Facts (generated from tool results)

- Package: `certifi` (found by requirements)
- Current version: `2022.12.7`
- Proposed version: `2024.7.4` (major upgrade)
- Tests with the upgrade: **passed** in 4s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2023-37920 | Certifi 2023.07.22 removes root certificates from "e-Tugra" from the root store. | 2023.7.22 |
| CVE-2024-39689 | Certifi 2024.07.04 removes root certificates from "GLOBALTRUST" from the root store. | 2024.7.4 |

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._

<details><summary>Diff</summary>

```diff
diff --git a/requirements.txt b/requirements.txt
index 006fcf5..8812e87 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -2,5 +2,5 @@
 pyjwt==1.7.1
 ecdsa==0.18.0
 tqdm==4.65.0
-certifi==2022.12.7
+certifi==2024.7.4
 idna==3.4
```
</details>
