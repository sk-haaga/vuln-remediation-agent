# Upgrade tqdm 4.65.0 → 4.66.3 (fixes 1 vulnerability)

Branch: `vra/tqdm-4.66.3`

`tqdm` 4.65.0 has 1 known vulnerability. Upgrading to 4.66.3 fixes 1 of them; it is the smallest released version that does.

This is a minor release: new features may be added, but it should stay backwards compatible.

### Facts (generated from tool results)

- Package: `tqdm` (found by requirements)
- Current version: `4.65.0`
- Proposed version: `4.66.3` (minor upgrade)
- Tests with the upgrade: **passed** in 4s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2024-34062 | Any optional non-boolean CLI arguments (e.g. | 4.66.3 |

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._

<details><summary>Diff</summary>

```diff
diff --git a/requirements.txt b/requirements.txt
index 006fcf5..3adc84b 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,6 +1,6 @@
 # auth-service runtime dependencies (pinned)
 pyjwt==1.7.1
 ecdsa==0.18.0
-tqdm==4.65.0
+tqdm==4.66.3
 certifi==2022.12.7
 idna==3.4
```
</details>
