# Upgrade ecdsa 0.18.0 → 0.19.2 (fixes 1 vulnerability)

Branch: `vra/ecdsa-0.19.2`

`ecdsa` 0.18.0 has 2 known vulnerabilities. Upgrading to 0.19.2 fixes 1 of them; it is the smallest released version that does.

This is a minor release: new features may be added, but it should stay backwards compatible.

1 issue(s) have no fixed release yet and remain: CVE-2024-23342.

### Facts (generated from tool results)

- Package: `ecdsa` (found by requirements)
- Current version: `0.18.0`
- Proposed version: `0.19.2` (minor upgrade)
- Tests with the upgrade: **passed** in 4s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2024-23342 | python-ecdsa has been found to be subject to a Minerva timing attack on the P-256 curve. | no fix released |
| CVE-2026-33936 | An issue in the low-level DER parsing functions can cause unexpected exceptions to be raised from the public API functions. | 0.19.2 |

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._

<details><summary>Diff</summary>

```diff
diff --git a/requirements.txt b/requirements.txt
index 006fcf5..79c2eca 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,6 +1,6 @@
 # auth-service runtime dependencies (pinned)
 pyjwt==1.7.1
-ecdsa==0.18.0
+ecdsa==0.19.2
 tqdm==4.65.0
 certifi==2022.12.7
 idna==3.4
```
</details>
