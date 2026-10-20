# Upgrade pygments 2.7.1 → 2.20.0 (fixes 4 vulnerabilities)

Branch: `vra/pygments-2.20.0`

`pygments` 2.7.1 has 4 known vulnerabilities. Upgrading to 2.20.0 fixes 4 of them; it is the smallest released version that does.

This is a minor release: new features may be added, but it should stay backwards compatible.

### Facts (generated from tool results)

- Package: `pygments` (found by requirements)
- Current version: `2.7.1`
- Proposed version: `2.20.0` (minor upgrade)
- Tests with the upgrade: **passed** in 5s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2021-20270 | An infinite loop in SMLLexer in Pygments versions 1.5 to 2.7.3 may lead to denial of service when performing syntax highlighting of a Standard ML (SML) source file, as demonstrated by input that only contains the "excep… | 2.7.4 |
| CVE-2021-27291 | In pygments 1.1+, fixed in 2.7.4, the lexers used to parse programming languages rely heavily on regular expressions. | 2.7.4 |
| CVE-2022-40896 | A ReDoS issue was discovered in pygments/lexers/smithy.py in Pygments until 2.15.0 via SmithyLexer. | 2.15.0, 2.15.1 |
| CVE-2026-4539 | A security flaw has been discovered in pygments before 2.20.0. | 2.20.0 |

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._

<details><summary>Diff</summary>

```diff
diff --git a/requirements.txt b/requirements.txt
index 4cfdafc..a7cd0d8 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,5 +1,5 @@
 jinja2==2.11.3
 markupsafe==2.0.1
 mako==1.2.1
-pygments==2.7.1
+pygments==2.20.0
 sqlparse==0.4.1
```
</details>
