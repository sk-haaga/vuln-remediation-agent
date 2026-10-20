# Upgrade sqlparse 0.4.1 → 0.6.0 (fixes 9 vulnerabilities)

Branch: `vra/sqlparse-0.6.0`

`sqlparse` 0.4.1 has 9 known vulnerabilities. Upgrading to 0.6.0 fixes 9 of them; it is the smallest released version that does.

This is a minor release: new features may be added, but it should stay backwards compatible.

### Facts (generated from tool results)

- Package: `sqlparse` (found by requirements)
- Current version: `0.4.1`
- Proposed version: `0.6.0` (minor upgrade)
- Tests with the upgrade: **passed** in 5s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2021-32839 | In sqlparse versions 0.4.0 and 0.4.1 there is a regular Expression Denial of Service in sqlparse vulnerability. | 0.4.2 |
| CVE-2023-30608 | In affected versions the SQL parser contains a regular expression that is vulnerable to ReDoS (Regular Expression Denial of Service). | 0.4.4 |
| CVE-2024-4340 | Passing a heavily nested list to sqlparse.parse() leads to a Denial of Service due to RecursionError. | 0.5.0 |
| CVE-2026-54284 | sqlparse ships hard limits ( MAX_GROUPING_DEPTH=100 , MAX_GROUPING_TOKENS=10000 ) intended to bound parsing work on attacker-supplied SQL, but the path that reaches those limits is itself O(n depth) per token-group cons… | 0.6.0 |
| CVE-2026-59893 | sqlparse contains a Regular Expression Denial of Service (ReDoS) vulnerability in its dollar-quoted SQL literal lexer. | 0.6.0 |
| CVE-2026-59894 | The documented Python and PHP output modes generate source-code snippets from caller-supplied SQL. | 0.6.0 |
| CVE-2026-71491 | A comment-only statement ( -- c\n n) may cause a Denial of Service (DoS). | 0.6.0 |
| CVE-2026-84305 | When SQL is formatted with reindentation enabled, ReindentFilter repeatedly rebuilds prefixes of the current statement to calculate token offsets. | 0.6.0 |
| GHSA-27jp-wm6q-gp25 | The below gist hangs while attempting to format a long list of tuples. | 0.5.4 |

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._

<details><summary>Diff</summary>

```diff
diff --git a/requirements.txt b/requirements.txt
index 4cfdafc..138bae0 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -2,4 +2,4 @@ jinja2==2.11.3
 markupsafe==2.0.1
 mako==1.2.1
 pygments==2.7.1
-sqlparse==0.4.1
+sqlparse==0.6.0
```
</details>
