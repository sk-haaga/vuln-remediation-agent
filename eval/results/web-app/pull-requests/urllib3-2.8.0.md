# Upgrade urllib3 1.26.18 → 2.8.0 (fixes 8 vulnerabilities)

Branch: `vra/urllib3-2.8.0`

`urllib3` 1.26.18 has 8 known vulnerabilities. Upgrading to 2.8.0 fixes 8 of them; it is the smallest released version that does.

This is a major version upgrade, which may change or remove APIs. The tests passed, but please check the release notes for behaviour the tests do not cover.

### Facts (generated from tool results)

- Package: `urllib3` (found by requirements)
- Current version: `1.26.18`
- Proposed version: `2.8.0` (major upgrade)
- Tests with the upgrade: **passed** in 5s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2024-37891 | When using urllib3's proxy support with ProxyManager , the Proxy-Authorization header is only sent to the configured proxy, as expected. | 1.26.19, 2.2.2 |
| CVE-2025-50181 | urllib3 handles redirects and retries using the same mechanism, which is controlled by the Retry object. | 2.5.0 |
| CVE-2025-66418 | urllib3 supports chained HTTP encoding algorithms for response content according to RFC 9110 (e.g., Content-Encoding: gzip, zstd ). | 2.6.0 |
| CVE-2025-66471 | urllib3's [streaming API](https://urllib3.readthedocs.io/en/2.5.0/advanced-usage.html streaming-and-i-o) is designed for the efficient handling of large HTTP responses by reading the content in chunks, rather than loadi… | 2.6.0 |
| CVE-2026-21441 | urllib3's [streaming API](https://urllib3.readthedocs.io/en/2.6.2/advanced-usage.html streaming-and-i-o) is designed for the efficient handling of large HTTP responses by reading the content in chunks, rather than loadi… | 2.6.3 |
| CVE-2026-44431 | From 1.23 to before 2.7.0, cross-origin redirects followed from the low-level API via ProxyManager.connection_from_url().urlopen(..., assert_same_host=False) still forward these sensitive headers. | 2.7.0 |
| CVE-2026-97687 | urllib3 supports configuring TLS independently for an HTTPS proxy and the target server. | 2.8.0 |
| CVE-2026-97689 | urllib3's [streaming API](https://urllib3.readthedocs.io/en/2.7.0/advanced-usage.html streaming-and-i-o) is designed for efficiently handling large HTTP responses by reading the content in chunks, rather than loading th… | 2.8.0 |

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._

<details><summary>Diff</summary>

```diff
diff --git a/requirements.txt b/requirements.txt
index ebec501..99457f6 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -5,7 +5,7 @@ markupsafe==2.1.5
 itsdangerous==2.1.2
 click==8.1.7
 requests==2.31.0
-urllib3==1.26.18
+urllib3==2.8.0
 charset-normalizer==3.3.2
 idna==3.6
 certifi==2024.7.4
```
</details>
