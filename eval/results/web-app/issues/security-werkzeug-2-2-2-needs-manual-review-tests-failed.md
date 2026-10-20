# Security: werkzeug 2.2.2 needs manual review (tests-failed)

The smallest safe upgrade breaks the test suite, so the agent did not open a pull request. The smallest safe version is 3.1.9 (major upgrade from 2.2.2). A major upgrade often needs code changes; the test output below shows where.

### Facts (generated from tool results)

- Package: `werkzeug` (found by requirements)
- Current version: `2.2.2`
- Proposed version: `3.1.9` (major upgrade)
- Tests with the upgrade: **failed at the tests step (exit 2)** in 5s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2023-23934 | Browsers may allow "nameless" cookies that look like =value instead of key=value . | 2.2.3 |
| CVE-2023-25577 | Werkzeug's multipart form data parser will parse an unlimited number of parts, including file parts. | 2.2.3 |
| CVE-2023-46136 | If an upload of a file that starts with CR or LF and then is followed by megabytes of data without these characters: all of these bytes are appended chunk by chunk into internal bytearray and lookup for boundary is perf… | 2.3.8, 3.0.1 |
| CVE-2024-34069 | The debugger in affected versions of Werkzeug can allow an attacker to execute code on a developer's machine under some circumstances. | 3.0.3 |
| CVE-2024-49766 | On Python < 3.11 on Windows, os.path.isabs() does not catch UNC paths like //server/share . | 3.0.6 |
| CVE-2024-49767 | Applications using Werkzeug to parse multipart/form-data requests are vulnerable to resource exhaustion. | 3.0.6 |
| CVE-2025-66221 | Werkzeug's safe_join function allows path segments with Windows device names. | 3.1.4 |
| CVE-2026-102598 | Werkzeug's safe_join function allows Windows device names as filenames when they have an empty ADS marker on NTFS. | 3.1.9 |
| CVE-2026-21860 | Werkzeug's safe_join function allows path segments with Windows device names that have file extensions or trailing spaces. | 3.1.5 |
| CVE-2026-27199 | Werkzeug's safe_join function allows Windows device names as filenames if when preceded by other path segments. | 3.1.6 |

<details><summary>Test output (last lines)</summary>

```

==================================== ERRORS ====================================
______________________ ERROR collecting tests/test_app.py ______________________
ImportError while importing test module '/tmp/vra-zr7na54w/werkzeug/tests/test_app.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/usr/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
tests/test_app.py:1: in <module>
    from webapp.app import app, build_request
webapp/app.py:2: in <module>
    from flask import Flask, jsonify, render_template_string
.vra-venv/lib/python3.13/site-packages/flask/__init__.py:5: in <module>
    from .app import Flask as Flask
.vra-venv/lib/python3.13/site-packages/flask/app.py:30: in <module>
    from werkzeug.urls import url_quote
E   ImportError: cannot import name 'url_quote' from 'werkzeug.urls' (/tmp/vra-zr7na54w/werkzeug/.vra-venv/lib/python3.13/site-packages/werkzeug/urls.py)
=========================== short test summary info ============================
ERROR tests/test_app.py
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
1 error in 0.20s

```
</details>

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._
