# Security: jinja2 2.11.3 needs manual review (tests-failed)

The smallest safe upgrade breaks the test suite, so the agent did not open a pull request. The smallest safe version is 3.1.6 (major upgrade from 2.11.3). A major upgrade often needs code changes; the test output below shows where.

### Facts (generated from tool results)

- Package: `jinja2` (found by requirements)
- Current version: `2.11.3`
- Proposed version: `3.1.6` (major upgrade)
- Tests with the upgrade: **failed at the tests step (exit 2)** in 6s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2024-22195 | The xmlattr filter in affected versions of Jinja accepts keys containing spaces. | 3.1.3 |
| CVE-2024-34064 | The xmlattr filter in affected versions of Jinja accepts keys containing non-attribute characters. | 3.1.4 |
| CVE-2024-56326 | An oversight in how the Jinja sandboxed environment detects calls to str.format allows an attacker that controls the content of a template to execute arbitrary Python code. | 3.1.5 |
| CVE-2025-27516 | An oversight in how the Jinja sandboxed environment interacts with the /attr filter allows an attacker that controls the content of a template to execute arbitrary Python code. | 3.1.6 |

<details><summary>Test output (last lines)</summary>

```

==================================== ERRORS ====================================
____________________ ERROR collecting tests/test_render.py _____________________
ImportError while importing test module '/tmp/vra-wdj08j2a/jinja2/tests/test_render.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/usr/lib/python3.13/importlib/__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
tests/test_render.py:1: in <module>
    from reports import render
reports/render.py:2: in <module>
    from jinja2 import Environment, Markup
E   ImportError: cannot import name 'Markup' from 'jinja2' (/tmp/vra-wdj08j2a/jinja2/.vra-venv/lib/python3.13/site-packages/jinja2/__init__.py)
=========================== short test summary info ============================
ERROR tests/test_render.py
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
1 error in 0.17s

```
</details>

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._
