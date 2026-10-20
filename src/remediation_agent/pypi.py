"""Small read-only client for the PyPI JSON API.

PyPI publishes the known vulnerabilities for every released version
(sourced from the OSV / PyPA advisory database). The agent uses it both to
look up advisories and to check that a candidate upgrade is actually clean.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from functools import lru_cache

from packaging.version import InvalidVersion, Version

from .models import Vulnerability
from .vulns import merge_vulns

PYPI = "https://pypi.org/pypi"
_TIMEOUT = 30


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@lru_cache(maxsize=512)
def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "vuln-remediation-agent"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return json.load(resp)


def _to_vuln(raw: dict) -> Vulnerability:
    summary = (raw.get("summary") or raw.get("details") or "").strip()
    return Vulnerability(
        id=raw["id"],
        aliases=list(raw.get("aliases") or []),
        fix_versions=list(raw.get("fixed_in") or []),
        summary=summary,
        link=raw.get("link") or "",
    )


def version_vulns(package: str, version: str) -> list[Vulnerability]:
    """Known vulnerabilities affecting exactly ``package==version`` (aliases merged)."""
    data = _get(f"{PYPI}/{normalise(package)}/{version}/json")
    return merge_vulns([_to_vuln(v) for v in data.get("vulnerabilities") or []])


def released_versions(package: str) -> list[Version]:
    """All final, non-yanked releases that have at least one file, oldest first."""
    data = _get(f"{PYPI}/{normalise(package)}/json")
    out = []
    for raw, files in (data.get("releases") or {}).items():
        try:
            v = Version(raw)
        except InvalidVersion:
            continue
        if v.is_prerelease or v.is_devrelease:
            continue
        if not files or all(f.get("yanked") for f in files):
            continue
        out.append(v)
    return sorted(out)


def requires_python(package: str, version: str) -> str | None:
    data = _get(f"{PYPI}/{normalise(package)}/{version}/json")
    return (data.get("info") or {}).get("requires_python")


def reachable() -> bool:
    try:
        _get.__wrapped__(f"{PYPI}/pip/json")
        return True
    except (urllib.error.URLError, TimeoutError):
        return False
