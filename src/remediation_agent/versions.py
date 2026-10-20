"""Pick the smallest upgrade that leaves no fixable vulnerability behind.

The choice is made by code, not by the language model: the model can ask
for a plan but cannot invent a version number. Advisory "fixed in" data is
only used to skip versions that obviously cannot be clean; every candidate
is then confirmed against PyPI's own vulnerability list for that exact
version, which also catches vulnerabilities *introduced* in newer releases.
"""

from __future__ import annotations

import platform
from collections.abc import Callable

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from . import pypi
from .models import UpgradePlan, Vulnerability

MAX_CANDIDATES_CHECKED = 40


def bump_kind(old: Version, new: Version) -> str:
    a, b = (list(old.release) + [0, 0, 0])[:3], (list(new.release) + [0, 0, 0])[:3]
    if a[0] != b[0]:
        return "major"
    if a[1] != b[1]:
        return "minor"
    return "patch"


def _parse(v: str) -> Version | None:
    try:
        return Version(v)
    except InvalidVersion:
        return None


def _could_be_fixed(candidate: Version, current: Version, vuln: Vulnerability) -> bool:
    fixes = [f for f in (_parse(x) for x in vuln.fix_versions) if f is not None and f > current]
    return any(f <= candidate for f in fixes)


def plan_upgrade(
    package: str,
    current: str,
    vulns: list[Vulnerability],
    *,
    python_version: str | None = None,
    released: Callable[[str], list[Version]] = pypi.released_versions,
    vulns_for: Callable[[str, str], list[Vulnerability]] = pypi.version_vulns,
    requires_python: Callable[[str, str], str | None] = pypi.requires_python,
) -> UpgradePlan:
    cur = Version(current)
    py = Version(python_version or platform.python_version())
    fixable = [v for v in vulns if v.fix_versions]
    no_fix = [v.label for v in vulns if not v.fix_versions]

    if not fixable:
        return UpgradePlan(
            package, current, None, None, [], no_fix, reason="None of the vulnerabilities has a fixed release yet."
        )

    candidates = [v for v in released(package) if v > cur and all(_could_be_fixed(v, cur, x) for x in fixable)]
    checked = 0
    for cand in candidates:
        if checked >= MAX_CANDIDATES_CHECKED:
            break
        rp = requires_python(package, str(cand))
        if rp:
            try:
                if py not in SpecifierSet(rp):
                    continue
            except InvalidSpecifier:
                pass
        checked += 1
        remaining = vulns_for(package, str(cand))
        if any(r.fix_versions for r in remaining):
            continue  # still has something an upgrade could fix; keep looking
        remaining_ids = set().union(*(r.all_ids() for r in remaining)) if remaining else set()
        resolves = [v.label for v in vulns if not (v.all_ids() & remaining_ids)]
        return UpgradePlan(
            package=package,
            current=current,
            target=str(cand),
            bump=bump_kind(cur, cand),
            resolves=resolves,
            unfixable=[r.label for r in remaining],
        )

    return UpgradePlan(
        package,
        current,
        None,
        None,
        [],
        [v.label for v in vulns],
        reason=f"No released version of {package} newer than {current} is free of fixable "
        f"vulnerabilities and supports Python {py}.",
    )
