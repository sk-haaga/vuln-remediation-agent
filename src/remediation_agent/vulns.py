"""Merge duplicate vulnerability records.

Scanners and advisory databases report the same issue under several ids
(PYSEC-…, GHSA-…, CVE-…). Counting those separately would inflate the
numbers, so any records whose ids overlap are merged into one.
"""

from __future__ import annotations

from .models import Vulnerability


def _preferred_id(ids: set[str]) -> str:
    for prefix in ("CVE-", "GHSA-", "PYSEC-"):
        matches = sorted(i for i in ids if i.startswith(prefix))
        if matches:
            return matches[0]
    return sorted(ids)[0]


def merge_vulns(records: list[Vulnerability]) -> list[Vulnerability]:
    groups: list[tuple[set[str], list[Vulnerability]]] = []
    for rec in records:
        ids = rec.all_ids()
        hit = [g for g in groups if g[0] & ids]
        merged_ids, merged_recs = set(ids), [rec]
        for g in hit:
            merged_ids |= g[0]
            merged_recs += g[1]
            groups.remove(g)
        groups.append((merged_ids, merged_recs))

    out: list[Vulnerability] = []
    for ids, recs in groups:
        canonical = _preferred_id(ids)
        fixes: list[str] = []
        for r in recs:
            for f in r.fix_versions:
                if f not in fixes:
                    fixes.append(f)
        # Prefer the most concise description that still says something (NVD-style
        # text) over long markdown write-ups with proof-of-concept code.
        texts = sorted((r.summary for r in recs if r.summary), key=len)
        summary = next((t for t in texts if len(t) >= 60), texts[-1] if texts else "")
        link = next((r.link for r in recs if r.link), "")
        severity = next((r.severity for r in recs if r.severity), "")
        out.append(
            Vulnerability(
                id=canonical,
                aliases=sorted(ids - {canonical}),
                fix_versions=fixes,
                summary=summary,
                link=link,
                severity=severity,
            )
        )
    return sorted(out, key=lambda v: v.label)
