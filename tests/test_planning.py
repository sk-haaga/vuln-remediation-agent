"""Version planning, alias merging, requirements editing and scanner parsing (all offline)."""

from __future__ import annotations

import pytest
from packaging.version import Version

from remediation_agent import requirements_file
from remediation_agent.explain import first_sentence
from remediation_agent.models import Source, Vulnerability
from remediation_agent.scanners import parse_pip_audit, parse_trivy
from remediation_agent.versions import bump_kind, plan_upgrade
from remediation_agent.vulns import merge_vulns

V = Vulnerability


def fake_index(releases, vulns_by_version, requires=None):
    return dict(
        released=lambda pkg: [Version(r) for r in releases],
        vulns_for=lambda pkg, ver: vulns_by_version.get(ver, []),
        requires_python=lambda pkg, ver: (requires or {}).get(ver),
    )


def test_picks_smallest_clean_version():
    cve = V("CVE-1", fix_versions=["1.2.3"])
    idx = fake_index(["1.0.0", "1.2.2", "1.2.3", "1.3.0", "2.0.0"], {})
    plan = plan_upgrade("pkg", "1.0.0", [cve], python_version="3.12", **idx)
    assert (plan.target, plan.bump, plan.resolves) == ("1.2.3", "minor", ["CVE-1"])


def test_skips_version_with_a_new_fixable_vulnerability():
    old = V("CVE-1", fix_versions=["1.1.0"])
    new = V("CVE-2", fix_versions=["1.1.1"])
    idx = fake_index(["1.0.0", "1.1.0", "1.1.1"], {"1.1.0": [new]})
    assert plan_upgrade("pkg", "1.0.0", [old], python_version="3.12", **idx).target == "1.1.1"


def test_accepts_version_whose_only_issues_have_no_fix():
    fixable = V("CVE-1", fix_versions=["0.19.2"])
    unfixable = V("CVE-2", fix_versions=[])
    idx = fake_index(["0.18.0", "0.19.2"], {"0.19.2": [unfixable]})
    plan = plan_upgrade("ecdsa", "0.18.0", [fixable, unfixable], python_version="3.12", **idx)
    assert plan.target == "0.19.2" and plan.resolves == ["CVE-1"] and plan.unfixable == ["CVE-2"]


def test_nothing_to_do_when_no_fix_exists():
    plan = plan_upgrade("pkg", "1.0", [V("CVE-1")], python_version="3.12", **fake_index(["1.0", "2.0"], {}))
    assert plan.target is None and plan.unfixable == ["CVE-1"]


def test_respects_requires_python():
    cve = V("CVE-1", fix_versions=["1.1"])
    idx = fake_index(["1.0", "1.1", "1.2"], {}, requires={"1.1": ">=3.14"})
    assert plan_upgrade("pkg", "1.0", [cve], python_version="3.12", **idx).target == "1.2"


def test_branch_fixes_confirmed_against_index():
    # fixed in 2.2.28 on the 2.x line and 3.2.13 on the 3.x line; 3.0.0 is still affected
    cve = V("CVE-1", fix_versions=["2.2.28", "3.2.13"])
    idx = fake_index(["3.0.0", "3.2.12", "3.2.13"], {"3.0.0": [cve], "3.2.12": [cve]})
    assert plan_upgrade("django", "2.2.0", [cve], python_version="3.12", **idx).target == "3.2.13"


@pytest.mark.parametrize("a,b,kind", [("1.2.3", "1.2.4", "patch"), ("1.2", "1.3", "minor"), ("1.9", "2.0", "major")])
def test_bump_kind(a, b, kind):
    assert bump_kind(Version(a), Version(b)) == kind


def test_aliases_are_merged_and_counted_once():
    merged = merge_vulns(
        [
            V("PYSEC-2022-202", ["CVE-2022-29217", "GHSA-ffqj"], ["2.4.0"]),
            V("GHSA-ffqj", ["CVE-2022-29217"], ["2.4.0"]),
            V("PYSEC-2026-120", ["CVE-2026-32597"], ["2.12.0"]),
        ]
    )
    assert [m.id for m in merged] == ["CVE-2022-29217", "CVE-2026-32597"]


def test_requirements_rewrite_keeps_formatting(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("# web\nRequests[socks] == 2.25.1 ; python_version >= '3.8'  # http\nflask==2.2.2\n")
    assert requirements_file.pinned(req) == {"requests": "2.25.1", "flask": "2.2.2"}
    assert requirements_file.set_version(req, "requests", "2.33.0")
    assert req.read_text() == "# web\nRequests[socks] == 2.33.0 ; python_version >= '3.8'  # http\nflask==2.2.2\n"


def test_hash_pinned_lines_are_left_to_lock_tooling(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask==2.2.2 \\\n    --hash=sha256:abc\n")
    with pytest.raises(ValueError):
        requirements_file.set_version(req, "flask", "2.2.5")


def test_parse_pip_audit():
    data = {
        "dependencies": [
            {
                "name": "PyJWT",
                "version": "1.7.1",
                "vulns": [
                    {
                        "id": "PYSEC-2022-202",
                        "fix_versions": ["2.4.0"],
                        "aliases": ["CVE-2022-29217"],
                        "description": "x",
                    },
                    {
                        "id": "PYSEC-2022-202",
                        "fix_versions": ["2.4.0"],
                        "aliases": ["CVE-2022-29217"],
                        "description": "y",
                    },
                ],
            },
            {"name": "flask", "version": "3.1.3", "vulns": []},
        ]
    }
    (f,) = parse_pip_audit(data)
    assert (f.name, f.version, len(f.vulns)) == ("pyjwt", "1.7.1", 1)


def test_parse_trivy_splits_python_and_os_packages():
    # Shape of `trivy image --format json` output (synthetic values for the test).
    data = {
        "Results": [
            {
                "Target": "debian 12",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.11-1",
                        "FixedVersion": "3.0.13-1",
                        "Severity": "HIGH",
                        "Title": "openssl: example",
                    }
                ],
            },
            {
                "Target": "Python",
                "Type": "python-pkg",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2022-29217",
                        "VendorIDs": ["GHSA-ffqj-6fqr-9h24"],
                        "PkgName": "PyJWT",
                        "InstalledVersion": "1.7.1",
                        "FixedVersion": "2.4.0",
                        "Severity": "HIGH",
                    }
                ],
            },
        ]
    }
    by_source = {f.source: f for f in parse_trivy(data)}
    assert by_source[Source.IMAGE_OS].name == "openssl"
    assert by_source[Source.IMAGE_PYTHON].name == "pyjwt"
    assert by_source[Source.IMAGE_PYTHON].vulns[0].fix_versions == ["2.4.0"]


def test_first_sentence_skips_headings_and_boilerplate():
    text = (
        "### Summary\nPyJWT is a JSON Web Token implementation in Python. Prior to 2.13.0, `get_signing_key` refetches."
    )
    assert first_sentence(text) == "Prior to 2.13.0, get_signing_key refetches."
