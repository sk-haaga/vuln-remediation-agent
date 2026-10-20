"""Wrappers around pip-audit (dependencies) and Trivy (container image)."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from .models import PackageFinding, Source, Vulnerability
from .pypi import normalise
from .sandbox import Sandbox
from .vulns import merge_vulns


class ScanError(RuntimeError):
    pass


def pip_audit_executable() -> str | None:
    """pip-audit installed next to the running interpreter, else on PATH.

    Works when the agent runs from a virtualenv that was never activated.
    """
    beside = Path(sys.executable).parent / "pip-audit"
    return str(beside) if beside.exists() else shutil.which("pip-audit")


def pip_audit(sandbox: Sandbox, requirements: Path) -> list[PackageFinding]:
    """Scan a pinned requirements file. Exit code 1 just means "found something"."""
    exe = pip_audit_executable()
    if exe is None:
        raise ScanError("pip-audit is not installed")
    res = sandbox.run(
        [exe, "-r", str(requirements), "--disable-pip", "--no-deps", "--progress-spinner", "off", "-f", "json"],
        timeout=600,
    )
    if res.returncode not in (0, 1) or not res.stdout.strip():
        raise ScanError(f"pip-audit failed ({res.returncode}): {res.stderr[-2000:]}")
    return parse_pip_audit(json.loads(res.stdout))


def parse_pip_audit(data: dict) -> list[PackageFinding]:
    findings = []
    for dep in data.get("dependencies", []):
        raw = dep.get("vulns") or []
        if not raw:
            continue
        vulns = merge_vulns(
            [
                Vulnerability(
                    id=v["id"],
                    aliases=v.get("aliases") or [],
                    fix_versions=v.get("fix_versions") or [],
                    summary=(v.get("description") or "").strip(),
                )
                for v in raw
            ]
        )
        findings.append(PackageFinding(normalise(dep["name"]), dep["version"], Source.REQUIREMENTS, vulns))
    return findings


def trivy_image(sandbox: Sandbox, image: str) -> list[PackageFinding]:
    res = sandbox.run(["trivy", "image", "--quiet", "--scanners", "vuln", "--format", "json", image], timeout=1200)
    if res.returncode != 0:
        raise ScanError(f"trivy failed ({res.returncode}): {res.stderr[-2000:]}")
    return parse_trivy(json.loads(res.stdout))


def parse_trivy(data: dict) -> list[PackageFinding]:
    """Group Trivy results by package. Python packages are tagged so they can be
    matched to the requirements file; everything else is an OS package."""
    grouped: dict[tuple[str, str, Source], list[Vulnerability]] = {}
    for result in data.get("Results") or []:
        is_python = result.get("Type") in {"python-pkg", "pip", "pipenv", "poetry"}
        for v in result.get("Vulnerabilities") or []:
            name = v["PkgName"]
            source = Source.IMAGE_PYTHON if is_python else Source.IMAGE_OS
            key = (normalise(name) if is_python else name, v["InstalledVersion"], source)
            fixed = [x.strip() for x in (v.get("FixedVersion") or "").split(",") if x.strip()]
            grouped.setdefault(key, []).append(
                Vulnerability(
                    id=v["VulnerabilityID"],
                    aliases=[a for a in (v.get("VendorIDs") or []) if a != v["VulnerabilityID"]],
                    fix_versions=fixed,
                    summary=(v.get("Title") or v.get("Description") or "").strip(),
                    link=v.get("PrimaryURL") or "",
                    severity=v.get("Severity") or "",
                )
            )
    findings = []
    for (name, version, source), vulns in grouped.items():
        ecosystem = "pypi" if source is Source.IMAGE_PYTHON else "os"
        findings.append(PackageFinding(name, version, source, merge_vulns(vulns), ecosystem))
    return findings


def load_trivy_report(path: Path) -> list[PackageFinding]:
    return parse_trivy(json.loads(path.read_text()))
