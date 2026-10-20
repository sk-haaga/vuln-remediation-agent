"""Read and rewrite pinned requirements files without disturbing formatting."""

from __future__ import annotations

import re
from pathlib import Path

from .pypi import normalise

_PIN = re.compile(
    r"^(?P<lead>\s*)(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?"
    r"(?P<ws1>\s*)==(?P<ws2>\s*)(?P<version>[A-Za-z0-9.!+*_-]+)(?P<rest>.*)$"
)


def pinned(path: Path) -> dict[str, str]:
    """``{normalised name: version}`` for every ``name==version`` line."""
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        m = _PIN.match(line)
        if m:
            out[normalise(m["name"])] = m["version"]
    return out


def set_version(path: Path, package: str, new_version: str) -> bool:
    """Change the pin for ``package``. Keeps extras, markers and comments.

    Hash-pinned lines are refused: their hashes would no longer match and
    regenerating them is a job for the project's lock tooling.
    """
    lines = path.read_text().splitlines(keepends=True)
    target = normalise(package)
    changed = False
    for i, line in enumerate(lines):
        body = line.rstrip("\r\n")
        m = _PIN.match(body)
        if not m or normalise(m["name"]) != target:
            continue
        if "--hash" in m["rest"] or (i + 1 < len(lines) and lines[i + 1].lstrip().startswith("--hash")):
            raise ValueError(f"{package} is hash-pinned; regenerate the lock file instead")
        new = f"{m['lead']}{m['name']}{m['extras'] or ''}{m['ws1']}=={m['ws2']}{new_version}{m['rest']}"
        lines[i] = new + line[len(body) :]
        changed = True
    if changed:
        path.write_text("".join(lines))
    return changed
