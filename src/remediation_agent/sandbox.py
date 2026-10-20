"""The only way the agent runs external programs.

Every subprocess goes through ``run``, which refuses anything not on the
executable allowlist and logs each call to the audit log. There is no shell:
arguments are passed as a list, so nothing the model writes can be
interpreted as a command.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

# Programs the agent may start. The test command is added at runtime from the
# operator's configuration (never from the model).
ALLOWED_EXECUTABLES = {"pip-audit", "trivy", "git", "python", "python3", "pip"}


class CommandNotAllowed(PermissionError):
    pass


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    duration_s: float


class Sandbox:
    def __init__(self, audit_log: Path | None = None, extra_allowed: set[str] | None = None):
        self.allowed = set(ALLOWED_EXECUTABLES) | set(extra_allowed or ())
        self.audit_log = audit_log

    def _log(self, record: dict) -> None:
        if self.audit_log:
            self.audit_log.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_log.open("a") as fh:
                fh.write(json.dumps(record) + "\n")

    def run(
        self, argv: list[str], *, cwd: Path | None = None, timeout: int = 900, env: dict[str, str] | None = None
    ) -> CommandResult:
        exe = Path(argv[0]).name
        if exe not in self.allowed and not re.fullmatch(r"python3\.\d+", exe):
            self._log({"event": "command_refused", "argv": argv, "ts": time.time()})
            raise CommandNotAllowed(f"'{exe}' is not on the approved executable list")
        full_env = {**os.environ, **(env or {})}
        start = time.monotonic()
        try:
            proc = subprocess.run(argv, cwd=cwd, env=full_env, capture_output=True, text=True, timeout=timeout)
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            partial = e.stdout or ""
            if isinstance(partial, bytes):
                partial = partial.decode(errors="replace")
            rc, out, err = 124, partial, f"timed out after {timeout}s"
        except FileNotFoundError as e:
            rc, out, err = 127, "", str(e)
        dur = time.monotonic() - start
        self._log(
            {
                "event": "command",
                "argv": argv,
                "cwd": str(cwd) if cwd else None,
                "returncode": rc,
                "duration_s": round(dur, 2),
                "ts": time.time(),
            }
        )
        return CommandResult(rc, out, err, dur)
