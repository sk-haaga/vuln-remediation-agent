"""Isolated copies of the target repository, and test runs inside them.

Every candidate upgrade is applied in its own git worktree (or a plain copy
when the target is not a git repository), installed into a fresh virtual
environment and tested there. The operator's checkout is never modified.
"""

from __future__ import annotations

import shlex
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import requirements_file
from .models import TestResult
from .sandbox import Sandbox

_TAIL = 4000
_COPY_IGNORE = shutil.ignore_patterns(".git", ".venv", "venv", ".vra-venv", "__pycache__", ".pytest_cache", "*.pyc")
DEV_REQUIREMENT_FILES = (
    "requirements-dev.txt",
    "requirements-test.txt",
    "dev-requirements.txt",
    "test-requirements.txt",
)


@dataclass
class Workspace:
    repo: Path
    requirements: Path  # relative to project_dir
    test_command: str
    sandbox: Sandbox
    python: str = "python3"
    base_ref: str = "HEAD"
    install_timeout: int = 900
    test_timeout: int = 900
    project_dir: Path = Path(".")  # subfolder of the repo that holds the Python project
    _root: Path = field(default_factory=lambda: Path(tempfile.mkdtemp(prefix="vra-")))
    _trees: dict[str, Path] = field(default_factory=dict)

    @property
    def is_git(self) -> bool:
        return (self.repo / ".git").exists()

    def test_argv(self) -> list[str]:
        return shlex.split(self.test_command)

    # -- copies -----------------------------------------------------------
    def checkout(self, key: str) -> Path:
        """A fresh, unmodified copy of the repository for ``key``."""
        if key in self._trees:
            self.discard(key)
        dest = self._root / key
        if self.is_git:
            res = self.sandbox.run(
                ["git", "-C", str(self.repo), "worktree", "add", "--detach", str(dest), self.base_ref]
            )
            if res.returncode != 0:
                raise RuntimeError(f"git worktree add failed: {res.stderr}")
        else:
            shutil.copytree(self.repo, dest, ignore=_COPY_IGNORE)
        self._trees[key] = dest
        return dest

    def path(self, key: str) -> Path:
        return self._trees[key]

    def project(self, key: str) -> Path:
        return self._trees[key] / self.project_dir

    @property
    def requirements_in_repo(self) -> Path:
        return self.project_dir / self.requirements

    def discard(self, key: str) -> None:
        dest = self._trees.pop(key, None)
        if dest is None:
            return
        if self.is_git:
            self.sandbox.run(["git", "-C", str(self.repo), "worktree", "remove", "--force", str(dest)])
        shutil.rmtree(dest, ignore_errors=True)

    def cleanup(self) -> None:
        for key in list(self._trees):
            self.discard(key)
        shutil.rmtree(self._root, ignore_errors=True)

    # -- edits ------------------------------------------------------------
    def apply_upgrade(self, key: str, package: str, version: str) -> None:
        if not requirements_file.set_version(self.project(key) / self.requirements, package, version):
            raise ValueError(f"{package} is not pinned in {self.requirements}")

    def diff(self, key: str) -> str:
        if self.is_git:
            return self.sandbox.run(["git", "-C", str(self.path(key)), "diff"]).stdout
        return ""

    # -- tests ------------------------------------------------------------
    def run_tests(self, key: str) -> TestResult:
        tree = self.project(key)
        venv = tree / ".vra-venv"
        start = time.monotonic()
        env = {"PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1", "PYTHONDONTWRITEBYTECODE": "1"}

        res = self.sandbox.run([self.python, "-m", "venv", str(venv)], cwd=tree)
        if res.returncode != 0:
            return TestResult(
                False, "install", res.returncode, (res.stdout + res.stderr)[-_TAIL:], time.monotonic() - start
            )

        vpy = str(venv / "bin" / "python")
        install = [vpy, "-m", "pip", "install", "-q", "-r", str(self.requirements)]
        for extra in DEV_REQUIREMENT_FILES:
            if (tree / extra).exists() and Path(extra) != self.requirements:
                install += ["-r", extra]
        res = self.sandbox.run(install, cwd=tree, env=env, timeout=self.install_timeout)
        if res.returncode != 0:
            return TestResult(
                False, "install", res.returncode, (res.stdout + res.stderr)[-_TAIL:], time.monotonic() - start
            )

        argv = self.test_argv()
        resolved = shutil.which(argv[0], path=str(venv / "bin"))
        if resolved:
            argv = [resolved, *argv[1:]]
        env["VIRTUAL_ENV"] = str(venv)
        res = self.sandbox.run(argv, cwd=tree, env=env, timeout=self.test_timeout)
        return TestResult(
            res.returncode == 0, "tests", res.returncode, (res.stdout + res.stderr)[-_TAIL:], time.monotonic() - start
        )
