"""Small helpers shared by the packager: logging and subprocess execution."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

StrPath = str | os.PathLike[str]


class BuildError(RuntimeError):
    """A build step failed; the message is meant for the user."""


def log(msg: str) -> None:
    print(f"[packager] {msg}", file=sys.stderr, flush=True)


def run(
    cmd: Sequence[StrPath],
    *,
    cwd: StrPath | None = None,
    env: Mapping[str, str] | None = None,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a command (no shell). With capture=True stdout is returned, stderr passes through."""
    args = [os.fspath(c) for c in cmd]
    log("$ " + " ".join(shlex.quote(a) for a in args) + (f"   (in {cwd})" if cwd else ""))
    full_env = None if env is None else {**os.environ, **env}
    proc = subprocess.run(
        args,
        cwd=cwd,
        env=full_env,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        check=False,
    )
    if check and proc.returncode != 0:
        raise BuildError(f"command failed with exit code {proc.returncode}: {args[0]} {' '.join(args[1:3])} ...")
    return proc


def which(name: str) -> bool:
    from shutil import which as _which

    return _which(name) is not None
