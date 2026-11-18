# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""Shared pytest options and helpers.

Markers (pyproject.toml): nginx (needs a built .deb, ASan or valgrind binary), docker, network, slow.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# valgrind's memcheck as the tests run it. -q: only errors are printed, so any output is a finding. Leaks of the
# definite, indirect and possible kinds count as errors; still-reachable blocks do not.
VALGRIND = ("valgrind", "-q", "--error-exitcode=99", "--leak-check=full",
            "--show-leak-kinds=definite,indirect,possible", "--errors-for-leak-kinds=definite,indirect,possible",
            "--track-origins=yes", "--num-callers=30", "--vgdb=no")


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--target", default="ubuntu-24.04", help="dist/<target>/ to test (integration tests)")
    parser.addoption("--flavor", default="1.31", help="nginx flavor to test: 1.31 or 1.30")
    parser.addoption("--fuzz-seconds", type=int, default=60, help="libFuzzer run time per target")


def docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, check=False).returncode == 0


@pytest.fixture(scope="session")
def require_docker() -> None:
    if not docker_ok():
        pytest.skip("docker is not available")
