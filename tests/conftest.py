"""Shared pytest options and helpers.

Markers (pyproject.toml): nginx (needs a built .deb or ASan binary), docker, network, slow.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


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
