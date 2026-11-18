"""The packager's debian/ files: the changelog names the distribution the package is built for (decision 041)."""

from __future__ import annotations

from pathlib import Path

import pytest

from packager import debian
from packager.model import FLAVORS, TARGETS, Versions, distribution


@pytest.mark.parametrize("name", sorted(TARGETS))
def test_changelog_names_the_target_codename(name: str, tmp_path: Path) -> None:
    v = Versions(FLAVORS["1.31"], "1.31.8", "1")
    debian.render(tmp_path / "debian", v, distribution(name))
    first = (tmp_path / "debian" / "changelog").read_text().splitlines()[0]
    assert first == f"nginx-clientfp (1.31.8-1) {TARGETS[name].codename}; urgency=medium"


def test_native_build_on_other_distro_takes_codename_of_running_system(tmp_path: Path) -> None:
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=linuxmint\nVERSION_ID="22.1"\nVERSION_CODENAME=xia\n')
    assert distribution("linuxmint-22.1", os_release) == "xia"


def test_native_build_without_codename_is_refused(tmp_path: Path) -> None:
    os_release = tmp_path / "os-release"
    os_release.write_text("ID=example\nVERSION_ID=1\n")
    with pytest.raises(ValueError, match="VERSION_CODENAME"):
        distribution("example-1", os_release)
