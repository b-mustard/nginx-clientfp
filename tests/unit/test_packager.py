# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""The packager's debian/ files: the changelog names the distribution the package is built for (decision 041).
The tests use the package with the highest version, in the order of dpkg (decision 048)."""

from __future__ import annotations

from pathlib import Path

import pytest

from packager import debian
from packager.model import FLAVORS, TARGETS, Versions, compare_versions, distribution, newest_deb


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


# Each pair is in the order of `dpkg --compare-versions`.
@pytest.mark.parametrize("older, newer", [
    ("1.31.9-1", "1.31.10-1"),         # numbers, not text: 9 < 10
    ("1.31.9-9", "1.31.9-10"),
    ("1.31.9-1", "1.31.9-2"),
    ("1.31.10~rc1-1", "1.31.10-1"),    # "~" comes before the end
    ("1.31.9-1~rc1", "1.31.9-1"),
    ("1.31.9-1~~", "1.31.9-1~"),
    ("1.31.9-1", "1.31.9-1a"),         # the end comes before any other character
    ("1.31.9-1a", "1.31.9-1+b1"),      # letters come before the other characters
    ("1.31.9-1a", "1.31.9-1.1"),
    ("1.31.9-1+b1", "1.31.9-1.1"),     # the other characters in ASCII order
])
def test_compare_versions(older: str, newer: str) -> None:
    assert compare_versions(older, newer) < 0
    assert compare_versions(newer, older) > 0
    assert compare_versions(newer, newer) == 0


def test_compare_versions_ignores_leading_zeros() -> None:
    assert compare_versions("1.31.9-01", "1.31.9-1") == 0


def test_newest_deb_takes_the_highest_version(tmp_path: Path) -> None:
    for name in ("nginx-clientfp_1.31.9-1_amd64.deb",
                 "nginx-clientfp_1.31.10-1_amd64.deb",
                 "nginx-clientfp_1.31.10-1~rc1_amd64.deb",
                 "nginx-clientfp_1.30.7-1_amd64.deb",
                 "nginx-clientfp_1.31.8+openssl4.0.3-1_amd64.deb",   # the scheme before decision 031
                 "nginx-clientfp-dbgsym_1.31.11-1_amd64.deb",
                 "nginx-clientfp_1.31.11-1_amd64.deb.json"):
        (tmp_path / name).touch()
    assert newest_deb(tmp_path, "1.31") == tmp_path / "nginx-clientfp_1.31.10-1_amd64.deb"
    assert newest_deb(tmp_path, "1.30") == tmp_path / "nginx-clientfp_1.30.7-1_amd64.deb"
    assert newest_deb(tmp_path, "1.29") is None
    assert newest_deb(tmp_path / "missing", "1.31") is None
