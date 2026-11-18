# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""Build matrix: flavors (nginx lines), targets (distros), resolved versions."""

from __future__ import annotations

import functools
import itertools
import re
from dataclasses import dataclass
from pathlib import Path

PACKAGE = "nginx-clientfp"
ARCH = "amd64"

NGINX_GIT = "https://github.com/nginx/nginx.git"


@dataclass(frozen=True)
class Flavor:
    """One supported nginx line (gs5; built with the target distro's TLS library, decision 029)."""

    nginx_series: str  # "1.31"

    @property
    def name(self) -> str:
        return self.nginx_series

    @property
    def nginx_tag_re(self) -> re.Pattern[str]:
        return re.compile(r"^release-" + re.escape(self.nginx_series) + r"\.(\d+)$")


FLAVORS: dict[str, Flavor] = {
    "1.31": Flavor("1.31"),
    "1.30": Flavor("1.30"),
}


@dataclass(frozen=True)
class Target:
    """A distro the .deb is built for (gs3, gs4)."""

    name: str  # "ubuntu-24.04", also the dist/ subdirectory (decision 003)
    image: str  # docker base image
    codename: str  # VERSION_CODENAME in the image's /etc/os-release: the changelog distribution (decision 041)

    @property
    def build_image(self) -> str:
        return f"{PACKAGE}-build:{self.name}"


TARGETS: dict[str, Target] = {
    t.name: t
    for t in (
        Target("ubuntu-24.04", "ubuntu:24.04", "noble"),
        Target("ubuntu-26.04", "ubuntu:26.04", "resolute"),
        Target("debian-12", "debian:12", "bookworm"),
        Target("debian-13", "debian:13", "trixie"),
    )
}


OS_RELEASE = Path("/etc/os-release")


def os_release_fields(os_release: Path = OS_RELEASE) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in os_release.read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key] = value.strip().strip('"')
    return fields


def native_target_name(os_release: Path = OS_RELEASE) -> str:
    """'<ID>-<VERSION_ID>' of the running system, e.g. 'ubuntu-24.04'."""
    fields = os_release_fields(os_release)
    return f"{fields.get('ID', 'unknown')}-{fields.get('VERSION_ID', 'unknown')}"


def distribution(target_name: str, os_release: Path = OS_RELEASE) -> str:
    """The distribution field of debian/changelog: the codename of the target (decision 041). A native build on
    a distro that is not in TARGETS takes it from the running system."""
    if target_name in TARGETS:
        return TARGETS[target_name].codename
    codename = os_release_fields(os_release).get("VERSION_CODENAME", "")
    if not codename:
        raise ValueError(f"{os_release} has no VERSION_CODENAME: no distribution for the changelog of {target_name}")
    return codename


@dataclass(frozen=True)
class Versions:
    """Exact versions of one build."""

    flavor: Flavor
    nginx: str  # "1.31.8"
    revision: str  # "1" (gs9: configurable)

    @property
    def nginx_tag(self) -> str:
        return f"release-{self.nginx}"

    @property
    def deb_version(self) -> str:
        return f"{self.nginx}-{self.revision}"  # decision 031

    @property
    def deb_filename(self) -> str:
        return f"{PACKAGE}_{self.deb_version}_{ARCH}.deb"

    @property
    def tree_name(self) -> str:
        return f"{PACKAGE}-{self.nginx}"


REVISION = r"[0-9][0-9A-Za-z.+~]*"
REVISION_RE = re.compile(rf"^{REVISION}$")


_VERSION_PART = re.compile(r"([^0-9]*)([0-9]*)")


def _weights(text: str) -> list[int]:
    """dpkg's order of the characters between numbers: "~" before the end, then letters, then the others."""
    return [-1 if c == "~" else ord(c) if c.isascii() and c.isalpha() else ord(c) + 256 for c in text] + [0]


def _compare_part(a: str, b: str) -> int:
    parts = itertools.zip_longest(_VERSION_PART.findall(a), _VERSION_PART.findall(b), fillvalue=("", ""))
    for (text_a, num_a), (text_b, num_b) in parts:
        wa, wb = _weights(text_a), _weights(text_b)
        if wa != wb:
            return -1 if wa < wb else 1
        na, nb = int(num_a or 0), int(num_b or 0)
        if na != nb:
            return -1 if na < nb else 1
    return 0


def compare_versions(a: str, b: str) -> int:
    """Order two package versions without an epoch, "1.31.9-1", as dpkg does: <0, 0 or >0 (decision 048)."""
    upstream_a, _, revision_a = a.rpartition("-") if "-" in a else (a, "", "")
    upstream_b, _, revision_b = b.rpartition("-") if "-" in b else (b, "", "")
    return _compare_part(upstream_a, upstream_b) or _compare_part(revision_a, revision_b)


def newest_deb(directory: Path, flavor: str) -> Path | None:
    """The package of a flavor in a dist/<target>/ directory with the highest version (decision 048). Only names of
    the current scheme count (decision 031)."""
    name = re.compile(rf"{re.escape(PACKAGE)}_({re.escape(flavor)}\.[0-9]+-{REVISION})_{re.escape(ARCH)}\.deb")
    found = [(m.group(1), p) for p in directory.glob(f"{PACKAGE}_{flavor}.*_{ARCH}.deb")
             if (m := name.fullmatch(p.name))]
    if not found:
        return None
    order = functools.cmp_to_key(compare_versions)
    return max(found, key=lambda version_path: order(version_path[0]))[1]
