"""Build matrix: flavors (nginx lines), targets (distros), resolved versions."""

from __future__ import annotations

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


REVISION_RE = re.compile(r"^[0-9][0-9A-Za-z.+~]*$")
