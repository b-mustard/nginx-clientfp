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

    @property
    def build_image(self) -> str:
        return f"{PACKAGE}-build:{self.name}"


TARGETS: dict[str, Target] = {
    t.name: t
    for t in (
        Target("ubuntu-24.04", "ubuntu:24.04"),
        Target("ubuntu-26.04", "ubuntu:26.04"),
        Target("debian-12", "debian:12"),
        Target("debian-13", "debian:13"),
    )
}


def native_target_name(os_release: Path = Path("/etc/os-release")) -> str:
    """'<ID>-<VERSION_ID>' of the running system, e.g. 'ubuntu-24.04'."""
    fields: dict[str, str] = {}
    for line in os_release.read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key] = value.strip().strip('"')
    return f"{fields.get('ID', 'unknown')}-{fields.get('VERSION_ID', 'unknown')}"


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
