"""Assemble the source tree that dpkg-buildpackage builds:

    build/<target>/<flavor>/<tree_name>/
        nginx/      nginx at the release tag + patches/nginx/<series>/*.patch
        openssl/    OpenSSL at the release tag + patches/openssl/<series>/*.patch (none today, decision 006)
        clientfp/   copy of nginx_module/
        debian/     rendered from packager/debian/
"""

from __future__ import annotations

import shutil
from pathlib import Path

from . import debian, sources
from .model import Target, Versions
from .util import REPO, BuildError, log, run

PATCHES = REPO / "patches"
MODULE = REPO / "nginx_module"
BUILD = REPO / "build"


def tree_dir(target: Target | str, v: Versions) -> Path:
    name = target if isinstance(target, str) else target.name
    return BUILD / name / v.flavor.name / v.tree_name


def patch_files(component: str, series: str) -> list[Path]:
    return sorted((PATCHES / component / series).glob("*.patch"))


def apply_patches(component: str, series: str, dest: Path) -> None:
    for patch in patch_files(component, series):
        log(f"applying {patch.relative_to(REPO)}")
        run(["git", "apply", "--check", "-p1", patch], cwd=dest)
        run(["git", "apply", "-p1", patch], cwd=dest)


def prepare(target_name: str, v: Versions) -> Path:
    """Create a fresh tree (an existing one is removed) and return its path."""
    root = tree_dir(target_name, v)
    if root.parent.exists():
        shutil.rmtree(root.parent)
    root.parent.mkdir(parents=True)

    if not patch_files("nginx", v.flavor.nginx_series):
        raise BuildError(f"no patches for nginx {v.flavor.nginx_series} in {PATCHES / 'nginx'}")

    sources.export(sources.NGINX_REPO, v.nginx_tag, root / "nginx")
    apply_patches("nginx", v.flavor.nginx_series, root / "nginx")

    sources.export(sources.OPENSSL_REPO, v.openssl_tag, root / "openssl")
    apply_patches("openssl", v.flavor.openssl_series, root / "openssl")

    shutil.copytree(MODULE, root / "clientfp", ignore=shutil.ignore_patterns("tests", "*.o", "*.a"))
    debian.render(root / "debian", v)
    return root
