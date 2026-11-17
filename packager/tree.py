"""Assemble the source tree that dpkg-buildpackage builds:

    build/<target>/<flavor>/<tree_name>/
        nginx/      nginx at the release tag + patches/nginx/<series>/*.patch
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
    """Apply the series' patches to an exported source tree, then prove they are applied.

    dest lies inside this project's git work tree (build/ is only gitignored). There `git apply` would take patch
    paths relative to the project root and silently skip every file outside dest's subdirectory, so repository
    discovery is stopped at dest's parent and git treats dest like a plain directory."""
    env = {"GIT_CEILING_DIRECTORIES": str(dest.parent.resolve())}
    for patch in patch_files(component, series):
        log(f"applying {patch.relative_to(REPO)}")
        run(["git", "apply", "--check", "-p1", patch], cwd=dest, env=env)
        run(["git", "apply", "-p1", patch], cwd=dest, env=env)
        if run(["git", "apply", "--check", "--reverse", "-p1", patch], cwd=dest, env=env, check=False).returncode:
            raise BuildError(f"{patch.name} is not applied to {dest} after git apply")


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

    shutil.copytree(MODULE, root / "clientfp", ignore=shutil.ignore_patterns("tests", "*.o", "*.a"))
    debian.render(root / "debian", v)
    return root
