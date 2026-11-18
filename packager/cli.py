# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""Command line: `./build.sh <command>` (build.sh runs `python -m packager`)."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from . import build as build_mod
from . import sources
from .model import FLAVORS, REVISION_RE, TARGETS, Versions, native_target_name
from .util import REPO, BuildError, log


def _flavors(arg: str) -> list[str]:
    names = list(FLAVORS) if arg == "all" else arg.split(",")
    for n in names:
        if n not in FLAVORS:
            raise BuildError(f"unknown flavor {n!r}; choose from {', '.join(FLAVORS)} or all")
    return names


def _targets(arg: str) -> list[tuple[str, bool]]:
    """(target name, native?) pairs. 'native' = this distro without docker."""
    if arg == "native":
        return [(native_target_name(), True)]
    names = list(TARGETS) if arg == "all" else arg.split(",")
    out: list[tuple[str, bool]] = []
    for n in names:
        if n == "native":
            out.append((native_target_name(), True))
        elif n in TARGETS:
            out.append((n, False))
        else:
            raise BuildError(f"unknown target {n!r}; choose from native, {', '.join(TARGETS)} or all")
    return out


def cmd_fetch(a: argparse.Namespace) -> int:
    for name in _flavors(a.flavor):
        v = sources.resolve(FLAVORS[name], a.revision, offline=a.offline)
        print(f"{name}: nginx {v.nginx}  ->  {v.deb_filename}")
    return 0


def cmd_build(a: argparse.Namespace) -> int:
    targets = _targets(a.target)
    if any(not native for _, native in targets) and not build_mod.docker_available():
        raise BuildError("docker is not available; use --target native")
    versions: list[Versions] = []
    for name in _flavors(a.flavor):
        pin = a.nginx if a.flavor != "all" else None
        versions.append(sources.resolve(FLAVORS[name], a.revision, offline=a.offline, nginx=pin))
    built: list[Path] = []
    for target, native in targets:
        for v in versions:
            log(f"=== {target}{' (native)' if native else ''}: {v.deb_filename}")
            built.append(build_mod.build(target, v, native=native, jobs=a.jobs, lintian=not a.no_lintian))
    print("\n".join(str(p.relative_to(REPO)) for p in built))
    return 0


def cmd_package(a: argparse.Namespace) -> int:
    build_mod.package(Path(a.tree), a.target, a.jobs, lintian=not a.no_lintian)
    return 0


def cmd_testbuild(a: argparse.Namespace) -> int:
    from . import testbuild

    for name in _flavors(a.flavor):
        v = sources.resolve(FLAVORS[name], a.revision, offline=a.offline)
        print(testbuild.build(a.cmd, v, a.jobs).relative_to(REPO))
    return 0


def cmd_clean(a: argparse.Namespace) -> int:
    for d in ("build", "dist") + (("extern_src",) if a.all else ()):
        if (REPO / d).exists():
            log(f"removing {d}/")
            shutil.rmtree(REPO / d)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="build.sh", description="Build nginx-clientfp .deb packages.")
    sub = ap.add_subparsers(dest="cmd")

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--flavor", default="all", help="nginx line: 1.31, 1.30, or all")
        p.add_argument("--revision", default="1", help="Debian revision, the -N in the file name (gs9)")
        p.add_argument("--offline", action="store_true", help="use only tags already in extern_src/")

    p = sub.add_parser("fetch", help="update extern_src/ and print the versions a build would use")
    common(p)
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("build", help="build .deb packages into dist/<target>/")
    common(p)
    p.add_argument("--target", default="native",
                   help=f"native (this distro, no docker), all, or a comma list of: {', '.join(TARGETS)}")
    p.add_argument("--nginx", help="pin the nginx version (single flavor only)")
    p.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    p.add_argument("--no-lintian", action="store_true")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("package", help="(internal) dpkg-buildpackage a prepared tree")
    p.add_argument("--tree", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    p.add_argument("--no-lintian", action="store_true")
    p.set_defaults(func=cmd_package)

    p = sub.add_parser("asan", help="build an ASan/UBSan nginx into build/asan/<flavor>/ (tests only)")
    common(p)
    p.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    p.set_defaults(func=cmd_testbuild)

    p = sub.add_parser("valgrind", help="build an nginx to run under valgrind into build/valgrind/<flavor>/ "
                                        "(tests only)")
    common(p)
    p.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    p.set_defaults(func=cmd_testbuild)

    p = sub.add_parser("clean", help="remove build/ and dist/")
    p.add_argument("--all", action="store_true", help="also remove extern_src/")
    p.set_defaults(func=cmd_clean)

    a = ap.parse_args(argv)
    if a.cmd is None:
        a = ap.parse_args(["build", *(argv or [])])
    if hasattr(a, "revision") and not REVISION_RE.match(a.revision):
        ap.error(f"invalid Debian revision {a.revision!r}")
    try:
        rc: int = a.func(a)
        return rc
    except BuildError as e:
        log(f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
