"""Build orchestration.

Host side (`build`): resolve versions, prepare each tree, then compile + package either natively (target ==
this distro, gs3) or in a docker container per target (gs4). Container side (`package`): run
dpkg-buildpackage in a prepared tree, verify the result and copy it to dist/<target>/.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path

from . import tree, verify
from .model import TARGETS, Target, Versions
from .util import REPO, BuildError, log, run, which

DIST = REPO / "dist"
DOCKERFILE = Path(__file__).resolve().parent / "docker" / "Dockerfile"
CONTAINER_REPO = "/work"


@dataclass
class Artifact:
    target: str
    deb: str
    dbgsym: str | None
    nginx: str
    openssl: str
    revision: str
    exported_openssl_symbols: int
    needed: list[str]
    lintian_exit: int


# ------------------------------------------------------------------------------------------- container side

def package(tree_root: Path, target_name: str, jobs: int, lintian: bool = True) -> Artifact:
    """dpkg-buildpackage in tree_root, verify, copy to dist/<target>/. Runs natively or inside a container."""
    missing = run(["dpkg-checkbuilddeps"], cwd=tree_root, check=False)
    if missing.returncode != 0:
        raise BuildError("missing build dependencies (see above); install them with:\n"
                         "  sudo apt-get install build-essential debhelper dpkg-dev fakeroot lintian "
                         "libpcre2-dev zlib1g-dev\nor build in docker: ./build.sh build --target <distro>")

    meta = json.loads((tree_root / "debian" / "clientfp-build.json").read_text())
    run(["dpkg-buildpackage", "-b", "-uc", "-us", f"-j{jobs}"], cwd=tree_root,
        env={"DEB_BUILD_OPTIONS": f"parallel={jobs}"})

    parent = tree_root.parent
    deb = parent / meta["deb_filename"]
    if not deb.is_file():
        raise BuildError(f"dpkg-buildpackage did not produce {deb.name}")
    dbg = sorted(parent.glob("nginx-clientfp-dbgsym_*"))

    libs = [tree_root / "openssl" / ".openssl" / "lib" / name for name in ("libssl.a", "libcrypto.a")]
    report = verify.check(deb, libs)
    if not report.ok:
        raise BuildError(f"{deb.name}: OpenSSL is dynamically linked or its symbols are exported "
                         f"(NEEDED={report.needed}, exported={len(report.exported_openssl)})")
    lint = verify.lintian(deb) if lintian else -1

    out = DIST / target_name
    out.mkdir(parents=True, exist_ok=True)
    shutil.copy2(deb, out / deb.name)
    for d in dbg:
        shutil.copy2(d, out / d.name)
    art = Artifact(target_name, str((out / deb.name).relative_to(REPO)),
                   str((out / dbg[0].name).relative_to(REPO)) if dbg else None,
                   meta["nginx"], meta["openssl"], meta["revision"], len(report.exported_openssl),
                   report.needed, lint)
    (out / (deb.name + ".json")).write_text(json.dumps(asdict(art), indent=2) + "\n")
    log(f"OK {art.deb}")
    return art


# ------------------------------------------------------------------------------------------------ host side

def write_meta(tree_root: Path, v: Versions) -> None:
    (tree_root / "debian" / "clientfp-build.json").write_text(json.dumps({
        "nginx": v.nginx, "openssl": v.openssl, "revision": v.revision, "deb_filename": v.deb_filename,
    }) + "\n")


def docker_rootless() -> bool:
    """Rootless docker maps container root to the invoking user, so files written as root are ours."""
    out = run(["docker", "info", "--format", "{{json .SecurityOptions}}"], capture=True, check=False).stdout or ""
    return "rootless" in out


def docker_user_args() -> list[str]:
    return [] if docker_rootless() else ["--user", f"{os.getuid()}:{os.getgid()}"]


def docker_available() -> bool:
    return which("docker") and run(["docker", "info", "--format", "{{.ServerVersion}}"], capture=True,
                                   check=False).returncode == 0


def ensure_image(target: Target) -> None:
    digest = hashlib.sha256(DOCKERFILE.read_bytes() + target.image.encode()).hexdigest()[:16]
    have = run(["docker", "image", "inspect", "--format", '{{index .Config.Labels "clientfp.digest"}}',
                target.build_image], capture=True, check=False)
    if have.returncode == 0 and have.stdout.strip() == digest:
        return
    log(f"building docker image {target.build_image} from {target.image}")
    run(["docker", "build", "--pull", "--build-arg", f"BASE={target.image}", "--label", f"clientfp.digest={digest}",
         "-t", target.build_image, "-f", DOCKERFILE, DOCKERFILE.parent])


def package_in_docker(target: Target, tree_root: Path, jobs: int, lintian: bool) -> None:
    ensure_image(target)
    rel = tree_root.relative_to(REPO)
    run(["docker", "run", "--rm", *docker_user_args(), "-e", "HOME=/tmp",
         "-v", f"{REPO}:{CONTAINER_REPO}", "-w", CONTAINER_REPO, target.build_image,
         "python3", "-m", "packager", "package", "--tree", f"{CONTAINER_REPO}/{rel}", "--target", target.name,
         "--jobs", str(jobs), *([] if lintian else ["--no-lintian"])])


def build(target_name: str, v: Versions, *, native: bool, jobs: int, lintian: bool = True) -> Path:
    """Prepare the tree and produce dist/<target>/<deb>. Returns the .deb path."""
    root = tree.prepare(target_name, v)
    write_meta(root, v)
    if native:
        package(root, target_name, jobs, lintian)
    else:
        target = TARGETS[target_name]
        package_in_docker(target, root, jobs, lintian)
    deb = DIST / target_name / v.deb_filename
    if not deb.is_file():
        raise BuildError(f"expected {deb}")
    return deb
