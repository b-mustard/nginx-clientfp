"""AddressSanitizer + UBSan build of the patched nginx, for hostile-input tests (t3). Not packaged.

Uses the same prepared tree as a package build (patched nginx, OpenSSL, module) and the target's build image.
NGX_DEBUG_PALLOC makes every nginx pool allocation a separate malloc(), so ASan sees pool overflows too.
The result is build/asan/<flavor>/sbin/nginx with prefix build/asan/<flavor>/ (paths inside the container).
"""

from __future__ import annotations

from pathlib import Path

from . import tree
from .build import CONTAINER_REPO, docker_user_args, ensure_image
from .model import TARGETS, Versions
from .util import REPO, run

SAN = "-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"

CONFIGURE = [
    "--with-debug",
    "--with-threads",
    "--with-http_ssl_module",
    "--with-http_v2_module",
    "--with-http_v3_module",
    "--with-http_realip_module",
    "--with-http_stub_status_module",
]


def asan_dir(v: Versions) -> Path:
    return REPO / "build" / "asan" / v.flavor.name


def build(v: Versions, jobs: int, target_name: str = "ubuntu-24.04") -> Path:
    target = TARGETS[target_name]
    root = tree.prepare("asan-src", v)
    out = asan_dir(v)
    rel_root = root.relative_to(REPO)
    rel_out = out.relative_to(REPO)
    script = f"""
set -e
cd {CONTAINER_REPO}/{rel_root}/nginx
./auto/configure --prefix={CONTAINER_REPO}/{rel_out} {' '.join(CONFIGURE)} \\
    --with-openssl={CONTAINER_REPO}/{rel_root}/openssl --with-openssl-opt='no-module no-docs no-tests no-apps' \\
    --add-module={CONTAINER_REPO}/{rel_root}/clientfp \\
    --with-cc-opt='-O1 -g {SAN} -DNGX_DEBUG_PALLOC=1' --with-ld-opt='{SAN}'
make -j{jobs}
make install
"""
    ensure_image(target)
    run(["docker", "run", "--rm", *docker_user_args(), "-e", "HOME=/tmp", "-v", f"{REPO}:{CONTAINER_REPO}",
         "-w", CONTAINER_REPO, target.build_image, "bash", "-c", script])
    return out / "sbin" / "nginx"
