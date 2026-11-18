"""Builds of the patched nginx for the integration tests (t3). Not packaged.

- "asan": AddressSanitizer + UBSan, -O1.
- "valgrind": no sanitizers, -O2 as the package is, for running under valgrind's memcheck.

Both use the same prepared tree as a package build (patched nginx, module) and the target's build image, whose
libssl they link like the package does. NGX_DEBUG_PALLOC makes every nginx pool allocation a separate malloc(), so
ASan and memcheck see pool overflows too. The result is build/<kind>/<flavor>/sbin/nginx with prefix
build/<kind>/<flavor>/ (paths inside the container).
"""

from __future__ import annotations

from pathlib import Path

from . import tree
from .build import CONTAINER_REPO, docker_user_args, ensure_image
from .model import TARGETS, Versions
from .util import REPO, run

# nginx does unaligned 16/32-bit loads and stores on purpose where the CPU allows them (NGX_HAVE_NONALIGNED, set on
# x86), so UBSan's alignment check would abort on upstream code paths. The module's C cores keep the full check in
# tests/test_c_core.py and tests/test_fuzz.py.
SAN = ("-fsanitize=address,undefined -fno-sanitize=alignment -fno-sanitize-recover=undefined "
       "-fno-omit-frame-pointer")

# nginx before 1.31 copies the empty "-g" parameter in ngx_init_cycle() with memcpy(dst, NULL, 0): undefined in C,
# harmless in practice, and fixed upstream in 1.31 (the copy is skipped when the parameter is empty). On such a
# source tree, UBSan's nonnull-attribute check alone is turned off; ASan still catches any real NULL access.
NONNULL_FIX = "if (old_cycle->conf_param.len) {"


def sanitizer_flags(nginx_src: Path) -> str:
    cycle = (nginx_src / "src" / "core" / "ngx_cycle.c").read_text(encoding="utf-8", errors="replace")
    return SAN if NONNULL_FIX in cycle else f"{SAN} -fno-sanitize=nonnull-attribute"

CONFIGURE = [
    "--with-debug",
    "--with-threads",
    "--with-http_ssl_module",
    "--with-http_v2_module",
    "--with-http_v3_module",
    "--with-http_realip_module",
    "--with-http_stub_status_module",
    # not in the package, which uses epoll only: lets tests run the module's ClientHello wait under level-triggered
    # event methods (tests/integration/test_hello_wait.py)
    "--with-poll_module",
    "--with-select_module",
]


KINDS = ("asan", "valgrind")


def out_dir(kind: str, v: Versions) -> Path:
    return REPO / "build" / kind / v.flavor.name


def build(kind: str, v: Versions, jobs: int, target_name: str = "ubuntu-24.04") -> Path:
    target = TARGETS[target_name]
    root = tree.prepare(f"{kind}-src", v)
    out = out_dir(kind, v)
    rel_root = root.relative_to(REPO)
    rel_out = out.relative_to(REPO)
    if kind == "asan":
        san = sanitizer_flags(root / "nginx")
        cc_opt, ld_opt = f"-O1 -g {san} -DNGX_DEBUG_PALLOC=1", san
    else:
        cc_opt, ld_opt = "-O2 -g -DNGX_DEBUG_PALLOC=1", ""
    script = f"""
set -e
cd {CONTAINER_REPO}/{rel_root}/nginx
./auto/configure --prefix={CONTAINER_REPO}/{rel_out} {' '.join(CONFIGURE)} \\
    --add-module={CONTAINER_REPO}/{rel_root}/clientfp \\
    --with-cc-opt='{cc_opt}' --with-ld-opt='{ld_opt}'
make -j{jobs}
make install
"""
    ensure_image(target)
    run(["docker", "run", "--rm", *docker_user_args(), "-e", "HOME=/tmp", "-v", f"{REPO}:{CONTAINER_REPO}",
         "-w", CONTAINER_REPO, target.build_image, "bash", "-c", script])
    return out / "sbin" / "nginx"
