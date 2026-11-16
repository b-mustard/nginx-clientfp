"""Post-build checks on the produced .deb (gs6): OpenSSL is linked statically and none of its symbols are exported.

nginx links with -Wl,-E so dynamic modules can resolve nginx's own symbols. Every OpenSSL symbol exported from
the executable would take precedence over the system libssl/libcrypto for any library loaded into the process
(a dynamic module, or a library that a module pulls in), so OpenSSL calls in that library would silently run
against this OpenSSL. The check compares the executable's dynamic symbol table with every global symbol defined
in the static libssl.a / libcrypto.a that were linked in.
"""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .util import BuildError, log, run

FORBIDDEN_NEEDED = re.compile(r"^lib(ssl|crypto)\.so")


# The module and every HTTP/2 hook the nginx patch calls. nginx links with -Wl,-E, so they are in the dynamic symbol
# table; a missing one means the module or the patch did not make it into the build.
REQUIRED_SYMBOLS = frozenset({
    "ngx_http_clientfp_module",
    "ngx_http_clientfp_h2_settings_frame", "ngx_http_clientfp_h2_setting", "ngx_http_clientfp_h2_window_update",
    "ngx_http_clientfp_h2_priority", "ngx_http_clientfp_h2_stream", "ngx_http_clientfp_h2_pseudo_header",
    "ngx_http_clientfp_h2_headers_done",
})

@dataclass
class Report:
    deb: Path
    needed: list[str] = field(default_factory=list)
    exported_openssl: list[str] = field(default_factory=list)
    dynamic_symbols: int = 0
    openssl_symbols: int = 0
    nginx_v: str = ""
    missing_hooks: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (not self.exported_openssl and not self.missing_hooks
                and not any(FORBIDDEN_NEEDED.match(n) for n in self.needed))


def defined_globals(path: Path, *, dynamic: bool) -> set[str]:
    """Global (incl. weak) defined symbol names; versioned names are stripped of '@...'."""
    args = ["nm", "--defined-only", "--format=posix"]
    if dynamic:
        args.append("-D")
    out = run([*args, path], capture=True).stdout
    names: set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0].endswith(":"):  # "libssl.a[ssl_lib.o]:" member headers
            continue
        kind = parts[1]
        if (kind.isupper() and kind != "U") or kind in ("u", "i", "v", "w"):
            names.add(parts[0].split("@", 1)[0])
    return names


def needed_libs(binary: Path) -> list[str]:
    out = run(["readelf", "-d", binary], capture=True).stdout
    return re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", out)


def check(deb: Path, openssl_libs: list[Path]) -> Report:
    """Unpack deb and check /usr/sbin/nginx against the static OpenSSL archives it was built from."""
    report = Report(deb)
    for lib in openssl_libs:
        if not lib.is_file():
            raise BuildError(f"missing {lib}: cannot check symbol export")
    with tempfile.TemporaryDirectory(prefix="clientfp-verify-") as tmp:
        root = Path(tmp)
        run(["dpkg-deb", "-x", deb, root])
        binary = root / "usr/sbin/nginx"
        if not binary.is_file():
            raise BuildError(f"{deb} has no usr/sbin/nginx")

        report.needed = needed_libs(binary)
        exported = defined_globals(binary, dynamic=True)
        openssl: set[str] = set()
        for lib in openssl_libs:
            openssl |= defined_globals(lib, dynamic=False)
        report.dynamic_symbols = len(exported)
        report.openssl_symbols = len(openssl)
        report.exported_openssl = sorted(exported & openssl)
        report.missing_hooks = sorted(REQUIRED_SYMBOLS - exported)
        report.nginx_v = run([binary, "-V"], capture=True, check=False).stdout or ""

    log(f"{deb.name}: NEEDED={report.needed}")
    log(f"{deb.name}: {report.dynamic_symbols} exported symbols, {report.openssl_symbols} OpenSSL symbols, "
        f"{len(report.exported_openssl)} OpenSSL symbols exported")
    if report.missing_hooks:
        log("module/patch symbols missing from the binary: " + ", ".join(report.missing_hooks))
    if report.exported_openssl:
        log("exported OpenSSL symbols (first 20): " + ", ".join(report.exported_openssl[:20]))
    return report


def lintian(deb: Path) -> int:
    """Run lintian; returns its exit code (errors are reported, the caller decides)."""
    proc = run(["lintian", "--tag-display-limit", "0", "--suppress-tags-from-file",
                Path(__file__).resolve().parent / "lintian-suppress", deb], check=False)
    return proc.returncode
