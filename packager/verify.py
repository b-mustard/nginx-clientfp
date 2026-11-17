"""Post-build checks on the produced .deb.

- TLS comes from the distribution's libssl, linked dynamically (decision 029): the executable must need libssl and
  libcrypto, so the package depends on the distro's libssl through ${shlibs:Depends}.
- The module and every hook the nginx patches call must be in the binary. nginx links with -Wl,-E, so they are in
  the dynamic symbol table; a missing one means the module or a patch did not make it into the build.
"""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .util import BuildError, log, run

REQUIRED_NEEDED = (re.compile(r"^libssl\.so\."), re.compile(r"^libcrypto\.so\."))

REQUIRED_SYMBOLS = frozenset({
    "ngx_http_clientfp_module", "clientfp_tlsfp_compute",
    "ngx_http_clientfp_tls_hello", "ngx_http_clientfp_quic_crypto",
    "ngx_http_clientfp_h2_settings_frame", "ngx_http_clientfp_h2_setting", "ngx_http_clientfp_h2_window_update",
    "ngx_http_clientfp_h2_priority", "ngx_http_clientfp_h2_stream", "ngx_http_clientfp_h2_pseudo_header",
    "ngx_http_clientfp_h2_headers_done",
})


@dataclass
class Report:
    deb: Path
    needed: list[str] = field(default_factory=list)
    dynamic_symbols: int = 0
    nginx_v: str = ""
    missing_needed: list[str] = field(default_factory=list)
    missing_hooks: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.missing_needed and not self.missing_hooks


def defined_globals(path: Path, *, dynamic: bool) -> set[str]:
    """Global (incl. weak) defined symbol names; versioned names are stripped of '@...'."""
    args = ["nm", "--defined-only", "--format=posix"]
    if dynamic:
        args.append("-D")
    out = run([*args, path], capture=True).stdout
    names: set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0].endswith(":"):
            continue
        kind = parts[1]
        if (kind.isupper() and kind != "U") or kind in ("u", "i", "v", "w"):
            names.add(parts[0].split("@", 1)[0])
    return names


def needed_libs(binary: Path) -> list[str]:
    out = run(["readelf", "-d", binary], capture=True).stdout
    return re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", out)


def check(deb: Path) -> Report:
    """Unpack deb and check /usr/sbin/nginx."""
    report = Report(deb)
    with tempfile.TemporaryDirectory(prefix="clientfp-verify-") as tmp:
        root = Path(tmp)
        run(["dpkg-deb", "-x", deb, root])
        binary = root / "usr/sbin/nginx"
        if not binary.is_file():
            raise BuildError(f"{deb} has no usr/sbin/nginx")

        report.needed = needed_libs(binary)
        report.missing_needed = [p.pattern for p in REQUIRED_NEEDED if not any(p.match(n) for n in report.needed)]
        exported = defined_globals(binary, dynamic=True)
        report.dynamic_symbols = len(exported)
        report.missing_hooks = sorted(REQUIRED_SYMBOLS - exported)
        report.nginx_v = run([binary, "-V"], capture=True, check=False).stdout or ""

    log(f"{deb.name}: NEEDED={report.needed}, {report.dynamic_symbols} exported symbols")
    if report.missing_needed:
        log("libraries not linked: " + ", ".join(report.missing_needed))
    if report.missing_hooks:
        log("module/patch symbols missing from the binary: " + ", ".join(report.missing_hooks))
    return report


def lintian(deb: Path) -> int:
    """Run lintian; returns its exit code (errors are reported, the caller decides)."""
    proc = run(["lintian", "--tag-display-limit", "0", "--suppress-tags-from-file",
                Path(__file__).resolve().parent / "lintian-suppress", deb], check=False)
    return proc.returncode
