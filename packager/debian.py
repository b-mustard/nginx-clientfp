"""Render packager/debian/ into a build tree's debian/ directory (decision 010)."""

from __future__ import annotations

import email.utils
import os
import shutil
import time
from pathlib import Path

from .model import Versions

TEMPLATES = Path(__file__).resolve().parent / "debian"
DOC = Path(__file__).resolve().parent.parent / "doc"
EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
EXAMPLE_FILES = ("echo_server.py", "nginx-echo.conf")

# Debian/Ubuntu paths (decision 002) and the module set of decision 008.
CONFIGURE_ARGS = [
    "--prefix=/usr/share/nginx",
    "--sbin-path=/usr/sbin/nginx",
    "--conf-path=/etc/nginx/nginx.conf",
    "--http-log-path=/var/log/nginx/access.log",
    "--error-log-path=/var/log/nginx/error.log",
    "--lock-path=/var/lock/nginx.lock",
    "--pid-path=/run/nginx.pid",
    "--modules-path=/usr/lib/nginx/modules",
    "--http-client-body-temp-path=/var/lib/nginx/body",
    "--http-fastcgi-temp-path=/var/lib/nginx/fastcgi",
    "--http-proxy-temp-path=/var/lib/nginx/proxy",
    "--http-scgi-temp-path=/var/lib/nginx/scgi",
    "--http-uwsgi-temp-path=/var/lib/nginx/uwsgi",
    "--user=www-data",
    "--group=www-data",
    "--with-compat",
    "--with-debug",
    "--with-pcre-jit",
    "--with-threads",
    "--with-http_ssl_module",
    "--with-http_v2_module",
    "--with-http_v3_module",
    "--with-http_realip_module",
    "--with-http_stub_status_module",
    "--with-http_auth_request_module",
    "--with-http_dav_module",
    "--with-http_slice_module",
    "--with-http_addition_module",
    "--with-http_flv_module",
    "--with-http_gunzip_module",
    "--with-http_gzip_static_module",
    "--with-http_mp4_module",
    "--with-http_random_index_module",
    "--with-http_secure_link_module",
    "--with-http_sub_module",
    "--with-mail",
    "--with-mail_ssl_module",
    "--with-stream",
    "--with-stream_ssl_module",
    "--with-stream_ssl_preread_module",
    "--with-stream_realip_module",
]

def substitutions(v: Versions, distribution: str) -> dict[str, str]:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    return {
        "@DEB_VERSION@": v.deb_version,
        "@DISTRIBUTION@": distribution,
        "@NGINX_VERSION@": v.nginx,
        "@DATE@": email.utils.formatdate(epoch, localtime=False),
        "@CONFIGURE_ARGS@": " \\\n\t\t".join(CONFIGURE_ARGS),
    }


def render(dest: Path, v: Versions, distribution: str) -> None:
    """debian/ from the templates; `distribution` is the changelog's distribution field (decision 041)."""
    shutil.copytree(TEMPLATES, dest, ignore=shutil.ignore_patterns("__pycache__"))
    subs = substitutions(v, distribution)
    for tpl in sorted(dest.rglob("*.in")):
        text = tpl.read_text()
        for key, value in subs.items():
            text = text.replace(key, value)
        out = tpl.with_suffix("")
        out.write_text(text)
        tpl.unlink()
    (dest / "rules").chmod(0o755)

    files = dest / "extra"
    shutil.copy(DOC / "clientfp_module.md", files / "README.clientfp.md")
    ex = files / "examples"
    ex.mkdir(exist_ok=True)
    for name in EXAMPLE_FILES:            # gs8: a missing example is a build error, not an empty directory
        shutil.copy(EXAMPLES / name, ex / name)
