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

# Appended to nginx's "./config --prefix=... no-shared no-threads" (auto/lib/openssl/make).
# OPENSSLDIR: decision 007. no-module: providers are built into libcrypto, nothing is dlopen()ed from a
# build-tree path. enable-ktls matches the distro OpenSSL builds.
OPENSSL_OPT = [
    "--openssldir=/etc/nginx/openssl",
    "no-module",
    "no-docs",
    "no-tests",
    "no-apps",
    "enable-ktls",
]


def substitutions(v: Versions) -> dict[str, str]:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    return {
        "@DEB_VERSION@": v.deb_version,
        "@NGINX_VERSION@": v.nginx,
        "@OPENSSL_VERSION@": v.openssl,
        "@DATE@": email.utils.formatdate(epoch, localtime=False),
        "@CONFIGURE_ARGS@": " \\\n\t\t".join(CONFIGURE_ARGS),
        "@OPENSSL_OPT@": " ".join(OPENSSL_OPT),
    }


def render(dest: Path, v: Versions) -> None:
    shutil.copytree(TEMPLATES, dest, ignore=shutil.ignore_patterns("__pycache__"))
    subs = substitutions(v)
    for tpl in sorted(dest.rglob("*.in")):
        text = tpl.read_text()
        for key, value in subs.items():
            text = text.replace(key, value)
        out = tpl.with_suffix("")
        out.write_text(text)
        tpl.unlink()
    (dest / "rules").chmod(0o755)

    files = dest / "extra"
    readme = DOC / "clientfp_module.md"
    if readme.exists():
        shutil.copy(readme, files / "README.clientfp.md")
    else:
        (files / "README.clientfp.md").write_text("See https://nginx.org and the project README.\n")
    ex = files / "examples"
    ex.mkdir(exist_ok=True)
    if EXAMPLES.is_dir():
        for f in sorted(EXAMPLES.iterdir()):
            if f.is_file() and f.suffix in (".conf", ".py", ".md"):
                shutil.copy(f, ex / f.name)
    if not any(ex.iterdir()):
        (ex / "README").write_text("No examples bundled.\n")
