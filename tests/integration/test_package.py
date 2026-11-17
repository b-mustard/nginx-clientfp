"""The installed package (gs6, gs10): files, configuration, the distro's TLS library, module present."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from .conftest import Nginx

pytestmark = [pytest.mark.nginx, pytest.mark.docker]


def test_files_installed(nginx_pkg: Nginx) -> None:
    out = nginx_pkg.exec("sh", "-c", "ls -d "
                         "/usr/sbin/nginx /etc/nginx/nginx.conf /etc/nginx/mime.types "
                         "/etc/nginx/fastcgi_params /etc/nginx/proxy_params /etc/nginx/sites-available/default "
                         "/etc/nginx/snippets/snakeoil.conf /etc/nginx/snippets/fastcgi-php.conf "
                         "/etc/nginx/modules-enabled /etc/nginx/conf.d "
                         "/etc/logrotate.d/nginx /etc/init.d/nginx /etc/default/nginx /etc/ufw/applications.d/nginx "
                         "/usr/share/nginx/html/index.html /var/www/html/index.nginx-debian.html "
                         "/usr/share/doc/nginx-clientfp/copyright /usr/share/vim/addons/syntax/nginx.vim")
    assert "No such file" not in out
    unit = nginx_pkg.exec("sh", "-c", "cat /usr/lib/systemd/system/nginx.service /lib/systemd/system/nginx.service "
                          "2>/dev/null", check=False)
    assert "ExecStart=/usr/sbin/nginx" in unit


def test_deb_contents(deb: Path) -> None:
    """Checked in the .deb itself: minimized docker images drop /usr/share/man at install time."""
    listing = subprocess.run(["dpkg-deb", "-c", str(deb)], capture_output=True, text=True, check=True).stdout
    for f in ("./usr/share/man/man8/nginx.8.gz", "./usr/share/doc/nginx-clientfp/README.clientfp.md",
              "./usr/share/doc/nginx-clientfp/examples/echo_server.py",
              "./usr/share/doc/nginx-clientfp/examples/nginx-echo.conf"):
        assert f in listing, f


def test_conffiles(nginx_pkg: Nginx) -> None:
    conffiles = nginx_pkg.exec("sh", "-c", "cat /var/lib/dpkg/info/nginx-clientfp.conffiles")
    for f in ("/etc/nginx/nginx.conf", "/etc/nginx/sites-available/default", "/etc/logrotate.d/nginx"):
        assert f in conffiles


def test_dependencies(nginx_pkg: Nginx) -> None:
    """The distro's libssl (decision 029), PCRE2 and zlib, all through ${shlibs:Depends}."""
    depends = nginx_pkg.exec("dpkg-query", "-W", "-f", "${Depends}", "nginx-clientfp")
    assert "libssl" in depends
    assert "libpcre2-8-0" in depends and "zlib1g" in depends


def test_tls_library_dynamic(nginx_pkg: Nginx) -> None:
    """decision 029: libssl and libcrypto are the distro's shared libraries."""
    ldd = nginx_pkg.exec("ldd", "/usr/sbin/nginx")
    assert "not found" not in ldd
    assert re.search(r"^\s*libssl\.so\.\S+ => /", ldd, re.M), ldd
    assert re.search(r"^\s*libcrypto\.so\.\S+ => /", ldd, re.M), ldd


def test_nginx_v(nginx_pkg: Nginx, flavor: str) -> None:
    v = nginx_pkg.exec("nginx", "-V")
    assert re.search(rf"nginx version: nginx/{re.escape(flavor)}\.\d+", v)
    assert re.search(r"built with \S+ \d+\.\d+", v)
    assert "running with" not in v                       # built against the library the target distro ships
    for arg in ("--with-http_v3_module", "--with-http_v2_module", "--conf-path=/etc/nginx/nginx.conf",
                "--add-module=", "/clientfp", "--with-stream", "--with-mail"):
        assert arg in v


def test_packaged_config_valid(nginx_pkg: Nginx) -> None:
    out = nginx_pkg.exec("nginx", "-t")
    assert "syntax is ok" in out and "test is successful" in out
    conf = nginx_pkg.exec("cat", "/etc/nginx/nginx.conf")
    assert "clientfp_request_header X-Client-JA4 $clientfp_ja4;" in conf
    assert "clientfp_request_header X-Client-TLSFP $clientfp_tlsfp;" in conf
