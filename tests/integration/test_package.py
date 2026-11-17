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


def test_refuse_sslv2_hello_off(nginx_pkg: Nginx) -> None:
    """decision 036, `clientfp_refuse_sslv2_hello off`: a second nginx in the container hands an SSLv2-format hello
    to the TLS library, which answers it with a ServerHello at security level 0; the connection has no fingerprint."""
    (nginx_pkg.workdir / "sslv2-off.conf").write_text(
        "pid /tmp/sslv2-off.pid; error_log /tmp/sslv2-off.log info; events {}\n"
        "http { clientfp_refuse_sslv2_hello off; server { listen 127.0.0.1:9443 ssl;\n"
        "  ssl_certificate /etc/nginx/test/cert.pem; ssl_certificate_key /etc/nginx/test/key.pem;\n"
        "  ssl_protocols TLSv1.2; ssl_ciphers ALL:@SECLEVEL=0; } }\n")
    (nginx_pkg.workdir / "sslv2-client.py").write_text(
        "import socket, struct\n"
        "specs = bytes.fromhex('00002f000035')\n"
        "body = b'\\x01\\x03\\x03' + struct.pack('>HHH', len(specs), 0, 32) + specs + bytes(32)\n"
        "s = socket.create_connection(('127.0.0.1', 9443), timeout=5)\n"
        "s.sendall(struct.pack('>H', 0x8000 | len(body)) + body)\n"
        "print(s.recv(16).hex())\n")
    nginx_pkg.exec("nginx", "-c", "/etc/nginx/test/sslv2-off.conf")
    try:
        reply = nginx_pkg.exec("python3", "/etc/nginx/test/sslv2-client.py").strip()
        assert reply[:2] == "16" and reply[10:12] == "02", reply          # handshake record, ServerHello
        log = nginx_pkg.exec("cat", "/tmp/sslv2-off.log")
        assert "no JA4/TLSFP for this connection: SSLv2-format ClientHello" in log, log
    finally:
        nginx_pkg.exec("nginx", "-c", "/etc/nginx/test/sslv2-off.conf", "-s", "quit", check=False)


def test_packaged_config_valid(nginx_pkg: Nginx) -> None:
    out = nginx_pkg.exec("nginx", "-t")
    assert "syntax is ok" in out and "test is successful" in out
    conf = nginx_pkg.exec("cat", "/etc/nginx/nginx.conf")
    assert "clientfp_request_header X-Client-JA4 $clientfp_ja4;" in conf
    assert "clientfp_request_header X-Client-TLSFP $clientfp_tlsfp;" in conf
