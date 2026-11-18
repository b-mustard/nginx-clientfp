"""A running nginx-clientfp for integration tests.

`nginx_pkg`: the built .deb from dist/<target>/ installed with dpkg into a clean <target> container (proving its
dependencies are met by a minimal system), the packaged /etc/nginx/nginx.conf, plus tests/integration/
clientfp-test.conf and the examples/ echo upstream on 127.0.0.1:8081.

`nginx_asan`: the ASan/UBSan nginx from `./build.sh asan` (build/asan/<flavor>/), same site, in the build image.

`custom_nginx()`: either of them with an nginx.conf of the test's own (`nginx_conf()`), in a container of its own.

Ports are published on 127.0.0.1 with the same host port for TCP and UDP (QUIC).
"""

from __future__ import annotations

import datetime
import json
import re
import socket
import ssl
import subprocess
import time
import uuid
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ..conftest import REPO

HERE = Path(__file__).resolve().parent
TARGET_IMAGES = {
    "ubuntu-24.04": "ubuntu:24.04",
    "ubuntu-26.04": "ubuntu:26.04",
    "debian-12": "debian:12",
    "debian-13": "debian:13",
}


@dataclass
class Nginx:
    container: str
    tls: int          # 8443: TLS (h1 + h2) and QUIC (h3), same host port number
    h2c: int          # 8080: cleartext h1 + h2 prior knowledge
    tls_alt: int      # 8444: server with its own clientfp_request_header list
    workdir: Path
    logs: str         # error log files inside the container (shell words)

    def exec(self, *cmd: str, check: bool = True) -> str:
        proc = subprocess.run(["docker", "exec", self.container, *cmd], capture_output=True, text=True,
                              errors="replace", check=False)   # logs quote raw client bytes
        if check and proc.returncode != 0:
            raise AssertionError(f"{cmd} failed: {proc.stderr}")
        return proc.stdout + proc.stderr

    def error_log(self) -> str:
        return self.exec("sh", "-c", f"cat {self.logs} 2>/dev/null", check=False)

    def log_mark(self) -> list[int]:
        """The current size of each error log file, for log_since()."""
        sizes = self.exec("sh", "-c", " ".join(f"cat {f} 2>/dev/null | wc -c;" for f in self.logs.split()))
        return [int(s) for s in sizes.split()]

    def log_since(self, mark: list[int] | None = None) -> str:
        """What each error log file gained after `mark` (all of it without one)."""
        files = self.logs.split()
        offsets = mark or [0] * len(files)
        return self.exec("sh", "-c", "; ".join(f"tail -c +{m + 1} {f} 2>/dev/null" for f, m in zip(files, offsets)),
                         check=False)

    def alive(self) -> bool:
        try:
            get(self.tls, "/fp")
            return True
        except OSError:
            return False


def get(port: int, path: str, headers: dict[str, str] | None = None, host: str = "localhost") -> str:
    """HTTP/1.1 GET over TLS (no ALPN h2) with raw headers, so duplicate/odd headers are sent as written."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
            for k, v in (headers or {}).items():
                req += f"{k}: {v}\r\n"
            s.sendall((req + "\r\n").encode())
            data = b""
            while chunk := s.recv(65536):
                data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    if b" 200 " not in head.split(b"\r\n", 1)[0]:
        raise AssertionError(head.decode(errors="replace"))
    return body.decode()


def _free_port() -> int:
    for _ in range(50):
        with socket.socket() as t, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            t.bind(("127.0.0.1", 0))
            port = int(t.getsockname()[1])
            try:
                u.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free port")


def _cert(dest: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    (dest / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (dest / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                     serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))


def _wait_ready(n: Nginx, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if n.alive():
            return
        time.sleep(0.5)
    logs = subprocess.run(["docker", "logs", n.container], capture_output=True, text=True, check=False)
    raise AssertionError(f"nginx did not come up:\n{logs.stdout[-3000:]}\n{logs.stderr[-3000:]}")


def _start(image: str, mounts: list[str], script: str, tmp: Path, logs: str) -> Generator[Nginx, None, None]:
    name = f"clientfp-test-{uuid.uuid4().hex[:8]}"
    tls, h2c, alt = _free_port(), _free_port(), _free_port()
    cmd = ["docker", "run", "-d", "--name", name,
           "-p", f"127.0.0.1:{tls}:8443/tcp", "-p", f"127.0.0.1:{tls}:8443/udp",
           "-p", f"127.0.0.1:{h2c}:8080/tcp", "-p", f"127.0.0.1:{alt}:8444/tcp",
           "-v", f"{tmp}:/etc/nginx/test:ro", "-v", f"{REPO / 'examples'}:/examples:ro",
           *mounts, image, "sh", "-c", script]
    subprocess.run(cmd, check=True, capture_output=True)
    n = Nginx(name, tls, h2c, alt, tmp, logs)
    try:
        _wait_ready(n)
        yield n
    finally:
        log = n.error_log()
        (REPO / "build" / "test-logs").mkdir(parents=True, exist_ok=True)
        (REPO / "build" / "test-logs" / f"{name}.log").write_text(log)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


def _deb(target: str, flavor: str) -> Path:
    name = re.compile(rf"nginx-clientfp_{re.escape(flavor)}\.\d+-[0-9][0-9A-Za-z.+~]*_amd64\.deb")   # decision 031
    debs = sorted(p for p in (REPO / "dist" / target).glob(f"nginx-clientfp_{flavor}.*_amd64.deb")
                  if name.fullmatch(p.name))
    if not debs:
        pytest.skip(f"no package for flavor {flavor} in dist/{target}/ (run ./build.sh build --target {target})")
    return debs[-1]


@pytest.fixture(scope="session")
def target(request: pytest.FixtureRequest) -> str:
    return str(request.config.getoption("--target"))


@pytest.fixture(scope="session")
def flavor(request: pytest.FixtureRequest) -> str:
    return str(request.config.getoption("--flavor"))


@pytest.fixture(scope="session")
def deb(target: str, flavor: str) -> Path:
    return _deb(target, flavor)


@pytest.fixture(scope="session")
def runtime_image(require_docker: None, target: str) -> str:
    image = f"nginx-clientfp-runtime:{target}"
    subprocess.run(["docker", "build", "-q", "--build-arg", f"BASE={TARGET_IMAGES[target]}", "-t", image,
                    "-f", str(REPO / "tests" / "docker" / "Dockerfile.runtime"), str(REPO / "tests" / "docker")],
                   check=True, capture_output=True)
    return image


INSTALL_DEB = "set -e; dpkg -i /pkg/nginx-clientfp.deb > /tmp/dpkg.log 2>&1 || { cat /tmp/dpkg.log; exit 1; }; "
ECHO_UPSTREAM = "python3 /examples/echo_server.py --port 8081 > /tmp/echo.log 2>&1 & "


@pytest.fixture(scope="session")
def nginx_pkg(runtime_image: str, deb: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Nginx]:
    tmp = tmp_path_factory.mktemp("nginx-pkg")
    _cert(tmp)
    (tmp / "clientfp-test.conf").write_text((HERE / "clientfp-test.conf").read_text())
    script = (
        INSTALL_DEB + "rm -f /etc/nginx/sites-enabled/default; "
        "cp /etc/nginx/test/clientfp-test.conf /etc/nginx/sites-enabled/; "
        + ECHO_UPSTREAM + "exec nginx -g 'daemon off;' 2> /tmp/nginx.stderr"
    )
    yield from _start(runtime_image, ["-v", f"{deb}:/pkg/nginx-clientfp.deb:ro"], script, tmp,
                      "/var/log/nginx/error.log /tmp/nginx.stderr")


def nginx_conf(events: str = "worker_connections 512;", workers: int = 2, http: str = "") -> str:
    """A complete nginx.conf around the test site, with the request headers of the packaged nginx.conf; `events`
    and `http` are added to those blocks."""
    site = (HERE / "clientfp-test.conf").read_text()
    return f"""
daemon off;
master_process on;
worker_processes {workers};
error_log /tmp/error.log info;
pid /tmp/nginx.pid;
events {{ {events} }}
http {{
    access_log off;
    client_body_temp_path /tmp/body; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi;
    uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi;
    clientfp_request_header X-Client-JA4 $clientfp_ja4;
    clientfp_request_header X-Client-TLSFP $clientfp_tlsfp;
    clientfp_request_header X-Client-HTTP2-FP $clientfp_http2;
    {http}
{site}
}}
"""


@contextmanager
def custom_nginx(request: pytest.FixtureRequest, kind: str, conf: str) -> Iterator[Nginx]:
    """The installed package (`kind` "pkg") or the ASan build ("asan") running `conf`, in a container of its own.
    The ASan build's sanitizer reports are kept in build/test-logs/."""
    tmp = request.getfixturevalue("tmp_path_factory").mktemp(f"nginx-{kind}")
    _cert(tmp)
    (tmp / "nginx.conf").write_text(conf)
    if kind == "pkg":
        image = str(request.getfixturevalue("runtime_image"))
        mounts = ["-v", f"{request.getfixturevalue('deb')}:/pkg/nginx-clientfp.deb:ro"]
        script = INSTALL_DEB + ECHO_UPSTREAM + "exec nginx -c /etc/nginx/test/nginx.conf 2> /tmp/nginx.stderr"
    else:
        request.getfixturevalue("require_docker")
        flavor = str(request.getfixturevalue("flavor"))
        prefix = REPO / "build" / "asan" / flavor
        if not (prefix / "sbin" / "nginx").exists():
            pytest.skip(f"no ASan build in {prefix} (run ./build.sh asan --flavor {flavor})")
        image = "nginx-clientfp-build:ubuntu-24.04"
        mounts = ["-v", f"{REPO}:/work:ro"]
        script = (
            ECHO_UPSTREAM + "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=/tmp/asan "
            "UBSAN_OPTIONS=print_stacktrace=1:log_path=/tmp/ubsan "
            f"exec /work/build/asan/{flavor}/sbin/nginx -p /tmp/ -c /etc/nginx/test/nginx.conf 2> /tmp/nginx.stderr"
        )
    container = _start(image, mounts, script, tmp, "/tmp/error.log /tmp/nginx.stderr")
    n = next(container)
    try:
        yield n
    finally:
        if kind == "asan":
            report = n.exec("sh", "-c", "cat /tmp/asan* /tmp/ubsan* /tmp/error.log 2>/dev/null", check=False)
            (REPO / "build" / "test-logs").mkdir(parents=True, exist_ok=True)
            (REPO / "build" / "test-logs" / f"{n.container}-asan.log").write_text(report)
        container.close()   # saves the error log and removes the container


@pytest.fixture(scope="session")
def nginx_asan(request: pytest.FixtureRequest) -> Iterator[Nginx]:
    with custom_nginx(request, "asan", nginx_conf()) as n:
        yield n


def fp_json(port: int) -> dict[str, str]:
    data: dict[str, str] = json.loads(get(port, "/fp"))
    return data
