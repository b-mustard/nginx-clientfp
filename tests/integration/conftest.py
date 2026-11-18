# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""A running nginx-clientfp for integration tests.

`nginx_pkg`: the built .deb from dist/<target>/ installed with dpkg into a clean <target> container (proving its
dependencies are met by a minimal system), the packaged /etc/nginx/nginx.conf, plus tests/integration/
clientfp-test.conf and the examples/ echo upstream on 127.0.0.1:8081.

`nginx_asan`: the ASan/UBSan nginx from `./build.sh asan` (build/asan/<flavor>/), same site, in the build image.

`nginx_valgrind`: the nginx from `./build.sh valgrind` (build/valgrind/<flavor>/) under valgrind's memcheck, same
site, in the build image. When the session ends it is stopped gracefully, so every process exits and memcheck reports
what it leaked; any memcheck output fails the session.

`srv`: each of the three in turn, checked after every test (still answering, no crashed worker, no sanitizer or
memcheck report).

`custom_nginx()`: any of them with an nginx.conf of the test's own (`nginx_conf()`), in a container of its own.

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

from packager.model import newest_deb

from ..conftest import REPO, VALGRIND

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
    patience: float = 0   # seconds alive() waits for a slow server (the valgrind build) to catch up

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

    def answers(self) -> bool:
        try:
            get(self.tls, "/fp")
            return True
        except OSError:
            return False

    def alive(self) -> bool:
        """Answers /fp, within `patience` seconds."""
        deadline = time.monotonic() + self.patience
        while not self.answers():
            if time.monotonic() >= deadline:
                return False
            time.sleep(1)
        return True


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
        if n.answers():
            return
        time.sleep(0.5)
    logs = subprocess.run(["docker", "logs", n.container], capture_output=True, text=True, check=False)
    raise AssertionError(f"nginx did not come up:\n{logs.stdout[-3000:]}\n{logs.stderr[-3000:]}")


def _start(image: str, mounts: list[str], script: str, tmp: Path, logs: str,
           patience: float = 0) -> Generator[Nginx, None, None]:
    name = f"clientfp-test-{uuid.uuid4().hex[:8]}"
    tls, h2c, alt = _free_port(), _free_port(), _free_port()
    cmd = ["docker", "run", "-d", "--name", name,
           "-p", f"127.0.0.1:{tls}:8443/tcp", "-p", f"127.0.0.1:{tls}:8443/udp",
           "-p", f"127.0.0.1:{h2c}:8080/tcp", "-p", f"127.0.0.1:{alt}:8444/tcp",
           "-v", f"{tmp}:/etc/nginx/test:ro", "-v", f"{REPO / 'examples'}:/examples:ro",
           *mounts, image, "sh", "-c", script]
    subprocess.run(cmd, check=True, capture_output=True)
    n = Nginx(name, tls, h2c, alt, tmp, logs, patience)
    try:
        _wait_ready(n)
        yield n
    finally:
        log = n.error_log()
        (REPO / "build" / "test-logs").mkdir(parents=True, exist_ok=True)
        (REPO / "build" / "test-logs" / f"{name}.log").write_text(log)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


def _deb(target: str, flavor: str) -> Path:
    deb = newest_deb(REPO / "dist" / target, flavor)   # the highest version (decision 048)
    if deb is None:
        pytest.skip(f"no package for flavor {flavor} in dist/{target}/ (run ./build.sh build --target {target})")
    return deb


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
# --no-lookup: a test run sends no requests to the trace URL (decision 044)
ECHO_UPSTREAM = "python3 /examples/echo_server.py --no-lookup > /tmp/echo.log 2>&1 & "


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


SERVER_KINDS = ["pkg", "asan", "valgrind"]
TEST_BUILD_IMAGE = "nginx-clientfp-build:ubuntu-24.04"
MEMCHECK_LINE = re.compile(r"^==\d+== ", re.M)


def _test_build(request: pytest.FixtureRequest, kind: str) -> str:
    """The flavor of the ./build.sh <kind> nginx to run; skips the test when there is none."""
    request.getfixturevalue("require_docker")
    flavor = str(request.getfixturevalue("flavor"))
    prefix = REPO / "build" / kind / flavor
    if not (prefix / "sbin" / "nginx").exists():
        pytest.skip(f"no {kind} build in {prefix} (run ./build.sh {kind} --flavor {flavor})")
    return flavor


def _stop_under_memcheck(n: Nginx) -> str:
    """Stop nginx gracefully so that every process exits and memcheck reports its leaks; return what memcheck
    printed during the whole run, or why it could not be collected."""
    n.exec("sh", "-c", "kill -QUIT $(cat /tmp/nginx.pid)", check=False)
    deadline = time.monotonic() + 120
    while not n.exec("sh", "-c", "test -e /tmp/nginx.exited && echo exited", check=False).strip():
        if time.monotonic() > deadline:
            return "nginx did not exit within 120 s of SIGQUIT"
        time.sleep(1)
    out = n.exec("sh", "-c", "cat /tmp/nginx.stderr /tmp/error.log 2>/dev/null", check=False)
    (REPO / "build" / "test-logs").mkdir(parents=True, exist_ok=True)
    (REPO / "build" / "test-logs" / f"{n.container}-valgrind.log").write_text(out)
    return "\n".join(line for line in out.splitlines() if MEMCHECK_LINE.match(line))


@contextmanager
def custom_nginx(request: pytest.FixtureRequest, kind: str, conf: str) -> Iterator[Nginx]:
    """The installed package (`kind` "pkg"), the ASan build ("asan") or the valgrind build under memcheck
    ("valgrind") running `conf`, in a container of its own. The ASan build's sanitizer reports and the valgrind
    build's full log are kept in build/test-logs/. The valgrind build is stopped gracefully at the end, and any
    memcheck output, leaks included, fails the test or fixture that owns it."""
    tmp = request.getfixturevalue("tmp_path_factory").mktemp(f"nginx-{kind}")
    _cert(tmp)
    (tmp / "nginx.conf").write_text(conf)
    args = "-p /tmp/ -c /etc/nginx/test/nginx.conf 2> /tmp/nginx.stderr"
    if kind == "pkg":
        image = str(request.getfixturevalue("runtime_image"))
        mounts = ["-v", f"{request.getfixturevalue('deb')}:/pkg/nginx-clientfp.deb:ro"]
        script = INSTALL_DEB + ECHO_UPSTREAM + f"exec nginx {args}"
    elif kind == "asan":
        flavor = _test_build(request, kind)
        image, mounts = TEST_BUILD_IMAGE, ["-v", f"{REPO}:/work:ro"]
        script = (
            ECHO_UPSTREAM + "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=/tmp/asan "
            "UBSAN_OPTIONS=print_stacktrace=1:log_path=/tmp/ubsan "
            f"exec /work/build/asan/{flavor}/sbin/nginx {args}"
        )
    else:
        flavor = _test_build(request, kind)
        image, mounts = TEST_BUILD_IMAGE, ["-v", f"{REPO}:/work:ro"]
        # the shell stays, so that the logs can still be read once nginx has exited
        valgrind = " ".join(VALGRIND) + " --suppressions=/work/tests/valgrind/nginx.supp"
        script = (ECHO_UPSTREAM + f"{valgrind} /work/build/valgrind/{flavor}/sbin/nginx {args}; "
                  "touch /tmp/nginx.exited; exec sleep infinity")
    # under memcheck, a flood of handshakes takes the server a while to work through
    patience = 120 if kind == "valgrind" else 0
    container = _start(image, mounts, script, tmp, "/tmp/error.log /tmp/nginx.stderr", patience)
    n = next(container)
    memcheck = ""
    try:
        yield n
    finally:
        if kind == "asan":
            report = n.exec("sh", "-c", "cat /tmp/asan* /tmp/ubsan* /tmp/error.log 2>/dev/null", check=False)
            (REPO / "build" / "test-logs").mkdir(parents=True, exist_ok=True)
            (REPO / "build" / "test-logs" / f"{n.container}-asan.log").write_text(report)
        if kind == "valgrind":
            memcheck = _stop_under_memcheck(n)
        container.close()   # saves the error log and removes the container
    assert not memcheck, f"memcheck ({n.container}):\n{memcheck[-6000:]}"


@pytest.fixture(scope="session")
def nginx_asan(request: pytest.FixtureRequest) -> Iterator[Nginx]:
    with custom_nginx(request, "asan", nginx_conf()) as n:
        yield n


@pytest.fixture(scope="session")
def nginx_valgrind(request: pytest.FixtureRequest) -> Iterator[Nginx]:
    with custom_nginx(request, "valgrind", nginx_conf()) as n:
        yield n


def mark_logs(n: Nginx) -> list[int]:
    """Set earlier sanitizer reports aside and return the error logs' current sizes, so a test is judged only by what
    happens during it (a crashed worker is replaced by the master, later tests stay meaningful)."""
    n.exec("sh", "-c", "mkdir -p /tmp/seen; mv /tmp/asan.* /tmp/ubsan.* /tmp/seen/ 2>/dev/null; true", check=False)
    return n.log_mark()


def assert_healthy(n: Nginx, mark: list[int] | None = None) -> None:
    """Still answering; no crashed worker, sanitizer report or memcheck error since `mark`."""
    assert n.alive(), "nginx stopped answering"
    report = n.exec("sh", "-c", "cat /tmp/asan.* /tmp/ubsan.* 2>/dev/null", check=False)
    crash = re.compile(r"exited on signal|runtime error|AddressSanitizer")
    report += "".join(line + "\n" for line in n.log_since(mark).splitlines()
                      if crash.search(line) or MEMCHECK_LINE.match(line))
    assert report.strip() == "", report[-6000:]


@pytest.fixture(params=SERVER_KINDS)
def srv(request: pytest.FixtureRequest) -> Iterator[Nginx]:
    n: Nginx = request.getfixturevalue(f"nginx_{request.param}")
    mark = mark_logs(n)
    yield n
    assert_healthy(n, mark)


def fp_json(port: int) -> dict[str, str]:
    data: dict[str, str] = json.loads(get(port, "/fp"))
    return data
