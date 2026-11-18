"""How the TLS ClientHello capture waits for the rest of a hello (decisions 030, 037, 038). Each case runs in an
nginx of its own with the settings under test.

- A level-triggered event method (`use poll`, `use select`) gives no new event while the peeked bytes stay queued,
  so the module does not wait there. A hello that has arrived whole is fingerprinted, one still arriving is not,
  and the worker never spins. The package is built with epoll only, so these run against the ASan and valgrind
  builds alone, which have the poll and select modules for them (decision 039).
- A connection waiting for the rest of its hello is not reusable (decision 038). When the worker runs short of
  connections, nginx closes idle connections to make room, but not that one.
- New bytes do not restart `client_header_timeout`, so a hello sent a byte at a time is closed when it expires.

As in test_hostile, the other tests run against the package, the ASan build and the valgrind build under memcheck.
Afterwards the server must still answer and must have no crashed worker, sanitizer report or memcheck error.
"""

from __future__ import annotations

import select
import socket
import time
from collections.abc import Iterator

import pytest

from .conftest import SERVER_KINDS, Nginx, assert_healthy, custom_nginx, mark_logs, nginx_conf
from .tlsclient import BioClient

pytestmark = [pytest.mark.nginx, pytest.mark.docker]

HEADER_TIMEOUT = 10   # client_header_timeout of the small server, in seconds


def _checked(n: Nginx) -> Iterator[Nginx]:
    mark = mark_logs(n)
    yield n
    assert_healthy(n, mark)


def worker_cpu(n: Nginx) -> float:
    """CPU seconds used so far by the server's only worker process: the master's child with the master's process
    name (not the echo upstream, which the master inherits when it is PID 1). The process title cannot be used:
    under valgrind, /proc/<pid>/cmdline shows valgrind's command line."""
    out = n.exec("sh", "-c", "m=$(cat /tmp/nginx.pid); c=$(cat /proc/$m/stat); c=${c#*(}; c=${c%%)*}; "
                 "getconf CLK_TCK; for p in /proc/[0-9]*; do s=$(cat $p/stat 2>/dev/null) || continue; "
                 "n=${s#*(}; n=${n%%)*}; set -- ${s##*) }; "
                 "[ \"$2\" = \"$m\" ] && [ \"$n\" = \"$c\" ] && echo \"$s\"; done; true")
    tick, *rest = out.splitlines()
    stats = [s for s in rest if s.strip()]
    assert len(stats) == 1, out
    fields = stats[0].rsplit(")", 1)[1].split()   # from field 3 (state); utime and stime are fields 14 and 15
    return (int(fields[11]) + int(fields[12])) / int(tick)


# ------------------------------------------------------------------------------- level-triggered event methods

@pytest.fixture(scope="module", params=[(k, m) for k in ("asan", "valgrind") for m in ("poll", "select")],
                ids=lambda p: f"{p[0]}-{p[1]}")
def level_server(request: pytest.FixtureRequest) -> Iterator[Nginx]:
    kind, method = request.param
    conf = nginx_conf(events=f"use {method}; worker_connections 512;", workers=1)
    with custom_nginx(request, kind, conf) as n:
        yield n


@pytest.fixture
def level(level_server: Nginx) -> Iterator[Nginx]:
    yield from _checked(level_server)


def test_level_triggered_whole_hello(level: Nginx) -> None:
    """A hello that has arrived whole when nginx first looks at the connection is fingerprinted."""
    with BioClient() as c:
        c.connect(level.tls)
        c.send(c.flight)
        assert c.fetch_fp()["ja4"] == c.ja4


def test_level_triggered_hello_in_pieces(level: Nginx) -> None:
    """A hello still arriving gets no fingerprint (logged), and the handshake goes on as without the module."""
    mark = mark_logs(level)
    with BioClient() as c:
        c.connect(level.tls)
        c.send(c.flight, segment=100, delay=0.3)
        assert c.fetch_fp()["ja4"] == ""
    assert "no JA4/TLSFP for this connection: incomplete ClientHello" in level.log_since(mark)


def test_level_triggered_stalled_hello_does_not_spin(level: Nginx) -> None:
    """A hello that stops half-way: the worker sleeps until more data comes. A module that waited here would be
    handed the same readable event again and again."""
    with BioClient() as c:
        c.connect(level.tls)
        c.send(c.flight[:100])
        time.sleep(0.5)
        before = worker_cpu(level)
        time.sleep(2)
        used = worker_cpu(level) - before
    assert used < 0.5, f"the worker used {used:.2f} s of CPU in 2 s"


# ----------------------------------------------------------- a worker short of connections, client_header_timeout

@pytest.fixture(scope="module", params=SERVER_KINDS)
def small_server(request: pytest.FixtureRequest) -> Iterator[Nginx]:
    conf = nginx_conf(events="worker_connections 32;", workers=1, http=f"client_header_timeout {HEADER_TIMEOUT}s;")
    with custom_nginx(request, request.param, conf) as n:
        yield n


@pytest.fixture
def small(small_server: Nginx) -> Iterator[Nginx]:
    yield from _checked(small_server)


def test_waiting_hello_kept_when_connections_run_short(small: Nginx) -> None:
    """decision 038: a connection whose hello has partly arrived is not reusable, as during the handshake. When the
    worker runs short of connections, nginx closes the oldest idle connections (nothing sent yet) to make room. The
    waiting connections are older still, but they are left alone and complete their handshakes."""
    mark = mark_logs(small)
    waiting = [BioClient() for _ in range(4)]
    idle: list[socket.socket] = []
    try:
        for c in waiting:
            c.connect(small.tls)
            c.send(c.flight[:100])
        time.sleep(1)
        for _ in range(60):
            idle.append(socket.create_connection(("127.0.0.1", small.tls), timeout=10))
            time.sleep(0.02)
        time.sleep(0.5)
        assert "worker_connections are not enough, reusing connections" in small.log_since(mark), \
            "the worker never ran short of connections"
        for c in waiting:
            c.send(c.flight[100:])
            assert c.fetch_fp()["ja4"] == c.ja4
    finally:
        for s in idle:
            s.close()
        for c in waiting:
            c.close()


def test_hello_sent_byte_by_byte_closed_at_client_header_timeout(small: Nginx) -> None:
    """New bytes do not restart client_header_timeout. A hello sent a byte every half second is closed when the
    timer, started when the connection was accepted, expires, as a stalled handshake would be."""
    mark = mark_logs(small)
    with BioClient() as c:
        s = c.connect(small.tls)
        t0 = time.monotonic()
        for byte in c.flight:
            readable, _, _ = select.select([s], [], [], 0.5)
            if readable or time.monotonic() - t0 > HEADER_TIMEOUT + 10:
                break
            try:
                s.sendall(bytes([byte]))
            except OSError:
                break
        elapsed = time.monotonic() - t0
        try:
            tail = s.recv(100)
        except OSError:
            tail = b""
    assert tail == b"", tail
    assert HEADER_TIMEOUT - 1 <= elapsed <= HEADER_TIMEOUT + 4, f"closed after {elapsed:.1f} s"
    assert "client timed out" in small.log_since(mark)
