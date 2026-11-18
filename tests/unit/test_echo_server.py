# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""examples/echo_server.py: malformed requests get 400 without an exception in the server, the log shows binary data
as escapes, and the server's address agrees with examples/nginx-echo.conf."""

from __future__ import annotations

import re
import socket
import sys
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

import examples.echo_server as echo
from examples.echo_server import EchoHandler

REPO = Path(__file__).resolve().parents[2]


class RecordingServer(ThreadingHTTPServer):
    """Keeps the exceptions that socketserver would print, so a test can assert there were none."""

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), EchoHandler)
        self.errors: list[BaseException] = []

    def handle_error(self, request: Any, client_address: Any) -> None:
        exc = sys.exc_info()[1]
        if exc is not None:
            self.errors.append(exc)


@pytest.fixture
def server() -> Iterator[RecordingServer]:
    srv = RecordingServer()
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    thread.join()


def exchange(srv: RecordingServer, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", srv.server_port), timeout=5) as s:
        s.sendall(request)
        s.shutdown(socket.SHUT_WR)
        reply = b""
        while chunk := s.recv(4096):
            reply += chunk
    return reply


@pytest.mark.parametrize("request_bytes", [
    b"GET / HTTP/1.1x\r\n\r\n",                                          # bad version: logged before headers exist
    b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03" + bytes(32) + b"\r\n\r\n",   # a TLS ClientHello on the HTTP port
    b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n",
    b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n",
], ids=["bad-version", "tls-hello", "content-length-text", "content-length-negative"])
def test_malformed_request_gets_400(server: RecordingServer, request_bytes: bytes,
                                    capsys: pytest.CaptureFixture[str]) -> None:
    reply = exchange(server, request_bytes)
    # the error page, with or without a status line: http.server answers a request whose HTTP version it cannot
    # read in HTTP/0.9 style, without one
    assert b"Error code: 400" in reply, reply[:200]
    assert server.errors == []
    assert "code 400" in capsys.readouterr().out


def test_request_is_echoed(server: RecordingServer) -> None:
    reply = exchange(server, b"GET /x HTTP/1.1\r\nHost: x\r\nX-Client-JA4: t13d0000h2_a_b\r\n\r\n")
    assert reply.startswith(b"HTTP/1.0 200")
    assert b'"X-Client-JA4": "t13d0000h2_a_b"' in reply
    assert server.errors == []


@pytest.mark.parametrize("request_bytes", [
    b"GET /\x1b[2J\x1b[31mred HTTP/1.1\r\nHost: x\r\n\r\n",          # terminal escape sequences in the path
    b"GET / HTTP/\xba\x13\x07\r\n\r\n",                           # binary in the version
], ids=["escape-sequence", "binary-version"])
def test_log_shows_binary_as_escapes(server: RecordingServer, request_bytes: bytes,
                                     capsys: pytest.CaptureFixture[str]) -> None:
    exchange(server, request_bytes)
    out = capsys.readouterr().out
    assert out
    bad = sorted({c for c in out if not (" " <= c <= "~" or c == "\n")})
    assert not bad, f"unescaped characters in the log: {bad!r}"
    assert "\\x1b" in out or "\\xba" in out


def test_address_agrees_with_nginx_conf() -> None:
    """The server takes no options: its address is the proxy_pass target of the example site, and the address it
    prints is the port nginx listens on."""
    conf = (REPO / "examples" / "nginx-echo.conf").read_text()
    upstream = re.findall(r"proxy_pass http://([\d.]+):(\d+);", conf)
    assert upstream == [(echo.LISTEN[0], str(echo.LISTEN[1]))]
    assert set(re.findall(r"listen (\d+) ssl;", conf)) == {str(echo.NGINX_PORT)}


def test_banner_names_nginx_not_the_echo_server() -> None:
    text = echo.banner()
    assert f"https://localhost:{echo.NGINX_PORT}/" in text
    assert str(echo.LISTEN[1]) not in text
