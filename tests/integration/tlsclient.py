# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""A real TLS client (Python's ssl over memory BIOs), so a test decides how its first flight reaches the server: the
bytes, their record framing, and their TCP segmentation and timing."""

from __future__ import annotations

import json
import socket
import ssl
import time
from types import TracebackType

from clientfp.fp import ja4 as ref_ja4


class BioClient:
    def __init__(self) -> None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        self._inc, self._out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self._tls = ctx.wrap_bio(self._inc, self._out, server_hostname="localhost")
        try:
            self._tls.do_handshake()
        except ssl.SSLWantReadError:
            pass
        self.flight = self._out.read()   # the first flight as the TLS library framed it
        msg = ref_ja4.client_hello_from_records(self.flight)
        assert msg is not None
        self.hello = msg                 # the ClientHello handshake message
        self.sock: socket.socket | None = None

    @property
    def ja4(self) -> str:
        """The hello's JA4, computed locally."""
        return ref_ja4.from_bytes(self.hello, "t").ja4

    def connect(self, port: int) -> socket.socket:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return self.sock

    def send(self, data: bytes, segment: int = 1 << 20, delay: float = 0.0) -> None:
        """Raw bytes, in TCP segments of `segment` bytes sent `delay` seconds apart."""
        assert self.sock is not None
        for i in range(0, len(data), segment):
            self.sock.sendall(data[i:i + segment])
            time.sleep(delay)

    def _pump(self) -> None:
        assert self.sock is not None
        if self._out.pending:
            self.sock.sendall(self._out.read())
        data = self.sock.recv(65536)
        if not data:
            raise ConnectionError("server closed the connection")
        self._inc.write(data)

    def fetch_fp(self) -> dict[str, str]:
        """Complete the handshake (the first flight must have been sent), GET /fp, and return its fields."""
        while True:
            try:
                self._tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                self._pump()
        self._tls.write(b"GET /fp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        resp = b""
        while not resp.endswith(b"}\n"):
            try:
                resp += self._tls.read(65536)
            except ssl.SSLWantReadError:
                self._pump()
        fields: dict[str, str] = json.loads(resp.split(b"\r\n\r\n", 1)[1])
        return fields

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def __enter__(self) -> BioClient:
        return self

    def __exit__(self, typ: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()
