"""Reference for the module's ClientHello capture (nginx_module/src/clientfp_hello.c, decisions 030 and 033).

The module reassembles the first handshake message of a connection itself, before the TLS library reads anything:

- TLS over TCP: from the bytes peeked at the start of the connection (`tls_capture`);
- QUIC: from the CRYPTO frames of Initial packets, in any order, overlapping or not (`QuicCapture`).

tests/test_c_core.py checks the C code against these functions, including the number of bytes the TCP capture says it
still needs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Literal

HELLO_MAX: Final = 16384
"""Largest handshake message captured, 4-byte header included (decision 033)."""
HELLO_RAW_MAX: Final = 32768
"""Largest number of raw TLS record bytes (headers included) the TCP capture waits for."""
RECORD_MAX: Final = 16384
"""RFC 8446 §5.1: plaintext record fragment limit."""

Status = Literal["done", "again", "nothello", "toobig", "sslv2"]
STATUS_CODE: Final[dict[str, int]] = {"done": 0, "again": 1, "nothello": 2, "toobig": 3, "sslv2": 4}


@dataclass(frozen=True)
class TlsResult:
    status: Status
    msg: bytes = b""      # the ClientHello message when status == "done"
    need: int = 0         # when status == "again": raw bytes required before another attempt can progress


def _message_header(h: bytes) -> Status | int:
    """Message size from a 4-byte handshake header, or the failure status."""
    if h[0] != 0x01:
        return "nothello"
    total = 4 + int.from_bytes(h[1:4], "big")
    return "toobig" if total > HELLO_MAX else total


def _record_header(h: bytes) -> Status | int | None:
    """Checks 0..5 record header bytes: the record length when all 5 are valid, None when fewer, or 'nothello'.
    Empty records are valid: the TLS library accepts them before the hello is complete."""
    if len(h) >= 1 and h[0] != 22:
        return "nothello"
    if len(h) >= 2 and h[1] != 3:
        return "nothello"
    if len(h) < 5:
        return None
    n = int.from_bytes(h[3:5], "big")
    return "nothello" if n > RECORD_MAX else n


def tls_capture(raw: bytes) -> TlsResult:
    """The first handshake message from the leading TLS records of a connection.

    An SSLv2-format ClientHello (first byte's top bit set, third byte 1) gives 'sslv2' and is not reassembled.
    Only complete records count towards the message. While it is incomplete, `need` is a lower bound on the raw
    bytes that must be available before the message can be complete: the end of the record being received, plus
    one more record header and the missing payload when that record cannot hold the rest.
    """
    if raw[:1] and raw[0] & 0x80:
        # SSLv2 record header (decision 036): recognised by its message type, never reassembled
        if len(raw) < 3:
            return TlsResult("again", need=3)
        return TlsResult("sslv2" if raw[2] == 1 else "nothello")
    payload = b""
    pos = 0
    total: int | None = None
    while True:
        rh = _record_header(raw[pos:pos + 5])
        if rh == "nothello":
            return TlsResult("nothello")
        if rh is None or isinstance(rh, str):
            break
        frag = raw[pos + 5:pos + 5 + rh]
        if len(frag) < rh:
            break
        payload += frag
        pos += 5 + rh
        if total is None and len(payload) >= 4:
            mh = _message_header(payload[:4])
            if isinstance(mh, str):
                return TlsResult(mh)
            total = mh
        if total is not None and len(payload) >= total:
            return TlsResult("done", payload[:total])

    # incomplete record (or missing header) at pos
    rest = raw[pos:]
    rlen = _record_header(rest[:5])
    if total is None and len(rest) >= 5 and len(payload) + len(rest) - 5 >= 4:
        mh = _message_header((payload + rest[5:])[:4])
        if isinstance(mh, str):
            return TlsResult(mh)
        total = mh
    missing = (total - len(payload)) if total is not None else 4 - len(payload)
    if isinstance(rlen, int):
        need = pos + 5 + rlen + (5 + missing - rlen if missing > rlen else 0)
    else:
        need = pos + 5 + missing
    return TlsResult("toobig") if need > HELLO_RAW_MAX else TlsResult("again", need=need)


@dataclass
class QuicCapture:
    """Reassembles the start of the QUIC Initial CRYPTO stream: the first copy of each byte wins, bytes at or beyond
    the message end (HELLO_MAX while the length is unknown) are ignored, and the state never changes once it is not
    'again'."""

    got: dict[int, int] = field(default_factory=dict)
    total: int = 0
    status: Status = "again"

    def add(self, offset: int, data: bytes) -> Status:
        if self.status != "again":
            return self.status
        limit = self.total or HELLO_MAX
        for i, b in enumerate(data):
            if offset + i >= limit:
                break
            self.got.setdefault(offset + i, b)
        if not self.total and all(k in self.got for k in range(4)):
            mh = _message_header(bytes(self.got[k] for k in range(4)))
            if isinstance(mh, str):
                self.status = mh
                return mh
            self.total = mh
        if self.total and all(k in self.got for k in range(self.total)):
            self.status = "done"
        return self.status

    @property
    def msg(self) -> bytes:
        return bytes(self.got[k] for k in range(self.total)) if self.status == "done" else b""


def records(msg: bytes, sizes: list[int], version: int = 0x0301) -> bytes:
    """Splits a handshake message into handshake records of the given payload sizes (the last takes the rest)."""
    out, p = b"", 0
    for n in sizes:
        if p >= len(msg):
            break
        chunk = msg[p:p + n]
        out += bytes([22]) + version.to_bytes(2, "big") + len(chunk).to_bytes(2, "big") + chunk
        p += n
    if p < len(msg):
        chunk = msg[p:]
        out += bytes([22]) + version.to_bytes(2, "big") + len(chunk).to_bytes(2, "big") + chunk
    return out
