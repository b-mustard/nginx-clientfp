# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""TLS ClientHello framing shared by the fingerprint calculators (ja4.py, tlsfp.py). No fingerprint logic here.

Input is the ClientHello *handshake message* (msg_type 0x01, 3-byte length, body), as the module's capture reassembles
it (hello.py), or the TLS records (content type 22) that carry it, as captured on the wire.

Decoding follows the TLS presentation language (RFC 8446 §3): every length must fit what encloses it and fill it
exactly. The handshake message, the body (which ends with the extensions block, if any), the extensions block and each
extension are checked here; calculators check the inside of the extensions they decode with `whole_vector` and
`u16_list`.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Literal, get_args

HANDSHAKE_CLIENT_HELLO: Final = 0x01
RECORD_HANDSHAKE: Final = 22

Proto = Literal["t", "q", "d"]
"""`t` TLS over TCP, `q` QUIC, `d` DTLS."""
PROTOS: Final[tuple[str, ...]] = get_args(Proto)


class ClientHelloError(ValueError):
    """The input is not a complete, well-formed ClientHello (or an extension a calculator decodes is malformed)."""


class Reader:
    """Bounds-checked big-endian reader over `buf[start:end]`. Every failure raises ClientHelloError."""

    __slots__ = ("_buf", "_pos", "_end", "_what")

    def __init__(self, buf: bytes, what: str) -> None:
        self._buf = buf
        self._pos = 0
        self._end = len(buf)
        self._what = what

    @property
    def remaining(self) -> int:
        return self._end - self._pos

    def take(self, n: int, field: str) -> bytes:
        if n > self.remaining:
            raise ClientHelloError(
                f"truncated {self._what}: {field} needs {n} bytes at offset {self._pos}, {self.remaining} left")
        out = self._buf[self._pos:self._pos + n]
        self._pos += n
        return out

    def uint(self, size: int, field: str) -> int:
        return int.from_bytes(self.take(size, field), "big")

    def vector(self, len_size: int, field: str) -> bytes:
        """A length-prefixed vector (`len_size`-byte length, then that many bytes)."""
        return self.take(self.uint(len_size, f"{field} length"), field)

    def expect_end(self) -> None:
        if self.remaining:
            raise ClientHelloError(f"malformed {self._what}: {self.remaining} unexpected trailing bytes")


def _u16_list(data: bytes, field: str) -> tuple[int, ...]:
    if len(data) % 2:
        raise ClientHelloError(f"malformed {field}: odd byte length {len(data)}")
    return struct.unpack(f">{len(data) // 2}H", data)


def u16_list(data: bytes, field: str) -> tuple[int, ...]:
    if len(data) % 2:
        raise ClientHelloError(f"malformed {field}: odd byte length {len(data)}")
    return struct.unpack(f">{len(data) // 2}H", data)


@dataclass(frozen=True, slots=True)
class Extension:
    type: int
    data: bytes


@dataclass(frozen=True, slots=True)
class ClientHello:
    """The ClientHello fields the calculators use. Lists are in wire order and include GREASE values."""

    legacy_version: int
    ciphers: tuple[int, ...]
    extensions: tuple[Extension, ...] = ()

    def ext(self, ext_type: int) -> bytes | None:
        """Data of the first extension of this type, or None if absent."""
        return next((e.data for e in self.extensions if e.type == ext_type), None)


def parse_client_hello(msg: bytes) -> ClientHello:
    """Parse one complete ClientHello handshake message: type(1) = 0x01, length(3), body."""
    hdr = Reader(msg, "handshake message")
    if hdr.uint(1, "msg_type") != HANDSHAKE_CLIENT_HELLO:
        raise ClientHelloError(f"not a ClientHello: handshake msg_type {msg[0]:#04x}")
    body = Reader(hdr.vector(3, "ClientHello body"), "ClientHello body")
    hdr.expect_end()

    legacy_version = body.uint(2, "legacy_version")
    body.take(32, "random")
    body.vector(1, "session_id")
    ciphers = u16_list(body.vector(2, "cipher_suites"), "cipher_suites")
    body.vector(1, "compression_methods")
    extensions: list[Extension] = []
    if body.remaining:  # the extensions block may be absent: zero extensions
        block = Reader(body.vector(2, "extensions"), "extensions block")
        while block.remaining:
            ext_type = block.uint(2, "extension type")
            extensions.append(Extension(ext_type, block.vector(2, f"extension {ext_type:04x} data")))
        body.expect_end()
    return ClientHello(legacy_version, ciphers, tuple(extensions))


def client_hello_from_records(data: bytes) -> bytes | None:
    """Reassemble the first handshake message from leading TLS handshake records. None if it is incomplete."""
    hs, p = b"", 0
    while p + 5 <= len(data) and data[p] == RECORD_HANDSHAKE:
        n = int.from_bytes(data[p + 3:p + 5], "big")
        hs += data[p + 5:p + 5 + n]
        p += 5 + n
        if len(hs) >= 4:
            end = 4 + int.from_bytes(hs[1:4], "big")
            if len(hs) >= end:
                return hs[:end]
    return None


def whole_vector(data: bytes, len_size: int, what: str) -> bytes:
    r = Reader(data, what)
    out = r.vector(len_size, "list")
    r.expect_end()
    return out



def encode_client_hello(legacy_version: int, ciphers: Sequence[int], extensions: Sequence[Extension] | None,
                        *, session_id: bytes = b"", compression: bytes = b"\x00") -> bytes:
    """Build a ClientHello handshake message (zero random). `extensions=None` omits the extensions block."""
    body = (struct.pack(">H", legacy_version) + bytes(32) + bytes([len(session_id)]) + session_id
            + struct.pack(f">H{len(ciphers)}H", 2 * len(ciphers), *ciphers)
            + bytes([len(compression)]) + compression)
    if extensions is not None:
        block = b"".join(struct.pack(">HH", e.type, len(e.data)) + e.data for e in extensions)
        body += struct.pack(">H", len(block)) + block
    return bytes([HANDSHAKE_CLIENT_HELLO]) + len(body).to_bytes(3, "big") + body
