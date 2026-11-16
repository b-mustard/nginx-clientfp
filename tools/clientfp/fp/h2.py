"""Akamai HTTP/2 client fingerprint: reference calculator for doc/http2_sig.md §2-§3.

Input is what the client sends after TLS (or on a cleartext h2c connection): the 24-octet client preface followed
by frames.

    compute(stream)                          # -> H2Fingerprint(fingerprint=..., hash=..., overflow=..., ...)
    python -m clientfp.fp.h2 <hex>           # prints fingerprint, hash, overflow

Rules (normative text: doc/http2_sig.md):

* S: the first SETTINGS frame that is not an ACK and has at least one parameter. Wire order, duplicate and unknown
  ids kept, `id:value` in decimal joined by `;`. Empty if there is no such frame.
* WU: the first WINDOW_UPDATE on stream 0, `increment & 0x7fffffff`. `00` if there is none.
* P: every PRIORITY frame, `stream_id:E:depends_on:weight` with weight = wire octet + 1, joined by `,`. `0` if
  there is none. The priority block of a HEADERS frame is not included.
* PS: the pseudo-headers of the first HEADERS frame's header block (with its CONTINUATION frames), HPACK-decoded, as
  `m`/`p`/`a`/`s` joined by `,` in decode order. Each letter is recorded once; other headers are ignored.
* Capture stops at the end of the first header block. Everything after it is ignored and not even parsed.
* Bounds (doc/ai_dec/decision_012.md): at most 32 settings and 32 PRIORITY frames are recorded. Further ones are
  dropped and `overflow` is set; the string keeps its grammar.

Errors. Both are `ValueError`; after either one, discard the parser.

* `IncompleteStreamError`: the input ends before the first header block is complete, for example in the middle of a
  frame. No fingerprint exists yet: nginx builds the fingerprint for a request, and the first request exists only
  once its header block is complete. Feed more data with `H2FingerprintParser.feed()`.
* `ValueError`: input the calculator cannot decode, on which a server closes the connection before the first
  request: a wrong preface; a SETTINGS frame (the one recorded), stream-0 WINDOW_UPDATE (the one recorded) or PRIORITY
  frame whose length does not fit its type; HEADERS padding or priority fields longer than the frame; a header block
  interrupted by another frame or continued on another stream; CONTINUATION without an open header block;
  PUSH_PROMISE (clients must not send it); an HPACK decoding error.

Not checked, because they do not change what is extracted and the references tolerate them (doc/http2_sig.md §4.4):
stream-id rules (PRIORITY on stream 0, WINDOW_UPDATE on an idle stream), setting value ranges, a zero WINDOW_UPDATE
increment, frame size limits, and frames that are ignored anyway (DATA, RST_STREAM, PING, GOAWAY, unknown types).
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

import hpack

PREFACE: Final = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_HEADER_LEN: Final = 9

MAX_SETTINGS: Final = 32
MAX_PRIORITIES: Final = 32


class FrameType(IntEnum):
    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    RST_STREAM = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    PING = 0x6
    GOAWAY = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION = 0x9


FLAG_ACK: Final = 0x01  # SETTINGS, PING
FLAG_END_STREAM: Final = 0x01  # DATA, HEADERS
FLAG_END_HEADERS: Final = 0x04
FLAG_PADDED: Final = 0x08
FLAG_PRIORITY: Final = 0x20

PSEUDO_HEADER_LETTERS: Final[dict[bytes, str]] = {b":method": "m", b":path": "p", b":authority": "a", b":scheme": "s"}


class IncompleteStreamError(ValueError):
    """The stream ends before the first header block is complete."""


@dataclass(frozen=True, slots=True)
class Setting:
    id: int
    value: int

    def __str__(self) -> str:
        return f"{self.id}:{self.value}"


@dataclass(frozen=True, slots=True)
class Priority:
    stream_id: int
    exclusive: bool
    depends_on: int
    weight: int
    """Wire octet + 1, so 1-256."""

    def __str__(self) -> str:
        return f"{self.stream_id}:{int(self.exclusive)}:{self.depends_on}:{self.weight}"


@dataclass(frozen=True, slots=True)
class H2Fingerprint:
    fingerprint: str
    hash: str
    """lowercase hex MD5 of `fingerprint` (kittens.sh: akamai_fingerprint_hash)."""
    overflow: bool
    """More than MAX_SETTINGS settings or MAX_PRIORITIES PRIORITY frames were seen; the extra ones are not included."""
    settings: tuple[Setting, ...]
    window_update: int | None
    priorities: tuple[Priority, ...]
    pseudo_header_order: tuple[str, ...]


def format_fingerprint(settings: Iterable[Setting], window_update: int | None, priorities: Iterable[Priority],
                       pseudo_header_order: Iterable[str]) -> str:
    """`S|WU|P|PS` (doc/http2_sig.md §1)."""
    s = ";".join(map(str, settings))
    wu = "00" if window_update is None else str(window_update)
    p = ",".join(map(str, priorities)) or "0"
    return f"{s}|{wu}|{p}|{','.join(pseudo_header_order)}"


def fingerprint_hash(fingerprint: str) -> str:
    return hashlib.md5(fingerprint.encode(), usedforsecurity=False).hexdigest()


class H2FingerprintParser:
    """Incremental calculator: `feed()` the client stream in pieces of any size, then read `result()`."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._preface_done = False
        self._frozen = False
        self._overflow = False
        self._settings: tuple[Setting, ...] | None = None  # None until the first non-empty SETTINGS frame
        self._window_update: int | None = None
        self._priorities: list[Priority] = []
        self._block: bytearray | None = None  # first header block, while its CONTINUATION frames are pending
        self._block_stream = 0
        self._pseudo: tuple[str, ...] = ()

    @property
    def frozen(self) -> bool:
        """True once the first header block is complete; further input is ignored."""
        return self._frozen

    def feed(self, data: bytes) -> bool:
        """Consume more of the client stream. Returns `frozen`."""
        if self._frozen:
            return True
        self._buf += data
        if not self._preface_done:
            n = min(len(self._buf), len(PREFACE))
            if self._buf[:n] != PREFACE[:n]:
                raise ValueError("stream does not start with the HTTP/2 client preface")
            if n < len(PREFACE):
                return False
            del self._buf[:len(PREFACE)]
            self._preface_done = True
        while len(self._buf) >= FRAME_HEADER_LEN:
            length = int.from_bytes(self._buf[0:3], "big")
            end = FRAME_HEADER_LEN + length
            if len(self._buf) < end:
                break
            ftype, flags = self._buf[3], self._buf[4]
            stream_id = int.from_bytes(self._buf[5:9], "big") & 0x7FFFFFFF
            payload = bytes(self._buf[FRAME_HEADER_LEN:end])
            del self._buf[:end]
            if self._frame(ftype, flags, stream_id, payload):
                self._buf.clear()  # everything after the first header block is ignored
                return True
        return False

    def result(self) -> H2Fingerprint:
        if not self._frozen:
            where = "in the preface" if not self._preface_done else (
                "inside the first header block" if self._block is not None else "before the first HEADERS frame")
            raise IncompleteStreamError(f"stream ends {where} ({len(self._buf)} bytes of an incomplete frame)")
        settings = self._settings or ()
        fp = format_fingerprint(settings, self._window_update, self._priorities, self._pseudo)
        return H2Fingerprint(fingerprint=fp, hash=fingerprint_hash(fp), overflow=self._overflow, settings=settings,
                             window_update=self._window_update, priorities=tuple(self._priorities),
                             pseudo_header_order=self._pseudo)

    def _frame(self, ftype: int, flags: int, stream_id: int, payload: bytes) -> bool:
        """Record one frame. Returns True when it ends the first header block (the capture is frozen)."""
        if self._block is not None:
            if ftype != FrameType.CONTINUATION or stream_id != self._block_stream:
                raise ValueError(f"header block on stream {self._block_stream} interrupted by frame type {ftype} "
                                 f"on stream {stream_id}")
            self._block += payload
            if flags & FLAG_END_HEADERS:
                self._end_header_block()
        elif ftype == FrameType.SETTINGS:
            if flags & FLAG_ACK or not payload or self._settings is not None:
                return False
            if len(payload) % 6:
                raise ValueError(f"SETTINGS payload of {len(payload)} bytes is not a multiple of 6")
            entries = [Setting(*struct.unpack_from(">HI", payload, i)) for i in range(0, len(payload), 6)]
            if len(entries) > MAX_SETTINGS:
                self._overflow = True
            self._settings = tuple(entries[:MAX_SETTINGS])
        elif ftype == FrameType.WINDOW_UPDATE:
            if stream_id != 0 or self._window_update is not None:
                return False
            if len(payload) != 4:
                raise ValueError(f"WINDOW_UPDATE payload of {len(payload)} bytes, want 4")
            self._window_update = int.from_bytes(payload, "big") & 0x7FFFFFFF
        elif ftype == FrameType.PRIORITY:
            if len(payload) != 5:
                raise ValueError(f"PRIORITY payload of {len(payload)} bytes, want 5")
            if len(self._priorities) >= MAX_PRIORITIES:
                self._overflow = True
                return False
            dep = int.from_bytes(payload[:4], "big")
            self._priorities.append(Priority(stream_id, bool(dep >> 31), dep & 0x7FFFFFFF, payload[4] + 1))
        elif ftype == FrameType.HEADERS:
            self._block = bytearray(_header_block_fragment(flags, payload))
            self._block_stream = stream_id
            if flags & FLAG_END_HEADERS:
                self._end_header_block()
        elif ftype == FrameType.CONTINUATION:
            raise ValueError("CONTINUATION frame without a preceding HEADERS frame")
        elif ftype == FrameType.PUSH_PROMISE:
            raise ValueError("PUSH_PROMISE from a client")
        # DATA, RST_STREAM, PING, GOAWAY and unknown frame types are not part of the fingerprint
        return self._frozen

    def _end_header_block(self) -> None:
        assert self._block is not None
        try:
            headers = hpack.Decoder().decode(bytes(self._block), raw=True)
        except hpack.HPACKError as e:
            raise ValueError(f"HPACK decoding of the first header block failed: {e}") from e
        letters: list[str] = []
        for name, _value in headers:
            letter = PSEUDO_HEADER_LETTERS.get(name if isinstance(name, bytes) else name.encode())
            if letter is not None and letter not in letters:
                letters.append(letter)
        self._pseudo = tuple(letters)
        self._block = None
        self._frozen = True


def _header_block_fragment(flags: int, payload: bytes) -> bytes:
    """Strip the HEADERS frame's pad length, priority block (not part of P) and padding."""
    start, pad = 0, 0
    if flags & FLAG_PADDED:
        if not payload:
            raise ValueError("PADDED HEADERS frame without a pad length")
        start, pad = 1, payload[0]
    if flags & FLAG_PRIORITY:
        start += 5
    if start + pad > len(payload):
        raise ValueError(f"HEADERS padding/priority fields ({start} + {pad} bytes) exceed the {len(payload)}-byte "
                         "payload")
    return payload[start:len(payload) - pad]


def compute(stream: bytes) -> H2Fingerprint:
    """Fingerprint of a complete client stream (preface + frames up to at least the end of the first header block)."""
    parser = H2FingerprintParser()
    parser.feed(stream)
    return parser.result()


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m clientfp.fp.h2",
                                 description="Akamai HTTP/2 fingerprint of a client stream (doc/http2_sig.md)")
    ap.add_argument("hex", help="client bytes after TLS: preface + frames, hex")
    a = ap.parse_args(argv)
    try:
        r = compute(bytes.fromhex(a.hex.strip()))
    except ValueError as e:
        print(f"{ap.prog}: error: {e}", file=sys.stderr)
        return 1
    print(f"fingerprint {r.fingerprint}\nhash        {r.hash}\noverflow    {int(r.overflow)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
