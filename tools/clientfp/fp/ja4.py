# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""JA4 (TLS client) fingerprint: reference implementation of doc/ja4_sig.md.

Upstream definition: FoxIO's JA4.md,
https://github.com/FoxIO-LLC/ja4/blob/16b96d95c220762cf658f67d678cda2aac95c81e/technical_details/JA4.md

Input is the ClientHello *handshake message* (msg_type 0x01, 3-byte length, body), as the module's capture
reassembles it (clientfp.fp.hello), or the TLS records (content type 22) that carry it, as captured on the wire.

    clientfp-ja4 <hex> [--proto t|q|d]     # prints ja4, ja4_r, ja4_o, ja4_ro, a, b_raw, c_raw
    clientfp-ja4 --selftest                # worked examples and ALPN examples of the spec

Parsing (doc/ja4_sig.md §2, "parse defensively"):

* Structure is strict. Every length field is checked against the bytes that enclose it, and every length-prefixed
  structure must be filled exactly: the handshake message, the body (which ends with the extensions block, if there
  is one), the extensions block, and the inner lists of the three extensions that JA4 decodes. A u16 list must have
  an even length. Any violation raises `ClientHelloError`, a `ValueError`: no fingerprint.
* Content is lenient. Unknown versions, cipher suites and extension types are fingerprinted as they are, and
  zero-length lists are not errors, because the spec defines their result: no ciphers gives `000000000000`, an empty
  ALPN list or an empty first protocol gives `00`, an empty sigalg list gives `c_raw` without `_`, no extensions give
  `c = 000000000000`, and a `supported_versions` list without a non-GREASE value falls back to `legacy_version`.
* Only ALPN (0x0010), signature_algorithms (0x000d) and supported_versions (0x002b) are decoded, each from its first
  occurrence. All other extension data, including the SNI value, is opaque.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

from .tls import (HANDSHAKE_CLIENT_HELLO, PROTOS, RECORD_HANDSHAKE, ClientHello, ClientHelloError, Extension, Proto,
                  Reader, client_hello_from_records, encode_client_hello, parse_client_hello, u16_list, whole_vector)

__all__ = ["HANDSHAKE_CLIENT_HELLO", "PROTOS", "RECORD_HANDSHAKE", "ClientHello", "ClientHelloError", "Extension",
           "Proto", "client_hello_from_records", "encode_client_hello", "parse_client_hello"]

_Reader = Reader
_u16_list = u16_list
_whole_vector = whole_vector

EXT_SNI: Final = 0x0000
EXT_SIGALGS: Final = 0x000D
EXT_ALPN: Final = 0x0010
EXT_SUPPORTED_VERSIONS: Final = 0x002B


VERSIONS: Final[dict[int, str]] = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
    0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}
ZERO_HASH: Final = "000000000000"
FORMS: Final = ("ja4", "ja4_r", "ja4_o", "ja4_ro")


def is_grease(v: int) -> bool:
    """RFC 8701 GREASE value: 0x0a0a, 0x1a1a, ... 0xfafa."""
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


# ---------------------------------------------------------------------------------------------------- extensions


def parse_alpn(data: bytes) -> tuple[bytes, ...]:
    """ALPN extension data: u16 list length, then { u8 length, name }*. The list may be empty."""
    names, lst = [], _Reader(_whole_vector(data, 2, "ALPN extension"), "ALPN protocol list")
    while lst.remaining:
        names.append(lst.vector(1, "protocol name"))
    return tuple(names)


def parse_sigalgs(data: bytes) -> tuple[int, ...]:
    """signature_algorithms extension data: u16 list length, then u16*."""
    return _u16_list(_whole_vector(data, 2, "signature_algorithms extension"), "signature_algorithms list")


def parse_supported_versions(data: bytes) -> tuple[int, ...]:
    """supported_versions extension data (ClientHello form): u8 list length, then u16*."""
    return _u16_list(_whole_vector(data, 1, "supported_versions extension"), "supported_versions list")


# ---------------------------------------------------------------------------------------------------- JA4


@dataclass(frozen=True, slots=True)
class JA4Fingerprint:
    """All four JA4 forms (doc/ja4_sig.md §1) plus the parts they are built from."""

    ja4: str
    ja4_r: str
    ja4_o: str
    ja4_ro: str
    a: str
    b_raw: str
    c_raw: str

    def forms(self) -> dict[str, str]:
        """`ja4`, `ja4_r`, `ja4_o`, `ja4_ro`."""
        return {k: getattr(self, k) for k in FORMS}

    def as_dict(self) -> dict[str, str]:
        return {**self.forms(), "a": self.a, "b_raw": self.b_raw, "c_raw": self.c_raw}


def tls_version(ch: ClientHello) -> str:
    """Highest non-GREASE supported_versions value, else legacy_version; mapped to 2 characters, `00` if unknown."""
    version = ch.legacy_version
    sv = ch.ext(EXT_SUPPORTED_VERSIONS)
    if sv is not None:
        offered = [v for v in parse_supported_versions(sv) if not is_grease(v)]
        if offered:  # spec is silent on a GREASE-only list: fall back to legacy_version
            version = max(offered)
    return VERSIONS.get(version, "00")


def _alnum(b: int) -> bool:
    return 0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A


def alpn_chars(ch: ClientHello) -> str:
    """First and last character of the first offered ALPN protocol; hex nibbles if either end is not alnum."""
    data = ch.ext(EXT_ALPN)
    names = parse_alpn(data) if data is not None else ()
    if not names or not names[0]:  # no extension, empty list, empty first value
        return "00"
    first = names[0]
    if _alnum(first[0]) and _alnum(first[-1]):
        return chr(first[0]) + chr(first[-1])
    h = first.hex()
    return h[0] + h[-1]


def sigalgs(ch: ClientHello) -> list[int]:
    """Non-GREASE signature algorithms in wire order (duplicates kept)."""
    data = ch.ext(EXT_SIGALGS)
    return [v for v in parse_sigalgs(data) if not is_grease(v)] if data is not None else []


def hash12(s: str) -> str:
    """First 12 hex digits of sha256(s); `000000000000` for the empty string."""
    return hashlib.sha256(s.encode()).hexdigest()[:12] if s else ZERO_HASH


def _hexlist(values: Iterable[int]) -> str:
    return ",".join(f"{v:04x}" for v in values)


def compute(ch: ClientHello, proto: Proto = "t") -> JA4Fingerprint:
    """JA4 of a parsed ClientHello. Raises ClientHelloError if an extension JA4 decodes is malformed."""
    if proto not in PROTOS:
        raise ValueError(f"proto must be one of {PROTOS}, not {proto!r}")
    ciphers = [c for c in ch.ciphers if not is_grease(c)]
    exts = [e.type for e in ch.extensions if not is_grease(e.type)]
    sni = "d" if EXT_SNI in exts else "i"
    a = f"{proto}{tls_version(ch)}{sni}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn_chars(ch)}"
    sig = _hexlist(sigalgs(ch))

    def c_part(ext_list: Iterable[int]) -> str:
        s = _hexlist(ext_list)
        if not s:
            return ""  # no extensions -> c = 000000000000
        return f"{s}_{sig}" if sig else s

    b_sorted = _hexlist(sorted(ciphers))
    c_sorted = c_part(sorted(t for t in exts if t not in (EXT_SNI, EXT_ALPN)))
    b_orig = _hexlist(ciphers)
    c_orig = c_part(exts)  # wire order keeps SNI and ALPN
    return JA4Fingerprint(
        ja4=f"{a}_{hash12(b_sorted)}_{hash12(c_sorted)}",
        ja4_r=f"{a}_{b_sorted}_{c_sorted}",
        ja4_o=f"{a}_{hash12(b_orig)}_{hash12(c_orig)}",
        ja4_ro=f"{a}_{b_orig}_{c_orig}",
        a=a, b_raw=b_sorted, c_raw=c_sorted,
    )


def from_bytes(raw: bytes, proto: Proto = "t") -> JA4Fingerprint:
    """JA4 of a ClientHello handshake message, or of TLS records starting with one (first byte 0x16)."""
    if raw[:1] == bytes([RECORD_HANDSHAKE]):
        msg = client_hello_from_records(raw)
        if msg is None:
            raise ClientHelloError("incomplete ClientHello in TLS records")
        raw = msg
    return compute(parse_client_hello(raw), proto)


# ---------------------------------------------------------------------------------------------------- encoding


def alpn_ext(*names: bytes) -> Extension:
    lst = b"".join(bytes([len(n)]) + n for n in names)
    return Extension(EXT_ALPN, struct.pack(">H", len(lst)) + lst)


def sigalgs_ext(*algs: int) -> Extension:
    return Extension(EXT_SIGALGS, struct.pack(f">H{len(algs)}H", 2 * len(algs), *algs))


def supported_versions_ext(*versions: int) -> Extension:
    return Extension(EXT_SUPPORTED_VERSIONS, struct.pack(f">B{len(versions)}H", 2 * len(versions), *versions))


# ---------------------------------------------------------------------------------------------------- selftest

ALPN_EXAMPLES: Final[dict[bytes, str]] = {  # doc/ja4_sig.md §3 a.6, plus the empty value and a lone non-alnum byte
    b"h2": "h2", b"http/1.1": "h1", b"a": "aa", b"\xab": "ab", b"\xab\xcd": "ad", b"\x20\x61": "21", b"\x30\xab": "3b",
    b"\x61\x20": "60", b"\x30\x31\xab\xcd": "3d", b"\x30\xab\xcd\x31": "01", b"#x": "28", b"\x20": "20", b"": "00",
}
SPEC_EXAMPLE_CIPHERS: Final = (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013,
                               0xC014, 0x009C, 0x009D, 0x002F, 0x0035)
SPEC_EXAMPLE_EXTS: Final = (0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D, 0x0005, 0x0023, 0x0012,
                            0x002B, 0xFF01, 0x000B, 0x000A, 0x0015)
SPEC_EXAMPLE_SIGALGS: Final = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)


def spec_example_hello() -> bytes:
    """The spec's worked example (doc/ja4_sig.md §3) as a handshake message, with GREASE added in every list."""
    special = {EXT_SIGALGS: sigalgs_ext(0x5A5A, *SPEC_EXAMPLE_SIGALGS), EXT_ALPN: alpn_ext(b"h2", b"http/1.1"),
               EXT_SUPPORTED_VERSIONS: supported_versions_ext(0x2A2A, 0x0304, 0x0303)}
    exts = [Extension(0x3A3A, b"")] + [special.get(t, Extension(t, b"")) for t in SPEC_EXAMPLE_EXTS]
    return encode_client_hello(0x0303, (0x0A0A, *SPEC_EXAMPLE_CIPHERS), exts, session_id=bytes(32))


def selftest() -> list[str]:
    """Check the worked examples and ALPN examples of the spec. Returns the failures (empty: all good)."""
    failures: list[str] = []

    def check(what: str, got: object, want: object) -> None:
        if got != want:
            failures.append(f"{what}: got {got!r}, want {want!r}")

    ext = "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01"
    sig = "0403,0804,0401,0503,0805,0501,0806,0601"
    check("hash12(b_raw)",
          hash12("002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"), "8daaf6152771")
    check("hash12(c_raw)", hash12(f"{ext}_{sig}"), "e5627efa2ab1")
    check("hash12(c_raw without sigalgs)", hash12(ext), "6d807ffa2a79")
    check("hash12('')", hash12(""), ZERO_HASH)
    check("GREASE values", [v for v in range(0x10000) if is_grease(v)], [0x0A0A + 0x1010 * i for i in range(16)])

    for value, want in ALPN_EXAMPLES.items():
        hello = encode_client_hello(0x0303, [0x1301], [alpn_ext(value, b"http/1.1")])
        check(f"ALPN {value.hex(' ') or '<empty>'}", from_bytes(hello).a[-2:], want)

    r = from_bytes(spec_example_hello())
    check("spec JA4", r.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1")
    check("spec JA4_o", r.ja4_o, "t13d1516h2_acb858a92679_18f69afefd3d")
    check("spec JA4_r", r.ja4_r,
          "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_" + f"{ext}_{sig}")
    check("spec JA4_ro", r.ja4_ro,
          "t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_"
          f"001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015_{sig}")
    return failures


# ---------------------------------------------------------------------------------------------------- CLI


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="clientfp-ja4", description="JA4 fingerprint of a ClientHello (doc/ja4_sig.md)")
    ap.add_argument("hex", nargs="?", help="ClientHello handshake message or TLS record(s), hex")
    ap.add_argument("--proto", default="t", choices=PROTOS, help="t: TLS/TCP (default), q: QUIC, d: DTLS")
    ap.add_argument("--selftest", action="store_true", help="check the spec's worked examples (default without hex)")
    a = ap.parse_args(argv)
    if a.selftest or not a.hex:
        failures = selftest()
        for f in failures:
            print(f"FAIL {f}")
        print("selftest FAILED" if failures else "selftest OK")
        return 1 if failures else 0
    try:
        result = from_bytes(bytes.fromhex(a.hex.strip()), a.proto)
    except ValueError as e:
        print(f"{ap.prog}: error: {e}", file=sys.stderr)
        return 1
    for k, v in result.as_dict().items():
        print(f"{k:7s} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
