# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""nDPI TLS Client Fingerprint (TLSFP): reference calculator.

Normative source: doc/nDPI_TLS_Fingerprint.md (draft v0.1, ntop/nDPI a01ea9463125), as interpreted in
doc/tlsfp_sig.md and decisions 022-027. TLSFP is computed here from the spec text, *not* derived from JA4: where the
two formats differ (ALPN case, version table, sigalg GREASE, the `_` in the c input, uncapped inputs, per-field
errors) the TLSFP rule applies.

    compute(parse_client_hello(msg), "t")   # -> TLSFPFingerprint(tlsfp=..., a=..., b=..., c=..., d=..., ...)
    python -m clientfp.fp.tlsfp <hex>        # prints the fingerprint and its hash inputs

Rules (spec section, decision):

* GREASE (§6.2, d027): RFC 8701 values 0x0a0a, 0x1a1a ... 0xfafa, removed from cipher suites, extension types and
  supported groups. Signature algorithms are not filtered: §6.2 does not list them.
* Ephemeral extensions (§6.3, Appendix B, Registry v1): 0x0015 padding, 0x0023 session_ticket, 0x0029
  pre_shared_key, 0x002a early_data, 0x002c cookie, 0x002d psk_key_exchange_modes. Removed after GREASE.
* a (§6.4): proto, version, `d`/`i` (SNI extension present), cipher count, sanitized extension count (SNI and ALPN
  included), ALPN; counts capped at 99 for display only (§7.5).
  - version: highest non-GREASE supported_versions value, else legacy_version; 0304 13, 0303 12, 0302 11,
    0301 10, 0300 s3, feff d1, fefd d2, fefc d3, anything else 00 (no `s2`: not in the TLSFP table).
  - ALPN: first and last byte of the first protocol, lower-cased; `00` if the extension, the list or the first
    protocol is empty. If either byte is not a letter or digit: first hex nibble of the first byte and last hex
    nibble of the last byte (d025), so the field is always 2 safe characters.
* b (§6.5): SHA-256 of the sorted cipher list, `,`-joined 4-digit lowercase hex, first 12 hex digits.
* c (§6.6): sorted sanitized extensions without SNI (0000) and ALPN (0010), `_`, signature algorithms in advertised
  order. The `_` is always present, also with no signature algorithms (§6.6 formula).
* d (§6.7): SHA-256 of the sorted non-GREASE supported_groups; `000000000000` when the extension is absent or has no
  non-GREASE group (d023).
* Lists are not deduplicated (§7.4); repeated extensions are counted and listed; the first occurrence of a repeated
  ALPN / signature_algorithms / supported_versions / supported_groups extension is decoded.
* Errors (§9): a ClientHello whose framing is broken has no TLSFP (ClientHelloError). An extension that one field
  decodes and that is malformed empties that field only: supported_versions or ALPN -> a, signature_algorithms -> c,
  supported_groups -> d. Malformed means it does not decode exactly (TLS presentation language, RFC 8446 §3).
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from typing import Final

from .tls import (PROTOS, RECORD_HANDSHAKE, ClientHello, ClientHelloError, Extension, Proto, Reader,
                  client_hello_from_records, encode_client_hello, parse_client_hello, u16_list, whole_vector)

REGISTRY_VERSION: Final = 1
"""Ephemeral extension registry version (Appendix B), exported next to every TLSFP (§13, $clientfp_tlsfp_registry)."""

EPHEMERAL_V1: Final = frozenset({0x0015, 0x0023, 0x0029, 0x002A, 0x002C, 0x002D})

EXT_SNI: Final = 0x0000
EXT_SUPPORTED_GROUPS: Final = 0x000A
EXT_SIGALGS: Final = 0x000D
EXT_ALPN: Final = 0x0010
EXT_SUPPORTED_VERSIONS: Final = 0x002B

VERSIONS: Final[dict[int, str]] = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}
NO_GROUPS: Final = "000000000000"
MAX_COUNT: Final = 99


def is_grease(v: int) -> bool:
    """RFC 8701 GREASE (§6.2): both octets equal, low nibble 0xA."""
    return (v >> 8) == (v & 0xFF) and (v & 0x0F) == 0x0A


def hash12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def hexlist(values: Iterable[int]) -> str:
    return ",".join(f"{v:04x}" for v in values)


# ---------------------------------------------------------------------------------------------------- extensions


def parse_alpn(data: bytes) -> tuple[bytes, ...]:
    """ALPN extension data: u16 list length, then { u8 length, name }*, exactly filling the extension."""
    names, lst = [], Reader(whole_vector(data, 2, "ALPN extension"), "ALPN protocol list")
    while lst.remaining:
        names.append(lst.vector(1, "protocol name"))
    return tuple(names)


def parse_supported_versions(data: bytes) -> tuple[int, ...]:
    return u16_list(whole_vector(data, 1, "supported_versions extension"), "supported_versions list")


def parse_u16_vector(data: bytes, what: str) -> tuple[int, ...]:
    """signature_algorithms / supported_groups: u16 list length, then u16*, exactly filling the extension."""
    return u16_list(whole_vector(data, 2, f"{what} extension"), f"{what} list")


def _alnum(b: int) -> bool:
    return 0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A


def alpn_chars(ch: ClientHello) -> str:
    data = ch.ext(EXT_ALPN)
    names = parse_alpn(data) if data is not None else ()
    if not names or not names[0]:
        return "00"
    first, last = names[0][0], names[0][-1]
    if _alnum(first) and _alnum(last):
        return (chr(first) + chr(last)).lower()
    return f"{first:02x}"[0] + f"{last:02x}"[1]


def version(ch: ClientHello) -> str:
    v = ch.legacy_version
    data = ch.ext(EXT_SUPPORTED_VERSIONS)
    if data is not None:
        offered = [x for x in parse_supported_versions(data) if not is_grease(x)]
        if offered:
            v = max(offered)
    return VERSIONS.get(v, "00")


# ---------------------------------------------------------------------------------------------------- TLSFP


@dataclass(frozen=True, slots=True)
class TLSFPFingerprint:
    tlsfp: str
    a: str
    b: str
    c: str
    d: str
    input_b: str
    input_c: str | None
    """None when c is empty because signature_algorithms is malformed."""
    input_d: str | None
    """None when d is `000000000000` (no groups) or empty (malformed supported_groups)."""
    registry: int = REGISTRY_VERSION

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def compute(ch: ClientHello, proto: Proto = "t") -> TLSFPFingerprint:
    if proto not in PROTOS:
        raise ValueError(f"proto must be one of {PROTOS}, not {proto!r}")
    ciphers = [c for c in ch.ciphers if not is_grease(c)]
    exts = [e.type for e in ch.extensions if not is_grease(e.type)]
    sanitized = [t for t in exts if t not in EPHEMERAL_V1]

    try:
        a = (proto + version(ch) + ("d" if EXT_SNI in exts else "i") + f"{min(len(ciphers), MAX_COUNT):02d}"
             + f"{min(len(sanitized), MAX_COUNT):02d}" + alpn_chars(ch))
    except ClientHelloError:
        a = ""

    input_b = hexlist(sorted(ciphers))
    b = hash12(input_b)

    input_c: str | None
    sig = ch.ext(EXT_SIGALGS)
    try:
        sigalgs = parse_u16_vector(sig, "signature_algorithms") if sig is not None else ()
    except ClientHelloError:
        input_c, c = None, ""
    else:
        input_c = hexlist(sorted(t for t in sanitized if t not in (EXT_SNI, EXT_ALPN))) + "_" + hexlist(sigalgs)
        c = hash12(input_c)

    input_d: str | None = None
    grp = ch.ext(EXT_SUPPORTED_GROUPS)
    if grp is None:
        d = NO_GROUPS
    else:
        try:
            groups = sorted(g for g in parse_u16_vector(grp, "supported_groups") if not is_grease(g))
        except ClientHelloError:
            d = ""
        else:
            input_d = hexlist(groups) if groups else None
            d = hash12(input_d) if input_d is not None else NO_GROUPS

    return TLSFPFingerprint("_".join((a, b, c, d)), a, b, c, d, input_b, input_c, input_d)


def from_bytes(raw: bytes, proto: Proto = "t") -> TLSFPFingerprint:
    """TLSFP of a ClientHello handshake message, or of TLS records starting with one (first byte 0x16)."""
    if raw[:1] == bytes([RECORD_HANDSHAKE]):
        msg = client_hello_from_records(raw)
        if msg is None:
            raise ClientHelloError("incomplete ClientHello in TLS records")
        raw = msg
    return compute(parse_client_hello(raw), proto)


# ---------------------------------------------------------------------------------------------------- encoding


def u16_vector_ext(ext_type: int, values: Sequence[int]) -> Extension:
    return Extension(ext_type, struct.pack(f">H{len(values)}H", 2 * len(values), *values))


def alpn_ext(*names: bytes) -> Extension:
    lst = b"".join(bytes([len(n)]) + n for n in names)
    return Extension(EXT_ALPN, struct.pack(">H", len(lst)) + lst)


def supported_versions_ext(*versions: int) -> Extension:
    return Extension(EXT_SUPPORTED_VERSIONS, struct.pack(f">B{len(versions)}H", 2 * len(versions), *versions))


# ---------------------------------------------------------------------------------------------------- selftest

# Spec Appendix A, vector 1: the only field whose stated hash follows the spec's own algorithm (doc/tlsfp_sig.md §3).
SPEC_VECTOR1_GROUPS: Final = (0x0017, 0x0018, 0x0019, 0x001D, 0x001E)
SPEC_VECTOR1_D: Final = "0a47a2b05960"
# §6.5: TLSFP_b is JA4_b; for the vector's 15 cipher suites (Chrome's) that is 8daaf6152771 (FoxIO, kittens.sh).
SPEC_VECTOR1_CIPHERS: Final = (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013,
                               0xC014, 0x009C, 0x009D, 0x002F, 0x0035)
SPEC_VECTOR1_B: Final = "8daaf6152771"
ALPN_EXAMPLES: Final[dict[bytes, str]] = {
    b"h2": "h2", b"http/1.1": "h1", b"H2": "h2", b"HTTP/1.1": "h1", b"a": "aa", b"Z": "zz", b"\xab": "ab",
    b"\xab\xcd": "ad", b"\x20\x61": "21", b"#x": "28", b"x#": "73", b"": "00",
}


def selftest() -> list[str]:
    failures: list[str] = []

    def check(what: str, got: object, want: object) -> None:
        if got != want:
            failures.append(f"{what}: got {got!r}, want {want!r}")

    hello = encode_client_hello(0x0303, (0x0A0A, *SPEC_VECTOR1_CIPHERS), [
        Extension(EXT_SNI, b"\x00\x0e\x00\x00\x0bexample.com"),
        u16_vector_ext(EXT_SUPPORTED_GROUPS, (0x2A2A, 0x001D, 0x0017, 0x0018, 0x0019, 0x001E)),
        supported_versions_ext(0x3A3A, 0x0304, 0x0303),
        alpn_ext(b"h2", b"http/1.1"),
        Extension(0x0015, bytes(10)), Extension(0x0023, b""), Extension(0x002D, b"\x01\x01"),
        u16_vector_ext(EXT_SIGALGS, (0x0403, 0x0804, 0x0401)),
    ])
    r = compute(parse_client_hello(hello))
    check("vector 1 TLSFP_d", r.d, SPEC_VECTOR1_D)
    check("vector 1 TLSFP_b", r.b, SPEC_VECTOR1_B)
    check("a: GREASE and 3 ephemeral extensions removed from the count", r.a, "t13d1505h2")
    check("c input", r.input_c, "000a,000d,002b_0403,0804,0401")
    check("length", len(r.tlsfp), 49)
    for name, want in ALPN_EXAMPLES.items():
        ch = ClientHello(0x0303, (0x1301,), (alpn_ext(name),))
        check(f"ALPN {name!r}", alpn_chars(ch), want)
    no_groups = compute(ClientHello(0x0303, (0x1301,), ()))
    check("no extensions", (no_groups.a, no_groups.input_c, no_groups.d), ("t12i010000", "_", NO_GROUPS))
    return failures


# ---------------------------------------------------------------------------------------------------- CLI


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="clientfp-tlsfp",
                                 description="nDPI TLS client fingerprint (TLSFP) of a ClientHello (doc/tlsfp_sig.md)")
    ap.add_argument("hex", nargs="?", help="ClientHello handshake message or TLS record(s), hex")
    ap.add_argument("--proto", default="t", choices=PROTOS, help="t: TLS/TCP (default), q: QUIC, d: DTLS")
    ap.add_argument("--selftest", action="store_true", help="check the spec examples (default without hex)")
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
        print(f"{k:8s} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
