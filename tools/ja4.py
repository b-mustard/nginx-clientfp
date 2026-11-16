#!/usr/bin/env python3
"""Reference JA4 (TLS client) fingerprint implementation, per FoxIO's JA4.md:
https://github.com/FoxIO-LLC/ja4/blob/16b96d95c220762cf658f67d678cda2aac95c81e/technical_details/JA4.md

Works on the raw ClientHello *handshake message* (starts with 0x01 + 3-byte length) — exactly what
OpenSSL's msg_callback delivers — or on raw TLS records (0x16 ...) as captured from the wire.

    .venv/bin/python tools/ja4.py <hex>            # prints ja4, ja4_r, ja4_o, ja4_ro
    .venv/bin/python tools/ja4.py --selftest       # checks the worked examples from the spec
"""
import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass, field

EXT_SNI, EXT_SIGALGS, EXT_ALPN, EXT_SUPPORTED_VERSIONS = 0x0000, 0x000D, 0x0010, 0x002B

VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
            0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}


def is_grease(v):
    """RFC 8701: 0x0a0a, 0x1a1a, ... 0xfafa."""
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


@dataclass
class ClientHello:
    legacy_version: int
    ciphers: list                                   # u16, wire order, GREASE included
    extensions: list = field(default_factory=list)  # (type, data bytes), wire order, GREASE included

    def ext(self, t):
        return next((d for et, d in self.extensions if et == t), None)


def _u16s(b):
    return list(struct.unpack(f">{len(b) // 2}H", b[: len(b) // 2 * 2]))


def parse_client_hello(msg):
    """msg = full handshake message: type(1)=0x01, length(3), body."""
    if len(msg) < 4 or msg[0] != 1:
        raise ValueError("not a ClientHello handshake message")
    body = msg[4:4 + int.from_bytes(msg[1:4], "big")]
    p = 0
    legacy_version = int.from_bytes(body[p:p + 2], "big"); p += 2
    p += 32                                            # random
    p += 1 + body[p]                                   # session_id
    n = int.from_bytes(body[p:p + 2], "big"); p += 2
    ciphers = _u16s(body[p:p + n]); p += n
    p += 1 + body[p]                                   # compression_methods
    exts = []
    if p + 2 <= len(body):                             # extensions block is optional
        end = p + 2 + int.from_bytes(body[p:p + 2], "big"); p += 2
        while p + 4 <= end:
            t, ln = struct.unpack(">HH", body[p:p + 4]); p += 4
            exts.append((t, bytes(body[p:p + ln]))); p += ln
    return ClientHello(legacy_version, ciphers, exts)


def client_hello_from_records(data):
    """Reassemble the first ClientHello handshake message from TLS records (type 22). None if incomplete."""
    hs, p = b"", 0
    while p + 5 <= len(data):
        ctype, _ver, ln = struct.unpack(">BHH", data[p:p + 5])
        if ctype != 22:
            break
        hs += data[p + 5:p + 5 + ln]; p += 5 + ln
        if len(hs) >= 4 and len(hs) >= 4 + int.from_bytes(hs[1:4], "big"):
            return hs[:4 + int.from_bytes(hs[1:4], "big")]
    return None


def tls_version(ch):
    sv = ch.ext(EXT_SUPPORTED_VERSIONS)
    if sv is not None:
        vals = [v for v in _u16s(sv[1:1 + sv[0]]) if not is_grease(v)] if sv else []
        v = max(vals) if vals else ch.legacy_version   # spec silent on "only GREASE"; fall back
    else:
        v = ch.legacy_version
    return VERSIONS.get(v, "00")


def alpn_chars(ch):
    a = ch.ext(EXT_ALPN)
    if not a or len(a) < 3 or a[2] == 0:               # no ext / empty list / empty first value
        return "00"
    first = a[3:3 + a[2]]
    alnum = lambda b: 0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A
    if alnum(first[0]) and alnum(first[-1]):
        return chr(first[0]) + chr(first[-1])
    h = first.hex()                                    # non-alnum at either end -> hex of whole value
    return h[0] + h[-1]


def sigalgs(ch):
    s = ch.ext(EXT_SIGALGS)
    if not s or len(s) < 2:
        return []
    return [v for v in _u16s(s[2:2 + int.from_bytes(s[:2], "big")]) if not is_grease(v)]


def hash12(s):
    return hashlib.sha256(s.encode()).hexdigest()[:12] if s else "000000000000"


def ja4(ch, proto="t"):
    """proto: 't' TLS/TCP, 'q' QUIC, 'd' DTLS. Returns dict with ja4, ja4_r, ja4_o, ja4_ro and parts."""
    ciphers = [c for c in ch.ciphers if not is_grease(c)]
    exts = [t for t, _ in ch.extensions if not is_grease(t)]
    sni = "d" if EXT_SNI in exts else "i"
    a = f"{proto}{tls_version(ch)}{sni}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn_chars(ch)}"
    sig = ",".join(f"{v:04x}" for v in sigalgs(ch))

    def c_part(ext_list):
        s = ",".join(f"{v:04x}" for v in ext_list)
        if not s:
            return ""                                   # spec: no extensions -> 000000000000
        return f"{s}_{sig}" if sig else s

    b_sorted = ",".join(f"{v:04x}" for v in sorted(ciphers))
    c_sorted = c_part(sorted(t for t in exts if t not in (EXT_SNI, EXT_ALPN)))
    b_orig = ",".join(f"{v:04x}" for v in ciphers)
    c_orig = c_part(exts)                               # original order keeps SNI + ALPN
    return {
        "ja4": f"{a}_{hash12(b_sorted)}_{hash12(c_sorted)}",
        "ja4_r": f"{a}_{b_sorted}_{c_sorted}",
        "ja4_o": f"{a}_{hash12(b_orig)}_{hash12(c_orig)}",
        "ja4_ro": f"{a}_{b_orig}_{c_orig}",
        "a": a, "b_raw": b_sorted, "c_raw": c_sorted,
    }


def from_bytes(raw, proto="t"):
    msg = client_hello_from_records(raw) if raw[:1] == b"\x16" else raw
    if msg is None:
        raise ValueError("incomplete ClientHello")
    return ja4(parse_client_hello(msg), proto)


def selftest():
    """Worked examples from JA4.md."""
    assert hash12("002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9") == "8daaf6152771"
    ext = "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01"
    assert hash12(ext + "_0403,0804,0401,0503,0805,0501,0806,0601") == "e5627efa2ab1"
    assert hash12(ext) == "6d807ffa2a79"
    assert all(is_grease(0x0A0A + 0x1010 * i) for i in range(16)) and not is_grease(0x0A1A)

    def alpn(first):
        body = bytes([len(first)]) + first
        return alpn_chars(ClientHello(0x0303, [], [(EXT_ALPN, struct.pack(">H", len(body)) + body)]))
    cases = {b"h2": "h2", b"http/1.1": "h1", b"a": "aa", b"\xab": "ab", b"\x20": "20", b"\xab\xcd": "ad",
             b"\x20\x61": "21", b"\x30\xab": "3b", b"\x61\x20": "60", b"\x30\x31\xab\xcd": "3d",
             b"\x30\xab\xcd\x31": "01", b"": "00"}
    for v, want in cases.items():
        assert alpn(v) == want, (v, alpn(v), want)

    # Spec example ClientHello, rebuilt from its lists (GREASE sprinkled in to prove it is ignored)
    ciphers = [0x0A0A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014,
               0x009C, 0x009D, 0x002F, 0x0035]
    sig = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    alpn_ext = b"\x00\x0c\x02h2\x08http/1.1"
    exts = []
    for t in [0x3A3A, 0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D, 0x0005, 0x0023, 0x0012,
              0x002B, 0xFF01, 0x000B, 0x000A, 0x0015]:
        data = {0x000D: struct.pack(f">H{len(sig)}H", 2 * len(sig), *sig), 0x0010: alpn_ext,
                0x002B: b"\x06\x2a\x2a\x03\x04\x03\x03"}.get(t, b"")
        exts.append((t, data))
    r = ja4(ClientHello(0x0303, ciphers, exts))
    assert r["ja4"] == "t13d1516h2_8daaf6152771_e5627efa2ab1", r["ja4"]
    assert r["ja4_o"] == "t13d1516h2_acb858a92679_18f69afefd3d", r["ja4_o"]
    assert r["ja4_ro"] == ("t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_"
                           "001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015_"
                           "0403,0804,0401,0503,0805,0501,0806,0601"), r["ja4_ro"]
    print("selftest OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hex", nargs="?", help="ClientHello handshake message or TLS record(s), hex")
    ap.add_argument("--proto", default="t", choices="tqd")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest or not a.hex:
        return selftest()
    for k, v in from_bytes(bytes.fromhex(a.hex.strip()), a.proto).items():
        print(f"{k:7s} {v}")


if __name__ == "__main__":
    sys.exit(main())
