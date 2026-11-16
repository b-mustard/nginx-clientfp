"""Raw HTTP/2 probe: sends hand-crafted client frame sequences (SETTINGS / WINDOW_UPDATE / PRIORITY / HEADERS in an
exact order with exact values) and compares the fingerprint the server reports with the expected one.

Used to verify the Akamai HTTP/2 fingerprint rules (doc/http2_sig.md) against a reference endpoint
(https://kittens.sh/api/http2) or against our own nginx build.

    clientfp-h2-probe [--host kittens.sh] [--port 443] [--path /api/http2] [--case NAME|all] [--insecure]

The endpoint may answer with JSON containing "akamai_fingerprint" (kittens.sh), "akamai_text"
(tls.browserleaks.com/http2) or "h2" (thumbprint.me/api/v1/probe), or with the bare fingerprint string.

Every case's recorded expectation is also cross-checked against the local reference calculator
(clientfp.fp.h2); a disagreement there is a FAIL as well.
"""

from __future__ import annotations

import argparse
import gzip
import json
import socket
import ssl
import struct
from collections.abc import Sequence
from typing import Final, NamedTuple

from clientfp.fp import h2 as h2fp
from clientfp.fp.h2 import FLAG_ACK, FLAG_END_HEADERS, FLAG_END_STREAM, FLAG_PRIORITY, PREFACE, FrameType

FP_KEYS: Final = ("akamai_fingerprint", "akamai_text", "h2")
"""JSON key holding the fingerprint: kittens.sh, tls.browserleaks.com, thumbprint.me."""


# ---------------------------------------------------------------------------------------------------- frame builders


def frame(ftype: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return struct.pack(">I", len(payload))[1:] + struct.pack(">BBI", ftype, flags, stream_id & 0x7FFFFFFF) + payload


def settings(pairs: Sequence[tuple[int, int]]) -> bytes:
    return frame(FrameType.SETTINGS, 0, 0, b"".join(struct.pack(">HI", k, v) for k, v in pairs))


def window_update(increment: int, stream_id: int = 0) -> bytes:
    return frame(FrameType.WINDOW_UPDATE, 0, stream_id, struct.pack(">I", increment & 0x7FFFFFFF))


def prio_payload(dep: int, weight_wire: int, exclusive: int) -> bytes:
    return struct.pack(">IB", (dep & 0x7FFFFFFF) | (0x80000000 if exclusive else 0), weight_wire)


def priority(stream_id: int, dep: int, weight_wire: int, exclusive: int = 0) -> bytes:
    """weight_wire is the raw 0..255 octet (RFC 7540 weight = wire + 1)."""
    return frame(FrameType.PRIORITY, 0, stream_id, prio_payload(dep, weight_wire, exclusive))


def hpack_literal(name: str, value: str) -> bytes:
    """Literal Header Field without Indexing, new name, no Huffman (RFC 7541 6.2.2)."""
    def s(b: bytes) -> bytes:
        if len(b) >= 127:
            raise ValueError("hpack_literal handles strings shorter than 127 bytes only")
        return bytes([len(b)]) + b
    return b"\x00" + s(name.encode()) + s(value.encode())


def headers(stream_id: int, hdrs: Sequence[tuple[str, str]], prio: tuple[int, int, int] | None = None) -> bytes:
    """HEADERS with END_STREAM | END_HEADERS. prio = (depends_on, weight_wire, exclusive) sets the PRIORITY flag."""
    block = b"".join(hpack_literal(n, v) for n, v in hdrs)
    flags = FLAG_END_STREAM | FLAG_END_HEADERS
    if prio is not None:
        flags |= FLAG_PRIORITY
        block = prio_payload(*prio) + block
    return frame(FrameType.HEADERS, flags, stream_id, block)


def req_headers(host: str, path: str, order: str = "mpas", ua: str = "h2-probe/1.0") -> list[tuple[str, str]]:
    pseudo = {"m": (":method", "GET"), "p": (":path", path), "a": (":authority", host), "s": (":scheme", "https")}
    return [pseudo[c] for c in order] + [("user-agent", ua), ("accept", "*/*")]


# ---------------------------------------------------------------------------------------------------- transport


def text(body: bytes) -> str:
    # replayed real-client header blocks may ask for gzip
    return (gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body).decode(errors="replace")


def run(host: str, port: int, frames: Sequence[bytes], timeout: float = 10, insecure: bool = False) -> str:
    """Send the preface + `frames` over TLS (ALPN h2) and return the response body, or a `<...>` description of how
    the connection ended without one."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    with socket.create_connection((host, port), timeout=timeout) as raw, \
            ctx.wrap_socket(raw, server_hostname=host) as s:
        if s.selected_alpn_protocol() != "h2":
            raise RuntimeError(f"server selected ALPN {s.selected_alpn_protocol()!r}, not h2")
        s.sendall(PREFACE + b"".join(frames))
        buf, body, acked = b"", b"", False
        while True:
            while len(buf) < 9:
                chunk = s.recv(65536)
                if not chunk:
                    return text(body) or "<connection closed>"
                buf += chunk
            ln = int.from_bytes(buf[:3], "big")
            ftype, flags, sid = buf[3], buf[4], int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
            while len(buf) < 9 + ln:
                chunk = s.recv(65536)
                if not chunk:
                    return text(body) or "<connection closed>"
                buf += chunk
            payload, buf = buf[9:9 + ln], buf[9 + ln:]
            if ftype == FrameType.SETTINGS and not flags & FLAG_ACK and not acked:
                s.sendall(frame(FrameType.SETTINGS, FLAG_ACK, 0))
                acked = True
            elif ftype == FrameType.DATA:
                body += payload
                if flags & FLAG_END_STREAM:
                    return text(body)
            elif ftype == FrameType.HEADERS and flags & FLAG_END_STREAM:
                return text(body) or "<headers only, END_STREAM>"
            elif ftype == FrameType.GOAWAY:
                last, code = struct.unpack(">II", payload[:8])
                if code:  # NO_ERROR = graceful shutdown notice, the in-flight response still follows
                    return f"<GOAWAY last={last & 0x7FFFFFFF} err={code} {payload[8:]!r}>"
            elif ftype == FrameType.RST_STREAM:
                return f"<RST_STREAM sid={sid} err={struct.unpack('>I', payload)[0]}>"


def fingerprint_from_body(body: str) -> str | None:
    """The fingerprint from a JSON response (first of FP_KEYS present; None if that field is null or not a string),
    or the stripped body itself if it is not a JSON object with one of those keys."""
    try:
        j = json.loads(body)
    except ValueError:
        return body.strip()
    if isinstance(j, dict):
        for k in FP_KEYS:
            if k in j:
                v = j[k]
                return v if isinstance(v, str) else None
    return body.strip()


# ---------------------------------------------------------------------------------------------------- cases


class ProbeCase(NamedTuple):
    frames: list[bytes]
    """Frames sent after the preface."""
    expected: str
    """Fingerprint recorded from kittens.sh/api/http2."""


FIREFOX_PRIO: Final = [(3, 0, 200, 0), (5, 0, 100, 0), (7, 0, 0, 0), (9, 7, 0, 0), (11, 3, 0, 0)]


def cases(host: str, path: str) -> dict[str, ProbeCase]:
    """name -> (frames, expected Akamai fingerprint). Expectations verified against kittens.sh/api/http2."""
    def hdr(order: str = "mpas", sid: int = 1, prio: tuple[int, int, int] | None = None) -> bytes:
        return headers(sid, req_headers(host, path, order), prio)

    ff = "3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1"
    c = ProbeCase
    return {
        # Paper example 5 (Firefox 53)
        "paper_firefox": c([settings([(1, 65536), (4, 131072), (5, 16384)]), window_update(12517377),
                            *[priority(*p) for p in FIREFOX_PRIO], hdr("mpas", 13)],
                           f"1:65536;4:131072;5:16384|12517377|{ff}|m,p,a,s"),
        # Paper example 1 (Chrome 58) with Chrome pseudo-header order
        "paper_chrome58": c([settings([(1, 65536), (3, 1000), (4, 6291456)]), window_update(15663105), hdr("masp")],
                            "1:65536;3:1000;4:6291456|15663105|0|m,a,s,p"),
        # No WINDOW_UPDATE at all -> "00"
        "no_window_update": c([settings([(3, 100), (4, 65535)]), hdr("mpsa")], "3:100;4:65535|00|0|m,p,s,a"),
        # Empty SETTINGS frame -> empty S field
        "empty_settings": c([settings([]), window_update(1000), hdr()], "|1000|0|m,p,a,s"),
        # Wire order is preserved (not sorted)
        "settings_order": c([settings([(4, 65535), (1, 4096), (3, 100)]), window_update(1000), hdr()],
                            "4:65535;1:4096;3:100|1000|0|m,p,a,s"),
        # Unknown / newer ids (8 ENABLE_CONNECT_PROTOCOL, 9 NO_RFC7540_PRIORITIES, GREASE 0x0a0a) kept, decimal
        "unknown_settings": c([settings([(1, 65536), (8, 1), (9, 1), (0x0A0A, 12345)]), window_update(1000), hdr()],
                              "1:65536;8:1;9:1;2570:12345|1000|0|m,p,a,s"),
        # Duplicate id inside one frame -> both kept. Tolerance case: strict servers (browserleaks) send PROTOCOL_ERROR
        "dup_setting": c([settings([(1, 4096), (1, 65536)]), window_update(1000), hdr()],
                         "1:4096;1:65536|1000|0|m,p,a,s"),
        # Values are unsigned 32-bit
        "u32_setting_values": c([settings([(6, 0xFFFFFFFF), (1, 0)]), window_update(1000), hdr()],
                                "6:4294967295;1:0|1000|0|m,p,a,s"),
        # Only the FIRST SETTINGS frame that carries parameters is used (empty frames / ACKs are skipped)
        "two_settings_frames": c([settings([(1, 65536)]), settings([(4, 131072)]), window_update(1000), hdr()],
                                 "1:65536|1000|0|m,p,a,s"),
        "empty_then_full_settings": c([settings([]), settings([(1, 65536)]), window_update(1000), hdr()],
                                      "1:65536|1000|0|m,p,a,s"),
        "settings_ack_then_full": c([frame(FrameType.SETTINGS, FLAG_ACK, 0), settings([(1, 65536)]),
                                     window_update(1000), hdr()],
                                    "1:65536|1000|0|m,p,a,s"),
        # SETTINGS arriving after the first HEADERS is not captured
        "settings_after_headers": c([settings([]), window_update(1000), hdr(), settings([(1, 65536)])],
                                    "|1000|0|m,p,a,s"),
        # Only the FIRST connection-level WINDOW_UPDATE is used (not last, not sum)
        "two_window_updates": c([settings([(1, 65536)]), window_update(1000), window_update(2000), hdr()],
                                "1:65536|1000|0|m,p,a,s"),
        # Stream-level WINDOW_UPDATE (stream != 0) is ignored. NB: idle stream -> RFC says PROTOCOL_ERROR,
        # tolerance case only.
        "stream_wu_before_conn_wu": c([settings([(1, 65536)]), window_update(5000, 3), window_update(1000), hdr()],
                                      "1:65536|1000|0|m,p,a,s"),
        "stream_wu_only": c([settings([(1, 65536)]), window_update(5000, 3), hdr()], "1:65536|00|0|m,p,a,s"),
        # Reserved (top) bit of the increment is masked off
        "wu_reserved_bit": c([settings([(1, 65536)]),
                              frame(FrameType.WINDOW_UPDATE, 0, 0, struct.pack(">I", 0x80000000 | 1000)), hdr()],
                             "1:65536|1000|0|m,p,a,s"),
        # PRIORITY flag inside HEADERS is NOT part of P
        "headers_prio_flag": c([settings([(1, 65536)]), window_update(1000), hdr("masp", 1, (0, 255, 1))],
                               "1:65536|1000|0|m,a,s,p"),
        # Exclusive bit -> 1, weight = wire + 1 (255 -> 256)
        "prio_exclusive": c([settings([(1, 65536)]), window_update(1000), priority(3, 0, 255, 1), hdr("masp", 5)],
                            "1:65536|1000|3:1:0:256|m,a,s,p"),
        # Capture stops at the first HEADERS frame
        "prio_after_headers": c([settings([(1, 65536)]), window_update(1000), hdr(), priority(3, 0, 10)],
                                "1:65536|1000|0|m,p,a,s"),
        # PRIORITY position relative to WINDOW_UPDATE does not matter
        "prio_before_wu": c([settings([(1, 65536)]), priority(3, 0, 200), window_update(1000), hdr("mpas", 5)],
                            "1:65536|1000|3:0:0:201|m,p,a,s"),
        # Absent pseudo-header (:authority replaced by Host) -> just omitted from PS
        "no_authority": c([settings([(1, 65536)]), window_update(1000),
                           headers(1, [(":method", "GET"), (":scheme", "https"), (":path", path), ("host", host),
                                       ("user-agent", "h2-probe/1.0")])],
                          "1:65536|1000|0|m,s,p"),
    }


def calculated(case: ProbeCase) -> str:
    """The fingerprint the local reference calculator gives for a case's frames."""
    return h2fp.compute(PREFACE + b"".join(case.frames)).fingerprint


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="clientfp-h2-probe",
                                 description="Send synthetic HTTP/2 frame sequences, compare the reported fingerprint")
    ap.add_argument("--host", default="kittens.sh")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--path", default="/api/http2")
    ap.add_argument("--case", default="all")
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate verification (local nginx)")
    a = ap.parse_args(argv)
    failed = 0
    for name, case in cases(a.host, a.path).items():
        if a.case not in ("all", name):
            continue
        out: str | None
        try:
            out = fingerprint_from_body(run(a.host, a.port, case.frames, insecure=a.insecure))
        except Exception as e:  # noqa: BLE001  (report every transport failure as this case's result)
            out = f"<error {type(e).__name__}: {e}>"
        local = calculated(case)
        ok = out == case.expected and local == case.expected
        failed += not ok
        shown = out if out is not None else "<null fingerprint>"
        print(f"{'PASS' if ok else 'FAIL'} {name:26s} {shown}")
        if out != case.expected:
            print(f"     {'expected':26s} {case.expected}")
        if local != case.expected:
            print(f"     {'local calculator':26s} {local}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
