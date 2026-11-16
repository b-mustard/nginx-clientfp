#!/usr/bin/env python3
"""Raw HTTP/2 probe: sends a hand-crafted client preface (SETTINGS / WINDOW_UPDATE /
PRIORITY / HEADERS in exact order and values) and prints the response body.

Used to verify the Akamai HTTP/2 fingerprint rules against a reference endpoint
(https://kittens.sh/api/http2) or against our own nginx build.

    .venv/bin/python tools/h2_probe.py [--host kittens.sh] [--path /api/http2] [--case NAME|all] [--insecure]

The endpoint may answer with JSON containing "akamai_fingerprint" (kittens.sh), "akamai_text"
(tls.browserleaks.com/http2) or "h2" (thumbprint.me/api/v1/probe), or with the bare fingerprint string.
"""
import argparse
import gzip
import json
import socket
import ssl
import struct

# JSON key holding the fingerprint: kittens.sh, tls.browserleaks.com, thumbprint.me
FP_KEYS = ("akamai_fingerprint", "akamai_text", "h2")
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = range(10)
FLAG_END_STREAM, FLAG_ACK, FLAG_END_HEADERS, FLAG_PRIORITY = 0x1, 0x1, 0x4, 0x20


def frame(ftype, flags, stream_id, payload=b""):
    return struct.pack(">I", len(payload))[1:] + struct.pack(">BBI", ftype, flags, stream_id & 0x7FFFFFFF) + payload


def settings(pairs):
    return frame(SETTINGS, 0, 0, b"".join(struct.pack(">HI", k, v) for k, v in pairs))


def window_update(increment, stream_id=0):
    return frame(WINDOW_UPDATE, 0, stream_id, struct.pack(">I", increment & 0x7FFFFFFF))


def prio_payload(dep, weight_wire, exclusive):
    return struct.pack(">IB", (dep & 0x7FFFFFFF) | (0x80000000 if exclusive else 0), weight_wire)


def priority(stream_id, dep, weight_wire, exclusive=0):
    """weight_wire is the raw 0..255 octet (RFC 7540 weight = wire + 1)."""
    return frame(PRIORITY, 0, stream_id, prio_payload(dep, weight_wire, exclusive))


def hpack_literal(name, value):
    # Literal Header Field without Indexing, new name, no Huffman (RFC 7541 6.2.2)
    def s(b):
        assert len(b) < 127
        return bytes([len(b)]) + b
    return b"\x00" + s(name.encode()) + s(value.encode())


def headers(stream_id, hdrs, prio=None):
    block = b"".join(hpack_literal(n, v) for n, v in hdrs)
    flags = FLAG_END_STREAM | FLAG_END_HEADERS
    if prio is not None:
        flags |= FLAG_PRIORITY
        block = prio_payload(*prio) + block
    return frame(HEADERS, flags, stream_id, block)


def req_headers(host, path, order="mpas", ua="h2-probe/1.0"):
    pseudo = {"m": (":method", "GET"), "p": (":path", path), "a": (":authority", host), "s": (":scheme", "https")}
    return [pseudo[c] for c in order] + [("user-agent", ua), ("accept", "*/*")]


def text(body):
    # replayed real-client header blocks may ask for gzip
    return (gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body).decode(errors="replace")


def run(host, port, frames, timeout=10, insecure=False):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
        assert s.selected_alpn_protocol() == "h2", s.selected_alpn_protocol()
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
            if ftype == SETTINGS and not flags & FLAG_ACK and not acked:
                s.sendall(frame(SETTINGS, FLAG_ACK, 0))
                acked = True
            elif ftype == DATA:
                body += payload
                if flags & FLAG_END_STREAM:
                    return text(body)
            elif ftype == HEADERS and flags & FLAG_END_STREAM:
                return text(body) or "<headers only, END_STREAM>"
            elif ftype == GOAWAY:
                last, code = struct.unpack(">II", payload[:8])
                if code:  # NO_ERROR = graceful shutdown notice, the in-flight response still follows
                    return f"<GOAWAY last={last & 0x7FFFFFFF} err={code} {payload[8:]!r}>"
            elif ftype == RST_STREAM:
                return f"<RST_STREAM sid={sid} err={struct.unpack('>I', payload)[0]}>"


FIREFOX_PRIO = [(3, 0, 200, 0), (5, 0, 100, 0), (7, 0, 0, 0), (9, 7, 0, 0), (11, 3, 0, 0)]


def cases(host, path):
    """name -> (frames, expected akamai fingerprint). Expectations verified against kittens.sh/api/http2."""
    H = lambda order="mpas", sid=1, prio=None: headers(sid, req_headers(host, path, order), prio)
    ff = "3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1"
    return {
        # Paper example 5 (Firefox 53)
        "paper_firefox": ([settings([(1, 65536), (4, 131072), (5, 16384)]), window_update(12517377),
                           *[priority(*p) for p in FIREFOX_PRIO], H("mpas", 13)],
                          f"1:65536;4:131072;5:16384|12517377|{ff}|m,p,a,s"),
        # Paper example 1 (Chrome 58) with Chrome pseudo-header order
        "paper_chrome58": ([settings([(1, 65536), (3, 1000), (4, 6291456)]), window_update(15663105), H("masp")],
                           "1:65536;3:1000;4:6291456|15663105|0|m,a,s,p"),
        # No WINDOW_UPDATE at all -> "00"
        "no_window_update": ([settings([(3, 100), (4, 65535)]), H("mpsa")], "3:100;4:65535|00|0|m,p,s,a"),
        # Empty SETTINGS frame -> empty S field
        "empty_settings": ([settings([]), window_update(1000), H()], "|1000|0|m,p,a,s"),
        # Wire order is preserved (not sorted)
        "settings_order": ([settings([(4, 65535), (1, 4096), (3, 100)]), window_update(1000), H()],
                           "4:65535;1:4096;3:100|1000|0|m,p,a,s"),
        # Unknown / newer ids (8 ENABLE_CONNECT_PROTOCOL, 9 NO_RFC7540_PRIORITIES, GREASE 0x0a0a) kept, decimal
        "unknown_settings": ([settings([(1, 65536), (8, 1), (9, 1), (0x0A0A, 12345)]), window_update(1000), H()],
                             "1:65536;8:1;9:1;2570:12345|1000|0|m,p,a,s"),
        # Duplicate id inside one frame -> both kept. Tolerance case: strict servers (browserleaks) send PROTOCOL_ERROR
        "dup_setting": ([settings([(1, 4096), (1, 65536)]), window_update(1000), H()],
                        "1:4096;1:65536|1000|0|m,p,a,s"),
        # Values are unsigned 32-bit
        "u32_setting_values": ([settings([(6, 0xFFFFFFFF), (1, 0)]), window_update(1000), H()],
                               "6:4294967295;1:0|1000|0|m,p,a,s"),
        # Only the FIRST SETTINGS frame that carries parameters is used (empty frames / ACKs are skipped)
        "two_settings_frames": ([settings([(1, 65536)]), settings([(4, 131072)]), window_update(1000), H()],
                                "1:65536|1000|0|m,p,a,s"),
        "empty_then_full_settings": ([settings([]), settings([(1, 65536)]), window_update(1000), H()],
                                     "1:65536|1000|0|m,p,a,s"),
        "settings_ack_then_full": ([frame(SETTINGS, FLAG_ACK, 0), settings([(1, 65536)]), window_update(1000), H()],
                                   "1:65536|1000|0|m,p,a,s"),
        # SETTINGS arriving after the first HEADERS is not captured
        "settings_after_headers": ([settings([]), window_update(1000), H(), settings([(1, 65536)])],
                                   "|1000|0|m,p,a,s"),
        # Only the FIRST connection-level WINDOW_UPDATE is used (not last, not sum)
        "two_window_updates": ([settings([(1, 65536)]), window_update(1000), window_update(2000), H()],
                               "1:65536|1000|0|m,p,a,s"),
        # Stream-level WINDOW_UPDATE (stream != 0) is ignored. NB: idle stream -> RFC says PROTOCOL_ERROR,
        # tolerance case only.
        "stream_wu_before_conn_wu": ([settings([(1, 65536)]), window_update(5000, 3), window_update(1000), H()],
                                     "1:65536|1000|0|m,p,a,s"),
        "stream_wu_only": ([settings([(1, 65536)]), window_update(5000, 3), H()], "1:65536|00|0|m,p,a,s"),
        # Reserved (top) bit of the increment is masked off
        "wu_reserved_bit": ([settings([(1, 65536)]), frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", 0x80000000 | 1000)),
                             H()], "1:65536|1000|0|m,p,a,s"),
        # PRIORITY flag inside HEADERS is NOT part of P
        "headers_prio_flag": ([settings([(1, 65536)]), window_update(1000), H("masp", 1, (0, 255, 1))],
                              "1:65536|1000|0|m,a,s,p"),
        # Exclusive bit -> 1, weight = wire + 1 (255 -> 256)
        "prio_exclusive": ([settings([(1, 65536)]), window_update(1000), priority(3, 0, 255, 1), H("masp", 5)],
                           "1:65536|1000|3:1:0:256|m,a,s,p"),
        # Capture stops at the first HEADERS frame
        "prio_after_headers": ([settings([(1, 65536)]), window_update(1000), H(), priority(3, 0, 10)],
                               "1:65536|1000|0|m,p,a,s"),
        # PRIORITY position relative to WINDOW_UPDATE does not matter
        "prio_before_wu": ([settings([(1, 65536)]), priority(3, 0, 200), window_update(1000), H("mpas", 5)],
                           "1:65536|1000|3:0:0:201|m,p,a,s"),
        # Absent pseudo-header (:authority replaced by Host) -> just omitted from PS
        "no_authority": ([settings([(1, 65536)]), window_update(1000),
                          headers(1, [(":method", "GET"), (":scheme", "https"), (":path", path), ("host", host),
                                      ("user-agent", "h2-probe/1.0")])],
                         "1:65536|1000|0|m,s,p"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="kittens.sh")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--path", default="/api/http2")
    ap.add_argument("--case", default="all")
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate verification (local nginx)")
    a = ap.parse_args()
    all_cases = cases(a.host, a.path)
    failed = 0
    for name, (frames, expected) in all_cases.items():
        if a.case not in ("all", name):
            continue
        try:
            out = run(a.host, a.port, frames, insecure=a.insecure)
            try:  # reference API returns JSON; our nginx endpoint may return the bare fingerprint string
                j = json.loads(out)
                out = next(j[k] for k in FP_KEYS if k in j)
            except (ValueError, KeyError, TypeError, StopIteration):
                out = out.strip()
        except Exception as e:  # noqa: BLE001
            out = f"<error {type(e).__name__}: {e}>"
        ok = out == expected
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'} {name:26s} {out}" + ("" if ok else f"\n     {'expected':26s} {expected}"))
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
