"""Impossible and malicious input against a running nginx (t3).

Every test runs against the installed package and, when `./build.sh asan` has been run, against the ASan/UBSan
build (NGX_DEBUG_PALLOC: every pool allocation is its own malloc). After each test the server must still answer and
must have no crashed worker and no sanitizer report.

HTTP/2 traffic uses cleartext prior knowledge (h2c) so the frame bytes and their TCP segmentation are exactly what the
test writes; TLS traffic uses raw records so hellos can be malformed.
"""

from __future__ import annotations

import json
import random
import socket
import struct
import time
from collections.abc import Iterator, Sequence

import hpack
import pytest

from clientfp.fp import h2 as ref_h2
from clientfp.probe import h2_probe as hp

from ..conftest import REPO
from .conftest import Nginx

pytestmark = [pytest.mark.nginx, pytest.mark.docker]

F = ref_h2.FrameType
END_STREAM, END_HEADERS, PADDED, PRIORITY_FLAG = 0x1, 0x4, 0x8, 0x20


@pytest.fixture(params=["pkg", "asan"])
def srv(request: pytest.FixtureRequest) -> Iterator[Nginx]:
    n: Nginx = request.getfixturevalue(f"nginx_{request.param}")
    offset = mark_logs(n)
    yield n
    assert_healthy(n, offset)


def mark_logs(n: Nginx) -> int:
    """Set earlier sanitizer reports aside and return the current error-log size, so a test is judged only by what
    happens during it (a crashed worker is replaced by the master, later tests stay meaningful)."""
    out = n.exec("sh", "-c", "mkdir -p /tmp/seen; mv /tmp/asan.* /tmp/ubsan.* /tmp/seen/ 2>/dev/null; "
                 f"cat {n.logs} 2>/dev/null | wc -c", check=False)
    return int(out.split()[-1])


def assert_healthy(n: Nginx, offset: int = 0) -> None:
    assert n.alive(), "nginx stopped answering"
    report = n.exec("sh", "-c", "cat /tmp/asan.* /tmp/ubsan.* 2>/dev/null; "
                    f"cat {n.logs} 2>/dev/null | tail -c +{offset + 1} | "
                    "grep -h 'exited on signal\\|runtime error\\|AddressSanitizer'", check=False)
    assert report.strip() == "", report[-4000:]


# ------------------------------------------------------------------------------------------------- raw HTTP/2


def _recv_frames(s: socket.socket, timeout: float) -> Iterator[tuple[int, int, int, bytes]]:
    s.settimeout(timeout)
    buf = b""
    while True:
        while len(buf) >= 9 and len(buf) >= 9 + int.from_bytes(buf[:3], "big"):
            n = int.from_bytes(buf[:3], "big")
            yield buf[3], buf[4], int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF, buf[9:9 + n]
            buf = buf[9 + n:]
        try:
            chunk = s.recv(65536)
        except (TimeoutError, ConnectionResetError):
            return
        if not chunk:
            return
        buf += chunk


class Outcome:
    def __init__(self) -> None:
        self.status: str | None = None
        self.body = b""
        self.goaway: int | None = None
        self.rst: int | None = None

    def __repr__(self) -> str:
        return f"Outcome(status={self.status}, goaway={self.goaway}, rst={self.rst}, body={self.body[:200]!r})"


def h2_exchange(port: int, data: bytes, chunks: Sequence[int] = (), delay: float = 0.0, sid: int = 1,
                timeout: float = 10, close_early: bool = False) -> Outcome:
    """Send `data` (client preface included) over h2c, split at `chunks` sizes (cycled) with `delay` between writes,
    then read until stream `sid` ends, GOAWAY, or the connection closes."""
    out = Outcome()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if chunks:
            p, i = 0, 0
            while p < len(data):
                n = chunks[i % len(chunks)]
                s.sendall(data[p:p + n])
                p, i = p + n, i + 1
                if delay:
                    time.sleep(delay)
        else:
            s.sendall(data)
        if close_early:
            return out
        dec = hpack.Decoder()
        for ftype, flags, fsid, payload in _recv_frames(s, timeout):
            if ftype == F.GOAWAY:
                out.goaway = int.from_bytes(payload[4:8], "big")
                break
            if ftype == F.HEADERS:                  # decode every block: the HPACK table is per connection
                fields = dec.decode(payload, raw=True)
                if fsid == sid:
                    out.status = dict(fields).get(b":status", b"?").decode()
            if fsid != sid:
                continue
            if ftype == F.DATA:
                out.body += payload
            elif ftype == F.RST_STREAM:
                out.rst = int.from_bytes(payload, "big")
                break
            if flags & END_STREAM:
                break
    return out


def req(path: str, sid: int = 1, order: str = "mpas") -> bytes:
    return hp.headers(sid, hp.req_headers("localhost", path, order))


def fp_of(o: Outcome) -> dict[str, str]:
    assert o.status == "200", o
    data: dict[str, str] = json.loads(o.body)
    return data


def test_h2_segmented_everywhere(srv: Nginx) -> None:
    """Every frame type we hook, split at every possible point across TCP segments (nginx's state_save paths,
    including the PRIORITY parsing the 1.31 patch adds). The result must equal the reference calculator's."""
    block = hpack.Encoder().encode(hp.req_headers("localhost", "/fp", "msap"))
    frames = [
        hp.settings([(1, 65536), (2, 0), (4, 6291456), (6, 262144), (0x0A0A, 7)]),
        hp.frame(F.SETTINGS, 0x1, 0),
        hp.window_update(15663105),
        hp.window_update(77),
        *[hp.priority(sid, dep, w, e) for sid, dep, w, e in hp.FIREFOX_PRIO],
        hp.frame(F.HEADERS, END_STREAM, 13, block[:3]),
        hp.frame(F.CONTINUATION, 0, 13, block[3:5]),
        hp.frame(F.CONTINUATION, END_HEADERS, 13, block[5:]),
    ]
    stream = ref_h2.PREFACE + b"".join(frames)
    want = ref_h2.compute(stream)
    rng = random.Random(7)
    for chunks in ([1], [2, 3], [5, 1, 9], [rng.randint(1, 13) for _ in range(40)]):
        got = fp_of(h2_exchange(srv.h2c, stream, chunks, delay=0.0005, sid=13))
        assert (got["akamai_fingerprint"], got["akamai_fingerprint_hash"], got["overflow"]) == \
            (want.fingerprint, want.hash, "0"), chunks


def test_h2_padded_headers_with_priority(srv: Nginx) -> None:
    block = hpack.Encoder().encode(hp.req_headers("localhost", "/fp", "spam"))
    pad = 200
    payload = bytes([pad]) + struct.pack(">IB", 0x80000000 | 3, 41) + block + bytes(pad)
    stream = ref_h2.PREFACE + hp.settings([(3, 100)]) + hp.frame(
        F.HEADERS, END_STREAM | END_HEADERS | PADDED | PRIORITY_FLAG, 1, payload)
    got = fp_of(h2_exchange(srv.h2c, stream))
    assert got["akamai_fingerprint"] == ref_h2.compute(stream).fingerprint == "3:100|00|0|s,p,a,m"


def test_h2_largest_settings_frame(srv: Nginx) -> None:
    """2730 parameters, the most a 16384-octet frame holds; ids nginx ignores. Recorded: 32, overflow set."""
    pairs = [(0x100 + i, 0xFFFFFFFF - i) for i in range(16384 // 6)]
    stream = ref_h2.PREFACE + hp.settings(pairs) + req("/fp")
    got = fp_of(h2_exchange(srv.h2c, stream))
    want = ref_h2.compute(stream)
    assert got["overflow"] == "1" and want.overflow
    assert got["akamai_fingerprint"] == want.fingerprint
    assert got["akamai_fingerprint"].split("|")[0].count(";") == 31


def test_h2_settings_flood_frames(srv: Nginx) -> None:
    """Many SETTINGS frames: only the first non-empty one is recorded; nginx may refuse the flood itself."""
    stream = ref_h2.PREFACE + hp.settings([(3, 7)]) + hp.settings([(4, 65535)] * 100) * 300 + req("/fp")
    o = h2_exchange(srv.h2c, stream)
    if o.status is not None:
        assert fp_of(o)["akamai_fingerprint"].startswith("3:7|")
    else:
        assert o.goaway is not None


def test_h2_priority_flood(srv: Nginx) -> None:
    """20000 PRIORITY frames before the request: 32 recorded, overflow set (or the connection refused by nginx's
    own flood limit, nginx 1.30); memory use must not grow with the count."""
    rng = random.Random(3)
    prios = b"".join(hp.priority(rng.randrange(1, 1 << 31), rng.randrange(1 << 31), rng.randrange(256),
                                 rng.randrange(2)) for _ in range(20000))
    stream = ref_h2.PREFACE + hp.settings([(1, 4096)]) + prios + req("/fp", sid=1)
    o = h2_exchange(srv.h2c, stream)
    if o.status is None:
        assert o.goaway is not None, o
        return
    got, want = fp_of(o), ref_h2.compute(stream)
    assert got["overflow"] == "1"
    assert got["akamai_fingerprint"] == want.fingerprint
    assert got["akamai_fingerprint"].split("|")[2].count(",") == 31


def test_h2_continuation_flood(srv: Nginx) -> None:
    """A header block in 1-octet CONTINUATION frames (CVE-2024-27316 shape); it ends, the request is served."""
    block = hpack.Encoder().encode(hp.req_headers("localhost", "/fp", "apsm") + [("x-pad", "a" * 600)])
    frames = [hp.frame(F.HEADERS, END_STREAM, 1, block[:1])]
    frames += [hp.frame(F.CONTINUATION, 0, 1, block[i:i + 1]) for i in range(1, len(block) - 1)]
    frames += [hp.frame(F.CONTINUATION, END_HEADERS, 1, block[-1:])]
    stream = ref_h2.PREFACE + hp.settings([(1, 4096)]) + b"".join(frames)
    o = h2_exchange(srv.h2c, stream)
    if o.status is not None:
        assert fp_of(o)["akamai_fingerprint"] == ref_h2.compute(stream).fingerprint == "1:4096|00|0|a,p,s,m"
    else:
        assert o.goaway is not None


def test_h2_endless_continuation(srv: Nginx) -> None:
    """CONTINUATION frames that never end the block: nginx must cut the connection (header size limits)."""
    frames = [hp.frame(F.HEADERS, 0, 1, hpack.Encoder().encode([(":method", "GET")]))]
    frames += [hp.frame(F.CONTINUATION, 0, 1, b"\x40\x03x-a\x03aaa")] * 20000
    o = h2_exchange(srv.h2c, ref_h2.PREFACE + hp.settings([(1, 4096)]) + b"".join(frames), timeout=15)
    assert o.status != "200", o


ODD_PSEUDO: list[list[tuple[bytes, bytes]]] = [
    [(b":", b"x"), (b":method", b"GET"), (b":path", b"/fp"), (b":scheme", b"http")],
    [(b":methodx", b"GET"), (b":method", b"GET"), (b":path", b"/fp"), (b":scheme", b"http")],
    [(b":METHOD", b"GET"), (b":path", b"/fp"), (b":scheme", b"http")],
    [(b":method", b"GET"), (b":method", b"POST"), (b":path", b"/fp"), (b":scheme", b"http")],
    [(b":method", b"GET"), (b":path", b"/fp"), (b":scheme", b"http"), (b"x", b"1"), (b":authority", b"h")],
    [(b":" + b"a" * 8000, b"v"), (b":method", b"GET"), (b":path", b"/fp"), (b":scheme", b"http")],
    [(b":method", b"\x00\xff" * 100), (b":path", b"/fp"), (b":scheme", b"http")],
    [(b":path", b"/fp")],
    [],
]


@pytest.mark.parametrize("hdrs", ODD_PSEUDO, ids=range(len(ODD_PSEUDO)))
def test_h2_odd_pseudo_headers(srv: Nginx, hdrs: list[tuple[bytes, bytes]]) -> None:
    """Pseudo-header blocks nginx must reject (400 / stream or connection error); the hook sees the names first."""
    enc = hpack.Encoder()
    block = enc.encode(hdrs, huffman=False) if hdrs else b""
    stream = ref_h2.PREFACE + hp.settings([(1, 4096)]) + hp.frame(F.HEADERS, END_STREAM | END_HEADERS, 1, block)
    o = h2_exchange(srv.h2c, stream)
    if o.status == "200":                         # accepted after all: the value must still be the reference's
        assert fp_of(o)["akamai_fingerprint"] == ref_h2.compute(stream).fingerprint


BAD_STREAMS: dict[str, bytes] = {
    "priority_len4": hp.frame(F.PRIORITY, 0, 3, b"\0\0\0\0"),
    "priority_len6": hp.frame(F.PRIORITY, 0, 3, b"\0\0\0\0\0\0"),
    "priority_len0": hp.frame(F.PRIORITY, 0, 3, b""),
    "priority_sid0": hp.frame(F.PRIORITY, 0, 0, b"\0\0\0\0\0"),
    "priority_self": hp.priority(3, 3, 0),
    "settings_len5": hp.frame(F.SETTINGS, 0, 0, b"\0\x01\0\0\0"),
    "settings_ack_payload": hp.frame(F.SETTINGS, 0x1, 0, b"\0\x01\0\0\0\0"),
    "settings_on_stream": hp.frame(F.SETTINGS, 0, 1, b"\0\x01\0\0\0\0"),
    "settings_bad_window": hp.settings([(4, 0x80000000)]),
    "settings_bad_frame_size": hp.settings([(5, 1)]),
    "wu_len3": hp.frame(F.WINDOW_UPDATE, 0, 0, b"\0\0\1"),
    "wu_zero": hp.window_update(0),
    "wu_overflow": hp.window_update(0x7FFFFFFF) + hp.window_update(0x7FFFFFFF),
    "headers_pad_too_long": hp.frame(F.HEADERS, END_HEADERS | PADDED, 1, b"\xff" + b"\x82"),
    "headers_prio_truncated": hp.frame(F.HEADERS, END_HEADERS | PRIORITY_FLAG, 1, b"\0\0"),
    "headers_sid0": hp.frame(F.HEADERS, END_HEADERS, 0, b"\x82"),
    "headers_even_sid": hp.frame(F.HEADERS, END_HEADERS, 2, b"\x82"),
    "continuation_orphan": hp.frame(F.CONTINUATION, END_HEADERS, 1, b"\x82"),
    "continuation_other_stream": hp.frame(F.HEADERS, 0, 1, b"\x82") + hp.frame(F.CONTINUATION, END_HEADERS, 3, b"\x84"),
    "interleaved_in_block": hp.frame(F.HEADERS, 0, 1, b"\x82") + hp.priority(3, 0, 1)
    + hp.frame(F.CONTINUATION, END_HEADERS, 1, b"\x84"),
    "hpack_garbage": hp.frame(F.HEADERS, END_HEADERS, 1, bytes(range(256))),
    "hpack_index_oob": hp.frame(F.HEADERS, END_HEADERS, 1, b"\xff\xff\xff\xff\x0f"),
    "hpack_table_size_huge": hp.frame(F.HEADERS, END_HEADERS, 1, b"\x3f\xe1\xff\xff\xff\x0f\x82"),
    "push_promise": hp.frame(F.PUSH_PROMISE, END_HEADERS, 1, b"\0\0\0\2\x82"),
    "huge_frame_len": b"\xff\xff\xff\x01\x04\0\0\0\x01",
    "unknown_type": hp.frame(0xEE, 0xFF, 7, b"x" * 100),
}


@pytest.mark.parametrize("name", list(BAD_STREAMS))
def test_h2_protocol_violations(srv: Nginx, name: str) -> None:
    """Malformed frames around the hooks: nginx answers with an error or closes; nothing else may happen."""
    stream = ref_h2.PREFACE + hp.settings([(1, 4096)]) + hp.window_update(1000) + BAD_STREAMS[name] + req("/fp", 5)
    o = h2_exchange(srv.h2c, stream, sid=5, timeout=5)
    if name == "unknown_type":                      # ignored by RFC 9113: the request after it is served
        assert fp_of(o)["akamai_fingerprint"] == "1:4096|1000|0|m,p,a,s"


@pytest.mark.parametrize("cut", [1, 10, 24, 30, 33, 36, 40, 50, 60, 65])
def test_h2_connection_dropped_mid_frame(srv: Nginx, cut: int) -> None:
    """The client vanishes inside a frame (state saved for the next read, then the connection is freed)."""
    stream = (ref_h2.PREFACE + hp.settings([(1, 4096)]) + hp.priority(3, 0, 7) + hp.window_update(9)
              + req("/fp"))
    h2_exchange(srv.h2c, stream[:cut], close_early=True)
    with socket.create_connection(("127.0.0.1", srv.h2c)) as s:   # and with RST instead of FIN
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.sendall(stream[:cut])
        time.sleep(0.05)


def test_h2_many_connections_after_flood(srv: Nginx) -> None:
    """State lives in the connection pool: after floods, ordinary connections still get exact results."""
    stream = ref_h2.PREFACE + hp.settings([(1, 65536)]) + hp.window_update(1000) + req("/fp")
    for _ in range(50):
        assert fp_of(h2_exchange(srv.h2c, stream))["akamai_fingerprint"] == "1:65536|1000|0|m,p,a,s"


def test_h2_second_request_same_connection(srv: Nginx) -> None:
    """The fingerprint is frozen with the first stream; a later stream with other pseudo-header order and more
    PRIORITY frames returns the same value."""
    stream = (ref_h2.PREFACE + hp.settings([(1, 65536)]) + req("/fp", 1, "mpas") + hp.priority(5, 0, 9)
              + hp.settings([(3, 50)]) + req("/fp", 3, "spam"))
    o = h2_exchange(srv.h2c, stream, sid=3)
    assert fp_of(o)["akamai_fingerprint"] == "1:65536|00|0|m,p,a,s"


# ------------------------------------------------------------------------------------------------- raw TLS


VECTORS = [v for v in json.loads((REPO / "doc" / "ja4_vectors.json").read_text()) if v["ja4"][0] == "t"]


def records(msg: bytes, size: int = 16384, version: bytes = b"\x03\x01") -> bytes:
    return b"".join(b"\x16" + version + len(msg[i:i + size]).to_bytes(2, "big") + msg[i:i + size]
                    for i in range(0, len(msg), size))


def tls_exchange(port: int, data: bytes, timeout: float = 3) -> bytes:
    """Send raw TLS records; return the server's first bytes (at least a record header plus one octet) or whatever
    it sent before closing or going quiet."""
    got = b""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        try:
            s.sendall(data)
            while len(got) < 6:
                chunk = s.recv(65536)
                if not chunk:
                    break
                got += chunk
        except (TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
    return got


def reframe(body: bytes) -> bytes:
    """A handshake message whose outer length matches the (possibly corrupted) body, so OpenSSL reads all of it and
    hands it to the msg_callback before validating the inside."""
    return b"\x01" + len(body).to_bytes(3, "big") + body


def mutate(rng: random.Random, body: bytes) -> bytes:
    b = bytearray(body)
    for _ in range(rng.randint(1, 4)):
        k = rng.randrange(5)
        if k == 0 and b:
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif k == 1 and len(b) > 2:
            i = rng.randrange(len(b) - 1)
            b[i:i + 2] = rng.choice([b"\xff\xff", b"\x00\x00", b"\x7f\xff", b"\x00\x01"])
        elif k == 2:
            del b[rng.randrange(len(b)):]
        elif k == 3:
            b += rng.randbytes(rng.randint(1, 64))
        elif len(b) > 8:
            i, j = sorted(rng.sample(range(len(b)), 2))
            del b[i:j]
    return bytes(b)


def test_tls_mutated_hellos(srv: Nginx) -> None:
    """Corrupted ClientHellos with consistent outer framing reach the JA4 parser before OpenSSL's own checks."""
    rng = random.Random(11)
    for v in VECTORS:
        msg = bytes.fromhex(v["client_hello_hex"])
        for _ in range(6):
            data = reframe(mutate(rng, msg[4:]))
            tls_exchange(srv.tls, records(data, rng.choice([16384, 16384, 7, 300])), timeout=1)


IMPOSSIBLE_TLS: dict[str, bytes] = {
    "empty_hello": records(reframe(b"")),
    "len_max": b"\x16\x03\x01\x00\x04\x01\xff\xff\xff",
    "len_beyond_records": b"\x16\x03\x01\x00\x10\x01\x00\x40\x00" + bytes(12),
    "one_byte_records": records(bytes.fromhex(VECTORS[0]["client_hello_hex"]), size=1),
    "zero_length_record": b"\x16\x03\x01\x00\x00" + records(bytes.fromhex(VECTORS[0]["client_hello_hex"])),
    "two_hellos_one_record": records(bytes.fromhex(VECTORS[0]["client_hello_hex"]) * 2),
    "server_hello_type": records(b"\x02" + bytes.fromhex(VECTORS[0]["client_hello_hex"])[1:]),
    "sslv2_hello": b"\x80\x2e\x01\x03\x01\x00\x15\x00\x00\x00\x10" + bytes(21) + bytes(16),
    "alert_first": b"\x15\x03\x03\x00\x02\x02\x28",
    "appdata_first": b"\x17\x03\x03\x00\x05hello",
    "http_on_tls_port": b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    "record_too_big": b"\x16\x03\x01\xff\xff" + bytes(100),
}


@pytest.mark.parametrize("name", list(IMPOSSIBLE_TLS))
def test_tls_impossible_input(srv: Nginx, name: str) -> None:
    tls_exchange(srv.tls, IMPOSSIBLE_TLS[name], timeout=2)


def _hello_with(ciphers: int, exts: int, sigalgs: int) -> bytes:
    """A TLS 1.2 ClientHello OpenSSL accepts (one real suite, the rest unknown values it ignores), with oversized
    lists for the JA4 caps (decision 011): cipher suites, unknown extensions, signature algorithms."""
    suites = [0xC02F] + [0x5A00 + i for i in range(ciphers)]
    ext = b""
    ext += struct.pack(">HH", 0x000A, 4) + struct.pack(">HH", 2, 0x0017)               # supported_groups P-256
    ext += struct.pack(">HH", 0x000B, 2) + b"\x01\x00"                                 # ec_point_formats
    sa = [0x0401] + [0x7A00 + i for i in range(sigalgs)]
    ext += struct.pack(">HHH", 0x000D, 2 + 2 * len(sa), 2 * len(sa)) + b"".join(struct.pack(">H", s) for s in sa)
    for i in range(exts):
        ext += struct.pack(">HH", 0x7000 + i, 0)
    body = (b"\x03\x03" + bytes(32) + b"\x00" + struct.pack(">H", 2 * len(suites))
            + b"".join(struct.pack(">H", c) for c in suites) + b"\x01\x00" + struct.pack(">H", len(ext)) + ext)
    return reframe(body)


@pytest.mark.parametrize("shape", [(1100, 0, 0), (0, 1100, 0), (0, 0, 1100), (2000, 1500, 1500), (1023, 1020, 1023)])
def test_tls_oversized_lists_complete_handshake(srv: Nginx, shape: tuple[int, int, int]) -> None:
    """Lists over the 1024 cap: the hello is valid TLS, so the server must answer with a ServerHello as usual."""
    got = tls_exchange(srv.tls, records(_hello_with(*shape)), timeout=3)
    assert got[:1] == b"\x16" and got[5:6] == b"\x02", got[:16].hex()


def test_tls_handshake_flood(srv: Nginx) -> None:
    """Half-open handshakes: hello sent, connection dropped. Per-connection state must be freed every time."""
    hello = records(bytes.fromhex(VECTORS[1]["client_hello_hex"]))
    for _ in range(300):
        with socket.create_connection(("127.0.0.1", srv.tls)) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.sendall(hello)



# ------------------------------------------------------------------------------------------------- HTTP/1.x


def plain_exchange(port: int, data: bytes, timeout: float = 5) -> bytes:
    got = b""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(data)
        try:
            while chunk := s.recv(65536):
                got += chunk
        except (TimeoutError, ConnectionResetError):
            pass
    return got


def test_http09_request(srv: Nginx) -> None:
    """HTTP/0.9 has no header list at all (nginx never initialises it); the header handler must cope."""
    plain_exchange(srv.h2c, b"GET /echo\r\n")


def test_many_spoofed_copies_removed(srv: Nginx) -> None:
    """300 client copies of a managed header in mixed case, interleaved with other headers: all are removed and the
    other headers survive in order. (The echo upstream accepts at most 100 header lines, so 38 are kept.)"""
    lines = []
    for i in range(300):
        name = "".join(ch.upper() if (i >> k) & 1 else ch for k, ch in enumerate("x-client-ja4"))
        lines.append(f"{name}: spoof{i}\r\n" + (f"X-Keep-{i // 8}: {i // 8}\r\n" if i % 8 == 0 else ""))
    raw = plain_exchange(srv.h2c, ("GET /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n" + "".join(lines)
                                   + "\r\n").encode())
    head, _, body = raw.partition(b"\r\n\r\n")
    assert b" 200 " in head.split(b"\r\n")[0], head
    echoed = json.loads(body)["headers"]
    names = [k.lower() for k, _ in echoed]
    assert "x-client-ja4" not in names                     # cleartext port: no JA4, so nothing is added
    keeps = [int(v) for k, v in echoed if k.lower().startswith("x-keep-")]
    assert keeps == list(range(38))
