# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""The nginx module's pure-C cores (nginx_module/src/clientfp_*.c), checked against the Python reference
implementations (t1, t3). Every test runs twice in the nginx-clientfp-ctest image: with drivers built with ASan + UBSan
(-O1), and with drivers built without sanitizers (-O2, as the package is) run under valgrind's memcheck, which also
reports reads of uninitialised memory and every block not freed (the JA4 core allocates nothing on error, and the
TLSFP core releases every buffer it allocates).

- every captured ClientHello in doc/ja4_vectors.json gives the recorded JA4 in all four forms;
- differential testing on many mutated hellos: the C parser accepts exactly what the reference accepts and
  formats the same strings; any memory error fails the driver;
- HTTP/2: hook-event sequences derived from frame sequences give the reference fingerprint;
- TLSFP: the same hellos, mutated hellos and hellos with corrupted inner lists give the reference's TLSFP (including
  the fields emptied by spec §9), with no cap on list sizes;
- ClientHello capture (decision 030): TLS records split every way, every prefix, hostile record streams and shuffled,
  overlapping QUIC CRYPTO fragments give the reference's result, and the bytes still needed are a true lower bound;
- SHA-256: hashlib's digest for every length around the block boundaries, fed in pieces of every size.
"""

from __future__ import annotations

import hashlib
import json
import random
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from clientfp.fp import hello as ref_hello
from clientfp.fp import ja4 as ref_ja4
from clientfp.fp import tlsfp as ref_tlsfp
from clientfp.fp.tls import Extension, encode_client_hello, parse_client_hello

from .conftest import REPO, VALGRIND

pytestmark = [pytest.mark.docker]

IMAGE = "nginx-clientfp-ctest"
OUT = REPO / "build" / "ctest"
SRC = REPO / "nginx_module" / "src"


def _docker(*cmd: str, stdin: str | None = None) -> str:
    proc = subprocess.run(
        ["docker", "run", "--rm", "-i", "-v", f"{REPO}:/work", "-w", "/work", IMAGE, *cmd],
        input=stdin, capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"{' '.join(cmd)} failed ({proc.returncode}):\n{proc.stderr[-4000:]}")
    return proc.stdout


# driver -> the core sources it links
DRIVERS: dict[str, tuple[str, ...]] = {
    "ja4": ("clientfp_ja4.c", "clientfp_sha256.c"),
    "h2": ("clientfp_h2.c",),
    "tlsfp": ("clientfp_tlsfp.c", "clientfp_sha256.c"),
    "hello": ("clientfp_hello.c",),
    "sha256": ("clientfp_sha256.c",),
}


@dataclass(frozen=True)
class Variant:
    cflags: tuple[str, ...]
    runner: tuple[str, ...]   # command prefix


VARIANTS: dict[str, Variant] = {
    "asan": Variant(("-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"), ()),
    "valgrind": Variant(("-O2", "-g"), VALGRIND),
}


@dataclass(frozen=True)
class Drivers:
    """The drivers built for one variant."""

    variant: str

    def run(self, name: str, stdin: str) -> str:
        return _docker(*VARIANTS[self.variant].runner, f"build/ctest/{self.variant}/{name}_driver", stdin=stdin)


@pytest.fixture(scope="session")
def ctest_image(require_docker: None) -> str:
    dockerfile = REPO / "tests" / "docker" / "Dockerfile.ctest"
    subprocess.run(["docker", "build", "-q", "-t", IMAGE, "-f", str(dockerfile), str(dockerfile.parent)],
                   check=True, capture_output=True)
    return IMAGE


@pytest.fixture(scope="session", params=list(VARIANTS))
def drivers(request: pytest.FixtureRequest, ctest_image: str) -> Drivers:
    """Build the drivers of one variant once; rebuild only when sources change."""
    variant: str = request.param
    out = OUT / variant
    out.mkdir(parents=True, exist_ok=True)
    srcs = sorted([*SRC.glob("clientfp_*.[ch]"), *(REPO / "tests" / "c").glob("*.c")])
    cflags = VARIANTS[variant].cflags
    digest = hashlib.sha256(b"".join(p.read_bytes() for p in srcs) + " ".join(cflags).encode()).hexdigest()
    stamp = out / "drivers.sha256"
    if not stamp.exists() or stamp.read_text() != digest:
        for d, srcs_d in DRIVERS.items():
            _docker("gcc", *cflags, "-Wall", "-Wextra", "-Werror", "-Inginx_module/src",
                    "-o", f"build/ctest/{variant}/{d}_driver", f"tests/c/{d}_driver.c",
                    *(f"nginx_module/src/{s}" for s in srcs_d))
        stamp.write_text(digest)
    return Drivers(variant)


def run_ja4(drivers: Drivers, hellos: list[tuple[str, bytes]]) -> list[tuple[int, list[str]]]:
    stdin = "".join(f"{proto} {msg.hex()}\n" for proto, msg in hellos)
    out = drivers.run("ja4", stdin).splitlines()
    assert len(out) == len(hellos)
    res = []
    for line in out:
        status, *forms = line.split("\t")
        res.append((int(status), forms))
    return res


def reference(proto: str, msg: bytes) -> list[str] | None:
    """The reference's four forms for a handshake message, None if it rejects the message."""
    try:
        f = ref_ja4.compute(ref_ja4.parse_client_hello(msg), "q" if proto == "q" else "t")
    except ValueError:
        return None
    return [f.ja4, f.ja4_r, f.ja4_o, f.ja4_ro]


VECTORS = json.loads((REPO / "doc" / "ja4_vectors.json").read_text())


def test_ja4_vectors(drivers: Drivers) -> None:
    hellos = [(v["ja4"][0], bytes.fromhex(v["client_hello_hex"])) for v in VECTORS]
    for v, (status, forms) in zip(VECTORS, run_ja4(drivers, hellos)):
        assert status == 0, v["name"]
        assert forms == [v["ja4"], v["ja4_r"], v["ja4_o"], v["ja4_ro"]], v["name"]


def mutations(msg: bytes, rng: random.Random, n: int) -> Iterator[bytes]:
    for _ in range(n):
        b = bytearray(msg)
        kind = rng.randrange(6)
        if kind == 0:                                   # truncate
            yield bytes(b[: rng.randrange(len(b))])
        elif kind == 1:                                 # flip bytes
            for _ in range(rng.randint(1, 4)):
                i = rng.randrange(len(b))
                b[i] ^= 1 << rng.randrange(8)
            yield bytes(b)
        elif kind == 2:                                 # overwrite a length-ish byte with an extreme value
            i = rng.randrange(len(b))
            b[i] = rng.choice((0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF))
            yield bytes(b)
        elif kind == 3:                                 # insert junk
            i = rng.randrange(len(b))
            yield bytes(b[:i] + rng.randbytes(rng.randint(1, 8)) + b[i:])
        elif kind == 4:                                 # delete a slice
            i = rng.randrange(len(b))
            yield bytes(b[:i] + b[i + rng.randint(1, 8):])
        else:                                           # trailing data after the extensions block
            yield bytes(b) + rng.randbytes(rng.randint(1, 4))


def test_ja4_differential_mutations(drivers: Drivers) -> None:
    rng = random.Random(4)
    cases: list[tuple[str, bytes]] = []
    for v in VECTORS:
        msg = bytes.fromhex(v["client_hello_hex"])
        cases += [(v["ja4"][0], m) for m in mutations(msg, rng, 120)]
    results = run_ja4(drivers, cases)
    accepted = 0
    for (proto, msg), (status, forms) in zip(cases, results):
        want = reference(proto, msg)
        if want is None:
            assert status != 0, f"C accepted what the reference rejects: {msg.hex()}"
        else:
            accepted += 1
            assert status == 0, f"C rejected ({status}) what the reference accepts: {msg.hex()}"
            assert forms == want, msg.hex()
    assert accepted > len(cases) // 10        # the mutations must also exercise the success path


def _hello(ciphers: list[int], exts: list[tuple[int, bytes]], version: int = 0x0303) -> bytes:
    body = version.to_bytes(2, "big") + bytes(32) + b"\x00"
    body += (2 * len(ciphers)).to_bytes(2, "big") + b"".join(c.to_bytes(2, "big") for c in ciphers)
    body += b"\x01\x00"
    if exts:
        blob = b"".join(t.to_bytes(2, "big") + len(d).to_bytes(2, "big") + d for t, d in exts)
        body += len(blob).to_bytes(2, "big") + blob
    return b"\x01" + len(body).to_bytes(3, "big") + body


def test_ja4_list_caps(drivers: Drivers) -> None:
    """Decision 011: more than 1024 entries in any list -> no fingerprint (status 2); 1024 is still fine."""
    ok_ciphers = [0x1301 + i for i in range(1024)]
    too_many = [0x1301 + i for i in range(1025)]
    def sig(n: int) -> tuple[int, bytes]:
        return 0x000D, (2 * n).to_bytes(2, "big") + b"".join((0x0401 + i).to_bytes(2, "big") for i in range(n))

    cases = [
        ("t", _hello(ok_ciphers, [])),
        ("t", _hello(too_many, [])),
        ("t", _hello([0x1301], [(0x7000 + i, b"") for i in range(1025)])),
        ("t", _hello([0x1301], [sig(1025)])),
        ("t", _hello([0x1301], [sig(1024)])),
        ("q", _hello(too_many + [0x0A0A] * 10, [])),
    ]
    got = [s for s, _ in run_ja4(drivers, cases)]
    assert got == [0, 2, 2, 2, 0, 2]


def test_ja4_impossible_inputs(drivers: Drivers) -> None:
    """Hand-written hostile hellos: every one must be rejected cleanly (status 1) or parsed, never crash."""
    good = bytes.fromhex(VECTORS[0]["client_hello_hex"])
    cases = [
        b"",
        b"\x01",
        b"\x01\x00\x00",
        b"\x02" + good[1:],                                 # not a ClientHello
        b"\x01\xff\xff\xff" + good[4:],                     # length beyond the buffer
        b"\x01\x00\x00\x00",                                # empty body
        b"\x01\x00\x00\x22" + bytes(34),                    # version + random, nothing else
        _hello([0x1301], [(0x0010, b"\x00\x05\x0a")]),     # ALPN list longer than the extension
        _hello([0x1301], [(0x0010, b"\x00\x02\x05h")]),    # first ALPN name longer than the list
        _hello([0x1301], [(0x000D, b"\x00\x03\x04\x03\x08")]),  # odd sigalgs length
        _hello([0x1301], [(0x002B, b"\x05\x03\x04\x03\x03\x7f")]),  # odd supported_versions length
        _hello([0x1301], [(0x002B, b"\x09\x03\x04")]),     # supported_versions list too long
        _hello([], []),                                     # no ciphers, no extensions
        good[:4] + good[4:] + b"\x00",                      # trailing byte not covered by the length
    ]
    results = run_ja4(drivers, [("t", c) for c in cases])
    for c, (status, _forms) in zip(cases, results):
        assert status in (0, 1), c.hex()
        assert (status == 0) == (reference("t", c) is not None), c.hex()


# ------------------------------------------------------------------------------------------------- HTTP/2

def nginx_hook_events(stream: bytes) -> list[str]:
    """The hook calls the patched ngx_http_v2.c makes for a client byte stream (preface + frames), as driver
    lines. Mirrors the patch: ACK-only SETTINGS frames (flags == 0x1) never reach the hook; each HEADERS frame
    that gets a stream reports T, its decoded pseudo-header names, then D at the end of its block."""
    import hpack

    from clientfp.fp import h2 as ref_h2

    assert stream.startswith(ref_h2.PREFACE)
    p = len(ref_h2.PREFACE)
    dec = hpack.Decoder()
    events: list[str] = []
    block = b""
    block_sid = 0
    while p + 9 <= len(stream):
        length = int.from_bytes(stream[p:p + 3], "big")
        ftype, flags = stream[p + 3], stream[p + 4]
        sid = int.from_bytes(stream[p + 5:p + 9], "big") & 0x7FFFFFFF
        payload = stream[p + 9:p + 9 + length]
        p += 9 + length
        if ftype == 0x4 and sid == 0 and flags != 0x1 and length % 6 == 0:
            events.append(f"F {flags} {length}")
            for i in range(0, length, 6):
                events.append(f"s {int.from_bytes(payload[i:i + 2], 'big')} "
                              f"{int.from_bytes(payload[i + 2:i + 6], 'big')}")
        elif ftype == 0x8 and length == 4:
            events.append(f"W {sid} {int.from_bytes(payload, 'big') & 0x7FFFFFFF}")
        elif ftype == 0x2 and length == 5 and sid != 0:
            dep = int.from_bytes(payload[:4], "big")
            events.append(f"P {sid} {dep >> 31} {dep & 0x7FFFFFFF} {payload[4] + 1}")
        elif ftype in (0x1, 0x9):
            if ftype == 0x1:
                block_sid = sid
                frag = payload
                if flags & 0x8:                                   # PADDED
                    frag = frag[1:len(frag) - frag[0]]
                if flags & 0x20:                                  # PRIORITY block, not part of P
                    frag = frag[5:]
                block = frag
                events.append(f"T {sid}")
            else:
                block += payload
            if flags & 0x4:                                       # END_HEADERS
                for name, _value in dec.decode(block, raw=True):
                    if name.startswith(b":"):
                        events.append(f"H {block_sid} {name.decode()}")
                events.append(f"D {block_sid}")
    return events


def run_h2(drivers: Drivers, connections: list[list[str]]) -> list[tuple[int, str, str, int]]:
    """(frozen, fingerprint, MD5, overflow) per connection. The module hashes with nginx's ngx_md5, outside the core;
    hashlib stands in for it here."""
    stdin = "".join("\n".join(ev) + "\nE\n" for ev in connections)
    out = drivers.run("h2", stdin).splitlines()
    assert len(out) == len(connections)
    res = []
    for line in out:
        frozen, fp, overflow = line.split("\t")
        res.append((int(frozen), fp, hashlib.md5(fp.encode()).hexdigest(), int(overflow)))
    return res


def _random_stream(rng: random.Random) -> bytes:
    from clientfp.fp import h2 as ref_h2
    from clientfp.probe import h2_probe as hp

    frames: list[bytes] = []

    def misc() -> None:
        k = rng.randrange(8)
        if k == 0:
            frames.append(hp.settings([(rng.randrange(1 << 16), rng.randrange(1 << 32))
                                       for _ in range(rng.choice((0, 1, 3, 6, 33, 40)))]))
        elif k == 1:
            frames.append(hp.frame(ref_h2.FrameType.SETTINGS, 0x1, 0))
        elif k == 2:
            frames.append(hp.window_update(rng.randrange(1, 1 << 31), rng.choice((0, 0, 3))))
        elif k == 3:
            for _ in range(rng.choice((1, 2, 5, 31, 33))):
                frames.append(hp.priority(rng.randrange(1, 1 << 31), rng.randrange(1 << 31), rng.randrange(256),
                                          rng.randrange(2)))
        elif k == 4:
            frames.append(hp.frame(ref_h2.FrameType.PING, 0, 0, bytes(8)))
        elif k == 5:
            frames.append(hp.frame(ref_h2.FrameType.SETTINGS, 0x81, 0, b""))
        else:
            frames.append(hp.settings([(1, 4096)]))

    for _ in range(rng.randrange(6)):
        misc()
    order = "".join(rng.sample("mpas", rng.randint(1, 4)))
    frames.append(hp.headers(1, hp.req_headers("h", "/", order),
                             (0, rng.randrange(256), 1) if rng.random() < 0.3 else None))
    for _ in range(rng.randrange(3)):
        misc()
    frames.append(hp.headers(3, hp.req_headers("h", "/", "spam")))
    return ref_h2.PREFACE + b"".join(frames)


def test_h2_against_reference(drivers: Drivers) -> None:
    from clientfp.fp import h2 as ref_h2
    from clientfp.probe import h2_probe as hp

    streams = [ref_h2.PREFACE + b"".join(c.frames) for c in hp.cases("localhost", "/").values()]
    rng = random.Random(2)
    streams += [_random_stream(rng) for _ in range(400)]
    results = run_h2(drivers, [nginx_hook_events(s) for s in streams])
    overflowed = 0
    for s, (frozen, fp, md5, overflow) in zip(streams, results):
        want = ref_h2.compute(s)
        assert frozen == 1
        assert (fp, md5, bool(overflow)) == (want.fingerprint, want.hash, want.overflow), s.hex()
        overflowed += overflow
    assert overflowed > 10


def test_h2_hostile_events(drivers: Drivers) -> None:
    """Event sequences nginx can produce for hostile clients: thousands of settings / PRIORITY frames, a refused
    first stream, a first request whose header block repeats pseudo-headers, 2^31-1 values everywhere."""
    big = [f"F 0 {6 * 2700}"] + [f"s {i % 65536} 4294967295" for i in range(2700)]
    prios = ["P 2147483647 1 2147483647 256" for _ in range(5000)]
    dup = ["T 1"] + [f"H 1 {n}" for n in (":method", ":method", ":path", ":scheme", ":authority", ":path")] + ["D 1"]
    refused = ["H 1 :method", "D 1", "T 3", "H 3 :path", "D 3"]
    res = run_h2(drivers, [big + ["T 1", "D 1"], prios + ["T 1", "D 1"], dup, refused,
                           ["W 0 4294967295", "T 1", "D 1"]])
    assert res[0][0] == 1 and res[0][3] == 1 and res[0][1].count(";") == 31
    assert res[1][3] == 1 and res[1][1].split("|")[2].count(",") == 31 and "2147483647:1:2147483647:256" in res[1][1]
    assert res[2][1] == "|00|0|m,p,s,a"
    assert res[3][1] == "|00|0|p"
    assert res[4][1] == "|2147483647|0|"


# ------------------------------------------------------------------------------------------------- TLSFP


def run_tlsfp(drivers: Drivers, hellos: list[tuple[str, bytes]]) -> list[tuple[int, str]]:
    stdin = "".join(f"{proto} {msg.hex()}\n" for proto, msg in hellos)
    out = drivers.run("tlsfp", stdin).splitlines()
    assert len(out) == len(hellos)
    res = []
    for line in out:
        status, fp = line.split("\t")
        res.append((int(status), fp))
    return res


def reference_tlsfp(proto: str, msg: bytes) -> str | None:
    try:
        return ref_tlsfp.compute(parse_client_hello(msg), "q" if proto == "q" else "t").tlsfp
    except ValueError:
        return None


def _check_tlsfp(drivers: Drivers, cases: list[tuple[str, bytes]]) -> tuple[int, set[str]]:
    """Compare C and reference on every case; return (#accepted, shapes of the accepted results)."""
    accepted, shapes = 0, set()
    for (proto, msg), (status, fp) in zip(cases, run_tlsfp(drivers, cases)):
        want = reference_tlsfp(proto, msg)
        if want is None:
            assert status != 0 and fp == "", f"C accepted what the reference rejects: {msg.hex()}"
            continue
        accepted += 1
        assert (status, fp) == (0, want), f"{proto} {msg.hex()}"
        shapes.add("".join("x" if part else "-" for part in fp.split("_")))
    return accepted, shapes


def test_tlsfp_vectors(drivers: Drivers) -> None:
    cases = [("q" if v["ja4"][0] == "q" else "t", bytes.fromhex(v["client_hello_hex"])) for v in VECTORS]
    accepted, shapes = _check_tlsfp(drivers, cases)
    assert accepted == len(VECTORS) and shapes == {"xxxx"}


def test_tlsfp_differential_mutations(drivers: Drivers) -> None:
    rng = random.Random(5)
    cases: list[tuple[str, bytes]] = []
    for v in VECTORS:
        msg = bytes.fromhex(v["client_hello_hex"])
        cases += [(v["ja4"][0], m) for m in mutations(msg, rng, 120)]
    accepted, _ = _check_tlsfp(drivers, cases)
    assert accepted > len(cases) // 10


def _corrupt_inner(msg: bytes, ext_type: int, rng: random.Random) -> bytes | None:
    """Rewrite the data of the first `ext_type` extension with a corrupted inner list, keeping every outer length
    consistent, so only the inside of that extension is malformed."""
    ch = parse_client_hello(msg)
    data = ch.ext(ext_type)
    if data is None:
        return None
    b = bytearray(data)
    kind = rng.randrange(5)
    if kind == 0 and b:
        b[0] ^= 0xFF                                            # inner length: way off
    elif kind == 1 and len(b) >= 2:
        n = rng.choice((1, -1))
        if ext_type == 0x002B:
            b[0] = (b[0] + n) & 0xFF
        else:
            v = (int.from_bytes(b[:2], "big") + n) & 0xFFFF
            b[:2] = v.to_bytes(2, "big")
    elif kind == 2:
        b += b"\x00"                                           # trailing byte after the list
    elif kind == 3:
        b = b[:-1]                                              # list shorter than declared
    else:
        b = bytearray()                                         # no list length at all
    seen = False
    fixed = []
    for orig in ch.extensions:                    # only the first occurrence is rewritten
        if orig.type == ext_type and not seen:
            seen = True
            fixed.append(Extension(ext_type, bytes(b)))
        else:
            fixed.append(orig)
    return encode_client_hello(ch.legacy_version, ch.ciphers, fixed)


def test_tlsfp_malformed_inner_lists(drivers: Drivers) -> None:
    """Spec §9: a malformed ALPN / supported_versions / signature_algorithms / supported_groups empties a, a, c or d
    only. Each case must be one the reference still accepts, and C must agree field by field."""
    rng = random.Random(6)
    cases: list[tuple[str, bytes]] = []
    for v in VECTORS:
        msg = bytes.fromhex(v["client_hello_hex"])
        for ext in (0x0010, 0x002B, 0x000D, 0x000A):
            for _ in range(4):
                m = _corrupt_inner(msg, ext, rng)
                if m is not None:
                    cases.append((v["ja4"][0], m))
    accepted, shapes = _check_tlsfp(drivers, cases)
    assert accepted == len(cases)
    assert {"-xxx", "xx-x", "xxx-"} <= shapes


def test_tlsfp_lists_uncapped(drivers: Drivers) -> None:
    """§7.5: counts stop at 99, hash inputs do not. Far beyond JA4's 1024 cap, and the largest lists a 2^24-byte
    handshake message allows for ciphers."""
    def sig(n: int) -> tuple[int, bytes]:
        return 0x000D, (2 * n).to_bytes(2, "big") + b"".join((0x0401 + i).to_bytes(2, "big") for i in range(n))

    def groups(n: int) -> tuple[int, bytes]:
        return 0x000A, (2 * n).to_bytes(2, "big") + b"".join(((7 * i) & 0xFFFF).to_bytes(2, "big") for i in range(n))

    cases = [
        ("t", _hello(list(range(0x0100, 0x0100 + 5000)), [])),
        ("t", _hello([0x1301], [(0x7000 + i, b"") for i in range(3000)])),
        ("t", _hello([0x1301], [sig(4000), groups(6000)])),
        ("q", _hello([(0x0100 + i * 3) & 0xFFFF for i in range(32767)], [(0x0010, b"\x00\x03\x02H2")])),
    ]
    accepted, _ = _check_tlsfp(drivers, cases)
    assert accepted == len(cases)
    assert run_tlsfp(drivers, cases[:1])[0][1].startswith("t12i9900")


# ------------------------------------------------------------------------------------------- ClientHello capture

def run_hello(drivers: Drivers, cases: list[str]) -> list[tuple[int, str, int]]:
    out = drivers.run("hello", "".join(c + "\n" for c in cases)).splitlines()
    assert len(out) == len(cases)
    res = []
    for line in out:
        status, msg, need = line.split("\t")
        res.append((int(status), msg, int(need)))
    return res


def _tls_case(raw: bytes) -> tuple[str, tuple[int, str, int]]:
    r = ref_hello.tls_capture(raw)
    return f"T {raw.hex()}", (ref_hello.STATUS_CODE[r.status], r.msg.hex() if r.status == "done" else "-", r.need)


def _quic_case(frags: list[tuple[int, bytes]]) -> tuple[str, tuple[int, str, int]]:
    q = ref_hello.QuicCapture()
    for off, data in frags:
        q.add(off, data)
    line = "Q " + " ".join(f"{off}:{data.hex()}" for off, data in frags)
    return line, (ref_hello.STATUS_CODE[q.status], q.msg.hex() if q.status == "done" else "-", 0)


def _check_hello(drivers: Drivers, cases: list[tuple[str, tuple[int, str, int]]]) -> list[tuple[int, str, int]]:
    got = run_hello(drivers, [c for c, _ in cases])
    for (line, want), res in zip(cases, got):
        assert res == want, line[:300]
    return got


def _rec(payload: bytes, ctype: int = 22, version: int = 0x0301) -> bytes:
    return bytes([ctype]) + version.to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload


def test_hello_tls_against_reference(drivers: Drivers) -> None:
    """Every recorded hello, split into records every way, with trailing data, and many prefixes of each."""
    rng = random.Random(7)
    cases = []
    for v in VECTORS:
        msg = bytes.fromhex(v["client_hello_hex"])
        for sizes in ([16384], [1], [2, 3], [4], [5, 500], [len(msg) - 1], [rng.randrange(1, 64) for _ in range(99)]):
            raw = ref_hello.records(msg, sizes, rng.choice((0x0300, 0x0301, 0x0303)))
            raw += rng.choice((b"", _rec(b"\x01", 20), _rec(b"\x00" * 40, 23), b"\x16"))
            cuts = {0, 1, 4, 5, 6, 9, len(raw) // 3, len(raw) - 1, len(raw),
                    *(rng.randrange(len(raw)) for _ in range(4))}
            for n in cuts:
                cases.append(_tls_case(raw[:n]))
    got = _check_hello(drivers, cases)
    assert sum(1 for s, _, _ in got if s == 0) > 600


def test_hello_tls_need_is_a_lower_bound(drivers: Drivers) -> None:
    """For every prefix that is incomplete, all longer prefixes short of the reported need stay incomplete, and the
    full stream completes. Small records make need grow in many small steps."""
    msgs = [bytes.fromhex(v["client_hello_hex"]) for v in VECTORS[:3]]
    for msg, sizes in zip(msgs, ([1], [7, 1, 300], [3, 40])):
        raw = ref_hello.records(msg, sizes)
        res = _check_hello(drivers, [_tls_case(raw[:n]) for n in range(len(raw) + 1)])
        assert res[-1][0] == 0
        for n, (status, _, need) in enumerate(res):
            if status == 1:
                assert all(res[k][0] == 1 for k in range(n, min(need, len(raw) + 1)))


def test_hello_tls_hostile(drivers: Drivers) -> None:
    rng = random.Random(8)
    small = bytes.fromhex(VECTORS[0]["client_hello_hex"])
    big = _hello(list(range(0x0100, 0x0100 + 8150)), [])                   # 16 KiB message, just within the limit
    assert len(big) <= ref_hello.HELLO_MAX
    raws = [
        b"\x17\x03\x03\x00\x05hello", b"\x15\x03\x01\x00\x02\x02\x28", b"\x80\x2e\x01\x00\x02", b"\x16\x02\x00",
        b"\x16\x03\x01\x00\x00", b"\x16\x03\x01\x40\x01" + bytes(100), b"\x16\x03\x01\xff\xff",
        _rec(b"\x02\x00\x00\x00"), _rec(b"\x00"), _rec(b"\x0b") + _rec(b"\x00\x00\x00"),         # not a ClientHello
        _rec(b"\x01\x00\x40\x00" + bytes(100)),                                                  # message > 16 KiB
        _rec(b"\x01\xff\xff\xff"),
        ref_hello.records(small, [100])[:120] + _rec(b"\x01", 20) + ref_hello.records(small, [100])[105:],
        ref_hello.records(small, [1]),                                       # ~6x expansion, still within 32 KiB
        ref_hello.records(big, [16384]), ref_hello.records(big, [3000]),
        ref_hello.records(big, [2]),                                         # needs > 32 KiB of records: too big
        ref_hello.records(small[:4] + bytes(len(small) - 4), [len(small)]),  # completes; parsing is the cores' job
    ]
    for _ in range(300):
        raw = bytearray(ref_hello.records(small, [rng.randrange(1, 400) for _ in range(20)]))
        for _ in range(rng.randrange(1, 4)):
            raw[rng.randrange(len(raw))] = rng.randrange(256)
        raws.append(bytes(raw))
    for _ in range(300):
        raws.append(b"\x16\x03" + bytes(rng.randrange(256) for _ in range(rng.randrange(40))))
    for _ in range(100):
        raws.append(bytes([rng.randrange(0x80, 0x100)]) + bytes(rng.randrange(256) for _ in range(rng.randrange(6))))
    got = _check_hello(drivers, [_tls_case(r) for r in raws])
    assert {s for s, _, _ in got} == {0, 1, 2, 3, 4}


def test_hello_tls_sslv2(drivers: Drivers) -> None:
    """SSLv2-format ClientHellos are recognised from their first three bytes (decision 036)."""
    v2 = b"\x80\x2e\x01\x03\x03\x00\x06\x00\x00\x00\x20" + bytes(38)
    got = _check_hello(drivers, [_tls_case(r) for r in (v2, v2[:3], v2[:2], v2[:1], b"\xff\xff\x01", b"\x80\x2e\x02")])
    assert got == [(4, "-", 0), (4, "-", 0), (1, "-", 3), (1, "-", 3), (4, "-", 0), (2, "-", 0)]


def test_hello_tls_empty_records(drivers: Drivers) -> None:
    """Empty handshake records before and inside the hello are skipped, as the TLS library skips them; otherwise a
    client could avoid fingerprinting with a handshake that still succeeds."""
    msg = bytes.fromhex(VECTORS[0]["client_hello_hex"])
    parts = [ref_hello.records(msg[i:i + 100], [100]) for i in range(0, len(msg), 100)]
    raws = [
        _rec(b"") + ref_hello.records(msg, [16384]),
        _rec(b"") * 32 + ref_hello.records(msg, [16384]),
        b"".join(p + _rec(b"") for p in parts[:-1]) + parts[-1],
    ]
    got = _check_hello(drivers, [_tls_case(r) for r in raws])
    assert [(s, m) for s, m, _ in got] == [(0, msg.hex())] * len(raws)


def test_hello_quic_against_reference(drivers: Drivers) -> None:
    """Initial CRYPTO fragments in any order, duplicated, overlapping with conflicting bytes (the first copy wins),
    beyond the message, and hostile offsets and lengths."""
    rng = random.Random(9)
    cases = []
    for v in VECTORS:
        msg = bytes.fromhex(v["client_hello_hex"])
        for _ in range(5):
            frags, p = [], 0
            while p < len(msg):
                n = rng.randrange(1, 700)
                frags.append((p, msg[p:p + n]))
                p += n
            for _ in range(rng.randrange(4)):
                o = rng.randrange(len(msg))
                data = msg[o:o + rng.randrange(1, 80)]
                frags.append((o, bytes(b ^ 0xFF for b in data) if rng.random() < 0.3 else data))
            frags.append((len(msg) + rng.randrange(50), b"\x01\x00\x00\x09second"))     # after HRR, ignored
            rng.shuffle(frags)
            if rng.random() < 0.2:
                frags = frags[:-1]
            cases.append(_quic_case(frags))
    small = bytes.fromhex(VECTORS[0]["client_hello_hex"])
    cases += [
        _quic_case([]), _quic_case([(0, b"")]), _quic_case([(0, b"\x01\x00")]), _quic_case([(0, b"\x02\x00\x00\x00")]),
        _quic_case([(0, b"\x01\x00\x40\x00")]), _quic_case([(1, b"\x00\x40\x00"), (0, b"\x01")]),
        _quic_case([(2**62, b"\x01"), (ref_hello.HELLO_MAX, b"x" * 100), (ref_hello.HELLO_MAX - 1, b"yz")]),
        _quic_case([(0, b"\x01\x00\x00\x00")]),
        _quic_case([(4, small[4:]), (0, small[:4])]),
        _quic_case([(0, small), (0, b"\x02" + small[1:])]),
        _quic_case([(i, small[i:i + 1]) for i in reversed(range(len(small)))]),
    ]
    got = _check_hello(drivers, cases)
    assert sum(1 for s, _, _ in got if s == 0) > 300


def test_sha256(drivers: Drivers) -> None:
    rng = random.Random(10)
    lines, want = [], []
    for n in [*range(0, 140), 1000, 4095, 4096, 4097, 65536]:
        data = bytes(rng.randrange(256) for _ in range(n))
        for chunk in {1, 3, 63, 64, 65, max(n, 1)}:
            lines.append(f"{chunk}:{data.hex()}")
            want.append(hashlib.sha256(data).hexdigest())
    out = drivers.run("sha256", "".join(f"{x}\n" for x in lines)).splitlines()
    assert out == want
