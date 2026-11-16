"""The nginx module's pure-C cores (nginx_module/src/clientfp_{ja4,h2}.c), built with ASan + UBSan in the
nginx-clientfp-ctest image and checked against the Python reference implementations (t1, t3):

- every captured ClientHello in doc/ja4_vectors.json gives the recorded JA4 in all four forms;
- differential testing on many mutated hellos: the C parser accepts exactly what the reference accepts and
  formats the same strings; ASan/UBSan abort the driver on any memory error;
- HTTP/2: hook-event sequences derived from frame sequences give the reference fingerprint.
"""

from __future__ import annotations

import hashlib
import json
import random
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from clientfp.fp import ja4 as ref_ja4

from .conftest import REPO

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


@pytest.fixture(scope="session")
def drivers(require_docker: None) -> Path:
    """Build the image and both drivers once; rebuild only when sources change."""
    dockerfile = REPO / "tests" / "docker" / "Dockerfile.ctest"
    subprocess.run(["docker", "build", "-q", "-t", IMAGE, "-f", str(dockerfile), str(dockerfile.parent)],
                   check=True, capture_output=True)
    OUT.mkdir(parents=True, exist_ok=True)
    srcs = sorted([*SRC.glob("clientfp_*.[ch]"), *(REPO / "tests" / "c").glob("*.c")])
    digest = hashlib.sha256(b"".join(p.read_bytes() for p in srcs)).hexdigest()
    stamp = OUT / "drivers.sha256"
    if not stamp.exists() or stamp.read_text() != digest:
        for d in ("ja4", "h2"):
            _docker("gcc", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
                    "-fno-sanitize-recover=all", "-Inginx_module/src", "-o", f"build/ctest/{d}_driver",
                    f"tests/c/{d}_driver.c", f"nginx_module/src/clientfp_{d}.c", "-lcrypto")
        stamp.write_text(digest)
    return OUT


def run_ja4(hellos: list[tuple[str, bytes]]) -> list[tuple[int, list[str]]]:
    stdin = "".join(f"{proto} {msg.hex()}\n" for proto, msg in hellos)
    out = _docker("build/ctest/ja4_driver", stdin=stdin).splitlines()
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


def test_ja4_vectors(drivers: Path) -> None:
    hellos = [(v["ja4"][0], bytes.fromhex(v["client_hello_hex"])) for v in VECTORS]
    for v, (status, forms) in zip(VECTORS, run_ja4(hellos)):
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


def test_ja4_differential_mutations(drivers: Path) -> None:
    rng = random.Random(4)
    cases: list[tuple[str, bytes]] = []
    for v in VECTORS:
        msg = bytes.fromhex(v["client_hello_hex"])
        cases += [(v["ja4"][0], m) for m in mutations(msg, rng, 120)]
    results = run_ja4(cases)
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


def test_ja4_list_caps(drivers: Path) -> None:
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
    got = [s for s, _ in run_ja4(cases)]
    assert got == [0, 2, 2, 2, 0, 2]


def test_ja4_impossible_inputs(drivers: Path) -> None:
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
    results = run_ja4([("t", c) for c in cases])
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


def run_h2(connections: list[list[str]]) -> list[tuple[int, str, str, int]]:
    stdin = "".join("\n".join(ev) + "\nE\n" for ev in connections)
    out = _docker("build/ctest/h2_driver", stdin=stdin).splitlines()
    assert len(out) == len(connections)
    res = []
    for line in out:
        frozen, fp, md5, overflow = line.split("\t")
        res.append((int(frozen), fp, md5, int(overflow)))
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


def test_h2_against_reference(drivers: Path) -> None:
    from clientfp.fp import h2 as ref_h2
    from clientfp.probe import h2_probe as hp

    streams = [ref_h2.PREFACE + b"".join(c.frames) for c in hp.cases("localhost", "/").values()]
    rng = random.Random(2)
    streams += [_random_stream(rng) for _ in range(400)]
    results = run_h2([nginx_hook_events(s) for s in streams])
    overflowed = 0
    for s, (frozen, fp, md5, overflow) in zip(streams, results):
        want = ref_h2.compute(s)
        assert frozen == 1
        assert (fp, md5, bool(overflow)) == (want.fingerprint, want.hash, want.overflow), s.hex()
        overflowed += overflow
    assert overflowed > 10


def test_h2_hostile_events(drivers: Path) -> None:
    """Event sequences nginx can produce for hostile clients: thousands of settings / PRIORITY frames, a refused
    first stream, a first request whose header block repeats pseudo-headers, 2^31-1 values everywhere."""
    big = [f"F 0 {6 * 2700}"] + [f"s {i % 65536} 4294967295" for i in range(2700)]
    prios = ["P 2147483647 1 2147483647 256" for _ in range(5000)]
    dup = ["T 1"] + [f"H 1 {n}" for n in (":method", ":method", ":path", ":scheme", ":authority", ":path")] + ["D 1"]
    refused = ["H 1 :method", "D 1", "T 3", "H 3 :path", "D 3"]
    res = run_h2([big + ["T 1", "D 1"], prios + ["T 1", "D 1"], dup, refused, ["W 0 4294967295", "T 1", "D 1"]])
    assert res[0][0] == 1 and res[0][3] == 1 and res[0][1].count(";") == 31
    assert res[1][3] == 1 and res[1][1].split("|")[2].count(",") == 31 and "2147483647:1:2147483647:256" in res[1][1]
    assert res[2][1] == "|00|0|m,p,s,a"
    assert res[3][1] == "|00|0|p"
    assert res[4][1] == "|2147483647|0|"
