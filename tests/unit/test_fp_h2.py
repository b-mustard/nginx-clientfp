# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""clientfp.fp.h2 against doc/http2_sig.md: §4.1 vectors, the 21 probe cases, bounds, partial and malformed input."""

from __future__ import annotations

import hashlib
import random
import re
import struct
from pathlib import Path

import hpack
import pytest

from clientfp.fp import h2
from clientfp.fp.h2 import (FLAG_END_HEADERS, FLAG_END_STREAM, FLAG_PADDED, FLAG_PRIORITY, MAX_PRIORITIES, MAX_SETTINGS,
                            PREFACE, FrameType, IncompleteStreamError)
from clientfp.probe import h2_clients, h2_probe
from clientfp.probe.h2_probe import frame, headers, priority, req_headers, settings, window_update

DOC = Path(__file__).resolve().parents[2] / "doc"
HOST, PATH = "kittens.sh", "/api/http2"
CASES = h2_probe.cases(HOST, PATH)
FP_RE = re.compile(r"[0-9:;]*\|(?:\d+|00)\|(?:[0-9:,]+)\|[mpas,]*")


def stream(*frames: bytes) -> bytes:
    return PREFACE + b"".join(frames)


def fp(*frames: bytes) -> str:
    return h2.compute(stream(*frames)).fingerprint


def hdr(order: str = "mpas", sid: int = 1) -> bytes:
    return headers(sid, req_headers(HOST, PATH, order))


def block(order: str = "mpas") -> bytes:
    """An uncompressed (literal, no Huffman) header block, as the probe builds it."""
    return b"".join(h2_probe.hpack_literal(n, v) for n, v in req_headers(HOST, PATH, order))


# ---------------------------------------------------------------------------------------------- doc vectors

# doc/http2_sig.md §4.1: probe case -> (fingerprint, MD5)
DOC_TABLE = {
    "paper_firefox": ("1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1|m,p,a,s",
                      "b151efdd3ac38eb07621c822c1852a27"),
    "paper_chrome58": ("1:65536;3:1000;4:6291456|15663105|0|m,a,s,p", "9a7d2493dea05d3d5d1c2a797b83e8fd"),
    "no_window_update": ("3:100;4:65535|00|0|m,p,s,a", "821c4a0a02c6f80bb474340772269027"),
    "empty_settings": ("|1000|0|m,p,a,s", "b90ba10e3fa878e6c299ce7811dbe44c"),
    "prio_exclusive": ("1:65536|1000|3:1:0:256|m,a,s,p", "535bd3c91efe1d901175a6437636a79a"),
}


def _doc_rows(heading: str) -> list[tuple[str, str]]:
    """(fingerprint, md5) pairs from the table under a doc/http2_sig.md heading."""
    text = (DOC / "http2_sig.md").read_text()
    start = text.index(heading)
    section = text[start:text.index("\n### ", start + 1)]
    return [(f.replace("\\|", "|"), md5) for f, md5 in re.findall(r"`([^`]*\|[^`]*)` \| `([0-9a-f]{32})`", section)]


def test_doc_table_in_sync() -> None:
    assert sorted(_doc_rows("### 4.1")) == sorted(DOC_TABLE.values())


@pytest.mark.parametrize("name", DOC_TABLE)
def test_doc_vectors(name: str) -> None:
    r = h2.compute(stream(*CASES[name].frames))
    assert (r.fingerprint, r.hash) == DOC_TABLE[name]
    assert not r.overflow


def test_doc_real_client_hashes() -> None:
    """§4.2: every recorded real-client fingerprint has the MD5 the doc lists, and h2_clients expects those values."""
    rows = dict(_doc_rows("### 4.2"))
    assert len(rows) == 7
    for f, md5 in rows.items():
        assert h2.fingerprint_hash(f) == md5
    assert {c.expected for c in h2_clients.CASES if c.expected is not None} == set(rows)


def test_paper_firefox_fields() -> None:
    r = h2.compute(stream(*CASES["paper_firefox"].frames))
    assert r.settings == (h2.Setting(1, 65536), h2.Setting(4, 131072), h2.Setting(5, 16384))
    assert r.window_update == 12517377
    assert r.priorities[0] == h2.Priority(stream_id=3, exclusive=False, depends_on=0, weight=201)
    assert r.priorities[3] == h2.Priority(stream_id=9, exclusive=False, depends_on=7, weight=1)
    assert r.pseudo_header_order == ("m", "p", "a", "s")
    assert r.hash == hashlib.md5(r.fingerprint.encode()).hexdigest()


# ---------------------------------------------------------------------------------------------- probe cases


def test_probe_case_count() -> None:
    assert len(CASES) == 21


@pytest.mark.parametrize("name", CASES)
def test_probe_case(name: str) -> None:
    case = CASES[name]
    r = h2.compute(stream(*case.frames))
    assert r.fingerprint == case.expected
    assert h2_probe.calculated(case) == case.expected
    assert not r.overflow


# ---------------------------------------------------------------------------------------------- rules


def test_exclusive_and_weight_range() -> None:
    assert fp(priority(3, 0, 0), priority(5, 3, 255, 1), hdr()) == "|00|3:0:0:1,5:1:3:256|m,p,a,s"
    assert fp(priority(7, 0x7FFFFFFF, 10, 1), hdr()) == "|00|7:1:2147483647:11|m,p,a,s"


def test_headers_priority_block_not_in_p() -> None:
    f = frame(FrameType.HEADERS, FLAG_END_HEADERS | FLAG_PRIORITY, 1, h2_probe.prio_payload(0, 255, 1) + block())
    assert fp(f) == "|00|0|m,p,a,s"


def test_padded_headers() -> None:
    pad = 7
    f = frame(FrameType.HEADERS, FLAG_END_HEADERS | FLAG_PADDED | FLAG_PRIORITY, 1,
              bytes([pad]) + h2_probe.prio_payload(0, 15, 0) + block("masp") + bytes(pad))
    assert fp(settings([(1, 4096)]), f) == "1:4096|00|0|m,a,s,p"


def test_hpack_huffman_and_indexed() -> None:
    """PS comes from HPACK-decoded names: static-table indexes, Huffman literals and dynamic-table entries alike."""
    enc = hpack.Encoder()
    hb = enc.encode([(":method", "GET"), (":scheme", "https"), (":path", "/x"), (":authority", HOST),
                     ("user-agent", "t")], huffman=True)
    assert hb[0] == 0x82  # indexed :method GET
    assert fp(frame(FrameType.HEADERS, FLAG_END_HEADERS, 1, hb)) == "|00|0|m,s,p,a"


def test_pseudo_header_letters() -> None:
    hb = b"".join(h2_probe.hpack_literal(n, v) for n, v in [
        (":protocol", "websocket"), (":path", "/"), ("method", "GET"), (":method", "GET"), (":path", "/again"),
        (":authority", "x"), ("host", "x"), (":method", "POST")])
    assert fp(frame(FrameType.HEADERS, FLAG_END_HEADERS, 1, hb)) == "|00|0|p,m,a"  # each letter once, others ignored


def test_no_pseudo_headers() -> None:
    hb = h2_probe.hpack_literal("host", "x")
    assert fp(settings([(3, 1)]), frame(FrameType.HEADERS, FLAG_END_HEADERS, 1, hb)) == "3:1|00|0|"


def test_ignored_frames_before_headers() -> None:
    """DATA, RST_STREAM, PING, GOAWAY, unknown types, SETTINGS ACK with payload, stream WU of any size: no effect."""
    noise = [frame(FrameType.DATA, 0, 3, b"abc"), frame(FrameType.RST_STREAM, 0, 3, bytes(4)),
             frame(FrameType.PING, 0, 0, bytes(8)), frame(FrameType.GOAWAY, 0, 0, bytes(8)), frame(0xFA, 0xFF, 0, b"?"),
             frame(FrameType.SETTINGS, h2.FLAG_ACK, 0, bytes(6)), frame(FrameType.WINDOW_UPDATE, 0, 5, b"x")]
    assert fp(*noise, settings([(1, 1)]), *noise, window_update(9), *noise, hdr()) == "1:1|9|0|m,p,a,s"


def test_later_frames_of_a_recorded_kind_are_not_decoded() -> None:
    assert fp(settings([(1, 1)]), frame(FrameType.SETTINGS, 0, 0, bytes(7)), window_update(2),
              frame(FrameType.WINDOW_UPDATE, 0, 0, bytes(3)), hdr()) == "1:1|2|0|m,p,a,s"


# ---------------------------------------------------------------------------------------------- bounds


def test_settings_at_cap() -> None:
    r = h2.compute(stream(settings([(i, i) for i in range(MAX_SETTINGS)]), hdr()))
    assert len(r.settings) == MAX_SETTINGS and not r.overflow


def test_settings_overflow() -> None:
    pairs = [(0x100 + i, i) for i in range(33)]
    r = h2.compute(stream(settings(pairs), window_update(1000), hdr()))
    assert r.overflow
    assert r.settings == tuple(h2.Setting(k, v) for k, v in pairs[:32])
    s = r.fingerprint.split("|")[0]
    assert s.count(";") == 31 and s.startswith("256:0;257:1;") and s.endswith(";287:31")
    assert r.fingerprint.endswith("|1000|0|m,p,a,s") and FP_RE.fullmatch(r.fingerprint)


def test_settings_overflow_in_ignored_frame() -> None:
    """Only the first non-empty SETTINGS frame counts, so a big later one sets no overflow."""
    r = h2.compute(stream(settings([(1, 1)]), settings([(i, i) for i in range(40)]), hdr()))
    assert r.fingerprint == "1:1|00|0|m,p,a,s" and not r.overflow


def test_priorities_at_cap() -> None:
    r = h2.compute(stream(*[priority(3 + 2 * i, 0, i) for i in range(MAX_PRIORITIES)], hdr()))
    assert len(r.priorities) == MAX_PRIORITIES and not r.overflow


def test_priorities_overflow() -> None:
    r = h2.compute(stream(settings([(1, 1)]), *[priority(3 + 2 * i, 0, i) for i in range(40)], window_update(5),
                          hdr()))
    assert r.overflow
    assert r.priorities == tuple(h2.Priority(3 + 2 * i, False, 0, i + 1) for i in range(32))
    p = r.fingerprint.split("|")[2]
    assert p.count(",") == 31 and p.endswith(",65:0:0:32")
    assert r.fingerprint.startswith("1:1|5|") and FP_RE.fullmatch(r.fingerprint)


def test_both_overflow_hash() -> None:
    r = h2.compute(stream(settings([(1, 1)] * 50), *[priority(3, 0, 0)] * 50, hdr()))
    assert r.overflow and len(r.settings) == 32 and len(r.priorities) == 32
    assert r.hash == h2.fingerprint_hash(r.fingerprint)


# ---------------------------------------------------------------------------------------------- capture window


def test_frames_after_first_headers_ignored() -> None:
    base = [settings([(1, 65536)]), window_update(1000), priority(3, 0, 200), hdr("masp")]
    want = h2.compute(stream(*base))
    after = [settings([(4, 1)]), window_update(7), priority(5, 0, 9), hdr("pmsa", 3), frame(FrameType.HEADERS, 0, 5),
             frame(FrameType.CONTINUATION, 0, 9, b"\xff"), frame(FrameType.SETTINGS, 0, 0, b"bad"),
             frame(FrameType.PUSH_PROMISE, 0, 1)]
    assert h2.compute(stream(*base, *after)) == want
    assert h2.compute(stream(*base) + b"\xff" * 50) == want  # not even parsed
    assert h2.compute(stream(*base) + b"\x00\x40\x00") == want  # a partial frame after the block is fine too


def test_settings_only_after_headers() -> None:
    assert fp(hdr(), settings([(1, 65536)]), window_update(5)) == "|00|0|m,p,a,s"


# ---------------------------------------------------------------------------------------------- CONTINUATION


def _split_headers(hb: bytes, cuts: list[int], sid: int = 1, flags: int = FLAG_END_STREAM) -> list[bytes]:
    parts = [hb[a:b] for a, b in zip([0, *cuts], [*cuts, len(hb)])]
    frames = [frame(FrameType.HEADERS, flags, sid, parts[0])]
    frames += [frame(FrameType.CONTINUATION, 0, sid, p) for p in parts[1:-1]]
    frames.append(frame(FrameType.CONTINUATION, FLAG_END_HEADERS, sid, parts[-1]))
    return frames


@pytest.mark.parametrize("cuts", [[10], [1, 2, 3], [0, 5, 40], [17, 17]], ids=["one", "tiny", "empty_first", "empty"])
def test_continuation_split_block(cuts: list[int]) -> None:
    """The block is split at arbitrary byte positions, inside HPACK fields too, and still decodes as one."""
    frames = _split_headers(block("smap"), cuts, sid=3)
    assert fp(settings([(2, 0)]), *frames) == "2:0|00|0|s,m,a,p"


def test_continuation_split_huffman() -> None:
    hb = hpack.Encoder().encode(req_headers(HOST, PATH, "spam"), huffman=True)
    for cut in range(1, len(hb)):
        assert fp(*_split_headers(hb, [cut])) == "|00|0|s,p,a,m"


def test_continuation_interrupted() -> None:
    frames = _split_headers(block(), [10, 20])
    with pytest.raises(ValueError, match="interrupted"):
        h2.compute(stream(frames[0], priority(3, 0, 0), *frames[1:]))
    with pytest.raises(ValueError, match="interrupted"):
        h2.compute(stream(frames[0], frame(FrameType.CONTINUATION, FLAG_END_HEADERS, 3, b"")))


def test_continuation_without_headers() -> None:
    with pytest.raises(ValueError, match="CONTINUATION"):
        fp(frame(FrameType.CONTINUATION, FLAG_END_HEADERS, 1, block()))


def test_continuation_missing() -> None:
    with pytest.raises(IncompleteStreamError, match="inside the first header block"):
        h2.compute(stream(*_split_headers(block(), [10, 20])[:2]))


# ---------------------------------------------------------------------------------------------- partial input


def test_partial_stream_every_offset() -> None:
    full = stream(*CASES["paper_firefox"].frames)
    want = h2.compute(full)
    for k in range(len(full)):
        with pytest.raises(IncompleteStreamError):
            h2.compute(full[:k])
    assert h2.compute(full) == want


def test_byte_by_byte_feed() -> None:
    full = stream(*CASES["paper_firefox"].frames, settings([(9, 9)]))
    end_of_headers = len(stream(*CASES["paper_firefox"].frames))
    p = h2.H2FingerprintParser()
    for i in range(len(full)):
        assert p.feed(full[i:i + 1]) == (i + 1 >= end_of_headers)
        assert p.frozen == (i + 1 >= end_of_headers)
    assert p.result() == h2.compute(full)


def test_incomplete_messages() -> None:
    with pytest.raises(IncompleteStreamError, match="preface"):
        h2.compute(PREFACE[:10])
    with pytest.raises(IncompleteStreamError, match="before the first HEADERS"):
        h2.compute(stream(settings([(1, 1)])))
    assert issubclass(IncompleteStreamError, ValueError)


def test_bad_preface() -> None:
    with pytest.raises(ValueError, match="preface") as e:
        h2.compute(b"GET / HTTP/1.1\r\n\r\n")
    assert not isinstance(e.value, IncompleteStreamError)
    with pytest.raises(ValueError, match="preface"):
        h2.H2FingerprintParser().feed(b"PRI * HTTP/1.1")  # fails as soon as a byte differs


# ---------------------------------------------------------------------------------------------- malformed input


@pytest.mark.parametrize("bad", [
    frame(FrameType.SETTINGS, 0, 0, bytes(7)),
    frame(FrameType.WINDOW_UPDATE, 0, 0, bytes(3)),
    frame(FrameType.WINDOW_UPDATE, 0, 0, bytes(5)),
    frame(FrameType.PRIORITY, 0, 3, bytes(4)),
    frame(FrameType.PRIORITY, 0, 3, bytes(6)),
    frame(FrameType.PUSH_PROMISE, FLAG_END_HEADERS, 1, bytes(4)),
    frame(FrameType.HEADERS, FLAG_END_HEADERS | FLAG_PADDED, 1, b""),
    frame(FrameType.HEADERS, FLAG_END_HEADERS | FLAG_PADDED, 1, b"\x05abc"),
    frame(FrameType.HEADERS, FLAG_END_HEADERS | FLAG_PRIORITY, 1, b"\x00\x00"),
    frame(FrameType.HEADERS, FLAG_END_HEADERS, 1, b"\xff\xff\xff\xff\xff"),  # HPACK index out of range
    frame(FrameType.HEADERS, FLAG_END_HEADERS, 1, b"\x00\x05ab"),  # truncated HPACK literal
    frame(FrameType.HEADERS, FLAG_END_HEADERS, 1, b"\x3f\xe2\x1f"),  # table size update to 4097 (max 4096)
], ids=["settings_7", "wu_3", "wu_5", "prio_4", "prio_6", "push_promise", "pad_missing", "pad_too_long",
        "prio_too_short", "hpack_index", "hpack_truncated", "hpack_table_size"])
def test_malformed(bad: bytes) -> None:
    """The malformed frame is the one the calculator has to decode: the first of its kind."""
    with pytest.raises(ValueError) as e:
        h2.compute(stream(bad, settings([(1, 1)]), window_update(1), hdr()))
    assert not isinstance(e.value, IncompleteStreamError)


@pytest.mark.parametrize("name", ["paper_firefox", "headers_prio_flag", "no_authority"])
def test_fuzz_only_value_error(name: str) -> None:
    """Random corruption either still gives a fingerprint or raises ValueError: never anything else."""
    full = stream(*CASES[name].frames)
    rng = random.Random(f"h2-{name}")
    for _ in range(500):
        b = bytearray(full)
        for _ in range(rng.randint(1, 4)):
            i = rng.randrange(len(PREFACE), len(b))
            op = rng.random()
            if op < 0.6:
                b[i] = rng.randrange(256)
            elif op < 0.8:
                del b[i:i + rng.randint(1, 8)]
            else:
                b[i:i] = rng.randbytes(rng.randint(1, 8))
        try:
            r = h2.compute(bytes(b))
        except ValueError:
            continue
        assert r.hash == h2.fingerprint_hash(r.fingerprint)
        assert FP_RE.fullmatch(r.fingerprint), r.fingerprint


# ---------------------------------------------------------------------------------------------- CLI and probe helpers


def test_cli(capsys: pytest.CaptureFixture[str]) -> None:
    assert h2.main([stream(*CASES["paper_chrome58"].frames).hex()]) == 0
    out = capsys.readouterr().out
    assert "1:65536;3:1000;4:6291456|15663105|0|m,a,s,p" in out and "9a7d2493dea05d3d5d1c2a797b83e8fd" in out
    assert h2.main([PREFACE.hex()]) == 1
    assert "stream ends" in capsys.readouterr().err


@pytest.mark.parametrize(("body", "want"), [
    ('{"akamai_fingerprint": "1:1|00|0|m", "akamai_fingerprint_hash": "x"}', "1:1|00|0|m"),
    ('{"akamai_text": "|00|0|m"}', "|00|0|m"),
    ('{"ja4": "t13d", "h2": "2:0|1|0|m,p"}', "2:0|1|0|m,p"),
    ('{"h2": null}', None),
    ("  3:100|00|0|m,s,a,p\n", "3:100|00|0|m,s,a,p"),
    ("connection is not HTTP/2", "connection is not HTTP/2"),
])
def test_fingerprint_from_body(body: str, want: str | None) -> None:
    assert h2_probe.fingerprint_from_body(body) == want
    assert h2_clients.extract_fp(body) == (want if want and FP_RE.fullmatch(want) else None)
