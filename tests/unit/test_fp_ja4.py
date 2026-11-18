# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""clientfp.fp.ja4 against doc/ja4_sig.md: worked examples, ALPN table, the 81 recorded vectors, malformed input."""

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from clientfp.fp import ja4
from clientfp.fp.ja4 import (EXT_ALPN, EXT_SIGALGS, EXT_SUPPORTED_VERSIONS, ClientHelloError, Extension, alpn_ext,
                             encode_client_hello, sigalgs_ext, supported_versions_ext)

DOC = Path(__file__).resolve().parents[2] / "doc"
JA4_RE = re.compile(r"[tqd][0-9s]{2}[di]\d{4}[0-9a-zA-Z]{2}_[0-9a-f]{12}_[0-9a-f]{12}")


VECTORS: list[dict[str, Any]] = json.loads((DOC / "ja4_vectors.json").read_text())


def vector(server: str, name: str) -> bytes:
    return bytes.fromhex(next(v["client_hello_hex"] for v in VECTORS if v["server"] == server and v["name"] == name))


def to_records(msg: bytes, size: int = 16384) -> bytes:
    """Wrap a handshake message in TLS handshake records of at most `size` bytes."""
    return b"".join(b"\x16\x03\x01" + len(chunk).to_bytes(2, "big") + chunk
                    for chunk in (msg[i:i + size] for i in range(0, len(msg), size)))


# ---------------------------------------------------------------------------------------------- spec examples


def test_selftest() -> None:
    assert ja4.selftest() == []


def test_selftest_cli(capsys: pytest.CaptureFixture[str]) -> None:
    assert ja4.main(["--selftest"]) == 0
    assert capsys.readouterr().out.strip() == "selftest OK"


def test_spec_worked_example() -> None:
    r = ja4.from_bytes(ja4.spec_example_hello())
    assert r.a == "t13d1516h2"
    assert r.b_raw == "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
    assert r.c_raw == ("0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_"
                       "0403,0804,0401,0503,0805,0501,0806,0601")
    assert r.ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert r.ja4_o == "t13d1516h2_acb858a92679_18f69afefd3d"


def test_spec_example_without_sigalgs() -> None:
    """With no sigalgs, c_raw = E without `_` (spec: 6d807ffa2a79)."""
    ch = ja4.parse_client_hello(ja4.spec_example_hello())
    empty_list = [sigalgs_ext() if e.type == EXT_SIGALGS else e for e in ch.extensions]
    r = ja4.compute(ja4.ClientHello(ch.legacy_version, ch.ciphers, tuple(empty_list)))
    assert r.c_raw == "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01"
    assert r.ja4 == "t13d1516h2_8daaf6152771_6d807ffa2a79"
    no_ext = tuple(e for e in ch.extensions if e.type != EXT_SIGALGS)
    r = ja4.compute(ja4.ClientHello(ch.legacy_version, ch.ciphers, no_ext))
    assert r.c_raw == "0005,000a,000b,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01"  # 000d itself is gone too


# doc/ja4_sig.md §3 a.6, "Examples" table: first ALPN value -> result
ALPN_DOC_TABLE: list[tuple[bytes, str]] = [
    (b"h2", "h2"), (b"http/1.1", "h1"), (b"a", "aa"), (b"\xab", "ab"), (b"\xab\xcd", "ad"), (b"\x20\x61", "21"),
    (b"\x30\xab", "3b"), (b"\x61\x20", "60"), (b"\x30\x31\xab\xcd", "3d"), (b"\x30\xab\xcd\x31", "01"), (b"#x", "28"),
]


def _doc_alpn_value(cell: str) -> bytes:
    tokens = cell.split()
    if all(re.fullmatch(r"[0-9A-Fa-f]{2}", t) for t in tokens):
        return bytes.fromhex(cell)
    return cell.encode()


def test_alpn_table_matches_doc() -> None:
    text = (DOC / "ja4_sig.md").read_text()
    section = text[text.index("first ALPN value | result"):text.index("### b")]
    rows = re.findall(r"^\s*\| `([^`]+)`(?: \([^)]*\))? \| `([^`]+)` \|\s*$", section, re.M)
    assert [(_doc_alpn_value(v), want) for v, want in rows] == ALPN_DOC_TABLE


@pytest.mark.parametrize(("value", "want"), ALPN_DOC_TABLE, ids=[v.hex() for v, _ in ALPN_DOC_TABLE])
def test_alpn_doc_examples(value: bytes, want: str) -> None:
    hello = encode_client_hello(0x0303, [0x1301], [alpn_ext(value, b"http/1.1")])
    assert ja4.from_bytes(hello).a[-2:] == want


def test_grease() -> None:
    assert [v for v in range(0x10000) if ja4.is_grease(v)] == [0x0A0A + 0x1010 * i for i in range(16)]


# ---------------------------------------------------------------------------------------------- recorded vectors


def test_vector_set() -> None:
    assert len(VECTORS) == 81
    assert sum(v["server"] == "kittens.sh" for v in VECTORS) == 39
    assert sum(v["server"] == "thumbprint.me" for v in VECTORS) == 42


@pytest.mark.parametrize("vec", VECTORS, ids=[f"{v['server']}-{v['name']}" for v in VECTORS])
def test_vector(vec: dict[str, Any]) -> None:
    proto = vec["ja4"][0]
    assert proto in ja4.PROTOS
    msg = bytes.fromhex(vec["client_hello_hex"])
    want = {k: vec[k] for k in ja4.FORMS}
    assert ja4.from_bytes(msg, proto).forms() == want
    assert set(vec["server_confirmed"]) <= set(ja4.FORMS)
    # the same hello inside TLS records, whole and fragmented, reassembles to the same message
    for size in (16384, 64):
        assert ja4.from_bytes(to_records(msg, size), proto).forms() == want


# ---------------------------------------------------------------------------------------------- zero-length lists


def test_no_ciphers() -> None:
    r = ja4.from_bytes(encode_client_hello(0x0303, [], [supported_versions_ext(0x0304)]))
    assert r.a == "t13i000100"
    assert r.ja4.split("_")[1] == ja4.ZERO_HASH and r.b_raw == ""


def test_only_grease_ciphers() -> None:
    assert ja4.from_bytes(encode_client_hello(0x0303, [0x0A0A, 0xFAFA], [])).ja4 == \
        f"t12i000000_{ja4.ZERO_HASH}_{ja4.ZERO_HASH}"


@pytest.mark.parametrize("exts", [None, []], ids=["no_extensions_block", "empty_extensions_block"])
def test_no_extensions(exts: list[Extension] | None) -> None:
    r = ja4.from_bytes(encode_client_hello(0x0303, [0x002F, 0x0035], exts))
    assert r.ja4 == f"t12i020000_{ja4.hash12('002f,0035')}_{ja4.ZERO_HASH}"
    assert r.c_raw == ""


def test_only_grease_extensions() -> None:
    r = ja4.from_bytes(encode_client_hello(0x0303, [0x002F], [Extension(0x0A0A, b""), Extension(0x1A1A, b"\x00")]))
    assert r.a == "t12i010000" and r.ja4.endswith(ja4.ZERO_HASH)


@pytest.mark.parametrize("alpn", [Extension(EXT_ALPN, b"\x00\x00"), alpn_ext(), alpn_ext(b"", b"h2")],
                         ids=["empty_list", "empty_list_builder", "empty_first_value"])
def test_empty_alpn(alpn: Extension) -> None:
    assert ja4.from_bytes(encode_client_hello(0x0303, [0x1301], [alpn])).a == "t12i010100"


def test_empty_sigalgs_list() -> None:
    r = ja4.from_bytes(encode_client_hello(0x0303, [0x1301], [sigalgs_ext(), Extension(0x000A, b"")]))
    assert r.c_raw == "000a,000d"


@pytest.mark.parametrize("versions", [(), (0x2A2A,), (0x2A2A, 0x3A3A)], ids=["empty", "grease", "grease2"])
def test_supported_versions_without_real_value(versions: tuple[int, ...]) -> None:
    """Spec is silent on a GREASE-only list: fall back to legacy_version."""
    r = ja4.from_bytes(encode_client_hello(0x0302, [0x1301], [supported_versions_ext(*versions)]))
    assert r.a.startswith("t11")


def test_version_rule() -> None:
    def version(legacy: int, *sv: int) -> str:
        exts = [supported_versions_ext(*sv)] if sv else []
        return ja4.from_bytes(encode_client_hello(legacy, [0x1301], exts)).a[1:3]
    assert version(0x0303, 0x0304, 0x0303) == "13"
    assert version(0x0303, 0x0303, 0x0304) == "13"  # numerically highest, not first
    assert version(0x0303, 0x7F1C, 0x0304) == "00"  # literal max: unknown draft version
    assert version(0x0303) == "12"
    assert version(0x0300) == "s3"
    assert version(0xFEFD) == "d2"
    assert version(0x1234) == "00"


def test_counts_capped_at_99() -> None:
    exts = [Extension(0x1000 + i, b"") for i in range(120)]
    r = ja4.from_bytes(encode_client_hello(0x0303, list(range(0x0100, 0x0100 + 150)), exts))
    assert r.a == "t12i999900"


def test_duplicate_extension_counts_twice() -> None:
    r = ja4.from_bytes(encode_client_hello(0x0303, [0x1301], [Extension(0x1234, b""), Extension(0x1234, b"")]))
    assert r.a == "t12i010200" and r.c_raw == "1234,1234"


def test_proto() -> None:
    hello = encode_client_hello(0x0303, [0x1301], [])
    assert ja4.from_bytes(hello, "q").a.startswith("q")
    assert ja4.from_bytes(hello, "d").a.startswith("d")
    with pytest.raises(ValueError):
        ja4.from_bytes(hello, "x")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------------------------- malformed input

SAMPLES = [("kittens.sh", "curl_default_h2"), ("thumbprint.me", "chrome"), ("thumbprint.me", "tlslite_grease"),
           ("thumbprint.me", "chrome_h3")]
SAMPLE_IDS = [n for _, n in SAMPLES]


@pytest.mark.parametrize("sample", SAMPLES, ids=SAMPLE_IDS)
def test_truncated_message_every_offset(sample: tuple[str, str]) -> None:
    msg = vector(*sample)
    for k in range(len(msg)):
        with pytest.raises(ValueError):
            ja4.from_bytes(msg[:k])


def _extensions_offset(msg: bytes) -> int:
    p = 4 + 2 + 32
    p += 1 + msg[p]
    p += 2 + int.from_bytes(msg[p:p + 2], "big")
    return p + 1 + msg[p]


@pytest.mark.parametrize("sample", SAMPLES, ids=SAMPLE_IDS)
def test_truncated_body_every_offset(sample: tuple[str, str]) -> None:
    """The handshake length is patched to the truncated size, so the inner lengths have to catch the truncation.
    The one valid cut is right before the extensions block: a hello without extensions."""
    msg = vector(*sample)
    ext_at = _extensions_offset(msg)
    nc = ja4.from_bytes(msg).a[4:6]
    for k in range(4, len(msg)):
        cut = b"\x01" + (k - 4).to_bytes(3, "big") + msg[4:k]
        if k == ext_at:
            assert ja4.from_bytes(cut).a[3:] == f"i{nc}0000"
            continue
        with pytest.raises(ValueError):
            ja4.from_bytes(cut)


@pytest.mark.parametrize("sample", SAMPLES, ids=SAMPLE_IDS)
def test_truncated_records_every_offset(sample: tuple[str, str]) -> None:
    records = to_records(vector(*sample), 200)
    for k in range(len(records)):
        with pytest.raises(ValueError):
            ja4.from_bytes(records[:k])


def test_trailing_bytes() -> None:
    msg = vector("kittens.sh", "curl_default_h2")
    with pytest.raises(ValueError, match="trailing"):
        ja4.from_bytes(msg + b"\x00")  # after the handshake message
    body = msg[4:] + b"\x00"
    with pytest.raises(ValueError, match="trailing"):
        ja4.from_bytes(b"\x01" + len(body).to_bytes(3, "big") + body)  # inside the body, after the extensions block


@dataclass(frozen=True)
class LengthField:
    name: str
    offset: int
    width: int
    room: int
    """Bytes available to this length's contents inside the enclosing structure."""


def length_fields(msg: bytes) -> list[LengthField]:
    """Every length field of a ClientHello whose contents the parser reads (decoded extensions: first occurrence)."""
    out = [LengthField("handshake", 1, 3, len(msg) - 4)]
    p = 4 + 2 + 32
    for name, width in (("session_id", 1), ("cipher_suites", 2), ("compression_methods", 1)):
        out.append(LengthField(name, p, width, len(msg) - p - width))
        p += width + int.from_bytes(msg[p:p + width], "big")
    if p == len(msg):
        return out
    out.append(LengthField("extensions", p, 2, len(msg) - p - 2))
    block_end = len(msg)
    p += 2
    decoded: set[int] = set()
    while p < block_end:
        t, ln = int.from_bytes(msg[p:p + 2], "big"), int.from_bytes(msg[p + 2:p + 4], "big")
        out.append(LengthField(f"ext {t:04x}", p + 2, 2, block_end - p - 4))
        data, data_end = p + 4, p + 4 + ln
        if t in (EXT_ALPN, EXT_SIGALGS, EXT_SUPPORTED_VERSIONS) and t not in decoded:
            decoded.add(t)
            width = 1 if t == EXT_SUPPORTED_VERSIONS else 2
            out.append(LengthField(f"ext {t:04x} list", data, width, ln - width))
            if t == EXT_ALPN:
                q = data + 2
                while q < data_end:
                    out.append(LengthField(f"ALPN name at {q}", q, 1, data_end - q - 1))
                    q += 1 + msg[q]
        p = data_end
    return out


def _patch(msg: bytes, f: LengthField, value: int) -> bytes:
    return msg[:f.offset] + value.to_bytes(f.width, "big") + msg[f.offset + f.width:]


@pytest.mark.parametrize("sample", SAMPLES, ids=SAMPLE_IDS)
def test_bogus_lengths(sample: tuple[str, str]) -> None:
    """A length longer than its enclosing structure, or a u16 list of odd length, is always an error."""
    msg = vector(*sample)
    fields = length_fields(msg)
    assert {"handshake", "cipher_suites", "extensions", "ext 0010 list", "ext 000d list"} <= {f.name for f in fields}
    for f in fields:
        limit = (1 << (8 * f.width)) - 1
        for bogus in (f.room + 1, limit):
            if f.room < bogus <= limit:
                with pytest.raises(ValueError):
                    ja4.from_bytes(_patch(msg, f, bogus))
        if f.name in ("cipher_suites", "ext 000d list", "ext 002b list"):
            with pytest.raises(ValueError):
                ja4.from_bytes(_patch(msg, f, int.from_bytes(msg[f.offset:f.offset + f.width], "big") - 1))


@pytest.mark.parametrize("data", [b"", b"\x00", b"\x00\x05\x02h2", b"\x00\x03\x02h2\x00", b"\x00\x04\x02h2\x05"],
                         ids=["empty", "short_length", "list_too_long", "trailing", "name_too_long"])
def test_malformed_alpn(data: bytes) -> None:
    with pytest.raises(ClientHelloError):
        ja4.from_bytes(encode_client_hello(0x0303, [0x1301], [Extension(EXT_ALPN, data)]))


@pytest.mark.parametrize(("ext_type", "data"), [
    (EXT_SIGALGS, b""), (EXT_SIGALGS, b"\x00"), (EXT_SIGALGS, b"\x00\x03\x04\x03\x05"),
    (EXT_SIGALGS, b"\x00\x04\x04\x03"), (EXT_SUPPORTED_VERSIONS, b""), (EXT_SUPPORTED_VERSIONS, b"\x03\x03\x04\x03"),
    (EXT_SUPPORTED_VERSIONS, b"\x04\x03\x04"),
])
def test_malformed_lists(ext_type: int, data: bytes) -> None:
    with pytest.raises(ClientHelloError):
        ja4.from_bytes(encode_client_hello(0x0303, [0x1301], [Extension(ext_type, data)]))


def test_opaque_extension_data_is_not_parsed() -> None:
    """SNI and every extension JA4 does not decode may hold anything; so may a 2nd ALPN extension."""
    exts = [Extension(0x0000, b"\xff"), Extension(0x000A, b"\x00\x01"), alpn_ext(b"h2"), Extension(EXT_ALPN, b"\x01")]
    assert ja4.from_bytes(encode_client_hello(0x0303, [0x1301], exts)).a == "t12d0104h2"


def test_not_a_client_hello() -> None:
    with pytest.raises(ValueError, match="not a ClientHello"):
        ja4.from_bytes(b"\x02" + bytes(3))
    with pytest.raises(ValueError):
        ja4.from_bytes(b"\x17\x03\x03\x00\x01\x00")  # application data record


@pytest.mark.parametrize("sample", SAMPLES, ids=SAMPLE_IDS)
def test_fuzz_only_value_error(sample: tuple[str, str]) -> None:
    """Random corruption either still parses or raises ValueError: never IndexError, struct.error, ..."""
    msg = vector(*sample)
    rng = random.Random(f"ja4-{sample}")
    for _ in range(400):
        b = bytearray(msg)
        for _ in range(rng.randint(1, 4)):
            i = rng.randrange(len(b))
            op = rng.random()
            if op < 0.6:
                b[i] = rng.randrange(256)
            elif op < 0.8:
                del b[i:i + rng.randint(1, 8)]
            else:
                b[i:i] = rng.randbytes(rng.randint(1, 8))
        for data in (bytes(b), to_records(bytes(b), 100)):
            try:
                r = ja4.from_bytes(data)
            except ValueError:
                continue
            assert JA4_RE.fullmatch(r.ja4)


# ---------------------------------------------------------------------------------------------- CLI


def test_cli(capsys: pytest.CaptureFixture[str]) -> None:
    v = VECTORS[0]
    assert ja4.main([v["client_hello_hex"]]) == 0
    out = {k: val for k, val in (line.split(maxsplit=1) for line in capsys.readouterr().out.splitlines())}
    assert {k: out[k] for k in ja4.FORMS} == {k: v[k] for k in ja4.FORMS}
    assert set(out) == {*ja4.FORMS, "a", "b_raw", "c_raw"}


def test_cli_proto_and_errors(capsys: pytest.CaptureFixture[str]) -> None:
    hello = encode_client_hello(0x0303, [0x1301], []).hex()
    assert ja4.main(["--proto", "q", hello]) == 0
    assert capsys.readouterr().out.startswith("ja4     q12i")
    assert ja4.main([hello[:-2]]) == 1
    assert "truncated" in capsys.readouterr().err
    assert ja4.main(["zz"]) == 1
