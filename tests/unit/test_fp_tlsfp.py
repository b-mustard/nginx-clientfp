# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""TLSFP reference calculator (tools/clientfp/fp/tlsfp.py) against the spec text (doc/nDPI_TLS_Fingerprint.md) and
decisions 022-027. Expected hash inputs are written out by hand and hashed here, never taken from the implementation."""

from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path

import pytest

from clientfp.fp import ja4 as ja4mod
from clientfp.fp import tlsfp
from clientfp.fp.tls import ClientHello, ClientHelloError, Extension, Proto, encode_client_hello, parse_client_hello
from clientfp.fp.tlsfp import (EXT_ALPN, EXT_SIGALGS, EXT_SNI, EXT_SUPPORTED_GROUPS, EXT_SUPPORTED_VERSIONS,
                               NO_GROUPS, alpn_ext, compute, supported_versions_ext, u16_vector_ext)

REPO = Path(__file__).resolve().parents[2]
SNI = Extension(EXT_SNI, b"\x00\x0e\x00\x00\x0bexample.com")
TLSFP_RE = re.compile(r"[tqd](13|12|11|10|s3|d1|d2|d3|00)[di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}")


def h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def fp(ciphers: tuple[int, ...] = (0x1301,), exts: tuple[Extension, ...] = (), legacy: int = 0x0303,
       proto: Proto = "t") -> tlsfp.TLSFPFingerprint:
    return compute(parse_client_hello(encode_client_hello(legacy, ciphers, list(exts))), proto)


def test_selftest() -> None:
    assert tlsfp.selftest() == []


def test_spec_vector1_supported_groups_hash() -> None:
    r = fp(exts=(u16_vector_ext(EXT_SUPPORTED_GROUPS, (0x001E, 0x001D, 0x0019, 0x0018, 0x0017)),))
    assert r.input_d == "0017,0018,0019,001d,001e"
    assert r.d == "0a47a2b05960"                                      # Appendix A, vector 1


def test_registry_v1() -> None:
    assert tlsfp.EPHEMERAL_V1 == {0x15, 0x23, 0x29, 0x2A, 0x2C, 0x2D}
    assert tlsfp.REGISTRY_VERSION == 1 and fp().registry == 1


@pytest.mark.parametrize("eph", sorted(tlsfp.EPHEMERAL_V1))
def test_each_ephemeral_extension_is_removed(eph: int) -> None:
    with_eph = fp(exts=(SNI, Extension(0x0016, b""), Extension(eph, b""), Extension(0x0017, b"")))
    without = fp(exts=(SNI, Extension(0x0016, b""), Extension(0x0017, b"")))
    assert with_eph.a == without.a == "t12d0103" + "00"
    assert with_eph.input_c == without.input_c == "0016,0017_"
    assert with_eph.tlsfp == without.tlsfp


def test_neighbours_of_ephemeral_codes_are_kept() -> None:
    exts = tuple(Extension(t, b"") for t in (0x0014, 0x0016, 0x0022, 0x0024, 0x0028, 0x002E, 0x0115, 0x1523))
    r = fp(exts=exts)
    assert r.a[6:8] == "08"
    assert r.input_c == "0014,0016,0022,0024,0028,002e,0115,1523_"


def test_sni_and_alpn_counted_but_not_hashed() -> None:
    r = fp(exts=(SNI, alpn_ext(b"h2"), Extension(0x0017, b"")))
    assert r.a == "t12d0103h2"
    assert r.input_c == "0017_"
    assert r.c == h("0017_")


def test_grease_is_rfc8701_only() -> None:
    """§6.2: 0x?A?A with both octets equal. 0x1a2a matches the spec's bitwise shorthand but is not GREASE (d027)."""
    r = fp(ciphers=(0x2A2A, 0x1A2A, 0x1301), exts=(Extension(0x3A3A, b""), Extension(0x0A1A, b""),
                                                   u16_vector_ext(EXT_SUPPORTED_GROUPS, (0xFAFA, 0x1A2A, 0x001D))))
    assert r.input_b == "1301,1a2a"
    assert r.a[4:8] == "0202"
    assert r.input_c == "000a,0a1a_"
    assert r.input_d == "001d,1a2a"


def test_sigalgs_keep_grease_and_wire_order() -> None:
    r = fp(exts=(u16_vector_ext(EXT_SIGALGS, (0x0804, 0x0A0A, 0x0403, 0x0804)),))
    assert r.input_c == "000d_0804,0a0a,0403,0804"


def test_c_underscore_always_present() -> None:
    assert fp().input_c == "_" and fp().c == h("_")
    assert fp(exts=(Extension(0x0017, b""),)).input_c == "0017_"


def test_b_sorted_like_spec_6_5() -> None:
    r = fp(ciphers=tlsfp.SPEC_VECTOR1_CIPHERS)
    assert r.input_b == "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
    assert r.b == "8daaf6152771"


def test_no_dedup_and_uncapped_inputs() -> None:
    ciphers = tuple(range(0x0100, 0x0100 + 150)) + (0x0100,)
    exts = tuple(Extension(0x7000 + i, b"") for i in range(120)) + (Extension(0x7000, b""),)
    r = fp(ciphers=ciphers, exts=exts)
    assert r.a == "t12i999900"                                        # §7.5: display capped
    assert r.input_b.count(",") == 150 and r.input_b.startswith("0100,0100,0101")
    assert r.input_c is not None
    assert r.input_c.startswith("7000,7000,7001") and r.input_c.count(",") == 120


@pytest.mark.parametrize(("versions", "legacy", "want"), [
    (None, 0x0303, "12"), (None, 0x0301, "10"), (None, 0x0300, "s3"), (None, 0x0002, "00"), (None, 0xFEFD, "d2"),
    ((0x0304, 0x0303), 0x0303, "13"), ((0x0303, 0x0304), 0x0303, "13"), ((0x5A5A, 0x0304), 0x0303, "13"),
    ((0x7A7A,), 0x0301, "10"), ((0x7F1C, 0x0304), 0x0303, "00"), ((), 0x0303, "12"),
])
def test_version(versions: tuple[int, ...] | None, legacy: int, want: str) -> None:
    exts = () if versions is None else (supported_versions_ext(*versions),)
    assert fp(legacy=legacy, exts=exts).a[1:3] == want


@pytest.mark.parametrize(("names", "want"), [
    ((b"h2", b"http/1.1"), "h2"), ((b"http/1.1",), "h1"), ((b"H2",), "h2"), ((b"HTTP/1.1",), "h1"),
    ((b"Ab",), "ab"), ((b"a",), "aa"), ((b"\xab\xcd",), "ad"), ((b"#x",), "28"), ((b"x#",), "73"),
    ((b"\r\n",), "0a"), ((b"",), "00"), ((), "00"), ((b"", b"h2"), "00"),
])
def test_alpn(names: tuple[bytes, ...], want: str) -> None:
    assert fp(exts=(alpn_ext(*names),)).a[8:] == want
    assert re.fullmatch(r"[0-9a-z]{2}", want)


def test_alpn_absent() -> None:
    assert fp().a.endswith("00")


def test_proto() -> None:
    assert fp(proto="q").a[0] == "q"
    with pytest.raises(ValueError):
        compute(ClientHello(0x0303, (0x1301,), ()), "x")  # type: ignore[arg-type]


def test_groups_absent_or_grease_only() -> None:
    assert fp().d == NO_GROUPS
    assert fp(exts=(u16_vector_ext(EXT_SUPPORTED_GROUPS, (0x0A0A, 0x2A2A)),)).d == NO_GROUPS
    r = fp(exts=(u16_vector_ext(EXT_SUPPORTED_GROUPS, ()),))
    assert (r.d, r.input_d) == (NO_GROUPS, None)
    assert len(fp().tlsfp) == 49


def test_groups_not_deduplicated() -> None:
    r = fp(exts=(u16_vector_ext(EXT_SUPPORTED_GROUPS, (0x001D, 0x0017, 0x001D)),))
    assert r.input_d == "0017,001d,001d" and r.d == h("0017,001d,001d")


# §9: a malformed extension empties only the field that decodes it

def _raw(t: int, data: bytes) -> Extension:
    return Extension(t, data)


@pytest.mark.parametrize("data", [b"", b"\x00", b"\x00\x02\x00", b"\x00\x02\x00\x1d\x00", b"\x00\x03\x00\x1d\x00",
                                  b"\x00\x04\x00\x1d"])
def test_malformed_groups_empty_d_only(data: bytes) -> None:
    r = fp(exts=(SNI, _raw(EXT_SUPPORTED_GROUPS, data)))
    assert r.d == "" and r.input_d is None
    assert r.a == "t12d0102" + "00" and r.c == h("000a_")
    assert r.tlsfp == f"{r.a}_{r.b}_{r.c}_"


@pytest.mark.parametrize("data", [b"", b"\x00\x01\x04", b"\x00\x02\x04\x03\x00", b"\x00\x03\x04\x03\x05"])
def test_malformed_sigalgs_empty_c_only(data: bytes) -> None:
    r = fp(exts=(_raw(EXT_SIGALGS, data), u16_vector_ext(EXT_SUPPORTED_GROUPS, (0x001D,))))
    assert r.c == "" and r.input_c is None
    assert r.a and r.d == h("001d")
    assert r.tlsfp == f"{r.a}_{r.b}__{r.d}"


@pytest.mark.parametrize(("ext", "data"), [
    (EXT_ALPN, b"\x00\x03\x02h2\x00"), (EXT_ALPN, b"\x00\x04\x02h2"), (EXT_ALPN, b"\x00\x02\x05h"), (EXT_ALPN, b""),
    (EXT_SUPPORTED_VERSIONS, b"\x03\x03\x04\x03"), (EXT_SUPPORTED_VERSIONS, b"\x02\x03\x04\x00"),
    (EXT_SUPPORTED_VERSIONS, b""),
])
def test_malformed_a_inputs_empty_a_only(ext: int, data: bytes) -> None:
    r = fp(exts=(_raw(ext, data),))
    assert r.a == ""
    assert r.b and r.c and r.d == NO_GROUPS
    assert r.tlsfp.startswith("_")


def test_first_occurrence_decoded() -> None:
    r = fp(exts=(alpn_ext(b"h2"), alpn_ext(b"\x00"),
                 u16_vector_ext(EXT_SUPPORTED_GROUPS, (0x001D,)), u16_vector_ext(EXT_SUPPORTED_GROUPS, (0x0017,))))
    assert r.a.endswith("h2") and r.a[6:8] == "04"
    assert r.input_d == "001d" and r.input_c == "000a,000a_"


@pytest.mark.parametrize("msg", [
    b"", b"\x01", b"\x02\x00\x00\x00", b"\x01\x00\x00\x05\x03\x03",
    encode_client_hello(0x0303, (0x1301,), []) + b"\x00",
    encode_client_hello(0x0303, (0x1301,), [Extension(0x0017, b"")])[:-1],
])
def test_broken_framing_has_no_tlsfp(msg: bytes) -> None:
    with pytest.raises(ClientHelloError):
        tlsfp.from_bytes(msg)


def test_from_records() -> None:
    msg = encode_client_hello(0x0303, (0x1301,), [SNI])
    rec = b"\x16\x03\x01" + struct.pack(">H", len(msg)) + msg
    assert tlsfp.from_bytes(rec) == tlsfp.from_bytes(msg)


VECTORS = json.loads((REPO / "doc" / "ja4_vectors.json").read_text())


@pytest.mark.parametrize("v", VECTORS, ids=[f"{i:02d}" for i in range(len(VECTORS))])
def test_recorded_hellos(v: dict[str, str]) -> None:
    """Every real ClientHello we captured: well-formed TLSFP, b equal to JA4_b (§6.5), d present iff groups are."""
    msg = bytes.fromhex(v["client_hello_hex"])
    proto = "q" if v["ja4"][0] == "q" else "t"
    r = tlsfp.from_bytes(msg, proto)  # type: ignore[arg-type]
    assert TLSFP_RE.fullmatch(r.tlsfp), r.tlsfp
    assert r.b == ja4mod.from_bytes(msg, proto).ja4.split("_")[1]  # type: ignore[arg-type]
    ch = parse_client_hello(msg)
    assert (r.d == NO_GROUPS) == (ch.ext(EXT_SUPPORTED_GROUPS) is None)


def test_cli(capsys: pytest.CaptureFixture[str]) -> None:
    msg = encode_client_hello(0x0303, (0x1301,), [SNI])
    assert tlsfp.main([msg.hex()]) == 0
    out = capsys.readouterr().out
    assert "tlsfp    t12d010100_" in out and "registry 1" in out
    assert tlsfp.main(["zz"]) == 1
