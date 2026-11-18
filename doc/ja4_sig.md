# JA4 (TLS client) signature — implementation spec for nginx

This is a condensed, normative version of [FoxIO's JA4.md](https://github.com/FoxIO-LLC/ja4/blob/16b96d95c220762cf658f67d678cda2aac95c81e/technical_details/JA4.md) (upstream commit `16b96d9`, 2026-09-22),
written for implementing JA4 inside nginx (`nginx_module/`), independently of the TLS library.
Every rule below was checked on 2026-09-28 against two independent reference servers:

- `https://kittens.sh/api/ja4`. Its `/api/all` also returns `ja4_r` and the raw ClientHello.
  Its TLS stack behaves like Go's `crypto/tls`.
- `https://thumbprint.me/api/v1/probe`. It returns all four forms (`ja4`, `ja4_r`, `ja4_o`, `ja4_ro`), answers with
  `server: nginx`, and also speaks HTTP/3.

81 live handshakes completed across the two servers, and every one matched the local computation. This includes curl,
wget, Python urllib, httpx and niquests, three browser profiles, HTTP/3, and a set of crafted edge-case hellos. See
[§8](#8-verification).

Scope: **JA4 only** (the client fingerprint). JA4S, JA4H, JA4X and so on are out of scope.

---

## 1. Output

```
JA4    = <a>_<b>_<c>                         e.g. t13d1516h2_8daaf6152771_e5627efa2ab1   (always 36 chars)
JA4_r  = <a>_<b_raw>_<c_raw>                 sorted lists, un-hashed
JA4_o  = <a>_<hash(b_orig)>_<hash(c_orig)>   wire order, SNI and ALPN kept
JA4_ro = <a>_<b_orig>_<c_orig>               wire order, un-hashed
```

The canonical value is `JA4`. The other three are debugging and analytics forms. All four forms were verified against
thumbprint.me in every case, as well as the spec's worked example (`t13d1516h2_acb858a92679_18f69afefd3d`).

`a` is 10 characters: `[proto:1][version:2][sni:1][ciphers:2][extensions:2][alpn:2]`.

## 2. Values to extract from the ClientHello

Only these values feed the fingerprint. Everything else in the hello is ignored: random, session_id, compression
methods, supported_groups, key_share, ec_point_formats, the SNI *value*, and the record-layer version.

| # | Value | Where (ClientHello body) | Used for |
|---|-------|--------------------------|----------|
| 1 | transport | connection property, not in the hello | `a[0]`: `t` TLS/TCP, `q` QUIC, `d` DTLS |
| 2 | `legacy_version` u16 | bytes 0–1 of body | version, **only if** ext `0x002b` is absent |
| 3 | `cipher_suites` u16[] | after session_id | count, `b` |
| 4 | extension **types** u16[], wire order, *all* of them | extensions block | count, `c`, SNI flag |
| 5 | ALPN first protocol name (bytes) | ext `0x0010` | `a[8..9]` |
| 6 | `supported_versions` u16[] | ext `0x002b` | version |
| 7 | `signature_algorithms` u16[], wire order | ext `0x000d` | tail of `c` |

Wire layout of the handshake message. This is exactly the buffer the module's capture produces ([§5](#5-capture-in-nginx)):

```
off  size          field
0    1             msg_type = 0x01 (ClientHello)
1    3             length (big-endian) of body
4    2             legacy_version
6    32            random
38   1 + n         session_id  (u8 length prefix)
     2 + 2k        cipher_suites (u16 length prefix, k suites)
     1 + m         compression_methods (u8 length prefix)
     [2 + ...]     extensions (u16 length prefix; the whole block MAY be absent -> zero extensions)
                   each: u16 type, u16 len, len bytes data
ext data formats (ClientHello forms):
  0x0000 server_name          presence only
  0x0010 ALPN                 u16 list_len, then { u8 len, bytes }*        -> take the FIRST entry
  0x000d signature_algorithms u16 list_len, then u16*
  0x002b supported_versions   u8  list_len, then u16*
```

Parse defensively. Every length must be bounds-checked against its enclosing length. Truncated or malformed input
means no fingerprint (the TLS library aborts such a handshake anyway).

## 3. Algorithm

**GREASE** (RFC 8701): `v` is GREASE iff `(v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)`, which gives the 16 values
`0x0a0a, 0x1a1a, … 0xfafa`.
Remove GREASE values from every list before any use: ciphers, extension types, supported_versions and sigalgs.
Nothing else is filtered.

Hex formatting: every value is exactly 4 lowercase hex digits (`%04x`), and lists are joined with `,` with no spaces.
`hash12(s)` is the first 12 hex characters of `sha256(s)`, lowercase. If `s == ""`, `hash12` returns `000000000000`
without hashing.

### a — `[proto][version][sni][nc][ne][alpn]`

1. **proto**: `t` for TLS over TCP. `q` if the hello arrived over QUIC (in nginx: an HTTP/3 or QUIC connection).
   `d` is for DTLS, which nginx never produces.
   - Over QUIC, every other rule is unchanged. The QUIC hello carries `0039` quic_transport_parameters, which counts
     like any other extension, and its ALPN is usually `h3`.
   - Verified: HTTP/3 hellos from curl_cffi (Chrome profile) and niquests/qh3, decrypted from their QUIC Initial
     packets, gave the same `q13d…` values as thumbprint.me in all four forms.
2. **version**:
   - If ext `0x002b` is present, use the **numerically highest** non-GREASE value in it.
   - Otherwise use `legacy_version`.
   - Ignore the record-layer version.
   - Map the value: `0304→13 0303→12 0302→11 0301→10 0300→s3 0002→s2 feff→d1 fefd→d2 fefc→d3`. Any other value
     gives `00`.
   - The rule is literal. If a client lists an unknown value that is higher than `0x0304`, for example draft
     `0x7f1c`, the version is `00`. This was verified: both reference servers returned `t00…`.
   - If `0x002b` contains only GREASE, the spec says nothing. Fall back to `legacy_version`. This case cannot be
     verified: both reference servers reject such hellos with a `protocol_version` alert, and so does nginx-clientfp.
     It only matters if JA4 is logged for failed handshakes.
3. **sni**: `d` if extension type `0x0000` is present (the value is irrelevant), otherwise `i`.
4. **nc**: the number of non-GREASE cipher suites, as 2 decimal digits, capped at `99`.
   - SCSVs (`0x00ff`, `0x5600`) and reserved values (`0xfe00`–`0xfeff`) count.
   - Unknown values count.
5. **ne**: the number of non-GREASE extensions, as 2 decimal digits, capped at `99`.
   - SNI (`0x0000`) and ALPN (`0x0010`) are included in the count.
   - Padding (`0x0015`), unknown types and every other type also count.
   - A repeated extension type counts once per occurrence. TLS libraries accept duplicates of types they do not
     recognise (nginx-clientfp does).
     Verified against thumbprint.me: two copies of `1234` gave `ne = 17` and appear twice in `c`.
6. **alpn**: let `v` = the bytes of the first protocol name in ext `0x0010`.
   - It is the first value the client *offers*, not the protocol that is negotiated. httpx with `http2=True` offers
     `http/1.1,h2`. Both servers negotiated `h2`, and both reported `h1`.
   - The result is `00` if any of these hold:
     - ext `0x0010` is absent;
     - its list is empty;
     - `len(v) == 0`.
   - Otherwise, call a byte *alnum* if it is in `0-9`, `A-Z` or `a-z`. If both `v[0]` and `v[len-1]` are alnum, the
     result is `chr(v[0]) chr(v[len-1])`. A single-character `v` uses the same character twice: `a` → `aa`.
   - Otherwise, `h = lowercase hex(v)` over the whole value, and the result is `h[0] h[last]`. In effect, that is the
     high nibble of the first byte and the low nibble of the last byte.
   - Examples:

     | first ALPN value | result |
     |------------------|--------|
     | `h2` | `h2` |
     | `http/1.1` | `h1` |
     | `a` | `aa` |
     | `AB` (0xab) | `ab` |
     | `AB CD` | `ad` |
     | `20 61` | `21` |
     | `30 AB` | `3b` |
     | `61 20` | `60` |
     | `30 31 AB CD` | `3d` |
     | `30 AB CD 31` | `01` |
     | `#x` | `28` |

### b — cipher hash

`b_raw` is the non-GREASE cipher suites, sorted ascending (numeric order equals hex-string order), as 4-hex values
joined with `,`. Then `b = hash12(b_raw)`. With no ciphers, `b = 000000000000`.
`b_orig` is the same list in wire order.

### c — extension and signature-algorithm hash

1. Build `E`: the non-GREASE extension types **minus `0x0000` and `0x0010`**, sorted ascending, as 4-hex values joined
   with `,`. Duplicates stay in the list.
2. Build `S`: the non-GREASE sigalgs from ext `0x000d`, in **wire order**, not sorted and not de-duplicated. Safari
   sends `0805` twice, and both are kept.
3. Combine them:
   - `c_raw = E + "_" + S` if `S` is non-empty;
   - `c_raw = E` if `S` is empty (no underscore);
   - `c_raw = ""` if `E` is empty, which makes `c = 000000000000`.
4. `c = hash12(c_raw)`.

`c_orig` uses every non-GREASE extension type in **wire order, keeping `0x0000` and `0x0010`**, followed by `_S` as
above.

Extension order is irrelevant for `JA4` because `E` is sorted. Chrome's per-connection extension shuffle does not
change its JA4. This was verified.

### Worked example (spec)

```
ciphers (wire)  1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035
exts (wire)     001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015
sigalgs         0403,0804,0401,0503,0805,0501,0806,0601
supported_vers  0304,0303        ALPN h2,http/1.1        SNI present
b_raw  002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9           -> 8daaf6152771
c_raw  0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601
                                                                                           -> e5627efa2ab1
c_raw without sigalgs: 0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01 -> 6d807ffa2a79
JA4   = t13d1516h2_8daaf6152771_e5627efa2ab1
JA4_o = t13d1516h2_acb858a92679_18f69afefd3d
```

## 4. Which ClientHello

- Fingerprint the **first** ClientHello of the connection. After a HelloRetryRequest the client sends a second hello.
  It usually adds `0x002c` cookie and changes `key_share`. **Ignore that second hello.** Verified with a
  second hello that deliberately differs (an extra extension gives `t13d4716…_10907f08e575` instead of
  `t13d4715…_3a32f3cec0e4`): both reference servers reported the first hello's JA4. The upstream Rust implementation
  also uses the first hello.
- Renegotiation hellos (TLS ≤ 1.2) are not the connection's fingerprint either.
- SSLv2-format (backwards-compatible) ClientHellos: no fingerprint is defined for them, and nginx-clientfp computes
  none. By default it refuses such connections before the handshake (`clientfp_refuse_sslv2_hello`, decision 036).
  The TLS library would otherwise accept them only at security level 0 with RSA key exchange ciphers.
- ECH: JA4 is defined on the hello as seen on the wire (the outer hello). The capture in [§5](#5-capture-in-nginx)
  reads the bytes before the TLS library does, so it sees only the outer hello. ECH was not configured or tested.

## 5. Capture in nginx

### 5.1 Why the raw bytes

JA4 needs every extension type exactly as sent, including unknown types and GREASE. A TLS library's view of the
ClientHello does not give that: APIs that list the extensions of a ClientHello typically report only the types the
library implements, and silently drop the rest. Common types that are lost that way:

- `0015` padding;
- `001c` record_size_limit;
- `0022` delegated_credentials;
- `4469` and `44cd` ALPS;
- `000f` heartbeat;
- `0039` quic_transport_parameters on TCP;
- every GREASE value.

Measured impact on real clients when only implemented types are kept:

| client | JA4 from wire bytes (correct) | JA4 from implemented types only | lost |
|--------|-------------------------------|---------------------------------|------|
| Chrome (curl_cffi) | `t13d1516h2_8daaf6152771_806a8c22fdea` | `t13d1515h2_…_e4c2b8c727f2` | `44cd` |
| Firefox (curl_cffi) | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` | `t13d1715h2_…_c1eccb039341` | `001c`, `0022` |
| curl 8.5 | `t13d3112h2_e8f1e7e78f70_b26ce05bbdd6` | `t13d3111h2_…_375ca2c5e164` | `0015` |
| Safari (curl_cffi) | `t13d2013h2_a09f3c656075_7f0f34a4126d` | same | none |

QUIC hellos have the same problem. niquests/qh3 over HTTP/3 sends `44cd` (ALPS).

### 5.2 The module reassembles the ClientHello itself (decision 030)

The module never asks the TLS library for the hello. Two small hooks in nginx (`patches/nginx/<line>/0002-*`) give
it the client's bytes before the TLS library reads them, and `nginx_module/src/clientfp_hello.c` reassembles the
handshake message (the layout of [§2](#2-values-to-extract-from-the-clienthello)):

- **TLS over TCP.** `ngx_http_ssl_handshake()` calls `ngx_http_clientfp_tls_hello()` before it creates the TLS
  connection. The module peeks at the socket (`MSG_PEEK`), so the TLS library later reads the same bytes, and walks
  the handshake records (content type 22, version major 3, length 0–16384; empty records are skipped, as the TLS
  library skips them). A ClientHello split over several records is joined. While it is incomplete the module
  returns `NGX_AGAIN` and nginx waits for more data, under `client_header_timeout`; as during the handshake, the
  connection is not one nginx closes to make room for others (decision 038). The capture computes a lower
  bound on the bytes still needed, and `FIONREAD` avoids copying again before they are there. It gives up after
  64 peeks or when the client closes its side; the handshake then goes on without a fingerprint.
- **QUIC.** `ngx_quic_handle_crypto_frame()` calls `ngx_http_clientfp_quic_crypto()` for every CRYPTO frame of an
  Initial packet, until HTTP/3 has started its session. Frames may arrive in any order and overlap (Chrome
  shuffles them); the first copy of each byte wins.
- **Limits** (decision 033): the ClientHello may be at most 16 KiB, carried in at most 32 KiB of TLS records.
- **Which hello.** Only the first ClientHello of the connection is captured ([§4](#4-which-clienthello)): the
  TCP hook runs once before the handshake, and the QUIC hook stops when the first hello is complete.
- **Where the result lives.** In the connection's `ngx_http_connection_t` (decision 034), so HTTP/1.x, HTTP/2 and
  HTTP/3 requests find it. JA4 is parsed into compact lists once; the four strings are formatted on first use.
- **Hashes.** SHA-256 is the module's own (`clientfp_sha256.c`); no TLS library function is called.

`tools/clientfp/fp/hello.py` is the reference for the reassembly. `tests/test_c_core.py` checks the C code against it
on every recorded hello split into records every way, thousands of prefixes, hostile record streams and shuffled,
overlapping QUIC fragments. `tests/integration/test_hostile.py` checks real handshakes whose hello is framed and
segmented in many ways against a running nginx.

## 6. Values the nginx side should expose

| value | example |
|-------|---------|
| `ja4` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| `ja4_r` | `t13d1516h2_002f,0035,…_0005,000a,…_0403,0804,…` |
| `ja4_o` | `a` + wire-order hashes |
| `ja4_ro` | `a` + wire-order raw lists |

Empty or "not a TLS connection" gives an empty value, not `000000000000…`. The zero hashes are only for empty lists
inside a real ClientHello.

## 7. Reference implementations disagree on ALPN — follow this doc

| input first ALPN | spec + kittens.sh + thumbprint.me (verified) | upstream Rust | upstream Python | Wireshark plugin |
|---|---|---|---|---|
| `a` (1 char) | `aa` | `a0` | `aa` | `aa` |
| non-ASCII `ab cd` | `ad` | `99` | `99` | `99` |
| ASCII non-alnum `#x` | `28` | `#x` | `#x` | `99` |

The spec's hex rule (dated 2026-01) is newer than the other implementations. Everything else (GREASE, counts, sorting,
the version rule, `000000000000` for empty lists, and the first ClientHello only) is the same across the spec, Rust,
Python and both reference servers.

## 8. Verification

Tools, all run with the project `.venv`. They are the `clientfp` package in `tools/clientfp/`. Install it and its
dependencies with:

```
.venv/bin/pip install -e '.[dev]'      # the `test` extra of pyproject.toml holds the probe clients
```

`curl_cffi` is pinned because the Chrome, Firefox and Safari JA4 values depend on its browser profiles. `cryptography`
decrypts QUIC Initial packets. httpx, niquests and qh3 (pulled in by niquests) come from the same `test` extra, which
also serves the HTTP/2 work.

- `clientfp-ja4 <hex> [--proto t|q|d]` / `clientfp-ja4 --selftest` (`tools/clientfp/fp/ja4.py`)
  - Reference implementation: raw hello → `ja4`, `ja4_r`, `ja4_o`, `ja4_ro`.
  - `--selftest` checks every worked example and ALPN example in the spec, including `JA4_o`.
- `clientfp-ja4-probe [--ref kittens,thumbprint] [--host H --connect IP --port P --path /x -k] [--case C] [--dump F]`
  (`tools/clientfp/probe/ja4_probe.py`)
  - Drives 41 cases, using:
    - curl, wget, Python urllib, httpx and niquests;
    - curl_cffi (Chrome, Firefox and Safari over TCP; Chrome over HTTP/3);
    - niquests/qh3 over HTTP/3;
    - a tlslite-ng client whose ClientHello is mutated on the fly.
  - Captures each real ClientHello through a local relay. TCP clients connect directly or through HTTP CONNECT.
    QUIC traffic goes through a UDP relay, and the ClientHello is recovered by decrypting the Initial packets.
  - Computes JA4 locally and compares it with every form the server returns. The server can return JSON with
    `ja4`/`ja4_r`/`ja4_o`/`ja4_ro`, or a bare JA4 string, as the nginx endpoint will.
  - Each case also pins the expected `a` section with a regex.
  - Cases marked `may_refuse` are reported as `SKIP`, not `FAIL`, when the server's TLS stack rejects the hello.
  - `-k` does not change any client's ClientHello.
  - Point it at nginx with `--host localhost --connect 127.0.0.1 --port 8443 --path /ja4 -k`.
- `doc/ja4_vectors.json`
  - 81 captured ClientHellos: 39 confirmed by kittens.sh and 42 by thumbprint.me. Each is stored as the hex handshake
    message, as the module's capture reassembles it (for QUIC, as recovered from the Initial packets).
  - Each entry has the local `ja4/_r/_o/_ro`, the `server`, and the forms that server confirmed.
  - Use them as offline unit-test vectors for the C parser.

Live results: 81 completed handshakes, 0 mismatches.

Common tools. All four forms were confirmed by thumbprint.me, and `ja4`/`ja4_r` by kittens.sh:

| client | JA4 | note |
|---|---|---|
| curl 8.5.0 (default, h2) | `t13d3112h2_e8f1e7e78f70_b26ce05bbdd6` | niquests (default) gives the same value |
| curl `--tlsv1.3` | `t13d0412h2_16476d049b0b_85302d7e289e` | TLS 1.3 suites only |
| curl `--no-alpn` | `t13d311100_e8f1e7e78f70_b26ce05bbdd6` | `00` |
| curl `https://<ip>/` (no SNI) | `t13i3111h1_e8f1e7e78f70_b26ce05bbdd6` | `i` |
| wget 1.21.4 | `t13d751100_479067518aa3_fb8d5ffd48c1` | no ALPN, 75 ciphers |
| Python 3.12 urllib | `t13d3113h1_e8f1e7e78f70_d339722ba4af` | curl's extension set plus `0023` session_ticket |
| httpx 0.28 (h1, or `http2=True`) | `t13d3112h1_e8f1e7e78f70_d41ae481755e` | has `0023` but no `0031`; offers `http/1.1,h2`, so `h1` even when h2 is negotiated |
| curl_cffi Chrome over HTTP/3 | `q13d0308h3_55b375c5d22e_1b7ced03430d` | QUIC |
| niquests/qh3 over HTTP/3 | `q13d0310h3_55b375c5d22e_37b0b428b5c5` | QUIC; carries `44cd` and `fe0d` |

Edge cases (the same values from both servers unless noted):

| case | JA4 | rule exercised |
|---|---|---|
| curl default / `--http1.1` | `t13d3112h2_e8f1e7e78f70_b26ce05bbdd6` / `…h1…` | baseline, `h2`/`h1` |
| curl `--tls-max 1.2` | `t12d2807h1_d943125447b4_a44c6288192a` | no `0x002b` → legacy_version |
| Chrome / Firefox / Safari | see [§5.1](#51-why-the-raw-bytes) | GREASE, ALPS, ECH-GREASE, shuffled extensions |
| tlslite + GREASE in ciphers, exts, sigalgs, versions, groups | `t13d4715h1_ace53f506114_3a32f3cec0e4` | identical to the no-GREASE hello |
| tlslite, extensions reversed | same as above | `c` is order-independent |
| tlslite, sigalgs reversed | `…_9b711b71942c` | `c` depends on sigalg order |
| tlslite + 100 ciphers + `00ff,5600,fe00,feff` | `t13d9915h1_4ac807645e40_…` | 99 cap, SCSV and reserved values counted |
| tlslite, `supported_versions` includes `7f1c` | `t00d4715h1_…` | literal max → unknown → `00` |
| tlslite, forced HRR (empty key_share); the 2nd hello gets an extra extension | first-hello JA4 | first ClientHello only |
| tlslite, unknown extension `1234` sent twice | `t13d4717h1_ace53f506114_76aa05b37b2e` | thumbprint.me only (kittens rejects duplicates) |
| tlslite, ClientHello split into 9 records of 64 bytes | same as default | record reassembly |
| tlslite ALPN `a`, `ab cd`, `20 61`, `30 ab`, `61 20`, `30 ab cd 31`, `#x` | `aa ad 21 3b 60 01 28` | ALPN rule |

The tlslite values above were recorded with the tlslite-ng git checkout that came with the specs. The PyPI release
pinned in `pyproject.toml` (0.8.2) sends one more extension, so the same cases now give `t13d4716h1_…` (or `t13d4719`,
`t13d4718` and so on) with other `c` hashes. The rules exercised are unchanged. `tests/integration/test_fingerprints.py`
checks every case against nginx-clientfp itself, using the reference calculator on the captured bytes. It does not
rely on these recorded strings.

Not verifiable against either reference server. Both refuse these hellos, so the rules come from the spec alone.
nginx-clientfp completes them at security level 0, and `tests/integration/test_fingerprints.py` checks that the
bytes are captured exactly.

- TLS 1.2 without `signature_algorithms`:
  - Both servers answer `handshake_failure`. With no sigalgs, the server would have to sign with SHA-1.
  - kittens.sh also refuses a resumed session in this case. thumbprint.me issues no TLS 1.2 session ID or ticket.
  - The result is `c_raw = E` with no `_`, matching the spec example `6d807ffa2a79`.
- A hello with no extensions at all. The result is `c = 000000000000`.
- A `supported_versions` list that contains only GREASE. Both servers answer `protocol_version`.

## License

This document is derived from FoxIO's `JA4.md` (link at the top), and is under its license, BSD-3-Clause. Changes
are Copyright (c) 2026 nginx-clientfp contributors, under the same license. FoxIO's notice:

```
Copyright (c) 2026 FoxIO
All rights reserved.
Software: JA4 (TLS client fingerprinting)

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following
  disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
  following disclaimer in the documentation and/or other materials provided with the distribution.

* Neither the name of FoxIO nor the names of its contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
