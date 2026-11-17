# nDPI TLS client fingerprint (TLSFP): implementation notes

TLSFP is ntop's extension of JA4. Normative source:
[nDPI_TLS_Fingerprint.md](nDPI_TLS_Fingerprint.md), draft v0.1, imported verbatim from `ntop/nDPI` branch `dev`,
`fingerprint/nDPI_TLS_Fingerprint.md` at commit `a01ea9463125` (2026-10-08), CC BY 4.0, © ntop. This file
records how nginx-clientfp reads that draft: what it implements, where the draft contradicts itself, and where
nDPI's own code differs.

The draft builds on JA4, but TLSFP is implemented as a separate fingerprint (decision 022). It has its own
Python reference (`tools/clientfp/fp/tlsfp.py`) and its own C core (`nginx_module/src/clientfp_tlsfp.c`). Neither
calls the JA4 code. The two share only the ClientHello framing parser in Python (`tools/clientfp/fp/tls.py`).
Where the TLSFP text differs from JA4, the TLSFP text applies.

## 1. Format

```
TLSFP_a _ TLSFP_b _ TLSFP_c _ TLSFP_d          49 characters
t13d1514h2_8daaf6152771_aabe8f104b71_646c356617d7   (Chrome; JA4 t13d1516h2_8daaf6152771_806a8c22fdea)
```

| field | content | spec |
|---|---|---|
| `a` | proto `t`/`q`/`d`, version, `d`/`i`, cipher count, sanitized extension count, ALPN | §6.4 |
| `b` | first 12 hex of SHA-256 of the sorted cipher list | §6.5 |
| `c` | SHA-256 of sorted sanitized extensions without SNI/ALPN, `_`, signature algorithms in wire order | §6.6 |
| `d` | SHA-256 of the sorted supported groups; `000000000000` without groups | §6.7, decision 023 |

## 2. Algorithm as implemented

1. **Input.** The first ClientHello of the connection, as the handshake message the module's capture
   reassembles before the TLS library reads it (§4, §7.1; [ja4_sig.md §5](ja4_sig.md#5-capture-in-nginx)). The
   ClientHello after a HelloRetryRequest is ignored.
2. **GREASE** (§6.2). RFC 8701 values, where both octets are equal and the low nibble is `A` (`0a0a`, `1a1a` …
   `fafa`), are removed from cipher suites, extension types and supported groups. Signature algorithms are not
   filtered, because §6.2 does not list them.
3. **Ephemeral extensions** (§6.3, Appendix B, registry v1). `0015` padding, `0023` session_ticket, `0029`
   pre_shared_key, `002a` early_data, `002c` cookie and `002d` psk_key_exchange_modes are removed after GREASE.
   The rest is the *sanitized* list.
4. **a** (§6.4): `proto` + `version` + `sni` + `cnt_c` + `cnt_e` + `alpn`.
   - `version`: the highest non-GREASE `supported_versions` value, else `legacy_version`. It maps
     `0304`→`13`, `0303`→`12`, `0302`→`11`, `0301`→`10`, `0300`→`s3`, `feff`→`d1`, `fefd`→`d2`, `fefc`→`d3`;
     anything else gives `00`. The table has no `s2` (JA4 has one).
   - `sni`: `d` if extension `0000` is present, else `i`.
   - `cnt_c`: the number of non-GREASE ciphers. `cnt_e`: the number of sanitized extensions, SNI and ALPN
     included. Both are shown with two digits and capped at `99`; the hash inputs are not capped (§7.5).
   - `alpn`: the first and last byte of the first ALPN protocol, lower-cased (`H2` → `h2`). It is `00` if the
     extension, the protocol list or the first protocol is empty. If either byte is not a letter or digit, the
     field is the first hex nibble of the first byte and the last hex nibble of the last byte (`\xab\xcd` → `ad`,
     `#x` → `28`), so it never contains anything but `[0-9a-z]` (decision 025).
5. **b** (§6.5): the sorted ciphers, as 4-digit lowercase hex joined with `,`, then SHA-256, first 12 hex digits.
   This equals JA4_b for every real hello (checked on all 81 recorded vectors).
6. **c** (§6.6): the sorted sanitized extensions without `0000` and `0010`, `,`-joined, then `_`, then the
   signature algorithms in advertised order, `,`-joined. The `_` is always there, so a hello without
   signature_algorithms hashes `<exts>_`.
7. **d** (§6.7): the sorted non-GREASE supported groups, `,`-joined, SHA-256. If the extension is absent or holds
   no non-GREASE group, the field is `000000000000` (decision 023).
8. No list is deduplicated (§7.4). When an extension appears twice, it is counted and listed twice, and the first
   ALPN / signature_algorithms / supported_versions / supported_groups is decoded.
9. **Errors** (§9).
   - If the ClientHello framing is broken, there is no TLSFP: the variable is empty.
   - If one extension is malformed, only the field that decodes it is emptied:
     - supported_versions or ALPN → `a`;
     - signature_algorithms → `c`;
     - supported_groups → `d`.

     Examples: `_8daaf6152771_aabe8f104b71_646c356617d7`, `t13d1514h2_8daaf6152771_aabe8f104b71_`.
   - Malformed means the extension does not decode exactly under the TLS presentation language (RFC 8446 §3):
     each length must fit its enclosing length and fill it exactly, and u16 lists must have an even length.
   - The TLS library validates these extensions as well and usually aborts such a handshake, so a partial TLSFP
     rarely reaches a request. The rule keeps the C core well-defined on any input; the TLSFP is computed from
     the captured hello before the TLS library looks at the extensions.
10. **Registry version.** `$clientfp_tlsfp_registry` is `1` whenever `$clientfp_tlsfp` is set (§13, Appendix B).

## 3. Errata in draft v0.1

The draft contradicts itself in these places. The resolution used here is listed for each.

| # | draft text | problem | resolution |
|---|---|---|---|
| E1 | §6.2: the RFC 8701 test "equivalently, in bitwise form, `(v & 0x0F0F) == 0x0A0A`" | The forms are not equivalent: `0x1a2a` passes the bitwise test only | RFC 8701 form (both octets equal), as in nDPI's code (decision 027) |
| E2 | §6.7 / §7.6 / ABNF / Vector 3: `TLSFP_d` empty without groups. §5.2 example: `000000000000` | Contradiction | `000000000000`, which also matches nDPI's code (decision 023) |
| E3 | §7.6 "absent stays distinguishable from present but data-poor" | §6.7 gives the same result for both | Both give `000000000000` |
| E4 | §5: TLSFP_a is "semantically identical" to JA4_a except `cnt_e`. §6.4: ALPN bytes lower-cased, no non-alnum rule | Contradiction, and raw bytes are unsafe in a header | Lower-case, plus hex nibbles for non-alnum ends (decision 025) |
| E5 | Appendix A vector 1, `TLSFP_b = acb858a92679` | That is the SHA-256 of the ciphers in *wire* order; §6.5 sorts them (`8daaf6152771`) | §6.5 |
| E6 | Appendix A vector 1, `TLSFP_c = 7dc829385eb9` | It hashes a list that still holds `0010` (ALPN, removed by §6.6), `0023` and `002d` (ephemeral per Appendix B); "14 members" lists 13 | §6.6 and Appendix B |
| E7 | Appendix A vector 3 | No inputs given, so it cannot be checked | Not used |
| E8 | §5 "49 characters" | Not true when a field is empty (§9) | 49 except under §9 |

Only `TLSFP_d = 0a47a2b05960` of vector 1 follows the draft's own algorithm. It is checked by `clientfp-tlsfp
--selftest` and the unit tests.

## 4. Differences from nDPI's implementation

nDPI (`src/lib/protocols/tls.c`, `ndpi_compute_ja4()`, branch `dev` as of 2026-11-16) computes `tlsfp_client`. It
gives the same value for typical browser hellos, but differs in these cases (decision 022: we follow the draft):

- **No SNI.** nDPI's comma condition `i > num_ephemeral_extn + 1` drops the comma after the first extension, for
  example `000a000b,000d,…`. Of our 81 recorded hellos, 6 have no SNI, so their `TLSFP_c` differs from nDPI.
- **GREASE signature algorithms.** nDPI also keeps them; this matches the draft.
- **JA4_a quirks.** nDPI builds `TLSFP_a` from its own JA4_a:
  - an SNI that holds an IP address gives `i`;
  - the ALPN characters are raw bytes, not lower-cased, with no hex rule.
- **No signature algorithms.** nDPI omits the `_` from the c input; the draft's §6.6 formula keeps it.
- **No extensions at all.** nDPI gives `c = 000000000000`; the draft hashes `_`.
- **List caps.** nDPI caps lists at its `MAX_NUM_JA` and drops the fingerprint beyond it; the draft (§7.5) and
  this implementation do not cap.

## 5. nginx integration

- **Computation (decision 026).** TLSFP is computed eagerly, once per handshake, in the same first-ClientHello
  callback as JA4, but independently of it. A hello with more than 1024 ciphers has no JA4 (decision 011) and
  still has a TLSFP. The lists are sorted in temporary heap memory that is freed before the callback returns.
  Only the 49-byte string is kept per connection. The cost is three SHA-256 hashes of a few hundred bytes per
  handshake.
- **Variables.**
  - `$clientfp_tlsfp`: the fingerprint, or empty when there is none.
  - `$clientfp_tlsfp_registry`: `1` (decision 028).
- **Header.** The packaged `nginx.conf` sends `X-Client-TLSFP` to upstreams by default (decision 024).
- **QUIC.** HTTP/3 connections give `q…`, from the ClientHello in the QUIC Initial packets.

## 6. Verification

- `clientfp-tlsfp --selftest` and `tests/unit/test_fp_tlsfp.py` check every rule above with hand-written hash
  inputs, and all 81 recorded hellos for shape and for `b == JA4_b`.
- `tests/test_c_core.py` compares the C core with the Python reference, under ASan and UBSan:
  - the 81 vectors;
  - about 9,700 mutated hellos;
  - hellos whose ALPN, supported_versions, signature_algorithms or supported_groups inner list is corrupted,
    covering each §9 field-emptying path;
  - lists of up to 32,767 entries.
- `tests/test_fuzz.py` runs a libFuzzer target. The output must stay within 49 bytes of `[0-9a-z_]`.
- `tests/integration`:
  - `clientfp-ja4-probe` compares nginx's `$clientfp_tlsfp` with the reference value of each captured hello, for
    45 live client cases including HTTP/3;
  - header injection and anti-spoofing of `X-Client-TLSFP`;
  - real handshakes with 1,100 to 3,000 ciphers or extensions.
