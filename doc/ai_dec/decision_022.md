# 022 — TLSFP: follow the draft, implemented separately from JA4

- Date: 2026-11-16
- Type: human

## Context
The nDPI TLS fingerprint draft v0.1 (`doc/nDPI_TLS_Fingerprint.md`) builds on JA4, but its worked example
contradicts its own algorithm (Appendix A, vector 1: `TLSFP_b` and `TLSFP_c`). nDPI's code also differs from
the text (comma bug without SNI, raw ALPN bytes, `000000000000` for an empty c). See `doc/tlsfp_sig.md` §3–4.

## Options
1. Follow the draft's text (§6, §7, §9, Appendix B) and record its errata.
2. Match nDPI's code byte for byte, bugs included.
3. Match the Appendix A vectors.

## Decision
Option 1. The user also asked that TLSFP is implemented in parallel to JA4, without reusing the JA4 fingerprint
code. TLSFP has its own Python reference (`tools/clientfp/fp/tlsfp.py`) and its own C core
(`nginx_module/src/clientfp_tlsfp.c`, with its own reader and hashing). The only shared code is the ClientHello
framing parser in Python (`tools/clientfp/fp/tls.py`), which `ja4.py` also uses. Where TLSFP and JA4 rules
differ (version table, GREASE in sigalgs, the `_` in c, uncapped lists), the TLSFP text applies.
