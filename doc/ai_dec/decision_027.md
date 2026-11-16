# 027 — TLSFP interpretation details

- Date: 2026-11-16
- Type: automatic

These follow from the draft's text where it is ambiguous. Errata references are in `doc/tlsfp_sig.md` §3.

- **GREASE** is the RFC 8701 test: both octets are equal and the low nibble is `A`. The draft's "equivalent"
  bitwise test `(v & 0x0F0F) == 0x0A0A` also accepts `0x1a2a`, so the two tests are not equivalent (E1). nDPI's
  code uses the RFC test.
- **Signature algorithms** are not GREASE-filtered, because §6.2 lists only ciphers, extensions and groups.
  They are hashed in wire order.
- The **`_` between the extension list and the signature algorithms** in the c input is always present, so a
  hello without signature_algorithms hashes `<exts>_` and a hello with no extensions hashes `_`.
- An **empty cipher list** hashes the empty string.
- The **version table** has no `s2`; unknown values give `00`.
- **§9** applies per field:
  - broken outer framing → no TLSFP;
  - a malformed supported_versions or ALPN → empty `a`;
  - malformed signature_algorithms → empty `c`;
  - malformed supported_groups → empty `d`.

  Every inner list must fit its enclosing length exactly, and u16 lists must have an even length (RFC 8446 §3).
- A **repeated extension** is counted and listed each time; the first occurrence is decoded. No list is
  deduplicated (§7.4).
- **cnt_c / cnt_e** are capped at `99` for display only.
