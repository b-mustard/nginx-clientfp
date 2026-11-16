# 025 — TLSFP ALPN characters: lower-case, hex nibbles for non-alphanumeric ends

- Date: 2026-11-16
- Type: human

## Context
§6.4 takes the first and last byte of the first ALPN protocol, lower-cased, with no rule for other bytes. Raw
bytes could put `_`, control characters or non-ASCII bytes into a header value and break the field layout. §5
also says TLSFP_a is "semantically identical" to JA4_a.

## Options
1. Hex nibbles: if either byte is not `[0-9A-Za-z]`, use the first nibble of the first byte and the last nibble of
   the last byte (`#x` → `28`). This is JA4's rule.
2. Raw bytes, lower-cased (nDPI's code without lower-casing).
3. Replace each non-alphanumeric byte with `9` or `0`.

## Decision
Option 1, plus lower-casing (`H2` → `h2`), as §6.4 says. `00` for an absent extension or an empty list or name.
The output alphabet is always `[0-9a-z_]`.
