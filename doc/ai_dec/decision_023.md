# 023 — TLSFP_d without supported groups: 000000000000

- Date: 2026-11-16
- Type: human

## Context
The draft gives two answers for a hello without supported_groups, or with GREASE-only groups:
- §6.7, §7.6, the ABNF and vector 3 say `TLSFP_d` is empty;
- §5.2 shows `000000000000`.

## Options
1. `000000000000`: the fingerprint keeps its 49-character shape. This matches nDPI's code.
2. An empty field: the fingerprint ends in `_`, which is also what a malformed groups extension gives (§9).

## Decision
Option 1. An empty `TLSFP_d` is kept only for a malformed supported_groups extension (§9).
