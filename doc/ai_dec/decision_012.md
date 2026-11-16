# 012 — HTTP/2 signature overflow: truncate + flag variable

- Date: 2026-11-16
- Type: human

## Context
doc/http2_sig.md §5.1 asks for bounded arrays and a documented overflow behaviour.

## Options
1. Truncate at 32 settings / 32 PRIORITY frames; `$clientfp_http2_overflow` = `1` when truncated.
2. Empty signature on overflow.
3. Truncate silently.

## Decision
Option 1. The signature string always keeps the valid grammar. Real clients send <= 10 of each.
