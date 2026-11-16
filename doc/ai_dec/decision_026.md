# 026 — TLSFP computed eagerly, lists uncapped

- Date: 2026-11-16
- Type: human

## Context
JA4 keeps compact lists of at most 1024 entries per connection and formats the strings lazily (decision 011).
TLSFP §7.5 says the hash inputs are never capped, and OpenSSL accepts hellos of about 128 KB.

## Options
1. Eager: compute TLSFP in the ClientHello callback. Sort the full lists in a temporary heap buffer
   (`ngx_alloc`, freed before the callback returns) and keep only the 49-byte string.
2. Lazy: keep a copy of the raw hello and compute on first use.
3. Reuse JA4's capped lists (no TLSFP above 1024 entries).

## Decision
Option 1. Each handshake costs three SHA-256 hashes of a few hundred bytes and one short-lived allocation. The
worst case is a temporary 128 KB buffer. Per connection, TLSFP keeps 49 bytes plus a length and a status. A
hello over the JA4 cap still gets a TLSFP.
