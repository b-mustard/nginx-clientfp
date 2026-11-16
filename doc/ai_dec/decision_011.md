# 011 — JA4 per-connection storage: compact capped lists

- Date: 2026-11-16
- Type: human

## Context
OpenSSL accepts ClientHello messages up to ~128 KB; the fingerprint lives for the whole connection.

## Options
1. Parse in the msg_callback, keep compact u16 lists (ciphers, extension types, sigalgs) + version, SNI flag,
   ALPN chars; no fingerprint when a list exceeds 1024 entries.
2. Keep a raw copy of the ClientHello and parse lazily.
3. Compute `ja4`/`ja4_o` eagerly, raw forms only on request.

## Decision
Option 1. Typical cost ~100-200 bytes per TLS connection, worst case ~6 KB. Over the cap all JA4 variables are
empty and an info-level message is logged. Strings are formatted lazily on first variable access and cached.
