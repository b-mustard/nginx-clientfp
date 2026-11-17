# 030 — Library-independent ClientHello capture and hashing

- Date: 2026-11-17
- Type: human

## Context
After decision 029 the project's own code must not depend on OpenSSL. The module used OpenSSL's `msg_callback`
and ex_data to get the first ClientHello, and EVP for SHA-256 and MD5.

Research (2026-11-17): with a system OpenSSL older than 3.5, nginx's QUIC compatibility layer replaces the
`msg_callback` on every QUIC connection, so HTTP/3 requests got no JA4 or TLSFP. Debian 12 and Ubuntu 24.04 ship
OpenSSL 3.0.

## Options
1. Library-independent: the module uses no TLS-library API. Our nginx patch hands the raw ClientHello to the
   module: over TCP by peeking at the socket before the handshake starts, over QUIC from the Initial CRYPTO frames.
   Own SHA-256, nginx's built-in `ngx_md5`.
2. Keep `msg_callback` and EVP from the system library. Small change; HTTP/3 fingerprints stay empty on OpenSSL 3.0.
3. Keep `msg_callback` and EVP, plus a patch hook so the QUIC compatibility layer forwards the ClientHello.

## Decision
Option 1.
- Works with any TLS library nginx can use, and gives HTTP/3 fingerprints with both QUIC back ends (native OpenSSL
  3.5+ API and the compatibility layer).
- Only the first ClientHello is seen by construction: the TCP peek runs once before the handshake, and QUIC
  capture stops at the end of the first handshake message in the Initial CRYPTO stream.
- Size limit: decision 033. Per-connection storage: decision 034.
- Supersedes decision 014 (capture via `msg_callback`) and the "in the callback" part of decision 026; TLSFP is
  still computed eagerly, once per connection.
