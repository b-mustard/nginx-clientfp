# 034 — Per-connection result in `ngx_http_connection_t`

- Date: 2026-11-17
- Type: human

## Context
Without OpenSSL's ex_data (decision 030) the JA4/TLSFP result needs another per-connection home that HTTP/1,
HTTP/2 and HTTP/3 requests can reach.

## Options
1. Our nginx patch appends `void *clientfp` to `ngx_http_connection_t`, the pattern already used for
   `h2c->clientfp`. HTTP/2 requests reach it through `r->http_connection`, HTTP/3 requests through the QUIC
   session's `http_connection`.
2. A module-owned lookup table keyed by connection, cleaned up by pool cleanups. No struct change, more code, a
   lookup on every variable access.

## Decision
Option 1. The field is appended at the end of the struct.
