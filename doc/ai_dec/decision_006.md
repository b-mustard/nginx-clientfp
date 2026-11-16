# 006 — Static module + thin nginx patch, OpenSSL unpatched

- Date: 2026-11-16
- Type: human

## Context
- JA4 needs the raw first ClientHello. OpenSSL's public `msg_callback` delivers it before parsing
  (doc/ja4_sig.md §5). nginx only uses `SSL_set_msg_callback` in its QUIC OpenSSL-compat layer, which is not
  compiled with OpenSSL >= 3.5 (native `SSL_set_quic_tls_cbs` is used instead).
- The HTTP/2 signature needs hooks inside `src/http/v2/ngx_http_v2.c`; there is no module API for frames.
  That file changed by ~550 lines between 1.30.6 and 1.31.8.

## Options
1. Static module (`--add-module`) + thin per-line nginx patch with hook calls only; pure-C parsers.
2. Same as a dynamic module.
3. Everything in nginx core patches.

## Decision
Option 1.
- `nginx_module/` is compiled into the binary.
- `patches/nginx/<line>/` holds one small hook patch per nginx line (1.30, 1.31).
- JA4 and HTTP/2 signature parsing/formatting live in nginx-independent C files, unit-tested and fuzzed standalone.
- OpenSSL is not patched.
