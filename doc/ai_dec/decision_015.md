# 015 — HTTP/2 hook details

- Date: 2026-11-16
- Type: automatic (implements decisions 006 and 012)

- Per-connection state is allocated from `h2c->connection->pool`, not `h2c->pool`: nginx destroys `h2c->pool`
  whenever the connection becomes idle (`ngx_http_v2.c`, `ngx_destroy_pool(h2c->pool)`).
- The pseudo-header order (PS) belongs to the first HEADERS frame for which nginx creates a stream (a refused
  stream does not count, doc/http2_sig.md §5.2). The fingerprint freezes when that stream's header block ends,
  even if the request is then rejected (e.g. 400), so a bad first request can never mix its PS with a later one.
  Freezing happens before `ngx_http_v2_run_request()`, so header injection in the POST_READ phase already sees
  the final value.
- A repeated pseudo-header (a malformed request that nginx answers with 400) is recorded once.
- nginx 1.31 no longer parses PRIORITY frames (RFC 9218 replaced RFC 7540 priorities); the 1.31 patch parses the
  5-byte payload itself (with `ngx_http_v2_state_save()` for partial frames). nginx 1.30 still parses them, and
  the patch only reports the parsed values.
- SETTINGS: a frame with the ACK bit set is skipped even when nginx treats it as non-ACK (nginx tests
  `flags == ACK`, the fingerprint spec tests the bit).
- The patch adds hook calls only, each under `#if (NGX_HTTP_CLIENTFP)`, plus one pointer at the end of
  `ngx_http_v2_connection_t`. It defines `NGX_HTTP_V2_CLIENTFP_HOOKS`, so the module also compiles (JA4 only)
  against an unpatched nginx.
