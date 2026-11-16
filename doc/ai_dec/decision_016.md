# 016 — Directive semantics

- Date: 2026-11-16
- Type: automatic (implements decisions 004 and 013)

- `clientfp on|off` is `http`-level only. Per-server switching would be misleading: the ClientHello is captured
  before SNI selects a server, and HTTP/2 frames before the Host header does.
- `clientfp_request_header <name> <value>` is allowed in `http` and `server`. It runs in the POST_READ phase,
  before rewrite, so `$http_<name>` is trusted everywhere. Location context is not offered: the location is not
  known in POST_READ, and a later phase would let rewrite rules see the client's spoofed value.
- The header list is rebuilt rather than edited in place: element copies keep nginx's own pointers
  (`r->headers_in.host`, …) valid. Header names nginx parses itself (`ngx_http_headers_in[]`) are rejected at
  configuration time, so those pointers can never refer to a dropped header.
- Like `proxy_set_header`, a list in `server {}` replaces the inherited `http {}` list.
- Empty values are not added (the client's copy is still removed).
