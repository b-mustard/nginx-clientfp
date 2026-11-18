# 037 — ClientHello capture: implementation details

- Date: 2026-11-18
- Type: automatic

Details of decisions 030, 033, 034 and 036 that needed no human choice.

The connection is no longer marked reusable while it waits: decision 038 replaces that detail.

## TCP wait
- The hook runs in `ngx_http_ssl_handshake()` right after nginx's own 1-byte peek (and after a PROXY protocol
  header has been consumed), before the TLS connection is created. `NGX_AGAIN` reuses nginx's own waiting code:
  `rev->ready = 0`, the `client_header_timeout` timer if none is set, the connection marked reusable, and
  `ngx_handle_read_event()`.
- Waiting relies on an event per new segment, which edge-triggered methods (epoll, kqueue) give. With a
  level-triggered method a hello that has not fully arrived gets no fingerprint instead of a busy loop.
- `clientfp_hello_tls()` returns a lower bound on the raw bytes needed; with `FIONREAD` the socket is peeked again
  only once that many bytes are queued.
- The module gives up (no fingerprint, the handshake goes on) after 64 peeks of a still-incomplete hello and when
  the event reports a pending EOF, so a client that stops mid-hello is not held for `client_header_timeout`.
- The peek buffer (at most 32 KiB plus 16 KiB for reassembly) is `ngx_alloc`ed per peek and freed before return.

## Record rules
- Content type 22, version major 3, length 0..16384, as the TLS library checks them. Empty handshake records are
  skipped: OpenSSL 3.0 accepts up to 32 of them anywhere before the hello is complete, so refusing them would let
  a client avoid fingerprinting with a handshake that still succeeds (measured on 2026-11-17).
- Another record type before the hello is complete gives no fingerprint; the TLS library refuses those handshakes
  (`unexpected_message`).
- SSLv2 format: top bit of byte 0 set and byte 2 = 1, the test the TLS library itself uses.

## QUIC
- The reassembly buffer (16 KiB plus a 2 KiB bitmap) is allocated with `ngx_alloc` and freed when the capture ends,
  or by a cleanup on the QUIC connection's pool.
- The hook is guarded by `pkt->level == NGX_QUIC_ENCRYPTION_INITIAL && !qc->streams.initialized`: until HTTP/3
  initializes its session, `c->data` is the `ngx_http_connection_t`.

## Other
- The JA4 and TLSFP cores initialize three variables that gcc reports as maybe-uninitialized at `-O2`; nginx builds
  with `-Werror`.
- The module still builds without the 0002 patch (`NGX_HTTP_CLIENTFP_HELLO_HOOKS` undefined); JA4 and TLSFP are
  then empty.
