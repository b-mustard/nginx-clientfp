# 014 — JA4 capture details in the module

- Date: 2026-11-16
- Type: automatic (implements decisions 006 and 011)

- `SSL_CTX_set_msg_callback()` is installed in the module's postconfiguration on every server `SSL_CTX` of
  `http {}`. `SSL_new()` copies the callback from the listen socket's default server context before SNI switches
  contexts, so installing it everywhere is required.
- Only the first ClientHello of a connection is used: the per-connection state is attached to the `SSL` object
  with a module-owned ex_data index, and a second hello (after HelloRetryRequest, or renegotiation) is ignored
  because the slot is already set. The slot is also set when parsing fails, so a malformed first hello is never
  replaced by a later one.
- The transport letter is `q` when the connection's listening socket is a QUIC one (`c->listening->quic`), `t`
  otherwise. HTTP/3 stream connections share the QUIC connection's `SSL` object.
- Parsed lists live in the pool of the connection that owns the `SSL` object (`ngx_ssl_get_connection()`), and
  so do cached formatted strings. HTTP/2 fake connections and HTTP/3 stream connections reach them through the
  shared `SSL` object.
- SHA-256 / MD5 use OpenSSL's EVP API (`EVP_MD_CTX` streaming for JA4, so no temporary string is built).
- Parsing is strict on outer framing (as strict as OpenSSL, so it never rejects a hello OpenSSL accepts) and
  requires the ALPN / signature_algorithms / supported_versions lists to fit their extension.
