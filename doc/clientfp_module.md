# ngx_http_clientfp_module

Client fingerprints for nginx, compiled into the `nginx-clientfp` package:

- **JA4**: the TLS ClientHello fingerprint (FoxIO JA4), for TLS over TCP (`t…`) and QUIC / HTTP/3 (`q…`).
- **TLSFP**: the nDPI TLS client fingerprint (draft v0.1): JA4-like, without ephemeral extensions, plus a hash of
  the supported groups.
- **HTTP/2 signature**: the Akamai passive HTTP/2 fingerprint (`S|WU|P|PS`) and its MD5.

Specifications: `doc/ja4_sig.md`, `doc/tlsfp_sig.md` and `doc/http2_sig.md` in the project repository.

## Variables

| Variable | Example | Empty when |
|---|---|---|
| `$clientfp_ja4` | `t13d1516h2_8daaf6152771_e5627efa2ab1` | not TLS; no usable ClientHello (see below) |
| `$clientfp_ja4_r` | `t13d1516h2_002f,0035,…_0005,000a,…_0403,…` | as above |
| `$clientfp_ja4_o` | `t13d1516h2_acb858a92679_18f69afefd3d` | as above |
| `$clientfp_ja4_ro` | `t13d1516h2_1301,1302,…_001b,0000,…_0403,…` | as above |
| `$clientfp_tlsfp` | `t13d1514h2_8daaf6152771_aabe8f104b71_646c356617d7` | not TLS; no usable ClientHello; framing broken |
| `$clientfp_tlsfp_registry` | `1` (ephemeral extension registry version) | `$clientfp_tlsfp` is empty |
| `$clientfp_http2` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | not HTTP/2 (HTTP/1.x, HTTP/3) |
| `$clientfp_http2_hash` | `52d84b11737d980aef856699f885ca86` | as above |
| `$clientfp_http2_overflow` | `0` / `1` | as above |

- JA4 is computed from the **first** ClientHello of the connection (not the one after a HelloRetryRequest).
  Every request on the connection sees the same value.
- The HTTP/2 signature is captured from the start of the connection until the end of the first request's
  header block, then frozen; every request on the connection sees the same value (doc/http2_sig.md §3).
- At most 32 SETTINGS parameters and 32 PRIORITY frames are recorded. Past that the signature is truncated
  and `$clientfp_http2_overflow` is `1`. Real clients send 10 or fewer of each.
- A ClientHello with more than 1024 cipher suites, extensions or signature algorithms gets no JA4 (all JA4
  variables are empty, and an `info`-level line is logged).
- A TLS connection has no JA4 and no TLSFP when its ClientHello is larger than 16 KiB (or needs more than
  32 KiB of TLS records), is not a ClientHello, does not arrive within `client_header_timeout`, keeps arriving
  in tiny pieces (64 peeks), or is abandoned by the client. Each case logs an `info`-level line. An
  SSLv2-format ClientHello also gets no fingerprint; by default such connections are refused, see
  `clientfp_refuse_sslv2_hello`. An empty `$clientfp_ja4` on a TLS connection is therefore itself a signal.
- TLSFP is computed from the same first ClientHello, independently of JA4 and with no list limit. A malformed
  extension empties only the field that uses it (for example `t13d1514h2_8daaf6152771_aabe8f104b71_` for
  malformed supported groups). A hello without supported groups ends in `_000000000000`. Details and the
  draft's errata: `doc/tlsfp_sig.md`.

## Directives

### clientfp

    Syntax:  clientfp on | off;
    Default: clientfp on;
    Context: http

Turns capture on or off for the whole `http {}` block. When off, the ClientHello and HTTP/2 hooks do nothing,
all variables are empty, and `clientfp_refuse_sslv2_hello` has no effect.

### clientfp_refuse_sslv2_hello

    Syntax:  clientfp_refuse_sslv2_hello on | off;
    Default: clientfp_refuse_sslv2_hello on;
    Context: http

An SSLv2-format (backwards-compatible) ClientHello has no defined fingerprint, so such a connection would get
none. When on, the connection is closed before the TLS library reads the hello, and an `info`-level line
("SSLv2-format ClientHello refused") is logged. When off, the TLS library decides; the connection then has no
JA4 and no TLSFP.

In practice the TLS library refuses these hellos anyway unless the security level is 0 (`ssl_ciphers
…:@SECLEVEL=0`) and RSA key exchange ciphers are enabled: the format cannot carry `signature_algorithms`, so
TLS 1.2 falls back to SHA-1, which the distributions' TLS library allows only at level 0. No mainstream client
sends this format. `ssl_protocols` cannot turn it off: nginx's `SSLv2` keyword no longer has any effect.

### clientfp_request_header

    Syntax:  clientfp_request_header name value;
    Default: —
    Context: http, server

Before any other request processing (POST_READ phase), every header line named `name` that the client sent
is removed from the request, then `name: value` is added if `value` (which may contain variables) is not
empty. Upstream modules (`proxy_pass`, `fastcgi_pass`, `grpc_pass`, `uwsgi_pass`, `scgi_pass`) then forward the
header like any other client header, and `$http_<name>` returns the trusted value. Clients therefore cannot
spoof these headers.

- `name` may contain only letters, digits and `-`. Headers that nginx itself interprets (`Host`, `Cookie`,
  `X-Forwarded-For`, `User-Agent`, …) are rejected at configuration time.
- Directives in a `server {}` block replace the whole list inherited from `http {}`.
- The packaged `/etc/nginx/nginx.conf` enables:

      clientfp_request_header X-Client-JA4 $clientfp_ja4;
      clientfp_request_header X-Client-TLSFP $clientfp_tlsfp;
      clientfp_request_header X-Client-HTTP2-FP $clientfp_http2;

## Logging example

    log_format clientfp '$remote_addr [$time_local] "$request" $status ja4=$clientfp_ja4 '
                        'tlsfp=$clientfp_tlsfp/$clientfp_tlsfp_registry h2="$clientfp_http2"';
    access_log /var/log/nginx/clientfp.log clientfp;

## Implementation notes

- ClientHello capture (`clientfp_hello.c`), independent of the TLS library:
  - TLS over TCP: a hook in `ngx_http_ssl_handshake()` (`patches/nginx/<line>/0002-*`) runs before the TLS
    library reads anything. The module peeks at the socket (`MSG_PEEK`, so the TLS library later reads the same
    bytes) and reassembles the ClientHello from its handshake records. While it is incomplete the connection waits
    for more data under `client_header_timeout`, and, as during the handshake, nginx does not close it to make room
    for other connections. `FIONREAD` avoids copying until the bytes still needed have arrived. It gives up (no
    fingerprint, the handshake goes on) after 64 peeks or when the client closes its side.
    An SSLv2-format ClientHello is recognised from its first three bytes and refused or passed on as set by
    `clientfp_refuse_sslv2_hello`.
  - QUIC: a hook in `ngx_quic_handle_crypto_frame()` passes the CRYPTO frames of Initial packets, in any order
    and overlapping, until HTTP/3 starts its session.
  - Limits: a ClientHello of at most 16 KiB, carried in at most 32 KiB of TLS records. Larger, malformed or
    abandoned hellos give no JA4/TLSFP and an `info` line in the error log. Empty handshake records are skipped,
    as the TLS library skips them.
  - The result is kept in the connection's `ngx_http_connection_t` (a field the patch adds), so HTTP/1.x, HTTP/2
    and HTTP/3 requests find it.
- JA4: the captured ClientHello is parsed into compact lists (typically 100–200 bytes per connection); strings are
  formatted on first use. Unknown and GREASE extensions are seen exactly as sent.
- TLSFP: computed once from the same ClientHello by its own parser (`clientfp_tlsfp.c`); the lists are sorted in
  temporary memory freed at once, and only the 49-byte string is kept per connection.
- Hashes: SHA-256 (JA4, TLSFP) is the module's own (`clientfp_sha256.c`); the HTTP/2 MD5 is nginx's `ngx_md5`.
  The module calls no TLS library function.
- HTTP/2: a small patch on `src/http/v2/ngx_http_v2.c` (`patches/nginx/<line>/`) reports SETTINGS,
  WINDOW_UPDATE, PRIORITY frames and pseudo-header names to the module. About 600 bytes per HTTP/2 connection.
- TLS: nginx is linked with the distribution's libssl; system-wide TLS configuration applies as for the
  distribution's own nginx.
