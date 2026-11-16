# ngx_http_clientfp_module

Client fingerprints for nginx, compiled into the `nginx-clientfp` package:

- **JA4**: the TLS ClientHello fingerprint (FoxIO JA4), for TLS over TCP (`t…`) and QUIC / HTTP/3 (`q…`).
- **HTTP/2 signature**: the Akamai passive HTTP/2 fingerprint (`S|WU|P|PS`) and its MD5.

Specifications: `doc/ja4_sig.md` and `doc/http2_sig.md` in the project repository.

## Variables

| Variable | Example | Empty when |
|---|---|---|
| `$clientfp_ja4` | `t13d1516h2_8daaf6152771_e5627efa2ab1` | not TLS; malformed or oversized ClientHello |
| `$clientfp_ja4_r` | `t13d1516h2_002f,0035,…_0005,000a,…_0403,…` | as above |
| `$clientfp_ja4_o` | `t13d1516h2_acb858a92679_18f69afefd3d` | as above |
| `$clientfp_ja4_ro` | `t13d1516h2_1301,1302,…_001b,0000,…_0403,…` | as above |
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

## Directives

### clientfp

    Syntax:  clientfp on | off;
    Default: clientfp on;
    Context: http

Turns capture on or off for the whole `http {}` block. When off, no ClientHello callback is installed, the
HTTP/2 hooks do nothing and all variables are empty.

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
      clientfp_request_header X-Client-HTTP2-FP $clientfp_http2;

## Logging example

    log_format clientfp '$remote_addr [$time_local] "$request" $status ja4=$clientfp_ja4 h2="$clientfp_http2"';
    access_log /var/log/nginx/clientfp.log clientfp;

## Implementation notes

- JA4: a `msg_callback` installed on every server `SSL_CTX` of `http {}` sees the raw ClientHello before OpenSSL
  parses it (unknown and GREASE extensions included, which the `SSL_client_hello_*` API drops). Only compact
  lists are kept per connection (typically 100–200 bytes); strings are formatted on first use. OpenSSL is not
  patched.
- HTTP/2: a small patch on `src/http/v2/ngx_http_v2.c` (`patches/nginx/<line>/`) reports SETTINGS,
  WINDOW_UPDATE, PRIORITY frames and pseudo-header names to the module. About 600 bytes per HTTP/2 connection.
- `OPENSSLDIR` is `/etc/nginx/openssl`; the static OpenSSL reads `/etc/nginx/openssl/openssl.cnf`, not the
  system file.
