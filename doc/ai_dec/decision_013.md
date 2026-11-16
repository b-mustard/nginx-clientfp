# 013 — Defaults: capture and header injection enabled

- Date: 2026-11-16
- Type: human

## Options
1. Capture on, headers off (commented example only).
2. Capture off.
3. Capture on, and the packaged `nginx.conf` injects the signatures into every upstream request.

## Decision
Option 3.
- `clientfp on;` is the module default.
- The packaged `/etc/nginx/nginx.conf` contains, in `http {}`:
  `clientfp_request_header X-Client-JA4 $clientfp_ja4;` and
  `clientfp_request_header X-Client-HTTP2-FP $clientfp_http2;`.
- Client-sent copies of those headers are always removed first (decision 004), so upstreams can trust them.
