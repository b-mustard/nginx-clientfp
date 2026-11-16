# 004 — Header extension: variables + request-header directive

- Date: 2026-11-16
- Type: human

## Context
gs7: an nginx extension that puts the signatures into HTTP headers.

## Options
1. Variables plus a directive that injects headers into the client request before upstream modules run, after
   removing any client-sent header of the same name (anti-spoofing).
2. Variables only (`proxy_set_header X-JA4 $clientfp_ja4;` per upstream type).
3. Option 1 plus response headers.

## Decision
Option 1. The module exposes `$clientfp_*` variables and a directive (working name `clientfp_request_header`).
Injected headers are seen by proxy, fastcgi, grpc, uwsgi and scgi without extra config; spoofed copies sent by
the client are always removed.
