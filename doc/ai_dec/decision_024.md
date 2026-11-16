# 024 — X-Client-TLSFP sent by default

- Date: 2026-11-16
- Type: human

## Context
The packaged `nginx.conf` sends `X-Client-JA4` and `X-Client-HTTP2-FP` to upstreams by default (decision 013).

## Options
1. Also add `clientfp_request_header X-Client-TLSFP $clientfp_tlsfp;`.
2. Provide the variable only; administrators add the header themselves.

## Decision
Option 1. Client-sent copies of `X-Client-TLSFP` are removed like the other headers. The example site also
sends `X-Client-TLSFP-Registry`.
