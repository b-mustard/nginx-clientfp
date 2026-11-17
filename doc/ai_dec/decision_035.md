# 035 — HTTP/3 on every target

- Date: 2026-11-17
- Type: human

## Context
With the distribution's TLS library (decision 029), Debian 12 and Ubuntu 24.04 (OpenSSL 3.0) get nginx's QUIC
compatibility layer, which has no 0-RTT. Debian 13 and Ubuntu 26.04 (OpenSSL 3.5) get the native QUIC API. The
capture of decision 030 gives HTTP/3 fingerprints with both.

## Options
1. Build `--with-http_v3_module` on all targets.
2. Build HTTP/3 only where the system library has the native QUIC API.

## Decision
Option 1. The compatibility layer is supported upstream since nginx 1.25. The documentation says that 0-RTT needs
a system TLS library with the native QUIC API.
