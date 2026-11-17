# 036 — SSLv2-format ClientHellos: no fingerprint, refused by default

- Date: 2026-11-18
- Type: human

## Context
The distribution's TLS library (decision 029) is OpenSSL 3.0 or 3.5 on every target, and both accept an
SSLv2-format (backwards-compatible) ClientHello as the first record of a connection. No library option turns this
off, and nginx's `SSL_OP_NO_SSLv2` (set unless `ssl_protocols` lists `SSLv2`) has been defined as 0 since
OpenSSL 1.1.0. Such a hello cannot carry extensions, so TLS 1.2 falls back to SHA-1 signatures. Measured on Ubuntu
24.04 (OpenSSL 3.0.13), the handshake goes ahead only with `@SECLEVEL=0` and RSA key exchange ciphers; nginx's
defaults, the packaged `nginx.conf`, the Mozilla "intermediate" list and `@SECLEVEL=1` all refuse it.

The capture of decision 030 reads TLS handshake records only, so a connection that does get through has no JA4 and
no TLSFP. Neither the JA4 spec nor the reference implementations define a fingerprint for this format.

## Options
1. No fingerprint, documented.
2. Fingerprint it with a mapping of our own (cipher specs, no extensions, version from the hello).
3. Refuse it (close the connection before the handshake).

## Decision
Option 1, plus option 3 as a setting: `clientfp_refuse_sslv2_hello on | off` (http level, default `on`). When it
is on, the module closes a connection whose first record is an SSLv2-format ClientHello before the TLS library
reads it, and logs this at `info` level. When it is off, the handshake is left to the TLS library and the
connection has no fingerprint. The setting acts only while `clientfp` is on.
