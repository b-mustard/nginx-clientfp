# 008 — nginx module set

- Date: 2026-11-16
- Type: human

## Options
1. Debian's module set with no external-library modules, plus HTTP/3.
2. Option 1 + dynamic geoip, image_filter, xslt, perl.
3. Option 1 without HTTP/3.

## Decision
Option 1. Compiled in: ssl, v2, v3 (QUIC), realip, stub_status, auth_request, dav, slice, addition, flv, gunzip,
gzip_static, mp4, random_index, secure_link, sub, mail + mail_ssl, stream + stream_ssl + stream_ssl_preread +
stream_realip, threads, pcre-jit, debug, and the clientfp module. `--with-compat` is kept.
Runtime dependencies are limited to libc, libpcre2-8 and zlib. Over HTTP/3, JA4 reports `q…`.
