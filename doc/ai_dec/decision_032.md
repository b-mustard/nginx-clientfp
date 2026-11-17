# 032 — Remove the OpenSSL-only tools and tests

- Date: 2026-11-17
- Type: human

## Context
Some tools and tests existed only to exercise OpenSSL:
- `tools/harness/ja4_ossl_harness.c` and `clientfp-ja4-harness-check` (what OpenSSL's ClientHello API drops);
- the installed-package checks for static OpenSSL and leaked symbols, and `packager/verify.py`'s symbol check;
- `/etc/nginx/openssl/openssl.cnf`;
- six `clientfp-ja4-probe` cases that use the `openssl s_client` binary as a client.

## Options
1. Remove all of them. tlslite-ng rebuilds the specific hellos the s_client cases covered.
2. Remove everything except the s_client cases.

## Decision
Option 1.
