# 007 — Private OPENSSLDIR with shipped openssl.cnf

- Date: 2026-11-16
- Type: human

## Context
With OpenSSL linked statically, nginx reads `$OPENSSLDIR/openssl.cnf` at startup. The default OPENSSLDIR would be a
build-tree path.

## Options
1. Private `OPENSSLDIR=/etc/nginx/openssl` + minimal commented `openssl.cnf` shipped as a conffile.
2. System `/usr/lib/ssl` (distro crypto policy; risk of version skew stopping nginx).
3. Private dir, no config file.

## Decision
Option 1. Behaviour does not change when the system openssl package is updated; admins can still edit the file.
