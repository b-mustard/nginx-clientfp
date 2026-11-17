# 029 — Remove OpenSSL from the project; nginx uses the distribution's TLS library

- Date: 2026-11-17
- Type: human

## Context
The user asked to remove OpenSSL from the project completely: code, documentation (except decisions) and naming.
Until now each package built OpenSSL 4.0.x (nginx 1.31) or 3.5.x (nginx 1.30) from source and linked it
statically (gs5, gs6, decisions 006, 007, 009, 017).

Research before this decision (2026-11-17):
- OpenSSL needs no patch for our approach in any version from 1.0.2 to 4.0.
- Supported apt-based distributions ship OpenSSL 3.0 (Debian 12, Ubuntu 22.04/24.04) or 3.5 (Debian 13,
  Ubuntu 26.04). Ubuntu 26.10 ships 4.0.

nginx still needs a TLS library for https and HTTP/3; JA4 and TLSFP need TLS.

## Options
1. Use the distribution's system TLS library (libssl), linked dynamically. The project stops fetching, building,
   patching, naming and symbol-checking OpenSSL.
2. Bundle a different TLS library (BoringSSL, AWS-LC, LibreSSL) and link it statically.
3. No TLS at all: only the HTTP/2 fingerprint on cleartext h2c remains.

## Decision
Option 1.
- Each package is built against the libssl of its target distribution (`Build-Depends: libssl-dev`); the runtime
  dependency comes from `dpkg-shlibdeps`. Security updates for TLS come from the distribution.
- Removed: OpenSSL source acquisition and version selection, the static build and its options, the private
  `/etc/nginx/openssl/openssl.cnf`, the symbol-leak checks, and every OpenSSL name in our code, docs and package
  names.
- Supersedes the OpenSSL parts of gs5 (version pairing), gs6 (static linking and symbol check), gs9 (package name),
  and decisions 006, 007, 009 and 017 as far as they concern OpenSSL.
- How the module gets the ClientHello without OpenSSL calls: decision 030. Package version: decision 031.
