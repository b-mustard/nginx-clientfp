# 017 — OpenSSL build options and symbol hiding

- Date: 2026-11-16
- Type: automatic

OpenSSL is built by nginx's own rules (`--with-openssl`), which always pass `no-shared no-threads`. Added:

| option | why |
|---|---|
| `--openssldir=/etc/nginx/openssl` | decision 007 |
| `no-module` | providers are built into libcrypto; nothing is `dlopen()`ed from a build-tree path |
| `no-docs no-tests no-apps` | not shipped; faster build |
| `enable-ktls` | matches the distribution OpenSSL builds; usable via `ssl_conf_command Options KTLS` |

The distro's hardening flags (`dpkg-buildflags`, incl. LTO on Ubuntu) reach OpenSSL through the exported
`CFLAGS`.

Symbol hiding (gs6): nginx links with `-Wl,-E` (needed by dynamic modules). `-Wl,--exclude-libs,ALL` keeps every
symbol that comes from a static archive (`libssl.a`, `libcrypto.a`) out of the dynamic symbol table, while
nginx's own symbols stay exported. `packager/verify.py` checks each built `.deb`: no `libssl`/`libcrypto` in
`NEEDED`, and the intersection of `nm -D` of `/usr/sbin/nginx` with the global symbols of the two archives must
be empty. A failed check fails the build.

Consequence: a third-party dynamic module that calls OpenSSL functions directly cannot resolve them from nginx.
Such modules are not ABI-compatible with this build anyway.
