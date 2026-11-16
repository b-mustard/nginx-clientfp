# 010 — .deb assembly with debhelper

- Date: 2026-11-16
- Type: human

## Options
1. Python renders `debian/` and runs `dpkg-buildpackage` (debhelper compat 13).
2. Python stages the tree and calls `dpkg-deb --build` directly.

## Decision
Option 1. `dh_shlibdeps` computes per-distro `Depends`; `dh_installsystemd`, `dh_installman`, `dh_installlogrotate`
and `dh_strip` (separate `-dbgsym` package) follow Debian policy; `lintian` checks the result.
The build environment needs `debhelper`.
