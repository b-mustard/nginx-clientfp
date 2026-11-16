# 002 — Debian/Ubuntu-style package layout

- Date: 2026-11-16
- Type: human

## Context
gs10 requires a complete package (man page, `/etc/nginx` files, service integration).

## Options
1. nginx.org style: `conf.d/`, user `nginx`, `/var/cache/nginx`.
2. Debian/Ubuntu style: `sites-available/` + `sites-enabled/`, `snippets/`, `modules-enabled/`, user `www-data`,
   temp dirs under `/var/lib/nginx`.
3. Hybrid.

## Decision
Option 2. The package mirrors the distro nginx layout so existing Debian/Ubuntu configs drop in. It conflicts with,
replaces and provides the distro `nginx` packages.
