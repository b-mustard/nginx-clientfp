# 003 — Per-distro dist/ subdirectories

- Date: 2026-11-16
- Type: human

## Context
The gs9 file name (`nginx-clientfp_<nginx>+openssl<openssl>-<rev>_amd64.deb`) carries no distro, but gs4 builds for
several distros.

## Options
1. Keep the exact gs9 name; separate distros by directory: `dist/<distro>-<version>/`.
2. nginx.org-style `~codename` suffix in the revision.
3. Both.

## Decision
Option 1, e.g. `dist/ubuntu-24.04/nginx-clientfp_1.31.8+openssl4.0.3-1_amd64.deb`.
The package version is identical across distros.
