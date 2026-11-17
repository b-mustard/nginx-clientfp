# 031 — Package version without the TLS library: `<nginx>-<revision>`

- Date: 2026-11-17
- Type: human

## Context
gs9 named packages `nginx-clientfp_1.31.x+openssl4.0.x-1_amd64.deb`. After decision 029 the version carries no TLS
library. dpkg sorts `1.31.8-1` below the old `1.31.8+openssl4.0.3-1`, so apt does not upgrade a machine that has
an old build installed.

## Options
1. Plain `1.31.8-1` (`nginx-clientfp_1.31.8-1_amd64.deb`). Machines with an old build need a one-time manual
   reinstall.
2. Epoch `1:1.31.8-1`: same file name, upgrades cleanly, but every later version carries the epoch.

## Decision
Option 1. The revision stays configurable (`--revision`, default 1). Nothing had been deployed from the old
naming scheme.
