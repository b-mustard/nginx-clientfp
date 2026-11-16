# 009 — Source acquisition and version selection

- Date: 2026-11-16
- Type: automatic

## Context
gs2: always use the newest release of each series; clone if missing, update if present. gs5: nginx 1.31.x with
OpenSSL 4.0.x, nginx 1.30.x with OpenSSL 3.5.x.

## Decision
- Sources are git clones from `https://github.com/nginx/nginx.git` and `https://github.com/openssl/openssl.git`
  in `extern_src/` (one clone each, shared by all flavors).
- On every build, `git ls-remote --tags` lists release tags; the highest `release-1.31.N` / `release-1.30.N` and
  `openssl-4.0.N` / `openssl-3.5.N` (no alpha/beta/rc) are selected. The tag is fetched shallowly if missing.
- Each flavor's tree is exported with `git archive <tag>` into `build/<flavor>/`, so `extern_src/` stays pristine
  and patches are applied to a fresh copy.
- `--offline` (or no network) falls back to the newest tag already present locally, with a warning.
- A version can be pinned on the command line for reproducible rebuilds.
