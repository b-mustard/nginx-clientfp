# 047 — The docs write `<version>` in package file names

- Date: 2026-11-18
- Type: human

## Context
The install command in `README.md` and the example build output in `examples/echo_server.md` named
`nginx-clientfp_1.31.8-1_amd64.deb`. A build makes the newest nginx release of the line, so the names were wrong
after nginx 1.31.9 came out, and each new release would need another change.

## Decision
- These docs write `nginx-clientfp_<version>_amd64.deb` and say what `<version>` is: the newest nginx release of the
  line, then the package revision. The last line of the build output gives the real path (maintainer's choice, over
  a change of the version at each nginx release).
- Automatic: decision records, release notes and test data keep real version numbers. Decision records are
  history, release notes describe one release, and test data must be exact.
