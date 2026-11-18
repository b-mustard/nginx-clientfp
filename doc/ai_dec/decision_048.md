# 048 — The tests use the package with the highest version

- Date: 2026-11-18
- Type: human

## Context
The integration tests install the package of a line from `dist/<target>/`. When the directory had more than one,
they used the last file name in text order. In text order `1.31.10` comes before `1.31.9`, so after nginx 1.31.10
the tests would use an older package and not say so.

## Decision
- The tests use the package with the highest version (maintainer's choice, over the order of file names).
- Automatic: versions are compared with the rules of dpkg, the order that apt uses, for both the nginx version and
  the package revision. A revision can have letters and `~` (the build takes it from `--revision`).
- Automatic: the selection is `newest_deb()` in `packager/model.py`, next to the file name scheme (decision 031),
  so that the unit tests can check it without docker.
