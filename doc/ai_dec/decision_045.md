# 045 — GitHub releases of the packages

- Date: 2026-11-18
- Type: human

## Context
The maintainer asked to publish the packages as releases on the public repository `origin_pub` (decision 042).
A build makes 8 packages: 2 nginx lines times 4 distributions. The 4 packages of one line have the same file
name, because the version is the same on every distribution (decision 003), and GitHub needs a different name for
each file of a release.

## Decision
- One release holds all 8 packages. Its tag is the date of the build, for example `2026-11-18`, on the pushed
  commit the packages are built from (maintainer's choice, over one release for each nginx line).
- An uploaded file has the distribution before the architecture:
  `nginx-clientfp_<version>_<distribution>_amd64.deb`, for example
  `nginx-clientfp_1.31.8-1_debian-12_amd64.deb`. The package itself is not changed.
- Each release has a `SHA256SUMS` file for its packages. The debug symbol packages (Debian targets only) are not
  uploaded.
- The release is published at once and marked Latest. It is created as a draft first, and published only when all
  its files are uploaded and their checksums agree with the local files.
- Before a release, all 8 packages are built again from the commit, and the package tests run for each target.
