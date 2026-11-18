# 041 — The changelog names the codename of the target

- Date: 2026-11-18
- Type: automatic

## Context
`debian/changelog` said `unstable` for every target. dpkg-buildpackage reported "source distribution unstable", and
every package claimed to be for Debian unstable, whichever distribution it was built for. The user pointed this out.

## Decision
- The distribution field of the changelog is the codename of the target, as `VERSION_CODENAME` in its
  `/etc/os-release` gives it: `noble` (Ubuntu 24.04), `resolute` (Ubuntu 26.04), `bookworm` (Debian 12), `trixie`
  (Debian 13). `TARGETS` in `packager/model.py` holds the codenames.
- A native build on a distribution that is not in `TARGETS` takes `VERSION_CODENAME` of the running system. The
  build stops if there is none.
- The test builds (`./build.sh asan`, `./build.sh valgrind`) make no package. Their tree gets `UNRELEASED`.
- Tests: `tests/unit/test_packager.py` renders `debian/` for each target. `tests/integration/test_package.py`
  compares the changelog in the `.deb` with `VERSION_CODENAME` in a container of the target distribution, so a
  wrong entry in `TARGETS` is found too.

## Not changed
The version stays the same for every distribution (decision 003), and `dist/<distro>/` keeps the packages apart. An
apt repository that serves several distributions from one pool needs a different version for each distribution (for
example a `~noble` suffix). That is a separate decision.
