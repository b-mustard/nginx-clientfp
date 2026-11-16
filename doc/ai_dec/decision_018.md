# 018 — Docker builds: rootless detection, build images, tree location

- Date: 2026-11-16
- Type: automatic

- One build image per target (`nginx-clientfp-build:<target>`, from `packager/docker/Dockerfile` with
  `BASE=<distro image>`), labelled with a digest of the Dockerfile so it is rebuilt only when that file changes.
- The repository is bind-mounted at `/work`. Trees are prepared on the host (`build/<target>/<flavor>/...`) and
  only `dpkg-buildpackage` runs in the container, so the same code path serves native and docker builds.
- Rootless docker maps container root to the invoking user. `--user` is then left out, because it would map to a
  sub-uid that cannot write the bind mount. With rootful docker, `--user $(id -u):$(id -g)` keeps `build/` and
  `dist/` owned by the user. Detection: `docker info --format '{{json .SecurityOptions}}'` contains `rootless`.
- Patches are applied with `git apply` with `GIT_CEILING_DIRECTORIES` set to the tree's parent. Without it, git
  finds this project's repository above `build/`, resolves patch paths against it and skips every file without an
  error. Each patch is then checked with `git apply --reverse --check`, and the built binary must export every
  module/hook symbol (`packager/verify.py`), so a patch can never again be lost without failing the build.
