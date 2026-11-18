# 040 — valgrind's memcheck in the tests

- Date: 2026-11-18
- Type: automatic

## Context
The C code was tested with ASan and UBSan only. The user asked for valgrind to be used as well, and installed in the
docker images. Memcheck adds what ASan cannot see: reads of uninitialised memory, and every block not freed at exit
without LeakSanitizer's limits. It cannot see overruns of stack or global arrays, which ASan keeps covering.

## Decision
- valgrind is installed in the C test image (`tests/docker/Dockerfile.ctest`) and in the build image
  (`packager/docker/Dockerfile`), where the test builds of nginx run.
- One memcheck command line for every use (`tests/conftest.py`, `VALGRIND`): `-q`, full leak check, and the
  definite, indirect and possible leak kinds count as errors. Any output from memcheck is a finding.
- C cores: every test in `tests/test_c_core.py` runs twice, with the ASan + UBSan drivers (-O1) and with drivers
  built without sanitizers at -O2 (as the package is) under memcheck.
- Fuzzing: after each libFuzzer run, the corpus it leaves is replayed under memcheck by the same target built at -O2
  without sanitizers (`tests/fuzz/replay_main.c`).
- nginx: `./build.sh valgrind` builds the patched nginx at -O2 without sanitizers, with NGX_DEBUG_PALLOC so every
  pool allocation is its own block (`packager/testbuild.py`, formerly `asan.py`, builds both test variants). The
  integration tests that send traffic run against the package, the ASan build and this build under memcheck. The
  memcheck server is stopped gracefully at the end, so its leak report covers every process.
- Suppressions (`tests/valgrind/nginx.supp`) cover only blocks nginx itself allocates once per worker and never frees
  because the process exits: the connection and event arrays, and the worker's environment.
