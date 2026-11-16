# 019 — Test strategy

- Date: 2026-11-16
- Type: automatic

Three layers, all pytest, selected with markers (`nginx`, `docker`, `network`, `slow`):

1. **Reference unit tests** (`tests/unit`, no markers): the Python calculators in `tools/clientfp/fp` against the
   spec examples and recorded vectors. These calculators are the oracle for everything else.
2. **C core** (`tests/test_c_core.py`, `docker`): the module's pure-C JA4 and HTTP/2 cores compiled with clang
   ASan+UBSan into small stdin drivers, run in the `nginx-clientfp-ctest` image.
   - JA4: all recorded vectors, about 9,700 mutated hellos compared with the reference (same status, same four
     forms), list caps, impossible inputs.
   - HTTP/2: the probe cases plus 400 random frame sequences, turned into the hook calls the nginx patch makes
     and compared with the reference; extreme event counts.
   - libFuzzer targets in `tests/fuzz` (`test_fuzz.py`, `slow`).
3. **Integration** (`tests/integration`, `nginx` + `docker`):
   - The built `.deb` installed with `dpkg -i` in a clean container of the target distribution: package
     contents, conffiles, dependencies, `nginx -V`, exported symbols.
   - Live clients through `clientfp-ja4-probe`, `clientfp-h2-probe` and `clientfp-h2-clients`.
   - Header injection and anti-spoofing through the examples echo server.
   - Hostile input (t3) against both the package and an ASan/UBSan nginx (`./build.sh asan`):
     - segmented, flooded and malformed HTTP/2 frames;
     - mutated and impossible TLS hellos;
     - oversized lists;
     - dropped connections.

     After each test the server must answer, with no crashed worker and no sanitizer report.

Rejected: comparing against public reference servers in CI (`network` marker only). They change without notice,
and they are unreachable in offline builds.
