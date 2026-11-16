# Tests

All tests are pytest. Run them through `./build.sh` (it sets up `.venv` and `PYTHONPATH`) or with
`.venv/bin/python -m pytest`. The strategy is recorded in [decision 019](../doc/ai_dec/decision_019.md).

```
./build.sh check                                  # mypy + every test that needs neither docker nor a build
./build.sh test tests/test_c_core.py              # C cores under ASan/UBSan vs the Python reference
./build.sh test tests/test_fuzz.py --fuzz-seconds 300
./build.sh build --target ubuntu-24.04 && ./build.sh asan --flavor 1.31
./build.sh test tests/integration                 # package + ASan nginx (default: --target ubuntu-24.04 --flavor 1.31)
./build.sh test tests/integration --target debian-13 --flavor 1.30
```

## Markers

| marker | meaning |
|---|---|
| `docker` | needs a working `docker` (rootless is fine) |
| `nginx` | needs a built package in `dist/<target>/` or an ASan build in `build/asan/<flavor>/`; skipped otherwise |
| `slow` | minutes, not seconds (live-client probes, libFuzzer) |
| `network` | talks to public reference servers; never needed for a release |

## Layout

| path | what |
|---|---|
| `unit/` | Reference calculators (`tools/clientfp/fp`) against the spec's worked examples and the recorded vectors in `doc/ja4_vectors.json`. These are the oracle for everything else. |
| `test_c_core.py` | Builds `c/ja4_driver.c` and `c/h2_driver.c` with the module's `clientfp_ja4.c` / `clientfp_h2.c`, ASan + UBSan, in the `nginx-clientfp-ctest` image (`docker/Dockerfile.ctest`). JA4: all vectors, about 9,700 mutated hellos (status and all four forms must equal the reference), list caps, impossible input. HTTP/2: probe cases and 400 random frame sequences translated into the hook calls the nginx patch makes, plus extreme event counts. |
| `test_fuzz.py`, `fuzz/` | libFuzzer targets for both cores, seeded with the vectors; `--fuzz-seconds` each. Crash reproducers and logs go to `build/fuzz/<target>/`. |
| `integration/conftest.py` | Fixtures. `nginx_pkg` installs the `.deb` with `dpkg -i` into a clean container of the target distribution (`docker/Dockerfile.runtime`). `nginx_asan` runs the ASan/UBSan nginx in the build image. Both serve `integration/clientfp-test.conf` with a fresh self-signed certificate and use `examples/echo_server.py` as the upstream. Ports are random and published on 127.0.0.1. TCP and UDP share a port number for QUIC. Error logs end up in `build/test-logs/`. |
| `integration/test_package.py` | Package contents, conffiles, dependencies (no libssl), `nginx -V`, packaged config valid, no OpenSSL symbol exported. |
| `integration/test_fingerprints.py` | `clientfp-ja4-probe` (45 client cases incl. HTTP/3), `clientfp-h2-probe` (synthetic frame sequences), `clientfp-h2-clients` (real HTTP/2 clients over TLS and h2c). nginx must return exactly what the reference computes from the captured bytes. |
| `integration/test_headers.py` | `clientfp_request_header`: headers reach the upstream over HTTP/1.1 and HTTP/2; client-sent copies are removed in any letter case; a server-level list replaces the http-level one; invalid names are rejected by `nginx -t`. |
| `integration/test_hostile.py` | t3 against both the package and the ASan build. HTTP/2 coverage: every hooked frame split at every byte, floods (2730 settings, 20,000 PRIORITY, 1-octet CONTINUATION), malformed frames, odd pseudo-headers, dropped connections. TLS coverage: mutated hellos with consistent outer framing, impossible records, lists over the 1024 cap, half-open handshake floods. After each test nginx must answer and must show no crashed worker and no sanitizer report. |

## When a test fails

- A C-core mismatch prints the hello in hex. Feed it to the reference: `clientfp-ja4 <hex>`. Feed it to the
  driver: `echo "t <hex>" | docker run --rm -i -v $PWD:/work -w /work nginx-clientfp-ctest build/ctest/ja4_driver`.
- An integration failure leaves the nginx error log in `build/test-logs/<container>.log`. ASan reports go to
  `build/test-logs/<container>-asan.log`.
