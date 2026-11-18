# Tests

All tests are pytest. Run them through `./build.sh` (it sets up `.venv` and `PYTHONPATH`) or with
`.venv/bin/python -m pytest`. The strategy is recorded in [decision 019](../doc/ai_dec/decision_019.md).

```
./build.sh check                                  # mypy + every test that needs neither docker nor a build
./build.sh test tests/test_c_core.py              # C cores under ASan/UBSan and valgrind vs the Python reference
./build.sh test tests/test_fuzz.py --fuzz-seconds 300
./build.sh build --target ubuntu-24.04 && ./build.sh asan --flavor 1.31 && ./build.sh valgrind --flavor 1.31
./build.sh test tests/integration                 # package, ASan and valgrind nginx (default: --target ubuntu-24.04 --flavor 1.31)
./build.sh test tests/integration --target debian-13 --flavor 1.30
```

## Markers

| marker | meaning |
|---|---|
| `docker` | needs a working `docker` (rootless is fine) |
| `nginx` | needs a built package in `dist/<target>/`, or an ASan or valgrind build in `build/{asan,valgrind}/<flavor>/`; skipped otherwise |
| `slow` | minutes, not seconds (live-client probes, libFuzzer) |
| `network` | talks to public reference servers; never needed for a release |

## Layout

| path | what |
|---|---|
| `unit/` | Reference calculators (`tools/clientfp/fp`) against the spec's worked examples and the recorded vectors in `doc/ja4_vectors.json`. These are the oracle for everything else. TLSFP (`test_fp_tlsfp.py`) checks each rule of `doc/tlsfp_sig.md` with hand-written hash inputs, since the draft's own vectors are partly wrong. `test_packager.py` checks the `debian/` files the packager renders: the changelog names the codename of each target (decision 041). `test_license.py` checks the license notices (decision 043): `LICENSE`, the SPDX and copyright lines at the top of every code file, and the documents that keep the license of their source. |
| `test_c_core.py` | Builds `c/{ja4,tlsfp,h2,hello,sha256}_driver.c` with the module's matching cores (`clientfp_ja4.c`, `clientfp_tlsfp.c`, `clientfp_h2.c`, `clientfp_hello.c`, `clientfp_sha256.c`) in the `nginx-clientfp-ctest` image (`docker/Dockerfile.ctest`), twice: with ASan + UBSan at -O1, and without sanitizers at -O2 (as the package) under valgrind's memcheck, which also reports reads of uninitialised memory and every block not freed. Every test below runs with both. JA4: all vectors, about 9,700 mutated hellos (status and all four forms must equal the reference), list caps, impossible input. TLSFP: the same vectors and mutations, plus corrupted ALPN / supported_versions / signature_algorithms / supported_groups inner lists (only that field may be empty) and lists of up to 32,767 entries; the driver aborts on any leaked temporary buffer. HTTP/2: probe cases and 400 random frame sequences translated into the hook calls the nginx patch makes, plus extreme event counts (the MD5 is checked with hashlib, as the module hashes with `ngx_md5`). ClientHello capture: every vector split into records every way, thousands of prefixes, hostile record streams, empty records, and shuffled, overlapping, conflicting QUIC CRYPTO fragments, SSLv2-format hellos, against `clientfp.fp.hello`; the number of bytes the TCP capture says it still needs must be a true lower bound. SHA-256: hashlib's digest for every length around the block boundaries, fed in pieces of every size. |
| `test_fuzz.py`, `fuzz/` | libFuzzer targets for the JA4, TLSFP and HTTP/2 cores and for the capture (whose output feeds JA4 and TLSFP), seeded with the vectors; `--fuzz-seconds` each. The corpus each run leaves is then replayed under memcheck (`fuzz/replay_main.c`, -O2, no sanitizers). Crash reproducers and logs go to `build/fuzz/<target>/`. |
| `integration/conftest.py` | Fixtures. `nginx_pkg` installs the `.deb` with `dpkg -i` into a clean container of the target distribution (`docker/Dockerfile.runtime`). `nginx_asan` runs the ASan/UBSan nginx in the build image, `nginx_valgrind` the `./build.sh valgrind` nginx under memcheck in the same image (with `valgrind/nginx.supp`); at the end of the session it is stopped gracefully so that memcheck reports leaks, and any memcheck output fails the session. All three serve `integration/clientfp-test.conf` with a fresh self-signed certificate and use `examples/echo_server.py` as the upstream. `srv` is each of the three in turn, checked after every test: still answering, no crashed worker, no sanitizer report, no memcheck error. `custom_nginx()` starts any of them with an `nginx.conf` of the test's own (`nginx_conf()`: other `events` or `http` settings) in a container of its own. Ports are random and published on 127.0.0.1. TCP and UDP share a port number for QUIC. Error logs end up in `build/test-logs/`. |
| `integration/test_package.py` | Package contents, conffiles, dependencies (the distribution's libssl, PCRE2, zlib), libssl and libcrypto resolved as shared libraries, `nginx -V`, packaged config valid, the changelog's distribution is the target's codename, `clientfp_refuse_sslv2_hello off` (a second nginx in the container answers an SSLv2-format hello, without a fingerprint). |
| `integration/test_fingerprints.py` | Against the package, the ASan build and the valgrind build (`srv`). `clientfp-ja4-probe` (41 client cases incl. HTTP/3; JA4 and TLSFP), `clientfp-h2-probe` (synthetic frame sequences), `clientfp-h2-clients` (real HTTP/2 clients over TLS and h2c). nginx must return exactly what the reference computes from the captured bytes. |
| `integration/test_headers.py` | `clientfp_request_header`, against the package, the ASan build and the valgrind build: headers reach the upstream over HTTP/1.1 and HTTP/2; client-sent copies are removed in any letter case; a server-level list replaces the http-level one; invalid names are rejected by `nginx -t`. |
| `integration/test_hostile.py` | t3 against the package, the ASan build and the valgrind build under memcheck (`srv`). HTTP/2 coverage: every hooked frame split at every byte, floods (2730 settings, 20,000 PRIORITY, 1-octet CONTINUATION), malformed frames, odd pseudo-headers, dropped connections. TLS coverage: mutated hellos with consistent outer framing, impossible records, lists over the 1024 cap, half-open handshake floods, real handshakes whose hello is framed in 1- or 40-byte records or with empty records and sent whole, in 50-byte or in 1-byte TCP segments (the server's JA4 must equal the client's), a half-sent hello followed by FIN (released at once), an SSLv2-format hello (refused by default), real handshakes with up to 3,000 ciphers / 2,000 extensions (no JA4, exact TLSFP). After each test nginx must answer and must show no crashed worker, sanitizer report or memcheck error. |
| `integration/test_hello_wait.py` | How the TCP ClientHello capture waits, each case in an nginx of its own. Under `use poll` and `use select` (ASan and valgrind builds only; the package has epoll alone, decision 039): a hello that arrived whole is fingerprinted, one arriving in pieces is not, and a stalled hello does not make the worker spin. With `worker_connections 32`: connections whose hello has partly arrived survive while nginx closes idle connections to make room, then complete their handshakes with the right JA4 (decision 038). A hello sent a byte every half second is closed at `client_header_timeout`. |
| `valgrind/nginx.supp` | memcheck suppressions for the valgrind nginx: only blocks nginx itself allocates once per worker and never frees (the process exits). |

## When a test fails

- A C-core mismatch prints the hello in hex. Feed it to the reference: `clientfp-ja4 <hex>`. Feed it to the
  driver: `echo "t <hex>" | docker run --rm -i -v $PWD:/work -w /work nginx-clientfp-ctest build/ctest/asan/ja4_driver`.
  TLSFP: `clientfp-tlsfp <hex>` and `build/ctest/asan/tlsfp_driver`.
- An integration failure leaves the nginx error log in `build/test-logs/<container>.log`. ASan reports go to
  `build/test-logs/<container>-asan.log`, the valgrind nginx's full memcheck output to
  `build/test-logs/<container>-valgrind.log`.
- A memcheck finding in a C driver is printed in the test failure. To rerun one input by hand, prefix the driver
  with valgrind: `echo "t <hex>" | docker run --rm -i -v $PWD:/work -w /work nginx-clientfp-ctest valgrind -q
  --leak-check=full --track-origins=yes build/ctest/valgrind/ja4_driver`.
