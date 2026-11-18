# 039 — Level-triggered event methods are tested on the ASan build only

- Date: 2026-11-18
- Type: automatic

## Context
The module waits for the rest of a ClientHello only with edge-triggered event methods (epoll, kqueue). With a
level-triggered one (poll, select) it fingerprints only a hello that has arrived whole, because waiting there
would make the worker spin (decision 037). nginx's configure builds the poll and select modules only when no
better method exists or when asked, so the Linux packages have epoll alone and cannot run that path.

## Decision
The ASan build (`./build.sh asan`, used only by the tests) is configured with `--with-poll_module` and
`--with-select_module`. `tests/integration/test_hello_wait.py` runs its level-triggered cases against it. The
package keeps the default event modules.
