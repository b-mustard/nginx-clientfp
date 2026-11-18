# Working on nginx-clientfp

Rules for anyone, human or AI agent, who changes this repository. The rules come from the maintainer; the codes in
brackets (h1, g1, ...) are the names the decision log uses for them.

## Decisions

- **Ask before deciding** [h1]. Put every non-obvious engineering decision to the maintainer, with the top options
  and a recommendation. Decide alone only what has one sensible answer.
- **Record every decision** [h2] in `doc/ai_dec/decision_NNN.md` (next free number) and add a row to
  `doc/ai_dec/README.md`. `Type: human` when the maintainer chose, `automatic` otherwise. Decision files are
  history: do not rewrite an old one; add a note that points to the decision replacing it.
- **A human decision is a commit point** [h3]: commit the decision record on its own, before its implementation.

## Commits

- Author: `<your model or name> <noreply@example.com>`, for example `Claude Opus 5.5 <noreply@example.com>` [g1].
- No `Co-authored-by` trailers [g1]. No links to chat sessions, and no account details such as e-mail
  addresses, in commits, code or docs [g2].
- Brief messages [g3]: one line, `Area: what changed`, plus the decision number when there is one.
- One commit per logical change, without being asked [g4]: decision record, implementation, tests, docs.
- Current state (2026-11-18): the branch `no_openssl` is merged into `main`, and work goes to `main`. **Do not
  push** until the maintainer says that pushing is allowed again.

## Code

- Python is typed and passes `mypy --strict` (configured in `pyproject.toml`). Use `.venv`, which `./build.sh`
  creates; do not install into the system Python.
- Lines are at most 120 characters (code and Markdown).
- The module's pure-C cores (`nginx_module/src/clientfp_*.c`) do not depend on nginx or on a TLS library. nginx
  changes go in `patches/nginx/<line>/`, kept as small as possible.
- OpenSSL is not part of the project: packages link the distribution's libssl (decision 029). Code, docs and
  names do not mention OpenSSL; only the decision log does.

## Building

- `./build.sh build --target <distro> --flavor <1.31|1.30>` builds a `.deb` in docker; `./build.sh asan` and
  `./build.sh valgrind` build the test-only nginx variants. `./build.sh --help` lists everything.
- The development host is small (2 CPUs, 2 GB). Run builds one at a time, in the background, with output to
  `build/logs/`. Never run a build under a tool that kills it after a time limit: the build container is left
  behind.
- Containers: remove only `clientfp-test-*` containers and containers of `nginx-clientfp-build:*` images. The
  host runs unrelated containers; leave them alone.

## Testing

See `tests/README.md` for what each suite covers.

- Before every commit: `./build.sh check` (mypy and the fast tests).
- C changes: `./build.sh test tests/test_c_core.py` (ASan + UBSan and valgrind); for parser changes also
  `./build.sh test tests/test_fuzz.py`.
- nginx, module or patch changes: rebuild the package and the test builds, then run
  `./build.sh test -m nginx --target ubuntu-24.04 --flavor <line>` for both lines. The other targets run the
  package tests: `-k "not asan and not valgrind"`.
- A new test must fail on the code it guards against. Run it once against the old build, or a deliberately
  broken one, before trusting it; then revert the break and rebuild.
- Report results as they are: failures with their output, skipped steps as skipped.
