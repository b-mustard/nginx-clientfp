# nginx-clientfp

## Purpose

Anyone operating a public-facing website is getting hammered by AI bots right now. One effective countermeasure is to
inspect incoming connections at the TLS and HTTP/2 levels, identifying and blocking simplistic automated tools before
they can access your site.

This project provides a drop-in Nginx patch designed to make this kind of traffic filtering straightforward, while
remaining easy to maintain and update with future security patches.

## What it is

Debian/Ubuntu packages of nginx, built against the distribution's own TLS library (libssl), with client
fingerprinting built in:

- **JA4**: TLS ClientHello fingerprint (TLS over TCP and QUIC/HTTP/3), spec in [doc/ja4_sig.md](doc/ja4_sig.md).
- **TLSFP**: nDPI TLS client fingerprint (JA4 without ephemeral extensions, plus a supported-groups hash),
  draft [doc/nDPI_TLS_Fingerprint.md](doc/nDPI_TLS_Fingerprint.md), implementation notes in
  [doc/tlsfp_sig.md](doc/tlsfp_sig.md).
- **HTTP/2 signature**: Akamai passive HTTP/2 fingerprint, spec in [doc/http2_sig.md](doc/http2_sig.md).

The fingerprints are available as `$clientfp_*` variables and are passed to upstreams as request headers that
clients cannot spoof. Module reference: [doc/clientfp_module.md](doc/clientfp_module.md).

| Flavor | nginx | Package |
|---|---|---|
| `1.31` | newest 1.31.x | `nginx-clientfp_1.31.x-<rev>_amd64.deb` |
| `1.30` | newest 1.30.x | `nginx-clientfp_1.30.x-<rev>_amd64.deb` |

Targets: this distro (native build), and in docker `ubuntu-24.04`, `ubuntu-26.04`, `debian-12`, `debian-13`.
Output goes to `dist/<distro>-<version>/`.

The module reads the ClientHello itself, before the TLS library does (TCP: from the socket; QUIC: from the Initial
CRYPTO frames), so fingerprints do not depend on the TLS library or its version. HTTP/3 works on every target; where
the distribution's libssl has no QUIC API (Ubuntu 24.04, Debian 12), nginx uses its QUIC compatibility layer, which
has no 0-RTT.

## Build

For a first build, follow the end-to-end guide [examples/echo_server.md](examples/echo_server.md). It goes from
`git clone` to a running nginx: it installs the build dependencies, builds and installs the package, and starts an
echo server that shows the fingerprints of your requests.

```sh
./build.sh                                   # this distro, both flavors (needs the build deps below)
./build.sh build --target all                # every docker target
./build.sh build --target debian-12 --flavor 1.30 --revision 2
./build.sh fetch                             # update sources, show the versions a build would use
```

`build.sh` creates `.venv`, then runs `python -m packager`. Every build checks upstream for the newest release
of each series, clones or updates `extern_src/`, exports the tags into `build/`, applies `patches/`, builds with
`dpkg-buildpackage`, and verifies the result: `/usr/sbin/nginx` must link the distribution's libssl and contain the
module and every patched hook.

Native build dependencies:

```sh
sudo apt install git python3-venv build-essential debhelper dpkg-dev fakeroot lintian \
    libpcre2-dev libssl-dev zlib1g-dev
```

Docker builds need `git`, `python3-venv` and docker (rootless works): `build.sh` and the source download run on the
host, the package build runs in the container.

## Install

```sh
sudo apt install ./dist/<distro name>/nginx-clientfp_1.31.8-1_amd64.deb
```

`<distro name>` is the directory that the build put the package in: the docker target, for example `debian-12`, or,
for a native build, the system of the build machine, for example `ubuntu-24.04`.

The package replaces the distro's `nginx`/`nginx-common` and keeps their layout (`sites-available/`,
`sites-enabled/`, `snippets/`, `modules-enabled/`, user `www-data`, systemd unit, logrotate, man page).
The packaged `nginx.conf` adds `X-Client-JA4`, `X-Client-TLSFP` and `X-Client-HTTP2-FP` to every upstream request.

## Test

```sh
./build.sh check                             # mypy + unit tests (no build needed)
./build.sh test                              # everything, incl. docker-based C, fuzz and nginx tests
./build.sh test -m nginx --target ubuntu-24.04 --flavor 1.31
```

See [tests/README.md](tests/README.md).

## Layout

| Directory | Contents |
|---|---|
| `doc/` | Specs, module reference, decision log (`doc/ai_dec/`) |
| `packager/` | Python build orchestration, `debian/` templates, build Dockerfile |
| `patches/nginx/<line>/` | nginx patches: HTTP/2 hooks, ClientHello capture hooks |
| `nginx_module/` | `ngx_http_clientfp_module`: nginx glue and pure-C cores (capture, JA4, TLSFP, HTTP/2, SHA-256) |
| `tools/clientfp/` | Python package: reference implementations and live probes |
| `tests/` | pytest suites, C drivers, fuzz targets, test Dockerfiles, valgrind suppressions |
| `examples/` | Echo upstream and nginx site that show the added headers; `echo_server.md` is the end-to-end guide |

Made by the build, not in git:

| Directory | Contents |
|---|---|
| `extern_src/` | Upstream git clones |
| `build/` | Working trees, test builds of nginx (`asan/`, `valgrind/`), logs |
| `dist/<distro>/` | `.deb` output |

## License

BSD-2-Clause, the license of nginx itself: see [LICENSE](LICENSE). Two documents keep the license of their source:

- `doc/ja4_sig.md` is derived from FoxIO's `JA4.md` and is under BSD-3-Clause, Copyright (c) 2026 FoxIO.
- `doc/nDPI_TLS_Fingerprint.md` is ntop's draft, under CC BY 4.0.
