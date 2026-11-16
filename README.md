# nginx-clientfp

Debian/Ubuntu packages of nginx, statically linked with OpenSSL, with client fingerprinting built in:

- **JA4**: TLS ClientHello fingerprint (TLS over TCP and QUIC/HTTP/3), spec in [doc/ja4_sig.md](doc/ja4_sig.md).
- **HTTP/2 signature**: Akamai passive HTTP/2 fingerprint, spec in [doc/http2_sig.md](doc/http2_sig.md).

The fingerprints are available as `$clientfp_*` variables and are passed to upstreams as request headers that
clients cannot spoof. Module reference: [doc/clientfp_module.md](doc/clientfp_module.md).

| Flavor | nginx | OpenSSL (static) | Package |
|---|---|---|---|
| `1.31` | newest 1.31.x | newest 4.0.x | `nginx-clientfp_1.31.x+openssl4.0.x-<rev>_amd64.deb` |
| `1.30` | newest 1.30.x | newest 3.5.x | `nginx-clientfp_1.30.x+openssl3.5.x-<rev>_amd64.deb` |

Targets: this distro (native build), and in docker `ubuntu-24.04`, `ubuntu-26.04`, `debian-12`, `debian-13`.
Output goes to `dist/<distro>-<version>/`.

## Build

```sh
./build.sh                                   # this distro, both flavors (needs the build deps below)
./build.sh build --target all                # every docker target
./build.sh build --target debian-12 --flavor 1.30 --revision 2
./build.sh fetch                             # update sources, show the versions a build would use
```

`build.sh` creates `.venv`, then runs `python -m packager`. Every build checks upstream for the newest release
of each series, clones or updates `extern_src/`, exports the tags into `build/`, applies `patches/`, builds with
`dpkg-buildpackage`, and verifies the result: OpenSSL must be linked statically and none of its symbols may be
exported from `/usr/sbin/nginx`.

Native build dependencies: `build-essential debhelper dpkg-dev fakeroot lintian libpcre2-dev zlib1g-dev git`.
Docker builds need only docker (rootless works).

## Install

```sh
sudo apt install ./dist/ubuntu-24.04/nginx-clientfp_1.31.8+openssl4.0.3-1_amd64.deb
```

The package replaces the distro's `nginx`/`nginx-common` and keeps their layout (`sites-available/`,
`sites-enabled/`, `snippets/`, `modules-enabled/`, user `www-data`, systemd unit, logrotate, man page).
The packaged `nginx.conf` adds `X-Client-JA4` and `X-Client-HTTP2-FP` to every upstream request.

## Test

```sh
./build.sh check                             # mypy + unit tests (no build needed)
./build.sh test                              # everything, incl. docker-based C, fuzz and nginx tests
./build.sh test -m nginx --target ubuntu-24.04 --flavor 1.31
```

See [tests/README.md](tests/README.md).

## Layout

```
doc/            specs, module reference, decision log (doc/ai_dec/)
packager/       Python build orchestration + debian/ templates + Dockerfile
patches/        patches/nginx/<line>/*.patch (HTTP/2 hooks); OpenSSL is not patched
nginx_module/   ngx_http_clientfp_module (nginx glue + pure-C JA4/HTTP2 cores)
tools/          clientfp Python package: reference implementations and live probes
tests/          pytest suites, C drivers, fuzz targets, test Dockerfiles
examples/       echo upstream + nginx site showing the injected headers
[extern_src/]   upstream git clones        [build/] working trees        [dist/] .deb output
```
