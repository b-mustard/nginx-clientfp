#!/usr/bin/env bash
# Single entry point (gs1): creates/updates .venv, then runs the Python tooling.
#
#   ./build.sh                                   build .deb for this distro, all flavors (native)
#   ./build.sh build --target all                build for every docker target (ubuntu 24.04/26.04, debian 12/13)
#   ./build.sh build --target debian-12 --flavor 1.30 --revision 2
#   ./build.sh fetch                             update sources, print the versions a build would use
#   ./build.sh test [pytest args]                run the test suite (tests/)
#   ./build.sh check                             mypy + fast unit tests
#   ./build.sh clean [--all]
#
# Everything else is passed to `python -m packager`; see ./build.sh --help.
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

PYTHON=${PYTHON:-python3}
VENV=.venv
STAMP=$VENV/.clientfp-installed

bootstrap() {
    if [ ! -x "$VENV/bin/python" ]; then
        echo "[build.sh] creating $VENV" >&2
        "$PYTHON" -m venv "$VENV"
    fi
    local want
    want=$(sha256sum pyproject.toml | cut -d' ' -f1)
    if [ ! -f "$STAMP" ] || [ "$(cat "$STAMP")" != "$want" ]; then
        echo "[build.sh] installing tooling into $VENV" >&2
        if "$VENV/bin/python" -m pip install -q --upgrade pip && "$VENV/bin/python" -m pip install -q -e '.[dev]'; then
            echo "$want" > "$STAMP"
        else
            # The packager needs only the standard library: building still works offline.
            echo "[build.sh] WARNING: could not install test dependencies (offline?); continuing" >&2
        fi
    fi
}

bootstrap
export PYTHONPATH="$PWD:$PWD/tools${PYTHONPATH:+:$PYTHONPATH}"

case "${1:-}" in
    test)
        shift
        exec "$VENV/bin/python" -m pytest "$@"
        ;;
    check)
        shift
        "$VENV/bin/python" -m mypy
        exec "$VENV/bin/python" -m pytest -m "not nginx and not docker and not network and not slow" "$@"
        ;;
    *)
        exec "$VENV/bin/python" -m packager "$@"
        ;;
esac
