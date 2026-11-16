# 005 — Python code layout

- Date: 2026-11-16
- Type: human (directory name: automatic)

## Context
`tools/` holds untyped prototypes to be refactored. The draft `packaging/` directory cannot be a Python package:
it would shadow PyPI's `packaging` library, which pip, setuptools and mypy import.

## Options
1. `tools/clientfp/` typed package; `packaging/` data only.
2. `src/clientfp/` src-layout; `tools/` removed.

## Decision
Option 1, with the user's amendment: the build orchestration is non-trivial Python, so the draft `packaging/`
directory is renamed to **`packager/`** and becomes a Python package that holds both the build code and its data
(`packager/debian/`, `packager/docker/`).

- `tools/clientfp/`: reference fingerprint code (`fp/`) and live probes (`probe/`), typed, mypy-strict.
- `packager/`: fetch, patch, configure, compile, symbol check, .deb assembly, docker matrix.
- `tests/`: pytest suites.
- `pyproject.toml` at the root holds dependencies, mypy and pytest config.
