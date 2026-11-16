# 021 — build.sh bootstrap

- Date: 2026-11-16
- Type: automatic

`build.sh` is the only entry point (gs1). It:

1. creates `.venv` with the system `python3` (≥ 3.11) if it is missing;
2. runs `pip install -e '.[dev]'` when a SHA-256 of `pyproject.toml` differs from the stamp in `.venv`. If pip
   fails, for example offline, and a usable venv already exists, it warns and continues;
3. dispatches:
   - `test` → pytest;
   - `check` → mypy + the offline, docker-free tests;
   - anything else → `python -m packager`, with `build` as the default command.

The packager itself is stdlib-only, so a build never depends on PyPI packages.
