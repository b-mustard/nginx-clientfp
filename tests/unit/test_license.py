# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""License notices (decision 043): LICENSE holds the BSD-2-Clause text, every code file starts with the SPDX and
copyright lines, and the documents from other sources keep their own license."""

from __future__ import annotations

import subprocess
import tomllib
from fnmatch import fnmatch
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SPDX = "SPDX-License-Identifier: BSD-2-Clause"
COPYRIGHT = "Copyright (c) 2026 nginx-clientfp contributors"

# Code files carry the two lines. packager/debian/ holds files from Debian's nginx packaging; debian/copyright
# covers it. Documentation and data files are covered by LICENSE.
CODE = ("*.c", "*.h", "*.py", "*.sh", "*.conf", "*.patch", "*.supp", "*Dockerfile*", "nginx_module/config",
        "packager/lintian-suppress")
EXEMPT = ("packager/debian/*",)


def code_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True).stdout
    return [f for f in out.splitlines()
            if any(fnmatch(f, p) for p in CODE) and not any(fnmatch(f, p) for p in EXEMPT)]


def header(path: Path) -> list[str]:
    """The lines where the notice must be, without comment markers: the first four lines (a shebang and a "/*" can
    come first), or in a patch the text before the first diff, which git apply ignores."""
    lines = path.read_text(errors="replace").splitlines()
    if path.suffix == ".patch":
        lines = lines[:next((i for i, line in enumerate(lines) if line.startswith("diff --git ")), len(lines))]
    else:
        lines = lines[:4]
    return [line.lstrip("/*# ").rstrip() for line in lines]


def test_code_files_are_found() -> None:
    files = code_files()
    for f in ("build.sh", "nginx_module/config", "nginx_module/src/clientfp_ja4.c", "examples/echo_server.py",
              "patches/nginx/1.31/0001-http2-clientfp-hooks.patch", "tests/docker/Dockerfile.runtime"):
        assert f in files
    assert not [f for f in files if f.startswith("packager/debian/")]


@pytest.mark.parametrize("name", code_files())
def test_code_file_has_notice(name: str) -> None:
    lines = header(REPO / name)
    assert SPDX in lines, f"{name}: no '{SPDX}' line at the top"
    assert lines[lines.index(SPDX) + 1:][:1] == [COPYRIGHT], f"{name}: '{COPYRIGHT}' must follow the SPDX line"


def test_license_file_is_bsd_2_clause() -> None:
    text = (REPO / "LICENSE").read_text()
    assert text.startswith("BSD 2-Clause License\n")
    assert COPYRIGHT in text.splitlines()
    assert "1. Redistributions of source code must retain" in text
    assert "2. Redistributions in binary form must reproduce" in text
    assert "Neither the name" not in text      # the third clause of BSD-3-Clause


def test_pyproject_names_the_license() -> None:
    project = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]
    assert project["license"] == "BSD-2-Clause"


def test_documents_from_other_sources_keep_their_license() -> None:
    ja4 = (REPO / "doc" / "ja4_sig.md").read_text()
    assert "BSD-3-Clause" in ja4 and "Copyright (c) 2026 FoxIO" in ja4
    assert "CC BY 4.0" in (REPO / "doc" / "nDPI_TLS_Fingerprint.md").read_text()
    readme = (REPO / "README.md").read_text()
    license_section = readme[readme.index("## License"):]
    for name in ("LICENSE", "doc/ja4_sig.md", "doc/nDPI_TLS_Fingerprint.md"):
        assert name in license_section
