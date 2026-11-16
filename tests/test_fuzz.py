"""libFuzzer runs of the module's C cores (t3): tests/fuzz/fuzz_{ja4,h2}.c with ASan + UBSan, seeded with every
recorded ClientHello and the HTTP/2 probe cases. `--fuzz-seconds` per target (default 60).

Any crash, sanitizer report, leak or timeout fails the test; the reproducer is kept in build/fuzz/<target>/."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from .conftest import REPO
from .test_c_core import IMAGE, drivers  # noqa: F401  (fixture: builds the ctest image)

pytestmark = [pytest.mark.docker, pytest.mark.slow]

OUT = REPO / "build" / "fuzz"


def _seed_ja4(corpus: Path) -> None:
    for i, v in enumerate(json.loads((REPO / "doc" / "ja4_vectors.json").read_text())):
        proto = b"\x01" if v["ja4"][0] == "q" else b"\x00"
        (corpus / f"vector{i:03d}").write_bytes(proto + bytes.fromhex(v["client_hello_hex"]))


def _seed_h2(corpus: Path) -> None:
    # The event encoding is defined by the target; a few random seeds suffice, libFuzzer finds the structure.
    for i in range(16):
        (corpus / f"seed{i:02d}").write_bytes(bytes((i * 37 + k * 11) & 0xFF for k in range(64 + 32 * i)))


@pytest.mark.parametrize("target", ["ja4", "h2"])
def test_fuzz(drivers: Path, target: str, request: pytest.FixtureRequest) -> None:  # noqa: F811
    seconds = int(request.config.getoption("--fuzz-seconds"))
    work = OUT / target
    corpus = work / "corpus"
    if work.exists():
        shutil.rmtree(work)
    corpus.mkdir(parents=True)
    (_seed_ja4 if target == "ja4" else _seed_h2)(corpus)
    rel = work.relative_to(REPO)
    script = (
        f"set -e; clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all "
        f"-Inginx_module/src -o {rel}/fuzz_{target} tests/fuzz/fuzz_{target}.c nginx_module/src/clientfp_{target}.c "
        f"-lcrypto; cd {rel}; ./fuzz_{target} -max_total_time={seconds} -max_len=20000 -timeout=10 "
        f"-print_final_stats=1 corpus"
    )
    proc = subprocess.run(["docker", "run", "--rm", "-v", f"{REPO}:/work", "-w", "/work", IMAGE, "bash", "-c", script],
                          capture_output=True, text=True, check=False)
    log = proc.stdout + proc.stderr
    (work / "fuzz.log").write_text(log)
    assert proc.returncode == 0, log[-6000:]
    assert "stat::number_of_executed_units" in log
