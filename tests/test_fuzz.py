# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""libFuzzer runs of the module's C cores (t3): tests/fuzz/fuzz_{ja4,h2,tlsfp,hello}.c with ASan + UBSan, seeded with
every recorded ClientHello (as a message, as TLS records, as QUIC CRYPTO fragments) and a few HTTP/2 event streams.
`--fuzz-seconds` per target (default 60).

Any crash, sanitizer report, leak or timeout fails the test; the reproducer is kept in build/fuzz/<target>/.

The corpus the run leaves is then replayed under valgrind's memcheck (tests/fuzz/replay_main.c), built without
sanitizers at -O2 as the package is: memcheck also reports reads of uninitialised memory, which ASan does not."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from .conftest import REPO, VALGRIND
from .test_c_core import IMAGE, ctest_image  # noqa: F401  (fixture: builds the ctest image)

pytestmark = [pytest.mark.docker, pytest.mark.slow]

OUT = REPO / "build" / "fuzz"


def _seed_ja4(corpus: Path) -> None:
    for i, v in enumerate(json.loads((REPO / "doc" / "ja4_vectors.json").read_text())):
        proto = b"\x01" if v["ja4"][0] == "q" else b"\x00"
        (corpus / f"vector{i:03d}").write_bytes(proto + bytes.fromhex(v["client_hello_hex"]))


def _seed_hello(corpus: Path) -> None:
    from clientfp.fp.hello import records

    for i, v in enumerate(json.loads((REPO / "doc" / "ja4_vectors.json").read_text())):
        msg = bytes.fromhex(v["client_hello_hex"])
        (corpus / f"tcp{i:03d}").write_bytes(b"\x00" + records(msg, [100 + 37 * i]))
        frags = b"".join(o.to_bytes(2, "big") + len(msg[o:o + 500]).to_bytes(2, "big") + msg[o:o + 500]
                         for o in reversed(range(0, len(msg), 500)))
        (corpus / f"quic{i:03d}").write_bytes(b"\x01" + frags)


# target -> core sources it links
SOURCES: dict[str, tuple[str, ...]] = {
    "ja4": ("clientfp_ja4.c", "clientfp_sha256.c"),
    "h2": ("clientfp_h2.c",),
    "tlsfp": ("clientfp_tlsfp.c", "clientfp_sha256.c"),
    "hello": ("clientfp_hello.c", "clientfp_ja4.c", "clientfp_tlsfp.c", "clientfp_sha256.c"),
}


def _seed_h2(corpus: Path) -> None:
    # The event encoding is defined by the target; a few random seeds suffice, libFuzzer finds the structure.
    for i in range(16):
        (corpus / f"seed{i:02d}").write_bytes(bytes((i * 37 + k * 11) & 0xFF for k in range(64 + 32 * i)))


@pytest.mark.parametrize("target", list(SOURCES))
def test_fuzz(ctest_image: str, target: str, request: pytest.FixtureRequest) -> None:  # noqa: F811
    seconds = int(request.config.getoption("--fuzz-seconds"))
    work = OUT / target
    corpus = work / "corpus"
    if work.exists():
        shutil.rmtree(work)
    corpus.mkdir(parents=True)
    {"h2": _seed_h2, "hello": _seed_hello}.get(target, _seed_ja4)(corpus)
    rel = work.relative_to(REPO)
    script = (
        f"set -e; clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all "
        f"-Inginx_module/src -o {rel}/fuzz_{target} tests/fuzz/fuzz_{target}.c "
        f"{' '.join('nginx_module/src/' + s for s in SOURCES[target])}; "
        f"cd {rel}; ./fuzz_{target} -max_total_time={seconds} -max_len=40000 -timeout=10 "
        f"-print_final_stats=1 corpus"
    )
    proc = subprocess.run(["docker", "run", "--rm", "-v", f"{REPO}:/work", "-w", "/work", IMAGE, "bash", "-c", script],
                          capture_output=True, text=True, check=False)
    log = proc.stdout + proc.stderr
    (work / "fuzz.log").write_text(log)
    assert proc.returncode == 0, log[-6000:]
    assert "stat::number_of_executed_units" in log

    srcs = " ".join("nginx_module/src/" + s for s in SOURCES[target])
    script = (
        f"set -e; gcc -O2 -g -Wall -Wextra -Werror -Inginx_module/src -o {rel}/replay_{target} "
        f"tests/fuzz/replay_main.c tests/fuzz/fuzz_{target}.c {srcs}; "
        f"{' '.join(VALGRIND)} {rel}/replay_{target} {rel}/corpus"
    )
    proc = subprocess.run(["docker", "run", "--rm", "-v", f"{REPO}:/work", "-w", "/work", IMAGE, "bash", "-c", script],
                          capture_output=True, text=True, check=False)
    log = proc.stdout + proc.stderr
    (work / "replay.log").write_text(log)
    assert proc.returncode == 0, log[-6000:]
    assert "replayed" in log
