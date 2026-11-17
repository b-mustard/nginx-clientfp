"""Correctness of the fingerprints nginx computes (t1), with real clients and crafted traffic:

- JA4 and TLSFP: every case of clientfp-ja4-probe (curl, wget, urllib, httpx, niquests, s_client, curl_cffi
  browser profiles, tlslite-ng mutated hellos, HTTP/3 over QUIC). The probe captures each ClientHello on the wire,
  computes JA4 and TLSFP with the reference implementations and compares all four JA4 forms and the TLSFP nginx
  returns.
- HTTP/2: the 21 synthetic frame sequences of clientfp-h2-probe and the real clients of clientfp-h2-clients,
  over TLS+ALPN and over cleartext h2c.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from .conftest import Nginx, fp_json

pytestmark = [pytest.mark.nginx, pytest.mark.docker, pytest.mark.slow]

BIN = Path(sys.executable).parent


def _run(*cmd: str, timeout: int = 900) -> str:
    proc = subprocess.run([str(BIN / cmd[0]), *cmd[1:]], capture_output=True, text=True, timeout=timeout,
                          check=False, env={**os.environ, "PYTHONUNBUFFERED": "1"})
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out[-6000:]
    return out


def test_ja4_probe_all_clients(nginx_pkg: Nginx) -> None:
    out = _run("clientfp-ja4-probe", "--host", "localhost", "--connect", "127.0.0.1", "--port", str(nginx_pkg.tls),
               "--path", "/fp", "-k")
    m = re.search(r"== (\d+) passed, (\d+) failed, (\d+) skipped", out)
    assert m, out[-3000:]
    passed, failed, skipped = map(int, m.groups())
    assert failed == 0
    assert passed >= 39, out[-3000:]
    # nginx (security level 0 in the test site) completes every crafted hello the probe sends
    assert skipped <= 2, out[-3000:]
    assert re.search(r"^PASS \S*h3\S*\s+local=q13", out, re.M), "no HTTP/3 (QUIC) case passed"
    assert len(re.findall(r"^PASS .*\[ja4,ja4_r,ja4_o,ja4_ro,tlsfp\]", out, re.M)) == passed, "TLSFP not compared"


def _passes(out: str) -> int:
    assert not re.search(r"^FAIL", out, re.M), out[-6000:]
    return len(re.findall(r"^PASS", out, re.M))


def test_h2_probe_synthetic(nginx_pkg: Nginx) -> None:
    from clientfp.probe.h2_probe import cases

    out = _run("clientfp-h2-probe", "--host", "127.0.0.1", "--port", str(nginx_pkg.tls), "--path", "/fp",
               "--insecure")
    assert _passes(out) == len(cases("h", "/")), out


def test_h2_clients_tls(nginx_pkg: Nginx) -> None:
    out = _run("clientfp-h2-clients", "--url", f"https://127.0.0.1:{nginx_pkg.tls}/fp", "--insecure")
    assert _passes(out) >= 8, out


def test_h2_clients_h2c(nginx_pkg: Nginx) -> None:
    out = _run("clientfp-h2-clients", "--url", f"http://127.0.0.1:{nginx_pkg.h2c}/fp")
    assert _passes(out) >= 6, out


def test_http1_has_no_h2_fingerprint(nginx_pkg: Nginx) -> None:
    fp = fp_json(nginx_pkg.tls)
    assert fp["protocol"] == "HTTP/1.1"
    assert fp["akamai_fingerprint"] == "" and fp["akamai_fingerprint_hash"] == ""
    assert re.fullmatch(r"t1[23]d\d{4}h1_[0-9a-f]{12}_[0-9a-f]{12}", fp["ja4"])
    assert re.fullmatch(r"t1[23]d\d{4}h1_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}", fp["tlsfp"])
    assert fp["tlsfp_registry"] == "1"


def test_cleartext_has_no_ja4(nginx_pkg: Nginx) -> None:
    import urllib.request

    body = urllib.request.urlopen(f"http://127.0.0.1:{nginx_pkg.h2c}/fp", timeout=10).read().decode()
    assert '"ja4":""' in body and '"ja4_ro":""' in body and '"tlsfp":""' in body and '"tlsfp_registry":""' in body
