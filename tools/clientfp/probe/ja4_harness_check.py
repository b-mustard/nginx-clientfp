"""Drive the ja4_probe clients against tools/harness/ja4_ossl_harness.c (an OpenSSL server) and check, per client
(doc/ja4_sig.md §5.3):

  1. the ClientHello delivered by OpenSSL's msg_callback is byte-identical to the one on the wire,
  2. msg_callback fires before the client_hello callback,
  3. which wire extensions SSL_client_hello_get1_extensions_present() / _get_extension_order() drop,
  4. SSL_client_hello_get0_ciphers() returns the raw cipher list (GREASE included),
  5. JA4 computed from the msg_callback bytes == JA4 computed from the wire bytes.

    .venv/bin/python -m clientfp.probe.ja4_harness_check --harness ./ja4_ossl_harness --lib $OSSL/lib64 [--case NAME]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from clientfp.fp import ja4
from clientfp.probe import ja4_probe as probe

CASES: Final = [
    "curl_default_h2", "curl_tls12_max", "wget", "python_urllib", "python_httpx_h2", "python_niquests",
    "s_client_no_sni", "s_client_serverinfo_unknown", "chrome", "firefox", "safari", "tlslite_default",
    "tlslite_grease", "tlslite_unknown_exts", "tlslite_dup_unknown_ext", "tlslite_many_ciphers_scsv", "tlslite_hrr",
    "tlslite_fragmented_hello", "alpn_ab_cd",
    # refused by both reference servers; the harness (security level 0, default session cache) completes them
    "tlslite_tls12_no_sigalgs", "tlslite_tls12_no_extensions", "tlslite_resumed_no_sigalgs",
]


def check_case(o: probe.Target, name: str) -> tuple[bool, str]:
    """Run one probe client through a relay to the harness; returns (ok, report lines)."""
    case = probe.CASES[name]
    r = probe.Relay(o.connect or o.host, o.port)
    try:
        j = json.loads(case.runner(o, r.port))
    except Exception as e:  # noqa: BLE001  (a client or harness failure is this case's result)
        return False, f"FAIL {name}: {type(e).__name__}: {e}"
    wire_hellos = r.client_hellos()
    if not wire_hellos:
        return False, f"FAIL {name}: no ClientHello captured on the wire"
    wire = wire_hellos[0]
    ch = ja4.parse_client_hello(wire)
    raw = bytes.fromhex(j["raw"])
    api = j["api"]
    wire_exts = [f"{e.type:04x}" for e in ch.extensions]
    dropped = [t for t in wire_exts if t not in api["extensions_present"]]
    raw_ja4 = ja4.from_bytes(raw).ja4
    checks = {
        "msgcb_bytes_eq_wire": raw == wire,
        "msgcb_before_chcb": bool(j["msgcb_before_chcb"]),
        "ja4_eq": raw_ja4 == ja4.from_bytes(wire).ja4,
        "get0_ciphers_raw": api["ciphers"] == "".join(f"{c:04x}" for c in ch.ciphers),
        "ext_order_eq_present": api["extension_order"] == api["extensions_present"],
        "api_is_wire_subsequence": [t for t in wire_exts if t in api["extensions_present"]]
                                   == api["extensions_present"],
    }
    ok = all(checks.values())
    bad = [k for k, v in checks.items() if not v]
    g0 = {k: ("present" if v is not None else "null") for k, v in api["get0_ext"].items()
          if k in wire_exts or v is not None}
    head = (f"{'PASS' if ok else 'FAIL'} {name:28s} ja4={raw_ja4} "
            f"hellos(wire/msgcb/chcb)={len(wire_hellos)}/{j['msgcb_count']}/{j['chcb_count']}"
            + (f" failed={bad}" if bad else ""))
    return ok, f"{head}\n     API drops {dropped}   get0_ext on wire-present types: {g0}"


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m clientfp.probe.ja4_harness_check",
                                 description="Check the OpenSSL JA4 harness against the ja4_probe clients")
    ap.add_argument("--harness", required=True, help="the built tools/harness/ja4_ossl_harness binary")
    ap.add_argument("--lib", help="LD_LIBRARY_PATH for the harness (OpenSSL under test)")
    ap.add_argument("--port", type=int, default=18443)
    ap.add_argument("--case", default="all")
    a = ap.parse_args(argv)

    tmp = Path(tempfile.mkdtemp())
    # RSA so that even an extension-less TLS 1.2 hello (no supported_groups -> no ECDHE) can use RSA key exchange
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-subj", "/CN=localhost", "-days", "2", "-keyout", tmp / "key.pem", "-out", tmp / "cert.pem"],
                   check=True, capture_output=True)
    env = dict(os.environ, **({"LD_LIBRARY_PATH": a.lib} if a.lib else {}))
    srv = subprocess.Popen([a.harness, str(a.port), tmp / "cert.pem", tmp / "key.pem"], env=env,
                           stderr=subprocess.PIPE, text=True)
    if srv.stderr is not None:
        print(srv.stderr.readline().strip())
    time.sleep(0.2)
    o = probe.Target(host="localhost", connect="127.0.0.1", port=a.port, path="/", insecure=True)
    failed = 0
    try:
        for name in CASES:
            if a.case not in ("all", name):
                continue
            ok, report = check_case(o, name)
            failed += not ok
            print(report)
    finally:
        srv.terminate()
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
