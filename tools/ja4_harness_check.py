#!/usr/bin/env python3
"""Drive the ja4_probe clients against tools/ja4_ossl_harness.c (an OpenSSL server) and check, per client:

  1. the ClientHello delivered by OpenSSL's msg_callback is byte-identical to the one on the wire,
  2. msg_callback fires before the client_hello callback,
  3. which wire extensions SSL_client_hello_get1_extensions_present() / _get_extension_order() drop,
  4. SSL_client_hello_get0_ciphers() returns the raw cipher list (GREASE included),
  5. JA4 computed from the msg_callback bytes == JA4 computed from the wire bytes.

    .venv/bin/python tools/ja4_harness_check.py --harness ./ja4_ossl_harness --lib $OSSL/lib64 [--case NAME]
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ja4  # noqa: E402
import ja4_probe as probe  # noqa: E402

CASES = ["curl_default_h2", "curl_tls12_max", "wget", "python_urllib", "python_httpx_h2", "python_niquests",
         "s_client_no_sni", "s_client_serverinfo_unknown", "chrome", "firefox", "safari", "tlslite_default",
         "tlslite_grease", "tlslite_unknown_exts", "tlslite_dup_unknown_ext", "tlslite_many_ciphers_scsv", "tlslite_hrr",
         "tlslite_fragmented_hello", "alpn_ab_cd",
         # refused by both reference servers; the harness (security level 0, default session cache) completes them
         "tlslite_tls12_no_sigalgs", "tlslite_tls12_no_extensions", "tlslite_resumed_no_sigalgs"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--harness", required=True)
    ap.add_argument("--lib", help="LD_LIBRARY_PATH for the harness (OpenSSL under test)")
    ap.add_argument("--port", type=int, default=18443)
    ap.add_argument("--case", default="all")
    a = ap.parse_args()

    tmp = Path(tempfile.mkdtemp())
    # RSA so that even an extension-less TLS 1.2 hello (no supported_groups -> no ECDHE) can use RSA key exchange
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-subj", "/CN=localhost", "-days", "2", "-keyout", tmp / "key.pem", "-out", tmp / "cert.pem"],
                   check=True, capture_output=True)
    env = dict(os.environ, **({"LD_LIBRARY_PATH": a.lib} if a.lib else {}))
    srv = subprocess.Popen([a.harness, str(a.port), tmp / "cert.pem", tmp / "key.pem"], env=env,
                           stderr=subprocess.PIPE, text=True)
    print(srv.stderr.readline().strip())
    time.sleep(0.2)
    o = argparse.Namespace(host="localhost", connect="127.0.0.1", port=a.port, path="/", insecure=True)
    failed = 0
    try:
        for name in CASES:
            if a.case not in ("all", name):
                continue
            runner = probe.CASES[name][0]
            r = probe.Relay(o.connect, o.port)
            try:
                j = json.loads(runner(o, r))
            except Exception as e:  # noqa: BLE001
                print(f"FAIL {name}: {type(e).__name__}: {e}")
                failed += 1
                continue
            wire_hellos = r.client_hellos()
            wire = wire_hellos[0]
            ch = ja4.parse_client_hello(wire)
            raw = bytes.fromhex(j["raw"])
            api = j["api"]
            wire_exts = [f"{t:04x}" for t, _ in ch.extensions]
            dropped = [t for t in wire_exts if t not in api["extensions_present"]]
            checks = {
                "msgcb_bytes_eq_wire": raw == wire,
                "msgcb_before_chcb": j["msgcb_before_chcb"],
                "ja4_eq": ja4.from_bytes(raw)["ja4"] == ja4.from_bytes(wire)["ja4"],
                "get0_ciphers_raw": api["ciphers"] == "".join(f"{c:04x}" for c in ch.ciphers),
                "ext_order_eq_present": api["extension_order"] == api["extensions_present"],
                "api_is_wire_subsequence": [t for t in wire_exts if t in api["extensions_present"]]
                                           == api["extensions_present"],
            }
            ok = all(checks.values())
            failed += not ok
            bad = [k for k, v in checks.items() if not v]
            g0 = {k: ("present" if v is not None else "null") for k, v in api["get0_ext"].items()
                  if k in wire_exts or v is not None}
            print(f"{'PASS' if ok else 'FAIL'} {name:28s} ja4={ja4.from_bytes(raw)['ja4']} "
                  f"hellos(wire/msgcb/chcb)={len(wire_hellos)}/{j['msgcb_count']}/{j['chcb_count']}"
                  + (f" failed={bad}" if bad else ""))
            print(f"     API drops {dropped}   get0_ext on wire-present types: {g0}")
    finally:
        srv.terminate()
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
