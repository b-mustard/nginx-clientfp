#!/usr/bin/env python3
"""Run real HTTP/2 client libraries/tools against a fingerprint endpoint and compare the
Akamai HTTP/2 fingerprint with the value recorded from the reference (kittens.sh).

    .venv/bin/python tools/h2_clients.py [--url https://kittens.sh/api/http2] [--client NAME|all] [--insecure]

The endpoint may answer with JSON containing "akamai_fingerprint" (kittens.sh), "akamai_text"
(tls.browserleaks.com/http2) or "h2" (thumbprint.me/api/v1/probe), or with the bare fingerprint string.
Fingerprints are version dependent: every case records the versions it was captured with, and a
mismatch on a different version is reported as CHANGED rather than FAIL.

Requires: curl, node, wget, and .venv built from tools/requirements.txt (pinned versions).
"""
import argparse
import asyncio
import json
import os
import re
import socket
import ssl
import subprocess
from urllib.parse import urlsplit

# JSON key holding the fingerprint: kittens.sh, tls.browserleaks.com, thumbprint.me
FP_KEYS = ("akamai_fingerprint", "akamai_text", "h2")
FP_RE = re.compile(r"^[0-9:;]*\|(?:\d+|00)\|(?:[0-9:,]+)\|[mpas,]*$")


def extract_fp(body):
    try:
        j = json.loads(body)
        body = next(j[k] for k in FP_KEYS if k in j)
    except (ValueError, KeyError, TypeError, StopIteration):
        pass
    body = (body or "").strip()
    return body if FP_RE.match(body) else None


def sh(*cmd, env=None):
    """Run a client; a failed request (non-zero exit) raises, so negative cases cannot pass by accident."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=True, env=env).stdout


# ---------------------------------------------------------------- clients: fetch body, report version

def c_curl(url, insecure):
    flags = ["--http2-prior-knowledge"] if url.startswith("http:") else ["--http2"]
    return sh("curl", "-s", *flags, *(["-k"] if insecure else []), url)


def v_curl():
    first = sh("curl", "-V").split("\n")[0].split()
    return f"curl {first[1]} " + " ".join(p for p in first if p.startswith(("nghttp2/", "OpenSSL/")))


def c_httpx(url, insecure):
    import httpx
    with httpx.Client(http1=not url.startswith("http:"), http2=True, verify=not insecure) as c:
        return c.get(url).text


def c_httpx_async(url, insecure):
    import httpx

    async def go():
        async with httpx.AsyncClient(http1=not url.startswith("http:"), http2=True, verify=not insecure) as c:
            return (await c.get(url)).text
    return asyncio.run(go())


def v_httpx():
    import h2
    import httpcore
    import httpx
    return f"httpx {httpx.__version__} httpcore {httpcore.__version__} h2 {h2.__version__}"


def c_niquests(url, insecure):
    import niquests
    with niquests.Session(disable_http3=True, disable_http1=url.startswith("http:")) as s:
        r = s.get(url, verify=not insecure)
        assert r.http_version == 20, f"negotiated HTTP/{r.http_version}"
        return r.text


def v_niquests():
    import jh2
    import niquests
    import urllib3
    return f"niquests {niquests.__version__} urllib3-future {urllib3.__version__} jh2 {jh2.__version__}"


def c_h2_bare(url, insecure):
    """python-h2 with its default H2Configuration; pseudo-header order is chosen by the caller (m,p,a,s)."""
    import h2.config
    import h2.connection
    import h2.events
    u = urlsplit(url)
    tls = u.scheme == "https"
    port = u.port or (443 if tls else 80)
    sock = socket.create_connection((u.hostname, port), timeout=15)
    if tls:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        sock = ctx.wrap_socket(sock, server_hostname=u.hostname)
    with sock:
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        conn.initiate_connection()
        conn.send_headers(1, [(":method", "GET"), (":path", u.path or "/"), (":authority", u.netloc),
                              (":scheme", u.scheme)], end_stream=True)
        sock.sendall(conn.data_to_send())
        body = b""
        while True:
            data = sock.recv(65536)
            if not data:
                return body.decode()
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.DataReceived):
                    body += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset)):
                    return body.decode()
            sock.sendall(conn.data_to_send())


def v_h2_bare():
    import h2
    return f"h2 {h2.__version__}"


NODE_HTTP2 = r"""
const http2 = require('http2');
const [url, insecure, headers, settings] = process.argv.slice(1);
const u = new URL(url);
const c = http2.connect(u.origin, {rejectUnauthorized: insecure !== '1', settings: JSON.parse(settings)});
c.on('error', e => { console.error(e.message); process.exit(1); });
const h = JSON.parse(headers.replace('$PATH', JSON.stringify(u.pathname + u.search).slice(1, -1)));
const r = c.request(h);
let b = ''; r.on('data', d => b += d); r.on('end', () => { process.stdout.write(b); c.close(); });
"""


def node_http2(headers, settings="{}"):
    def run(url, insecure):
        return sh("node", "-e", NODE_HTTP2, url, "1" if insecure else "0", headers, settings)
    return run


def c_node_fetch(url, insecure):
    js = "fetch(process.argv[1]).then(r => r.text()).then(t => process.stdout.write(t))"
    return sh("node", "-e", js, url, env={**os.environ, **({"NODE_TLS_REJECT_UNAUTHORIZED": "0"} if insecure else {})})


def v_node():
    return "node " + sh("node", "-p", "process.versions.node + ' nghttp2 ' + process.versions.nghttp2").strip()


def c_wget(url, insecure):
    r = subprocess.run(["wget", "-q", "-O", "-", "--content-on-error", *(["--no-check-certificate"] if insecure else []),
                        url], capture_output=True, text=True, timeout=30)
    if r.returncode not in (0, 8):  # 8 = HTTP error status (reference answers HTTP/1.1 with 404); others = transport
        raise RuntimeError(f"wget exit {r.returncode}")
    return r.stdout


def v_wget():
    return " ".join(sh("wget", "--version").split()[:3])


# ---------------------------------------------------------------- cases
# (name, fetch, version, recorded_version, expected_fp or None = "must NOT yield an HTTP/2 fingerprint", note)
CASES = [
    ("curl", c_curl, v_curl, "curl 8.5.0 OpenSSL/3.0.13 nghttp2/1.59.0",
     "3:100;4:10485760;2:0|1048510465|0|m,s,a,p", "WU = 1000 MiB - 65535"),
    ("httpx", c_httpx, v_httpx, "httpx 0.28.1 httpcore 1.0.9 h2 4.4.1",
     "1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p", "httpcore drops setting 8, WU = 2^24"),
    ("httpx_async", c_httpx_async, v_httpx, "httpx 0.28.1 httpcore 1.0.9 h2 4.4.1",
     "1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p", "same as sync httpx"),
    ("niquests", c_niquests, v_niquests, "niquests 3.21.2 urllib3-future 2.25.900 jh2 5.0.15",
     "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", "copies Chrome's settings and WU"),
    ("h2_bare", c_h2_bare, v_h2_bare, "h2 4.4.1",
     "1:4096;2:1;4:65535;5:16384;8:0;3:100;6:65536|00|0|m,p,a,s", "library defaults; PS chosen by caller"),
    ("node_http2", node_http2('{":path":"$PATH"}'), v_node, "node 24.19.0 nghttp2 1.69.0",
     "|00|0|p,m,a,s", "empty SETTINGS, no WU; Node docs style request({':path'})"),
    ("node_http2_method_first", node_http2('{":method":"GET",":path":"$PATH"}'), v_node,
     "node 24.19.0 nghttp2 1.69.0", "|00|0|m,p,a,s", "PS follows the caller's header object key order"),
    ("node_http2_settings", node_http2('{":path":"$PATH"}', '{"enablePush":false,"initialWindowSize":6291456}'),
     v_node, "node 24.19.0 nghttp2 1.69.0", "2:0;4:6291456|00|0|p,m,a,s", "only non-default settings are sent"),
    ("node_fetch_h1", c_node_fetch, v_node, "node 24.19.0 nghttp2 1.69.0", None,
     "undici uses HTTP/1.1 by default -> no fingerprint"),
    ("wget_h1", c_wget, v_wget, "GNU Wget 1.21.4", None, "HTTP/1.1 only -> no fingerprint"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="https://kittens.sh/api/http2")
    ap.add_argument("--client", default="all")
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate verification (local nginx)")
    a = ap.parse_args()
    failed = 0
    for name, fetch, version, recorded, expected, note in CASES:
        if a.client not in ("all", name):
            continue
        try:
            ver = version()
        except Exception as e:  # noqa: BLE001
            print(f"SKIP    {name:24s} not available ({type(e).__name__}: {e})")
            continue
        try:
            got = extract_fp(fetch(a.url, a.insecure))
        except Exception as e:  # noqa: BLE001
            got = f"<error {type(e).__name__}: {e}>"
        if got == expected:
            status = "PASS"
        elif ver != recorded:
            status = "CHANGED"  # different client version: re-record, don't treat as a server bug
        else:
            status, failed = "FAIL", failed + 1
        shown = got if got is not None else "<no HTTP/2 fingerprint>"
        print(f"{status:7s} {name:24s} {shown}")
        if status != "PASS":
            print(f"        {'expected':24s} {expected if expected is not None else '<no HTTP/2 fingerprint>'}")
            print(f"        {'version now/recorded':24s} {ver} / {recorded}")
        elif a.client != "all":
            print(f"        {ver} -- {note}")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
