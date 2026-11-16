#!/usr/bin/env python3
"""Echo the client fingerprints that nginx-clientfp passes to an upstream.

nginx terminates TLS / HTTP/2 / HTTP/3, computes the signatures and adds them as request headers
(clientfp_request_header); this server answers every request with a JSON object of those headers, plus every
other request header, so you can see what an application behind nginx receives.

    python3 examples/echo_server.py [--host 127.0.0.1] [--port 8081]

nginx side: see examples/nginx-echo.conf.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FINGERPRINT_HEADERS = (
    "X-Client-JA4",
    "X-Client-JA4-R",
    "X-Client-JA4-O",
    "X-Client-JA4-RO",
    "X-Client-HTTP2-FP",
    "X-Client-HTTP2-FP-Hash",
    "X-Client-HTTP2-FP-Overflow",
)


class EchoHandler(BaseHTTPRequestHandler):
    server_version = "clientfp-echo/1.0"

    def _answer(self) -> None:
        fingerprints = {name: self.headers.get(name) for name in FINGERPRINT_HEADERS}
        body = json.dumps(
            {
                "fingerprints": {k: v for k, v in fingerprints.items() if v is not None},
                "method": self.command,
                "path": self.path,
                "headers": [[k, v] for k, v in self.headers.items()],
            },
            indent=2,
        ).encode() + b"\n"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        self._answer()

    def do_HEAD(self) -> None:  # noqa: N802
        self._answer()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(min(length, 1 << 20))
        self._answer()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 (base class signature)
        ja4 = self.headers.get("X-Client-JA4", "-") if self.headers else "-"
        print(f"{self.address_string()} {format % args} ja4={ja4}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8081)
    a = ap.parse_args()
    httpd = ThreadingHTTPServer((a.host, a.port), EchoHandler)
    print(f"echo server on http://{a.host}:{a.port}/", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
