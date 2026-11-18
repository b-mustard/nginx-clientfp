#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 nginx-clientfp contributors

"""Echo the client fingerprints that nginx-clientfp passes to an upstream.

nginx terminates TLS / HTTP/2 / HTTP/3, computes the signatures and adds them as request headers
(clientfp_request_header); this server answers every request with a JSON object of those headers, plus every
other request header, so you can see what an application behind nginx receives.

    python3 examples/echo_server.py [--no-lookup]

The server listens on 127.0.0.1:8081, the upstream of examples/nginx-echo.conf; clients send their requests to
nginx, at https://localhost:8443/. A request sent here directly carries no fingerprints.

At start, the server asks https://cloudflare.com/cdn-cgi/trace for the public address of this machine, and shows
it in the address for other machines. --no-lookup skips that request.
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import sys
import urllib.request
from email.message import Message
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Both fixed by examples/nginx-echo.conf: the upstream (proxy_pass) and the port nginx listens on for clients.
LISTEN = ("127.0.0.1", 8081)
NGINX_PORT = 8443

# Where the public address comes from (decision 044). Its reply has one "key=value" per line, among them "ip=".
TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"
LOOKUP_TIMEOUT = 3.0
UNKNOWN_ADDRESS = "<this machine>"

FINGERPRINT_HEADERS = (
    "X-Client-JA4",
    "X-Client-JA4-R",
    "X-Client-JA4-O",
    "X-Client-JA4-RO",
    "X-Client-TLSFP",
    "X-Client-TLSFP-Registry",
    "X-Client-HTTP2-FP",
    "X-Client-HTTP2-FP-Hash",
    "X-Client-HTTP2-FP-Overflow",
)


def printable(text: str) -> str:
    """`text` with each character outside printable ASCII written as an escape such as \\x16, so that a request
    with binary data cannot put control characters or escape sequences on the terminal."""
    return "".join(c if " " <= c <= "~" else ascii(c)[1:-1] for c in text)


def address_from_trace(text: str) -> str | None:
    """The `ip=` value of a trace reply, written as the host part of a URL (an IPv6 address in brackets), or None if
    the reply has no valid IP address."""
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key == "ip":
            try:
                address = ipaddress.ip_address(value.strip())
            except ValueError:
                return None
            return f"[{address}]" if address.version == 6 else str(address)
    return None


def public_address() -> str:
    """The address that the internet sees for this machine, or UNKNOWN_ADDRESS if the lookup fails. The reason of a
    failure goes to stderr."""
    try:
        with urllib.request.urlopen(TRACE_URL, timeout=LOOKUP_TIMEOUT) as reply:
            text = reply.read(4096).decode("ascii", "replace")
    except (OSError, ValueError, http.client.HTTPException) as e:  # OSError: also URLError, timeouts, TLS errors
        reason = str(e) or type(e).__name__
    else:
        address = address_from_trace(text)
        if address is not None:
            return address
        reason = "the reply has no IP address"
    print(printable(f"cannot get the public address from {TRACE_URL}: {reason}"), file=sys.stderr, flush=True)
    return UNKNOWN_ADDRESS


def banner(address: str = UNKNOWN_ADDRESS) -> str:
    return (f"echo server ready. Send requests to nginx: https://localhost:{NGINX_PORT}/ "
            f"(other machines: https://{address}:{NGINX_PORT}/)")


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
        value = self.headers.get("Content-Length") or "0"
        length = int(value) if value.isdigit() else -1
        if length < 0:
            self.send_error(HTTPStatus.BAD_REQUEST, "Bad Content-Length")
            return
        if length:
            self.rfile.read(min(length, 1 << 20))
        self._answer()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 (base class signature)
        # http.server logs a request that it cannot parse before it sets self.headers. The type stubs declare the
        # attribute on every handler, so mypy does not see that it can be missing.
        headers: Message | None = getattr(self, "headers", None)

        def value(name: str) -> str:
            return str(headers.get(name, "-")) if headers is not None else "-"

        line = f"{self.address_string()} {format % args} ja4={value('X-Client-JA4')} tlsfp={value('X-Client-TLSFP')}"
        print(printable(line), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-lookup", action="store_true",
                        help=f"do not ask {TRACE_URL} for the public address of this machine")
    no_lookup: bool = parser.parse_args().no_lookup
    try:
        httpd = ThreadingHTTPServer(LISTEN, EchoHandler)
    except OSError as e:
        sys.exit(f"cannot listen on {LISTEN[0]}:{LISTEN[1]}: {e.strerror}")
    # The socket listens already: a request that arrives during the lookup waits in the queue (decision 044).
    print(banner(UNKNOWN_ADDRESS if no_lookup else public_address()), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
