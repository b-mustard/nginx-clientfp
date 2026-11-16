"""clientfp_request_header (gs7, decisions 004/013/016): signatures reach the upstream as headers, and client-sent
copies are always removed. Upstream = examples/echo_server.py, which echoes the headers it received."""

from __future__ import annotations

import json
import ssl

import httpx
import pytest

from .conftest import Nginx, fp_json, get

pytestmark = [pytest.mark.nginx, pytest.mark.docker]


def _echo(port: int, headers: dict[str, str] | None = None) -> dict[str, object]:
    data: dict[str, object] = json.loads(get(port, "/echo", headers))
    return data


def _headers(echo: dict[str, object], name: str) -> list[str]:
    pairs = echo["headers"]
    assert isinstance(pairs, list)
    return [v for k, v in pairs if k.lower() == name.lower()]


def test_injected_over_http1(nginx_pkg: Nginx) -> None:
    echo = _echo(nginx_pkg.tls)
    ja4 = fp_json(nginx_pkg.tls)["ja4"]
    assert _headers(echo, "X-Client-JA4") == [ja4]
    assert _headers(echo, "X-Client-HTTP2-FP") == []        # HTTP/1.1: empty value, header not added


def test_spoofed_headers_removed(nginx_pkg: Nginx) -> None:
    echo = _echo(nginx_pkg.tls, {"X-Client-JA4": "spoofed", "x-client-ja4": "spoofed2",
                                 "X-CLIENT-HTTP2-FP": "1:1|00|0|m", "X-Other": "kept"})
    assert _headers(echo, "X-Client-JA4") == [fp_json(nginx_pkg.tls)["ja4"]]
    assert _headers(echo, "X-Client-HTTP2-FP") == []
    assert _headers(echo, "X-Other") == ["kept"]


def test_injected_over_http2(nginx_pkg: Nginx) -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with httpx.Client(http1=False, http2=True, verify=ctx) as c:
        base = f"https://localhost:{nginx_pkg.tls}"
        fp = c.get(f"{base}/fp").json()
        r = c.get(f"{base}/echo", headers={"X-Client-HTTP2-FP": "spoofed", "X-Client-JA4": "spoofed"})
        assert r.http_version == "HTTP/2"
        echo = r.json()
    assert fp["akamai_fingerprint"]
    assert _headers(echo, "X-Client-JA4") == [fp["ja4"]]
    assert _headers(echo, "X-Client-HTTP2-FP") == [fp["akamai_fingerprint"]]


def test_server_level_list_replaces_http_level(nginx_pkg: Nginx) -> None:
    """Port 8444 has its own list: X-FP-Ja4-O and X-FP-H2-Hash only. Headers named only in http{} are not
    managed there, so a client-sent X-Client-JA4 passes through unchanged (documented)."""
    data = json.loads(get(nginx_pkg.tls_alt, "/", {"X-FP-Ja4-O": "spoofed", "X-Client-JA4": "client"}))
    assert _headers(data, "X-FP-Ja4-O") != ["spoofed"]
    assert len(_headers(data, "X-FP-Ja4-O")) == 1 and _headers(data, "X-FP-Ja4-O")[0].startswith("t1")
    assert _headers(data, "X-FP-H2-Hash") == []
    assert _headers(data, "X-Client-JA4") == ["client"]


def test_bad_directive_rejected(nginx_pkg: Nginx) -> None:
    """Header names nginx parses itself cannot be configured (configuration test fails)."""
    out = nginx_pkg.exec("sh", "-c", "printf 'events{} http{ clientfp_request_header Host $clientfp_ja4; }' "
                         "> /tmp/bad.conf; nginx -t -c /tmp/bad.conf", check=False)
    assert "processed by nginx itself" in out
    out = nginx_pkg.exec("sh", "-c", "printf 'events{} http{ clientfp_request_header \"X Bad\" 1; }' "
                         "> /tmp/bad2.conf; nginx -t -c /tmp/bad2.conf", check=False)
    assert "invalid header name" in out
