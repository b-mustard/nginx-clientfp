"""JA4 probe: drives several TLS clients (curl, wget, Python urllib/httpx/niquests, openssl s_client, curl_cffi
browser impersonation, and a tlslite-ng client whose ClientHello is mutated on the fly) at a JA4 endpoint, captures
each client's real ClientHello through a local one-shot relay, computes JA4 locally (clientfp.fp.ja4) and compares
it with what the server reports.

    clientfp-ja4-probe [--ref kittens,thumbprint] [--case NAME|all] [--dump FILE]
    clientfp-ja4-probe --host localhost --connect 127.0.0.1 --port 8443 --path /ja4 -k

Reference servers (kittens.sh and thumbprint.me): kittens.sh /api/all returns JSON with "ja4", "ja4_r" and the
raw ClientHello; thumbprint.me /api/v1/probe returns JSON with "ja4", "ja4_r", "ja4_o", "ja4_ro". Our nginx may
return a bare JA4 string. Every form the server returns is compared. Each case may also carry a regex on JA4_a that
pins the spec's edge-case rules independently of the server; cases flagged may_refuse are SKIPped (not failed) when
the server's TLS stack rejects the hello. --dump writes the captured ClientHellos with their JA4 values (offline
test vectors, the format of doc/ja4_vectors.json).

TCP clients connect to the relay directly or through HTTP CONNECT. QUIC clients go through a UDP relay, and their
ClientHello is recovered by decrypting the Initial packets (RFC 9001 §5.2).
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import socket
import subprocess
import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, Protocol, TypedDict

from clientfp.fp import ja4


@dataclass(frozen=True)
class Target:
    host: str
    """Host header and SNI."""
    connect: str | None
    """TCP/UDP address to connect to, if different from host."""
    port: int
    path: str
    insecure: bool


class HelloCapture(Protocol):
    """A one-shot relay on 127.0.0.1 that records what the client sends."""

    @property
    def port(self) -> int: ...

    def client_hellos(self) -> list[bytes]: ...


# ---- TCP relay ---------------------------------------------------------------------------------------------------


class Relay:
    """Accept one TCP connection on 127.0.0.1, pipe it to host:port, record client->server bytes."""

    def __init__(self, host: str, port: int) -> None:
        self.srv = socket.create_server(("127.0.0.1", 0))
        self._port: int = self.srv.getsockname()[1]
        self.c2s = bytearray()
        self.upstream = (host, port)
        threading.Thread(target=self._run, daemon=True).start()

    @property
    def port(self) -> int:
        return self._port

    def _pump(self, src: socket.socket, dst: socket.socket, record: bool) -> None:
        try:
            while chunk := src.recv(65536):
                if record and len(self.c2s) < 1 << 20:
                    self.c2s += chunk
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _run(self) -> None:
        self.srv.settimeout(30)
        try:
            cli, _ = self.srv.accept()
        except OSError:
            return
        first = cli.recv(65536)
        if first.startswith(b"CONNECT "):  # also usable as an HTTP CONNECT proxy (curl_cffi has no CONNECT_TO)
            while b"\r\n\r\n" not in first:
                first += cli.recv(65536)
            first = first.partition(b"\r\n\r\n")[2]
            cli.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        up = socket.create_connection(self.upstream, timeout=30)
        self.c2s += first
        up.sendall(first)
        t = threading.Thread(target=self._pump, args=(up, cli, False), daemon=True)
        t.start()
        self._pump(cli, up, True)
        t.join(5)

    def client_hellos(self) -> list[bytes]:
        """All plaintext ClientHello messages (2 after a HelloRetryRequest), in order."""
        data, p, hs = bytes(self.c2s), 0, b""
        while p + 5 <= len(data):
            ctype, ln = data[p], int.from_bytes(data[p + 3:p + 5], "big")
            if ctype == 22:
                hs += data[p + 5:p + 5 + ln]
            elif ctype != 20:  # stop at first encrypted / app-data record; skip compat CCS
                break
            p += 5 + ln
        out, q = [], 0
        while q + 4 <= len(hs) and hs[q] == 1:
            n = int.from_bytes(hs[q + 1:q + 4], "big")
            if q + 4 + n > len(hs):
                break
            out.append(hs[q:q + 4 + n])
            q += 4 + n
        return out


# ---- QUIC: UDP relay + Initial packet decryption (RFC 9001 5.2) to recover the ClientHello ----------------------

QUIC_VERSIONS: Final = {  # version -> (initial salt, HKDF label prefix, long-header type of Initial packets)
    0x00000001: (bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), b"quic ", 0),
    0x6B3343CF: (bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"), b"quicv2 ", 1),
}


def _hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), "sha256").digest()
        out, i = out + t, i + 1
    return out[:length]


def _varint(b: bytes, p: int) -> tuple[int, int]:
    n, v = 1 << (b[p] >> 6), b[p] & 0x3F
    for i in range(1, n):
        v = (v << 8) | b[p + i]
    return v, p + n


def _initial_crypto_frames(d: bytes, crypto: dict[int, bytes]) -> None:
    """Decrypt the client Initial packets of one datagram (possibly coalesced) and collect their CRYPTO frames."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pos = 0
    while pos + 7 <= len(d) and d[pos] & 0x80:  # long header packets
        ver = int.from_bytes(d[pos + 1:pos + 5], "big")
        p = pos + 5
        dcid = d[p + 1:p + 1 + d[p]]
        p += 1 + d[p]
        p += 1 + d[p]  # scid
        if ver not in QUIC_VERSIONS:
            break
        salt, prefix, initial_type = QUIC_VERSIONS[ver]
        is_initial = (d[pos] >> 4) & 3 == initial_type
        if is_initial:
            tl, p = _varint(d, p)
            p += tl  # token
        ln, p = _varint(d, p)
        end = p + ln
        if is_initial:
            secret = _hkdf_expand_label(hmac.new(salt, dcid, "sha256").digest(), b"client in", 32)
            key, iv, hp = (_hkdf_expand_label(secret, prefix + x, n)
                           for x, n in ((b"key", 16), (b"iv", 12), (b"hp", 16)))
            enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
            mask = enc.update(d[p + 4:p + 20]) + enc.finalize()
            first = d[pos] ^ (mask[0] & 0x0F)
            pnl = (first & 3) + 1
            pn = bytes(d[p + i] ^ mask[1 + i] for i in range(pnl))
            nonce = bytes(a ^ b for a, b in zip(iv, pn.rjust(12, b"\x00")))
            try:
                plain = AESGCM(key).decrypt(nonce, d[p + pnl:end], bytes([first]) + d[pos + 1:p] + pn)
            except Exception:  # noqa: BLE001  (keys from a later DCID: not a first-flight packet)
                plain = b""
            q = 0
            while q < len(plain):
                if plain[q] in (0x00, 0x01):  # PADDING, PING
                    q += 1
                elif plain[q] == 0x06:  # CRYPTO
                    off, q = _varint(plain, q + 1)
                    n, q = _varint(plain, q)
                    crypto[off] = plain[q:q + n]
                    q += n
                else:
                    break  # ACK etc. never precede the hello in flight 1
        pos = end


def quic_client_hellos(datagrams: Iterable[bytes]) -> list[bytes]:
    """Decrypt client Initial packets and reassemble the CRYPTO stream. Keys come from each packet's own DCID, so
    only the first flight (and a post-Retry resend) decrypts - which is exactly where the ClientHello lives.
    A truncated or garbled datagram is skipped."""
    crypto: dict[int, bytes] = {}
    for d in datagrams:
        try:
            _initial_crypto_frames(d, crypto)
        except IndexError:
            continue
    stream = b""
    for off in sorted(crypto):
        if off > len(stream):
            break
        stream = stream[:off] + crypto[off] + stream[off + len(crypto[off]):]
    if len(stream) >= 4 and stream[0] == 1 and len(stream) >= 4 + int.from_bytes(stream[1:4], "big"):
        return [stream[:4 + int.from_bytes(stream[1:4], "big")]]
    return []


class UdpRelay:
    """Relay UDP datagrams between the client (on 127.0.0.1) and host:port, recording client->server datagrams."""

    def __init__(self, host: str, port: int) -> None:
        fam, _, _, _, addr = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self._port: int = self.sock.getsockname()[1]
        self.up = socket.socket(fam, socket.SOCK_DGRAM)
        self.up.connect(addr)
        self.datagrams: list[bytes] = []
        self.client: Any = None  # the client's address, once it has sent something
        for sock, fn in ((self.sock, self._c2s), (self.up, self._s2c)):
            sock.settimeout(30)
            threading.Thread(target=fn, daemon=True).start()

    @property
    def port(self) -> int:
        return self._port

    def _c2s(self) -> None:
        try:
            while True:
                data, self.client = self.sock.recvfrom(65535)
                self.datagrams.append(data)
                self.up.send(data)
        except OSError:
            pass

    def _s2c(self) -> None:
        try:
            while True:
                data = self.up.recv(65535)
                if self.client:
                    self.sock.sendto(data, self.client)
        except OSError:
            pass

    def client_hellos(self) -> list[bytes]:
        return quic_client_hellos(self.datagrams)


def http_body(raw: bytes) -> str:
    head, _, body = raw.partition(b"\r\n\r\n")
    if b"transfer-encoding: chunked" in head.lower():
        out = b""
        while body:
            size, _, rest = body.partition(b"\r\n")
            n = int(size.split(b";")[0] or b"0", 16)
            if n == 0:
                break
            out, body = out + rest[:n], rest[n + 2:]
        body = out
    return body.decode(errors="replace")


def req(o: Target) -> bytes:
    return f"GET {o.path} HTTP/1.1\r\nHost: {o.host}\r\nUser-Agent: ja4-probe\r\nConnection: close\r\n\r\n".encode()


# ---- client runners: each gets (target, local relay port) and returns the response body -------------------------

Runner = Callable[[Target, int], str]


def curl(*args: str, ip: bool = False) -> Runner:
    """ip=True: request https://127.0.0.1:<relay>/ with a Host header, so curl sends no SNI (IP literal)."""
    def run(o: Target, relay_port: int) -> str:
        if ip:
            target = ["-k", "-H", f"Host: {o.host}", f"https://127.0.0.1:{relay_port}{o.path}"]
        else:
            target = ["--connect-to", f"{o.host}:{o.port}:127.0.0.1:{relay_port}", *(["-k"] if o.insecure else []),
                      f"https://{o.host}:{o.port}{o.path}"]
        cmd = ["curl", "-s", "--max-time", "20", *args, *target]
        return subprocess.run(cmd, capture_output=True, timeout=30).stdout.decode(errors="replace")
    return run


def s_client(*args: str | bytes) -> Runner:
    def run(o: Target, relay_port: int) -> str:
        sni = [] if "-noservername" in args else ["-servername", o.host]
        cmd = ["openssl", "s_client", "-connect", f"127.0.0.1:{relay_port}", "-quiet", *sni, *args]
        p = subprocess.run(cmd, input=req(o), capture_output=True, timeout=30)
        return http_body(p.stdout)
    return run


def cffi(target: str) -> Runner:
    def run(o: Target, relay_port: int) -> str:
        from curl_cffi import requests as creq
        resp = creq.get(f"https://{o.host}:{o.port}{o.path}", impersonate=target,
                        verify=not o.insecure, timeout=20, proxy=f"http://127.0.0.1:{relay_port}")
        return resp.text
    return run


def wget(*args: str) -> Runner:
    def run(o: Target, relay_port: int) -> str:
        cmd = ["wget", "-q", "-O", "-", "-T", "20", "-t", "1", "-e", "use_proxy=yes", "-e",
               f"https_proxy=http://127.0.0.1:{relay_port}", *(["--no-check-certificate"] if o.insecure else []),
               *args, f"https://{o.host}:{o.port}{o.path}"]
        return subprocess.run(cmd, capture_output=True, timeout=30).stdout.decode(errors="replace")
    return run


def urllib_() -> Runner:
    def run(o: Target, relay_port: int) -> str:
        import ssl
        import urllib.request
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{relay_port}"})]
        if o.insecure:  # http.client's own default context (ALPN, PHA), only with verification off: same hello
            import http.client
            ctx: ssl.SSLContext = getattr(http.client, "_create_https_context")(11)
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        with urllib.request.build_opener(*handlers).open(f"https://{o.host}:{o.port}{o.path}", timeout=20) as resp:
            body: bytes = resp.read()
            return body.decode(errors="replace")
    return run


def httpx_(http2: bool = False) -> Runner:
    def run(o: Target, relay_port: int) -> str:
        import httpx
        with httpx.Client(http2=http2, verify=not o.insecure, proxy=f"http://127.0.0.1:{relay_port}", timeout=20) as c:
            return c.get(f"https://{o.host}:{o.port}{o.path}").text
    return run


def niquests_() -> Runner:
    def run(o: Target, relay_port: int) -> str:
        import niquests
        r = niquests.get(f"https://{o.host}:{o.port}{o.path}", verify=not o.insecure, timeout=20,
                         proxies={"https": f"http://127.0.0.1:{relay_port}"})
        return r.text or ""
    return run


def cffi_h3(target: str) -> Runner:
    """curl_cffi over HTTP/3 (QUIC). curl_cffi's setopt() cannot pass CONNECT_TO, so the slist goes in raw."""
    def run(o: Target, relay_port: int) -> str:
        from io import BytesIO

        from curl_cffi import Curl, CurlHttpVersion, CurlOpt
        from curl_cffi._wrapper import ffi, lib
        c, buf = Curl(), BytesIO()
        c.impersonate(target)
        c.setopt(CurlOpt.URL, f"https://{o.host}:{o.port}{o.path}")
        c.setopt(CurlOpt.HTTP_VERSION, CurlHttpVersion.V3ONLY)
        c.setopt(CurlOpt.WRITEDATA, buf)
        c.setopt(CurlOpt.TIMEOUT, 20)
        if o.insecure:
            c.setopt(CurlOpt.SSL_VERIFYPEER, 0)
            c.setopt(CurlOpt.SSL_VERIFYHOST, 0)
        sl = lib.curl_slist_append(ffi.NULL, f"{o.host}:{o.port}:127.0.0.1:{relay_port}".encode())
        lib._curl_easy_setopt(c._curl, CurlOpt.CONNECT_TO, sl)
        try:
            c.perform()
        finally:
            c.close()
            lib.curl_slist_free_all(sl)
        return buf.getvalue().decode(errors="replace")
    return run


def niquests_h3() -> Runner:
    """niquests (qh3) forced onto HTTP/3; the host resolves to 127.0.0.1 and the URL carries the relay port."""
    def run(o: Target, relay_port: int) -> str:
        import niquests
        with niquests.Session(disable_http1=True, disable_http2=True,
                              resolver=f"in-memory://default/?hosts={o.host}:127.0.0.1") as s:
            return s.get(f"https://{o.host}:{relay_port}{o.path}", verify=not o.insecure, timeout=20).text or ""
    return run


# ---- tlslite-ng client with ClientHello mutations ----------------------------------------------------------------

Hook = Callable[[Any], None]
"""Mutates a tlslite.messages.ClientHello in place, right before it is serialised."""


def tlslite(hook: Hook | None = None, sni: bool = True, alpn: Sequence[bytes] | None = (b"http/1.1",),
            record_size: int | None = None, hook2: Hook | None = None, resume: bool = False,
            **settings: Any) -> Runner:
    """tlslite-ng client. `hook(ClientHello)` mutates the first hello right before it is serialised, `hook2` the
    second one (after a HelloRetryRequest). resume=True first does a full handshake directly with the server and then
    resumes that TLS 1.2 session through the relay (a resumed handshake needs no signature, so hellos without
    signature_algorithms or without any extension can still complete)."""
    def run(o: Target, relay_port: int) -> str:
        from tlslite import HandshakeSettings, TLSConnection
        from tlslite.messages import ClientHello

        class Conn(TLSConnection):  # type: ignore[misc]  # tlslite is untyped
            hellos = 0

            def _sendMsg(self, msg: Any, *a: Any, **kw: Any) -> Any:
                if isinstance(msg, ClientHello):
                    h = (hook, hook2)[min(self.hellos, 1)] if self.hellos < 2 else None
                    self.hellos += 1
                    if h:
                        h(msg)  # the post-HRR hello is the same object, so hook's changes persist
                return super()._sendMsg(msg, *a, **kw)

        hs = HandshakeSettings()
        for k, v in settings.items():
            setattr(hs, k, v)
        names = dict(serverName=o.host if sni else None, alpn=[bytearray(a) for a in alpn] if alpn else None)
        session = None
        if resume:
            first = TLSConnection(socket.create_connection((o.connect or o.host, o.port), timeout=20))
            first.handshakeClientCert(settings=hs, **names)
            session = first.session
            first.close()
            if not session.sessionID:  # ticket-only server: client may pick the session ID (RFC 5077 3.4)
                session.sessionID = bytearray(os.urandom(32))
        c = Conn(socket.create_connection(("127.0.0.1", relay_port), timeout=20))
        if record_size:
            c.recordSize = record_size  # split the ClientHello over many TLS records
        c.handshakeClientCert(settings=hs, session=session, **names)
        if resume and not c.resumed:
            raise RuntimeError("server did not resume the session")
        c.write(req(o))
        raw = b""
        try:
            while d := c.read():
                raw += bytes(d)
        except Exception:  # noqa: BLE001  (abrupt close after response is fine)
            pass
        return http_body(raw)
    return run


def _ext(t: int, data: bytes = b"") -> Any:
    from tlslite.extensions import TLSExtension
    return TLSExtension(extType=t).create(bytearray(data))


def _get(ch: Any, t: int) -> Any:
    return next(e for e in ch.extensions if e.extType == t)


def grease_everywhere(ch: Any) -> None:
    ch.cipher_suites = [0x0A0A] + ch.cipher_suites[:3] + [0x1A1A] + ch.cipher_suites[3:]
    ch.extensions = [_ext(0x2A2A)] + ch.extensions[:4] + [_ext(0x3A3A, b"\x00")] + ch.extensions[4:] + [_ext(0x4A4A)]
    sig = _get(ch, 0x000D)
    sig.sigalgs = [(0x5A, 0x5A)] + sig.sigalgs[:2] + [(0x6A, 0x6A)] + sig.sigalgs[2:]
    _get(ch, 0x002B).versions = [(0x7A, 0x7A)] + _get(ch, 0x002B).versions
    _get(ch, 0x000A).groups = [0x8A8A] + _get(ch, 0x000A).groups


def unknown_exts(ch: Any) -> None:
    # all of these are ignored (dropped) by OpenSSL's SSL_client_hello_get1_extensions_present()
    # (tlslite itself already sends 0x000f heartbeat, 0x001c record_size_limit and 0x0015 padding - also unknown)
    ch.extensions = ch.extensions[:2] + [_ext(0x4469, b"\x00\x03\x02h2"), _ext(0x1234),
                                         _ext(0x0022, b"\x00\x02\x04\x03")] + ch.extensions[2:]


def alpn_first(first: bytes) -> Hook:
    def h(ch: Any) -> None:
        _get(ch, 0x0010).protocol_names = [bytearray(first), bytearray(b"http/1.1")]
    return h


def many_ciphers(ch: Any) -> None:
    ch.cipher_suites = ch.cipher_suites + [0x00FF, 0x5600, 0xFE00, 0xFEFF] + list(range(0x0100, 0x0100 + 100))


def reversed_sigalgs(ch: Any) -> None:
    _get(ch, 0x000D).sigalgs = list(reversed(_get(ch, 0x000D).sigalgs))


def shuffled_exts(ch: Any) -> None:
    ch.extensions = list(reversed(ch.extensions))


def future_version(ch: Any) -> None:
    _get(ch, 0x002B).versions = [(0x7F, 0x1C)] + _get(ch, 0x002B).versions


def only_grease_versions(ch: Any) -> None:
    _get(ch, 0x002B).versions = [(0x2A, 0x2A)]


def add_unknown_ext(ch: Any) -> None:
    ch.extensions = [_ext(0x1234)] + ch.extensions


def dup_unknown_ext(ch: Any) -> None:
    ch.extensions = [_ext(0x1234)] + ch.extensions[:-1] + [_ext(0x1234)] + ch.extensions[-1:]


def drop_ext(t: int) -> Hook:
    def h(ch: Any) -> None:
        ch.extensions = [e for e in ch.extensions if e.extType != t]
    return h


def no_extensions(ch: Any) -> None:
    ch.extensions = None


# ---- cases --------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    runner: Runner
    pattern: str | None
    """Regex the local JA4_a must match (pins the spec's edge-case rule independently of the server)."""
    may_refuse: bool = False
    """SKIP instead of FAIL when the server's TLS stack rejects the hello."""
    udp: bool = False
    """QUIC client: UDP relay, ClientHello recovered from the Initial packets, proto `q`."""


CASES: Final[dict[str, Case]] = {
    "curl_default_h2": Case(curl(), r"t13d\d{4}h2"),
    "curl_http11": Case(curl("--http1.1"), r"t13d\d{4}h1"),
    "curl_tls12_max": Case(curl("--http1.1", "--tls-max", "1.2"), r"t12d\d{4}h1"),
    "curl_tls13_only": Case(curl("--tlsv1.3"), r"t13d\d{4}h2"),
    "curl_no_alpn": Case(curl("--no-alpn"), r"t13d\d{4}00"),
    "curl_ip_no_sni": Case(curl("--http1.1", ip=True), r"t13i\d{4}h1"),
    "wget": Case(wget(), r"t13d\d{4}00"),
    "python_urllib": Case(urllib_(), r"t13d\d{4}h1"),
    "python_httpx_h1": Case(httpx_(), r"t13d\d{4}h1"),
    "python_httpx_h2": Case(httpx_(http2=True), r"t13d\d{4}h1"),  # offers "http/1.1,h2": first value counts
    "python_niquests": Case(niquests_(), r"t13d\d{4}h2"),
    "s_client_no_alpn": Case(s_client(), r"t13d\d{4}00"),
    "s_client_no_sni": Case(s_client("-noservername", "-alpn", "http/1.1"), r"t13i\d{4}h1"),
    "s_client_sigalgs_order": Case(s_client("-alpn", "http/1.1", "-sigalgs",
                                            "rsa_pss_rsae_sha256:ECDSA+SHA256:RSA+SHA256:ed25519"), r"t13d\d{4}h1"),
    "s_client_tls12_all_ciphers": Case(s_client("-tls1_2", "-alpn", "http/1.1", "-cipher",
                                                "ALL:COMPLEMENTOFALL:@SECLEVEL=0"), r"t12d\d{4}h1"),
    "s_client_serverinfo_unknown": Case(s_client("-alpn", "http/1.1", "-serverinfo", "2570,17513,4660"),
                                        r"t13d\d{4}h1"),
    "s_client_nonascii_alpn": Case(s_client("-alpn", b"\xab\xcd,http/1.1"), r"t13d\d{4}ad"),
    "chrome": Case(cffi("chrome"), r"t13d\d{4}h2"),
    "firefox": Case(cffi("firefox"), r"t13d\d{4}h2"),
    "safari": Case(cffi("safari"), r"t13d\d{4}h2"),
    # QUIC / HTTP/3 (ClientHello recovered by decrypting the Initial packets); kittens.sh has no HTTP/3 -> may_refuse
    "chrome_h3": Case(cffi_h3("chrome"), r"q13d\d{4}h3", may_refuse=True, udp=True),
    # (curl_cffi's firefox/safari h3 send this same hello)
    "python_niquests_h3": Case(niquests_h3(), r"q13d\d{4}h3", may_refuse=True, udp=True),
    "tlslite_default": Case(tlslite(), r"t13d\d{4}h1"),
    "tlslite_grease": Case(tlslite(grease_everywhere), r"t13d\d{4}h1"),
    "tlslite_unknown_exts": Case(tlslite(unknown_exts), r"t13d\d{4}h1"),
    "tlslite_reversed_sigalgs": Case(tlslite(reversed_sigalgs), r"t13d\d{4}h1"),
    "tlslite_shuffled_exts": Case(tlslite(shuffled_exts), r"t13d\d{4}h1"),
    "tlslite_many_ciphers_scsv": Case(tlslite(many_ciphers), r"t13d99\d\dh1"),
    "tlslite_future_version": Case(tlslite(future_version), r"t00d\d{4}h1"),
    "tlslite_tls12_only": Case(tlslite(maxVersion=(3, 3)), r"t12d\d{4}h1"),
    # spec is silent; clientfp.fp.ja4 falls back to legacy_version (0x0303 -> "12")
    "tlslite_versions_only_grease": Case(tlslite(only_grease_versions), r"t12d\d{4}h1", may_refuse=True),
    "tlslite_no_sni": Case(tlslite(sni=False), r"t13i\d{4}h1"),
    "tlslite_no_alpn": Case(tlslite(alpn=None), r"t13d\d{4}00"),
    # HRR: 2nd hello gets an extra extension, so its JA4 differs and shows which hello the server fingerprinted
    "tlslite_hrr": Case(tlslite(hook2=add_unknown_ext, keyShares=[]), r"t13d\d{4}h1"),
    "tlslite_dup_unknown_ext": Case(tlslite(dup_unknown_ext), r"t13d\d{4}h1", may_refuse=True),
    "tlslite_tls12_no_sigalgs": Case(tlslite(drop_ext(0x000D), maxVersion=(3, 3)), r"t12d\d{4}h1", may_refuse=True),
    "tlslite_tls12_no_extensions": Case(tlslite(no_extensions, sni=False, alpn=None, maxVersion=(3, 3)),
                                        r"t12i\d{2}0000", may_refuse=True),
    # no sigalgs again, but resuming a TLS 1.2 session (ticket), which needs no server signature: works on OpenSSL
    # servers with tickets enabled at any security level
    "tlslite_resumed_no_sigalgs": Case(tlslite(drop_ext(0x000D), resume=True, maxVersion=(3, 3)), r"t12d\d{4}h1",
                                       may_refuse=True),
    "tlslite_fragmented_hello": Case(tlslite(record_size=64), r"t13d\d{4}h1"),
    "alpn_single_char": Case(tlslite(alpn_first(b"a")), r"t13d\d{4}aa"),
    "alpn_ab_cd": Case(tlslite(alpn_first(b"\xab\xcd")), r"t13d\d{4}ad"),
    "alpn_20_61": Case(tlslite(alpn_first(b"\x20\x61")), r"t13d\d{4}21"),
    "alpn_30_ab": Case(tlslite(alpn_first(b"\x30\xab")), r"t13d\d{4}3b"),
    "alpn_61_20": Case(tlslite(alpn_first(b"\x61\x20")), r"t13d\d{4}60"),
    "alpn_30_ab_cd_31": Case(tlslite(alpn_first(b"\x30\xab\xcd\x31")), r"t13d\d{4}01"),
    "alpn_hash_x": Case(tlslite(alpn_first(b"#x")), r"t13d\d{4}28"),  # '#'=0x23 not alnum -> hex "2378"
}


FORMS: Final = ja4.FORMS
REFS: Final = {"kittens": ("kittens.sh", "/api/all"), "thumbprint": ("thumbprint.me", "/api/v1/probe")}
JA4_RE: Final = re.compile(r"[tqd][0-9s]{2}[di]\d{4}[0-9a-zA-Z]{2}_[0-9a-f]{12}_[0-9a-f]{12}")


class Vector(TypedDict):
    """One entry of doc/ja4_vectors.json."""

    name: str
    server: str
    server_confirmed: list[str]
    client_hello_hex: str
    ja4: str
    ja4_r: str
    ja4_o: str
    ja4_ro: str


@dataclass(frozen=True)
class CaseResult:
    status: Literal["PASS", "FAIL", "SKIP"]
    text: str
    vector: Vector | None


def relay_for(o: Target, case: Case) -> HelloCapture:
    return (UdpRelay if case.udp else Relay)(o.connect or o.host, o.port)


def run_case(o: Target, name: str, case: Case) -> CaseResult:
    r = relay_for(o, case)
    proto: ja4.Proto = "q" if case.udp else "t"
    try:
        body = case.runner(o, r.port)
    except Exception as e:  # noqa: BLE001  (a client failure is this case's result)
        body = f"<client error {type(e).__name__}: {e}>"
    hellos = r.client_hellos()
    if not hellos:
        return CaseResult("FAIL", f"FAIL {name}: no ClientHello captured ({body[:120]!r})", None)
    try:
        local = ja4.from_bytes(hellos[0], proto)
    except ValueError as e:
        return CaseResult("FAIL", f"FAIL {name}: captured ClientHello does not parse: {e}", None)
    server: dict[str, str]
    server_raw: str | None = None
    try:
        j = json.loads(body)
    except ValueError:
        server = {"ja4": body.strip()} if body.strip() else {}
    else:
        if isinstance(j, dict):
            server = {k: j[k] for k in FORMS if isinstance(j.get(k), str)}
            raw = (j.get("tls") or {}).get("raw", {}).get("hex")
            server_raw = raw if isinstance(raw, str) else None
        else:
            server = {"ja4": body.strip()}
    lines: list[str] = []
    ok = True
    if not JA4_RE.fullmatch(server.get("ja4", "")):
        if case.may_refuse and body.startswith("<client error"):
            return CaseResult("SKIP", f"SKIP {name:28s} local={local.ja4} server refused the hello: {body[:90]}", None)
        ok = False
        server = {"ja4": f"<no ja4 in response: {body[:160]!r}>"}
    else:
        forms = local.forms()
        for k, v in server.items():
            if v != forms[k]:
                ok = False
                lines.append(f"     {k:6s} local  {forms[k]}\n     {k:6s} server {v}")
        others = [_ja4_or_none(h, proto) for h in hellos[1:]]
        if server["ja4"] in others:
            lines.append(f"     NOTE: server fingerprinted ClientHello #{others.index(server['ja4']) + 2} (after HRR)")
    if case.pattern and not re.fullmatch(case.pattern, local.a):
        ok = False
        lines.append(f"     JA4_a {local.a} does not match expected /{case.pattern}/")
    if server_raw and all(server_raw != h.hex() for h in hellos):
        lines.append("     NOTE: server raw ClientHello differs from captured one")
    extra = f" (+{len(hellos) - 1} more ClientHello)" if len(hellos) > 1 else ""
    checked = ",".join(k for k in FORMS if k in server)
    head = f"{'PASS' if ok else 'FAIL'} {name:28s} local={local.ja4} server={server['ja4']} [{checked}]{extra}"
    vector = Vector(name=name, server=o.host, server_confirmed=sorted(server) if ok else [],
                    client_hello_hex=hellos[0].hex(), ja4=local.ja4, ja4_r=local.ja4_r, ja4_o=local.ja4_o,
                    ja4_ro=local.ja4_ro)
    return CaseResult("PASS" if ok else "FAIL", "\n".join([head, *lines]), vector)


def _ja4_or_none(hello: bytes, proto: ja4.Proto) -> str | None:
    try:
        return ja4.from_bytes(hello, proto).ja4
    except ValueError:
        return None


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="clientfp-ja4-probe",
                                 description="Compare locally computed JA4 of real clients with a JA4 endpoint")
    ap.add_argument("--ref", default="kittens,thumbprint", help=f"reference servers, comma list of {list(REFS)}")
    ap.add_argument("--host", help="custom target: Host header / SNI (overrides --ref)")
    ap.add_argument("--connect", help="TCP address to connect to, if different from --host")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--path", default="/")
    ap.add_argument("--case", default="all")
    ap.add_argument("-k", "--insecure", action="store_true", help="skip certificate verification")
    ap.add_argument("--dump", help="write captured ClientHellos + JA4 values of passing cases to this JSON file")
    a = ap.parse_args(argv)
    if a.host:
        targets = [Target(host=a.host, connect=a.connect, port=a.port, path=a.path, insecure=a.insecure)]
    else:
        try:
            targets = [Target(host=REFS[n][0], connect=None, port=443, path=REFS[n][1], insecure=a.insecure)
                       for n in a.ref.split(",")]
        except KeyError as e:
            ap.error(f"unknown reference server {e}; choose from {list(REFS)}")
    failed, skipped, vectors = 0, 0, []
    for o in targets:
        print(f"== {o.host}:{o.port}{o.path}", flush=True)
        for name, case in CASES.items():
            if a.case not in ("all", name):
                continue
            res = run_case(o, name, case)
            failed += res.status == "FAIL"
            skipped += res.status == "SKIP"
            print(res.text, flush=True)
            if res.status == "PASS" and res.vector:
                vectors.append(res.vector)
    print(f"== {len(vectors)} passed, {failed} failed, {skipped} skipped")
    if a.dump:
        Path(a.dump).write_text(json.dumps(vectors, indent=1) + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
