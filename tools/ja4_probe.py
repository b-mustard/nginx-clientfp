#!/usr/bin/env python3
"""JA4 probe: drives several TLS clients (curl, wget, python urllib/httpx/niquests, openssl s_client, curl_cffi
browser impersonation, and a tlslite-ng client whose ClientHello is mutated on the fly) at a JA4 endpoint, captures
each client's real ClientHello through a local one-shot TCP relay, computes JA4 locally (tools/ja4.py) and compares
with what the server reports.

    .venv/bin/python tools/ja4_probe.py [--ref kittens,thumbprint] [--case NAME|all] [--dump FILE]
    .venv/bin/python tools/ja4_probe.py --host localhost --connect 127.0.0.1 --port 8443 --path /ja4 -k

Reference servers (kittens.sh and thumbprint.me): kittens.sh /api/all returns JSON with "ja4", "ja4_r" and the
raw ClientHello; thumbprint.me /api/v1/probe returns JSON with "ja4", "ja4_r", "ja4_o", "ja4_ro". Our nginx may
return a bare JA4 string. Every form the server returns is compared. Each case may also carry a regex on JA4_a that
pins the spec's edge-case rules independently of the server; cases flagged may_refuse are SKIPped (not failed) when
the server's TLS stack rejects the hello. --dump writes the captured ClientHellos with their JA4 values (offline
test vectors).
"""
import argparse
import hmac
import json
import os
import re
import socket
import subprocess
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ja4  # noqa: E402


class Relay:
    """Accept one TCP connection on 127.0.0.1, pipe it to host:port, record client->server bytes."""

    def __init__(self, host, port):
        self.srv = socket.create_server(("127.0.0.1", 0))
        self.port = self.srv.getsockname()[1]
        self.c2s = bytearray()
        self.upstream = (host, port)
        threading.Thread(target=self._run, daemon=True).start()

    def _pump(self, src, dst, record):
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

    def _run(self):
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

    def client_hellos(self):
        """All plaintext ClientHello messages (2 after a HelloRetryRequest), in order."""
        data, p, hs = bytes(self.c2s), 0, b""
        while p + 5 <= len(data):
            ctype, _v, ln = data[p], data[p + 1:p + 3], int.from_bytes(data[p + 3:p + 5], "big")
            if ctype == 22:
                hs += data[p + 5:p + 5 + ln]
            elif ctype != 20:            # stop at first encrypted / app-data record; skip compat CCS
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

QUIC_VERSIONS = {  # version -> (initial salt, HKDF label prefix, long-header type of Initial packets)
    0x00000001: (bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), b"quic ", 0),
    0x6B3343CF: (bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"), b"quicv2 ", 1),
}


def _hkdf_expand_label(secret, label, length):
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), "sha256").digest()
        out, i = out + t, i + 1
    return out[:length]


def _varint(b, p):
    n, v = 1 << (b[p] >> 6), b[p] & 0x3F
    for i in range(1, n):
        v = (v << 8) | b[p + i]
    return v, p + n


def quic_client_hellos(datagrams):
    """Decrypt client Initial packets and reassemble the CRYPTO stream. Keys come from each packet's own DCID, so
    only the first flight (and a post-Retry resend) decrypts - which is exactly where the ClientHello lives."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    crypto = {}
    for d in datagrams:
        pos = 0
        while pos + 7 <= len(d) and d[pos] & 0x80:           # long header packets (possibly coalesced)
            ver = int.from_bytes(d[pos + 1:pos + 5], "big")
            p = pos + 5
            dcid = d[p + 1:p + 1 + d[p]]
            p += 1 + d[p]
            p += 1 + d[p]                                     # scid
            if ver not in QUIC_VERSIONS:
                break
            salt, prefix, initial_type = QUIC_VERSIONS[ver]
            is_initial = (d[pos] >> 4) & 3 == initial_type
            if is_initial:
                tl, p = _varint(d, p)
                p += tl                                       # token
            ln, p = _varint(d, p)
            end = p + ln
            if is_initial:
                secret = _hkdf_expand_label(hmac.new(salt, dcid, "sha256").digest(), b"client in", 32)
                key, iv, hp = (_hkdf_expand_label(secret, prefix + x, n) for x, n in ((b"key", 16), (b"iv", 12), (b"hp", 16)))
                enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
                mask = enc.update(bytes(d[p + 4:p + 20])) + enc.finalize()
                first = d[pos] ^ (mask[0] & 0x0F)
                pnl = (first & 3) + 1
                pn = bytes(d[p + i] ^ mask[1 + i] for i in range(pnl))
                nonce = bytes(a ^ b for a, b in zip(iv, pn.rjust(12, b"\x00")))
                try:
                    plain = AESGCM(key).decrypt(nonce, bytes(d[p + pnl:end]), bytes([first]) + bytes(d[pos + 1:p]) + pn)
                except Exception:  # noqa: BLE001  (keys from a later DCID: not a first-flight packet)
                    plain = b""
                q = 0
                while q < len(plain):
                    if plain[q] in (0x00, 0x01):              # PADDING, PING
                        q += 1
                    elif plain[q] == 0x06:                    # CRYPTO
                        off, q = _varint(plain, q + 1)
                        n, q = _varint(plain, q)
                        crypto[off] = plain[q:q + n]
                        q += n
                    else:
                        break                                 # ACK etc. never precede the hello in flight 1
            pos = end
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

    def __init__(self, host, port):
        fam, _, _, _, addr = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.up = socket.socket(fam, socket.SOCK_DGRAM)
        self.up.connect(addr)
        self.datagrams, self.client = [], None
        for sock, fn in ((self.sock, self._c2s), (self.up, self._s2c)):
            sock.settimeout(30)
            threading.Thread(target=fn, daemon=True).start()

    def _c2s(self):
        try:
            while True:
                data, self.client = self.sock.recvfrom(65535)
                self.datagrams.append(data)
                self.up.send(data)
        except OSError:
            pass

    def _s2c(self):
        try:
            while True:
                data = self.up.recv(65535)
                if self.client:
                    self.sock.sendto(data, self.client)
        except OSError:
            pass

    def client_hellos(self):
        return quic_client_hellos(self.datagrams)


def http_body(raw):
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


def req(o):
    return f"GET {o.path} HTTP/1.1\r\nHost: {o.host}\r\nUser-Agent: ja4-probe\r\nConnection: close\r\n\r\n".encode()


# ---- client runners: each gets (options, relay) and returns the response body --------------------------------

def curl(*args, ip=False):
    """ip=True: request https://127.0.0.1:<relay>/ with a Host header, so curl sends no SNI (IP literal)."""
    def run(o, r):
        if ip:
            target = ["-k", "-H", f"Host: {o.host}", f"https://127.0.0.1:{r.port}{o.path}"]
        else:
            target = ["--connect-to", f"{o.host}:{o.port}:127.0.0.1:{r.port}", *(["-k"] if o.insecure else []),
                      f"https://{o.host}:{o.port}{o.path}"]
        cmd = ["curl", "-s", "--max-time", "20", *args, *target]
        return subprocess.run(cmd, capture_output=True, timeout=30).stdout.decode(errors="replace")
    return run


def s_client(*args):
    def run(o, r):
        sni = [] if "-noservername" in args else ["-servername", o.host]
        cmd = ["openssl", "s_client", "-connect", f"127.0.0.1:{r.port}", "-quiet", *sni, *args]
        p = subprocess.run(cmd, input=req(o), capture_output=True, timeout=30)
        return http_body(p.stdout)
    return run


def cffi(target):
    def run(o, r):
        from curl_cffi import requests as creq
        resp = creq.get(f"https://{o.host}:{o.port}{o.path}", impersonate=target, verify=not o.insecure, timeout=20,
                        proxy=f"http://127.0.0.1:{r.port}")
        return resp.text
    return run


def wget(*args):
    def run(o, r):
        cmd = ["wget", "-q", "-O", "-", "-T", "20", "-t", "1", "-e", "use_proxy=yes", "-e",
               f"https_proxy=http://127.0.0.1:{r.port}", *(["--no-check-certificate"] if o.insecure else []), *args,
               f"https://{o.host}:{o.port}{o.path}"]
        return subprocess.run(cmd, capture_output=True, timeout=30).stdout.decode(errors="replace")
    return run


def urllib_():
    def run(o, r):
        import ssl
        import urllib.request
        handlers = [urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{r.port}"})]
        if o.insecure:  # http.client's own default context (ALPN, PHA), only with verification off: same hello
            import http.client
            ctx = http.client._create_https_context(11)
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        with urllib.request.build_opener(*handlers).open(f"https://{o.host}:{o.port}{o.path}", timeout=20) as resp:
            return resp.read().decode(errors="replace")
    return run


def httpx_(http2=False):
    def run(o, r):
        import httpx
        with httpx.Client(http2=http2, verify=not o.insecure, proxy=f"http://127.0.0.1:{r.port}", timeout=20) as c:
            return c.get(f"https://{o.host}:{o.port}{o.path}").text
    return run


def niquests_():
    def run(o, r):
        import niquests
        return niquests.get(f"https://{o.host}:{o.port}{o.path}", verify=not o.insecure, timeout=20,
                            proxies={"https": f"http://127.0.0.1:{r.port}"}).text
    return run


def cffi_h3(target):
    """curl_cffi over HTTP/3 (QUIC). curl_cffi's setopt() cannot pass CONNECT_TO, so the slist goes in raw."""
    def run(o, r):
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
        sl = lib.curl_slist_append(ffi.NULL, f"{o.host}:{o.port}:127.0.0.1:{r.port}".encode())
        lib._curl_easy_setopt(c._curl, CurlOpt.CONNECT_TO, sl)
        try:
            c.perform()
        finally:
            c.close()
            lib.curl_slist_free_all(sl)
        return buf.getvalue().decode(errors="replace")
    run.udp = True
    return run


def niquests_h3():
    """niquests (qh3) forced onto HTTP/3; the host resolves to 127.0.0.1 and the URL carries the relay port."""
    def run(o, r):
        import niquests
        with niquests.Session(disable_http1=True, disable_http2=True,
                              resolver=f"in-memory://default/?hosts={o.host}:127.0.0.1") as s:
            return s.get(f"https://{o.host}:{r.port}{o.path}", verify=not o.insecure, timeout=20).text
    run.udp = True
    return run


def tlslite(hook=None, sni=True, alpn=(b"http/1.1",), record_size=None, hook2=None, resume=False, **settings):
    """tlslite-ng client. `hook(ClientHello)` mutates the first hello right before it is serialised, `hook2` the
    second one (after a HelloRetryRequest). resume=True first does a full handshake directly with the server and then
    resumes that TLS 1.2 session through the relay (a resumed handshake needs no signature, so hellos without
    signature_algorithms or without any extension can still complete)."""
    def run(o, r):
        from tlslite import HandshakeSettings, TLSConnection
        from tlslite.messages import ClientHello

        class Conn(TLSConnection):
            hellos = 0

            def _sendMsg(self, msg, *a, **kw):
                if isinstance(msg, ClientHello):
                    h = (hook, hook2)[min(self.hellos, 1)] if self.hellos < 2 else None
                    self.hellos += 1
                    if h:
                        h(msg)            # the post-HRR hello is the same object, so hook's changes persist
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
            if not session.sessionID:   # ticket-only server: client may pick the session ID (RFC 5077 3.4)
                session.sessionID = bytearray(os.urandom(32))
        c = Conn(socket.create_connection(("127.0.0.1", r.port), timeout=20))
        if record_size:
            c.recordSize = record_size   # split the ClientHello over many TLS records
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


# ---- ClientHello mutations for tlslite ---------------------------------------------------------------------------

def _ext(t, data=b""):
    from tlslite.extensions import TLSExtension
    return TLSExtension(extType=t).create(bytearray(data))


def _get(ch, t):
    return next(e for e in ch.extensions if e.extType == t)


def grease_everywhere(ch):
    ch.cipher_suites = [0x0A0A] + ch.cipher_suites[:3] + [0x1A1A] + ch.cipher_suites[3:]
    ch.extensions = [_ext(0x2A2A)] + ch.extensions[:4] + [_ext(0x3A3A, b"\x00")] + ch.extensions[4:] + [_ext(0x4A4A)]
    _get(ch, 0x000D).sigalgs = [(0x5A, 0x5A)] + _get(ch, 0x000D).sigalgs[:2] + [(0x6A, 0x6A)] + _get(ch, 0x000D).sigalgs[2:]
    _get(ch, 0x002B).versions = [(0x7A, 0x7A)] + _get(ch, 0x002B).versions
    _get(ch, 0x000A).groups = [0x8A8A] + _get(ch, 0x000A).groups


def unknown_exts(ch):
    # all of these are ignored (dropped) by OpenSSL's SSL_client_hello_get1_extensions_present()
    # (tlslite itself already sends 0x000f heartbeat, 0x001c record_size_limit and 0x0015 padding - also unknown)
    ch.extensions = ch.extensions[:2] + [_ext(0x4469, b"\x00\x03\x02h2"), _ext(0x1234),
                                         _ext(0x0022, b"\x00\x02\x04\x03")] + ch.extensions[2:]


def alpn_first(first):
    def h(ch):
        _get(ch, 0x0010).protocol_names = [bytearray(first), bytearray(b"http/1.1")]
    return h


def many_ciphers(ch):
    ch.cipher_suites = ch.cipher_suites + [0x00FF, 0x5600, 0xFE00, 0xFEFF] + list(range(0x0100, 0x0100 + 100))


def reversed_sigalgs(ch):
    _get(ch, 0x000D).sigalgs = list(reversed(_get(ch, 0x000D).sigalgs))


def shuffled_exts(ch):
    ch.extensions = list(reversed(ch.extensions))


def future_version(ch):
    _get(ch, 0x002B).versions = [(0x7F, 0x1C)] + _get(ch, 0x002B).versions


def only_grease_versions(ch):
    _get(ch, 0x002B).versions = [(0x2A, 0x2A)]


def add_unknown_ext(ch):
    ch.extensions = [_ext(0x1234)] + ch.extensions


def dup_unknown_ext(ch):
    ch.extensions = [_ext(0x1234)] + ch.extensions[:-1] + [_ext(0x1234)] + ch.extensions[-1:]


def drop_ext(t):
    def h(ch):
        ch.extensions = [e for e in ch.extensions if e.extType != t]
    return h


def no_extensions(ch):
    ch.extensions = None


# ---- cases: name -> (runner, regex on JA4_a or None[, may_refuse]) ------------------------------------------------
CASES = {
    "curl_default_h2": (curl(), r"t13d\d{4}h2"),
    "curl_http11": (curl("--http1.1"), r"t13d\d{4}h1"),
    "curl_tls12_max": (curl("--http1.1", "--tls-max", "1.2"), r"t12d\d{4}h1"),
    "curl_tls13_only": (curl("--tlsv1.3"), r"t13d\d{4}h2"),
    "curl_no_alpn": (curl("--no-alpn"), r"t13d\d{4}00"),
    "curl_ip_no_sni": (curl("--http1.1", ip=True), r"t13i\d{4}h1"),
    "wget": (wget(), r"t13d\d{4}00"),
    "python_urllib": (urllib_(), r"t13d\d{4}h1"),
    "python_httpx_h1": (httpx_(), r"t13d\d{4}h1"),
    "python_httpx_h2": (httpx_(http2=True), r"t13d\d{4}h1"),  # offers "http/1.1,h2": first value counts
    "python_niquests": (niquests_(), r"t13d\d{4}h2"),
    "s_client_no_alpn": (s_client(), r"t13d\d{4}00"),
    "s_client_no_sni": (s_client("-noservername", "-alpn", "http/1.1"), r"t13i\d{4}h1"),
    "s_client_sigalgs_order": (s_client("-alpn", "http/1.1", "-sigalgs",
                                        "rsa_pss_rsae_sha256:ECDSA+SHA256:RSA+SHA256:ed25519"), r"t13d\d{4}h1"),
    "s_client_tls12_all_ciphers": (s_client("-tls1_2", "-alpn", "http/1.1", "-cipher", "ALL:COMPLEMENTOFALL:@SECLEVEL=0"),
                                   r"t12d\d{4}h1"),
    "s_client_serverinfo_unknown": (s_client("-alpn", "http/1.1", "-serverinfo", "2570,17513,4660"), r"t13d\d{4}h1"),
    "s_client_nonascii_alpn": (s_client("-alpn", b"\xab\xcd,http/1.1"), r"t13d\d{4}ad"),
    "chrome": (cffi("chrome"), r"t13d\d{4}h2"),
    "firefox": (cffi("firefox"), r"t13d\d{4}h2"),
    "safari": (cffi("safari"), r"t13d\d{4}h2"),
    # QUIC / HTTP/3 (ClientHello recovered by decrypting the Initial packets); kittens.sh has no HTTP/3 -> may_refuse
    "chrome_h3": (cffi_h3("chrome"), r"q13d\d{4}h3", True),  # (curl_cffi's firefox/safari h3 send this same hello)
    "python_niquests_h3": (niquests_h3(), r"q13d\d{4}h3", True),
    "tlslite_default": (tlslite(), r"t13d\d{4}h1"),
    "tlslite_grease": (tlslite(grease_everywhere), r"t13d\d{4}h1"),
    "tlslite_unknown_exts": (tlslite(unknown_exts), r"t13d\d{4}h1"),
    "tlslite_reversed_sigalgs": (tlslite(reversed_sigalgs), r"t13d\d{4}h1"),
    "tlslite_shuffled_exts": (tlslite(shuffled_exts), r"t13d\d{4}h1"),
    "tlslite_many_ciphers_scsv": (tlslite(many_ciphers), r"t13d99\d\dh1"),
    "tlslite_future_version": (tlslite(future_version), r"t00d\d{4}h1"),
    "tlslite_tls12_only": (tlslite(maxVersion=(3, 3)), r"t12d\d{4}h1"),
    # spec is silent; tools/ja4.py falls back to legacy_version (0x0303 -> "12")
    "tlslite_versions_only_grease": (tlslite(only_grease_versions), r"t12d\d{4}h1", True),
    "tlslite_no_sni": (tlslite(sni=False), r"t13i\d{4}h1"),
    "tlslite_no_alpn": (tlslite(alpn=None), r"t13d\d{4}00"),
    # HRR: 2nd hello gets an extra extension, so its JA4 differs and shows which hello the server fingerprinted
    "tlslite_hrr": (tlslite(hook2=add_unknown_ext, keyShares=[]), r"t13d\d{4}h1"),
    "tlslite_dup_unknown_ext": (tlslite(dup_unknown_ext), r"t13d\d{4}h1", True),
    "tlslite_tls12_no_sigalgs": (tlslite(drop_ext(0x000D), maxVersion=(3, 3)), r"t12d\d{4}h1", True),
    "tlslite_tls12_no_extensions": (tlslite(no_extensions, sni=False, alpn=None, maxVersion=(3, 3)), r"t12i\d{2}0000",
                                    True),
    # no sigalgs again, but resuming a TLS 1.2 session (ticket), which needs no server signature: works on OpenSSL
    # servers with tickets enabled at any security level
    "tlslite_resumed_no_sigalgs": (tlslite(drop_ext(0x000D), resume=True, maxVersion=(3, 3)), r"t12d\d{4}h1", True),
    "tlslite_fragmented_hello": (tlslite(record_size=64), r"t13d\d{4}h1"),
    "alpn_single_char": (tlslite(alpn_first(b"a")), r"t13d\d{4}aa"),
    "alpn_ab_cd": (tlslite(alpn_first(b"\xab\xcd")), r"t13d\d{4}ad"),
    "alpn_20_61": (tlslite(alpn_first(b"\x20\x61")), r"t13d\d{4}21"),
    "alpn_30_ab": (tlslite(alpn_first(b"\x30\xab")), r"t13d\d{4}3b"),
    "alpn_61_20": (tlslite(alpn_first(b"\x61\x20")), r"t13d\d{4}60"),
    "alpn_30_ab_cd_31": (tlslite(alpn_first(b"\x30\xab\xcd\x31")), r"t13d\d{4}01"),
    "alpn_hash_x": (tlslite(alpn_first(b"#x")), r"t13d\d{4}28"),  # '#'=0x23 not alnum -> hex "2378"
}


FORMS = ("ja4", "ja4_r", "ja4_o", "ja4_ro")
REFS = {"kittens": ("kittens.sh", "/api/all"), "thumbprint": ("thumbprint.me", "/api/v1/probe")}


def run_case(o, name, runner, pattern, may_refuse=False):
    udp = getattr(runner, "udp", False)
    r = (UdpRelay if udp else Relay)(o.connect or o.host, o.port)
    try:
        body = runner(o, r)
    except Exception as e:  # noqa: BLE001
        body = f"<client error {type(e).__name__}: {e}>"
    hellos = r.client_hellos()
    if not hellos:
        return False, f"FAIL {name}: no ClientHello captured ({body[:120]!r})", None
    local = ja4.from_bytes(hellos[0], "q" if udp else "t")
    try:
        j = json.loads(body)
        server = {k: j[k] for k in FORMS if isinstance(j.get(k), str)}
        server_raw = (j.get("tls") or {}).get("raw", {}).get("hex")
    except ValueError:
        server, server_raw = ({"ja4": body.strip()} if body.strip() else {}), None
    lines, ok = [], True
    if not re.fullmatch(r"[tqd][0-9s]{2}[di]\d{4}[0-9a-zA-Z]{2}_[0-9a-f]{12}_[0-9a-f]{12}", server.get("ja4", "")):
        if may_refuse and body.startswith("<client error"):
            return None, f"SKIP {name:28s} local={local['ja4']} server refused the hello: {body[:90]}", None
        ok = False
        server = {"ja4": f"<no ja4 in response: {body[:160]!r}>"}
    else:
        for k, v in server.items():
            if v != local[k]:
                ok = False
                lines.append(f"     {k:6s} local  {local[k]}\n     {k:6s} server {v}")
        others = [ja4.from_bytes(h, "q" if udp else "t")["ja4"] for h in hellos[1:]]
        if server["ja4"] in others:
            lines.append(f"     NOTE: server fingerprinted ClientHello #{others.index(server['ja4']) + 2} (after HRR)")
    if pattern and not re.fullmatch(pattern, local["a"]):
        ok = False
        lines.append(f"     JA4_a {local['a']} does not match expected /{pattern}/")
    if server_raw and server_raw != hellos[0].hex() and all(server_raw != h.hex() for h in hellos):
        lines.append("     NOTE: server raw ClientHello differs from captured one")
    extra = f" (+{len(hellos) - 1} more ClientHello)" if len(hellos) > 1 else ""
    checked = ",".join(k for k in FORMS if k in server)
    head = f"{'PASS' if ok else 'FAIL'} {name:28s} local={local['ja4']} server={server['ja4']} [{checked}]{extra}"
    vector = {"name": name, "server": o.host, "server_confirmed": sorted(server) if ok else [],
              "client_hello_hex": hellos[0].hex(), **{k: local[k] for k in FORMS}}
    return ok, "\n".join([head, *lines]), vector


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", default="kittens,thumbprint", help=f"reference servers, comma list of {list(REFS)}")
    ap.add_argument("--host", help="custom target: Host header / SNI (overrides --ref)")
    ap.add_argument("--connect", help="TCP address to connect to, if different from --host")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--path", default="/")
    ap.add_argument("--case", default="all")
    ap.add_argument("-k", "--insecure", action="store_true", help="skip certificate verification")
    ap.add_argument("--dump", help="write captured ClientHellos + JA4 values of passing cases to this JSON file")
    a = ap.parse_args()
    if a.host:
        targets = [argparse.Namespace(host=a.host, connect=a.connect, port=a.port, path=a.path, insecure=a.insecure)]
    else:
        targets = [argparse.Namespace(host=REFS[n][0], connect=None, port=443, path=REFS[n][1], insecure=a.insecure)
                   for n in a.ref.split(",")]
    failed, skipped, vectors = 0, 0, []
    for o in targets:
        print(f"== {o.host}:{o.port}{o.path}", flush=True)
        for name, (runner, pattern, *flags) in CASES.items():
            if a.case not in ("all", name):
                continue
            ok, text, vector = run_case(o, name, runner, pattern, *flags)
            failed += ok is False
            skipped += ok is None
            print(text, flush=True)
            if ok and vector:
                vectors.append(vector)
    print(f"== {len(vectors)} passed, {failed} failed, {skipped} skipped")
    if a.dump:
        Path(a.dump).write_text(json.dumps(vectors, indent=1) + "\n")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
