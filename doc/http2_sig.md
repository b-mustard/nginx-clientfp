# HTTP/2 client signature (Akamai format): technical specification

Sources:
- Akamai white paper, "Passive Fingerprinting of HTTP/2 Clients" (Shuster, Segal, Fridman, Black Hat Europe 2017): <https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf>.
- Reference implementation `https://kittens.sh/api/http2`. Every rule marked **[verified]** was checked against it on 2026-09-28 with `clientfp-h2-probe` (21/21 synthetic cases pass) and `clientfp-h2-clients` (10/10 real-client cases pass).
- Cross-checks, run the same day (section 4.5). On the fields that real clients send, all three references agree with the spec. Each one departs from it in its own edge cases:
  - `https://tls.browserleaks.com/http2`, the JSON behind `https://browserleaks.com/http2`. It differs on the PRIORITY tuple format, GREASE ids, and frames after HEADERS.
  - `https://thumbprint.me/api/v1/probe`. It differs on the empty-S form, several SETTINGS frames, and the HEADERS priority block.

The signature is a passive fingerprint. It is built from what an HTTP/2 client sends at the start of a connection: the first SETTINGS frame, the first WINDOW_UPDATE frame, the PRIORITY frames, and the pseudo-header order of the first request. The signature describes the client's HTTP/2 implementation, not the user.

---

## 1. Format

```
fingerprint = S "|" WU "|" P "|" PS

S   = [ setting *( ";" setting ) ]          ; can be empty
setting = id ":" value                      ; decimal, unsigned
WU  = increment / "00"                      ; "00" = no WINDOW_UPDATE seen
P   = prio *( "," prio ) / "0"              ; "0"  = no PRIORITY frame seen
prio = stream_id ":" exclusive ":" depends_on ":" weight
PS  = pseudo *( "," pseudo )                ; m / p / a / s, in wire order
```

Example (Firefox 53, from the paper) **[verified]**:

```
1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1|m,p,a,s
```

Hash: `akamai_fingerprint_hash = lowercase_hex( MD5( fingerprint ) )`, 32 characters. **[verified]**

Notes on the paper's text:
- The paper writes the format as `S[;]|WU|P[,]#|PS[,]`. The `#` is a typesetting artifact. Do **not** emit it. None of the paper's examples contain it, and neither does the reference output.
- The paper's first format (section 4) has only 3 fields. Section 4.1 adds `PS`. The reference always emits all **4 fields**, so always emit 4.

---

## 2. Fields

All wire integers are big-endian (network byte order). Frame header = 9 octets: `length(24) type(8) flags(8) R(1)+stream_id(31)`.

### 2.1 `S`: SETTINGS (frame type `0x4`)

Payload = N × 6-octet entries: `id(16) value(32)`.

| Rule | Detail |
|---|---|
| Which frame | The **first SETTINGS frame that has ≥1 parameter**. Skip SETTINGS frames with ACK set (flag `0x1`) and empty SETTINGS frames. Ignore all later SETTINGS frames. **[verified]** (thumbprint.me joins all of them; see 4.5.) |
| Order | Wire order. **Do not sort.** **[verified]** |
| Unknown ids | Keep them, printed as decimal (e.g. GREASE `0x0a0a` → `2570`). **[verified]** |
| Duplicate ids | Keep every occurrence, in wire order (`1:4096;1:65536`). **[verified]** |
| Value | Unsigned 32-bit decimal (`6:4294967295`). **[verified]** |
| Empty | No qualifying SETTINGS frame → `S` is the empty string, so the fingerprint starts with `\|`. **[verified]** (thumbprint.me prints `0`; see 4.5.) |

Setting ids and the names the reference uses:

| id | name | id | name |
|---|---|---|---|
| 1 | HEADER_TABLE_SIZE | 6 | MAX_HEADER_LIST_SIZE |
| 2 | ENABLE_PUSH | 8 | ENABLE_CONNECT_PROTOCOL (RFC 8441) |
| 3 | MAX_CONCURRENT_STREAMS | 9 | NO_RFC7540_PRIORITIES (RFC 9218) |
| 4 | INITIAL_WINDOW_SIZE | other | UNKNOWN |
| 5 | MAX_FRAME_SIZE | | |

### 2.2 `WU`: WINDOW_UPDATE (frame type `0x8`)

Payload = `R(1) increment(31)`.

| Rule | Detail |
|---|---|
| Which frame | The **first WINDOW_UPDATE with stream_id == 0** (connection level). Ignore later ones. The value is not a sum and not the last one. **[verified]** |
| Stream-level WU | Ignore WINDOW_UPDATE frames with stream_id ≠ 0 completely. **[verified]** |
| Value | `increment & 0x7FFFFFFF`, as decimal. **[verified]** |
| Absent | `00` (two zeros, not `0`). **[verified]** |

Tip: `increment + 65535` is often a round number that identifies the client. For example, curl sends `1048510465 + 65535 = 1000 × 2^20`.

### 2.3 `P`: PRIORITY frames (frame type `0x2`)

Payload = 5 octets: `E(1) depends_on(31) weight(8)`.

| Rule | Detail |
|---|---|
| Which frames | **Every** PRIORITY frame, in wire order. They can come before or after the WINDOW_UPDATE. **[verified]** |
| Tuple | `stream_id:E:depends_on:weight` |
| `stream_id` | From the frame header (31 bits). These are usually idle streams that are never opened (Firefox: 3, 5, 7, 9, 11). |
| `E` | Exclusive bit: `1` or `0`. **[verified]** |
| `depends_on` | `& 0x7FFFFFFF`, as decimal. |
| `weight` | **Wire octet + 1** (range 1–256). The wire value 200 is printed as `201`, and 255 as `256`. **[verified]** |
| HEADERS priority | Do **not** include the priority block of a HEADERS frame (flag `0x20`). Chrome and Safari send one, but it does not go into `P`. **[verified]** (thumbprint.me adds it; see 4.5.) |
| Absent | `0`. |

### 2.4 `PS`: pseudo-header order (first request)

Take the order in which the request pseudo-headers occur in the **first HEADERS frame's header block**, after HPACK decoding. The block includes its CONTINUATION frames. Use wire order, no matter if the field is indexed, literal, or Huffman-coded.

| Pseudo-header | Letter |
|---|---|
| `:method` | `m` |
| `:path` | `p` |
| `:authority` | `a` |
| `:scheme` | `s` |

- Join the letters with `,`. If a pseudo-header is missing, leave its letter out. For example, `:authority` replaced by a `Host` header gives `m,s,p`. **[verified]**
- The paper defines only these 4 letters. nginx rejects other pseudo-headers (`:protocol`, unknown ones) with 400, so no other letter can occur.
- Regular headers are not part of the signature.

Known orders: Chrome `m,a,s,p` · Firefox `m,p,a,s` · Safari `m,s,p,a` · curl/nghttp2 (current) `m,s,a,p` · httpx/niquests `m,a,s,p` · Go `a,m,p,s` (2017) · Jetty `s,m,a,p`. For low-level libraries (python-h2, Node `http2`), the caller sets the order. Node sends the caller's keys first, then adds any missing ones, so `request({':path'})` gives `p,m,a,s`.

---

## 3. Capture window and connection state

The signature is a property of the **connection**. Capture it once per HTTP/2 connection and share it with all requests on that connection.

**Recommended rule for nginx: freeze at the first HEADERS frame.** Start after the 24-octet client preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`). Record SETTINGS, WINDOW_UPDATE, and PRIORITY frames by the rules above. Take `PS` from the first HEADERS frame, then freeze all 4 fields. Ignore frames that arrive after that frame.

This rule gives the same result as the reference for the **first request** of every connection:
- A PRIORITY or SETTINGS frame sent after the first HEADERS does not appear in the first response. **[verified]**

For later requests on the same connection, the references do not agree **[verified]**. kittens keeps parsing and takes a snapshot for each request. thumbprint.me freezes S, WU and P, but takes PS from each request. browserleaks allows only one request per connection.

| Field | kittens, 2nd+ request | thumbprint.me, 2nd+ request | Recommended nginx |
|---|---|---|---|
| `S` | first non-empty SETTINGS seen so far, even if it came after HEADERS #1 | frozen at HEADERS #1 | frozen at HEADERS #1 |
| `WU` | first connection-level WU seen so far, even if it came after HEADERS #1 | frozen | frozen |
| `P` | PRIORITY frames seen so far, so the list keeps growing | frozen | frozen |
| `PS` | from HEADERS #1 | **from the current request** | from HEADERS #1 |

The frozen form is deterministic and matches the paper's intent ("right after the connection phase"). For S, WU and P it matches thumbprint.me, and for PS it matches kittens. For parity with kittens, keep appending `P` after HEADERS #1, and keep filling `S` and `WU` while they are empty. The differences show only in two situations: a client sends SETTINGS, WU or PRIORITY frames after its first request (browsers that re-prioritize can do this), or a client changes its pseudo-header order between requests (browsers don't; low-level libraries can).

The reference also reports `total_frames`: the number of frames received after the preface up to the snapshot, including the HEADERS frame (for example curl = 3: SETTINGS, WU, HEADERS). It is diagnostic only and not part of the fingerprint.

---

## 4. Test vectors

### 4.1 Synthetic frame sequences (`clientfp-h2-probe`, `tools/clientfp/probe/h2_probe.py`)

The probe sends exact frame sequences: these cases and 16 more edge cases, one for each rule in section 2. All values below match the reference fingerprint and MD5 hash.

| Case | Frames sent (after preface) | Fingerprint | MD5 |
|---|---|---|---|
| Firefox 53 (paper) | S{1:65536,4:131072,5:16384} WU 12517377, PRIO×5 (wire weights 200,100,0,0,0), H(mpas) | `1:65536;4:131072;5:16384\|12517377\|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1\|m,p,a,s` | `b151efdd3ac38eb07621c822c1852a27` |
| Chrome 58 (paper) | S{1:65536,3:1000,4:6291456} WU 15663105, H(masp) | `1:65536;3:1000;4:6291456\|15663105\|0\|m,a,s,p` | `9a7d2493dea05d3d5d1c2a797b83e8fd` |
| no WINDOW_UPDATE | S{3:100,4:65535} H(mpsa) | `3:100;4:65535\|00\|0\|m,p,s,a` | `821c4a0a02c6f80bb474340772269027` |
| empty SETTINGS | S{} WU 1000, H(mpas) | `\|1000\|0\|m,p,a,s` | `b90ba10e3fa878e6c299ce7811dbe44c` |
| exclusive, max weight | S{1:65536} WU 1000, PRIO(3, E=1, dep 0, wire 255), H(masp) | `1:65536\|1000\|3:1:0:256\|m,a,s,p` | `535bd3c91efe1d901175a6437636a79a` |

### 4.2 Real clients in this environment (`clientfp-h2-clients`, `tools/clientfp/probe/h2_clients.py`)

All values were captured from the reference on 2026-09-28. The 4 hashes that the reference reported matched the local MD5 values. Every HTTP/2 client also gave the same fingerprint over cleartext h2c (prior knowledge, checked with a local test server). A client's settings do not depend on TLS.

| Case | Version | Fingerprint | MD5 | What it shows |
|---|---|---|---|---|
| `curl` | curl 8.5.0, nghttp2 1.59.0 | `3:100;4:10485760;2:0\|1048510465\|0\|m,s,a,p` | `64a832f547be33249bf4d33e8a46c5dc` | Settings out of numeric order; WU = 1000 MiB − 65535 |
| `httpx` (sync and async) | httpx 0.28.1, httpcore 1.0.9, h2 4.4.1 | `1:4096;2:0;4:65535;5:16384;3:100;6:65536\|16777216\|0\|m,a,s,p` | `29e6a0e9b360185223ec1278a845fdb1` | 6 settings; WU = 2^24 |
| `niquests` | niquests 3.21.2, urllib3-future 2.25.900, jh2 5.0.15 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | `52d84b11737d980aef856699f885ca86` | Copies Chrome's SETTINGS and WU. A spoofing test: only the TLS fingerprint (JA4) can tell it apart from Chrome |
| `h2_bare` | h2 4.4.1, default `H2Configuration` | `1:4096;2:1;4:65535;5:16384;8:0;3:100;6:65536\|00\|0\|m,p,a,s` | `f40d4e124a8d0a65b575059e767f12ae` | Setting id 8 (RFC 8441); no WU. httpcore changes these defaults, which is why httpx differs |
| `node_http2` | Node 24.19.0, nghttp2 1.69.0 | `\|00\|0\|p,m,a,s` | `38e36840395e07ae27bae1632ddc8b92` | **Empty SETTINGS and no WU**, so both S and WU take their empty values. Request made the way Node's docs show it: `request({':path'})` |
| `node_http2_method_first` | same | `\|00\|0\|m,p,a,s` | `a830180579edb2d225744f09afb60f3d` | In Node, PS follows the key order of the caller's header object |
| `node_http2_settings` | same, `settings:{enablePush:false, initialWindowSize:6291456}` | `2:0;4:6291456\|00\|0\|p,m,a,s` | `a623bc3f012e676e027236d2cff1f09f` | Node sends only settings that differ from the defaults |
| `node_fetch_h1` | Node 24.19.0 (undici) | none | | Negative case: `fetch` uses HTTP/1.1 by default. The reference returns `connection is not HTTP/2` |
| `wget_h1` | GNU Wget 1.21.4 | none | | Negative case: HTTP/1.1 only |

For the negative cases, nginx must not produce a fingerprint: the variable is empty. The reference answers HTTP/1.1 requests with `404` and the body `connection is not HTTP/2`. The runner accepts any HTTP status and any body that is not a fingerprint, but a transport failure (connection or TLS error) counts as FAIL.

Not installed here, so not covered: Go `net/http`, nghttp/h2load, Java, browsers. Go and browser fingerprints change between versions, so capture new vectors from the reference rather than trusting the 2017 values below.

### 4.3 Historical vectors from the paper (2017, not re-verified)

Edge 14 `3:1024;4:10485760|10420225|0`; OkHttp 3.6 `4:16777216|16711681|0`; Firefox 53 Android `1:4096;4:32768;5:16384|12517377|<ff-prio>`; Go 2.0 `2:0;4:4194304;6:10485760|1073741824|0`; curl 7.54 `3:100;4:1073741824;2:0|1073676289|0`; nghttp2 1.22 `3:100;4:65535|00|<ff-prio>`. These are in the paper's 3-field form. Append `|PS` to compare with 4-field output.

### 4.4 Running the tests

Both tools accept an endpoint that returns JSON with `akamai_fingerprint`, or the bare fingerprint string. Both exit with a non-zero code on failure. `--insecure` turns off the certificate check, for a local self-signed certificate.

```sh
# synthetic frame sequences
.venv/bin/clientfp-h2-probe                                                      # reference
.venv/bin/clientfp-h2-probe --host 127.0.0.1 --port 8443 --path /fp --insecure    # our nginx

# real clients (needs curl, node, wget and .venv/bin/pip install -e '.[dev]')
.venv/bin/clientfp-h2-clients                                                    # reference
.venv/bin/clientfp-h2-clients --url https://127.0.0.1:8443/fp --insecure         # our nginx, TLS + ALPN
.venv/bin/clientfp-h2-clients --url http://127.0.0.1:8080/fp                     # our nginx, h2c prior knowledge
.venv/bin/clientfp-h2-clients --client node_http2                                # one case, prints the version

# cross-check references (expected differences are listed in 4.5)
.venv/bin/clientfp-h2-probe --host tls.browserleaks.com --path /http2
.venv/bin/clientfp-h2-probe --host thumbprint.me --path /api/v1/probe
.venv/bin/clientfp-h2-clients --url https://tls.browserleaks.com/http2
.venv/bin/clientfp-h2-clients --url https://thumbprint.me/api/v1/probe

# offline: the reference calculator on a captured client stream (preface + frames, hex)
.venv/bin/python -m clientfp.fp.h2 <hex>
```

`clientfp-h2-clients` reports `CHANGED` instead of `FAIL` when the fingerprint differs and the installed client version also differs from the recorded one. In that case, capture a new value from the reference before you look for a server bug.

Three probe cases test how tolerant the server is, not a fingerprint rule: `dup_setting`, `stream_wu_before_conn_wu` and `stream_wu_only`. RFC 9113 allows a server to reject them, and browserleaks does, with `GOAWAY PROTOCOL_ERROR`. If our nginx rejects them too, that is acceptable. Only a wrong fingerprint on a request that succeeded is a bug.

### 4.5 Cross-checks against other implementations

#### 4.5.1 Comparison matrix

Every cell was observed with `clientfp-h2-probe`, `clientfp-h2-clients`, or two requests on one connection, on 2026-09-28. **Bold** marks a departure from the spec.

| Rule | Paper | kittens.sh | browserleaks | thumbprint.me | **Spec** |
|---|---|---|---|---|---|
| S: which SETTINGS frame | "the SETTINGS frame" | first non-empty | first non-empty | **all SETTINGS frames before HEADERS #1, joined** | first non-empty |
| S: no parameters | not defined | empty | empty | **`0`** | empty |
| S: unknown or GREASE id | not defined | `2570:12345` | **`GREASE`** | `2570:12345` | `id:value`, decimal |
| S: duplicate id | not defined | both kept | PROTOCOL_ERROR | both kept | both kept (tolerance case) |
| WU | "the WINDOW_UPDATE" | first on stream 0 | first on stream 0 | first on stream 0 | first on stream 0 |
| WU absent | `00` | `00` | `00` | `00` | `00` |
| P tuple | `stream:E:dep:weight`, weight 1–256 | same | **`stream:weight`, 256 → 0** | same | `stream:E:dep:weight` |
| P includes the HEADERS priority block | no (PRIORITY frames only) | no | no | **yes (`1:1:0:256`)** | no |
| P absent | `0` | `0` | `0` | `0` | `0` |
| Frames after HEADERS #1 (first response) | not defined | ignored | **garbled output** | ignored | ignored |
| 2nd+ request: S / WU / P | not defined | **keep accumulating** | n/a (one request per connection) | frozen | frozen |
| 2nd+ request: PS | not defined | from request 1 | n/a | **per request** | from request 1 |
| Hash | not defined | `akamai_fingerprint_hash`, MD5 | `akamai_hash`, MD5 | none | MD5 |
| HTTP/1.1 request | n/a | `404` + text | `200`, `akamai_text: ""` | `200`, `h2: null` | empty variable |
| Probe cases (21) | | 21 pass | 12 pass | 17 pass | |
| Real clients (10) | | 10 pass | 10 pass (2 by replay) | 8 pass | |

How the spec was decided: on every rule where the references disagree, at least two of the three agree with the spec, and the paper supports it or says nothing. For every client seen here in practice, all references give the same string, with one exception: Node's `http2` client. It sends an empty SETTINGS frame, so thumbprint.me shows `0|00|0|p,m,a,s` where the others show `|00|0|p,m,a,s`.

Possible real-world impact, not verified (no browser available here): Chrome and Safari set the priority flag on their HEADERS frames. So thumbprint.me probably shows a non-`0` P for them (for example `1:1:0:256`), where kittens and browserleaks show `0`.

#### 4.5.2 browserleaks.com

`https://browserleaks.com/http2` gets its values through JavaScript from `https://tls.browserleaks.com/http2`. That endpoint returns JSON with `akamai_text` (the fingerprint), `akamai_hash` (MD5) and `http2`, the list of received frames. Both tools read `akamai_text`. The server header is `server: nginx`. It sends `GOAWAY NO_ERROR` before its first response, which looks like `keepalive_requests 1`.

curl result, identical to kittens and to this spec:

```
akamai_text: 3:100;4:10485760;2:0|1048510465|0|m,s,a,p
akamai_hash: 64a832f547be33249bf4d33e8a46c5dc
```

**Where it agrees:**
- **Real clients:** 10/10 match.
  - 8 match directly with `clientfp-h2-clients --url https://tls.browserleaks.com/http2`.
  - `httpx` and `h2_bare` fail live because python-h2 aborts on the early GOAWAY (`ConnectionTerminated error_code:0`). I recorded the exact bytes each one sends (after TLS) and replayed them through `clientfp.probe.h2_probe.run()`. Both gave the expected fingerprint and hash. As a control, the same replay on kittens gives the same result as the live request.
- **HTTP/1.1:** it returns `200` with an empty `akamai_text`, where kittens returns `404`. Either way, there is no fingerprint.
- **Synthetic cases:** 12/21 match exactly, including every SETTINGS and WINDOW_UPDATE rule:
  - wire order, unknown ids 8 and 9, u32 values
  - the empty-S form (`|1000|0|…`)
  - the first non-empty SETTINGS wins, even after an empty frame or an ACK
  - the first connection-level WU wins, the reserved bit is masked, `00` when absent
  - the HEADERS priority flag is ignored, and a missing `:authority` is left out of PS

**Where it differs:**

| Probe case | browserleaks `akamai_text` | Cause | Spec decision |
|---|---|---|---|
| `paper_firefox` | `…\|12517377\|3:201,5:101,7:1,9:1,11:1\|m,p,a,s` | **The P tuple is `stream_id:weight` only.** Exclusive bit and dependency are dropped. | Keep the paper's 4 fields `stream:E:dep:weight`. kittens and the paper's own example use them, and a 2-field form loses Firefox's dependency tree. |
| `prio_before_wu` | `…\|3:201\|…` | same | same |
| `prio_exclusive` | `…\|3:0\|…` (JSON: `"weight": 0, "exclusive": 1`) | The weight (wire + 1) is stored in 8 bits, so 256 wraps to 0 (a bug) | Weight is 1–256. Store it in ≥ 16 bits. |
| `unknown_settings` | `1:65536;8:1;9:1;GREASE\|…` | Setting ids matching the GREASE pattern `0x?a?a` are printed as the word `GREASE`, without a value | Keep `id:value` in decimal (kittens form). No browser sends GREASE settings by default today. |
| `settings_after_headers` | `m,p,a,s1:65536\|1000\|0` | Frames that arrive **after** the first HEADERS in the same read are added to the text in arrival order. The format breaks (a bug). | Freeze at the first HEADERS (section 3). Our nginx must not repeat this bug. |
| `prio_after_headers` | `1:65536\|1000\|m,p,a,s3:11` | same | same |
| `dup_setting` | `GOAWAY PROTOCOL_ERROR` | Strict server | Tolerance case, see 4.4 |
| `stream_wu_before_conn_wu`, `stream_wu_only` | `GOAWAY PROTOCOL_ERROR` | Strict server (WINDOW_UPDATE on an idle stream) | Tolerance case, see 4.4 |

#### 4.5.3 thumbprint.me

`https://thumbprint.me/api/v1/probe` returns JSON (`server: nginx`, `alt-svc: h3`). The HTTP/2 fingerprint is in the `h2` field, and there is **no hash field**. The same response also has `alpn`, `ja4`, `ja4_r`, `ja4_o`, `ja4_ro`, `ja4h`, `ja4h_r`, `tcp_ja4t` and `tcp_p0f`, which makes it a useful reference for the JA4 step. Both tools read `h2`. It answers HTTP/1.1 requests with `200` and `"h2": null`.

curl result, identical to the spec:

```
h2: 3:100;4:10485760;2:0|1048510465|0|m,s,a,p
```

**Where it agrees:**
- **Real clients:** 8/10 match directly, including httpx and h2_bare. Unlike browserleaks, it sends no early GOAWAY.
- **Synthetic cases:** 17/21 match, including:
  - the 4-field P tuple with weight 256 (`paper_firefox`, `prio_exclusive`)
  - GREASE ids in decimal
  - duplicate ids kept, and stream-level WU ignored (tolerant, like kittens)
  - frames after HEADERS #1 ignored

**Where it differs:**

| Case | thumbprint.me `h2` | Cause | Spec decision |
|---|---|---|---|
| `empty_settings`, `settings_after_headers` | `0\|1000\|0\|m,p,a,s` | An empty S is printed as `0` | Empty, as kittens and browserleaks do. The paper defines `00` and `0` fallbacks only for WU and P. |
| `node_http2`, `node_http2_method_first` (real clients) | `0\|00\|0\|p,m,a,s` | same | same |
| `two_settings_frames` | `1:65536;4:131072\|1000\|0\|m,p,a,s` | The parameters of **every** SETTINGS frame before HEADERS #1 are joined | Take the first non-empty frame only, as kittens and browserleaks do. |
| `headers_prio_flag` | `1:65536\|1000\|1:1:0:256\|m,a,s,p` | **The priority block inside HEADERS (flag `0x20`) is added to P** | Leave it out. The paper builds P from PRIORITY frames only, and so do kittens and browserleaks. |

---

## 5. Extraction in nginx + OpenSSL

### 5.1 What to capture per connection

```c
/* suggested: hang off ngx_http_v2_connection_t (h2c), allocate from c->pool */
typedef struct {
    uint16_t   settings_id[N_SET];    uint32_t settings_val[N_SET];  ngx_uint_t nsettings;
    unsigned   settings_done:1;       /* first non-empty SETTINGS already taken   */
    unsigned   wu_seen:1;             uint32_t window_update;         /* & 0x7fffffff */
    struct { uint32_t sid, dep; uint8_t excl; uint16_t weight; } prio[N_PRIO];  ngx_uint_t nprio;
    u_char     ps[4];                 ngx_uint_t nps;                 /* 'm','p','a','s' */
    unsigned   frozen:1;              /* set when the first HEADERS block is done */
} ngx_http_v2_fp_t;
```

Bound the arrays. For example, `N_SET = 32` and `N_PRIO = 32` is enough for all known clients: Firefox sends 5–6 PRIORITY frames, and browsers send ≤ 10 settings. Choose one overflow behavior and document it: stop recording, or append a marker. A hostile client can send about 2,700 settings in one 16 KB frame.

Build the string (and the MD5 hash) lazily when a variable is read. Cache it on the connection. Suggested variables: `$http2_fingerprint`, `$http2_fingerprint_hash`. Both are empty or not-found for non-HTTP/2 requests.

### 5.2 Hook points in `src/http/v2/ngx_http_v2.c`

These names come from upstream nginx. nginx source is **not yet in this repo**, so check each name against the tree you add.

| Field | nginx function | Capture rule |
|---|---|---|
| `S` | `ngx_http_v2_state_settings`, then `ngx_http_v2_state_settings_params` | In `state_settings`, skip frames with `NGX_HTTP_V2_ACK_FLAG` and zero-length frames. In the params loop, record `(id, value)` **before** the `switch` that validates known ids and ignores unknown ones. nginx returns a connection error on a bad INITIAL_WINDOW_SIZE or MAX_FRAME_SIZE, and it silently drops unknown ids. Set `settings_done` when that frame ends. |
| `WU` | `ngx_http_v2_state_window_update` | Record only if `h2c->state.sid == 0`, `!wu_seen`, and `!frozen`. |
| `P` | `ngx_http_v2_state_priority` | Record `(h2c->state.sid, excl, depend, weight)`. Check whether nginx already adds 1 to the weight (`ngx_http_v2_parse_weight` or similar) so that you do not add it twice. Record before the stream lookup and the dependency checks. Firefox's streams are idle and have no node yet. |
| `PS` | `ngx_http_v2_state_header_block` / `ngx_http_v2_state_process_header` → `ngx_http_v2_pseudo_header` | Only for the first HEADERS block (`!frozen`). Append a letter for each `:method`/`:path`/`:authority`/`:scheme` in decode order. Record at the point where the name is known, before nginx strips the leading `:`. |
| freeze | end of the first header block (`END_HEADERS`, e.g. `ngx_http_v2_state_header_complete` / `ngx_http_v2_run_request`) | Set `frozen = 1`. After this, all hooks do nothing. Do **not** read the priority block from `ngx_http_v2_state_headers` (flag `0x20`). |

Pitfalls:
- **Partial frames.** nginx parses incrementally and resumes through `ngx_http_v2_state_save` / `h2c->state.handler`. Record each SETTINGS entry only after all 6 octets are present, so a resumed parse does not record it twice.
- **HPACK state.** Header fields that come from the dynamic table still go through `process_header`, in order. Because only the first request counts, table reuse across requests does not matter.
- **Rejected first stream.** nginx can refuse a stream (concurrency limit, a GOAWAY in flight) and skip `process_header` for it. A refused first stream is rare. The simplest rule: freeze on the first HEADERS block that nginx processes.
- **Early GOAWAY breaks python-h2 clients.** When a connection reaches `keepalive_requests`, nginx sends `GOAWAY NO_ERROR` before the response (browserleaks does this on the first request). httpx and python-h2 then drop the response. Keep the default `keepalive_requests` in the test nginx config, or `clientfp-h2-clients` will report false FAILs.
- **Cleartext h2c** (prior knowledge, `listen … http2` without TLS) uses the same code path, so the same capture applies.
- **HTTP/3 / QUIC** is out of scope. The frame model is different.

### 5.3 OpenSSL

This signature needs no OpenSSL hooks. All inputs are HTTP/2 frames after TLS decryption. The only TLS dependency is ALPN: HTTP/2 over TLS exists only when the client offers `h2` and nginx selects it (nginx's `SSL_CTX_set_alpn_select_cb` callback, `SSL_get0_alpn_selected`). OpenSSL hooks (ClientHello capture) belong to the JA4 step (`https://kittens.sh/api/ja4`, <https://github.com/FoxIO-LLC/ja4>), not here.

---

## 6. Reference JSON shape (for optional parity output)

`GET https://kittens.sh/api/http2` returns:

```jsonc
{
  "akamai_fingerprint": "3:100;4:10485760;2:0|1048510465|0|m,s,a,p",
  "akamai_fingerprint_hash": "64a832f547be33249bf4d33e8a46c5dc",
  "settings": [{"id": 3, "name": "MAX_CONCURRENT_STREAMS", "value": 100}, ...],
  "window_update": 1048510465,            // null when absent
  "priorities": [{"stream_id": 3, "exclusive": false, "depends_on": 0, "weight": 201}, ...],
  "pseudo_header_order": ["m", "s", "a", "p"],
  "total_frames": 3,
  "headers": [[":method", "GET"], [":scheme", "https"], ...]   // this request, wire order
}
```
