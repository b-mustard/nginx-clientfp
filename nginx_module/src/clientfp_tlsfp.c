/*
 * nDPI TLS client fingerprint (TLSFP). See clientfp_tlsfp.h and doc/tlsfp_sig.md.
 *
 * Rules, as in tools/clientfp/fp/tlsfp.py (spec section, decision):
 *
 * - Framing (RFC 8446 §3): every length fits its enclosing length and fills it exactly. Broken framing: no
 *   fingerprint. A malformed extension that one field decodes empties that field only (§9): supported_versions or
 *   ALPN -> a, signature_algorithms -> c, supported_groups -> d. The first occurrence of each is decoded.
 * - GREASE (§6.2, d027): RFC 8701 values, removed from cipher suites, extension types and groups, not from
 *   signature algorithms.
 * - Ephemeral extensions (§6.3, Appendix B, registry v1): 0015 0023 0029 002a 002c 002d.
 * - a (§6.4): proto, version (no "s2"), d/i, min(ciphers,99), min(sanitized extensions,99), ALPN first+last byte
 *   lower-cased, hex nibbles when either is not alphanumeric (d025), "00" when absent/empty.
 * - b (§6.5): sha256 of sorted ciphers. c (§6.6): sha256 of sorted sanitized extensions without 0000/0010, "_",
 *   signature algorithms in wire order ("_" always present). d (§6.7): sha256 of sorted groups; "000000000000"
 *   when absent or GREASE-only (d023). No list is deduplicated (§7.4) or capped (§7.5).
 */

#include <stdlib.h>
#include <string.h>


#include "clientfp_tlsfp.h"
#include "clientfp_sha256.h"


#define EXT_SNI                 0x0000
#define EXT_SUPPORTED_GROUPS    0x000a
#define EXT_SIGALGS             0x000d
#define EXT_ALPN                0x0010
#define EXT_SUPPORTED_VERSIONS  0x002b

#define FIELD_OK       0
#define FIELD_ABSENT   1
#define FIELD_BAD      2


typedef struct {
    const uint8_t  *p;
    const uint8_t  *end;
} rd_t;


static int
rd_u8(rd_t *r, unsigned *v)
{
    if (r->end - r->p < 1) {
        return -1;
    }

    *v = r->p[0];
    r->p += 1;
    return 0;
}


static int
rd_u16(rd_t *r, unsigned *v)
{
    if (r->end - r->p < 2) {
        return -1;
    }

    *v = ((unsigned) r->p[0] << 8) | r->p[1];
    r->p += 2;
    return 0;
}


static int
rd_u24(rd_t *r, size_t *v)
{
    if (r->end - r->p < 3) {
        return -1;
    }

    *v = ((size_t) r->p[0] << 16) | ((size_t) r->p[1] << 8) | r->p[2];
    r->p += 3;
    return 0;
}


static int
rd_sub(rd_t *r, size_t n, rd_t *sub)
{
    if ((size_t) (r->end - r->p) < n) {
        return -1;
    }

    sub->p = r->p;
    sub->end = r->p + n;
    r->p += n;
    return 0;
}


static size_t
rd_left(const rd_t *r)
{
    return (size_t) (r->end - r->p);
}


static uint16_t
u16at(const uint8_t *p)
{
    return (uint16_t) (((unsigned) p[0] << 8) | p[1]);
}


static int
is_grease(unsigned v)
{
    return (v >> 8) == (v & 0xff) && (v & 0x0f) == 0x0a;
}


static int
is_ephemeral(unsigned t)
{
    switch (t) {
    case 0x0015:    /* padding                */
    case 0x0023:    /* session_ticket         */
    case 0x0029:    /* pre_shared_key         */
    case 0x002a:    /* early_data             */
    case 0x002c:    /* cookie                 */
    case 0x002d:    /* psk_key_exchange_modes */
        return 1;
    }

    return 0;
}


static int
is_alnum(unsigned c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}


static unsigned
lower(unsigned c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}


static const char  hexdig[] = "0123456789abcdef";


/* u16 list with a u16 length that exactly fills the extension data (signature_algorithms, supported_groups) */
static int
u16_vector(rd_t data, rd_t *list)
{
    unsigned  n;
    rd_t      sub;

    if (rd_u16(&data, &n) != 0 || rd_sub(&data, n, &sub) != 0 || rd_left(&data) != 0 || n % 2) {
        return -1;
    }

    *list = sub;            /* only on success: callers size buffers from a valid list */
    return 0;
}


/* version characters (§6.4); -1 if supported_versions is malformed */
static int
version_chars(unsigned legacy, const rd_t *sv, char out[2])
{
    unsigned  n, v, best;
    rd_t      data, list;

    best = legacy;

    if (sv != NULL) {
        data = *sv;

        if (rd_u8(&data, &n) != 0 || rd_sub(&data, n, &list) != 0 || rd_left(&data) != 0 || n % 2) {
            return -1;
        }

        n = 0;

        while (rd_left(&list)) {
            (void) rd_u16(&list, &v);

            if (!is_grease(v) && (n == 0 || v > best)) {
                best = v;
                n = 1;
            }
        }
    }

    switch (best) {
    case 0x0304: memcpy(out, "13", 2); break;
    case 0x0303: memcpy(out, "12", 2); break;
    case 0x0302: memcpy(out, "11", 2); break;
    case 0x0301: memcpy(out, "10", 2); break;
    case 0x0300: memcpy(out, "s3", 2); break;
    case 0xfeff: memcpy(out, "d1", 2); break;
    case 0xfefd: memcpy(out, "d2", 2); break;
    case 0xfefc: memcpy(out, "d3", 2); break;
    default:     memcpy(out, "00", 2); break;
    }

    return 0;
}


/* ALPN characters (§6.4, d025); -1 if the extension is malformed */
static int
alpn_chars(const rd_t *alpn, char out[2])
{
    unsigned  n, name_len, first_len, f, l;
    rd_t      data, list, name, first;

    out[0] = '0';
    out[1] = '0';

    if (alpn == NULL) {
        return 0;
    }

    data = *alpn;

    if (rd_u16(&data, &n) != 0 || rd_sub(&data, n, &list) != 0 || rd_left(&data) != 0) {
        return -1;
    }

    first.p = NULL;
    first_len = 0;

    while (rd_left(&list)) {
        if (rd_u8(&list, &name_len) != 0 || rd_sub(&list, name_len, &name) != 0) {
            return -1;
        }

        if (first.p == NULL) {
            first = name;
            first_len = name_len;
        }
    }

    if (first.p == NULL || first_len == 0) {
        return 0;
    }

    f = first.p[0];
    l = first.p[first_len - 1];

    if (is_alnum(f) && is_alnum(l)) {
        out[0] = (char) lower(f);
        out[1] = (char) lower(l);

    } else {
        out[0] = hexdig[f >> 4];
        out[1] = hexdig[l & 0x0f];
    }

    return 0;
}


/* ------------------------------------------------------------------------------------- hashing */

typedef struct {
    clientfp_sha256_t  sha;
    size_t             n;          /* items written, for the "," separator */
} hash_t;


static void
hash_put(hash_t *h, const char *p, size_t n)
{
    clientfp_sha256_update(&h->sha, p, n);
}


static void
hash_u16(hash_t *h, unsigned v)
{
    char  s[5];

    s[0] = ',';
    s[1] = hexdig[(v >> 12) & 0x0f];
    s[2] = hexdig[(v >> 8) & 0x0f];
    s[3] = hexdig[(v >> 4) & 0x0f];
    s[4] = hexdig[v & 0x0f];

    if (h->n++ == 0) {
        hash_put(h, s + 1, 4);

    } else {
        hash_put(h, s, 5);
    }
}


static void
hash_begin(hash_t *h)
{
    clientfp_sha256_init(&h->sha);
    h->n = 0;
}


/* finish and write the first 12 hex digits */
static void
hash_end(hash_t *h, uint8_t *out)
{
    unsigned  i;
    uint8_t   md[CLIENTFP_SHA256_LEN];

    clientfp_sha256_final(&h->sha, md);

    for (i = 0; i < 6; i++) {
        out[2 * i] = (uint8_t) hexdig[md[i] >> 4];
        out[2 * i + 1] = (uint8_t) hexdig[md[i] & 0x0f];
    }
}


static int
cmp_u16(const void *a, const void *b)
{
    return (int) *(const uint16_t *) a - (int) *(const uint16_t *) b;
}


/* ------------------------------------------------------------------------------------- compute */

int
clientfp_tlsfp_compute(const uint8_t *msg, size_t len, char proto, uint8_t *out, size_t *out_len,
    clientfp_tlsfp_alloc_pt alloc, clientfp_tlsfp_free_pt release, void *ctx)
{
    int          sni, a_ok, c_state, d_state;
    char         ver[2], alpn[2];
    size_t       body_len, n_c, n_s, n_h, n_g, i, k, o, total;
    unsigned     legacy, n, t, v, ext_len;
    uint16_t    *buf, *ciphers, *exts, *groups;
    rd_t         r, body, sess, cs, comp, block, ext, sig_list, grp_list;
    rd_t         alpn_data, sv_data, sig_data, grp_data;
    rd_t        *alpn_p, *sv_p, *sig_p, *grp_p;
    hash_t       h;

    *out_len = 0;

    if (proto != 't' && proto != 'q' && proto != 'd') {
        return CLIENTFP_TLSFP_EMALFORMED;
    }

    /* ---- framing: handshake header, body, extensions; exact fit everywhere */

    r.p = msg;
    r.end = msg + len;

    if (rd_u8(&r, &t) != 0 || t != 0x01 || rd_u24(&r, &body_len) != 0 || body_len != rd_left(&r)) {
        return CLIENTFP_TLSFP_EMALFORMED;
    }

    body = r;

    if (rd_u16(&body, &legacy) != 0 || rd_sub(&body, 32, &sess) != 0
        || rd_u8(&body, &n) != 0 || rd_sub(&body, n, &sess) != 0
        || rd_u16(&body, &n) != 0 || rd_sub(&body, n, &cs) != 0 || n % 2
        || rd_u8(&body, &n) != 0 || rd_sub(&body, n, &comp) != 0)
    {
        return CLIENTFP_TLSFP_EMALFORMED;
    }

    block.p = block.end = body.p;

    if (rd_left(&body)) {
        if (rd_u16(&body, &n) != 0 || rd_sub(&body, n, &block) != 0 || rd_left(&body) != 0) {
            return CLIENTFP_TLSFP_EMALFORMED;
        }
    }

    /* ---- first pass: counts, first occurrences of the decoded extensions */

    n_c = 0;

    for (i = 0; i < rd_left(&cs); i += 2) {
        n_c += !is_grease(u16at(cs.p + i));
    }

    sni = 0;
    n_s = 0;            /* sanitized extensions, SNI and ALPN included: the a count */
    n_h = 0;            /* sanitized extensions without SNI and ALPN: the c list    */
    alpn_p = sv_p = sig_p = grp_p = NULL;

    r = block;

    while (rd_left(&r)) {
        if (rd_u16(&r, &t) != 0 || rd_u16(&r, &ext_len) != 0 || rd_sub(&r, ext_len, &ext) != 0) {
            return CLIENTFP_TLSFP_EMALFORMED;
        }

        if (t == EXT_SNI) {
            sni = 1;

        } else if (t == EXT_ALPN && alpn_p == NULL) {
            alpn_data = ext;
            alpn_p = &alpn_data;

        } else if (t == EXT_SUPPORTED_VERSIONS && sv_p == NULL) {
            sv_data = ext;
            sv_p = &sv_data;

        } else if (t == EXT_SIGALGS && sig_p == NULL) {
            sig_data = ext;
            sig_p = &sig_data;

        } else if (t == EXT_SUPPORTED_GROUPS && grp_p == NULL) {
            grp_data = ext;
            grp_p = &grp_data;
        }

        if (is_grease(t) || is_ephemeral(t)) {
            continue;
        }

        n_s++;
        n_h += (t != EXT_SNI && t != EXT_ALPN);
    }

    /* ---- per-field decoding (§9: a malformed extension empties its field only) */

    a_ok = version_chars(legacy, sv_p, ver) == 0 && alpn_chars(alpn_p, alpn) == 0;

    c_state = FIELD_ABSENT;
    sig_list.p = sig_list.end = NULL;

    if (sig_p != NULL) {
        c_state = (u16_vector(*sig_p, &sig_list) == 0) ? FIELD_OK : FIELD_BAD;
    }

    d_state = FIELD_ABSENT;
    n_g = 0;
    grp_list.p = grp_list.end = NULL;

    if (grp_p != NULL) {
        if (u16_vector(*grp_p, &grp_list) == 0) {
            d_state = FIELD_OK;

            for (i = 0; i < rd_left(&grp_list); i += 2) {
                n_g += !is_grease(u16at(grp_list.p + i));
            }

        } else {
            d_state = FIELD_BAD;
        }
    }

    /* ---- second pass: the three sortable lists in one temporary block */

    total = n_c + n_h + n_g;
    buf = ciphers = exts = groups = NULL;

    if (total) {
        buf = alloc(ctx, total * sizeof(uint16_t));
        if (buf == NULL) {
            return CLIENTFP_TLSFP_ENOMEM;
        }

        ciphers = buf;
        exts = buf + n_c;
        groups = exts + n_h;
    }

    for (i = 0, k = 0; i < rd_left(&cs); i += 2) {
        v = u16at(cs.p + i);
        if (!is_grease(v)) {
            ciphers[k++] = (uint16_t) v;
        }
    }

    r = block;
    k = 0;

    while (rd_left(&r)) {
        (void) rd_u16(&r, &t);
        (void) rd_u16(&r, &ext_len);
        r.p += ext_len;

        if (!is_grease(t) && !is_ephemeral(t) && t != EXT_SNI && t != EXT_ALPN) {
            exts[k++] = (uint16_t) t;
        }
    }

    for (i = 0, k = 0; d_state == FIELD_OK && i < rd_left(&grp_list); i += 2) {
        v = u16at(grp_list.p + i);
        if (!is_grease(v)) {
            groups[k++] = (uint16_t) v;
        }
    }

    if (n_c > 1) {
        qsort(ciphers, n_c, sizeof(uint16_t), cmp_u16);
    }

    if (n_h > 1) {
        qsort(exts, n_h, sizeof(uint16_t), cmp_u16);
    }

    if (n_g > 1) {
        qsort(groups, n_g, sizeof(uint16_t), cmp_u16);
    }

    /* ---- format */

    o = 0;

    if (a_ok) {
        out[o++] = (uint8_t) proto;
        out[o++] = (uint8_t) ver[0];
        out[o++] = (uint8_t) ver[1];
        out[o++] = sni ? 'd' : 'i';
        n = (unsigned) (n_c > 99 ? 99 : n_c);
        out[o++] = (uint8_t) ('0' + n / 10);
        out[o++] = (uint8_t) ('0' + n % 10);
        n = (unsigned) (n_s > 99 ? 99 : n_s);
        out[o++] = (uint8_t) ('0' + n / 10);
        out[o++] = (uint8_t) ('0' + n % 10);
        out[o++] = (uint8_t) alpn[0];
        out[o++] = (uint8_t) alpn[1];
    }

    out[o++] = '_';

    hash_begin(&h);

    for (i = 0; i < n_c; i++) {
        hash_u16(&h, ciphers[i]);
    }

    hash_end(&h, out + o);

    o += 12;
    out[o++] = '_';

    if (c_state != FIELD_BAD) {
        hash_begin(&h);

        for (i = 0; i < n_h; i++) {
            hash_u16(&h, exts[i]);
        }

        hash_put(&h, "_", 1);
        h.n = 0;

        for (i = 0; i < rd_left(&sig_list); i += 2) {
            hash_u16(&h, u16at(sig_list.p + i));
        }

        hash_end(&h, out + o);

        o += 12;
    }

    out[o++] = '_';

    if (d_state == FIELD_OK && n_g > 0) {
        hash_begin(&h);

        for (i = 0; i < n_g; i++) {
            hash_u16(&h, groups[i]);
        }

        hash_end(&h, out + o);

        o += 12;

    } else if (d_state != FIELD_BAD) {
        memcpy(out + o, "000000000000", 12);
        o += 12;
    }

    *out_len = o;

    if (buf != NULL) {
        release(ctx, buf);
    }

    return CLIENTFP_TLSFP_OK;
}
