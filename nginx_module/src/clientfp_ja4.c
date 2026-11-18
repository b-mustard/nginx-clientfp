/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 nginx-clientfp contributors
 *
 * JA4 TLS client fingerprint: ClientHello parser and formatter. See clientfp_ja4.h and doc/ja4_sig.md.
 *
 * Parsing rules (the TLS presentation language of RFC 8446 §3, as in the reference tools/clientfp/fp/ja4.py):
 * - Every length must fit its enclosing length and fill it exactly: the handshake message, the body (which ends
 *   with the extensions block, if any), the extensions block, each extension, and the lists inside the three
 *   extensions we decode (ALPN protocol list, signature_algorithms, supported_versions). u16 lists must have an
 *   even length. A hello we call malformed never completes a handshake.
 * - Repeated extensions: the first occurrence of ALPN / sigalgs / supported_versions is decoded; every occurrence
 *   counts and is listed.
 */

#include "clientfp_ja4.h"
#include "clientfp_sha256.h"

#include <stdlib.h>
#include <string.h>



#define EXT_SNI                 0x0000
#define EXT_SIGALGS             0x000d
#define EXT_ALPN                0x0010
#define EXT_SUPPORTED_VERSIONS  0x002b


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
get_u16(const uint8_t *p)
{
    return (uint16_t) (((unsigned) p[0] << 8) | p[1]);
}


static const char *
version_code(unsigned v)
{
    switch (v) {
    case 0x0304: return "13";
    case 0x0303: return "12";
    case 0x0302: return "11";
    case 0x0301: return "10";
    case 0x0300: return "s3";
    case 0x0002: return "s2";
    case 0xfeff: return "d1";
    case 0xfefd: return "d2";
    case 0xfefc: return "d3";
    default:     return "00";
    }
}


static int
is_alnum(uint8_t c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}


static const char  hexdig[] = "0123456789abcdef";


/* a[8..9] from the first ALPN protocol name (doc/ja4_sig.md §3 a.6). */
static int
alpn_code(rd_t data, char out[2])
{
    unsigned  list_len, first_len;
    rd_t      list;

    out[0] = '0';
    out[1] = '0';

    unsigned  name_len;
    rd_t      name, first;

    if (rd_u16(&data, &list_len) != 0 || rd_sub(&data, list_len, &list) != 0 || rd_left(&data) != 0) {
        return -1;
    }

    /* the whole protocol list must be well-formed; the first name is used */

    first.p = first.end = NULL;
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
        return 0;                       /* empty list or empty first name */
    }

    if (is_alnum(first.p[0]) && is_alnum(first.p[first_len - 1])) {
        out[0] = (char) first.p[0];
        out[1] = (char) first.p[first_len - 1];

    } else {
        out[0] = hexdig[first.p[0] >> 4];
        out[1] = hexdig[first.p[first_len - 1] & 0x0f];
    }

    return 0;
}


/* Highest non-GREASE supported_versions entry; 0 if there is none. */
static int
max_supported_version(rd_t data, unsigned *max)
{
    unsigned  list_len, v = 0;      /* initialized for gcc -O2 -Wmaybe-uninitialized; rd_u16 always sets it */
    rd_t      list;

    *max = 0;

    if (rd_u8(&data, &list_len) != 0 || rd_sub(&data, list_len, &list) != 0 || rd_left(&data) != 0
        || list_len % 2)
    {
        return -1;
    }

    while (rd_left(&list)) {
        (void) rd_u16(&list, &v);

        if (!clientfp_is_grease((uint16_t) v) && v > *max) {
            *max = v;
        }
    }

    return 0;
}


static int
sigalgs_list(rd_t data, rd_t *list)
{
    unsigned  list_len;

    if (rd_u16(&data, &list_len) != 0 || rd_sub(&data, list_len, list) != 0 || rd_left(&data) != 0
        || list_len % 2)
    {
        return -1;
    }

    return 0;
}


static size_t
count_u16_non_grease(rd_t r)
{
    size_t  n = 0;

    for ( /* void */ ; rd_left(&r) >= 2; r.p += 2) {
        n += !clientfp_is_grease(get_u16(r.p));
    }

    return n;
}


static uint16_t *
fill_u16_non_grease(rd_t r, uint16_t *dst)
{
    uint16_t  v;

    for ( /* void */ ; rd_left(&r) >= 2; r.p += 2) {
        v = get_u16(r.p);

        if (!clientfp_is_grease(v)) {
            *dst++ = v;
        }
    }

    return dst;
}


static void
two_digits(char *out, size_t n)
{
    if (n > 99) {
        n = 99;
    }

    out[0] = (char) ('0' + n / 10);
    out[1] = (char) ('0' + n % 10);
}


int
clientfp_ja4_parse(clientfp_ja4_t *ja4, const uint8_t *msg, size_t len, char proto, clientfp_alloc_pt alloc,
    void *ctx)
{
    int        sni, have_alpn, have_sig, have_sv;
    char       alpn[2];
    size_t     body_len, nc, ne, ns, total;
    unsigned   legacy_version, sid_len, cs_len, comp_len, exts_len, type, dlen, version;
    rd_t       body, cs, exts, ext, data, sig, alpn_data, sv_data;
    uint16_t  *block, *p;

    memset(ja4, 0, sizeof(*ja4));

    if (msg == NULL || len < 4 || msg[0] != 0x01) {
        return CLIENTFP_EMALFORMED;
    }

    body_len = ((size_t) msg[1] << 16) | ((size_t) msg[2] << 8) | msg[3];

    if (body_len != len - 4) {
        return CLIENTFP_EMALFORMED;
    }

    body.p = msg + 4;
    body.end = body.p + body_len;

    if (rd_u16(&body, &legacy_version) != 0
        || rd_sub(&body, 32, &data) != 0                      /* random */
        || rd_u8(&body, &sid_len) != 0
        || rd_sub(&body, sid_len, &data) != 0
        || rd_u16(&body, &cs_len) != 0
        || rd_sub(&body, cs_len, &cs) != 0
        || cs_len % 2
        || rd_u8(&body, &comp_len) != 0
        || rd_sub(&body, comp_len, &data) != 0)
    {
        return CLIENTFP_EMALFORMED;
    }

    exts.p = exts.end = body.p;                                /* the block may be absent */

    if (rd_left(&body)) {
        if (rd_u16(&body, &exts_len) != 0 || rd_sub(&body, exts_len, &exts) != 0 || rd_left(&body) != 0) {
            return CLIENTFP_EMALFORMED;
        }
    }

    /* pass 1: validate the extensions block, count, find the extensions we read */

    sni = have_alpn = have_sig = have_sv = 0;
    ne = 0;
    sig.p = sig.end = NULL;
    alpn_data = sv_data = sig;

    ext = exts;

    while (rd_left(&ext)) {
        if (rd_u16(&ext, &type) != 0 || rd_u16(&ext, &dlen) != 0 || rd_sub(&ext, dlen, &data) != 0) {
            return CLIENTFP_EMALFORMED;
        }

        if (clientfp_is_grease((uint16_t) type)) {
            continue;
        }

        ne++;

        switch (type) {

        case EXT_SNI:
            sni = 1;
            break;

        case EXT_ALPN:
            if (!have_alpn) {
                have_alpn = 1;
                alpn_data = data;
            }
            break;

        case EXT_SIGALGS:
            if (!have_sig) {
                have_sig = 1;
                if (sigalgs_list(data, &sig) != 0) {
                    return CLIENTFP_EMALFORMED;
                }
            }
            break;

        case EXT_SUPPORTED_VERSIONS:
            if (!have_sv) {
                have_sv = 1;
                sv_data = data;
            }
            break;
        }
    }

    alpn[0] = alpn[1] = '0';

    if (have_alpn && alpn_code(alpn_data, alpn) != 0) {
        return CLIENTFP_EMALFORMED;
    }

    version = legacy_version;

    if (have_sv) {
        unsigned  max;

        if (max_supported_version(sv_data, &max) != 0) {
            return CLIENTFP_EMALFORMED;
        }

        if (max) {
            version = max;          /* only GREASE listed: fall back to legacy_version (doc §3 a.2) */
        }
    }

    nc = count_u16_non_grease(cs);
    ns = have_sig ? count_u16_non_grease(sig) : 0;

    if (nc > CLIENTFP_JA4_MAX_LIST || ne > CLIENTFP_JA4_MAX_LIST || ns > CLIENTFP_JA4_MAX_LIST) {
        return CLIENTFP_ETOOBIG;
    }

    /* pass 2: copy the lists into one block */

    total = nc + ne + ns;
    block = NULL;

    if (total) {
        block = alloc(ctx, total * sizeof(uint16_t));
        if (block == NULL) {
            return CLIENTFP_ENOMEM;
        }
    }

    p = block;

    ja4->ciphers = nc ? p : NULL;
    p = fill_u16_non_grease(cs, p);

    ja4->exts = ne ? p : NULL;
    for (ext = exts; rd_left(&ext); ext.p += 4 + dlen) {
        type = get_u16(ext.p);
        dlen = get_u16(ext.p + 2);

        if (!clientfp_is_grease((uint16_t) type)) {
            *p++ = (uint16_t) type;
        }
    }

    ja4->sigalgs = ns ? p : NULL;
    if (have_sig) {
        (void) fill_u16_non_grease(sig, p);
    }

    ja4->n_ciphers = (uint16_t) nc;
    ja4->n_exts = (uint16_t) ne;
    ja4->n_sigalgs = (uint16_t) ns;

    ja4->a[0] = proto;
    memcpy(&ja4->a[1], version_code(version), 2);
    ja4->a[3] = sni ? 'd' : 'i';
    two_digits(&ja4->a[4], nc);
    two_digits(&ja4->a[6], ne);
    ja4->a[8] = alpn[0];
    ja4->a[9] = alpn[1];

    return CLIENTFP_OK;
}


/* ---------------------------------------------------------------------------------------------------------- */

/* Output sink: either copies bytes to a buffer or streams them into SHA-256. */
typedef struct {
    uint8_t            *out;
    clientfp_sha256_t  *sha;
    size_t              total;
} sink_t;


static void
sink_put(sink_t *s, const char *p, size_t n)
{
    s->total += n;

    if (s->sha) {
        clientfp_sha256_update(s->sha, p, n);
        return;
    }

    memcpy(s->out, p, n);
    s->out += n;
}


static void
sink_list(sink_t *s, const uint16_t *v, size_t n)
{
    size_t  i;
    char    hex[5];

    for (i = 0; i < n; i++) {
        hex[0] = ',';
        hex[1] = hexdig[(v[i] >> 12) & 0xf];
        hex[2] = hexdig[(v[i] >> 8) & 0xf];
        hex[3] = hexdig[(v[i] >> 4) & 0xf];
        hex[4] = hexdig[v[i] & 0xf];

        if (i == 0) {
            sink_put(s, hex + 1, 4);

        } else {
            sink_put(s, hex, 5);
        }
    }
}


/* c_raw: E, then "_" + S when S is not empty; empty when E is empty (doc §3 c). */
static void
sink_c(sink_t *s, const uint16_t *e, size_t ne, const uint16_t *sig, size_t ns)
{
    if (ne == 0) {
        return;
    }

    sink_list(s, e, ne);

    if (ns) {
        sink_put(s, "_", 1);
        sink_list(s, sig, ns);
    }
}


/* hash12 of the string the sink receives: 12 lowercase hex chars, or 000000000000 for an empty string. */
static void
hash12(uint8_t out[12], const uint16_t *l1, size_t n1, const uint16_t *l2, size_t n2, int is_c)
{
    size_t             i;
    sink_t             s;
    uint8_t            md[CLIENTFP_SHA256_LEN];
    clientfp_sha256_t  sha;

    clientfp_sha256_init(&sha);

    s.out = NULL;
    s.sha = &sha;
    s.total = 0;

    if (is_c) {
        sink_c(&s, l1, n1, l2, n2);

    } else {
        sink_list(&s, l1, n1);
    }

    if (s.total == 0) {
        memset(out, '0', 12);
        return;
    }

    clientfp_sha256_final(&sha, md);

    for (i = 0; i < 6; i++) {
        out[2 * i] = (uint8_t) hexdig[md[i] >> 4];
        out[2 * i + 1] = (uint8_t) hexdig[md[i] & 0xf];
    }
}


static int
cmp_u16(const void *a, const void *b)
{
    return (int) *(const uint16_t *) a - (int) *(const uint16_t *) b;
}


static size_t
list_len(size_t n)
{
    return n ? 5 * n - 1 : 0;
}


size_t
clientfp_ja4_max_len(const clientfp_ja4_t *ja4, clientfp_ja4_form_e form)
{
    if (form == CLIENTFP_JA4 || form == CLIENTFP_JA4_O) {
        return CLIENTFP_JA4_HASHED_LEN;
    }

    /* a _ b _ E _ S, with E bounded by all extension types */
    return 10 + 1 + list_len(ja4->n_ciphers) + 1 + list_len(ja4->n_exts) + 1 + list_len(ja4->n_sigalgs);
}


size_t
clientfp_ja4_format(const clientfp_ja4_t *ja4, clientfp_ja4_form_e form, uint8_t *out)
{
    int              sorted;
    size_t           i, ne;
    sink_t           s;
    const uint16_t  *ciphers, *exts;
    uint16_t         sc[CLIENTFP_JA4_MAX_LIST], se[CLIENTFP_JA4_MAX_LIST];

    sorted = (form == CLIENTFP_JA4 || form == CLIENTFP_JA4_R);

    ciphers = ja4->ciphers;
    exts = ja4->exts;
    ne = ja4->n_exts;

    if (sorted) {
        if (ja4->n_ciphers) {
            memcpy(sc, ja4->ciphers, ja4->n_ciphers * sizeof(uint16_t));
            qsort(sc, ja4->n_ciphers, sizeof(uint16_t), cmp_u16);
        }

        ne = 0;
        for (i = 0; i < ja4->n_exts; i++) {
            if (ja4->exts[i] != EXT_SNI && ja4->exts[i] != EXT_ALPN) {
                se[ne++] = ja4->exts[i];
            }
        }

        if (ne) {
            qsort(se, ne, sizeof(uint16_t), cmp_u16);
        }

        ciphers = sc;
        exts = se;
    }

    memcpy(out, ja4->a, 10);
    out[10] = '_';

    if (form == CLIENTFP_JA4 || form == CLIENTFP_JA4_O) {
        hash12(out + 11, ciphers, ja4->n_ciphers, NULL, 0, 0);
        out[23] = '_';
        hash12(out + 24, exts, ne, ja4->sigalgs, ja4->n_sigalgs, 1);

        return CLIENTFP_JA4_HASHED_LEN;
    }

    s.out = out + 11;
    s.sha = NULL;
    s.total = 0;

    sink_list(&s, ciphers, ja4->n_ciphers);
    sink_put(&s, "_", 1);
    sink_c(&s, exts, ne, ja4->sigalgs, ja4->n_sigalgs);

    return 11 + s.total;
}
