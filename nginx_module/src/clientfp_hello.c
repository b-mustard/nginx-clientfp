/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 nginx-clientfp contributors
 *
 * ClientHello capture from TLS records (TCP) or QUIC Initial CRYPTO frames. See clientfp_hello.h.
 */

#include "clientfp_hello.h"

#include <string.h>


#define TLS_RECORD_HANDSHAKE   22
#define TLS_RECORD_MAX         16384     /* RFC 8446 §5.1: plaintext fragment limit */
#define HS_CLIENT_HELLO        1
#define SSL2_MT_CLIENT_HELLO   1


/* Checks a handshake message header; sets *total to the message size. 0, NOTHELLO or TOOBIG. */
static int
message_header(const uint8_t h[4], size_t *total)
{
    if (h[0] != HS_CLIENT_HELLO) {
        return CLIENTFP_HELLO_NOTHELLO;
    }

    *total = 4 + ((size_t) h[1] << 16 | (size_t) h[2] << 8 | h[3]);

    return *total > CLIENTFP_HELLO_MAX ? CLIENTFP_HELLO_TOOBIG : 0;
}


/*
 * Checks the record header bytes we have (1..5 of them). 0 or NOTHELLO; *rlen is set when all 5 are there.
 * Empty records are allowed: they carry nothing, and the TLS library accepts them before the hello is complete.
 */
static int
record_header(const uint8_t *p, size_t n, size_t *rlen)
{
    if (n >= 1 && p[0] != TLS_RECORD_HANDSHAKE) {
        return CLIENTFP_HELLO_NOTHELLO;
    }

    if (n >= 2 && p[1] != 3) {
        return CLIENTFP_HELLO_NOTHELLO;
    }

    if (n >= 5) {
        *rlen = (size_t) p[3] << 8 | p[4];

        if (*rlen > TLS_RECORD_MAX) {
            return CLIENTFP_HELLO_NOTHELLO;
        }
    }

    return 0;
}


int
clientfp_hello_tls(const uint8_t *raw, size_t len, uint8_t *buf, const uint8_t **msg, size_t *msg_len,
    size_t *need)
{
    int             rc;
    size_t          pos, rlen, have, total, t, k, n, rem, avail, end;
    uint8_t         h[4];
    const uint8_t  *p;

    if (len >= 1 && (raw[0] & 0x80)) {
        /* SSLv2 record header: 2-byte length with the top bit set, then the message type */

        if (len < 3) {
            *need = 3;
            return CLIENTFP_HELLO_AGAIN;
        }

        return raw[2] == SSL2_MT_CLIENT_HELLO ? CLIENTFP_HELLO_SSLV2 : CLIENTFP_HELLO_NOTHELLO;
    }

    pos = 0;
    have = 0;           /* message bytes collected in buf */
    total = 0;          /* message size, once its header has been collected */
    rlen = 0;

    /* complete records */

    while (len - pos >= 5) {
        p = raw + pos;

        rc = record_header(p, 5, &rlen);
        if (rc != 0) {
            return rc;
        }

        if (len - pos - 5 < rlen) {
            break;
        }

        p += 5;
        pos += 5 + rlen;

        if (have == 0 && rlen >= 4) {
            /* the usual case: the whole message in the first record, no copy */

            rc = message_header(p, &t);
            if (rc != 0) {
                return rc;
            }

            if (rlen >= t) {
                *msg = p;
                *msg_len = t;
                return CLIENTFP_HELLO_DONE;
            }
        }

        for (n = rlen; n; ) {
            if (total == 0) {
                k = 4 - have < n ? 4 - have : n;
                memcpy(buf + have, p, k);
                have += k;
                p += k;
                n -= k;

                if (have == 4) {
                    rc = message_header(buf, &total);
                    if (rc != 0) {
                        return rc;
                    }
                }

                continue;
            }

            k = total - have < n ? total - have : n;
            memcpy(buf + have, p, k);
            have += k;

            break;      /* the rest of the record (if any) follows the message */
        }

        if (total && have == total) {
            *msg = buf;
            *msg_len = total;
            return CLIENTFP_HELLO_DONE;
        }
    }

    /* an incomplete record at pos: check what we have of it, then work out the bytes still needed */

    p = raw + pos;
    avail = len - pos;

    rc = record_header(p, avail, &rlen);
    if (rc != 0) {
        return rc;
    }

    if (avail >= 5 && total == 0) {
        /* look ahead at the message header inside the partial record */

        k = avail - 5;

        if (have + k >= 4) {
            memcpy(h, buf, have);
            memcpy(h + have, p + 5, 4 - have);

            rc = message_header(h, &t);
            if (rc != 0) {
                return rc;
            }

            total = t;
        }
    }

    rem = total ? total - have : 4 - have;     /* message bytes still missing (a lower bound without total) */

    if (avail >= 5) {
        end = pos + 5 + rlen;
        *need = end + (rem > rlen ? 5 + (rem - rlen) : 0);

    } else {
        *need = pos + 5 + rem;
    }

    return *need > CLIENTFP_HELLO_RAW_MAX ? CLIENTFP_HELLO_TOOBIG : CLIENTFP_HELLO_AGAIN;
}


void
clientfp_hello_quic_init(clientfp_hello_quic_t *q)
{
    memset(q, 0, sizeof(*q));
    q->state = CLIENTFP_HELLO_AGAIN;
}


int
clientfp_hello_quic_add(clientfp_hello_quic_t *q, uint64_t offset, const uint8_t *data, size_t len)
{
    int     rc;
    size_t  i, limit, end, t;

    if (q->state != CLIENTFP_HELLO_AGAIN) {
        return q->state;
    }

    limit = q->total ? q->total : CLIENTFP_HELLO_MAX;

    if (len == 0 || offset >= limit) {
        return CLIENTFP_HELLO_AGAIN;
    }

    end = len < limit - (size_t) offset ? (size_t) offset + len : limit;

    for (i = (size_t) offset; i < end; i++) {
        if ((q->have[i >> 3] & (1u << (i & 7))) == 0) {
            q->have[i >> 3] |= (uint8_t) (1u << (i & 7));
            q->buf[i] = data[i - (size_t) offset];
            q->filled++;
        }
    }

    if (q->total == 0 && (q->have[0] & 0x0f) == 0x0f) {
        rc = message_header(q->buf, &t);
        if (rc != 0) {
            q->state = rc;
            return rc;
        }

        q->total = t;
        q->filled = 0;

        for (i = 0; i < t; i++) {
            q->filled += (q->have[i >> 3] >> (i & 7)) & 1;
        }
    }

    if (q->total && q->filled == q->total) {
        q->state = CLIENTFP_HELLO_DONE;
    }

    return q->state;
}
