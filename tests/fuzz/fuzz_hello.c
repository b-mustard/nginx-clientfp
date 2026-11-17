/*
 * libFuzzer target: ClientHello capture (clientfp_hello.c), then both fingerprints of whatever it captures.
 *
 * data[0] even: data[1..] is the start of a TCP connection (TLS records); the capture also runs on a prefix.
 * data[0] odd:  data[1..] is a sequence of QUIC CRYPTO fragments: offset(2) length(2) bytes(length), big-endian.
 */

#include <stdlib.h>
#include <string.h>

#include "clientfp_hello.h"
#include "clientfp_ja4.h"
#include "clientfp_tlsfp.h"


static void *
alloc(void *ctx, size_t size)
{
    (void) ctx;
    return malloc(size);
}


static void
release(void *ctx, void *p)
{
    (void) ctx;
    free(p);
}


static void
fingerprint(const uint8_t *msg, size_t len, char proto)
{
    size_t          n;
    uint8_t         out[CLIENTFP_TLSFP_MAX_LEN];
    clientfp_ja4_t  ja4;

    if (clientfp_ja4_parse(&ja4, msg, len, proto, alloc, NULL) == CLIENTFP_OK
        && ja4.n_ciphers + ja4.n_exts + ja4.n_sigalgs)
    {
        /* one block, starting at the first non-empty list */
        free(ja4.n_ciphers ? (void *) ja4.ciphers : ja4.n_exts ? (void *) ja4.exts : (void *) ja4.sigalgs);
    }

    if (clientfp_tlsfp_compute(msg, len, proto, out, &n, alloc, release, NULL) == CLIENTFP_TLSFP_OK
        && n > CLIENTFP_TLSFP_MAX_LEN)
    {
        abort();
    }
}


static void
tcp(const uint8_t *data, size_t size)
{
    int             rc;
    size_t          msg_len, need;
    uint8_t        *raw, *buf;
    const uint8_t  *msg;

    raw = malloc(size ? size : 1);          /* exactly the "peeked" bytes */
    buf = malloc(CLIENTFP_HELLO_MAX);
    if (raw == NULL || buf == NULL) {
        abort();
    }

    memcpy(raw, data, size);

    rc = clientfp_hello_tls(raw, size, buf, &msg, &msg_len, &need);

    if (rc == CLIENTFP_HELLO_AGAIN && (need <= size || need > CLIENTFP_HELLO_RAW_MAX)) {
        abort();
    }

    if (rc == CLIENTFP_HELLO_DONE) {
        if (msg_len < 4 || msg_len > CLIENTFP_HELLO_MAX || msg[0] != 0x01) {
            abort();
        }

        fingerprint(msg, msg_len, 't');

        /* a prefix shorter than the message cannot be DONE */
        if (clientfp_hello_tls(raw, size / 2, buf, &msg, &msg_len, &need) == CLIENTFP_HELLO_DONE
            && msg_len > size / 2)
        {
            abort();
        }
    }

    free(buf);
    free(raw);
}


static void
quic(const uint8_t *data, size_t size)
{
    int                     rc;
    size_t                  i, len;
    uint8_t                *frag;
    uint64_t                offset;
    clientfp_hello_quic_t  *q;

    q = malloc(sizeof(clientfp_hello_quic_t));
    if (q == NULL) {
        abort();
    }

    clientfp_hello_quic_init(q);
    rc = CLIENTFP_HELLO_AGAIN;

    for (i = 0; i + 4 <= size; i += 4 + len) {
        offset = (uint64_t) data[i] << 8 | data[i + 1];
        len = (size_t) data[i + 2] << 8 | data[i + 3];

        if (len > size - i - 4) {
            len = size - i - 4;
        }

        frag = malloc(len ? len : 1);
        if (frag == NULL) {
            abort();
        }

        memcpy(frag, data + i + 4, len);
        rc = clientfp_hello_quic_add(q, offset, frag, len);
        free(frag);
    }

    if (rc == CLIENTFP_HELLO_DONE) {
        if (q->total < 4 || q->total > CLIENTFP_HELLO_MAX || q->buf[0] != 0x01) {
            abort();
        }

        fingerprint(q->buf, q->total, 'q');
    }

    free(q);
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) {
        return 0;
    }

    if (data[0] & 1) {
        quic(data + 1, size - 1);

    } else {
        tcp(data + 1, size - 1);
    }

    return 0;
}
