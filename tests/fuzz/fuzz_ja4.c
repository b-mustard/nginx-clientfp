/* libFuzzer target: arbitrary bytes as a ClientHello handshake message; every form is formatted. */

#include <stdlib.h>
#include <string.h>

#include "clientfp_ja4.h"


static void *
alloc(void *ctx, size_t size)
{
    (void) ctx;
    return malloc(size);
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    clientfp_ja4_t  ja4;
    uint8_t        *msg;

    if (size < 1) {
        return 0;
    }

    /* first byte picks the proto; the rest is the message, copied so ASan sees its exact bounds */
    msg = malloc(size - 1 ? size - 1 : 1);
    memcpy(msg, data + 1, size - 1);

    if (clientfp_ja4_parse(&ja4, msg, size - 1, (data[0] & 1) ? 'q' : 't', alloc, NULL) == CLIENTFP_OK) {
        for (int f = CLIENTFP_JA4; f <= CLIENTFP_JA4_RO; f++) {
            size_t   max = clientfp_ja4_max_len(&ja4, (clientfp_ja4_form_e) f);
            uint8_t *out = malloc(max ? max : 1);
            size_t   n = clientfp_ja4_format(&ja4, (clientfp_ja4_form_e) f, out);

            if (n > max || ((f == CLIENTFP_JA4 || f == CLIENTFP_JA4_O) && n != CLIENTFP_JA4_HASHED_LEN)) {
                abort();
            }
            free(out);
        }

        if (ja4.n_ciphers + ja4.n_exts + ja4.n_sigalgs) {
            free(ja4.n_ciphers ? (void *) ja4.ciphers : ja4.n_exts ? (void *) ja4.exts : (void *) ja4.sigalgs);
        }
    }

    free(msg);
    return 0;
}
