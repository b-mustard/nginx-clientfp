/* libFuzzer target: arbitrary bytes as a ClientHello handshake message for the TLSFP core. */

#include <stdlib.h>
#include <string.h>

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


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const char  protos[] = "tqd";
    uint8_t            out[CLIENTFP_TLSFP_MAX_LEN], *msg;
    size_t             len, i;
    int                rc;

    if (size < 1) {
        return 0;
    }

    /* first byte picks the proto; the rest is the message, copied so ASan sees its exact bounds */
    msg = malloc(size - 1 ? size - 1 : 1);
    memcpy(msg, data + 1, size - 1);

    rc = clientfp_tlsfp_compute(msg, size - 1, protos[data[0] % 3], out, &len, alloc, release, NULL);

    if (rc == CLIENTFP_TLSFP_OK) {
        if (len > CLIENTFP_TLSFP_MAX_LEN || len < 3) {
            abort();
        }

        for (i = 0; i < len; i++) {     /* safe for a header or a log line: [0-9a-z_] only */
            if (!((out[i] >= '0' && out[i] <= '9') || (out[i] >= 'a' && out[i] <= 'z') || out[i] == '_')) {
                abort();
            }
        }
    }

    free(msg);
    return 0;
}
