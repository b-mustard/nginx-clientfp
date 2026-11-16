/*
 * Test driver for nginx_module/src/clientfp_tlsfp.c.
 *
 * stdin: one ClientHello per line: "<proto> <hex handshake message>" (proto t|q|d).
 * stdout: one line per input: "<status>\t<tlsfp>" (empty unless status is 0).
 * Allocations are counted: every buffer must be released before clientfp_tlsfp_compute() returns.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clientfp_tlsfp.h"


static long  live;


static void *
alloc(void *ctx, size_t size)
{
    (void) ctx;
    live++;
    return malloc(size);
}


static void
release(void *ctx, void *p)
{
    (void) ctx;
    live--;
    free(p);
}


static int
unhex(const char *s, size_t n, uint8_t *out)
{
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t) v;
    }
    return 0;
}


int
main(void)
{
    static char  line[1 << 20];

    while (fgets(line, sizeof(line), stdin)) {
        char      proto = line[0];
        char     *hex = line + 2;
        size_t    n = strcspn(hex, "\r\n"), len;
        uint8_t  *msg = malloc(n / 2 + 1);
        uint8_t   out[CLIENTFP_TLSFP_MAX_LEN];

        if (msg == NULL || n % 2 || unhex(hex, n, msg) != 0) {
            fprintf(stderr, "bad input line\n");
            return 2;
        }

        int rc = clientfp_tlsfp_compute(msg, n / 2, proto, out, &len, alloc, release, NULL);

        if (live != 0 || len > CLIENTFP_TLSFP_MAX_LEN || (rc != CLIENTFP_TLSFP_OK && len != 0)) {
            fprintf(stderr, "invariant broken: live=%ld len=%zu rc=%d\n", live, len, rc);
            abort();
        }

        printf("%d\t%.*s\n", rc, (int) len, (const char *) out);
        free(msg);
    }

    return 0;
}
