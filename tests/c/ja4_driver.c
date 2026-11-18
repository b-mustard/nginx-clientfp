/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 nginx-clientfp contributors
 *
 * Test driver for nginx_module/src/clientfp_ja4.c.
 *
 * stdin: one ClientHello per line: "<proto> <hex handshake message>" (proto t|q).
 * stdout: one line per input: "<status>\t<ja4>\t<ja4_r>\t<ja4_o>\t<ja4_ro>" (forms empty unless status is 0).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clientfp_ja4.h"


static void *
alloc(void *ctx, size_t size)
{
    (void) ctx;
    return malloc(size);
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
        char            proto = line[0];
        char           *hex = line + 2;
        size_t          n = strcspn(hex, "\r\n");
        uint8_t        *msg = malloc(n / 2 + 1);
        clientfp_ja4_t  ja4;

        if (msg == NULL || n % 2 || unhex(hex, n, msg) != 0) {
            fprintf(stderr, "bad input line\n");
            return 2;
        }

        int rc = clientfp_ja4_parse(&ja4, msg, n / 2, proto, alloc, NULL);
        printf("%d", rc);

        for (int form = CLIENTFP_JA4; form <= CLIENTFP_JA4_RO; form++) {
            if (rc != CLIENTFP_OK) {
                printf("\t");
                continue;
            }
            size_t   max = clientfp_ja4_max_len(&ja4, (clientfp_ja4_form_e) form);
            uint8_t *out = malloc(max + 1);
            size_t   len = clientfp_ja4_format(&ja4, (clientfp_ja4_form_e) form, out);
            if (len > max) {
                fprintf(stderr, "format overflow\n");
                abort();
            }
            printf("\t%.*s", (int) len, out);
            free(out);
        }
        printf("\n");

        if (rc == CLIENTFP_OK) {
            free(ja4.ciphers ? (void *) ja4.ciphers : ja4.exts ? (void *) ja4.exts : (void *) ja4.sigalgs);
        }
        free(msg);
    }

    return 0;
}
