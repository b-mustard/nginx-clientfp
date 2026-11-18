/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 nginx-clientfp contributors
 *
 * Test driver for nginx_module/src/clientfp_sha256.c.
 *
 * stdin: one input per line as "<chunk>:<hex>"; the input is fed in pieces of <chunk> bytes (1..n).
 * stdout: the SHA-256 digest of each input as lowercase hex.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clientfp_sha256.h"


int
main(void)
{
    char               *line, b[3] = { 0, 0, 0 };
    size_t              cap, n, len, i, chunk, k;
    uint8_t            *data, md[CLIENTFP_SHA256_LEN];
    clientfp_sha256_t   s;

    cap = 1 << 22;
    line = malloc(cap);
    data = malloc(cap / 2);

    if (line == NULL || data == NULL) {
        return 1;
    }

    while (fgets(line, (int) cap, stdin)) {
        n = strcspn(line, "\r\n");
        line[n] = '\0';

        chunk = strtoul(line, NULL, 10);
        char *hex = strchr(line, ':') + 1;
        len = strlen(hex) / 2;

        for (i = 0; i < len; i++) {
            b[0] = hex[2 * i];
            b[1] = hex[2 * i + 1];
            data[i] = (uint8_t) strtoul(b, NULL, 16);
        }

        clientfp_sha256_init(&s);

        for (i = 0; i < len; i += k) {
            k = len - i < chunk ? len - i : chunk;
            clientfp_sha256_update(&s, data + i, k);
        }

        clientfp_sha256_update(&s, NULL, 0);
        clientfp_sha256_final(&s, md);

        for (i = 0; i < CLIENTFP_SHA256_LEN; i++) {
            printf("%02x", md[i]);
        }

        printf("\n");
    }

    free(data);
    free(line);

    return 0;
}
