/*
 * Test driver for nginx_module/src/clientfp_hello.c (ClientHello capture).
 *
 * stdin, one case per line:
 *   T <hex>                          TLS records as peeked from a TCP socket
 *   Q <offset>:<hex> <offset>:<hex>  QUIC Initial CRYPTO frame fragments, in arrival order (hex may be empty)
 * stdout, one line per case: "<status>\t<message hex or ->\t<need>" (need only for T, else 0).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clientfp_hello.h"


static size_t
unhex(const char *s, size_t n, uint8_t *out)
{
    size_t  i;
    char    b[3] = { 0, 0, 0 };

    for (i = 0; i + 1 < n; i += 2) {
        b[0] = s[i];
        b[1] = s[i + 1];
        out[i / 2] = (uint8_t) strtoul(b, NULL, 16);
    }

    return n / 2;
}


static void
print(int status, const uint8_t *msg, size_t len, size_t need)
{
    size_t  i;

    printf("%d\t", status);

    if (status == CLIENTFP_HELLO_DONE) {
        for (i = 0; i < len; i++) {
            printf("%02x", msg[i]);
        }

    } else {
        printf("-");
    }

    printf("\t%zu\n", need);
}


int
main(void)
{
    int                     rc;
    char                   *line, *p, *colon, *end;
    size_t                  cap, n, len, msg_len, need;
    uint8_t                *raw, *buf;
    uint64_t                offset;
    const uint8_t          *msg;
    clientfp_hello_quic_t  *q;

    cap = 1 << 22;
    line = malloc(cap);
    raw = malloc(cap / 2);
    buf = malloc(CLIENTFP_HELLO_MAX);
    q = malloc(sizeof(clientfp_hello_quic_t));

    if (line == NULL || raw == NULL || buf == NULL || q == NULL) {
        return 1;
    }

    while (fgets(line, (int) cap, stdin)) {
        n = strcspn(line, "\r\n");
        line[n] = '\0';

        if (line[0] == 'T') {
            len = unhex(line + 2, strlen(line + 2), raw);

            /* exactly len bytes, so ASan sees any read past what was "peeked" */
            uint8_t *exact = malloc(len ? len : 1);
            memcpy(exact, raw, len);
            msg = NULL;
            msg_len = 0;
            need = 0;
            rc = clientfp_hello_tls(exact, len, buf, &msg, &msg_len, &need);
            if (rc == CLIENTFP_HELLO_AGAIN && (need <= len || need > CLIENTFP_HELLO_RAW_MAX)) {
                abort();
            }
            if (rc == CLIENTFP_HELLO_DONE && (msg_len > CLIENTFP_HELLO_MAX || msg_len < 4)) {
                abort();
            }
            print(rc, msg, msg_len, rc == CLIENTFP_HELLO_AGAIN ? need : 0);
            free(exact);

        } else if (line[0] == 'Q') {
            clientfp_hello_quic_init(q);
            rc = CLIENTFP_HELLO_AGAIN;

            for (p = strtok(line + 1, " "); p; p = strtok(NULL, " ")) {
                colon = strchr(p, ':');
                if (colon == NULL) {
                    return 2;
                }
                offset = strtoull(p, &end, 10);
                len = unhex(colon + 1, strlen(colon + 1), raw);
                uint8_t *exact = malloc(len ? len : 1);
                memcpy(exact, raw, len);
                rc = clientfp_hello_quic_add(q, offset, exact, len);
                free(exact);
            }

            print(rc, q->buf, q->total, 0);
        }

        fflush(stdout);
    }

    free(q);
    free(buf);
    free(raw);
    free(line);

    return 0;
}
