/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 nginx-clientfp contributors
 *
 * Test driver for nginx_module/src/clientfp_h2.c.
 *
 * stdin: hook events as nginx's patched HTTP/2 code reports them, one per line, a connection per block:
 *   F <flags> <length>         SETTINGS frame starts
 *   s <id> <value>             SETTINGS parameter
 *   W <sid> <increment>        WINDOW_UPDATE
 *   P <sid> <excl> <dep> <weight>   PRIORITY (weight 1..256)
 *   T <sid>                    stream created for HEADERS
 *   H <sid> <name>             pseudo-header name (e.g. :method)
 *   D <sid>                    header block ended
 *   E                          end of connection: print "<frozen>\t<fingerprint>\t<overflow>"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clientfp_h2.h"


int
main(void)
{
    char           line[4096], name[4096];
    unsigned long  a, b, c, d;
    clientfp_h2_t  fp;
    uint8_t        out[CLIENTFP_H2_MAX_LEN];

    memset(&fp, 0, sizeof(fp));

    while (fgets(line, sizeof(line), stdin)) {
        switch (line[0]) {
        case 'F':
            sscanf(line + 1, "%lu %lu", &a, &b);
            clientfp_h2_settings_frame(&fp, (unsigned) a, b);
            break;
        case 's':
            sscanf(line + 1, "%lu %lu", &a, &b);
            clientfp_h2_setting(&fp, (unsigned) a, (uint32_t) b);
            break;
        case 'W':
            sscanf(line + 1, "%lu %lu", &a, &b);
            clientfp_h2_window_update(&fp, (uint32_t) a, (uint32_t) b);
            break;
        case 'P':
            sscanf(line + 1, "%lu %lu %lu %lu", &a, &b, &c, &d);
            clientfp_h2_priority(&fp, (uint32_t) a, (int) b, (uint32_t) c, (unsigned) d);
            break;
        case 'T':
            sscanf(line + 1, "%lu", &a);
            clientfp_h2_stream(&fp, (uint32_t) a);
            break;
        case 'H':
            sscanf(line + 1, "%lu %4095s", &a, name);
            clientfp_h2_pseudo_header(&fp, (uint32_t) a, (const uint8_t *) name, strlen(name));
            break;
        case 'D':
            sscanf(line + 1, "%lu", &a);
            clientfp_h2_headers_done(&fp, (uint32_t) a);
            break;
        case 'E': {
            size_t n = clientfp_h2_format(&fp, out);
            if (n > sizeof(out)) {
                abort();
            }
            printf("%d\t%.*s\t%d\n", fp.frozen, (int) n, out, fp.overflow);
            memset(&fp, 0, sizeof(fp));
            break;
        }
        default:
            break;
        }
    }

    return 0;
}
