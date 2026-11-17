/* libFuzzer target: arbitrary bytes as a sequence of HTTP/2 hook events, then format. */

#include <stdlib.h>
#include <string.h>

#include "clientfp_h2.h"


static uint32_t
u32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const char *names[] = { ":method", ":path", ":authority", ":scheme", ":protocol", ":", "x" };

    clientfp_h2_t  fp;
    uint8_t        out[CLIENTFP_H2_MAX_LEN];
    size_t         i, n;

    memset(&fp, 0, sizeof(fp));

    for (i = 0; i + 9 <= size; i += 9) {
        const uint8_t *e = data + i;
        uint32_t a = u32(e + 1), b = u32(e + 5);

        switch (e[0] % 7) {
        case 0: clientfp_h2_settings_frame(&fp, e[1], b % 20000); break;
        case 1: clientfp_h2_setting(&fp, a & 0xffff, b); break;
        case 2: clientfp_h2_window_update(&fp, a % 4, b); break;
        case 3: clientfp_h2_priority(&fp, a, e[5] & 1, b, 1 + e[8]); break;
        case 4: clientfp_h2_stream(&fp, a % 8); break;
        case 5: {
            const char *nm = names[e[5] % 7];
            clientfp_h2_pseudo_header(&fp, a % 8, (const uint8_t *) nm, strlen(nm));
            break;
        }
        default: clientfp_h2_headers_done(&fp, a % 8); break;
        }
    }

    n = clientfp_h2_format(&fp, out);
    if (n > sizeof(out)) {
        abort();
    }
    return 0;
}
