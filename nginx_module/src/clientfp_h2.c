/*
 * Akamai HTTP/2 client fingerprint recorder. See clientfp_h2.h and doc/http2_sig.md.
 */

#include "clientfp_h2.h"

#include <string.h>


#define FLAG_ACK  0x1


void
clientfp_h2_settings_frame(clientfp_h2_t *fp, unsigned flags, size_t length)
{
    fp->settings_open = 0;

    if (fp->frozen || fp->settings_done || (flags & FLAG_ACK) || length == 0) {
        return;
    }

    fp->settings_done = 1;
    fp->settings_open = 1;
}


void
clientfp_h2_setting(clientfp_h2_t *fp, unsigned id, uint32_t value)
{
    if (fp->frozen || !fp->settings_open) {
        return;
    }

    if (fp->n_settings == CLIENTFP_H2_MAX_SETTINGS) {
        fp->overflow = 1;
        return;
    }

    fp->settings_id[fp->n_settings] = (uint16_t) id;
    fp->settings_val[fp->n_settings] = value;
    fp->n_settings++;
}


void
clientfp_h2_window_update(clientfp_h2_t *fp, uint32_t sid, uint32_t increment)
{
    if (fp->frozen || sid != 0 || fp->wu_seen) {
        return;
    }

    fp->wu_seen = 1;
    fp->window_update = increment & 0x7fffffff;
}


void
clientfp_h2_priority(clientfp_h2_t *fp, uint32_t sid, int exclusive, uint32_t depends_on, unsigned weight)
{
    clientfp_h2_prio_t  *p;

    if (fp->frozen) {
        return;
    }

    if (fp->n_prio == CLIENTFP_H2_MAX_PRIORITY) {
        fp->overflow = 1;
        return;
    }

    p = &fp->prio[fp->n_prio++];
    p->sid = sid & 0x7fffffff;
    p->exclusive = exclusive ? 1 : 0;
    p->depends_on = depends_on & 0x7fffffff;
    p->weight = (uint16_t) (weight > 256 ? 256 : weight);
}


void
clientfp_h2_stream(clientfp_h2_t *fp, uint32_t sid)
{
    if (fp->frozen || fp->first_sid != 0 || sid == 0) {
        return;
    }

    fp->first_sid = sid;
}


void
clientfp_h2_pseudo_header(clientfp_h2_t *fp, uint32_t sid, const uint8_t *name, size_t len)
{
    char      c;
    unsigned  i;

    if (fp->frozen || sid == 0 || sid != fp->first_sid) {
        return;
    }

#define is(s)  (len == sizeof(s) - 1 && memcmp(name, s, sizeof(s) - 1) == 0)

    if (is(":method")) {
        c = 'm';

    } else if (is(":path")) {
        c = 'p';

    } else if (is(":authority")) {
        c = 'a';

    } else if (is(":scheme")) {
        c = 's';

    } else {
        return;
    }

#undef is

    for (i = 0; i < fp->n_ps; i++) {
        if (fp->ps[i] == c) {
            return;                     /* a repeated pseudo-header is recorded once */
        }
    }

    fp->ps[fp->n_ps++] = c;
}


void
clientfp_h2_headers_done(clientfp_h2_t *fp, uint32_t sid)
{
    if (fp->frozen || sid == 0 || sid != fp->first_sid) {
        return;
    }

    fp->frozen = 1;
    fp->settings_open = 0;
}


static uint8_t *
put_uint(uint8_t *p, uint32_t v)
{
    uint8_t   tmp[10];
    unsigned  n = 0;

    do {
        tmp[n++] = (uint8_t) ('0' + v % 10);
        v /= 10;
    } while (v);

    while (n) {
        *p++ = tmp[--n];
    }

    return p;
}


size_t
clientfp_h2_format(const clientfp_h2_t *fp, uint8_t *out)
{
    unsigned                   i;
    uint8_t                   *p;
    const clientfp_h2_prio_t  *pr;

    p = out;

    for (i = 0; i < fp->n_settings; i++) {
        if (i) {
            *p++ = ';';
        }

        p = put_uint(p, fp->settings_id[i]);
        *p++ = ':';
        p = put_uint(p, fp->settings_val[i]);
    }

    *p++ = '|';

    if (fp->wu_seen) {
        p = put_uint(p, fp->window_update);

    } else {
        *p++ = '0';
        *p++ = '0';
    }

    *p++ = '|';

    if (fp->n_prio == 0) {
        *p++ = '0';
    }

    for (i = 0; i < fp->n_prio; i++) {
        pr = &fp->prio[i];

        if (i) {
            *p++ = ',';
        }

        p = put_uint(p, pr->sid);
        *p++ = ':';
        *p++ = pr->exclusive ? '1' : '0';
        *p++ = ':';
        p = put_uint(p, pr->depends_on);
        *p++ = ':';
        p = put_uint(p, pr->weight);
    }

    *p++ = '|';

    for (i = 0; i < fp->n_ps; i++) {
        if (i) {
            *p++ = ',';
        }

        *p++ = (uint8_t) fp->ps[i];
    }

    return (size_t) (p - out);
}

