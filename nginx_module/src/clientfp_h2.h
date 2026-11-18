/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 nginx-clientfp contributors
 *
 * Akamai HTTP/2 client fingerprint: per-connection recorder and formatter.
 *
 * Pure C, no nginx dependency. The patched nginx HTTP/2 state machine reports frames through the
 * clientfp_h2_*() calls below; the recorder applies the capture rules of doc/http2_sig.md §2-§3:
 * first non-empty non-ACK SETTINGS frame, first connection-level WINDOW_UPDATE, every PRIORITY frame and the
 * pseudo-header order of the first HEADERS block, all frozen when that block ends. The MD5 for
 * $clientfp_http2_hash is computed by the module with nginx's ngx_md5.
 */

#ifndef CLIENTFP_H2_H
#define CLIENTFP_H2_H

#include <stddef.h>
#include <stdint.h>


#define CLIENTFP_H2_MAX_SETTINGS  32       /* decision 012: truncate and flag overflow */
#define CLIENTFP_H2_MAX_PRIORITY  32

/* settings 32 x "65535:4294967295;", WU 10, priority 32 x "2147483647:1:2147483647:256,", PS 7, 3 separators */
#define CLIENTFP_H2_MAX_LEN       (32 * 17 + 10 + 32 * 28 + 7 + 3)


typedef struct {
    uint32_t   sid;
    uint32_t   depends_on;
    uint16_t   weight;                     /* 1..256 (wire octet + 1) */
    uint8_t    exclusive;
} clientfp_h2_prio_t;


typedef struct {
    uint32_t             settings_val[CLIENTFP_H2_MAX_SETTINGS];
    uint16_t             settings_id[CLIENTFP_H2_MAX_SETTINGS];
    clientfp_h2_prio_t   prio[CLIENTFP_H2_MAX_PRIORITY];
    uint32_t             window_update;
    uint32_t             first_sid;        /* stream id of the first HEADERS block nginx processes */
    uint8_t              n_settings;
    uint8_t              n_prio;
    uint8_t              n_ps;
    char                 ps[4];

    unsigned             settings_done:1;  /* the qualifying SETTINGS frame has started */
    unsigned             settings_open:1;  /* parameters being reported belong to it */
    unsigned             wu_seen:1;
    unsigned             frozen:1;         /* the first HEADERS block has ended */
    unsigned             overflow:1;
} clientfp_h2_t;


/* A SETTINGS frame starts (frame header parsed and validated). */
void clientfp_h2_settings_frame(clientfp_h2_t *fp, unsigned flags, size_t length);

/* One SETTINGS parameter of the frame announced last. */
void clientfp_h2_setting(clientfp_h2_t *fp, unsigned id, uint32_t value);

void clientfp_h2_window_update(clientfp_h2_t *fp, uint32_t sid, uint32_t increment);

/* weight is the RFC 7540 weight 1..256, i.e. wire octet + 1. */
void clientfp_h2_priority(clientfp_h2_t *fp, uint32_t sid, int exclusive, uint32_t depends_on, unsigned weight);

/* nginx created a stream for a HEADERS frame; the first one defines PS. */
void clientfp_h2_stream(clientfp_h2_t *fp, uint32_t sid);

/* A header field name starting with ':', in decode order. Recorded for the first stream only. */
void clientfp_h2_pseudo_header(clientfp_h2_t *fp, uint32_t sid, const uint8_t *name, size_t len);

/* A header block has ended; the first stream's block freezes the fingerprint. */
void clientfp_h2_headers_done(clientfp_h2_t *fp, uint32_t sid);

/* Writes the fingerprint into out (capacity CLIENTFP_H2_MAX_LEN) and returns its length. */
size_t clientfp_h2_format(const clientfp_h2_t *fp, uint8_t *out);

#endif /* CLIENTFP_H2_H */
