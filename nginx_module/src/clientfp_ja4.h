/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 nginx-clientfp contributors
 *
 * JA4 TLS client fingerprint: ClientHello parser and formatter.
 *
 * Pure C, no nginx or TLS-library dependency, so it can be unit-tested and fuzzed on its own. SHA-256 comes from
 * clientfp_sha256.c. Normative spec: doc/ja4_sig.md.
 */

#ifndef CLIENTFP_JA4_H
#define CLIENTFP_JA4_H

#include <stddef.h>
#include <stdint.h>


/* No fingerprint when any non-GREASE list is longer than this (decision 011). */
#define CLIENTFP_JA4_MAX_LIST   1024

/* Every hashed form (ja4, ja4_o) is exactly this long: a(10) _ b(12) _ c(12). */
#define CLIENTFP_JA4_HASHED_LEN 36

#define CLIENTFP_OK          0
#define CLIENTFP_EMALFORMED  1   /* truncated or inconsistent lengths        */
#define CLIENTFP_ETOOBIG     2   /* a list exceeds CLIENTFP_JA4_MAX_LIST      */
#define CLIENTFP_ENOMEM      3   /* the allocator returned NULL               */


typedef enum {
    CLIENTFP_JA4 = 0,           /* a_hash(sorted ciphers)_hash(sorted exts_sigalgs) */
    CLIENTFP_JA4_R,             /* a_sorted ciphers_sorted exts_sigalgs             */
    CLIENTFP_JA4_O,             /* a_hash(wire ciphers)_hash(wire exts_sigalgs)     */
    CLIENTFP_JA4_RO             /* a_wire ciphers_wire exts_sigalgs                 */
} clientfp_ja4_form_e;


/* Everything JA4 needs from one ClientHello. GREASE values are already removed. */
typedef struct {
    uint16_t   *ciphers;        /* wire order */
    uint16_t   *exts;           /* extension types, wire order, duplicates kept */
    uint16_t   *sigalgs;        /* wire order, duplicates kept */
    uint16_t    n_ciphers;
    uint16_t    n_exts;
    uint16_t    n_sigalgs;
    char        a[10];          /* proto, version(2), sni, nc(2), ne(2), alpn(2) */
} clientfp_ja4_t;


typedef void *(*clientfp_alloc_pt)(void *ctx, size_t size);


/*
 * Parses a complete ClientHello handshake message (msg_type 0x01, 3-byte length, body): the TLS records'
 * payload reassembled, or the start of the QUIC Initial CRYPTO stream (clientfp_hello.h). proto is 't' (TLS over
 * TCP) or 'q' (QUIC).
 *
 * On success all three lists live in ONE block obtained from alloc(ctx, size) (size may be 0, in which case
 * alloc is not called and the list pointers are NULL). On error nothing was allocated and *ja4 is zeroed.
 */
int clientfp_ja4_parse(clientfp_ja4_t *ja4, const uint8_t *msg, size_t len, char proto, clientfp_alloc_pt alloc,
    void *ctx);

/* Upper bound for the output of clientfp_ja4_format() for this fingerprint and form. */
size_t clientfp_ja4_max_len(const clientfp_ja4_t *ja4, clientfp_ja4_form_e form);

/*
 * Writes one form into out (capacity >= clientfp_ja4_max_len()). Returns the length written (never 0). The output
 * is not NUL-terminated.
 */
size_t clientfp_ja4_format(const clientfp_ja4_t *ja4, clientfp_ja4_form_e form, uint8_t *out);

/* RFC 8701 GREASE test. */
static inline int
clientfp_is_grease(uint16_t v)
{
    return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff);
}

#endif /* CLIENTFP_JA4_H */
