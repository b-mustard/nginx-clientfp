/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 nginx-clientfp contributors
 *
 * nDPI TLS client fingerprint (TLSFP): ClientHello -> fingerprint string.
 *
 * Pure C, no nginx or TLS-library dependency, independent of the JA4 core (decision 022). SHA-256 comes from
 * clientfp_sha256.c.
 * Normative text: doc/nDPI_TLS_Fingerprint.md (draft v0.1), interpretation: doc/tlsfp_sig.md, reference
 * implementation: tools/clientfp/fp/tlsfp.py.
 */

#ifndef CLIENTFP_TLSFP_H
#define CLIENTFP_TLSFP_H

#include <stddef.h>
#include <stdint.h>


/* a(10) _ b(12) _ c(12) _ d(12). Shorter only when a field is empty (spec §9). */
#define CLIENTFP_TLSFP_MAX_LEN     49

/* Ephemeral extension registry version (spec Appendix B), exported next to the fingerprint (spec §13). */
#define CLIENTFP_TLSFP_REGISTRY    1

#define CLIENTFP_TLSFP_OK          0
#define CLIENTFP_TLSFP_EMALFORMED  1   /* ClientHello framing broken: no fingerprint */
#define CLIENTFP_TLSFP_ENOMEM      3   /* the allocator returned NULL                */


typedef void *(*clientfp_tlsfp_alloc_pt)(void *ctx, size_t size);
typedef void (*clientfp_tlsfp_free_pt)(void *ctx, void *p);


/*
 * Computes the TLSFP of a complete ClientHello handshake message (msg_type 0x01, 3-byte length, body): the TLS
 * records' payload reassembled, or the start of the QUIC Initial CRYPTO stream (clientfp_hello.h). proto is 't'
 * (TLS over TCP), 'q' (QUIC) or 'd' (DTLS).
 *
 * out must hold CLIENTFP_TLSFP_MAX_LEN bytes; on success *out_len is the length written (not NUL-terminated).
 * Lists are not capped (spec §7.5): the sort buffers come from alloc(ctx, size) and are passed to release(ctx, p)
 * before the function returns. Nothing is retained.
 */
int clientfp_tlsfp_compute(const uint8_t *msg, size_t len, char proto, uint8_t *out, size_t *out_len,
    clientfp_tlsfp_alloc_pt alloc, clientfp_tlsfp_free_pt release, void *ctx);

#endif /* CLIENTFP_TLSFP_H */
