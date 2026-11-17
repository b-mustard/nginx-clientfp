/*
 * SHA-256 (FIPS 180-4), streaming. Pure C, no nginx or TLS-library dependency (decision 030).
 * Used by the JA4 and TLSFP cores; checked against Python's hashlib in tests/test_c_core.py.
 */

#ifndef CLIENTFP_SHA256_H
#define CLIENTFP_SHA256_H

#include <stddef.h>
#include <stdint.h>


#define CLIENTFP_SHA256_LEN  32


typedef struct {
    uint32_t  h[8];
    uint64_t  len;              /* bytes hashed so far */
    size_t    blen;             /* bytes waiting in buf */
    uint8_t   buf[64];
} clientfp_sha256_t;


void clientfp_sha256_init(clientfp_sha256_t *s);
void clientfp_sha256_update(clientfp_sha256_t *s, const void *data, size_t n);
void clientfp_sha256_final(clientfp_sha256_t *s, uint8_t out[CLIENTFP_SHA256_LEN]);

#endif /* CLIENTFP_SHA256_H */
