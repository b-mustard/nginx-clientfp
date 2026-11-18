/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 nginx-clientfp contributors
 *
 * ClientHello capture: reassembles the first handshake message of a connection from what the client sent,
 * before the TLS library reads it (decision 030). Pure C, no nginx or TLS-library dependency.
 *
 * - TLS over TCP: the bytes at the start of the connection, as peeked from the socket. The ClientHello may be
 *   split across several handshake records.
 * - QUIC: the CRYPTO frames of Initial packets, in any order, possibly overlapping (RFC 9000 §19.6).
 *
 * The result is the complete handshake message (msg_type 0x01, 3-byte length, body) that the JA4 and TLSFP cores
 * take. Limits: decision 033.
 */

#ifndef CLIENTFP_HELLO_H
#define CLIENTFP_HELLO_H

#include <stddef.h>
#include <stdint.h>


#define CLIENTFP_HELLO_MAX       16384   /* handshake message, 4-byte header included */
#define CLIENTFP_HELLO_RAW_MAX   32768   /* TLS record bytes (headers included) we wait for */

#define CLIENTFP_HELLO_DONE      0       /* the complete ClientHello is available       */
#define CLIENTFP_HELLO_AGAIN     1       /* incomplete: more bytes are needed            */
#define CLIENTFP_HELLO_NOTHELLO  2       /* not a TLS handshake starting with ClientHello */
#define CLIENTFP_HELLO_TOOBIG    3       /* over CLIENTFP_HELLO_MAX or _RAW_MAX           */
#define CLIENTFP_HELLO_SSLV2     4       /* an SSLv2-format ClientHello (decision 036)    */


/*
 * TLS over TCP. raw/len: the first len bytes the client sent. buf: CLIENTFP_HELLO_MAX bytes of scratch space.
 *
 * DONE:  *msg and *msg_len give the message, pointing into raw when it sits in one record, else into buf.
 * AGAIN: *need is a lower bound on the raw bytes required to finish (or to fail), always > len and
 *        <= CLIENTFP_HELLO_RAW_MAX. Calling again with fewer bytes cannot make progress.
 *
 * SSLV2: the first byte has its top bit set and the third is 1 (SSL2_MT_CLIENT_HELLO), which is how TLS libraries
 * recognise an SSLv2-format ClientHello; it is not reassembled (no fingerprint is defined for it). A top bit with
 * any other third byte gives NOTHELLO. Until 3 bytes are there: AGAIN with *need = 3.
 *
 * Record rules: content type 22 (handshake), version major 3, length 0..16384. Empty records are skipped (the TLS
 * library accepts them, so refusing them would let a client avoid fingerprinting). The record version and anything
 * after the message are ignored. Records of other types before the message is complete give NOTHELLO.
 */
int clientfp_hello_tls(const uint8_t *raw, size_t len, uint8_t *buf, const uint8_t **msg, size_t *msg_len,
    size_t *need);


/* QUIC: reassembly state for the start of the Initial CRYPTO stream. Set up with clientfp_hello_quic_init(). */
typedef struct {
    size_t   total;                              /* 4 + message length once bytes 0..3 are known, else 0 */
    size_t   filled;                             /* distinct bytes received below the limit */
    int      state;                              /* AGAIN until it becomes DONE, NOTHELLO or TOOBIG */
    uint8_t  have[CLIENTFP_HELLO_MAX / 8];       /* one bit per received byte */
    uint8_t  buf[CLIENTFP_HELLO_MAX];
} clientfp_hello_quic_t;


void clientfp_hello_quic_init(clientfp_hello_quic_t *q);

/*
 * Adds one CRYPTO frame fragment (stream offset, bytes). Bytes at or beyond the message end (or
 * CLIENTFP_HELLO_MAX while the length is unknown) are ignored; overlapping bytes keep the first copy.
 * Returns the state; once it is not AGAIN, further calls change nothing. On DONE the message is
 * q->buf[0 .. q->total).
 */
int clientfp_hello_quic_add(clientfp_hello_quic_t *q, uint64_t offset, const uint8_t *data, size_t len);

#endif /* CLIENTFP_HELLO_H */
