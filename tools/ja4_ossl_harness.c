/*
 * Minimal OpenSSL TLS server showing what a JA4 implementation can see from inside OpenSSL:
 *   - the raw ClientHello handshake message, captured with the msg_callback, and
 *   - the SSL_client_hello_* API view from inside the client_hello callback.
 *
 * Every HTTP/1.1 request is answered with JSON:
 *   {"raw": "<hex of 1st ClientHello from msg_callback>", "msgcb_count": N, "chcb_count": M,
 *    "msgcb_before_chcb": true|false, "api": {...}}
 * tools/ja4_harness_check.py drives the ja4_probe clients against it.
 *
 * build: cc -o ja4_ossl_harness tools/ja4_ossl_harness.c -I$OSSL/include -L$OSSL/lib64 -lssl -lcrypto
 * run:   LD_LIBRARY_PATH=$OSSL/lib64 ./ja4_ossl_harness 8443 cert.pem key.pem
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    unsigned char *ch;                  /* first ClientHello (handshake header included) */
    size_t ch_len;
    int n_msgcb, n_chcb, msgcb_before_chcb;
    char api[16384];
} probe_t;

static int probe_idx;

static char *hex(char *out, const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out += sprintf(out, "%02x", p[i]);
    return out;
}

static void msg_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
    probe_t *pr = SSL_get_ex_data(ssl, probe_idx);
    const unsigned char *b = buf;

    (void)version, (void)arg;
    if (pr == NULL || write_p || content_type != SSL3_RT_HANDSHAKE || len < 4 || b[0] != SSL3_MT_CLIENT_HELLO)
        return;
    if (pr->n_msgcb++ == 0) {           /* keep only the first ClientHello (not the one after HRR) */
        pr->ch = OPENSSL_memdup(buf, len);
        pr->ch_len = len;
    }
}

static int ch_cb(SSL *ssl, int *al, void *arg)
{
    probe_t *pr = SSL_get_ex_data(ssl, probe_idx);
    const unsigned char *c, *d;
    size_t n, dl, next = 0;
    int *ext = NULL;
    uint16_t order[256];
    size_t norder = 256;
    char *p = pr->api;

    (void)al, (void)arg;
    if (pr->n_chcb++ > 0)
        return SSL_CLIENT_HELLO_SUCCESS;
    pr->msgcb_before_chcb = pr->n_msgcb > 0;

    p += sprintf(p, "\"legacy_version\":\"%04x\",\"ciphers\":\"", SSL_client_hello_get0_legacy_version(ssl));
    n = SSL_client_hello_get0_ciphers(ssl, &c);
    p = hex(p, c, n);
    p += sprintf(p, "\",\"extensions_present\":[");
    if (SSL_client_hello_get1_extensions_present(ssl, &ext, &next))
        for (size_t i = 0; i < next; i++)
            p += sprintf(p, "%s\"%04x\"", i ? "," : "", ext[i]);
    OPENSSL_free(ext);
    p += sprintf(p, "],\"extension_order\":[");
    if (SSL_client_hello_get_extension_order(ssl, order, &norder))
        for (size_t i = 0; i < norder; i++)
            p += sprintf(p, "%s\"%04x\"", i ? "," : "", order[i]);
    p += sprintf(p, "],\"get0_ext\":{");
    static const unsigned int probe_types[] = { 0x0000, 0x000d, 0x0010, 0x002b, 0x0015, 0x44cd, 0x4469, 0x0a0a };
    for (size_t i = 0; i < sizeof(probe_types) / sizeof(probe_types[0]); i++) {
        int found = SSL_client_hello_get0_ext(ssl, probe_types[i], &d, &dl);
        p += sprintf(p, "%s\"%04x\":", i ? "," : "", probe_types[i]);
        if (found) {
            *p++ = '"';
            p = hex(p, d, dl);
            *p++ = '"';
        } else {
            p += sprintf(p, "null");
        }
    }
    sprintf(p, "}");
    return SSL_CLIENT_HELLO_SUCCESS;
}

static int alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg)
{
    static const unsigned char h11[] = "\x08http/1.1";

    (void)ssl, (void)arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen, h11, sizeof(h11) - 1, in, inlen)
        == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_NOACK;
}

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    int ls, one = 1;
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };

    if (argc != 4) {
        fprintf(stderr, "usage: %s port cert.pem key.pem\n", argv[0]);
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);           /* peers that close right after the handshake (session priming) */
    ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_security_level(ctx, 0);
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    if (SSL_CTX_use_certificate_chain_file(ctx, argv[2]) != 1
        || SSL_CTX_use_PrivateKey_file(ctx, argv[3], SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_set_msg_callback(ctx, msg_cb);
    SSL_CTX_set_client_hello_cb(ctx, ch_cb, NULL);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, NULL);
    probe_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    sa.sin_port = htons((unsigned short)atoi(argv[1]));
    ls = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(ls, 16) != 0) {
        perror("bind/listen");
        return 1;
    }
    fprintf(stderr, "%s listening on 127.0.0.1:%s\n", OpenSSL_version(OPENSSL_VERSION), argv[1]);

    for (;;) {
        int fd = accept(ls, NULL, NULL), r, got = 0;
        probe_t pr = { 0 };
        char req[8192], *body = NULL, *resp = NULL;
        SSL *ssl;

        if (fd < 0)
            continue;
        ssl = SSL_new(ctx);
        SSL_set_ex_data(ssl, probe_idx, &pr);
        SSL_set_fd(ssl, fd);
        if (SSL_accept(ssl) == 1) {
            req[0] = 0;
            while (got < (int)sizeof(req) - 1 && (r = SSL_read(ssl, req + got, sizeof(req) - 1 - got)) > 0) {
                got += r;
                req[got] = 0;
                if (strstr(req, "\r\n\r\n"))
                    break;
            }
            if (strstr(req, "\r\n\r\n") == NULL)
                goto shutdown;          /* handshake-only connection: nothing to answer */
            body = malloc(2 * pr.ch_len + sizeof(pr.api) + 256);
            resp = malloc(2 * pr.ch_len + sizeof(pr.api) + 512);
            char *p = body + sprintf(body, "{\"raw\":\"");
            p = hex(p, pr.ch, pr.ch_len);
            sprintf(p, "\",\"msgcb_count\":%d,\"chcb_count\":%d,\"msgcb_before_chcb\":%s,\"api\":{%s}}\n",
                pr.n_msgcb, pr.n_chcb, pr.msgcb_before_chcb ? "true" : "false", pr.api);
            r = sprintf(resp, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
                              "Connection: close\r\n\r\n%s", strlen(body), body);
            SSL_write(ssl, resp, r);
        shutdown:
            SSL_shutdown(ssl);          /* clean close keeps the session in the session-ID cache */
            free(body);
            free(resp);
        } else {
            ERR_print_errors_fp(stderr);
        }
        SSL_free(ssl);
        OPENSSL_free(pr.ch);
        close(fd);
    }
}
