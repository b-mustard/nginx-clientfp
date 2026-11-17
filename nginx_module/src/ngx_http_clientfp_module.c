/*
 * ngx_http_clientfp_module: JA4, nDPI TLSFP and HTTP/2 (Akamai) client fingerprints for nginx.
 *
 * Directives
 *   clientfp on | off;                        http        default on
 *   clientfp_request_header <name> <value>;   http, server
 *
 * Variables
 *   $clientfp_ja4 $clientfp_ja4_r $clientfp_ja4_o $clientfp_ja4_ro
 *   $clientfp_tlsfp $clientfp_tlsfp_registry
 *   $clientfp_http2 $clientfp_http2_hash $clientfp_http2_overflow
 *
 * ClientHello capture (decision 030), independent of the TLS library: the patched nginx calls
 * ngx_http_clientfp_tls_hello() before the TLS handshake of a TCP connection starts (the module peeks at the
 * socket until the whole ClientHello has arrived) and ngx_http_clientfp_quic_crypto() for every CRYPTO frame of
 * a QUIC Initial packet. clientfp_hello.c reassembles the message (at most 16 KiB, decision 033). The result lives
 * in the connection's pool at hc->clientfp (decision 034), so HTTP/1, HTTP/2 and HTTP/3 requests find it.
 *
 * JA4: the captured ClientHello is parsed into compact lists (clientfp_ja4.c); the strings are formatted on first
 * use. TLSFP (nDPI TLS client fingerprint, doc/tlsfp_sig.md): computed from the same ClientHello by its own core
 * (clientfp_tlsfp.c), independently of JA4, once per connection; only the 49-byte string is kept (decision 026).
 *
 * HTTP/2: the patched ngx_http_v2.c calls the ngx_http_clientfp_h2_*() hooks below
 * (patches/nginx/<line>/); without the patch the module builds with JA4 only.
 *
 * clientfp_request_header: in the POST_READ phase of every main request, all client-sent header lines with a
 * configured name are removed and the configured value is added (if not empty), so upstream modules forward a
 * value that the client cannot spoof.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#include "clientfp_hello.h"
#include "clientfp_ja4.h"
#include "clientfp_tlsfp.h"

#if (NGX_HTTP_V2 && defined NGX_HTTP_V2_CLIENTFP_HOOKS)
#define NGX_HTTP_CLIENTFP_H2  1
#include "clientfp_h2.h"
#else
#define NGX_HTTP_CLIENTFP_H2  0
#endif


typedef struct {
    ngx_flag_t                  enable;
} ngx_http_clientfp_main_conf_t;


typedef struct {
    ngx_str_t                   name;
    ngx_str_t                   lowcase;
    ngx_uint_t                  hash;
    ngx_http_complex_value_t    value;
} ngx_http_clientfp_header_t;


typedef struct {
    ngx_array_t                *headers;      /* of ngx_http_clientfp_header_t */
} ngx_http_clientfp_srv_conf_t;


/*
 * Per TLS-over-TCP or QUIC connection, in that connection's pool, at hc->clientfp. While the ClientHello arrives
 * it holds the capture state; once captured is set, the results. JA4 and TLSFP are independent: either may be
 * missing while the other is present.
 */
typedef struct {
    ngx_uint_t                  captured;     /* the capture has finished, with or without a ClientHello */
    size_t                      need;         /* TCP: bytes to wait for before peeking again */
    ngx_uint_t                  peeks;        /* TCP: peeks so far */
    clientfp_hello_quic_t      *quic;         /* QUIC: reassembly buffer until the capture finishes */
    ngx_pool_t                 *pool;         /* the connection's pool: parsed lists and cached strings */

    ngx_int_t                   status;       /* CLIENTFP_OK or an error code */
    clientfp_ja4_t              ja4;
    ngx_str_t                   cache[4];     /* formatted forms, by clientfp_ja4_form_e */

    ngx_int_t                   tlsfp_status; /* CLIENTFP_TLSFP_OK or an error code */
    size_t                      tlsfp_len;
    u_char                      tlsfp[CLIENTFP_TLSFP_MAX_LEN];
} ngx_http_clientfp_tls_ctx_t;


#if (NGX_HTTP_CLIENTFP_H2)

/* Per HTTP/2 connection, in c->pool (h2c->pool is destroyed when the connection is idle). */
typedef struct {
    clientfp_h2_t               fp;
    ngx_str_t                   text;
    ngx_str_t                   hash;
} ngx_http_clientfp_h2_ctx_t;

#endif


static ngx_int_t ngx_http_clientfp_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_clientfp_init(ngx_conf_t *cf);
static void *ngx_http_clientfp_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_clientfp_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_clientfp_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_clientfp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_clientfp_request_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_http_clientfp_tls_ctx_t *ngx_http_clientfp_tls_get(ngx_http_request_t *r);
static ngx_int_t ngx_http_clientfp_ja4_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t ngx_http_clientfp_tlsfp_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t ngx_http_clientfp_h2_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t ngx_http_clientfp_post_read_handler(ngx_http_request_t *r);


static ngx_command_t  ngx_http_clientfp_commands[] = {

    { ngx_string("clientfp"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_clientfp_main_conf_t, enable),
      NULL },

    { ngx_string("clientfp_request_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
      ngx_http_clientfp_request_header,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_clientfp_module_ctx = {
    ngx_http_clientfp_add_variables,       /* preconfiguration */
    ngx_http_clientfp_init,                /* postconfiguration */

    ngx_http_clientfp_create_main_conf,    /* create main configuration */
    ngx_http_clientfp_init_main_conf,      /* init main configuration */

    ngx_http_clientfp_create_srv_conf,     /* create server configuration */
    ngx_http_clientfp_merge_srv_conf,      /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_clientfp_module = {
    NGX_MODULE_V1,
    &ngx_http_clientfp_module_ctx,         /* module context */
    ngx_http_clientfp_commands,            /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


#define NGX_HTTP_CLIENTFP_H2_TEXT      0
#define NGX_HTTP_CLIENTFP_H2_HASH      1
#define NGX_HTTP_CLIENTFP_H2_OVERFLOW  2


#define NGX_HTTP_CLIENTFP_TLSFP_TEXT      0
#define NGX_HTTP_CLIENTFP_TLSFP_REGISTRY  1


static ngx_http_variable_t  ngx_http_clientfp_vars[] = {

    { ngx_string("clientfp_ja4"), NULL, ngx_http_clientfp_ja4_variable,
      CLIENTFP_JA4, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("clientfp_ja4_r"), NULL, ngx_http_clientfp_ja4_variable,
      CLIENTFP_JA4_R, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("clientfp_ja4_o"), NULL, ngx_http_clientfp_ja4_variable,
      CLIENTFP_JA4_O, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("clientfp_ja4_ro"), NULL, ngx_http_clientfp_ja4_variable,
      CLIENTFP_JA4_RO, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("clientfp_tlsfp"), NULL, ngx_http_clientfp_tlsfp_variable,
      NGX_HTTP_CLIENTFP_TLSFP_TEXT, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("clientfp_tlsfp_registry"), NULL, ngx_http_clientfp_tlsfp_variable,
      NGX_HTTP_CLIENTFP_TLSFP_REGISTRY, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("clientfp_http2"), NULL, ngx_http_clientfp_h2_variable,
      NGX_HTTP_CLIENTFP_H2_TEXT, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("clientfp_http2_hash"), NULL, ngx_http_clientfp_h2_variable,
      NGX_HTTP_CLIENTFP_H2_HASH, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("clientfp_http2_overflow"), NULL, ngx_http_clientfp_h2_variable,
      NGX_HTTP_CLIENTFP_H2_OVERFLOW, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


/* ---------------------------------------------------------------------------------------------- config */

static ngx_int_t
ngx_http_clientfp_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_clientfp_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_clientfp_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_clientfp_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_clientfp_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    cmcf->enable = NGX_CONF_UNSET;

    return cmcf;
}


static char *
ngx_http_clientfp_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_clientfp_main_conf_t  *cmcf = conf;

    ngx_conf_init_value(cmcf->enable, 1);

    return NGX_CONF_OK;
}


static void *
ngx_http_clientfp_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_clientfp_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_clientfp_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    cscf->headers = NGX_CONF_UNSET_PTR;

    return cscf;
}


static char *
ngx_http_clientfp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_clientfp_srv_conf_t  *prev = parent;
    ngx_http_clientfp_srv_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->headers, prev->headers, NULL);

    return NGX_CONF_OK;
}


/* Header names nginx parses itself (Host, Cookie, X-Forwarded-For, ...) cannot be replaced safely. */
static ngx_int_t
ngx_http_clientfp_is_core_header(ngx_str_t *name)
{
    ngx_http_header_t  *hh;

    for (hh = ngx_http_headers_in; hh->name.len; hh++) {
        if (hh->name.len == name->len && ngx_strncasecmp(hh->name.data, name->data, name->len) == 0) {
            return 1;
        }
    }

    return 0;
}


static char *
ngx_http_clientfp_request_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_clientfp_srv_conf_t  *cscf = conf;

    u_char                             c;
    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_http_clientfp_header_t        *h;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].len == 0) {
        return "has an empty header name";
    }

    for (i = 0; i < value[1].len; i++) {
        c = value[1].data[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid header name \"%V\": only letters, digits and \"-\" are allowed",
                               &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_http_clientfp_is_core_header(&value[1])) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "header \"%V\" is processed by nginx itself and cannot be replaced", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (cscf->headers == NGX_CONF_UNSET_PTR) {
        cscf->headers = ngx_array_create(cf->pool, 2, sizeof(ngx_http_clientfp_header_t));
        if (cscf->headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    h = cscf->headers->elts;

    for (i = 0; i < cscf->headers->nelts; i++) {
        if (h[i].name.len == value[1].len && ngx_strncasecmp(h[i].name.data, value[1].data, value[1].len) == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate header \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    h = ngx_array_push(cscf->headers);
    if (h == NULL) {
        return NGX_CONF_ERROR;
    }

    h->name = value[1];

    h->lowcase.len = value[1].len;
    h->lowcase.data = ngx_pnalloc(cf->pool, value[1].len);
    if (h->lowcase.data == NULL) {
        return NGX_CONF_ERROR;
    }

    h->hash = ngx_hash_strlow(h->lowcase.data, value[1].data, value[1].len);

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &h->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_clientfp_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_clientfp_post_read_handler;

    return NGX_OK;
}


/* ----------------------------------------------------------------------------------- ClientHello capture */

#if (NGX_HTTP_CLIENTFP_HELLO_HOOKS)

/* TCP: give up after this many peeks of a ClientHello that keeps arriving in small pieces */
#define NGX_HTTP_CLIENTFP_MAX_PEEKS  64


static void *
ngx_http_clientfp_palloc(void *pool, size_t size)
{
    return ngx_palloc(pool, size);
}


static void *
ngx_http_clientfp_tmp_alloc(void *log, size_t size)
{
    return ngx_alloc(size, log);
}


static void
ngx_http_clientfp_tmp_free(void *log, void *p)
{
    ngx_free(p);
}


/* NULL when clientfp is off or memory is short: the connection then has no fingerprint. */
static ngx_http_clientfp_tls_ctx_t *
ngx_http_clientfp_tls_create(ngx_connection_t *c, ngx_http_connection_t *hc)
{
    ngx_http_clientfp_tls_ctx_t    *ctx;
    ngx_http_clientfp_main_conf_t  *fmcf;

    fmcf = hc->conf_ctx->main_conf[ngx_http_clientfp_module.ctx_index];

    if (!fmcf->enable) {
        return NULL;
    }

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_http_clientfp_tls_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->need = 1;
    ctx->pool = c->pool;
    ctx->status = CLIENTFP_EMALFORMED;
    ctx->tlsfp_status = CLIENTFP_TLSFP_EMALFORMED;

    hc->clientfp = ctx;

    return ctx;
}


/* The capture is over: compute both fingerprints from the ClientHello, or log why there is none. */
static void
ngx_http_clientfp_finish(ngx_connection_t *c, ngx_http_clientfp_tls_ctx_t *ctx, int rc, const u_char *msg,
    size_t len, char proto)
{
    ctx->captured = 1;

    switch (rc) {

    case CLIENTFP_HELLO_DONE:
        break;

    case CLIENTFP_HELLO_TOOBIG:
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "clientfp: no JA4/TLSFP for this connection: ClientHello larger than %d bytes",
                      CLIENTFP_HELLO_MAX);
        ctx->status = CLIENTFP_ETOOBIG;
        return;

    case CLIENTFP_HELLO_NOTHELLO:
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "clientfp: no JA4/TLSFP for this connection: not a TLS ClientHello");
        return;

    default: /* CLIENTFP_HELLO_AGAIN: gave up waiting */
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "clientfp: no JA4/TLSFP for this connection: incomplete ClientHello");
        return;
    }

    ctx->status = clientfp_ja4_parse(&ctx->ja4, msg, len, proto, ngx_http_clientfp_palloc, c->pool);

    if (ctx->status != CLIENTFP_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "clientfp: no JA4 for this connection: %s ClientHello (%uz bytes)",
                      ctx->status == CLIENTFP_ETOOBIG ? "oversized" :
                      ctx->status == CLIENTFP_ENOMEM ? "out of memory for" : "malformed", len);
    }

    /* TLSFP: its own parse of the same message; uncapped lists, temporary memory released before return */

    ctx->tlsfp_status = clientfp_tlsfp_compute(msg, len, proto, ctx->tlsfp, &ctx->tlsfp_len,
                                               ngx_http_clientfp_tmp_alloc, ngx_http_clientfp_tmp_free, c->log);

    if (ctx->tlsfp_status != CLIENTFP_TLSFP_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "clientfp: no TLSFP for this connection: %s ClientHello (%uz bytes)",
                      ctx->tlsfp_status == CLIENTFP_TLSFP_ENOMEM ? "out of memory for" : "malformed", len);
    }
}


/*
 * TLS over TCP, called by ngx_http_ssl_handshake() before the TLS library reads anything: NGX_AGAIN to wait for
 * more of the ClientHello, NGX_OK to start the handshake (with or without a fingerprint).
 *
 * The socket is peeked, not read, so the TLS library later reads the same bytes. FIONREAD avoids copying until
 * at least the bytes that clientfp_hello_tls() said it needs are there; a hello that keeps arriving in tiny
 * pieces is given up after NGX_HTTP_CLIENTFP_MAX_PEEKS peeks, and so is one the client stopped sending
 * (pending_eof). Waiting needs a new event for each new segment, which only edge-triggered event methods (epoll,
 * kqueue) deliver; with the others only a hello that has arrived completely is captured.
 */
ngx_int_t
ngx_http_clientfp_tls_hello(ngx_connection_t *c)
{
    int                           rc;
    u_char                       *raw;
    size_t                        size, msg_len, need;
    ssize_t                       n;
    ngx_err_t                     err;
    ngx_uint_t                    wait;
    const u_char                 *msg;
    ngx_http_connection_t        *hc;
    ngx_http_clientfp_tls_ctx_t  *ctx;
#if (NGX_HAVE_FIONREAD)
    int                           avail;
#endif

    hc = c->data;
    ctx = hc->clientfp;

    if (ctx == NULL) {
        ctx = ngx_http_clientfp_tls_create(c, hc);
        if (ctx == NULL) {
            return NGX_OK;
        }
    }

    if (ctx->captured) {
        return NGX_OK;
    }

    wait = (ngx_event_flags & NGX_USE_CLEAR_EVENT) ? 1 : 0;
    size = CLIENTFP_HELLO_RAW_MAX;

#if (NGX_HAVE_FIONREAD)

    if (ngx_socket_nread(c->fd, &avail) == -1) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, ngx_socket_errno, "clientfp: %s failed", ngx_socket_nread_n);
        ngx_http_clientfp_finish(c, ctx, CLIENTFP_HELLO_AGAIN, NULL, 0, 't');
        return NGX_OK;
    }

    if (avail < 0 || (size_t) avail < ctx->need) {
        if (wait && !c->read->pending_eof) {
            return NGX_AGAIN;
        }

        ngx_http_clientfp_finish(c, ctx, CLIENTFP_HELLO_AGAIN, NULL, 0, 't');
        return NGX_OK;
    }

    if ((size_t) avail < size) {
        size = (size_t) avail;
    }

#endif

    /* the peeked bytes, then CLIENTFP_HELLO_MAX bytes for a ClientHello split across records */

    raw = ngx_alloc(size + CLIENTFP_HELLO_MAX, c->log);
    if (raw == NULL) {
        ngx_http_clientfp_finish(c, ctx, CLIENTFP_HELLO_AGAIN, NULL, 0, 't');
        return NGX_OK;
    }

    n = recv(c->fd, (char *) raw, size, MSG_PEEK);
    err = ngx_socket_errno;

    if (n <= 0) {
        ngx_free(raw);

        if (n == -1 && err == NGX_EAGAIN && wait) {
            return NGX_AGAIN;
        }

        /* end of stream or an error: the handshake reports it */
        ngx_http_clientfp_finish(c, ctx, CLIENTFP_HELLO_AGAIN, NULL, 0, 't');
        return NGX_OK;
    }

    msg = NULL;
    msg_len = 0;
    need = 0;

    rc = clientfp_hello_tls(raw, (size_t) n, raw + size, &msg, &msg_len, &need);

    if (rc == CLIENTFP_HELLO_AGAIN && wait && !c->read->pending_eof
        && ++ctx->peeks < NGX_HTTP_CLIENTFP_MAX_PEEKS)
    {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "clientfp: ClientHello incomplete: %z of %uz bytes, peek %ui",
                       n, need, ctx->peeks);
        ctx->need = need;
        ngx_free(raw);
        return NGX_AGAIN;
    }

    ngx_http_clientfp_finish(c, ctx, rc, msg, msg_len, 't');
    ngx_free(raw);

    return NGX_OK;
}


#if (NGX_QUIC)

static void
ngx_http_clientfp_quic_cleanup(void *data)
{
    ngx_http_clientfp_tls_ctx_t  *ctx = data;

    if (ctx->quic) {
        ngx_free(ctx->quic);
        ctx->quic = NULL;
    }
}


/*
 * QUIC, called for each CRYPTO frame of an Initial packet until HTTP/3 initializes its session (c->data is still
 * the ngx_http_connection_t then). Frames may arrive in any order and overlap; the reassembly buffer is freed when
 * the capture finishes, or with the connection.
 */
void
ngx_http_clientfp_quic_crypto(ngx_connection_t *c, uint64_t offset, ngx_chain_t *data, size_t len)
{
    int                           rc;
    size_t                        n;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl;
    ngx_pool_cleanup_t           *cln;
    ngx_http_connection_t        *hc;
    ngx_http_clientfp_tls_ctx_t  *ctx;

    hc = c->data;
    ctx = hc->clientfp;

    if (ctx == NULL) {
        ctx = ngx_http_clientfp_tls_create(c, hc);
        if (ctx == NULL) {
            return;
        }

        cln = ngx_pool_cleanup_add(c->pool, 0);
        ctx->quic = ngx_alloc(sizeof(clientfp_hello_quic_t), c->log);

        if (cln == NULL || ctx->quic == NULL) {
            if (ctx->quic) {
                ngx_free(ctx->quic);
                ctx->quic = NULL;
            }

            ctx->captured = 1;
            return;
        }

        cln->handler = ngx_http_clientfp_quic_cleanup;
        cln->data = ctx;

        clientfp_hello_quic_init(ctx->quic);
    }

    if (ctx->captured) {
        return;
    }

    rc = CLIENTFP_HELLO_AGAIN;

    for (cl = data; cl && len && rc == CLIENTFP_HELLO_AGAIN; cl = cl->next) {
        b = cl->buf;
        n = (size_t) (b->last - b->pos);

        if (n > len) {
            n = len;
        }

        rc = clientfp_hello_quic_add(ctx->quic, offset, b->pos, n);

        offset += n;
        len -= n;
    }

    if (rc == CLIENTFP_HELLO_AGAIN) {
        return;
    }

    ngx_http_clientfp_finish(c, ctx, rc, ctx->quic->buf, ctx->quic->total, 'q');

    ngx_free(ctx->quic);
    ctx->quic = NULL;
}

#endif /* NGX_QUIC */

#endif /* NGX_HTTP_CLIENTFP_HELLO_HOOKS */


/* The connection's capture result, once it is complete. */
static ngx_http_clientfp_tls_ctx_t *
ngx_http_clientfp_tls_get(ngx_http_request_t *r)
{
#if (NGX_HTTP_CLIENTFP_HELLO_HOOKS)
    ngx_http_connection_t        *hc;
    ngx_http_clientfp_tls_ctx_t  *ctx;

#if (NGX_HTTP_V3)
    if (r->connection->quic) {
        hc = ngx_http_quic_get_connection(r->connection);

    } else
#endif
    {
        hc = r->http_connection;
    }

    if (hc == NULL) {
        return NULL;
    }

    ctx = hc->clientfp;

    return (ctx != NULL && ctx->captured) ? ctx : NULL;
#else
    return NULL;
#endif
}


/* ----------------------------------------------------------------------------------------------- JA4 */

static ngx_int_t
ngx_http_clientfp_ja4_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    ngx_str_t                    *s;
    ngx_http_clientfp_tls_ctx_t  *ctx;

    v->not_found = 1;

    ctx = ngx_http_clientfp_tls_get(r);

    if (ctx == NULL || ctx->status != CLIENTFP_OK) {
        return NGX_OK;
    }

    s = &ctx->cache[data];

    if (s->data == NULL) {
        /*
         * Cached in the pool of the TCP or QUIC connection: HTTP/2 and HTTP/3 requests run on per-stream
         * connections with shorter-lived pools.
         */
        p = ngx_pnalloc(ctx->pool, clientfp_ja4_max_len(&ctx->ja4, (clientfp_ja4_form_e) data));
        if (p == NULL) {
            return NGX_ERROR;
        }

        s->len = clientfp_ja4_format(&ctx->ja4, (clientfp_ja4_form_e) data, p);
        s->data = p;
    }

    v->data = s->data;
    v->len = s->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_clientfp_tlsfp_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_clientfp_tls_ctx_t  *ctx;

    static u_char  registry[] = { '0' + CLIENTFP_TLSFP_REGISTRY };

    v->not_found = 1;

    ctx = ngx_http_clientfp_tls_get(r);

    if (ctx == NULL || ctx->tlsfp_status != CLIENTFP_TLSFP_OK) {
        return NGX_OK;
    }

    if (data == NGX_HTTP_CLIENTFP_TLSFP_REGISTRY) {
        v->data = registry;
        v->len = sizeof(registry);

    } else {
        v->data = ctx->tlsfp;
        v->len = ctx->tlsfp_len;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


/* ------------------------------------------------------------------------------------------- HTTP/2 */

#if (NGX_HTTP_CLIENTFP_H2)

static clientfp_h2_t *
ngx_http_clientfp_h2_get(ngx_http_v2_connection_t *h2c)
{
    ngx_http_clientfp_h2_ctx_t     *ctx;
    ngx_http_clientfp_main_conf_t  *fmcf;

    if (h2c->clientfp) {
        return &((ngx_http_clientfp_h2_ctx_t *) h2c->clientfp)->fp;
    }

    fmcf = ngx_http_get_module_main_conf(h2c->http_connection->conf_ctx, ngx_http_clientfp_module);

    if (!fmcf->enable) {
        return NULL;
    }

    ctx = ngx_pcalloc(h2c->connection->pool, sizeof(ngx_http_clientfp_h2_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    h2c->clientfp = ctx;

    return &ctx->fp;
}


void
ngx_http_clientfp_h2_settings_frame(ngx_http_v2_connection_t *h2c, ngx_uint_t flags, size_t length)
{
    clientfp_h2_t  *fp = ngx_http_clientfp_h2_get(h2c);

    if (fp) {
        clientfp_h2_settings_frame(fp, (unsigned) flags, length);
    }
}


void
ngx_http_clientfp_h2_setting(ngx_http_v2_connection_t *h2c, ngx_uint_t id, ngx_uint_t value)
{
    clientfp_h2_t  *fp = ngx_http_clientfp_h2_get(h2c);

    if (fp) {
        clientfp_h2_setting(fp, (unsigned) id, (uint32_t) value);
    }
}


void
ngx_http_clientfp_h2_window_update(ngx_http_v2_connection_t *h2c, ngx_uint_t sid, size_t window)
{
    clientfp_h2_t  *fp = ngx_http_clientfp_h2_get(h2c);

    if (fp) {
        clientfp_h2_window_update(fp, (uint32_t) sid, (uint32_t) window);
    }
}


void
ngx_http_clientfp_h2_priority(ngx_http_v2_connection_t *h2c, ngx_uint_t sid, ngx_uint_t excl,
    ngx_uint_t depend, ngx_uint_t weight)
{
    clientfp_h2_t  *fp = ngx_http_clientfp_h2_get(h2c);

    if (fp) {
        clientfp_h2_priority(fp, (uint32_t) sid, (int) excl, (uint32_t) depend, (unsigned) weight);
    }
}


void
ngx_http_clientfp_h2_stream(ngx_http_v2_connection_t *h2c, ngx_uint_t sid)
{
    clientfp_h2_t  *fp = ngx_http_clientfp_h2_get(h2c);

    if (fp) {
        clientfp_h2_stream(fp, (uint32_t) sid);
    }
}


void
ngx_http_clientfp_h2_pseudo_header(ngx_http_v2_connection_t *h2c, ngx_uint_t sid, ngx_str_t *name)
{
    clientfp_h2_t  *fp = ngx_http_clientfp_h2_get(h2c);

    if (fp) {
        clientfp_h2_pseudo_header(fp, (uint32_t) sid, name->data, name->len);
    }
}


void
ngx_http_clientfp_h2_headers_done(ngx_http_v2_connection_t *h2c, ngx_uint_t sid)
{
    clientfp_h2_t  *fp = ngx_http_clientfp_h2_get(h2c);

    if (fp) {
        clientfp_h2_headers_done(fp, (uint32_t) sid);
    }
}

#endif


static ngx_int_t
ngx_http_clientfp_h2_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
#if (NGX_HTTP_CLIENTFP_H2)
    u_char                      *p, md[16];
    size_t                       n;
    ngx_md5_t                    md5;
    ngx_pool_t                  *pool;
    ngx_http_v2_connection_t    *h2c;
    ngx_http_clientfp_h2_ctx_t  *ctx;

    v->not_found = 1;

    if (r->stream == NULL) {
        return NGX_OK;
    }

    h2c = r->stream->connection;
    ctx = h2c->clientfp;

    if (ctx == NULL || !ctx->fp.frozen) {
        return NGX_OK;
    }

    pool = h2c->connection->pool;

    if (ctx->text.data == NULL) {
        p = ngx_pnalloc(pool, CLIENTFP_H2_MAX_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        n = clientfp_h2_format(&ctx->fp, p);

        ctx->text.data = p;
        ctx->text.len = n;
    }

    switch (data) {

    case NGX_HTTP_CLIENTFP_H2_TEXT:
        v->data = ctx->text.data;
        v->len = ctx->text.len;
        break;

    case NGX_HTTP_CLIENTFP_H2_HASH:
        if (ctx->hash.data == NULL) {
            p = ngx_pnalloc(pool, 32);
            if (p == NULL) {
                return NGX_ERROR;
            }

            ngx_md5_init(&md5);
            ngx_md5_update(&md5, ctx->text.data, ctx->text.len);
            ngx_md5_final(md, &md5);
            ngx_hex_dump(p, md, sizeof(md));

            ctx->hash.data = p;
            ctx->hash.len = 32;
        }

        v->data = ctx->hash.data;
        v->len = ctx->hash.len;
        break;

    default: /* NGX_HTTP_CLIENTFP_H2_OVERFLOW */
        v->data = (u_char *) (ctx->fp.overflow ? "1" : "0");
        v->len = 1;
        break;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

#else

    v->not_found = 1;

#endif

    return NGX_OK;
}


/* --------------------------------------------------------------------------------- header injection */

static ngx_int_t
ngx_http_clientfp_post_read_handler(ngx_http_request_t *r)
{
    ngx_str_t                      value;
    ngx_uint_t                     i, j, n, drop;
    ngx_list_t                     headers;
    ngx_list_part_t               *part;
    ngx_table_elt_t               *h, *nh;
    ngx_http_clientfp_header_t    *ch;
    ngx_http_clientfp_srv_conf_t  *cscf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_clientfp_module);

    if (cscf->headers == NULL || cscf->headers->nelts == 0) {
        return NGX_DECLINED;
    }

    ch = cscf->headers->elts;

    /* count the client's header lines to size the new list in one part */

    n = 0;

    for (part = &r->headers_in.headers.part; part; part = part->next) {
        n += part->nelts;
    }

    if (ngx_list_init(&headers, r->pool, n + cscf->headers->nelts, sizeof(ngx_table_elt_t)) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Copies keep every pointer nginx already holds (r->headers_in.host, ...) valid: the old list stays in
     * r->pool, and only names nginx does not parse itself are dropped (enforced at configuration time).
     */

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        drop = 0;

        for (j = 0; j < cscf->headers->nelts; j++) {
            if (h[i].key.len == ch[j].name.len
                && ngx_strncasecmp(h[i].key.data, ch[j].name.data, ch[j].name.len) == 0)
            {
                drop = 1;
                break;
            }
        }

        if (drop) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "clientfp: dropped client header \"%V: %V\"", &h[i].key, &h[i].value);
            continue;
        }

        nh = ngx_list_push(&headers);
        if (nh == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        *nh = h[i];
    }

    for (j = 0; j < cscf->headers->nelts; j++) {
        if (ngx_http_complex_value(r, &ch[j].value, &value) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (value.len == 0) {
            continue;
        }

        nh = ngx_list_push(&headers);
        if (nh == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        nh->hash = ch[j].hash;
        nh->key = ch[j].name;
        nh->value = value;
        nh->lowcase_key = ch[j].lowcase.data;
        nh->next = NULL;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "clientfp: added header \"%V: %V\"", &nh->key, &nh->value);
    }

    r->headers_in.headers = headers;

    return NGX_DECLINED;
}
