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
 * JA4: a msg_callback on every server SSL_CTX of http{} captures the first ClientHello of each connection,
 * parses it into compact lists (clientfp_ja4.c) kept in the connection pool, and the strings are formatted on
 * first use. OpenSSL is not patched.
 *
 * TLSFP (nDPI TLS client fingerprint, doc/tlsfp_sig.md): computed from the same first ClientHello by its own core
 * (clientfp_tlsfp.c), independently of JA4, once per handshake; only the 49-byte string is kept (decision 026).
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
 * Per TLS connection, in c->pool, attached to the SSL object with ex_data (its presence marks the first
 * ClientHello as seen). JA4 and TLSFP are independent: either may be missing while the other is present.
 */
typedef struct {
    ngx_int_t                   status;       /* CLIENTFP_OK or an error code */
    clientfp_ja4_t              ja4;
    ngx_str_t                   cache[4];     /* formatted forms, by clientfp_ja4_form_e */

    ngx_int_t                   tlsfp_status; /* CLIENTFP_TLSFP_OK or an error code */
    size_t                      tlsfp_len;
    u_char                      tlsfp[CLIENTFP_TLSFP_MAX_LEN];
} ngx_http_clientfp_ja4_ctx_t;


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

static void ngx_http_clientfp_msg_callback(int write_p, int version, int content_type, const void *buf,
    size_t len, SSL *ssl, void *arg);
static void *ngx_http_clientfp_palloc(void *pool, size_t size);
static ngx_int_t ngx_http_clientfp_ja4_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t ngx_http_clientfp_tlsfp_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t ngx_http_clientfp_h2_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t ngx_http_clientfp_post_read_handler(ngx_http_request_t *r);


static int  ngx_http_clientfp_ssl_index = -1;


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
    ngx_uint_t                      s;
    ngx_http_handler_pt            *h;
    ngx_http_ssl_srv_conf_t        *sscf;
    ngx_http_core_srv_conf_t      **cscfp;
    ngx_http_core_main_conf_t      *cmcf;
    ngx_http_clientfp_main_conf_t  *fmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    fmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_clientfp_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_clientfp_post_read_handler;

    if (!fmcf->enable) {
        return NGX_OK;
    }

    if (ngx_http_clientfp_ssl_index == -1) {
        ngx_http_clientfp_ssl_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

        if (ngx_http_clientfp_ssl_index == -1) {
            ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0, "SSL_get_ex_new_index() failed");
            return NGX_ERROR;
        }
    }

    /*
     * Every server SSL_CTX gets the callback: SSL_new() copies it from the default server's context of the
     * listen socket, before SNI selects the final server.
     */

    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (sscf == NULL || sscf->ssl.ctx == NULL) {
            continue;
        }

        SSL_CTX_set_msg_callback(sscf->ssl.ctx, ngx_http_clientfp_msg_callback);
    }

    return NGX_OK;
}


/* ----------------------------------------------------------------------------------------------- JA4 */

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


static void
ngx_http_clientfp_msg_callback(int write_p, int version, int content_type, const void *buf, size_t len,
    SSL *ssl, void *arg)
{
    char                          proto;
    const u_char                 *p = buf;
    ngx_connection_t             *c;
    ngx_http_clientfp_ja4_ctx_t  *ctx;

    if (write_p || content_type != SSL3_RT_HANDSHAKE || len < 4 || p[0] != SSL3_MT_CLIENT_HELLO) {
        return;
    }

    /* only the first ClientHello: not the one after a HelloRetryRequest, nor a renegotiation */

    if (ngx_http_clientfp_ssl_index == -1 || SSL_get_ex_data(ssl, ngx_http_clientfp_ssl_index) != NULL) {
        return;
    }

    c = ngx_ssl_get_connection(ssl);
    if (c == NULL || c->pool == NULL) {
        return;
    }

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_http_clientfp_ja4_ctx_t));
    if (ctx == NULL) {
        return;
    }

    proto = (c->listening && c->listening->quic) ? 'q' : 't';

    ctx->status = clientfp_ja4_parse(&ctx->ja4, p, len, proto, ngx_http_clientfp_palloc, c->pool);

    if (ctx->status != CLIENTFP_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "clientfp: no JA4 for this connection: %s ClientHello (%uz bytes)",
                      ctx->status == CLIENTFP_ETOOBIG ? "oversized" :
                      ctx->status == CLIENTFP_ENOMEM ? "out of memory for" : "malformed", len);
    }

    /* TLSFP: its own parse of the same message; uncapped lists, temporary memory released before return */

    ctx->tlsfp_status = clientfp_tlsfp_compute(p, len, proto, ctx->tlsfp, &ctx->tlsfp_len,
                                               ngx_http_clientfp_tmp_alloc, ngx_http_clientfp_tmp_free, c->log);

    if (ctx->tlsfp_status != CLIENTFP_TLSFP_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "clientfp: no TLSFP for this connection: %s ClientHello (%uz bytes)",
                      ctx->tlsfp_status == CLIENTFP_TLSFP_ENOMEM ? "out of memory for" : "malformed", len);
    }

    if (SSL_set_ex_data(ssl, ngx_http_clientfp_ssl_index, ctx) == 0) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_ex_data() failed");
    }
}


static ngx_int_t
ngx_http_clientfp_ja4_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    size_t                          n;
    u_char                         *p;
    ngx_str_t                      *s;
    ngx_connection_t               *c, *tc;
    ngx_http_clientfp_ja4_ctx_t    *ctx;
    ngx_http_clientfp_main_conf_t  *fmcf;

    v->not_found = 1;

    fmcf = ngx_http_get_module_main_conf(r, ngx_http_clientfp_module);
    c = r->connection;

    if (!fmcf->enable || c->ssl == NULL || c->ssl->connection == NULL || ngx_http_clientfp_ssl_index == -1) {
        return NGX_OK;
    }

    ctx = SSL_get_ex_data(c->ssl->connection, ngx_http_clientfp_ssl_index);

    if (ctx == NULL || ctx->status != CLIENTFP_OK) {
        return NGX_OK;
    }

    s = &ctx->cache[data];

    if (s->data == NULL) {
        /*
         * Cache in the pool of the connection that owns the SSL object: HTTP/2 and HTTP/3 requests run on
         * per-stream connections that share it.
         */
        tc = ngx_ssl_get_connection(c->ssl->connection);
        if (tc == NULL) {
            return NGX_OK;
        }

        p = ngx_pnalloc(tc->pool, clientfp_ja4_max_len(&ctx->ja4, (clientfp_ja4_form_e) data));
        if (p == NULL) {
            return NGX_ERROR;
        }

        n = clientfp_ja4_format(&ctx->ja4, (clientfp_ja4_form_e) data, p);
        if (n == 0) {
            return NGX_OK;
        }

        s->data = p;
        s->len = n;
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
    ngx_connection_t               *c;
    ngx_http_clientfp_ja4_ctx_t    *ctx;
    ngx_http_clientfp_main_conf_t  *fmcf;

    static u_char  registry[] = { '0' + CLIENTFP_TLSFP_REGISTRY };

    v->not_found = 1;

    fmcf = ngx_http_get_module_main_conf(r, ngx_http_clientfp_module);
    c = r->connection;

    if (!fmcf->enable || c->ssl == NULL || c->ssl->connection == NULL || ngx_http_clientfp_ssl_index == -1) {
        return NGX_OK;
    }

    ctx = SSL_get_ex_data(c->ssl->connection, ngx_http_clientfp_ssl_index);

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
