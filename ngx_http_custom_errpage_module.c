// Copyright 2017-2018 liwq

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t         uri;
} ngx_http_custom_errpage_conf_t;


typedef struct {
    ngx_uint_t                done;
    ngx_uint_t                status;
    ngx_http_request_t       *subrequest;
} ngx_http_custom_errpage_ctx_t;


static ngx_command_t  ngx_http_custom_errpage_commands[] = {

    { ngx_string("custom_errpage_request"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_custom_errpage_request,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_custom_errpage_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_custom_errpage_create_conf,   /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_custom_errpage_module = {
    NGX_MODULE_V1,
    &ngx_http_custom_errpage_module_ctx,   /* module context */
    ngx_http_custom_errpage_commands,      /* module directives */
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


static void *
ngx_http_custom_errpage_create_conf(ngx_conf_t *cf)
{
    ngx_http_custom_errpage_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_custom_errpage_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->uri = { 0, NULL };
     */

    return conf;
}


static char *
ngx_http_custom_errpage_request(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_custom_errpage_conf_t *cecf = conf;

    ngx_str_t        *value;

    if (cecf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        cecf->uri.len = 0;
        cecf->uri.data = (u_char *) "";

        return NGX_CONF_OK;
    }

    cecf->uri = value[1];

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    if (clcf == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf->handler = ngx_http_custom_errpage_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_custom_errpage_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_custom_errpage_ctx_t   *ctx = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "custom errpage subrequest done s:%ui",
                   r->headers_out.status);

    ctx->done = 1;

    if (rc != NGX_OK) {
        ctx->status = NGX_HTTP_NOT_FOUND;
        return NGX_OK;
    }

    ctx->status = r->headers_out.status;

    return rc;
}



static ngx_int_t
ngx_http_custom_errpage_handler(ngx_http_request_t *r)
{
    ngx_str_t                        args;
    ngx_buf_t                       *b;
    ngx_chain_t                      out;
    ngx_http_request_t              *sr;
    ngx_http_post_subrequest_t      *ps;
    ngx_http_custom_errpage_ctx_t   *ctx;
    ngx_http_custom_errpage_conf_t  *cecf;

    cecf = ngx_http_get_module_loc_conf(r, ngx_http_auth_request_module);

    if (cecf->uri.len == 0) {
        return NGX_DECLINED;
    }

    if (r->args.len == 0) {
        return NGX_DECLINED;
    }
    // ngx_str_set(args, "test");
    args = r->args;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_request_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        if (ctx->status == NGX_HTTP_OK) {
            r->headers_out.content_type_len = sizeof("text/html") - 1;
            ngx_str_set(&r->headers_out.content_type, "text/html");
            r->headers_out.content_type_lowcase = NULL;

            r->headers_out.content_length_n =
                r->upstream->buffer.last - r->upstream->buffer.pos;

            ngx_http_clear_accept_ranges(r);
            ngx_http_clear_last_modified(r);
            ngx_http_clear_etag(r);

            rc = ngx_http_send_header(r);
            if (rc == NGX_ERROR) {
                return NGX_DECLINED;
            }
            b = ngx_calloc_buf(r->pool);
            if (b == NULL) return NGX_ERROR;
            b->start = r->upstream->buffer.pos;
            b->pos   = r->upstream->buffer.pos;
            b->last  = r->upstream->buffer.last;
            b->end   = r->upstream->buffer.last;
            b->last_buf = 1;

            out.buf = b;
            out.next = NULL;
            return ngx_http_output_filter(r, &out);
        }

        return NGX_DECLINED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_request_ctx_t));
    if (ctx == NULL) {
        return NGX_DECLINED;
    }

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_DECLINED;
    }

    ps->handler = ngx_http_custom_errpage_done;
    ps->data = ctx;

    if (ngx_http_subrequest(r, &cecf->uri, &args, &sr, ps,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY|
                            NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    // sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    // if (sr->request_body == NULL) {
    //     return NGX_DECLINED;
    // }

    ctx->subrequest = sr;

    ngx_http_set_ctx(r, ctx, ngx_http_auth_request_module);

    return NGX_AGAIN;
}
