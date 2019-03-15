/*
 * h2sim - HTTP2 Simple Application Framework using nghttp2
 *
 * Copyright 2019 Lee Yongjae, Telcoware Co.,LTD.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __h2_h__
#define __h2_h__

#include <stdio.h>
#include <stdint.h>


/* opaque type defintions */
typedef struct h2_msg h2_msg;
typedef struct h2_strm h2_strm;
typedef struct h2_sess h2_sess;
typedef struct h2_svr h2_svr;
typedef struct h2_ctx h2_ctx;


/* TLS utilities --------------------------------------------------------  */

#ifdef TLS_MODE
#include <openssl/ssl.h>
SSL_CTX *h2_ssl_ctx_init(int is_server/* else client */,
                         const char *key_file, const char *cert_file);
  /* returned pointer is to be freed by SSL_CTX_free(SSL_CTX *ssl_ctx) */
#else
typedef void SSL_CTX;
#endif

 
/* Messages utilities ----------------------------------------------------- */

/* h2 message management */
h2_msg *h2_msg_init(void);
void h2_msg_free(h2_msg *msg);

/* h2 mesage prepare utilities */
void h2_cpy_msg(h2_msg *dst, h2_msg *src);
void h2_prepare_rsp(h2_msg *rsp, h2_msg *ref_req);
void h2_prepare_prm(h2_msg *prm, h2_msg *ref_req,
                    const char *method, const char *path);

/* get message psuedo headers */
const char *h2_method(h2_msg *req);
const char *h2_scheme(h2_msg *req);
const char *h2_authority(h2_msg *req);
const char *h2_path(h2_msg *req);
int h2_status(h2_msg *rsp);

/* set message psuedo headers */
void h2_set_method(h2_msg *req, const char *method);
void h2_set_scheme(h2_msg *req, const char *scheme);
void h2_set_authority(h2_msg *req, const char *authority);
void h2_set_path(h2_msg *req, const char *path);
void h2_set_status(h2_msg *rsp, int status);

/* set request message's scheme, authority and path */
int h2_set_req_uri(h2_msg *req, const char *uri);
  /* returns 0(success), <0(error) */

/* get message header */
const char *h2_hdr_value(h2_msg *msg, const char *name);
  /* returns NULL if not found */

/* append message header */
int h2_add_hdr(h2_msg *msg, const char *name, const char *value);
int h2_add_hdr_n(h2_msg *msg, const char *name, int name_len,
                 const char *value, int value_len);
int h2_add_hdr_s(h2_msg *msg, const char *name_value_str);
  /* returns 1(added), 0(no add for null value) or <0(error) */
  /* NOTE: put operation does not check duplication */

/* update message header */
int h2_set_hdr(h2_msg *msg, const char *name, const char *value);
  /* update or add header; delete if value=null */
  /* returns 1(added), 0(same value), 2(delete by null value) or <0(error) */

/* delete message header */
int h2_del_hdr(h2_msg *msg, const char *name);
  /* returns 1(deleted), 0(not found) or <0(error) */

/* copy message headers */
int h2_cpy_hdr(h2_msg *dst, h2_msg *src, const char *name);
  /* add header from src to dst if the header found in src */
  /* returns 1(added), 0(not found) or <0(error) */

/* header array access */
int h2_hdr_num(h2_msg *msg);
const char *h2_hdr_idx_name(h2_msg *msg, int hdr_idx);
const char *h2_hdr_idx_value(h2_msg *msg, int hdr_idx);

/* messageo body utility */
void *h2_body(h2_msg *msg);
int h2_body_len(h2_msg *msg);
int h2_set_body(h2_msg *msg, void *body, int body_len);
  /* body SHOULD be malloced and set as it is and */
  /* not to be freed by the caller after this call */
  /* returns 1(valid body), 0(null body) or <0(error) */
int h2_cpy_body(h2_msg *msg, void *body, int body_len);
  /* assigne msg body by copied from given body */
  /* returns 1(valid body), 0(null body) or <0(error) */

/* message dump utility */
void h2_dump_msg(FILE *fp, h2_msg *msg, const char *line_prefix,
                 const char *msg_name_fmt, ...);


/* Session Common API Calls and Callbacks -------------------------------- */

/* to be called at session, stream, server socket is closed */
/* for the user to free user_data */
typedef void (*h2_sess_free_cb)(h2_sess *sess, void *sess_user_data);
typedef void (*h2_strm_free_cb)(h2_strm *strm, void *strm_user_data);
typedef void (*h2_svr_free_cb)(h2_svr *svr, void *svr_user_data);

/* trigger to terminate session; session is destroyed later */
int h2_sess_terminate(h2_sess *sess);
  /* returns: 0(terminated), 1(already terminated), <(error) */
  /* NOTE: there might be more message receives after this call */


/* Client Side API Calls and Callbacks ----------------------------------- */

/* client side callbacks */
typedef int (*h2_response_cb)(h2_sess *sess, h2_msg *rsp,
                    void *sess_user_data, void *strm_user_data);
  /* returns: 0(ok), 0<(error) */
typedef int (*h2_push_promise_cb)(
                    h2_sess *sess, h2_msg *prm_req,
                    void *sess_user_data, void *strm_user_data,
                    h2_strm_free_cb *push_strm_free_cb_ret,
                    void **push_strm_user_data_ret);
  /* returns: 0(ok), <0(error; send RST_STREAM on push promise stream) */
typedef int (*h2_push_response_cb)(
                    h2_sess *sess, h2_msg *prm_rsp,
                    void *sess_user_data, void *push_strm_user_data);
  /* returns: 0(ok), 0<(error) */

/* client side context create api to start session */
h2_sess *h2_connect(h2_ctx *ctx, const char *authority, SSL_CTX *cli_ssl_ctx,
                    h2_response_cb response_cb, 
                    h2_push_promise_cb push_promise_cb,
                    h2_push_response_cb push_response_cb,
                    h2_sess_free_cb sess_free_cb, void *sess_user_data);
  /* cls_ssl_ctx=NULL for tcp mode */

/* h2 client application api for request */
int h2_send_request(h2_sess *sess, h2_msg *req,
                    h2_strm_free_cb strm_free_cb, void *strm_user_data);


/* Server Session API Calls and Callbacks -------------------------------- */

typedef int (*h2_request_cb)(h2_sess *sess, h2_strm *strm,
                    h2_msg *req, void *sess_user_data);
  /* returns: 0(msg handled), >0(status code for no-body rsp), 0<(error) */

/* h2 server application api for response */
int h2_send_response(h2_sess *sess, h2_strm *strm, h2_msg *rsp);
int h2_send_response_simple(h2_sess *sess, h2_strm *strm, h2_msg *ref_req,
                    int status, const char *content_type,
                    void *body, int body_len);
  /* conent_type and body might be NULL */
int h2_send_push_promise(h2_sess *sess, h2_strm *strm,
                    h2_msg *prm_req, h2_msg *prm_rsp);
  /* strm is of request callback's */


/* Server Accept Session API Calls and Callbacks ------------------------- */

typedef int (*h2_accept_cb)(h2_svr *svr, void *svr_user_data,
                    const char *peer_ip, unsigned short peer_port,
                    /* return parameters for accepted sess */
                    SSL_CTX **sess_ssl_ctx_ret,
                    h2_request_cb *request_cb_ret,
                    h2_sess_free_cb *sess_free_cb_ret,
                    void **sess_user_data_ret);
  /* returns: 0(ok), <0(error; close session) */
  /* on ok, set *sess_free_cb_ret for *sess_user_data_ret for accepted sess */
  /* else *sess_free_cb_ret and *sess_user_data_ret are ignored */ 
  /* if *sess_ssl_ctx_ret is set non NULL, it is used instead of svr_ssl_ctx */
 
/* server listen socket binding api; authority is key as well as binding addr */
h2_svr *h2_listen(h2_ctx *ctx, const char *authority, SSL_CTX *svr_ssl_ctx,
                  h2_accept_cb accept_cb,
                  h2_svr_free_cb svr_free_cb, void *svr_user_data);
void h2_svr_free(h2_svr *svr);
  /* removes listen socket only; connected session are not affected */

const char *h2_svr_authority(h2_svr *svr);
SSL_CTX *h2_svr_ssl_ctx(h2_svr *svr);


/* H2 Service Context ---------------------------------------------------- */

h2_ctx *h2_ctx_init(int verbose);
void h2_ctx_free(h2_ctx *ctx);
void h2_ctx_run(h2_ctx *ctx);
void h2_ctx_stop(h2_ctx *ctx);  /* mark ctx run look stop */
void h2_ctx_set_verbose(h2_ctx *ctx, int verbose);


/* Message Body Utilities ------------------------------------------------ */
/* NOTE: this is just for utility; pron to be changed */

int h2_body_from_hex_str(char *hex_str, void **body_ret, int *body_len_ret);
int h2_body_from_file(char *file, void **body_ret, int *body_len_ret);
  /* returns dynamic alloced data via *body_ret */



#endif  /* __h2_h__ */

