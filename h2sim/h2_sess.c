/*
 * h2sim - HTTP2 Simple Application Framework using nghttp2
 *
 * Copyright (c) 2019 Lee Yongjae, Telcoware Co.,LTD.
 *
 * All rights reserved.
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

#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>    /* for gettimeofday */
#include <sys/types.h>
#include <sys/socket.h>  /* for shutdown() */
#ifdef EPOLL_MODE
#include <sys/epoll.h>
#endif

#include <nghttp2/nghttp2.h>

#include "h2.h"
#include "h2_priv.h"


/* global variables representing the entry class */
h2_cls h2_cls_cls  = { { NULL }, "h2_cls_cls"  };
h2_cls h2_cls_strm = { { &h2_cls_cls }, "h2_cls_strm" };
h2_cls h2_cls_sess = { { &h2_cls_cls }, "h2_cls_sess" };
h2_cls h2_cls_peer = { { &h2_cls_cls }, "h2_cls_peer" };
h2_cls h2_cls_svr  = { { &h2_cls_cls }, "h2_cls_svr"  };
h2_cls h2_cls_ctx  = { { &h2_cls_cls }, "h2_cls_ctx"  };

/* HTTP/1.1 reason values per status */
static char *http_status_reason[5][20] = {
  { /*100*/"Continue",
    /*101*/"Switching Protocols"
  },
  { /*200*/"OK",
    /*201*/ "Created",
    /*202*/"Accepted",
    /*203*/"Non-Authoritative Information",
    /*204*/"No Content",
    /*205*/"Reset Content",
    /*206*/"Partial Content",
  },
  { /*300*/"Multiple Choices",
    /*301*/"Moved Permanently",
    /*302*/"Found",
    /*303*/"See Other",
    /*304*/"Not Modified",
    /*305*/"Use Proxy",
    /*307*/"Temporary Redirect"
  },
  {
    /*400*/"Bad Request",
    /*401*/"Unauthorized",
    /*402*/"Payment Required",
    /*403*/"Forbidden",
    /*404*/"Not Found",
    /*405*/"Method Not Allowed",
    /*406*/"Not Acceptable",
    /*407*/"Proxy Authentication Required",
    /*408*/"Request Time-out",
    /*409*/"Conflict",
    /*410*/"Gone",
    /*411*/"Length Required",
    /*412*/"Precondition Failed",
    /*413*/"Request Entity Too Large",
    /*414*/"Request-URI Too Large",
    /*415*/"Unsupported Media Type",
    /*416*/"Requested range not satisfiable",
    /*417*/"Expectation Failed"
  },
  {
    /*500*/"Internal Server Error",
    /*501*/"Not Implemented",
    /*502*/"Bad Gateway",
    /*503*/"Service Unavailable",
    /*504*/"Gateway Time-out",
    /*505*/"HTTP Version not supported"
  }
};


/* forward declaration */
static void h2_cpy_read_data_prd(nghttp2_data_provider *data_prd, 
                                 h2_strm *strm, void *data, int size);
static void h2_set_read_data_prd(nghttp2_data_provider *data_prd, 
                                 h2_strm *strm, void *data, int size);


/*
 * NGHTTP2 Header Utilities ------------------------------------------------
 */

static int ng_hdr_append(nghttp2_nv *hdr_tbl, int *hdr_num, int hdr_max,
                      const char *name, const char *value)
{
  if (*hdr_num >= hdr_max) {
    warnx("hdr_tbl is full: hdr_max=%d", hdr_max);
    return -1;
  }

  nghttp2_nv *nv = &hdr_tbl[(*hdr_num)++];
  nv->name = (uint8_t *)name;
  nv->value = (uint8_t *)value;
  nv->namelen = strlen(name);
  nv->valuelen = strlen(value);
  nv->flags = NGHTTP2_NV_FLAG_NONE;
  // NOTE: PERF: NGHTTP@_NV_FLAG_NO_INDEX shows inferior performance

  return 0;
}

static void ng_print_header(FILE *f, const char *name, int namelen,
                            const char *value, int value_len,
                            const char *prefix, int stream_id) {
  fprintf(f, "%s[%d]     %-16.*s = %.*s\n",
          prefix, stream_id, namelen, name, value_len, value);
}

static void ng_print_headers(FILE *f, nghttp2_nv *nva, size_t nvlen,
                   const char *prefix, int stream_id) {
  size_t i;
  for (i = 0; i < nvlen; ++i) {
    ng_print_header(f, (char *)nva[i].name, nva[i].namelen,
                    (char *)nva[i].value, nva[i].valuelen,
                    prefix, stream_id);
  }
}


/*
 * Stream Utilities ---------------------------------------------------------
 */

h2_strm *h2_strm_init(h2_sess *sess, int stream_id, int recv_msg_type,
                      h2_strm_free_cb strm_free_cb, void *strm_user_data) {
  /* alloc and init stream data */
  h2_strm *strm = calloc(1, sizeof(h2_strm));
  strm->obj.cls = &h2_cls_strm;

  /* append to session's stream list */
#if 1
  h2_strm *st = &sess->strm_list_head;
  while (st->next) {
    st = st->next;
  }
  strm->next = NULL;
  st->next = strm;
  strm->prev = st;
#else
  strm->next = sess->strm_list_head.next;
  sess->strm_list_head.next = strm;
  strm->prev = &sess->strm_list_head;
  if (strm->next) {
    strm->next->prev = strm;
  }
#endif

  strm->stream_id = stream_id;
  strm->recv_msg_type = recv_msg_type;
  switch (recv_msg_type) {
  case H2_REQUEST:       strm->send_msg_type = H2_RESPONSE;      break;
  case H2_RESPONSE:      strm->send_msg_type = H2_REQUEST;       break;
  case H2_PUSH_PROMISE:  strm->send_msg_type = H2_PUSH_PROMISE;  break;
  case H2_PUSH_RESPONSE: strm->send_msg_type = H2_PUSH_RESPONSE; break;
       /* special handling on PUSH_PROMISE/RESPONSE */
  }
  strm->rmsg = h2_msg_init();

  strm->strm_free_cb = strm_free_cb;
  strm->user_data = strm_user_data;
  return strm;
}

void h2_strm_free(h2_strm *strm) {

  /* free user_data */
  if (strm->strm_free_cb) {
    strm->strm_free_cb(strm, strm->user_data);
    strm->strm_free_cb = NULL;
    strm->user_data = NULL;
  }

  /* remove from session's stream list */
  strm->prev->next = strm->next;
  if (strm->next) {
    strm->next->prev = strm->prev;
  }

  /* clean and dealloc stream data */
  if (strm->rmsg) {
    h2_msg_free(strm->rmsg);
    strm->rmsg = NULL;
  }
  if (strm->send_body_rb.to_be_freed) {
    free(strm->send_body_rb.data);
  }
  strm->stream_id = 0;  /* to check invalidattion */

  // HERE: TOOD: here goes the application logic: deallocate user_data

  free(strm);
}


/*
 * HTTP/1.1 Message Send ---------------------------------------------------
 */

static int h2_send_request_v1_1(h2_sess *sess, h2_msg *req,
                         h2_strm_free_cb strm_free_cb, void *strm_user_data) {
  char *p, *buf;
  int i, buf_len;

  if (sess->is_server) {
    warnx("%scannot send request for sess is not client sess\n",
          sess->log_prefix);
    return -1;
  }
  if (sess->is_terminated) {
    warnx("%scannot send request for sess is terminated\n", sess->log_prefix);
    return -1;
  }

  /* NOTE: buf should contain extra headers */
  buf_len = 64 + h2_sbuf_used(&req->sbuf) + h2_hdr_num(req) * 4 + 
            req->body_len + 1;
  buf = malloc(buf_len);

  /* set header */
  p = buf;
  p += sprintf(p, "%s %s HTTP/1.1\r\n", h2_method(req), h2_path(req));
  p += sprintf(p, "host: %s\r\n", h2_authority(req));
  if (req->body && req->body_len > 0) {
    p += sprintf(p, "content-length: %d\r\n", req->body_len);
  }
  for (i = 0; i < req->hdr_num; i++) {
    p += sprintf(p, "%s: %s\r\n",
                 h2_hdr_idx_name(req, i), h2_hdr_idx_value(req, i));
  }
  p += sprintf(p, "\r\n");

  /* set body */
  if (req->body && req->body_len > 0) {
    memcpy(p, req->body, req->body_len);
    p += req->body_len;
  }
  *p = '\0';  /* mark NULL at the end of message */

  /* ASSUME: success */ /* TODO: handled error case */
  h2_strm *strm = h2_strm_init(sess, 2 * sess->req_cnt + 1, H2_RESPONSE,
                               strm_free_cb, strm_user_data);
  sess->req_cnt++;
  strm->is_req = 1;

  /* set send message as read data buf */
  h2_set_read_data_prd(NULL, strm, buf, p - buf);
  sess->send_data_remain += strm->send_body_rb.data_size;

  return h2_sess_send(sess);
}

static int h2_send_response_v1_1(h2_sess *sess, h2_strm *strm, h2_msg *rsp) {
  char *p, *buf, *reason = NULL;
  int s, i, j, buf_len;

  s = h2_status(rsp); 
  i = s / 100;
  j = s % 100;
  if (i >= 1 && i <= 5 && j >= 0 && j <= 19) {
    reason = http_status_reason[i - 1][j];
  }
  if (reason == NULL) {
    reason = "Unknown";
  }

  buf_len = 64 + h2_sbuf_used(&rsp->sbuf) + h2_hdr_num(rsp) * 4 + rsp->body_len;
  buf = malloc(buf_len);

  /* set header */
  p = buf;
  p += sprintf(p, "%d %s\r\n", s, reason);
  if (rsp->body && rsp->body_len > 0) {
    p += sprintf(p, "content-length: %d\r\n", rsp->body_len);
  }
  for (i = 0; i < rsp->hdr_num; i++) {
    p += sprintf(p, "%s: %s\r\n",
                 h2_hdr_idx_name(rsp, i), h2_hdr_idx_value(rsp, i));
  }
  p += sprintf(p, "\r\n");

  /* set body */
  if (rsp->body && rsp->body_len > 0) {
    memcpy(p, rsp->body, rsp->body_len);
    p += rsp->body_len;
  }

  /* set send message as read data buf */
  h2_set_read_data_prd(NULL, strm, buf, p - buf);

  /* mark response to send */
  strm->response_set = 1;
  sess->send_data_remain += strm->send_body_rb.data_size;
  sess->rsp_cnt++;

  h2_sess_mark_send_pending(sess);
  return 0;
}


/*
 * NGHTTP2 Message Send APIs -----------------------------------------------
 */

static ssize_t ng_send_msg_body_cb(nghttp2_session *ng_sess,
                    int32_t stream_id, uint8_t *buf, size_t length,
                    uint32_t *data_flags, nghttp2_data_source *source,
                    void *user_data) {
  h2_read_buf *rb = source->ptr;
  h2_sess *sess = user_data;
  (void)ng_sess;
  (void)stream_id;

  int n = rb->data_size - rb->data_used;
  if (n > (int)length) {
    n = (int)length;
  }
  if (n > 0) {
    memcpy(buf, &rb->data[rb->data_used], n);
  }

  /* dump out response body */
  if (sess->ctx->verbose) {
    if (n == rb->data_size)
      fprintf(stderr, "%s[%d] %s DATA(%d):\n",
              sess->log_prefix, stream_id,
              h2_msg_type_str(rb->send_msg_type), n);
    else
      fprintf(stderr, "%s[%d] %s DATA(%d+%d/%d):\n",
              sess->log_prefix, stream_id,
              h2_msg_type_str(rb->send_msg_type),
              rb->data_used, n, rb->data_size);
    fwrite(buf, 1, n, stdout);
    if (n >= 1 && buf[n - 1] != '\n' && buf[0] != '\0') {
      fwrite("\n", 1, 1, stdout);
    }
    fflush(stdout);
  }

  rb->data_used += n;
  if (rb->data_used >= rb->data_size) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  } else {
    //fprintf(stderr, "DEBUG: %s[%d] REMAINS DATA: %d sess.send_data_remain=%d\n",
    //        sess->log_prefix, stream_id, rb->data_size - rb->data_used,
    //        sess->send_data_remain);
  }

  sess->send_data_remain -= n;
  return n;
}

static void h2_cpy_read_data_prd(nghttp2_data_provider *data_prd, 
                                 h2_strm *strm, void *data, int size) {
  /* ASSUME: data!=null, size>0 */
  h2_read_buf *read_buf = &strm->send_body_rb;
  read_buf->data = malloc(size + 1);
  memcpy(read_buf->data, data, size);
  read_buf->data[size] = '\0';
  read_buf->data_size = size;
  read_buf->data_used = 0;
  read_buf->to_be_freed = 1;
  read_buf->send_msg_type = strm->send_msg_type;
  if (data_prd) {
    data_prd->source.ptr = read_buf;
    data_prd->read_callback = ng_send_msg_body_cb;
  }
}

static void h2_set_read_data_prd(nghttp2_data_provider *data_prd, 
                                 h2_strm *strm, void *data, int size) {
  /* ASSUME: data!=null, size>0 */
  /* NOTE: the caller should not free data */
  h2_read_buf *read_buf = &strm->send_body_rb;
  read_buf->data = data;
  read_buf->data_size = size;
  read_buf->data_used = 0;
  read_buf->to_be_freed = 1;
  read_buf->send_msg_type = strm->send_msg_type;
  if (data_prd) {
    data_prd->source.ptr = read_buf;
    data_prd->read_callback = ng_send_msg_body_cb;
  }
}

/* Send HTTP request to the remote peer */
int h2_send_request(h2_sess *sess, h2_msg *req,
                    h2_strm_free_cb strm_free_cb, void *strm_user_data) {

  if (sess->http_ver != H2_HTTP_V2) {
    return h2_send_request_v1_1(sess, req, strm_free_cb, strm_user_data);
  }

#define REQ_HDR_MAX  (5 + H2_MSG_HDR_MAX)
  nghttp2_nv ng_hdr[REQ_HDR_MAX];
  int ng_hdr_num = 0;
  int stream_id, i;
  char s[1][32];

  if (sess->is_terminated) {
    warnx("%scannot send request for sess is terminated\n", sess->log_prefix);
    return -1;
  }

  ng_hdr_append(ng_hdr, &ng_hdr_num, REQ_HDR_MAX, ":method", h2_method(req));
  ng_hdr_append(ng_hdr, &ng_hdr_num, REQ_HDR_MAX, ":scheme", h2_scheme(req));
  ng_hdr_append(ng_hdr, &ng_hdr_num, REQ_HDR_MAX, ":authority",
                                                             h2_authority(req));
  ng_hdr_append(ng_hdr, &ng_hdr_num, REQ_HDR_MAX, ":path", h2_path(req));
  /* TODO: content-length MUST NOT be sent if  transfer-encoding is set. */
  /*       (rfc7230 3.3.2. Content-Length) */
  if (req->body && req->body_len > 0) {
    sprintf(s[0], "%d", req->body_len);
    ng_hdr_append(ng_hdr, &ng_hdr_num, REQ_HDR_MAX, "content-length", s[0]);
  }
  for (i = 0; i < req->hdr_num; i++) {
    ng_hdr_append(ng_hdr, &ng_hdr_num, REQ_HDR_MAX,
                  h2_hdr_idx_name(req, i), h2_hdr_idx_value(req, i));
  }

  /* ASSUME: success */ /* TODO: handled error case */
  h2_strm *strm = h2_strm_init(sess, 0, H2_RESPONSE,
                               strm_free_cb, strm_user_data);

  /* set send message body read handler */
  nghttp2_data_provider data_prd_buf, *data_prd = NULL;
  if (req->body && req->body_len > 0) {
    h2_cpy_read_data_prd(&data_prd_buf, strm, req->body, req->body_len);
    data_prd = &data_prd_buf;
  }

  stream_id = nghttp2_submit_request(sess->ng_sess, NULL,
                                     ng_hdr, ng_hdr_num, data_prd, strm);
  if (stream_id < 0) {
    warnx("%sCannot not submit HTTP request: %s",
          sess->log_prefix, nghttp2_strerror(stream_id));
    h2_strm_free(strm);
    return -2;
  }
  strm->is_req = 1;
  strm->stream_id = stream_id;
  sess->send_data_remain += strm->send_body_rb.data_size;
  sess->req_cnt++;

  if (sess->ctx->verbose) {
    fprintf(stderr, "%s[%d] REQUEST HEADER:\n",
            sess->log_prefix, stream_id);
    ng_print_headers(stderr, ng_hdr, ng_hdr_num, sess->log_prefix, stream_id);
  }

  //h2_sess_mark_send_pending(sess);
  h2_sess_send(sess);
  return 0;
}

int h2_send_response(h2_sess *sess, h2_strm *strm, h2_msg *rsp) {

  if (sess->http_ver != H2_HTTP_V2) {
    return h2_send_response_v1_1(sess, strm, rsp);
  }

#define RSP_HDR_MAX  (2 + H2_MSG_HDR_MAX)
  nghttp2_nv ng_hdr[RSP_HDR_MAX];
  int ng_hdr_num = 0;
  int i, r;
  char s[2][32];

  sprintf(s[0], "%d", rsp->status);
  ng_hdr_append(ng_hdr, &ng_hdr_num, RSP_HDR_MAX, ":status", s[0]);
  if (rsp->body && rsp->body_len > 0) {
    sprintf(s[1], "%d", rsp->body_len);
    ng_hdr_append(ng_hdr, &ng_hdr_num, RSP_HDR_MAX, "content-length", s[1]);
  }
  for (i = 0; i < rsp->hdr_num; i++) {
    ng_hdr_append(ng_hdr, &ng_hdr_num, RSP_HDR_MAX,
                  h2_hdr_idx_name(rsp, i), h2_hdr_idx_value(rsp, i));
  }

  /* set response body read handler */
  nghttp2_data_provider data_prd_buf, *data_prd = NULL;
  if (rsp->body && rsp->body_len > 0) {
    h2_cpy_read_data_prd(&data_prd_buf, strm, rsp->body, rsp->body_len);
    data_prd = &data_prd_buf;
  }

  /* mark response sent to prevent further push_promise */
  strm->response_set = 1;
  sess->send_data_remain += strm->send_body_rb.data_size;

  r = nghttp2_submit_response(sess->ng_sess, strm->stream_id,
                               ng_hdr, ng_hdr_num, data_prd);
  if (r != 0) {
    warnx("%s[%d] Fatal error: %d:%s",
          sess->log_prefix, strm->stream_id, r, nghttp2_strerror(r));
    return -1;
  }

  if (sess->ctx->verbose) {
    fprintf(stderr, "%s[%d] %s HEADER:\n",
            sess->log_prefix, strm->stream_id,
            h2_msg_type_str(strm->send_msg_type));
    ng_print_headers(stderr, ng_hdr, ng_hdr_num,
                     sess->log_prefix, strm->stream_id);
  }

  h2_sess_mark_send_pending(sess);
  return 0;
}

int h2_send_response_simple(h2_sess *sess, h2_strm *strm, h2_msg *ref_req,
                            int status, const char *content_type,
                            void *body, int body_len) {
  /* use temporary static message */
  h2_msg rsp;
  h2_msg_init_static(&rsp);
  h2_prepare_rsp(&rsp, ref_req);
  if (content_type) {
    h2_add_hdr(&rsp, "content-type", content_type);
  }
  rsp.status = status;
  rsp.body = body;
  rsp.body_len = body_len;

  if (h2_send_response(sess, strm, &rsp) < 0) {
    return -1;
  }

  rsp.body = NULL;
  rsp.body_len = 0;
  h2_msg_clean_static(&rsp);
  return 0;
}

int h2_send_push_promise(h2_sess *sess, h2_strm *request_strm,
                         h2_msg *prm_req, h2_msg *prm_rsp) {

  /* ASSUME PUSH_PROMISE request has no body */

#define PRM_HDR_MAX  (5 + H2_MSG_HDR_MAX)
  nghttp2_nv ng_hdr[REQ_HDR_MAX];
  int ng_hdr_num = 0;
  int stream_id, i;

  if (sess->http_ver != H2_HTTP_V2) {
    warnx("%s[%d] Push promise is NOT available on HTTP/1.1 session",
          sess->log_prefix, request_strm->stream_id);
    return -1;
  }
  if (request_strm->response_set) {
    warnx("%s[%d] Push promise should be sent before orignal response",
          sess->log_prefix, request_strm->stream_id);
    return -1;
  }

  /* send PUSH_PROMISE with request headers */

  ng_hdr_append(ng_hdr, &ng_hdr_num, PRM_HDR_MAX, ":method", h2_method(prm_req));
  ng_hdr_append(ng_hdr, &ng_hdr_num, PRM_HDR_MAX, ":scheme", h2_scheme(prm_req));
  ng_hdr_append(ng_hdr, &ng_hdr_num, PRM_HDR_MAX, ":authority", h2_authority(prm_req));
  ng_hdr_append(ng_hdr, &ng_hdr_num, PRM_HDR_MAX, ":path", h2_path(prm_req));
  for (i = 0; i < prm_req->hdr_num; i++) {
    ng_hdr_append(ng_hdr, &ng_hdr_num, PRM_HDR_MAX,
                  h2_hdr_idx_name(prm_req, i), h2_hdr_idx_value(prm_req, i));
  }
  /* ASSUME: prm_req has no body */

  h2_strm *strm = h2_strm_init(sess, 0, H2_PUSH_PROMISE, NULL, NULL);

  stream_id = nghttp2_submit_push_promise(sess->ng_sess,
                               NGHTTP2_FLAG_NONE,
                               request_strm->stream_id,
                               ng_hdr, ng_hdr_num, strm);
  if (stream_id < 0) {
    warnx("%sCannot not submit HTTP push promise: %s",
          sess->log_prefix, nghttp2_strerror(stream_id));
    h2_strm_free(strm);
    return -1;
  }
  strm->stream_id = stream_id;

  if (sess->ctx->verbose) {
    fprintf(stderr, "%s[%d] PUSH_PROMISE(%d)\n",
            sess->log_prefix, request_strm->stream_id,
            strm->stream_id);
    ng_print_headers(stderr, ng_hdr, ng_hdr_num,
                     sess->log_prefix, request_strm->stream_id);
  }

  /* send push response HEADERS with reponse headers and body */
  strm->send_msg_type = H2_PUSH_RESPONSE;
  return h2_send_response(sess, strm, prm_rsp);
}


/*
 * Internal Integration Handlers --------------------------------------------
 */

int h2_on_request_recv(h2_sess *sess, h2_strm *strm) {
  /* check request headers */
  if (!strm->rmsg->method || !strm->rmsg->authority || !strm->rmsg->path) {
    warnx("%s[%d] request psuedo header missing; send 400 response",
          sess->log_prefix, strm->stream_id);
    if (h2_send_response_simple(sess, strm, strm->rmsg, 400,
                                NULL, NULL, 0) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  int rs = 404;
  if (sess->request_cb) {
    rs = sess->request_cb(sess, strm, strm->rmsg, sess->user_data);
  }

  if (rs < 0) {
#if 1
    /* TODO: log and do response as 500 Internal Server Error */
    warnx("%s[%d] request_cb returns error; send 500 response: ret=%d",
          sess->log_prefix, strm->stream_id, rs);
    rs = 500;
#else 
    /* TEST for RST STREAM */
    warnx("%s[%d] request_cb returns error(%d); send RST_STREAM",
          sess->log_prefix, rs, strm->stream_id);
    nghttp2_submit_rst_stream(sess->ng_sess, NGHTTP2_FLAG_NONE,
                              strm->stream_id, 0);
#endif
  }

  if (rs > 0) {
    if (h2_send_response_simple(sess, strm, strm->rmsg, rs,
                                NULL, NULL, 0) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

int h2_on_response_recv(h2_sess *sess, h2_strm *strm) {
  /* TODO: check response header */
  if (sess->response_cb) {
    int ret = sess->response_cb(sess, strm->rmsg,
                                sess->user_data, strm->user_data);
    if (ret < 0) {
      warnx("%s[%d] response_cb failed; go ahead: ret=%d",
            sess->log_prefix, strm->stream_id, ret);
    }
  }
  if (strm->is_req) {
    sess->rsp_cnt++;
    if (sess->is_terminated == 2 && 
        sess->req_cnt == sess->rsp_cnt &&
        sess->send_data_remain <= 0) {
      h2_sess_terminate(sess, 0);
    }
  }
  return 0;
}

static int h2_on_rst_stream_recv(h2_sess *sess, h2_strm *strm) {
  if (strm->is_req) {
    /* resposnse_cb is called with NULL rsp */
    if (sess->response_cb) {
      int ret = sess->response_cb(sess, NULL,
                                  sess->user_data, strm->user_data);
      if (ret < 0) {
        warnx("%s[%d] response_cb for RST_STREAM failed; go ahead: ret=%d",
              sess->log_prefix, strm->stream_id, ret);
      }
    }
    sess->rsp_rst_cnt++;
    sess->rsp_cnt++;  /* for req-rsp count matching */
    if (sess->is_terminated == 2 && 
        sess->req_cnt == sess->rsp_cnt &&
        sess->send_data_remain <= 0) {
      h2_sess_terminate(sess, 0);
    }
  }
  return 0;
}

static int h2_on_push_promise_recv(h2_sess *sess, h2_strm *req_strm,
                                   h2_strm *prm_strm) {
  /* TODO: check response header */
  if (sess->push_promise_cb) {
    /* NOTE: now, strm->user_data is request_stream.user_data */
    /* HERE: TODO: NEED TO assign new field for org request_stream_user_data */
    h2_strm_free_cb push_strm_free_cb = NULL;
    void *push_strm_user_data = NULL;
    int r = sess->push_promise_cb(sess, prm_strm->rmsg,
                                  sess->user_data, req_strm->user_data,
                                  &push_strm_free_cb, &push_strm_user_data);
    if (r < 0) {
      warnx("%s[%d] push_promise_callback failed; reset: ret=%d",
            sess->log_prefix, req_strm->stream_id, r);
    } else {
      prm_strm->strm_free_cb = push_strm_free_cb;
      prm_strm->user_data = push_strm_user_data;
      return 0;
    }
  }
  /* else, RST promise stream */
  prm_strm->strm_free_cb = NULL;
  prm_strm->user_data = NULL;  /* invaliadate stream user_data */
  nghttp2_submit_rst_stream(sess->ng_sess, NGHTTP2_FLAG_NONE,
                            prm_strm->stream_id, NGHTTP2_REFUSED_STREAM);
  return 0;
}

static int h2_on_push_response_recv(h2_sess *sess, h2_strm *prm_strm) {
  /* TODO: check response header */
  if (sess->push_response_cb) {
    int ret = sess->push_response_cb(sess, prm_strm->rmsg,
                                     sess->user_data, prm_strm->user_data);
    if (ret < 0) {
      warnx("%s[%d] on_push_promise_callback failed; go ahead: ret=%d",
            sess->log_prefix, prm_strm->stream_id, ret);
    }
  }
  return 0;
}


/*
 * NGHTTP2 Session Callbacks h2_sess ----------------------------------------
 */

static int ng_header_cb(nghttp2_session *ng_sess,
                       const nghttp2_frame *frame, const uint8_t *name,
                       size_t name_len, const uint8_t *_value,
                       size_t value_len, uint8_t flags, void *user_data) {
  h2_strm *strm;
  h2_sess *sess = (h2_sess *)user_data;
  const char *value = (const char *)_value;
  (void)flags;

  /* NOTE: cannot batch process in on_frame_recived_callback */
  /*       because frame.headers.nva is not valid on this case */

  int is_request = 0;
  if (frame->hd.type == NGHTTP2_HEADERS &&
      (strm = nghttp2_session_get_stream_user_data(ng_sess,
                         frame->hd.stream_id)) &&
      strm->stream_id == frame->hd.stream_id) {
    if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
      is_request = 1;
    }
  } else if (frame->hd.type == NGHTTP2_PUSH_PROMISE &&
      (strm = nghttp2_session_get_stream_user_data(ng_sess,
                         frame->push_promise.promised_stream_id)) &&
      strm->stream_id == frame->push_promise.promised_stream_id) {
    is_request = 1;
  } else {
    warnx("%s[%d] UNKNOWN HEADER FRAME; ignore: "
          "frame.hd.type=%d frame.headers.cat=%d",
          sess->log_prefix, frame->hd.stream_id,
          frame->hd.type, frame->headers.cat);
    return 0;
  }

  h2_msg *msg = strm->rmsg;
  if (name[0] == ':') {  /* psuedo heaers */
    if (is_request) {
      if (name_len == 7 && !memcmp(":method", name, name_len)) {
        msg->method = h2_sbuf_put_n(&msg->sbuf, value, value_len);
      } else if (name_len == 7 && !memcmp(":scheme", name, name_len)) {
        msg->scheme = h2_sbuf_put_n(&msg->sbuf, value, value_len);
      } else if (name_len == 10 && !memcmp(":authority", name, name_len)) {
        msg->authority = h2_sbuf_put_n(&msg->sbuf, value, value_len);
      } else if (name_len == 5 && !memcmp(":path", name, name_len)) {
        /* TODO: NEED TO DECODE URI ENCODING(PERCENT ENCOOED) */
        /*
        char *req_path = percent_decode(value, value_len);
        h2_phdr_put(msg, &msg->path, req_path, strlen(req_path));
        free(req_path);
        */
        msg->path = h2_sbuf_put_n(&msg->sbuf, value, value_len);
      } else {
        warnx("%s[%d] Unknown psuedo header for request; ignore: %.*s=%.*s",
              sess->log_prefix, strm->stream_id,
              (int)name_len, name, (int)value_len, value);
      }
    } else {  /* response case */
      if (name_len == 7 && !memcmp(":status", name, name_len) &&
          value_len == 3 &&
          isdigit(value[0]) && isdigit(value[1]) && isdigit(value[2])) {
        msg->status = ((int)(value[0] - '0') * 100 +
                       (int)(value[1] - '0') * 10 +
                       (int)(value[2] - '0'));
      } else {
        warnx("%s[%d] Invalid psuedo header for response; ignore: %.*s=%.*s",
              sess->log_prefix, strm->stream_id,
              (int)name_len, name, (int)value_len, value);
      }
    }
  } else {
    /* normal headers */
    h2_add_hdr_n(msg, (char *)name, name_len, value, value_len);

    /* TODO: NEED TO HANDLE content-lenght header for body buffer pre-alloc */
  }

  if (sess->ctx->verbose) {
    ng_print_header(stderr, (char *)name, name_len, value, value_len,
                    sess->log_prefix, frame->hd.stream_id);
  }
  return 0;
}

static int ng_begin_hdr_cb(nghttp2_session *ng_sess,
                           const nghttp2_frame *frame, void *user_data) {
  /* NOTE: on_header_recv_callback and on_frame_recv_callback are called */
  /*       after this callback */

  h2_sess *sess = (h2_sess *)user_data;
  h2_strm *strm, *promise_strm;

  if (frame->hd.type == NGHTTP2_HEADERS) {
    if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
      /* server side */
      strm = h2_strm_init(sess, frame->hd.stream_id, H2_REQUEST, NULL, NULL);
      nghttp2_session_set_stream_user_data(ng_sess, frame->hd.stream_id,
                                           strm);
    } else if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      /* client side */
      strm = nghttp2_session_get_stream_user_data(ng_sess, frame->hd.stream_id);
    } else if (frame->headers.cat == NGHTTP2_HCAT_PUSH_RESPONSE) {
      /* client side; after PUSH_PROMISE */
      strm = nghttp2_session_get_stream_user_data(ng_sess, frame->hd.stream_id);
      /* reinit for push_response */
      h2_msg_free(strm->rmsg);
      strm->recv_msg_type = H2_PUSH_RESPONSE;
      strm->rmsg = h2_msg_init();
    } else {
      warnx("%s[%d] UNKNOWN BEGIN HEADER; ignore: "
            "frame.hd.type=%d frame.headers.cat=%d",
            sess->log_prefix, frame->hd.stream_id,
            frame->hd.type, frame->headers.cat);
      return 0;
    }
    if (sess->ctx->verbose) {
      fprintf(stderr, "%s[%d] %s HEADER:\n",
              sess->log_prefix, frame->hd.stream_id,
              h2_msg_type_str(strm->recv_msg_type));
    }
  } else if (frame->hd.type == NGHTTP2_PUSH_PROMISE) {
    /* client side; prepare push promise session data */
    strm = nghttp2_session_get_stream_user_data(ng_sess, frame->hd.stream_id);
    promise_strm = h2_strm_init(sess, frame->push_promise.promised_stream_id,
                                H2_PUSH_PROMISE, NULL, NULL);
    nghttp2_session_set_stream_user_data(ng_sess,
                                frame->push_promise.promised_stream_id,
                                promise_strm);
    if (sess->ctx->verbose) {
      fprintf(stderr, "%s[%d] %s (%d):\n",
              sess->log_prefix, frame->hd.stream_id,
              h2_msg_type_str(promise_strm->recv_msg_type),
              frame->push_promise.promised_stream_id);
    }
  } else {
    warnx("%s[%d] UNKNOWN BEGIN HEADER; ignore: "
          "frame.hd.type=%d frame.headers.cat=%d",
          sess->log_prefix, frame->hd.stream_id,
          frame->hd.type, frame->headers.cat);
  }

  return 0;
}

static int ng_frame_recv_cb(nghttp2_session *ng_sess,
                            const nghttp2_frame *frame, void *user_data) {
  /* NOTE: NGHTTP2 handles CONTINUATION FRAME internally; do not consider */
  /* NOTE: cannot batch process in on_frame_recived_callback */
  /*       because frame.headers.nva is not valid on this case */

  h2_sess *sess = (h2_sess *)user_data;
  h2_strm *strm = NULL;
  h2_strm *request_strm, *promised_strm;

  switch (frame->hd.type) {
  case NGHTTP2_DATA:     /* called after on_data_chunk_recevied */
  case NGHTTP2_HEADERS:
    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) &&
        (strm ||
         (strm = nghttp2_session_get_stream_user_data(ng_sess,
                                                      frame->hd.stream_id))) &&
        strm->stream_id == frame->hd.stream_id) {
      switch (strm->recv_msg_type) {
      case H2_REQUEST:       return h2_on_request_recv(sess, strm);
      case H2_RESPONSE:      return h2_on_response_recv(sess, strm);
      case H2_PUSH_RESPONSE: return h2_on_push_response_recv(sess, strm);
      }
    }
    break;

  case NGHTTP2_PUSH_PROMISE:
    /* note promised_stream_id alread created */
    if ((frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) &&
        (request_strm = nghttp2_session_get_stream_user_data(ng_sess,
                                    frame->hd.stream_id)) &&
        ((promised_strm = strm) ||
          (promised_strm = nghttp2_session_get_stream_user_data(ng_sess,
                                    frame->push_promise.promised_stream_id))) &&
        request_strm->stream_id == frame->hd.stream_id &&
        promised_strm->stream_id == frame->push_promise.promised_stream_id) {
      h2_on_push_promise_recv(sess, request_strm, promised_strm);
    }
    break;

  case NGHTTP2_RST_STREAM:
    warnx("%s[%d] RST_STREAM RECEIVED", sess->log_prefix, frame->hd.stream_id);
    if ((strm ||
         (strm = nghttp2_session_get_stream_user_data(ng_sess,
                                                      frame->hd.stream_id))) &&
        strm->stream_id == frame->hd.stream_id) {
      h2_on_rst_stream_recv(sess, strm);
    }
    break;
  }

  return 0;
}

static int ng_data_cb(nghttp2_session *ng_sess, uint8_t flags,
                      int32_t stream_id, const uint8_t *data,
                      size_t len, void *user_data) {
  h2_sess *sess = (h2_sess *)user_data;
  h2_strm *strm;
  (void)flags;

  strm = nghttp2_session_get_stream_user_data(ng_sess, stream_id);
  if (strm == NULL || strm->stream_id != stream_id || len <= 0) {
    return 0;
  }

  /* TODO: pre-alloc body buffer if content-length header detected */
  /*       add h2_msg.body_alloced_size */

  h2_msg *msg = strm->rmsg;
  if (msg->body) {
    msg->body = (uint8_t *)realloc(msg->body, msg->body_len + len + 1);
  } else {
    msg->body = (uint8_t *)malloc(len + 1);
  }
  if (len > 0) {
    memcpy(&msg->body[msg->body_len], data, len);
    msg->body_len += len;
  }
  msg->body[msg->body_len] = '\0';  /* mark zero at the end of body buf */

  /* TODO: do total data chunk size counting per session */

  if (sess->ctx->verbose) {
    fprintf(stderr, "%s[%d] %s DATA(%d):\n",
            sess->log_prefix, stream_id,
            h2_msg_type_str(strm->recv_msg_type), (int)len);
    fwrite(data, 1, len, stdout);
    if (len >= 1 && data[len - 1] != '\n' && data[0] != '\0') {
      fwrite("\n", 1, 1, stdout);
    }
    fflush(stdout);
  }

  // HERE: TODO: here comes the application logic: data chunk received 
  
  return 0;
}

static int ng_strm_close_cb(nghttp2_session *ng_sess, int32_t stream_id,
                            uint32_t error_code, void *user_data) {
  h2_sess *sess = (h2_sess *)user_data;
  h2_strm *strm;

  if (sess->ctx->verbose) {
    fprintf(stderr, "%s[%d] END OF STREAM (%u)\n",
            sess->log_prefix, stream_id, error_code);
  }

  strm = nghttp2_session_get_stream_user_data(ng_sess, stream_id);
  if (strm == NULL || strm->stream_id != stream_id) {
    return 0;
  }

  sess->strm_close_cnt++;
  sess->send_data_remain -=
    (strm->send_body_rb.data_size - strm->send_body_rb.data_used);
  h2_strm_free(strm);
  nghttp2_session_set_stream_user_data(ng_sess, stream_id, NULL);

  return 0;
}

static int ng_error2_cb(nghttp2_session *ng_sess, int lib_error_code,
                        const char *msg, size_t len, void *user_data) {
  h2_sess *sess = (h2_sess *)user_data;
  (void)ng_sess;

  warnx("%s### NGHTTP2_ERROR: error=%d:%s msg[%d]=%s",
        sess->log_prefix, 
        lib_error_code, nghttp2_strerror(lib_error_code), (int)len, msg);

  return 0;
}


/*
 * Session Management -------------------------------------------------------
 */

inline char *h2_sess_close_reason_str(h2_sess *sess) {
  if (sess->close_reason == CLOSE_BY_NGHTTP2_END && sess->is_terminated) {
     return "sess term";
  }
  return ((sess->close_reason == CLOSE_BY_SOCK_EOF)?    "socket closed" :
          (sess->close_reason == CLOSE_BY_SOCK_ERR)?    "socket error" :
          (sess->close_reason == CLOSE_BY_SSL_ERR)?     "SSL error" :
          (sess->close_reason == CLOSE_BY_NGHTTP2_ERR)? "nghttp2 error" :
          (sess->close_reason == CLOSE_BY_NGHTTP2_END)? "nghttp2 end" :
          (sess->close_reason == CLOSE_BY_HTTP_ERR)?    "http error" :
          (sess->close_reason == CLOSE_BY_HTTP_END)?    "http end" :
          "unknown");
}

void h2_sess_nghttp2_init(h2_sess *sess) {
  nghttp2_session_callbacks *cbs;

  nghttp2_session_callbacks_new(&cbs);
  nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, ng_begin_hdr_cb);
  nghttp2_session_callbacks_set_on_header_callback(cbs, ng_header_cb);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, ng_data_cb);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, ng_frame_recv_cb);
  nghttp2_session_callbacks_set_on_stream_close_callback(cbs, ng_strm_close_cb);
  nghttp2_session_callbacks_set_error_callback2(cbs, ng_error2_cb);
  if (sess->is_server) {
    nghttp2_session_server_new(&sess->ng_sess, cbs, sess);
  } else {
    nghttp2_session_client_new(&sess->ng_sess, cbs, sess);
  }
  nghttp2_session_callbacks_del(cbs);
}

void h2_sess_free(h2_sess *sess) {
  /* show performance */
  gettimeofday(&sess->tv_end, NULL);
  double elapsed =
     ((sess->tv_end.tv_sec - sess->tv_begin.tv_sec) * 1.0 +
      (sess->tv_end.tv_usec - sess->tv_begin.tv_usec) * 0.000001);

  if (sess->is_server) {
    fprintf(stderr, "%sDISCONNECTED%s%s: %.0f tps (%.3f secs for %d streams)\n",
            sess->log_prefix,
            (sess->close_reason)? " by " : "",
            (sess->close_reason)? h2_sess_close_reason_str(sess) : "",
            sess->strm_close_cnt / elapsed, elapsed, sess->strm_close_cnt);
  } else {
    fprintf(stderr, "%sDISCONNECTED%s%s: %.0f tps (%.3f secs for "
            "%d reqs %d rsps %d streams)%s\n",
            sess->log_prefix,
            (sess->close_reason)? " by " : "",
            (sess->close_reason)? h2_sess_close_reason_str(sess) : "",
            sess->strm_close_cnt / elapsed, elapsed,
            sess->req_cnt, sess->rsp_cnt, sess->strm_close_cnt,
            (sess->req_cnt != sess->rsp_cnt)? " !!!" : "");
  }

  if (sess->fd >= 0) {
#ifdef EPOLL_MODE
    epoll_ctl(sess->ctx->epoll_fd, EPOLL_CTL_DEL, sess->fd, NULL);
    if (epoll_ctl(sess->ctx->epoll_fd, EPOLL_CTL_DEL, sess->fd, NULL) < 0) {
      /* for linux <= 2.9.0 */
      struct epoll_event e;
      memset(&e, 0, sizeof(e));
      epoll_ctl(sess->ctx->epoll_fd, EPOLL_CTL_DEL, sess->fd, &e);
    }
#endif
    /* NOTE: close() SHOULD be called event when shutdown() is called */
    shutdown(sess->fd, SHUT_RDWR);
    close(sess->fd);
    sess->fd = -1;
  }

  if (sess->ng_sess) {
    nghttp2_session_del(sess->ng_sess);
    sess->ng_sess = NULL;
  }

#ifdef TLS_MODE
  if (sess->ssl) {
    SSL_shutdown(sess->ssl);
    SSL_free(sess->ssl);
    sess->ssl = NULL;
  }
#endif

  /* free streams */
  h2_strm *strm = sess->strm_list_head.next;
  while (strm) {
    h2_strm *next = strm->next;
    sess->send_data_remain -=
      (strm->send_body_rb.data_size - strm->send_body_rb.data_used);
    h2_strm_free(strm);
    strm = next;
  }

  /* free user_data */
  if (sess->sess_free_cb) {
    sess->sess_free_cb(sess, sess->user_data);
    sess->sess_free_cb = NULL;
    sess->user_data = NULL;
  }

  if (sess->send_data_remain) {
    warnx("%sSESS FREE BUT SEND_DATA REMAINS: %d\n",
           sess->log_prefix, sess->send_data_remain);
  }

  /* free http1.1 context */
  if (sess->rdata) {
    free(sess->rdata);
    sess->rdata = NULL;
    sess->rdata_alloced = 0;
    sess->rdata_size = 0;
    sess->rdata_used = 0;
  }
  sess->strm_recving = NULL;
  sess->strm_sending = NULL;

  /* delete from ctx sess list */
  sess->prev->next = sess->next;
  if (sess->next) {
    sess->next->prev = sess->prev;
  }
  sess->ctx->sess_num--;

  // HERE: TODO: here comes the application logic: session removed 
  //app_context *app_ctx = session->ctx->application_data;

  sess->ctx = NULL;
  free(sess->log_prefix);
  free(sess);
}

h2_ctx *h2_sess_ctx(h2_sess *sess) {
  return (sess)? sess->ctx : NULL;
}

