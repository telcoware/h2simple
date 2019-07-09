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

#include "h2.h"
#include "h2_priv.h"


/* global variables representing the entry class */
h2_cls h2_cls_cls  = { { NULL }, "h2_cls_cls"  };
h2_cls h2_cls_strm = { { &h2_cls_cls }, "h2_cls_strm" };
h2_cls h2_cls_sess = { { &h2_cls_cls }, "h2_cls_sess" };
h2_cls h2_cls_peer = { { &h2_cls_cls }, "h2_cls_peer" };
h2_cls h2_cls_svr  = { { &h2_cls_cls }, "h2_cls_svr"  };
h2_cls h2_cls_ctx  = { { &h2_cls_cls }, "h2_cls_ctx"  };


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
 * Message Send APIs ------------------------------------------------------
 */

/* Send HTTP request to the remote peer */
int h2_send_request(h2_sess *sess, h2_msg *req,
                    h2_strm_free_cb strm_free_cb, void *strm_user_data) {

  if (sess->http_ver == H2_HTTP_V2) {
    return h2_send_request_v2(sess, req, strm_free_cb, strm_user_data);
  } else {
    return h2_send_request_v1_1(sess, req, strm_free_cb, strm_user_data);
  }
}

int h2_send_response(h2_sess *sess, h2_strm *strm, h2_msg *rsp) {
  if (sess->http_ver == H2_HTTP_V2) {
    return h2_send_response_v2(sess, strm, rsp);
  } else {
    return h2_send_response_v1_1(sess, strm, rsp);
  }
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
  if (sess->http_ver == H2_HTTP_V2) {
     return h2_send_push_promise_v2(sess, request_strm, prm_req, prm_rsp);
  } else {
    warnx("%s[%d] Push promise is NOT available on HTTP/1.1 session",
          sess->log_prefix, request_strm->stream_id);
    return -1;
  }
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
      return -1;
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
      return -1;
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
    h2_sess_free_v2(sess);
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

