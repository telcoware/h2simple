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
                      h2_response_cb response_cb, void *strm_user_data) {
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

  strm->response_cb = response_cb;
  strm->user_data = strm_user_data;
  return strm;
}

void h2_strm_free(h2_strm *strm) {

  /* free user_data */
  strm->response_cb = NULL;
  strm->user_data = NULL;

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
  if (strm->send_body_sb.to_be_freed) {
    free(strm->send_body_sb.data);
  }
  strm->stream_id = 0;  /* to check invalidattion */

  // HERE: TOOD: here goes the application logic: deallocate user_data

  free(strm);
}


/*
 * Client Messaging APIs ---------------------------------------------------
 */

/* Send HTTP request to the remote peer */
static int h2_sess_send_request(h2_sess *sess, h2_msg *req,
                         h2_response_cb response_cb, void *strm_user_data) {
  if (sess->is_server) {
    warnx("%scannot send request for sess is not client sess\n",
          sess->log_prefix);
    return -1;
  }
  if (sess->is_terminated || sess->is_no_more_req) {
    warnx("%scannot send request for sess is terminated\n", sess->log_prefix);
    return -1;
  }

  if (sess->http_ver == H2_HTTP_V2) {
    return h2_send_request_v2(sess, req, response_cb, strm_user_data);
  } else {
    return h2_send_request_v1_1(sess, req, response_cb, strm_user_data);
  }
}

/* h2 client application api for request on peer with sess load balancing */
int h2_send_request(h2_peer *peer, h2_msg *req,
                    h2_response_cb response_cb, void *strm_user_data) {
  h2_sess *sess = NULL;
  int i, r, n = peer->sess_num, nsi = peer->next_sess_idx;

  if (peer->is_terminated || peer->is_no_more_req) {
    warnx("cannot send request for peer is terminated: %s\n", peer->authority);
    return -1;
  }

  /* find active session with round-robin load balancing */
  for (i = 0; i < n; i++) {
    int si = (nsi + i) % n;
    if ((sess = peer->sess[si]) && peer->act_sess[si])  {
      /* house keep for to-be-terminated of HTTP/2 */
      if (peer->req_max_per_sess > 0 &&
          sess->req_cnt >= peer->req_max_per_sess &&
          peer->act_sess_num >= peer->sess_num) {
        /* terminate for too may requests handled */
        if (peer->act_sess[si]) {  /* update before sess terminate call */
          peer->act_sess[si] = 0;
          peer->act_sess_num--;
        }
        h2_sess_terminate(sess, 1/* wait_rsp */);
        sess = NULL;  /* try other sess */
      } else {
        /* use this session */
        break;
      }
    }
  }
  peer->next_sess_idx = (nsi + i + 1) % n;  /* advances even no valid sess */

  if (sess == NULL) {
    /* TODO: try to connect server */
  }

  if (sess) {
    r = h2_sess_send_request(sess, req, response_cb, strm_user_data);
  } else {
    warnx("no session available to peer: %s", peer->authority);
    r = -1;
  }

  /* try to house keep till act_sess_num */
  if (sess && peer->act_sess_num < peer->sess_num) {
    /* TODO: try to connect server */
  }

  return r;
}

/* terminalte all sessions on the peer */
int h2_terminate(h2_peer *peer, int wait_rsp) {
  int i;

  if (peer == NULL || peer->is_terminated) {
    return 1;
  }

  if (wait_rsp) {
    if (peer->is_no_more_req) {
      return 1;
    }
    peer->is_no_more_req = 1;
  }

  for (i = 0; i < peer->sess_num; i++) {
    if (peer->act_sess[i]) {
      peer->act_sess[i] = 0;
      peer->act_sess_num--;
    }
    h2_sess_terminate(peer->sess[i], wait_rsp);  /* go ahread even on error */
  }
  return 0;
}


/*
 * Server Messaging APIs ---------------------------------------------------
 */

/* Send HTTP request to the remote peer */

int h2_send_response(h2_sess *sess, h2_strm *strm, h2_msg *rsp) {
  if (!sess->is_server) {
    warnx("%scannot send response for sess is not server sess\n",
          sess->log_prefix);
    return -1;
  }
  if (sess->is_terminated) {
    warnx("%scannot send response for sess is terminated\n", sess->log_prefix);
    return -1;
  }

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
  if (!sess->is_server) {
    warnx("%scannot send request for sess is not server sess\n",
          sess->log_prefix);
    return -1;
  }
  if (request_strm->is_rsp_set) {
    warnx("%s[%d] Push promise should NOT be sent after orignal response",
          sess->log_prefix, request_strm->stream_id);
    return -1;
  }

  if (sess->http_ver == H2_HTTP_V2) {
     return h2_send_push_promise_v2(sess, request_strm, prm_req, prm_rsp);
  } else {
    warnx("%s[%d] Push promise is NOT available on HTTP/1.1 session",
          sess->log_prefix, request_strm->stream_id);
    return -1;
  }
}


/*
 * Receive Message Event Handlers -----------------------------------------
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
    /* TODO: log and do response as 500 Internal Server Error */
    warnx("%s[%d] request_cb returns error; send 500 response: ret=%d",
          sess->log_prefix, strm->stream_id, rs);
    rs = 500;
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
  if (strm->is_req) {
    if (strm->is_rsp_set) {
      warnx("%s[%d] response already handled before this response; ignore",
            sess->log_prefix, strm->stream_id);
      return -1;
    }
    if (strm->response_cb) {
      h2_peer *peer = sess->peer;
      int r = strm->response_cb(peer, strm->rmsg,
                                peer->user_data, strm->user_data);
      if (r < 0) {
        warnx("%s[%d] response_cb failed; go ahead: ret=%d",
              sess->log_prefix, strm->stream_id, r);
      }
    }
    strm->is_rsp_set = 1;
    sess->rsp_cnt++;
    if (sess->is_no_more_req && sess->req_cnt == sess->rsp_cnt) {
      h2_sess_terminate(sess, 0);
    }
  }
  return 0;
}


/*
 * HTTP/2-Only Receive Message Event Handlers -----------------------------
 */

int h2_on_rst_stream_recv(h2_sess *sess, h2_strm *strm) {
  /* NOTE: HTTP_V2 ONLY */
  if (strm->is_req && strm->is_rsp_set) {
    warnx("%s[%d] response already handled before this RST_STREAM; ignore",
          sess->log_prefix, strm->stream_id);
    return -1;
  }
  /* NOTE: response_cb might be called for push_response stream */
  if (strm->response_cb && !strm->is_rsp_set) {
    h2_peer *peer = sess->peer;
    int r = strm->response_cb(peer, NULL,
                              peer->user_data, strm->user_data);
    if (r < 0) {
      warnx("%s[%d] response_cb for RST_STREAM failed; go ahead: ret=%d",
            sess->log_prefix, strm->stream_id, r);
    }
    strm->is_rsp_set = 1;
  }
  if (strm->is_req) {
    /* NOTE: resposnse_cb is called with NULL rsp */
    sess->rsp_rst_cnt++;
    sess->rsp_cnt++;  /* for req-rsp count matching */
    if (sess->is_no_more_req && sess->req_cnt == sess->rsp_cnt) {
      h2_sess_terminate(sess, 0);
    }
  }
  return 0;
}

int h2_on_push_promise_recv(h2_sess *sess, h2_strm *req_strm,
                            h2_strm *prm_strm) {
  /* NOTE: HTTP_V2 ONLY */
  /* TODO: check response header */
  if (sess->peer && sess->peer->push_promise_cb) {
    /* NOTE: now, strm->user_data is request_stream.user_data */
    /* HERE: TODO: NEED TO assign new field for org request_stream_user_data */
    h2_peer *peer = sess->peer;
    h2_response_cb push_response_cb = NULL;
    void *push_strm_user_data = NULL;
    int r = peer->push_promise_cb(peer, prm_strm->rmsg,
                                  peer->user_data, req_strm->user_data,
                                  &push_response_cb, &push_strm_user_data);
    if (r < 0) {
      warnx("%s[%d] push_promise_callback failed; reset: ret=%d",
            sess->log_prefix, req_strm->stream_id, r);
    } else {
      prm_strm->response_cb = push_response_cb;
      prm_strm->user_data = push_strm_user_data;
      return 0;
    }
  }

  /* else, RST promise stream */
  prm_strm->response_cb = NULL;
  prm_strm->user_data = NULL;  /* invaliadate stream user_data */
  h2_send_rst_stream_v2(sess, prm_strm);
  return 0;
}

int h2_on_push_response_recv(h2_sess *sess, h2_strm *prm_strm) {
  /* NOTE: HTTP_V2 ONLY */
  /* TODO: check response header */
  if (sess->peer && prm_strm->response_cb) {
    h2_peer *peer = sess->peer;
    int ret = prm_strm->response_cb(peer, prm_strm->rmsg,
                                    peer->user_data, prm_strm->user_data);
    if (ret < 0) {
      warnx("%s[%d] on_push_promise_callback failed; go ahead: ret=%d",
            sess->log_prefix, prm_strm->stream_id, ret);
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
            "%d reqs %d rsps %d rsts %d streams)%s\n",
            sess->log_prefix,
            (sess->close_reason)? " by " : "",
            (sess->close_reason)? h2_sess_close_reason_str(sess) : "",
            sess->strm_close_cnt / elapsed, elapsed,
            sess->req_cnt, sess->rsp_cnt, sess->rsp_rst_cnt,
            sess->strm_close_cnt,
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
    if (strm->send_body_sb.data_size > strm->send_body_sb.data_used) {
      /*
      warnx("%sfree stream with remaining send data: "
            "stream_id=%d send_remaining=%d\n",
            sess->log_prefix, strm->stream_id,
            (int)(strm->send_body_sb.data_size - strm->send_body_sb.data_used));
      */
      sess->send_data_remain -=
        (strm->send_body_sb.data_size - strm->send_body_sb.data_used);
    }
    if (sess->peer && !strm->is_rsp_set && strm->response_cb) {
      /* NOTE: call response callback with rsp=NULL */
      h2_peer *peer = sess->peer;
      strm->response_cb(peer, NULL, peer->user_data, strm->user_data);
    }
    h2_strm_free(strm);
    strm = next;
  }

  /* free user_data for server session */
  if (sess->sess_free_cb) {
    sess->sess_free_cb(sess, sess->user_data);
    sess->sess_free_cb = NULL;
    sess->user_data = NULL;
  }

  /* sess free handling on peer */
  if (sess->peer) {
    h2_peer_sess_free_hdlr(sess->peer, sess);
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
  sess->peer = NULL;
  free(sess->log_prefix);
  free(sess);
}

h2_ctx *h2_sess_ctx(h2_sess *sess) {
  return (sess)? sess->ctx : NULL;
}


/*
 * Session Settings --------------------------------------------------------
 */

void h2_settings_init(h2_settings *settings) {
  /* HTTP/2 */
  settings->header_table_size = -1;
  settings->enable_push = -1;
  settings->max_concurrent_streams = -1;
  settings->initial_window_size = -1;
  settings->max_frame_size = -1;
  settings->max_header_list_size = -1;
  settings->enable_connect_protocol = -1;
  /* HTTP/1.1 */
  settings->single_req = 0;
  settings->keep_alive_timeout = H2_HTTP_V1_1_KEEP_ALIVE_TIMEOUT;
  settings->keep_alive_max = H2_HTTP_V1_1_KEEP_ALIVE_MAX;
}

int h2_set_settings(h2_settings *settings, char *id_value_str)
  /* id_value_str is <id>=<value> formatted string */
  /* returns 0(ok) or <0(failed) */
{
  char *str, *id, *p;
  int val;

  if (settings == NULL || id_value_str == NULL) {
    warnx("set settings: invalid arguments: settings=%p id_value_str=%p",
          settings, id_value_str);
    return -1;
  }

  str = strdup(id_value_str);
  id = str;
  if ((p = strchr(str, '=')) == NULL) {
    warnx("set settings: format should be <id>=<value>: %s", id_value_str);
    free(str);
    return -1;
  }
  *p = '\0';  /* make id a string */
  p++;  /* skip '=' from value */
  if (sscanf(p, "%i", &val) != 1 || val < 0) {
    warnx("set settings: value should be natural number: %s", p);
    free(str);
    return -1;
  }

  /* HTTP/2 Settings */
  if (!strcasecmp(id, "header_table_size")) {
    settings->header_table_size = val;
  } else if (!strcasecmp(id, "enable_push")) {
    settings->enable_push = val;
  } else if (!strcasecmp(id, "max_concurrent_streams")) {
    settings->max_concurrent_streams = val;
  } else if (!strcasecmp(id, "initial_window_size")) {
    settings->initial_window_size = val;
  } else if (!strcasecmp(id, "max_frame_size")) {
    settings->max_frame_size = val;
  } else if (!strcasecmp(id, "max_header_list_size")) {
    settings->max_header_list_size = val;
  } else if (!strcasecmp(id, "enable_connect_protocol")) {
    settings->enable_connect_protocol = val;
  /* HTTP/1.1 Settings */ 
  } else if (!strcasecmp(id, "single_request")) {
    settings->single_req = val;
  } else if (!strcasecmp(id, "keep_alive_timeout")) {
    settings->keep_alive_timeout = val;
  } else if (!strcasecmp(id, "keep_alive_max")) {
    settings->keep_alive_max = val;
  } else {
    warnx("set settings: unknown setting identifier: %s", id);
    free(str);
    return -1;
  }

  free(str);
  return 0;
}

