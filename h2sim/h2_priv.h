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

#ifndef __h2_priv_h__
#define __h2_priv_h__

#include <stdio.h>
#include <stdint.h>

#include "h2.h"


/* logging utilities */
#define warnx(format, args...)  \
    fprintf(stderr, format "\n", ##args)
/* CONSIDER: fprintf(stderr, "%s:: " format "\n", __func__, ##args) */

#define errx(exitcode, format, args...)  \
    do { warnx(format, ##args); exit(exitcode); } while(0)


#ifdef TLS_MODE
#else
typedef void SSL;
#endif

/* opaque type defintion */
struct nghttp2_session;


/*
 * H2 object and class definition ------------------------------------------
 * NOTE: to distinquish h2 entry type
 */

/* forward declaration */
typedef struct h2_obj h2_obj;
typedef struct h2_cls h2_cls;

struct h2_obj {
  h2_cls *cls;  /* pointer to class object */
};

struct h2_cls {
  struct h2_obj obj;   /* class obj */
  const char *name;
};

/* global variables representing the entry class; defined in h2_sess.c */
extern h2_cls h2_cls_cls;
extern h2_cls h2_cls_strm;
extern h2_cls h2_cls_sess;
extern h2_cls h2_cls_peer;
extern h2_cls h2_cls_svr;
extern h2_cls h2_cls_ctx;


/*
 * Simple string buffer utility for H2 Message Headers ---------------------
 * allocates string on sbuf.xbuf and returns sbuf index of none zero
 */

typedef unsigned short h2_sbuf_idx;  /* 0 for none */

typedef struct h2_xbuf {
  struct h2_xbuf *next;
  int size;
  int free;
  char buf[];  /* char[size] */
} h2_xbuf;

typedef struct h2_sbuf {
  int ext_step_size;  /* allocated power of 2 exponentally */
  h2_xbuf xbuf;  /* linked list of xbuf; first is on h2_sbuf.buf[buf_size] */  
  /* CAUTION: char[sbuf_size] MUST BE ALLOCATED after h2_sbuf */
} h2_sbuf;

/* sbuf is to be used ONLY in h2_msg */
/*void h2_sbuf_init(h2_sbuf *sbuf, int buf_size, int ext_step_size); */
/*void h2_sbuf_clean(h2_sbuf *sbuf); */  /* frees used data and clean to init */

/* get string pointer from sbuf_idx */
/* const char *h2_sbuf_get(h2_sbuf *sbuf, h2_sbuf_idx sbuf_idx); */

h2_sbuf_idx h2_sbuf_put(h2_sbuf *sbuf, const char *str);
h2_sbuf_idx h2_sbuf_put_n(h2_sbuf *sbuf, const char *str, int str_len);
  /* return pointer to copyed string onto sbuf buf[] */
  /* NOTE: str might be any binary stream */
  /* ASSUME:: sbuf has enough free space; to be checked wit sbuf_avail() */

int h2_sbuf_used(h2_sbuf *sbuf);
  /* returns total size used in sbuf */


/*
 * Messages utilities ------------------------------------------------------
 */

#define H2_MSG_HDR_MAX        32  /* TODO: TO BE UNLIMITED */
#define H2_MSG_SBUF_SIZE      (1024 - 188/* offsetof(h2_msg,sbuf_buf) */)
#define H2_MSG_SBUF_EXT_STEP  (1024 - (int)sizeof(h2_xbuf))


/* h2 msg type */
#define H2_REQUEST        1
#define H2_RESPONSE       2
#define H2_PUSH_PROMISE   3
#define H2_PUSH_RESPONSE  4
const char *h2_msg_type_str(int msg_type);

typedef struct h2_hdr {
  h2_sbuf_idx name;
  h2_sbuf_idx value;
} h2_hdr;

struct h2_msg {
  /* request pseudo header; pointer on sbuf */
  h2_sbuf_idx method;
  h2_sbuf_idx scheme;
  h2_sbuf_idx authority;
  h2_sbuf_idx path;
  /* response pseudo header */
  int status;

  /* non-psuedo headers; pointers on sbuf */
  h2_hdr hdr[H2_MSG_HDR_MAX];
  int hdr_num;

  /* body */
  unsigned char *body; /* dynamic alloced */
  int body_len;

  /* sbuf for header */
  h2_sbuf sbuf;
  char sbuf_buf[H2_MSG_SBUF_SIZE];
};

/* initialize static message buffer; sbuf init/cleaned; body not touched */
void h2_msg_init_static(h2_msg *msg);
void h2_msg_clean_static(h2_msg *msg);


/*
 * HTTP Common IO Handlers: defined in "h2_io.c" ---------------------------
 */

void h2_sess_mark_send_pending(h2_sess *sess);
void h2_sess_clear_send_pending(h2_sess *sess);

void h2_peer_sess_free_hdlr(h2_peer *peer, h2_sess *sess);


/*
 * HTTP/2 Handlers: defined in "h2_v2.c" -----------------------------------
 */

/* send message */
int h2_send_request_v2(h2_sess *sess, h2_msg *req,
                       h2_response_cb response_cb, void *strm_user_data);
int h2_send_response_v2(h2_sess *sess, h2_strm *strm, h2_msg *rsp);
int h2_send_push_promise_v2(h2_sess *sess, h2_strm *request_strm,
                            h2_msg *prm_req, h2_msg *prm_rsp);
int h2_send_rst_stream_v2(h2_sess *sess, h2_strm *strm);

/* io */
int h2_sess_send_once_v2(h2_sess *sess);
int h2_sess_send_settings_v2(h2_sess *sess);
int h2_sess_recv_v2(h2_sess *sess, const void *data, int size);
/* sess manange */
void h2_sess_init_v2(h2_sess *sess);
void h2_sess_free_v2(h2_sess *sess);
void h2_sess_terminate_v2(h2_sess *sess);
void h2_sess_shutdown_send_v2(h2_sess *sess);


/*
 * HTTP/1.1 Handlers: deifned in "h2_v1_1.c" -------------------------------
 */

/* send message */
int h2_send_request_v1_1(h2_sess *sess, h2_msg *req,
                         h2_response_cb response_cb, void *strm_user_data);
int h2_send_response_v1_1(h2_sess *sess, h2_strm *strm, h2_msg *rsp);

/* io */
int h2_sess_send_once_v1_1(h2_sess *sess);
int h2_sess_recv_v1_1(h2_sess *sess, const void *data, int size);
/* sess manange */
void h2_sess_terminate_v1_1(h2_sess *sess);
void h2_sess_shutdown_send_v1_1(h2_sess *sess);


/*
 * Stream Utilities --------------------------------------------------------
 */

/* memory buffer for message body send handling */
typedef struct h2_send_buf {
  unsigned char *data;
  int data_size;
  int data_used;
  int to_be_freed;
  int msg_type;             /* H2_REQUEST/RESPONSE/PUSH_PROMISE/PUSH_RESPONSE */
} h2_send_buf;

struct h2_strm {
  h2_obj obj;
  h2_strm *prev, *next;
  
  int stream_id;
  int send_msg_type;        /* H2_REQUEST/H2_RESPONSE/H2_PUSH_PROMISE */
  int recv_msg_type;
  h2_msg *rmsg;
  h2_send_buf send_body_sb; /* for HTTP/2: */
                            /*   server: response body, client: request body */
                            /*   send data buffer for nghttp2_data_provider */
                            /*   .data is to freed at delete strm */
                            /* for HTTP/1.1: message to send */ 

  h2_response_cb response_cb; 
  void *user_data;          /* for client stream only; set at request submit */

  int is_req;               /* set whee strm is created by h2_send_request() */
  int is_rsp_set;           /* set when h2_send_response() is called (server) */
                            /* or reponse callback called (client) */

  /* for http/1.1 Connection: close handling */
  int close_sess;           /* close session after handling this session */
};

/* create strm and append to sess */
h2_strm *h2_strm_init(h2_sess *sess, int stream_id, int recv_msg_type,
                      h2_response_cb response_cb, void *strm_user_data);
void h2_strm_free(h2_strm *strm);

/* receive message event handler */
int h2_on_request_recv(h2_sess *sess, h2_strm *strm);
int h2_on_response_recv(h2_sess *sess, h2_strm *strm);

/* HTTP/2-only receive message event handler */
int h2_on_rst_stream_recv(h2_sess *sess, h2_strm *strm);
int h2_on_push_promise_recv(h2_sess *sess, h2_strm *req_strm,
                            h2_strm *prm_strm);
int h2_on_push_response_recv(h2_sess *sess, h2_strm *prm_strm);


/*
 * Session Utilities -------------------------------------------------------
 */

#define H2_RD_BUF_SIZE  (16 * 1024)

/* send write pending buffer for nghttp2 mem send handling */
/* NOTE: nghttp2_sesion_mem_send() retruns per frame */
/*       so merge men_send return data for io perf; sock is NODELAY mode */
/*       send size needs to be just NOT too small */
/* NOTE: PERF: BIGGER WINDOW_SIZE shows no significant perf up */
/* NOTE: PERF: BIGGER CONCURRENT_STREAM option shows NO significant perf up */
#define H2_WR_BUF_SIZE  (4 * 1024)

typedef struct h2_wr_buf {
  /* last pending merge buffer */
  unsigned char merge_data[H2_WR_BUF_SIZE];
  int merge_size;
  /* last nghttp2_mem_send() retruned data, not sent yet */
  unsigned char *mem_send_data;  /* static; moved on partially sent */
  int mem_send_size;
} h2_wr_buf;

/* h2_sess close reason */
#define CLOSE_BY_SOCK_EOF     (-1)
#define CLOSE_BY_SOCK_ERR     (-2)
#define CLOSE_BY_SSL_ERR      (-3)
#define CLOSE_BY_NGHTTP2_ERR  (-4)
#define CLOSE_BY_NGHTTP2_END  (-5)
/* for HTTP/1.1 */
#define CLOSE_BY_HTTP_ERR     (-7)
#define CLOSE_BY_HTTP_END     (-6)

struct h2_sess {
  h2_obj obj;
  h2_sess *prev, *next;

  h2_ctx *ctx;
  h2_peer *peer;            /* for client session */
  int http_ver;             /* H2_HTTP_V* */
  int is_server;
  h2_settings settings;

  h2_strm strm_list_head;

  SSL *ssl;                 /* non-NULL for tsl sess only */
  int fd;                   /* connected socket fd */
  int close_reason;         /* CLOSE_BY_* */
  char *log_prefix;         /* dynamic alloced */

  h2_wr_buf wr_buf;         /* write buffer for nonblocking send */
  int send_pending;         /* mark when send skipping by would block */
  int send_data_remain;     /* sum of h2_send_buf remains to be sent */

  int req_cnt;              /* HTTP/2: client only; HTTP/1.1: both */
  int rsp_cnt;              /* HTTP/2: client only; HTTP/1.1: both */
  int rsp_rst_cnt;          /* HTTP/2: client only for rst_stream on req */
                            /*         NOTE: rsp_cnt is also counted */
  int strm_close_cnt;
  struct timeval tv_begin;
  struct timeval tv_end;

  int is_req_max_reconn;    /* mark to be terminated for req_max_per_sess */
  int is_terminated;
  int is_no_more_req;
  int is_shutdown_send_called;

  /* HTTP/2 nghttp2 session context */
  struct nghttp2_session *ng_sess;

  /* HTTP/1.1 receive parser context */
  /* received data buffer */
  char *rdata;
  int rdata_alloced;
  int rdata_size;
  int rdata_used;
  int rdata_offset;         /* offset of rdata from session start */

  /* HTTP/1.1 received message parsing status */ 
  h2_strm *strm_recving;    /* maintained for recv */
  int rmsg_header_done;     /* header is parsed all */
  int rmsg_header_line;     /* header line count parsed */
  int rmsg_content_length;  /* Content-Length header value */

  /* HTTP/1.1 send message status */
  h2_strm *strm_sending;    /* maintained for client request send */

  /* server session only */
  h2_request_cb request_cb;
  h2_sess_free_cb sess_free_cb;
  void *user_data;   /* NOTE: on client session, peer->user_data is used */
};

/* sess management */
void h2_sess_free(h2_sess *sess);

/* mark something to be sent */
void h2_sess_mark_send_pending(h2_sess *sess);
int h2_sess_send(h2_sess *sess);


/*
 * Peer Utilities ----------------------------------------------------------
 * warp up entry for multiples sessions for client api
 */

struct h2_peer {
  h2_obj obj;
  struct h2_peer *prev, *next;
  h2_ctx *ctx;

  /* configuration for client session */
  char *authority;          /* dyanmic alloced */
  SSL_CTX *ssl_ctx;
  h2_settings settings;
  h2_push_promise_cb push_promise_cb;
  h2_peer_free_cb peer_free_cb;
  void *user_data;

  /* sessions and load balancing status */
  h2_sess **sess;           /* dynamic sess[sess_num] */
  int next_sess_idx;
  int *act_sess;            /* dynamic int[sess_num]; mark in act_sess_num */
  int act_sess_num;         /* number of connected sessions */
  int reconn_num;           /* number of session reconnect tried */

  int is_terminated;
  int is_no_more_req;

  /* performance counts */
  int req_cnt;              /* HTTP/2: client only; HTTP/1.1: both */
  int rsp_cnt;              /* HTTP/2: client only; HTTP/1.1: both */
  int rsp_rst_cnt;          /* HTTP/2: client only for rst_stream on req */
  int strm_close_cnt;       /* aggregated from sess */
  int sess_close_cnt;
  struct timeval tv_begin;
  struct timeval tv_end;
};

void h2_peer_free(h2_peer *peer);


/*
 * Server Listen Context ---------------------------------------------------
 */

struct h2_svr {
  h2_obj obj;
  struct h2_svr *prev, *next;
  h2_ctx *ctx;

  char *authority;          /* dyanmic alloced; binding address and also key */
  SSL_CTX *ssl_ctx;         /* ASSUME: managed by caller */
  int accept_fd;
  
  h2_accept_cb accept_cb;

  /* user data */
  h2_svr_free_cb svr_free_cb;
  void *user_data; 
};

 
/*
 * Context Utilities -------------------------------------------------------
 */

struct h2_ctx {
  h2_obj obj;

  h2_sess sess_list_head;
  int sess_num; 

  h2_svr svr_list_head;
  int svr_num;

  h2_peer peer_list_head;
  int peer_num;

#ifdef EPOLL_MODE
  int epoll_fd;
#endif

  /* ctx run loop control flag */
  /* set at h2_ctx_run() start, cleared by h2_ctx_stop() */
  int service_flag;

  int http_ver;   /* HTTP version; H2_HTTP_V* */
  int verbose;    /* verbose flag */
};


#endif  /* __h2_priv_h__ */

