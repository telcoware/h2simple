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
typedef struct h2_cls h2_cls;

typedef struct h2_obj {
  h2_cls *cls;  /* pointer to class object */
} h2_obj;

typedef struct h2_cls {
  h2_obj obj;   /* class obj */
  const char *name;
} h2_cls;

/* global variables representing the entry class; defined in h2_sess.c */
extern h2_cls h2_cls_cls;
extern h2_cls h2_cls_strm;
extern h2_cls h2_cls_sess;
extern h2_cls h2_cls_svr;
extern h2_cls h2_cls_ctx;


/*
 * Simple string buffer utility --------------------------------------------
 */

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

char *h2_sbuf_put(h2_sbuf *sbuf, const char *str);
char *h2_sbuf_put_n(h2_sbuf *sbuf, const char *str, int str_len);
  /* return pointer to copyed string onto sbuf buf[] */
  /* NOTE: str might be any binary stream */
  /* ASSUME:: sbuf has enough free space; to be checked wit sbuf_avail() */


/*
 * Messages utilities ------------------------------------------------------
 */

#define H2_MSG_HDR_MAX        32  /* TODO: TO BE UNLIMITED */
#define H2_MSG_SBUF_SIZE      (4 * 1024 - 596/*h2_msg*/)
#define H2_MSG_SBUF_EXT_STEP  (4 * 1024 - 16/*h2_xbuf*/)


/* h2 msg type */
#define H2_REQUEST        1
#define H2_RESPONSE       2
#define H2_PUSH_PROMISE   3
#define H2_PUSH_RESPONSE  4
const char *h2_msg_type_str(int msg_type);

typedef struct h2_hdr {
  char *name;
  char *value;
} h2_hdr;

typedef struct h2_msg {
  /* request pseudo header; pointer on sbuf */
  char *method;
  char *scheme;
  char *authority;  /* might be null */
  char *path;
  // HERE: TODO: candadite for special fields
  // int path_len;
  // int path_arg_off;    /* path after '?' */
  // HERE: TODO: candadite for special fields
  // int content_length;  /* value of content_length header */ 
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
} h2_msg;

/* initialize static message buffer; sbuf init/cleaned; body not touched */
void h2_msg_init_static(h2_msg *msg);
void h2_msg_clean_static(h2_msg *msg);


/*
 * Stream Utilities --------------------------------------------------------
 */

/* read buffer for message body send handling */
typedef struct h2_read_buf {
  unsigned char *data;
  int data_size;
  int data_used;
  int to_be_freed;
  int send_msg_type;  /* H2_REQUEST/RESPONSE/PUSH_PROMISE/PUSH_RESPONSE */
} h2_read_buf;

typedef struct h2_strm {
  h2_obj obj;
  h2_strm *prev, *next;

  int stream_id;
  int send_msg_type;        /* H2_REQUEST/H2_RESPONSE/H2_PUSH_PROMISE */
  int recv_msg_type;
  h2_msg *rmsg;
  h2_read_buf send_body_rb; /* server: response body, client: request body */
                            /* send data buffer for nghttp2_data_provider */
                            /* .data is to freed at delete strm */
 
  h2_strm_free_cb strm_free_cb;
  void *user_data;          /* for client stream only; set at request submit */

  int response_sent;        /* set when h2_send_response() is called */
} h2_strm;


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
#define H2_WR_BUF_SIZE  1024

typedef struct h2_wr_buf {
  /* last pending merge buffer */
  unsigned char merge_data[H2_WR_BUF_SIZE];
  int merge_size;
  /* last nghttp2_mem_send() retruned data, not sent yet */
  const unsigned char *mem_send_data;  /* static; moved on partially sent */
  int mem_send_size;
} h2_wr_buf;

/* h2_sess close reason */
#define CLOSE_BY_SOCK_EOF     (-1)
#define CLOSE_BY_SOCK_ERR     (-2)
#define CLOSE_BY_SSL_ERR      (-3)
#define CLOSE_BY_NGHTTP2_ERR  (-4)
#define CLOSE_BY_NGHTTP2_END  (-5)

typedef struct h2_sess {
  h2_obj obj;
  h2_sess *prev, *next;
  h2_strm strm_list_head;
  h2_ctx *ctx;
  int is_server;

  struct nghttp2_session *ng_sess;
  SSL *ssl;                 /* non-NULL for tsl sess only */
  int fd;                   /* connected socket fd */
  int close_reason;         /* CLOSE_BY_* */
  char *log_prefix;         /* dynamic alloced */

  h2_wr_buf wr_buf;         /* write buffer for nonblocing send */
  int send_pending;         /* mark when send skipping by would block */

  int stream_close_cnt;
  struct timeval tv_begin;
  struct timeval tv_end;

  int is_terminated;        /* set when h2_sess_terminate() */

  /* server callbacks */
  h2_request_cb request_cb;
  /* client callbacks */
  h2_response_cb response_cb;
  h2_push_promise_cb push_promise_cb;
  h2_push_response_cb push_response_cb;

  /* user data */
  h2_sess_free_cb sess_free_cb;
  void *user_data;

} h2_sess;

/* sess management */
void h2_sess_nghttp2_init(h2_sess *sess);
void h2_sess_free(h2_sess *sess);


/*
 * Server Listen Context ---------------------------------------------------
 */

typedef struct h2_svr {
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

} h2_svr;

 
/*
 * Context Utilities -------------------------------------------------------
 */

typedef struct h2_ctx {
  h2_obj obj;
  h2_sess sess_list_head;
  int sess_num; 

  h2_svr svr_list_head;
  int svr_num;

#ifdef EPOLL_MODE
  int epoll_fd;
#endif

  /* ctx run loop control flag */
  /* set at h2_ctx_run() start, cleared by h2_ctx_stop() */
  int service_flag;

  /* verbose flag */
  int verbose;

} h2_ctx;


#endif  /* __h2_priv_h__ */

