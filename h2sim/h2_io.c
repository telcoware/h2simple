/*
 * h2sim - HTTP2 Simple Application Framework using nghttp2
 *
 * Copyright 2019 Lee Yongjae, Telcoware Co.,LTD.
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
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#ifdef EPOLL_MODE
#include <sys/epoll.h>
#else
#include <poll.h>
#endif

#ifdef TLS_MODE
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#else
/* NOTE: h2_util.h defines dummy SSL_CTX and SSL */
#endif

#include <nghttp2/nghttp2.h>

#include "h2.h"
#include "h2_priv.h"


/*
 * TLS Utilities -----------------------------------------------------------
 */

#ifdef TLS_MODE

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#if OPENSSL_VERSION_NUMBER < 0x10002000L
#error "openssl version SHOULD be >= 1.0.2"
#endif

static int h2_server_alpn_cb(SSL *ssl, const unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
  (void)ssl;
  (void)arg;

  return (nghttp2_select_next_protocol((void *)out, outlen, in, inlen) == 1)?
         SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
}

SSL_CTX *h2_ssl_ctx_init(int is_server/* else client */,
                         const char *key_file, const char *cert_file) {

  if (is_server && (!key_file || !cert_file)) {
    errx(1, "server ssl ctx requires key_file and cert_file");
  } else if ((key_file && !cert_file) || (!key_file && cert_file)) {
    errx(1, "key_file and cert_file should be coincident");
  }

  SSL_CTX *ssl_ctx;
  ssl_ctx = SSL_CTX_new((is_server)? SSLv23_server_method() :
                                     SSLv23_client_method());
  if (!ssl_ctx) {
    errx(1, "cannot create tls context: %s",
         ERR_error_string(ERR_get_error(), NULL));
  }

  /* NOTE: set crypto parameters for 3GPP R15 */
  SSL_CTX_set_options(ssl_ctx,
                      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                      SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
                      SSL_OP_NO_COMPRESSION |
                      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

  /* FROM: 3GPP 33.210-f20 6.2 TLS protocol profiles */
  /* for TLSv1.2 */
  SSL_CTX_set_cipher_list(ssl_ctx,
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "DHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384");
  /* for TLSv1.3 */
  /* SSL_CTX_set_ciphersuites(ssl_ctx, ""); */
  /* default: TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:  */
  /*          TLS_AES_128_GCM_SHA256 */

  if (key_file && cert_file) {  /* coincidence already checked */
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
      errx(1, "cannot use private key file %s", key_file);
    }
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
      errx(1, "cannot use certificate file %s", cert_file);
    }
  }

  if (is_server) {
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh) {
      errx(1, "EC_KEY_new_by_curv_name failed: %s",
           ERR_error_string(ERR_get_error(), NULL));
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
    EC_KEY_free(ecdh);
    SSL_CTX_set_alpn_select_cb(ssl_ctx, h2_server_alpn_cb, NULL);
  } else {
    /* client */
    SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);
  }

  return ssl_ctx;
}

#endif /* TLS_MODE */


/*
 * File Control Flag Utilities ---------------------------------------------
 */

static void h2_set_nonblock(int fd) {
  int v;
  if ((v = fcntl(fd, F_GETFL, 0)) != -1) {
    fcntl(fd, F_SETFL, v | O_NONBLOCK);
  }
}

static void h2_set_close_exec(int fd) {
  int v;
  if ((v = fcntl(fd, F_GETFD, 0)) != -1) {
    fcntl(fd, F_SETFD, v | FD_CLOEXEC);
  }
}


/*
 * Session Send ------------------------------------------------------------
 */

/*
 * Send merge buf size consideration:
 * - min: too small packet causes perf damage including all network components
 * - max: cocurrent streams x req_hdr+data or rsp_hdr+data size
 * - tcp send buf range min value: /proc/sys/net/ipv4/tcp_wmem
 * - TLS record size
 * - tcp MTU: 1360 or less; cf. some public CPs site has MTU 1360
 */


inline void h2_sess_mark_send_pending(h2_sess *sess) {
  if (!sess->send_pending) {
#ifdef EPOLL_MODE
    struct epoll_event e;
    e.events = EPOLLIN | EPOLLOUT;
    e.data.ptr = &sess->obj;
    epoll_ctl(sess->fd, EPOLL_CTL_MOD, sess->fd, &e);
#endif
    sess->send_pending = 1;
  }
}

inline void h2_sess_clear_send_pending(h2_sess *sess) {
  if (sess->send_pending) {
#ifdef EPOLL_MODE
    struct epoll_event e;
    e.events = EPOLLIN | EPOLLOUT;
    e.data.ptr = &sess->obj;
    epoll_ctl(sess->fd, EPOLL_CTL_MOD, sess->fd, &e);
#endif
    sess->send_pending = 0;
  }
}

inline int h2_wr_buf_pending(h2_wr_buf *wr_buf) {
  return wr_buf->merge_size + wr_buf->mem_send_size;
}

static int h2_sess_send_once(h2_sess *sess) {
  h2_wr_buf *wb = &sess->wr_buf;
  int sent, total_sent = 0;
#ifdef TLS_MODE
  SSL *ssl = sess->ssl;
#endif
#ifdef EPOLL_MODE
  int mem_send_zero = 0;
#endif

  /* NOTE: send is always blocking */
  /* TODO: save and retry to send on last to_send data */

  if (wb->merge_size > 0 && wb->mem_send_size > 0) {
    warnx("### DEBUG: REENTRY WITH REMAINING WRITE: "
          "merge_size=%d mem_send_size=%d", wb->merge_size, wb->mem_send_size);
  }

  while (wb->mem_send_size <= 0 && wb->merge_size < H2_WR_BUF_SIZE) {
    const uint8_t *mem_send_data;
    ssize_t mem_send_size;
    
    mem_send_size = nghttp2_session_mem_send(sess->ng_sess, &mem_send_data);
    /* DEBUG: to check mem_send size */
    /* fprintf(stderr, "%d ", (int)mem_send_size); */

    if (mem_send_size < 0) {
      /* probablly NGHTTP2_ERR_NOMEM; abort immediately */
      warnx("nghttp2_session_mem_send() error: %s",
            nghttp2_strerror(mem_send_size));
      sess->close_reason = CLOSE_BY_NGHTTP2_ERR;
      return -1;
    } else if (mem_send_size == 0) {
      /* no more data to send */
#ifdef EPOLL_MODE
      mem_send_zero = 1;
#endif
      break;
    } else if (wb->merge_size + mem_send_size <= (int)sizeof(wb->merge_data)) {
      /* merge to buf */
      memcpy(&wb->merge_data[wb->merge_size], mem_send_data, mem_send_size);
      wb->merge_size += mem_send_size;
    } else {
      /* cannot merge to buf */
      wb->mem_send_data = mem_send_data;
      wb->mem_send_size = mem_send_size;
      break;
    }
  }

  /* DEBUG: to check merge_size and mem_send size */
  /* fprintf(stderr, "%d+%d ", merge_size, (int)mem_send_size); */

  /* try to send merge_data once */
  if (wb->merge_size > 0) {
#ifdef TLS_MODE
    if (ssl) {
      sent = SSL_write(ssl, wb->merge_data, wb->merge_size);
      if (sent <= 0) {
        if (SSL_get_error(ssl, sent) == SSL_ERROR_WANT_WRITE) {
          fprintf(stderr, "DEBUG: TLS SEND merge_data WOULD BLOCK: "
                  "to_send=%d\n", (int)wb->merge_size);
          h2_sess_mark_send_pending(sess);
          return total_sent;  /* retry later */
        }
        warnx("SSL_write(merge_data) error: %d", SSL_get_error(ssl, sent));
        sess->close_reason = CLOSE_BY_SSL_ERR;
        return -2;
      }
    } else
#endif
    {
      sent = send(sess->fd, wb->merge_data, wb->merge_size, 0);
      if (sent <= 0) {
        // note: in linux EAGAIN=EWHOULDBLOCK but some oldes are not */
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
          fprintf(stderr, "DEBUG: TCP SEND merge_data WOULD BLOCK: "
                  "to_send=%d\n", (int)wb->merge_size);
          h2_sess_mark_send_pending(sess);
          return total_sent;
        }
        warnx("send() error with to_send=%d: %s",
              wb->merge_size, strerror(errno));
        sess->close_reason = CLOSE_BY_SOCK_ERR;
        return -3;
      }
    }

    //warnx("### DEBUG: DATA SENT: merge_buf sent=%d", sent);
    total_sent += sent;

    if (sent < wb->merge_size) {
      /* DEBUG: to check partial send for tcp socket buffer overflow */
      warnx("### DEBUG: MERGE_BUF PARTIAL!!! %d/%d ", sent, wb->merge_size);

      memmove(wb->merge_data, &wb->merge_data[sent], wb->merge_size - sent);
      wb->merge_size -= sent;
      return total_sent;  /* possible block at send */
    } else {
      wb->merge_size = 0;
    }
  }

  /* try to send mem_send_data once */
  if (wb->mem_send_size) {
#ifdef TLS_MODE
    if (ssl) {
      sent = SSL_write(ssl, wb->mem_send_data, wb->mem_send_size);
      if (sent <= 0) {
        if (SSL_get_error(ssl, sent) == SSL_ERROR_WANT_WRITE) {
          fprintf(stderr, "DEBUG: TLS SEND mem_send_data WOULD BLOCK: "
                  "to_send=%d\n", (int)wb->mem_send_size);
          h2_sess_mark_send_pending(sess);
          return total_sent;  /* retry later */
        }
        warnx("SSL_write(mem_send_data) error: %d", SSL_get_error(ssl, sent));
        sess->close_reason = CLOSE_BY_SSL_ERR;
        return -2;
      }
    } else
#endif
    {
      sent = send(sess->fd, wb->mem_send_data, wb->mem_send_size, 0);
      if (sent <= 0) {
        // note: in linux EAGAIN=EWHOULDBLOCK but some oldes are not */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          fprintf(stderr, "DEBUG: TCP SEND mem_send_data WOULD BLOCK: "
                  "to_send=%d\n", (int)wb->mem_send_size);
          h2_sess_mark_send_pending(sess);
          return total_sent;
        }
        warnx("send() error with to_send=%d: %s",
              wb->mem_send_size, strerror(errno));
        sess->close_reason = CLOSE_BY_SOCK_ERR;
        return -5;
      }
    }

    //warnx("### DEBUG: DATA SENT: mem_send sent=%d", sent);
    total_sent += sent;

    if (sent < wb->merge_size) {  /* indication for possible block at next */
      /* DEBUG: to check partial send for tcp socket buffer overflow */
      fprintf(stderr, "### DEBUG: MEM_SEND PARTIAL!!!%d/%d ", sent, wb->mem_send_size);

      wb->mem_send_data += sent;
      wb->mem_send_size -= sent;
      return total_sent;  /* possible block at send */
    } else {
      wb->mem_send_data = NULL;
      wb->mem_send_size = 0;
    }
  }

  if (total_sent == 0) {
    h2_sess_clear_send_pending(sess);
    /*
    static int c = 0;
    c++;
    warnx("### DEBUG: [%d] EXIT WITHOUT SENT DATA: merge_size=%d "
          "mem_send_size=%d", c, wb->merge_size, wb->mem_send_size);
    */
  }

#if EPOLL_MODE
  if (mem_send_zero && !nghttp2_session_want_read(sess->ng_sess)) {
    sess->close_reason = CLOSE_BY_NGHTTP2_END;
    return -6;
  }
#endif

  return total_sent;
}

static int h2_sess_send(h2_sess *sess) {
  int r;
  do {
    r = h2_sess_send_once(sess);
  } while (r > 0);
  return r;
}

static int h2_sess_recv(h2_sess *sess) {
  uint8_t buf[H2_RD_BUF_SIZE];
  ssize_t recv_len, read_len;
#ifdef TLS_MODE
  SSL *ssl = sess->ssl;
#endif

#ifdef TLS_MODE
  if (ssl) {
    recv_len = SSL_read(ssl, buf, sizeof(buf));
    if (recv_len < 0) {
      if (SSL_get_error(ssl, recv_len) == SSL_ERROR_WANT_READ) {
        return 0;  /* retry later */
      }
      ERR_print_errors_fp(stderr);
    }
  } else
#endif
  {
    recv_len = recv(sess->fd, buf, sizeof(buf), 0);
  }
  if (recv_len < 0) {
    // note: in linux EAGAIN=EWHOULDBLOCK but some oldes are not */
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
      return 0;  /* retry later */
    }
    warnx("network error: %s", strerror(errno));
    sess->close_reason = CLOSE_BY_SOCK_ERR;
    return -1;
  } else if (recv_len == 0) {
    warnx("disconnected from the remote host");
    sess->close_reason = CLOSE_BY_SOCK_EOF;
    return -2;
  }

  //warnx("### DEBUG: DATA RECEIVED: recv_len=%d", (int)recv_len);

  read_len = nghttp2_session_mem_recv(sess->ng_sess, buf, recv_len);
  /* NOTE: read_len is same as recv_len on success case */
  if (read_len < 0) {
    warnx("Fatal error: %s", nghttp2_strerror((int)read_len));
    sess->close_reason = CLOSE_BY_NGHTTP2_ERR;
    return -3;
  }

  return (int)read_len;
}


/*
 * Client Session I/O ------------------------------------------------------
 */

static h2_sess *h2_sess_init_client(h2_ctx *ctx, SSL *ssl,
                                    int fd, const char *authority) {

  h2_sess *sess = calloc(1, sizeof(h2_sess));
  sess->obj.cls = &h2_cls_sess;

  /* insert into ctx session list */
  sess->next = ctx->sess_list_head.next;
  ctx->sess_list_head.next = sess;
  sess->prev = &ctx->sess_list_head;
  if (sess->next) {
    sess->next->prev = sess;
  }
  ctx->sess_num++;

  sess->ctx = ctx;
  sess->is_server = 0;

  sess->ssl = ssl;
  sess->fd = fd;

  /* use local binding address for session log prefix */
  struct sockaddr addr;
  socklen_t addrlen = sizeof(addr);
  if (getsockname(fd, &addr, &addrlen) == 0) {
    /* get log prefix info */
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    if (getnameinfo(&addr, addrlen, host, sizeof(host),
                    serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV)) {
      sess->log_prefix = strdup("(unknown)");
    } else {
      char log_prefix[NI_MAXHOST + NI_MAXSERV + 1 + 1];
      sprintf(log_prefix, "%s:%s ", host, serv);
      sess->log_prefix = strdup(log_prefix);
    }
  } else {
    sess->log_prefix = malloc(3 + strlen(authority) + 2);
    strcpy(sess->log_prefix, "to:");
    strcat(sess->log_prefix, authority);
    strcat(sess->log_prefix, " ");
  }
  
#ifdef EPOLL_MODE
  struct epoll_event e;
  e.events = EPOLLIN;
  e.data.ptr = &sess->obj;
  if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, sess->fd, &e) < 0) {
    warnx("sess client init failed for epoll_ctl() error: %s", strerror(errno));
    h2_sess_free(sess);
    return NULL;
  }
#endif

  h2_sess_nghttp2_init(sess);

  /* mark start time */
  gettimeofday(&sess->tv_begin, NULL);

  return sess;
}

static void h2_sess_client_send_conn_hdr(h2_sess *sess) {
  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int r;

  /* client 24 bytes magic string will be sent by nghttp2 library */
  r = nghttp2_submit_settings(sess->ng_sess, NGHTTP2_FLAG_NONE, iv, 1);
  if (r != 0) {
    errx(1, "cannot not submit setttings: %s", nghttp2_strerror(r));
  }
}

static h2_sess *h2_sess_client_start(int sock, h2_ctx *ctx,
                    const char *authority, SSL_CTX *client_ssl_ctx) {
  SSL *ssl = NULL;
#ifdef TLS_MODE
#else
  (void)client_ssl_ctx;
#endif

  // do blocking and no wait send
  int v = 1;
  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &v, sizeof(v));

#ifdef TLS_MODE
  if (client_ssl_ctx) {
    const unsigned char *alpn = NULL;
    unsigned int alpnlen = 0;
    int r;

    /* HERE: TODO: MAY NEED TO SET sock NOBLOCKING before  SSL_set_fd() */
    /* HERE: TO CHECK: is sock needs to be close()ed on error exit case? */

    ssl = SSL_new(client_ssl_ctx);
    if (!ssl) {
      warnx("%s connected but cannot create tls session: %s",
            authority, ERR_error_string(ERR_get_error(), NULL));
      return NULL;
    }
    SSL_set_fd(ssl, sock);
    r = SSL_connect(ssl);
    if (r == 0) {
      warnx("%s connected but shutdown by tls protocol: %d",
            authority, SSL_get_error(ssl, r));
      SSL_free(ssl);
      return NULL;
    } else if (r < 0) {
      warnx("%s tls handshake failed: %d", authority, SSL_get_error(ssl, r));
      SSL_free(ssl);
      return NULL;
    }
    SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
    if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
      warnx("%s h2 is not negotiated", authority);
      SSL_free(ssl);
      return NULL;
    }
  }
#endif /* TLS_MODE */
  
  h2_sess *sess = h2_sess_init_client(ctx, ssl, sock, authority);

  /* send HTTP/2 client start message */
  h2_sess_client_send_conn_hdr(sess);
  if (h2_sess_send(sess) < 0) {
    h2_sess_free(sess);
    return NULL;
  }

  h2_set_nonblock(sock);

  fprintf(stderr, "%sCONNECTED\n", sess->log_prefix);
  return sess;
}

/* Start connecting to the remote peer |host:port| */
h2_sess *h2_connect(h2_ctx *ctx, const char *authority, SSL_CTX *cli_ssl_ctx,
                    h2_response_cb response_cb,
                    h2_push_promise_cb push_promise_cb,
                    h2_push_response_cb push_response_cb,
                    h2_sess_free_cb sess_free_cb, void *sess_user_data) {

  if ((push_promise_cb && !push_response_cb) ||
      (!push_promise_cb && push_response_cb)) {
    warnx("push_promise_cb and push_response_cb should be set conicide");
    return NULL;
  }

  /* get host and port from req[0].authority */
  char *port, *host = strdup(authority);
  if ((port = strrchr(host, ':'))) {
    *(port++) = '\0';  /* close host string and skip ':' */
  }
  if (strlen(host) <= 0 || port == 0) {
    warnx("invalid first authority value; should be ip:port formatted: %s",
          authority);
    free(host);
    return NULL;
  }

  struct addrinfo hints;
  struct addrinfo *res, *ai;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif
  hints.ai_protocol = 0;
  if (getaddrinfo(host, port, &hints, &res)) {
    warnx("cannot resolve server address: %s", authority);
    free(host);
    return NULL;
  }
  free(host);

  h2_sess *sess = NULL;
  for (ai = res; ai; ai = ai->ai_next) {
    int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock >= 0) {
      h2_set_close_exec(sock);
      if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) {
        /* connect succeeded */
        if ((sess = h2_sess_client_start(sock, ctx, authority, cli_ssl_ctx))) {
          break;
        }
      }
      close(sock);
    }
  }
  freeaddrinfo(res);
  if (sess == NULL) {
    warnx("%s cannot connect\n", authority);
    return NULL;
  }

  /* init user data and callbacks */ 
  sess->response_cb = response_cb;
  sess->push_promise_cb = push_promise_cb;
  sess->push_response_cb = push_response_cb;
  sess->sess_free_cb = sess_free_cb;
  sess->user_data = sess_user_data;

  return sess;
}


/*
 * Server Session I/O ------------------------------------------------------
 */

/* Send HTTP/2 client connection header, which includes 24 bytes */
/* magic octets and SETTINGS frame */
static int h2_sess_server_send_conn_hdr(h2_sess *sess) {
  nghttp2_settings_entry iv[] = {
      { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 } };

  int r = nghttp2_submit_settings(sess->ng_sess, NGHTTP2_FLAG_NONE, iv, 1);
  if (r != 0) {
    warnx("submit setting failed: %s", nghttp2_strerror(r));
    return -1;
  }
  if (h2_sess_send(sess) < 0) {
    return -2;
  }
  return 0;
}

static int h2_sess_server_tcp_start(h2_sess *sess)
{
  fprintf(stderr, "%sCONNECTED TCP\n", sess->log_prefix);

  h2_sess_nghttp2_init(sess);

  return h2_sess_server_send_conn_hdr(sess);
}


#ifdef TLS_MODE
static int h2_sess_server_tls_start(h2_sess *sess)
{
  const unsigned char *alpn = NULL;
  unsigned int alpnlen = 0;
  SSL *ssl = sess->ssl;

  fprintf(stderr, "%sCONNECTED TLS\n", sess->log_prefix);

  SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
  if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
    warnx("%stls alpn h2 is not negotiated: alpn=%p alpnlen=%d\n",
          sess->log_prefix, alpn, alpnlen);
    return -1;
  }

  h2_sess_nghttp2_init(sess);

  if (h2_sess_server_send_conn_hdr(sess) < 0) {
    return -2;
  }
  return 0;
}
#endif

static h2_sess *h2_sess_init_server(h2_ctx *ctx, h2_svr *svr, int fd, 
                                    struct sockaddr *addr, socklen_t addrlen) {
  /* NOTE: on error, fd is closed */

  h2_sess *sess = calloc(1, sizeof(h2_sess));
  sess->obj.cls = &h2_cls_sess;

  /* insert into ctx session list */
  sess->next = ctx->sess_list_head.next;
  ctx->sess_list_head.next = sess;
  sess->prev = &ctx->sess_list_head;
  if (sess->next) {
    sess->next->prev = sess;
  }
  ctx->sess_num++;

  sess->ctx = ctx;
  sess->is_server = 1;

  /* mark start time */
  gettimeofday(&sess->tv_begin, NULL);

  /* get log prefix info */
  char host[NI_MAXHOST], serv[NI_MAXSERV];
  if (getnameinfo(addr, addrlen, host, sizeof(host),
                  serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV)) {
    sess->log_prefix = strdup("(unknown)");
  } else {
    char log_prefix[NI_MAXHOST + NI_MAXSERV + 1 + 1];
    sprintf(log_prefix, "%s:%s ", host, serv);
    sess->log_prefix = strdup(log_prefix);
  }
  unsigned short port = atoi(serv);

  /* do blocking, no wait send */
  int v = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof(v));
  sess->fd = fd;

#ifdef EPOLL_MODE
  struct epoll_event e;
  e.events = EPOLLIN;
  e.data.ptr = &sess->obj;
  if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, sess->fd, &e) < 0) {
    warnx("sess server init failed for epoll_ctl() error: %s", strerror(errno));
    h2_svr_free(svr);
    return NULL;
  }
#endif

  /* call user accept callback */
  SSL_CTX *sess_ssl_ctx = NULL;
  if (svr->accept_cb) {
    int r = svr->accept_cb(svr, svr->user_data, host, port,
                           &sess_ssl_ctx, &sess->request_cb,
                           &sess->sess_free_cb, &sess->user_data);
    if (r < 0) {
      warnx("%saccept_cb failed: %d", sess->log_prefix, r);
      sess->sess_free_cb = NULL;
      sess->user_data = NULL;
      h2_sess_free(sess);
      return NULL;
    }
  }

#ifdef TLS_MODE
  if (svr->ssl_ctx) {
    sess->ssl = SSL_new((sess_ssl_ctx)? sess_ssl_ctx : svr->ssl_ctx);
    if (!sess->ssl) {
      warnx("%scannot create ssl session: %s",
            sess->log_prefix, ERR_error_string(ERR_get_error(), NULL));
      h2_sess_free(sess);
      return NULL;
    }
    SSL_set_fd(sess->ssl, sess->fd);
    if (SSL_accept(sess->ssl) < 0) {
      warnx("%scannot create ssl session: %s",
            sess->log_prefix, ERR_error_string(ERR_get_error(), NULL));
      h2_sess_free(sess);
      return NULL;
    }
    if (h2_sess_server_tls_start(sess) < 0)  {
      h2_sess_free(sess);
      return NULL;
    }
  } else
#endif
  {
    if (h2_sess_server_tcp_start(sess) < 0) {
      h2_sess_free(sess);
      return NULL;
    }
  }

  h2_set_nonblock(fd);
  return sess;
}

h2_svr *h2_listen(h2_ctx *ctx, const char *authority, SSL_CTX *svr_ssl_ctx,
                  h2_accept_cb accept_cb,
                  h2_svr_free_cb svr_free_cb, void *svr_user_data) {
  /* get host and port from req[0].authority */
  char *port, *host = strdup(authority);
  if ((port = strrchr(host, ':'))) {
    *(port++) = '\0';  /* close host string and skip ':' */
  }
  if (port == NULL) {
    warnx("invalid first authority value; should be ip:port formatted: %s",
          authority);
    free(host);
    return NULL;
  }

  struct addrinfo hints;
  struct addrinfo *res, *ai;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif
  hints.ai_protocol = 0;
  if (getaddrinfo(host, port, &hints, &res)) {
    warnx("cannot resolve server address: %s", authority);
    free(host);
    return NULL;
  }
  free(host);

  int v = 1, sock = -1;
  for (ai = res; ai; ai = ai->ai_next) {
    sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock >= 0) {
      h2_set_close_exec(sock);
      if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) < 0) {
        warnx("setsockopt(SO_REUSEADDR) failed; go ahead: %s",
              authority);
      }
      if (bind(sock, ai->ai_addr, ai->ai_addrlen) == 0) {
        if (listen(sock, 1024/* TO BE TUNED WITH SYSTEM SOMAXCONN */) == 0) {
          break;
        }
        warnx("Listen failed: %s error=%s", authority, strerror(errno));
      }
      close(sock);
      sock = -1;
    }
  }
  freeaddrinfo(res);
  if (sock < 0) {
    warnx("cannot listen on %s", authority);
    return NULL;
  }
  /* now, sock is valid listen socket */
  /* ASSUME: authority is not conflicting for bind() already checked */

  h2_svr *svr = calloc(1, sizeof(h2_svr));
  svr->obj.cls = &h2_cls_svr;

  /* insert into ctx server list */
  svr->next = ctx->svr_list_head.next;
  ctx->svr_list_head.next = svr;
  svr->prev = &ctx->svr_list_head;
  if (svr->next) {
    svr->next->prev = svr;
  }
  ctx->svr_num++;

  svr->ctx = ctx;
  svr->authority = strdup(authority);
  svr->ssl_ctx = svr_ssl_ctx;
  svr->accept_fd = sock;

  svr->accept_cb = accept_cb;
  svr->svr_free_cb = svr_free_cb;
  svr->user_data = svr_user_data;

#ifdef EPOLL_MODE
  struct epoll_event e;
  e.events = EPOLLIN;
  e.data.ptr = &svr->obj;
  if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, svr->accept_fd, &e) < 0) {
    warnx("svr init failed for epoll_ctl() error: %s", strerror(errno));
    h2_svr_free(svr);
    return NULL;
  }
#endif

  fprintf(stderr, "listen %s for http2/%s\n",
          authority, (svr_ssl_ctx)? "tls" : "tcp");
  return svr;
}

void h2_svr_free(h2_svr *svr) {
  /* call server user data free callback */
  if (svr->svr_free_cb) {
    svr->svr_free_cb(svr, svr->user_data);
    svr->svr_free_cb = NULL;
    svr->user_data = NULL;
  }

  /* delete from ctx server list */
  svr->prev->next = svr->next;
  if (svr->next) {
    svr->next->prev = svr->prev;
  }
  svr->ctx->svr_num--;

  if (svr->accept_fd >= 0) {
#ifdef EPOLL_MODE
    epoll_ctl(svr->ctx->epoll_fd, EPOLL_CTL_DEL, svr->accept_fd, NULL);
#endif
    close(svr->accept_fd);
    svr->accept_fd = -1;
  }

  free(svr->authority);
  svr->authority = NULL;

  free(svr);
}

const char *h2_svr_authority(h2_svr *svr) {
  return (svr)? svr->authority : NULL;
}

SSL_CTX *h2_svr_ssl_ctx(h2_svr *svr) {
  return (svr)? svr->ssl_ctx : NULL;
}


/*
 * Context and Service Loop common for client and server --------------------
 */

h2_ctx *h2_ctx_init(int verbose) {
  h2_ctx *ctx = calloc(1, sizeof(h2_ctx));
  ctx->obj.cls = &h2_cls_ctx;

#ifdef EPOLL_MODE
  ctx->epoll_fd = epoll_create(1/* not used; just non zero */);
  if (ctx->epoll_fd < 0) {
    warnx("init failed for epoll create error: %s\n", strerror(errno));
    free(ctx);
    return NULL;
  }
#endif

  ctx->verbose = verbose;
  return ctx;
}

void h2_ctx_free(h2_ctx *ctx) {

  h2_svr *svr = ctx->svr_list_head.next;
  while (svr) {
    h2_svr *next = svr->next;
    h2_svr_free(svr);
    svr = next;
  }

  h2_sess *sess = ctx->sess_list_head.next;
  while (sess) {
    h2_sess *next = sess->next;
    h2_sess_free(sess);
    sess = next;
  }

#ifdef EPOLL_MODE
  if (ctx->epoll_fd >= 0) {
    close(ctx->epoll_fd);
    ctx->epoll_fd = -1;
  }
#endif

  free(ctx);
}

void h2_ctx_set_verbose(h2_ctx *ctx, int verbose)
{
  if (ctx) {
    ctx->verbose = verbose;
  }
}

void h2_ctx_stop(h2_ctx *ctx) {
  if (ctx) {
    ctx->service_flag = 0;
  }
}

#ifdef EPOLL_MODE

void h2_ctx_run(h2_ctx *ctx) {
  ctx->service_flag = 1;

  int epe_max, epe_alloced = 1024;
  struct epoll_event *epe;  /* dynamic allcoed epoll_event[epe_alloced] */
  epe = malloc(sizeof(*epe) * epe_alloced); 

  while (ctx->service_flag) {
    /* prepare poll fd array */
    epe_max = ctx->sess_num + ctx->svr_num;
    if (epe_alloced < epe_max) {
      epe_alloced = ((epe_max + 16 + 1023) / 1024) * 1024;
      epe = realloc(epe, sizeof(*epe) * epe_alloced); 
      if (epe == NULL) {
        warnx("epoll event buffer realloc failed; quit run loop: size=%d",
              (int)(sizeof(*epe) * epe_alloced));
        break;
      }
    }
    if (epe_max <= 0) {
      break;  /* no more session to service */
    }

    /* wait for epoll event */
    int r = epoll_wait(ctx->epoll_fd, epe, epe_max, 100);
    if (r == 0 || (r < 0 && errno == EINTR)) {
      continue;
    } else if (r < 0) {
      warnx("epoll_wait() error; quit run loop: %s", strerror(errno));
      break;
    }

    /* check for h2 sess/srv socket */
    struct epoll_event *e = epe;
    for ( ; r > 0; r--, e++) {
      int events = e->events;
      if (((h2_obj *)e->data.ptr)->cls == &h2_cls_svr) {
        /* server acccept event */
        h2_svr *svr = (void *)e->data.ptr;
        if ((events & EPOLLIN)) {
          struct sockaddr sa;
          socklen_t sa_len = sizeof(sa);  /* in/out argument */
          int fd;
          if ((fd = accept(svr->accept_fd, &sa, &sa_len)) >= 0) {
            h2_set_close_exec(fd);
            h2_sess_init_server(ctx, svr, fd, &sa, sa_len);
          } else {
            warnx("accept() failed on server socket: %s", strerror(errno));
          }
        }
      } else if (((h2_obj *)e->data.ptr)->cls == &h2_cls_sess) {
        /* session rw event */
        h2_sess *sess = (void *)e->data.ptr;
        if ((events & EPOLLIN)) {
          if (h2_sess_recv(sess) < 0) {
            h2_sess_free(sess);
            continue;
          }
        }
        if ((events & (EPOLLOUT | EPOLLIN))) {
          if (h2_sess_send(sess) < 0) {
            h2_sess_free(sess);
            continue;
          }
        }
        if ((events & EPOLLRDHUP)) {
          warnx("socket closed by peer\n");
          sess->close_reason = CLOSE_BY_SOCK_EOF;
          h2_sess_free(sess);
          continue;
        }
        if ((events & (EPOLLERR | EPOLLHUP))) {
          warnx("socket errored: epoll_events=0x%02x\n", events);
          sess->close_reason = CLOSE_BY_SOCK_ERR;
          h2_sess_free(sess);
          continue;
        }
      }
    }
  }

  free(epe);
}

#else /* EPOLL_MODE */

void h2_ctx_run(h2_ctx *ctx) {
  ctx->service_flag = 1;

  int pfd_alloced = 1024;
  struct pollfd *pfd = NULL;
  h2_obj **pfd_obj = NULL;
  pfd = malloc(sizeof(*pfd) * pfd_alloced); 
  pfd_obj = malloc(sizeof(*pfd_obj) * pfd_alloced); 

  while (ctx->service_flag) {
    /* prepare poll fd array */
    if (pfd_alloced < ctx->sess_num + ctx->svr_num) {
      pfd_alloced = ((ctx->sess_num + ctx->svr_num + 16 + 1023) / 1024) * 1024;
      pfd = realloc(pfd, sizeof(*pfd) * pfd_alloced); 
      pfd_obj = realloc(pfd_obj, sizeof(*pfd_obj) * pfd_alloced); 
    }
    /* fill pollfds and wait for events */
    int n = 0;
    h2_svr *svr;
    for (svr = ctx->svr_list_head.next; svr; svr = svr->next) {
      if (svr->accept_fd >= 0) {
        pfd[n].fd = svr->accept_fd;
        pfd[n].events = POLLIN;
        pfd_obj[n] = &svr->obj;
        n++;
      }
    }
    h2_sess *sess, *sess_next;
    for (sess = ctx->sess_list_head.next; sess; sess = sess_next) {
      sess_next = sess->next;  /* for sess free case */
      pfd[n].fd = sess->fd;
      pfd[n].events = 0;
      if (nghttp2_session_want_read(sess->ng_sess)) {
        pfd[n].events |= POLLIN;
      }
      if (h2_wr_buf_pending(&sess->wr_buf) ||
          nghttp2_session_want_write(sess->ng_sess)) {
        pfd[n].events |= POLLOUT;
      }
      if (pfd[n].events == 0) {
        h2_sess_free(sess);
        continue;
      }
      pfd_obj[n] = &sess->obj;
      n++;
    }
    if (n == 0) { /* quit service if nothing to do */
      break;
    }

    /* wait for event */
    int r = poll(pfd, n, 100);
    if (r == 0 || (r < 0 && errno == EINTR)) {
      continue;
    } else if (r < 0) {
      warnx("poll() error; quit run loop: %s", strerror(errno));
      break;
    }

    /* check for h2 sess/srv socket */
    int i;
    for (i = 0; i < n && r > 0; i++) {
      if (pfd[i].revents == 0) {
        continue;
      }
      r--;
      int revents = pfd[i].revents;
      if (pfd_obj[i]->cls == &h2_cls_svr) {
        /* server acccept event */
        svr = (void *)pfd_obj[i];
        if ((revents & POLLIN)) {
          struct sockaddr sa;
          socklen_t sa_len = sizeof(sa);  /* in/out argument */
          int fd;
          if ((fd = accept(svr->accept_fd, &sa, &sa_len)) >= 0) {
            h2_set_close_exec(fd);
            h2_sess_init_server(ctx, svr, fd, &sa, sa_len);
          } else {
            warnx("accept() failed on server socket: %s", strerror(errno));
          }
        }
      } else if (pfd_obj[i]->cls == &h2_cls_sess) {
        /* session rw event */
        sess = (void *)pfd_obj[i];
        if ((revents & POLLIN)) {
          if (h2_sess_recv(sess) < 0) {
            h2_sess_free(sess);
            continue;
          }
        }
        if ((revents & (POLLOUT | POLLIN))) {
          if (h2_sess_send(sess) < 0) {
            h2_sess_free(sess);
            continue;
          }
        }
        if ((revents & POLLRDHUP)) {
          warnx("socket closed by peer\n");
          sess->close_reason = CLOSE_BY_SOCK_EOF;
          h2_sess_free(sess);
          continue;
        }
        if ((revents & (POLLERR | POLLHUP | POLLNVAL))) {
          warnx("socket errored: revents=0x%02x\n", revents);
          sess->close_reason = CLOSE_BY_SOCK_ERR;
          h2_sess_free(sess);
          continue;
        }
      }
    }
  }

  free(pfd);
  free(pfd_obj);
}

#endif /* EPOLL_MODE */

