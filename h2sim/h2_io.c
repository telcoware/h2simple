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
#include <arpa/inet.h>
#ifdef EPOLL_MODE
#include <sys/epoll.h>
#endif
#include <poll.h>

#ifdef TLS_MODE
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#endif

#include "h2.h"
#include "h2_priv.h"


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

void h2_sess_mark_send_pending(h2_sess *sess) {
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

void h2_sess_clear_send_pending(h2_sess *sess) {
  if (sess->send_pending) {
#ifdef EPOLL_MODE
    struct epoll_event e;
    e.events = EPOLLIN;
    e.data.ptr = &sess->obj;
    epoll_ctl(sess->fd, EPOLL_CTL_MOD, sess->fd, &e);
#endif
    sess->send_pending = 0;
  }
}

int h2_sess_send(h2_sess *sess) {
  int r;

  if (sess->http_ver == H2_HTTP_V2) {
    do {
      r = h2_sess_send_once_v2(sess);
    } while (r > 0);
  } else {
    do {
      r = h2_sess_send_once_v1_1(sess);
    } while (r > 0);
  }

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

  if (sess->http_ver == H2_HTTP_V2) {
    /* NOTE: read_len is same as recv_len on success case */
    if ((read_len = h2_sess_recv_v2(sess, buf, recv_len)) < 0) {
      sess->close_reason = CLOSE_BY_NGHTTP2_ERR;
      return -3;
    }
  } else {
    if ((read_len = h2_sess_recv_v1_1(sess, buf, recv_len)) < 0) {
      sess->close_reason = CLOSE_BY_HTTP_ERR;
      return -3;
    }
  }

  if (sess->is_no_more_req && sess->req_cnt == sess->rsp_cnt &&
      !sess->is_terminated) {
    /* shutdown send side */
    if (sess->ctx->verbose) {
      warnx("%sTERMINATE SESSION FOR ALL RESPONSE RECEIVED", sess->log_prefix);
    }
    if (sess->http_ver == H2_HTTP_V2) {
      h2_sess_terminate_v2(sess);
    } else {
      h2_sess_terminate_v1_1(sess);
    }
  }

  return (int)read_len;
}


/*
 * Session Common ----------------------------------------------------------
 */

int h2_sess_terminate(h2_sess *sess, int wait_rsp) {
  if (sess == NULL || sess->is_terminated) {
    return 1;  /* already terminated */
  }

  if (wait_rsp) {
    if (sess->is_no_more_req) {
      return 1;  /* already no_more_req marked */
    }
    sess->is_no_more_req = 1;
    /* session is to be shutdown(SEND) when current strms are all closed */
  } else {
    if (sess->ctx->verbose) {
      warnx("%sTERMINATE SESSION IMMEDIATE", sess->log_prefix);
    }
    sess->is_terminated = 1;
    if (sess->http_ver == H2_HTTP_V2) {
      h2_sess_terminate_v2(sess);
    } else {
      h2_sess_terminate_v1_1(sess);
    } 
    /* mark close event to be handled */  
    h2_sess_mark_send_pending(sess);
  }

  return 0;
}
  

/*
 * Client Session I/O ------------------------------------------------------
 */

static h2_sess *h2_sess_init_client(h2_ctx *ctx, h2_peer *peer, SSL *ssl,
                                    int fd, const char *authority,
                                    int http_ver, h2_settings *settings) {
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
  sess->peer = peer;
  sess->http_ver = http_ver;
  sess->is_server = 0;
  if (settings) {
    sess->settings = *settings;
  } else {
    h2_settings_init(&sess->settings);
  }

  sess->ssl = ssl;
  sess->fd = fd;

  /* use local binding address for session log prefix */
  struct sockaddr_in6 sa;  /* to allow ipv4 and ipv6 */
  socklen_t salen = sizeof(sa);
  if (getsockname(fd, (struct sockaddr *)&sa, &salen) == 0) {
    /* get log prefix info */
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    if (getnameinfo((struct sockaddr *)&sa, salen, host, sizeof(host),
                    serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV)) {
      sess->log_prefix = strdup("(unknown)");
    } else {
      char log_prefix[1 + NI_MAXHOST + 1 + 1 + NI_MAXSERV + 1];
      if (((struct sockaddr *)&sa)->sa_family == AF_INET6) {
         sprintf(log_prefix, "[%s]:%s ", host, serv);
      } else {
         sprintf(log_prefix, "%s:%s ", host, serv);
      }
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

  if (http_ver == H2_HTTP_V2 || http_ver == H2_HTTP_V2_TRY) {
    h2_sess_init_v2(sess);
  }

  /* mark start time */
  gettimeofday(&sess->tv_begin, NULL);

  return sess;
}

static h2_sess *h2_sess_client_start(int sock, h2_ctx *ctx, h2_peer *peer,
                    const char *authority, SSL_CTX *client_ssl_ctx,
                    h2_settings *settings) {
  SSL *ssl = NULL;
  int http_ver = ctx->http_ver;
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
    if (http_ver == H2_HTTP_V2 || http_ver == H2_HTTP_V2_TRY) {
      SSL_set_alpn_protos(ssl, (const unsigned char *)"\x02h2", 3);
    }
    SSL_set_fd(ssl, sock);
    r = SSL_connect(ssl);
    if (r == 0) {
      warnx("%s connected but shutdown by tls protocol: %d",
            authority, SSL_get_error(ssl, r));
      SSL_free(ssl);
      return NULL;
    } else if (r < 0) {
      warnx("%s tls handshake failed: %s",
            authority, ERR_error_string(ERR_get_error(), NULL));
      SSL_free(ssl);
      return NULL;
    }
    SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
    if (alpn && alpnlen == 2 && !memcmp("h2", alpn, 2)) {
      http_ver = H2_HTTP_V2;
    } else if (http_ver == H2_HTTP_V2) {
      warnx("%s h2 is not negotiated; HTTP/2 failed", authority);
      SSL_free(ssl);
      return NULL;
    } else {
      http_ver = H2_HTTP_V1_1;
    }
    /* now, http_ver of TLS is fixed to H2_HTTP_V2 or H2_HTTP_V1_1 */
  }
#endif /* TLS_MODE */
  
  h2_sess *sess = h2_sess_init_client(ctx, peer, ssl, sock, authority,
                                      http_ver, settings);
  if (sess == NULL) {
    return NULL;
  }

  char *transport = (client_ssl_ctx)? "TLS" : "TCP";
  if (http_ver == H2_HTTP_V2) {
    /* HTTP2 initial message */
    if (h2_sess_send_settings_v2(sess) < 0) {
      h2_sess_free(sess);
      return NULL;
    }
    fprintf(stderr, "%sCONNECTED %s HTTP/2 TO %s\n",
            sess->log_prefix, transport, authority);
  } else if (http_ver == H2_HTTP_V2_TRY) {
    /* try to upgrade to HTTP2; TCP only */
#if 0  /* TODO: TO BE IMPLEMENTED */
    if (h2_sess_send_upgrade_req_tcp(sess, authority, settings) < 0) {
      h2_sess_free(sess);
      return NULL;
    }
#endif
    fprintf(stderr, "%sCONNECTED %s HTTP/2-TRY TO %s\n",
            sess->log_prefix, transport, authority);
  } else {
    /* HTTP/1.1 */
    fprintf(stderr, "%sCONNECTED %s HTTP/1.1 TO %s\n",
            sess->log_prefix, transport, authority);
  }

  return sess;
}

/* Start connecting to the remote peer |host:port| */
static h2_sess *h2_sess_connect(h2_ctx *ctx, h2_peer *peer,
                                const char *authority, SSL_CTX *cli_ssl_ctx,
                                h2_settings *settings) {

  /* get host and port from req[0].authority */
  char *port, *host = strdup(authority);
  int n;
  if ((port = strrchr(host, ':'))) {
    *(port++) = '\0';  /* close host string and skip ':' */
  }
  if (host[0] == '[' && host[(n = strlen(host)) - 1] == ']' && n >= 3) {
    /* '[ipv6_address]' case */
    memmove(host, host + 1, n - 2);
    host[n - 2] = '\0';
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
    warnx("cannot resolve server address: %s: host='%s' port='%s'", authority,
          host, port);
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
        if ((sess = h2_sess_client_start(sock, ctx, peer, authority,
                                         cli_ssl_ctx, settings))) {
          break;
        }
      }
      close(sock);
    }
  }
  freeaddrinfo(res);
  if (sess == NULL) {
    warnx("cannot connect to %s", authority);
    return NULL;
  }

  h2_set_nonblock(sess->fd);

  return sess;
}


/*
 * Server Session I/O ------------------------------------------------------
 */

static int h2_sess_server_tcp_start(h2_sess *sess) {

  if (sess->http_ver == H2_HTTP_V2) {
    h2_sess_init_v2(sess);
    if (h2_sess_send_settings_v2(sess) < 0) {
      return -1;
    } 
    fprintf(stderr, "%sCONNECTED TCP HTTP/2\n", sess->log_prefix);
  } else if (sess->http_ver == H2_HTTP_V1_1) {
    fprintf(stderr, "%sCONNECTED TCP HTTP/1.1\n", sess->log_prefix);
  } else {
    /* NOTE: on client's setting received, h2_sess_send_settings_v2() is called */
    h2_sess_init_v2(sess);
    fprintf(stderr, "%sCONNECTED TCP HTTP/1.1 UPGRADABLE TO HTTP/2\n",
            sess->log_prefix);
  }
  return 0;
}

#ifdef TLS_MODE
static int h2_sess_server_tls_start(h2_sess *sess) {
  const unsigned char *alpn = NULL;
  unsigned int alpnlen = 0;
  SSL *ssl = sess->ssl;

  SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
  if (alpn && alpnlen == 2 && !memcmp("h2", alpn, 2)) {
    sess->http_ver = H2_HTTP_V2;
  } else {
    if (sess->http_ver == H2_HTTP_V2) {
      warnx("%stls alpn h2 is not negotiated: alpn=%p alpnlen=%d",
            sess->log_prefix, alpn, alpnlen);
      return -1;
    }
    /* else, sess->http_ver == H2_HTTP_V2_TRY */
    sess->http_ver = H2_HTTP_V1_1;
  }

  if (sess->http_ver == H2_HTTP_V2) {
    h2_sess_init_v2(sess);
    if (h2_sess_send_settings_v2(sess) < 0) {
       return -1;
    }
    fprintf(stderr, "%sCONNECTED TLS HTTP/2\n", sess->log_prefix);
  } else {
    fprintf(stderr, "%sCONNECTED TLS HTTP/1.1\n", sess->log_prefix);
  }
  return 0;
}
#endif

static h2_sess *h2_sess_init_server(h2_ctx *ctx, h2_svr *svr, int fd, 
                                    struct sockaddr *sa, socklen_t salen) {
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
  sess->peer = NULL;
  sess->http_ver = ctx->http_ver;
  sess->is_server = 1;
  h2_settings_init(&sess->settings);

  /* mark start time */
  gettimeofday(&sess->tv_begin, NULL);

  /* get log prefix info */
  char host[NI_MAXHOST], serv[NI_MAXSERV];
  if (getnameinfo(sa, salen, host, sizeof(host),
                  serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV)) {
    sess->log_prefix = strdup("(unknown)");
  } else {
    char log_prefix[1 + NI_MAXHOST + 1 + 1 + NI_MAXSERV + 1];
    if (sa->sa_family == AF_INET6) {
       sprintf(log_prefix, "[%s]:%s ", host, serv);
    } else {
       sprintf(log_prefix, "%s:%s ", host, serv);
    }
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
                           &sess_ssl_ctx, &sess->settings,
                           &sess->request_cb,
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

  h2_set_nonblock(sess->fd);

  return sess;
}

h2_svr *h2_listen(h2_ctx *ctx, const char *authority, SSL_CTX *svr_ssl_ctx,
                  h2_accept_cb accept_cb,
                  h2_svr_free_cb svr_free_cb, void *svr_user_data) { /* get host and port from req[0].authority */
  char *port, *host = strdup(authority);
  int n;
  if ((port = strrchr(host, ':'))) {
    *(port++) = '\0';  /* close host string and skip ':' */
  }
  if (host[0] == '[' && host[(n = strlen(host)) - 1] == ']' && n >= 3) {
    /* '[ipv6_address]' case */
    memmove(host, host + 1, n - 2);
    host[n - 2] = '\0';
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

h2_ctx *h2_ctx_init(int http_ver, int verbose) {
  h2_ctx *ctx = calloc(1, sizeof(h2_ctx));
  ctx->obj.cls = &h2_cls_ctx;

#ifdef EPOLL_MODE
  ctx->epoll_fd = epoll_create(1/* not used; just non zero */);
  if (ctx->epoll_fd < 0) {
    warnx("init failed for epoll create error: %s", strerror(errno));
    free(ctx);
    return NULL;
  }
#endif

  ctx->http_ver = http_ver;
  ctx->verbose = verbose;
  return ctx;
}

void h2_ctx_free(h2_ctx *ctx) {
  ctx->service_flag = 0;

  while (ctx->svr_list_head.next) {
    h2_svr_free(ctx->svr_list_head.next);
  }

  while (ctx->peer_list_head.next) {
    h2_terminate(ctx->peer_list_head.next, 0);
    h2_peer_free(ctx->peer_list_head.next);
  }

  while (ctx->sess_list_head.next) {
    h2_sess_terminate(ctx->sess_list_head.next, 0);
    h2_sess_free(ctx->sess_list_head.next);
  }

#ifdef EPOLL_MODE
  if (ctx->epoll_fd >= 0) {
    close(ctx->epoll_fd);
    ctx->epoll_fd = -1;
  }
#endif

  free(ctx);
}

void h2_ctx_set_http_ver(h2_ctx *ctx, int http_ver) {
  if (ctx) {
    ctx->http_ver = http_ver;
  }
}

void h2_ctx_set_verbose(h2_ctx *ctx, int verbose) {
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

  int ea_max, ea_alloced = 1024;
  struct epoll_event *ea;  /* dynamic allcoed epoll_event[epe_alloced] */
  ea = malloc(sizeof(*ea) * ea_alloced); 

  while (ctx->service_flag) {
    /* prepare poll fd array */
    ea_max = ctx->sess_num + ctx->svr_num;
    if (ea_alloced < ea_max) {
      ea_alloced = ((ea_max + 16 + 1023) / 1024) * 1024;
      ea = realloc(ea, sizeof(*ea) * ea_alloced); 
      if (ea == NULL) {
        warnx("epoll event buffer realloc failed; quit run loop: size=%d",
              (int)(sizeof(*ea) * ea_alloced));
        break;
      }
    }
    if (ea_max <= 0) {
      break;  /* no more session to service */
    }

    /* wait for epoll event */
    int r = epoll_wait(ctx->epoll_fd, ea, ea_max, 100);
    if (r == 0 || (r < 0 && errno == EINTR)) {
      continue;
    } else if (r < 0) {
      warnx("epoll_wait() error; quit run loop: %s", strerror(errno));
      break;
    }

    /* check for h2 sess/srv socket */
    struct epoll_event *e = ea;
    int event_num;
    for (event_num = r ; event_num > 0; event_num--, e++) {
      int events = e->events;
      if (((h2_obj *)e->data.ptr)->cls == &h2_cls_svr) {
        /* server acccept event */
        h2_svr *svr = (void *)e->data.ptr;
        if ((events & EPOLLIN)) {
          struct sockaddr_in6 sa;  /* to allow ipv4 and ipv6 */
          socklen_t sa_len = sizeof(sa);  /* in/out argument */
          int fd = accept(svr->accept_fd, (struct sockaddr *)&sa, &sa_len);
          if (fd >= 0) {
            h2_set_close_exec(fd);
            h2_sess_init_server(ctx, svr, fd, (struct sockaddr *)&sa, sa_len);
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
        if ((events & (EPOLLOUT || EPOLLIN))) {  /* always do send after recv */
          if (sess->is_terminated && sess->http_ver != H2_HTTP_V2) {
            sess->close_reason = CLOSE_BY_HTTP_END;
            h2_sess_free(sess);
          } else {
            if (h2_sess_send(sess) < 0) {
              h2_sess_free(sess);
              continue;
            }
          }
        }
        if ((events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
          sess->close_reason = CLOSE_BY_SOCK_ERR;
          if (!sess->is_terminated) {
            warnx("socket errored: epoll_events=0x%02x sess=%s",
                  events, sess->log_prefix);
          }
          h2_sess_free(sess);
          continue;
        }
      }
    }
  }

  free(ea);
}

#else /* EPOLL_MODE; use poll() */

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
#if 1
      /* do not use nghttp2_session info; just follow epoll event status */
      if (!sess->is_terminated) {
        pfd[n].events |= POLLIN;
      }
      if (sess->send_pending) {
        pfd[n].events |= POLLOUT;
      }
#else 
      if (sess->http_ver == H2_HTTP_V2) {
        if (nghttp2_session_want_read(sess->ng_sess)) {
          pfd[n].events |= POLLIN;
        }
        if (sess->send_pending || nghttp2_session_want_write(sess->ng_sess)) {
          pfd[n].events |= POLLOUT;
        }
      } else {
        if (sess->is_terminated == 1) {
          pfd[n].events |= POLLIN;
        }
        if (sess->send_pending) {
          pfd[n].events |= POLLOUT;
        }
      }
#endif
      if (pfd[n].events == 0) {
        sess->close_reason = CLOSE_BY_HTTP_END;
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
    int i, event_num = r;
    for (i = 0; i < n && event_num > 0; i++) {
      if (pfd[i].revents == 0) {
        continue;
      }
      event_num--;
      int revents = pfd[i].revents;
      if (pfd_obj[i]->cls == &h2_cls_svr) {
        /* server acccept event */
        svr = (void *)pfd_obj[i];
        if ((revents & POLLIN)) {
          struct sockaddr_in6 sa;  /* to allow ipv4 and ipv6 */
          socklen_t sa_len = sizeof(sa);  /* in/out argument */
          int fd = accept(svr->accept_fd, (struct sockaddr *)&sa, &sa_len);
          if (fd >= 0) {
            h2_set_close_exec(fd);
            h2_sess_init_server(ctx, svr, fd, (struct sockaddr *)&sa, sa_len);
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
        if ((revents & (POLLOUT || POLLIN))) {  /* always do send after recv */
          if (h2_sess_send(sess) < 0) {
            h2_sess_free(sess);
            continue;
          }
        }
        if ((revents & POLLRDHUP)) {
          warnx("socket closed by peer");
          sess->close_reason = CLOSE_BY_SOCK_EOF;
          h2_sess_free(sess);
          continue;
        }
        if ((revents & (POLLERR | POLLHUP | POLLNVAL))) {
          warnx("socket errored: revents=0x%02x", revents);
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


/*
 * Client API Peer I/O -----------------------------------------------------
 */

static h2_sess *h2_peer_connect_sess(h2_peer *peer, int sess_idx) {
  h2_sess *sess = h2_sess_connect(peer->ctx, peer,
                                  peer->authority, peer->ssl_ctx,
                                  &peer->settings);
  if (sess) {
    peer->sess[sess_idx] = sess;
    if (!peer->act_sess[sess_idx]) {
      /* init peers sess status */
      peer->act_sess[sess_idx] = 1;
      peer->act_sess_num++;
    }
  } else {
    warnx("idling 1 sec to prevent busy retry: peer=%s sess_idx=%d",
          peer->authority, sess_idx);
    poll(NULL, 0, 1000);
  }
  return sess;
}

void h2_peer_sess_free_hdlr(h2_peer *peer, h2_sess *sess) {
  int i;

  for (i = 0; i < peer->sess_num; i++) {
    if (peer->sess[i] == sess) {
      break;
    }
  }
  if (i >= peer->sess_num) {
    warnx("peer_sess_free_cb:: unknown session for peer: peer=%s sess=%s",
          peer->authority, sess->log_prefix);
    return;
  }
  /* now, peer->sess[i] is known to be freed */

  /* gather stat from sess */
  peer->req_cnt += sess->req_cnt;
  peer->rsp_cnt += sess->rsp_cnt;
  peer->rsp_rst_cnt += sess->rsp_rst_cnt;
  peer->strm_close_cnt += sess->strm_close_cnt;
  peer->sess_close_cnt++;

  peer->sess[i] = NULL; 
  if (peer->act_sess[i]) {
    peer->act_sess[i] = 0;
    peer->act_sess_num--;
  }

  /* try reconnect is peer or ctx is not termiating */
  if (!peer->is_terminated && !peer->is_no_more_req &&
      peer->ctx->service_flag) {
    h2_peer_connect_sess(peer, i);
  }
}

/* client side context create api to start sessions */
h2_peer *h2_connect(h2_ctx *ctx, SSL_CTX *cli_ssl_ctx,
                    const char *authority, int sess_num, int req_max_per_sess,
                    h2_settings *settings,
                    h2_push_promise_cb push_promise_cb,
                    h2_peer_free_cb peer_free_cb, void *peer_user_data) {
  h2_peer *peer;

  peer = calloc(1, sizeof(*peer)); 
  peer->obj.cls = &h2_cls_peer;

  /* add to ctx peer list */
  peer->next = ctx->peer_list_head.next;
  ctx->peer_list_head.next = peer;
  peer->prev = &ctx->peer_list_head;
  if (peer->next) {
    peer->next->prev = peer; }
  ctx->peer_num++;
  peer->ctx = ctx;

  peer->sess_num = sess_num;
  peer->req_max_per_sess = req_max_per_sess;

  peer->authority = strdup(authority);
  peer->ssl_ctx = cli_ssl_ctx;
  if (settings) {
    peer->settings = *settings;
  } else {
    h2_settings_init(&peer->settings);
  }

  peer->sess = calloc(sess_num, sizeof(*peer->sess));
  peer->next_sess_idx = 0;
  peer->act_sess = calloc(sess_num, sizeof(*peer->act_sess));
  peer->act_sess_num = 0;

  /* mark start time */
  peer->sess_close_cnt = 0;
  peer->strm_close_cnt = 0;
  gettimeofday(&peer->tv_begin, NULL);

  /* connect to peer as sess_num sessions */
  int i;
  for (i = 0; i < sess_num; i++) {
    h2_peer_connect_sess(peer, i);
  }
  if (peer->act_sess_num <= 0) {
    warnx("cannot connect to peer: %s", authority);
    h2_peer_free(peer);
    return NULL;
  }

  /* lazy callbacks assigned for no callback on intial connect failure cases */
  peer->push_promise_cb = push_promise_cb;
  peer->peer_free_cb = peer_free_cb;
  peer->user_data = peer_user_data;

  return peer;
}

void h2_peer_free(h2_peer *peer) {
  int i;

  /* free all sessions */
  for (i = 0; i < peer->sess_num; i++) {
    if (peer->sess[i]) {
      h2_sess_free(peer->sess[i]);
      peer->sess[i] = NULL;
    }
  }

  /* free user data */
  if (peer->peer_free_cb) {
    peer->peer_free_cb(peer, peer->user_data);
    peer->peer_free_cb = NULL;
    peer->user_data = NULL;
  }

  /* delete from ctx sess list */
  peer->prev->next = peer->next;
  if (peer->next) {
    peer->next->prev = peer->prev;
  }
  peer->ctx->peer_num--;
  peer->ctx = NULL;

  peer->ssl_ctx = NULL;

  /* show performance */
  gettimeofday(&peer->tv_end, NULL);
  double elapsed =
     ((peer->tv_end.tv_sec - peer->tv_begin.tv_sec) * 1.0 +
      (peer->tv_end.tv_usec - peer->tv_begin.tv_usec) * 0.000001);
  if (peer->sess_num > 1) {
    fprintf(stderr, "PEER CLOSED %s: %.0f tps (%.3f secs for "
            "%d reqs %d rsps(%d rsts) %d streams in %d sessions)%s\n",
            peer->authority, peer->strm_close_cnt / elapsed,
            elapsed, peer->req_cnt, peer->rsp_cnt, peer->rsp_rst_cnt,
            peer->strm_close_cnt, peer->sess_close_cnt,
            (peer->req_cnt != peer->rsp_cnt|| peer->rsp_rst_cnt)? " !!!" : "");
  }

  free(peer->authority);
  free(peer->sess);
  free(peer->act_sess);
  free(peer);
}

