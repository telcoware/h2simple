/*
 * h2sim - HTTP2 Simple Application Framework using nghttp2
 *
 * Copyright (c) 2019 Lee Yongjae, Telcoware Co.,LTD.
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/time.h>  /* for gettimeofday() */
#include <sys/stat.h>  /* for file read */
#include <fcntl.h>     /* for file read */

#ifdef TLS_MODE
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#else
/* NOTE: h2_util.h defines dummy SSL_CTX and SSL */
#endif

#include "h2sim/h2.h"


int verbose = 1;


#define GET_FILE   1  /* GET request handling for file of request path */

#define RSP_CASE_MAX  100
#define PUSH_PRM_MAX  100


/* application context */

typedef struct http2_rsp_case {
  /* request pattern */
  char *req_method;       /* static string; may be NULL */
  char *req_authority;    /* static string; may be NULL */
  char *req_path_prefix;  /* static string; may be NULL */
  int req_path_prefix_len;

  /* corresponding response */
  h2_msg *rsp;

#ifdef GET_FILE
  /* GET path returns file contents of rsp_base_dir as root dir */
  char *rsp_base_dir;     /* static string; may be NULL */
#endif

  /* push promise and push reponse */
  int push_prm_idx;      /* start of push promises for this req */
  int push_prm_num;      /* number of push promises for this req */

} http2_rsp_case;

typedef struct app_context {
  http2_rsp_case rsp_case[RSP_CASE_MAX];
  int rsp_case_num;

  http2_rsp_case push_prm[PUSH_PRM_MAX];
  int push_prm_num;
} app_context;


/*
 * Application logics -------------------------------------------------------
 */

int request_cb(h2_sess *sess, h2_strm *strm,
               h2_msg *req, void *sess_user_data) {
  /* returns: 0(msg handled), >0(status code to be retured), 0<(error) */
  app_context *app_ctx = sess_user_data;

  if (verbose) {
    h2_dump_msg(stdout, req, "", "REQUEST");
  }

  /* find rsp_case for the request */
  http2_rsp_case *rc = app_ctx->rsp_case;
  int n = app_ctx->rsp_case_num;
  for ( ; n > 0; n--, rc++) {
    if ((rc->req_method == NULL ||
         !strcmp(h2_method(req), rc->req_method)) &&
        (rc->req_authority == NULL ||
         !strcmp(h2_authority(req), rc->req_authority)) &&
        (rc->req_path_prefix == NULL ||
         !strncmp(h2_path(req), rc->req_path_prefix,
                  rc->req_path_prefix_len))) {
      break;  /* rc is matched */
    }
  }
  if (n <= 0) {
    return 404;
  }
  
  /* set response body from rc->rsp */
  h2_msg *rsp = h2_msg_init();
  h2_cpy_msg(rsp, rc->rsp); 
  h2_prepare_rsp(rsp, req);
  /* HERE: TODO: NEED TO PREPARE RESPONSE FROM REQUERST MESSAGE */

#ifdef GET_FILE
  if (h2_body_len(rsp) == 0 && rc->rsp_base_dir) {
    const char *rel_path = h2_path(req);
    char path[1024], *body;
    int body_len;
    if (rel_path[0] == '/') {
      rel_path++;
    }
    sprintf(path, "%s%s", rc->rsp_base_dir, rel_path);
    /* TODO: need to check resulting path; might be security hole */
    if (h2_body_from_file(path, (void **)&body, &body_len) < 0) {
      h2_msg_free(rsp);
      return 404;
    }
    h2_set_body(rsp, body, body_len);
  }
#endif

  /* send optional push promise */
  http2_rsp_case *prm = &app_ctx->push_prm[rc->push_prm_idx];
  for (n = rc->push_prm_num; n > 0; n--, prm++) {
    /* prepare push_promise message */
    h2_msg *prm_req = h2_msg_init();
    h2_prepare_prm(prm_req, req, prm->req_method,
                   (prm->req_path_prefix)? prm->req_path_prefix : h2_path(req));
    /* prepare push_response message */
    h2_msg *prm_rsp = h2_msg_init();
    h2_cpy_msg(prm_rsp, prm->rsp);
    h2_prepare_rsp(prm_rsp, req);

    h2_send_push_promise(sess, strm, prm_req, prm_rsp);

    h2_msg_free(prm_req);
    h2_msg_free(prm_rsp);
  }

  /* send response */
  if (verbose) {
    h2_dump_msg(stdout, rsp, "", "RESPONSE");
  }
  int rs = h2_send_response(sess, strm, rsp);
  h2_msg_free(rsp);

  return (rs < 0)? -1 : 0;
}

int accept_cb(h2_svr *svr, void *server_user_data,
              const char *peer_ip, unsigned short peer_port,
              SSL_CTX **ssl_ctx_ret, h2_request_cb *request_cb_ret,
              h2_sess_free_cb *sess_free_cb_ret, void **sess_user_data_ret) {
  (void)svr;
  (void)peer_ip;
  (void)peer_port;

  /* set accepted session paramters */
  *ssl_ctx_ret = NULL/* use svr_ssl_ctx */;
  *request_cb_ret = request_cb;
  *sess_free_cb_ret = NULL/* static user data */;
  *sess_user_data_ret = server_user_data/* app_ctx * */; 
  return 0;
}

void svr_free_cb(h2_svr *svr, void *svr_user_data) {
  (void)svr_user_data; 
  if (h2_svr_ssl_ctx(svr)) {
    SSL_CTX_free(h2_svr_ssl_ctx(svr));
  }
}


/*
 * Application main and runtime argument parsers ----------------------------
 */

static void help(char *prog) {
  fprintf(stderr, "Usage: %s [server_options] [rsp_case_options]...\n", prog);
  fprintf(stderr, "server_options:\n");
#ifdef TLS_MODE
  fprintf(stderr, "  -K key_file                # default:eckey.pem\n");
  fprintf(stderr, "  -C cert_file               # default:eccert.pem\n");
  fprintf(stderr, "  -S https://<ip>:<port>     # tls server listen ip:port\n");
#endif
  fprintf(stderr, "  -S http://<ip>:<port>      # tcp server listen ip:port\n");
  fprintf(stderr, "  -Q                         # h2sim io quiet mode\n");
  fprintf(stderr, "  -q                         # all quiet mode\n");
  fprintf(stderr, "rsp_case_options:\n");
  fprintf(stderr, "  # -m starts each case\n");
  fprintf(stderr, "  # -a and -p are optional matching condition\n");
  fprintf(stderr, "  -m req_method              # GET|POST|PUT|PATCH|DELETE\n");
  fprintf(stderr, "  -a req_authority\n");
  fprintf(stderr, "  -p req_path_prefix\n");
  fprintf(stderr, "  # -o starts push promose req and response on the case\n");
  fprintf(stderr, "  -o push_prmise_req_path    # assume GET method\n");
  fprintf(stderr, "  -s rsp_status              # default:200\n");
  fprintf(stderr, "  -x rsp_header_name=value\n");
  fprintf(stderr, "  -t rsp_body_text\n");
  fprintf(stderr, "  -b rsp_body_hex_binary\n");
  fprintf(stderr, "  -f rsp_body_file\n");
  fprintf(stderr, "  -e rsp_body_size           # dummy zero value body of given size\n");
#ifdef GET_FILE
  fprintf(stderr, "  -d rsp_file_base_directory # req path is / mapped to this directory\n");
#endif
#ifdef TLS_MODE
  fprintf(stderr, "default: -S https -P 8080 -K eckey.pem -C eccert.pem -m GET -s 200 -r ./\n");
#else
  fprintf(stderr, "default: -S http -P 8080 -m GET -s 200 -r ./\n");
#endif
}

h2_ctx *ctx = NULL;

void sighdlr_mark_stop(int signo) {
  (void)signo;
  h2_ctx_stop(ctx); 
}

int main(int argc, char **argv) {
  /* set app_ctx default */
  app_context app_ctx;
  memset(&app_ctx, 0, sizeof(app_ctx));
  app_ctx.rsp_case_num = 0;

  int verbose_h2 = 1;
#ifdef TLS_MODE
  char *key_file = "eckey.pem";    /* default private key file */
  char *cert_file = "eccert.pem";  /* default certificate file */
#endif
  char *authority = NULL;
  SSL_CTX *ssl_ctx = NULL;
  void *body;
  int body_len;

  /* intialize current response case */
  int rc_is_push_prm = 0;
  http2_rsp_case *rc = &app_ctx.rsp_case[0];
  http2_rsp_case *rc_for_push_prm = rc;
  app_ctx.rsp_case[0].rsp = h2_msg_init();
  app_ctx.push_prm[0].rsp = h2_msg_init();

#ifdef TLS_MODE
  SSL_load_error_strings();
  SSL_library_init();
#endif

  ctx = h2_ctx_init(verbose_h2); 

  int c;
  int listen_num = 0;
  char scale;
  while ((c = getopt(argc, argv, "K:C:S:Qqm:a:p:o:s:x:t:b:f:e:d:h")) >=  0) {
    switch (c) {
#ifdef TLS_MODE
    case 'K':
      key_file = optarg;
      break;
    case 'C':
      cert_file = optarg;
      break;
#endif
    case 'S':
#ifdef TLS_MODE
      if (!strncasecmp(optarg, "https://", 8)) {
        authority = optarg + 8;
        if (!(ssl_ctx = h2_ssl_ctx_init(1/*server*/, key_file, cert_file))) {
          fprintf(stderr, "cannot initialize ssl_ctx: "
                  "key_file=%s cert_file=%s\n", key_file, cert_file);
          return EXIT_FAILURE;
        }
      } else
#endif
      if (!strncasecmp(optarg, "http://", 7)) {
        authority = optarg + 7;
        ssl_ctx = NULL; 
      } else {
        fprintf(stderr, "unknown server binding format: %s\n", optarg);
        return EXIT_FAILURE;
      }
      if (!h2_listen(ctx, authority, ssl_ctx, accept_cb,
                     svr_free_cb, &app_ctx)) {
        fprintf(stderr, "server binding failed; quit: %s\n", authority);
        return EXIT_FAILURE;
      }
      listen_num++;
      break;
    case 'Q':
      verbose_h2 = 0;
      h2_ctx_set_verbose(ctx, verbose_h2);
      break;
    case 'q':
      verbose = 0;
      verbose_h2 = 0;
      h2_ctx_set_verbose(ctx, verbose_h2);
      break;

    /* reponse case request matching parameters */
    case 'm':  /* http request method to match; ALSO start of reponse case */
      if (app_ctx.rsp_case_num >= RSP_CASE_MAX) {
        fprintf(stderr, "too many response cases: %d\n", app_ctx.rsp_case_num);
        return EXIT_FAILURE;
      }
      if (rc_is_push_prm == 1) {
        rc_is_push_prm = 0;
      }
      rc = &app_ctx.rsp_case[app_ctx.rsp_case_num];
      rc->req_method = optarg;
      h2_set_status(rc->rsp, 200);
      app_ctx.rsp_case_num++;
      rc_is_push_prm = 0;
      if (app_ctx.rsp_case_num < RSP_CASE_MAX) {
        /* pre-init next rsp in rsp_case */
        (rc+1)->rsp = h2_msg_init();
      }
      break;
    case 'a':  /* http request authority to match */
      rc->req_authority = optarg;
      break;
    case 'p':  /* http request path prefix to match */
      rc->req_path_prefix = optarg;
      rc->req_path_prefix_len = strlen(optarg);
      break;
    case 'o':
      if (app_ctx.push_prm_num >= PUSH_PRM_MAX) {
        fprintf(stderr, "too many push promise cases: %d\n",
                app_ctx.push_prm_num);
        return EXIT_FAILURE;
      }
      if (rc_is_push_prm == 0) {
        rc_is_push_prm = 1;
        rc_for_push_prm = rc;
        rc_for_push_prm->push_prm_idx = app_ctx.push_prm_num;
      }
      rc_for_push_prm->push_prm_num++;
      rc = &app_ctx.push_prm[app_ctx.push_prm_num];
      rc->req_method = "GET";
      rc->req_path_prefix = optarg;  /* use req_path_prefix as req_path */
      rc->req_path_prefix_len = strlen(optarg);
      h2_set_status(rc->rsp, 200);
      app_ctx.push_prm_num++;
      if (app_ctx.push_prm_num < RSP_CASE_MAX) {
        /* pre-init next push promise rsp in push_prm */
        (rc+1)->rsp = h2_msg_init();
      }
      break;

    /* reponse case response parameters */
    case 's':  /* http reponse status */
      h2_set_status(rc->rsp, atoi(optarg));
      break;
    case 'x':  /* https response user header value */
      if (h2_add_hdr_s(rc->rsp, optarg) < 0) {
        return EXIT_FAILURE;
      }
      break;
    case 't':  /* http response body as text */
      h2_set_body(rc->rsp, strdup(optarg), strlen(optarg));
      break;
    case 'b':  /* http response body as hex binary */
      if (h2_body_from_hex_str(optarg, &body, &body_len) < 0) {
        return EXIT_FAILURE;
      }
      h2_set_body(rc->rsp, body, body_len);
      break;
    case 'f':  /* http response body as file */
      if (h2_body_from_file(optarg, &body, &body_len) < 0) {
        return EXIT_FAILURE;
      }
      h2_set_body(rc->rsp, body, body_len);
      break;
    case 'e':
      if (sscanf(optarg, "%d%c", &body_len, &scale) == 2 &&
          (scale == 'k' || scale == 'K')) {
        body_len *= 1024;
      } else if (sscanf(optarg, "%d%c", &body_len, &scale) != 1) {
        fprintf(stderr, "invalid -e req_body_size option value: %s\n", optarg);
        return EXIT_FAILURE;
      }
      h2_set_body(rc->rsp, calloc(1, body_len + 1), body_len);
      break;
#ifdef GET_FILE
    case 'd':  /* http response file base directory */
      rc->rsp_base_dir = optarg;
      break;
#endif

    case 'h':
      help(argv[0]);
      return EXIT_FAILURE;

    case '?':
      c = optopt;
    default:
      fprintf(stderr, "unknown option: %c", c);
      return EXIT_FAILURE;
    }
  }
  if (argc - optind > 0) {
    fprintf(stderr, "unknown option: argc=%d optind=%d optval='%s'\n",
            argc, optind, argv[optind]);
    return EXIT_FAILURE;
  }
  if (listen_num == 0) {
      help(argv[0]);
      return EXIT_FAILURE;
  }

  /* default rsp_case */
  if (app_ctx.rsp_case_num == 0) {
    rc = &app_ctx.rsp_case[0];
    rc->req_method = "GET";
    h2_set_status(rc->rsp, 200);
#ifdef GET_FILE
    rc->rsp_base_dir = strdup("./");
#endif
    app_ctx.rsp_case_num = 1;
  }

  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, sighdlr_mark_stop);

  h2_ctx_run(ctx);

  h2_ctx_free(ctx);

  int i;
  for (i = 0; i <= app_ctx.rsp_case_num && i < RSP_CASE_MAX; i++) {
    h2_msg_free(app_ctx.rsp_case[i].rsp);
  }
  for (i = 0; i <= app_ctx.push_prm_num && i < PUSH_PRM_MAX; i++) {
    h2_msg_free(app_ctx.push_prm[i].rsp);
  } 

#ifdef TLS_MODE
  ERR_free_strings();
#endif

  return 0;
}

