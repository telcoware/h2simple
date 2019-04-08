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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>  /* for gettimeofday() */
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#ifdef TLS_MODE
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#else
/* NOTE: h2_util.h defines dummy SSL_CTX and SSL */
#endif

#include <nghttp2/nghttp2.h>

#include "h2sim/h2.h"


int verbose = 1;


#define CLIENT_JOB_REPL_SYM_MAX  16    /* replace symbol max */
                                       /* MUST be < 32 for repl_sym_idx_mask */
#define CLIENT_JOB_SBUF_SIZE     (128 * 1024)
#define REQ_STEP_MAX             32
#define MSG_HDR_MAX              32


/* symbol replace is applied on uri, header value and request body */
#define REPL_SYM_MASK_PATH  1
#define REPL_SYM_MASK_HDR   2
#define REPL_SYM_MASK_BODY  4
/* replaced string buffer max */
#define REPL_SYM_BUF_MAX    256
typedef struct {
  char *sym;    /* symbol to be replaced */
  char *fmt;    /* sprintf format string on req_id (0 ~ req_max-1) argument */
  int sym_len;
  int mask;     /* bitwize-OR of REPL_SYM_MASK_* */
                /* TODO: mask need to be defined per req_step */
} repl_sym_fmt_t;

typedef struct {
  char *sym;    /* symbol to be replaced */
  char *value;  /* value to replace symbol */
  int sym_len;
  int value_len;
} repl_sym_val_t;

typedef struct {
  /* job/req/step status fields */
  int par_idx;   /* 0 ~ req_par-1 */
  int req_id;    /* 0 ~ req_max-1 */
  int req_step;  /* 0 ~ req_step_num-1 */
  /* push promise status */
  int prm_num;   /* push promize per this request */
} req_task_t;

/* server connections per <scheme, authority> */
/* TODO: MAY NEED TO BE PROMOTED TO h2_peer */
typedef struct {
  const char *scheme;
  const char *authority;
  h2_peer *peer;
} svr_peer_t;

/* client job to be handled by run(); set by runtime parameters */
typedef struct client_job {
  /* request job configuration */
  int req_par;
  int req_max; 
  int req_tps;  /* 0:unlimited */

  /* replace symbol format */
  repl_sym_fmt_t repl_sym[CLIENT_JOB_REPL_SYM_MAX];
  int repl_sym_num;
  int repl_sym_mask[REQ_STEP_MAX];  /* ORs of REPL_SYM_MASK_* per req_step */
  int hdr_repl_sym_idx_mask[REQ_STEP_MAX][MSG_HDR_MAX];
                            /* bit-OR of (1 << repl_sym_idx) matched in value */

  /* request context; 1 request message per request step  */
  int req_cnt;  /* current request status; req_psr_tasks per each req_cnt */
  req_task_t *req_par_task;  /* alloced as req_task_t[req_par] */
  h2_msg *req_step_msg[REQ_STEP_MAX];
  h2_peer *req_step_peer[REQ_STEP_MAX];
  int req_step_num;

  /* response status */
  int rsp_num;  /* reponse message count */

  /* request tps control; managed by sleep_for_req_tps() */
  struct timeval start_tv;
} client_job_t;

#define SVR_PEER_MAX  100
svr_peer_t svr_peers[SVR_PEER_MAX];
int svr_peer_num = 0;

 
/*
 * Replace Symbold Utilities ------------------------------------------------
 */

static void update_replace_symbol_mask(client_job_t *job) {
  /* check and set repl_sym_mask of each repl_sym and req_step in client_job */ 
  /* and set each user_hdr's repl_sym_mask */
  int s, i, j;

  for (s = 0; s < job->req_step_num; s++) {
    h2_msg *req = job->req_step_msg[s];
    int req_hdr_num = h2_hdr_num(req);
    job->repl_sym_mask[s] = 0;

    for (i = 0; i < job->repl_sym_num; i++) {
      char *sym = job->repl_sym[i].sym;
      int mask = 0; 
      
      if (strstr(h2_path(req), sym)) {
        mask |= REPL_SYM_MASK_PATH;
      }
      for (j = 0; j < req_hdr_num; j++) {
        if (strstr(h2_hdr_idx_value(req, j), sym)) {
          mask |= REPL_SYM_MASK_HDR;
          job->hdr_repl_sym_idx_mask[s][j] |= (1 << i);
        }
      }
      /* NOTE: all body buffer has '\0' at body_len+1 */
      /* NOTE: might be faulty on non-text body */
      if (h2_body_len(req) > 0 && strstr(h2_body(req), sym)) {
        mask |= REPL_SYM_MASK_BODY;
      }

      job->repl_sym[i].mask |= mask;  /* TODO: to be alloced per req step */
      job->repl_sym_mask[s] |= mask;
    }
  }
}

static void replace_symbol(repl_sym_fmt_t *rs, char **str_pp, int *len_p,
                           int req_id)
{
  /* ASSUME: str is dynamic alloced and null terminated (even with body case) */
  char *str, *p, buf[REPL_SYM_BUF_MAX];
  int len, skip, offset, r, n;

  str = *str_pp;
  len = *len_p;
  skip = 0;
  while ((p = strstr(str + skip, rs->sym))) {
    offset = p - str;  /* p should not be used any more */
    r = len - offset - rs->sym_len;
    n = sprintf(buf, rs->fmt, req_id);
    if (n > rs->sym_len) {
      str = realloc(str, len + n - rs->sym_len + 1); 
      *str_pp = str;  /* update str return value */
    }
    if (r > 0 && n != rs->sym_len)
      memmove(str + offset + n, str + offset + rs->sym_len, r);
    if (n > 0)
      memcpy(str + offset, buf, n);
    len += n - rs->sym_len;
    *len_p = len;  /* update len return value */
    str[len] = '\0';
    skip = offset + n;
   }
}

static h2_msg *gen_request(h2_msg *src, client_job_t *job,
                           int repl_sym_mask, req_task_t *req_task) {

  /* NOTE: special version of h2_msg_cpy() to copy with symbol replace */
  h2_msg *msg = h2_msg_init();

  if (job->repl_sym_num <= 0 || job->repl_sym_mask[req_task->req_step] == 0) {
    h2_cpy_msg(msg, src);
    return msg;
  }
  /* else, do local copy with check and replace symboles */

  h2_set_method(msg, h2_method(src));
  h2_set_scheme(msg, h2_scheme(src));
  h2_set_authority(msg, h2_authority(src));

  if ((repl_sym_mask & REPL_SYM_MASK_PATH)) {
    char *path = strdup(h2_path(src));
    int i, path_len = strlen(path);
    for (i = 0; i < job->repl_sym_num; i++) {
      if ((job->repl_sym[i].mask & REPL_SYM_MASK_PATH)) {
        replace_symbol(&job->repl_sym[i], &path, &path_len, req_task->req_id);
      }
    }
    h2_set_path(msg, path);
    free(path);
  } else {
    h2_set_path(msg, h2_path(src));
  }

  h2_set_status(msg, h2_status(src));

  if ((repl_sym_mask & REPL_SYM_MASK_HDR)) {
    int i, m, s;
    int hdr_num = h2_hdr_num(src);
    for (i = 0; i < hdr_num; i++) {
      char *value = strdup(h2_hdr_idx_value(src, i));
      int value_len = strlen(value);
      for (m = job->hdr_repl_sym_idx_mask[req_task->req_step][i], s = 0;
           m; m >>= 1, s++) {
        if ((m & 1)) {
          replace_symbol(&job->repl_sym[s], &value, &value_len,
                         req_task->req_id);
        }
      }
      h2_add_hdr(msg, h2_hdr_idx_name(src, i), value);
      free(value);
    }
  }

  if (h2_body_len(src) > 0) {
    int i, body_len = h2_body_len(src);
    char *body = malloc(body_len + 1);
    memcpy(body, h2_body(src), body_len + 1/* '\0' */);
    body[body_len] = '\0';
    if ((repl_sym_mask & REPL_SYM_MASK_BODY)) {
      for (i = 0; i < job->repl_sym_num; i++) {
        if ((job->repl_sym[i].mask & REPL_SYM_MASK_BODY))
          replace_symbol(&job->repl_sym[i], &body, &body_len, req_task->req_id);
      }
    }
    h2_set_body(msg, body, body_len);
  }

  return msg;
}


/*
 * H2 Application Callbacks ------------------------------------------------
 */

static void sleep_for_req_tps(client_job_t *job) { 
  if (job->start_tv.tv_sec == 0) {
    gettimeofday(&job->start_tv, NULL);
  } if (job->req_tps > 0) {
    struct timeval cur_tv, sleep_tv;
    long long elapsed_usec, sleep_usec;

    gettimeofday(&cur_tv, NULL);
    elapsed_usec = ((cur_tv.tv_sec - job->start_tv.tv_sec) * 1000000 +
                    (cur_tv.tv_usec - job->start_tv.tv_usec));
    sleep_usec = ((long long)(job->req_cnt) * 1000000 / job->req_tps
                  - elapsed_usec);
    if (sleep_usec >= 1) {
      sleep_tv.tv_sec = sleep_usec / 1000000;
      sleep_tv.tv_usec = sleep_usec % 1000000;
      select(0, NULL, NULL, NULL, &sleep_tv);
    }
  }
}

static int start_request(client_job_t *job) {
  int i, r;

  job->req_cnt = 0;
  job->rsp_num = 0;

  /* send initial requests as req_par */
  for (i = 0; i < job->req_par && job->req_cnt < job->req_max; i++) {
    req_task_t *req_task = &job->req_par_task[i]; 
    req_task->par_idx = i;
    req_task->req_id = job->req_cnt++;
    req_task->req_step = 0;
    req_task->prm_num = 0;

    h2_msg *req = gen_request(job->req_step_msg[0],
                              job, job->repl_sym_mask[0], req_task);

    if (verbose) {
      h2_dump_msg(stdout, req, "", "REQUEST[%d/%d,%d]",
                  req_task->req_id, req_task->req_step, req_task->par_idx);
    }

    sleep_for_req_tps(job);
    r = h2_peer_send_request(job->req_step_peer[req_task->req_step],
                             req, NULL, req_task);
    h2_msg_free(req);
    if (r < 0) {
      break;
    }
  }
  return 0;
}

static int response_cb(h2_peer *peer, h2_msg *rsp, void *peer_user_data,
                       void *strm_user_data) {
  client_job_t *job = peer_user_data;
  req_task_t *req_task = strm_user_data;
  (void)rsp;

  job->rsp_num++;

  if (verbose) {
    h2_dump_msg(stdout, rsp, "", "RESPONSE[%d/%d,%d]",
                req_task->req_id, req_task->req_step, req_task->par_idx);
  }

  /* prepare new request */
  if (req_task->req_step + 1 < job->req_step_num) {
    req_task->req_step += 1;
  } else if (job->req_cnt < job->req_max) {
    req_task->req_id = job->req_cnt++; 
    req_task->req_step = 0;
    req_task->prm_num = 0;
  } else {
    if (job->rsp_num >= job->req_max * job->req_step_num) {
      /* NOTE: all peers are closed at once */
      int i;
      for (i = 0; i < svr_peer_num; i++) {
        h2_peer_terminate(svr_peers[i].peer, 0);
      }
    }
    return 0;  /* no more request stream */
  }

  /* send new request */
  h2_msg *req = gen_request(job->req_step_msg[req_task->req_step], job,
                            job->repl_sym_mask[req_task->req_step], req_task);
  sleep_for_req_tps(job);
  h2_peer_send_request(peer, req, NULL, req_task);
  h2_msg_free(req);
  return 0;
}

static void push_strm_free_cb(h2_strm *strm, void *user_data) {
  (void)strm;  
  free(user_data); 
}

static int push_promise_cb(h2_peer *peer, h2_msg *prm_req,
                           void *peer_user_data, void *strm_user_data,
                           h2_strm_free_cb *push_strm_free_cb_ret,
                           void **push_strm_user_data_ret) {
  req_task_t *req_task = strm_user_data;
  (void)peer;
  (void)peer_user_data;

  req_task->prm_num++;

  if (verbose) {
    h2_dump_msg(stdout, prm_req, "", "PUSH_PROMISE[%d/%d,%d](%d) on %s",
                req_task->req_id, req_task->req_step, req_task->par_idx,
                req_task->prm_num, h2_path(prm_req));
  }

  *push_strm_free_cb_ret = push_strm_free_cb;
  *push_strm_user_data_ret = strdup(h2_path(prm_req));
  return 0;
}

static int push_response_cb(h2_peer *peer, h2_msg *prm_rsp,
                            void *peer_user_data, void *push_stream_user_data) {
  char *prm_req_path = push_stream_user_data;
  (void)peer;
  (void)peer_user_data;
  
  if (verbose) {
    h2_dump_msg(stdout, prm_rsp, "", "PUSH_RESPONSE on %s", prm_req_path);
  }

  free(prm_req_path);
  return 0;
}


/*
 * Application main and runtime argument parsers ----------------------------
 */

static void help(char *prog) {
  fprintf(stderr, "Usage: %s [client_run_options] [request_options]\n", prog);
  fprintf(stderr, "    or %s [client_run_options] uri\n", prog);
  fprintf(stderr, "client_run_options:\n");
  fprintf(stderr, "  -P req_parallel       # default:1\n");
  fprintf(stderr, "  -C req_max_count      # default:1\n");
  fprintf(stderr, "  -T req_tps            # request tps; 0 for unlimited; default:0\n");
  fprintf(stderr, "  -S sess_per_peer      # sessions per server: default:1\n");
  fprintf(stderr, "  -L req_thr_for_reconn # default:0(unlimited)\n");
  fprintf(stderr, "  -R symbol=format      # rep default:1\n");
#ifdef TLS_MODE
  fprintf(stderr, "  -k key_file           # default:eckey.pem\n");
  fprintf(stderr, "  -c cert_file          # default:eccert.pem\n");
#endif
  fprintf(stderr, "  -H <settings_id>=<value>   # set http2 settings value\n");
  fprintf(stderr, "     # <settings_id> := header_table_size | enable_push |\n");
  fprintf(stderr, "     #   max_concurrent_streams, initial_window_size | max_frame_size\n");
  fprintf(stderr, "     #   max_header_list_size, enable_connect_protocol\n");
  fprintf(stderr, "  -Q                    # h2sim io quiet mode\n");
  fprintf(stderr, "  -q                    # all quiet mode\n");
  fprintf(stderr, "request_options:\n");
  fprintf(stderr, "  # -m starts each request step\n");
  fprintf(stderr, "  # previous step's -s and -a are used if not specifiied\n");
  fprintf(stderr, "  -m method             # GET|POST|PUT|PATCH|DELETE\n");
  fprintf(stderr, "  -u uri                # insteads of -s, -a, -p\n");
#ifdef TLS_MODE
  fprintf(stderr, "  -s scheme             # http|https; default:https\n");
#else
  fprintf(stderr, "  -s scheme             # http; default:http\n");
#endif
  fprintf(stderr, "  -a authority\n");
  fprintf(stderr, "  -p path\n");
  fprintf(stderr, "  -x req_header_name=value\n");
  fprintf(stderr, "  -t req_body_text\n");
  fprintf(stderr, "  -b req_body_hex_binary\n");
  fprintf(stderr, "  -f req_body_file\n");
  fprintf(stderr, "  -e req_body_size      # dummy zero value body of given size\n");
  fprintf(stderr, "NOTE: now, only the first req step's scheme and authority is used\n");
}

static int get_replace_symbol(char *symbol_format_str, client_job_t *job) {
  char *sym, *fmt;
  int sym_len, fmt_len;

  if ((fmt = strchr(symbol_format_str, '=')) == NULL) {
    fprintf(stderr, "replace symbol option should be symbol=format format: "
            "%s\n", symbol_format_str);
    return -1;
  } 
  fmt++;  /* next of '=' */ 
  fmt_len = strlen(fmt);
  sym = symbol_format_str;
  sym_len = fmt - sym - 1/* '=' */;

  if (job->repl_sym_num >= CLIENT_JOB_REPL_SYM_MAX) {
    fprintf(stderr, "too many replace symbols; max=%d: %s\n",
            CLIENT_JOB_REPL_SYM_MAX, symbol_format_str);
    return -2;
  } 
  job->repl_sym[job->repl_sym_num].sym = strndup(sym, sym_len);
  job->repl_sym[job->repl_sym_num].fmt = strndup(fmt, fmt_len);
  job->repl_sym[job->repl_sym_num].sym_len = sym_len;
  job->repl_sym[job->repl_sym_num].mask = 0;
  job->repl_sym_num++; 

  return 0;
}

h2_ctx *ctx = NULL;

void sighdlr_mark_stop(int signo) {
  (void)signo;
  h2_ctx_stop(ctx);
}

int main(int argc, char **argv) {
  int verbose_h2 = 1;
#ifdef TLS_MODE
  char *key_file = "eckey.pem";    /* default private key file */
  char *cert_file = "eccert.pem";  /* default certificate file */
#endif
  client_job_t job = {
    .req_par = 1,
    .req_max = 1,
    .req_tps = 0,
  };
  int sess_per_svr = 1;
  int req_thr_for_reconn = 0; /* 0:unlimited */
  void *body;
  int body_len;

  h2_settings settings;
  h2_settings_init(&settings);

  h2_msg *req = h2_msg_init();
  h2_set_method(req, "GET");
#if TLS_MODE
  h2_set_scheme(req, "https");
#else
  h2_set_scheme(req, "http");
#endif
  job.req_step_msg[0] = req;

  int c;
  char scale;
  while ((c = getopt(argc, argv, "P:C:T:S:R:k:c:H:L:Qqm:u:s:a:p:x:t:b:f:e:h")) >= 0) {
    switch (c) {
    /* client run options */
    case 'P':  /* concurrent requests (ie. streams) */
      job.req_par = atoi(optarg);
      if (job.req_par <= 0)
        job.req_par = 1;
      break;
    case 'C':  /* total request counts */
      job.req_max = atoi(optarg);
      if (job.req_max <= 0)
        job.req_max = 1;
      break;
    case 'T':
      job.req_tps = atoi(optarg);
      break;
    case 'S':
      sess_per_svr = atoi(optarg);
      break;
    case 'L':
      req_thr_for_reconn = atoi(optarg);
      break;
    case 'R':
      if (get_replace_symbol(optarg, &job) < 0) {
        return EXIT_FAILURE;
      }
      break;
#ifdef TLS_MODE
    case 'k':  /* NOTE: K on server case */
      key_file = optarg;
      break;
    case 'c':  /* NOTE: S on server case */
      cert_file = optarg;
      break;
#endif
    case 'H':
      if (h2_set_settings(&settings, optarg) < 0) {
        fprintf(stderr, "invalid argument for options <id>=<value>: %s\n",
                optarg);
        return EXIT_FAILURE;
      }
    case 'Q':
      verbose_h2 = 0;
      break;
    case 'q':
      verbose_h2 = 0;
      verbose = 0;
      break;

    /* request step options */
    case 'm':  /* http request method */
      if (job.req_step_num >= REQ_STEP_MAX) {
        fprintf(stderr, "too many request steps: max=%d\n", REQ_STEP_MAX);
        return EXIT_FAILURE;
      }
      req = job.req_step_msg[job.req_step_num];
      h2_set_method(req, optarg);
      if (job.req_step_num >= 1) {
        /* set defaults from previous req step */
        h2_msg *prev_req = job.req_step_msg[job.req_step_num - 1];
        h2_set_scheme(req, h2_scheme(prev_req));
        h2_set_authority(req, h2_authority(prev_req));
      } 
      job.req_step_num++;
      if (job.req_step_num < REQ_STEP_MAX) {
        /* pre-init next step's req msg */
        job.req_step_msg[job.req_step_num] = h2_msg_init();
      }
      break;
    case 'u':  /* http request uri */
      if (h2_set_req_uri(req, optarg) < 0) {
        return EXIT_FAILURE;
      }
      break;
    case 's':  /* http request sheme */
      h2_set_scheme(req, optarg);
      break;
    case 'a':  /* http request authority */
      h2_set_authority(req, optarg);
      break;
    case 'p':  /* http request path */
      h2_set_path(req, optarg);
      break;
    case 'x':  /* user header value */
      if (h2_add_hdr_s(req, optarg) < 0) {
        return EXIT_FAILURE;
      }
      break;
    case 't':  /* http request body as text */
      h2_set_body(req, strdup(optarg), strlen(optarg));
      break;
    case 'b':  /* http request body as hex binary */
      if (h2_body_from_hex_str(optarg, &body, &body_len) < 0) {
        return EXIT_FAILURE;
      }
      h2_set_body(req, body, body_len);
      break;
    case 'f':  /* http request body as file */
      if (h2_body_from_file(optarg, &body, &body_len) < 0) {
        return EXIT_FAILURE;
      }
      h2_set_body(req, body, body_len);
      break;
    case 'e':
      if (sscanf(optarg, "%d%c", &body_len, &scale) == 2 &&
          (scale == 'k' || scale == 'K')) {
        body_len *= 1024; 
      } else if (sscanf(optarg, "%d%c", &body_len, &scale) != 1) {
        fprintf(stderr, "invalid -e req_body_size option value: %s\n", optarg);
        return EXIT_FAILURE;
      }
      h2_set_body(req, calloc(1, body_len + 1), body_len);
      break;

    case 'h':
      help(argv[0]);
      return EXIT_FAILURE;
      break;
    case '?':
      c = optopt;
    default:
      fprintf(stderr, "unknown option: %c\n", c);
      return EXIT_FAILURE;
    }
  }

  if ((job.req_step_num == 0 || job.req_step_num == 0) &&
      argc - optind == 1) {
    /* simple uri argument case */
    if (h2_set_req_uri(req, argv[optind]) < 0) {
      return EXIT_FAILURE;
    }
    job.req_step_num = 1;
  } else if (argc - optind != 0) {
    fprintf(stderr, "unknown argumens\n");
    return EXIT_FAILURE;
  }
  if (job.req_step_num == 0 || h2_authority(job.req_step_msg[0]) == NULL) { 
    fprintf(stderr, "request and first req step msg's authority "
            "should be defined\n");
    help(argv[0]);
    return EXIT_FAILURE;
  }
  int i;
  for (i = 0; i < job.req_step_num; i++) {
    if (h2_path(job.req_step_msg[i]) == NULL) {
      fprintf(stderr, "every req step must defined -p path value; "
              "missed in %dth req step msg\n", i + 1);
      return EXIT_FAILURE;
    }
  } 

  /* init parallel task table */
  job.req_par_task = calloc(job.req_par, sizeof(req_task_t));

  /* job's all fields are ready */
  update_replace_symbol_mask(&job);

  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, sighdlr_mark_stop);

  SSL_CTX *ssl_ctx = NULL;
#ifdef TLS_MODE
  SSL_load_error_strings();
  SSL_library_init();
  ssl_ctx = h2_ssl_ctx_init(0/*client*/, key_file, cert_file);
#endif
  ctx = h2_ctx_init(verbose_h2);

  /* create sessions for all <scheme, authority> */
  for (i = 0; i < job.req_step_num; i++) {
    const char *scheme = h2_scheme(job.req_step_msg[i]);
    const char *authority = h2_authority(job.req_step_msg[i]);
    int j;
    for (j = 0; j < svr_peer_num; j++) {
      if (!strcmp(scheme, svr_peers[j].scheme) &&
          !strcmp(authority, svr_peers[j].authority)) {
        job.req_step_peer[i] = svr_peers[j].peer;
        break;
      }
    }
    if (j == svr_peer_num) {
      /* no match; create new peer and connect to server */
      if (svr_peer_num >= SVR_PEER_MAX) {
        fprintf(stderr, "too many server peers: max=%d\n", SVR_PEER_MAX);
        return EXIT_FAILURE;
      }
      fprintf(stderr, "NEW SERVER PEER: %s://%s\n", scheme, authority);
      svr_peers[j].scheme = scheme;
      svr_peers[j].authority = authority;
      svr_peers[j].peer = h2_peer_connect(sess_per_svr, req_thr_for_reconn,
                              ctx, authority,
                              !strcasecmp(scheme, "https")? ssl_ctx : NULL,
                              &settings,
                              response_cb, push_promise_cb, push_response_cb,
                              NULL/* job is static */, &job);
      if (svr_peers[j].peer == NULL) {
        fprintf(stderr, "connect failed to server: %s\n", authority);
        return EXIT_FAILURE;
      }
      job.req_step_peer[i] = svr_peers[j].peer;
      svr_peer_num++;
    }
  }

  /* initial requests logic per parallel streams */
  start_request(&job);

  h2_ctx_run(ctx);

  h2_ctx_free(ctx); 
#ifdef TLS_MODE
  if (ssl_ctx) {
    SSL_CTX_free(ssl_ctx);
    ERR_free_strings();
  }
#endif

  /* free parallel task table */
  free(job.req_par_task);

  /* free client job */
  for (i = 0; i <= job.req_step_num && i < REQ_STEP_MAX; i++) {
    h2_msg_free(job.req_step_msg[i]);
  }
  for (i = 0; i < job.repl_sym_num; i++) {
    free(job.repl_sym[i].sym);
    job.repl_sym[i].sym = NULL;
    free(job.repl_sym[i].fmt);
    job.repl_sym[i].fmt = NULL;
  }

  return 0;
}

