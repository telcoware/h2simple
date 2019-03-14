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
#include <stdarg.h>      /* for va_start */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>    /* for file read */
#include <fcntl.h>       /* for file read */


#include "h2.h"
#include "h2_priv.h"


/*
 * Message Utility ----------------------------------------------------------
 */

const char *h2_msg_type_str(int msg_type) {
  switch (msg_type) {
  case H2_REQUEST:       return "REQUEST";
  case H2_RESPONSE:      return "RESPONSE";
  case H2_PUSH_PROMISE:  return "PUSH_PROMISE";
  case H2_PUSH_RESPONSE: return "PUSH_RESPONSE";
  default:               return "(UNKNOWN)";
  }
}


/*
 * Message String Buffer Utility --------------------------------------------
 */

inline void h2_sbuf_init(h2_sbuf *sbuf, int buf_size, int ext_step_size) {
  sbuf->ext_step_size = ext_step_size;
  sbuf->xbuf.next = NULL;
  sbuf->xbuf.size = buf_size;
  sbuf->xbuf.free = buf_size;
}

inline void h2_sbuf_clean(h2_sbuf *sbuf) {
  if (sbuf) {
    h2_xbuf *xbuf;
    while ((xbuf = sbuf->xbuf.next)) {
      sbuf->xbuf.next = xbuf->next;
      xbuf->next = NULL;
      free(xbuf);
    }
    sbuf->xbuf.free = sbuf->xbuf.size;
  }
}

char *h2_sbuf_put_n(h2_sbuf *sbuf, const char *data, int size) {
  /* allocate data allowing asciiz string by appending null char */
  if (data == NULL) {
    return NULL; 
  }

  /* allocate buffer */
  char *r;
  if (sbuf->xbuf.free >= size + 1) {
    /* fit in self xbuf */
    r = &sbuf->xbuf.buf[sbuf->xbuf.size - sbuf->xbuf.free];
    sbuf->xbuf.free -= size + 1;
  } else {
    /* scan for available buffer at xbuf->next */
    h2_xbuf *xbuf = &sbuf->xbuf;
    while (xbuf->next && xbuf->next->free < size + 1) {
      xbuf = xbuf->next;
    }
    if (xbuf->next == NULL) {
      /* append new xbuf */
      /* TODO: may need to redefine ext_step_size for malloc fragmentation */ 
      int ext_size = sbuf->ext_step_size;
      while (ext_size < size + 1) {
        ext_size *= 2;
      }
      xbuf->next = malloc(sizeof(h2_xbuf) + ext_size);
      if (xbuf->next == NULL) {
        warnx("cannot allocate xbuf for msg.sbuf: ext_size=%d", ext_size);
        return NULL;
      }
      xbuf->next->next = NULL;
      xbuf->next->size = ext_size;
      xbuf->next->free = ext_size;
    }
    xbuf = xbuf->next;
    /* now, xbuf has the buf[] to use */
    r = &xbuf->buf[xbuf->size - xbuf->free];
    xbuf->free -= size + 1;
  }

  /* copy data */
  if (size > 0) {
    memcpy(r, data, size);
  }
  r[size] = '\0';  /* make null terminated */ 
  return r;
}

char *h2_sbuf_put(h2_sbuf *sbuf, const char *str) {
  return h2_sbuf_put_n(sbuf, str, (str)? strlen(str) : 0);
}


/*
 * Message Management ------------------------------------------------------
 */

void h2_msg_init_static(h2_msg *msg) {
  /* NOTE: body is not touched */
  /* PRIVATE */
  if (msg) {
    h2_sbuf_init(&msg->sbuf, sizeof(msg->sbuf_buf), H2_MSG_SBUF_EXT_STEP);
  } 
}

void h2_msg_clean_static(h2_msg *msg) {
  /* NOTE: body is not touched */
  /* PRIVATE */
  if (msg) {
    h2_sbuf_clean(&msg->sbuf);
  } 
}

h2_msg *h2_msg_init() {
  h2_msg *msg = calloc(1, sizeof(h2_msg));
  if (msg) {
    h2_sbuf_init(&msg->sbuf, sizeof(msg->sbuf_buf), H2_MSG_SBUF_EXT_STEP);
  }
  return msg;
}

void h2_msg_free(h2_msg *msg) {
  if (msg) {
    h2_sbuf_clean(&msg->sbuf);
    if (msg->body) {
      free(msg->body);
      msg->body = NULL;
      msg->body_len = 0;
    }
    free(msg);
  }
}


/*
 * Message Prepare Utilities -----------------------------------------------
 */

void h2_cpy_msg(h2_msg *dst, h2_msg *src) {
  if (dst && src) {
    dst->method = h2_sbuf_put(&dst->sbuf, src->method);
    dst->scheme = h2_sbuf_put(&dst->sbuf, src->scheme);
    dst->authority = h2_sbuf_put(&dst->sbuf, src->authority);
    dst->path = h2_sbuf_put(&dst->sbuf, src->path);
    dst->status = src->status;

    int i;
    for (i = 0; i < src->hdr_num; i++) { 
      h2_add_hdr(dst, src->hdr[i].name, src->hdr[i].value);
    }
 
    if (src->body && src->body_len) {
      dst->body = malloc(src->body_len + 1);
      memcpy(dst->body, src->body, src->body_len + 1/* '\0' */);
      dst->body[src->body_len] = '\0';
      dst->body_len = src->body_len;    
    }
  }
}

void h2_prepare_rsp(h2_msg *rsp, h2_msg *ref_req) {
  if (rsp && ref_req) {
    /* copy proxying header */
    h2_cpy_hdr(rsp, ref_req, "x-forwarded-for");
  }
}

void h2_prepare_prm(h2_msg *prm, h2_msg *ref_req,
                    const char *method, const char *path) {
  if (prm && ref_req) {
    /* copy request pseudo headers */
    prm->method = h2_sbuf_put(&prm->sbuf, method);
    prm->scheme = h2_sbuf_put(&prm->sbuf, ref_req->scheme);
    prm->authority = h2_sbuf_put(&prm->sbuf, ref_req->authority);
    prm->path = h2_sbuf_put(&prm->sbuf, path);
  }
}


/*
 * Message Psuedo Header Management -----------------------------------------
 */

const char *h2_method(h2_msg *req) {
  return req->method;
}

const char *h2_scheme(h2_msg *req) {
  return req->scheme;
}

const char *h2_authority(h2_msg *req) {
  return req->authority;
}

const char *h2_path(h2_msg *req) {
  return req->path;
}

int h2_status(h2_msg *rsp) {
  return rsp->status;
}

void h2_set_method(h2_msg *req, const char *method) {
  req->method = h2_sbuf_put(&req->sbuf, method);
}

void h2_set_scheme(h2_msg *req, const char *scheme) {
  req->scheme = h2_sbuf_put(&req->sbuf, scheme);
}

void h2_set_authority(h2_msg *req, const char *authority) {
  req->authority = h2_sbuf_put(&req->sbuf, authority);
}

void h2_set_path(h2_msg *req, const char *path) {
  req->path = h2_sbuf_put(&req->sbuf, path);
}

void h2_set_status(h2_msg *rsp, int status) {
  rsp->status = status;
}

int h2_set_req_uri(h2_msg *msg, const char *uri) {
  /* ASSUME: msg is already initialized as H2_MSG_REQUEST or PUSH_PROMISE */
  const char *scheme, *authority, *path, *p;
  int authority_len, path_len;

  /* get scheme */
  if (!strncmp(uri, "http://", 7)) {
    authority = uri + 7;
    scheme = "http";
#ifdef TLS_MODE
  } else if (!strncmp(uri, "https://", 8)) {
    authority = uri + 8;
    scheme = "https";
#endif
  } else {
#ifdef TLS_MODE
    warnx("Invalid scheme in uri; should be 'http' or 'https': %s\n", uri);
#else
    warnx("Invalid scheme in uri; should be 'http' only: %s\n", uri);
#endif
    return -1;
  }

  /* get authority */
  if ((path = strchr(authority, '/')) == NULL) {
    warnx("Invalid authority and path in uri: %s", uri);
    return -2;
  }
  if ((p = memrchr(authority, '@', (path - authority)))) {
    /* for now, just ignore username part */
    authority = p + 1;
  }
  if (path - authority < 1) {
    warnx("Empty authority in uri: %s", uri);
    return -3;
  }

  authority_len = path - authority;
  path_len = strlen(path);
  msg->scheme = h2_sbuf_put(&msg->sbuf, scheme);
  msg->authority = h2_sbuf_put_n(&msg->sbuf, authority, authority_len);
  msg->path = h2_sbuf_put_n(&msg->sbuf, path, path_len);
  return 0;
}


/*
 * Message Header Management ------------------------------------------------
 */

const char *h2_hdr_value(h2_msg *msg, const char *name) {
  int n;
  if (msg) {
    h2_hdr *hdr = msg->hdr;
    for (n = msg->hdr_num; n >= 0; n--, hdr++) {
      if (!strcmp(hdr->name, name)) {
        return hdr->value;
      }
    }
  }
  return NULL;
}

int h2_add_hdr(h2_msg *msg, const char *name, const char *value) {
  if (name == NULL || value == NULL) {
    return 0;
  }
  return h2_add_hdr_n(msg, name, strlen(name), value, strlen(value));
}

int h2_add_hdr_n(h2_msg *msg, const char *name, int name_len,
                 const char *value, int value_len) {
  if (name == NULL || value == NULL) {
    return 0;
  }
  if (msg->hdr_num >= H2_MSG_HDR_MAX) {
    warnx("too many entries; max=%d: %.*s=%.*s",
          H2_MSG_HDR_MAX, name_len, name, value_len, value);
    return -1;
  }
  msg->hdr[msg->hdr_num].name = h2_sbuf_put_n(&msg->sbuf, name, name_len);
  msg->hdr[msg->hdr_num].value = h2_sbuf_put_n(&msg->sbuf, value, value_len);
  msg->hdr_num++;
  return 1;
}

int h2_add_hdr_s(h2_msg *msg, const char *name_value_str) {
  const char *p;
  if (name_value_str == NULL) {
    return 0;
  }
  if ((p = strchr(name_value_str, '=')) == NULL) {
    warnx("should be name'='value format: %s", name_value_str);
    return -1;
  }
  return h2_add_hdr_n(msg, name_value_str, p - name_value_str,
                      p + 1, strlen(name_value_str) - (p + 1 - name_value_str));
}

int h2_set_hdr(h2_msg *msg, const char *name, const char *value) {
  int n, value_len = strlen(value);
  h2_hdr *hdr = msg->hdr;
  for (n = msg->hdr_num; n >= 0; n--, hdr++) {
    if (!strcmp(hdr->name, name)) {
      if (value == NULL) {
        /* delete header */
        for (n--; n > 0; n--, hdr++) {
          /* NOTE: there is no dealloc in msg->sbuf */
          *(hdr) = *(hdr + 1);
        }
        memset(hdr, 0, sizeof(*hdr));
        return 2;
      } else if (!strcmp(hdr->value, value)) {
        /* already has same value; no change */ 
        return 0;
      } else {
        /* update value */
        hdr->value = h2_sbuf_put_n(&msg->sbuf, value, value_len);
        return 1;
      }
    }
  }
  return h2_add_hdr_n(msg, name, strlen(name), value, strlen(value));
}

int h2_del_hdr(h2_msg *msg, const char *name) {
  int n;
  h2_hdr *hdr = msg->hdr;
  for (n = msg->hdr_num; n > 0; n--, hdr++) {
    if (!strcmp(hdr->name, name)) {
      for (n--; n > 0; n--, hdr++) {
        *(hdr) = *(hdr + 1); /* NOTE: there is no dealloc in msg->sbuf */
      }
      memset(hdr, 0, sizeof(*hdr));
      return 1;
    }
  }
  return 0; /* not found */
}

int h2_cpy_hdr(h2_msg *dst, h2_msg *src, const char *name) {
  int n;
  h2_hdr *hdr = src->hdr;
  for (n = src->hdr_num; n > 0; n--, hdr++) {
    if (!strcmp(hdr->name, name)) {
      return h2_add_hdr(dst, name, hdr->value);
    }
  }
  return 0; /* not found */
}

/* header array access */
int h2_hdr_num(h2_msg *msg) {
  return msg->hdr_num;
}

const char *h2_hdr_idx_name(h2_msg *msg, int hdr_idx) {
  if (hdr_idx >= 0 && hdr_idx < msg->hdr_num) {
    return msg->hdr[hdr_idx].name;
  }
  return NULL;
}

const char *h2_hdr_idx_value(h2_msg *msg, int hdr_idx) {
  if (hdr_idx >= 0 && hdr_idx < msg->hdr_num) {
    return msg->hdr[hdr_idx].value;
  }
  return NULL;
}


/*
 * Message Header Management ------------------------------------------------
 */

void *h2_body(h2_msg *msg) {
  return msg->body;
}

int h2_body_len(h2_msg *msg) {
  return msg->body_len;
}

int h2_set_body(h2_msg *msg, void *body, int body_len) {
  if (msg->body) {
    free(msg->body);
  }
  if (body && body_len > 0) {
    msg->body = body;
    msg->body_len = body_len;
    return 1;
  } else {
    msg->body = NULL;
    msg->body_len = 0;
    return 0;
  }
}

int h2_cpy_tbody(h2_msg *msg, void *body, int body_len) {
  if (msg->body) {
    free(msg->body);
  }
  if (body && body_len > 0) {
    msg->body = malloc(body_len + 1);
    memcpy(msg->body, body, body_len);
    msg->body[body_len] = '\0';
    msg->body_len = body_len;
    return 1;
  } else {
    msg->body = NULL;
    msg->body_len = 0;
    return 0;
  }
}


/*
 * Body Handling Utilities --------------------------------------------------
 */

static int h2_hex_value(char c) {
  return ((c >= '0' && c <= '9')? c - '0' :
          (c >= 'A' && c <= 'F')? c - 'A' + 10 :
          (c >= 'a' && c <= 'f')? c - 'a' + 10 : 0);
}

int h2_body_from_hex_str(char *hex_str, void **body_ret, int *body_len_ret) {
  int n;
  char *s;
  uint8_t *body, *d;

  n = strlen(optarg);
  s = optarg;
  body = calloc(1, n + 1/* '\0' */);  /* might has n/2 unused */
  d = body;

  if (n >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    s += 2;  /* skip optional leading "0x" or "0X" */

  for ( ; *s; s++) {
    if (isspace(*s))
      continue;
    if (!isxdigit(*s)) {
      warnx("non hexadecial character '%c' 0x%02x at %dth char "
            "of hex body: %s", *s, *s, (int)(s - hex_str), hex_str);
      free(*body_ret);
      *body_ret = NULL;
      return -1;
    }
    if (isxdigit(*(s + 1))) {
      *d = h2_hex_value(*s) * 16 + h2_hex_value(*(s + 1));
      s++;
    } else {
      *d = h2_hex_value(*s);
    }
    d++;
  }
  *d = '\0';  /* mark for string end */

  *body_ret = body;
  *body_len_ret = d - body;
  return 0;
}

int h2_body_from_file(char *file, void **body_ret, int *body_len_ret)
{
  int fd, file_size, n, r;
  off_t off;
  uint8_t *buf;

  if ((fd = open(file, O_RDONLY)) < 0) {
    warnx("cannot open file: error=%s file=%s", strerror(errno), file);
    return -1;
  }
  if ((off = lseek(fd, 0, SEEK_END)) < 0) {
    warnx("cannot get file size: error=%s file=%s", strerror(errno), file);
    close(fd);
    return -2;
  }
  if ((lseek(fd, 0, SEEK_SET)) < 0) {
    warnx("cannot move to first for file: error=%s file=%s",
          strerror(errno), file);
    close(fd);
    return -3;
  }

  file_size = off;
  buf = calloc(1, file_size + 1/* '\0' */);
  if (buf == NULL) {
    warnx("cannot alloc memory for file read: size=%d file=%s",
          file_size, file);
    close(fd);
    return -4;
  }

  for (n = 0; n < file_size; n += r) {
    if ((r = read(fd, &buf[n], file_size - n)) <= 0) {
      warnx("read file failed: error=%s read_size=%d file_size=%d file=%s",
            strerror(errno), n, file_size, file);
      close(fd);
      free(buf);
      return -5;
    }
  }
  buf[file_size] = '\0';  /* mark for string end */

  *body_ret = buf;
  *body_len_ret = file_size;
  close(fd);
  return 0;
}


/*
 * Message Dump Utility -----------------------------------------------------
 */

void h2_dump_msg(FILE *fp, h2_msg *msg, const char *line_prefix, 
                 const char *msg_name_fmt, ...) {
  va_list ap;
  char msg_name[1024];

  if (line_prefix == NULL) {
    line_prefix = "";
  }

  va_start(ap, msg_name_fmt);
  vsnprintf(msg_name, sizeof(msg_name), msg_name_fmt, ap);
  va_end(ap);
  fprintf(fp, "%s%s:\n", line_prefix, msg_name);

  /* print pseudo headers */
  if (msg->status) {
    fprintf(fp, "%s  %-14s = %d\n", line_prefix, ":status", msg->status);
  } else {
    fprintf(fp, "%s  %-14s = %s\n", line_prefix, ":method", msg->method);
    fprintf(fp, "%s  %-14s = %s\n", line_prefix, ":scheme", msg->scheme);
    fprintf(fp, "%s  %-14s = %s\n", line_prefix, ":authority", msg->authority);
    fprintf(fp, "%s  %-14s = %s\n", line_prefix, ":path", msg->path);
  }

  /* print headers */
  int n = msg->hdr_num;
  h2_hdr *hdr;
  for (hdr = msg->hdr; n > 0; n--, hdr++) {
    fprintf(fp, "%s  %-14s = %s\n", line_prefix, hdr->name, hdr->value);
  }

  /* print body */
  if (msg->body && msg->body_len > 0) {
    fprintf(fp, "%s  __body__[%d]:\n", line_prefix, msg->body_len);
    fprintf(fp, "%s  %s\n", line_prefix, msg->body);
  }
}

