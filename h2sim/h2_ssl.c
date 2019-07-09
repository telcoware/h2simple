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

#include "h2.h"
#include "h2_priv.h"


#ifdef TLS_MODE

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER < 0x10002000L
#error "openssl version SHOULD be >= 1.0.2"
#endif


/*
 * ALPN Selection ---------------------------------------------------------
 */

static int select_next_protocol(unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen,
                                const char *key, unsigned int keylen) {
  unsigned int i;
  for (i = 0; i + keylen <= inlen; i += (unsigned int)(in[i] + 1)) {
    if (memcmp(&in[i], key, keylen) == 0) {
      *out = (unsigned char *)&in[i + 1];
      *outlen = in[i];
      return 0;
    }
  }
  return -1;
}

static int ng_select_next_protocol(unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen) {
  if (select_next_protocol(out, outlen, in, inlen, "\x2h2", 3) == 0) {
    return 1;
  }
  if (select_next_protocol(out, outlen, in, inlen, "\x8http/1.1", 9) == 0) {
    return 0;
  }
  return -1;
}


/*
 * TLS Context Intialize --------------------------------------------------
 */

static int h2_server_alpn_cb(SSL *ssl, const unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
  (void)ssl;
  (void)arg;
  return (ng_select_next_protocol((void *)out, outlen, in, inlen) == 1)?
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
#if 0  /* controlled by ctx->http_ver_opt at sess_init */
    /* client */
    SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);
#endif
  }

  return ssl_ctx;
}


/*
 * Peer Certificate Verify Config Utilities -------------------------------
 */

static int h2_cert_verify_pass_cb(int preverify_ok, X509_STORE_CTX *ctx) {
  char subject[256];
  int err, depth;
  X509 *cert;
  (void)preverify_ok;

  if ((err = X509_STORE_CTX_get_error(ctx)) != 0) {
    depth = X509_STORE_CTX_get_error_depth(ctx);
    cert = X509_STORE_CTX_get_current_cert(ctx);

    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    warnx("cert_verify_pass: err='%s' depth=%d subject=%s",
          X509_verify_cert_error_string(err), depth, subject);
  }
  return 1;  /* always ok regardless of preverify_ok */
}

static int h2_cert_verify_cb(int preverify_ok, X509_STORE_CTX *ctx) {
  char subject[256];
  int err, depth;
  X509 *cert;

  if ((err = X509_STORE_CTX_get_error(ctx)) != 0) {
    depth = X509_STORE_CTX_get_error_depth(ctx);
    cert = X509_STORE_CTX_get_current_cert(ctx);

    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    warnx("cert_verify: err='%s' depth=%d subject=%s",
          X509_verify_cert_error_string(err), depth, subject);
  }
  return preverify_ok;
}

/* test code to dump out peer's public key to file */
int h2_cert_save_verify_cb(int preverify_ok, X509_STORE_CTX *ctx) {
  char subject[256];
  int err, depth;
  X509 *cert;

  err = X509_STORE_CTX_get_error(ctx);
  cert = X509_STORE_CTX_get_current_cert(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);

  X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
  warnx("cert_verify_save: err='%s' depth=%d subject=%s",
        X509_verify_cert_error_string(err), depth, subject);

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  if (preverify_ok && depth == 0 && err == 0 && cert != NULL) {
    char *p, file[1024];
    FILE *fp = NULL;

    /* replace subject's '/' by ',' to be safe for file name */ 
    for (p = subject; *p; p++) {
      if (*p == '/')
        *p = ',';
    }
    snprintf(file, sizeof(file), "/tmp/peer_cert_%s.der",
             subject + ((subject[0] == ',')? 1 : 0));
    if ((fp = fopen(file, "w"))) {
      warnx("certs_save to %s", file);
      i2d_PUBKEY_fp(fp, X509_get0_pubkey(cert));
      fclose(fp);
    }
  }
#endif

  return preverify_ok;
}

int h2_ssl_ctx_set_verify(SSL_CTX *ssl_ctx, int is_server, int ssl_verify_flag,
                          const char *trust_file, const char *trust_dir) {
  /* trust_file is trusted CA cerfificates as PEM file */
  /* trust_dir is trusted CA cerfificates PEM dir, prepared by 'c_rehash' */
  /* to be used as CAfile and CApath args of SSL_CTX_loca_verify_locations() */

  if (ssl_ctx == NULL) {
    warnx("invalid arugment: ssl_ctx should not be NULL");
    return -1;
  }

  if ((ssl_verify_flag & H2_SSL_VERIFY_PEER) == 0) {
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    return 0;
  }

  int r = SSL_CTX_load_verify_locations(ssl_ctx, trust_file, trust_dir);
  if (r < 0) {
    warnx("SSL_CTX_load_verify_locations() failed; ret=%d "
          "trust_file=%s trust_dir=%s", r, trust_file, trust_dir);
    return -2;
  }

  X509_VERIFY_PARAM *param = SSL_CTX_get0_param(ssl_ctx);
  if (param == NULL) {
    warnx("SSL_CTX_get0_param() failed");
    return -3;
  }
  if ((ssl_verify_flag & H2_SSL_VERIFY_CRL)) {
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
  }
  if ((ssl_verify_flag & H2_SSL_VERIFY_CRL_ALL)) {
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK_ALL);
  }
  if ((ssl_verify_flag & H2_SSL_VERIFY_PURPOSE)) {
    X509_VERIFY_PARAM_set_purpose(param,
        (is_server)? X509_PURPOSE_SSL_CLIENT : X509_PURPOSE_SSL_SERVER);
  }

  int mode = SSL_VERIFY_PEER;
  if (is_server) {
    mode |= SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  }

  if ((ssl_verify_flag & H2_SSL_VERIFY_PASS)) {
    SSL_CTX_set_verify(ssl_ctx, mode, h2_cert_verify_pass_cb);
  } else {
    SSL_CTX_set_verify(ssl_ctx, mode, h2_cert_verify_cb);
  }

  return 0;
}

int h2_ssl_ctx_set_verify_from_str(SSL_CTX *ssl_ctx, int is_server,
                                   char *verify_str) {
  /* parses as H2_SSL_VERIFY_STR_FORMAT and apply */

  if (ssl_ctx == NULL) {
    warnx("invalid arugment: ssl_ctx should not be NULL");
    return -1;
  } else if (verify_str == NULL) {
    warnx("invalid arugment: verify_str should not be NULL");
    return -1;
  }

  char *str = strdup(verify_str);
  char *tk, *last_p = NULL;
  int ssl_verify_flag = 0/* H2_SSL_VERIFY_NONE */;
  char *trust_file = NULL, *trust_dir = NULL;

  tk = strtok_r(str, ",", &last_p);
  do {
    if (!strcasecmp(tk, "none")) {
      ssl_verify_flag = H2_SSL_VERIFY_NONE;
    } else if (!strcasecmp(tk, "verify") || !strcasecmp(tk, "peer"/* aux */)) {
      ssl_verify_flag |= H2_SSL_VERIFY_PEER;
    } else if (!strcasecmp(tk, "pass")) {
      ssl_verify_flag |= H2_SSL_VERIFY_PEER | H2_SSL_VERIFY_PASS;
    } else if (!strncasecmp(tk, "trust_file=", 11)) {
      trust_file = tk + 11;
    } else if (!strncasecmp(tk, "trust_dir=", 10)) {
      trust_dir = tk + 10;
    } else if (!strcasecmp(tk, "crl")) {
      ssl_verify_flag |= H2_SSL_VERIFY_CRL;
    } else if (!strcasecmp(tk, "crl_all")) {
      ssl_verify_flag |= H2_SSL_VERIFY_CRL_ALL;
    } else if (!strcasecmp(tk, "purpose")) {
      ssl_verify_flag |= H2_SSL_VERIFY_PURPOSE;
    } else {
      warnx("unknown verify string token: %s", tk);
      return -1;
    }
  } while ((tk = strtok_r(NULL, ",", &last_p)));

  int r = h2_ssl_ctx_set_verify(ssl_ctx, is_server, ssl_verify_flag,
                                trust_file, trust_dir);
  free(str);
  return r; 
}

int h2_ssl_set_verify_param_host(SSL *ssl, const char *host_name) {
  X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
  return X509_VERIFY_PARAM_set1_host(param, host_name,
                                     (host_name)? strlen(host_name) : 0);
}

int h2_ssl_add_verify_param_host(SSL *ssl, const char *host_name) {
  X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
  return X509_VERIFY_PARAM_add1_host(param, host_name,
                                     (host_name)? strlen(host_name) : 0);
}


#endif /* TLS_MODE */

