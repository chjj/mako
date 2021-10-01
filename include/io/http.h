/*!
 * http.h - http server for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_IO_HTTP_H
#define BTC_IO_HTTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "core.h"
#include "loop.h"
#include "../satoshi/common.h"

/*
 * Types
 */

typedef struct http_string {
  char *data;
  size_t alloc;
  size_t length;
} http_string_t;

typedef struct http_header {
  http_string_t field;
  http_string_t value;
} http_header_t;

typedef struct http_head {
  http_header_t **items;
  size_t alloc;
  size_t length;
} http_head_t;

typedef struct http_req {
  unsigned int method;
  http_string_t url;
  http_head_t headers;
  http_string_t body;
} http_req_t;

typedef struct http_res_s {
  btc_socket_t *socket;
  http_head_t headers;
} http_res_t;

struct http_server_s;

typedef int http_server_request_cb(struct http_server_s *,
                                   http_req_t *,
                                   http_res_t *);

typedef struct http_server_s {
  btc_loop_t *loop;
  btc_socket_t *socket;
  http_server_request_cb *on_request;
  void *data;
} http_server_t;

/*
 * Request
 */

BTC_EXTERN const http_string_t *
http_req_header(const http_req_t *req, const char *name);

/*
 * Response
 */

BTC_EXTERN void
http_res_header(http_res_t *res, const char *field, const char *value);

BTC_EXTERN void
http_res_send(http_res_t *res,
              unsigned int status,
              const char *type,
              const char *body);

BTC_EXTERN void
http_res_txt(http_res_t *res, unsigned int status, const char *body);

BTC_EXTERN void
http_res_json(http_res_t *res, unsigned int status, const char *body);

BTC_EXTERN void
http_res_error(http_res_t *res, unsigned int status);

/*
 * Server
 */

BTC_EXTERN http_server_t *
http_server_create(btc_loop_t *loop);

BTC_EXTERN void
http_server_destroy(http_server_t *server);

BTC_EXTERN int
http_server_open(http_server_t *server, const btc_sockaddr_t *addr);

BTC_EXTERN void
http_server_close(http_server_t *server);

#ifdef __cplusplus
}
#endif

#endif /* BTC_IO_HTTP_H */
