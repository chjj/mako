/*!
 * http.c - http server for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <io/core.h>
#include <io/http.h>
#include <io/loop.h>
#include "http_parser.h"

/*
 * Types
 */

typedef struct http_conn_s {
  http_server_t *server;
  btc_socket_t *socket;
  struct http_parser parser;
  struct http_parser_settings settings;
  http_req_t *req;
  int last_was_value;
} http_conn_t;

/*
 * Helpers
 */

static void *
safe_malloc(size_t size) {
  void *ptr = malloc(size);

  if (ptr == NULL)
    abort(); /* LCOV_EXCL_LINE */

  return ptr;
}

static void *
safe_realloc(void *ptr, size_t size) {
  ptr = realloc(ptr, size);

  if (ptr == NULL) {
    abort(); /* LCOV_EXCL_LINE */
    return NULL;
  }

  return ptr;
}

/*
 * String
 */

static void
http_string_init(http_string_t *str) {
  str->data = safe_malloc(1);
  str->data[0] = '\0';
  str->alloc = 0;
  str->length = 0;
}

static void
http_string_clear(http_string_t *str) {
  free(str->data);
}

#if 0
static void
http_string_reset(http_string_t *str) {
  str->data[0] = '\0';
  str->length = 0;
}
#endif

static void
http_string_grow(http_string_t *str, size_t len) {
  if (len > str->alloc) {
    str->data = safe_realloc(str->data, len + 1);
    str->alloc = len;
  }
}

#if 0
static void
http_string_copy(http_string_t *z, const http_string_t *x) {
  http_string_grow(z, x->length);

  memcpy(z->data, x->data, x->length + 1);

  z->length = x->length;
}
#endif

static void
http_string_assign(http_string_t *z, const char *xp, size_t xn) {
  http_string_grow(z, xn);

  memcpy(z->data, xp, xn);

  z->length = xn;
  z->data[z->length] = '\0';
}

static void
http_string_set(http_string_t *z, const char *xp) {
  http_string_assign(z, xp, strlen(xp));
}

static void
http_string_append(http_string_t *z, const char *xp, size_t xn) {
  http_string_grow(z, z->length + xn);

  memcpy(z->data + z->length, xp, xn);

  z->length += xn;
  z->data[z->length] = '\0';
}

#if 0
static void
http_string_cat(http_string_t *z, const char *xp) {
  http_string_append(z, xp, strlen(xp));
}
#endif

static void
http_string_lower(http_string_t *z) {
  size_t i;

  for (i = 0; i < z->length; i++)
    z->data[i] |= 0x20;
}

static int
http_string_equal(const http_string_t *x, const char *yp, size_t yn) {
  size_t i;

  if (x->length != yn)
    return 0;

  for (i = 0; i < x->length; i++) {
    int a = x->data[i] | 0x20;
    int b = yp[i] | 0x20;

    if (a != b)
      return 0;
  }

  return 1;
}

#if 0
static http_string_t *
http_string_create(void) {
  http_string_t *str = safe_malloc(sizeof(http_string_t));
  http_string_init(str);
  return str;
}

static void
http_string_destroy(http_string_t *str) {
  http_string_clear(str);
  free(str);
}
#endif

/*
 * Header
 */

static void
http_header_init(http_header_t *hdr) {
  http_string_init(&hdr->field);
  http_string_init(&hdr->value);
}

static void
http_header_clear(http_header_t *hdr) {
  http_string_clear(&hdr->field);
  http_string_clear(&hdr->value);
}

#if 0
static void
http_header_reset(http_header_t *hdr) {
  http_string_reset(&hdr->field);
  http_string_reset(&hdr->value);
}
#endif

static http_header_t *
http_header_create(void) {
  http_header_t *hdr = safe_malloc(sizeof(http_header_t));
  http_header_init(hdr);
  return hdr;
}

static void
http_header_destroy(http_header_t *hdr) {
  http_header_clear(hdr);
  free(hdr);
}

/*
 * Head
 */

static void
http_head_init(http_head_t *z) {
  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

static void
http_head_clear(http_head_t *z) {
  size_t i;

  for (i = 0; i < z->length; i++)
    http_header_destroy(z->items[i]);

  if (z->alloc > 0)
    free(z->items);

  z->items = NULL;
  z->alloc = 0;
  z->length = 0;
}

static void
http_head_grow(http_head_t *z, size_t zn) {
  if (zn > z->alloc) {
    z->items = safe_realloc(z->items, zn * sizeof(http_header_t *));
    z->alloc = zn;
  }
}

static void
http_head_push(http_head_t *z, http_header_t *x) {
  if (z->length == z->alloc)
    http_head_grow(z, (z->alloc * 3) / 2 + (z->alloc <= 1));

  z->items[z->length++] = x;
}

static void
http_head_push_item(http_head_t *z, const char *field, const char *value) {
  http_header_t *hdr = http_header_create();

  http_string_set(&hdr->field, field);
  http_string_set(&hdr->value, value);

  http_head_push(z, hdr);
}

/*
 * Request
 */

static void
http_req_init(http_req_t *req) {
  req->method = 0;
  http_string_init(&req->url);
  http_head_init(&req->headers);
  http_string_init(&req->body);
}

static void
http_req_clear(http_req_t *req) {
  http_string_clear(&req->url);
  http_head_clear(&req->headers);
  http_string_clear(&req->body);
}

static http_req_t *
http_req_create(void) {
  http_req_t *req = safe_malloc(sizeof(http_req_t));
  http_req_init(req);
  return req;
}

static void
http_req_destroy(http_req_t *req) {
  http_req_clear(req);
  free(req);
}

const http_string_t *
http_req_header(const http_req_t *req, const char *name) {
  size_t len = strlen(name);
  size_t i;

  for (i = 0; i < req->headers.length; i++) {
    const http_header_t *hdr = req->headers.items[i];

    if (http_string_equal(&hdr->field, name, len))
      return &hdr->value;
  }

  return NULL;
}

/*
 * Response
 */

static void
http_res_init(http_res_t *res, btc_socket_t *socket) {
  res->socket = socket;
  http_head_init(&res->headers);
}

static void
http_res_clear(http_res_t *res) {
  http_head_clear(&res->headers);
}

static http_res_t *
http_res_create(btc_socket_t *socket) {
  http_res_t *res = safe_malloc(sizeof(http_res_t));
  http_res_init(res, socket);
  return res;
}

static void
http_res_destroy(http_res_t *res) {
  http_res_clear(res);
  free(res);
}

static void
http_res_write(http_res_t *res, const void *data, size_t size) {
  unsigned char *out = safe_malloc(size + 1);
  int rc;

  memcpy(out, data, size);

  rc = btc_socket_write(res->socket, out, size);

  if (rc == -1) {
    btc_socket_close(res->socket);
    return;
  }

  if (rc == 0) {
    if (btc_socket_buffered(res->socket) > (10 << 20)) {
      btc_socket_close(res->socket);
      return;
    }
  }
}

static void
http_res_print(http_res_t *res, const char *fmt, ...) {
  /* Passing a string >=1kb is undefined behavior. */
  char out[1024];
  va_list ap;

  va_start(ap, fmt);

  http_res_write(res, out, vsprintf(out, fmt, ap));

  va_end(ap);
}

void
http_res_header(http_res_t *res, const char *field, const char *value) {
  http_head_push_item(&res->headers, field, value);
}

static const char *
http_res_descriptor(unsigned int status) {
  switch (status) {
    case 200: return "OK";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 500: return "Internal Server Error";
  }
  return "Unknown";
}

void
http_res_send(http_res_t *res,
              unsigned int status,
              const char *type,
              const char *body) {
  unsigned long length = strlen(body);
  const char *desc = http_res_descriptor(status);
  size_t i;

  http_res_print(res, "HTTP/1.1 %u %s\r\n", status, desc);
  http_res_print(res, "Connection: keep-alive\r\n");
  http_res_print(res, "Content-Type: %s\r\n", type);
  http_res_print(res, "Content-Length: %lu\r\n", length);

  for (i = 0; i < res->headers.length; i++) {
    http_header_t *hdr = res->headers.items[i];

    http_res_print(res, "%s: %s\r\n", hdr->field.data,
                                      hdr->value.data);
  }

  http_res_print(res, "\r\n");
  http_res_write(res, body, length);
}

void
http_res_txt(http_res_t *res, unsigned int status, const char *body) {
  http_res_send(res, status, "text/plain", body);
}

void
http_res_json(http_res_t *res, unsigned int status, const char *body) {
  http_res_send(res, status, "application/json", body);
}

void
http_res_error(http_res_t *res, unsigned int status) {
  const char *body = http_res_descriptor(status);
  http_res_send(res, status, "text/plain", body);
}

/*
 * Connection
 */

static void
http_conn_init(http_conn_t *conn, http_server_t *server);

static void
http_conn_clear(http_conn_t *conn) {
  if (conn->req != NULL)
    http_req_destroy(conn->req);
}

static http_conn_t *
http_conn_create(http_server_t *server) {
  http_conn_t *conn = safe_malloc(sizeof(http_conn_t));
  http_conn_init(conn, server);
  return conn;
}

static void
http_conn_destroy(http_conn_t *conn) {
  http_conn_clear(conn);
  free(conn);
}

static void
on_disconnect(btc_socket_t *socket) {
  http_conn_t *conn = btc_socket_get_data(socket);
  http_conn_destroy(conn);
}

static void
on_error(btc_socket_t *socket) {
  btc_socket_close(socket);
}

static void
on_data(btc_socket_t *socket, const void *data, size_t size) {
  http_conn_t *conn = btc_socket_get_data(socket);

  size_t nparsed = http_parser_execute(&conn->parser,
                                       &conn->settings,
                                       data,
                                       size);

  if (conn->parser.upgrade || nparsed != size)
    btc_socket_close(socket);
}

static int
on_message_begin(struct http_parser *parser) {
  http_conn_t *conn = parser->data;

  conn->req = http_req_create();
  conn->last_was_value = 0;

  return 0;
}

static int
on_url(struct http_parser *parser, const char *at, size_t length) {
  http_conn_t *conn = parser->data;
  http_req_t *req = conn->req;

  http_string_append(&req->url, at, length);

  return 0;
}

static int
on_header_field(struct http_parser *parser, const char *at, size_t length) {
  http_conn_t *conn = parser->data;
  http_req_t *req = conn->req;

  if (req->headers.length > 0 && conn->last_was_value == 0) {
    http_header_t *hdr = req->headers.items[req->headers.length - 1];

    http_string_append(&hdr->field, at, length);
  } else {
    http_header_t *hdr = http_header_create();

    http_string_assign(&hdr->field, at, length);

    http_head_push(&req->headers, hdr);
  }

  conn->last_was_value = 0;

  return 0;
}

static int
on_header_value(struct http_parser *parser, const char *at, size_t length) {
  http_conn_t *conn = parser->data;
  http_req_t *req = conn->req;
  http_header_t *hdr = req->headers.items[req->headers.length - 1];

  http_string_append(&hdr->value, at, length);

  conn->last_was_value = 1;

  return 0;
}

static int
on_headers_complete(struct http_parser *parser) {
  http_conn_t *conn = parser->data;
  http_req_t *req = conn->req;
  size_t i;

  req->method = parser->method;

  for (i = 0; i < req->headers.length; i++) {
    http_header_t *hdr = req->headers.items[i];

    http_string_lower(&hdr->field);
  }

  return 0;
}

static int
on_body(struct http_parser *parser, const char *at, size_t length) {
  http_conn_t *conn = parser->data;
  http_req_t *req = conn->req;

  http_string_append(&req->body, at, length);

  if (req->body.length > (10 << 20)) {
    http_req_destroy(req);
    btc_socket_close(conn->socket);
    conn->req = NULL;
    return 1;
  }

  return 0;
}

static int
on_message_complete(struct http_parser *parser) {
  http_conn_t *conn = parser->data;
  http_server_t *server = conn->server;
  http_req_t *req = conn->req;
  http_res_t *res = http_res_create(conn->socket);

  conn->req = NULL;

  if (server->on_request != NULL) {
    if (!server->on_request(server, req, res)) {
      http_req_destroy(req);
      http_res_destroy(res);
      btc_socket_close(conn->socket);
      return 1;
    }
  }

  http_req_destroy(req);
  http_res_destroy(res);

  return 0;
}

static void
http_conn_init(http_conn_t *conn, http_server_t *server) {
  conn->server = server;
  conn->socket = NULL;

  http_parser_init(&conn->parser, HTTP_REQUEST);
  http_parser_settings_init(&conn->settings);

  conn->parser.data = conn;

  conn->settings.on_message_begin = on_message_begin;
  conn->settings.on_url = on_url;
  conn->settings.on_status = NULL;
  conn->settings.on_header_field = on_header_field;
  conn->settings.on_header_value = on_header_value;
  conn->settings.on_headers_complete = on_headers_complete;
  conn->settings.on_body = on_body;
  conn->settings.on_message_complete = on_message_complete;
  conn->settings.on_chunk_header = NULL;
  conn->settings.on_chunk_complete = NULL;

  conn->req = NULL;
}

static void
http_conn_accept(http_conn_t *conn, btc_socket_t *socket) {
  conn->socket = socket;

  btc_socket_set_data(socket, conn);
  btc_socket_on_disconnect(socket, on_disconnect);
  btc_socket_on_error(socket, on_error);
  btc_socket_on_data(socket, on_data);
}

/*
 * Server
 */

static void
http_server_init(http_server_t *server, btc_loop_t *loop) {
  server->loop = loop;
  server->socket = NULL;
  server->on_request = NULL;
  server->data = NULL;
}

static void
http_server_clear(http_server_t *server) {
  (void)server;
}

http_server_t *
http_server_create(btc_loop_t *loop) {
  http_server_t *server = safe_malloc(sizeof(http_server_t));
  http_server_init(server, loop);
  return server;
}

void
http_server_destroy(http_server_t *server) {
  http_server_clear(server);
  free(server);
}

static void
on_socket(btc_socket_t *parent, btc_socket_t *child) {
  http_server_t *server = (http_server_t *)btc_socket_get_data(parent);
  http_conn_t *conn = http_conn_create(server);

  http_conn_accept(conn, child);
}

int
http_server_open(http_server_t *server, const btc_sockaddr_t *addr) {
  server->socket = btc_loop_listen(server->loop, addr, 1000);

  if (server->socket == NULL)
    return 0;

  /* Note: This also needs on_disconnect.
           Maybe rename on_disconnect to on_close. */
  btc_socket_set_data(server->socket, server);
  btc_socket_on_socket(server->socket, on_socket);

  return 1;
}

void
http_server_close(http_server_t *server) {
  btc_socket_close(server->socket);
  server->socket = NULL;
}
