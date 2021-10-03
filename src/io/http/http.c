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
 * Constants
 */

#define HTTP_MAX_BUFFER (20 << 20)
#define HTTP_MAX_FIELD_SIZE (1 << 10)
#define HTTP_MAX_HEADERS 100
#define HTTP_BACKLOG 100

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
  size_t total_buffered;
  http_response_cb *respond;
  void *data;
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
  http_string_init(&req->path);
  http_head_init(&req->headers);
  http_string_init(&req->body);
}

static void
http_req_clear(http_req_t *req) {
  http_string_clear(&req->path);
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

static int
http_res_write(http_res_t *res, void *data, size_t size) {
  int rc = btc_socket_write(res->socket, data, size);

  if (rc == -1) {
    btc_socket_close(res->socket);
    return 0;
  }

  if (rc == 0) {
    if (btc_socket_buffered(res->socket) > HTTP_MAX_BUFFER)
      btc_socket_close(res->socket);

    return 0;
  }

  return 1;
}

static int
http_res_put(http_res_t *res, const char *str, size_t len) {
  void *data;

  if (len == 0)
    return 1;

  data = safe_malloc(len);

  memcpy(data, str, len);

  return http_res_write(res, data, len);
}

static void
http_res_print(http_res_t *res, const char *fmt, ...) {
  /* Passing a string >=1kb is undefined behavior. */
  char out[1024];
  va_list ap;

  va_start(ap, fmt);

  http_res_put(res, out, vsprintf(out, fmt, ap));

  va_end(ap);
}

void
http_res_header(http_res_t *res, const char *field, const char *value) {
  http_head_push_item(&res->headers, field, value);
}

static void
http_res_write_head(http_res_t *res,
                    unsigned int status,
                    const char *type,
                    unsigned int length) {
  const char *desc = http_status_str(status);
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
}

void
http_res_send(http_res_t *res,
              unsigned int status,
              const char *type,
              const char *body) {
  size_t length = strlen(body);

  http_res_write_head(res, status, type, length);
  http_res_put(res, body, length);
}

void
http_res_send_data(http_res_t *res,
                   unsigned int status,
                   const char *type,
                   void *body,
                   size_t length) {
  http_res_write_head(res, status, type, length);
  http_res_write(res, body, length);
}

void
http_res_error(http_res_t *res, unsigned int status) {
  char body[33];

  sprintf(body, "%s\n", http_status_str(status));

  http_res_send(res, status, "text/plain", body);
}

/*
 * Connection
 */

static void
http_conn_init(http_conn_t *conn, enum http_parser_type type);

static void
http_conn_clear(http_conn_t *conn) {
  if (conn->req != NULL)
    http_req_destroy(conn->req);
}

static http_conn_t *
http_conn_create(enum http_parser_type type) {
  http_conn_t *conn = safe_malloc(sizeof(http_conn_t));
  http_conn_init(conn, type);
  return conn;
}

static void
http_conn_destroy(http_conn_t *conn) {
  http_conn_clear(conn);
  free(conn);
}

static int
http_conn_abort(http_conn_t *conn) {
  if (conn->req != NULL)
    http_req_destroy(conn->req);

  btc_socket_close(conn->socket);

  conn->req = NULL;
  conn->last_was_value = 0;
  conn->total_buffered = 0;

  return 1;
}

static void
on_close(btc_socket_t *socket) {
  http_conn_t *conn = btc_socket_get_data(socket);

  if (conn->respond != NULL) {
    conn->respond(NULL, conn->data);
    conn->respond = NULL;
  }

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

  if (conn->parser.upgrade || nparsed != size || size == 0)
    btc_socket_close(socket);
}

static int
on_message_begin(struct http_parser *parser) {
  http_conn_t *conn = parser->data;

  if (conn->req != NULL)
    http_req_destroy(conn->req);

  conn->req = http_req_create();
  conn->last_was_value = 0;
  conn->total_buffered = 0;

  return 0;
}

static int
on_url(struct http_parser *parser, const char *at, size_t length) {
  http_conn_t *conn = parser->data;
  http_req_t *req = conn->req;

  http_string_append(&req->path, at, length);

  conn->total_buffered += length;

  if (req->path.length > HTTP_MAX_FIELD_SIZE)
    return http_conn_abort(conn);

  if (conn->total_buffered > HTTP_MAX_BUFFER)
    return http_conn_abort(conn);

  return 0;
}

static int
on_header_field(struct http_parser *parser, const char *at, size_t length) {
  http_conn_t *conn = parser->data;
  http_req_t *req = conn->req;

  if (req->headers.length > 0 && conn->last_was_value == 0) {
    http_header_t *hdr = req->headers.items[req->headers.length - 1];

    http_string_append(&hdr->field, at, length);

    if (hdr->field.length > HTTP_MAX_FIELD_SIZE)
      return http_conn_abort(conn);
  } else {
    http_header_t *hdr = http_header_create();

    http_string_assign(&hdr->field, at, length);

    if (hdr->field.length > HTTP_MAX_FIELD_SIZE)
      return http_conn_abort(conn);

    http_head_push(&req->headers, hdr);
  }

  conn->last_was_value = 0;
  conn->total_buffered += length;

  if (req->headers.length > HTTP_MAX_HEADERS)
    return http_conn_abort(conn);

  if (conn->total_buffered > HTTP_MAX_BUFFER)
    return http_conn_abort(conn);

  return 0;
}

static int
on_header_value(struct http_parser *parser, const char *at, size_t length) {
  http_conn_t *conn = parser->data;
  http_req_t *req = conn->req;
  http_header_t *hdr = req->headers.items[req->headers.length - 1];

  http_string_append(&hdr->value, at, length);

  conn->last_was_value = 1;
  conn->total_buffered += length;

  if (hdr->value.length > HTTP_MAX_FIELD_SIZE)
    return http_conn_abort(conn);

  if (conn->total_buffered > HTTP_MAX_BUFFER)
    return http_conn_abort(conn);

  return 0;
}

static int
on_headers_complete(struct http_parser *parser) {
  http_conn_t *conn = parser->data;
  http_req_t *req = conn->req;
  size_t i;

  req->status = parser->status_code; /* client only */
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

  conn->total_buffered += length;

  if (conn->total_buffered > HTTP_MAX_BUFFER)
    return http_conn_abort(conn);

  return 0;
}

static int
on_message_complete(struct http_parser *parser) {
  http_conn_t *conn = parser->data;
  http_server_t *server = conn->server;
  http_req_t *req = conn->req;
  http_res_t *res = http_res_create(conn->socket);

  conn->req = NULL;
  conn->last_was_value = 0;
  conn->total_buffered = 0;

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

static int
on_message_client(struct http_parser *parser) {
  http_conn_t *conn = parser->data;
  http_req_t *req = conn->req;

  conn->req = NULL;
  conn->last_was_value = 0;
  conn->total_buffered = 0;

  if (conn->respond != NULL) {
    conn->respond(req, conn->data);
    conn->respond = NULL;
  }

  http_req_destroy(req);

  btc_socket_close(conn->socket);

  return 0;
}

static void
http_conn_init(http_conn_t *conn, enum http_parser_type type) {
  conn->server = NULL;
  conn->socket = NULL;

  http_parser_init(&conn->parser, type);
  http_parser_settings_init(&conn->settings);

  conn->parser.data = conn;

  conn->settings.on_message_begin = on_message_begin;
  conn->settings.on_url = on_url;
  conn->settings.on_status = NULL;
  conn->settings.on_header_field = on_header_field;
  conn->settings.on_header_value = on_header_value;
  conn->settings.on_headers_complete = on_headers_complete;
  conn->settings.on_body = on_body;

  if (type == HTTP_RESPONSE)
    conn->settings.on_message_complete = on_message_client;
  else
    conn->settings.on_message_complete = on_message_complete;

  conn->settings.on_chunk_header = NULL;
  conn->settings.on_chunk_complete = NULL;

  conn->req = NULL;
  conn->last_was_value = 0;
  conn->total_buffered = 0;
  conn->respond = NULL;
  conn->data = NULL;
}

static void
http_conn_accept(http_conn_t *conn, btc_socket_t *socket) {
  conn->socket = socket;

  btc_socket_set_data(socket, conn);
  btc_socket_on_close(socket, on_close);
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
  http_server_t *server = btc_socket_get_data(parent);
  http_conn_t *conn = http_conn_create(HTTP_REQUEST);

  conn->server = server;

  http_conn_accept(conn, child);
}

static void
on_server_close(btc_socket_t *socket) {
  http_server_t *server = btc_socket_get_data(socket);
  server->socket = NULL;
}

int
http_server_open(http_server_t *server, const btc_sockaddr_t *addr) {
  server->socket = btc_loop_listen(server->loop, addr, HTTP_BACKLOG);

  if (server->socket == NULL)
    return 0;

  btc_socket_set_data(server->socket, server);
  btc_socket_on_socket(server->socket, on_socket);
  btc_socket_on_close(server->socket, on_server_close);

  return 1;
}

void
http_server_close(http_server_t *server) {
  if (server->socket != NULL)
    btc_socket_close(server->socket);
}

/*
 * Client
 */

void
http_options_init(http_options_t *options) {
  options->method = HTTP_GET;
  options->hostname = "127.0.0.1";
  options->port = 80;
  options->path = "/";
  options->headers = NULL;
  options->agent = "libio 0.0";
  options->accept = "*/*";
  options->type = NULL;
  options->body = NULL;
}

int
http_request(btc_loop_t *loop,
             const http_options_t *options,
             http_response_cb *callback,
             void *data) {
  unsigned long length = 0;
  btc_sockaddr_t addr;
  btc_socket_t *socket;
  http_conn_t *conn;
  http_res_t res;
  const char *method;
  size_t i;

  if (!btc_sockaddr_import(&addr, options->hostname, options->port)) {
    btc_sockaddr_t *r, *p;

    if (!btc_getaddrinfo(&r, options->hostname))
      return 0;

    for (p = r; p != NULL; p = p->next) {
      if (p->family == BTC_AF_INET)
        break;
    }

    if (p == NULL) {
      btc_freeaddrinfo(r);
      return 0;
    }

    addr = *p;
    addr.port = options->port;

    btc_freeaddrinfo(r);
  }

  socket = btc_loop_connect(loop, &addr);

  if (socket == NULL)
    return 0;

  conn = http_conn_create(HTTP_RESPONSE);

  conn->respond = callback;
  conn->data = data;

  http_conn_accept(conn, socket);

  res.socket = socket;

  method = http_method_str(options->method);

  http_res_print(&res, "%s %s HTTP/1.1\r\n", method, options->path);

  if (options->port != 80)
    http_res_print(&res, "Host: %s:%u\r\n", options->hostname, options->port);
  else
    http_res_print(&res, "Host: %s\r\n", options->hostname);

  if (options->agent != NULL)
    http_res_print(&res, "User-Agent: %s\r\n", options->agent);

  if (options->accept != NULL)
    http_res_print(&res, "Accept: %s\r\n", options->accept);

  if (options->method != HTTP_GET) {
    if (options->body != NULL)
      length = strlen(options->body);

    if (options->type != NULL)
      http_res_print(&res, "Content-Type: %s\r\n", options->type);

    if (length != 0)
      http_res_print(&res, "Content-Length: %lu\r\n", length);
  }

  if (options->headers != NULL) {
    for (i = 0; options->headers[i] != NULL; i += 2) {
      const char *field = options->headers[i + 0];
      const char *value = options->headers[i + 1];

      http_res_print(&res, "%s: %s\r\n", field, value);
    }
  }

  http_res_print(&res, "\r\n");

  if (length != 0)
    http_res_put(&res, options->body, length);

  btc_socket_complete(socket);

  return 1;
}
