/*!
 * http_client.c - http client for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <io/core.h>
#include <io/http.h>
#include <io/loop.h>

#include "http_common.h"
#include "http_parser.h"

/*
 * Types
 */

struct http_client {
  btc_loop_t *loop;
  btc_socket_t *socket;
  char hostname[1024];
  int port;
  btc_sockaddr_t addr;
  int connected;
  struct http_parser parser;
  struct http_parser_settings settings;
  http_msg_t *msg;
  int last_was_value;
  size_t total_buffered;
  int done;
};

/*
 * Options
 */

void
http_options_init(http_options_t *options) {
  options->method = HTTP_GET;
  options->path = "/";
  options->headers = NULL;
  options->agent = "libio 0.0";
  options->accept = "*/*";
  options->type = NULL;
  options->body = NULL;
}

/*
 * Message
 */

void
http_msg_init(http_msg_t *msg) {
  msg->status = HTTP_STATUS_NOT_FOUND;
  http_head_init(&msg->headers);
  http_string_init(&msg->body);
}

void
http_msg_clear(http_msg_t *msg) {
  http_head_clear(&msg->headers);
  http_string_clear(&msg->body);
}

http_msg_t *
http_msg_create(void) {
  http_msg_t *msg = http_malloc(sizeof(http_msg_t));
  http_msg_init(msg);
  return msg;
}

void
http_msg_destroy(http_msg_t *msg) {
  http_msg_clear(msg);
  free(msg);
}

/*
 * Client
 */

static void
http_client_init(http_client_t *client);

static void
http_client_clear(http_client_t *client) {
  btc_loop_close(client->loop);
  btc_loop_destroy(client->loop);

  if (client->msg != NULL)
    http_msg_destroy(client->msg);
}

http_client_t *
http_client_create(void) {
  http_client_t *client = http_malloc(sizeof(http_client_t));
  http_client_init(client);
  return client;
}

void
http_client_destroy(http_client_t *client) {
  http_client_clear(client);
  free(client);
}

const char *
http_client_strerror(http_client_t *client) {
  return btc_loop_strerror(client->loop);
}

static void
on_connect(btc_socket_t *socket) {
  http_client_t *client = btc_socket_get_data(socket);
  client->connected = 1;
}

static void
on_close(btc_socket_t *socket) {
  http_client_t *client = btc_socket_get_data(socket);
  client->socket = NULL;
  client->connected = 0;
  client->done = 1;
}

static void
on_error(btc_socket_t *socket) {
  btc_socket_close(socket);
}

static int
on_data(btc_socket_t *socket, const void *data, size_t size) {
  http_client_t *client = btc_socket_get_data(socket);

  size_t nparsed = http_parser_execute(&client->parser,
                                       &client->settings,
                                       data,
                                       size);

  if (client->parser.upgrade || nparsed != size || size == 0)
    btc_socket_close(socket);

  return 1;
}

static int
http_resolve(btc_sockaddr_t *addr, const char *hostname, int port, int family) {
  btc_sockaddr_t *res, *it;
  int total = 0;

  if (btc_sockaddr_import(addr, hostname, port))
    return 1;

  if (!btc_getaddrinfo(&res, hostname))
    return 0;

  if (family == BTC_AF_UNSPEC) {
    for (it = res; it != NULL; it = it->next)
      total++;

    if (total > 0)
      total = (btc_time_usec() % total) + 1;

    for (it = res; it != NULL; it = it->next) {
      if (--total == 0)
        break;
    }
  } else {
    for (it = res; it != NULL; it = it->next) {
      if (it->family == family)
        total++;
    }

    if (total > 0)
      total = (btc_time_usec() % total) + 1;

    for (it = res; it != NULL; it = it->next) {
      if (it->family == family && --total == 0)
        break;
    }
  }

  if (it == NULL) {
    btc_freeaddrinfo(res);
    return 0;
  }

  *addr = *it;
  addr->port = port;

  btc_freeaddrinfo(res);

  return 1;
}

static int
http_client_connect(http_client_t *client, const btc_sockaddr_t *addr) {
  btc_socket_t *socket = btc_loop_connect(client->loop, addr);

  if (socket == NULL)
    return 0;

  http_parser_init(&client->parser, HTTP_RESPONSE);

  client->parser.data = client;

  btc_socket_set_data(socket, client);
  btc_socket_on_connect(socket, on_connect);
  btc_socket_on_close(socket, on_close);
  btc_socket_on_error(socket, on_error);
  btc_socket_on_data(socket, on_data);

  client->socket = socket;

  btc_socket_complete(socket);

  return 1;
}

int
http_client_open(http_client_t *client,
                 const char *hostname,
                 int port,
                 int family) {
  size_t len = strlen(hostname);
  btc_sockaddr_t addr;

  if (len + 1 > sizeof(client->hostname))
    return 0;

  if (port <= 0 || port > 0xffff)
    return 0;

  if (!http_resolve(&addr, hostname, port, family))
    return 0;

  if (!http_client_connect(client, &addr))
    return 0;

  memcpy(client->hostname, hostname, len + 1);

  client->port = port;
  client->addr = addr;

  return 1;
}

static int
http_client_reopen(http_client_t *client) {
  return http_client_connect(client, &client->addr);
}

void
http_client_close(http_client_t *client) {
  if (client->socket != NULL)
    btc_socket_close(client->socket);

  client->hostname[0] = '\0';
  client->port = 0;

  btc_sockaddr_init(&client->addr);

  client->connected = 0;
}

static void
http_client_reset(http_client_t *client) {
  if (client->msg != NULL)
    http_msg_destroy(client->msg);

  client->msg = NULL;
  client->last_was_value = 0;
  client->total_buffered = 0;
  client->done = 0;
}

static int
http_client_abort(http_client_t *client) {
  http_client_reset(client);
  client->done = 1;
  return 1;
}

static int
on_message_begin(struct http_parser *parser) {
  http_client_t *client = parser->data;

  http_client_reset(client);

  client->msg = http_msg_create();

  return 0;
}

static int
on_header_field(struct http_parser *parser, const char *at, size_t length) {
  http_client_t *client = parser->data;
  http_msg_t *msg = client->msg;

  if (msg->headers.length > 0 && client->last_was_value == 0) {
    http_header_t *hdr = msg->headers.items[msg->headers.length - 1];

    http_string_append(&hdr->field, at, length);

    if (hdr->field.length > HTTP_MAX_FIELD_SIZE)
      return http_client_abort(client);
  } else {
    http_header_t *hdr = http_header_create();

    http_string_assign(&hdr->field, at, length);

    if (hdr->field.length > HTTP_MAX_FIELD_SIZE)
      return http_client_abort(client);

    http_head_push(&msg->headers, hdr);
  }

  client->last_was_value = 0;
  client->total_buffered += length;

  if (msg->headers.length > HTTP_MAX_HEADERS)
    return http_client_abort(client);

  if (client->total_buffered > HTTP_MAX_BUFFER)
    return http_client_abort(client);

  return 0;
}

static int
on_header_value(struct http_parser *parser, const char *at, size_t length) {
  http_client_t *client = parser->data;
  http_msg_t *msg = client->msg;
  http_header_t *hdr = msg->headers.items[msg->headers.length - 1];

  http_string_append(&hdr->value, at, length);

  client->last_was_value = 1;
  client->total_buffered += length;

  if (hdr->value.length > HTTP_MAX_FIELD_SIZE)
    return http_client_abort(client);

  if (client->total_buffered > HTTP_MAX_BUFFER)
    return http_client_abort(client);

  return 0;
}

static int
on_headers_complete(struct http_parser *parser) {
  http_client_t *client = parser->data;
  http_msg_t *msg = client->msg;
  size_t i;

  msg->status = parser->status_code;

  for (i = 0; i < msg->headers.length; i++) {
    http_header_t *hdr = msg->headers.items[i];

    http_string_lower(&hdr->field);
  }

  return 0;
}

static int
on_body(struct http_parser *parser, const char *at, size_t length) {
  http_client_t *client = parser->data;
  http_msg_t *msg = client->msg;

  http_string_append(&msg->body, at, length);

  client->total_buffered += length;

  if (client->total_buffered > HTTP_MAX_BUFFER)
    return http_client_abort(client);

  return 0;
}

static int
on_message_complete(struct http_parser *parser) {
  http_client_t *client = parser->data;

  client->done = 1;

  return 0;
}

static void
http_client_init(http_client_t *client) {
  client->loop = btc_loop_create();
  client->socket = NULL;
  client->hostname[0] = '\0';
  client->port = 0;
  btc_sockaddr_init(&client->addr);
  client->connected = 0;

  http_parser_init(&client->parser, HTTP_RESPONSE);
  http_parser_settings_init(&client->settings);

  client->parser.data = client;

  client->settings.on_message_begin = on_message_begin;
  client->settings.on_url = NULL;
  client->settings.on_status = NULL;
  client->settings.on_header_field = on_header_field;
  client->settings.on_header_value = on_header_value;
  client->settings.on_headers_complete = on_headers_complete;
  client->settings.on_body = on_body;
  client->settings.on_message_complete = on_message_complete;
  client->settings.on_chunk_header = NULL;
  client->settings.on_chunk_complete = NULL;

  client->msg = NULL;
  client->last_was_value = 0;
  client->total_buffered = 0;
  client->done = 0;
}

static int
http_client_write(http_client_t *client, void *data, size_t size) {
  int rc = btc_socket_write(client->socket, data, size);

  if (rc == -1) {
    btc_socket_close(client->socket);
    return 0;
  }

  if (rc == 0) {
    if (btc_socket_buffered(client->socket) > HTTP_MAX_BUFFER) {
      btc_socket_close(client->socket);
      return 0;
    }
  }

  return 1;
}

static int
http_client_put(http_client_t *client, const char *str, size_t len) {
  void *data;

  if (len == 0)
    return 1;

  data = http_malloc(len);

  memcpy(data, str, len);

  return http_client_write(client, data, len);
}

static int
http_client_print(http_client_t *client, const char *fmt, ...) {
  /* Passing a string >=1kb is undefined behavior. */
  char buf[1024];
  va_list ap;
  int rc;

  va_start(ap, fmt);

  rc = http_client_put(client, buf, vsprintf(buf, fmt, ap));

  va_end(ap);

  return rc;
}

static int
http_client_write_head(http_client_t *client, const http_options_t *opt) {
  const char *method = http_method_str(opt->method);

  if (!http_client_print(client, "%s %s HTTP/1.1\r\n", method, opt->path))
    return 0;

  if (client->port != 80) {
    if (!http_client_print(client, "Host: %s:%d\r\n", client->hostname,
                                                      client->port)) {
      return 0;
    }
  } else {
    if (!http_client_print(client, "Host: %s\r\n", client->hostname))
      return 0;
  }

  if (opt->agent != NULL) {
    if (!http_client_print(client, "User-Agent: %s\r\n", opt->agent))
      return 0;
  }

  if (opt->accept != NULL) {
    if (!http_client_print(client, "Accept: %s\r\n", opt->accept))
      return 0;
  }

  if (opt->type != NULL) {
    if (!http_client_print(client, "Content-Type: %s\r\n", opt->type))
      return 0;
  }

  if (opt->body != NULL) {
    unsigned long length = strlen(opt->body);

    if (!http_client_print(client, "Content-Length: %lu\r\n", length))
      return 0;
  }

  if (opt->headers != NULL) {
    size_t i;

    for (i = 0; opt->headers[i] != NULL; i += 2) {
      const char *field = opt->headers[i + 0];
      const char *value = opt->headers[i + 1];

      if (!http_client_print(client, "%s: %s\r\n", field, value))
        return 0;
    }
  }

  if (!http_client_print(client, "\r\n"))
    return 0;

  return 1;
}

http_msg_t *
http_client_request(http_client_t *client, const http_options_t *options) {
  http_msg_t *msg = NULL;
  int64_t start;

  if (client->socket == NULL) {
    if (!http_client_reopen(client))
      return NULL;
  }

  if (!http_client_write_head(client, options))
    return NULL;

  if (options->body != NULL) {
    if (!http_client_put(client, options->body, strlen(options->body)))
      return NULL;
  }

  http_client_reset(client);

  start = btc_time_msec();

  while (!client->done) {
    if (btc_time_msec() > start + 10 * 1000)
      goto fail;

    btc_loop_poll(client->loop, 1000);
  }

  msg = client->msg;

  client->msg = NULL;

fail:
  http_client_reset(client);
  return msg;
}

http_msg_t *
http_get(const char *hostname, int port, const char *path, int family) {
  http_client_t *client = http_client_create();
  http_options_t options;
  http_msg_t *msg = NULL;

  if (!http_client_open(client, hostname, port, family))
    goto fail;

  http_options_init(&options);

  options.path = path;

  msg = http_client_request(client, &options);

  http_client_close(client);
fail:
  http_client_destroy(client);
  return msg;
}

int
btc_net_external(btc_sockaddr_t *addr, int family, int port) {
  http_msg_t *msg = http_get("icanhazip.com", 80, "/", family);
  char *xp;
  int ret;

  if (msg == NULL)
    return 0;

  xp = msg->body.data;

  while (*xp > ' ')
    xp++;

  *xp = '\0';

  ret = btc_sockaddr_import(addr, msg->body.data, port);

  http_msg_destroy(msg);

  return ret;
}
