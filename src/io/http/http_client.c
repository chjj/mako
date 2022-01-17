/*!
 * http_client.c - http client for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

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
  options->user = NULL;
  options->pass = NULL;
  options->body = NULL;
  options->length = 0;
}

void
http_options_clear(http_options_t *options) {
  if (options->headers != NULL)
    free(options->headers);

  options->headers = NULL;
  options->length = 0;
}

void
http_options_header(http_options_t *options, const char *field,
                                             const char *value) {
  http_options_t *z = options;

  z->headers = http_realloc(z->headers, (z->length + 2) * sizeof(const char *));

  z->headers[z->length++] = field;
  z->headers[z->length++] = value;
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

  if (!btc_getaddrinfo(&res, hostname, port))
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

  btc_loop_close(client->loop);
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
    btc_loop_cleanup(client->loop);
    return 0;
  }

  if (rc == 0) {
    if (btc_socket_buffered(client->socket) > HTTP_MAX_BUFFER) {
      btc_socket_close(client->socket);
      btc_loop_cleanup(client->loop);
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

static size_t
http_client_size_head(http_client_t *client,
                      const char *method,
                      const http_options_t *opt) {
  size_t size = 0;

  size += 12 + strlen(method) + strlen(opt->path); /* %s %s HTTP/1.1 */

  if (client->port == 80)
    size += 8 + strlen(client->hostname); /* Host: %s */
  else
    size += 11 + strlen(client->hostname) + 11; /* Host: [%s]:%d */

  if (opt->agent != NULL)
    size += 14 + strlen(opt->agent); /* User-Agent: %s */

  if (opt->accept != NULL)
    size += 10 + strlen(opt->accept); /* Accept: %s */

  if (opt->type != NULL)
    size += 16 + strlen(opt->type); /* Content-Type: %s */

  if (opt->body != NULL)
    size += 18 + 20; /* Content-Length: %lu */

  if (opt->user != NULL && opt->pass != NULL) {
    size_t len = strlen(opt->user) + 1 + strlen(opt->pass);

    size += 23 + base64_encode_size(len); /* Authorization: Basic %s */
  }

  if (opt->headers != NULL) {
    size_t i;

    for (i = 0; i < opt->length; i += 2) {
      const char *field = opt->headers[i + 0];
      const char *value = opt->headers[i + 1];

      size += 4 + strlen(field) + strlen(value); /* %s: %s */
    }
  }

  size += 2; /* \r\n */
  size += 1; /* \0 */

  return size;
}

static int
http_client_write_head(http_client_t *client, const http_options_t *opt) {
  const char *method = http_method_str(opt->method);
  char *head = http_malloc(http_client_size_head(client, method, opt));
  char *zp = head;

  zp += sprintf(zp, "%s %s HTTP/1.1\r\n", method, opt->path);

  if (client->port == 80)
    zp += sprintf(zp, "Host: %s\r\n", client->hostname);
  else if (strchr(client->hostname, ':') != NULL)
    zp += sprintf(zp, "Host: [%s]:%d\r\n", client->hostname, client->port);
  else
    zp += sprintf(zp, "Host: %s:%d\r\n", client->hostname, client->port);

  if (opt->agent != NULL)
    zp += sprintf(zp, "User-Agent: %s\r\n", opt->agent);

  if (opt->accept != NULL)
    zp += sprintf(zp, "Accept: %s\r\n", opt->accept);

  if (opt->type != NULL)
    zp += sprintf(zp, "Content-Type: %s\r\n", opt->type);

  if (opt->body != NULL) {
    unsigned long length = strlen(opt->body);

    zp += sprintf(zp, "Content-Length: %lu\r\n", length);
  }

  if (opt->user != NULL && opt->pass != NULL) {
    char tp[512], bp[685];
    int tn;

    if (strlen(opt->user) > 255 || strlen(opt->pass) > 255) {
      free(head);
      return 0;
    }

    tn = sprintf(tp, "%s:%s", opt->user, opt->pass);

    base64_encode(bp, NULL, (unsigned char *)tp, tn);

    zp += sprintf(zp, "Authorization: Basic %s\r\n", bp);
  }

  if (opt->headers != NULL) {
    size_t i;

    for (i = 0; i < opt->length; i += 2) {
      const char *field = opt->headers[i + 0];
      const char *value = opt->headers[i + 1];

      zp += sprintf(zp, "%s: %s\r\n", field, value);
    }
  }

  zp += sprintf(zp, "\r\n");

  return http_client_write(client, head, zp - head);
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
    if (btc_time_msec() > start + 10 * 1000) {
      btc_socket_timeout(client->socket);
      btc_loop_cleanup(client->loop);
      goto fail;
    }

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
  size_t xn;
  char *xp;
  int ret;

  if (msg == NULL)
    return 0;

  xp = msg->body.data;
  xn = msg->body.length;

  while (xn > 0 && xp[xn - 1] <= ' ')
    xn -= 1;

  xp[xn] = '\0';

  ret = btc_sockaddr_import(addr, xp, port);

  http_msg_destroy(msg);

  return ret;
}
