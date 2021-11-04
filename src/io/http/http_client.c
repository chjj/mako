/*!
 * http_client.c - http client for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  ifndef __MINGW32__
#    pragma comment(lib, "ws2_32.lib")
#  endif
#else
#  include <sys/types.h>
#  include <sys/time.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <sys/un.h>
#  include <fcntl.h>
#  include <unistd.h>
#endif

#include <io/core.h>
#include <io/http.h>

#include "http_common.h"
#include "http_parser.h"

/*
 * Compat
 */

#if defined(_WIN32)
typedef SOCKET btc_sockfd_t;
#  define BTC_INVALID_SOCKET INVALID_SOCKET
#  define BTC_SOCKET_ERROR SOCKET_ERROR
#  define BTC_NOSIGNAL 0
#  define btc_errno (WSAGetLastError())
#  define BTC_EINTR WSAEINTR
#  define btc_closesocket closesocket
#else
typedef int btc_sockfd_t;
#  define BTC_INVALID_SOCKET -1
#  define BTC_SOCKET_ERROR -1
#  if defined(MSG_NOSIGNAL)
#    define BTC_NOSIGNAL MSG_NOSIGNAL
#  else
#    define BTC_NOSIGNAL 0
#  endif
#  define btc_errno errno
#  define BTC_EINTR EINTR
#  define btc_closesocket close
#endif

/*
 * Types
 */

struct http_client {
  char hostname[1024];
  int port;
  btc_sockfd_t fd;
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

static int
http_resolve(struct sockaddr *addr, const char *hostname, int port) {
  btc_sockaddr_t host;

  if (!btc_sockaddr_import(&host, hostname, port)) {
    btc_sockaddr_t *r, *p;

    if (!btc_getaddrinfo(&r, hostname))
      return 0;

    for (p = r; p != NULL; p = p->next) {
      if (p->family == BTC_AF_INET)
        break;
    }

    if (p == NULL) {
      for (p = r; p != NULL; p = p->next) {
        if (p->family == BTC_AF_INET6)
          break;
      }

      if (p == NULL) {
        btc_freeaddrinfo(r);
        return 0;
      }
    }

    host = *p;
    host.port = port;

    btc_freeaddrinfo(r);
  }

  return btc_sockaddr_get(addr, &host);
}

static btc_sockfd_t
http_connect(const struct sockaddr *addr) {
  int domain, addrlen;
  btc_sockfd_t fd;

  switch (addr->sa_family) {
    case AF_INET:
      domain = PF_INET;
      addrlen = sizeof(struct sockaddr_in);
      break;
    case AF_INET6:
      domain = PF_INET6;
      addrlen = sizeof(struct sockaddr_in6);
      break;
    default:
      return BTC_INVALID_SOCKET;
  }

  fd = socket(domain, SOCK_STREAM, 0);

  if (fd == BTC_INVALID_SOCKET)
    return BTC_INVALID_SOCKET;

#ifdef SO_NOSIGPIPE
  {
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
  }
#endif

  if (connect(fd, addr, addrlen) == BTC_SOCKET_ERROR) {
    btc_closesocket(fd);
    return BTC_INVALID_SOCKET;
  }

  return fd;
}

int
http_client_open(http_client_t *client, const char *hostname, int port) {
  struct sockaddr_storage storage;
  struct sockaddr *addr = (struct sockaddr *)&storage;
  size_t len = strlen(hostname);
  btc_sockfd_t fd;

  if (len + 1 > sizeof(client->hostname))
    return 0;

  if (!http_resolve(addr, hostname, port))
    return 0;

  fd = http_connect(addr);

  if (fd == BTC_INVALID_SOCKET)
    return 0;

  client->fd = fd;
  client->port = port;

  memcpy(client->hostname, hostname, len + 1);

  return 1;
}

void
http_client_close(http_client_t *client) {
  btc_closesocket(client->fd);
  client->hostname[0] = '\0';
  client->port = 0;
  client->fd = BTC_INVALID_SOCKET;
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
  client->hostname[0] = '\0';
  client->port = 0;
  client->fd = BTC_INVALID_SOCKET;

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
http_client_write(http_client_t *client, const char *buf, size_t len) {
  int nwrite;

  while (len > 0) {
    do {
      nwrite = send(client->fd, buf, len, BTC_NOSIGNAL);
    } while (nwrite == BTC_SOCKET_ERROR && btc_errno == BTC_EINTR);

    if (nwrite == BTC_SOCKET_ERROR)
      return 0;

    buf += nwrite;
    len -= nwrite;
  }

  return 1;
}

static int
http_client_print(http_client_t *client, const char *fmt, ...) {
  /* Passing a string >=1kb is undefined behavior. */
  char buf[1024];
  va_list ap;
  int rc;

  va_start(ap, fmt);

  rc = http_client_write(client, buf, vsprintf(buf, fmt, ap));

  va_end(ap);

  return rc;
}

static int
http_client_write_head(http_client_t *client, const http_options_t *opt) {
  const char *method = http_method_str(opt->method);

  if (!http_client_print(client, "%s %s HTTP/1.1\r\n", method, opt->path))
    return 0;

  if (client->port != 80) {
    if (!http_client_print(client, "Host: %s:%u\r\n", client->hostname,
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

static int
http_client_parse(http_client_t *client, const void *data, size_t size) {
  size_t nparsed = http_parser_execute(&client->parser,
                                       &client->settings,
                                       data,
                                       size);

  return nparsed == size;
}

http_msg_t *
http_client_request(http_client_t *client, const http_options_t *options) {
  http_msg_t *msg = NULL;
  char buf[8192];
  int nread;

  if (!http_client_write_head(client, options))
    return NULL;

  if (options->body != NULL) {
    if (!http_client_write(client, options->body, strlen(options->body)))
      return NULL;
  }

  http_client_reset(client);

  while (!client->done) {
    do {
      nread = recv(client->fd, buf, sizeof(buf), 0);
    } while (nread == BTC_SOCKET_ERROR && btc_errno == BTC_EINTR);

    if (nread == BTC_SOCKET_ERROR)
      goto fail;

    if (!http_client_parse(client, buf, nread))
      goto fail;

    if (nread == 0)
      break;
  }

  msg = client->msg;

  client->msg = NULL;

fail:
  http_client_reset(client);
  return msg;
}
