/*!
 * t-http.c - http test for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io/core.h>
#include <io/loop.h>
#include <io/http.h>
#include "lib/tests.h"

static int got_request = 0;
static int got_response = 0;

static int
on_request(http_server_t *server, http_req_t *req, http_res_t *res) {
  size_t i;

  (void)server;

  printf("Received HTTP request:\n");
  printf("  Path: %s\n", req->path.data);

  printf("  Headers:\n");

  for (i = 0; i < req->headers.length; i++) {
    http_header_t *hdr = req->headers.items[i];

    printf("    %s: %s\n", hdr->field.data, hdr->value.data);
  }

  got_request = 1;

  http_res_send(res, 200, "text/plain", "Hello world\n");

  return 1;
}

static void
on_response(const http_response_t *res, void *data) {
  btc_loop_t *loop = data;

  ASSERT(got_request);

  if (res != NULL) {
    printf("Received HTTP response:\n");
    printf("  %s", res->body.data);

    ASSERT(strcmp(res->body.data, "Hello world\n") == 0);

    got_response = 1;
  } else {
    printf("HTTP request failed.\n");
  }

  btc_loop_stop(loop);
}

int main(void) {
  btc_loop_t *loop = btc_loop_create();
  http_server_t *server = http_server_create(loop);
  btc_sockaddr_t addr;

  btc_sockaddr_import(&addr, "127.0.0.1", 12345);

  server->on_request = on_request;
  server->data = NULL;

  if (!http_server_open(server, &addr))
    return 1;

  {
    http_options_t opt;

    http_options_init(&opt);

    opt.hostname = "localhost";
    opt.port = 12345;

    ASSERT(http_request(loop, &opt, on_response, loop));
  }

  btc_loop_start(loop);

  ASSERT(got_request);
  ASSERT(got_response);

  http_server_close(server);
  http_server_destroy(server);

  btc_loop_destroy(loop);

  return 0;
}
