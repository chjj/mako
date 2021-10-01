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

static int
on_request(http_server_t *server, http_req_t *req, http_res_t *res) {
  size_t i;

  (void)server;

  printf("URL: %s\n", req->url.data);

  printf("Headers:\n");

  for (i = 0; i < req->headers.length; i++) {
    http_header_t *hdr = req->headers.items[i];

    printf("  %s: %s\n", hdr->field.data, hdr->value.data);
  }

  http_res_send(res, 200, "text/plain", "Hello world\n");

  return 1;
}

int main(void) {
  btc_loop_t *loop = btc_loop_create();
  http_server_t *server = http_server_create(loop);
  btc_sockaddr_t addr;

  btc_sockaddr_import(&addr, "127.0.0.1", 8080);

  server->on_request = on_request;
  server->data = NULL;

  if (!http_server_open(server, &addr))
    return 1;

  btc_loop_start(loop);

  return 0;
}
