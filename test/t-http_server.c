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

static int g_sent = 0;
static int g_recv = 0;

static int
on_request(http_server_t *server, http_req_t *req, http_res_t *res) {
  size_t i;

  (void)server;

  printf("Path: %s\n", req->path.data);

  printf("Headers:\n");

  for (i = 0; i < req->headers.length; i++) {
    http_header_t *hdr = req->headers.items[i];

    printf("  %s: %s\n", hdr->field.data, hdr->value.data);
  }

  http_res_send(res, 200, "text/plain", "Hello world\n");

  g_sent = 1;

  return 1;
}

static void
set_recv(btc_mutex_t *lock, int value) {
  btc_mutex_lock(lock);
  g_recv = value;
  btc_mutex_unlock(lock);
}

static int
get_recv(btc_mutex_t *lock) {
  int value;
  btc_mutex_lock(lock);
  value = g_recv;
  btc_mutex_unlock(lock);
  return value;
}

static void
request_thread(void *lock) {
  http_msg_t *msg = http_get("localhost.", 1337, "/", BTC_AF_INET);

  ASSERT(msg != NULL);
  ASSERT(strcmp(msg->body.data, "Hello world\n") == 0);

  http_msg_destroy(msg);

  set_recv(lock, 1);
}

int main(void) {
  btc_thread_t *thread = btc_thread_alloc();
  btc_mutex_t *lock = btc_mutex_create();
  http_server_t *server;
  btc_sockaddr_t addr;
  btc_loop_t *loop;
  int64_t start;

  btc_net_startup();

  ASSERT(btc_sockaddr_import(&addr, "127.0.0.1", 1337));

  loop = btc_loop_create();
  server = http_server_create(loop);
  server->on_request = on_request;

  ASSERT(http_server_open(server, &addr));

  btc_thread_create(thread, request_thread, lock);

  start = btc_time_msec();

  while (!get_recv(lock)) {
    ASSERT(btc_time_msec() < start + 10 * 1000);

    btc_loop_poll(loop);
  }

  btc_thread_join(thread);
  btc_thread_free(thread);
  btc_mutex_destroy(lock);

  btc_loop_close(loop);

  http_server_close(server);
  http_server_destroy(server);

  btc_loop_destroy(loop);

  ASSERT(g_sent == 1);
  ASSERT(g_recv == 1);

  btc_net_cleanup();

  return 0;
}
