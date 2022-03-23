/*!
 * t-http.c - http test for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io/core.h>
#include <io/loop.h>
#include <io/http.h>
#include "lib/tests.h"

#if defined(_WIN32) || defined(BTC_HAVE_PTHREAD)

static int g_sent = 0;
static int g_recv = 0;

static void
inc_recv(btc_mutex_t *lock) {
  btc_mutex_lock(lock);
  g_recv++;
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

static int
on_request(http_server_t *server, http_req_t *req, http_res_t *res) {
  (void)server;

  if (g_sent == 0) {
    ASSERT(req->method == HTTP_METHOD_GET);
    ASSERT(strcmp(req->path.data, "/") == 0);
    ASSERT(req->headers.length == 3);

    ASSERT(strcmp(req->headers.items[0]->field.data, "host") == 0);
    ASSERT(strcmp(req->headers.items[0]->value.data, "localhost:1337") == 0);

    ASSERT(strcmp(req->headers.items[1]->field.data, "user-agent") == 0);
    ASSERT(strcmp(req->headers.items[1]->value.data, "libio 0.0") == 0);

    ASSERT(strcmp(req->headers.items[2]->field.data, "accept") == 0);
    ASSERT(strcmp(req->headers.items[2]->value.data, "*/*") == 0);
  } else {
    ASSERT(req->method == HTTP_METHOD_POST);
    ASSERT(strcmp(req->path.data, "/post") == 0);
    ASSERT(req->headers.length == 7);

    ASSERT(strcmp(req->headers.items[0]->field.data, "host") == 0);
    ASSERT(strcmp(req->headers.items[0]->value.data, "localhost:1337") == 0);

    ASSERT(strcmp(req->headers.items[1]->field.data, "user-agent") == 0);
    ASSERT(strcmp(req->headers.items[1]->value.data, "libio 0.0") == 0);

    ASSERT(strcmp(req->headers.items[2]->field.data, "accept") == 0);
    ASSERT(strcmp(req->headers.items[2]->value.data, "*/*") == 0);

    ASSERT(strcmp(req->headers.items[3]->field.data, "content-type") == 0);
    ASSERT(strcmp(req->headers.items[3]->value.data, "text/plain") == 0);

    ASSERT(strcmp(req->headers.items[4]->field.data, "content-length") == 0);
    ASSERT(strcmp(req->headers.items[4]->value.data, "13") == 0);

    ASSERT(strcmp(req->headers.items[5]->field.data, "authorization") == 0);
    ASSERT(strcmp(req->headers.items[5]->value.data, "Basic Zm9vOmJhcg==") == 0);

    ASSERT(strcmp(req->headers.items[6]->field.data, "x-foobar") == 0);
    ASSERT(strcmp(req->headers.items[6]->value.data, "baz") == 0);

    ASSERT(strcmp(req->user.data, "foo") == 0);
    ASSERT(strcmp(req->pass.data, "bar") == 0);

    ASSERT(strcmp(req->body.data, "request body\n") == 0);
  }

  http_res_header(res, "X-Test", "value");
  http_res_send(res, 200, "text/plain", "Hello world\n");

  g_sent++;

  return 1;
}

static void
send_request1(btc_mutex_t *lock) {
  http_msg_t *msg = http_get("localhost", 1337, "/", BTC_AF_INET);

  ASSERT(msg != NULL);
  ASSERT(msg->status == 200);
  ASSERT(msg->headers.length == 5);

  ASSERT(strcmp(msg->headers.items[0]->field.data, "date") == 0);

  ASSERT(strcmp(msg->headers.items[1]->field.data, "content-type") == 0);
  ASSERT(strcmp(msg->headers.items[1]->value.data, "text/plain") == 0);

  ASSERT(strcmp(msg->headers.items[2]->field.data, "content-length") == 0);
  ASSERT(strcmp(msg->headers.items[2]->value.data, "12") == 0);

  ASSERT(strcmp(msg->headers.items[3]->field.data, "connection") == 0);
  ASSERT(strcmp(msg->headers.items[3]->value.data, "keep-alive") == 0);

  ASSERT(strcmp(msg->headers.items[4]->field.data, "x-test") == 0);
  ASSERT(strcmp(msg->headers.items[4]->value.data, "value") == 0);

  ASSERT(strcmp(msg->body.data, "Hello world\n") == 0);

  http_msg_destroy(msg);

  inc_recv(lock);
}

static void
send_request2(btc_mutex_t *lock) {
  http_client_t *client = http_client_create();
  http_options_t options;
  http_msg_t *msg = NULL;

  ASSERT(http_client_open(client, "localhost", 1337, BTC_AF_INET));

  http_options_init(&options);

  options.method = HTTP_METHOD_POST;
  options.path = "/post";
  options.type = "text/plain";
  options.user = "foo";
  options.pass = "bar";
  options.body = "request body\n";

  http_options_header(&options, "X-Foobar", "baz");

  msg = http_client_request(client, &options);

  http_options_clear(&options);

  http_client_close(client);
  http_client_destroy(client);

  ASSERT(msg != NULL);
  ASSERT(msg->status == 200);
  ASSERT(msg->headers.length == 5);

  ASSERT(strcmp(msg->headers.items[0]->field.data, "date") == 0);

  ASSERT(strcmp(msg->headers.items[1]->field.data, "content-type") == 0);
  ASSERT(strcmp(msg->headers.items[1]->value.data, "text/plain") == 0);

  ASSERT(strcmp(msg->headers.items[2]->field.data, "content-length") == 0);
  ASSERT(strcmp(msg->headers.items[2]->value.data, "12") == 0);

  ASSERT(strcmp(msg->headers.items[3]->field.data, "connection") == 0);
  ASSERT(strcmp(msg->headers.items[3]->value.data, "keep-alive") == 0);

  ASSERT(strcmp(msg->headers.items[4]->field.data, "x-test") == 0);
  ASSERT(strcmp(msg->headers.items[4]->value.data, "value") == 0);

  ASSERT(strcmp(msg->body.data, "Hello world\n") == 0);

  http_msg_destroy(msg);

  inc_recv(lock);
}

static void
send_requests(void *lock) {
  send_request1(lock);
  send_request2(lock);
}

int main(void) {
  http_server_t *server;
  btc_sockaddr_t addr;
  btc_thread_t thread;
  btc_mutex_t lock;
  btc_loop_t *loop;
  int64_t start;

  btc_mutex_init(&lock);

  btc_net_startup();

  ASSERT(btc_sockaddr_import(&addr, "127.0.0.1", 1337));

  loop = btc_loop_create();
  server = http_server_create(loop);
  server->on_request = on_request;

  ASSERT(http_server_listen(server, &addr));

  btc_thread_create(&thread, send_requests, &lock);

  start = btc_time_msec();

  while (get_recv(&lock) < 2) {
    ASSERT(btc_time_msec() < start + 10 * 1000);

    btc_loop_poll(loop, 1000);
  }

  btc_thread_join(&thread);
  btc_mutex_destroy(&lock);

  http_server_close(server);

  btc_loop_close(loop);

  http_server_destroy(server);

  btc_loop_destroy(loop);

  ASSERT(g_sent == 2);
  ASSERT(g_recv == 2);

  btc_net_cleanup();

  return 0;
}

#else /* !_WIN32 && !BTC_HAVE_PTHREAD */

int main(void) {
  return 0;
}

#endif /* !_WIN32 && !BTC_HAVE_PTHREAD */
