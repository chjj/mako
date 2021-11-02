/*!
 * client.c - rpc client for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <client/client.h>
#include <io/http.h>
#include <satoshi/json.h>

#include "../internal.h"

/*
 * Client
 */

struct btc_client_s {
  http_client_t *http;
};

static void
btc_client_init(btc_client_t *client) {
  client->http = http_client_create();
}

static void
btc_client_clear(btc_client_t *client) {
  http_client_destroy(client->http);
}

btc_client_t *
btc_client_create(void) {
  btc_client_t *client = btc_malloc(sizeof(btc_client_t));
  btc_client_init(client);
  return client;
}

void
btc_client_destroy(btc_client_t *client) {
  btc_client_clear(client);
  btc_free(client);
}

int
btc_client_open(btc_client_t *client, const char *hostname, int port) {
  return http_client_open(client->http, hostname, port);
}

void
btc_client_close(btc_client_t *client) {
  http_client_close(client->http);
}

json_value *
btc_client_call(btc_client_t *client, const char *method, json_value *params) {
  json_value *error, *code, *message, *result;
  json_value *obj = json_object_new(3);
  http_options_t options;
  http_msg_t *msg;
  char *body;

  if (params == NULL)
    params = json_array_new(0);

  json_object_push(obj, "method", json_string_new(method));
  json_object_push(obj, "params", params);
  json_object_push(obj, "id", json_integer_new(0));

  body = json_encode(obj);

  json_builder_free(obj);

  http_options_init(&options);

  options.method = HTTP_METHOD_POST;
  options.path = "/";
  options.headers = NULL;
  options.agent = "libsatoshi";
  options.accept = "application/json";
  options.type = "application/json";
  options.body = body;

  msg = http_client_request(client->http, &options);

  btc_free(body);

  if (msg == NULL) {
    fprintf(stderr, "Error while receiving/parsing HTTP response.\n");
    return NULL;
  }

  if (msg->status != 200) {
    fprintf(stderr, "HTTP Server responded with %u.\n", msg->status);
    http_msg_destroy(msg);
    return NULL;
  }

  obj = json_decode(msg->body.data, msg->body.length);

  http_msg_destroy(msg);

  if (obj == NULL || obj->type != json_object)
    goto fail;

  error = json_object_get(obj, "error");

  if (error != NULL && error->type != json_null) {
    if (error->type != json_object)
      goto fail;

    message = json_object_get(error, "message");

    if (message == NULL || message->type != json_string)
      goto fail;

    code = json_object_get(error, "code");

    if (code == NULL || code->type != json_integer)
      goto fail;

    fprintf(stderr, "JSON RPC call failed with %d (%s).\n",
                    (int)code->u.integer, message->u.string.ptr);

    json_builder_free(obj);

    return NULL;
  }

  result = json_object_remove(obj, "result");

  json_builder_free(obj);

  if (result == NULL)
    result = json_null_new();

  return result;
fail:
  fprintf(stderr, "Could not parse JSON.\n");
  if (obj != NULL)
    json_builder_free(obj);
  return NULL;
}
