/*!
 * client.c - rpc client for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <client/client.h>
#include <io/http.h>
#include <mako/json.h>

#include "../internal.h"

/*
 * Client
 */

struct btc_client_s {
  http_client_t *http;
  uint32_t id;
  char user[256];
  char pass[256];
};

static void
btc_client_init(btc_client_t *client) {
  client->http = http_client_create();
  client->id = 0;
  client->user[0] = '\0';
  client->pass[0] = '\0';
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
btc_client_open(btc_client_t *client,
                const char *hostname,
                int port,
                int family) {
  return http_client_open(client->http, hostname, port, family);
}

void
btc_client_close(btc_client_t *client) {
  http_client_close(client->http);
}

void
btc_client_auth(btc_client_t *client, const char *user, const char *pass) {
  if (pass != NULL && *pass != '\0') {
    size_t userlen = strlen(user);
    size_t passlen = strlen(pass);

    CHECK(userlen + 1 <= sizeof(client->user));
    CHECK(passlen + 1 <= sizeof(client->pass));

    memcpy(client->user, user, userlen + 1);
    memcpy(client->pass, pass, passlen + 1);
  } else {
    client->user[0] = '\0';
    client->pass[0] = '\0';
  }
}

json_value *
btc_client_call(btc_client_t *client, const char *method, json_value *params) {
  json_value *id, *error, *code, *message, *result;
  json_value *obj = json_object_new(3);
  uint32_t num = client->id++;
  http_options_t options;
  http_msg_t *msg;
  char *body;

  if (params == NULL)
    params = json_array_new(0);

  json_object_push(obj, "method", json_string_new(method));
  json_object_push(obj, "params", params);
  json_object_push(obj, "id", json_integer_new(num));

  body = json_encode(obj);

  json_builder_free(obj);

  http_options_init(&options);

  options.method = HTTP_METHOD_POST;
  options.path = "/";
  options.headers = NULL;
  options.agent = "mako";
  options.accept = "application/json";
  options.type = "application/json";
  options.body = body;

  if (*client->pass) {
    options.user = client->user;
    options.pass = client->pass;
  }

  msg = http_client_request(client->http, &options);

  btc_free(body);

  if (msg == NULL) {
    fprintf(stderr, "Error: %s\n", http_client_strerror(client->http));
    return NULL;
  }

  if (msg->status != 200) {
    if (msg->status == 401)
      fprintf(stderr, "Invalid RPC credentials.\n");
    else
      fprintf(stderr, "HTTP Error (status=%u).\n", msg->status);

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

    code = json_object_get(error, "code");

    if (code == NULL || code->type != json_integer)
      goto fail;

    message = json_object_get(error, "message");

    if (message == NULL || message->type != json_string)
      goto fail;

    if (strcmp(method, "help") == 0 && code->u.integer == -1) {
      fprintf(stderr, "Usage: %s\n", message->u.string.ptr);
    } else {
      fprintf(stderr, "RPC Error: %s (code=%d).\n",
                      message->u.string.ptr,
                      (int)code->u.integer);
    }

    json_builder_free(obj);

    return NULL;
  }

  id = json_object_get(obj, "id");

  if (id == NULL || id->type != json_integer)
    goto fail;

  if (id->u.integer != (json_int_t)num)
    goto fail;

  result = json_object_pluck(obj, "result");

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
