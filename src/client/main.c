/*!
 * main.c - cli interface for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <client/client.h>

#include <io/core.h>

#include <satoshi/config.h>
#include <satoshi/json.h>

#include "../internal.h"

/*
 * Constants
 */

static const json_serialize_opts json_options = {
  json_serialize_mode_multiline,
  json_serialize_opt_pack_brackets,
  2
};

/*
 * Methods
 */

static const struct {
  const char *method;
  json_type schema[8];
} rpc_methods[] = {
  { "generate", { json_integer } },
  { "generatetoaddress", { json_integer, json_string } },
  { "getgenerate", { json_none } },
  { "getinfo", { json_none } },
  { "sendtoaddress", { json_string, json_amount } },
  { "setgenerate", { json_boolean, json_integer } }
};

static const json_type *
find_schema(const char *method) {
  int end = lengthof(rpc_methods) - 1;
  int start = 0;
  int pos, cmp;

  while (start <= end) {
    pos = (start + end) >> 1;
    cmp = strcmp(rpc_methods[pos].method, method);

    if (cmp == 0)
      return rpc_methods[pos].schema;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  return NULL;
}

/*
 * Config
 */

static int
get_config(btc_conf_t *args, int argc, char **argv) {
  char prefix[BTC_PATH_MAX];

  if (!btc_sys_datadir(prefix, sizeof(prefix), "satoshi")) {
    fprintf(stderr, "Could not find suitable datadir.\n");
    return 0;
  }

  btc_conf_init(args, argc, argv, prefix, 1);

  return 1;
}

/*
 * Main
 */

int
main(int argc, char **argv) {
  btc_client_t *client = NULL;
  json_value *params = NULL;
  const json_type *schema;
  json_value *result;
  btc_conf_t args;
  int ret = EXIT_FAILURE;
  size_t i;

  if (!get_config(&args, argc, argv))
    return EXIT_FAILURE;

  if (args.help) {
    puts("Usage: satoshi [options] <command> [params]");
    return EXIT_SUCCESS;
  }

  if (args.version) {
    puts("0.0.0");
    return EXIT_SUCCESS;
  }

  if (args.method == NULL) {
    fprintf(stderr, "Must specify a command.\n");
    return EXIT_FAILURE;
  }

  schema = find_schema(args.method);

  if (schema == NULL) {
    fprintf(stderr, "RPC method '%s' not found.\n", args.method);
    return EXIT_FAILURE;
  }

  params = json_array_new(args.length);

  for (i = 0; i < args.length; i++) {
    const char *param = args.params[i];
    json_type type = schema[i];
    json_value *obj;

    if (type == json_none) {
      fprintf(stderr, "Too many arguments for %s.\n", args.method);
      goto fail;
    }

    if (type == json_string || type == json_amount) {
      json_array_push(params, json_string_new(param));
      continue;
    }

    obj = json_decode(param, strlen(param));

    if (obj != NULL) {
      json_array_push(params, obj);

      switch (type) {
        case json_object:
        case json_array:
        case json_integer:
        case json_null:
          if (obj->type == type)
            continue;
          break;
        case json_boolean:
          if (obj->type == json_integer || obj->type == json_boolean)
            continue;
          break;
        case json_double:
          if (obj->type == json_integer || obj->type == json_double)
            continue;
          break;
        default:
          break;
      }
    }

    fprintf(stderr, "Invalid arguments.\n");

    goto fail;
  }

  btc_net_startup();

  client = btc_client_create();

  if (!btc_client_open(client, args.rpc_connect, args.rpc_port, 0)) {
    fprintf(stderr, "Could not connect to %s:%d.\n",
                    args.rpc_connect, args.rpc_port);
    goto fail;
  }

  result = btc_client_call(client, args.method, params);
  params = NULL;

  btc_client_close(client);

  if (result == NULL)
    goto fail;

  json_print_ex(result, puts, json_options);
  json_builder_free(result);

  ret = EXIT_SUCCESS;
fail:
  if (params != NULL)
    json_builder_free(params);

  if (client != NULL)
    btc_client_destroy(client);

  btc_net_cleanup();

  return ret;
}
