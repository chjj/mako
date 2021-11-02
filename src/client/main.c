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
#include <satoshi/json.h>

#include "../internal.h"

/*
 * Constants
 */

#define MAX_PARAMS 8

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
  json_type schema[MAX_PARAMS];
} rpc_methods[] = {
  { "getinfo", { json_none } },
  { "sendtoaddress", { json_string, json_amount } }
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
 * Argument Parsing
 */

typedef struct args_s {
  const char *config;
  const char *prefix;
  const char *hostname;
  unsigned short port;
  const char *user;
  const char *pass;
  const char *method;
  const char *params[MAX_PARAMS];
  size_t length;
} args_t;

static int
arg_match(const char **zp, const char *xp, const char *yp) {
  while (*xp && *xp == *yp) {
    xp++;
    yp++;
  }

  if (*yp)
    return 0;

  *zp = xp;

  return 1;
}

static int
args_init(args_t *args, char **argv, size_t argc) {
  size_t i;

  args->config = NULL;
  args->prefix = NULL;
  args->hostname = "127.0.0.1";
  args->port = 8332;
  args->user = NULL;
  args->pass = NULL;
  args->method = NULL;
  args->length = 0;

  for (i = 1; i < argc; i++) {
    const char *arg = argv[i];
    const char *val;

    if (arg_match(&args->config, arg, "-conf="))
      continue;

    if (arg_match(&args->prefix, arg, "-datadir="))
      continue;

    if (arg_match(&args->hostname, arg, "-rpcconnect="))
      continue;

    if (arg_match(&val, arg, "-rpcport=")) {
      if (sscanf(val, "%hu", &args->port) != 1)
        return 0;
      continue;
    }

    if (arg_match(&args->user, arg, "-rpcuser="))
      continue;

    if (arg_match(&args->pass, arg, "-rpcpassword="))
      continue;

    if (arg_match(&val, arg, "-chain=")) {
      if (strcmp(val, "mainnet") == 0 || strcmp(val, "main") == 0)
        args->port = 8332;
      else if (strcmp(val, "testnet") == 0 || strcmp(val, "test") == 0)
        args->port = 18332;
      else if (strcmp(val, "regtest") == 0)
        args->port = 48332;
      else if (strcmp(val, "simnet") == 0)
        args->port = 18556;
      else
        return 0;

      continue;
    }

    if (strcmp(arg, "-testnet") == 0) {
      args->port = 8332;
      continue;
    }

    if (strcmp(arg, "-version") == 0) {
      puts("0.0.0");
      exit(0);
      return 0;
    }

    if (args->method == NULL) {
      args->method = arg;
      continue;
    }

    if (args->length == MAX_PARAMS)
      return 0;

    args->params[args->length++] = arg;
  }

  if (args->method == NULL)
    return 0;

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
  args_t args;
  int ret = 1;
  size_t i;

  if (!args_init(&args, argv, argc)) {
    fprintf(stderr, "Invalid arguments.\n");
    return 1;
  }

  schema = find_schema(args.method);

  if (schema == NULL) {
    fprintf(stderr, "RPC method '%s' not found.\n", args.method);
    return 1;
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
        case json_boolean:
        case json_null:
          if (obj->type == type)
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

  client = btc_client_create();

  if (!btc_client_open(client, args.hostname, args.port)) {
    fprintf(stderr, "Could not connect to %s:%d.\n",
                    args.hostname, args.port);
    goto fail;
  }

  result = btc_client_call(client, args.method, params);
  params = NULL;

  btc_client_close(client);

  if (result == NULL)
    goto fail;

  json_print_ex(result, puts, json_options);
  json_builder_free(result);

  ret = 0;
fail:
  if (params != NULL)
    json_builder_free(params);

  if (client != NULL)
    btc_client_destroy(client);

  return ret;
}
