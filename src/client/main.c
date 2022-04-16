/*!
 * main.c - cli interface for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <client/client.h>

#include <io/core.h>

#include <base/config.h>
#include <mako/json.h>
#include <mako/util.h>

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
 * Arguments
 */

static const char *rpc_args[] = {
  "-?",
  "-chain=",
  "-conf=",
  "-datadir=",
  "-rpcconnect=",
  "-rpcpassword=",
  "-rpcport=",
  "-rpcuser=",
  "-testnet",
  "-version"
};

/*
 * Methods
 */

static const struct {
  const char *method;
  json_type schema[8];
} rpc_methods[] = {
  { "abandontransaction", { json_string } },
  { "addnode", { json_string, json_string } },
  { "backupwallet", { json_string } },
  { "bumpfee", { json_string, json_object } },
  { "clearbanned", { json_none } },
  { "createaccount", { json_string, json_integer } },
  { "createrawtransaction", { json_array, json_array,
                              json_integer, json_boolean } },
  { "decoderawtransaction", { json_string, json_boolean } },
  { "decodescript", { json_string } },
  { "deleteaccount", { json_string } },
  { "disconnectnode", { json_string, json_integer } },
  { "dumpprivkey", { json_string } },
  { "dumpwallet", { json_none } },
  { "encryptwallet", { json_string } },
  { "estimatesmartfee", { json_integer, json_string } },
  { "fundhwtransaction", { json_string, json_array,
                           json_integer, json_boolean } },
  { "fundrawtransaction", { json_string, json_string,
                            json_integer, json_boolean } },
  { "generate", { json_integer } },
  { "generateblock", { json_string, json_array } },
  { "generatetoaddress", { json_integer, json_string } },
  { "getaccount", { json_string } },
  { "getaccountaddress", { json_string } },
  { "getaccountinfo", { json_string } },
  { "getaddednodeinfo", { json_string } },
  { "getaddressesbyaccount", { json_string, json_integer, json_string } },
  { "getaddressinfo", { json_string } },
  { "getbalance", { json_string, json_boolean } },
  { "getbalances", { json_string } },
  { "getbestblockhash", { json_none } },
  { "getblock", { json_null, json_integer } },
  { "getblockchaininfo", { json_none } },
  { "getblockcount", { json_none } },
  { "getblockhash", { json_integer } },
  { "getblockheader", { json_null, json_boolean } },
  { "getblocktemplate", { json_object } },
  { "getchaintips", { json_none } },
  { "getconnectioncount", { json_none } },
  { "getdifficulty", { json_none } },
  { "getgenerate", { json_none } },
  { "getmemoryinfo", { json_string } },
  { "getmempoolentry", { json_string } },
  { "getmempoolinfo", { json_none } },
  { "getmininginfo", { json_none } },
  { "getnettotals", { json_none } },
  { "getnetworkhashps", { json_integer, json_integer } },
  { "getnetworkinfo", { json_none } },
  { "getnewaddress", { json_string } },
  { "getnodeaddresses", { json_integer } },
  { "getpeerinfo", { json_none } },
  { "getrawchangeaddress", { json_string } },
  { "getrawmempool", { json_boolean, json_boolean } },
  { "getrawtransaction", { json_string, json_integer } },
  { "gettransaction", { json_string } },
  { "gettxout", { json_string, json_integer, json_boolean } },
  { "gettxoutsetinfo", { json_none } },
  { "getwalletinfo", { json_none } },
  { "getwork", { json_string } },
  { "help", { json_string } },
  { "listaccounts", { json_boolean, json_integer, json_string } },
  { "listbanned", { json_none } },
  { "listlockunspent", { json_none } },
  { "listsinceblock", { json_string, json_null, json_integer } },
  { "listtransactions", { json_string, json_integer, json_integer } },
  { "listunspent", { json_string, json_integer, json_object } },
  { "lockunspent", { json_boolean, json_array } },
  { "ping", { json_none } },
  { "prioritisetransaction", { json_string, json_amount } },
  { "pruneblockchain", { json_integer } },
  { "renameaccount", { json_string, json_string } },
  { "rescanblockchain", { json_integer } },
  { "resendwallettransactions", { json_none } },
  { "savemempool", { json_none } },
  { "send", { json_array, json_object } },
  { "sendfrom", { json_string, json_string, json_amount,
                               json_integer, json_boolean } },
  { "sendmany", { json_string, json_object, json_integer, json_boolean } },
  { "sendrawtransaction", { json_string } },
  { "sendtoaddress", { json_string, json_amount, json_integer, json_boolean } },
  { "setban", { json_string, json_string, json_integer, json_boolean } },
  { "setgenerate", { json_boolean, json_integer } },
  { "setloglevel", { json_string } },
  { "setnetworkactive", { json_boolean } },
  { "settxfee", { json_amount } },
  { "signmessage", { json_string, json_string } },
  { "signmessagewithprivkey", { json_string, json_string } },
  { "signrawtransactionwithkey", { json_string, json_array, json_array } },
  { "signrawtransactionwithwallet", { json_string } },
  { "stop", { json_none } },
  { "submitblock", { json_string } },
  { "testmempoolaccept", { json_array, json_amount } },
  { "uptime", { json_none } },
  { "validateaddress", { json_string } },
  { "verifychain", { json_integer, json_integer } },
  { "verifymessage", { json_string, json_string, json_string } },
  { "walletlock", { json_none } },
  { "walletpassphrase", { json_string, json_integer } },
  { "walletpassphrasechange", { json_string, json_string } },
  { "watchaccount", { json_string, json_string } }
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

static btc_conf_t *
get_config(int argc, char **argv) {
  char prefix[BTC_PATH_MAX];

  if (!btc_sys_datadir(prefix, sizeof(prefix), "mako")) {
    fprintf(stderr, "Could not find suitable datadir.\n");
    return NULL;
  }

  return btc_conf_create(argc, argv, prefix, 1);
}

/*
 * Main
 */

static int
btc_main(const btc_conf_t *conf) {
  btc_client_t *client = NULL;
  json_value *params = NULL;
  const json_type *schema;
  json_value *result;
  int ret = 0;
  size_t i;

  if (conf->help) {
    puts("Usage: mako [options] <command> [params]");
    return 1;
  }

  if (conf->version) {
    puts("0.0.0");
    return 1;
  }

  if (conf->method == NULL) {
    fprintf(stderr, "Must specify a command.\n");
    return 0;
  }

  schema = find_schema(conf->method);

  if (schema == NULL) {
    fprintf(stderr, "RPC method '%s' not found.\n", conf->method);
    return 0;
  }

  btc_net_startup();

  params = json_array_new(conf->length);

  for (i = 0; i < conf->length; i++) {
    const char *param = conf->params[i];
    json_type type = schema[i];
    json_value *obj;

    if (type == json_none) {
      fprintf(stderr, "Too many arguments for %s.\n", conf->method);
      goto fail;
    }

    if (type == json_string) {
      json_array_push(params, json_string_new(param));
      continue;
    }

    obj = json_decode(param, strlen(param));

    /* json_null = string or integer */
    if (type == json_null && obj == NULL) {
      json_array_push(params, json_string_new(param));
      continue;
    }

    if (obj != NULL) {
      json_array_push(params, obj);

      switch (type) {
        case json_none:
          break;
        case json_object:
        case json_array:
        case json_integer:
          if (obj->type == type)
            continue;
          break;
        case json_amount:
          if (obj->type == json_amount || obj->type == json_integer)
            continue;
          break;
        case json_double:
          if (obj->type == json_double
              || obj->type == json_integer
              || obj->type == json_amount) {
            continue;
          }
          break;
        case json_string:
          break;
        case json_boolean:
          if (obj->type == json_boolean || obj->type == json_integer)
            continue;
          break;
        case json_null:
          /* json_null = string or integer */
          if (obj->type == json_integer)
            continue;
          break;
      }
    }

    fprintf(stderr, "Invalid arguments.\n");

    goto fail;
  }

  client = btc_client_create();

  btc_client_auth(client, conf->rpc_user, conf->rpc_pass);

  if (!btc_client_open(client, conf->rpc_connect, conf->rpc_port, 0)) {
    fprintf(stderr, "Could not connect to %s (port=%d).\n",
                    conf->rpc_connect, conf->rpc_port);
    goto fail;
  }

  result = btc_client_call(client, conf->method, params);
  params = NULL;

  btc_client_close(client);

  if (result == NULL)
    goto fail;

  if (result->type == json_string)
    puts(result->u.string.ptr);
  else
    json_print_ex(result, puts, json_options);

  json_builder_free(result);

  ret = 1;
fail:
  if (params != NULL)
    json_builder_free(params);

  if (client != NULL)
    btc_client_destroy(client);

  btc_net_cleanup();

  return ret;
}

int
main(int argc, char **argv) {
  btc_conf_t *conf;
  int ok;

  if (argc > 1 && strcmp(argv[1], "_complete") == 0) {
    const char *word = argc > 2 ? argv[argc - 1] : "";
    size_t i;

    if (word[0] == '-') {
      for (i = 0; i < lengthof(rpc_args); i++) {
        if (btc_starts_with(rpc_args[i], word))
          puts(rpc_args[i]);
      }
    } else {
      for (i = 0; i < lengthof(rpc_methods); i++) {
        const char *method = rpc_methods[i].method;

        if (btc_starts_with(method, word))
          puts(method);
      }
    }

    return EXIT_SUCCESS;
  }

  conf = get_config(argc, argv);

  if (conf == NULL)
    return EXIT_FAILURE;

  ok = btc_main(conf);

  btc_conf_destroy(conf);

  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
