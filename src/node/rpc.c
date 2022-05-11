/*!
 * rpc.c - rpc for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <io/core.h>
#include <io/http.h>
#include <io/loop.h>

#include <base/addrman.h>
#include <node/chain.h>
#include <base/logger.h>
#include <node/mempool.h>
#include <node/miner.h>
#include <node/node.h>
#include <node/pool.h>
#include <node/rpc.h>
#include <base/timedata.h>

#include <mako/crypto/ecc.h>
#include <mako/crypto/hash.h>

#include <mako/address.h>
#include <mako/bip32.h>
#include <mako/bip39.h>
#include <mako/block.h>
#include <mako/coins.h>
#include <mako/consensus.h>
#include <mako/crypto/hash.h>
#include <mako/encoding.h>
#include <mako/entry.h>
#include <mako/header.h>
#include <mako/json.h>
#include <mako/map.h>
#include <mako/net.h>
#include <mako/netaddr.h>
#include <mako/netmsg.h>
#include <mako/network.h>
#include <mako/script.h>
#include <mako/tx.h>
#include <mako/util.h>
#include <mako/vector.h>

#include <wallet/iterator.h>
#include <wallet/wallet.h>

#include "../internal.h"

/*
 * Constants
 */

enum rpc_error {
  /* Standard JSON-RPC 2.0 errors */
  RPC_INVALID_REQUEST = -32600,
  RPC_METHOD_NOT_FOUND = -32601,
  RPC_INVALID_PARAMS = -32602,
  RPC_INTERNAL_ERROR = -32603,
  RPC_PARSE_ERROR = -32700,

  /* General application defined errors */
  RPC_MISC_ERROR = -1,
  RPC_FORBIDDEN_BY_SAFE_MODE = -2,
  RPC_TYPE_ERROR = -3,
  RPC_INVALID_ADDRESS_OR_KEY = -5,
  RPC_OUT_OF_MEMORY = -7,
  RPC_INVALID_PARAMETER = -8,
  RPC_DATABASE_ERROR = -20,
  RPC_DESERIALIZATION_ERROR = -22,
  RPC_VERIFY_ERROR = -25,
  RPC_VERIFY_REJECTED = -26,
  RPC_VERIFY_ALREADY_IN_CHAIN = -27,
  RPC_IN_WARMUP = -28,

  /* P2P client errors */
  RPC_CLIENT_NOT_CONNECTED = -9,
  RPC_CLIENT_IN_INITIAL_DOWNLOAD = -10,
  RPC_CLIENT_NODE_ALREADY_ADDED = -23,
  RPC_CLIENT_NODE_NOT_ADDED = -24,
  RPC_CLIENT_NODE_NOT_CONNECTED = -29,
  RPC_CLIENT_INVALID_IP_OR_SUBNET = -30,
  RPC_CLIENT_P2P_DISABLED = -31,

  /* Wallet errors */
  RPC_WALLET_ERROR = -4,
  RPC_WALLET_INSUFFICIENT_FUNDS = -6,
  RPC_WALLET_INVALID_ACCOUNT_NAME = -11,
  RPC_WALLET_KEYPOOL_RAN_OUT = -12,
  RPC_WALLET_UNLOCK_NEEDED = -13,
  RPC_WALLET_PASSPHRASE_INCORRECT = -14,
  RPC_WALLET_WRONG_ENC_STATE = -15,
  RPC_WALLET_ENCRYPTION_FAILED = -16,
  RPC_WALLET_ALREADY_UNLOCKED = -17
};

/*
 * Types
 */

typedef struct {
  unsigned int length;
  json_value **values;
  int help;
} json_params;

/*
 * HTTP Helpers
 */

static void
http_res_send_json(http_res_t *res, json_value *value) {
  char *body = json_encode(value);
  size_t length = strlen(body);

  body[length++] = '\n';

  http_res_send_data(res, 200, "application/json", body, length);
}

/*
 * Hash Helpers
 */

static void
btc_hash_auth(uint8_t *hash, const char *user, const char *pass) {
  btc_hmac256_t ctx;
  btc_hmac256_init(&ctx, (const uint8_t *)user, strlen(user));
  btc_hmac256_update(&ctx, (const uint8_t *)pass, strlen(pass));
  btc_hmac256_final(&ctx, hash);
}

/*
 * RPC Request
 */

typedef struct rpc_req_s {
  const char *method;
  const json_value *params;
  const json_value *id;
} rpc_req_t;

static void
rpc_req_init(rpc_req_t *req) {
  req->method = "";
  req->params = NULL;
  req->id = NULL;
}

static int
rpc_req_set(rpc_req_t *req, const json_value *obj) {
  const json_value *id, *method, *params;

  if (obj == NULL || obj->type != json_object)
    return 0;

  id = json_object_get(obj, "id");

  if (id != NULL
      && id->type != json_null
      && id->type != json_integer
      && id->type != json_string) {
    return 0;
  }

  req->id = id;

  method = json_object_get(obj, "method");

  if (method == NULL || method->type != json_string)
    return 0;

  req->method = method->u.string.ptr;

  params = json_object_get(obj, "params");

  if (params != NULL
      && params->type != json_null
      && params->type != json_array) {
    return 0;
  }

  req->params = params;

  return 1;
}

/*
 * RPC Response
 */

typedef struct rpc_res_s {
  json_value *result;
  json_int_t code;
  const char *msg;
} rpc_res_t;

static void
rpc_res_init(rpc_res_t *res) {
  res->result = NULL;
  res->code = 0;
  res->msg = NULL;
}

static void
rpc_res_error(rpc_res_t *res, int code, const char *msg) {
  if (res->result != NULL)
    json_builder_free(res->result);

  res->result = NULL;
  res->code = code;
  res->msg = msg;
}

static json_value *
rpc_res_encode(rpc_res_t *res, const json_value *id) {
  json_value *obj = json_object_new(3);
  json_value *err;

  if (res->result == NULL)
    res->result = json_null_new();

  if (res->code != 0) {
    err = json_object_new(2);

    if (res->msg == NULL)
      res->msg = "Error";

    json_object_push(err, "code", json_integer_new(res->code));
    json_object_push(err, "message", json_string_new(res->msg));
  } else {
    err = json_null_new();
  }

  json_object_push(obj, "result", res->result);
  json_object_push(obj, "error", err);

  if (id != NULL && id->type == json_integer)
    json_object_push(obj, "id", json_integer_new(id->u.integer));
  else if (id != NULL && id->type == json_string)
    json_object_push(obj, "id", json_string_new(id->u.string.ptr));
  else
    json_object_push(obj, "id", json_null_new());

  res->result = NULL;

  return obj;
}

/*
 * RPC
 */

struct btc_rpc_s {
  btc_node_t *node;
  const btc_network_t *network;
  btc_loop_t *loop;
  btc_logger_t *logger;
  const btc_timedata_t *timedata;
  btc_chain_t *chain;
  btc_mempool_t *mempool;
  btc_miner_t *miner;
  btc_pool_t *pool;
  btc_wallet_t *wallet;
  http_server_t *http;
  unsigned int flags;
  int port;
  btc_vector_t bind;
  uint8_t auth_hash[32];
};

BTC_DEFINE_LOGGER(btc_log, btc_rpc_t, "rpc")

static int
on_request(http_server_t *server, http_req_t *req, http_res_t *res);

btc_rpc_t *
btc_rpc_create(btc_node_t *node) {
  const btc_network_t *network = node->network;
  btc_rpc_t *rpc = btc_malloc(sizeof(btc_rpc_t));

  memset(rpc, 0, sizeof(*rpc));

  rpc->node = node;
  rpc->network = node->network;
  rpc->loop = node->loop;
  rpc->logger = node->logger;
  rpc->timedata = node->timedata;
  rpc->chain = node->chain;
  rpc->mempool = node->mempool;
  rpc->miner = node->miner;
  rpc->pool = node->pool;
  rpc->wallet = node->wallet;
  rpc->http = http_server_create(node->loop);
  rpc->flags = BTC_RPC_DEFAULT_FLAGS;
  rpc->port = network->rpc_port;

  btc_vector_init(&rpc->bind);

  rpc->http->on_request = on_request;
  rpc->http->data = rpc;

  return rpc;
}

void
btc_rpc_destroy(btc_rpc_t *rpc) {
  size_t i;

  for (i = 0; i < rpc->bind.length; i++)
    btc_free(rpc->bind.items[i]);

  btc_vector_clear(&rpc->bind);
  http_server_destroy(rpc->http);
  btc_free(rpc);
}

void
btc_rpc_set_port(btc_rpc_t *rpc, int port) {
  CHECK(port > 0 && port <= 0xffff);
  rpc->port = port;
}

void
btc_rpc_set_bind(btc_rpc_t *rpc, const btc_netaddr_t *addr) {
  btc_sockaddr_t *sa = btc_malloc(sizeof(btc_sockaddr_t));

  btc_netaddr_get_sockaddr(sa, addr);

  btc_vector_push(&rpc->bind, sa);
}

void
btc_rpc_set_credentials(btc_rpc_t *rpc, const char *user, const char *pass) {
  if (pass != NULL && *pass != '\0')
    btc_hash_auth(rpc->auth_hash, user, pass);
  else
    btc_hash_init(rpc->auth_hash);
}

static int
btc_rpc_listen(btc_rpc_t *rpc) {
  size_t i;

  if (rpc->bind.length == 0) {
    if (!http_server_listen_local(rpc->http, rpc->port)) {
      const char *msg = http_server_strerror(rpc->http);

      btc_log_error(rpc, "Could not listen on port %d: %s.", rpc->port, msg);

      http_server_close(rpc->http);

      return 0;
    }

    btc_log_info(rpc, "Listening on port %d.", rpc->port);

    return 1;
  }

  for (i = 0; i < rpc->bind.length; i++) {
    btc_sockaddr_t *addr = rpc->bind.items[i];

    if (addr->port == 0)
      addr->port = rpc->port;

    if (!http_server_listen(rpc->http, addr)) {
      const char *msg = http_server_strerror(rpc->http);

      btc_log_error(rpc, "Could not listen on %S: %s.", addr, msg);

      http_server_close(rpc->http);

      return 0;
    }

    btc_log_info(rpc, "Listening on %S.", addr);
  }

  return 1;
}

int
btc_rpc_open(btc_rpc_t *rpc, unsigned int flags) {
  rpc->flags = flags;

  btc_log_info(rpc, "Opening RPC.");

  if (!btc_rpc_listen(rpc))
    return 0;

  return 1;
}

void
btc_rpc_close(btc_rpc_t *rpc) {
  btc_log_info(rpc, "Closing RPC.");

  http_server_close(rpc->http);
}

/*
 * Macros
 */

#define THROW(code, msg) do {    \
  rpc_res_error(res, code, msg); \
  return;                        \
} while (0)

#define THROW_MISC(msg) THROW(RPC_MISC_ERROR, msg)

#define THROW_TYPE(name, type) \
  THROW(RPC_TYPE_ERROR, "`" #name "` must be a(n) " #type)

/*
 * Call Helpers
 */

static int32_t
btc_rpc_get_depth(btc_rpc_t *rpc,
                  const btc_entry_t *entry,
                  const uint8_t **next) {
  const btc_entry_t *tip = btc_chain_tip(rpc->chain);

  if (entry == tip) {
    *next = NULL;
    return 1;
  }

  if (entry->next != NULL) {
    *next = entry->next->hash;
    return tip->height - entry->height + 1;
  }

  *next = NULL;

  return -1;
}

/*
 * Blockchain
 */

static void
btc_rpc_getbestblockhash(btc_rpc_t *rpc,
                         const json_params *params,
                         rpc_res_t *res) {
  const btc_entry_t *tip = btc_chain_tip(rpc->chain);

  if (params->help || params->length != 0)
    THROW_MISC("getbestblockhash");

  res->result = json_hash_new(tip->hash);
}

static void
btc_rpc_getblock(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  const btc_entry_t *entry;
  int32_t confirmations;
  const uint8_t *next;
  int verbosity = 1;
  uint8_t hash[32];
  int height;

  if (params->help || params->length < 1 || params->length > 2)
    THROW_MISC("getblock hash ( verbosity )");

  if (params->values[0]->type == json_integer) {
    if (!json_unsigned_get(&height, params->values[0]))
      THROW(RPC_INVALID_PARAMETER, "Target block height out of range");

    entry = btc_chain_by_height(rpc->chain, height);

    if (entry == NULL)
      THROW(RPC_INVALID_PARAMETER, "Target block height after current tip");
  } else {
    if (!json_hash_get(hash, params->values[0]))
      THROW_TYPE(hash, hash_or_height);

    entry = btc_chain_by_hash(rpc->chain, hash);

    if (entry == NULL)
      THROW(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
  }

  if (params->length > 1) {
    if (!json_unsigned_get(&verbosity, params->values[1]))
      THROW_TYPE(verbosity, integer);
  }

  if (verbosity > 0) {
    btc_block_t *block = btc_chain_get_block(rpc->chain, entry);
    btc_view_t *view = NULL;

    if (block == NULL)
      THROW_MISC("Can't read block from disk");

    confirmations = btc_rpc_get_depth(rpc, entry, &next);

    if (verbosity > 2)
      view = btc_chain_get_undo(rpc->chain, entry, block);

    res->result = json_block_new_ex(block,
                                    entry,
                                    view,
                                    confirmations,
                                    next,
                                    verbosity > 1,
                                    rpc->network);

    btc_block_destroy(block);

    if (view != NULL)
      btc_view_destroy(view);
  } else {
    uint8_t *data;
    size_t length;

    if (!btc_chain_get_raw_block(rpc->chain, &data, &length, entry))
      THROW_MISC("Can't read block from disk");

    res->result = json_raw_new(data, length);

    btc_free(data);
  }
}

static void
btc_rpc_getblockchaininfo(btc_rpc_t *rpc,
                          const json_params *params,
                          rpc_res_t *res) {
  const btc_network_t *network = rpc->network;
  const btc_entry_t *tip = btc_chain_tip(rpc->chain);
  double diff, prog;
  json_value *obj;
  int64_t mtp;

  if (params->help || params->length != 0)
    THROW_MISC("getblockchaininfo");

  diff = btc_difficulty(tip->header.bits);
  prog = btc_chain_progress(rpc->chain);
  mtp = btc_entry_median_time(tip);

  obj = json_object_new(7);

  json_object_push(obj, "chain", json_string_new(network->name));
  json_object_push(obj, "blocks", json_integer_new(tip->height));
  json_object_push(obj, "bestblockhash", json_hash_new(tip->hash));
  json_object_push(obj, "difficulty", json_double_new(diff));
  json_object_push(obj, "mediantime", json_integer_new(mtp));
  json_object_push(obj, "verificationprogress", json_double_new(prog));
  json_object_push(obj, "chainwork", json_hash_new(tip->chainwork));

  res->result = obj;
}

static void
btc_rpc_getblockcount(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  const btc_entry_t *tip = btc_chain_tip(rpc->chain);

  if (params->help || params->length != 0)
    THROW_MISC("getblockcount");

  res->result = json_integer_new(tip->height);
}

static void
btc_rpc_getblockhash(btc_rpc_t *rpc,
                     const json_params *params,
                     rpc_res_t *res) {
  const btc_entry_t *entry;
  int height;

  if (params->help || params->length != 1)
    THROW_MISC("getblockhash index");

  if (!json_unsigned_get(&height, params->values[0]))
    THROW_TYPE(index, integer);

  entry = btc_chain_by_height(rpc->chain, height);

  if (entry == NULL)
    THROW(RPC_INVALID_PARAMETER, "Block height out of range");

  res->result = json_hash_new(entry->hash);
}

static void
btc_rpc_getblockheader(btc_rpc_t *rpc,
                       const json_params *params,
                       rpc_res_t *res) {
  const btc_entry_t *entry;
  int32_t confirmations;
  const uint8_t *next;
  uint8_t hash[32];
  int verbose = 1;
  int height;

  if (params->help || params->length < 1 || params->length > 2)
    THROW_MISC("getblockheader hash ( verbose )");

  if (params->values[0]->type == json_integer) {
    if (!json_unsigned_get(&height, params->values[0]))
      THROW(RPC_INVALID_PARAMETER, "Target block height out of range");

    entry = btc_chain_by_height(rpc->chain, height);

    if (entry == NULL)
      THROW(RPC_INVALID_PARAMETER, "Target block height after current tip");
  } else {
    if (!json_hash_get(hash, params->values[0]))
      THROW_TYPE(hash, hash_or_height);

    entry = btc_chain_by_hash(rpc->chain, hash);

    if (entry == NULL)
      THROW(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
  }

  if (params->length > 1) {
    if (!json_boolean_get(&verbose, params->values[1]))
      THROW_TYPE(verbose, boolean);
  }

  if (verbose) {
    confirmations = btc_rpc_get_depth(rpc, entry, &next);

    res->result = json_entry_new_ex(entry, confirmations, next);
  } else {
    res->result = json_header_raw(&entry->header);
  }
}

static void
btc_rpc_getchaintips(btc_rpc_t *rpc,
                     const json_params *params,
                     rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("getchaintips");
}

static void
btc_rpc_getdifficulty(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  const btc_entry_t *tip = btc_chain_tip(rpc->chain);
  double diff;

  if (params->help || params->length != 0)
    THROW_MISC("getdifficulty");

  diff = btc_difficulty(tip->header.bits);

  res->result = json_double_new(diff);
}

static void
btc_rpc_getmempoolentry(btc_rpc_t *rpc,
                        const json_params *params,
                        rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 1)
    THROW_MISC("getmempoolentry \"txid\"");
}

static void
btc_rpc_getmempoolinfo(btc_rpc_t *rpc,
                       const json_params *params,
                       rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("getmempoolinfo");
}

static void
btc_rpc_getrawmempool(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length > 2)
    THROW_MISC("getrawmempool ( verbose mempool_sequence )");
}

static void
btc_rpc_gettxout(btc_rpc_t *rpc,
                 const json_params *params,
                 rpc_res_t *res) {
  const btc_entry_t *tip = btc_chain_tip(rpc->chain);
  btc_coin_t *coin = NULL;
  int32_t depth = 0;
  uint8_t hash[32];
  int mempool = 1;
  json_value *obj;
  int index;

  (void)rpc;

  if (params->help || params->length < 2 || params->length > 3)
    THROW_MISC("gettxout \"txid\" n ( include_mempool )");

  if (!json_hash_get(hash, params->values[0]))
    THROW_TYPE(txid, hash);

  if (!json_unsigned_get(&index, params->values[1]))
    THROW_TYPE(n, integer);

  if (params->length > 2) {
    if (!json_boolean_get(&mempool, params->values[2]))
      THROW_TYPE(include_mempool, boolean);
  }

  if (mempool)
    coin = btc_mempool_coin(rpc->mempool, hash, index);

  if (coin == NULL)
    coin = btc_chain_coin(rpc->chain, hash, index);

  if (coin == NULL) {
    res->result = json_null_new();
    return;
  }

  if (coin->height >= 0)
    depth = tip->height - coin->height + 1;

  obj = json_object_new(6);

  json_object_push(obj, "bestblock", json_hash_new(tip->hash));
  json_object_push(obj, "confirmations", json_integer_new(depth));
  json_object_push(obj, "value", json_amount_new(coin->output.value));
  json_object_push(obj, "scriptPubKey", json_script_new(&coin->output.script,
                                                        rpc->network));
  json_object_push(obj, "version", json_integer_new(coin->version));
  json_object_push(obj, "coinbase", json_boolean_new(coin->coinbase));

  res->result = obj;

  btc_coin_destroy(coin);
}

static void
btc_rpc_gettxoutsetinfo(btc_rpc_t *rpc,
                        const json_params *params,
                        rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("gettxoutsetinfo");
}

static void
btc_rpc_pruneblockchain(btc_rpc_t *rpc,
                        const json_params *params,
                        rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 1)
    THROW_MISC("pruneblockchain height");
}

static void
btc_rpc_savemempool(btc_rpc_t *rpc,
                    const json_params *params,
                    rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("savemempool");
}

static void
btc_rpc_verifychain(btc_rpc_t *rpc,
                    const json_params *params,
                    rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length > 2)
    THROW_MISC("verifychain ( checklevel nblocks )");
}

/*
 * Control
 */

static void
btc_rpc_getmemoryinfo(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length > 1)
    THROW_MISC("getmemoryinfo ( \"mode\" )");
}

static void
btc_rpc_setloglevel(btc_rpc_t *rpc,
                    const json_params *params,
                    rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 1)
    THROW_MISC("setloglevel \"level\"");
}

static void
btc_rpc_stop(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("stop");
}

static void
btc_rpc_uptime(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("uptime");
}

/*
 * Generation
 */

static void
btc_rpc_generate(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  const btc_entry_t *tip = btc_chain_tip(rpc->chain);
  int blocks;

  if (params->help || params->length != 1)
    THROW_MISC("generate numblocks");

  if (!json_unsigned_get(&blocks, params->values[0]))
    THROW_TYPE(numblocks, integer);

  btc_miner_generate(rpc->miner, blocks, NULL);

  res->result = json_array_new(blocks);

  while (blocks--) {
    tip = tip->next;
    json_array_push(res->result, json_hash_new(tip->hash));
  }
}

static void
btc_rpc_generateblock(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 2)
    THROW_MISC("generateblock \"output\" [\"rawtx/txid\",...]");
}

static void
btc_rpc_generatetoaddress(btc_rpc_t *rpc,
                          const json_params *params,
                          rpc_res_t *res) {
  const btc_entry_t *tip = btc_chain_tip(rpc->chain);
  btc_address_t addr;
  int blocks;

  if (params->help || params->length != 2)
    THROW_MISC("generatetoaddress numblocks address");

  if (!json_unsigned_get(&blocks, params->values[0]))
    THROW_TYPE(numblocks, integer);

  if (!json_address_get(&addr, params->values[1], rpc->network))
    THROW_TYPE(address, address);

  btc_miner_generate(rpc->miner, blocks, &addr);

  res->result = json_array_new(blocks);

  while (blocks--) {
    tip = tip->next;
    json_array_push(res->result, json_hash_new(tip->hash));
  }
}

static void
btc_rpc_getgenerate(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  int mining;

  if (params->help || params->length != 0)
    THROW_MISC("getgenerate");

  mining = btc_miner_getgenerate(rpc->miner);

  res->result = json_boolean_new(mining);
}

static void
btc_rpc_setgenerate(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  int active = 1;
  int mine;

  if (params->help || params->length < 1 || params->length > 2)
    THROW_MISC("setgenerate mine ( active )");

  if (!json_boolean_get(&mine, params->values[0]))
    THROW_TYPE(mine, boolean);

  if (params->length > 1) {
    if (!json_unsigned_get(&active, params->values[1]))
      THROW_TYPE(active, integer);

    if (active == 0)
      active = 1;
  }

  btc_miner_setgenerate(rpc->miner, mine, active);

  res->result = json_boolean_new(mine);
}

/*
 * Mining
 */

static void
btc_rpc_getblocktemplate(btc_rpc_t *rpc,
                         const json_params *params,
                         rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length > 1)
    THROW_MISC("getblocktemplate ( \"template_request\" )");
}

static void
btc_rpc_getmininginfo(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("getmininginfo");
}

static void
btc_rpc_getnetworkhashps(btc_rpc_t *rpc,
                         const json_params *params,
                         rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length > 2)
    THROW_MISC("getnetworkhashps ( nblocks height )");
}

static void
btc_rpc_getwork(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length > 1)
    THROW_MISC("getwork ( \"data\" )");
}

static void
btc_rpc_prioritisetransaction(btc_rpc_t *rpc,
                              const json_params *params,
                              rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 2)
    THROW_MISC("prioritisetransaction \"txid\" fee_delta");
}

static void
btc_rpc_submitblock(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 1)
    THROW_MISC("submitblock \"hexdata\"");
}

/*
 * Network
 */

static void
btc_rpc_addnode(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 2)
    THROW_MISC("addnode \"node\" \"command\"");
}

static void
btc_rpc_clearbanned(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("clearbanned");
}

static void
btc_rpc_disconnectnode(btc_rpc_t *rpc,
                       const json_params *params,
                       rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length > 2)
    THROW_MISC("disconnectnode ( \"address\" nodeid )");
}

static void
btc_rpc_getaddednodeinfo(btc_rpc_t *rpc,
                         const json_params *params,
                         rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length > 1)
    THROW_MISC("getaddednodeinfo ( \"node\" )");
}

static void
btc_rpc_getconnectioncount(btc_rpc_t *rpc,
                           const json_params *params,
                           rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("getconnectioncount");
}

static void
btc_rpc_getnettotals(btc_rpc_t *rpc,
                     const json_params *params,
                     rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("getnettotals");
}

static void
btc_rpc_getnetworkinfo(btc_rpc_t *rpc,
                       const json_params *params,
                       rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("getnetworkinfo");
}

static void
btc_rpc_getnodeaddresses(btc_rpc_t *rpc,
                         const json_params *params,
                         rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length > 1)
    THROW_MISC("getnodeaddresses ( count )");
}

static void
btc_rpc_getpeerinfo(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("getpeerinfo");
}

static void
btc_rpc_listbanned(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("listbanned");
}

static void
btc_rpc_ping(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("ping");
}

static void
btc_rpc_setban(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length < 2 || params->length > 4)
    THROW_MISC("setban \"subnet\" \"command\" ( bantime absolute )");
}

static void
btc_rpc_setnetworkactive(btc_rpc_t *rpc,
                         const json_params *params,
                         rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 1)
    THROW_MISC("setnetworkactive state");
}

/*
 * Raw Transaction
 */

static void
btc_rpc_createrawtransaction(btc_rpc_t *rpc,
                             const json_params *params,
                             rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length < 2 || params->length > 4)
    THROW_MISC("createrawtransaction inputs outputs ( locktime replaceable )");
}

static void
btc_rpc_decoderawtransaction(btc_rpc_t *rpc,
                             const json_params *params,
                             rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length < 1 || params->length > 2)
    THROW_MISC("decoderawtransaction \"hexstring\" ( iswitness )");
}

static void
btc_rpc_decodescript(btc_rpc_t *rpc,
                     const json_params *params,
                     rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 1)
    THROW_MISC("decodescript \"hexstring\"");
}

static void
btc_rpc_fundrawtransaction(btc_rpc_t *rpc,
                           const json_params *params,
                           rpc_res_t *res) {
  btc_selopt_t options;
  const char *name;
  uint32_t account;
  btc_view_t *view;
  json_value *obj;
  int subfee = 0;
  int depth = -1;
  size_t outlen;
  btc_tx_t *tx;
  int pos = -1;
  int64_t fee;

  if (params->help || params->length < 2 || params->length > 4)
    THROW_MISC("fundrawtransaction \"account\" \"hexstr\" ( minconf subfee )");

  if (!json_string_get(&name, params->values[0]) ||
      !btc_wallet_lookup(&account, rpc->wallet, name)) {
    THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
  }

  if (params->length > 2) {
    if (!json_signed_get(&depth, params->values[2]))
      THROW_TYPE(minconf, integer);
  }

  if (params->length > 3) {
    if (!json_boolean_get(&subfee, params->values[3]))
      THROW_TYPE(subfee, boolean);
  }

  if (!json_tx_base_get(&tx, params->values[1]))
    THROW_TYPE(hexstr, transaction);

  if (tx->outputs.length == 0) {
    btc_tx_destroy(tx);
    THROW(RPC_INVALID_PARAMETER, "Must have at least one output");
  }

  btc_selopt_init(&options);

  options.depth = depth;
  options.subfee = subfee;
  options.smart = (depth != 0);

  outlen = tx->outputs.length;

  if (!btc_wallet_fund(rpc->wallet, account, &options, tx)) {
    btc_tx_destroy(tx);
    THROW(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
  }

  if (tx->outputs.length > outlen)
    pos = tx->outputs.length - 1;

  view = btc_wallet_view(rpc->wallet, tx);
  fee = btc_tx_fee(tx, view);

  obj = json_object_new(3);

  json_object_push(obj, "hex", json_tx_raw(tx));
  json_object_push(obj, "changepos", json_integer_new(pos));
  json_object_push(obj, "fee", json_amount_new(fee));

  res->result = obj;

  btc_view_destroy(view);
  btc_tx_destroy(tx);
}

static void
btc_rpc_getrawtransaction(btc_rpc_t *rpc,
                          const json_params *params,
                          rpc_res_t *res) {
  const btc_mpentry_t *entry;
  btc_view_t *view = NULL;
  int verbosity = 1;
  uint8_t hash[32];
  btc_tx_t *tx;

  if (params->help || params->length < 1 || params->length > 2)
    THROW_MISC("getrawtransaction \"txid\" ( verbosity )");

  if (!json_hash_get(hash, params->values[0]))
    THROW_TYPE(txid, hash);

  if (params->length > 1) {
    if (!json_unsigned_get(&verbosity, params->values[1]))
      THROW_TYPE(verbosity, integer);
  }

  entry = btc_mempool_get(rpc->mempool, hash);

  if (entry != NULL) {
    tx = btc_tx_ref(entry->tx);

    if (verbosity > 1)
      view = btc_mempool_view(rpc->mempool, tx);
  } else {
    if (!btc_wallet_tx(&tx, rpc->wallet, hash))
      THROW_MISC("Transaction not found");

    if (verbosity > 1)
      view = btc_wallet_undo(rpc->wallet, tx);
  }

  if (verbosity == 0)
    res->result = json_tx_raw(tx);
  else
    res->result = json_tx_new(tx, view, rpc->network);

  if (view != NULL)
    btc_view_destroy(view);

  btc_tx_destroy(tx);
}

static void
btc_rpc_sendrawtransaction(btc_rpc_t *rpc,
                           const json_params *params,
                           rpc_res_t *res) {
  btc_tx_t *tx;

  if (params->help || params->length != 1)
    THROW_MISC("sendrawtransaction \"hexstring\"");

  if (!json_tx_get(&tx, params->values[0]))
    THROW_TYPE(hexstring, transaction);

  /* XXX need call to resend invs */
  btc_mempool_add(rpc->mempool, tx, 0);

  res->result = json_hash_new(tx->hash);

  btc_tx_destroy(tx);
}

static void
btc_rpc_signrawtransactionwithkey(btc_rpc_t *rpc,
                                  const json_params *params,
                                  rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length < 2 || params->length > 3)
    THROW_MISC("signrawtransactionwithkey \"hex\" [\"key\",...] ( prevtxs )");
}

static void
btc_rpc_testmempoolaccept(btc_rpc_t *rpc,
                          const json_params *params,
                          rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length < 1 || params->length > 2)
    THROW_MISC("testmempoolaccept [\"rawtx\",...] ( maxfeerate )");
}

/*
 * Utilities
 */

static void
btc_rpc_estimatesmartfee(btc_rpc_t *rpc,
                         const json_params *params,
                         rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length < 1 || params->length > 2)
    THROW_MISC("estimatesmartfee conf_target ( \"estimate_mode\" )");
}

static void
btc_rpc_signmessagewithprivkey(btc_rpc_t *rpc,
                               const json_params *params,
                               rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 2)
    THROW_MISC("signmessagewithprivkey \"privkey\" \"message\"");
}

static void
btc_rpc_validateaddress(btc_rpc_t *rpc,
                        const json_params *params,
                        rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 1)
    THROW_MISC("validateaddress \"address\"");
}

static void
btc_rpc_verifymessage(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 3)
    THROW_MISC("verifymessage \"address\" \"signature\" \"message\"");
}

/*
 * Wallet JSON
 */

static json_value *
json_credit_new(const btc_output_t *output,
                size_t index,
                const char *name,
                const btc_network_t *network) {
  int64_t amount = -output->value;
  const char *category = "send";
  btc_address_t addr;
  size_t length = 3;
  int address = 0;
  json_value *obj;

  if (name != NULL) {
    amount = output->value;
    category = "receive";
    length += 1;
  }

  if (btc_address_set_script(&addr, &output->script)) {
    address = 1;
    length += 1;
  }

  obj = json_object_new(length);

  if (name != NULL)
    json_object_push(obj, "account", json_string_new(name));

  if (address)
    json_object_push(obj, "address", json_address_new(&addr, network));

  json_object_push(obj, "category", json_string_new(category));
  json_object_push(obj, "amount", json_amount_new(amount));
  json_object_push(obj, "vout", json_integer_new(index));

  return obj;
}

static json_value *
json_wtx_new(btc_rpc_t *rpc, const btc_txmeta_t *meta, const btc_tx_t *tx) {
  const btc_network_t *network = rpc->network;
  int is_send = (meta->resolved != 0);
  btc_wallet_t *wallet = rpc->wallet;
  json_value *details, *wtx;
  int64_t sent = 0;
  int64_t recv = 0;
  char name[64];
  size_t i;

  name[0] = '\0';

  details = json_array_new(tx->outputs.length);

  for (i = 0; i < tx->outputs.length; i++) {
    const btc_output_t *output = tx->outputs.items[i];
    btc_path_t path;
    int is_recv = 0;

    if (btc_wallet_output_path(&path, wallet, output)) {
      if (path.change)
        continue;

      is_recv = 1;
    }

    if (is_send) {
      json_array_push(details, json_credit_new(output, i, NULL, network));

      sent += output->value;
    }

    if (is_recv) {
      btc_wallet_name(name, sizeof(name), wallet, path.account);

      json_array_push(details, json_credit_new(output, i, name, network));

      recv += output->value;
    }
  }

  wtx = json_object_new(9 + (meta->height >= 0 ? 4 : 0));

  json_object_push(wtx, "amount", json_amount_new(recv - sent));

  if (meta->resolved == tx->inputs.length) {
    int64_t fee = meta->inpval - btc_tx_output_value(tx);

    json_object_push(wtx, "fee", json_amount_new(fee));
  }

  if (meta->height >= 0) {
    int32_t depth = btc_wallet_height(wallet) - meta->height + 1;

    json_object_push(wtx, "confirmations", json_integer_new(depth));
  } else {
    json_object_push(wtx, "confirmations", json_integer_new(0));
  }

  if (btc_tx_is_coinbase(tx))
    json_object_push(wtx, "generated", json_boolean_new(1));

  if (meta->height >= 0) {
    json_object_push(wtx, "blockhash", json_hash_new(meta->block));
    json_object_push(wtx, "blockheight", json_integer_new(meta->height));
    json_object_push(wtx, "blocktime", json_integer_new(meta->time));
    json_object_push(wtx, "blockindex", json_integer_new(meta->index));
  }

  json_object_push(wtx, "txid", json_hash_new(tx->hash));
  json_object_push(wtx, "time", json_integer_new(meta->mtime));
  json_object_push(wtx, "timereceived", json_integer_new(meta->mtime));
  json_object_push(wtx, "details", details);
  json_object_push(wtx, "id", json_integer_new(meta->id));

  return wtx;
}

static json_value *
json_ltx_new(btc_rpc_t *rpc, const btc_txmeta_t *meta, const btc_tx_t *tx) {
  const btc_network_t *network = rpc->network;
  int is_send = (meta->resolved != 0);
  btc_wallet_t *wallet = rpc->wallet;
  btc_address_t addr;
  json_value *wtx;
  int64_t sent = 0;
  int64_t recv = 0;
  char name[64];
  size_t i;

  btc_address_init(&addr);

  name[0] = '\0';

  for (i = 0; i < tx->outputs.length; i++) {
    const btc_output_t *output = tx->outputs.items[i];
    btc_path_t path;

    if (btc_wallet_output_path(&path, wallet, output)) {
      if (path.change)
        continue;

      if (!*name) {
        btc_wallet_name(name, sizeof(name), wallet, path.account);
        btc_address_set_script(&addr, &output->script);
      }

      recv += output->value;
    }

    if (is_send)
      sent += output->value;
  }

  wtx = json_object_new(8);

  if (*name) {
    json_object_push(wtx, "account", json_string_new(name));
    json_object_push(wtx, "address", json_address_new(&addr, network));
  }

  if (!btc_tx_is_coinbase(tx)) {
    const char *category = is_send ? "send" : "receive";

    if (is_send && *name)
      category = "both";

    json_object_push(wtx, "category", json_string_new(category));
  } else {
    json_object_push(wtx, "category", json_string_new("generate"));
  }

  json_object_push(wtx, "amount", json_amount_new(recv - sent));

  if (meta->resolved == tx->inputs.length) {
    int64_t fee = meta->inpval - btc_tx_output_value(tx);

    json_object_push(wtx, "fee", json_amount_new(fee));
  }

  if (meta->height >= 0) {
    int32_t depth = btc_wallet_height(wallet) - meta->height + 1;

    json_object_push(wtx, "confirmations", json_integer_new(depth));
  } else {
    json_object_push(wtx, "confirmations", json_integer_new(0));
  }

  json_object_push(wtx, "txid", json_hash_new(tx->hash));
  json_object_push(wtx, "id", json_integer_new(meta->id));

  return wtx;
}

static json_value *
json_wcoin_new(btc_rpc_t *rpc,
               const btc_outpoint_t *prevout,
               const btc_coin_t *coin) {
  btc_wallet_t *wallet = rpc->wallet;
  int has_account = 0;
  int spendable = 0;
  btc_address_t addr;
  btc_path_t path;
  json_value *obj;
  int depth = 0;
  char name[64];

  if (coin->height >= 0)
    depth = btc_wallet_height(wallet) - coin->height + 1;

  if (btc_address_set_script(&addr, &coin->output.script) &&
      btc_wallet_path(&path, wallet, &addr) &&
      btc_wallet_name(name, sizeof(name), wallet, path.account)) {
    has_account = 1;
  }

  if (!coin->spent && !btc_wallet_is_frozen(wallet, prevout)) {
    if (!coin->coinbase || depth > BTC_COINBASE_MATURITY)
      spendable = 1;
  }

  obj = json_object_new(8);

  json_object_push(obj, "txid", json_hash_new(prevout->hash));
  json_object_push(obj, "vout", json_integer_new(prevout->index));

  if (has_account) {
    json_object_push(obj, "account", json_string_new(name));
    json_object_push(obj, "address", json_address_new(&addr, rpc->network));
  }

  json_object_push(obj, "amount", json_amount_new(coin->output.value));
  json_object_push(obj, "confirmations", json_integer_new(depth));
  json_object_push(obj, "spendable", json_boolean_new(spendable));
  json_object_push(obj, "safe", json_boolean_new(coin->safe));

  return obj;
}

/*
 * Wallet
 */

static void
btc_rpc_abandontransaction(btc_rpc_t *rpc,
                           const json_params *params,
                           rpc_res_t *res) {
  uint8_t hash[32];

  if (params->help || params->length != 1)
    THROW_MISC("abandontransaction \"txid\"");

  if (!json_hash_get(hash, params->values[0]))
    THROW_TYPE(txid, hash);

  if (!btc_wallet_abandon(rpc->wallet, hash))
    THROW(RPC_WALLET_ERROR, "No unconfirmed transaction found");

  res->result = json_null_new();
}

static void
btc_rpc_backupwallet(btc_rpc_t *rpc,
                     const json_params *params,
                     rpc_res_t *res) {
  const char *dst;

  if (params->help || params->length != 1)
    THROW_MISC("backupwallet \"destination\"");

  if (!json_string_get(&dst, params->values[0]))
    THROW_TYPE(destination, string);

  if (!btc_wallet_backup(rpc->wallet, dst))
    THROW(RPC_WALLET_ERROR, "Could not backup wallet");

  res->result = json_null_new();
}

static void
btc_rpc_bumpfee(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length < 1 || params->length > 2)
    THROW_MISC("bumpfee \"txid\" ( options )");
}

static void
btc_rpc_createaccount(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  uint32_t account = BTC_NO_ACCOUNT;
  const char *name;
  size_t len;

  if (params->help || params->length < 1 || params->length > 2)
    THROW_MISC("createaccount \"name\" ( index )");

  if (!json_string_get(&name, params->values[0]))
    THROW_TYPE(name, string);

  if (params->length > 1) {
    if (!json_uint32_get(&account, params->values[1]))
      THROW_TYPE(index, integer);

    account &= ~BTC_BIP32_HARDEN;
  }

  len = strlen(name);

  if (len == 0 || len > 63 ||
      strcmp(name, "*") == 0 ||
      strcmp(name, ".") == 0) {
    THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
  }

  if (btc_wallet_locked(rpc->wallet))
    THROW(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");

  if (!btc_wallet_create_account(rpc->wallet, name, account))
    THROW(RPC_WALLET_ERROR, "Account already exists");

  res->result = json_boolean_new(1);
}

static void
btc_rpc_deleteaccount(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 1)
    THROW_MISC("deleteaccount \"name\"");
}

static void
btc_rpc_dumpprivkey(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  btc_address_t addr;
  uint8_t priv[32];
  btc_path_t path;

  if (params->help || params->length != 1)
    THROW_MISC("dumpprivkey \"address\"");

  if (!json_address_get(&addr, params->values[0], rpc->network))
    THROW_TYPE(address, address);

  if (!btc_wallet_path(&path, rpc->wallet, &addr))
    THROW(RPC_WALLET_ERROR, "Address not found");

  if (btc_wallet_locked(rpc->wallet))
    THROW(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");

  if (!btc_wallet_privkey(priv, rpc->wallet, &path))
    THROW(RPC_WALLET_ERROR, "Could not derive key");

  /* XXX should be WIF */
  res->result = json_raw_new(priv, sizeof(priv));

  btc_memzero(priv, sizeof(priv));
}

static void
btc_rpc_dumpwallet(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  char phrase[BTC_PHRASE_MAX + 1];
  char xprv[BTC_BIP32_STRLEN + 1];
  btc_mnemonic_t mnemonic;
  btc_hdnode_t master;

  if (params->help || params->length > 0)
    THROW_MISC("dumpwallet");

  if (!btc_wallet_master(&mnemonic, &master, rpc->wallet))
    THROW(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");

  res->result = json_object_new(2);

  if (!btc_mnemonic_is_null(&mnemonic)) {
    btc_mnemonic_get_phrase(phrase, &mnemonic);

    json_object_push(res->result, "mnemonic", json_string_new(phrase));
  }

  if (!btc_hdpriv_is_null(&master)) {
    btc_hdpriv_get_str(xprv, &master, rpc->network);

    json_object_push(res->result, "master", json_string_new(xprv));
  }

  btc_mnemonic_clear(&mnemonic);
  btc_hdpriv_clear(&master);

  btc_memzero(phrase, sizeof(phrase));
  btc_memzero(xprv, sizeof(xprv));
}

static void
btc_rpc_encryptwallet(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  const char *pass;
  size_t len;

  if (params->help || params->length != 1)
    THROW_MISC("encryptwallet \"passphrase\"");

  if (btc_wallet_encrypted(rpc->wallet))
    THROW(RPC_WALLET_WRONG_ENC_STATE, "Wallet is already encrypted");

  if (!json_string_get(&pass, params->values[0]))
    THROW_TYPE(passphrase, string);

  len = strlen(pass);

  if (len == 0)
    THROW_TYPE(passphrase, string);

  if (!btc_wallet_encrypt(rpc->wallet, pass))
    THROW(RPC_WALLET_ENCRYPTION_FAILED, "Could not encrypt wallet");

  res->result = json_string_new("wallet encrypted");

  btc_memzero((void *)pass, len);
}

static void
btc_rpc_fundhwtransaction(btc_rpc_t *rpc,
                          const json_params *params,
                          rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length < 2 || params->length > 4)
    THROW_MISC("fundhwtransaction \"account\" outputs ( minconf subfee )");
}

static void
btc_rpc_getaccount(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  btc_address_t addr;
  btc_path_t path;
  char name[64];

  if (params->help || params->length != 1)
    THROW_MISC("getaccount \"address\"");

  if (!json_address_get(&addr, params->values[0], rpc->network))
    THROW(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");

  if (!btc_wallet_path(&path, rpc->wallet, &addr)) {
    res->result = json_null_new();
    return;
  }

  if (!btc_wallet_name(name, sizeof(name), rpc->wallet, path.account))
    THROW(RPC_DATABASE_ERROR, "Database error");

  res->result = json_string_new(name);
}

static void
btc_rpc_getaccountaddress(btc_rpc_t *rpc,
                          const json_params *params,
                          rpc_res_t *res) {
  uint32_t account = BTC_NO_ACCOUNT;
  const char *name = NULL;
  btc_address_t addr;

  if (params->help || params->length > 1)
    THROW_MISC("getaccountaddress ( \"account\" )");

  if (params->length > 0) {
    if (!json_string_get(&name, params->values[0]) ||
        !btc_wallet_lookup(&account, rpc->wallet, name)) {
      THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    }
  }

  if (!btc_wallet_receive(&addr, rpc->wallet, account))
    THROW(RPC_DATABASE_ERROR, "Database error");

  res->result = json_address_new(&addr, rpc->network);
}

static void
btc_rpc_getaccountinfo(btc_rpc_t *rpc,
                       const json_params *params,
                       rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 1)
    THROW_MISC("getaccountinfo \"account\"");
}

static void
btc_rpc_getaddressesbyaccount(btc_rpc_t *rpc,
                              const json_params *params,
                              rpc_res_t *res) {
  btc_address_t after;
  btc_addriter_t *it;
  const char *name;
  uint32_t account;
  int limit = 100;
  json_value *obj;
  int i = 0;

  if (params->help || params->length < 1 || params->length > 3)
    THROW_MISC("getaddressesbyaccount \"account\" ( limit \"after\" )");

  if (!json_string_get(&name, params->values[0]) ||
      !btc_wallet_lookup(&account, rpc->wallet, name)) {
    THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
  }

  if (params->length > 1) {
    if (!json_unsigned_get(&limit, params->values[1]) || limit > 10000)
      THROW_TYPE(limit, integer);
  }

  if (params->length > 2) {
    if (!json_address_get(&after, params->values[2], rpc->network))
      THROW(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
  }

  obj = json_array_new(limit);

  it = btc_wallet_addresses(rpc->wallet);

  btc_addriter_account(it, account);

  if (params->length > 2)
    btc_addriter_seek_gt(it, &after);
  else
    btc_addriter_first(it);

  for (; btc_addriter_valid(it) && i < limit; btc_addriter_next(it), i++) {
    const btc_address_t *addr = btc_addriter_key(it);

    json_array_push(obj, json_address_new(addr, rpc->network));
  }

  btc_addriter_destroy(it);

  res->result = obj;
}

static void
btc_rpc_getaddressinfo(btc_rpc_t *rpc,
                       const json_params *params,
                       rpc_res_t *res) {
  btc_wallet_t *wallet = rpc->wallet;
  btc_program_t program;
  btc_script_t script;
  btc_address_t addr;
  btc_path_t path;
  json_value *obj;
  int is_mine = 0;
  int is_witness;
  uint8_t pub[33];
  char name[64];

  if (params->help || params->length != 1)
    THROW_MISC("getaddressinfo \"address\"");

  if (!json_address_get(&addr, params->values[0], rpc->network))
    THROW_TYPE(address, address);

  if (btc_wallet_path(&path, wallet, &addr)) {
    if (!btc_wallet_name(name, sizeof(name), wallet, path.account))
      THROW(RPC_WALLET_ERROR, "Account not found");

    if (!btc_wallet_pubkey(pub, wallet, &path))
      THROW(RPC_WALLET_ERROR, "Key not found");

    is_mine = 1;
  }

  obj = json_object_new(11);

  btc_script_init(&script);

  btc_address_get_script(&script, &addr);

  is_witness = btc_script_get_program(&program, &script);

  if (is_mine)
    json_object_push(obj, "account", json_string_new(name));

  json_object_push(obj, "address", json_address_new(&addr, rpc->network));
  json_object_push(obj, "scriptPubKey", json_buffer_new(&script));
  json_object_push(obj, "ismine", json_boolean_new(is_mine));

  if (is_mine) {
    json_object_push(obj, "iswatchonly", json_boolean_new(path.account >> 31));
    json_object_push(obj, "ischange", json_boolean_new(path.change != 0));
  } else {
    json_object_push(obj, "iswatchonly", json_boolean_new(0));
    json_object_push(obj, "ischange", json_boolean_new(0));
  }

  json_object_push(obj, "iswitness", json_boolean_new(is_witness));

  if (is_witness) {
    json_object_push(obj, "witness_version", json_integer_new(program.version));
    json_object_push(obj, "witness_program", json_raw_new(program.data,
                                                          program.length));
  }

  btc_script_clear(&script);

  if (is_mine) {
    uint32_t coin_type = rpc->network->key.coin_type;
    uint32_t purpose, account;
    char str[9 + 5 * 10 + 1];

    if (!btc_wallet_purpose(&purpose, &account, wallet, path.account))
      THROW(RPC_WALLET_ERROR, "Account not found");

    sprintf(str, "m/%u'/%u'/%u'/%u/%u", purpose,
                                        coin_type,
                                        account,
                                        path.change,
                                        path.index);

    json_object_push(obj, "pubkey", json_raw_new(pub, sizeof(pub)));
    json_object_push(obj, "hdkeypath", json_string_new(str));
  }

  res->result = obj;
}

static void
btc_rpc_getbalance(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  uint32_t account = BTC_NO_ACCOUNT;
  const char *name = NULL;
  int confirmed = 0;
  btc_balance_t bal;

  if (params->help || params->length > 2)
    THROW_MISC("getbalance ( \"account\" confirmed )");

  if (params->length > 0) {
    if (!json_string_get(&name, params->values[0]) ||
        !btc_wallet_lookup(&account, rpc->wallet, name)) {
      THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    }
  }

  if (params->length > 1) {
    if (!json_boolean_get(&confirmed, params->values[1]))
      THROW_TYPE(confirmed, boolean);
  }

  if (!btc_wallet_balance(&bal, rpc->wallet, account))
    THROW(RPC_DATABASE_ERROR, "Database error");

  if (confirmed)
    res->result = json_amount_new(bal.confirmed);
  else
    res->result = json_amount_new(bal.unconfirmed);
}

static void
btc_rpc_getbalances(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  uint32_t account = BTC_NO_ACCOUNT;
  json_value *obj, *mine, *only;
  const char *name = NULL;
  btc_balance_t bal, wat;

  if (params->help || params->length > 1)
    THROW_MISC("getbalances ( \"account\" )");

  if (params->length > 0) {
    if (!json_string_get(&name, params->values[0]) ||
        !btc_wallet_lookup(&account, rpc->wallet, name)) {
      THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    }
  }

  if (!btc_wallet_balance(&bal, rpc->wallet, account))
    THROW(RPC_DATABASE_ERROR, "Database error");

  if (!btc_wallet_watched(&wat, rpc->wallet, account))
    THROW(RPC_DATABASE_ERROR, "Database error");

  obj = json_object_new(2);
  mine = json_object_new(4);
  only = json_object_new(4);

  json_object_push(mine, "tx", json_integer_new(bal.tx));
  json_object_push(mine, "coin", json_integer_new(bal.coin));
  json_object_push(mine, "confirmed", json_amount_new(bal.confirmed));
  json_object_push(mine, "unconfirmed", json_amount_new(bal.unconfirmed));

  json_object_push(only, "tx", json_integer_new(wat.tx));
  json_object_push(only, "coin", json_integer_new(wat.coin));
  json_object_push(only, "confirmed", json_amount_new(wat.confirmed));
  json_object_push(only, "unconfirmed", json_amount_new(wat.unconfirmed));

  json_object_push(obj, "mine", mine);
  json_object_push(obj, "watchonly", only);

  res->result = obj;
}

static void
btc_rpc_getnewaddress(btc_rpc_t *rpc,
                          const json_params *params,
                          rpc_res_t *res) {
  uint32_t account = BTC_NO_ACCOUNT;
  btc_address_t addr;
  const char *name;

  if (params->help || params->length > 1)
    THROW_MISC("getnewaddress ( \"account\" )");

  if (params->length > 0) {
    if (!json_string_get(&name, params->values[0]) ||
        !btc_wallet_lookup(&account, rpc->wallet, name)) {
      THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    }
  }

  if (!btc_wallet_next(&addr, rpc->wallet, account))
    THROW(RPC_DATABASE_ERROR, "Database error");

  res->result = json_address_new(&addr, rpc->network);
}

static void
btc_rpc_getrawchangeaddress(btc_rpc_t *rpc,
                            const json_params *params,
                            rpc_res_t *res) {
  uint32_t account = BTC_NO_ACCOUNT;
  btc_address_t addr;
  const char *name;

  if (params->help || params->length > 1)
    THROW_MISC("getrawchangeaddress ( \"account\" )");

  if (params->length > 0) {
    if (!json_string_get(&name, params->values[0]) ||
        !btc_wallet_lookup(&account, rpc->wallet, name)) {
      THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    }
  }

  if (!btc_wallet_change(&addr, rpc->wallet, account))
    THROW(RPC_DATABASE_ERROR, "Database error");

  res->result = json_address_new(&addr, rpc->network);
}

static void
btc_rpc_gettransaction(btc_rpc_t *rpc,
                       const json_params *params,
                       rpc_res_t *res) {
  uint8_t hash[32];
  btc_txmeta_t meta;
  btc_tx_t *tx;

  if (params->help || params->length != 1)
    THROW_MISC("gettransaction \"txid\"");

  if (!json_hash_get(hash, params->values[0]))
    THROW_TYPE(txid, hash);

  if (!btc_wallet_meta(&meta, rpc->wallet, hash))
    THROW(RPC_WALLET_ERROR, "Transaction not found");

  if (!btc_wallet_tx(&tx, rpc->wallet, hash))
    THROW(RPC_DATABASE_ERROR, "Database error");

  res->result = json_wtx_new(rpc, &meta, tx);

  btc_tx_destroy(tx);
}

static void
btc_rpc_getwalletinfo(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  int64_t until, rate;
  btc_balance_t bal;
  json_value *obj;

  if (params->help || params->length != 0)
    THROW_MISC("getwalletinfo");

  if (!btc_wallet_balance(&bal, rpc->wallet, -1))
    THROW(RPC_DATABASE_ERROR, "Database error");

  obj = json_object_new(5);
  until = btc_wallet_until(rpc->wallet);
  rate = btc_wallet_rate(rpc->wallet, -1);

  json_object_push(obj, "balance", json_amount_new(bal.confirmed));
  json_object_push(obj, "unconfirmed_balance",
                        json_amount_new(bal.unconfirmed));
  json_object_push(obj, "txcount", json_integer_new(bal.tx));
  json_object_push(obj, "unlocked_until", json_integer_new(until));
  json_object_push(obj, "paytxfee", json_amount_new(rate));

  res->result = obj;
}

static void
btc_rpc_listaccounts(btc_rpc_t *rpc,
                     const json_params *params,
                     rpc_res_t *res) {
  const char *after = NULL;
  btc_acctiter_t *it;
  int confirmed = 0;
  int limit = 100;
  json_value *obj;
  int i = 0;

  if (params->help || params->length > 3)
    THROW_MISC("listaccounts ( confirmed limit \"after\" )");

  if (params->length > 0) {
    if (!json_boolean_get(&confirmed, params->values[0]))
      THROW_TYPE(confirmed, boolean);
  }

  if (params->length > 1) {
    if (!json_unsigned_get(&limit, params->values[1]) || limit > 10000)
      THROW_TYPE(limit, integer);
  }

  if (params->length > 2) {
    if (!json_string_get(&after, params->values[2]))
      THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
  }

  obj = json_object_new(limit);

  it = btc_wallet_accounts(rpc->wallet);

  if (params->length > 2)
    btc_acctiter_seek_gt(it, after);
  else
    btc_acctiter_first(it);

  for (; btc_acctiter_valid(it) && i < limit; btc_acctiter_next(it), i++) {
    const char *name = btc_acctiter_key(it);
    btc_balance_t *bal = btc_acctiter_value(it);

    json_object_push(obj, name,
      json_amount_new(confirmed ? bal->confirmed
                                : bal->unconfirmed));
  }

  btc_acctiter_destroy(it);

  res->result = obj;
}

static void
btc_rpc_listlockunspent(btc_rpc_t *rpc,
                        const json_params *params,
                        rpc_res_t *res) {
  const btc_outset_t *map;
  btc_mapiter_t it;
  json_value *obj;

  if (params->help || params->length > 0)
    THROW_MISC("listlockunspent");

  map = btc_wallet_frozen(rpc->wallet);
  obj = json_array_new(map->size);

  btc_map_each(map, it) {
    const btc_outpoint_t *key = map->keys[it];

    json_array_push(obj, json_outpoint_new(key));
  }

  res->result = obj;
}

static void
btc_rpc_listsinceblock(btc_rpc_t *rpc,
                       const json_params *params,
                       rpc_res_t *res) {
  uint32_t account = BTC_NO_ACCOUNT;
  const uint8_t *next = NULL;
  const btc_entry_t *entry;
  const char *name = NULL;
  json_value *txs, *obj;
  btc_txiter_t *it;
  uint8_t hash[32];
  int limit = 100;
  int height = -1;
  int last = -1;
  int stop = 0;
  int i = 0;

  if (params->help || params->length > 3)
    THROW_MISC("listsinceblock ( \"account\" \"blockhash\" limit )");

  if (params->length > 0) {
    if (!json_string_get(&name, params->values[0]) ||
        !btc_wallet_lookup(&account, rpc->wallet, name)) {
      THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    }
  }

  if (params->length > 1) {
    if (params->values[1]->type == json_integer) {
      if (!json_signed_get(&height, params->values[1]) || height < -1)
        THROW(RPC_INVALID_PARAMETER, "Target block height out of range");
    } else {
      if (!json_hash_get(hash, params->values[1]))
        THROW_TYPE(hash, hash_or_height);

      if (!btc_hash_is_null(hash)) {
        entry = btc_chain_by_hash(rpc->chain, hash);

        if (entry == NULL)
          THROW(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        height = entry->height;
      }
    }
  }

  if (params->length > 2) {
    if (!json_unsigned_get(&limit, params->values[2]) || limit > 10000)
      THROW_TYPE(limit, integer);
  }

  txs = json_array_new(limit + 100);

  it = btc_wallet_txs(rpc->wallet);

  btc_txiter_account(it, account);
  btc_txiter_start(it, height);
  btc_txiter_first(it);

  for (; btc_txiter_valid(it); btc_txiter_next(it), i++) {
    const btc_txmeta_t *meta;
    const btc_tx_t *tx;

    if (height >= 0) {
      if (btc_txiter_height(it) == stop)
        break;

      if (i + 1 >= limit)
        stop = btc_txiter_height(it) + 1;
    }

    meta = btc_txiter_meta(it);
    tx = btc_txiter_value(it);

    json_array_push(txs, json_ltx_new(rpc, meta, tx));

    last = btc_txiter_height(it);
  }

  if (last >= 0) {
    entry = btc_chain_by_height(rpc->chain, last + 1);

    if (entry != NULL) {
      next = entry->hash;
      last += 1;
    } else {
      last = -1;
    }
  }

  btc_txiter_destroy(it);

  obj = json_object_new(2);

  json_object_push(obj, "transactions", txs);
  json_object_push(obj, "nextblock", json_hash_new(next));
  json_object_push(obj, "nextheight", json_integer_new(last));

  res->result = obj;
}

static void
btc_rpc_listtransactions(btc_rpc_t *rpc,
                         const json_params *params,
                         rpc_res_t *res) {
  uint32_t account = BTC_NO_ACCOUNT;
  const char *name = NULL;
  uint64_t after = 0;
  btc_txiter_t *it;
  json_value *txs;
  int limit = 100;
  int reverse = 0;
  int i = 0;

  if (params->help || params->length > 3)
    THROW_MISC("listtransactions ( \"account\" limit after )");

  if (params->length > 0) {
    if (!json_string_get(&name, params->values[0]) ||
        !btc_wallet_lookup(&account, rpc->wallet, name)) {
      THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    }
  }

  if (params->length > 1) {
    if (!json_signed_get(&limit, params->values[1]))
      THROW_TYPE(limit, integer);

    if (limit < 0) {
      limit = -limit;
      reverse = 1;
    }

    if (limit > 10000)
      THROW_TYPE(limit, integer);
  }

  if (params->length > 2) {
    if (!json_uint64_get(&after, params->values[2]))
      THROW_TYPE(after, integer);
  }

  txs = json_array_new(limit);

  it = btc_wallet_txs(rpc->wallet);

  btc_txiter_account(it, account);

  if (params->length > 2) {
    if (reverse)
      btc_txiter_seek_lt(it, after);
    else
      btc_txiter_seek_gt(it, after);
  } else {
    if (reverse)
      btc_txiter_last(it);
    else
      btc_txiter_first(it);
  }

  while (btc_txiter_valid(it) && i++ < limit) {
    const btc_txmeta_t *meta = btc_txiter_meta(it);
    const btc_tx_t *tx = btc_txiter_value(it);

    json_array_push(txs, json_ltx_new(rpc, meta, tx));

    if (reverse)
      btc_txiter_prev(it);
    else
      btc_txiter_next(it);
  }

  btc_txiter_destroy(it);

  res->result = txs;
}

static void
btc_rpc_listunspent(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  uint32_t account = BTC_NO_ACCOUNT;
  const char *name = NULL;
  btc_outpoint_t after;
  btc_coiniter_t *it;
  json_value *coins;
  int limit = 100;
  int i = 0;

  if (params->help || params->length > 3)
    THROW_MISC("listunspent ( \"account\" limit {\"txid\":txid,\"vout\":n} )");

  if (params->length > 0) {
    if (!json_string_get(&name, params->values[0]) ||
        !btc_wallet_lookup(&account, rpc->wallet, name)) {
      THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    }
  }

  if (params->length > 1) {
    if (!json_signed_get(&limit, params->values[1]) || limit > 10000)
      THROW_TYPE(limit, integer);
  }

  if (params->length > 2) {
    if (!json_outpoint_get(&after, params->values[2]))
      THROW_TYPE(after, outpoint);
  }

  coins = json_array_new(limit);

  it = btc_wallet_coins(rpc->wallet);

  btc_coiniter_account(it, account);

  if (params->length > 2)
    btc_coiniter_seek_gt(it, &after);
  else
    btc_coiniter_first(it);

  for (; btc_coiniter_valid(it) && i < limit; btc_coiniter_next(it), i++) {
    const btc_outpoint_t *prevout = btc_coiniter_key(it);
    const btc_coin_t *coin = btc_coiniter_value(it);

    if (account == BTC_NO_ACCOUNT && coin->watch)
      continue;

    json_array_push(coins, json_wcoin_new(rpc, prevout, coin));
  }

  btc_coiniter_destroy(it);

  res->result = coins;
}

static void
btc_rpc_lockunspent(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  const json_value *items;
  int unlock;
  size_t i;

  if (params->help || params->length < 1 || params->length > 2)
    THROW_MISC("lockunspent unlock ( [{\"txid\":\"txid\",\"vout\":n},...] )");

  if (!json_boolean_get(&unlock, params->values[0]))
    THROW_TYPE(unlock, boolean);

  if (params->length == 1) {
    if (unlock)
      btc_wallet_unfreeze(rpc->wallet, NULL);

    res->result = json_boolean_new(1);

    return;
  }

  items = params->values[1];

  if (items->type != json_array)
    THROW_TYPE(items, array);

  for (i = 0; i < items->u.array.length; i++) {
    const json_value *item = items->u.array.values[i];
    btc_outpoint_t key;

    if (!json_outpoint_get(&key, item))
      THROW_TYPE(item, outpoint);

    if (unlock)
      btc_wallet_unfreeze(rpc->wallet, &key);
    else
      btc_wallet_freeze(rpc->wallet, &key);
  }

  res->result = json_boolean_new(1);
}

static void
btc_rpc_renameaccount(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length != 2)
    THROW_MISC("renameaccount \"oldname\" \"newname\"");
}

static void
btc_rpc_rescanblockchain(btc_rpc_t *rpc,
                         const json_params *params,
                         rpc_res_t *res) {
  int height = -1;

  if (params->help || params->length > 1)
    THROW_MISC("rescanblockchain ( start_height )");

  if (params->length > 0) {
    if (!json_unsigned_get(&height, params->values[0]))
      THROW_TYPE(height, integer);
  }

  if (!btc_wallet_rescan(rpc->wallet, height))
    THROW(RPC_WALLET_ERROR, "Rescan failed");

  res->result = json_object_new(1);

  json_object_push(res->result, "start_height", json_integer_new(height));
}

static void
btc_rpc_resendwallettransactions(btc_rpc_t *rpc,
                                 const json_params *params,
                                 rpc_res_t *res) {
  json_value *txids;
  btc_txiter_t *it;

  if (params->help || params->length != 0)
    THROW_MISC("resendwallettransactions");

  txids = json_array_new(4096);

  it = btc_wallet_txs(rpc->wallet);

  btc_txiter_start(it, -1);
  btc_txiter_first(it);

  for (; btc_txiter_valid(it); btc_txiter_next(it)) {
    const btc_tx_t *tx = btc_txiter_value(it);

    /* XXX need call to resend invs */
    btc_mempool_add(rpc->mempool, tx, 0);

    json_array_push(txids, json_hash_new(tx->hash));
  }

  btc_txiter_destroy(it);

  res->result = txids;
}

static void
btc_rpc_send_internal(btc_rpc_t *rpc,
                      uint32_t account,
                      btc_tx_t *tx,
                      int depth,
                      int subfee,
                      rpc_res_t *res) {
  btc_selopt_t options;

  btc_selopt_init(&options);

  options.depth = depth;
  options.subfee = subfee;
  options.smart = (depth != 0);

  if (!btc_wallet_send(rpc->wallet, account, &options, tx)) {
    btc_tx_destroy(tx);
    THROW(RPC_WALLET_ERROR, "Could not send transaction");
  }

  res->result = json_hash_new(tx->hash);

  btc_tx_destroy(tx);
}

static void
btc_rpc_send(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  (void)rpc;

  if (params->help || params->length < 1 || params->length > 2)
    THROW_MISC("send [{\"address\":amount},{\"data\":\"hex\"},...] (options)");
}

static void
btc_rpc_sendfrom(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  btc_address_t addr;
  const char *name;
  uint32_t account;
  int subfee = 0;
  int depth = -1;
  int64_t value;
  btc_tx_t *tx;

  if (params->help || params->length < 3 || params->length > 5)
    THROW_MISC("sendfrom \"account\" \"address\" amount ( minconf subfee )");

  if (!json_string_get(&name, params->values[0]) ||
      !btc_wallet_lookup(&account, rpc->wallet, name)) {
    THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
  }

  if (!json_address_get(&addr, params->values[1], rpc->network))
    THROW_TYPE(address, address);

  if (!json_amount_get(&value, params->values[2]))
    THROW_TYPE(amount, amount);

  if (params->length > 3) {
    if (!json_signed_get(&depth, params->values[3]))
      THROW_TYPE(minconf, integer);
  }

  if (params->length > 4) {
    if (!json_boolean_get(&subfee, params->values[4]))
      THROW_TYPE(subfee, boolean);
  }

  if (btc_wallet_locked(rpc->wallet))
    THROW(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");

  tx = btc_tx_create();

  btc_tx_add_output(tx, &addr, value);

  btc_rpc_send_internal(rpc, account, tx, depth, subfee, res);
}

static void
btc_rpc_sendmany(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  const json_object_entry *entry;
  const json_value *outputs;
  btc_address_t addr;
  const char *name;
  uint32_t account;
  int subfee = 0;
  int depth = -1;
  int64_t value;
  btc_tx_t *tx;
  size_t i;

  if (params->help || params->length < 2 || params->length > 4) {
    THROW_MISC("sendmany \"account\" {\"address\":amount,...}"
                                   " ( minconf subfee )");
  }

  if (!json_string_get(&name, params->values[0]) ||
      !btc_wallet_lookup(&account, rpc->wallet, name)) {
    THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
  }

  outputs = params->values[1];

  if (outputs->type != json_object || outputs->u.object.length == 0)
    THROW_TYPE(outputs, object);

  if (params->length > 2) {
    if (!json_signed_get(&depth, params->values[2]))
      THROW_TYPE(minconf, integer);
  }

  if (params->length > 3) {
    if (!json_boolean_get(&subfee, params->values[3]))
      THROW_TYPE(subfee, boolean);
  }

  if (btc_wallet_locked(rpc->wallet))
    THROW(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");

  tx = btc_tx_create();

  for (i = 0; i < outputs->u.object.length; i++) {
    entry = &outputs->u.object.values[i];

    if (strcmp(entry->name, "data") == 0) {
      uint8_t raw[80];
      size_t len = 80;

      if (!json_raw_get(raw, &len, entry->value)) {
        btc_tx_destroy(tx);
        THROW_TYPE(data, string);
      }

      btc_tx_add_nulldata(tx, raw, len);

      continue;
    }

    if (!btc_address_set_str(&addr, entry->name, rpc->network)) {
      btc_tx_destroy(tx);
      THROW_TYPE(key, address);
    }

    if (!json_amount_get(&value, entry->value)) {
      btc_tx_destroy(tx);
      THROW_TYPE(value, amount);
    }

    btc_tx_add_output(tx, &addr, value);
  }

  btc_rpc_send_internal(rpc, account, tx, depth, subfee, res);
}

static void
btc_rpc_sendtoaddress(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  uint32_t account = BTC_NO_ACCOUNT;
  btc_address_t addr;
  int subfee = 0;
  int depth = -1;
  int64_t value;
  btc_tx_t *tx;

  if (params->help || params->length < 2 || params->length > 4)
    THROW_MISC("sendtoaddress \"address\" amount ( minconf subfee )");

  if (!json_address_get(&addr, params->values[0], rpc->network))
    THROW_TYPE(address, address);

  if (!json_amount_get(&value, params->values[1]))
    THROW_TYPE(amount, amount);

  if (params->length > 2) {
    if (!json_signed_get(&depth, params->values[2]))
      THROW_TYPE(minconf, integer);
  }

  if (params->length > 3) {
    if (!json_boolean_get(&subfee, params->values[3]))
      THROW_TYPE(subfee, boolean);
  }

  if (btc_wallet_locked(rpc->wallet))
    THROW(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");

  tx = btc_tx_create();

  btc_tx_add_output(tx, &addr, value);

  btc_rpc_send_internal(rpc, account, tx, depth, subfee, res);
}

static void
btc_rpc_settxfee(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  int64_t rate;

  if (params->help || params->length != 1)
    THROW_MISC("settxfee amount");

  if (!json_amount_get(&rate, params->values[0]))
    THROW_TYPE(rate, amount);

  btc_wallet_rate(rpc->wallet, rate);

  res->result = json_boolean_new(1);
}

static void
btc_rpc_signmessage(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  static const char magic[] = "Bitcoin Signed Message:\n";
  btc_address_t addr;
  btc_hash256_t ctx;
  btc_path_t path;
  const char *msg;
  uint8_t hash[32];
  uint8_t key[32];
  uint8_t tmp[64];
  uint8_t sig[72];
  char str[145];
  size_t len;

  if (params->help || params->length != 2)
    THROW_MISC("signmessage \"address\" \"message\"");

  if (!json_address_get(&addr, params->values[0], rpc->network))
    THROW_TYPE(address, address);

  if (!json_string_get(&msg, params->values[1]))
    THROW_TYPE(message, string);

  if (btc_wallet_locked(rpc->wallet))
    THROW(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");

  if (!btc_wallet_path(&path, rpc->wallet, &addr))
    THROW(RPC_WALLET_ERROR, "Address not found");

  if (!btc_wallet_privkey(key, rpc->wallet, &path))
    THROW(RPC_WALLET_ERROR, "Key not found");

  btc_hash256_init(&ctx);
  btc_hash256_update(&ctx, magic, sizeof(magic) - 1);
  btc_hash256_update(&ctx, msg, strlen(msg));
  btc_hash256_final(&ctx, hash);

  if (!btc_ecdsa_sign(tmp, NULL, hash, 32, key))
    THROW(RPC_WALLET_ERROR, "Invalid private key");

  CHECK(btc_ecdsa_sig_export(sig, &len, tmp));

  btc_base16_encode(str, sig, len);

  res->result = json_string_new(str);

  btc_memzero(key, sizeof(key));
}

static void
btc_rpc_signrawtransactionwithwallet(btc_rpc_t *rpc,
                                     const json_params *params,
                                     rpc_res_t *res) {
  btc_wallet_t *wallet = rpc->wallet;
  btc_view_t *view;
  btc_tx_t *tx;
  size_t total;
  int complete;

  if (params->help || params->length != 1)
    THROW_MISC("signrawtransactionwithwallet \"hexstring\"");

  if (btc_wallet_locked(wallet))
    THROW(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");

  if (!json_tx_get(&tx, params->values[0]))
    THROW_TYPE(hexstring, transaction);

  view = btc_wallet_view(wallet, tx);
  total = btc_wallet_sign(wallet, tx, view);
  complete = (total == tx->inputs.length);

  res->result = json_object_new(2);

  json_object_push(res->result, "hex", json_tx_raw(tx));
  json_object_push(res->result, "complete", json_boolean_new(complete));

  btc_view_destroy(view);
  btc_tx_destroy(tx);
}

static void
btc_rpc_walletlock(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  if (params->help || params->length != 0)
    THROW_MISC("walletlock");

  if (!btc_wallet_encrypted(rpc->wallet))
    THROW(RPC_WALLET_WRONG_ENC_STATE, "Wallet is not encrypted");

  btc_wallet_lock(rpc->wallet);

  res->result = json_null_new();
}

static void
btc_rpc_walletpassphrase(btc_rpc_t *rpc,
                         const json_params *params,
                         rpc_res_t *res) {
  int64_t msec = -1;
  const char *pass;
  int timeout;

  if (params->help || params->length != 2)
    THROW_MISC("walletpassphrase \"passphrase\" timeout");

  if (!btc_wallet_encrypted(rpc->wallet))
    THROW(RPC_WALLET_WRONG_ENC_STATE, "Wallet is not encrypted");

  if (!json_string_get(&pass, params->values[0]))
    THROW_TYPE(passphrase, string);

  if (!json_signed_get(&timeout, params->values[1]))
    THROW_TYPE(timeout, integer);

  if (timeout >= 0)
    msec = (int64_t)timeout * 1000;

  if (!btc_wallet_unlock(rpc->wallet, pass, msec))
    THROW(RPC_WALLET_PASSPHRASE_INCORRECT, "Could not unlock wallet");

  res->result = json_null_new();

  btc_memzero((void *)pass, strlen(pass));
}

static void
btc_rpc_walletpassphrasechange(btc_rpc_t *rpc,
                               const json_params *params,
                               rpc_res_t *res) {
  const char *oldpass, *newpass;
  size_t oldlen, newlen;

  if (params->help || params->length != 2)
    THROW_MISC("walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"");

  if (!btc_wallet_encrypted(rpc->wallet))
    THROW(RPC_WALLET_WRONG_ENC_STATE, "Wallet is not encrypted");

  if (!json_string_get(&oldpass, params->values[0]))
    THROW_TYPE(oldpassphrase, string);

  if (!json_string_get(&newpass, params->values[1]))
    THROW_TYPE(newpassphrase, string);

  if (!btc_wallet_unlock(rpc->wallet, oldpass, -1))
    THROW(RPC_WALLET_PASSPHRASE_INCORRECT, "Could not unlock wallet");

  oldlen = strlen(oldpass);
  newlen = strlen(newpass);

  if (newlen > 0) {
    if (!btc_wallet_encrypt(rpc->wallet, newpass))
      THROW(RPC_WALLET_ENCRYPTION_FAILED, "Could not encrypt wallet");
  } else {
    if (!btc_wallet_decrypt(rpc->wallet))
      THROW(RPC_WALLET_ENCRYPTION_FAILED, "Could not decrypt wallet");
  }

  res->result = json_null_new();

  btc_memzero((void *)oldpass, oldlen);
  btc_memzero((void *)newpass, newlen);
}

static void
btc_rpc_watchaccount(btc_rpc_t *rpc,
                     const json_params *params,
                     rpc_res_t *res) {
  const char *name, *xpub;
  btc_hdnode_t key;
  size_t len;

  if (params->help || params->length != 2)
    THROW_MISC("watchaccount \"name\" \"xpubkey\"");

  if (!json_string_get(&name, params->values[0]))
    THROW_TYPE(name, string);

  if (!json_string_get(&xpub, params->values[1]))
    THROW_TYPE(xpubkey, string);

  len = strlen(name);

  if (len == 0 || len > 63 ||
      strcmp(name, "*") == 0 ||
      strcmp(name, ".") == 0) {
    THROW(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
  }

  if (!btc_hdpub_set_str(&key, xpub, rpc->network))
    THROW(RPC_TYPE_ERROR, "Invalid xpubkey");

  switch (key.type) {
    case BTC_BIP32_STANDARD:
    case BTC_BIP32_P2WPKH:
    case BTC_BIP32_NESTED_P2WPKH:
      break;
    default:
      THROW(RPC_TYPE_ERROR, "Invalid xpubkey type");
  }

  if (key.depth != 2 || !(key.index & BTC_BIP32_HARDEN))
    THROW(RPC_TYPE_ERROR, "Invalid xpubkey depth/index");

  if (!btc_wallet_create_watcher(rpc->wallet, name, &key))
    THROW(RPC_WALLET_ERROR, "Account already exists");

  res->result = json_boolean_new(1);
}

/*
 * Registry
 */

static void
btc_rpc_help(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res);

static const struct {
  const char *method;
  void (*handler)(btc_rpc_t *,
                  const json_params *,
                  rpc_res_t *);
} btc_rpc_methods[] = {
  { "abandontransaction", btc_rpc_abandontransaction },
  { "addnode", btc_rpc_addnode },
  { "backupwallet", btc_rpc_backupwallet },
  { "bumpfee", btc_rpc_bumpfee },
  { "clearbanned", btc_rpc_clearbanned },
  { "createaccount", btc_rpc_createaccount },
  { "createrawtransaction", btc_rpc_createrawtransaction },
  { "decoderawtransaction", btc_rpc_decoderawtransaction },
  { "decodescript", btc_rpc_decodescript },
  { "deleteaccount", btc_rpc_deleteaccount },
  { "disconnectnode", btc_rpc_disconnectnode },
  { "dumpprivkey", btc_rpc_dumpprivkey },
  { "dumpwallet", btc_rpc_dumpwallet },
  { "encryptwallet", btc_rpc_encryptwallet },
  { "estimatesmartfee", btc_rpc_estimatesmartfee },
  { "fundhwtransaction", btc_rpc_fundhwtransaction },
  { "fundrawtransaction", btc_rpc_fundrawtransaction },
  { "generate", btc_rpc_generate },
  { "generateblock", btc_rpc_generateblock },
  { "generatetoaddress", btc_rpc_generatetoaddress },
  { "getaccount", btc_rpc_getaccount },
  { "getaccountaddress", btc_rpc_getaccountaddress },
  { "getaccountinfo", btc_rpc_getaccountinfo },
  { "getaddednodeinfo", btc_rpc_getaddednodeinfo },
  { "getaddressesbyaccount", btc_rpc_getaddressesbyaccount },
  { "getaddressinfo", btc_rpc_getaddressinfo },
  { "getbalance", btc_rpc_getbalance },
  { "getbalances", btc_rpc_getbalances },
  { "getbestblockhash", btc_rpc_getbestblockhash },
  { "getblock", btc_rpc_getblock },
  { "getblockchaininfo", btc_rpc_getblockchaininfo },
  { "getblockcount", btc_rpc_getblockcount },
  { "getblockhash", btc_rpc_getblockhash },
  { "getblockheader", btc_rpc_getblockheader },
  { "getblocktemplate", btc_rpc_getblocktemplate },
  { "getchaintips", btc_rpc_getchaintips },
  { "getconnectioncount", btc_rpc_getconnectioncount },
  { "getdifficulty", btc_rpc_getdifficulty },
  { "getgenerate", btc_rpc_getgenerate },
  { "getmemoryinfo", btc_rpc_getmemoryinfo },
  { "getmempoolentry", btc_rpc_getmempoolentry },
  { "getmempoolinfo", btc_rpc_getmempoolinfo },
  { "getmininginfo", btc_rpc_getmininginfo },
  { "getnettotals", btc_rpc_getnettotals },
  { "getnetworkhashps", btc_rpc_getnetworkhashps },
  { "getnetworkinfo", btc_rpc_getnetworkinfo },
  { "getnewaddress", btc_rpc_getnewaddress },
  { "getnodeaddresses", btc_rpc_getnodeaddresses },
  { "getpeerinfo", btc_rpc_getpeerinfo },
  { "getrawchangeaddress", btc_rpc_getrawchangeaddress },
  { "getrawmempool", btc_rpc_getrawmempool },
  { "getrawtransaction", btc_rpc_getrawtransaction },
  { "gettransaction", btc_rpc_gettransaction },
  { "gettxout", btc_rpc_gettxout },
  { "gettxoutsetinfo", btc_rpc_gettxoutsetinfo },
  { "getwalletinfo", btc_rpc_getwalletinfo },
  { "getwork", btc_rpc_getwork },
  { "help", btc_rpc_help },
  { "listaccounts", btc_rpc_listaccounts },
  { "listbanned", btc_rpc_listbanned },
  { "listlockunspent", btc_rpc_listlockunspent },
  { "listsinceblock", btc_rpc_listsinceblock },
  { "listtransactions", btc_rpc_listtransactions },
  { "listunspent", btc_rpc_listunspent },
  { "lockunspent", btc_rpc_lockunspent },
  { "ping", btc_rpc_ping },
  { "prioritisetransaction", btc_rpc_prioritisetransaction },
  { "pruneblockchain", btc_rpc_pruneblockchain },
  { "renameaccount", btc_rpc_renameaccount },
  { "rescanblockchain", btc_rpc_rescanblockchain },
  { "resendwallettransactions", btc_rpc_resendwallettransactions },
  { "savemempool", btc_rpc_savemempool },
  { "send", btc_rpc_send },
  { "sendfrom", btc_rpc_sendfrom },
  { "sendmany", btc_rpc_sendmany },
  { "sendrawtransaction", btc_rpc_sendrawtransaction },
  { "sendtoaddress", btc_rpc_sendtoaddress },
  { "setban", btc_rpc_setban },
  { "setgenerate", btc_rpc_setgenerate },
  { "setloglevel", btc_rpc_setloglevel },
  { "setnetworkactive", btc_rpc_setnetworkactive },
  { "settxfee", btc_rpc_settxfee },
  { "signmessage", btc_rpc_signmessage },
  { "signmessagewithprivkey", btc_rpc_signmessagewithprivkey },
  { "signrawtransactionwithkey", btc_rpc_signrawtransactionwithkey },
  { "signrawtransactionwithwallet", btc_rpc_signrawtransactionwithwallet },
  { "stop", btc_rpc_stop },
  { "submitblock", btc_rpc_submitblock },
  { "testmempoolaccept", btc_rpc_testmempoolaccept },
  { "uptime", btc_rpc_uptime },
  { "validateaddress", btc_rpc_validateaddress },
  { "verifychain", btc_rpc_verifychain },
  { "verifymessage", btc_rpc_verifymessage },
  { "walletlock", btc_rpc_walletlock },
  { "walletpassphrase", btc_rpc_walletpassphrase },
  { "walletpassphrasechange", btc_rpc_walletpassphrasechange },
  { "watchaccount", btc_rpc_watchaccount }
};

static int
btc_rpc_find_handler(const char *method) {
  int end = lengthof(btc_rpc_methods) - 1;
  int start = 0;
  int pos, cmp;

  while (start <= end) {
    pos = (start + end) >> 1;
    cmp = strcmp(btc_rpc_methods[pos].method, method);

    if (cmp == 0)
      return pos;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  return -1;
}

/*
 * Handling
 */

static void
btc_rpc_handle(btc_rpc_t *rpc, const rpc_req_t *req, rpc_res_t *res) {
  int index = btc_rpc_find_handler(req->method);
  json_params params;

  if (index < 0) {
    rpc_res_error(res, RPC_METHOD_NOT_FOUND, "Method not found");
    return;
  }

  btc_log_debug(rpc, "Handling RPC call: %s.", req->method);

  if (req->params == NULL || req->params->type == json_null) {
    params.length = 0;
    params.values = NULL;
  } else if (req->params->type == json_array) {
    params.length = req->params->u.array.length;
    params.values = req->params->u.array.values;
  } else {
    btc_abort(); /* LCOV_EXCL_LINE */
  }

  params.help = 0;

  btc_rpc_methods[index].handler(rpc, &params, res);
}

static void
btc_rpc_help(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  const char *method;
  json_params dummy;
  int index;

  if (params->length != 1 || params->values[0]->type != json_string)
    THROW_MISC("help method");

  method = params->values[0]->u.string.ptr;
  index = btc_rpc_find_handler(method);

  if (index < 0) {
    rpc_res_error(res, RPC_METHOD_NOT_FOUND, "Method not found");
    return;
  }

  dummy.length = 0;
  dummy.values = NULL;
  dummy.help = 1;

  btc_rpc_methods[index].handler(rpc, &dummy, res);
}

static int
on_request(http_server_t *server, http_req_t *req, http_res_t *res) {
  btc_rpc_t *rpc = server->data;
  json_value *input, *output;
  json_settings settings;
  rpc_req_t rreq;
  rpc_res_t rres;
  unsigned int i;

  if (req->method != HTTP_METHOD_POST) {
    http_res_error(res, 400);
    return 1;
  }

  if (req->path.length != 1 || req->path.data[0] != '/') {
    http_res_error(res, 404);
    return 1;
  }

  if (!btc_hash_is_null(rpc->auth_hash)) {
    uint8_t hash[32];

    btc_hash_auth(hash, req->user.data, req->pass.data);

    if (!btc_memequal(hash, rpc->auth_hash, 32)) {
      http_res_unauthorized(res, "jsonrpc");
      return 1;
    }
  }

  memset(&settings, 0, sizeof(settings));

  settings.settings = json_enable_amounts;

  input = json_parse_ex(&settings, req->body.data, req->body.length, NULL);

  if (input != NULL && input->type == json_array) {
    output = json_array_new(input->u.array.length);

    for (i = 0; i < input->u.array.length; i++) {
      rpc_req_init(&rreq);
      rpc_res_init(&rres);

      if (!rpc_req_set(&rreq, input->u.array.values[i]))
        rpc_res_error(&rres, RPC_INVALID_PARAMS, "Invalid params");
      else
        btc_rpc_handle(rpc, &rreq, &rres);

      json_array_push(output, rpc_res_encode(&rres, rreq.id));
    }
  } else {
    rpc_req_init(&rreq);
    rpc_res_init(&rres);

    if (!rpc_req_set(&rreq, input))
      rpc_res_error(&rres, RPC_INVALID_REQUEST, "Invalid request");
    else
      btc_rpc_handle(rpc, &rreq, &rres);

    output = rpc_res_encode(&rres, rreq.id);
  }

  http_res_send_json(res, output);

  json_value_free(input); /* Accepts NULL. */
  json_builder_free(output);

  return 1;
}

/*
 * Testing
 */

json_value *
btc_rpc_call(btc_rpc_t *rpc, const char *method, const json_value *params) {
  int index = btc_rpc_find_handler(method);
  rpc_res_t res;

  rpc_res_init(&res);

  if (index < 0) {
    rpc_res_error(&res, RPC_METHOD_NOT_FOUND, "Method not found");
  } else if (params != NULL && params->type != json_array) {
    rpc_res_error(&res, RPC_INVALID_REQUEST, "Invalid request");
  } else {
    json_params parms;

    if (params == NULL) {
      parms.length = 0;
      parms.values = NULL;
    } else {
      parms.length = params->u.array.length;
      parms.values = params->u.array.values;
    }

    parms.help = 0;

    btc_rpc_methods[index].handler(rpc, &parms, &res);
  }

  return rpc_res_encode(&res, NULL);
}
