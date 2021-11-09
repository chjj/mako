/*!
 * rpc.c - rpc for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <io/core.h>
#include <io/http.h>
#include <io/loop.h>

#include <node/addrman.h>
#include <node/chain.h>
#include <node/logger.h>
#include <node/mempool.h>
#include <node/miner.h>
#include <node/node.h>
#include <node/pool.h>
#include <node/rpc.h>
#include <node/timedata.h>

#include <satoshi/address.h>
#include <satoshi/block.h>
#include <satoshi/coins.h>
#include <satoshi/consensus.h>
#include <satoshi/crypto/hash.h>
#include <satoshi/encoding.h>
#include <satoshi/entry.h>
#include <satoshi/header.h>
#include <satoshi/json.h>
#include <satoshi/map.h>
#include <satoshi/net.h>
#include <satoshi/netaddr.h>
#include <satoshi/netmsg.h>
#include <satoshi/network.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include <satoshi/util.h>
#include <satoshi/vector.h>

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
 * RPC Request
 */

typedef struct rpc_req_s {
  const char *method;
  const json_value *params;
  int64_t id;
} rpc_req_t;

static void
rpc_req_init(rpc_req_t *req) {
  req->method = NULL;
  req->params = NULL;
  req->id = 0;
}

static int
rpc_req_set(rpc_req_t *req, const json_value *obj) {
  const json_value *method, *params, *id;

  if (obj == NULL || obj->type != json_object)
    return 0;

  method = json_object_get(obj, "method");

  if (method == NULL || method->type != json_string)
    return 0;

  params = json_object_get(obj, "params");

  if (params == NULL || params->type != json_array)
    return 0;

  id = json_object_get(obj, "id");

  if (id == NULL || id->type != json_integer)
    return 0;

  req->method = method->u.string.ptr;
  req->params = params;
  req->id = id->u.integer;

  return 1;
}

/*
 * RPC Response
 */

typedef struct rpc_res_s {
  json_value *result;
  const char *msg;
  int code;
} rpc_res_t;

static void
rpc_res_init(rpc_res_t *res) {
  res->result = NULL;
  res->msg = NULL;
  res->code = 0;
}

static void
rpc_res_error(rpc_res_t *res, int code, const char *msg) {
  if (res->result != NULL)
    json_builder_free(res->result);

  res->result = NULL;
  res->msg = msg;
  res->code = code;
}

static json_value *
rpc_res_encode(rpc_res_t *res, int64_t id) {
  json_value *obj = json_object_new(3);
  json_value *err;

  if (res->result == NULL)
    res->result = json_null_new();

  if (res->code != 0) {
    err = json_object_new(2);

    if (res->msg == NULL)
      res->msg = "Error";

    json_object_push(err, "message", json_string_new(res->msg));
    json_object_push(err, "code", json_integer_new(res->code));
  } else {
    err = json_null_new();
  }

  json_object_push(obj, "result", res->result);
  json_object_push(obj, "error", err);
  json_object_push(obj, "id", json_integer_new(id));

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
  http_server_t *http;
  unsigned int flags;
  btc_sockaddr_t bind;
  uint8_t auth_hash[32];
};

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
  rpc->http = http_server_create(node->loop);
  rpc->flags = BTC_RPC_DEFAULT_FLAGS;

  btc_sockaddr_import(&rpc->bind, "127.0.0.1", network->rpc_port);

  rpc->http->on_request = on_request;
  rpc->http->data = rpc;

  return rpc;
}

void
btc_rpc_destroy(btc_rpc_t *rpc) {
  http_server_destroy(rpc->http);
  btc_free(rpc);
}

void
btc_rpc_set_bind(btc_rpc_t *rpc, const btc_netaddr_t *addr) {
  btc_netaddr_get_sockaddr(&rpc->bind, addr);
}

void
btc_rpc_set_credentials(btc_rpc_t *rpc, const char *user, const char *pass) {
  btc_hmac256_t hmac;

  if (pass == NULL || *pass == '\0') {
    btc_hash_init(rpc->auth_hash);
  } else {
    btc_hmac256_init(&hmac, (const uint8_t *)user, strlen(user));
    btc_hmac256_update(&hmac, (const uint8_t *)pass, strlen(pass));
    btc_hmac256_final(&hmac, rpc->auth_hash);
  }
}

static void
btc_rpc_log(btc_rpc_t *rpc, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(rpc->logger, "rpc", fmt, ap);
  va_end(ap);
}

int
btc_rpc_open(btc_rpc_t *rpc, unsigned int flags) {
  rpc->flags = flags;

  btc_rpc_log(rpc, "Opening RPC.");

  if (!http_server_open(rpc->http, &rpc->bind))
    return 0;

  btc_rpc_log(rpc, "RPC listening on %S.", &rpc->bind);

  return 1;
}

void
btc_rpc_close(btc_rpc_t *rpc) {
  btc_rpc_log(rpc, "Closing RPC.");

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
 * Info
 */

static void
btc_rpc_getinfo(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  json_value *result;

  (void)rpc;

  if (params->help || params->length != 0)
    THROW_MISC("getinfo");

  result = json_object_new(1);

  json_object_push(result, "time", json_integer_new(btc_time_msec()));

  res->result = result;
}

/*
 * Blockchain
 */

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
btc_rpc_getbestblockhash(btc_rpc_t *rpc,
                         const json_params *params,
                         rpc_res_t *res) {
  const btc_entry_t *tip = btc_chain_tip(rpc->chain);

  if (params->help || params->length != 0)
    THROW_MISC("getbestblockhash");

  res->result = json_hash_new(tip->hash);
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
btc_rpc_getblock(btc_rpc_t *rpc, const json_params *params, rpc_res_t *res) {
  const btc_entry_t *entry;
  int32_t confirmations;
  const uint8_t *next;
  btc_block_t *block;
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

  block = btc_chain_get_block(rpc->chain, entry);

  if (block == NULL)
    THROW_MISC("Can't read block from disk");

  if (verbosity > 0) {
    confirmations = btc_rpc_get_depth(rpc, entry, &next);

    res->result = json_block_new_ex(block,
                                    entry,
                                    NULL,
                                    confirmations,
                                    next,
                                    verbosity > 1,
                                    rpc->network);
  } else {
    res->result = json_block_raw(block);
  }

  btc_block_destroy(block);
}

/*
 * Mining
 */

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

/*
 * Wallet
 */

static void
btc_rpc_sendtoaddress(btc_rpc_t *rpc,
                      const json_params *params,
                      rpc_res_t *res) {
  btc_address_t addr;
  json_value *obj;
  int64_t value;

  if (params->help || params->length != 2)
    THROW_MISC("sendtoaddress address amount");

  if (!json_address_get(&addr, params->values[0], rpc->network))
    THROW(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");

  if (!json_amount_get(&value, params->values[1]))
    THROW_TYPE(amount, amount);

  obj = json_object_new(2);

  json_object_push(obj, "address", json_address_new(&addr, rpc->network));
  json_object_push(obj, "amount", json_amount_new(value));

  res->result = obj;
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
  { "generate", btc_rpc_generate },
  { "generatetoaddress", btc_rpc_generatetoaddress },
  { "getbestblockhash", btc_rpc_getbestblockhash },
  { "getblock", btc_rpc_getblock },
  { "getblockchaininfo", btc_rpc_getblockchaininfo },
  { "getblockcount", btc_rpc_getblockcount },
  { "getblockhash", btc_rpc_getblockhash },
  { "getblockheader", btc_rpc_getblockheader },
  { "getdifficulty", btc_rpc_getdifficulty },
  { "getgenerate", btc_rpc_getgenerate },
  { "getinfo", btc_rpc_getinfo },
  { "help", btc_rpc_help },
  { "sendtoaddress", btc_rpc_sendtoaddress },
  { "setgenerate", btc_rpc_setgenerate }
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

  btc_rpc_log(rpc, "Incoming RPC request: %s.", req->method);

  params.length = req->params->u.array.length;
  params.values = req->params->u.array.values;
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
  json_settings settings;
  json_value *obj;
  rpc_req_t rreq;
  rpc_res_t rres;

  if (req->method != HTTP_METHOD_POST) {
    http_res_error(res, 400);
    return 1;
  }

  if (req->path.length != 1 || req->path.data[0] != '/') {
    http_res_error(res, 404);
    return 1;
  }

  rpc_req_init(&rreq);
  rpc_res_init(&rres);

  memset(&settings, 0, sizeof(settings));

  settings.settings = json_enable_amounts;

  obj = json_parse_ex(&settings, req->body.data, req->body.length, NULL);

  if (!rpc_req_set(&rreq, obj))
    rpc_res_error(&rres, RPC_INVALID_REQUEST, "Invalid request");
  else
    btc_rpc_handle(rpc, &rreq, &rres);

  if (obj != NULL)
    json_value_free(obj);

  obj = rpc_res_encode(&rres, rreq.id);

  http_res_send_json(res, obj);

  json_builder_free(obj);

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
  } else if (params->type != json_array) {
    rpc_res_error(&res, RPC_INVALID_REQUEST, "Invalid request");
  } else {
    json_params parms;

    parms.length = params->u.array.length;
    parms.values = params->u.array.values;
    parms.help = 0;

    btc_rpc_methods[index].handler(rpc, &parms, &res);
  }

  return rpc_res_encode(&res, 0);
}
