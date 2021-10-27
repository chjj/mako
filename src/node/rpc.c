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

#include <json.h>
#include <json-builder.h>

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
  RPC_CLIENT_P2P_DISABLED = -31
};

/*
 * Helpers
 */

static double
difficulty(uint32_t bits) {
  double diff = (double)0x0000ffff / (double)(bits & 0x00ffffff);
  int shift = (bits >> 24) & 0xff;

  while (shift < 29) {
    diff *= 256.0;
    shift++;
  }

  while (shift > 29) {
    diff /= 256.0;
    shift--;
  }

  return diff;
}

/*
 * HTTP Helpers
 */

static const json_serialize_opts json_options = {
  json_serialize_mode_multiline,
  json_serialize_opt_pack_brackets,
  2
};

static void
http_res_send_json(http_res_t *res, json_value *value) {
  /* Note: json_measure includes the null terminator. */
  size_t size = json_measure_ex(value, json_options);
  char *body = btc_malloc(size);
  size_t length;

  json_serialize_ex(body, value, json_options);

  length = strlen(body);

  body[length++] = '\n';

  http_res_send_data(res, 200, "application/json", body, length);
}

/*
 * JSON Helpers
 */

static json_value *
json_object_get(const json_value *obj, const char *name) {
  const json_object_entry *entry;
  unsigned int i;

  if (obj->type != json_object)
    return NULL;

  for (i = 0; i < obj->u.object.length; i++) {
    entry = &obj->u.object.values[i];

    if (strcmp(entry->name, name) == 0)
      return (json_value *)entry->value;
  }

  return NULL;
}

BTC_UNUSED static json_value *
json_hash_new(const uint8_t *hash) {
  char str[64 + 1];

  if (hash == NULL || btc_hash_is_null(hash))
    return json_null_new();

  btc_hash_export(str, hash);

  return json_string_new_length(64, str);
}

BTC_UNUSED static int
json_hash_get(uint8_t *hash, const json_value *obj) {
  if (obj->type != json_string)
    return 0;

  if (obj->u.string.length != 64)
    return 0;

  return btc_hash_import(hash, obj->u.string.ptr);
}

BTC_UNUSED static json_value *
json_buffer_new(const btc_buffer_t *item) {
  char *str;

  if (item->length == 0)
    return json_string_new_length(0, "");

  str = btc_malloc(item->length * 2 + 1);

  btc_base16_encode(str, item->data, item->length);

  return json_string_new_nocopy(item->length * 2, str);
}

BTC_UNUSED static int
json_buffer_get(btc_buffer_t *item, const json_value *obj) {
  if (obj->type != json_string)
    return 0;

  btc_buffer_grow(item, obj->u.string.length / 2);

  if (!btc_base16_decode(item->data, obj->u.string.ptr, obj->u.string.length))
    return 0;

  item->length = obj->u.string.length / 2;

  return 1;
}

BTC_UNUSED static json_value *
json_address_new(const btc_address_t *addr, const btc_network_t *network) {
  char str[BTC_ADDRESS_MAXLEN + 1];

  btc_address_get_str(str, addr, network);

  return json_string_new(str);
}

BTC_UNUSED static int
json_address_get(btc_address_t *addr,
                 const json_value *obj,
                 const btc_network_t *network) {
  if (obj->type != json_string)
    return 0;

  return btc_address_set_str(addr, obj->u.string.ptr, network);
}

BTC_UNUSED static json_value *
json_amount_new(int64_t x) {
  if ((x % BTC_COIN) == 0)
    return json_integer_new(x / BTC_COIN);

  return json_double_new(btc_amount_to_double(x));
}

BTC_UNUSED static int
json_amount_get(int64_t *z, const json_value *obj) {
  if (obj->type == json_integer) {
    int64_t x = obj->u.integer;

    if (x < 0 || x > (BTC_MAX_MONEY / BTC_COIN))
      return 0;

    *z = x * BTC_COIN;

    return 1;
  }

  if (obj->type == json_double) {
    int64_t x;

    if (!btc_amount_from_double(&x, obj->u.dbl))
      return 0;

    if (x < 0)
      return 0;

    *z = x;

    return 1;
  }

  if (obj->type == json_string) {
    int64_t x;

    if (!btc_amount_import(&x, obj->u.string.ptr))
      return 0;

    if (x < 0)
      return 0;

    *z = x;

    return 1;
  }

  return 0;
}

BTC_UNUSED static json_value *
json_netaddr_new(const btc_netaddr_t *addr) {
  char str[BTC_ADDRSTRLEN + 1];

  btc_netaddr_get_str(str, addr);

  return json_string_new(str);
}

BTC_UNUSED static int
json_netaddr_get(btc_netaddr_t *addr, const json_value *obj) {
  if (obj->type != json_string)
    return 0;

  return btc_netaddr_set_str(addr, obj->u.string.ptr);
}

BTC_UNUSED static json_value *
json_stack_new(const btc_stack_t *stack) {
  json_value *obj = json_array_new(stack->length);
  size_t i;

  for (i = 0; i < stack->length; i++)
    json_array_push(obj, json_buffer_new(stack->items[i]));

  return obj;
}

BTC_UNUSED static json_value *
json_script_type_new(const btc_script_t *script) {
  if (btc_script_is_p2pk(script))
    return json_string_new("pubkey");

  if (btc_script_is_p2pkh(script))
    return json_string_new("pubkeyhash");

  if (btc_script_is_p2sh(script))
    return json_string_new("scripthash");

  if (btc_script_is_multisig(script))
    return json_string_new("multisig");

  if (btc_script_is_nulldata(script))
    return json_string_new("nulldata");

  if (btc_script_is_p2wpkh(script))
    return json_string_new("witness_v0_keyhash");

  if (btc_script_is_p2wsh(script))
    return json_string_new("witness_v0_scripthash");

  if (btc_script_is_program(script))
    return json_string_new("witness_unknown");

  return json_string_new("nonstandard");
}

BTC_UNUSED static json_value *
json_script_asm_new(const btc_script_t *script) {
  char *str = btc_script_asm(script);
  size_t len = strlen(str);

  return json_string_new_nocopy(len, str);
}

BTC_UNUSED static json_value *
json_scriptsig_new(const btc_script_t *script) {
  json_value *obj = json_object_new(2);

  json_object_push(obj, "asm", json_script_asm_new(script));
  json_object_push(obj, "hex", json_buffer_new(script));

  return obj;
}

BTC_UNUSED static json_value *
json_script_new(const btc_script_t *script, const btc_network_t *network) {
  btc_address_t addr;
  size_t length = 3;
  int has_addr = 0;
  json_value *obj;

  if (btc_address_set_script(&addr, script)) {
    has_addr = 1;
    length += 1;
  }

  obj = json_object_new(length);

  json_object_push(obj, "asm", json_script_asm_new(script));
  json_object_push(obj, "hex", json_buffer_new(script));

  if (has_addr)
    json_object_push(obj, "address", json_address_new(&addr, network));

  json_object_push(obj, "type", json_script_type_new(script));

  return obj;
}

BTC_UNUSED static json_value *
json_coin_new(const btc_coin_t *coin, const btc_network_t *network) {
  json_value *obj = json_object_new(4);

  json_object_push(obj, "generated", json_boolean_new(coin->coinbase));
  json_object_push(obj, "height", json_integer_new(coin->height));
  json_object_push(obj, "value", json_amount_new(coin->output.value));
  json_object_push(obj, "scriptPubKey", json_script_new(&coin->output.script,
                                                        network));

  return obj;
}

BTC_UNUSED static json_value *
json_input_new(const btc_input_t *input,
               const btc_view_t *view,
               const btc_network_t *network) {
  const btc_coin_t *coin = NULL;
  size_t length = 0;
  json_value *obj;

  if (view != NULL)
    coin = btc_view_get(view, &input->prevout);

  if (btc_outpoint_is_null(&input->prevout))
    length += 1;
  else
    length += 3;

  if (input->witness.length > 0)
    length += 1;

  if (coin != NULL)
    length += 1;

  length += 1;

  obj = json_object_new(length);

  if (btc_outpoint_is_null(&input->prevout)) {
    json_object_push(obj, "coinbase", json_buffer_new(&input->script));
  } else {
    json_object_push(obj, "txid", json_hash_new(input->prevout.hash));
    json_object_push(obj, "vout", json_integer_new(input->prevout.index));
    json_object_push(obj, "scriptSig", json_scriptsig_new(&input->script));
  }

  if (input->witness.length > 0)
    json_object_push(obj, "txinwitness", json_stack_new(&input->witness));

  if (coin != NULL)
    json_object_push(obj, "prevout", json_coin_new(coin, network));

  json_object_push(obj, "sequence", json_integer_new(input->sequence));

  return obj;
}

BTC_UNUSED static json_value *
json_output_new(const btc_output_t *output,
                size_t index,
                const btc_network_t *network) {
  json_value *obj = json_object_new(3);

  json_object_push(obj, "value", json_amount_new(output->value));
  json_object_push(obj, "n", json_integer_new(index));
  json_object_push(obj, "scriptPubKey", json_script_new(&output->script,
                                                        network));

  return obj;
}

BTC_UNUSED static json_value *
json_txbase_new(const btc_tx_t *tx) {
  size_t size = btc_tx_base_size(tx);
  uint8_t *raw = btc_malloc(size);
  char *str = btc_malloc(size * 2 + 1);

  btc_tx_base_write(raw, tx);
  btc_base16_encode(str, raw, size);
  btc_free(raw);

  return json_string_new_nocopy(size * 2, str);
}

BTC_UNUSED static json_value *
json_txraw_new(const btc_tx_t *tx) {
  size_t size = btc_tx_size(tx);
  uint8_t *raw = btc_malloc(size);
  char *str = btc_malloc(size * 2 + 1);

  btc_tx_write(raw, tx);
  btc_base16_encode(str, raw, size);
  btc_free(raw);

  return json_string_new_nocopy(size * 2, str);
}

BTC_UNUSED static json_value *
json_tx_new_ex(const btc_tx_t *tx,
               const btc_view_t *view,
               const uint8_t *block,
               int include_hex,
               const btc_network_t *network) {
  json_value *obj, *vin, *vout;
  size_t base = btc_tx_base_size(tx);
  size_t wit = btc_tx_witness_size(tx);
  size_t size = base + wit;
  size_t weight = (base * BTC_WITNESS_SCALE_FACTOR) + wit;
  size_t vsize = weight;
  size_t length = 9;
  int64_t fee = -1;
  size_t i;

  vsize += (BTC_WITNESS_SCALE_FACTOR - 1);
  vsize /= BTC_WITNESS_SCALE_FACTOR;

  if (view != NULL) {
    fee = btc_tx_fee(tx, view);

    if (fee != -1)
      length += 1;
  }

  if (block != NULL)
    length += 1;

  if (include_hex)
    length += 1;

  obj = json_object_new(length);

  json_object_push(obj, "txid", json_hash_new(tx->hash));
  json_object_push(obj, "hash", json_hash_new(tx->whash));
  json_object_push(obj, "version", json_integer_new(tx->version));
  json_object_push(obj, "size", json_integer_new(size));
  json_object_push(obj, "vsize", json_integer_new(vsize));
  json_object_push(obj, "weight", json_integer_new(weight));
  json_object_push(obj, "locktime", json_integer_new(tx->locktime));

  vin = json_array_new(tx->inputs.length);

  for (i = 0; i < tx->inputs.length; i++)
    json_array_push(vin, json_input_new(tx->inputs.items[i], view, network));

  json_object_push(obj, "vin", vin);

  vout = json_array_new(tx->outputs.length);

  for (i = 0; i < tx->outputs.length; i++)
    json_array_push(vout, json_output_new(tx->outputs.items[i], i, network));

  json_object_push(obj, "vout", vout);

  if (fee != -1)
    json_object_push(obj, "fee", json_amount_new(fee));

  if (block != NULL)
    json_object_push(obj, "blockhash", json_hash_new(block));

  if (include_hex)
    json_object_push(obj, "hex", json_txraw_new(tx));

  return obj;
}

BTC_UNUSED static json_value *
json_tx_new(const btc_tx_t *tx,
            const btc_view_t *view,
            const btc_network_t *network) {
  return json_tx_new_ex(tx, view, NULL, 0, network);
}

BTC_UNUSED static json_value *
json_push_entry(json_value *obj,
                const btc_entry_t *entry,
                int confs,
                size_t ntx,
                const uint8_t *next) {
  const btc_header_t *hdr = &entry->header;
  int64_t mtp = btc_entry_median_time(entry);
  double diff = difficulty(hdr->bits);
  char hex[8 + 1];

  sprintf(hex, "%.8x", hdr->version);

  json_object_push(obj, "hash", json_hash_new(entry->hash));
  json_object_push(obj, "confirmations", json_integer_new(confs));
  json_object_push(obj, "height", json_integer_new(entry->height));
  json_object_push(obj, "version", json_integer_new(hdr->version));
  json_object_push(obj, "versionHex", json_string_new_length(8, hex));
  json_object_push(obj, "merkleroot", json_hash_new(hdr->merkle_root));
  json_object_push(obj, "time", json_integer_new(hdr->time));
  json_object_push(obj, "mediantime", json_integer_new(mtp));
  json_object_push(obj, "nonce", json_integer_new(hdr->nonce));
  json_object_push(obj, "bits", json_integer_new(hdr->bits));
  json_object_push(obj, "difficulty", json_double_new(diff));
  json_object_push(obj, "chainwork", json_hash_new(entry->chainwork));
  json_object_push(obj, "nTx", json_integer_new(ntx));
  json_object_push(obj, "previousblockhash", json_hash_new(hdr->prev_block));
  json_object_push(obj, "nextblockhash", json_hash_new(next));

  return obj;
}

BTC_UNUSED static json_value *
json_entry_new_ex(const btc_entry_t *entry, int confs, const uint8_t *next) {
  json_value *obj = json_object_new(15);
  return json_push_entry(obj, entry, confs, 0, next);
}

BTC_UNUSED static json_value *
json_entry_new(const btc_entry_t *entry) {
  return json_entry_new_ex(entry, 0, NULL);
}

BTC_UNUSED static json_value *
json_block_new_ex(const btc_block_t *block,
                  const btc_entry_t *entry,
                  const btc_view_t *view,
                  int confs,
                  const uint8_t *next,
                  int verbose,
                  const btc_network_t *network) {
  size_t base = btc_block_base_size(block);
  size_t wit = btc_block_witness_size(block);
  size_t size = base + wit;
  size_t weight = (base * BTC_WITNESS_SCALE_FACTOR) + wit;
  json_value *txs = json_array_new(block->txs.length);
  json_value *obj = json_object_new(19);
  size_t i;

  json_push_entry(obj, entry, confs, block->txs.length, next);

  json_object_push(obj, "strippedsize", json_integer_new(base));
  json_object_push(obj, "size", json_integer_new(size));
  json_object_push(obj, "weight", json_integer_new(weight));

  if (verbose) {
    for (i = 0; i < block->txs.length; i++)
      json_array_push(txs, json_tx_new(block->txs.items[i], view, network));
  } else {
    for (i = 0; i < block->txs.length; i++)
      json_array_push(txs, json_hash_new(block->txs.items[i]->hash));
  }

  json_object_push(obj, "tx", txs);

  return obj;
}

BTC_UNUSED static json_value *
json_block_new(const btc_block_t *block,
               const btc_view_t *view,
               const btc_network_t *network) {
  const btc_header_t *hdr = &block->header;
  size_t base = btc_block_base_size(block);
  size_t wit = btc_block_witness_size(block);
  size_t size = base + wit;
  size_t weight = (base * BTC_WITNESS_SCALE_FACTOR) + wit;
  json_value *txs = json_array_new(block->txs.length);
  json_value *obj = json_object_new(12);
  uint8_t hash[32];
  size_t i;

  btc_header_hash(hash, hdr);

  json_object_push(obj, "hash", json_hash_new(hash));
  json_object_push(obj, "version", json_integer_new(hdr->version));
  json_object_push(obj, "previousblockhash", json_hash_new(hdr->prev_block));
  json_object_push(obj, "merkleroot", json_hash_new(hdr->merkle_root));
  json_object_push(obj, "time", json_integer_new(hdr->time));
  json_object_push(obj, "bits", json_integer_new(hdr->bits));
  json_object_push(obj, "nonce", json_integer_new(hdr->nonce));
  json_object_push(obj, "strippedsize", json_integer_new(base));
  json_object_push(obj, "size", json_integer_new(size));
  json_object_push(obj, "weight", json_integer_new(weight));
  json_object_push(obj, "nTx", json_integer_new(block->txs.length));

  for (i = 0; i < block->txs.length; i++)
    json_array_push(txs, json_tx_new(block->txs.items[i], view, network));

  json_object_push(obj, "tx", txs);

  return obj;
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
};

static int
on_request(http_server_t *server, http_req_t *req, http_res_t *res);

btc_rpc_t *
btc_rpc_create(btc_node_t *node) {
  btc_rpc_t *rpc =
    (btc_rpc_t *)btc_malloc(sizeof(btc_rpc_t));

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

  rpc->http->on_request = on_request;
  rpc->http->data = rpc;

  return rpc;
}

void
btc_rpc_destroy(btc_rpc_t *rpc) {
  http_server_destroy(rpc->http);
  btc_free(rpc);
}

static void
btc_rpc_log(btc_rpc_t *rpc, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(rpc->logger, "rpc", fmt, ap);
  va_end(ap);
}

int
btc_rpc_open(btc_rpc_t *rpc) {
  btc_sockaddr_t addr;

  CHECK(btc_sockaddr_import(&addr, "127.0.0.1", rpc->network->rpc_port));

  btc_rpc_log(rpc, "Opening rpc.");

  if (!http_server_open(rpc->http, &addr))
    return 0;

  btc_rpc_log(rpc, "RPC listening on %S.", &addr);

  return 1;
}

void
btc_rpc_close(btc_rpc_t *rpc) {
  http_server_close(rpc->http);
}

/*
 * Methods
 */

static void
btc_rpc_getinfo(btc_rpc_t *rpc, const json_value *params, rpc_res_t *res) {
  json_value *result = json_object_new(1);

  (void)rpc;
  (void)params;

  json_object_push(result, "time", json_integer_new(btc_ms()));

  res->result = result;
}

/*
 * Registry
 */

static const struct {
  const char *method;
  void (*handler)(btc_rpc_t *,
                  const json_value *,
                  rpc_res_t *);
} btc_rpc_methods[] = {
  { "getinfo", btc_rpc_getinfo }
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

  if (index < 0) {
    rpc_res_error(res, RPC_METHOD_NOT_FOUND, "Method not found");
    return;
  }

  btc_rpc_log(rpc, "Incoming RPC request: %s.", req->method);

  btc_rpc_methods[index].handler(rpc, req->params, res);
}

static int
on_request(http_server_t *server, http_req_t *req, http_res_t *res) {
  btc_rpc_t *rpc = server->data;
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

  obj = json_parse(req->body.data, req->body.length);

  if (!rpc_req_set(&rreq, obj))
    rpc_res_error(&rres, RPC_INVALID_REQUEST, "Invalid request");
  else
    btc_rpc_handle(rpc, &rreq, &rres);

  if (obj != NULL)
    json_value_free(obj);

  obj = rpc_res_encode(&rres, rreq.id);

  http_res_header(res, "X-Long-Polling", "/?longpoll=1");
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

  if (index < 0)
    rpc_res_error(&res, RPC_METHOD_NOT_FOUND, "Method not found");
  else
    btc_rpc_methods[index].handler(rpc, params, &res);

  return rpc_res_encode(&res, 0);
}
