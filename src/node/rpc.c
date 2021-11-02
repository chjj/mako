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
  RPC_CLIENT_P2P_DISABLED = -31
};

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
