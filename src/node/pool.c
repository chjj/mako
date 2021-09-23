/*!
 * pool.c - p2p pool for libsatoshi
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <io/core.h>
#include <io/loop.h>

#include <node/addrman.h>
#include <node/chain.h>
#include <node/logger.h>
#include <node/pool.h>
#include <node/timedata.h>

#include <satoshi/block.h>
#include <satoshi/coins.h>
#include <satoshi/consensus.h>
#include <satoshi/crypto/hash.h>
#include <satoshi/crypto/rand.h>
#include <satoshi/entry.h>
#include <satoshi/header.h>
#include <satoshi/net.h>
#include <satoshi/netaddr.h>
#include <satoshi/netmsg.h>
#include <satoshi/network.h>
#include <satoshi/script.h>
#include <satoshi/tx.h>
#include <satoshi/util.h>
#include <satoshi/vector.h>

#include "../bio.h"
#include "../map.h"
#include "../impl.h"
#include "../internal.h"

/*
 * Constants
 */

enum btc_peer_state {
  BTC_PEER_CONNECTING,
  BTC_PEER_WAIT_VERSION,
  BTC_PEER_WAIT_VERACK,
  BTC_PEER_CONNECTED,
  BTC_PEER_DEAD
};

/*
 * Types
 */

KHASH_SET_INIT_HASH(hashes)
KHASH_MAP_INIT_HASH(times, int64_t)
KHASH_MAP_INIT_INT(types, int64_t)

typedef void parser_on_msg_cb(btc_msg_t *msg, void *arg);

typedef struct parser_s {
  uint32_t magic;
  uint8_t *pending;
  size_t alloc;
  size_t total;
  size_t waiting;
  /* Header */
  char cmd[12];
  int has_header;
  uint32_t checksum;
  /* Callback */
  parser_on_msg_cb *on_msg;
  void *arg;
} parser_t;

typedef struct btc_peer_s {
  struct btc_pool_s *pool;
  const btc_network_t *network;
  btc_logger_t *logger;
  btc_loop_t *loop;
  btc_socket_t *socket;
  parser_t parser;
  enum btc_peer_state state;
  unsigned int id;
  int outbound;
  int loader;
  btc_netaddr_t addr;
  btc_netaddr_t local;
  int64_t time;
  int64_t last_send;
  int64_t last_recv;
  int ban_score;
  uint32_t version;
  uint64_t services;
  int32_t height;
  char agent[256 + 1];
  int no_relay;
  int prefer_headers;
  uint8_t hash_continue[32];
  int64_t fee_rate;
  int compact_mode;
  int syncing;
  int sent_addr;
  int getting_addr;
  int sent_getaddr;
  uint64_t challenge;
  int64_t last_pong;
  int64_t last_ping;
  int64_t min_ping;
  int64_t block_time;
  uint8_t best_hash[32];
  int32_t best_height;
  uint8_t last_tip[32];
  uint8_t last_stop[32];
  int64_t ping_timer;
  int64_t inv_timer;
  int64_t stall_timer;
  /* btc_filter_t addr_filter; */
  /* btc_filter_t inv_filter; */
  khash_t(times) *block_map;
  khash_t(times) *tx_map;
  khash_t(times) *compact_map;
  khash_t(types) *response_map;
  struct btc_peer_s *prev;
  struct btc_peer_s *next;
} btc_peer_t;

KHASH_MAP_INIT_INT64(nonces, btc_netaddr_t *)
KHASH_MAP_INIT_CONST_NETADDR(hosts, uint64_t)

typedef struct btc_nonces_s {
  khash_t(nonces) *map; /* uint64_t -> btc_netaddr_t */
  khash_t(hosts) *hosts; /* btc_netaddr_t -> uint64_t */
} btc_nonces_t;

KHASH_MAP_INIT_CONST_NETADDR(addrs, btc_peer_t *)
KHASH_MAP_INIT_INT(ids, btc_peer_t *)

typedef struct btc_peers_s {
  khash_t(addrs) *map;
  khash_t(ids) *ids;
  btc_peer_t *head;
  btc_peer_t *tail;
  btc_peer_t *load;
  size_t inbound;
  size_t outbound;
  size_t size;
} btc_peers_t;

typedef struct btc_hdrentry_s {
  uint8_t hash[32];
  int32_t height;
  struct btc_hdrentry_s *next;
} btc_hdrentry_t;

struct btc_pool_s {
  const btc_network_t *network;
  btc_loop_t *loop;
  btc_logger_t *logger;
  btc_timedata_t *timedata;
  btc_addrman_t *addrman;
  btc_chain_t *chain;
  btc_mempool_t *mempool;
  btc_peers_t peers;
  btc_nonces_t nonces;
  /* btc_filter_t tx_filter; */
  khash_t(hashes) *block_map;
  khash_t(hashes) *tx_map;
  khash_t(hashes) *compact_map;
  int checkpoints;
  btc_hdrentry_t *header_chain;
  btc_hdrentry_t *header_next;
  btc_hdrentry_t *header_tip;
  int64_t refill_timer;
  unsigned int id;
  uint64_t required_services;
  size_t max_outbound;
  size_t max_inbound;
};

/*
 * Hash Set
 */

static khash_t(hashes) *
hashset_create(void) {
  khash_t(hashes) *map = kh_init(hashes);

  CHECK(map != NULL);

  return map;
}

static void
hashset_destroy(khash_t(hashes) *map) {
  kh_destroy(hashes, map);
}

static size_t
hashset_size(khash_t(hashes) *map) {
  return kh_size(map);
}

static int
hashset_has(khash_t(hashes) *map, const uint8_t *hash) {
  khiter_t it = kh_get(hashes, map, (uint8_t *)hash);
  return it != kh_end(map);
}

static int
hashset_put(khash_t(hashes) *map, uint8_t *hash) {
  int ret = -1;
  khiter_t it;

  it = kh_put(hashes, map, hash, &ret);

  CHECK(ret != -1);

  if (ret == 0) {
    CHECK(kh_key(map, it) != hash);
    return 0;
  }

  CHECK(kh_key(map, it) == hash);

  return 1;
}

static int
hashset_del(khash_t(hashes) *map, const uint8_t *hash) {
  khiter_t it = kh_get(hashes, map, (uint8_t *)hash);

  if (it == kh_end(map))
    return 0;

  kh_del(hashes, map, it);

  return 1;
}

/*
 * Time Map (hash->time)
 */

static khash_t(times) *
timemap_create(void) {
  khash_t(times) *map = kh_init(times);

  CHECK(map != NULL);

  return map;
}

static void
timemap_destroy(khash_t(times) *map) {
  kh_destroy(times, map);
}

static size_t
timemap_size(khash_t(times) *map) {
  return kh_size(map);
}

static int
timemap_has(khash_t(times) *map, const uint8_t *hash) {
  khiter_t it = kh_get(times, map, (uint8_t *)hash);
  return it != kh_end(map);
}

static int64_t
timemap_get(khash_t(times) *map, const uint8_t *hash) {
  khiter_t it = kh_get(times, map, (uint8_t *)hash);

  if (it == kh_end(map))
    return -1;

  return kh_value(map, it);
}

static int
timemap_put(khash_t(times) *map, uint8_t *hash, int64_t ts) {
  int ret = -1;
  khiter_t it;

  it = kh_put(times, map, hash, &ret);

  CHECK(ret != -1);

  if (ret == 0)
    return 0;

  kh_value(map, it) = ts;

  return 1;
}

static int
timemap_del(khash_t(times) *map, const uint8_t *hash) {
  khiter_t it = kh_get(times, map, (uint8_t *)hash);

  if (it == kh_end(map))
    return 0;

  kh_del(times, map, it);

  return 1;
}

/*
 * Type Map (type->time)
 */

static khash_t(types) *
typemap_create(void) {
  khash_t(types) *map = kh_init(types);

  CHECK(map != NULL);

  return map;
}

static void
typemap_destroy(khash_t(types) *map) {
  kh_destroy(types, map);
}

static size_t
typemap_size(khash_t(types) *map) {
  return kh_size(map);
}

static int
typemap_put(khash_t(types) *map, int type, int64_t ts) {
  int ret = -1;
  khiter_t it;

  it = kh_put(types, map, type, &ret);

  CHECK(ret != -1);

  if (ret == 0)
    return 0;

  kh_value(map, it) = ts;

  return 1;
}

static int
typemap_has(khash_t(types) *map, int type) {
  khiter_t it = kh_get(types, map, type);
  return it != kh_end(map);
}

static int64_t
typemap_get(khash_t(types) *map, int type) {
  khiter_t it = kh_get(types, map, type);

  if (it == kh_end(map))
    return -1;

  return kh_value(map, it);
}

/*
 * Nonce List
 */

static void
btc_nonces_init(btc_nonces_t *list) {
  list->map = kh_init(nonces);
  list->hosts = kh_init(hosts);

  CHECK(list->map != NULL);
  CHECK(list->hosts != NULL);
}

static void
btc_nonces_clear(btc_nonces_t *list) {
  kh_destroy(hosts, list->hosts);
  kh_destroy(nonces, list->map);

  list->hosts = NULL;
  list->map = NULL;
}

static int
btc_nonces_has(btc_nonces_t *list, uint64_t nonce) {
  khiter_t it = kh_get(nonces, list->map, nonce);
  return it != kh_end(list->map);
}

static uint64_t
btc_nonces_alloc(btc_nonces_t *list, const btc_netaddr_t *addr_) {
  btc_netaddr_t *addr = btc_netaddr_clone(addr_);
  uint64_t nonce;
  int ret = -1;
  khiter_t it;

  for (;;) {
    nonce = ((uint64_t)btc_random() << 32) | btc_random();

    it = kh_put(nonces, list->map, nonce, &ret);

    CHECK(ret != -1);

    if (ret == 0)
      continue;

    kh_value(list->map, it) = addr;

    it = kh_put(hosts, list->hosts, addr, &ret);

    CHECK(ret > 0);

    kh_value(list->hosts, it) = nonce;

    return nonce;
  }
}

static int
btc_nonces_remove(btc_nonces_t *list, const btc_netaddr_t *addr) {
  khiter_t it = kh_get(hosts, list->hosts, addr);
  uint64_t nonce;

  if (it == kh_end(list->hosts))
    return 0;

  nonce = kh_value(list->hosts, it);

  kh_del(hosts, list->hosts, it);

  it = kh_get(nonces, list->map, nonce);

  CHECK(it != kh_end(list->map));

  kh_del(nonces, list->map, it);

  return 1;
}

/*
 * Parser
 */

static void
parser_init(parser_t *parser, uint32_t magic) {
  parser->magic = magic;
  parser->pending = NULL;
  parser->alloc = 0;
  parser->total = 0;
  parser->waiting = 24;
  parser->cmd[0] = '\0';
  parser->has_header = 0;
  parser->checksum = 0;
  parser->on_msg = NULL;
  parser->arg = NULL;
}

static void
parser_clear(parser_t *parser) {
  if (parser->alloc > 0)
    free(parser->pending);

  parser->pending = NULL;
}

static void
parser_on_msg(parser_t *parser, parser_on_msg_cb *handler, void *arg) {
  parser->on_msg = handler;
  parser->arg = arg;
}

static uint8_t *
parser_append(parser_t *parser, const uint8_t *data, size_t length) {
  if (parser->total + length > parser->alloc) {
    void *ptr = realloc(parser->pending, parser->total + length);

    CHECK(ptr != NULL);

    parser->pending = (uint8_t *)ptr;
    parser->alloc = parser->total + length;
  }

  if (length > 0)
    memcpy(parser->pending + parser->total, data, length);

  parser->total += length;

  return parser->pending;
}

static int
parser_parse_header(parser_t *parser, const uint8_t *data) {
  size_t i, size;

  if (read32le(data) != parser->magic)
    return 0;

  for (i = 0; data[i + 4] != 0 && i < 12; i++);

  if (i == 12)
    return 0;

  memcpy(parser->cmd, data + 4, i + 1);

  size = read32le(data + 16);

  if (size > BTC_NET_MAX_MESSAGE) {
    parser->waiting = 24;
    return 0;
  }

  parser->waiting = size;
  parser->checksum = read32le(data + 20);
  parser->has_header = 1;

  return 1;
}

static int
parser_parse(parser_t *parser, const uint8_t *data, size_t length) {
  uint8_t hash[32];
  btc_msg_t *msg;

  CHECK(length <= BTC_NET_MAX_MESSAGE);

  if (!parser->has_header) {
    CHECK(length == 24);
    return parser_parse_header(parser, data);
  }

  btc_hash256(hash, data, length);

  if (read32le(hash) != parser->checksum) {
    parser->waiting = 24;
    parser->has_header = 0;
    return 0;
  }

  msg = btc_msg_create();

  btc_msg_set_cmd(msg, parser->cmd);
  btc_msg_alloc(msg);

  if (!btc_msg_import(msg, data, length)) {
    btc_msg_destroy(msg);
    parser->waiting = 24;
    parser->has_header = 0;
    return 0;
  }

  parser->waiting = 24;
  parser->has_header = 0;
  parser->on_msg(msg, parser->arg);

  return 1;
}

static int
parser_feed(parser_t *parser, const uint8_t *data, size_t length) {
  uint8_t *ptr = parser_append(parser, data, length);
  size_t len = parser->total;
  size_t wait;

  while (len >= parser->waiting) {
    wait = parser->waiting;

    if (!parser_parse(parser, ptr, wait)) {
      parser->total = len;
      return 0;
    }

    ptr += wait;
    len -= wait;
  }

  if (len > 0 && ptr != parser->pending)
    memmove(parser->pending, ptr, len);

  parser->total = len;

  return 1;
}

/*
 * Events
 */

static void
btc_pool_on_tick(struct btc_pool_s *pool);

static void
btc_pool_on_socket(struct btc_pool_s *pool, btc_socket_t *socket);

static void
btc_peer_on_tick(btc_peer_t *peer);

static void
btc_peer_on_connect(btc_peer_t *peer);

static void
btc_peer_on_disconnect(btc_peer_t *peer);

static void
btc_peer_on_error(btc_peer_t *peer, const char *msg);

static void
btc_peer_on_data(btc_peer_t *peer, const uint8_t *data, size_t size);

static void
btc_peer_on_drain(btc_peer_t *peer);

static void
btc_peer_on_msg(btc_peer_t *peer, btc_msg_t *msg);

static void
on_socket(btc_socket_t *socket) {
  btc_loop_t *loop = btc_socket_loop(socket);
  struct btc_pool_s *pool = (struct btc_pool_s *)btc_loop_get_data(loop, 0);

  btc_pool_on_socket(pool, socket);
}

static void
on_tick(btc_loop_t *loop) {
  struct btc_pool_s *pool = (struct btc_pool_s *)btc_loop_get_data(loop, 0);
  btc_peer_t *peer, *next;

  for (peer = pool->peers.head; peer != NULL; peer = next) {
    next = peer->next;
    btc_peer_on_tick(peer);
  }

  btc_pool_on_tick(pool);
}

static void
on_connect(btc_socket_t *socket) {
  btc_peer_on_connect((btc_peer_t *)btc_socket_get_data(socket));
}

static void
on_disconnect(btc_socket_t *socket) {
  btc_peer_on_disconnect((btc_peer_t *)btc_socket_get_data(socket));
}

static void
on_error(btc_socket_t *socket) {
  btc_peer_on_error((btc_peer_t *)btc_socket_get_data(socket),
                    btc_socket_strerror(socket));
}

static void
on_data(btc_socket_t *socket, const uint8_t *data, size_t size) {
  btc_peer_on_data((btc_peer_t *)btc_socket_get_data(socket), data, size);
}

static void
on_drain(btc_socket_t *socket) {
  btc_peer_on_drain((btc_peer_t *)btc_socket_get_data(socket));
}

static void
on_msg(btc_msg_t *msg, void *arg) {
  btc_peer_on_msg((btc_peer_t *)arg, msg);
}

/*
 * Peer
 */

static btc_peer_t *
btc_peer_create(struct btc_pool_s *pool) {
  btc_peer_t *peer = (btc_peer_t *)btc_malloc(sizeof(btc_peer_t));

  memset(peer, 0, sizeof(*peer));

  peer->pool = pool;
  peer->network = pool->network;
  peer->logger = pool->logger;
  peer->loop = pool->loop;
  peer->socket = NULL;

  peer->state = BTC_PEER_DEAD;
  peer->id = pool->id++;
  peer->version = -1;
  peer->height = -1;
  peer->fee_rate = -1;
  peer->compact_mode = -1;
  peer->last_pong = -1;
  peer->last_ping = -1;
  peer->min_ping = -1;
  peer->block_time = -1;
  peer->best_height = -1;

  parser_init(&peer->parser, peer->network->magic);
  parser_on_msg(&peer->parser, on_msg, peer);

  peer->block_map = timemap_create();
  peer->tx_map = timemap_create();
  peer->compact_map = timemap_create();
  peer->response_map = typemap_create();

  return peer;
}

static void
btc_peer_destroy(btc_peer_t *peer) {
  khiter_t it;

  parser_clear(&peer->parser);

  it = kh_begin(peer->block_map);

  for (; it != kh_end(peer->block_map); it++) {
    if (kh_exist(peer->block_map, it))
      btc_free(kh_key(peer->block_map, it));
  }

  it = kh_begin(peer->tx_map);

  for (; it != kh_end(peer->tx_map); it++) {
    if (kh_exist(peer->tx_map, it))
      btc_free(kh_key(peer->tx_map, it));
  }

  it = kh_begin(peer->compact_map);

  for (; it != kh_end(peer->compact_map); it++) {
    if (kh_exist(peer->compact_map, it))
      btc_free(kh_key(peer->compact_map, it));
  }

  timemap_destroy(peer->block_map);
  timemap_destroy(peer->tx_map);
  timemap_destroy(peer->compact_map);
  typemap_destroy(peer->response_map);

  btc_free(peer);
}

static void
btc_peer_log(btc_peer_t *peer, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(peer->logger, "peer", fmt, ap);
  va_end(ap);
}

static int
btc_peer_open(btc_peer_t *peer, const btc_netaddr_t *addr) {
  btc_socket_t *socket;
  btc_sockaddr_t sa;

  btc_netaddr_get_sockaddr(&sa, addr);

  socket = btc_loop_connect(peer->loop, &sa);

  if (socket == NULL)
    return 0;

  peer->state = BTC_PEER_CONNECTING;
  /* peer->state_time = btc_ms(); */
  peer->socket = socket;
  peer->addr = *addr;
  peer->outbound = 1;

  btc_socket_set_data(socket, peer);
  btc_socket_on_connect(socket, on_connect);
  btc_socket_on_disconnect(socket, on_disconnect);
  btc_socket_on_error(socket, on_error);
  btc_socket_on_data(socket, on_data);
  btc_socket_on_drain(socket, on_drain);

  return 1;
}

static int
btc_peer_accept(btc_peer_t *peer, btc_socket_t *socket) {
  btc_sockaddr_t sa;

  btc_socket_address(&sa, socket);

  /* We're shy. Wait for an introduction. */
  peer->state = BTC_PEER_WAIT_VERSION;
  peer->socket = socket;

  btc_netaddr_set_sockaddr(&peer->addr, &sa);

  peer->outbound = 0;

  btc_socket_set_data(socket, peer);
  btc_socket_on_connect(socket, on_connect);
  btc_socket_on_disconnect(socket, on_disconnect);
  btc_socket_on_error(socket, on_error);
  btc_socket_on_data(socket, on_data);
  btc_socket_on_drain(socket, on_drain);

  btc_peer_log(peer, "Connected to %N.", &peer->addr);

  return 1;
}

static void
btc_peer_close(btc_peer_t *peer) {
  btc_socket_kill(peer->socket);
  peer->state = BTC_PEER_DEAD;
}

static int
btc_peer_write(btc_peer_t *peer, uint8_t *data, size_t length) {
  return btc_socket_write(peer->socket, data, length);
}

static int
btc_peer_send(btc_peer_t *peer, const btc_msg_t *msg) {
  size_t cmdlen = strlen(msg->cmd);
  size_t bodylen = btc_msg_size(msg);
  size_t length = 24 + bodylen;
  uint8_t *data = (uint8_t *)btc_malloc(length);
  uint8_t *body = data + 24;
  uint8_t hash[32];
  size_t i;

  btc_msg_export(body, msg);
  btc_hash256(hash, body, bodylen);

  /* Magic value. */
  btc_uint32_write(data, peer->network->magic);

  /* Command. */
  memcpy(data + 4, msg->cmd, cmdlen);

  for (i = 4 + cmdlen; i < 16; i++)
    data[i] = 0;

  /* Payload length. */
  btc_uint32_write(data + 16, bodylen);

  /* Checksum. */
  memcpy(data + 20, hash, 4);

  return btc_socket_write(peer->socket, data, length);
}

static int
btc_peer_send_version(btc_peer_t *peer) {
  btc_version_t body;
  btc_msg_t msg;

  btc_version_init(&body);

  body.version = BTC_NET_PROTOCOL_VERSION;
  body.services = BTC_NET_LOCAL_SERVICES;
  body.time = btc_timedata_now(peer->pool->timedata);
  body.remote = peer->addr;
  btc_netaddr_init(&body.local);
  body.local.services = BTC_NET_LOCAL_SERVICES;
  body.nonce = btc_nonces_alloc(&peer->pool->nonces, &peer->addr);
  strcpy(body.agent, BTC_NET_USER_AGENT);
  body.height = btc_chain_height(peer->pool->chain);
  body.no_relay = 0;

  btc_msg_set_type(&msg, BTC_MSG_VERSION);

  msg.body = &body;

  return btc_peer_send(peer, &msg);
}

static int
btc_peer_send_verack(btc_peer_t *peer) {
  btc_msg_t msg;

  btc_msg_set_type(&msg, BTC_MSG_VERACK);

  msg.body = NULL;

  return btc_peer_send(peer, &msg);
}

static int
btc_peer_send_ping(btc_peer_t *peer) {
  btc_ping_t ping;
  btc_msg_t msg;

  if (peer->state != BTC_PEER_CONNECTED)
    return 1;

  if (peer->challenge != 0) {
    btc_peer_log(peer, "Peer has not responded to ping (%N).", &peer->addr);
    return 1;
  }

  peer->last_ping = btc_ms();
  peer->challenge = ((uint64_t)btc_random() << 32) | btc_random();

  ping.nonce = peer->challenge;

  btc_msg_set_type(&msg, BTC_MSG_PING);

  msg.body = &ping;

  return btc_peer_send(peer, &msg);
}

static int
btc_peer_send_pong(btc_peer_t *peer, uint64_t nonce) {
  btc_pong_t pong;
  btc_msg_t msg;

  pong.nonce = nonce;

  btc_msg_set_type(&msg, BTC_MSG_PONG);

  msg.body = &pong;

  return btc_peer_send(peer, &msg);
}

static int
btc_peer_send_getaddr(btc_peer_t *peer) {
  btc_msg_t msg;

  if (peer->sent_getaddr)
    return 1;

  peer->sent_getaddr = 1;

  btc_msg_set_type(&msg, BTC_MSG_GETADDR);

  msg.body = NULL;

  return btc_peer_send(peer, &msg);
}

static int
btc_peer_send_addr(btc_peer_t *peer, const btc_addrs_t *body) {
  btc_msg_t msg;

  btc_msg_set_type(&msg, BTC_MSG_ADDR);

  msg.body = (void *)body;

  return btc_peer_send(peer, &msg);
}

static int
btc_peer_send_getblocks(btc_peer_t *peer,
                        const btc_vector_t *locator,
                        const uint8_t *stop) {
  btc_getblocks_t body;
  btc_msg_t msg;

  body.version = BTC_NET_PROTOCOL_VERSION;
  body.locator = *locator;

  if (stop != NULL)
    btc_hash_copy(body.stop, stop);
  else
    btc_hash_init(body.stop);

  btc_msg_set_type(&msg, BTC_MSG_GETBLOCKS);

  msg.body = &body;

  return btc_peer_send(peer, &msg);
}

static int
btc_peer_send_getdata(btc_peer_t *peer, const btc_inv_t *body) {
  btc_msg_t msg;

  btc_msg_set_type(&msg, BTC_MSG_GETDATA);

  msg.body = (void *)body;

  return btc_peer_send(peer, &msg);
}

static void
btc_peer_on_tick(btc_peer_t *peer) {
  int64_t now = btc_ms();

  if (now - peer->ping_timer >= 30000) {
    btc_peer_send_ping(peer);
    peer->ping_timer = now;
  }

#if 0
  if (now - peer->stall_timer >= 5000)
    ; /* TODO: do stall checks */
#endif
}

static void
btc_pool_on_connect(struct btc_pool_s *pool, btc_peer_t *peer);

static void
btc_peer_on_connect(btc_peer_t *peer) {
  if (peer->outbound) {
    /* Say hello. */
    btc_peer_send_version(peer);
  } else {
    /* We're shy. Wait for an introduction. */
  }

  peer->state = BTC_PEER_WAIT_VERSION;

  btc_pool_on_connect(peer->pool, peer);
}

static void
btc_pool_on_disconnect(struct btc_pool_s *pool, btc_peer_t *peer);

static void
btc_peer_on_disconnect(btc_peer_t *peer) {
  btc_pool_on_disconnect(peer->pool, peer);
}

static void
btc_pool_on_complete(struct btc_pool_s *pool, btc_peer_t *peer);

static int
btc_peer_on_version(btc_peer_t *peer, const btc_version_t *msg) {
  if (peer->state != BTC_PEER_WAIT_VERSION) {
    btc_peer_log(peer, "Peer sent unsolicited version (%N).", &peer->addr);
    btc_peer_close(peer);
    return 0;
  }

  peer->version = msg->version;
  peer->services = msg->services;
  peer->height = msg->height;
  strcpy(peer->agent, msg->agent);
  peer->no_relay = msg->no_relay;
  peer->local = msg->remote;

  if (!peer->network->self_connect) {
    if (btc_nonces_has(&peer->pool->nonces, msg->nonce)) {
      btc_peer_log(peer, "We connected to ourself. Oops (%N).", &peer->addr);
      btc_peer_close(peer);
      return 0;
    }
  }

  if (peer->version < BTC_NET_MIN_VERSION) {
    btc_peer_log(peer, "Peer does not support required protocol version (%N).",
                       &peer->addr);
    btc_peer_close(peer);
    return 0;
  }

  if (peer->outbound) {
    if ((peer->services & BTC_NET_SERVICE_NETWORK) == 0) {
      btc_peer_log(peer, "Peer does not support network services (%N).",
                         &peer->addr);
      btc_peer_close(peer);
      return 0;
    }
  }

  if (!peer->outbound)
    btc_peer_send_version(peer);

  btc_peer_send_verack(peer);

  peer->state = BTC_PEER_WAIT_VERACK;

  return 1;
}

static int
btc_peer_on_verack(btc_peer_t *peer) {
  if (peer->state != BTC_PEER_WAIT_VERACK) {
    btc_peer_log(peer, "Peer sent unsolicited verack (%N).", &peer->addr);
    btc_peer_close(peer);
    return 0;
  }

  peer->state = BTC_PEER_CONNECTED;

  btc_peer_log(peer, "Version handshake complete (%N).", &peer->addr);
  btc_pool_on_complete(peer->pool, peer);

  return 1;
}

static void
btc_peer_on_ping(btc_peer_t *peer, const btc_ping_t *msg) {
  if (msg->nonce == 0)
    return;

  btc_peer_send_pong(peer, msg->nonce);
}

static void
btc_peer_on_pong(btc_peer_t *peer, const btc_pong_t *msg) {
  int64_t now = btc_ms();

  if (peer->challenge == 0) {
    btc_peer_log(peer, "Peer sent an unsolicited pong (%N).", &peer->addr);
    return;
  }

  if (msg->nonce != peer->challenge) {
    if (msg->nonce == 0) {
      btc_peer_log(peer, "Peer sent a zero nonce (%N).", &peer->addr);
      peer->challenge = 0;
      return;
    }
    btc_peer_log(peer, "Peer sent the wrong nonce (%N).", &peer->addr);
    return;
  }

  if (now >= peer->last_ping) {
    peer->last_pong = now;

    if (peer->min_ping == -1)
      peer->min_ping = now - peer->last_ping;

    now -= peer->last_ping;

    if (now < peer->min_ping)
      peer->min_ping = now;
  } else {
    btc_peer_log(peer, "Timing mismatch (what?) (%N).", &peer->addr);
  }

  peer->challenge = 0;
}

static void
btc_peer_on_sendheaders(btc_peer_t *peer) {
  if (peer->prefer_headers) {
    btc_peer_log(peer, "Peer sent a duplicate sendheaders (%N).", &peer->addr);
    return;
  }

  peer->prefer_headers = 1;
}

static int
btc_peer_on_feefilter(btc_peer_t *peer, const btc_feefilter_t *msg) {
  if (msg->rate < 0 || msg->rate > BTC_MAX_MONEY) {
    /* btc_peer_increase_ban(peer, 100); */
    btc_peer_close(peer);
    return 0;
  }

  peer->fee_rate = msg->rate;

  return 1;
}

static void
btc_peer_on_sendcmpct(btc_peer_t *peer, const btc_sendcmpct_t *msg) {
  if (peer->compact_mode != -1) {
    btc_peer_log(peer, "Peer sent a duplicate sendcmpct (%N).", &peer->addr);
    return;
  }

  if (msg->version > 1) {
    /* Ignore. */
    btc_peer_log(peer, "Peer requested compact blocks version %llu (%N).",
                       msg->version, &peer->addr);
    return;
  }

  if (msg->mode > 1) {
    /* Ignore. */
    btc_peer_log(peer, "Peer requested compact blocks mode %hhu (%N).",
                       msg->mode, &peer->addr);
    return;
  }

  btc_peer_log(peer,
    "Peer initialized compact blocks (mode=%hhu, version=%llu) (%N).",
    msg->mode, msg->version, &peer->addr);

  peer->compact_mode = msg->mode;
}

static void
btc_peer_on_error(btc_peer_t *peer, const char *msg) {
  btc_peer_log(peer, "Socket error (%N): %s", &peer->addr, msg);
  btc_peer_close(peer);
}

static void
btc_peer_on_data(btc_peer_t *peer, const uint8_t *data, size_t size) {
  if (!parser_feed(&peer->parser, data, size)) {
    btc_peer_log(peer, "Parse error (%N).", &peer->addr);
    btc_peer_close(peer);
  }
}

static void
btc_peer_on_drain(btc_peer_t *peer) {
  (void)peer;
}

static void
btc_pool_on_msg(struct btc_pool_s *pool, btc_peer_t *peer, btc_msg_t *msg);

static void
btc_peer_on_msg(btc_peer_t *peer, btc_msg_t *msg) {
  switch (msg->type) {
    case BTC_MSG_VERSION:
      if (!btc_peer_on_version(peer, (btc_version_t *)msg->body)) {
        btc_msg_destroy(msg);
        return;
      }
      break;
    case BTC_MSG_VERACK:
      if (!btc_peer_on_verack(peer)) {
        btc_msg_destroy(msg);
        return;
      }
      break;
    case BTC_MSG_PING:
      btc_peer_on_ping(peer, (btc_ping_t *)msg->body);
      break;
    case BTC_MSG_PONG:
      btc_peer_on_pong(peer, (btc_pong_t *)msg->body);
      break;
    case BTC_MSG_SENDHEADERS:
      btc_peer_on_sendheaders(peer);
      break;
    case BTC_MSG_FEEFILTER:
      if (!btc_peer_on_feefilter(peer, (btc_feefilter_t *)msg->body)) {
        btc_msg_destroy(msg);
        return;
      }
      break;
    case BTC_MSG_SENDCMPCT:
      btc_peer_on_sendcmpct(peer, (btc_sendcmpct_t *)msg->body);
      break;
    default:
      break;
  }
  btc_pool_on_msg(peer->pool, peer, msg);
}

/**
 * Peer List
 */

static void
btc_peers_init(btc_peers_t *list) {
  list->map = kh_init(addrs);
  list->ids = kh_init(ids);
  list->head = NULL;
  list->tail = NULL;
  list->load = NULL;
  list->inbound = 0;
  list->outbound = 0;
  list->size = 0;

  CHECK(list->map != NULL);
  CHECK(list->ids != NULL);
}

static void
btc_peers_clear(btc_peers_t *list) {
  kh_destroy(addrs, list->map);
  kh_destroy(ids, list->ids);
}

static void
btc_peers_add(btc_peers_t *list, btc_peer_t *peer) {
  int ret = -1;
  khiter_t it;

  if (list->head == NULL)
    list->head = peer;

  if (list->tail != NULL)
    list->tail->next = peer;

  peer->prev = list->tail;
  peer->next = NULL;

  list->tail = peer;

  it = kh_put(addrs, list->map, &peer->addr, &ret);

  CHECK(ret > 0);

  kh_value(list->map, it) = peer;

  it = kh_put(ids, list->ids, peer->id, &ret);

  CHECK(ret > 0);

  kh_value(list->ids, it) = peer;

  if (peer->outbound)
    list->outbound += 1;
  else
    list->inbound += 1;

  list->size += 1;
}

static void
btc_peers_remove(btc_peers_t *list, btc_peer_t *peer) {
  khiter_t it;

  if (list->head == peer)
    list->head = peer->next;

  if (list->tail == peer)
    list->tail = peer->prev != NULL ? peer->prev : list->head;

  if (peer->prev != NULL)
    peer->prev->next = peer->next;

  if (peer->next != NULL)
    peer->next->prev = peer->prev;

  peer->prev = NULL;
  peer->next = NULL;

  it = kh_get(addrs, list->map, &peer->addr);

  CHECK(it != kh_end(list->map));

  kh_del(addrs, list->map, it);

  it = kh_get(ids, list->ids, peer->id);

  CHECK(it != kh_end(list->ids));

  kh_del(ids, list->ids, it);

  if (peer == list->load) {
    CHECK(peer->loader == 1);
    peer->loader = 0;
    list->load = NULL;
  }

  if (peer->outbound)
    list->outbound -= 1;
  else
    list->inbound -= 1;

  list->size -= 1;
}

static int
btc_peers_has(btc_peers_t *list, const btc_netaddr_t *addr) {
  khiter_t it = kh_get(addrs, list->map, addr);
  return it != kh_end(list->map);
}

static btc_peer_t *
btc_peers_get(btc_peers_t *list, const btc_netaddr_t *addr) {
  khiter_t it = kh_get(addrs, list->map, addr);

  if (it == kh_end(list->map))
    return NULL;

  return kh_value(list->map, it);
}

static btc_peer_t *
btc_peers_find(btc_peers_t *list, uint32_t id) {
  khiter_t it = kh_get(ids, list->ids, id);

  if (it == kh_end(list->ids))
    return NULL;

  return kh_value(list->ids, it);
}

static void
btc_peers_close(btc_peers_t *list) {
  btc_peer_t *peer, *next;

  for (peer = list->head; peer != NULL; peer = next) {
    next = peer->next;
    btc_peer_close(peer);
  }
}

/*
 * Pool
 */

struct btc_pool_s *
btc_pool_create(const btc_network_t *network,
                btc_loop_t *loop,
                btc_chain_t *chain,
                btc_mempool_t *mempool) {
  struct btc_pool_s *pool =
    (struct btc_pool_s *)btc_malloc(sizeof(struct btc_pool_s));

  memset(pool, 0, sizeof(*pool));

  pool->network = network;
  pool->loop = loop;
  pool->logger = NULL;
  pool->timedata = NULL;
  pool->addrman = btc_addrman_create(network);
  pool->chain = chain;
  pool->mempool = mempool;
  btc_peers_init(&pool->peers);
  btc_nonces_init(&pool->nonces);
  pool->block_map = hashset_create();
  pool->tx_map = hashset_create();
  pool->compact_map = hashset_create();
  pool->checkpoints = 0;
  pool->header_chain = NULL;
  pool->header_next = NULL;
  pool->header_tip = NULL;
  pool->refill_timer = 0;
  pool->id = 0;
  pool->required_services = BTC_NET_LOCAL_SERVICES;
  pool->max_outbound = 8;
  pool->max_inbound = 8;

  btc_loop_set_data(loop, 0, pool);
  btc_loop_on_tick(loop, on_tick);
  /* btc_loop_on_socket(loop, on_socket); */

  return pool;
}

void
btc_pool_destroy(struct btc_pool_s *pool) {
  btc_addrman_destroy(pool->addrman);
  btc_peers_clear(&pool->peers);
  btc_nonces_clear(&pool->nonces);
  hashset_destroy(pool->block_map);
  hashset_destroy(pool->tx_map);
  hashset_destroy(pool->compact_map);
  btc_free(pool);
}

void
btc_pool_set_logger(struct btc_pool_s *pool, btc_logger_t *logger) {
  pool->logger = logger;
  btc_addrman_set_logger(pool->addrman, logger);
}

void
btc_pool_set_timedata(struct btc_pool_s *pool, btc_timedata_t *td) {
  pool->timedata = td;
  btc_addrman_set_timedata(pool->addrman, td);
}

static void
btc_pool_log(struct btc_pool_s *pool, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  btc_logger_write(pool->logger, "pool", fmt, ap);
  va_end(ap);
}

int
btc_pool_open(struct btc_pool_s *pool) {
  btc_pool_log(pool, "Opening pool.");

  if (!btc_addrman_open(pool->addrman))
    return 0;

  return 1;
}

void
btc_pool_close(struct btc_pool_s *pool) {
  btc_addrman_close(pool->addrman);
}

static const btc_netaddr_t *
btc_pool_get_addr(struct btc_pool_s *pool) {
  /* int64_t now = btc_timedata_now(pool->timedata); */
  const btc_netaddr_t *addr;
  int i;

  for (i = 0; i < 100; i++) {
    addr = btc_addrman_get(pool->addrman);

    if (addr == NULL)
      break;

    if (btc_peers_has(&pool->peers, addr))
      continue;

#if 0
    if (btc_addrman_has_local(pool->addrman, addr))
      continue;
#endif

    if (btc_addrman_is_banned(pool->addrman, addr))
      continue;

    if (!btc_netaddr_is_valid(addr))
      continue;

    if ((addr->services & pool->required_services) != pool->required_services)
      continue;

    if (btc_netaddr_is_onion(addr))
      continue;

#if 0
    if (i < 30 && now - entry->last_attempt < 600)
      continue;
#endif

    if (i < 50 && addr->port != pool->network->port)
      continue;

    return addr;
  }

  return NULL;
}

static btc_peer_t *
btc_pool_create_outbound(struct btc_pool_s *pool, const btc_netaddr_t *addr) {
  btc_peer_t *peer = btc_peer_create(pool);

  btc_addrman_mark_attempt(pool->addrman, addr);

  btc_pool_log(pool, "Connecting to %N.", addr);

  if (!btc_peer_open(peer, addr)) {
    const char *msg = btc_loop_strerror(pool->loop);

    btc_pool_log(pool, "Connection failed: %s (%N).", msg, addr);
    btc_peer_destroy(peer);

    return NULL;
  }

  return peer;
}

static int
btc_pool_add_outbound(struct btc_pool_s *pool) {
  const btc_netaddr_t *addr;
  btc_peer_t *peer;

  if (pool->peers.outbound >= pool->max_outbound)
    return 0;

  /* Hang back if we don't have a loader peer yet. */
  if (pool->peers.load == NULL)
    return 0;

  addr = btc_pool_get_addr(pool);

  if (addr == NULL)
    return 0;

  peer = btc_pool_create_outbound(pool, addr);

  if (peer == NULL)
    return 0;

  btc_peers_add(&pool->peers, peer);

  return 1;
}

static int
btc_pool_is_syncable(struct btc_pool_s *pool, btc_peer_t *peer) {
  if (peer->state != BTC_PEER_CONNECTED)
    return 0;

  if ((peer->services & BTC_NET_SERVICE_NETWORK) == 0)
    return 0;

  if (!peer->loader) {
    if (!btc_chain_synced(pool->chain))
      return 0;
  }

  return 1;
}

static int
btc_pool_send_locator(struct btc_pool_s *pool,
                      const btc_vector_t *locator,
                      btc_peer_t *peer) {
  if (!btc_pool_is_syncable(pool, peer))
    return 0;

  /* Ask for the mempool if we're synced. */
#if 0
  if (pool->network->request_mempool) {
    if (peer->loader && btc_chain_synced(pool->chain))
      btc_peer_send_mempool(peer);
  }
#endif

  peer->syncing = 1;
  peer->block_time = btc_ms();

#if 0
  if (pool->checkpoints) {
    btc_peer_send_getheaders(peer, locator, pool->header_tip->hash);
    return 1;
  }
#endif

  btc_peer_send_getblocks(peer, locator, NULL);

  return 1;
}

static int
btc_pool_send_sync(struct btc_pool_s *pool, btc_peer_t *peer) {
  btc_vector_t locator;

  if (peer->syncing)
    return 0;

  if (!btc_pool_is_syncable(pool, peer))
    return 0;

  btc_vector_init(&locator);
  btc_chain_get_locator(pool->chain, &locator, NULL);
  btc_pool_send_locator(pool, &locator, peer);
  btc_vector_clear(&locator);

  return 1;
}

static void
btc_pool_set_loader(struct btc_pool_s *pool, btc_peer_t *peer) {
  CHECK(peer->outbound == 1);
  CHECK(pool->peers.load == NULL);
  CHECK(peer->loader == 0);

  peer->loader = 1;
  pool->peers.load = peer;

  btc_pool_send_sync(pool, peer);
}

static int
btc_pool_add_loader(struct btc_pool_s *pool) {
  const btc_netaddr_t *addr;
  btc_peer_t *peer;

  CHECK(pool->peers.load == NULL);

  for (peer = pool->peers.head; peer != NULL; peer = peer->next) {
    if (!peer->outbound)
      continue;

    /*
    if (!btc_pool_is_syncable(pool, peer))
      continue;
    */

    btc_pool_log(pool, "Repurposing peer for loader (%N).", &peer->addr);

    btc_pool_set_loader(pool, peer);

    return 1;
  }

  addr = btc_pool_get_addr(pool);

  if (addr == NULL)
    return 0;

  peer = btc_pool_create_outbound(pool, addr);

  if (peer == NULL)
    return 0;

  btc_pool_log(pool, "Adding loader peer (%N).", &peer->addr);

  btc_peers_add(&pool->peers, peer);

  btc_pool_set_loader(pool, peer);

  return 1;
}

static int
btc_pool_fill_outbound(struct btc_pool_s *pool) {
  size_t total = btc_addrman_size(pool->addrman);
  size_t i, need;

  if (pool->peers.load == NULL) {
    if (!btc_pool_add_loader(pool))
      return 0;
  }

  if (pool->peers.outbound >= pool->max_outbound)
    return 1;

  need = pool->max_outbound - pool->peers.outbound;

  if (need > total)
    need = total;

  if (need == 0)
    return 0;

  btc_pool_log(pool, "Refilling %zu peers (%zu/%zu).", need,
               pool->peers.outbound, pool->max_outbound);

  for (i = 0; i < need; i++)
    btc_pool_add_outbound(pool);

  return 1;
}

static void
btc_pool_on_tick(struct btc_pool_s *pool) {
  int64_t now = btc_ms();

  if (now - pool->refill_timer >= 3000) {
    btc_pool_fill_outbound(pool);
    pool->refill_timer = now;
  }
}

static void
btc_pool_on_socket(struct btc_pool_s *pool, btc_socket_t *socket) {
  (void)pool;
  (void)socket;
}

static void
btc_pool_on_connect(struct btc_pool_s *pool, btc_peer_t *peer) {
  btc_pool_log(pool, "Connected to %N.", &peer->addr);

  if (peer->outbound)
    btc_addrman_mark_success(pool->addrman, &peer->addr);
}

static void
btc_pool_on_complete(struct btc_pool_s *pool, btc_peer_t *peer) {
  /* const btc_netaddr_t *addr; */

  /* Advertise our address. */
  if (peer->outbound) {
#if 0
    if (pool->listening) {
      addr = btc_addrman_get_local(pool->addrman, &peer->addr);

      if (addr != NULL)
        btc_peer_send_addr(peer, addr);
    }
#endif

    /* Find some more peers. */
    btc_peer_send_getaddr(peer);
    peer->getting_addr = 1;
  }

  /* We want compact blocks! */
  /* btc_peer_sendcmpct(pool->block_mode); */

  /* Set a fee rate filter. */
#if 0
  if (pool->fee_rate != -1)
    btc_peer_send_feerate(pool->fee_rate);
#endif

  if (peer->outbound) {
    /* Start syncing the chain. */
    btc_pool_send_sync(pool, peer);

    /* Mark success. */
    btc_addrman_mark_ack(pool->addrman, &peer->addr, peer->services);

    /* If we don't have an ack'd loader yet, consider it dead. */
    if (!peer->loader) {
      if (pool->peers.load != NULL
          && pool->peers.load->state != BTC_PEER_CONNECTED) {
        pool->peers.load->loader = 0;
        pool->peers.load = NULL;
      }
    }

    /* If we do not have a loader, use this peer. */
    if (pool->peers.load == NULL)
      btc_pool_set_loader(pool, peer);
  }
}

static void
btc_pool_resync(struct btc_pool_s *pool, int force) {
  btc_vector_t locator;
  btc_peer_t *peer;

#if 0
  if (!pool->syncing)
    return;
#endif

  btc_vector_init(&locator);
  btc_chain_get_locator(pool->chain, &locator, NULL);

  for (peer = pool->peers.head; peer != NULL; peer = peer->next) {
    if (!peer->outbound)
      continue;

    if (!force && peer->syncing)
      continue;

    btc_pool_send_locator(pool, &locator, peer);
  }

  btc_vector_clear(&locator);
}

static int
btc_pool_resolve_block(struct btc_pool_s *pool,
                       btc_peer_t *peer,
                       const uint8_t *hash) {
  khiter_t it = kh_get(times, peer->block_map, (uint8_t *)hash);
  uint8_t *key;

  if (it == kh_end(peer->block_map))
    return 0;

  kh_del(times, peer->block_map, it);

  it = kh_get(hashes, pool->block_map, (uint8_t *)hash);

  CHECK(it != kh_end(pool->block_map));

  key = kh_key(pool->block_map, it);

  kh_del(hashes, pool->block_map, it);

  btc_free(key);

  return 1;
}

static int
btc_pool_resolve_tx(struct btc_pool_s *pool,
                    btc_peer_t *peer,
                    const uint8_t *hash) {
  khiter_t it = kh_get(times, peer->tx_map, (uint8_t *)hash);
  uint8_t *key;

  if (it == kh_end(peer->tx_map))
    return 0;

  kh_del(times, peer->tx_map, it);

  it = kh_get(hashes, pool->tx_map, (uint8_t *)hash);

  CHECK(it != kh_end(pool->tx_map));

  key = kh_key(pool->tx_map, it);

  kh_del(hashes, pool->tx_map, it);

  btc_free(key);

  return 1;
}

static int
btc_pool_resolve_compact(struct btc_pool_s *pool,
                         btc_peer_t *peer,
                         const uint8_t *hash) {
  khiter_t it = kh_get(times, peer->compact_map, (uint8_t *)hash);
  uint8_t *key;

  if (it == kh_end(peer->compact_map))
    return 0;

  kh_del(times, peer->compact_map, it);

  it = kh_get(hashes, pool->compact_map, (uint8_t *)hash);

  CHECK(it != kh_end(pool->compact_map));

  key = kh_key(pool->compact_map, it);

  kh_del(hashes, pool->compact_map, it);

  btc_free(key);

  return 1;
}

static int
btc_pool_resolve_item(struct btc_pool_s *pool,
                      btc_peer_t *peer,
                      const btc_invitem_t *item) {
  switch (item->type) {
    case BTC_INV_TX:
    case BTC_INV_WITNESS_TX:
      return btc_pool_resolve_tx(pool, peer, item->hash);
    case BTC_INV_BLOCK:
    case BTC_INV_FILTERED_BLOCK:
    case BTC_INV_WITNESS_BLOCK:
    case BTC_INV_WITNESS_FILTERED_BLOCK:
      return btc_pool_resolve_block(pool, peer, item->hash);
    case BTC_INV_CMPCT_BLOCK:
      return btc_pool_resolve_compact(pool, peer, item->hash);
    default:
      return 0;
  }
}

static void
btc_pool_remove_peer(struct btc_pool_s *pool, btc_peer_t *peer) {
  khiter_t it;

  btc_peers_remove(&pool->peers, peer);

  it = kh_begin(peer->block_map);

  for (; it != kh_end(peer->block_map); it++) {
    if (kh_exist(peer->block_map, it))
      hashset_del(pool->block_map, kh_key(peer->block_map, it));
  }

  it = kh_begin(peer->tx_map);

  for (; it != kh_end(peer->tx_map); it++) {
    if (kh_exist(peer->tx_map, it))
      hashset_del(pool->tx_map, kh_key(peer->tx_map, it));
  }

  it = kh_begin(peer->compact_map);

  for (; it != kh_end(peer->compact_map); it++) {
    if (kh_exist(peer->compact_map, it))
      hashset_del(pool->compact_map, kh_key(peer->compact_map, it));
  }
}

static void
btc_pool_on_disconnect(struct btc_pool_s *pool, btc_peer_t *peer) {
  int loader = peer->loader;
  size_t size = timemap_size(peer->block_map);

  btc_pool_remove_peer(pool, peer);

  if (loader) {
    btc_pool_log(pool, "Removed loader peer (%N).", &peer->addr);
#if 0
    if (pool->checkpoints)
      btc_pool_reset_chain(pool);
#endif
  }

  btc_nonces_remove(&pool->nonces, &peer->addr);

  if (btc_chain_synced(pool->chain) && size > 0) {
    btc_pool_log(pool, "Peer disconnected with requested blocks (%N).",
                       &peer->addr);
    btc_pool_log(pool, "Resending sync...");
    btc_pool_resync(pool, 1);
  }

  btc_peer_destroy(peer);
}

static void
btc_pool_on_version(struct btc_pool_s *pool, btc_peer_t *peer, btc_version_t *msg) {
  btc_pool_log(pool,
    "Received version (%N): version=%d height=%d services=%#.16llx agent=%s",
    &peer->addr,
    msg->version,
    msg->height,
    msg->services,
    msg->agent);

  if (pool->timedata != NULL)
    btc_timedata_add(pool->timedata, msg->time);

  btc_nonces_remove(&pool->nonces, &peer->addr);

#if 0
  if (!peer->outbound && btc_netaddr_is_routable(&msg->remote))
    btc_addrman_mark_local(pool->addrman, &msg->remote);
#endif

  btc_version_destroy(msg);
}

static void
btc_pool_on_verack(struct btc_pool_s *pool, btc_peer_t *peer) {
  (void)pool;
  (void)peer;
}

static void
btc_pool_on_ping(struct btc_pool_s *pool, btc_peer_t *peer, btc_ping_t *msg) {
  (void)pool;
  (void)peer;
  (void)msg;
  btc_ping_destroy(msg);
}

static void
btc_pool_on_pong(struct btc_pool_s *pool, btc_peer_t *peer, btc_pong_t *msg) {
  (void)pool;
  (void)peer;
  (void)msg;
  btc_pong_destroy(msg);
}

static void
btc_pool_on_getaddr(struct btc_pool_s *pool, btc_peer_t *peer) {
  /* TODO */
  (void)pool;
  (void)peer;
}

static void
btc_pool_on_addr(struct btc_pool_s *pool, btc_peer_t *peer, btc_addrs_t *msg) {
  /* TODO */
  (void)pool;
  (void)peer;
  (void)msg;

  btc_addrs_destroy(msg);
}

static void
btc_pool_resolve_orphan(struct btc_pool_s *pool,
                        btc_peer_t *peer,
                        const uint8_t *orphan) {
  const uint8_t *root = btc_chain_get_orphan_root(pool->chain, orphan);
  btc_vector_t locator;

  CHECK(root != NULL);

  btc_vector_init(&locator);
  btc_chain_get_locator(pool->chain, &locator, NULL);
  btc_peer_send_getblocks(peer, &locator, root);
  btc_vector_clear(&locator);
}

static void
btc_pool_getblocks(struct btc_pool_s *pool,
                   btc_peer_t *peer,
                   const uint8_t *tip,
                   const uint8_t *stop) {
  btc_vector_t locator;

  btc_vector_init(&locator);
  btc_chain_get_locator(pool->chain, &locator, tip);
  btc_peer_send_getblocks(peer, &locator, stop);
  btc_vector_clear(&locator);
}

static void
btc_pool_getblock(struct btc_pool_s *pool,
                  btc_peer_t *peer,
                  btc_vector_t *items) {
  btc_invitem_t *item;
  btc_getdata_t inv;
  uint8_t *hash;
  int64_t now;
  size_t i;

  if (peer->state != BTC_PEER_CONNECTED) {
    btc_pool_log(pool, "Peer handshake not complete (getdata) (%N).",
                       &peer->addr);
    return;
  }

  now = btc_ms();

  btc_inv_init(&inv);

  for (i = 0; i < items->length; i++) {
    item = (btc_invitem_t *)items->items[i];

    if (hashset_has(pool->block_map, item->hash))
      continue;

    hash = btc_hash_clone(item->hash);

    hashset_put(pool->block_map, hash);
    timemap_put(peer->block_map, hash, now);

    if (btc_chain_synced(pool->chain))
      now += 100;

    if (peer->services & BTC_NET_SERVICE_WITNESS)
      item->type |= BTC_INV_WITNESS_FLAG;

    btc_inv_push(&inv, item);
  }

  if (inv.length == 0) {
    btc_inv_clear(&inv);
    return;
  }

  if (timemap_size(peer->block_map) >= BTC_NET_MAX_BLOCK_REQUEST) {
    btc_pool_log(pool, "Peer advertised too many blocks (%N).",
                       &peer->addr);
    btc_peer_close(peer);
    return;
  }

  btc_pool_log(pool, "Requesting %zu/%zu blocks from peer with getdata (%N).",
                     inv.length, hashset_size(pool->block_map), &peer->addr);

  btc_peer_send_getdata(peer, &inv);

  /* Caller must free up inv items. */
  inv.length = 0;

  btc_inv_clear(&inv);
}

static void
btc_pool_on_blockinv(struct btc_pool_s *pool,
                     btc_peer_t *peer,
                     btc_vector_t *items) {
  const uint8_t *exists = NULL;
  btc_invitem_t *item;
  btc_vector_t out;
  size_t i;

  CHECK(items->length > 0);

#if 0
  if (!pool->syncing)
    return;
#endif

  /* Always keep track of the peer's best hash. */
  if (!peer->loader || btc_chain_synced(pool->chain)) {
    item = (btc_invitem_t *)btc_vector_top(items);

    btc_hash_copy(peer->best_hash, item->hash);
  }

  /* Ignore for now if we're still syncing. */
  if (!btc_chain_synced(pool->chain) && !peer->loader)
    return;

#if 0
  /* Request headers instead. */
  if (pool->checkpoints)
    return;
#endif

  btc_pool_log(pool, "Received %zu block hashes from peer (%N).",
                     items->length, &peer->addr);

  btc_vector_init(&out);

  for (i = 0; i < items->length; i++) {
    item = (btc_invitem_t *)items->items[i];

    /* Resolve orphan chain. */
    if (btc_chain_has_orphan(pool->chain, item->hash)) {
      btc_pool_log(pool, "Received known orphan hash (%N).", &peer->addr);
      btc_pool_resolve_orphan(pool, peer, item->hash);
      continue;
    }

/*
    if (btc_chain_has_invalid(pool->chain, item->hash))
      continue;
*/

    /* Request the block if we don't have it. */
    if (!btc_chain_has(pool->chain, item->hash)) {
      btc_vector_push(&out, item);
      continue;
    }

    exists = item->hash;

    /* Normally we request the hashContinue.
       In the odd case where we already have
       it, we can do one of two things: either
       force re-downloading of the block to
       continue the sync, or do a getblocks
       from the last hash. */
    if (i == items->length - 1) {
      btc_pool_log(pool, "Received existing hash (%N).", &peer->addr);
      btc_pool_getblocks(pool, peer, item->hash, NULL);
    }
  }

  /* Attempt to update the peer's best height
     with the last existing hash we know of. */
  if (exists != NULL && btc_chain_synced(pool->chain)) {
    const btc_entry_t *entry = btc_chain_by_hash(pool->chain, item->hash);

    if (entry != NULL)
      peer->best_height = entry->height;
  }

  btc_pool_getblock(pool, peer, &out);

  btc_vector_clear(&out);
}

static void
btc_pool_on_txinv(struct btc_pool_s *pool,
                  btc_peer_t *peer,
                  btc_vector_t *items) {
  (void)pool;
  (void)peer;
  (void)items;
}

static void
btc_pool_on_inv(struct btc_pool_s *pool, btc_peer_t *peer, btc_inv_t *inv) {
  int64_t unknown = -1;
  btc_invitem_t *item;
  btc_vector_t blocks;
  btc_vector_t txs;
  size_t i;

  if (inv->length > BTC_NET_MAX_INV) {
    /* btc_peer_increase_ban(peer, 100); */
    btc_inv_destroy(inv);
    return;
  }

  btc_vector_init(&blocks);
  btc_vector_init(&txs);

  for (i = 0; i < inv->length; i++) {
    item = (btc_invitem_t *)inv->items[i];

    switch (item->type) {
      case BTC_INV_BLOCK:
        btc_vector_push(&blocks, item);
        break;
      case BTC_INV_TX:
        btc_vector_push(&txs, item);
        break;
      default:
        unknown = item->type;
        break;
    }

    /* btc_filter_add(peer->inv_filter, item->hash, 32); */
  }

  btc_pool_log(pool,
    "Received inv packet with %zu items: blocks=%zu txs=%zu (%N).",
    inv->length, blocks.length, txs.length, &peer->addr);

  if (unknown != -1) {
    btc_pool_log(pool,
      "Peer sent an unknown inv type: %u (%N).",
      (uint32_t)unknown, &peer->addr);
  }

  if (blocks.length > 0)
    btc_pool_on_blockinv(pool, peer, &blocks);

  if (txs.length > 0)
    btc_pool_on_txinv(pool, peer, &txs);

  btc_vector_clear(&blocks);
  btc_vector_clear(&txs);
  btc_inv_destroy(inv);
}

static void
btc_pool_on_getdata(struct btc_pool_s *pool, btc_peer_t *peer, btc_getdata_t *msg) {
  /* TODO */
  (void)pool;
  (void)peer;
  (void)msg;
  btc_inv_destroy(msg);
}

static void
btc_pool_on_notfound(struct btc_pool_s *pool, btc_peer_t *peer, btc_notfound_t *msg) {
  const btc_invitem_t *item;
  size_t i;

  for (i = 0; i < msg->length; i++) {
    item = msg->items[i];

    if (!btc_pool_resolve_item(pool, peer, item)) {
      btc_pool_log(pool,
        "Peer sent notfound for unrequested item: %H (%N).",
        item->hash, &peer->addr);
      btc_peer_close(peer);
      return;
    }
  }

  btc_inv_destroy(msg);
}

static void
btc_pool_on_getblocks(struct btc_pool_s *pool, btc_peer_t *peer, btc_getblocks_t *msg) {
  /* TODO */
  (void)pool;
  (void)peer;
  (void)msg;
  btc_getblocks_destroy(msg);
}

static void
btc_pool_on_getheaders(struct btc_pool_s *pool, btc_peer_t *peer, btc_getheaders_t *msg) {
  /* TODO */
  (void)pool;
  (void)peer;
  (void)msg;
  btc_getblocks_destroy(msg);
}

static void
btc_pool_on_headers(struct btc_pool_s *pool, btc_peer_t *peer, btc_headers_t *msg) {
  /* TODO */
  (void)pool;
  (void)peer;
  btc_headers_destroy(msg);
}

static void
btc_pool_on_sendheaders(struct btc_pool_s *pool, btc_peer_t *peer) {
  (void)pool;
  (void)peer;
}

static void
btc_pool_add_block(struct btc_pool_s *pool,
                   btc_peer_t *peer,
                   const btc_block_t *block,
                   unsigned int flags) {
  uint8_t hash[32];
  int32_t height;

#if 0
  if (!pool->syncing)
    return;
#endif

  btc_header_hash(hash, &block->header);

  if (!btc_pool_resolve_block(pool, peer, hash)) {
    btc_pool_log(pool, "Received unrequested block: %H (%N).",
                       hash, &peer->addr);
    btc_peer_close(peer);
    return;
  }

  peer->block_time = btc_ms();

  btc_pool_log(pool, "Adding block: %H (%N).", hash, &peer->addr);

  if (!btc_chain_add(pool->chain, block, flags, peer->id)) {
#if 0
    btc_peer_reject(peer, BTC_MSG_BLOCK, btc_chain_error(pool->chain));
#endif
    return;
  }

  /* Block was orphaned. */
  if (btc_chain_has_orphan(pool->chain, hash)) {
    if (pool->checkpoints) {
      btc_pool_log(pool, "Peer sent orphan block with getheaders (%N).",
                         &peer->addr);
      return;
    }

    /* During a getblocks sync, peers send
       their best tip frequently. We can grab
       the height commitment from the coinbase. */
    height = btc_block_coinbase_height(block);

    if (height != -1) {
      btc_hash_copy(peer->best_hash, hash);

      peer->best_height = height;

      /* btc_pool_resolve_height(pool, hash, height); */
    }

    btc_pool_log(pool, "Peer sent an orphan block. Resolving.");

    btc_pool_resolve_orphan(pool, peer, hash);

    return;
  }

  if (btc_chain_synced(pool->chain)) {
    const btc_entry_t *entry = btc_chain_by_hash(pool->chain, hash);

    CHECK(entry != NULL);

    btc_hash_copy(peer->best_hash, entry->hash);

    peer->best_height = entry->height;

    /* btc_pool_resolve_height(pool, entry->hash, entry->height); */
  }

  height = btc_chain_height(pool->chain);

  if (height % 20 == 0) {
    btc_pool_log(pool, "Status:"
                       " time=%D height=%d progress=%.2f"
                       " orphans=%d active=%zu"
                       " target=%#.8x peers=%zu",
      block->header.time,
      height,
      (double)0.0,
      0,
      hashset_size(pool->block_map),
      block->header.bits,
      pool->peers.size);
  }

  if (height % 2000 == 0) {
    btc_pool_log(pool, "Received 2000 more blocks (height=%d, hash=%H).",
                       height, hash);
  }

  /* btc_pool_resolve_chain(pool, peer, hash); */
}

static void
btc_pool_on_block(struct btc_pool_s *pool, btc_peer_t *peer, btc_block_t *msg) {
  unsigned int flags = BTC_CHAIN_DEFAULT_FLAGS;

  btc_pool_add_block(pool, peer, msg, flags);
  btc_block_destroy(msg);
}

static void
btc_pool_on_tx(struct btc_pool_s *pool, btc_peer_t *peer, btc_tx_t *msg) {
  /* TODO */
  (void)pool;
  (void)peer;
  (void)msg;
  btc_tx_destroy(msg);
}

static void
btc_pool_on_reject(struct btc_pool_s *pool, btc_peer_t *peer, btc_reject_t *msg) {
  btc_pool_log(pool, "Received reject (%N): msg=%s code=%s reason=%s hash=%H.",
                     &peer->addr,
                     msg->message,
                     btc_reject_get_code(msg),
                     msg->reason,
                     msg->hash);

  btc_reject_destroy(msg);
}

static void
btc_pool_on_mempool(struct btc_pool_s *pool, btc_peer_t *peer) {
  /* TODO */
  (void)pool;
  (void)peer;
}

static void
btc_pool_on_feefilter(struct btc_pool_s *pool, btc_peer_t *peer, btc_feefilter_t *msg) {
  /* TODO */
  (void)pool;
  (void)peer;
  (void)msg;
  btc_feefilter_destroy(msg);
}

static void
btc_pool_on_sendcmpct(struct btc_pool_s *pool, btc_peer_t *peer, btc_sendcmpct_t *msg) {
  /* TODO */
  (void)pool;
  (void)peer;
  btc_sendcmpct_destroy(msg);
}

static void
btc_pool_on_unknown(struct btc_pool_s *pool, btc_peer_t *peer, btc_msg_t *msg) {
  btc_pool_log(pool, "Unknown packet: %s (%N).", msg->cmd, &peer->addr);
  btc_msg_destroy(msg);
}

static void
btc_pool_on_msg(struct btc_pool_s *pool, btc_peer_t *peer, btc_msg_t *msg) {
  switch (msg->type) {
    case BTC_MSG_VERSION:
      btc_pool_on_version(pool, peer, (btc_version_t *)msg->body);
      break;
    case BTC_MSG_VERACK:
      btc_pool_on_verack(pool, peer);
      break;
    case BTC_MSG_PING:
      btc_pool_on_ping(pool, peer, (btc_ping_t *)msg->body);
      break;
    case BTC_MSG_PONG:
      btc_pool_on_pong(pool, peer, (btc_pong_t *)msg->body);
      break;
    case BTC_MSG_GETADDR:
      btc_pool_on_getaddr(pool, peer);
      break;
    case BTC_MSG_ADDR:
      btc_pool_on_addr(pool, peer, (btc_addrs_t *)msg->body);
      break;
    case BTC_MSG_INV:
      btc_pool_on_inv(pool, peer, (btc_inv_t *)msg->body);
      break;
    case BTC_MSG_GETDATA:
      btc_pool_on_getdata(pool, peer, (btc_getdata_t *)msg->body);
      break;
    case BTC_MSG_NOTFOUND:
      btc_pool_on_notfound(pool, peer, (btc_notfound_t *)msg->body);
      break;
    case BTC_MSG_GETBLOCKS:
      btc_pool_on_getblocks(pool, peer, (btc_getblocks_t *)msg->body);
      break;
    case BTC_MSG_GETHEADERS:
      btc_pool_on_getheaders(pool, peer, (btc_getheaders_t *)msg->body);
      break;
    case BTC_MSG_HEADERS:
      btc_pool_on_headers(pool, peer, (btc_headers_t *)msg->body);
      break;
    case BTC_MSG_SENDHEADERS:
      btc_pool_on_sendheaders(pool, peer);
      break;
    case BTC_MSG_BLOCK:
      btc_pool_on_block(pool, peer, (btc_block_t *)msg->body);
      break;
    case BTC_MSG_TX:
      btc_pool_on_tx(pool, peer, (btc_tx_t *)msg->body);
      break;
    case BTC_MSG_REJECT:
      btc_pool_on_reject(pool, peer, (btc_reject_t *)msg->body);
      break;
    case BTC_MSG_MEMPOOL:
      btc_pool_on_mempool(pool, peer);
      break;
    case BTC_MSG_FEEFILTER:
      btc_pool_on_feefilter(pool, peer, (btc_feefilter_t *)msg->body);
      break;
    case BTC_MSG_SENDCMPCT:
      btc_pool_on_sendcmpct(pool, peer, (btc_sendcmpct_t *)msg->body);
      break;
    case BTC_MSG_UNKNOWN:
      btc_pool_on_unknown(pool, peer, msg);
      return;
    default:
      btc_msg_destroy(msg);
      return;
  }

  msg->body = NULL;

  btc_msg_destroy(msg);
}
